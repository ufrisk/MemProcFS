// vmmwinreg.c : implementation of functionality related to the Windows registry.
//
// (c) Ulf Frisk, 2019-2023
// Author: Ulf Frisk, pcileech@frizk.net
//
// Registry key parsing partly built on documentation found at:
// https://github.com/msuhanov/regf
// 

#include "vmmwinreg.h"
#include "leechcore.h"
#include "pe.h"
#include "charutil.h"
#include "util.h"
#include "vmmwin.h"

#define REG_SIGNATURE_HBIN      0x6e696268

typedef struct tdVMMWIN_REGISTRY_OFFSET {
    QWORD vaHintCMHIVE;
    struct {
        WORD Signature;
        WORD FLinkAll;
        WORD Length0;
        WORD StorageMap0;
        WORD StorageSmallDir0;
        WORD Length1;
        WORD StorageMap1;
        WORD StorageSmallDir1;
        WORD BaseBlock;
        WORD FileFullPathOpt;
        WORD FileUserNameOpt;
        WORD HiveRootPathOpt;
        WORD _Size;
    } CM;
    struct {
        WORD Signature;
        WORD Length;
        WORD Major;
        WORD Minor;
        WORD FileName;
    } BB;
    struct {
        WORD _Size;
    } HE;
} VMMWIN_REGISTRY_OFFSET, *PVMMWIN_REGISTRY_OFFSET;

typedef struct tdVMMWIN_REGISTRY_CONTEXT {
    POB_CONTAINER pObCHiveMap;
    CRITICAL_SECTION LockUpdate;
    VMMWIN_REGISTRY_OFFSET Offset;
} VMMWIN_REGISTRY_CONTEXT, *PVMMWIN_REGISTRY_CONTEXT;

//-----------------------------------------------------------------------------
// READ & WRITE TO REGISTRY "MEMORY SPACE" BELOW:
// Each individual registry hive may be addressed with an addressing scheme
// similar to the X86 non-PAE addressing mode. A registry address is translated
// into a virtual address. The virtual address is then read.
//-----------------------------------------------------------------------------

/*
* Retrieve the 'Registry' process - or if not found the 'SYSTEM' process.
* CALLER DECREF: return
* -- H
* -- return
*/
PVMM_PROCESS VmmWinReg_GetRegistryProcess(_In_ VMM_HANDLE H)
{
    PVMM_PROCESS pObProcess = VmmProcessGet(H, H->vmm.kernel.dwPidRegistry);
    if(pObProcess) { return pObProcess; }
    return VmmProcessGet(H, 4);
}

#define _IS_HMAP_KDDR64(a)     ((a & 0xffff800000000ff0) == 0xffff800000000000)
#define _IS_HMAP_ADDR64(a)     (a && ((((a >> 47) == 0x1ffff) || (a >> 47) == 0)) && (a & 0x0000ffffffff0000) && !(a & 0xff0))
#define _IS_HMAP_ZERO64(a)     (!a)
#define _IS_HMAP_SIZE64(a)     (a && !(a & 0xffffffffffff0fff))
#define _IS_HMAP_ZERO32(a)     (!a)
#define _IS_HMAP_KDDR32(a)     (((a & 0x80000ff0) == 0x80000000) && (a & 0xfff00000))
#define _IS_HMAP_ADDR32(a)     (!(a & 0xff0) && (a & 0xfff00000))
#define _IS_HMAP_SIZE32(a)     (a && !(a & 0xffff0fff))

_Success_(return)
BOOL VmmWinReg_Reg2Virt64(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcessRegistry, _In_ POB_REGISTRY_HIVE pRegistryHive, _In_ DWORD ra, _Out_ PQWORD pva)
{
    PVMMWIN_REGISTRY_OFFSET po = &H->vmm.pRegistry->Offset;
    QWORD iSV, iDirectory, iTable;
    QWORD vaTable, vaCell, oCell;
    BYTE pbHE[0x40];
    // TRANSLATION REMINDS OF X86 MEMORY MODEL
    // 1-bit    10-bits   9-bits    12-bits
    // +-----+-----------+-------+-------------+
    // | S/V | DIRECTORY | TABLE | CELL OFFSET |
    // +-----+-----------+-------+-------------+
    iSV = (ra >> 31);
    iDirectory = (ra >> (12 + 9)) & 0x3ff;
    iTable = (ra >> 12) & 0x1ff;
    ra = ra & 0x7fffffff;
    if(ra >= pRegistryHive->_DUAL[iSV].cb) { return FALSE; }
    if(iDirectory || !pRegistryHive->_DUAL[iSV].vaHMAP_TABLE_SmallDir) {
        // REG directory is array of max 1024 pointers to tables [ nt!_HMAP_DIRECTORY +0x000 Directory : [1024] Ptr64 _HMAP_TABLE ]
        if(!VmmRead(H, pProcessRegistry, pRegistryHive->_DUAL[iSV].vaHMAP_DIRECTORY + iDirectory * sizeof(QWORD), (PBYTE)&vaTable, sizeof(QWORD)) || !vaTable) { return FALSE; }
    } else {
        vaTable = pRegistryHive->_DUAL[iSV].vaHMAP_TABLE_SmallDir;
    }
    if(!VMM_KADDR64(vaTable)) { return FALSE; }
    // REG table is array of 512 _HMAP_ENTRY of size 0x18 or 0x20 or 0x28
    // [ --------------------------------------- ]
    // [ WINVISTA->WIN81: dt nt!_HMAP_ENTRY      ]
    // [    + 0x000 BlockAddress : Uint8B        ]
    // [ --------------------------------------- ]
    // [    WINDOWS10 : dt nt!_HMAP_ENTRY        ]
    // [    + 0x000 BlockOffset : Uint8B         ]
    // [    + 0x008 PermanentBinAddress : Uint8B ]
    // [ --------------------------------------- ]
    if(!VmmRead(H, pProcessRegistry, vaTable + iTable * po->HE._Size, (PBYTE)&pbHE, po->HE._Size)) { return FALSE; }
    if(H->vmm.kernel.dwVersionMajor == 10) {
        oCell = *(PQWORD)pbHE;
        vaCell = *(PQWORD)(pbHE + 8);
        if((oCell & 0xfff) || (oCell >= 0x10000)) { return FALSE; }
        vaCell += oCell;
    } else {
        vaCell = *(PQWORD)pbHE;
    }
    if(!_IS_HMAP_ADDR64(vaCell)) { return FALSE; }
    *pva = (vaCell & 0xfffffffffffff000) | (ra & 0xfff);
    return TRUE;
}

_Success_(return)
BOOL VmmWinReg_Reg2Virt32(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcessRegistry, _In_ POB_REGISTRY_HIVE pRegistryHive, _In_ DWORD ra, _Out_ PQWORD pva)
{
    PVMMWIN_REGISTRY_OFFSET po = &H->vmm.pRegistry->Offset;
    QWORD iSV, iDirectory, iTable;
    DWORD vaTable, vaCell, oCell;
    BYTE pbHE[0x20];
    // TRANSLATION REMINDS OF X86 MEMORY MODEL
    // 1-bit    10-bits   9-bits    12-bits
    // +-----+-----------+-------+-------------+
    // | S/V | DIRECTORY | TABLE | CELL OFFSET |
    // +-----+-----------+-------+-------------+
    iSV = (ra >> 31);
    iDirectory = (ra >> (12 + 9)) & 0x3ff;
    iTable = (ra >> 12) & 0x1ff;
    ra = ra & 0x7fffffff;
    if(ra >= pRegistryHive->_DUAL[iSV].cb) { return FALSE; }
    // DIRECTORY
    if(iDirectory || !pRegistryHive->_DUAL[iSV].vaHMAP_TABLE_SmallDir) {
        if(!VmmRead(H, pProcessRegistry, pRegistryHive->_DUAL[iSV].vaHMAP_DIRECTORY + iDirectory * sizeof(DWORD), (PBYTE)&vaTable, sizeof(DWORD)) || !vaTable) { return FALSE; }
    } else {
        vaTable = (DWORD)pRegistryHive->_DUAL[iSV].vaHMAP_TABLE_SmallDir;
    }
    if(!VMM_KADDR32(vaTable)) { return FALSE; }
    // [ --------------------------------------- ]
    // [ WINVISTA->WIN81: dt nt!_HMAP_ENTRY      ]
    // [    + 0x000 BlockAddress : Uint4B        ]
    // [ --------------------------------------- ]
    // [    WINDOWS10 : dt nt!_HMAP_ENTRY        ]
    // [    + 0x000 BlockOffset : Uint4B         ]
    // [    + 0x004 PermanentBinAddress : Uint4B ]
    // [ --------------------------------------- ]
    if(!VmmRead(H, pProcessRegistry, vaTable + iTable * po->HE._Size, (PBYTE)&pbHE, po->HE._Size)) { return FALSE; }
    if(H->vmm.kernel.dwVersionMajor == 10) {
        oCell = *(PDWORD)pbHE;
        vaCell = *(PDWORD)(pbHE + 4);
        if((oCell & 0xfff) || (oCell >= 0x10000)) { return FALSE; }
        vaCell += oCell;
    } else {
        vaCell = *(PDWORD)pbHE;
    }
    if(!_IS_HMAP_ADDR32(vaCell)) { return FALSE; }
    *pva = (vaCell & 0xfffff000) | (ra & 0xfff);
    return TRUE;
}

/*
* Translate a registry address 'ra' into a virtual address 'va'
* -- pProcessRegistry = the registry process
* -- pRegistryHive = the registry hive
* -- ra = the registry address to translate
* -- pva = ptr to receive the virtual address
* -- return
*/
_Success_(return)
BOOL VmmWinReg_Reg2Virt(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcessRegistry, _In_ POB_REGISTRY_HIVE pRegistryHive, _In_ DWORD ra, _Out_ PQWORD pva)
{
    if(!pProcessRegistry || !pRegistryHive) { return FALSE; }
    return H->vmm.f32 ?
        VmmWinReg_Reg2Virt32(H, pProcessRegistry, pRegistryHive, ra, pva) :
        VmmWinReg_Reg2Virt64(H, pProcessRegistry, pRegistryHive, ra, pva);
}

/*
* Read scatter registry address. This translates each registry memory scatter
* request item into a virtual memory scatter request item and submits it to
* the underlying vmm sub-system. See VmmReadScatterVirtual for additional
* information.
* -- H
* -- pProcessRegistry
* -- pRegistryHive
* -- ppMEMsReg
* -- cpMEMsReg
* -- flags
*/
VOID VmmWinReg_ReadScatter(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcessRegistry, _In_ POB_REGISTRY_HIVE pRegistryHive, _Inout_ PPMEM_SCATTER ppMEMsReg, _In_ DWORD cpMEMsReg, _In_ QWORD flags)
{
    DWORD i;
    PMEM_SCATTER pMEM;
    for(i = 0; i < cpMEMsReg; i++) {
        pMEM = ppMEMsReg[i];
        MEM_SCATTER_STACK_PUSH(pMEM, pMEM->qwA);
        if(pMEM->f || !VmmWinReg_Reg2Virt(H, pProcessRegistry, pRegistryHive, (DWORD)pMEM->qwA, &pMEM->qwA)) {
            pMEM->qwA = -1;
        }
    }
    VmmReadScatterVirtual(H, pProcessRegistry, ppMEMsReg, cpMEMsReg, flags);
    for(i = 0; i < cpMEMsReg; i++) {
        pMEM = ppMEMsReg[i];
        pMEM->qwA = MEM_SCATTER_STACK_POP(pMEM);
    }
}

/*
* Read a contigious arbitrary amount of registry hive memory and report the
* number of bytes read in pcbRead.
* NB! Address space does not include regf registry hive file header!
* -- H
* -- pRegistryHive
* -- ra
* -- pb
* -- cb
* -- pcbRead
* -- flags = flags as in VMM_FLAG_*
*/
VOID VmmWinReg_HiveReadEx(_In_ VMM_HANDLE H, _In_ POB_REGISTRY_HIVE pRegistryHive, _In_ DWORD ra, _Out_writes_(cb) PBYTE pb, _In_ DWORD cb, _Out_opt_ PDWORD pcbReadOpt, _In_ QWORD flags)
{
    PVMM_PROCESS pObProcessRegistry = NULL;
    DWORD cbP, cMEMs, cbRead = 0;
    PBYTE pbBuffer;
    PMEM_SCATTER pMEMs, *ppMEMs;
    QWORD i, oVA;
    if(pcbReadOpt) { *pcbReadOpt = 0; }
    if(!cb) { return; }
    cMEMs = (DWORD)(((ra & 0xfff) + cb + 0xfff) >> 12);
    pbBuffer = (PBYTE)LocalAlloc(LMEM_ZEROINIT, 0x2000 + cMEMs * (sizeof(MEM_SCATTER) + sizeof(PMEM_SCATTER)));
    if(!pbBuffer) {
        ZeroMemory(pb, cb);
        return;
    }
    pMEMs = (PMEM_SCATTER)(pbBuffer + 0x2000);
    ppMEMs = (PPMEM_SCATTER)(pbBuffer + 0x2000 + cMEMs * sizeof(MEM_SCATTER));
    oVA = ra & 0xfff;
    // prepare "middle" pages
    for(i = 0; i < cMEMs; i++) {
        ppMEMs[i] = &pMEMs[i];
        pMEMs[i].version = MEM_SCATTER_VERSION;
        pMEMs[i].qwA = ra - oVA + (i << 12);
        pMEMs[i].cb = 0x1000;
        pMEMs[i].pb = pb - oVA + (i << 12);
    }
    // fixup "first/last" pages
    pMEMs[0].pb = pbBuffer;
    if(cMEMs > 1) {
        pMEMs[cMEMs - 1].pb = pbBuffer + 0x1000;
    }
    // Read REG and handle result
    pObProcessRegistry = VmmWinReg_GetRegistryProcess(H);
    if(pObProcessRegistry) {
        VmmWinReg_ReadScatter(H, pObProcessRegistry, pRegistryHive, ppMEMs, cMEMs, flags);
        Ob_DECREF(pObProcessRegistry);
        pObProcessRegistry = NULL;
    }
    for(i = 0; i < cMEMs; i++) {
        if(pMEMs[i].f) {
            cbRead += 0x1000;
        } else {
            ZeroMemory(pMEMs[i].pb, 0x1000);
        }
    }
    cbRead -= pMEMs[0].f ? 0x1000 : 0;                             // adjust byte count for first page (if needed)
    cbRead -= ((cMEMs > 1) && pMEMs[cMEMs - 1].f) ? 0x1000 : 0;    // adjust byte count for last page (if needed)
    // Handle first page
    cbP = (DWORD)min(cb, 0x1000 - oVA);
    if(pMEMs[0].f) {
        memcpy(pb, pMEMs[0].pb + oVA, cbP);
        cbRead += cbP;
    } else {
        ZeroMemory(pb, cbP);
    }
    // Handle last page
    if(cMEMs > 1) {
        cbP = (((ra + cb) & 0xfff) ? ((ra + cb) & 0xfff) : 0x1000);
        if(pMEMs[cMEMs - 1].f) {
            memcpy(pb + ((QWORD)cMEMs << 12) - oVA - 0x1000, pMEMs[cMEMs - 1].pb, cbP);
            cbRead += cbP;
        } else {
            ZeroMemory(pb + ((QWORD)cMEMs << 12) - oVA - 0x1000, cbP);
        }
    }
    if(pcbReadOpt) { *pcbReadOpt = cbRead; }
    LocalFree(pbBuffer);
}

_Success_(return)
BOOL VmmWinReg_HiveRead(_In_ VMM_HANDLE H, _In_ POB_REGISTRY_HIVE pRegistryHive, _In_ DWORD ra, _Out_ PBYTE pb, _In_ DWORD cb)
{
    DWORD cbRead;
    VmmWinReg_HiveReadEx(H, pRegistryHive, ra, pb, cb, &cbRead, 0);
    return (cbRead == cb);
}

/*
* Write a virtually contigious arbitrary amount of memory.
* NB! Address space does not include regf registry hive file header!
* -- H
* -- pRegistryHive
* -- ra
* -- pb
* -- cb
* -- return = TRUE on success, FALSE on partial or zero write.
*/
_Success_(return)
BOOL VmmWinReg_HiveWrite(_In_ VMM_HANDLE H, _In_ POB_REGISTRY_HIVE pRegistryHive, _In_ DWORD ra, _In_reads_(cb) PBYTE pb, _In_ DWORD cb)
{
    QWORD vaWrite;
    DWORD cbWrite;
    BOOL fSuccess = TRUE;
    PVMM_PROCESS pObProcessRegistry = NULL;
    if(!cb || !(pObProcessRegistry = VmmWinReg_GetRegistryProcess(H))) { return FALSE; }
    while(cb) {
        cbWrite = 0x1000 - (ra & 0xfff);
        if(VmmWinReg_Reg2Virt(H, pObProcessRegistry, pRegistryHive, ra, &vaWrite) && vaWrite) {
            fSuccess = VmmWrite(H, pObProcessRegistry, vaWrite, pb, cbWrite) && fSuccess;
        } else {
            fSuccess = FALSE;
        }
        ra += cbWrite;
        pb += cbWrite;
    }
    Ob_DECREF(pObProcessRegistry);
    return fSuccess;
}



//-----------------------------------------------------------------------------
// REGISTRY ONE TIME INITIALIZATION FUNCTIONALITY BELOW:
// Locate potential registry hive addresses by looking at ntoskrnl.exe '.data'
// section (Windows 10) or by scanning lower physical memory (Win 7/8). Once
// potential hives are located then FUZZ offsets within the hive page. Upon
// success offsets are stored in the core H->vmm.RegistryOffset global object.
//-----------------------------------------------------------------------------

VOID VmmWinReg_FuzzHiveOffsets_PrintResultVerbose(_In_ VMM_HANDLE H, _In_ PBYTE pb, _In_ DWORD cb)
{
    PVMMWIN_REGISTRY_OFFSET po = &H->vmm.pRegistry->Offset;
    VmmLog(H, MID_REGISTRY, LOGLEVEL_DEBUG,
        "CM.Sig   %03X, CM.Len0   %03X, CM.StorMap0  %03X, CM.StorSmallDir0 %03X, CM.BaseBlock %03X",
        po->CM.Signature, po->CM.Length0, po->CM.StorageMap0, po->CM.StorageSmallDir0, po->CM.BaseBlock);
    VmmLog(H, MID_REGISTRY, LOGLEVEL_DEBUG,
        "              CM.Len1   %03X, CM.StorMap1  %03X, CM.StorSmallDir1 %03X, HE._Size     %03X",
        po->CM.Length1, po->CM.StorageMap1, po->CM.StorageSmallDir1, po->HE._Size);
    VmmLog(H, MID_REGISTRY, LOGLEVEL_DEBUG,
        "CM.FLAll %03X, CM._Size  %03X, CM.FileFull  %03X, CM.FileUserPath  %03X, CM.HiveRoot  %03X",
        po->CM.FLinkAll, po->CM._Size, po->CM.FileFullPathOpt, po->CM.FileUserNameOpt, po->CM.HiveRootPathOpt);
    VmmLog(H, MID_REGISTRY, LOGLEVEL_DEBUG,
        "BB.Sig   %03X, BB.Length %03X, BB.FileName  %03X, BB.Major         %03X, BB.Minor     %03X",
        po->BB.Signature, po->BB.Length, po->BB.FileName, po->BB.Major, po->BB.Minor);
}

/*
* Fuzz required offsets for registry structures and upon success store the
* result in H->vmm.RegistryOffset. This function is overly complicated and
* should ideally be replaced with parsing the structs from Microsoft SymSrv -
* but that will introduce additional dependencies also ... This works for now.
*/
BOOL VmmWinReg_FuzzHiveOffsets64(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcessSystem, _In_ QWORD vaCMHIVE, _In_reads_(0x1000) PBYTE pbCMHIVE)
{
    CONST BYTE pbTEXT_REGISTRY[] = { '\\', 0, 'R', 0, 'E', 0, 'G', 0, 'I', 0, 'S', 0, 'T', 0, 'R', 0, 'Y', 0, '\\', 0, };
    BOOL f;
    WORD o, cbDual;
    DWORD dw;
    QWORD qw, vaSmallDir;
    BYTE pbBuffer[20];
    QWORD qwHE[10];
    PVMMWIN_REGISTRY_OFFSET po;
    // _CMHIVE BASE
    if((*(PDWORD)(pbCMHIVE + 0x004) == 0x30314D43) || (*(PDWORD)(pbCMHIVE + 0x010) == 0xBEE0BEE0)) {
        pbCMHIVE += 0x10;
        if(vaCMHIVE) { vaCMHIVE += 0x10; }
    }
    if(*(PDWORD)(pbCMHIVE + 0x000) != 0xBEE0BEE0) { return FALSE; }
    po = &H->vmm.pRegistry->Offset;
    po->CM.Signature = 0;
    // _CMHIVE.BaseBlock
    for(o = 0x30; o < 0x60; o += 8) {
        if((f = VMM_KADDR64_PAGE(*(PQWORD)(pbCMHIVE + o)))) { break; }
    }
    if(!f) { return FALSE; }
    po->CM.BaseBlock = o;
    // sizeof(_DUAL): WinVista -> Win10
    cbDual = 0x278;
    // _CMHIVE _HHIVE.STORAGE._DUAL[0]
    for(; o < 0x800; o += 8) {
        vaSmallDir = *(PQWORD)(pbCMHIVE + o + 0x010);                                           // _DUAL[0].SmallDir may be zero sometimes ...
        f = (*(PDWORD)(pbCMHIVE + o + 0x018) == 0xffffffff) &&                                  // _DUAL[0].Guard
            (*(PDWORD)(pbCMHIVE + o + 0x000) < 0x40000000) &&                                   // _DUAL[0].Length < 1GB
            VMM_KADDR64_8(*(PQWORD)(pbCMHIVE + o + 0x008)) &&                                   // _DUAL[0].Map = kernel 8-byte align
            ((vaSmallDir == 0) || VMM_KADDR64_PAGE(vaSmallDir)) &&                              // _DUAL[0].SmallDir = kernel page base
            VmmRead(H, pProcessSystem, *(PQWORD)(pbCMHIVE + o + 0x008), (PBYTE)&qw, sizeof(QWORD)) && // [_DUAL[0].Map]
            ((vaSmallDir == 0) || (vaSmallDir == qw));                                          // _DUAL[0].SmallDir = 1st entry in _DUAL.Map 'directory'
        if(f) { break; }
    }
    if(!f) { return FALSE; }
    po->CM.Length0 = o + 0x000;
    po->CM.StorageMap0 = o + 0x008;
    po->CM.StorageSmallDir0 = o + 0x010;
    o += cbDual;
    po->CM.Length1 = o + 0x000;
    po->CM.StorageMap1 = o + 0x008;
    po->CM.StorageSmallDir1 = o + 0x010;
    o += cbDual;
    // _CMHIVE _LIST_ENTRY
    for(; o < 0xff0; o += 8) {
        f = VMM_KADDR64_8(*(PQWORD)(pbCMHIVE + o)) &&                                           // FLinkAll
            VMM_KADDR64_8(*(PQWORD)(pbCMHIVE + o + 8)) &&                                       // BLink
            (*(PQWORD)(pbCMHIVE + o) != *(PQWORD)(pbCMHIVE + o + 8)) &&                         // FLinkAll != BLink
            ((*(PQWORD)(pbCMHIVE + o) - o) != vaCMHIVE) &&                                      // Not ptr to this CMHIVE
            VmmRead(H, pProcessSystem, *(PQWORD)(pbCMHIVE + o) + 8, (PBYTE)&qw, sizeof(QWORD)) &&  // Read FLinkAll->BLink
            (!vaCMHIVE || (qw - o == vaCMHIVE)) &&                                              // vaCMHIVE == FLinkAll->BLink
            VmmRead(H, pProcessSystem, ((*(PQWORD)(pbCMHIVE + o) - o)), (PBYTE)&dw, sizeof(DWORD)) &&
            (dw == 0xBEE0BEE0);                                                                 // Signature check
        if(f) { break; }
    }
    if(!f) { return FALSE; }
    po->CM.FLinkAll = o;
    // _CMHIVE UNICODE_STRING HiveRootPath (OPTIONAL)
    for(; o < 0xff0; o += 8) {
        f = (*(PWORD)(pbCMHIVE + o) <= *(PWORD)(pbCMHIVE + o + 2)) &&                           // UNICODE_STRING.Length <= UNICODE_STRING.MaxLength
            (*(PWORD)(pbCMHIVE + o) > 12) &&                                                    // UNICODE_STRING.Length > 12 (\\REGISTRY\\)
            (*(PWORD)(pbCMHIVE + o) < 0xff) &&                                                  // UNICODE_STRING.Length < 0xff
            VMM_KADDR64(*(PQWORD)(pbCMHIVE + o + 8)) &&                                         // Is kernel address
            VmmRead(H, pProcessSystem, *(PQWORD)(pbCMHIVE + o + 8), pbBuffer, 20) &&               // Read STRING
            !memcmp(pbBuffer, pbTEXT_REGISTRY, 20);                                             // Starts with '\REGISTRY\'
        if(f) { break; }
    }
    if(f) {
        po->CM.HiveRootPathOpt = o;
        po->CM.FileFullPathOpt = po->CM.HiveRootPathOpt - 0x020;
        po->CM.FileUserNameOpt = po->CM.HiveRootPathOpt - 0x010;
    }
    po->CM._Size = max(po->CM.FLinkAll, po->CM.HiveRootPathOpt) + 0x020;
    // _HMAP_ENTRY SIZE AND OFFSETS
    ZeroMemory(qwHE, sizeof(qwHE));
    po->HE._Size = 0x018;               // Most common (default try)
    if(!vaSmallDir) {
        VmmRead(H, pProcessSystem, *(PQWORD)(pbCMHIVE + po->CM.StorageMap0), (PBYTE)&vaSmallDir, sizeof(QWORD));
    }
    if((vaSmallDir & 0xffff800000000fff) == 0xffff800000000000) {
        VmmRead(H, pProcessSystem, vaSmallDir, (PBYTE)qwHE, sizeof(qwHE));
        f = _IS_HMAP_KDDR64(qwHE[0]) && _IS_HMAP_KDDR64(qwHE[1]) && _IS_HMAP_ZERO64(qwHE[2]) && _IS_HMAP_SIZE64(qwHE[3]) &&
            _IS_HMAP_ZERO64(qwHE[4]) && _IS_HMAP_ZERO64(qwHE[5]) && _IS_HMAP_ZERO64(qwHE[6]) && _IS_HMAP_ZERO64(qwHE[7]);
        if(f) { po->HE._Size = 0x20; }  // only 1 entry in table of length 0x20
        f = _IS_HMAP_KDDR64(qwHE[5]);
        if(f) { po->HE._Size = 0x20; }
        f = _IS_HMAP_ZERO64(qwHE[0]) && _IS_HMAP_KDDR64(qwHE[1]) && _IS_HMAP_SIZE64(qwHE[4]) &&
            _IS_HMAP_ZERO64(qwHE[5]) && _IS_HMAP_KDDR64(qwHE[6]) && _IS_HMAP_SIZE64(qwHE[9]);
        if(f) { po->HE._Size = 0x28; }
    }
    // BaseBlock (regf) static offsets
    po->BB.Signature = 0x000;
    po->BB.Length = 0x028;
    po->BB.Major = 0x014;
    po->BB.Minor = 0x018;
    po->BB.FileName = 0x030;
    // CMHIVE virtual address hint
    po->vaHintCMHIVE = vaCMHIVE ? vaCMHIVE : (*(PQWORD)(pbCMHIVE + po->CM.FLinkAll) - po->CM.FLinkAll);
    VmmWinReg_FuzzHiveOffsets_PrintResultVerbose(H, (PBYTE)qwHE, sizeof(qwHE));
    return TRUE;
}

BOOL VmmWinReg_FuzzHiveOffsets32(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcessSystem, _In_ QWORD vaCMHIVE, _In_reads_(0x1000) PBYTE pbCMHIVE)
{
    CONST BYTE pbTEXT_REGISTRY[] = { '\\', 0, 'R', 0, 'E', 0, 'G', 0, 'I', 0, 'S', 0, 'T', 0, 'R', 0, 'Y', 0, '\\', 0, };
    BOOL f;
    WORD o, cbDual;
    DWORD dw, vaSmallDir;
    BYTE pbBuffer[20];
    DWORD dwHE[0x10];
    PVMMWIN_REGISTRY_OFFSET po = &H->vmm.pRegistry->Offset;
    // _CMHIVE BASE
    for(o = 0; o < 0x40; o += 8) {
        if(*(PQWORD)(pbCMHIVE + o + 0x004) == 0xBEE0BEE030314D43) {
            pbCMHIVE = pbCMHIVE + o + 0x008;
            if(vaCMHIVE) { vaCMHIVE = vaCMHIVE + o + 0x008; }
            break;
        }
    }
    if(*(PDWORD)(pbCMHIVE + 0x000) != 0xBEE0BEE0) { return FALSE; }
    po = &H->vmm.pRegistry->Offset;
    po->CM.Signature = 0;
    // _CMHIVE.BaseBlock
    for(o = 0x18; o < 0x30; o += 4) {
        if((f = VMM_KADDR32_PAGE(*(PDWORD)(pbCMHIVE + o)))) { break; }
    }
    if(!f) { return FALSE; }
    po->CM.BaseBlock = o;
    // sizeof(_DUAL):
    if(H->vmm.kernel.dwVersionBuild < 6000) {
        cbDual = 0x0dc;     // WinXP
    } else if(H->vmm.kernel.dwVersionBuild < 9200) {
        cbDual = 0x13c;     // WinVista-Win7
    } else {
        cbDual = 0x19c;     // Win8+
    }
    // _CMHIVE _HHIVE.STORAGE._DUAL[0]
    for(; o < 0x400; o += 4) {
        vaSmallDir = *(PDWORD)(pbCMHIVE + o + 0x008);                                           // _DUAL[0].SmallDir may be zero sometimes ...
        f = (*(PDWORD)(pbCMHIVE + o + 0x00c) == 0xffffffff) &&                                  // _DUAL[0].Guard
            (*(PDWORD)(pbCMHIVE + o + 0x000) < 0x40000000) &&                                   // _DUAL[0].Length < 1GB
            VMM_KADDR32_4(*(PDWORD)(pbCMHIVE + o + 0x004)) &&                                   // _DUAL[0].Map = kernel 4-byte align
            ((vaSmallDir == 0) || VMM_KADDR32_PAGE(vaSmallDir)) &&                              // _DUAL[0].SmallDir = kernel page base
            VmmRead(H, pProcessSystem, *(PDWORD)(pbCMHIVE + o + 0x004), (PBYTE)&dw, sizeof(DWORD)) &&  // [_DUAL[0].Map]
            ((vaSmallDir == 0) || (vaSmallDir == dw));                                          // _DUAL[0].SmallDir = 1st entry in _DUAL.Map 'directory'
        if(f) { break; }
    }
    if(!f) { return FALSE; }
    po->CM.Length0 = o + 0x000;
    po->CM.StorageMap0 = o + 0x004;
    po->CM.StorageSmallDir0 = o + 0x008;
    o += cbDual;
    po->CM.Length1 = o + 0x000;
    po->CM.StorageMap1 = o + 0x004;
    po->CM.StorageSmallDir1 = o + 0x008;
    o += cbDual;
    // _CMHIVE _LIST_ENTRY
    for(; o < 0x800; o += 4) {
        f = VMM_KADDR32_4(*(PDWORD)(pbCMHIVE + o)) &&                                                       // FLinkAll
            VMM_KADDR32_4(*(PDWORD)(pbCMHIVE + o + 4)) &&                                                   // BLink
            (*(PDWORD)(pbCMHIVE + o) != *(PDWORD)(pbCMHIVE + o + 4)) &&                                     // FLinkAll != BLink
            VmmRead(H, pProcessSystem, *(PDWORD)(pbCMHIVE + o) + sizeof(DWORD), (PBYTE)&dw, sizeof(DWORD)) && // Read FLinkAll->BLink
            VmmRead(H, pProcessSystem, (QWORD)dw - o + po->CM.Signature, (PBYTE)&dw, sizeof(DWORD)) &&      // Read (FLinkAll->BLink) Signature
            (dw == 0xBEE0BEE0) &&                                                                           // Signature check
            VmmRead(H, pProcessSystem, *(PDWORD)(pbCMHIVE + o + 4), (PBYTE)&dw, sizeof(DWORD)) &&           // Read BLink->FLinkAll
            VmmRead(H, pProcessSystem, (QWORD)dw - o + po->CM.Signature, (PBYTE)&dw, sizeof(DWORD)) &&      // Read (BLink->FLinkAll) Signature
            (dw == 0xBEE0BEE0);                                                                             // Signature check
        if(f) { break; }
    }
    if(!f) { return FALSE; }
    po->CM.FLinkAll = o;
    // _CMHIVE UNICODE_STRING HiveRootPath
    for(o = po->CM.FLinkAll; o < 0xf00; o += 4) {
        f = (*(PWORD)(pbCMHIVE + o) <= *(PWORD)(pbCMHIVE + o + 2)) &&                           // UNICODE_STRING.Length <= UNICODE_STRING.MaxLength
            (*(PWORD)(pbCMHIVE + o) > 12) &&                                                    // UNICODE_STRING.Length > 12 (\\REGISTRY\\)
            (*(PWORD)(pbCMHIVE + o) < 0xff) &&                                                  // UNICODE_STRING.Length < 0xff
            VMM_KADDR32(*(PDWORD)(pbCMHIVE + o + 4)) &&                                         // Is kernel address
            VmmRead(H, pProcessSystem, *(PDWORD)(pbCMHIVE + o + 4), pbBuffer, 20) &&            // Read STRING
            !memcmp(pbBuffer, pbTEXT_REGISTRY, 20);                                             // Starts with '\REGISTRY\'
        if(f) {
            po->CM.HiveRootPathOpt = o;
            break;
        }
    }
    if(f) {
        po->CM.FileFullPathOpt = po->CM.HiveRootPathOpt - 0x010;
        po->CM.FileUserNameOpt = po->CM.HiveRootPathOpt - 0x008;
    }
    po->CM._Size = max(po->CM.FLinkAll, po->CM.HiveRootPathOpt) + 0x010;
    // _HMAP_ENTRY SIZE AND OFFSETS
    ZeroMemory(dwHE, sizeof(dwHE));
    po->HE._Size = 0x00c;               // Most common (default try)
    if(!vaSmallDir) {
        VmmRead(H, pProcessSystem, *(PDWORD)(pbCMHIVE + po->CM.StorageMap0), (PBYTE)&vaSmallDir, sizeof(DWORD));
    }
    if((vaSmallDir & 0x80000fff) == 0x80000000) {
        VmmRead(H, pProcessSystem, vaSmallDir, (PBYTE)dwHE, sizeof(dwHE));
        f = _IS_HMAP_ADDR32(dwHE[0]) && _IS_HMAP_ADDR32(dwHE[1]) && _IS_HMAP_SIZE32(dwHE[3]) &&
            _IS_HMAP_ADDR32(dwHE[4]) && _IS_HMAP_ADDR32(dwHE[5]) && _IS_HMAP_SIZE32(dwHE[7]);
        if(f) { po->HE._Size = 0x010; }
        f = _IS_HMAP_KDDR32(dwHE[0]) && _IS_HMAP_KDDR32(dwHE[1]) && _IS_HMAP_SIZE32(dwHE[3]) &&
            _IS_HMAP_ZERO32(dwHE[4]) && _IS_HMAP_ZERO32(dwHE[5]) && _IS_HMAP_ZERO32(dwHE[7]);
        if(f) { po->HE._Size = 0x10; }    // only 1 entry in table of length 0x10
        f = _IS_HMAP_ZERO32(dwHE[0]) && _IS_HMAP_ZERO32(dwHE[5]) && _IS_HMAP_SIZE32(dwHE[4]) && _IS_HMAP_SIZE32(dwHE[9]) &&
            _IS_HMAP_SIZE32(dwHE[15]) && _IS_HMAP_ADDR32(dwHE[1]) && _IS_HMAP_ADDR32(dwHE[6]) && _IS_HMAP_ADDR32(dwHE[11]);
        if(f) { po->HE._Size = 0x014; }
    }
    // BaseBlock (regf) static offsets
    po->BB.Signature = 0x000;
    po->BB.Length = 0x028;
    po->BB.Major = 0x014;
    po->BB.Minor = 0x018;
    po->BB.FileName = 0x030;
    // CMHIVE virtual address hint
    po->vaHintCMHIVE = vaCMHIVE ? vaCMHIVE : (*(PDWORD)(pbCMHIVE + po->CM.FLinkAll) - po->CM.FLinkAll);
    VmmWinReg_FuzzHiveOffsets_PrintResultVerbose(H, (PBYTE)dwHE, sizeof(dwHE));
    return TRUE;
}

/*
* Locate a registry hive. Once a single registry hive is located the linked
* list may be traversed to enumerate the remaining registry hives.
* The search algorithm looks for promising addresses in ntoskrnl.exe .data
* section and checks if any of these addresses are part of a CMHIVE. If the
* above technique fail then the lower memory is scanned (also fail sometimes).
* -- H
* -- return
*/
#define MAX_NUM_POTENTIAL_HIVE_HINT        0x20
BOOL VmmWinReg_LocateRegistryHive(_In_ VMM_HANDLE H)
{
    BOOL result = FALSE;
    BOOL f32 = H->vmm.f32;
    PVMM_PROCESS pObProcessSystem = VmmProcessGet(H, 4);
    IMAGE_SECTION_HEADER SectionHeader;
    DWORD iSection, cbSectionSize, cbPoolHdr, cbPoolHdrMax, cPotentialHive, o, p, i;
    QWORD vaPotentialHive[MAX_NUM_POTENTIAL_HIVE_HINT];
    PBYTE pb = NULL;
    PPMEM_SCATTER ppMEMs = NULL;
    if(!pObProcessSystem || !(pb = LocalAlloc(0, 0x01000000))) { goto cleanup; }
    // 1: Try locate registry by scanning ntoskrnl.exe .data section.
    for(iSection = 0; iSection < 2; iSection++) {    // 1st check '.data' section, then PAGEDATA' for pointers.
        if(!PE_SectionGetFromName(H, pObProcessSystem, H->vmm.kernel.vaBase, iSection ? "PAGEDATA" : ".data", &SectionHeader)) { goto cleanup; }
        cbSectionSize = min(0x01000000, SectionHeader.Misc.VirtualSize);
        VmmReadEx(H, pObProcessSystem, H->vmm.kernel.vaBase + SectionHeader.VirtualAddress, pb, min(0x01000000, SectionHeader.Misc.VirtualSize), NULL, VMM_FLAG_ZEROPAD_ON_FAIL);
        cbPoolHdrMax = f32 ? 0x08 : 0x10;
        for(cbPoolHdr = 0; cbPoolHdr <= cbPoolHdrMax; cbPoolHdr += cbPoolHdrMax) {
            for(cPotentialHive = 0, o = 0; o < cbSectionSize && cPotentialHive < MAX_NUM_POTENTIAL_HIVE_HINT; o += (f32 ? 4 : 8)) {
                if(f32) {
                    if((*(PDWORD)(pb + o) & 0x80000fff) == 0x80000000 + cbPoolHdr) {
                        vaPotentialHive[cPotentialHive++] = *(PDWORD)(pb + o);
                    }
                } else {
                    if((*(PQWORD)(pb + o) & 0xffff800000000fff) == (0xffff800000000000 + cbPoolHdr)) {
                        vaPotentialHive[cPotentialHive++] = *(PQWORD)(pb + o);
                    }
                }
            }
            if(!cPotentialHive) { continue; }
            if(!LcAllocScatter1(cPotentialHive, &ppMEMs)) { continue; }
            for(i = 0; i < cPotentialHive; i++) {
                ppMEMs[i]->qwA = vaPotentialHive[i] & ~0xfff;
            }
            VmmReadScatterVirtual(H, pObProcessSystem, ppMEMs, cPotentialHive, 0);
            for(i = 0; i < cPotentialHive; i++) {
                if(ppMEMs[i]->f) {
                    if((result = f32 ? VmmWinReg_FuzzHiveOffsets32(H, pObProcessSystem, ppMEMs[i]->qwA, ppMEMs[i]->pb) : VmmWinReg_FuzzHiveOffsets64(H, pObProcessSystem, ppMEMs[i]->qwA, ppMEMs[i]->pb))) {
                        goto cleanup;
                    }
                }
            }
        }
    }
    // 2: As a fallback - try locate registry by scanning lower physical memory.
    //    This is much slower, but will work sometimes when the above method fail.
    for(o = 0x00000000; o < 0x08000000; o += 0x01000000) {
        VmmReadEx(H, NULL, o, pb, 0x01000000, NULL, 0);
        for(p = 0; p < 0x01000000; p += 0x1000) {
            if((result = f32 ? VmmWinReg_FuzzHiveOffsets32(H, pObProcessSystem, 0, pb + p) : VmmWinReg_FuzzHiveOffsets64(H, pObProcessSystem, 0, pb + p))) {
                goto cleanup;
            }
        }
    }
cleanup:
    LocalFree(pb);
    LcMemFree(ppMEMs);
    Ob_DECREF(pObProcessSystem);
    return result;
}



//-----------------------------------------------------------------------------
// REGISTRY RETRIEVAL, INITIALIZATION AND ENUMERATION FUNCTIONALITY BELOW:
// If required first call the one-time offset fuzzer on first call.
// If required enumerate or re-enumerate all registry hives.
// If a re-enumeration is on-going and a parallell thread enters it will
//   receive the old copy of the registry for performance reasons.
// Enumeration/ListTraversal is done both 'efficiently' and 'lazy' on-demand.
//-----------------------------------------------------------------------------

VOID VmmWinReg_CallbackCleanup_ObRegistryHive(POB_REGISTRY_HIVE pOb)
{
    DeleteCriticalSection(&pOb->LockUpdate);
    Ob_DECREF(pOb->Snapshot.pmKeyHash);
    Ob_DECREF(pOb->Snapshot.pmKeyOffset);
    LocalFree(pOb->Snapshot._DUAL[0].pb);
    LocalFree(pOb->Snapshot._DUAL[1].pb);
}

/*
* Callback function from VmmWin_ListTraversePrefetch[32|64].
* Gather referenced addresses into prefetch dataset.
*/
VOID VmmWinReg_EnumHive64_Pre(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess, _In_opt_ POB_MAP pHiveMap, _In_ QWORD va, _In_ PBYTE pb, _In_ DWORD cb, _In_ QWORD vaFLink, _In_ QWORD vaBLink, _In_ POB_SET pVSetAddress, _Inout_ PBOOL pfValidEntry, _Inout_ PBOOL pfValidFLink, _Inout_ PBOOL pfValidBLink)
{
    PVMMWIN_REGISTRY_OFFSET po = &H->vmm.pRegistry->Offset;
    if((va & 0xffff800000000007) != 0xffff800000000000) { return; }               // not aligned kernel address
    *pfValidFLink = ((vaFLink & 0xffff800000000007) == 0xffff800000000000);       // aligned kernel address
    *pfValidBLink = ((vaBLink & 0xffff800000000007) == 0xffff800000000000);       // aligned kernel address
    if(*pfValidFLink && *pfValidBLink && (*(PDWORD)(pb + po->CM.Signature) == 0xBEE0BEE0) && ((*(PQWORD)(pb + po->CM.BaseBlock) & 0xfff) == 0x000)) {
        ObSet_Push(pVSetAddress, *(PQWORD)(pb + po->CM.BaseBlock));
        if(po->CM.HiveRootPathOpt && *(PQWORD)(pb + po->CM.HiveRootPathOpt)) {  // _CMHIVE.HiveRootPath
            ObSet_Push(pVSetAddress, *(PQWORD)(pb + po->CM.HiveRootPathOpt + 8) & ~0xfff);
        }
        *pfValidEntry = TRUE;
    }
}

VOID VmmWinReg_EnumHive32_Pre(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess, _In_opt_ POB_MAP pHiveMap, _In_ QWORD va, _In_ PBYTE pb, _In_ DWORD cb, _In_ QWORD vaFLink, _In_ QWORD vaBLink, _In_ POB_SET pVSetAddress, _Inout_ PBOOL pfValidEntry, _Inout_ PBOOL pfValidFLink, _Inout_ PBOOL pfValidBLink)
{
    PVMMWIN_REGISTRY_OFFSET po = &H->vmm.pRegistry->Offset;
    if((va & 0x80000007) != 0x80000000) { return; }         // not aligned kernel address
    *pfValidFLink = ((vaFLink & 0x80000003) == 0x80000000);       // aligned kernel address
    *pfValidBLink = ((vaBLink & 0x80000003) == 0x80000000);       // aligned kernel address
    if(*pfValidFLink && *pfValidBLink && (*(PDWORD)(pb + po->CM.Signature) == 0xBEE0BEE0) && ((*(PDWORD)(pb + po->CM.BaseBlock) & 0xfff) == 0x000)) {
        ObSet_Push(pVSetAddress, *(PDWORD)(pb + po->CM.BaseBlock));
        if(po->CM.HiveRootPathOpt && *(PDWORD)(pb + po->CM.HiveRootPathOpt)) {  // _CMHIVE.HiveRootPath
            ObSet_Push(pVSetAddress, *(PDWORD)(pb + po->CM.HiveRootPathOpt + 4) & ~0xfff);
        }
        *pfValidEntry = TRUE;
    }
}

VOID VmmWinReg_HiveGetShortName(_In_ POB_REGISTRY_HIVE pHive, _Out_writes_(32) LPSTR sz)
{
    DWORD i, iStart = 0;
    LPSTR szNS = pHive->uszNameShort;
    for(i = 0; i < 32; i++) {
        if(szNS[i] == '\\') { iStart = i + 1; }
    }
    for(i = 0; iStart < 32; iStart++) {
        if(((szNS[iStart] >= '0') && (szNS[iStart] <= '9')) || ((szNS[iStart] >= 'a') && (szNS[iStart] <= 'z')) || ((szNS[iStart] >= 'A') && (szNS[iStart] <= 'Z'))) { sz[i++] = szNS[iStart]; }
        if(!szNS[iStart]) { break; }
    }
}

/*
* Callback function from VmmWin_ListTraversePrefetch[32|64].
* Set up a single Registry Hive.
*/
VOID VmmWinReg_EnumHive64_Post(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess, _In_opt_ POB_MAP pHiveMap, _In_ QWORD vaData, _In_ PBYTE pbData, _In_ DWORD cbData)
{
    BOOL f;
    CHAR chDefault = '_';
    BOOL fBoolTrue = TRUE;
    CHAR szHiveFileNameShort[32+1] = { 0 };
    CHAR szHiveFileNameLong[72] = { 0 };
    POB_REGISTRY_HIVE pObHive = NULL;
    PVMMWIN_REGISTRY_OFFSET po = &H->vmm.pRegistry->Offset;
    // 1: validity check
    f = VMM_KADDR64_16(vaData) &&
        pHiveMap &&
        (*(PDWORD)(pbData + po->CM.Signature) == 0xBEE0BEE0) &&                 // Signature match
        (*(PQWORD)(pbData + po->CM.StorageMap0)) &&                             // _CMHIVE.Hive.Storage.Map
        (*(PDWORD)(pbData + po->CM.Length0)) &&                                  // Length > 0
        (*(PDWORD)(pbData + po->CM.Length0) <= 0x40000000);                      // Length < 1GB
    if(!f) { return; }
    // 2: Allocate and Initialize
    if(!(pObHive = Ob_AllocEx(H, OB_TAG_REG_HIVE, LMEM_ZEROINIT, sizeof(OB_REGISTRY_HIVE), (OB_CLEANUP_CB)VmmWinReg_CallbackCleanup_ObRegistryHive, NULL))) { return; }
    pObHive->vaCMHIVE = vaData;
    pObHive->vaHBASE_BLOCK = *(PQWORD)(pbData + po->CM.BaseBlock);
    pObHive->cbLength = *(PDWORD)(pbData + po->CM.Length0);
    pObHive->_DUAL[0].cb = *(PDWORD)(pbData + po->CM.Length0);
    pObHive->_DUAL[0].vaHMAP_DIRECTORY = *(PQWORD)(pbData + po->CM.StorageMap0);
    pObHive->_DUAL[0].vaHMAP_TABLE_SmallDir = *(PQWORD)(pbData + po->CM.StorageSmallDir0);
    pObHive->_DUAL[1].cb = *(PDWORD)(pbData + po->CM.Length1);
    pObHive->_DUAL[1].vaHMAP_DIRECTORY = *(PQWORD)(pbData + po->CM.StorageMap1);
    pObHive->_DUAL[1].vaHMAP_TABLE_SmallDir = *(PQWORD)(pbData + po->CM.StorageSmallDir1);
    InitializeCriticalSection(&pObHive->LockUpdate);
    //_HBASE_BLOCK.FileName
    VmmReadWtoU(
        H,
        pProcess,
        *(PQWORD)(pbData + po->CM.BaseBlock) + po->BB.FileName,
        2 * _countof(pObHive->uszNameShort) - 2,
        VMM_FLAG_ZEROPAD_ON_FAIL,
        (PBYTE)pObHive->uszNameShort,
        sizeof(pObHive->uszNameShort),
        NULL,
        NULL,
        CHARUTIL_FLAG_TRUNCATE_ONFAIL_NULLSTR | CHARUTIL_FLAG_STR_BUFONLY
    );
    if(po->CM.HiveRootPathOpt && *(PQWORD)(pbData + po->CM.HiveRootPathOpt)) {  // _CMHIVE.HiveRootPath
        VmmReadWtoU(
            H,
            pProcess,
            *(PQWORD)(pbData + po->CM.HiveRootPathOpt + 8),
            min(*(PWORD)(pbData + po->CM.HiveRootPathOpt), 2 * _countof(pObHive->uszHiveRootPath) - 2),
            VMM_FLAG_ZEROPAD_ON_FAIL,
            (PBYTE)pObHive->uszHiveRootPath,
            sizeof(pObHive->uszHiveRootPath),
            NULL,
            NULL,
            CHARUTIL_FLAG_TRUNCATE_ONFAIL_NULLSTR | CHARUTIL_FLAG_STR_BUFONLY
        );
    }
    if(!pObHive->uszHiveRootPath[0] && po->CM.FileUserNameOpt && *(PQWORD)(pbData + po->CM.FileUserNameOpt)) {  // _CMHIVE.FileUserName (as backup to _CMHIVE.HiveRootPath)
        VmmReadWtoU(
            H,
            pProcess,
            *(PQWORD)(pbData + po->CM.FileUserNameOpt + 8),
            min(*(PWORD)(pbData + po->CM.FileUserNameOpt), 2 * _countof(pObHive->uszHiveRootPath) - 2),
            VMM_FLAG_ZEROPAD_ON_FAIL,
            (PBYTE)pObHive->uszHiveRootPath,
            sizeof(pObHive->uszHiveRootPath),
            NULL,
            NULL,
            CHARUTIL_FLAG_TRUNCATE_ONFAIL_NULLSTR | CHARUTIL_FLAG_STR_BUFONLY
        );
    }
    // 3: Post processing
    if(strlen(pObHive->uszHiveRootPath) > 10) {
        CharUtil_UtoU(pObHive->uszHiveRootPath + 10, -1, szHiveFileNameLong, sizeof(szHiveFileNameLong), NULL, NULL, CHARUTIL_FLAG_TRUNCATE_ONFAIL_NULLSTR | CHARUTIL_FLAG_STR_BUFONLY);
        Util_AsciiFileNameFix(szHiveFileNameLong, '_');
    }
    VmmWinReg_HiveGetShortName(pObHive, szHiveFileNameShort);
    snprintf(
        pObHive->uszName,
        sizeof(pObHive->uszName) - 1,
        "0x%llx-%s-%s",
        pObHive->vaCMHIVE,
        (szHiveFileNameShort[0] ? szHiveFileNameShort : "unknown"),
        (szHiveFileNameLong[0] ? szHiveFileNameLong : "unknown"));
    // 4: Attach and Return
    ObMap_Push(pHiveMap, pObHive->vaCMHIVE, pObHive);
    VmmLog(H, MID_REGISTRY, LOGLEVEL_DEBUG, "HIVE_ENUM: %04i: %s", ObMap_Size(pHiveMap), pObHive->uszName);
    Ob_DECREF(pObHive);
}

VOID VmmWinReg_EnumHive32_Post(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess, _In_opt_ POB_MAP pHiveMap, _In_ QWORD vaData, _In_ PBYTE pbData, _In_ DWORD cbData)
{
    BOOL f;
    CHAR chDefault = '_';
    BOOL fBoolTrue = TRUE;
    CHAR szHiveFileNameShort[32+1] = { 0 };
    CHAR szHiveFileNameLong[72] = { 0 };
    POB_REGISTRY_HIVE pObHive = NULL;
    PVMMWIN_REGISTRY_OFFSET po = &H->vmm.pRegistry->Offset;
    // 1: validity check
    f = VMM_KADDR32_8(vaData) &&
        pHiveMap &&
        (*(PDWORD)(pbData + po->CM.Signature) == 0xBEE0BEE0) &&                 // Signature match
        !(*(PDWORD)(pbData + po->CM.BaseBlock) & 0xfff) &&                      // _CMHIVE.BaseBlock on page boundary
        (*(PQWORD)(pbData + po->CM.StorageMap0)) &&                             // _CMHIVE.Hive.Storage.Map
        (*(PDWORD)(pbData + po->CM.Length0)) &&                                  // Length > 0
        (*(PDWORD)(pbData + po->CM.Length0) <= 0x40000000);                      // Length < 1GB
    if(!f) { return; }
    // 2: Allocate and Initialize
    if(!(pObHive = Ob_AllocEx(H, OB_TAG_REG_HIVE, LMEM_ZEROINIT, sizeof(OB_REGISTRY_HIVE), (OB_CLEANUP_CB)VmmWinReg_CallbackCleanup_ObRegistryHive, NULL))) { return; }
    pObHive->vaCMHIVE = vaData;
    pObHive->vaHBASE_BLOCK = *(PDWORD)(pbData + po->CM.BaseBlock);
    pObHive->cbLength = *(PDWORD)(pbData + po->CM.Length0);
    pObHive->_DUAL[0].cb = *(PDWORD)(pbData + po->CM.Length0);
    pObHive->_DUAL[0].vaHMAP_DIRECTORY = *(PDWORD)(pbData + po->CM.StorageMap0);
    pObHive->_DUAL[0].vaHMAP_TABLE_SmallDir = *(PDWORD)(pbData + po->CM.StorageSmallDir0);
    pObHive->_DUAL[1].cb = *(PDWORD)(pbData + po->CM.Length1);
    pObHive->_DUAL[1].vaHMAP_DIRECTORY = *(PDWORD)(pbData + po->CM.StorageMap1);
    pObHive->_DUAL[1].vaHMAP_TABLE_SmallDir = *(PDWORD)(pbData + po->CM.StorageSmallDir1);
    InitializeCriticalSection(&pObHive->LockUpdate);
    //_HBASE_BLOCK.FileName
    VmmReadWtoU(
        H,
        pProcess,
        (QWORD)*(PDWORD)(pbData + po->CM.BaseBlock) + po->BB.FileName,
        2 * _countof(pObHive->uszNameShort) - 2,
        VMM_FLAG_ZEROPAD_ON_FAIL,
        (PBYTE)pObHive->uszNameShort,
        sizeof(pObHive->uszNameShort),
        NULL,
        NULL,
        CHARUTIL_FLAG_TRUNCATE_ONFAIL_NULLSTR | CHARUTIL_FLAG_STR_BUFONLY
    );
    if(po->CM.HiveRootPathOpt && *(PQWORD)(pbData + po->CM.HiveRootPathOpt)) {  // _CMHIVE.HiveRootPath
        VmmReadWtoU(
            H,
            pProcess,
            *(PDWORD)(pbData + po->CM.HiveRootPathOpt + 4),
            min(*(PWORD)(pbData + po->CM.HiveRootPathOpt), 2 * _countof(pObHive->uszHiveRootPath) - 2),
            VMM_FLAG_ZEROPAD_ON_FAIL,
            (PBYTE)pObHive->uszHiveRootPath,
            sizeof(pObHive->uszHiveRootPath),
            NULL,
            NULL,
            CHARUTIL_FLAG_TRUNCATE_ONFAIL_NULLSTR | CHARUTIL_FLAG_STR_BUFONLY
        );
    }
    if(!pObHive->uszHiveRootPath[0] && po->CM.FileUserNameOpt && *(PQWORD)(pbData + po->CM.FileUserNameOpt)) {  // _CMHIVE.FileUserName (as backup to _CMHIVE.HiveRootPath)
        VmmReadWtoU(
            H,
            pProcess,
            *(PDWORD)(pbData + po->CM.FileUserNameOpt + 4),
            min(*(PWORD)(pbData + po->CM.FileUserNameOpt), 2 * _countof(pObHive->uszHiveRootPath) - 2),
            VMM_FLAG_ZEROPAD_ON_FAIL,
            (PBYTE)pObHive->uszHiveRootPath,
            sizeof(pObHive->uszHiveRootPath),
            NULL,
            NULL,
            CHARUTIL_FLAG_TRUNCATE_ONFAIL_NULLSTR | CHARUTIL_FLAG_STR_BUFONLY
        );
    }
    // 3: Post processing
    if(strlen(pObHive->uszHiveRootPath) > 10) {
        CharUtil_UtoU(pObHive->uszHiveRootPath + 10, -1, szHiveFileNameLong, sizeof(szHiveFileNameLong), NULL, NULL, CHARUTIL_FLAG_TRUNCATE_ONFAIL_NULLSTR | CHARUTIL_FLAG_STR_BUFONLY);
        Util_AsciiFileNameFix(szHiveFileNameLong, '_');
    }
    VmmWinReg_HiveGetShortName(pObHive, szHiveFileNameShort);
    snprintf(
        pObHive->uszName,
        sizeof(pObHive->uszName) - 1,
        "0x%llx-%s-%s",
        pObHive->vaCMHIVE,
        (szHiveFileNameShort[0] ? szHiveFileNameShort : "unknown"),
        (szHiveFileNameLong[0] ? szHiveFileNameLong : "unknown"));
    // 4: Attach and Return
    ObMap_Push(pHiveMap, pObHive->vaCMHIVE, pObHive);                   // pRegistry->pmHive takes responsibility for pObHive reference
    VmmLog(H, MID_REGISTRY, LOGLEVEL_DEBUG, "HIVE_ENUM: %04i: %s", ObMap_Size(pHiveMap), pObHive->uszName);
}

/*
* Internal function to create / set up a new registry objects.
* NB! This function must NOT be called in a multi-threaded way.
* CALLER DECREF: return
* -- H
* -- return
*/
POB_MAP VmmWinReg_HiveMap_New(_In_ VMM_HANDLE H)
{
    BOOL f32 = H->vmm.f32;
    POB_MAP pObHiveMap = NULL;
    PVMM_PROCESS pObProcessSystem = NULL;
    if(!(pObProcessSystem = VmmProcessGet(H, 4))) { goto fail; }    
    if(!H->vmm.pRegistry->Offset.vaHintCMHIVE && !VmmWinReg_LocateRegistryHive(H)) { goto fail; }
    if(!(pObHiveMap = ObMap_New(H, OB_MAP_FLAGS_OBJECT_OB))) { goto fail; }
    // Traverse the CMHIVE linked list in an efficient way
    VmmWin_ListTraversePrefetch(
        H,
        pObProcessSystem,
        f32,
        pObHiveMap,
        1,
        &H->vmm.pRegistry->Offset.vaHintCMHIVE,
        H->vmm.pRegistry->Offset.CM.FLinkAll,
        H->vmm.pRegistry->Offset.CM._Size,
        (VMMWIN_LISTTRAVERSE_PRE_CB)(f32 ? VmmWinReg_EnumHive32_Pre : VmmWinReg_EnumHive64_Pre),
        (VMMWIN_LISTTRAVERSE_POST_CB)(f32 ? VmmWinReg_EnumHive32_Post : VmmWinReg_EnumHive64_Post),
        H->vmm.pObCCachePrefetchRegistry);
    ObContainer_SetOb(H->vmm.pRegistry->pObCHiveMap, pObHiveMap);
    Ob_DECREF(pObProcessSystem);
    return pObHiveMap;
fail:
    Ob_DECREF(pObHiveMap);
    Ob_DECREF(pObProcessSystem);
    return NULL;
}

/*
* Retrieve the hive map containing the hive objects.
* If the map is not yet initialized this call will initalize the hive map.
* CALLER DECREF: return
* -- H
* -- return = a map containing the hive objects
*/
POB_MAP VmmWinReg_HiveMap(_In_ VMM_HANDLE H)
{
    POB_MAP pObHiveMap;
    if(!H->vmm.pRegistry) { return NULL; }
    pObHiveMap = ObContainer_GetOb(H->vmm.pRegistry->pObCHiveMap);
    if(!pObHiveMap) {
        EnterCriticalSection(&H->vmm.pRegistry->LockUpdate);
        pObHiveMap = ObContainer_GetOb(H->vmm.pRegistry->pObCHiveMap);
        if(!pObHiveMap) {
            pObHiveMap = VmmWinReg_HiveMap_New(H);
        }
        LeaveCriticalSection(&H->vmm.pRegistry->LockUpdate);
    }
    return pObHiveMap;
}

_Success_(return)
BOOL VmmWinReg_KeyInitialize(_In_ VMM_HANDLE H, _In_ POB_REGISTRY_HIVE pHive);

/*
* Ensure a registry hive snapshot is taken of the hive and stored within the
* hive object. A snapshot is created by copying the whole registry hive into
* memory and performing analysis on it to generate a key tree for convenient
* parsing of the keys. Any keys derived from the hive must never be used after
* Ob_DECREF has been called on the hive.
* -- H
* -- pHive
* -- return
*/
_Success_(return)
BOOL VmmWinReg_HiveSnapshotEnsure(_In_ VMM_HANDLE H, _In_ POB_REGISTRY_HIVE pHive)
{
    DWORD i, cbRead;
    // 1: check already cached
    if(!pHive) { return FALSE; }
    if(pHive->Snapshot.fInitialized) { return TRUE; }
    if(pHive->cbLength > 0x10000000) { return FALSE; }      // max 256MB hive
    // 2: lock and retry retrieve cached
    EnterCriticalSection(&pHive->LockUpdate);
    if(pHive->Snapshot.fInitialized) {
        LeaveCriticalSection(&pHive->LockUpdate);
        return TRUE;
    }
    // 3: allocate new
    pHive->Snapshot.pmKeyHash = ObMap_New(H, OB_MAP_FLAGS_OBJECT_OB);
    pHive->Snapshot.pmKeyOffset = ObMap_New(H, OB_MAP_FLAGS_OBJECT_OB);
    if(!pHive->Snapshot.pmKeyHash || !pHive->Snapshot.pmKeyOffset) { goto fail; }
    for(i = 0; i < 2; i++) {
        pHive->Snapshot._DUAL[i].cb = pHive->_DUAL[i].cb;
        if(!(pHive->Snapshot._DUAL[i].pb = LocalAlloc(0, pHive->Snapshot._DUAL[i].cb))) { goto fail; }
        VmmWinReg_HiveReadEx(H, pHive, (i ? 0x80000000 : 0), pHive->Snapshot._DUAL[i].pb, pHive->Snapshot._DUAL[i].cb, &cbRead, VMM_FLAG_ZEROPAD_ON_FAIL);
    }
    if(!VmmWinReg_KeyInitialize(H, pHive)) { goto fail; }
    pHive->Snapshot.fInitialized = TRUE;
    LeaveCriticalSection(&pHive->LockUpdate);
    return TRUE;
fail:
    Ob_DECREF_NULL(&pHive->Snapshot.pmKeyHash);
    Ob_DECREF_NULL(&pHive->Snapshot.pmKeyOffset);
    LocalFree(pHive->Snapshot._DUAL[0].pb);
    LocalFree(pHive->Snapshot._DUAL[1].pb);
    pHive->Snapshot._DUAL[0].pb = NULL;
    pHive->Snapshot._DUAL[1].pb = NULL;
    LeaveCriticalSection(&pHive->LockUpdate);
    return FALSE;
}



//-----------------------------------------------------------------------------
// EXPORTED INITIALIZATION/REFRESH/CLOSE FUNCTIONALITY BELOW:
//-----------------------------------------------------------------------------

VOID VmmWinReg_Initialize(_In_ VMM_HANDLE H)
{
    PVMMWIN_REGISTRY_CONTEXT ctx;
    if(!(ctx = LocalAlloc(LMEM_ZEROINIT, sizeof(VMMWIN_REGISTRY_CONTEXT)))) { goto fail; }
    if(!(ctx->pObCHiveMap = ObContainer_New())) { goto fail; }
    InitializeCriticalSection(&ctx->LockUpdate);
    H->vmm.pRegistry = ctx;
    return;
fail:
    if(ctx) {
        Ob_DECREF(ctx->pObCHiveMap);
        LocalFree(ctx);
    }
}

VOID VmmWinReg_Close(_In_ VMM_HANDLE H)
{
    if(H->vmm.pRegistry) {
        Ob_DECREF(H->vmm.pRegistry->pObCHiveMap);
        DeleteCriticalSection(&H->vmm.pRegistry->LockUpdate);
        LocalFree(H->vmm.pRegistry);
        H->vmm.pRegistry = NULL;
    }
}

VOID VmmWinReg_Refresh(_In_ VMM_HANDLE H)
{
    if(H->vmm.pRegistry) {
        ObContainer_SetOb(H->vmm.pRegistry->pObCHiveMap, NULL);
    }
}



//-----------------------------------------------------------------------------
// EXPORTED HIVE FUNCTIONALITY BELOW:
//-----------------------------------------------------------------------------

DWORD VmmWinReg_HiveCount(_In_ VMM_HANDLE H)
{
    DWORD c;
    POB_MAP pObHiveMap = VmmWinReg_HiveMap(H);
    c = ObMap_Size(pObHiveMap);
    Ob_DECREF(pObHiveMap);
    return c;
}

POB_REGISTRY_HIVE VmmWinReg_HiveGetNext(_In_ VMM_HANDLE H, _In_opt_ POB_REGISTRY_HIVE pObRegistryHive)
{
    POB_MAP pObHiveMap;
    POB_REGISTRY_HIVE pObRegistryHiveReturn = NULL;
    if((pObHiveMap = VmmWinReg_HiveMap(H))) {
        pObRegistryHiveReturn = ObMap_GetNextByKey(pObHiveMap, (pObRegistryHive ? pObRegistryHive->vaCMHIVE : 0), pObRegistryHive);
        pObRegistryHive = NULL;
    }
    Ob_DECREF(pObHiveMap);
    Ob_DECREF(pObRegistryHive);
    return pObRegistryHiveReturn;
}

POB_REGISTRY_HIVE VmmWinReg_HiveGetByAddress(_In_ VMM_HANDLE H, _In_ QWORD vaCMHIVE)
{
    POB_MAP pObHiveMap;
    POB_REGISTRY_HIVE pObRegistryHiveReturn = NULL;
    if((pObHiveMap = VmmWinReg_HiveMap(H))) {
        pObRegistryHiveReturn = ObMap_GetByKey(pObHiveMap, vaCMHIVE);
    }
    Ob_DECREF(pObHiveMap);
    return pObRegistryHiveReturn;
}



//-----------------------------------------------------------------------------
// REGISTRY KEY AND VALUE FUNCTIONALITY:
// - Internal functionality
//-----------------------------------------------------------------------------

#pragma pack(push, 4)

#define REG_CM_KEY_SIGNATURE_KEYNODE        0x6B6E  // 'nk'-key
#define REG_CM_KEY_SIGNATURE_KEYVALUE       0x6B76  // 'vk'-key
#define REG_CM_HASH_LEAF_SIGNATURE          0x686C  // 'hl'-key
#define REG_CM_KEY_SIGNATURE_BIGDATA        0x6264  // 'db'-key

#define REG_CM_KEY_VALUE_FLAGS_COMP_NAME    0x01
#define REG_CM_KEY_NODE_FLAGS_COMP_NAME     0x20
#define REG_CM_KEY_NODE_FLAGS_HIVE_ENTRY    0x04

typedef struct tdREG_CM_KEY_REFERENCE {
    DWORD KeyCell;              // +0x000 KeyCell : Uint4B
    QWORD vaKeyHive;            // +0x008 KeyHive : Ptr64 _HHIVE
} REG_CM_KEY_REFERENCE, *PREG_CM_KEY_REFERENCE;

typedef struct tdREG_CHILD_LIST {
    DWORD Count;                // +0x000 Count : Uint4B
    DWORD List;                 // +0x004 List : Uint4B
} REG_CHILD_LIST, * PREG_CHILD_LIST;

// "nk-key"
typedef struct tdREG_CM_KEY_NODE {
    WORD Signature;             // +0x000 Signature : Uint2B
    WORD Flags;                 // +0x002 Flags : Uint2B
    QWORD LastWriteTime;        // +0x004 LastWriteTime : _LARGE_INTEGER
    BYTE AccessBits;            // +0x00c AccessBits : UChar
    BYTE LayerSemantics : 2;    // +0x00d LayerSemantics : Pos 0, 2 Bits
    BYTE Spare1 : 5;            // +0x00d Spare1 : Pos 2, 5 Bits
    BYTE InheritClass : 1;      // +0x00d InheritClass : Pos 7, 1 Bit
    WORD Spare2;                // +0x00e Spare2 : Uint2B
    DWORD Parent;               // +0x010 Parent : Uint4B [parent "nk-key"]
    DWORD SubKeyCounts[2];      // +0x014 SubKeyCounts : [2] Uint4B        // [0] = persistent, [1] = volatile
    union {
        struct {
            DWORD SubKeyLists[2];       // +0x01c SubKeyLists : [2] Uint4B        // [0] = persistent, [1] = volatile
            REG_CHILD_LIST ValueList;   // +0x024 ValueList : _CHILD_LIST
        };
        REG_CM_KEY_REFERENCE ChildHiveReference;    // +0x01c ChildHiveReference : _CM_KEY_REFERENCE
    };
    DWORD Security;             // +0x02c Security : Uint4B
    DWORD Class;                // +0x030 Class : Uint4B
    DWORD MaxNameLen : 16;      // +0x034 MaxNameLen : Pos 0, 16 Bits
    DWORD UserFlags : 4;        // +0x034 UserFlags : Pos 16, 4 Bits
    DWORD VirtControlFlags : 4; // +0x034 VirtControlFlags : Pos 20, 4 Bits
    DWORD Debug : 8;            // +0x034 Debug : Pos 24, 8 Bits
    DWORD MaxClassLen;          // +0x038 MaxClassLen : Uint4B
    DWORD MaxValueNameLen;      // +0x03c MaxValueNameLen : Uint4B
    DWORD MaxValueDataLen;      // +0x040 MaxValueDataLen : Uint4B
    DWORD WorkVar;              // +0x044 WorkVar : Uint4B
    WORD NameLength;            // +0x048 NameLength : Uint2B
    WORD ClassLength;           // +0x04a ClassLength : Uint2B
    union {
        CHAR szName[1];          // +0x04c Name : [1] Wchar
        WCHAR wszName[1];        // +0x04c Name : [1] Wchar
    };
} REG_CM_KEY_NODE, *PREG_CM_KEY_NODE;

// "vk-key-value"
typedef struct tdREG_CM_KEY_VALUE {
    WORD Signature;             // 0x000 Signature : Uint2B
    WORD NameLength;            // 0x002 NameLength : Uint2B
    DWORD DataLength;           // 0x004 DataLength : Uint4B
    DWORD Data;                 // 0x008 Data : Uint4B
    DWORD Type;                 // 0x00c Type : Uint4B
    WORD Flags;                 // 0x010 Flags : Uint2B
    WORD Spare;                 // 0x012 Spare : Uint2B
    union {
        CHAR szName[1];          // +0x014 Name : [1] Wchar
        WCHAR wszName[1];        // +0x014 Name : [1] Wchar
    };
} REG_CM_KEY_VALUE, *PREG_CM_KEY_VALUE;

typedef struct tdREG_CM_BIG_DATA {
    WORD Signature;             // +0x000 Signature : Uint2B
    WORD Count;                 // +0x002 Count : Uint2B
    DWORD List;                 // +0x004 List : Uint4B
} REG_CM_BIG_DATA, *PREG_CM_BIG_DATA;

#pragma pack(pop)

typedef struct tdOB_REGISTRY_KEY {
    OB ObHdr;
    DWORD dwCellHead;
    DWORD oCell;
    WORD cbCell;
    WORD iSuffix;                   // suffix (0-9) (order/count) for keys with identical name/parent
    QWORD qwHashKeyParent;          // parent key hash (calculated on file system compatible hash)
    QWORD qwHashKeyThis;            // this key hash (calculated on file system compatible hash)
    PREG_CM_KEY_NODE pKey;          // points into pHive->Snapshot.pb (must not be free'd)
    struct {
        DWORD c;
        DWORD cMax;
        PDWORD po;
    } Child;
} OB_REGISTRY_KEY, *POB_REGISTRY_KEY;

typedef struct tdOB_REGISTRY_VALUE {
    OB ObHdr;
    DWORD dwCellHead;
    DWORD oCell;
    DWORD cbCell;
    PREG_CM_KEY_VALUE pValue;
} OB_REGISTRY_VALUE, *POB_REGISTRY_VALUE;

#define REG_CM_KEY_NODE_SIZEOF                      (sizeof(REG_CM_KEY_NODE)-4)         // excl. variable end
#define REG_CM_KEY_VALUE_SIZEOF                     (sizeof(REG_CM_KEY_VALUE)-4)        // excl. variable end

#define REG_CELL_ISACTIVE(dwCellHead)               (dwCellHead >> 31)
#define REG_CELL_SIZE(dwCellHead)                   ((dwCellHead >> 31) ? (DWORD)(0-dwCellHead) : dwCellHead)
#define REG_CELL_SIZE_EX(pb, dwCellHead)             REG_CELL_SIZE(*(PDWORD)(pb + (dwCellHead)))

#define REG_CELL_SV(oCell)                          (oCell >> 31)                       // static/volatile bit
#define REG_CELL_ORAW(oCell)                        (oCell & 0x7fffffff)                // raw cell offset (from a static/volatile offset)

VOID VmmWinReg_CallbackCleanup_ObRegKey(POB_REGISTRY_KEY pOb)
{
    LocalFree(pOb->Child.po);
}

/*
* Hash a registry key name in a way that is supported by the file system.
* NB! this is not the same hash as the Windows registry uses.
* -- pnk
* -- iSuffix
* -- return
*/
DWORD VmmWinReg_KeyHashName(_In_ PREG_CM_KEY_NODE pnk, _In_ DWORD iSuffix)
{
    DWORD i, c, dwHash = 0;
    CHAR uszBuffer[2 * MAX_PATH];
    c = (pnk->Flags & REG_CM_KEY_NODE_FLAGS_COMP_NAME) ?
        CharUtil_FixFsName(uszBuffer, sizeof(uszBuffer), NULL, pnk->szName, NULL, pnk->NameLength, iSuffix, TRUE) :
        CharUtil_FixFsName(uszBuffer, sizeof(uszBuffer), NULL, NULL, pnk->wszName, pnk->NameLength, iSuffix, TRUE);
    if(c) { c--; }
    for(i = 0; i < c; i++) {
        dwHash = ((dwHash >> 13) | (dwHash << 19)) + uszBuffer[i];
    }
    return dwHash;
}

/*
* Hash a directly dependent child by name.
* -- pParentKey
* -- uszPath
* -- return
*/
QWORD VmmWinReg_KeyHashChildName(_In_ POB_REGISTRY_KEY pParentKey, _In_ LPSTR uszChildName)
{
    return CharUtil_HashNameFsU(uszChildName, 0) + ((pParentKey->qwHashKeyThis >> 13) | (pParentKey->qwHashKeyThis << 51));
}

/*
* Helper function to validate the sanity of a Cell Size.
* -- pHive
* -- oCell = cell offset (incl. SV-bit).
* -- cbCellSizeMin
* -- cbCellSizeMax
* -- return
*/
BOOL VmmWinReg_KeyValidateCellSize(_In_ POB_REGISTRY_HIVE pHive, _In_ DWORD oCell, _In_ DWORD cbCellSizeMin, _In_ DWORD cbCellSizeMax)
{
    DWORD iSV, cbCell;
    iSV = oCell >> 31;
    oCell = oCell & 0x7fffffff;
    if(oCell + 4 > pHive->Snapshot._DUAL[iSV].cb) { return FALSE; }
    cbCell = REG_CELL_SIZE_EX(pHive->Snapshot._DUAL[iSV].pb, oCell);
    if((cbCell < cbCellSizeMin) || (cbCell > cbCellSizeMax) || (oCell + cbCell > pHive->Snapshot._DUAL[iSV].cb)) { return FALSE; }
    if(((oCell & 0xfff) + cbCell > 0x1000) && (REG_SIGNATURE_HBIN == *(PDWORD)(pHive->Snapshot._DUAL[iSV].pb + ((oCell + 0xfff) & ~0xfff)))) { return FALSE; }
    return TRUE;
}

/*
* Add a child key reference to a parent key.
* -- pObKeyParent
* -- oCellChild
*/
VOID VmmWinReg_KeyInitializeCreateKey_AddChild(_In_opt_ POB_REGISTRY_KEY pObKeyParent, _In_ DWORD oCellChild)
{
    DWORD cMax;
    PDWORD poNew;
    if(!pObKeyParent) { return; }
    if(pObKeyParent->Child.c == pObKeyParent->Child.cMax) {
        cMax = pObKeyParent->Child.cMax ? pObKeyParent->Child.cMax * 2 : 4;
        if(!(poNew = LocalAlloc(0, cMax * sizeof(DWORD)))) { return; }
        if(pObKeyParent->Child.po) {
            memcpy(poNew, pObKeyParent->Child.po, pObKeyParent->Child.c * sizeof(DWORD));
        }
        LocalFree(pObKeyParent->Child.po);
        pObKeyParent->Child.po = poNew;
        pObKeyParent->Child.cMax = cMax;
    }
    pObKeyParent->Child.po[pObKeyParent->Child.c++] = oCellChild;
}

/*
* Try to create a new key from a given hbin offset.
* CALLER DECREF: return
* -- H
* -- pHive
* -- oCell
* -- iLevel
* -- return
*/
POB_REGISTRY_KEY VmmWinReg_KeyInitializeCreateKey(_In_ VMM_HANDLE H, _In_ POB_REGISTRY_HIVE pHive, _In_ DWORD oCell, _In_ DWORD iLevel)
{
    QWORD qwKeyHash;
    WORD iSuffix = 0;
    DWORD iSV, oCellRaw, dwCellHead, cbCell, cbKey, dwNameHash;
	PREG_CM_KEY_NODE pnk;
	POB_REGISTRY_KEY pObKeyParent = NULL, pObKey = NULL;
	// 1: already exists in cache ?
	if((pObKey = ObMap_GetByKey(pHive->Snapshot.pmKeyOffset, oCell))) {
		if(Ob_VALID_TAG(pObKey, OB_TAG_REG_KEY)) { return pObKey; }
		Ob_DECREF_NULL(&pObKey);
	}
	// 2: retrieve key & validate
    if(!VmmWinReg_KeyValidateCellSize(pHive, oCell, REG_CM_KEY_NODE_SIZEOF + 4, 0x1000)) { goto fail; }
    iSV = REG_CELL_SV(oCell);
    oCellRaw = REG_CELL_ORAW(oCell);
	dwCellHead = *(PDWORD)(pHive->Snapshot._DUAL[iSV].pb + oCellRaw);
	cbCell = REG_CELL_SIZE(dwCellHead);
	cbKey = cbCell - 4;
	pnk = (PREG_CM_KEY_NODE)(pHive->Snapshot._DUAL[iSV].pb + oCellRaw + 4);
    if(pnk->Signature != REG_CM_KEY_SIGNATURE_KEYNODE) { goto fail; }
	if(((QWORD)pnk->NameLength << ((pnk->Flags & REG_CM_KEY_NODE_FLAGS_COMP_NAME) ? 0 : 1)) > (cbKey - REG_CM_KEY_NODE_SIZEOF)) { goto fail; }
    if(pnk->Parent == oCell) { goto fail; }
	// 3: get parent key
	pObKeyParent = ObMap_GetByKey(pHive->Snapshot.pmKeyOffset, pnk->Parent);
	if(!pObKeyParent) {
		if(iLevel < 0x10) {
			pObKeyParent = VmmWinReg_KeyInitializeCreateKey(H, pHive, pnk->Parent, iLevel + 1);
		}
        if(!pObKeyParent) {
            pObKeyParent = ObMap_GetByKey(pHive->Snapshot.pmKeyOffset, pnk->Parent);
        }
		if(!pObKeyParent) {
			pObKeyParent = ObMap_GetByIndex(pHive->Snapshot.pmKeyOffset, 1);		// e[0] = ROOT, e[1] = orphan root
		}
	}
    // 4: check for and adjust for duplicate key names at different offsets
    if(ObMap_ExistsKey(pHive->Snapshot.pmKeyOffset, oCell)) {
        goto fail;
    }
    while(TRUE) {
        qwKeyHash = dwNameHash = VmmWinReg_KeyHashName(pnk, iSuffix);
        qwKeyHash += pObKeyParent ? ((pObKeyParent->qwHashKeyThis >> 13) | (pObKeyParent->qwHashKeyThis << 51)) : 0;
        if(!ObMap_ExistsKey(pHive->Snapshot.pmKeyHash, qwKeyHash)) { break; }
        if(iSuffix == 9) { goto fail; }
        iSuffix++;
    }
	// 5: allocate and prepare
	pObKey = Ob_AllocEx(H, OB_TAG_REG_KEY, LMEM_ZEROINIT, sizeof(OB_REGISTRY_KEY), (OB_CLEANUP_CB)VmmWinReg_CallbackCleanup_ObRegKey, NULL);
	if(!pObKey) { goto fail; }
    pObKey->dwCellHead = dwCellHead;
    pObKey->iSuffix = iSuffix;
	pObKey->oCell = oCell;
	pObKey->cbCell = (WORD)cbCell;
    pObKey->pKey = pnk;
	// 6: calculate lookup hashes
	pObKey->qwHashKeyParent = pObKeyParent ? pObKeyParent->qwHashKeyThis : 0;
	pObKey->qwHashKeyThis = VmmWinReg_KeyHashName(pnk, iSuffix) + ((pObKey->qwHashKeyParent >> 13) | (pObKey->qwHashKeyParent << 51));
	// 7: store to cache
    if(!ObMap_Push(pHive->Snapshot.pmKeyOffset, oCell, pObKey)) {
        VmmLog(H, MID_REGISTRY, LOGLEVEL_WARNING, "SHOULD NOT HAPPEN #1");
    }
    if(!ObMap_Push(pHive->Snapshot.pmKeyHash, pObKey->qwHashKeyThis, pObKey)) {
        VmmLog(H, MID_REGISTRY, LOGLEVEL_WARNING, "SHOULD NOT HAPPEN #2");
    }
    VmmWinReg_KeyInitializeCreateKey_AddChild(pObKeyParent, oCell);
	Ob_INCREF(pObKey);
fail:
	Ob_DECREF(pObKeyParent);
	return Ob_DECREF(pObKey);
}

/*
* Create a dummy key - used to create 'ROOT' and 'ORPHAN' root keys.
* (Helper function to VmmWinReg_KeyInitializeRootKey)
* CALLER DECREF: return
* -- H
* -- pHive
* -- oCell
* -- qwKeyParentHash
* -- uszName
* -- fActive
* -- return
*/
POB_REGISTRY_KEY VmmWinReg_KeyInitializeRootKeyDummy(_In_ VMM_HANDLE H, _In_ POB_REGISTRY_HIVE pHive, _In_ DWORD oCell, _In_ QWORD qwKeyParentHash, _In_ LPSTR uszName, _In_ BOOL fActive)
{
    DWORD cbw;
	WORD cbuName;
	POB_REGISTRY_KEY pObKey = NULL;
    cbuName = (WORD)(strlen(uszName) + 1);
	// 1: allocate dummy entry
	pObKey = Ob_AllocEx(H, OB_TAG_REG_KEY, LMEM_ZEROINIT, sizeof(OB_REGISTRY_KEY) + REG_CM_KEY_NODE_SIZEOF + 2ULL * cbuName, (OB_CLEANUP_CB)VmmWinReg_CallbackCleanup_ObRegKey, NULL);
	if(!pObKey) { return NULL; }
	pObKey->oCell = oCell;
	pObKey->cbCell = 4 + REG_CM_KEY_NODE_SIZEOF + cbuName * 2ULL - 2;
    pObKey->dwCellHead = pObKey->oCell + (fActive ? 0x80000000 : 0);
    pObKey->pKey = (PREG_CM_KEY_NODE)((PBYTE)pObKey + sizeof(OB_REGISTRY_KEY));
    CharUtil_UtoW(uszName, -1, (PBYTE)&pObKey->pKey->wszName, 2 * cbuName, NULL, &cbw, CHARUTIL_FLAG_TRUNCATE_ONFAIL_NULLSTR | CHARUTIL_FLAG_STR_BUFONLY);
	pObKey->pKey->NameLength = cbw ? (WORD)(cbw >> 1) - 1 : 0;
	// 2: calculate lookup hashes
	pObKey->qwHashKeyParent = qwKeyParentHash;
	pObKey->qwHashKeyThis = CharUtil_HashNameFsU(uszName, 0) + ((pObKey->qwHashKeyParent >> 13) | (pObKey->qwHashKeyParent << 51));
	// 3: store to cache and return
	ObMap_Push(pHive->Snapshot.pmKeyHash, pObKey->qwHashKeyThis, pObKey);
	ObMap_Push(pHive->Snapshot.pmKeyOffset, oCell, pObKey);
	return pObKey;
}

/*
* Create a dummy key - used to create 'ROOT' and 'ORPHAN' root keys.
* -- H
* -- pHive
* -- return
*/
_Success_(return)
BOOL VmmWinReg_KeyInitializeRootKey(_In_ VMM_HANDLE H, _In_ POB_REGISTRY_HIVE pHive)
{
    PREG_CM_KEY_NODE pnk;
    DWORD i, oRootKey = -1, cbCell, cbKey;
	QWORD qwKeyRootHash = 0;
    // 1: get root key offset from regf-header (this is most often 0x20)
    if(!VmmRead(H, PVMM_PROCESS_SYSTEM, pHive->vaHBASE_BLOCK + 0x24, (PBYTE)&oRootKey, sizeof(DWORD)) || !oRootKey || (oRootKey > pHive->Snapshot._DUAL[0].cb - REG_CM_KEY_NODE_SIZEOF)) {
        // regf base block unreadable or corrupt - try locate root key in 1st hive page
        i = 0x20;
        while(TRUE) {
            cbCell = REG_CELL_SIZE_EX(pHive->Snapshot._DUAL[0].pb, i);
            cbKey = (cbCell > 4) ? cbCell - 4 : 0;
			if((cbKey < sizeof(REG_CM_KEY_NODE)) || (i + cbCell > 0x1000)) { break; }
            pnk = (PREG_CM_KEY_NODE)(pHive->Snapshot._DUAL[0].pb + i + 4);
            if((pnk->Signature != REG_CM_KEY_SIGNATURE_KEYNODE) || !(pnk->Flags & REG_CM_KEY_NODE_FLAGS_HIVE_ENTRY) || !(pnk->Flags & REG_CM_KEY_NODE_FLAGS_COMP_NAME)) {
                i += cbCell;
                continue;
            }
            oRootKey = i;
            break;
        }
    }
    Ob_DECREF(VmmWinReg_KeyInitializeRootKeyDummy(H, pHive, oRootKey, 0, "ROOT", TRUE));
	Ob_DECREF(VmmWinReg_KeyInitializeRootKeyDummy(H, pHive, 0x7ffffffe, 0, "ORPHAN", FALSE));
	return TRUE;
}

/*
* Initialize the registry key functionality by first "snapshotting" the hive
* contents into memory then walking the complete hive to try to find and index
* relations beteen parent-child registry keys - which are then stored into
* hash maps for faster lookups.
* -- H
* -- pHive
* -- return
*/
_Success_(return)
BOOL VmmWinReg_KeyInitialize(_In_ VMM_HANDLE H, _In_ POB_REGISTRY_HIVE pHive)
{
	DWORD oCell, dwSignature, cbCell, cbHbin, iSV, iHbin;
    if(!VmmWinReg_KeyInitializeRootKey(H, pHive)) { return FALSE; }
    for(iSV = 0; iSV < 2; iSV++) {
        iHbin = 0;
        while(iHbin < (pHive->Snapshot._DUAL[iSV].cb & ~0xfff)) {
            dwSignature = *(PDWORD)(pHive->Snapshot._DUAL[iSV].pb + iHbin);
            if(!dwSignature) {  // zero-padded hbin
                iHbin += 0x1000;
                continue;
            }
            if(dwSignature != REG_SIGNATURE_HBIN) {
                VmmLog(H, MID_REGISTRY, LOGLEVEL_DEBUG, "BAD HBIN HEADER: Hive=%016llx HBin=%08x Sig=%08x", pHive->vaCMHIVE, ((iSV << 31) | iHbin), dwSignature);
                iHbin += 0x1000;
                continue;
            }
            cbHbin = *(PDWORD)(pHive->Snapshot._DUAL[iSV].pb + iHbin + 8);
            cbHbin = min(cbHbin, pHive->Snapshot._DUAL[iSV].cb - iHbin);
            if((cbHbin & 0xfff) || (cbHbin > 0x10000)) { cbHbin = 0x1000; }
            oCell = 0x20;
            while(oCell + 4 < cbHbin) {
                cbCell = REG_CELL_SIZE_EX(pHive->Snapshot._DUAL[iSV].pb, (QWORD)iHbin + oCell);
                if(!cbCell || (oCell + cbCell) > cbHbin) {
                    oCell += 4;
                    continue;
                }
                if(cbCell < 4 + REG_CM_KEY_NODE_SIZEOF) {
                    oCell += (cbCell + 3) & ~0x3;
                    continue;
                }
                if(REG_CM_KEY_SIGNATURE_KEYNODE == *(PWORD)(pHive->Snapshot._DUAL[iSV].pb + iHbin + oCell + 4)) {
                    Ob_DECREF(VmmWinReg_KeyInitializeCreateKey(H, pHive, iHbin + oCell + (iSV ? 0x80000000 : 0), 0));
                }
                oCell += (cbCell + 3) & ~0x3;
            }
            iHbin += cbHbin;
        }
    }
    return TRUE;
}

/*
* Try to create a key-value object manager object from the given cell offset.
* -- H
* -- pHive
* -- oCell = offset to cell (incl. static/volatile bit).
* -- return
*/
POB_REGISTRY_VALUE VmmWinReg_KeyValueGetByOffset(_In_ VMM_HANDLE H, _In_ POB_REGISTRY_HIVE pHive, _In_ DWORD oCell)
{
    DWORD dwCellHead, cbCell, cbKeyValue;
    PREG_CM_KEY_VALUE pvk;
    POB_REGISTRY_VALUE pObKeyValue;
    // 1: retrieve key & validate
    if(!VmmWinReg_KeyValidateCellSize(pHive, oCell, REG_CM_KEY_VALUE_SIZEOF + 4, 0x1000)) { return NULL; }
    dwCellHead = *(PDWORD)(pHive->Snapshot._DUAL[REG_CELL_SV(oCell)].pb + REG_CELL_ORAW(oCell));
    cbCell = REG_CELL_SIZE(dwCellHead);
    cbKeyValue = cbCell - 4;
    pvk = (PREG_CM_KEY_VALUE)(pHive->Snapshot._DUAL[REG_CELL_SV(oCell)].pb + REG_CELL_ORAW(oCell) + 4);
    if(pvk->Signature != REG_CM_KEY_SIGNATURE_KEYVALUE) { return NULL; }
    if(((QWORD)pvk->NameLength << ((pvk->Flags & REG_CM_KEY_VALUE_FLAGS_COMP_NAME) ? 0 : 1)) > (cbKeyValue - REG_CM_KEY_VALUE_SIZEOF)) { return NULL; }
    // 2: allocate and prepare
    pObKeyValue = Ob_AllocEx(H, OB_TAG_REG_KEYVALUE, LMEM_ZEROINIT, sizeof(OB_REGISTRY_VALUE), NULL, NULL);
    if(!pObKeyValue) { return NULL; }
    pObKeyValue->dwCellHead = dwCellHead;
    pObKeyValue->oCell = oCell;
    pObKeyValue->cbCell = cbCell;
    pObKeyValue->pValue = pvk;
    return pObKeyValue;
}

/*
* Helper function (core functionality) for the VmmWinReg_ValueQuery1/VmmWinReg_ValueQueryInternal functions.
* CALLER DECREF: return
* -- H
* -- pHice
* -- pKey
* -- wszKeyValueName
* -- return
*/
POB_REGISTRY_VALUE VmmWinReg_ValueByKeyAndName(_In_ VMM_HANDLE H, _In_ POB_REGISTRY_HIVE pHive, _In_ POB_REGISTRY_KEY pKey, _In_ LPCSTR uszKeyValueName)
{
    DWORD cbListCell, iValues, cValues, *praValues;
    POB_REGISTRY_VALUE pObKeyValue;
    VMM_REGISTRY_VALUE_INFO ValueInfo;
    DWORD oListCellRaw = REG_CELL_ORAW(pKey->pKey->ValueList.List);
    DWORD cbSnapshot = pHive->Snapshot._DUAL[REG_CELL_SV(pKey->pKey->ValueList.List)].cb;
    PBYTE pbSnapshot = pHive->Snapshot._DUAL[REG_CELL_SV(pKey->pKey->ValueList.List)].pb;
    if(!pKey->pKey->ValueList.Count || (oListCellRaw + 8 > cbSnapshot)) { return NULL; }
    cbListCell = REG_CELL_SIZE_EX(pbSnapshot, oListCellRaw);
    if((cbListCell < 8) || (oListCellRaw & 0xfff) + cbListCell > 0x1000) { return NULL; }
    cValues = min(pKey->pKey->ValueList.Count, (cbListCell - 4) >> 2);
    praValues = (PDWORD)(pbSnapshot + oListCellRaw + 4);
    for(iValues = 0; iValues < cValues; iValues++) {
        pObKeyValue = VmmWinReg_KeyValueGetByOffset(H, pHive, praValues[iValues]);
        if(!pObKeyValue) { continue; }
        VmmWinReg_ValueInfo(pHive, pObKeyValue, &ValueInfo);
        if(!_stricmp(uszKeyValueName, ValueInfo.uszName)) { return pObKeyValue; }
        Ob_DECREF_NULL(&pObKeyValue);
    }
    return NULL;
}

/*
* Helper function for the VmmWinReg_ValueQueryInternal_BigDataList function.
* Read an individual BigData 'Cell'. If the read fail data will be zero-padded.
* -- pHive
* -- oDataCell
* -- fDataCellLast
* -- pbData
* -- cbData
* -- cbDataOffset
*/
VOID VmmWinReg_ValueQueryInternal_BigDataCell(_In_ POB_REGISTRY_HIVE pHive, _In_ DWORD oDataCell, _In_ BOOL fDataCellLast, _Out_writes_opt_(cbData) PBYTE pbData, _In_ DWORD cbData, _In_ DWORD cbDataOffset)
{
    BOOL f;
    DWORD iDataCellSV, oDataCellRaw, cbDataCell;
    if(!pbData) { return; }
    iDataCellSV = REG_CELL_SV(oDataCell);
    oDataCellRaw = REG_CELL_ORAW(oDataCell);
    cbDataCell = REG_CELL_SIZE_EX(pHive->Snapshot._DUAL[iDataCellSV].pb, oDataCellRaw);
    f = (oDataCellRaw + cbDataCell <= pHive->Snapshot._DUAL[iDataCellSV].cb) &&
        (fDataCellLast || (cbDataCell == 16344 + 8)) &&
        (cbDataCell <= 16344 + 8) &&
        (cbDataCell > 8);
    if(f) {
        memcpy(pbData, pHive->Snapshot._DUAL[iDataCellSV].pb + oDataCellRaw + 4 + cbDataOffset, min(cbData, cbDataCell));
    } else {
        ZeroMemory(pbData, cbData);
    }
}

/*
* Helper function for the VmmWinReg_ValueQueryInternal function.
* BigData 'List' functionality.
* -- pHive
* -- cNumSegments
* -- oListCell
* -- pbData
* -- cbData
* -- pcbDataRead
* -- cbDataOffset
* -- return
*/
_Success_(return)
BOOL VmmWinReg_ValueQueryInternal_BigDataList(_In_ POB_REGISTRY_HIVE pHive, _In_ WORD cNumSegments, _In_ DWORD oListCell, _Out_writes_opt_(cbData) PBYTE pbData, _In_ DWORD cbData, _Out_opt_ PDWORD pcbDataRead, _In_ DWORD cbDataOffset)
{
    DWORD i, cbMaxSizeTotalSegments, iListCellSV, oListCellRaw, cbListCell, cbReadDataCell;
    cbMaxSizeTotalSegments = cNumSegments * 16344;
    // adjust read size (if required)
    if(cbDataOffset > cbMaxSizeTotalSegments) { return FALSE; }
    if(cbData + cbDataOffset > cbMaxSizeTotalSegments) {
        cbData = cbMaxSizeTotalSegments - cbDataOffset;
    }
    // verify list cell
    iListCellSV = REG_CELL_SV(oListCell);
    oListCellRaw = REG_CELL_ORAW(oListCell);
    if(oListCellRaw + 4 + cNumSegments * 4 > pHive->Snapshot._DUAL[iListCellSV].cb) { return FALSE; }
    cbListCell = REG_CELL_SIZE_EX(pHive->Snapshot._DUAL[iListCellSV].pb, oListCellRaw);
    if(oListCellRaw + cbListCell > pHive->Snapshot._DUAL[iListCellSV].cb) { return FALSE; }
    if(cbListCell < 4 + cNumSegments * 4UL) { return FALSE; }
    // read individual data cells
    if(pcbDataRead) { *pcbDataRead = cbData; }
    if(pbData) { ZeroMemory(pbData, cbData); }
    for(i = 0; cbData && (i < cNumSegments); i++) {
        if(cbDataOffset > 16344) {
            cbDataOffset -= 16344;
            continue;
        }
        cbReadDataCell = min(cbData, 16344 - cbDataOffset);
        VmmWinReg_ValueQueryInternal_BigDataCell(
            pHive,
            *(PDWORD)(pHive->Snapshot._DUAL[iListCellSV].pb + oListCellRaw + 4 + i * 4ULL),
            (i + 1 == cNumSegments),
            pbData,
            cbReadDataCell,
            cbDataOffset
        );
        pbData += cbReadDataCell;
        cbData -= cbReadDataCell;
        cbDataOffset -= min(cbReadDataCell, cbDataOffset);
    }
    return TRUE;
}

/*
* Helper function (core functionality) for the VmmWinReg_ValueQuery* functions.
*/
_Success_(return)
BOOL VmmWinReg_ValueQueryInternal(_In_ POB_REGISTRY_HIVE pHive, _In_ POB_REGISTRY_VALUE pKeyValue, _Out_opt_ PDWORD pdwType, _Out_opt_ PDWORD pra, _Out_opt_ PDWORD pdwLength, _Out_writes_opt_(cbData) PBYTE pbData, _In_ DWORD cbData, _Out_opt_ PDWORD pcbDataRead, _In_ DWORD cbDataOffset) {
    DWORD cbDataRead = 0, cbDataLength, iCellSV, oCellRaw, cbCell;
    if(pcbDataRead) { *pcbDataRead = 0; }
    cbDataLength = pKeyValue->pValue->DataLength & 0x7fffffff;
    if(pdwType) {
        *pdwType = pKeyValue->pValue->Type;
    }
    if(pra) {
        *pra = pKeyValue->oCell;
    }
    if(pdwLength) {
        *pdwLength = cbDataLength;
    }
    if(!pbData) { goto success; }
    if(!cbData || (cbDataOffset >= cbDataLength)) { return FALSE; }
    cbDataRead = min(cbData, cbDataLength - cbDataOffset);
    if(pKeyValue->pValue->DataLength & 0x80000000) {
        // "small data" stored within keyvalue
        if((cbDataLength > 4) || (cbDataRead > 4)) { return FALSE; }
        memcpy(pbData, (PBYTE)(&pKeyValue->pValue->Data) + cbDataOffset, cbDataRead);
        goto success;
    }
    iCellSV = REG_CELL_SV(pKeyValue->pValue->Data);
    oCellRaw = REG_CELL_ORAW(pKeyValue->pValue->Data);
    if(oCellRaw + 0x10 > pHive->Snapshot._DUAL[iCellSV].cb) { return FALSE; }
    cbCell = REG_CELL_SIZE_EX(pHive->Snapshot._DUAL[iCellSV].pb, oCellRaw);
    if(cbCell < 8) { return FALSE; }
    // "big data" table
    if(*(PWORD)(pHive->Snapshot._DUAL[iCellSV].pb + oCellRaw + 4) == REG_CM_KEY_SIGNATURE_BIGDATA) {
        return VmmWinReg_ValueQueryInternal_BigDataList(
            pHive,
            *(PWORD)(pHive->Snapshot._DUAL[iCellSV].pb + oCellRaw + 4 + 2),
            *(PDWORD)(pHive->Snapshot._DUAL[iCellSV].pb + oCellRaw + 4 + 4),
            pbData, cbDataRead, pcbDataRead, cbDataOffset);
    }
    // "ordinary" data
    if(cbDataOffset > cbCell - 4) { return FALSE; }
    cbDataRead = min(cbDataRead, cbCell - 4 - cbDataOffset);
    if(oCellRaw + 4ULL + cbDataOffset + cbDataRead > pHive->Snapshot._DUAL[iCellSV].cb) { return FALSE; }
    memcpy(pbData, pHive->Snapshot._DUAL[iCellSV].pb + oCellRaw + 4 + cbDataOffset, cbDataRead);
success:
    if(pcbDataRead) { *pcbDataRead = cbDataRead; }
    return TRUE;
}



//-----------------------------------------------------------------------------
// EXTERNAL REGISTRY KEY AND VALUE FUNCTIONALITY:
//-----------------------------------------------------------------------------

/*
* Retrieve registry hive and key/value path from a "full" path starting with:
* '0x...', 'by-hive\0x...' or 'HKLM\'
* CALLER DECREF: *ppObHive
* -- H
* -- uszPathFull
* -- ppObHive
* -- uszPathKeyValue
* -- return
*/
_Success_(return)
BOOL VmmWinReg_PathHiveGetByFullPath(_In_ VMM_HANDLE H, _In_ LPSTR uszPathFull, _Out_ POB_REGISTRY_HIVE *ppHive, _Out_writes_(MAX_PATH) LPSTR uszPathKeyValue)
{
    BOOL fUser = FALSE, fUserSystem = FALSE, fOrphan = FALSE;
    DWORD i;
    LPSTR usz, uszPath2;
    CHAR uszPath1[MAX_PATH];
    POB_REGISTRY_HIVE pObHive = NULL;
    POB_REGISTRY_KEY pObKey = NULL;
    PVMMOB_MAP_USER pObUserMap = NULL;
    if(!strncmp(uszPathFull, "HKLM\\", 5) || (fUser = !strncmp(uszPathFull, "HKU\\", 4))) {
        uszPathFull += fUser ? 4 : 5;
        if(!strncmp(uszPathFull, "ORPHAN\\", 7)) {
            uszPathFull += 7;
            fOrphan = TRUE;
        }
        uszPath2 = CharUtil_PathSplitFirst(uszPathFull, uszPath1, _countof(uszPath1));
        strncpy_s(uszPathKeyValue, MAX_PATH, fOrphan ? "ORPHAN\\" : "ROOT\\", _TRUNCATE);
        strncat_s(uszPathKeyValue, MAX_PATH, uszPath2, _TRUNCATE);
        if(fUser) {
            if(strstr("LocalSystem", uszPath1)) { fUserSystem = TRUE;  strncpy_s(uszPath1, sizeof(uszPath1), "DEFAULT-USER_.DEFAULT", _TRUNCATE); }
            if(strstr("LocalService", uszPath1)) { fUserSystem = TRUE;  strncpy_s(uszPath1, sizeof(uszPath1), "NTUSERDAT-USER_S-1-5-19", _TRUNCATE); }
            if(strstr("NetworkService", uszPath1)) { fUserSystem = TRUE;  strncpy_s(uszPath1, sizeof(uszPath1), "NTUSERDAT-USER_S-1-5-20", _TRUNCATE); }
            if(fUserSystem) {
                while((pObHive = VmmWinReg_HiveGetNext(H, pObHive))) {
                    if(strstr(pObHive->uszName, uszPath1)) {
                        *ppHive = pObHive;
                        return TRUE;                // CALLER DECREF: *ppHive
                    }
                }
            } else if(VmmMap_GetUser(H, &pObUserMap)) {
                for(i = 0; i < pObUserMap->cMap; i++) {
                    if(strstr(pObUserMap->pMap[i].uszText, uszPath1)) {
                        *ppHive = VmmWinReg_HiveGetByAddress(H, pObUserMap->pMap[i].vaRegHive);
                        Ob_DECREF(pObUserMap);
                        return (*ppHive != NULL);   // CALLER DECREF: *ppHive
                    }
                }
                Ob_DECREF_NULL(&pObUserMap);
            }
        } else {
            while((pObHive = VmmWinReg_HiveGetNext(H, pObHive))) {
                if(strstr(pObHive->uszNameShort, uszPath1)) {
                    *ppHive = pObHive;
                    return TRUE;    // CALLER DECREF: *ppHive
                }
            }
            while((pObHive = VmmWinReg_HiveGetNext(H, pObHive))) {
                if(strstr(pObHive->uszHiveRootPath, uszPath1)) {
                    *ppHive = pObHive;
                    return TRUE;    // CALLER DECREF: *ppHive
                }
            }
            if(!_stricmp(uszPath1, "HARDWARE")) {
                while((pObHive = VmmWinReg_HiveGetNext(H, pObHive))) {
                    if(!pObHive->uszNameShort[0] && !pObHive->uszHiveRootPath[0] && (pObKey = VmmWinReg_KeyGetByPath(H, pObHive, "ROOT\\RESOURCEMAP"))) {
                        Ob_DECREF(pObKey);
                        *ppHive = pObHive;
                        return TRUE;    // CALLER DECREF: *ppHive                        
                    }
                }
            }
        }
        return FALSE;
    }
    // try retrieve hive by address (path starts with 0x ...)
    if(!strncmp(uszPathFull, "by-hive\\", 8)) {
        uszPathFull += 8;
    }
    *ppHive = VmmWinReg_HiveGetByAddress(H, Util_GetNumericA(uszPathFull));
    if(!*ppHive) { return FALSE; }
    usz = CharUtil_PathSplitNext(uszPathFull);
    CharUtil_UtoU(usz, -1, uszPathKeyValue, MAX_PATH, NULL, NULL, CHARUTIL_FLAG_TRUNCATE_ONFAIL_NULLSTR | CHARUTIL_FLAG_STR_BUFONLY);
    return TRUE;    // CALLER DECREF: *ppHive
}

/*
* Retrieve registry hive and key from a "full" path starting with:
* '0x...', 'by-hive\0x...' or 'HKLM\'
* CALLER DECREF: *ppObHive, *ppObKey
* -- H
* -- uszPathFull
* -- ppObHive
* -- ppObKey
* -- return
*/
_Success_(return)
BOOL VmmWinReg_KeyHiveGetByFullPath(_In_ VMM_HANDLE H, _In_ LPSTR uszPathFull, _Out_ POB_REGISTRY_HIVE *ppObHive, _Out_opt_ POB_REGISTRY_KEY *ppObKey)
{
    CHAR uszPathKey[MAX_PATH];
    if(!VmmWinReg_PathHiveGetByFullPath(H, uszPathFull, ppObHive, uszPathKey)) { return FALSE; }
    if(!ppObKey) { return TRUE; }
    if((*ppObKey = VmmWinReg_KeyGetByPath(H, *ppObHive, uszPathKey))) { return TRUE; }
    Ob_DECREF_NULL(ppObHive);
    return FALSE;
}

/*
* Retrieve a registry key by its path. If no registry key is found then NULL
* will be returned.
* CALLER DECREF: return
* -- H
* -- pHive
* -- uszPath
* -- return
*/
_Success_(return != NULL)
POB_REGISTRY_KEY VmmWinReg_KeyGetByPath(_In_ VMM_HANDLE H, _In_ POB_REGISTRY_HIVE pHive, _In_ LPSTR uszPath)
{
    if(!VmmWinReg_HiveSnapshotEnsure(H, pHive)) { return NULL; }
    return (POB_REGISTRY_KEY)ObMap_GetByKey(pHive->Snapshot.pmKeyHash, CharUtil_HashPathFsU(uszPath));
}

/*
* Retrieve a registry key by parent key and name.
* If no registry key is found then NULL is returned.
* CALLER DECREF: return
* -- H
* -- pHive
* -- pParentKey
* -- uszChildName
* -- return
*/
_Success_(return != NULL)
POB_REGISTRY_KEY VmmWinReg_KeyGetByChildName(_In_ VMM_HANDLE H, _In_ POB_REGISTRY_HIVE pHive, _In_ POB_REGISTRY_KEY pParentKey, _In_ LPSTR uszChildName)
{
    if(!VmmWinReg_HiveSnapshotEnsure(H, pHive)) { return NULL; }
    return (POB_REGISTRY_KEY)ObMap_GetByKey(pHive->Snapshot.pmKeyHash, VmmWinReg_KeyHashChildName(pParentKey, uszChildName));
}

/*
* Retrieve a registry key by its cell offset (incl. static/volatile bit).
* If no registry key is found then NULL will be returned.
* CALLER DECREF: return
* -- H
* -- pHive
* -- raCellOffset
* -- return
*/
_Success_(return != NULL)
POB_REGISTRY_KEY VmmWinReg_KeyGetByCellOffset(_In_ VMM_HANDLE H, _In_ POB_REGISTRY_HIVE pHive, _In_ DWORD raCellOffset)
{
    if(!VmmWinReg_HiveSnapshotEnsure(H, pHive)) { return NULL; }
    return (POB_REGISTRY_KEY)ObMap_GetByKey(pHive->Snapshot.pmKeyOffset, raCellOffset);
}

/*
* Retrive registry sub-keys from the level directly below the given parent key.
* The resulting keys are returned in a no-key map (set). If no parent key is
* given the root keys are returned.
* CALLER DECREF: return
* -- H
* -- pHive
* -- pKeyParent
* -- return
*/
POB_MAP VmmWinReg_KeyList(_In_ VMM_HANDLE H, _In_ POB_REGISTRY_HIVE pHive, _In_opt_ POB_REGISTRY_KEY pKeyParent)
{
    DWORD i;
    POB_MAP pmObSubkeys;
    POB_REGISTRY_KEY pKeyChild;
    if(!VmmWinReg_HiveSnapshotEnsure(H, pHive)) { return NULL; }
    if(!(pmObSubkeys = ObMap_New(H, OB_MAP_FLAGS_OBJECT_OB | OB_MAP_FLAGS_NOKEY))) { return NULL; }
    if(pKeyParent) {
        for(i = 0; i < pKeyParent->Child.c; i++) {
            pKeyChild = ObMap_GetByKey(pHive->Snapshot.pmKeyOffset, pKeyParent->Child.po[i]);
            ObMap_Push(pmObSubkeys, 0, pKeyChild);
            Ob_DECREF(pKeyChild);
        }
    } else {
        for(i = 0; i < 2; i++) {
            pKeyChild = ObMap_GetByIndex(pHive->Snapshot.pmKeyOffset, i);
            ObMap_Push(pmObSubkeys, 0, pKeyChild);
            Ob_DECREF(pKeyChild);
        }
    }
    return pmObSubkeys;
}

/*
* Retrieve information about a registry key.
* -- pHive
* -- pKey
* -- pKeyInfo
*/
VOID VmmWinReg_KeyInfo(_In_ POB_REGISTRY_HIVE pHive, _In_ POB_REGISTRY_KEY pKey, _Out_ PVMM_REGISTRY_KEY_INFO pKeyInfo)
{
    pKeyInfo->raKeyCell = pKey->oCell;
    pKeyInfo->cbKeyCell = pKey->cbCell;
    pKeyInfo->fActive = pKey->dwCellHead >> 31;
    pKeyInfo->ftLastWrite = pKey->pKey->LastWriteTime;
    if(pKey->pKey->Flags & REG_CM_KEY_NODE_FLAGS_COMP_NAME) {
        pKeyInfo->cbuName = CharUtil_FixFsName(pKeyInfo->uszName, sizeof(pKeyInfo->uszName), NULL, pKey->pKey->szName, NULL, pKey->pKey->NameLength, pKey->iSuffix, FALSE);
    } else {
        pKeyInfo->cbuName = CharUtil_FixFsName(pKeyInfo->uszName, sizeof(pKeyInfo->uszName), NULL, NULL, pKey->pKey->wszName, pKey->pKey->NameLength, pKey->iSuffix, FALSE);
    }
}

/*
* Retrieve information about a registry key - pKeyInfo->wszName = set to full path.
* -- H
* -- pHive
* -- pKey
* -- pKeyInfo
*/
VOID VmmWinReg_KeyInfo2(_In_ VMM_HANDLE H, _In_ POB_REGISTRY_HIVE pHive, _In_ POB_REGISTRY_KEY pKey, _Out_ PVMM_REGISTRY_KEY_INFO pKeyInfo)
{
    POB_SET ps;
    QWORD qwHashKeyParent;
    POB_REGISTRY_KEY pObKey;
    VMM_REGISTRY_KEY_INFO KeyInfo;
    int status;
    DWORD cuszPath = 0;
    CHAR szHiveShortName[33] = { 0 };
    CHAR uszPath[MAX_PATH] = { 0 };
    VmmWinReg_KeyInfo(pHive, pKey, pKeyInfo);
    if(!(ps = ObSet_New(H))) { return; }
    ObSet_Push(ps, (QWORD)Ob_INCREF(pKey));
    qwHashKeyParent = pKey->qwHashKeyParent;
    while((pObKey = ObMap_GetByKey(pHive->Snapshot.pmKeyHash, qwHashKeyParent))) {
        ObSet_Push(ps, (QWORD)pObKey);
        qwHashKeyParent = pObKey->qwHashKeyParent;
    }
    Ob_DECREF((POB_REGISTRY_KEY)ObSet_Pop(ps));  // skip "root"
    if(pHive->uszNameShort[0]) {
        VmmWinReg_HiveGetShortName(pHive, szHiveShortName);
    }
    cuszPath = _snprintf_s(uszPath, _countof(uszPath), _TRUNCATE, "%s", szHiveShortName);
    while((pObKey = (POB_REGISTRY_KEY)ObSet_Pop(ps))) {
        VmmWinReg_KeyInfo(pHive, pObKey, &KeyInfo);
        Ob_DECREF(pObKey);
        status = _snprintf_s(uszPath + cuszPath, _countof(uszPath) - cuszPath, _TRUNCATE, "\\%s", KeyInfo.uszName);
        if(status == -1) {
            cuszPath = _countof(uszPath) - 1;
            break;
        } else if(status > 0) {
            cuszPath += status;
        }
    }
    Ob_DECREF(ps);
    if(cuszPath) {
        pKeyInfo->cbuName = cuszPath + 1;
        memcpy(pKeyInfo->uszName, uszPath, pKeyInfo->cbuName);
    }
}

/*
* Retrive registry values given a key. The resulting values are returned in a
* no-key map (set). If no values are found the empty set or NULL are returned.
* CALLER DECREF: return
* -- H
* -- pHive
* -- pKeyParent
* -- return = ObMap of POB_REGISTRY_VALUE
*/
POB_MAP VmmWinReg_KeyValueList(_In_ VMM_HANDLE H, _In_ POB_REGISTRY_HIVE pHive, _In_ POB_REGISTRY_KEY pKeyParent)
{
    DWORD cbListCell, iValues, cValues, *praValues;
    POB_REGISTRY_VALUE pObKeyValue;
    POB_MAP pmObValues;
    DWORD oListCellRaw = REG_CELL_ORAW(pKeyParent->pKey->ValueList.List);
    DWORD cbSnapshot = pHive->Snapshot._DUAL[REG_CELL_SV(pKeyParent->pKey->ValueList.List)].cb;
    PBYTE pbSnapshot = pHive->Snapshot._DUAL[REG_CELL_SV(pKeyParent->pKey->ValueList.List)].pb;
    if(!VmmWinReg_HiveSnapshotEnsure(H, pHive)) { return NULL; }
    if(!(pmObValues = ObMap_New(H, OB_MAP_FLAGS_OBJECT_OB | OB_MAP_FLAGS_NOKEY))) { return NULL; }
    if(!pKeyParent->pKey->ValueList.Count || (oListCellRaw > cbSnapshot - 8)) { return pmObValues; }
    if(!VmmWinReg_KeyValidateCellSize(pHive, pKeyParent->pKey->ValueList.List, 8, 0x1000)) { return pmObValues; }
    cbListCell = REG_CELL_SIZE_EX(pbSnapshot, oListCellRaw);
    cValues = min(pKeyParent->pKey->ValueList.Count, (cbListCell - 4) >> 2);
    praValues = (PDWORD)(pbSnapshot + oListCellRaw + 4);
    for(iValues = 0; iValues < cValues; iValues++) {
        pObKeyValue = VmmWinReg_KeyValueGetByOffset(H, pHive, praValues[iValues]);
        ObMap_Push(pmObValues, 0, pObKeyValue);
        Ob_DECREF_NULL(&pObKeyValue);
    }
    return pmObValues;
}

/*
* Retrive registry values given a key and value name.
* NB! VmmWinReg_KeyValueList is the preferred function.
* CALLER DECREF: return
* -- H
* -- pHive
* -- pKeyParent
* -- uszValueName = value name or NULL for default.
* -- return = registry value or NULL if not found.
*/
POB_REGISTRY_VALUE VmmWinReg_KeyValueGetByName(_In_ VMM_HANDLE H, _In_ POB_REGISTRY_HIVE pHive, _In_ POB_REGISTRY_KEY pKeyParent, _In_ LPSTR uszValueName)
{
    POB_MAP pmObValues = NULL;
    POB_REGISTRY_VALUE pObValue = NULL;
    VMM_REGISTRY_VALUE_INFO ValueInfo = { 0 };
    if(!(pmObValues = VmmWinReg_KeyValueList(H, pHive, pKeyParent))) { return NULL; }
    if(!uszValueName) {
        uszValueName = "(Default)";
    }
    while((pObValue = ObMap_GetNext(pmObValues, pObValue))) {
        VmmWinReg_ValueInfo(pHive, pObValue, &ValueInfo);
        if(0 == _stricmp(uszValueName, ValueInfo.uszName)) {
            Ob_DECREF(pmObValues);
            return pObValue;
        }
    }
    Ob_DECREF(pmObValues);
    return NULL;
}

/*
* Retrieve information about a registry key value.
* -- pHive
* -- pValue
* -- pValueInfo
*/
VOID VmmWinReg_ValueInfo(_In_ POB_REGISTRY_HIVE pHive, _In_ POB_REGISTRY_VALUE pValue, _Out_ PVMM_REGISTRY_VALUE_INFO pValueInfo)
{
    pValueInfo->dwType = pValue->pValue->Type;
    pValueInfo->cbData = pValue->pValue->DataLength & 0x7fffffff;
    pValueInfo->raValueCell = pValue->oCell;
    if(!pValue->pValue->NameLength) {
        strcpy_s(pValueInfo->uszName, _countof(pValueInfo->uszName), "(Default)");
        pValueInfo->cbuName = 10;
    } else if(pValue->pValue->Flags & REG_CM_KEY_VALUE_FLAGS_COMP_NAME) {
        pValueInfo->cbuName = CharUtil_FixFsName(pValueInfo->uszName, sizeof(pValueInfo->uszName), NULL, pValue->pValue->szName, NULL, pValue->pValue->NameLength, 0, FALSE);
    } else {
        pValueInfo->cbuName = CharUtil_FixFsName(pValueInfo->uszName, sizeof(pValueInfo->uszName), NULL, NULL, pValue->pValue->wszName, pValue->pValue->NameLength, 0, FALSE);
    }
}

/*
* Read a registry value - similar to WINAPI function 'RegQueryValueEx'.
* -- H
* -- pHive
* -- uszPathKeyValue
* -- pdwType
* -- pra = registry address of value cell
* -- pb
* -- cb
* -- pcbRead
* -- cbOffset
* -- return
*/
_Success_(return)
BOOL VmmWinReg_ValueQuery1(_In_ VMM_HANDLE H, _In_ POB_REGISTRY_HIVE pHive, _In_ LPSTR uszPathKeyValue, _Out_opt_ PDWORD pdwType, _Out_opt_ PDWORD pra, _Out_writes_opt_(cb) PBYTE pb, _In_ DWORD cb, _Out_opt_ PDWORD pcbRead, _In_ QWORD cbOffset)
{
    BOOL f;
    LPSTR uszValueName;
    CHAR uszPathKey[MAX_PATH];
    POB_REGISTRY_KEY pObKey = NULL;
    POB_REGISTRY_VALUE pObKeyValue = NULL;
    if(pcbRead) { *pcbRead = 0; }
    f = VmmWinReg_HiveSnapshotEnsure(H, pHive) &&
        (uszValueName = CharUtil_PathSplitLastEx(uszPathKeyValue, uszPathKey, sizeof(uszPathKey))) &&
        (pObKey = VmmWinReg_KeyGetByPath(H, pHive, uszPathKey)) &&
        (pObKeyValue = VmmWinReg_ValueByKeyAndName(H, pHive, pObKey, uszValueName)) &&
        (pb ? VmmWinReg_ValueQueryInternal(pHive, pObKeyValue, pdwType, pra, NULL, pb, cb, pcbRead, (DWORD)cbOffset) : VmmWinReg_ValueQueryInternal(pHive, pObKeyValue, pdwType, pra, pcbRead, NULL, 0, NULL, 0));
    Ob_DECREF(pObKeyValue);
    Ob_DECREF(pObKey);
    return f;
}

/*
* Read a registry value - similar to WINAPI function 'RegQueryValueEx'.
* -- H
* -- uszFullPathKeyValue
* -- pdwType
* -- pbData
* -- cbData
* -- pcbData
* -- return
*/
_Success_(return)
BOOL VmmWinReg_ValueQuery2(_In_ VMM_HANDLE H, _In_ LPSTR uszFullPathKeyValue, _Out_opt_ PDWORD pdwType, _Out_writes_opt_(cbData) PBYTE pbData, _In_ DWORD cbData, _Out_opt_ PDWORD pcbData)
{
    BOOL f;
    CHAR uszPathKeyValue[MAX_PATH];
    POB_REGISTRY_HIVE pObHive = NULL;
    f = VmmWinReg_PathHiveGetByFullPath(H, uszFullPathKeyValue, &pObHive, uszPathKeyValue) &&
        VmmWinReg_ValueQuery1(H, pObHive, uszPathKeyValue, pdwType, NULL, pbData, cbData, pcbData, 0);
    Ob_DECREF(pObHive);
    return f;
}

/*
* Read a registry value - similar to WINAPI function 'RegQueryValueEx'.
* -- H
* -- pHive
* -- uszPathKeyValue
* -- pdwType
* -- pbData
* -- cbData
* -- pcbData
* -- return
*/
_Success_(return)
BOOL VmmWinReg_ValueQuery3(_In_ VMM_HANDLE H, _In_ POB_REGISTRY_HIVE pHive, _In_ LPSTR uszPathKeyValue, _Out_opt_ PDWORD pdwType, _Out_writes_opt_(cbData) PBYTE pbData, _In_ DWORD cbData, _Out_opt_ PDWORD pcbData)
{
    return VmmWinReg_ValueQuery1(H, pHive, uszPathKeyValue, pdwType, NULL, pbData, cbData, pcbData, 0);
}

/*
* Read a registry value - similar to WINAPI function 'RegQueryValueEx'.
* -- H
* -- pHive
* -- pObKeyValue
* -- pdwType
* -- pbData
* -- cbData
* -- pcbData
* -- return
*/
_Success_(return)
BOOL VmmWinReg_ValueQuery4(_In_ VMM_HANDLE H, _In_ POB_REGISTRY_HIVE pHive, _In_ POB_REGISTRY_VALUE pKeyValue, _Out_opt_ PDWORD pdwType, _Out_writes_opt_(cbData) PBYTE pbData, _In_ DWORD cbData, _Out_opt_ PDWORD pcbData)
{
    if(VmmWinReg_HiveSnapshotEnsure(H, pHive)) {
        return VmmWinReg_ValueQueryInternal(pHive, pKeyValue, pdwType, NULL, NULL, pbData, cbData, pcbData, 0);
    }
    if(pdwType) { *pdwType = 0; }
    if(pcbData) { *pcbData = 0; }
    return FALSE;
}

/*
* Read a registry value - similar to WINAPI function 'RegQueryValueEx'.
* -- H
* -- pHive
* -- pObKey
* -- uszValueName
* -- pdwType
* -- pbData
* -- cbData
* -- pcbData
* -- return
*/
_Success_(return)
BOOL VmmWinReg_ValueQuery5(_In_ VMM_HANDLE H, _In_ POB_REGISTRY_HIVE pHive, _In_ POB_REGISTRY_KEY pKey, _In_ LPSTR uszValueName, _Out_opt_ PDWORD pdwType, _Out_writes_opt_(cbData) PBYTE pbData, _In_ DWORD cbData, _Out_opt_ PDWORD pcbData)
{
    BOOL fResult = FALSE;
    POB_REGISTRY_VALUE pObKeyValue;
    if((pObKeyValue = VmmWinReg_KeyValueGetByName(H, pHive, pKey, uszValueName))) {
        fResult = VmmWinReg_ValueQuery4(H, pHive, pObKeyValue, pdwType, pbData, cbData, pcbData);
        Ob_DECREF(pObKeyValue);
    }
    return fResult;
}

/*
* Create a full path given a registry key. This string format is primarily used
* for forensic storage purposes.
* -- pHive
* -- pKey
* -- uszHivePrefix
* -- uszHiveName
* -- uszFullPath
*/
VOID VmmWinReg_KeyFullPath(_In_ POB_REGISTRY_HIVE pHive, _In_ POB_REGISTRY_KEY pKey, _In_ LPSTR uszHivePrefix, _In_ LPSTR uszHiveName, _Out_writes_(1024) LPSTR uszFullPath)
{
    CONST BYTE pbTEXT_ROOT[] = { '\\', 0, 'R', 0, 'O', 0, 'O', 0, 'T', 0 };
    BOOL fResult = TRUE, fSkip = TRUE;
    SIZE_T cch;
    DWORD o = 0, iKey = 0, cbName;
    POB_REGISTRY_KEY pk, ppObKey[0x40];
    // fetch parents (max depth: 0x40)
    ppObKey[iKey++] = Ob_INCREF(pKey);
    while((iKey < 0x40) && (ppObKey[iKey] = ObMap_GetByKey(pHive->Snapshot.pmKeyHash, ppObKey[iKey - 1]->qwHashKeyParent))) {
        iKey++;
    }
    // unwind, copy name
    cch = strlen(uszHivePrefix);
    memcpy((PBYTE)(uszFullPath + o), (PBYTE)uszHivePrefix, cch); o += (DWORD)cch;
    cch = strlen(uszHiveName);
    memcpy((PBYTE)(uszFullPath + o), (PBYTE)uszHiveName, cch); o += (DWORD)cch;
    while(iKey) {
        pk = ppObKey[--iKey];
        if(o + pk->pKey->NameLength + 4 > 1024) {
            fResult = FALSE;
        } else if(fSkip && !pk->qwHashKeyParent && memcmp(pk->pKey->wszName, pbTEXT_ROOT, sizeof(pbTEXT_ROOT))) {
            ;
        } else {
            cbName = 0;
            uszFullPath[o++] = '\\';
            if(pk->pKey->Flags & REG_CM_KEY_NODE_FLAGS_COMP_NAME) {
                CharUtil_AtoU(pk->pKey->szName, pk->pKey->NameLength, uszFullPath + o, 1024 - o, NULL, &cbName, CHARUTIL_FLAG_TRUNCATE_ONFAIL_NULLSTR | CHARUTIL_FLAG_STR_BUFONLY);
            } else {
                CharUtil_WtoU(pk->pKey->wszName, pk->pKey->NameLength, uszFullPath + o, 1024 - o, NULL, &cbName, CHARUTIL_FLAG_TRUNCATE_ONFAIL_NULLSTR | CHARUTIL_FLAG_STR_BUFONLY);
            }
            if(cbName) {
                o += cbName - 1;
            }
        }
        Ob_DECREF(pk);
        fSkip = FALSE;
    }
    uszFullPath[fResult ? o : 0] = 0;
}

/*
* Function to allow the forensic sub-system to request extraction of all keys
* and their values from a specific hive. The key information will be delivered
* back to the forensic sub-system by the use of callback functions.
* -- H
* -- pHive
* -- hCallback1
* -- hCallback2
* -- pfnKeyCB = callback to populate the forensic database with keys.
* -- pfnJsonKeyCB
* -- pfnJsonValueCB
*/
VOID VmmWinReg_ForensicGetAllKeysAndValues(
    _In_ VMM_HANDLE H,
    _In_ POB_REGISTRY_HIVE pHive,
    _In_ HANDLE hCallback1,
    _In_ HANDLE hCallback2,
    _In_ VOID(*pfnKeyCB)(_In_ VMM_HANDLE H, _In_ HANDLE hCallback1, _In_ HANDLE hCallback2, _In_ LPSTR uszPathName, _In_ QWORD vaHive, _In_ DWORD dwCell, _In_ DWORD dwCellParent, _In_ QWORD ftLastWrite),
    _In_ VOID(*pfnJsonKeyCB)(_In_ VMM_HANDLE H, _Inout_ PVMMWINREG_FORENSIC_CONTEXT ctx, _In_z_ LPSTR uszPathName, _In_ QWORD ftLastWrite),
    _In_ VOID(*pfnJsonValueCB)(_In_ VMM_HANDLE H, _Inout_ PVMMWINREG_FORENSIC_CONTEXT ctx)
) {
    DWORD i, c, oHive, j, jMax;
    CHAR uszFullPath[1024];
    LPSTR uszHivePrefix;
    POB_REGISTRY_KEY pObKey;
    POB_MAP pmObValues = NULL;
    POB_REGISTRY_VALUE pObValue = NULL;
    PVMMWINREG_FORENSIC_CONTEXT ctx;
    if(!(ctx = LocalAlloc(LMEM_ZEROINIT, sizeof(VMMWINREG_FORENSIC_CONTEXT)))) { return; }
    if(VmmWinReg_HiveSnapshotEnsure(H, pHive)) {
        oHive = 0;
        uszHivePrefix = "";
        if(pHive->uszHiveRootPath[oHive] == '\\') {
            oHive += 1;
        }
        if(!_strnicmp(pHive->uszHiveRootPath + oHive, "REGISTRY\\", 9)) {
            oHive += 9;
        }
        if(!_strnicmp(pHive->uszHiveRootPath + oHive, "MACHINE\\", 8)) {
            oHive += 8;
            uszHivePrefix = "HKLM\\";
        }
        if(!_strnicmp(pHive->uszHiveRootPath + oHive, "USER\\", 5)) {
            oHive += 5;
            uszHivePrefix = "HKU\\";
        }
        c = ObMap_Size(pHive->Snapshot.pmKeyOffset);
        for(i = 0; ((i < c) && !H->fAbort); i++) {
            if((pObKey = ObMap_GetByIndex(pHive->Snapshot.pmKeyOffset, i))) {
                VmmWinReg_KeyFullPath(pHive, pObKey, uszHivePrefix, pHive->uszHiveRootPath + oHive, uszFullPath);
                // registry timeline:
                pfnKeyCB(H, hCallback1, hCallback2, uszFullPath, pHive->vaCMHIVE, pObKey->oCell, pObKey->pKey->Parent, pObKey->pKey->LastWriteTime);
                // registry json data:
                pfnJsonKeyCB(H, ctx, uszFullPath, pObKey->pKey->LastWriteTime);
                if((pmObValues = VmmWinReg_KeyValueList(H, pHive, pObKey))) {
                    for(j = 0, jMax = ObMap_Size(pmObValues); j < jMax; j++) {
                        if((pObValue = ObMap_GetByIndex(pmObValues, j))) {
                            VmmWinReg_ValueInfo(pHive, pObValue, &ctx->value.info);
                            VmmWinReg_ValueQueryInternal(pHive, pObValue, NULL, NULL, NULL, ctx->value.pb, sizeof(ctx->value.pb), &ctx->value.cb, 0);
                            pfnJsonValueCB(H, ctx);
                            Ob_DECREF_NULL(&pObValue);
                        }
                    }
                    Ob_DECREF_NULL(&pmObValues);
                }
                Ob_DECREF(pObKey);
            }
        }
    }
    LocalFree(ctx);
}
