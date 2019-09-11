// vmmwinreg.c : implementation of functionality related to the Windows registry.
//
// (c) Ulf Frisk, 2019
// Author: Ulf Frisk, pcileech@frizk.net
//
// Registry key parsing partly built on documentatin found at:
// https://github.com/msuhanov/regf
// 

#include "vmmwinreg.h"
#include "leechcore.h"
#include "pe.h"
#include "util.h"
#include "vmmwin.h"

#define REG_SIGNATURE_HBIN      0x6e696268

typedef struct tdVMMWIN_REGISTRY_OFFSET {
    QWORD vaHintCMHIVE;
    struct {
        WORD Signature;
        WORD FLink;
        WORD Length;
        WORD StorageMap;
        WORD StorageSmallDir;
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
* -- return
*/
PVMM_PROCESS VmmWinReg_GetRegistryProcess()
{
    PVMM_PROCESS pObProcess = VmmProcessGet(ctxVmm->kernel.dwPidRegistry);
    if(pObProcess) { return pObProcess; }
    return VmmProcessGet(4);
}

#define _IS_HMAP_KDDR64(a)    ((a & 0xffff8000'00000ff0) == 0xffff8000'00000000)
#define _IS_HMAP_ADDR64(a)     (a && ((((a >> 47) == 0x1ffff) || (a >> 47) == 0)) && (a & 0x0000ffff'ffff0000) && !(a & 0xff0))
#define _IS_HMAP_ZERO64(a)     (!a)
#define _IS_HMAP_SIZE64(a)     (a && !(a & 0xffffffff'ffff0fff))
#define _IS_HMAP_ZERO32(a)     (!a)
#define _IS_HMAP_KDDR32(a)     (((a & 0x80000ff0) == 0x80000000) && (a & 0xfff00000))
#define _IS_HMAP_ADDR32(a)     (!(a & 0xff0) && (a & 0xfff00000))
#define _IS_HMAP_SIZE32(a)     (a && !(a & 0xffff0fff))

_Success_(return)
BOOL VmmWinReg_Reg2Virt64(_In_ PVMM_PROCESS pProcessRegistry, _In_ POB_REGISTRY_HIVE pRegistryHive, _In_ DWORD ra, _Out_ PQWORD pva)
{
    PVMMWIN_REGISTRY_OFFSET po = &ctxVmm->pRegistry->Offset;
    QWORD iDirectory, iTable;
    QWORD vaTable, vaCell, oCell;
    BYTE pbHE[0x40];
    if(ra >= pRegistryHive->cbLength) { return FALSE; }
    // TRANSLATION REMINDS OF X86 MEMORY MODEL
    // 1-bit    10-bits   9-bits    12-bits
    // +-----+-----------+-------+-------------+
    // | S/V | DIRECTORY | TABLE | CELL OFFSET |
    // +-----+-----------+-------+-------------+
    iDirectory = (ra >> (12 + 9)) & 0x3ff;
    iTable = (ra >> 12) & 0x1ff;
    if(iDirectory || !pRegistryHive->vaHMAP_TABLE_SmallDir) {
        // REG directory is array of max 1024 pointers to tables [ nt!_HMAP_DIRECTORY +0x000 Directory : [1024] Ptr64 _HMAP_TABLE ]
        if(!VmmRead(pProcessRegistry, pRegistryHive->vaHMAP_DIRECTORY + iDirectory * sizeof(QWORD), (PBYTE)&vaTable, sizeof(QWORD)) || !vaTable) { return FALSE; }
        if((vaTable & 0xffff8000'00000000) != 0xffff8000'00000000) { return FALSE; }  // not kernel addrees
    } else {
        vaTable = pRegistryHive->vaHMAP_TABLE_SmallDir;
    }
    // REG table is array of 512 _HMAP_ENTRY of size 0x18 or 0x20 or 0x28
    // [ --------------------------------------- ]
    // [ WINVISTA->WIN81: dt nt!_HMAP_ENTRY      ]
    // [    + 0x000 BlockAddress : Uint8B        ]
    // [ --------------------------------------- ]
    // [    WINDOWS10 : dt nt!_HMAP_ENTRY        ]
    // [    + 0x000 BlockOffset : Uint8B         ]
    // [    + 0x008 PermanentBinAddress : Uint8B ]
    // [ --------------------------------------- ]
    if(!VmmRead(pProcessRegistry, vaTable + iTable * po->HE._Size, (PBYTE)&pbHE, po->HE._Size)) { return FALSE; }
    if(ctxVmm->kernel.dwVersionMajor == 10) {
        oCell = *(PQWORD)pbHE;
        vaCell = *(PQWORD)(pbHE + 8);
        if((oCell & 0xfff) || (oCell >= 0x10000)) { return FALSE; }
        vaCell += oCell;
    } else {
        vaCell = *(PQWORD)pbHE;
    }
    if(!_IS_HMAP_ADDR64(vaCell)) { return FALSE; }
    *pva = (vaCell & 0xffffffff'fffff000) | (ra & 0xfff);
    return TRUE;
}

_Success_(return)
BOOL VmmWinReg_Reg2Virt32(_In_ PVMM_PROCESS pProcessRegistry, _In_ POB_REGISTRY_HIVE pRegistryHive, _In_ DWORD ra, _Out_ PQWORD pva)
{
    PVMMWIN_REGISTRY_OFFSET po = &ctxVmm->pRegistry->Offset;
    QWORD iDirectory, iTable;
    DWORD vaTable, vaCell, oCell;
    BYTE pbHE[0x20];
    if(ra >= pRegistryHive->cbLength) { return FALSE; }
    iDirectory = (ra >> (12 + 9)) & 0x3ff;
    iTable = (ra >> 12) & 0x1ff;
    // DIRECTORY
    if(iDirectory || !pRegistryHive->vaHMAP_TABLE_SmallDir) {
        if(!VmmRead(pProcessRegistry, pRegistryHive->vaHMAP_DIRECTORY + iDirectory * sizeof(DWORD), (PBYTE)&vaTable, sizeof(DWORD)) || !vaTable) { return FALSE; }
        if((vaTable & 0x80000000) != 0x80000000) { return FALSE; }  // not kernel address
    } else {
        vaTable = (DWORD)pRegistryHive->vaHMAP_TABLE_SmallDir;
    }
    // [ --------------------------------------- ]
    // [ WINVISTA->WIN81: dt nt!_HMAP_ENTRY      ]
    // [    + 0x000 BlockAddress : Uint4B        ]
    // [ --------------------------------------- ]
    // [    WINDOWS10 : dt nt!_HMAP_ENTRY        ]
    // [    + 0x000 BlockOffset : Uint4B         ]
    // [    + 0x004 PermanentBinAddress : Uint4B ]
    // [ --------------------------------------- ]
    if(!VmmRead(pProcessRegistry, vaTable + iTable * po->HE._Size, (PBYTE)&pbHE, po->HE._Size)) { return FALSE; }
    if(ctxVmm->kernel.dwVersionMajor == 10) {
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
BOOL VmmWinReg_Reg2Virt(_In_ PVMM_PROCESS pProcessRegistry, _In_ POB_REGISTRY_HIVE pRegistryHive, _In_ DWORD ra, _Out_ PQWORD pva)
{
    if(!pProcessRegistry || !pRegistryHive) { return FALSE; }
    return ctxVmm->f32 ?
        VmmWinReg_Reg2Virt32(pProcessRegistry, pRegistryHive, ra, pva) :
        VmmWinReg_Reg2Virt64(pProcessRegistry, pRegistryHive, ra, pva);
}

/*
* Read scatter registry address. This translates each registry memory scatter
* request item into a virtual memory scatter request item and submits it to
* the underlying vmm sub-system. See VmmReadScatterVirtual for additional
* information.
* -- pProcessRegistry
* -- pRegistryHive
* -- ppMEMsReg
* -- cpMEMsReg
* -- flags
*/
VOID VmmWinReg_ReadScatter(_In_ PVMM_PROCESS pProcessRegistry, _In_ POB_REGISTRY_HIVE pRegistryHive, _Inout_ PPMEM_IO_SCATTER_HEADER ppMEMsReg, _In_ DWORD cpMEMsReg, _In_ QWORD flags)
{
    QWORD va;
    DWORD i = 0, iRA, iVA;
    BYTE pbBufferSmall[0x20 * (sizeof(MEM_IO_SCATTER_HEADER) + sizeof(PMEM_IO_SCATTER_HEADER))];
    PBYTE pbBufferMEMs, pbBufferLarge = NULL;
    PMEM_IO_SCATTER_HEADER pIoVA, pIoRA;
    PPMEM_IO_SCATTER_HEADER ppMEMsVirt = NULL;
    // 1: allocate / set up buffers (if needed)
    if(cpMEMsReg < 0x20) {
        ppMEMsVirt = (PPMEM_IO_SCATTER_HEADER)pbBufferSmall;
        pbBufferMEMs = pbBufferSmall + cpMEMsReg * sizeof(PMEM_IO_SCATTER_HEADER);
    } else {
        if(!(pbBufferLarge = LocalAlloc(0, cpMEMsReg * (sizeof(MEM_IO_SCATTER_HEADER) + sizeof(PMEM_IO_SCATTER_HEADER))))) { return; }
        ppMEMsVirt = (PPMEM_IO_SCATTER_HEADER)pbBufferLarge;
        pbBufferMEMs = pbBufferLarge + cpMEMsReg * sizeof(PMEM_IO_SCATTER_HEADER);
    }
    // 2: translate reg2virt
    for(iRA = 0, iVA = 0; iRA < cpMEMsReg; iRA++) {
        pIoRA = ppMEMsReg[iRA];
        if(VmmWinReg_Reg2Virt(pProcessRegistry, pRegistryHive, (DWORD)pIoRA->qwA, &va)) {
            pIoVA = ppMEMsVirt[iVA] = (PMEM_IO_SCATTER_HEADER)pbBufferMEMs + iVA;
            iVA++;
            pIoVA->magic = MEM_IO_SCATTER_HEADER_MAGIC;
            pIoVA->version = MEM_IO_SCATTER_HEADER_VERSION;
            pIoVA->qwA = va;
            pIoVA->cbMax = 0x1000;
            pIoVA->cb = 0;
            pIoVA->pb = pIoRA->pb;
            pIoVA->pvReserved1 = (PVOID)pIoRA;
        } else {
            pIoRA->cb = 0;
        }
    }
    // 3: read and check result
    VmmReadScatterVirtual(pProcessRegistry, ppMEMsVirt, iVA, flags);
    while(iVA > 0) {
        pIoVA = ppMEMsVirt[--iVA];
        pIoRA = (PMEM_IO_SCATTER_HEADER)pIoVA->pvReserved1;
        pIoRA->cb = pIoVA->cb;
    }
    LocalFree(pbBufferLarge);
}

/*
* Read a contigious arbitrary amount of registry hive memory and report the
* number of bytes read in pcbRead.
* NB! Address space does not include regf registry hive file header!
* -- pRegistryHive
* -- ra
* -- pb
* -- cb
* -- pcbRead
* -- flags = flags as in VMM_FLAG_*
*/
VOID VmmWinReg_HiveReadEx(_In_ POB_REGISTRY_HIVE pRegistryHive, _In_ DWORD ra, _Out_writes_(cb) PBYTE pb, _In_ DWORD cb, _Out_opt_ PDWORD pcbReadOpt, _In_ QWORD flags)
{
    PVMM_PROCESS pObProcessRegistry = NULL;
    DWORD cbP, cMEMs, cbRead = 0;
    PBYTE pbBuffer;
    PMEM_IO_SCATTER_HEADER pMEMs, * ppMEMs;
    QWORD i, oVA;
    if(pcbReadOpt) { *pcbReadOpt = 0; }
    if(!cb) { return; }
    cMEMs = (DWORD)(((ra & 0xfff) + cb + 0xfff) >> 12);
    pbBuffer = (PBYTE)LocalAlloc(LMEM_ZEROINIT, 0x2000 + cMEMs * (sizeof(MEM_IO_SCATTER_HEADER) + sizeof(PMEM_IO_SCATTER_HEADER)));
    if(!pbBuffer) { return; }
    pMEMs = (PMEM_IO_SCATTER_HEADER)(pbBuffer + 0x2000);
    ppMEMs = (PPMEM_IO_SCATTER_HEADER)(pbBuffer + 0x2000 + cMEMs * sizeof(MEM_IO_SCATTER_HEADER));
    oVA = ra & 0xfff;
    // prepare "middle" pages
    for(i = 0; i < cMEMs; i++) {
        ppMEMs[i] = &pMEMs[i];
        pMEMs[i].magic = MEM_IO_SCATTER_HEADER_MAGIC;
        pMEMs[i].version = MEM_IO_SCATTER_HEADER_VERSION;
        pMEMs[i].qwA = ra - oVA + (i << 12);
        pMEMs[i].cbMax = 0x1000;
        pMEMs[i].pb = pb - oVA + (i << 12);
    }
    // fixup "first/last" pages
    pMEMs[0].pb = pbBuffer;
    if(cMEMs > 1) {
        pMEMs[cMEMs - 1].pb = pbBuffer + 0x1000;
    }
    // Read REG and handle result
    pObProcessRegistry = VmmWinReg_GetRegistryProcess();
    if(pObProcessRegistry) {
        VmmWinReg_ReadScatter(pObProcessRegistry, pRegistryHive, ppMEMs, cMEMs, flags);
        Ob_DECREF(pObProcessRegistry);
        pObProcessRegistry = NULL;
    }
    for(i = 0; i < cMEMs; i++) {
        if(pMEMs[i].cb == 0x1000) {
            cbRead += 0x1000;
        } else {
            ZeroMemory(pMEMs[i].pb, 0x1000);
        }
    }
    cbRead -= (pMEMs[0].cb == 0x1000) ? 0x1000 : 0;                             // adjust byte count for first page (if needed)
    cbRead -= ((cMEMs > 1) && (pMEMs[cMEMs - 1].cb == 0x1000)) ? 0x1000 : 0;    // adjust byte count for last page (if needed)
    // Handle first page
    cbP = (DWORD)min(cb, 0x1000 - oVA);
    if(pMEMs[0].cb == 0x1000) {
        memcpy(pb, pMEMs[0].pb + oVA, cbP);
        cbRead += cbP;
    } else {
        ZeroMemory(pb, cbP);
    }
    // Handle last page
    if(cMEMs > 1) {
        cbP = (((ra + cb) & 0xfff) ? ((ra + cb) & 0xfff) : 0x1000);
        if(pMEMs[cMEMs - 1].cb == 0x1000) {
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
BOOL VmmWinReg_HiveRead(_In_ POB_REGISTRY_HIVE pRegistryHive, _In_ DWORD ra, _Out_ PBYTE pb, _In_ DWORD cb)
{
    DWORD cbRead;
    VmmWinReg_HiveReadEx(pRegistryHive, ra, pb, cb, &cbRead, 0);
    return (cbRead == cb);
}

/*
* Write a virtually contigious arbitrary amount of memory.
* NB! Address space does not include regf registry hive file header!
* -- pRegistryHive
* -- ra
* -- pb
* -- cb
* -- return = TRUE on success, FALSE on partial or zero write.
*/
_Success_(return)
BOOL VmmWinReg_HiveWrite(_In_ POB_REGISTRY_HIVE pRegistryHive, _In_ DWORD ra, _In_ PBYTE pb, _In_ DWORD cb)
{
    QWORD vaWrite;
    DWORD cbWrite;
    BOOL fSuccess = TRUE;
    PVMM_PROCESS pObProcessRegistry = NULL;
    if(!cb || !(pObProcessRegistry = VmmWinReg_GetRegistryProcess())) { return FALSE; }
    while(cb) {
        cbWrite = 0x1000 - (ra & 0xfff);
        if(VmmWinReg_Reg2Virt(pObProcessRegistry, pRegistryHive, ra, &vaWrite) && vaWrite) {
            fSuccess = VmmWrite(pObProcessRegistry, vaWrite, pb, cbWrite) && fSuccess;
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
// success offsets are stored in the core ctxVmm->RegistryOffset global object.
//-----------------------------------------------------------------------------

VOID VmmWinReg_FuzzHiveOffsets_PrintResultVerbose(_In_ PBYTE pb, _In_ DWORD cb)
{
    PVMMWIN_REGISTRY_OFFSET po = &ctxVmm->pRegistry->Offset;
    if(ctxMain->cfg.fVerboseExtra) {
        vmmprintfvv_fn("\n");
        vmmprintfvv(
            "    CM.Sig   %03X, CM.Length %03X, CM.StorMap   %03X, CM.StorSmallDir %03X, CM.BaseBlock %03X \n",
            po->CM.Signature, po->CM.Length, po->CM.StorageMap, po->CM.StorageSmallDir, po->CM.BaseBlock);
        vmmprintfvv(
            "    CM.FLink %03X, CM._Size  %03X, CM.FileFull  %03X, CM.FileUserPath %03X, CM.HiveRoot  %03X \n",
            po->CM.FLink, po->CM._Size, po->CM.FileFullPathOpt, po->CM.FileUserNameOpt, po->CM.HiveRootPathOpt);
        vmmprintfvv(
            "    BB.Sig   %03X, BB.Length %03X, BB.FileName  %03X, BB.Major        %03X, BB.Minor     %03X, HE._Size %03X \n",
            po->BB.Signature, po->BB.Length, po->BB.FileName, po->BB.Major, po->BB.Minor, po->HE._Size);
        Util_PrintHexAscii(pb, cb, 0);
        vmmprintfvv("----------------\n");
    }
}

/*
* Fuzz required offsets for registry structures and upon success store the
* result in ctxVmm->RegistryOffset. This function is overly complicated and
* should ideally be replaced with parsing the structs from Microsoft SymSrv -
* but that will introduce additional dependencies also ... This works for now.
*/
BOOL VmmWinReg_FuzzHiveOffsets64(_In_ PVMM_PROCESS pProcessSystem, _In_ QWORD vaCMHIVE, _In_reads_(0x1000) PBYTE pbCMHIVE)
{
    BOOL f;
    WORD o;
    DWORD dw;
    QWORD qw, vaSmallDir;
    WCHAR wszBuffer[10];
    QWORD qwHE[10];
    PVMMWIN_REGISTRY_OFFSET po;
    // _CMHIVE BASE
    if((*(PDWORD)(pbCMHIVE + 0x004) == 0x30314D43) || (*(PDWORD)(pbCMHIVE + 0x010) == 0xBEE0BEE0)) {
        pbCMHIVE += 0x10;
        if(vaCMHIVE) { vaCMHIVE += 0x10; }
    }
    if(*(PDWORD)(pbCMHIVE + 0x000) != 0xBEE0BEE0) { return FALSE; }
    po = &ctxVmm->pRegistry->Offset;
    po->CM.Signature = 0;
    // _CMHIVE.BaseBlock
    for(o = 0x30; o < 0x60; o += 8) {
        f = (*(PQWORD)(pbCMHIVE + o) & 0xffff8000'00000fff) == 0xffff8000'00000000;
        if(f) { break; }
    }
    if(!f) { return FALSE; }
    po->CM.BaseBlock = o;
    // _CMHIVE _HHIVE.STORAGE._DUAL[1]
    for(; o < 0x800; o += 8) {
        vaSmallDir = *(PQWORD)(pbCMHIVE + o + 0x010);                                           // _DUAL.SmallDir may be zero sometimes ...
        f = (*(PDWORD)(pbCMHIVE + o + 0x018) == 0xffffffff) &&                                  // _DUAL.Guard
            (*(PDWORD)(pbCMHIVE + o + 0x000) < 0x40000000) &&                                   // _DUAL.Length < 1GB
            ((*(PQWORD)(pbCMHIVE + o + 0x008) & 0xffff8000'00000007) == 0xffff8000'00000000) && // _DUAL.Map = kernel 8-byte align
            ((vaSmallDir == 0) || ((vaSmallDir & 0xffff8000'00000fff) == 0xffff8000'00000000)) && // _DUAL.SmallDir = kernel page base
            VmmRead(pProcessSystem, *(PQWORD)(pbCMHIVE + o + 0x008), (PBYTE)&qw, sizeof(QWORD)) && // [_DUAL.Map][0]
            ((vaSmallDir == 0) || (vaSmallDir == qw));                                          // _DUAL.SmallDir = 1st entry in _DUAL.Map 'directory'
        if(f) { break; }
    }
    if(!f) { return FALSE; }
    po->CM.Length = o + 0x000;
    po->CM.StorageMap = o + 0x008;
    po->CM.StorageSmallDir = o + 0x010;
    o += 2 * 0x278;                                                                             // sizeof(_DUAL WINVISTA-WIN10)
    // _CMHIVE _LIST_ENTRY
    for(; o < 0xff0; o += 8) {
        f = ((*(PQWORD)(pbCMHIVE + o) & 0xffff8000'00000007) == 0xffff8000'00000000) &&         // FLink
            ((*(PQWORD)(pbCMHIVE + o + 8) & 0xffff8000'00000007) == 0xffff8000'00000000) &&     // BLink
            (*(PQWORD)(pbCMHIVE + o) != *(PQWORD)(pbCMHIVE + o + 8)) &&                         // FLink != BLink
            ((*(PQWORD)(pbCMHIVE + o) - o) != vaCMHIVE) &&                                      // Not ptr to this CMHIVE
            VmmRead(pProcessSystem, *(PQWORD)(pbCMHIVE + o) + 8, (PBYTE)&qw, sizeof(QWORD)) &&  // Read FLink->BLink
            (!vaCMHIVE || (qw - o == vaCMHIVE)) &&                                              // vaCMHIVE == FLink->BLink
            VmmRead(pProcessSystem, ((*(PQWORD)(pbCMHIVE + o) - o)), (PBYTE)&dw, sizeof(DWORD)) &&
            (dw == 0xBEE0BEE0);                                                                 // Signature check
        if(f) { break; }
    }
    if(!f) { return FALSE; }
    po->CM.FLink = o;
    // _CMHIVE UNICODE_STRING HiveRootPath (OPTIONAL)
    for(; o < 0xff0; o += 8) {
        f = (*(PWORD)(pbCMHIVE + o) <= *(PWORD)(pbCMHIVE + o + 2)) &&                           // UNICODE_STRING.Length <= UNICODE_STRING.MaxLength
            (*(PWORD)(pbCMHIVE + o) > 12) &&                                                    // UNICODE_STRING.Length > 12 (\\REGISTRY\\)
            (*(PWORD)(pbCMHIVE + o) < 0xff) &&                                                  // UNICODE_STRING.Length < 0xff
            ((*(PQWORD)(pbCMHIVE + o + 8) & 0xffff8000'00000000) == 0xffff8000'00000000) &&     // Is kernel address
            VmmRead(pProcessSystem, *(PQWORD)(pbCMHIVE + o + 8), (PBYTE)wszBuffer, 20) &&       // Read STRING
            !memcmp(wszBuffer, L"\\REGISTRY\\", 20);                                            // Starts with '\REGISTRY\'
        if(f) { break; }
    }
    if(f) {
        po->CM.HiveRootPathOpt = o;
        po->CM.FileFullPathOpt = po->CM.HiveRootPathOpt - 0x020;
        po->CM.FileUserNameOpt = po->CM.HiveRootPathOpt - 0x010;
    }
    po->CM._Size = max(po->CM.FLink, po->CM.HiveRootPathOpt) + 0x020;
    // _HMAP_ENTRY SIZE AND OFFSETS
    ZeroMemory(qwHE, sizeof(qwHE));
    po->HE._Size = 0x018;               // Most common (default try)
    if(!vaSmallDir) {
        VmmRead(pProcessSystem, *(PQWORD)(pbCMHIVE + po->CM.StorageMap), (PBYTE)&vaSmallDir, sizeof(QWORD));
    }
    if((vaSmallDir & 0xffff8000'00000fff) == 0xffff8000'00000000) {
        VmmRead(pProcessSystem, vaSmallDir, (PBYTE)qwHE, sizeof(qwHE));
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
    po->vaHintCMHIVE = vaCMHIVE ? vaCMHIVE : (*(PQWORD)(pbCMHIVE + po->CM.FLink) - po->CM.FLink);
    VmmWinReg_FuzzHiveOffsets_PrintResultVerbose((PBYTE)qwHE, sizeof(qwHE));
    return TRUE;
}

BOOL VmmWinReg_FuzzHiveOffsets32(_In_ PVMM_PROCESS pProcessSystem, _In_ QWORD vaCMHIVE, _In_reads_(0x1000) PBYTE pbCMHIVE)
{
    BOOL f;
    WORD o;
    DWORD dw, vaSmallDir;
    WCHAR wszBuffer[10];
    DWORD dwHE[0x10];
    PVMMWIN_REGISTRY_OFFSET po = &ctxVmm->pRegistry->Offset;
    // _CMHIVE BASE
    for(o = 0; o < 0x40; o += 8) {
        if(*(PQWORD)(pbCMHIVE + o + 0x004) == 0xBEE0BEE030314D43) {
            pbCMHIVE = pbCMHIVE + o + 0x008;
            if(vaCMHIVE) { vaCMHIVE = vaCMHIVE + o + 0x008; }
            break;
        }
    }
    if(*(PDWORD)(pbCMHIVE + 0x000) != 0xBEE0BEE0) { return FALSE; }
    po = &ctxVmm->pRegistry->Offset;
    po->CM.Signature = 0;
    // _CMHIVE.BaseBlock
    for(o = 0x18; o < 0x30; o += 4) {
        f = (*(PDWORD)(pbCMHIVE + o) & 0x80000fff) == 0x80000000;
        if(f) { break; }
    }
    if(!f) { return FALSE; }
    po->CM.BaseBlock = o;
    // _CMHIVE _HHIVE.STORAGE._DUAL[1]
    for(; o < 0x400; o += 4) {
        vaSmallDir = *(PDWORD)(pbCMHIVE + o + 0x008);                                           // _DUAL.SmallDir may be zero sometimes ...
        f = (*(PDWORD)(pbCMHIVE + o + 0x00c) == 0xffffffff) &&                                  // _DUAL.Guard
            (*(PDWORD)(pbCMHIVE + o + 0x000) < 0x40000000) &&                                   // _DUAL.Length < 1GB
            ((*(PDWORD)(pbCMHIVE + o + 0x004) & 0x80000003) == 0x80000000) &&                   // _DUAL.Map = kernel 4-byte align
            ((vaSmallDir == 0) || ((vaSmallDir & 0x80000fff) == 0x80000000)) &&                 // _DUAL.SmallDir = kernel page base
            VmmRead(pProcessSystem, *(PDWORD)(pbCMHIVE + o + 0x004), (PBYTE)&dw, sizeof(DWORD)) &&  // [_DUAL.Map][0]
            ((vaSmallDir == 0) || (vaSmallDir == dw));                                          // _DUAL.SmallDir = 1st entry in _DUAL.Map 'directory'
        if(f) { break; }
    }
    if(!f) { return FALSE; }
    po->CM.Length = o + 0x000;
    po->CM.StorageMap = o + 0x004;
    po->CM.StorageSmallDir = o + 0x008;
    o += 2 * 0xdc;                                                                              // sizeof(_DUAL) 0xdc on WinXP, 0x13c on Win7SP0, but grows to 0x19c on later versions, use the smaller value.
    // _CMHIVE _LIST_ENTRY
    for(; o < 0x800; o += 4) {
        f = ((*(PDWORD)(pbCMHIVE + o) & 0x80000003) == 0x80000000) &&                                   // FLink
            ((*(PDWORD)(pbCMHIVE + o + 4) & 0x80000003) == 0x80000000) &&                               // BLink
            (*(PDWORD)(pbCMHIVE + o) != *(PDWORD)(pbCMHIVE + o + 4)) &&                                 // FLink != BLink
            VmmRead(pProcessSystem, *(PDWORD)(pbCMHIVE + o) + sizeof(DWORD), (PBYTE)&dw, sizeof(DWORD)) && // Read FLink->BLink
            VmmRead(pProcessSystem, (QWORD)dw - o + po->CM.Signature, (PBYTE)&dw, sizeof(DWORD)) &&     // Read (FLink->BLink) Signature
            (dw == 0xBEE0BEE0) &&                                                                       // Signature check
            VmmRead(pProcessSystem, *(PDWORD)(pbCMHIVE + o + 4), (PBYTE)&dw, sizeof(DWORD)) &&          // Read BLink->FLink
            VmmRead(pProcessSystem, (QWORD)dw - o + po->CM.Signature, (PBYTE)&dw, sizeof(DWORD)) &&     // Read (BLink->FLink) Signature
            (dw == 0xBEE0BEE0);                                                                         // Signature check
        if(f) { break; }
    }
    if(!f) { return FALSE; }
    po->CM.FLink = o;
    // _CMHIVE UNICODE_STRING HiveRootPath
    for(o = po->CM.FLink; o < 0xf00; o += 4) {
        f = (*(PWORD)(pbCMHIVE + o) <= *(PWORD)(pbCMHIVE + o + 2)) &&                           // UNICODE_STRING.Length <= UNICODE_STRING.MaxLength
            (*(PWORD)(pbCMHIVE + o) > 12) &&                                                    // UNICODE_STRING.Length > 12 (\\REGISTRY\\)
            (*(PWORD)(pbCMHIVE + o) < 0xff) &&                                                  // UNICODE_STRING.Length < 0xff
            ((*(PDWORD)(pbCMHIVE + o + 4) & 0x80000000) == 0x80000000) &&                       // Is kernel address
            VmmRead(pProcessSystem, *(PDWORD)(pbCMHIVE + o + 4), (PBYTE)wszBuffer, 20) &&       // Read STRING
            !memcmp(wszBuffer, L"\\REGISTRY\\", 20);                                            // Starts with '\REGISTRY\'
        if(f) {
            po->CM.HiveRootPathOpt = o;
            break;
        }
    }
    if(f) {
        po->CM.FileFullPathOpt = po->CM.HiveRootPathOpt - 0x010;
        po->CM.FileUserNameOpt = po->CM.HiveRootPathOpt - 0x008;
    }
    po->CM._Size = max(po->CM.FLink, po->CM.HiveRootPathOpt) + 0x010;
    // _HMAP_ENTRY SIZE AND OFFSETS
    ZeroMemory(dwHE, sizeof(dwHE));
    po->HE._Size = 0x00c;               // Most common (default try)
    if(!vaSmallDir) {
        VmmRead(pProcessSystem, *(PDWORD)(pbCMHIVE + po->CM.StorageMap), (PBYTE)&vaSmallDir, sizeof(DWORD));
    }
    if((vaSmallDir & 0x80000fff) == 0x80000000) {
        VmmRead(pProcessSystem, vaSmallDir, (PBYTE)dwHE, sizeof(dwHE));
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
    po->vaHintCMHIVE = vaCMHIVE ? vaCMHIVE : (*(PDWORD)(pbCMHIVE + po->CM.FLink) - po->CM.FLink);
    VmmWinReg_FuzzHiveOffsets_PrintResultVerbose((PBYTE)dwHE, sizeof(dwHE));
    return TRUE;
}

/*
* Locate a registry hive. Once a single registry hive is located the linked
* list may be traversed to enumerate the remaining registry hives.
* The search algorithm looks for promising addresses in ntoskrnl.exe .data
* section and checks if any of these addresses are part of a CMHIVE. If the
* above technique fail then the lower memory is scanned (also fail sometimes).
* -- return
*/
#define MAX_NUM_POTENTIAL_HIVE_HINT        0x20
BOOL VmmWinReg_LocateRegistryHive()
{
    BOOL result = FALSE;
    BOOL f32 = ctxVmm->f32;
    PVMM_PROCESS pObProcessSystem = VmmProcessGet(4);
    IMAGE_SECTION_HEADER SectionHeader;
    DWORD iSection, cbSectionSize, cbPoolHdr, cbPoolHdrMax, cPotentialHive, o, p, i;
    QWORD vaPotentialHive[MAX_NUM_POTENTIAL_HIVE_HINT];
    PBYTE pb = NULL;
    PPMEM_IO_SCATTER_HEADER ppMEMs = NULL;
    if(!VmmProcessGet(4) || !(pb = LocalAlloc(0, 0x01000000))) { goto cleanup; }
    // 1: Try locate registry by scanning ntoskrnl.exe .data section.
    for(iSection = 0; iSection < 2; iSection++) {    // 1st check '.data' section, then PAGEDATA' for pointers.
        if(!PE_SectionGetFromName(pObProcessSystem, ctxVmm->kernel.vaBase, iSection ? "PAGEDATA" : ".data", &SectionHeader)) { goto cleanup; }
        cbSectionSize = min(0x01000000, SectionHeader.Misc.VirtualSize);
        VmmReadEx(pObProcessSystem, ctxVmm->kernel.vaBase + SectionHeader.VirtualAddress, pb, min(0x01000000, SectionHeader.Misc.VirtualSize), NULL, VMM_FLAG_ZEROPAD_ON_FAIL);
        cbPoolHdrMax = f32 ? 0x08 : 0x10;
        for(cbPoolHdr = 0; cbPoolHdr <= cbPoolHdrMax; cbPoolHdr += cbPoolHdrMax) {
            for(cPotentialHive = 0, o = 0; o < cbSectionSize && cPotentialHive < MAX_NUM_POTENTIAL_HIVE_HINT; o += (f32 ? 4 : 8)) {
                if(f32) {
                    if((*(PDWORD)(pb + o) & 0x80000fff) == 0x80000000 + cbPoolHdr) {
                        vaPotentialHive[cPotentialHive++] = *(PDWORD)(pb + o);
                    }
                } else {
                    if((*(PQWORD)(pb + o) & 0xffff8000'00000fff) == (0xffff8000'00000000 + cbPoolHdr)) {
                        vaPotentialHive[cPotentialHive++] = *(PQWORD)(pb + o);
                    }
                }
            }
            if(!cPotentialHive) { continue; }
            if(!LeechCore_AllocScatterEmpty(cPotentialHive, &ppMEMs)) { continue; }
            for(i = 0; i < cPotentialHive; i++) {
                ppMEMs[i]->qwA = vaPotentialHive[i] & ~0xfff;
            }
            VmmReadScatterVirtual(pObProcessSystem, ppMEMs, cPotentialHive, 0);
            for(i = 0; i < cPotentialHive; i++) {
                if(ppMEMs[i]->cb == 0x1000) {
                    if((result = f32 ? VmmWinReg_FuzzHiveOffsets32(pObProcessSystem, ppMEMs[i]->qwA, ppMEMs[i]->pb) : VmmWinReg_FuzzHiveOffsets64(pObProcessSystem, ppMEMs[i]->qwA, ppMEMs[i]->pb))) {
                        goto cleanup;
                    }
                }
            }
        }
    }
    // 2: As a fallback - try locate registry by scanning lower physical memory.
    //    This is much slower, but will work sometimes when the above method fail.
    for(o = 0x00000000; o < 0x08000000; o += 0x01000000) {
        VmmReadEx(NULL, o, pb, 0x01000000, NULL, 0);
        for(p = 0; p < 0x01000000; p += 0x1000) {
            if((result = f32 ? VmmWinReg_FuzzHiveOffsets32(pObProcessSystem, 0, pb + p) : VmmWinReg_FuzzHiveOffsets64(pObProcessSystem, 0, pb + p))) {
                goto cleanup;
            }
        }
    }
cleanup:
    LocalFree(pb);
    LocalFree(ppMEMs);
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
    LocalFree(pOb->Snapshot.pb);
}

/*
* Callback function from VmmWin_ListTraversePrefetch[32|64].
* Gather referenced addresses into prefetch dataset.
*/
VOID VmmWinReg_EnumHive64_Pre(_In_ PVMM_PROCESS pProcess, _In_opt_ POB_MAP pHiveMap, _In_ QWORD va, _In_ PBYTE pb, _In_ DWORD cb, _In_ QWORD vaFLink, _In_ QWORD vaBLink, _In_ POB_VSET pVSetAddress, _Inout_ PBOOL pfValidEntry, _Inout_ PBOOL pfValidFLink, _Inout_ PBOOL pfValidBLink)
{
    PVMMWIN_REGISTRY_OFFSET po = &ctxVmm->pRegistry->Offset;
    if((va & 0xffff8000'00000007) != 0xffff8000'00000000) { return; }               // not aligned kernel address
    *pfValidFLink = ((vaFLink & 0xffff8000'00000007) == 0xffff8000'00000000);       // aligned kernel address
    *pfValidBLink = ((vaBLink & 0xffff8000'00000007) == 0xffff8000'00000000);       // aligned kernel address
    if(*pfValidFLink && *pfValidBLink && (*(PDWORD)(pb + po->CM.Signature) == 0xBEE0BEE0) && ((*(PQWORD)(pb + po->CM.BaseBlock) & 0xfff) == 0x000)) {
        ObVSet_Push(pVSetAddress, *(PQWORD)(pb + po->CM.BaseBlock));
        if(po->CM.HiveRootPathOpt && *(PQWORD)(pb + po->CM.HiveRootPathOpt)) {  // _CMHIVE.HiveRootPath
            ObVSet_Push(pVSetAddress, *(PQWORD)(pb + po->CM.HiveRootPathOpt + 8) & ~0xfff);
        }
        *pfValidEntry = TRUE;
    }
}

VOID VmmWinReg_EnumHive32_Pre(_In_ PVMM_PROCESS pProcess, _In_opt_ POB_MAP pHiveMap, _In_ QWORD va, _In_ PBYTE pb, _In_ DWORD cb, _In_ QWORD vaFLink, _In_ QWORD vaBLink, _In_ POB_VSET pVSetAddress, _Inout_ PBOOL pfValidEntry, _Inout_ PBOOL pfValidFLink, _Inout_ PBOOL pfValidBLink)
{
    PVMMWIN_REGISTRY_OFFSET po = &ctxVmm->pRegistry->Offset;
    if((va & 0x80000007) != 0x80000000) { return; }         // not aligned kernel address
    *pfValidFLink = ((vaFLink & 0x80000003) == 0x80000000);       // aligned kernel address
    *pfValidBLink = ((vaBLink & 0x80000003) == 0x80000000);       // aligned kernel address
    if(*pfValidFLink && *pfValidBLink && (*(PDWORD)(pb + po->CM.Signature) == 0xBEE0BEE0) && ((*(PDWORD)(pb + po->CM.BaseBlock) & 0xfff) == 0x000)) {
        ObVSet_Push(pVSetAddress, *(PDWORD)(pb + po->CM.BaseBlock));
        if(po->CM.HiveRootPathOpt && *(PDWORD)(pb + po->CM.HiveRootPathOpt)) {  // _CMHIVE.HiveRootPath
            ObVSet_Push(pVSetAddress, *(PDWORD)(pb + po->CM.HiveRootPathOpt + 4) & ~0xfff);
        }
        *pfValidEntry = TRUE;
    }
}

VOID VmmWinReg_ListTraversePrefetch_CallbackPost_GetShortName(_In_ LPWSTR wsz, _Out_writes_(32) LPSTR sz)
{
    DWORD i, iStart = 0;
    for(i = 0; i < 32; i++) {
        if(wsz[i] == L'\\') { iStart = i + 1; }
    }
    for(i = 0; iStart < 32; iStart++) {
        if(((wsz[iStart] >= L'0') && (wsz[iStart] <= L'9')) || ((wsz[iStart] >= L'a') && (wsz[iStart] <= L'z')) || ((wsz[iStart] >= L'A') && (wsz[iStart] <= L'Z'))) { sz[i++] = (CHAR)wsz[iStart]; }
        if(!wsz[iStart]) { break; }
    }
}

/*
* Callback function from VmmWin_ListTraversePrefetch[32|64].
* Set up a single Registry Hive.
*/
BOOL VmmWinReg_EnumHive64_Post(_In_ PVMM_PROCESS pProcess, _In_opt_ POB_MAP pHiveMap, _In_ QWORD vaData, _In_ PBYTE pbData, _In_ DWORD cbData)
{
    BOOL f;
    CHAR chDefault = '_';
    BOOL fBoolTrue = TRUE;
    CHAR szHiveFileNameShort[32+1] = { 0 };
    CHAR szHiveFileNameLong[72] = { 0 };
    POB_REGISTRY_HIVE pObHive = NULL;
    PVMMWIN_REGISTRY_OFFSET po = &ctxVmm->pRegistry->Offset;
    // 1: validity check
    if((vaData & 0xffff8000'00000000) != 0xffff8000'00000000) { return FALSE; } // not kernel address
    f = pHiveMap &&
        (*(PDWORD)(pbData + po->CM.Signature) == 0xBEE0BEE0) &&                 // Signature match
        (*(PQWORD)(pbData + po->CM.StorageMap)) &&                              // _CMHIVE.Hive.Storage.Map
        (*(PDWORD)(pbData + po->CM.Length)) &&                                  // Length > 0
        (*(PDWORD)(pbData + po->CM.Length) <= 0x40000000);                      // Length < 1GB
    if(!f) { return TRUE; }
    // 2: Allocate and Initialize
    if(!(pObHive = Ob_Alloc(OB_TAG_REG_HIVE, LMEM_ZEROINIT, sizeof(OB_REGISTRY_HIVE), VmmWinReg_CallbackCleanup_ObRegistryHive, NULL))) { return TRUE; }
    pObHive->vaCMHIVE = vaData;
    pObHive->vaHBASE_BLOCK = *(PQWORD)(pbData + po->CM.BaseBlock);
    pObHive->cbLength = *(PDWORD)(pbData + po->CM.Length);
    pObHive->vaHMAP_DIRECTORY = *(PQWORD)(pbData + po->CM.StorageMap);
    pObHive->vaHMAP_TABLE_SmallDir = *(PQWORD)(pbData + po->CM.StorageSmallDir);
    InitializeCriticalSection(&pObHive->LockUpdate);
    VmmRead(pProcess, *(PQWORD)(pbData + po->CM.BaseBlock) + po->BB.FileName, (PBYTE)pObHive->wszNameShort, sizeof(pObHive->wszNameShort) - 2);   //_HBASE_BLOCK.FileName
    if(po->CM.HiveRootPathOpt && *(PQWORD)(pbData + po->CM.HiveRootPathOpt)) {  // _CMHIVE.HiveRootPath
        VmmRead(
            pProcess,
            *(PQWORD)(pbData + po->CM.HiveRootPathOpt + 8),
            (PBYTE)pObHive->wszHiveRootPath,
            min(*(PWORD)(pbData + po->CM.HiveRootPathOpt), sizeof(pObHive->wszHiveRootPath) - 2));
    }
    // 3: Post processing
    if(pObHive->wszHiveRootPath[0] && WideCharToMultiByte(CP_ACP, 0, pObHive->wszHiveRootPath + 10, -1, szHiveFileNameLong, sizeof(szHiveFileNameLong) - 1, &chDefault, &fBoolTrue)) {
        Util_AsciiFileNameFix(szHiveFileNameLong, '_');
    }
    VmmWinReg_ListTraversePrefetch_CallbackPost_GetShortName(pObHive->wszNameShort, szHiveFileNameShort);
    snprintf(
        pObHive->szName,
        sizeof(pObHive->szName) - 1,
        "0x%llx-%s-%s",
        pObHive->vaCMHIVE,
        (szHiveFileNameShort[0] ? szHiveFileNameShort : "unknown"),
        (szHiveFileNameLong[0] ? szHiveFileNameLong : "unknown"));
    // 4: Attach and Return
    ObMap_Push(pHiveMap, pObHive->vaCMHIVE, pObHive);
    vmmprintfvv_fn("%04i %s\n", ObMap_Size(pHiveMap), pObHive->szName);
    Ob_DECREF(pObHive);
    return TRUE;
}

BOOL VmmWinReg_EnumHive32_Post(_In_ PVMM_PROCESS pProcess, _In_opt_ POB_MAP pHiveMap, _In_ QWORD vaData, _In_ PBYTE pbData, _In_ DWORD cbData)
{
    BOOL f;
    CHAR chDefault = '_';
    BOOL fBoolTrue = TRUE;
    CHAR szHiveFileNameShort[32+1] = { 0 };
    CHAR szHiveFileNameLong[72] = { 0 };
    POB_REGISTRY_HIVE pObHive = NULL;
    PVMMWIN_REGISTRY_OFFSET po = &ctxVmm->pRegistry->Offset;
    // 1: validity check
    if((vaData & 0x80000007) != 0x80000000) { return FALSE; }                   // not kernel address
    f = pHiveMap &&
        (*(PDWORD)(pbData + po->CM.Signature) == 0xBEE0BEE0) &&                 // Signature match
        !(*(PDWORD)(pbData + po->CM.BaseBlock) & 0xfff) &&                      // _CMHIVE.BaseBlock on page boundary
        (*(PQWORD)(pbData + po->CM.StorageMap)) &&                              // _CMHIVE.Hive.Storage.Map
        (*(PDWORD)(pbData + po->CM.Length)) &&                                  // Length > 0
        (*(PDWORD)(pbData + po->CM.Length) <= 0x40000000);                      // Length < 1GB
    if(!f) { return TRUE; }
    // 2: Allocate and Initialize
    if(!(pObHive = Ob_Alloc(OB_TAG_REG_HIVE, LMEM_ZEROINIT, sizeof(OB_REGISTRY_HIVE), VmmWinReg_CallbackCleanup_ObRegistryHive, NULL))) { return TRUE; }
    pObHive->vaCMHIVE = vaData;
    pObHive->vaHBASE_BLOCK = *(PDWORD)(pbData + po->CM.BaseBlock);
    pObHive->cbLength = *(PDWORD)(pbData + po->CM.Length);
    pObHive->vaHMAP_DIRECTORY = *(PDWORD)(pbData + po->CM.StorageMap);
    pObHive->vaHMAP_TABLE_SmallDir = *(PDWORD)(pbData + po->CM.StorageSmallDir);
    InitializeCriticalSection(&pObHive->LockUpdate);
    VmmRead(pProcess, (QWORD)*(PDWORD)(pbData + po->CM.BaseBlock) + po->BB.FileName, (PBYTE)pObHive->wszNameShort, sizeof(pObHive->wszNameShort) - 2);   //_HBASE_BLOCK.FileName
    if(po->CM.HiveRootPathOpt && *(PDWORD)(pbData + po->CM.HiveRootPathOpt)) {  // _CMHIVE.HiveRootPath
        VmmRead(
            pProcess,
            *(PDWORD)(pbData + po->CM.HiveRootPathOpt + 4),
            (PBYTE)pObHive->wszHiveRootPath,
            min(*(PWORD)(pbData + po->CM.HiveRootPathOpt), sizeof(pObHive->wszHiveRootPath) - 2));
    }
    // 3: Post processing
    if(pObHive->wszHiveRootPath[0] && WideCharToMultiByte(CP_ACP, 0, pObHive->wszHiveRootPath + 10, -1, szHiveFileNameLong, sizeof(szHiveFileNameLong) - 1, &chDefault, &fBoolTrue)) {
        Util_AsciiFileNameFix(szHiveFileNameLong, '_');
    }
    VmmWinReg_ListTraversePrefetch_CallbackPost_GetShortName(pObHive->wszNameShort, szHiveFileNameShort);
    snprintf(
        pObHive->szName,
        sizeof(pObHive->szName) - 1,
        "0x%llx-%s-%s",
        pObHive->vaCMHIVE,
        (szHiveFileNameShort[0] ? szHiveFileNameShort : "unknown"),
        (szHiveFileNameLong[0] ? szHiveFileNameLong : "unknown"));
    // 4: Attach and Return
    ObMap_Push(pHiveMap, pObHive->vaCMHIVE, pObHive);                   // pRegistry->pmHive takes responsibility for pObHive reference
    vmmprintfvv_fn("%04i %s\n", ObMap_Size(pHiveMap), pObHive->szName);
    return TRUE;
}

/*
* Internal function to create / set up a new registry objects.
* NB! This function must NOT be called in a multi-threaded way.
* CALLER DECREF: return
* -- return
*/
POB_MAP VmmWinReg_HiveMap_New()
{
    BOOL f32 = ctxVmm->f32;
    POB_MAP pObHiveMap = NULL;
    POB_REGISTRY_HIVE pHiveCurrent = NULL;
    PVMM_PROCESS pObProcessSystem = NULL;
    if(!(pObProcessSystem = VmmProcessGet(4))) { goto fail; }    
    if(!ctxVmm->pRegistry->Offset.vaHintCMHIVE && !VmmWinReg_LocateRegistryHive()) { goto fail; }
    if(!(pObHiveMap = ObMap_New(OB_MAP_FLAGS_OBJECT_OB))) { goto fail; }
    // Traverse the CMHIVE linked list in an efficient way
    VmmWin_ListTraversePrefetch(
        pObProcessSystem,
        f32,
        pObHiveMap,
        ctxVmm->pRegistry->Offset.vaHintCMHIVE,
        ctxVmm->pRegistry->Offset.CM.FLink,
        ctxVmm->pRegistry->Offset.CM._Size,
        f32 ? VmmWinReg_EnumHive32_Pre : VmmWinReg_EnumHive64_Pre,
        f32 ? VmmWinReg_EnumHive32_Post : VmmWinReg_EnumHive64_Post,
        ctxVmm->pObCCachePrefetchRegistry);
    ObContainer_SetOb(ctxVmm->pRegistry->pObCHiveMap, pObHiveMap);
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
* -- return = a map containing the hive objects
*/
POB_MAP VmmWinReg_HiveMap()
{
    POB_MAP pObHiveMap;
    if(!ctxVmm->pRegistry) { return NULL; }
    pObHiveMap = ObContainer_GetOb(ctxVmm->pRegistry->pObCHiveMap);
    if(!pObHiveMap) {
        EnterCriticalSection(&ctxVmm->pRegistry->LockUpdate);
        pObHiveMap = ObContainer_GetOb(ctxVmm->pRegistry->pObCHiveMap);
        if(!pObHiveMap) {
            pObHiveMap = VmmWinReg_HiveMap_New();
        }
        LeaveCriticalSection(&ctxVmm->pRegistry->LockUpdate);
    }
    return pObHiveMap;
}

_Success_(return)
BOOL VmmWinReg_KeyInitialize(_In_ POB_REGISTRY_HIVE pHive);

/*
* Ensure a registry hive snapshot is taken of the hive and stored within the
* hive object. A snapshot is created by copying the whole registry hive into
* memory and performing analysis on it to generate a key tree for convenient
* parsing of the keys. Any keys derived from the hive must never be used after
* Ob_DECREF has been called on the hive.
* -- pHive
* -- return
*/
_Success_(return)
BOOL VmmWinReg_HiveSnapshotEnsure(_In_ POB_REGISTRY_HIVE pHive)
{
    DWORD cbRead;
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
    pHive->Snapshot.pmKeyHash = ObMap_New(OB_MAP_FLAGS_OBJECT_OB);
    pHive->Snapshot.pmKeyOffset = ObMap_New(OB_MAP_FLAGS_OBJECT_OB);
    pHive->Snapshot.cb = pHive->cbLength;
    pHive->Snapshot.pb = LocalAlloc(0, pHive->Snapshot.cb);
    if(!pHive->Snapshot.pmKeyHash || !pHive->Snapshot.pmKeyOffset || !pHive->Snapshot.pb) { goto fail; }
    VmmWinReg_HiveReadEx(pHive, 0, pHive->Snapshot.pb, pHive->Snapshot.cb, &cbRead, VMM_FLAG_ZEROPAD_ON_FAIL);
    if(!VmmWinReg_KeyInitialize(pHive)) { goto fail; }
    pHive->Snapshot.fInitialized = TRUE;
    LeaveCriticalSection(&pHive->LockUpdate);
    return TRUE;
fail:
    Ob_DECREF_NULL(&pHive->Snapshot.pmKeyHash);
    Ob_DECREF_NULL(&pHive->Snapshot.pmKeyOffset);
    LocalFree(pHive->Snapshot.pb);
    pHive->Snapshot.pb = NULL;
    LeaveCriticalSection(&pHive->LockUpdate);
    return FALSE;
}



//-----------------------------------------------------------------------------
// EXPORTED INITIALIZATION/REFRESH/CLOSE FUNCTIONALITY BELOW:
//-----------------------------------------------------------------------------

VOID VmmWinReg_Initialize()
{
    PVMMWIN_REGISTRY_CONTEXT ctx;
    if(!(ctx = LocalAlloc(LMEM_ZEROINIT, sizeof(VMMWIN_REGISTRY_CONTEXT)))) { goto fail; }
    if(!(ctx->pObCHiveMap = ObContainer_New(NULL))) { goto fail; }
    InitializeCriticalSection(&ctx->LockUpdate);
    ctxVmm->pRegistry = ctx;
    return;
fail:
    if(ctx) {
        Ob_DECREF(ctx->pObCHiveMap);
        LocalFree(ctx);
    }
}

VOID VmmWinReg_Close()
{
    if(ctxVmm->pRegistry) {
        Ob_DECREF(ctxVmm->pRegistry->pObCHiveMap);
        DeleteCriticalSection(&ctxVmm->pRegistry->LockUpdate);
        LocalFree(ctxVmm->pRegistry);
        ctxVmm->pRegistry = NULL;
    }
}

VOID VmmWinReg_Refresh()
{
    if(ctxVmm->pRegistry) {
        ObContainer_SetOb(ctxVmm->pRegistry->pObCHiveMap, NULL);
    }
}



//-----------------------------------------------------------------------------
// EXPORTED HIVE FUNCTIONALITY BELOW:
//-----------------------------------------------------------------------------

DWORD VmmWinReg_HiveCount()
{
    DWORD c;
    POB_MAP pObHiveMap = VmmWinReg_HiveMap();
    c = ObMap_Size(pObHiveMap);
    Ob_DECREF(pObHiveMap);
    return c;
}

POB_REGISTRY_HIVE VmmWinReg_HiveGetNext(_In_opt_ POB_REGISTRY_HIVE pObRegistryHive)
{
    POB_MAP pObHiveMap;
    POB_REGISTRY_HIVE pObRegistryHiveReturn = NULL;
    if((pObHiveMap = VmmWinReg_HiveMap())) {
        pObRegistryHiveReturn = ObMap_GetNextByKey(pObHiveMap, (pObRegistryHive ? pObRegistryHive->vaCMHIVE : 0), pObRegistryHive);
        pObRegistryHive = NULL;
    }
    Ob_DECREF(pObHiveMap);
    Ob_DECREF(pObRegistryHive);
    return pObRegistryHiveReturn;
}

POB_REGISTRY_HIVE VmmWinReg_HiveGetByAddress(_In_ QWORD vaCMHIVE)
{
    POB_MAP pObHiveMap;
    POB_REGISTRY_HIVE pObRegistryHiveReturn = NULL;
    if((pObHiveMap = VmmWinReg_HiveMap())) {
        pObRegistryHiveReturn = ObMap_GetByKey(pObHiveMap, vaCMHIVE);
    }
    Ob_DECREF(pObHiveMap);
    return pObRegistryHiveReturn;
}

POB_REGISTRY_HIVE VmmWinReg_HiveGetByName(_In_ LPSTR szName)
{
    POB_MAP pObHiveMap = NULL;
    POB_REGISTRY_HIVE pObHive = NULL;
    pObHiveMap = VmmWinReg_HiveMap();
    while((pObHive = ObMap_GetNext(pObHiveMap, pObHive)) && !strstr(pObHive->szName, szName));
    Ob_DECREF(pObHiveMap);
    return pObHive;
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
        CHAR szName[];          // +0x04c Name : [1] Wchar
        WCHAR wszName[];        // +0x04c Name : [1] Wchar
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
        CHAR szName[];          // +0x014 Name : [1] Wchar
        WCHAR wszName[];        // +0x014 Name : [1] Wchar
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
        WORD c;
        WORD cMax;
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
#define REG_CELL_SIZE_EX(pb, iCellHead)             REG_CELL_SIZE(*(PDWORD)(pb + (iCellHead)))

VOID VmmWinReg_CallbackCleanup_ObRegKey(POB_REGISTRY_KEY pOb)
{
    LocalFree(pOb->Child.po);
}

/*
* Hash a registry key name in a way that is supported by the file system.
* NB! this is not the same hash as the Windows registry uses.
* -- wsz
* -- return
*/
DWORD VmmWinReg_KeyHashNameW(_In_ LPCWSTR wsz)
{
    DWORD i, c, dwHash = 0;
    WCHAR wszBuffer[MAX_PATH];
    c = Util_PathFileNameFix_Registry(wszBuffer, NULL, wsz, 0, 0, TRUE);
    for(i = 0; i < c; i++) {
        dwHash = ((dwHash >> 13) | (dwHash << 19)) + wszBuffer[i];
    }
    return dwHash;
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
    WCHAR wszBuffer[MAX_PATH];
    c = (pnk->Flags & REG_CM_KEY_NODE_FLAGS_COMP_NAME) ?
        Util_PathFileNameFix_Registry(wszBuffer, pnk->szName, NULL, pnk->NameLength, iSuffix, TRUE) :
        Util_PathFileNameFix_Registry(wszBuffer, NULL, pnk->wszName, pnk->NameLength, iSuffix, TRUE);
    for(i = 0; i < c; i++) {
        dwHash = ((dwHash >> 13) | (dwHash << 19)) + wszBuffer[i];
    }
    return dwHash;
}

/*
* Hash a path. Used to calculate a registry key hash from a file system path.
* -- wszPath
* -- return
*/
QWORD VmmWinReg_KeyHashPathW(_In_ LPWSTR wszPath)
{
    DWORD dwHashName;
    QWORD qwHashTotal = 0;
    WCHAR wsz1[MAX_PATH];
    while(wszPath && wszPath[0]) {
        wszPath = Util_PathSplit2_ExWCHAR(wszPath, wsz1, _countof(wsz1));
        dwHashName = VmmWinReg_KeyHashNameW(wsz1);
        qwHashTotal = dwHashName + ((qwHashTotal >> 13) | (qwHashTotal << 51));
    }
    return qwHashTotal;
}

/*
* Helper function to validate the sanity of a Cell Size.
* -- pHive
* -- oCell
* -- cbCellSizeMin
* -- cbCellSizeMax
* -- return
*/
BOOL VmmWinReg_KeyValidateCellSize(_In_ POB_REGISTRY_HIVE pHive, _In_ DWORD oCell, _In_ DWORD cbCellSizeMin, _In_ DWORD cbCellSizeMax)
{
    DWORD cbCell;
    if(oCell + 4 > pHive->Snapshot.cb) { return FALSE; }
    cbCell = REG_CELL_SIZE_EX(pHive->Snapshot.pb, oCell);
    if((cbCell < cbCellSizeMin) || (cbCell > cbCellSizeMax) || (oCell + cbCell > pHive->Snapshot.cb)) { return FALSE; }
    if(((oCell & 0xfff) + cbCell > 0x1000) && (REG_SIGNATURE_HBIN == *(PDWORD)(pHive->Snapshot.pb + ((oCell + 0xfff) & ~0xfff)))) { return FALSE; }
    return TRUE;
}

/*
* Add a child key reference to a parent key.
* -- pObKeyParent
* -- oCellChild
*/
VOID VmmWinReg_KeyInitializeCreateKey_AddChild(_In_opt_ POB_REGISTRY_KEY pObKeyParent, _In_ DWORD oCellChild)
{
    WORD cMax;
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
* -- pHive
* -- oCell
* -- iLevel
* -- return
*/
POB_REGISTRY_KEY VmmWinReg_KeyInitializeCreateKey(_In_ POB_REGISTRY_HIVE pHive, _In_ DWORD oCell, _In_ DWORD iLevel)
{
    QWORD qwKeyHash;
    WORD iSuffix = 0;
    DWORD dwCellHead, cbCell, cbKey, dwNameHash;
	PREG_CM_KEY_NODE pnk;
	POB_REGISTRY_KEY pObKeyParent = NULL, pObKey = NULL;
	// 1: already exists in cache ?
	if((pObKey = ObMap_GetByKey(pHive->Snapshot.pmKeyOffset, oCell))) {
		if(Ob_VALID_TAG(pObKey, OB_TAG_REG_KEY)) { return pObKey; }
		Ob_DECREF_NULL(&pObKey);
	}
	// 2: retrieve key & validate
    if(!VmmWinReg_KeyValidateCellSize(pHive, oCell, REG_CM_KEY_NODE_SIZEOF + 4, 0x1000)) { goto fail; }
	dwCellHead = *(PDWORD)(pHive->Snapshot.pb + oCell);
	cbCell = REG_CELL_SIZE(dwCellHead);
	cbKey = cbCell - 4;
	pnk = (PREG_CM_KEY_NODE)(pHive->Snapshot.pb + oCell + 4);
    if(pnk->Signature != REG_CM_KEY_SIGNATURE_KEYNODE) { goto fail; }
	if(((QWORD)pnk->NameLength << ((pnk->Flags & REG_CM_KEY_NODE_FLAGS_COMP_NAME) ? 0 : 1)) > (cbKey - REG_CM_KEY_NODE_SIZEOF)) { goto fail; }
    if(pnk->Parent == oCell) { goto fail; }
	// 3: get parent key
	pObKeyParent = ObMap_GetByKey(pHive->Snapshot.pmKeyOffset, pnk->Parent);
	if(!pObKeyParent) {
		if(iLevel < 0x10) {
			pObKeyParent = VmmWinReg_KeyInitializeCreateKey(pHive, pnk->Parent, iLevel + 1);
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
	pObKey = Ob_Alloc(OB_TAG_REG_KEY, LMEM_ZEROINIT, sizeof(OB_REGISTRY_KEY), VmmWinReg_CallbackCleanup_ObRegKey, NULL);
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
        vmmprintf_fn("SHOULD NOT HAPPEN #1 \n");
    }
    if(!ObMap_Push(pHive->Snapshot.pmKeyHash, pObKey->qwHashKeyThis, pObKey)) {
        vmmprintf_fn("SHOULD NOT HAPPEN #2 \n");
    }
    VmmWinReg_KeyInitializeCreateKey_AddChild(pObKeyParent, oCell);
	Ob_DECREF(pObKeyParent);
	return pObKey;
fail:
	Ob_DECREF(pObKey);
	Ob_DECREF(pObKeyParent);
	return NULL;
}

/*
* Create a dummy key - used to create 'ROOT' and 'ORPHAN' root keys.
* (Helper function to VmmWinReg_KeyInitializeRootKey)
* CALLER DECREF: return
* -- pHive
* -- oCell
* -- qwKeyParentHash
* -- wszName
* -- fActive
* -- return
*/
POB_REGISTRY_KEY VmmWinReg_KeyInitializeRootKeyDummy(_In_ POB_REGISTRY_HIVE pHive, _In_ DWORD oCell, _In_ QWORD qwKeyParentHash, _In_ LPWSTR wszName, _In_ BOOL fActive)
{
	WORD cwszName;
	POB_REGISTRY_KEY pObKey = NULL;
    cwszName = (WORD)wcslen(wszName);
	// 1: allocate dummy entry
	pObKey = Ob_Alloc(OB_TAG_REG_KEY, LMEM_ZEROINIT, sizeof(OB_REGISTRY_KEY) + REG_CM_KEY_NODE_SIZEOF + cwszName * 2ULL, VmmWinReg_CallbackCleanup_ObRegKey, NULL);
	if(!pObKey) { return NULL; }
	pObKey->oCell = oCell;
	pObKey->cbCell = 4 + REG_CM_KEY_NODE_SIZEOF + cwszName * 2ULL;
    pObKey->dwCellHead = pObKey->oCell + (fActive ? 0x80000000 : 0);
    pObKey->pKey = (PREG_CM_KEY_NODE)((PBYTE)pObKey + sizeof(OB_REGISTRY_KEY));
	memcpy(&pObKey->pKey->wszName, wszName, cwszName * 2ULL);
	pObKey->pKey->NameLength = cwszName;
	// 2: calculate lookup hashes
	pObKey->qwHashKeyParent = qwKeyParentHash;
	pObKey->qwHashKeyThis = VmmWinReg_KeyHashNameW(wszName) + ((pObKey->qwHashKeyParent >> 13) | (pObKey->qwHashKeyParent << 51));
	// 3: store to cache and return
	ObMap_Push(pHive->Snapshot.pmKeyHash, pObKey->qwHashKeyThis, pObKey);
	ObMap_Push(pHive->Snapshot.pmKeyOffset, oCell, pObKey);
	return pObKey;
}

/*
* Create a dummy key - used to create 'ROOT' and 'ORPHAN' root keys.
* -- pHive
* -- return
*/
_Success_(return)
BOOL VmmWinReg_KeyInitializeRootKey(_In_ POB_REGISTRY_HIVE pHive)
{
    PVMM_PROCESS pObSystemProcess = NULL;
    PREG_CM_KEY_NODE pnk;
    DWORD i, oRootKey = -1, cbCell, cbKey;
	POB_REGISTRY_KEY pObKeyRoot = NULL;
	QWORD qwKeyRootHash = 0;
    // 1: get root key offset from regf-header (this is most often 0x20)
    if(!(pObSystemProcess = VmmProcessGet(4))) { return FALSE; }
    if(!VmmRead(pObSystemProcess, pHive->vaHBASE_BLOCK + 0x24, (PBYTE)&oRootKey, sizeof(DWORD)) || !oRootKey || (oRootKey > pHive->Snapshot.cb - REG_CM_KEY_NODE_SIZEOF)) {
        // regf base block unreadable or corrupt - try locate root key in 1st hive page
        i = 0x20;
        while(TRUE) {
            cbCell = REG_CELL_SIZE_EX(pHive->Snapshot.pb, i);
            cbKey = (cbCell > 4) ? cbCell - 4 : 0;
			if((cbKey < sizeof(REG_CM_KEY_NODE)) || (i + cbCell > 0x1000)) { break; }
            pnk = (PREG_CM_KEY_NODE)(pHive->Snapshot.pb + i + 4);
            if((pnk->Signature != REG_CM_KEY_SIGNATURE_KEYNODE) || (pnk->Flags != (REG_CM_KEY_NODE_FLAGS_HIVE_ENTRY | REG_CM_KEY_NODE_FLAGS_COMP_NAME))) {
                i += cbCell;
                continue;
            }
            oRootKey = i;
            break;
        }
    }
    Ob_DECREF(VmmWinReg_KeyInitializeRootKeyDummy(pHive, oRootKey, 0, L"ROOT", TRUE));
	Ob_DECREF(VmmWinReg_KeyInitializeRootKeyDummy(pHive, 0x7ffffffe, 0, L"ORPHAN", FALSE));
	return TRUE;
}

/*
* Initialize the registry key functionality by first "snapshotting" the hive
* contents into memory then walking the complete hive to try to find and index
* relations beteen parent-child registry keys - which are then stored into
* hash maps for faster lookups.
* -- pHive
* -- return
*/
_Success_(return)
BOOL VmmWinReg_KeyInitialize(_In_ POB_REGISTRY_HIVE pHive)
{
	DWORD oCell, dwSignature, cbCell, cbHbin, iHbin = 0;
    if(!VmmWinReg_KeyInitializeRootKey(pHive)) { return FALSE; }
    while(iHbin < (pHive->Snapshot.cb & ~0xfff)) {
        dwSignature = *(PDWORD)(pHive->Snapshot.pb + iHbin);
        if(!dwSignature) {  // zero-padded hbin
            iHbin += 0x1000;
            continue;
        }	
        if(dwSignature != REG_SIGNATURE_HBIN) {
            vmmprintfvv_fn("BAD HBIN HEADER: Hive=%016llx HBin=%08x Sig=%08x \n", pHive->vaCMHIVE, iHbin, dwSignature);
            iHbin += 0x1000;
            continue;
        }
        cbHbin = *(PDWORD)(pHive->Snapshot.pb + iHbin + 8);
        if((cbHbin & 0xfff) || (cbHbin > 0x10000)) { cbHbin = 0x1000; }
        oCell = 0x20;
        while(oCell < cbHbin) {
            cbCell = REG_CELL_SIZE_EX(pHive->Snapshot.pb, (QWORD)iHbin + oCell);
            if(!cbCell || (oCell + cbCell) > cbHbin) {
                oCell += 4;
                continue;
            }
            if(cbCell < 4 + REG_CM_KEY_NODE_SIZEOF) {
                oCell += (cbCell + 3) & ~0x3;
                continue;
            }
            if(REG_CM_KEY_SIGNATURE_KEYNODE == *(PWORD)(pHive->Snapshot.pb + iHbin + oCell + 4)) {
                Ob_DECREF(VmmWinReg_KeyInitializeCreateKey(pHive, iHbin + oCell, 0));
            }
            oCell += (cbCell + 3) & ~0x3;
        }

        iHbin += cbHbin;
    }
    return TRUE;
}

/*
* Try to create a key-value object manager object from the given cell offset.
* -- pHive
* -- oCell
* -- return
*/
POB_REGISTRY_VALUE VmmWinReg_KeyValue_Create(_In_ POB_REGISTRY_HIVE pHive, _In_ DWORD oCell)
{
    DWORD dwCellHead, cbCell, cbKeyValue;
    PREG_CM_KEY_VALUE pvk;
    POB_REGISTRY_VALUE pObKeyValue;
    // 1: retrieve key & validate
    if(!VmmWinReg_KeyValidateCellSize(pHive, oCell, REG_CM_KEY_VALUE_SIZEOF + 4, 0x1000)) { return NULL; }
    dwCellHead = *(PDWORD)(pHive->Snapshot.pb + oCell);
    cbCell = REG_CELL_SIZE(dwCellHead);
    cbKeyValue = cbCell - 4;
    pvk = (PREG_CM_KEY_VALUE)(pHive->Snapshot.pb + oCell + 4);
    if(pvk->Signature != REG_CM_KEY_SIGNATURE_KEYVALUE) { return NULL; }
    if(((QWORD)pvk->NameLength << ((pvk->Flags & REG_CM_KEY_VALUE_FLAGS_COMP_NAME) ? 0 : 1)) > (cbKeyValue - REG_CM_KEY_VALUE_SIZEOF)) { return NULL; }
    // 2: allocate and prepare
    pObKeyValue = Ob_Alloc(OB_TAG_REG_KEYVALUE, LMEM_ZEROINIT, sizeof(OB_REGISTRY_VALUE), NULL, NULL);
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
* -- pHice
* -- pKey
* -- wszKeyValueName
* -- return
*/
POB_REGISTRY_VALUE VmmWinReg_ValueByKeyAndName(_In_ POB_REGISTRY_HIVE pHive, _In_ POB_REGISTRY_KEY pKey, _In_ LPCWSTR wszKeyValueName)
{
    DWORD cbListCell, iValues, cValues, *praValues;
    POB_REGISTRY_VALUE pObKeyValue;
    VMM_REGISTRY_VALUE_INFO ValueInfo;
    if(!pKey->pKey->ValueList.Count || (pKey->pKey->ValueList.List + 8 > pHive->Snapshot.cb)) { return NULL; }
    cbListCell = REG_CELL_SIZE_EX(pHive->Snapshot.pb, pKey->pKey->ValueList.List);
    if((cbListCell < 8) || (pKey->pKey->ValueList.List & 0xfff) + cbListCell > 0x1000) { return NULL; }
    cValues = min(pKey->pKey->ValueList.Count, (cbListCell - 4) >> 2);
    praValues = (PDWORD)(pHive->Snapshot.pb + pKey->pKey->ValueList.List + 4);
    for(iValues = 0; iValues < cValues; iValues++) {
        pObKeyValue = VmmWinReg_KeyValue_Create(pHive, praValues[iValues]);
        if(!pObKeyValue) { continue; }
        VmmWinReg_ValueInfo(pHive, pObKeyValue, &ValueInfo);
        if(!wcscmp(wszKeyValueName, ValueInfo.wszName)) { return pObKeyValue; }
        Ob_DECREF_NULL(&pObKeyValue);
    }
    return NULL;
}

/*
* Helper function (core functionality) for the VmmWinReg_ValueQuery1 function.
*/
_Success_(return)
BOOL VmmWinReg_ValueQueryInternal(_In_ POB_REGISTRY_HIVE pHive, _In_ POB_REGISTRY_VALUE pObKeyValue, _Out_opt_ PDWORD pdwType, _Out_opt_ PDWORD pdwLength, _Out_writes_opt_(cbData) PBYTE pbData, _In_ DWORD cbData, _Out_opt_ PDWORD pcbDataRead, _In_ DWORD cbDataOffset) {
    DWORD cbDataRead = 0, cbDataLength, oCellData, cbCellData;
    if(pcbDataRead) { *pcbDataRead = 0; }
    cbDataLength = pObKeyValue->pValue->DataLength & 0x7fffffff;
    if(pdwType) {
        *pdwType = pObKeyValue->pValue->Type;
    }
    if(pdwLength) {
        *pdwLength = cbDataLength;
    }
    if(!pbData) { goto success; }
    if(!cbData || (cbDataOffset >= cbDataLength)) { return FALSE; }
    cbDataRead = min(cbData, cbDataLength - cbDataOffset);
    if(pObKeyValue->pValue->DataLength & 0x80000000) {
        // "small data" stored within keyvalue
        if((cbDataLength > 4) || (cbDataRead > 4)) { return FALSE; }
        memcpy(pbData, (PBYTE)(&pObKeyValue->pValue->Data) + cbDataOffset, cbDataRead);
        goto success;
    }
    oCellData = pObKeyValue->pValue->Data;
    if(oCellData + 0x10 > pHive->Snapshot.cb) { return FALSE; }
    cbCellData = REG_CELL_SIZE_EX(pHive->Snapshot.pb, oCellData);
    if(cbCellData < 8) { return FALSE; }
    // "big data" table
    if(*(PWORD)(pHive->Snapshot.pb + oCellData + 4) == REG_CM_KEY_SIGNATURE_BIGDATA) {
        vmmprintfvv_fn("BIG DATA TABLE NOT YET SUPPORTED. Hive=%016llx Cell=%08x \n", pHive->vaCMHIVE, pObKeyValue->oCell);
        return FALSE;
    }
    // "ordinary" data
    if(cbDataOffset > cbCellData - 4) { return FALSE; }
    cbDataRead = min(cbDataRead, cbCellData - 4 - cbDataOffset);
    if(oCellData + 4ULL + cbDataOffset + cbDataRead > pHive->Snapshot.cb) { return FALSE; }
    memcpy(pbData, pHive->Snapshot.pb + oCellData + 4 + cbDataOffset, cbDataRead);
    goto success;
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
* CALLER DECREF: *ppHive
* -- wszPathFull
* -- ppHive
* -- wszPathKeyValue
* -- return
*/
_Success_(return)
BOOL VmmWinRegKey_KeyValuePathFromPath(_In_ LPWSTR wszPathFull, _Out_ POB_REGISTRY_HIVE *ppHive, _Out_writes_(MAX_PATH) LPWSTR wszPathKeyValue)
{
    BOOL fOrphan = FALSE;
    LPWSTR wsz, wszPath2;
    WCHAR wszPath1[MAX_PATH];
    POB_REGISTRY_HIVE pObHive = NULL;
    if(!wcsncmp(wszPathFull, L"HKLM\\", 5)) {
        wszPathFull += 5;
        if(!wcsncmp(wszPathFull, L"ORPHAN\\", 7)) {
            wszPathFull += 7;
            fOrphan = TRUE;
        }
        wszPath2 = Util_PathSplit2_ExWCHAR(wszPathFull, wszPath1, MAX_PATH);
        wcsncpy_s(wszPathKeyValue, MAX_PATH, fOrphan ? L"ORPHAN\\" : L"ROOT\\", _TRUNCATE);
        wcsncat_s(wszPathKeyValue, MAX_PATH, wszPath2, _TRUNCATE);
        while((pObHive = VmmWinReg_HiveGetNext(pObHive))) {
            if(wcsstr(pObHive->wszNameShort, wszPath1)) {
                *ppHive = pObHive;
                return TRUE;    // CALLER DECREF: *ppHive
            }
        }
        while((pObHive = VmmWinReg_HiveGetNext(pObHive))) {
            if(wcsstr(pObHive->wszHiveRootPath, wszPath1)) {
                *ppHive = pObHive;
                return TRUE;    // CALLER DECREF: *ppHive
            }
        }
        return FALSE;
    }
    // try retrieve hive by address (path starts with 0x ...)
    if(!wcsncmp(wszPathFull, L"by-hive\\", 8)) {
        wszPathFull += 8;
    }
    *ppHive = VmmWinReg_HiveGetByAddress(Util_GetNumericW(wszPathFull));
    if(!*ppHive) { return FALSE; }
    wsz = Util_PathSplitNextW(wszPathFull);
    wcsncpy_s(wszPathKeyValue, MAX_PATH, wsz, _TRUNCATE);
    return TRUE;    // CALLER DECREF: *ppHive
}

/*
* Retrieve a registry key by its path. If no registry key is found then NULL
* will be returned.
* CALLER DECREF: return
* -- pHive
* -- wszPath
* -- return
*/
POB_REGISTRY_KEY VmmWinReg_KeyGetByPathW(_In_ POB_REGISTRY_HIVE pHive, _In_ LPWSTR wszPath)
{
    if(!VmmWinReg_HiveSnapshotEnsure(pHive)) { return NULL; }
    return (POB_REGISTRY_KEY)ObMap_GetByKey(pHive->Snapshot.pmKeyHash, VmmWinReg_KeyHashPathW(wszPath));
}

/*
* Retrive registry sub-keys from the level directly below the given parent key.
* The resulting keys are returned in a no-key map (set). If no parent key is
* given the root keys are returned.
* CALLER DECREF: return
* -- pHive
* -- pKeyParent
* -- return
*/
POB_MAP VmmWinReg_KeyList(_In_ POB_REGISTRY_HIVE pHive, _In_opt_ POB_REGISTRY_KEY pKeyParent)
{
    DWORD i;
    POB_MAP pmObSubkeys;
    POB_REGISTRY_KEY pKeyChild;
    if(!VmmWinReg_HiveSnapshotEnsure(pHive)) { return NULL; }
    if(!(pmObSubkeys = ObMap_New(OB_MAP_FLAGS_OBJECT_OB | OB_MAP_FLAGS_NOKEY))) { return NULL; }
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
    pKeyInfo->fActive = pKey->dwCellHead >> 31;
    pKeyInfo->ftLastWrite = pKey->pKey->LastWriteTime;
    if(pKey->pKey->Flags & REG_CM_KEY_NODE_FLAGS_COMP_NAME) {
        pKeyInfo->cchName = Util_PathFileNameFix_Registry(pKeyInfo->wszName, pKey->pKey->szName, NULL, pKey->pKey->NameLength, pKey->iSuffix, FALSE);
    } else {
        pKeyInfo->cchName = Util_PathFileNameFix_Registry(pKeyInfo->wszName, NULL, pKey->pKey->wszName, pKey->pKey->NameLength, pKey->iSuffix, FALSE);
    }
}

/*
* Retrive registry values given a key. The resulting values are returned in a
* no-key map (set). If no values are found the empty set or NULL are returned.
* CALLER DECREF: return
* -- pHive
* -- pKeyParent
* -- return
*/
POB_MAP VmmWinReg_KeyValueList(_In_ POB_REGISTRY_HIVE pHive, _In_ POB_REGISTRY_KEY pKeyParent)
{
    DWORD cbListCell, iValues, cValues, * praValues;
    POB_REGISTRY_VALUE pObKeyValue;
    POB_MAP pmObValues;
    if(!VmmWinReg_HiveSnapshotEnsure(pHive)) { return NULL; }
    if(!(pmObValues = ObMap_New(OB_MAP_FLAGS_OBJECT_OB | OB_MAP_FLAGS_NOKEY))) { return NULL; }
    if(!pKeyParent->pKey->ValueList.Count || (pKeyParent->pKey->ValueList.List > pHive->Snapshot.cb - 8)) { return pmObValues; }
    if(!VmmWinReg_KeyValidateCellSize(pHive, pKeyParent->pKey->ValueList.List, 8, 0x1000)) { return pmObValues; }
    cbListCell = REG_CELL_SIZE_EX(pHive->Snapshot.pb, pKeyParent->pKey->ValueList.List);
    cValues = min(pKeyParent->pKey->ValueList.Count, (cbListCell - 4) >> 2);
    praValues = (PDWORD)(pHive->Snapshot.pb + pKeyParent->pKey->ValueList.List + 4);
    for(iValues = 0; iValues < cValues; iValues++) {
        pObKeyValue = VmmWinReg_KeyValue_Create(pHive, praValues[iValues]);
        ObMap_Push(pmObValues, 0, pObKeyValue);
        Ob_DECREF_NULL(&pObKeyValue);
    }
    return pmObValues;
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
    if(!pValue->pValue->NameLength) {
        wcscpy_s(pValueInfo->wszName, _countof(pValueInfo->wszName), L"(Default)");
    } else if(pValue->pValue->Flags & REG_CM_KEY_VALUE_FLAGS_COMP_NAME) {
        pValueInfo->cchName = Util_PathFileNameFix_Registry(pValueInfo->wszName, pValue->pValue->szName, NULL, pValue->pValue->NameLength, 0, FALSE);
    } else {
        pValueInfo->cchName = Util_PathFileNameFix_Registry(pValueInfo->wszName, NULL, pValue->pValue->wszName, pValue->pValue->NameLength, 0, FALSE);
    }
}

/*
* Read a registry value - similar to WINAPI function 'RegQueryValueEx'.
* -- pHive
* -- wszPathKeyValue
* -- pdwType
* -- pb
* -- cb
* -- pcbRead
* -- cbOffset
* -- return
*/
_Success_(return)
BOOL VmmWinReg_ValueQuery1(_In_ POB_REGISTRY_HIVE pHive, _In_ LPWSTR wszPathKeyValue, _Out_opt_ PDWORD pdwType, _Out_writes_opt_(cb) PBYTE pb, _In_ DWORD cb, _Out_opt_ PDWORD pcbRead, _In_ QWORD cbOffset)
{
    BOOL f;
    LPWSTR wszValueName;
    WCHAR wszPathKey[MAX_PATH];
    POB_REGISTRY_KEY pObKey = NULL;
    POB_REGISTRY_VALUE pObKeyValue = NULL;
    if(pcbRead) { *pcbRead = 0; }
    f = VmmWinReg_HiveSnapshotEnsure(pHive) &&
        (wszValueName = Util_PathFileSplitW(wszPathKeyValue, wszPathKey)) &&
        (pObKey = VmmWinReg_KeyGetByPathW(pHive, wszPathKey)) &&
        (pObKeyValue = VmmWinReg_ValueByKeyAndName(pHive, pObKey, wszValueName)) &&
        (pb ? VmmWinReg_ValueQueryInternal(pHive, pObKeyValue, pdwType, NULL, pb, cb, pcbRead, (DWORD)cbOffset) : VmmWinReg_ValueQueryInternal(pHive, pObKeyValue, pdwType, pcbRead, NULL, 0, NULL, 0));        
    Ob_DECREF(pObKeyValue);
    Ob_DECREF(pObKey);
    return f;
}

/*
* Read a registry value - similar to WINAPI function 'RegQueryValueEx'.
* -- wszFullPathKeyValue
* -- pdwType
* -- pbData
* -- cbData
* -- pcbData
* -- return
*/
_Success_(return)
BOOL VmmWinReg_ValueQuery2(_In_ LPWSTR wszFullPathKeyValue, _Out_opt_ PDWORD pdwType, _Out_writes_opt_(cbData) PBYTE pbData, _In_ DWORD cbData, _Out_opt_ PDWORD pcbData)
{
    BOOL f;
    WCHAR wszPathKeyValue[MAX_PATH];
    POB_REGISTRY_HIVE pObHive = NULL;
    f = VmmWinRegKey_KeyValuePathFromPath(wszFullPathKeyValue, &pObHive, wszPathKeyValue) &&
        VmmWinReg_ValueQuery1(pObHive, wszPathKeyValue, pdwType, pbData, cbData, pcbData, 0);
    Ob_DECREF(pObHive);
    return f;
}

/*
* Read a registry value - similar to WINAPI function 'RegQueryValueEx'.
* -- pHive
* -- wszPathKeyValue
* -- pdwType
* -- pbData
* -- cbData
* -- pcbData
* -- return
*/
_Success_(return)
BOOL VmmWinReg_ValueQuery3(_In_ POB_REGISTRY_HIVE pHive, _In_ LPWSTR wszPathKeyValue, _Out_opt_ PDWORD pdwType, _Out_writes_opt_(cbData) PBYTE pbData, _In_ DWORD cbData, _Out_opt_ PDWORD pcbData)
{
    return VmmWinReg_ValueQuery1(pHive, wszPathKeyValue, pdwType, pbData, cbData, pcbData, 0);
}

/*
* Read a registry value - similar to WINAPI function 'RegQueryValueEx'.
* -- pHive
* -- pObKeyValue
* -- pdwType
* -- pbData
* -- cbData
* -- pcbData
* -- return
*/
_Success_(return)
BOOL VmmWinReg_ValueQuery4(_In_ POB_REGISTRY_HIVE pHive, _In_ POB_REGISTRY_VALUE pObKeyValue, _Out_opt_ PDWORD pdwType, _Out_writes_opt_(cbData) PBYTE pbData, _In_ DWORD cbData, _Out_opt_ PDWORD pcbData)
{
    if(VmmWinReg_HiveSnapshotEnsure(pHive)) {
        return VmmWinReg_ValueQueryInternal(pHive, pObKeyValue, pdwType, NULL, pbData, cbData, pcbData, 0);
    }
    if(pdwType) { *pdwType = 0; }
    if(pcbData) { *pcbData = 0; }
    return FALSE;
}
