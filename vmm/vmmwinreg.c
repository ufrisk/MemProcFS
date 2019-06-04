// vmmwinreg.h : implementation of functionality related to the Windows registry.
//
// (c) Ulf Frisk, 2019
// Author: Ulf Frisk, pcileech@frizk.net
//

#include "vmmwinreg.h"
#include "leechcore.h"
#include "pe.h"
#include "util.h"
#include "vmmwin.h"

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
BOOL VmmWinReg_Reg2Virt64(_In_ PVMM_PROCESS pProcessRegistry, _In_ PVMMOB_REGISTRY_HIVE pRegistryHive, _In_ DWORD ra, _Out_ PQWORD pva)
{
    PVMMWIN_REGISTRY_OFFSET po = &ctxVmm->RegistryOffset;
    QWORD iDirectory, iTable;
    QWORD vaTable, vaCell;
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
    // [ +0x000 Table : [512] _HMAP_ENTRY        ]
    // [ nt!_HMAP_ENTRY                          ]
    // [   + 0x000 BlockOffset      : Uint8B     ]
    // [   + 0x008 PermanentBinAddress : Uint8B  ]
    // [   + 0x010 ...                           ]
    if(!VmmRead(pProcessRegistry, vaTable + iTable * po->HE._Size, (PBYTE)&pbHE, po->HE._Size)) { return FALSE; }
    vaCell = *(PQWORD)(pbHE + po->HE.BlkA);
    if(!_IS_HMAP_ADDR64(vaCell)) {
        vaCell = *(PQWORD)(pbHE + po->HE.HBin);
        if(!vaCell) { return FALSE; }
    }
    *pva = (vaCell & 0xffffffff'fffff000) | (ra & 0xfff);
    return TRUE;
}

_Success_(return)
BOOL VmmWinReg_Reg2Virt32(_In_ PVMM_PROCESS pProcessRegistry, _In_ PVMMOB_REGISTRY_HIVE pRegistryHive, _In_ DWORD ra, _Out_ PQWORD pva)
{
    PVMMWIN_REGISTRY_OFFSET po = &ctxVmm->RegistryOffset;
    QWORD iDirectory, iTable;
    DWORD vaTable, vaCell;
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
    // TABLE
    if(!VmmRead(pProcessRegistry, vaTable + iTable * po->HE._Size, (PBYTE)&pbHE, po->HE._Size)) { return FALSE; }
    vaCell = *(PDWORD)(pbHE + po->HE.BlkA);
    if(!_IS_HMAP_ADDR32(vaCell)) {
        vaCell = *(PDWORD)(pbHE + po->HE.HBin);
        if(!vaCell) { return FALSE; }
    }
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
BOOL VmmWinReg_Reg2Virt(_In_ PVMM_PROCESS pProcessRegistry, _In_ PVMMOB_REGISTRY_HIVE pRegistryHive, _In_ DWORD ra, _Out_ PQWORD pva)
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
VOID VmmWinReg_ReadScatter(_In_ PVMM_PROCESS pProcessRegistry, _In_ PVMMOB_REGISTRY_HIVE pRegistryHive, _Inout_ PPMEM_IO_SCATTER_HEADER ppMEMsReg, _In_ DWORD cpMEMsReg, _In_ QWORD flags)
{
    DWORD i = 0, iRA, iVA;
    QWORD va;
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
        iVA--;
        ((PMEM_IO_SCATTER_HEADER)ppMEMsVirt[iVA]->pvReserved1)->cb = ppMEMsVirt[iVA]->cb;
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
VOID VmmWinReg_HiveReadEx(_In_ PVMMOB_REGISTRY_HIVE pRegistryHive, _In_ DWORD ra, _Out_ PBYTE pb, _In_ DWORD cb, _Out_opt_ PDWORD pcbReadOpt, _In_ QWORD flags)
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
BOOL VmmWinReg_HiveWrite(_In_ PVMMOB_REGISTRY_HIVE pRegistryHive, _In_ DWORD ra, _In_ PBYTE pb, _In_ DWORD cb)
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
    PVMMWIN_REGISTRY_OFFSET po = &ctxVmm->RegistryOffset;
    if(ctxMain->cfg.fVerboseExtra) {
        vmmprintfvv_fn("\n");
        vmmprintfvv(
            "    CM.Sig   %03X, CM.Length %03X, CM.StorMap   %03X, CM.StorSmallDir %03X, CM.BaseBlock %03X, HE.HBin  %03X \n",
            po->CM.Signature, po->CM.Length, po->CM.StorageMap, po->CM.StorageSmallDir, po->CM.BaseBlock, po->HE.HBin);
        vmmprintfvv(
            "    CM.FLink %03X, CM._Size  %03X, CM.FileFull  %03X, CM.FileUserPath %03X, CM.HiveRoot  %03X, HE.BlkA  %03X \n",
            po->CM.FLink, po->CM._Size, po->CM.FileFullPathOpt, po->CM.FileUserNameOpt, po->CM.HiveRootPathOpt, po->HE.BlkA);
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
    po = &ctxVmm->RegistryOffset;
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
    po->HE.BlkA = 0x000;
    po->HE.HBin = 0x008;                // Always in x64
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
    PVMMWIN_REGISTRY_OFFSET po = &ctxVmm->RegistryOffset;
    // _CMHIVE BASE
    for(o = 0; o < 0x40; o += 8) {
        if(*(PQWORD)(pbCMHIVE + o + 0x004) == 0xBEE0BEE030314D43) {
            pbCMHIVE = pbCMHIVE + o + 0x008;
            if(vaCMHIVE) { vaCMHIVE = vaCMHIVE + o + 0x008; }
            break;
        }
    }
    if(*(PDWORD)(pbCMHIVE + 0x000) != 0xBEE0BEE0) { return FALSE; }
    po = &ctxVmm->RegistryOffset;
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
    po->HE.BlkA = 0x000;
    po->HE.HBin = 0x004;                // Always in x86
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

VOID VmmWinReg_CallbackCleanup_ObRegistry(PVMMOB_REGISTRY pOb)
{
    DeleteCriticalSection(&pOb->LockRefresh);
    Ob_DECREF(pOb->pHiveList);
}

VOID VmmWinReg_CallbackCleanup_ObRegistryHive(PVMMOB_REGISTRY_HIVE pOb)
{
    Ob_DECREF(pOb->FLink);
}

/*
* Callback function from VmmWin_ListTraversePrefetch[32|64].
* Gather referenced addresses into prefetch dataset.
*/
VOID VmmWinReg_EnumHive64_Pre(_In_ PVMM_PROCESS pProcess, _In_opt_ PVMMOB_REGISTRY pRegistry, _In_ QWORD va, _In_ PBYTE pb, _In_ DWORD cb, _In_ QWORD vaFLink, _In_ QWORD vaBLink, _In_ POB_VSET pVSetAddress, _Inout_ PBOOL pfValidEntry, _Inout_ PBOOL pfValidFLink, _Inout_ PBOOL pfValidBLink)
{
    PVMMWIN_REGISTRY_OFFSET po = &ctxVmm->RegistryOffset;
    if((va & 0xffff8000'00000007) != 0xffff8000'00000000) { return; }               // not aligned kernel address
    *pfValidFLink = ((vaFLink & 0xffff8000'00000007) == 0xffff8000'00000000);       // aligned kernel address
    *pfValidBLink = ((vaBLink & 0xffff8000'00000007) == 0xffff8000'00000000);       // aligned kernel address
    if(*pfValidFLink && *pfValidBLink && (*(PDWORD)(pb + po->CM.Signature) == 0xBEE0BEE0) && ((*(PQWORD)(pb + po->CM.BaseBlock) & 0xfff) == 0x000)) {
        ObVSet_Put(pVSetAddress, *(PQWORD)(pb + po->CM.BaseBlock));
        if(po->CM.HiveRootPathOpt && *(PQWORD)(pb + po->CM.HiveRootPathOpt)) {  // _CMHIVE.HiveRootPath
            ObVSet_Put(pVSetAddress, *(PQWORD)(pb + po->CM.HiveRootPathOpt + 8) & ~0xfff);
        }
        *pfValidEntry = TRUE;
    }
}

VOID VmmWinReg_EnumHive32_Pre(_In_ PVMM_PROCESS pProcess, _In_opt_ PVMMOB_REGISTRY pRegistry, _In_ QWORD va, _In_ PBYTE pb, _In_ DWORD cb, _In_ QWORD vaFLink, _In_ QWORD vaBLink, _In_ POB_VSET pVSetAddress, _Inout_ PBOOL pfValidEntry, _Inout_ PBOOL pfValidFLink, _Inout_ PBOOL pfValidBLink)
{
    PVMMWIN_REGISTRY_OFFSET po = &ctxVmm->RegistryOffset;
    if((va & 0x80000007) != 0x80000000) { return; }         // not aligned kernel address
    *pfValidFLink = ((vaFLink & 0x80000003) == 0x80000000);       // aligned kernel address
    *pfValidBLink = ((vaBLink & 0x80000003) == 0x80000000);       // aligned kernel address
    if(*pfValidFLink && *pfValidBLink && (*(PDWORD)(pb + po->CM.Signature) == 0xBEE0BEE0) && ((*(PDWORD)(pb + po->CM.BaseBlock) & 0xfff) == 0x000)) {
        ObVSet_Put(pVSetAddress, *(PDWORD)(pb + po->CM.BaseBlock));
        if(po->CM.HiveRootPathOpt && *(PDWORD)(pb + po->CM.HiveRootPathOpt)) {  // _CMHIVE.HiveRootPath
            ObVSet_Put(pVSetAddress, *(PDWORD)(pb + po->CM.HiveRootPathOpt + 4) & ~0xfff);
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
BOOL VmmWinReg_EnumHive64_Post(_In_ PVMM_PROCESS pProcess, _In_opt_ PVMMOB_REGISTRY pRegistry, _In_ QWORD vaData, _In_ PBYTE pbData, _In_ DWORD cbData)
{
    BOOL f;
    CHAR chDefault = '_';
    BOOL fBoolTrue = TRUE;
    CHAR szHiveFileNameShort[32+1] = { 0 };
    CHAR szHiveFileNameLong[72] = { 0 };
    PVMMOB_REGISTRY_HIVE pObHive = NULL;
    PVMMWIN_REGISTRY_OFFSET po = &ctxVmm->RegistryOffset;
    // 1: validity check
    if((vaData & 0xffff8000'00000000) != 0xffff8000'00000000) { return FALSE; } // not kernel address
    f = pRegistry &&
        (*(PDWORD)(pbData + po->CM.Signature) == 0xBEE0BEE0) &&                 // Signature match
        (*(PQWORD)(pbData + po->CM.StorageMap)) &&                              // _CMHIVE.Hive.Storage.Map
        (*(PDWORD)(pbData + po->CM.Length)) &&                                  // Length > 0
        (*(PDWORD)(pbData + po->CM.Length) <= 0x40000000);                      // Length < 1GB
    if(!f) { return TRUE; }
    // 2: Allocate and Initialize
    if(!(pObHive = Ob_Alloc('re', LMEM_ZEROINIT, sizeof(VMMOB_REGISTRY_HIVE), VmmWinReg_CallbackCleanup_ObRegistryHive, NULL))) { return TRUE; }
    pObHive->vaCMHIVE = vaData;
    pObHive->vaHBASE_BLOCK = *(PQWORD)(pbData + po->CM.BaseBlock);
    pObHive->cbLength = *(PDWORD)(pbData + po->CM.Length);
    pObHive->vaHMAP_DIRECTORY = *(PQWORD)(pbData + po->CM.StorageMap);
    pObHive->vaHMAP_TABLE_SmallDir = *(PQWORD)(pbData + po->CM.StorageSmallDir);
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
        "0x%llx-%s-%s.reghive",
        pObHive->vaCMHIVE,
        (szHiveFileNameShort[0] ? szHiveFileNameShort : "unknown"),
        (szHiveFileNameLong[0] ? szHiveFileNameLong : "unknown"));
    // 4: Attach and Return
    pObHive->FLink = pRegistry->pHiveList;
    pRegistry->pHiveList = pObHive;
    pRegistry->cHives++;
    vmmprintfvv_fn("%04i %s\n", pRegistry->cHives, pObHive->szName);
    return TRUE;
}

BOOL VmmWinReg_EnumHive32_Post(_In_ PVMM_PROCESS pProcess, _In_opt_ PVMMOB_REGISTRY pRegistry, _In_ QWORD vaData, _In_ PBYTE pbData, _In_ DWORD cbData)
{
    BOOL f;
    CHAR chDefault = '_';
    BOOL fBoolTrue = TRUE;
    CHAR szHiveFileNameShort[32+1] = { 0 };
    CHAR szHiveFileNameLong[72] = { 0 };
    PVMMOB_REGISTRY_HIVE pObHive = NULL;
    PVMMWIN_REGISTRY_OFFSET po = &ctxVmm->RegistryOffset;
    // 1: validity check
    if((vaData & 0x80000007) != 0x80000000) { return FALSE; }                   // not kernel address
    f = pRegistry &&
        (*(PDWORD)(pbData + po->CM.Signature) == 0xBEE0BEE0) &&                 // Signature match
        !(*(PDWORD)(pbData + po->CM.BaseBlock) & 0xfff) &&                      // _CMHIVE.BaseBlock on page boundary
        (*(PQWORD)(pbData + po->CM.StorageMap)) &&                              // _CMHIVE.Hive.Storage.Map
        (*(PDWORD)(pbData + po->CM.Length)) &&                                  // Length > 0
        (*(PDWORD)(pbData + po->CM.Length) <= 0x40000000);                      // Length < 1GB
    if(!f) { return TRUE; }
    // 2: Allocate and Initialize
    if(!(pObHive = Ob_Alloc('re', LMEM_ZEROINIT, sizeof(VMMOB_REGISTRY_HIVE), VmmWinReg_CallbackCleanup_ObRegistryHive, NULL))) { return TRUE; }
    pObHive->vaCMHIVE = vaData;
    pObHive->vaHBASE_BLOCK = *(PDWORD)(pbData + po->CM.BaseBlock);
    pObHive->cbLength = *(PDWORD)(pbData + po->CM.Length);
    pObHive->vaHMAP_DIRECTORY = *(PDWORD)(pbData + po->CM.StorageMap);
    pObHive->vaHMAP_TABLE_SmallDir = *(PDWORD)(pbData + po->CM.StorageSmallDir);
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
        "0x%llx-%s-%s.reghive",
        pObHive->vaCMHIVE,
        (szHiveFileNameShort[0] ? szHiveFileNameShort : "unknown"),
        (szHiveFileNameLong[0] ? szHiveFileNameLong : "unknown"));
    // 4: Attach and Return
    pObHive->FLink = pRegistry->pHiveList;
    pRegistry->pHiveList = pObHive;
    pRegistry->cHives++;
    vmmprintfvv_fn("%04i %s\n", pRegistry->cHives, pObHive->szName);
    return TRUE;
}

/*
* Internal function to create / set up a new registry objects.
* NB! This function must NOT be called in a multi-threaded way.
* CALLER DECREF: return
* -- return
*/
PVMMOB_REGISTRY VmmWinReg_EnumHive()
{
    BOOL f32 = ctxVmm->f32;
    PVMMOB_REGISTRY pObRegistry = NULL;
    PVMMOB_REGISTRY_HIVE pHiveCurrent = NULL;
    PVMM_PROCESS pObProcessSystem = NULL;
    if(!(pObProcessSystem = VmmProcessGet(4))) { goto cleanup; }    
    if(!ctxVmm->RegistryOffset.vaHintCMHIVE && !VmmWinReg_LocateRegistryHive()) { goto cleanup; }
    if(!(pObRegistry = Ob_Alloc('RE', LMEM_ZEROINIT, sizeof(VMMOB_REGISTRY), VmmWinReg_CallbackCleanup_ObRegistry, NULL))) { goto cleanup; }
    InitializeCriticalSection(&pObRegistry->LockRefresh);
    // Traverse the CMHIVE linked list in an efficient way
    VmmWin_ListTraversePrefetch(
        pObProcessSystem,
        f32,
        pObRegistry,
        ctxVmm->RegistryOffset.vaHintCMHIVE,
        ctxVmm->RegistryOffset.CM.FLink,
        ctxVmm->RegistryOffset.CM._Size,
        f32 ? VmmWinReg_EnumHive32_Pre : VmmWinReg_EnumHive64_Pre,
        f32 ? VmmWinReg_EnumHive32_Post : VmmWinReg_EnumHive64_Post,
        ctxVmm->pObCCachePrefetchRegistry);
    pObRegistry->fValid = TRUE;
    ObContainer_SetOb(ctxVmm->pObCRegistry, pObRegistry);
cleanup:
    Ob_DECREF(pObProcessSystem);
    return pObRegistry;
}

/*
* Retrieve the registry information object. If the registry sub-system is not
* yet initialized it will be initialized on the first call to this function.
* CALLER DECREF: return
* -- return = a registry information struct, or NULL if not found.
*/
PVMMOB_REGISTRY VmmWinReg_RegistryGet()
{
    PVMMOB_REGISTRY pObRegistry, pObRegistryRefreshed;
    pObRegistry = ObContainer_GetOb(ctxVmm->pObCRegistry);
    if(!pObRegistry) {
        EnterCriticalSection(&ctxVmm->MasterLock);
        pObRegistry = ObContainer_GetOb(ctxVmm->pObCRegistry);
        if(!pObRegistry) {
            pObRegistry = VmmWinReg_EnumHive();
        }
        LeaveCriticalSection(&ctxVmm->MasterLock);
    }
    if(pObRegistry && pObRegistry->fValid) {
        if(pObRegistry->fRefreshRequired && TryEnterCriticalSection(&pObRegistry->LockRefresh)) {
            // Refresh registry by create new registry object. Other threads
            // accessing registry during update will get the old copy.
            pObRegistryRefreshed = VmmWinReg_EnumHive();
            LeaveCriticalSection(&pObRegistry->LockRefresh);
            Ob_DECREF(pObRegistry);
            return pObRegistryRefreshed;
        }
        return pObRegistry;
    }
    Ob_DECREF(pObRegistry);
    return NULL;
}

/*
* Set the refresh flag on the registry subsystem.
* The registry will be refreshed upon next access.
*/
VOID VmmWinReg_Refresh()
{
    PVMMOB_REGISTRY pObRegistry = ObContainer_GetOb(ctxVmm->pObCRegistry);
    if(pObRegistry) {
        pObRegistry->fRefreshRequired = TRUE;
        Ob_DECREF(pObRegistry);
    }
}



//-----------------------------------------------------------------------------
// EXPORTED UTILITY FUNCTIONALITY BELOW:
//-----------------------------------------------------------------------------
PVMMOB_REGISTRY_HIVE VmmWinReg_HiveGetNext(_In_opt_ PVMMOB_REGISTRY_HIVE pObRegistryHive)
{
    PVMMOB_REGISTRY pObRegistry;
    PVMMOB_REGISTRY_HIVE pObRegistryHiveReturn;
    if(pObRegistryHive) {
        pObRegistryHiveReturn = pObRegistryHive->FLink;
        Ob_INCREF(pObRegistryHiveReturn);
        Ob_DECREF(pObRegistryHive);
        return pObRegistryHiveReturn;
    }
    pObRegistry = VmmWinReg_RegistryGet();
    if(!pObRegistry) { return NULL; }
    pObRegistryHiveReturn = pObRegistry->pHiveList;
    Ob_INCREF(pObRegistryHiveReturn);
    Ob_DECREF(pObRegistry);
    return pObRegistryHiveReturn;
}

PVMMOB_REGISTRY_HIVE VmmWinReg_HiveGetByAddress(_In_ QWORD vaCMHIVE)
{
    PVMMOB_REGISTRY_HIVE pObHive = NULL;
    while((pObHive = VmmWinReg_HiveGetNext(pObHive))) {
        if(pObHive->vaCMHIVE == vaCMHIVE) {
            return pObHive;  // CALLER DECREF: pObHive
        }
    }
    return NULL;
}
