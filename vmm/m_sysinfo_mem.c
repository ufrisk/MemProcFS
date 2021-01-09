// m_sysinfo_mem.c : implementation related to the SysInfo/Memory built-in module.
//
// The SysInfo/Mmeory module is responsible for displaying various memory related
// information such as information about the Windows PFN database.
//
// (c) Ulf Frisk, 2020-2021
// Author: Ulf Frisk, pcileech@frizk.net
//
#include "pluginmanager.h"
#include "mm_pfn.h"
#include "util.h"

#define MSYSINFOMEM_PHYSMEMMAP_LINE_LENGTH          33ULL
#define MSYSINFOMEM_PFNMAP_LINE_LENGTH              56ULL

_Success_(return == 0)
NTSTATUS MSysInfoMem_Read_PhysMemMap(_Out_writes_to_(cb, *pcbRead) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset)
{
    NTSTATUS nt;
    LPSTR sz;
    QWORD i, o = 0, cbMax, cStart, cEnd, cbLINELENGTH;
    PVMMOB_MAP_PHYSMEM pObPhysMemMap = NULL;
    if(!VmmMap_GetPhysMem(&pObPhysMemMap)) { return VMMDLL_STATUS_END_OF_FILE; }
    cbLINELENGTH = MSYSINFOMEM_PHYSMEMMAP_LINE_LENGTH;
    cStart = (DWORD)(cbOffset / cbLINELENGTH);
    cEnd = (DWORD)min(pObPhysMemMap->cMap - 1, (cb + cbOffset + cbLINELENGTH - 1) / cbLINELENGTH);
    cbMax = 1 + (1 + cEnd - cStart) * cbLINELENGTH;
    if(!pObPhysMemMap->cMap || (cStart > pObPhysMemMap->cMap)) {
        Ob_DECREF(pObPhysMemMap);
        return VMMDLL_STATUS_END_OF_FILE;
    }
    if(!(sz = LocalAlloc(LMEM_ZEROINIT, cbMax))) {
        Ob_DECREF(pObPhysMemMap);
        return VMMDLL_STATUS_FILE_INVALID;
    }
    for(i = cStart; i <= cEnd; i++) {
        o += Util_snwprintf_u8ln(
            sz + o,
            cbLINELENGTH,
            L"%04x %12llx - %12llx",
            (DWORD)i,
            pObPhysMemMap->pMap[i].pa,
            pObPhysMemMap->pMap[i].pa + pObPhysMemMap->pMap[i].cb - 1
        );
    }
    nt = Util_VfsReadFile_FromPBYTE(sz, cbMax - 1, pb, cb, pcbRead, cbOffset - cStart * cbLINELENGTH);
    Ob_DECREF(pObPhysMemMap);
    LocalFree(sz);
    return nt;
}


_Success_(return == 0)
NTSTATUS MSysInfoMem_Read_PfnMap(_Out_writes_to_(cb, *pcbRead) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset)
{
    NTSTATUS nt;
    LPSTR sz;
    QWORD i, o = 0, cbMax, cbLINELENGTH;
    PMMPFN_MAP_ENTRY pe;
    PMMPFNOB_MAP pObPfnMap = NULL;
    CHAR szType[MAX_PATH] = { 0 };
    DWORD tp, cPfnTotal, cPfnStart, cPfnEnd;
    BOOL fModified, fPrototype;
    cPfnTotal = (DWORD)(ctxMain->dev.paMax >> 12);
    cbLINELENGTH = MSYSINFOMEM_PFNMAP_LINE_LENGTH;
    cPfnStart = (DWORD)(cbOffset / cbLINELENGTH);
    cPfnEnd = (DWORD)min(cPfnTotal - 1, (cb + cbOffset + cbLINELENGTH - 1) / cbLINELENGTH);
    cbMax = 1 + (1ULL + cPfnEnd - cPfnStart) * cbLINELENGTH;
    if(cPfnStart >= cPfnTotal) { return VMMDLL_STATUS_END_OF_FILE; }
    if(!MmPfn_Map_GetPfn(cPfnStart, cPfnEnd - cPfnStart + 1, &pObPfnMap, TRUE)) { return VMMDLL_STATUS_FILE_INVALID; }
    if(!(sz = LocalAlloc(LMEM_ZEROINIT, cbMax))) {
        Ob_DECREF(pObPfnMap);
        return VMMDLL_STATUS_FILE_INVALID;
    }
    for(i = 0; i <= cPfnEnd - cPfnStart; i++) {
        pe = pObPfnMap->pMap + i;
        tp = pe->PageLocation;
        fModified = pe->Modified && ((tp == MmPfnTypeStandby) || (tp == MmPfnTypeModified) || (tp == MmPfnTypeModifiedNoWrite) || (tp == MmPfnTypeActive) || (tp == MmPfnTypeTransition));
        fPrototype = pe->PrototypePte && ((tp == MmPfnTypeStandby) || (tp == MmPfnTypeModified) || (tp == MmPfnTypeModifiedNoWrite) || (tp == MmPfnTypeActive) || (tp == MmPfnTypeTransition));
        o += Util_snwprintf_u8ln(
            sz + o,
            cbLINELENGTH,
            L"%8x%7i %-7S %-10S %i%c%c %16llx\n",
            pe->dwPfn,
            pe->AddressInfo.dwPid,
            MMPFN_TYPE_TEXT[pe->PageLocation],
            MMPFN_TYPEEXTENDED_TEXT[pe->tpExtended],
            pe->Priority,
            fModified ? 'M' : '-',
            fPrototype ? 'P' : '-',
            pe->AddressInfo.va
        );
    }
    nt = Util_VfsReadFile_FromPBYTE(sz, cbMax - 1, pb, cb, pcbRead, cbOffset - cPfnStart * cbLINELENGTH);
    LocalFree(sz);
    Ob_DECREF(pObPfnMap);
    return nt;
}

NTSTATUS MSysInfoMem_Read(_In_ PVMMDLL_PLUGIN_CONTEXT ctx, _Out_writes_to_(cb, *pcbRead) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset)
{
    NTSTATUS nt = VMMDLL_STATUS_FILE_INVALID;
    if(!_wcsicmp(ctx->wszPath, L"physmemmap.txt")) {
        nt = MSysInfoMem_Read_PhysMemMap(pb, cb, pcbRead, cbOffset);
    }
    if(!_wcsicmp(ctx->wszPath, L"pfndb.txt")) {
        nt = MSysInfoMem_Read_PfnMap(pb, cb, pcbRead, cbOffset);
    }
    if(!_wcsicmp(ctx->wszPath, L"pfnaddr.txt")) {
        nt = ctxVmm->f32 ?
            Util_VfsReadFile_FromDWORD((DWORD)ctxVmm->kernel.opt.vaPfnDatabase, pb, cb, pcbRead, cbOffset, FALSE) :
            Util_VfsReadFile_FromQWORD((QWORD)ctxVmm->kernel.opt.vaPfnDatabase, pb, cb, pcbRead, cbOffset, FALSE);
    }
    return nt;
}

BOOL MSysInfoMem_List(_In_ PVMMDLL_PLUGIN_CONTEXT ctx, _Inout_ PHANDLE pFileList)
{
    DWORD cPfn;
    PVMMOB_MAP_PHYSMEM pObPhysMemMap = NULL;
    // PFN database:
    if(ctxVmm->kernel.opt.vaPfnDatabase) {
        cPfn = (DWORD)(ctxMain->dev.paMax >> 12);
        VMMDLL_VfsList_AddFile(pFileList, L"pfndb.txt", cPfn * MSYSINFOMEM_PFNMAP_LINE_LENGTH, NULL);
        VMMDLL_VfsList_AddFile(pFileList, L"pfnaddr.txt", ctxVmm->f32 ? 8 : 16, NULL);
    }
    // Physical Memory Map:
    VmmMap_GetPhysMem(&pObPhysMemMap);
    VMMDLL_VfsList_AddFile(pFileList, L"physmemmap.txt", (pObPhysMemMap ? pObPhysMemMap->cMap * MSYSINFOMEM_PHYSMEMMAP_LINE_LENGTH : 0), NULL);
    Ob_DECREF(pObPhysMemMap);
    return TRUE;
}

VOID M_SysInfoMem_Initialize(_Inout_ PVMMDLL_PLUGIN_REGINFO pRI)
{
    if((pRI->magic != VMMDLL_PLUGIN_REGINFO_MAGIC) || (pRI->wVersion != VMMDLL_PLUGIN_REGINFO_VERSION)) { return; }
    if((pRI->tpSystem != VMM_SYSTEM_WINDOWS_X64) && (pRI->tpSystem != VMM_SYSTEM_WINDOWS_X86)) { return; }
    wcscpy_s(pRI->reg_info.wszPathName, 128, L"\\sysinfo\\memory");         // module name
    pRI->reg_info.fRootModule = TRUE;                                       // module shows in root directory
    pRI->reg_fn.pfnList = MSysInfoMem_List;                                 // List function supported
    pRI->reg_fn.pfnRead = MSysInfoMem_Read;                                 // Read function supported
    pRI->pfnPluginManager_Register(pRI);
}
