// m_sys_mem.c : implementation related to the Sys/Memory built-in module.
//
// The '/sys/memory' module is responsible for displaying various memory related
// information such as information about the Windows PFN database.
//
// (c) Ulf Frisk, 2020-2021
// Author: Ulf Frisk, pcileech@frizk.net
//
#include "pluginmanager.h"
#include "mm_pfn.h"
#include "util.h"

#define MSYSMEM_PFNMAP_LINELENGTH           56ULL
#define MSYSMEM_PHYSMEMMAP_LINELENGTH       33ULL
#define MSYSMEM_PHYSMEMMAP_LINEHEADER       "   #         Base            Top"

VOID MSysMem_PhysMemReadLine_Callback(_Inout_opt_ PVOID ctx, _In_ DWORD cbLineLength, _In_ DWORD ie, _In_ PVMM_MAP_PHYSMEMENTRY pe, _Out_writes_(cbLineLength + 1) LPSTR usz)
{
    Util_usnprintf_ln(usz, cbLineLength,
        "%04x %12llx - %12llx",
        ie,
        pe->pa,
        pe->pa + pe->cb - 1
    );
}

_Success_(return == 0)
NTSTATUS MSysMem_Read_PfnMap(_Out_writes_to_(cb, *pcbRead) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset)
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
    cbLINELENGTH = MSYSMEM_PFNMAP_LINELENGTH;
    cPfnStart = (DWORD)(cbOffset / cbLINELENGTH);
    cPfnEnd = (DWORD)min(cPfnTotal - 1, (cb + cbOffset + cbLINELENGTH - 1) / cbLINELENGTH);
    cbMax = 1 + (1ULL + cPfnEnd - cPfnStart) * cbLINELENGTH;
    if(cPfnStart >= cPfnTotal) { return VMMDLL_STATUS_END_OF_FILE; }
    if(!MmPfn_Map_GetPfn(cPfnStart, cPfnEnd - cPfnStart + 1, &pObPfnMap, TRUE)) { return VMMDLL_STATUS_FILE_INVALID; }
    if(!(sz = LocalAlloc(LMEM_ZEROINIT, (SIZE_T)cbMax))) {
        Ob_DECREF(pObPfnMap);
        return VMMDLL_STATUS_FILE_INVALID;
    }
    for(i = 0; i <= cPfnEnd - cPfnStart; i++) {
        pe = pObPfnMap->pMap + i;
        tp = pe->PageLocation;
        fModified = pe->Modified && ((tp == MmPfnTypeStandby) || (tp == MmPfnTypeModified) || (tp == MmPfnTypeModifiedNoWrite) || (tp == MmPfnTypeActive) || (tp == MmPfnTypeTransition));
        fPrototype = pe->PrototypePte && ((tp == MmPfnTypeStandby) || (tp == MmPfnTypeModified) || (tp == MmPfnTypeModifiedNoWrite) || (tp == MmPfnTypeActive) || (tp == MmPfnTypeTransition));
        o += Util_usnprintf_ln(
            sz + o,
            cbLINELENGTH,
            "%8x%7i %-7s %-10s %i%c%c %16llx\n",
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

NTSTATUS MSysMem_Read(_In_ PVMMDLL_PLUGIN_CONTEXT ctx, _Out_writes_to_(cb, *pcbRead) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset)
{
    NTSTATUS nt = VMMDLL_STATUS_FILE_INVALID;
    PVMMOB_MAP_PHYSMEM pObPhysMemMap = NULL;
    if(!_stricmp(ctx->uszPath, "physmemmap.txt") && VmmMap_GetPhysMem(&pObPhysMemMap)) {
        nt = Util_VfsLineFixed_Read(
            (UTIL_VFSLINEFIXED_PFN_CB)MSysMem_PhysMemReadLine_Callback, NULL, MSYSMEM_PHYSMEMMAP_LINELENGTH, MSYSMEM_PHYSMEMMAP_LINEHEADER,
            pObPhysMemMap->pMap, pObPhysMemMap->cMap, sizeof(VMM_MAP_PHYSMEMENTRY),
            pb, cb, pcbRead, cbOffset
        );
        Ob_DECREF_NULL(&pObPhysMemMap);
    }
    if(!_stricmp(ctx->uszPath, "pfndb.txt")) {
        nt = MSysMem_Read_PfnMap(pb, cb, pcbRead, cbOffset);
    }
    if(!_stricmp(ctx->uszPath, "pfnaddr.txt")) {
        nt = ctxVmm->f32 ?
            Util_VfsReadFile_FromDWORD((DWORD)ctxVmm->kernel.opt.vaPfnDatabase, pb, cb, pcbRead, cbOffset, FALSE) :
            Util_VfsReadFile_FromQWORD((QWORD)ctxVmm->kernel.opt.vaPfnDatabase, pb, cb, pcbRead, cbOffset, FALSE);
    }
    return nt;
}

BOOL MSysMem_List(_In_ PVMMDLL_PLUGIN_CONTEXT ctx, _Inout_ PHANDLE pFileList)
{
    DWORD cPfn, cPhys;
    PVMMOB_MAP_PHYSMEM pObPhysMemMap = NULL;
    // PFN database:
    if(ctxVmm->kernel.opt.vaPfnDatabase) {
        cPfn = (DWORD)(ctxMain->dev.paMax >> 12);
        VMMDLL_VfsList_AddFile(pFileList, "pfndb.txt", cPfn * MSYSMEM_PFNMAP_LINELENGTH, NULL);
        VMMDLL_VfsList_AddFile(pFileList, "pfnaddr.txt", ctxVmm->f32 ? 8 : 16, NULL);
    }
    // Physical Memory Map:
    VmmMap_GetPhysMem(&pObPhysMemMap);
    cPhys = pObPhysMemMap ? pObPhysMemMap->cMap : 0;
    VMMDLL_VfsList_AddFile(pFileList, "physmemmap.txt", UTIL_VFSLINEFIXED_LINECOUNT(cPhys) * MSYSMEM_PHYSMEMMAP_LINELENGTH, NULL);
    Ob_DECREF(pObPhysMemMap);
    return TRUE;
}

VOID MSysMem_FcLogJSON(_In_ PVMMDLL_PLUGIN_CONTEXT ctxP, _In_ VOID(*pfnLogJSON)(_In_ PVMMDLL_PLUGIN_FORENSIC_JSONDATA pData))
{
    PVMMDLL_PLUGIN_FORENSIC_JSONDATA pd;
    PVMMOB_MAP_PHYSMEM pObPhysMemMap = NULL;
    PVMM_MAP_PHYSMEMENTRY pe;
    DWORD i;
    if(ctxP->pProcess || !(pd = LocalAlloc(LMEM_ZEROINIT, sizeof(VMMDLL_PLUGIN_FORENSIC_JSONDATA)))) { return; }
    pd->dwVersion = VMMDLL_PLUGIN_FORENSIC_JSONDATA_VERSION;
    pd->szjType = "memorymap";
    if(VmmMap_GetPhysMem(&pObPhysMemMap)) {
        for(i = 0; i < pObPhysMemMap->cMap; i++) {
            pe = pObPhysMemMap->pMap + i;
            pd->i = i;
            pd->va[0] = pe->pa;
            pd->va[1] = pe->pa + pe->cb - 1;
            pd->qwNum[0] = pe->cb;
            pfnLogJSON(pd);
        }
    }
    Ob_DECREF(pObPhysMemMap);
    LocalFree(pd);
}

VOID M_SysMem_Initialize(_Inout_ PVMMDLL_PLUGIN_REGINFO pRI)
{
    if((pRI->magic != VMMDLL_PLUGIN_REGINFO_MAGIC) || (pRI->wVersion != VMMDLL_PLUGIN_REGINFO_VERSION)) { return; }
    if((pRI->tpSystem != VMM_SYSTEM_WINDOWS_X64) && (pRI->tpSystem != VMM_SYSTEM_WINDOWS_X86)) { return; }
    strcpy_s(pRI->reg_info.uszPathName, 128, "\\sys\\memory");          // module name
    pRI->reg_info.fRootModule = TRUE;                                   // module shows in root directory
    pRI->reg_fn.pfnList = MSysMem_List;                                 // List function supported
    pRI->reg_fn.pfnRead = MSysMem_Read;                                 // Read function supported
    pRI->reg_fnfc.pfnLogJSON = MSysMem_FcLogJSON;                       // JSON log function supported
    pRI->pfnPluginManager_Register(pRI);
}
