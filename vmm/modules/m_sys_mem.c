// m_sys_mem.c : implementation related to the Sys/Memory built-in module.
//
// The '/sys/memory' module is responsible for displaying various memory related
// information such as information about the Windows PFN database.
//
// (c) Ulf Frisk, 2020-2025
// Author: Ulf Frisk, pcileech@frizk.net
//

#include "modules.h"

#define MSYSMEM_PFNMAP_LINELENGTH           56ULL
#define MSYSMEM_PHYSMEMMAP_LINELENGTH       33ULL
#define MSYSMEM_PHYSMEMMAP_LINEHEADER       "   #         Base            Top"

VOID MSysMem_PhysMemReadLineCB(_In_ VMM_HANDLE H, _Inout_opt_ PVOID ctx, _In_ DWORD cbLineLength, _In_ DWORD ie, _In_ PVMM_MAP_PHYSMEMENTRY pe, _Out_writes_(cbLineLength + 1) LPSTR usz)
{
    Util_usnprintf_ln(usz, cbLineLength,
        "%04x %12llx - %12llx",
        ie,
        pe->pa,
        pe->pa + pe->cb - 1
    );
}

_Success_(return == 0)
NTSTATUS MSysMem_Read_PfnMap(_In_ VMM_HANDLE H, _Out_writes_to_(cb, *pcbRead) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset)
{
    NTSTATUS nt;
    LPSTR sz;
    QWORD i, o = 0, cbMax, cbLINELENGTH;
    PMMPFN_MAP_ENTRY pe;
    PMMPFNOB_MAP pObPfnMap = NULL;
    CHAR szType[MAX_PATH] = { 0 };
    DWORD tp, cPfnTotal, cPfnStart, cPfnEnd;
    BOOL fModified, fPrototype;
    cPfnTotal = (DWORD)(H->dev.paMax >> 12);
    cbLINELENGTH = MSYSMEM_PFNMAP_LINELENGTH;
    cPfnStart = (DWORD)(cbOffset / cbLINELENGTH);
    cPfnEnd = (DWORD)min(cPfnTotal - 1, (cb + cbOffset + cbLINELENGTH - 1) / cbLINELENGTH);
    cbMax = 1 + (1ULL + cPfnEnd - cPfnStart) * cbLINELENGTH;
    if(cPfnStart >= cPfnTotal) { return VMMDLL_STATUS_END_OF_FILE; }
    if(!MmPfn_Map_GetPfn(H, cPfnStart, cPfnEnd - cPfnStart + 1, &pObPfnMap, TRUE)) { return VMMDLL_STATUS_FILE_INVALID; }
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

NTSTATUS MSysMem_Read(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_CONTEXT ctxP, _Out_writes_to_(cb, *pcbRead) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset)
{
    NTSTATUS nt = VMMDLL_STATUS_FILE_INVALID;
    PVMMOB_MAP_PHYSMEM pObPhysMemMap = NULL;
    if(!_stricmp(ctxP->uszPath, "physmemmap.txt") && VmmMap_GetPhysMem(H, &pObPhysMemMap)) {
        nt = Util_VfsLineFixed_Read(
            H, (UTIL_VFSLINEFIXED_PFN_CB)MSysMem_PhysMemReadLineCB, NULL, MSYSMEM_PHYSMEMMAP_LINELENGTH, MSYSMEM_PHYSMEMMAP_LINEHEADER,
            pObPhysMemMap->pMap, pObPhysMemMap->cMap, sizeof(VMM_MAP_PHYSMEMENTRY),
            pb, cb, pcbRead, cbOffset
        );
        Ob_DECREF_NULL(&pObPhysMemMap);
    }
    if(!_stricmp(ctxP->uszPath, "pfndb.txt")) {
        nt = MSysMem_Read_PfnMap(H, pb, cb, pcbRead, cbOffset);
    }
    if(!_stricmp(ctxP->uszPath, "pfnaddr.txt")) {
        nt = H->vmm.f32 ?
            Util_VfsReadFile_FromDWORD((DWORD)H->vmm.kernel.opt.vaPfnDatabase, pb, cb, pcbRead, cbOffset, FALSE) :
            Util_VfsReadFile_FromQWORD((QWORD)H->vmm.kernel.opt.vaPfnDatabase, pb, cb, pcbRead, cbOffset, FALSE);
    }
    return nt;
}

BOOL MSysMem_List(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_CONTEXT ctxP, _Inout_ PHANDLE pFileList)
{
    DWORD cPfn, cPhys;
    PVMMOB_MAP_PHYSMEM pObPhysMemMap = NULL;
    // PFN database:
    if(H->vmm.kernel.opt.vaPfnDatabase) {
        cPfn = (DWORD)(H->dev.paMax >> 12);
        VMMDLL_VfsList_AddFile(pFileList, "pfndb.txt", cPfn * MSYSMEM_PFNMAP_LINELENGTH, NULL);
        VMMDLL_VfsList_AddFile(pFileList, "pfnaddr.txt", H->vmm.f32 ? 8 : 16, NULL);
    }
    // Physical Memory Map:
    VmmMap_GetPhysMem(H, &pObPhysMemMap);
    cPhys = pObPhysMemMap ? pObPhysMemMap->cMap : 0;
    VMMDLL_VfsList_AddFile(pFileList, "physmemmap.txt", UTIL_VFSLINEFIXED_LINECOUNT(H, cPhys) * MSYSMEM_PHYSMEMMAP_LINELENGTH, NULL);
    Ob_DECREF(pObPhysMemMap);
    return TRUE;
}

VOID MSysMem_FcLogJSON(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_CONTEXT ctxP, _In_ VOID(*pfnLogJSON)(_In_ VMM_HANDLE H, _In_ PVMMDLL_FORENSIC_JSONDATA pData))
{
    PVMMDLL_FORENSIC_JSONDATA pd;
    PVMMOB_MAP_PHYSMEM pObPhysMemMap = NULL;
    PVMM_MAP_PHYSMEMENTRY pe;
    DWORD i;
    if(ctxP->pProcess || !(pd = LocalAlloc(LMEM_ZEROINIT, sizeof(VMMDLL_FORENSIC_JSONDATA)))) { return; }
    pd->dwVersion = VMMDLL_FORENSIC_JSONDATA_VERSION;
    pd->szjType = "memorymap";
    if(VmmMap_GetPhysMem(H, &pObPhysMemMap)) {
        for(i = 0; i < pObPhysMemMap->cMap; i++) {
            pe = pObPhysMemMap->pMap + i;
            pd->i = i;
            pd->va[0] = pe->pa;
            pd->va[1] = pe->pa + pe->cb - 1;
            pd->qwNum[0] = pe->cb;
            pfnLogJSON(H, pd);
        }
    }
    Ob_DECREF(pObPhysMemMap);
    LocalFree(pd);
}

VOID M_SysMem_Initialize(_In_ VMM_HANDLE H, _Inout_ PVMMDLL_PLUGIN_REGINFO pRI)
{
    if((pRI->magic != VMMDLL_PLUGIN_REGINFO_MAGIC) || (pRI->wVersion != VMMDLL_PLUGIN_REGINFO_VERSION)) { return; }
    if((pRI->tpSystem != VMMDLL_SYSTEM_WINDOWS_64) && (pRI->tpSystem != VMMDLL_SYSTEM_WINDOWS_32)) { return; }
    strcpy_s(pRI->reg_info.uszPathName, 128, "\\sys\\memory");          // module name
    pRI->reg_info.fRootModule = TRUE;                                   // module shows in root directory
    pRI->reg_fn.pfnList = MSysMem_List;                                 // List function supported
    pRI->reg_fn.pfnRead = MSysMem_Read;                                 // Read function supported
    pRI->reg_fnfc.pfnLogJSON = MSysMem_FcLogJSON;                       // JSON log function supported
    pRI->pfnPluginManager_Register(H, pRI);
}
