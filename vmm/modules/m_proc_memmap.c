// m_proc_memmap.c : implementation of the memmap built-in module.
//
// (c) Ulf Frisk, 2019-2025
// Author: Ulf Frisk, pcileech@frizk.net
//

#include "modules.h"
#include "../mm/mm.h"

#define MEMMAP_PTE_LINELENGTH_X86       112ULL
#define MEMMAP_PTE_LINELENGTH_X64       128ULL
#define MEMMAP_VAD_LINELENGTH_X86       137ULL
#define MEMMAP_VAD_LINELENGTH_X64       161ULL
#define MEMMAP_VADEX_LINELENGTH         162ULL

#define MEMMAP_PTE_LINEHEADER_X86       "   #    PID    Pages Range Start-End   FLAGS   Description"
#define MEMMAP_PTE_LINEHEADER_X64       "   #    PID    Pages      Range Start-End              FLAGS   Description"
#define MEMMAP_VAD_LINEHEADER_X86       "   #    PID  ObjAddr    Pages     Commit Range Start-End   Type  FLAGS  Description"
#define MEMMAP_VAD_LINEHEADER_X64       "   #    PID   Object Address    Pages     Commit      Range Start-End              Type  FLAGS  Description"

VOID MemMap_VadReadLineCB(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess, _In_ DWORD cbLineLength, _In_ DWORD ie, _In_ PVMM_MAP_VADENTRY pe, _Out_writes_(cbLineLength + 1) LPSTR usz)
{
    CHAR szProtection[7] = { 0 };
    MmVad_StrProtectionFlags(pe, szProtection);
    Util_usnprintf_ln(usz, cbLineLength,
        (H->vmm.f32 ? "%04x%7i %08x %8x %8x %i %08x-%08x %s %s %s" : "%04x%7i %016llx %8x %8x %i %016llx-%016llx %s %s %s"),
        ie,
        pProcess->dwPID,
        pe->vaVad,
        (DWORD)((pe->vaEnd - pe->vaStart + 1) >> 12),
        pe->CommitCharge,
        pe->MemCommit ? 1 : 0,
        pe->vaStart,
        pe->vaEnd,
        MmVad_StrType(pe),
        szProtection,
        pe->uszText + pe->cbuText - min(65, pe->cbuText)
    );
}

_Success_(return == 0)
NTSTATUS MemMap_Read_VadExMap2(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess, _In_ DWORD oVadExPages, _In_ DWORD cVadExPagesMax, _Out_writes_to_(cb, *pcbRead) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset)
{
    NTSTATUS nt;
    LPSTR sz;
    BOOL fPteA;
    DWORD i, iPage, cPage;
    QWORD o = 0, cbMax, cbLINELENGTH;
    PVMMOB_MAP_VADEX pObMap = NULL;
    PVMM_MAP_VADEXENTRY pex;
    PVMM_MAP_VADENTRY pVad;
    CHAR szProtection[7] = { 0 };
    cbLINELENGTH = MEMMAP_VADEX_LINELENGTH;
    iPage = (DWORD)(cbOffset / cbLINELENGTH) + oVadExPages;
    cPage = (DWORD)min((cb + cbOffset + cbLINELENGTH - 1) / cbLINELENGTH, cVadExPagesMax - (iPage - oVadExPages));
    if(!VmmMap_GetVadEx(H, pProcess, &pObMap, VMM_VADMAP_TP_FULL, iPage, cPage)) { return VMMDLL_STATUS_FILE_INVALID; }
    cPage = pObMap->cMap;
    cbMax = 1 + pObMap->cMap * cbLINELENGTH;
    if(!(sz = LocalAlloc(LMEM_ZEROINIT, (SIZE_T)cbMax))) { Ob_DECREF(pObMap); return VMMDLL_STATUS_FILE_INVALID; }
    for(i = 0; i < pObMap->cMap; i++) {
        pex = pObMap->pMap + i;
        pVad = pex->peVad;
        MmVad_StrProtectionFlags(pVad, szProtection);
        fPteA = pex->flags & VADEXENTRY_FLAG_HARDWARE;
        o += Util_usnprintf_ln(
            sz + o,
            cbLINELENGTH,
            "%06x%7i %016llx %012llx %016llx %c %c%c%c %016llx %012llx %016llx %c %s %s %s",
            iPage + i,
            pProcess->dwPID,
            pex->va,
            pex->pa,
            pex->pte,
            MmVadEx_StrType(pex->tp),
            fPteA ? 'r' : '-',
            (fPteA && (pex->flags & VADEXENTRY_FLAG_W)) ? 'w' : '-',
            (!fPteA || (pex->flags & VADEXENTRY_FLAG_NX)) ? '-' : 'x',
            pVad->vaVad,
            pex->proto.pa,
            pex->proto.pte,
            MmVadEx_StrType(pex->proto.tp),
            MmVad_StrType(pVad),
            szProtection,
            pVad->uszText + pVad->cbuText - min(33, pVad->cbuText)
        );
    }
    nt = Util_VfsReadFile_FromPBYTE(sz, cbMax - 1, pb, cb, pcbRead, cbOffset - (iPage - oVadExPages) * cbLINELENGTH);
    LocalFree(sz);
    Ob_DECREF(pObMap);
    return nt;
}

int MemMap_Read_VadExMap_CmpFind(_In_ QWORD vaBase, _In_ QWORD qwEntry)
{
    PVMM_MAP_VADENTRY pEntry = (PVMM_MAP_VADENTRY)qwEntry;
    if(pEntry->vaStart < vaBase) { return 1; }
    if(pEntry->vaStart > vaBase) { return -1; }
    return 0;
}

_Success_(return == 0)
NTSTATUS MemMap_Read_VadExMap(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess, _In_ LPCSTR uszFile, _Out_writes_to_(cb, *pcbRead) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset)
{
    NTSTATUS nt = VMMDLL_STATUS_FILE_INVALID;
    QWORD vaVad;
    PVMM_MAP_VADENTRY peVad;
    PVMMOB_MAP_VAD pObVadMap = NULL;
    if(!_stricmp(uszFile, "_vad-v.txt")) {
        return MemMap_Read_VadExMap2(H, pProcess, 0, 0xffffffff, pb, cb, pcbRead, cbOffset);
    }
    if(uszFile[0] == '0' && uszFile[1] == 'x' && VmmMap_GetVad(H, pProcess, &pObVadMap, VMM_VADMAP_TP_CORE)) {
        vaVad = Util_GetNumericA(uszFile);
        peVad = Util_qfind(vaVad, pObVadMap->cMap, pObVadMap->pMap, sizeof(VMM_MAP_VADENTRY), MemMap_Read_VadExMap_CmpFind);
        if(peVad) {
            nt = MemMap_Read_VadExMap2(H, pProcess, peVad->cVadExPagesBase, peVad->cVadExPages, pb, cb, pcbRead, cbOffset);
        }
        Ob_DECREF_NULL(&pObVadMap);
        return nt;
    }
    return nt;
}

VOID MemMap_PteReadLine_Callback(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess, _In_ DWORD cbLineLength, _In_ DWORD ie, _In_ PVMM_MAP_PTEENTRY pe, _Out_writes_(cbLineLength + 1) LPSTR szu8)
{
    Util_usnprintf_ln(szu8, cbLineLength,
        H->vmm.f32 ? "%04x%7i %8x %08x-%08x %cr%c%c%s%s" : "%04x%7i %8x %016llx-%016llx %cr%c%c%s%s",
        ie,
        pProcess->dwPID,
        (DWORD)pe->cPages,
        pe->vaBase,
        pe->vaBase + (pe->cPages << 12) - 1,
        pe->fPage & VMM_MEMMAP_PAGE_NS ? '-' : 's',
        pe->fPage & VMM_MEMMAP_PAGE_W ? 'w' : '-',
        pe->fPage & VMM_MEMMAP_PAGE_NX ? '-' : 'x',
        pe->fWoW64 ? " 32 " : "    ",
        pe->uszText
    );
}

/*
* Read : function as specified by the module manager. The module manager will
* call into this callback function whenever a read shall occur from a "file".
* -- H
* -- ctxP
* -- pb
* -- cb
* -- pcbRead
* -- cbOffset
* -- return
*/
_Success_(return == 0)
NTSTATUS MemMap_Read(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_CONTEXT ctxP, _Out_writes_to_(cb, *pcbRead) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset)
{
    BOOL f32 = H->vmm.f32;
    NTSTATUS nt = VMMDLL_STATUS_FILE_INVALID;
    LPCSTR uszFile;
    CHAR uszPath1[MAX_PATH];
    PVMMOB_MAP_PTE pObPteMap = NULL;
    PVMMOB_MAP_VAD pObVadMap = NULL;
    // read page table memory map.
    if(!_stricmp(ctxP->uszPath, "pte.txt")) {
        if(VmmMap_GetPte(H, ctxP->pProcess, &pObPteMap, TRUE)) {
            nt = Util_VfsLineFixed_Read(
                H, (UTIL_VFSLINEFIXED_PFN_CB)MemMap_PteReadLine_Callback, ctxP->pProcess,
                (f32 ? MEMMAP_PTE_LINELENGTH_X86 : MEMMAP_PTE_LINELENGTH_X64),
                (f32 ? MEMMAP_PTE_LINEHEADER_X86 : MEMMAP_PTE_LINEHEADER_X64),
                pObPteMap->pMap, pObPteMap->cMap, sizeof(VMM_MAP_PTEENTRY),
                pb, cb, pcbRead, cbOffset
            );
            Ob_DECREF_NULL(&pObPteMap);
        }
        return nt;
    }
    if(!_stricmp(ctxP->uszPath, "vad.txt")) {
        if(VmmMap_GetVad(H, ctxP->pProcess, &pObVadMap, VMM_VADMAP_TP_FULL)) {
            nt = Util_VfsLineFixed_Read(
                H, (UTIL_VFSLINEFIXED_PFN_CB)MemMap_VadReadLineCB, ctxP->pProcess,
                (f32 ? MEMMAP_VAD_LINELENGTH_X86 : MEMMAP_VAD_LINELENGTH_X64),
                (f32 ? MEMMAP_VAD_LINEHEADER_X86 : MEMMAP_VAD_LINEHEADER_X64),
                pObVadMap->pMap, pObVadMap->cMap, sizeof(VMM_MAP_VADENTRY),
                pb, cb, pcbRead, cbOffset
            );
            Ob_DECREF(pObVadMap);
        }
        return nt;
    }
    uszFile = CharUtil_PathSplitFirst(ctxP->uszPath, uszPath1, sizeof(uszPath1));
    if(!_stricmp(uszPath1, "vad-v") && uszFile[0]) {
        return MemMap_Read_VadExMap(H, ctxP->pProcess, uszFile, pb, cb, pcbRead, cbOffset);

    }
    return nt;
}

/*
* List : function as specified by the module manager. The module manager will
* call into this callback function whenever a list directory shall occur from
* the given module.
* -- H
* -- ctxP
* -- pFileList
* -- return
*/
BOOL MemMap_List(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_CONTEXT ctxP, _Inout_ PHANDLE pFileList)
{
    BOOL f32 = H->vmm.f32;
    DWORD iVad, cbLine;
    LPCSTR uszFile;
    CHAR uszPath1[MAX_PATH];
    PVMMOB_MAP_PTE pObPteMap = NULL;
    PVMMOB_MAP_VAD pObVadMap = NULL;
    if(!ctxP->uszPath[0]) {
        // list page table memory map.
        if(VmmMap_GetPte(H, ctxP->pProcess, &pObPteMap, FALSE)) {
            cbLine = f32 ? MEMMAP_PTE_LINELENGTH_X86 : MEMMAP_PTE_LINELENGTH_X64;
            VMMDLL_VfsList_AddFile(pFileList, "pte.txt", UTIL_VFSLINEFIXED_LINECOUNT(H, pObPteMap->cMap) * cbLine, NULL);
            Ob_DECREF_NULL(&pObPteMap);
        }
        // list vad & and extended vad map directory
        VMMDLL_VfsList_AddDirectory(pFileList, "vad-v", NULL);
        if(VmmMap_GetVad(H, ctxP->pProcess, &pObVadMap, VMM_VADMAP_TP_CORE)) {
            cbLine = f32 ? MEMMAP_VAD_LINELENGTH_X86 : MEMMAP_VAD_LINELENGTH_X64;
            VMMDLL_VfsList_AddFile(pFileList, "vad.txt", UTIL_VFSLINEFIXED_LINECOUNT(H, pObVadMap->cMap) * cbLine, NULL);
            Ob_DECREF_NULL(&pObVadMap);
        }
        return TRUE;
    }
    uszFile = CharUtil_PathSplitFirst(ctxP->uszPath, uszPath1, sizeof(uszPath1));
    if(!_stricmp(uszPath1, "vad-v") && !uszFile[0]) {
        if(VmmMap_GetVad(H, ctxP->pProcess, &pObVadMap, VMM_VADMAP_TP_FULL)) {
            VMMDLL_VfsList_AddFile(pFileList, "_vad-v.txt", pObVadMap->cPage * MEMMAP_VADEX_LINELENGTH, NULL);
            for(iVad = 0; iVad < pObVadMap->cMap; iVad++) {
                sprintf_s(
                    uszPath1,
                    _countof(uszPath1) - 1,
                    f32 ? "0x%08llx%s%s.txt" : "0x%016llx%s%s.txt",
                    pObVadMap->pMap[iVad].vaStart,
                    (pObVadMap->pMap[iVad].uszText && pObVadMap->pMap[iVad].uszText[0]) ? "-" : "",
                    pObVadMap->pMap[iVad].uszText ? CharUtil_PathSplitLast(pObVadMap->pMap[iVad].uszText) : ""
                );
                VMMDLL_VfsList_AddFile(pFileList, uszPath1, pObVadMap->pMap[iVad].cVadExPages * MEMMAP_VADEX_LINELENGTH, NULL);
            }
            Ob_DECREF_NULL(&pObVadMap);
        }
    }
    return TRUE;
}

/*
* Forensic JSON log:
*/
VOID MemMap_FcLogJSON(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_CONTEXT ctxP, _In_ VOID(*pfnLogJSON)(_In_ VMM_HANDLE H, _In_ PVMMDLL_FORENSIC_JSONDATA pData))
{
    PVMM_PROCESS pProcess = ctxP->pProcess;
    PVMMDLL_FORENSIC_JSONDATA pd;
    PVMMOB_MAP_PTE pObPteMap = NULL;
    PVMMOB_MAP_VAD pObVadMap = NULL;
    PVMM_MAP_PTEENTRY pep;
    PVMM_MAP_VADENTRY pev;
    DWORD i;
    CHAR usz[MAX_PATH] = { 0 };
    if(!pProcess || !(pd = LocalAlloc(LMEM_ZEROINIT, sizeof(VMMDLL_FORENSIC_JSONDATA)))) { return; }
    pd->dwVersion = VMMDLL_FORENSIC_JSONDATA_VERSION;
    pd->dwPID = pProcess->dwPID;
    pd->szjType = "pte";
    // 1: PTEs
    pd->fHex[0] = TRUE;
    usz[1] = 'r'; usz[6] = ' ';
    if(VmmMap_GetPte(H, pProcess, &pObPteMap, TRUE)) {
        for(i = 0; i < pObPteMap->cMap; i++) {
            pep = pObPteMap->pMap + i;
            usz[0] = pep->fPage & VMM_MEMMAP_PAGE_NS ? '-' : 's';
            usz[2] = pep->fPage & VMM_MEMMAP_PAGE_W ? 'w' : '-';
            usz[3] = pep->fPage & VMM_MEMMAP_PAGE_NX ? '-' : 'x';
            pd->i = i;
            pd->qwNum[0] = pep->cPages << 12;
            pd->qwHex[0] = pep->cPages;
            pd->va[0] = pep->vaBase;
            pd->va[1] = pep->vaBase + (pep->cPages << 12) - 1;
            pd->usz[0] = usz;
            pd->usz[1] = pep->uszText;
            pfnLogJSON(H, pd);
        }
    }
    // 2: VADs
    pd->szjType = "vad";
    pd->fHex[1] = TRUE;
    if(VmmMap_GetVad(H, pProcess, &pObVadMap, VMM_VADMAP_TP_FULL)) {
        for(i = 0; i < pObVadMap->cMap; i++) {
            pev = pObVadMap->pMap + i;
            MmVad_StrProtectionFlags(pev, usz);
            snprintf(usz + 7, sizeof(usz) - 7, "%s", pev->uszText);
            pd->i = i;
            pd->vaObj = pev->vaVad;
            pd->qwNum[0] = pev->vaEnd - pev->vaStart + 1;
            pd->qwHex[0] = ((pev->vaEnd - pev->vaStart + 1) >> 12);   // pages
            pd->qwHex[1] = pev->CommitCharge;
            pd->va[0] = pev->vaStart;
            pd->va[1] = pev->vaEnd;
            pd->usz[0] = (LPSTR)MmVad_StrType(pev);
            pd->usz[1] = usz;
            pfnLogJSON(H, pd);
        }
    }
    Ob_DECREF(pObVadMap);
    Ob_DECREF(pObPteMap);
    LocalFree(pd);
}

/*
* Initialization function. The module manager shall call into this function
* when the module shall be initialized. If the module wish to initialize it
* shall call the supplied pfnPluginManager_Register function.
* NB! the module does not have to register itself - for example if the target
* operating system or architecture is unsupported.
* -- pPluginRegInfo
*/
VOID M_ProcMemMap_Initialize(_In_ VMM_HANDLE H, _Inout_ PVMMDLL_PLUGIN_REGINFO pRI)
{
    if((pRI->magic != VMMDLL_PLUGIN_REGINFO_MAGIC) || (pRI->wVersion != VMMDLL_PLUGIN_REGINFO_VERSION)) { return; }
    if(!((pRI->tpMemoryModel == VMM_MEMORYMODEL_X64) || (pRI->tpMemoryModel == VMM_MEMORYMODEL_ARM64) || (pRI->tpMemoryModel == VMM_MEMORYMODEL_X86) || (pRI->tpMemoryModel == VMM_MEMORYMODEL_X86PAE))) { return; }
    strcpy_s(pRI->reg_info.uszPathName, 128, "\\memmap");               // module name
    pRI->reg_info.fRootModule = FALSE;                                  // module shows in root directory
    pRI->reg_info.fProcessModule = TRUE;                                // module shows in process directory
    pRI->reg_fn.pfnList = MemMap_List;                                  // List function supported
    pRI->reg_fn.pfnRead = MemMap_Read;                                  // Read function supported
    pRI->reg_fnfc.pfnLogJSON = MemMap_FcLogJSON;                        // JSON log function supported
    pRI->pfnPluginManager_Register(H, pRI);
}
