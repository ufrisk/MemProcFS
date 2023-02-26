// m_misc_procinfo.c : various process informational lists.
//
// (c) Ulf Frisk, 2022-2023
// Author: Ulf Frisk, pcileech@frizk.net
//

#include "modules.h"

typedef struct tdOB_MMISCINFO_CONTEXT {
    OB ObHdr;
    BOOL fAbort;
    BOOL fCompleted;
    DWORD dwProgressPercent;
    VMMDLL_MODULE_ID MID;
    POB_COMPRESSED pDTB;
} OB_MMISCINFO_CONTEXT, *POB_PMMISCINFO_CONTEXT;

VOID MMiscProcInfo_Context_CallbackCleanup(POB_PMMISCINFO_CONTEXT pOb)
{
    Ob_DECREF(pOb->pDTB);
}

#define MMISCPROCINFO_MAP_NUM_PFNS      0x2000

VOID MMiscProcInfo_InitializeDTB(_In_ VMM_HANDLE H, _In_ POB_PMMISCINFO_CONTEXT ctx)
{
    BYTE pbDTB[0x1000];
    SIZE_T oText = 0;
    LPSTR uszText = NULL;
    DWORD cEntries = 0, i, oPfn, cPfn, cPfnMax;
    QWORD vaPfnPteSystem;
    PMMPFN_MAP_ENTRY pPfn;
    PMMPFNOB_MAP pObPfnMap = NULL, pObPfnMap2 = NULL;
    PVMM_PROCESS pObProcess = NULL;
    PVMM_PROCESS pObSystemProcess = NULL;
    // 1: INIT:
    if(!(uszText = LocalAlloc(LMEM_ZEROINIT, 0x00100000))) { goto fail; }
    if(!(pObSystemProcess = VmmProcessGet(H, 4))) { goto fail; }
    // 2: Get System DTB PFN:
    if(!MmPfn_Map_GetPfn(H, (DWORD)(pObSystemProcess->paDTB >> 12), 1, &pObPfnMap, FALSE) || (pObPfnMap->cMap != 1)) { goto fail; }
    vaPfnPteSystem = pObPfnMap->pMap[0].vaPte;
    Ob_DECREF_NULL(&pObPfnMap);
    // 4: Walk PFN database:
    cPfnMax = (DWORD)(H->dev.paMax >> 12);
    for(oPfn = 0; oPfn < cPfnMax; oPfn += MMISCPROCINFO_MAP_NUM_PFNS) {
        cPfn = min(MMISCPROCINFO_MAP_NUM_PFNS, cPfnMax - oPfn);
        if(H->fAbort || ctx->fAbort) { goto fail; }
        ctx->dwProgressPercent = (DWORD)((100ULL * oPfn) / cPfnMax);
        if(!MmPfn_Map_GetPfn(H, oPfn, cPfn, &pObPfnMap, FALSE)) { goto fail; }
        for(i = 0; i < pObPfnMap->cMap; i++) {
            pPfn = pObPfnMap->pMap + i;
            if((pPfn->vaPte == vaPfnPteSystem) && (pPfn->PageLocation == MmPfnTypeActive)) {
                if(oText > 0x00100000 - 0x1000) { goto fail; }
                // verify dtb validity:
                if(!VmmRead(H, NULL, (QWORD)pPfn->dwPfn << 12, pbDTB, 0x1000)) { continue; }
                if(!VmmTlbPageTableVerify(H, pbDTB, (QWORD)pPfn->dwPfn << 12, TRUE)) { continue; }
                // get process from pfn db:
                if(MmPfn_Map_GetPfn(H, pPfn->dwPfn, 1, &pObPfnMap2, TRUE)) {
                    if(pObPfnMap2->cMap) {
                        pObProcess = VmmProcessGet(H, pObPfnMap2->pMap[0].AddressInfo.dwPid);
                    }
                    Ob_DECREF_NULL(&pObPfnMap2);
                }
                oText += _snprintf_s(uszText + oText, MAX_PATH, _TRUNCATE, "%04x%7i %16llx %16llx %s\n",
                    cEntries++,
                    pObProcess ? pObProcess->dwPID : 0,
                    (QWORD)pPfn->dwPfn << 12,
                    pObProcess ? pObProcess->win.EPROCESS.va : 0,
                    pObProcess ? pObProcess->szName : "---"
                );
                Ob_DECREF_NULL(&pObProcess);
            }
        }
        Ob_DECREF_NULL(&pObPfnMap);
    }
    ctx->dwProgressPercent = 100;
    ctx->fCompleted = TRUE;
    ctx->pDTB = ObCompress_NewFromStrA(H, H->vmm.pObCacheMapObCompressedShared, uszText);
fail:
    Ob_DECREF(pObSystemProcess);
    Ob_DECREF(pObProcess);
    Ob_DECREF(pObPfnMap2);
    Ob_DECREF(pObPfnMap);
    LocalFree(uszText);
}

/*
* Iterate over all process in a separate async thread.
*/
VOID MMiscProcInfo_Process_ThreadProc(_In_ VMM_HANDLE H, _In_ POB_PMMISCINFO_CONTEXT ctx)
{
    VMMSTATISTICS_LOG Statistics = { 0 };
    VmmStatisticsLogStart(H, ctx->MID, LOGLEVEL_6_TRACE, NULL, &Statistics, "GET_CONTEXT");
    MMiscProcInfo_InitializeDTB(H, ctx);
    VmmStatisticsLogEnd(H, &Statistics, "GET_CONTEXT");
}

/*
* Retrieve a context object containing the generated output.
* CALLER DECREF: return
* -- H
* -- ctxP
* -- return
*/
_Success_(return != NULL)
POB_PMMISCINFO_CONTEXT MMiscProcInfo_GetContext(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_CONTEXT ctxP)
{
    static SRWLOCK LockSRW = SRWLOCK_INIT;
    POB_PMMISCINFO_CONTEXT pObInfo;
    if((pObInfo = (POB_PMMISCINFO_CONTEXT)ObContainer_GetOb((POB_CONTAINER)ctxP->ctxM))) { return pObInfo; }
    AcquireSRWLockExclusive(&LockSRW);
    if(!(pObInfo = (POB_PMMISCINFO_CONTEXT)ObContainer_GetOb((POB_CONTAINER)ctxP->ctxM))) {
        if((pObInfo = Ob_AllocEx(H, OB_TAG_CTX_MMISCINFO, LMEM_ZEROINIT, sizeof(OB_MMISCINFO_CONTEXT), (OB_CLEANUP_CB)MMiscProcInfo_Context_CallbackCleanup, NULL))) {
            pObInfo->MID = ctxP->MID;
            ObContainer_SetOb((POB_CONTAINER)ctxP->ctxM, pObInfo);
            VmmWork_Ob(H, (PVMM_WORK_START_ROUTINE_OB_PFN)MMiscProcInfo_Process_ThreadProc, (POB)pObInfo, 0, VMMWORK_FLAG_PRIO_NORMAL);
        }
    }
    ReleaseSRWLockExclusive(&LockSRW);
    return pObInfo;
}

NTSTATUS MMiscProcInfo_Read(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_CONTEXT ctxP, _Out_writes_to_(cb, *pcbRead) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset)
{
    NTSTATUS nt = VMMDLL_STATUS_FILE_INVALID;
    POB_PMMISCINFO_CONTEXT ctxOb = MMiscProcInfo_GetContext(H, ctxP);
    if(ctxOb) {
        if(!_stricmp(ctxP->uszPath, "progress_percent.txt")) {
            return Util_VfsReadFile_FromNumber(ctxOb->dwProgressPercent, pb, cb, pcbRead, cbOffset);
        }
        if(!_stricmp(ctxP->uszPath, "dtb.txt")) {
            nt = Util_VfsReadFile_FromObCompressed(ctxOb->pDTB, pb, cb, pcbRead, cbOffset);
        }
    }
    Ob_DECREF(ctxOb);
    return nt;
}

BOOL MMiscProcInfo_List(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_CONTEXT ctxP, _Inout_ PHANDLE pFileList)
{
    DWORD cbProgress;
    POB_PMMISCINFO_CONTEXT ctxOb = MMiscProcInfo_GetContext(H, ctxP);
    if(ctxOb && !ctxP->uszPath[0]) {
        cbProgress = (ctxOb->dwProgressPercent == 100) ? 3 : ((ctxOb->dwProgressPercent >= 10) ? 2 : 1);
        VMMDLL_VfsList_AddFile(pFileList, "progress_percent.txt", cbProgress, NULL);
        VMMDLL_VfsList_AddFile(pFileList, "dtb.txt", ObCompress_Size(ctxOb->pDTB), NULL);
    }
    Ob_DECREF(ctxOb);
    return TRUE;
}

VOID MMiscProcInfo_Notify(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_CONTEXT ctxP, _In_ DWORD fEvent, _In_opt_ PVOID pvEvent, _In_opt_ DWORD cbEvent)
{
    POB_PMMISCINFO_CONTEXT ctxOb;
    if(fEvent == VMMDLL_PLUGIN_NOTIFY_REFRESH_SLOW) {
        if(ObContainer_Exists((POB_CONTAINER)ctxP->ctxM)) {
            if((ctxOb = MMiscProcInfo_GetContext(H, ctxP))) {
                if(ctxOb->fCompleted) {
                    ObContainer_SetOb((POB_CONTAINER)ctxP->ctxM, NULL);
                }
                Ob_DECREF(ctxOb);
            }
        }
    }
}

VOID MMiscProcInfo_Close(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_CONTEXT ctxP)
{
    POB_PMMISCINFO_CONTEXT ctxOb;
    if((ctxOb = MMiscProcInfo_GetContext(H, ctxP))) {
        ctxOb->fAbort = TRUE;
        Ob_DECREF(ctxOb);
    }
    Ob_DECREF(ctxP->ctxM);
}

VOID M_MiscProcInfo_Initialize(_In_ VMM_HANDLE H, _Inout_ PVMMDLL_PLUGIN_REGINFO pRI)
{
    if((pRI->magic != VMMDLL_PLUGIN_REGINFO_MAGIC) || (pRI->wVersion != VMMDLL_PLUGIN_REGINFO_VERSION)) { return; }
    if((pRI->tpSystem != VMM_SYSTEM_WINDOWS_X64)) { return; }
    if(!(pRI->reg_info.ctxM = (PVMMDLL_PLUGIN_INTERNAL_CONTEXT)ObContainer_New())) { return; }
    strcpy_s(pRI->reg_info.uszPathName, 128, "\\misc\\procinfo");               // module name
    pRI->reg_info.fRootModule = TRUE;                                           // module shows in root directory
    // functions supported:
    pRI->reg_fn.pfnList = MMiscProcInfo_List;
    pRI->reg_fn.pfnRead = MMiscProcInfo_Read;
    pRI->reg_fn.pfnNotify = MMiscProcInfo_Notify;
    pRI->reg_fn.pfnClose = MMiscProcInfo_Close;
    pRI->pfnPluginManager_Register(H, pRI);
}
