// m_searchyara.c : implementation of the yara memory search built-in module.
//
// (c) Ulf Frisk, 2023-2025
// Author: Ulf Frisk, pcileech@frizk.net
//

#include "modules.h"
#include "../vmmyarautil.h"

LPCSTR szYARASEARCH_README =
"Information about the yara search module                                     \n" \
"========================================                                     \n" \
"Write the full path to a yara rule file (compiled or source or index source) \n" \
"into the file yara-rules-file.txt to start a search.                         \n" \
"---                                                                          \n" \
"An ongoing search may be cancelled by writing '1' to reset.txt.              \n" \
"Additional info is shown in status.txt.                                      \n" \
"---                                                                          \n" \
"Documentation: https://github.com/ufrisk/MemProcFS/wiki/FS_YaraSearch        \n";

typedef struct tdMOB_YARASEARCH_CONTEXT {
    OB ObHdr;
    DWORD dwPID;
    BOOL fActive;
    BOOL fCompleted;
    VMMDLL_YARA_CONFIG sctx;
    POB_DATA pObDataResult;
    POB_MEMFILE pmfObResult;
    LPSTR _uszYaraRulesFilePtr;
    CHAR uszYaraRulesFile[MAX_PATH];
    QWORD tcStart;
    QWORD tcEnd;
    PVMMYARAUTILOB_CONTEXT pObYaraUtil;
} MOB_YARASEARCH_CONTEXT, *PMOB_YARASEARCH_CONTEXT;

VOID MSearchYara_ContextUpdate(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_CONTEXT ctxP, _In_opt_ PMOB_YARASEARCH_CONTEXT ctxS)
{
    EnterCriticalSection(&H->vmm.LockPlugin);
    if(!ctxS || !ObMap_Exists((POB_MAP)ctxP->ctxM, ctxS)) {
        Ob_DECREF(ObMap_RemoveByKey((POB_MAP)ctxP->ctxM, ctxP->dwPID));
        if(ctxS) { ObMap_Push((POB_MAP)ctxP->ctxM, ctxP->dwPID, ctxS); }
    }
    LeaveCriticalSection(&H->vmm.LockPlugin);
}

VOID MSearchYara_ContextCleanup1_CB(PVOID pOb)
{
    ((PMOB_YARASEARCH_CONTEXT)pOb)->sctx.fAbortRequested = TRUE;
}

VOID MSearchYara_ContextCleanup_CB(PVOID pOb)
{
    PMOB_YARASEARCH_CONTEXT ctx = (PMOB_YARASEARCH_CONTEXT)pOb;
    Ob_DECREF(ctx->pObDataResult);
    Ob_DECREF(ctx->pmfObResult);
    Ob_DECREF(ctx->pObYaraUtil);
}

/*
* CALLER DECREF: return
*/
PMOB_YARASEARCH_CONTEXT MSearchYara_ContextGet(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_CONTEXT ctxP)
{
    PMOB_YARASEARCH_CONTEXT pObCtx = NULL;
    EnterCriticalSection(&H->vmm.LockPlugin);
    pObCtx = ObMap_GetByKey((POB_MAP)ctxP->ctxM, ctxP->dwPID);
    LeaveCriticalSection(&H->vmm.LockPlugin);
    if(!pObCtx && (pObCtx = Ob_AllocEx(H, OB_TAG_MOD_SEARCH_CTX, LMEM_ZEROINIT, sizeof(MOB_YARASEARCH_CONTEXT), MSearchYara_ContextCleanup_CB, MSearchYara_ContextCleanup1_CB))) {
        pObCtx->sctx.cRules = 1;
        pObCtx->_uszYaraRulesFilePtr = pObCtx->uszYaraRulesFile;
        pObCtx->sctx.pszRules = &pObCtx->_uszYaraRulesFilePtr;
        if(ctxP->pProcess) {
            // virtual memory search in process address space
            pObCtx->dwPID = ((PVMM_PROCESS)ctxP->pProcess)->dwPID;
            if(((PVMM_PROCESS)ctxP->pProcess)->fUserOnly) {
                pObCtx->sctx.vaMax = H->vmm.f32 ? 0x7fffffff : 0x7fffffffffff;
            } else {
                pObCtx->sctx.vaMax = H->vmm.f32 ? 0xffffffff : 0xffffffffffffffff;
            }
        } else {
            // physical memory search
            pObCtx->dwPID = 0;
            pObCtx->sctx.vaMax = H->dev.paMax - 1;
        }
    }
    return pObCtx;
}

/*
* Yara callback function to process a single match from the yara scanner.
* -- ctxScan
* -- pMatch
* -- pbBuffer
* -- cbBuffer
* -- return = TRUE to continue scanning, FALSE to stop scanning.
*/
BOOL MSearchYara_MatchCB(_In_ PMOB_YARASEARCH_CONTEXT ctx, _In_ PVMMYARA_RULE_MATCH pMatch, _In_reads_bytes_(cbBuffer) PBYTE pbBuffer, _In_ SIZE_T cbBuffer)
{
    VMMYARAUTIL_SCAN_CONTEXT ctxScan = { 0 };
    // init yara util context on first match:
    if(!ctx->pObYaraUtil) {
        ctx->pObYaraUtil = VmmYaraUtil_Initialize(ctx->ObHdr.H, NULL, VMMDLL_YARA_CONFIG_MAX_RESULT);
        if(!ctx->pObYaraUtil) {
            return FALSE;
        }
    }
    // init scan context:
    ctxScan.va = ctx->sctx.vaCurrent;
    ctxScan.pb = pbBuffer;
    ctxScan.cb = (DWORD)cbBuffer;
    ctxScan.dwPID = ctx->dwPID;
    ctxScan.ctx = ctx->pObYaraUtil;
    // process match:
    return VmmYaraUtil_MatchCB(&ctxScan, pMatch, pbBuffer, cbBuffer);
}

/*
* Perform the memory search in an async worker thread
*/
VOID MSearchYara_PerformSeach_ThreadProc(_In_ VMM_HANDLE H, _In_ PMOB_YARASEARCH_CONTEXT ctxS)
{
    LPSTR uszTXT;
    POB_MEMFILE pmfOb = NULL;
    PVMM_PROCESS pObProcess = NULL;
    ctxS->tcStart = GetTickCount64();
    // perform scan:
    if(!ctxS->dwPID) {
        VmmYaraUtil_SearchSingleProcess(H, NULL, &ctxS->sctx, &ctxS->pObDataResult);
    } else if((pObProcess = VmmProcessGet(H, ctxS->dwPID))) {
        VmmYaraUtil_SearchSingleProcess(H, pObProcess, &ctxS->sctx, &ctxS->pObDataResult);
    }
    // finalize results (if any) with vmmyarautil:
    if(ctxS->pObYaraUtil) {
        if(VmmYaraUtil_IngestFinalize(H, ctxS->pObYaraUtil) && (pmfOb = ObMemFile_New(H, H->vmm.pObCacheMapObCompressedShared))) {
            while(VmmYaraUtil_ParseSingleResultNext(H, ctxS->pObYaraUtil, &uszTXT, NULL, NULL, NULL)) {
                ObMemFile_AppendString(pmfOb, uszTXT);
            }
            // assign result (and reference count responsibility) to context:
            Ob_DECREF_NULL(&ctxS->pmfObResult);
            ctxS->pmfObResult = pmfOb;
        }
        Ob_DECREF_NULL(&ctxS->pObYaraUtil);

    }
    ctxS->tcEnd = GetTickCount64();
    ctxS->fCompleted = TRUE;
    ctxS->fActive = FALSE;
    Ob_DECREF(pObProcess);
}

/*
* Write : function as specified by the module manager. The module manager will
* call into this callback function whenever a write shall occur from a "file".
* -- H
* -- ctxP
* -- pb
* -- cb
* -- pcbWrite
* -- cbOffset
* -- return
*/
NTSTATUS MSearchYara_Write(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_CONTEXT ctxP, _In_reads_(cb) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbWrite, _In_ QWORD cbOffset)
{
    NTSTATUS nt = VMMDLL_STATUS_SUCCESS;
    PMOB_YARASEARCH_CONTEXT pObCtx = NULL;
    BOOL fReset;
    QWORD qw;
    *pcbWrite = cb;
    if(!(pObCtx = MSearchYara_ContextGet(H, ctxP))) { return VMMDLL_STATUS_FILE_INVALID; }
    if(!_stricmp(ctxP->uszPath, "reset.txt")) {
        fReset = FALSE;
        nt = Util_VfsWriteFile_BOOL(&fReset, pb, cb, pcbWrite, cbOffset);
        if(fReset) {
            // removal via context update will clear up objects and also
            // cancel / abort any running tasks via the object refcount.
            MSearchYara_ContextUpdate(H, ctxP, NULL);
        }
    }
    if(!pObCtx->fActive && !pObCtx->fCompleted) {
        if(!_stricmp(ctxP->uszPath, "addr-max.txt")) {
            qw = pObCtx->sctx.vaMax;
            nt = Util_VfsWriteFile_QWORD(&qw, pb, cb, pcbWrite, cbOffset + (H->vmm.f32 ? 8 : 0), 1, 0);
            qw = (qw - 1) | 0xfff;
            if((qw != pObCtx->sctx.vaMax)) {
                // update (if ok) within critical section
                EnterCriticalSection(&H->vmm.LockPlugin);
                if(!pObCtx->fActive && !pObCtx->fCompleted) {
                    pObCtx->sctx.vaMax = qw;
                    MSearchYara_ContextUpdate(H, ctxP, pObCtx);
                }
                LeaveCriticalSection(&H->vmm.LockPlugin);
            }
        }
        if(!_stricmp(ctxP->uszPath, "addr-min.txt")) {
            qw = pObCtx->sctx.vaMin;
            nt = Util_VfsWriteFile_QWORD(&qw, pb, cb, pcbWrite, cbOffset + (H->vmm.f32 ? 8 : 0), 0, 0);
            qw = qw & ~0xfff;
            if((qw != pObCtx->sctx.vaMin)) {
                // update (if ok) within critical section
                EnterCriticalSection(&H->vmm.LockPlugin);
                if(!pObCtx->fActive && !pObCtx->fCompleted) {
                    pObCtx->sctx.vaMin = qw;
                    MSearchYara_ContextUpdate(H, ctxP, pObCtx);
                }
                LeaveCriticalSection(&H->vmm.LockPlugin);
            }
        }
        if(!_stricmp(ctxP->uszPath, "yara-rules-file.txt")) {
            nt = Util_VfsWriteFile_PBYTE(pObCtx->uszYaraRulesFile, sizeof(pObCtx->uszYaraRulesFile), pb, cb, pcbWrite, cbOffset, TRUE);
            if(*pcbWrite && (strlen(pObCtx->uszYaraRulesFile) > 4)) {
                // update (if ok) within critical section
                EnterCriticalSection(&H->vmm.LockPlugin);
                if(!pObCtx->fActive && !pObCtx->fCompleted) {
                    MSearchYara_ContextUpdate(H, ctxP, pObCtx);
                    // start search by queuing the search onto a work item
                    // in a separate thread. also increase refcount since
                    // worker thread is responsible for its own DECREF.
                    pObCtx->sctx.fAbortRequested = FALSE;
                    pObCtx->fActive = TRUE;
                    pObCtx->sctx.pvUserPtrOpt = pObCtx;
                    pObCtx->sctx.pfnScanMemoryCB = (VMMYARA_SCAN_MEMORY_CALLBACK)MSearchYara_MatchCB;
                    VmmWork_Ob(H, (PVMM_WORK_START_ROUTINE_OB_PFN)MSearchYara_PerformSeach_ThreadProc, (POB)pObCtx, NULL, VMMWORK_FLAG_PRIO_NORMAL);
                }
                LeaveCriticalSection(&H->vmm.LockPlugin);
            }
            *pcbWrite = cb;
        }
    }
    Ob_DECREF(pObCtx);
    return nt;
}

_Success_(return == 0)
NTSTATUS MSearchYara_ReadStatus(_In_ PMOB_YARASEARCH_CONTEXT ctxS, _Out_writes_to_(cb, *pcbRead) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset)
{
    QWORD qwSpeed = 0;
    CHAR *szStatus, szBuffer[512];
    if(ctxS->fActive) {
        szStatus = "RUNNING";
    } else if(ctxS->fCompleted) {
        szStatus = "COMPLETED";
    } else {
        szStatus = "NOT_STARTED";
    }
    if(ctxS->tcStart) {
        qwSpeed = ctxS->sctx.cbReadTotal / (1000 * ((ctxS->tcEnd ? ctxS->tcEnd : GetTickCount64()) - ctxS->tcStart));
    }
    snprintf(
        szBuffer,
        sizeof(szBuffer),
        "Status:          %s\n" \
        "Yara rules:      %s\n" \
        "Min address:     0x%llx\n" \
        "Max address:     0x%llx\n" \
        "Current address: 0x%llx\n" \
        "Bytes read:      0x%llx\n" \
        "Speed (MB/s):    %llu\n" \
        "Search hits:     %i\n",
        szStatus,
        ctxS->sctx.pszRules[0],
        ctxS->sctx.vaMin,
        ctxS->sctx.vaMax,
        ctxS->sctx.vaCurrent,
        ctxS->sctx.cbReadTotal,
        qwSpeed,
        ctxS->sctx.cResult
    );
    if(pb) {
        return Util_VfsReadFile_FromPBYTE(szBuffer, strlen(szBuffer), pb, cb, pcbRead, cbOffset);
    } else {
        *pcbRead = (DWORD)strlen(szBuffer);
        return VMMDLL_STATUS_SUCCESS;
    }
}

VOID MSearchYara_ReadLine_CB(_In_ VMM_HANDLE H, _Inout_opt_ PVOID ctx, _In_ DWORD cbLineLength, _In_ DWORD ie, _In_ PQWORD pe, _Out_writes_(cbLineLength + 1) LPSTR szu8)
{
    Util_usnprintf_ln(szu8, cbLineLength, H->vmm.f32 ? "%08x" : "%016llx", *pe);
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
NTSTATUS MSearchYara_Read(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_CONTEXT ctxP, _Out_writes_to_(cb, *pcbRead) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset)
{
    NTSTATUS nt = VMMDLL_STATUS_FILE_INVALID;
    PMOB_YARASEARCH_CONTEXT pObCtx = NULL;
    if(!(pObCtx = MSearchYara_ContextGet(H, ctxP))) { return VMMDLL_STATUS_FILE_INVALID; }
    if(!_stricmp(ctxP->uszPath, "readme.txt")) {
        nt = Util_VfsReadFile_FromStrA(szYARASEARCH_README, pb, cb, pcbRead, cbOffset);
    } else if(!_stricmp(ctxP->uszPath, "addr-max.txt")) {
        nt = H->vmm.f32 ?
            Util_VfsReadFile_FromDWORD((DWORD)pObCtx->sctx.vaMax, pb, cb, pcbRead, cbOffset, FALSE) :
            Util_VfsReadFile_FromQWORD((QWORD)pObCtx->sctx.vaMax, pb, cb, pcbRead, cbOffset, FALSE);
    } else if(!_stricmp(ctxP->uszPath, "addr-min.txt")) {
        nt = H->vmm.f32 ?
            Util_VfsReadFile_FromDWORD((DWORD)pObCtx->sctx.vaMin, pb, cb, pcbRead, cbOffset, FALSE) :
            Util_VfsReadFile_FromQWORD((QWORD)pObCtx->sctx.vaMin, pb, cb, pcbRead, cbOffset, FALSE);
    } else if(!_stricmp(ctxP->uszPath, "reset.txt")) {
        nt = Util_VfsReadFile_FromBOOL(FALSE, pb, cb, pcbRead, cbOffset);
    } else if(!_stricmp(ctxP->uszPath, "result.txt")) {
        nt = VMMDLL_STATUS_END_OF_FILE;
        if(pObCtx->pObDataResult) {
            nt = Util_VfsLineFixed_Read(
                H, (UTIL_VFSLINEFIXED_PFN_CB)MSearchYara_ReadLine_CB, NULL, H->vmm.f32 ? 9 : 17, NULL,
                pObCtx->pObDataResult->pqw, pObCtx->pObDataResult->ObHdr.cbData / sizeof(QWORD), sizeof(QWORD),
                pb, cb, pcbRead, cbOffset
            );
        }
    } else if(!_stricmp(ctxP->uszPath, "result-v.txt")) {
        nt = VMMDLL_STATUS_END_OF_FILE;
        if(pObCtx->pmfObResult) {
            nt = ObMemFile_ReadFile(pObCtx->pmfObResult, pb, cb, pcbRead, cbOffset);
        }
    } else if(!_stricmp(ctxP->uszPath, "yara-rules-file.txt")) {
        nt = Util_VfsReadFile_FromStrA(pObCtx->uszYaraRulesFile, pb, cb, pcbRead, cbOffset);
    } else if(!_stricmp(ctxP->uszPath, "status.txt")) {
        nt = MSearchYara_ReadStatus(pObCtx, pb, cb, pcbRead, cbOffset);
    }
    Ob_DECREF(pObCtx);
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
BOOL MSearchYara_List(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_CONTEXT ctxP, _Inout_ PHANDLE pFileList)
{
    DWORD cbResult = 0;
    PMOB_YARASEARCH_CONTEXT pObCtx = NULL;
    if(ctxP->uszPath[0]) { return FALSE; }
    if(!(pObCtx = MSearchYara_ContextGet(H, ctxP))) { return FALSE; }
    VMMDLL_VfsList_AddFile(pFileList, "addr-max.txt", H->vmm.f32 ? 8 : 16, NULL);
    VMMDLL_VfsList_AddFile(pFileList, "addr-min.txt", H->vmm.f32 ? 8 : 16, NULL);
    VMMDLL_VfsList_AddFile(pFileList, "readme.txt", strlen(szYARASEARCH_README), NULL);
    VMMDLL_VfsList_AddFile(pFileList, "reset.txt", 1, NULL);
    cbResult = pObCtx->pObDataResult ? ((H->vmm.f32 ? 9ULL : 17ULL) * pObCtx->pObDataResult->ObHdr.cbData / sizeof(QWORD)) : 0;
    VMMDLL_VfsList_AddFile(pFileList, "result.txt", cbResult, NULL);
    cbResult = pObCtx->pmfObResult ? (DWORD)ObMemFile_Size(pObCtx->pmfObResult) : 0;
    VMMDLL_VfsList_AddFile(pFileList, "result-v.txt", cbResult, NULL);
    VMMDLL_VfsList_AddFile(pFileList, "yara-rules-file.txt", strlen(pObCtx->uszYaraRulesFile), NULL);
    cbResult = 0;
    MSearchYara_ReadStatus(pObCtx, NULL, 0, &cbResult, 0);
    VMMDLL_VfsList_AddFile(pFileList, "status.txt", cbResult, NULL);
    Ob_DECREF(pObCtx);
    return TRUE;
}

VOID MSearchYara_Close(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_CONTEXT ctxP)
{
    Ob_DECREF(ctxP->ctxM);
}

/*
* Initialization function. The module manager shall call into this function
* when the module shall be initialized. If the module wish to initialize it
* shall call the supplied pfnPluginManager_Register function.
* NB! the module does not have to register itself - for example if the target
* operating system or architecture is unsupported.
* -- H
* -- pRI
*/
VOID M_SearchYara_Initialize(_In_ VMM_HANDLE H, _Inout_ PVMMDLL_PLUGIN_REGINFO pRI)
{
    if((pRI->magic != VMMDLL_PLUGIN_REGINFO_MAGIC) || (pRI->wVersion != VMMDLL_PLUGIN_REGINFO_VERSION)) { return; }
    if(H->cfg.fDisableYara) { return; }
    if(!(pRI->reg_info.ctxM = (PVMMDLL_PLUGIN_INTERNAL_CONTEXT)ObMap_New(H, OB_MAP_FLAGS_OBJECT_OB))) { return; }
    pRI->reg_fn.pfnList = MSearchYara_List;
    pRI->reg_fn.pfnRead = MSearchYara_Read;
    pRI->reg_fn.pfnWrite = MSearchYara_Write;
    // register process plugin (virtual memory search)
    strcpy_s(pRI->reg_info.uszPathName, 128, "\\search\\yara");
    pRI->reg_info.fRootModule = FALSE;
    pRI->reg_info.fProcessModule = TRUE;
    pRI->pfnPluginManager_Register(H, pRI);
    // register root plugin (physical memory search)
    pRI->reg_fn.pfnClose = MSearchYara_Close;           // Close function supported (but should only be called once on unload so put it here...)
    strcpy_s(pRI->reg_info.uszPathName, 128, "\\misc\\search\\yara");
    pRI->reg_info.fRootModule = TRUE;
    pRI->reg_info.fProcessModule = FALSE;
    pRI->pfnPluginManager_Register(H, pRI);
}
