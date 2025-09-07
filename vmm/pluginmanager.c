// pluginmanager.c : implementation of the plugin manager for MemProcFS plugins.
//
// (c) Ulf Frisk, 2018-2025
// Author: Ulf Frisk, pcileech@frizk.net
//
#include "pluginmanager.h"
#include "statistics.h"
#include "charutil.h"
#include "util.h"
#include "vmm.h"
#include "vmmex.h"
#include "vmmdll.h"
#include "vmmlog.h"
#include "fc.h"
#include "modules/modules_init.h"

#ifdef VMM_PROFILE_FULL
#include "ex/vmmex_modules_init.h"
#endif /* VMM_PROFILE_FULL */

//
// This file contains functionality related to keeping track of plugins, both
// internal built-in ones and loadable plugins in the form of compliant DLLs.
//
// The functionality and data structures are at this moment single-threaded in
// this implementation and should be protected by a lock (H->vmm.LockMaster).
//
// Core module calls are: List, Read, Write.
// Other module calls are: Notify and Close.
//
// In general, a pointer to a stored-away module specific handle is given in
// every call together with a plugin/process specific pointer to a handle.
// The plugin/process specific handle is stored per module, per PID.
//
// A pProcess struct (if applicable) and a PID is also given in each call
// together with the module name and path.
//

// ----------------------------------------------------------------------------
// MODULES CORE FUNCTIONALITY - DEFINES BELOW:
// ----------------------------------------------------------------------------

typedef struct tdPLUGIN_ENTRY {
    struct tdPLUGIN_ENTRY *FLinkAll;
    struct tdPLUGIN_ENTRY *FLinkNotify;
    struct tdPLUGIN_ENTRY *FLinkForensic;
    DWORD MID;          // module id (used by logging)
    HMODULE hDLL;
    CHAR uszName[32];
    DWORD dwNameHash;
    BOOL fRootModule;
    BOOL fProcessModule;
    PVMMDLL_PLUGIN_INTERNAL_CONTEXT ctxM;
    BOOL(*pfnVisibleModule)(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_CONTEXT ctxP);
    BOOL(*pfnList)(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_CONTEXT ctxP, _Inout_ PHANDLE pFileList);
    NTSTATUS(*pfnRead)(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_CONTEXT ctxP, _Out_writes_to_(cb, *pcbRead) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset);
    NTSTATUS(*pfnWrite)(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_CONTEXT ctxP, _In_reads_(cb) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbWrite, _In_ QWORD cbOffset);
    VOID(*pfnNotify)(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_CONTEXT ctxP, _In_ DWORD fEvent, _In_opt_ PVOID pvEvent, _In_opt_ DWORD cbEvent);
    VOID(*pfnClose)(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_CONTEXT ctxP);
    struct {
        PVOID ctxfc;
        PVOID(*pfnInitialize)(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_CONTEXT ctxP);
        VOID(*pfnFinalize)(_In_ VMM_HANDLE H, _In_opt_ PVOID ctxfc);
        VOID(*pfnTimeline)(
            _In_ VMM_HANDLE H,
            _In_opt_ PVOID ctxfc,
            _In_ HANDLE hTimeline,
            _In_ VOID(*pfnAddEntry)(_In_ VMM_HANDLE H, _In_ HANDLE hTimeline, _In_ QWORD ft, _In_ DWORD dwAction, _In_ DWORD dwPID, _In_ DWORD dwData32, _In_ QWORD qwData64, _In_ LPCSTR uszText),
            _In_ VOID(*pfnEntryAddBySql)(_In_ VMM_HANDLE H, _In_ HANDLE hTimeline, _In_ DWORD cEntrySql, _In_ LPCSTR *pszEntrySql));
        VOID(*pfnLogCSV)(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_CONTEXT ctxP, VMMDLL_CSV_HANDLE hCSV);
        VOID(*pfnLogJSON)(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_CONTEXT ctxP, _In_ VOID(*pfnLogJSON)(_In_ VMM_HANDLE H, _In_ PVMMDLL_FORENSIC_JSONDATA pData));
        VOID(*pfnFindEvil)(_In_ VMM_HANDLE H, _In_ VMMDLL_MODULE_ID MID, _In_opt_ PVOID ctxfc);
        VOID(*pfnIngestObject)(_In_ VMM_HANDLE H, _In_opt_ PVOID ctxfc, _In_ PVMMDLL_FORENSIC_INGEST_OBJECT pIngestObject);
        VOID(*pfnIngestPhysmem)(_In_ VMM_HANDLE H, _In_opt_ PVOID ctxfc, _In_ PVMMDLL_FORENSIC_INGEST_PHYSMEM pIngestPhysmem);
        VOID(*pfnIngestVirtmem)(_In_ VMM_HANDLE H, _In_opt_ PVOID ctxfc, _In_ PVMMDLL_FORENSIC_INGEST_VIRTMEM pIngestVirtmem);
        VOID(*pfnIngestFinalize)(_In_ VMM_HANDLE H, _In_opt_ PVOID ctxfc);
        struct {
            PVMMDLL_FORENSIC_INGEST_PHYSMEM p;
        } IngestPhysmem;
        struct {
            CHAR sNameShort[6];
            CHAR _Reserved[2];
            CHAR szFileUTF8[32];
        } Timeline;
    } fc;
} PLUGIN_ENTRY, *PPLUGIN_ENTRY;

#define PLUGIN_TREE_MAX_CHILDITEMS      32

typedef struct tdPLUGIN_TREE {
    CHAR uszName[32];
    DWORD dwHashName;
    DWORD cChild;
    BOOL fVisible;
    struct tdPLUGIN_TREE *pParent;
    struct tdPLUGIN_TREE *Child[PLUGIN_TREE_MAX_CHILDITEMS];
    PPLUGIN_ENTRY pPlugin;
} PLUGIN_TREE, *PPLUGIN_TREE;

VOID PluginManager_Initialize_Python(_In_ VMM_HANDLE H);



// ----------------------------------------------------------------------------
// MODULES GENERAL FUNCTIONALITY - IMPLEMENTATION BELOW:
// ----------------------------------------------------------------------------

VOID PluginManager_SetTreeVisibility(_In_opt_ PPLUGIN_TREE pTree, _In_ BOOL fVisible)
{
    DWORD i;
    if(!pTree || (pTree->fVisible == fVisible)) { return; }
    for(i = 0; !fVisible && (i < pTree->cChild); i++) {
        fVisible = pTree->Child[i]->fVisible;
    }
    if(pTree->fVisible != fVisible) {
        pTree->fVisible = fVisible;
        if(fVisible || (pTree->pParent && !pTree->pParent->pPlugin)) {
            PluginManager_SetTreeVisibility(pTree->pParent, fVisible);
        }
    }
}

PPLUGIN_TREE PluginManager_Register_GetCreateTree(_In_ PPLUGIN_TREE pTree, _In_ LPCSTR uszPathName, _In_ BOOL fVisible)
{
    DWORD i, dwHash;
    CHAR uszEntry[32];
    PPLUGIN_TREE pChild;
    // 1: no more levels to create - return
    if(!uszPathName[0]) { return pTree; }
    // 2: check existing tree child entries
    uszPathName = CharUtil_PathSplitFirst(uszPathName, uszEntry, _countof(uszEntry));
    dwHash = CharUtil_HashNameFsU(uszEntry, 0);
    for(i = 0; i < pTree->cChild; i++) {
        if(pTree->Child[i]->dwHashName == dwHash) {
            return PluginManager_Register_GetCreateTree(pTree->Child[i], uszPathName, fVisible);
        }
    }
    // 3: create new entry
    if(pTree->cChild == PLUGIN_TREE_MAX_CHILDITEMS) { return NULL; }
    if(!(pTree->Child[pTree->cChild] = pChild = LocalAlloc(LMEM_ZEROINIT, sizeof(PLUGIN_TREE)))) { return NULL; }
    pTree->cChild++;
    strncpy_s(pChild->uszName, _countof(pChild->uszName), uszEntry, _TRUNCATE);
    pChild->dwHashName = dwHash;
    pChild->pParent = pTree;
    PluginManager_SetTreeVisibility(pChild, fVisible);
    return PluginManager_Register_GetCreateTree(pChild, uszPathName, fVisible);
}

/*
* Retrieve the PLUGIN_TREE entry and the remaining path given a root tree and a root path.
* -- pTree
* -- uszPath
* -- pTree
* -- pwszSubPath
*/
VOID PluginManager_GetTree(_In_ PPLUGIN_TREE pTree, _In_ LPCSTR uszPath, _Out_ PPLUGIN_TREE *ppTree, _Out_ LPSTR *puszSubPath)
{
    DWORD i, dwHash;
    CHAR uszEntry[32];
    LPCSTR uszSubPath;
    if(!uszPath[0]) { goto finish; }
    uszSubPath = CharUtil_PathSplitFirst(uszPath, uszEntry, _countof(uszEntry));
    dwHash = CharUtil_HashNameFsU(uszEntry, 0);
    for(i = 0; i < pTree->cChild; i++) {
        if(pTree->Child[i]->dwHashName == dwHash) {
            PluginManager_GetTree(pTree->Child[i], uszSubPath, ppTree, puszSubPath);
            return;
        }
    }
finish:
    *ppTree = pTree;
    *puszSubPath = (LPSTR)uszPath;
}

VOID PluginManager_SetVisibility(_In_ VMM_HANDLE H, _In_ BOOL fRoot, _In_ LPCSTR uszPluginPath, _In_ BOOL fVisible)
{
    LPSTR uszSubPath;
    PPLUGIN_TREE pTree;
    if(uszPluginPath[0] == '\\') { uszPluginPath++; }
    PluginManager_GetTree((fRoot ? H->vmm.PluginManager.Root : H->vmm.PluginManager.Proc), uszPluginPath, &pTree, &uszSubPath);
    PluginManager_SetTreeVisibility(pTree, fVisible);
}

BOOL PluginManager_ModuleExistsDll(_In_ VMM_HANDLE H, _In_opt_ HMODULE hDLL) {
    PPLUGIN_ENTRY pModule = (PPLUGIN_ENTRY)H->vmm.PluginManager.FLinkAll;
    while(pModule) {
        if(hDLL && (hDLL == pModule->hDLL)) { return TRUE; }
        pModule = pModule->FLinkAll;
    }
    return FALSE;
}

BOOL PluginManager_ModuleExists(_In_ PPLUGIN_TREE pTree, _In_ LPSTR uszPath) {
    LPSTR uszSubPath;
    PPLUGIN_TREE pTreePlugin;
    PluginManager_GetTree(pTree, uszPath, &pTreePlugin, &uszSubPath);
    return pTreePlugin->pPlugin && !uszSubPath[0];
}

VOID PluginManager_ContextInitialize(_Out_ PVMMDLL_PLUGIN_CONTEXT ctx, _In_ PPLUGIN_ENTRY pModule, _In_opt_ PVMM_PROCESS pProcess, _In_opt_ LPSTR uszPath)
{
    ctx->magic = VMMDLL_PLUGIN_CONTEXT_MAGIC;
    ctx->wVersion = VMMDLL_PLUGIN_CONTEXT_VERSION;
    ctx->wSize = sizeof(VMMDLL_PLUGIN_CONTEXT);
    ctx->dwPID = (pProcess ? pProcess->dwPID : (DWORD)-1);
    ctx->pProcess = pModule->hDLL ? NULL : pProcess;
    ctx->uszModule = pModule->uszName;
    ctx->uszPath = uszPath;
    ctx->ctxM = pModule->ctxM;
    ctx->MID = pModule->MID;
}

VOID PluginManager_List(_In_ VMM_HANDLE H, _In_opt_ PVMM_PROCESS pProcess, _In_ LPCSTR uszPath, _Inout_ PHANDLE pFileList)
{
    DWORD i;
    BOOL fVisibleProgrammatic, result = TRUE;
    QWORD tmStart = Statistics_CallStart(H);
    VMMDLL_PLUGIN_CONTEXT ctxPlugin;
    LPSTR uszSubPath;
    PPLUGIN_TREE pTree;
    PPLUGIN_ENTRY pPlugin;
    pTree = pProcess ? H->vmm.PluginManager.Proc : H->vmm.PluginManager.Root;
    if(!pTree) { return; }
    PluginManager_GetTree((pProcess ? H->vmm.PluginManager.Proc : H->vmm.PluginManager.Root), uszPath, &pTree, &uszSubPath);
    if(pTree->fVisible) {
        if(pTree->cChild && !uszSubPath[0]) {
            for(i = 0; i < pTree->cChild; i++) {
                if(pTree->Child[i]->fVisible) {
                    fVisibleProgrammatic = pTree->Child[i]->cChild || !pTree->Child[i]->pPlugin || !pTree->Child[i]->pPlugin->pfnVisibleModule;
                    if(!fVisibleProgrammatic) {
                        PluginManager_ContextInitialize(&ctxPlugin, pTree->Child[i]->pPlugin, pProcess, uszSubPath);
                        fVisibleProgrammatic = pTree->Child[i]->pPlugin->pfnVisibleModule(H, &ctxPlugin);
                    }
                    if(fVisibleProgrammatic) {
                        VMMDLL_VfsList_AddDirectory(pFileList, pTree->Child[i]->uszName, NULL);
                    }
                }
            }
        }
        if((pPlugin = pTree->pPlugin) && pPlugin->pfnList) {
            PluginManager_ContextInitialize(&ctxPlugin, pPlugin, pProcess, uszSubPath);
            if(!pPlugin->pfnVisibleModule || pPlugin->pfnVisibleModule(H, &ctxPlugin)) {
                pTree->pPlugin->pfnList(H, &ctxPlugin, pFileList);
            }
        }
    }
    Statistics_CallEnd(H, STATISTICS_ID_PluginManager_List, tmStart);
}

NTSTATUS PluginManager_Read(_In_ VMM_HANDLE H, _In_opt_ PVMM_PROCESS pProcess, _In_ LPCSTR uszPath, _Out_writes_to_(cb, *pcbRead) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset)
{
    QWORD tmStart = Statistics_CallStart(H);
    NTSTATUS nt;
    VMMDLL_PLUGIN_CONTEXT ctxPlugin;
    LPSTR uszSubPath;
    PPLUGIN_TREE pTree;
    PPLUGIN_ENTRY pPlugin;
    pTree = pProcess ? H->vmm.PluginManager.Proc : H->vmm.PluginManager.Root;
    if(!pTree) { return VMMDLL_STATUS_FILE_INVALID; }
    PluginManager_GetTree((pProcess ? H->vmm.PluginManager.Proc : H->vmm.PluginManager.Root), uszPath, &pTree, &uszSubPath);
    if(pTree->fVisible) {
        if((pPlugin = pTree->pPlugin) && pPlugin->pfnRead) {
            PluginManager_ContextInitialize(&ctxPlugin, pPlugin, pProcess, uszSubPath);
            nt = pPlugin->pfnRead(H, &ctxPlugin, pb, cb, pcbRead, cbOffset);
            Statistics_CallEnd(H, STATISTICS_ID_PluginManager_Read, tmStart);
            return nt;
        }
    }
    Statistics_CallEnd(H, STATISTICS_ID_PluginManager_Read, tmStart);
    return VMMDLL_STATUS_FILE_INVALID;
}

NTSTATUS PluginManager_Write(_In_ VMM_HANDLE H, _In_opt_ PVMM_PROCESS pProcess, _In_ LPCSTR uszPath, _In_reads_(cb) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbWrite, _In_ QWORD cbOffset)
{
    QWORD tmStart = Statistics_CallStart(H);
    NTSTATUS nt;
    VMMDLL_PLUGIN_CONTEXT ctxPlugin;
    LPSTR uszSubPath;
    PPLUGIN_TREE pTree;
    PPLUGIN_ENTRY pPlugin;
    pTree = pProcess ? H->vmm.PluginManager.Proc : H->vmm.PluginManager.Root;
    if(!pTree) { return VMMDLL_STATUS_FILE_INVALID; }
    PluginManager_GetTree((pProcess ? H->vmm.PluginManager.Proc : H->vmm.PluginManager.Root), uszPath, &pTree, &uszSubPath);
    if(pTree->fVisible) {
        if((pPlugin = pTree->pPlugin) && pPlugin->pfnWrite) {
            PluginManager_ContextInitialize(&ctxPlugin, pPlugin, pProcess, uszSubPath);
            nt = pPlugin->pfnWrite(H, &ctxPlugin, pb, cb, pcbWrite, cbOffset);
            Statistics_CallEnd(H, STATISTICS_ID_PluginManager_Write, tmStart);
            return nt;
        }
    }
    Statistics_CallEnd(H, STATISTICS_ID_PluginManager_Write, tmStart);
    return VMMDLL_STATUS_FILE_INVALID;
}

BOOL PluginManager_Notify(_In_ VMM_HANDLE H, _In_ DWORD fEvent, _In_opt_ PVOID pvEvent, _In_opt_ DWORD cbEvent)
{
    VMMDLL_PLUGIN_CONTEXT ctxPlugin;
    QWORD tmStart = Statistics_CallStart(H);
    PPLUGIN_ENTRY pPlugin = (PPLUGIN_ENTRY)H->vmm.PluginManager.FLinkNotify;
    while(pPlugin) {
        if(pPlugin->pfnNotify) {
            PluginManager_ContextInitialize(&ctxPlugin, pPlugin, NULL, NULL);
            pPlugin->pfnNotify(H, &ctxPlugin, fEvent, pvEvent, cbEvent);
        }
        pPlugin = pPlugin->FLinkNotify;
    }
    Statistics_CallEnd(H, STATISTICS_ID_PluginManager_Notify, tmStart);
    return TRUE;
}

VOID PluginManager_FcInitialize_ThreadProc(_In_ VMM_HANDLE H, _In_ PPLUGIN_ENTRY pPlugin)
{
    VMMDLL_PLUGIN_CONTEXT ctxPlugin;
    if(!H->fAbort && pPlugin->fc.pfnInitialize) {
        PluginManager_ContextInitialize(&ctxPlugin, pPlugin, NULL, NULL);
        pPlugin->fc.ctxfc = pPlugin->fc.pfnInitialize(H, &ctxPlugin);
    }
}

/*
* Initialize plugins with forensic mode capabilities.
* -- H
*/
VOID PluginManager_FcInitialize(_In_ VMM_HANDLE H)
{
    DWORD cWork = 0;
    QWORD tmStart = Statistics_CallStart(H);
    PPLUGIN_ENTRY pPlugin = (PPLUGIN_ENTRY)H->vmm.PluginManager.FLinkForensic;
    PVMM_WORK_START_ROUTINE_PVOID_PFN pfns[MAXIMUM_WAIT_OBJECTS];
    PVOID ctxs[MAXIMUM_WAIT_OBJECTS];
    if(H->fAbort) { return; }
    while(pPlugin) {
        if(pPlugin->fc.pfnInitialize) {
            pfns[cWork] = (PVMM_WORK_START_ROUTINE_PVOID_PFN)PluginManager_FcInitialize_ThreadProc;
            ctxs[cWork] = pPlugin;
            cWork++;
            if(cWork == MAXIMUM_WAIT_OBJECTS) {
                VmmLog(H, MID_PLUGIN, LOGLEVEL_2_WARNING, "FcInitialize max plugins reached. Some plugins may not be run.");
                break;
            }
        }
        pPlugin = pPlugin->FLinkForensic;
    }
    if(H->fAbort) { return; }
    VmmWorkWaitMultiple2_Void(H, cWork, pfns, ctxs);
    Statistics_CallEnd(H, STATISTICS_ID_PluginManager_FcInitialize, tmStart);
}

/*
* Finalize plugins with forensic mode capabilities.
* -- H
*/
VOID PluginManager_FcFinalize(_In_ VMM_HANDLE H)
{
    QWORD tmStart = Statistics_CallStart(H);
    PPLUGIN_ENTRY pModule = (PPLUGIN_ENTRY)H->vmm.PluginManager.FLinkForensic;
    while(pModule) {
        if(pModule->fc.pfnFinalize) {
            pModule->fc.pfnFinalize(H, pModule->fc.ctxfc);
            pModule->fc.pfnFinalize = NULL;
            pModule->fc.ctxfc = NULL;
        }
        pModule = pModule->FLinkForensic;
    }
    Statistics_CallEnd(H, STATISTICS_ID_PluginManager_FcFinalize, tmStart);
}

/*
* Worker thread entry point:
* Ingest physical memory into plugins with forensic mode capabilities.
* -- H
* -- ctx
*/
VOID PluginManager_FcIngestPhysmem_ThreadProc(_In_ VMM_HANDLE H, _In_ PVOID ctx)
{
    PPLUGIN_ENTRY pModule = ctx;
    if(H->fAbort) { return; }
    pModule->fc.pfnIngestPhysmem(H, pModule->fc.ctxfc, pModule->fc.IngestPhysmem.p);
}

/*
* Ingest physical memory into plugins with forensic mode capabilities.
* -- H
* -- pIngestPhysmem
*/
VOID PluginManager_FcIngestPhysmem(_In_ VMM_HANDLE H, _In_ PVMMDLL_FORENSIC_INGEST_PHYSMEM pIngestPhysmem)
{
    DWORD cWork = 0;
    PVOID ctxs[MAXIMUM_WAIT_OBJECTS];
    PVMM_WORK_START_ROUTINE_PVOID_PFN pfns[MAXIMUM_WAIT_OBJECTS];
    QWORD tmStart = Statistics_CallStart(H);
    PPLUGIN_ENTRY pModule = (PPLUGIN_ENTRY)H->vmm.PluginManager.FLinkForensic;
    while(pModule) {
        if(pModule->fc.pfnIngestPhysmem) {
            pModule->fc.IngestPhysmem.p = pIngestPhysmem;
            ctxs[cWork] = pModule;
            pfns[cWork] = PluginManager_FcIngestPhysmem_ThreadProc;
            cWork++;
            if(cWork >= MAXIMUM_WAIT_OBJECTS) { return; }
        }
        pModule = pModule->FLinkForensic;
    }
    VmmWorkWaitMultiple2_Void(H, cWork, pfns, ctxs);
    Statistics_CallEnd(H, STATISTICS_ID_PluginManager_FcIngestPhysmem, tmStart);
}

/*
* Ingest virtual memory into plugins with forensic mode capabilities.
* -- H
* -- pIngestVirtmem
*/
VOID PluginManager_FcIngestVirtmem(_In_ VMM_HANDLE H, _In_ PVMMDLL_FORENSIC_INGEST_VIRTMEM pIngestVirtmem)
{
    QWORD tmStart = Statistics_CallStart(H);
    PPLUGIN_ENTRY pModule = (PPLUGIN_ENTRY)H->vmm.PluginManager.FLinkForensic;
    while(pModule) {
        if(pModule->fc.pfnIngestVirtmem) {
            pModule->fc.pfnIngestVirtmem(H, pModule->fc.ctxfc, pIngestVirtmem);
        }
        pModule = pModule->FLinkForensic;
    }
    Statistics_CallEnd(H, STATISTICS_ID_PluginManager_FcIngestVirtmem, tmStart);
}

/*
* Ingest an object into plugins with forensic mode capabilities.
* -- H
* -- pIngestVirtmem
*/
VOID PluginManager_FcIngestObject(_In_ VMM_HANDLE H, _In_ PVMMDLL_FORENSIC_INGEST_OBJECT pIngestObject)
{
    QWORD tmStart = Statistics_CallStart(H);
    PPLUGIN_ENTRY pModule = (PPLUGIN_ENTRY)H->vmm.PluginManager.FLinkForensic;
    while(pModule) {
        if(pModule->fc.pfnIngestObject) {
            pModule->fc.pfnIngestObject(H, pModule->fc.ctxfc, pIngestObject);
        }
        pModule = pModule->FLinkForensic;
    }
    Statistics_CallEnd(H, STATISTICS_ID_PluginManager_FcIngestObject, tmStart);
}

/*
* All ingestion actions are completed.
* -- H
*/
VOID PluginManager_FcIngestFinalize(_In_ VMM_HANDLE H)
{
    QWORD tmStart = Statistics_CallStart(H);
    PPLUGIN_ENTRY pModule = (PPLUGIN_ENTRY)H->vmm.PluginManager.FLinkForensic;
    while(pModule) {
        if(pModule->fc.pfnIngestFinalize) {
            pModule->fc.pfnIngestFinalize(H, pModule->fc.ctxfc);
        }
        pModule = pModule->FLinkForensic;
    }
    Statistics_CallEnd(H, STATISTICS_ID_PluginManager_FcIngestFinalize, tmStart);
}

/*
* Register plugins with timelining capabilities with the timeline manager
* and call into each plugin to allow them to add their timelining entries.
* NB! This function is meant to be called by the core forensic subsystem only.
* -- H
* -- pfnRegister = callback function to register timeline module.
* -- pfnClose = function to close the timeline handle.
* -- pfnAddEntry = callback function to call to add a timelining entry.
* -- pfnEntryAddBySql = callback function to add timelining entries by sqlite query.
*/
VOID PluginManager_FcTimeline(
    _In_ VMM_HANDLE H,
    _In_ HANDLE(*pfnRegister)(_In_ VMM_HANDLE H, _In_reads_(6) LPCSTR sNameShort, _In_reads_(32) LPCSTR szFileUTF8),
    _In_ VOID(*pfnClose)(_In_ VMM_HANDLE H, _In_ HANDLE hTimeline),
    _In_ VOID(*pfnAddEntry)(_In_ VMM_HANDLE H, _In_ HANDLE hTimeline, _In_ QWORD ft, _In_ DWORD dwAction, _In_ DWORD dwPID, _In_ DWORD dwData32, _In_ QWORD qwData64, _In_ LPCSTR uszText),
    _In_ VOID(*pfnEntryAddBySql)(_In_ VMM_HANDLE H, _In_ HANDLE hTimeline, _In_ DWORD cEntrySql, _In_ LPCSTR *pszEntrySql)
) {
    HANDLE hTimeline;
    QWORD tmStart = Statistics_CallStart(H);
    PPLUGIN_ENTRY pModule = (PPLUGIN_ENTRY)H->vmm.PluginManager.FLinkForensic;
    while(pModule) {
        if(pModule->fc.pfnTimeline) {
            hTimeline = pfnRegister(H, pModule->fc.Timeline.sNameShort, pModule->fc.Timeline.szFileUTF8);
            if(hTimeline) {
                pModule->fc.pfnTimeline(H, pModule->fc.ctxfc, hTimeline, pfnAddEntry, pfnEntryAddBySql);
                pfnClose(H, hTimeline);
                hTimeline = NULL;
            }
        }
        pModule = pModule->FLinkForensic;
    }
    Statistics_CallEnd(H, STATISTICS_ID_PluginManager_FcTimeline, tmStart);
}

/*
* Call each plugin capable of forensic csv log. Plugins may be process or global.
* NB! This function is meant to be called by the core forensic subsystem only.
* -- H
* -- hCSV
* -- return = 0 (to make function compatible with LPTHREAD_START_ROUTINE).
*/
DWORD PluginManager_FcLogCSV(_In_ VMM_HANDLE H, _In_ VMMDLL_CSV_HANDLE hCSV)
{
    VMMDLL_PLUGIN_CONTEXT ctxPlugin;
    QWORD tmStart = Statistics_CallStart(H);
    PPLUGIN_ENTRY pPlugin = (PPLUGIN_ENTRY)H->vmm.PluginManager.FLinkForensic;
    PVMM_PROCESS pObProcess = NULL;
    while(pPlugin && !H->fAbort) {
        if(pPlugin->fc.pfnLogCSV) {
            // global plugins:
            PluginManager_ContextInitialize(&ctxPlugin, pPlugin, NULL, NULL);
            pPlugin->fc.pfnLogCSV(H, &ctxPlugin, hCSV);
            // per-process plugins:
            while((pObProcess = VmmProcessGetNext(H, pObProcess, VMM_FLAG_PROCESS_SHOW_TERMINATED | VMM_FLAG_PROCESS_TOKEN))) {
                PluginManager_ContextInitialize(&ctxPlugin, pPlugin, pObProcess, NULL);
                FcCsv_Reset(hCSV);
                pPlugin->fc.pfnLogCSV(H, &ctxPlugin, hCSV);
            }
        }
        pPlugin = pPlugin->FLinkForensic;
    }
    Statistics_CallEnd(H, STATISTICS_ID_PluginManager_FcLogCSV, tmStart);
    return 0;
}

/*
* Call each plugin capable of forensic json log. Plugins may be process or global.
* NB! This function is meant to be called by the core forensic subsystem only.
* -- H
* -- pfnAddEntry = callback function to call to add a json entry.
* -- return = 0 (to make function compatible with LPTHREAD_START_ROUTINE).
*/
DWORD PluginManager_FcLogJSON(_In_ VMM_HANDLE H, _In_ VOID(*pfnLogJSON)(_In_ VMM_HANDLE H, _In_ PVMMDLL_FORENSIC_JSONDATA pData))
{
    VMMDLL_PLUGIN_CONTEXT ctxPlugin;
    QWORD tmStart = Statistics_CallStart(H);
    PPLUGIN_ENTRY pPlugin = (PPLUGIN_ENTRY)H->vmm.PluginManager.FLinkForensic;
    PVMM_PROCESS pObProcess = NULL;
    while(pPlugin && !H->fAbort) {
        if(pPlugin->fc.pfnLogJSON) {
            // global plugins:
            PluginManager_ContextInitialize(&ctxPlugin, pPlugin, NULL, NULL);
            pPlugin->fc.pfnLogJSON(H, &ctxPlugin, pfnLogJSON);
            // per-process plugins:
            while((pObProcess = VmmProcessGetNext(H, pObProcess, VMM_FLAG_PROCESS_SHOW_TERMINATED | VMM_FLAG_PROCESS_TOKEN))) {
                PluginManager_ContextInitialize(&ctxPlugin, pPlugin, pObProcess, NULL);
                pPlugin->fc.pfnLogJSON(H, &ctxPlugin, pfnLogJSON);
            }
        }
        pPlugin = pPlugin->FLinkForensic;
    }
    Statistics_CallEnd(H, STATISTICS_ID_PluginManager_FcLogJSON, tmStart);
    return 0;
}

VOID PluginManager_FcFindEvil_ThreadProc(_In_ VMM_HANDLE H, _In_ PPLUGIN_ENTRY pPlugin)
{
    if(!H->fAbort && pPlugin->fc.pfnFindEvil) {
        pPlugin->fc.pfnFindEvil(H, pPlugin->MID, pPlugin->fc.ctxfc);
    }
}

/*
* Call each plugin capable of FindEvil functionality.
* NB! This function is meant to be called by the core forensic subsystem only.
* -- H
*/
VOID PluginManager_FcFindEvil(_In_ VMM_HANDLE H)
{
    DWORD cWork = 0;
    QWORD tmStart = Statistics_CallStart(H);
    PPLUGIN_ENTRY pPlugin = (PPLUGIN_ENTRY)H->vmm.PluginManager.FLinkForensic;
    PVMM_WORK_START_ROUTINE_PVOID_PFN pfns[MAXIMUM_WAIT_OBJECTS];
    PVOID ctxs[MAXIMUM_WAIT_OBJECTS];
    if(H->fAbort) { return; }
    while(pPlugin) {
        if(pPlugin->fc.pfnFindEvil) {
            pfns[cWork] = (PVMM_WORK_START_ROUTINE_PVOID_PFN)PluginManager_FcFindEvil_ThreadProc;
            ctxs[cWork] = pPlugin;
            cWork++;
            if(cWork == MAXIMUM_WAIT_OBJECTS) {
                VmmLog(H, MID_PLUGIN, LOGLEVEL_2_WARNING, "FindEvil max plugins reached. Some plugins may not be run.");
                break;
            }
        }
        pPlugin = pPlugin->FLinkForensic;
    }
    if(H->fAbort) { return; }
    VmmWorkWaitMultiple2_Void(H, cWork, pfns, ctxs);
    Statistics_CallEnd(H, STATISTICS_ID_PluginManager_FcFindEvil, tmStart);
}

/*
* Execute python code in the python plugin sub-system and retrieve its result.
* -- CALLER LocalFree: *puszResultOfExec
* -- H
* -- uszPythonCodeToExec
* -- puszResultOfExec
* -- return
*/
_Success_(return)
BOOL PluginManager_PythonExecCode(_In_ VMM_HANDLE H, _In_ LPSTR uszPythonCodeToExec, _Out_ LPSTR *puszResultOfExec)
{
    BOOL fResult = FALSE;
    LPSTR uszSubPath;
    PPLUGIN_TREE pTree = NULL;
    BOOL(*pfnPY2C_Exec)(VMM_HANDLE, LPSTR, LPSTR*);
    *puszResultOfExec = NULL;
    if(PluginManager_Initialize(H)) {
        PluginManager_GetTree(H->vmm.PluginManager.Root, "py", &pTree, &uszSubPath);
    }
    if(pTree && pTree->pPlugin && pTree->pPlugin->hDLL) {
        if((pfnPY2C_Exec = (BOOL(*)(VMM_HANDLE, LPSTR, LPSTR*))GetProcAddress(pTree->pPlugin->hDLL, "PY2C_Exec"))) {
            // wait for forensic mode to complete (if enabled and not completed already)
            if(H->fc && H->fc->fInitStart) {
                VmmLog(H, MID_PYTHON, LOGLEVEL_4_VERBOSE, "Python Code Execute: Wait for forensic mode to finish.")
                while(!H->fAbort && !H->fc->fInitFinish) {
                    Sleep(100);
                }
                VmmLog(H, MID_PYTHON, LOGLEVEL_4_VERBOSE, "Python Code Execute: Wait for forensic mode completed.")
            }
            // dispatch to python plugin to execute python code in vmm context.
            if(!H->fAbort) {
                fResult = pfnPY2C_Exec(H, uszPythonCodeToExec, puszResultOfExec);
                if(!fResult) {
                    VmmLog(H, MID_PYTHON, LOGLEVEL_1_CRITICAL, "Python Code Execute: Fail executing code.");
                }
            }
        }
    } else {
        VmmLog(H, MID_PYTHON, LOGLEVEL_1_CRITICAL, "Python Code Execute: Fail - Unable to load Python plugin.");
    }
    return fResult;
}

/*
* Execute python code in the python plugin sub-system and print it's result on-screen.
* -- H
* -- szPythonFileToExec
*/
VOID PluginManager_PythonExecFile(_In_ VMM_HANDLE H, _In_ LPCSTR szPythonFileToExec)
{
    BOOL f;
    FILE *hFile = NULL;
    DWORD cbPythonProgram;
    LPSTR uszResultOfExec = NULL;
    PBYTE pbPythonProgram = NULL;
    f = (pbPythonProgram = LocalAlloc(LMEM_ZEROINIT, 0x01000000)) &&
        !fopen_s(&hFile, H->cfg.szPythonExecuteFile, "rb") && hFile &&
        (cbPythonProgram = (DWORD)fread(pbPythonProgram, 1, 0x01000000, hFile)) && (cbPythonProgram < 0x01000000);
    if(f) {
        if(PluginManager_PythonExecCode(H, (LPSTR)pbPythonProgram, &uszResultOfExec) && uszResultOfExec) {
            vmmprintf(H, "%s", uszResultOfExec);
        }
    } else {
        VmmLog(H, MID_PYTHON, LOGLEVEL_1_CRITICAL, "Python Code Execute: Unable to read file: '%s'", H->cfg.szPythonExecuteFile);
    }
    LocalFree(uszResultOfExec);
    LocalFree(pbPythonProgram);
    if(hFile) { fclose(hFile); }
}



// ----------------------------------------------------------------------------
// MODULES REGISTRATION/CLEANUP FUNCTIONALITY - IMPLEMENTATION BELOW:
// ----------------------------------------------------------------------------

BOOL PluginManager_Register(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_REGINFO pRegInfo)
{
    DWORD iPluginNameStart;
    LPCSTR uszPluginName, uszLogName;
    PPLUGIN_ENTRY pModule;
    PPLUGIN_TREE pPluginTreeEntry;
    // 1: tests if plugin is valid
    pRegInfo->reg_info.uszPathName[127] = 0;
    if(!pRegInfo || (pRegInfo->magic != VMMDLL_PLUGIN_REGINFO_MAGIC) || (pRegInfo->wVersion > VMMDLL_PLUGIN_REGINFO_VERSION)) {
        VmmLog(H, MID_PLUGIN, LOGLEVEL_WARNING, "LOAD_FAIL: invalid plugin magic/version va=%p", pRegInfo);
        return FALSE;
    }
    if(!pRegInfo->reg_info.uszPathName[0]) {
        VmmLog(H, MID_PLUGIN, LOGLEVEL_WARNING, "LOAD_FAIL: missing plugin path/name");
        return FALSE;
    }
    uszPluginName = CharUtil_PathSplitLast(pRegInfo->reg_info.uszPathName);
    if(strlen(uszPluginName) > 31) { return FALSE; }
    if(pRegInfo->reg_info.fRootModule && PluginManager_ModuleExists(H->vmm.PluginManager.Root, pRegInfo->reg_info.uszPathName)) {
        VmmLog(H, MID_PLUGIN, LOGLEVEL_WARNING, "LOAD_FAIL: root plugin '%s' already exists", uszPluginName);
        return FALSE;
    }
    if(pRegInfo->reg_info.fProcessModule && PluginManager_ModuleExists(H->vmm.PluginManager.Proc, pRegInfo->reg_info.uszPathName)) {
        VmmLog(H, MID_PLUGIN, LOGLEVEL_WARNING, "LOAD_FAIL: process plugin '%s' already exists", uszPluginName);
        return FALSE;
    }
    if(!pRegInfo->reg_info.fRootModule && !pRegInfo->reg_info.fProcessModule) {
        VmmLog(H, MID_PLUGIN, LOGLEVEL_WARNING, "LOAD_FAIL: plugin '%s' is neither root/process type", uszPluginName);
        return FALSE;
    }
    if(!pRegInfo->reg_fnfc.pfnIngestPhysmem && (H->vmm.PluginManager.cIngestPhysmem >= MAXIMUM_WAIT_OBJECTS)) {
        VmmLog(H, MID_PLUGIN, LOGLEVEL_WARNING, "LOAD_FAIL: plugin '%s' would exceed max # IngestPhysmem modules (%i)", uszPluginName, MAXIMUM_WAIT_OBJECTS);
        return FALSE;
    }
    if(!pRegInfo->reg_fnfc.pfnIngestVirtmem && (H->vmm.PluginManager.cIngestVirtmem >= MAXIMUM_WAIT_OBJECTS)) {
        VmmLog(H, MID_PLUGIN, LOGLEVEL_WARNING, "LOAD_FAIL: plugin '%s' would exceed max # Ingestvirtmem modules (%i)", uszPluginName, MAXIMUM_WAIT_OBJECTS);
        return FALSE;
    }
    // 2: register plugin
    pModule = (PPLUGIN_ENTRY)LocalAlloc(LMEM_ZEROINIT, sizeof(PLUGIN_ENTRY));
    if(!pModule) { return FALSE; }
    pModule->hDLL = pRegInfo->hDLL;
    pModule->MID = InterlockedIncrement(&H->vmm.PluginManager.NextMID);
    strncpy_s(pModule->uszName, 32, uszPluginName, _TRUNCATE);
    pModule->dwNameHash = CharUtil_HashNameFsU(pModule->uszName, TRUE);
    pModule->fRootModule = pRegInfo->reg_info.fRootModule;
    pModule->fProcessModule = pRegInfo->reg_info.fProcessModule;
    pModule->ctxM = pRegInfo->reg_info.ctxM;
    pModule->pfnList = pRegInfo->reg_fn.pfnList;
    pModule->pfnRead = pRegInfo->reg_fn.pfnRead;
    pModule->pfnWrite = pRegInfo->reg_fn.pfnWrite;
    pModule->pfnNotify = pRegInfo->reg_fn.pfnNotify;
    pModule->pfnClose = pRegInfo->reg_fn.pfnClose;
    pModule->pfnVisibleModule = pRegInfo->reg_fn.pfnVisibleModule;
    // 3: register plugin (forensic functionality)
    pModule->fc.pfnInitialize = pRegInfo->reg_fnfc.pfnInitialize;
    pModule->fc.pfnFinalize = pRegInfo->reg_fnfc.pfnFinalize;
    pModule->fc.pfnTimeline = pRegInfo->reg_fnfc.pfnTimeline;
    pModule->fc.pfnLogCSV = pRegInfo->reg_fnfc.pfnLogCSV;
    pModule->fc.pfnLogJSON = pRegInfo->reg_fnfc.pfnLogJSON;
    pModule->fc.pfnFindEvil = pRegInfo->reg_fnfc.pfnFindEvil;
    pModule->fc.pfnIngestObject = pRegInfo->reg_fnfc.pfnIngestObject;
    pModule->fc.pfnIngestPhysmem = pRegInfo->reg_fnfc.pfnIngestPhysmem;
    pModule->fc.pfnIngestVirtmem = pRegInfo->reg_fnfc.pfnIngestVirtmem;
    pModule->fc.pfnIngestFinalize = pRegInfo->reg_fnfc.pfnIngestFinalize;
    memcpy(pModule->fc.Timeline.sNameShort, pRegInfo->reg_info.sTimelineNameShort, _countof(pModule->fc.Timeline.sNameShort));
    memcpy(pModule->fc.Timeline.szFileUTF8, pRegInfo->reg_info.uszTimelineFile, _countof(pModule->fc.Timeline.szFileUTF8));
    VmmLog(H, MID_PLUGIN, LOGLEVEL_VERBOSE, "LOAD: %s module: '%s'", (pModule->hDLL ? " native " : "built-in"), pRegInfo->reg_info.uszPathName);
    if(pModule->pfnNotify) {
        pModule->FLinkNotify = (PPLUGIN_ENTRY)H->vmm.PluginManager.FLinkNotify;
        H->vmm.PluginManager.FLinkNotify = pModule;
    }
    if(pModule->fc.pfnInitialize || pModule->fc.pfnFinalize || pModule->fc.pfnTimeline || pModule->fc.pfnLogCSV || pModule->fc.pfnLogJSON || pModule->fc.pfnFindEvil || pModule->fc.pfnIngestObject || pModule->fc.pfnIngestPhysmem || pModule->fc.pfnIngestVirtmem || pModule->fc.pfnIngestFinalize) {
        if(pModule->fc.pfnIngestPhysmem) { H->vmm.PluginManager.cIngestPhysmem++; }
        if(pModule->fc.pfnIngestVirtmem) { H->vmm.PluginManager.cIngestVirtmem++; }
        pModule->FLinkForensic = (PPLUGIN_ENTRY)H->vmm.PluginManager.FLinkForensic;
        H->vmm.PluginManager.FLinkForensic = pModule;
    }
    pModule->FLinkAll = (PPLUGIN_ENTRY)H->vmm.PluginManager.FLinkAll;
    H->vmm.PluginManager.FLinkAll = pModule;
    // 3: register plugin in plugin tree
    iPluginNameStart = (pRegInfo->reg_info.uszPathName[0] == '\\') ? 1 : 0;
    if(pModule->fRootModule) {
        pPluginTreeEntry = PluginManager_Register_GetCreateTree(H->vmm.PluginManager.Root, pRegInfo->reg_info.uszPathName + iPluginNameStart, !pRegInfo->reg_info.fRootModuleHidden);
        if(pPluginTreeEntry && !pPluginTreeEntry->pPlugin) {
            pPluginTreeEntry->pPlugin = pModule;
        }
    }
    if(pModule->fProcessModule) {
        pPluginTreeEntry = PluginManager_Register_GetCreateTree(H->vmm.PluginManager.Proc, pRegInfo->reg_info.uszPathName + iPluginNameStart, !pRegInfo->reg_info.fProcessModuleHidden);
        if(pPluginTreeEntry && !pPluginTreeEntry->pPlugin) {
            pPluginTreeEntry->pPlugin = pModule;
        }
    }
    // 4: register module id with logging sub-system
    if(pModule->MID > 2) {
        uszLogName = pModule->uszName;
    } else if(pModule->MID == 2) {
        uszLogName = "process";
    } else {
        uszLogName = "root";
    }
    VmmLog_RegisterModule(H, pModule->MID, uszLogName, (pModule->hDLL ? TRUE : FALSE));
    return TRUE;
}

VOID PluginManager_Close_Tree(_In_ PPLUGIN_TREE pTree)
{
    DWORD i;
    if(!pTree) { return; }
    for(i = 0; i < pTree->cChild; i++) {
        PluginManager_Close_Tree(pTree->Child[i]);
    }
    LocalFree(pTree);
}

VOID PluginManager_Close(_In_ VMM_HANDLE H)
{
    PPLUGIN_ENTRY pPlugin;
    VMMDLL_PLUGIN_CONTEXT ctxPlugin;
    PPLUGIN_TREE pTreeRoot = H->vmm.PluginManager.Root, pTreeProc = H->vmm.PluginManager.Proc;
    H->vmm.PluginManager.Root = NULL;
    H->vmm.PluginManager.Proc = NULL;
    PluginManager_Close_Tree(pTreeRoot);
    PluginManager_Close_Tree(pTreeProc);
    H->vmm.PluginManager.FLinkNotify = NULL;
    while((pPlugin = (PPLUGIN_ENTRY)H->vmm.PluginManager.FLinkAll)) {
        // 1: Detach current module list entry from list
        H->vmm.PluginManager.FLinkAll = pPlugin->FLinkAll;
        // 2: Close module callback
        if(pPlugin->pfnClose) {
            PluginManager_ContextInitialize(&ctxPlugin, pPlugin, NULL, NULL);
            pPlugin->pfnClose(H, &ctxPlugin);
        }
        // 3: FreeLibrary (if last module belonging to specific Library)
        if(pPlugin->hDLL && !PluginManager_ModuleExistsDll(H, pPlugin->hDLL)) { FreeLibrary(pPlugin->hDLL); }
        // 4: LocalFree this ListEntry
        LocalFree(pPlugin);
    }
}

VOID PluginManager_Initialize_RegInfoInit(_In_ VMM_HANDLE H, _Out_ PVMMDLL_PLUGIN_REGINFO pRI, _In_opt_ HMODULE hDLL)
{
    ZeroMemory(pRI, sizeof(VMMDLL_PLUGIN_REGINFO));
    pRI->magic = VMMDLL_PLUGIN_REGINFO_MAGIC;
    pRI->wVersion = VMMDLL_PLUGIN_REGINFO_VERSION;
    pRI->wSize = sizeof(VMMDLL_PLUGIN_REGINFO);
    pRI->hDLL = hDLL;
    pRI->uszPathVmmDLL = H->cfg.szPathLibraryVmm;
    pRI->tpMemoryModel = (VMMDLL_MEMORYMODEL_TP)H->vmm.tpMemoryModel;
    pRI->tpSystem = (VMMDLL_SYSTEM_TP)H->vmm.tpSystem;
    pRI->pfnPluginManager_Register = PluginManager_Register;
    pRI->sysinfo.f32 = H->vmm.f32;
    pRI->sysinfo.dwVersionMajor = H->vmm.kernel.dwVersionMajor;
    pRI->sysinfo.dwVersionMinor = H->vmm.kernel.dwVersionMinor;
    pRI->sysinfo.dwVersionBuild = H->vmm.kernel.dwVersionBuild;
}

#ifdef _WIN32
VOID PluginManager_Initialize_Python(_In_ VMM_HANDLE H)
{
    LPSTR szPYTHON_VERSIONS_SUPPORTED[] = {
        "python315.dll",
        "python314.dll",
        "python313.dll",
        "python312.dll",
        "python311.dll",
        "python310.dll",
        "python39.dll",
        "python38.dll",
        "python37.dll",
        "python36.dll"
    };
    DWORD cszPYTHON_VERSIONS_SUPPORTED = (sizeof(szPYTHON_VERSIONS_SUPPORTED) / sizeof(LPSTR));
    DWORD i;
    BOOL fBitnessFail = FALSE, fPythonStandalone = FALSE;
    VMMDLL_PLUGIN_REGINFO ri;
    CHAR szPythonPath[MAX_PATH];
    HMODULE hDllPython3X = NULL, hDllPython3 = NULL, hDllPyPlugin = NULL;
    VOID(*pfnInitializeVmmPlugin)(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_REGINFO pRegInfo);
    // 0: Verify that Python should be enabled
    if(H->cfg.fDisablePython) { return; }
    // 1: Locate Python by trying user-defined path
    if(H->cfg.szPythonPath[0]) {
        for(i = 0; i < cszPYTHON_VERSIONS_SUPPORTED; i++) {
            ZeroMemory(szPythonPath, MAX_PATH);
            strcpy_s(szPythonPath, MAX_PATH, H->cfg.szPythonPath);
            strcat_s(szPythonPath, MAX_PATH, "\\");
            strcat_s(szPythonPath, MAX_PATH, szPYTHON_VERSIONS_SUPPORTED[i]);
            hDllPython3X = LoadLibraryExA(szPythonPath, 0, LOAD_WITH_ALTERED_SEARCH_PATH);
            if(hDllPython3X) { break; }
            fBitnessFail = fBitnessFail || (ERROR_BAD_EXE_FORMAT == GetLastError());
        }
        if(!hDllPython3X) {
            ZeroMemory(H->cfg.szPythonPath, MAX_PATH);
            VmmLog(H, MID_PLUGIN, LOGLEVEL_INFO,
                fBitnessFail ?
                "Python initialization failed. Unable to load 32-bit Python. 64-bit required." :
                "Python initialization failed. Python 3.6 or later not found on user specified path."
            );
            return;
        }
    }
    // 2: If Python is already loaded - use it!
    if(0 == H->cfg.szPythonPath[0]) {
        for(i = 0; i < cszPYTHON_VERSIONS_SUPPORTED; i++) {
            if((hDllPython3X = GetModuleHandleA(szPYTHON_VERSIONS_SUPPORTED[i]))) {
                GetModuleFileNameA(hDllPython3X, szPythonPath, MAX_PATH);
                hDllPython3X = LoadLibraryU(szPythonPath);
                if(hDllPython3X) {
                    Util_GetPathDll(H->cfg.szPythonPath, hDllPython3X);
                    fPythonStandalone = TRUE;
                    break;
                }
            }
        }
    }
    // 3: Try locate Python by checking the python36 sub-directory relative to the current library (vmm.dll).
    if(0 == H->cfg.szPythonPath[0]) {
        for(i = 0; i < cszPYTHON_VERSIONS_SUPPORTED; i++) {
            ZeroMemory(szPythonPath, MAX_PATH);
            Util_GetPathLib(szPythonPath);
            strcat_s(szPythonPath, MAX_PATH, "python\\");
            strcat_s(szPythonPath, MAX_PATH, szPYTHON_VERSIONS_SUPPORTED[i]);
            hDllPython3X = LoadLibraryExA(szPythonPath, 0, LOAD_WITH_ALTERED_SEARCH_PATH);
            if(hDllPython3X) { break; }
            fBitnessFail = fBitnessFail || (ERROR_BAD_EXE_FORMAT == GetLastError());
        }
        if(hDllPython3X) {
            Util_GetPathLib(H->cfg.szPythonPath);
            strcat_s(H->cfg.szPythonPath, MAX_PATH, "python\\");
        }
    }
    // 4: Try locate Python by loading from the current path.
    if(0 == H->cfg.szPythonPath[0]) {
        for(i = 0; i < cszPYTHON_VERSIONS_SUPPORTED; i++) {
            hDllPython3X = LoadLibraryU(szPYTHON_VERSIONS_SUPPORTED[i]);
            if(hDllPython3X) { break; }
            fBitnessFail = fBitnessFail || (ERROR_BAD_EXE_FORMAT == GetLastError());
        }
        if(hDllPython3X) {
            Util_GetPathDll(H->cfg.szPythonPath, hDllPython3X);
        }
    }
    // 5: Python is not found?
    if(0 == H->cfg.szPythonPath[0]) {
        VmmLog(H, MID_PLUGIN, LOGLEVEL_INFO,
            fBitnessFail ?
            "Python initialization failed. Unable to load 32-bit Python. 64-bit required." :
            "Python initialization failed. Python 3.6 or later not found."
        );
        goto fail;
    }
    // 6: Load Python3.dll as well (i.e. prevent vmmpyc.pyd to fetch the wrong one by mistake...)
    Util_GetPathDll(szPythonPath, hDllPython3X);
    strcat_s(szPythonPath, MAX_PATH, "python3.dll");
    hDllPython3 = LoadLibraryExA(szPythonPath, 0, LOAD_WITH_ALTERED_SEARCH_PATH);
    VmmLog(H, MID_PLUGIN, LOGLEVEL_DEBUG, "PYTHON_PATH: %s", H->cfg.szPythonPath);
    // 7: process 'special status' python plugin manager.
    hDllPyPlugin = LoadLibraryU("vmmpyc.pyd");
    if(!hDllPyPlugin) {
        VmmLog(H, MID_PLUGIN, LOGLEVEL_WARNING, "Python plugin manager failed to load.");
        goto fail;
    }
    pfnInitializeVmmPlugin = (VOID(*)(VMM_HANDLE, PVMMDLL_PLUGIN_REGINFO))GetProcAddress(hDllPyPlugin, "InitializeVmmPlugin");
    if(!pfnInitializeVmmPlugin) {
        VmmLog(H, MID_PLUGIN, LOGLEVEL_WARNING, "Python plugin manager failed to load due to corrupt DLL.");
        goto fail;
    }
    PluginManager_Initialize_RegInfoInit(H, &ri, hDllPyPlugin);
    ri.python.fPythonStandalone = fPythonStandalone;
    ri.python.hReservedDllPython3X = hDllPython3X;
    ri.python.hReservedDllPython3 = hDllPython3;
    pfnInitializeVmmPlugin(H, &ri);
    if(!PluginManager_ModuleExistsDll(H, hDllPyPlugin)) {
        VmmLog(H, MID_PLUGIN, LOGLEVEL_WARNING, "Python plugin manager failed to load due to internal error.");
        return;
    }
    VmmLog(H, MID_PLUGIN, LOGLEVEL_VERBOSE, "PluginManager: Python plugin loaded.");
    if(hDllPython3X) { FreeLibrary(hDllPython3X); }
    return;
fail:
    if(hDllPyPlugin) { FreeLibrary(hDllPyPlugin); }
    if(hDllPython3X) { FreeLibrary(hDllPython3X); }
    if(hDllPython3) { FreeLibrary(hDllPython3); }
}

VOID PluginManager_Initialize_ExternalDlls(_In_ VMM_HANDLE H)
{
    VMMDLL_PLUGIN_REGINFO ri;
    CHAR uszPath[MAX_PATH];
    WCHAR wszPath[MAX_PATH];
    DWORD cchPathBase;
    HANDLE hFindFile;
    WIN32_FIND_DATAW FindData;
    HMODULE hDLL;
    VOID(*pfnInitializeVmmPlugin)(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_REGINFO pRegInfo);
    Util_GetPathLib(uszPath);
    if(!CharUtil_UtoW(uszPath, (DWORD)-1, (PBYTE)wszPath, sizeof(wszPath), NULL, NULL, CHARUTIL_FLAG_STR_BUFONLY)) { return; }
    cchPathBase = (DWORD)wcsnlen(wszPath, MAX_PATH - 1);
    wcscat_s(wszPath, MAX_PATH, L"plugins\\m_*.dll");
    hFindFile = FindFirstFileW(wszPath, &FindData);
    if(hFindFile != INVALID_HANDLE_VALUE) {
        do {
            wszPath[min(cchPathBase, MAX_PATH - 1)] = L'\0';
            wcscat_s(wszPath, MAX_PATH, L"plugins\\");
            wcscat_s(wszPath, MAX_PATH, FindData.cFileName);
            hDLL = LoadLibraryExW(wszPath, 0, 0);
            if(!hDLL) {
                VmmLog(H, MID_PLUGIN, LOGLEVEL_DEBUG, "FAIL: Load DLL: '%S' - missing dependencies?", FindData.cFileName);
                continue;
            }
            VmmLog(H, MID_PLUGIN, LOGLEVEL_DEBUG, "Load DLL: '%S'", FindData.cFileName);
            pfnInitializeVmmPlugin = (VOID(*)(VMM_HANDLE, PVMMDLL_PLUGIN_REGINFO))GetProcAddress(hDLL, "InitializeVmmPlugin");
            if(!pfnInitializeVmmPlugin) {
                VmmLog(H, MID_PLUGIN, LOGLEVEL_DEBUG, "Unload DLL: '%S' - Plugin Entry Point not found", FindData.cFileName);
                FreeLibrary(hDLL);
                continue;
            }
            PluginManager_Initialize_RegInfoInit(H, &ri, hDLL);
            pfnInitializeVmmPlugin(H, &ri);
            if(!PluginManager_ModuleExistsDll(H, hDLL)) {
                VmmLog(H, MID_PLUGIN, LOGLEVEL_DEBUG, "Unload DLL: '%S' - not registered with plugin manager", FindData.cFileName);
                FreeLibrary(hDLL);
                continue;
            }
        } while(FindNextFileW(hFindFile, &FindData) && !H->fAbort);
        FindClose(hFindFile);
    }
}
#endif /* _WIN32 */

#if defined(LINUX) || defined(MACOS)
VOID PluginManager_Initialize_Python(_In_ VMM_HANDLE H)
{
    struct link_map *lm;
    LPSTR szPYTHON_VERSIONS_SUPPORTED[] = {
        "libpython3.15.so.1", "libpython3.15.so",
        "libpython3.14.so.1", "libpython3.14.so",
        "libpython3.13.so.1", "libpython3.13.so",
        "libpython3.12.so.1", "libpython3.12.so",
        "libpython3.11.so.1", "libpython3.11.so",
        "libpython3.10.so.1", "libpython3.10.so",
        "libpython3.9.so.1", "libpython3.9.so",
        "libpython3.8.so.1", "libpython3.8.so",
        "libpython3.7.so.1", "libpython3.7.so",
        "libpython3.6.so.1", "libpython3.6.so"
    };
    DWORD cszPYTHON_VERSIONS_SUPPORTED = (sizeof(szPYTHON_VERSIONS_SUPPORTED) / sizeof(LPSTR));
    DWORD i;
    BOOL fPythonStandalone = FALSE;
    VMMDLL_PLUGIN_REGINFO ri;
    CHAR szPythonPath[MAX_PATH];
    HMODULE hDllPython3X = NULL, hDllPyPlugin = NULL;
    VOID(*pfnInitializeVmmPlugin)(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_REGINFO pRegInfo);
    // 0: Verify that Python should be enabled
    if(H->cfg.fDisablePython) { return; }
    // 1: Locate Python by trying user-defined path
    if(H->cfg.szPythonPath[0]) {
        for(i = 0; i < cszPYTHON_VERSIONS_SUPPORTED; i++) {
            ZeroMemory(szPythonPath, MAX_PATH);
            strcpy_s(szPythonPath, MAX_PATH, H->cfg.szPythonPath);
            strcat_s(szPythonPath, MAX_PATH, "/");
            strcat_s(szPythonPath, MAX_PATH, szPYTHON_VERSIONS_SUPPORTED[i]);
            hDllPython3X = dlopen(szPythonPath, RTLD_NOW | RTLD_GLOBAL);
            if(hDllPython3X) { break; }
        }
        if(!hDllPython3X) {
            ZeroMemory(H->cfg.szPythonPath, MAX_PATH);
            VmmLog(H, MID_PLUGIN, LOGLEVEL_INFO, "Python initialization failed. Python 3.6 or later not found on user specified path.");
            return;
        }
    }
    // 2: If Python is already loaded - use it!
    if(0 == H->cfg.szPythonPath[0]) {
        for(i = 0; i < cszPYTHON_VERSIONS_SUPPORTED; i++) {
            if((hDllPython3X = GetModuleHandleA(szPYTHON_VERSIONS_SUPPORTED[i]))) {
                GetModuleFileNameA(hDllPython3X, szPythonPath, MAX_PATH);
                hDllPython3X = dlopen(szPythonPath, RTLD_NOW | RTLD_GLOBAL);
                if(hDllPython3X) {
                    Util_GetPathDll(H->cfg.szPythonPath, hDllPython3X);
                    fPythonStandalone = TRUE;
                    break;
                }
            }
        }
    }
    // 3: Try locate Python by checking the python36 sub-directory relative to the current executable (.exe).
    if(0 == H->cfg.szPythonPath[0]) {
        for(i = 0; i < cszPYTHON_VERSIONS_SUPPORTED; i++) {
            ZeroMemory(szPythonPath, MAX_PATH);
            Util_GetPathDll(szPythonPath, NULL);
            strcat_s(szPythonPath, MAX_PATH, "python/");
            strcat_s(szPythonPath, MAX_PATH, szPYTHON_VERSIONS_SUPPORTED[i]);
            hDllPython3X = dlopen(szPythonPath, RTLD_NOW | RTLD_GLOBAL);
            if(hDllPython3X) { break; }
        }
        if(hDllPython3X) {
            Util_GetPathDll(H->cfg.szPythonPath, NULL);
            strcat_s(H->cfg.szPythonPath, MAX_PATH, "python/");
        }
    }
    // 4: Try locate Python by loading from the current path.
    if(0 == H->cfg.szPythonPath[0]) {
        for(i = 0; i < cszPYTHON_VERSIONS_SUPPORTED; i++) {
            hDllPython3X = dlopen(szPYTHON_VERSIONS_SUPPORTED[i], RTLD_NOW | RTLD_GLOBAL);
            if(hDllPython3X) { break; }
        }
        if(hDllPython3X) {
            Util_GetPathDll(H->cfg.szPythonPath, hDllPython3X);
        }
    }
    // 5: Python is not found?
    if(0 == H->cfg.szPythonPath[0]) {
        VmmLog(H, MID_PLUGIN, LOGLEVEL_INFO, "Python initialization failed. Python 3.6 or later not found.");
        goto fail;
    }
    VmmLog(H, MID_PLUGIN, LOGLEVEL_DEBUG, "PYTHON_PATH: %s", H->cfg.szPythonPath);
    // 7: process 'special status' python plugin manager.
    hDllPyPlugin = dlopen("vmmpyc.so", RTLD_NOW | RTLD_GLOBAL);
    if(!hDllPyPlugin) {
        VmmLog(H, MID_PLUGIN, LOGLEVEL_WARNING, "Python plugin manager failed to load.");
        goto fail;
    }
    pfnInitializeVmmPlugin = (VOID(*)(VMM_HANDLE, PVMMDLL_PLUGIN_REGINFO))GetProcAddress(hDllPyPlugin, "InitializeVmmPlugin");
    if(!pfnInitializeVmmPlugin) {
        VmmLog(H, MID_PLUGIN, LOGLEVEL_WARNING, "Python plugin manager failed to load due to corrupt DLL.");
        goto fail;
    }
    PluginManager_Initialize_RegInfoInit(H, &ri, hDllPyPlugin);
    ri.python.fPythonStandalone = fPythonStandalone;
    ri.python.hReservedDllPython3X = NULL;
    ri.python.hReservedDllPython3 = hDllPython3X;
    pfnInitializeVmmPlugin(H, &ri);
    if(!PluginManager_ModuleExistsDll(H, hDllPyPlugin)) {
        VmmLog(H, MID_PLUGIN, LOGLEVEL_WARNING, "Python plugin manager failed to load due to internal error.");
        return;
    }
    VmmLog(H, MID_PLUGIN, LOGLEVEL_VERBOSE, "PluginManager: Python plugin loaded.");
    return;
fail:
    if(hDllPyPlugin) { dlclose(hDllPyPlugin); }
    if(hDllPython3X) { dlclose(hDllPython3X); }
}

VOID PluginManager_Initialize_ExternalDlls(_In_ VMM_HANDLE H)
{
    HMODULE hDLL;
    VMMDLL_PLUGIN_REGINFO ri;
    CHAR szPath[MAX_PATH];
    DWORD cchPathBase;
    DIR *dp;
    struct dirent *ep;
    VOID(*pfnInitializeVmmPlugin)(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_REGINFO pRegInfo);
    Util_GetPathLib(szPath);
    strcat_s(szPath, MAX_PATH, "/plugins/");
    cchPathBase = (DWORD)strnlen(szPath, MAX_PATH - 1);
    if(cchPathBase > MAX_PATH - 0x20) {
        VmmLog(H, MID_PLUGIN, LOGLEVEL_DEBUG, "FAIL load external modules - path too long");
        return;
    }
    if(!(dp = opendir(szPath))) {
        VmmLog(H, MID_PLUGIN, LOGLEVEL_DEBUG, "FAIL load external modules - plugins directory missing");
        return;
    }
    while((ep = readdir(dp)) && !H->fAbort) {
        if((ep->d_name[0] != 'm') || (ep->d_name[1] != '_')) { continue; }
        if(!CharUtil_StrEndsWith(ep->d_name, VMM_LIBRARY_FILETYPE, TRUE)) { continue; }
        szPath[cchPathBase] = '\0';
        strcat_s(szPath + cchPathBase, MAX_PATH - cchPathBase, ep->d_name);
        VmmLog(H, MID_PLUGIN, LOGLEVEL_6_TRACE, "Try load external module '%s'", szPath);
        hDLL = dlopen(szPath, RTLD_NOW);
        if(!hDLL) {
            VmmLog(H, MID_PLUGIN, LOGLEVEL_DEBUG, "FAIL load external module '%s' - ('%s') missing dependencies?", ep->d_name, dlerror());
            continue;
        }
        pfnInitializeVmmPlugin = (VOID(*)(VMM_HANDLE, PVMMDLL_PLUGIN_REGINFO))dlsym(hDLL, "InitializeVmmPlugin");
        if(!pfnInitializeVmmPlugin) {
            VmmLog(H, MID_PLUGIN, LOGLEVEL_DEBUG, "FAIL load external module '%s' - plugin entry point not found", ep->d_name);
            dlclose(hDLL);
            continue;
        }
        PluginManager_Initialize_RegInfoInit(H, &ri, hDLL);
        pfnInitializeVmmPlugin(H, &ri);
        if(!PluginManager_ModuleExistsDll(H, hDLL)) {
            VmmLog(H, MID_PLUGIN, LOGLEVEL_DEBUG, "FAIL load external module '%s' - not registered with plugin manager", ep->d_name);
            dlclose(hDLL);
            continue;
        }
    }
    closedir(dp);
}
#endif /* LINUX || MACOS */

BOOL PluginManager_Initialize(_In_ VMM_HANDLE H)
{
    DWORD i;
    VMMDLL_PLUGIN_REGINFO ri;
    // 1: check if already initialized
    if(H->vmm.PluginManager.FLinkAll) { return TRUE; }
    AcquireSRWLockExclusive(&H->vmm.LockSRW.PluginMgr);
    if(H->vmm.PluginManager.FLinkAll) {
        ReleaseSRWLockExclusive(&H->vmm.LockSRW.PluginMgr);
        return TRUE;
    }
    // 2: set up root nodes of process plugin tree
    H->vmm.PluginManager.Root = LocalAlloc(LMEM_ZEROINIT, sizeof(PLUGIN_TREE));
    H->vmm.PluginManager.Proc = LocalAlloc(LMEM_ZEROINIT, sizeof(PLUGIN_TREE));
    if(!H->vmm.PluginManager.Root || !H->vmm.PluginManager.Proc) { goto fail; }
    // 3: process built-in modules
    for(i = 0; i < sizeof(g_pfnModulesAllInternal) / sizeof(PVOID); i++) {
        if(H->fAbort) { goto fail; }
        PluginManager_Initialize_RegInfoInit(H, &ri, NULL);
        g_pfnModulesAllInternal[i](H, &ri);
    }
    for(i = 0; i < sizeof(g_pfnModulesExAllInternal) / sizeof(PVOID); i++) {
        if(H->fAbort) { goto fail; }
        PluginManager_Initialize_RegInfoInit(H, &ri, NULL);
        g_pfnModulesExAllInternal[i](H, &ri);
    }
    // 4: process dll modules
    PluginManager_Initialize_ExternalDlls(H);
    // 5: process 'special status' python plugin manager.
    if(H->fAbort) { goto fail; }
    PluginManager_Initialize_Python(H);
    // 6: refresh logging (module specific overrides not yet applied may exist)
    VmmLog_LevelRefresh(H);
    ReleaseSRWLockExclusive(&H->vmm.LockSRW.PluginMgr);
    return TRUE;
fail:
    ReleaseSRWLockExclusive(&H->vmm.LockSRW.PluginMgr);
    return FALSE;
}
