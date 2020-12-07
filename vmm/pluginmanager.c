// pluginmanager.c : implementation of the plugin manager for memory process file system plugins.
//
// (c) Ulf Frisk, 2018-2020
// Author: Ulf Frisk, pcileech@frizk.net
//
#include "pluginmanager.h"
#include "statistics.h"
#include "util.h"
#include "vmm.h"
#include "vmmdll.h"
#include "m_modules.h"

//
// This file contains functionality related to keeping track of plugins, both
// internal built-in ones and loadable plugins in the form of compliant DLLs.
//
// The functionality and data structures are at this moment single-threaded in
// this implementation and should be protected by a lock (ctxVmm->LockMaster).
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
    HMODULE hDLL;
    WCHAR wszName[32];
    DWORD dwNameHash;
    BOOL fRootModule;
    BOOL fProcessModule;
    BOOL(*pfnVisibleModule)(_In_ PVMMDLL_PLUGIN_CONTEXT ctx);
    BOOL(*pfnList)(_In_ PVMMDLL_PLUGIN_CONTEXT ctx, _Inout_ PHANDLE pFileList);
    NTSTATUS(*pfnRead)(_In_ PVMMDLL_PLUGIN_CONTEXT ctx, _Out_writes_to_(cb, *pcbRead) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset);
    NTSTATUS(*pfnWrite)(_In_ PVMMDLL_PLUGIN_CONTEXT ctx, _In_reads_(cb) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbWrite, _In_ QWORD cbOffset);
    VOID(*pfnNotify)(_In_ DWORD fEvent, _In_opt_ PVOID pvEvent, _In_opt_ DWORD cbEvent);
    VOID(*pfnClose)();
    struct {
        PVOID ctxfc;
        PHANDLE phEventIngestFinish;
        PVOID(*pfnInitialize)();
        VOID(*pfnFinalize)(_In_opt_ PVOID ctxfc);
        VOID(*pfnTimeline)(
            _In_opt_ PVOID ctxfc,
            _In_ HANDLE hTimeline,
            _In_ VOID(*pfnAddEntry)(_In_ HANDLE hTimeline, _In_ QWORD ft, _In_ DWORD dwAction, _In_ DWORD dwPID, _In_ QWORD qwValue, _In_ LPWSTR wszText),
            _In_ VOID(*pfnEntryAddBySql)(_In_ HANDLE hTimeline, _In_ DWORD cEntrySql, _In_ LPSTR *pszEntrySql));
        VOID(*pfnIngestPhysmem)(_In_opt_ PVOID ctxfc, _In_ PVMMDLL_PLUGIN_FORENSIC_INGEST_PHYSMEM pIngestPhysmem);
        VOID(*pfnIngestFinalize)(_In_opt_ PVOID ctxfc);
        struct {
            PVMMDLL_PLUGIN_FORENSIC_INGEST_PHYSMEM p;
        } IngestPhysmem;
        struct {
            CHAR sNameShort[6];
            CHAR _Reserved[2];
            CHAR szFileUTF8[32];
            CHAR szFileJSON[32];
        } Timeline;
    } fc;
} PLUGIN_ENTRY, *PPLUGIN_ENTRY;

#define PLUGIN_TREE_MAX_CHILDITEMS      32

typedef struct tdPLUGIN_TREE {
    WCHAR wszName[32];
    DWORD dwHashName;
    DWORD cChild;
    BOOL fVisible;
    struct tdPLUGIN_TREE *pParent;
    struct tdPLUGIN_TREE *Child[PLUGIN_TREE_MAX_CHILDITEMS];
    PPLUGIN_ENTRY pPlugin;
} PLUGIN_TREE, *PPLUGIN_TREE;



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

PPLUGIN_TREE PluginManager_Register_GetCreateTree(_In_ PPLUGIN_TREE pTree, _In_ LPWSTR wszPathName, _In_ BOOL fVisible)
{
    DWORD i, dwHash;
    WCHAR wszEntry[32];
    PPLUGIN_TREE pChild;
    // 1: no more levels to create - return
    if(!wszPathName[0]) { return pTree; }
    // 2: check existing tree child entries
    wszPathName = Util_PathSplit2_ExWCHAR(wszPathName, wszEntry, _countof(wszEntry));
    dwHash = Util_HashStringUpperW(wszEntry);
    for(i = 0; i < pTree->cChild; i++) {
        if(pTree->Child[i]->dwHashName == dwHash) {
            return PluginManager_Register_GetCreateTree(pTree->Child[i], wszPathName, fVisible);
        }
    }
    // 3: create new entry
    if(pTree->cChild == PLUGIN_TREE_MAX_CHILDITEMS) { return NULL; }
    if(!(pTree->Child[pTree->cChild] = pChild = LocalAlloc(LMEM_ZEROINIT, sizeof(PLUGIN_TREE)))) { return NULL; }
    pTree->cChild++;
    wcsncpy_s(pChild->wszName, _countof(pChild->wszName), wszEntry, _TRUNCATE);
    pChild->dwHashName = dwHash;
    pChild->pParent = pTree;
    PluginManager_SetTreeVisibility(pChild, fVisible);
    return PluginManager_Register_GetCreateTree(pChild, wszPathName, fVisible);
}

/*
* Retrieve the PLUGIN_TREE entry and the remaining path given a root tree and a root path.
* -- pTree
* -- wszPath
* -- pTree
* -- pwszSubPath
*/
VOID PluginManager_GetTree(_In_ PPLUGIN_TREE pTree, _In_ LPWSTR wszPath, _Out_ PPLUGIN_TREE *ppTree, _Out_ LPWSTR *pwszSubPath)
{
    DWORD i, dwHash;
    WCHAR wszEntry[32];
    LPWSTR wszSubPath;
    if(!wszPath[0]) { goto finish; }
    wszSubPath = Util_PathSplit2_ExWCHAR(wszPath, wszEntry, _countof(wszEntry));
    dwHash = Util_HashStringUpperW(wszEntry);
    for(i = 0; i < pTree->cChild; i++) {
        if(pTree->Child[i]->dwHashName == dwHash) {
            PluginManager_GetTree(pTree->Child[i], wszSubPath, ppTree, pwszSubPath);
            return;
        }
    }
finish:
    *ppTree = pTree;
    *pwszSubPath = wszPath;
}

VOID PluginManager_SetVisibility(_In_ BOOL fRoot, _In_ LPWSTR wszPluginPath, _In_ BOOL fVisible)
{
    LPWSTR wszSubPath;
    PPLUGIN_TREE pTree;
    if(wszPluginPath[0] == '\\') { wszPluginPath++; }
    PluginManager_GetTree((fRoot ? ctxVmm->PluginManager.Root : ctxVmm->PluginManager.Proc), wszPluginPath, &pTree, &wszSubPath);
    PluginManager_SetTreeVisibility(pTree, fVisible);
}

BOOL PluginManager_ModuleExistsDll(_In_opt_ HMODULE hDLL) {
    PPLUGIN_ENTRY pModule = (PPLUGIN_ENTRY)ctxVmm->PluginManager.FLinkAll;
    while(pModule) {
        if(hDLL && (hDLL == pModule->hDLL)) { return TRUE; }
        pModule = pModule->FLinkAll;
    }
    return FALSE;
}

BOOL PluginManager_ModuleExists(_In_ PPLUGIN_TREE pTree, _In_ LPWSTR wszPath) {
    LPWSTR wszSubPath;
    PPLUGIN_TREE pTreePlugin;
    PluginManager_GetTree(pTree, wszPath, &pTreePlugin, &wszSubPath);
    return pTreePlugin->pPlugin && !wszSubPath[0];
}

VOID PluginManager_ContextInitialize(_Out_ PVMMDLL_PLUGIN_CONTEXT ctx, PPLUGIN_ENTRY pModule, _In_opt_ PVMM_PROCESS pProcess, _In_ LPWSTR wszPath)
{
    ctx->magic = VMMDLL_PLUGIN_CONTEXT_MAGIC;
    ctx->wVersion = VMMDLL_PLUGIN_CONTEXT_VERSION;
    ctx->wSize = sizeof(VMMDLL_PLUGIN_CONTEXT);
    ctx->dwPID = (pProcess ? pProcess->dwPID : (DWORD)-1);
    ctx->pProcess = pModule->hDLL ? NULL : pProcess;
    ctx->wszModule = pModule->wszName;
    ctx->wszPath = wszPath;
}

VOID PluginManager_List(_In_opt_ PVMM_PROCESS pProcess, _In_ LPWSTR wszPath, _Inout_ PHANDLE pFileList)
{
    DWORD i;
    BOOL fVisibleProgrammatic, result = TRUE;
    QWORD tmStart = Statistics_CallStart();
    VMMDLL_PLUGIN_CONTEXT ctx;
    LPWSTR wszSubPath;
    PPLUGIN_TREE pTree;
    PPLUGIN_ENTRY pPlugin;
    pTree = pProcess ? ctxVmm->PluginManager.Proc : ctxVmm->PluginManager.Root;
    if(!pTree) { return; }
    PluginManager_GetTree((pProcess ? ctxVmm->PluginManager.Proc : ctxVmm->PluginManager.Root), wszPath, &pTree, &wszSubPath);
    if(pTree->fVisible) {
        if(pTree->cChild && !wszSubPath[0]) {
            for(i = 0; i < pTree->cChild; i++) {
                if(pTree->Child[i]->fVisible) {
                    fVisibleProgrammatic = pTree->Child[i]->cChild || !pTree->Child[i]->pPlugin || !pTree->Child[i]->pPlugin->pfnVisibleModule;
                    if(!fVisibleProgrammatic) {
                        PluginManager_ContextInitialize(&ctx, pTree->Child[i]->pPlugin, pProcess, wszSubPath);
                        fVisibleProgrammatic = pTree->Child[i]->pPlugin->pfnVisibleModule(&ctx);
                    }
                    if(fVisibleProgrammatic) {
                        VMMDLL_VfsList_AddDirectory(pFileList, pTree->Child[i]->wszName, NULL);
                    }
                }
            }
        }
        if((pPlugin = pTree->pPlugin) && pPlugin->pfnList) {
            PluginManager_ContextInitialize(&ctx, pPlugin, pProcess, wszSubPath);
            if(!pPlugin->pfnVisibleModule || pPlugin->pfnVisibleModule(&ctx)) {
                pTree->pPlugin->pfnList(&ctx, pFileList);
            }
        }
    }
    Statistics_CallEnd(STATISTICS_ID_PluginManager_List, tmStart);
}

NTSTATUS PluginManager_Read(_In_opt_ PVMM_PROCESS pProcess, _In_ LPWSTR wszPath, _Out_writes_to_(cb, *pcbRead) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset)
{
    QWORD tmStart = Statistics_CallStart();
    NTSTATUS nt;
    VMMDLL_PLUGIN_CONTEXT ctx;
    LPWSTR wszSubPath;
    PPLUGIN_TREE pTree;
    PPLUGIN_ENTRY pPlugin;
    pTree = pProcess ? ctxVmm->PluginManager.Proc : ctxVmm->PluginManager.Root;
    if(!pTree) { return VMMDLL_STATUS_FILE_INVALID; }
    PluginManager_GetTree((pProcess ? ctxVmm->PluginManager.Proc : ctxVmm->PluginManager.Root), wszPath, &pTree, &wszSubPath);
    if(pTree->fVisible) {
        if((pPlugin = pTree->pPlugin) && pPlugin->pfnRead) {
            PluginManager_ContextInitialize(&ctx, pPlugin, pProcess, wszSubPath);
            nt = pPlugin->pfnRead(&ctx, pb, cb, pcbRead, cbOffset);
            Statistics_CallEnd(STATISTICS_ID_PluginManager_Read, tmStart);
            return nt;
        }
    }
    Statistics_CallEnd(STATISTICS_ID_PluginManager_List, tmStart);
    return VMMDLL_STATUS_FILE_INVALID;
}

NTSTATUS PluginManager_Write(_In_opt_ PVMM_PROCESS pProcess, _In_ LPWSTR wszPath, _In_reads_(cb) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbWrite, _In_ QWORD cbOffset)
{
    QWORD tmStart = Statistics_CallStart();
    NTSTATUS nt;
    VMMDLL_PLUGIN_CONTEXT ctx;
    LPWSTR wszSubPath;
    PPLUGIN_TREE pTree;
    PPLUGIN_ENTRY pPlugin;
    pTree = pProcess ? ctxVmm->PluginManager.Proc : ctxVmm->PluginManager.Root;
    if(!pTree) { return VMMDLL_STATUS_FILE_INVALID; }
    PluginManager_GetTree((pProcess ? ctxVmm->PluginManager.Proc : ctxVmm->PluginManager.Root), wszPath, &pTree, &wszSubPath);
    if(pTree->fVisible) {
        if((pPlugin = pTree->pPlugin) && pPlugin->pfnWrite) {
            PluginManager_ContextInitialize(&ctx, pPlugin, pProcess, wszSubPath);
            nt = pPlugin->pfnWrite(&ctx, pb, cb, pcbWrite, cbOffset);
            Statistics_CallEnd(STATISTICS_ID_PluginManager_Read, tmStart);
            return nt;
        }
    }
    Statistics_CallEnd(STATISTICS_ID_PluginManager_List, tmStart);
    return VMMDLL_STATUS_FILE_INVALID;
}

BOOL PluginManager_Notify(_In_ DWORD fEvent, _In_opt_ PVOID pvEvent, _In_opt_ DWORD cbEvent)
{
    QWORD tmStart = Statistics_CallStart();
    PPLUGIN_ENTRY pModule = (PPLUGIN_ENTRY)ctxVmm->PluginManager.FLinkNotify;
    while(pModule) {
        if(pModule->pfnNotify) {
            pModule->pfnNotify(fEvent, pvEvent, cbEvent);
        }
        pModule = pModule->FLinkNotify;
    }
    Statistics_CallEnd(STATISTICS_ID_PluginManager_Notify, tmStart);
    return TRUE;
}

/*
* Initialize plugins with forensic mode capabilities.
*/
VOID PluginManager_FcInitialize()
{
    QWORD tmStart = Statistics_CallStart();
    PPLUGIN_ENTRY pModule = (PPLUGIN_ENTRY)ctxVmm->PluginManager.FLinkForensic;
    while(pModule) {
        if(pModule->fc.pfnInitialize) {
            pModule->fc.ctxfc = pModule->fc.pfnInitialize();
        }
        pModule = pModule->FLinkForensic;
    }
    Statistics_CallEnd(STATISTICS_ID_PluginManager_FcInitialize, tmStart);
}

/*
* Finalize plugins with forensic mode capabilities.
*/
VOID PluginManager_FcFinalize()
{
    QWORD tmStart = Statistics_CallStart();
    PPLUGIN_ENTRY pModule = (PPLUGIN_ENTRY)ctxVmm->PluginManager.FLinkForensic;
    while(pModule) {
        if(pModule->fc.pfnFinalize) {
            pModule->fc.pfnFinalize(pModule->fc.ctxfc);
            pModule->fc.ctxfc = NULL;
        }
        pModule = pModule->FLinkForensic;
    }
    Statistics_CallEnd(STATISTICS_ID_PluginManager_FcFinalize, tmStart);
}

/*
* Worker thread entry point:
* Ingest physical memory into plugins with forensic mode capabilities.
* -- pModule
*/
VOID PluginManager_FcIngestPhysmem_ThreadProc(PPLUGIN_ENTRY pModule)
{
    pModule->fc.pfnIngestPhysmem(pModule->fc.ctxfc, pModule->fc.IngestPhysmem.p);
}

/*
* Ingest physical memory into plugins with forensic mode capabilities.
* -- pIngestPhysmem
*/
VOID PluginManager_FcIngestPhysmem(_In_ PVMMDLL_PLUGIN_FORENSIC_INGEST_PHYSMEM pIngestPhysmem)
{
    QWORD tmStart = Statistics_CallStart();
    PPLUGIN_ENTRY pModule = (PPLUGIN_ENTRY)ctxVmm->PluginManager.FLinkForensic;
    while(pModule) {
        if(pModule->fc.pfnIngestPhysmem) {
            ResetEvent(pModule->fc.phEventIngestFinish);
            pModule->fc.IngestPhysmem.p = pIngestPhysmem;
            // ingestion will happen in parallel between all plugins, but this
            // function will wait for all ingestion to finish before exiting.
            VmmWork((LPTHREAD_START_ROUTINE)PluginManager_FcIngestPhysmem_ThreadProc, pModule, pModule->fc.phEventIngestFinish);
        }
        pModule = pModule->FLinkForensic;
    }
    WaitForMultipleObjects(ctxVmm->PluginManager.fc.cEvent, ctxVmm->PluginManager.fc.hEvent, TRUE, INFINITE);
    Statistics_CallEnd(STATISTICS_ID_PluginManager_FcIngestPhysmem, tmStart);
}

/*
* All ingestion actions are completed.
*/
VOID PluginManager_FcIngestFinalize()
{
    QWORD tmStart = Statistics_CallStart();
    PPLUGIN_ENTRY pModule = (PPLUGIN_ENTRY)ctxVmm->PluginManager.FLinkForensic;
    while(pModule) {
        if(pModule->fc.pfnIngestFinalize) {
            pModule->fc.pfnIngestFinalize(pModule->fc.ctxfc);
        }
        pModule = pModule->FLinkForensic;
    }
    Statistics_CallEnd(STATISTICS_ID_PluginManager_FcIngestPhysmem, tmStart);
}

/*
* Register plugins with timelining capabilities with the timeline manager
* and call into each plugin to allow them to add their timelining entries.
* NB! This function is meant to be called by the core forensic subsystem only.
* -- pfnRegister = callback function to register timeline module.
* -- pfnClose = function to close the timeline handle.
* -- pfnAddEntry = callback function to call to add a timelining entry.
*/
VOID PluginManager_FcTimeline(
    _In_ HANDLE(*pfnRegister)(_In_reads_(6) LPSTR sNameShort, _In_reads_(32) LPSTR szFileUTF8, _In_reads_(32) LPSTR szFileJSON),
    _In_ VOID(*pfnClose)(_In_ HANDLE hTimeline),
    _In_ VOID(*pfnAddEntry)(_In_ HANDLE hTimeline, _In_ QWORD ft, _In_ DWORD dwAction, _In_ DWORD dwPID, _In_ QWORD qwValue, _In_ LPWSTR wszText),
    _In_ VOID(*pfnEntryAddBySql)(_In_ HANDLE hTimeline, _In_ DWORD cEntrySql, _In_ LPSTR *pszEntrySql)
) {
    HANDLE hTimeline;
    QWORD tmStart = Statistics_CallStart();
    PPLUGIN_ENTRY pModule = (PPLUGIN_ENTRY)ctxVmm->PluginManager.FLinkForensic;
    while(pModule) {
        if(pModule->fc.pfnTimeline) {
            hTimeline = pfnRegister(pModule->fc.Timeline.sNameShort, pModule->fc.Timeline.szFileUTF8, pModule->fc.Timeline.szFileJSON);
            if(hTimeline) {
                pModule->fc.pfnTimeline(pModule->fc.ctxfc, hTimeline, pfnAddEntry, pfnEntryAddBySql);
                pfnClose(hTimeline);
            }
        }
        pModule = pModule->FLinkForensic;
    }
    Statistics_CallEnd(STATISTICS_ID_PluginManager_FcTimeline, tmStart);
}

// ----------------------------------------------------------------------------
// MODULES REGISTRATION/CLEANUP FUNCTIONALITY - IMPLEMENTATION BELOW:
// ----------------------------------------------------------------------------

BOOL PluginManager_Register(_In_ PVMMDLL_PLUGIN_REGINFO pRegInfo)
{
    DWORD iPluginNameStart;
    LPWSTR wszPluginName;
    PPLUGIN_ENTRY pModule;
    PPLUGIN_TREE pPluginTreeEntry;
    // 1: tests if plugin is valid
    pRegInfo->reg_info.wszPathName[127] = 0;
    if(ctxVmm->PluginManager.fc.cEvent >= _countof(ctxVmm->PluginManager.fc.hEvent)) { return FALSE; }
    if(!pRegInfo || (pRegInfo->magic != VMMDLL_PLUGIN_REGINFO_MAGIC) || (pRegInfo->wVersion > VMMDLL_PLUGIN_REGINFO_VERSION)) { return FALSE; }
    if(!pRegInfo->reg_info.wszPathName[0]) { return FALSE; }
    wszPluginName = Util_PathSplitLastW(pRegInfo->reg_info.wszPathName);
    if(wcslen(wszPluginName) > 31) { return FALSE; }
    if(pRegInfo->reg_info.fRootModule && PluginManager_ModuleExists(ctxVmm->PluginManager.Root, pRegInfo->reg_info.wszPathName)) { return FALSE; }
    if(pRegInfo->reg_info.fProcessModule && PluginManager_ModuleExists(ctxVmm->PluginManager.Proc, pRegInfo->reg_info.wszPathName)) { return FALSE; }
    pModule = (PPLUGIN_ENTRY)LocalAlloc(LMEM_ZEROINIT, sizeof(PLUGIN_ENTRY));
    if(!pModule) { return FALSE; }
    if(!pRegInfo->reg_info.fRootModule && !pRegInfo->reg_info.fProcessModule) { return FALSE; }
    // 2: register plugin
    pModule->hDLL = pRegInfo->hDLL;
    wcsncpy_s(pModule->wszName, 32, wszPluginName, _TRUNCATE);
    pModule->dwNameHash = Util_HashStringUpperW(pModule->wszName);
    pModule->fRootModule = pRegInfo->reg_info.fRootModule;
    pModule->fProcessModule = pRegInfo->reg_info.fProcessModule;
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
    pModule->fc.pfnIngestPhysmem = pRegInfo->reg_fnfc.pfnIngestPhysmem;
    pModule->fc.pfnIngestFinalize = pRegInfo->reg_fnfc.pfnIngestFinalize;
    memcpy(pModule->fc.Timeline.sNameShort, pRegInfo->reg_info.sTimelineNameShort, _countof(pModule->fc.Timeline.sNameShort));
    memcpy(pModule->fc.Timeline.szFileUTF8, pRegInfo->reg_info.szTimelineFileUTF8, _countof(pModule->fc.Timeline.szFileUTF8));
    memcpy(pModule->fc.Timeline.szFileJSON, pRegInfo->reg_info.szTimelineFileJSON, _countof(pModule->fc.Timeline.szFileJSON));
    if(pRegInfo->reg_fnfc.pfnIngestPhysmem) {
        ctxVmm->PluginManager.fc.hEvent[ctxVmm->PluginManager.fc.cEvent] = CreateEvent(NULL, TRUE, TRUE, NULL);
        pModule->fc.phEventIngestFinish = ctxVmm->PluginManager.fc.hEvent[ctxVmm->PluginManager.fc.cEvent++];
    }
    vmmprintfv("PluginManager: Loaded %s module: '%S'\n", (pModule->hDLL ? " native " : "built-in"), pRegInfo->reg_info.wszPathName);
    if(pModule->pfnNotify) {
        pModule->FLinkNotify = (PPLUGIN_ENTRY)ctxVmm->PluginManager.FLinkNotify;
        ctxVmm->PluginManager.FLinkNotify = pModule;
    }
    if(pModule->fc.pfnInitialize || pModule->fc.pfnFinalize || pModule->fc.pfnTimeline || pModule->fc.pfnIngestPhysmem || pModule->fc.pfnIngestFinalize) {
        pModule->FLinkForensic = (PPLUGIN_ENTRY)ctxVmm->PluginManager.FLinkForensic;
        ctxVmm->PluginManager.FLinkForensic = pModule;
    }
    pModule->FLinkAll = (PPLUGIN_ENTRY)ctxVmm->PluginManager.FLinkAll;
    ctxVmm->PluginManager.FLinkAll = pModule;
    // 3: register plugin in plugin tree
    iPluginNameStart = (pRegInfo->reg_info.wszPathName[0] == '\\') ? 1 : 0;
    if(pModule->fRootModule) {
        pPluginTreeEntry = PluginManager_Register_GetCreateTree(ctxVmm->PluginManager.Root, pRegInfo->reg_info.wszPathName + iPluginNameStart, !pRegInfo->reg_info.fRootModuleHidden);
        if(pPluginTreeEntry && !pPluginTreeEntry->pPlugin) {
            pPluginTreeEntry->pPlugin = pModule;
        }
    }
    if(pModule->fProcessModule) {
        pPluginTreeEntry = PluginManager_Register_GetCreateTree(ctxVmm->PluginManager.Proc, pRegInfo->reg_info.wszPathName + iPluginNameStart, !pRegInfo->reg_info.fProcessModuleHidden);
        if(pPluginTreeEntry && !pPluginTreeEntry->pPlugin) {
            pPluginTreeEntry->pPlugin = pModule;
        }
    }
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

VOID PluginManager_Close()
{
    PPLUGIN_ENTRY pm;
    PPLUGIN_TREE pTreeRoot = ctxVmm->PluginManager.Root, pTreeProc = ctxVmm->PluginManager.Proc;
    ctxVmm->PluginManager.Root = NULL;
    ctxVmm->PluginManager.Proc = NULL;
    PluginManager_Close_Tree(pTreeRoot);
    PluginManager_Close_Tree(pTreeProc);
    ctxVmm->PluginManager.FLinkNotify = NULL;
    while((pm = (PPLUGIN_ENTRY)ctxVmm->PluginManager.FLinkAll)) {
        // 1: Detach current module list entry from list
        ctxVmm->PluginManager.FLinkAll = pm->FLinkAll;
        // 2: Close module callback
        if(pm->pfnClose) {
            pm->pfnClose();
        }
        // 3: FreeLibrary (if last module belonging to specific Library)
        if(pm->hDLL && !PluginManager_ModuleExistsDll(pm->hDLL)) { FreeLibrary(pm->hDLL); }
        // 4: LocalFree this ListEntry
        LocalFree(pm);
    }
    // 5: Clean up events
    while(ctxVmm->PluginManager.fc.cEvent) {
        CloseHandle(ctxVmm->PluginManager.fc.hEvent[--ctxVmm->PluginManager.fc.cEvent]);
    }
}

VOID PluginManager_Initialize_RegInfoInit(_Out_ PVMMDLL_PLUGIN_REGINFO pRI, _In_opt_ HMODULE hDLL)
{
    ZeroMemory(pRI, sizeof(VMMDLL_PLUGIN_REGINFO));
    pRI->magic = VMMDLL_PLUGIN_REGINFO_MAGIC;
    pRI->wVersion = VMMDLL_PLUGIN_REGINFO_VERSION;
    pRI->wSize = sizeof(VMMDLL_PLUGIN_REGINFO);
    pRI->hDLL = hDLL;
    pRI->tpMemoryModel = ctxVmm->tpMemoryModel;
    pRI->tpSystem = ctxVmm->tpSystem;
    pRI->pfnPluginManager_Register = PluginManager_Register;
    pRI->sysinfo.f32 = ctxVmm->f32;
    pRI->sysinfo.dwVersionMajor = ctxVmm->kernel.dwVersionMajor;
    pRI->sysinfo.dwVersionMinor = ctxVmm->kernel.dwVersionMinor;
    pRI->sysinfo.dwVersionBuild = ctxVmm->kernel.dwVersionBuild;
}

VOID PluginManager_Initialize_Python()
{
    LPSTR szPYTHON_VERSIONS_SUPPORTED[] = { "python315.dll", "python314.dll", "python313.dll", "python312.dll", "python311.dll", "python310.dll", "python39.dll", "python38.dll", "python37.dll", "python36.dll"};
    DWORD cszPYTHON_VERSIONS_SUPPORTED = (sizeof(szPYTHON_VERSIONS_SUPPORTED) / sizeof(LPSTR));
    DWORD i;
    BOOL fBitnessFail = FALSE;
    VMMDLL_PLUGIN_REGINFO ri;
    CHAR szPythonPath[MAX_PATH];
    HMODULE hDllPython3X = NULL, hDllPython3 = NULL, hDllPyPlugin = NULL;
    VOID(*pfnInitializeVmmPlugin)(_In_ PVMMDLL_PLUGIN_REGINFO pRegInfo);
    // 1: Locate Python by trying user-defined path
    if(ctxMain->cfg.szPythonPath[0]) {
        for(i = 0; i < cszPYTHON_VERSIONS_SUPPORTED; i++) {
            ZeroMemory(szPythonPath, MAX_PATH);
            strcpy_s(szPythonPath, MAX_PATH, ctxMain->cfg.szPythonPath);
            strcat_s(szPythonPath, MAX_PATH, "\\");
            strcat_s(szPythonPath, MAX_PATH, szPYTHON_VERSIONS_SUPPORTED[i]);
            hDllPython3X = LoadLibraryExA(szPythonPath, 0, LOAD_WITH_ALTERED_SEARCH_PATH);
            if(hDllPython3X) { break; }
            fBitnessFail = fBitnessFail || (ERROR_BAD_EXE_FORMAT == GetLastError());
        }
        if(!hDllPython3X) {
            ZeroMemory(ctxMain->cfg.szPythonPath, MAX_PATH);
            vmmprintf(
                fBitnessFail ?
                "PluginManager: Python initialization failed. Unable to load 32-bit Python. 64-bit required.\n" :
                "PluginManager: Python initialization failed. Python 3.6 or later not found on user specified path.\n"
            );
            return;
        }
    }
    // 2: Try locate Python by checking the python36 sub-directory relative to the current executable (.exe).
    if(0 == ctxMain->cfg.szPythonPath[0]) {
        for(i = 0; i < cszPYTHON_VERSIONS_SUPPORTED; i++) {
            ZeroMemory(szPythonPath, MAX_PATH);
            Util_GetPathDll(szPythonPath, NULL);
            strcat_s(szPythonPath, MAX_PATH, "python\\");
            strcat_s(szPythonPath, MAX_PATH, szPYTHON_VERSIONS_SUPPORTED[i]);
            hDllPython3X = LoadLibraryExA(szPythonPath, 0, LOAD_WITH_ALTERED_SEARCH_PATH);
            if(hDllPython3X) { break; }
            fBitnessFail = fBitnessFail || (ERROR_BAD_EXE_FORMAT == GetLastError());
        }
        if(hDllPython3X) {
            Util_GetPathDll(ctxMain->cfg.szPythonPath, NULL);
            strcat_s(ctxMain->cfg.szPythonPath, MAX_PATH, "python\\");
        }
    }
    // 3: Try locate Python by loading from the current path.
    if(0 == ctxMain->cfg.szPythonPath[0]) {
        for(i = 0; i < cszPYTHON_VERSIONS_SUPPORTED; i++) {
            hDllPython3X = LoadLibraryA(szPYTHON_VERSIONS_SUPPORTED[i]);
            if(hDllPython3X) { break; }
            fBitnessFail = fBitnessFail || (ERROR_BAD_EXE_FORMAT == GetLastError());
        }
        if(hDllPython3X) {
            Util_GetPathDll(ctxMain->cfg.szPythonPath, hDllPython3X);
        }
    }
    // 4: Python is not found?
    if(0 == ctxMain->cfg.szPythonPath[0]) {
        vmmprintf(
            fBitnessFail ?
            "PluginManager: Python initialization failed. Unable to load 32-bit Python. 64-bit required.\n" :
            "PluginManager: Python initialization failed. Python 3.6 or later not found.\n"
        );
        goto fail;
    }
    // 5: Load Python3.dll as well (i.e. prevent vmmpycplugin.dll to fetch the wrong one by mistake...)
    Util_GetPathDll(szPythonPath, hDllPython3X);
    strcat_s(szPythonPath, MAX_PATH, "python3.dll");
    hDllPython3 = LoadLibraryExA(szPythonPath, 0, LOAD_WITH_ALTERED_SEARCH_PATH);
    // 6: process 'special status' python plugin manager.
    hDllPyPlugin = LoadLibraryA("vmmpycplugin.dll");
    if(!hDllPyPlugin) {
        vmmprintf("PluginManager: Python plugin manager failed to load.\n");
        goto fail;
    }
    pfnInitializeVmmPlugin = (VOID(*)(PVMMDLL_PLUGIN_REGINFO))GetProcAddress(hDllPyPlugin, "InitializeVmmPlugin");
    if(!pfnInitializeVmmPlugin) {
        vmmprintf("PluginManager: Python plugin manager failed to load due to corrupt DLL.\n");
        goto fail;
    }
    PluginManager_Initialize_RegInfoInit(&ri, hDllPyPlugin);
    ri.hReservedDllPython3X = hDllPython3X;
    ri.hReservedDllPython3 = hDllPython3;
    pfnInitializeVmmPlugin(&ri);
    if(!PluginManager_ModuleExistsDll(hDllPyPlugin)) {
        vmmprintf("PluginManager: Python plugin manager failed to load due to internal error.\n");
        return;
    }
    vmmprintfv("PluginManager: Python plugin loaded.\n");
    if(hDllPython3X) { FreeLibrary(hDllPython3X); }
    return;
fail:
    if(hDllPyPlugin) { FreeLibrary(hDllPyPlugin); }
    if(hDllPython3X) { FreeLibrary(hDllPython3X); }
    if(hDllPython3) { FreeLibrary(hDllPython3); }
}

BOOL PluginManager_Initialize()
{
    VMMDLL_PLUGIN_REGINFO ri;
    CHAR szPath[MAX_PATH];
    DWORD i, cchPathBase;
    HANDLE hFindFile;
    WIN32_FIND_DATAA FindData;
    HMODULE hDLL;
    VOID(*pfnInitializeVmmPlugin)(_In_ PVMMDLL_PLUGIN_REGINFO pRegInfo);
    // 1: check if already initialized
    if(ctxVmm->PluginManager.FLinkAll) { return FALSE; }
    EnterCriticalSection(&ctxVmm->LockMaster);
    if(ctxVmm->PluginManager.FLinkAll) { goto fail; }
    // 2: set up root nodes of process plugin tree
    ctxVmm->PluginManager.Root = LocalAlloc(LMEM_ZEROINIT, sizeof(PLUGIN_TREE));
    ctxVmm->PluginManager.Proc = LocalAlloc(LMEM_ZEROINIT, sizeof(PLUGIN_TREE));
    if(!ctxVmm->PluginManager.Root || !ctxVmm->PluginManager.Proc) { goto fail; }
    // 3: process built-in modules
    for(i = 0; i < sizeof(g_pfnModulesAllInternal) / sizeof(PVOID); i++) {
        PluginManager_Initialize_RegInfoInit(&ri, NULL);
        g_pfnModulesAllInternal[i](&ri);
    }
    // 4: process dll modules
    Util_GetPathDll(szPath, NULL);
    cchPathBase = (DWORD)strnlen(szPath, MAX_PATH - 1);
    strcat_s(szPath, MAX_PATH, "plugins\\m_*.dll");
    hFindFile = FindFirstFileA(szPath, &FindData);
    if(hFindFile != INVALID_HANDLE_VALUE) {
        do {
            szPath[min(cchPathBase, MAX_PATH - 1)] = '\0';
            strcat_s(szPath, MAX_PATH, "plugins\\");
            strcat_s(szPath, MAX_PATH, FindData.cFileName);
            hDLL = LoadLibraryExA(szPath, 0, 0);
            if(!hDLL) { 
                vmmprintfvv("PluginManager: FAIL: Load DLL: '%s' - missing dependencies?\n", FindData.cFileName);
                continue;
            }
            vmmprintfvv("PluginManager: Load DLL: '%s'\n", FindData.cFileName);
            pfnInitializeVmmPlugin = (VOID(*)(PVMMDLL_PLUGIN_REGINFO))GetProcAddress(hDLL, "InitializeVmmPlugin");
            if(!pfnInitializeVmmPlugin) {
                vmmprintfvv("PluginManager: UnLoad DLL: '%s' - Plugin Entry Point not found.\n", FindData.cFileName);
                FreeLibrary(hDLL);
                continue;
            }
            PluginManager_Initialize_RegInfoInit(&ri, hDLL);
            pfnInitializeVmmPlugin(&ri);
            if(!PluginManager_ModuleExistsDll(hDLL)) {
                vmmprintfvv("PluginManager: UnLoad DLL: '%s' - not registered with plugin manager.\n", FindData.cFileName);
                FreeLibrary(hDLL);
                continue;
            }
        } while(FindNextFileA(hFindFile, &FindData));
    }
    // 5: process 'special status' python plugin manager.
    PluginManager_Initialize_Python();
    LeaveCriticalSection(&ctxVmm->LockMaster);
    return TRUE;
fail:
    LeaveCriticalSection(&ctxVmm->LockMaster);
    return FALSE;
}
