// pluginmanager.h : implementation of the plugin manager for memory process file system plugins.
//
// (c) Ulf Frisk, 2018-2019
// Author: Ulf Frisk, pcileech@frizk.net
//
#include "pluginmanager.h"
#include "statistics.h"
#include "util.h"
#include "vmm.h"
#include "vmmdll.h"
#include "m_ldrmodules.h"
#include "m_pedump.h"
#include "m_status.h"
#include "m_virt2phys.h"

//
// This file contains functionality related to keeping track of plugins, both
// internal built-in ones and loadable plugins in the form of compliant DLLs.
//
// The functionality and data structures are at this moment single-threaded in
// this implementation and should be protected by a lock (ctxVmm->MasterLock).
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

typedef struct tdPLUGIN_LISTENTRY {
    struct tdPLUGIN_LISTENTRY *FLink;
    HMODULE hDLL;
    CHAR szModuleName[32];
    BOOL fRootModule;
    BOOL fProcessModule;
    BOOL(*pfnList)(_In_ PVMMDLL_PLUGIN_CONTEXT ctx, _Inout_ PHANDLE pFileList);
    NTSTATUS(*pfnRead)(_In_ PVMMDLL_PLUGIN_CONTEXT ctx, _Out_ LPVOID pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset);
    NTSTATUS(*pfnWrite)(_In_ PVMMDLL_PLUGIN_CONTEXT ctx, _In_ LPVOID pb, _In_ DWORD cb, _Out_ PDWORD pcbWrite, _In_ QWORD cbOffset);
    VOID(*pfnNotify)(_In_ DWORD fEvent, _In_opt_ PVOID pvEvent, _In_opt_ DWORD cbEvent);
    VOID(*pfnClose)();
} PLUGIN_LISTENTRY, *PPLUGIN_LISTENTRY;

// ----------------------------------------------------------------------------
// MODULES CORE FUNCTIONALITY - IMPLEMENTATION BELOW:
// ----------------------------------------------------------------------------

VOID PluginManager_ContextInitialize(_Out_ PVMMDLL_PLUGIN_CONTEXT ctx, PPLUGIN_LISTENTRY pModule, _In_opt_ PVMM_PROCESS pProcess, _In_ LPSTR szPath)
{
    ctx->magic = VMMDLL_PLUGIN_CONTEXT_MAGIC;
    ctx->wVersion = VMMDLL_PLUGIN_CONTEXT_VERSION;
    ctx->wSize = sizeof(VMMDLL_PLUGIN_CONTEXT);
    ctx->dwPID = (pProcess ? pProcess->dwPID : (DWORD)-1);
    ctx->pProcess = pModule->hDLL ? NULL : pProcess;
    ctx->szModule = pModule->szModuleName;
    ctx->szPath = szPath;
}

VOID PluginManager_ListAll(_In_opt_ PVMM_PROCESS pProcess, _Inout_ PHANDLE pFileList)
{
    PPLUGIN_LISTENTRY pModule = (PPLUGIN_LISTENTRY)ctxVmm->pVmmVfsModuleList;
    while(pModule) {
        if((pProcess && pModule->fProcessModule) || (!pProcess && pModule->fRootModule)) {
            VMMDLL_VfsList_AddDirectory(pFileList, pModule->szModuleName);
        }
        pModule = pModule->FLink;
    }
}

BOOL PluginManager_List(_In_opt_ PVMM_PROCESS pProcess, _In_ LPSTR szModule, _In_ LPSTR szPath, _Inout_ PHANDLE pFileList)
{
    QWORD tmStart = Statistics_CallStart();
    BOOL result;
    VMMDLL_PLUGIN_CONTEXT ctx;
    PPLUGIN_LISTENTRY pModule = (PPLUGIN_LISTENTRY)ctxVmm->pVmmVfsModuleList;
    while(pModule) {
        if(!((pProcess && pModule->fProcessModule) || (!pProcess && pModule->fRootModule))) {
            pModule = pModule->FLink;
            continue;
        }
        if(pModule->pfnList && !_stricmp(szModule, pModule->szModuleName)) {
            PluginManager_ContextInitialize(&ctx, pModule, pProcess, (szPath ? szPath : ""));
            result = pModule->pfnList(&ctx, pFileList);
            Statistics_CallEnd(STATISTICS_ID_PluginManager_List, tmStart);
            return result;
        }
        pModule = pModule->FLink;
    }
    Statistics_CallEnd(STATISTICS_ID_PluginManager_List, tmStart);
    return FALSE;
}

NTSTATUS PluginManager_Read(_In_opt_ PVMM_PROCESS pProcess, _In_ LPSTR szModule, _In_ LPSTR szPath, _Out_ LPVOID pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset)
{
    QWORD tmStart = Statistics_CallStart();
    NTSTATUS nt;
    VMMDLL_PLUGIN_CONTEXT ctx;
    PPLUGIN_LISTENTRY pModule = (PPLUGIN_LISTENTRY)ctxVmm->pVmmVfsModuleList;
    while(pModule) {
        if(!((pProcess && pModule->fProcessModule) || (!pProcess && pModule->fRootModule))) {
            pModule = pModule->FLink;
            continue;
        }
        if(pModule->pfnRead && !_stricmp(szModule, pModule->szModuleName)) {
            PluginManager_ContextInitialize(&ctx, pModule, pProcess, (szPath ? szPath : ""));
            nt = pModule->pfnRead(&ctx, pb, cb, pcbRead, cbOffset);
            Statistics_CallEnd(STATISTICS_ID_PluginManager_Read, tmStart);
            return nt;
        }
        pModule = pModule->FLink;
    }
    Statistics_CallEnd(STATISTICS_ID_PluginManager_Read, tmStart);
    return VMMDLL_STATUS_FILE_INVALID;
}

NTSTATUS PluginManager_Write(_In_opt_ PVMM_PROCESS pProcess, _In_ LPSTR szModule, _In_ LPSTR szPath, _In_ LPVOID pb, _In_ DWORD cb, _Out_ PDWORD pcbWrite, _In_ QWORD cbOffset)
{
    QWORD tmStart = Statistics_CallStart();
    NTSTATUS nt;
    VMMDLL_PLUGIN_CONTEXT ctx;
    PPLUGIN_LISTENTRY pModule = (PPLUGIN_LISTENTRY)ctxVmm->pVmmVfsModuleList;
    while(pModule) {
        if(!((pProcess && pModule->fProcessModule) || (!pProcess && pModule->fRootModule))) {
            pModule = pModule->FLink;
            continue;
        }
        if(pModule->pfnWrite && !_stricmp(szModule, pModule->szModuleName)) {
            PluginManager_ContextInitialize(&ctx, pModule, pProcess, (szPath ? szPath : ""));
            nt = pModule->pfnWrite(&ctx, pb, cb, pcbWrite, cbOffset);
            Statistics_CallEnd(STATISTICS_ID_PluginManager_Write, tmStart);
            return nt;
        }
        pModule = pModule->FLink;
    }
    Statistics_CallEnd(STATISTICS_ID_PluginManager_Write, tmStart);
    return VMMDLL_STATUS_FILE_INVALID;
}

BOOL PluginManager_Notify(_In_ DWORD fEvent, _In_opt_ PVOID pvEvent, _In_opt_ DWORD cbEvent)
{
    QWORD tmStart = Statistics_CallStart();
    PPLUGIN_LISTENTRY pModule = (PPLUGIN_LISTENTRY)ctxVmm->pVmmVfsModuleList;
    while(pModule) {
        if(pModule->pfnNotify) {
            pModule->pfnNotify(fEvent, pvEvent, cbEvent);
        }
        pModule = pModule->FLink;
    }
    Statistics_CallEnd(STATISTICS_ID_PluginManager_Notify, tmStart);
    return TRUE;
}

BOOL PluginManager_ModuleExists(_In_opt_ HMODULE hDLL, _In_opt_ LPSTR szModule) {
    PPLUGIN_LISTENTRY pModule = (PPLUGIN_LISTENTRY)ctxVmm->pVmmVfsModuleList;
    while(pModule) {
        if(hDLL && (hDLL == pModule->hDLL)) { return TRUE; }
        if(szModule && !_stricmp(szModule, pModule->szModuleName)) { return TRUE; }
        pModule = pModule->FLink;
    }
    return FALSE;
}

BOOL PluginManager_Register(_In_ PVMMDLL_PLUGIN_REGINFO pRegInfo)
{
    const LPSTR RESERVED_NAMES[] = { "name", "pid", "pmem", "map", "pml4", "vmem", "pml4-user", "win-eprocess", "win-entry", "win-peb", "win-peb32", "win-modules" };
    PPLUGIN_LISTENTRY pModule;
    DWORD i;
    // 1: tests if module is valid
    if(!pRegInfo || (pRegInfo->magic != VMMDLL_PLUGIN_REGINFO_MAGIC) || (pRegInfo->wVersion > VMMDLL_PLUGIN_REGINFO_VERSION)) { return FALSE; }
    if(!pRegInfo->reg_fn.pfnList || !pRegInfo->reg_info.szModuleName[0] || (strlen(pRegInfo->reg_info.szModuleName) > 31)) { return FALSE; }
    if(PluginManager_ModuleExists(NULL, pRegInfo->reg_info.szModuleName)) { return FALSE; }
    pModule = (PPLUGIN_LISTENTRY)LocalAlloc(LMEM_ZEROINIT, sizeof(PLUGIN_LISTENTRY));
    if(!pModule) { return FALSE; }
    if(!pRegInfo->reg_info.fRootModule && !pRegInfo->reg_info.fProcessModule) { return FALSE; }
    for(i = 0; i < (sizeof(RESERVED_NAMES) / sizeof(LPSTR)); i++) {
        if(!strcmp(pRegInfo->reg_info.szModuleName, RESERVED_NAMES[i])) { return FALSE; }
    }
    // 2: register module
    pModule->hDLL = pRegInfo->hDLL;
    strncpy_s(pModule->szModuleName, 32, pRegInfo->reg_info.szModuleName, 32);
    pModule->fRootModule = pRegInfo->reg_info.fRootModule;
    pModule->fProcessModule = pRegInfo->reg_info.fProcessModule;
    pModule->pfnList = pRegInfo->reg_fn.pfnList;
    pModule->pfnRead = pRegInfo->reg_fn.pfnRead;
    pModule->pfnWrite = pRegInfo->reg_fn.pfnWrite;
    pModule->pfnNotify = pRegInfo->reg_fn.pfnNotify;
    pModule->pfnClose = pRegInfo->reg_fn.pfnClose;
    vmmprintfv("PluginManager: Loaded %s module '%s'.\n", (pModule->hDLL ? "native" : "built-in"), pModule->szModuleName);
    pModule->FLink = (PPLUGIN_LISTENTRY)ctxVmm->pVmmVfsModuleList;
    ctxVmm->pVmmVfsModuleList = pModule;
    return TRUE;
}

VOID PluginManager_Close()
{
    PPLUGIN_LISTENTRY pm;
    while((pm = (PPLUGIN_LISTENTRY)ctxVmm->pVmmVfsModuleList)) {
        // 1: Detach current module list entry from list
        ctxVmm->pVmmVfsModuleList = pm->FLink;
        // 2: Close module callback
        if(pm->pfnClose) {
            pm->pfnClose();
        }
        // 3: FreeLibrary (if last module belonging to specific Library)
        if(pm->hDLL && !PluginManager_ModuleExists(pm->hDLL, NULL)) { FreeLibrary(pm->hDLL); }
        // 4: LocalFree this ListEntry
        LocalFree(pm);
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
}

VOID PluginManager_Initialize_Python()
{
    LPSTR szPYTHON_VERSIONS_SUPPORTED[] = { "python36.dll", "python37.dll", "python38.dll" };
    DWORD cszPYTHON_VERSIONS_SUPPORTED = (sizeof(szPYTHON_VERSIONS_SUPPORTED) / sizeof(LPSTR));
    DWORD i;
    VMMDLL_PLUGIN_REGINFO ri;
    CHAR szPythonPath[MAX_PATH];
    HMODULE hDllPython3X = NULL, hDllPython3 = NULL, hDllPyPlugin = NULL;
    VOID(*pfnInitializeVmmPlugin)(_In_ PVMMDLL_PLUGIN_REGINFO pRegInfo);
    // 1: Locate Python by trying user-defined path
    if(ctxMain->cfg.szPythonPath[0]) {
        for(i = 0; i < cszPYTHON_VERSIONS_SUPPORTED; i++) {
            ZeroMemory(szPythonPath, _countof(szPythonPath));
            strcpy_s(szPythonPath, _countof(szPythonPath), ctxMain->cfg.szPythonPath);
            strcat_s(szPythonPath, _countof(szPythonPath), "\\");
            strcat_s(szPythonPath, _countof(szPythonPath), szPYTHON_VERSIONS_SUPPORTED[i]);
            hDllPython3X = LoadLibraryExA(szPythonPath, 0, LOAD_WITH_ALTERED_SEARCH_PATH);
            if(hDllPython3X) { break; }
        }
        if(!hDllPython3X) {
            ZeroMemory(ctxMain->cfg.szPythonPath, _countof(ctxMain->cfg.szPythonPath));
            vmmprintf("PluginManager: Python initialization failed. Python 3.6 or later not found on user specified path.\n");
            return;
        }
    }
    // 2: Try locate Python by checking the python36 sub-directory relative to the current executable (.exe).
    if(0 == ctxMain->cfg.szPythonPath[0]) {
        for(i = 0; i < cszPYTHON_VERSIONS_SUPPORTED; i++) {
            ZeroMemory(szPythonPath, _countof(szPythonPath));
            Util_GetPathDll(szPythonPath, NULL);
            strcat_s(szPythonPath, _countof(szPythonPath), "python\\");
            strcat_s(szPythonPath, _countof(szPythonPath), szPYTHON_VERSIONS_SUPPORTED[i]);
            hDllPython3X = LoadLibraryExA(szPythonPath, 0, LOAD_WITH_ALTERED_SEARCH_PATH);
            if(hDllPython3X) { break; }
        }
        if(hDllPython3X) {
            Util_GetPathDll(ctxMain->cfg.szPythonPath, NULL);
            strcat_s(ctxMain->cfg.szPythonPath, _countof(ctxMain->cfg.szPythonPath), "python\\");
        }
    }
    // 3: Try locate Python by loading from the current path.
    if(0 == ctxMain->cfg.szPythonPath[0]) {
        for(i = 0; i < cszPYTHON_VERSIONS_SUPPORTED; i++) {
            hDllPython3X = LoadLibraryA(szPYTHON_VERSIONS_SUPPORTED[i]);
            if(hDllPython3X) { break; }
        }
        if(hDllPython3X) {
            Util_GetPathDll(ctxMain->cfg.szPythonPath, hDllPython3X);
        }
    }
    // 4: Python is not found?
    if(0 == ctxMain->cfg.szPythonPath[0]) {
        vmmprintf("PluginManager: Python initialization failed. Python 3.6 or later not found.\n");
        goto fail;
    }
    // 5: Load Python3.dll as well (i.e. prevent vmmpycplugin.dll to fetch the wrong one by mistake...)
    Util_GetPathDll(szPythonPath, hDllPython3X);
    strcat_s(szPythonPath, _countof(szPythonPath), "python3.dll");
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
    if(!PluginManager_ModuleExists(hDllPyPlugin, NULL)) {
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
    DWORD cchPathBase;
    HANDLE hFindFile;
    WIN32_FIND_DATAA FindData;
    HMODULE hDLL;
    VOID(*pfnInitializeVmmPlugin)(_In_ PVMMDLL_PLUGIN_REGINFO pRegInfo);
    if(ctxVmm->pVmmVfsModuleList) { return FALSE; } // already initialized
    ZeroMemory(&ri, sizeof(VMMDLL_PLUGIN_REGINFO));
    // 1: process built-in modules
    EnterCriticalSection(&ctxVmm->MasterLock);
    PluginManager_Initialize_RegInfoInit(&ri, NULL);
    M_Virt2Phys_Initialize(&ri);
    PluginManager_Initialize_RegInfoInit(&ri, NULL);
    M_LdrModules_Initialize(&ri);
    PluginManager_Initialize_RegInfoInit(&ri, NULL);
    M_Status_Initialize(&ri);
    PluginManager_Initialize_RegInfoInit(&ri, NULL);
    M_PEDump_Initialize(&ri);
    // 2: process dll modules
    Util_GetPathDll(szPath, NULL);
    cchPathBase = (DWORD)strnlen(szPath, _countof(szPath) - 1);
    strcat_s(szPath, _countof(szPath), "plugins\\m_*.dll");
    hFindFile = FindFirstFileA(szPath, &FindData);
    if(hFindFile != INVALID_HANDLE_VALUE) {
        do {
            szPath[cchPathBase] = '\0';
            strcat_s(szPath, _countof(szPath), "plugins\\");
            strcat_s(szPath, _countof(szPath), FindData.cFileName);
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
            if(!PluginManager_ModuleExists(hDLL, NULL)) {
                vmmprintfvv("PluginManager: UnLoad DLL: '%s' - not registered with plugin manager.\n", FindData.cFileName);
                FreeLibrary(hDLL);
                continue;
            }
        } while(FindNextFileA(hFindFile, &FindData));
    }
    // 3: process 'special status' python plugin manager.
    PluginManager_Initialize_Python();
    LeaveCriticalSection(&ctxVmm->MasterLock);
    return TRUE;
}
