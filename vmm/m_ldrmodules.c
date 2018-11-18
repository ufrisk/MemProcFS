// m_ldrmodules.c : implementation of the ldrmodules built-in module.
//
// (c) Ulf Frisk, 2018
// Author: Ulf Frisk, pcileech@frizk.net
//
#include "m_ldrmodules.h"
#include "pluginmanager.h"
#include "vmm.h"
#include "vmmproc_windows.h"
#include "vmmvfs.h"
#include "util.h"

#define LDRMODULES_CACHE_TP_EAT     1
#define LDRMODULES_CACHE_TP_IAT     2
#define LDRMODULES_NUM_CACHE        8
typedef struct tdLDRMODULES_CACHE_ENTRY {
    DWORD dwCounter;
    DWORD dwPID;
    CHAR szDll[MAX_PATH];
    DWORD tp;
    DWORD cb;
    PBYTE pb;
} LDRMODULES_CACHE_ENTRY, *PLDRMODULES_CACHE_ENTRY;

/*
* CloseHandleModule : function as specified by the module manager. The module
* manager will call into this callback function whenever the module should be
* unloaded. Any private handle stored in phModulePrivate should be deallocated.
* -- phModulePrivate
*/
VOID LdrModule_CloseHandleModule(_Inout_opt_ PHANDLE phModulePrivate)
{
    DWORD i;
    PLDRMODULES_CACHE_ENTRY pCache;
    if(!phModulePrivate || !*phModulePrivate) { return; }
    pCache = (PLDRMODULES_CACHE_ENTRY)*phModulePrivate;
    for(i = 0; i < LDRMODULES_NUM_CACHE; i++) {
        if(pCache[i].pb) { LocalFree(pCache[i].pb); }
    }
    LocalFree(pCache);
    *phModulePrivate = NULL;
}

PLDRMODULES_CACHE_ENTRY LdrModule_GetCacheEntry(_In_ PVMMDLL_PLUGIN_CONTEXT ctx, _In_ LPSTR szDll, _In_ DWORD tp)
{
    DWORD i, iMin = 0, iMax = 0, iEmpty = (DWORD)-1;
    PLDRMODULES_CACHE_ENTRY e, pCache;
    pCache = (PLDRMODULES_CACHE_ENTRY)*ctx->phModulePrivate;
    // find existing cached item
    for(i = 0; i < LDRMODULES_NUM_CACHE; i++) {
        e = pCache + i;
        if((e->dwPID == ctx->dwPID) && (e->tp == tp) && e->pb && !strcmp(e->szDll, szDll)) {
            return e;
        }
        if(e->dwCounter < pCache[iMin].dwCounter) { iMin = i; }
        if(e->dwCounter > pCache[iMax].dwCounter) { iMax = i; }
        if(!e->pb) { iEmpty = i; }
    }
    // reserve and prepare new item
    i = (iEmpty < LDRMODULES_NUM_CACHE) ? iEmpty : iMin;
    e = pCache + i;
    if(e->pb) { LocalFree(e->pb); }
    ZeroMemory(e, sizeof(LDRMODULES_CACHE_ENTRY));
    e->dwCounter = pCache[iMax].dwCounter + 1;
    e->dwPID = ctx->dwPID;
    e->tp = tp;
    strncpy_s(e->szDll, MAX_PATH, szDll, MAX_PATH);
    return e;
}

#define LDRMODULES_MAX_IATEAT   0x10000

PLDRMODULES_CACHE_ENTRY LdrModule_GetEAT(_In_ PVMMDLL_PLUGIN_CONTEXT ctx, _In_ PVMM_MODULEMAP_ENTRY pModule)
{
    DWORD i, o, cEATs;
    PVMMPROC_WINDOWS_EAT_ENTRY pEATs = NULL;
    PLDRMODULES_CACHE_ENTRY pCacheEntry;
    // 1: retrieve cache
    pCacheEntry = LdrModule_GetCacheEntry(ctx, pModule->szName, LDRMODULES_CACHE_TP_EAT);
    if(pCacheEntry->pb) { return pCacheEntry; }
    // 2: retrieve exported functions
    cEATs = LDRMODULES_MAX_IATEAT;
    pEATs = LocalAlloc(0, LDRMODULES_MAX_IATEAT * sizeof(VMMPROC_WINDOWS_EAT_ENTRY));
    if(!pEATs) { goto fail; }
    VmmProcWindows_PE_LoadEAT_DisplayBuffer(ctx->pProcess, pModule, pEATs, &cEATs);
    if(!cEATs) { goto fail; }
    // 3: fill "display buffer"
    pCacheEntry->cb = cEATs * 64 + 1;
    pCacheEntry->pb = LocalAlloc(0, pCacheEntry->cb);
    if(!pCacheEntry->pb) { goto fail; }
    for(i = 0, o = 0; i < cEATs; i++) {
        o += snprintf(
            pCacheEntry->pb + o,
            pCacheEntry->cb - o,
            "%04x %016llx %-40.40s \n",     // 64 bytes (chars) / line (function)
            (WORD)i,
            pModule->BaseAddress + pEATs[i].vaFunctionOffset,
            pEATs[i].szFunction
        );
    }
    pCacheEntry->cb = o;
    LocalFree(pEATs);
    return pCacheEntry;
fail:
    LocalFree(pEATs);
    return NULL;
}

PLDRMODULES_CACHE_ENTRY LdrModule_GetIAT(_In_ PVMMDLL_PLUGIN_CONTEXT ctx, _In_ PVMM_MODULEMAP_ENTRY pModule)
{
    DWORD i, o, cIATs;
    PVMMPROC_WINDOWS_IAT_ENTRY pIATs = NULL;
    PLDRMODULES_CACHE_ENTRY pCacheEntry;
    // 1: retrieve cache
    pCacheEntry = LdrModule_GetCacheEntry(ctx, pModule->szName, LDRMODULES_CACHE_TP_IAT);
    if(pCacheEntry->pb) { return pCacheEntry; }
    // 2: retrieve exported functions
    cIATs = LDRMODULES_MAX_IATEAT;
    pIATs = LocalAlloc(0, LDRMODULES_MAX_IATEAT * sizeof(VMMPROC_WINDOWS_IAT_ENTRY));
    if(!pIATs) { goto fail; }
    VmmProcWindows_PE_LoadIAT_DisplayBuffer(ctx->pProcess, pModule, pIATs, &cIATs);
    if(!cIATs) { goto fail; }
    // 3: fill "display buffer"
    pCacheEntry->cb = cIATs * 128 + 1;
    pCacheEntry->pb = LocalAlloc(0, pCacheEntry->cb);
    if(!pCacheEntry->pb) { goto fail; }
    for(i = 0, o = 0; i < cIATs; i++) {
        o += snprintf(
            pCacheEntry->pb + o,
            pCacheEntry->cb - o,
            "%04x %016llx %-40.40s %-64.64s\n",     // 128 bytes (chars) / line (function)
            (WORD)i,
            pIATs[i].vaFunction,
            pIATs[i].szFunction,
            pIATs[i].szModule
        );
    }
    pCacheEntry->cb = o;
    LocalFree(pIATs);
    return pCacheEntry;
fail:
    LocalFree(pIATs);
    return NULL;
}

/*
* Read : function as specified by the module manager. The module manager will
* call into this callback function whenever a read shall occur from a "file".
* -- ctx
* -- pb
* -- cb
* -- pcbRead
* -- cbOffset
* -- return
*/
NTSTATUS LdrModules_Read(_In_ PVMMDLL_PLUGIN_CONTEXT ctx, _Out_ LPVOID pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset)
{
    DWORD i, cbBuffer;
    BYTE pbBuffer[0x800];
    CHAR _szBuf[MAX_PATH] = { 0 };
    LPSTR szPath1, szPath2;
    PLDRMODULES_CACHE_ENTRY pCacheEntry;
    PVMM_PROCESS pProcess = (PVMM_PROCESS)ctx->pProcess;
    Util_PathSplit2(ctx->szPath, _szBuf, &szPath1, &szPath2);
    if(szPath1[0] && szPath2[0]) {
        for(i = 0; i < pProcess->cModuleMap; i++) {
            if(0 == strncmp(szPath1, pProcess->pModuleMap[i].szName, MAX_PATH)) {
                if(!_stricmp(szPath2, "base")) {
                    return Util_VfsReadFile_FromQWORD(pProcess->pModuleMap[i].BaseAddress, pb, cb, pcbRead, cbOffset, FALSE);
                }
                if(!_stricmp(szPath2, "entry")) {
                    return Util_VfsReadFile_FromQWORD(pProcess->pModuleMap[i].EntryPoint, pb, cb, pcbRead, cbOffset, FALSE);
                }
                if(!_stricmp(szPath2, "size")) {
                    return Util_VfsReadFile_FromDWORD(pProcess->pModuleMap[i].SizeOfImage, pb, cb, pcbRead, cbOffset, FALSE);
                }
                if(!_stricmp(szPath2, "directories")) {
                    VmmProcWindows_PE_DIRECTORY_DisplayBuffer(ctx->pProcess, pProcess->pModuleMap + i, pbBuffer, 0x400, &cbBuffer, NULL);
                    return Util_VfsReadFile_FromPBYTE(pbBuffer, cbBuffer, pb, cb, pcbRead, cbOffset);
                }
                if(!_stricmp(szPath2, "export")) {
                    pCacheEntry = LdrModule_GetEAT(ctx, pProcess->pModuleMap + i);
                    if(!pCacheEntry) { return VMMDLL_STATUS_FILE_INVALID; }
                    return Util_VfsReadFile_FromPBYTE(pCacheEntry->pb, pCacheEntry->cb, pb, cb, pcbRead, cbOffset);
                }
                if(!_stricmp(szPath2, "import")) {
                    pCacheEntry = LdrModule_GetIAT(ctx, pProcess->pModuleMap + i);
                    if(!pCacheEntry) { return VMMDLL_STATUS_FILE_INVALID; }
                    return Util_VfsReadFile_FromPBYTE(pCacheEntry->pb, pCacheEntry->cb, pb, cb, pcbRead, cbOffset);
                }
                if(!_stricmp(szPath2, "sections")) {
                    VmmProcWindows_PE_SECTION_DisplayBuffer(ctx->pProcess, pProcess->pModuleMap + i, pbBuffer, 0x800, &cbBuffer, NULL);
                    return Util_VfsReadFile_FromPBYTE(pbBuffer, cbBuffer, pb, cb, pcbRead, cbOffset);
                }
                return VMMDLL_STATUS_FILE_INVALID;
            }
        }
    }
    return VMMDLL_STATUS_FILE_INVALID;
}

/*
* List : function as specified by the module manager. The module manager will
* call into this callback function whenever a list directory shall occur from
* the given module.
* -- ctx
* -- pFileList
* -- return
*/
BOOL LdrModules_List(_In_ PVMMDLL_PLUGIN_CONTEXT ctx, _Inout_ PHANDLE pFileList)
{
    DWORD i;
    CHAR _szBuf[MAX_PATH] = { 0 };
    LPSTR szPath1, szPath2;
    PVMM_PROCESS pProcess = (PVMM_PROCESS)ctx->pProcess;
    // modules root directory -> add directory per DLL
    if(!ctx->szPath[0]) {
        for(i = 0; i < pProcess->cModuleMap; i++) {
            VMMDLL_VfsList_AddDirectory(pFileList, pProcess->pModuleMap[i].szName);
        }
        return TRUE;
    }
    // individual module directory -> list files
    Util_PathSplit2(ctx->szPath, _szBuf, &szPath1, &szPath2);
    if(!szPath2[0]) {
        for(i = 0; i < pProcess->cModuleMap; i++) {
            if(0 == strncmp(szPath1, pProcess->pModuleMap[i].szName, MAX_PATH)) {
                VmmProcWindows_PE_SetSizeSectionIATEAT_DisplayBuffer(ctx->pProcess, pProcess->pModuleMap + i);
                VMMDLL_VfsList_AddFile(pFileList, "base", 16);
                VMMDLL_VfsList_AddFile(pFileList, "entry", 16);
                VMMDLL_VfsList_AddFile(pFileList, "size", 8);
                VMMDLL_VfsList_AddFile(pFileList, "directories", 864);
                VMMDLL_VfsList_AddFile(pFileList, "export", pProcess->pModuleMap[i].cbDisplayBufferEAT);
                VMMDLL_VfsList_AddFile(pFileList, "import", pProcess->pModuleMap[i].cbDisplayBufferIAT);
                VMMDLL_VfsList_AddFile(pFileList, "sections", pProcess->pModuleMap[i].cbDisplayBufferSections);
                return TRUE;
            }
        }
        return FALSE;
    }
    return FALSE;
}

/*
* Initialization function. The module manager shall call into this function
* when the module shall be initialized. If the module wish to initialize it
* shall call the supplied pfnPluginManager_Register function.
* NB! the module does not have to register itself - for example if the target
* operating system or architecture is unsupported.
* -- pPluginRegInfo
*/
VOID M_LdrModules_Initialize(_Inout_ PVMMDLL_PLUGIN_REGINFO pPluginRegInfo)
{
    PLDRMODULES_CACHE_ENTRY pCache;
    if(0 == (pPluginRegInfo->fTargetSystem & VMM_TARGET_WINDOWS_X64)) { return; }
    pCache = LocalAlloc(LMEM_ZEROINIT, LDRMODULES_NUM_CACHE * sizeof(LDRMODULES_CACHE_ENTRY));
    if(!pCache) { return; }
    strcpy_s(pPluginRegInfo->reg_info.szModuleName, 32, "modules");             // module name
    pPluginRegInfo->reg_info.fProcessModule = TRUE;                             // module shows in process directory
    pPluginRegInfo->reg_info.hModulePrivate = pCache;                           // module private handle (for cache)
    pPluginRegInfo->reg_fn.pfnList = LdrModules_List;                           // List function supported
    pPluginRegInfo->reg_fn.pfnRead = LdrModules_Read;                           // Read function supported
    pPluginRegInfo->reg_fn.pfnCloseHandleModule = LdrModule_CloseHandleModule;  // Close module private handle supported
    pPluginRegInfo->pfnPluginManager_Register(pPluginRegInfo);
}
