// m_files_modules.c : implementation of the 'files/modules' built-in module.
//
// (c) Ulf Frisk, 2019-2021
// Author: Ulf Frisk, pcileech@frizk.net
//
#include "pluginmanager.h"
#include "vmm.h"
#include "pe.h"
#include "util.h"

typedef struct tdFILEMODULES_FILENTRY {
    DWORD cb;
    DWORD dwNameHash;
    QWORD vaBase;
    CHAR uszName[MAX_PATH];
} FILEMODULES_FILENTRY, *PFILEMODULES_FILENTRY;

typedef struct tdOBFILEMODULES_MODULECACHE {
    OB ObHdr;
    DWORD dwPID;
    DWORD cFiles;
    FILEMODULES_FILENTRY File[0];
} OBFILEMODULES_MODULECACHE, *POBFILEMODULES_MODULECACHE;

/*
* CALLER DECREF: return
* -- ctx
* -- pFileList
* -- return
*/
POBFILEMODULES_MODULECACHE M_FileModules_GetModuleCache(_In_ PVMMDLL_PLUGIN_CONTEXT ctx)
{
    BOOL result = FALSE;
    DWORD iModule, cVad = 0;
    PVMMOB_MAP_MODULE pObModuleMap = NULL;
    POBFILEMODULES_MODULECACHE pObCache = NULL;
    POB_SET pObSet_ModuleBaseAddresses = NULL;
    PVMM_PROCESS pProcess = (PVMM_PROCESS)ctx->pProcess;
    DWORD cbPageRead;
    BYTE pbPage[0x1000];
    // 1: get cached entries
    pObCache = ObContainer_GetOb(pProcess->Plugin.pObCPeDumpDirCache);
    // 2: set up cache (if needed)
    if(!pObCache) {
        if(!VmmMap_GetModule(pProcess, &pObModuleMap)) { goto fail; }
        pObCache = Ob_Alloc('MPeD', LMEM_ZEROINIT, sizeof(OBFILEMODULES_MODULECACHE) + ((QWORD)pObModuleMap->cMap + cVad) * sizeof(FILEMODULES_FILENTRY), NULL, NULL);
        if(!pObCache) { goto fail; }
        // Load module bases (PE header) memory into cache with one single call.
        if(!(pObSet_ModuleBaseAddresses = ObSet_New())) { goto fail; }
        for(iModule = 0; iModule < pObModuleMap->cMap; iModule++) {
            ObSet_Push(pObSet_ModuleBaseAddresses, pObModuleMap->pMap[iModule].vaBase);
        }
        VmmCachePrefetchPages(pProcess, pObSet_ModuleBaseAddresses, 0);
        // Build file listing information cache (only from in-cache items).
        ZeroMemory(pbPage, 0x1000);
        for(iModule = 0; iModule < pObModuleMap->cMap; iModule++) {
            VmmReadEx(pProcess, pObModuleMap->pMap[iModule].vaBase, pbPage, 0x1000, &cbPageRead, VMM_FLAG_FORCECACHE_READ);
            if(cbPageRead != 0x1000) {
                vmmprintfvv_fn("Skipping module: '%s' - paged/invalid?\n", pObModuleMap->pMap[iModule].uszText);
                continue;
            }
            pObCache->File[pObCache->cFiles].cb = PE_FileRaw_Size(pProcess, pObModuleMap->pMap[iModule].vaBase, pbPage);
            if(!pObCache->File[pObCache->cFiles].cb) {
                vmmprintfvv_fn("Skipping module: '%s' - paged/invalid?\n", pObModuleMap->pMap[iModule].uszText);
                continue;
            }
            strncpy_s(pObCache->File[pObCache->cFiles].uszName, MAX_PATH, pObModuleMap->pMap[iModule].uszText, _TRUNCATE);
            pObCache->cFiles++;
        }
        ObContainer_SetOb(pProcess->Plugin.pObCPeDumpDirCache, pObCache);
    }
fail:
    Ob_DECREF(pObModuleMap);
    Ob_DECREF(pObSet_ModuleBaseAddresses);
    return pObCache;    // CALLER DECREF
}

/*
* List : function as specified by the module manager. The module manager will
* call into this callback function whenever a list directory shall occur from
* the given module.
* -- ctx
* -- pFileList
* -- return
*/
_Success_(return)
BOOL M_FileModules_List(_In_ PVMMDLL_PLUGIN_CONTEXT ctx, _Inout_ PHANDLE pFileList)
{
    BOOL result = FALSE;
    DWORD iModule;
    POBFILEMODULES_MODULECACHE pObCache = NULL;
    if(ctx->uszPath[0]) { return FALSE; }
    if(!(pObCache = M_FileModules_GetModuleCache(ctx))) { return FALSE; }
    for(iModule = 0; iModule < pObCache->cFiles; iModule++) {
        VMMDLL_VfsList_AddFile(pFileList, pObCache->File[iModule].uszName, pObCache->File[iModule].cb, NULL);
    }
    Ob_DECREF(pObCache);
    return TRUE;
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
NTSTATUS M_FileModules_Read(_In_ PVMMDLL_PLUGIN_CONTEXT ctx, _Out_writes_to_(cb, *pcbRead) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset)
{
    BOOL f;
    PVMM_MAP_MODULEENTRY pModule = NULL;
    PVMMOB_MAP_MODULE pObModuleMap = NULL;
    *pcbRead = 0;
    f = (cbOffset <= 0x02000000) &&
        VmmMap_GetModuleEntryEx((PVMM_PROCESS)ctx->pProcess, 0, ctx->uszPath, &pObModuleMap, &pModule) &&
        PE_FileRaw_Read(ctx->pProcess, pModule->vaBase, pb, cb, pcbRead, (DWORD)cbOffset);
    Ob_DECREF_NULL(&pObModuleMap);
    return f ? VMMDLL_STATUS_SUCCESS : VMMDLL_STATUS_FILE_INVALID;
}

/*
* Write : function as specified by the module manager. The module manager will
* call into this callback function whenever a write shall occur to a "file".
* NB! writes to memory mapped re-constructed PE files are very dangerous and
* is not recommended (even if possible). PE files are usually loaded as IMAGE
* and are shared between all processes. A write in one process is most likely
* to affect all processes with this specific module loaded!
* Writing may crash the target system!
* -- ctx
* -- pb
* -- cb
* -- pcbWrite
* -- cbOffset
* -- return
*/
NTSTATUS M_FileModules_Write(_In_ PVMMDLL_PLUGIN_CONTEXT ctx, _In_reads_(cb) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbWrite, _In_ QWORD cbOffset)
{
    BOOL f;
    PVMM_MAP_MODULEENTRY pModule = NULL;
    PVMMOB_MAP_MODULE pObModuleMap = NULL;
    *pcbWrite = 0;
    f = (cbOffset <= 0x02000000) &&
        VmmMap_GetModuleEntryEx((PVMM_PROCESS)ctx->pProcess, 0, ctx->uszPath, &pObModuleMap, &pModule) &&
        PE_FileRaw_Write(ctx->pProcess, pModule->vaBase, pb, cb, pcbWrite, (DWORD)cbOffset);
    Ob_DECREF_NULL(&pObModuleMap);
    return f ? VMMDLL_STATUS_SUCCESS : VMMDLL_STATUS_FILE_INVALID;
}

/*
* Initialization function. The module manager shall call into this function
* when the module shall be initialized. If the module wish to initialize it
* shall call the supplied pfnPluginManager_Register function.
* NB! the module does not have to register itself - for example if the target
* operating system or architecture is unsupported.
* -- pPluginRegInfo
*/
VOID M_FileModules_Initialize(_Inout_ PVMMDLL_PLUGIN_REGINFO pRI)
{
    if((pRI->magic != VMMDLL_PLUGIN_REGINFO_MAGIC) || (pRI->wVersion != VMMDLL_PLUGIN_REGINFO_VERSION)) { return; }
    if((pRI->tpSystem != VMM_SYSTEM_WINDOWS_X64) && (pRI->tpSystem != VMM_SYSTEM_WINDOWS_X86)) { return; }
    strcpy_s(pRI->reg_info.uszPathName, 128, "\\files\\modules");       // module name
    pRI->reg_info.fProcessModule = TRUE;                                // module shows in process directory
    pRI->reg_fn.pfnList = M_FileModules_List;                           // List function supported
    pRI->reg_fn.pfnRead = M_FileModules_Read;                           // Read function supported
    pRI->reg_fn.pfnWrite = M_FileModules_Write;                         // Write function supported
    pRI->pfnPluginManager_Register(pRI);
}
