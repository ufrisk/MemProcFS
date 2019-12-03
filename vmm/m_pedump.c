// m_pedump.c : implementation of the pedump built-in module.
//
// (c) Ulf Frisk, 2019
// Author: Ulf Frisk, pcileech@frizk.net
//
#include "m_modules.h"
#include "pluginmanager.h"
#include "vmm.h"
#include "pe.h"

typedef struct tdPEDUMP_FILENTRY {
    DWORD cb;
    WCHAR wszName[MAX_PATH];
} PEDUMP_FILENTRY;

typedef struct tdOBPEDUMP_MODULECACHE {
    OB ObHdr;
    DWORD dwPID;
    DWORD cFiles;
    PEDUMP_FILENTRY File[];
} OBPEDUMP_MODULECACHE, *POBPEDUMP_MODULECACHE;

/*
* List : function as specified by the module manager. The module manager will
* call into this callback function whenever a list directory shall occur from
* the given module.
* -- ctx
* -- pFileList
* -- return
*/
_Success_(return)
BOOL M_PEDump_List(_In_ PVMMDLL_PLUGIN_CONTEXT ctx, _Inout_ PHANDLE pFileList)
{
    BOOL result = FALSE;
    DWORD iModule;
    PVMMOB_MAP_MODULE pObModuleMap = NULL;
    POBPEDUMP_MODULECACHE pObCache = NULL;
    POB_VSET pObVSet_ModuleBaseAddresses = NULL;
    PVMM_PROCESS pProcess = (PVMM_PROCESS)ctx->pProcess;
    DWORD cbPageRead;
    BYTE pbPage[0x1000];
    if(ctx->wszPath[0]) { return FALSE; }
    // 1: get cached entries
    pObCache = ObContainer_GetOb(pProcess->Plugin.pObCPeDumpDirCache);
    // 2: set up cache (if needed)
    if(!pObCache) {
        if(!VmmMap_GetModule(pProcess, &pObModuleMap)) { return FALSE; }
        pObCache = Ob_Alloc('MPeD', LMEM_ZEROINIT, sizeof(OBPEDUMP_MODULECACHE) + pObModuleMap->cMap * sizeof(PEDUMP_FILENTRY), NULL, NULL);
        if(!pObCache) { goto fail; }
        // Load module bases (PE header) memory into cache with one single call.
        if(!(pObVSet_ModuleBaseAddresses = ObVSet_New())) { goto fail; }
        for(iModule = 0; iModule < pObModuleMap->cMap; iModule++) {
            ObVSet_Push(pObVSet_ModuleBaseAddresses, pObModuleMap->pMap[iModule].vaBase);
        }
        VmmCachePrefetchPages(pProcess, pObVSet_ModuleBaseAddresses, 0);
        // Build file listing information cache (only from in-cache items).
        ZeroMemory(pbPage, 0x1000);
        for(iModule = 0; iModule < pObModuleMap->cMap; iModule++) {
            VmmReadEx(pProcess, pObModuleMap->pMap[iModule].vaBase, pbPage, 0x1000, &cbPageRead, VMM_FLAG_FORCECACHE_READ);
            if(cbPageRead != 0x1000) { 
                vmmprintfvv_fn("Skipping module: '%S' - paged/invalid?\n", pObModuleMap->pMap[iModule].wszText);
                continue;
            }
            pObCache->File[pObCache->cFiles].cb = PE_FileRaw_Size(pProcess, pObModuleMap->pMap[iModule].vaBase, pbPage);
            if(!pObCache->File[pObCache->cFiles].cb) {
                vmmprintfvv_fn("Skipping module: '%S' - paged/invalid?\n", pObModuleMap->pMap[iModule].wszText);
                continue;
            }
            wcsncpy_s(pObCache->File[pObCache->cFiles].wszName, MAX_PATH, pObModuleMap->pMap[iModule].wszText, _TRUNCATE);
            pObCache->cFiles++;
        }
        ObContainer_SetOb(pProcess->Plugin.pObCPeDumpDirCache, pObCache);
    }
    // 3: show results and return
    for(iModule = 0; iModule < pObCache->cFiles; iModule++) {
        VMMDLL_VfsList_AddFileEx(pFileList, NULL, pObCache->File[iModule].wszName, pObCache->File[iModule].cb, NULL);
    }
    result = TRUE;
fail:
    Ob_DECREF(pObCache);
    Ob_DECREF(pObModuleMap);
    Ob_DECREF(pObVSet_ModuleBaseAddresses);
    return result;
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
NTSTATUS M_PEDump_Read(_In_ PVMMDLL_PLUGIN_CONTEXT ctx, _Out_ PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset)
{
    BOOL f;
    PVMM_MAP_MODULEENTRY pModule = NULL;
    PVMMOB_MAP_MODULE pObModuleMap = NULL;
    f = (cbOffset <= 0x02000000) &&
        VmmMap_GetModule((PVMM_PROCESS)ctx->pProcess, &pObModuleMap) &&
        (pModule = VmmMap_GetModuleEntry(pObModuleMap, ctx->wszPath)) &&
        PE_FileRaw_Read(ctx->pProcess, pModule->vaBase, pb, cb, pcbRead, (DWORD)cbOffset);
    Ob_DECREF(pObModuleMap);
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
NTSTATUS M_PEDump_Write(_In_ PVMMDLL_PLUGIN_CONTEXT ctx, _In_ PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbWrite, _In_ QWORD cbOffset)
{
    BOOL f;
    PVMM_MAP_MODULEENTRY pModule = NULL;
    PVMMOB_MAP_MODULE pObModuleMap = NULL;
    f = (cbOffset <= 0x02000000) &&
        VmmMap_GetModule((PVMM_PROCESS)ctx->pProcess, &pObModuleMap) &&
        (pModule = VmmMap_GetModuleEntry(pObModuleMap, ctx->wszPath)) &&
        PE_FileRaw_Write(ctx->pProcess, pModule->vaBase, pb, cb, pcbWrite, (DWORD)cbOffset);
    Ob_DECREF(pObModuleMap);
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
VOID M_PEDump_Initialize(_Inout_ PVMMDLL_PLUGIN_REGINFO pRI)
{
    if((pRI->magic != VMMDLL_PLUGIN_REGINFO_MAGIC) || (pRI->wVersion != VMMDLL_PLUGIN_REGINFO_VERSION)) { return; }
    if((pRI->tpSystem != VMM_SYSTEM_WINDOWS_X64) && (pRI->tpSystem != VMM_SYSTEM_WINDOWS_X86)) { return; }
    wcscpy_s(pRI->reg_info.wszModuleName, 32, L"pedump");            // module name
    pRI->reg_info.fProcessModule = TRUE;                             // module shows in process directory
    pRI->reg_fn.pfnList = M_PEDump_List;                             // List function supported
    pRI->reg_fn.pfnRead = M_PEDump_Read;                             // Read function supported
    if(ctxMain->dev.fWritable) {
        pRI->reg_fn.pfnWrite = M_PEDump_Write;                       // Write function supported
    }
    pRI->pfnPluginManager_Register(pRI);
}
