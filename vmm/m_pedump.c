// m_pedump.c : implementation of the pedump built-in module.
//
// (c) Ulf Frisk, 2019
// Author: Ulf Frisk, pcileech@frizk.net
//
#include "m_ldrmodules.h"
#include "pluginmanager.h"
#include "vmm.h"
#include "vmmproc.h"
#include "vmmwin.h"
#include "vmmvfs.h"
#include "util.h"
#include "pe.h"

typedef struct tdPEDUMP_FILENTRY {
    DWORD cb;
    CHAR szName[32];
} PEDUMP_FILENTRY;

typedef struct tdOBPEDUMP_MODULECACHE {
    VMMOB ObHdr;
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
    PVMMOB_MODULEMAP pObModuleMap = NULL;
    POBPEDUMP_MODULECACHE pObCache = NULL;
    PVMMOB_DATASET pObSetModuleBaseAddress = NULL;
    PVMM_PROCESS pProcess = (PVMM_PROCESS)ctx->pProcess;
    DWORD cbPageRead;
    BYTE pbPage[0x1000];
    if(ctx->szPath[0]) { return FALSE; }
    // 1: get cached entries
    pObCache = VmmObContainer_GetOb(&pProcess->Plugin.ObCPeDumpDirCache);
    // 2: set up cache (if needed)
    if(!pObCache) {
        if(!VmmProc_ModuleMapGet(pProcess, &pObModuleMap)) { return FALSE; }
        pObCache = VmmOb_Alloc('MP', LMEM_ZEROINIT, sizeof(OBPEDUMP_MODULECACHE) + pObModuleMap->cMap * sizeof(PEDUMP_FILENTRY), NULL, NULL);
        if(!pObCache) { goto fail; }
        // Load module bases (PE header) memory into cache with one single call.
        if(!(pObSetModuleBaseAddress = VmmObDataSet_Alloc(TRUE))) { goto fail; }
        for(iModule = 0; iModule < pObModuleMap->cMap; iModule++) {
            VmmObDataSet_Put(pObSetModuleBaseAddress, pObModuleMap->pMap[iModule].BaseAddress);
        }
        VmmCachePrefetchPages(pProcess, pObSetModuleBaseAddress);
        // Build file listing information cache (only from in-cache items).
        ZeroMemory(pbPage, 0x1000);
        for(iModule = 0; iModule < pObModuleMap->cMap; iModule++) {
            VmmReadEx(pProcess, pObModuleMap->pMap[iModule].BaseAddress, pbPage, 0x1000, &cbPageRead, VMM_FLAG_FORCECACHE_READ);
            if(cbPageRead != 0x1000) { 
                vmmprintfvv_fn("Skipping module: '%s' - paged/invalid?\n", pObModuleMap->pMap[iModule].szName);
                continue;
            }
            pObCache->File[pObCache->cFiles].cb = PE_FileRaw_Size(pProcess, pObModuleMap->pMap[iModule].BaseAddress, pbPage);
            if(!pObCache->File[pObCache->cFiles].cb) {
                vmmprintfvv_fn("Skipping module: '%s' - paged/invalid?\n", pObModuleMap->pMap[iModule].szName);
                continue;
            }
            memcpy(pObCache->File[pObCache->cFiles].szName, pObModuleMap->pMap[iModule].szName, 32);
            pObCache->cFiles++;
        }
        VmmObContainer_SetOb(&pProcess->Plugin.ObCPeDumpDirCache, pObCache);
    }
    // 3: show results and return
    for(iModule = 0; iModule < pObCache->cFiles; iModule++) {
        VMMDLL_VfsList_AddFile(pFileList, pObCache->File[iModule].szName, pObCache->File[iModule].cb);
    }
    result = TRUE;
fail:
    VmmOb_DECREF(pObCache);
    VmmOb_DECREF(pObModuleMap);
    VmmOb_DECREF(pObSetModuleBaseAddress);
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
NTSTATUS M_PEDump_Read(_In_ PVMMDLL_PLUGIN_CONTEXT ctx, _Out_ LPVOID pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset)
{
    BOOL result;
    PVMM_MODULEMAP_ENTRY pModule = NULL;
    PVMMOB_MODULEMAP pObModuleMap = NULL;
    result =
        (cbOffset <= 0x02000000) &&
        VmmProc_ModuleMapGetSingleEntry((PVMM_PROCESS)ctx->pProcess, ctx->szPath, &pObModuleMap, &pModule) &&
        PE_FileRaw_Read(ctx->pProcess, pModule->BaseAddress, (PBYTE)pb, cb, pcbRead, (DWORD)cbOffset);
    VmmOb_DECREF(pObModuleMap);
    return result ? VMMDLL_STATUS_SUCCESS : VMMDLL_STATUS_FILE_INVALID;
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
NTSTATUS M_PEDump_Write(_In_ PVMMDLL_PLUGIN_CONTEXT ctx, _In_ LPVOID pb, _In_ DWORD cb, _Out_ PDWORD pcbWrite, _In_ QWORD cbOffset)
{
    BOOL result;
    PVMM_MODULEMAP_ENTRY pModule = NULL;
    PVMMOB_MODULEMAP pObModuleMap = NULL;
    result =
        (cbOffset <= 0x02000000) &&
        VmmProc_ModuleMapGetSingleEntry((PVMM_PROCESS)ctx->pProcess, ctx->szPath, &pObModuleMap, &pModule) &&
        PE_FileRaw_Write(ctx->pProcess, pModule->BaseAddress, (PBYTE)pb, cb, pcbWrite, (DWORD)cbOffset);
    VmmOb_DECREF(pObModuleMap);
    return result ? VMMDLL_STATUS_SUCCESS : VMMDLL_STATUS_FILE_INVALID;
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
    strcpy_s(pRI->reg_info.szModuleName, 32, "pedump");              // module name
    pRI->reg_info.fProcessModule = TRUE;                             // module shows in process directory
    pRI->reg_fn.pfnList = M_PEDump_List;                             // List function supported
    pRI->reg_fn.pfnRead = M_PEDump_Read;                             // Read function supported
    if(ctxMain->dev.fWritable) {
        pRI->reg_fn.pfnWrite = M_PEDump_Write;                       // Write function supported
    }
    pRI->pfnPluginManager_Register(pRI);
}
