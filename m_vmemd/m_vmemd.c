// m_vmemd.h : implementation related to the vmemd native plugin module for the
// memory process file system.
//
// (c) Ulf Frisk, 2018
// Author: Ulf Frisk, pcileech@frizk.net
//
#include <Windows.h>
#include <stdio.h>
#include "vmmdll.h"

VMMDLL_MEMORYMODEL_TP g_VMemD_TpMemoryModel = VMMDLL_MEMORYMODEL_NA;

ULONG64 VMemD_GetBaseFromFileName(LPSTR sz)
{
    if((strlen(sz) < 15) || (sz[0] != '0') || (sz[1] != 'x')) { return (ULONG64)-1; }
    return strtoull(sz, NULL, 16);
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
NTSTATUS VMemD_Read(_In_ PVMMDLL_PLUGIN_CONTEXT ctx, _Out_ LPVOID pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ ULONG64 cbOffset)
{
    BOOL result;
    ULONG64 cbMax, vaBase;
    VMMDLL_MEMMAP_ENTRY entry;
    // read memory from "vmemd" directory file
    vaBase = VMemD_GetBaseFromFileName(ctx->szPath);
    if(vaBase & 0xfff) { return VMMDLL_STATUS_FILE_INVALID; }
    result = VMMDLL_ProcessGetMemoryMapEntry(ctx->dwPID, &entry, vaBase, FALSE);
    if(!result) { return VMMDLL_STATUS_FILE_INVALID; }
    *pcbRead = 0;
    if(entry.AddrBase + (entry.cPages << 12) <= vaBase + cbOffset) { return VMMDLL_STATUS_END_OF_FILE; }
    cbMax = min((entry.AddrBase + (entry.cPages << 12)), (vaBase + cb + cbOffset)) - (vaBase - cbOffset);   // min(entry_top_addr, request_top_addr) - request_start_addr
    result = VMMDLL_MemReadEx(ctx->dwPID, vaBase + cbOffset, pb, (DWORD)min(cb, cbMax), pcbRead, 0);
    return (result && *pcbRead) ? VMMDLL_STATUS_SUCCESS : VMMDLL_STATUS_END_OF_FILE;
}

/*
* Write : function as specified by the module manager. The module manager will
* call into this callback function whenever a write shall occur from a "file".
* -- ctx
* -- pb
* -- cb
* -- pcbWrite
* -- cbOffset
* -- return
*/
NTSTATUS VMemD_Write(_In_ PVMMDLL_PLUGIN_CONTEXT ctx, _In_ LPVOID pb, _In_ DWORD cb, _Out_ PDWORD pcbWrite, _In_ ULONG64 cbOffset)
{
    BOOL result;
    ULONG64 cbMax, vaBase;
    VMMDLL_MEMMAP_ENTRY entry;
    // write memory from "vmemd" directory file
    vaBase = VMemD_GetBaseFromFileName(ctx->szPath);
    if(vaBase & 0xfff) { return VMMDLL_STATUS_FILE_INVALID; }
    result = VMMDLL_ProcessGetMemoryMapEntry(ctx->dwPID, &entry, vaBase, FALSE);
    if(!result) { return VMMDLL_STATUS_FILE_INVALID; }
    *pcbWrite = 0;
    if(entry.AddrBase + (entry.cPages << 12) <= vaBase + cbOffset) { return VMMDLL_STATUS_END_OF_FILE; }
    cbMax = min((entry.AddrBase + (entry.cPages << 12)), (vaBase + cb + cbOffset)) - (vaBase - cbOffset);   // min(entry_top_addr, request_top_addr) - request_start_addr
    VMMDLL_MemWrite(ctx->dwPID, vaBase + cbOffset, pb, (DWORD)min(cb, cbMax));
    *pcbWrite = cb;
    return VMMDLL_STATUS_SUCCESS;
}

/*
* List : function as specified by the module manager. The module manager will
* call into this callback function whenever a list directory shall occur from
* the given module.
* -- ctx
* -- pFileList
* -- return
*/
BOOL VMemD_List(_In_ PVMMDLL_PLUGIN_CONTEXT ctx, _Inout_ PHANDLE pFileList)
{
    BOOL result;
    DWORD i;
    ULONG64 cEntries = 0;
    CHAR szBufferFileName[MAX_PATH];
    PVMMDLL_MEMMAP_ENTRY pMemMap;
    if(ctx->szPath[0]) {
        // only list in module root directory.
        // not root directory == error for this module.
        return FALSE;
    }
    // populate memory map directory
    result = VMMDLL_ProcessGetMemoryMap(ctx->dwPID, NULL, &cEntries, FALSE);
    if(!result) { return FALSE; }
    pMemMap = (PVMMDLL_MEMMAP_ENTRY)LocalAlloc(0, cEntries * sizeof(VMMDLL_MEMMAP_ENTRY));
    if(!pMemMap) { return FALSE; }
    result = VMMDLL_ProcessGetMemoryMap(ctx->dwPID, pMemMap, &cEntries, TRUE);
    if(!result) {
        LocalFree(pMemMap);
        return FALSE;
    }
    for(i = 0; i < cEntries; i++) {
        if(g_VMemD_TpMemoryModel == VMMDLL_MEMORYMODEL_X64) {
            sprintf_s(
                szBufferFileName,
                MAX_PATH - 1,
                "0x%016llx%s%s.vmem",
                pMemMap[i].AddrBase,
                pMemMap[i].szTag[0] ? "-" : "",
                pMemMap[i].szTag[0] ? pMemMap[i].szTag : "");
        } else if((g_VMemD_TpMemoryModel == VMMDLL_MEMORYMODEL_X86) || (g_VMemD_TpMemoryModel == VMMDLL_MEMORYMODEL_X86PAE)) {
            sprintf_s(
                szBufferFileName,
                MAX_PATH - 1,
                "0x%08x%s%s.vmem",
                (DWORD)pMemMap[i].AddrBase,
                pMemMap[i].szTag[0] ? "-" : "",
                pMemMap[i].szTag[0] ? pMemMap[i].szTag : "");
        }
        VMMDLL_VfsList_AddFile(pFileList, szBufferFileName, (pMemMap[i].cPages << 12));
    }
    LocalFree(pMemMap);
    return TRUE;
}

/*
* Initialization function for the vmemd native plugin module.
* It's important that the function is exported in the DLL and that it is
* declared exactly as below. The plugin manager will call into this function
* after the DLL is loaded. The DLL then must fill the appropriate information
* into the supplied struct and call the pfnPluginManager_Register function to
* register itself with the plugin manager.
* -- pRegInfo
*/
__declspec(dllexport)
VOID InitializeVmmPlugin(_In_ PVMMDLL_PLUGIN_REGINFO pRegInfo)
{
    if((pRegInfo->magic != VMMDLL_PLUGIN_REGINFO_MAGIC) || (pRegInfo->wVersion != VMMDLL_PLUGIN_REGINFO_VERSION)) { return; }
    // Ensure that the plugin support the memory model that is used. The plugin
    // currently supports the 64-bit x64 and 32-bit x86 and x86-pae memory models.
    if(!((pRegInfo->tpMemoryModel == VMMDLL_MEMORYMODEL_X64) || (pRegInfo->tpMemoryModel == VMMDLL_MEMORYMODEL_X86) || (pRegInfo->tpMemoryModel == VMMDLL_MEMORYMODEL_X86PAE))) { return; }
    g_VMemD_TpMemoryModel = pRegInfo->tpMemoryModel;
    strcpy_s(pRegInfo->reg_info.szModuleName, 32, "vmemd");     // module name - 'vmemd'.
    pRegInfo->reg_info.fProcessModule = TRUE;                   // module shows in process directory.
    pRegInfo->reg_fn.pfnList = VMemD_List;                      // List function supported.
    pRegInfo->reg_fn.pfnRead = VMemD_Read;                      // Read function supported.
    pRegInfo->reg_fn.pfnWrite = VMemD_Write;                    // Write function supported.
    pRegInfo->pfnPluginManager_Register(pRegInfo);              // Register with the plugin maanger.
}
