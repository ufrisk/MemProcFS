// m_ldrmodules.c : implementation of the ldrmodules built-in module.
//
// (c) Ulf Frisk, 2018-2019
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

#define LDRMODULES_CACHE_TP_EAT     1
#define LDRMODULES_CACHE_TP_IAT     2
#define LDRMODULES_NUM_CACHE        8
typedef struct tdOBLDRMODULES_CACHE_ENTRY {
    VMMOB ObHdr;
    CHAR szDll[32];
    DWORD tp;
    DWORD cb;
    BYTE pb[];
} OBLDRMODULES_CACHE_ENTRY, *POBLDRMODULES_CACHE_ENTRY;


#define LDRMODULES_MAX_IATEAT   0x10000

/*
* Retrieve a OBLDRMODULES_CACHE_ENTRY object for the Export Address Table (EAT).
* CALLER DECREF: return
* -- ctx
* -- pModule
* -- return
*/
POBLDRMODULES_CACHE_ENTRY LdrModule_GetEAT(_In_ PVMMDLL_PLUGIN_CONTEXT ctx, _In_ PVMM_MODULEMAP_ENTRY pModule)
{
    DWORD i, o, cEATs = 0;
    PVMMPROC_WINDOWS_EAT_ENTRY pEATs = NULL;
    POBLDRMODULES_CACHE_ENTRY pObCacheEntry = NULL;
    PVMM_PROCESS pProcess = (PVMM_PROCESS)ctx->pProcess;
    // 1: retrieve cache
    pObCacheEntry = VmmObContainer_GetOb(&pProcess->Plugin.ObCLdrModulesDisplayCache);
    if(pObCacheEntry && (pObCacheEntry->tp == LDRMODULES_CACHE_TP_EAT) && !_strnicmp(pObCacheEntry->szDll, pModule->szName, 32)) {
        return pObCacheEntry;
    }
    VmmOb_DECREF(pObCacheEntry);
    pObCacheEntry = NULL;
    // 2: retrieve exported functions
    pEATs = LocalAlloc(0, LDRMODULES_MAX_IATEAT * sizeof(VMMPROC_WINDOWS_EAT_ENTRY));
    if(!pEATs) { goto fail; }
    VmmWin_PE_LoadEAT_DisplayBuffer(ctx->pProcess, pModule, pEATs, LDRMODULES_MAX_IATEAT, &cEATs);
    if(!cEATs) { goto fail; }
    // 3: fill "display buffer"
    pObCacheEntry = VmmOb_Alloc('EA', LMEM_ZEROINIT, sizeof(OBLDRMODULES_CACHE_ENTRY) + (QWORD)cEATs * 64 + 1, NULL, NULL);
    if(!pObCacheEntry) { goto fail; }
    pObCacheEntry->tp = LDRMODULES_CACHE_TP_EAT;
    pObCacheEntry->cb = cEATs * 64 + 1;
    memcpy(pObCacheEntry->szDll, pModule->szName, 32);
    for(i = 0, o = 0; i < cEATs; i++) {
        o += snprintf(
            pObCacheEntry->pb + o,
            pObCacheEntry->cb - o,
            "%04x %016llx %-40.40s \n",     // 64 bytes (chars) / line (function)
            (WORD)i,
            pModule->BaseAddress + pEATs[i].vaFunctionOffset,
            pEATs[i].szFunction
        );
    }
    pObCacheEntry->cb = o;
    LocalFree(pEATs);
    VmmObContainer_SetOb(&pProcess->Plugin.ObCLdrModulesDisplayCache, pObCacheEntry);
    return pObCacheEntry;
fail:
    VmmOb_DECREF(pObCacheEntry);
    LocalFree(pEATs);
    return NULL;
}

/*
* Retrieve a OBLDRMODULES_CACHE_ENTRY object for the Import Address Table (IAT).
* CALLER DECREF: return
* -- ctx
* -- pModule
* -- return
*/
POBLDRMODULES_CACHE_ENTRY LdrModule_GetIAT(_In_ PVMMDLL_PLUGIN_CONTEXT ctx, _In_ PVMM_MODULEMAP_ENTRY pModule)
{
    DWORD i, o, cIATs = 0;
    PVMMWIN_IAT_ENTRY pIATs = NULL;
    POBLDRMODULES_CACHE_ENTRY pObCacheEntry = NULL;
    PVMM_PROCESS pProcess = (PVMM_PROCESS)ctx->pProcess;
    // 1: retrieve cache
    pObCacheEntry = VmmObContainer_GetOb(&pProcess->Plugin.ObCLdrModulesDisplayCache);
    if(pObCacheEntry && (pObCacheEntry->tp == LDRMODULES_CACHE_TP_IAT) && !_strnicmp(pObCacheEntry->szDll, pModule->szName, 32)) {
        return pObCacheEntry;
    }
    VmmOb_DECREF(pObCacheEntry);
    pObCacheEntry = NULL;
    // 2: retrieve exported functions
    pIATs = LocalAlloc(0, LDRMODULES_MAX_IATEAT * sizeof(VMMWIN_IAT_ENTRY));
    if(!pIATs) { goto fail; }
    VmmWin_PE_LoadIAT_DisplayBuffer(ctx->pProcess, pModule, pIATs, LDRMODULES_MAX_IATEAT, &cIATs);
    if(!cIATs) { goto fail; }
    // 3: fill "display buffer"
    pObCacheEntry = VmmOb_Alloc('IA', LMEM_ZEROINIT, sizeof(OBLDRMODULES_CACHE_ENTRY) + (QWORD)cIATs * 128 + 1, NULL, NULL);
    if(!pObCacheEntry) { goto fail; }
    pObCacheEntry->tp = LDRMODULES_CACHE_TP_IAT;
    pObCacheEntry->cb = cIATs * 128 + 1;
    memcpy(pObCacheEntry->szDll, pModule->szName, 32);
    for(i = 0, o = 0; i < cIATs; i++) {
        o += snprintf(
            pObCacheEntry->pb + o,
            pObCacheEntry->cb - o,
            "%04x %016llx %-40.40s %-64.64s\n",     // 128 bytes (chars) / line (function)
            (WORD)i,
            pIATs[i].vaFunction,
            pIATs[i].szFunction,
            pIATs[i].szModule
        );
    }
    pObCacheEntry->cb = o;
    LocalFree(pIATs);
    VmmObContainer_SetOb(&pProcess->Plugin.ObCLdrModulesDisplayCache, pObCacheEntry);
    return pObCacheEntry;
fail:
    VmmOb_DECREF(pObCacheEntry);
    LocalFree(pIATs);
    return NULL;
}

/*
* Helper write function - Write to a virtual memory backed "file".
*/
VOID LdrModules_Write_MemFile(_In_ PVMM_PROCESS pProcess, _In_ QWORD vaMem, _In_ QWORD cbMem, _In_ LPVOID pb, _In_ DWORD cb, _Out_ PDWORD pcbWrite, _In_ ULONG64 cbOffset)
{
    if(cbMem <= cbOffset) { *pcbWrite = 0; return; }
    *pcbWrite = (DWORD)min(cb, cbMem - cbOffset);
    VmmWrite(pProcess, vaMem + cbOffset, pb, *pcbWrite);
}

/*
* Helper write function - Write to the requested data directory file.
*/
VOID LdrModules_Write_DirectoriesD(_In_ PVMM_PROCESS pProcess, _In_ PVMM_MODULEMAP_ENTRY pModule, _In_ LPSTR szDirectory, _In_ LPVOID pb, _In_ DWORD cb, _Out_ PDWORD pcbWrite, _In_ QWORD cbOffset)
{
    DWORD i;
    IMAGE_DATA_DIRECTORY pDataDirectories[16];
    *pcbWrite = 0;
    for(i = 0; i < 16; i++) {
        if(!strcmp(szDirectory, PE_DATA_DIRECTORIES[i])) {
            VmmWin_PE_DIRECTORY_DisplayBuffer(pProcess, pModule, NULL, 0, NULL, pDataDirectories);
            LdrModules_Write_MemFile(pProcess, pModule->BaseAddress + pDataDirectories[i].VirtualAddress, pDataDirectories[i].Size, pb, cb, pcbWrite, cbOffset);
        }
    }
}

/*
* Helper write function - Write to the requested section header file.
*/
VOID LdrModules_Write_SectionsD(_In_ PVMM_PROCESS pProcess, _In_ PVMM_MODULEMAP_ENTRY pModule, _In_ LPSTR szSection, _In_ LPVOID pb, _In_ DWORD cb, _Out_ PDWORD pcbWrite, _In_ QWORD cbOffset)
{
    IMAGE_SECTION_HEADER SectionHeader;
    if(!PE_SectionGetFromName(pProcess, pModule->BaseAddress, szSection, &SectionHeader)) { *pcbWrite = 0;  return; }
    LdrModules_Write_MemFile(pProcess, pModule->BaseAddress + SectionHeader.VirtualAddress, SectionHeader.Misc.VirtualSize, pb, cb, pcbWrite, cbOffset);
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
NTSTATUS LdrModules_Write(_In_ PVMMDLL_PLUGIN_CONTEXT ctx, _In_ LPVOID pb, _In_ DWORD cb, _Out_ PDWORD pcbWrite, _In_ QWORD cbOffset)
{
    CHAR _szBuf[MAX_PATH] = { 0 };
    PVMM_MODULEMAP_ENTRY pModule = NULL;
    PVMMOB_MODULEMAP pObModuleMap = NULL;
    LPSTR szModuleName, szModuleSubPath;
    PVMM_PROCESS pProcess = (PVMM_PROCESS)ctx->pProcess;
    *pcbWrite = 0;
    Util_PathSplit2(ctx->szPath, _szBuf, &szModuleName, &szModuleSubPath);
    if(szModuleName[0] && szModuleSubPath[0] && VmmProc_ModuleMapGetSingleEntry(pProcess, szModuleName, &pObModuleMap, &pModule)) {
        if(!_stricmp(szModuleSubPath, "pefile.dll")) {
            PE_FileRaw_Write(pProcess, pModule->BaseAddress, (PBYTE)pb, cb, pcbWrite, (DWORD)cbOffset);
        }
        if(!_strnicmp(szModuleSubPath, "sectionsd\\", 10)) {
            LdrModules_Write_SectionsD(pProcess, pModule, szModuleSubPath + 10, pb, cb, pcbWrite, cbOffset);
        }
        if(!_strnicmp(szModuleSubPath, "directoriesd\\", 13)) {
            LdrModules_Write_DirectoriesD(pProcess, pModule, szModuleSubPath + 13, pb, cb, pcbWrite, cbOffset);
        }
        VmmOb_DECREF(pObModuleMap);
    }
    return VMM_STATUS_SUCCESS;
}

/*
* Helper read function - Read a virtual memory backed "file".
*/
NTSTATUS LdrModules_Read_MemFile(_In_ PVMM_PROCESS pProcess, _In_ QWORD vaMem, _In_ QWORD cbMem, _Out_ LPVOID pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ ULONG64 cbOffset)
{
    if(cbMem <= cbOffset) { return VMM_STATUS_END_OF_FILE; }
    VmmReadEx(pProcess, vaMem + cbOffset, pb, (DWORD)min(cb, cbMem - cbOffset), pcbRead, 0);
    return *pcbRead ? VMMDLL_STATUS_SUCCESS : VMMDLL_STATUS_END_OF_FILE;
}

/*
* Helper read function - Read the requested data directory file.
*/
NTSTATUS LdrModules_Read_DirectoriesD(_In_ PVMM_PROCESS pProcess, _In_ PVMM_MODULEMAP_ENTRY pModule, _In_ LPSTR szDirectory, _Out_ LPVOID pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset)
{
    DWORD i;
    IMAGE_DATA_DIRECTORY pDataDirectories[16];
    for(i = 0; i < 16; i++) {
        if(!strcmp(szDirectory, PE_DATA_DIRECTORIES[i])) {
            VmmWin_PE_DIRECTORY_DisplayBuffer(pProcess, pModule, NULL, 0, NULL, pDataDirectories);
            return LdrModules_Read_MemFile(pProcess, pModule->BaseAddress + pDataDirectories[i].VirtualAddress, pDataDirectories[i].Size, pb, cb, pcbRead, cbOffset);
        }
    }
    return VMMDLL_STATUS_FILE_INVALID;
}

/*
* Helper read function - Read the requested section header file.
*/
NTSTATUS LdrModules_Read_SectionsD(_In_ PVMM_PROCESS pProcess, _In_ PVMM_MODULEMAP_ENTRY pModule, _In_ LPSTR szSection, _Out_ LPVOID pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset)
{
    IMAGE_SECTION_HEADER SectionHeader;
    if(!PE_SectionGetFromName(pProcess, pModule->BaseAddress, szSection, &SectionHeader)) { return VMMDLL_STATUS_FILE_INVALID; }
    return LdrModules_Read_MemFile(pProcess, pModule->BaseAddress + SectionHeader.VirtualAddress, SectionHeader.Misc.VirtualSize, pb, cb, pcbRead, cbOffset);
}

NTSTATUS LdrModules_Read_ModuleSubFile(_In_ PVMMDLL_PLUGIN_CONTEXT ctx, _In_ PVMM_MODULEMAP_ENTRY pModule, _In_ LPSTR szPath, _Out_ LPVOID pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset)
{
    NTSTATUS nt;
    DWORD cbBuffer;
    BYTE pbBuffer[0x800];
    POBLDRMODULES_CACHE_ENTRY pObCacheEntry = NULL;
    PVMM_PROCESS pProcess = (PVMM_PROCESS)ctx->pProcess;
    if(!_stricmp(szPath, "base")) {
        return Util_VfsReadFile_FromQWORD(pModule->BaseAddress, pb, cb, pcbRead, cbOffset, FALSE);
    }
    if(!_stricmp(szPath, "entry")) {
        return Util_VfsReadFile_FromQWORD(pModule->EntryPoint, pb, cb, pcbRead, cbOffset, FALSE);
    }
    if(!_stricmp(szPath, "size")) {
        return Util_VfsReadFile_FromDWORD(pModule->SizeOfImage, pb, cb, pcbRead, cbOffset, FALSE);
    }
    if(!_stricmp(szPath, "directories")) {
        VmmWin_PE_DIRECTORY_DisplayBuffer(ctx->pProcess, pModule, pbBuffer, 0x800, &cbBuffer, NULL);
        return Util_VfsReadFile_FromPBYTE(pbBuffer, cbBuffer, pb, cb, pcbRead, cbOffset);
    }
    if(!_stricmp(szPath, "export")) {
        pObCacheEntry = LdrModule_GetEAT(ctx, pModule);
        if(!pObCacheEntry) { return VMMDLL_STATUS_FILE_INVALID; }
        nt = Util_VfsReadFile_FromPBYTE(pObCacheEntry->pb, pObCacheEntry->cb, pb, cb, pcbRead, cbOffset);
        VmmOb_DECREF(pObCacheEntry);
        return nt;
    }
    if(!_stricmp(szPath, "import")) {
        pObCacheEntry = LdrModule_GetIAT(ctx, pModule);
        if(!pObCacheEntry) { return VMMDLL_STATUS_FILE_INVALID; }
        nt = Util_VfsReadFile_FromPBYTE(pObCacheEntry->pb, pObCacheEntry->cb, pb, cb, pcbRead, cbOffset);
        VmmOb_DECREF(pObCacheEntry);
        return nt;
    }
    if(!_stricmp(szPath, "pefile.dll")) {
        return PE_FileRaw_Read(pProcess, pModule->BaseAddress, (PBYTE)pb, cb, pcbRead, (DWORD)cbOffset) ? VMMDLL_STATUS_SUCCESS : VMMDLL_STATUS_FILE_INVALID;
    }
    if(!_stricmp(szPath, "sections")) {
        VmmWin_PE_SECTION_DisplayBuffer(ctx->pProcess, pModule, pbBuffer, 0x800, &cbBuffer, NULL, NULL);
        return Util_VfsReadFile_FromPBYTE(pbBuffer, cbBuffer, pb, cb, pcbRead, cbOffset);
    }
    if(!_strnicmp(szPath, "sectionsd\\", 10)) {
        return LdrModules_Read_SectionsD(pProcess, pModule, szPath + 10, pb, cb, pcbRead, cbOffset);
    }
    if(!_strnicmp(szPath, "directoriesd\\", 13)) {
        return LdrModules_Read_DirectoriesD(pProcess, pModule, szPath + 13, pb, cb, pcbRead, cbOffset);
    }
    return VMMDLL_STATUS_FILE_INVALID;
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
    NTSTATUS nt;
    CHAR _szBuf[MAX_PATH] = { 0 };
    LPSTR szModuleName, szModuleSubPath;
    PVMM_MODULEMAP_ENTRY pModule = NULL;
    PVMMOB_MODULEMAP pObModuleMap = NULL;
    Util_PathSplit2(ctx->szPath, _szBuf, &szModuleName, &szModuleSubPath);
    *pcbRead = 0;
    if(szModuleName[0] && szModuleSubPath[0] && VmmProc_ModuleMapGetSingleEntry((PVMM_PROCESS)ctx->pProcess, szModuleName, &pObModuleMap, &pModule)) {
        nt = LdrModules_Read_ModuleSubFile(ctx, pModule, szModuleSubPath, pb, cb, pcbRead, cbOffset);
        VmmOb_DECREF(pObModuleMap);
        return nt;
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
    DWORD c, i;
    CHAR _szBuf[MAX_PATH] = { 0 };
    LPSTR szPath1, szPath2;
    PVMMOB_MODULEMAP pObModuleMap = NULL;
    PVMM_MODULEMAP_ENTRY pModule = NULL;
    PIMAGE_SECTION_HEADER pSections = NULL;
    IMAGE_DATA_DIRECTORY pDataDirectories[16];
    PVMM_PROCESS pProcess = (PVMM_PROCESS)ctx->pProcess;
    if(!VmmProc_ModuleMapGet(pProcess, &pObModuleMap)) { goto fail; }
    // modules root directory -> add directory per DLL
    if(!ctx->szPath[0]) {
        for(i = 0; i < pObModuleMap->cMap; i++) {
            VMMDLL_VfsList_AddDirectory(pFileList, pObModuleMap->pMap[i].szName);
        }
        goto success;
    }
    // individual module directory -> list files
    Util_PathSplit2(ctx->szPath, _szBuf, &szPath1, &szPath2);
    for(i = 0; i < pObModuleMap->cMap; i++) {
        if(0 == strncmp(szPath1, pObModuleMap->pMap[i].szName, 32)) {
            pModule = pObModuleMap->pMap + i;
            break;
        }
    }
    if(!pModule) { goto fail; }
    // module-specific 'root' directory
    if(!szPath2[0]) {
        VmmWin_PE_SetSizeSectionIATEAT_DisplayBuffer(ctx->pProcess, pObModuleMap->pMap + i);
        VMMDLL_VfsList_AddFile(pFileList, "base", 16);
        VMMDLL_VfsList_AddFile(pFileList, "entry", 16);
        VMMDLL_VfsList_AddFile(pFileList, "size", 8);
        VMMDLL_VfsList_AddFile(pFileList, "directories", 864);
        VMMDLL_VfsList_AddFile(pFileList, "export", pObModuleMap->pMap[i].cbDisplayBufferEAT);
        VMMDLL_VfsList_AddFile(pFileList, "import", pObModuleMap->pMap[i].cbDisplayBufferIAT);
        VMMDLL_VfsList_AddFile(pFileList, "sections", pObModuleMap->pMap[i].cbDisplayBufferSections);
        VMMDLL_VfsList_AddFile(pFileList, "pefile.dll", pObModuleMap->pMap[i].cbFileSizeRaw);
        VMMDLL_VfsList_AddDirectory(pFileList, "sectionsd");
        VMMDLL_VfsList_AddDirectory(pFileList, "directoriesd");
        goto success;
    }
    // module-specific 'sectiond' directory
    if(szPath2[0] && !strcmp(szPath2, "sectionsd")) {
        _szBuf[8] = 0;
        c = PE_SectionGetNumberOf(pProcess, pModule->BaseAddress);
        if(!(pSections = LocalAlloc(0, c * sizeof(IMAGE_SECTION_HEADER)))) { goto fail; }
        VmmWin_PE_SECTION_DisplayBuffer(pProcess, pModule, NULL, 0, NULL, &c, pSections);
        for(i = 0; i < c; i++) {
            *(PQWORD)_szBuf = *(PQWORD)pSections[i].Name;
            VMMDLL_VfsList_AddFile(pFileList, _szBuf, pSections[i].Misc.VirtualSize);
        }
        LocalFree(pSections);
        goto success;
    }
    // module-specific 'directoriesd' directory
    if(szPath2[0] && !strcmp(szPath2, "directoriesd")) {
        ZeroMemory(pDataDirectories, 16 * sizeof(IMAGE_DATA_DIRECTORY));
        VmmWin_PE_DIRECTORY_DisplayBuffer(pProcess, pModule, NULL, 0, NULL, pDataDirectories);
        for(i = 0; i < 16; i++) {
            VMMDLL_VfsList_AddFile(pFileList, (LPSTR)PE_DATA_DIRECTORIES[i], pDataDirectories[i].Size);
        }
        goto success;
    }
fail:
    VmmOb_DECREF(pObModuleMap);
    return FALSE;
success:
    VmmOb_DECREF(pObModuleMap);
    return TRUE;
}

/*
* Initialization function. The module manager shall call into this function
* when the module shall be initialized. If the module wish to initialize it
* shall call the supplied pfnPluginManager_Register function.
* NB! the module does not have to register itself - for example if the target
* operating system or architecture is unsupported.
* -- pPluginRegInfo
*/
VOID M_LdrModules_Initialize(_Inout_ PVMMDLL_PLUGIN_REGINFO pRI)
{
    if((pRI->magic != VMMDLL_PLUGIN_REGINFO_MAGIC) || (pRI->wVersion != VMMDLL_PLUGIN_REGINFO_VERSION)) { return; }
    if((pRI->tpSystem != VMM_SYSTEM_WINDOWS_X64) && (pRI->tpSystem != VMM_SYSTEM_WINDOWS_X86)) { return; }
    strcpy_s(pRI->reg_info.szModuleName, 32, "modules");             // module name
    pRI->reg_info.fProcessModule = TRUE;                             // module shows in process directory
    pRI->reg_fn.pfnList = LdrModules_List;                           // List function supported
    pRI->reg_fn.pfnRead = LdrModules_Read;                           // Read function supported
    if(ctxMain->dev.fWritable) {
        pRI->reg_fn.pfnWrite = LdrModules_Write;                     // Write function supported
    }
    pRI->pfnPluginManager_Register(pRI);
}
