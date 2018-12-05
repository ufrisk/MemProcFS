// m_ldrmodules.c : implementation of the ldrmodules built-in module.
//
// (c) Ulf Frisk, 2018
// Author: Ulf Frisk, pcileech@frizk.net
//
#include "m_ldrmodules.h"
#include "pluginmanager.h"
#include "vmm.h"
#include "vmmwin.h"
#include "vmmvfs.h"
#include "util.h"
#include "pe.h"

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
        LocalFree(pCache[i].pb);
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
    LocalFree(e->pb);
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
    VmmWin_PE_LoadEAT_DisplayBuffer(ctx->pProcess, pModule, pEATs, &cEATs);
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
    PVMMWIN_IAT_ENTRY pIATs = NULL;
    PLDRMODULES_CACHE_ENTRY pCacheEntry;
    // 1: retrieve cache
    pCacheEntry = LdrModule_GetCacheEntry(ctx, pModule->szName, LDRMODULES_CACHE_TP_IAT);
    if(pCacheEntry->pb) { return pCacheEntry; }
    // 2: retrieve exported functions
    cIATs = LDRMODULES_MAX_IATEAT;
    pIATs = LocalAlloc(0, LDRMODULES_MAX_IATEAT * sizeof(VMMWIN_IAT_ENTRY));
    if(!pIATs) { goto fail; }
    VmmWin_PE_LoadIAT_DisplayBuffer(ctx->pProcess, pModule, pIATs, &cIATs);
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
NTSTATUS LdrModules_Write(_In_ PVMMDLL_PLUGIN_CONTEXT ctx, _Out_ LPVOID pb, _In_ DWORD cb, _Out_ PDWORD pcbWrite, _In_ QWORD cbOffset)
{
    DWORD i;
    CHAR _szBuf[MAX_PATH] = { 0 };
    LPSTR szPath1, szPath2;
    PVMM_PROCESS pProcess = (PVMM_PROCESS)ctx->pProcess;
    *pcbWrite = 0;
    Util_PathSplit2(ctx->szPath, _szBuf, &szPath1, &szPath2);
    if(szPath1[0] && szPath2[0]) {
        for(i = 0; i < pProcess->cModuleMap; i++) {
            if(0 == strncmp(szPath1, pProcess->pModuleMap[i].szName, MAX_PATH)) {
                if(!_strnicmp(szPath2, "sectionsd\\", 10)) {
                    LdrModules_Write_SectionsD(pProcess, pProcess->pModuleMap + i, szPath2 + 10, pb, cb, pcbWrite, cbOffset);
                }
                if(!_strnicmp(szPath2, "directoriesd\\", 13)) {
                    LdrModules_Write_DirectoriesD(pProcess, pProcess->pModuleMap + i, szPath2 + 13, pb, cb, pcbWrite, cbOffset);
                }
                break;
            }
        }
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
    *pcbRead = 0;
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
                    VmmWin_PE_DIRECTORY_DisplayBuffer(ctx->pProcess, pProcess->pModuleMap + i, pbBuffer, 0x400, &cbBuffer, NULL);
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
                    VmmWin_PE_SECTION_DisplayBuffer(ctx->pProcess, pProcess->pModuleMap + i, pbBuffer, 0x800, &cbBuffer, NULL, NULL);
                    return Util_VfsReadFile_FromPBYTE(pbBuffer, cbBuffer, pb, cb, pcbRead, cbOffset);
                }
                if(!_strnicmp(szPath2, "sectionsd\\", 10)) {
                    return LdrModules_Read_SectionsD(pProcess, pProcess->pModuleMap + i, szPath2 + 10, pb, cb, pcbRead, cbOffset);
                }
                if(!_strnicmp(szPath2, "directoriesd\\", 13)) {
                    return LdrModules_Read_DirectoriesD(pProcess, pProcess->pModuleMap + i, szPath2 + 13, pb, cb, pcbRead, cbOffset);
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
    DWORD c, i;
    CHAR _szBuf[MAX_PATH] = { 0 };
    LPSTR szPath1, szPath2;
    PVMM_MODULEMAP_ENTRY pModule = NULL;
    PIMAGE_SECTION_HEADER pSections = NULL;
    IMAGE_DATA_DIRECTORY pDataDirectories[16];
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
    for(i = 0; i < pProcess->cModuleMap; i++) {
        if(0 == strncmp(szPath1, pProcess->pModuleMap[i].szName, 32)) {
            pModule = pProcess->pModuleMap + i;
            break;
        }
    }
    if(!pModule) { return FALSE; }
    // module-specific 'root' directory
    if(!szPath2[0]) {
        VmmWin_PE_SetSizeSectionIATEAT_DisplayBuffer(ctx->pProcess, pProcess->pModuleMap + i);
        VMMDLL_VfsList_AddFile(pFileList, "base", 16);
        VMMDLL_VfsList_AddFile(pFileList, "entry", 16);
        VMMDLL_VfsList_AddFile(pFileList, "size", 8);
        VMMDLL_VfsList_AddFile(pFileList, "directories", 864);
        VMMDLL_VfsList_AddFile(pFileList, "export", pProcess->pModuleMap[i].cbDisplayBufferEAT);
        VMMDLL_VfsList_AddFile(pFileList, "import", pProcess->pModuleMap[i].cbDisplayBufferIAT);
        VMMDLL_VfsList_AddFile(pFileList, "sections", pProcess->pModuleMap[i].cbDisplayBufferSections);
        VMMDLL_VfsList_AddDirectory(pFileList, "sectionsd");
        VMMDLL_VfsList_AddDirectory(pFileList, "directoriesd");
        return TRUE;
    }
    // module-specific 'sectiond' directory
    if(szPath2[0] && !strcmp(szPath2, "sectionsd")) {
        _szBuf[8] = 0;
        c = PE_SectionGetNumberOf(pProcess, pModule->BaseAddress);
        if(!(pSections = LocalAlloc(0, c * sizeof(IMAGE_SECTION_HEADER)))) { return FALSE; }
        VmmWin_PE_SECTION_DisplayBuffer(pProcess, pModule, NULL, 0, NULL, &c, pSections);
        for(i = 0; i < c; i++) {
            *(PQWORD)_szBuf = *(PQWORD)pSections[i].Name;
            VMMDLL_VfsList_AddFile(pFileList, _szBuf, pSections[i].Misc.VirtualSize);
        }
        LocalFree(pSections);
        return TRUE;
    }
    // module-specific 'directoriesd' directory
    if(szPath2[0] && !strcmp(szPath2, "directoriesd")) {
        VmmWin_PE_DIRECTORY_DisplayBuffer(pProcess, pModule, NULL, 0, NULL, pDataDirectories);
        for(i = 0; i < 16; i++) {
            VMMDLL_VfsList_AddFile(pFileList, (LPSTR)PE_DATA_DIRECTORIES[i], pDataDirectories[i].Size);
        }
        return TRUE;
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
VOID M_LdrModules_Initialize(_Inout_ PVMMDLL_PLUGIN_REGINFO pRI)
{
    PLDRMODULES_CACHE_ENTRY pCache;
    if((pRI->magic != VMMDLL_PLUGIN_REGINFO_MAGIC) || (pRI->wVersion != VMMDLL_PLUGIN_REGINFO_VERSION)) { return; }
    if((pRI->tpSystem != VMM_SYSTEM_WINDOWS_X64) && (pRI->tpSystem != VMM_SYSTEM_WINDOWS_X86)) { return; }
    pCache = LocalAlloc(LMEM_ZEROINIT, LDRMODULES_NUM_CACHE * sizeof(LDRMODULES_CACHE_ENTRY));
    if(!pCache) { return; }
    strcpy_s(pRI->reg_info.szModuleName, 32, "modules");             // module name
    pRI->reg_info.fProcessModule = TRUE;                             // module shows in process directory
    pRI->reg_info.hModulePrivate = pCache;                           // module private handle (for cache)
    pRI->reg_fn.pfnList = LdrModules_List;                           // List function supported
    pRI->reg_fn.pfnRead = LdrModules_Read;                           // Read function supported
    pRI->reg_fn.pfnWrite = LdrModules_Write;                         // Write function supported
    pRI->reg_fn.pfnCloseHandleModule = LdrModule_CloseHandleModule;  // Close module private handle supported
    pRI->pfnPluginManager_Register(pRI);
}
