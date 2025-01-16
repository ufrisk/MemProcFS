// m_proc_ldrmodules.c : implementation of the ldrmodules built-in module.
//
// (c) Ulf Frisk, 2018-2025
// Author: Ulf Frisk, pcileech@frizk.net
//

#include "modules.h"

#define LDRMODULES_CACHE_TP_EAT             1
#define LDRMODULES_CACHE_TP_IAT             2
#define LDRMODULES_NUM_CACHE                8
#define LDRMODULES_LINELENGTH_X86           107ULL
#define LDRMODULES_LINELENGTH_X64           123ULL
#define LDRMODULES_LINELENGTH_X86_VERB      (LDRMODULES_LINELENGTH_X86+156ULL)
#define LDRMODULES_LINELENGTH_X64_VERB      (LDRMODULES_LINELENGTH_X64+156ULL)
#define LDRMODULES_LINELENGTH_DIRECTORIES   54ULL
#define LDRMODULES_LINELENGTH_SECTIONS      70ULL

#define LDRMODULES_LINEHEADER_X86           "   #    PID    Pages Range Start-End      Description"
#define LDRMODULES_LINEHEADER_X64           "   #    PID    Pages      Range Start-End                 Description"
#define LDRMODULES_LINEHEADER_X86_VERB      LDRMODULES_LINEHEADER_X86"                                     #Imports #Exports #Sect Path                                                                    KernelPath"
#define LDRMODULES_LINEHEADER_X64_VERB      LDRMODULES_LINEHEADER_X64"                                     #Imports #Exports #Sect Path                                                                    KernelPath"

#define LDRMODULES_UNLOAD_LINELENGTH_X86    132ULL
#define LDRMODULES_UNLOAD_LINELENGTH_X64    148ULL
#define LDRMODULES_UNLOAD_LINEHEADER_X86    "   #    PID    Pages Range Start-End      UnloadTime               Description"
#define LDRMODULES_UNLOAD_LINEHEADER_X64    "   #    PID    Pages      Range Start-End                 UnloadTime               Description"

#define LDRMODULE_LINELENGTH_VERSIONINFO    364
#define LDRMODULE_LINEHEADER_VERSIONINFO    "   #    PID          Address Module                            CompanyName               FileDescription                           FileVersion                                       InternalName                      LegalCopyright                                    OriginalFilename                  ProductName                               ProductVersion"

#define LDRMODULES_LINELENGTH_EAT           144ULL
#define LDRMODULES_LINELENGTH_IAT           128ULL
#define LDRMODULES_LINEHEADER_EAT           "   # Ordinal Offset         Address Name                                     ForwardedFunction"
#define LDRMODULES_LINEHEADER_IAT           "   #          Address Name                                     Module"

#define LDRMODULES_MAX_IATEAT               0x10000

#define LDRMODULE_FILELENGTH_DEBUGINFO      356
#define LDRMODULE_FILELENGTH_VERSIONINFO    672

typedef struct tdOBLDRMODULES_CACHE_ENTRY {
    OB ObHdr;
    DWORD dwHash;
    DWORD tp;
    DWORD cb;
    BYTE pb[0];
} OBLDRMODULES_CACHE_ENTRY, *POBLDRMODULES_CACHE_ENTRY;

/*
* Dynamically generate the file \<modulename>\export.txt
*/
VOID LdrModules_ReadLineEAT_CB(_In_ VMM_HANDLE H, _In_ PVMMOB_MAP_EAT pEatMap, _In_ DWORD cbLineLength, _In_ DWORD ie, _In_ PVMM_MAP_EATENTRY pe, _Out_writes_(cbLineLength + 1) LPSTR szu8)
{
    Util_usnprintf_ln(szu8, cbLineLength, "%04x %5i%8x %016llx %-40s %s",
        ie,
        pe->dwOrdinal,
        (DWORD)(pe->vaFunction ? (pe->vaFunction - pEatMap->vaModuleBase) : 0),
        pe->vaFunction,
        pe->uszFunction[0] ? pe->uszFunction : "---",
        pe->uszForwardedFunction ? pe->uszForwardedFunction : ""
    );
}

/*
* Dynamically generate the file \<modulename>\import.txt
*/
VOID LdrModules_ReadLineIAT_CB(_In_ VMM_HANDLE H, _In_ PVMMOB_MAP_IAT pIatMap, _In_ DWORD cbLineLength, _In_ DWORD ie, _In_ PVMM_MAP_IATENTRY pe, _Out_writes_(cbLineLength + 1) LPSTR szu8)
{
    Util_usnprintf_ln(szu8, cbLineLength, "%04x %016llx %-40.40s %s",
        ie,
        pe->vaFunction,
        pe->uszFunction,
        pe->uszModule
    );
}

/*
* Dynamically generate the file \<modulename>\directories
*/
_Success_(return == 0)
NTSTATUS LdrModules_ReadFile_Directories(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess, _In_ QWORD vaModuleBase, _Out_ PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset)
{
    NTSTATUS nt;
    LPSTR sz;
    QWORD i, o = 0, cbMax, cStart, cEnd, cbLINELENGTH;
    IMAGE_DATA_DIRECTORY Directory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
    if(!PE_DirectoryGetAll(H, pProcess, vaModuleBase, NULL, Directory)) { return VMMDLL_STATUS_FILE_INVALID; }
    cbLINELENGTH = LDRMODULES_LINELENGTH_DIRECTORIES;
    cStart = (DWORD)(cbOffset / cbLINELENGTH);
    cEnd = (DWORD)min(16 - 1, (cb + cbOffset + cbLINELENGTH - 1) / cbLINELENGTH);
    cbMax = 1 + (1 + cEnd - cStart) * cbLINELENGTH;
    if(cStart > 16) { return VMMDLL_STATUS_END_OF_FILE; }
    if(!(sz = LocalAlloc(LMEM_ZEROINIT, (SIZE_T)cbMax))) { return VMMDLL_STATUS_FILE_INVALID; }
    for(i = cStart; i <= min(15, cEnd); i++) {
        o += Util_usnprintf_ln(
            sz + o,
            cbLINELENGTH,
            "%x %-16.16s %016llx %08x %08x",
            (DWORD)i,
            PE_DATA_DIRECTORIES[i],
            vaModuleBase + Directory[i].VirtualAddress,
            Directory[i].VirtualAddress,
            Directory[i].Size
        );
    }
    nt = Util_VfsReadFile_FromPBYTE(sz, cbMax - 1, pb, cb, pcbRead, cbOffset - cStart * cbLINELENGTH);
    LocalFree(sz);
    return nt;
}

/*
* Dynamically generate the file \<modulename>\sections
*/
_Success_(return == 0)
NTSTATUS LdrModules_ReadFile_Sections(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess, _In_ QWORD vaModuleBase, _Out_ PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset)
{
    NTSTATUS nt = VMMDLL_STATUS_FILE_INVALID;
    LPSTR sz;
    QWORD i, o = 0, cbMax, cStart, cEnd, cbLINELENGTH;
    DWORD cSections;
    PIMAGE_SECTION_HEADER pSections = NULL;
    cSections = PE_SectionGetNumberOf(H, pProcess, vaModuleBase);
    cbLINELENGTH = LDRMODULES_LINELENGTH_SECTIONS;
    cStart = (DWORD)(cbOffset / cbLINELENGTH);
    cEnd = (DWORD)min(cSections - 1, (cb + cbOffset + cbLINELENGTH - 1) / cbLINELENGTH);
    cbMax = 1 + (1 + cEnd - cStart) * cbLINELENGTH;
    if(!cSections || (cStart > cSections)) { return VMMDLL_STATUS_END_OF_FILE; }
    if(!(sz = LocalAlloc(LMEM_ZEROINIT, (SIZE_T)cbMax))) { goto fail; }
    if(!(pSections = LocalAlloc(LMEM_ZEROINIT, cSections * sizeof(IMAGE_SECTION_HEADER)))) { goto fail; }
    if(!PE_SectionGetAll(H, pProcess, vaModuleBase, cSections, pSections)) { goto fail; }
    for(i = cStart; i <= cEnd; i++) {
        o += Util_usnprintf_ln(
            sz + o,
            cbLINELENGTH,
            "%02x %-8.8s  %016llx %08x %08x %c%c%c %08x %08x",
            (DWORD)i,
            pSections[i].Name,
            vaModuleBase + pSections[i].VirtualAddress,
            pSections[i].VirtualAddress,
            pSections[i].Misc.VirtualSize,
            (pSections[i].Characteristics & IMAGE_SCN_MEM_READ) ? 'r' : '-',
            (pSections[i].Characteristics & IMAGE_SCN_MEM_WRITE) ? 'w' : '-',
            (pSections[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) ? 'x' : '-',
            pSections[i].PointerToRawData,
            pSections[i].SizeOfRawData
        );
    }
    nt = Util_VfsReadFile_FromPBYTE(sz, cbMax - 1, pb, cb, pcbRead, cbOffset - cStart * cbLINELENGTH);
fail:
    LocalFree(pSections);
    LocalFree(sz);
    return nt;
}

/*
* Dynamically generate the file \<modulename>\debuginfo.txt.
*/
_Success_(return == 0)
NTSTATUS LdrModules_Read_PEDebugInfo(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess, _In_ PVMM_MAP_MODULEENTRY pe, _Out_writes_to_(cb, *pcbRead) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset)
{
    CHAR szSymbolServer[MAX_PATH];
    CHAR sz[LDRMODULE_FILELENGTH_DEBUGINFO + 1];
    VmmWinLdrModule_SymbolServer(H, pe, TRUE, _countof(szSymbolServer), szSymbolServer);
    snprintf(
        sz,
        LDRMODULE_FILELENGTH_DEBUGINFO + 1,
        "PDB filename:  %-64.64s\n" \
        "GUID:          %-32.32s\n" \
        "Age:           %-4u\n" \
        "Symbol server: %-192.192s\n",
        (pe->pExDebugInfo && pe->pExDebugInfo->uszPdbFilename) ? pe->pExDebugInfo->uszPdbFilename : "",
        (pe->pExDebugInfo && pe->pExDebugInfo->uszGuid) ? pe->pExDebugInfo->uszGuid : "",
        (pe->pExDebugInfo) ? pe->pExDebugInfo->dwAge : 0,
        szSymbolServer
    );
    return Util_VfsReadFile_FromPBYTE(sz, LDRMODULE_FILELENGTH_DEBUGINFO, pb, cb, pcbRead, cbOffset);
}

/*
* Dynamically generate the file \<modulename>\versioninfo.txt.
*/
_Success_(return == 0)
NTSTATUS LdrModules_Read_PEVersionInfo(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess, _In_ PVMM_MAP_MODULEENTRY pe, _Out_writes_to_(cb, *pcbRead) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset)
{
    CHAR sz[LDRMODULE_FILELENGTH_VERSIONINFO + 1];
    snprintf(
        sz,
        LDRMODULE_FILELENGTH_VERSIONINFO + 1,
        "Company Name:      %-64.64s\n" \
        "File Description:  %-64.64s\n" \
        "File Version:      %-64.64s\n" \
        "Internal Name:     %-64.64s\n" \
        "Legal Copyright:   %-64.64s\n" \
        "Original Filename: %-64.64s\n" \
        "Product Name:      %-64.64s\n" \
        "Product Version:   %-64.64s\n",
        (pe->pExVersionInfo && pe->pExVersionInfo->uszCompanyName) ? pe->pExVersionInfo->uszCompanyName : "",
        (pe->pExVersionInfo && pe->pExVersionInfo->uszFileDescription) ? pe->pExVersionInfo->uszFileDescription : "",
        (pe->pExVersionInfo && pe->pExVersionInfo->uszFileVersion) ? pe->pExVersionInfo->uszFileVersion : "",
        (pe->pExVersionInfo && pe->pExVersionInfo->uszInternalName) ? pe->pExVersionInfo->uszInternalName : "",
        (pe->pExVersionInfo && pe->pExVersionInfo->uszLegalCopyright) ? pe->pExVersionInfo->uszLegalCopyright : "",
        (pe->pExVersionInfo && pe->pExVersionInfo->uszOriginalFilename) ? pe->pExVersionInfo->uszOriginalFilename : "",
        (pe->pExVersionInfo && pe->pExVersionInfo->uszProductName) ? pe->pExVersionInfo->uszProductName : "",
        (pe->pExVersionInfo && pe->pExVersionInfo->uszProductVersion) ? pe->pExVersionInfo->uszProductVersion : ""
    );
    return Util_VfsReadFile_FromPBYTE(sz, LDRMODULE_FILELENGTH_VERSIONINFO, pb, cb, pcbRead, cbOffset);
}

/*
* Dynamically generate the file \modules.txt.
*/
VOID LdrModules_ModuleReadLineCB(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess, _In_ DWORD cbLineLength, _In_ DWORD ie, _In_ PVMM_MAP_MODULEENTRY pe, _Out_writes_(cbLineLength + 1) LPSTR usz)
{
    Util_usnprintf_ln(usz, cbLineLength,
        H->vmm.f32 ? "%04x%7i %8x %08x-%08x %s %s" : "%04x%7i %8x %016llx-%016llx %s %s",
        ie,
        pProcess->dwPID,
        pe->cbImageSize >> 12,
        pe->vaBase,
        pe->vaBase + pe->cbImageSize - 1,
        pe->fWoW64 ? "32" : "  ",
        pe->uszText + pe->cbuText - min(65, pe->cbuText)
    );
}

/*
* Dynamically generate the file \modules-v.txt.
*/
VOID LdrModules_ModuleVerbReadLineCB(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess, _In_ DWORD cbLineLength, _In_ DWORD ie, _In_ PVMM_MAP_MODULEENTRY pe, _Out_writes_(cbLineLength + 1) LPSTR usz)
{
    PVMM_MAP_VADENTRY peVad = NULL;
    PVMMOB_MAP_VAD pObVadMap = NULL;
    if(VmmMap_GetVad(H, pProcess, &pObVadMap, VMM_VADMAP_TP_FULL)) {
        peVad = VmmMap_GetVadEntry(H, pObVadMap, pe->vaBase);
    }
    Util_usnprintf_ln(usz, cbLineLength,
        H->vmm.f32 ? "%04x%7i %8x %08x-%08x %s %s" : "%04x%7i %8x %016llx-%016llx %s %-48s%8i%9i%6i %-72s%s",
        ie,
        pProcess->dwPID,
        pe->cbImageSize >> 12,
        pe->vaBase,
        pe->vaBase + pe->cbImageSize - 1,
        pe->fWoW64 ? "32" : "  ",
        pe->uszText + pe->cbuText - min(48, pe->cbuText),
        pe->cIAT,
        pe->cEAT,
        pe->cSection,
        pe->uszFullName + pe->cbuFullName - min(72, pe->cbuFullName),
        (peVad && peVad->uszText) ? peVad->uszText : ""
    );
    Ob_DECREF(pObVadMap);
}

/*
* Dynamically generate the file \modules-versioninfo.txt.
*/
VOID LdrModules_ModuleVersionInfoReadLineCB(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess, _In_ DWORD cbLineLength, _In_ DWORD ie, _In_ PVMM_MAP_MODULEENTRY pe, _Out_writes_(cbLineLength + 1) LPSTR usz)
{
    Util_usnprintf_ln(usz, cbLineLength, "%04x%7i %16llx %-32.32s  %-24.24s  %-40.40s  %-48.48s  %-32.32s  %-48.48s  %-32.32s  %-40.40s  %-32.32s",
        ie,
        pProcess->dwPID,
        pe->vaBase,
        pe->uszText,
        pe->pExVersionInfo->uszCompanyName,
        pe->pExVersionInfo->uszFileDescription,
        pe->pExVersionInfo->uszFileVersion,
        pe->pExVersionInfo->uszInternalName,
        pe->pExVersionInfo->uszLegalCopyright,
        pe->pExVersionInfo->uszOriginalFilename,
        pe->pExVersionInfo->uszProductName,
        pe->pExVersionInfo->uszProductVersion
    );
}

/*
* Dynamically generate the file \unloaded_modules.txt.
*/
VOID LdrModules_UnloadedReadLineCB(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess, _In_ DWORD cbLineLength, _In_ DWORD ie, _In_ PVMM_MAP_UNLOADEDMODULEENTRY pe, _Out_writes_(cbLineLength + 1) LPSTR usz)
{
    CHAR szTime[24];
    Util_FileTime2String(pe->ftUnload, szTime);
    Util_usnprintf_ln(usz, cbLineLength,
        H->vmm.f32 ? "%04x%7i %8x %08x-%08x %s %s" : "%04x%7i %8x %016llx-%016llx %s %s  %s",
        ie,
        pProcess->dwPID,
        pe->cbImageSize >> 12,
        pe->vaBase,
        pe->vaBase + pe->cbImageSize - 1,
        pe->fWoW64 ? "32" : "  ",
        szTime,
        pe->uszText
    );
}

/*
* Helper write function - Write to the requested data directory file.
*/
VOID LdrModules_Write_DirectoriesD(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess, _In_ PVMM_MAP_MODULEENTRY pModule, _In_ LPCSTR uszDirectory, _In_reads_(cb) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbWrite, _In_ QWORD cbOffset)
{
    DWORD i;
    IMAGE_DATA_DIRECTORY Directory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
    *pcbWrite = 0;
    if(PE_DirectoryGetAll(H, pProcess, pModule->vaBase, NULL, Directory)) {
        for(i = 0; i < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; i++) {
            if(!_strnicmp((LPSTR)PE_DATA_DIRECTORIES[i], uszDirectory, 0)) {
                VmmWriteAsFile(H, pProcess, pModule->vaBase + Directory[i].VirtualAddress, Directory[i].Size, pb, cb, pcbWrite, cbOffset);
            }
        }
    }
}

/*
* Helper write function - Write to the requested section header file.
*/
VOID LdrModules_Write_SectionsD(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess, _In_ PVMM_MAP_MODULEENTRY pModule, _In_ LPCSTR uszSection, _In_reads_(cb) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbWrite, _In_ QWORD cbOffset)
{
    IMAGE_SECTION_HEADER SectionHeader;
    if(!PE_SectionGetFromName(H, pProcess, pModule->vaBase, uszSection, &SectionHeader)) { *pcbWrite = 0;  return; }
    VmmWriteAsFile(H, pProcess, pModule->vaBase + SectionHeader.VirtualAddress, SectionHeader.Misc.VirtualSize, pb, cb, pcbWrite, cbOffset);
}

/*
* Write : function as specified by the module manager. The module manager will
* call into this callback function whenever a write shall occur from a "file".
* -- H
* -- ctxP
* -- pb
* -- cb
* -- pcbWrite
* -- cbOffset
* -- return
*/
NTSTATUS LdrModules_Write(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_CONTEXT ctxP, _In_reads_(cb) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbWrite, _In_ QWORD cbOffset)
{
    PVMM_MAP_MODULEENTRY pModule = NULL;
    PVMMOB_MAP_MODULE pObModuleMap = NULL;
    CHAR uszModuleName[MAX_PATH];
    LPCSTR uszModuleSubPath;
    PVMM_PROCESS pProcess = (PVMM_PROCESS)ctxP->pProcess;
    *pcbWrite = 0;
    uszModuleSubPath = CharUtil_PathSplitFirst(ctxP->uszPath, uszModuleName, sizeof(uszModuleName));
    if(uszModuleName[0] && uszModuleSubPath[0] && VmmMap_GetModuleEntryEx(H, (PVMM_PROCESS)ctxP->pProcess, 0, uszModuleName, 0, &pObModuleMap, &pModule)) {
        if(!_stricmp(uszModuleSubPath, "pefile.dll")) {
            PE_FileRaw_Write(H, pProcess, pModule->vaBase, pb, cb, pcbWrite, (DWORD)cbOffset);
        }
        if(!_strnicmp(uszModuleSubPath, "sectionsd\\", 10)) {
            LdrModules_Write_SectionsD(H, pProcess, pModule, uszModuleSubPath + 10, pb, cb, pcbWrite, cbOffset);
        }
        if(!_strnicmp(uszModuleSubPath, "directoriesd\\", 13)) {
            LdrModules_Write_DirectoriesD(H, pProcess, pModule, uszModuleSubPath + 13, pb, cb, pcbWrite, cbOffset);
        }
    }
    Ob_DECREF(pObModuleMap);
    return VMM_STATUS_SUCCESS;
}

/*
* Helper read function - Read the requested data directory file.
*/
NTSTATUS LdrModules_Read_DirectoriesD(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess, _In_ PVMM_MAP_MODULEENTRY pModule, _In_ LPCSTR uszDirectory, _Out_writes_to_(cb, *pcbRead) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset)
{
    DWORD i;
    IMAGE_DATA_DIRECTORY Directory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
    if(PE_DirectoryGetAll(H, pProcess, pModule->vaBase, NULL, Directory)) {
        for(i = 0; i < 16; i++) {
            if(!_stricmp(uszDirectory, PE_DATA_DIRECTORIES[i])) {
                return VmmReadAsFile(H, pProcess, pModule->vaBase + Directory[i].VirtualAddress, Directory[i].Size, pb, cb, pcbRead, cbOffset);
            }
        }
    }
    return VMMDLL_STATUS_FILE_INVALID;
}

/*
* Helper read function - Read the requested section header file.
*/
NTSTATUS LdrModules_Read_SectionsD(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess, _In_ PVMM_MAP_MODULEENTRY pModule, _In_ LPCSTR uszSection, _Out_writes_to_(cb, *pcbRead) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset)
{
    IMAGE_SECTION_HEADER SectionHeader;
    if(!PE_SectionGetFromName(H, pProcess, pModule->vaBase, uszSection, &SectionHeader)) { return VMMDLL_STATUS_FILE_INVALID; }
    return VmmReadAsFile(H, pProcess, pModule->vaBase + SectionHeader.VirtualAddress, SectionHeader.Misc.VirtualSize, pb, cb, pcbRead, cbOffset);
}

NTSTATUS LdrModules_Read_ModuleSubFile(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_CONTEXT ctx, _In_ PVMM_MAP_MODULEENTRY pModule, _In_ LPCSTR uszPath, _Out_writes_to_(cb, *pcbRead) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset)
{
    NTSTATUS nt = VMMDLL_STATUS_FILE_INVALID;
    PVMMOB_MAP_EAT pObEatMap = NULL;
    PVMMOB_MAP_IAT pObIatMap = NULL;
    POBLDRMODULES_CACHE_ENTRY pObCacheEntry = NULL;
    PVMM_PROCESS pProcess = (PVMM_PROCESS)ctx->pProcess;
    if(!_stricmp(uszPath, "base.txt")) {
        return Util_VfsReadFile_FromQWORD(pModule->vaBase, pb, cb, pcbRead, cbOffset, FALSE);
    }
    if(!_stricmp(uszPath, "entry.txt")) {
        return Util_VfsReadFile_FromQWORD(pModule->vaEntry, pb, cb, pcbRead, cbOffset, FALSE);
    }
    if(!_stricmp(uszPath, "fullname.txt")) {
        return Util_VfsReadFile_FromPBYTE(pModule->uszFullName, strlen(pModule->uszFullName), pb, cb, pcbRead, cbOffset);
    }
    if(!_stricmp(uszPath, "size.txt")) {
        return Util_VfsReadFile_FromDWORD(pModule->cbImageSize, pb, cb, pcbRead, cbOffset, FALSE);
    }
    if(!_stricmp(uszPath, "directories.txt")) {
        return LdrModules_ReadFile_Directories(H, pProcess, pModule->vaBase, pb, cb, pcbRead, cbOffset);
    }
    if(!_stricmp(uszPath, "export.txt")) {
        if(VmmMap_GetEAT(H, pProcess, pModule, &pObEatMap)) {
            nt = Util_VfsLineFixed_Read(
                H, (UTIL_VFSLINEFIXED_PFN_CB)LdrModules_ReadLineEAT_CB, pObEatMap, LDRMODULES_LINELENGTH_EAT, LDRMODULES_LINEHEADER_EAT,
                pObEatMap->pMap, pObEatMap->cMap, sizeof(VMM_MAP_EATENTRY),
                pb, cb, pcbRead, cbOffset
            );
            Ob_DECREF(pObEatMap);
        }
        return nt;
    }
    if(!_stricmp(uszPath, "import.txt")) {
        if(VmmMap_GetIAT(H, pProcess, pModule, &pObIatMap)) {
            nt = Util_VfsLineFixed_Read(
                H, (UTIL_VFSLINEFIXED_PFN_CB)LdrModules_ReadLineIAT_CB, pObIatMap, LDRMODULES_LINELENGTH_IAT, LDRMODULES_LINEHEADER_IAT,
                pObIatMap->pMap, pObIatMap->cMap, sizeof(VMM_MAP_IATENTRY),
                pb, cb, pcbRead, cbOffset
            );
            Ob_DECREF(pObIatMap);
        }
        return nt;
    }
    if(!_stricmp(uszPath, "pefile.dll")) {
        return PE_FileRaw_Read(H, pProcess, pModule->vaBase, pb, cb, pcbRead, (DWORD)cbOffset) ? VMMDLL_STATUS_SUCCESS : VMMDLL_STATUS_FILE_INVALID;
    }
    if(!_stricmp(uszPath, "sections.txt")) {
        return LdrModules_ReadFile_Sections(H, pProcess, pModule->vaBase, pb, cb, pcbRead, cbOffset);
    }
    if(!_stricmp(uszPath, "debuginfo.txt")) {
        return LdrModules_Read_PEDebugInfo(H, pProcess, pModule, pb, cb, pcbRead, cbOffset);
    }
    if(!_stricmp(uszPath, "versioninfo.txt")) {
        return LdrModules_Read_PEVersionInfo(H, pProcess, pModule, pb, cb, pcbRead, cbOffset);
    }
    if(!_strnicmp(uszPath, "sectionsd\\", 10)) {
        return LdrModules_Read_SectionsD(H, pProcess, pModule, uszPath + 10, pb, cb, pcbRead, cbOffset);
    }
    if(!_strnicmp(uszPath, "directoriesd\\", 13)) {
        return LdrModules_Read_DirectoriesD(H, pProcess, pModule, uszPath + 13, pb, cb, pcbRead, cbOffset);
    }
    return VMMDLL_STATUS_FILE_INVALID;
}

/*
* Read : function as specified by the module manager. The module manager will
* call into this callback function whenever a read shall occur from a "file".
* -- H
* -- ctxP
* -- pb
* -- cb
* -- pcbRead
* -- cbOffset
* -- return
*/
NTSTATUS LdrModules_Read(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_CONTEXT ctxP, _Out_writes_to_(cb, *pcbRead) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset)
{
    NTSTATUS nt = VMMDLL_STATUS_FILE_INVALID;
    CHAR uszModuleName[MAX_PATH];
    LPCSTR uszModuleSubPath;
    DWORD flags = 0;
    PVMM_MAP_MODULEENTRY pModule = NULL;
    PVMMOB_MAP_MODULE pObModuleMap = NULL;
    PVMMOB_MAP_UNLOADEDMODULE pObUnloadedModuleMap = NULL;
    if(!_stricmp(ctxP->uszPath, "modules.txt")) {
        if(VmmMap_GetModule(H, (PVMM_PROCESS)ctxP->pProcess, 0, &pObModuleMap)) {
            nt = Util_VfsLineFixed_Read(
                H, (UTIL_VFSLINEFIXED_PFN_CB)LdrModules_ModuleReadLineCB, ctxP->pProcess,
                (H->vmm.f32 ? LDRMODULES_LINELENGTH_X86 : LDRMODULES_LINELENGTH_X64),
                (H->vmm.f32 ? LDRMODULES_LINEHEADER_X86 : LDRMODULES_LINEHEADER_X64),
                pObModuleMap->pMap, pObModuleMap->cMap, sizeof(VMM_MAP_MODULEENTRY),
                pb, cb, pcbRead, cbOffset
            );
            Ob_DECREF(pObModuleMap);
        }
        return nt;
    }
    if(!_stricmp(ctxP->uszPath, "modules-v.txt")) {
        if(VmmMap_GetModule(H, (PVMM_PROCESS)ctxP->pProcess, 0, &pObModuleMap)) {
            nt = Util_VfsLineFixed_Read(
                H, (UTIL_VFSLINEFIXED_PFN_CB)LdrModules_ModuleVerbReadLineCB, ctxP->pProcess,
                (H->vmm.f32 ? LDRMODULES_LINELENGTH_X86_VERB : LDRMODULES_LINELENGTH_X64_VERB),
                (H->vmm.f32 ? LDRMODULES_LINEHEADER_X86_VERB : LDRMODULES_LINEHEADER_X64_VERB),
                pObModuleMap->pMap, pObModuleMap->cMap, sizeof(VMM_MAP_MODULEENTRY),
                pb, cb, pcbRead, cbOffset
            );
            Ob_DECREF(pObModuleMap);
        }
        return nt;
    }
    if(!_stricmp(ctxP->uszPath, "modules-versioninfo.txt")) {
        if(VmmMap_GetModule(H, (PVMM_PROCESS)ctxP->pProcess, VMM_MODULE_FLAG_VERSIONINFO, &pObModuleMap)) {
            nt = Util_VfsLineFixed_Read(
                H, (UTIL_VFSLINEFIXED_PFN_CB)LdrModules_ModuleVersionInfoReadLineCB, ctxP->pProcess,
                LDRMODULE_LINELENGTH_VERSIONINFO,
                LDRMODULE_LINEHEADER_VERSIONINFO,
                pObModuleMap->pMap, pObModuleMap->cMap, sizeof(VMM_MAP_MODULEENTRY),
                pb, cb, pcbRead, cbOffset
            );
            Ob_DECREF(pObModuleMap);
        }
        return nt;
    }
    if(!_stricmp(ctxP->uszPath, "unloaded_modules.txt")) {
        if(VmmMap_GetUnloadedModule(H, (PVMM_PROCESS)ctxP->pProcess, &pObUnloadedModuleMap)) {
            nt = Util_VfsLineFixed_Read(
                H, (UTIL_VFSLINEFIXED_PFN_CB)LdrModules_UnloadedReadLineCB, ctxP->pProcess,
                (H->vmm.f32 ? LDRMODULES_UNLOAD_LINELENGTH_X86 : LDRMODULES_UNLOAD_LINELENGTH_X64),
                (H->vmm.f32 ? LDRMODULES_UNLOAD_LINEHEADER_X86 : LDRMODULES_UNLOAD_LINEHEADER_X64),
                pObUnloadedModuleMap->pMap, pObUnloadedModuleMap->cMap, sizeof(VMM_MAP_UNLOADEDMODULEENTRY),
                pb, cb, pcbRead, cbOffset
            );
            Ob_DECREF(pObUnloadedModuleMap);
        }
        return nt;
    }
    uszModuleSubPath = CharUtil_PathSplitFirst(ctxP->uszPath, uszModuleName, sizeof(uszModuleName));
    *pcbRead = 0;
    flags |= CharUtil_StrEndsWith(uszModuleSubPath, "debuginfo.txt", TRUE) ? VMM_MODULE_FLAG_DEBUGINFO | VMM_MODULE_FLAG_VERSIONINFO : 0;
    flags |= CharUtil_StrEndsWith(uszModuleSubPath, "versioninfo.txt", TRUE) ? VMM_MODULE_FLAG_VERSIONINFO : 0;
    if(uszModuleName[0] && uszModuleSubPath[0] && VmmMap_GetModuleEntryEx(H, (PVMM_PROCESS)ctxP->pProcess, 0, uszModuleName, flags, &pObModuleMap, &pModule)) {
        nt = LdrModules_Read_ModuleSubFile(H, ctxP, pModule, uszModuleSubPath, pb, cb, pcbRead, cbOffset);
        Ob_DECREF(pObModuleMap);
        return nt;
    }
    Ob_DECREF(pObModuleMap);
    return VMMDLL_STATUS_FILE_INVALID;
}

/*
* List : function as specified by the module manager. The module manager will
* call into this callback function whenever a list directory shall occur from
* the given module.
* -- H
* -- ctxP
* -- pFileList
* -- return
*/
BOOL LdrModules_List(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_CONTEXT ctxP, _Inout_ PHANDLE pFileList)
{
    DWORD c, i, cbLine, cbLineV, cbLineUnload;
    CHAR szSectionName[9] = { 0 };
    CHAR uszPath1[MAX_PATH];
    LPCSTR uszPath2;
    PVMMOB_MAP_MODULE pObModuleMap = NULL;
    PVMM_MAP_MODULEENTRY pModule = NULL;
    PIMAGE_SECTION_HEADER pSections = NULL;
    IMAGE_DATA_DIRECTORY pDataDirectories[16];
    PVMMOB_MAP_UNLOADEDMODULE pObUnloadedModuleMap = NULL;
    PVMM_PROCESS pProcess = (PVMM_PROCESS)ctxP->pProcess;
    if(!VmmMap_GetModule(H, pProcess, 0, &pObModuleMap)) { goto fail; }
    // modules root directory -> add directory per DLL
    if(!ctxP->uszPath[0]) {
        for(i = 0; i < pObModuleMap->cMap; i++) {
            VMMDLL_VfsList_AddDirectory(pFileList, pObModuleMap->pMap[i].uszText, NULL);
        }
        cbLine = H->vmm.f32 ? LDRMODULES_LINELENGTH_X86 : LDRMODULES_LINELENGTH_X64;
        cbLineV = H->vmm.f32 ? LDRMODULES_LINELENGTH_X86_VERB : LDRMODULES_LINELENGTH_X64_VERB;
        cbLineUnload = H->vmm.f32 ? LDRMODULES_UNLOAD_LINELENGTH_X86 : LDRMODULES_UNLOAD_LINELENGTH_X64;
        VMMDLL_VfsList_AddFile(pFileList, "modules.txt", UTIL_VFSLINEFIXED_LINECOUNT(H, pObModuleMap->cMap) * cbLine, NULL);
        VMMDLL_VfsList_AddFile(pFileList, "modules-v.txt", UTIL_VFSLINEFIXED_LINECOUNT(H, pObModuleMap->cMap) * cbLineV, NULL);
        VMMDLL_VfsList_AddFile(pFileList, "modules-versioninfo.txt", UTIL_VFSLINEFIXED_LINECOUNT(H, pObModuleMap->cMap) * LDRMODULE_LINELENGTH_VERSIONINFO, NULL);
        if(VmmMap_GetUnloadedModule(H, pProcess, &pObUnloadedModuleMap)) {
            VMMDLL_VfsList_AddFile(pFileList, "unloaded_modules.txt", UTIL_VFSLINEFIXED_LINECOUNT(H, pObUnloadedModuleMap->cMap) * cbLineUnload, NULL);
            Ob_DECREF_NULL(&pObUnloadedModuleMap);
        }
        goto success;
    }
    // individual module directory -> list files
    uszPath2 = CharUtil_PathSplitFirst(ctxP->uszPath, uszPath1, sizeof(uszPath1));
    if(!(pModule = VmmMap_GetModuleEntry(H, pObModuleMap, uszPath1))) { goto fail; }
    // module-specific 'root' directory
    if(!uszPath2[0]) {
        VMMDLL_VfsList_AddFile(pFileList, "base.txt", 16, NULL);
        VMMDLL_VfsList_AddFile(pFileList, "debuginfo.txt", LDRMODULE_FILELENGTH_DEBUGINFO, NULL);
        VMMDLL_VfsList_AddFile(pFileList, "entry.txt", 16, NULL);
        VMMDLL_VfsList_AddFile(pFileList, "fullname.txt",  strlen(pModule->uszFullName), NULL);
        VMMDLL_VfsList_AddFile(pFileList, "size.txt", 8, NULL);
        VMMDLL_VfsList_AddFile(pFileList, "directories.txt", IMAGE_NUMBEROF_DIRECTORY_ENTRIES * LDRMODULES_LINELENGTH_DIRECTORIES, NULL);
        VMMDLL_VfsList_AddFile(pFileList, "export.txt", pModule->cEAT * LDRMODULES_LINELENGTH_EAT, NULL);
        VMMDLL_VfsList_AddFile(pFileList, "import.txt", pModule->cIAT * LDRMODULES_LINELENGTH_IAT, NULL);
        VMMDLL_VfsList_AddFile(pFileList, "sections.txt", pModule->cSection * LDRMODULES_LINELENGTH_SECTIONS, NULL);
        VMMDLL_VfsList_AddFile(pFileList, "pefile.dll", pModule->cbFileSizeRaw, NULL);
        VMMDLL_VfsList_AddFile(pFileList, "versioninfo.txt", LDRMODULE_FILELENGTH_VERSIONINFO, NULL);
        VMMDLL_VfsList_AddDirectory(pFileList, "sectionsd", NULL);
        VMMDLL_VfsList_AddDirectory(pFileList, "directoriesd", NULL);
        goto success;
    }
    // module-specific 'sectiond' directory
    if(uszPath2[0] && !_stricmp(uszPath2, "sectionsd")) {
        c = PE_SectionGetNumberOf(H, pProcess, pModule->vaBase);
        if(!(pSections = LocalAlloc(0, c * sizeof(IMAGE_SECTION_HEADER)))) { goto fail; }
        if(!PE_SectionGetAll(H, pProcess, pModule->vaBase, c, pSections)) { goto fail; }
        for(i = 0; i < c; i++) {
            if(pSections[i].Name[0]) {
                memcpy(szSectionName, pSections[i].Name, 8);
            } else {
                snprintf(szSectionName, 9, "%02x", i);
            }
            VMMDLL_VfsList_AddFile(pFileList, szSectionName, pSections[i].Misc.VirtualSize, NULL);
        }
        LocalFree(pSections);
        goto success;
    }
    // module-specific 'directoriesd' directory
    if(uszPath2[0] && !_stricmp(uszPath2, "directoriesd")) {
        ZeroMemory(pDataDirectories, IMAGE_NUMBEROF_DIRECTORY_ENTRIES * sizeof(IMAGE_DATA_DIRECTORY));
        if(PE_DirectoryGetAll(H, pProcess, pModule->vaBase, NULL, pDataDirectories)) {
            for(i = 0; i < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; i++) {
                VMMDLL_VfsList_AddFile(pFileList, (LPSTR)PE_DATA_DIRECTORIES[i], pDataDirectories[i].Size, NULL);
            }
        }
        goto success;
    }
fail:
    Ob_DECREF(pObModuleMap);
    return FALSE;
success:
    Ob_DECREF(pObModuleMap);
    return TRUE;
}

/*
* Initialization function. The module manager shall call into this function
* when the module shall be initialized. If the module wish to initialize it
* shall call the supplied pfnPluginManager_Register function.
* NB! the module does not have to register itself - for example if the target
* operating system or architecture is unsupported.
* -- H
* -- pRI
*/
VOID M_ProcLdrModules_Initialize(_In_ VMM_HANDLE H, _Inout_ PVMMDLL_PLUGIN_REGINFO pRI)
{
    if((pRI->magic != VMMDLL_PLUGIN_REGINFO_MAGIC) || (pRI->wVersion != VMMDLL_PLUGIN_REGINFO_VERSION)) { return; }
    if((pRI->tpSystem != VMM_SYSTEM_WINDOWS_64) && (pRI->tpSystem != VMM_SYSTEM_WINDOWS_32)) { return; }
    strcpy_s(pRI->reg_info.uszPathName, 128, "\\modules");           // module name
    pRI->reg_info.fProcessModule = TRUE;                             // module shows in process directory
    pRI->reg_fn.pfnList = LdrModules_List;                           // List function supported
    pRI->reg_fn.pfnRead = LdrModules_Read;                           // Read function supported
    if(H->dev.fWritable) {
        pRI->reg_fn.pfnWrite = LdrModules_Write;                     // Write function supported
    }
    pRI->pfnPluginManager_Register(H, pRI);
}
