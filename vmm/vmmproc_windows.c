// vmmproc_windows.h : implementation related to operating system and process
// parsing of virtual memory. Windows related features only.
//
// (c) Ulf Frisk, 2018
// Author: Ulf Frisk, pcileech@frizk.net
//

#include "vmmproc_windows.h"
#include "device.h"
#include "util.h"
#include <Winternl.h>

// ----------------------------------------------------------------------------
// WINDOWS SPECIFIC PROCESS RELATED FUNCTIONALITY BELOW:
//    GENERAL FUNCTIONALITY
// ----------------------------------------------------------------------------

PIMAGE_NT_HEADERS VmmProcWindows_GetVerifyHeaderPE(_In_ PVMM_PROCESS pProcess, _In_opt_ QWORD vaModule, _Inout_ PBYTE pbModuleHeader, _Out_ PBOOL pfHdr32)
{
    PIMAGE_DOS_HEADER dosHeader;
    PIMAGE_NT_HEADERS ntHeader;
    *pfHdr32 = FALSE;
    if(vaModule) {
        if(!VmmReadPage(pProcess, vaModule, pbModuleHeader)) { return NULL; }
    }
    dosHeader = (PIMAGE_DOS_HEADER)pbModuleHeader; // dos header.
    if(!dosHeader || dosHeader->e_magic != IMAGE_DOS_SIGNATURE) { return NULL; }
    if(dosHeader->e_lfanew > 0x800) { return NULL; }
    ntHeader = (PIMAGE_NT_HEADERS)(pbModuleHeader + dosHeader->e_lfanew); // nt header
    if(!ntHeader || ntHeader->Signature != IMAGE_NT_SIGNATURE) { return NULL; }
    if((ntHeader->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) && (ntHeader->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC)) { return NULL; }
    *pfHdr32 = (ntHeader->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC);
    return ntHeader;
}

// ----------------------------------------------------------------------------
// WINDOWS SPECIFIC PROCESS RELATED FUNCTIONALITY BELOW:
//    IMPORT/EXPORT DIRECTORY PARSING
// ----------------------------------------------------------------------------

VOID VmmProcWindows_PE_SECTION_DisplayBuffer(_In_ PVMM_PROCESS pProcess, _In_ PVMM_MODULEMAP_ENTRY pModule, _Out_opt_ PBYTE pbDisplayBufferOpt, _In_ DWORD cbDisplayBufferMax, _Out_ PDWORD pcbDisplayBuffer, _Out_opt_ PIMAGE_SECTION_HEADER pSectionsOpt)
{
    BYTE pbModuleHeader[0x1000];
    PIMAGE_NT_HEADERS64 ntHeader64;
    PIMAGE_NT_HEADERS32 ntHeader32;
    BOOL fHdr32;
    DWORD i;
    PIMAGE_SECTION_HEADER pSectionBase;
    if(pcbDisplayBuffer) { *pcbDisplayBuffer = 0; }
    if(!(ntHeader64 = VmmProcWindows_GetVerifyHeaderPE(pProcess, pModule->BaseAddress, pbModuleHeader, &fHdr32))) { return; }
    ntHeader32 = (PIMAGE_NT_HEADERS32)ntHeader64;
    pSectionBase = fHdr32 ?
        (PIMAGE_SECTION_HEADER)((QWORD)ntHeader32 + sizeof(IMAGE_NT_HEADERS32)) :
        (PIMAGE_SECTION_HEADER)((QWORD)ntHeader64 + sizeof(IMAGE_NT_HEADERS64));
    if(pbDisplayBufferOpt) {
        for(i = 0; i < (DWORD)min(32, ntHeader64->FileHeader.NumberOfSections); i++) {
            // 52 byte per line (indluding newline)
            *pcbDisplayBuffer += snprintf(
                pbDisplayBufferOpt + *pcbDisplayBuffer,
                cbDisplayBufferMax - *pcbDisplayBuffer,
                "%02x %-8.8s  %016llx %08x %08x %c%c%c\n",
                i,
                pSectionBase[i].Name,
                pModule->BaseAddress + pSectionBase[i].VirtualAddress,
                pSectionBase[i].VirtualAddress,
                pSectionBase[i].Misc.VirtualSize,
                (pSectionBase[i].Characteristics & IMAGE_SCN_MEM_READ) ? 'r' : '-',
                (pSectionBase[i].Characteristics & IMAGE_SCN_MEM_WRITE) ? 'w' : '-',
                (pSectionBase[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) ? 'x' : '-'
            );
        }
    }
    if(pSectionsOpt) {
        memcpy(pSectionsOpt, pSectionBase, ntHeader64->FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER));
    }
}

VOID VmmProcWindows_PE_DIRECTORY_DisplayBuffer(_In_ PVMM_PROCESS pProcess, _In_ PVMM_MODULEMAP_ENTRY pModule, _Out_opt_ PBYTE pbDisplayBufferOpt, _In_ DWORD cbDisplayBufferMax, _Out_ PDWORD pcbDisplayBuffer, _Out_opt_ PIMAGE_DATA_DIRECTORY pDataDirectoryOpt)
{
    LPCSTR DIRECTORIES[16] = { "EXPORT", "IMPORT", "RESOURCE", "EXCEPTION", "SECURITY", "BASERELOC", "DEBUG", "ARCHITECTURE", "GLOBALPTR", "TLS", "LOAD_CONFIG", "BOUND_IMPORT", "IAT", "DELAY_IMPORT", "COM_DESCRIPTOR", "RESERVED" };
    BYTE i, pbModuleHeader[0x1000];
    PIMAGE_NT_HEADERS64 ntHeader64;
    PIMAGE_NT_HEADERS32 ntHeader32;
    PIMAGE_DATA_DIRECTORY pDataDirectoryBase;
    BOOL fHdr32;
    if(pcbDisplayBuffer) { *pcbDisplayBuffer = 0; }
    if(!(ntHeader64 = VmmProcWindows_GetVerifyHeaderPE(pProcess, pModule->BaseAddress, pbModuleHeader, &fHdr32))) { return; }
    ntHeader32 = (PIMAGE_NT_HEADERS32)ntHeader64;
    pDataDirectoryBase = fHdr32 ? ntHeader32->OptionalHeader.DataDirectory : ntHeader64->OptionalHeader.DataDirectory;
    if(pbDisplayBufferOpt) {
        for(i = 0; i < 16; i++) {
            if(pbDisplayBufferOpt) {
                *pcbDisplayBuffer += snprintf(
                    pbDisplayBufferOpt + *pcbDisplayBuffer,
                    cbDisplayBufferMax - *pcbDisplayBuffer,
                    "%x %-16.16s %016llx %08x %08x\n",
                    i,
                    DIRECTORIES[i],
                    pModule->BaseAddress + pDataDirectoryBase[i].VirtualAddress,
                    pDataDirectoryBase[i].VirtualAddress,
                    pDataDirectoryBase[i].Size
                );
            }
        }
    }
    if(pDataDirectoryOpt) {
        memcpy(pDataDirectoryOpt, pDataDirectoryBase, 16 * sizeof(IMAGE_DATA_DIRECTORY));
    }
}


VOID VmmProcWindows_PE_LoadEAT_DisplayBuffer(_Inout_ PVMM_PROCESS pProcess, _Inout_ PVMM_MODULEMAP_ENTRY pModule, _Out_ PVMMPROC_WINDOWS_EAT_ENTRY pEATs, _Inout_ PDWORD pcEATs)
{
    BYTE pbModuleHeader[0x1000];
    PIMAGE_NT_HEADERS64 ntHeader64;
    PIMAGE_NT_HEADERS32 ntHeader32;
    QWORD oExportDirectory, cbExportDirectory;
    PBYTE pbExportDirectory = NULL;
    PIMAGE_EXPORT_DIRECTORY pExportDirectory;
    QWORD oNameOrdinal, ooName, oName, oFunction;
    WORD wOrdinalFnIdx;
    DWORD vaFunctionOffset;
    BOOL fHdr32;
    DWORD i, cEATs = *pcEATs;
    *pcEATs = 0;
    // load both 32/64 bit ntHeader (only one will be valid)
    if(!(ntHeader64 = VmmProcWindows_GetVerifyHeaderPE(pProcess, pModule->BaseAddress, pbModuleHeader, &fHdr32))) { goto cleanup; }
    ntHeader32 = (PIMAGE_NT_HEADERS32)ntHeader64;
    // Load Export Address Table (EAT)
    oExportDirectory = fHdr32 ?
        ntHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress :
        ntHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    cbExportDirectory = fHdr32 ?
        ntHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size :
        ntHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
    if(!oExportDirectory || !cbExportDirectory || cbExportDirectory > 0x01000000) { goto cleanup; }
    if(!(pbExportDirectory = LocalAlloc(0, cbExportDirectory))) { goto cleanup; }
    if(!VmmRead(pProcess, pModule->BaseAddress + oExportDirectory, pbExportDirectory, (DWORD)cbExportDirectory)) { goto cleanup; }
    // Walk exported functions
    pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)pbExportDirectory;
    for(i = 0; i < pExportDirectory->NumberOfNames && i < cEATs; i++) {
        //
        oNameOrdinal = pExportDirectory->AddressOfNameOrdinals + (i << 1);
        if((oNameOrdinal - sizeof(WORD) - oExportDirectory) > cbExportDirectory) { continue; }
        wOrdinalFnIdx = *(PWORD)(pbExportDirectory - oExportDirectory + oNameOrdinal);
        //
        ooName = pExportDirectory->AddressOfNames + (i << 2);
        if((ooName - sizeof(DWORD) - oExportDirectory) > cbExportDirectory) { continue; }
        oName = *(PDWORD)(pbExportDirectory - oExportDirectory + ooName);
        if((oName - 2 - oExportDirectory) > cbExportDirectory) { continue; }
        //
        oFunction = pExportDirectory->AddressOfFunctions + (wOrdinalFnIdx << 2);
        if((oFunction - sizeof(DWORD) - oExportDirectory) > cbExportDirectory) { continue; }
        vaFunctionOffset = *(PDWORD)(pbExportDirectory - oExportDirectory + oFunction);
        // store into caller supplied info struct
        pEATs[i].vaFunctionOffset = vaFunctionOffset;
        pEATs[i].vaFunction = pModule->BaseAddress + vaFunctionOffset;
        strncpy_s(pEATs[i].szFunction, 40, (LPSTR)(pbExportDirectory - oExportDirectory + oName), _TRUNCATE);
    }
    *pcEATs = i;
cleanup:
    LocalFree(pbExportDirectory);
}

VOID VmmProcWindows_PE_LoadIAT_DisplayBuffer(_Inout_ PVMM_PROCESS pProcess, _Inout_ PVMM_MODULEMAP_ENTRY pModule, _Out_ PVMMPROC_WINDOWS_IAT_ENTRY pIATs, _Inout_ PDWORD pcIATs)
{
    BYTE pbModuleHeader[0x1000];
    PIMAGE_NT_HEADERS64 ntHeader64;
    PIMAGE_NT_HEADERS32 ntHeader32;
    QWORD oImportDirectory;
    PIMAGE_IMPORT_DESCRIPTOR pIID;
    PQWORD pIAT64, pHNA64;
    PDWORD pIAT32, pHNA32;
    PBYTE pbModule;
    DWORD cbModule, cbRead;
    BOOL fHdr32, fFnName;
    DWORD c, i, j, cIATs = *pcIATs;
    *pcIATs = 0;
    // Load the module
    if(pModule->SizeOfImage > 0x01000000) { return; }
    cbModule = pModule->SizeOfImage;
    if(!(pbModule = LocalAlloc(LMEM_ZEROINIT, cbModule))) { return; }
    VmmReadEx(pProcess, pModule->BaseAddress, pbModule, cbModule, &cbRead, 0);
    if(cbRead <= 0x2000) { goto cleanup; }
    // load both 32/64 bit ntHeader (only one will be valid)
    if(!(ntHeader64 = VmmProcWindows_GetVerifyHeaderPE(pProcess, pModule->BaseAddress, pbModuleHeader, &fHdr32))) { goto cleanup; }
    ntHeader32 = (PIMAGE_NT_HEADERS32)ntHeader64;
    oImportDirectory = fHdr32 ?
        ntHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress :
        ntHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    if(!oImportDirectory || (oImportDirectory >= cbModule)) { goto cleanup; }
    // Walk imported modules / functions
    pIID = (PIMAGE_IMPORT_DESCRIPTOR)(pbModule + oImportDirectory);
    i = 0, c = 0;
    while((oImportDirectory + (i + 1) * sizeof(IMAGE_IMPORT_DESCRIPTOR) < cbModule) && pIID[i].FirstThunk) {
        if(c >= cIATs) { break; }
        if(pIID[i].Name > cbModule - 64) { i++; continue; }
        if(fHdr32) {
            // 32-bit PE
            j = 0;
            pIAT32 = (PDWORD)(pbModule + pIID[i].FirstThunk);
            pHNA32 = (PDWORD)(pbModule + pIID[i].OriginalFirstThunk);
            while(TRUE) {
                if(c >= cIATs) { break; }
                if((QWORD)(pIAT32 + j) + sizeof(DWORD) - (QWORD)pbModule > cbModule) { break; }
                if((QWORD)(pHNA32 + j) + sizeof(DWORD) - (QWORD)pbModule > cbModule) { break; }
                if(!pIAT32[j]) { break; }
                if(!pHNA32[j]) { break; }
                fFnName = (pHNA32[j] < cbModule - 40);
                // store into caller supplied info struct
                pIATs[c].vaFunction = pIAT32[j];
                strncpy_s(pIATs[c].szFunction, 40, (fFnName ? (LPSTR)(pbModule + pHNA32[j] + 2) : ""), _TRUNCATE);
                strncpy_s(pIATs[c].szModule, 64, (LPSTR)(pbModule + pIID[i].Name), _TRUNCATE);
                c++;
                j++;
            }
        } else {
            // 64-bit PE
            j = 0;
            pIAT64 = (PQWORD)(pbModule + pIID[i].FirstThunk);
            pHNA64 = (PQWORD)(pbModule + pIID[i].OriginalFirstThunk);
            while(TRUE) {
                if(c >= cIATs) { break; }
                if((QWORD)(pIAT64 + j) + sizeof(QWORD) - (QWORD)pbModule > cbModule) { break; }
                if((QWORD)(pHNA64 + j) + sizeof(QWORD) - (QWORD)pbModule > cbModule) { break; }
                if(!pIAT64[j]) { break; }
                if(!pHNA64[j]) { break; }
                fFnName = (pHNA64[j] < cbModule - 40);
                // store into caller supplied info struct
                pIATs[c].vaFunction = pIAT64[j];
                strncpy_s(pIATs[c].szFunction, 40, (fFnName ? (LPSTR)(pbModule + pHNA64[j] + 2) : ""), _TRUNCATE);
                strncpy_s(pIATs[c].szModule, 64, (LPSTR)(pbModule + pIID[i].Name), _TRUNCATE);
                c++;
                j++;
            }
        }
        i++;
    }
    *pcIATs = c;
cleanup:
    LocalFree(pbModule);
}

WORD VmmProcWindows_PE_GetNumberOfSection(_In_ PVMM_PROCESS pProcess, _Inout_ PVMM_MODULEMAP_ENTRY pModule, _In_opt_ PIMAGE_NT_HEADERS pbModuleHeaderOpt, _In_opt_ BOOL fHdr32)
{
    BYTE pbModuleHeader[0x1000];
    PIMAGE_NT_HEADERS64 pNtHeader64;
    PIMAGE_NT_HEADERS32 pNtHeader32;
    // load both 32/64 bit ntHeader unless already supplied in parameter (only one of 32/64 bit hdr will be valid)
    if(!(pNtHeader64 = pbModuleHeaderOpt ? pbModuleHeaderOpt : VmmProcWindows_GetVerifyHeaderPE(pProcess, pModule->BaseAddress, pbModuleHeader, &fHdr32))) { return 0; }
    pNtHeader32 = (PIMAGE_NT_HEADERS32)pNtHeader64;
    // retrieve number of sections
    return fHdr32 ? pNtHeader32->FileHeader.NumberOfSections : pNtHeader64->FileHeader.NumberOfSections;
}

DWORD VmmProcWindows_PE_GetNumberOfIAT(_In_ PVMM_PROCESS pProcess, _Inout_ PVMM_MODULEMAP_ENTRY pModule, _In_opt_ PIMAGE_NT_HEADERS pbModuleHeaderOpt, _In_opt_ BOOL fHdr32)
{
    BYTE pbModuleHeader[0x1000];
    PIMAGE_NT_HEADERS64 pNtHeader64;
    PIMAGE_NT_HEADERS32 pNtHeader32;
    DWORD cbImportDirectory, cbImportAddressTable, cIatEntries, cModules;
    // load both 32/64 bit ntHeader unless already supplied in parameter (only one of 32/64 bit hdr will be valid)
    if(!(pNtHeader64 = pbModuleHeaderOpt ? pbModuleHeaderOpt : VmmProcWindows_GetVerifyHeaderPE(pProcess, pModule->BaseAddress, pbModuleHeader, &fHdr32))) { return 0; }
    pNtHeader32 = (PIMAGE_NT_HEADERS32)pNtHeader64;
    // Calculate the number of functions in the import address table (IAT).
    // Number of functions = # IAT entries - # Imported modules
    cbImportDirectory = fHdr32 ?
        pNtHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size :
        pNtHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
    cbImportAddressTable = fHdr32 ?
        pNtHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].Size :
        pNtHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].Size;
    cIatEntries = cbImportAddressTable / (fHdr32 ? sizeof(DWORD) : sizeof(QWORD));
    cModules = cbImportDirectory / sizeof(IMAGE_IMPORT_DESCRIPTOR);
    return cIatEntries - cModules;
}

DWORD VmmProcWindows_PE_GetNumberOfEAT(_In_ PVMM_PROCESS pProcess, _Inout_ PVMM_MODULEMAP_ENTRY pModule, _In_opt_ PIMAGE_NT_HEADERS pbModuleHeaderOpt, _In_opt_ BOOL fHdr32)
{
    BYTE pbModuleHeader[0x1000];
    PIMAGE_NT_HEADERS64 pNtHeader64;
    PIMAGE_NT_HEADERS32 pNtHeader32;
    QWORD va, vaExportDirectory;
    IMAGE_EXPORT_DIRECTORY hdrExportDirectory;
    // load both 32/64 bit ntHeader unless already supplied in parameter (only one of 32/64 bit hdr will be valid)
    if(!(pNtHeader64 = pbModuleHeaderOpt ? pbModuleHeaderOpt : VmmProcWindows_GetVerifyHeaderPE(pProcess, pModule->BaseAddress, pbModuleHeader, &fHdr32))) { return 0; }
    pNtHeader32 = (PIMAGE_NT_HEADERS32)pNtHeader64;
    // Calculate the number of functions in the export address table (EAT).
    va = fHdr32 ?
        pNtHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress :
        pNtHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    vaExportDirectory = va ? pModule->BaseAddress + va : 0;
    if(vaExportDirectory && VmmRead(pProcess, vaExportDirectory, (PBYTE)&hdrExportDirectory, sizeof(IMAGE_EXPORT_DIRECTORY)) && (hdrExportDirectory.NumberOfNames < 0x00010000)) {
        return hdrExportDirectory.NumberOfNames;
    }
    return 0;
}

VOID VmmProcWindows_PE_SetSizeSectionIATEAT_DisplayBuffer(_In_ PVMM_PROCESS pProcess, _Inout_ PVMM_MODULEMAP_ENTRY pModule)
{
    BYTE pbModuleHeader[0x1000];
    PIMAGE_NT_HEADERS64 pNtHeaders64;
    BOOL fHdr32;
    // check if function is required
    if(pModule->fLoadedEAT && pModule->fLoadedIAT) { return; }
    // load both 32/64 bit ntHeader (only one will be valid)
    if(!(pNtHeaders64 = VmmProcWindows_GetVerifyHeaderPE(pProcess, pModule->BaseAddress, pbModuleHeader, &fHdr32))) { return; }
    // calculate display buffer size of: SECTIONS, EAT, IAT
    pModule->cbDisplayBufferSections = VmmProcWindows_PE_GetNumberOfSection(pProcess, pModule, pNtHeaders64, fHdr32) * 52;  // each display buffer human readable line == 52 bytes.
    if(!pModule->fLoadedEAT) {
        pModule->cbDisplayBufferEAT = VmmProcWindows_PE_GetNumberOfEAT(pProcess, pModule, pNtHeaders64, fHdr32) * 64;       // each display buffer human readable line == 64 bytes.
        pModule->fLoadedEAT = TRUE;
    }
    if(!pModule->fLoadedIAT) {
        pModule->cbDisplayBufferIAT = VmmProcWindows_PE_GetNumberOfIAT(pProcess, pModule, pNtHeaders64, fHdr32) * 128;      // each display buffer human readable line == 128 bytes.
        pModule->fLoadedIAT = TRUE;
    }
}

// ----------------------------------------------------------------------------
// WINDOWS SPECIFIC PROCESS RELATED FUNCTIONALITY BELOW:
//    PEB/LDR USER MODE PARSING CODE (64-bit and 32-bit)
// ----------------------------------------------------------------------------

// more extensive definition of the Windows LDR_DATA_TABLE_ENTRY struct.
typedef struct _VMMPROC_LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY          InLoadOrderModuleList;
    LIST_ENTRY          InMemoryOrderModuleList;
    LIST_ENTRY          InInitializationOrderModuleList;
    PVOID               BaseAddress;
    PVOID               EntryPoint;
    ULONG               SizeOfImage;
    UNICODE_STRING      FullDllName;
    UNICODE_STRING      BaseDllName;
    ULONG               Flags;
    SHORT               LoadCount;
    SHORT               TlsIndex;
    LIST_ENTRY          HashTableEntry;
    ULONG               TimeDateStamp;
} VMMPROC_LDR_DATA_TABLE_ENTRY, *PVMMPROC_LDR_DATA_TABLE_ENTRY;

QWORD VmmProcWindows_GetProcAddress(_In_ PVMM_PROCESS pProcess, _In_ QWORD vaModule, _In_ LPSTR lpProcName);

VOID VmmProcWindows_ScanLdrModules64(_In_ PVMM_PROCESS pProcess, _Inout_ PVMM_MODULEMAP_ENTRY pModules, _Inout_ PDWORD pcModules, _In_ DWORD cModulesMax, _Out_ PBOOL fWow64)
{
    QWORD vaPsLoadedModuleList, vaModuleLdrFirst, vaModuleLdr = 0;
    BYTE pbPEB[sizeof(PEB)], pbPEBLdrData[sizeof(PEB_LDR_DATA)], pbLdrModule[sizeof(VMMPROC_LDR_DATA_TABLE_ENTRY)];
    PPEB pPEB = (PPEB)pbPEB;
    PPEB_LDR_DATA pPEBLdrData = (PPEB_LDR_DATA)pbPEBLdrData;
    PVMMPROC_LDR_DATA_TABLE_ENTRY pLdrModule = (PVMMPROC_LDR_DATA_TABLE_ENTRY)pbLdrModule;
    PVMM_MODULEMAP_ENTRY pModule;
    *fWow64 = FALSE;
    if(pProcess->fUserOnly) {
        // User mode process -> walk PEB LDR list to enumerate modules / .dlls.
        if(!pProcess->os.win.vaPEB) { return; }
        if(!VmmRead(pProcess, pProcess->os.win.vaPEB, pbPEB, sizeof(PEB))) { return; }
        if(!VmmRead(pProcess, (QWORD)pPEB->Ldr, pbPEBLdrData, sizeof(PEB_LDR_DATA))) { return; }
        vaModuleLdr = vaModuleLdrFirst = (QWORD)pPEBLdrData->InMemoryOrderModuleList.Flink - 0x10; // InLoadOrderModuleList == InMemoryOrderModuleList - 0x10
    } else {
        // Kernel mode process -> walk PsLoadedModuleList to enumerate drivers / .sys and .dlls.
        vaPsLoadedModuleList = VmmProcWindows_GetProcAddress(pProcess, ctxVmm->kernelinfo.vaBase, "PsLoadedModuleList");
        if(!vaPsLoadedModuleList) { return; }
        if(!VmmRead(pProcess, vaPsLoadedModuleList, (PBYTE)&vaModuleLdrFirst, sizeof(QWORD)) || !vaModuleLdrFirst) { return; }
        if(!VmmRead(pProcess, vaPsLoadedModuleList, pbPEBLdrData, sizeof(PEB_LDR_DATA))) { return; }
        vaModuleLdr = vaModuleLdrFirst;
    }
    do {
        if(!VmmRead(pProcess, vaModuleLdr, pbLdrModule, sizeof(VMMPROC_LDR_DATA_TABLE_ENTRY))) { break; }
        pModule = pModules + *pcModules;
        pModule->BaseAddress = (QWORD)pLdrModule->BaseAddress;
        pModule->EntryPoint = (QWORD)pLdrModule->EntryPoint;
        pModule->SizeOfImage = (DWORD)pLdrModule->SizeOfImage;
        pModule->fWoW64 = FALSE;
        if(!pLdrModule->BaseDllName.Length) { break; }
        if(!VmmReadString_Unicode2Ansi(pProcess, (QWORD)pLdrModule->BaseDllName.Buffer, pModule->szName, min(31, pLdrModule->BaseDllName.Length))) { break; }
        *fWow64 = pProcess->fUserOnly && (*fWow64 || !memcmp(pModule->szName, "wow64.dll", 10));
        vmmprintfvv("vmmproc.c!VmmProcWindows_ScanLdrModules: %016llx %016llx %016llx %08x %i %s\n", vaModuleLdr, pModule->BaseAddress, pModule->EntryPoint, pModule->SizeOfImage, (pModule->fWoW64 ? 1 : 0), pModule->szName);
        vaModuleLdr = (QWORD)pLdrModule->InLoadOrderModuleList.Flink;
        *pcModules = *pcModules + 1;
    } while((vaModuleLdr != vaModuleLdrFirst) && (*pcModules < cModulesMax));
}

typedef struct _UNICODE_STRING32 {
    USHORT Length;
    USHORT MaximumLength;
    DWORD  Buffer;
} UNICODE_STRING32;

typedef struct _LDR_MODULE32 {
    LIST_ENTRY32        InLoadOrderModuleList;
    LIST_ENTRY32        InMemoryOrderModuleList;
    LIST_ENTRY32        InInitializationOrderModuleList;
    DWORD               BaseAddress;
    DWORD               EntryPoint;
    ULONG               SizeOfImage;
    UNICODE_STRING32    FullDllName;
    UNICODE_STRING32    BaseDllName;
    ULONG               Flags;
    SHORT               LoadCount;
    SHORT               TlsIndex;
    LIST_ENTRY32        HashTableEntry;
    ULONG               TimeDateStamp;
} LDR_MODULE32, *PLDR_MODULE32;

typedef struct _PEB_LDR_DATA32 {
    BYTE Reserved1[8];
    DWORD Reserved2[3];
    LIST_ENTRY32 InMemoryOrderModuleList;
} PEB_LDR_DATA32, *PPEB_LDR_DATA32;

typedef struct _PEB32 {
    BYTE Reserved1[2];
    BYTE BeingDebugged;
    BYTE Reserved2[1];
    DWORD Reserved3[2];
    DWORD Ldr;
    // ...
} PEB32, *PPEB32;

_Success_(return)
BOOL VmmProcWindows_ScanLdrModules32(_In_ PVMM_PROCESS pProcess, _Inout_ PVMM_MODULEMAP_ENTRY pModules, _Inout_ PDWORD pcModules, _In_ DWORD cModulesMax)
{
    DWORD vaModuleLdrFirst32, vaModuleLdr32 = 0;
    BYTE pbPEB32[sizeof(PEB32)], pbPEBLdrData32[sizeof(PEB_LDR_DATA32)], pbLdrModule32[sizeof(LDR_MODULE32)];
    PPEB32 pPEB32 = (PPEB32)pbPEB32;
    PPEB_LDR_DATA32 pPEBLdrData32 = (PPEB_LDR_DATA32)pbPEBLdrData32;
    PLDR_MODULE32 pLdrModule32 = (PLDR_MODULE32)pbLdrModule32;
    PVMM_MODULEMAP_ENTRY pModule;
    if(!pProcess->os.win.vaPEB) { return FALSE; }
    if(!VmmRead(pProcess, pProcess->os.win.vaPEB32, pbPEB32, sizeof(PEB32))) { return FALSE; }
    if(!VmmRead(pProcess, (DWORD)pPEB32->Ldr, pbPEBLdrData32, sizeof(PEB_LDR_DATA32))) { return FALSE; }
    vaModuleLdr32 = vaModuleLdrFirst32 = (DWORD)pPEBLdrData32->InMemoryOrderModuleList.Flink - 0x08; // InLoadOrderModuleList == InMemoryOrderModuleList - 0x08
    do {
        if(!VmmRead(pProcess, vaModuleLdr32, pbLdrModule32, sizeof(LDR_MODULE32))) { break; }
        pModule = pModules + *pcModules;
        pModule->BaseAddress = (QWORD)pLdrModule32->BaseAddress;
        pModule->EntryPoint = (QWORD)pLdrModule32->EntryPoint;
        pModule->SizeOfImage = (DWORD)pLdrModule32->SizeOfImage;
        pModule->fWoW64 = TRUE;
        if(!pLdrModule32->BaseDllName.Length) { break; }
        if(!VmmReadString_Unicode2Ansi(pProcess, (QWORD)pLdrModule32->BaseDllName.Buffer, pModule->szName, min(31, pLdrModule32->BaseDllName.Length))) { break; }
        vmmprintfvv("vmmproc.c!VmmProcWindows_ScanLdrModules32: %08x %08x %08x %08x %s\n", vaModuleLdr32, (DWORD)pModule->BaseAddress, (DWORD)pModule->EntryPoint, pModule->SizeOfImage, pModule->szName);
        vaModuleLdr32 = (QWORD)pLdrModule32->InLoadOrderModuleList.Flink;
        *pcModules = *pcModules + 1;
    } while((vaModuleLdr32 != vaModuleLdrFirst32) && (*pcModules < cModulesMax));
    return TRUE;
}

VOID VmmProcWindows_InitializeLdrModules(_In_ PVMM_PROCESS pProcess)
{
    PVMM_MODULEMAP_ENTRY pModules, pModule;
    PBYTE pbResult;
    DWORD i, o, cModules;
    BOOL result, fWow64;
    // clear out any previous data
    LocalFree(pProcess->os.win.pbLdrModulesDisplayCache);
    pProcess->os.win.pbLdrModulesDisplayCache = NULL;
    pProcess->os.win.cbLdrModulesDisplayCache = 0;
    pProcess->os.win.vaENTRY = 0;
    // allocate and enumerate
    pModules = (PVMM_MODULEMAP_ENTRY)LocalAlloc(LMEM_ZEROINIT, 512 * sizeof(VMM_MODULEMAP_ENTRY));
    if(!pModules) { goto fail; }
    cModules = 0;
    VmmProcWindows_ScanLdrModules64(pProcess, pModules, &cModules, 512, &fWow64);
    if((cModules > 0) && (!pModules[cModules - 1].BaseAddress)) { cModules--; }
    if(fWow64) {
        pProcess->os.win.vaPEB32 = (DWORD)pProcess->os.win.vaPEB - 0x1000;
        result = VmmProcWindows_ScanLdrModules32(pProcess, pModules, &cModules, 512);
        if(!result) {
            pProcess->os.win.vaPEB32 = (DWORD)pProcess->os.win.vaPEB + 0x1000;
            result = VmmProcWindows_ScanLdrModules32(pProcess, pModules, &cModules, 512);
        }
        if(!result) {
            pProcess->os.win.vaPEB32 = 0;
        }
    }
    if((cModules > 0) && (!pModules[cModules - 1].BaseAddress)) { cModules--; }
    if(!cModules) { goto fail; }
    // generate display cache
    pProcess->os.win.vaENTRY = pModules[0].EntryPoint;
    pbResult = pProcess->os.win.pbLdrModulesDisplayCache = (PBYTE)LocalAlloc(LMEM_ZEROINIT, 89 * cModules);
    if(!pbResult) { goto fail; }
    for(i = 0, o = 0; i < cModules; i++) {
        pModule = pModules + i;
        if(!pModule->BaseAddress) { continue; }
        o += snprintf(
            pbResult + o,
            89,
            "%04x %8x %016llx-%016llx      %s %s\n",
            i,
            pModule->SizeOfImage >> 12,
            pModule->BaseAddress,
            pModule->BaseAddress + pModule->SizeOfImage - 1,
            pModule->fWoW64 ? "32" : "  ",
            pModule->szName
        );
    }
    pProcess->os.win.fWow64 = fWow64;
    // update memory map with names
    for(i = 0; i < cModules; i++) {
        pModule = pModules + i;
        VmmMapTag(pProcess, pModule->BaseAddress, pModule->BaseAddress + pModule->SizeOfImage, pModule->szName, NULL, pModule->fWoW64);
    }
    pProcess->os.win.cbLdrModulesDisplayCache = o;
    // copy modules map into Process struct
    pProcess->pModuleMap = (PVMM_MODULEMAP_ENTRY)LocalAlloc(0, cModules * sizeof(VMM_MODULEMAP_ENTRY));
    if(!pProcess->pModuleMap) { goto fail; }
    memcpy(pProcess->pModuleMap, pModules, cModules * sizeof(VMM_MODULEMAP_ENTRY));
    pProcess->cModuleMap = cModules;
fail:
    LocalFree(pModules);
}

// ----------------------------------------------------------------------------
// WINDOWS SPECIFIC PROCESS RELATED FUNCTIONALITY BELOW:
// ----------------------------------------------------------------------------

/*
* Locate the virtual base address of ntoskrnl.exe given any address inside the
* kernel. Localization will be done by a scan-back method. A maximum of 16MB
* will be scanned back.
*/
QWORD VmmProcWindows_FindNtoskrnl(_In_ PVMM_PROCESS pSystemProcess, _In_ QWORD vaKernelEntry)
{
    PBYTE pb;
    QWORD vaBase, oPage, o, vaNtosBase = 0;
    BOOL fINITKDBG, fPOOLCODE;
    DWORD cbRead;
    pb = LocalAlloc(0, 0x200000);
    if(!pb) { goto cleanup; }
    // Scan back in 2MB chunks a time, (ntoskrnl.exe is loaded in 2MB pages).
    for(vaBase = vaKernelEntry & ~0x1fffff; vaBase + 0x02000000 > vaKernelEntry; vaBase -= 0x200000) {
        VmmReadEx(pSystemProcess, vaBase, pb, 0x200000, &cbRead, 0);
        // only fail here if all virtual memory in read fails. reason is that kernel is
        // properly mapped in memory (with NX MZ header in separate page) with empty
        // space before next valid kernel pages when running Virtualization Based Security.
        if(!cbRead) { goto cleanup; }
        for(oPage = 0; oPage < 0x200000; oPage += 0x1000) {
            if(*(PWORD)(pb + oPage) == 0x5a4d) { // MZ header
                fINITKDBG = FALSE;
                fPOOLCODE = FALSE;
                for(o = 0; o < 0x1000; o += 8) {
                    if(*(PQWORD)(pb + oPage + o) == 0x4742444B54494E49) { // INITKDBG
                        fINITKDBG = TRUE;
                    }
                    if(*(PQWORD)(pb + oPage + o) == 0x45444F434C4F4F50) { // POOLCODE
                        fPOOLCODE = TRUE;
                    }
                    if(fINITKDBG && fPOOLCODE) {
                        vaNtosBase = vaBase + oPage;
                        goto cleanup;
                    }
                }
            }
        }
    }
cleanup:
    LocalFree(pb);
    return vaNtosBase;
}

/*
* Perform GetProcAddress given a PE header.
* NB! very messy code due to lots of sanity checks on untrusted data.
*/
QWORD VmmProcWindows_GetProcAddress(_In_ PVMM_PROCESS pProcess, _In_ QWORD vaModule, _In_ LPSTR lpProcName)
{
    BYTE pbModuleHeader[0x1000];
    PIMAGE_NT_HEADERS32 ntHeader32;
    PIMAGE_NT_HEADERS64 ntHeader64;
    PDWORD pdwRVAAddrNames, pdwRVAAddrFunctions;
    PWORD pwNameOrdinals;
    DWORD i, cbProcName, cbExportDirectoryOffset;
    LPSTR sz;
    QWORD vaFnPtr;
    QWORD vaExportDirectory;
    DWORD cbExportDirectory;
    PBYTE pbExportDirectory = NULL;
    QWORD vaRVAAddrNames, vaNameOrdinals, vaRVAAddrFunctions;
    BOOL fHdr32;
    if(!(ntHeader64 = VmmProcWindows_GetVerifyHeaderPE(pProcess, vaModule, pbModuleHeader, &fHdr32))) { goto cleanup; }
    if(fHdr32) { // 32-bit PE
        ntHeader32 = (PIMAGE_NT_HEADERS32)ntHeader64;
        vaExportDirectory = vaModule + ntHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        cbExportDirectory = ntHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
    } else { // 64-bit PE
        vaExportDirectory = vaModule + ntHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        cbExportDirectory = ntHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
    }
    if((cbExportDirectory < sizeof(IMAGE_EXPORT_DIRECTORY)) || (cbExportDirectory > 0x01000000) || (vaExportDirectory == vaModule) || (vaExportDirectory > vaModule + 0x80000000)) { goto cleanup; }
    if(!(pbExportDirectory = LocalAlloc(0, cbExportDirectory))) { goto cleanup; }
    if(!VmmRead(pProcess, vaExportDirectory, pbExportDirectory, cbExportDirectory)) { goto cleanup; }
    PIMAGE_EXPORT_DIRECTORY exp = (PIMAGE_EXPORT_DIRECTORY)pbExportDirectory;
    if(!exp || !exp->NumberOfNames || !exp->AddressOfNames) { goto cleanup; }
    vaRVAAddrNames = vaModule + exp->AddressOfNames;
    vaNameOrdinals = vaModule + exp->AddressOfNameOrdinals;
    vaRVAAddrFunctions = vaModule + exp->AddressOfFunctions;
    if((vaRVAAddrNames < vaExportDirectory) || (vaRVAAddrNames > vaExportDirectory + cbExportDirectory - exp->NumberOfNames * sizeof(DWORD))) { goto cleanup; }
    if((vaNameOrdinals < vaExportDirectory) || (vaNameOrdinals > vaExportDirectory + cbExportDirectory - exp->NumberOfNames * sizeof(WORD))) { goto cleanup; }
    if((vaRVAAddrFunctions < vaExportDirectory) || (vaRVAAddrFunctions > vaExportDirectory + cbExportDirectory - exp->NumberOfNames * sizeof(DWORD))) { goto cleanup; }
    cbProcName = (DWORD)strnlen_s(lpProcName, MAX_PATH) + 1;
    cbExportDirectoryOffset = (DWORD)(vaExportDirectory - vaModule);
    pdwRVAAddrNames = (PDWORD)(pbExportDirectory + exp->AddressOfNames - cbExportDirectoryOffset);
    pwNameOrdinals = (PWORD)(pbExportDirectory + exp->AddressOfNameOrdinals - cbExportDirectoryOffset);
    pdwRVAAddrFunctions = (PDWORD)(pbExportDirectory + exp->AddressOfFunctions - cbExportDirectoryOffset);
    for(i = 0; i < exp->NumberOfNames; i++) {
        if(pdwRVAAddrNames[i] - cbExportDirectoryOffset + cbProcName > cbExportDirectory) { continue; }
        sz = (LPSTR)(pbExportDirectory + pdwRVAAddrNames[i] - cbExportDirectoryOffset);
        if(0 == memcmp(sz, lpProcName, cbProcName)) {
            if(pwNameOrdinals[i] >= exp->NumberOfFunctions) { goto cleanup; }
            vaFnPtr = (QWORD)(vaModule + pdwRVAAddrFunctions[pwNameOrdinals[i]]);
            LocalFree(pbExportDirectory);
            return vaFnPtr;
        }
    }
cleanup:
    LocalFree(pbExportDirectory);
    return 0;
}

/*
* Retrieve PE module name given a PE header.
* Function handles both 64-bit and 32-bit PE images.
* NB! very messy code due to lots of sanity checks on untrusted data.
*/
_Success_(return)
BOOL VmmProcWindows_GetModuleName(_In_ PVMM_PROCESS pProcess, _In_ QWORD vaModule, _Out_ CHAR pbModuleName[MAX_PATH], _Out_ PDWORD pdwSize, _In_opt_ PBYTE pbPageMZHeaderPreCacheOpt, _In_ BOOL fDummyPENameOnExportDirectoryFail)
{
    PIMAGE_NT_HEADERS64 ntHeader64;
    PIMAGE_NT_HEADERS32 ntHeader32;
    PIMAGE_EXPORT_DIRECTORY exp;
    QWORD vaExportDirectory;
    DWORD cbImageSize, cbExportDirectory;
    BYTE pbModuleHeader[0x1000], pbExportDirectory[sizeof(IMAGE_EXPORT_DIRECTORY)];
    BOOL fHdr32;
    if(pbPageMZHeaderPreCacheOpt) {
        memcpy(pbModuleHeader, pbPageMZHeaderPreCacheOpt, 0x1000);
        ntHeader64 = VmmProcWindows_GetVerifyHeaderPE(pProcess, 0, pbModuleHeader, &fHdr32);
    } else {
        ntHeader64 = VmmProcWindows_GetVerifyHeaderPE(pProcess, vaModule, pbModuleHeader, &fHdr32);
    }
    if(!ntHeader64) { return FALSE; }
    if(!fHdr32) { // 64-bit PE
        *pdwSize = ntHeader64->OptionalHeader.SizeOfImage;
        vaExportDirectory = vaModule + ntHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        cbExportDirectory = ntHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
        cbImageSize = ntHeader64->OptionalHeader.SizeOfImage;
    } else { // 32-bit PE
        ntHeader32 = (PIMAGE_NT_HEADERS32)ntHeader64;
        *pdwSize = ntHeader32->OptionalHeader.SizeOfImage;
        vaExportDirectory = vaModule + ntHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        cbExportDirectory = ntHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
        cbImageSize = ntHeader32->OptionalHeader.SizeOfImage;
    }
    if((cbExportDirectory < sizeof(IMAGE_EXPORT_DIRECTORY)) || (vaExportDirectory == vaModule) || (cbExportDirectory > cbImageSize)) { goto fail; }
    if(!VmmRead(pProcess, vaExportDirectory, pbExportDirectory, sizeof(IMAGE_EXPORT_DIRECTORY))) { goto fail; }
    exp = (PIMAGE_EXPORT_DIRECTORY)pbExportDirectory;
    if(!exp || !exp->Name || exp->Name > cbImageSize) { goto fail; }
    pbModuleName[MAX_PATH - 1] = 0;
    if(!VmmRead(pProcess, vaModule + exp->Name, pbModuleName, MAX_PATH - 1)) { goto fail; }
    return TRUE;
fail:
    if(fDummyPENameOnExportDirectoryFail) {
        memcpy(pbModuleName, "UNKNOWN", 8);
        return TRUE;
    }
    return FALSE;
}

/*
* Load module proc names into memory map list if possible.
* NB! this function parallelize reads of MZ header candidates to speed things up.
*/
VOID VmmProcWindows_ScanHeaderPE(_In_ PVMM_PROCESS pProcess)
{
    typedef struct tdMAP {
        MEM_IO_SCATTER_HEADER dma;
        PVMM_MEMMAP_ENTRY mme;
        BYTE pb[0x1000];
    } MAP, *PMAP;
    PMAP pMap, pMaps;
    PPMEM_IO_SCATTER_HEADER ppDMAs;
    PBYTE pbBuffer;
    DWORD i, cDMAs = 0, cbImageSize;
    BOOL result;
    CHAR szBuffer[MAX_PATH];
    // 1: checks and allocate buffers for parallell read of MZ header candidates
    if(!pProcess->cMemMap || !pProcess->pMemMap) { return; }
    pbBuffer = LocalAlloc(LMEM_ZEROINIT, 0x400 * (sizeof(PMEM_IO_SCATTER_HEADER) + sizeof(MAP)));
    if(!pbBuffer) { return; }
    ppDMAs = (PPMEM_IO_SCATTER_HEADER)pbBuffer;
    pMaps = (PMAP)(pbBuffer + 0x400 * sizeof(PMEM_IO_SCATTER_HEADER));
    // 2: scan memory map for MZ header candidates and put them on list for read
    for(i = 0; i < pProcess->cMemMap - 1; i++) {
        if(
            (pProcess->pMemMap[i].cPages == 1) &&                           // PE header is only 1 page
            !(pProcess->pMemMap[i].AddrBase & 0xffff) &&                    // starts at even 0x10000 offset
            !pProcess->pMemMap[i].szTag[0] &&                               // tag not already set
            (pProcess->pMemMap[i].fPage & VMM_MEMMAP_FLAG_PAGE_NX) &&       // no-execute
            !(pProcess->pMemMap[i + 1].fPage & VMM_MEMMAP_FLAG_PAGE_NX))    // next page is executable
        {
            pMap = pMaps + cDMAs;
            pMap->mme = pProcess->pMemMap + i;
            pMap->dma.cbMax = 0x1000;
            pMap->dma.qwA = pProcess->pMemMap[i].AddrBase;
            pMap->dma.pb = pMap->pb;
            ppDMAs[cDMAs] = &pMap->dma;
            cDMAs++;
            if(cDMAs == 0x400) { break; }
        }
    }
    // 3: read all MZ header candicates previously selected and try load name from them (after read is successful)
    VmmReadScatterVirtual(pProcess, ppDMAs, cDMAs, 0);
    for(i = 0; i < cDMAs; i++) {
        if(pMaps[i].dma.cb == 0x1000) {
            pMap = pMaps + i;
            result = VmmProcWindows_GetModuleName(pProcess, pMap->mme->AddrBase, szBuffer, &cbImageSize, pMap->pb, TRUE);
            if(result && (cbImageSize < 0x01000000)) {
                VmmMapTag(pProcess, pMap->mme->AddrBase, pMap->mme->AddrBase + cbImageSize, szBuffer, NULL, FALSE);
            }
        }
    }
    LocalFree(pbBuffer);
}

#define VMMPROC_EPROCESS_MAX_SIZE 0x500

/*
* Very ugly hack that tries to locate some offsets required withn the EPROCESS struct.
*/
_Success_(return)
BOOL VmmProcWindows_OffsetLocatorEPROCESS(_In_ PVMM_PROCESS pSystemProcess,
    _Out_ PDWORD pdwoState, _Out_ PDWORD pdwoPML4, _Out_ PDWORD pdwoName, _Out_ PDWORD pdwoPID,
    _Out_ PDWORD pdwoFLink, _Out_ PDWORD pdwoPEB, _Out_ PDWORD dwoPML4_User)
{
    BOOL f;
    DWORD i;
    QWORD va1, vaPEB, paPEB;
    BYTE pb0[VMMPROC_EPROCESS_MAX_SIZE], pb1[VMMPROC_EPROCESS_MAX_SIZE], pbPage[0x1000], pbZero[0x800];
    QWORD paMax, paPML4_0, paPML4_1;
    if(!VmmRead(pSystemProcess, pSystemProcess->os.win.vaEPROCESS, pb0, 0x500)) { return FALSE; }
    if(ctxMain->cfg.fVerboseExtra) {
        vmmprintf("vmmproc.c!VmmProcWindows_OffsetLocatorEPROCESS: %016llx %016llx\n", pSystemProcess->paPML4, pSystemProcess->os.win.vaEPROCESS);
        Util_PrintHexAscii(pb0, VMMPROC_EPROCESS_MAX_SIZE, 0);
    }
    // find offset State (static for now)
    if(*(PDWORD)(pb0 + 0x04)) { return FALSE; }
    *pdwoState = 0x04;
    // find offset PML4 (static for now)
    if(pSystemProcess->paPML4 != (0xfffffffffffff000 & *(PQWORD)(pb0 + 0x28))) { return FALSE; }
    *pdwoPML4 = 0x28;
    // find offset for Name
    for(i = 0, f = FALSE; i < VMMPROC_EPROCESS_MAX_SIZE - 8; i += 8) {
        if(*(PQWORD)(pb0 + i) == 0x00006D6574737953) {
            *pdwoName = i;
            f = TRUE;
            break;
        }
    }
    if(!f) { return FALSE; }
    // find offset for PID, FLink, BLink (assumed to be following eachother)
    for(i = 0, f = FALSE; i < VMMPROC_EPROCESS_MAX_SIZE - 8; i += 8) {
        if(*(PQWORD)(pb0 + i) == 4) {
            // PID = correct, this is a candidate
            if(0xffff000000000000 != (0xffff000000000003 & *(PQWORD)(pb0 + i + 8))) { continue; }    // FLink not valid kernel pointer
            va1 = *(PQWORD)(pb0 + i + 8) - i - 8;
            f = VmmRead(pSystemProcess, va1, pb1, VMMPROC_EPROCESS_MAX_SIZE);
            if(!f) { continue; }
            f = FALSE;
            if((*(PQWORD)(pb1 + *pdwoName) != 0x6578652e73736d73) && // smss.exe
                (*(PQWORD)(pb1 + *pdwoName) != 0x7972747369676552) && // Registry
                (*(PQWORD)(pb1 + *pdwoName) != 0x5320657275636553))   // Secure System
            {
                continue;
            }
            if((*(PQWORD)(pb1 + i + 16) - i - 8) != pSystemProcess->os.win.vaEPROCESS) {
                continue;
            }
            *pdwoPID = i;
            *pdwoFLink = i + 8;
            f = TRUE;
            break;
        }
    }
    if(!f) { return FALSE; }
    // skip over "processes" without PEB
    while((*(PQWORD)(pb1 + *pdwoName) == 0x5320657275636553) ||       // Secure System
        (*(PQWORD)(pb1 + *pdwoName) == 0x7972747369676552))         // Registry
    {
        va1 = *(PQWORD)(pb1 + *pdwoFLink) - *pdwoFLink;
        f = VmmRead(pSystemProcess, va1, pb1, VMMPROC_EPROCESS_MAX_SIZE);
        if(!f) { return FALSE; }
    }
    if(ctxMain->cfg.fVerboseExtra) {
        vmmprintf("---------------------------------------------------------------------------\n");
        Util_PrintHexAscii(pb1, VMMPROC_EPROCESS_MAX_SIZE, 0);
    }
    // find offset for PEB (in EPROCESS)
    for(i = 0x300, f = FALSE; i < 0x480; i += 8) {
        if(*(PQWORD)(pb0 + i)) { continue; }
        vaPEB = *(PQWORD)(pb1 + i);
        if(!vaPEB || (*(PQWORD)(pb1 + i) & 0xffff800000000fff)) { continue; }
        // Verify potential PEB
        if(!VmmReadPhysicalPage(*(PQWORD)(pb1 + *pdwoPML4), pbPage)) { continue; }
        if(!VmmVirt2PhysEx(TRUE, vaPEB, -1, pbPage, &paPEB)) { continue; }
        if(!VmmReadPhysicalPage(paPEB, pbPage)) { continue; }
        if(*(PWORD)pbPage == 0x5a4d) { continue; }  // MZ header -> likely entry point or something not PEB ...
        *pdwoPEB = i;
        f = TRUE;
        break;
    }
    if(!f) { return FALSE; }
    // find "optional" offset for user cr3/pml4 (post meltdown only)
    // System have an entry pointing to a shadow PML4 which has empty user part
    // smss.exe do not have an entry since it's running as admin ...
    *dwoPML4_User = 0;
    ZeroMemory(pbZero, 0x800);
    paMax = ctxMain->cfg.paAddrMax;
    for(i = *pdwoPML4 + 8; i < VMMPROC_EPROCESS_MAX_SIZE - 8; i += 8) {
        paPML4_0 = *(PQWORD)(pb0 + i);  // EPROCESS entry item of System
        paPML4_1 = *(PQWORD)(pb1 + i);  // EPROCESS entry item of smss.exe
        f = (paPML4_1 != 0);
        f = f || (paPML4_0 == 0);
        f = f || (paPML4_0 & 0xfff);
        f = f || (paPML4_0 >= paMax);
        f = f || !VmmReadPhysicalPage(paPML4_0, pbPage);
        f = f || memcmp(pbPage, pbZero, 0x800);
        f = f || !VmmTlbPageTableVerify(pbPage, paPML4_0, TRUE);
        if(!f) {
            *dwoPML4_User = i;
            break;
        }
    }
    return TRUE;
}

/*
* Try walk the EPROCESS list in the Windows kernel to enumerate processes into
* the VMM/PROC file system.
* NB! This may be done to refresh an existing PID cache hence migration code.
* -- pSystemProcess
* -- return
*/
BOOL VmmProcWindows_EnumerateEPROCESS(_In_ PVMM_PROCESS pSystemProcess)
{
    DWORD dwoState, dwoPML4, dwoPML4_User, dwoName, dwoPID, dwoFLink, dwoPEB, dwoMax;
    PQWORD pqwPML4, pqwPML4_User, pqwFLink, pqwPEB;
    PDWORD pdwState, pdwPID;
    LPSTR szName;
    BYTE pb[VMMPROC_EPROCESS_MAX_SIZE];
    BOOL result, fSystem, fKernel;
    PVMM_PROCESS pVmmProcess;
    QWORD vaSystemEPROCESS, vaEPROCESS, cPID = 0;
    // retrieve offsets
    vaSystemEPROCESS = pSystemProcess->os.win.vaEPROCESS;
    result = VmmProcWindows_OffsetLocatorEPROCESS(pSystemProcess, &dwoState, &dwoPML4, &dwoName, &dwoPID, &dwoFLink, &dwoPEB, &dwoPML4_User);
    if(!result) {
        vmmprintf("VmmProc: Unable to locate EPROCESS offsets.\n");
        return FALSE;
    }
    vmmprintfvv("vmmproc.c!VmmProcWindows_EnumerateEPROCESS: %016llx %016llx\n", pSystemProcess->paPML4, vaSystemEPROCESS);
    dwoMax = min(VMMPROC_EPROCESS_MAX_SIZE, 16 + max(max(dwoState, dwoPID), max(max(dwoPML4, dwoFLink), max(dwoName, dwoPEB))));
    pdwState = (PDWORD)(pb + dwoState);
    pdwPID = (PDWORD)(pb + dwoPID);
    pqwPML4 = (PQWORD)(pb + dwoPML4);
    pqwPML4_User = (PQWORD)(pb + dwoPML4_User);
    pqwFLink = (PQWORD)(pb + dwoFLink);
    szName = (LPSTR)(pb + dwoName);
    pqwPEB = (PQWORD)(pb + dwoPEB);
    // SCAN!
    if(!VmmRead(pSystemProcess, vaSystemEPROCESS, pb, dwoMax)) { return FALSE; }
    vaEPROCESS = vaSystemEPROCESS;
    while(TRUE) {
        cPID++;
        fSystem = (*pdwPID == 4);
        fKernel = fSystem || ((*pdwState == 0) && (*pqwPEB == 0));
        // NB! Windows/Dokany does not support full 64-bit sizes on files, hence
        // the max value 0x0001000000000000 for kernel space. Top 16-bits (ffff)
        // are sign extended anyway so this should be fine if user skips them.
        if(*pqwPML4 && *(PQWORD)szName) {
            pVmmProcess = VmmProcessCreateEntry(
                *pdwPID,
                *pdwState,
                ~0xfff & *pqwPML4,
                dwoPML4_User ? (~0xfff & *pqwPML4_User) : 0,
                szName,
                !fKernel,
                fSystem);
        } else {
            pVmmProcess = NULL;
        }
        if(pVmmProcess) {
            pVmmProcess->os.win.vaEPROCESS = vaEPROCESS;
            pVmmProcess->os.win.vaPEB = *pqwPEB;
            vmmprintfvv("vmmproc.c!VmmProcWindows_EnumerateEPROCESS: %016llx %016llx %016llx %08x %s\n",
                pVmmProcess->paPML4,
                pVmmProcess->os.win.vaEPROCESS,
                pVmmProcess->os.win.vaPEB,
                pVmmProcess->dwPID,
                pVmmProcess->szName);
        } else {
            szName[14] = 0; // in case of bad string data ...
            vmmprintfv("VMM: Skipping process due to parsing error.\n     PML4: %016llx PID: %i STATE: %i EPROCESS: %016llx NAME: %s\n", ~0xfff & *pqwPML4, *pdwPID, *pdwState, vaEPROCESS, szName);
        }
        vaEPROCESS = *pqwFLink - dwoFLink;
        if(vaEPROCESS == vaSystemEPROCESS) {
            break;
        }
        if(!VmmRead(pSystemProcess, vaEPROCESS, pb, dwoMax)) {
            break;
        }
        if(*pqwPML4 & 0xffffff0000000000) {
            break;
        }
        if(0xffff000000000000 != (0xffff000000000003 & *pqwFLink)) {
            break;
        }
    }
    VmmProcessCreateFinish();
    return (cPID > 10);
}

// ----------------------------------------------------------------------------
// WINDOWS SPECIFIC IMAGE IDENTIFYING BELOW
// ----------------------------------------------------------------------------

/*
* Find and validate the low stub (loaded <1MB if exists).   The low stub almost
* always exists on real hardware. It may be missing on virtual machines though.
* Upon success the PML4 and ntoskrnl.ese KernelEntry point are returned.
* NB! KernelEntry != Kernel Base
*/
_Success_(return)
BOOL VmmProcWindows_FindValidateLowStub(_Out_ PQWORD ppaPML4, _Out_ PQWORD pvaKernelEntry)
{
    PBYTE pbLowStub;
    DWORD o;
    if(!(pbLowStub = LocalAlloc(LMEM_ZEROINIT, 0x100000))) { return FALSE; }
    DeviceReadMEMEx(0, pbLowStub, 0x100000, NULL);
    o = 0;
    while(o < 0x100000) {
        o += 0x1000;
        if(0x00000001000600E9 != (0xffffffffffff00ff & *(PQWORD)(pbLowStub + o + 0x000))) { continue; } // START BYTES
        if(0xfffff80000000000 != (0xfffff80000000000 & *(PQWORD)(pbLowStub + o + 0x070))) { continue; } // KERNEL ENTRY
        if(0xffffff0000000fff & *(PQWORD)(pbLowStub + o + 0x0a0)) { continue; }                         // PML4
        *ppaPML4 = *(PQWORD)(pbLowStub + o + 0x0a0);
        *pvaKernelEntry = *(PQWORD)(pbLowStub + o + 0x070);
        LocalFree(pbLowStub);
        return TRUE;
    }
    LocalFree(pbLowStub);
    return FALSE;
}

/*
* Try initialize the VMM from scratch with new WINDOWS support.
*/
BOOL VmmProcWindows_TryInitialize(_In_opt_ QWORD paPML4Opt, _In_opt_ QWORD vaKernelBaseOpt)
{
    BOOL result;
    PVMM_PROCESS pSystemProcess;
    QWORD paPML4, vaKernelEntry, vaKernelBase, vaPsInitialSystemProcess, vaSystemEPROCESS;
    // Fetch Directory Base (PML4) and Kernel Entry (if optional hints not supplied)
    if(!paPML4Opt || !vaKernelBaseOpt) {
        result = VmmProcWindows_FindValidateLowStub(&paPML4, &vaKernelEntry);
        if(!result) {
            vmmprintfv("VmmProc: Initialization Failed. Bad data #1.\n");
            return FALSE;
        }
        vaKernelBase = 0;
    } else {
        paPML4 = paPML4Opt;
        vaKernelBase = vaKernelBaseOpt; // not entry here, but at least inside kernel ...
    }
    // Spider PML4 to speed things up
    VmmTlbSpider(paPML4, FALSE);
    // Pre-initialize System PID (required by VMM)
    pSystemProcess = VmmProcessCreateEntry(4, 0, paPML4, 0, "System", FALSE, TRUE);
    VmmProcessCreateFinish();
    if(!pSystemProcess) {
        vmmprintfv("VmmProc: Initialization Failed. #4.\n");
        return FALSE;
    }
    // Locate Kernel Base (if required)
    if(!vaKernelBase) {
        vaKernelBase = VmmProcWindows_FindNtoskrnl(pSystemProcess, vaKernelEntry);
        if(!vaKernelBase) {
            vmmprintfv("VmmProc: Initialization Failed. Unable to locate kernel #5\n");
            vmmprintfvv("VmmProc: PML4: 0x%016llx PTR: %016llx\n", pSystemProcess->paPML4, vaKernelEntry);
            return FALSE;
        }
    }
    vmmprintfvv("VmmProc: INFO: Kernel Base located at %016llx.\n", vaKernelBase);
    // Locate System EPROCESS
    vaPsInitialSystemProcess = VmmProcWindows_GetProcAddress(pSystemProcess, vaKernelBase, "PsInitialSystemProcess");
    result = VmmRead(pSystemProcess, vaPsInitialSystemProcess, (PBYTE)&vaSystemEPROCESS, 8);
    if(!result) {
        vmmprintfv("VmmProc: Initialization Failed. Unable to locate EPROCESS. #6\n");
        return FALSE;
    }
    pSystemProcess->os.win.vaEPROCESS = vaSystemEPROCESS;
    vmmprintfvv("VmmProc: INFO: PsInitialSystemProcess located at %016llx.\n", vaPsInitialSystemProcess);
    vmmprintfvv("VmmProc: INFO: EPROCESS located at %016llx.\n", vaSystemEPROCESS);
    // Enumerate processes
    result = VmmProcWindows_EnumerateEPROCESS(pSystemProcess);
    if(!result) {
        vmmprintfv("VmmProc: Initialization Failed. Unable to walk EPROCESS. #7\n");
        return FALSE;
    }
    ctxVmm->fTargetSystem = VMM_TARGET_WINDOWS_X64;
    ctxVmm->kernelinfo.vaBase = vaKernelBase;
    ctxVmm->kernelinfo.paDTB = paPML4;
    return TRUE;
}

VOID VmmProcWindows_InitializeModuleNames(_In_ PVMM_PROCESS pProcess)
{
    VmmProcWindows_InitializeLdrModules(pProcess);
    VmmProcWindows_ScanHeaderPE(pProcess);
}
