// vmmwin.c : implementation related to operating system and process
// parsing of virtual memory. Windows related features only.
//
// (c) Ulf Frisk, 2018
// Author: Ulf Frisk, pcileech@frizk.net
//

#include "vmmwin.h"
#include "vmmproc.h"
#include "device.h"
#include "util.h"
#include "pe.h"
#include <Winternl.h>

// ----------------------------------------------------------------------------
// WINDOWS SPECIFIC PROCESS RELATED FUNCTIONALITY BELOW:
//    GENERAL FUNCTIONALITY
// ----------------------------------------------------------------------------

PIMAGE_NT_HEADERS VmmWin_GetVerifyHeaderPE(_In_ PVMM_PROCESS pProcess, _In_opt_ QWORD vaModule, _Inout_ PBYTE pbModuleHeader, _Out_ PBOOL pfHdr32)
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

VOID VmmWin_PE_SECTION_DisplayBuffer(_In_ PVMM_PROCESS pProcess, _In_ PVMM_MODULEMAP_ENTRY pModule, _Out_opt_ PBYTE pbDisplayBufferOpt, _In_ DWORD cbDisplayBufferMax, _Out_opt_ PDWORD pcbDisplayBuffer, _Inout_opt_ PDWORD pcSectionsOpt, _Out_opt_ PIMAGE_SECTION_HEADER pSectionsOpt)
{
    BYTE pbModuleHeader[0x1000] = { 0 };
    PIMAGE_NT_HEADERS64 ntHeader64;
    BOOL fHdr32;
    DWORD i, cSections, cSectionsOpt;
    PIMAGE_SECTION_HEADER pSectionBase;
    if(pcbDisplayBuffer) { *pcbDisplayBuffer = 0; }
    if(pcSectionsOpt) {
        cSectionsOpt = *pcSectionsOpt;
        *pcSectionsOpt = 0;
    }
    if(!(ntHeader64 = VmmWin_GetVerifyHeaderPE(pProcess, pModule->BaseAddress, pbModuleHeader, &fHdr32))) { return; }
    pSectionBase = fHdr32 ?
        (PIMAGE_SECTION_HEADER)((QWORD)ntHeader64 + sizeof(IMAGE_NT_HEADERS32)) :
        (PIMAGE_SECTION_HEADER)((QWORD)ntHeader64 + sizeof(IMAGE_NT_HEADERS64));
    cSections = (DWORD)(((QWORD)pbModuleHeader + 0x1000 - (QWORD)pSectionBase) / sizeof(IMAGE_SECTION_HEADER)); // max section headers possible in 0x1000 module header buffer
    cSections = (DWORD)min(cSections, ntHeader64->FileHeader.NumberOfSections); // FileHeader are the same in both 32/64-bit versions of struct
    if(pbDisplayBufferOpt) {
        for(i = 0; i < cSections; i++) {
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
    if(pSectionsOpt && pcSectionsOpt && cSectionsOpt) {
        *pcSectionsOpt = min(cSectionsOpt, ntHeader64->FileHeader.NumberOfSections);
        memcpy(pSectionsOpt, pSectionBase, *pcSectionsOpt * sizeof(IMAGE_SECTION_HEADER));
    }
}

VOID VmmWin_PE_DIRECTORY_DisplayBuffer(_In_ PVMM_PROCESS pProcess, _In_ PVMM_MODULEMAP_ENTRY pModule, _Out_opt_ PBYTE pbDisplayBufferOpt, _In_ DWORD cbDisplayBufferMax, _Out_opt_ PDWORD pcbDisplayBuffer, _Out_writes_opt_(16) PIMAGE_DATA_DIRECTORY pDataDirectoryOpt)
{
    BYTE i, pbModuleHeader[0x1000] = { 0 };
    PIMAGE_NT_HEADERS64 ntHeader64;
    PIMAGE_NT_HEADERS32 ntHeader32;
    PIMAGE_DATA_DIRECTORY pDataDirectoryBase;
    BOOL fHdr32;
    if(pcbDisplayBuffer) { *pcbDisplayBuffer = 0; }
    if(!(ntHeader64 = VmmWin_GetVerifyHeaderPE(pProcess, pModule->BaseAddress, pbModuleHeader, &fHdr32))) { return; }
    ntHeader32 = (PIMAGE_NT_HEADERS32)ntHeader64;
    pDataDirectoryBase = fHdr32 ? ntHeader32->OptionalHeader.DataDirectory : ntHeader64->OptionalHeader.DataDirectory;
    if(pbDisplayBufferOpt) {
        for(i = 0; i < 16; i++) {
            if(pbDisplayBufferOpt && pcbDisplayBuffer) {
                *pcbDisplayBuffer += snprintf(
                    pbDisplayBufferOpt + *pcbDisplayBuffer,
                    cbDisplayBufferMax - *pcbDisplayBuffer,
                    "%x %-16.16s %016llx %08x %08x\n",
                    i,
                    PE_DATA_DIRECTORIES[i],
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


VOID VmmWin_PE_LoadEAT_DisplayBuffer(_Inout_ PVMM_PROCESS pProcess, _Inout_ PVMM_MODULEMAP_ENTRY pModule, _Out_ PVMMPROC_WINDOWS_EAT_ENTRY pEATs, _Inout_ PDWORD pcEATs)
{
    BYTE pbModuleHeader[0x1000] = { 0 };
    PIMAGE_NT_HEADERS64 ntHeader64;
    PIMAGE_NT_HEADERS32 ntHeader32;
    QWORD oExportDirectory, cbExportDirectory;
    PBYTE pbExportDirectory = NULL;
    PIMAGE_EXPORT_DIRECTORY pExportDirectory;
    QWORD i, oNameOrdinal, ooName, oName, oFunction, wOrdinalFnIdx;
    DWORD vaFunctionOffset;
    BOOL fHdr32;
    DWORD cEATs = *pcEATs;
    *pcEATs = 0;
    // load both 32/64 bit ntHeader (only one will be valid)
    if(!(ntHeader64 = VmmWin_GetVerifyHeaderPE(pProcess, pModule->BaseAddress, pbModuleHeader, &fHdr32))) { goto cleanup; }
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
    *pcEATs = (DWORD)i;
cleanup:
    LocalFree(pbExportDirectory);
}

VOID VmmWin_PE_LoadIAT_DisplayBuffer(_Inout_ PVMM_PROCESS pProcess, _Inout_ PVMM_MODULEMAP_ENTRY pModule, _Out_ PVMMWIN_IAT_ENTRY pIATs, _Inout_ PDWORD pcIATs)
{
    BYTE pbModuleHeader[0x1000] = { 0 };
    PIMAGE_NT_HEADERS64 ntHeader64;
    PIMAGE_NT_HEADERS32 ntHeader32;
    QWORD i, oImportDirectory;
    PIMAGE_IMPORT_DESCRIPTOR pIID;
    PQWORD pIAT64, pHNA64;
    PDWORD pIAT32, pHNA32;
    PBYTE pbModule;
    DWORD cbModule, cbRead;
    BOOL fHdr32, fFnName;
    DWORD c, j, cIATs = *pcIATs;
    *pcIATs = 0;
    // Load the module
    if(pModule->SizeOfImage > 0x01000000) { return; }
    cbModule = pModule->SizeOfImage;
    if(!(pbModule = LocalAlloc(LMEM_ZEROINIT, cbModule))) { return; }
    VmmReadEx(pProcess, pModule->BaseAddress, pbModule, cbModule, &cbRead, 0);
    if(cbRead <= 0x2000) { goto cleanup; }
    // load both 32/64 bit ntHeader (only one will be valid)
    if(!(ntHeader64 = VmmWin_GetVerifyHeaderPE(pProcess, pModule->BaseAddress, pbModuleHeader, &fHdr32))) { goto cleanup; }
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

VOID VmmWin_PE_SetSizeSectionIATEAT_DisplayBuffer(_In_ PVMM_PROCESS pProcess, _Inout_ PVMM_MODULEMAP_ENTRY pModule)
{
    BYTE pbModuleHeader[0x1000] = { 0 };
    PIMAGE_NT_HEADERS64 pNtHeaders64;
    BOOL fHdr32;
    // check if function is required
    if(pModule->fLoadedEAT && pModule->fLoadedIAT) { return; }
    // load both 32/64 bit ntHeader (only one will be valid)
    if(!(pNtHeaders64 = VmmWin_GetVerifyHeaderPE(pProcess, pModule->BaseAddress, pbModuleHeader, &fHdr32))) { return; }
    // calculate display buffer size of: SECTIONS, EAT, IAT
    pModule->cbDisplayBufferSections = PE_SectionGetNumberOfEx(pProcess, pModule->BaseAddress, pbModuleHeader) * 52;    // each display buffer human readable line == 52 bytes.
    if(!pModule->fLoadedEAT) {
        pModule->cbDisplayBufferEAT = PE_EatGetNumberOfEx(pProcess, pModule->BaseAddress, pbModuleHeader) * 64;         // each display buffer human readable line == 64 bytes.
        pModule->fLoadedEAT = TRUE;
    }
    if(!pModule->fLoadedIAT) {
        pModule->cbDisplayBufferIAT = PE_IatGetNumberOfEx(pProcess, pModule->BaseAddress, pbModuleHeader) * 128;        // each display buffer human readable line == 128 bytes.
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

VOID VmmWin_ScanLdrModules64(_In_ PVMM_PROCESS pProcess, _Inout_ PVMM_MODULEMAP_ENTRY pModules, _Inout_ PDWORD pcModules, _In_ DWORD cModulesMax, _Out_ PBOOL fWow64)
{
    QWORD vaModuleLdrFirst, vaModuleLdr = 0;
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
        if(!ctxVmm->kernel.vaPsLoadedModuleList) { return; }
        if(!VmmRead(pProcess, ctxVmm->kernel.vaPsLoadedModuleList, (PBYTE)&vaModuleLdrFirst, sizeof(QWORD)) || !vaModuleLdrFirst) { return; }
        if(!VmmRead(pProcess, ctxVmm->kernel.vaPsLoadedModuleList, pbPEBLdrData, sizeof(PEB_LDR_DATA))) { return; }
        vaModuleLdr = vaModuleLdrFirst;
        // If vaPsLoadedModuleList was applied from KDBG (pre-win10) 'ntoskrnl.exe' pointer will
        // go to 2nd entry in list and 'ntoskrnl.exe' will be missed unless Blink is followed first.
        if(ctxVmm->kernel.vaKDBG) {
            if(!VmmRead(pProcess, vaModuleLdr, pbLdrModule, sizeof(VMMPROC_LDR_DATA_TABLE_ENTRY))) { return; }
            if((ctxVmm->kernel.vaBase != (QWORD)pLdrModule->BaseAddress) && (QWORD)pLdrModule->InLoadOrderModuleList.Blink) {
                vaModuleLdrFirst = vaModuleLdr = (QWORD)pLdrModule->InLoadOrderModuleList.Blink;
            }
        }
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
        vmmprintfvv("vmmwin.c!VmmWin_ScanLdrModules: %016llx %016llx %016llx %08x %i %s\n", vaModuleLdr, pModule->BaseAddress, pModule->EntryPoint, pModule->SizeOfImage, (pModule->fWoW64 ? 1 : 0), pModule->szName);
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
BOOL VmmWin_ScanLdrModules32(_In_ PVMM_PROCESS pProcess, _Inout_ PVMM_MODULEMAP_ENTRY pModules, _Inout_ PDWORD pcModules, _In_ DWORD cModulesMax)
{
    DWORD vaModuleLdrFirst32, vaModuleLdr32 = 0;
    BYTE pbPEB32[sizeof(PEB32)], pbPEBLdrData32[sizeof(PEB_LDR_DATA32)], pbLdrModule32[sizeof(LDR_MODULE32)];
    PPEB32 pPEB32 = (PPEB32)pbPEB32;
    PPEB_LDR_DATA32 pPEBLdrData32 = (PPEB_LDR_DATA32)pbPEBLdrData32;
    PLDR_MODULE32 pLdrModule32 = (PLDR_MODULE32)pbLdrModule32;
    PVMM_MODULEMAP_ENTRY pModule;
    if(pProcess->fUserOnly) {
        if(!pProcess->os.win.vaPEB) { return FALSE; }
        if(!VmmRead(pProcess, pProcess->os.win.vaPEB32, pbPEB32, sizeof(PEB32))) { return FALSE; }
        if(!VmmRead(pProcess, (DWORD)pPEB32->Ldr, pbPEBLdrData32, sizeof(PEB_LDR_DATA32))) { return FALSE; }
        vaModuleLdr32 = vaModuleLdrFirst32 = (DWORD)pPEBLdrData32->InMemoryOrderModuleList.Flink - 0x08; // InLoadOrderModuleList == InMemoryOrderModuleList - 0x08
    } else if(ctxVmm->tpSystem == VMM_SYSTEM_WINDOWS_X86) {
        // Kernel mode process -> walk PsLoadedModuleList to enumerate drivers / .sys and .dlls.
        if(!ctxVmm->kernel.vaPsLoadedModuleList) { return FALSE; }
        if(!VmmRead(pProcess, ctxVmm->kernel.vaPsLoadedModuleList, (PBYTE)&vaModuleLdrFirst32, sizeof(DWORD)) || !vaModuleLdrFirst32) { return FALSE; }
        if(!VmmRead(pProcess, ctxVmm->kernel.vaPsLoadedModuleList, pbPEBLdrData32, sizeof(PEB_LDR_DATA32))) { return FALSE; }
        vaModuleLdr32 = vaModuleLdrFirst32;
        // If vaPsLoadedModuleList was applied from KDBG (pre-win10) 'ntoskrnl.exe' pointer will
        // go to 2nd entry in list and 'ntoskrnl.exe' will be missed unless Blink is followed first.
        if(ctxVmm->kernel.vaKDBG) {
            if(!VmmRead(pProcess, vaModuleLdr32, pbLdrModule32, sizeof(LDR_MODULE32))) { return FALSE; }
            if((ctxVmm->kernel.vaBase != (DWORD)pLdrModule32->BaseAddress) && (DWORD)pLdrModule32->InLoadOrderModuleList.Blink) {
                vaModuleLdrFirst32 = vaModuleLdr32 = (DWORD)pLdrModule32->InLoadOrderModuleList.Blink;
            }
        }
    } else {
        return FALSE;
    }
    do {
        if(!VmmRead(pProcess, vaModuleLdr32, pbLdrModule32, sizeof(LDR_MODULE32))) { break; }
        pModule = pModules + *pcModules;
        pModule->BaseAddress = (QWORD)pLdrModule32->BaseAddress;
        pModule->EntryPoint = (QWORD)pLdrModule32->EntryPoint;
        pModule->SizeOfImage = (DWORD)pLdrModule32->SizeOfImage;
        pModule->fWoW64 = TRUE;
        if(!pLdrModule32->BaseDllName.Length) { break; }
        if(!VmmReadString_Unicode2Ansi(pProcess, (QWORD)pLdrModule32->BaseDllName.Buffer, pModule->szName, min(31, pLdrModule32->BaseDllName.Length))) { break; }
        vmmprintfvv("vmmwin.c!VmmWin_ScanLdrModules32: %08x %08x %08x %08x %s\n", vaModuleLdr32, (DWORD)pModule->BaseAddress, (DWORD)pModule->EntryPoint, pModule->SizeOfImage, pModule->szName);
        vaModuleLdr32 = (QWORD)pLdrModule32->InLoadOrderModuleList.Flink;
        *pcModules = *pcModules + 1;
    } while((vaModuleLdr32 != vaModuleLdrFirst32) && (*pcModules < cModulesMax));
    return TRUE;
}

#define VMMPROCWINDOWS_MAX_MODULES      512

VOID VmmWin_InitializeLdrModules(_In_ PVMM_PROCESS pProcess)
{
    PVMM_MODULEMAP_ENTRY pModules, pModule;
    PBYTE pbResult;
    DWORD i, o, cModules;
    BOOL result, fWow64 = FALSE;
    // clear out any previous data
    LocalFree(pProcess->os.win.pbLdrModulesDisplayCache);
    pProcess->os.win.pbLdrModulesDisplayCache = NULL;
    pProcess->os.win.cbLdrModulesDisplayCache = 0;
    pProcess->os.win.vaENTRY = 0;
    // allocate and enumerate
    pModules = (PVMM_MODULEMAP_ENTRY)LocalAlloc(LMEM_ZEROINIT, 512 * sizeof(VMM_MODULEMAP_ENTRY));
    if(!pModules) { goto fail; }
    cModules = 0;
    if(ctxVmm->tpSystem == VMM_SYSTEM_WINDOWS_X64) {
        VmmWin_ScanLdrModules64(pProcess, pModules, &cModules, VMMPROCWINDOWS_MAX_MODULES, &fWow64);
        if((cModules > 0) && (!pModules[cModules - 1].BaseAddress)) { cModules--; }
        if(fWow64) {
            pProcess->os.win.vaPEB32 = (DWORD)pProcess->os.win.vaPEB - 0x1000;
            result = VmmWin_ScanLdrModules32(pProcess, pModules, &cModules, VMMPROCWINDOWS_MAX_MODULES);
            if(!result) {
                pProcess->os.win.vaPEB32 = (DWORD)pProcess->os.win.vaPEB + 0x1000;
                result = VmmWin_ScanLdrModules32(pProcess, pModules, &cModules, VMMPROCWINDOWS_MAX_MODULES);
            }
            if(!result) {
                pProcess->os.win.vaPEB32 = 0;
            }
        }
        if((cModules > 0) && (!pModules[cModules - 1].BaseAddress)) { cModules--; }
        if(!cModules) { goto fail; }
        // generate display cache
        pProcess->os.win.vaENTRY = pModules[0].EntryPoint;
        pbResult = pProcess->os.win.pbLdrModulesDisplayCache = (PBYTE)LocalAlloc(LMEM_ZEROINIT, 89ULL * cModules);
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
            VmmMapTag(pProcess, pModule->BaseAddress, pModule->BaseAddress + pModule->SizeOfImage, pModule->szName, NULL, FALSE);
        }
        pProcess->os.win.cbLdrModulesDisplayCache = o;
    } else if(ctxVmm->tpSystem == VMM_SYSTEM_WINDOWS_X86) {
        pProcess->os.win.vaPEB32 = (DWORD)pProcess->os.win.vaPEB;
        VmmWin_ScanLdrModules32(pProcess, pModules, &cModules, VMMPROCWINDOWS_MAX_MODULES);
        if((cModules > 0) && (!pModules[cModules - 1].BaseAddress)) { cModules--; }
        // generate display cache
        pProcess->os.win.vaENTRY = pModules[0].EntryPoint;
        pbResult = pProcess->os.win.pbLdrModulesDisplayCache = (PBYTE)LocalAlloc(LMEM_ZEROINIT, 70ULL * cModules);
        if(!pbResult) { goto fail; }
        for(i = 0, o = 0; i < cModules; i++) {
            pModule = pModules + i;
            if(!pModule->BaseAddress) { continue; }
            o += snprintf(
                pbResult + o,
                70,
                "%04x %8x %08x-%08x      %s\n",
                i,
                pModule->SizeOfImage >> 12,
                (DWORD)pModule->BaseAddress,
                (DWORD)(pModule->BaseAddress + pModule->SizeOfImage - 1),
                pModule->szName
            );
        }
        // update memory map with names
        for(i = 0; i < cModules; i++) {
            pModule = pModules + i;
            VmmMapTag(pProcess, pModule->BaseAddress, pModule->BaseAddress + pModule->SizeOfImage, pModule->szName, NULL, FALSE);
        }
        pProcess->os.win.cbLdrModulesDisplayCache = o;
    }
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
* Load module proc names into memory map list if possible.
* NB! this function parallelize reads of MZ header candidates to speed things up.
*/
VOID VmmWin_ScanHeaderPE(_In_ PVMM_PROCESS pProcess)
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
            pMap->dma.version = MEM_IO_SCATTER_HEADER_VERSION;
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
            result = PE_GetModuleNameEx(pProcess, pMap->mme->AddrBase, TRUE, pMap->pb, szBuffer, &cbImageSize);
            if(result && (cbImageSize < 0x01000000)) {
                VmmMapTag(pProcess, pMap->mme->AddrBase, pMap->mme->AddrBase + cbImageSize, szBuffer, NULL, FALSE);
            }
        }
    }
    LocalFree(pbBuffer);
}

// ----------------------------------------------------------------------------
// WINDOWS EPROCESS WALKING FUNCTIONALITY FOR 64/32 BIT BELOW:
// ----------------------------------------------------------------------------

#define VMMPROC_EPROCESS_MAX_SIZE 0x500

/*
* Very ugly hack that tries to locate some offsets required withn the EPROCESS struct.
*/
_Success_(return)
BOOL VmmWin_OffsetLocatorEPROCESS64(_In_ PVMM_PROCESS pSystemProcess,
    _Out_ PDWORD pdwoState, _Out_ PDWORD pdwoDTB, _Out_ PDWORD pdwoName, _Out_ PDWORD pdwoPID,
    _Out_ PDWORD pdwoFLink, _Out_ PDWORD pdwoPEB, _Out_ PDWORD dwoDTB_User)
{
    BOOL f;
    DWORD i;
    QWORD va1, vaPEB, paPEB;
    BYTE pb0[VMMPROC_EPROCESS_MAX_SIZE], pb1[VMMPROC_EPROCESS_MAX_SIZE], pbPage[0x1000];
    BYTE pbZero[0x800];
    QWORD paMax, paDTB_0, paDTB_1;
    if(!VmmRead(pSystemProcess, pSystemProcess->os.win.vaEPROCESS, pb0, VMMPROC_EPROCESS_MAX_SIZE)) { return FALSE; }
    if(ctxMain->cfg.fVerboseExtra) {
        vmmprintf("vmmwin.c!OffsetLocatorEPROCESS64: %016llx %016llx\n", pSystemProcess->paDTB, pSystemProcess->os.win.vaEPROCESS);
        Util_PrintHexAscii(pb0, VMMPROC_EPROCESS_MAX_SIZE, 0);
    }
    // find offset State (static for now)
    if(*(PDWORD)(pb0 + 0x04)) { return FALSE; }
    *pdwoState = 0x04;
    // find offset PML4 (static for now)
    if(pSystemProcess->paDTB != (0xfffffffffffff000 & *(PQWORD)(pb0 + 0x28))) { return FALSE; }
    *pdwoDTB = 0x28;
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
            if((*(PQWORD)(pb1 + *pdwoName) != 0x6578652e73736d73) &&    // smss.exe
                (*(PQWORD)(pb1 + *pdwoName) != 0x7972747369676552) &&   // Registry
                (*(PQWORD)(pb1 + *pdwoName) != 0x5320657275636553))     // Secure System
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
    while((*(PQWORD)(pb1 + *pdwoName) == 0x5320657275636553) ||         // Secure System
        (*(PQWORD)(pb1 + *pdwoName) == 0x7972747369676552))             // Registry
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
        if(!vaPEB || (vaPEB & 0xffff800000000fff)) { continue; }
        // Verify potential PEB
        if(!VmmVirt2PhysEx(*(PQWORD)(pb1 + *pdwoDTB), TRUE, vaPEB, &paPEB)) { continue; }
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
    *dwoDTB_User = 0;
    ZeroMemory(pbZero, 0x800);
    paMax = ctxMain->cfg.paAddrMax;
    for(i = *pdwoDTB + 8; i < VMMPROC_EPROCESS_MAX_SIZE - 8; i += 8) {
        paDTB_0 = *(PQWORD)(pb0 + i);  // EPROCESS entry item of System
        paDTB_1 = *(PQWORD)(pb1 + i);  // EPROCESS entry item of smss.exe
        f = (paDTB_1 != 0);
        f = f || (paDTB_0 == 0);
        f = f || (paDTB_0 & 0xfff);
        f = f || (paDTB_0 >= paMax);
        f = f || !VmmReadPhysicalPage(paDTB_0, pbPage);
        f = f || memcmp(pbPage, pbZero, 0x800);
        f = f || !VmmTlbPageTableVerify(pbPage, paDTB_0, TRUE);
        if(!f) {
            *dwoDTB_User = i;
            break;
        }
    }
    vmmprintfvv("vmmwin.c!64_OffsetLocatorEPROCESS: PID: %x STATE: %x DTB: %x DTB_User: %x NAME: %x PEB: %x FLink: %x\n", *pdwoPID, *pdwoState, *pdwoDTB, *dwoDTB_User, *pdwoName, *pdwoPEB, *pdwoFLink);
    return TRUE;
}

/*
* Try walk the EPROCESS list in the Windows kernel to enumerate processes into
* the VMM/PROC file system.
* NB! This may be done to refresh an existing PID cache hence migration code.
* -- pSystemProcess
* -- return
*/
BOOL VmmWin_EnumerateEPROCESS64(_In_ PVMM_PROCESS pSystemProcess)
{
    DWORD dwoState, dwoDTB, dwoDTB_User, dwoName, dwoPID, dwoFLink, dwoPEB, dwoMax;
    PQWORD pqwDTB, pqwDTB_User, pqwFLink, pqwPEB;
    PDWORD pdwState, pdwPID;
    LPSTR szName;
    BYTE pb[VMMPROC_EPROCESS_MAX_SIZE];
    BOOL result, fSystem, fKernel;
    PVMM_PROCESS pVmmProcess;
    QWORD vaSystemEPROCESS, vaEPROCESS, cPID = 0, cNewProcessCollision = 0;
    BOOL fShowTerminated;
    fShowTerminated = ctxVmm->flags & VMM_FLAG_PROCESS_SHOW_TERMINATED;
    // retrieve offsets
    vaSystemEPROCESS = pSystemProcess->os.win.vaEPROCESS;
    result = VmmWin_OffsetLocatorEPROCESS64(pSystemProcess, &dwoState, &dwoDTB, &dwoName, &dwoPID, &dwoFLink, &dwoPEB, &dwoDTB_User);
    if(!result) {
        vmmprintf("VmmProc: Unable to locate EPROCESS offsets.\n");
        return FALSE;
    }
    vmmprintfvv("vmmwin.c!EnumerateEPROCESS64: %016llx %016llx\n", pSystemProcess->paDTB, vaSystemEPROCESS);
    dwoMax = min(VMMPROC_EPROCESS_MAX_SIZE, 16 + max(max(dwoState, dwoPID), max(max(dwoDTB, dwoFLink), max(dwoName, dwoPEB))));
    pdwState = (PDWORD)(pb + dwoState);
    pdwPID = (PDWORD)(pb + dwoPID);
    pqwDTB = (PQWORD)(pb + dwoDTB);
    pqwDTB_User = (PQWORD)(pb + dwoDTB_User);
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
        if(*pqwDTB && *(PQWORD)szName && (fShowTerminated || !*pdwState)) {
            pVmmProcess = VmmProcessCreateEntry(
                *pdwPID,
                *pdwState,
                ~0xfff & *pqwDTB,
                dwoDTB_User ? (~0xfff & *pqwDTB_User) : 0,
                szName,
                !fKernel,
                fSystem);
            if(!pVmmProcess) {
                vmmprintfv("VMM: WARNING: PID '%i' already exists.\n", *pdwPID);
                if(++cNewProcessCollision >= 8) { 
                    break; 
                }
            }
        } else {
            pVmmProcess = NULL;
        }
        if(pVmmProcess) {
            pVmmProcess->os.win.vaEPROCESS = vaEPROCESS;
            pVmmProcess->os.win.vaPEB = *pqwPEB;
            vmmprintfvv("vmmwin.c!EnumerateEPROCESS64: %016llx %016llx %016llx %08x %s\n",
                pVmmProcess->paDTB,
                pVmmProcess->os.win.vaEPROCESS,
                pVmmProcess->os.win.vaPEB,
                pVmmProcess->dwPID,
                pVmmProcess->szName);
        } else {
            szName[14] = 0; // in case of bad string data ...
            vmmprintfv("VMM: Skipping process - parse error  or terminated state.\n     PML4: %016llx PID: %i STATE: %i EPROCESS: %016llx NAME: %s\n", ~0xfff & *pqwDTB, *pdwPID, *pdwState, vaEPROCESS, szName);
        }
        vaEPROCESS = *pqwFLink - dwoFLink;
        if(vaEPROCESS == vaSystemEPROCESS) {
            break;
        }
        if(!VmmRead(pSystemProcess, vaEPROCESS, pb, dwoMax)) {
            break;
        }
        if(*pqwDTB & 0xffffff0000000000) {
            break;
        }
        if(0xffff000000000000 != (0xffff000000000003 & *pqwFLink)) {
            break;
        }
    }
    VmmProcessCreateFinish();
    return (cPID > 10);
}

/*
* Very ugly hack that tries to locate some offsets required withn the EPROCESS struct.
*/
_Success_(return)
BOOL VmmWin_OffsetLocatorEPROCESS32(_In_ PVMM_PROCESS pSystemProcess,
    _Out_ PDWORD pdwoState, _Out_ PDWORD pdwoDTB, _Out_ PDWORD pdwoName, _Out_ PDWORD pdwoPID,
    _Out_ PDWORD pdwoFLink, _Out_ PDWORD pdwoPEB, _Out_ PDWORD dwoDTB_User)
{
    BOOL f;
    DWORD i;
    DWORD va1, vaPEB;
    QWORD paPEB;
    BYTE pb0[VMMPROC_EPROCESS_MAX_SIZE], pb1[VMMPROC_EPROCESS_MAX_SIZE], pbPage[0x1000];
    //BYTE pbZero[0x800];
    //QWORD paMax, paDTB_0, paDTB_1;
    if(!VmmRead(pSystemProcess, pSystemProcess->os.win.vaEPROCESS, pb0, VMMPROC_EPROCESS_MAX_SIZE)) { return FALSE; }
    if(ctxMain->cfg.fVerboseExtra) {
        vmmprintf("vmmwin.c!32_OffsetLocatorEPROCESS: %016llx %016llx\n", pSystemProcess->paDTB, pSystemProcess->os.win.vaEPROCESS);
        Util_PrintHexAscii(pb0, VMMPROC_EPROCESS_MAX_SIZE, 0);
    }
    // find offset State (static for now)
    if(*(PDWORD)(pb0 + 0x04)) { return FALSE; }
    *pdwoState = 0x04;
    // find offset PML4 (static for now)
    //if(pSystemProcess->paDTB != (0xfffff000 & *(PDWORD)(pb0 + 0x18))) { return FALSE; }
    *pdwoDTB = 0x18;
    // find offset for Name
    for(i = 0, f = FALSE; i < VMMPROC_EPROCESS_MAX_SIZE - 4; i += 4) {
        if(*(PQWORD)(pb0 + i) == 0x00006D6574737953) {
            *pdwoName = i;
            f = TRUE;
            break;
        }
    }
    if(!f) { return FALSE; }
    // find offset for PID, FLink, BLink (assumed to be following eachother)
    for(i = 0, f = FALSE; i < VMMPROC_EPROCESS_MAX_SIZE - 4; i += 4) {
        if(*(PDWORD)(pb0 + i) == 4) {
            // PID = correct, this is a candidate
            if(0x80000000 != (0x80000003 & *(PDWORD)(pb0 + i + 4))) { continue; }    // FLink not valid kernel pointer
            va1 = *(PDWORD)(pb0 + i + 4) - i - 4;
            f = VmmRead(pSystemProcess, va1, pb1, VMMPROC_EPROCESS_MAX_SIZE);
            if(!f) { continue; }
            f = FALSE;
            if((*(PQWORD)(pb1 + *pdwoName) != 0x6578652e73736d73) &&    // smss.exe
                (*(PQWORD)(pb1 + *pdwoName) != 0x7972747369676552) &&   // Registry
                (*(PQWORD)(pb1 + *pdwoName) != 0x5320657275636553))     // Secure System
            {
                continue;
            }
            if((*(PDWORD)(pb1 + i + 8) - i - 4) != pSystemProcess->os.win.vaEPROCESS) {
                continue;
            }
            *pdwoPID = i;
            *pdwoFLink = i + 4;
            f = TRUE;
            break;
        }
    }
    if(!f) { return FALSE; }
    // skip over "processes" without PEB
    while((*(PQWORD)(pb1 + *pdwoName) == 0x5320657275636553) ||         // Secure System
        (*(PQWORD)(pb1 + *pdwoName) == 0x7972747369676552))             // Registry
    {
        va1 = *(PDWORD)(pb1 + *pdwoFLink) - *pdwoFLink;
        f = VmmRead(pSystemProcess, va1, pb1, VMMPROC_EPROCESS_MAX_SIZE);
        if(!f) { return FALSE; }
    }
    if(ctxMain->cfg.fVerboseExtra) {
        vmmprintf("---------------------------------------------------------------------------\n");
        Util_PrintHexAscii(pb1, VMMPROC_EPROCESS_MAX_SIZE, 0);
    }
    // find offset for PEB (in EPROCESS)
    for(i = 0x100, f = FALSE; i < 0x240; i += 4) {
        if(*(PDWORD)(pb0 + i)) { continue; }
        vaPEB = *(PDWORD)(pb1 + i);
        if(!vaPEB || (vaPEB & 0x80000fff)) { continue; }
        // Verify potential PEB
        if(!VmmVirt2PhysEx(*(PDWORD)(pb1 + *pdwoDTB), TRUE, vaPEB, &paPEB)) { continue; }
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
    *dwoDTB_User = 0;
    /*
    ZeroMemory(pbZero, 0x800);
    paMax = ctxMain->cfg.paAddrMax;
    for(i = *pdwoDTB + 4; i < VMMPROC_EPROCESS_MAX_SIZE - 4; i += 4) {
        paDTB_0 = *(PDWORD)(pb0 + i);  // EPROCESS entry item of System
        paDTB_1 = *(PDWORD)(pb1 + i);  // EPROCESS entry item of smss.exe
        f = (paDTB_1 != 0);
        f = f || (paDTB_0 == 0);
        f = f || (paDTB_0 & 0x1f);
        f = f || (paDTB_0 >= paMax);
        f = f || !VmmReadPhysicalPage(paDTB_0, pbPage);
        f = f || memcmp(pbPage, pbZero, 0x800);
        f = f || !VmmTlbPageTableVerify(pbPage, paDTB_0, TRUE);
        if(!f) {
            *dwoDTB_User = i;
            break;
        }
    }
    */
    vmmprintfvv("vmmwin.c!32_OffsetLocatorEPROCESS: PID: %x STATE: %x DTB: %x DTB_User: %x NAME: %x PEB: %x FLink: %x\n", *pdwoPID, *pdwoState, *pdwoDTB, *dwoDTB_User, *pdwoName, *pdwoPEB, *pdwoFLink);
    return TRUE;
}

BOOL VmmWin_EnumerateEPROCESS32(_In_ PVMM_PROCESS pSystemProcess)
{
    DWORD dwoState, dwoDTB, dwoDTB_User, dwoName, dwoPID, dwoFLink, dwoPEB, dwoMax;
    PDWORD pdwDTB, pdwDTB_User, pdwFLink, pdwPEB;
    PDWORD pdwState, pdwPID;
    LPSTR szName;
    BYTE pb[VMMPROC_EPROCESS_MAX_SIZE];
    BOOL result, fSystem, fKernel;
    PVMM_PROCESS pVmmProcess;
    DWORD vaSystemEPROCESS, vaEPROCESS, cPID = 0, cNewProcessCollision = 0;
    BOOL fShowTerminated;
    fShowTerminated = ctxVmm->flags & VMM_FLAG_PROCESS_SHOW_TERMINATED;
    // retrieve offsets
    vaSystemEPROCESS = (DWORD)pSystemProcess->os.win.vaEPROCESS;
    result = VmmWin_OffsetLocatorEPROCESS32(pSystemProcess, &dwoState, &dwoDTB, &dwoName, &dwoPID, &dwoFLink, &dwoPEB, &dwoDTB_User);
    if(!result) {
        vmmprintf("VmmProc: Unable to locate EPROCESS offsets.\n");
        return FALSE;
    }
    vmmprintfvv("vmmwin.c!EnumerateEPROCESS32: %016llx %08x\n", pSystemProcess->paDTB, vaSystemEPROCESS);
    dwoMax = min(VMMPROC_EPROCESS_MAX_SIZE, 16 + max(max(dwoState, dwoPID), max(max(dwoDTB, dwoFLink), max(dwoName, dwoPEB))));
    pdwState = (PDWORD)(pb + dwoState);
    pdwPID = (PDWORD)(pb + dwoPID);
    pdwDTB = (PDWORD)(pb + dwoDTB);
    pdwDTB_User = (PDWORD)(pb + dwoDTB_User);
    pdwFLink = (PDWORD)(pb + dwoFLink);
    szName = (LPSTR)(pb + dwoName);
    pdwPEB = (PDWORD)(pb + dwoPEB);
    // SCAN!
    if(!VmmRead(pSystemProcess, vaSystemEPROCESS, pb, dwoMax)) { return FALSE; }
    vaEPROCESS = vaSystemEPROCESS;
    while(TRUE) {
        cPID++;
        fSystem = (*pdwPID == 4);
        fKernel = fSystem || ((*pdwState == 0) && (*pdwPEB == 0));
        // NB! Windows/Dokany does not support full 64-bit sizes on files, hence
        // the max value 0x0001000000000000 for kernel space. Top 16-bits (ffff)
        // are sign extended anyway so this should be fine if user skips them.
        if(*pdwDTB && *(PQWORD)szName && (fShowTerminated || !*pdwState)) {
            pVmmProcess = VmmProcessCreateEntry(
                *pdwPID,
                *pdwState,
                *pdwDTB & 0xffffffe0,
                dwoDTB_User ? (~0xfff & *pdwDTB_User) : 0,
                szName,
                !fKernel,
                fSystem);
        } else {
            pVmmProcess = NULL;
        }
        if(pVmmProcess) {
            pVmmProcess->os.win.vaEPROCESS = vaEPROCESS;
            pVmmProcess->os.win.vaPEB = *pdwPEB;
            vmmprintfvv("vmmwin.c!EnumerateEPROCESS32: %016llx %08x %08x %08x %s\n",
                pVmmProcess->paDTB,
                (DWORD)pVmmProcess->os.win.vaEPROCESS,
                (DWORD)pVmmProcess->os.win.vaPEB,
                pVmmProcess->dwPID,
                pVmmProcess->szName);
            if(!pVmmProcess) {
                vmmprintfv("VMM: WARNING: PID '%i' already exists.\n", *pdwPID);
                if(++cNewProcessCollision >= 8) {
                    break;
                }
            }
        } else {
            szName[14] = 0; // in case of bad string data ...
            vmmprintfv("VMM: Skipping process - parse error or terminated state.\n     PDPT: %08x PID: %i STATE: %i EPROCESS: %08x NAME: %s\n", ~0xfff & *pdwDTB, *pdwPID, *pdwState, vaEPROCESS, szName);
        }
        vaEPROCESS = *pdwFLink - dwoFLink;
        if(vaEPROCESS == vaSystemEPROCESS) {
            break;
        }
        if(!VmmRead(pSystemProcess, vaEPROCESS, pb, dwoMax)) {
            break;
        }
        if(*pdwDTB & 0x1f) {
            break;
        }
        if(0x80000000 != (0x80000003 & *pdwFLink)) {
            break;
        }
    }
    VmmProcessCreateFinish();
    return (cPID > 10);
}

BOOL VmmWin_EnumerateEPROCESS(_In_ PVMM_PROCESS pSystemProcess)
{
    switch(ctxVmm->tpMemoryModel) {
        case VMM_MEMORYMODEL_X64:
            return VmmWin_EnumerateEPROCESS64(pSystemProcess);
        case VMM_MEMORYMODEL_X86:
        case VMM_MEMORYMODEL_X86PAE:
            return VmmWin_EnumerateEPROCESS32(pSystemProcess);
    }
    return FALSE;
}

VOID VmmWin_InitializeModuleNames(_In_ PVMM_PROCESS pProcess)
{
    VmmWin_InitializeLdrModules(pProcess);
    VmmWin_ScanHeaderPE(pProcess);
}
