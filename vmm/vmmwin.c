// vmmwin.c : implementation related to operating system and process
// parsing of virtual memory. Windows related features only.
//
// (c) Ulf Frisk, 2018-2019
// Author: Ulf Frisk, pcileech@frizk.net
//

#include "vmmwin.h"
#include "vmmproc.h"
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

VOID VmmWin_PE_SECTION_DisplayBuffer(
    _In_ PVMM_PROCESS pProcess,
    _In_ PVMM_MODULEMAP_ENTRY pModule,
    _Out_writes_bytes_opt_(*pcbDisplayBuffer) PBYTE pbDisplayBufferOpt,
    _In_ DWORD cbDisplayBufferMax,
    _Out_opt_ PDWORD pcbDisplayBuffer,
    _Inout_opt_ PDWORD pcSectionsOpt,
    _Out_writes_opt_(*pcSectionsOpt) PIMAGE_SECTION_HEADER pSectionsOpt)
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
            // 70 byte per line (including newline)
            *pcbDisplayBuffer += snprintf(
                pbDisplayBufferOpt + *pcbDisplayBuffer,
                cbDisplayBufferMax - *pcbDisplayBuffer,
                "%02x %-8.8s  %016llx %08x %08x %c%c%c %08x %08x\n",
                i,
                pSectionBase[i].Name,
                pModule->BaseAddress + pSectionBase[i].VirtualAddress,
                pSectionBase[i].VirtualAddress,
                pSectionBase[i].Misc.VirtualSize,
                (pSectionBase[i].Characteristics & IMAGE_SCN_MEM_READ) ? 'r' : '-',
                (pSectionBase[i].Characteristics & IMAGE_SCN_MEM_WRITE) ? 'w' : '-',
                (pSectionBase[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) ? 'x' : '-',
                pSectionBase[i].PointerToRawData,
                pSectionBase[i].SizeOfRawData
            );
        }
    }
    if(pSectionsOpt && pcSectionsOpt && cSectionsOpt) {
        *pcSectionsOpt = min(cSectionsOpt, ntHeader64->FileHeader.NumberOfSections);
        memcpy(pSectionsOpt, pSectionBase, *pcSectionsOpt * sizeof(IMAGE_SECTION_HEADER));
    }
}

VOID VmmWin_PE_DIRECTORY_DisplayBuffer(
    _In_ PVMM_PROCESS pProcess,
    _In_ PVMM_MODULEMAP_ENTRY pModule,
    _Out_writes_bytes_opt_(*pcbDisplayBuffer) PBYTE pbDisplayBufferOpt,
    _In_ DWORD cbDisplayBufferMax,
    _Out_opt_ PDWORD pcbDisplayBuffer,
    _Out_writes_opt_(16) PIMAGE_DATA_DIRECTORY pDataDirectoryOpt)
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

_Success_(return)
BOOL VmmWin_PE_LoadEAT_DisplayBuffer(_In_ PVMM_PROCESS pProcess, _In_ PVMM_MODULEMAP_ENTRY pModule, _Out_writes_opt_(cEATs) PVMMPROC_WINDOWS_EAT_ENTRY pEATs, _In_ DWORD cEATs, _Out_ PDWORD pcEATs)
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
    *pcEATs = 0;
    // load both 32/64 bit ntHeader (only one will be valid)
    if(!(ntHeader64 = VmmWin_GetVerifyHeaderPE(pProcess, pModule->BaseAddress, pbModuleHeader, &fHdr32))) { goto fail; }
    ntHeader32 = (PIMAGE_NT_HEADERS32)ntHeader64;
    // Load Export Address Table (EAT)
    oExportDirectory = fHdr32 ?
        ntHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress :
        ntHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    cbExportDirectory = fHdr32 ?
        ntHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size :
        ntHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
    if(!oExportDirectory || !cbExportDirectory || cbExportDirectory > 0x01000000) { goto fail; }
    if(!(pbExportDirectory = LocalAlloc(0, cbExportDirectory))) { goto fail; }
    if(!VmmRead(pProcess, pModule->BaseAddress + oExportDirectory, pbExportDirectory, (DWORD)cbExportDirectory)) { goto fail; }
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
    LocalFree(pbExportDirectory);
    return TRUE;
fail:
    LocalFree(pbExportDirectory);
    return FALSE;
}

VOID VmmWin_PE_LoadIAT_DisplayBuffer(_In_ PVMM_PROCESS pProcess, _In_ PVMM_MODULEMAP_ENTRY pModule, _Out_writes_(*pcIATs) PVMMWIN_IAT_ENTRY pIATs, _In_ DWORD cIATs, _Out_ PDWORD pcIATs)
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
    DWORD c, j;
    *pcIATs = 0;
    // Load the module
    if(pModule->SizeOfImage > 0x02000000) { return; }
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
    EnterCriticalSection(&pProcess->LockUpdate);
    if(pModule->fLoadedEAT && pModule->fLoadedIAT) {
        LeaveCriticalSection(&pProcess->LockUpdate);
        return;
    }
    // load both 32/64 bit ntHeader (only one will be valid)
    if(!(pNtHeaders64 = VmmWin_GetVerifyHeaderPE(pProcess, pModule->BaseAddress, pbModuleHeader, &fHdr32))) {
        LeaveCriticalSection(&pProcess->LockUpdate);
        return;
    }
    // calculate display buffer size of: SECTIONS, EAT, IAT, RawFileSize
    pModule->cbFileSizeRaw = PE_FileRaw_Size(pProcess, pModule->BaseAddress, pbModuleHeader);
    pModule->cbDisplayBufferSections = PE_SectionGetNumberOfEx(pProcess, pModule->BaseAddress, pbModuleHeader) * 70;    // each display buffer human readable line == 70 bytes.
    if(!pModule->fLoadedEAT) {
        pModule->cbDisplayBufferEAT = PE_EatGetNumberOfEx(pProcess, pModule->BaseAddress, pbModuleHeader) * 64;         // each display buffer human readable line == 64 bytes.
        pModule->fLoadedEAT = TRUE;
    }
    if(!pModule->fLoadedIAT) {
        pModule->cbDisplayBufferIAT = PE_IatGetNumberOfEx(pProcess, pModule->BaseAddress, pbModuleHeader) * 128;        // each display buffer human readable line == 128 bytes.
        pModule->fLoadedIAT = TRUE;
    }
    LeaveCriticalSection(&pProcess->LockUpdate);
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

#define VMMWIN_SCANLDRMODULES_PREFETCH_MAX      0x100

VOID VmmWin_ScanLdrModules64(_In_ PVMM_PROCESS pProcess, _Inout_ PVMM_MODULEMAP_ENTRY pModules, _Inout_ PDWORD pcModules, _In_ DWORD cModulesMax, _Out_ PBOOL fWow64)
{
    QWORD vaModuleLdrFirst, vaModuleLdr = 0;
    BYTE pbPEB[sizeof(PEB)], pbPEBLdrData[sizeof(PEB_LDR_DATA)], pbLdrModule[sizeof(VMMPROC_LDR_DATA_TABLE_ENTRY)];
    PPEB pPEB = (PPEB)pbPEB;
    PPEB_LDR_DATA pPEBLdrData = (PPEB_LDR_DATA)pbPEBLdrData;
    PVMMPROC_LDR_DATA_TABLE_ENTRY pLdrModule = (PVMMPROC_LDR_DATA_TABLE_ENTRY)pbLdrModule;
    PVMM_MODULEMAP_ENTRY pModule;
    PVMMOB_DATASET pObDataSet_vaModuleLdr = NULL;
    BOOL fNameRead, fNameDefaultChar;
    DWORD iModuleLdr;
    // prefetch existing addresses (if any) & allocate new vaModuleLdr DataSet
    pObDataSet_vaModuleLdr = VmmObContainer_GetOb(&pProcess->pObProcessPersistent->ObCLdrModulesCachePrefetch64);
    VmmCachePrefetchPages(pProcess, pObDataSet_vaModuleLdr);
    VmmOb_DECREF(pObDataSet_vaModuleLdr);
    pObDataSet_vaModuleLdr = VmmObDataSet_Alloc(TRUE);
    if(!pObDataSet_vaModuleLdr) { goto fail; }
    // set up initial entry in vaModuleLdr DataSet
    *fWow64 = FALSE;
    if(pProcess->fUserOnly) {
        // User mode process -> walk PEB LDR list to enumerate modules / .dlls.
        if(!pProcess->os.win.vaPEB) { goto fail; }
        if(!VmmRead(pProcess, pProcess->os.win.vaPEB, pbPEB, sizeof(PEB))) { goto fail; }
        if(!VmmRead(pProcess, (QWORD)pPEB->Ldr, pbPEBLdrData, sizeof(PEB_LDR_DATA))) { goto fail; }
        vaModuleLdrFirst = (QWORD)pPEBLdrData->InMemoryOrderModuleList.Flink - 0x10; // InLoadOrderModuleList == InMemoryOrderModuleList - 0x10
        VmmObDataSet_Put(pObDataSet_vaModuleLdr, vaModuleLdrFirst);
    } else {
        // Kernel mode process -> walk PsLoadedModuleList to enumerate drivers / .sys and .dlls.
        if(!ctxVmm->kernel.vaPsLoadedModuleList) { goto fail; }
        if(!VmmRead(pProcess, ctxVmm->kernel.vaPsLoadedModuleList, (PBYTE)&vaModuleLdrFirst, sizeof(QWORD)) || !vaModuleLdrFirst) { goto fail; }
        if(!VmmRead(pProcess, ctxVmm->kernel.vaPsLoadedModuleList, pbPEBLdrData, sizeof(PEB_LDR_DATA))) { goto fail; }
        VmmObDataSet_Put(pObDataSet_vaModuleLdr, vaModuleLdrFirst);
    }
    // loop!
    for(iModuleLdr = 0; iModuleLdr < pObDataSet_vaModuleLdr->c; iModuleLdr++) {
        vaModuleLdr = pObDataSet_vaModuleLdr->pObData->pList[iModuleLdr].Value;
        if(!VmmRead(pProcess, vaModuleLdr, pbLdrModule, sizeof(VMMPROC_LDR_DATA_TABLE_ENTRY))) { continue; }
        if(!pLdrModule->BaseAddress || !pLdrModule->SizeOfImage) { continue; }
        pModule = pModules + *pcModules;
        pModule->BaseAddress = (QWORD)pLdrModule->BaseAddress;
        pModule->EntryPoint = (QWORD)pLdrModule->EntryPoint;
        pModule->SizeOfImage = (DWORD)pLdrModule->SizeOfImage;
        pModule->fWoW64 = FALSE;
        if(!pLdrModule->BaseDllName.Length) { continue; }
        fNameRead = VmmReadString_Unicode2Ansi(pProcess, (QWORD)pLdrModule->BaseDllName.Buffer, pModule->szName, min(31, pLdrModule->BaseDllName.Length), &fNameDefaultChar) && !fNameDefaultChar;
        fNameRead = fNameRead || PE_GetModuleName(pProcess, pModule->BaseAddress, pModule->szName, 32);
        if(fNameRead) {
            *fWow64 = pProcess->fUserOnly && (*fWow64 || !memcmp(pModule->szName, "wow64.dll", 10));
            vmmprintfvv_fn("%016llx %016llx %016llx %08x %i %s\n", vaModuleLdr, pModule->BaseAddress, pModule->EntryPoint, pModule->SizeOfImage, (pModule->fWoW64 ? 1 : 0), pModule->szName);
        } else {
            snprintf(pModule->szName, 31, "_UNKNOWN-%llx.dll", pModule->BaseAddress);
            vmmprintfvv_fn("INFO: Unable to get name - paged out? PID=%04i BASE=0x%016llx REPLACE='%s'\n", pProcess->dwPID, pModule->BaseAddress, pModule->szName);
        }
        *pcModules = *pcModules + 1;
        // add FLink/BLink lists
        if(pLdrModule->InLoadOrderModuleList.Flink && !((QWORD)pLdrModule->InLoadOrderModuleList.Flink & 0x7)) {
            VmmObDataSet_Put(pObDataSet_vaModuleLdr, (QWORD)CONTAINING_RECORD(pLdrModule->InLoadOrderModuleList.Flink, VMMPROC_LDR_DATA_TABLE_ENTRY, InLoadOrderModuleList));
        }
        if(pLdrModule->InLoadOrderModuleList.Blink && !((QWORD)pLdrModule->InLoadOrderModuleList.Blink & 0x7)) {
            VmmObDataSet_Put(pObDataSet_vaModuleLdr, (QWORD)CONTAINING_RECORD(pLdrModule->InLoadOrderModuleList.Blink, VMMPROC_LDR_DATA_TABLE_ENTRY, InLoadOrderModuleList));
        }
        if(pProcess->fUserOnly) {
            if(pLdrModule->InInitializationOrderModuleList.Flink && !((QWORD)pLdrModule->InInitializationOrderModuleList.Flink & 0x7)) {
                VmmObDataSet_Put(pObDataSet_vaModuleLdr, (QWORD)CONTAINING_RECORD(pLdrModule->InInitializationOrderModuleList.Flink, VMMPROC_LDR_DATA_TABLE_ENTRY, InInitializationOrderModuleList));
            }
            if(pLdrModule->InInitializationOrderModuleList.Blink && !((QWORD)pLdrModule->InInitializationOrderModuleList.Blink & 0x7)) {
                VmmObDataSet_Put(pObDataSet_vaModuleLdr, (QWORD)CONTAINING_RECORD(pLdrModule->InInitializationOrderModuleList.Blink, VMMPROC_LDR_DATA_TABLE_ENTRY, InInitializationOrderModuleList));
            }
            if(pLdrModule->InMemoryOrderModuleList.Flink && !((QWORD)pLdrModule->InMemoryOrderModuleList.Flink & 0x7)) {
                VmmObDataSet_Put(pObDataSet_vaModuleLdr, (QWORD)CONTAINING_RECORD(pLdrModule->InMemoryOrderModuleList.Flink, VMMPROC_LDR_DATA_TABLE_ENTRY, InMemoryOrderModuleList));
            }
            if(pLdrModule->InMemoryOrderModuleList.Blink && !((QWORD)pLdrModule->InMemoryOrderModuleList.Blink & 0x7)) {
                VmmObDataSet_Put(pObDataSet_vaModuleLdr, (QWORD)CONTAINING_RECORD(pLdrModule->InMemoryOrderModuleList.Blink, VMMPROC_LDR_DATA_TABLE_ENTRY, InMemoryOrderModuleList));
            }
        }
        if(*pcModules >= cModulesMax) { break; }
    }
    if(ctxMain->dev.fRemote && ctxVmm->ThreadProcCache.fEnabled) {
        VmmObContainer_SetOb(&pProcess->pObProcessPersistent->ObCLdrModulesCachePrefetch64, pObDataSet_vaModuleLdr);
    }
fail:
    VmmOb_DECREF(pObDataSet_vaModuleLdr);
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
    DWORD ProcessParameters;
    DWORD SubSystemData;
    DWORD ProcessHeap;
    DWORD Unknown1[27];
    DWORD NumberOfHeaps;
    DWORD MaximumNumberOfHeaps;
    DWORD ProcessHeaps;
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
    PVMMOB_DATASET pObDataSet_vaModuleLdr = NULL;
    BOOL fNameRead, fNameDefaultChar;
    DWORD iModuleLdr;
    // prefetch existing addresses (if any) & allocate new vaModuleLdr DataSet
    pObDataSet_vaModuleLdr = VmmObContainer_GetOb(&pProcess->pObProcessPersistent->ObCLdrModulesCachePrefetch32);
    VmmCachePrefetchPages(pProcess, pObDataSet_vaModuleLdr);
    VmmOb_DECREF(pObDataSet_vaModuleLdr);
    pObDataSet_vaModuleLdr = VmmObDataSet_Alloc(TRUE);
    if(!pObDataSet_vaModuleLdr) { goto fail; }
    // set up initial entry in vaModuleLdr DataSet
    if(pProcess->fUserOnly) {
        if(!pProcess->os.win.vaPEB) { goto fail; }
        if(!VmmRead(pProcess, pProcess->os.win.vaPEB32, pbPEB32, sizeof(PEB32))) { goto fail; }
        if(!VmmRead(pProcess, (DWORD)pPEB32->Ldr, pbPEBLdrData32, sizeof(PEB_LDR_DATA32))) { goto fail; }
        vaModuleLdr32 = vaModuleLdrFirst32 = (DWORD)pPEBLdrData32->InMemoryOrderModuleList.Flink - 0x08; // InLoadOrderModuleList == InMemoryOrderModuleList - 0x08
        VmmObDataSet_Put(pObDataSet_vaModuleLdr, vaModuleLdr32);
    } else if(ctxVmm->tpSystem == VMM_SYSTEM_WINDOWS_X86) {
        // Kernel mode process -> walk PsLoadedModuleList to enumerate drivers / .sys and .dlls.
        if(!ctxVmm->kernel.vaPsLoadedModuleList) { goto fail; }
        if(!VmmRead(pProcess, ctxVmm->kernel.vaPsLoadedModuleList, (PBYTE)&vaModuleLdrFirst32, sizeof(DWORD)) || !vaModuleLdrFirst32) { goto fail; }
        if(!VmmRead(pProcess, ctxVmm->kernel.vaPsLoadedModuleList, pbPEBLdrData32, sizeof(PEB_LDR_DATA32))) { goto fail; }
        VmmObDataSet_Put(pObDataSet_vaModuleLdr, vaModuleLdrFirst32);
    } else {
        goto fail;
    }
    // loop!
    for(iModuleLdr = 0; iModuleLdr < pObDataSet_vaModuleLdr->c; iModuleLdr++) {
        vaModuleLdr32 = (DWORD)pObDataSet_vaModuleLdr->pObData->pList[iModuleLdr].Value;
        if(!VmmRead(pProcess, vaModuleLdr32, pbLdrModule32, sizeof(LDR_MODULE32))) { continue; }
        if(!pLdrModule32->BaseAddress || !pLdrModule32->SizeOfImage) { continue; }
        pModule = pModules + *pcModules;
        pModule->BaseAddress = (QWORD)pLdrModule32->BaseAddress;
        pModule->EntryPoint = (QWORD)pLdrModule32->EntryPoint;
        pModule->SizeOfImage = (DWORD)pLdrModule32->SizeOfImage;
        pModule->fWoW64 = TRUE;
        if(!pLdrModule32->BaseDllName.Length) { continue; }
        fNameRead = VmmReadString_Unicode2Ansi(pProcess, (QWORD)pLdrModule32->BaseDllName.Buffer, pModule->szName, min(31, pLdrModule32->BaseDllName.Length), &fNameDefaultChar) && !fNameDefaultChar;
        fNameRead = fNameRead || PE_GetModuleName(pProcess, pModule->BaseAddress, pModule->szName, 32);
        if(fNameRead) {
            vmmprintfvv_fn("%08x %08x %08x %08x %s\n", vaModuleLdr32, (DWORD)pModule->BaseAddress, (DWORD)pModule->EntryPoint, pModule->SizeOfImage, pModule->szName);
        } else {
            snprintf(pModule->szName, 31, "_UNKNOWN-%llx.dll", pModule->BaseAddress);
            vmmprintfvv_fn("INFO: Unable to get name - paged out? PID=%04i BASE=0x%08x REPLACE='%s'\n", pProcess->dwPID, (DWORD)pModule->BaseAddress, pModule->szName);
        }
        *pcModules = *pcModules + 1;
        // add FLink/BLink lists
        if(pLdrModule32->InLoadOrderModuleList.Flink && !((DWORD)pLdrModule32->InLoadOrderModuleList.Flink & 0x3)) {
            VmmObDataSet_Put(pObDataSet_vaModuleLdr, (QWORD)CONTAINING_RECORD32(pLdrModule32->InLoadOrderModuleList.Flink, LDR_MODULE32, InLoadOrderModuleList));
        }
        if(pLdrModule32->InLoadOrderModuleList.Blink && !((DWORD)pLdrModule32->InLoadOrderModuleList.Blink & 0x3)) {
            VmmObDataSet_Put(pObDataSet_vaModuleLdr, (QWORD)CONTAINING_RECORD32(pLdrModule32->InLoadOrderModuleList.Blink, LDR_MODULE32, InLoadOrderModuleList));
        }
        if(pProcess->fUserOnly) {
            if(pLdrModule32->InInitializationOrderModuleList.Flink && !((DWORD)pLdrModule32->InInitializationOrderModuleList.Flink & 0x3)) {
                VmmObDataSet_Put(pObDataSet_vaModuleLdr, (QWORD)CONTAINING_RECORD32(pLdrModule32->InInitializationOrderModuleList.Flink, LDR_MODULE32, InInitializationOrderModuleList));
            }
            if(pLdrModule32->InInitializationOrderModuleList.Blink && !((DWORD)pLdrModule32->InInitializationOrderModuleList.Blink & 0x3)) {
                VmmObDataSet_Put(pObDataSet_vaModuleLdr, (QWORD)CONTAINING_RECORD32(pLdrModule32->InInitializationOrderModuleList.Blink, LDR_MODULE32, InInitializationOrderModuleList));
            }
            if(pLdrModule32->InMemoryOrderModuleList.Flink && !((DWORD)pLdrModule32->InMemoryOrderModuleList.Flink & 0x3)) {
                VmmObDataSet_Put(pObDataSet_vaModuleLdr, (QWORD)CONTAINING_RECORD32(pLdrModule32->InMemoryOrderModuleList.Flink, LDR_MODULE32, InMemoryOrderModuleList));
            }
            if(pLdrModule32->InMemoryOrderModuleList.Blink && !((DWORD)pLdrModule32->InMemoryOrderModuleList.Blink & 0x3)) {
                VmmObDataSet_Put(pObDataSet_vaModuleLdr, (QWORD)CONTAINING_RECORD32(pLdrModule32->InMemoryOrderModuleList.Blink, LDR_MODULE32, InMemoryOrderModuleList));
            }
        }
        if(*pcModules >= cModulesMax) { break; }
    }
    if(ctxMain->dev.fRemote && ctxVmm->ThreadProcCache.fEnabled) {
        VmmObContainer_SetOb(&pProcess->pObProcessPersistent->ObCLdrModulesCachePrefetch64, pObDataSet_vaModuleLdr);
    }
    VmmOb_DECREF(pObDataSet_vaModuleLdr);
    return TRUE;
fail:
    VmmOb_DECREF(pObDataSet_vaModuleLdr);
    return FALSE;
}

#define VMMPROCWINDOWS_MAX_MODULES      512

VOID VmmWin_InitializeLdrModules(_In_ PVMM_PROCESS pProcess)
{
    PVMM_MODULEMAP_ENTRY pModules, pModule;
    PVMMOB_MODULEMAP pOb = NULL;
    DWORD i, o, cModules;
    BOOL result, fWow64 = FALSE;
    if(pProcess->pObModuleMap) { return; }
    EnterCriticalSection(&pProcess->LockUpdate);
    if(pProcess->pObModuleMap) {
        LeaveCriticalSection(&pProcess->LockUpdate);
        return;
    }
    // allocate and enumerate
    pModules = (PVMM_MODULEMAP_ENTRY)LocalAlloc(LMEM_ZEROINIT, VMMPROCWINDOWS_MAX_MODULES * sizeof(VMM_MODULEMAP_ENTRY));
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
        pProcess->os.win.vaENTRY = pModules[0].EntryPoint;
        // allocate / set up VmmOb
        pOb = VmmOb_Alloc('MO', 0, sizeof(VMMOB_MODULEMAP) + cModules * (89ULL + sizeof(VMM_MODULEMAP_ENTRY)), NULL, NULL);
        if(!pOb) { goto fail; }
        pOb->pbDisplay = ((PBYTE)pOb->pMap) + cModules * sizeof(VMM_MODULEMAP_ENTRY);
        // create 'text' module map
        for(i = 0, o = 0; i < cModules; i++) {
            pModule = pModules + i;
            if(!pModule->BaseAddress) { continue; }
            o += snprintf(
                pOb->pbDisplay + o,
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
        pOb->cbDisplay = o;
    } else if(ctxVmm->tpSystem == VMM_SYSTEM_WINDOWS_X86) {
        pProcess->os.win.vaPEB32 = (DWORD)pProcess->os.win.vaPEB;
        VmmWin_ScanLdrModules32(pProcess, pModules, &cModules, VMMPROCWINDOWS_MAX_MODULES);
        if((cModules > 0) && (!pModules[cModules - 1].BaseAddress)) { cModules--; }
        pProcess->os.win.vaENTRY = pModules[0].EntryPoint;
        // allocate / set up VmmOb
        pOb = VmmOb_Alloc('MO', 0, sizeof(VMMOB_MODULEMAP) + cModules * (89ULL + sizeof(VMM_MODULEMAP_ENTRY)), NULL, NULL);
        if(!pOb) { goto fail; }
        pOb->pbDisplay = ((PBYTE)pOb->pMap) + cModules * sizeof(VMM_MODULEMAP_ENTRY);
        // create 'text' module map
        for(i = 0, o = 0; i < cModules; i++) {
            pModule = pModules + i;
            if(!pModule->BaseAddress) { continue; }
            o += snprintf(
                pOb->pbDisplay + o,
                70,
                "%04x %8x %08x-%08x      %s\n",
                i,
                pModule->SizeOfImage >> 12,
                (DWORD)pModule->BaseAddress,
                (DWORD)(pModule->BaseAddress + pModule->SizeOfImage - 1),
                pModule->szName
            );
        }
        pOb->cbDisplay = o;
    } else {
        LeaveCriticalSection(&pProcess->LockUpdate);
        return;
    }
    // copy modules map into Process struct
    pOb->fValid = TRUE;
    pOb->cMap = cModules;
    memcpy(pOb->pMap, pModules, cModules * sizeof(VMM_MODULEMAP_ENTRY));
    pProcess->pObModuleMap = pOb;   // reference taken by pProcess -> no need for DECREF.
    LeaveCriticalSection(&pProcess->LockUpdate);
    LocalFree(pModules);
    return;
fail:
    pProcess->pObModuleMap = VmmOb_Alloc('MO', LMEM_ZEROINIT, sizeof(VMMOB_MODULEMAP), NULL, NULL); // fValid set to false by default == failed initialization!
    LeaveCriticalSection(&pProcess->LockUpdate);
    LocalFree(pModules);
}

typedef struct tdVMMWIN_HEAP_SEGMENT64 {
    QWORD HeapEntry[2];
    DWORD SegmentSignature;
    DWORD SegmentFlags;
    LIST_ENTRY64 _ListEntry;
    QWORD Heap;
    QWORD BaseAddress;
    QWORD NumberOfPages;
    QWORD FirstEntry;
    QWORD LastValidEntry;
    DWORD NumberOfUnCommittedPages;
    DWORD NumberOfUnCommittedRanges;
    DWORD SegmentAllocatorBackTraceIndex;
    DWORD Reserved;
    LIST_ENTRY64 UCRSegmentList;
} VMMWIN_HEAP_SEGMENT64, *PVMMWIN_HEAP_SEGMENT64;

typedef struct tdVMMWIN_HEAP_SEGMENT32 {
    DWORD HeapEntry[2];
    DWORD SegmentSignature;
    DWORD SegmentFlags;
    LIST_ENTRY32 _ListEntry;
    DWORD Heap;
    DWORD BaseAddress;
    DWORD NumberOfPages;
    DWORD FirstEntry;
    DWORD LastValidEntry;
    DWORD NumberOfUnCommittedPages;
    DWORD NumberOfUnCommittedRanges;
    DWORD SegmentAllocatorBackTraceIndex;
    DWORD Reserved;
    LIST_ENTRY32 UCRSegmentList;
} VMMWIN_HEAP_SEGMENT32, *PVMMWIN_HEAP_SEGMENT32;


// ----------------------------------------------------------------------------
// WINDOWS SPECIFIC PROCESS RELATED FUNCTIONALITY BELOW:
// ----------------------------------------------------------------------------

/*
* Identify 64-bit HEAPs in a process and tag them into the memory map.
* WINXP is not supported.
*/
VOID VmmWin_ScanPebHeap64(_In_ PVMM_PROCESS pProcess)
{
    BOOL fReadHasMore, fFirst = TRUE;
    CHAR szBuffer[MAX_PATH];
    BYTE pbPEB[sizeof(PEB)];
    PPEB pPEB = (PPEB)pbPEB;
    DWORD i, j, cHeaps, cHeapsMax, cLoopProtect = 0;
    QWORD vaHeapPrimary, vaHeaps[0x80];
    PMEM_IO_SCATTER_HEADER pMEM, *ppMEMs = NULL;
    PVMMWIN_HEAP_SEGMENT64 pH, PH2;
    // 1: Read PEB
    if(!pProcess->os.win.vaPEB) { return; }
    if(!VmmRead(pProcess, pProcess->os.win.vaPEB, pbPEB, sizeof(PEB))) { return; }
    vaHeapPrimary = (QWORD)pPEB->Reserved4[1];
    cHeaps = (DWORD)((QWORD)pPEB->Reserved9[16]);
    cHeapsMax = (DWORD)((QWORD)pPEB->Reserved9[16] >> 32);
    if(cHeaps > 0x80) { return; } // probably not valid
    // 2: Read heap array
    if(!VmmRead(pProcess, (QWORD)pPEB->Reserved9[17], (PBYTE)vaHeaps, sizeof(QWORD) * cHeaps)) { return; }
    if(vaHeaps[0] != vaHeapPrimary) { return; }
    // 3: Read heap headers in one go (scatter read)
    if(!LeechCore_AllocScatterEmpty(cHeaps << 1, &ppMEMs)) { return; }
    for(i = 0; i < cHeaps; i++) {
        if(vaHeaps[i] & 0xffff) {
            LocalFree(ppMEMs);
            return;
        }
        ppMEMs[i]->qwA = vaHeaps[i];
    }
    // 4: Analyze result
    do {
        VmmReadScatterVirtual(pProcess, ppMEMs, cHeaps << 1, 0);
        fReadHasMore = FALSE;
        for(i = 0; i < (cHeaps << 1); i++) {
            pMEM = ppMEMs[i];
            if(pMEM->cb != 0x1000) { continue; }
            pH = PH2 = (PVMMWIN_HEAP_SEGMENT64)ppMEMs[i]->pb;
            if(pH->SegmentSignature != 0xffeeffee) { continue; }
            if(pH->Heap != vaHeaps[i % cHeaps]) { continue; }   // heap address mis-match
            if(pH->NumberOfPages >= 0x40000) { continue; }      // heap size > 1GB == unrealistic.
            // set tag
            sprintf_s(szBuffer, MAX_PATH, "HEAP%02X", i % cHeaps);
            VmmMemMapTag(pProcess, pH->BaseAddress, pH->BaseAddress + (pH->NumberOfPages << 12), szBuffer, NULL, FALSE, FALSE);
            // prepare next read
            pMEM[i].cb = 0;
            if((i >= cHeaps) || fFirst) { // BLink
                j = i + ((i < cHeaps) ? cHeaps : 0);
                // BLink inside same page -> jump forward
                if((PH2->_ListEntry.Blink - pMEM[i].qwA < 0x800) && ((PH2->_ListEntry.Blink & 0xfff) >= sizeof(VMMWIN_HEAP_SEGMENT64))) {
                    PH2 = (PVMMWIN_HEAP_SEGMENT64)(ppMEMs[i]->pb + (PH2->_ListEntry.Blink & 0xfff) - 0x18);
                }
                pMEM[j].qwA = (QWORD)-1;
                if((((PH2->_ListEntry.Blink - 0x18) & 0xffff) == 0) && ((PH2->_ListEntry.Blink - 0x18) != vaHeaps[i])) {
                    pMEM[j].qwA = PH2->_ListEntry.Blink - 0x18;
                    fReadHasMore = TRUE;
                }
            }
            if(i < cHeaps) { // FLink
                pMEM[i].qwA = (QWORD)-1;
                if((((pH->_ListEntry.Flink - 0x18) & 0xffff) == 0) && ((pH->_ListEntry.Flink - 0x18) != vaHeaps[i])) {
                    pMEM[i].qwA = pH->_ListEntry.Flink - 0x18;
                    fReadHasMore = TRUE;
                }
            }
        }
        fFirst = FALSE;
    } while(fReadHasMore && (++cLoopProtect < 0x40));
    LocalFree(ppMEMs);
}

/*
* Identify 32-bit HEAPs in a process and tag them into the memory map.
* NB! The 32-bit variant below is NOT robust. It will fail a lot of times
* especially on older versions - but it will fail silently without causing
* harm except a few extra reads. Probably due to bad hardcoded values. It's
* primarily heap-header analysis that is failing. But it seems to mostly work
* on newer windows versions.
* WINXP is not supported.
*/
VOID VmmWin_ScanPebHeap32(_In_ PVMM_PROCESS pProcess, _In_ BOOL fWow64)
{
    BOOL fReadHasMore, fFirst = TRUE;
    CHAR szBuffer[MAX_PATH];
    BYTE pbPEB[sizeof(PEB32)];
    PPEB32 pPEB = (PPEB32)pbPEB;
    DWORD i, j, cHeaps, cHeapsMax, cLoopProtect = 0;
    DWORD vaHeapPrimary, vaHeaps[0x80];
    PMEM_IO_SCATTER_HEADER pMEM, *ppMEMs = NULL;
    PVMMWIN_HEAP_SEGMENT32 pH, PH2;
    // 1: Read PEB
    if(!fWow64 && !pProcess->os.win.vaPEB) { return; }
    if(fWow64 && !pProcess->os.win.vaPEB32) { return; }
    if(!VmmRead(pProcess, (fWow64 ? pProcess->os.win.vaPEB32 : pProcess->os.win.vaPEB), pbPEB, sizeof(PEB32))) { return; }
    vaHeapPrimary = pPEB->ProcessHeap;
    cHeaps = pPEB->NumberOfHeaps;
    cHeapsMax = pPEB->MaximumNumberOfHeaps;
    if(cHeaps > 0x80) { return; } // probably not valid
    // 2: Read heap array
    if(!VmmRead(pProcess, pPEB->ProcessHeaps, (PBYTE)vaHeaps, sizeof(DWORD) * cHeaps)) { return; }
    if(vaHeaps[0] != vaHeapPrimary) { return; }
    // 3: Read heap headers in one go (scatter read)
    if(!LeechCore_AllocScatterEmpty(cHeaps << 1, &ppMEMs)) { return; }
    for(i = 0; i < cHeaps; i++) {
        if(vaHeaps[i] & 0xffff) {
            LocalFree(ppMEMs);
            return;
        }
        ppMEMs[i]->qwA = vaHeaps[i];
    }
    VmmReadScatterVirtual(pProcess, ppMEMs, cHeaps, 0);
    // 4: Analyze result
    do {
        VmmReadScatterVirtual(pProcess, ppMEMs, cHeaps << 1, 0);
        fReadHasMore = FALSE;
        for(i = 0; i < (cHeaps << 1); i++) {
            pMEM = ppMEMs[i];
            if(pMEM->cb != 0x1000) { continue; }
            pH = PH2 = (PVMMWIN_HEAP_SEGMENT32)ppMEMs[i]->pb;
            if(pH->SegmentSignature != 0xffeeffee) { continue; }
            if(pH->Heap != vaHeaps[i % cHeaps]) { continue; }   // heap address mis-match
            if(pH->NumberOfPages >= 0x40000) { continue; }      // heap size > 1GB == unrealistic.
            // set tag
            sprintf_s(szBuffer, MAX_PATH, "HEAP%02X", i % cHeaps);
            VmmMemMapTag(pProcess, pH->BaseAddress, (QWORD)pH->BaseAddress + ((QWORD)pH->NumberOfPages << 12), szBuffer, NULL, fWow64, FALSE);
            // prepare next read
            pMEM[i].cb = 0;
            if((i >= cHeaps) || fFirst) { // BLink
                j = i + ((i < cHeaps) ? cHeaps : 0);
                // BLink inside same page -> jump forward
                if((PH2->_ListEntry.Blink - pMEM[i].qwA < 0x800) && ((PH2->_ListEntry.Blink & 0xfff) >= sizeof(VMMWIN_HEAP_SEGMENT64))) {
                    PH2 = (PVMMWIN_HEAP_SEGMENT32)(ppMEMs[i]->pb + (PH2->_ListEntry.Blink & 0xfff) - 0x18);
                }
                pMEM[j].qwA = (QWORD)-1;
                if((((PH2->_ListEntry.Blink - 0x18) & 0xffff) == 0) && ((PH2->_ListEntry.Blink - 0x18) != vaHeaps[i])) {
                    pMEM[j].qwA = PH2->_ListEntry.Blink - 0x18;
                    fReadHasMore = TRUE;
                }
            }
            if(i < cHeaps) { // FLink
                pMEM[i].qwA = (QWORD)-1;
                if((((pH->_ListEntry.Flink - 0x18) & 0xffff) == 0) && ((pH->_ListEntry.Flink - 0x18) != vaHeaps[i])) {
                    pMEM[i].qwA = pH->_ListEntry.Flink - 0x18;
                    fReadHasMore = TRUE;
                }
            }
        }
        fFirst = FALSE;
    } while(fReadHasMore && (++cLoopProtect < 0x40));
    LocalFree(ppMEMs);
}

/*
* Identify module names by scanning for PE headers and tag them into the memory map.
*/
VOID VmmWin_ScanHeaderPE(_In_ PVMM_PROCESS pProcess)
{
    DWORD cMap;
    PVMMOB_MEMMAP pObMemMap = NULL;
    PVMM_MEMMAP_ENTRY pMap;
    PVMM_MEMMAP_ENTRY ppMAPs[0x400];
    PPMEM_IO_SCATTER_HEADER ppMEMs = NULL;
    DWORD i, cMEMs = 0, cbImageSize;
    BOOL result;
    CHAR szBuffer[MAX_PATH];
    // 1: checks and allocate buffers for parallel read of MZ header candidates
    if(!LeechCore_AllocScatterEmpty(0x400, &ppMEMs)) { return; }
    if(!VmmMemMapGetEntries(pProcess, 0, &pObMemMap)) { return; }
    cMap = pObMemMap->cMap;
    pMap = pObMemMap->pMap;
    // 2: scan memory map for MZ header candidates and put them on list for read
    for(i = 0; i < cMap - 1; i++) {
        if(ctxVmm->tpMemoryModel == VMM_MEMORYMODEL_X86) {
            result =
                !(pMap[i].AddrBase & 0xffff) &&                 // starts at even 0x10000 offset
                !pMap[i].szTag[0];                              // tag not already set
        } else {
            result =
                (pMap[i].cPages == 1) &&                        // PE header is only 1 page
                !(pMap[i].AddrBase & 0xffff) &&                 // starts at even 0x10000 offset
                !pMap[i].szTag[0] &&                            // tag not already set
                (pMap[i].fPage & VMM_MEMMAP_PAGE_NX) &&         // no-execute
                !(pMap[i + 1].fPage & VMM_MEMMAP_PAGE_NX);      // next page is executable
        }
        if(result) {
            ppMEMs[cMEMs]->qwA = pMap[i].AddrBase;
            ppMAPs[cMEMs] = pMap + i;
            cMEMs++;
            if(cMEMs == 0x400) { break; }
        }
    }
    // 3: read all MZ header candicates previously selected and try load name from them (after read is successful)
    if(cMEMs) {
        VmmReadScatterVirtual(pProcess, ppMEMs, cMEMs, 0);
        for(i = 0; i < cMEMs; i++) {
            if(ppMEMs[i]->cb == 0x1000) {
                result = PE_GetModuleNameEx(pProcess, ppMAPs[i]->AddrBase, TRUE, ppMEMs[i]->pb, szBuffer, _countof(szBuffer), &cbImageSize);
                if(result && (cbImageSize < 0x01000000)) {
                    VmmMemMapTag(pProcess, ppMAPs[i]->AddrBase, ppMAPs[i]->AddrBase + cbImageSize, szBuffer, NULL, FALSE, FALSE);
                }
            }
        }
    }
    LocalFree(ppMEMs);
    VmmOb_DECREF(pObMemMap);
}

// ----------------------------------------------------------------------------
// WINDOWS EPROCESS WALKING FUNCTIONALITY FOR 64/32 BIT BELOW:
// ----------------------------------------------------------------------------

#define VMMPROC_EPROCESS_MAX_SIZE       0x500
#define VMMWIN_EPROCESS_PREFETCH_MAX    0x200

/*
* Very ugly hack that tries to locate some offsets required withn the EPROCESS struct.
*/
VOID VmmWin_OffsetLocatorEPROCESS64(_In_ PVMM_PROCESS pSystemProcess)
{
    BOOL f;
    WORD i;
    QWORD va1, vaPEB, paPEB;
    BYTE pb0[VMMPROC_EPROCESS_MAX_SIZE], pb1[VMMPROC_EPROCESS_MAX_SIZE], pbPage[0x1000];
    BYTE pbZero[0x800];
    QWORD paMax, paDTB_0, paDTB_1;
    PVMM_WIN_EPROCESS_OFFSET pOffsetEPROCESS = &ctxVmm->kernel.OffsetEPROCESS;
    ZeroMemory(pOffsetEPROCESS, sizeof(VMM_WIN_EPROCESS_OFFSET));
    if(!VmmRead(pSystemProcess, pSystemProcess->os.win.vaEPROCESS, pb0, VMMPROC_EPROCESS_MAX_SIZE)) { return; }
    if(ctxMain->cfg.fVerboseExtra) {
        vmmprintf_fn("%016llx %016llx\n", pSystemProcess->paDTB, pSystemProcess->os.win.vaEPROCESS);
        Util_PrintHexAscii(pb0, VMMPROC_EPROCESS_MAX_SIZE, 0);
    }
    // find offset State (static for now)
    if(*(PDWORD)(pb0 + 0x04)) { return; }
    pOffsetEPROCESS->State = 0x04;
    // find offset PML4 (static for now)
    if(pSystemProcess->paDTB != (0xfffffffffffff000 & *(PQWORD)(pb0 + 0x28))) { return; }
    pOffsetEPROCESS->DTB = 0x28;
    // find offset for Name
    for(i = 0, f = FALSE; i < VMMPROC_EPROCESS_MAX_SIZE - 8; i += 8) {
        if(*(PQWORD)(pb0 + i) == 0x00006D6574737953) {
            pOffsetEPROCESS->Name = i;
            f = TRUE;
            break;
        }
    }
    if(!f) { return; }
    // find offset for PID, FLink, BLink (assumed to be following eachother)
    for(i = 0, f = FALSE; i < VMMPROC_EPROCESS_MAX_SIZE - 8; i += 8) {
        if(*(PQWORD)(pb0 + i) == 4) {
            // PID = correct, this is a candidate
            if(0xffff000000000000 != (0xffff000000000003 & *(PQWORD)(pb0 + i + 8))) { continue; }    // FLink not valid kernel pointer
            va1 = *(PQWORD)(pb0 + i + 8) - i - 8;
            f = VmmRead(pSystemProcess, va1, pb1, VMMPROC_EPROCESS_MAX_SIZE);
            if(!f) { continue; }
            f = FALSE;
            if((*(PQWORD)(pb1 + pOffsetEPROCESS->Name) != 0x6578652e73736d73) &&    // smss.exe
                (*(PQWORD)(pb1 + pOffsetEPROCESS->Name) != 0x7972747369676552) &&   // Registry
                (*(PQWORD)(pb1 + pOffsetEPROCESS->Name) != 0x5320657275636553))     // Secure System
            {
                continue;
            }
            if((*(PQWORD)(pb1 + i + 16) - i - 8) != pSystemProcess->os.win.vaEPROCESS) {
                continue;
            }
            pOffsetEPROCESS->PID = i;
            pOffsetEPROCESS->FLink = i + 8;
            pOffsetEPROCESS->BLink = i + 16;
            f = TRUE;
            break;
        }
    }
    if(!f) { return; }
    // skip over "processes" without PEB
    while((*(PQWORD)(pb1 + pOffsetEPROCESS->Name) == 0x5320657275636553) ||         // Secure System
        (*(PQWORD)(pb1 + pOffsetEPROCESS->Name) == 0x7972747369676552))             // Registry
    {
        va1 = *(PQWORD)(pb1 + pOffsetEPROCESS->FLink) - pOffsetEPROCESS->FLink;
        f = VmmRead(pSystemProcess, va1, pb1, VMMPROC_EPROCESS_MAX_SIZE);
        if(!f) { return; }
    }
    if(ctxMain->cfg.fVerboseExtra) {
        vmmprintf("---------------------------------------------------------------------------\n");
        Util_PrintHexAscii(pb1, VMMPROC_EPROCESS_MAX_SIZE, 0);
    }
    // find offset for PEB (in EPROCESS)
    for(i = 0x280, f = FALSE; i < 0x480; i += 8) {
        if(*(PQWORD)(pb0 + i)) { continue; }
        vaPEB = *(PQWORD)(pb1 + i);
        if(!vaPEB || (vaPEB & 0xffff800000000fff)) { continue; }
        // Verify potential PEB
        if(!VmmVirt2PhysEx(*(PQWORD)(pb1 + pOffsetEPROCESS->DTB), TRUE, vaPEB, &paPEB)) { continue; }
        if(!VmmReadPhysicalPage(paPEB, pbPage)) { continue; }
        if(*(PWORD)pbPage == 0x5a4d) { continue; }  // MZ header -> likely entry point or something not PEB ...
        pOffsetEPROCESS->PEB = i;
        f = TRUE;
        break;
    }
    if(!f) { return; }
    // find "optional" offset for user cr3/pml4 (post meltdown only)
    // System have an entry pointing to a shadow PML4 which has empty user part
    // smss.exe do not have an entry since it's running as admin ...
    pOffsetEPROCESS->DTB_User = 0;
    ZeroMemory(pbZero, 0x800);
    paMax = ctxMain->dev.paMax;
    for(i = pOffsetEPROCESS->DTB + 8; i < VMMPROC_EPROCESS_MAX_SIZE - 8; i += 8) {
        paDTB_0 = *(PQWORD)(pb0 + i);  // EPROCESS entry item of System
        paDTB_1 = *(PQWORD)(pb1 + i);  // EPROCESS entry item of smss.exe
        f = ((paDTB_1 & ~1) != 0);
        f = f || (paDTB_0 == 0);
        f = f || (paDTB_0 & 0xffe);
        f = f || (paDTB_0 >= paMax);
        f = f || !VmmReadPhysicalPage((paDTB_0 & ~0xfff), pbPage);
        f = f || memcmp(pbPage, pbZero, 0x800);
        f = f || !VmmTlbPageTableVerify(pbPage, (paDTB_0 & ~0xfff), TRUE);
        if(!f) {
            pOffsetEPROCESS->DTB_User = i;
            break;
        }
    }
    vmmprintfvv_fn(
        "PID: %x STATE: %x DTB: %x DTB_User: %x NAME: %x PEB: %x FLink: %x\n",
        pOffsetEPROCESS->PID,
        pOffsetEPROCESS->State,
        pOffsetEPROCESS->DTB,
        pOffsetEPROCESS->DTB_User,
        pOffsetEPROCESS->Name,
        pOffsetEPROCESS->PEB,
        pOffsetEPROCESS->FLink);
    pOffsetEPROCESS->cbMaxOffset = min(VMMPROC_EPROCESS_MAX_SIZE, 16 + max(max(max(pOffsetEPROCESS->State, pOffsetEPROCESS->PID), max(pOffsetEPROCESS->Name, pOffsetEPROCESS->FLink)), max(pOffsetEPROCESS->DTB_User, max(pOffsetEPROCESS->DTB, pOffsetEPROCESS->PEB))));
    pOffsetEPROCESS->fValid = TRUE;
}

/*
* Try walk the EPROCESS list in the Windows kernel to enumerate processes into
* the VMM/PROC file system.
* NB! This may be done to refresh an existing PID cache hence migration code.
* -- pSystemProcess
* -- return
*/
BOOL VmmWin_EnumerateEPROCESS64(_In_ PVMM_PROCESS pSystemProcess, _In_ BOOL fTotalRefresh)
{
    PQWORD pqwDTB, pqwDTB_User, pqwFLink, pqwBLink, pqwPEB;
    PDWORD pdwState, pdwPID;
    LPSTR szName;
    BYTE pb[VMMPROC_EPROCESS_MAX_SIZE];
    PVMM_PROCESS pObProcess = NULL;
    QWORD vaSystemEPROCESS, vaEPROCESS, cNewProcessCollision = 0;
    DWORD iProc = 0;
    BOOL fShowTerminated, fUser;
    PVMM_WIN_EPROCESS_OFFSET pOffsetEPROCESS = &ctxVmm->kernel.OffsetEPROCESS;
    PVMMOB_DATASET pObSetAddressEPROCESS = NULL;
    fShowTerminated = ctxVmm->flags & VMM_FLAG_PROCESS_SHOW_TERMINATED;
    vaSystemEPROCESS = pSystemProcess->os.win.vaEPROCESS;
    // retrieve offsets
    if(!pOffsetEPROCESS->fValid) {
        VmmWin_OffsetLocatorEPROCESS64(pSystemProcess);
        if(!pOffsetEPROCESS->fValid) {
            vmmprintf("VmmProc: Unable to locate EPROCESS offsets.\n");
            return FALSE;
        }
    }
    vmmprintfvv_fn("%016llx %016llx\n", pSystemProcess->paDTB, vaSystemEPROCESS);
    pdwState = (PDWORD)(pb + pOffsetEPROCESS->State);
    pdwPID = (PDWORD)(pb + pOffsetEPROCESS->PID);
    pqwDTB = (PQWORD)(pb + pOffsetEPROCESS->DTB);
    pqwDTB_User = (PQWORD)(pb + pOffsetEPROCESS->DTB_User);
    pqwFLink = (PQWORD)(pb + pOffsetEPROCESS->FLink);
    pqwBLink = (PQWORD)(pb + pOffsetEPROCESS->BLink);
    szName = (LPSTR)(pb + pOffsetEPROCESS->Name);
    pqwPEB = (PQWORD)(pb + pOffsetEPROCESS->PEB);
    // prefetch pages into cache (if any)
    pObSetAddressEPROCESS = VmmObContainer_GetOb(&ctxVmm->ObCEPROCESSCachePrefetch);
    VmmCachePrefetchPages(pSystemProcess, pObSetAddressEPROCESS);
    VmmOb_DECREF(pObSetAddressEPROCESS);
    // initialize address set
    if(!(pObSetAddressEPROCESS = VmmObDataSet_Alloc(TRUE))) { return FALSE; }
    VmmObDataSet_Put(pObSetAddressEPROCESS, vaSystemEPROCESS);
    // loop!
    vmmprintfvv_fn("   # STATE  PID      DTB          EPROCESS         PEB          NAME  \n");
    for(iProc = 0; iProc < pObSetAddressEPROCESS->c; iProc++) {
        vaEPROCESS = pObSetAddressEPROCESS->pObData->pList[iProc].Value;
        if(!VmmRead(pSystemProcess, vaEPROCESS, pb, pOffsetEPROCESS->cbMaxOffset)) { continue; }
        if(*pqwDTB & 0xffffff0000000000) { continue; }
        VmmOb_DECREF(pObProcess);
        pObProcess = NULL;
        if(*pqwDTB && *(PQWORD)szName && (fShowTerminated || !*pdwState)) {
            fUser = 
                !((*pdwPID == 4) || ((*pdwState == 0) && (*pqwPEB == 0))) ||
                ((*(PQWORD)(szName + 0x00) == 0x7972747369676552) && (*(PDWORD)(szName + 0x08) == 0x00000000)) ||   // Registry "process"
                ((*(PQWORD)(szName + 0x00) == 0x72706d6f436d654d) && (*(PDWORD)(szName + 0x08) == 0x69737365));     // MemCompression "process"
            pObProcess = VmmProcessCreateEntry(
                fTotalRefresh,
                *pdwPID,
                *pdwState,
                ~0xfff & *pqwDTB,
                pOffsetEPROCESS->DTB_User ? (~0xfff & *pqwDTB_User) : 0,
                szName,
                fUser);
            if(!pObProcess) {
                vmmprintfv("VMM: WARNING: PID '%i' already exists.\n", *pdwPID);
                if(++cNewProcessCollision >= 8) {
                    continue;
                }
            }
        }
        if(pObProcess) {
            pObProcess->os.win.vaEPROCESS = vaEPROCESS;
            if(*pqwPEB % PAGE_SIZE) {
                vmmprintfv("VMM: WARNING: Bad PEB alignment for PID: '%i' (0x%016llx).\n", *pdwPID, *pqwPEB);
            } else {
                pObProcess->os.win.vaPEB = *pqwPEB;
            }
        } else {
            szName[14] = 0; // in case of bad string data ...
        }
        vmmprintfvv_fn("%04i (%s) %08x %012llx %016llx %012llx %s\n",
            iProc,
            pObProcess ? "list" : "skip",
            *pdwPID,
            ~0xfff & *pqwDTB,
            vaEPROCESS,
            *pqwPEB,
            szName);
        // Add FLink & BLink
        if(0xffff800000000000 == (0xffff800000000007 & *pqwFLink)) {
            VmmObDataSet_Put(pObSetAddressEPROCESS, *pqwFLink - pOffsetEPROCESS->FLink);
        }
        if(0xffff800000000000 == (0xffff800000000007 & *pqwBLink)) {
            VmmObDataSet_Put(pObSetAddressEPROCESS, *pqwBLink - pOffsetEPROCESS->FLink);
        }
    }
    VmmObContainer_SetOb(&ctxVmm->ObCEPROCESSCachePrefetch, pObSetAddressEPROCESS);
    VmmOb_DECREF(pObSetAddressEPROCESS);
    VmmOb_DECREF(pObProcess);
    VmmProcessCreateFinish();
    return (iProc > 10);
}

/*
* Very ugly hack that tries to locate some offsets required withn the EPROCESS struct.
*/
VOID VmmWin_OffsetLocatorEPROCESS32(_In_ PVMM_PROCESS pSystemProcess)
{
    BOOL f;
    WORD i;
    DWORD va1, vaPEB;
    QWORD paPEB;
    BYTE pb0[VMMPROC_EPROCESS_MAX_SIZE], pb1[VMMPROC_EPROCESS_MAX_SIZE], pbPage[0x1000];
    PVMM_WIN_EPROCESS_OFFSET pOffsetEPROCESS = &ctxVmm->kernel.OffsetEPROCESS;
    ZeroMemory(pOffsetEPROCESS, sizeof(VMM_WIN_EPROCESS_OFFSET));
    //BYTE pbZero[0x800]
    //QWORD paMax, paDTB_0, paDTB_1;
    if(!VmmRead(pSystemProcess, pSystemProcess->os.win.vaEPROCESS, pb0, VMMPROC_EPROCESS_MAX_SIZE)) { return; }
    if(ctxMain->cfg.fVerboseExtra) {
        vmmprintf("vmmwin.c!32_OffsetLocatorEPROCESS: %016llx %016llx\n", pSystemProcess->paDTB, pSystemProcess->os.win.vaEPROCESS);
        Util_PrintHexAscii(pb0, VMMPROC_EPROCESS_MAX_SIZE, 0);
    }
    // find offset State (static for now)
    if(*(PDWORD)(pb0 + 0x04)) { return; }
    pOffsetEPROCESS->State = 0x04;
    // find offset PML4 (static for now)
    //if(pSystemProcess->paDTB != (0xfffff000 & *(PDWORD)(pb0 + 0x18))) { return FALSE; }
    pOffsetEPROCESS->DTB = 0x18;
    // find offset for Name
    for(i = 0, f = FALSE; i < VMMPROC_EPROCESS_MAX_SIZE - 4; i += 4) {
        if(*(PQWORD)(pb0 + i) == 0x00006D6574737953) {
            pOffsetEPROCESS->Name = i;
            f = TRUE;
            break;
        }
    }
    if(!f) { return; }
    // find offset for PID, FLink, BLink (assumed to be following eachother)
    for(i = 0, f = FALSE; i < VMMPROC_EPROCESS_MAX_SIZE - 4; i += 4) {
        if(*(PDWORD)(pb0 + i) == 4) {
            // PID = correct, this is a candidate
            if(0x80000000 != (0x80000003 & *(PDWORD)(pb0 + i + 4))) { continue; }    // FLink not valid kernel pointer
            va1 = *(PDWORD)(pb0 + i + 4) - i - 4;
            f = VmmRead(pSystemProcess, va1, pb1, VMMPROC_EPROCESS_MAX_SIZE);
            if(!f) { continue; }
            f = FALSE;
            if((*(PQWORD)(pb1 + pOffsetEPROCESS->Name) != 0x6578652e73736d73) &&    // smss.exe
                (*(PQWORD)(pb1 + pOffsetEPROCESS->Name) != 0x7972747369676552) &&   // Registry
                (*(PQWORD)(pb1 + pOffsetEPROCESS->Name) != 0x5320657275636553))     // Secure System
            {
                continue;
            }
            if((*(PDWORD)(pb1 + i + 8) - i - 4) != pSystemProcess->os.win.vaEPROCESS) {
                continue;
            }
            pOffsetEPROCESS->PID = i;
            pOffsetEPROCESS->FLink = i + 4;
            pOffsetEPROCESS->BLink = i + 8;
            f = TRUE;
            break;
        }
    }
    if(!f) { return; }
    // skip over "processes" without PEB
    while((*(PQWORD)(pb1 + pOffsetEPROCESS->Name) == 0x5320657275636553) ||         // Secure System
        (*(PQWORD)(pb1 + pOffsetEPROCESS->Name) == 0x7972747369676552))             // Registry
    {
        va1 = *(PDWORD)(pb1 + pOffsetEPROCESS->FLink) - pOffsetEPROCESS->FLink;
        f = VmmRead(pSystemProcess, va1, pb1, VMMPROC_EPROCESS_MAX_SIZE);
        if(!f) { return; }
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
        if(!VmmVirt2PhysEx(*(PDWORD)(pb1 + pOffsetEPROCESS->DTB), TRUE, vaPEB, &paPEB)) { continue; }
        if(!VmmReadPhysicalPage(paPEB, pbPage)) { continue; }
        if(*(PWORD)pbPage == 0x5a4d) { continue; }  // MZ header -> likely entry point or something not PEB ...
        pOffsetEPROCESS->PEB = i;
        f = TRUE;
        break;
    }
    if(!f) { return; }
    // find "optional" offset for user cr3/pml4 (post meltdown only)
    // System have an entry pointing to a shadow PML4 which has empty user part
    // smss.exe do not have an entry since it's running as admin ...
    pOffsetEPROCESS->DTB_User = 0;
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
    vmmprintfvv_fn(
        "PID: %x STATE: %x DTB: %x DTB_User: %x NAME: %x PEB: %x FLink: %x\n", 
        pOffsetEPROCESS->PID, 
        pOffsetEPROCESS->State,
        pOffsetEPROCESS->DTB,
        pOffsetEPROCESS->DTB_User,
        pOffsetEPROCESS->Name,
        pOffsetEPROCESS->PEB,
        pOffsetEPROCESS->FLink);
    pOffsetEPROCESS->cbMaxOffset = min(VMMPROC_EPROCESS_MAX_SIZE, 16 + max(max(max(pOffsetEPROCESS->State, pOffsetEPROCESS->PID), max(pOffsetEPROCESS->Name, pOffsetEPROCESS->FLink)), max(pOffsetEPROCESS->DTB_User, max(pOffsetEPROCESS->DTB, pOffsetEPROCESS->PEB))));
    pOffsetEPROCESS->fValid = TRUE;
}

BOOL VmmWin_EnumerateEPROCESS32(_In_ PVMM_PROCESS pSystemProcess, _In_ BOOL fTotalRefresh)
{
    PDWORD pdwDTB, pdwDTB_User, pdwFLink, pdwBLink, pdwPEB;
    PDWORD pdwState, pdwPID;
    LPSTR szName;
    BYTE pb[VMMPROC_EPROCESS_MAX_SIZE];
    PVMM_PROCESS pObProcess = NULL;
    DWORD vaSystemEPROCESS, vaEPROCESS, cPID = 0, cNewProcessCollision = 0;
    DWORD iProc = 0;
    BOOL fShowTerminated, fUser;
    PVMM_WIN_EPROCESS_OFFSET pOffsetEPROCESS = &ctxVmm->kernel.OffsetEPROCESS;
    PVMMOB_DATASET pObSetAddressEPROCESS = NULL;
    fShowTerminated = ctxVmm->flags & VMM_FLAG_PROCESS_SHOW_TERMINATED;
    vaSystemEPROCESS = (DWORD)pSystemProcess->os.win.vaEPROCESS;
    // retrieve offsets
    if(!pOffsetEPROCESS->fValid) {
        VmmWin_OffsetLocatorEPROCESS32(pSystemProcess);
        if(!pOffsetEPROCESS->fValid) {
            vmmprintf("VmmProc: Unable to locate EPROCESS offsets.\n");
            return FALSE;
        }
    }
    vmmprintfvv_fn("%016llx %08x\n", pSystemProcess->paDTB, vaSystemEPROCESS);
    pdwState = (PDWORD)(pb + pOffsetEPROCESS->State);
    pdwPID = (PDWORD)(pb + pOffsetEPROCESS->PID);
    pdwDTB = (PDWORD)(pb + pOffsetEPROCESS->DTB);
    pdwDTB_User = (PDWORD)(pb + pOffsetEPROCESS->DTB_User);
    pdwFLink = (PDWORD)(pb + pOffsetEPROCESS->FLink);
    pdwBLink = (PDWORD)(pb + pOffsetEPROCESS->BLink);
    szName = (LPSTR)(pb + pOffsetEPROCESS->Name);
    pdwPEB = (PDWORD)(pb + pOffsetEPROCESS->PEB);
    // prefetch pages into cache (if any)
    pObSetAddressEPROCESS = VmmObContainer_GetOb(&ctxVmm->ObCEPROCESSCachePrefetch);
    VmmCachePrefetchPages(pSystemProcess, pObSetAddressEPROCESS);
    VmmOb_DECREF(pObSetAddressEPROCESS);
    // initialize address set
    if(!(pObSetAddressEPROCESS = VmmObDataSet_Alloc(TRUE))) { return FALSE; }
    VmmObDataSet_Put(pObSetAddressEPROCESS, vaSystemEPROCESS);
    // loop!
    vmmprintfvv_fn("   # STATE  PID      DTB      EPROCESS PEB      NAME  \n");

    for(iProc = 0; iProc < pObSetAddressEPROCESS->c; iProc++) {
        vaEPROCESS = (DWORD)pObSetAddressEPROCESS->pObData->pList[iProc].Value;
        if(!VmmRead(pSystemProcess, vaEPROCESS, pb, pOffsetEPROCESS->cbMaxOffset)) { continue; }
        if(*pdwDTB & 0x1f) { continue; }
        VmmOb_DECREF(pObProcess);
        pObProcess = NULL;
        if(*pdwDTB && *(PQWORD)szName && (fShowTerminated || !*pdwState)) {
            fUser =
                !((*pdwPID == 4) || ((*pdwState == 0) && (*pdwPEB == 0))) ||
                ((*(PQWORD)(szName + 0x00) == 0x72706d6f436d654d) && (*(PDWORD)(szName + 0x08) == 0x69737365)); // MemCompression "process"
            pObProcess = VmmProcessCreateEntry(
                fTotalRefresh,
                *pdwPID,
                *pdwState,
                *pdwDTB & 0xffffffe0,
                pOffsetEPROCESS->DTB_User ? (~0xfff & *pdwDTB_User) : 0,
                szName,
                fUser);
        }
        if(pObProcess) {
            pObProcess->os.win.vaEPROCESS = vaEPROCESS;
            if(*pdwPEB % PAGE_SIZE) {
                vmmprintfv("VMM: WARNING: Bad PEB alignment for PID: '%i' (0x%08x).\n", *pdwPID, *pdwPEB);
            } else {
                pObProcess->os.win.vaPEB = *pdwPEB;
            }
            if(!pObProcess) {
                vmmprintfv("VMM: WARNING: PID '%i' already exists.\n", *pdwPID);
                if(++cNewProcessCollision >= 8) {
                    break;
                }
            }
        } else {
            szName[14] = 0; // in case of bad string data ...
        }
        vmmprintfvv_fn("%04i (%s) %08x %08x %08x %08x %s\n",
            iProc,
            pObProcess ? "list" : "skip",
            *pdwPID,
            *pdwDTB & 0xffffffe0,
            vaEPROCESS,
            *pdwPEB,
            szName);
        // Add FLink & BLink
        if(0x80000000 == (0x80000003 & *pdwFLink)) {
            VmmObDataSet_Put(pObSetAddressEPROCESS, *pdwFLink - pOffsetEPROCESS->FLink);
        }
        if(0x80000000 == (0x80000003 & *pdwBLink)) {
            VmmObDataSet_Put(pObSetAddressEPROCESS, *pdwBLink - pOffsetEPROCESS->FLink);
        }
    }
    VmmObContainer_SetOb(&ctxVmm->ObCEPROCESSCachePrefetch, pObSetAddressEPROCESS);
    VmmOb_DECREF(pObSetAddressEPROCESS);
    VmmOb_DECREF(pObProcess);
    VmmProcessCreateFinish();
    return (iProc > 10);
}

BOOL VmmWin_EnumerateEPROCESS(_In_ PVMM_PROCESS pSystemProcess, _In_ BOOL fRefreshTotal)
{
    // spider TLB and set up initial system process and enumerate EPROCESS
    VmmTlbSpider(pSystemProcess);
    switch(ctxVmm->tpMemoryModel) {
        case VMM_MEMORYMODEL_X64:
            return VmmWin_EnumerateEPROCESS64(pSystemProcess, fRefreshTotal);
        case VMM_MEMORYMODEL_X86:
        case VMM_MEMORYMODEL_X86PAE:
            return VmmWin_EnumerateEPROCESS32(pSystemProcess, fRefreshTotal);
    }
    return FALSE;
}

VOID VmmWin_ModuleMapInitialize(_In_ PVMM_PROCESS pProcess)
{
    VmmWin_InitializeLdrModules(pProcess);
}

VOID VmmWin_ScanTagsMemMap(_In_ PVMM_PROCESS pProcess)
{
    // scan for not already known pe name headers
    VmmWin_ScanHeaderPE(pProcess);
    // scan for heaps
    if(ctxVmm->tpSystem == VMM_SYSTEM_WINDOWS_X64) {
        VmmWin_ScanPebHeap64(pProcess);
        if(pProcess->os.win.fWow64) {
            VmmWin_ScanPebHeap32(pProcess, TRUE);
        }
    }
    if(ctxVmm->tpSystem == VMM_SYSTEM_WINDOWS_X86) {
        VmmWin_ScanPebHeap32(pProcess, FALSE);
    }
}
