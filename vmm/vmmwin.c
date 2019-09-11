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

VOID VmmWin_ScanLdrModules_VSetPutVA(_In_ POB_VSET pObVSet_vaAll, _In_ POB_VSET pObVSet_vaTry1, _In_ QWORD va)
{
    if(!ObVSet_Exists(pObVSet_vaAll, va)) {
        ObVSet_Push(pObVSet_vaAll, va);
        ObVSet_Push(pObVSet_vaTry1, va);
    }
}

VOID VmmWin_ScanLdrModules64(_In_ PVMM_PROCESS pProcess, _Inout_ PVMM_MODULEMAP_ENTRY pModules, _Inout_ PDWORD pcModules, _In_ DWORD cModulesMax, _Out_ PBOOL fWow64)
{
    QWORD vaModuleLdrFirst, vaModuleLdr = 0;
    BYTE pbPEB[sizeof(PEB)], pbPEBLdrData[sizeof(PEB_LDR_DATA)], pbLdrModule[sizeof(VMMPROC_LDR_DATA_TABLE_ENTRY)];
    PPEB pPEB = (PPEB)pbPEB;
    PPEB_LDR_DATA pPEBLdrData = (PPEB_LDR_DATA)pbPEBLdrData;
    PVMMPROC_LDR_DATA_TABLE_ENTRY pLdrModule = (PVMMPROC_LDR_DATA_TABLE_ENTRY)pbLdrModule;
    PVMM_MODULEMAP_ENTRY pModule;
    POB_VSET pObVSet_vaAll = NULL, pObVSet_vaTry1 = NULL, pObVSet_vaTry2 = NULL, pObVSet_vaName = NULL;
    BOOL fNameRead, fNameDefaultChar, fTry1;
    DWORD i, cbReadData;
    // prefetch existing addresses (if any) & allocate new vaModuleLdr VSet
    pObVSet_vaAll = ObContainer_GetOb(pProcess->pObProcessPersistent->pObCLdrModulesCachePrefetch64);
    VmmCachePrefetchPages3(pProcess, pObVSet_vaAll, sizeof(VMMPROC_LDR_DATA_TABLE_ENTRY));
    Ob_DECREF_NULL(&pObVSet_vaAll);
    if(!(pObVSet_vaAll = ObVSet_New())) { goto fail; }
    if(!(pObVSet_vaTry1 = ObVSet_New())) { goto fail; }
    if(!(pObVSet_vaTry2 = ObVSet_New())) { goto fail; }
    if(!(pObVSet_vaName = ObVSet_New())) { goto fail; }
    // set up initial entry in vaModuleLdr DataSet
    *fWow64 = FALSE;
    if(pProcess->fUserOnly) {
        // User mode process -> walk PEB LDR list to enumerate modules / .dlls.
        if(!pProcess->win.vaPEB) { goto fail; }
        if(!VmmRead(pProcess, pProcess->win.vaPEB, pbPEB, sizeof(PEB))) { goto fail; }
        if(!VmmRead(pProcess, (QWORD)pPEB->Ldr, pbPEBLdrData, sizeof(PEB_LDR_DATA))) { goto fail; }
        vaModuleLdrFirst = (QWORD)pPEBLdrData->InMemoryOrderModuleList.Flink - 0x10; // InLoadOrderModuleList == InMemoryOrderModuleList - 0x10
    } else {
        // Kernel mode process -> walk PsLoadedModuleList to enumerate drivers / .sys and .dlls.
        if(!ctxVmm->kernel.vaPsLoadedModuleList) { goto fail; }
        if(!VmmRead(pProcess, ctxVmm->kernel.vaPsLoadedModuleList, (PBYTE)&vaModuleLdrFirst, sizeof(QWORD)) || !vaModuleLdrFirst) { goto fail; }
        if(!VmmRead(pProcess, ctxVmm->kernel.vaPsLoadedModuleList, pbPEBLdrData, sizeof(PEB_LDR_DATA))) { goto fail; }
    }
    ObVSet_Push(pObVSet_vaAll, vaModuleLdrFirst);
    ObVSet_Push(pObVSet_vaTry1, vaModuleLdrFirst);
    // iterate over modules using all available linked lists in an efficient way.
    fTry1 = TRUE;
    vaModuleLdr = 0;
    while(TRUE) {
        if(fTry1) {
            vaModuleLdr = ObVSet_Pop(pObVSet_vaTry1);
            if(!vaModuleLdr && (0 == ObVSet_Size(pObVSet_vaTry2))) { break; }
            if(!vaModuleLdr) {
                VmmCachePrefetchPages3(pProcess, pObVSet_vaAll, sizeof(PEB_LDR_DATA));
                fTry1 = FALSE;
                continue;
            }
            VmmReadEx(pProcess, vaModuleLdr, pbLdrModule, sizeof(VMMPROC_LDR_DATA_TABLE_ENTRY), &cbReadData, VMM_FLAG_FORCECACHE_READ);
            if(cbReadData != sizeof(VMMPROC_LDR_DATA_TABLE_ENTRY)) {
                ObVSet_Push(pObVSet_vaTry2, vaModuleLdr);
                continue;
            }
        } else {
            vaModuleLdr = ObVSet_Pop(pObVSet_vaTry2);
            if(!vaModuleLdr && (0 == ObVSet_Size(pObVSet_vaTry1))) { break; }
            if(!vaModuleLdr) { fTry1 = TRUE; continue; }
            if(!VmmRead(pProcess, vaModuleLdr, pbLdrModule, sizeof(VMMPROC_LDR_DATA_TABLE_ENTRY))) { continue; }
        }
        if(!pLdrModule->BaseAddress || !pLdrModule->SizeOfImage) { continue; }
        pModule = pModules + *pcModules;
        pModule->BaseAddress = (QWORD)pLdrModule->BaseAddress;
        pModule->EntryPoint = (QWORD)pLdrModule->EntryPoint;
        pModule->SizeOfImage = (DWORD)pLdrModule->SizeOfImage;
        pModule->fWoW64 = FALSE;
        if(!pLdrModule->BaseDllName.Length) { continue; }
        pModule->BaseDllName_Buffer = (QWORD)pLdrModule->BaseDllName.Buffer;
        pModule->BaseDllName_Length = pLdrModule->BaseDllName.Length;
        *pcModules = *pcModules + 1;
        // add FLink/BLink lists
        if(pLdrModule->InLoadOrderModuleList.Flink && !((QWORD)pLdrModule->InLoadOrderModuleList.Flink & 0x7)) {
            VmmWin_ScanLdrModules_VSetPutVA(pObVSet_vaAll, pObVSet_vaTry1, (QWORD)CONTAINING_RECORD(pLdrModule->InLoadOrderModuleList.Flink, VMMPROC_LDR_DATA_TABLE_ENTRY, InLoadOrderModuleList));
        }
        if(pLdrModule->InLoadOrderModuleList.Blink && !((QWORD)pLdrModule->InLoadOrderModuleList.Blink & 0x7)) {
            VmmWin_ScanLdrModules_VSetPutVA(pObVSet_vaAll, pObVSet_vaTry1, (QWORD)CONTAINING_RECORD(pLdrModule->InLoadOrderModuleList.Blink, VMMPROC_LDR_DATA_TABLE_ENTRY, InLoadOrderModuleList));
        }
        if(pProcess->fUserOnly) {
            if(pLdrModule->InInitializationOrderModuleList.Flink && !((QWORD)pLdrModule->InInitializationOrderModuleList.Flink & 0x7)) {
                VmmWin_ScanLdrModules_VSetPutVA(pObVSet_vaAll, pObVSet_vaTry1, (QWORD)CONTAINING_RECORD(pLdrModule->InInitializationOrderModuleList.Flink, VMMPROC_LDR_DATA_TABLE_ENTRY, InInitializationOrderModuleList));
            }
            if(pLdrModule->InInitializationOrderModuleList.Blink && !((QWORD)pLdrModule->InInitializationOrderModuleList.Blink & 0x7)) {
                VmmWin_ScanLdrModules_VSetPutVA(pObVSet_vaAll, pObVSet_vaTry1, (QWORD)CONTAINING_RECORD(pLdrModule->InInitializationOrderModuleList.Blink, VMMPROC_LDR_DATA_TABLE_ENTRY, InInitializationOrderModuleList));
            }
            if(pLdrModule->InMemoryOrderModuleList.Flink && !((QWORD)pLdrModule->InMemoryOrderModuleList.Flink & 0x7)) {
                VmmWin_ScanLdrModules_VSetPutVA(pObVSet_vaAll, pObVSet_vaTry1, (QWORD)CONTAINING_RECORD(pLdrModule->InMemoryOrderModuleList.Flink, VMMPROC_LDR_DATA_TABLE_ENTRY, InMemoryOrderModuleList));
            }
            if(pLdrModule->InMemoryOrderModuleList.Blink && !((QWORD)pLdrModule->InMemoryOrderModuleList.Blink & 0x7)) {
                VmmWin_ScanLdrModules_VSetPutVA(pObVSet_vaAll, pObVSet_vaTry1, (QWORD)CONTAINING_RECORD(pLdrModule->InMemoryOrderModuleList.Blink, VMMPROC_LDR_DATA_TABLE_ENTRY, InMemoryOrderModuleList));
            }
        }
        if(*pcModules >= cModulesMax) { break; }
    }
    // fetch module names in an efficient way.
    for(i = 0; i < *pcModules; i++) {
        ObVSet_Push_PageAlign(pObVSet_vaName, pModules[i].BaseDllName_Buffer, 32);
    }
    VmmCachePrefetchPages(pProcess, pObVSet_vaName);
    for(i = 0; i < *pcModules; i++) {
        pModule = pModules + i;
        fNameRead = VmmRead_U2A_RawStr(pProcess, 0, pModule->BaseDllName_Buffer, pModule->BaseDllName_Length, pModule->szName, _countof(pModule->szName), NULL, &fNameDefaultChar) && !fNameDefaultChar;
        fNameRead = fNameRead || PE_GetModuleName(pProcess, pModule->BaseAddress, pModule->szName, 32);
        if(fNameRead) {
            *fWow64 = pProcess->fUserOnly && (*fWow64 || !memcmp(pModule->szName, "wow64.dll", 10));
            vmmprintfvv_fn("%016llx %016llx %08x %i %s\n", pModule->BaseAddress, pModule->EntryPoint, pModule->SizeOfImage, (pModule->fWoW64 ? 1 : 0), pModule->szName);
        } else {
            snprintf(pModule->szName, 31, "_UNKNOWN-%llx.dll", pModule->BaseAddress);
            vmmprintfvv_fn("INFO: Unable to get name - paged out? PID=%04i BASE=0x%016llx REPLACE='%s'\n", pProcess->dwPID, pModule->BaseAddress, pModule->szName);
        }
    }
    // save prefetch addresses (if required)
    if(ctxMain->dev.fRemote && ctxVmm->ThreadProcCache.fEnabled) {
        ObContainer_SetOb(pProcess->pObProcessPersistent->pObCLdrModulesCachePrefetch64, pObVSet_vaAll);
    }
fail:
    Ob_DECREF(pObVSet_vaAll);
    Ob_DECREF(pObVSet_vaTry1);
    Ob_DECREF(pObVSet_vaTry2);
    Ob_DECREF(pObVSet_vaName);
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
    BOOL fResult = FALSE;
    DWORD vaModuleLdrFirst32, vaModuleLdr32 = 0;
    BYTE pbPEB32[sizeof(PEB32)], pbPEBLdrData32[sizeof(PEB_LDR_DATA32)], pbLdrModule32[sizeof(LDR_MODULE32)];
    PPEB32 pPEB32 = (PPEB32)pbPEB32;
    PPEB_LDR_DATA32 pPEBLdrData32 = (PPEB_LDR_DATA32)pbPEBLdrData32;
    PLDR_MODULE32 pLdrModule32 = (PLDR_MODULE32)pbLdrModule32;
    PVMM_MODULEMAP_ENTRY pModule;
    POB_VSET pObVSet_vaAll = NULL, pObVSet_vaTry1 = NULL, pObVSet_vaTry2 = NULL, pObVSet_vaName = NULL;
    BOOL fNameRead, fNameDefaultChar, fTry1;
    DWORD i, cbReadData;
    // prefetch existing addresses (if any) & allocate new vaModuleLdr VSet
    pObVSet_vaAll = ObContainer_GetOb(pProcess->pObProcessPersistent->pObCLdrModulesCachePrefetch32);
    VmmCachePrefetchPages3(pProcess, pObVSet_vaAll, sizeof(LDR_MODULE32));
    Ob_DECREF(pObVSet_vaAll);
    if(!(pObVSet_vaAll = ObVSet_New())) { goto fail; }
    if(!(pObVSet_vaTry1 = ObVSet_New())) { goto fail; }
    if(!(pObVSet_vaTry2 = ObVSet_New())) { goto fail; }
    if(!(pObVSet_vaName = ObVSet_New())) { goto fail; }
    // set up initial entry in vaModuleLdr DataSet
    if(pProcess->fUserOnly) {
        if(!pProcess->win.vaPEB) { goto fail; }
        if(!VmmRead(pProcess, pProcess->win.vaPEB32, pbPEB32, sizeof(PEB32))) { goto fail; }
        if(!VmmRead(pProcess, (DWORD)pPEB32->Ldr, pbPEBLdrData32, sizeof(PEB_LDR_DATA32))) { goto fail; }
        vaModuleLdrFirst32 = (DWORD)pPEBLdrData32->InMemoryOrderModuleList.Flink - 0x08; // InLoadOrderModuleList == InMemoryOrderModuleList - 0x08
    } else if(ctxVmm->tpSystem == VMM_SYSTEM_WINDOWS_X86) {
        // Kernel mode process -> walk PsLoadedModuleList to enumerate drivers / .sys and .dlls.
        if(!ctxVmm->kernel.vaPsLoadedModuleList) { goto fail; }
        if(!VmmRead(pProcess, ctxVmm->kernel.vaPsLoadedModuleList, (PBYTE)&vaModuleLdrFirst32, sizeof(DWORD)) || !vaModuleLdrFirst32) { goto fail; }
        if(!VmmRead(pProcess, ctxVmm->kernel.vaPsLoadedModuleList, pbPEBLdrData32, sizeof(PEB_LDR_DATA32))) { goto fail; }
    } else {
        goto fail;
    }
    ObVSet_Push(pObVSet_vaAll, vaModuleLdrFirst32);
    ObVSet_Push(pObVSet_vaTry1, vaModuleLdrFirst32);
    // iterate over modules using all available linked lists in an efficient way.
    fTry1 = TRUE;
    vaModuleLdr32 = 0;
    while(TRUE) {
        if(fTry1) {
            vaModuleLdr32 = (DWORD)ObVSet_Pop(pObVSet_vaTry1);
            if(!vaModuleLdr32 && (0 == ObVSet_Size(pObVSet_vaTry2))) { break; }
            if(!vaModuleLdr32) {
                VmmCachePrefetchPages3(pProcess, pObVSet_vaAll, sizeof(PEB_LDR_DATA));
                fTry1 = FALSE;
                continue;
            }
            VmmReadEx(pProcess, vaModuleLdr32, pbLdrModule32, sizeof(LDR_MODULE32), &cbReadData, VMM_FLAG_FORCECACHE_READ);
            if(cbReadData != sizeof(VMMPROC_LDR_DATA_TABLE_ENTRY)) {
                ObVSet_Push(pObVSet_vaTry2, vaModuleLdr32);
                continue;
            }
        } else {
            vaModuleLdr32 = (DWORD)ObVSet_Pop(pObVSet_vaTry2);
            if(!vaModuleLdr32 && (0 == ObVSet_Size(pObVSet_vaTry1))) { break; }
            if(!vaModuleLdr32) { fTry1 = TRUE; continue; }
            if(!VmmRead(pProcess, vaModuleLdr32, pbLdrModule32, sizeof(LDR_MODULE32))) { continue; }
        }

        if(!pLdrModule32->BaseAddress || !pLdrModule32->SizeOfImage) { continue; }
        pModule = pModules + *pcModules;
        pModule->BaseAddress = (QWORD)pLdrModule32->BaseAddress;
        pModule->EntryPoint = (QWORD)pLdrModule32->EntryPoint;
        pModule->SizeOfImage = (DWORD)pLdrModule32->SizeOfImage;
        pModule->fWoW64 = TRUE;
        if(!pLdrModule32->BaseDllName.Length) { continue; }
        pModule->BaseDllName_Buffer = (QWORD)pLdrModule32->BaseDllName.Buffer;
        pModule->BaseDllName_Length = pLdrModule32->BaseDllName.Length;
        *pcModules = *pcModules + 1;
        // add FLink/BLink lists
        if(pLdrModule32->InLoadOrderModuleList.Flink && !((DWORD)pLdrModule32->InLoadOrderModuleList.Flink & 0x3)) {
            VmmWin_ScanLdrModules_VSetPutVA(pObVSet_vaAll, pObVSet_vaTry1, (QWORD)CONTAINING_RECORD32(pLdrModule32->InLoadOrderModuleList.Flink, LDR_MODULE32, InLoadOrderModuleList));
        }
        if(pLdrModule32->InLoadOrderModuleList.Blink && !((DWORD)pLdrModule32->InLoadOrderModuleList.Blink & 0x3)) {
            VmmWin_ScanLdrModules_VSetPutVA(pObVSet_vaAll, pObVSet_vaTry1, (QWORD)CONTAINING_RECORD32(pLdrModule32->InLoadOrderModuleList.Blink, LDR_MODULE32, InLoadOrderModuleList));
        }
        if(pProcess->fUserOnly) {
            if(pLdrModule32->InInitializationOrderModuleList.Flink && !((DWORD)pLdrModule32->InInitializationOrderModuleList.Flink & 0x3)) {
                VmmWin_ScanLdrModules_VSetPutVA(pObVSet_vaAll, pObVSet_vaTry1, (QWORD)CONTAINING_RECORD32(pLdrModule32->InInitializationOrderModuleList.Flink, LDR_MODULE32, InInitializationOrderModuleList));
            }
            if(pLdrModule32->InInitializationOrderModuleList.Blink && !((DWORD)pLdrModule32->InInitializationOrderModuleList.Blink & 0x3)) {
                VmmWin_ScanLdrModules_VSetPutVA(pObVSet_vaAll, pObVSet_vaTry1, (QWORD)CONTAINING_RECORD32(pLdrModule32->InInitializationOrderModuleList.Blink, LDR_MODULE32, InInitializationOrderModuleList));
            }
            if(pLdrModule32->InMemoryOrderModuleList.Flink && !((DWORD)pLdrModule32->InMemoryOrderModuleList.Flink & 0x3)) {
                VmmWin_ScanLdrModules_VSetPutVA(pObVSet_vaAll, pObVSet_vaTry1, (QWORD)CONTAINING_RECORD32(pLdrModule32->InMemoryOrderModuleList.Flink, LDR_MODULE32, InMemoryOrderModuleList));
            }
            if(pLdrModule32->InMemoryOrderModuleList.Blink && !((DWORD)pLdrModule32->InMemoryOrderModuleList.Blink & 0x3)) {
                VmmWin_ScanLdrModules_VSetPutVA(pObVSet_vaAll, pObVSet_vaTry1, (QWORD)CONTAINING_RECORD32(pLdrModule32->InMemoryOrderModuleList.Blink, LDR_MODULE32, InMemoryOrderModuleList));
            }
        }
        if(*pcModules >= cModulesMax) { break; }
    }
    // fetch module names in an efficient way.
    for(i = 0; i < *pcModules; i++) {
        ObVSet_Push_PageAlign(pObVSet_vaName, pModules[i].BaseDllName_Buffer, 32);
    }
    VmmCachePrefetchPages(pProcess, pObVSet_vaName);
    for(i = 0; i < *pcModules; i++) {
        pModule = pModules + i;
        fNameRead = VmmRead_U2A_RawStr(pProcess, 0, pModule->BaseDllName_Buffer, pModule->BaseDllName_Length, pModule->szName, _countof(pModule->szName), NULL, &fNameDefaultChar) && !fNameDefaultChar;
        fNameRead = fNameRead || PE_GetModuleName(pProcess, pModule->BaseAddress, pModule->szName, 32);
        if(fNameRead) {
            vmmprintfvv_fn("%08x %08x %08x %s\n", (DWORD)pModule->BaseAddress, (DWORD)pModule->EntryPoint, pModule->SizeOfImage, pModule->szName);
        } else {
            snprintf(pModule->szName, 31, "_UNKNOWN-%llx.dll", pModule->BaseAddress);
            vmmprintfvv_fn("INFO: Unable to get name - paged out? PID=%04i BASE=0x%08x REPLACE='%s'\n", pProcess->dwPID, (DWORD)pModule->BaseAddress, pModule->szName);
        }
    }
    // save prefetch addresses (if required)
    if(ctxMain->dev.fRemote && ctxVmm->ThreadProcCache.fEnabled) {
        ObContainer_SetOb(pProcess->pObProcessPersistent->pObCLdrModulesCachePrefetch64, pObVSet_vaAll);
    }
    fResult = TRUE;
fail:
    Ob_DECREF(pObVSet_vaAll);
    Ob_DECREF(pObVSet_vaTry1);
    Ob_DECREF(pObVSet_vaTry2);
    Ob_DECREF(pObVSet_vaName);
    return fResult;
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
            pProcess->win.vaPEB32 = (DWORD)pProcess->win.vaPEB - 0x1000;
            result = VmmWin_ScanLdrModules32(pProcess, pModules, &cModules, VMMPROCWINDOWS_MAX_MODULES);
            if(!result) {
                pProcess->win.vaPEB32 = (DWORD)pProcess->win.vaPEB + 0x1000;
                result = VmmWin_ScanLdrModules32(pProcess, pModules, &cModules, VMMPROCWINDOWS_MAX_MODULES);
            }
            if(!result) {
                pProcess->win.vaPEB32 = 0;
            }
        }
        if((cModules > 0) && (!pModules[cModules - 1].BaseAddress)) { cModules--; }
        if(!cModules) { goto fail; }
        pProcess->win.vaENTRY = pModules[0].EntryPoint;
        // allocate / set up VmmOb
        pOb = Ob_Alloc('MO', 0, sizeof(VMMOB_MODULEMAP) + cModules * (89ULL + sizeof(VMM_MODULEMAP_ENTRY)), NULL, NULL);
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
        pProcess->win.fWow64 = fWow64;
        pOb->cbDisplay = o;
    } else if(ctxVmm->tpSystem == VMM_SYSTEM_WINDOWS_X86) {
        pProcess->win.vaPEB32 = (DWORD)pProcess->win.vaPEB;
        VmmWin_ScanLdrModules32(pProcess, pModules, &cModules, VMMPROCWINDOWS_MAX_MODULES);
        if((cModules > 0) && (!pModules[cModules - 1].BaseAddress)) { cModules--; }
        pProcess->win.vaENTRY = pModules[0].EntryPoint;
        // allocate / set up VmmOb
        pOb = Ob_Alloc('MO', 0, sizeof(VMMOB_MODULEMAP) + cModules * (89ULL + sizeof(VMM_MODULEMAP_ENTRY)), NULL, NULL);
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
    pProcess->pObModuleMap = Ob_Alloc('MO', LMEM_ZEROINIT, sizeof(VMMOB_MODULEMAP), NULL, NULL); // fValid set to false by default == failed initialization!
    LeaveCriticalSection(&pProcess->LockUpdate);
    LocalFree(pModules);
}

// ----------------------------------------------------------------------------
// USER PROCESS PARAMETERS FUNCTIONALITY BELOW:
// ----------------------------------------------------------------------------

PVMMWIN_USER_PROCESS_PARAMETERS VmmWin_UserProcessParameters_Get(_In_ PVMM_PROCESS pProcess)
{
    BOOL f;
    QWORD vaUserProcessParameters = 0;
    PVMMWIN_USER_PROCESS_PARAMETERS pu = &pProcess->pObProcessPersistent->UserProcessParams;
    if(pu->fProcessed) { return pu; }
    EnterCriticalSection(&pProcess->LockUpdate);
    if(ctxVmm->f32) {
        f = pProcess->win.vaPEB &&
            VmmRead(pProcess, pProcess->win.vaPEB + 0x10, (PBYTE)&vaUserProcessParameters, sizeof(DWORD)) &&
            !(vaUserProcessParameters & 0x80000003);
    } else {
        f = pProcess->win.vaPEB &&
            VmmRead(pProcess, pProcess->win.vaPEB + 0x20, (PBYTE)&vaUserProcessParameters, sizeof(QWORD)) &&
            !(vaUserProcessParameters & 0xffff8000'00000007);
    }
    if(f) {
        if(!VmmRead_U2A_Alloc(pProcess, ctxVmm->f32, 0, vaUserProcessParameters + (ctxVmm->f32 ? 0x038 : 0x060), &pu->szImagePathName, &pu->cchImagePathName, NULL)) { // ImagePathName
            VmmRead_U2A_Alloc(pProcess, ctxVmm->f32, 0, vaUserProcessParameters + (ctxVmm->f32 ? 0x030 : 0x050), &pu->szImagePathName, &pu->cchImagePathName, NULL);   // DllPath (mutually exclusive with ImagePathName?)
        }
        VmmRead_U2A_Alloc(pProcess, ctxVmm->f32, 0, vaUserProcessParameters + (ctxVmm->f32 ? 0x040 : 0x070), &pu->szCommandLine, &pu->cchCommandLine, NULL);           // CommandLine
    }
    pu->fProcessed = TRUE;
    LeaveCriticalSection(&pProcess->LockUpdate);
    return pu;
}

// ----------------------------------------------------------------------------
// HEAP FUNCTIONALITY BELOW:
// ----------------------------------------------------------------------------

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
    if(!pProcess->win.vaPEB) { return; }
    if(!VmmRead(pProcess, pProcess->win.vaPEB, pbPEB, sizeof(PEB))) { return; }
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
    if(!fWow64 && !pProcess->win.vaPEB) { return; }
    if(fWow64 && !pProcess->win.vaPEB32) { return; }
    if(!VmmRead(pProcess, (fWow64 ? pProcess->win.vaPEB32 : pProcess->win.vaPEB), pbPEB, sizeof(PEB32))) { return; }
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
    Ob_DECREF(pObMemMap);
}

// ----------------------------------------------------------------------------
// WINDOWS EPROCESS WALKING FUNCTIONALITY FOR 64/32 BIT BELOW:
// ----------------------------------------------------------------------------

#define VMMPROC_EPROCESS_MAX_SIZE       0x500
#define VMMWIN_EPROCESS_PREFETCH_MAX    0x200

VOID VmmWin_OffsetLocatorEPROCESS_Print()
{
    PVMM_WIN_EPROCESS_OFFSET po = &ctxVmm->kernel.OffsetEPROCESS;
    vmmprintf_fn("OK: %s \n" \
        "    PID:  %03x PPID: %03x STAT: %03x DTB:  %03x DTBU: %03x NAME: %03x PEB:  %03x\n" \
        "    FLnk: %03x BLnk: %03x oMax: %03x SeAu: %03x      \n",
        po->fValid ? "TRUE" :  "FALSE",
        po->PID, po->PPID, po->State, po->DTB, po->DTB_User, po->Name, po->PEB,
        po->FLink, po->BLink, po->cbMaxOffset, po->SeAuditProcessCreationInfo
    );
}

/*
* Very ugly hack that tries to locate some offsets required withn the EPROCESS struct.
*/
VOID VmmWin_OffsetLocatorEPROCESS64(_In_ PVMM_PROCESS pSystemProcess)
{
    BOOL f;
    WORD i, j, cLoopProtect;
    QWORD va1, vaPEB, paPEB;
    BYTE pbSYSTEM[VMMPROC_EPROCESS_MAX_SIZE], pbSMSS[VMMPROC_EPROCESS_MAX_SIZE], pb1[VMMPROC_EPROCESS_MAX_SIZE], pbPage[0x1000];
    BYTE pbZero[0x800];
    QWORD paMax, paDTB_0, paDTB_1;
    PVMM_WIN_EPROCESS_OFFSET poEPROCESS = &ctxVmm->kernel.OffsetEPROCESS;
    ZeroMemory(poEPROCESS, sizeof(VMM_WIN_EPROCESS_OFFSET));
    if(!VmmRead(pSystemProcess, pSystemProcess->win.vaEPROCESS, pbSYSTEM, VMMPROC_EPROCESS_MAX_SIZE)) { return; }
    if(ctxMain->cfg.fVerboseExtra) {
        vmmprintf_fn("SYSTEM DTB: %016llx EPROCESS: %016llx\n", pSystemProcess->paDTB, pSystemProcess->win.vaEPROCESS);
        Util_PrintHexAscii(pbSYSTEM, VMMPROC_EPROCESS_MAX_SIZE, 0);
    }
    // find offset State (static for now)
    if(*(PDWORD)(pbSYSTEM + 0x04)) { return; }
    poEPROCESS->State = 0x04;
    // find offset PML4 (static for now)
    if(pSystemProcess->paDTB != (0xfffffffffffff000 & *(PQWORD)(pbSYSTEM + 0x28))) { return; }
    poEPROCESS->DTB = 0x28;
    // find offset for Name
    for(i = 0, f = FALSE; i < VMMPROC_EPROCESS_MAX_SIZE - 8; i += 8) {
        if(*(PQWORD)(pbSYSTEM + i) == 0x00006D6574737953) {
            poEPROCESS->Name = i;
            f = TRUE;
            break;
        }
    }
    if(!f) { return; }
    // find offset for PID, FLink, BLink (assumed to be following eachother)
    for(i = 0, f = FALSE; i < VMMPROC_EPROCESS_MAX_SIZE - 8; i += 8) {
        if(*(PQWORD)(pbSYSTEM + i) == 4) {
            // PID = correct, this is a candidate
            if(0xffff000000000000 != (0xffff000000000003 & *(PQWORD)(pbSYSTEM + i + 8))) { continue; }    // FLink not valid kernel pointer
            va1 = *(PQWORD)(pbSYSTEM + i + 8) - i - 8;
            f = VmmRead(pSystemProcess, va1, pb1, VMMPROC_EPROCESS_MAX_SIZE);
            if(!f) { continue; }
            f = FALSE;
            if((*(PQWORD)(pb1 + poEPROCESS->Name) != 0x6578652e73736d73) &&    // smss.exe
                (*(PQWORD)(pb1 + poEPROCESS->Name) != 0x7972747369676552) &&   // Registry
                (*(PQWORD)(pb1 + poEPROCESS->Name) != 0x5320657275636553))     // Secure System
            {
                continue;
            }
            if((*(PQWORD)(pb1 + i + 16) - i - 8) != pSystemProcess->win.vaEPROCESS) {
                continue;
            }
            poEPROCESS->PID = i;
            poEPROCESS->FLink = i + 8;
            poEPROCESS->BLink = i + 16;
            f = TRUE;
            break;
        }
    }
    if(!f) { return; }
    // find and read smss.exe
    {
        cLoopProtect = 0;
        memcpy(pbSMSS, pbSYSTEM, VMMPROC_EPROCESS_MAX_SIZE);
        while(++cLoopProtect < 8) {
            va1 = *(PQWORD)(pbSMSS + poEPROCESS->FLink) - poEPROCESS->FLink;
            f = VmmRead(pSystemProcess, va1, pbSMSS, VMMPROC_EPROCESS_MAX_SIZE) &&
                (*(PQWORD)(pbSMSS + poEPROCESS->Name) == 0x6578652e73736d73);
            if(f) { break; }
        }
        if(!f) { return; }
        if(ctxMain->cfg.fVerboseExtra) {
            vmmprintf_fn("EPROCESS smss.exe BELOW:\n");
            Util_PrintHexAscii(pbSMSS, VMMPROC_EPROCESS_MAX_SIZE, 0);
        }
    }
    // find offset for ParentPid (_EPROCESS!InheritedFromUniqueProcessId)
    // (parent pid is assumed to be located between BLink and Name
    {
        for(i = poEPROCESS->BLink; i < poEPROCESS->Name; i += 8) {
            if((*(PQWORD)(pbSYSTEM + i) == 0) && (*(PQWORD)(pbSMSS + i) == 4)) {
                poEPROCESS->PPID = i;
                break;
            }
        }
        if(!poEPROCESS->PPID) { return; }
    }
    // find offset for PEB (in EPROCESS) by comparing SYSTEM and SMSS  [or other process on fail - max 4 tries]
    {
        for(j = 0; j < 4; j++) {
            for(i = 0x280, f = FALSE; i < 0x480; i += 8) {
                if(*(PQWORD)(pbSYSTEM + i)) { continue; }
                vaPEB = *(PQWORD)(pbSMSS + i);
                if(!vaPEB || (vaPEB & 0xffff800000000fff)) { continue; }
                // Verify potential PEB
                if(!VmmVirt2PhysEx(*(PQWORD)(pbSMSS + poEPROCESS->DTB), TRUE, vaPEB, &paPEB)) { continue; }
                if(!VmmReadPage(NULL, paPEB, pbPage)) { continue; }
                if(*(PWORD)pbPage == 0x5a4d) { continue; }  // MZ header -> likely entry point or something not PEB ...
                poEPROCESS->PEB = i;
                f = TRUE;
                break;
            }
            if(f) { break; }
            // failed locating PEB (paging?) -> try next process in EPROCESS list.
            va1 = *(PQWORD)(pbSMSS + poEPROCESS->FLink) - poEPROCESS->FLink;
            if(!VmmRead(pSystemProcess, va1, pbSMSS, VMMPROC_EPROCESS_MAX_SIZE)) { return; }
        }
        if(!f) { return; }
    }
    // find offset for SeAuditProcessCreationInfo by looking at SMSS. offset is
    // located between PEB+0x058 and PEB+0x070 as observed so far. Look at some
    // extra offsets just in case for the future.
    {
        for(i = 0x058 + poEPROCESS->PEB; i < 0x090 + poEPROCESS->PEB; i += 8) {
            va1 = *(PQWORD)(pbSMSS + i);
            f = ((va1 & 0xffff8000'00000007) == 0xffff8000'00000000) &&
                VmmRead(pSystemProcess, va1, pbPage, 0x20) &&
                (*(PQWORD)(pbPage + 0x10) == 0x007600650044005C) && (*(PQWORD)(pbPage + 0x18) == 0x005C006500630069) && // L"\Device\"
                (*(PWORD)(pbPage + 0x00) < MAX_PATH) && (*(PWORD)(pbPage + 0x00) < *(PWORD)(pbPage + 0x02));            // _UNICODE_STRING length
            if(f) { break; }
        }
        if(!f) { return; }
        poEPROCESS->SeAuditProcessCreationInfo = i;
    }
    // find "optional" offset for user cr3/pml4 (post meltdown only)
    // System have an entry pointing to a shadow PML4 which has empty user part
    // smss.exe do not have an entry since it's running as admin ...
    {
        ZeroMemory(pbZero, 0x800);
        paMax = ctxMain->dev.paMax;
        for(i = poEPROCESS->DTB + 8; i < VMMPROC_EPROCESS_MAX_SIZE - 8; i += 8) {
            paDTB_0 = *(PQWORD)(pbSYSTEM + i);
            paDTB_1 = *(PQWORD)(pbSMSS + i);
            f = !(paDTB_1 & ~1) &&
                paDTB_0 &&
                !(paDTB_0 & 0xffe) &&
                (paDTB_0 < paMax) &&
                VmmReadPage(NULL, (paDTB_0 & ~0xfff), pbPage) &&
                !memcmp(pbPage, pbZero, 0x800) &&
                VmmTlbPageTableVerify(pbPage, (paDTB_0 & ~0xfff), TRUE);
            if(f) {
                poEPROCESS->DTB_User = i;
                break;
            }
        }
    }
    poEPROCESS->cbMaxOffset = min(VMMPROC_EPROCESS_MAX_SIZE, 16 + max(max(max(poEPROCESS->State, poEPROCESS->PID), max(poEPROCESS->Name, poEPROCESS->FLink)), max(max(poEPROCESS->DTB_User, poEPROCESS->DTB), max(poEPROCESS->PEB, poEPROCESS->SeAuditProcessCreationInfo))));
    poEPROCESS->fValid = TRUE;
}

/*
* Post-process new process in the "new" process table before they are comitted VmmProcessCreateFinish()
* At this moment "only" the full path and name is retrieved by using 'SeAuditProcessCreationInfo'.
* -- pSystemProcess
*/
VOID VmmWin_EnumerateEPROCESS_PostProcessing(_In_ PVMM_PROCESS pSystemProcess)
{
    BOOL f;
    DWORD i, cch, cAdjust;
    CHAR szBuffer[MAX_PATH];
    LPSTR sz;
    POB_VSET pObPrefetchAddr = NULL;
    PVMM_PROCESS pObProcess = NULL;
    PVMMOB_PROCESS_TABLE ptObCurrent = NULL, ptObNew = NULL;
    PVMMOB_PROCESS_PERSISTENT pProcPers;
    if(!(pObPrefetchAddr = ObVSet_New())) { goto fail; }
    if(!(ptObCurrent = (PVMMOB_PROCESS_TABLE)ObContainer_GetOb(ctxVmm->pObCPROC))) { goto fail; }
    if(!(ptObNew = (PVMMOB_PROCESS_TABLE)ObContainer_GetOb(ptObCurrent->pObCNewPROC))) { goto fail; }
    // 1: Iterate to gather memory locations of "SeAuditProcessCreationInfo" / "kernel path" for new processes
    while((pObProcess = VmmProcessGetNextEx(ptObNew, pObProcess, VMM_FLAG_PROCESS_SHOW_TERMINATED))) {
        if(!pObProcess->pObProcessPersistent->fIsPostProcessingComplete) {
            ObVSet_Push_PageAlign(pObPrefetchAddr, pObProcess->win.vaSeAuditProcessCreationInfo, 540);
        }
    }
    if(0 == ObVSet_Size(pObPrefetchAddr)) { goto fail; }
    VmmCachePrefetchPages(pSystemProcess, pObPrefetchAddr);
    // 2: Fetch "kernel path" and set "long name" for new processes.
    while((pObProcess = VmmProcessGetNextEx(ptObNew, pObProcess, VMM_FLAG_PROCESS_SHOW_TERMINATED))) {
        pProcPers = pObProcess->pObProcessPersistent;
        if(!pProcPers->fIsPostProcessingComplete) {
            pProcPers->fIsPostProcessingComplete = TRUE;
            f = VmmRead_U2A(pSystemProcess, ctxVmm->f32, VMM_FLAG_FORCECACHE_READ, pObProcess->win.vaSeAuditProcessCreationInfo, szBuffer, MAX_PATH, &cch, NULL) &&
                !memcmp(szBuffer, "\\Device\\", 8);
            sz = szBuffer;
            if(f && (cch > _countof(pProcPers->szPathKernel) - 1)) {
                // adjust down to buffer space by cutting away start of string (if required)
                cAdjust = cch + 1 - _countof(pProcPers->szPathKernel);
                cch -= cAdjust;
                sz += cAdjust;
            }
            if(f) {
                memcpy(pProcPers->szPathKernel, sz, cch);
            } else {
                // Fail - use EPROCESS name
                memcpy(pProcPers->szPathKernel, pObProcess->szName, _countof(pObProcess->szName));
                pProcPers->szNameLong = pProcPers->szPathKernel;
                pProcPers->cchNameLong = pProcPers->cchPathKernel = (WORD)strlen(pProcPers->szPathKernel);
                continue;
            }
            pProcPers->cchPathKernel = (WORD)strlen(pProcPers->szPathKernel);
            // locate FullName by skipping to last \ character.
            pProcPers->szNameLong = pProcPers->szPathKernel;
            i = pProcPers->cchPathKernel;
            while(i && (pProcPers->szPathKernel[--i] != '\\')) {
                ;
            }
            pProcPers->cchNameLong = (WORD)(pProcPers->cchPathKernel - i - 1);
            pProcPers->szNameLong = pProcPers->szPathKernel + i + 1;
        }
    }
fail:
    Ob_DECREF(pObProcess);
    Ob_DECREF(pObPrefetchAddr);
    Ob_DECREF(ptObCurrent);
    Ob_DECREF(ptObNew);
}

typedef struct tdVMMWIN_ENUMERATE_EPROCESS_CONTEXT {
    DWORD cProc;
    BOOL fTotalRefresh;
    DWORD cNewProcessCollision;
    POB_VSET pObVSetPrefetchDTB;
} VMMWIN_ENUMERATE_EPROCESS_CONTEXT, *PVMMWIN_ENUMERATE_EPROCESS_CONTEXT;

VOID VmmWin_EnumEPROCESS64_Pre(_In_ PVMM_PROCESS pProcess, _In_opt_ PVMMWIN_ENUMERATE_EPROCESS_CONTEXT ctx, _In_ QWORD va, _In_ PBYTE pb, _In_ DWORD cb, _In_ QWORD vaFLink, _In_ QWORD vaBLink, _In_ POB_VSET pVSetAddress, _Inout_ PBOOL pfValidEntry, _Inout_ PBOOL pfValidFLink, _Inout_ PBOOL pfValidBLink)
{
    if(!ctx || ((va & 0xffff8000'0000000f) != 0xffff8000'00000000)) { return; }
    ObVSet_Push(ctx->pObVSetPrefetchDTB, *(PQWORD)(pb + ctxVmm->kernel.OffsetEPROCESS.DTB) & ~0xfff);
    *pfValidFLink = ((vaFLink & 0xffff8000'00000007) == 0xffff8000'00000000);
    *pfValidBLink = ((vaBLink & 0xffff8000'00000007) == 0xffff8000'00000000);
    *pfValidEntry = *pfValidFLink || *pfValidBLink;
}

BOOL VmmWin_EnumEPROCESS64_Post(_In_ PVMM_PROCESS pSystemProcess, _In_opt_ PVMMWIN_ENUMERATE_EPROCESS_CONTEXT ctx, _In_ QWORD va, _In_ PBYTE pb, _In_ DWORD cb)
{
    PVMM_WIN_EPROCESS_OFFSET po = &ctxVmm->kernel.OffsetEPROCESS;
    PQWORD pqwDTB, pqwDTB_User, pqwPEB;
    PDWORD pdwState, pdwPID, pdwPPID;
    LPSTR szName;
    BOOL fUser;
    PVMM_PROCESS pObProcess = NULL;
    if(!ctx || ((va & 0xffff8000'0000000f) != 0xffff8000'00000000)) { return FALSE; }
    pdwState = (PDWORD)(pb + po->State);
    pdwPID = (PDWORD)(pb + po->PID);
    pdwPPID = (PDWORD)(pb + po->PPID);
    pqwDTB = (PQWORD)(pb + po->DTB);
    pqwDTB_User = (PQWORD)(pb + po->DTB_User);
    szName = (LPSTR)(pb + po->Name);
    pqwPEB = (PQWORD)(pb + po->PEB);
    if(*pqwDTB & 0xffffff00'00000000) { return TRUE; }   // NB! Fail if target system have more than 1TB of memory (unlikely)
    if(ctx->pObVSetPrefetchDTB) {    // prefetch any physical pages in ctx->pObSetPrefetchDTB on 1st run only
        VmmCachePrefetchPages(NULL, ctx->pObVSetPrefetchDTB);
        Ob_DECREF_NULL(&ctx->pObVSetPrefetchDTB);
    }
    if(*pqwDTB && *(PQWORD)szName) {
        fUser =
            !((*pdwPID == 4) || ((*pdwState == 0) && (*pqwPEB == 0))) ||
            ((*(PQWORD)(szName + 0x00) == 0x72706d6f436d654d) && (*(PDWORD)(szName + 0x08) == 0x69737365));     // MemCompression "process"
        pObProcess = VmmProcessCreateEntry(
            ctx->fTotalRefresh,
            *pdwPID,
            *pdwPPID,
            *pdwState,
            ~0xfff & *pqwDTB,
            po->DTB_User ? (~0xfff & *pqwDTB_User) : 0,
            szName,
            fUser);
        if(!pObProcess) {
            vmmprintfv("VMM: WARNING: PID '%i' already exists.\n", *pdwPID);
            if(++ctx->cNewProcessCollision >= 8) {
                return TRUE;
            }
        }
    }
    if(pObProcess) {
        pObProcess->win.vaEPROCESS = va;
        pObProcess->win.vaSeAuditProcessCreationInfo = *(PQWORD)(pb + po->SeAuditProcessCreationInfo);
        if(*pqwPEB % PAGE_SIZE) {
            vmmprintfv("VMM: WARNING: Bad PEB alignment for PID: '%i' (0x%016llx).\n", *pdwPID, *pqwPEB);
        } else {
            pObProcess->win.vaPEB = *pqwPEB;
        }
    } else {
        szName[14] = 0; // in case of bad string data ...
    }
    vmmprintfvv_fn("%04i (%s) %08x %012llx %016llx %012llx %s\n",
        ctx->cProc,
        !pObProcess ? "skip" : (pObProcess->dwState ? "exit" : "list"),
        *pdwPID,
        ~0xfff & *pqwDTB,
        va,
        *pqwPEB,
        szName);
    Ob_DECREF_NULL(&pObProcess);
    ctx->cProc++;
    return TRUE;
}

/*
* Try walk the EPROCESS list in the Windows kernel to enumerate processes into
* the VMM/PROC file system.
* NB! This may be done to refresh an existing PID cache hence migration code.
* -- pSystemProcess
* -- return
*/
BOOL VmmWin_EnumEPROCESS64(_In_ PVMM_PROCESS pSystemProcess, _In_ BOOL fTotalRefresh)
{
    PVMM_WIN_EPROCESS_OFFSET po = &ctxVmm->kernel.OffsetEPROCESS;
    VMMWIN_ENUMERATE_EPROCESS_CONTEXT ctx = { 0 };
    // retrieve offsets
    if(!po->fValid) {
        VmmWin_OffsetLocatorEPROCESS64(pSystemProcess);
        if(!po->fValid || ctxMain->cfg.fVerboseExtra) {
            VmmWin_OffsetLocatorEPROCESS_Print();
        }
        if(!po->fValid) {
            vmmprintf("VmmWin: Unable to locate EPROCESS offsets.\n");
            return FALSE;
        }
    }
    vmmprintfvv_fn("SYSTEM DTB: %016llx EPROCESS: %016llx\n", pSystemProcess->paDTB, pSystemProcess->win.vaEPROCESS);
    // set up context
    ctx.fTotalRefresh = fTotalRefresh;
    if(!(ctx.pObVSetPrefetchDTB = ObVSet_New())) { return FALSE; }
    // traverse EPROCESS linked list
    vmmprintfvv_fn("        # STATE  PID      DTB          EPROCESS         PEB          NAME  \n");
    VmmWin_ListTraversePrefetch(
        pSystemProcess,
        FALSE,
        &ctx,
        pSystemProcess->win.vaEPROCESS,
        ctxVmm->kernel.OffsetEPROCESS.FLink,
        ctxVmm->kernel.OffsetEPROCESS.cbMaxOffset + 0x20,
        VmmWin_EnumEPROCESS64_Pre,
        VmmWin_EnumEPROCESS64_Post,
        ctxVmm->pObCCachePrefetchEPROCESS);
    // set resulting prefetch cache
    Ob_DECREF_NULL(&ctx.pObVSetPrefetchDTB);
    VmmWin_EnumerateEPROCESS_PostProcessing(pSystemProcess);
    VmmProcessCreateFinish();
    return (ctx.cProc > 10);
}

/*
* Very ugly hack that tries to locate some offsets required withn the EPROCESS struct.
*/
VOID VmmWin_OffsetLocatorEPROCESS32(_In_ PVMM_PROCESS pSystemProcess)
{
    BOOL f;
    WORD i, j, cLoopProtect;
    DWORD va1, vaPEB;
    QWORD paPEB;
    BYTE pbSYSTEM[VMMPROC_EPROCESS_MAX_SIZE], pbSMSS[VMMPROC_EPROCESS_MAX_SIZE], pb1[VMMPROC_EPROCESS_MAX_SIZE], pbPage[0x1000];
    PVMM_WIN_EPROCESS_OFFSET poEPROCESS = &ctxVmm->kernel.OffsetEPROCESS;
    ZeroMemory(poEPROCESS, sizeof(VMM_WIN_EPROCESS_OFFSET));
    //BYTE pbZero[0x800]
    //QWORD paMax, paDTB_0, paDTB_1;
    if(!VmmRead(pSystemProcess, pSystemProcess->win.vaEPROCESS, pbSYSTEM, VMMPROC_EPROCESS_MAX_SIZE)) { return; }
    if(ctxMain->cfg.fVerboseExtra) {
        vmmprintf_fn("SYSTEM DTB: %016llx EPROCESS: %016llx\n", pSystemProcess->paDTB, pSystemProcess->win.vaEPROCESS);
        Util_PrintHexAscii(pbSYSTEM, VMMPROC_EPROCESS_MAX_SIZE, 0);
    }
    // find offset State (static for now)
    if(*(PDWORD)(pbSYSTEM + 0x04)) { return; }
    poEPROCESS->State = 0x04;
    // find offset PML4 (static for now)
    poEPROCESS->DTB = 0x18;
    // find offset for Name
    for(i = 0, f = FALSE; i < VMMPROC_EPROCESS_MAX_SIZE - 4; i += 4) {
        if(*(PQWORD)(pbSYSTEM + i) == 0x00006D6574737953) {
            poEPROCESS->Name = i;
            f = TRUE;
            break;
        }
    }
    if(!f) { return; }
    // find offset for PID, FLink, BLink (assumed to be following eachother)
    for(i = 0, f = FALSE; i < VMMPROC_EPROCESS_MAX_SIZE - 4; i += 4) {
        if(*(PDWORD)(pbSYSTEM + i) == 4) {
            // PID = correct, this is a candidate
            if(0x80000000 != (0x80000003 & *(PDWORD)(pbSYSTEM + i + 4))) { continue; }    // FLink not valid kernel pointer
            va1 = *(PDWORD)(pbSYSTEM + i + 4) - i - 4;
            f = VmmRead(pSystemProcess, va1, pb1, VMMPROC_EPROCESS_MAX_SIZE);
            if(!f) { continue; }
            f = FALSE;
            if((*(PQWORD)(pb1 + poEPROCESS->Name) != 0x6578652e73736d73) &&    // smss.exe
                (*(PQWORD)(pb1 + poEPROCESS->Name) != 0x7972747369676552) &&   // Registry
                (*(PQWORD)(pb1 + poEPROCESS->Name) != 0x5320657275636553))     // Secure System
            {
                continue;
            }
            if((*(PDWORD)(pb1 + i + 8) - i - 4) != pSystemProcess->win.vaEPROCESS) {
                continue;
            }
            poEPROCESS->PID = i;
            poEPROCESS->FLink = i + 4;
            poEPROCESS->BLink = i + 8;
            f = TRUE;
            break;
        }
    }
    if(!f) { return; }
    // find and read smss.exe
    {
        cLoopProtect = 0;
        memcpy(pbSMSS, pbSYSTEM, VMMPROC_EPROCESS_MAX_SIZE);
        while(++cLoopProtect < 8) {
            va1 = *(PDWORD)(pbSMSS + poEPROCESS->FLink) - poEPROCESS->FLink;
            f = VmmRead(pSystemProcess, va1, pbSMSS, VMMPROC_EPROCESS_MAX_SIZE) &&
                (*(PQWORD)(pbSMSS + poEPROCESS->Name) == 0x6578652e73736d73);
            if(f) { break; }
        }
        if(!f) { return; }
        if(ctxMain->cfg.fVerboseExtra) {
            vmmprintf_fn("EPROCESS smss.exe BELOW:\n");
            Util_PrintHexAscii(pbSMSS, VMMPROC_EPROCESS_MAX_SIZE, 0);
        }
    }
    // find offset for ParentPid (_EPROCESS!InheritedFromUniqueProcessId)
    // (parent pid is assumed to be located between BLink and Name
    {
        for(i = poEPROCESS->BLink; i < poEPROCESS->Name; i += 4) {
            if((*(PDWORD)(pbSYSTEM + i) == 0) && (*(PDWORD)(pbSMSS + i) == 4)) {
                poEPROCESS->PPID = i;
                break;
            }
        }
        if(!poEPROCESS->PPID) { return; }
    }
    // find offset for PEB (in EPROCESS) by comparing SYSTEM and SMSS  [or other process on fail - max 4 tries]
    {
        for(j = 0; j < 4; j++) {
            for(i = 0x100, f = FALSE; i < 0x240; i += 4) {
                if(*(PDWORD)(pbSYSTEM + i)) { continue; }
                vaPEB = *(PDWORD)(pbSMSS + i);
                if(!vaPEB || (vaPEB & 0x80000fff)) { continue; }
                // Verify potential PEB
                if(!VmmVirt2PhysEx(*(PDWORD)(pbSMSS + poEPROCESS->DTB), TRUE, vaPEB, &paPEB)) { continue; }
                if(!VmmReadPage(NULL, paPEB, pbPage)) { continue; }
                if(*(PWORD)pbPage == 0x5a4d) { continue; }  // MZ header -> likely entry point or something not PEB ...
                poEPROCESS->PEB = i;
                f = TRUE;
                break;
            }
            if(f) { break; }
            // failed locating PEB (paging?) -> try next process in EPROCESS list.
            va1 = *(PDWORD)(pbSMSS + poEPROCESS->FLink) - poEPROCESS->FLink;
            if(!VmmRead(pSystemProcess, va1, pbSMSS, VMMPROC_EPROCESS_MAX_SIZE)) { return; }
        }
        if(!f) { return; }
    }
    // find offset for SeAuditProcessCreationInfo by looking at SMSS. offset is
    // located between PEB+0x044 and PEB+0x04C as observed so far. Look at some
    // extra offsets just in case for the future.
    {
        for(i = 0x044 + poEPROCESS->PEB; i < 0x058 + poEPROCESS->PEB; i += 4) {
            va1 = *(PDWORD)(pbSMSS + i);
            f = ((va1 & 0x80000003) == 0x80000000) &&
                VmmRead(pSystemProcess, va1, pbPage, 0x18) &&
                (*(PQWORD)(pbPage + 0x08) == 0x007600650044005C) && (*(PQWORD)(pbPage + 0x10) == 0x005C006500630069) && // L"\Device\"
                (*(PWORD)(pbPage + 0x00) < MAX_PATH) && (*(PWORD)(pbPage + 0x00) < *(PWORD)(pbPage + 0x02));            // _UNICODE_STRING length
            if(f) { break; }
        }
        if(!f) { return; }
        poEPROCESS->SeAuditProcessCreationInfo = i;
    }
    // DTB_USER not searched for in 32-bit EPROCESS
    poEPROCESS->cbMaxOffset = min(VMMPROC_EPROCESS_MAX_SIZE, 16 + max(max(max(poEPROCESS->State, poEPROCESS->PID), max(poEPROCESS->Name, poEPROCESS->FLink)), max(max(poEPROCESS->DTB_User, poEPROCESS->DTB), max(poEPROCESS->PEB, poEPROCESS->SeAuditProcessCreationInfo))));
    poEPROCESS->fValid = TRUE;
}

VOID VmmWin_EnumEPROCESS32_Pre(_In_ PVMM_PROCESS pProcess, _In_opt_ PVMMWIN_ENUMERATE_EPROCESS_CONTEXT ctx, _In_ QWORD va, _In_ PBYTE pb, _In_ DWORD cb, _In_ QWORD vaFLink, _In_ QWORD vaBLink, _In_ POB_VSET pVSetAddress, _Inout_ PBOOL pfValidEntry, _Inout_ PBOOL pfValidFLink, _Inout_ PBOOL pfValidBLink)
{
    if(!ctx || ((va & 0x80000007) != 0x80000000)) { return; }
    ObVSet_Push(ctx->pObVSetPrefetchDTB, *(PDWORD)(pb + ctxVmm->kernel.OffsetEPROCESS.DTB) & ~0xfff);
    *pfValidFLink = ((vaFLink & 0x80000003) == 0x80000000);
    *pfValidBLink = ((vaBLink & 0x80000003) == 0x80000000);
    *pfValidEntry = *pfValidFLink || *pfValidBLink;
}

BOOL VmmWin_EnumEPROCESS32_Post(_In_ PVMM_PROCESS pSystemProcess, _In_opt_ PVMMWIN_ENUMERATE_EPROCESS_CONTEXT ctx, _In_ QWORD va, _In_ PBYTE pb, _In_ DWORD cb)
{
    PVMM_WIN_EPROCESS_OFFSET po = &ctxVmm->kernel.OffsetEPROCESS;
    PDWORD pdwDTB, pdwDTB_User, pdwPEB;
    PDWORD pdwState, pdwPID, pdwPPID;
    LPSTR szName;
    BOOL fUser;
    PVMM_PROCESS pObProcess = NULL;
    if(!ctx || ((va & 0x80000007) != 0x80000000)) { return FALSE; }
    pdwState = (PDWORD)(pb + po->State);
    pdwPID = (PDWORD)(pb + po->PID);
    pdwPPID = (PDWORD)(pb + po->PPID);
    pdwDTB = (PDWORD)(pb + po->DTB);
    pdwDTB_User = (PDWORD)(pb + po->DTB_User);
    szName = (LPSTR)(pb + po->Name);
    pdwPEB = (PDWORD)(pb + po->PEB);
    if(ctx->pObVSetPrefetchDTB) {    // prefetch any physical pages in ctx->pObSetPrefetchDTB on 1st run only
        VmmCachePrefetchPages(NULL, ctx->pObVSetPrefetchDTB);
        Ob_DECREF_NULL(&ctx->pObVSetPrefetchDTB);
    }
    if(*pdwDTB && *(PQWORD)szName) {
        fUser =
            !((*pdwPID == 4) || ((*pdwState == 0) && (*pdwPEB == 0))) ||
            ((*(PQWORD)(szName + 0x00) == 0x72706d6f436d654d) && (*(PDWORD)(szName + 0x08) == 0x69737365)); // MemCompression "process"
        pObProcess = VmmProcessCreateEntry(
            ctx->fTotalRefresh,
            *pdwPID,
            *pdwPPID,
            *pdwState,
            *pdwDTB & 0xffffffe0,
            po->DTB_User ? (~0xfff & *pdwDTB_User) : 0,
            szName,
            fUser);
        if(!pObProcess) {
            vmmprintfv("VMM: WARNING: PID '%i' already exists.\n", *pdwPID);
            if(++ctx->cNewProcessCollision >= 8) {
                return TRUE;
            }
        }
    }
    if(pObProcess) {
        pObProcess->win.vaEPROCESS = (DWORD)va;
        pObProcess->win.vaSeAuditProcessCreationInfo = *(PDWORD)(pb + po->SeAuditProcessCreationInfo);
        if(*pdwPEB % PAGE_SIZE) {
            vmmprintfv("VMM: WARNING: Bad PEB alignment for PID: '%i' (0x%08x).\n", *pdwPID, *pdwPEB);
        } else {
            pObProcess->win.vaPEB = *pdwPEB;
        }
    } else {
        szName[14] = 0; // in case of bad string data ...
    }
    vmmprintfvv_fn("%04i (%s) %08x %08x %08x %08x %s\n",
        ctx->cProc,
        !pObProcess ? "skip" : (pObProcess->dwState ? "exit" : "list"),
        *pdwPID,
        *pdwDTB & 0xffffffe0,
        (DWORD)va,
        *pdwPEB,
        szName);
    Ob_DECREF_NULL(&pObProcess);
    ctx->cProc++;
    return TRUE;
}

BOOL VmmWin_EnumEPROCESS32(_In_ PVMM_PROCESS pSystemProcess, _In_ BOOL fTotalRefresh)
{
    PVMM_WIN_EPROCESS_OFFSET po = &ctxVmm->kernel.OffsetEPROCESS;
    VMMWIN_ENUMERATE_EPROCESS_CONTEXT ctx = { 0 };
    // retrieve offsets
    if(!po->fValid) {
        VmmWin_OffsetLocatorEPROCESS32(pSystemProcess);
        if(!po->fValid || ctxMain->cfg.fVerboseExtra) {
            VmmWin_OffsetLocatorEPROCESS_Print();
        }
        if(!po->fValid) {
            vmmprintf("VmmWin: Unable to locate EPROCESS offsets.\n");
            return FALSE;
        }
    }
    vmmprintfvv_fn("SYSTEM DTB: %016llx EPROCESS: %08x\n", pSystemProcess->paDTB, (DWORD)pSystemProcess->win.vaEPROCESS);
    // set up context
    ctx.fTotalRefresh = fTotalRefresh;
    if(!(ctx.pObVSetPrefetchDTB = ObVSet_New())) { return FALSE; }
    // traverse EPROCESS linked list
    vmmprintfvv_fn("        # STATE  PID      DTB      EPROCESS PEB      NAME\n");
    VmmWin_ListTraversePrefetch(
        pSystemProcess,
        TRUE,
        &ctx,
        (DWORD)pSystemProcess->win.vaEPROCESS,
        ctxVmm->kernel.OffsetEPROCESS.FLink,
        ctxVmm->kernel.OffsetEPROCESS.cbMaxOffset + 0x20,
        VmmWin_EnumEPROCESS32_Pre,
        VmmWin_EnumEPROCESS32_Post,
        ctxVmm->pObCCachePrefetchEPROCESS);
    // set resulting prefetch cache
    Ob_DECREF_NULL(&ctx.pObVSetPrefetchDTB);
    VmmWin_EnumerateEPROCESS_PostProcessing(pSystemProcess);
    VmmProcessCreateFinish();
    return (ctx.cProc > 10);
}

BOOL VmmWin_EnumerateEPROCESS(_In_ PVMM_PROCESS pSystemProcess, _In_ BOOL fRefreshTotal)
{
    // spider TLB and set up initial system process and enumerate EPROCESS
    VmmTlbSpider(pSystemProcess);
    switch(ctxVmm->tpMemoryModel) {
        case VMM_MEMORYMODEL_X64:
            return VmmWin_EnumEPROCESS64(pSystemProcess, fRefreshTotal);
        case VMM_MEMORYMODEL_X86:
        case VMM_MEMORYMODEL_X86PAE:
            return VmmWin_EnumEPROCESS32(pSystemProcess, fRefreshTotal);
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
        if(pProcess->win.fWow64) {
            VmmWin_ScanPebHeap32(pProcess, TRUE);
        }
    }
    if(ctxVmm->tpSystem == VMM_SYSTEM_WINDOWS_X86) {
        VmmWin_ScanPebHeap32(pProcess, FALSE);
    }
}

// ----------------------------------------------------------------------------
// WINDOWS LIST WALKING FUNCTIONALITY BELOW:
// Walk a Windows Linked List in an efficient way that minimizes the number of
// IO requests to the LeechCore/Device sub-system. This is done by prefetching
// as much as possible before the main functionality is performed. This is done
// by first calling a callback to add additional memory addresses to prefetch
// (pfnCallback_Pre). Then a prefetch into cache is done, and then a callback
// into the main analysis functionality is done (pfnCallback_Post).
// ----------------------------------------------------------------------------

#define VMMWIN_LISTTRAVERSEPREFETCH_LOOPPROTECT_MAX         0x1000

/*
* Walk a windows linked list in an efficient way that minimize IO requests to
* the the device. This is advantageous for latency reasons. The function return
* a set of the addresses used - this may be used to prefetch pages in advance
* if the list should be walked again at a later time.
* The callback function must only return FALSE on severe errors when the list
* should no longer be continued to be walked in the direction.
* CALLER_DECREF: return
* -- pProcess
* -- f32
* -- ctx = ctx to pass along to callback function (if any)
* -- vaDataStart
* -- oListStart = offset (in bytes) to _LIST_ENTRY from vaDataStart
* -- cbData
* -- pfnCallback_Pre = optional callback function to gather additional addresses.
* -- pfnCallback_Post = optional callback function called after all pages fetched into cache.
* -- pContainerPrefetch = optional pointer to a PVMMOBCONTAINER containing a POB_VSET of prefetch addresses to use/update.
*/
VOID VmmWin_ListTraversePrefetch(
    _In_ PVMM_PROCESS pProcess,
    _In_ BOOL f32,
    _In_opt_ PVOID ctx,
    _In_ QWORD vaDataStart,
    _In_ DWORD oListStart,
    _In_ DWORD cbData,
    _In_opt_ VOID(*pfnCallback_Pre)(_In_ PVMM_PROCESS pProcess, _In_opt_ PVOID ctx, _In_ QWORD va, _In_ PBYTE pb, _In_ DWORD cb, _In_ QWORD vaFLink, _In_ QWORD vaBLink, _In_ POB_VSET pVSetAddress, _Inout_ PBOOL pfValidEntry, _Inout_ PBOOL pfValidFLink, _Inout_ PBOOL pfValidBLink),
    _In_opt_ BOOL(*pfnCallback_Post)(_In_ PVMM_PROCESS pProcess, _In_opt_ PVOID ctx, _In_ QWORD va, _In_ PBYTE pb, _In_ DWORD cb),
    _In_opt_ POB_CONTAINER pPrefetchAddressContainer)
{
    QWORD vaData;
    DWORD cbReadData;
    PBYTE pbData = NULL;
    QWORD vaFLink, vaBLink;
    POB_VSET pObVSet_vaAll = NULL, pObVSet_vaTry1 = NULL, pObVSet_vaTry2 = NULL, pObVSet_vaValid = NULL;
    BOOL fValidEntry, fValidFLink, fValidBLink, fTry1;
    // 1: Prefetch any addresses stored in optional address container
    pObVSet_vaAll = ObContainer_GetOb(pPrefetchAddressContainer);
    VmmCachePrefetchPages3(pProcess, pObVSet_vaAll, cbData);
    Ob_DECREF_NULL(&pObVSet_vaAll);
    // 2: Prepare/Allocate and set up initial entry
    if(!(pObVSet_vaAll = ObVSet_New())) { goto fail; }
    if(!(pObVSet_vaTry1 = ObVSet_New())) { goto fail; }
    if(!(pObVSet_vaTry2 = ObVSet_New())) { goto fail; }
    if(!(pObVSet_vaValid = ObVSet_New())) { goto fail; }
    if(!(pbData = LocalAlloc(0, cbData))) { goto fail; }
    ObVSet_Push(pObVSet_vaAll, vaDataStart);
    ObVSet_Push(pObVSet_vaTry1, vaDataStart);
    // 3: Initial list walk
    fTry1 = TRUE;
    while(TRUE) {
        if(fTry1) {
            vaData = ObVSet_Pop(pObVSet_vaTry1);
            if(!vaData && (0 == ObVSet_Size(pObVSet_vaTry2))) { break; }
            if(!vaData) {
                VmmCachePrefetchPages3(pProcess, pObVSet_vaAll, cbData);
                fTry1 = FALSE;
                continue;
            }
            VmmReadEx(pProcess, vaData, pbData, cbData, &cbReadData, VMM_FLAG_FORCECACHE_READ);
            if(cbReadData != cbData) {
                ObVSet_Push(pObVSet_vaTry2, vaData);
                continue;
            }
        } else {
            vaData = ObVSet_Pop(pObVSet_vaTry2);
            if(!vaData && (0 == ObVSet_Size(pObVSet_vaTry1))) { break; }
            if(!vaData) { fTry1 = TRUE; continue; }
            if(!VmmRead(pProcess, vaData, pbData, cbData)) { continue; }
        }
        vaFLink = f32 ? *(PDWORD)(pbData + oListStart + 0) : *(PQWORD)(pbData + oListStart + 0);
        vaBLink = f32 ? *(PDWORD)(pbData + oListStart + 4) : *(PQWORD)(pbData + oListStart + 8);
        if(pfnCallback_Pre) {
            fValidEntry = FALSE; fValidFLink = FALSE; fValidBLink = FALSE;
            pfnCallback_Pre(pProcess, ctx, vaData, pbData, cbData, vaFLink, vaBLink, pObVSet_vaAll, &fValidEntry, &fValidFLink, &fValidBLink);
        } else {
            if(f32) {
                fValidFLink = !(vaFLink & 0x03);
                fValidBLink = !(vaBLink & 0x03);
            } else {
                fValidFLink = !(vaFLink & 0xffff8000'00000007) || ((vaFLink & 0xffff8000'00000007) == 0xffff8000'00000000);
                fValidBLink = !(vaBLink & 0xffff8000'00000007) || ((vaBLink & 0xffff8000'00000007) == 0xffff8000'00000000);
            }
            fValidEntry = fValidFLink || fValidBLink;
        }
        if(fValidEntry) {
            ObVSet_Push(pObVSet_vaValid, vaData);
        }
        vaFLink -= oListStart;
        vaBLink -= oListStart;
        if(fValidFLink && !ObVSet_Exists(pObVSet_vaAll, vaFLink)) {
            ObVSet_Push(pObVSet_vaAll, vaFLink);
            ObVSet_Push(pObVSet_vaTry1, vaFLink);
        }
        if(fValidBLink && !ObVSet_Exists(pObVSet_vaAll, vaBLink)) {
            ObVSet_Push(pObVSet_vaAll, vaBLink);
            ObVSet_Push(pObVSet_vaTry1, vaBLink);
        }
    }
    // 4: Prefetch additional gathered addresses into cache.
    VmmCachePrefetchPages3(pProcess, pObVSet_vaAll, cbData);
    // 5: 2nd main list walk. Call into optional pfnCallback_Post to do the main
    //    processing of the list items.
    if(pfnCallback_Post) {
        while((vaData = ObVSet_Pop(pObVSet_vaValid))) {
            if(VmmRead(pProcess, vaData, pbData, cbData)) {
                pfnCallback_Post(pProcess, ctx, vaData, pbData, cbData);
            }
        }
    }
    // 6: Store/Update the optional container with the newly prefetch addresses (if possible).
    if(pPrefetchAddressContainer) {
        ObContainer_SetOb(pPrefetchAddressContainer, pObVSet_vaAll);
    }
fail:
    // 7: Cleanup
    Ob_DECREF_NULL(&pObVSet_vaAll);
    Ob_DECREF_NULL(&pObVSet_vaTry1);
    Ob_DECREF_NULL(&pObVSet_vaTry2);
    Ob_DECREF_NULL(&pObVSet_vaValid);
    LocalFree(pbData);
}
