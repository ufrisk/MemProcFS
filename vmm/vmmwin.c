// vmmwin.c : implementation related to operating system and process
// parsing of virtual memory. Windows related features only.
//
// (c) Ulf Frisk, 2018-2020
// Author: Ulf Frisk, pcileech@frizk.net
//

#include "vmmwin.h"
#include "vmmwindef.h"
#include "vmmwinreg.h"
#include "vmmproc.h"
#include "util.h"
#include "pdb.h"
#include "pe.h"
#include <sddl.h>
#include <shlwapi.h>
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
    _In_ PVMM_MAP_MODULEENTRY pModule,
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
    if(!(ntHeader64 = VmmWin_GetVerifyHeaderPE(pProcess, pModule->vaBase, pbModuleHeader, &fHdr32))) { return; }
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
                pModule->vaBase + pSectionBase[i].VirtualAddress,
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
    _In_ PVMM_MAP_MODULEENTRY pModule,
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
    if(!(ntHeader64 = VmmWin_GetVerifyHeaderPE(pProcess, pModule->vaBase, pbModuleHeader, &fHdr32))) { return; }
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
                    pModule->vaBase + pDataDirectoryBase[i].VirtualAddress,
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
BOOL VmmWin_PE_LoadEAT_DisplayBuffer(_In_ PVMM_PROCESS pProcess, _In_ PVMM_MAP_MODULEENTRY pModule, _Out_writes_opt_(cEATs) PVMMPROC_WINDOWS_EAT_ENTRY pEATs, _In_ DWORD cEATs, _Out_ PDWORD pcEATs)
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
    if(!(ntHeader64 = VmmWin_GetVerifyHeaderPE(pProcess, pModule->vaBase, pbModuleHeader, &fHdr32))) { goto fail; }
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
    if(!VmmRead(pProcess, pModule->vaBase + oExportDirectory, pbExportDirectory, (DWORD)cbExportDirectory)) { goto fail; }
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
        pEATs[i].vaFunction = pModule->vaBase + vaFunctionOffset;
        strncpy_s(pEATs[i].szFunction, 40, (LPSTR)(pbExportDirectory - oExportDirectory + oName), _TRUNCATE);
    }
    *pcEATs = (DWORD)i;
    LocalFree(pbExportDirectory);
    return TRUE;
fail:
    LocalFree(pbExportDirectory);
    return FALSE;
}

VOID VmmWin_PE_LoadIAT_DisplayBuffer(_In_ PVMM_PROCESS pProcess, _In_ PVMM_MAP_MODULEENTRY pModule, _Out_writes_(*pcIATs) PVMMWIN_IAT_ENTRY pIATs, _In_ DWORD cIATs, _Out_ PDWORD pcIATs)
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
    if(pModule->cbImageSize > 0x02000000) { return; }
    cbModule = pModule->cbImageSize;
    if(!(pbModule = LocalAlloc(LMEM_ZEROINIT, cbModule))) { return; }
    VmmReadEx(pProcess, pModule->vaBase, pbModule, cbModule, &cbRead, 0);
    if(cbRead <= 0x2000) { goto cleanup; }
    // load both 32/64 bit ntHeader (only one will be valid)
    if(!(ntHeader64 = VmmWin_GetVerifyHeaderPE(pProcess, pModule->vaBase, pbModuleHeader, &fHdr32))) { goto cleanup; }
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

VOID VmmWin_PE_SetSizeSectionIATEAT_DisplayBuffer(_In_ PVMM_PROCESS pProcess, _In_ PVMM_MAP_MODULEENTRY pModule)
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
    if(!(pNtHeaders64 = VmmWin_GetVerifyHeaderPE(pProcess, pModule->vaBase, pbModuleHeader, &fHdr32))) {
        LeaveCriticalSection(&pProcess->LockUpdate);
        return;
    }
    // calculate display buffer size of: SECTIONS, EAT, IAT, RawFileSize
    pModule->cbFileSizeRaw = PE_FileRaw_Size(pProcess, pModule->vaBase, pbModuleHeader);
    pModule->cbDisplayBufferSections = PE_SectionGetNumberOfEx(pProcess, pModule->vaBase, pbModuleHeader) * 70;    // each display buffer human readable line == 70 bytes.
    if(!pModule->fLoadedEAT) {
        pModule->cbDisplayBufferEAT = PE_EatGetNumberOfEx(pProcess, pModule->vaBase, pbModuleHeader) * 64;         // each display buffer human readable line == 64 bytes.
        pModule->fLoadedEAT = TRUE;
    }
    if(!pModule->fLoadedIAT) {
        pModule->cbDisplayBufferIAT = PE_IatGetNumberOfEx(pProcess, pModule->vaBase, pbModuleHeader) * 128;        // each display buffer human readable line == 128 bytes.
        pModule->fLoadedIAT = TRUE;
    }
    LeaveCriticalSection(&pProcess->LockUpdate);
}

// ----------------------------------------------------------------------------
// WINDOWS SPECIFIC PROCESS RELATED FUNCTIONALITY BELOW:
//    PEB/LDR USER MODE PARSING CODE (64-bit and 32-bit)
// ----------------------------------------------------------------------------

#define VMMPROCWINDOWS_MAX_MODULES      512

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

typedef struct tdVMMWIN_LDRMODULES_CONTEXT {
    DWORD cchNameTotal;
    DWORD cModules;
    DWORD cModulesMax;
    PVMM_MAP_MODULEENTRY pModules;
    POB_SET psVaName;
} VMMWIN_LDRMODULES_CONTEXT, *PVMMWIN_LDRMODULES_CONTEXT;

VOID VmmWin_InitializeLdrModules_VSetPutVA(_In_ POB_SET pObSet_vaAll, _In_ POB_SET pObSet_vaTry1, _In_ QWORD va)
{
    if(!ObSet_Exists(pObSet_vaAll, va)) {
        ObSet_Push(pObSet_vaAll, va);
        ObSet_Push(pObSet_vaTry1, va);
    }
}

VOID VmmWin_InitializeLdrModules64(_In_ PVMM_PROCESS pProcess, _In_ PVMMWIN_LDRMODULES_CONTEXT ctx)
{
    QWORD vaModuleLdrFirst, vaModuleLdr = 0;
    BYTE pbPEB[sizeof(PEB)], pbPEBLdrData[sizeof(PEB_LDR_DATA)], pbLdrModule[sizeof(VMMPROC_LDR_DATA_TABLE_ENTRY)];
    PPEB pPEB = (PPEB)pbPEB;
    PPEB_LDR_DATA pPEBLdrData = (PPEB_LDR_DATA)pbPEBLdrData;
    PVMMPROC_LDR_DATA_TABLE_ENTRY pLdrModule = (PVMMPROC_LDR_DATA_TABLE_ENTRY)pbLdrModule;
    PVMM_MAP_MODULEENTRY pModule;
    POB_SET pObSet_vaAll = NULL, pObSet_vaTry1 = NULL, pObSet_vaTry2 = NULL;
    BOOL fTry1;
    DWORD cbReadData;
    // prefetch existing addresses (if any) & allocate new vaModuleLdr VSet
    pObSet_vaAll = ObContainer_GetOb(pProcess->pObPersistent->pObCLdrModulesPrefetch64);
    VmmCachePrefetchPages3(pProcess, pObSet_vaAll, sizeof(VMMPROC_LDR_DATA_TABLE_ENTRY), 0);
    Ob_DECREF_NULL(&pObSet_vaAll);
    if(!(pObSet_vaAll = ObSet_New())) { goto fail; }
    if(!(pObSet_vaTry1 = ObSet_New())) { goto fail; }
    if(!(pObSet_vaTry2 = ObSet_New())) { goto fail; }
    // set up initial entry in vaModuleLdr DataSet
    if(pProcess->fUserOnly) {
        // User mode process -> walk PEB LDR list to enumerate modules / .dlls.
        if(!pProcess->win.vaPEB) { goto fail; }
        if(!VmmRead(pProcess, pProcess->win.vaPEB, pbPEB, sizeof(PEB))) { goto fail; }
        if(!VmmRead(pProcess, (QWORD)pPEB->Ldr, pbPEBLdrData, sizeof(PEB_LDR_DATA))) { goto fail; }
        vaModuleLdrFirst = (QWORD)pPEBLdrData->InMemoryOrderModuleList.Flink - 0x10; // InLoadOrderModuleList == InMemoryOrderModuleList - 0x10
    } else {
        // Kernel mode process -> walk PsLoadedModuleList to enumerate drivers / .sys and .dlls.
        if(!ctxVmm->kernel.vaPsLoadedModuleListPtr) { goto fail; }
        if(!VmmRead(pProcess, ctxVmm->kernel.vaPsLoadedModuleListPtr, (PBYTE)&vaModuleLdrFirst, sizeof(QWORD)) || !vaModuleLdrFirst) { goto fail; }
        if(!VmmRead(pProcess, ctxVmm->kernel.vaPsLoadedModuleListPtr, pbPEBLdrData, sizeof(PEB_LDR_DATA))) { goto fail; }
    }
    ObSet_Push(pObSet_vaAll, vaModuleLdrFirst);
    ObSet_Push(pObSet_vaTry1, vaModuleLdrFirst);
    // iterate over modules using all available linked lists in an efficient way.
    fTry1 = TRUE;
    vaModuleLdr = 0;
    while(ctx->cModules < ctx->cModulesMax) {
        if(fTry1) {
            vaModuleLdr = ObSet_Pop(pObSet_vaTry1);
            if(!vaModuleLdr && (0 == ObSet_Size(pObSet_vaTry2))) { break; }
            if(!vaModuleLdr) {
                VmmCachePrefetchPages3(pProcess, pObSet_vaAll, sizeof(PEB_LDR_DATA), 0);
                fTry1 = FALSE;
                continue;
            }
            VmmReadEx(pProcess, vaModuleLdr, pbLdrModule, sizeof(VMMPROC_LDR_DATA_TABLE_ENTRY), &cbReadData, VMM_FLAG_FORCECACHE_READ);
            if(cbReadData != sizeof(VMMPROC_LDR_DATA_TABLE_ENTRY)) {
                ObSet_Push(pObSet_vaTry2, vaModuleLdr);
                continue;
            }
        } else {
            vaModuleLdr = ObSet_Pop(pObSet_vaTry2);
            if(!vaModuleLdr && (0 == ObSet_Size(pObSet_vaTry1))) { break; }
            if(!vaModuleLdr) { fTry1 = TRUE; continue; }
            if(!VmmRead(pProcess, vaModuleLdr, pbLdrModule, sizeof(VMMPROC_LDR_DATA_TABLE_ENTRY))) { continue; }
        }
        if(!pLdrModule->BaseAddress || !pLdrModule->SizeOfImage) { continue; }
        pModule = ctx->pModules + ctx->cModules;
        if(!pLdrModule->BaseDllName.Length) { continue; }
        pModule->vaBase = (QWORD)pLdrModule->BaseAddress;
        pModule->vaEntry = (QWORD)pLdrModule->EntryPoint;
        pModule->cbImageSize = (DWORD)pLdrModule->SizeOfImage;
        pModule->fWoW64 = FALSE;
        pModule->cwszText = min(MAX_PATH - 1, pLdrModule->BaseDllName.Length);
        ctx->cchNameTotal += max(12, 1 + pModule->cwszText);
        pModule->_Reserved1 = ((QWORD)pLdrModule->BaseDllName.Buffer) + pLdrModule->BaseDllName.Length - pModule->cwszText;
        ObSet_Push(ctx->psVaName, pModule->_Reserved1);
        ctx->cModules = ctx->cModules + 1;
        // add FLink/BLink lists
        if(pLdrModule->InLoadOrderModuleList.Flink && !((QWORD)pLdrModule->InLoadOrderModuleList.Flink & 0x7)) {
            VmmWin_InitializeLdrModules_VSetPutVA(pObSet_vaAll, pObSet_vaTry1, (QWORD)CONTAINING_RECORD(pLdrModule->InLoadOrderModuleList.Flink, VMMPROC_LDR_DATA_TABLE_ENTRY, InLoadOrderModuleList));
        }
        if(pLdrModule->InLoadOrderModuleList.Blink && !((QWORD)pLdrModule->InLoadOrderModuleList.Blink & 0x7)) {
            VmmWin_InitializeLdrModules_VSetPutVA(pObSet_vaAll, pObSet_vaTry1, (QWORD)CONTAINING_RECORD(pLdrModule->InLoadOrderModuleList.Blink, VMMPROC_LDR_DATA_TABLE_ENTRY, InLoadOrderModuleList));
        }
        if(pProcess->fUserOnly) {
            if(pLdrModule->InInitializationOrderModuleList.Flink && !((QWORD)pLdrModule->InInitializationOrderModuleList.Flink & 0x7)) {
                VmmWin_InitializeLdrModules_VSetPutVA(pObSet_vaAll, pObSet_vaTry1, (QWORD)CONTAINING_RECORD(pLdrModule->InInitializationOrderModuleList.Flink, VMMPROC_LDR_DATA_TABLE_ENTRY, InInitializationOrderModuleList));
            }
            if(pLdrModule->InInitializationOrderModuleList.Blink && !((QWORD)pLdrModule->InInitializationOrderModuleList.Blink & 0x7)) {
                VmmWin_InitializeLdrModules_VSetPutVA(pObSet_vaAll, pObSet_vaTry1, (QWORD)CONTAINING_RECORD(pLdrModule->InInitializationOrderModuleList.Blink, VMMPROC_LDR_DATA_TABLE_ENTRY, InInitializationOrderModuleList));
            }
            if(pLdrModule->InMemoryOrderModuleList.Flink && !((QWORD)pLdrModule->InMemoryOrderModuleList.Flink & 0x7)) {
                VmmWin_InitializeLdrModules_VSetPutVA(pObSet_vaAll, pObSet_vaTry1, (QWORD)CONTAINING_RECORD(pLdrModule->InMemoryOrderModuleList.Flink, VMMPROC_LDR_DATA_TABLE_ENTRY, InMemoryOrderModuleList));
            }
            if(pLdrModule->InMemoryOrderModuleList.Blink && !((QWORD)pLdrModule->InMemoryOrderModuleList.Blink & 0x7)) {
                VmmWin_InitializeLdrModules_VSetPutVA(pObSet_vaAll, pObSet_vaTry1, (QWORD)CONTAINING_RECORD(pLdrModule->InMemoryOrderModuleList.Blink, VMMPROC_LDR_DATA_TABLE_ENTRY, InMemoryOrderModuleList));
            }
        }
    }
    // save prefetch addresses (if desirable)
    if(ctxMain->dev.fVolatile && ctxVmm->ThreadProcCache.fEnabled) {
        ObContainer_SetOb(pProcess->pObPersistent->pObCLdrModulesPrefetch64, pObSet_vaAll);
    }
fail:
    Ob_DECREF(pObSet_vaAll);
    Ob_DECREF(pObSet_vaTry1);
    Ob_DECREF(pObSet_vaTry2);
}

VOID VmmWin_InitializeLdrModules32(_In_ PVMM_PROCESS pProcess, _In_ PVMMWIN_LDRMODULES_CONTEXT ctx)
{
    DWORD vaModuleLdrFirst32, vaModuleLdr32 = 0;
    BYTE pbPEB32[sizeof(PEB32)], pbPEBLdrData32[sizeof(PEB_LDR_DATA32)], pbLdrModule32[sizeof(LDR_MODULE32)];
    PPEB32 pPEB32 = (PPEB32)pbPEB32;
    PPEB_LDR_DATA32 pPEBLdrData32 = (PPEB_LDR_DATA32)pbPEBLdrData32;
    PLDR_MODULE32 pLdrModule32 = (PLDR_MODULE32)pbLdrModule32;
    PVMM_MAP_MODULEENTRY pModule;
    POB_SET pObSet_vaAll = NULL, pObSet_vaTry1 = NULL, pObSet_vaTry2 = NULL;
    BOOL fTry1;
    DWORD cbReadData;
    // prefetch existing addresses (if any) & allocate new vaModuleLdr VSet
    pObSet_vaAll = ObContainer_GetOb(pProcess->pObPersistent->pObCLdrModulesPrefetch32);
    VmmCachePrefetchPages3(pProcess, pObSet_vaAll, sizeof(LDR_MODULE32), 0);
    Ob_DECREF(pObSet_vaAll);
    if(!(pObSet_vaAll = ObSet_New())) { goto fail; }
    if(!(pObSet_vaTry1 = ObSet_New())) { goto fail; }
    if(!(pObSet_vaTry2 = ObSet_New())) { goto fail; }
    // set up initial entry in vaModuleLdr DataSet
    if(pProcess->fUserOnly) {
        if(!pProcess->win.vaPEB32) { goto fail; }
        if(!VmmRead(pProcess, pProcess->win.vaPEB32, pbPEB32, sizeof(PEB32))) { goto fail; }
        if(!VmmRead(pProcess, (DWORD)pPEB32->Ldr, pbPEBLdrData32, sizeof(PEB_LDR_DATA32))) { goto fail; }
        vaModuleLdrFirst32 = (DWORD)pPEBLdrData32->InMemoryOrderModuleList.Flink - 0x08; // InLoadOrderModuleList == InMemoryOrderModuleList - 0x08
    } else if(ctxVmm->tpSystem == VMM_SYSTEM_WINDOWS_X86) {
        // Kernel mode process -> walk PsLoadedModuleList to enumerate drivers / .sys and .dlls.
        if(!ctxVmm->kernel.vaPsLoadedModuleListPtr) { goto fail; }
        if(!VmmRead(pProcess, ctxVmm->kernel.vaPsLoadedModuleListPtr, (PBYTE)&vaModuleLdrFirst32, sizeof(DWORD)) || !vaModuleLdrFirst32) { goto fail; }
        if(!VmmRead(pProcess, ctxVmm->kernel.vaPsLoadedModuleListPtr, pbPEBLdrData32, sizeof(PEB_LDR_DATA32))) { goto fail; }
    } else {
        goto fail;
    }
    ObSet_Push(pObSet_vaAll, vaModuleLdrFirst32);
    ObSet_Push(pObSet_vaTry1, vaModuleLdrFirst32);
    // iterate over modules using all available linked lists in an efficient way.
    fTry1 = TRUE;
    vaModuleLdr32 = 0;
    while(ctx->cModules < ctx->cModulesMax) {
        if(fTry1) {
            vaModuleLdr32 = (DWORD)ObSet_Pop(pObSet_vaTry1);
            if(!vaModuleLdr32 && (0 == ObSet_Size(pObSet_vaTry2))) { break; }
            if(!vaModuleLdr32) {
                VmmCachePrefetchPages3(pProcess, pObSet_vaAll, sizeof(PEB_LDR_DATA), 0);
                fTry1 = FALSE;
                continue;
            }
            VmmReadEx(pProcess, vaModuleLdr32, pbLdrModule32, sizeof(LDR_MODULE32), &cbReadData, VMM_FLAG_FORCECACHE_READ);
            if(cbReadData != sizeof(VMMPROC_LDR_DATA_TABLE_ENTRY)) {
                ObSet_Push(pObSet_vaTry2, vaModuleLdr32);
                continue;
            }
        } else {
            vaModuleLdr32 = (DWORD)ObSet_Pop(pObSet_vaTry2);
            if(!vaModuleLdr32 && (0 == ObSet_Size(pObSet_vaTry1))) { break; }
            if(!vaModuleLdr32) { fTry1 = TRUE; continue; }
            if(!VmmRead(pProcess, vaModuleLdr32, pbLdrModule32, sizeof(LDR_MODULE32))) { continue; }
        }
        if(!pLdrModule32->BaseAddress || !pLdrModule32->SizeOfImage) { continue; }
        if(pProcess->win.fWow64 && (pLdrModule32->BaseAddress == ctx->pModules[0].vaBase)) {
            // WOW64 only: 32-bit main exeutable (.exe) shows up in both 32-bit and
            //             64-bit views in WOW64-processes.
            //             -> convert the 1st entry to a correct WoW64 (32-bit) entry.
            ctx->pModules[0].fWoW64 = TRUE;
        } else {
            pModule = ctx->pModules + ctx->cModules;
            if(!pLdrModule32->BaseDllName.Length) { continue; }
            pModule->vaBase = (QWORD)pLdrModule32->BaseAddress;
            pModule->vaEntry = (QWORD)pLdrModule32->EntryPoint;
            pModule->cbImageSize = (DWORD)pLdrModule32->SizeOfImage;
            pModule->fWoW64 = pProcess->win.fWow64;
            pModule->cwszText = min(MAX_PATH - 1, pLdrModule32->BaseDllName.Length);
            ctx->cchNameTotal += max(12, 1 + pModule->cwszText);
            pModule->_Reserved1 = ((QWORD)pLdrModule32->BaseDllName.Buffer) + pLdrModule32->BaseDllName.Length - pModule->cwszText;
            ObSet_Push(ctx->psVaName, pModule->_Reserved1);
            ctx->cModules = ctx->cModules + 1;
        }
        // add FLink/BLink lists
        if(pLdrModule32->InLoadOrderModuleList.Flink && !((DWORD)pLdrModule32->InLoadOrderModuleList.Flink & 0x3)) {
            VmmWin_InitializeLdrModules_VSetPutVA(pObSet_vaAll, pObSet_vaTry1, (QWORD)CONTAINING_RECORD32(pLdrModule32->InLoadOrderModuleList.Flink, LDR_MODULE32, InLoadOrderModuleList));
        }
        if(pLdrModule32->InLoadOrderModuleList.Blink && !((DWORD)pLdrModule32->InLoadOrderModuleList.Blink & 0x3)) {
            VmmWin_InitializeLdrModules_VSetPutVA(pObSet_vaAll, pObSet_vaTry1, (QWORD)CONTAINING_RECORD32(pLdrModule32->InLoadOrderModuleList.Blink, LDR_MODULE32, InLoadOrderModuleList));
        }
        if(pProcess->fUserOnly) {
            if(pLdrModule32->InInitializationOrderModuleList.Flink && !((DWORD)pLdrModule32->InInitializationOrderModuleList.Flink & 0x3)) {
                VmmWin_InitializeLdrModules_VSetPutVA(pObSet_vaAll, pObSet_vaTry1, (QWORD)CONTAINING_RECORD32(pLdrModule32->InInitializationOrderModuleList.Flink, LDR_MODULE32, InInitializationOrderModuleList));
            }
            if(pLdrModule32->InInitializationOrderModuleList.Blink && !((DWORD)pLdrModule32->InInitializationOrderModuleList.Blink & 0x3)) {
                VmmWin_InitializeLdrModules_VSetPutVA(pObSet_vaAll, pObSet_vaTry1, (QWORD)CONTAINING_RECORD32(pLdrModule32->InInitializationOrderModuleList.Blink, LDR_MODULE32, InInitializationOrderModuleList));
            }
            if(pLdrModule32->InMemoryOrderModuleList.Flink && !((DWORD)pLdrModule32->InMemoryOrderModuleList.Flink & 0x3)) {
                VmmWin_InitializeLdrModules_VSetPutVA(pObSet_vaAll, pObSet_vaTry1, (QWORD)CONTAINING_RECORD32(pLdrModule32->InMemoryOrderModuleList.Flink, LDR_MODULE32, InMemoryOrderModuleList));
            }
            if(pLdrModule32->InMemoryOrderModuleList.Blink && !((DWORD)pLdrModule32->InMemoryOrderModuleList.Blink & 0x3)) {
                VmmWin_InitializeLdrModules_VSetPutVA(pObSet_vaAll, pObSet_vaTry1, (QWORD)CONTAINING_RECORD32(pLdrModule32->InMemoryOrderModuleList.Blink, LDR_MODULE32, InMemoryOrderModuleList));
            }
        }
    }
    // save prefetch addresses (if desirable)
    if(ctxMain->dev.fVolatile && ctxVmm->ThreadProcCache.fEnabled) {
        ObContainer_SetOb(pProcess->pObPersistent->pObCLdrModulesPrefetch64, pObSet_vaAll);
    }
fail:
    Ob_DECREF(pObSet_vaAll);
    Ob_DECREF(pObSet_vaTry1);
    Ob_DECREF(pObSet_vaTry2);
}

VOID VmmWin_InitializeLdrModules_Name(_In_ PVMM_PROCESS pProcess, _In_ PVMMOB_MAP_MODULE pModuleMap)
{
    QWORD i;
    DWORD cUnknown = 0, oText = 1;
    PVMM_MAP_MODULEENTRY pe;
    CHAR szBuffer[MAX_PATH] = { 0 };
    WCHAR wszBuffer[MAX_PATH] = { 0 };
    for(i = 0; i < pModuleMap->cMap; i++) {
        pe = pModuleMap->pMap + i;
        if(VmmRead2(pProcess, pe->_Reserved1, (PBYTE)wszBuffer, pe->cwszText << 1, VMM_FLAG_FORCECACHE_READ)) {
            pe->wszText = pModuleMap->wszMultiText + oText;
            pe->cwszText = Util_PathFileNameFixW(pModuleMap->wszMultiText + oText, wszBuffer, pe->cwszText);
            oText += pe->cwszText + 1;
        }
    }
    for(i = 0; i < pModuleMap->cMap; i++) {
        pe = pModuleMap->pMap + i;
        if(!pe->wszText) {
            if(PE_GetModuleName(pProcess, pe->vaBase, szBuffer, MAX_PATH - 1)) {
                pe->wszText = pModuleMap->wszMultiText + oText;
                pe->cwszText = Util_PathFileNameFixA(pModuleMap->wszMultiText + oText, szBuffer, pe->cwszText);
                oText += pe->cwszText + 1;
            } else {
                pe->wszText = pModuleMap->wszMultiText + oText;
                pe->cwszText = swprintf_s(pModuleMap->wszMultiText + oText, 12, L"_NA-%x.dll", ++cUnknown);
                oText += pe->cwszText + 1;
            }
        }
        pModuleMap->pHashTableLookup[i] = (i << 32) | Util_HashStringUpperW(pe->wszText);

    }
    if(ctxMain->cfg.fVerboseExtra) {
        for(i = 0; i < pModuleMap->cMap; i++) {
            pe = pModuleMap->pMap + i;
            vmmprintfvv_fn("%016llx %016llx %08x %i %S\n", pe->vaBase, pe->vaEntry, pe->cbImageSize, (pe->fWoW64 ? 1 : 0), pe->wszText);
        }
    }
}

int VmmWin_InitializeLdrModules_CmpSort(PDWORD pdw1, PDWORD pdw2)
{
    return
        (*pdw1 < *pdw2) ? -1 :
        (*pdw1 > *pdw2) ? 1 : 0;
}

/*
* Initialize the module map containing information about loaded modules in the
* system. This is performed by a PEB/Ldr walk/scan of in-process memory
* structures. This may be unreliable if a process is obfuscated or tampered.
* -- pProcess
* -- return
*/
_Success_(return)
BOOL VmmWin_InitializeLdrModules(_In_ PVMM_PROCESS pProcess)
{
    DWORD cbObMap;
    PVMMOB_MAP_MODULE pObMap = NULL;
    VMMWIN_LDRMODULES_CONTEXT ctx = { 0 };
    if(pProcess->Map.pObModule) { return TRUE; }
    VmmTlbSpider(pProcess);
    EnterCriticalSection(&pProcess->LockUpdate);
    if(pProcess->Map.pObModule) {
        LeaveCriticalSection(&pProcess->LockUpdate);
        return TRUE;
    }
    // set up ctx
    ctx.cchNameTotal = 1;
    ctx.cModulesMax = VMMPROCWINDOWS_MAX_MODULES;
    if(!(ctx.psVaName = ObSet_New())) { goto fail; }
    if(!(ctx.pModules = (PVMM_MAP_MODULEENTRY)LocalAlloc(LMEM_ZEROINIT, VMMPROCWINDOWS_MAX_MODULES * sizeof(VMM_MAP_MODULEENTRY)))) { goto fail; }
    // fetch modules
    if(ctxVmm->tpSystem == VMM_SYSTEM_WINDOWS_X64) {
        VmmWin_InitializeLdrModules64(pProcess, &ctx);
    }
    if((ctxVmm->tpSystem == VMM_SYSTEM_WINDOWS_X86) || ((ctxVmm->tpSystem == VMM_SYSTEM_WINDOWS_X64) && pProcess->win.fWow64)) {
        VmmWin_InitializeLdrModules32(pProcess, &ctx);
    }
    // set up module map object
    cbObMap = sizeof(VMMOB_MAP_MODULE) + ctx.cModules * (sizeof(VMM_MAP_MODULEENTRY) + sizeof(QWORD)) + ctx.cchNameTotal * sizeof(WCHAR);
    if(!(pObMap = Ob_Alloc(OB_TAG_MAP_MODULE, LMEM_ZEROINIT, cbObMap, NULL, NULL))) { goto fail; }
    pObMap->pHashTableLookup = (PQWORD)(((PBYTE)pObMap) + sizeof(VMMOB_MAP_MODULE) + ctx.cModules * sizeof(VMM_MAP_MODULEENTRY));
    pObMap->wszMultiText = (LPWSTR)(((PBYTE)pObMap) + sizeof(VMMOB_MAP_MODULE) + ctx.cModules * (sizeof(VMM_MAP_MODULEENTRY) + sizeof(QWORD)));
    pObMap->cbMultiText = ctx.cchNameTotal * sizeof(WCHAR);
    pObMap->cMap = ctx.cModules;
    memcpy(pObMap->pMap, ctx.pModules, ctx.cModules * sizeof(VMM_MAP_MODULEENTRY));
    // fetch module names
    VmmCachePrefetchPages3(pProcess, ctx.psVaName, MAX_PATH << 1, 0);
    VmmWin_InitializeLdrModules_Name(pProcess, pObMap);
    // finish set-up
    qsort(pObMap->pHashTableLookup, pObMap->cMap, sizeof(QWORD), (int(*)(const void*, const void*))VmmWin_InitializeLdrModules_CmpSort);
    pProcess->Map.pObModule = pObMap;
fail:
    if(!pProcess->Map.pObModule) {
        // try set up zero-sized module map on fail
        pObMap = Ob_Alloc(OB_TAG_MAP_MODULE, LMEM_ZEROINIT, sizeof(VMMOB_MAP_MODULE) + 2, NULL, NULL);
        pObMap->wszMultiText = (LPWSTR)pObMap->pMap;
        pObMap->pHashTableLookup = (PQWORD)pObMap->pMap;
        pProcess->Map.pObModule = pObMap;
    }
    LeaveCriticalSection(&pProcess->LockUpdate);
    Ob_DECREF(ctx.psVaName);
    LocalFree(ctx.pModules);
    return pProcess->Map.pObModule ? TRUE : FALSE;
}

// ----------------------------------------------------------------------------
// USER PROCESS PARAMETERS FUNCTIONALITY BELOW:
// ----------------------------------------------------------------------------

PVMMWIN_USER_PROCESS_PARAMETERS VmmWin_UserProcessParameters_Get(_In_ PVMM_PROCESS pProcess)
{
    BOOL f;
    QWORD vaUserProcessParameters = 0;
    PVMMWIN_USER_PROCESS_PARAMETERS pu = &pProcess->pObPersistent->UserProcessParams;
    if(pu->fProcessed || pProcess->dwState) { return pu; }
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
        if(!VmmReadAllocUnicodeString(pProcess, ctxVmm->f32, 0, vaUserProcessParameters + (ctxVmm->f32 ? 0x038 : 0x060), 0x400, &pu->wszImagePathName, &pu->cchImagePathName)) {    // ImagePathName
            VmmReadAllocUnicodeString(pProcess, ctxVmm->f32, 0, vaUserProcessParameters + (ctxVmm->f32 ? 0x030 : 0x050), 0x400, &pu->wszImagePathName, &pu->cchImagePathName);      // DllPath (mutually exclusive with ImagePathName?)
        }
        VmmReadAllocUnicodeString(pProcess, ctxVmm->f32, 0, vaUserProcessParameters + (ctxVmm->f32 ? 0x040 : 0x070), 0x800, &pu->wszCommandLine, &pu->cchCommandLine);              // CommandLine
        if(pu->wszImagePathName) {
            pu->szImagePathName = Util_StrDupW2A(pu->wszImagePathName);
        }
        if(pu->wszCommandLine) {
            pu->szCommandLine = Util_StrDupW2A(pu->wszCommandLine);
        }
    }
    pu->fProcessed = TRUE;
    LeaveCriticalSection(&pProcess->LockUpdate);
    return pu;
}

// ----------------------------------------------------------------------------
// PTE MAP FUNCTIONALITY BELOW:
//
// Memory Maps based on hardware page tables (PTE MAP) is generated by the
// virtual memory sub-system be waking the hardware page tables. The generated
// pte map does initially not contain information about loaded modules but may
// be enriched with this information by calling VmmWin_InitializePteMapText().
// Module names will be inserted from:
// 1) the module map
// 2) if not found in (1) and suitable pte signature by PE header peek.
// ----------------------------------------------------------------------------

typedef struct tdVMMWIN_INITIALIZEPTEMAP_CONTEXT {
    LPWSTR wsz;
    QWORD cwsz;
    QWORD cwszMax;
} VMMWIN_INITIALIZEPTEMAP_CONTEXT, *PVMMWIN_INITIALIZEPTEMAP_CONTEXT;

/*
* Map a tag into the sorted memory map in O(log2) operations. Supply only one of szTag or wszTag.
* -- pProcess
* -- ctx
* -- vaBase
* -- vaLimit = limit == vaBase + size (== top address in range +1)
* -- szTag
* -- wszTag
* -- fWoW64
*/
VOID VmmWin_InitializePteMapText_MapTag(_In_ PVMM_PROCESS pProcess, _In_ PVMMWIN_INITIALIZEPTEMAP_CONTEXT ctx, _In_ QWORD vaBase, _In_ QWORD vaLimit, _In_opt_z_ LPSTR szTag, _In_opt_z_ LPWSTR wszTag, _In_ BOOL fWoW64)
{
    PVMM_MAP_PTEENTRY pMap;
    QWORD i, lvl, cMap, cwszTag, cwszBufCount;
    BOOL fTagWrite = FALSE;
    pMap = pProcess->Map.pObPte->pMap;
    cMap = pProcess->Map.pObPte->cMap;
    if(!pMap || !cMap) { return; }
    // 1: locate base
    lvl = 1;
    i = cMap >> lvl;
    while(TRUE) {
        lvl++;
        if((cMap >> lvl) == 0) {
            break;
        }
        if(pMap[i].vaBase > vaBase) {
            i -= (cMap >> lvl);
        } else {
            i += (cMap >> lvl);
        }
    }
    // 2: scan back if needed
    while(i && (pMap[i].vaBase > vaBase)) {
        i--;
    }
    // 3.1: fill in tag
    cwszBufCount = ctx->cwszMax - ctx->cwsz;
    if(szTag) {
        cwszTag = _snwprintf_s(ctx->wsz + ctx->cwsz, cwszBufCount, cwszBufCount, L"%S", szTag);
    } else {
        cwszTag = _snwprintf_s(ctx->wsz + ctx->cwsz, cwszBufCount, cwszBufCount, L"%s", wszTag);
    }
    for(; i < cMap; i++) {
        if(pMap[i].vaBase >= vaLimit) { break; }                              // outside scope
        if(pMap[i].vaBase + (pMap[i].cPages << 12) <= vaBase) { continue; }   // outside scope
        if(pMap[i].cwszText) { continue; }
        pMap[i].fWoW64 = fWoW64;
        pMap[i].cwszText = (DWORD)cwszTag;
        pMap[i]._Reserved1[0] = (DWORD)ctx->cwsz;
        fTagWrite = TRUE;
    }
    if(fTagWrite) {
        ctx->cwsz += cwszTag + 1;
    }
}

/*
* Identify module names by scanning for PE headers and tag them into the memory map.
*/
VOID VmmWin_InitializePteMapText_ScanHeaderPE(_In_ PVMM_PROCESS pProcess, _In_ PVMMWIN_INITIALIZEPTEMAP_CONTEXT ctx)
{
    DWORD cMap;
    PVMMOB_MAP_PTE pObMemMap = NULL;
    PVMM_MAP_PTEENTRY pMap;
    PVMM_MAP_PTEENTRY ppMAPs[0x400];
    PPMEM_IO_SCATTER_HEADER ppMEMs = NULL;
    DWORD i, cMEMs = 0, cbImageSize;
    BOOL result;
    CHAR szBuffer[MAX_PATH];
    // 1: checks and allocate buffers for parallel read of MZ header candidates
    if(!LeechCore_AllocScatterEmpty(0x400, &ppMEMs)) { goto fail; }
    if(!VmmMap_GetPte(pProcess, &pObMemMap, FALSE)) { goto fail; }
    if(!pObMemMap || !pObMemMap->cMap) { goto fail; }
    cMap = pObMemMap->cMap;
    pMap = pObMemMap->pMap;
    // 2: scan memory map for MZ header candidates and put them on list for read
    for(i = 0; i < cMap - 1; i++) {
        if(ctxVmm->tpMemoryModel == VMM_MEMORYMODEL_X86) {
            result =
                !(pMap[i].vaBase & 0xffff) &&                 // starts at even 0x10000 offset
                !pMap[i].cwszText;                              // tag not already set
        } else {
            result =
                (pMap[i].cPages == 1) &&                        // PE header is only 1 page
                !(pMap[i].vaBase & 0xffff) &&                 // starts at even 0x10000 offset
                !pMap[i].cwszText &&                            // tag not already set
                (pMap[i].fPage & VMM_MEMMAP_PAGE_NX) &&         // no-execute
                !(pMap[i + 1].fPage & VMM_MEMMAP_PAGE_NX);      // next page is executable
        }
        if(result) {
            ppMEMs[cMEMs]->qwA = pMap[i].vaBase;
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
                result = PE_GetModuleNameEx(pProcess, ppMAPs[i]->vaBase, TRUE, ppMEMs[i]->pb, szBuffer, _countof(szBuffer), &cbImageSize);
                if(result && (cbImageSize < 0x01000000)) {
                    VmmWin_InitializePteMapText_MapTag(pProcess, ctx, ppMAPs[i]->vaBase, ppMAPs[i]->vaBase + cbImageSize - 1, szBuffer, NULL, FALSE);
                }
            }
        }
    }
fail:
    LocalFree(ppMEMs);
    Ob_DECREF(pObMemMap);
}

VOID VmmWin_InitializePteMapText_Modules(_In_ PVMM_PROCESS pProcess, _In_ PVMMWIN_INITIALIZEPTEMAP_CONTEXT ctx)
{
    DWORD i;
    PVMM_MAP_MODULEENTRY pModule;
    PVMMOB_MAP_MODULE pObModuleMap = NULL;
    if(VmmMap_GetModule(pProcess, &pObModuleMap)) {
        // update memory map with names
        for(i = 0; i < pObModuleMap->cMap; i++) {
            pModule = pObModuleMap->pMap + i;
            VmmWin_InitializePteMapText_MapTag(pProcess, ctx, pModule->vaBase, pModule->vaBase + pModule->cbImageSize - 1, NULL, pModule->wszText, pModule->fWoW64);
        }
        Ob_DECREF(pObModuleMap);
    }
}

VOID VmmWin_InitializePteMapText_DoWork(_In_ PVMM_PROCESS pProcess)
{
    DWORD i, cbMultiText;
    PVMM_MAP_PTEENTRY pe;
    VMMWIN_INITIALIZEPTEMAP_CONTEXT ctx = { 0 };
    PVMMOB_MAP_PTE pObMap = pProcess->Map.pObPte;
    ctx.cwsz = 1;
    ctx.cwszMax = 0x00080000;
    ctx.wsz = LocalAlloc(0, ctx.cwszMax << 1);
    if(!ctx.wsz) { return; }
    ctx.wsz[0] = 0;
    VmmWin_InitializePteMapText_Modules(pProcess, &ctx);
    VmmWin_InitializePteMapText_ScanHeaderPE(pProcess, &ctx);
    cbMultiText = (DWORD)(ctx.cwsz << 1);
    if(!(pObMap->wszMultiText = LocalAlloc(0, cbMultiText))) {
        LocalFree(ctx.wsz);
        return;
    }
    memcpy(pObMap->wszMultiText, ctx.wsz, cbMultiText);
    pObMap->cbMultiText = cbMultiText;
    for(i = 0; i < pObMap->cMap; i++) {
        pe = pObMap->pMap + i;
        pe->wszText = pObMap->wszMultiText + pe->_Reserved1[0];
    }
    pObMap->fTagScan = TRUE;
}

/*
* Try initialize PteMap text descriptions. This function will first try to pop-
* ulate the pre-existing VMMOB_MAP_PTE object in pProcess with module names and
* then, if failed or partially failed, try to initialize from PE file headers.
* -- pProcess
* -- return
*/
_Success_(return)
BOOL VmmWin_InitializePteMapText(_In_ PVMM_PROCESS pProcess)
{
    if(pProcess->Map.pObPte->fTagScan) { return TRUE; }
    EnterCriticalSection(&pProcess->LockUpdate);
    if(!pProcess->Map.pObPte->fTagScan) {
        VmmTlbSpider(pProcess);
        VmmWin_InitializePteMapText_DoWork(pProcess);
    }
    LeaveCriticalSection(&pProcess->LockUpdate);
    return pProcess->Map.pObPte->fTagScan;
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

VOID VmmWinHeap_Initialize32_Pre(_In_ PVMM_PROCESS pProcess, _In_opt_ POB_MAP ctx, _In_ QWORD va, _In_ PBYTE pb, _In_ DWORD cb, _In_ QWORD vaFLink, _In_ QWORD vaBLink, _In_ POB_SET pVSetAddress, _Inout_ PBOOL pfValidEntry, _Inout_ PBOOL pfValidFLink, _Inout_ PBOOL pfValidBLink)
{
    QWORD v;
    VMM_MAP_HEAPENTRY e = { 0 };
    PVMMWIN_HEAP_SEGMENT32 h = (PVMMWIN_HEAP_SEGMENT32)pb;
    if((h->SegmentSignature != 0xffeeffee) || (h->NumberOfPages >= 0x00f00000)) { return; }
    *pfValidFLink = VMM_UADDR32_4(vaFLink);
    *pfValidBLink = VMM_UADDR32_4(vaBLink);
    *pfValidEntry = *pfValidFLink || *pfValidBLink;
    if((v = (QWORD)ObMap_GetByKey(ctx, h->Heap))) {
        e.HeapId = v >> 57;
    } else {
        e.HeapId = ObMap_Size(ctx);
        e.fPrimary = 1;
    }
    e.cPages = (DWORD)h->NumberOfPages;
    e.cPagesUnCommitted = h->NumberOfUnCommittedPages;
    ObMap_Push(ctx, va, (PVOID)e.qwHeapData);
}

VOID VmmWinHeap_Initialize64_Pre(_In_ PVMM_PROCESS pProcess, _In_opt_ POB_MAP ctx, _In_ QWORD va, _In_ PBYTE pb, _In_ DWORD cb, _In_ QWORD vaFLink, _In_ QWORD vaBLink, _In_ POB_SET pVSetAddress, _Inout_ PBOOL pfValidEntry, _Inout_ PBOOL pfValidFLink, _Inout_ PBOOL pfValidBLink)
{
    QWORD v;
    VMM_MAP_HEAPENTRY e = { 0 };
    PVMMWIN_HEAP_SEGMENT64 h = (PVMMWIN_HEAP_SEGMENT64)pb;
    if((h->SegmentSignature != 0xffeeffee) || (h->NumberOfPages >= 0x00f00000)) { return; }
    *pfValidFLink = VMM_UADDR64_8(vaFLink);
    *pfValidBLink = VMM_UADDR64_8(vaBLink);
    *pfValidEntry = *pfValidFLink || *pfValidBLink;
    if((v = (QWORD)ObMap_GetByKey(ctx, h->Heap))) {
        e.HeapId = v >> 57;
    } else {
        e.HeapId = ObMap_Size(ctx);
        e.fPrimary = 1;
    }
    e.cPages = (DWORD)h->NumberOfPages;
    e.cPagesUnCommitted = h->NumberOfUnCommittedPages;
    ObMap_Push(ctx, va, (PVOID)e.qwHeapData);
}

/*
* Identify and scan for 64-bit heaps in a process memory space and commit the
* result to the pProcess memory map.
* NB! The 32-bit variant below is NOT robust. It will fail a lot of times
* especially on older versions - but it will fail silently without causing
* harm except a few extra reads. Probably due to bad hardcoded values. It's
* primarily heap-header analysis that is failing. But it seems to mostly work
* on newer windows versions.
* NB! WINXP is not supported.
* NB! Must be called in thread-safe way.
*/
VOID VmmWinHeap_Initialize32(_In_ PVMM_PROCESS pProcess, _In_ BOOL fWow64)
{
    BOOL f;
    BYTE pbPEB[sizeof(PEB32)];
    PPEB32 pPEB = (PPEB32)pbPEB;
    DWORD cHeaps;
    QWORD vaHeapPrimary, vaHeaps[0x80];
    POB_MAP pmObHeap;
    PVMMOB_MAP_HEAP pObHeapMap;
    // 1: Read PEB
    if(!fWow64 && !pProcess->win.vaPEB) { return; }
    if(fWow64 && !pProcess->win.vaPEB32) { return; }
    if(!VmmRead(pProcess, (fWow64 ? pProcess->win.vaPEB32 : pProcess->win.vaPEB), pbPEB, sizeof(PEB32))) { return; }
    vaHeapPrimary = pPEB->ProcessHeap;
    cHeaps = pPEB->NumberOfHeaps;
    if(cHeaps > 0x80) { return; } // probably not valid
    // 2: Read heap array
    f = (cHeaps <= 0x80) &&
        VmmRead(pProcess, pPEB->ProcessHeaps, (PBYTE)vaHeaps, sizeof(DWORD) * cHeaps) &&
        (vaHeaps[0] == vaHeapPrimary);
    if(!f) { return; }
    // 3: Traverse heap linked list
    if(!(pmObHeap = ObMap_New(0))) { return; }
    VmmWin_ListTraversePrefetch(
        pProcess,
        FALSE,
        pmObHeap,
        cHeaps,
        vaHeaps,
        0x18,
        sizeof(VMMWIN_HEAP_SEGMENT32),
        VmmWinHeap_Initialize32_Pre,
        NULL,
        NULL
    );
    // 4: allocate and set result
    cHeaps = ObMap_Size(pmObHeap);
    if((pObHeapMap = Ob_Alloc('HeaM', 0, sizeof(VMMOB_MAP_HEAP) + cHeaps * sizeof(VMM_MAP_HEAPENTRY), NULL, NULL))) {
        pObHeapMap->cMap = cHeaps;
        while(cHeaps) {
            cHeaps--;
            pObHeapMap->pMap[cHeaps].qwHeapData = (QWORD)ObMap_PopWithKey(pmObHeap, &pObHeapMap->pMap[cHeaps].vaHeapSegment);
        }
        pProcess->Map.pObHeap = pObHeapMap;
    }
    Ob_DECREF(pmObHeap);
}

/*
* Identify and scan for 64-bit heaps in a process memory space and commit the
* result to the pProcess memory map.
* NB! WINXP is not supported.
* NB! Must be called in thread-safe way.
*/
VOID VmmWinHeap_Initialize64(_In_ PVMM_PROCESS pProcess)
{
    BOOL f;
    BYTE pbPEB[sizeof(PEB)];
    PPEB pPEB = (PPEB)pbPEB;
    DWORD cHeaps;
    QWORD vaHeapPrimary, vaHeaps[0x80];
    POB_MAP pmObHeap;
    PVMMOB_MAP_HEAP pObHeapMap;
    // 1: Read PEB
    f = pProcess->win.vaPEB && VmmRead(pProcess, pProcess->win.vaPEB, pbPEB, sizeof(PEB));
    if(!f) { return; }
    vaHeapPrimary = (QWORD)pPEB->Reserved4[1];
    cHeaps = (DWORD)(QWORD)pPEB->Reserved9[16];
    // 2: Read heap array
    f = (cHeaps <= 0x80) &&
        VmmRead(pProcess, (QWORD)pPEB->Reserved9[17], (PBYTE)vaHeaps, sizeof(QWORD) * cHeaps) &&
        (vaHeaps[0] == vaHeapPrimary);
    if(!f) { return; }
    // 3: Traverse heap linked list
    if(!(pmObHeap = ObMap_New(0))) { return; }
    VmmWin_ListTraversePrefetch(
        pProcess,
        FALSE,
        pmObHeap,
        cHeaps,
        vaHeaps,
        0x18,
        sizeof(VMMWIN_HEAP_SEGMENT64),
        VmmWinHeap_Initialize64_Pre,
        NULL,
        NULL
    );
    // 4: allocate and set result
    cHeaps = ObMap_Size(pmObHeap);
    if((pObHeapMap = Ob_Alloc('HeaM', 0, sizeof(VMMOB_MAP_HEAP) + cHeaps * sizeof(VMM_MAP_HEAPENTRY), NULL, NULL))) {
        pObHeapMap->cMap = cHeaps;
        while(cHeaps) {
            cHeaps--;
            pObHeapMap->pMap[cHeaps].qwHeapData = (QWORD)ObMap_PopWithKey(pmObHeap, &pObHeapMap->pMap[cHeaps].vaHeapSegment);
        }
        pProcess->Map.pObHeap = pObHeapMap;     // pProcess take reference responsibility
    }
    Ob_DECREF(pmObHeap);
}

/*
* Initialize the meap map containing information about the process heaps in the
* specific process. This is performed by a PEB walk/scan of in-process memory
* structures. This may be unreliable if a process is obfuscated or tampered.
* -- pProcess
* -- return
*/
BOOL VmmWinHeap_Initialize(_In_ PVMM_PROCESS pProcess)
{
    if(pProcess->Map.pObHeap) { return TRUE; }
    VmmTlbSpider(pProcess);
    EnterCriticalSection(&pProcess->LockUpdate);
    if(!pProcess->Map.pObHeap) {
        if((ctxVmm->tpSystem == VMM_SYSTEM_WINDOWS_X86) || ((ctxVmm->tpSystem == VMM_SYSTEM_WINDOWS_X64) && pProcess->win.fWow64)) {
            VmmWinHeap_Initialize32(pProcess, pProcess->win.fWow64);
        } else if(ctxVmm->tpSystem == VMM_SYSTEM_WINDOWS_X64) {
            VmmWinHeap_Initialize64(pProcess);
        }
    }
    LeaveCriticalSection(&pProcess->LockUpdate);
    return pProcess->Map.pObHeap ? TRUE : FALSE;
}

// ----------------------------------------------------------------------------
// THREADING FUNCTIONALITY BELOW:
//
// The threading subsystem is dependent on loaded kernel pdb symbols and being
// initialized asynchronously at startup. i.e. it may not be immediately avail-
// able at startup time or not available at all. Loading threads may be slow
// the first time if many threads exist in a process since a list have to be
// traversed - hence functionality exists to start a load asynchronously.
// ----------------------------------------------------------------------------

typedef struct tdVMMWIN_INITIALIZETHREAD_CONTEXT {
    POB_MAP pmThread;
    POB_SET psTeb;
    PVMM_PROCESS pProcess;
} VMMWIN_INITIALIZETHREAD_CONTEXT, *PVMMWIN_INITIALIZETHREAD_CONTEXT;

int VmmWinThread_Initialize_CmpThreadEntry(PVMM_MAP_THREADENTRY v1, PVMM_MAP_THREADENTRY v2)
{
    return
        (v1->dwTID < v2->dwTID) ? -1 :
        (v1->dwTID > v2->dwTID) ? 1 : 0;
}

VOID VmmWinThread_Initialize_DoWork_Pre(_In_ PVMM_PROCESS pSystemProcess, _In_opt_ PVMMWIN_INITIALIZETHREAD_CONTEXT ctx, _In_ QWORD va, _In_ PBYTE pb, _In_ DWORD cb, _In_ QWORD vaFLink, _In_ QWORD vaBLink, _In_ POB_SET pVSetAddress, _Inout_ PBOOL pfValidEntry, _Inout_ PBOOL pfValidFLink, _Inout_ PBOOL pfValidBLink)
{
    BOOL f, f32 = ctxVmm->f32;
    PVMM_MAP_THREADENTRY e;
    PVMM_OFFSET_ETHREAD ot = &ctxVmm->offset.ETHREAD;
    // 1: sanity check
    f = ctx &&
        (f32 ? VMM_KADDR32_4(vaFLink) : VMM_KADDR64_8(vaFLink)) &&
        (f32 ? VMM_KADDR32_4(vaBLink) : VMM_KADDR64_8(vaBLink)) &&
        (!ot->oProcessOpt || (VMM_PTR_OFFSET(f32, pb, ot->oProcessOpt) == ctx->pProcess->win.EPROCESS.va));
    if(!f) { return; }
    *pfValidEntry = *pfValidFLink = *pfValidBLink = TRUE;
    // 2: allocate and populate thread entry with info.
    if(!(e = LocalAlloc(LMEM_ZEROINIT, sizeof(VMM_MAP_THREADENTRY)))) { return; }
    e->vaETHREAD = va;
    e->dwTID = (DWORD)VMM_PTR_OFFSET(f32, pb, ot->oCid + (f32 ? 4ULL : 8ULL));
    e->dwPID = (DWORD)VMM_PTR_OFFSET(f32, pb, ot->oCid);
    e->dwExitStatus = *(PDWORD)(pb + ot->oExitStatus);
    e->bState = *(PUCHAR)(pb + ot->oState);
    if(ot->oRunningOpt) { e->bRunning = *(PUCHAR)(pb + ot->oRunningOpt); }
    e->bPriority = *(PUCHAR)(pb + ot->oPriority);
    e->bBasePriority = *(PUCHAR)(pb + ot->oBasePriority);
    e->vaTeb = VMM_PTR_OFFSET(f32, pb, ot->oTeb);
    e->ftCreateTime = *(PQWORD)(pb + ot->oCreateTime);
    e->ftExitTime = *(PQWORD)(pb + ot->oExitTime);
    e->vaStartAddress = VMM_PTR_OFFSET(f32, pb, ot->oStartAddress);
    e->vaStackBaseKernel = VMM_PTR_OFFSET(f32, pb, ot->oStackBase);
    e->vaStackLimitKernel = VMM_PTR_OFFSET(f32, pb, ot->oStackLimit);
    if(e->ftExitTime > 0x02000000'00000000) { e->ftExitTime = 0; }
    ObSet_Push(ctx->psTeb, e->vaTeb);
    ObMap_Push(ctx->pmThread, e->dwTID, e);  // map will free allocation when cleared
}

VOID VmmWinThread_Initialize_DoWork(_In_ PVMM_PROCESS pProcess)
{
    BOOL f32 = ctxVmm->f32;
    BYTE pbTeb[0x20];
    DWORD i, cMap;
    QWORD va, vaThreadListEntry;
    POB_SET psObTeb = NULL;
    POB_MAP pmObThreads = NULL;
    PVMMOB_MAP_THREAD pObThreadMap = NULL;
    PVMM_MAP_THREADENTRY pThreadEntry;
    PVMM_PROCESS pObSystemProcess = NULL;
    VMMWIN_INITIALIZETHREAD_CONTEXT ctx = { 0 };
    // 1: set up and perform list traversal call.
    vaThreadListEntry = VMM_PTR_OFFSET(f32, pProcess->win.EPROCESS.pb, ctxVmm->offset.ETHREAD.oThreadListHeadKP);
    if(f32 ? !VMM_KADDR32_4(vaThreadListEntry) : !VMM_KADDR64_8(vaThreadListEntry)) { goto fail; }
    if(!(pObSystemProcess = VmmProcessGet(4))) { goto fail; }
    if(!(psObTeb = ObSet_New())) { goto fail; }
    if(!(pmObThreads = ObMap_New(OB_MAP_FLAGS_OBJECT_LOCALFREE))) { goto fail; }
    ctx.pmThread = pmObThreads;
    ctx.psTeb = psObTeb;
    ctx.pProcess = pProcess;
    va = vaThreadListEntry - ctxVmm->offset.ETHREAD.oThreadListEntry;
    VmmWin_ListTraversePrefetch(
        pObSystemProcess,
        f32,
        &ctx,
        1,
        &va,
        ctxVmm->offset.ETHREAD.oThreadListEntry,
        ctxVmm->offset.ETHREAD.oMax,
        VmmWinThread_Initialize_DoWork_Pre,
        NULL,
        pProcess->pObPersistent->pObCMapThreadPrefetch);
    // 2: transfer result from generic map into PVMMOB_MAP_THREAD
    if(!(cMap = ObMap_Size(pmObThreads))) { goto fail; }
    if(!(pObThreadMap = Ob_Alloc(OB_TAG_MAP_THREAD, 0, sizeof(VMMOB_MAP_THREAD) + cMap * sizeof(VMM_MAP_THREADENTRY), NULL, NULL))) { goto fail; }
    pObThreadMap->cMap = cMap;
    VmmCachePrefetchPages3(pProcess, psObTeb, 0x20, 0);
    for(i = 0; i < cMap; i++) {
        pThreadEntry = (PVMM_MAP_THREADENTRY)ObMap_GetByIndex(pmObThreads, i);
        if(VmmRead2(pProcess, pThreadEntry->vaTeb, pbTeb, 0x20, VMM_FLAG_FORCECACHE_READ)) {
            pThreadEntry->vaStackBaseUser = f32 ? *(PDWORD)(pbTeb + 4) : *(PQWORD)(pbTeb + 8);
            pThreadEntry->vaStackLimitUser = f32 ? *(PDWORD)(pbTeb + 8) : *(PQWORD)(pbTeb + 16);
        }
        memcpy(pObThreadMap->pMap + i, pThreadEntry, sizeof(VMM_MAP_THREADENTRY));
    }
    // 3: sort on thread id (TID) and assign result to process object.
    qsort(pObThreadMap->pMap, cMap, sizeof(VMM_MAP_THREADENTRY), (int(*)(const void*, const void*))VmmWinThread_Initialize_CmpThreadEntry);
    pProcess->Map.pObThread = pObThreadMap;     // pProcess take reference responsibility
fail:
    Ob_DECREF(psObTeb);
    Ob_DECREF(pmObThreads);
    Ob_DECREF(pObSystemProcess);
}

/*
* Initialize the thread map for a specific process.
* NB! The threading sub-system is dependent on pdb symbols and may take a small
* amount of time before it's available after system startup.
* -- pProcess
* -- fNonBlocking
* -- return
*/
BOOL VmmWinThread_Initialize(_In_ PVMM_PROCESS pProcess, _In_ BOOL fNonBlocking)
{
    if(pProcess->Map.pObThread) { return TRUE; }
    if(!ctxVmm->fThreadMapEnabled) { return FALSE; }
    VmmTlbSpider(pProcess);
    if(fNonBlocking) {
        if(!TryEnterCriticalSection(&pProcess->Map.LockUpdateThreadMap)) { return FALSE; }
    } else {
        EnterCriticalSection(&pProcess->Map.LockUpdateThreadMap);
    }
    if(!pProcess->Map.pObThread) {
        VmmWinThread_Initialize_DoWork(pProcess);
        if(!pProcess->Map.pObThread) {
            pProcess->Map.pObThread = Ob_Alloc(OB_TAG_MAP_THREAD, LMEM_ZEROINIT, sizeof(VMMOB_MAP_THREAD), NULL, NULL);
        }
    }
    LeaveCriticalSection(&pProcess->Map.LockUpdateThreadMap);
    return pProcess->Map.pObThread ? TRUE : FALSE;
}

// ----------------------------------------------------------------------------
// HANDLE FUNCTIONALITY BELOW:
//
// The code below is responsible for parsing the HANDLE table into a map. The
// function will read the handle table and then also peek into each handle to
// determine its type. Even though parsing is generally efficient in number of
// calls quite a few memory pages may be retrieved - worst case ~1 per handle!
// ----------------------------------------------------------------------------

/*
* Retrieve a pointer to a VMMWIN_OBJECT_TYPE if possible. Initialization of the
* table takes place on first use. The table only exists in Win7+ and is is
* dependant on PDB symbol functionality for initialization.
* -- iObjectType
* -- return
*/
_Success_(return != NULL)
PVMMWIN_OBJECT_TYPE VmmWin_ObjectTypeGet(_In_ BYTE iObjectType)
{
    BOOL f, fResult = FALSE;
    QWORD vaTypeTable = 0;
    PVMM_PROCESS pObSystemProcess = NULL;
    DWORD i, cType = 2;
    QWORD ava[256];
    WORD acbwsz[256];
    BYTE pb[256 * 8];
    PQWORD pva64;
    PDWORD pva32;
    DWORD owszMultiText = 1;
    LPWSTR wszMultiText = NULL;
    if(ctxVmm->ObjectTypeTable.fInitialized) {
        return ctxVmm->ObjectTypeTable.h[iObjectType].wsz ? &ctxVmm->ObjectTypeTable.h[iObjectType] : NULL;
    }
    EnterCriticalSection(&ctxVmm->MasterLock);
    if(ctxVmm->ObjectTypeTable.fInitialized) {
        LeaveCriticalSection(&ctxVmm->MasterLock);
        return ctxVmm->ObjectTypeTable.h[iObjectType].wsz ? &ctxVmm->ObjectTypeTable.h[iObjectType] : NULL;
    }
    if(!(pObSystemProcess = VmmProcessGet(4))) { goto fail; }
    PDB_Initialize_WaitComplete();
    if(!PDB_GetSymbolAddress(VMMWIN_PDB_HANDLE_KERNEL, "ObTypeIndexTable", &vaTypeTable)) { goto fail; }
    if(ctxVmm->kernel.dwVersionMajor == 10) {
        if(!PDB_GetSymbolDWORD(VMMWIN_PDB_HANDLE_KERNEL, "ObHeaderCookie", pObSystemProcess, &i)) { goto fail; }
        ctxVmm->ObjectTypeTable.bObjectHeaderCookie = (BYTE)i;
    }
    // fetch and count object type addresses
    ZeroMemory(ava, sizeof(ava));
    ZeroMemory(acbwsz, sizeof(acbwsz));
    VmmReadEx(pObSystemProcess, vaTypeTable, pb, 256 * 8, NULL, VMM_FLAG_ZEROPAD_ON_FAIL);
    if(ctxVmm->f32) {
        pva32 = (PDWORD)pb;
        while(VMM_KADDR32_8(pva32[cType]) && (cType < 256)) {
            ava[cType] = pva32[cType];
            cType++;
        }
    } else {
        pva64 = (PQWORD)pb;
        while(VMM_KADDR64_16(pva64[cType]) && (cType < 256)) {
            ava[cType] = pva64[cType];
            cType++;
        }
    }
    if(cType == 2) { goto fail; }   // none found
    // fetch unicode length and addresses of text
    VmmCachePrefetchPages4(pObSystemProcess, cType, ava, 0x10, 0);
    for(i = 2; i < cType; i++) {
        f = VmmRead2(pObSystemProcess, ava[i] + (ctxVmm->f32 ? 8 : 16), pb, 0x10, VMM_FLAG_FORCECACHE_READ);
        f = f && (*(PWORD)(pb) < MAX_PATH);
        f = f && (*(PWORD)(pb) <= *(PQWORD)(pb + 2));
        f = f && (acbwsz[i] = *(PWORD)(pb));
        f = f && (ava[i] = ctxVmm->f32 ? *(PDWORD)(pb + 4) : *(PQWORD)(pb + 8));
        f = f && (ctxVmm->f32 ? VMM_KADDR32_8(ava[i]) : VMM_KADDR64_16(ava[i]));
        if(!f) {
            ava[i] = 0;
        }
    }
    // fetch text
    if(!(wszMultiText = LocalAlloc(0, 2 + 2ULL * MAX_PATH * cType))) { goto fail; }
    wszMultiText[0] = 0;
    VmmCachePrefetchPages4(pObSystemProcess, cType, ava, 2 * MAX_PATH, 0);
    for(i = 2; i < cType; i++) {
        if(ava[i] && VmmRead2(pObSystemProcess, ava[i] - 16, pb, 16 + acbwsz[i], VMM_FLAG_FORCECACHE_READ) && VMM_POOLTAG_PREPENDED(pb, 16, 'ObNm')) {
            memcpy((PBYTE)(wszMultiText + owszMultiText), pb + 16, acbwsz[i]);
            ava[i] = owszMultiText;
            owszMultiText += acbwsz[i] >> 1;
            wszMultiText[owszMultiText] = 0;
            owszMultiText++;
        }
    }
    // finish!
    ctxVmm->ObjectTypeTable.cbMultiText = owszMultiText << 1;
    if(!(ctxVmm->ObjectTypeTable.wszMultiText = LocalAlloc(0, ctxVmm->ObjectTypeTable.cbMultiText))) { goto fail; }
    memcpy(ctxVmm->ObjectTypeTable.wszMultiText, wszMultiText, ctxVmm->ObjectTypeTable.cbMultiText);
    for(i = 2; i < cType; i++) {
        if(ava[i]) {
            ctxVmm->ObjectTypeTable.h[i].cwsz = acbwsz[i] >> 1;
            ctxVmm->ObjectTypeTable.h[i].owsz = (WORD)ava[i];
            ctxVmm->ObjectTypeTable.h[i].wsz = ctxVmm->ObjectTypeTable.wszMultiText + ava[i];
        }
    }
    ctxVmm->ObjectTypeTable.c = cType;
    fResult = TRUE;
    // fall-trough to cleanup / "fail"
fail:
    ctxVmm->ObjectTypeTable.fInitialized = TRUE;
    if(!fResult) { ctxVmm->ObjectTypeTable.fInitializedFailed = TRUE; }
    LeaveCriticalSection(&ctxVmm->MasterLock);
    Ob_DECREF(pObSystemProcess);
    LocalFree(wszMultiText);
    return ctxVmm->ObjectTypeTable.h[iObjectType].wsz ? &ctxVmm->ObjectTypeTable.h[iObjectType] : NULL;
}

/*
* _OBJECT_HEADER.TypeIndex is encoded on Windows 10 - this function decodes it.
* https://medium.com/@ashabdalhalim/e8f907e7073a
* -- vaObjectHeader
* -- iTypeIndexTableEncoded
* -- return
*/
BYTE VmmWin_ObjectTypeGetIndexFromEncoded(_In_ QWORD vaObjectHeader, _In_ BYTE iTypeIndexTableEncoded)
{
    if(ctxVmm->kernel.dwVersionMajor != 10) { return iTypeIndexTableEncoded; }
    if(!ctxVmm->ObjectTypeTable.fInitialized) { VmmWin_ObjectTypeGet(0); }  // DUMMY call to initialize ctxVmm->ObjectTypeTable
    if(ctxVmm->ObjectTypeTable.fInitializedFailed) { return 0; }
    return iTypeIndexTableEncoded ^ (BYTE)(vaObjectHeader >> 8) ^ ctxVmm->ObjectTypeTable.bObjectHeaderCookie;
}

typedef struct tdVMMWIN_INITIALIZE_HANDLE_CONTEXT {
    PVMM_PROCESS pSystemProcess;
    PVMM_PROCESS pProcess;
    DWORD cTables;
    DWORD cTablesMax;
    PQWORD pvaTables;
    PVMMOB_MAP_HANDLE pHandleMap;
    DWORD iMap;
} VMMWIN_INITIALIZE_HANDLE_CONTEXT, *PVMMWIN_INITIALIZE_HANDLE_CONTEXT;

/*
* Object manager callback function for object cleanup tasks.
* -- pVmmHandle
*/
VOID VmmWinHandle_CloseObCallback(_In_ PVOID pVmmHandle)
{
    PVMMOB_MAP_HANDLE pOb = (PVMMOB_MAP_HANDLE)pVmmHandle;
    LocalFree(pOb->wszMultiText);
}

/*
* Spider the handle table hierarchy if there is one.
* -- ctx
* -- vaTable
* -- fLevel2
*/
VOID VmmWinHandle_InitializeCore_SpiderTables(_In_ PVMMWIN_INITIALIZE_HANDLE_CONTEXT ctx, _In_ QWORD vaTable, _In_ BOOL fLevel2)
{
    QWORD i, va = 0;
    union {
        BYTE pb[0x1000];
        DWORD pdw[0x400];
        QWORD pqw[0x200];
    } u;
    if(!VmmRead(ctx->pSystemProcess, vaTable, u.pb, 0x1000)) { return; }
    if(ctxVmm->f32) {
        for(i = 0; i < 0x400; i++) {
            va = u.pdw[i];
            if(!VMM_KADDR32_PAGE(va)) { return; }
            if(fLevel2) {
                VmmWinHandle_InitializeCore_SpiderTables(ctx, va, FALSE);
                if(ctx->cTables == ctx->cTablesMax) { return; }
            } else {
                ctx->pvaTables[ctx->cTables] = va;
                ctx->cTables++;
                if(ctx->cTables == ctx->cTablesMax) { return; }
            }
        }
    } else {
        for(i = 0; i < 0x200; i++) {
            va = u.pqw[i];
            if(!VMM_KADDR64_PAGE(va)) { return; }
            if(fLevel2) {
                VmmWinHandle_InitializeCore_SpiderTables(ctx, va, FALSE);
                if(ctx->cTables == ctx->cTablesMax) { return; }
            } else {
                ctx->pvaTables[ctx->cTables] = va;
                ctx->cTables++;
                if(ctx->cTables == ctx->cTablesMax) { return; }
            }
        }
    }
}

/*
* Count the number of valid handles.
* -- ctx
* -- return = the number of valid handles.
*/
DWORD VmmWinHandle_InitializeCore_CountHandles(_In_ PVMMWIN_INITIALIZE_HANDLE_CONTEXT ctx)
{
    QWORD va;
    DWORD iTable, i, cHandles = 0;
    union {
        BYTE pb[0x1000];
        DWORD pdw[0x400];
        QWORD pqw[0x200];
    } u;
    VmmCachePrefetchPages4(ctx->pSystemProcess, ctx->cTables, ctx->pvaTables, 0x1000, 0);
    for(iTable = 0; iTable < ctx->cTables; iTable++) {
        if(!VmmRead(ctx->pSystemProcess, ctx->pvaTables[iTable], u.pb, 0x1000)) { continue; }
        if(ctxVmm->f32) {
            for(i = 1; i < 512; i++) {
                if(!VMM_KADDR32(u.pdw[i << 1])) { continue; }
                cHandles++;
            }
        } else {
            for(i = 1; i < 256; i++) {
                va = u.pqw[i << 1];
                if(ctxVmm->kernel.dwVersionBuild >= 9200) {     // Win8 or later
                    va = 0xffff0000'00000000 | (va >> 16);
                }
                if(!VMM_KADDR64(va)) { continue; }
                cHandles++;
            }
        }
    }
    return cHandles;
}

/*
* Read the handle tables and populate only basic information into the HandleMap
* i.e. data that don't require reading of the actual objects pointed to.
* -- ctx
* -- vaHandleTable
* -- dwBaseHandleId
*/
VOID VmmWinHandle_InitializeCore_ReadHandleTable(_In_ PVMMWIN_INITIALIZE_HANDLE_CONTEXT ctx, _In_ QWORD vaHandleTable, _In_ DWORD dwBaseHandleId)
{
    DWORD i;
    QWORD va;
    PVMM_MAP_HANDLEENTRY pe;
    union {
        BYTE pb[0x1000];
        DWORD pdw[0x400];
        QWORD pqw[0x200];
    } u;
    if(!VmmRead(ctx->pSystemProcess, vaHandleTable, u.pb, 0x1000)) { return; }
    if(ctxVmm->f32) {
        for(i = 1; i < 512; i++) {
            va = u.pdw[i << 1] & ~3;
            if(!VMM_KADDR32(va)) { continue; }
            pe = ctx->pHandleMap->pMap + ctx->iMap;
            pe->vaObject = (va & ~7) + 0x18ULL;
            pe->dwGrantedAccess = u.pdw[(i << 1) + 1] & 0x00ffffff;
            pe->dwHandle = dwBaseHandleId + (i << 2);
            pe->dwPID = ctx->pProcess->dwPID;
            ctx->iMap++;
            if(ctx->iMap == ctx->pHandleMap->cMap) { break; }
        }
    } else {
        for(i = 1; i < 256; i++) {
            va = u.pqw[i << 1];
            if(ctxVmm->kernel.dwVersionBuild >= 9600) {         // Win8.1 or later
                va = 0xffff0000'00000000 | (va >> 16);
            } else if(ctxVmm->kernel.dwVersionBuild >= 9200) {  // Win8 or later
                va = 0xfffff800'00000000 | (va >> 19);
            }
            if(!VMM_KADDR64(va)) { continue; }
            pe = ctx->pHandleMap->pMap + ctx->iMap;
            pe->vaObject = (va & ~7) + 0x30;
            pe->dwGrantedAccess = (DWORD)u.pqw[(i << 1) + 1] & 0x00ffffff;
            pe->dwHandle = dwBaseHandleId + (i << 2);
            pe->dwPID = ctx->pProcess->dwPID;
            ctx->iMap++;
            if(ctx->iMap == ctx->pHandleMap->cMap) { break; }
        }
    }
}

typedef struct tdVMMWIN_OBJECT_HEADER32 {
    DWORD PointerCount;
    DWORD HandleCount;
    DWORD Lock;
    BYTE TypeIndex;
    BYTE TraceFlags;
    BYTE _Flags[2];
    DWORD ObjectCreateInfo;
    DWORD SecurityDescriptor;
} VMMWIN_OBJECT_HEADER32, *PVMMWIN_OBJECT_HEADER32;

typedef struct tdVMMWIN_OBJECT_HEADER64 {
    QWORD PointerCount;
    QWORD HandleCount;
    QWORD Lock;
    BYTE TypeIndex;
    BYTE TraceFlags;
    BYTE _Flags[2];
    DWORD _Reserved;
    QWORD ObjectCreateInfo;
    QWORD SecurityDescriptor;
} VMMWIN_OBJECT_HEADER64, *PVMMWIN_OBJECT_HEADER64;

DWORD VmmWinHandle_InitializeText_GetPoolHeader2(DWORD dwPoolHeaderCandidate)
{
    CHAR i, ch;
    for(i = 0; i < 32; i = i + 8) {
        ch = (CHAR)(dwPoolHeaderCandidate >> i);
        if(ch >= 'a' && ch <= 'z') { continue; }
        if(ch >= 'A' && ch <= 'Z') { continue; }
        if(ch == ' ') { continue; }
        if((i == 24) && (ctxVmm->kernel.dwVersionBuild <= 9601)) {
            return 0x20000000 | (dwPoolHeaderCandidate & 0x00ffffff);   // last char usually A-Z in win7
        }
        return 0;
    }
    return dwPoolHeaderCandidate;
}

DWORD VmmWinHandle_InitializeText_GetPoolHeader32(_In_reads_(0x40) PBYTE pb, _Out_ PDWORD pdwOffset)
{
    DWORD dwPoolHeader, i = 0x40;
    while(i) {
        i -= 0x08;
        if((dwPoolHeader = VmmWinHandle_InitializeText_GetPoolHeader2(*(PDWORD)(pb + i + 4)))) {
            *pdwOffset = i + 4;
            return dwPoolHeader;
        }
    }
    *pdwOffset = 0;
    return 0;
}

DWORD VmmWinHandle_InitializeText_GetPoolHeader64(_In_reads_(0x60) PBYTE pb, _Out_ PDWORD pdwOffset)
{
    DWORD dwPoolHeader, i = 0x60;
    while(i) {
        i -= 0x10;
        if((dwPoolHeader = VmmWinHandle_InitializeText_GetPoolHeader2(*(PDWORD)(pb + i + 4)))) {
            *pdwOffset = i + 4;
            return dwPoolHeader;
        }
    }
    *pdwOffset = 0;
    return 0;
}

typedef struct tdVMMWINHANDLE_REGHELPER {
    QWORD vaCmKeyControlBlock;
    QWORD vaHive;
    DWORD raKeyCell;
    VMM_REGISTRY_KEY_INFO KeyInfo;
    DWORD cwszText;
    LPWSTR wszText;
} VMMWINHANDLE_REGHELPER, *PVMMWINHANDLE_REGHELPER;

/*
* Helper function for VmmWinHandle_InitializeText_DoWork that fetches registry
* names provided that the underlying _CM_KEY_CONTROL_BLOCK is prefetched.
* -- pSystemProcess
* -- pm
* -- return = number of bytes that is required to hold multi-text data incl. NULL terminators.
*/
DWORD VmmWinHandle_InitializeText_DoWork_RegKeyHelper(_In_ PVMM_PROCESS pSystemProcess, _In_ POB_MAP pm)
{
    BYTE pb[0x30];
    DWORD raCell, cchTotal = 0, dwBuild = ctxVmm->kernel.dwVersionBuild;
    QWORD vaHive;
    POB_REGISTRY_KEY pObKey = NULL;
    POB_REGISTRY_HIVE pObHive = NULL;
    PVMMWINHANDLE_REGHELPER prh = NULL;
    while((prh = ObMap_GetNext(pm, prh))) {
        if(!VmmRead2(pSystemProcess, prh->vaCmKeyControlBlock, pb, 0x30, VMM_FLAG_FORCECACHE_READ)) { continue; }
        if(ctxVmm->f32) {
            if((dwBuild >= 7600) && (dwBuild <= 10586)) {
                // Win7 :: Win10_10586
                vaHive = *(PDWORD)(pb + 0x14);
                raCell = *(PDWORD)(pb + 0x18);
            } else {
                vaHive = *(PDWORD)(pb + 0x10);
                raCell = *(PDWORD)(pb + 0x14);
            }
            if(!VMM_KADDR32(vaHive)) { continue; }
        } else {
            if((dwBuild <= 6002) || ((dwBuild >= 14393) && (dwBuild <= 17763))) {
                // VISTA & Win10_1607 :: Win10_1809
                vaHive = *(PQWORD)(pb + 0x18);
                raCell = *(PDWORD)(pb + 0x20);
            } else {
                vaHive = *(PQWORD)(pb + 0x20);
                raCell = *(PDWORD)(pb + 0x28);
            }
            if(!VMM_KADDR64(vaHive)) { continue; }
        }
        if(!raCell || ((raCell & 0x7fffffff) > 0x20000000)) { continue; }
        prh->vaHive = vaHive;
        prh->raKeyCell = raCell;
    }
    while((prh = ObMap_GetNext(pm, prh))) {
        if((pObHive = VmmWinReg_HiveGetByAddress(prh->vaHive))) {
            if((pObKey = VmmWinReg_KeyGetByCellOffset(pObHive, prh->raKeyCell))) {
                VmmWinReg_KeyInfo2(pObHive, pObKey, &prh->KeyInfo);
                cchTotal += 28 + prh->KeyInfo.cchName + 1;
                Ob_DECREF_NULL(&pObKey);
            }
            Ob_DECREF_NULL(&pObHive);
        }
    }
    return cchTotal * sizeof(WCHAR);
}

VOID VmmWinHandle_InitializeText_DoWork_FileSizeHelper(_In_ PVMM_PROCESS pSystemProcess, _In_ POB_SET psPrefetch, _In_ PVMMOB_MAP_HANDLE pHandleMap)
{
    BOOL f;
    QWORD i, cMax, cb, va;
    BYTE pb[0x100];
    PVMM_MAP_HANDLEENTRY pe;
    // 1: fetch, if required, _SHARED_CACHE_MAP // _CONTROL_AREA
    if(0 == ObSet_Size(psPrefetch)) { return; }
    VmmCachePrefetchPages3(pSystemProcess, psPrefetch, 0x20, 0);
    ObSet_Clear(psPrefetch);
    for(i = 0, cMax = pHandleMap->cMap; i < cMax; i++) {
        pe = pHandleMap->pMap + i;
        if(pe->tpInfoEx != HANDLEENTRY_TP_INFO_FILE) { continue; }
        if(!VmmRead2(pSystemProcess, pe->_Reserved.qw - 0x10, pb, 0x20, VMM_FLAG_FORCECACHE_READ)) { continue; }
        if(VMM_POOLTAG_PREPENDED(pb, 0x10, 'CcSc')) {
            cb = *(PQWORD)(pb + 0x10 + O_SHARED_CACHE_MAP_FileSize);
            pe->_InfoFile.cb = (cb <= 0xffffffff) ? (DWORD)cb : 0xffffffff;
            continue;
        }
        f = VMM_POOLTAG_PREPENDED(pb, 0x10, 'MmCa') &&
            (va = VMM_PTR_OFFSET(ctxVmm->f32, pb + 0x10, O_CONTROL_AREA_Segment)) &&
            VMM_KADDR_8_16(va);
        if(f) {
            pe->_Reserved.qw = va;
            ObSet_Push(psPrefetch, va - 0x10);
        }
    }
    // 2: fetch, if required, _SEGMENT
    if(0 == ObSet_Size(psPrefetch)) { return; }
    VmmCachePrefetchPages3(pSystemProcess, psPrefetch, 0x30, 0);
    for(i = 0, cMax = pHandleMap->cMap; i < cMax; i++) {
        pe = pHandleMap->pMap + i;
        if(pe->tpInfoEx != HANDLEENTRY_TP_INFO_FILE) { continue; }
        if(!VmmRead2(pSystemProcess, pe->_Reserved.qw - 0x10, pb, 0x30, VMM_FLAG_FORCECACHE_READ)) { continue; }
        if(VMM_POOLTAG_PREPENDED(pb, 0x10, 'MmSm')) {
            cb = *(PQWORD)(pb + 0x10 + (ctxVmm->f32 ? O32_SEGMENT_SizeOfSegment : O64_SEGMENT_SizeOfSegment));
            cb = (cb <= 0xffffffff) ? cb : 0xffffffff;
            pe->_InfoFile.cb = (DWORD)(pe->_InfoFile.cb ? min(pe->_InfoFile.cb, cb) : cb);
        }
    }
}

VOID VmmWinHandle_InitializeText_DoWork(_In_ PVMM_PROCESS pSystemProcess, _In_ PVMMOB_MAP_HANDLE pHandleMap)
{
    BOOL f, fThreadingEnabled;
    PBYTE pbMultiText = NULL;
    QWORD va;
    DWORD i, cbRead, oPoolHdr, cbObjectRead, cbMultiText = 4, ocbMultiText = 2;
    POB_SET psObPrefetch = NULL, psObRegPrefetch = NULL;
    POB_MAP pmObRegHelperMap = NULL;
    PUNICODE_STRING32 pus32;
    PUNICODE_STRING64 pus64;
    PVMM_MAP_HANDLEENTRY pe;
    PVMM_PROCESS pObProcessHnd;
    union {
        BYTE pb[0x1000];
        struct {
            BYTE _Filler1[0x60 - 0x18 - 0x0c];
            UNICODE_STRING32 String;
            DWORD _Filler2;
            VMMWIN_OBJECT_HEADER32 Header;
            BYTE pb[];
        } O32;
        struct {
            BYTE _Filler1[0x90 - 0x30 - 0x18];
            UNICODE_STRING64 String;
            QWORD _Filler2;
            VMMWIN_OBJECT_HEADER64 Header;
            BYTE pb[];
        } O64;
    } u;
    PVMMWINHANDLE_REGHELPER pRegHelp = NULL;
    fThreadingEnabled = (ctxVmm->offset.ETHREAD.oCid > 0);
    cbObjectRead = max(ctxVmm->offset.EPROCESS.PID + 0x08, ctxVmm->offset.ETHREAD.oCid + 0x20);
    cbObjectRead = 0x90 + max(0x70, cbObjectRead);
    // 1: cache prefetch object data
    if(!(psObPrefetch = ObSet_New())) { goto fail; }
    if(!(psObRegPrefetch = ObSet_New())) { goto fail; }
    if(!(pmObRegHelperMap = ObMap_New(OB_MAP_FLAGS_OBJECT_LOCALFREE))) { goto fail; }
    for(i = 0; i < pHandleMap->cMap; i++) {
        ObSet_Push(psObPrefetch, pHandleMap->pMap[i].vaObject - 0x90);
    }
    VmmCachePrefetchPages3(pSystemProcess, psObPrefetch, cbObjectRead, 0);
    ObSet_Clear(psObPrefetch);
    // 2: read and interpret object data
    if(ctxVmm->f32) {
        for(i = 0; i < pHandleMap->cMap; i++) {
            pe = pHandleMap->pMap + i;
            VmmReadEx(pSystemProcess, pe->vaObject - 0x60, u.pb, cbObjectRead, &cbRead, VMM_FLAG_ZEROPAD_ON_FAIL | VMM_FLAG_FORCECACHE_READ);
            if(cbRead < 0x60) { continue; }
            // fetch and validate type index
            if(ctxVmm->ObjectTypeTable.fInitialized) {
                pe->iType = VmmWin_ObjectTypeGetIndexFromEncoded(pe->vaObject - 0x18, u.O32.Header.TypeIndex);
                if(!pe->iType || (pe->iType > ctxVmm->ObjectTypeTable.c)) {
                    continue;
                }
            }
            // fetch pool tag (if found)
            pe->dwPoolTag = VmmWinHandle_InitializeText_GetPoolHeader32(u.pb, &oPoolHdr);
            // fetch remaining object header values
            pe->qwHandleCount = u.O32.Header.HandleCount;
            pe->qwPointerCount = u.O32.Header.PointerCount;
            pe->vaObjectCreateInfo = u.O32.Header.ObjectCreateInfo;
            pe->vaSecurityDescriptor = u.O32.Header.SecurityDescriptor;
            // fetch text description length and address (if possible)
            if(pe->dwPoolTag) {
                pus32 = NULL;
                if((pe->dwPoolTag & 0x00ffffff) == 'yeK') {         // REG KEY
                    if(!VMM_KADDR32(*(PDWORD)(u.O32.pb + 4))) { continue; }
                    if(ObMap_ExistsKey(pmObRegHelperMap, pe->vaObject)) { continue; }
                    if(!(pRegHelp = LocalAlloc(LMEM_ZEROINIT, sizeof(VMMWINHANDLE_REGHELPER)))) { continue; }
                    pRegHelp->vaCmKeyControlBlock = *(PDWORD)(u.O32.pb + 4);
                    ObMap_Push(pmObRegHelperMap, pe->vaObject, pRegHelp);           // map is responsible for free of pRegHelp
                    ObSet_Push(psObRegPrefetch, pRegHelp->vaCmKeyControlBlock);
                } else if((pe->dwPoolTag & 0x00ffffff) == 'orP') {  // PROCESS
                    pe->_Reserved.dw = *(PDWORD)(u.O32.pb + ctxVmm->offset.EPROCESS.PID);
                    cbMultiText += 31 * sizeof(WCHAR) + 2;
                } else if(((pe->dwPoolTag & 0x00ffffff) == 'rhT') && fThreadingEnabled) {   // THREAD
                    if(ctxVmm->offset.ETHREAD.oCid && *(PDWORD)(u.O32.pb + ctxVmm->offset.ETHREAD.oCid + 4)) {
                        pe->_Reserved.dw = *(PDWORD)(u.O32.pb + ctxVmm->offset.ETHREAD.oCid + 4);
                        cbMultiText += 11 * sizeof(WCHAR) + 2;
                    }
                } else if((pe->dwPoolTag & 0x00ffffff) == 'liF') {  // FILE HANDLE
                    pus32 = (PUNICODE_STRING32)(u.O32.pb + O32_FILE_OBJECT_FileName);
                    if((va = *(PDWORD)(u.O32.pb + O32_FILE_OBJECT_SectionObjectPointer)) && VMM_KADDR32_4(va)) {
                        ObSet_Push(psObPrefetch, va);
                        pe->tpInfoEx = HANDLEENTRY_TP_INFO_PRE_1;
                        pe->_Reserved.qw2 = va;
                    }
                } else if(pe->dwPoolTag && (oPoolHdr <= 0x34)) {
                    pus32 = &u.O32.String;
                }
                f = pus32 && (pus32->Length > 2) &&
                    !(pus32->Length & 1) && (pus32->Length < (2 * MAX_PATH)) && (pus32->Length <= pus32->MaximumLength) &&
                    VMM_KADDR32(pus32->Buffer);
                if(f) {
                    cbMultiText += pus32->Length + 2;
                    pe->_Reserved.dw = pus32->Length;
                    pe->_Reserved.qw = pus32->Buffer;
                    ObSet_Push(psObPrefetch, pus32->Buffer);
                }
            }
        }
    } else {
        for(i = 0; i < pHandleMap->cMap; i++) {
            pe = pHandleMap->pMap + i;
            max(0x70, ctxVmm->offset.ETHREAD.oCid + 0x10);
            VmmReadEx(pSystemProcess, pe->vaObject - 0x90, u.pb, cbObjectRead, &cbRead, VMM_FLAG_ZEROPAD_ON_FAIL | VMM_FLAG_FORCECACHE_READ);
            if(cbRead < 0x90) { continue; }
            // fetch and validate type index
            if(ctxVmm->ObjectTypeTable.fInitialized) {
                pe->iType = VmmWin_ObjectTypeGetIndexFromEncoded(pe->vaObject - 0x30, u.O64.Header.TypeIndex);
                if(!pe->iType || (pe->iType > ctxVmm->ObjectTypeTable.c)) {
                    continue;
                }
            }
            // fetch pool tag (if found)
            pe->dwPoolTag = VmmWinHandle_InitializeText_GetPoolHeader64(u.pb, &oPoolHdr);
            // fetch remaining object header values
            pe->qwHandleCount = u.O64.Header.HandleCount;
            pe->qwPointerCount = u.O64.Header.PointerCount;
            pe->vaObjectCreateInfo = u.O64.Header.ObjectCreateInfo;
            pe->vaSecurityDescriptor = u.O64.Header.SecurityDescriptor;
            // fetch text description length and address (if possible)
            if(pe->dwPoolTag) {
                pus64 = NULL;
                if((pe->dwPoolTag & 0x00ffffff) == 'yeK') {         // REG KEY
                    if(!VMM_KADDR64(*(PQWORD)(u.O64.pb + 8))) { continue; }
                    if(ObMap_ExistsKey(pmObRegHelperMap, pe->vaObject)) { continue; }
                    if(!(pRegHelp = LocalAlloc(LMEM_ZEROINIT, sizeof(VMMWINHANDLE_REGHELPER)))) { continue; }
                    pRegHelp->vaCmKeyControlBlock = *(PQWORD)(u.O64.pb + 8);
                    ObMap_Push(pmObRegHelperMap, pe->vaObject, pRegHelp);           // map is responsible for free of pRegHelp
                    ObSet_Push(psObRegPrefetch, pRegHelp->vaCmKeyControlBlock);
                } else if((pe->dwPoolTag & 0x00ffffff) == 'orP') {  // PROCESS
                    pe->_Reserved.dw = *(PDWORD)(u.O64.pb + ctxVmm->offset.EPROCESS.PID);
                    cbMultiText += 31 * sizeof(WCHAR) + 2;
                } else if(((pe->dwPoolTag & 0x00ffffff) == 'rhT') && fThreadingEnabled) {   // THREAD
                    if(ctxVmm->offset.ETHREAD.oCid && *(PDWORD)(u.O64.pb + ctxVmm->offset.ETHREAD.oCid + 8)) {
                        pe->_Reserved.dw = *(PDWORD)(u.O64.pb + ctxVmm->offset.ETHREAD.oCid + 8);
                        cbMultiText += 11 * sizeof(WCHAR) + 2;
                    }
                } else if((pe->dwPoolTag & 0x00ffffff) == 'liF') {  // FILE HANDLE
                    pus64 = (PUNICODE_STRING64)(u.O64.pb + O64_FILE_OBJECT_FileName);
                    if((va = *(PQWORD)(u.O64.pb + O64_FILE_OBJECT_SectionObjectPointer)) && VMM_KADDR64_8(va)) {
                        pe->tpInfoEx = HANDLEENTRY_TP_INFO_PRE_1;
                        pe->_Reserved.qw2 = va;
                        ObSet_Push(psObPrefetch, va);
                    }

                } else if(pe->dwPoolTag && (oPoolHdr <= 0x38)) {
                    pus64 = &u.O64.String;
                }
                f = pus64 && (pus64->Length > 2) &&
                    !(pus64->Length & 1) && (pus64->Length < (2 * MAX_PATH)) && (pus64->Length <= pus64->MaximumLength) &&
                    VMM_KADDR64(pus64->Buffer);
                if(f) {
                    cbMultiText += pus64->Length + 2;
                    pe->_Reserved.dw = pus64->Length;
                    pe->_Reserved.qw = pus64->Buffer;
                    ObSet_Push(psObPrefetch, pus64->Buffer);
                }
            }
        }
    }
    // registry key retrieve names
    VmmCachePrefetchPages3(pSystemProcess, psObRegPrefetch, 0x30, 0);
    cbMultiText += VmmWinHandle_InitializeText_DoWork_RegKeyHelper(pSystemProcess, pmObRegHelperMap);
    // create and fill text descriptions
    // also get potential _FILE_OBJECT->SectionObjectPointer->SharedCacheMap (if applicable)
    pHandleMap->wszMultiText = (LPWSTR)pbMultiText = LocalAlloc(LMEM_ZEROINIT, cbMultiText);
    if(!pHandleMap->wszMultiText) { goto fail; }
    pHandleMap->cbMultiText = cbMultiText;
    VmmCachePrefetchPages3(pSystemProcess, psObPrefetch, MAX_PATH * 2, 0);
    ObSet_Clear(psObPrefetch);
    for(i = 0; i < pHandleMap->cMap; i++) {
        pe = pHandleMap->pMap + i;
        if((pe->dwPoolTag & 0x00ffffff) == 'yeK') {         // REG KEY
            if((pRegHelp = ObMap_GetByKey(pmObRegHelperMap, pe->vaObject)) && pRegHelp->KeyInfo.cchName) {
                if(!pRegHelp->cwszText) {
                    pRegHelp->cwszText = swprintf_s((LPWSTR)(pbMultiText + ocbMultiText), 28ULL + pRegHelp->KeyInfo.cchName + 1, L"[%llx:%08x] %s", pRegHelp->vaHive, pRegHelp->KeyInfo.raKeyCell, pRegHelp->KeyInfo.wszName);
                    pRegHelp->wszText = (LPWSTR)(pbMultiText + ocbMultiText);
                    ocbMultiText += pRegHelp->cwszText * sizeof(WCHAR) + 2;
                }
                pe->cwszText = pRegHelp->cwszText;
                pe->wszText = pRegHelp->wszText;
            } else {
                pe->wszText = (LPWSTR)pbMultiText;
            }
        } else if((pe->dwPoolTag & 0x00ffffff) == 'orP') {  // PROCESS
            if((pe->_Reserved.dw < 99999) && (pObProcessHnd = VmmProcessGet(pe->_Reserved.dw))) {
                pe->cwszText = swprintf_s((LPWSTR)(pbMultiText + ocbMultiText), 32, L"PID %i - %S", pObProcessHnd->dwPID, pObProcessHnd->szName);
                pe->wszText = (LPWSTR)(pbMultiText + ocbMultiText);
                ocbMultiText += 31 * sizeof(WCHAR) + 2;
                Ob_DECREF_NULL(&pObProcessHnd);
            } else {
                pe->wszText = (LPWSTR)pbMultiText;
            }
        } else if((pe->dwPoolTag & 0x00ffffff) == 'rhT') {   // THREAD
            if(pe->_Reserved.dw && (pe->_Reserved.dw < 99999)) {
                pe->cwszText = swprintf_s((LPWSTR)(pbMultiText + ocbMultiText), 12, L"TID %i", pe->_Reserved.dw);
                pe->wszText = (LPWSTR)(pbMultiText + ocbMultiText);
                ocbMultiText += 11 * sizeof(WCHAR) + 2;
            } else {
                pe->wszText = (LPWSTR)pbMultiText;
            }
        } else if(pe->_Reserved.qw) {
            if(VmmRead2(pSystemProcess, pe->_Reserved.qw, pbMultiText + ocbMultiText, pe->_Reserved.dw, VMM_FLAG_FORCECACHE_READ)) {
                pe->cwszText = pe->_Reserved.dw >> 1;
                pe->wszText = (LPWSTR)(pbMultiText + ocbMultiText);
                ocbMultiText += pe->_Reserved.dw + 2;
            }
        } else {
            pe->wszText = (LPWSTR)pbMultiText;
        }
        // Process _SECTION_OBJECT_POINTERS DataSectionObject&SharedCacheMap:
        if((pe->tpInfoEx == HANDLEENTRY_TP_INFO_PRE_1) && VmmRead2(pSystemProcess, pe->_Reserved.qw2, u.pb, 0x18, VMM_FLAG_FORCECACHE_READ)) {
            pe->_InfoFile.cb = 0;
            f = VMM_KADDR_4_8((va = VMM_PTR_OFFSET_DUAL(ctxVmm->f32, u.pb, O32_SECTION_OBJECT_POINTERS_SharedCacheMap, O64_SECTION_OBJECT_POINTERS_SharedCacheMap))) ||
                VMM_KADDR_4_8((va = VMM_PTR_OFFSET_DUAL(ctxVmm->f32, u.pb, O32_SECTION_OBJECT_POINTERS_DataSectionObject, O64_SECTION_OBJECT_POINTERS_DataSectionObject)));
            if(f) {
                pe->_Reserved.qw = va;
                pe->tpInfoEx = HANDLEENTRY_TP_INFO_FILE;
                ObSet_Push(psObPrefetch, va - 0x10);
            }
        }
    }
    // retrieve (if applicable) file sizes
    VmmWinHandle_InitializeText_DoWork_FileSizeHelper(pSystemProcess, psObPrefetch, pHandleMap);
fail:
    Ob_DECREF(psObPrefetch);
    Ob_DECREF(psObRegPrefetch);
    Ob_DECREF(pmObRegHelperMap);
}

VOID VmmWinHandle_InitializeCore_DoWork(_In_ PVMM_PROCESS pSystemProcess, _In_ PVMM_PROCESS pProcess)
{
    BOOL fResult = FALSE;
    BOOL f32 = ctxVmm->f32;
    BYTE pb[0x20], iLevel;
    WORD oTableCode;
    DWORD i, cHandles, iHandleMap = 0;
    QWORD vaHandleTable = 0, vaTableCode = 0;
    VMMWIN_INITIALIZE_HANDLE_CONTEXT ctx = { 0 };
    PVMMOB_MAP_HANDLE pObHandleMap = NULL;
    ctx.pSystemProcess = pSystemProcess;
    ctx.pProcess = pProcess;
    vaHandleTable = VMM_PTR_OFFSET(f32, pProcess->win.EPROCESS.pb, ctxVmm->offset.EPROCESS.ObjectTable);
    if(!VMM_KADDR(vaHandleTable) || !VmmRead(pSystemProcess, vaHandleTable - 0x10, pb, 0x20)) { return; }
    if(!VMM_POOLTAG_PREPENDED(pb, 0x10, 'Obtb') && !VMM_KADDR_PAGE(vaHandleTable)) { return; }
    oTableCode = (ctxVmm->kernel.dwVersionBuild < 9200) ? 0 : 8;    // WinXP::Win7 -> 0, otherwise 8.
    vaTableCode = VMM_PTR_OFFSET(f32, pb + 0x10, oTableCode) & ~7;
    iLevel = VMM_PTR_OFFSET(f32, pb + 0x10, oTableCode) & 7;
    if((iLevel > 2) || !VMM_KADDR_PAGE(vaTableCode)) { return; }
    ctx.cTablesMax = f32 ? 1024 : 512;
    ctx.cTablesMax = iLevel ? ((iLevel == 1) ? (ctx.cTablesMax * ctx.cTablesMax) : ctx.cTablesMax) : 1;
    if(!(ctx.pvaTables = LocalAlloc(0, ctx.cTablesMax * sizeof(QWORD)))) { return; }
    if(iLevel) {
        VmmWinHandle_InitializeCore_SpiderTables(&ctx, vaTableCode, (iLevel == 2));
    } else {
        ctx.cTables = 1;
        ctx.pvaTables[0] = vaTableCode;
    }
    // count handles and allocate map
    if(!(cHandles = VmmWinHandle_InitializeCore_CountHandles(&ctx))) { goto fail; }
    cHandles = min(cHandles, 256 * 1024);
    ctx.pHandleMap = pObHandleMap = Ob_Alloc(OB_TAG_MAP_HANDLE, LMEM_ZEROINIT, sizeof(VMMOB_MAP_HANDLE) + cHandles * sizeof(VMM_MAP_HANDLEENTRY), VmmWinHandle_CloseObCallback, NULL);
    if(!pObHandleMap) { goto fail; }
    pObHandleMap->cMap = cHandles;
    // walk handle tables to fill map with core handle information
    for(i = 0; i < ctx.cTables; i++) {
        VmmWinHandle_InitializeCore_ReadHandleTable(&ctx, ctx.pvaTables[i], i * (f32 ? 2048 : 1024));
    }
    pProcess->Map.pObHandle = Ob_INCREF(pObHandleMap);
fail:
    LocalFree(ctx.pvaTables);
    Ob_DECREF(pObHandleMap);
}

_Success_(return)
BOOL VmmWinHandle_InitializeCore(_In_ PVMM_PROCESS pProcess)
{
    PVMM_PROCESS pObSystemProcess;
    if(pProcess->Map.pObHandle) { return TRUE; }
    EnterCriticalSection(&pProcess->LockUpdate);
    if(!pProcess->Map.pObHandle && (pObSystemProcess = VmmProcessGet(4))) {
        VmmWinHandle_InitializeCore_DoWork(pObSystemProcess, pProcess);
        if(!pProcess->Map.pObHandle) {
            pProcess->Map.pObHandle = Ob_Alloc(OB_TAG_MAP_HANDLE, LMEM_ZEROINIT, sizeof(VMMOB_MAP_HANDLE), VmmWinHandle_CloseObCallback, NULL);
        }
        Ob_DECREF(pObSystemProcess);
    }
    LeaveCriticalSection(&pProcess->LockUpdate);
    return pProcess->Map.pObHandle ? TRUE : FALSE;
}

_Success_(return)
BOOL VmmWinHandle_InitializeText(_In_ PVMM_PROCESS pProcess)
{
    PVMM_PROCESS pObSystemProcess;
    if(pProcess->Map.pObHandle->wszMultiText) { return TRUE; }
    EnterCriticalSection(&pProcess->Map.LockUpdateExtendedInfo);
    if(!pProcess->Map.pObHandle->wszMultiText && (pObSystemProcess = VmmProcessGet(4))) {
        VmmWinHandle_InitializeText_DoWork(pObSystemProcess, pProcess->Map.pObHandle);
        Ob_DECREF(pObSystemProcess);
    }
    LeaveCriticalSection(&pProcess->Map.LockUpdateExtendedInfo);
    return pProcess->Map.pObHandle->wszMultiText ? TRUE : FALSE;
}

/*
* Initialize Handles for a specific process. Extended information text may take
* extra time to initialize.
* -- pProcess
* -- fExtendedText = also fetch extended info such as handle paths/names.
* -- return
*/
_Success_(return)
BOOL VmmWinHandle_Initialize(_In_ PVMM_PROCESS pProcess, _In_ BOOL fExtendedText)
{
    if(pProcess->Map.pObHandle && (!fExtendedText || pProcess->Map.pObHandle->wszMultiText)) { return TRUE; }
    VmmTlbSpider(pProcess);
    return VmmWinHandle_InitializeCore(pProcess) && (!fExtendedText || VmmWinHandle_InitializeText(pProcess));
}

// ----------------------------------------------------------------------------
// PHYSICAL MEMORY MAP FUNCTIONALITY BELOW:
//
// The physical memory map functionality is responsible for retrieving the
// physical memory map from the Windows registry (if possible).
// ----------------------------------------------------------------------------

#pragma pack(push, 1) /* DISABLE STRUCT PADDINGS (REENABLE AFTER STRUCT DEFINITIONS) */
typedef struct tdVMMWIN_PHYSMEMMAP_MEMORY_RANGE32 {
    UCHAR Type;
    UCHAR ShareDisposition;
    USHORT Flags;
    QWORD pa;
    DWORD cb;
} VMMWIN_PHYSMEMMAP_MEMORY_RANGE32, *PVMMWIN_PHYSMEMMAP_MEMORY_RANGE32;

typedef struct tdVMMWIN_PHYSMEMMAP_MEMORY_RANGE64 {
    UCHAR Type;
    UCHAR ShareDisposition;
    USHORT Flags;
    QWORD pa;
    QWORD cb;
} VMMWIN_PHYSMEMMAP_MEMORY_RANGE64, *PVMMWIN_PHYSMEMMAP_MEMORY_RANGE64;
#pragma pack(pop) /* RE-ENABLE STRUCT PADDINGS */

PVMMOB_MAP_PHYSMEM VmmWinPhysMemMap_Initialize_DoWork()
{
    BOOL f32 = ctxVmm->f32;
    DWORD cMap, cbData = 0;
    PBYTE pbData = NULL;
    QWORD c1, i, o;
    PVMMWIN_PHYSMEMMAP_MEMORY_RANGE32 pMR32;
    PVMMWIN_PHYSMEMMAP_MEMORY_RANGE64 pMR64;
    PVMMOB_MAP_PHYSMEM pObPhysMemMap = NULL;
    // 1: fetch binary data from registry
    if(!VmmWinReg_ValueQuery2(L"HKLM\\HARDWARE\\RESOURCEMAP\\System Resources\\Physical Memory\\.Translated", NULL, NULL, 0, &cbData) || !cbData) { goto fail; }
    if(!(pbData = LocalAlloc(0, cbData))) { goto fail; }
    if(!VmmWinReg_ValueQuery2(L"HKLM\\HARDWARE\\RESOURCEMAP\\System Resources\\Physical Memory\\.Translated", NULL, pbData, cbData, &cbData)) { goto fail; }
    if(cbData < (DWORD)(f32 ? 0x18 : 0x28)) { goto fail; }
    // 2: fetch number of memory regions and allocate map object.
    c1 = *(PQWORD)pbData;
    if(!c1) { goto fail; }
    o = 0x10;
    cMap = *(PDWORD)(pbData + o); // this should be loop in case of c1 > 1, but works for now ...
    if(f32 && (!cMap || (cbData < cMap * sizeof(VMMWIN_PHYSMEMMAP_MEMORY_RANGE32) + 0x0c))) { goto fail; }
    if(!f32 && (!cMap || (cbData < cMap * sizeof(VMMWIN_PHYSMEMMAP_MEMORY_RANGE64) + 0x14))) { goto fail; }
    if(!(pObPhysMemMap = Ob_Alloc(OB_TAG_MAP_PHYSMEM, LMEM_ZEROINIT, sizeof(VMMOB_MAP_PHYSMEM) + cMap * sizeof(VMM_MAP_PHYSMEMENTRY), NULL, NULL))) { goto fail; }
    pObPhysMemMap->cMap = cMap;
    // 3: iterate over the memory regions.
    o += sizeof(DWORD);
    for(i = 0; i < cMap; i++) {
        if(f32) {
            pMR32 = (PVMMWIN_PHYSMEMMAP_MEMORY_RANGE32)(pbData + o + i * sizeof(VMMWIN_PHYSMEMMAP_MEMORY_RANGE32));
            pObPhysMemMap->pMap[i].pa = pMR32->pa;
            pObPhysMemMap->pMap[i].cb = pMR32->cb;
            if(pMR32->Flags & 0xff00) {
                pObPhysMemMap->pMap[i].cb = pObPhysMemMap->pMap[i].cb << 8;
            }
        } else {
            pMR64 = (PVMMWIN_PHYSMEMMAP_MEMORY_RANGE64)(pbData + o + i * sizeof(VMMWIN_PHYSMEMMAP_MEMORY_RANGE64));
            pObPhysMemMap->pMap[i].pa = pMR64->pa;
            pObPhysMemMap->pMap[i].cb = pMR64->cb;
            if(pMR64->Flags & 0xff00) {
                pObPhysMemMap->pMap[i].cb = pObPhysMemMap->pMap[i].cb << 8;
            }
        }
        if((pObPhysMemMap->pMap[i].pa & 0xfff) || (pObPhysMemMap->pMap[i].cb & 0xfff)) { goto fail; }
    }
    return pObPhysMemMap;
fail:
    Ob_DECREF(pObPhysMemMap);
    LocalFree(pbData);
    return NULL;
}

/*
* Create a physical memory map and assign to the global context upon success.
* CALLER DECREF: return
* -- return
*/
PVMMOB_MAP_PHYSMEM VmmWinPhysMemMap_Initialize()
{
    PVMMOB_MAP_PHYSMEM pObPhysMem;
    if((pObPhysMem = ObContainer_GetOb(ctxVmm->pObCMapPhysMem))) { return pObPhysMem; }
    EnterCriticalSection(&ctxVmm->LockUpdateMap);
    if((pObPhysMem = ObContainer_GetOb(ctxVmm->pObCMapPhysMem))) {
        LeaveCriticalSection(&ctxVmm->LockUpdateMap);
        return pObPhysMem;
    }
    pObPhysMem = VmmWinPhysMemMap_Initialize_DoWork();
    if(!pObPhysMem) {
        pObPhysMem = Ob_Alloc(OB_TAG_MAP_PHYSMEM, LMEM_ZEROINIT, sizeof(VMMOB_MAP_PHYSMEM), NULL, NULL);
    }
    ObContainer_SetOb(ctxVmm->pObCMapPhysMem, pObPhysMem);
    LeaveCriticalSection(&ctxVmm->LockUpdateMap);
    return pObPhysMem;
}

/*
* Refresh the physical memory map.
*/
VOID VmmWinPhysMemMap_Refresh()
{
    ObContainer_SetOb(ctxVmm->pObCMapPhysMem, NULL);
}

// ----------------------------------------------------------------------------
// USER FUNCTIONALITY BELOW:
//
// The user functionality is responsible for creating the user map consisting
// of non-built-in users and also for retrieving account names for SIDs - both
// well known and system-specific.
// ----------------------------------------------------------------------------

/*
* Retrieve the account name and length of the user account given a SID.
* NB! Names for well known SIDs will be given in the language of the system
* running MemProcFS and not in the name of the analyzed system.
* -- pSID
* -- wszName
* -- cwszName
* -- pcwszName
* -- fAccountWellKnown
* -- return
*/
_Success_(return)
BOOL VmmWinUser_GetNameW(_In_opt_ PSID pSID, _Out_writes_opt_(cwszName) LPWSTR wszName, _In_ DWORD cwszName, _Out_opt_ PDWORD pcwszName, _Out_opt_ PBOOL pfAccountWellKnown)
{
    BOOL f;
    SID_NAME_USE eUse;
    DWORD i, cwszNameBuffer = MAX_PATH, cwszDomainBuffer = MAX_PATH, dwHashSID;
    WCHAR wszNameBuffer[MAX_PATH+1], wszDomainBuffer[MAX_PATH+1];
    LPSTR szSID = NULL;
    PVMMOB_MAP_USER pObUser = NULL;
    if(!pSID) { return FALSE; }
    if(pfAccountWellKnown) { *pfAccountWellKnown = FALSE; }
    // 1: Try lookup name from User Map
    if(!ConvertSidToStringSidA(pSID, &szSID)) { return FALSE; }
    dwHashSID = Util_HashStringA(szSID);
    LocalFree(szSID);
    if(VmmMap_GetUser(&pObUser)) {
        for(i = 0; i < pObUser->cMap; i++) {
            if(dwHashSID != pObUser->pMap[i].dwHashSID) { continue; }
            // user entry located
            if(pcwszName) {
                *pcwszName = pObUser->pMap[i].cwszText;
                if(!wszName) {
                    Ob_DECREF(pObUser);
                    return TRUE;
                }
            }
            if(cwszName >= pObUser->pMap[i].cwszText) {
                wcscpy_s(wszName, cwszName, pObUser->pMap[i].wszText);
                Ob_DECREF(pObUser);
                return TRUE;
            }
            Ob_DECREF(pObUser);
            return FALSE;
        }
        Ob_DECREF_NULL(&pObUser);
    }
    // 2: Try lookup name from Well Known SID
    f = LookupAccountSidW(NULL, pSID, wszNameBuffer, &cwszNameBuffer, wszDomainBuffer, &cwszDomainBuffer, &eUse);
    if(cwszDomainBuffer != MAX_PATH) {
        if(pfAccountWellKnown) { *pfAccountWellKnown = TRUE; }
        if(pcwszName) {
            *pcwszName = (cwszNameBuffer == MAX_PATH) ? 0 : cwszNameBuffer;
            if(!wszName) { return TRUE; }
        }
        if(f && wszName && (cwszName >= cwszNameBuffer)) {
            wcscpy_s(wszName, cwszName, wszNameBuffer);
            return TRUE;
        }
        return FALSE;
    }
    return FALSE;
}

/*
* Object manager callback function for object cleanup tasks.
* -- pVmmUserMap
*/
VOID VmmWinUser_CloseObCallback(_In_ PVOID pVmmUserMap)
{
    PVMMOB_MAP_USER pOb = (PVMMOB_MAP_USER)pVmmUserMap;
    DWORD i;
    for(i = 0; i < pOb->cMap; i++) {
        LocalFree(pOb->pMap[i].pSID);
        LocalFree(pOb->pMap[i].szSID);
    }
    LocalFree(pOb->wszMultiText);
}

/*
* Create a user map and assign it to the ctxVmm global context upon success.
* NB! function must be called in single-threaded context.
* CALLER DECREF: return
* -- return
*/
PVMMOB_MAP_USER VmmWinUser_Initialize_DoWork()
{
    typedef struct tdVMMWINUSER_CONTEXT_ENTRY {
        PSID pSID;
        DWORD cbSID;
        LPSTR szSID;
        DWORD dwHashSID;
        QWORD vaHive;
        DWORD cchUser;
        WCHAR wszUser[MAX_PATH];
    } VMMWINUSER_CONTEXT_ENTRY, *PVMMWINUSER_CONTEXT_ENTRY;
    DWORD i, dwType, cchUserTotal = 1, oMultiText = 1;
    LPSTR szNtdat, szUser;
    LPWSTR wszSymlinkSid, wszSymlinkUser;
    WCHAR wszSymlinkValue[MAX_PATH];
    POB_REGISTRY_HIVE pObHive = NULL;
    POB_SET pObSet = NULL;
    PVMMWINUSER_CONTEXT_ENTRY e = NULL;
    PVMMOB_MAP_USER pObMapUser = NULL;
    PVMM_MAP_USERENTRY pe;
    if(!(pObSet = ObSet_New())) { goto fail; }
    // 1: user hive enumeration
    while((pObHive = VmmWinReg_HiveGetNext(pObHive))) {
        if(!e && !(e = LocalAlloc(0, sizeof(VMMWINUSER_CONTEXT_ENTRY)))) { continue; }
        ZeroMemory(e, sizeof(VMMWINUSER_CONTEXT_ENTRY));
        szUser = StrStrIA(pObHive->szName, "-USER_S-");
        szNtdat = StrStrIA(pObHive->szName, "-ntuserdat-");
        if(!szNtdat && !szUser) { continue; }
        if(!szUser && !StrStrIA(szNtdat, "-unknown")) { continue; }
        if(szUser && ((strlen(szUser) < 20) || StrStrIA(szUser, "Classes"))) { continue; }
        // get username
        if(!VmmWinReg_ValueQuery1(pObHive, L"ROOT\\Volatile Environment\\USERNAME", &dwType, (PBYTE)e->wszUser, sizeof(e->wszUser) - 2, NULL, 0) || (dwType != REG_SZ)) {
            if(ctxVmm->kernel.dwVersionBuild > 2600) { continue; }      // allow missing USERNAME if WinXP
        }
        // get sid
        if(szUser) {
            ConvertStringSidToSidA(szUser + 6, &e->pSID);
        }
        if(!e->pSID) {
            i = 0;
            ZeroMemory(wszSymlinkValue, sizeof(wszSymlinkValue));
            if(!VmmWinReg_ValueQuery1(pObHive, L"ROOT\\Software\\Classes\\SymbolicLinkValue", &dwType, (PBYTE)wszSymlinkValue, sizeof(wszSymlinkValue) - 2, NULL, 0) || (dwType != REG_LINK)) { continue; }
            if(!(wszSymlinkSid = wcsstr(wszSymlinkValue, L"\\S-"))) { continue; }
            if(wcslen(wszSymlinkSid) < 20) { continue; }
            while(wszSymlinkSid[i] && (wszSymlinkSid[i] != L'_') && ++i);
            wszSymlinkSid[i] = 0;
            if(!ConvertStringSidToSidW(wszSymlinkSid + 1, &e->pSID) || !e->pSID) { continue; }
        }
        // get username - WinXP only
        if(!e->wszUser[0]) {
            i = 0;
            wszSymlinkUser = wszSymlinkValue + 10;
            while(wszSymlinkUser[i] && (wszSymlinkUser[i] != L'\\') && ++i);
            if(i == 0) { continue; }
            wszSymlinkUser[i] = 0;
            wcsncpy_s(e->wszUser, MAX_PATH, wszSymlinkUser, _TRUNCATE);
        }
        // get length and hash of sid string
        e->vaHive = pObHive->vaCMHIVE;
        e->cbSID = GetLengthSid(e->pSID);
        if(!e->cbSID || !ConvertSidToStringSidA(e->pSID, &e->szSID) || !e->szSID) {
            LocalFree(e->pSID);
            continue;
        }
        e->dwHashSID = Util_HashStringA(e->szSID);
        // store context in map
        e->cchUser = (DWORD)wcslen(e->wszUser);
        cchUserTotal += e->cchUser + 1;
        ObSet_Push(pObSet, (QWORD)e);
        e = NULL;
    }
    LocalFree(e);
    // 2: create user map and assign data
    if(!(pObMapUser = Ob_Alloc(OB_TAG_MAP_USER, LMEM_ZEROINIT, sizeof(VMMOB_MAP_USER) + ObSet_Size(pObSet) * sizeof(VMM_MAP_USERENTRY), VmmWinUser_CloseObCallback, NULL))) { goto fail; }
    pObMapUser->cMap = ObSet_Size(pObSet);
    pObMapUser->cbMultiText = cchUserTotal * sizeof(WCHAR);
    if(!(pObMapUser->wszMultiText = LocalAlloc(LMEM_ZEROINIT, pObMapUser->cbMultiText))) { goto fail; }
    for(i = 0; i < pObMapUser->cMap; i++) {
        if(!(e = (PVMMWINUSER_CONTEXT_ENTRY)ObSet_Pop(pObSet))) { goto fail; }
        pe = pObMapUser->pMap + i;
        pe->pSID = e->pSID;
        pe->cbSID = e->cbSID;
        pe->szSID = e->szSID;
        pe->dwHashSID = e->dwHashSID;
        pe->vaRegHive = e->vaHive;
        pe->cwszText = e->cchUser;
        pe->wszText = pObMapUser->wszMultiText + oMultiText;
        memcpy(pe->wszText, e->wszUser, pe->cwszText * sizeof(WCHAR));
        oMultiText += e->cchUser + 1;
        LocalFree(e);
    }
    // finish & return
    Ob_DECREF(pObSet);
    return pObMapUser;
fail:
    Ob_DECREF(pObMapUser);
    if(pObSet) {
        while((e = (PVMMWINUSER_CONTEXT_ENTRY)ObSet_Pop(pObSet))) {
            LocalFree(e->pSID);
            LocalFree(e->szSID);
            LocalFree(e);
        }
        Ob_DECREF(pObSet);
    }
    return NULL;
}

/*
* Create a user map and assign to the global context upon success.
* CALLER DECREF: return
* -- return
*/
PVMMOB_MAP_USER VmmWinUser_Initialize()
{
    PVMMOB_MAP_USER pObUser;
    if((pObUser = ObContainer_GetOb(ctxVmm->pObCMapUser))) { return pObUser; }
    EnterCriticalSection(&ctxVmm->LockUpdateMap);
    if((pObUser = ObContainer_GetOb(ctxVmm->pObCMapUser))) {
        LeaveCriticalSection(&ctxVmm->LockUpdateMap);
        return pObUser;
    }
    pObUser = VmmWinUser_Initialize_DoWork();
    if(!pObUser) {
        pObUser = Ob_Alloc(OB_TAG_MAP_USER, LMEM_ZEROINIT, sizeof(VMMOB_MAP_USER), NULL, NULL);
        if(pObUser) {
            pObUser->wszMultiText = (LPWSTR)&pObUser->cbMultiText;   // NULL CHAR guaranteed.
        }
    }
    ObContainer_SetOb(ctxVmm->pObCMapUser, pObUser);
    LeaveCriticalSection(&ctxVmm->LockUpdateMap);
    return pObUser;
}

/*
* Refresh the user map.
*/
VOID VmmWinUser_Refresh()
{
    ObContainer_SetOb(ctxVmm->pObCMapUser, NULL);
}

// ----------------------------------------------------------------------------
// WINDOWS EPROCESS WALKING FUNCTIONALITY FOR 64/32 BIT BELOW:
// ----------------------------------------------------------------------------

#define VMMPROC_EPROCESS64_MAX_SIZE       0x800
#define VMMPROC_EPROCESS32_MAX_SIZE       0x480

VOID VmmWin_OffsetLocatorEPROCESS_Print()
{
    PVMM_OFFSET_EPROCESS po = &ctxVmm->offset.EPROCESS;
    vmmprintf_fn("OK: %s \n" \
        "    PID:  %03x PPID: %03x STAT: %03x DTB:  %03x DTBU: %03x NAME: %03x PEB: %03x\n" \
        "    FLnk: %03x BLnk: %03x oMax: %03x SeAu: %03x VadR: %03x ObjT: %03x WoW: %03x\n",
        po->fValid ? "TRUE" :  "FALSE",
        po->PID, po->PPID, po->State, po->DTB, po->DTB_User, po->Name, po->PEB,
        po->FLink, po->BLink, po->cbMaxOffset, po->SeAuditProcessCreationInfo, po->VadRoot, po->ObjectTable, po->Wow64Process
    );
}

VOID VmmWin_OffsetLocatorEPROCESS_SetMaxOffset()
{
    PVMM_OFFSET_EPROCESS po = &ctxVmm->offset.EPROCESS;
    WORD o;
    o = max(po->opt.CreateTime, po->opt.ExitTime);
    o = max(max(o, po->State), max(po->DTB, po->DTB_User));
    o = max(max(o, po->Name), max(po->PID, po->PPID));
    o = max(max(o, po->PEB), max(po->FLink, po->BLink));
    o = max(max(o, po->SeAuditProcessCreationInfo), max(po->VadRoot, po->ObjectTable));
    po->cbMaxOffset = o + 0x30;
}

/*
* Very ugly hack that tries to locate some offsets required withn the EPROCESS struct.
*/
VOID VmmWin_OffsetLocatorEPROCESS64(_In_ PVMM_PROCESS pSystemProcess)
{
    PVMM_OFFSET_EPROCESS po = &ctxVmm->offset.EPROCESS;
    BOOL f;
    WORD i, j, cLoopProtect;
    QWORD va1, vaPEB, paPEB, vaP, oP;
    BYTE pbSYSTEM[VMMPROC_EPROCESS64_MAX_SIZE], pbSMSS[VMMPROC_EPROCESS64_MAX_SIZE], pb1[VMMPROC_EPROCESS64_MAX_SIZE], pbPage[0x1000];
    BYTE pbZero[0x800];
    QWORD paMax, paDTB_0, paDTB_1;
    POB_SET psObOff = NULL, psObVa = NULL;
    ZeroMemory(po, sizeof(VMM_OFFSET_EPROCESS));
    if(!VmmRead(pSystemProcess, pSystemProcess->win.EPROCESS.va, pbSYSTEM, VMMPROC_EPROCESS64_MAX_SIZE)) { return; }
    if(ctxMain->cfg.fVerboseExtra) {
        vmmprintf_fn("SYSTEM DTB: %016llx EPROCESS: %016llx\n", pSystemProcess->paDTB, pSystemProcess->win.EPROCESS.va);
        Util_PrintHexAscii(pbSYSTEM, VMMPROC_EPROCESS64_MAX_SIZE, 0);
    }
    // find offset State (static for now)
    if(*(PDWORD)(pbSYSTEM + 0x04)) { return; }
    po->State = 0x04;
    // find offset PML4 (static for now)
    if(pSystemProcess->paDTB != (0xfffffffffffff000 & *(PQWORD)(pbSYSTEM + 0x28))) { return; }
    po->DTB = 0x28;
    // find offset for Name
    for(i = 0, f = FALSE; i < VMMPROC_EPROCESS64_MAX_SIZE - 8; i += 8) {
        if(*(PQWORD)(pbSYSTEM + i) == 0x00006D6574737953) {
            po->Name = i;
            f = TRUE;
            break;
        }
    }
    if(!f) { return; }
    // find offset for PID, FLink, BLink (assumed to be following eachother)
    for(i = 0, f = FALSE; i < VMMPROC_EPROCESS64_MAX_SIZE - 8; i += 8) {
        if(*(PQWORD)(pbSYSTEM + i) == 4) {
            // PID = correct, this is a candidate
            if(0xffff000000000000 != (0xffff000000000003 & *(PQWORD)(pbSYSTEM + i + 8))) { continue; }    // FLink not valid kernel pointer
            va1 = *(PQWORD)(pbSYSTEM + i + 8) - i - 8;
            f = VmmRead(pSystemProcess, va1, pb1, VMMPROC_EPROCESS64_MAX_SIZE);
            if(!f) { continue; }
            f = FALSE;
            if((*(PQWORD)(pb1 + po->Name) != 0x6578652e73736d73) &&    // smss.exe
                (*(PQWORD)(pb1 + po->Name) != 0x7972747369676552) &&   // Registry
                (*(PQWORD)(pb1 + po->Name) != 0x5320657275636553))     // Secure System
            {
                continue;
            }
            if((*(PQWORD)(pb1 + i + 16) - i - 8) != pSystemProcess->win.EPROCESS.va) {
                continue;
            }
            po->PID = i;
            po->FLink = i + 8;
            po->BLink = i + 16;
            f = TRUE;
            break;
        }
    }
    if(!f) { return; }
    // find and read smss.exe
    {
        cLoopProtect = 0;
        memcpy(pbSMSS, pbSYSTEM, VMMPROC_EPROCESS64_MAX_SIZE);
        while(++cLoopProtect < 8) {
            va1 = *(PQWORD)(pbSMSS + po->FLink) - po->FLink;
            f = VmmRead(pSystemProcess, va1, pbSMSS, VMMPROC_EPROCESS64_MAX_SIZE) &&
                (*(PQWORD)(pbSMSS + po->Name) == 0x6578652e73736d73);
            if(f) { break; }
        }
        if(!f) { return; }
        if(ctxMain->cfg.fVerboseExtra) {
            vmmprintf_fn("EPROCESS smss.exe BELOW:\n");
            Util_PrintHexAscii(pbSMSS, VMMPROC_EPROCESS64_MAX_SIZE, 0);
        }
    }
    // find offset for ParentPid (_EPROCESS!InheritedFromUniqueProcessId)
    // (parent pid is assumed to be located between BLink and Name
    {
        for(i = po->BLink; i < po->Name; i += 8) {
            if((*(PQWORD)(pbSYSTEM + i) == 0) && (*(PQWORD)(pbSMSS + i) == 4)) {
                po->PPID = i;
                break;
            }
        }
        if(!po->PPID) { return; }
    }
    // find offset for PEB (in EPROCESS) by comparing SYSTEM and SMSS  [or other process on fail - max 4 tries]
    {
        for(j = 0; j < 4; j++) {
            for(i = 0x280, f = FALSE; i < 0x580; i += 8) {
                if(*(PQWORD)(pbSYSTEM + i)) { continue; }
                vaPEB = *(PQWORD)(pbSMSS + i);
                if(!vaPEB || (vaPEB & 0xffff800000000fff)) { continue; }
                // Verify potential PEB
                if(!VmmVirt2PhysEx(*(PQWORD)(pbSMSS + po->DTB), TRUE, vaPEB, &paPEB)) { continue; }
                if(!VmmReadPage(NULL, paPEB, pbPage)) { continue; }
                if(*(PWORD)pbPage == 0x5a4d) { continue; }  // MZ header -> likely entry point or something not PEB ...
                po->PEB = i;
                f = TRUE;
                break;
            }
            if(f) { break; }
            // failed locating PEB (paging?) -> try next process in EPROCESS list.
            va1 = *(PQWORD)(pbSMSS + po->FLink) - po->FLink;
            if(!VmmRead(pSystemProcess, va1, pbSMSS, VMMPROC_EPROCESS64_MAX_SIZE)) { return; }
        }
        if(!f) { return; }
    }
    // Wow64Process offset - "static" rule.
    {
        if(po->Name < po->PEB) {
            po->f64VistaOr7 = TRUE;
            po->Wow64Process = po->Name + 0x40;     // Vista, Win7
        } else {
            po->Wow64Process = po->PEB + 0x30;      // Win8, Win10
        }
    }
    // locate various offsets primarily by reading pointers and checking pool
    // headers in an efficient way (minimize number of reads).
    {
        if(!(psObVa = ObSet_New())) { goto fail; }
        if(!(psObOff = ObSet_New())) { goto fail; }
        // ObjectTable candidate pointers
        for(i = po->Name - 0x0e0; i < po->Name - 0x020; i += 8) {
            if(VMM_KADDR64_16(*(PQWORD)(pbSYSTEM + i))) {
                ObSet_Push(psObOff, (i << 16) | 1);
                ObSet_Push(psObVa, *(PQWORD)(pbSYSTEM + i) - 0x10);
            }
        }
        // SeAuditProcessCreationInfo candidate pointers by looking at SMSS.
        // Offset is located between PEB+0x058 and PEB+0x070 as observed so far.
        // Look at some extra offsets just in case for the future.
        for(i = 0x058 + po->PEB; i < 0x090 + po->PEB; i += 8) {
            if(VMM_KADDR64_8(*(PQWORD)(pbSMSS + i))) {
                ObSet_Push(psObOff, (i << 16) | 2);
                ObSet_Push(psObVa, *(PQWORD)(pbSMSS + i));
            }
        }
        // prefetch result into cache
        VmmCachePrefetchPages3(pSystemProcess, psObVa, 0x40, 0);
        // interpret result
        while(ObSet_Size(psObVa)) {
            oP = ObSet_Pop(psObOff);
            vaP = ObSet_Pop(psObVa);
            if(!VmmRead2(pSystemProcess, vaP, pbPage, 0x40, VMM_FLAG_FORCECACHE_READ)) { continue; }
            // ObjectTable
            f = (1 == (oP & 0xff)) && (*(PDWORD)(pbPage + 4) == 0x6274624f);  // Pool Header: Obtb
            if(f) { po->ObjectTable = (WORD)(oP >> 16); }
            f = (1 == (oP & 0xff)) && VMM_KADDR64_PAGE(vaP + 0x10) && !*(PQWORD)(pbPage + 0x10 + 0x10) && VMM_KADDR64_8(*(PQWORD)(pbPage + 0x10 + 0x18)) && VMM_KADDR64_8(*(PQWORD)(pbPage + 0x10 + 0x20));     // page-align (no pool hdr)
            if(f) { po->ObjectTable = (WORD)(oP >> 16); }
            // SeAuditProcessCreationInfo
            f = (2 == (oP & 0xff)) &&
                (*(PQWORD)(pbPage + 0x10) == 0x007600650044005C) && (*(PQWORD)(pbPage + 0x18) == 0x005C006500630069) && // L"\Device\"
                (*(PWORD)(pbPage + 0x00) < MAX_PATH) && (*(PWORD)(pbPage + 0x00) < *(PWORD)(pbPage + 0x02));            // _UNICODE_STRING length
            if(f) { po->SeAuditProcessCreationInfo = (WORD)(oP >> 16); }
        }
        // check validity
        if(!po->ObjectTable) { goto fail; }
        if(!po->SeAuditProcessCreationInfo) { goto fail; }
    }
    // find offset for VadRoot by searching for ExitStatus value assumed to be
    // set to: 0x00000103 and existing prior to VadRoot by -12(VISTA)/-4(Win7+)
    {
        for(i = 0x140 + po->Name; i < 0x7f0; i += 8) {
            f = VMM_KADDR64(*(PQWORD)(pbSYSTEM + i)) && ((*(PDWORD)(pbSYSTEM + i - 4) == 0x00000103) || (*(PDWORD)(pbSYSTEM + i - 12) == 0x00000103));
            if(f) { break; }
        }
        if(!f) { return; }
        po->VadRoot = i;
    }
    // find "optional" offset for user cr3/pml4 (post meltdown only)
    // System have an entry pointing to a shadow PML4 which has empty user part
    // smss.exe do not have an entry since it's running as admin ...
    {
        ZeroMemory(pbZero, 0x800);
        paMax = ctxMain->dev.paMax;
        for(i = po->DTB + 8; i < VMMPROC_EPROCESS64_MAX_SIZE - 8; i += 8) {
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
                po->DTB_User = i;
                break;
            }
        }
    }
    VmmWin_OffsetLocatorEPROCESS_SetMaxOffset();
    po->fValid = TRUE;
fail:
    Ob_DECREF(psObVa);
    Ob_DECREF(psObOff);
}

/*
* Post-process new process in the "new" process table before they are comitted VmmProcessCreateFinish()
* At this moment "only" the full path and name is retrieved by using 'SeAuditProcessCreationInfo'.
* -- pSystemProcess
*/
VOID VmmWin_EnumerateEPROCESS_PostProcessing(_In_ PVMM_PROCESS pSystemProcess)
{
    DWORD i;
    LPWSTR wszPathKernel;
    POB_SET pObPrefetchAddr = NULL;
    PVMM_PROCESS pObProcess = NULL;
    PVMMOB_PROCESS_TABLE ptObCurrent = NULL, ptObNew = NULL;
    PVMMOB_PROCESS_PERSISTENT pProcPers;
    if(!(pObPrefetchAddr = ObSet_New())) { goto fail; }
    if(!(ptObCurrent = (PVMMOB_PROCESS_TABLE)ObContainer_GetOb(ctxVmm->pObCPROC))) { goto fail; }
    if(!(ptObNew = (PVMMOB_PROCESS_TABLE)ObContainer_GetOb(ptObCurrent->pObCNewPROC))) { goto fail; }
    // 1: Iterate to gather memory locations of "SeAuditProcessCreationInfo" / "kernel path" for new processes
    while((pObProcess = VmmProcessGetNextEx(ptObNew, pObProcess, VMM_FLAG_PROCESS_SHOW_TERMINATED))) {
        if(!pObProcess->pObPersistent->fIsPostProcessingComplete) {
            ObSet_Push_PageAlign(pObPrefetchAddr, VMM_EPROCESS_PTR(pObProcess, ctxVmm->offset.EPROCESS.SeAuditProcessCreationInfo), 540);
        }
    }
    if(0 == ObSet_Size(pObPrefetchAddr)) { goto fail; }
    VmmCachePrefetchPages(pSystemProcess, pObPrefetchAddr, 0);
    // 2: Fetch "kernel path" and set "long name" for new processes.
    while((pObProcess = VmmProcessGetNextEx(ptObNew, pObProcess, VMM_FLAG_PROCESS_SHOW_TERMINATED))) {
        pProcPers = pObProcess->pObPersistent;
        if(!pProcPers->fIsPostProcessingComplete) {
            pProcPers->fIsPostProcessingComplete = TRUE;
            wszPathKernel = NULL;
            if(VmmReadAllocUnicodeString(pSystemProcess, ctxVmm->f32, VMM_FLAG_FORCECACHE_READ, VMM_EPROCESS_PTR(pObProcess, ctxVmm->offset.EPROCESS.SeAuditProcessCreationInfo), 0x400, &wszPathKernel, NULL)) {
                if(memcmp(wszPathKernel, L"\\Device\\", 16)) {
                    LocalFree(wszPathKernel);
                    wszPathKernel = NULL;
                }
            }
            if(!wszPathKernel) {
                // Fail - use EPROCESS name
                if(!(wszPathKernel = LocalAlloc(LMEM_ZEROINIT, 32))) { continue; }
                for(i = 0; i < 15; i++) {
                    wszPathKernel[i] = pObProcess->szName[i];
                }
            }
            pProcPers->szPathKernel = Util_StrDupW2A(wszPathKernel);
            pProcPers->wszPathKernel = wszPathKernel;
            pProcPers->cchPathKernel = (WORD)wcslen(pProcPers->wszPathKernel);
            // locate FullName by skipping to last \ character.
            pProcPers->szNameLong = Util_PathSplitLastA(pProcPers->szPathKernel);
            pProcPers->wszNameLong = Util_PathSplitLastW(pProcPers->wszPathKernel);
            pProcPers->cchNameLong = (WORD)wcslen(pProcPers->wszNameLong);
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
    POB_SET pObSetPrefetchDTB;
} VMMWIN_ENUMERATE_EPROCESS_CONTEXT, *PVMMWIN_ENUMERATE_EPROCESS_CONTEXT;

VOID VmmWin_EnumEPROCESS64_Pre(_In_ PVMM_PROCESS pProcess, _In_opt_ PVMMWIN_ENUMERATE_EPROCESS_CONTEXT ctx, _In_ QWORD va, _In_ PBYTE pb, _In_ DWORD cb, _In_ QWORD vaFLink, _In_ QWORD vaBLink, _In_ POB_SET pVSetAddress, _Inout_ PBOOL pfValidEntry, _Inout_ PBOOL pfValidFLink, _Inout_ PBOOL pfValidBLink)
{
    if(!ctx || !VMM_KADDR64_16(va)) { return; }
    ObSet_Push(ctx->pObSetPrefetchDTB, *(PQWORD)(pb + ctxVmm->offset.EPROCESS.DTB) & ~0xfff);
    *pfValidFLink = VMM_KADDR64_8(vaFLink);
    *pfValidBLink = VMM_KADDR64_8(vaBLink);
    *pfValidEntry = *pfValidFLink || *pfValidBLink;
}

VOID VmmWin_EnumEPROCESS64_Post(_In_ PVMM_PROCESS pSystemProcess, _In_opt_ PVMMWIN_ENUMERATE_EPROCESS_CONTEXT ctx, _In_ QWORD va, _In_ PBYTE pb, _In_ DWORD cb)
{
    PVMM_OFFSET_EPROCESS po = &ctxVmm->offset.EPROCESS;
    PQWORD pqwDTB, pqwDTB_User, pqwPEB, pqwWow64Process;
    PDWORD pdwState, pdwPID, pdwPPID;
    LPSTR szName;
    BOOL fUser;
    PVMM_PROCESS pObProcess = NULL;
    if(!ctx || !VMM_KADDR64_16(va)) { return; }
    pdwState = (PDWORD)(pb + po->State);
    pdwPID = (PDWORD)(pb + po->PID);
    pdwPPID = (PDWORD)(pb + po->PPID);
    pqwDTB = (PQWORD)(pb + po->DTB);
    pqwDTB_User = (PQWORD)(pb + po->DTB_User);
    szName = (LPSTR)(pb + po->Name);
    pqwPEB = (PQWORD)(pb + po->PEB);
    pqwWow64Process = (PQWORD)(pb + po->Wow64Process);
    if(*pqwDTB & 0xffffff00'00000000) { return; }   // NB! Fail if target system have more than 1TB of memory (unlikely)
    if(ctx->pObSetPrefetchDTB) {    // prefetch any physical pages in ctx->pObSetPrefetchDTB on 1st run only
        VmmCachePrefetchPages(NULL, ctx->pObSetPrefetchDTB, 0);
        Ob_DECREF_NULL(&ctx->pObSetPrefetchDTB);
    }
    if(*pdwPID && *pqwDTB && *(PQWORD)szName) {
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
            fUser,
            pb,
            cb);
        if(!pObProcess) {
            vmmprintfv("VMM: WARNING: PID '%i' already exists.\n", *pdwPID);
            if(++ctx->cNewProcessCollision >= 8) {
                return;
            }
        }
    }
    if(pObProcess) {
        pObProcess->win.EPROCESS.va = va;
        // PEB
        if(*pqwPEB % PAGE_SIZE) {
            vmmprintfv("VMM: WARNING: Bad PEB alignment for PID: '%i' (0x%016llx).\n", *pdwPID, *pqwPEB);
        } else {
            pObProcess->win.vaPEB = *pqwPEB;
        }
        // WoW64 and PEB32
        if(*pqwWow64Process) {
            pObProcess->win.fWow64 = TRUE;
            if(*pqwWow64Process & 0xffffffff'00000fff) {
                pObProcess->win.vaPEB32 = (DWORD)*pqwPEB + (po->f64VistaOr7 ? -0x1000 : +0x1000);
            } else {
                pObProcess->win.vaPEB32 = (DWORD)*pqwWow64Process;
            }
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
    PVMM_OFFSET_EPROCESS po = &ctxVmm->offset.EPROCESS;
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
    vmmprintfvv_fn("SYSTEM DTB: %016llx EPROCESS: %016llx\n", pSystemProcess->paDTB, pSystemProcess->win.EPROCESS.va);
    // set up context
    ctx.fTotalRefresh = fTotalRefresh;
    if(!(ctx.pObSetPrefetchDTB = ObSet_New())) { return FALSE; }
    // traverse EPROCESS linked list
    vmmprintfvv_fn("        # STATE  PID      DTB          EPROCESS         PEB          NAME  \n");
    VmmWin_ListTraversePrefetch(
        pSystemProcess,
        FALSE,
        &ctx,
        1,
        &pSystemProcess->win.EPROCESS.va,
        ctxVmm->offset.EPROCESS.FLink,
        ctxVmm->offset.EPROCESS.cbMaxOffset + 0x20,
        VmmWin_EnumEPROCESS64_Pre,
        VmmWin_EnumEPROCESS64_Post,
        ctxVmm->pObCCachePrefetchEPROCESS);
    // set resulting prefetch cache
    Ob_DECREF_NULL(&ctx.pObSetPrefetchDTB);
    VmmWin_EnumerateEPROCESS_PostProcessing(pSystemProcess);
    VmmProcessCreateFinish();
    return (ctx.cProc > 10);
}

/*
* Very ugly hack that tries to locate some offsets required withn the EPROCESS struct.
*/
VOID VmmWin_OffsetLocatorEPROCESS32(_In_ PVMM_PROCESS pSystemProcess)
{
    PVMM_OFFSET_EPROCESS po = &ctxVmm->offset.EPROCESS;
    BOOL f;
    WORD i, j, cLoopProtect;
    DWORD va1, vaPEB, vaP, oP;
    QWORD paPEB;
    BYTE pbSYSTEM[VMMPROC_EPROCESS32_MAX_SIZE], pbSMSS[VMMPROC_EPROCESS32_MAX_SIZE], pb1[VMMPROC_EPROCESS32_MAX_SIZE], pbPage[0x1000];
    //BYTE pbZero[0x800]
    //QWORD paMax, paDTB_0, paDTB_1;
    POB_SET psObOff = NULL, psObVa = NULL;
    ZeroMemory(po, sizeof(VMM_OFFSET_EPROCESS));
    if(!VmmRead(pSystemProcess, pSystemProcess->win.EPROCESS.va, pbSYSTEM, VMMPROC_EPROCESS32_MAX_SIZE)) { return; }
    if(ctxMain->cfg.fVerboseExtra) {
        vmmprintf_fn("SYSTEM DTB: %016llx EPROCESS: %016llx\n", pSystemProcess->paDTB, pSystemProcess->win.EPROCESS.va);
        Util_PrintHexAscii(pbSYSTEM, VMMPROC_EPROCESS32_MAX_SIZE, 0);
    }
    // find offset State (static for now)
    if(*(PDWORD)(pbSYSTEM + 0x04)) { return; }
    po->State = 0x04;
    // find offset PML4 (static for now)
    po->DTB = 0x18;
    // find offset for Name
    for(i = 0, f = FALSE; i < VMMPROC_EPROCESS32_MAX_SIZE - 4; i += 4) {
        if(*(PQWORD)(pbSYSTEM + i) == 0x00006D6574737953) {
            po->Name = i;
            f = TRUE;
            break;
        }
    }
    if(!f) { return; }
    // find offset for PID, FLink, BLink (assumed to be following eachother)
    for(i = 0, f = FALSE; i < VMMPROC_EPROCESS32_MAX_SIZE - 4; i += 4) {
        if(*(PDWORD)(pbSYSTEM + i) == 4) {
            // PID = correct, this is a candidate
            if(0x80000000 != (0x80000003 & *(PDWORD)(pbSYSTEM + i + 4))) { continue; }    // FLink not valid kernel pointer
            va1 = *(PDWORD)(pbSYSTEM + i + 4) - i - 4;
            f = VmmRead(pSystemProcess, va1, pb1, VMMPROC_EPROCESS32_MAX_SIZE);
            if(!f) { continue; }
            f = FALSE;
            if((*(PQWORD)(pb1 + po->Name) != 0x6578652e73736d73) &&    // smss.exe
                (*(PQWORD)(pb1 + po->Name) != 0x7972747369676552) &&   // Registry
                (*(PQWORD)(pb1 + po->Name) != 0x5320657275636553))     // Secure System
            {
                continue;
            }
            if((*(PDWORD)(pb1 + i + 8) - i - 4) != pSystemProcess->win.EPROCESS.va) {
                continue;
            }
            po->PID = i;
            po->FLink = i + 4;
            po->BLink = i + 8;
            f = TRUE;
            break;
        }
    }
    if(!f) { return; }
    // find and read smss.exe
    {
        cLoopProtect = 0;
        memcpy(pbSMSS, pbSYSTEM, VMMPROC_EPROCESS32_MAX_SIZE);
        while(++cLoopProtect < 8) {
            va1 = *(PDWORD)(pbSMSS + po->FLink) - po->FLink;
            f = VmmRead(pSystemProcess, va1, pbSMSS, VMMPROC_EPROCESS32_MAX_SIZE) &&
                (*(PQWORD)(pbSMSS + po->Name) == 0x6578652e73736d73);
            if(f) { break; }
        }
        if(!f) { return; }
        if(ctxMain->cfg.fVerboseExtra) {
            vmmprintf_fn("EPROCESS smss.exe BELOW:\n");
            Util_PrintHexAscii(pbSMSS, VMMPROC_EPROCESS32_MAX_SIZE, 0);
        }
    }
    // find offset for ParentPid (_EPROCESS!InheritedFromUniqueProcessId)
    // (parent pid is assumed to be located between BLink and Name
    {
        for(i = po->BLink; i < po->Name; i += 4) {
            if((*(PDWORD)(pbSYSTEM + i) == 0) && (*(PDWORD)(pbSMSS + i) == 4)) {
                po->PPID = i;
                break;
            }
        }
        if(!po->PPID) { return; }
    }
    // find offset for PEB (in EPROCESS) by comparing SYSTEM and SMSS  [or other process on fail - max 4 tries]
    {
        for(j = 0; j < 4; j++) {
            for(i = 0x100, f = FALSE; i < 0x240; i += 4) {
                if(*(PDWORD)(pbSYSTEM + i)) { continue; }
                vaPEB = *(PDWORD)(pbSMSS + i);
                if(!vaPEB || (vaPEB & 0x80000fff)) { continue; }
                // Verify potential PEB
                if(!VmmVirt2PhysEx(*(PDWORD)(pbSMSS + po->DTB), TRUE, vaPEB, &paPEB)) { continue; }
                if(!VmmReadPage(NULL, paPEB, pbPage)) { continue; }
                if(*(PWORD)pbPage == 0x5a4d) { continue; }  // MZ header -> likely entry point or something not PEB ...
                po->PEB = i;
                f = TRUE;
                break;
            }
            if(f) { break; }
            // failed locating PEB (paging?) -> try next process in EPROCESS list.
            va1 = *(PDWORD)(pbSMSS + po->FLink) - po->FLink;
            if(!VmmRead(pSystemProcess, va1, pbSMSS, VMMPROC_EPROCESS32_MAX_SIZE)) { return; }
        }
        if(!f) { return; }
    }
    // locate various offsets primarily by reading pointers and checking pool
    // headers in an efficient way (minimize number of reads).
    {
        if(!(psObVa = ObSet_New())) { goto fail; }
        if(!(psObOff = ObSet_New())) { goto fail; }
        // ObjectTable candidate pointers
        for(i = po->Name - 0x0c0; i < po->Name - 0x010; i += 4) {
            if(VMM_KADDR32_8(*(PDWORD)(pbSYSTEM + i))) {
                ObSet_Push(psObOff, (i << 16) | 1);
                ObSet_Push(psObVa, *(PDWORD)(pbSYSTEM + i) - 0x10);
            }
        }
        // SeAuditProcessCreationInfo candidate pointers by looking at SMSS.
        // Offset is located between PEB+0x044 and PEB+0x04C as observed so far.
        // Look at some extra offsets just in case for the future.
        for(i = po->PEB + 0x044; i < po->PEB + 0x058; i += 4) {
            if(VMM_KADDR32_4(*(PDWORD)(pbSMSS + i))) {
                ObSet_Push(psObOff, (i << 16) | 2);
                ObSet_Push(psObVa, *(PDWORD)(pbSMSS + i));
            }
        }
        // prefetch result into cache
        VmmCachePrefetchPages3(pSystemProcess, psObVa, 0x40, 0);
        // interpret result
        while(ObSet_Size(psObVa)) {
            oP = (DWORD)ObSet_Pop(psObOff);
            vaP = (DWORD)ObSet_Pop(psObVa);
            if(!VmmRead2(pSystemProcess, vaP, pbPage, 0x40, VMM_FLAG_FORCECACHE_READ)) { continue; }
            // ObjectTable
            f = (1 == (oP & 0xff)) && (*(PDWORD)(pbPage + 12) == 0x6274624f);     // Pool Header: Obtb
            if(f) { po->ObjectTable = (WORD)(oP >> 16); }
            f = (1 == (oP & 0xff)) && VMM_KADDR32_PAGE(vaP + 0x10) && !*(PDWORD)(pbPage + 0x10 + 0x0c) && VMM_KADDR32_4(*(PDWORD)(pbPage + 0x10 + 0x10)) && VMM_KADDR32_4(*(PDWORD)(pbPage + 0x10 + 0x14));     // page-align (no pool hdr)
            if(f) { po->ObjectTable = (WORD)(oP >> 16); }
            // SeAuditProcessCreationInfo
            f = (2 == (oP & 0xff)) && 
                (*(PQWORD)(pbPage + 0x08) == 0x007600650044005C) && (*(PQWORD)(pbPage + 0x10) == 0x005C006500630069) && // L"\Device\"
                (*(PWORD)(pbPage + 0x00) < MAX_PATH) && (*(PWORD)(pbPage + 0x00) < *(PWORD)(pbPage + 0x02));            // _UNICODE_STRING length
            if(f) { po->SeAuditProcessCreationInfo = (WORD)(oP >> 16); }
        }
        // check validity
        if(!po->ObjectTable) { goto fail; }
        if(!po->SeAuditProcessCreationInfo) { goto fail; }
    }
    // find offset for VadRoot by searching for ExitStatus value assumed to be
    // set to: 0x00000103 and existing prior to VadRoot by -12(VISTA)/-4(Win7+)
    {
        for(i = 0x0e0 + po->Name; i < 0x380; i += 4) {
            f = VMM_KADDR32(*(PDWORD)(pbSYSTEM + i)) && ((*(PDWORD)(pbSYSTEM + i - 4) == 0x00000103) || (*(PDWORD)(pbSYSTEM + i - 12) == 0x00000103));
            if(f) { break; }
        }
        if(!f && (*(PDWORD)(pbSYSTEM + 0x11c) == *(PDWORD)(pbSYSTEM + +0x120))) {   // WINXP
            i = 0x11c;
            f = TRUE;
        }
        if(!f) { return; }
        po->VadRoot = i;
    }
    // DTB_USER not searched for in 32-bit EPROCESS
    VmmWin_OffsetLocatorEPROCESS_SetMaxOffset();
    po->fValid = TRUE;
fail:
    Ob_DECREF(psObVa);
    Ob_DECREF(psObOff);
}

VOID VmmWin_EnumEPROCESS32_Pre(_In_ PVMM_PROCESS pProcess, _In_opt_ PVMMWIN_ENUMERATE_EPROCESS_CONTEXT ctx, _In_ QWORD va, _In_ PBYTE pb, _In_ DWORD cb, _In_ QWORD vaFLink, _In_ QWORD vaBLink, _In_ POB_SET pVSetAddress, _Inout_ PBOOL pfValidEntry, _Inout_ PBOOL pfValidFLink, _Inout_ PBOOL pfValidBLink)
{
    if(!ctx || !VMM_KADDR32_8(va)) { return; }
    ObSet_Push(ctx->pObSetPrefetchDTB, *(PDWORD)(pb + ctxVmm->offset.EPROCESS.DTB) & ~0xfff);
    *pfValidFLink = VMM_KADDR32_4(vaFLink);
    *pfValidBLink = VMM_KADDR32_4(vaBLink);
    *pfValidEntry = *pfValidFLink || *pfValidBLink;
}

VOID VmmWin_EnumEPROCESS32_Post(_In_ PVMM_PROCESS pSystemProcess, _In_opt_ PVMMWIN_ENUMERATE_EPROCESS_CONTEXT ctx, _In_ QWORD va, _In_ PBYTE pb, _In_ DWORD cb)
{
    PVMM_OFFSET_EPROCESS po = &ctxVmm->offset.EPROCESS;
    PDWORD pdwDTB, pdwDTB_User, pdwPEB;
    PDWORD pdwState, pdwPID, pdwPPID;
    LPSTR szName;
    BOOL fUser;
    PVMM_PROCESS pObProcess = NULL;
    if(!ctx || !VMM_KADDR32_8(va)) { return; }
    pdwState = (PDWORD)(pb + po->State);
    pdwPID = (PDWORD)(pb + po->PID);
    pdwPPID = (PDWORD)(pb + po->PPID);
    pdwDTB = (PDWORD)(pb + po->DTB);
    pdwDTB_User = (PDWORD)(pb + po->DTB_User);
    szName = (LPSTR)(pb + po->Name);
    pdwPEB = (PDWORD)(pb + po->PEB);
    if(ctx->pObSetPrefetchDTB) {    // prefetch any physical pages in ctx->pObSetPrefetchDTB on 1st run only
        VmmCachePrefetchPages(NULL, ctx->pObSetPrefetchDTB, 0);
        Ob_DECREF_NULL(&ctx->pObSetPrefetchDTB);
    }
    if(*pdwPID && *pdwDTB && *(PQWORD)szName) {
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
            fUser,
            pb,
            cb);
        if(!pObProcess) {
            vmmprintfv("VMM: WARNING: PID '%i' already exists.\n", *pdwPID);
            if(++ctx->cNewProcessCollision >= 8) {
                return;
            }
        }
    }
    if(pObProcess) {
        pObProcess->win.EPROCESS.va = (DWORD)va;
        // PEB
        if(*pdwPEB % PAGE_SIZE) {
            vmmprintfv("VMM: WARNING: Bad PEB alignment for PID: '%i' (0x%08x).\n", *pdwPID, *pdwPEB);
        } else {
            pObProcess->win.vaPEB = *pdwPEB;
            pObProcess->win.vaPEB32 = *pdwPEB;
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
}

BOOL VmmWin_EnumEPROCESS32(_In_ PVMM_PROCESS pSystemProcess, _In_ BOOL fTotalRefresh)
{
    PVMM_OFFSET_EPROCESS po = &ctxVmm->offset.EPROCESS;
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
    vmmprintfvv_fn("SYSTEM DTB: %016llx EPROCESS: %08x\n", pSystemProcess->paDTB, (DWORD)pSystemProcess->win.EPROCESS.va);
    // set up context
    ctx.fTotalRefresh = fTotalRefresh;
    if(!(ctx.pObSetPrefetchDTB = ObSet_New())) { return FALSE; }
    // traverse EPROCESS linked list
    vmmprintfvv_fn("        # STATE  PID      DTB      EPROCESS PEB      NAME\n");
    VmmWin_ListTraversePrefetch(
        pSystemProcess,
        TRUE,
        &ctx,
        1,
        &pSystemProcess->win.EPROCESS.va,
        ctxVmm->offset.EPROCESS.FLink,
        ctxVmm->offset.EPROCESS.cbMaxOffset + 0x20,
        VmmWin_EnumEPROCESS32_Pre,
        VmmWin_EnumEPROCESS32_Post,
        ctxVmm->pObCCachePrefetchEPROCESS);
    // set resulting prefetch cache
    Ob_DECREF_NULL(&ctx.pObSetPrefetchDTB);
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
* -- cvaDataStart
* -- pvaDataStart
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
    _In_ DWORD cvaDataStart,
    _In_ PQWORD pvaDataStart,
    _In_ DWORD oListStart,
    _In_ DWORD cbData,
    _In_opt_ VOID(*pfnCallback_Pre)(_In_ PVMM_PROCESS pProcess, _In_opt_ PVOID ctx, _In_ QWORD va, _In_ PBYTE pb, _In_ DWORD cb, _In_ QWORD vaFLink, _In_ QWORD vaBLink, _In_ POB_SET pVSetAddress, _Inout_ PBOOL pfValidEntry, _Inout_ PBOOL pfValidFLink, _Inout_ PBOOL pfValidBLink),
    _In_opt_ VOID(*pfnCallback_Post)(_In_ PVMM_PROCESS pProcess, _In_opt_ PVOID ctx, _In_ QWORD va, _In_ PBYTE pb, _In_ DWORD cb),
    _In_opt_ POB_CONTAINER pPrefetchAddressContainer)
{
    QWORD vaData;
    DWORD cbReadData;
    PBYTE pbData = NULL;
    QWORD vaFLink, vaBLink;
    POB_SET pObSet_vaAll = NULL, pObSet_vaTry1 = NULL, pObSet_vaTry2 = NULL, pObSet_vaValid = NULL;
    BOOL fValidEntry, fValidFLink, fValidBLink, fTry1;
    // 1: Prefetch any addresses stored in optional address container
    pObSet_vaAll = ObContainer_GetOb(pPrefetchAddressContainer);
    VmmCachePrefetchPages3(pProcess, pObSet_vaAll, cbData, 0);
    Ob_DECREF_NULL(&pObSet_vaAll);
    // 2: Prepare/Allocate and set up initial entry
    if(!(pObSet_vaAll = ObSet_New())) { goto fail; }
    if(!(pObSet_vaTry1 = ObSet_New())) { goto fail; }
    if(!(pObSet_vaTry2 = ObSet_New())) { goto fail; }
    if(!(pObSet_vaValid = ObSet_New())) { goto fail; }
    if(!(pbData = LocalAlloc(0, cbData))) { goto fail; }
    while(cvaDataStart) {
        cvaDataStart--;
        ObSet_Push(pObSet_vaAll, pvaDataStart[cvaDataStart]);
        ObSet_Push(pObSet_vaTry1, pvaDataStart[cvaDataStart]);
    }
    // 3: Initial list walk
    fTry1 = TRUE;
    while(TRUE) {
        if(fTry1) {
            vaData = ObSet_Pop(pObSet_vaTry1);
            if(!vaData && (0 == ObSet_Size(pObSet_vaTry2))) { break; }
            if(!vaData) {
                VmmCachePrefetchPages3(pProcess, pObSet_vaAll, cbData, 0);
                fTry1 = FALSE;
                continue;
            }
            VmmReadEx(pProcess, vaData, pbData, cbData, &cbReadData, VMM_FLAG_FORCECACHE_READ);
            if(cbReadData != cbData) {
                ObSet_Push(pObSet_vaTry2, vaData);
                continue;
            }
        } else {
            vaData = ObSet_Pop(pObSet_vaTry2);
            if(!vaData && (0 == ObSet_Size(pObSet_vaTry1))) { break; }
            if(!vaData) { fTry1 = TRUE; continue; }
            if(!VmmRead(pProcess, vaData, pbData, cbData)) { continue; }
        }
        vaFLink = f32 ? *(PDWORD)(pbData + oListStart + 0) : *(PQWORD)(pbData + oListStart + 0);
        vaBLink = f32 ? *(PDWORD)(pbData + oListStart + 4) : *(PQWORD)(pbData + oListStart + 8);
        if(pfnCallback_Pre) {
            fValidEntry = FALSE; fValidFLink = FALSE; fValidBLink = FALSE;
            pfnCallback_Pre(pProcess, ctx, vaData, pbData, cbData, vaFLink, vaBLink, pObSet_vaAll, &fValidEntry, &fValidFLink, &fValidBLink);
        } else {
            if(f32) {
                fValidFLink = !(vaFLink & 0x03);
                fValidBLink = !(vaBLink & 0x03);
            } else {
                fValidFLink = VMM_KADDR64_8(vaFLink) || VMM_UADDR64_8(vaFLink);
                fValidBLink = VMM_KADDR64_8(vaBLink) || VMM_UADDR64_8(vaBLink);
            }
            fValidEntry = fValidFLink || fValidBLink;
        }
        if(fValidEntry) {
            ObSet_Push(pObSet_vaValid, vaData);
        }
        vaFLink -= oListStart;
        vaBLink -= oListStart;
        if(fValidFLink && !ObSet_Exists(pObSet_vaAll, vaFLink)) {
            ObSet_Push(pObSet_vaAll, vaFLink);
            ObSet_Push(pObSet_vaTry1, vaFLink);
        }
        if(fValidBLink && !ObSet_Exists(pObSet_vaAll, vaBLink)) {
            ObSet_Push(pObSet_vaAll, vaBLink);
            ObSet_Push(pObSet_vaTry1, vaBLink);
        }
    }
    // 4: Prefetch additional gathered addresses into cache.
    VmmCachePrefetchPages3(pProcess, pObSet_vaAll, cbData, 0);
    // 5: 2nd main list walk. Call into optional pfnCallback_Post to do the main
    //    processing of the list items.
    if(pfnCallback_Post) {
        while((vaData = ObSet_Pop(pObSet_vaValid))) {
            if(VmmRead(pProcess, vaData, pbData, cbData)) {
                pfnCallback_Post(pProcess, ctx, vaData, pbData, cbData);
            }
        }
    }
    // 6: Store/Update the optional container with the newly prefetch addresses (if possible and desirable).
    if(pPrefetchAddressContainer && ctxMain->dev.fVolatile && ctxVmm->ThreadProcCache.fEnabled) {
        ObContainer_SetOb(pPrefetchAddressContainer, pObSet_vaAll);
    }
fail:
    // 7: Cleanup
    Ob_DECREF_NULL(&pObSet_vaAll);
    Ob_DECREF_NULL(&pObSet_vaTry1);
    Ob_DECREF_NULL(&pObSet_vaTry2);
    Ob_DECREF_NULL(&pObSet_vaValid);
    LocalFree(pbData);
}
