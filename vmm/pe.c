// pe.c : implementation related to parsing of portable executable (PE) images
//        in virtual address space. This may mostly (but not exclusively) be
//        used by Windows functionality.
//
// (c) Ulf Frisk, 2018-2019
// Author: Ulf Frisk, pcileech@frizk.net
//
#include "vmm.h"
#include "pe.h"

PIMAGE_NT_HEADERS PE_HeaderGetVerify(_In_ PVMM_PROCESS pProcess, _In_opt_ QWORD vaModuleBase, _Inout_ PBYTE pbModuleHeader, _Out_opt_ PBOOL pfHdr32)
{
    PIMAGE_DOS_HEADER dosHeader;
    PIMAGE_NT_HEADERS ntHeader;
    if(pfHdr32) { *pfHdr32 = FALSE; }
    if(vaModuleBase) {
        if(!VmmReadPage(pProcess, vaModuleBase, pbModuleHeader)) { return NULL; }
    }
    dosHeader = (PIMAGE_DOS_HEADER)pbModuleHeader; // dos header.
    if(!dosHeader || dosHeader->e_magic != IMAGE_DOS_SIGNATURE) { return NULL; }
    if(dosHeader->e_lfanew > 0x800) { return NULL; }
    ntHeader = (PIMAGE_NT_HEADERS)(pbModuleHeader + dosHeader->e_lfanew); // nt header
    if(!ntHeader || ntHeader->Signature != IMAGE_NT_SIGNATURE) { return NULL; }
    if((ntHeader->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) && (ntHeader->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC)) { return NULL; }
    if(pfHdr32) { *pfHdr32 = (ntHeader->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC); }
    return ntHeader;
}

QWORD PE_GetSize(_In_ PVMM_PROCESS pProcess, _In_opt_ QWORD vaModuleBase)
{
    BYTE pbHeader[0x1000] = { 0 };
    PIMAGE_NT_HEADERS ntHeader;
    DWORD cbSize;
    BOOL f32;
    ntHeader = PE_HeaderGetVerify(pProcess, vaModuleBase, pbHeader, &f32);
    cbSize = f32 ?
        ((PIMAGE_NT_HEADERS32)ntHeader)->OptionalHeader.SizeOfImage :
        ((PIMAGE_NT_HEADERS64)ntHeader)->OptionalHeader.SizeOfImage;
    if(cbSize > 0x02000000) { cbSize = 0; }
    return cbSize;
}

_Success_(return)
BOOL PE_GetThunkInfoIAT(_In_ PVMM_PROCESS pProcess, _In_ QWORD vaModuleBase, _In_ LPSTR szImportModuleName, _In_ LPSTR szImportProcName, _Out_ PPE_THUNKINFO_IAT pThunkInfoIAT)
{
    BYTE pbModuleHeader[0x1000] = { 0 };
    PIMAGE_NT_HEADERS64 ntHeader64;
    PIMAGE_NT_HEADERS32 ntHeader32;
    QWORD i, oImportDirectory;
    PIMAGE_IMPORT_DESCRIPTOR pIID;
    PQWORD pIAT64, pHNA64;
    PDWORD pIAT32, pHNA32;
    DWORD cbModule, cbRead;
    PBYTE pbModule = NULL;
    BOOL f32, fFnName;
    DWORD c, j;
    LPSTR szNameFunction, szNameModule;
    // load both 32/64 bit ntHeader (only one will be valid)
    if(!(ntHeader64 = PE_HeaderGetVerify(pProcess, vaModuleBase, pbModuleHeader, &f32))) { goto fail; }
    ntHeader32 = (PIMAGE_NT_HEADERS32)ntHeader64;
    cbModule = f32 ?
        ntHeader32->OptionalHeader.SizeOfImage :
        ntHeader64->OptionalHeader.SizeOfImage;
    if(cbModule > 0x02000000) { goto fail; }
    oImportDirectory = f32 ?
        ntHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress :
        ntHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    if(!oImportDirectory || (oImportDirectory >= cbModule)) { goto fail;  }
    if(!(pbModule = LocalAlloc(LMEM_ZEROINIT, cbModule))) { goto fail; }
    VmmReadEx(pProcess, vaModuleBase, pbModule, cbModule, &cbRead, VMM_FLAG_ZEROPAD_ON_FAIL);
    if(cbRead <= 0x2000) { goto fail; }
    // Walk imported modules / functions
    pIID = (PIMAGE_IMPORT_DESCRIPTOR)(pbModule + oImportDirectory);
    i = 0, c = 0;
    while((oImportDirectory + (i + 1) * sizeof(IMAGE_IMPORT_DESCRIPTOR) < cbModule) && pIID[i].FirstThunk) {
        if(pIID[i].Name > cbModule - 64) { i++; continue; }
        if(f32) {
            // 32-bit PE
            j = 0;
            pIAT32 = (PDWORD)(pbModule + pIID[i].FirstThunk);
            pHNA32 = (PDWORD)(pbModule + pIID[i].OriginalFirstThunk);
            while(TRUE) {
                if((QWORD)(pIAT32 + j) + sizeof(DWORD) - (QWORD)pbModule > cbModule) { break; }
                if((QWORD)(pHNA32 + j) + sizeof(DWORD) - (QWORD)pbModule > cbModule) { break; }
                if(!pIAT32[j]) { break; }
                if(!pHNA32[j]) { break; }
                fFnName = (pHNA32[j] < cbModule - 40);
                szNameFunction = (LPSTR)(pbModule + pHNA32[j] + 2);
                szNameModule = (LPSTR)(pbModule + pIID[i].Name);
                if(fFnName && !strcmp(szNameFunction, szImportProcName) && !_stricmp(szNameModule, szImportModuleName)) {
                    pThunkInfoIAT->fValid = TRUE;
                    pThunkInfoIAT->f32 = TRUE;
                    pThunkInfoIAT->vaThunk = vaModuleBase + pIID[i].FirstThunk + sizeof(DWORD) * j;
                    pThunkInfoIAT->vaFunction = pIAT32[j];
                    pThunkInfoIAT->vaNameFunction = vaModuleBase + pHNA32[j] + 2;
                    pThunkInfoIAT->vaNameModule = vaModuleBase + pIID[i].Name;
                    LocalFree(pbModule);
                    return TRUE;
                }
                c++;
                j++;
            }
        } else {
            // 64-bit PE
            j = 0;
            pIAT64 = (PQWORD)(pbModule + pIID[i].FirstThunk);
            pHNA64 = (PQWORD)(pbModule + pIID[i].OriginalFirstThunk);
            while(TRUE) {
                if((QWORD)(pIAT64 + j) + sizeof(QWORD) - (QWORD)pbModule > cbModule) { break; }
                if((QWORD)(pHNA64 + j) + sizeof(QWORD) - (QWORD)pbModule > cbModule) { break; }
                if(!pIAT64[j]) { break; }
                if(!pHNA64[j]) { break; }
                fFnName = (pHNA64[j] < cbModule - 40);
                szNameFunction = (LPSTR)(pbModule + pHNA64[j] + 2);
                szNameModule = (LPSTR)(pbModule + pIID[i].Name);
                if(fFnName && !strcmp(szNameFunction, szImportProcName) && !_stricmp(szNameModule, szImportModuleName)) {
                    pThunkInfoIAT->fValid = TRUE;
                    pThunkInfoIAT->f32 = FALSE;
                    pThunkInfoIAT->vaThunk = vaModuleBase + pIID[i].FirstThunk + sizeof(QWORD) * j;
                    pThunkInfoIAT->vaFunction = pIAT64[j];
                    pThunkInfoIAT->vaNameFunction = vaModuleBase + pHNA64[j] + 2;
                    pThunkInfoIAT->vaNameModule = vaModuleBase + pIID[i].Name;
                    LocalFree(pbModule);
                    return TRUE;
                }
                c++;
                j++;
            }
        }
        i++;
    }
fail:
    LocalFree(pbModule);
    return FALSE;
}

_Success_(return)
BOOL PE_GetThunkInfoEAT(_In_ PVMM_PROCESS pProcess, _In_ QWORD vaModuleBase, _In_ LPSTR szProcName, _Out_ PPE_THUNKINFO_EAT pThunkInfoEAT)
{
    BYTE pbModuleHeader[0x1000] = { 0 };
    PIMAGE_NT_HEADERS32 ntHeader32;
    PIMAGE_NT_HEADERS64 ntHeader64;
    PDWORD pdwRVAAddrNames, pdwRVAAddrFunctions;
    PWORD pwNameOrdinals;
    DWORD i, cbProcName, cbExportDirectoryOffset, cbRead = 0;
    LPSTR sz;
    QWORD vaExportDirectory;
    DWORD cbExportDirectory;
    PBYTE pbExportDirectory = NULL;
    QWORD vaRVAAddrNames, vaNameOrdinals, vaRVAAddrFunctions;
    BOOL f32;
    if(!(ntHeader64 = PE_HeaderGetVerify(pProcess, vaModuleBase, pbModuleHeader, &f32))) { goto cleanup; }
    if(f32) { // 32-bit PE
        ntHeader32 = (PIMAGE_NT_HEADERS32)ntHeader64;
        vaExportDirectory = vaModuleBase + ntHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        cbExportDirectory = ntHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
    } else { // 64-bit PE
        vaExportDirectory = vaModuleBase + ntHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        cbExportDirectory = ntHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
    }
    if((cbExportDirectory < sizeof(IMAGE_EXPORT_DIRECTORY)) || (cbExportDirectory > 0x01000000) || (vaExportDirectory == vaModuleBase) || (vaExportDirectory > vaModuleBase + 0x80000000)) { goto cleanup; }
    if(!(pbExportDirectory = LocalAlloc(0, cbExportDirectory))) { goto cleanup; }
    VmmReadEx(pProcess, vaExportDirectory, pbExportDirectory, cbExportDirectory, &cbRead, VMM_FLAG_ZEROPAD_ON_FAIL);
    if(!cbRead) { goto cleanup; }
    PIMAGE_EXPORT_DIRECTORY exp = (PIMAGE_EXPORT_DIRECTORY)pbExportDirectory;
    if(!exp || !exp->NumberOfNames || !exp->AddressOfNames) { goto cleanup; }
    vaRVAAddrNames = vaModuleBase + exp->AddressOfNames;
    vaNameOrdinals = vaModuleBase + exp->AddressOfNameOrdinals;
    vaRVAAddrFunctions = vaModuleBase + exp->AddressOfFunctions;
    if((vaRVAAddrNames < vaExportDirectory) || (vaRVAAddrNames > vaExportDirectory + cbExportDirectory - exp->NumberOfNames * sizeof(DWORD))) { goto cleanup; }
    if((vaNameOrdinals < vaExportDirectory) || (vaNameOrdinals > vaExportDirectory + cbExportDirectory - exp->NumberOfNames * sizeof(WORD))) { goto cleanup; }
    if((vaRVAAddrFunctions < vaExportDirectory) || (vaRVAAddrFunctions > vaExportDirectory + cbExportDirectory - exp->NumberOfNames * sizeof(DWORD))) { goto cleanup; }
    cbProcName = (DWORD)strnlen_s(szProcName, MAX_PATH) + 1;
    cbExportDirectoryOffset = (DWORD)(vaExportDirectory - vaModuleBase);
    pdwRVAAddrNames = (PDWORD)(pbExportDirectory + exp->AddressOfNames - cbExportDirectoryOffset);
    pwNameOrdinals = (PWORD)(pbExportDirectory + exp->AddressOfNameOrdinals - cbExportDirectoryOffset);
    pdwRVAAddrFunctions = (PDWORD)(pbExportDirectory + exp->AddressOfFunctions - cbExportDirectoryOffset);
    for(i = 0; i < exp->NumberOfNames; i++) {
        if(pdwRVAAddrNames[i] - cbExportDirectoryOffset + cbProcName > cbExportDirectory) { continue; }
        sz = (LPSTR)(pbExportDirectory + pdwRVAAddrNames[i] - cbExportDirectoryOffset);
        if(0 == memcmp(sz, szProcName, cbProcName)) {
            if(pwNameOrdinals[i] >= exp->NumberOfFunctions) { goto cleanup; }
            pThunkInfoEAT->fValid = TRUE;
            pThunkInfoEAT->vaFunction = (QWORD)(vaModuleBase + pdwRVAAddrFunctions[pwNameOrdinals[i]]);
            pThunkInfoEAT->valueThunk = pdwRVAAddrFunctions[pwNameOrdinals[i]];
            pThunkInfoEAT->vaThunk = vaExportDirectory + exp->AddressOfFunctions - cbExportDirectoryOffset + sizeof(DWORD) * pwNameOrdinals[i];
            pThunkInfoEAT->vaNameFunction = vaExportDirectory + pdwRVAAddrNames[i] - cbExportDirectoryOffset;
            LocalFree(pbExportDirectory);
            return TRUE;
        }
    }
cleanup:
    LocalFree(pbExportDirectory);
    return FALSE;
}

QWORD PE_GetProcAddress(_In_ PVMM_PROCESS pProcess, _In_ QWORD vaModuleBase, _In_ LPSTR lpProcName)
{
    PE_THUNKINFO_EAT oThunkInfoEAT = { 0 };
    PE_GetThunkInfoEAT(pProcess, vaModuleBase, lpProcName, &oThunkInfoEAT);
    return oThunkInfoEAT.vaFunction;
}

WORD PE_SectionGetNumberOfEx(_In_ PVMM_PROCESS pProcess, _In_opt_ QWORD vaModuleBase, _In_reads_opt_(0x1000) PBYTE pbModuleHeaderOpt)
{
    BOOL f32;
    BYTE pbModuleHeader[0x1000] = { 0 };
    WORD cSections;
    PIMAGE_NT_HEADERS ntHeader;
    // load nt header either by using optionally supplied module header or by fetching from memory.
    ntHeader = pbModuleHeaderOpt ? PE_HeaderGetVerify(pProcess, 0, pbModuleHeaderOpt, &f32) : PE_HeaderGetVerify(pProcess, vaModuleBase, pbModuleHeader, &f32);
    if(!ntHeader) { return 0; }
    cSections = f32 ? ((PIMAGE_NT_HEADERS32)ntHeader)->FileHeader.NumberOfSections : ((PIMAGE_NT_HEADERS64)ntHeader)->FileHeader.NumberOfSections;
    if(cSections > 0x40) { return 0; }
    return cSections;
}

_Success_(return)
BOOL PE_SectionGetFromName(_In_ PVMM_PROCESS pProcess, _In_ QWORD vaModuleBase, _In_ LPSTR szSectionName, _Out_ PIMAGE_SECTION_HEADER pSection)
{
    BOOL f32;
    BYTE pbModuleHeader[0x1000] = { 0 };
    PIMAGE_NT_HEADERS ntHeader;
    PIMAGE_SECTION_HEADER pSectionBase;
    DWORD i, cSections;
    if(!(ntHeader = PE_HeaderGetVerify(pProcess, vaModuleBase, pbModuleHeader, &f32))) { return FALSE; }
    pSectionBase = f32 ?
        (PIMAGE_SECTION_HEADER)((QWORD)ntHeader + sizeof(IMAGE_NT_HEADERS32)) :
        (PIMAGE_SECTION_HEADER)((QWORD)ntHeader + sizeof(IMAGE_NT_HEADERS64));
    cSections = (DWORD)(((QWORD)pbModuleHeader + 0x1000 - (QWORD)pSectionBase) / sizeof(IMAGE_SECTION_HEADER)); // max section headers possible in 0x1000 module header buffer
    cSections = (DWORD)min(cSections, ntHeader->FileHeader.NumberOfSections); // FileHeader is the same in both 32/64-bit versions of struct
    for(i = 0; i < cSections; i++) {
        if(!strncmp((pSectionBase + i)->Name, szSectionName, 8)) {
            memcpy(pSection, pSectionBase + i, sizeof(IMAGE_SECTION_HEADER));
            return TRUE;
        }
    }
    return FALSE;
}

DWORD PE_IatGetNumberOfEx(_In_ PVMM_PROCESS pProcess, _In_ QWORD vaModuleBase, _In_reads_opt_(0x1000) PBYTE pbModuleHeaderOpt)
{
    BOOL f32;
    BYTE pbModuleHeader[0x1000] = { 0 };
    PIMAGE_NT_HEADERS ntHeader;
    DWORD cbImportDirectory, cbImportAddressTable, cIatEntries, cModules;
    // load nt header either by using optionally supplied module header or by fetching from memory.
    ntHeader = pbModuleHeaderOpt ? PE_HeaderGetVerify(pProcess, 0, pbModuleHeaderOpt, &f32) : PE_HeaderGetVerify(pProcess, vaModuleBase, pbModuleHeader, &f32);
    if(!ntHeader) { return 0; }
    // Calculate the number of functions in the import address table (IAT).
    // Number of functions = # IAT entries - # Imported modules
    cbImportDirectory = f32 ?
        ((PIMAGE_NT_HEADERS32)ntHeader)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size :
        ((PIMAGE_NT_HEADERS64)ntHeader)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
    cbImportAddressTable = f32 ?
        ((PIMAGE_NT_HEADERS32)ntHeader)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].Size :
        ((PIMAGE_NT_HEADERS64)ntHeader)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].Size;
    cIatEntries = cbImportAddressTable / (f32 ? sizeof(DWORD) : sizeof(QWORD));
    cModules = cbImportDirectory / sizeof(IMAGE_IMPORT_DESCRIPTOR);
    return cIatEntries - cModules;
}

DWORD PE_EatGetNumberOfEx(_In_ PVMM_PROCESS pProcess, _In_ QWORD vaModuleBase, _In_reads_opt_(0x1000) PBYTE pbModuleHeaderOpt)
{
    BOOL f32;
    BYTE pbModuleHeader[0x1000] = { 0 };
    PIMAGE_NT_HEADERS ntHeader;
    QWORD va, vaExportDirectory;
    IMAGE_EXPORT_DIRECTORY hdrExportDirectory;
    // load both 32/64 bit ntHeader unless already supplied in parameter (only one of 32/64 bit hdr will be valid)
    // load nt header either by using optionally supplied module header or by fetching from memory.
    ntHeader = pbModuleHeaderOpt ? PE_HeaderGetVerify(pProcess, 0, pbModuleHeaderOpt, &f32) : PE_HeaderGetVerify(pProcess, vaModuleBase, pbModuleHeader, &f32);
    if(!ntHeader) { return 0; }
    // Calculate the number of functions in the export address table (EAT).
    va = f32 ?
        ((PIMAGE_NT_HEADERS32)ntHeader)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress :
        ((PIMAGE_NT_HEADERS64)ntHeader)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    vaExportDirectory = va ? vaModuleBase + va : 0;
    if(vaExportDirectory && VmmRead(pProcess, vaExportDirectory, (PBYTE)&hdrExportDirectory, sizeof(IMAGE_EXPORT_DIRECTORY)) && (hdrExportDirectory.NumberOfNames < 0x00010000)) {
        return hdrExportDirectory.NumberOfNames;
    }
    return 0;
}

_Success_(return)
BOOL PE_GetModuleNameEx(_In_ PVMM_PROCESS pProcess, _In_ QWORD vaModuleBase, _In_ BOOL fOnFailDummyName, _In_reads_opt_(0x1000) PBYTE pbModuleHeaderOpt, _Out_writes_(cszModuleName) PCHAR szModuleName, _In_ DWORD cszModuleName, _Out_opt_ PDWORD pdwSize)
{
    BOOL f32;
    BYTE pbModuleHeader[0x1000] = { 0 };
    PIMAGE_NT_HEADERS ntHeader;
    PIMAGE_NT_HEADERS64 ntHeader64;
    PIMAGE_NT_HEADERS32 ntHeader32;
    PIMAGE_EXPORT_DIRECTORY exp;
    QWORD vaExportDirectory;
    DWORD cbImageSize, cbExportDirectory;
    BYTE pbExportDirectory[sizeof(IMAGE_EXPORT_DIRECTORY)];
    // load both 32/64 bit ntHeader unless already supplied in parameter (only one of 32/64 bit hdr will be valid)
    // load nt header either by using optionally supplied module header or by fetching from memory.
    ntHeader = pbModuleHeaderOpt ? PE_HeaderGetVerify(pProcess, 0, pbModuleHeaderOpt, &f32) : PE_HeaderGetVerify(pProcess, vaModuleBase, pbModuleHeader, &f32);
    if(!ntHeader) { return FALSE; }
    if(!f32) { // 64-bit PE
        ntHeader64 = (PIMAGE_NT_HEADERS64)ntHeader;
        if(pdwSize) { *pdwSize = ntHeader64->OptionalHeader.SizeOfImage; }
        vaExportDirectory = vaModuleBase + ntHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        cbExportDirectory = ntHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
        cbImageSize = ntHeader64->OptionalHeader.SizeOfImage;
    } else { // 32-bit PE
        ntHeader32 = (PIMAGE_NT_HEADERS32)ntHeader;
        if(pdwSize) { *pdwSize = ntHeader32->OptionalHeader.SizeOfImage; }
        vaExportDirectory = vaModuleBase + ntHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        cbExportDirectory = ntHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
        cbImageSize = ntHeader32->OptionalHeader.SizeOfImage;
    }
    if((cbExportDirectory < sizeof(IMAGE_EXPORT_DIRECTORY)) || (vaExportDirectory == vaModuleBase) || (cbExportDirectory > cbImageSize)) { goto fail; }
    if(!VmmRead(pProcess, vaExportDirectory, pbExportDirectory, sizeof(IMAGE_EXPORT_DIRECTORY))) { goto fail; }
    exp = (PIMAGE_EXPORT_DIRECTORY)pbExportDirectory;
    if(!exp || !exp->Name || exp->Name > cbImageSize) { goto fail; }
    szModuleName[cszModuleName - 1] = 0;
    if(!VmmRead(pProcess, vaModuleBase + exp->Name, szModuleName, cszModuleName - 1)) { goto fail; }
    return TRUE;
fail:
    if(fOnFailDummyName) {
        memcpy(szModuleName, "UNKNOWN", 8);
        return TRUE;
    }
    return FALSE;
}
