// pe.c : implementation related to parsing of portable executable (PE) images
//        in virtual address space. This may mostly (but not exclusively) be
//        used by Windows functionality.
//
// (c) Ulf Frisk, 2018-2024
// Author: Ulf Frisk, pcileech@frizk.net
//
#include "vmm.h"
#include "pe.h"
#include "charutil.h"

PIMAGE_NT_HEADERS PE_HeaderGetVerify(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess, _In_opt_ QWORD vaModuleBase, _Inout_ PBYTE pbModuleHeader, _Out_opt_ PBOOL pfHdr32)
{
    PIMAGE_DOS_HEADER dosHeader;
    PIMAGE_NT_HEADERS ntHeader;
    if(pfHdr32) { *pfHdr32 = FALSE; }
    if(vaModuleBase) {
        if(!VmmReadPage(H, pProcess, vaModuleBase, pbModuleHeader)) { return NULL; }
    }
    dosHeader = (PIMAGE_DOS_HEADER)pbModuleHeader; // dos header.
    if(!dosHeader || dosHeader->e_magic != IMAGE_DOS_SIGNATURE) { return NULL; }
    if((dosHeader->e_lfanew < 0) || (dosHeader->e_lfanew > 0x800)) { return NULL; }
    ntHeader = (PIMAGE_NT_HEADERS)(pbModuleHeader + dosHeader->e_lfanew); // nt header
    if(!ntHeader || ntHeader->Signature != IMAGE_NT_SIGNATURE) { return NULL; }
    if((ntHeader->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) && (ntHeader->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC)) { return NULL; }
    if(pfHdr32) { *pfHdr32 = (ntHeader->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC); }
    return ntHeader;
}

QWORD PE_GetSize(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess, _In_opt_ QWORD vaModuleBase)
{
    BYTE pbHeader[0x1000] = { 0 };
    PIMAGE_NT_HEADERS ntHeader;
    DWORD cbSize;
    BOOL f32;
    ntHeader = PE_HeaderGetVerify(H, pProcess, vaModuleBase, pbHeader, &f32);
    if(!ntHeader) { return 0; }
    cbSize = f32 ?
        ((PIMAGE_NT_HEADERS32)ntHeader)->OptionalHeader.SizeOfImage :
        ((PIMAGE_NT_HEADERS64)ntHeader)->OptionalHeader.SizeOfImage;
    if(cbSize > 0x02000000) { cbSize = 0; }
    return cbSize;
}

_Success_(return)
BOOL PE_GetTimeDateStampCheckSum(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess, _In_opt_ QWORD vaModuleBase, _Out_opt_ PDWORD pdwTimeDateStamp, _Out_opt_ PDWORD pdwCheckSum)
{
    BYTE pbHeader[0x1000] = { 0 };
    PIMAGE_NT_HEADERS ntHeader;
    BOOL f32;
    DWORD dwTimeDateStamp, dwCheckSum;
    ntHeader = PE_HeaderGetVerify(H, pProcess, vaModuleBase, pbHeader, &f32);
    if(!ntHeader) { return FALSE; }
    if(f32) {
        dwCheckSum = ((PIMAGE_NT_HEADERS32)ntHeader)->OptionalHeader.CheckSum;
        dwTimeDateStamp = ((PIMAGE_NT_HEADERS32)ntHeader)->FileHeader.TimeDateStamp;
    } else {
        dwCheckSum = ((PIMAGE_NT_HEADERS64)ntHeader)->OptionalHeader.CheckSum;
        dwTimeDateStamp = ((PIMAGE_NT_HEADERS64)ntHeader)->FileHeader.TimeDateStamp;
    }
    if(pdwCheckSum) { *pdwCheckSum = dwCheckSum; }
    if(pdwTimeDateStamp) { *pdwTimeDateStamp = dwTimeDateStamp; }
    return TRUE;
}

_Success_(return)
BOOL PE_GetThunkInfoIAT(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess, _In_ QWORD vaModuleBase, _In_ LPCSTR szImportModuleName, _In_ LPCSTR szImportProcName, _Out_ PPE_THUNKINFO_IAT pThunkInfoIAT)
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
    if(!(ntHeader64 = (PIMAGE_NT_HEADERS64)PE_HeaderGetVerify(H, pProcess, vaModuleBase, pbModuleHeader, &f32))) { goto fail; }
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
    VmmReadEx(H, pProcess, vaModuleBase, pbModule, cbModule, &cbRead, VMM_FLAG_ZEROPAD_ON_FAIL);
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
BOOL PE_GetThunkInfoEAT(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess, _In_ QWORD vaModuleBase, _In_ LPCSTR szProcName, _Out_ PPE_THUNKINFO_EAT pThunkInfoEAT)
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
    if(!(ntHeader64 = (PIMAGE_NT_HEADERS64)PE_HeaderGetVerify(H, pProcess, vaModuleBase, pbModuleHeader, &f32))) { goto cleanup; }
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
    VmmReadEx(H, pProcess, vaExportDirectory, pbExportDirectory, cbExportDirectory, &cbRead, VMM_FLAG_ZEROPAD_ON_FAIL);
    if(!cbRead) { goto cleanup; }
    PIMAGE_EXPORT_DIRECTORY exp = (PIMAGE_EXPORT_DIRECTORY)pbExportDirectory;
    if(!exp || !exp->NumberOfNames || (exp->NumberOfNames > 0x00100000) || !exp->AddressOfNames) { goto cleanup; }
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

QWORD PE_GetProcAddress(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess, _In_ QWORD vaModuleBase, _In_ LPCSTR lpProcName)
{
    PE_THUNKINFO_EAT oThunkInfoEAT = { 0 };
    PE_GetThunkInfoEAT(H, pProcess, vaModuleBase, lpProcName, &oThunkInfoEAT);
    return oThunkInfoEAT.vaFunction;
}

WORD PE_SectionGetNumberOfEx(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess, _In_opt_ QWORD vaModuleBase, _In_reads_opt_(0x1000) PBYTE pbModuleHeaderOpt)
{
    BOOL f32;
    BYTE pbModuleHeader[0x1000] = { 0 };
    WORD cSections;
    PIMAGE_NT_HEADERS ntHeader;
    // load nt header either by using optionally supplied module header or by fetching from memory.
    ntHeader = pbModuleHeaderOpt ? PE_HeaderGetVerify(H, pProcess, 0, pbModuleHeaderOpt, &f32) : PE_HeaderGetVerify(H, pProcess, vaModuleBase, pbModuleHeader, &f32);
    if(!ntHeader) { return 0; }
    if(f32) {
        if(((PIMAGE_NT_HEADERS32)ntHeader)->OptionalHeader.SectionAlignment < 0x1000) {
            return 1;       // LowAlign
        }
    } else {
        if(((PIMAGE_NT_HEADERS64)ntHeader)->OptionalHeader.SectionAlignment < 0x1000) {
            return 1;       // LowAlign
        }
    }
    cSections = f32 ? ((PIMAGE_NT_HEADERS32)ntHeader)->FileHeader.NumberOfSections : ((PIMAGE_NT_HEADERS64)ntHeader)->FileHeader.NumberOfSections;
    if(cSections > 0x40) { return 0; }
    return cSections;
}

WORD PE_SectionGetNumberOf(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess, _In_opt_ QWORD vaModuleBase)
{
    return PE_SectionGetNumberOfEx(H, pProcess, vaModuleBase, NULL);
}

/*
* Internal helper function to set a fake 'LowAlign' section header.
* This may be used to spoof PE section headers.
* Info at:
*    - https://secret.club/2023/06/05/spoof-pe-sections.html
*    - https://reverseengineering.stackexchange.com/questions/4457/what-implications-has-the-low-alignment-mode-of-a-pe-file
* -- dwSizeOfImage
* -- pSection
* -- return = always returns TRUE.
*/
BOOL PE_SectionSetLowAlign(_In_ DWORD dwSizeOfImage, _Out_ PIMAGE_SECTION_HEADER pSection)
{
    ZeroMemory(pSection, sizeof(IMAGE_SECTION_HEADER));
    memcpy(pSection->Name, "LOWALIGN", 8);
    pSection->SizeOfRawData = dwSizeOfImage;
    pSection->Misc.VirtualSize = dwSizeOfImage;
    pSection->Characteristics = IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE;
    return TRUE;
}

_Success_(return)
BOOL PE_SectionGetAll(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess, _In_ QWORD vaModuleBase, _In_ DWORD cSections, _Out_writes_(cSections) PIMAGE_SECTION_HEADER pSections)
{
    BOOL f32;
    BYTE pbModuleHeader[0x1000] = { 0 };
    PIMAGE_NT_HEADERS ntHeader;
    PIMAGE_SECTION_HEADER pSectionBase;
    DWORD cSectionsHdr;
    if(!(ntHeader = PE_HeaderGetVerify(H, pProcess, vaModuleBase, pbModuleHeader, &f32))) { return FALSE; }
    if(f32) {
        pSectionBase = (PIMAGE_SECTION_HEADER)((QWORD)ntHeader + sizeof(IMAGE_NT_HEADERS32));
        if(((PIMAGE_NT_HEADERS32)ntHeader)->OptionalHeader.SectionAlignment < 0x1000) {
            return PE_SectionSetLowAlign(((PIMAGE_NT_HEADERS32)ntHeader)->OptionalHeader.SizeOfImage, pSections);
        }
    } else {
        pSectionBase = (PIMAGE_SECTION_HEADER)((QWORD)ntHeader + sizeof(IMAGE_NT_HEADERS64));
        if(((PIMAGE_NT_HEADERS64)ntHeader)->OptionalHeader.SectionAlignment < 0x1000) {
            return PE_SectionSetLowAlign(((PIMAGE_NT_HEADERS64)ntHeader)->OptionalHeader.SizeOfImage, pSections);
        }
    }
    cSectionsHdr = (DWORD)(((QWORD)pbModuleHeader + 0x1000 - (QWORD)pSectionBase) / sizeof(IMAGE_SECTION_HEADER)); // max section headers possible in 0x1000 module header buffer
    cSectionsHdr = (DWORD)min(cSectionsHdr, ntHeader->FileHeader.NumberOfSections); // FileHeader is the same in both 32/64-bit versions of struct
    if(cSections != cSectionsHdr) { return FALSE; }
    memcpy(pSections, pSectionBase, cSections * sizeof(IMAGE_SECTION_HEADER));
    return TRUE;
}

_Success_(return)
BOOL PE_SectionGetFromName(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess, _In_ QWORD vaModuleBase, _In_ LPCSTR szSectionName, _Out_ PIMAGE_SECTION_HEADER pSection)
{
    BOOL f32;
    BYTE pbModuleHeader[0x1000] = { 0 };
    PIMAGE_NT_HEADERS ntHeader;
    PIMAGE_SECTION_HEADER pSectionBase;
    DWORD i, cSections;
    if(!(ntHeader = PE_HeaderGetVerify(H, pProcess, vaModuleBase, pbModuleHeader, &f32))) { return FALSE; }
    if(f32) {
        pSectionBase = (PIMAGE_SECTION_HEADER)((QWORD)ntHeader + sizeof(IMAGE_NT_HEADERS32));
        if(((PIMAGE_NT_HEADERS32)ntHeader)->OptionalHeader.SectionAlignment < 0x1000) {
            if(memcmp(szSectionName, "LOWALIGN", 8)) {
                return FALSE;
            } else {
                return PE_SectionSetLowAlign(((PIMAGE_NT_HEADERS32)ntHeader)->OptionalHeader.SizeOfImage, pSection);
            }
        }
    } else {
        pSectionBase = (PIMAGE_SECTION_HEADER)((QWORD)ntHeader + sizeof(IMAGE_NT_HEADERS64));
        if(((PIMAGE_NT_HEADERS64)ntHeader)->OptionalHeader.SectionAlignment < 0x1000) {
            if(memcmp(szSectionName, "LOWALIGN", 8)) {
                return FALSE;
            } else {
                return PE_SectionSetLowAlign(((PIMAGE_NT_HEADERS64)ntHeader)->OptionalHeader.SizeOfImage, pSection);
            }
        }
    }
    cSections = (DWORD)(((QWORD)pbModuleHeader + 0x1000 - (QWORD)pSectionBase) / sizeof(IMAGE_SECTION_HEADER)); // max section headers possible in 0x1000 module header buffer
    cSections = (DWORD)min(cSections, ntHeader->FileHeader.NumberOfSections); // FileHeader is the same in both 32/64-bit versions of struct
    // get section by name
    for(i = 0; i < cSections; i++) {
        if(!strncmp((pSectionBase + i)->Name, szSectionName, 8)) {
            memcpy(pSection, pSectionBase + i, sizeof(IMAGE_SECTION_HEADER));
            return TRUE;
        }
    }
    // get section by index (two hex#)
    if(!szSectionName[2] && ((i = strtoul(szSectionName, NULL, 16)) || (*(PWORD)szSectionName == 0x3030)) && (i < cSections)) {
        memcpy(pSection, pSectionBase + i, sizeof(IMAGE_SECTION_HEADER));
        return TRUE;
    }
    return FALSE;
}

/*
* Retrieve a single section header given its address offset.
* -- H
* -- pProcess
* -- vaModuleBase
* -- cboAddress
* -- pSection
* -- return
*/
_Success_(return)
BOOL PE_SectionGetFromAddressOffset(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess, _In_ QWORD vaModuleBase, _In_ DWORD cboAddress, _Out_ PIMAGE_SECTION_HEADER pSection)
{
    WORD i, cSections;
    IMAGE_SECTION_HEADER Sections[0x40];
    cSections = PE_SectionGetNumberOf(H, pProcess, vaModuleBase);
    if(!cSections || (cSections > 0x40)) { return FALSE; }
    if(!PE_SectionGetAll(H, pProcess, vaModuleBase, cSections, Sections)) { return FALSE; }
    for(i = 0; i < cSections; i++) {
        if((cboAddress >= Sections[i].VirtualAddress) && (cboAddress - Sections[i].VirtualAddress < Sections[i].Misc.VirtualSize)) {
            memcpy(pSection, &Sections[i], sizeof(IMAGE_SECTION_HEADER));
            return TRUE;
        }
    }
    return FALSE;
}

DWORD PE_IatGetNumberOfEx(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess, _In_opt_ QWORD vaModuleBase, _In_reads_opt_(0x1000) PBYTE pbModuleHeaderOpt)
{
    BOOL f32;
    BYTE pbModuleHeader[0x1000] = { 0 };
    PIMAGE_NT_HEADERS ntHeader;
    DWORD cbImportDirectory, cbImportAddressTable, cIatEntries, cModules;
    // load nt header either by using optionally supplied module header or by fetching from memory.
    ntHeader = pbModuleHeaderOpt ? PE_HeaderGetVerify(H, pProcess, 0, pbModuleHeaderOpt, &f32) : PE_HeaderGetVerify(H, pProcess, vaModuleBase, pbModuleHeader, &f32);
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
    return cIatEntries - min(cIatEntries, cModules);
}

_Success_(return != NULL)
LPSTR PE_EatForwardedFunctionNameValidate(
    _In_ LPCSTR szForwardedFunction,
    _Out_writes_opt_(cbModule) LPSTR szModule,
    _In_ DWORD cbModule,
    _Out_opt_ PDWORD pdwOrdinal
)
{
    LPSTR szFunction = NULL;
    if(pdwOrdinal) { *pdwOrdinal = 0; }
    if(cbModule && szModule) { szModule[0] = 0; }
    if(!CharUtil_IsAnsiFsA(szForwardedFunction)) { return NULL; }
    szFunction = strrchr(szForwardedFunction, '.');
    if(!szFunction || ((szFunction - szForwardedFunction) < 2)) { return NULL; }
    szFunction++;
    if(pdwOrdinal && (szFunction[0] == '#')) {
        *pdwOrdinal = strtoul(szFunction + 1, NULL, 10);
    }
    if(cbModule && szModule) {
        strncpy_s(szModule, cbModule, szForwardedFunction, (SIZE_T)(szFunction - szForwardedFunction));
    }
    return szFunction;
}

DWORD PE_EatGetNumberOfEx(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess, _In_opt_ QWORD vaModuleBase, _In_reads_opt_(0x1000) PBYTE pbModuleHeaderOpt)
{
    BOOL f32;
    BYTE pbModuleHeader[0x1000] = { 0 };
    PIMAGE_NT_HEADERS ntHeader;
    QWORD va, vaExportDirectory;
    IMAGE_EXPORT_DIRECTORY hdrExportDirectory;
    // load both 32/64 bit ntHeader unless already supplied in parameter (only one of 32/64 bit hdr will be valid)
    // load nt header either by using optionally supplied module header or by fetching from memory.
    ntHeader = pbModuleHeaderOpt ? PE_HeaderGetVerify(H, pProcess, 0, pbModuleHeaderOpt, &f32) : PE_HeaderGetVerify(H, pProcess, vaModuleBase, pbModuleHeader, &f32);
    if(!ntHeader) { return 0; }
    // Calculate the number of functions in the export address table (EAT).
    va = f32 ?
        ((PIMAGE_NT_HEADERS32)ntHeader)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress :
        ((PIMAGE_NT_HEADERS64)ntHeader)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    vaExportDirectory = va ? vaModuleBase + va : 0;
    if(vaExportDirectory && VmmRead(H, pProcess, vaExportDirectory, (PBYTE)&hdrExportDirectory, sizeof(IMAGE_EXPORT_DIRECTORY)) && (hdrExportDirectory.NumberOfFunctions < 0x00010000)) {
        return hdrExportDirectory.NumberOfFunctions;
    }
    return 0;
}

_Success_(return)
BOOL PE_GetModuleNameEx(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess, _In_ QWORD vaModuleBase, _In_ BOOL fOnFailDummyName, _In_reads_opt_(0x1000) PBYTE pbModuleHeaderOpt, _Out_writes_(cszModuleName) PCHAR szModuleName, _In_ DWORD cszModuleName, _Out_opt_ PDWORD pdwSize)
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
    ntHeader = pbModuleHeaderOpt ? PE_HeaderGetVerify(H, pProcess, 0, pbModuleHeaderOpt, &f32) : PE_HeaderGetVerify(H, pProcess, vaModuleBase, pbModuleHeader, &f32);
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
    if(!VmmRead(H, pProcess, vaExportDirectory, pbExportDirectory, sizeof(IMAGE_EXPORT_DIRECTORY))) { goto fail; }
    exp = (PIMAGE_EXPORT_DIRECTORY)pbExportDirectory;
    if(!exp || !exp->Name || exp->Name > cbImageSize) { goto fail; }
    szModuleName[cszModuleName - 1] = 0;
    if(!VmmRead(H, pProcess, vaModuleBase + exp->Name, szModuleName, cszModuleName - 1)) { goto fail; }
    return TRUE;
fail:
    if(fOnFailDummyName) {
        memcpy(szModuleName, "UNKNOWN", 8);
        return TRUE;
    }
    return FALSE;
}

_Success_(return)
BOOL PE_GetModuleName(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess, _In_ QWORD vaModuleBase, _Out_writes_(cszModuleName) PCHAR szModuleName, _In_ DWORD cszModuleName)
{
    return PE_GetModuleNameEx(H, pProcess, vaModuleBase, FALSE, NULL, szModuleName, cszModuleName, NULL);
}

_Success_(return != 0)
DWORD PE_DirectoryGetOffset(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess, _In_opt_ QWORD vaModuleBase, _In_reads_opt_(0x1000) PBYTE pbModuleHeaderOpt, _In_ DWORD dwDirectory, _Out_opt_ PDWORD pcbSizeOfDirectory)
{
    BOOL f32;
    DWORD cbSizeOfImage, cbOffsetDirectory, cbSizeOfDirectory;
    PIMAGE_NT_HEADERS ntHeader;
    BYTE pbModuleHeader[0x1000] = { 0 };
    // load both 32/64 bit ntHeader unless already supplied in parameter (only one of 32/64 bit hdr will be valid)
    // load nt header either by using optionally supplied module header or by fetching from memory.
    ntHeader = pbModuleHeaderOpt ? PE_HeaderGetVerify(H, pProcess, 0, pbModuleHeaderOpt, &f32) : PE_HeaderGetVerify(H, pProcess, vaModuleBase, pbModuleHeader, &f32);
    if(!ntHeader) { return 0; }
    if(f32) {
        cbSizeOfImage = ((PIMAGE_NT_HEADERS32)ntHeader)->OptionalHeader.SizeOfImage;
        cbOffsetDirectory = ((PIMAGE_NT_HEADERS32)ntHeader)->OptionalHeader.DataDirectory[dwDirectory].VirtualAddress;
        cbSizeOfDirectory = ((PIMAGE_NT_HEADERS32)ntHeader)->OptionalHeader.DataDirectory[dwDirectory].Size;
    } else {
        cbSizeOfImage = ((PIMAGE_NT_HEADERS64)ntHeader)->OptionalHeader.SizeOfImage;
        cbOffsetDirectory = ((PIMAGE_NT_HEADERS64)ntHeader)->OptionalHeader.DataDirectory[dwDirectory].VirtualAddress;
        cbSizeOfDirectory = ((PIMAGE_NT_HEADERS64)ntHeader)->OptionalHeader.DataDirectory[dwDirectory].Size;
    }
    if((cbOffsetDirectory > 0x40000000) || (cbSizeOfDirectory > 0x40000000)) { return 0; }
    if(cbOffsetDirectory + cbSizeOfDirectory > cbSizeOfImage) { return 0; }
    if(pcbSizeOfDirectory) {
        *pcbSizeOfDirectory = cbSizeOfDirectory;
    }
    return cbOffsetDirectory;
}

_Success_(return)
BOOL PE_DirectoryGetAll(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess, _In_opt_ QWORD vaModuleBase, _In_reads_opt_(0x1000) PBYTE pbModuleHeaderOpt, _Out_writes_(IMAGE_NUMBEROF_DIRECTORY_ENTRIES) PIMAGE_DATA_DIRECTORY pDirectories)
{
    BOOL f32;
    PIMAGE_NT_HEADERS ntHeader;
    BYTE pbModuleHeader[0x1000] = { 0 };
    // load both 32/64 bit ntHeader unless already supplied in parameter (only one of 32/64 bit hdr will be valid)
    // load nt header either by using optionally supplied module header or by fetching from memory.
    ntHeader = pbModuleHeaderOpt ? PE_HeaderGetVerify(H, pProcess, 0, pbModuleHeaderOpt, &f32) : PE_HeaderGetVerify(H, pProcess, vaModuleBase, pbModuleHeader, &f32);
    if(!ntHeader) { return FALSE; }
    if(f32) {
        memcpy(pDirectories, ((PIMAGE_NT_HEADERS32)ntHeader)->OptionalHeader.DataDirectory, IMAGE_NUMBEROF_DIRECTORY_ENTRIES * sizeof(IMAGE_DATA_DIRECTORY));
    } else {
        memcpy(pDirectories, ((PIMAGE_NT_HEADERS64)ntHeader)->OptionalHeader.DataDirectory, IMAGE_NUMBEROF_DIRECTORY_ENTRIES * sizeof(IMAGE_DATA_DIRECTORY));
    }
    return TRUE;
}

_Success_(return)
BOOL PE_GetCodeViewInfo(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess, _In_opt_ QWORD vaModuleBase, _In_reads_opt_(0x1000) PBYTE pbModuleHeaderOpt, _Out_ PPE_CODEVIEW_INFO pCodeViewInfo)
{
    BOOL f, f32;
    BYTE pbModuleHeader[0x1000] = { 0 };
    PIMAGE_NT_HEADERS ntHeader;
    PIMAGE_NT_HEADERS64 ntHeader64;
    PIMAGE_NT_HEADERS32 ntHeader32;
    QWORD vaDebugDirectory;
    DWORD i, iMax, cbImageSize, cbDebugDirectory;
    PBYTE pbDebugDirectory = NULL;
    PIMAGE_DEBUG_DIRECTORY pDebugDirectory;
    ZeroMemory(pCodeViewInfo, sizeof(PE_CODEVIEW_INFO));
    // load both 32/64 bit ntHeader unless already supplied in parameter (only one of 32/64 bit hdr will be valid)
    // load nt header either by using optionally supplied module header or by fetching from memory.
    ntHeader = pbModuleHeaderOpt ? PE_HeaderGetVerify(H, pProcess, 0, pbModuleHeaderOpt, &f32) : PE_HeaderGetVerify(H, pProcess, vaModuleBase, pbModuleHeader, &f32);
    if(!ntHeader) { return FALSE; }
    if(!f32) { // 64-bit PE
        ntHeader64 = (PIMAGE_NT_HEADERS64)ntHeader;
        vaDebugDirectory = vaModuleBase + ntHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress;
        cbDebugDirectory = ntHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].Size;
        cbImageSize = ntHeader64->OptionalHeader.SizeOfImage;
    } else { // 32-bit PE
        ntHeader32 = (PIMAGE_NT_HEADERS32)ntHeader;
        vaDebugDirectory = vaModuleBase + ntHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress;
        cbDebugDirectory = ntHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].Size;
        cbImageSize = ntHeader32->OptionalHeader.SizeOfImage;
    }
    if((cbDebugDirectory < sizeof(IMAGE_DEBUG_DIRECTORY)) || (vaDebugDirectory == vaModuleBase) || (cbDebugDirectory > cbImageSize)) { goto fail; }
    if(!(pbDebugDirectory = LocalAlloc(0, cbDebugDirectory))) { goto fail; }
    if(!VmmRead(H, pProcess, vaDebugDirectory, pbDebugDirectory, cbDebugDirectory)) { goto fail; }
    for(i = 0, iMax = cbDebugDirectory / sizeof(IMAGE_DEBUG_DIRECTORY); i < iMax; i++) {
        pDebugDirectory = ((PIMAGE_DEBUG_DIRECTORY)pbDebugDirectory) + i;
        f = !pDebugDirectory->Characteristics &&
            (pDebugDirectory->Type == IMAGE_DEBUG_TYPE_CODEVIEW) &&
            (pDebugDirectory->SizeOfData <= sizeof(PE_CODEVIEW)) &&
            (pDebugDirectory->SizeOfData > 24) &&
            (pDebugDirectory->AddressOfRawData + pDebugDirectory->SizeOfData < cbImageSize) &&
            VmmRead(H, pProcess, vaModuleBase + pDebugDirectory->AddressOfRawData, (PBYTE)&pCodeViewInfo->CodeView, pDebugDirectory->SizeOfData) &&
            (pCodeViewInfo->CodeView.Signature == 0x53445352) &&
            (pCodeViewInfo->SizeCodeView = pDebugDirectory->SizeOfData);
        if(f) {
            LocalFree(pbDebugDirectory);
            return TRUE;
        }
        ZeroMemory(pCodeViewInfo, sizeof(PE_CODEVIEW_INFO));
    }
fail:
    ZeroMemory(pCodeViewInfo, sizeof(PE_CODEVIEW_INFO));
    LocalFree(pbDebugDirectory);
    return FALSE;

}

//-----------------------------------------------------------------------------
// READ / WRITE TO MEMORY BACKED RE-CONSTRUCTED 'RAW' PE FILES BELOW:
//-----------------------------------------------------------------------------

#define PE_SECTION_MEMREGIONS_MAX 0x40

typedef struct tdPE_SECTION_FILEREGIONS_RAW {
    DWORD cRegions;
    DWORD cbTotalSize;
    struct {
        DWORD cbOffsetFile;
        DWORD cbOffsetVMem;
        DWORD cb;
    } Region[PE_SECTION_MEMREGIONS_MAX + 1];
} PE_SECTION_FILEREGIONS_RAW, * PPE_SECTION_FILEREGIONS_RAW;

/*
* Retrieve the 'raw' section file regions from a PE header. The sections are
* optionally retrieved between the cbStartOpt and cbSizeOpt address/sizes.
* This is useful when reconstructing PE files from in-memory items.
* -- H
* -- pProcess
* -- vaModuleBase = PE module base address (unless pbModuleHeaderOpt is specified)
* -- pbModuleHaderOpt = Optional buffer containing module header (MZ) page.
* -- cbFileRegionStart = Start of the file region.
* -- cbSizeOpt = Size of file region.
* -- pRegions
* -- return
*/
_Success_(return)
BOOL PE_FileRaw_FileRegions(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess, _In_opt_ QWORD vaModuleBase, _In_reads_opt_(0x1000) PBYTE pbModuleHeaderOpt, _In_ DWORD cbFileRegionStart, _In_ DWORD cbFileRegionSize, _Out_ PPE_SECTION_FILEREGIONS_RAW pRegions)
{
    BOOL f32, fRegionInScope, fRegionInScopeAll;
    BYTE pbModuleHeader[0x1000] = { 0 };
    PIMAGE_NT_HEADERS ntHeader;
    PIMAGE_NT_HEADERS64 ntHeader64;
    PIMAGE_NT_HEADERS32 ntHeader32;
    DWORD cSections;
    DWORD iSection, dwMinSection = (DWORD)-1;
    DWORD cbFileRegionEnd = cbFileRegionStart + cbFileRegionSize;
    DWORD cbFileSectionStart, cbFileSectionEnd;
    PIMAGE_SECTION_HEADER pSections, pSection;
    // 1: load nt header and section base
    ntHeader = pbModuleHeaderOpt ? PE_HeaderGetVerify(H, pProcess, 0, pbModuleHeaderOpt, &f32) : PE_HeaderGetVerify(H, pProcess, vaModuleBase, pbModuleHeader, &f32);
    if(!ntHeader) { return FALSE; }
    if(f32) { // 32-bit PE
        ntHeader32 = (PIMAGE_NT_HEADERS32)ntHeader;
        cSections = ntHeader32->FileHeader.NumberOfSections;
        pSections = (PIMAGE_SECTION_HEADER)((QWORD)ntHeader32 + sizeof(IMAGE_NT_HEADERS32));
    } else { // 64-bit PE
        ntHeader64 = (PIMAGE_NT_HEADERS64)ntHeader;
        cSections = ntHeader64->FileHeader.NumberOfSections;
        pSections = (PIMAGE_SECTION_HEADER)((QWORD)ntHeader64 + sizeof(IMAGE_NT_HEADERS64));
    }
    if(!cSections || (cSections > PE_SECTION_MEMREGIONS_MAX)) { return FALSE; }
    ZeroMemory(pRegions, sizeof(PE_SECTION_FILEREGIONS_RAW));
    // 2: locate regions
    fRegionInScopeAll = !cbFileRegionStart && !cbFileRegionSize;
    for(iSection = 0; iSection < cSections; iSection++) {
        pSection = &pSections[iSection];
        if(0 == pSection->SizeOfRawData) { continue; }
        dwMinSection = min(dwMinSection, pSection->PointerToRawData);
        fRegionInScope =
            fRegionInScopeAll ||
            ((cbFileRegionStart >= pSection->PointerToRawData) && (cbFileRegionStart < pSection->PointerToRawData + pSection->SizeOfRawData)) ||
            ((cbFileRegionEnd > pSection->PointerToRawData) && (cbFileRegionEnd <= pSection->PointerToRawData + pSection->SizeOfRawData)) ||
            ((cbFileRegionStart < pSection->PointerToRawData) && (cbFileRegionEnd > pSection->PointerToRawData + pSection->SizeOfRawData));
        if(fRegionInScope) {
            // 3.1: some part inside section
            cbFileSectionStart = max(cbFileRegionStart, pSection->PointerToRawData);
            cbFileSectionEnd = min(cbFileRegionEnd, pSection->PointerToRawData + pSection->SizeOfRawData);
            pRegions->Region[pRegions->cRegions].cbOffsetVMem = pSection->VirtualAddress + cbFileSectionStart - pSection->PointerToRawData;
            pRegions->Region[pRegions->cRegions].cbOffsetFile = cbFileSectionStart;
            pRegions->Region[pRegions->cRegions].cb = cbFileSectionEnd - cbFileSectionStart;
            pRegions->cbTotalSize = max(pRegions->cbTotalSize, pSection->PointerToRawData + pSection->SizeOfRawData);
            if((pRegions->cbTotalSize > PE_MAX_SUPPORTED_SIZE) || (pRegions->Region[pRegions->cRegions].cb > PE_MAX_SUPPORTED_SIZE)) { return FALSE; }  // above max supported size (may be indication of corrupt data)
            pRegions->cRegions++;
        }
    }
    // 4: PE header fixup (not in section)
    if(dwMinSection > 0x1000) { dwMinSection = 0x1000; }
    if(cbFileRegionStart < dwMinSection) {
        pRegions->Region[pRegions->cRegions].cbOffsetVMem = cbFileRegionStart;
        pRegions->Region[pRegions->cRegions].cbOffsetFile = cbFileRegionStart;
        pRegions->Region[pRegions->cRegions].cb = min(cbFileRegionSize, dwMinSection - cbFileRegionStart);
        pRegions->cbTotalSize = max(pRegions->cbTotalSize, dwMinSection);
        pRegions->cRegions++;
    }
    return TRUE;
}

DWORD PE_FileRaw_Size(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess, _In_opt_ QWORD vaModuleBase, _In_reads_opt_(0x1000) PBYTE pbModuleHeaderOpt)
{
    BOOL f32;
    BYTE pbModuleHeader[0x1000] = { 0 };
    PIMAGE_NT_HEADERS ntHeader;
    PIMAGE_NT_HEADERS64 ntHeader64;
    PIMAGE_NT_HEADERS32 ntHeader32;
    DWORD cSections, cbModuleFile, iSection;
    PIMAGE_SECTION_HEADER pSections;
    // 1: load nt header and section base
    ntHeader = pbModuleHeaderOpt ? PE_HeaderGetVerify(H, pProcess, 0, pbModuleHeaderOpt, &f32) : PE_HeaderGetVerify(H, pProcess, vaModuleBase, pbModuleHeader, &f32);
    if(!ntHeader) { return FALSE; }
    if(f32) { // 32-bit PE
        ntHeader32 = (PIMAGE_NT_HEADERS32)ntHeader;
        cSections = ntHeader32->FileHeader.NumberOfSections;
        pSections = (PIMAGE_SECTION_HEADER)((QWORD)ntHeader32 + sizeof(IMAGE_NT_HEADERS32));
    } else { // 64-bit PE
        ntHeader64 = (PIMAGE_NT_HEADERS64)ntHeader;
        cSections = ntHeader64->FileHeader.NumberOfSections;
        pSections = (PIMAGE_SECTION_HEADER)((QWORD)ntHeader64 + sizeof(IMAGE_NT_HEADERS64));
    }
    // 2: calculate resulting size and return
    if(!cSections || (cSections > PE_SECTION_MEMREGIONS_MAX)) { return FALSE; }
    for(cbModuleFile = 0, iSection = 0; iSection < cSections; iSection++) {
        cbModuleFile = max(cbModuleFile, pSections[iSection].PointerToRawData + pSections[iSection].SizeOfRawData);
    }
    if(cbModuleFile > PE_MAX_SUPPORTED_SIZE) { return 0; }  // above max supported size (may be indication of corrupt data)
    return cbModuleFile;
}

_Success_(return)
BOOL PE_FileRaw_Read(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess, _In_ QWORD vaModuleBase, _Out_ PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ DWORD cbOffset)
{
    BOOL result;
    DWORD iRegion;
    PE_SECTION_FILEREGIONS_RAW PERegions;
    DWORD cbOffsetBuffer, cbRead;
    *pcbRead = 0;
    result = PE_FileRaw_FileRegions(H, pProcess, vaModuleBase, NULL, cbOffset, cb, &PERegions);
    if(!result) { return FALSE; }
    ZeroMemory(pb, cb);
    if(cbOffset + cb > PERegions.cbTotalSize) {
        if(cbOffset >= PERegions.cbTotalSize) {
            *pcbRead = 0;
            return TRUE;
        }
        cb = PERegions.cbTotalSize - cbOffset;
    }
    for(iRegion = 0; iRegion < PERegions.cRegions; iRegion++) {
        cbOffsetBuffer = PERegions.Region[iRegion].cbOffsetFile - cbOffset;
        if(cbOffsetBuffer + PERegions.Region[iRegion].cb > cb) {
            VmmLog(H, MID_PE, LOGLEVEL_WARNING, "SHOULD NOT HAPPEN! potential buffer overflow avoided reading module at PID=%i BASE=%016llx", pProcess->dwPID, vaModuleBase);
            continue;
        }
        VmmReadEx(
            H,
            pProcess,
            vaModuleBase + PERegions.Region[iRegion].cbOffsetVMem,
            pb + cbOffsetBuffer,
            PERegions.Region[iRegion].cb,
            &cbRead,
            VMM_FLAG_ZEROPAD_ON_FAIL);
    }
    *pcbRead = cb;
    return TRUE;
}

_Success_(return)
BOOL PE_FileRaw_Write(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess, _In_ QWORD vaModuleBase, _In_reads_(cb) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbWrite, _In_ DWORD cbOffset)
{
    BOOL result;
    DWORD iRegion, cbOffsetBuffer;
    PE_SECTION_FILEREGIONS_RAW PERegions;
    *pcbWrite = 0;
    result = PE_FileRaw_FileRegions(H, pProcess, vaModuleBase, NULL, cbOffset, cb, &PERegions);
    if(!result) { return FALSE; }
    if(cbOffset + cb > PERegions.cbTotalSize) {
        if(cbOffset >= PERegions.cbTotalSize) {
            *pcbWrite = 0;
            return TRUE;
        }
        cb = PERegions.cbTotalSize - cbOffset;
    }
    for(iRegion = 0; iRegion < PERegions.cRegions; iRegion++) {
        cbOffsetBuffer = PERegions.Region[iRegion].cbOffsetFile - cbOffset;
        if(cbOffsetBuffer + PERegions.Region[iRegion].cb > cb) {
            VmmLog(H, MID_PE, LOGLEVEL_WARNING, "SHOULD NOT HAPPEN! potential buffer overflow avoided writing module at PID=%i BASE=%016llx", pProcess->dwPID, vaModuleBase);
            continue;
        }
        VmmWrite(
            H,
            pProcess,
            vaModuleBase + PERegions.Region[iRegion].cbOffsetVMem,
            pb + cbOffsetBuffer,
            PERegions.Region[iRegion].cb);
    }
    *pcbWrite = cb;
    return TRUE;
}

/*
* Ensure that the requested PVOID is inside the resource data directory and
* that at least 0x800 remaining bytes in the buffer is available before end.
*/
PVOID PE_VsGetVersionInfo_EnsureBuffer(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess, _In_ QWORD vaResourceDataDirectory, _In_ DWORD cbResourceDataDirectory, _In_bytecount_(0x1000) PBYTE pbBuffer, _Inout_ PDWORD poBuffer, _In_ DWORD oResourceDataDirectory)
{
    if((oResourceDataDirectory >= *poBuffer) && (oResourceDataDirectory < *poBuffer + 0x800)) {
        return pbBuffer + oResourceDataDirectory - *poBuffer;
    }
    if(oResourceDataDirectory > cbResourceDataDirectory - 0x40) {
        return NULL;
    }
    if(!VmmRead(H, pProcess, vaResourceDataDirectory + oResourceDataDirectory, pbBuffer, 0x1000)) {
        return FALSE;
    }
    *poBuffer = oResourceDataDirectory;
    return pbBuffer;
}

// linux compatible byte representations of static resource strings:
static const BYTE PE_VERSIONINFO_VS_VERSION_INFO[]  = { 'V', 0, 'S', 0, '_', 0, 'V', 0, 'E', 0, 'R', 0, 'S', 0, 'I', 0, 'O', 0, 'N', 0, '_', 0, 'I', 0, 'N', 0, 'F', 0, 'O', 0, 0 };
static const BYTE PE_VERSIONINFO_StringFileInfo[]   = { 'S', 0, 't', 0, 'r', 0, 'i', 0, 'n', 0, 'g', 0, 'F', 0, 'i', 0, 'l', 0, 'e', 0, 'I', 0, 'n', 0, 'f', 0, 'o' };
static const BYTE PE_VERSIONINFO_CompanyName[]      = { 'C', 0, 'o', 0, 'm', 0, 'p', 0, 'a', 0, 'n', 0, 'y', 0, 'N', 0, 'a', 0, 'm', 0, 'e', 0 };
static const BYTE PE_VERSIONINFO_FileVersion[]      = { 'F', 0, 'i', 0, 'l', 0, 'e', 0, 'V', 0, 'e', 0, 'r', 0, 's', 0, 'i', 0, 'o', 0, 'n', 0 };
static const BYTE PE_VERSIONINFO_ProductName[]      = { 'P', 0, 'r', 0, 'o', 0, 'd', 0, 'u', 0, 'c', 0, 't', 0, 'N', 0, 'a', 0, 'm', 0, 'e', 0 };
static const BYTE PE_VERSIONINFO_InternalName[]     = { 'I', 0, 'n', 0, 't', 0, 'e', 0, 'r', 0, 'n', 0, 'a', 0, 'l', 0, 'N', 0, 'a', 0, 'm', 0, 'e', 0 };
static const BYTE PE_VERSIONINFO_LegalCopyright[]   = { 'L', 0, 'e', 0, 'g', 0, 'a', 0, 'l', 0, 'C', 0, 'o', 0, 'p', 0, 'y', 0, 'r', 0, 'i', 0, 'g', 0, 'h', 0, 't', 0 };
static const BYTE PE_VERSIONINFO_ProductVersion[]   = { 'P', 0, 'r', 0, 'o', 0, 'd', 0, 'u', 0, 'c', 0, 't', 0, 'V', 0, 'e', 0, 'r', 0, 's', 0, 'i', 0, 'o', 0, 'n', 0 };
static const BYTE PE_VERSIONINFO_FileDescription[]  = { 'F', 0, 'i', 0, 'l', 0, 'e', 0, 'D', 0, 'e', 0, 's', 0, 'c', 0, 'r', 0, 'i', 0, 'p', 0, 't', 0, 'i', 0, 'o', 0, 'n', 0 };
static const BYTE PE_VERSIONINFO_OriginalFilename[] = { 'O', 0, 'r', 0, 'i', 0, 'g', 0, 'i', 0, 'n', 0, 'a', 0, 'l', 0, 'F', 0, 'i', 0, 'l', 0, 'e', 0, 'n', 0, 'a', 0, 'm', 0, 'e', 0 };

#define PE_VERSIONINFO_ADDENTRY(psm, K, V, wszCMP, ppDstStr)      { if((*(PQWORD)K == *(PQWORD)wszCMP) && ((SIZE_T)V - (SIZE_T)K > sizeof(wszCMP)) && !memcmp(K, wszCMP, sizeof(wszCMP))) { ObStrMap_PushPtrWU(psm, V, ppDstStr, NULL); } }

_Success_(return)
BOOL PE_VsGetVersionInfo(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess, _In_ QWORD vaModuleBase, _In_ POB_STRMAP psm, _In_ PVMM_MAP_MODULEENTRY_VERSIONINFO pMEVI)
{
    // Parsing VS_VERSIONINFO out of the resource data directory is quite
    // horrible at least if doing securely with buffers and pointers.
    // Lots of code :(
    DWORD oBuffer = 0;
    BYTE *pb, pbBuffer[0x1000];
    DWORD cbResourceDataDirectory, oResourceDataDirectory;
    QWORD vaResourceDataDirectory;
    DWORD iLevel, i, cEntries;
    PIMAGE_RESOURCE_DIRECTORY pImageResourceDirectory = (PIMAGE_RESOURCE_DIRECTORY)pbBuffer;
    PIMAGE_RESOURCE_DIRECTORY_ENTRY pImageResourceDirectoryEntry = NULL;
    DWORD oNext, oMax, oVsVersionInfo, o;
    LPWSTR wszKey, wszValue;
    oResourceDataDirectory = PE_DirectoryGetOffset(H, pProcess, vaModuleBase, NULL, IMAGE_DIRECTORY_ENTRY_RESOURCE, &cbResourceDataDirectory);
    if(!oResourceDataDirectory || (cbResourceDataDirectory < 0x100)) { return FALSE; }
    vaResourceDataDirectory = vaModuleBase + oResourceDataDirectory;
    // 1: GRAB RT_VERSION (level1):
    if(!VmmRead(H, pProcess, vaModuleBase + oResourceDataDirectory, pbBuffer, sizeof(pbBuffer))) { return FALSE; }
    cEntries = pImageResourceDirectory->NumberOfNamedEntries + pImageResourceDirectory->NumberOfIdEntries;
    if(sizeof(pbBuffer) < sizeof(IMAGE_RESOURCE_DIRECTORY) + cEntries * sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY)) {
        cEntries = (sizeof(pbBuffer) - sizeof(IMAGE_RESOURCE_DIRECTORY)) / sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY);
    }
    for(i = 0; i < cEntries; i++) {
        pImageResourceDirectoryEntry = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)(pImageResourceDirectory + 1) + i;
        if(pImageResourceDirectoryEntry->Name == 16) {
            break;
        }
    }
    if(!pImageResourceDirectoryEntry || (pImageResourceDirectoryEntry->Name != 16) || !pImageResourceDirectoryEntry->DataIsDirectory) { return FALSE; }
    // 2: (level2 and level3/language):
    for(iLevel = 2; iLevel <= 3; iLevel++) {
        pImageResourceDirectory = (PIMAGE_RESOURCE_DIRECTORY)PE_VsGetVersionInfo_EnsureBuffer(H, pProcess, vaResourceDataDirectory, cbResourceDataDirectory, pbBuffer, &oBuffer, pImageResourceDirectoryEntry->OffsetToDirectory);
        if(!pImageResourceDirectory) { return FALSE; }
        if(0 == pImageResourceDirectory->NumberOfNamedEntries + pImageResourceDirectory->NumberOfIdEntries) { return FALSE; }
        pImageResourceDirectoryEntry = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)(pImageResourceDirectory + 1);
        if(pImageResourceDirectoryEntry->DataIsDirectory == iLevel - 2) { return FALSE; }
    }
    // 3: fetch offset (from start of module) to VS_VERSIONINFO resource and sanity check:
    pb = (PBYTE)PE_VsGetVersionInfo_EnsureBuffer(H, pProcess, vaResourceDataDirectory, cbResourceDataDirectory, pbBuffer, &oBuffer, pImageResourceDirectoryEntry->OffsetToData);
    if(!pb) { return FALSE; }
    oVsVersionInfo = *(PDWORD)pb - oResourceDataDirectory;          // offset inside resource directory of VS_VERSIONINFO struct
    pb = (PBYTE)PE_VsGetVersionInfo_EnsureBuffer(H, pProcess, vaResourceDataDirectory, cbResourceDataDirectory, pbBuffer, &oBuffer, oVsVersionInfo);
    if(!pb) { return FALSE; }
    // 4: readjust pb buffer (it should be able to hold remaining data without having to do a memory read):
    oMax = 0x1000 - ((SIZE_T)(pb - pbBuffer) & 0xfff);
    // 5: validate VS_VERSIONINFO struct:
    if(*(PWORD)pb > oMax) { return FALSE; }
    oMax = min(oMax, *(PWORD)pb);
    if(memcmp(pb + 6, PE_VERSIONINFO_VS_VERSION_INFO, sizeof(PE_VERSIONINFO_VS_VERSION_INFO))) { return FALSE; }
    oNext = (6 + sizeof(PE_VERSIONINFO_VS_VERSION_INFO) + *(PWORD)(pb + 2) + 3) & 0xffc;
    if(oNext + 2 > oMax) { return FALSE; }
    pb += oNext; oMax -= oNext;
    // 5: validate StringFileInfo:
    if(*(PWORD)pb > oMax) { return FALSE; }
    if(memcmp(pb + 6, PE_VERSIONINFO_StringFileInfo, sizeof(PE_VERSIONINFO_StringFileInfo))) { return FALSE; }
    oNext = (6 + sizeof(PE_VERSIONINFO_StringFileInfo) + 3) & 0xffc;
    if(oNext + 2 > oMax) { return FALSE; }
    pb += oNext; oMax -= oNext;
    // 6: validate StringTable:
    if(*(PWORD)pb > oMax) { return FALSE; }
    oNext = 0x18;
    if(oNext + 16 > oMax) { return FALSE; }
    pb += oNext; oMax -= oNext;
    // 7: Iterate Strings in remaining table:
    while(TRUE) {
        oNext = (*(PWORD)pb + 3) & 0xffc;
        if((oNext < 8) || (oNext + 10 > oMax)) { break; }
        if(*(PWORD)(pb + 4) == 1) {
            wszValue = NULL;
            wszKey = (LPWSTR)(pb + 6);
            // find end of key:
            for(o = 6; (o < oNext) && *(PWORD)(pb + o); o += 2) {
                ;
            }
            if(o < oNext) {
                o += 2;
                // find start of value:
                for(; o < oNext; o += 2) {
                    if(*(PWORD)(pb + o)) {
                        wszValue = (LPWSTR)(pb + o);
                        pb[oNext - 1] = 0;   // ensure null termination
                        pb[oNext - 2] = 0;
                        break;
                    }
                }
            }
            if(wszValue) {
                PE_VERSIONINFO_ADDENTRY(psm, wszKey, wszValue, PE_VERSIONINFO_CompanyName,      &pMEVI->uszCompanyName);
                PE_VERSIONINFO_ADDENTRY(psm, wszKey, wszValue, PE_VERSIONINFO_FileVersion,      &pMEVI->uszFileVersion);
                PE_VERSIONINFO_ADDENTRY(psm, wszKey, wszValue, PE_VERSIONINFO_ProductName,      &pMEVI->uszProductName);
                PE_VERSIONINFO_ADDENTRY(psm, wszKey, wszValue, PE_VERSIONINFO_InternalName,     &pMEVI->uszInternalName);
                PE_VERSIONINFO_ADDENTRY(psm, wszKey, wszValue, PE_VERSIONINFO_LegalCopyright,   &pMEVI->uszLegalCopyright);
                PE_VERSIONINFO_ADDENTRY(psm, wszKey, wszValue, PE_VERSIONINFO_ProductVersion,   &pMEVI->uszProductVersion);
                PE_VERSIONINFO_ADDENTRY(psm, wszKey, wszValue, PE_VERSIONINFO_FileDescription,  &pMEVI->uszFileDescription);
                PE_VERSIONINFO_ADDENTRY(psm, wszKey, wszValue, PE_VERSIONINFO_OriginalFilename, &pMEVI->uszOriginalFilename);
            }
        }
        pb += oNext; oMax -= oNext;
    }
    return TRUE;
}
