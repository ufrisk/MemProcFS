// vmmwin.c : implementation related to operating system and process
// parsing of virtual memory. Windows related features only.
//
// (c) Ulf Frisk, 2018-2025
// Author: Ulf Frisk, pcileech@frizk.net
//

#include "vmmwin.h"
#include "vmmwindef.h"
#include "vmmwinreg.h"
#include "vmmproc.h"
#include "charutil.h"
#include "util.h"
#include "pdb.h"
#include "pe.h"
#include "mm/mm.h"
#include "infodb.h"
#include "statistics.h"
#ifdef _WIN32
#include <sddl.h>
#include <shlwapi.h>
#endif /* _WIN32 */

// ----------------------------------------------------------------------------
// WINDOWS SPECIFIC PROCESS RELATED FUNCTIONALITY BELOW:
//    GENERAL FUNCTIONALITY
// ----------------------------------------------------------------------------

PIMAGE_NT_HEADERS VmmWin_GetVerifyHeaderPE(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess, _In_opt_ QWORD vaModule, _Inout_ PBYTE pbModuleHeader, _Out_ PBOOL pfHdr32)
{
    PIMAGE_DOS_HEADER dosHeader;
    PIMAGE_NT_HEADERS ntHeader;
    *pfHdr32 = FALSE;
    if(vaModule) {
        if(!VmmReadPage(H, pProcess, vaModule, pbModuleHeader)) { return NULL; }
    }
    dosHeader = (PIMAGE_DOS_HEADER)pbModuleHeader; // dos header.
    if(!dosHeader || dosHeader->e_magic != IMAGE_DOS_SIGNATURE) { return NULL; }
    if((dosHeader->e_lfanew < 0) || (dosHeader->e_lfanew > 0x800)) { return NULL; }
    ntHeader = (PIMAGE_NT_HEADERS)(pbModuleHeader + dosHeader->e_lfanew); // nt header
    if(!ntHeader || ntHeader->Signature != IMAGE_NT_SIGNATURE) { return NULL; }
    if((ntHeader->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) && (ntHeader->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC)) { return NULL; }
    *pfHdr32 = (ntHeader->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC);
    return ntHeader;
}

int VmmWin_HashTableLookup_CmpSort(PDWORD pdw1, PDWORD pdw2)
{
    return (*pdw1 < *pdw2) ? -1 : ((*pdw1 > *pdw2) ? 1 : 0);
}

// ----------------------------------------------------------------------------
// WINDOWS SPECIFIC PROCESS RELATED FUNCTIONALITY BELOW:
//    IMPORT/EXPORT DIRECTORY PARSING
// ----------------------------------------------------------------------------

/*
* Callback function for cache map entry validity - an entry is valid
* if it's in the same medium refresh tickcount.
*/
BOOL VmmWinEATIAT_Callback_ValidEntry(_In_ VMM_HANDLE H, _Inout_ PQWORD qwContext, _In_ QWORD qwKey, _In_ PVOID pvObject)
{
    return *qwContext == H->vmm.tcRefreshMedium;
}

VOID VmmWinEAT_ObCloseCallback(_In_ PVMMOB_MAP_EAT pObEAT)
{
    LocalFree(pObEAT->pbMultiText);
}

/*
* Helper function for EAT initialization.
* CALLER DECREF: return
* -- H
* -- pProcess
* -- pModule
* -- return
*/
PVMMOB_MAP_EAT VmmWinEAT_Initialize_DoWork(_In_ VMM_HANDLE H,  _In_ PVMM_PROCESS pProcess, _In_ PVMM_MAP_MODULEENTRY pModule)
{
    BYTE pbModuleHeader[0x1000] = { 0 };
    PIMAGE_NT_HEADERS64 ntHeader64;
    PIMAGE_NT_HEADERS32 ntHeader32;
    QWORD vaExpDir, vaExpDirTop, vaAddressOfNames, vaAddressOfNameOrdinals, vaAddressOfFunctions;
    DWORD i, oExpDir, cbExpDir, cForwardedFunctions = 0;
    PWORD pwNameOrdinals;
    PDWORD pdwRvaNames, pdwRvaFunctions;
    PBYTE pbExpDir = NULL;
    PIMAGE_EXPORT_DIRECTORY pExpDir;
    BOOL fHdr32;
    POB_STRMAP pObStrMap = NULL;
    PVMMOB_MAP_EAT pObEAT = NULL;
    PVMM_MAP_EATENTRY pe;
    // load both 32/64 bit ntHeader (only one will be valid)
    if(!(ntHeader64 = (PIMAGE_NT_HEADERS64)VmmWin_GetVerifyHeaderPE(H, pProcess, pModule->vaBase, pbModuleHeader, &fHdr32))) { goto fail; }
    ntHeader32 = (PIMAGE_NT_HEADERS32)ntHeader64;
    // load Export Address Table (EAT)
    oExpDir = fHdr32 ?
        ntHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress :
        ntHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    cbExpDir = fHdr32 ?
        ntHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size :
        ntHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
    vaExpDir = pModule->vaBase + oExpDir;
    vaExpDirTop = vaExpDir + cbExpDir - 1;
    if(!oExpDir || !cbExpDir || cbExpDir > 0x01000000) { goto fail; }
    if(!(pbExpDir = LocalAlloc(0, cbExpDir + 1ULL))) { goto fail; }
    if(!VmmRead(H, pProcess, vaExpDir, pbExpDir, cbExpDir)) { goto fail; }
    pbExpDir[cbExpDir] = 0;
    // sanity check EAT
    pExpDir = (PIMAGE_EXPORT_DIRECTORY)pbExpDir;
    if(!pExpDir->NumberOfFunctions || (pExpDir->NumberOfFunctions > 0xffff)) { goto fail; }
    if(pExpDir->NumberOfNames > pExpDir->NumberOfFunctions) { goto fail; }
    vaAddressOfNames = pModule->vaBase + pExpDir->AddressOfNames;
    vaAddressOfNameOrdinals = pModule->vaBase + pExpDir->AddressOfNameOrdinals;
    vaAddressOfFunctions = pModule->vaBase + pExpDir->AddressOfFunctions;
    if((vaAddressOfNames < vaExpDir) || (vaAddressOfNames >= vaExpDirTop - pExpDir->NumberOfNames * sizeof(DWORD))) { goto fail; }
    if((vaAddressOfNameOrdinals < vaExpDir) || (vaAddressOfNameOrdinals >= vaExpDirTop - pExpDir->NumberOfNames * sizeof(WORD))) { goto fail; }
    if((vaAddressOfFunctions < vaExpDir) || (vaAddressOfFunctions >= vaExpDirTop - pExpDir->NumberOfNames * sizeof(DWORD))) { goto fail; }
    pdwRvaNames = (PDWORD)(pbExpDir + pExpDir->AddressOfNames - oExpDir);
    pwNameOrdinals = (PWORD)(pbExpDir + pExpDir->AddressOfNameOrdinals - oExpDir);
    pdwRvaFunctions = (PDWORD)(pbExpDir + pExpDir->AddressOfFunctions - oExpDir);
    // allocate EAT-MAP
    if(!(pObStrMap = ObStrMap_New(H, OB_STRMAP_FLAGS_CASE_SENSITIVE))) { goto fail; }
    if(!(pObEAT = Ob_AllocEx(H, OB_TAG_MAP_EAT, LMEM_ZEROINIT, sizeof(VMMOB_MAP_EAT) + pExpDir->NumberOfFunctions * (sizeof(VMM_MAP_EATENTRY) + sizeof(QWORD)), (OB_CLEANUP_CB)VmmWinEAT_ObCloseCallback, NULL))) { goto fail; }
    pObEAT->pHashTableLookup = (PQWORD)((QWORD)pObEAT + sizeof(VMMOB_MAP_EAT) + pExpDir->NumberOfFunctions * sizeof(VMM_MAP_EATENTRY));
    pObEAT->cMap = pExpDir->NumberOfFunctions;
    pObEAT->vaModuleBase = pModule->vaBase;
    pObEAT->dwOrdinalBase = pExpDir->Base;
    pObEAT->vaAddressOfFunctions = vaAddressOfFunctions;
    pObEAT->vaAddressOfNames = vaAddressOfNames;
    pObEAT->cNumberOfFunctions = pExpDir->NumberOfFunctions;
    pObEAT->cNumberOfNames = pExpDir->NumberOfNames;
    // walk exported function names
    for(i = 0; i < pExpDir->NumberOfNames && i < pObEAT->cMap; i++) {
        if(pwNameOrdinals[i] >= pExpDir->NumberOfFunctions) { continue; }                   // name ordinal >= number of functions -> "fail"
        if(pdwRvaNames[i] < oExpDir || (pdwRvaNames[i] > vaExpDirTop)) { continue; }        // name outside export directory -> "fail"
        pe = pObEAT->pMap + pwNameOrdinals[i];
        pe->vaFunction = pModule->vaBase + pdwRvaFunctions[pwNameOrdinals[i]];
        pe->dwOrdinal = pExpDir->Base + pwNameOrdinals[i];
        pe->oFunctionsArray = pwNameOrdinals[i];
        pe->oNamesArray = i;
        ObStrMap_PushPtrAU(pObStrMap, (LPSTR)(pbExpDir - oExpDir + pdwRvaNames[i]), &pe->uszFunction, &pe->cbuFunction);
        if((pe->vaFunction > vaExpDir) && (pe->vaFunction < vaExpDirTop)) {
            // function pointer to export directory -> probably forwarded symbol
            if(PE_EatForwardedFunctionNameValidate((LPSTR)(pbExpDir + pe->vaFunction - vaExpDir), NULL, 0, NULL)) {
                ObStrMap_PushPtrAU(pObStrMap, (LPSTR)(pbExpDir + pe->vaFunction - vaExpDir), &pe->uszForwardedFunction, NULL);
                cForwardedFunctions++;
            }
            pe->vaFunction = 0;
        }
    }
    ObStrMap_FinalizeAllocU_DECREF_NULL(&pObStrMap, &pObEAT->pbMultiText, &pObEAT->cbMultiText);
    pObEAT->cNumberOfForwardedFunctions = cForwardedFunctions;
    // walk exported functions
    for(i = 0; i < pObEAT->cMap; i++) {
        pe = pObEAT->pMap + i;
        if(pe->cbuFunction) {    // function has name
            pObEAT->pHashTableLookup[i] = ((QWORD)i << 32) | (DWORD)CharUtil_Hash64U(pe->uszFunction, TRUE);
            continue;
        }
        pe->vaFunction = pModule->vaBase + pdwRvaFunctions[i];
        pe->dwOrdinal = pExpDir->Base + i;
        pe->oFunctionsArray = i;
        pe->oNamesArray = -1;
        pe->cbuFunction = 1;
        pe->uszFunction = (LPSTR)pObEAT->pbMultiText;
    }
    // sort hashtable, cleanup, return
    qsort(pObEAT->pHashTableLookup, pObEAT->cMap, sizeof(QWORD), (int(*)(const void *, const void *))VmmWin_HashTableLookup_CmpSort);
    LocalFree(pbExpDir);
    return pObEAT;
fail:
    Ob_DECREF(pObStrMap);
    LocalFree(pbExpDir);
    return Ob_AllocEx(H, OB_TAG_MAP_EAT, LMEM_ZEROINIT, sizeof(VMMOB_MAP_EAT), NULL, NULL);
}

/*
* Initialize EAT (exported functions) for a specific module.
* CALLER DECREF: return
* -- H
* -- pProcess
* -- pModule
* -- return
*/
_Success_(return != NULL)
PVMMOB_MAP_EAT VmmWinEAT_Initialize(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess, _In_ PVMM_MAP_MODULEENTRY pModule)
{
    BOOL f;
    PVMMOB_MAP_EAT pObMap = NULL;
    QWORD qwKey = (pProcess->dwPID ^ ((QWORD)pProcess->dwPID << 48) ^ pModule->vaBase);
    f = H->vmm.pObCacheMapEAT ||
        (H->vmm.pObCacheMapEAT = ObCacheMap_New(H, 0x20, VmmWinEATIAT_Callback_ValidEntry, OB_CACHEMAP_FLAGS_OBJECT_OB));
    if(!f) { return NULL; }
    if((pObMap = ObCacheMap_GetByKey(H->vmm.pObCacheMapEAT, qwKey))) { return pObMap; }
    EnterCriticalSection(&pProcess->LockUpdate);
    pObMap = ObCacheMap_GetByKey(H->vmm.pObCacheMapEAT, qwKey);
    if(!pObMap && (pObMap = VmmWinEAT_Initialize_DoWork(H, pProcess, pModule))) {
        ObCacheMap_Push(H->vmm.pObCacheMapEAT, qwKey, pObMap, H->vmm.tcRefreshMedium);
    }
    LeaveCriticalSection(&pProcess->LockUpdate);
    return pObMap;
}

VOID VmmWinIAT_ObCloseCallback(_In_ PVMMOB_MAP_IAT pObIAT)
{
    LocalFree(pObIAT->pbMultiText);
}

/*
* Helper function for IAT initialization.
* CALLER DECREF: return
* -- H
* -- pProcess
* -- pModule
* -- return
*/
PVMMOB_MAP_IAT VmmWinIAT_Initialize_DoWork(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess, _In_ PVMM_MAP_MODULEENTRY pModule)
{
    BYTE pbModuleHeader[0x1000] = { 0 };
    PIMAGE_NT_HEADERS64 ntHeader64;
    PIMAGE_NT_HEADERS32 ntHeader32;
    QWORD i, oImportDirectory;
    PIMAGE_IMPORT_DESCRIPTOR pIID;
    PQWORD pIAT64, pHNA64;
    PDWORD pIAT32, pHNA32;
    PBYTE pbModule = NULL;
    DWORD c, j, cbModule, cbRead;
    BOOL fHdr32, fNameFn, fNameMod;
    POB_STRMAP pObStrMap = NULL;
    PVMMOB_MAP_IAT pObIAT = NULL;
    PVMM_MAP_IATENTRY pe;
    // Load the module
    if(pModule->cbImageSize > PE_MAX_SUPPORTED_SIZE) { goto fail; }    // above max supported size (may be indication of corrupt data)
    cbModule = pModule->cbImageSize;
    if(!(pbModule = LocalAlloc(LMEM_ZEROINIT, cbModule))) { goto fail; }
    VmmReadEx(H, pProcess, pModule->vaBase, pbModule, cbModule, &cbRead, 0);
    if(cbRead <= 0x2000) { goto fail; }
    pbModule[cbModule - 1] = 0;
    // load both 32/64 bit ntHeader (only one will be valid)
    if(!(ntHeader64 = (PIMAGE_NT_HEADERS64)VmmWin_GetVerifyHeaderPE(H, pProcess, pModule->vaBase, pbModuleHeader, &fHdr32))) { goto fail; }
    ntHeader32 = (PIMAGE_NT_HEADERS32)ntHeader64;
    oImportDirectory = fHdr32 ?
        ntHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress :
        ntHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    if(!oImportDirectory || (oImportDirectory >= cbModule)) { goto fail; }
    // Allocate IAT-MAP
    if(!(pObStrMap = ObStrMap_New(H, OB_STRMAP_FLAGS_CASE_SENSITIVE))) { goto fail; }
    if(!(pObIAT = Ob_AllocEx(H, OB_TAG_MAP_IAT, LMEM_ZEROINIT, sizeof(VMMOB_MAP_IAT) + pModule->cIAT * sizeof(VMM_MAP_IATENTRY), (OB_CLEANUP_CB)VmmWinIAT_ObCloseCallback, NULL))) { goto fail; }
    pObIAT->cMap = pModule->cIAT;
    pObIAT->vaModuleBase = pModule->vaBase;
    // Walk imported modules / functions
    pIID = (PIMAGE_IMPORT_DESCRIPTOR)(pbModule + oImportDirectory);
    i = 0, c = 0;
    while((oImportDirectory + (i + 1) * sizeof(IMAGE_IMPORT_DESCRIPTOR) < cbModule) && pIID[i].FirstThunk) {
        if(c >= pObIAT->cMap) { break; }
        if(pIID[i].Name > cbModule - 64) { i++; continue; }
        if(fHdr32) {
            // 32-bit PE
            j = 0;
            pIAT32 = (PDWORD)(pbModule + pIID[i].FirstThunk);
            pHNA32 = (PDWORD)(pbModule + pIID[i].OriginalFirstThunk);
            while(TRUE) {
                if(c >= pObIAT->cMap) { break; }
                if((QWORD)(pIAT32 + j) + sizeof(DWORD) - (QWORD)pbModule > cbModule) { break; }
                if((QWORD)(pHNA32 + j) + sizeof(DWORD) - (QWORD)pbModule > cbModule) { break; }
                if(!pIAT32[j]) { break; }
                if(!pHNA32[j]) { break; }
                fNameFn = (pHNA32[j] < cbModule);
                fNameMod = (pIID[i].Name < cbModule);
                // store
                pe = pObIAT->pMap + c;
                pe->vaFunction = pIAT32[j];
                ObStrMap_PushPtrAU(pObStrMap, (fNameFn ? (LPSTR)(pbModule + pHNA32[j] + 2) : NULL), &pe->uszFunction, &pe->cbuFunction);
                ObStrMap_PushPtrAU(pObStrMap, (fNameMod ? (LPSTR)(pbModule + pIID[i].Name) : NULL), &pe->uszModule, &pe->cbuModule);
                pe->Thunk.f32 = TRUE;
                pe->Thunk.rvaFirstThunk = pIID[i].FirstThunk + j * sizeof(DWORD);
                pe->Thunk.rvaOriginalFirstThunk = pIID[i].OriginalFirstThunk + j * sizeof(DWORD);
                pe->Thunk.wHint = fNameFn ? *(PWORD)(pbModule + pHNA32[j]) : 0;
                pe->Thunk.rvaNameFunction = pHNA32[j];
                pe->Thunk.rvaNameModule = pIID[i].Name;
                c++;
                j++;
            }
        } else {
            // 64-bit PE
            j = 0;
            pIAT64 = (PQWORD)(pbModule + pIID[i].FirstThunk);
            pHNA64 = (PQWORD)(pbModule + pIID[i].OriginalFirstThunk);
            while(TRUE) {
                if(c >= pObIAT->cMap) { break; }
                if((QWORD)(pIAT64 + j) + sizeof(QWORD) - (QWORD)pbModule > cbModule) { break; }
                if((QWORD)(pHNA64 + j) + sizeof(QWORD) - (QWORD)pbModule > cbModule) { break; }
                if(!pIAT64[j] || (!VMM_UADDR64(pIAT64[j]) && !VMM_KADDR64(pIAT64[j]))) { break; }
                if(!pHNA64[j]) { break; }
                fNameFn = (pHNA64[j] < cbModule);
                fNameMod = (pIID[i].Name < cbModule);
                // store
                pe = pObIAT->pMap + c;
                pe->vaFunction = pIAT64[j];
                ObStrMap_PushPtrAU(pObStrMap, (fNameFn ? (LPSTR)(pbModule + pHNA64[j] + 2) : NULL), &pe->uszFunction, &pe->cbuFunction);
                ObStrMap_PushPtrAU(pObStrMap, (fNameMod ? (LPSTR)(pbModule + pIID[i].Name) : NULL), &pe->uszModule, &pe->cbuModule);
                pe->Thunk.f32 = FALSE;
                pe->Thunk.rvaFirstThunk = pIID[i].FirstThunk + j * sizeof(QWORD);
                pe->Thunk.rvaOriginalFirstThunk = pIID[i].OriginalFirstThunk + j * sizeof(QWORD);
                pe->Thunk.wHint = fNameFn ? *(PWORD)(pbModule + pHNA64[j]) : 0;
                pe->Thunk.rvaNameFunction = (DWORD)pHNA64[j];
                pe->Thunk.rvaNameModule = pIID[i].Name;
                c++;
                j++;
            }
        }
        i++;
    }
    // fixups
    ObStrMap_FinalizeAllocU_DECREF_NULL(&pObStrMap, &pObIAT->pbMultiText, &pObIAT->cbMultiText);
    for(i = 0; i < pObIAT->cMap; i++) {
        pe = pObIAT->pMap + i;
        if(!pe->uszModule) {
            pe->cbuModule = 1;
            pe->uszModule = (LPSTR)pObIAT->pbMultiText;
        }
        if(!pe->uszFunction) {
            pe->cbuFunction = 1;
            pe->uszFunction = (LPSTR)pObIAT->pbMultiText;
        }
    }
    LocalFree(pbModule);
    return pObIAT;
fail:
    LocalFree(pbModule);
    Ob_DECREF(pObStrMap);
    return Ob_AllocEx(H, OB_TAG_MAP_IAT, LMEM_ZEROINIT, sizeof(VMMOB_MAP_IAT), NULL, NULL);
}

/*
* Initialize IAT (imported functions) for a specific module.
* CALLER DECREF: return
* -- H
* -- pProcess
* -- pModule
* -- return
*/
_Success_(return != NULL)
PVMMOB_MAP_IAT VmmWinIAT_Initialize(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess, _In_ PVMM_MAP_MODULEENTRY pModule)
{
    BOOL f;
    PVMMOB_MAP_IAT pObMap = NULL;
    QWORD qwKey = (pProcess->dwPID ^ ((QWORD)pProcess->dwPID << 48) ^ pModule->vaBase);
    f = H->vmm.pObCacheMapIAT ||
        (H->vmm.pObCacheMapIAT = ObCacheMap_New(H, 0x20, VmmWinEATIAT_Callback_ValidEntry, OB_CACHEMAP_FLAGS_OBJECT_OB));
    if(!f) { return NULL; }
    if((pObMap = ObCacheMap_GetByKey(H->vmm.pObCacheMapIAT, qwKey))) { return pObMap; }
    EnterCriticalSection(&pProcess->LockUpdate);
    pObMap = ObCacheMap_GetByKey(H->vmm.pObCacheMapIAT, qwKey);
    if(!pObMap && (pObMap = VmmWinIAT_Initialize_DoWork(H, pProcess, pModule))) {
        ObCacheMap_Push(H->vmm.pObCacheMapIAT, qwKey, pObMap, H->vmm.tcRefreshMedium);
    }
    LeaveCriticalSection(&pProcess->LockUpdate);
    return pObMap;
}



// ----------------------------------------------------------------------------
// WINDOWS SPECIFIC PROCESS RELATED FUNCTIONALITY BELOW:
//    PEB/LDR USER MODE PARSING CODE (64-bit and 32-bit)
// ----------------------------------------------------------------------------

#define VMMPROCWINDOWS_MAX_MODULES      512

typedef struct tdVMMWIN_LDRMODULES_CONTEXT {
    DWORD cwszTextTotal;
    DWORD cModules;
    DWORD cModulesMax;
    PVMM_MAP_MODULEENTRY pModules;
    POB_SET psVaName;
} VMMWIN_LDRMODULES_CONTEXT, *PVMMWIN_LDRMODULES_CONTEXT;

VOID VmmWinLdrModule_Initialize_VSetPutVA(_In_ POB_SET pObSet_vaAll, _In_ POB_SET pObSet_vaTry1, _In_ QWORD va)
{
    if(!ObSet_Exists(pObSet_vaAll, va)) {
        ObSet_Push(pObSet_vaAll, va);
        ObSet_Push(pObSet_vaTry1, va);
    }
}

VOID VmmWinLdrModule_Initialize64(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess, _Inout_ POB_MAP pmModules, _In_ BOOL fUserOnly)
{
    QWORD vaModuleLdrFirst64, vaModuleLdr64 = 0;
    BYTE pbPEB64[sizeof(PEB64)], pbPEBLdrData64[sizeof(PEB_LDR_DATA64)], pbLdrModule64[sizeof(LDR_MODULE64)];
    PPEB64 pPEB64 = (PPEB64)pbPEB64;
    PPEB_LDR_DATA64 pPEBLdrData64 = (PPEB_LDR_DATA64)pbPEBLdrData64;
    PLDR_MODULE64 pLdrModule64 = (PLDR_MODULE64)pbLdrModule64;
    VMM_MAP_MODULEENTRY oModule;
    POB_SET pObSet_vaAll = NULL, pObSet_vaTry1 = NULL, pObSet_vaTry2 = NULL;
    BOOL fTry1;
    DWORD i, cbReadData;
    // prefetch existing addresses (if any) & allocate new vaModuleLdr VSet
    pObSet_vaAll = ObContainer_GetOb(pProcess->pObPersistent->pObCLdrModulesPrefetch64);
    VmmCachePrefetchPages3(H, pProcess, pObSet_vaAll, sizeof(LDR_MODULE64), 0);
    Ob_DECREF_NULL(&pObSet_vaAll);
    if(!(pObSet_vaAll = ObSet_New(H))) { goto fail; }
    if(!(pObSet_vaTry1 = ObSet_New(H))) { goto fail; }
    if(!(pObSet_vaTry2 = ObSet_New(H))) { goto fail; }
    // set up initial entry in vaModuleLdr DataSet
    if(fUserOnly) {
        // User mode process -> walk PEB LDR list to enumerate modules / .dlls.
        if(!pProcess->win.vaPEB) { goto fail; }
        if(!VmmRead(H, pProcess, pProcess->win.vaPEB, pbPEB64, sizeof(PEB64))) { goto fail; }
        if(!VmmRead(H, pProcess, (QWORD)pPEB64->Ldr, pbPEBLdrData64, sizeof(PEB_LDR_DATA64))) { goto fail; }
        for(i = 0; i < 6; i++) {
            vaModuleLdrFirst64 = *(PQWORD)((PBYTE)&pPEBLdrData64->InLoadOrderModuleList + (5 - i) * sizeof(QWORD));
            if(VMM_UADDR64_8(vaModuleLdrFirst64)) {
                ObSet_Push(pObSet_vaAll, vaModuleLdrFirst64);
                ObSet_Push(pObSet_vaTry1, vaModuleLdrFirst64);
            }
        }
    } else {
        // Kernel mode process -> walk PsLoadedModuleList to enumerate drivers / .sys and .dlls.
        if(!H->vmm.kernel.vaPsLoadedModuleListPtr) { goto fail; }
        if(!VmmRead(H, pProcess, H->vmm.kernel.vaPsLoadedModuleListPtr, (PBYTE)&vaModuleLdrFirst64, sizeof(QWORD)) || !vaModuleLdrFirst64) { goto fail; }
        if(!VmmRead(H, pProcess, H->vmm.kernel.vaPsLoadedModuleListPtr, pbPEBLdrData64, sizeof(PEB_LDR_DATA64))) { goto fail; }
        ObSet_Push(pObSet_vaAll, vaModuleLdrFirst64);
        ObSet_Push(pObSet_vaTry1, vaModuleLdrFirst64);
    }
    // iterate over modules using all available linked lists in an efficient way.
    fTry1 = TRUE;
    vaModuleLdr64 = 0;
    VmmCachePrefetchPages3(H, pProcess, pObSet_vaTry1, sizeof(PEB_LDR_DATA64), 0);
    while(ObMap_Size(pmModules) < VMMPROCWINDOWS_MAX_MODULES) {
        if(fTry1) {
            vaModuleLdr64 = ObSet_Pop(pObSet_vaTry1);
            if(!vaModuleLdr64 && (0 == ObSet_Size(pObSet_vaTry2))) { break; }
            if(!vaModuleLdr64) {
                VmmCachePrefetchPages3(H, pProcess, pObSet_vaAll, sizeof(PEB_LDR_DATA64), 0);
                fTry1 = FALSE;
                continue;
            }
            VmmReadEx(H, pProcess, vaModuleLdr64, pbLdrModule64, sizeof(LDR_MODULE64), &cbReadData, VMM_FLAG_FORCECACHE_READ);
            if(cbReadData != sizeof(LDR_MODULE64)) {
                ObSet_Push(pObSet_vaTry2, vaModuleLdr64);
                continue;
            }
        } else {
            vaModuleLdr64 = ObSet_Pop(pObSet_vaTry2);
            if(!vaModuleLdr64 && (0 == ObSet_Size(pObSet_vaTry1))) { break; }
            if(!vaModuleLdr64) { fTry1 = TRUE; continue; }
            if(!VmmRead(H, pProcess, vaModuleLdr64, pbLdrModule64, sizeof(LDR_MODULE64))) { continue; }
        }
        if(!pLdrModule64->BaseAddress || (pLdrModule64->BaseAddress & 0xfff)) { continue; }
        if(!pLdrModule64->SizeOfImage || (pLdrModule64->SizeOfImage >= 0x40000000)) { continue; }
        if(!pLdrModule64->BaseDllName.Length || pLdrModule64->BaseDllName.Length >= 0x1000) { continue; }
        ZeroMemory(&oModule, sizeof(VMM_MAP_MODULEENTRY));
        oModule.vaBase = pLdrModule64->BaseAddress;
        oModule.vaEntry = pLdrModule64->EntryPoint;
        oModule.cbImageSize = (DWORD)pLdrModule64->SizeOfImage;
        oModule.fWoW64 = FALSE;
        // module name
        oModule.cbuText = pLdrModule64->BaseDllName.Length;
        oModule._Reserved1 = pLdrModule64->BaseDllName.Buffer;
        // module path+name
        oModule.cbuFullName = pLdrModule64->FullDllName.Length;
        oModule._Reserved3 = pLdrModule64->FullDllName.Buffer;
        // push module to result map
        ObMap_PushCopy(pmModules, oModule.vaBase, &oModule, sizeof(VMM_MAP_MODULEENTRY));
        // add FLinkAll/BLink lists
        if(pLdrModule64->InLoadOrderModuleList.Flink && !((QWORD)pLdrModule64->InLoadOrderModuleList.Flink & 0x7)) {
            VmmWinLdrModule_Initialize_VSetPutVA(pObSet_vaAll, pObSet_vaTry1, (QWORD)CONTAINING_RECORD64(pLdrModule64->InLoadOrderModuleList.Flink, LDR_MODULE64, InLoadOrderModuleList));
        }
        if(pLdrModule64->InLoadOrderModuleList.Blink && !((QWORD)pLdrModule64->InLoadOrderModuleList.Blink & 0x7)) {
            VmmWinLdrModule_Initialize_VSetPutVA(pObSet_vaAll, pObSet_vaTry1, (QWORD)CONTAINING_RECORD64(pLdrModule64->InLoadOrderModuleList.Blink, LDR_MODULE64, InLoadOrderModuleList));
        }
        if(pProcess->fUserOnly) {
            if(pLdrModule64->InInitializationOrderModuleList.Flink && !((QWORD)pLdrModule64->InInitializationOrderModuleList.Flink & 0x7)) {
                VmmWinLdrModule_Initialize_VSetPutVA(pObSet_vaAll, pObSet_vaTry1, (QWORD)CONTAINING_RECORD64(pLdrModule64->InInitializationOrderModuleList.Flink, LDR_MODULE64, InInitializationOrderModuleList));
            }
            if(pLdrModule64->InInitializationOrderModuleList.Blink && !((QWORD)pLdrModule64->InInitializationOrderModuleList.Blink & 0x7)) {
                VmmWinLdrModule_Initialize_VSetPutVA(pObSet_vaAll, pObSet_vaTry1, (QWORD)CONTAINING_RECORD64(pLdrModule64->InInitializationOrderModuleList.Blink, LDR_MODULE64, InInitializationOrderModuleList));
            }
            if(pLdrModule64->InMemoryOrderModuleList.Flink && !((QWORD)pLdrModule64->InMemoryOrderModuleList.Flink & 0x7)) {
                VmmWinLdrModule_Initialize_VSetPutVA(pObSet_vaAll, pObSet_vaTry1, (QWORD)CONTAINING_RECORD64(pLdrModule64->InMemoryOrderModuleList.Flink, LDR_MODULE64, InMemoryOrderModuleList));
            }
            if(pLdrModule64->InMemoryOrderModuleList.Blink && !((QWORD)pLdrModule64->InMemoryOrderModuleList.Blink & 0x7)) {
                VmmWinLdrModule_Initialize_VSetPutVA(pObSet_vaAll, pObSet_vaTry1, (QWORD)CONTAINING_RECORD64(pLdrModule64->InMemoryOrderModuleList.Blink, LDR_MODULE64, InMemoryOrderModuleList));
            }
        }
    }
    // save prefetch addresses (if desirable)
    if(H->dev.fVolatile && H->vmm.ThreadProcCache.fEnabled) {
        ObContainer_SetOb(pProcess->pObPersistent->pObCLdrModulesPrefetch64, pObSet_vaAll);
    }
fail:
    Ob_DECREF(pObSet_vaAll);
    Ob_DECREF(pObSet_vaTry1);
    Ob_DECREF(pObSet_vaTry2);
    if(!fUserOnly && pProcess->win.vaPEB) {
        VmmWinLdrModule_Initialize64(H, pProcess, pmModules, TRUE);
    }
}

VOID VmmWinLdrModule_Initialize32(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess, _Inout_ POB_MAP pmModules, _In_ BOOL fUserOnly)
{
    DWORD vaModuleLdrFirst32, vaModuleLdr32 = 0;
    BYTE pbPEB32[sizeof(PEB32)], pbPEBLdrData32[sizeof(PEB_LDR_DATA32)], pbLdrModule32[sizeof(LDR_MODULE32)];
    PPEB32 pPEB32 = (PPEB32)pbPEB32;
    PPEB_LDR_DATA32 pPEBLdrData32 = (PPEB_LDR_DATA32)pbPEBLdrData32;
    PLDR_MODULE32 pLdrModule32 = (PLDR_MODULE32)pbLdrModule32;
    VMM_MAP_MODULEENTRY oModule;
    POB_SET pObSet_vaAll = NULL, pObSet_vaTry1 = NULL, pObSet_vaTry2 = NULL;
    BOOL fTry1;
    DWORD i, cbReadData;
    // prefetch existing addresses (if any) & allocate new vaModuleLdr VSet
    pObSet_vaAll = ObContainer_GetOb(pProcess->pObPersistent->pObCLdrModulesPrefetch32);
    VmmCachePrefetchPages3(H, pProcess, pObSet_vaAll, sizeof(LDR_MODULE32), 0);
    Ob_DECREF(pObSet_vaAll);
    if(!(pObSet_vaAll = ObSet_New(H))) { goto fail; }
    if(!(pObSet_vaTry1 = ObSet_New(H))) { goto fail; }
    if(!(pObSet_vaTry2 = ObSet_New(H))) { goto fail; }
    // set up initial entry in vaModuleLdr DataSet
    if(fUserOnly) {
        if(!pProcess->win.vaPEB32) { goto fail; }
        if(!VmmRead(H, pProcess, pProcess->win.vaPEB32, pbPEB32, sizeof(PEB32))) { goto fail; }
        if(!VmmRead(H, pProcess, (QWORD)pPEB32->Ldr, pbPEBLdrData32, sizeof(PEB_LDR_DATA32))) { goto fail; }
        for(i = 0; i < 6; i++) {
            vaModuleLdrFirst32 = *(PDWORD)((PBYTE)&pPEBLdrData32->InLoadOrderModuleList + (5 - i) * sizeof(DWORD));
            if(VMM_UADDR32_4(vaModuleLdrFirst32)) {
                ObSet_Push(pObSet_vaAll, vaModuleLdrFirst32);
                ObSet_Push(pObSet_vaTry1, vaModuleLdrFirst32);
            }
        }

    } else if(H->vmm.tpSystem == VMM_SYSTEM_WINDOWS_32) {
        // Kernel mode process -> walk PsLoadedModuleList to enumerate drivers / .sys and .dlls.
        if(!H->vmm.kernel.vaPsLoadedModuleListPtr) { goto fail; }
        if(!VmmRead(H, pProcess, H->vmm.kernel.vaPsLoadedModuleListPtr, (PBYTE)&vaModuleLdrFirst32, sizeof(DWORD)) || !vaModuleLdrFirst32) { goto fail; }
        if(!VmmRead(H, pProcess, H->vmm.kernel.vaPsLoadedModuleListPtr, pbPEBLdrData32, sizeof(PEB_LDR_DATA32))) { goto fail; }
        ObSet_Push(pObSet_vaAll, vaModuleLdrFirst32);
        ObSet_Push(pObSet_vaTry1, vaModuleLdrFirst32);
    } else {
        goto fail;
    }
    // iterate over modules using all available linked lists in an efficient way.
    fTry1 = TRUE;
    vaModuleLdr32 = 0;
    VmmCachePrefetchPages3(H, pProcess, pObSet_vaTry1, sizeof(PEB_LDR_DATA32), 0);
    while(ObMap_Size(pmModules) < VMMPROCWINDOWS_MAX_MODULES) {
        if(fTry1) {
            vaModuleLdr32 = (DWORD)ObSet_Pop(pObSet_vaTry1);
            if(!vaModuleLdr32 && (0 == ObSet_Size(pObSet_vaTry2))) { break; }
            if(!vaModuleLdr32) {
                VmmCachePrefetchPages3(H, pProcess, pObSet_vaAll, sizeof(PEB_LDR_DATA32), 0);
                fTry1 = FALSE;
                continue;
            }
            VmmReadEx(H, pProcess, vaModuleLdr32, pbLdrModule32, sizeof(LDR_MODULE32), &cbReadData, VMM_FLAG_FORCECACHE_READ);
            if(cbReadData != sizeof(LDR_MODULE64)) {
                ObSet_Push(pObSet_vaTry2, vaModuleLdr32);
                continue;
            }
        } else {
            vaModuleLdr32 = (DWORD)ObSet_Pop(pObSet_vaTry2);
            if(!vaModuleLdr32 && (0 == ObSet_Size(pObSet_vaTry1))) { break; }
            if(!vaModuleLdr32) { fTry1 = TRUE; continue; }
            if(!VmmRead(H, pProcess, vaModuleLdr32, pbLdrModule32, sizeof(LDR_MODULE32))) { continue; }
        }
        if(!pLdrModule32->BaseAddress || (pLdrModule32->BaseAddress & 0xfff)) { continue; }
        if(!pLdrModule32->SizeOfImage || (pLdrModule32->SizeOfImage >= 0x10000000)) { continue; }
        if(!pLdrModule32->BaseDllName.Length || pLdrModule32->BaseDllName.Length >= 0x1000) { continue; }
        ZeroMemory(&oModule, sizeof(VMM_MAP_MODULEENTRY));
        oModule.vaBase = (QWORD)pLdrModule32->BaseAddress;
        oModule.vaEntry = (QWORD)pLdrModule32->EntryPoint;
        oModule.cbImageSize = (DWORD)pLdrModule32->SizeOfImage;
        oModule.fWoW64 = pProcess->win.fWow64;
        // module name
        oModule.cbuText = pLdrModule32->BaseDllName.Length;
        oModule._Reserved1 = pLdrModule32->BaseDllName.Buffer;
        // module path+name
        oModule.cbuFullName = pLdrModule32->FullDllName.Length;
        oModule._Reserved3 = pLdrModule32->FullDllName.Buffer;
        // push module to result map
        ObMap_PushCopy(pmModules, oModule.vaBase, &oModule, sizeof(VMM_MAP_MODULEENTRY));
        // add FLinkAll/BLink lists
        if(pLdrModule32->InLoadOrderModuleList.Flink && !((DWORD)pLdrModule32->InLoadOrderModuleList.Flink & 0x3)) {
            VmmWinLdrModule_Initialize_VSetPutVA(pObSet_vaAll, pObSet_vaTry1, (QWORD)CONTAINING_RECORD32(pLdrModule32->InLoadOrderModuleList.Flink, LDR_MODULE32, InLoadOrderModuleList));
        }
        if(pLdrModule32->InLoadOrderModuleList.Blink && !((DWORD)pLdrModule32->InLoadOrderModuleList.Blink & 0x3)) {
            VmmWinLdrModule_Initialize_VSetPutVA(pObSet_vaAll, pObSet_vaTry1, (QWORD)CONTAINING_RECORD32(pLdrModule32->InLoadOrderModuleList.Blink, LDR_MODULE32, InLoadOrderModuleList));
        }
        if(pProcess->fUserOnly) {
            if(pLdrModule32->InInitializationOrderModuleList.Flink && !((DWORD)pLdrModule32->InInitializationOrderModuleList.Flink & 0x3)) {
                VmmWinLdrModule_Initialize_VSetPutVA(pObSet_vaAll, pObSet_vaTry1, (QWORD)CONTAINING_RECORD32(pLdrModule32->InInitializationOrderModuleList.Flink, LDR_MODULE32, InInitializationOrderModuleList));
            }
            if(pLdrModule32->InInitializationOrderModuleList.Blink && !((DWORD)pLdrModule32->InInitializationOrderModuleList.Blink & 0x3)) {
                VmmWinLdrModule_Initialize_VSetPutVA(pObSet_vaAll, pObSet_vaTry1, (QWORD)CONTAINING_RECORD32(pLdrModule32->InInitializationOrderModuleList.Blink, LDR_MODULE32, InInitializationOrderModuleList));
            }
            if(pLdrModule32->InMemoryOrderModuleList.Flink && !((DWORD)pLdrModule32->InMemoryOrderModuleList.Flink & 0x3)) {
                VmmWinLdrModule_Initialize_VSetPutVA(pObSet_vaAll, pObSet_vaTry1, (QWORD)CONTAINING_RECORD32(pLdrModule32->InMemoryOrderModuleList.Flink, LDR_MODULE32, InMemoryOrderModuleList));
            }
            if(pLdrModule32->InMemoryOrderModuleList.Blink && !((DWORD)pLdrModule32->InMemoryOrderModuleList.Blink & 0x3)) {
                VmmWinLdrModule_Initialize_VSetPutVA(pObSet_vaAll, pObSet_vaTry1, (QWORD)CONTAINING_RECORD32(pLdrModule32->InMemoryOrderModuleList.Blink, LDR_MODULE32, InMemoryOrderModuleList));
            }
        }
    }
    // save prefetch addresses (if desirable)
    if(H->dev.fVolatile && H->vmm.ThreadProcCache.fEnabled) {
        ObContainer_SetOb(pProcess->pObPersistent->pObCLdrModulesPrefetch64, pObSet_vaAll);
    }
fail:
    Ob_DECREF(pObSet_vaAll);
    Ob_DECREF(pObSet_vaTry1);
    Ob_DECREF(pObSet_vaTry2);
    if(!fUserOnly && pProcess->win.vaPEB) {
        VmmWinLdrModule_Initialize32(H, pProcess, pmModules, TRUE);
    }
}

VOID VmmWinLdrModule_InitializeVAD(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess, _Inout_ POB_MAP pmModules)
{
    BOOL fX;
    DWORD iVad, iPte = 0;
    PVMM_MAP_VADENTRY peVad;
    PVMMOB_MAP_PTE pObPteMap = NULL;
    PVMMOB_MAP_VAD pObVadMap = NULL;
    VMM_MAP_MODULEENTRY oModule;
    if(!pProcess->fUserOnly) { return; }
    if(!VmmMap_GetVad(H, pProcess, &pObVadMap, VMM_VADMAP_TP_PARTIAL)) { return; }
    for(iVad = 0; iVad < pObVadMap->cMap; iVad++) {
        peVad = pObVadMap->pMap + iVad;
        if(!peVad->fImage) { continue; }
        if(ObMap_ExistsKey(pmModules, peVad->vaStart)) { continue; }
        ZeroMemory(&oModule, sizeof(VMM_MAP_MODULEENTRY));
        oModule.vaBase = peVad->vaStart;
        oModule.cbImageSize = (DWORD)PE_GetSize(H, pProcess, oModule.vaBase);
        if(!oModule.cbImageSize || (oModule.cbImageSize > 0x04000000)) { continue; }
        oModule.fWoW64 = pProcess->win.fWow64 && (oModule.vaBase < 0xffffffff);
        // image vad not already in map found; check if pte map contains hw
        // executable pte's -> assume unlinked module, otherwise assume data.
        if(!pObPteMap && !VmmMap_GetPte(H, pProcess, &pObPteMap, FALSE)) { goto fail; }
        // move pte index to current vad
        while((iPte < pObPteMap->cMap) && (pObPteMap->pMap[iPte].vaBase + (pObPteMap->pMap[iPte].cPages << 12) <= peVad->vaStart)) {
            iPte++;
        }
        // check if vad contains hw executable page
        fX = FALSE;
        while(!fX && (iPte < pObPteMap->cMap) && (pObPteMap->pMap[iPte].vaBase < peVad->vaEnd)) {
            fX = pObPteMap->pMap[iPte].fPage && !(pObPteMap->pMap[iPte].fPage & VMM_MEMMAP_PAGE_NX);
            iPte++;
        }
        oModule.tp = fX ? VMM_MODULE_TP_NOTLINKED : VMM_MODULE_TP_DATA;
        ObMap_PushCopy(pmModules, oModule.vaBase, &oModule, sizeof(VMM_MAP_MODULEENTRY));
    }
fail:
    Ob_DECREF(pObPteMap);
    Ob_DECREF(pObVadMap);
}

_Success_(return)
BOOL VmmWinLdrModule_InitializeInjectedEntry(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess, _Inout_ POB_MAP pmModules, _In_ QWORD vaModuleBase)
{
    QWORD cbImageSize;
    VMM_MAP_MODULEENTRY oModule = { 0 };
    cbImageSize = PE_GetSize(H, pProcess, vaModuleBase);
    if(ObMap_ExistsKey(pmModules, vaModuleBase)) { return FALSE; }
    if(!cbImageSize || cbImageSize > 0x04000000) { return FALSE; }
    oModule.vaBase = vaModuleBase;
    oModule.tp = VMM_MODULE_TP_INJECTED;
    oModule.cbImageSize = (DWORD)cbImageSize;
    oModule.fWoW64 = pProcess->win.fWow64 && (oModule.vaBase < 0xffffffff);
    return ObMap_PushCopy(pmModules, oModule.vaBase, &oModule, sizeof(VMM_MAP_MODULEENTRY));
}

VOID VmmWinLdrModule_InitializeInjected(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess, _Inout_ POB_MAP pmModules, _Inout_opt_ POB_SET psvaInjected)
{
    DWORD i;
    QWORD va;
    PVMMOB_MAP_VAD pObVadMap = NULL;
    POB_DATA pvaObDataInjected = NULL;
    BOOL fObAlloc_psvaInjected;  
    if(!psvaInjected && !ObContainer_Exists(pProcess->pObPersistent->pObCLdrModulesInjected)) { return; }
    fObAlloc_psvaInjected = !psvaInjected && (psvaInjected = ObSet_New(H));
    // merge previously saved injected modules into 'psvaInjected' address set
    if((pvaObDataInjected = ObContainer_GetOb(pProcess->pObPersistent->pObCLdrModulesInjected))) {
        ObSet_PushData(psvaInjected, pvaObDataInjected);
        Ob_DECREF_NULL(&pvaObDataInjected);
    }
    // add injected modules module map
    if(ObSet_Size(psvaInjected)) {
        if(!VmmMap_GetVad(H, pProcess, &pObVadMap, VMM_VADMAP_TP_FULL)) { goto fail; }
        i = 0;
        while(i < ObSet_Size(psvaInjected)) {
            va = ObSet_Get(psvaInjected, i);
            if(!VmmWinLdrModule_InitializeInjectedEntry(H, pProcess, pmModules, va)) {
                ObSet_Remove(psvaInjected, va);
            } else {
                i++;
            }
        }
        Ob_DECREF_NULL(&pObVadMap);
    }
    //  save to "persistent" refresh memory storage.
    if(ObSet_Size(psvaInjected)) {
        pvaObDataInjected = ObSet_GetAll(psvaInjected);
        ObContainer_SetOb(pProcess->pObPersistent->pObCLdrModulesInjected, pvaObDataInjected);
        Ob_DECREF_NULL(&pvaObDataInjected);
    }
fail:
    if(fObAlloc_psvaInjected) {
        Ob_DECREF(psvaInjected);
    }
    Ob_DECREF(pObVadMap);
}

_Success_(return)
BOOL VmmWinLdrModule_Initialize_Name(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess, _Inout_ PVMMOB_MAP_MODULE pModuleMap)
{
    BOOL fWow64 = pProcess->win.fWow64;
    DWORD i;
    PVMM_MAP_MODULEENTRY pe;
    POB_SET psObPrefetch = NULL;
    POB_STRMAP psmOb = NULL;
    LPSTR uszPrefix;
    CHAR uszName[MAX_PATH], uszFullName[MAX_PATH], szNamePE[MAX_PATH];
    if(!(psmOb = ObStrMap_New(H, OB_STRMAP_FLAGS_CASE_INSENSITIVE))) { return FALSE; }
    // 1: prefetch
    psObPrefetch = ObSet_New(H);
    for(i = 0; i < pModuleMap->cMap; i++) {
        pe = pModuleMap->pMap + i;
        ObSet_Push_PageAlign(psObPrefetch, pe->vaBase, 0x1000);
        ObSet_Push_PageAlign(psObPrefetch, pe->_Reserved1, MAX_PATH * 2);
        ObSet_Push_PageAlign(psObPrefetch, pe->_Reserved3, MAX_PATH * 2);
    }
    VmmCachePrefetchPages(H, pProcess, psObPrefetch, 0);
    // 2: iterate over entries
    for(i = 0; i < pModuleMap->cMap; i++) {
        pe = pModuleMap->pMap + i;
        uszFullName[0] = 0;
        uszName[0] = 0;
        uszPrefix = "";
        // name from ldr list
        if(pe->_Reserved1) {
            VmmReadWtoU(H, pProcess, pe->_Reserved1, min(pe->cbuText, 2 * MAX_PATH), VMM_FLAG_FORCECACHE_READ, uszName, sizeof(uszName), NULL, NULL, CHARUTIL_FLAG_TRUNCATE_ONFAIL_NULLSTR | CHARUTIL_FLAG_STR_BUFONLY);
            CharUtil_FixFsNameU(uszName, sizeof(uszName), uszName, 0, FALSE);
            pe->_Reserved1 = 0;
        }
        // fullname from ldr list
        if(pe->_Reserved3) {
            VmmReadWtoU(H, pProcess, pe->_Reserved3, min(pe->cbuFullName, 2 * MAX_PATH), VMM_FLAG_FORCECACHE_READ, uszFullName, sizeof(uszFullName), NULL, NULL, CHARUTIL_FLAG_TRUNCATE_ONFAIL_NULLSTR | CHARUTIL_FLAG_STR_BUFONLY);
            pe->_Reserved3 = 0;
        }
        // name from pe embedded
        if(!uszName[0] && PE_GetModuleName(H, pProcess, pe->vaBase, szNamePE, MAX_PATH)) {
            CharUtil_FixFsName(uszName, sizeof(uszName), NULL, szNamePE, NULL, MAX_PATH, 0, FALSE);
        }
        // name from VAD not feasible due to deadlock risk when initializing VAD names.
        // set prefix, fix fullname and commit to strmap
        if(!uszName[0]) {
            sprintf_s(uszName, MAX_PATH, "0x%llx.dll", pe->vaBase);
            uszPrefix = "_NA-";
        }
        // ntdll.dll rename on wow64 processes to avoid name collisions
        if(fWow64 && (pe->vaBase > 0xffffffff) && !strcmp(uszName, "ntdll.dll")) {
            uszPrefix = "_64-";
        }
        if(pe->tp == VMM_MODULE_TP_DATA) { uszPrefix = "_DATA-"; }
        if(pe->tp == VMM_MODULE_TP_NOTLINKED) { uszPrefix = "_NOTLINKED-"; }
        if(pe->tp == VMM_MODULE_TP_INJECTED) { uszPrefix = "_INJECTED-"; }
        ObStrMap_PushUU_snprintf_s(psmOb, &pe->uszText, &pe->cbuText, "%s%s", uszPrefix, uszName);
        ObStrMap_PushPtrUU(psmOb, (uszFullName[0] ? uszFullName : uszName), &pe->uszFullName, &pe->cbuFullName);
    }
    ObStrMap_FinalizeAllocU_DECREF_NULL(&psmOb, &pModuleMap->pbMultiText, &pModuleMap->cbMultiText);
    Ob_DECREF(psObPrefetch);
    return TRUE;
}

VOID VmmWinLdrModule_Initialize_SetHash(_In_ PVMM_PROCESS pProcess, _Inout_ PVMMOB_MAP_MODULE pModuleMap)
{
    QWORD i;
    for(i = 0; i < pModuleMap->cMap; i++) {
        pModuleMap->pHashTableLookup[i] = (i << 32) | CharUtil_HashNameFsU(pModuleMap->pMap[i].uszText, 0);
    }
    qsort(pModuleMap->pHashTableLookup, pModuleMap->cMap, sizeof(QWORD), (int(*)(const void*, const void*))VmmWin_HashTableLookup_CmpSort);
}

VOID VmmWinLdrModule_Initialize_SetSize(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess, _Inout_ PVMMOB_MAP_MODULE pModuleMap)
{
    DWORD i;
    BYTE pbModuleHeader[0x1000];
    PVMM_MAP_MODULEENTRY pe;
    POB_SET psObPrefetch = NULL;
    // prefetch MZ header
    if(!(psObPrefetch = ObSet_New(H))) { return; }
    for(i = 0; i < pModuleMap->cMap; i++) {
        ObSet_Push(psObPrefetch, pModuleMap->pMap[i].vaBase);
    }
    // fetch size values from cache loaded nt header.
    VmmCachePrefetchPages(H, pProcess, psObPrefetch, 0); ObSet_Clear(psObPrefetch);
    for(i = 0; i < pModuleMap->cMap; i++) {
        pe = pModuleMap->pMap + i;
        if(!VmmRead2(H, pProcess, pe->vaBase, pbModuleHeader, 0x1000, VMM_FLAG_FORCECACHE_READ)) { continue; }
        pe->cbFileSizeRaw = PE_FileRaw_Size(H, pProcess, 0, pbModuleHeader);
        pe->cSection = PE_SectionGetNumberOfEx(H, pProcess, 0, pbModuleHeader);
        pe->cIAT = PE_IatGetNumberOfEx(H, pProcess, 0, pbModuleHeader);
        ObSet_Push_PageAlign(psObPrefetch, pe->vaBase + PE_DirectoryGetOffset(H, pProcess, 0, pbModuleHeader, IMAGE_DIRECTORY_ENTRY_EXPORT, NULL), sizeof(IMAGE_EXPORT_DIRECTORY));
    }
    // fetch number of exports (EAT)
    VmmCachePrefetchPages(H, pProcess, psObPrefetch, 0);
    for(i = 0; i < pModuleMap->cMap; i++) {
        pModuleMap->pMap[i].cEAT = PE_EatGetNumberOfEx(H, pProcess, pModuleMap->pMap[i].vaBase, NULL);
    }
    Ob_DECREF(psObPrefetch);
}

VOID VmmWinLdrModule_CallbackCleanup_ObMapModule(PVMMOB_MAP_MODULE pOb)
{
    LocalFree(pOb->pbMultiText);
    if(pOb->fDebugInfo) {
        LocalFree(pOb->pbDebugInfo1);
        LocalFree(pOb->pbDebugInfo2);
    }
    if(pOb->fVersionInfo) {
        LocalFree(pOb->pbVersionInfo1);
        LocalFree(pOb->pbVersionInfo2);
    }
}

/*
* Initialize the module map containing information about loaded modules in the
* system. This is performed by a PEB/Ldr walk/scan of in-process memory
* structures. This may be unreliable if a process is obfuscated or tampered.
* -- pProcess
* -- psvaInjected = optional set of injected addresses, updated on exit.
* -- return
*/
_Success_(return)
BOOL VmmWinLdrModule_Initialize(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess, _Inout_opt_ POB_SET psvaInjected)
{
    PVMM_MAP_MODULEENTRY pe;
    POB_MAP pmObModules = NULL;
    PVMMOB_MAP_MODULE pObMap = NULL, pObMap_PreExisting = NULL;
    DWORD i, cModules, cbObMap;
    // check if already initialized -> skip
    if(pProcess->Map.pObModule && (!psvaInjected || !ObSet_Size(psvaInjected))) { return TRUE; }
    VmmTlbSpider(H, pProcess);
    EnterCriticalSection(&pProcess->LockUpdate);
    if(pProcess->Map.pObModule && (!psvaInjected || !ObSet_Size(psvaInjected))) { goto fail; }  // not strict fail - but trigger cleanup and success.
    // set up context
    if(!(pmObModules = ObMap_New(H, OB_MAP_FLAGS_OBJECT_LOCALFREE))) { goto fail; }
    // fetch modules: "ordinary" linked list
    if((H->vmm.tpSystem == VMM_SYSTEM_WINDOWS_32) || ((H->vmm.tpSystem == VMM_SYSTEM_WINDOWS_64) && pProcess->win.fWow64)) {
        VmmWinLdrModule_Initialize32(H, pProcess, pmObModules, pProcess->fUserOnly);
    }
    if(H->vmm.tpSystem == VMM_SYSTEM_WINDOWS_64) {
        VmmWinLdrModule_Initialize64(H, pProcess, pmObModules, pProcess->fUserOnly);
    }
    // fetch modules: VADs
    VmmWinLdrModule_InitializeVAD(H, pProcess, pmObModules);
    // fetch modules: optional injected
    VmmWinLdrModule_InitializeInjected(H, pProcess, pmObModules, psvaInjected);
    // set up module map object
    cModules = ObMap_Size(pmObModules);
    cbObMap = sizeof(VMMOB_MAP_MODULE) + cModules * (sizeof(VMM_MAP_MODULEENTRY) + sizeof(QWORD));
    if(!(pObMap = Ob_AllocEx(H, OB_TAG_MAP_MODULE, LMEM_ZEROINIT, cbObMap, (OB_CLEANUP_CB)VmmWinLdrModule_CallbackCleanup_ObMapModule, NULL))) { goto fail; }
    pObMap->pHashTableLookup = (PQWORD)(((PBYTE)pObMap) + sizeof(VMMOB_MAP_MODULE) + cModules * sizeof(VMM_MAP_MODULEENTRY));
    pObMap->cMap = cModules;
    for(i = 0; i < cModules; i++) {
        pe = ObMap_GetByIndex(pmObModules, i);
        memcpy(pObMap->pMap + i, pe, sizeof(VMM_MAP_MODULEENTRY));
    }
    // sort modules by virtual address (except for primary module).
    if(pObMap->cMap > 2) {
        qsort(pObMap->pMap + 1, pObMap->cMap - 1, sizeof(VMM_MAP_MODULEENTRY), Util_qsort_QWORD);
    }
    // fetch module names
    if(!VmmWinLdrModule_Initialize_Name(H, pProcess, pObMap)) { goto fail; }
    // fetch raw file size, #sections, imports (IAT) and exports (EAT)
    VmmWinLdrModule_Initialize_SetSize(H, pProcess, pObMap);
    // set name hash table
    VmmWinLdrModule_Initialize_SetHash(pProcess, pObMap);
    // finish set-up
    pObMap_PreExisting = pProcess->Map.pObModule;
    pProcess->Map.pObModule = Ob_INCREF(pObMap);
fail:
    if(!pProcess->Map.pObModule) {
        // try set up zero-sized module map on fail
        pObMap = Ob_AllocEx(H, OB_TAG_MAP_MODULE, LMEM_ZEROINIT, sizeof(VMMOB_MAP_MODULE), NULL, NULL);
        pProcess->Map.pObModule = pObMap;
    }
    LeaveCriticalSection(&pProcess->LockUpdate);
    Ob_DECREF(pmObModules);
    Ob_DECREF(pObMap);
    Ob_DECREF(pObMap_PreExisting);
    return pProcess->Map.pObModule ? TRUE : FALSE;
}

/*
* Helper function to the LdrModule Enrich functions to prefetch PE header and
* the required data directory into the cache to speed things up.
*/
VOID VmmWinLdrModule_Enrich_Prefetch(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess, _In_ PVMMOB_MAP_MODULE pModuleMap, _In_ DWORD dwImageDataDirectory)
{
    DWORD i, cboDataDirectory;
    POB_SET psObPrefetch = NULL;
    if((psObPrefetch = ObSet_New(H))) {
        // 1: Prefetch module MZ header:
        for(i = 0; i < pModuleMap->cMap; i++) {
            ObSet_Push(psObPrefetch, pModuleMap->pMap[i].vaBase);
        }
        VmmCachePrefetchPages(H, pProcess, psObPrefetch, 0); ObSet_Clear(psObPrefetch);
        // 2: Prefetch module data directory:
        for(i = 0; i < pModuleMap->cMap; i++) {
            if((cboDataDirectory = PE_DirectoryGetOffset(H, pProcess, pModuleMap->pMap[i].vaBase, NULL, dwImageDataDirectory, NULL))) {
                ObSet_Push_PageAlign(psObPrefetch, pModuleMap->pMap[i].vaBase + cboDataDirectory, 0x1000);
            }
        }
        VmmCachePrefetchPages(H, pProcess, psObPrefetch, 0);
    }
    Ob_DECREF(psObPrefetch);
}

VOID VmmWinLdrModule_EnrichDebugInfo(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess)
{
    static const LPCSTR szHEX_ALPHABET = "0123456789ABCDEF";
    PVMMOB_MAP_MODULE pModuleMap = pProcess->Map.pObModule;
    PVMM_MAP_MODULEENTRY_DEBUGINFO pDebugInfo;
    PVMM_MAP_MODULEENTRY pe;
    POB_STRMAP psmOb = NULL;
    DWORD i, j, k, cbMultiStr;
    BYTE b;
    CHAR szGUID[33] = { 0 };
    PE_CODEVIEW_INFO CodeViewInfo;
    VMMSTATISTICS_LOG Statistics = { 0 };
    if(!pModuleMap || pModuleMap->fDebugInfo) { return; }
    EnterCriticalSection(&pProcess->LockUpdate);
    if(pModuleMap->fDebugInfo) {
        LeaveCriticalSection(&pProcess->LockUpdate);
        return;
    }
    VmmStatisticsLogStart(H, MID_MODULE, LOGLEVEL_6_TRACE, pProcess, &Statistics, "INIT_DEBUGINFO");
    VmmWinLdrModule_Enrich_Prefetch(H, pProcess, pModuleMap, IMAGE_DIRECTORY_ENTRY_DEBUG);
    // alloc/fill module VersionInfo
    if(!(psmOb = ObStrMap_New(H, OB_STRMAP_FLAGS_CASE_SENSITIVE | OB_STRMAP_FLAGS_STR_ASSIGN_TEMPORARY))) { goto fail; }
    if(!(pModuleMap->pbDebugInfo1 = (PBYTE)LocalAlloc(LMEM_ZEROINIT, pModuleMap->cMap * sizeof(VMM_MAP_MODULEENTRY_DEBUGINFO)))) { goto fail; }
    for(i = 0; i < pModuleMap->cMap; i++) {
        pe = pModuleMap->pMap + i;
        pDebugInfo = ((PVMM_MAP_MODULEENTRY_DEBUGINFO)pModuleMap->pbDebugInfo1) + i;
        pe->pExDebugInfo = pDebugInfo;
        if(PE_GetCodeViewInfo(H, pProcess, pe->vaBase, NULL, &CodeViewInfo)) {
            // guid -> hex
            for(k = 0, j = 0; k < 16; k++) {
                b = CodeViewInfo.CodeView.Guid[k];
                szGUID[j++] = szHEX_ALPHABET[b >> 4];
                szGUID[j++] = szHEX_ALPHABET[b & 7];
            }
            // populate ExDebugInfo
            pDebugInfo->dwAge = CodeViewInfo.CodeView.Age;
            memcpy(pDebugInfo->Guid, CodeViewInfo.CodeView.Guid, sizeof(pDebugInfo->Guid));
            ObStrMap_PushPtrAU(psmOb, szGUID, &pDebugInfo->uszGuid, NULL);
            ObStrMap_PushPtrUU(psmOb, CodeViewInfo.CodeView.PdbFileName, &pDebugInfo->uszPdbFilename, NULL);
        }
    }
    // finish str alloc:
    ObStrMap_FinalizeAllocU_DECREF_NULL(&psmOb, &pModuleMap->pbDebugInfo2, &cbMultiStr);
    // fixup any NULLs
    for(i = 0; i < pModuleMap->cMap; i++) {
        pDebugInfo = pModuleMap->pMap[i].pExDebugInfo;
        if(!pDebugInfo->uszGuid)        { pDebugInfo->uszGuid = "";         }
        if(!pDebugInfo->uszPdbFilename) { pDebugInfo->uszPdbFilename = "";  }
    }
    pModuleMap->fDebugInfo = TRUE;
fail:
    VmmStatisticsLogEnd(H, &Statistics, "INIT_DEBUGINFO");
    LeaveCriticalSection(&pProcess->LockUpdate);
    Ob_DECREF(psmOb);
}

VOID VmmWinLdrModule_EnrichVersionInfo(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess)
{
    PVMMOB_MAP_MODULE pModuleMap = pProcess->Map.pObModule;
    PVMM_MAP_MODULEENTRY_VERSIONINFO pVersionInfo;
    PVMM_MAP_MODULEENTRY pe;
    POB_STRMAP psmOb = NULL;
    DWORD i, cbMultiStr;
    VMMSTATISTICS_LOG Statistics = { 0 };
    if(!pModuleMap || pModuleMap->fVersionInfo) { return; }
    EnterCriticalSection(&pProcess->LockUpdate);
    if(pModuleMap->fVersionInfo) {
        LeaveCriticalSection(&pProcess->LockUpdate);
        return;
    }
    VmmStatisticsLogStart(H, MID_MODULE, LOGLEVEL_6_TRACE, pProcess, &Statistics, "INIT_VERSIONINFO");
    VmmWinLdrModule_Enrich_Prefetch(H, pProcess, pModuleMap, IMAGE_DIRECTORY_ENTRY_RESOURCE);
    // alloc/fill module VersionInfo
    if(!(psmOb = ObStrMap_New(H, OB_STRMAP_FLAGS_CASE_SENSITIVE | OB_STRMAP_FLAGS_STR_ASSIGN_TEMPORARY))) { goto fail; }
    if(!(pModuleMap->pbVersionInfo1 = (PBYTE)LocalAlloc(LMEM_ZEROINIT, pModuleMap->cMap * sizeof(VMM_MAP_MODULEENTRY_VERSIONINFO)))) { goto fail; }
    for(i = 0; i < pModuleMap->cMap; i++) {
        pe = pModuleMap->pMap + i;
        pVersionInfo = ((PVMM_MAP_MODULEENTRY_VERSIONINFO)pModuleMap->pbVersionInfo1) + i;
        pe->pExVersionInfo = pVersionInfo;
        PE_VsGetVersionInfo(H, pProcess, pe->vaBase, psmOb, pVersionInfo);
    }
    // finish str alloc:
    ObStrMap_FinalizeAllocU_DECREF_NULL(&psmOb, &pModuleMap->pbVersionInfo2, &cbMultiStr);
    // fixup any NULLs
    for(i = 0; i < pModuleMap->cMap; i++) {
        pVersionInfo = pModuleMap->pMap[i].pExVersionInfo;
        if(!pVersionInfo->uszCompanyName)       { pVersionInfo->uszCompanyName = "";      }
        if(!pVersionInfo->uszFileDescription)   { pVersionInfo->uszFileDescription = "";  }
        if(!pVersionInfo->uszFileVersion)       { pVersionInfo->uszFileVersion = "";      }
        if(!pVersionInfo->uszInternalName)      { pVersionInfo->uszInternalName = "";     }
        if(!pVersionInfo->uszLegalCopyright)    { pVersionInfo->uszLegalCopyright = "";   }
        if(!pVersionInfo->uszOriginalFilename)  { pVersionInfo->uszOriginalFilename = ""; }
        if(!pVersionInfo->uszProductName)       { pVersionInfo->uszProductName = "";      }
        if(!pVersionInfo->uszProductVersion)    { pVersionInfo->uszProductVersion = "";   }
    }
    pModuleMap->fVersionInfo = TRUE;
fail:
    VmmStatisticsLogEnd(H, &Statistics, "INIT_VERSIONINFO");
    LeaveCriticalSection(&pProcess->LockUpdate);
    Ob_DECREF(psmOb);
}

_Success_(return)
BOOL VmmWinLdrModule_SymbolServer(_In_ VMM_HANDLE H, _In_ PVMM_MAP_MODULEENTRY pe, _In_ BOOL fExtendedChecks, _In_ DWORD cbSymbolServer, _Out_writes_(cbSymbolServer) LPSTR szSymbolServer) {
    int cch;
    PVMM_MAP_MODULEENTRY_DEBUGINFO pD;
    if(cbSymbolServer) {
        szSymbolServer[0] = 0;
    }
    if(pe->pExDebugInfo && pe->pExDebugInfo->uszGuid && pe->pExDebugInfo->uszPdbFilename && pe->pExVersionInfo && pe->pExVersionInfo->uszLegalCopyright) {
        if((strlen(pe->pExDebugInfo->uszGuid) == 32) && !strstr(pe->pExDebugInfo->uszPdbFilename, "\\") && strstr(pe->pExVersionInfo->uszLegalCopyright, "Microsoft")) {
            pD = pe->pExDebugInfo;
            cch = _snprintf_s(szSymbolServer, cbSymbolServer, _TRUNCATE, "https://msdl.microsoft.com/download/symbols/%s/%08X%04X%04X%02X%02X%02X%02X%02X%02X%02X%02X%i/%s",
                pe->pExDebugInfo->uszPdbFilename,
                *(PDWORD)(pD->Guid + 0), *(PWORD)(pD->Guid + 4), *(PWORD)(pD->Guid + 6),
                pD->Guid[8], pD->Guid[9], pD->Guid[10], pD->Guid[11],
                pD->Guid[12], pD->Guid[13], pD->Guid[14], pD->Guid[15],
                pD->dwAge,
                pe->pExDebugInfo->uszPdbFilename
            );
            return cch > 0;
        }
    }
    return FALSE;
}



// ----------------------------------------------------------------------------
// UNLOADED MODULE FUNCTIONALITY BELOW:
// ----------------------------------------------------------------------------

VOID VmmWinUnloadedModule_CallbackCleanup_ObMapUnloadedModule(PVMMOB_MAP_UNLOADEDMODULE pOb)
{
    LocalFree(pOb->pbMultiText);
}

QWORD VmmWinUnloadedModule_vaNtdllUnloadedArray(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess, _In_ BOOL f32)
{
    BYTE pb[8];
    PDB_HANDLE hPDB;
    QWORD va, vaUnloadedArray = 0;
    PVMM_MAP_MODULEENTRY peModule;
    PVMMOB_MAP_MODULE pObModuleMap = NULL;
    // 1: fetch cached
    vaUnloadedArray = f32 ? H->vmm.ContextUnloadedModule.vaNtdll32 : H->vmm.ContextUnloadedModule.vaNtdll64;
    if((DWORD)vaUnloadedArray == (DWORD)-1) { return 0; }
    if(vaUnloadedArray) { return vaUnloadedArray; }
    // 2: fetch ntdll module
    if(!VmmMap_GetModuleEntryEx(H, pProcess, 0, "ntdll.dll", 0, &pObModuleMap, &peModule)) { goto fail; }
    // 2.1: try fetch addr RtlpUnloadEventTrace from dism of RtlGetUnloadEventTrace export
    if((va = PE_GetProcAddress(H, pProcess, peModule->vaBase, "RtlGetUnloadEventTrace")) && VmmRead(H, pProcess, va, pb, 8)) {
        if(f32 && (pb[0] == 0xb8) && (pb[5] == 0xc3)) { // x86 dism
            vaUnloadedArray = *(PDWORD)(pb + 1);
        }
        if(!f32 && (pb[0] == 0x48) && (pb[1] == 0x8d) && (pb[2] == 0x05) && (pb[7] == 0xc3)) {  // x64 dism
            va += 7ULL + *(PDWORD)(pb + 3);
            if(VmmRead(H, pProcess, va, pb, 8)) {
                vaUnloadedArray = va;
            }
        }
    }
    // 2.2: try fetch addr ntdll!RtlpUnloadEventTrace from PDB
    if(!vaUnloadedArray) {
        hPDB = PDB_GetHandleFromModuleAddress(H, pProcess, peModule->vaBase);
        PDB_GetSymbolAddress(H, hPDB, "RtlpUnloadEventTrace", &vaUnloadedArray);
    }
    // 3: commit to cache
    if(f32) {
        H->vmm.ContextUnloadedModule.vaNtdll32 = vaUnloadedArray ? (DWORD)vaUnloadedArray : (DWORD)-1;
    } else {
        H->vmm.ContextUnloadedModule.vaNtdll64 = vaUnloadedArray ? vaUnloadedArray : (QWORD)-1;
    }
fail:
    Ob_DECREF(pObModuleMap);
    return vaUnloadedArray;
}

/*
* Retrieve unloaded user-mode modules for the specific process. This is achieved
* by parsing the array RtlpUnloadEventTrace in ntdll.dll. The array location is
* retrieved by (1) parsing exports or (2) loading symbol from ntdll.dll PDB.
*/
VOID VmmWinUnloadedModule_InitializeUser(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess)
{
    BOOL f32 = (H->vmm.f32 || pProcess->win.fWow64);
    DWORD dwVersionBuild = H->vmm.kernel.dwVersionBuild;
    BYTE pbBuffer[RTL_UNLOAD_EVENT_TRACE_NUMBER * 0x68] = { 0 };
    QWORD cbStruct, vaUnloadedArray;
    DWORD i, cbBuffer, cMap;
    PRTL_UNLOAD_EVENT_TRACE32 pe32;
    PRTL_UNLOAD_EVENT_TRACE64 pe64;
    PVMM_MAP_UNLOADEDMODULEENTRY pe;
    PVMMOB_MAP_UNLOADEDMODULE pObMap = NULL;
    POB_STRMAP psmOb = NULL;
    // 1: fetch unloaded modules array
    if(!(vaUnloadedArray = VmmWinUnloadedModule_vaNtdllUnloadedArray(H, pProcess, f32))) { return; }
    cbBuffer = RTL_UNLOAD_EVENT_TRACE_NUMBER * (f32 ? sizeof(RTL_UNLOAD_EVENT_TRACE32) : sizeof(RTL_UNLOAD_EVENT_TRACE64));
    VmmRead2(H, pProcess, vaUnloadedArray, pbBuffer, cbBuffer, VMM_FLAG_ZEROPAD_ON_FAIL);
    // 2: parse data and count
    if(f32) {
        cbStruct = 0x5c;
        if(dwVersionBuild <= 6002) { cbStruct = 0x54; }  // <= VISTA SP2
        for(cMap = 0; cMap < RTL_UNLOAD_EVENT_TRACE_NUMBER; cMap++) {
            pe32 = (PRTL_UNLOAD_EVENT_TRACE32)(pbBuffer + cMap * cbStruct);
            if(!VMM_UADDR32_PAGE(pe32->BaseAddress)) { break; }
            if(!pe32->SizeOfImage || (pe32->SizeOfImage > 0x10000000)) { break; }
            pe32->ImageName[31] = 0;
        }
    } else {
        cbStruct = 0x68;
        if(dwVersionBuild <= 6002) { cbStruct = 0x60; }  // <= VISTA SP2
        for(cMap = 0; cMap < RTL_UNLOAD_EVENT_TRACE_NUMBER; cMap++) {
            pe64 = (PRTL_UNLOAD_EVENT_TRACE64)(pbBuffer + cMap * cbStruct);
            if(!VMM_UADDR64_PAGE(pe64->BaseAddress)) { break; }
            if(!pe64->SizeOfImage || (pe64->SizeOfImage > 0x10000000)) { break; }
            pe64->ImageName[31] = 0;
        }
    }
    // 3: alloc and fill
    if(!(psmOb = ObStrMap_New(H, 0))) { return; }
    pObMap = Ob_AllocEx(H, OB_TAG_MAP_UNLOADEDMODULE, LMEM_ZEROINIT, sizeof(VMMOB_MAP_UNLOADEDMODULE) + cMap * sizeof(VMM_MAP_UNLOADEDMODULEENTRY), (OB_CLEANUP_CB)VmmWinUnloadedModule_CallbackCleanup_ObMapUnloadedModule, NULL);
    if(!pObMap) {
        Ob_DECREF(psmOb);
        return;
    }
    pObMap->cMap = cMap;
    if(f32) {
        for(i = 0; i < cMap; i++) {
            pe = pObMap->pMap + i;
            pe32 = (PRTL_UNLOAD_EVENT_TRACE32)(pbBuffer + i * cbStruct);
            pe->fWoW64 = pProcess->win.fWow64;
            pe->vaBase = pe32->BaseAddress;
            pe->cbImageSize = pe32->SizeOfImage;
            pe->dwCheckSum = pe32->CheckSum;
            pe->dwTimeDateStamp = pe32->TimeDateStamp;
            ObStrMap_PushPtrWU(psmOb, pe32->ImageName, &pe->uszText, &pe->cbuText);
        }
    } else {
        for(i = 0; i < cMap; i++) {
            pe = pObMap->pMap + i;
            pe64 = (PRTL_UNLOAD_EVENT_TRACE64)(pbBuffer + i * cbStruct);
            pe->vaBase = pe64->BaseAddress;
            pe->cbImageSize = (DWORD)pe64->SizeOfImage;
            pe->dwCheckSum = pe64->CheckSum;
            pe->dwTimeDateStamp = pe64->TimeDateStamp;
            ObStrMap_PushPtrWU(psmOb, pe64->ImageName, &pe->uszText, &pe->cbuText);
        }
    }
    ObStrMap_FinalizeAllocU_DECREF_NULL(&psmOb, &pObMap->pbMultiText, &pObMap->cbMultiText);
    pProcess->Map.pObUnloadedModule = pObMap;   // pass on reference ownership to pProcess
}

/*
* Retrieve unloaded kernel modules. This is done by analyzing the kernel symbols
* MmUnloadedDrivers and MmLastUnloadedDriver. This function requires a valid PDB
* for the kernel to properly function.
*/
VOID VmmWinUnloadedModule_InitializeKernel(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess)
{
    BOOL f, f32 = H->vmm.f32;
    QWORD i, j, va = 0;
    DWORD cMap = 0, cUnloadMax, cbStruct, cbMultiText = 2, owszMultiText = 1;
    PMM_UNLOADED_DRIVER32 pe32;
    PMM_UNLOADED_DRIVER64 pe64;
    PVMM_MAP_UNLOADEDMODULEENTRY pe;
    PVMMOB_MAP_UNLOADEDMODULE pObMap = NULL;
    POB_STRMAP psmOb = NULL;
    BYTE pbBuffer[MM_UNLOADED_DRIVER_MAX * sizeof(MM_UNLOADED_DRIVER64)] = { 0 };
    if(!H->vmm.kernel.opt.vaMmUnloadedDrivers || !H->vmm.kernel.opt.vaMmLastUnloadedDriver) { return; }
    // 1: fetch data
    cbStruct = f32 ? sizeof(MM_UNLOADED_DRIVER32) : sizeof(MM_UNLOADED_DRIVER64);
    if(!VmmRead(H, pProcess, H->vmm.kernel.opt.vaMmUnloadedDrivers, (PBYTE)&va, f32 ? sizeof(DWORD) : sizeof(QWORD))) { return; }
    if(!VmmRead(H, pProcess, H->vmm.kernel.opt.vaMmLastUnloadedDriver, (PBYTE)&cUnloadMax, sizeof(DWORD))) { return; }
    if(!VMM_KADDR_4_8(f32, va) || !cUnloadMax || (cUnloadMax > MM_UNLOADED_DRIVER_MAX)) { return; }
    if(!VmmRead(H, pProcess, va, pbBuffer, cUnloadMax * cbStruct)) { return; }
    // 2: parse data and count
    for(i = 0; i < cUnloadMax; i++) {
        if(f32) {
            pe32 = (PMM_UNLOADED_DRIVER32)(pbBuffer + i * cbStruct);
            f = VMM_KADDR32_PAGE(pe32->ModuleStart) && VMM_KADDR32(pe32->ModuleEnd) && pe32->UnloadTime &&
                pe32->Name.Length && !(pe32->Name.Length & 1) && VMM_KADDR32(pe32->Name.Buffer) &&
                (pe32->ModuleEnd - pe32->ModuleStart < 0x10000000);
            if(!f) {
                pe32->ModuleStart = 0;
                continue;
            }
            cMap++;
        } else {
            pe64 = (PMM_UNLOADED_DRIVER64)(pbBuffer + i * cbStruct);
            f = VMM_KADDR64_PAGE(pe64->ModuleStart) && VMM_KADDR64(pe64->ModuleEnd) && pe64->UnloadTime &&
                pe64->Name.Length && !(pe64->Name.Length & 1) && VMM_KADDR64(pe64->Name.Buffer) &&
                (pe64->ModuleEnd - pe64->ModuleStart < 0x10000000);
            if(!f) {
                pe64->ModuleStart = 0;
                continue;
            }
            cMap++;
        }
    }
    // 3: alloc and fill
    if(!(psmOb = ObStrMap_New(H, 0))) { return; }
    pObMap = Ob_AllocEx(H, OB_TAG_MAP_UNLOADEDMODULE, LMEM_ZEROINIT, sizeof(VMMOB_MAP_UNLOADEDMODULE) + cMap * sizeof(VMM_MAP_UNLOADEDMODULEENTRY), (OB_CLEANUP_CB)VmmWinUnloadedModule_CallbackCleanup_ObMapUnloadedModule, NULL);
    if(!pObMap) {
        Ob_DECREF(psmOb);
        return;
    }
    pObMap->cMap = cMap;
    for(i = 0, j = 0; i < cUnloadMax; i++) {
        if(f32) {
            pe32 = (PMM_UNLOADED_DRIVER32)(pbBuffer + i * cbStruct);
            if(!pe32->ModuleStart) { continue; }
            pe = pObMap->pMap + j; j++;
            pe->vaBase = pe32->ModuleStart;
            pe->cbImageSize = pe32->ModuleEnd+ pe32->ModuleStart;
            pe->ftUnload = pe32->UnloadTime;
            ObStrMap_Push_UnicodeBuffer(psmOb, pe32->Name.Length, pe32->Name.Buffer, &pe->uszText, &pe->cbuText);
        } else {
            pe64 = (PMM_UNLOADED_DRIVER64)(pbBuffer + i * cbStruct);
            if(!pe64->ModuleStart) { continue; }
            pe = pObMap->pMap + j; j++;
            pe->vaBase = pe64->ModuleStart;
            pe->cbImageSize = (DWORD)(pe64->ModuleEnd + pe64->ModuleStart);
            pe->ftUnload = pe64->UnloadTime;
            ObStrMap_Push_UnicodeBuffer(psmOb, pe64->Name.Length, pe64->Name.Buffer, &pe->uszText, &pe->cbuText);
        }
    }
    ObStrMap_FinalizeAllocU_DECREF_NULL(&psmOb, &pObMap->pbMultiText, &pObMap->cbMultiText);
    pProcess->Map.pObUnloadedModule = pObMap;   // pass on reference ownership to pProcess
}

/*
* Initialize the unloaded module map containing information about unloaded modules.
* -- H
* -- pProcess
* -- return
*/
_Success_(return)
BOOL VmmWinUnloadedModule_Initialize(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess)
{
    if(pProcess->Map.pObUnloadedModule) { return TRUE; }
    EnterCriticalSection(&pProcess->LockUpdate);
    if(!pProcess->Map.pObUnloadedModule) {
        if(pProcess->fUserOnly) {
            VmmWinUnloadedModule_InitializeUser(H, pProcess);
        } else {
            VmmWinUnloadedModule_InitializeKernel(H, pProcess);
        }
    }
    if(!pProcess->Map.pObUnloadedModule) {
        pProcess->Map.pObUnloadedModule = Ob_AllocEx(H, OB_TAG_MAP_UNLOADEDMODULE, LMEM_ZEROINIT, sizeof(VMMOB_MAP_UNLOADEDMODULE), NULL, NULL);
    }
    LeaveCriticalSection(&pProcess->LockUpdate);
    return pProcess->Map.pObUnloadedModule ? TRUE : FALSE;
}



// ----------------------------------------------------------------------------
// USER PROCESS PARAMETERS FUNCTIONALITY BELOW:
// ----------------------------------------------------------------------------

PVMMWIN_USER_PROCESS_PARAMETERS VmmWin_UserProcessParameters_Get(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess)
{
    BOOL f, f32 = H->vmm.f32;
    LPWSTR wszTMP = NULL;
    DWORD i, cEnv = 0;
    LPWSTR wszEnv;
    QWORD vaEnv = 0, vaUserProcessParameters = 0;
    PVMMWIN_USER_PROCESS_PARAMETERS pu = &pProcess->pObPersistent->UserProcessParams;
    if(pu->fProcessed || pProcess->dwState) { return pu; }
    EnterCriticalSection(&pProcess->LockUpdate);
    if(pu->fProcessed || pProcess->dwState) { LeaveCriticalSection(&pProcess->LockUpdate); return pu; }
    if(f32) {
        f = pProcess->win.vaPEB &&
            VmmRead(H, pProcess, pProcess->win.vaPEB + 0x10, (PBYTE)&vaUserProcessParameters, sizeof(DWORD)) &&
            !(vaUserProcessParameters & 0x80000003);
    } else {
        f = pProcess->win.vaPEB &&
            VmmRead(H, pProcess, pProcess->win.vaPEB + 0x20, (PBYTE)&vaUserProcessParameters, sizeof(QWORD)) &&
            !(vaUserProcessParameters & 0xffff800000000007);
    }
    if(f) {
        // ImagePathName or DllPath
        if(!VmmReadAllocUnicodeStringAsUTF8(H, pProcess, f32, 0, vaUserProcessParameters + (f32 ? 0x038 : 0x060), 0x400, &pu->uszImagePathName, &pu->cbuImagePathName)) {  // ImagePathName
            VmmReadAllocUnicodeStringAsUTF8(H, pProcess, f32, 0, vaUserProcessParameters + (f32 ? 0x030 : 0x050), 0x400, &pu->uszImagePathName, &pu->cbuImagePathName);    // DllPath (mutually exclusive with ImagePathName?)
        }
        VmmReadAllocUnicodeStringAsUTF8(H, pProcess, f32, 0, vaUserProcessParameters + (f32 ? 0x024 : 0x038), 0x00010000, &pu->uszCurrentDirectory, &pu->cbuCurrentDirectory);
        VmmReadAllocUnicodeStringAsUTF8(H, pProcess, f32, 0, vaUserProcessParameters + (f32 ? 0x040 : 0x070), 0x00010000, &pu->uszCommandLine, &pu->cbuCommandLine);
        VmmReadAllocUnicodeStringAsUTF8(H, pProcess, f32, 0, vaUserProcessParameters + (f32 ? 0x070 : 0x0b0), 0x00010000, &pu->uszWindowTitle, &pu->cbuWindowTitle);
    }
    if(f && (H->vmm.kernel.dwVersionBuild >= 6000)) {
        // Environment (multi-str)
        VmmRead(H, pProcess, vaUserProcessParameters + (f32 ? 0x048 : 0x080), (PBYTE)&vaEnv, (f32 ? 4 : 8));   // Environment
        VmmRead(H, pProcess, vaUserProcessParameters + (f32 ? 0x290 : 0x3f0), (PBYTE)&cEnv, sizeof(DWORD));    // EnvironmentSize
        if(vaEnv && (cEnv > 0x10) && (cEnv < 0x10000) && VmmReadAlloc(H, pProcess, vaEnv, (PBYTE *)&wszEnv, cEnv, 0)) {
            cEnv = (cEnv >> 1);     // bytes to wchar_count
            for(i = 0; i < cEnv; i++) {
                if(!wszEnv[i]) {
                    wszEnv[i] = '\n';
                    i++;
                    continue;
                }
            }
            CharUtil_WtoU(wszEnv, -1, NULL, 0, &pu->uszEnvironment, &pu->cbuEnvironment, CHARUTIL_FLAG_ALLOC);
            LocalFree(wszEnv);
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
// be enriched with this information by calling VmmWinPte_InitializeMapText().
// Module names will be inserted from:
// 1) the module map
// 2) if not found in (1) and suitable pte signature by PE header peek.
// ----------------------------------------------------------------------------

/*
* Map a tag into the sorted memory map in O(log2) operations. Supply only one of szTag or wszTag.
* -- pProcess
* -- psm
* -- va
* -- vaLimit = limit == va + size (== top address in range +1)
* -- uszTag
* -- fWoW64
*/
VOID VmmWinPte_InitializeMapText_MapTag(_In_ PVMM_PROCESS pProcess, _In_ POB_STRMAP psm, _In_ QWORD vaBase, _In_ QWORD vaLimit, _In_opt_z_ LPSTR uszTag, _In_ BOOL fWoW64)
{
    PVMM_MAP_PTEENTRY pMap;
    QWORD i, lvl, cMap;
    pMap = pProcess->Map.pObPte->pMap;
    cMap = pProcess->Map.pObPte->cMap;
    if(!pMap || !cMap) { return; }
    if(!uszTag) { return; }
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
    for(; i < cMap; i++) {
        if(pMap[i].vaBase >= vaLimit) { break; }                              // outside scope
        if(pMap[i].vaBase + (pMap[i].cPages << 12) <= vaBase) { continue; }   // outside scope
        if(pMap[i].cbuText > 1) { continue; }
        pMap[i].fWoW64 = fWoW64;
        ObStrMap_PushPtrUU(psm, uszTag, &pMap[i].uszText, &pMap[i].cbuText);
    }
}

/*
* Identify module names by scanning for PE headers and tag them into the memory map.
*/
VOID VmmWinPte_InitializeMapText_ScanHeaderPE(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess, _In_ POB_STRMAP psm)
{
    DWORD cMap;
    PVMMOB_MAP_PTE pObMemMap = NULL;
    PVMM_MAP_PTEENTRY pMap;
    PVMM_MAP_PTEENTRY ppMAPs[0x400];
    PPMEM_SCATTER ppMEMs = NULL;
    DWORD i, cMEMs = 0, cbImageSize;
    BOOL result;
    CHAR szBuffer[MAX_PATH];
    // 1: checks and allocate buffers for parallel read of MZ header candidates
    if(!LcAllocScatter1(0x400, &ppMEMs)) { goto fail; }
    if(!VmmMap_GetPte(H, pProcess, &pObMemMap, FALSE)) { goto fail; }
    if(!pObMemMap || !pObMemMap->cMap) { goto fail; }
    cMap = pObMemMap->cMap;
    pMap = pObMemMap->pMap;
    // 2: scan memory map for MZ header candidates and put them on list for read
    for(i = 0; i < cMap - 1; i++) {
        if(H->vmm.tpMemoryModel == VMM_MEMORYMODEL_X86) {
            result =
                !(pMap[i].vaBase & 0xffff) &&                   // starts at even 0x10000 offset
                !pMap[i].cbuText;                               // tag not already set
        } else {
            result =
                (pMap[i].cPages == 1) &&                        // PE header is only 1 page
                !(pMap[i].vaBase & 0xffff) &&                   // starts at even 0x10000 offset
                !pMap[i].cbuText &&                             // tag not already set
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
        VmmReadScatterVirtual(H, pProcess, ppMEMs, cMEMs, 0);
        for(i = 0; i < cMEMs; i++) {
            if(ppMEMs[i]->f) {
                result = PE_GetModuleNameEx(H, pProcess, ppMAPs[i]->vaBase, TRUE, ppMEMs[i]->pb, szBuffer, _countof(szBuffer), &cbImageSize);
                if(result && (cbImageSize < 0x01000000)) {
                    VmmWinPte_InitializeMapText_MapTag(pProcess, psm, ppMAPs[i]->vaBase, ppMAPs[i]->vaBase + cbImageSize - 1, szBuffer, FALSE);
                }
            }
        }
    }
fail:
    LcMemFree(ppMEMs);
    Ob_DECREF(pObMemMap);
}

VOID VmmWinPte_InitializeMapText_Modules(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess, _In_ POB_STRMAP psm)
{
    DWORD i;
    PVMM_MAP_MODULEENTRY pModule;
    PVMMOB_MAP_MODULE pObModuleMap = NULL;
    if(VmmMap_GetModule(H, pProcess, 0, &pObModuleMap)) {
        // update memory map with names
        for(i = 0; i < pObModuleMap->cMap; i++) {
            pModule = pObModuleMap->pMap + i;
            VmmWinPte_InitializeMapText_MapTag(pProcess, psm, pModule->vaBase, pModule->vaBase + pModule->cbImageSize - 1, pModule->uszText, pModule->fWoW64);
        }
        Ob_DECREF(pObModuleMap);
    }
}

VOID VmmWinPte_InitializeMapText_Drivers(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess, _In_ POB_STRMAP psm)
{
    DWORD i;
    PVMM_MAP_KDRIVERENTRY pDrv;
    PVMMOB_MAP_KDRIVER pObDrvMap = NULL;
    if(pProcess->dwPID != 4) { return; }
    VmmWinPte_InitializeMapText_MapTag(pProcess, psm, H->vmm.kernel.vaBase, H->vmm.kernel.cbSize, "nt", FALSE);
    if(VmmMap_GetKDriver(H, &pObDrvMap)) {
        // update memory map with names
        for(i = 0; i < pObDrvMap->cMap; i++) {
            pDrv = pObDrvMap->pMap + i;
            if(pDrv->vaStart && pDrv->cbDriverSize && (pDrv->cbDriverSize < 0x10000000)) {
                VmmWinPte_InitializeMapText_MapTag(pProcess, psm, pDrv->vaStart, pDrv->vaStart + pDrv->cbDriverSize - 1, pDrv->uszName, FALSE);
            }
        }
        Ob_DECREF(pObDrvMap);
    }
}

VOID VmmWinPte_InitializeMapText_DoWork(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess)
{
    DWORD i;
    PVMMOB_MAP_PTE pMapPte = pProcess->Map.pObPte;
    POB_STRMAP psmOb = NULL;
    if(!(psmOb = ObStrMap_New(H, OB_STRMAP_FLAGS_STR_ASSIGN_TEMPORARY))) { return; }
    VmmWinPte_InitializeMapText_Drivers(H, pProcess, psmOb);
    VmmWinPte_InitializeMapText_Modules(H, pProcess, psmOb);
    VmmWinPte_InitializeMapText_ScanHeaderPE(H, pProcess, psmOb);
    ObStrMap_FinalizeAllocU_DECREF_NULL(&psmOb, &pMapPte->pbMultiText, &pMapPte->cbMultiText);
    // fixups not set values
    for(i = 0; i < pMapPte->cMap; i++) {
        if(!pMapPte->pMap[i].uszText) {
            pMapPte->pMap[i].uszText = (LPSTR)pMapPte->pbMultiText;
            pMapPte->pMap[i].cbuText = 1;
        }
    }
    pMapPte->fTagScan = TRUE;
}

/*
* Try initialize PteMap text descriptions. This function will first try to pop-
* ulate the pre-existing VMMOB_MAP_PTE object in pProcess with module names and
* then, if failed or partially failed, try to initialize from PE file headers.
* -- H
* -- pProcess
* -- return
*/
_Success_(return)
BOOL VmmWinPte_InitializeMapText(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess)
{
    if(pProcess->Map.pObPte->fTagScan) { return TRUE; }
    EnterCriticalSection(&pProcess->LockUpdate);
    if(!pProcess->Map.pObPte->fTagScan) {
        VmmTlbSpider(H, pProcess);
        VmmWinPte_InitializeMapText_DoWork(H, pProcess);
    }
    LeaveCriticalSection(&pProcess->LockUpdate);
    return pProcess->Map.pObPte->fTagScan;
}



// ----------------------------------------------------------------------------
// TOKEN FUNCTIONALITY BELOW:
//
// Tokens are used to determine access rights to objects. Most often the token
// is related to a process, but it may also be an impersonation token related
// to a thread.
// ----------------------------------------------------------------------------

/*
* Object manager callback function for object cleanup tasks.
* -- pVmmHandle
*/
VOID VmmWinToken_CloseObCallback(_In_ PVMMOB_TOKEN pOb)
{
    LocalFree(pOb->szSID);
}

/*
* Initialize tokens for specific processes.
* CALLER DECREF: *ppObTokens (each individual token).
* -- H
* -- cTokens = number of tokens to initialize.
* -- pvaTokens
* -- ppObTokens = buffer of size cToken to receive pointers to initialized tokens.
* -- return
*/
_Success_(return)
BOOL VmmWinToken_Initialize(_In_ VMM_HANDLE H, _In_ DWORD cTokens, _In_reads_(cTokens) QWORD *pvaToken, _Out_writes_(cTokens) PVMMOB_TOKEN *ppObTokens)
{
    BOOL f, fResult = FALSE, f32 = H->vmm.f32;
    DWORD i, j, cbHdr, cb, dwIntegrityLevelIndex = 0;;
    BYTE pb[0x1000];
    PVMMOB_TOKEN pe;
    PVMM_PROCESS pObSystemProcess = NULL;
    PVMM_OFFSET_EPROCESS poe = &H->vmm.offset.EPROCESS;
    QWORD va, *pva = NULL;
    DWORD dwTokenSource;
    LPSTR szSidIntegrity = NULL, szSidUser = NULL;
    BOOL fSidIntegrity;
    union {
        SID SID;
        BYTE pb[SECURITY_MAX_SID_SIZE];
    } SidIntegrity;
    VMM_TOKEN_INTEGRITY_LEVEL IntegrityLevel;
    // 1: Initialize:
    ZeroMemory(ppObTokens, cTokens * sizeof(PVMMOB_TOKEN));
    if(!poe->opt.TOKEN_TokenId) { goto fail; }
    cbHdr = f32 ? 0x2c : 0x5c;
    cb = cbHdr + poe->opt.TOKEN_cb;
    if((cb > sizeof(pb)) || !poe->opt.TOKEN_cb) { goto fail; }
    if(!(pObSystemProcess = VmmProcessGet(H, 4))) { goto fail; }
    if(!(pva = LocalAlloc(LMEM_ZEROINIT, (SIZE_T)cTokens * 2 * sizeof(QWORD)))) { goto fail; }
    // 2: Initialize token objects:
    for(i = 0; i < cTokens; i++) {
        if(!(ppObTokens[i] = Ob_AllocEx(H, OB_TAG_VMM_TOKEN, LMEM_ZEROINIT, sizeof(VMMOB_TOKEN), (OB_CLEANUP_CB)VmmWinToken_CloseObCallback, NULL))) { goto fail; }
        ppObTokens[i]->vaToken = pvaToken[i];
        pva[i] = pvaToken[i] - cbHdr;           // adjust for _OBJECT_HEADER and Pool Header
    }
    // 3: Read token data:
    VmmCachePrefetchPages4(H, pObSystemProcess, cTokens, pva, cb, 0);
    for(i = 0; i < cTokens; i++) {
        pe = ppObTokens[i];
        if(!pe->vaToken || !VmmRead2(H, pObSystemProcess, pva[i], pb, cb, VMM_FLAG_FORCECACHE_READ)) { continue; }
        // 2.1: fetch TOKEN.UserAndGroups (user id [_SID_AND_ATTRIBUTES])
        pva[i] = VMM_PTR_OFFSET(f32, pb + cbHdr, poe->opt.TOKEN_UserAndGroups);
        if(!VMM_KADDR(f32, pva[i])) { pva[i] = 0; continue; }
        pe->vaUserAndGroups = pva[i];
        // 2.2: fetch various offsets
        for(j = 0, f = FALSE; !f && (j < cbHdr); j += (f32 ? 0x08 : 0x10)) {
            f = VMM_POOLTAG_SHORT(*(PDWORD)(pb + j), 'Toke');
        }
        if(!f) {
            dwTokenSource = _byteswap_ulong(*(PDWORD)(pb + cbHdr));
            if((dwTokenSource != 'Adva') && (dwTokenSource != 'User')) {
                pva[i] = 0;
                continue;
            }
        }
        pe->qwLUID = *(PQWORD)(pb + cbHdr + poe->opt.TOKEN_TokenId);
        pe->dwSessionId = *(PDWORD)(pb + cbHdr + poe->opt.TOKEN_SessionId);
        if(poe->opt.TOKEN_UserAndGroupCount) {
            pe->dwUserAndGroupCount = *(PDWORD)(pb + cbHdr + poe->opt.TOKEN_UserAndGroupCount);
        }
        if(poe->opt.TOKEN_IntegrityLevelIndex) {
            dwIntegrityLevelIndex = *(PDWORD)(pb + cbHdr + poe->opt.TOKEN_IntegrityLevelIndex);
            if(dwIntegrityLevelIndex > pe->dwUserAndGroupCount) { dwIntegrityLevelIndex = 0; }
        }
        // 2.3: fetch TOKEN.UserAndGroups+dwIntegrityLevelIndex (integrity level [_SID_AND_ATTRIBUTES])
        if(dwIntegrityLevelIndex) {
            va = VMM_PTR_OFFSET(f32, pb + cbHdr, poe->opt.TOKEN_UserAndGroups) + dwIntegrityLevelIndex * (f32 ? 8ULL : 16ULL);
            if(VMM_KADDR(f32, va)) { pva[cTokens + i] = va; }
        }
        // 2.4: fetch TOKEN.Privileges (VISTA+)
        if(poe->opt.TOKEN_Privileges && (H->vmm.kernel.dwVersionBuild >= 6000)) {
            memcpy(&pe->Privileges, pb + cbHdr + poe->opt.TOKEN_Privileges, sizeof(SEP_TOKEN_PRIVILEGES));
        }
    }
    // 4: Read SID user & integrity ptr:
    VmmCachePrefetchPages4(H, pObSystemProcess, 2 * cTokens, pva, 8, 0);
    for(i = 0; i < cTokens; i++) {
        // user:
        f = pva[i] && VmmRead2(H, pObSystemProcess, pva[i], pb, 8, VMM_FLAG_FORCECACHE_READ) &&
            (va = VMM_PTR_OFFSET(f32, pb, 0)) &&
            VMM_KADDR(f32, va);
        pva[i] = f ? va : 0;
        // integrity:
        f = pva[cTokens + i] && VmmRead2(H, pObSystemProcess, pva[cTokens + i], pb, 8, VMM_FLAG_FORCECACHE_READ) &&
            (va = VMM_PTR_OFFSET(f32, pb, 0)) &&
            VMM_KADDR(f32, va);
        pva[cTokens + i] = f ? va : 0;
    }
    // 5: Get SID user & integrity:
    VmmCachePrefetchPages4(H, pObSystemProcess, 2 * cTokens, pva, SECURITY_MAX_SID_SIZE, 0);
    for(i = 0; i < cTokens; i++) {
        pe = ppObTokens[i];
        // user:
        pe->fSidUserValid =
            (va = pva[i]) &&
            VmmRead2(H, pObSystemProcess, va, pe->SidUser.pb, SECURITY_MAX_SID_SIZE, VMM_FLAG_FORCECACHE_READ) &&
            IsValidSid(&pe->SidUser.SID);
        // integrity:
        fSidIntegrity =
            (va = pva[cTokens + i]) &&
            VmmRead2(H, pObSystemProcess, va, SidIntegrity.pb, SECURITY_MAX_SID_SIZE, VMM_FLAG_FORCECACHE_READ) &&
            IsValidSid(&SidIntegrity.SID) &&
            ConvertSidToStringSidA(&SidIntegrity.SID, &szSidIntegrity);
        if(fSidIntegrity) {
            // https://redcanary.com/blog/process-integrity-levels/
            IntegrityLevel = VMM_TOKEN_INTEGRITY_LEVEL_UNKNOWN;
            if(!strcmp(szSidIntegrity, "S-1-16-16384")) { IntegrityLevel = VMM_TOKEN_INTEGRITY_LEVEL_SYSTEM; } else
            if(!strcmp(szSidIntegrity, "S-1-16-0"))     { IntegrityLevel = VMM_TOKEN_INTEGRITY_LEVEL_UNTRUSTED; } else
            if(!strcmp(szSidIntegrity, "S-1-16-4096"))  { IntegrityLevel = VMM_TOKEN_INTEGRITY_LEVEL_LOW; } else
            if(!strcmp(szSidIntegrity, "S-1-16-8192"))  { IntegrityLevel = VMM_TOKEN_INTEGRITY_LEVEL_MEDIUM; } else
            if(!strcmp(szSidIntegrity, "S-1-16-8448"))  { IntegrityLevel = VMM_TOKEN_INTEGRITY_LEVEL_MEDIUMPLUS; } else
            if(!strcmp(szSidIntegrity, "S-1-16-12288")) { IntegrityLevel = VMM_TOKEN_INTEGRITY_LEVEL_HIGH; } else
            if(!strcmp(szSidIntegrity, "S-1-16-20480")) { IntegrityLevel = VMM_TOKEN_INTEGRITY_LEVEL_PROTECTED; };
            pe->IntegrityLevel = IntegrityLevel;
            LocalFree(szSidIntegrity); szSidIntegrity = NULL;
        }
        // system process:
        pe->fSidUserSYSTEM =
            pe->fSidUserValid &&
            ConvertSidToStringSidA(&pe->SidUser.SID, &szSidUser) &&
            CharUtil_StrEquals(szSidUser, "S-1-5-18", FALSE);
        LocalFree(szSidUser); szSidUser = NULL;
    }
    // 6: finish up:
    for(i = 0; i < cTokens; i++) {
        pe = ppObTokens[i];
        pe->fSidUserValid =
            pe->fSidUserValid &&
            ConvertSidToStringSidA(&pe->SidUser.SID, &pe->szSID) &&
            (pe->dwHashSID = CharUtil_Hash32A(pe->szSID, FALSE));
    }
    fResult = TRUE;
fail:
    if(!fResult) {
        for(i = 0; i < cTokens; i++) {
            Ob_DECREF_NULL(&ppObTokens[i]);
        }
    }
    Ob_DECREF(pObSystemProcess);
    LocalFree(pva);
    return fResult;
}



// ----------------------------------------------------------------------------
// HANDLE FUNCTIONALITY BELOW:
//
// The code below is responsible for parsing the HANDLE table into a map. The
// function will read the handle table and then also peek into each handle to
// determine its type. Even though parsing is generally efficient in number of
// calls quite a few memory pages may be retrieved - worst case ~1 per handle!
// ----------------------------------------------------------------------------

typedef struct tdVMMWIN_OBJECTTYPE_NAME2OBJECT_ENTRY {
    LPSTR usz;
    LPSTR sz;
} VMMWIN_OBJECTTYPE_NAME2OBJECT_ENTRY;

static const VMMWIN_OBJECTTYPE_NAME2OBJECT_ENTRY VMMWIN_OBJECTTYPE_NAME2OBJECT_ARRAY[] = {
    // NB! order and count must correspond to: VMMWIN_OBJECT_TYPE_TABLE._tpAll
    {.usz = "ALPC Port", .sz = "_ALPC_PORT"},
    {.usz = "Device", .sz = "_DEVICE_OBJECT"},
    {.usz = "Directory", .sz = "_OBJECT_DIRECTORY"},
    {.usz = "Driver", .sz = "_DRIVER_OBJECT"},
    {.usz = "Event", .sz = "_KEVENT"},
    {.usz = "File", .sz = "_FILE_OBJECT"},
    {.usz = "Job", .sz = "_EJOB"},
    {.usz = "Key", .sz = "_CM_KEY_BODY"},
    {.usz = "Mutant", .sz = "_KMUTANT"},
    {.usz = "Process", .sz = "_EPROCESS"},
    {.usz = "Section", .sz = "_SECTION"},
    {.usz = "Semaphore", .sz = "_KSEMAPHORE"},
    {.usz = "Session", .sz = "_MM_SESSION_SPACE"},
    {.usz = "SymbolicLink", .sz = "_OBJECT_SYMBOLIC_LINK"},
    {.usz = "Thread", .sz = "_ETHREAD"},
    {.usz = "Timer", .sz = "_KTIMER"},
    {.usz = "Token", .sz = "_TOKEN"},
    {.usz = "Type", .sz = "_OBJECT_TYPE"}
};

/*
* Retrieve a pointer to a VMMWIN_OBJECT_TYPE if possible. Initialization of the
* table takes place on first use. The table only exists in Win7+ and is is
* dependant on PDB symbol functionality for initialization.
* -- H
* -- iObjectType
* -- return
*/
_Success_(return != NULL)
PVMMWIN_OBJECT_TYPE VmmWin_ObjectTypeGet(_In_ VMM_HANDLE H, _In_ BYTE iObjectType)
{
    static SRWLOCK InitLockSRW = { 0 };
    BOOL f, fResult = FALSE;
    QWORD vaTypeTable = 0;
    PVMM_PROCESS pObSystemProcess = NULL;
    POB_STRMAP pObStrMap = NULL;
    DWORD i, j, cType = 2;
    QWORD ava[256];
    WORD acbwsz[256];
    BYTE pb[256 * 8];
    LPWSTR wsz;
    PQWORD pva64;
    PDWORD pva32;
    PVMMWIN_OBJECT_TYPE ptp;
    if(H->vmm.ObjectTypeTable.fInitialized) {
        return H->vmm.ObjectTypeTable.h[iObjectType].usz ? &H->vmm.ObjectTypeTable.h[iObjectType] : NULL;
    }
    PDB_Initialize_WaitComplete(H);
    AcquireSRWLockExclusive(&InitLockSRW);
    if(H->vmm.ObjectTypeTable.fInitialized) {
        ReleaseSRWLockExclusive(&InitLockSRW);
        return H->vmm.ObjectTypeTable.h[iObjectType].usz ? &H->vmm.ObjectTypeTable.h[iObjectType] : NULL;
    }
    if(!(pObSystemProcess = VmmProcessGet(H, 4))) { goto fail; }
    if(!PDB_GetSymbolAddress(H, PDB_HANDLE_KERNEL, "ObTypeIndexTable", &vaTypeTable)) { goto fail; }
    if(H->vmm.kernel.dwVersionMajor == 10) {
        if(!PDB_GetSymbolDWORD(H, PDB_HANDLE_KERNEL, "ObHeaderCookie", pObSystemProcess, &i)) { goto fail; }
        H->vmm.ObjectTypeTable.bObjectHeaderCookie = (BYTE)i;
    }
    // fetch and count object type addresses
    ZeroMemory(ava, sizeof(ava));
    ZeroMemory(acbwsz, sizeof(acbwsz));
    VmmReadEx(H, pObSystemProcess, vaTypeTable, pb, 256 * 8, NULL, VMM_FLAG_ZEROPAD_ON_FAIL);
    if(H->vmm.f32) {
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
    VmmCachePrefetchPages4(H, pObSystemProcess, cType, ava, 0x10, 0);
    for(i = 2; i < cType; i++) {
        f = VmmRead2(H, pObSystemProcess, ava[i] + (H->vmm.f32 ? 8 : 16), pb, 0x10, VMM_FLAG_FORCECACHE_READ);
        f = f && (*(PWORD)(pb) < MAX_PATH);
        f = f && (*(PWORD)(pb) <= *(PQWORD)(pb + 2));
        f = f && (acbwsz[i] = *(PWORD)(pb));
        f = f && (ava[i] = H->vmm.f32 ? *(PDWORD)(pb + 4) : *(PQWORD)(pb + 8));
        f = f && (H->vmm.f32 ? VMM_KADDR32_8(ava[i]) : VMM_KADDR64_16(ava[i]));
        if(!f) {
            ava[i] = 0;
        }
        H->vmm.ObjectTypeTable.h[i].iType = i;
    }
    // fetch text
    wsz = (LPWSTR)(pb + 16);
    VmmCachePrefetchPages4(H, pObSystemProcess, cType, ava, 2 * MAX_PATH, 0);
    if(!(pObStrMap = ObStrMap_New(H, 0))) { goto fail; }
    for(i = 2; i < cType; i++) {
        if(ava[i] && VmmRead2(H, pObSystemProcess, ava[i] - 16, pb, 16 + acbwsz[i], VMM_FLAG_FORCECACHE_READ) && VMM_POOLTAG_PREPENDED(H->vmm.f32, pb, 16, 'ObNm')) {
            wsz[acbwsz[i] >> 1] = 0;
            ObStrMap_PushPtrWU(pObStrMap, wsz, &H->vmm.ObjectTypeTable.h[i].usz, &H->vmm.ObjectTypeTable.h[i].cbu);
        }
    }
    ObStrMap_FinalizeAllocU_DECREF_NULL(&pObStrMap, (PBYTE*)&H->vmm.ObjectTypeTable.pbMultiText, &H->vmm.ObjectTypeTable.cbMultiText);
    // specific type lookups
    for(i = 2; i < cType; i++) {
        ptp = H->vmm.ObjectTypeTable.h + i;
        for(j = 0; j < sizeof(VMMWIN_OBJECTTYPE_NAME2OBJECT_ARRAY) / sizeof(VMMWIN_OBJECTTYPE_NAME2OBJECT_ENTRY); j++) {
            if(ptp->usz && (ptp->usz[0] == VMMWIN_OBJECTTYPE_NAME2OBJECT_ARRAY[j].usz[0]) && !strcmp(ptp->usz, VMMWIN_OBJECTTYPE_NAME2OBJECT_ARRAY[j].usz)) {
                H->vmm.ObjectTypeTable._tpAll[j] = (BYTE)i;
                PDB_GetTypeSize(H, PDB_HANDLE_KERNEL, VMMWIN_OBJECTTYPE_NAME2OBJECT_ARRAY[j].sz, &ptp->cb);
                ptp->szType = VMMWIN_OBJECTTYPE_NAME2OBJECT_ARRAY[j].sz;
            }
        }
    }
    // finish!
    H->vmm.ObjectTypeTable.c = cType;
    fResult = TRUE;
    // fall-trough to cleanup / "fail"
fail:
    H->vmm.ObjectTypeTable.fInitialized = TRUE;
    if(!fResult) { H->vmm.ObjectTypeTable.fInitializedFailed = TRUE; }
    ReleaseSRWLockExclusive(&InitLockSRW);
    Ob_DECREF(pObSystemProcess);
    return H->vmm.ObjectTypeTable.h[iObjectType].usz ? &H->vmm.ObjectTypeTable.h[iObjectType] : NULL;
}

/*
* _OBJECT_HEADER.TypeIndex is encoded on Windows 10 - this function decodes it.
* https://medium.com/@ashabdalhalim/e8f907e7073a
* -- H
* -- vaObjectHeader
* -- iTypeIndexTableEncoded
* -- return
*/
BYTE VmmWin_ObjectTypeGetIndexFromEncoded(_In_ VMM_HANDLE H, _In_ QWORD vaObjectHeader, _In_ BYTE iTypeIndexTableEncoded)
{
    if(H->vmm.kernel.dwVersionMajor != 10) { return iTypeIndexTableEncoded; }
    if(!H->vmm.ObjectTypeTable.fInitialized) { VmmWin_ObjectTypeGet(H, 0); }  // DUMMY call to initialize H->vmm.ObjectTypeTable
    if(H->vmm.ObjectTypeTable.fInitializedFailed) { return 0; }
    return iTypeIndexTableEncoded ^ (BYTE)(vaObjectHeader >> 8) ^ H->vmm.ObjectTypeTable.bObjectHeaderCookie;
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
VOID VmmWinHandle_CloseObCallback(_In_ PVMMOB_MAP_HANDLE pOb)
{
    LocalFree(pOb->pbMultiText);
}

/*
* Spider the handle table hierarchy if there is one.
* -- H
* -- ctx
* -- vaTable
* -- fLevel2
*/
VOID VmmWinHandle_InitializeCore_SpiderTables(_In_ VMM_HANDLE H, _In_ PVMMWIN_INITIALIZE_HANDLE_CONTEXT ctx, _In_ QWORD vaTable, _In_ BOOL fLevel2)
{
    QWORD i, va = 0;
    union {
        BYTE pb[0x1000];
        DWORD pdw[0x400];
        QWORD pqw[0x200];
    } u;
    if(!VmmRead(H, ctx->pSystemProcess, vaTable, u.pb, 0x1000)) { return; }
    if(H->vmm.f32) {
        for(i = 0; i < 0x400; i++) {
            va = u.pdw[i];
            if(!VMM_KADDR32_PAGE(va)) { return; }
            if(fLevel2) {
                VmmWinHandle_InitializeCore_SpiderTables(H, ctx, va, FALSE);
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
                VmmWinHandle_InitializeCore_SpiderTables(H, ctx, va, FALSE);
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
* -- H
* -- ctx
* -- return = the number of valid handles.
*/
DWORD VmmWinHandle_InitializeCore_CountHandles(_In_ VMM_HANDLE H, _In_ PVMMWIN_INITIALIZE_HANDLE_CONTEXT ctx)
{
    QWORD va;
    DWORD iTable, i, cHandles = 0;
    union {
        BYTE pb[0x1000];
        DWORD pdw[0x400];
        QWORD pqw[0x200];
    } u;
    VmmCachePrefetchPages4(H, ctx->pSystemProcess, ctx->cTables, ctx->pvaTables, 0x1000, 0);
    for(iTable = 0; iTable < ctx->cTables; iTable++) {
        if(!VmmRead(H, ctx->pSystemProcess, ctx->pvaTables[iTable], u.pb, 0x1000)) { continue; }
        if(H->vmm.f32) {
            for(i = 1; i < 512; i++) {
                if(!VMM_KADDR32(u.pdw[i << 1])) { continue; }
                cHandles++;
            }
        } else {
            for(i = 1; i < 256; i++) {
                va = u.pqw[i << 1];
                if(H->vmm.kernel.dwVersionBuild >= 9200) {     // Win8 or later
                    va = 0xffff000000000000 | (va >> 16);
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
* -- H
* -- ctx
* -- vaHandleTable
* -- dwBaseHandleId
*/
VOID VmmWinHandle_InitializeCore_ReadHandleTable(_In_ VMM_HANDLE H, _In_ PVMMWIN_INITIALIZE_HANDLE_CONTEXT ctx, _In_ QWORD vaHandleTable, _In_ DWORD dwBaseHandleId)
{
    DWORD i;
    QWORD va;
    PVMM_MAP_HANDLEENTRY pe;
    union {
        BYTE pb[0x1000];
        DWORD pdw[0x400];
        QWORD pqw[0x200];
    } u;
    if(!VmmRead(H, ctx->pSystemProcess, vaHandleTable, u.pb, 0x1000)) { return; }
    if(H->vmm.f32) {
        for(i = 1; i < 512; i++) {
            if(ctx->iMap == ctx->pHandleMap->cMap) { break; }
            va = u.pdw[i << 1] & ~3;
            if(!VMM_KADDR32(va)) { continue; }
            pe = ctx->pHandleMap->pMap + ctx->iMap;
            pe->vaObject = (va & ~7) + 0x18ULL;
            pe->dwGrantedAccess = u.pdw[(i << 1) + 1] & 0x00ffffff;
            pe->dwHandle = dwBaseHandleId + (i << 2);
            pe->dwPID = ctx->pProcess->dwPID;
            ctx->iMap++;
        }
    } else {
        for(i = 1; i < 256; i++) {
            if(ctx->iMap == ctx->pHandleMap->cMap) { break; }
            va = u.pqw[i << 1];
            if(H->vmm.kernel.dwVersionBuild >= 9600) {         // Win8.1 or later
                va = 0xffff000000000000 | (va >> 16);
            } else if(H->vmm.kernel.dwVersionBuild >= 9200) {  // Win8 or later
                va = 0xfffff80000000000 | (va >> 19);
            }
            if(!VMM_KADDR64(va)) { continue; }
            if(!(va & 0x000007ffffffff00)) { continue; }        // free handle
            pe = ctx->pHandleMap->pMap + ctx->iMap;
            pe->vaObject = (va & ~7) + 0x30;
            pe->dwGrantedAccess = (DWORD)u.pqw[(i << 1) + 1] & 0x00ffffff;
            pe->dwHandle = dwBaseHandleId + (i << 2);
            pe->dwPID = ctx->pProcess->dwPID;
            ctx->iMap++;
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

DWORD VmmWinHandle_InitializeText_GetPoolHeader2(_In_ VMM_HANDLE H, DWORD dwPoolHeaderCandidate)
{
    CHAR i, ch;
    for(i = 0; i < 32; i = i + 8) {
        ch = (CHAR)(dwPoolHeaderCandidate >> i);
        if(ch >= 'a' && ch <= 'z') { continue; }
        if(ch >= 'A' && ch <= 'Z') { continue; }
        if(ch == ' ') { continue; }
        if((i == 24) && (H->vmm.kernel.dwVersionBuild <= 9601)) {
            return 0x20000000 | (dwPoolHeaderCandidate & 0x00ffffff);   // last char usually A-Z in win7
        }
        return 0;
    }
    return dwPoolHeaderCandidate;
}

DWORD VmmWinHandle_InitializeText_GetPoolHeader32(_In_ VMM_HANDLE H, _In_reads_(0x40) PBYTE pb, _Out_ PDWORD pdwOffset)
{
    DWORD dwPoolHeader, i = 0x40;
    while(i) {
        i -= 0x08;
        if((dwPoolHeader = VmmWinHandle_InitializeText_GetPoolHeader2(H, *(PDWORD)(pb + i + 4)))) {
            *pdwOffset = i + 4;
            return dwPoolHeader;
        }
    }
    *pdwOffset = 0;
    return 0;
}

DWORD VmmWinHandle_InitializeText_GetPoolHeader64(_In_ VMM_HANDLE H, _In_reads_(0x60) PBYTE pb, _Out_ PDWORD pdwOffset)
{
    DWORD dwPoolHeader, i = 0x60;
    while(i) {
        i -= 0x10;
        if((dwPoolHeader = VmmWinHandle_InitializeText_GetPoolHeader2(H, *(PDWORD)(pb + i + 4)))) {
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
} VMMWINHANDLE_REGHELPER, *PVMMWINHANDLE_REGHELPER;

/*
* Helper function for VmmWinHandle_InitializeText_DoWork that fetches registry
* names provided that the underlying _CM_KEY_CONTROL_BLOCK is prefetched.
* -- H
* -- pSystemProcess
* -- pm
*/
VOID VmmWinHandle_InitializeText_DoWork_RegKeyHelper(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pSystemProcess, _In_ POB_MAP pm)
{
    BYTE pb[0x30];
    DWORD raCell, dwVersionBuild = H->vmm.kernel.dwVersionBuild;
    QWORD vaHive;
    POB_REGISTRY_KEY pObKey = NULL;
    POB_REGISTRY_HIVE pObHive = NULL;
    PVMMWINHANDLE_REGHELPER prh = NULL;
    while((prh = ObMap_GetNext(pm, prh))) {
        if(!VmmRead2(H, pSystemProcess, prh->vaCmKeyControlBlock, pb, 0x30, VMM_FLAG_FORCECACHE_READ)) { continue; }
        if(H->vmm.f32) {
            if((dwVersionBuild >= 7600) && (dwVersionBuild <= 10586)) {
                // Win7 :: Win10_10586
                vaHive = *(PDWORD)(pb + 0x14);
                raCell = *(PDWORD)(pb + 0x18);
            } else {
                vaHive = *(PDWORD)(pb + 0x10);
                raCell = *(PDWORD)(pb + 0x14);
            }
            if(!VMM_KADDR32(vaHive)) { continue; }
        } else {
            if((dwVersionBuild <= 6002) || ((dwVersionBuild >= 14393) && (dwVersionBuild <= 17763))) {
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
        if((pObHive = VmmWinReg_HiveGetByAddress(H, prh->vaHive))) {
            if((pObKey = VmmWinReg_KeyGetByCellOffset(H, pObHive, prh->raKeyCell))) {
                VmmWinReg_KeyInfo2(H, pObHive, pObKey, &prh->KeyInfo);
                Ob_DECREF_NULL(&pObKey);
            }
            Ob_DECREF_NULL(&pObHive);
        }
    }
}

VOID VmmWinHandle_InitializeText_DoWork_FileSizeHelper(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pSystemProcess, _In_ POB_SET psPrefetch, _In_ PVMMOB_MAP_HANDLE pHandleMap)
{
    BOOL f, f32 = H->vmm.f32;
    QWORD i, cMax, cb, va;
    BYTE pb[0x100];
    PVMM_MAP_HANDLEENTRY pe;
    // 1: fetch, if required, _SHARED_CACHE_MAP // _CONTROL_AREA
    if(0 == ObSet_Size(psPrefetch)) { return; }
    VmmCachePrefetchPages3(H, pSystemProcess, psPrefetch, 0x20, 0);
    ObSet_Clear(psPrefetch);
    for(i = 0, cMax = pHandleMap->cMap; i < cMax; i++) {
        pe = pHandleMap->pMap + i;
        if(pe->tpInfoEx != HANDLEENTRY_TP_INFO_FILE) { continue; }
        if(!VmmRead2(H, pSystemProcess, pe->_Reserved.qw - 0x10, pb, 0x20, VMM_FLAG_FORCECACHE_READ)) { continue; }
        if(VMM_POOLTAG_PREPENDED(f32, pb, 0x10, 'CcSc')) {
            cb = *(PQWORD)(pb + 0x10 + O_SHARED_CACHE_MAP_FileSize);
            pe->_InfoFile.cb = (cb <= 0xffffffff) ? (DWORD)cb : 0xffffffff;
            continue;
        }
        f = VMM_POOLTAG_PREPENDED(f32, pb, 0x10, 'MmCa') &&
            (va = VMM_PTR_OFFSET(f32, pb + 0x10, O_CONTROL_AREA_Segment)) &&
            VMM_KADDR_8_16(f32, va);
        if(f) {
            pe->_Reserved.qw = va;
            ObSet_Push(psPrefetch, va - 0x10);
        }
    }
    // 2: fetch, if required, _SEGMENT
    if(0 == ObSet_Size(psPrefetch)) { return; }
    VmmCachePrefetchPages3(H, pSystemProcess, psPrefetch, 0x30, 0);
    for(i = 0, cMax = pHandleMap->cMap; i < cMax; i++) {
        pe = pHandleMap->pMap + i;
        if(pe->tpInfoEx != HANDLEENTRY_TP_INFO_FILE) { continue; }
        if(!VmmRead2(H, pSystemProcess, pe->_Reserved.qw - 0x10, pb, 0x30, VMM_FLAG_FORCECACHE_READ)) { continue; }
        if(VMM_POOLTAG_PREPENDED(f32, pb, 0x10, 'MmSm')) {
            cb = *(PQWORD)(pb + 0x10 + (f32 ? O32_SEGMENT_SizeOfSegment : O64_SEGMENT_SizeOfSegment));
            cb = (cb <= 0xffffffff) ? cb : 0xffffffff;
            pe->_InfoFile.cb = (DWORD)(pe->_InfoFile.cb ? min(pe->_InfoFile.cb, cb) : cb);
        }
    }
}

VOID VmmWinHandle_InitializeText_DoWork(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pSystemProcess, _In_ PVMMOB_MAP_HANDLE pHandleMap)
{
    BOOL f, f32 = H->vmm.f32, fThreadingEnabled;
    PVMM_OFFSET po = &H->vmm.offset;
    PBYTE pbMultiText = NULL;
    QWORD va;
    DWORD i, cbRead, oPoolHdr, cbObjectRead, dwoName, dwTag;
    BYTE pbBuffer[2 * MAX_PATH];
    POB_SET psObPrefetch = NULL, psObDevRegPrefetch = NULL;
    POB_MAP pmObRegHelperMap = NULL;
    PUNICODE_STRING32 pus32;
    PUNICODE_STRING64 pus64;
    PVMM_MAP_HANDLEENTRY pe;
    PVMM_PROCESS pObProcessHnd;
    LPSTR uszTMP;
    union {
        BYTE pb[0x1000];
        struct {
            BYTE _Filler1[0x60 - 0x18 - 0x0c];
            UNICODE_STRING32 String;
            DWORD _Filler2;
            VMMWIN_OBJECT_HEADER32 Header;
            BYTE pb[0];
        } O32;
        struct {
            BYTE _Filler1[0x90 - 0x30 - 0x18];
            UNICODE_STRING64 String;
            QWORD _Filler2;
            VMMWIN_OBJECT_HEADER64 Header;
            BYTE pb[0];
        } O64;
    } u;
    PVMMWINHANDLE_REGHELPER pRegHelp = NULL;
    POB_STRMAP psmOb = NULL;
    fThreadingEnabled = (po->ETHREAD.oCid > 0);
    cbObjectRead = max(po->EPROCESS.PID + 0x08, po->ETHREAD.oCid + 0x20);
    cbObjectRead = 0x90 + max(0x70, cbObjectRead);
    // 1: cache prefetch object data
    if(!(psObPrefetch = ObSet_New(H))) { goto fail; }
    if(!(psObDevRegPrefetch = ObSet_New(H))) { goto fail; }
    if(!(pmObRegHelperMap = ObMap_New(H, OB_MAP_FLAGS_OBJECT_LOCALFREE))) { goto fail; }
    for(i = 0; i < pHandleMap->cMap; i++) {
        ObSet_Push(psObPrefetch, pHandleMap->pMap[i].vaObject - 0x90);
    }
    VmmCachePrefetchPages3(H, pSystemProcess, psObPrefetch, cbObjectRead, 0);
    ObSet_Clear(psObPrefetch);
    // 2: read and interpret object data
    if(f32) {
        for(i = 0; i < pHandleMap->cMap; i++) {
            pe = pHandleMap->pMap + i;
            VmmReadEx(H, pSystemProcess, pe->vaObject - 0x60, u.pb, cbObjectRead, &cbRead, VMM_FLAG_ZEROPAD_ON_FAIL | VMM_FLAG_FORCECACHE_READ);
            if(cbRead < 0x60) { continue; }
            // fetch and validate type index (if possible)
            pe->iType = VmmWin_ObjectTypeGetIndexFromEncoded(H, pe->vaObject - 0x18, u.O32.Header.TypeIndex);
            // fetch pool tag (if found)
            pe->dwPoolTag = VmmWinHandle_InitializeText_GetPoolHeader32(H, u.pb, &oPoolHdr);
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
                    ObSet_Push(psObDevRegPrefetch, pRegHelp->vaCmKeyControlBlock);
                } else if((pe->dwPoolTag & 0x00ffffff) == 'orP') {  // PROCESS
                    pe->_Reserved.dw = *(PDWORD)(u.O32.pb + po->EPROCESS.PID);
                } else if(((pe->dwPoolTag & 0x00ffffff) == 'rhT') && fThreadingEnabled) {   // THREAD
                    if(po->ETHREAD.oCid && *(PDWORD)(u.O32.pb + po->ETHREAD.oCid + 4)) {
                        pe->_Reserved.dw = *(PDWORD)(u.O32.pb + po->ETHREAD.oCid + 4);
                    }
                } else if((pe->dwPoolTag & 0x00ffffff) == 'liF') {  // FILE HANDLE
                    // file name (from file object)
                    pus32 = (PUNICODE_STRING32)(u.O32.pb + O32_FILE_OBJECT_FileName);
                    // ptr to DeviceObject (to retrieve its name)
                    va = *(PDWORD)(u.O32.pb + O32_FILE_OBJECT_DeviceObject);
                    if(VMM_KADDR32_4(va)) {
                        pe->_Reserved.qw3 = va;
                        ObSet_Push(psObDevRegPrefetch, va - 0x60);
                    }
                    // ptr to SectionObjectPointer (to retrieve file size)
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
                    pe->_Reserved.dw = pus32->Length;
                    pe->_Reserved.qw = pus32->Buffer;
                    ObSet_Push(psObPrefetch, pus32->Buffer);
                }
            }
        }
    } else {
        for(i = 0; i < pHandleMap->cMap; i++) {
            pe = pHandleMap->pMap + i;
            VmmReadEx(H, pSystemProcess, pe->vaObject - 0x90, u.pb, cbObjectRead, &cbRead, VMM_FLAG_ZEROPAD_ON_FAIL | VMM_FLAG_FORCECACHE_READ);
            if(cbRead < 0x90) { continue; }
            // fetch and validate type index (if possible)
            pe->iType = VmmWin_ObjectTypeGetIndexFromEncoded(H, pe->vaObject - 0x30, u.O64.Header.TypeIndex);
            // fetch pool tag (if found)
            pe->dwPoolTag = VmmWinHandle_InitializeText_GetPoolHeader64(H, u.pb, &oPoolHdr);
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
                    ObSet_Push(psObDevRegPrefetch, pRegHelp->vaCmKeyControlBlock);
                } else if((pe->dwPoolTag & 0x00ffffff) == 'orP') {  // PROCESS
                    pe->_Reserved.dw = *(PDWORD)(u.O64.pb + po->EPROCESS.PID);
                } else if(((pe->dwPoolTag & 0x00ffffff) == 'rhT') && fThreadingEnabled) {   // THREAD
                    if(po->ETHREAD.oCid && *(PDWORD)(u.O64.pb + po->ETHREAD.oCid + 8)) {
                        pe->_Reserved.dw = *(PDWORD)(u.O64.pb + po->ETHREAD.oCid + 8);
                    }
                } else if((pe->dwPoolTag & 0x00ffffff) == 'liF') {  // FILE HANDLE
                    // file name (from file object)
                    pus64 = (PUNICODE_STRING64)(u.O64.pb + O64_FILE_OBJECT_FileName);
                    // ptr to DeviceObject (to retrieve its name)
                    va = *(PQWORD)(u.O64.pb + O64_FILE_OBJECT_DeviceObject);
                    if(VMM_KADDR64_8(va)) {
                        pe->_Reserved.qw3 = va;
                        ObSet_Push(psObDevRegPrefetch, va - 0x90);
                    }
                    // ptr to SectionObjectPointer (to retrieve file size)
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
                    pe->_Reserved.dw = pus64->Length;
                    pe->_Reserved.qw = pus64->Buffer;
                    ObSet_Push(psObPrefetch, pus64->Buffer);
                }
            }
        }
    }
    // registry key retrieve names & file device object parse
    VmmCachePrefetchPages3(H, pSystemProcess, psObDevRegPrefetch, 0x90, 0);
    for(i = 0; i < pHandleMap->cMap; i++) {
        // file object -> device object name ptr
        pe = pHandleMap->pMap + i;
        va = pe->_Reserved.qw3;
        pe->_Reserved.qw3 = 0;
        if(va && (pe->dwPoolTag & 0x00ffffff) == 'liF') {
            if(f32) {
                VmmReadEx(H, pSystemProcess, va - 0x60, u.pb, cbObjectRead, &cbRead, VMM_FLAG_ZEROPAD_ON_FAIL | VMM_FLAG_FORCECACHE_READ);
                if(cbRead < 0x60) { continue; }
                dwTag = VmmWinHandle_InitializeText_GetPoolHeader32(H, u.pb, &oPoolHdr);
                if((dwTag & 0x00ffffff) != 'veD') { continue; }
                pus32 = &u.O32.String;
                f = pus32 && (pus32->Length > 2) &&
                    !(pus32->Length & 1) && (pus32->Length < (2 * MAX_PATH)) && (pus32->Length <= pus32->MaximumLength) &&
                    VMM_KADDR32(pus32->Buffer);
                if(f) {
                    pe->_Reserved.dw3 = pus32->Length;
                    pe->_Reserved.qw3 = pus32->Buffer;
                    ObSet_Push(psObPrefetch, pus32->Buffer);
                }
            } else {
                VmmReadEx(H, pSystemProcess, va - 0x90, u.pb, cbObjectRead, &cbRead, VMM_FLAG_ZEROPAD_ON_FAIL | VMM_FLAG_FORCECACHE_READ);
                if(cbRead < 0x90) { continue; }
                dwTag = VmmWinHandle_InitializeText_GetPoolHeader64(H, u.pb, &oPoolHdr);
                if((dwTag & 0x00ffffff) != 'veD') { continue; }
                pus64 = &u.O64.String;
                f = pus64 && (pus64->Length > 2) &&
                    !(pus64->Length & 1) && (pus64->Length < (2 * MAX_PATH)) && (pus64->Length <= pus64->MaximumLength) &&
                    VMM_KADDR64(pus64->Buffer);
                if(f) {
                    pe->_Reserved.dw3 = pus64->Length;
                    pe->_Reserved.qw3 = pus64->Buffer;
                    ObSet_Push(psObPrefetch, pus64->Buffer);
                }
            }
        }
    }
    VmmWinHandle_InitializeText_DoWork_RegKeyHelper(H, pSystemProcess, pmObRegHelperMap);
    // create and fill text descriptions
    // also get potential _FILE_OBJECT->SectionObjectPointer->SharedCacheMap (if applicable)
    psmOb = ObStrMap_New(H, 0);
    VmmCachePrefetchPages3(H, pSystemProcess, psObPrefetch, MAX_PATH * 2, 0);
    ObSet_Clear(psObPrefetch);
    for(i = 0; i < pHandleMap->cMap; i++) {
        pe = pHandleMap->pMap + i;
        dwoName = 0;
        if((pe->dwPoolTag & 0x00ffffff) == 'yeK') {         // REG KEY
            if((pRegHelp = ObMap_GetByKey(pmObRegHelperMap, pe->vaObject))) {
                if(pRegHelp->KeyInfo.uszName[0]) {
                    ObStrMap_PushUU_snprintf_s(psmOb, &pe->uszText, &pe->cbuText, "[%llx:%08x] %s", pRegHelp->vaHive, pRegHelp->KeyInfo.raKeyCell, pRegHelp->KeyInfo.uszName);
                } else {
                    ObStrMap_PushUU_snprintf_s(psmOb, &pe->uszText, &pe->cbuText, "[%llx:%08x]", pRegHelp->vaHive, pRegHelp->KeyInfo.raKeyCell);
                }
            }
        } else if((pe->dwPoolTag & 0x00ffffff) == 'orP') {  // PROCESS
            if((pe->_Reserved.dw < 99999) && (pObProcessHnd = VmmProcessGet(H, pe->_Reserved.dw))) {
                ObStrMap_PushUU_snprintf_s(psmOb, &pe->uszText, &pe->cbuText, "PID %i - %s", pObProcessHnd->dwPID, pObProcessHnd->szName);
                Ob_DECREF_NULL(&pObProcessHnd);
            }
        } else if((pe->dwPoolTag & 0x00ffffff) == 'rhT') {   // THREAD
            if(pe->_Reserved.dw && (pe->_Reserved.dw < 99999)) {
                ObStrMap_PushUU_snprintf_s(psmOb, &pe->uszText, &pe->cbuText, "TID %i", pe->_Reserved.dw);
            }
        } else if(pe->_Reserved.qw) {
            if(((pe->dwPoolTag & 0x00ffffff) == 'liF') && pe->_Reserved.qw3) {  // FILE with DeviceObjectName
                pbBuffer[dwoName++] = '\\';
                if(VmmReadWtoU(H, pSystemProcess, pe->_Reserved.qw3, pe->_Reserved.dw3, VMM_FLAG_FORCECACHE_READ, pbBuffer + dwoName, sizeof(pbBuffer) - dwoName, &uszTMP, NULL, CHARUTIL_FLAG_TRUNCATE)) {
                    dwoName = (DWORD)strlen((LPSTR)pbBuffer);
                }
            }
            if(VmmReadWtoU(H, pSystemProcess, pe->_Reserved.qw, pe->_Reserved.dw, VMM_FLAG_FORCECACHE_READ, pbBuffer + dwoName, sizeof(pbBuffer) - dwoName, &uszTMP, NULL, CHARUTIL_FLAG_TRUNCATE)) {
                ObStrMap_PushPtrUU(psmOb, (LPSTR)pbBuffer, &pe->uszText, &pe->cbuText);
            }
        }
        // Process _SECTION_OBJECT_POINTERS DataSectionObject&SharedCacheMap:
        if((pe->tpInfoEx == HANDLEENTRY_TP_INFO_PRE_1) && VmmRead2(H, pSystemProcess, pe->_Reserved.qw2, u.pb, 0x18, VMM_FLAG_FORCECACHE_READ)) {
            pe->_InfoFile.cb = 0;
            f = VMM_KADDR_4_8(f32, (va = VMM_PTR_OFFSET_DUAL(f32, u.pb, O32_SECTION_OBJECT_POINTERS_SharedCacheMap, O64_SECTION_OBJECT_POINTERS_SharedCacheMap))) ||
                VMM_KADDR_4_8(f32, (va = VMM_PTR_OFFSET_DUAL(f32, u.pb, O32_SECTION_OBJECT_POINTERS_DataSectionObject, O64_SECTION_OBJECT_POINTERS_DataSectionObject)));
            if(f) {
                pe->_Reserved.qw = va;
                pe->tpInfoEx = HANDLEENTRY_TP_INFO_FILE;
                ObSet_Push(psObPrefetch, va - 0x10);
            }
        }
        pe->_InfoFile.cb = 0;
        pe->_InfoFile.dwoName = dwoName;
    }
    // retrieve (if applicable) file sizes
    VmmWinHandle_InitializeText_DoWork_FileSizeHelper(H, pSystemProcess, psObPrefetch, pHandleMap);
    // finish
    ObStrMap_FinalizeAllocU_DECREF_NULL(&psmOb, &pHandleMap->pbMultiText, &pHandleMap->cbMultiText);
    for(i = 0; i < pHandleMap->cMap; i++) {
        pe = pHandleMap->pMap + i;
        if(!pe->uszText) {
            pe->cbuText = 1;
            pe->uszText = (LPSTR)pHandleMap->pbMultiText;
        }
    }
fail:
    Ob_DECREF(psObPrefetch);
    Ob_DECREF(psObDevRegPrefetch);
    Ob_DECREF(pmObRegHelperMap);
    Ob_DECREF(psmOb);
}

VOID VmmWinHandle_InitializeCore_DoWork(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pSystemProcess, _In_ PVMM_PROCESS pProcess)
{
    BOOL fResult = FALSE;
    BOOL f32 = H->vmm.f32;
    BYTE pb[0x20], iLevel;
    WORD oTableCode;
    DWORD i, cHandles, iHandleMap = 0;
    QWORD vaHandleTable = 0, vaTableCode = 0;
    VMMWIN_INITIALIZE_HANDLE_CONTEXT ctx = { 0 };
    PVMMOB_MAP_HANDLE pObHandleMap = NULL;
    ctx.pSystemProcess = pSystemProcess;
    ctx.pProcess = pProcess;
    vaHandleTable = VMM_PTR_OFFSET(f32, pProcess->win.EPROCESS.pb, H->vmm.offset.EPROCESS.ObjectTable);
    if(!VMM_KADDR(f32, vaHandleTable) || !VmmRead(H, pSystemProcess, vaHandleTable - 0x10, pb, 0x20)) { return; }
    if(!VMM_POOLTAG_PREPENDED(f32, pb, 0x10, 'Obtb') && !VMM_KADDR_PAGE(f32, vaHandleTable)) { return; }
    oTableCode = (H->vmm.kernel.dwVersionBuild < 9200) ? 0 : 8;    // WinXP::Win7 -> 0, otherwise 8.
    vaTableCode = VMM_PTR_OFFSET(f32, pb + 0x10, oTableCode) & ~7;
    iLevel = VMM_PTR_OFFSET(f32, pb + 0x10, oTableCode) & 7;
    if((iLevel > 2) || !VMM_KADDR_PAGE(f32, vaTableCode)) { return; }
    ctx.cTablesMax = f32 ? 1024 : 512;
    ctx.cTablesMax = iLevel ? ((iLevel == 1) ? (ctx.cTablesMax * ctx.cTablesMax) : ctx.cTablesMax) : 1;
    if(!(ctx.pvaTables = LocalAlloc(0, ctx.cTablesMax * sizeof(QWORD)))) { return; }
    if(iLevel) {
        VmmWinHandle_InitializeCore_SpiderTables(H, &ctx, vaTableCode, (iLevel == 2));
    } else {
        ctx.cTables = 1;
        ctx.pvaTables[0] = vaTableCode;
    }
    // count handles and allocate map
    if(!(cHandles = VmmWinHandle_InitializeCore_CountHandles(H, &ctx))) { goto fail; }
    cHandles = min(cHandles, 256 * 1024);
    ctx.pHandleMap = pObHandleMap = Ob_AllocEx(H, OB_TAG_MAP_HANDLE, LMEM_ZEROINIT, sizeof(VMMOB_MAP_HANDLE) + cHandles * sizeof(VMM_MAP_HANDLEENTRY), (OB_CLEANUP_CB)VmmWinHandle_CloseObCallback, NULL);
    if(!pObHandleMap) { goto fail; }
    pObHandleMap->cMap = cHandles;
    // walk handle tables to fill map with core handle information
    for(i = 0; i < ctx.cTables; i++) {
        VmmWinHandle_InitializeCore_ReadHandleTable(H, &ctx, ctx.pvaTables[i], i * (f32 ? 2048 : 1024));
    }
    pObHandleMap->cMap = ctx.iMap;
    pProcess->Map.pObHandle = Ob_INCREF(pObHandleMap);
fail:
    LocalFree(ctx.pvaTables);
    Ob_DECREF(pObHandleMap);
}

_Success_(return)
BOOL VmmWinHandle_InitializeCore(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess)
{
    PVMM_PROCESS pObSystemProcess;
    if(pProcess->Map.pObHandle) { return TRUE; }
    EnterCriticalSection(&pProcess->LockUpdate);
    if(!pProcess->Map.pObHandle && (pObSystemProcess = VmmProcessGet(H, 4))) {
        VmmWinHandle_InitializeCore_DoWork(H, pObSystemProcess, pProcess);
        if(!pProcess->Map.pObHandle) {
            pProcess->Map.pObHandle = Ob_AllocEx(H, OB_TAG_MAP_HANDLE, LMEM_ZEROINIT, sizeof(VMMOB_MAP_HANDLE), (OB_CLEANUP_CB)VmmWinHandle_CloseObCallback, NULL);
        }
        Ob_DECREF(pObSystemProcess);
    }
    LeaveCriticalSection(&pProcess->LockUpdate);
    return pProcess->Map.pObHandle ? TRUE : FALSE;
}

_Success_(return)
BOOL VmmWinHandle_InitializeText(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess)
{
    PVMM_PROCESS pObSystemProcess;
    if(pProcess->Map.pObHandle->pbMultiText) { return TRUE; }
    EnterCriticalSection(&pProcess->LockUpdate);
    if(!pProcess->Map.pObHandle->pbMultiText && (pObSystemProcess = VmmProcessGet(H, 4))) {
        VmmWinHandle_InitializeText_DoWork(H, pObSystemProcess, pProcess->Map.pObHandle);
        Ob_DECREF(pObSystemProcess);
    }
    LeaveCriticalSection(&pProcess->LockUpdate);
    return pProcess->Map.pObHandle->pbMultiText ? TRUE : FALSE;
}

/*
* Initialize Handles for a specific process. Extended information text may take
* extra time to initialize.
* -- H
* -- pProcess
* -- fExtendedText = also fetch extended info such as handle paths/names.
* -- return
*/
_Success_(return)
BOOL VmmWinHandle_Initialize(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess, _In_ BOOL fExtendedText)
{
    if(pProcess->Map.pObHandle && (!fExtendedText || pProcess->Map.pObHandle->pbMultiText)) { return TRUE; }
    return VmmWinHandle_InitializeCore(H, pProcess) && (!fExtendedText || VmmWinHandle_InitializeText(H, pProcess));
}



// ----------------------------------------------------------------------------
// PHYSICAL MEMORY MAP FUNCTIONALITY BELOW:
//
// The physical memory map functionality is responsible for retrieving the
// physical memory map from the Windows registry (if possible).
// ----------------------------------------------------------------------------

#pragma pack(push, 1) /* DISABLE STRUCT PADDINGS (REENABLE AFTER STRUCT DEFINITIONS) */
typedef struct tdVMMWIN_PHYSMEMMAP_REGISTRY_MEMORY_RANGE32 {
    UCHAR Type;
    UCHAR ShareDisposition;
    USHORT Flags;
    QWORD pa;
    DWORD cb;
} VMMWIN_PHYSMEMMAP_REGISTRY_MEMORY_RANGE32, *PVMMWIN_PHYSMEMMAP_REGISTRY_MEMORY_RANGE32;

typedef struct tdVMMWIN_PHYSMEMMAP_REGISTRY_MEMORY_RANGE64 {
    UCHAR Type;
    UCHAR ShareDisposition;
    USHORT Flags;
    QWORD pa;
    QWORD cb;
} VMMWIN_PHYSMEMMAP_REGISTRY_MEMORY_RANGE64, *PVMMWIN_PHYSMEMMAP_REGISTRY_MEMORY_RANGE64;
#pragma pack(pop) /* RE-ENABLE STRUCT PADDINGS */

/*
* Retrieve the physical memory by parsing the registry. This is only used as a
* fallback in case it cannot be parsed from kernel due to the extra overhead
* by parsing the registry hardware hive.
* -- H
* -- return
*/
_Success_(return != NULL)
PVMMOB_MAP_PHYSMEM VmmWinPhysMemMap_InitializeFromRegistry_DoWork(_In_ VMM_HANDLE H)
{
    BOOL f32 = H->vmm.f32;
    DWORD cMap, cbData = 0;
    PBYTE pbData = NULL;
    QWORD c1, i, o;
    PVMMWIN_PHYSMEMMAP_REGISTRY_MEMORY_RANGE32 pMR32;
    PVMMWIN_PHYSMEMMAP_REGISTRY_MEMORY_RANGE64 pMR64;
    PVMMOB_MAP_PHYSMEM pObPhysMemMap = NULL;
    // 1: fetch binary data from registry
    if(!VmmWinReg_ValueQuery2(H, "HKLM\\HARDWARE\\RESOURCEMAP\\System Resources\\Physical Memory\\.Translated", NULL, NULL, 0, &cbData) || !cbData) { goto fail; }
    if(!(pbData = LocalAlloc(0, cbData))) { goto fail; }
    if(!VmmWinReg_ValueQuery2(H, "HKLM\\HARDWARE\\RESOURCEMAP\\System Resources\\Physical Memory\\.Translated", NULL, pbData, cbData, &cbData)) { goto fail; }
    if(cbData < (DWORD)(f32 ? 0x18 : 0x28)) { goto fail; }
    // 2: fetch number of memory regions and allocate map object.
    c1 = *(PQWORD)pbData;
    if(!c1) { goto fail; }
    o = 0x10;
    cMap = *(PDWORD)(pbData + o); // this should be loop in case of c1 > 1, but works for now ...
    if(f32 && (!cMap || (cbData < cMap * sizeof(VMMWIN_PHYSMEMMAP_REGISTRY_MEMORY_RANGE32) + 0x0c))) { goto fail; }
    if(!f32 && (!cMap || (cbData < cMap * sizeof(VMMWIN_PHYSMEMMAP_REGISTRY_MEMORY_RANGE64) + 0x14))) { goto fail; }
    if(!(pObPhysMemMap = Ob_AllocEx(H, OB_TAG_MAP_PHYSMEM, LMEM_ZEROINIT, sizeof(VMMOB_MAP_PHYSMEM) + cMap * sizeof(VMM_MAP_PHYSMEMENTRY), NULL, NULL))) { goto fail; }
    pObPhysMemMap->cMap = cMap;
    // 3: iterate over the memory regions.
    o += sizeof(DWORD);
    for(i = 0; i < cMap; i++) {
        if(f32) {
            pMR32 = (PVMMWIN_PHYSMEMMAP_REGISTRY_MEMORY_RANGE32)(pbData + o + i * sizeof(VMMWIN_PHYSMEMMAP_REGISTRY_MEMORY_RANGE32));
            pObPhysMemMap->pMap[i].pa = pMR32->pa;
            pObPhysMemMap->pMap[i].cb = pMR32->cb;
            if(pMR32->Flags & 0xff00) {
                pObPhysMemMap->pMap[i].cb = pObPhysMemMap->pMap[i].cb << 8;
            }
        } else {
            pMR64 = (PVMMWIN_PHYSMEMMAP_REGISTRY_MEMORY_RANGE64)(pbData + o + i * sizeof(VMMWIN_PHYSMEMMAP_REGISTRY_MEMORY_RANGE64));
            pObPhysMemMap->pMap[i].pa = pMR64->pa;
            pObPhysMemMap->pMap[i].cb = pMR64->cb;
            if(pMR64->Flags & 0xff00) {
                pObPhysMemMap->pMap[i].cb = pObPhysMemMap->pMap[i].cb << 8;
            }
        }
        if((pObPhysMemMap->pMap[i].pa & 0xfff) || (pObPhysMemMap->pMap[i].cb & 0xfff)) { goto fail; }
    }
    LocalFree(pbData);
    return pObPhysMemMap;
fail:
    Ob_DECREF(pObPhysMemMap);
    LocalFree(pbData);
    return NULL;
}

/*
* Retrieve the physical memory map from the kernel by parsing the kernel symbol
* 'MmPhysicalMemoryBlock'. This is the preferred way of fetching the memory map
* due to better efficiency as compared to fallback - parsing from registry.
* -- H
* -- return
*/
_Success_(return != NULL)
PVMMOB_MAP_PHYSMEM VmmWinPhysMemMap_InitializeFromKernel_DoWork(_In_ VMM_HANDLE H)
{
    QWORD i, c, vaPhysicalMemoryBlock = 0;
    _PHYSICAL_MEMORY_DESCRIPTOR32 Md32;
    _PHYSICAL_MEMORY_DESCRIPTOR64 Md64;
    PVMM_PROCESS pObSystemProcess = NULL;
    PVMMOB_MAP_PHYSMEM pObMemMap = NULL;
    if(!(pObSystemProcess = VmmProcessGet(H, 4))) { goto fail; }
    if(!PDB_GetSymbolPTR(H, PDB_HANDLE_KERNEL, "MmPhysicalMemoryBlock", pObSystemProcess, (PVOID)&vaPhysicalMemoryBlock)) { goto fail; }
    if(!VMM_KADDR_4_8(H->vmm.f32, vaPhysicalMemoryBlock)) { goto fail; }
    if(H->vmm.f32) {
        if(!VmmRead2(H, pObSystemProcess, vaPhysicalMemoryBlock, (PBYTE)&Md32, sizeof(_PHYSICAL_MEMORY_DESCRIPTOR32), VMMDLL_FLAG_ZEROPAD_ON_FAIL)) { goto fail; }
        if(!Md32.NumberOfRuns || (Md32.NumberOfRuns > _PHYSICAL_MEMORY_MAX_RUNS)) { goto fail; }
        if(!(pObMemMap = Ob_AllocEx(H, OB_TAG_MAP_PHYSMEM, LMEM_ZEROINIT, sizeof(VMMOB_MAP_PHYSMEM) + Md32.NumberOfRuns * sizeof(VMM_MAP_PHYSMEMENTRY), NULL, NULL))) { goto fail; }
        pObMemMap->cMap = Md32.NumberOfRuns;
        for(i = 0, c = 0; i < Md32.NumberOfRuns; i++) {
            pObMemMap->pMap[i].pa = (QWORD)Md32.Run[i].BasePage << 12;
            pObMemMap->pMap[i].cb = (QWORD)Md32.Run[i].PageCount << 12;
            c += Md32.Run[i].PageCount;
            if(i && ((pObMemMap->pMap[i - 1].pa + pObMemMap->pMap[i - 1].cb) > pObMemMap->pMap[i].pa)) { goto fail; }
        }
        if(c != Md32.NumberOfPages) { goto fail; }
    } else {
        if(!VmmRead2(H, pObSystemProcess, vaPhysicalMemoryBlock, (PBYTE)&Md64, sizeof(_PHYSICAL_MEMORY_DESCRIPTOR64), VMMDLL_FLAG_ZEROPAD_ON_FAIL)) { goto fail; }
        if(!Md64.NumberOfRuns || (Md64.NumberOfRuns > _PHYSICAL_MEMORY_MAX_RUNS)) { goto fail; }
        if(!(pObMemMap = Ob_AllocEx(H, OB_TAG_MAP_PHYSMEM, LMEM_ZEROINIT, sizeof(VMMOB_MAP_PHYSMEM) + Md64.NumberOfRuns * sizeof(VMM_MAP_PHYSMEMENTRY), NULL, NULL))) { goto fail; }
        pObMemMap->cMap = Md64.NumberOfRuns;
        for(i = 0, c = 0; i < Md64.NumberOfRuns; i++) {
            pObMemMap->pMap[i].pa = Md64.Run[i].BasePage << 12;
            pObMemMap->pMap[i].cb = Md64.Run[i].PageCount << 12;
            c += Md64.Run[i].PageCount;
            if(i && ((pObMemMap->pMap[i-1].pa + pObMemMap->pMap[i-1].cb) > pObMemMap->pMap[i].pa)) { goto fail; }
        }
        if(c != Md64.NumberOfPages) { goto fail; }
    }
    Ob_INCREF(pObMemMap);
fail:
    Ob_DECREF(pObSystemProcess);
    return Ob_DECREF(pObMemMap);
}

/*
* Create a physical memory map and assign to the global context upon success.
* CALLER DECREF: return
* -- H
* -- return
*/
PVMMOB_MAP_PHYSMEM VmmWinPhysMemMap_Initialize(_In_ VMM_HANDLE H)
{
    PVMMOB_MAP_PHYSMEM pObPhysMem;
    if((pObPhysMem = ObContainer_GetOb(H->vmm.pObCMapPhysMem))) { return pObPhysMem; }
    EnterCriticalSection(&H->vmm.LockUpdateMap);
    if((pObPhysMem = ObContainer_GetOb(H->vmm.pObCMapPhysMem))) {
        LeaveCriticalSection(&H->vmm.LockUpdateMap);
        return pObPhysMem;
    }
    pObPhysMem = VmmWinPhysMemMap_InitializeFromKernel_DoWork(H);
    if(!pObPhysMem) {     // fallback to parsing registry (if error on no loaded symbols)
        pObPhysMem = VmmWinPhysMemMap_InitializeFromRegistry_DoWork(H);
    }
    if(!pObPhysMem) {
        pObPhysMem = Ob_AllocEx(H, OB_TAG_MAP_PHYSMEM, LMEM_ZEROINIT, sizeof(VMMOB_MAP_PHYSMEM), NULL, NULL);
    }
    ObContainer_SetOb(H->vmm.pObCMapPhysMem, pObPhysMem);
    LeaveCriticalSection(&H->vmm.LockUpdateMap);
    return pObPhysMem;
}

/*
* Refresh the physical memory map.
* -- H
*/
VOID VmmWinPhysMemMap_Refresh(_In_ VMM_HANDLE H)
{
    ObContainer_SetOb(H->vmm.pObCMapPhysMem, NULL);
}

// ----------------------------------------------------------------------------
// USER FUNCTIONALITY BELOW:
//
// The user functionality is responsible for creating the user map consisting
// of non-built-in users and also for retrieving account names for SIDs - both
// well known and system-specific.
// ----------------------------------------------------------------------------

/*
* Retrieve the account name of the user account given a SID.
* NB! Names for well known SIDs will be given in the language of the system
* running MemProcFS and not in the name of the analyzed system.
* -- H
* -- pSID
* -- uszName
* -- cbuName
* -- fAccountWellKnown
* -- return
*/
_Success_(return)
BOOL VmmWinUser_GetName(_In_ VMM_HANDLE H, _In_opt_ PSID pSID, _Out_writes_(cbuName) LPSTR uszName, _In_ DWORD cbuName, _Out_opt_ PBOOL pfAccountWellKnown)
{
    BOOL f;
    SID_NAME_USE eUse;
    DWORD i, cszNameBuffer = MAX_PATH, cszDomainBuffer = MAX_PATH, dwHashSID;
    CHAR szNameBuffer[MAX_PATH+1], szDomainBuffer[MAX_PATH+1];
    LPSTR szSID = NULL;
    PVMMOB_MAP_USER pObUser = NULL;
    if(!pSID) { return FALSE; }
    if(pfAccountWellKnown) { *pfAccountWellKnown = FALSE; }
    // 1: Try lookup from well known database
    if(!ConvertSidToStringSidA(pSID, &szSID)) { return FALSE; }
    f = InfoDB_SidToUser_Wellknown(H, szSID, szNameBuffer, &cszNameBuffer, szDomainBuffer, &cszDomainBuffer);
    dwHashSID = CharUtil_Hash32A(szSID, FALSE);
    LocalFree(szSID);
    szSID = NULL;
    if(f) {
        if(pfAccountWellKnown) { *pfAccountWellKnown = TRUE; }
        return CharUtil_AtoU(szNameBuffer, -1, (PBYTE)uszName, cbuName, NULL, NULL, CHARUTIL_FLAG_TRUNCATE | CHARUTIL_FLAG_STR_BUFONLY);
    }
    // 1: Try lookup name from User Map
    if(VmmMap_GetUser(H, &pObUser)) {
        for(i = 0; i < pObUser->cMap; i++) {
            if(dwHashSID != pObUser->pMap[i].dwHashSID) { continue; }
            // user entry located
            CharUtil_UtoU(pObUser->pMap[i].uszText, -1, (PBYTE)uszName, cbuName, NULL, NULL, CHARUTIL_FLAG_TRUNCATE_ONFAIL_NULLSTR | CHARUTIL_FLAG_STR_BUFONLY);
            Ob_DECREF(pObUser);
            return TRUE;
        }
        Ob_DECREF_NULL(&pObUser);
    }
    // 2: Try lookup name from Well Known SID
    f = LookupAccountSidA(NULL, pSID, szNameBuffer, &cszNameBuffer, szDomainBuffer, &cszDomainBuffer, &eUse);
    if(f && (cszDomainBuffer != MAX_PATH)) {
        f = CharUtil_AtoU(szNameBuffer, -1, (PBYTE)uszName, cbuName, NULL, NULL, CHARUTIL_FLAG_TRUNCATE | CHARUTIL_FLAG_STR_BUFONLY);
        if(pfAccountWellKnown) { *pfAccountWellKnown = f; }
        return f;
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
    PVMM_MAP_USERENTRY pe;
    DWORD i;
    for(i = 0; i < pOb->cMap; i++) {
        if((pe = pOb->pMap + i)) {
            LocalFree(pe->pSID);
        }
    }
    LocalFree(pOb->pbMultiText);
}

/*
* Fill the pmOb map with user information grabbed from the SOFTWARE hive profiles:
* HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList
* -- H
* -- pmOb
*/
VOID VmmWinUser_Initialize_DoWork_ProfileReg(_In_ VMM_HANDLE H, _In_ POB_MAP pmOb)
{
    BOOL f;
    DWORD dwType, cbBuffer;
    BYTE pbBuffer[MAX_PATH];
    BYTE szBufferPath[MAX_PATH];
    POB_REGISTRY_HIVE pObHive = NULL;
    POB_REGISTRY_KEY pObKeyParent, pObKey = NULL;
    POB_REGISTRY_VALUE pObValue = NULL;
    POB_MAP pmObKeys;
    VMM_REGISTRY_KEY_INFO KeyInfo;
    VMM_MAP_USERENTRY e;
    if(VmmWinReg_KeyHiveGetByFullPath(H, "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList", &pObHive, &pObKeyParent)) {
        pmObKeys = VmmWinReg_KeyList(H, pObHive, pObKeyParent);
        while(TRUE) {
            if(pObKey) { Ob_DECREF_NULL(&pObKey); }
            if(!(pObKey = ObMap_Pop(pmObKeys))) { break; }
            VmmWinReg_KeyInfo(pObHive, pObKey, &KeyInfo);
            if(_strnicmp(KeyInfo.uszName, "S-1-5-21-", 9)) { continue; }
            e.dwHashSID = CharUtil_Hash32A(KeyInfo.uszName, FALSE);
            if(ObMap_ExistsKey(pmOb, e.dwHashSID)) { continue; }
            f = (pObValue = VmmWinReg_KeyValueGetByName(H, pObHive, pObKey, "ProfileImagePath")) &&
                VmmWinReg_ValueQuery4(H, pObHive, pObValue, &dwType, pbBuffer, sizeof(pbBuffer), &cbBuffer) &&
                ((dwType == REG_SZ) || (dwType == REG_EXPAND_SZ)) &&
                CharUtil_WtoU((LPWSTR)pbBuffer, cbBuffer / 2, szBufferPath, sizeof(szBufferPath), NULL, NULL, CHARUTIL_FLAG_TRUNCATE | CHARUTIL_FLAG_STR_BUFONLY);
            Ob_DECREF_NULL(&pObValue);
            if(!f) { continue; }
            e.cbuText = 0;
            e.pSID = NULL;
            if(!CharUtil_UtoU(KeyInfo.uszName, -1, NULL, 0, &e.szSID, NULL, CHARUTIL_FLAG_ALLOC)) {
                continue;
            }
            if(!CharUtil_UtoU(szBufferPath, -1, NULL, 0, &e.uszText, NULL, CHARUTIL_FLAG_ALLOC)) {
                LocalFree(e.szSID);
                continue;
            }
            e.vaRegHive = 0;
            ObMap_PushCopy(pmOb, e.dwHashSID, &e, sizeof(VMM_MAP_USERENTRY));
        }
        Ob_DECREF(pmObKeys);
        Ob_DECREF(pObKeyParent);
        Ob_DECREF(pObHive);
    }
}

/*
* Fill the pmOb map with user information by walking potential user hives.
* -- H
* -- pmOb
*/
VOID VmmWinUser_Initialize_DoWork_UserHive(_In_ VMM_HANDLE H, _In_ POB_MAP pmOb)
{
    BOOL f;
    VMM_MAP_USERENTRY e;
    DWORD i, dwType, cbBuffer;
    BYTE pbBuffer[MAX_PATH];
    CHAR szBufferUser[MAX_PATH], szBufferSymlink[MAX_PATH];
    LPSTR szHiveUser, szHiveNtdat, szSymlinkUser, szSymlinkSid = "";
    POB_REGISTRY_HIVE pObHive = NULL;
    while((pObHive = VmmWinReg_HiveGetNext(H, pObHive))) {
        szBufferUser[0] = 0;
        ZeroMemory(&e, sizeof(VMM_MAP_USERENTRY));
        szHiveUser = StrStrIA(pObHive->uszName, "-USER_S-");
        szHiveNtdat = StrStrIA(pObHive->uszName, "-ntuserdat-");
        if(!szHiveNtdat && StrStrIA(pObHive->uszName, "_ntuser.dat")) {
            szHiveNtdat = StrStrIA(pObHive->uszName, "-unknown-");
        }
        if(!szHiveNtdat && !szHiveUser) { continue; }
        if(!szHiveUser && !StrStrIA(szHiveNtdat, "-unknown")) { continue; }
        if(szHiveUser && ((strlen(szHiveUser) < 20) || StrStrIA(szHiveUser, "Classes"))) { continue; }
        // get username
        f = VmmWinReg_ValueQuery1(H, pObHive, "ROOT\\Volatile Environment\\USERNAME", &dwType, NULL, pbBuffer, sizeof(pbBuffer) - 2, &cbBuffer, 0) &&
            (dwType == REG_SZ) &&
            CharUtil_WtoU((LPWSTR)pbBuffer, cbBuffer / 2, szBufferUser, sizeof(szBufferUser), NULL, NULL, CHARUTIL_FLAG_TRUNCATE | CHARUTIL_FLAG_STR_BUFONLY);
        if(!f && (H->vmm.kernel.dwVersionBuild > 2600)) { continue; }  // allow missing USERNAME only if WinXP
        // get sid
        if(szHiveUser) {
            ConvertStringSidToSidA(szHiveUser + 6, &e.pSID);
        }
        if(!e.pSID) {
            i = 0;
            f = VmmWinReg_ValueQuery1(H, pObHive, "ROOT\\Software\\Classes\\SymbolicLinkValue", &dwType, NULL, (PBYTE)pbBuffer, sizeof(pbBuffer) - 2, &cbBuffer, 0) &&
                (dwType == REG_LINK) &&
                CharUtil_WtoU((LPWSTR)pbBuffer, cbBuffer / 2, szBufferSymlink, sizeof(szBufferSymlink), NULL, NULL, CHARUTIL_FLAG_TRUNCATE | CHARUTIL_FLAG_STR_BUFONLY) &&
                (szSymlinkSid = strstr(szBufferSymlink, "\\S-"));
            if(!f || (strlen(szSymlinkSid) < 20)) { continue; }
            while(szSymlinkSid[i] && (szSymlinkSid[i] != '_') && ++i);
            szSymlinkSid[i] = 0;
            if(!ConvertStringSidToSidA(szSymlinkSid + 1, &e.pSID) || !e.pSID) { continue; }
        }
        // get username - WinXP only
        if(!szBufferUser[0] && (H->vmm.kernel.dwVersionBuild <= 2600)) {
            i = 0;
            szSymlinkUser = szBufferSymlink + 10;
            while(szSymlinkUser[i] && (szSymlinkUser[i] != '\\') && ++i);
            if(i == 0) { continue; }
            szSymlinkUser[i] = 0;
            CharUtil_UtoU(szSymlinkUser, -1, szBufferUser, sizeof(szBufferUser), NULL, NULL, CHARUTIL_FLAG_TRUNCATE | CHARUTIL_FLAG_STR_BUFONLY);
        }
        if(!szBufferUser[0]) { continue; }
        // get length and hash of sid string
        e.vaRegHive = pObHive->vaCMHIVE;
        if(!ConvertSidToStringSidA(e.pSID, &e.szSID) || !e.szSID) {
            LocalFree(e.pSID);
            continue;
        }
        e.dwHashSID = CharUtil_Hash32A(e.szSID, FALSE);
        if(ObMap_ExistsKey(pmOb, e.dwHashSID)) {
            LocalFree(e.pSID);
            continue;
        }
        if(!CharUtil_UtoU(szBufferUser, -1, NULL, 0, &e.uszText, NULL, CHARUTIL_FLAG_ALLOC)) {
            LocalFree(e.pSID);
            continue;
        }
        ObMap_PushCopy(pmOb, e.dwHashSID, &e, sizeof(VMM_MAP_USERENTRY));
    }
}

/*
* Create a user map and assign it to the ctxVmm global context upon success.
* NB! function must be called in single-threaded context.
* CALLER DECREF: return
* -- H
* -- return
*/
PVMMOB_MAP_USER VmmWinUser_Initialize_DoWork(_In_ VMM_HANDLE H)
{
    DWORD i;
    POB_MAP pmOb = NULL;
    POB_STRMAP psmOb = NULL;
    PVMM_MAP_USERENTRY pe, peDst, peSrc;
    PVMMOB_MAP_USER pObMapUser = NULL;
    if(!(pmOb = ObMap_New(H, OB_MAP_FLAGS_OBJECT_LOCALFREE))) { goto fail; }
    // 1: user hive enumeration (from user registry hives)
    VmmWinUser_Initialize_DoWork_UserHive(H, pmOb);
    // 2: user profile enumeration (from software hive)
    //    this is quite performance intense (and will slow down start-up) ->
    //    avoid loading users using this method for now (unless command line forensic mode).
    if(H->cfg.tpForensicMode) {
        VmmWinUser_Initialize_DoWork_ProfileReg(H, pmOb);
    }
    // 3: create user map and assign data
    if(!(psmOb = ObStrMap_New(H, OB_STRMAP_FLAGS_CASE_INSENSITIVE))) { goto fail; }
    if(!(pObMapUser = Ob_AllocEx(H, OB_TAG_MAP_USER, LMEM_ZEROINIT, sizeof(VMMOB_MAP_USER) + ObMap_Size(pmOb) * sizeof(VMM_MAP_USERENTRY), VmmWinUser_CloseObCallback, NULL))) { goto fail; }
    pObMapUser->cMap = ObMap_Size(pmOb);
    for(i = 0; i < pObMapUser->cMap; i++) {
        peSrc = ObMap_GetByIndex(pmOb, i);
        peDst = pObMapUser->pMap + i;
        peDst->dwHashSID = peSrc->dwHashSID;
        peDst->vaRegHive = peSrc->vaRegHive;
        peDst->pSID = peSrc->pSID; peSrc->pSID = NULL;
        // strmap below:
        ObStrMap_PushPtrUU(psmOb, peSrc->szSID, &peDst->szSID, NULL);
        ObStrMap_PushPtrUU(psmOb, peSrc->uszText, &peDst->uszText, &peDst->cbuText);
    }
    ObStrMap_FinalizeAllocU_DECREF_NULL(&psmOb, &pObMapUser->pbMultiText, &pObMapUser->cbMultiText);
    // fall-through to cleanup & return
fail:
    while((pe = ObMap_Pop(pmOb))) {
        LocalFree(pe->uszText);
        LocalFree(pe->szSID);
        LocalFree(pe->pSID);
        LocalFree(pe);
    }
    Ob_DECREF(pmOb);
    Ob_DECREF(psmOb);
    return pObMapUser;
}

/*
* Create a user map and assign to the global context upon success.
* CALLER DECREF: return
* -- H
* -- return
*/
PVMMOB_MAP_USER VmmWinUser_Initialize(_In_ VMM_HANDLE H)
{
    PVMMOB_MAP_USER pObUser;
    if((pObUser = ObContainer_GetOb(H->vmm.pObCMapUser))) { return pObUser; }
    EnterCriticalSection(&H->vmm.LockUpdateMap);
    if((pObUser = ObContainer_GetOb(H->vmm.pObCMapUser))) {
        LeaveCriticalSection(&H->vmm.LockUpdateMap);
        return pObUser;
    }
    pObUser = VmmWinUser_Initialize_DoWork(H);
    if(!pObUser) {
        pObUser = Ob_AllocEx(H, OB_TAG_MAP_USER, LMEM_ZEROINIT, sizeof(VMMOB_MAP_USER), NULL, NULL);
    }
    ObContainer_SetOb(H->vmm.pObCMapUser, pObUser);
    LeaveCriticalSection(&H->vmm.LockUpdateMap);
    return pObUser;
}

/*
* Refresh the user map.
* -- H
*/
VOID VmmWinUser_Refresh(_In_ VMM_HANDLE H)
{
    ObContainer_SetOb(H->vmm.pObCMapUser, NULL);
}



// ----------------------------------------------------------------------------
// WINDOWS EPROCESS WALKING FUNCTIONALITY FOR 64/32 BIT BELOW:
// ----------------------------------------------------------------------------

#define VMMPROC_EPROCESS64_MAX_SIZE       0x800
#define VMMPROC_EPROCESS32_MAX_SIZE       0x480

VOID VmmWinProcess_OffsetLocator_Print(_In_ VMM_HANDLE H)
{
    PVMM_OFFSET_EPROCESS po = &H->vmm.offset.EPROCESS;
    VmmLog(H, MID_PROCESS, LOGLEVEL_DEBUG, "OK: %s",
        (po->fValid ? "TRUE" : "FALSE"));
    VmmLog(H, MID_PROCESS, LOGLEVEL_DEBUG, "    PID:  %03x PPID: %03x STAT: %03x DTB:  %03x DTBU: %03x NAME: %03x PEB: %03x",
        po->PID, po->PPID, po->State, po->DTB, po->DTB_User, po->Name, po->PEB);
    VmmLog(H, MID_PROCESS, LOGLEVEL_DEBUG, "    FLnk: %03x BLnk: %03x oMax: %03x SeAu: %03x VadR: %03x ObjT: %03x WoW: %03x",
        po->FLink, po->BLink, po->cbMaxOffset, po->SeAuditProcessCreationInfo, po->VadRoot, po->ObjectTable, po->Wow64Process);
}

VOID VmmWinProcess_OffsetLocator_SetMaxOffset(_In_ VMM_HANDLE H)
{
    PVMM_OFFSET_EPROCESS po = &H->vmm.offset.EPROCESS;
    WORD o;
    o = max(po->opt.CreateTime, po->opt.ExitTime);
    o = max(max(o, po->State), max(po->DTB, po->DTB_User));
    o = max(max(o, po->Name), max(po->PID, po->PPID));
    o = max(max(o, po->PEB), max(po->FLink, po->BLink));
    o = max(max(o, po->SeAuditProcessCreationInfo), max(po->VadRoot, po->ObjectTable));
    po->cbMaxOffset = o + 0x80;
}

/*
* Fallback solution to use debug symbols to locate offsets within the EPROCESS struct.
* This is more resilient - but also add a slow dependency on the symbol server so only
* use this as a fallback for now.
*/
VOID VmmWinProcess_OffsetLocatorSYMSERV(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pSystemProcess)
{
    PVMM_OFFSET_EPROCESS po = &H->vmm.offset.EPROCESS;
    InfoDB_Initialize(H);
    PDB_Initialize(H, NULL, FALSE);
    PDB_GetTypeChildOffsetShort(H, PDB_HANDLE_KERNEL, "_DISPATCHER_HEADER", "SignalState", &po->State);
    PDB_GetTypeChildOffsetShort(H, PDB_HANDLE_KERNEL, "_KPROCESS", "DirectoryTableBase", &po->DTB);
    PDB_GetTypeChildOffsetShort(H, PDB_HANDLE_KERNEL, "_KPROCESS", "UserDirectoryTableBase", &po->DTB_User);
    PDB_GetTypeChildOffsetShort(H, PDB_HANDLE_KERNEL, "_EPROCESS", "ImageFileName", &po->Name);
    PDB_GetTypeChildOffsetShort(H, PDB_HANDLE_KERNEL, "_EPROCESS", "UniqueProcessId", &po->PID);
    PDB_GetTypeChildOffsetShort(H, PDB_HANDLE_KERNEL, "_EPROCESS", "InheritedFromUniqueProcessId", &po->PPID);
    PDB_GetTypeChildOffsetShort(H, PDB_HANDLE_KERNEL, "_EPROCESS", "ActiveProcessLinks", &po->FLink);
    po->BLink = po->FLink + H->vmm.f32 ? 4 : 8;
    PDB_GetTypeChildOffsetShort(H, PDB_HANDLE_KERNEL, "_EPROCESS", "Peb", &po->PEB);
    PDB_GetTypeChildOffsetShort(H, PDB_HANDLE_KERNEL, "_EPROCESS", "SeAuditProcessCreationInfo", &po->SeAuditProcessCreationInfo);
    PDB_GetTypeChildOffsetShort(H, PDB_HANDLE_KERNEL, "_EPROCESS", "VadRoot", &po->VadRoot);
    PDB_GetTypeChildOffsetShort(H, PDB_HANDLE_KERNEL, "_EPROCESS", "ObjectTable", &po->ObjectTable);
    if(!H->vmm.f32) {
        if(po->Name < po->PEB) {
            po->f64VistaOr7 = TRUE;
            po->Wow64Process = po->Name + 0x40;     // Vista, Win7
        } else {
            po->Wow64Process = po->PEB + 0x30;      // Win8, Win10
        }
    }
    PDB_GetTypeSizeShort(H, PDB_HANDLE_KERNEL, "_EPROCESS", &po->cbMaxOffset);
    po->fValid = po->State && po->DTB && po->Name && po->PPID && po->FLink && po->PEB && po->VadRoot && po->SeAuditProcessCreationInfo && po->ObjectTable;
}

/*
* Very ugly hack that tries to locate some offsets required within the EPROCESS struct.
*/
VOID VmmWinProcess_OffsetLocator64(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pSystemProcess)
{
    PVMM_OFFSET_EPROCESS po = &H->vmm.offset.EPROCESS;
    BOOL f;
    WORD i, j, cLoopProtect;
    QWORD va1, vaPEB, paPEB, vaP, oP;
    BYTE pbSYSTEM[VMMPROC_EPROCESS64_MAX_SIZE], pbSMSS[VMMPROC_EPROCESS64_MAX_SIZE], pb1[VMMPROC_EPROCESS64_MAX_SIZE], pbPage[0x1000];
    QWORD paMax, paDTB_0, paDTB_1;
    POB_SET psObOff = NULL, psObVa = NULL;
    ZeroMemory(po, sizeof(VMM_OFFSET_EPROCESS));
    if(!VmmRead(H, pSystemProcess, pSystemProcess->win.EPROCESS.va, pbSYSTEM, VMMPROC_EPROCESS64_MAX_SIZE)) { return; }
    VmmLogHexAsciiEx(H, MID_PROCESS, LOGLEVEL_DEBUG, pbSYSTEM, VMMPROC_EPROCESS64_MAX_SIZE, 0, "SYSTEM DTB: %016llx EPROCESS: %016llx", pSystemProcess->paDTB, pSystemProcess->win.EPROCESS.va);
    // find offset State (static for now)
    if(*(PDWORD)(pbSYSTEM + 0x04)) { return; }
    po->State = 0x04;
    // find offset PML4 (static for now)
    if(0xffff800000000000 & *(PQWORD)(pbSYSTEM + 0x28)) { return; }
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
    // find offset for PID, FLinkAll, BLink (assumed to be following eachother)
    for(i = 0, f = FALSE; i < VMMPROC_EPROCESS64_MAX_SIZE - 8; i += 8) {
        if(*(PQWORD)(pbSYSTEM + i) == 4) {
            // PID = correct, this is a candidate
            if(0xffff000000000000 != (0xffff000000000003 & *(PQWORD)(pbSYSTEM + i + 8))) { continue; }    // FLinkAll not valid kernel pointer
            va1 = *(PQWORD)(pbSYSTEM + i + 8) - i - 8;
            f = VmmRead(H, pSystemProcess, va1, pb1, VMMPROC_EPROCESS64_MAX_SIZE);
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
            f = VmmRead(H, pSystemProcess, va1, pbSMSS, VMMPROC_EPROCESS64_MAX_SIZE) &&
                (*(PQWORD)(pbSMSS + po->Name) == 0x6578652e73736d73);
            if(f) { break; }
        }
        if(!f) { return; }
        VmmLogHexAsciiEx(H, MID_PROCESS, LOGLEVEL_DEBUG, pbSMSS, VMMPROC_EPROCESS64_MAX_SIZE, 0, "EPROCESS smss.exe BELOW:");
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
                if(!VmmVirt2PhysEx(H, *(PQWORD)(pbSMSS + po->DTB), TRUE, vaPEB, &paPEB)) { continue; }
                if(!VmmReadPage(H, NULL, paPEB, pbPage)) { continue; }
                if(*(PWORD)pbPage == 0x5a4d) { continue; }  // MZ header -> likely entry point or something not PEB ...
                po->PEB = i;
                f = TRUE;
                break;
            }
            if(f) { break; }
            // failed locating PEB (paging?) -> try next process in EPROCESS list.
            va1 = *(PQWORD)(pbSMSS + po->FLink) - po->FLink;
            if(!VmmRead(H, pSystemProcess, va1, pbSMSS, VMMPROC_EPROCESS64_MAX_SIZE)) { return; }
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
        if(!(psObVa = ObSet_New(H))) { goto fail; }
        if(!(psObOff = ObSet_New(H))) { goto fail; }
        // ObjectTable candidate pointers
        for(i = po->Name - 0x0e0; i < po->Name - 0x020; i += 8) {
            vaP = *(PQWORD)(pbSYSTEM + i);
            if(VMM_KADDR64_16(vaP) && !ObSet_Exists(psObVa, vaP - 0x10)) {
                ObSet_Push(psObOff, (i << 16) | 1);
                ObSet_Push(psObVa, vaP - 0x10);
            }
        }
        // SeAuditProcessCreationInfo candidate pointers by looking at SMSS.
        // Offset is located between PEB+0x058 and PEB+0x070 as observed so far.
        // Look at some extra offsets just in case for the future.
        for(i = 0x058 + po->PEB; i < 0x090 + po->PEB; i += 8) {
            vaP = *(PQWORD)(pbSMSS + i);
            if(VMM_KADDR64_8(vaP) && !ObSet_Exists(psObVa, vaP)) {
                ObSet_Push(psObOff, (i << 16) | 2);
                ObSet_Push(psObVa, vaP);
            }
        }
        // prefetch result into cache
        VmmCachePrefetchPages3(H, pSystemProcess, psObVa, 0x40, 0);
        // interpret result
        while(ObSet_Size(psObVa)) {
            oP = ObSet_Pop(psObOff);
            vaP = ObSet_Pop(psObVa);
            if(!VmmRead2(H, pSystemProcess, vaP, pbPage, 0x40, VMM_FLAG_FORCECACHE_READ)) {
                if(((vaP + 0x10) & 0xfff) || !VmmRead2(H, pSystemProcess, vaP + 0x10, pbPage + 0x10, 0x30, VMM_FLAG_FORCECACHE_READ)) {
                    continue;
                }
            }
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
    // Value may be the 'VadHint' on some systems; scan back 0x40 to find any
    // identical match (which will be assumed to be vadroot).
    {
        for(i = 0x140 + po->Name; i < 0x7f0; i += 8) {
            f = VMM_KADDR64(*(PQWORD)(pbSYSTEM + i)) && ((*(PDWORD)(pbSYSTEM + i - 4) == 0x00000103) || (*(PDWORD)(pbSYSTEM + i - 12) == 0x00000103));
            if(f) { break; }
        }
        if(!f) { goto fail; }
        po->VadRoot = i;
        // Scanback 0x40 (in case of 'VadHint' false positive.
        for(i = po->VadRoot - 8; i > po->VadRoot - 0x40; i -= 8) {
            if(*(PQWORD)(pbSYSTEM + i) == *(PQWORD)(pbSYSTEM + po->VadRoot)) {
                po->VadRoot = i;
                break;
            }
        }
    }
    // find "optional" offset for user cr3/pml4 (post meltdown only)
    // System have an entry pointing to a shadow PML4 which has empty user part
    // smss.exe do not have an entry since it's running as admin ...
    {
        paMax = H->dev.paMax;
        for(i = 0x240; i < VMMPROC_EPROCESS64_MAX_SIZE - 8; i += 8) {
            paDTB_0 = *(PQWORD)(pbSYSTEM + i);
            paDTB_1 = *(PQWORD)(pbSMSS + i);
            f = !(paDTB_1 & ~1) &&
                paDTB_0 &&
                !(paDTB_0 & 0xffe) &&
                (paDTB_0 < paMax) &&
                VmmReadPage(H, NULL, (paDTB_0 & ~0xfff), pbPage) &&
                !memcmp(pbPage, H->ZERO_PAGE, 0x800) &&
                VmmTlbPageTableVerify(H, pbPage, (paDTB_0 & ~0xfff), TRUE);
            if(f) {
                po->DTB_User = i;
                break;
            }
        }
    }
    VmmWinProcess_OffsetLocator_SetMaxOffset(H);
    po->fValid = TRUE;
fail:
    Ob_DECREF(psObVa);
    Ob_DECREF(psObOff);
}

/*
* Post-process new process in the "new" process table before they are comitted VmmProcessCreateFinish()
* At this moment "only" the full path and name is retrieved by using 'SeAuditProcessCreationInfo'.
* -- H
* -- pSystemProcess
*/
VOID VmmWinProcess_Enumerate_PostProcessing(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pSystemProcess)
{
    BOOL f32 = H->vmm.f32;
    DWORD i;
    LPSTR uszPathKernel;
    POB_SET pObPrefetchAddr = NULL;
    PVMM_PROCESS pObProcess = NULL;
    PVMMOB_PROCESS_TABLE ptObCurrent = NULL, ptObNew = NULL;
    PVMMOB_PROCESS_PERSISTENT pProcPers;
    if(!(pObPrefetchAddr = ObSet_New(H))) { goto fail; }
    if(!(ptObCurrent = (PVMMOB_PROCESS_TABLE)ObContainer_GetOb(H->vmm.pObCPROC))) { goto fail; }
    if(!(ptObNew = (PVMMOB_PROCESS_TABLE)ObContainer_GetOb(ptObCurrent->pObCNewPROC))) { goto fail; }
    // 1: Iterate to gather memory locations of "SeAuditProcessCreationInfo" / "kernel path" for new processes
    while((pObProcess = VmmProcessGetNextEx(H, ptObNew, pObProcess, VMM_FLAG_PROCESS_SHOW_TERMINATED))) {
        if(!pObProcess->pObPersistent->fIsPostProcessingComplete) {
            ObSet_Push_PageAlign(pObPrefetchAddr, VMM_EPROCESS_PTR(f32, pObProcess, H->vmm.offset.EPROCESS.SeAuditProcessCreationInfo), 540);
        }
    }
    if(0 == ObSet_Size(pObPrefetchAddr)) { goto fail; }
    VmmCachePrefetchPages(H, pSystemProcess, pObPrefetchAddr, 0);
    // 2: Fetch "kernel path" and set "long name" for new processes.
    while((pObProcess = VmmProcessGetNextEx(H, ptObNew, pObProcess, VMM_FLAG_PROCESS_SHOW_TERMINATED))) {
        pProcPers = pObProcess->pObPersistent;
        if(!pProcPers->fIsPostProcessingComplete) {
            pProcPers->fIsPostProcessingComplete = TRUE;
            uszPathKernel = NULL;
            if(VmmReadAllocUnicodeStringAsUTF8(H, pSystemProcess, f32, VMM_FLAG_FORCECACHE_READ, VMM_EPROCESS_PTR(f32, pObProcess, H->vmm.offset.EPROCESS.SeAuditProcessCreationInfo), 0x400, &uszPathKernel, NULL)) {
                if(!CharUtil_StrStartsWith(uszPathKernel, "\\Device\\", TRUE)) {
                    LocalFree(uszPathKernel); uszPathKernel = NULL;
                }
            }
            if(!uszPathKernel) {
                // Fail - use EPROCESS name
                if(!(uszPathKernel = LocalAlloc(LMEM_ZEROINIT, 16))) { continue; }
                for(i = 0; i < 15; i++) {
                    uszPathKernel[i] = pObProcess->szName[i];
                }
            }
            pProcPers->uszPathKernel = uszPathKernel;
            pProcPers->cuszPathKernel = (WORD)strlen(pProcPers->uszPathKernel);
            // locate FullName by skipping to last \ character.
            pProcPers->uszNameLong = (LPSTR)CharUtil_PathSplitLast(pProcPers->uszPathKernel);
            pProcPers->cuszNameLong = (WORD)strlen(pProcPers->uszNameLong);
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
    BOOL fNoLinkEPROCESS;
    DWORD cNewProcessCollision;
    POB_SET pObSetPrefetchDTB;
} VMMWIN_ENUMERATE_EPROCESS_CONTEXT, *PVMMWIN_ENUMERATE_EPROCESS_CONTEXT;

VOID VmmWinProcess_Enum64_Pre(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess, _In_opt_ PVMMWIN_ENUMERATE_EPROCESS_CONTEXT ctx, _In_ QWORD va, _In_ PBYTE pb, _In_ DWORD cb, _In_ QWORD vaFLink, _In_ QWORD vaBLink, _In_ POB_SET pVSetAddress, _Inout_ PBOOL pfValidEntry, _Inout_ PBOOL pfValidFLink, _Inout_ PBOOL pfValidBLink)
{
    if(!ctx || !VMM_KADDR64_16(va)) { return; }
    ObSet_Push(ctx->pObSetPrefetchDTB, *(PQWORD)(pb + H->vmm.offset.EPROCESS.DTB) & ~0xfff);
    *pfValidFLink = VMM_KADDR64_8(vaFLink);
    *pfValidBLink = VMM_KADDR64_8(vaBLink);
    *pfValidEntry = *pfValidFLink || *pfValidBLink;
}

/*
* Process enumeration callback function:
* NB! REQUIRE SINGLE THREAD: [H->vmm.LockMaster]
* -- H
* -- pSystemProcess
* -- ctx
* -- va
* -- pb
* -- cb
*/
VOID VmmWinProcess_Enum64_Post(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pSystemProcess, _In_opt_ PVMMWIN_ENUMERATE_EPROCESS_CONTEXT ctx, _In_ QWORD va, _In_ PBYTE pb, _In_ DWORD cb)
{
    PVMM_OFFSET_EPROCESS po = &H->vmm.offset.EPROCESS;
    PQWORD ppaDTB_Kernel, ppaDTB_User, pqwPEB, pqwWow64Process;
    PDWORD pdwState, pdwPID, pdwPPID;
    LPSTR szName;
    BOOL fUser;
    PVMM_PROCESS pObProcess = NULL;
    if(!ctx || !VMM_KADDR64_16(va)) { return; }
    pdwState = (PDWORD)(pb + po->State);
    pdwPID = (PDWORD)(pb + po->PID);
    pdwPPID = (PDWORD)(pb + po->PPID);
    ppaDTB_Kernel = (PQWORD)(pb + po->DTB);
    ppaDTB_User = (PQWORD)(pb + po->DTB_User);
    szName = (LPSTR)(pb + po->Name);
    pqwPEB = (PQWORD)(pb + po->PEB);
    pqwWow64Process = (PQWORD)(pb + po->Wow64Process);
    if(ctx->pObSetPrefetchDTB) {    // prefetch any physical pages in ctx->pObSetPrefetchDTB on 1st run only
        VmmCachePrefetchPages(H, NULL, ctx->pObSetPrefetchDTB, 0);
        Ob_DECREF_NULL(&ctx->pObSetPrefetchDTB);
    }
    if(*pdwPID && (*pdwPID < 0x10000000) && *(PQWORD)szName) {
        // treat csrss.exe as 'kernel' due to win32k mapping missing in System Process _AND_ treat MemCompression as 'user'
        fUser =
            !((*pdwPID == 4) || ((*pdwState == 0) && (*pqwPEB == 0)) || (*(PQWORD)szName == 0x78652e7373727363)|| !((0x879ad18c8c9e8c93 ^ *(PQWORD)szName) + 1)) ||  // csrss.exe
            ((*(PQWORD)(szName + 0x00) == 0x72706d6f436d654d) && (*(PDWORD)(szName + 0x08) == 0x69737365));                                                          // MemCompression "process"
        pObProcess = VmmProcessCreateEntry(
            H,
            ctx->fTotalRefresh,
            *pdwPID,
            *pdwPPID,
            *pdwState,
            *ppaDTB_Kernel & ~0xfff,
            po->DTB_User ? (*ppaDTB_User & ~0xfff) : 0,
            szName,
            fUser,
            pb,
            cb);
        if(!pObProcess) {
            VmmLog(H, MID_PROCESS, LOGLEVEL_4_VERBOSE, "Process Creation Fail: PID '%i' already exists?", *pdwPID);
            if(++ctx->cNewProcessCollision >= 8) {
                return;
            }
        }
    }
    if(pObProcess) {
        pObProcess->win.EPROCESS.va = va;
        pObProcess->win.EPROCESS.fNoLink = ctx->fNoLinkEPROCESS;
        // PEB
        if(*pqwPEB & 0xfff) {
            VmmLog(H, MID_PROCESS, LOGLEVEL_4_VERBOSE, "Bad PEB alignment for PID: '%i' (0x%016llx)", *pdwPID, *pqwPEB);
        } else {
            pObProcess->win.vaPEB = *pqwPEB;
        }
        // WoW64 and PEB32
        if(*pqwWow64Process) {
            pObProcess->win.fWow64 = TRUE;
            if(*pqwWow64Process & 0xffffffff00000fff) {
                pObProcess->win.vaPEB32 = (DWORD)*pqwPEB + (po->f64VistaOr7 ? -0x1000 : +0x1000);
            } else {
                pObProcess->win.vaPEB32 = (DWORD)*pqwWow64Process;
            }
        }
    } else {
        szName[14] = 0; // in case of bad string data ...
    }
    VmmLog(H, MID_PROCESS, LOGLEVEL_5_DEBUG, "%04i (%s) %08x %012llx %016llx %012llx %s",
        ctx->cProc,
        !pObProcess ? "skip" : (pObProcess->dwState ? "exit" : "list"),
        *pdwPID,
        *ppaDTB_Kernel,
        va,
        *pqwPEB,
        szName);
    Ob_DECREF_NULL(&pObProcess);
    ctx->cProc++;
}

/*
* Process an optional set of no-link eprocess into the process list which is
* undergoing a fetch.
*/
VOID VmmWinProcess_Enum_AddNoLink(
    _In_ VMM_HANDLE H,
    _In_ PVMM_PROCESS pSystemProcess,
    _In_opt_ POB_SET psvaNoLinkEPROCESS,
    _In_ PVMMWIN_ENUMERATE_EPROCESS_CONTEXT ctx,
    _In_ VOID(*pfnCallback_Post)(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess, _In_opt_ PVOID ctx, _In_ QWORD va, _In_reads_(cb) PBYTE pb, _In_ DWORD cb)
) {
    QWORD va;
    BYTE pb[0x1000];
    DWORD cb = H->vmm.offset.EPROCESS.cbMaxOffset;
    ctx->fNoLinkEPROCESS = TRUE;
    while((va = ObSet_Pop(psvaNoLinkEPROCESS))) {
        if(VmmRead(H, pSystemProcess, va, pb, cb)) {
            pfnCallback_Post(H, pSystemProcess, ctx, va, pb, cb);
        }
    }
}

/*
* Try walk the EPROCESS list in the Windows kernel to enumerate processes into
* the VMM/PROC file system. 64-bit version.
* NB! This may be done to refresh an existing PID cache hence migration code.
* NB! REQUIRE SINGLE THREAD : [H->vmm.LockMaster]
* -- H
* -- pSystemProcess
* -- fTotalRefresh
* -- psvaNoLinkEPROCESS = optional list of non-linked EPROCESS va's.
* -- return
*/
BOOL VmmWinProcess_Enum64(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pSystemProcess, _In_ BOOL fTotalRefresh, _In_opt_ POB_SET psvaNoLinkEPROCESS)
{
    PVMM_OFFSET_EPROCESS po = &H->vmm.offset.EPROCESS;
    VMMWIN_ENUMERATE_EPROCESS_CONTEXT ctx = { 0 };
    // retrieve offsets
    if(!po->fValid) {
        VmmWinProcess_OffsetLocator64(H, pSystemProcess);
        VmmWinProcess_OffsetLocator_Print(H);
        if(!po->fValid) {
            VmmLog(H, MID_PROCESS, LOGLEVEL_VERBOSE, "Unable to fuzz EPROCESS offsets - trying debug symbols");
            VmmWinProcess_OffsetLocatorSYMSERV(H, pSystemProcess);
            VmmWinProcess_OffsetLocator_Print(H);
        }
        if(!po->fValid) {
            VmmLog(H, MID_PROCESS, LOGLEVEL_CRITICAL, "Unable to locate EPROCESS offsets");
            return FALSE;
        }
    }
    VmmLog(H, MID_PROCESS, LOGLEVEL_DEBUG, "SYSTEM DTB: %016llx EPROCESS: %016llx", pSystemProcess->paDTB, pSystemProcess->win.EPROCESS.va);
    // set up context
    ctx.fTotalRefresh = fTotalRefresh;
    if(!(ctx.pObSetPrefetchDTB = ObSet_New(H))) { return FALSE; }
    // traverse EPROCESS linked list
    VmmLog(H, MID_PROCESS, LOGLEVEL_DEBUG, "   # STATE  PID      DTB          EPROCESS         PEB          NAME");
    VmmWin_ListTraversePrefetch(
        H,
        pSystemProcess,
        FALSE,
        &ctx,
        1,
        &pSystemProcess->win.EPROCESS.va,
        H->vmm.offset.EPROCESS.FLink,
        H->vmm.offset.EPROCESS.cbMaxOffset,
        (VMMWIN_LISTTRAVERSE_PRE_CB)VmmWinProcess_Enum64_Pre,
        (VMMWIN_LISTTRAVERSE_POST_CB)VmmWinProcess_Enum64_Post,
        H->vmm.pObCCachePrefetchEPROCESS);
    // add no-link entries (if any)
    VmmWinProcess_Enum_AddNoLink(
        H,
        pSystemProcess,
        psvaNoLinkEPROCESS,
        &ctx,
        (VOID(*)(VMM_HANDLE, PVMM_PROCESS, PVOID, QWORD, PBYTE, DWORD))VmmWinProcess_Enum64_Post);
    // set resulting prefetch cache
    Ob_DECREF_NULL(&ctx.pObSetPrefetchDTB);
    VmmWinProcess_Enumerate_PostProcessing(H, pSystemProcess);
    VmmProcessCreateFinish(H);
    return (ctx.cProc > 10);
}

/*
* Very ugly hack that tries to locate some offsets required withn the EPROCESS struct.
*/
VOID VmmWinProcess_OffsetLocator32(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pSystemProcess)
{
    PVMM_OFFSET_EPROCESS po = &H->vmm.offset.EPROCESS;
    BOOL f;
    WORD i, j, cLoopProtect;
    DWORD va1, vaPEB, vaP, oP;
    QWORD paPEB;
    BYTE pbSYSTEM[VMMPROC_EPROCESS32_MAX_SIZE], pbSMSS[VMMPROC_EPROCESS32_MAX_SIZE], pb1[VMMPROC_EPROCESS32_MAX_SIZE], pbPage[0x1000];
    //QWORD paMax, paDTB_0, paDTB_1;
    POB_SET psObOff = NULL, psObVa = NULL;
    ZeroMemory(po, sizeof(VMM_OFFSET_EPROCESS));
    if(!VmmRead(H, pSystemProcess, pSystemProcess->win.EPROCESS.va, pbSYSTEM, VMMPROC_EPROCESS32_MAX_SIZE)) { return; }
    VmmLogHexAsciiEx(H, MID_PROCESS, LOGLEVEL_DEBUG, pbSYSTEM, VMMPROC_EPROCESS32_MAX_SIZE, 0, "SYSTEM DTB: %016llx EPROCESS: %016llx", pSystemProcess->paDTB, pSystemProcess->win.EPROCESS.va);
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
    // find offset for PID, FLinkAll, BLink (assumed to be following eachother)
    for(i = 0, f = FALSE; i < VMMPROC_EPROCESS32_MAX_SIZE - 4; i += 4) {
        if(*(PDWORD)(pbSYSTEM + i) == 4) {
            // PID = correct, this is a candidate
            if(0x80000000 != (0x80000003 & *(PDWORD)(pbSYSTEM + i + 4))) { continue; }    // FLinkAll not valid kernel pointer
            va1 = *(PDWORD)(pbSYSTEM + i + 4) - i - 4;
            f = VmmRead(H, pSystemProcess, va1, pb1, VMMPROC_EPROCESS32_MAX_SIZE);
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
            f = VmmRead(H, pSystemProcess, va1, pbSMSS, VMMPROC_EPROCESS32_MAX_SIZE) &&
                (*(PQWORD)(pbSMSS + po->Name) == 0x6578652e73736d73);
            if(f) { break; }
        }
        if(!f) { return; }
        VmmLogHexAsciiEx(H, MID_PROCESS, LOGLEVEL_DEBUG, pbSMSS, VMMPROC_EPROCESS32_MAX_SIZE, 0, "EPROCESS smss.exe BELOW:");
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
                if(!VmmVirt2PhysEx(H, *(PDWORD)(pbSMSS + po->DTB), TRUE, vaPEB, &paPEB)) { continue; }
                if(!VmmReadPage(H, NULL, paPEB, pbPage)) { continue; }
                if(*(PWORD)pbPage == 0x5a4d) { continue; }  // MZ header -> likely entry point or something not PEB ...
                po->PEB = i;
                f = TRUE;
                break;
            }
            if(f) { break; }
            // failed locating PEB (paging?) -> try next process in EPROCESS list.
            va1 = *(PDWORD)(pbSMSS + po->FLink) - po->FLink;
            if(!VmmRead(H, pSystemProcess, va1, pbSMSS, VMMPROC_EPROCESS32_MAX_SIZE)) { return; }
        }
        if(!f) { return; }
    }
    // locate various offsets primarily by reading pointers and checking pool
    // headers in an efficient way (minimize number of reads).
    {
        if(!(psObVa = ObSet_New(H))) { goto fail; }
        if(!(psObOff = ObSet_New(H))) { goto fail; }
        // ObjectTable candidate pointers
        for(i = po->Name - 0x0c0; i < po->Name - 0x010; i += 4) {
            vaP = *(PDWORD)(pbSYSTEM + i);
            if(VMM_KADDR32_8(vaP) && !ObSet_Exists(psObVa, vaP - 0x10)) {
                ObSet_Push(psObOff, (i << 16) | 1);
                ObSet_Push(psObVa, vaP - 0x10);
            }
        }
        // SeAuditProcessCreationInfo candidate pointers by looking at SMSS.
        // Offset is located between PEB+0x040 and PEB+0x058 as observed so far.
        // Look at some extra offsets just in case for the future.
        for(i = po->PEB + 0x040; i < po->PEB + 0x058; i += 4) {
            vaP = *(PDWORD)(pbSMSS + i);
            if(VMM_KADDR32_4(vaP) && !ObSet_Exists(psObVa, vaP)) {
                ObSet_Push(psObOff, (i << 16) | 2);
                ObSet_Push(psObVa, vaP);
            }
        }
        // prefetch result into cache
        VmmCachePrefetchPages3(H, pSystemProcess, psObVa, 0x40, 0);
        // interpret result
        while(ObSet_Size(psObVa)) {
            oP = (DWORD)ObSet_Pop(psObOff);
            vaP = (DWORD)ObSet_Pop(psObVa);
            if(!VmmRead2(H, pSystemProcess, vaP, pbPage, 0x40, VMM_FLAG_FORCECACHE_READ)) {
                if(((vaP + 0x10) & 0xfff) || !VmmRead2(H, pSystemProcess, vaP + 0x10ULL, pbPage + 0x10, 0x30, VMM_FLAG_FORCECACHE_READ)) {
                    continue;
                }
            }
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
    // Value may be the 'VadHint' on some systems; scan back 0x30 to find any
    // identical match (which will be assumed to be vadroot).
    {
        for(i = 0x0e0 + po->Name; i < 0x380; i += 4) {
            f = VMM_KADDR32(*(PDWORD)(pbSYSTEM + i)) && ((*(PDWORD)(pbSYSTEM + i - 4) == 0x00000103) || (*(PDWORD)(pbSYSTEM + i - 12) == 0x00000103));
            if(f) { break; }
        }
        if(!f && (*(PDWORD)(pbSYSTEM + 0x11c) == *(PDWORD)(pbSYSTEM + +0x120))) {   // WINXP
            i = 0x11c;
            f = TRUE;
        }
        if(!f) { goto fail; }
        po->VadRoot = i;
        // Scanback 0x30 (in case of 'VadHint' false positive.
        for(i = po->VadRoot - 8; i > po->VadRoot - 0x30; i -= 4) {
            if(*(PDWORD)(pbSYSTEM + i) == *(PDWORD)(pbSYSTEM + po->VadRoot)) {
                po->VadRoot = i;
                break;
            }
        }
    }
    // DTB_USER not searched for in 32-bit EPROCESS
    VmmWinProcess_OffsetLocator_SetMaxOffset(H);
    po->fValid = TRUE;
fail:
    Ob_DECREF(psObVa);
    Ob_DECREF(psObOff);
}

VOID VmmWinProcess_Enum32_Pre(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess, _In_opt_ PVMMWIN_ENUMERATE_EPROCESS_CONTEXT ctx, _In_ QWORD va, _In_ PBYTE pb, _In_ DWORD cb, _In_ QWORD vaFLink, _In_ QWORD vaBLink, _In_ POB_SET pVSetAddress, _Inout_ PBOOL pfValidEntry, _Inout_ PBOOL pfValidFLink, _Inout_ PBOOL pfValidBLink)
{
    if(!ctx || !VMM_KADDR32_8(va)) { return; }
    ObSet_Push(ctx->pObSetPrefetchDTB, *(PDWORD)(pb + H->vmm.offset.EPROCESS.DTB) & ~0xfff);
    *pfValidFLink = VMM_KADDR32_4(vaFLink);
    *pfValidBLink = VMM_KADDR32_4(vaBLink);
    *pfValidEntry = *pfValidFLink || *pfValidBLink;
}

/*
* Process enumeration callback function:
* NB! REQUIRE SINGLE THREAD: [H->vmm.LockMaster]
* -- H
* -- pSystemProcess
* -- ctx
* -- va
* -- pb
* -- cb
*/
VOID VmmWinProcess_Enum32_Post(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pSystemProcess, _In_opt_ PVMMWIN_ENUMERATE_EPROCESS_CONTEXT ctx, _In_ QWORD va, _In_ PBYTE pb, _In_ DWORD cb)
{
    PVMM_OFFSET_EPROCESS po = &H->vmm.offset.EPROCESS;
    PDWORD ppaDTB_Kernel, ppaDTB_User, pdwPEB;
    PDWORD pdwState, pdwPID, pdwPPID;
    LPSTR szName;
    BOOL fUser;
    PVMM_PROCESS pObProcess = NULL;
    if(!ctx || !VMM_KADDR32_8(va)) { return; }
    pdwState = (PDWORD)(pb + po->State);
    pdwPID = (PDWORD)(pb + po->PID);
    pdwPPID = (PDWORD)(pb + po->PPID);
    ppaDTB_Kernel = (PDWORD)(pb + po->DTB);
    ppaDTB_User = (PDWORD)(pb + po->DTB_User);
    szName = (LPSTR)(pb + po->Name);
    pdwPEB = (PDWORD)(pb + po->PEB);
    if(ctx->pObSetPrefetchDTB) {    // prefetch any physical pages in ctx->pObSetPrefetchDTB on 1st run only
        VmmCachePrefetchPages(H, NULL, ctx->pObSetPrefetchDTB, 0);
        Ob_DECREF_NULL(&ctx->pObSetPrefetchDTB);
    }
    if(*pdwPID && (*pdwPID < 0x10000000) && *(PQWORD)szName) {
        // treat csrss.exe as 'kernel' due to win32k mapping missing in System Process _AND_ treat MemCompression as 'user'
        fUser =
            !((*pdwPID == 4) || ((*pdwState == 0) && (*pdwPEB == 0)) || (*(PQWORD)szName == 0x78652e7373727363) || !((0x879ad18c8c9e8c93 ^ *(PQWORD)szName) + 1)) ||    // csrss.exe
            ((*(PQWORD)(szName + 0x00) == 0x72706d6f436d654d) && (*(PDWORD)(szName + 0x08) == 0x69737365));                                                             // MemCompression "process"
        pObProcess = VmmProcessCreateEntry(
            H,
            ctx->fTotalRefresh,
            *pdwPID,
            *pdwPPID,
            *pdwState,
            *ppaDTB_Kernel & 0xffffffe0,
            po->DTB_User ? (*ppaDTB_User & 0xffffffe0) : 0,
            szName,
            fUser,
            pb,
            cb);
        if(!pObProcess) {
            VmmLog(H, MID_PROCESS, LOGLEVEL_4_VERBOSE, "Process Creation Fail: PID '%i' already exists?", *pdwPID);
            if(++ctx->cNewProcessCollision >= 8) {
                return;
            }
        }
    }
    if(pObProcess) {
        pObProcess->win.EPROCESS.va = (DWORD)va;
        pObProcess->win.EPROCESS.fNoLink = ctx->fNoLinkEPROCESS;
        // PEB
        if(*pdwPEB & 0xfff) {
            VmmLog(H, MID_PROCESS, LOGLEVEL_4_VERBOSE, "Bad PEB alignment for PID: '%i' (0x%08x)", *pdwPID, *pdwPEB);
        } else {
            pObProcess->win.vaPEB = *pdwPEB;
            pObProcess->win.vaPEB32 = *pdwPEB;
        }
    } else {
        szName[14] = 0; // in case of bad string data ...
    }
    VmmLog(H, MID_PROCESS, LOGLEVEL_5_DEBUG, "%04i (%s) %08x %08x %08x %08x %s",
        ctx->cProc,
        !pObProcess ? "skip" : (pObProcess->dwState ? "exit" : "list"),
        *pdwPID,
        *ppaDTB_Kernel,
        (DWORD)va,
        *pdwPEB,
        szName);
    Ob_DECREF_NULL(&pObProcess);
    ctx->cProc++;
}

/*
* Try walk the EPROCESS list in the Windows kernel to enumerate processes into
* the VMM/PROC file system. 32-bit version.
* NB! This may be done to refresh an existing PID cache hence migration code.
* NB! REQUIRE SINGLE THREAD : [H->vmm.LockMaster]
* -- H
* -- pSystemProcess
* -- fTotalRefresh
* -- psvaNoLinkEPROCESS = optional list of non-linked EPROCESS va's.
* -- return
*/
BOOL VmmWinProcess_Enum32(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pSystemProcess, _In_ BOOL fTotalRefresh, _In_opt_ POB_SET psvaNoLinkEPROCESS)
{
    PVMM_OFFSET_EPROCESS po = &H->vmm.offset.EPROCESS;
    VMMWIN_ENUMERATE_EPROCESS_CONTEXT ctx = { 0 };
    // retrieve offsets
    if(!po->fValid) {
        VmmWinProcess_OffsetLocator32(H, pSystemProcess);
        VmmWinProcess_OffsetLocator_Print(H);
        if(!po->fValid) {
            VmmLog(H, MID_PROCESS, LOGLEVEL_VERBOSE, "Unable to fuzz EPROCESS offsets - trying debug symbols");
            VmmWinProcess_OffsetLocatorSYMSERV(H, pSystemProcess);
        }
        if(!po->fValid) {
            VmmLog(H, MID_PROCESS, LOGLEVEL_CRITICAL, "Unable to locate EPROCESS offsets");
            return FALSE;
        }
    }
    VmmLog(H, MID_PROCESS, LOGLEVEL_DEBUG, "SYSTEM DTB: %016llx EPROCESS: %08x", pSystemProcess->paDTB, (DWORD)pSystemProcess->win.EPROCESS.va);
    // set up context
    ctx.fTotalRefresh = fTotalRefresh;
    if(!(ctx.pObSetPrefetchDTB = ObSet_New(H))) { return FALSE; }
    // traverse EPROCESS linked list
    VmmLog(H, MID_PROCESS, LOGLEVEL_DEBUG, "   # STATE  PID      DTB      EPROCESS PEB      NAME");
    VmmWin_ListTraversePrefetch(
        H,
        pSystemProcess,
        TRUE,
        &ctx,
        1,
        &pSystemProcess->win.EPROCESS.va,
        po->FLink,
        po->cbMaxOffset,
        (VMMWIN_LISTTRAVERSE_PRE_CB)VmmWinProcess_Enum32_Pre,
        (VMMWIN_LISTTRAVERSE_POST_CB)VmmWinProcess_Enum32_Post,
        H->vmm.pObCCachePrefetchEPROCESS);
    // add no-link entries (if any)
    VmmWinProcess_Enum_AddNoLink(
        H,
        pSystemProcess,
        psvaNoLinkEPROCESS,
        &ctx,
        (VOID(*)(VMM_HANDLE, PVMM_PROCESS, PVOID, QWORD, PBYTE, DWORD))VmmWinProcess_Enum32_Post);
    // set resulting prefetch cache
    Ob_DECREF_NULL(&ctx.pObSetPrefetchDTB);
    VmmWinProcess_Enumerate_PostProcessing(H, pSystemProcess);
    VmmProcessCreateFinish(H);
    return (ctx.cProc > 10);
}

BOOL VmmWinProcess_Enumerate(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pSystemProcess, _In_ BOOL fRefreshTotal, _In_opt_ POB_SET psvaNoLinkEPROCESS)
{
    BOOL fResult = FALSE;
    VMMSTATISTICS_LOG Statistics = { 0 };
    VmmStatisticsLogStart(H, MID_PROCESS, LOGLEVEL_6_TRACE, NULL, &Statistics, "EPROCESS_ENUMERATE");
    // spider TLB and set up initial system process and enumerate EPROCESS
    VmmTlbSpider(H, pSystemProcess);
    // update processes within global lock (to avoid potential race conditions).
    EnterCriticalSection(&H->vmm.LockMaster);
    if((H->vmm.tpMemoryModel == VMM_MEMORYMODEL_X64) || (H->vmm.tpMemoryModel == VMM_MEMORYMODEL_ARM64)) {
        fResult = VmmWinProcess_Enum64(H, pSystemProcess, fRefreshTotal, psvaNoLinkEPROCESS);
    } else if((H->vmm.tpMemoryModel == VMM_MEMORYMODEL_X86PAE) || (H->vmm.tpMemoryModel == VMM_MEMORYMODEL_X86)) {
        fResult = VmmWinProcess_Enum32(H, pSystemProcess, fRefreshTotal, psvaNoLinkEPROCESS);
    }
    LeaveCriticalSection(&H->vmm.LockMaster);
    VmmStatisticsLogEnd(H, &Statistics, "EPROCESS_ENUMERATE");
    return fResult;
}



// ----------------------------------------------------------------------------
// NON-LINKED PROCESS ENUMERATION BELOW:
// Processes may not always be in the EPROCESS list. Running processes may have
// been maliciously unlinked, or terminated processes may have been cleaned up.
// Try to enumerate these processes in alternative ways.
// ----------------------------------------------------------------------------

/*
* Locate EPROCESS objects not linked by the EPROCESS list.
* This is achieved by analyzing the object table for the SYSTEM process.
* CALLER DECREF: return
* -- return = Set of vaEPROCESS if no-link addresses exist. NULL otherwise.
*/
POB_SET VmmWinProcess_Enumerate_FindNoLinkProcesses(_In_ VMM_HANDLE H)
{
    BOOL f32 = H->vmm.f32;
    BYTE tpProcess, tpObjectEncrypted;
    DWORD i, cbHdr;
    POB_SET psOb = NULL, psObNoLink = NULL;
    PVMM_PROCESS pObSystemProcess = NULL, pObProcess = NULL;
    PVMMOB_MAP_HANDLE pObHandleMap = NULL;
    PVMM_MAP_HANDLEENTRY pe;
    BYTE pbHdr[0x30];
    POBJECT_HEADER32 pHdr32 = (POBJECT_HEADER32)pbHdr;
    POBJECT_HEADER64 pHdr64 = (POBJECT_HEADER64)pbHdr;
    // 1: Initialize
    cbHdr = f32 ? sizeof(OBJECT_HEADER32) : sizeof(OBJECT_HEADER64);
    if(!(psOb = ObSet_New(H))) { goto fail; }
    if(!(pObSystemProcess = VmmProcessGet(H, 4))) { goto fail; }
    if(!VmmWin_ObjectTypeGet(H, 2) || !(tpProcess = H->vmm.ObjectTypeTable.tpProcess)) { goto fail; }
    if(!VmmMap_GetHandle(H, pObSystemProcess, &pObHandleMap, FALSE)) { goto fail; }
    // 2: Prefetch object headers
    for(i = 0; i < pObHandleMap->cMap; i++) {
        ObSet_Push_PageAlign(psOb, pObHandleMap->pMap[i].vaObject - cbHdr, cbHdr);
    }
    VmmCachePrefetchPages(H, pObSystemProcess, psOb, 0);
    ObSet_Clear(psOb);
    // 3: Index processes by EPROCESS va
    while((pObProcess = VmmProcessGetNext(H, pObProcess, VMM_FLAG_PROCESS_SHOW_TERMINATED))) {
        ObSet_Push(psOb, pObProcess->win.EPROCESS.va);
    }
    // 4: Check handles for process not in EPROCESS set
    for(i = 0; i < pObHandleMap->cMap; i++) {
        pe = pObHandleMap->pMap + i;
        if(!VmmRead2(H, pObSystemProcess, pe->vaObject - cbHdr, pbHdr, cbHdr, VMM_FLAG_FORCECACHE_READ | VMM_FLAG_NOPAGING)) { continue; }
        tpObjectEncrypted = f32 ? pHdr32->TypeIndex : pHdr64->TypeIndex;
        if(tpProcess == VmmWin_ObjectTypeGetIndexFromEncoded(H, pe->vaObject - cbHdr, tpObjectEncrypted)) {
            if(ObSet_Exists(psOb, pe->vaObject)) { continue; }
            // process object not in process list found
            if(!psObNoLink && !(psObNoLink = ObSet_New(H))) { goto fail; }
            ObSet_Push(psOb, pe->vaObject);
            ObSet_Push(psObNoLink, pe->vaObject);
            VmmLog(H, MID_PROCESS, LOGLEVEL_DEBUG, "NOLINK_EPROCESS: %016llx", pe->vaObject);
        }
    }
fail:
    Ob_DECREF(pObSystemProcess);
    Ob_DECREF(pObHandleMap);
    Ob_DECREF(psOb);
    return psObNoLink;
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

// use the topmost 4 bits to store additional information about 
// the initial array index which started this list walk.
#define VMMWIN_LISTTRAVERSEPREFETCH_EXVA_CREATE(va, id)     (((QWORD)id << 48) | (va & 0x0000ffffffffffff))
#define VMMWIN_LISTTRAVERSEPREFETCH_EXVA_GET_VA(exva)       (((exva & 0x0000800000000000) ? 0xffff000000000000 : 0) | (exva & 0x0000ffffffffffff))
#define VMMWIN_LISTTRAVERSEPREFETCH_EXVA_GET_ID(exva)       ((WORD)(exva >> 48))

/*
* Walk a windows linked list in an efficient way that minimize IO requests to
* the the device. This is advantageous for latency reasons. The function return
* a set of the addresses used - this may be used to prefetch pages in advance
* if the list should be walked again at a later time.
* The callback function must only return FALSE on severe errors when the list
* should no longer be continued to be walked in the direction.
* The function keeps track of the initial array index if it's below 0xffff.
* CALLER_DECREF: return
* -- H
* -- pProcess
* -- f32
* -- ctx = ctx to pass along to callback function (if any)
* -- cvaDataStart
* -- pvaDataStart
* -- oListStart = offset (in bytes) to _LIST_ENTRY from vaDataStart
* -- cbData
* -- pfnCallback_Pre = optional callback function to gather additional addresses.
* -- pfnCallback_Post = optional callback function called after all pages fetched into cache.
* -- pPrefetchAddressContainer = optional pointer to a PVMMOBCONTAINER containing a POB_VSET of prefetch addresses to use/update.
*/
VOID VmmWin_ListTraversePrefetch(
    _In_ VMM_HANDLE H,
    _In_ PVMM_PROCESS pProcess,
    _In_ BOOL f32,
    _In_opt_ PVOID ctx,
    _In_ DWORD cvaDataStart,
    _In_ PQWORD pvaDataStart,
    _In_ DWORD oListStart,
    _In_ DWORD cbData,
    _In_opt_ VMMWIN_LISTTRAVERSE_PRE_CB pfnCallback_Pre,
    _In_opt_ VMMWIN_LISTTRAVERSE_POST_CB pfnCallback_Post,
    _In_opt_ POB_CONTAINER pPrefetchAddressContainer
) {
    WORD idData;
    QWORD vaData, exvaData;
    DWORD cbReadData;
    PBYTE pbData = NULL;
    QWORD vaFLink, vaBLink;
    POB_SET pObSet_vaAll = NULL, pObSet_vaTry1 = NULL, pObSet_vaTry2 = NULL, pObSet_vaValid = NULL;
    BOOL fValidEntry, fValidFLink, fValidBLink, fTry1;
    // 1: Prefetch any addresses stored in optional address container
    pObSet_vaAll = ObContainer_GetOb(pPrefetchAddressContainer);
    VmmCachePrefetchPages3(H, pProcess, pObSet_vaAll, cbData, 0);
    Ob_DECREF_NULL(&pObSet_vaAll);
    // 2: Prepare/Allocate and set up initial entry
    if(!(pObSet_vaAll = ObSet_New(H))) { goto fail; }
    if(!(pObSet_vaTry1 = ObSet_New(H))) { goto fail; }
    if(!(pObSet_vaTry2 = ObSet_New(H))) { goto fail; }
    if(!(pObSet_vaValid = ObSet_New(H))) { goto fail; }
    if(!(pbData = LocalAlloc(0, cbData))) { goto fail; }
    while(cvaDataStart) {
        cvaDataStart--;
        if(ObSet_Push(pObSet_vaAll, pvaDataStart[cvaDataStart])) {
            ObSet_Push(pObSet_vaTry1, VMMWIN_LISTTRAVERSEPREFETCH_EXVA_CREATE(pvaDataStart[cvaDataStart], cvaDataStart));
        }
    }
    // 3: Initial list walk
    fTry1 = TRUE;
    while(TRUE) {
        if(fTry1) {
            exvaData = ObSet_Pop(pObSet_vaTry1);
            if(!exvaData && (0 == ObSet_Size(pObSet_vaTry2))) { break; }
            if(!exvaData) {
                VmmCachePrefetchPages3(H, pProcess, pObSet_vaAll, cbData, 0);
                fTry1 = FALSE;
                continue;
            }
            vaData = VMMWIN_LISTTRAVERSEPREFETCH_EXVA_GET_VA(exvaData);
            idData = VMMWIN_LISTTRAVERSEPREFETCH_EXVA_GET_ID(exvaData);
            VmmReadEx(H, pProcess, vaData, pbData, cbData, &cbReadData, VMM_FLAG_FORCECACHE_READ);
            if(cbReadData != cbData) {
                ObSet_Push(pObSet_vaTry2, exvaData);
                continue;
            }
        } else {
            exvaData = ObSet_Pop(pObSet_vaTry2);
            if(!exvaData && (0 == ObSet_Size(pObSet_vaTry1))) { break; }
            if(!exvaData) { fTry1 = TRUE; continue; }
            vaData = VMMWIN_LISTTRAVERSEPREFETCH_EXVA_GET_VA(exvaData);
            idData = VMMWIN_LISTTRAVERSEPREFETCH_EXVA_GET_ID(exvaData);
            if(!VmmRead(H, pProcess, vaData, pbData, cbData)) { continue; }
        }
        vaFLink = f32 ? *(PDWORD)(pbData + oListStart + 0) : *(PQWORD)(pbData + oListStart + 0);
        vaBLink = f32 ? *(PDWORD)(pbData + oListStart + 4) : *(PQWORD)(pbData + oListStart + 8);
        if(pfnCallback_Pre) {
            fValidEntry = FALSE; fValidFLink = FALSE; fValidBLink = FALSE;
            pfnCallback_Pre(H, pProcess, ctx, vaData, pbData, cbData, vaFLink, vaBLink, pObSet_vaAll, &fValidEntry, &fValidFLink, &fValidBLink, idData);
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
            ObSet_Push(pObSet_vaValid, exvaData);
        }
        vaFLink -= oListStart;
        vaBLink -= oListStart;
        if(fValidFLink && ObSet_Push(pObSet_vaAll, vaFLink)) {
            ObSet_Push(pObSet_vaTry1, VMMWIN_LISTTRAVERSEPREFETCH_EXVA_CREATE(vaFLink, idData));
        }
        if(fValidBLink && ObSet_Push(pObSet_vaAll, vaBLink)) {
            ObSet_Push(pObSet_vaTry1, VMMWIN_LISTTRAVERSEPREFETCH_EXVA_CREATE(vaBLink, idData));
        }
    }
    // 4: Prefetch additional gathered addresses into cache.
    VmmCachePrefetchPages3(H, pProcess, pObSet_vaAll, cbData, 0);
    // 5: 2nd main list walk. Call into optional pfnCallback_Post to do the main
    //    processing of the list items.
    if(pfnCallback_Post) {
        while((exvaData = ObSet_Pop(pObSet_vaValid))) {
            vaData = VMMWIN_LISTTRAVERSEPREFETCH_EXVA_GET_VA(exvaData);
            idData = VMMWIN_LISTTRAVERSEPREFETCH_EXVA_GET_ID(exvaData);
            if(VmmRead(H, pProcess, vaData, pbData, cbData)) {
                pfnCallback_Post(H, pProcess, ctx, vaData, pbData, cbData, idData);
            }
        }
    }
    // 6: Store/Update the optional container with the newly prefetch addresses (if possible and desirable).
    if(pPrefetchAddressContainer && H->dev.fVolatile && H->vmm.ThreadProcCache.fEnabled) {
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
