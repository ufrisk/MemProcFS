// m_evil_proc1.c : evil detectors for various process issues #1.
// 
// Detections:
//  - NOIMAGE_RWX
//  - NOIMAGE_RX
//  - PE_PATCHED
//  - PE_INJECT
//  - PE_NOLINK
//  - PEB_BAD_LDR
//  - PRIVATE_RWX
//  - PRIVATE_RX
//  - PROC_NOLINK
//
// (c) Ulf Frisk, 2023-2025
// Author: Ulf Frisk, pcileech@frizk.net
//

#include "modules.h"
#include "../mm/mm.h"
#include "../vmmwin.h"

#define EVIL_MAXCOUNT_VAD_PATCHED_PE             4   // max number of "patched" entries per vad
#define EVIL_MAXCOUNT_VAD_EXECUTE                4

/*
* Helper function to add an evil entry with a VAD.
*/
VOID MEvilProc1_AddEvilVad(
    _In_ VMM_HANDLE H,
    _In_ VMMEVIL_TYPE tpEvil,
    _In_ PVMM_PROCESS pProcess,
    _In_ QWORD va,
    _In_ QWORD vaVadBase,
    _In_ DWORD oVadEx
) {
    BOOL fPteA;
    PVMM_MAP_VADENTRY peVad;
    PVMM_MAP_VADEXENTRY pex;
    PVMMOB_MAP_VAD pObVadMap = NULL;
    PVMMOB_MAP_VADEX pObVadEx = NULL;
    CHAR szProtection[7] = { 0 };
    if(!pProcess) { return; }
    if(!VmmMap_GetVad(H, pProcess, &pObVadMap, VMM_VADMAP_TP_FULL)) { goto fail; }
    if(!(peVad = VmmMap_GetVadEntry(H, pObVadMap, vaVadBase))) { goto fail; }
    if(!VmmMap_GetVadEx(H, pProcess, &pObVadEx, VMM_VADMAP_TP_FULL, peVad->cVadExPagesBase + oVadEx, 1) || !pObVadEx->cMap) { goto fail; }
    pex = pObVadEx->pMap;
    MmVad_StrProtectionFlags(peVad, szProtection);
    fPteA = pex->flags & VADEXENTRY_FLAG_HARDWARE;
    FcEvilAdd(H, tpEvil, pProcess, va, "%012llx %016llx %c %c%c%c %016llx %012llx %016llx %c %s %s %s",
        pex->pa,
        pex->pte,
        MmVadEx_StrType(pex->tp),
        fPteA ? 'r' : '-',
        (fPteA && (pex->flags & VADEXENTRY_FLAG_W)) ? 'w' : '-',
        (!fPteA || (pex->flags & VADEXENTRY_FLAG_NX)) ? '-' : 'x',
        peVad->vaVad,
        pex->proto.pa,
        pex->proto.pte,
        MmVadEx_StrType(pex->proto.tp),
        MmVad_StrType(peVad),
        szProtection,
        peVad->uszText + peVad->cbuText - min(51, peVad->cbuText)
    );
fail:
    Ob_DECREF(pObVadMap);
    Ob_DECREF(pObVadEx);
}



//-----------------------------------------------------------------------------
// PEB_BAD_LDR / PROC_NOLINK / PE_INJECT / PE_NOLINK:
//-----------------------------------------------------------------------------

/*
* Locate "unlinked" modules; i.e. PE modules not in the PEB LdrList; but yet in
* the VAD map with executable entries.
* The module map generation logic contains the actual detections.
*/
VOID MEvilProc1_Modules(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess)
{
    BOOL fBadLdr = TRUE;
    DWORD i;
    LPSTR uszModuleName;
    PVMM_MAP_VADENTRY peVad = NULL;
    PVMMOB_MAP_VAD pObVadMap = NULL;
    PVMM_MAP_MODULEENTRY peModule;
    PVMMOB_MAP_MODULE pObModuleMap = NULL;
    if((pProcess->dwPPID == 4) && !memcmp("MemCompression", pProcess->szName, 15)) { return; }
    if(VmmMap_GetModule(H, pProcess, 0, &pObModuleMap)) {
        for(i = 0; i < pObModuleMap->cMap; i++) {
            if(pObModuleMap->pMap[i].tp == VMM_MODULE_TP_NORMAL) {
                fBadLdr = FALSE;
                break;
            }
        }
        if(fBadLdr) {
            FcEvilAdd(H, EVIL_PEB_BAD_LDR, pProcess, pProcess->win.vaPEB32 ? pProcess->win.vaPEB32 : pProcess->win.vaPEB, "");
        }
        if(pProcess->win.EPROCESS.fNoLink) {
            FcEvilAdd(H, EVIL_PROC_NOLINK, pProcess, pProcess->win.EPROCESS.va, "");
        }
        for(i = 0; i < pObModuleMap->cMap; i++) {
            peModule = pObModuleMap->pMap + i;
            if(peModule->tp == VMM_MODULE_TP_INJECTED) {
                if(!pObVadMap) {
                    VmmMap_GetVad(H, pProcess, &pObVadMap, VMM_VADMAP_TP_FULL);
                }
                peVad = VmmMap_GetVadEntry(H, pObVadMap, peModule->vaBase);
                uszModuleName = (peModule && peModule->uszFullName) ? peModule->uszFullName : "";
                if(peVad && (peVad->cbuText > 1)) {
                    FcEvilAdd(H, EVIL_PE_INJECT, pProcess, peModule->vaBase, "Module:[%s] VAD:[%s]", uszModuleName, peVad->uszText);
                } else {
                    FcEvilAdd(H, EVIL_PE_INJECT, pProcess, peModule->vaBase, "Module:[%s]", uszModuleName);
                }
            }
            if(!fBadLdr && (peModule->tp == VMM_MODULE_TP_NOTLINKED)) {
                if(!pObVadMap) {
                    VmmMap_GetVad(H, pProcess, &pObVadMap, VMM_VADMAP_TP_FULL);
                }
                peVad = VmmMap_GetVadEntry(H, pObVadMap, peModule->vaBase);
                uszModuleName = (peModule && peModule->uszFullName) ? peModule->uszFullName : "";
                if(peVad && (peVad->cbuText > 1)) {
                    FcEvilAdd(H, EVIL_PE_NOLINK, pProcess, peModule->vaBase, "Module:[%s] VAD:[%s]", uszModuleName, peVad->uszText);
                } else {
                    FcEvilAdd(H, EVIL_PE_NOLINK, pProcess, peModule->vaBase, "Module:[%s]", uszModuleName);
                }
            }
        }
        Ob_DECREF(pObModuleMap);
    }
}



//-----------------------------------------------------------------------------
// PRIVATE_RWX / NOIMAGE_RWX / PRIVATE_RX / NOIMAGE_RX:
//-----------------------------------------------------------------------------

/*
* Check a single VAD entry for: PRIVATE_EXECUTE and NOIMAGE_EXECUTE.
*/
VOID MEvilProc1_VadNoImageExecuteEntry(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess, _In_ PVMMOB_MAP_VAD pVadMap, _In_ DWORD iVad, _Inout_ POB_SET psInjectedPE)
{
    DWORD iVadEx, cEvilRX = 0, cEvilRWX = 0;
    QWORD cbPE;
    PVMM_MAP_VADENTRY peVad;
    PVMM_MAP_VADEXENTRY peVadEx;
    PVMMOB_MAP_VADEX pObVadExMap = NULL;
    VMMEVIL_TYPE tpEvil;
    BOOL fPteA;
    peVad = pVadMap->pMap + iVad;
    // 1: check for PE header (injected PE)
    cbPE = PE_GetSize(H, pProcess, peVad->vaStart);
    if(cbPE && (cbPE < 0x04000000)) {
        ObSet_Push(psInjectedPE, peVad->vaStart);
    }
    // 2: check executable pages
    if(!VmmMap_GetVadEx(H, pProcess, &pObVadExMap, VMM_VADMAP_TP_PARTIAL, peVad->cVadExPagesBase, peVad->cVadExPages)) { return; }
    for(iVadEx = 0; iVadEx < pObVadExMap->cMap; iVadEx++) {
        peVadEx = pObVadExMap->pMap + iVadEx;
        fPteA = peVadEx->flags & VADEXENTRY_FLAG_HARDWARE;
        //if(!fPteA && !MMVAD_IS_FLAG_X(peVad)) { continue; }
        if(fPteA && (peVadEx->flags & VADEXENTRY_FLAG_NX)) { continue; }
        if(peVadEx->tp == VMM_PTE_TP_DEMANDZERO) { continue; }
        if((fPteA && (peVadEx->flags & VADEXENTRY_FLAG_W)) || (!fPteA && MMVAD_IS_FLAG_W(peVad))) {
            if(cEvilRWX >= EVIL_MAXCOUNT_VAD_EXECUTE) { continue; }
            cEvilRWX++;
            tpEvil = peVad->fPrivateMemory ? EVIL_PRIVATE_RWX : EVIL_NOIMAGE_RWX;
        } else {
            if(!peVad->fPrivateMemory && peVad->fFile && (H->vmm.tpMemoryModel == VMM_MEMORYMODEL_ARM64) && CharUtil_StrStartsWith(peVad->uszText, "\\Windows\\XtaCache\\", TRUE)) {
                continue;
            }
            if(cEvilRX >= EVIL_MAXCOUNT_VAD_EXECUTE) { continue; }
            cEvilRX++;
            tpEvil = peVad->fPrivateMemory ? EVIL_PRIVATE_RX : EVIL_NOIMAGE_RX;
        }
        MEvilProc1_AddEvilVad(H, tpEvil, pProcess, peVadEx->va, peVad->vaStart, iVadEx);;
        if((cEvilRWX >= EVIL_MAXCOUNT_VAD_EXECUTE) && (cEvilRX >= EVIL_MAXCOUNT_VAD_EXECUTE)) { break; }
    }
    Ob_DECREF(pObVadExMap);
}

/*
* Helper function for VmmEvil_ProcessScan_VadNoImageExecute to reduce number of
* false positives in known problematic processes.
*/
VOID MEvilProc1_VadNoImageExecute_ProcWhitelist(_In_ PVMM_PROCESS pProcess, _Out_ PBOOL pfProcSuppressRX, _Out_ PBOOL fProcSuppressRWX)
{
    DWORD i;
    LPSTR szLIST_RWX[] = {
        "MsMpEng.exe", "PhoneExperienc"
    };
    LPSTR szLIST_RX[] = {
        "ApplicationFra", "dwm.exe", "iexplore.exe", "MicrosoftEdgeC", "powershell.exe", "SearchApp.exe", "SearchUI.exe", "SkypeApp.exe", "smartscreen.ex", "PhoneExperienc",
    };
    for(i = 0; i < sizeof(szLIST_RWX) / sizeof(LPSTR); i++) {
        if(!strcmp(pProcess->szName, szLIST_RWX[i])) {
            *pfProcSuppressRX = TRUE;
            *fProcSuppressRWX = TRUE;
            return;
        }
    }
    for(i = 0; i < sizeof(szLIST_RX) / sizeof(LPSTR); i++) {
        if(!strcmp(pProcess->szName, szLIST_RX[i])) {
            *pfProcSuppressRX = TRUE;
            *fProcSuppressRWX = FALSE;
            return;
        }
    }
    *pfProcSuppressRX = FALSE;
    *fProcSuppressRWX = FALSE;
}

/*
* Scan non-image VADs for PTEs with executable pages in the CPU page tables.
* If such an entry is found the VAD is suspicious and additionally checked for:
* INJECTED_PE, PRIVATE_EXECUTE and NOIMAGE_EXECUTE.
*/
VOID MEvilProc1_VadNoImageExecute(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess, _Inout_ POB_SET psInjectedPE)
{
    BOOL fRX, fRWX, fProcSuppressRX, fProcSuppressRWX;
    DWORD iVad, iPte = 0;
    PVMMOB_MAP_PTE pObPteMap = NULL;
    PVMM_MAP_VADENTRY peVad;
    PVMMOB_MAP_VAD pObVadMap = NULL;
    PVMMOB_MAP_VADEX pObVadExMap = NULL;
    if(!VmmMap_GetPte(H, pProcess, &pObPteMap, FALSE)) { goto fail; }
    if(!VmmMap_GetVad(H, pProcess, &pObVadMap, VMM_VADMAP_TP_PARTIAL)) { goto fail; }
    MEvilProc1_VadNoImageExecute_ProcWhitelist(pProcess, &fProcSuppressRX, &fProcSuppressRWX);
    for(iVad = 0; (iVad < pObVadMap->cMap) && (iPte < pObPteMap->cMap); iVad++) {
        peVad = pObVadMap->pMap + iVad;
        if(peVad->fImage) { continue; }
        // move pte index to current vad
        while((iPte < pObPteMap->cMap) && (pObPteMap->pMap[iPte].vaBase + (pObPteMap->pMap[iPte].cPages << 12) <= peVad->vaStart)) {
            iPte++;
        }
        // check if vad contains hw executable page
        fRX = FALSE;
        while(!fRX && (iPte < pObPteMap->cMap) && (pObPteMap->pMap[iPte].vaBase < peVad->vaEnd)) {
            fRX = pObPteMap->pMap[iPte].fPage && !(pObPteMap->pMap[iPte].fPage & VMM_MEMMAP_PAGE_NX);
            fRWX = fRX && pObPteMap->pMap[iPte].fPage && (pObPteMap->pMap[iPte].fPage & VMM_MEMMAP_PAGE_W);
            iPte++;
        }
        // check if vad is p-rwx-
        if(MMVAD_IS_FLAG_P(peVad) && MMVAD_IS_FLAG_R(peVad) && MMVAD_IS_FLAG_W(peVad) && MMVAD_IS_FLAG_X(peVad)) {
            fRX = TRUE,
                fRWX = TRUE;
        }
        // vad has hw executable page -> investigate closer
        if(fRX && !fProcSuppressRX && !(fRWX && fProcSuppressRWX)) {
            MEvilProc1_VadNoImageExecuteEntry(H, pProcess, pObVadMap, iVad, psInjectedPE);
        }
    }
fail:
    Ob_DECREF(pObPteMap);
    Ob_DECREF(pObVadMap);
}



//-----------------------------------------------------------------------------
// PE_PATCHED:
//-----------------------------------------------------------------------------

/*
* VMMEVIL_TYPE: PE_PATCHED
* Locate "patched" executable pages in Image VADs. This is achieved by for each
* active executable page checking its physical address against the address of
* the prototype page. If its possible (i.e. no paged out pages) and there is a
* mismatch then flag the page to the evil map.
*/
VOID MEvilProc1_PePatched_VadImageExecuteNoProto(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess)
{
    BOOL f;
    DWORD iVad, iVadEx, cPatch;
    PVMM_MAP_VADENTRY peVad;
    PVMMOB_MAP_VAD pObVadMap = NULL;
    PVMM_MAP_VADEXENTRY peVadEx;
    PVMMOB_MAP_VADEX pObVadExMap = NULL;
    BYTE pbPage1[0x1000], pbPage2[0x1000];
    if(!VmmMap_GetVad(H, pProcess, &pObVadMap, VMM_VADMAP_TP_PARTIAL)) { goto fail; }
    // 1: fetch VAD_PATCHED_PE by iterating over image VADs
    for(iVad = 0; iVad < pObVadMap->cMap; iVad++) {
        peVad = pObVadMap->pMap + iVad;
        if(!peVad->fImage) { continue; }
        if(!VmmMap_GetVadEx(H, pProcess, &pObVadExMap, VMM_VADMAP_TP_PARTIAL, peVad->cVadExPagesBase, peVad->cVadExPages)) { continue; }
        for(iVadEx = 0, cPatch = 0; (iVadEx < pObVadExMap->cMap) && (cPatch < EVIL_MAXCOUNT_VAD_PATCHED_PE); iVadEx++) {
            peVadEx = pObVadExMap->pMap + iVadEx;
            if(!(peVadEx->flags & VMM_PTE_TP_HARDWARE) || (peVadEx->flags & VADEXENTRY_FLAG_NX)) { continue; }
            if(!peVadEx->pa || !peVadEx->proto.pa) { continue; }
            if(peVadEx->pa == peVadEx->proto.pa) { continue; }
            if(!peVadEx->peVad->vaStart) { continue; }
            // ensure binary difference between physical address and prototype.
            f = VmmRead2(H, NULL, peVadEx->pa, pbPage1, 0x1000, 0) &&
                VmmRead2(H, NULL, peVadEx->proto.pa, pbPage2, 0x1000, 0) &&
                memcmp(pbPage1, pbPage2, 0x1000);
            if(f) {
                MEvilProc1_AddEvilVad(
                    H,
                    EVIL_PE_PATCHED,
                    pProcess,
                    peVadEx->va,
                    peVadEx->peVad->vaStart,
                    iVadEx
                );
                cPatch++;
            }
        }
        Ob_DECREF_NULL(&pObVadExMap);
    }
fail:
    Ob_DECREF(pObVadMap);
}



//-----------------------------------------------------------------------------
// COMMON:
//-----------------------------------------------------------------------------

VOID MEvilProc1_DoWork(_In_ VMM_HANDLE H, _In_ VMMDLL_MODULE_ID MID, _In_opt_ PVOID ctxfc)
{
    POB_SET psObInjectedPE = NULL;
    PVMM_PROCESS pObProcess = NULL;
    if(!(psObInjectedPE = ObSet_New(H))) { goto fail; }
    while((pObProcess = VmmProcessGetNext(H, pObProcess, 0))) {
        if(H->fAbort) { goto fail; }
        if(pObProcess->dwState || VmmProcess_IsKernelOnly(pObProcess)) { continue; }
        if(FcIsProcessSkip(H, pObProcess)) { continue; }
        MEvilProc1_PePatched_VadImageExecuteNoProto(H, pObProcess);
        // update result with execute pages in non image vads.
        // also commit to modules map as injected PE (if possible).
        MEvilProc1_VadNoImageExecute(H, pObProcess, psObInjectedPE);
        VmmWinLdrModule_Initialize(H, pObProcess, psObInjectedPE);
        // update result with interesting module entries.
        MEvilProc1_Modules(H, pObProcess);
    }
    VmmLog(H, MID, LOGLEVEL_6_TRACE, "COMPLETED FINDEVIL SCAN");
fail:
    Ob_DECREF(psObInjectedPE);
    Ob_DECREF(pObProcess);
}

VOID M_Evil_Proc1(_In_ VMM_HANDLE H, _Inout_ PVMMDLL_PLUGIN_REGINFO pRI)
{
    if((pRI->magic != VMMDLL_PLUGIN_REGINFO_MAGIC) || (pRI->wVersion != VMMDLL_PLUGIN_REGINFO_VERSION)) { return; }
    if(pRI->sysinfo.f32 || (pRI->sysinfo.dwVersionBuild < 9600)) { return; }    // only support 64-bit Win8.1+ for now
    // register findevil plugin:
    strcpy_s(pRI->reg_info.uszPathName, 128, "\\findevil\\EvPROC1");
    pRI->reg_info.fRootModule = TRUE;
    pRI->reg_info.fRootModuleHidden = TRUE;
    pRI->reg_fnfc.pfnFindEvil = MEvilProc1_DoWork;
    pRI->pfnPluginManager_Register(H, pRI);
}
