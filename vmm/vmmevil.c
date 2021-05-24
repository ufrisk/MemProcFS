// evil.c : implementation of functionality related to the "Evil" functionality.
//
// (c) Ulf Frisk, 2020-2021
// Author: Ulf Frisk, pcileech@frizk.net
//
#include "vmmevil.h"
#include "vmmwin.h"
#include "pe.h"
#include "charutil.h"
#include "util.h"

#define VMMEVIL_MAXCOUNT_VAD_PATCHED_PE             4   // max number of "patched" entries per vad
#define VMMEVIL_MAXCOUNT_VAD_EXECUTE                4

#define VMM_MAP_EVILENTRY_HASH(dwPID, tp, va)       (((QWORD)dwPID << 32) ^ ((QWORD)tp << 56) ^ (DWORD)(va >> 16) ^ va)

/*
* Helper function to create an entry and add it to the pmEvil map.
* The map holds the reference; the returned data must _NOT_ be free'd.
*/
PVMM_MAP_EVILENTRY VmmEvil_AddEvil_NoVadReq(_Inout_ POB_MAP pmEvil, _In_ PVMM_PROCESS pProcess, _In_ VMM_EVIL_TP tp, _In_ QWORD va, _In_ QWORD vaVadBase, _In_ DWORD oVadEx, _In_ BOOL fEvilAllSuppress)
{
    QWORD qwKey;
    PVMM_MAP_EVILENTRY peEvil = NULL;
    if((peEvil = LocalAlloc(0, sizeof(VMM_MAP_EVILENTRY)))) {
        qwKey = VMM_MAP_EVILENTRY_HASH(pProcess->dwPID, tp, va);
        peEvil->dwPID = pProcess->dwPID;
        peEvil->fEvilAllSuppress = fEvilAllSuppress;
        peEvil->tp = tp;
        peEvil->va = va;
        peEvil->oVadEx = oVadEx;
        peEvil->vaVad = vaVadBase;
        if(!ObMap_Push(pmEvil, qwKey, peEvil)) {
            LocalFree(peEvil);
            return NULL;
        }
        return peEvil;
    }
    return NULL;
}

PVMM_MAP_EVILENTRY VmmEvil_AddEvil(_Inout_ POB_MAP pmEvil, _In_ PVMM_PROCESS pProcess, _In_ VMM_EVIL_TP tp, _In_ QWORD va, _In_ QWORD vaVadBase, _In_ DWORD oVadEx, _In_ BOOL fEvilAllSuppress)
{
    return vaVadBase ? VmmEvil_AddEvil_NoVadReq(pmEvil, pProcess, tp, va, vaVadBase, oVadEx, fEvilAllSuppress) : NULL;
}

/*
* Check a single VAD entry for: PRIVATE_EXECUTE and NOIMAGE_EXECUTE.
*/
VOID VmmEvil_ProcessScan_VadNoImageExecuteEntry(_In_ PVMM_PROCESS pProcess, _In_ PVMMOB_MAP_VAD pVadMap, _In_ DWORD iVad, _Inout_ POB_MAP pmEvil, _Inout_ POB_SET psInjectedPE, _In_ BOOL fEvilAllSuppress)
{
    DWORD iVadEx, cEvilRX = 0, cEvilRWX = 0;
    QWORD cbPE, qwHwPte;
    PVMM_MAP_VADENTRY peVad;
    PVMM_MAP_VADEXENTRY peVadEx;
    PVMMOB_MAP_VADEX pObVadExMap = NULL;
    VMM_EVIL_TP tp;
    peVad = pVadMap->pMap + iVad;
    // 1: check for PE header (injected PE)
    cbPE = PE_GetSize(pProcess, peVad->vaStart);
    if(cbPE && (cbPE < 0x04000000)) {
        ObSet_Push(psInjectedPE, peVad->vaStart);
    }
    // 2: check executable pages
    if(!VmmMap_GetVadEx(pProcess, &pObVadExMap, VMM_VADMAP_TP_PARTIAL, peVad->cVadExPagesBase, peVad->cVadExPages)) { return; }
    for(iVadEx = 0; iVadEx < pObVadExMap->cMap; iVadEx++) {
        peVadEx = pObVadExMap->pMap + iVadEx;
        qwHwPte = (peVadEx->tp == VMM_PTE_TP_HARDWARE) ? peVadEx->pte : 0;
        if(!qwHwPte || (qwHwPte & VMM_MEMMAP_PAGE_NX)) { continue; }
        if(qwHwPte & VMM_MEMMAP_PAGE_W) {
            if(cEvilRWX >= VMMEVIL_MAXCOUNT_VAD_EXECUTE) { continue; }
            cEvilRWX++;
            tp = peVad->fPrivateMemory ? VMM_EVIL_TP_VAD_PRIVATE_RWX : VMM_EVIL_TP_VAD_NOIMAGE_RWX;
        } else {
            if(cEvilRX >= VMMEVIL_MAXCOUNT_VAD_EXECUTE) { continue; }
            cEvilRX++;
            tp = peVad->fPrivateMemory ? VMM_EVIL_TP_VAD_PRIVATE_RX : VMM_EVIL_TP_VAD_NOIMAGE_RX;
        }
        VmmEvil_AddEvil(
            pmEvil,
            pProcess,
            tp,
            peVadEx->va,
            peVad->vaStart,
            iVadEx,
            fEvilAllSuppress
        );
        if((cEvilRWX >= VMMEVIL_MAXCOUNT_VAD_EXECUTE) && (cEvilRX >= VMMEVIL_MAXCOUNT_VAD_EXECUTE)) { break; }
    }
}

/*
* Helper function for VmmEvil_ProcessScan_VadNoImageExecute to reduce number of
* false positives in known problematic processes.
*/
VOID VmmEvil_ProcessScan_VadNoImageExecute_ProcWhitelist(_In_ PVMM_PROCESS pProcess, _Out_ PBOOL pfProcSuppressRX, _Out_ PBOOL fProcSuppressRWX)
{
    DWORD i;
    LPSTR szLIST_RWX[] = {
        "MsMpEng.exe"
    };
    LPSTR szLIST_RX[] = {
        "ApplicationFra", "dwm.exe", "iexplore.exe", "MicrosoftEdgeC", "powershell.exe", "SearchApp.exe", "SearchUI.exe", "SkypeApp.exe", "smartscreen.ex",
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
VOID VmmEvil_ProcessScan_VadNoImageExecute(_In_ PVMM_PROCESS pProcess, _Inout_ POB_MAP pmEvil, _Inout_ POB_SET psInjectedPE)
{
    BOOL fRX, fRWX, fProcSuppressRX, fProcSuppressRWX;
    DWORD iVad, iPte = 0;
    PVMMOB_MAP_PTE pObPteMap = NULL;
    PVMM_MAP_VADENTRY peVad;
    PVMMOB_MAP_VAD pObVadMap = NULL;
    PVMMOB_MAP_VADEX pObVadExMap = NULL;
    if(!VmmMap_GetPte(pProcess, &pObPteMap, FALSE)) { goto fail; }
    if(!VmmMap_GetVad(pProcess, &pObVadMap, VMM_VADMAP_TP_PARTIAL)) { goto fail; }
    VmmEvil_ProcessScan_VadNoImageExecute_ProcWhitelist(pProcess, &fProcSuppressRX, &fProcSuppressRWX);
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
        // vad has hw executable page -> investigate closer
        if(fRX) {
            VmmEvil_ProcessScan_VadNoImageExecuteEntry(pProcess, pObVadMap, iVad, pmEvil, psInjectedPE, fProcSuppressRX || (fRWX && fProcSuppressRWX));
        }
    }
fail:
    Ob_DECREF(pObVadMap);
}

/*
* verify  
*/
VOID VmmEvil_ProcessScan_VadImageExecuteNoProto_PhysicalPageVerify(_In_ PVMM_PROCESS pProcess, _Inout_ POB_MAP pmEvil)
{
    BOOL f;
    short i, o, c;
    POB_SET psObRemove = NULL;
    PVMM_MAP_EVILENTRY pe = NULL;
    BYTE pbPage1[0x1000], pbPage2[0x1000];
    if(!(psObRemove = ObSet_New())) { return; }
    while((pe = ObMap_GetNext(pmEvil, pe))) {
        f = VmmRead2(NULL, pe->VAD_PATCHED_PE.pa, pbPage1, 0x1000, VMM_FLAG_FORCECACHE_READ) &&
            VmmRead2(NULL, pe->VAD_PATCHED_PE.paProto, pbPage2, 0x1000, VMM_FLAG_FORCECACHE_READ) &&
            memcmp(pbPage1, pbPage2, 0x1000);
        if(f) {
            for(i = 0xfff, o = 0, c = 0; i >= 0; i--) {
                if(pbPage1[i] != pbPage2[i]) {
                    c++;
                    o = i;
                }
            }
            pe->VAD_PATCHED_PE.wPatchOffset = o;
            pe->VAD_PATCHED_PE.wPatchByteCount = c;
        } else {
            ObSet_Push(psObRemove, (QWORD)pe);
        }
    }
    while((pe = (PVMM_MAP_EVILENTRY)ObSet_Pop(psObRemove))) {
        LocalFree(ObMap_Remove(pmEvil, pe));
    }
    Ob_DECREF(psObRemove);
}

/*
* Locate "patched" executable pages in Image VADs. This is achieved by for each
* active executable page checking its physical address against the address of
* the prototype page. If its possible (i.e. no paged out pages) and there is a
* mismatch then flag the page to the evil map.
*/
VOID VmmEvil_ProcessScan_VadImageExecuteNoProto(_In_ PVMM_PROCESS pProcess, _Inout_ POB_MAP pmEvil)
{
    QWORD qwHwPte;
    DWORD iVad, iVadEx, cPatch;
    PVMM_MAP_VADENTRY peVad;
    PVMMOB_MAP_VAD pObVadMap = NULL;
    PVMM_MAP_VADEXENTRY peVadEx;
    PVMMOB_MAP_VADEX pObVadExMap = NULL;
    PVMM_MAP_EVILENTRY peEvil;
    POB_SET pspaObPrefetch = NULL;
    if(!(pspaObPrefetch = ObSet_New())) { goto fail; }
    if(!VmmMap_GetVad(pProcess, &pObVadMap, VMM_VADMAP_TP_PARTIAL)) { goto fail; }
    // 1: fetch VAD_PATCHED_PE by iterating over image VADs
    for(iVad = 0; iVad < pObVadMap->cMap; iVad++) {
        peVad = pObVadMap->pMap + iVad;
        if(!peVad->fImage) { continue; }
        if(!VmmMap_GetVadEx(pProcess, &pObVadExMap, VMM_VADMAP_TP_PARTIAL, peVad->cVadExPagesBase, peVad->cVadExPages)) { continue; }
        for(iVadEx = 0, cPatch = 0; (iVadEx < pObVadExMap->cMap) && (cPatch < VMMEVIL_MAXCOUNT_VAD_PATCHED_PE); iVadEx++) {
            peVadEx = pObVadExMap->pMap + iVadEx;
            qwHwPte = (peVadEx->tp == VMM_PTE_TP_HARDWARE) ? peVadEx->pte : 0;
            if(!qwHwPte || (qwHwPte & VMM_MEMMAP_PAGE_NX)) { continue; }
            if(!peVadEx->pa || !peVadEx->proto.pa) { continue; }
            if(peVadEx->pa == peVadEx->proto.pa) { continue; }
            cPatch++;
            peEvil = VmmEvil_AddEvil(
                pmEvil,
                pProcess,
                VMM_EVIL_TP_VAD_PATCHED_PE,
                peVadEx->va,
                peVadEx->peVad->vaStart,
                iVadEx,
                FALSE
            );
            if(peEvil) {
                ObSet_Push(pspaObPrefetch, (peEvil->VAD_PATCHED_PE.pa = peVadEx->pa));
                ObSet_Push(pspaObPrefetch, (peEvil->VAD_PATCHED_PE.paProto = peVadEx->proto.pa));
            }
        }
        Ob_DECREF_NULL(&pObVadExMap);
    }
    // 2: ensure binary difference between physical address and prototype.
    if(ObSet_Size(pspaObPrefetch)) {
        VmmCachePrefetchPages(NULL, pspaObPrefetch, 0);
        VmmEvil_ProcessScan_VadImageExecuteNoProto_PhysicalPageVerify(pProcess, pmEvil);
    }
fail:
    Ob_DECREF(pObVadMap);
    Ob_DECREF(pspaObPrefetch);
}

/*
* Locate "unlinked" modules; i.e. PE modules not in the PEB LdrList; but yet in
* the VAD map with executable entries. Also register detected injected modules
* with the evil map here.
* The module map generation logic contains the actual detections.
*/
VOID VmmEvil_ProcessScan_Modules(_In_ PVMM_PROCESS pProcess, _Inout_ POB_MAP pmEvil)
{
    BOOL fBadLdr = TRUE;
    DWORD i;
    PVMM_MAP_MODULEENTRY pe;
    PVMMOB_MAP_MODULE pObModuleMap = NULL;
    if((pProcess->dwPPID == 4) && !memcmp("MemCompression", pProcess->szName, 15)) { return; }
    if(!VmmMap_GetModule(pProcess, &pObModuleMap)) { return; }
    for(i = 0; i < pObModuleMap->cMap; i++) {
        if(pObModuleMap->pMap[i].tp == VMM_MODULE_TP_NORMAL) {
            fBadLdr = FALSE;
            break;
        }
    }
    if(fBadLdr) {
        VmmEvil_AddEvil_NoVadReq(pmEvil, pProcess, VMM_EVIL_TP_PEB_BAD_LDR, pProcess->win.vaPEB32 ? pProcess->win.vaPEB32 : pProcess->win.vaPEB, 0, 0, FALSE);
    }
    if(pProcess->win.EPROCESS.fNoLink) {
        VmmEvil_AddEvil_NoVadReq(pmEvil, pProcess, VMM_EVIL_TP_PROC_NOLINK, pProcess->win.EPROCESS.va, 0, 0, FALSE);
    }
    for(i = 0; i < pObModuleMap->cMap; i++) {
        pe = pObModuleMap->pMap + i;
        if(pe->tp == VMM_MODULE_TP_INJECTED) {
            VmmEvil_AddEvil(pmEvil, pProcess, VMM_EVIL_TP_PE_INJECTED, pe->vaBase, pe->vaBase, 0, FALSE);
        }
        if(!fBadLdr && (pe->tp == VMM_MODULE_TP_NOTLINKED)) {
            VmmEvil_AddEvil(pmEvil, pProcess, VMM_EVIL_TP_PE_NOTLINKED, pe->vaBase, pe->vaBase, 0, FALSE);
        }
    }
    Ob_DECREF(pObModuleMap);
}

/*
* Locate PEB masquerading - i.e. when process image path in user-land differs from the kernel path.
* https://www.ired.team/offensive-security/defense-evasion/masquerading-processes-in-userland-through-_peb
*/
VOID VmmEvil_ProcessScan_PebMasquerade(_In_ PVMM_PROCESS pProcess, _Inout_ POB_MAP pmEvil)
{
    PVMMWIN_USER_PROCESS_PARAMETERS pu = VmmWin_UserProcessParameters_Get(pProcess);
    if(!pu || (pu->cbuImagePathName < 12) || pProcess->pObPersistent->cuszPathKernel < 24) { return; }                                  // length sanity checks
    if(CharUtil_StrEndsWith(pProcess->pObPersistent->uszPathKernel, pu->uszImagePathName + 12, TRUE)) { return; }                       // ends-with
    if(!CharUtil_StrEndsWith(pProcess->pObPersistent->uszPathKernel, pu->uszImagePathName + strlen(pu->uszImagePathName) - 4, TRUE)) { return; }  // file-ending match (remove windows apps)
    VmmEvil_AddEvil_NoVadReq(pmEvil, pProcess, VMM_EVIL_TP_PEB_MASQUERADE, 0, 0, 0, FALSE);
}


/*
* Scan a process for evil. Multiple scans are undertaken. The function may have
* side effects - such as inserting "injected" modules into the process list.
* Function is performance intensive since it performs multiple analysis steps.
*/
VOID VmmEvil_ProcessScan(_In_ PVMM_PROCESS pProcess, _Inout_ POB_MAP pmEvil)
{
    POB_SET psObInjectedPE = NULL;
    if(!pProcess->fUserOnly) { goto fail; }
    if(!(psObInjectedPE = ObSet_New())) { goto fail; }
    // scan image vads for executable memory not matching prototype pages.
    VmmEvil_ProcessScan_VadImageExecuteNoProto(pProcess, pmEvil);
    // update result with execute pages in non image vads.
    // also commit to modules map as injected PE (if possible).
    VmmEvil_ProcessScan_VadNoImageExecute(pProcess, pmEvil, psObInjectedPE);
    VmmWinLdrModule_Initialize(pProcess, psObInjectedPE);
    // update result with interesting module entries.
    VmmEvil_ProcessScan_Modules(pProcess, pmEvil);
    // update with other process-related findings:
    VmmEvil_ProcessScan_PebMasquerade(pProcess, pmEvil);
fail:
    Ob_DECREF(psObInjectedPE);
}

/*
* qsort compare function for sorting evil findings
*/
int VmmEvil_InitializeMap_CmpSort(PVMM_MAP_EVILENTRY a, PVMM_MAP_EVILENTRY b)
{
    if(a->tp != b->tp) {
        return a->tp - b->tp;
    }
    if(a->dwPID != b->dwPID) {
        return a->dwPID - b->dwPID;
    }
    if(a->va != b->va) {
        return (a->va < b->va) ? -1 : 1;
    }
    return 0;
}

/*
* Create VMMOB_MAP_EVIL from a given object manager map.
* CALLER DECREF: return
* -- pmEvil
* -- return
*/
PVMMOB_MAP_EVIL VmmEvil_InitializeMap(_In_ POB_MAP pmEvil)
{
    DWORD i;
    PVMM_MAP_EVILENTRY pe;
    PVMMOB_MAP_EVIL pObEvilMap = NULL;
    pObEvilMap = Ob_Alloc(OB_TAG_MAP_EVIL, 0, sizeof(VMMOB_MAP_EVIL) + ObMap_Size(pmEvil) * sizeof(VMM_MAP_EVILENTRY), NULL, NULL);
    if(!pObEvilMap) { 
        return Ob_Alloc(OB_TAG_MAP_EVIL, LMEM_ZEROINIT, sizeof(VMMOB_MAP_EVIL), NULL, NULL);
    }
    pObEvilMap->tcCreateTime = ctxVmm->tcRefreshMedium;
    pObEvilMap->cMap = ObMap_Size(pmEvil);
    for(i = 0; i < pObEvilMap->cMap; i++) {
        pe = ObMap_GetByIndex(pmEvil, i);
        memcpy(pObEvilMap->pMap + i, pe, sizeof(VMM_MAP_EVILENTRY));
    }
    qsort(pObEvilMap->pMap, pObEvilMap->cMap, sizeof(VMM_MAP_EVILENTRY), (int(*)(void const*, void const*))VmmEvil_InitializeMap_CmpSort);
    return pObEvilMap;
}

BOOL VmmEvil_InitializeProcess(_In_ PVMM_PROCESS pProcess, _In_opt_ POB_MAP pmEvilAll)
{
    DWORD i;
    QWORD qwKey;
    POB_MAP pmObEvil = NULL;
    PVMM_MAP_EVILENTRY pe;
    PVMMOB_MAP_EVIL pEvilMap = NULL;
    if((pProcess->dwState != 0) && !pProcess->fUserOnly) { return FALSE; }
    if(!pProcess->Map.pObEvil) {
        EnterCriticalSection(&pProcess->Map.LockUpdateMapEvil);
        if(!pProcess->Map.pObEvil) {
            if((pmObEvil = ObMap_New(OB_MAP_FLAGS_OBJECT_LOCALFREE))) {
                VmmEvil_ProcessScan(pProcess, pmObEvil);
                pProcess->Map.pObEvil = VmmEvil_InitializeMap(pmObEvil);
            }
        }
        Ob_DECREF_NULL(&pmObEvil);
        LeaveCriticalSection(&pProcess->Map.LockUpdateMapEvil);
    }
    if(!pProcess->Map.pObEvil) { return FALSE; }
    // add to optional all process evil object manager map.
    if(pmEvilAll) {
        pEvilMap = pProcess->Map.pObEvil;
        for(i = 0; i < pEvilMap->cMap; i++) {
            if(pEvilMap->pMap[i].fEvilAllSuppress) { continue; }
            if(!(pe = LocalAlloc(0, sizeof(VMM_MAP_EVILENTRY)))) { continue; }
            memcpy(pe, pEvilMap->pMap + i, sizeof(VMM_MAP_EVILENTRY));
            qwKey = VMM_MAP_EVILENTRY_HASH(pe->dwPID, pe->tp, pe->va);
            ObMap_Push(pmEvilAll, qwKey, pe);
        }
    }
    return TRUE;
}

/*
*   Iterate over all process in a separate async thread. Iterating takes about
*   the same time as when doing it in parallel due to I/O; but serial iteration
*   does not clog worker threads.
*/
DWORD VmmEvil_InitializeAll_ThreadProc(_In_opt_ PVOID pv)
{
    SIZE_T i, cPIDs = 0;
    PDWORD pPIDs = NULL;
    POB_MAP pmObEvilAll = NULL;
    PVMM_PROCESS pObProcess = NULL;
    PVMMOB_MAP_EVIL pObEvilMap = NULL;
    if(!(pmObEvilAll = ObMap_New(OB_MAP_FLAGS_OBJECT_LOCALFREE))) { goto fail; }
    VmmProcessListPIDs(NULL, &cPIDs, 0);
    if(!(pPIDs = LocalAlloc(LMEM_ZEROINIT, cPIDs * sizeof(DWORD)))) { goto fail; }
    VmmProcessListPIDs(pPIDs, &cPIDs, 0);
    for(i = 0; i < cPIDs; i++) {
        ctxVmm->EvilContext.cProgressPercent = min(99, max(1, (BYTE)(i * 100 / cPIDs)));
        if(!(pObProcess = VmmProcessGet(pPIDs[i])) || pObProcess->dwState || !pObProcess->fUserOnly) { continue; }
        VmmEvil_InitializeProcess(pObProcess, pmObEvilAll);
        Ob_DECREF_NULL(&pObProcess);
    }
    pObEvilMap = VmmEvil_InitializeMap(pmObEvilAll);
    ObContainer_SetOb(ctxVmm->pObCMapEvil, pObEvilMap);
    ctxVmm->EvilContext.cProgressPercent = 100;
fail:
    Ob_DECREF(pmObEvilAll);
    Ob_DECREF(pObEvilMap);
    LocalFree(pPIDs);
    return 0;
}

/*
* Initialize the "EVIL" map by running various malware analysis tasks. This
* may have a significant performance impact when running. If a process is
* specified analysis is run for that process in synchronous mode.
* If NULL is specified analysis is run for all processes in async mode.
* Retrieve progress by reading ctxVmm->EvilContext.cProgressPercent.
* CALLER DECREF: return
* -- pProcess
* -- return
*/
PVMMOB_MAP_EVIL VmmEvil_Initialize(_In_opt_ PVMM_PROCESS pProcess)
{
    PVMMOB_MAP_EVIL pObEvilMap = NULL;
    if(ctxVmm->f32 || (ctxVmm->kernel.dwVersionBuild < 9600)) { return NULL; }   // only support 64-bit Win8.1+ for now
    if(pProcess) {
        // single process entry
        if(pProcess->Map.pObEvil) {
            return Ob_INCREF(pProcess->Map.pObEvil);
        }
        VmmEvil_InitializeProcess(pProcess, NULL);
        return Ob_INCREF(pProcess->Map.pObEvil);
    }
    // all process entry
    if((pObEvilMap = ObContainer_GetOb(ctxVmm->pObCMapEvil))) {
        if(pObEvilMap->tcCreateTime == ctxVmm->tcRefreshMedium) { return pObEvilMap; }
        Ob_DECREF_NULL(&pObEvilMap);
    }
    EnterCriticalSection(&ctxVmm->LockMaster);
    if((pObEvilMap = ObContainer_GetOb(ctxVmm->pObCMapEvil))) {
        if(pObEvilMap->tcCreateTime == ctxVmm->tcRefreshMedium) {
            LeaveCriticalSection(&ctxVmm->LockMaster);
            return pObEvilMap;
        }
        Ob_DECREF_NULL(&pObEvilMap);
    }
    if(ctxVmm->EvilContext.cProgressPercent == 100) { ctxVmm->EvilContext.cProgressPercent = 0; }
    if(ctxVmm->EvilContext.cProgressPercent == 0) {
        ctxVmm->EvilContext.cProgressPercent = 1;
        VmmWork(VmmEvil_InitializeAll_ThreadProc, NULL, NULL);
    }
    LeaveCriticalSection(&ctxVmm->LockMaster);
    return NULL;
}

/*
* Initialize the global evil map in a synchronously waiting until it's finished.
*/
VOID VmmEvil_InitializeAll_WaitFinish()
{
    Ob_DECREF(VmmEvil_Initialize(NULL));
    while(ctxVmm->EvilContext.cProgressPercent != 100) {
        Sleep(50);
    }
}