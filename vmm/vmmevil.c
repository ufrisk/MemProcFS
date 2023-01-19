// evil.c : implementation of functionality related to the "Evil" functionality.
//
// (c) Ulf Frisk, 2020-2023
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

#define ROT13H_SYSTEM       0x282da577
#define ROT13H_REGISTRY     0x29a8afbd
#define ROT13H_MEMCOMPRESS  0x5de1c912
#define ROT13H_SMSS         0xdff94c0e
#define ROT13H_CSRSS        0x230d4c0f
#define ROT13H_WINLOGON     0x6c916b9f
#define ROT13H_WININIT      0xedffa2df
#define ROT13H_SERVICES     0x7679dad9
#define ROT13H_SVCHOST      0xe3040ac3
#define ROT13H_SIHOST       0x2903f2af
#define ROT13H_LSASS        0x2bc94c0f
#define ROT13H_USERINIT     0xf2a982de
#define ROT13H_EXPLORER     0x2c99bb9e
#define ROT13H_CMD          0xdfd051ab
#define ROT13H_POWERSHELL   0x1b896fad

#define VMMEVIL_IS_PARENT_PROCESS_STRICT(pChild, pParent)       (pChild && pParent && (pChild->dwPPID == pParent->dwPID) && \
                                                                VmmProcess_GetCreateTimeOpt(H, pChild) && VmmProcess_GetCreateTimeOpt(H, pParent) && \
                                                                (VmmProcess_GetCreateTimeOpt(H, pChild) > VmmProcess_GetCreateTimeOpt(H, pParent)))

typedef struct tdVMMEVIL_INIT_CONTEXT {
    POB_MAP pmEvil;
    POB_STRMAP psmEvil;
} VMMEVIL_INIT_CONTEXT, *PVMMEVIL_INIT_CONTEXT;

/*
* Helper function to create an entry and add it to the pmEvil map.
* The map holds the reference; the returned data must _NOT_ be free'd.
* -- ctxEvil
* -- pProcess
* -- tp
* -- va
* -- vaVadBase
* -- oVadEx
* -- uszText = optional descriptive text for the evil entry.
* -- fEvilAppSuppress = do not show in all-evil (only in process-evil).
*/
_Success_(return != NULL)
PVMM_MAP_EVILENTRY VmmEvil_AddEvil_NoVadReq(
    _Inout_ PVMMEVIL_INIT_CONTEXT ctxEvil,
    _In_ PVMM_PROCESS pProcess,
    _In_ VMM_EVIL_TP tp,
    _In_ QWORD va,
    _In_ QWORD vaVadBase,
    _In_ DWORD oVadEx,
    _In_opt_ LPSTR uszText,
    _In_ BOOL fEvilAllSuppress
) {
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
        peEvil->uszText = NULL;
        peEvil->cbuText = 0;
        if(uszText) {
            ObStrMap_PushPtrUU(ctxEvil->psmEvil, uszText, &peEvil->uszText, &peEvil->cbuText);
        }
        if(!ObMap_Push(ctxEvil->pmEvil, qwKey, peEvil)) {
            LocalFree(peEvil);
            return NULL;
        }
        return peEvil;
    }
    return NULL;
}

_Success_(return != NULL)
PVMM_MAP_EVILENTRY VmmEvil_AddEvil(
    _Inout_ PVMMEVIL_INIT_CONTEXT ctxEvil,
    _In_ PVMM_PROCESS pProcess,
    _In_ VMM_EVIL_TP tp,
    _In_ QWORD va,
    _In_ QWORD vaVadBase,
    _In_ DWORD oVadEx,
    _In_ BOOL fEvilAllSuppress
) {
    return vaVadBase ? VmmEvil_AddEvil_NoVadReq(ctxEvil, pProcess, tp, va, vaVadBase, oVadEx, NULL, fEvilAllSuppress) : NULL;
}

_Success_(return != NULL)
PVMM_MAP_EVILENTRY VmmEvil_AddEvilWithText(
    _Inout_ PVMMEVIL_INIT_CONTEXT ctxEvil,
    _In_ PVMM_PROCESS pProcess,
    _In_ VMM_EVIL_TP tp,
    _In_ QWORD va,
    _In_ BOOL fEvilAllSuppress,
    _In_z_ _Printf_format_string_ LPSTR uszFormat,
    ...
) {
    int csz = 0;
    LPSTR usz = NULL;
    va_list arglist, arglist_copy;
    PVMM_MAP_EVILENTRY peEvil = NULL;
    va_start(arglist, uszFormat);
    va_copy(arglist_copy, arglist);
    csz = _vscprintf(uszFormat, arglist_copy);
    if((csz > 0) && (csz < 0x00100000) && (usz = LocalAlloc(0, (SIZE_T)csz + 1))) {
        csz = _vsnprintf_s(usz, (SIZE_T)csz + 1, _TRUNCATE, uszFormat, arglist);
        if(csz > 0) {
            peEvil = VmmEvil_AddEvil_NoVadReq(ctxEvil, pProcess, tp, va, 0, 0, usz, fEvilAllSuppress);
        } else {
            LocalFree(usz);
        }
    }
    va_end(arglist);
    return peEvil;
}



//-----------------------------------------------------------------------------
// FINDEVIL PROCESS SCANNING FUNCTIONALITY BELOW:
//-----------------------------------------------------------------------------

/*
* Check a single VAD entry for: PRIVATE_EXECUTE and NOIMAGE_EXECUTE.
*/
VOID VmmEvil_ProcessScan_VadNoImageExecuteEntry(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess, _In_ PVMMOB_MAP_VAD pVadMap, _In_ DWORD iVad, _Inout_ PVMMEVIL_INIT_CONTEXT ctxEvil, _Inout_ POB_SET psInjectedPE, _In_ BOOL fEvilAllSuppress)
{
    DWORD iVadEx, cEvilRX = 0, cEvilRWX = 0;
    QWORD cbPE, qwHwPte;
    PVMM_MAP_VADENTRY peVad;
    PVMM_MAP_VADEXENTRY peVadEx;
    PVMMOB_MAP_VADEX pObVadExMap = NULL;
    VMM_EVIL_TP tp;
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
        qwHwPte = (peVadEx->tp == VMM_PTE_TP_HARDWARE) ? peVadEx->pte : 0;
        fPteA = qwHwPte & VMM_MEMMAP_PAGE_A;
        if(fPteA && (qwHwPte & VMM_MEMMAP_PAGE_NX)) { continue; }
        if((fPteA && (qwHwPte & VMM_MEMMAP_PAGE_W)) || (!fPteA && MMVAD_IS_FLAG_W(peVad))) {
            if(cEvilRWX >= VMMEVIL_MAXCOUNT_VAD_EXECUTE) { continue; }
            cEvilRWX++;
            tp = peVad->fPrivateMemory ? VMM_EVIL_TP_VAD_PRIVATE_RWX : VMM_EVIL_TP_VAD_NOIMAGE_RWX;
        } else {
            if(cEvilRX >= VMMEVIL_MAXCOUNT_VAD_EXECUTE) { continue; }
            cEvilRX++;
            tp = peVad->fPrivateMemory ? VMM_EVIL_TP_VAD_PRIVATE_RX : VMM_EVIL_TP_VAD_NOIMAGE_RX;
        }
        VmmEvil_AddEvil(
            ctxEvil,
            pProcess,
            tp,
            peVadEx->va,
            peVad->vaStart,
            iVadEx,
            fEvilAllSuppress
        );
        if((cEvilRWX >= VMMEVIL_MAXCOUNT_VAD_EXECUTE) && (cEvilRX >= VMMEVIL_MAXCOUNT_VAD_EXECUTE)) { break; }
    }
    Ob_DECREF(pObVadExMap);
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
VOID VmmEvil_ProcessScan_VadNoImageExecute(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess, _Inout_ PVMMEVIL_INIT_CONTEXT ctxEvil, _Inout_ POB_SET psInjectedPE)
{
    BOOL fRX, fRWX, fProcSuppressRX, fProcSuppressRWX;
    DWORD iVad, iPte = 0;
    PVMMOB_MAP_PTE pObPteMap = NULL;
    PVMM_MAP_VADENTRY peVad;
    PVMMOB_MAP_VAD pObVadMap = NULL;
    PVMMOB_MAP_VADEX pObVadExMap = NULL;
    if(!VmmMap_GetPte(H, pProcess, &pObPteMap, FALSE)) { goto fail; }
    if(!VmmMap_GetVad(H, pProcess, &pObVadMap, VMM_VADMAP_TP_PARTIAL)) { goto fail; }
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
        // check if vad is p-rwx-
        if(MMVAD_IS_FLAG_P(peVad) && MMVAD_IS_FLAG_R(peVad) && MMVAD_IS_FLAG_W(peVad) && MMVAD_IS_FLAG_X(peVad)) {
            fRX = TRUE,
            fRWX = TRUE;
        }
        // vad has hw executable page -> investigate closer
        if(fRX) {
            VmmEvil_ProcessScan_VadNoImageExecuteEntry(H, pProcess, pObVadMap, iVad, ctxEvil, psInjectedPE, fProcSuppressRX || (fRWX && fProcSuppressRWX));
        }
    }
fail:
    Ob_DECREF(pObPteMap);
    Ob_DECREF(pObVadMap);
}

/*
* verify  
*/
VOID VmmEvil_ProcessScan_VadImageExecuteNoProto_PhysicalPageVerify(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess, _Inout_ PVMMEVIL_INIT_CONTEXT ctxEvil)
{
    BOOL f;
    short i, o, c;
    POB_SET psObRemove = NULL;
    PVMM_MAP_EVILENTRY pe = NULL;
    BYTE pbPage1[0x1000], pbPage2[0x1000];
    if(!(psObRemove = ObSet_New(H))) { return; }
    while((pe = ObMap_GetNext(ctxEvil->pmEvil, pe))) {
        f = VmmRead2(H, NULL, pe->VAD_PATCHED_PE.pa, pbPage1, 0x1000, VMM_FLAG_FORCECACHE_READ) &&
            VmmRead2(H, NULL, pe->VAD_PATCHED_PE.paProto, pbPage2, 0x1000, VMM_FLAG_FORCECACHE_READ) &&
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
        LocalFree(ObMap_Remove(ctxEvil->pmEvil, pe));
    }
    Ob_DECREF(psObRemove);
}

/*
* Locate "patched" executable pages in Image VADs. This is achieved by for each
* active executable page checking its physical address against the address of
* the prototype page. If its possible (i.e. no paged out pages) and there is a
* mismatch then flag the page to the evil map.
*/
VOID VmmEvil_ProcessScan_VadImageExecuteNoProto(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess, _Inout_ PVMMEVIL_INIT_CONTEXT ctxEvil)
{
    QWORD qwHwPte;
    DWORD iVad, iVadEx, cPatch;
    PVMM_MAP_VADENTRY peVad;
    PVMMOB_MAP_VAD pObVadMap = NULL;
    PVMM_MAP_VADEXENTRY peVadEx;
    PVMMOB_MAP_VADEX pObVadExMap = NULL;
    PVMM_MAP_EVILENTRY peEvil;
    POB_SET pspaObPrefetch = NULL;
    if(!(pspaObPrefetch = ObSet_New(H))) { goto fail; }
    if(!VmmMap_GetVad(H, pProcess, &pObVadMap, VMM_VADMAP_TP_PARTIAL)) { goto fail; }
    // 1: fetch VAD_PATCHED_PE by iterating over image VADs
    for(iVad = 0; iVad < pObVadMap->cMap; iVad++) {
        peVad = pObVadMap->pMap + iVad;
        if(!peVad->fImage) { continue; }
        if(!VmmMap_GetVadEx(H, pProcess, &pObVadExMap, VMM_VADMAP_TP_PARTIAL, peVad->cVadExPagesBase, peVad->cVadExPages)) { continue; }
        for(iVadEx = 0, cPatch = 0; (iVadEx < pObVadExMap->cMap) && (cPatch < VMMEVIL_MAXCOUNT_VAD_PATCHED_PE); iVadEx++) {
            peVadEx = pObVadExMap->pMap + iVadEx;
            qwHwPte = (peVadEx->tp == VMM_PTE_TP_HARDWARE) ? peVadEx->pte : 0;
            if(!qwHwPte || (qwHwPte & VMM_MEMMAP_PAGE_NX)) { continue; }
            if(!peVadEx->pa || !peVadEx->proto.pa) { continue; }
            if(peVadEx->pa == peVadEx->proto.pa) { continue; }
            cPatch++;
            peEvil = VmmEvil_AddEvil(
                ctxEvil,
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
        VmmCachePrefetchPages(H, NULL, pspaObPrefetch, 0);
        VmmEvil_ProcessScan_VadImageExecuteNoProto_PhysicalPageVerify(H, pProcess, ctxEvil);
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
VOID VmmEvil_ProcessScan_Modules(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess, _Inout_ PVMMEVIL_INIT_CONTEXT ctxEvil)
{
    BOOL fBadLdr = TRUE;
    DWORD i;
    PVMM_MAP_MODULEENTRY pe;
    PVMMOB_MAP_MODULE pObModuleMap = NULL;
    if((pProcess->dwPPID == 4) && !memcmp("MemCompression", pProcess->szName, 15)) { return; }
    if(!VmmMap_GetModule(H, pProcess, 0, &pObModuleMap)) { return; }
    for(i = 0; i < pObModuleMap->cMap; i++) {
        if(pObModuleMap->pMap[i].tp == VMM_MODULE_TP_NORMAL) {
            fBadLdr = FALSE;
            break;
        }
    }
    if(fBadLdr) {
        VmmEvil_AddEvil_NoVadReq(ctxEvil, pProcess, VMM_EVIL_TP_PEB_BAD_LDR, pProcess->win.vaPEB32 ? pProcess->win.vaPEB32 : pProcess->win.vaPEB, 0, 0, NULL, FALSE);
    }
    if(pProcess->win.EPROCESS.fNoLink) {
        VmmEvil_AddEvil_NoVadReq(ctxEvil, pProcess, VMM_EVIL_TP_PROC_NOLINK, pProcess->win.EPROCESS.va, 0, 0, NULL, FALSE);
    }
    for(i = 0; i < pObModuleMap->cMap; i++) {
        pe = pObModuleMap->pMap + i;
        if(pe->tp == VMM_MODULE_TP_INJECTED) {
            VmmEvil_AddEvil(ctxEvil, pProcess, VMM_EVIL_TP_PE_INJECTED, pe->vaBase, pe->vaBase, 0, FALSE);
        }
        if(!fBadLdr && (pe->tp == VMM_MODULE_TP_NOTLINKED)) {
            VmmEvil_AddEvil(ctxEvil, pProcess, VMM_EVIL_TP_PE_NOTLINKED, pe->vaBase, pe->vaBase, 0, FALSE);
        }
    }
    Ob_DECREF(pObModuleMap);
}

/*
* Locate PEB masquerading - i.e. when process image path in user-land differs from the kernel path.
* https://www.ired.team/offensive-security/defense-evasion/masquerading-processes-in-userland-through-_peb
*/
VOID VmmEvil_ProcessScan_PebMasquerade(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess, _Inout_ PVMMEVIL_INIT_CONTEXT ctxEvil)
{
    PVMMWIN_USER_PROCESS_PARAMETERS pu = VmmWin_UserProcessParameters_Get(H, pProcess);
    if(!pu || (pu->cbuImagePathName < 12) || pProcess->pObPersistent->cuszPathKernel < 24) { return; }                                  // length sanity checks
    if(CharUtil_StrEndsWith(pProcess->pObPersistent->uszPathKernel, pu->uszImagePathName + 12, TRUE)) { return; }                       // ends-with
    if(!CharUtil_StrEndsWith(pProcess->pObPersistent->uszPathKernel, pu->uszImagePathName + strlen(pu->uszImagePathName) - 4, TRUE)) { return; }  // file-ending match (remove windows apps)
    VmmEvil_AddEvil_NoVadReq(ctxEvil, pProcess, VMM_EVIL_TP_PEB_MASQUERADE, 0, 0, 0, NULL, FALSE);
}

/*
* Some malware may masquerade the proper paging base (DirectoryTableBase) in EPROCESS
* to hide a process page tables. This will result in a running process having invalid
* page tables (0 in MemProcFS implementation).
*/
VOID VmmEvil_ProcessScan_BadDTB(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess, _Inout_ PVMMEVIL_INIT_CONTEXT ctxEvil)
{
    if(!pProcess->paDTB) {
        VmmEvil_AddEvil_NoVadReq(ctxEvil, pProcess, VMM_EVIL_TP_PROC_BAD_DTB, pProcess->paDTB_Kernel, 0, 0, NULL, FALSE);
    }
}

/*
* Locate well known processes with bad users - i.e. cmd running as system.
*/
VOID VmmEvil_ProcessScan_BadUser(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess, _Inout_ PVMMEVIL_INIT_CONTEXT ctxEvil)
{
    CHAR uszUserName[18];
    PVMM_PROCESS pObProcessWithToken;
    BOOL fRequireWellKnown, fWellKnown;
    DWORD dwHProcess = CharUtil_Hash32A(pProcess->szName, TRUE);
    switch(dwHProcess) {
        case ROT13H_SYSTEM:
        case ROT13H_REGISTRY:
        case ROT13H_MEMCOMPRESS:
        case ROT13H_SMSS:
        case ROT13H_CSRSS:
        case ROT13H_WINLOGON:
        case ROT13H_WININIT:
        case ROT13H_SERVICES:
        case ROT13H_LSASS:
            fRequireWellKnown = TRUE; break;
        case ROT13H_SIHOST:
        case ROT13H_EXPLORER:
        case ROT13H_POWERSHELL:
        case ROT13H_CMD:
            fRequireWellKnown = FALSE; break;
        default:
            return;
    }
    pObProcessWithToken = pProcess->win.TOKEN.fInitialized ? Ob_INCREF(pProcess) : VmmProcessGetEx(H, NULL, pProcess->dwPID, VMM_FLAG_PROCESS_TOKEN);
    if(pObProcessWithToken && pObProcessWithToken->win.TOKEN.fSidUserValid) {
        if(VmmWinUser_GetName(H, &pObProcessWithToken->win.TOKEN.SidUser.SID, uszUserName, 17, &fWellKnown)) {
            if((fRequireWellKnown && !fWellKnown) || (!fRequireWellKnown && fWellKnown)) {
                VmmEvil_AddEvil_NoVadReq(ctxEvil, pProcess, VMM_EVIL_TP_PROC_USER, 0, 0, 0, NULL, FALSE);
            }
        }
    }
    Ob_DECREF(pObProcessWithToken);
}

/*
* Locate well known processes with bad parents.
*/
VOID VmmEvil_ProcessScan_BadParent(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess, _Inout_ PVMMEVIL_INIT_CONTEXT ctxEvil)
{
    DWORD dwH, dwHProcess;
    BOOL fBad = FALSE;
    PVMM_PROCESS pObParentProcess = NULL;
    if((pObParentProcess = VmmProcessGetEx(H, NULL, pProcess->dwPPID, VMM_FLAG_PROCESS_SHOW_TERMINATED))) {
        if(VMMEVIL_IS_PARENT_PROCESS_STRICT(pProcess, pObParentProcess)) {
            dwH = CharUtil_Hash32A(pObParentProcess->szName, TRUE);
            dwHProcess = CharUtil_Hash32A(pProcess->szName, TRUE);
            switch(dwHProcess) {
                case ROT13H_SYSTEM:
                    fBad = TRUE; break;
                case ROT13H_MEMCOMPRESS:
                case ROT13H_REGISTRY:
                case ROT13H_SMSS:
                    fBad = (dwH != ROT13H_SYSTEM); break;
                case ROT13H_CSRSS:
                case ROT13H_WINLOGON:
                case ROT13H_WININIT:
                    fBad = (dwH != ROT13H_SMSS); break;
                case ROT13H_SERVICES:
                    fBad = (dwH != ROT13H_WININIT); break;
                case ROT13H_SVCHOST:
                    fBad = (dwH != ROT13H_SERVICES); break;
                case ROT13H_SIHOST:
                    fBad = (dwH != ROT13H_SVCHOST); break;
                case ROT13H_LSASS:
                    fBad = (dwH != ROT13H_WININIT); break;
                case ROT13H_USERINIT:
                    fBad = (dwH != ROT13H_WINLOGON); break;
                default:
                    break;
            }
            if(fBad) {
                VmmEvil_AddEvil_NoVadReq(ctxEvil, pProcess, VMM_EVIL_TP_PROC_PARENT, 0, 0, 0, NULL, FALSE);
            }
        }
        Ob_DECREF(pObParentProcess);
    }
}

/*
* Scan a process for evil. Multiple scans are undertaken. The function may have
* side effects - such as inserting "injected" modules into the process list.
* Function is performance intensive since it performs multiple analysis steps.
*/
VOID VmmEvil_ProcessScan(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess, _Inout_ PVMMEVIL_INIT_CONTEXT ctxEvil)
{
    POB_SET psObInjectedPE = NULL;
    if(!pProcess->fUserOnly) { goto fail; }
    if(!(psObInjectedPE = ObSet_New(H))) { goto fail; }    
    // scan image vads for executable memory not matching prototype pages.
    if(H->fAbort) { goto fail; }
    VmmEvil_ProcessScan_VadImageExecuteNoProto(H, pProcess, ctxEvil);
    // update result with execute pages in non image vads.
    // also commit to modules map as injected PE (if possible).
    if(H->fAbort) { goto fail; }
    VmmEvil_ProcessScan_VadNoImageExecute(H, pProcess, ctxEvil, psObInjectedPE);
    VmmWinLdrModule_Initialize(H, pProcess, psObInjectedPE);
    // update result with interesting module entries.
    if(H->fAbort) { goto fail; }
    VmmEvil_ProcessScan_Modules(H, pProcess, ctxEvil);
    // update with other process-related findings:
    if(H->fAbort) { goto fail; }
    VmmEvil_ProcessScan_BadParent(H, pProcess, ctxEvil);
    VmmEvil_ProcessScan_BadUser(H, pProcess, ctxEvil);
    VmmEvil_ProcessScan_BadDTB(H, pProcess, ctxEvil);
    VmmEvil_ProcessScan_PebMasquerade(H, pProcess, ctxEvil);
    // scan for kernel related issues (system process)}
fail:
    Ob_DECREF(psObInjectedPE);
}



//-----------------------------------------------------------------------------
// FINDEVIL KERNEL SCANNING FUNCTIONALITY BELOW:
//-----------------------------------------------------------------------------

/*
* Locate kernel drivers loaded from non standard paths.
*/
VOID VmmEvil_ProcessScan_KDriverPath(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pSystemProcess, _Inout_ PVMMEVIL_INIT_CONTEXT ctxEvil)
{
    // add more allowed paths to the list below:
    LPSTR szPATH_ALLOWLIST[] = {
        "\\SystemRoot\\system32\\DRIVERS\\",
        "\\SystemRoot\\System32\\DriverStore\\",
        "\\SystemRoot\\system32\\ntoskrnl.exe",
        "\\SystemRoot\\System32\\win32k",
        "\\SystemRoot\\system32\\hal.dll",
        "\\??\\C:\\Windows\\system32\\DRIVERS\\",
        "\\??\\C:\\Windows\\System32\\DriverStore\\",
        "\\??\\C:\\ProgramData\\Microsoft\\Windows Defender\\Definition Updates\\",
    };
    POB_MAP pmObModuleByVA = NULL;
    PVMMOB_MAP_MODULE pObModuleMap = NULL;
    PVMMOB_MAP_KDRIVER pObDriverMap = NULL;
    PVMM_MAP_KDRIVERENTRY peDriver;
    PVMM_MAP_MODULEENTRY peModule;
    DWORD iDriver, iPathAllow;
    BOOL fOK;
    if(!VmmMap_GetKDriver(H, &pObDriverMap)) { goto fail; }
    if(!VmmMap_GetModule(H, pSystemProcess, 0, &pObModuleMap)) { goto fail; }
    if(!VmmMap_GetModuleEntryEx3(H, pObModuleMap, &pmObModuleByVA)) { goto fail; }
    for(iDriver = 0; iDriver < pObDriverMap->cMap; iDriver++) {
        peDriver = pObDriverMap->pMap + iDriver;
        peModule = ObMap_GetByKey(pmObModuleByVA, peDriver->vaStart);
        if(!peModule) {
            if(CharUtil_StrStartsWith(peDriver->uszPath, "\\FileSystem\\RAW", TRUE)) { continue; }
            // evil: driver has no linked module:
            VmmEvil_AddEvilWithText(ctxEvil, pSystemProcess, VMM_EVIL_TP_DRIVER_PATH, peDriver->va, FALSE, "Driver:[%s] Module:NOT_FOUND", peDriver->uszName);
            VmmLog(H, MID_EVIL, LOGLEVEL_5_DEBUG, "DRIVER_PATH: Driver:[%s] Module:NOT_FOUND", peDriver->uszName);
            continue;
        }
        fOK = FALSE;
        for(iPathAllow = 0; iPathAllow < (sizeof(szPATH_ALLOWLIST) / sizeof(LPCSTR)); iPathAllow++) {
            if(CharUtil_StrStartsWith(peModule->uszFullName, szPATH_ALLOWLIST[iPathAllow], TRUE)) {
                fOK = TRUE;
                break;
            }
        }
        if(fOK) { continue; }
        // evil: driver module not loaded from path in allowlist:
        VmmEvil_AddEvilWithText(ctxEvil, pSystemProcess, VMM_EVIL_TP_DRIVER_PATH, peDriver->va, FALSE, "Driver:[%s] Module:[%s]", peDriver->uszName, peModule->uszFullName);
        VmmLog(H, MID_EVIL, LOGLEVEL_5_DEBUG, "DRIVER_PATH: Driver:[%s] Module:[%s] ", peDriver->uszName, peModule->uszFullName);
    }
fail:
    Ob_DECREF(pmObModuleByVA);
    Ob_DECREF(pObModuleMap);
    Ob_DECREF(pObDriverMap);
}

/*
* Scan kernel structures for evil.
* Function is performance intensive since it performs multiple analysis steps.
*/
VOID VmmEvil_KernelScan(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pSystemProcess, _Inout_ PVMMEVIL_INIT_CONTEXT ctxEvil)
{
    if(H->fAbort) { return; }
    VmmEvil_ProcessScan_KDriverPath(H, pSystemProcess, ctxEvil);
    VmmLog(H, MID_EVIL, LOGLEVEL_6_TRACE, "COMPLETED_KERNEL_SCAN");
}


//-----------------------------------------------------------------------------
// FINDEVIL GENERAL INITIALIZATION FUNCTIONALITY BELOW:
//-----------------------------------------------------------------------------

/*
* qsort compare function for sorting evil findings
*/
int VmmEvil_InitializeMap_CmpSort(PVMM_MAP_EVILENTRY a, PVMM_MAP_EVILENTRY b)
{
    QWORD v_a, v_b;
    if(a->tp != b->tp) {
        return a->tp - b->tp;
    }
    if(a->dwPID != b->dwPID) {
        return a->dwPID - b->dwPID;
    }
    if(a->va != b->va) {
        return (a->va < b->va) ? -1 : 1;
    }
    v_a = a->VAD_PATCHED_PE.pa + a->VAD_PATCHED_PE.paProto + a->VAD_PATCHED_PE.wPatchOffset + a->oVadEx;
    v_b = b->VAD_PATCHED_PE.pa + b->VAD_PATCHED_PE.paProto + b->VAD_PATCHED_PE.wPatchOffset + b->oVadEx;
    if(v_a != v_b) {
        return (v_a < v_b) ? -1 : 1;
    }
    return 0;
}

VOID VmmEvil_CleanupCB(_In_ PVOID pOb)
{
    PVMMOB_MAP_EVIL pMapEvil = (PVMMOB_MAP_EVIL)pOb;
    LocalFree(pMapEvil->pbMultiText);
}

/*
* Create VMMOB_MAP_EVIL from a given object manager map.
* CALLER DECREF: return
* -- H
* -- ctx
* -- return
*/
PVMMOB_MAP_EVIL VmmEvil_InitializeMap(_In_ VMM_HANDLE H, _In_ PVMMEVIL_INIT_CONTEXT ctx)
{
    DWORD i;
    PVMM_MAP_EVILENTRY pe;
    PVMMOB_MAP_EVIL pObEvilMap = NULL;
    pObEvilMap = Ob_AllocEx(H, OB_TAG_MAP_EVIL, 0, sizeof(VMMOB_MAP_EVIL) + ObMap_Size(ctx->pmEvil) * sizeof(VMM_MAP_EVILENTRY), VmmEvil_CleanupCB, NULL);
    if(pObEvilMap && !ObStrMap_FinalizeAllocU_DECREF_NULL(&ctx->psmEvil, &pObEvilMap->pbMultiText, &pObEvilMap->cMap)) {
        Ob_DECREF(pObEvilMap);
        pObEvilMap = NULL;
    }
    if(!pObEvilMap) { 
        return Ob_AllocEx(H, OB_TAG_MAP_EVIL, LMEM_ZEROINIT, sizeof(VMMOB_MAP_EVIL), NULL, NULL);
    }
    pObEvilMap->tcCreateTime = H->vmm.tcRefreshMedium;
    pObEvilMap->cMap = ObMap_Size(ctx->pmEvil);
    for(i = 0; i < pObEvilMap->cMap; i++) {
        pe = ObMap_GetByIndex(ctx->pmEvil, i);
        memcpy(pObEvilMap->pMap + i, pe, sizeof(VMM_MAP_EVILENTRY));
    }
    qsort(pObEvilMap->pMap, pObEvilMap->cMap, sizeof(VMM_MAP_EVILENTRY), (int(*)(void const*, void const*))VmmEvil_InitializeMap_CmpSort);
    return pObEvilMap;
}

BOOL VmmEvil_InitializeProcess(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess, _In_opt_ PVMMEVIL_INIT_CONTEXT ctxEvilAll)
{
    BOOL fResult = FALSE;
    DWORD i;
    QWORD qwKey;
    PVMM_MAP_EVILENTRY pe;
    PVMMOB_MAP_EVIL pEvilMap = NULL;
    VMMEVIL_INIT_CONTEXT ctxInit = { 0 };
    if((pProcess->dwState != 0) && !pProcess->fUserOnly) { goto fail; }
    if(!pProcess->Map.pObEvil) {
        if(!(ctxInit.pmEvil = ObMap_New(H, OB_MAP_FLAGS_OBJECT_LOCALFREE))) { goto fail; }
        if(!(ctxInit.psmEvil = ObStrMap_New(H, OB_STRMAP_FLAGS_CASE_SENSITIVE))) { goto fail; }
        EnterCriticalSection(&pProcess->Map.LockUpdateMapEvil);
        if(!pProcess->Map.pObEvil) {
            if(pProcess->dwPID == 4) {
                VmmEvil_KernelScan(H, pProcess, &ctxInit);
            } else {
                VmmEvil_ProcessScan(H, pProcess, &ctxInit);
            }
            pProcess->Map.pObEvil = VmmEvil_InitializeMap(H, &ctxInit);
        }
        LeaveCriticalSection(&pProcess->Map.LockUpdateMapEvil);
    }
    if(!pProcess->Map.pObEvil) { goto fail; }
    // add to optional all process evil object manager map.
    if(ctxEvilAll) {
        pEvilMap = pProcess->Map.pObEvil;
        for(i = 0; i < pEvilMap->cMap; i++) {
            if(pEvilMap->pMap[i].fEvilAllSuppress) { continue; }
            if(!(pe = LocalAlloc(0, sizeof(VMM_MAP_EVILENTRY)))) { continue; }
            memcpy(pe, pEvilMap->pMap + i, sizeof(VMM_MAP_EVILENTRY));
            qwKey = VMM_MAP_EVILENTRY_HASH(pe->dwPID, pe->tp, pe->va);
            ObStrMap_PushPtrUU(ctxEvilAll->psmEvil, pEvilMap->pMap[i].uszText, &pe->uszText, &pe->cbuText);
            ObMap_Push(ctxEvilAll->pmEvil, qwKey, pe);
        }
    }
    fResult = TRUE;
fail:
    Ob_DECREF(ctxInit.pmEvil);
    Ob_DECREF(ctxInit.psmEvil);
    return fResult;
}

/*
*   Iterate over all process in a separate async thread. Iterating takes about
*   the same time as when doing it in parallel due to I/O; but serial iteration
*   does not clog worker threads.
*/
VOID VmmEvil_InitializeAll_ThreadProc(_In_ VMM_HANDLE H, _In_ QWORD qwNotUsed)
{
    SIZE_T i, cPIDs = 0;
    PDWORD pPIDs = NULL;
    PVMM_PROCESS pObProcess = NULL;
    PVMMOB_MAP_EVIL pObEvilMap = NULL;
    VMMEVIL_INIT_CONTEXT ctxInit = { 0 };
    if(!(ctxInit.pmEvil = ObMap_New(H, OB_MAP_FLAGS_OBJECT_LOCALFREE))) { goto fail; }
    if(!(ctxInit.psmEvil = ObStrMap_New(H, OB_STRMAP_FLAGS_CASE_SENSITIVE))) { goto fail; }
    VmmProcessListPIDs(H, NULL, &cPIDs, 0);
    if(!(pPIDs = LocalAlloc(LMEM_ZEROINIT, cPIDs * sizeof(DWORD)))) { goto fail; }
    VmmProcessListPIDs(H, pPIDs, &cPIDs, 0);
    for(i = 0; (i < cPIDs) && !H->fAbort; i++) {
        H->vmm.EvilContext.cProgressPercent = min(99, max(1, (BYTE)(i * 100 / cPIDs)));
        if((pObProcess = VmmProcessGet(H, pPIDs[i]))) {
            if(!pObProcess->dwState && (pObProcess->fUserOnly || (pObProcess->dwPID == 4))) {
                VmmEvil_InitializeProcess(H, pObProcess, &ctxInit);
            }
            Ob_DECREF_NULL(&pObProcess);
        }
    }
    pObEvilMap = VmmEvil_InitializeMap(H, &ctxInit);
    ObContainer_SetOb(H->vmm.pObCMapEvil, pObEvilMap);
    H->vmm.EvilContext.cProgressPercent = 100;
fail:
    Ob_DECREF(ctxInit.pmEvil);
    Ob_DECREF(ctxInit.psmEvil);
    Ob_DECREF(pObEvilMap);
    LocalFree(pPIDs);
}

/*
* Initialize the "EVIL" map by running various malware analysis tasks. This
* may have a significant performance impact when running. If a process is
* specified analysis is run for that process in synchronous mode.
* If NULL is specified analysis is run for all processes in async mode.
* Retrieve progress by reading H->vmm.EvilContext.cProgressPercent.
* CALLER DECREF: return
* -- H
* -- pProcess
* -- return
*/
PVMMOB_MAP_EVIL VmmEvil_Initialize(_In_ VMM_HANDLE H, _In_opt_ PVMM_PROCESS pProcess)
{
    PVMMOB_MAP_EVIL pObEvilMap = NULL;
    if(H->vmm.f32 || (H->vmm.kernel.dwVersionBuild < 9600)) { return NULL; }   // only support 64-bit Win8.1+ for now
    if(pProcess) {
        // single process entry
        if(pProcess->Map.pObEvil) {
            return Ob_INCREF(pProcess->Map.pObEvil);
        }
        VmmEvil_InitializeProcess(H, pProcess, NULL);
        return Ob_INCREF(pProcess->Map.pObEvil);
    }
    // all process entry
    if((pObEvilMap = ObContainer_GetOb(H->vmm.pObCMapEvil))) {
        if(pObEvilMap->tcCreateTime == H->vmm.tcRefreshMedium) { return pObEvilMap; }
        Ob_DECREF_NULL(&pObEvilMap);
    }
    EnterCriticalSection(&H->vmm.LockMaster);
    if((pObEvilMap = ObContainer_GetOb(H->vmm.pObCMapEvil))) {
        if(pObEvilMap->tcCreateTime == H->vmm.tcRefreshMedium) {
            LeaveCriticalSection(&H->vmm.LockMaster);
            return pObEvilMap;
        }
        Ob_DECREF_NULL(&pObEvilMap);
    }
    if(H->vmm.EvilContext.cProgressPercent == 100) { H->vmm.EvilContext.cProgressPercent = 0; }
    if(H->vmm.EvilContext.cProgressPercent == 0) {
        H->vmm.EvilContext.cProgressPercent = 1;
        VmmWork_Value(H, VmmEvil_InitializeAll_ThreadProc, 0, 0, VMMWORK_FLAG_PRIO_NORMAL);
    }
    LeaveCriticalSection(&H->vmm.LockMaster);
    return NULL;
}

/*
* Initialize the global evil map in a synchronously waiting until it's finished.
* -- H
*/
VOID VmmEvil_InitializeAll_WaitFinish(_In_ VMM_HANDLE H)
{
    Ob_DECREF(VmmEvil_Initialize(H, NULL));
    while(!H->fAbort && (H->vmm.EvilContext.cProgressPercent != 100)) {
        Sleep(50);
    }
}