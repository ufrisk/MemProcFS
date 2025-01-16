// m_evil_proc2.c : evil detectors for various process issues #2.
//
// Detections:
//  - PEB_MASQ
//  - PROC_BAD_DTB
//  - PROC_PARENT
//  - PROC_USER
// 
// (c) Ulf Frisk, 2023-2025
// Author: Ulf Frisk, pcileech@frizk.net
//

#include "modules.h"
#include "../vmmwin.h"



//-----------------------------------------------------------------------------
// PROC_PARENT / PROC_BAD_DTB / PROC_USER / PEB_MASQ:
//-----------------------------------------------------------------------------

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

/*
* Locate PEB masquerading - i.e. when process image path in user-land differs from the kernel path.
* https://www.ired.team/offensive-security/defense-evasion/masquerading-processes-in-userland-through-_peb
*/
VOID MEvilProc2_PebMasquerade(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess)
{
    PVMMWIN_USER_PROCESS_PARAMETERS pu = VmmWin_UserProcessParameters_Get(H, pProcess);
    if(!pu || (pu->cbuImagePathName < 12) || pProcess->pObPersistent->cuszPathKernel < 24) { return; }                                  // length sanity checks
    if(CharUtil_StrEndsWith(pProcess->pObPersistent->uszPathKernel, pu->uszImagePathName + 12, TRUE)) { return; }                       // ends-with
    if(!CharUtil_StrEndsWith(pProcess->pObPersistent->uszPathKernel, pu->uszImagePathName + strlen(pu->uszImagePathName) - 4, TRUE)) { return; }  // file-ending match (remove windows apps)
    FcEvilAdd(H, EVIL_PEB_MASQ, pProcess, 0, "");
}

/*
* Some malware may masquerade the proper paging base (DirectoryTableBase) in EPROCESS
* to hide a process page tables. This will result in a running process having invalid
* page tables (0 in MemProcFS implementation).
*/
VOID MEvilProc2_BadDTB(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess)
{
    if(!pProcess->paDTB) {
        FcEvilAdd(H, EVIL_PROC_BAD_DTB, pProcess, pProcess->paDTB_Kernel, "");
    }
}

/*
* Locate well known processes with bad users - i.e. cmd running as system.
*/
VOID MEvilProc2_BadUser(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess)
{
    CHAR uszUserName[18];
    PVMM_PROCESS pObProcessWithToken;
    BOOL fRequireWellKnown, fWellKnown = FALSE;
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
    pObProcessWithToken = pProcess->win.Token ? Ob_INCREF(pProcess) : VmmProcessGetEx(H, NULL, pProcess->dwPID, VMM_FLAG_PROCESS_TOKEN);
    if(pObProcessWithToken && pObProcessWithToken->win.Token && pObProcessWithToken->win.Token->fSidUserValid) {
        if(VmmWinUser_GetName(H, &pObProcessWithToken->win.Token->SidUser.SID, uszUserName, 17, &fWellKnown)) {
            if((fRequireWellKnown && !fWellKnown) || (!fRequireWellKnown && fWellKnown)) {
                FcEvilAdd(H, EVIL_PROC_USER, pProcess, 0, "User:[%s]", uszUserName);
            }
        }
    }
    Ob_DECREF(pObProcessWithToken);
}

/*
* Locate well known processes with bad parents.
*/
VOID MEvilProc2_BadParent(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess)
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
                FcEvilAdd(H, EVIL_PROC_PARENT, pProcess, 0, "ParentProcess:[%s:%i]", pObParentProcess->szName, pObParentProcess->dwPID);
            }
        }
        Ob_DECREF(pObParentProcess);
    }
}



//-----------------------------------------------------------------------------
// COMMON:
//-----------------------------------------------------------------------------

VOID MEvilProc2_DoWork(_In_ VMM_HANDLE H, _In_ VMMDLL_MODULE_ID MID, _In_opt_ PVOID ctxfc)
{
    PVMM_PROCESS pObProcess = NULL;
    while((pObProcess = VmmProcessGetNext(H, pObProcess, 0))) {
        if(H->fAbort) { goto fail; }
        if(pObProcess->dwState || !pObProcess->fUserOnly) { continue; }
        if(FcIsProcessSkip(H, pObProcess)) { continue; }
        MEvilProc2_BadParent(H, pObProcess);
        MEvilProc2_BadUser(H, pObProcess);
        MEvilProc2_BadDTB(H, pObProcess);
        MEvilProc2_PebMasquerade(H, pObProcess);
    }
    VmmLog(H, MID, LOGLEVEL_6_TRACE, "COMPLETED FINDEVIL SCAN");
fail:
    Ob_DECREF(pObProcess);
}

VOID M_Evil_Proc2(_In_ VMM_HANDLE H, _Inout_ PVMMDLL_PLUGIN_REGINFO pRI)
{
    if((pRI->magic != VMMDLL_PLUGIN_REGINFO_MAGIC) || (pRI->wVersion != VMMDLL_PLUGIN_REGINFO_VERSION)) { return; }
    if(pRI->sysinfo.f32 || (pRI->sysinfo.dwVersionBuild < 9600)) { return; }    // only support 64-bit Win8.1+ for now
    // register findevil plugin:
    strcpy_s(pRI->reg_info.uszPathName, 128, "\\findevil\\EvPROC2");
    pRI->reg_info.fRootModule = TRUE;
    pRI->reg_info.fRootModuleHidden = TRUE;
    pRI->reg_fnfc.pfnFindEvil = MEvilProc2_DoWork;
    pRI->pfnPluginManager_Register(H, pRI);
}
