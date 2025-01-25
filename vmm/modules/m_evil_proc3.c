// m_evil_proc3.c : evil detectors for various process issues #3 (kernel issues).
//
// Detections:
//  - PROC_PRIV_DEBUG
// 
// (c) Ulf Frisk, 2023-2025
// Author: Ulf Frisk, pcileech@frizk.net
//

#include "modules.h"
#include "../vmmwin.h"

//-----------------------------------------------------------------------------
// TIME_CHANGE
//-----------------------------------------------------------------------------

typedef struct tdMEVILPROC3_TIMECHANGE {
    QWORD tmSystemCreate;
    BOOL fTimeChanged;
} MEVILPROC3_TIMECHANGE, *PMEVILPROC3_TIMECHANGE;

/*
* Check if the start time of the process is more than 1 minute before the start
* time of the SYSTEM process. This is an indicator of system time change.
*/
VOID MEvilProc3_TimeChange(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess, _Inout_ PMEVILPROC3_TIMECHANGE pTimeChange)
{
    QWORD tmProcessCreate;
    PVMM_PROCESS pObSystemProcess = NULL;
    if(pTimeChange->fTimeChanged) { return; }
    if(!pTimeChange->tmSystemCreate && (pObSystemProcess = VmmProcessGet(H, 4))) {
        pTimeChange->tmSystemCreate = VmmProcess_GetCreateTimeOpt(H, pObSystemProcess);
        Ob_DECREF(pObSystemProcess);
    }
    if(!pTimeChange->tmSystemCreate) { return; }
    tmProcessCreate = VmmProcess_GetCreateTimeOpt(H, pProcess);
    if(tmProcessCreate && ((tmProcessCreate + 60 * 10000000) < pTimeChange->tmSystemCreate)) {
        FcEvilAdd(H, EVIL_TIME_CHANGE, NULL, 0, "");
        pTimeChange->fTimeChanged = TRUE;
    }
}



//-----------------------------------------------------------------------------
// PROC_PRIV_DEBUG
//-----------------------------------------------------------------------------

/*
* Locate processes with SeDebugPrivilege set as present or enabled.
* This is not itself an indicator of evil, but malicious processes may
* make use of the SeDebugPrivilege.
*/
VOID MEvilProc3_SeDebugPrivilege(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess)
{
    if(!pProcess->win.Token) { return; }
    if(!pProcess->win.Token->fSidUserValid || pProcess->win.Token->fSidUserSYSTEM) { return; }
    if(!pProcess->win.Token->Privileges.Present.fSeDebugPrivilege && !pProcess->win.Token->Privileges.Enabled.fSeDebugPrivilege) { return; }
    FcEvilAdd(H, EVIL_PROC_DEBUG, pProcess, 0, "");
}



//-----------------------------------------------------------------------------
// PROC_BASE
//-----------------------------------------------------------------------------

/*
* Checks whether the ImageBaseAddress in the PEB matches the SectionBaseAddress
* in the EPROCESS. If they do not match, it is an indicator of process hollowing.
*/
VOID MEvilProc3_BaseAddressMismatch(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess)
{
    BOOL f32 = H->vmm.f32;
    QWORD vaImageBaseAddress = 0;
    QWORD vaSectionBaseAddress = VMM_EPROCESS_PTR(f32, pProcess, H->vmm.offset.EPROCESS.opt.SectionBaseAddress);
    DWORD oImageBaseAddress = f32 ? offsetof(PEB32, ImageBaseAddress) : offsetof(PEB64, ImageBaseAddress);
    if(!vaSectionBaseAddress) { return; }
    VmmRead(H, pProcess, pProcess->win.vaPEB + 0x10, (PBYTE)&vaImageBaseAddress, f32 ? 4 : 8);
    if(!vaImageBaseAddress) { return; }
    if(vaSectionBaseAddress != vaImageBaseAddress) {
        FcEvilAdd(H, EVIL_PROC_BASEADDR, pProcess, vaImageBaseAddress, "Process base address mismatch: PEB.ImageBaseAddress != EPROCESS.SectionBaseAddress (0x%llx != 0x%llx)", vaImageBaseAddress, vaSectionBaseAddress);
    }
}



//-----------------------------------------------------------------------------
// COMMON:
//-----------------------------------------------------------------------------

VOID MEvilProc3_DoWork(_In_ VMM_HANDLE H, _In_ VMMDLL_MODULE_ID MID, _In_opt_ PVOID ctxfc)
{
    PVMM_PROCESS pObProcess = NULL;
    MEVILPROC3_TIMECHANGE TimeChange = { 0 };
    while((pObProcess = VmmProcessGetNext(H, pObProcess, VMM_FLAG_PROCESS_TOKEN | VMM_FLAG_PROCESS_SHOW_TERMINATED))) {
        if(H->fAbort) { goto fail; }
        if(VmmProcess_IsKernelOnly(pObProcess)) { continue; }
        if(FcIsProcessSkip(H, pObProcess)) { continue; }
        MEvilProc3_SeDebugPrivilege(H, pObProcess);
        MEvilProc3_TimeChange(H, pObProcess, &TimeChange);
        MEvilProc3_BaseAddressMismatch(H, pObProcess);
    }
    VmmLog(H, MID, LOGLEVEL_6_TRACE, "COMPLETED FINDEVIL SCAN");
fail:
    Ob_DECREF(pObProcess);
}

VOID M_Evil_Proc3(_In_ VMM_HANDLE H, _Inout_ PVMMDLL_PLUGIN_REGINFO pRI)
{
    if((pRI->magic != VMMDLL_PLUGIN_REGINFO_MAGIC) || (pRI->wVersion != VMMDLL_PLUGIN_REGINFO_VERSION)) { return; }
    if(pRI->sysinfo.f32 || (pRI->sysinfo.dwVersionBuild < 9600)) { return; }    // only support 64-bit Win8.1+ for now
    // register findevil plugin:
    strcpy_s(pRI->reg_info.uszPathName, 128, "\\findevil\\EvPROC3");
    pRI->reg_info.fRootModule = TRUE;
    pRI->reg_info.fRootModuleHidden = TRUE;
    pRI->reg_fnfc.pfnFindEvil = MEvilProc3_DoWork;
    pRI->pfnPluginManager_Register(H, pRI);
}
