// m_evil_proc3.c : evil detectors for various process issues #3 (kernel issues).
//
// Detections:
//  - PROC_PRIV_DEBUG
// 
// (c) Ulf Frisk, 2023-2024
// Author: Ulf Frisk, pcileech@frizk.net
//

#include "modules.h"
#include "../vmmwin.h"



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
// COMMON:
//-----------------------------------------------------------------------------

VOID MEvilProc3_DoWork(_In_ VMM_HANDLE H, _In_ VMMDLL_MODULE_ID MID, _In_opt_ PVOID ctxfc)
{
    PVMM_PROCESS pObProcess = NULL;
    while((pObProcess = VmmProcessGetNext(H, pObProcess, VMM_FLAG_PROCESS_TOKEN | VMM_FLAG_PROCESS_SHOW_TERMINATED))) {
        if(H->fAbort) { goto fail; }
        if(!pObProcess->fUserOnly) { continue; }
        if(FcIsProcessSkip(H, pObProcess)) { continue; }
        MEvilProc3_SeDebugPrivilege(H, pObProcess);
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
