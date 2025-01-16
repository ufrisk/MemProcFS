// modules_init.h : definitions related to initialization of built-in modules.
//
// (c) Ulf Frisk, 2018-2025
// Author: Ulf Frisk, pcileech@frizk.net
//
#ifndef __M_MODULES_H__
#define __M_MODULES_H__

#include "../vmmdll.h"


/*
* Initialization function for the build-in virtual file system root folder module.
*/
VOID M_VfsRoot_Initialize(_In_ VMM_HANDLE H, _Inout_ PVMMDLL_PLUGIN_REGINFO pPluginRegInfo);

/*
* Initialization function for the build-in virtual file system process folder module.
*/
VOID M_VfsProc_Initialize(_In_ VMM_HANDLE H, _Inout_ PVMMDLL_PLUGIN_REGINFO pPluginRegInfo);

/*
* Initialization function for the build-in virtual file system forensic folder module.
*/
VOID M_VfsFc_Initialize(_In_ VMM_HANDLE H, _Inout_ PVMMDLL_PLUGIN_REGINFO pPluginRegInfo);

/*
* Initialization functions for ROOT modules.
* NB! modules may in some cases be combined ROOT/FORENSIC/PROCESS modules.
*/
VOID M_BDE_Initialize(_In_ VMM_HANDLE H, _Inout_ PVMMDLL_PLUGIN_REGINFO pPluginRegInfo);
VOID M_Conf_Initialize(_In_ VMM_HANDLE H, _Inout_ PVMMDLL_PLUGIN_REGINFO pPluginRegInfo);
VOID M_MiscEventlog_Initialize(_In_ VMM_HANDLE H, _Inout_ PVMMDLL_PLUGIN_REGINFO pPluginRegInfo);
VOID M_MiscProcInfo_Initialize(_In_ VMM_HANDLE H, _Inout_ PVMMDLL_PLUGIN_REGINFO pPluginRegInfo);
VOID M_MiscView_Initialize(_In_ VMM_HANDLE H, _Inout_ PVMMDLL_PLUGIN_REGINFO pPluginRegInfo);
VOID M_Phys2Virt_Initialize(_In_ VMM_HANDLE H, _Inout_ PVMMDLL_PLUGIN_REGINFO pPluginRegInfo);
VOID M_Sys_Initialize(_In_ VMM_HANDLE H, _Inout_ PVMMDLL_PLUGIN_REGINFO pPluginRegInfo);
VOID M_SysCert_Initialize(_In_ VMM_HANDLE H, _Inout_ PVMMDLL_PLUGIN_REGINFO pPluginRegInfo);
VOID M_SysDriver_Initialize(_In_ VMM_HANDLE H, _Inout_ PVMMDLL_PLUGIN_REGINFO pPluginRegInfo);
VOID M_SysMem_Initialize(_In_ VMM_HANDLE H, _Inout_ PVMMDLL_PLUGIN_REGINFO pPluginRegInfo);
VOID M_SysNet_Initialize(_In_ VMM_HANDLE H, _Inout_ PVMMDLL_PLUGIN_REGINFO pPluginRegInfo);
VOID M_SysObj_Initialize(_In_ VMM_HANDLE H, _Inout_ PVMMDLL_PLUGIN_REGINFO pPluginRegInfo);
VOID M_SysPool_Initialize(_In_ VMM_HANDLE H, _Inout_ PVMMDLL_PLUGIN_REGINFO pPluginRegInfo);
VOID M_SysProc_Initialize(_In_ VMM_HANDLE H, _Inout_ PVMMDLL_PLUGIN_REGINFO pPluginRegInfo);
VOID M_SysSvc_Initialize(_In_ VMM_HANDLE H, _Inout_ PVMMDLL_PLUGIN_REGINFO pPluginRegInfo);
VOID M_SysSyscall_Initialize(_In_ VMM_HANDLE H, _Inout_ PVMMDLL_PLUGIN_REGINFO pPluginRegInfo);
VOID M_SysSysinfo_Initialize(_In_ VMM_HANDLE H, _Inout_ PVMMDLL_PLUGIN_REGINFO pPluginRegInfo);
VOID M_SysTask_Initialize(_In_ VMM_HANDLE H, _Inout_ PVMMDLL_PLUGIN_REGINFO pPluginRegInfo);
VOID M_SysUser_Initialize(_In_ VMM_HANDLE H, _Inout_ PVMMDLL_PLUGIN_REGINFO pPluginRegInfo);
VOID M_Virt2Phys_Initialize(_In_ VMM_HANDLE H, _Inout_ PVMMDLL_PLUGIN_REGINFO pPluginRegInfo);
VOID M_WinReg_Initialize(_In_ VMM_HANDLE H, _Inout_ PVMMDLL_PLUGIN_REGINFO pPluginRegInfo);
VOID M_VM_Initialize(_In_ VMM_HANDLE H, _Inout_ PVMMDLL_PLUGIN_REGINFO pPluginRegInfo);

/*
* Initialization functions for FORENSIC related modules.
*/
VOID M_FcCSV_Initialize(_In_ VMM_HANDLE H, _Inout_ PVMMDLL_PLUGIN_REGINFO pPluginRegInfo);
VOID M_FcFile_Initialize(_In_ VMM_HANDLE H, _Inout_ PVMMDLL_PLUGIN_REGINFO pPluginRegInfo);
VOID M_FcFindEvil_Initialize(_In_ VMM_HANDLE H, _Inout_ PVMMDLL_PLUGIN_REGINFO pPluginRegInfo);
VOID M_FcHandle_Initialize(_In_ VMM_HANDLE H, _Inout_ PVMMDLL_PLUGIN_REGINFO pPluginRegInfo);
VOID M_FcJSON_Initialize(_In_ VMM_HANDLE H, _Inout_ PVMMDLL_PLUGIN_REGINFO pPluginRegInfo);
VOID M_FcTimeline_Initialize(_In_ VMM_HANDLE H, _Inout_ PVMMDLL_PLUGIN_REGINFO pPluginRegInfo);
VOID M_FcModule_Initialize(_In_ VMM_HANDLE H, _Inout_ PVMMDLL_PLUGIN_REGINFO pPluginRegInfo);
VOID M_FcNtfs_Initialize(_In_ VMM_HANDLE H, _Inout_ PVMMDLL_PLUGIN_REGINFO pPluginRegInfo);
VOID M_FcPrefetch_Initialize(_In_ VMM_HANDLE H, _Inout_ PVMMDLL_PLUGIN_REGINFO pPluginRegInfo);
VOID M_FcProc_Initialize(_In_ VMM_HANDLE H, _Inout_ PVMMDLL_PLUGIN_REGINFO pPluginRegInfo);
VOID M_FcRegistry_Initialize(_In_ VMM_HANDLE H, _Inout_ PVMMDLL_PLUGIN_REGINFO pPluginRegInfo);
VOID M_FcSys_Initialize(_In_ VMM_HANDLE H, _Inout_ PVMMDLL_PLUGIN_REGINFO pPluginRegInfo);
VOID M_FcThread_Initialize(_In_ VMM_HANDLE H, _Inout_ PVMMDLL_PLUGIN_REGINFO pPluginRegInfo);
VOID M_FcWeb_Initialize(_In_ VMM_HANDLE H, _Inout_ PVMMDLL_PLUGIN_REGINFO pPluginRegInfo);
VOID M_FcYara_Initialize(_In_ VMM_HANDLE H, _Inout_ PVMMDLL_PLUGIN_REGINFO pRI);

/*
* Initalization functions for FINDEVIL related modules.
*/
VOID M_Evil_Kern1(_In_ VMM_HANDLE H, _Inout_ PVMMDLL_PLUGIN_REGINFO pPluginRegInfo);
VOID M_Evil_KernProc1(_In_ VMM_HANDLE H, _Inout_ PVMMDLL_PLUGIN_REGINFO pPluginRegInfo);
VOID M_Evil_Proc1(_In_ VMM_HANDLE H, _Inout_ PVMMDLL_PLUGIN_REGINFO pPluginRegInfo);
VOID M_Evil_Proc2(_In_ VMM_HANDLE H, _Inout_ PVMMDLL_PLUGIN_REGINFO pPluginRegInfo);
VOID M_Evil_Proc3(_In_ VMM_HANDLE H, _Inout_ PVMMDLL_PLUGIN_REGINFO pPluginRegInfo);
VOID M_Evil_Thread1(_In_ VMM_HANDLE H, _Inout_ PVMMDLL_PLUGIN_REGINFO pPluginRegInfo);
VOID M_Evil_AV1(_In_ VMM_HANDLE H, _Inout_ PVMMDLL_PLUGIN_REGINFO pPluginRegInfo);
VOID M_Evil_APC1(_In_ VMM_HANDLE H, _Inout_ PVMMDLL_PLUGIN_REGINFO pPluginRegInfo);

/*
* Initialization functions for PROCESS related modules.
*/
VOID M_ProcConsole_Initialize(_In_ VMM_HANDLE H, _Inout_ PVMMDLL_PLUGIN_REGINFO pPluginRegInfo);
VOID M_ProcFileHandlesVads_Initialize(_In_ VMM_HANDLE H, _Inout_ PVMMDLL_PLUGIN_REGINFO pPluginRegInfo);
VOID M_ProcFileModules_Initialize(_In_ VMM_HANDLE H, _Inout_ PVMMDLL_PLUGIN_REGINFO pPluginRegInfo);
VOID M_ProcHandle_Initialize(_In_ VMM_HANDLE H, _Inout_ PVMMDLL_PLUGIN_REGINFO pPluginRegInfo);
VOID M_ProcHeap_Initialize(_In_ VMM_HANDLE H, _Inout_ PVMMDLL_PLUGIN_REGINFO pPluginRegInfo);
VOID M_ProcLdrModules_Initialize(_In_ VMM_HANDLE H, _Inout_ PVMMDLL_PLUGIN_REGINFO pPluginRegInfo);
VOID M_ProcMemMap_Initialize(_In_ VMM_HANDLE H, _Inout_ PVMMDLL_PLUGIN_REGINFO pPluginRegInfo);
VOID M_ProcMiniDump_Initialize(_In_ VMM_HANDLE H, _Inout_ PVMMDLL_PLUGIN_REGINFO pPluginRegInfo);
VOID M_ProcToken_Initialize(_In_ VMM_HANDLE H, _Inout_ PVMMDLL_PLUGIN_REGINFO pPluginRegInfo);
VOID M_ProcThread_Initialize(_In_ VMM_HANDLE H, _Inout_ PVMMDLL_PLUGIN_REGINFO pPluginRegInfo);
VOID M_Search_Initialize(_In_ VMM_HANDLE H, _Inout_ PVMMDLL_PLUGIN_REGINFO pPluginRegInfo);
VOID M_SearchYara_Initialize(_In_ VMM_HANDLE H, _Inout_ PVMMDLL_PLUGIN_REGINFO pPluginRegInfo);

VOID(*g_pfnModulesAllInternal[])(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_REGINFO pRegInfo) = {
    // core modules
    M_VfsRoot_Initialize,
    M_VfsProc_Initialize,
    M_VfsFc_Initialize,
    // per-process modules
    M_ProcConsole_Initialize,
    M_ProcFileHandlesVads_Initialize,
    M_ProcFileModules_Initialize,
    M_Phys2Virt_Initialize,
    M_ProcHandle_Initialize,
    M_ProcHeap_Initialize,
    M_ProcLdrModules_Initialize,
    M_ProcMemMap_Initialize,
    M_ProcMiniDump_Initialize,
    M_ProcThread_Initialize,
    M_ProcToken_Initialize,
    M_Search_Initialize,
    M_SearchYara_Initialize,
    M_Virt2Phys_Initialize,
    // global modules
    M_BDE_Initialize,
    M_Conf_Initialize,
    M_MiscEventlog_Initialize,
    M_MiscProcInfo_Initialize,
    M_MiscView_Initialize,
    M_Sys_Initialize,
    M_SysDriver_Initialize,
    M_SysMem_Initialize,
    M_SysNet_Initialize,
    M_SysObj_Initialize,
    M_SysPool_Initialize,
    M_SysProc_Initialize,
    M_SysSvc_Initialize,
    M_SysSyscall_Initialize,
    M_SysSysinfo_Initialize,
    M_SysTask_Initialize,
    M_SysUser_Initialize,
    M_WinReg_Initialize,
    M_VM_Initialize,
    // forensic modules
    M_FcCSV_Initialize,
    M_FcFile_Initialize,
    M_FcFindEvil_Initialize,
    M_FcHandle_Initialize,
    M_FcJSON_Initialize,
    M_FcTimeline_Initialize,
    M_FcModule_Initialize,
    M_FcNtfs_Initialize,
    M_FcPrefetch_Initialize,
    M_FcProc_Initialize,
    M_FcRegistry_Initialize,
    M_FcSys_Initialize,
    M_FcThread_Initialize,
    M_FcWeb_Initialize,
    M_FcYara_Initialize,
    // findevil modules
    M_Evil_Kern1,
    M_Evil_KernProc1,
    M_Evil_Proc1,
    M_Evil_Proc2,
    M_Evil_Proc3,
    M_Evil_Thread1,
    M_Evil_AV1,
    M_Evil_APC1,
#ifdef _WIN32
    // windows-only modules:
    M_SysCert_Initialize,           // req: winapi
#endif /* _WIN32 */
};

#endif /* __M_MODULES_H__ */
