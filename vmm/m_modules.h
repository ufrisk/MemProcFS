// m_modules.h : definitions related to initialization of built-in modules.
//
// (c) Ulf Frisk, 2018-2020
// Author: Ulf Frisk, pcileech@frizk.net
//
#ifndef __M_MODULES_H__
#define __M_MODULES_H__
#include <Windows.h>
#include "vmmdll.h"

/*
* Initialization function for the build-in virtual file system root folder module.
* -- pPluginRegInfo
*/
VOID M_VfsRoot_Initialize(_Inout_ PVMMDLL_PLUGIN_REGINFO pPluginRegInfo);

/*
* Initialization function for the build-in virtual file system process folder module.
* -- pPluginRegInfo
*/
VOID M_VfsProc_Initialize(_Inout_ PVMMDLL_PLUGIN_REGINFO pPluginRegInfo);

/*
* Initialization function for the built-in handle info module.
* -- pPluginRegInfo
*/
VOID M_HandleInfo_Initialize(_Inout_ PVMMDLL_PLUGIN_REGINFO pPluginRegInfo);

/*
* Initialization function for the built-in file handle and file vad module.
* -- pPluginRegInfo
*/
VOID M_FileHandlesVads_Initialize(_Inout_ PVMMDLL_PLUGIN_REGINFO pPluginRegInfo);

/*
* Initialization function for the built-in LdrModules module.
* -- pPluginRegInfo
*/
VOID M_LdrModules_Initialize(_Inout_ PVMMDLL_PLUGIN_REGINFO pPluginRegInfo);

/*
* Initialization function for the built-in memmap module.
* -- pPluginRegInfo
*/
VOID M_MemMap_Initialize(_Inout_ PVMMDLL_PLUGIN_REGINFO pPluginRegInfo);

/*
* Initialization function for the built-in files/modules module.
* -- pPluginRegInfo
*/
VOID M_FileModules_Initialize(_Inout_ PVMMDLL_PLUGIN_REGINFO pPluginRegInfo);

/*
* Initialization function for the built-in phys2virt module.
* -- pPluginRegInfo
*/
VOID M_Phys2Virt_Initialize(_Inout_ PVMMDLL_PLUGIN_REGINFO pPluginRegInfo);

/*
* Initialization function for the built-in ProcUser module.
* -- pPluginRegInfo
*/
VOID M_ProcUser_Initialize(_Inout_ PVMMDLL_PLUGIN_REGINFO pPluginRegInfo);

/*
* Initialization function for the built-in status module.
* -- pPluginRegInfo
*/
VOID M_Status_Initialize(_Inout_ PVMMDLL_PLUGIN_REGINFO pPluginRegInfo);

/*
* Initialization function for the built-in SysInfo module.
* -- pPluginRegInfo
*/
VOID M_SysInfo_Initialize(_Inout_ PVMMDLL_PLUGIN_REGINFO pPluginRegInfo);

/*
* Initialization function for the built-in SysInfo/Certificates module.
*/
VOID M_SysInfoCert_Initialize(_Inout_ PVMMDLL_PLUGIN_REGINFO pPluginRegInfo);

/*
* Initialization function for the built-in SysInfo/Memory module.
*/
VOID M_SysInfoMem_Initialize(_Inout_ PVMMDLL_PLUGIN_REGINFO pRI);

/*
* Initialization function for the built-in SysInfo/Net module.
*/
VOID M_SysInfoNet_Initialize(_Inout_ PVMMDLL_PLUGIN_REGINFO pPluginRegInfo);

/*
* Initialization function for the built-in SysInfo/Proc module.
*/
VOID M_SysInfoProc_Initialize(_Inout_ PVMMDLL_PLUGIN_REGINFO pPluginRegInfo);

/*
* Initialization function for the built-in thread info module.
* -- pPluginRegInfo
*/
VOID M_ThreadInfo_Initialize(_Inout_ PVMMDLL_PLUGIN_REGINFO pPluginRegInfo);

/*
* Initialization function for the built-in virt2phys module.
* -- pPluginRegInfo
*/
VOID M_Virt2Phys_Initialize(_Inout_ PVMMDLL_PLUGIN_REGINFO pPluginRegInfo);

/*
* Initialization function for the built-in WinReg module.
* -- pPluginRegInfo
*/
VOID M_WinReg_Initialize(_Inout_ PVMMDLL_PLUGIN_REGINFO pPluginRegInfo);

VOID(*g_pfnModulesAllInternal[])(_In_ PVMMDLL_PLUGIN_REGINFO pRegInfo) = {
    M_VfsRoot_Initialize, M_VfsProc_Initialize,
    M_HandleInfo_Initialize, M_FileHandlesVads_Initialize, M_MemMap_Initialize, M_LdrModules_Initialize, M_ThreadInfo_Initialize,
    M_Virt2Phys_Initialize, M_Phys2Virt_Initialize, M_FileModules_Initialize, M_ProcUser_Initialize,
    M_Status_Initialize, M_WinReg_Initialize,
    M_SysInfo_Initialize, M_SysInfoProc_Initialize, M_SysInfoNet_Initialize, M_SysInfoMem_Initialize, M_SysInfoCert_Initialize
};

#endif /* __M_MODULES_H__ */
