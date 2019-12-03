// m_modules.h : definitions related to initialization of built-in modules.
//
// (c) Ulf Frisk, 2018-2019
// Author: Ulf Frisk, pcileech@frizk.net
//
#ifndef __M_MODULES_H__
#define __M_MODULES_H__
#include <Windows.h>
#include "vmmdll.h"

/*
* Initialization function for the built-in handle info module.
* -- pPluginRegInfo
*/
VOID M_HandleInfo_Initialize(_Inout_ PVMMDLL_PLUGIN_REGINFO pPluginRegInfo);

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
* Initialization function for the built-in pedump module.
* -- pPluginRegInfo
*/
VOID M_PEDump_Initialize(_Inout_ PVMMDLL_PLUGIN_REGINFO pPluginRegInfo);

/*
* Initialization function for the built-in phys2virt module.
* -- pPluginRegInfo
*/
VOID M_Phys2Virt_Initialize(_Inout_ PVMMDLL_PLUGIN_REGINFO pPluginRegInfo);

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

#endif /* __M_MODULES_H__ */
