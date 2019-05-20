// m_winreg.h : definitions related to the WinReg built-in module.
//
// (c) Ulf Frisk, 2019
// Author: Ulf Frisk, pcileech@frizk.net
//
#ifndef __M_WINREG_H__
#define __M_WINREG_H__
#include <Windows.h>
#include "vmmdll.h"

/*
* Initialization function for the built-in WinReg module.
* -- pPluginRegInfo
*/
VOID M_WinReg_Initialize(_Inout_ PVMMDLL_PLUGIN_REGINFO pPluginRegInfo);

#endif /* __M_WINREG_H__ */
