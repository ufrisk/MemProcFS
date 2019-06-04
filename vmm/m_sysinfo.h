// m_sysinfo.h : definitions related to the SysInfo built-in module.
//
// The SysInfo module is responsible for displaying various informational files
// at the path /sysinfo/
//
// Functionality includes:
//   ProcTree - process tree listing showing parent processes - files:
//              "proctree"
//              "proctree-v"
//   Version -  operating system version information - files:
//              "version"
//              "version-major"
//              "version-minor"
//              "version-build"
//
// (c) Ulf Frisk, 2019
// Author: Ulf Frisk, pcileech@frizk.net
//
#ifndef __M_SYSINFO_H__
#define __M_SYSINFO_H__
#include <Windows.h>
#include "vmmdll.h"

/*
* Initialization function for the built-in SysInfo module.
* -- pPluginRegInfo
*/
VOID M_SysInfo_Initialize(_Inout_ PVMMDLL_PLUGIN_REGINFO pPluginRegInfo);

#endif /* __M_SYSINFO_H__ */
