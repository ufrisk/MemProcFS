// m_ldrmodules.h : definitions related to the ldrmodules built-in module.
//
// (c) Ulf Frisk, 2018-2019
// Author: Ulf Frisk, pcileech@frizk.net
//
#ifndef __M_LDRMODULES_H__
#define __M_LDRMODULES_H__
#include <Windows.h>
#include "vmmdll.h"

/*
* Initialization function for the built-in ldrmodules module.
* -- pPluginRegInfo
*/
VOID M_LdrModules_Initialize(_Inout_ PVMMDLL_PLUGIN_REGINFO pPluginRegInfo);

#endif /* __M_LDRMODULES_H__ */
