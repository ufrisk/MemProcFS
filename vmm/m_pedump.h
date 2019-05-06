// m_pedump.h : definitions related to the pedump built-in module.
//
// (c) Ulf Frisk, 2019
// Author: Ulf Frisk, pcileech@frizk.net
//
#ifndef __M_PEDUMP_H__
#define __M_PEDUMP_H__
#include <Windows.h>
#include "vmmdll.h"

/*
* Initialization function for the built-in pedump module.
* -- pPluginRegInfo
*/
VOID M_PEDump_Initialize(_Inout_ PVMMDLL_PLUGIN_REGINFO pPluginRegInfo);

#endif /* __M_PEDUMP_H__ */
