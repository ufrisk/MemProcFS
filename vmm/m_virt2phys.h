// m_virt2phys.h : definitions related to the virt2phys built-in module.
//
// (c) Ulf Frisk, 2018-2019
// Author: Ulf Frisk, pcileech@frizk.net
//
#ifndef __M_VIRT2PHYS_H__
#define __M_VIRT2PHYS_H__
#include <Windows.h>
#include "vmmdll.h"

/*
* Initialization function for the built-in virt2phys module.
* -- pPluginRegInfo
*/
VOID M_Virt2Phys_Initialize(_Inout_ PVMMDLL_PLUGIN_REGINFO pPluginRegInfo);

#endif /* __M_VIRT2PHYS_H__ */
