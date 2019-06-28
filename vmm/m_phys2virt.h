// m_phys2virt.h : definitions related to the phys2virt built-in module.
//
// (c) Ulf Frisk, 2019
// Author: Ulf Frisk, pcileech@frizk.net
//
#ifndef __M_PHYS2VIRT_H__
#define __M_PHYS2VIRT_H__
#include <Windows.h>
#include "vmmdll.h"

/*
* Initialization function for the built-in phys2virt module.
* -- pPluginRegInfo
*/
VOID M_Phys2Virt_Initialize(_Inout_ PVMMDLL_PLUGIN_REGINFO pPluginRegInfo);

#endif /* __M_PHYS2VIRT_H__ */
