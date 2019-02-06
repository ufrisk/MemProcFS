// m_status.h : definitions related to the .status built-in module.
//
// (c) Ulf Frisk, 2018-2019
// Author: Ulf Frisk, pcileech@frizk.net
//
#ifndef __M_STATUS_H__
#define __M_STATUS_H__
#include <Windows.h>
#include "vmmdll.h"

/*
* Initialization function for the built-in virt2phys module.
* -- pPluginRegInfo
*/
VOID M_Status_Initialize(_Inout_ PVMMDLL_PLUGIN_REGINFO pPluginRegInfo);

#endif /* __M_STATUS_H__ */
