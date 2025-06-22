// vmmex.h : MemProcFS extended functionality - full & light profiles.
//
// (c) Ulf Frisk, 2025
// Author: Ulf Frisk, pcileech@frizk.net
//
#ifdef VMM_PROFILE_FULL
#include "ex/vmmex.h"
#else /* VMM_PROFILE_FULL */

#ifndef __VMMEX_LIGHT_H__
#define __VMMEX_LIGHT_H__

#include "vmm.h"

#define VMMEX_VMM_COPYRIGHT_INFORMATION \
    " MemProcFS "VER_COPYRIGHT_STR"\n" \
    " License: GNU Affero General Public License v3.0                               \n" \
    " Contact information: pcileech@frizk.net                                       \n" \
    " MemProcFS:    https://github.com/ufrisk/MemProcFS                             \n" \
    " LeechCore:    https://github.com/ufrisk/LeechCore                             \n" \
    " PCILeech:     https://github.com/ufrisk/pcileech                              \n"

/*
* Perform additional verification of the config after the initial argument parsing.
* -- H
* -- return
*/
BOOL VmmEx_InitializeVerifyConfig(_In_ VMM_HANDLE H);

/*
* Tries to locate the Directory Table Base by scanning a user-defined range.
* -- H
* -- return
*/
_Success_(return)
BOOL VmmEx_DTB_FindValidate_UserDTBRange(_In_ VMM_HANDLE H);

/*
* Global variable 'g_pfnModulesExAllInternal' used by the plugin manager to load
* 'extended' plugins. In the light implementation this only contains the single
* placeholder module.
*/
extern VOID(*g_pfnModulesExAllInternal[1])(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_REGINFO pRegInfo);

#endif /* __VMMEX_LIGHT_H__ */

#endif /* VMM_PROFILE_FULL */
