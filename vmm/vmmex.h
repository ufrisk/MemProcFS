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

/*
* Perform additional verification of the config after the initial argument parsing.
* -- H
* -- return
*/
BOOL VmmEx_InitializeVerifyConfig(_In_ VMM_HANDLE H);

/*
* Print the copyright splash information at start-up.
* -- H
*/
VOID VmmEx_InitializePrintSplashCopyright(_In_ VMM_HANDLE H);

/*
* Return the licensed-to string.
* Caller LocalFree: return
* -- return = the licensed-to string as a utf-8 string or NULL on error (no license).
*/
_Success_(return != NULL)
LPSTR VmmEx_License_LicensedTo();

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

/*
* License information.
*/
extern LPCSTR g_VmmEx_szLICENSE;
extern DWORD  g_VmmEx_cbLICENSE;

#endif /* __VMMEX_LIGHT_H__ */

#endif /* VMM_PROFILE_FULL */
