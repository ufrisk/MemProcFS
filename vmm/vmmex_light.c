// vmmex_light.c : MemProcFS extended functionality - light profile.
//
// (c) Ulf Frisk, 2025
// Author: Ulf Frisk, pcileech@frizk.net
//
#ifndef VMM_PROFILE_FULL

#include "vmmex.h"

/*
* Perform additional verification of the config after the initial argument parsing.
* -- H
* -- return
*/
BOOL VmmEx_InitializeVerifyConfig(_In_ VMM_HANDLE H)
{
    return TRUE;
}

/*
* Tries to locate the Directory Table Base by scanning a user-defined range.
* -- H
* -- return
*/
_Success_(return)
BOOL VmmEx_DTB_FindValidate_UserDTBRange(_In_ VMM_HANDLE H)
{
    VmmLog(H, MID_CORE, LOGLEVEL_CRITICAL, "  '-dtb-range' option not supported in open source version.");
    return FALSE;
}

/*
* Placeholder function to satisfy the module interface requirements.
* -- H
* -- pPluginRegInfo
*/
VOID MEX_VOID_Initialize(_In_ VMM_HANDLE H, _Inout_ PVMMDLL_PLUGIN_REGINFO pPluginRegInfo)
{
    ;
}

/*
* Global variable 'g_pfnModulesExAllInternal' used by the plugin manager to load
* 'extended' plugins. In the light implementation this only contains the single
* placeholder module.
*/
VOID(*g_pfnModulesExAllInternal[1])(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_REGINFO pRegInfo) = {
   MEX_VOID_Initialize,
};

#endif /* VMM_PROFILE_FULL */
