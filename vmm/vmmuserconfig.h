// vmmuserconfig.h : get/set options in a persistent user configuration.
// 
// The user configuration is stored depending on operating system as follows:
// - Windows: HKCU\Software\UlfFrisk\MemProcFS
// - Linux: ~/.memprocfs
//
// (c) Ulf Frisk, 2023-2025
// Author: Ulf Frisk, pcileech@frizk.net
//
#ifndef __VMMUSERCONFIG_H__
#define __VMMUSERCONFIG_H__

#include "oscompatibility.h"

/*
* Delete a key from the user configuration.
*/
VOID VmmUserConfig_Delete(_In_ LPCSTR szKey);

/*
* Retrieve a string value from the user configuration.
* -- szKey
* -- cbValue
* -- szValue
* -- return
*/
_Success_(return)
BOOL VmmUserConfig_GetString(_In_ LPCSTR szKey, _In_ DWORD cbValue, _Out_writes_opt_(cbValue) LPSTR szValue);

/*
* Set a string value in the user configuration.
* -- szKey
* -- szValue
* -- return
*/
_Success_(return)
BOOL VmmUserConfig_SetString(_In_ LPCSTR szKey, _In_ LPCSTR szValue);

/*
* Check if a key exists in the user configuration.
* -- szKey
* -- return
*/
BOOL VmmUserConfig_Exists(_In_ LPCSTR szKey);

/*
* Retrieve a number value from the user configuration.
* -- szKey
* -- pdwValue
* -- return
*/
_Success_(return)
BOOL VmmUserConfig_GetNumber(_In_ LPCSTR szKey, _Out_opt_ PDWORD pdwValue);

/*
* Set a number value in the user configuration.
* -- szKey
* -- dwValue
* -- return
*/
_Success_(return)
BOOL VmmUserConfig_SetNumber(_In_ LPCSTR szKey, _In_ DWORD dwValue);

#endif /* __VMMUSERCONFIG_H__ */
