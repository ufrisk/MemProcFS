// sysquery.h : definitions of various system queries that may be performed.
//
// (c) Ulf Frisk, 2019-2023
// Author: Ulf Frisk, pcileech@frizk.net
//
#ifndef __SYSQUERY_H__
#define __SYSQUERY_H__
#include "vmm.h"

/*
* Retrieve the current system time as FILETIME.
* -- H
* -- return
*/
_Success_(return != 0)
QWORD SysQuery_TimeCurrent(_In_ VMM_HANDLE H);

/*
* Query the system for current time zone and its bias in minutes against UCT.
* NB! individual sessions connected remotely may have other time zones.
* -- H
* -- uszTimeZone = full name text representation - ex: 'Eastern Standard Time'.
* -- piActiveBias = bias against UCT in minutes - ex: (CET=UCT+1=-60).
* -- return
*/
_Success_(return)
BOOL SysQuery_TimeZone(_In_ VMM_HANDLE H, _Out_writes_opt_(32) LPSTR uszTimeZone, _Out_opt_ int *piActiveBias);

/*
* Retrieve an exported function address similar to kernel32!GetProcAddress().
* -- H
* -- pProcess
* -- uszModuleName
* -- szFunctionName
* -- return
*/
_Success_(return)
QWORD SysQuery_GetProcAddress(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess, _In_ LPSTR uszModuleName, _In_ LPSTR szFunctionName);

#endif /* __SYSQUERY_H__ */
