// sysquery.h : definitions of various system queries that may be performed.
//
// (c) Ulf Frisk, 2019-2025
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
* Query the time zone information into a formatted string.
* -- H
* -- uszTimeZone = formatted string representation - ex: 'Eastern Standard Time [UTC-5]'.
* -- fLine = if TRUE, the string will be formatted as a single line.
*/
VOID SysQuery_TimeZoneEx(_In_ VMM_HANDLE H, _Out_writes_(49) LPSTR uszTimeZone, _In_ BOOL fLine);

/*
* Query the computer name.
* -- H
* -- szuComputerName = buffer to receive the computer name.
* -- cbuComputerName = size of the buffer.
* -- return
*/
_Success_(return)
BOOL SysQuery_ComputerName(_In_ VMM_HANDLE H, _Out_writes_(cbuComputerName) LPSTR uszComputerName, _In_ DWORD cbuComputerName);

/*
* Retrieve an exported function address similar to kernel32!GetProcAddress().
* -- H
* -- pProcess
* -- uszModuleName
* -- szFunctionName
* -- return
*/
_Success_(return)
QWORD SysQuery_GetProcAddress(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess, _In_ LPCSTR uszModuleName, _In_ LPCSTR szFunctionName);

#endif /* __SYSQUERY_H__ */
