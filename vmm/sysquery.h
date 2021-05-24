// sysquery.h : definitions of various system queries that may be performed.
//
// (c) Ulf Frisk, 2019-2021
// Author: Ulf Frisk, pcileech@frizk.net
//
#ifndef __SYSQUERY_H__
#define __SYSQUERY_H__
#include "vmm.h"

/*
* Retrieve the current system time as FILETIME.
* -- return
*/
_Success_(return != 0)
QWORD SysQuery_TimeCurrent();

/*
* Query the system for current time zone and its bias in minutes against UCT.
* NB! individual sessions connected remotely may have other time zones.
* -- uszTimeZone = full name text representation - ex: 'Eastern Standard Time'.
* -- piActiveBias = bias against UCT in minutes - ex: (CET=UCT+1=-60).
* -- return
*/
_Success_(return)
BOOL SysQuery_TimeZone(_Out_writes_opt_(32) LPSTR uszTimeZone, _Out_opt_ int *piActiveBias);

#endif /* __SYSQUERY_H__ */
