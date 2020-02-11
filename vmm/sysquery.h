// sysquery.h : definitions of various system queries that may be performed.
//
// (c) Ulf Frisk, 2019-2020
// Author: Ulf Frisk, pcileech@frizk.net
//
#ifndef __SYSQUERY_H__
#define __SYSQUERY_H__
#include "vmm.h"

/*
* Query all processes for the minimum create and termination time.
* -- pftMin
* -- pftMax
* -- return
*/
_Success_(return)
BOOL SysQuery_TimeProcessMinMax(_Out_ PQWORD pftMin, _Out_ PQWORD pftMax);

#endif /* __SYSQUERY_H__ */
