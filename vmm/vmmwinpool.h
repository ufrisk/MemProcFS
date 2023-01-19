// vmmwinpool.h : declarations of functionality related to kernel pools.
//
// (c) Ulf Frisk, 2021-2023
// Author: Ulf Frisk, pcileech@frizk.net
//

#ifndef __VMMWINPOOL_H__
#define __VMMWINPOOL_H__
#include "vmm.h"

/*
* Refresh the Pool sub-system.
* -- H
*/
VOID VmmWinPool_Refresh(_In_ VMM_HANDLE H);

/*
* Create an pool map and assign to the global vmm context upon success.
* CALLER DECREF: return
* -- H
* -- fAll = TRUE: retrieve all pools; FALSE: retrieve big page pool only.
* -- return
*/
PVMMOB_MAP_POOL VmmWinPool_Initialize(_In_ VMM_HANDLE H, _In_ BOOL fAll);

#endif /* __VMMWINPOOL_H__ */
