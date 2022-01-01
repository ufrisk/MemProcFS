// vmmwinpool.h : declarations of functionality related to kernel pools.
//
// (c) Ulf Frisk, 2021-2022
// Author: Ulf Frisk, pcileech@frizk.net
//

#ifndef __VMMWINPOOL_H__
#define __VMMWINPOOL_H__
#include "vmm.h"

/*
* Refresh the Pool sub-system.
*/
VOID VmmWinPool_Refresh();

/*
* Create an pool map and assign to the global vmm context upon success.
* CALLER DECREF: return
* -- fAll = TRUE: retrieve all pools; FALSE: retrieve big page pool only.
* -- return
*/
PVMMOB_MAP_POOL VmmWinPool_Initialize(_In_ BOOL fAll);

#endif /* __VMMWINPOOL_H__ */
