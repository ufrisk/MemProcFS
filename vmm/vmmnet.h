// vmmnet.h : declarations of functionality related to the Windows networking.
//
// (c) Ulf Frisk, 2019-2023
// Author: Ulf Frisk, pcileech@frizk.net
//

#ifndef __VMMNET_H__
#define __VMMNET_H__
#include "vmm.h"

/*
* Create a network connection map and assign to the global context upon success.
* CALLER DECREF: return
* -- H
* -- return
*/
PVMMOB_MAP_NET VmmNet_Initialize(_In_ VMM_HANDLE H);

/*
* Refresh the network connection map.
* -- H
*/
VOID VmmNet_Refresh(_In_ VMM_HANDLE H);

/*
* Close the networking functionality.
* NB! Close() should only be called on vmm exit. To clear internal state plesae
* use function: VmmNet_Refresh().
* -- H
*/
VOID VmmNet_Close(_In_ VMM_HANDLE H);

#endif /* __VMMNET_H__ */
