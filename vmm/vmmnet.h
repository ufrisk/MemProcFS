// vmmnet.h : declarations of functionality related to the Windows networking.
//
// (c) Ulf Frisk, 2019-2021
// Author: Ulf Frisk, pcileech@frizk.net
//

#ifndef __VMMNET_H__
#define __VMMNET_H__
#include "vmm.h"

/*
* Create a network connection map and assign to the global context upon success.
* CALLER DECREF: return
* -- return
*/
PVMMOB_MAP_NET VmmNet_Initialize();

/*
* Refresh the network connection map.
*/
VOID VmmNet_Refresh();

/*
* Close the networking functionality.
* NB! Close() should only be called on vmm exit. To clear internal state plesae
* use function: VmmNet_Refresh().
*/
VOID VmmNet_Close();

#endif /* __VMMNET_H__ */
