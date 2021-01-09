// vmmwinsvc.h : definitions related to Windows service manager (SCM).
//
// (c) Ulf Frisk, 2020-2021
// Author: Ulf Frisk, pcileech@frizk.net
//
#include "vmm.h"

/*
* Create a service map and assign to the global context upon success.
* CALLER DECREF: return
* -- return
*/
PVMMOB_MAP_SERVICE VmmWinSvc_Initialize();

/*
* Refresh the service map.
*/
VOID VmmWinSvc_Refresh();
