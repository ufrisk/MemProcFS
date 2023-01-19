// vmmwinsvc.h : definitions related to Windows service manager (SCM).
//
// (c) Ulf Frisk, 2020-2023
// Author: Ulf Frisk, pcileech@frizk.net
//
#include "vmm.h"

/*
* Create a service map and assign to the global context upon success.
* CALLER DECREF: return
* -- H
* -- return
*/
PVMMOB_MAP_SERVICE VmmWinSvc_Initialize(_In_ VMM_HANDLE H);

/*
* Refresh the service map.
* -- H
*/
VOID VmmWinSvc_Refresh(_In_ VMM_HANDLE H);
