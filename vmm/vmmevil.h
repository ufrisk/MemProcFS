// findevil.h : declarations of functionality related to the "Evil" functionality.
//
// (c) Ulf Frisk, 2020-2023
// Author: Ulf Frisk, pcileech@frizk.net
//

#ifndef __VMMEVIL_H__
#define __VMMEVIL_H__
#include "vmm.h"

/*
* Initialize the "EVIL" map by running various malware analysis tasks. This
* may have a significant performance impact when running. If a process is
* specified analysis is run for that process in synchronous mode.
* If NULL is specified analysis is run for all processes in async mode.
* Retrieve progress by reading H->vmm.EvilContext.cProgressPercent.
* CALLER DECREF: return
* -- H
* -- pProcess
* -- return
*/
PVMMOB_MAP_EVIL VmmEvil_Initialize(_In_ VMM_HANDLE H, _In_opt_ PVMM_PROCESS pProcess);

/*
* Initialize the global evil map in a synchronously waiting until it's finished.
* -- H
*/
VOID VmmEvil_InitializeAll_WaitFinish(_In_ VMM_HANDLE H);

#endif /* __VMMEVIL_H__ */
