// findevil.h : declarations of functionality related to the "Evil" functionality.
//
// (c) Ulf Frisk, 2020-2021
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
* Retrieve progress by reading ctxVmm->EvilContext.cProgressPercent.
* CALLER DECREF: return
* -- pProcess
* -- return
*/
PVMMOB_MAP_EVIL VmmEvil_Initialize(_In_opt_ PVMM_PROCESS pProcess);

/*
* Initialize the global evil map in a synchronously waiting until it's finished.
*/
VOID VmmEvil_InitializeAll_WaitFinish();

#endif /* __VMMEVIL_H__ */
