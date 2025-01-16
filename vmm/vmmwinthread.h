// vmmwinthread.h : definitions related to windows threading.
//
// (c) Ulf Frisk, 2024-2025
// Author: Ulf Frisk, pcileech@frizk.net
//
#ifndef __VMMWINTHREAD_H__
#define __VMMWINTHREAD_H__
#include "vmm.h"

/*
* Initialize the thread map for a specific process.
* NB! The threading sub-system is dependent on pdb symbols and may take a small
* amount of time before it's available after system startup.
* -- H
* -- pProcess
* -- return
*/
_Success_(return)
BOOL VmmWinThread_Initialize(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess);



//-----------------------------------------------------------------------------
// CallStack unwinding features for threads in memory dumps
//
// Contributed under BSD 0-Clause License (0BSD)
// Author: MattCore71
//-----------------------------------------------------------------------------

/*
* Refresh the callstack cache.
* -- H
*/
VOID VmmWinThreadCs_Refresh(_In_ VMM_HANDLE H);

/*
* Retrieve the callstack for the specified thread.
* Callback parsing is only supported for x64 user-mode threads.
* Callback parsing is best-effort and is very resource intense since it may
* download a large amounts of PDB symbol data from the Microsoft symbol server.
* Use with caution!
* CALLER DECREF: *ppObCS
* -- H
* -- pProcess
* -- pThread
* -- flags = VMM_FLAG_NOCACHE (do not use cache)
* -- ppObCS
* -- return
*/
_Success_(return)
BOOL VmmWinThreadCs_GetCallstack(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess, _In_ PVMM_MAP_THREADENTRY pThread, _In_ DWORD flags, _Out_ PVMMOB_MAP_THREADCALLSTACK *ppObCS);

#endif /* __VMMWIN_H__ */
