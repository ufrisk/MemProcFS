// vmmwork.h : declarations of the internal MemprocFS 'work' threading solution.
//
// (c) Ulf Frisk, 2022-2023
// Author: Ulf Frisk, pcileech@frizk.net
//

#ifndef __VMMWORK_H__
#define __VMMWORK_H__
#include "vmm.h"

/*
* Initialize the VmmWork sub-system. This should only be done at handle init.
* -- H
* -- return
*/
_Success_(return)
BOOL VmmWork_Initialize(_In_ VMM_HANDLE H);

/*
* Interrupt the VmmWork sub-system (exit threads pre-maturely). This is
* usually done early in the cleanup process before VmmWork_Close() is called.
* -- H
*/
VOID VmmWork_Interrupt(_In_ VMM_HANDLE H);

/*
* Close the VmmWork sub-system. Wait until all worker threads have exited.
* -- H
*/
VOID VmmWork_Close(_In_ VMM_HANDLE H);

#endif /* __VMMWORK_H__ */
