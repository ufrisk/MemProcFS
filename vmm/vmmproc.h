// vmmproc.h : definitions related to operating system and process parsing of virtual memory
//
// (c) Ulf Frisk, 2018-2020
// Author: Ulf Frisk, pcileech@frizk.net
//
#ifndef __VMMPROC_H__
#define __VMMPROC_H__
#include "vmm.h"

/*
* Force a refresh of the process list.
* -- fRefreshTotal = full refresh of processes should be done instead of partial.
* -- return
*/
BOOL VmmProc_RefreshProcesses(_In_ BOOL fRefreshTotal);

/*
* Tries to automatically identify the operating system given by the supplied
* memory device (fpga hardware or file). If an operating system is successfully
* identified a VMM_CONTEXT will be created and stored within the PCILEECH_CONTEXT.
* If the VMM fails to identify an operating system FALSE is returned.
* -- return
*/
BOOL VmmProcInitialize();

#endif /* __VMMPROC_H__ */
