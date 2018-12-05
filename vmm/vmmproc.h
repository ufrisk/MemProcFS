// vmmproc.h : definitions related to operating system and process parsing of virtual memory
//
// (c) Ulf Frisk, 2018
// Author: Ulf Frisk, pcileech@frizk.net
//
#ifndef __VMMPROC_H__
#define __VMMPROC_H__
#include "vmm.h"

/*
* Force a refresh of the process list.
* -- fProcessList = partial refresh of processes should be done.
* -- fProcessFull = full refresh of processes should be done.
* -- return
*/
BOOL VmmProc_Refresh(_In_ BOOL fProcessList, _In_ BOOL fProcessFull);

/*
* Load operating system dependant module names, such as parsed from PE or ELF
* into the proper display caches, and also into the memory map.
*/
VOID VmmProc_InitializeModuleNames(_In_ PVMM_PROCESS pProcess);

/*
* Tries to automatically identify the operating system given by the supplied
* memory device (fpga hardware or file). If an operating system is successfully
* identified a VMM_CONTEXT will be created and stored within the PCILEECH_CONTEXT.
* If the VMM fails to identify an operating system FALSE is returned.
* -- return
*/
BOOL VmmProcInitialize();

/*
* Scans the memory for supported operating system structures, such as Windows
* page directory bases and update the ctxMain.cfg with the correct value upon
* success.
* -- return
*/
BOOL VmmProcIdentify();

#endif /* __VMMPROC_H__ */
