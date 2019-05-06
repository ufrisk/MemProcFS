// vmmproc.h : definitions related to operating system and process parsing of virtual memory
//
// (c) Ulf Frisk, 2018-2019
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
* Load operating system dependant module names, such as parsed from PE or ELF
* into the modules map.
*/
VOID VmmProc_ModuleMapInitialize(_In_ PVMM_PROCESS pProcess);

/*
* Retrieve the module map. Map is generated on-demand if not already existing.
* CALLER DECREF: ppObModuleMap
* -- pProcess
* -- ppObModuleMap
* -- return
*/
_Success_(return)
BOOL VmmProc_ModuleMapGet(_In_ PVMM_PROCESS pProcess, _Out_ PVMMOB_MODULEMAP *ppObModuleMap);

/*
* Retrieve a single module map entry and its backing module map (if found).
* CALLER DECREF: ppObModuleMap
* -- pProcess
* -- szModuleName
* -- ppObModuleMap
* -- pModuleMapEntry
* -- return
*/
_Success_(return)
BOOL VmmProc_ModuleMapGetSingleEntry(_In_ PVMM_PROCESS pProcess, _In_ LPSTR szModuleName, _Out_ PVMMOB_MODULEMAP *ppObModuleMap, _Out_ PVMM_MODULEMAP_ENTRY *ppModuleMapEntry);

/*
* Scan additional process information (not already in the initialized modulemap)
* and put the result into the memory map.
*/
VOID VmmProc_ScanTagsMemMap(_In_ PVMM_PROCESS pProcess);

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
