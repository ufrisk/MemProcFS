// vmmproc.h : definitions related to operating system and process parsing of virtual memory
//
// (c) Ulf Frisk, 2018-2023
// Author: Ulf Frisk, pcileech@frizk.net
//
#ifndef __VMMPROC_H__
#define __VMMPROC_H__
#include "vmm.h"

/*
* Refresh functions refreshes aspects of MemProcFS at different intervals.
* Frequency from frequent to less frequent is as:
* 1. VmmProcRefresh_MEM()    = refresh memory cache (except page tables).
* 2. VmmProcRefresh_TLB()    = refresh page table cache.
* 3. VmmProcRefresh_Fast()   = fast refresh incl. partial process refresh.
* 4. VmmProcRefresh_Medium() = medium refresh incl. full process refresh.
* 5. VmmProcRefresh_Slow()   = slow refresh.
* A slower more comprehensive refresh layer does not equal that the lower
* faster refresh layers are run automatically - user has to refresh them too.
*/
_Success_(return) BOOL VmmProcRefresh_MEM(_In_ VMM_HANDLE H);
_Success_(return) BOOL VmmProcRefresh_TLB(_In_ VMM_HANDLE H);
_Success_(return) BOOL VmmProcRefresh_Fast(_In_ VMM_HANDLE H);
_Success_(return) BOOL VmmProcRefresh_Medium(_In_ VMM_HANDLE H);
_Success_(return) BOOL VmmProcRefresh_Slow(_In_ VMM_HANDLE H);

/*
* Tries to automatically identify the operating system given by the supplied
* memory device (fpga hardware or file). If an operating system is successfully
* identified a VMM_CONTEXT will be created and stored within the PCILEECH_CONTEXT.
* If the VMM fails to identify an operating system FALSE is returned.
* -- H
* -- return
*/
BOOL VmmProcInitialize(_In_ VMM_HANDLE H);

#endif /* __VMMPROC_H__ */
