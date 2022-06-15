// vmmheap.h : declarations of functionality related to user-mode process heaps.
//
// (c) Ulf Frisk, 2022
// Author: Ulf Frisk, pcileech@frizk.net
//

#ifndef __VMMHEAP_H__
#define __VMMHEAP_H__
#include "vmm.h"

/*
* Initialize the heap map containing information about the process heaps in the
* specific process. This is performed by a PEB walk/scan of in-process memory
* structures. This may be unreliable if a process is obfuscated or tampered.
* -- pProcess
* -- return
*/
BOOL VmmHeap_Initialize(_In_ PVMM_PROCESS pProcess);

/*
* Refresh any cached heap allocation maps.
*/
VOID VmmHeapAlloc_Refresh();

/*
* Retrive the heap allocation map for the specific heap.
* The map is cached up until a total process refresh is made (medium refresh).
* CALLER DECREF: return
* -- pProcess
* -- vaHeap = va of heap or heap id.
* -- return
*/
PVMMOB_MAP_HEAPALLOC VmmHeapAlloc_Initialize(_In_ PVMM_PROCESS pProcess, _In_opt_ QWORD vaHeap);

#endif /* __VMMHEAP_H__ */
