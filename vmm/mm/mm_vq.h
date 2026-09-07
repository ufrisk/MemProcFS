// mm_vq.h : Windows VirtualQuery region reconstruction.
//
// (c) Ulf Frisk, 2026
// Author: Ulf Frisk, pcileech@frizk.net
//
#ifndef __MM_VQ_H__
#define __MM_VQ_H__
#include "../vmm.h"
#include "../vmmdll.h"

/*
* Query a user address, rounded down to a page, and its matching forward region.
* Windows 7+ x86/PAE/x64 ordinary private, mapped and image allocations are
* supported. Unsupported mappings or missing required metadata return FALSE.
* Normal memory caches apply; querying a live target is not an atomic snapshot.
* -- H
* -- pProcess
* -- va
* -- pInfo = populated only on success, including zeroed reserved fields.
* -- return
*/
_Success_(return)
BOOL MmVqQuery(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess, _In_ QWORD va, _Out_ PVMMDLL_MEMORY_BASIC_INFORMATION pInfo);

#endif /* __MM_VQ_H__ */
