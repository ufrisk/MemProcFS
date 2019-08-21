// mm_x64_page_win.h : definitions related to the x64 windows paging subsystem
//                     (including paged out virtual/compressed virtual memory).
//
// (c) Ulf Frisk, 2019
// Author: Ulf Frisk, pcileech@frizk.net
//
#ifndef __MM_X64_PAGE_WIN_H__
#define __MM_X64_PAGE_WIN_H__
#include "vmm.h"

/*
* Scatter read paged out virtual memory. Non contiguous 4096-byte pages.
* -- pProcess
* -- ppMEMsPaged
* -- cpMEMsPaged
*/
VOID MmX64PageWin_ReadScatterPaged(
    _In_ PVMM_PROCESS pProcess,
    _Inout_ PPMEM_IO_SCATTER_HEADER ppMEMsPaged,
    _In_ DWORD cpMEMsPaged
);

#endif /* __MM_X64_PAGE_WIN_H__ */
