// mm_x64_winpaged.h : definitions related to the x64 windows paging subsystem
//                     (including paged out virtual/compressed virtual memory).
//
// (c) Ulf Frisk, 2019
// Author: Ulf Frisk, pcileech@frizk.net
//
#ifndef __MM_X64_WINPAGED_H__
#define __MM_X64_WINPAGED_H__
#include "vmm.h"

/*
* Decompress compressed memory page stored in the MemCompression process.
* -- vaCompressedData = virtual address in 'MemCompression' to decompress.
* -- cbCompressedData = length of compressed data in 'MemCompression' to decompress.
* -- pbDecompressedPage
* -- return
*/
_Success_(return)
BOOL MmX64WinPaged_MemCompression_DecompressPage(
    _In_ QWORD vaCompressedData,
    _In_opt_ DWORD cbCompressedData,
    _Out_writes_(4096) PBYTE pbDecompressedPage,
    _Out_opt_ PDWORD pcbCompressedData
);

#endif /* __MM_X64_WINPAGED_H__ */
