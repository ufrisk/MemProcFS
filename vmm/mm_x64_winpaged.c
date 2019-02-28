// mm_x64_winpaged.c : implementation related to the x64 windows paging subsystem
//                     (including paged out virtual/compressed virtual memory).
//
// (c) Ulf Frisk, 2019
// Author: Ulf Frisk, pcileech@frizk.net
//
#include "mm_x64_winpaged.h"

#define COMPRESS_ALGORITHM_INVALID      0
#define COMPRESS_ALGORITHM_NULL         1
#define COMPRESS_ALGORITHM_MSZIP        2
#define COMPRESS_ALGORITHM_XPRESS       3
#define COMPRESS_ALGORITHM_XPRESS_HUFF  4
#define COMPRESS_ALGORITHM_LZMS         5
#define COMPRESS_ALGORITHM_MAX          6
#define COMPRESS_RAW             (1 << 29)

_Success_(return)
BOOL MmX64WinPaged_MemCompression_DecompressPage(_In_ QWORD vaCompressedData, _In_opt_ DWORD cbCompressedData, _Out_writes_(4096) PBYTE pbDecompressedPage, _Out_opt_ PDWORD pcbCompressedData)
{
    BOOL result = FALSE;
    DWORD i, cbReadCompressedData = 0, cbDecompressed = 0;
    BYTE pbCompressed[0x1000] = { 0 };
    PVMM_PROCESS pObProcess = NULL;
    if(pcbCompressedData) { *pcbCompressedData = 0; }
    if(!ctxVmm->fn.RtlDecompressBuffer) { return FALSE; }
    if(cbCompressedData > 0x1000) { return FALSE; }
    if(!ctxVmm->kernel.dwPidMemCompression) { return FALSE; }
    if(!(pObProcess = VmmProcessGet(ctxVmm->kernel.dwPidMemCompression))) { return FALSE; }
    // buffer size specified - use value!
    if(cbCompressedData) {
        result =
            VmmRead(pObProcess, vaCompressedData, pbCompressed, cbCompressedData) &&
            (VMM_STATUS_SUCCESS == ctxVmm->fn.RtlDecompressBuffer(COMPRESS_ALGORITHM_XPRESS, pbDecompressedPage, 0x1000, pbCompressed, cbCompressedData, &cbDecompressed)) &&
            (cbDecompressed == 0x1000);
        VmmOb_DECREF(pObProcess); pObProcess = NULL;
        if(pcbCompressedData) { *pcbCompressedData = cbCompressedData; }
        return result;
    }
    // buffer not specified - try auto-detect!
    VmmReadEx(pObProcess, vaCompressedData, pbCompressed, 0x1000, &cbReadCompressedData, VMM_FLAG_ZEROPAD_ON_FAIL);
    VmmOb_DECREF(pObProcess); pObProcess = NULL;
    if(cbReadCompressedData < 0x10) { return FALSE; }
    for(i = 0x10; i < 0x1000; i++) {
        result =
            (VMM_STATUS_SUCCESS == ctxVmm->fn.RtlDecompressBuffer(COMPRESS_ALGORITHM_XPRESS, pbDecompressedPage, 0x1000, pbCompressed, i, &cbDecompressed)) &&
            (cbDecompressed == 0x1000);
        if(result) {
            if(pcbCompressedData) { *pcbCompressedData = i; }
            return TRUE;
        }
    }
    return FALSE;
}
