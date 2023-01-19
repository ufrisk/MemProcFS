// ob_compressed.c : implementation of object manager compression functionality.
//
// Implements data compression as an object manager object.
// Data may optionally be cached.
//
// The compressed data object (ObCompressed) is thread safe.
// The ObCompressed is an object manager object and must be DECREF'ed when required.
//
// (c) Ulf Frisk, 2021-2023
// Author: Ulf Frisk, pcileech@frizk.net
//
#include "ob.h"

#define OB_COMPRESSED_IS_VALID(p)               (p && (p->ObHdr._magic2 == OB_HEADER_MAGIC) && (p->ObHdr._magic1 == OB_HEADER_MAGIC) && (p->ObHdr._tag == OB_TAG_CORE_COMPRESSED))

typedef struct tdOB_COMPRESSED {
    OB ObHdr;
    SRWLOCK LockSRW;
    QWORD qwCacheKey;
    DWORD cbUncompressed;
    DWORD cbCompressed;
    PBYTE pbCompressed;
    USHORT usRtlCompressionFormat;
    POB_CACHEMAP pcm;
} OB_COMPRESSED, *POB_COMPRESSED;

#define OB_COMPRESSED_CALL_SYNCHRONIZED_IMPLEMENTATION_EXCLUSIVE(pm, RetTp, RetValFail, fn) {   \
    if(!OB_COMPRESSED_IS_VALID(pm)) { return RetValFail; }                              \
    RetTp retVal;                                                                       \
    AcquireSRWLockExclusive(&pm->LockSRW);                                              \
    retVal = fn;                                                                        \
    ReleaseSRWLockExclusive(&pm->LockSRW);                                              \
    return retVal;                                                                      \
}

#ifdef _WIN32

#include <VersionHelpers.h>

typedef NTSTATUS WINAPI OB_COMPRESSED_RtlGetCompressionWorkSpaceSize(
    USHORT CompressionFormatAndEngine,
    PULONG CompressBufferWorkSpaceSize,
    PULONG CompressFragmentWorkSpaceSize
);

typedef NTSTATUS WINAPI OB_COMPRESSED_RtlCompressBuffer(
    USHORT CompressionFormatAndEngine,
    PUCHAR UncompressedBuffer,
    ULONG  UncompressedBufferSize,
    PUCHAR CompressedBuffer,
    ULONG  CompressedBufferSize,
    ULONG  UncompressedChunkSize,
    PULONG FinalCompressedSize,
    PVOID  WorkSpace
);

typedef NTSTATUS WINAPI OB_COMPRESSED_RtlDecompressBuffer(
    USHORT CompressionFormat,
    PUCHAR UncompressedBuffer,
    ULONG  UncompressedBufferSize,
    PUCHAR CompressedBuffer,
    ULONG  CompressedBufferSize,
    PULONG FinalUncompressedSize
);

/*
* Internal helper function to compress bytes.
* -- H
* -- pb
* -- cb
* -- ppb
* -- pcb
* -- pusRtlCompressionFormat
* -- return
* CALLER LocalFree: *ppb
*/
_Success_(return)
BOOL _ObCompressed_Compress(_In_opt_ VMM_HANDLE H, _In_reads_(cb) PBYTE pb, _In_ DWORD cb, _Out_ PBYTE *ppb, _Out_ PDWORD pcb, _Out_ PUSHORT pusRtlCompressionFormat)
{
    BOOL f;
    NTSTATUS nt;
    DWORD cbResult;
    PBYTE pbResult = NULL, pbBuffer = NULL, pbWorkBuffer = NULL;
    static OB_COMPRESSED_RtlCompressBuffer *pfnRtlCompressBuffer = NULL;
    static OB_COMPRESSED_RtlGetCompressionWorkSpaceSize *pfnRtlGetCompressionWorkSpaceSize = NULL;
    static SRWLOCK InitLockSRW = { 0 };
    static USHORT usRtlCompressionFormat = 0;
    static ULONG ulCompressBufferWorkSpaceSize = 0;
    static ULONG ulCompressFragmentWorkSpaceSize = 0;
    HANDLE hNtDll = 0;
    // 1: ensure initialization
    if(!pfnRtlCompressBuffer) {
        AcquireSRWLockExclusive(&InitLockSRW);
        f = !pfnRtlCompressBuffer &&
            (usRtlCompressionFormat = IsWindows8OrGreater() ? COMPRESSION_FORMAT_XPRESS : COMPRESSION_FORMAT_DEFAULT) &&
            (hNtDll = LoadLibraryA("ntdll.dll")) &&
            (pfnRtlGetCompressionWorkSpaceSize = (OB_COMPRESSED_RtlGetCompressionWorkSpaceSize *)GetProcAddress(hNtDll, "RtlGetCompressionWorkSpaceSize")) &&
            (0 == pfnRtlGetCompressionWorkSpaceSize(usRtlCompressionFormat, &ulCompressBufferWorkSpaceSize, &ulCompressFragmentWorkSpaceSize));
        if(f) {
            pfnRtlCompressBuffer = (OB_COMPRESSED_RtlCompressBuffer *)GetProcAddress(hNtDll, "RtlCompressBuffer");
        }
        ReleaseSRWLockExclusive(&InitLockSRW);
        if(hNtDll) {
            FreeLibrary(hNtDll);
            hNtDll = 0;
        }
        if(!pfnRtlCompressBuffer) { return FALSE; }
    }
    // 2: compress
    if(!(pbBuffer = LocalAlloc(0, cb))) { goto fail; }
    if(!(pbWorkBuffer = LocalAlloc(0, ulCompressBufferWorkSpaceSize))) { goto fail; }
    nt = pfnRtlCompressBuffer(usRtlCompressionFormat, pb, cb, pbBuffer, cb, 4096, &cbResult, pbWorkBuffer);
    if(nt) { goto fail; }
    if(!(pbResult = LocalAlloc(0, cbResult))) { goto fail; }
    memcpy(pbResult, pbBuffer, cbResult);
    *pcb = cbResult;
    *ppb = pbResult;
    *pusRtlCompressionFormat = usRtlCompressionFormat;
fail:
    LocalFree(pbBuffer);
    LocalFree(pbWorkBuffer);
    return pbResult ? TRUE : FALSE;
}

/*
* Retrieve uncompressed from a compressed data object.
* CALLER DECREF: return
* -- pdc
* -- return
*/
_Success_(return != NULL)
POB_DATA _ObCompressed_GetData(_In_ POB_COMPRESSED pdc)
{
    static SRWLOCK InitLockSRW = { 0 };
    static OB_COMPRESSED_RtlDecompressBuffer *pfnRtlDecompressBuffer = NULL;
    HANDLE hNtDll = 0;
    POB_DATA pObData = NULL;
    ULONG ulFinalUncompressedSize = 0;
    DWORD status;
    // 1: ensure compress functionality:
    if(!pfnRtlDecompressBuffer) {
        AcquireSRWLockExclusive(&InitLockSRW);
        if(!pfnRtlDecompressBuffer) {
            if((hNtDll = LoadLibraryA("ntdll.dll"))) {
                pfnRtlDecompressBuffer = (OB_COMPRESSED_RtlDecompressBuffer *)GetProcAddress(hNtDll, "RtlDecompressBuffer");
                FreeLibrary(hNtDll);
            }
        }
        ReleaseSRWLockExclusive(&InitLockSRW);
        if(!pfnRtlDecompressBuffer) { return NULL; }
    }
    // 2: fetch from cache (if possible):
    if((pObData = ObCacheMap_GetByKey(pdc->pcm, pdc->qwCacheKey))) {
        return pObData;
    }
    // 3: decompress and insert into cache
    if(!(pObData = Ob_AllocEx(pdc->ObHdr.H, OB_TAG_CORE_DATA, 0, sizeof(OB) + pdc->cbUncompressed, NULL, NULL))) {
        return NULL;
    }
    status = pfnRtlDecompressBuffer(pdc->usRtlCompressionFormat, pObData->pb, pdc->cbUncompressed, pdc->pbCompressed, pdc->cbCompressed, &ulFinalUncompressedSize);
    if(status != 0) {
        Ob_DECREF(pObData);
        return NULL;
    }
    if(pObData->ObHdr.cbData <= OB_COMPRESSED_CACHED_ENTRIES_MAXSIZE) {    // only cache objects smaller than threshold
        ObCacheMap_Push(pdc->pcm, pdc->qwCacheKey, pObData, 0);
    }
    return pObData;
}

#endif /* _WIN32 */
#ifdef LINUX

#include <lz4.h>

/*
* Internal helper function to compress bytes.
* -- H
* -- pb
* -- cb
* -- ppb
* -- pcb
* -- pusRtlCompressionFormat
* -- return
* CALLER LocalFree: *ppb
*/
_Success_(return)
BOOL _ObCompressed_Compress(_In_opt_ VMM_HANDLE H, _In_reads_(cb) PBYTE pb, _In_ DWORD cb, _Out_ PBYTE * ppb, _Out_ PDWORD pcb, _Out_ PUSHORT pusRtlCompressionFormat)
{
    DWORD cbResult = 0;
    PBYTE pbResult = NULL, pbBuffer = NULL;
    if(!(pbBuffer = LocalAlloc(0, cb))) { goto fail; }
    if(!(cbResult = LZ4_compress_default(pb, pbBuffer, cb, cb))) {
        goto fail;
    }
    if(!(pbResult = LocalAlloc(0, cbResult))) { goto fail; }
    memcpy(pbResult, pbBuffer, cbResult);
    *pcb = cbResult;
    *ppb = pbResult;
    *pusRtlCompressionFormat = 0;
fail:
    LocalFree(pbBuffer);
    return pbResult ? TRUE : FALSE;
}

/*
* Retrieve uncompressed from a compressed data object.
* CALLER DECREF: return
* -- pdc
* -- return
*/
_Success_(return != NULL)
POB_DATA _ObCompressed_GetData(_In_ POB_COMPRESSED pdc)
{
    POB_DATA pObData = NULL;
    // 1: ensure compress functionality:
    // NOT REQUIRED ON LINUX
    // 2: fetch from cache (if possible):
    if((pObData = ObCacheMap_GetByKey(pdc->pcm, pdc->qwCacheKey))) {
        return pObData;
    }
    // 3: decompress and insert into cache
    if(!(pObData = Ob_AllocEx(pdc->ObHdr.H, OB_TAG_CORE_DATA, 0, sizeof(OB) + pdc->cbUncompressed, NULL, NULL))) { return NULL; }
    if((int)pObData->ObHdr.cbData != LZ4_decompress_safe(pdc->pbCompressed, pObData->pb, pdc->cbCompressed, pdc->cbUncompressed)) {
        Ob_DECREF(pObData);
        return NULL;
    }
    if(pObData->ObHdr.cbData < OB_COMPRESSED_CACHED_ENTRIES_MAXSIZE) {    // only cache objects smaller than threshold
        ObCacheMap_Push(pdc->pcm, pdc->qwCacheKey, pObData, 0);
    }
    return pObData;
}

#endif /* LINUX */

/*
* Retrieve uncompressed from a compressed data object.
* CALLER DECREF: return
* -- pdc
* -- return
*/
_Success_(return != NULL)
POB_DATA ObCompressed_GetData(_In_opt_ POB_COMPRESSED pdc)
{
    OB_COMPRESSED_CALL_SYNCHRONIZED_IMPLEMENTATION_EXCLUSIVE(pdc, POB_DATA, NULL, _ObCompressed_GetData(pdc));
}

/*
* Object Map object manager cleanup function to be called when reference
* count reaches zero.
* -- pObCompressed
*/
VOID _ObCompressed_ObCloseCallback(_In_ POB_COMPRESSED pObCompressed)
{
    LocalFree(pObCompressed->pbCompressed);
    Ob_DECREF(pObCompressed->pcm);
}

/*
* Create a new compressed buffer object from a byte buffer.
* It's strongly recommended to supply a global cache map to use.
* CALLER DECREF: return
* -- H
* -- pcmg = optional global (per VMM_HANDLE) cache map to use.
* -- pb
* -- cb
* -- return
*/
_Success_(return != NULL)
POB_COMPRESSED ObCompressed_NewFromByte(_In_opt_ VMM_HANDLE H, _In_opt_ POB_CACHEMAP pcmg, _In_reads_(cb) PBYTE pb, _In_ DWORD cb)
{
    POB_COMPRESSED pObC = NULL;
    pObC = Ob_AllocEx(H, OB_TAG_CORE_COMPRESSED, LMEM_ZEROINIT, sizeof(OB_COMPRESSED), (OB_CLEANUP_CB)_ObCompressed_ObCloseCallback, NULL);
    if(!pObC) { return NULL; }
    if(!_ObCompressed_Compress(H, pb, cb, &pObC->pbCompressed, &pObC->cbCompressed, &pObC->usRtlCompressionFormat)) { goto fail; }
    pObC->cbUncompressed = cb;
    pObC->qwCacheKey = (QWORD)pObC ^ ((QWORD)pObC << 47) ^ (QWORD)pObC->pbCompressed ^ (QWORD)pb ^ ((QWORD)cb << 31);
    pObC->pcm = Ob_INCREF(pcmg);
    Ob_INCREF(pObC);
fail:
    return Ob_DECREF(pObC);
}

/*
* Create a new compressed buffer object from a zero terminated string.
* It's strongly recommended to supply a global cache map to use.
* CALLER DECREF: return
* -- H
* -- pcmg = optional global (per VMM_HANDLE) cache map to use.
* -- sz
* -- return
*/
_Success_(return != NULL)
POB_COMPRESSED ObCompress_NewFromStrA(_In_opt_ VMM_HANDLE H, _In_opt_ POB_CACHEMAP pcmg, _In_ LPSTR sz)
{
    SIZE_T csz = strlen(sz);
    if(csz > 0x01000000) { return NULL; }
    return ObCompressed_NewFromByte(H, pcmg, sz, (DWORD)csz);
}

/*
* Retrieve the uncompressed size of the compressed data object.
* -- pdc
* -- return
*/
DWORD ObCompress_Size(_In_opt_ POB_COMPRESSED pdc)
{
    return OB_COMPRESSED_IS_VALID(pdc) ? pdc->cbUncompressed : 0;
}
