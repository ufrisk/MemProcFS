// ob_compressed.c : implementation of object manager compression functionality.
//
// Implements data compression as an object manager object.
// Data may optionally be cached.
//
// The compressed data object (ObCompressed) is thread safe.
// The ObCompressed is an object manager object and must be DECREF'ed when required.
//
// (c) Ulf Frisk, 2021
// Author: Ulf Frisk, pcileech@frizk.net
//
#include "ob.h"

#define OB_COMPRESSED_MAX_THREADS               2
#define OB_COMPRESSED_CACHED_ENTRIES_MAX        0x40
#define OB_COMPRESSED_CACHED_ENTRIES_MAXSIZE    0x00100000
#define OB_COMPRESSED_IS_VALID(p)               (p && (p->ObHdr._magic == OB_HEADER_MAGIC) && (p->ObHdr._tag == OB_TAG_CORE_COMPRESSED))

typedef struct tdOB_COMPRESSED {
    OB ObHdr;
    QWORD qwCacheKey;
    DWORD cbUncompressed;
    DWORD cbCompressed;
    PBYTE pbCompressed;
    USHORT usRtlCompressionFormat;
} OB_COMPRESSED, *POB_COMPRESSED;

#ifdef _WIN32

#include <VersionHelpers.h>

typedef NTSTATUS OB_COMPRESSED_RtlGetCompressionWorkSpaceSize(
    USHORT CompressionFormatAndEngine,
    PULONG CompressBufferWorkSpaceSize,
    PULONG CompressFragmentWorkSpaceSize
);

typedef NTSTATUS OB_COMPRESSED_RtlCompressBuffer(
    USHORT CompressionFormatAndEngine,
    PUCHAR UncompressedBuffer,
    ULONG  UncompressedBufferSize,
    PUCHAR CompressedBuffer,
    ULONG  CompressedBufferSize,
    ULONG  UncompressedChunkSize,
    PULONG FinalCompressedSize,
    PVOID  WorkSpace
);

typedef NTSTATUS OB_COMPRESSED_RtlDecompressBuffer(
    USHORT CompressionFormat,
    PUCHAR UncompressedBuffer,
    ULONG  UncompressedBufferSize,
    PUCHAR CompressedBuffer,
    ULONG  CompressedBufferSize,
    PULONG FinalUncompressedSize
);

typedef struct tdOB_COMPRESSED_WORKSPACE {
    SRWLOCK LockSRW;
    PBYTE pbWorkBuffer;
    DWORD cbWorkBuffer;
} OB_COMPRESSED_WORKSPACE;

/*
* Internal helper function to compress bytes.
* -- pb
* -- cb
* -- ppb
* -- pcb
* -- pusRtlCompressionFormat
* -- return
* CALLER LocalFree: *ppb
*/
_Success_(return)
BOOL _ObCompressed_Compress(_In_reads_(cb) PBYTE pb, _In_ DWORD cb, _Out_ PBYTE *ppb, _Out_ PDWORD pcb, _Out_ PUSHORT pusRtlCompressionFormat)
{
    BOOL f;
    NTSTATUS nt;
    DWORD cbResult, i;
    PBYTE pbResult = NULL, pbBuffer = NULL;
    static DWORD iWorkSpace = 0;
    static OB_COMPRESSED_WORKSPACE WorkSpace[OB_COMPRESSED_MAX_THREADS] = { 0 };
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
        for(i = 0; f && (i < OB_COMPRESSED_MAX_THREADS); i++) {
            WorkSpace[i].cbWorkBuffer = ulCompressBufferWorkSpaceSize;
            WorkSpace[i].pbWorkBuffer = LocalAlloc(0, ulCompressBufferWorkSpaceSize);
        }
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
    i = InterlockedIncrement(&iWorkSpace) % OB_COMPRESSED_MAX_THREADS;
    AcquireSRWLockExclusive(&WorkSpace[i].LockSRW);
    nt = pfnRtlCompressBuffer(usRtlCompressionFormat, pb, cb, pbBuffer, cb, 4096, &cbResult, WorkSpace->pbWorkBuffer);
    ReleaseSRWLockExclusive(&WorkSpace[i].LockSRW);
    if(nt) { goto fail; }
    if(!(pbResult = LocalAlloc(0, cbResult))) { goto fail; }
    memcpy(pbResult, pbBuffer, cbResult);
    *pcb = cbResult;
    *ppb = pbResult;
    *pusRtlCompressionFormat = usRtlCompressionFormat;
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
POB_DATA ObCompressed_GetData(_In_opt_ POB_COMPRESSED pdc)
{
    // function have a static global cache map shared amongst all instances
    // which will cache up to OB_COMPRESSED_CACHED_ENTRIES_MAX decompressed
    // entries smaller than OB_COMPRESSED_CACHED_ENTRIES_MAXSIZE.
    static POB_CACHEMAP pObCacheMap = NULL;
    static SRWLOCK InitLockSRW = { 0 };
    static OB_COMPRESSED_RtlDecompressBuffer *pfnRtlDecompressBuffer = NULL;
    HANDLE hNtDll = 0;
    POB_DATA pObData = NULL;
    ULONG ulFinalUncompressedSize = 0;
    if(!OB_COMPRESSED_IS_VALID(pdc)) { return NULL; }
    // 1: ensure compress functionality:
    if(!pfnRtlDecompressBuffer) {
        AcquireSRWLockExclusive(&InitLockSRW);
        if(!pfnRtlDecompressBuffer) {
            if(!pObCacheMap) {
                pObCacheMap = ObCacheMap_New(OB_COMPRESSED_CACHED_ENTRIES_MAX, NULL, OB_CACHEMAP_FLAGS_OBJECT_OB);
            }
            if(pObCacheMap && (hNtDll = LoadLibraryA("ntdll.dll"))) {
                pfnRtlDecompressBuffer = (OB_COMPRESSED_RtlDecompressBuffer *)GetProcAddress(hNtDll, "RtlDecompressBuffer");
                FreeLibrary(hNtDll);
            }
        }
        ReleaseSRWLockExclusive(&InitLockSRW);
        if(!pfnRtlDecompressBuffer) { return NULL; }
    }
    // 2: fetch from cache (if possible):
    if(pObCacheMap && (pObData = ObCacheMap_GetByKey(pObCacheMap, pdc->qwCacheKey))) {
        return pObData;
    }
    // 3: decompress and insert into cache
    if(!(pObData = Ob_Alloc(OB_TAG_CORE_DATA, 0, sizeof(OB) + pdc->cbUncompressed, NULL, NULL))) { return NULL; }
    if(0 != pfnRtlDecompressBuffer(pdc->usRtlCompressionFormat, pObData->pb, pdc->cbUncompressed, pdc->pbCompressed, pdc->cbCompressed, &ulFinalUncompressedSize)) {
        Ob_DECREF(pObData);
        return NULL;
    }
    if(pObData->ObHdr.cbData < OB_COMPRESSED_CACHED_ENTRIES_MAXSIZE) {    // only cache objects smaller than threshold
        ObCacheMap_Push(pObCacheMap, pdc->qwCacheKey, pObData, 0);
    }
    return pObData;
}

#endif /* _WIN32 */
#ifdef LINUX

#include <lz4.h>

/*
* Internal helper function to compress bytes.
* -- pb
* -- cb
* -- ppb
* -- pcb
* -- pusRtlCompressionFormat
* -- return
* CALLER LocalFree: *ppb
*/
_Success_(return)
BOOL _ObCompressed_Compress(_In_reads_(cb) PBYTE pb, _In_ DWORD cb, _Out_ PBYTE * ppb, _Out_ PDWORD pcb, _Out_ PUSHORT pusRtlCompressionFormat)
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
POB_DATA ObCompressed_GetData(_In_opt_ POB_COMPRESSED pdc)
{
    // function have a static global cache map shared amongst all instances
    // which will cache up to OB_COMPRESSED_CACHED_ENTRIES_MAX decompressed
    // entries smaller than OB_COMPRESSED_CACHED_ENTRIES_MAXSIZE.
    static POB_CACHEMAP pObCacheMap = NULL;
    static SRWLOCK InitLockSRW = { 0 };
    POB_DATA pObData = NULL;
    if(!OB_COMPRESSED_IS_VALID(pdc)) { return NULL; }
    // 1: ensure compress functionality:
    if(!pObCacheMap) {
        AcquireSRWLockExclusive(&InitLockSRW);
        if(!pObCacheMap) {
            pObCacheMap = ObCacheMap_New(OB_COMPRESSED_CACHED_ENTRIES_MAX, NULL, OB_CACHEMAP_FLAGS_OBJECT_OB);
        }
        ReleaseSRWLockExclusive(&InitLockSRW);
        if(!pObCacheMap) { return NULL; }
    }
    // 2: fetch from cache (if possible):
    if(pObCacheMap && (pObData = ObCacheMap_GetByKey(pObCacheMap, pdc->qwCacheKey))) {
        return pObData;
    }
    // 3: decompress and insert into cache
    if(!(pObData = Ob_Alloc(OB_TAG_CORE_DATA, 0, sizeof(OB) + pdc->cbUncompressed, NULL, NULL))) { return NULL; }
    if(pObData->ObHdr.cbData != LZ4_decompress_safe(pdc->pbCompressed, pObData->pb, pdc->cbCompressed, pdc->cbUncompressed)) {
        Ob_DECREF(pObData);
        return NULL;
    }
    if(pObData->ObHdr.cbData < OB_COMPRESSED_CACHED_ENTRIES_MAXSIZE) {    // only cache objects smaller than threshold
        ObCacheMap_Push(pObCacheMap, pdc->qwCacheKey, pObData, 0);
    }
    return pObData;
}

#endif /* LINUX */

/*
* Object Map object manager cleanup function to be called when reference
* count reaches zero.
* -- pObCompressed
*/
VOID _ObCompressed_ObCloseCallback(_In_ POB_COMPRESSED pObCompressed)
{
    LocalFree(pObCompressed->pbCompressed);
}

/*
* Create a new compressed buffer object from a byte buffer.
* CALLER DECREF: return
* -- pb
* -- cb
* -- return
*/
_Success_(return != NULL)
POB_COMPRESSED ObCompressed_NewFromByte(_In_reads_(cb) PBYTE pb, _In_ DWORD cb)
{
    POB_COMPRESSED pObC = NULL;
    pObC = Ob_Alloc(OB_TAG_CORE_COMPRESSED, 0, sizeof(OB_COMPRESSED), (OB_CLEANUP_CB)_ObCompressed_ObCloseCallback, NULL);
    if(!pObC) { return NULL; }
    pObC->pbCompressed = NULL;
    if(!_ObCompressed_Compress(pb, cb, &pObC->pbCompressed, &pObC->cbCompressed, &pObC->usRtlCompressionFormat)) { goto fail; }
    pObC->cbUncompressed = cb;
    pObC->qwCacheKey = (QWORD)pObC ^ ((QWORD)pObC << 47) ^ (QWORD)pObC->pbCompressed ^ (QWORD)pb ^ ((QWORD)cb << 31);
    Ob_INCREF(pObC);
fail:
    return Ob_DECREF(pObC);
}

/*
* Create a new compressed buffer object from a zero terminated string.
* CALLER DECREF: return
* -- sz
* -- return
*/
_Success_(return != NULL)
POB_COMPRESSED ObCompress_NewFromStrA(_In_ LPSTR sz)
{
    SIZE_T csz = strlen(sz);
    if(csz > 0x01000000) { return NULL; }
    return ObCompressed_NewFromByte(sz, (DWORD)csz + 1);
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
