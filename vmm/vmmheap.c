// vmmheap.c : implementation of heap parsing functionality.
// 
// NT HEAP:
// The heap module will parse NT heaps on all versions of Windows. The LFH heap
// is reliant on symbols which may not always be possible to lookup. If symbols
// are missing the NT heap itself will parse, but LFH entries will be missing.
// 
// SEGMENT HEAP:
// The heap module will only parse segment heaps on Windows versions WIN10 1709+
// The segment heap is reliant on symbols and it will not be possible to parse
// without symbols.s
//
// (c) Ulf Frisk, 2022-2025
// Author: Ulf Frisk, pcileech@frizk.net
//

#include "vmm.h"
#include "vmmheap.h"
#include "vmmlog.h"
#include "vmmwin.h"
#include "vmmwindef.h"
#include "util.h"
#include "charutil.h"
#include "pdb.h"
#include "statistics.h"

#define VMMHEAP_MAX_HEAPS       0x80



// ----------------------------------------------------------------------------
// NT HEAP STRUCT WINDOWS DEFINES:
// ----------------------------------------------------------------------------

typedef struct td_HEAP_SEGMENT64 {
    QWORD HeapEntry[2];
    DWORD SegmentSignature;
    DWORD SegmentFlags;
    LIST_ENTRY64 _ListEntry;
    QWORD Heap;
    QWORD BaseAddress;
    QWORD NumberOfPages;
    QWORD FirstEntry;
    QWORD LastValidEntry;
    DWORD NumberOfUnCommittedPages;
    DWORD NumberOfUnCommittedRanges;
    DWORD SegmentAllocatorBackTraceIndex;
    DWORD Reserved;
    LIST_ENTRY64 UCRSegmentList;
} _HEAP_SEGMENT64, *_PHEAP_SEGMENT64;

typedef struct td_HEAP_SEGMENT32 {
    DWORD HeapEntry[2];
    DWORD SegmentSignature;
    DWORD SegmentFlags;
    LIST_ENTRY32 _ListEntry;
    DWORD Heap;
    DWORD BaseAddress;
    DWORD NumberOfPages;
    DWORD FirstEntry;
    DWORD LastValidEntry;
    DWORD NumberOfUnCommittedPages;
    DWORD NumberOfUnCommittedRanges;
    DWORD SegmentAllocatorBackTraceIndex;
    DWORD Reserved;
    LIST_ENTRY32 UCRSegmentList;
} _HEAP_SEGMENT32, *_PHEAP_SEGMENT32;

typedef struct td_HEAP_SEGMENT32_XP {
    DWORD HeapEntry[2];
    DWORD SegmentSignature;
    DWORD SegmentFlags;
    DWORD Heap;
    DWORD LargestUnCommittedRange;
    DWORD BaseAddress;
    DWORD NumberOfPages;
    DWORD FirstEntry;
    DWORD LastValidEntry;
    DWORD NumberOfUnCommittedPages;
    DWORD NumberOfUnCommittedRanges;
    DWORD UnCommittedRanges;
    WORD AllocatorBackTraceIndex;
    WORD Reserved;
    DWORD LastEntryInSegment;
} _HEAP_SEGMENT32_XP, *_PHEAP_SEGMENT32_XP;

typedef struct td_HEAP_LARGE_ALLOC_DATA64 {
    QWORD TreeNode[3];
    union { QWORD VirtualAddress; QWORD UnusedBytes : 16; };
    QWORD _Reserved : 12;
    QWORD AllocatedPages : 52;
} _HEAP_LARGE_ALLOC_DATA64, *_PHEAP_LARGE_ALLOC_DATA64;

typedef struct td_HEAP_LARGE_ALLOC_DATA32 {
    DWORD TreeNode[3];
    union { DWORD VirtualAddress; DWORD UnusedBytes : 16; };
    DWORD _Reserved : 12;
    DWORD AllocatedPages : 20;
} _HEAP_LARGE_ALLOC_DATA32, *_PHEAP_LARGE_ALLOC_DATA32;

typedef struct td_HEAP_ENTRY {
    WORD Size;
    BYTE Flags;
    BYTE SmallTagIndex;
    WORD PreviousSize;
    BYTE LFHFlags;
    BYTE UnusedBytes;
} _HEAPENTRY, *_PHEAPENTRY;

_Success_(return)
BOOL VmmHeap_GetEntryDecoded(_In_ BOOL f32, _In_ QWORD qwHeapEncoding, _In_ PBYTE pb, _In_ DWORD o, _Out_ _PHEAPENTRY pH)
{
    union {
        QWORD v;
        BYTE pbH[8];
    } u;
    if(!f32) { o += 8; }
    u.v = *(PQWORD)(pb + o);
    if(!u.v) { return FALSE; }
    if(qwHeapEncoding) {
        u.v ^= qwHeapEncoding;
        if(u.pbH[3] != (u.pbH[0] ^ u.pbH[1] ^ u.pbH[2])) { return FALSE; }
    }
    *(PQWORD)pH = u.v;
    return TRUE;
}



// ----------------------------------------------------------------------------
// HEAPALLOC MAP GENERATION (HEAP PARSE):
// ----------------------------------------------------------------------------

#define VMMWINHEAP_CTX_STORE_MAX            0xff0       // max # entries per store page.

typedef struct tdVMMWINHEAP_CTX_STORE {
    struct tdVMMWINHEAP_CTX_STORE *pNext;
    DWORD c;
    DWORD cPrevious;
    VMM_MAP_HEAPALLOCENTRY e[VMMWINHEAP_CTX_STORE_MAX];
} VMMWINHEAP_CTX_STORE, *PVMMWINHEAP_CTX_STORE;

typedef struct tdVMMHEAPNT_CTX {
    PVMM_PROCESS pProcess;
    PVMMOB_MAP_HEAP pHeapMap;
    PVMM_MAP_HEAPENTRY pHeapEntry;
    PVMMWINHEAP_CTX_STORE pStore;
    PVMM_OFFSET_HEAP po;
    BOOL f32;
    // NT heap:
    DWORD dwLfhKey;
    QWORD qwHeapEncoding;
    QWORD vaLfh;
    // Segment heap:
    DWORD dwSegLfhKey;
    QWORD qwSegHeapGbl;
    struct {
        QWORD va;
        UCHAR ucUnitShift;
        UCHAR ucFirstDescriptorIndex;
    } segctx[2];

} VMMHEAPNT_CTX, *PVMMHEAPNT_CTX;

VOID VmmHeapAlloc_NtInit(_In_ VMM_HANDLE H, _In_ PVMMHEAPNT_CTX ctx);
VOID VmmHeapAlloc_SegInit(_In_ VMM_HANDLE H, _In_ PVMMHEAPNT_CTX ctx);

/*
* Push an entry onto the heap store list.
*/
VOID VmmHeapAlloc_PushItem(
    _In_ VMM_HANDLE H,
    _In_ PVMMWINHEAP_CTX_STORE *ppStore,
    _In_ VMM_HEAPALLOC_TP tp,
    _In_ QWORD va,
    _In_ DWORD cb
) {
    PVMM_MAP_HEAPALLOCENTRY pe;
    PVMMWINHEAP_CTX_STORE pStore, pStoreNext;
    // get and grow store (if required)
    pStore = *ppStore;
    if(pStore->c == VMMWINHEAP_CTX_STORE_MAX) {
        if(pStore->cPrevious > 0x40000000) { return; }
        pStoreNext = pStore;
        if(!(pStore = LocalAlloc(0, sizeof(VMMWINHEAP_CTX_STORE)))) { return; }
        pStore->c = 0;
        pStore->cPrevious = pStoreNext->c + pStoreNext->cPrevious;
        pStore->pNext = pStoreNext;
        *ppStore = pStore;
    }
    // add to store
    pe = pStore->e + pStore->c;
    pe->va = va;
    pe->cb = cb;
    pe->tp = tp;
    pStore->c++;
    VmmLog(H, MID_HEAP, LOGLEVEL_6_TRACE, "[%-8s %llx +%x]", VMM_HEAPALLOC_TP_STR[pe->tp], pe->va, pe->cb);
}

/*
* Push large allocations onto the heap store list.
*/
VOID VmmHeapAlloc_PushLarge(_In_ VMM_HANDLE H, _In_ PVMMHEAPNT_CTX ctx, _In_ PVMMOB_MAP_HEAP pHeapMap, _In_ PVMM_MAP_HEAPENTRY peHeap)
{
    BYTE pbBuffer[0x40];
    DWORD i, cbHeapHdr = (ctx->f32 ? 0x20 : 0x40);
    _HEAPENTRY eH;
    QWORD cbAlloc;
    PVMM_MAP_HEAP_SEGMENTENTRY peSegment;
    for(i = 0; i < pHeapMap->cSegments; i++) {
        peSegment = pHeapMap->pSegments + i;
        if(peSegment->iHeap == peHeap->iHeap) {
            if(peSegment->tp == VMM_HEAP_SEGMENT_TP_NT_LARGE) {
                cbAlloc = peSegment->cb;
                if(ctx->qwHeapEncoding && VmmRead(H, ctx->pProcess, peSegment->va, pbBuffer, sizeof(pbBuffer))) {
                    cbAlloc = VMM_PTR_OFFSET_DUAL(ctx->f32, pbBuffer, 0x10, 0x20);
                    if((cbAlloc > 0x1000) && (cbAlloc <= peSegment->cb)) {
                        if(VmmHeap_GetEntryDecoded(ctx->f32, ctx->qwHeapEncoding, pbBuffer, (ctx->f32 ? 0x18 : 0x30), &eH)) {
                            cbAlloc -= eH.Size;
                        }
                    } else {
                        cbAlloc = peSegment->cb;
                    }
                }
                VmmHeapAlloc_PushItem(H, &ctx->pStore, VMM_HEAPALLOC_TP_NT_LARGE, peSegment->va + cbHeapHdr, (DWORD)(cbAlloc - cbHeapHdr));
            }
            if(peSegment->tp == VMM_HEAP_SEGMENT_TP_SEG_LARGE) {
                VmmHeapAlloc_PushItem(H, &ctx->pStore, VMM_HEAPALLOC_TP_SEG_LARGE, peSegment->va, peSegment->cb);
            }
        }
    }
}

/*
* Fetch LFH / Heap key from symbols.
* -- H
* -- pProcess
* -- f32
* -- pqwNtHeapKey = the HeapKey or 0 on fail
* -- pqwSegHeapGbl = the HeapGlobals or 0 on fail
* -- pdqSegLfhKey = the LfhKey or 0 on fail
* -- pdwNtLfhKey = the LfhKey or 0 on fail (32-bit nt-heap key)
*/
VOID VmmHeapAlloc_GetHeapKeys(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess, _In_ BOOL f32, _Out_opt_ PQWORD pqwNtHeapKey, _Out_opt_ PQWORD pqwSegHeapGbl, _Out_opt_ PDWORD pdwSegLfhKey, _Out_opt_ PDWORD pdwNtLfhKey)
{
    DWORD i;
    DWORD oHeapGlobals = 0;
    BOOL fWow = (f32 && !H->vmm.f32);
    PVMMOB_MAP_MODULE pObModuleMap = NULL;
    PVMM_MAP_MODULEENTRY pNtdll;
    PDB_HANDLE hPDB = (fWow ? PDB_HANDLE_NTDLL_WOW64 : PDB_HANDLE_NTDLL);
    // try fast path first: (windows os and symbols already loaded)
    if(pqwSegHeapGbl) { *pqwSegHeapGbl = 0; }
    if(pdwSegLfhKey) { *pdwSegLfhKey = 0; }
    if(pqwNtHeapKey && !PDB_GetSymbolQWORD(H, hPDB, "RtlpHeapKey", pProcess, pqwNtHeapKey)) { *pqwNtHeapKey = 0; }
    if(pdwNtLfhKey && !PDB_GetSymbolDWORD(H, hPDB, "RtlpLFHKey", pProcess, pdwNtLfhKey))   { *pdwNtLfhKey = 0;  }
    if(!pqwSegHeapGbl && !pdwSegLfhKey && (!pqwNtHeapKey || *pqwNtHeapKey) && (!pdwNtLfhKey || *pdwNtLfhKey)) { return; }
    // try slow path: (load symbols via module list)
    if(VmmMap_GetModuleEntryEx(H, pProcess, 0, "ntdll.dll", 0, &pObModuleMap, &pNtdll)) {
        if(fWow != pNtdll->fWoW64) {
            pNtdll = NULL;
            for(i = 0; i < pObModuleMap->cMap; i++) {
                if((pObModuleMap->pMap[i].fWoW64 == fWow) && CharUtil_StrEndsWith(pObModuleMap->pMap[i].uszText, "ntdll.dll", TRUE)) {
                    pNtdll = pObModuleMap->pMap + i;
                }
            }
        }
        if(pNtdll) {
            PDB_LoadEnsure(H, PDB_GetHandleFromModuleAddress(H, pProcess, pNtdll->vaBase));
            //if(pqwSegHeapGbl) { PDB_GetSymbolQWORD2(hPDB, pNtdll->vaBase, "RtlpHpHeapGlobals", pProcess, pqwSegHeapGbl); }
            if(pqwNtHeapKey) { PDB_GetSymbolQWORD2(H, hPDB, pNtdll->vaBase, "RtlpHeapKey", pProcess, pqwNtHeapKey); }
            if(pdwNtLfhKey)  { PDB_GetSymbolDWORD2(H, hPDB, pNtdll->vaBase, "RtlpLFHKey", pProcess, pdwNtLfhKey);   }
            if(pqwSegHeapGbl || pdwSegLfhKey) {
                if(PDB_GetSymbolOffset(H, hPDB, "RtlpHpHeapGlobals", &oHeapGlobals) && oHeapGlobals) {
                    VmmRead(H, pProcess, pNtdll->vaBase + oHeapGlobals, (PBYTE)pqwSegHeapGbl, sizeof(QWORD));
                    VmmRead(H, pProcess, pNtdll->vaBase + oHeapGlobals + (f32 ? 4 : 8), (PBYTE)pdwSegLfhKey, sizeof(DWORD));
                }
            }
        }
        Ob_DECREF(pObModuleMap);
    }
}

int VmmHeapAlloc_qsort_AllocEntry(PVMM_MAP_HEAPALLOCENTRY p1, PVMM_MAP_HEAPALLOCENTRY p2)
{
    return (p1->va < p2->va) ? -1 : ((p1->va > p2->va) ? 1 : 0);
}

/*
* Object manager callback function for object cleanup tasks.
*/
VOID VmmHeapAlloc_CloseObCallback(_In_ PVOID pVmmOb)
{
    PVMMOB_MAP_HEAPALLOC pOb = (PVMMOB_MAP_HEAPALLOC)pVmmOb;
    Ob_DECREF(pOb->pHeapMap);
}

/*
* Initialize a new heap allocation map.
* This function is called in a single-threaded process lock.
* -- H
* -- pProcess
* -- vaHeap = va of heap or heap id.
* -- return
*/
_Success_(return != NULL)
PVMMOB_MAP_HEAPALLOC VmmHeapAlloc_Init_DoWork(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess, _In_opt_ QWORD vaHeap)
{
    PVMMHEAPNT_CTX ctx = NULL;
    PVMMWINHEAP_CTX_STORE pStore;
    DWORD iMap = 0, cEntry;
    SIZE_T cbAlloc;
    PVMMOB_MAP_HEAPALLOC pObAlloc = NULL;
    VmmLog(H, MID_HEAP, LOGLEVEL_6_TRACE, "INIT HEAPALLOCMAP START: pid=%5i heap=%llx", pProcess->dwPID, vaHeap);
    // 1: init
    if(!(ctx = LocalAlloc(LMEM_ZEROINIT, sizeof(VMMHEAPNT_CTX)))) { goto fail; }
    if(!VmmMap_GetHeap(H, pProcess, &ctx->pHeapMap) || !(ctx->pHeapEntry = VmmMap_GetHeapEntry(H, ctx->pHeapMap, vaHeap))) {
        VmmLog(H, MID_HEAP, LOGLEVEL_5_DEBUG, "FAIL: NO HEAP ENTRY: pid=%i %va=%llx", pProcess->dwPID, vaHeap);
        goto fail;
    }
    ctx->f32 = ctx->pHeapEntry->f32;
    ctx->po = ctx->f32 ? &H->vmm.offset.HEAP32 : &H->vmm.offset.HEAP64;
    if(!(ctx->pStore = LocalAlloc(LMEM_ZEROINIT, sizeof(VMMWINHEAP_CTX_STORE)))) { goto fail; }
    ctx->pProcess = pProcess;
    // 2: dispatch to nt/segment heap subsystems
    if(ctx->pHeapEntry->tp == VMM_HEAP_TP_NT) {
        VmmHeapAlloc_NtInit(H, ctx);
    } else if(ctx->pHeapEntry->tp == VMM_HEAP_TP_SEG) {
        VmmHeapAlloc_SegInit(H, ctx);
    } else {
        VmmLog(H, MID_HEAP, LOGLEVEL_2_WARNING, "FAIL: UNSUPPORTED HEAP TYPE - SHOULD NOT HAPPEN!: pid=%i %va=%llx", pProcess->dwPID, vaHeap);
        goto fail;
    }
    // 3: add large entries from heap map segments
    VmmHeapAlloc_PushLarge(H, ctx, ctx->pHeapMap, ctx->pHeapEntry);
    // 4: alloc/create map object
    cEntry = ctx->pStore->c + ctx->pStore->cPrevious;
    cbAlloc = sizeof(VMMOB_MAP_HEAPALLOC) + cEntry * sizeof(VMM_MAP_HEAPALLOCENTRY);
    if(cbAlloc > 0x80000000) { goto fail; }
    if(!(pObAlloc = Ob_AllocEx(H, OB_TAG_MAP_HEAPALLOC, 0, cbAlloc, VmmHeapAlloc_CloseObCallback, NULL))) { goto fail; }
    pObAlloc->pHeapMap = Ob_INCREF(ctx->pHeapMap);
    pObAlloc->pHeapEntry = ctx->pHeapEntry;
    pObAlloc->cMap = cEntry;
    while((pStore = ctx->pStore)) {
        memcpy(pObAlloc->pMap + iMap, pStore->e, pStore->c * sizeof(VMM_MAP_HEAPALLOCENTRY));
        iMap += pStore->c;
        ctx->pStore = pStore->pNext;
        LocalFree(pStore);
    }
    qsort(pObAlloc->pMap, pObAlloc->cMap, sizeof(VMM_MAP_HEAPALLOCENTRY), (_CoreCrtNonSecureSearchSortCompareFunction)VmmHeapAlloc_qsort_AllocEntry);
fail:
    if(ctx) {
        while((pStore = ctx->pStore)) {
            ctx->pStore = pStore->pNext;
            LocalFree(pStore);
        }
        Ob_DECREF(ctx->pHeapMap);
        LocalFree(ctx);
    }
    VmmLog(H, MID_HEAP, LOGLEVEL_6_TRACE, "INIT HEAPALLOCMAP END:   pid=%5i heap=%llx count=%i", pProcess->dwPID, vaHeap, (pObAlloc ? pObAlloc->cMap : 0));
    return pObAlloc;
}

/*
* Refresh any cached heap allocation maps.
*/
VOID VmmHeapAlloc_Refresh(_In_ VMM_HANDLE H)
{
    ObCacheMap_Clear(H->vmm.pObCacheMapHeapAlloc);
}

/*
* Retrive the heap allocation map for the specific heap.
* The map is cached up until a total process refresh is made (medium refresh).
* CALLER DECREF: return
* -- H
* -- pProcess
* -- vaHeap = va of heap or heap id.
* -- return
*/
PVMMOB_MAP_HEAPALLOC VmmHeapAlloc_Initialize(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess, _In_opt_ QWORD vaHeap)
{
    PVMMOB_MAP_HEAPALLOC pObHeapAlloc = NULL;
    // 1: ensure cache map exists (or init)
    if(!H->vmm.pObCacheMapHeapAlloc) {
        EnterCriticalSection(&H->vmm.LockPlugin);
        if(!H->vmm.pObCacheMapHeapAlloc) {
            H->vmm.pObCacheMapHeapAlloc = ObCacheMap_New(H, 0x10, NULL, OB_CACHEMAP_FLAGS_OBJECT_OB);
        }
        LeaveCriticalSection(&H->vmm.LockPlugin);
    }
    // 2: try fetch from cache map
    if(!(pObHeapAlloc = ObCacheMap_GetByKey(H->vmm.pObCacheMapHeapAlloc, vaHeap + pProcess->dwPID))) {
        EnterCriticalSection(&pProcess->LockUpdate);
        if(!(pObHeapAlloc = ObCacheMap_GetByKey(H->vmm.pObCacheMapHeapAlloc, vaHeap + pProcess->dwPID))) {
            if((pObHeapAlloc = VmmHeapAlloc_Init_DoWork(H, pProcess, vaHeap))) {
                ObCacheMap_Push(H->vmm.pObCacheMapHeapAlloc, vaHeap + pProcess->dwPID, pObHeapAlloc, 0);
            }
        }
        LeaveCriticalSection(&pProcess->LockUpdate);
    }
    // 3: on fail, create dummy map and push to cache
    if(!pObHeapAlloc && (pObHeapAlloc = Ob_AllocEx(H, OB_TAG_MAP_HEAPALLOC, LMEM_ZEROINIT, sizeof(VMMOB_MAP_HEAPALLOC), NULL, NULL))) {
        ObCacheMap_Push(H->vmm.pObCacheMapHeapAlloc, vaHeap + pProcess->dwPID, pObHeapAlloc, 0);
    }
    return pObHeapAlloc;
}



// ----------------------------------------------------------------------------
// SEGMENT HEAP PARSING BELOW:
// ----------------------------------------------------------------------------

typedef union tdVMMHEAPALLOC_SEG_LFHENCODED_OFFSETS {
    struct {
        WORD BlockSize;
        WORD FirstBlockOffset;
    };
    DWORD EncodedData;
} VMMHEAPALLOC_SEG_LFHENCODED_OFFSETS, *PVMMHEAPALLOC_SEG_LFHENCODED_OFFSETS;

typedef union tdVMMHEAPALLOC_SEG_HEAP_VS_CHUNK_HEADER_SIZE32 {
    struct {
        DWORD MemoryCost : 1;
        DWORD UnsafeSize : 15;
        DWORD UnsafePrevSize : 15;
        DWORD Allocated : 1;
    };
    DWORD HeaderBits;
} VMMHEAPALLOC_SEG_HEAP_VS_CHUNK_HEADER_SIZE32, *PVMMHEAPALLOC_SEG_HEAP_VS_CHUNK_HEADER_SIZE32;

typedef union tdVMMHEAPALLOC_SEG_HEAP_VS_CHUNK_HEADER_SIZE64 {
    struct {
        DWORD MemoryCost : 16;
        DWORD UnsafeSize : 16;
        DWORD UnsafePrevSize : 16;
        DWORD Allocated : 8;
        DWORD _Pad : 8;
    };
    QWORD HeaderBits;
} VMMHEAPALLOC_SEG_HEAP_VS_CHUNK_HEADER_SIZE64, *PVMMHEAPALLOC_SEG_HEAP_VS_CHUNK_HEADER_SIZE64;

/*
* Parse the vs heap segment - [ntdll!_HEAP_VS_SUBSEGMENT] // [ntdll!_HEAP_VS_CHUNK_HEADER]
* TODO: VERIFY HEAP ALLOCATIONS BETTER!
*/
VOID VmmHeapAlloc_SegVS(_In_ VMM_HANDLE H, _In_ PVMMHEAPNT_CTX ctx, _In_ DWORD iCtx, _In_ QWORD va, _In_ PBYTE pb, _In_ DWORD cb)
{
    DWORD cbPoolHdr, oVsChunkHdr, cbChunkSize, oBlock, cbBlock, cbAdjust;
    QWORD vaBlock, vaChunkHeader;
    WORD wSize, wSignature;
    BOOL fAlloc;
    PVMMHEAPALLOC_SEG_HEAP_VS_CHUNK_HEADER_SIZE32 pChunkSize32;
    PVMMHEAPALLOC_SEG_HEAP_VS_CHUNK_HEADER_SIZE64 pChunkSize64;
    // 32/64-bit dependent offsets:
    if(ctx->f32) {
        cbPoolHdr = 8;
        oVsChunkHdr = 0x18;
        wSize = *(PWORD)(pb + 0x14);
        wSignature = *(PWORD)(pb + 0x16);
    } else {
        cbPoolHdr = 16;
        oVsChunkHdr = 0x30;
        wSize = *(PWORD)(pb + 0x20);
        wSignature = *(PWORD)(pb + 0x22);
    }
    // signature check: _HEAP_VS_SUBSEGMENT
    if(wSize != (wSignature ^ 0x2BED)) {
        return;
    }
    // loop over pool entries
    while(oVsChunkHdr + 0x30 < cb) {
        vaChunkHeader = va + oVsChunkHdr;
        if(H->vmm.f32) {
            pChunkSize32 = (PVMMHEAPALLOC_SEG_HEAP_VS_CHUNK_HEADER_SIZE32)(pb + oVsChunkHdr);
            pChunkSize32->HeaderBits = (DWORD)(pChunkSize32->HeaderBits ^ vaChunkHeader ^ ctx->qwSegHeapGbl);
            fAlloc = (pChunkSize32->Allocated & 1) ? TRUE : FALSE;
            cbChunkSize = pChunkSize32->UnsafeSize << 3;
        } else {
            pChunkSize64 = (PVMMHEAPALLOC_SEG_HEAP_VS_CHUNK_HEADER_SIZE64)(pb + oVsChunkHdr);
            pChunkSize64->HeaderBits = pChunkSize64->HeaderBits ^ vaChunkHeader ^ ctx->qwSegHeapGbl;
            fAlloc = (pChunkSize64->Allocated & 1) ? TRUE : FALSE;
            cbChunkSize = pChunkSize64->UnsafeSize << 4;
        }
        if((cbChunkSize < 0x10) || (oVsChunkHdr + cbChunkSize > cb)) {
            break;
        }
        if(fAlloc) {
            oBlock = oVsChunkHdr + ctx->po->seg.HEAP_VS_CHUNK_HEADER.cb;
            cbBlock = cbChunkSize - ctx->po->seg.HEAP_VS_CHUNK_HEADER.cb;
            vaBlock = va + oBlock;
            if((cbBlock < 0xff0) && (((vaBlock & 0xfff) + cbBlock) > 0x1040)) {
                // block crosses page boundary -> pool header will be found at
                // start of new page - adjust block size and address!
                cbAdjust = 0x1000 - (vaBlock & 0xfff);
                oBlock += cbAdjust;
                cbBlock -= cbAdjust;
                vaBlock += cbAdjust;
            }
            if(((vaBlock & ~0xfff) == ((vaBlock + cbBlock - cbPoolHdr) & ~0xfff)) || (cbBlock >= 0xff0)) {
                VmmHeapAlloc_PushItem(H, &ctx->pStore, VMM_HEAPALLOC_TP_SEG_VS, vaBlock, cbBlock);
            }
        }
        oVsChunkHdr += cbChunkSize;
    }
}

/*
* Parse the low fragmentation heap segment - [ntdll!_HEAP_LFH_SUBSEGMENT]
* TODO: VERIFY HEAP ALLOCATIONS BETTER!
*/
VOID VmmHeapAlloc_SegLFH(_In_ VMM_HANDLE H, _In_ PVMMHEAPNT_CTX ctx, _In_ DWORD iCtx, _In_ QWORD va, _In_ PBYTE pb, _In_ DWORD cb)
{
    UCHAR ucBits;
    PBYTE pbBitmap;
    DWORD iBlock, cBlock, oBlock;
    DWORD cbBlockSize, oFirstBlock, dwvaShift;
    PVMMHEAPALLOC_SEG_LFHENCODED_OFFSETS pEncoded;
    pbBitmap = pb + ctx->po->seg.HEAP_LFH_SUBSEGMENT.BlockBitmap;
    pEncoded = (PVMMHEAPALLOC_SEG_LFHENCODED_OFFSETS)(pb + ctx->po->seg.HEAP_LFH_SUBSEGMENT.BlockOffsets);
    dwvaShift = (H->vmm.kernel.dwVersionBuild >= 26100) ? ((DWORD)(va >> 12)) : ((DWORD)va >> 12);
    pEncoded->EncodedData = (DWORD)(pEncoded->EncodedData ^ ctx->dwSegLfhKey ^ dwvaShift);
    oFirstBlock = pEncoded->FirstBlockOffset;
    cbBlockSize = pEncoded->BlockSize;
    if((cbBlockSize >= 0xff8) || (oFirstBlock > cb)) { return; }
    cBlock = (cb - oFirstBlock) / cbBlockSize;
    for(iBlock = 0; iBlock < cBlock; iBlock++) {
        oBlock = oFirstBlock + iBlock * cbBlockSize;
        if(oBlock + cbBlockSize > cb) { return; }
        if((oBlock & 0xfff) + cbBlockSize > 0x1000) { continue; }   // block do not cross page boundaries
        ucBits = pbBitmap[iBlock >> 2] >> ((iBlock & 0x3) << 1);
        if(((ucBits & 3) == 1)) {
            VmmHeapAlloc_PushItem(H, &ctx->pStore, VMM_HEAPALLOC_TP_SEG_LFH, va + oBlock, cbBlockSize);
        }
    }
}

/*
* Parse a single segment heap range descriptor
*/
DWORD VmmHeapAlloc_SegRangeDescriptor(_In_ VMM_HANDLE H, _In_ PVMMHEAPNT_CTX ctx, _In_ DWORD iCtx, _In_ QWORD vaPgSeg, _In_ PBYTE pbPgSeg, _In_ DWORD cbPgSeg, _In_ DWORD iRD)
{
    UCHAR ucUnitSize, ucRangeFlags;
    DWORD oRange, cbRange, oRD;
    oRD = ctx->po->seg.HEAP_PAGE_RANGE_DESCRIPTOR.cb * iRD;
    ucUnitSize = *(PUCHAR)(pbPgSeg + oRD + ctx->po->seg.HEAP_PAGE_RANGE_DESCRIPTOR.UnitSize);
    ucRangeFlags = *(PUCHAR)(pbPgSeg + oRD + ctx->po->seg.HEAP_PAGE_RANGE_DESCRIPTOR.RangeFlags);
    if(ctx->f32) { ucRangeFlags &= 0x1f; }
    oRange = iRD * (1ULL << ctx->segctx[iCtx].ucUnitShift);
    cbRange = ucUnitSize * (1ULL << ctx->segctx[iCtx].ucUnitShift);
    if(ucUnitSize == 0) { return 1; }
    if(cbRange > 0x00100000) { return ucUnitSize; }  // >1MB sanity check
    if(oRange + cbRange > cbPgSeg) { return ucUnitSize; }
    if(ucRangeFlags == 3) {
        // Large Pool - not yet supported!
    } else if(ucRangeFlags == 11) {
        // Lfh
        VmmHeapAlloc_SegLFH(H, ctx, iCtx, vaPgSeg + oRange, pbPgSeg + oRange, cbRange);
    } else if(ucRangeFlags == 15) {
        // Vs
        VmmHeapAlloc_SegVS(H, ctx, iCtx, vaPgSeg + oRange, pbPgSeg + oRange, cbRange);
    }
    return ucUnitSize;
}

/*
* Init Segment heap entries (excl. large entries)
*/
VOID VmmHeapAlloc_SegInit(_In_ VMM_HANDLE H, _In_ PVMMHEAPNT_CTX ctx)
{
    BOOL f32 = ctx->f32;
    DWORD i, o, iCtx, iRD;
    QWORD vaSignature;
    DWORD cbPgSeg;
    PBYTE pbPgSeg = NULL;
    BYTE pbSegHdr[0x400];
    PVMM_MAP_HEAP_SEGMENTENTRY peSegment;
    // 1: init
    if(H->vmm.kernel.dwVersionBuild < 16299) {
        VmmLog(H, MID_HEAP, LOGLEVEL_5_DEBUG, "FAIL: Segment Heap not supported below Win10 1709 / 16299");
        goto fail;
    }
    // 2: fetch keys
    VmmHeapAlloc_GetHeapKeys(H, ctx->pProcess, ctx->f32, NULL, &ctx->qwSegHeapGbl, &ctx->dwSegLfhKey, NULL);
    if(!ctx->qwSegHeapGbl || !ctx->dwSegLfhKey) {
        VmmLog(H, MID_HEAP, LOGLEVEL_6_TRACE, "FAIL: HEAP / LFH KEY");
        goto fail;
    }
    // 3: fetch heap seg context info:
    if(!VmmRead(H, ctx->pProcess, ctx->pHeapEntry->va, pbSegHdr, sizeof(pbSegHdr))) {
        VmmLog(H, MID_HEAP, LOGLEVEL_5_DEBUG, "FAIL: Segment heap fail read at: %llx", ctx->pHeapEntry->va);
        goto fail;
    }
    for(i = 0; i < 2; i++) {
        o = ctx->po->seg.SEGMENT_HEAP.SegContexts + i * ctx->po->seg.HEAP_SEG_CONTEXT.cb;
        ctx->segctx[i].va = ctx->pHeapEntry->va + o;
        ctx->segctx[i].ucUnitShift = *(PUCHAR)(pbSegHdr + o + ctx->po->seg.HEAP_SEG_CONTEXT.UnitShift);
        ctx->segctx[i].ucFirstDescriptorIndex = *(PUCHAR)(pbSegHdr + o + ctx->po->seg.HEAP_SEG_CONTEXT.FirstDescriptorIndex);
    }
    // 4: walk segments and process them!
    for(i = 0; i < ctx->pHeapMap->cSegments; i++) {
        peSegment = ctx->pHeapMap->pSegments + i;
        if(peSegment->iHeap == ctx->pHeapEntry->iHeap) {
            if(peSegment->tp == VMM_HEAP_SEGMENT_TP_SEG_SEGMENT) {
                // alloc & read
                LocalFree(pbPgSeg);
                cbPgSeg = peSegment->cb;
                if(!(pbPgSeg = LocalAlloc(0, cbPgSeg))) { goto fail; }
                VmmRead2(H, ctx->pProcess, peSegment->va, pbPgSeg, cbPgSeg, VMM_FLAG_ZEROPAD_ON_FAIL);
                // signature check:
                vaSignature = VMM_PTR_OFFSET_DUAL(f32, pbPgSeg, 8, 16) ^ peSegment->va ^ ctx->qwSegHeapGbl ^ ctx->po->seg.HEAP_PAGE_SEGMENT.qwSignatureStaticKey;
                iCtx = (DWORD)-1;
                if(ctx->segctx[0].va == vaSignature) { iCtx = 0; }
                if(ctx->segctx[1].va == vaSignature) { iCtx = 1; }
                if(iCtx > 1) { continue; }
                // walk range descriptors:
                iRD = ctx->segctx[iCtx].ucFirstDescriptorIndex;
                while(iRD < 256) {
                    iRD += VmmHeapAlloc_SegRangeDescriptor(H, ctx, iCtx, peSegment->va, pbPgSeg, cbPgSeg, iRD);
                }
            }
        }
    }
fail:
    LocalFree(pbPgSeg);
}



// ----------------------------------------------------------------------------
// NT HEAP PARSING BELOW:
// ----------------------------------------------------------------------------

typedef union tdVMMHEAPALLOC_NTLFH_ENCODED {
    DWORD dw;
    struct {
        WORD FirstAllocationOffset;
        WORD BlockStride;
    };
} VMMHEAPALLOC_NTLFH_ENCODED, *PVMMHEAPALLOC_NTLFH_ENCODED;

BOOL VmmHeapAlloc_NtInitLfhUserData_VerifyEncoded(_In_ BOOL f32, _In_ PVMMHEAPALLOC_NTLFH_ENCODED pEncoded)
{
    BOOL fFail =
        (pEncoded->FirstAllocationOffset & 7) ||
        (pEncoded->FirstAllocationOffset < (f32 ? 0x20 : 0x40)) || (pEncoded->FirstAllocationOffset > 0x1000) ||
        (pEncoded->BlockStride & 3) || (pEncoded->BlockStride < (f32 ? 8 : 16));
    return !fFail;
}

VOID VmmHeapAlloc_NtInitLfhUserDataWin7(_In_ VMM_HANDLE H, _In_ PVMMHEAPNT_CTX ctx, _In_ QWORD vaLfhUD, _In_ PBYTE pbLfhUD, _In_ DWORD cbLfhUD)
{
    BYTE pbSubSegment[0x20];
    BOOL f32 = H->vmm.f32;
    QWORD vaSubSegment, vaChunk;
    DWORD cbChunk, cbUnitSize = ctx->f32 ? 8 : 16;
    DWORD cbHeaderSize = ctx->f32 ? 0x10 : 0x20;
    DWORD dwBlockSize, cBlock, cFreeBlock, cbAll, oBlock, iBlock;
    // 1: signature check
    if(0xf0e0d0c0 != *(PDWORD)(pbLfhUD + (f32 ? 0x0c : 0x18))) { return; }     // TODO: 32-bit
    // 2: fetch _HEAP_SUBSEGMENT with BlockSize, BlockCount and AggregateExchg (_INTERLOCK_SEQ)
    vaSubSegment = VMM_PTR_OFFSET(vaLfhUD, pbLfhUD, 0);
    if(!VMM_UADDR_DUAL_4_8(f32, vaSubSegment)) { return; }
    if(!VmmRead(H, ctx->pProcess, vaSubSegment, pbSubSegment, sizeof(pbSubSegment))) { return; }
    dwBlockSize = *(PWORD)(pbSubSegment + (f32 ? 0x10 : 0x18));
    cBlock = *(PWORD)(pbSubSegment + (f32 ? 0x14 : 0x1c));
    cFreeBlock = *(PWORD)(pbSubSegment + (f32 ? 0x08 : 0x10));
    // 3: sanity checks
    if(!cBlock || !dwBlockSize || (cFreeBlock >= cBlock)) { return; }
    cbAll = cbHeaderSize + cbUnitSize * dwBlockSize * cBlock;
    if((cbLfhUD < cbAll) || (cbLfhUD > cbAll + 0x80)) { return; }
    // 4: populate blocks
    for(iBlock = 0; iBlock < cBlock - cFreeBlock; iBlock++) {
        oBlock = cbHeaderSize + iBlock * cbUnitSize * dwBlockSize;
        vaChunk = vaLfhUD + oBlock + cbUnitSize;
        cbChunk = cbUnitSize * dwBlockSize - cbUnitSize;
        if(!cbChunk && !ctx->f32) {
            vaChunk -= cbUnitSize;
            cbChunk = 8;
        }
        VmmHeapAlloc_PushItem(H, &ctx->pStore, VMM_HEAPALLOC_TP_NT_LFH, vaChunk, cbChunk);
    }
}

/*
* Parse a _HEAP_USERDATA_HEADER for potential LFH entries.
* NB! Windows 7 and earlier are not supported!
*/
VOID VmmHeapAlloc_NtInitLfhUserData(_In_ VMM_HANDLE H, _In_ PVMMHEAPNT_CTX ctx, _In_ QWORD vaLfhUD, _In_ PBYTE pbLfhUD, _In_ DWORD cbLfhUD)
{
    PDWORD pdwBitmapData;
    DWORD cbUnitSize = ctx->f32 ? 8 : 16;
    DWORD cbHeaderSize = ctx->f32 ? 0x20 : 0x40;
    DWORD dw, i, iMax, iBit, cBit, oChunk, cbChunk;
    QWORD vaChunk;
    VMMHEAPALLOC_NTLFH_ENCODED Encoded;
    if(0xf0e0d0c0 != *(PDWORD)(pbLfhUD + ctx->po->nt.HEAP_USERDATA_HEADER.Signature)) { return; }
    Encoded.dw = *(PDWORD)(pbLfhUD + ctx->po->nt.HEAP_USERDATA_HEADER.EncodedOffsets);
    if(!VmmHeapAlloc_NtInitLfhUserData_VerifyEncoded(ctx->f32, &Encoded) || (Encoded.FirstAllocationOffset != cbHeaderSize)) {
        Encoded.dw = Encoded.dw ^ (DWORD)vaLfhUD ^ (DWORD)ctx->vaLfh ^ ctx->dwLfhKey;
    }
    if(!VmmHeapAlloc_NtInitLfhUserData_VerifyEncoded(ctx->f32, &Encoded)) { return; }
    cBit = *(PDWORD)(pbLfhUD + ctx->po->nt.HEAP_USERDATA_HEADER.BusyBitmap);
    if(!cBit || (cBit > cbLfhUD / Encoded.BlockStride)) { return; }
    pdwBitmapData = (PDWORD)(pbLfhUD + ctx->po->nt.HEAP_USERDATA_HEADER.BitmapData);
    iBit = 0;
    while(iBit < cBit) {
        dw = pdwBitmapData[iBit / 32];
        iMax = (DWORD)min(32, cBit - iBit);
        for(i = 0; i < iMax; i++) {
            if((dw >> i) & 1) {
                oChunk = Encoded.FirstAllocationOffset + (iBit + i) * Encoded.BlockStride;
                if(oChunk + cbUnitSize > cbLfhUD) { return; }
                vaChunk = vaLfhUD + oChunk + cbUnitSize;
                cbChunk = Encoded.BlockStride - cbUnitSize;
                if(!cbChunk && !ctx->f32) {
                    vaChunk -= cbUnitSize;
                    cbChunk = 8;
                }
                VmmHeapAlloc_PushItem(H, &ctx->pStore, VMM_HEAPALLOC_TP_NT_LFH, vaChunk, cbChunk);
            }
        }
        iBit += 32;
    }
}

/*
* Parse NT heap segment for heap entries.
*/
VOID VmmHeapAlloc_NtInitSeg(_In_ VMM_HANDLE H, _In_ PVMMHEAPNT_CTX ctx, _In_ QWORD vaSegment, _In_ PBYTE pbSegment, _In_ DWORD cbSegment, _In_ DWORD oFirst)
{
    DWORD cbUnitSize = ctx->f32 ? 8 : 16;
    QWORD vaChunk;
    _HEAPENTRY eH;
    DWORD cbAlloc, dwPreviousSize = 0, oEntry = oFirst;
    VmmLog(H, MID_HEAP, LOGLEVEL_6_TRACE, "PARSE SEGMENT: %llx :: %x ", vaSegment, cbSegment);
    while(oEntry < cbSegment - 0x10) {
        vaChunk = vaSegment + oEntry;
        if(!VmmHeap_GetEntryDecoded(ctx->f32, ctx->qwHeapEncoding, pbSegment, oEntry, &eH)) {
            if(!(vaChunk & 0xfff) && (oEntry + 0x1000 < cbSegment) && !memcmp(pbSegment + oEntry, H->ZERO_PAGE, 0x1000)) {
                // pages may be zeroed out -> skip to next page.
                dwPreviousSize = 0;
                oEntry += 0x1000;
                continue;
            }
            VmmLog(H, MID_HEAP, LOGLEVEL_6_TRACE, "FAIL: (CHECKSUM) AT: %llx %x", vaSegment, oEntry);
            break;
        }
        if(dwPreviousSize && (dwPreviousSize != eH.PreviousSize)) {
            VmmLog(H, MID_HEAP, LOGLEVEL_6_TRACE, "FAIL: (PREVSIZE) AT: %llx %x", vaSegment, oEntry);
            break;
        }
        cbAlloc = eH.Size * cbUnitSize - eH.UnusedBytes;
        if((eH.Flags & 1) && cbAlloc && (cbAlloc < 0x01000000)) {
            if(eH.Flags & 8) {
                // internal: potential lfh
                if(H->vmm.kernel.dwVersionBuild <= 7601) {
                    VmmHeapAlloc_NtInitLfhUserDataWin7(H, ctx, vaChunk + cbUnitSize, pbSegment + oEntry + cbUnitSize, cbAlloc);
                } else {
                    VmmHeapAlloc_NtInitLfhUserData(H, ctx, vaChunk + cbUnitSize, pbSegment + oEntry + cbUnitSize, cbAlloc);
                }
            } else {
                // only store active non-internal
                VmmHeapAlloc_PushItem(H, &ctx->pStore, VMM_HEAPALLOC_TP_NT_HEAP, vaChunk + cbUnitSize, cbAlloc);
            }
        }
        dwPreviousSize = eH.Size;
        oEntry += eH.Size * cbUnitSize;
    }
}

/*
* Init NT heap entries (excl. large entries)
*/
VOID VmmHeapAlloc_NtInit(_In_ VMM_HANDLE H, _In_ PVMMHEAPNT_CTX ctx)
{
    DWORD i, cbSegment, dwSegmentSignature;
    BYTE pbSegmentHdr[0x80];
    PBYTE pbSegment;
    QWORD vaFirstEntry, vaLastEntry;
    PVMM_MAP_HEAP_SEGMENTENTRY peSegment;
    if(H->vmm.kernel.dwVersionBuild <= 2600) {
        VmmLog(H, MID_HEAP, LOGLEVEL_5_DEBUG, "FAIL: HeapAlloc not supported on WinXP");
        return;
    }
    // 1: fetch encoding heap entry
    if(ctx->po->nt.HEAP.Encoding) {
        if(!VmmRead(H, ctx->pProcess, ctx->pHeapEntry->va + ctx->po->nt.HEAP.Encoding + (ctx->f32 ? 0 : 8), (PBYTE)&ctx->qwHeapEncoding, sizeof(QWORD))) {
            VmmLog(H, MID_HEAP, LOGLEVEL_4_VERBOSE, "FAIL: Fetch Heap Encoding: %llx", ctx->pHeapEntry->va);
        }
    }
    // 2: walk segments to find any LFH area, this is required for LFH decode:
    for(i = 0; i < ctx->pHeapMap->cSegments; i++) {
        peSegment = ctx->pHeapMap->pSegments + i;
        if(peSegment->iHeap == ctx->pHeapEntry->iHeap) {
            if(peSegment->tp == VMM_HEAP_SEGMENT_TP_NT_LFH) {
                ctx->vaLfh = peSegment->va;
            }
        }
    }
    // 3: fetch Lfh Key if LFH area exists
    if(ctx->vaLfh) {
        VmmHeapAlloc_GetHeapKeys(H, ctx->pProcess, ctx->f32, NULL, NULL, NULL, &ctx->dwLfhKey);
        VmmLog(H, MID_HEAP, LOGLEVEL_6_TRACE, "%s LFH KEY: %x ", (ctx->dwLfhKey ? "LOAD" : "FAIL"), ctx->dwLfhKey);
    }
    // 4: walk segments and process them!
    for(i = 0; i < ctx->pHeapMap->cSegments; i++) {
        peSegment = ctx->pHeapMap->pSegments + i;
        if(peSegment->iHeap == ctx->pHeapEntry->iHeap) {
            if(peSegment->tp == VMM_HEAP_SEGMENT_TP_NT_SEGMENT) {
                if(!VmmRead(H, ctx->pProcess, peSegment->va, pbSegmentHdr, sizeof(pbSegmentHdr))) { continue; }
                // signature check
                dwSegmentSignature = *(PDWORD)(pbSegmentHdr + (ctx->f32 ? 8 : 16));
                if(((dwSegmentSignature != 0xffeeffee) && (dwSegmentSignature != 0xeeffeeff))) { continue; }
                // first/last entry validity check
                vaFirstEntry = VMM_PTR_OFFSET(ctx->f32, pbSegmentHdr, ctx->po->nt.HEAP_SEGMENT.FirstEntry);
                vaLastEntry = VMM_PTR_OFFSET(ctx->f32, pbSegmentHdr, ctx->po->nt.HEAP_SEGMENT.LastValidEntry);
                if((vaFirstEntry < peSegment->va) || (vaLastEntry > peSegment->va + peSegment->cb) || (vaFirstEntry >= vaLastEntry)) { continue; }
                // segment size check
                cbSegment = (DWORD)((vaLastEntry + 0xfff - peSegment->va) & ~0xfff);
                if(cbSegment > peSegment->cb) { continue; }
                // read/alloc and dispatch
                if((pbSegment = LocalAlloc(0, cbSegment))) {
                    VmmReadEx(H, ctx->pProcess, peSegment->va, pbSegment, cbSegment, NULL, VMM_FLAG_ZEROPAD_ON_FAIL);
                    VmmHeapAlloc_NtInitSeg(H, ctx, peSegment->va, pbSegment, cbSegment, (DWORD)(vaFirstEntry - peSegment->va));
                    LocalFree(pbSegment);
                }
            }
        }
    }
}



// ----------------------------------------------------------------------------
// HEAP MAP GENERATION:
// ----------------------------------------------------------------------------

typedef struct tdVMMHEAP_INIT_CONTEXT {
    PVMM_PROCESS pProcess;
    POB_MAP pmeHeap;
    POB_MAP pmeHeapSegment;
    POB_SET psPrefetch;
    PVMM_OFFSET_HEAP po;
    PVMMOB_MAP_VAD pVadMap;
    BOOL f32;
} VMMHEAP_INIT_CONTEXT, *PVMMHEAP_INIT_CONTEXT;

/*
* Callback function for initialization of segment heap _HEAP_LARGE_ALLOC_DATA.
*/
VOID VmmHeap_InitializeSegment_SegLargeAllocCB(
    _In_ VMM_HANDLE H,
    _In_ PVMM_PROCESS pProcess,
    _In_ PVMMHEAP_INIT_CONTEXT ctx,
    _In_ QWORD va,
    _In_ PBYTE pb,
    _In_ DWORD cb,
    _In_ QWORD vaFLink,
    _In_ QWORD vaBLink,
    _In_ POB_SET pVSetAddress,
    _Inout_ PBOOL pfValidEntry,
    _Inout_ PBOOL pfValidFLink,
    _Inout_ PBOOL pfValidBLink,
    _In_ WORD iInitialEntry
) {
    QWORD cbVad;
    PVMM_MAP_VADENTRY peV;
    _PHEAP_LARGE_ALLOC_DATA32 p32;
    _PHEAP_LARGE_ALLOC_DATA64 p64;
    VMM_MAP_HEAP_SEGMENTENTRY e = { 0 };
    if(ctx->f32) {
        p32 = (_PHEAP_LARGE_ALLOC_DATA32)pb;
        e.va = p32->VirtualAddress;
        e.cb = min(0xffffffff, (DWORD)((p32->AllocatedPages << 12) - p32->UnusedBytes));
    } else {
        p64 = (_PHEAP_LARGE_ALLOC_DATA64)pb;
        e.va = p64->VirtualAddress;
        e.cb = (DWORD)min(0xffffffff, (p64->AllocatedPages << 12) - p64->UnusedBytes);
    }
    if((peV = VmmMap_GetVadEntry(H, ctx->pVadMap, va)) && (cbVad = peV->vaEnd + 1 + peV->vaStart) && (cbVad >= e.cb)) {
        e.tp = VMM_HEAP_SEGMENT_TP_SEG_LARGE;
        e.iHeap = iInitialEntry;
        ObMap_PushCopy(ctx->pmeHeapSegment, va, &e, sizeof(VMM_MAP_HEAP_SEGMENTENTRY));
        VmmLog(H, MID_HEAP, LOGLEVEL_6_TRACE, "SEG_LargeAlloc LOCATED: va=%llx iH=%i cb=%x", e.va, e.iHeap, e.cb);
    } else {
        VmmLog(H, MID_HEAP, LOGLEVEL_6_TRACE, "WARN: SEG_LargeAlloc NO MATCHING VAD: va=%llx", va);
    }
    *pfValidFLink = VMM_UADDR_DUAL_4_8(ctx->f32, vaFLink);
    *pfValidBLink = VMM_UADDR_DUAL_4_8(ctx->f32, vaBLink);
}

/*
* Callback function for initialization of segment heap _HEAP_PAGE_SEGMENT.
*/
VOID VmmHeap_InitializeSegment_SegPageSegmentCB(
    _In_ VMM_HANDLE H,
    _In_ PVMM_PROCESS pProcess,
    _In_ PVMMHEAP_INIT_CONTEXT ctx,
    _In_ QWORD va,
    _In_ PBYTE pb,
    _In_ DWORD cb,
    _In_ QWORD vaFLink,
    _In_ QWORD vaBLink,
    _In_ POB_SET pVSetAddress,
    _Inout_ PBOOL pfValidEntry,
    _Inout_ PBOOL pfValidFLink,
    _Inout_ PBOOL pfValidBLink,
    _In_ WORD iInitialEntry
) {
    PVMM_MAP_VADENTRY peV;
    VMM_MAP_HEAP_SEGMENTENTRY e = { 0 };
    if(va & 0xfff) { return; }
    *pfValidFLink = VMM_UADDR_DUAL_PAGE(ctx->f32, vaFLink);
    *pfValidBLink = VMM_UADDR_DUAL_PAGE(ctx->f32, vaBLink);
    if((peV = VmmMap_GetVadEntry(H, ctx->pVadMap, va))) {
        e.cb = (DWORD)min(0x00100000, peV->vaEnd + 1 - va);    // guesstimate segment size
        e.tp = VMM_HEAP_SEGMENT_TP_SEG_SEGMENT;
        e.va = va;
        e.iHeap = iInitialEntry / 2;
        ObMap_PushCopy(ctx->pmeHeapSegment, va, &e, sizeof(VMM_MAP_HEAP_SEGMENTENTRY));
        VmmLog(H, MID_HEAP, LOGLEVEL_6_TRACE, "SEG_PAGESEG LOCATED: va=%llx iH=%i", e.va, e.iHeap);
    } else {
        VmmLog(H, MID_HEAP, LOGLEVEL_6_TRACE, "WARN: SEG_PAGESEG NO MATCHING VAD: va=%llx", va);
    }
}

/*
* Callback function for initialization of NT heap large allocation.
*/
VOID VmmHeap_InitializeSegment_NtLargeAllocCB(
    _In_ VMM_HANDLE H,
    _In_ PVMM_PROCESS pProcess,
    _In_ PVMMHEAP_INIT_CONTEXT ctx,
    _In_ QWORD va,
    _In_ PBYTE pb,
    _In_ DWORD cb,
    _In_ QWORD vaFLink,
    _In_ QWORD vaBLink,
    _In_ POB_SET pVSetAddress,
    _Inout_ PBOOL pfValidEntry,
    _Inout_ PBOOL pfValidFLink,
    _Inout_ PBOOL pfValidBLink,
    _In_ WORD iInitialEntry
) {
    BOOL f32 = ctx->f32;
    QWORD cbVad, cbCommit, cbReserved;
    PVMM_MAP_VADENTRY peVad;
    VMM_MAP_HEAP_SEGMENTENTRY e = { 0 };
    if(va & 0xfff) { return; }
    if(!VMM_UADDR_DUAL_4_8(f32, vaFLink) || !VMM_UADDR_DUAL_4_8(f32, vaBLink)) {
        VmmLog(H, MID_HEAP, LOGLEVEL_6_TRACE, "WARN: NT_LargeAlloc BAD ENTRY #1: va=%llx", va);
        return;
    }
    cbCommit = VMM_PTR_OFFSET_DUAL(f32, pb, 0x10, 0x20);
    cbReserved = VMM_PTR_OFFSET_DUAL(f32, pb, 0x14, 0x28);
    if(!cbCommit || (cbCommit > cbReserved) || (cbReserved < 0x40)) {
        VmmLog(H, MID_HEAP, LOGLEVEL_6_TRACE, "WARN: NT_LargeAlloc BAD ENTRY #2: va=%llx", va);
        return;
    }
    if(!(peVad = VmmMap_GetVadEntry(H, ctx->pVadMap, va))) {
        VmmLog(H, MID_HEAP, LOGLEVEL_6_TRACE, "WARN: NT_LargeAlloc NO MATCHING VAD: va=%llx", va);
        return;
    }
    cbVad = peVad->vaEnd + 1 + max(va, peVad->vaStart);
    *pfValidFLink = ((vaFLink & 0xfff) == 0);
    *pfValidBLink = ((vaBLink & 0xfff) == 0);
    e.tp = VMM_HEAP_SEGMENT_TP_NT_LARGE;
    e.cb = (DWORD)min(0xffffffff, min(cbVad, cbCommit));
    e.va = va;
    e.iHeap = iInitialEntry / 2;
    ObMap_PushCopy(ctx->pmeHeapSegment, va, &e, sizeof(VMM_MAP_HEAP_SEGMENTENTRY));
    VmmLog(H, MID_HEAP, LOGLEVEL_6_TRACE, "NT_LargeAlloc LOCATED: va=%llx iH=%i", e.va, e.iHeap);
}

/*
* Callback function for initialization of NT heap _HEAP_SEGMENT.
*/
VOID VmmHeap_InitializeSegment_NtHeapSegmentCB(
    _In_ VMM_HANDLE H,
    _In_ PVMM_PROCESS pProcess,
    _In_ PVMMHEAP_INIT_CONTEXT ctx,
    _In_ QWORD va,
    _In_ PBYTE pb,
    _In_ DWORD cb,
    _In_ QWORD vaFLink,
    _In_ QWORD vaBLink,
    _In_ POB_SET pVSetAddress,
    _Inout_ PBOOL pfValidEntry,
    _Inout_ PBOOL pfValidFLink,
    _Inout_ PBOOL pfValidBLink,
    _In_ WORD iInitialEntry
) {
    BOOL f32 = ctx->f32;
    PVMM_MAP_HEAPENTRY pH;
    VMM_MAP_HEAP_SEGMENTENTRY e = { 0 };
    _PHEAP_SEGMENT64 ph64;
    _PHEAP_SEGMENT32 ph32;
    _PHEAP_SEGMENT32_XP ph32XP;
    DWORD dwSegmentSignature;
    QWORD vaHeap, cNumberOfPages;
    if(!va || !(!vaFLink || VMM_UADDR_DUAL_4_8(f32, vaFLink)) || !(!vaBLink || VMM_UADDR_DUAL_4_8(f32, vaBLink))) {
        VmmLog(H, MID_HEAP, LOGLEVEL_6_TRACE, "WARN: NT_SEG BAD ENTRY: va=%llx", va);
        return;
    }
    if(f32) {
        if(H->vmm.kernel.dwVersionBuild <= 2600) {
            ph32XP = (_PHEAP_SEGMENT32_XP)pb;
            vaHeap = ph32XP->Heap;
            cNumberOfPages = ph32XP->NumberOfPages;
            dwSegmentSignature = ph32XP->SegmentSignature;
        } else {
            ph32 = (_PHEAP_SEGMENT32)pb;
            vaHeap = ph32->Heap;
            cNumberOfPages = ph32->NumberOfPages;
            dwSegmentSignature = ph32->SegmentSignature;
        }
    } else {
        ph64 = (_PHEAP_SEGMENT64)pb;
        vaHeap = ph64->Heap;
        cNumberOfPages = ph64->NumberOfPages;
        dwSegmentSignature = ph64->SegmentSignature;
    }
    if((va & 0xfff) || (cNumberOfPages >= 0x00f00000) || ((dwSegmentSignature != 0xffeeffee) && (dwSegmentSignature != 0xeeffeeff))) {
        if(!(va & 0xfff)) {
            VmmLog(H, MID_HEAP, LOGLEVEL_6_TRACE, "WARN: NT_SEG BAD SEGMENT: va=%llx sig=%08x pg=%x", va, dwSegmentSignature, (DWORD)cNumberOfPages);
        }
        return;
    }
    if(!(pH = ObMap_GetByKey(ctx->pmeHeap, vaHeap)) && (H->vmm.kernel.dwVersionBuild > 2600)) {
        VmmLog(H, MID_HEAP, LOGLEVEL_6_TRACE, "WARN: NT_SEG BAD HEAP: va=%llx vaH=%llx", va, vaHeap);
        return;
    }
    *pfValidFLink = ((vaFLink & 0xfff) < 0x40);
    *pfValidBLink = ((vaFLink & 0xfff) < 0x40);
    e.tp = VMM_HEAP_SEGMENT_TP_NT_SEGMENT;
    e.cb = (DWORD)min(0xffffffff, cNumberOfPages << 12);
    e.va = va;
    e.iHeap = pH ? pH->iHeap : iInitialEntry;
    ObMap_PushCopy(ctx->pmeHeapSegment, va, &e, sizeof(VMM_MAP_HEAP_SEGMENTENTRY));
    VmmLog(H, MID_HEAP, LOGLEVEL_6_TRACE, "NT_SEG LOCATED: va=%llx iH=%i vaH=%llx", e.va, e.iHeap, vaHeap);
}

/*
* Initialize any segment heaps in process.
*/
VOID VmmHeap_Initialize3264_SegmentHeap(_In_ VMM_HANDLE H, _In_ PVMMHEAP_INIT_CONTEXT ctx, _In_ BOOL f32)
{
    PVMM_MAP_HEAPENTRY peH = NULL;
    VMM_MAP_HEAP_SEGMENTENTRY eR;
    PVMM_MAP_VADENTRY peV;
    DWORD iHeap, cHeap;
    QWORD i, ova, va;
    BYTE pbBuffer[0x400];
    BOOL fPageSegment = FALSE, fLargeAlloc = FALSE;
    PQWORD avaBuffer = NULL, avaPageSegment, avaLargeAlloc;
    // 1: initialize and fetch vad map
    if(!(avaBuffer = LocalAlloc(LMEM_ZEROINIT, 3 * VMMHEAP_MAX_HEAPS * sizeof(QWORD)))) { goto fail; }
    avaPageSegment = avaBuffer;
    avaLargeAlloc = avaBuffer + 2 * VMMHEAP_MAX_HEAPS;
    // 2: process segment heaps
    cHeap = ObMap_Size(ctx->pmeHeap);
    for(iHeap = 0; iHeap < cHeap; iHeap++) {
        peH = ObMap_GetByIndex(ctx->pmeHeap, iHeap);
        if((peH->tp != VMM_HEAP_TP_SEG) || (peH->f32 != f32)) { continue; }
        // 2.1: add the _SEGMENT_HEAP itself as a range:
        if((peV = VmmMap_GetVadEntry(H, ctx->pVadMap, peH->va))) {
            eR.tp = VMM_HEAP_SEGMENT_TP_SEG_HEAP;
            eR.cb = (DWORD)min(0xffffffff, peV->vaEnd + 1 - peV->vaStart);
            eR.va = peH->va;
            eR.iHeap = peH->iHeap;
            ObMap_PushCopy(ctx->pmeHeapSegment, eR.va, &eR, sizeof(VMM_MAP_HEAP_SEGMENTENTRY));
        }
        // 2.2: pepare list walk of _HEAP_PAGE_SEGMENT
        if(!VmmRead(H, ctx->pProcess, peH->va, pbBuffer, sizeof(pbBuffer))) { continue; }
        for(i = 0; i < 2; i++) {
            ova = ctx->po->seg.SEGMENT_HEAP.SegContexts + i * ctx->po->seg.HEAP_SEG_CONTEXT.cb + ctx->po->seg.HEAP_SEG_CONTEXT.SegmentListHead;
            va = VMM_PTR_OFFSET(f32, pbBuffer, ova);
            if(VMM_UADDR_DUAL_PAGE(f32, va)) {
                fPageSegment = TRUE;
                avaPageSegment[2 * peH->iHeap + 0] = va;
                va = VMM_PTR_OFFSET_DUAL(f32, pbBuffer, ova + 4, ova + 8);
                if(VMM_UADDR_DUAL_PAGE(f32, va)) {
                    avaPageSegment[2 * peH->iHeap + 1] = va;
                }
            }
        }
        // 2.3 prepare list walk of _HEAP_LARGE_ALLOC_DATA
        if(VMM_PTR_OFFSET(f32, pbBuffer, ctx->po->seg.SEGMENT_HEAP.LargeReservedPages)) {
            va = VMM_PTR_OFFSET(f32, pbBuffer, ctx->po->seg.SEGMENT_HEAP.LargeAllocMetadata);
            if(VMM_UADDR_DUAL_4_8(f32, va)) {
                fLargeAlloc = TRUE;
                avaLargeAlloc[peH->iHeap] = va;
            }
        }
    }
    // 3: walk _HEAP_PAGE_SEGMENT lists:
    if(fPageSegment) {
        VmmWin_ListTraversePrefetch(
            H,
            ctx->pProcess,
            f32,
            ctx,
            2 * cHeap,
            avaPageSegment,
            0,
            0x20,
            (VMMWIN_LISTTRAVERSE_PRE_CB)VmmHeap_InitializeSegment_SegPageSegmentCB,
            NULL,
            NULL
        );
    }
    // 3: walk _HEAP_LARGE_ALLOC_DATA trees:
    //    Even if it's a tree it can viewed as a list from the
    //    perspective of the list traversal function.
    if(fLargeAlloc) {
        VmmWin_ListTraversePrefetch(
            H,
            ctx->pProcess,
            f32,
            ctx,
            cHeap,
            avaLargeAlloc,
            0,
            0x40,
            (VMMWIN_LISTTRAVERSE_PRE_CB)VmmHeap_InitializeSegment_SegLargeAllocCB,
            NULL,
            NULL
        );
    }
fail:
    LocalFree(avaBuffer);
}

/*
* Initialize process heaps (NT and Segment) from either a 32-bit or 64-bit PEB.
*/
VOID VmmHeap_InitializeInternal(_In_ VMM_HANDLE H, _In_ PVMMHEAP_INIT_CONTEXT ctx, _In_ BOOL f32)
{
    BOOL f, fNtAllocD = FALSE, fSegmentHeap = FALSE;
    QWORD va, vaPEB, vaHeap;
    DWORD vaHeaps32[VMMHEAP_MAX_HEAPS];
    QWORD vaHeaps64[VMMHEAP_MAX_HEAPS];
    DWORD dwSignature, iHeap, cMaxHeaps, cNtSegment = 0, cNtAllocd = 0;
    VMM_MAP_HEAPENTRY eH = { 0 };
    BYTE pbBuffer[0x200];
    PPEB32 pPEB32 = (PPEB32)pbBuffer;
    PPEB64 pPEB64 = (PPEB64)pbBuffer;
    VMM_MAP_HEAP_SEGMENTENTRY eR = { 0 };
    PQWORD avaBuffer = NULL, avaNtSegment, avaNtLargeAlloc;
    if(f32) {
        // 1: read PEB
        f = (vaPEB = (DWORD)(ctx->pProcess->win.fWow64 ? ctx->pProcess->win.vaPEB32 : ctx->pProcess->win.vaPEB)) &&
            VmmRead(H, ctx->pProcess, vaPEB, pbBuffer, sizeof(PEB32));
        if(!f) {
            VmmLog(H, MID_HEAP, LOGLEVEL_6_TRACE, "FAIL: HEAP BAD PEB: va=%llx", vaPEB);
            return;
        }
        // 2: read heap array
        cMaxHeaps = pPEB32->NumberOfHeaps;
        f = (pPEB32->NumberOfHeaps < VMMHEAP_MAX_HEAPS) &&
            (pPEB32->NumberOfHeaps <= pPEB32->MaximumNumberOfHeaps) &&
            VMM_UADDR32_4(pPEB32->ProcessHeaps) &&
            VmmRead(H, ctx->pProcess, pPEB32->ProcessHeaps, (PBYTE)vaHeaps32, cMaxHeaps * sizeof(DWORD)) &&
            (vaHeaps32[0] == pPEB32->ProcessHeap);
        if(!f) {
            VmmLog(H, MID_HEAP, LOGLEVEL_6_TRACE, "FAIL: HEAP BAD ARRAY: va=%x #=%i #m=%i", pPEB32->ProcessHeaps, pPEB32->NumberOfHeaps, pPEB32->MaximumNumberOfHeaps);
            return;
        }
    } else {
        // 1: read PEB
        f = (vaPEB = ctx->pProcess->win.vaPEB) &&
            VmmRead(H, ctx->pProcess, vaPEB, pbBuffer, sizeof(PEB64));
        if(!f) {
            VmmLog(H, MID_HEAP, LOGLEVEL_6_TRACE, "FAIL: HEAP BAD PEB: va=%llx", vaPEB);
            return;
        }
        // 2: read heap array
        cMaxHeaps = pPEB64->NumberOfHeaps;
        f = (pPEB64->NumberOfHeaps < VMMHEAP_MAX_HEAPS) &&
            (pPEB64->NumberOfHeaps <= pPEB64->MaximumNumberOfHeaps) &&
            VMM_UADDR64_8(pPEB64->ProcessHeaps) &&
            VmmRead(H, ctx->pProcess, pPEB64->ProcessHeaps, (PBYTE)vaHeaps64, cMaxHeaps * sizeof(QWORD)) &&
            (vaHeaps64[0] == pPEB64->ProcessHeap);
        if(!f) {
            VmmLog(H, MID_HEAP, LOGLEVEL_6_TRACE, "FAIL: HEAP BAD ARRAY: va=%llx #=%i #m=%i", pPEB64->ProcessHeaps, pPEB64->NumberOfHeaps, pPEB64->MaximumNumberOfHeaps);
            return;
        }
    }
    // 3: initialize va buffers + verify & prefetch heaps
    if(!(avaBuffer = (PQWORD)LocalAlloc(LMEM_ZEROINIT, 3 * VMMHEAP_MAX_HEAPS * sizeof(QWORD)))) { return; }
    avaNtSegment = avaBuffer;
    avaNtLargeAlloc = avaBuffer + VMMHEAP_MAX_HEAPS;
    for(iHeap = 0; iHeap < cMaxHeaps; iHeap++) {
        vaHeap = f32 ? vaHeaps32[iHeap] : vaHeaps64[iHeap];
        if(VMM_UADDR_DUAL_PAGE(f32, vaHeap)) {
            ObSet_Push(ctx->psPrefetch, vaHeap);
        } else if(vaHeap) {
            VmmLog(H, MID_HEAP, LOGLEVEL_6_TRACE, "WARN: HEAP BAD ADDR: va=%llx i=%i", vaHeap, iHeap);
            vaHeaps32[iHeap] = 0;
            vaHeaps64[iHeap] = 0;
        }
    }
    VmmCachePrefetchPages(H, ctx->pProcess, ctx->psPrefetch, 0);
    // 4: read & add heaps:
    eH.f32 = f32;
    for(iHeap = 0; iHeap < cMaxHeaps; iHeap++) {
        vaHeap = f32 ? vaHeaps32[iHeap] : vaHeaps64[iHeap];
        if(!vaHeap) { continue; }
        if(ObMap_ExistsKey(ctx->pmeHeap, vaHeap)) {
            VmmLog(H, MID_HEAP, LOGLEVEL_6_TRACE, "WARN: HEAP EXISTS: va=%llx", vaHeap);
            continue;
        }
        if(!VmmRead2(H, ctx->pProcess, vaHeap, pbBuffer, sizeof(pbBuffer), VMM_FLAG_FORCECACHE_READ)) { continue; }
        dwSignature = *(PDWORD)(pbBuffer + (f32 ? 8 : 16));
        eH.iHeap = ObMap_Size(ctx->pmeHeap);
        eH.dwHeapNum = iHeap;
        eH.va = vaHeap;
        switch(dwSignature) {
            case 0xeeffeeff:    // NT HEAP XP
            case 0xffeeffee:    // NT HEAP
                // NtVirtualAllocD (large allocations)
                va = VMM_PTR_OFFSET(f32, pbBuffer, ctx->po->nt.HEAP.VirtualAllocdBlocks) & ~0xfff;
                if(va && (va != vaHeap)) {
                    fNtAllocD = TRUE;
                    avaNtLargeAlloc[2 * cNtSegment] = va;
                    avaNtLargeAlloc[2 * cNtSegment] = (DWORD)VMM_PTR_OFFSET(f32, pbBuffer, (QWORD)ctx->po->nt.HEAP.VirtualAllocdBlocks + (f32 ? 4 : 8)) & ~0xfff;
                }
                // LFH (frontend) area
                if((pbBuffer[ctx->po->nt.HEAP.FrontEndHeapType] == 2) && (va = VMM_PTR_OFFSET(f32, pbBuffer, ctx->po->nt.HEAP.FrontEndHeap)) && VMM_UADDR_PAGE(H->vmm.f32, va)) {
                    eR.tp = VMM_HEAP_SEGMENT_TP_NT_LFH;
                    eR.va = va;
                    eR.cb = 0x20000;
                    eR.iHeap = cNtSegment;
                    ObMap_PushCopy(ctx->pmeHeapSegment, va, &eR, sizeof(VMM_MAP_HEAP_SEGMENTENTRY));
                    VmmLog(H, MID_HEAP, LOGLEVEL_6_TRACE, "NT_LFH LOCATED: va=%llx iH=%i vaH=%llx", eR.va, eR.iHeap, vaHeap);
                }
                // NtSegment
                avaNtSegment[cNtSegment++] = vaHeap;
                eH.tp = VMM_HEAP_TP_NT;
                break;
            case 0xddeeddee:    // SEGMENT HEAP
                if(H->vmm.kernel.dwVersionBuild <= 9200) { continue; } // segment heap not valid on Win8.0 and before
                eH.tp = VMM_HEAP_TP_SEG;
                fSegmentHeap = TRUE;
                break;
            default:
                VmmLog(H, MID_HEAP, LOGLEVEL_6_TRACE, "WARN: HEAP BAD SIGNATURE: va=%llx sig=%08x", vaHeap, dwSignature);
                continue;
        }
        ObMap_PushCopy(ctx->pmeHeap, vaHeap, &eH, sizeof(VMM_MAP_HEAPENTRY));
        VmmLog(H, MID_HEAP, LOGLEVEL_6_TRACE, "%s_HEAP LOCATED: va=%llx iH=%i", VMM_HEAP_TP_STR[eH.tp], vaHeap, eH.iHeap);
    }
    // 5: walk nt heap ranges (_HEAP_SEGMENT) in an efficient way:
    if(cNtSegment) {
        VmmWin_ListTraversePrefetch(
            H,
            ctx->pProcess,
            f32,
            ctx,
            cNtSegment,
            avaNtSegment,
            f32 ? 0x10 : 0x18,
            f32 ? sizeof(_HEAP_SEGMENT32) : sizeof(_HEAP_SEGMENT64),
            (VMMWIN_LISTTRAVERSE_PRE_CB)VmmHeap_InitializeSegment_NtHeapSegmentCB,
            NULL,
            NULL
        );
    }
    // 6: walk nt heap ranges (_HEAP_VIRTUAL_ALLOC_ENTRY):
    if(fNtAllocD) {
        VmmWin_ListTraversePrefetch(
            H,
            ctx->pProcess,
            f32,
            ctx,
            2 * cNtSegment,
            avaNtLargeAlloc,
            0,
            0x40,
            (VMMWIN_LISTTRAVERSE_PRE_CB)VmmHeap_InitializeSegment_NtLargeAllocCB,
            NULL,
            NULL
        );
    }
    // 7: initialize segment heap ranges if they exists:
    if(fSegmentHeap) {
        VmmHeap_Initialize3264_SegmentHeap(H, ctx, f32);
    }
    LocalFree(avaBuffer);
}

int VmmHeap_qsort_SegmentEntry(PVMM_MAP_HEAP_SEGMENTENTRY p1, PVMM_MAP_HEAP_SEGMENTENTRY p2)
{
    return (p1->va < p2->va) ? -1 : ((p1->va > p2->va) ? 1 : 0);
}

int VmmHeap_qsort_HeapEntry(PVMM_MAP_HEAPENTRY p1, PVMM_MAP_HEAPENTRY p2)
{
    if(p1->dwHeapNum == p2->dwHeapNum) {
        return (p1->va < p2->va) ? -1 : ((p1->va > p2->va) ? 1 : 0);
    }
    return (p1->dwHeapNum < p2->dwHeapNum) ? -1 : ((p1->dwHeapNum > p2->dwHeapNum) ? 1 : 0);
}

/*
* Create a new heap map in a single-threaded process context. The heap map will
* upon completion be assigned to pProcess->Map.pObHeap
* -- pProcess
*/
VOID VmmHeap_Initialize_DoWork(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess)
{
    VMMHEAP_INIT_CONTEXT ctxInit = { 0 };
    PVMMOB_MAP_HEAP pObHeapMap;
    PVMM_MAP_HEAPENTRY peH;
    PVMM_MAP_HEAP_SEGMENTENTRY peR;
    DWORD i, cbData, cHeaps, cSegments;
    VMMSTATISTICS_LOG Statistics = { 0 };
    // init:
    VmmStatisticsLogStart(H, MID_HEAP, LOGLEVEL_6_TRACE, pProcess, &Statistics, "INIT_HEAPMAP");
    ctxInit.pProcess = pProcess;
    if(!(ctxInit.psPrefetch = ObSet_New(H))) { goto fail; }
    if(!(ctxInit.pmeHeap = ObMap_New(H, OB_MAP_FLAGS_OBJECT_LOCALFREE))) { goto fail; }
    if(!(ctxInit.pmeHeapSegment = ObMap_New(H, OB_MAP_FLAGS_OBJECT_LOCALFREE))) { goto fail; }
    if(!VmmMap_GetVad(H, pProcess, &ctxInit.pVadMap, VMM_VADMAP_TP_CORE)) {
        VmmLog(H, MID_HEAP, LOGLEVEL_5_DEBUG, "FAIL: NO VAD: pid=%i", pProcess->dwPID);
        goto fail;
    }
    // fetch data:
    if((H->vmm.tpSystem == VMM_SYSTEM_WINDOWS_32) || ((H->vmm.tpSystem == VMM_SYSTEM_WINDOWS_64) && pProcess->win.fWow64)) {
        if(!H->vmm.offset.HEAP32.fValid) { goto fail; }
        ctxInit.po = &H->vmm.offset.HEAP32;
        ctxInit.f32 = TRUE;
        VmmHeap_InitializeInternal(H, &ctxInit, TRUE);
        ObSet_Clear(ctxInit.psPrefetch);
    }
    if(H->vmm.tpSystem == VMM_SYSTEM_WINDOWS_64) {
        if(!H->vmm.offset.HEAP64.fValid) { goto fail; }
        ctxInit.po = &H->vmm.offset.HEAP64;
        ctxInit.f32 = FALSE;
        VmmHeap_InitializeInternal(H, &ctxInit, FALSE);
    }
    // alloc and fill map object:
    cHeaps = ObMap_Size(ctxInit.pmeHeap);
    cSegments = ObMap_Size(ctxInit.pmeHeapSegment);
    if((cHeaps > VMMHEAP_MAX_HEAPS) || (cSegments > 0x00100000)) { goto fail; }
    cbData = sizeof(VMMOB_MAP_HEAP) + cHeaps * sizeof(VMM_MAP_HEAPENTRY) + cSegments * sizeof(VMM_MAP_HEAP_SEGMENTENTRY);
    if(!(pObHeapMap = Ob_AllocEx(H, OB_TAG_MAP_HEAP, 0, cbData, NULL, NULL))) { goto fail; }
    pObHeapMap->cMap = cHeaps;
    for(i = 0; i < cHeaps; i++) {
        peH = ObMap_GetByIndex(ctxInit.pmeHeap, i);
        memcpy(pObHeapMap->pMap + i, peH, sizeof(VMM_MAP_HEAPENTRY));
    }
    pObHeapMap->pSegments = (PVMM_MAP_HEAP_SEGMENTENTRY)((SIZE_T)pObHeapMap + sizeof(VMMOB_MAP_HEAP) + cHeaps * sizeof(VMM_MAP_HEAPENTRY));
    pObHeapMap->cSegments = cSegments;
    for(i = 0; i < cSegments; i++) {
        peR = ObMap_GetByIndex(ctxInit.pmeHeapSegment, i);
        memcpy(pObHeapMap->pSegments + i, peR, sizeof(VMM_MAP_HEAP_SEGMENTENTRY));
    }
    qsort(pObHeapMap->pMap, pObHeapMap->cMap, sizeof(VMM_MAP_HEAPENTRY), (_CoreCrtNonSecureSearchSortCompareFunction)VmmHeap_qsort_HeapEntry);
    qsort(pObHeapMap->pSegments, pObHeapMap->cSegments, sizeof(VMM_MAP_HEAP_SEGMENTENTRY), (_CoreCrtNonSecureSearchSortCompareFunction)VmmHeap_qsort_SegmentEntry);
    pProcess->Map.pObHeap = pObHeapMap;     // pProcess take reference responsibility
fail:
    Ob_DECREF(ctxInit.pVadMap);
    Ob_DECREF(ctxInit.pmeHeap);
    Ob_DECREF(ctxInit.pmeHeapSegment);
    Ob_DECREF(ctxInit.psPrefetch);
    VmmStatisticsLogEnd(H, &Statistics, "INIT_HEAPMAP");
}

/*
* Initialize the heap map containing information about the process heaps in the
* specific process. This is performed by a PEB walk/scan of in-process memory
* structures. This may be unreliable if a process is obfuscated or tampered.
* -- pProcess
* -- return
*/
BOOL VmmHeap_Initialize(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess)
{
    if(pProcess->Map.pObHeap)   { return TRUE; }    // heap already exist
    if(pProcess->dwState == 1)  { return FALSE; }   // terminated process
    VmmTlbSpider(H, pProcess);
    EnterCriticalSection(&pProcess->LockUpdate);
    if(!pProcess->Map.pObHeap) {
        VmmHeap_Initialize_DoWork(H, pProcess);
    }
    LeaveCriticalSection(&pProcess->LockUpdate);
    return pProcess->Map.pObHeap ? TRUE : FALSE;
}
