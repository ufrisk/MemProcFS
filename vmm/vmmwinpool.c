// vmmwinpool.c : implementation of functionality related to kernel pools.
// 
// The pool functionality should be considered 'BETA' stage. The BigPoolTable
// is stable while other functionality is not.
// 
// Pool entries may be missing or may be false positives!
// 
// Limitations:
// WINXP: PagedPool & BigPoolTable not supported.
// VISTA->WIN8.1: PagedPool not supported.
// WIN10 1507->1803: PagedPool/NonPagedPool not supported.
// WIN10 1809+: Support but pages may be missing.
//
// (c) Ulf Frisk, 2021-2025
// Author: Ulf Frisk, pcileech@frizk.net
//

#include "vmmwinpool.h"
#include "vmmwindef.h"
#include "pdb.h"
#include "util.h"
#include "statistics.h"

#define VMMWINPOOL_PREFETCH_BUFFER_SIZE     0x00800000

//-----------------------------------------------------------------------------
// General Pool Functionality:
//-----------------------------------------------------------------------------

/*
* Convert the Windows internal pool type to VMM_MAP_POOL_TP
* -- dwPoolType
* -- return
*/
__forceinline VMM_MAP_POOL_TP VmmWinPool_PoolTypeConvert(_In_ DWORD dwPoolType)
{
    if(dwPoolType & 1) {
        return VMM_MAP_POOL_TP_PagedPool;
    } else if(dwPoolType & 0x200) {
        return VMM_MAP_POOL_TP_NonPagedPoolNx;
    } else {
        return VMM_MAP_POOL_TP_NonPagedPool;
    }
}



//-----------------------------------------------------------------------------
// BIG POOL TABLE:
// The Big Pool Table contains allocations of 0x1000 bytes and above on all
// Windows versions. XP is not yet supported. The Big Pool table is found by
// 'nt!PoolBigPageTable' and 'nt!PoolBigPageTableSize' debug symbols
// The Big Pool Table is parsed in one single efficient read/walk.
//-----------------------------------------------------------------------------

typedef struct {
    QWORD va;
    DWORD key;
    DWORD Pattern : 8;
    DWORD PoolType : 12;
    DWORD SlushSize : 12;
    QWORD NumberOfBytes;
    QWORD ProcessBilled;        // EPROCESS
} _BIGPOOL64_11, *P_BIGPOOL64_11;

typedef struct {
    QWORD va;
    DWORD key;
    DWORD Pattern : 8;
    DWORD PoolType : 12;
    DWORD SlushSize : 12;
    QWORD NumberOfBytes;
} _BIGPOOL64_10, *P_BIGPOOL64_10;

typedef struct {
    QWORD va;
    DWORD key;
    DWORD PoolType;
    QWORD NumberOfBytes;
} _BIGPOOL64_VISTA, *P_BIGPOOL64_VISTA;

typedef struct {
    DWORD va;
    DWORD key;
    DWORD Pattern   : 8;
    DWORD PoolType  : 12;
    DWORD SlushSize : 12;
    DWORD NumberOfBytes;
} _BIGPOOL32_10, *P_BIGPOOL32_10;

typedef struct {
    DWORD va;
    DWORD key;
    DWORD PoolType;
    DWORD NumberOfBytes;
} _BIGPOOL32_VISTA, *P_BIGPOOL32_VISTA;

typedef struct {
    DWORD va;
    DWORD key;
    DWORD NumberOfPages;
    DWORD _Filler;
} _BIGPOOL32_XP, *P_BIGPOOL32_XP;

int _VmmWinPool_qsort_PoolEntry(PVMM_MAP_POOLENTRY p1, PVMM_MAP_POOLENTRY p2)
{
    return (p1->va < p2->va) ? -1 : ((p1->va > p2->va) ? 1 : 0);
}

_Success_(return != NULL)
PVMMOB_MAP_POOL VmmWinPool_Initialize_BigPool_DoWork(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pSystemProcess)
{
    BOOL f32 = H->vmm.f32;
    DWORD dwVersionBuild = H->vmm.kernel.dwVersionBuild;
    DWORD i, j, o, cPoolBigTable = 0, iEntry, cbEntry = 0x10;
    DWORD cTag, cTag2Map = 0;
    QWORD cEntry;
    QWORD cbPool, va = 0, vaPoolBigTable = 0;
    PBYTE pb = NULL;
    POB_MAP pmObTag = NULL;
    POB_COUNTER pObCnt = NULL;
    PVMMOB_MAP_POOL pObPool = NULL;
    PVMM_MAP_POOLENTRY pePool;
    PVMM_MAP_POOLENTRYTAG peTag;
    // OS dependent bigpool entries
    P_BIGPOOL64_10    pbp1064;
    P_BIGPOOL64_VISTA pbpVI64;
    P_BIGPOOL32_10    pbp1032;
    P_BIGPOOL32_VISTA pbpVI32;
    P_BIGPOOL32_XP    pbpXP32;
    // 0: winxp big pool code is not working - return empty pool
    if(dwVersionBuild < 6000) {
        return (PVMMOB_MAP_POOL)Ob_AllocEx(H, OB_TAG_MAP_POOL, LMEM_ZEROINIT, sizeof(VMMOB_MAP_POOL), NULL, NULL);
    }
    // 1: initial sizes
    if(!f32) {
        cbEntry = 0x18;
        if(dwVersionBuild >= 20348) { cbEntry = 0x20; }  // SERVER-2022 / WIN11 and above
    }
    // 2: initial allocs
    if(!(pObCnt = ObCounter_New(H, 0))) { goto fail; }
    if(!PDB_GetSymbolPTR(H, PDB_HANDLE_KERNEL, "PoolBigPageTable", pSystemProcess, (PVOID)&vaPoolBigTable)) { goto fail; }
    if(!PDB_GetSymbolDWORD(H, PDB_HANDLE_KERNEL, "PoolBigPageTableSize", pSystemProcess, &cPoolBigTable)) { goto fail; }
    if(!VMM_KADDR_PAGE(f32, vaPoolBigTable) || (cPoolBigTable & 0xfff) || (cPoolBigTable > 0x01000000)) { goto fail; }
    if(!(pb = LocalAlloc(0, (SIZE_T)cbEntry * cPoolBigTable))) { goto fail; }
    VmmReadEx(H, pSystemProcess, vaPoolBigTable, pb, cbEntry * cPoolBigTable, NULL, VMM_FLAG_ZEROPAD_ON_FAIL);
    // 3: count entries
    if(f32) {
        for(i = 0, o = 0; i < cPoolBigTable; i++) {
            if(VMM_KADDR32(*(PDWORD)(pb + o))) {
                ObCounter_Inc(pObCnt, (QWORD)(*(PDWORD)(pb + o + 4)));
            }
            o += cbEntry;
        }
    } else {
        for(i = 0, o = 0; i < cPoolBigTable; i++) {
            if(VMM_KADDR64(*(PQWORD)(pb + o))) {
                ObCounter_Inc(pObCnt, (QWORD)(*(PDWORD)(pb + o + 8)));
            }
            o += cbEntry;
        }
    }
    cTag = ObCounter_Size(pObCnt);
    cEntry = ObCounter_CountAll(pObCnt);
    if(!cTag || !cEntry || (cEntry > 0x40000000)) { goto fail; }
    // 4: alloc map
    cbPool = sizeof(VMMOB_MAP_POOL);
    cbPool += (DWORD)cEntry * sizeof(VMM_MAP_POOLENTRY);
    cbPool += cTag * sizeof(VMM_MAP_POOLENTRYTAG);
    cbPool += (DWORD)cEntry * sizeof(DWORD);
    if(!(pObPool = Ob_AllocEx(H, OB_TAG_MAP_POOL, LMEM_ZEROINIT, (SIZE_T)cbPool, NULL, NULL))) { goto fail; }
    pObPool->cTag = cTag;
    pObPool->cMap = (DWORD)cEntry;
    pObPool->pTag = (PVMM_MAP_POOLENTRYTAG)(pObPool->pMap + pObPool->cMap);
    pObPool->piTag2Map = (PDWORD)(pObPool->pTag + pObPool->cTag);
    // 5: fill tags sorted by pool tag and set up shortcut hashmap
    if(!ObCounter_GetAllSortedByKey(pObCnt, pObPool->cTag, (POB_COUNTER_ENTRY)pObPool->pTag)) { goto fail; }
    if(!(pmObTag = ObMap_New(H, OB_MAP_FLAGS_OBJECT_VOID))) { goto fail; }
    for(i = 0; i < pObPool->cTag; i++) {
        peTag = pObPool->pTag + i;
        cTag2Map += peTag->cEntry;
        peTag->iTag2Map = cTag2Map;
        ObMap_Push(pmObTag, 0x100000000 | peTag->dwTag, peTag);
    }
    // 6: populate map entries (os dependent)
    if(f32) {
        for(i = 0, j = 0, o = 0; i < cPoolBigTable; i++) {
            va = *(PDWORD)(pb + o);
            if(VMM_KADDR32(va)) {
                pePool = pObPool->pMap + j;
                pePool->va = va;
                pePool->dwTag = *(PDWORD)(pb + o + 4);
                if(dwVersionBuild >= 10240) {
                    pbp1032 = (P_BIGPOOL32_10)(pb + o);
                    pePool->tpPool = VmmWinPool_PoolTypeConvert(pbp1032->PoolType);
                    pePool->cb = pbp1032->NumberOfBytes;
                } else if(dwVersionBuild >= 6000) {
                    pbpVI32 = (P_BIGPOOL32_VISTA)(pb + o);
                    pePool->tpPool = VmmWinPool_PoolTypeConvert(pbpVI32->PoolType);
                    pePool->cb = pbpVI32->NumberOfBytes;
                } else {
                    pbpXP32 = (P_BIGPOOL32_XP)(pb + o);
                    pePool->tpPool = VMM_MAP_POOL_TP_NonPagedPool;
                    pePool->cb = 0x1000 * pbpXP32->NumberOfPages;
                }
                j++;
            }
            o += cbEntry;
        }
    } else {
        for(i = 0, j = 0, o = 0; i < cPoolBigTable; i++) {
            va = *(PQWORD)(pb + o);
            if(VMM_KADDR64(va)) {
                pePool = pObPool->pMap + j;
                pePool->va = va;
                pePool->dwTag = *(PDWORD)(pb + o + 8);
                if(dwVersionBuild >= 10240) {
                    pbp1064 = (P_BIGPOOL64_10)(pb + o);
                    pePool->tpPool = VmmWinPool_PoolTypeConvert(pbp1064->PoolType);
                    pePool->cb = (DWORD)min(0xffffffff, pbp1064->NumberOfBytes);
                } else {
                    pbpVI64 = (P_BIGPOOL64_VISTA)(pb + o);
                    pePool->tpPool = VmmWinPool_PoolTypeConvert(pbpVI64->PoolType);
                    pePool->cb = (DWORD)min(0xffffffff, pbpVI64->NumberOfBytes);
                }
                j++;
            }
            o += cbEntry;
        }
    }
    // 7: sort by va and populate by-tag list
    qsort(pObPool->pMap, pObPool->cMap, sizeof(VMM_MAP_POOLENTRY), (_CoreCrtNonSecureSearchSortCompareFunction)_VmmWinPool_qsort_PoolEntry);
    iEntry = pObPool->cMap;
    while(iEntry) {
        iEntry--;
        pePool = pObPool->pMap + iEntry;
        pePool->va = pePool->va & ~0xfff;   // sometimes addr ends with '1' - why?
        if((peTag = ObMap_GetByKey(pmObTag, 0x100000000 | pePool->dwTag))) {
            peTag->iTag2Map--;
            pObPool->piTag2Map[peTag->iTag2Map] = iEntry;
        }
        pePool->tpSS = VMM_MAP_POOL_TPSS_BIG;
        pePool->fAlloc = 1;
    }
    // 8: finish!
    Ob_INCREF(pObPool);
fail:
    LocalFree(pb);
    Ob_DECREF(pObCnt);
    Ob_DECREF(pmObTag);
    return Ob_DECREF(pObPool);
}



//-----------------------------------------------------------------------------
// GENERAL POOL FUNCTIONALITY:
//-----------------------------------------------------------------------------

#define VMMWINPOOL_CTX_POOLSTORE_MAX    0x10000

typedef struct tdVMMWINPOOL_CTX_POOLSTORE {
    struct tdVMMWINPOOL_CTX_POOLSTORE *pNext;
    DWORD c;
    DWORD cPrevious;
    VMM_MAP_POOLENTRY e[VMMWINPOOL_CTX_POOLSTORE_MAX];
} VMMWINPOOL_CTX_POOLSTORE, *PVMMWINPOOL_CTX_POOLSTORE;

/*
* Push an entry onto the pool store lists.
* NB! va, pbPoolBlock, cbPoolEntry should _INCLUDE_ pool header!
*/
VOID VmmWinPool_AllPool_PushItem(
    _In_ VMM_HANDLE H,
    _In_ PVMMWINPOOL_CTX_POOLSTORE *ppStore,
    _In_ VMM_MAP_POOL_TP tp,
    _In_ VMM_MAP_POOL_TPSS tpSS,
    _In_ QWORD va,
    _In_ PBYTE pbPoolBlock,
    _In_ DWORD cbPoolBlock,
    _In_ BOOL fAlloc
) {
    PVMMWINPOOL_CTX_POOLSTORE pStore, pStoreNext;
    PVMM_MAP_POOLENTRY pe;
    DWORD i, cbHdr = 0, cbPoolEntryHdr, dwTag = 0;
    CHAR c;
    BOOL fBadTag = FALSE, f32 = H->vmm.f32;
    DWORD cbBigPoolThreshold = f32 ? 0xff0 : 0xfe0;
    if(cbPoolBlock < cbBigPoolThreshold) {
        cbHdr = f32 ? 8 : 16;
        if(cbPoolBlock < cbHdr) { return; }
        if(0 == *(PQWORD)pbPoolBlock) { return; }
        // sanity check: pool header len != alloc len
        cbPoolEntryHdr = f32 ? (8 * (*(PWORD)(pbPoolBlock + 2) & 0x1ff)) : (16 * pbPoolBlock[2]);
        if(cbPoolBlock != cbPoolEntryHdr) {
            if((tpSS != VMM_MAP_POOL_TPSS_VS) || (cbPoolBlock != cbPoolEntryHdr + cbHdr)) { return; }
        }
        // sanity check: bad tag _and_ not allocated
        for(i = 4; i < 8; i++) {
            c = pbPoolBlock[i];
            if(c < 32 || c > 126) { fBadTag = TRUE; }
        }
        if(fBadTag) {
            if(!fAlloc) { return; }
            if(0 == *(PDWORD)pbPoolBlock) { return; }
        }
        dwTag = *(PDWORD)(pbPoolBlock + 4);
    }
    // get and grow store (if required)
    pStore = *ppStore;
    if(pStore->c == VMMWINPOOL_CTX_POOLSTORE_MAX) {
        if(pStore->cPrevious > 0x40000000) { return; }
        pStoreNext = pStore;
        if(!(pStore = LocalAlloc(0, sizeof(VMMWINPOOL_CTX_POOLSTORE)))) { return; }
        pStore->c = 0;
        pStore->cPrevious = pStoreNext->c + pStoreNext->cPrevious;
        pStore->pNext = pStoreNext;
        *ppStore = pStore;
    }
    // add to store
    pe = pStore->e + pStore->c;
    pe->tpSS = tpSS;
    pe->fAlloc = fAlloc ? 1 : 0;
    pe->tpPool = tp;
    pe->dwTag = dwTag;
    pe->va = va + cbHdr;
    pe->cb = cbPoolBlock - cbHdr;
    pStore->c++;
}

/*
* Create the pool map.
* CALLER DECREF: return
* -- H
* -- pPoolBig
* -- ppStore
* -- cStore
* -- return
*/
_Success_(return != NULL)
PVMMOB_MAP_POOL VmmWinPool_AllPool_CreateMap(_In_ VMM_HANDLE H, _In_ PVMMOB_MAP_POOL pPoolBig, _In_reads_(cStore) PVMMWINPOOL_CTX_POOLSTORE *ppStore, _In_ DWORD cStore)
{
    PVMMWINPOOL_CTX_POOLSTORE pStore;
    PVMMOB_MAP_POOL pObPool = NULL;
    POB_COUNTER pObCnt = NULL;
    POB_MAP pmObTag = NULL;
    DWORD c, i, iStore, cTag, cEntry, iEntry, oMap, cTag2Map = 0;
    QWORD cbPool;
    PVMM_MAP_POOLENTRY pePool;
    PVMM_MAP_POOLENTRYTAG peTag;
    // 1: count tags and entries
    cEntry = pPoolBig->cMap;
    if(!(pObCnt = ObCounter_New(H, 0))) { goto fail; }
    for(i = 0; i < pPoolBig->cTag; i++) {
        ObCounter_Set(pObCnt, (QWORD)pPoolBig->pTag[i].dwTag, (QWORD)pPoolBig->pTag[i].cEntry);
    }
    for(iStore = 0; iStore < cStore; iStore++) {
        pStore = ppStore[iStore];
        cEntry += pStore->cPrevious + pStore->c;
        while(pStore) {
            for(i = 0, c = pStore->c; i < c; i++) {
                ObCounter_Inc(pObCnt, (QWORD)pStore->e[i].dwTag);
            }
            pStore = pStore->pNext;
        }
    }
    cTag = ObCounter_Size(pObCnt);
    // 2: alloc map and fill
    cbPool = sizeof(VMMOB_MAP_POOL);
    cbPool += cEntry * sizeof(VMM_MAP_POOLENTRY);
    cbPool += cTag * sizeof(VMM_MAP_POOLENTRYTAG);
    cbPool += (DWORD)cEntry * sizeof(DWORD);
    if(cbPool > 0x80000000) { goto fail; }
    if(!(pObPool = Ob_AllocEx(H, OB_TAG_MAP_POOL, LMEM_ZEROINIT, (SIZE_T)cbPool, NULL, NULL))) { goto fail; }
    pObPool->cTag = cTag;
    pObPool->cMap = cEntry;
    pObPool->pTag = (PVMM_MAP_POOLENTRYTAG)(pObPool->pMap + pObPool->cMap);
    pObPool->piTag2Map = (PDWORD)(pObPool->pTag + pObPool->cTag);
    // 3: fill tags sorted by pool tag and set up shortcut hashmap
    if(!ObCounter_GetAllSortedByKey(pObCnt, pObPool->cTag, (POB_COUNTER_ENTRY)pObPool->pTag)) { goto fail; }
    if(!(pmObTag = ObMap_New(H, OB_MAP_FLAGS_OBJECT_VOID))) { goto fail; }
    for(i = 0; i < pObPool->cTag; i++) {
        peTag = pObPool->pTag + i;
        cTag2Map += peTag->cEntry;
        peTag->iTag2Map = cTag2Map;
        ObMap_Push(pmObTag, 0x100000000 | peTag->dwTag, peTag);
    }
    // 4: populate map entries (os dependent)
    memcpy(pObPool->pMap, pPoolBig->pMap, pPoolBig->cMap * sizeof(VMM_MAP_POOLENTRY));
    oMap = pPoolBig->cMap;
    for(iStore = 0; iStore < cStore; iStore++) {
        pStore = ppStore[iStore];
        while(pStore) {
            memcpy(pObPool->pMap + oMap, pStore->e, pStore->c * sizeof(VMM_MAP_POOLENTRY));
            oMap += pStore->c;
            pStore = pStore->pNext;
        }
    }
    // 7: sort by va and populate by-tag list
    qsort(pObPool->pMap, pObPool->cMap, sizeof(VMM_MAP_POOLENTRY), (_CoreCrtNonSecureSearchSortCompareFunction)_VmmWinPool_qsort_PoolEntry);
    iEntry = pObPool->cMap;
    while(iEntry) {
        iEntry--;
        pePool = pObPool->pMap + iEntry;
        if((peTag = ObMap_GetByKey(pmObTag, 0x100000000 | pePool->dwTag))) {
            peTag->iTag2Map--;
            pObPool->piTag2Map[peTag->iTag2Map] = iEntry;
        }
    }
    // 8: finish!
    Ob_INCREF(pObPool);
fail:
    Ob_DECREF(pObCnt);
    Ob_DECREF(pmObTag);
    return Ob_DECREF(pObPool);
}



//-----------------------------------------------------------------------------
// 1809/17763 POOL / HEAP PARSING FOR NON-BIG HEAP-BASED ALLOCATIONS:
// Loosely based on Yarden Shafirs excellent PoolViewer:
// https://github.com/yardenshafir/PoolViewer
//-----------------------------------------------------------------------------

typedef struct tdVMMWINPOOL_OFFSETS {
    QWORD vaExPoolState;
    WORD cbBigPoolThreshold;
    struct {
        WORD oHeapKey;
        WORD oLfhKey;
        WORD oNumberOfPools;
        WORD oPoolNode;
        DWORD oSpecialHeaps;
    } _EX_POOL_HEAP_MANAGER_STATE;
    struct {
        WORD cb;
        WORD oHeaps;
    } _EX_HEAP_POOL_NODE;
    struct {
        WORD cb;
        WORD oSegContexts;
    } _SEGMENT_HEAP;
    struct {
        WORD cb;
        WORD oUnitShift;
        WORD oFirstDescriptorIndex;
        WORD oSegmentListHead;
    } _HEAP_SEG_CONTEXT;
    struct {
        WORD cb;
        QWORD qwSignatureStaticKey;
    } _HEAP_PAGE_SEGMENT;
    struct {
        WORD cb;
        WORD oTreeSignature;
        WORD oRangeFlags;
        WORD oUnitSize;
    } _HEAP_PAGE_RANGE_DESCRIPTOR;
    struct {
        WORD oBlockOffsets;
        WORD oBlockBitmap;
    } _HEAP_LFH_SUBSEGMENT;
    struct {
        WORD cb;
    } _HEAP_VS_CHUNK_HEADER;
} VMMWINPOOL_OFFSETS, *PVMMWINPOOL_OFFSETS;

typedef struct tdVMMWINPOOL_HEAP {
    QWORD va;
    BOOL fSpecial;
    DWORD iPoolNode;
    VMM_MAP_POOL_TP tpPool;
} VMMWINPOOL_HEAP, *PVMMWINPOOL_HEAP;

typedef struct tdVMMWINPOOL_HEAP_PAGE_SEGMENT {
    QWORD va;
    PVMMWINPOOL_HEAP pHeap;
    UCHAR ucUnitShift;
    UCHAR ucFirstDescriptorIndex;
    BOOL fValid;
    BYTE pb[0x2000];
} VMMWINPOOL_HEAP_PAGE_SEGMENT, *PVMMWINPOOL_HEAP_PAGE_SEGMENT;

typedef struct tdVMMWINPOOL_HEAP_LFH_VS {
    QWORD va;
    DWORD cb;
    PVMMWINPOOL_HEAP_PAGE_SEGMENT pPgSeg;
} VMMWINPOOL_HEAP_LFH_VS, *PVMMWINPOOL_HEAP_LFH_VS;

typedef struct tdVMMWINPOOL_CTX {
    PVMM_PROCESS pSystemProcess;
    PVMMWINPOOL_OFFSETS po;
    QWORD qwKeyHeap;
    QWORD qwKeyLfh;
    DWORD cPools;
    POB_SET psPrefetch;
    POB_MAP pmHeap;
    POB_MAP pmPgSeg;
    POB_MAP pmLfh;
    POB_MAP pmVs;
    PVMMWINPOOL_CTX_POOLSTORE pLfh;
    PVMMWINPOOL_CTX_POOLSTORE pVs;
    BYTE pb[0x01000000];            // 16MB buffer.
} VMMWINPOOL_CTX, *PVMMWINPOOL_CTX;

// windows typedef
typedef union td_HEAP_LFH_SUBSEGMENT_ENCODED_OFFSETS {
    struct {
        WORD BlockSize;
        WORD FirstBlockOffset;
    };
    DWORD EncodedData;
} _HEAP_LFH_SUBSEGMENT_ENCODED_OFFSETS, *P_HEAP_LFH_SUBSEGMENT_ENCODED_OFFSETS;

typedef union td_HEAP_VS_CHUNK_HEADER_SIZE32 {
    struct {
        DWORD MemoryCost : 1;
        DWORD UnsafeSize : 15;
        DWORD UnsafePrevSize : 15;
        DWORD Allocated : 1;
    };
    DWORD HeaderBits;
} _HEAP_VS_CHUNK_HEADER_SIZE32, *P_HEAP_VS_CHUNK_HEADER_SIZE32;

typedef union td_HEAP_VS_CHUNK_HEADER_SIZE64 {
    struct {
        DWORD MemoryCost : 16;
        DWORD UnsafeSize : 16;
        DWORD UnsafePrevSize : 16;
        DWORD Allocated : 8;
        DWORD _Pad : 8;
    };
    QWORD HeaderBits;
} _HEAP_VS_CHUNK_HEADER_SIZE64, *P_HEAP_VS_CHUNK_HEADER_SIZE64;

_Success_(return)
BOOL VmmWinPool_AllPool1903_Offsets(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pSystemProcess, _Out_ PVMMWINPOOL_OFFSETS po)
{
    // static initialization:
    po->_HEAP_PAGE_SEGMENT.qwSignatureStaticKey = ((H->vmm.kernel.dwVersionBuild < 26100) ? 0xa2e64eada2e64ead : 0);
    po->_EX_POOL_HEAP_MANAGER_STATE.oHeapKey = 0;
    po->_EX_HEAP_POOL_NODE.oHeaps = 0;
    if(H->vmm.f32) {
        po->cbBigPoolThreshold = 0xff0;
        po->_EX_POOL_HEAP_MANAGER_STATE.oLfhKey = 4;
        po->_HEAP_VS_CHUNK_HEADER.cb = 8;
    } else {
        po->cbBigPoolThreshold = 0xfe0;
        po->_EX_POOL_HEAP_MANAGER_STATE.oLfhKey = 8;
        po->_HEAP_VS_CHUNK_HEADER.cb = 16;
    }
    // dynamic symbol-based initialization:
    BOOL f =
        PDB_GetSymbolAddress(H, PDB_HANDLE_KERNEL, "ExPoolState", &po->vaExPoolState) &&
        PDB_GetTypeChildOffsetShort(H, PDB_HANDLE_KERNEL, "_EX_POOL_HEAP_MANAGER_STATE", "NumberOfPools", &po->_EX_POOL_HEAP_MANAGER_STATE.oNumberOfPools) &&
        PDB_GetTypeChildOffsetShort(H, PDB_HANDLE_KERNEL, "_EX_POOL_HEAP_MANAGER_STATE", "PoolNode", &po->_EX_POOL_HEAP_MANAGER_STATE.oPoolNode) &&
        PDB_GetTypeChildOffset(H, PDB_HANDLE_KERNEL, "_EX_POOL_HEAP_MANAGER_STATE", "SpecialHeaps", &po->_EX_POOL_HEAP_MANAGER_STATE.oSpecialHeaps) &&
        PDB_GetTypeSizeShort(H, PDB_HANDLE_KERNEL, "_EX_HEAP_POOL_NODE", &po->_EX_HEAP_POOL_NODE.cb) && (po->_EX_HEAP_POOL_NODE.cb < 0x8000) &&
        PDB_GetTypeSizeShort(H, PDB_HANDLE_KERNEL, "_SEGMENT_HEAP", &po->_SEGMENT_HEAP.cb) &&
        PDB_GetTypeChildOffsetShort(H, PDB_HANDLE_KERNEL, "_SEGMENT_HEAP", "SegContexts", &po->_SEGMENT_HEAP.oSegContexts) &&
        PDB_GetTypeSizeShort(H, PDB_HANDLE_KERNEL, "_HEAP_SEG_CONTEXT", &po->_HEAP_SEG_CONTEXT.cb) &&
        PDB_GetTypeChildOffsetShort(H, PDB_HANDLE_KERNEL, "_HEAP_SEG_CONTEXT", "UnitShift", &po->_HEAP_SEG_CONTEXT.oUnitShift) &&
        PDB_GetTypeChildOffsetShort(H, PDB_HANDLE_KERNEL, "_HEAP_SEG_CONTEXT", "FirstDescriptorIndex", &po->_HEAP_SEG_CONTEXT.oFirstDescriptorIndex) &&
        PDB_GetTypeChildOffsetShort(H, PDB_HANDLE_KERNEL, "_HEAP_SEG_CONTEXT", "SegmentListHead", &po->_HEAP_SEG_CONTEXT.oSegmentListHead) &&
        PDB_GetTypeSizeShort(H, PDB_HANDLE_KERNEL, "_HEAP_PAGE_SEGMENT", &po->_HEAP_PAGE_SEGMENT.cb) && (po->_HEAP_PAGE_SEGMENT.cb <= 0x2000) &&
        PDB_GetTypeSizeShort(H, PDB_HANDLE_KERNEL, "_HEAP_PAGE_RANGE_DESCRIPTOR", &po->_HEAP_PAGE_RANGE_DESCRIPTOR.cb) && (256 * po->_HEAP_PAGE_RANGE_DESCRIPTOR.cb == po->_HEAP_PAGE_SEGMENT.cb) &&
        PDB_GetTypeChildOffsetShort(H, PDB_HANDLE_KERNEL, "_HEAP_PAGE_RANGE_DESCRIPTOR", "UnitSize", &po->_HEAP_PAGE_RANGE_DESCRIPTOR.oUnitSize) &&
        PDB_GetTypeChildOffsetShort(H, PDB_HANDLE_KERNEL, "_HEAP_PAGE_RANGE_DESCRIPTOR", "RangeFlags", &po->_HEAP_PAGE_RANGE_DESCRIPTOR.oRangeFlags) &&
        PDB_GetTypeChildOffsetShort(H, PDB_HANDLE_KERNEL, "_HEAP_PAGE_RANGE_DESCRIPTOR", "TreeSignature", &po->_HEAP_PAGE_RANGE_DESCRIPTOR.oTreeSignature) &&
        PDB_GetTypeChildOffsetShort(H, PDB_HANDLE_KERNEL, "_HEAP_LFH_SUBSEGMENT", "BlockOffsets", &po->_HEAP_LFH_SUBSEGMENT.oBlockOffsets) &&
        PDB_GetTypeChildOffsetShort(H, PDB_HANDLE_KERNEL, "_HEAP_LFH_SUBSEGMENT", "BlockBitmap", &po->_HEAP_LFH_SUBSEGMENT.oBlockBitmap);
    return f;
}

/*
* Parses nt!_EX_POOL_HEAP_MANAGER_STATE to fetch the # pools, heaps and special
* heaps as well as the HeapKey and LfhKey.
*/
_Success_(return)
BOOL VmmWinPool_AllPool1903_1_HeapMgr(_In_ VMM_HANDLE H, PVMMWINPOOL_CTX ctx, PVMMWINPOOL_OFFSETS poff)
{
    BOOL f32 = H->vmm.f32;
    DWORD i, iPoolNode, cPools = 0;
    QWORD va = 0, oBase = 0, vaBase = 0, vaHeapGlobals = 0;
    PVMMWINPOOL_HEAP pHeap;
    // 1: read heap manager + special heaps
    ObSet_Clear(ctx->psPrefetch);
    ObSet_Push_PageAlign(ctx->psPrefetch, poff->vaExPoolState, 8);
    ObSet_Push_PageAlign(ctx->psPrefetch, poff->vaExPoolState + poff->_EX_POOL_HEAP_MANAGER_STATE.oNumberOfPools, 4);
    ObSet_Push_PageAlign(ctx->psPrefetch, poff->vaExPoolState + poff->_EX_POOL_HEAP_MANAGER_STATE.oSpecialHeaps, 0x20);
    VmmCachePrefetchPages(H, ctx->pSystemProcess, ctx->psPrefetch, 0);
    // 1.1 - va heap globals
    VmmReadEx(H, ctx->pSystemProcess, poff->vaExPoolState, (PBYTE)&vaHeapGlobals, f32 ? 4 : 8, NULL, VMM_FLAG_FORCECACHE_READ);
    if(!VMM_KADDR_4_8(f32, vaHeapGlobals)) { goto fail; }
    // 1.2 - # pools
    VmmReadEx(H, ctx->pSystemProcess, poff->vaExPoolState + poff->_EX_POOL_HEAP_MANAGER_STATE.oNumberOfPools, (PBYTE)&cPools, 4, NULL, VMM_FLAG_FORCECACHE_READ);
    if(!cPools || cPools > 64) { goto fail; }
    // 1.3 - special heaps
    for(i = 0; i < 4; i++) {
        VmmReadEx(H, ctx->pSystemProcess, poff->vaExPoolState + poff->_EX_POOL_HEAP_MANAGER_STATE.oSpecialHeaps, ctx->pb, 0x20, NULL, VMM_FLAG_FORCECACHE_READ);
        va = f32 ? *(PDWORD)(ctx->pb + i * 4ULL) : *(PQWORD)(ctx->pb + i * 8ULL);
        if(VMM_KADDR_PAGE(f32, va) && (pHeap = LocalAlloc(LMEM_ZEROINIT, sizeof(VMMWINPOOL_HEAP)))) {
            pHeap->va = va;
            pHeap->fSpecial = TRUE;
            pHeap->iPoolNode = (DWORD)-1;
            switch(i) {
                case 0: pHeap->tpPool = VMM_MAP_POOL_TP_NonPagedPool; break;
                case 1: pHeap->tpPool = VMM_MAP_POOL_TP_NonPagedPoolNx; break;
                case 2: pHeap->tpPool = VMM_MAP_POOL_TP_PagedPool; break;
                case 3: pHeap->tpPool = VMM_MAP_POOL_TP_PagedPool; break;
            }
            ObMap_Push(ctx->pmHeap, va, pHeap);
        }
    }
    // 2: heap globals + pool heaps
    ObSet_Clear(ctx->psPrefetch);
    ObSet_Push_PageAlign(ctx->psPrefetch, vaHeapGlobals, 0x10);
    ObSet_Push_PageAlign(ctx->psPrefetch, poff->vaExPoolState + poff->_EX_POOL_HEAP_MANAGER_STATE.oPoolNode, cPools * poff->_EX_HEAP_POOL_NODE.cb);
    VmmCachePrefetchPages(H, ctx->pSystemProcess, ctx->psPrefetch, 0);
    // 2.1 - heap globals
    if(!VmmRead2(H, ctx->pSystemProcess, vaHeapGlobals, ctx->pb, 0x10, VMM_FLAG_FORCECACHE_READ)) { goto fail; }
    ctx->qwKeyHeap = VMM_PTR_OFFSET_DUAL(f32, ctx->pb, 0, 0);
    ctx->qwKeyLfh = VMM_PTR_OFFSET_DUAL(f32, ctx->pb, 4, 8);
    // 2.2 - pool heaps
    vaBase = poff->vaExPoolState + poff->_EX_POOL_HEAP_MANAGER_STATE.oPoolNode;
    VmmReadEx(H, ctx->pSystemProcess, vaBase, ctx->pb, cPools * poff->_EX_HEAP_POOL_NODE.cb, NULL, VMM_FLAG_FORCECACHE_READ);
    for(iPoolNode = 0; iPoolNode < cPools; iPoolNode++) {
        for(i = 0; i < 4; i++) {
            va = f32 ? *(PDWORD)(ctx->pb + oBase + i * 4ULL) : *(PQWORD)(ctx->pb + oBase + i * 8ULL);
            if(VMM_KADDR_PAGE(f32, va) && (pHeap = LocalAlloc(LMEM_ZEROINIT, sizeof(VMMWINPOOL_HEAP)))) {
                pHeap->va = va;
                pHeap->fSpecial = FALSE;
                pHeap->iPoolNode = iPoolNode;
                switch(i) {
                    case 0: pHeap->tpPool = VMM_MAP_POOL_TP_NonPagedPool; break;
                    case 1: pHeap->tpPool = VMM_MAP_POOL_TP_NonPagedPoolNx; break;
                    case 2: pHeap->tpPool = VMM_MAP_POOL_TP_PagedPool; break;
                    case 3: pHeap->tpPool = VMM_MAP_POOL_TP_PagedPool; break;
                }
                ObMap_Push(ctx->pmHeap, va, pHeap);
            }
        }
        oBase += poff->_EX_HEAP_POOL_NODE.cb;
    }
    return TRUE;
fail:
    return FALSE;
}

/*
* fetch and parse [nt!_SEGMENT_HEAP]
* TODO: PARSE LargeAllocMetadata
*/
_Success_(return)
BOOL VmmWinPool_AllPool1903_2_HeapFillSegmentHeap(_In_ VMM_HANDLE H, PVMMWINPOOL_CTX ctx)
{
    BOOL f32 = H->vmm.f32;
    PVMMWINPOOL_HEAP peHeap;
    PVMMWINPOOL_HEAP_PAGE_SEGMENT pePgSeg;
    POB_SET psvaObPrefetch = NULL;
    CHAR ucUnitShift, ucFirstDescriptorIndex;
    DWORD i, iSegHeapCtx, iSegHeap, cSegHeap, oBase;
    QWORD va = 0;
    // 1: prefetch
    if(!(cSegHeap = ObMap_Size(ctx->pmHeap))) { return FALSE; }
    if(!(psvaObPrefetch = ObMap_FilterSet(ctx->pmHeap, NULL, ObMap_FilterSet_FilterAllKey))) { return FALSE; }
    VmmCachePrefetchPages3(H, ctx->pSystemProcess, psvaObPrefetch, ctx->po->_SEGMENT_HEAP.cb, 0);
    Ob_DECREF_NULL(&psvaObPrefetch);
    // 2: iterate nt!_SEGMENT_HEAP -> FETCH ADDR nt!_HEAP_PAGE_SEGMENT
    for(iSegHeap = 0; iSegHeap < cSegHeap; iSegHeap++) {
        peHeap = ObMap_GetByIndex(ctx->pmHeap, iSegHeap);
        if(!VmmRead2(H, ctx->pSystemProcess, peHeap->va, ctx->pb, ctx->po->_SEGMENT_HEAP.cb, VMMDLL_FLAG_FORCECACHE_READ)) { continue; }
        if(*(PDWORD)(ctx->pb + (f32 ? 8 : 16)) != 0xddeeddee) { continue; }   // _SEGMENT_HEAP.Signature == 0xddeeddee
        for(iSegHeapCtx = 0; iSegHeapCtx < 2; iSegHeapCtx++) {
            oBase = ctx->po->_SEGMENT_HEAP.oSegContexts + iSegHeapCtx * ctx->po->_HEAP_SEG_CONTEXT.cb;
            ucUnitShift = *(PUCHAR)(ctx->pb + oBase + ctx->po->_HEAP_SEG_CONTEXT.oUnitShift);
            ucFirstDescriptorIndex = *(PUCHAR)(ctx->pb + oBase + ctx->po->_HEAP_SEG_CONTEXT.oFirstDescriptorIndex);
            for(i = 0; i < 2; i++) {
                va = VMM_PTR_OFFSET_DUAL(f32, ctx->pb + oBase + ctx->po->_HEAP_SEG_CONTEXT.oSegmentListHead, i * 4ULL, i * 8ULL);
                if(VMM_KADDR_PAGE(f32, va) && !ObMap_ExistsKey(ctx->pmPgSeg, va) && (pePgSeg = LocalAlloc(0, sizeof(VMMWINPOOL_HEAP_PAGE_SEGMENT)))) {
                    pePgSeg->va = va;
                    pePgSeg->pHeap = peHeap;
                    pePgSeg->ucUnitShift = ucUnitShift;
                    pePgSeg->ucFirstDescriptorIndex = ucFirstDescriptorIndex;
                    pePgSeg->fValid = FALSE;
                    ObMap_Push(ctx->pmPgSeg, va, pePgSeg);
                }
            }
        }
    }
    return TRUE;
}

/*
* Prefetch addresses from a set into the memory cache. Also try to guess the
* next following likely addresses in FLink, BLink list - segments are usually
* located 1MB apart.
*/
VOID VmmWinPool_AllPool1903_3_HeapFillPageSegment_Prefetch(_In_ VMM_HANDLE H, _In_ PVMMWINPOOL_CTX ctx, _In_ POB_SET psva)
{
    QWORD va;
    DWORD i, j, iMax, cb;
    ObSet_Clear(ctx->psPrefetch);
    cb = ctx->po->_HEAP_PAGE_SEGMENT.cb;
    for(i = 0, iMax = ObSet_Size(psva); i < iMax; i++) {
        va = ObSet_Get(psva, i);
        for(j = 0; j < 8; j++) {
            ObSet_Push_PageAlign(ctx->psPrefetch, va + j * 0x00100000ULL, cb);
        }
        for(j = 1; j < 4; j++) {
            ObSet_Push_PageAlign(ctx->psPrefetch, va - j * 0x00100000ULL, cb);
        }
    }
    VmmCachePrefetchPages(H, ctx->pSystemProcess, ctx->psPrefetch, 0);
}

/*
* Process a single segment candidate.
* -- H
* -- ctx
* -- psvaNext
* -- va
* -- return = TRUE if processed, FALSE if memory read fail - i.e. read retry after prefetch is recommended
*/
BOOL VmmWinPool_AllPool1903_3_HeapFillPageSegment_ProcessSingleCandidate(_In_ VMM_HANDLE H, _In_ PVMMWINPOOL_CTX ctx, _In_ POB_SET psvaNext, _In_ QWORD va)
{
    BOOL f32 = H->vmm.f32;
    QWORD i, vaNext, vaSignature;
    PVMMWINPOOL_HEAP_PAGE_SEGMENT pe, peNext;
    if(!(pe = ObMap_GetByKey(ctx->pmPgSeg, va))) { return TRUE; }
    if(!VmmRead2(H, ctx->pSystemProcess, pe->va, pe->pb, ctx->po->_HEAP_PAGE_SEGMENT.cb, VMMDLL_FLAG_FORCECACHE_READ)) { return FALSE; }
    // signature check
    vaSignature = VMM_PTR_OFFSET_DUAL(f32, pe->pb, 8, 16) ^ ctx->qwKeyHeap ^ va ^ ctx->po->_HEAP_PAGE_SEGMENT.qwSignatureStaticKey;
    if(!VMM_KADDR_4_8(f32, vaSignature)) { return TRUE; }
    pe->fValid = TRUE;
    // flink/blink
    for(i = 0; i < 2; i++) {
        vaNext = VMM_PTR_OFFSET_DUAL(f32, pe->pb, i * 4, i * 8);
        if(VMM_KADDR_PAGE(f32, vaNext) && !ObMap_ExistsKey(ctx->pmPgSeg, vaNext) && (peNext = LocalAlloc(0, sizeof(VMMWINPOOL_HEAP_PAGE_SEGMENT)))) {
            peNext->va = vaNext;
            peNext->pHeap = pe->pHeap;
            peNext->ucUnitShift = pe->ucUnitShift;
            peNext->ucFirstDescriptorIndex = pe->ucFirstDescriptorIndex;
            peNext->fValid = FALSE;
            ObMap_Push(ctx->pmPgSeg, vaNext, peNext);
            ObSet_Push(psvaNext, vaNext);
        }
    }
    return TRUE;
}

/*
* fetch and parse [nt!_HEAP_PAGE_SEGMENT]
*/
VOID VmmWinPool_AllPool1903_3_HeapFillPageSegment(_In_ VMM_HANDLE H, _In_ PVMMWINPOOL_CTX ctx)
{
    QWORD va;
    POB_SET psvaObTry1 = NULL, psvaObTry2 = NULL;
    if(!(psvaObTry2 = ObSet_New(H))) { goto fail; }
    if(!(psvaObTry1 = ObMap_FilterSet(ctx->pmPgSeg, NULL, ObMap_FilterSet_FilterAllKey))) { goto fail; }
    while(TRUE) {
        // try1 items
        while((va = ObSet_Pop(psvaObTry1))) {
            if(!VmmWinPool_AllPool1903_3_HeapFillPageSegment_ProcessSingleCandidate(H, ctx, psvaObTry1, va)) {
                ObSet_Push(psvaObTry2, va);
            }
        }
        // prefetch & try2 items
        if(!ObSet_Size(psvaObTry2)) { break; }
        VmmWinPool_AllPool1903_3_HeapFillPageSegment_Prefetch(H, ctx, psvaObTry2);
        while((va = ObSet_Pop(psvaObTry2))) {
            VmmWinPool_AllPool1903_3_HeapFillPageSegment_ProcessSingleCandidate(H, ctx, psvaObTry1, va);
        }
    }
fail:
    Ob_DECREF(psvaObTry1);
    Ob_DECREF(psvaObTry2);
}

/*
* Classify a single [nt!_HEAP_PAGE_RANGE_DESCRIPTOR], push it into appropriate
* maps and return its unit size.
* TODO: add support for LargePool.
*/
UCHAR VmmWinPool_AllPool1903_4_HeapPageRangeDescriptor_SingleDescriptor(_In_ VMM_HANDLE H, _In_ PVMMWINPOOL_CTX ctx, _In_ PVMMWINPOOL_HEAP_PAGE_SEGMENT pPgSeg, _In_ DWORD iRD)
{
    QWORD vaRange;
    UCHAR ucUnitSize, ucRangeFlags;
    DWORD cbRange, oRD;
    PVMMWINPOOL_HEAP_LFH_VS pe;
    oRD = ctx->po->_HEAP_PAGE_RANGE_DESCRIPTOR.cb * iRD;
    ucUnitSize   = *(PUCHAR)(pPgSeg->pb + oRD + ctx->po->_HEAP_PAGE_RANGE_DESCRIPTOR.oUnitSize);
    ucRangeFlags = *(PUCHAR)(pPgSeg->pb + oRD + ctx->po->_HEAP_PAGE_RANGE_DESCRIPTOR.oRangeFlags);
    if(H->vmm.f32) { ucRangeFlags &= 0x1f; }
    vaRange = pPgSeg->va + iRD * (1ULL << pPgSeg->ucUnitShift);
    cbRange = ucUnitSize * (1ULL << pPgSeg->ucUnitShift);
    if(ucUnitSize == 0) { return 1; }
    if(cbRange > 0x00100000) { return ucUnitSize; }  // >1MB sanity check
    if(ucRangeFlags == 3) {
        // Large Pool - not yet supported!
    } else if(ucRangeFlags == 11) {
        // Lfh
        if((pe = LocalAlloc(0, sizeof(VMMWINPOOL_HEAP_LFH_VS)))) {
            pe->pPgSeg = pPgSeg;
            pe->va = vaRange;
            pe->cb = cbRange;
            ObMap_Push(ctx->pmLfh, pe->va, pe);
        }
    } else if(ucRangeFlags == 15) {
        // Vs
        if((pe = LocalAlloc(0, sizeof(VMMWINPOOL_HEAP_LFH_VS)))) {
            pe->pPgSeg = pPgSeg;
            pe->va = vaRange;
            pe->cb = cbRange;
            ObMap_Push(ctx->pmVs, pe->va, pe);
        }
    }
    return ucUnitSize;
}

/*
* Classify the [nt!_HEAP_PAGE_RANGE_DESCRIPTOR]s within a [nt!_HEAP_PAGE_SEGMENT].
* Mapping them into pmLfh, pmVs
* TODO: add support for LargePool.
*/
_Success_(return)
BOOL VmmWinPool_AllPool1903_4_HeapPageRangeDescriptor(_In_ VMM_HANDLE H, PVMMWINPOOL_CTX ctx)
{
    DWORD iPgSeg, cPgSegMax, iRD;
    PVMMWINPOOL_HEAP_PAGE_SEGMENT pePgSeg;
    cPgSegMax = ObMap_Size(ctx->pmPgSeg);
    for(iPgSeg = 0; iPgSeg < cPgSegMax; iPgSeg++) {
        pePgSeg = ObMap_GetByIndex(ctx->pmPgSeg, iPgSeg);
        if(!pePgSeg || !pePgSeg->fValid) { continue; }
        iRD = pePgSeg->ucFirstDescriptorIndex;
        while(iRD < 256) {
            iRD += VmmWinPool_AllPool1903_4_HeapPageRangeDescriptor_SingleDescriptor(H, ctx, pePgSeg, iRD);
        }
    }
    return ObMap_Size(ctx->pmLfh) || ObMap_Size(ctx->pmVs);
}

/*
* Parse the vs heap segment - [nt!_HEAP_VS_SUBSEGMENT] // [nt!_HEAP_VS_CHUNK_HEADER]
*/
VOID VmmWinPool_AllPool1903_5_VS_DoWork(
    _In_ VMM_HANDLE H,
    _In_ PVMMWINPOOL_CTX ctx,
    _In_ QWORD va,
    _In_ PBYTE pb,
    _In_ DWORD cb,
    _In_ PVMMWINPOOL_HEAP_PAGE_SEGMENT pPgSeg
) {
    BOOL f32 = H->vmm.f32;
    DWORD cbPoolHdr, oVsChunkHdr, cbChunkSize, oBlock, cbBlock, cbAdjust;
    QWORD vaBlock, vaChunkHeader;
    WORD wSize, wSignature;
    BOOL fAlloc;
    P_HEAP_VS_CHUNK_HEADER_SIZE32 pChunkSize32;
    P_HEAP_VS_CHUNK_HEADER_SIZE64 pChunkSize64;
    // 32/64-bit dependent offsets:
    if(f32) {
        cbPoolHdr = 8;
        oVsChunkHdr = 0x18;
        wSize = *(PWORD)(ctx->pb + 0x14);
        wSignature = *(PWORD)(ctx->pb + 0x16);
    } else {
        cbPoolHdr = 16;
        oVsChunkHdr = 0x30;
        wSize = *(PWORD)(ctx->pb + 0x20);
        wSignature = *(PWORD)(ctx->pb + 0x22);
    }
    // signature check: _HEAP_VS_SUBSEGMENT
    if(wSize != (wSignature ^ 0x2BED)) {
        if(wSignature & 0xf000) {
            return;
        }
    }
    // loop over pool entries
    while(oVsChunkHdr + 0x30 < cb) {
        vaChunkHeader = va + oVsChunkHdr;
        if(f32) {
            pChunkSize32 = (P_HEAP_VS_CHUNK_HEADER_SIZE32)(pb + oVsChunkHdr);
            pChunkSize32->HeaderBits = (DWORD)(pChunkSize32->HeaderBits ^ vaChunkHeader ^ ctx->qwKeyHeap);
            fAlloc = (pChunkSize32->Allocated & 1) ? TRUE : FALSE;
            cbChunkSize = pChunkSize32->UnsafeSize << 3;
        } else {
            pChunkSize64 = (P_HEAP_VS_CHUNK_HEADER_SIZE64)(pb + oVsChunkHdr);
            pChunkSize64->HeaderBits = pChunkSize64->HeaderBits ^ vaChunkHeader ^ ctx->qwKeyHeap;
            fAlloc = (pChunkSize64->Allocated & 1) ? TRUE : FALSE;
            cbChunkSize = pChunkSize64->UnsafeSize << 4;
        }
        if((cbChunkSize < 0x10) || (oVsChunkHdr + cbChunkSize > cb)) {
            break;
        }
        if(fAlloc) {
            oBlock = oVsChunkHdr + ctx->po->_HEAP_VS_CHUNK_HEADER.cb;
            cbBlock = cbChunkSize - ctx->po->_HEAP_VS_CHUNK_HEADER.cb;
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
                // nb! allocation (excl. chunkhdr) does not cross page boundary
                if((cbBlock < ctx->po->cbBigPoolThreshold) || ((vaBlock & 0xfff) < ctx->po->cbBigPoolThreshold)) {
                    // Larger [0xff0+] Vs allocations are also visible in big pool table - so skip these duplicates!
                    VmmWinPool_AllPool_PushItem(H, &ctx->pVs, pPgSeg->pHeap->tpPool, VMM_MAP_POOL_TPSS_VS, vaBlock, pb + oBlock, cbBlock, TRUE);
                }
            }
        }
        oVsChunkHdr += cbChunkSize;
    }
}

/*
* Parse the low fragmentation heap segment - [nt!_HEAP_LFH_SUBSEGMENT]
*/
VOID VmmWinPool_AllPool1903_5_LFH_DoWork(
    _In_ VMM_HANDLE H,
    _In_ PVMMWINPOOL_CTX ctx,
    _In_ QWORD va,
    _In_ PBYTE pb,
    _In_ DWORD cb,
    _In_ PVMMWINPOOL_HEAP_PAGE_SEGMENT pPgSeg
) {
    UCHAR ucBits;
    PBYTE pbBitmap;
    DWORD iBlock, cBlock, oBlock;
    DWORD cbBlockSize, oFirstBlock, dwvaShift;
    P_HEAP_LFH_SUBSEGMENT_ENCODED_OFFSETS pEncoded;
    pbBitmap = pb + ctx->po->_HEAP_LFH_SUBSEGMENT.oBlockBitmap;
    pEncoded = (P_HEAP_LFH_SUBSEGMENT_ENCODED_OFFSETS)(pb + ctx->po->_HEAP_LFH_SUBSEGMENT.oBlockOffsets);
    dwvaShift = (H->vmm.kernel.dwVersionBuild >= 26100) ? ((DWORD)(va >> 12)) : ((DWORD)va >> 12);
    pEncoded->EncodedData = (DWORD)(pEncoded->EncodedData ^ ctx->qwKeyLfh ^ dwvaShift);
    oFirstBlock = pEncoded->FirstBlockOffset;
    cbBlockSize = pEncoded->BlockSize;
    if((cbBlockSize >= 0xff8) || (oFirstBlock > cb)) { return; }
    cBlock = (cb - oFirstBlock) / cbBlockSize;
    for(iBlock = 0; iBlock < cBlock; iBlock++) {
        oBlock = oFirstBlock + iBlock * cbBlockSize;
        if((oBlock & 0xfff) + cbBlockSize > 0x1000) { continue; }   // block do not cross page boundaries
        ucBits = pbBitmap[iBlock >> 2] >> ((iBlock & 0x3) << 1);
        VmmWinPool_AllPool_PushItem(H, &ctx->pLfh, pPgSeg->pHeap->tpPool, VMM_MAP_POOL_TPSS_LFH, va + oBlock, pb + oBlock, cbBlockSize, ((ucBits & 3) == 1));
    }
}

/*
* Fetch LFH/VS segments:
* This should be done in a fairly efficient by fetching around 8MB LFH/VS data
* per read call to the underlying system.
*/
VOID VmmWinPool_AllPool1903_5_LFHVS(_In_ VMM_HANDLE H, _In_ PVMMWINPOOL_CTX ctx, _In_ BOOL fVS)
{
    DWORD i, iSS, iPrefetchBase = 0, cMax;
    QWORD cbPrefetch = 0;
    PBYTE pbBuffer;
    POB_MAP pmVsLfh;
    POB_SET psObPrefetch = NULL;
    PVMMWINPOOL_HEAP_LFH_VS pe;
    pbBuffer = fVS ? ctx->pb : ctx->pb + VMMWINPOOL_PREFETCH_BUFFER_SIZE;
    pmVsLfh = fVS ? ctx->pmVs : ctx->pmLfh;
    if(!(psObPrefetch = ObSet_New(H))) { return; }
    cMax = ObMap_Size(pmVsLfh);
    for(iSS = 0; iSS < cMax; iSS++) {
        pe = ObMap_GetByIndex(pmVsLfh, iSS);
        ObSet_Push_PageAlign(psObPrefetch, pe->va, pe->cb);
        cbPrefetch += pe->cb;
        if((cbPrefetch > VMMWINPOOL_PREFETCH_BUFFER_SIZE) || (iSS + 1 == cMax)) {
            VmmCachePrefetchPages(H, ctx->pSystemProcess, psObPrefetch, 0);
            for(i = iPrefetchBase; i <= iSS; i++) {
                pe = ObMap_GetByIndex(pmVsLfh, i);
                if(pe->cb > VMMWINPOOL_PREFETCH_BUFFER_SIZE) { continue; }
                VmmReadEx(H, ctx->pSystemProcess, pe->va, pbBuffer, pe->cb, NULL, VMM_FLAG_FORCECACHE_READ | VMM_FLAG_ZEROPAD_ON_FAIL);
                if(fVS) {
                    VmmWinPool_AllPool1903_5_VS_DoWork(H, ctx, pe->va, pbBuffer, pe->cb, pe->pPgSeg);
                } else {
                    VmmWinPool_AllPool1903_5_LFH_DoWork(H, ctx, pe->va, pbBuffer, pe->cb, pe->pPgSeg);
                }
            }
            ObSet_Clear(psObPrefetch);
            iPrefetchBase = iSS + 1;
            cbPrefetch = 0;
        }
    }
    Ob_DECREF(psObPrefetch);
}

DWORD WINAPI VmmWinPool_AllPool1903_5_LFH(_In_ VMM_HANDLE H, _In_ PVOID lpThreadParam)
{
    VmmWinPool_AllPool1903_5_LFHVS(H, lpThreadParam, FALSE);
    return 0;
}

DWORD WINAPI VmmWinPool_AllPool1903_5_VS(_In_ VMM_HANDLE H, _In_ PVOID lpThreadParam)
{
    VmmWinPool_AllPool1903_5_LFHVS(H, lpThreadParam, TRUE);
    return 0;
}

/*
* Create a pool map containing all pool entries on Windows 10 1809 and above.
* CALLER DECREF: return
* -- H
* -- pSystemProcess
* -- pPoolBig
* -- return
*/
_Success_(return != NULL)
PVMMOB_MAP_POOL VmmWinPool_AllPool1903_DoWork(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pSystemProcess, _In_ PVMMOB_MAP_POOL pPoolBig)
{
    PVMMOB_MAP_POOL pObPoolAll = NULL;
    PVMMWINPOOL_CTX ctx = NULL;
    VMMWINPOOL_OFFSETS off = { 0 };
    PVMMWINPOOL_CTX_POOLSTORE pStore;
    // 1: alloc & init
    if(!(ctx = LocalAlloc(LMEM_ZEROINIT, sizeof(VMMWINPOOL_CTX)))) { goto fail; }
    if(!(ctx->pmHeap = ObMap_New(H, OB_MAP_FLAGS_OBJECT_LOCALFREE))) { goto fail; }
    if(!(ctx->pmPgSeg = ObMap_New(H, OB_MAP_FLAGS_OBJECT_LOCALFREE))) { goto fail; }
    if(!(ctx->pmLfh = ObMap_New(H, OB_MAP_FLAGS_OBJECT_LOCALFREE))) { goto fail; }
    if(!(ctx->pmVs = ObMap_New(H, OB_MAP_FLAGS_OBJECT_LOCALFREE))) { goto fail; }
    if(!(ctx->psPrefetch = ObSet_New(H))) { goto fail; }
    if(!(ctx->pVs = LocalAlloc(LMEM_ZEROINIT, sizeof(VMMWINPOOL_CTX_POOLSTORE)))) { goto fail; }
    if(!(ctx->pLfh = LocalAlloc(LMEM_ZEROINIT, sizeof(VMMWINPOOL_CTX_POOLSTORE)))) { goto fail; }
    ctx->pSystemProcess = pSystemProcess;
    ctx->po = &off;
    // 2: do work in different stages
    if(!VmmWinPool_AllPool1903_Offsets(H, pSystemProcess, &off)) { goto fail; }
    if(!VmmWinPool_AllPool1903_1_HeapMgr(H, ctx, &off)) { goto fail; }
    if(!VmmWinPool_AllPool1903_2_HeapFillSegmentHeap(H, ctx)) { goto fail; }
    VmmWinPool_AllPool1903_3_HeapFillPageSegment(H, ctx);
    if(!VmmWinPool_AllPool1903_4_HeapPageRangeDescriptor(H, ctx)) { goto fail; }
    // 3: fetch LFH and VS heap allocations in two separate threads
    VmmWorkWaitMultiple_Void(H, ctx, 2, VmmWinPool_AllPool1903_5_LFH, VmmWinPool_AllPool1903_5_VS);
    // 4: create pool map given the lfh, vs and big pool entries
    pObPoolAll = VmmWinPool_AllPool_CreateMap(H, pPoolBig, (PVMMWINPOOL_CTX_POOLSTORE[2]){ ctx->pLfh, ctx->pVs }, 2);
fail:
    if(ctx) {
        while(ctx->pVs) {
            pStore = ctx->pVs;
            ctx->pVs = pStore->pNext;
            LocalFree(pStore);
        }
        while(ctx->pLfh) {
            pStore = ctx->pLfh;
            ctx->pLfh = pStore->pNext;
            LocalFree(pStore);
        }
        Ob_DECREF(ctx->psPrefetch);
        Ob_DECREF(ctx->pmPgSeg);
        Ob_DECREF(ctx->pmHeap);
        Ob_DECREF(ctx->pmLfh);
        Ob_DECREF(ctx->pmVs);
    }
    LocalFree(ctx);
    return pObPoolAll;
}



//-----------------------------------------------------------------------------
// Windows10_1809 (and earlier) POOLs
//-----------------------------------------------------------------------------

typedef struct tdVMMWINPOOL7_RANGE {
    QWORD va;
    DWORD cb;
    VMM_MAP_POOL_TP tp;
} VMMWINPOOL7_RANGE, *PVMMWINPOOL7_RANGE;

typedef struct tdVMMWINPOOL7_CTX {
    PVMM_PROCESS pSystemProcess;
    POB_MAP pmRange;
    PVMMWINPOOL_CTX_POOLSTORE pStore;
    BYTE pbBuffer2M[0x02000000];
} VMMWINPOOL7_CTX, *PVMMWINPOOL7_CTX;

_Success_(return)
BOOL VmmWinPool_AllPool7_RangeInit(_In_ VMM_HANDLE H, _In_ PVMMWINPOOL7_CTX ctx)
{
    BOOL fResult = FALSE;
    QWORD va, vaPteTop = 0;
    DWORD i, iPte = 0, iva = 0, cva;
    PVMMWINPOOL7_RANGE pr;
    POB_DATA pvaOb = NULL;
    POB_SET psvaOb = NULL;
    PVMMOB_MAP_HANDLE pObHnd = NULL;
    PVMMOB_MAP_OBJECT pObObj = NULL;
    if(!(psvaOb = ObSet_New(H))) { goto fail; }
    // 1: fetch sorted handle & object addresses (which are residing inside the pool):
    if(VmmMap_GetHandle(H, ctx->pSystemProcess, &pObHnd, FALSE)) {
        for(i = 0; i < pObHnd->cMap; i++) {
            ObSet_Push(psvaOb, pObHnd->pMap[i].vaObject & ~0x1fffff);   // 2MB align
        }
    }
    if(VmmMap_GetObject(H, &pObObj)) {
        for(i = 0; i < pObObj->cMap; i++) {
            ObSet_Push(psvaOb, pObObj->pMap[i].va & ~0x1fffff);         // 2MB align
        }
    }
    // 2: sort and populate 2MB ranges
    if(!(pvaOb = ObSet_GetAll(psvaOb))) { goto fail; }
    cva = pvaOb->ObHdr.cbData / sizeof(QWORD);
    qsort(pvaOb->pqw, cva, sizeof(QWORD), Util_qsort_QWORD);
    for(i = 0; i < cva; i++) {
        va = pvaOb->pqw[i];
        if(!(pr = LocalAlloc(LMEM_ZEROINIT, sizeof(VMMWINPOOL7_RANGE)))) { goto fail; }
        pr->va = va;
        pr->cb = 0x00200000;
        pr->tp = VMM_MAP_POOL_TP_Unknown;
        ObMap_Push(ctx->pmRange, pr->va, pr);
    }
    fResult = TRUE;
fail:
    Ob_DECREF(pvaOb);
    Ob_DECREF(psvaOb);
    Ob_DECREF(pObObj);
    Ob_DECREF(pObHnd);
    return fResult;
}

#define VMMWINPOOL_POOLTAG_STRICT_CHAR_ALLOW \
    "0000000000000000000000000000000011000000000001101111111111000000" \
    "0111111111111111111111111110000101111111111111111111111111100000"

VOID VmmWinPool_AllPool7_ProcessSingleRange(_In_ VMM_HANDLE H, _In_ PVMMWINPOOL7_CTX ctx, _In_ PVMMWINPOOL7_RANGE pe, _In_ PBYTE pb)
{
    BOOL f, fTagBad, fPrev = FALSE, f32 = H->vmm.f32;
    CHAR ch;
    DWORD cbBlock = f32 ? 8 : 16;
    DWORD i, o = 0, dwPrevBlockSize = 0;
    DWORD dwPreviousSize, dwPoolIndex, dwBlockSize, dwPoolType, dwPoolTag;
    QWORD qwProcessBilled = 0;
    _PPOOL_HEADER32 pHdr32;
    _PPOOL_HEADER64 pHdr64;
    while(o + cbBlock <= pe->cb) {
        if(f32) {
            pHdr32 = (_PPOOL_HEADER32)(pb + o);
            dwPreviousSize = pHdr32->PreviousSize;
            dwPoolIndex = pHdr32->PoolIndex;
            dwBlockSize = pHdr32->BlockSize;
            dwPoolType = pHdr32->PoolType;
            dwPoolTag = pHdr32->PoolTag;
        } else {
            pHdr64 = (_PPOOL_HEADER64)(pb + o);
            dwPreviousSize = pHdr64->PreviousSize;
            dwPoolIndex = pHdr64->PoolIndex;
            dwBlockSize = pHdr64->BlockSize;
            dwPoolType = pHdr64->PoolType;
            dwPoolTag = pHdr64->PoolTag;
            qwProcessBilled = pHdr64->ProcessBilled;
        }
        // check: index / block size / process billed
        //if(dwPoolIndex) { goto next; }
        if(dwBlockSize < 2) { goto next; }
        if(fPrev && dwPreviousSize && (dwPrevBlockSize != dwPreviousSize)) { goto next; }
        if(dwPoolIndex || (qwProcessBilled && !fPrev)) {
            // strict pool tag checking:
            for(i = 0; i <= 16; i += 8) {
                ch = (CHAR)(dwPoolTag >> i);
                if((ch & 0x80) || (VMMWINPOOL_POOLTAG_STRICT_CHAR_ALLOW[(BYTE)ch] == '0')) {
                    goto next;
                }
            }
        }
        // check: pool type
        f = FALSE;
        switch(pe->tp) {
            case VMM_MAP_POOL_TP_Unknown:
                pe->tp = (dwPoolType & 1) ? VMM_MAP_POOL_TP_PagedPool : VMM_MAP_POOL_TP_NonPagedPool;
                f = TRUE;
                break;
            case VMM_MAP_POOL_TP_NonPagedPool:
            case VMM_MAP_POOL_TP_NonPagedPoolNx:
                f = (dwPoolType & 1) ? FALSE : TRUE;
                break;
            case VMM_MAP_POOL_TP_PagedPool:
                f = (dwPoolType & 1) ? TRUE : FALSE;
                break;
        }
        if(!f) { goto next; }
        // check: pool tag
        fTagBad = FALSE;
        for(i = 0; i <= 16; i += 8) {
            ch = (CHAR)(dwPoolTag >> i);
            fTagBad = fTagBad || (ch < 32) || (ch > 126);
        }
        if(fTagBad) {
            if(!fPrev) { goto next; }
            if(dwBlockSize == 2) { goto next; }
            if((dwPoolTag >> 16) == 0xffff) { goto next; }
        }
        // add pool entry!
        VmmWinPool_AllPool_PushItem(
            H,
            &ctx->pStore,
            pe->tp,
            VMM_MAP_POOL_TPSS_NA,
            pe->va + o,
            pb + o,
            cbBlock * dwBlockSize,
            TRUE
        );
        // next
        o += cbBlock * dwBlockSize;
        dwPrevBlockSize = dwBlockSize;
        fPrev = TRUE;
        continue;
next:
        o += cbBlock;
        fPrev = FALSE;
    }
}

/*
* Process ranges within ctx->pmRange in a fairly efficient way.
*/
_Success_(return)
BOOL VmmWinPool_AllPool7_ProcessRanges(_In_ VMM_HANDLE H, _In_ PVMMWINPOOL7_CTX ctx)
{
    DWORD iRP, iR, cR, iPrefetchBase = 0;
    QWORD cbPrefetch = 0;
    PVMMWINPOOL7_RANGE pe;
    POB_SET psObPrefetch = NULL;
    if(!(psObPrefetch = ObSet_New(H))) { return FALSE; }
    cR = ObMap_Size(ctx->pmRange);
    for(iRP = 0; iRP < cR; iRP++) {
        pe = ObMap_GetByIndex(ctx->pmRange, iRP);
        ObSet_Push_PageAlign(psObPrefetch, pe->va, pe->cb);
        cbPrefetch += pe->cb;
        if((cbPrefetch > VMMWINPOOL_PREFETCH_BUFFER_SIZE) || (iRP + 1 == cR)) {
            VmmCachePrefetchPages(H, ctx->pSystemProcess, psObPrefetch, 0);
            for(iR = iPrefetchBase; iR <= iRP; iR++) {
                pe = ObMap_GetByIndex(ctx->pmRange, iR);
                if(pe->cb > 0x00200000) { continue; }
                VmmReadEx(H, ctx->pSystemProcess, pe->va, ctx->pbBuffer2M, pe->cb, NULL, VMM_FLAG_FORCECACHE_READ | VMM_FLAG_ZEROPAD_ON_FAIL);
                VmmWinPool_AllPool7_ProcessSingleRange(H, ctx, pe, ctx->pbBuffer2M);
            }
            ObSet_Clear(psObPrefetch);
            iPrefetchBase = iRP + 1;
            cbPrefetch = 0;
        }
    }
    Ob_DECREF(psObPrefetch);
    return ctx->pStore->c || ctx->pStore->cPrevious;
}

/*
* Create a pool map containing all pool entries on Windows Vista to Windows10_1809
* CALLER DECREF: return
* -- H
* -- pSystemProcess
* -- pPoolBig
* -- return
*/
_Success_(return != NULL)
PVMMOB_MAP_POOL VmmWinPool_AllPool7_DoWork(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pSystemProcess, _In_ PVMMOB_MAP_POOL pPoolBig)
{
    PVMMOB_MAP_POOL pObPoolAll = NULL;
    PVMMWINPOOL7_CTX ctx = NULL;
    PVMMWINPOOL_CTX_POOLSTORE pStore;
    // 1: alloc & init
    if(!(ctx = LocalAlloc(LMEM_ZEROINIT, sizeof(VMMWINPOOL7_CTX)))) { goto fail; }
    if(!(ctx->pmRange = ObMap_New(H, OB_MAP_FLAGS_OBJECT_LOCALFREE))) { goto fail; }
    if(!(ctx->pStore = LocalAlloc(LMEM_ZEROINIT, sizeof(VMMWINPOOL_CTX_POOLSTORE)))) { goto fail; }
    ctx->pSystemProcess = pSystemProcess;
    //if(!VmmWinPool_AllPool7_Offset(ctx)) { goto fail; }
    if(!VmmWinPool_AllPool7_RangeInit(H, ctx)) { goto fail; }
    if(!VmmWinPool_AllPool7_ProcessRanges(H, ctx)) { goto fail; }
    pObPoolAll = VmmWinPool_AllPool_CreateMap(H, pPoolBig, &ctx->pStore, 1);
fail:
    if(ctx) {
        while(ctx->pStore) {
            pStore = ctx->pStore;
            ctx->pStore = pStore->pNext;
            LocalFree(pStore);
        }
        Ob_DECREF(ctx->pmRange);
    }
    LocalFree(ctx);
    return pObPoolAll;
}



//-----------------------------------------------------------------------------
// GENERAL POOL FUNCTIONALITY BELOW:
//-----------------------------------------------------------------------------

/*
* Create a pool map containing all pool entries.
* CALLER DECREF: return
* -- H
* -- pSystemProcess
* -- pPoolBig
* -- return
*/
_Success_(return != NULL)
PVMMOB_MAP_POOL VmmWinPool_Initialize_AllPool_DoWork(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pSystemProcess, _In_ PVMMOB_MAP_POOL pPoolBig)
{
    return (H->vmm.kernel.dwVersionBuild >= 18362) ?
        VmmWinPool_AllPool1903_DoWork(H, pSystemProcess, pPoolBig) :   // 1903+
        VmmWinPool_AllPool7_DoWork(H, pSystemProcess, pPoolBig);       // XP->1809
}

/*
* Create a pool map and assign to the global vmm context upon success.
* CALLER DECREF: return
* -- H
* -- fAll = TRUE: retrieve all pools; FALSE: retrieve big page pool only.
* -- return
*/
PVMMOB_MAP_POOL VmmWinPool_Initialize(_In_ VMM_HANDLE H, _In_ BOOL fAll)
{
    PVMM_PROCESS pObSystemProcess = NULL;
    PVMMOB_MAP_POOL pObPoolBig = NULL, pObPoolAll = NULL;
    VMMSTATISTICS_LOG Statistics = { 0 };
    if(fAll && (pObPoolAll = ObContainer_GetOb(H->vmm.pObCMapPoolAll))) { return pObPoolAll; }
    if((pObPoolBig = ObContainer_GetOb(H->vmm.pObCMapPoolBig)) && !fAll) { return pObPoolBig; }
    // fetch big pool map (if required)
    if(!pObPoolBig && (pObSystemProcess = VmmProcessGet(H, 4))) {
        EnterCriticalSection(&H->vmm.LockUpdateMap);
        if(!(pObPoolBig = ObContainer_GetOb(H->vmm.pObCMapPoolBig))) {
            VmmStatisticsLogStart(H, MID_POOL, LOGLEVEL_6_TRACE, NULL, &Statistics, "INIT POOL(BIG)");
            pObPoolBig = VmmWinPool_Initialize_BigPool_DoWork(H, pObSystemProcess);
            VmmStatisticsLogEnd(H, &Statistics, "INIT POOL(BIG)");
            ObContainer_SetOb(H->vmm.pObCMapPoolBig, pObPoolBig);
        }
        LeaveCriticalSection(&H->vmm.LockUpdateMap);
        Ob_DECREF_NULL(&pObSystemProcess);
    }
    if(!fAll || !pObPoolBig) { return pObPoolBig; }
    // fetch all pool map
    if(!pObPoolAll && (pObSystemProcess = VmmProcessGet(H, 4))) {
        EnterCriticalSection(&H->vmm.LockUpdateMap);
        if(!(pObPoolAll = ObContainer_GetOb(H->vmm.pObCMapPoolAll))) {
            VmmStatisticsLogStart(H, MID_POOL, LOGLEVEL_6_TRACE, NULL, &Statistics, "INIT POOL(ALL)");
            pObPoolAll = VmmWinPool_Initialize_AllPool_DoWork(H, pObSystemProcess, pObPoolBig);
            VmmStatisticsLogEnd(H, &Statistics, "INIT POOL(ALL)");
            if(!pObPoolAll) {
                // if all pool map fail - fallback to big pool map
                pObPoolAll = Ob_INCREF(pObPoolBig);
            }
            ObContainer_SetOb(H->vmm.pObCMapPoolAll, pObPoolAll);
        }
        LeaveCriticalSection(&H->vmm.LockUpdateMap);
        Ob_DECREF_NULL(&pObSystemProcess);
    }
    Ob_DECREF(pObPoolBig);
    return pObPoolAll;
}

/*
* Refresh the Pool sub-system.
* -- H
*/
VOID VmmWinPool_Refresh(_In_ VMM_HANDLE H)
{
    ObContainer_SetOb(H->vmm.pObCMapPoolAll, NULL);
    ObContainer_SetOb(H->vmm.pObCMapPoolBig, NULL);
}
