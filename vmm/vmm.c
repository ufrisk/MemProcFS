// vmm.c : implementation of functions related to virtual memory management support.
//
// (c) Ulf Frisk, 2018-2019
// Author: Ulf Frisk, pcileech@frizk.net
//

#include "vmm.h"
#include "mm_x86.h"
#include "mm_x86pae.h"
#include "mm_x64.h"
#include "vmmproc.h"
#include "pluginmanager.h"
#include "util.h"

// ----------------------------------------------------------------------------
// OBJECT MANAGER FUNCTIONALITY:
//
// The object manager is a minimal non-threaded way of allocating objects with
// reference counts. When reference count reach zero the object is deallocated
// automatically.
//
// All VmmOb functions are thread-safe and performs only minimum locking.
//
// A thread calls VmmOb_Alloc to allocate an object of a specific length. The
// object initially have reference count 1. Reference counts may be increased
// by calling VmmOb_INCREF and decreased by calling VmmOb_DECREF. If the ref-
// count reach one or zero in a call to VmmOb_DECREF optional callbacks may be
// made (specified at VmmOb_Alloc time). Callbacks may be useful for cleanup
// tasks - such as decreasing reference count of sub-objects contained in the
// object that is to be deallocated.
//
// A container provides atomic access to a single VmmOb object. This is useful
// if a VmmOb object is to frequently be replaced by a new object in an atomic
// way. An example of this is the process list object containing the process
// information. The container holds a reference count to the object that is
// contained.
//
// ----------------------------------------------------------------------------

#define VMMOB_DEBUG_FOOTER_SIZE         0x20
#define VMMOB_DEBUG_FOOTER_MAGIC        0x001122334455667788
#define VMMOB_HEADER_MAGIC              0x0c0efefe

// Internal object manager use only - same size as opaque VMMOB struct.
typedef struct tdVMMOB_HEADER {
    DWORD magic;                        // magic value - VMMOB_HEADER_MAGIC
    WORD count;                         // reference count
    WORD tag;                           // tag - 2 chars, no null terminator
    VOID(*pfnRef_0)(_In_ PVOID pVmmOb); // callback - object specific cleanup before free
    VOID(*pfnRef_1)(_In_ PVOID pVmmOb); // callback - when object reach refcount 1 (not initial)
    DWORD dbg;
    DWORD cbData;
    BYTE pbData[];
} VMMOB_HEADER, *PVMMOB_HEADER;

/*
* Allocate a new vmm object manager memory object.
* -- tag = tag of the object to be allocated.
* -- uFlags = flags as given by LocalAlloc.
* -- uBytes = bytes of object (excluding object headers).
* -- pfnRef_0 = optional callback for cleanup o be called before object is destroyed.
*               (if object has references that should be decremented before destruction).
* -- pfnRef_1 = optional callback for when object reach refcount = 1 (excl. initial).
* -- return = allocated object on success, with refcount = 1, - NULL on fail.
*/
PVOID VmmOb_Alloc(_In_ WORD tag, _In_ UINT uFlags, _In_ SIZE_T uBytes, _In_opt_ VOID(*pfnRef_0)(_In_ PVOID pVmmOb), _In_opt_ VOID(*pfnRef_1)(_In_ PVOID pVmmOb))
{
    PVMMOB_HEADER pOb;
    if(uBytes > 0x40000000) { return NULL; }
    pOb = (PVMMOB_HEADER)LocalAlloc(uFlags, uBytes + sizeof(VMMOB_HEADER) + VMMOB_DEBUG_FOOTER_SIZE);
    if(!pOb) { return NULL; }
    pOb->magic = VMMOB_HEADER_MAGIC;
    pOb->count = 1;
    pOb->tag = tag;
    pOb->pfnRef_0 = pfnRef_0;
    pOb->pfnRef_1 = pfnRef_1;
    pOb->cbData = (DWORD)uBytes;
#ifdef VMMOB_DEBUG
    DWORD i, cb = sizeof(VMMOB_HEADER) + pOb->cbData;
    PBYTE pb = (PBYTE)pOb;
    for(i = 0; i < VMMOB_DEBUG_FOOTER_SIZE; i += 8) {
        *(PQWORD)(pb + cb + i) = VMMOB_DEBUG_FOOTER_MAGIC;
    }
#endif /* VMMOB_DEBUG */
    return pOb;
}

#define VmmOb_TpINCREF(pOb, type)     (type*)((pOb && (((PVMMOB_HEADER)pOb)->magic == VMMOB_HEADER_MAGIC) && InterlockedIncrement16(&((PVMMOB_HEADER)pOb)->count)) ? pOb : NULL)

/*
* Increase the reference count of a vmm object manager object.
* -- pVmmOb
*/
PVOID VmmOb_INCREF(PVOID pVmmOb)
{
    PVMMOB_HEADER pOb = (PVMMOB_HEADER)pVmmOb;
    if(pOb && (pOb->magic == VMMOB_HEADER_MAGIC)) {
        InterlockedIncrement16(&pOb->count);
        return (PVMMOB)pVmmOb;
    }
    return NULL;
}

/*
* Decrease the reference count of a vmm object manager object. If the reference
* count reaches zero the object will be cleaned up.
* -- pVmmOb
*/
VOID VmmOb_DECREF(PVOID pVmmOb)
{
    PVMMOB_HEADER pOb = (PVMMOB_HEADER)pVmmOb;
    WORD c;
    if(pOb && (pOb->magic == VMMOB_HEADER_MAGIC)) {
        c = InterlockedDecrement16(&pOb->count);
#ifdef VMMOB_DEBUG
        DWORD i, cb = sizeof(VMMOB_HEADER) + pOb->cbData;
        PBYTE pb = (PBYTE)pOb;
        for(i = 0; i < VMMOB_DEBUG_FOOTER_SIZE; i += 8) {
            if(*(PQWORD)(pb + cb + i) != VMMOB_DEBUG_FOOTER_MAGIC) {
                vmmprintfvv_fn("FOOTER OVERWRITTEN - MEMORY CORRUPTION? REFCNT: %i TAG: %02X\n", c, pOb->tag)
            }
        }
#endif /* VMMOB_DEBUG */
        if(c == 0) {
            if(pOb->pfnRef_0) { pOb->pfnRef_0(pVmmOb); }
            LocalFree(pVmmOb);
        } else if((c == 1) && pOb->pfnRef_1) {
            pOb->pfnRef_1(pVmmOb);
        }
    }
}

/*
* Initialize a VmmObContainer with an optional pVmmOb.
*/
VOID VmmObContainer_Initialize(_In_ PVMMOBCONTAINER pVmmObContainer, _In_opt_ PVOID pVmmOb)
{
    InitializeCriticalSectionAndSpinCount(&pVmmObContainer->Lock, 4096);
    pVmmObContainer->pVmmOb = VmmOb_INCREF(pVmmOb);
}

/*
* Retrieve an enclosed VmmOb from the given pVmmObContainer. Reference count
* of the retrieved VmmOb must be decremented by caller after use is completed!
*/
PVOID VmmObContainer_GetOb(_In_ PVMMOBCONTAINER pVmmObContainer)
{
    PVMMOB pOb;
    EnterCriticalSection(&pVmmObContainer->Lock);
    pOb = VmmOb_INCREF(pVmmObContainer->pVmmOb);
    LeaveCriticalSection(&pVmmObContainer->Lock);
    return pOb;
}

/*
* Set or Replace a VmmOb in the pVmmObContainer.
*/
VOID VmmObContainer_SetOb(_In_ PVMMOBCONTAINER pVmmObContainer, _In_opt_ PVOID pVmmOb)
{
    EnterCriticalSection(&pVmmObContainer->Lock);
    VmmOb_DECREF(pVmmObContainer->pVmmOb);
    pVmmObContainer->pVmmOb = VmmOb_INCREF(pVmmOb);
    LeaveCriticalSection(&pVmmObContainer->Lock);
}

VOID VmmObContainer_Close(_In_ PVMMOBCONTAINER pVmmObContainer)
{
    if(!pVmmObContainer) { return; }
    EnterCriticalSection(&pVmmObContainer->Lock);
    VmmOb_DECREF(pVmmObContainer->pVmmOb);
    pVmmObContainer->pVmmOb = NULL;
    LeaveCriticalSection(&pVmmObContainer->Lock);
    DeleteCriticalSection(&pVmmObContainer->Lock);
}

// ----------------------------------------------------------------------------
// DATASET STRUCT FUNCTIONALITY:
// The VMMOB_DATASET/VmmObDataSet_* functionality allows for auto-growing arrays
// of optionally unique data. The VmmObDataSet_Put is not thread safe and should
// only be used at creation time in single-threaded context.
// ----------------------------------------------------------------------------

VOID VmmObDataSet_CallbackClose(PVMMOB_MEM pOb)
{
    VmmOb_DECREF(((PVMMOB_DATASET)pOb)->pObData);
}

/*
* Allocate a VmmObDataSet and optionally set it to only contain unique items.
* CALLER_DECREF: return
* -- fUnique = set will only contain unique values.
* -- return
*/
PVMMOB_DATASET VmmObDataSet_Alloc(_In_ BOOL fUnique)
{
    PVMMOB_DATASET pObDataSet;
    pObDataSet = VmmOb_Alloc('ds', 0, sizeof(VMMOB_DATASET), VmmObDataSet_CallbackClose, NULL);
    if(!pObDataSet) { return NULL; }
    pObDataSet->c = 0;
    pObDataSet->cMax = 0x40;
    pObDataSet->iListStart = 0;
    pObDataSet->fUnique = fUnique;
    pObDataSet->pObData = VmmOb_Alloc('dl', 0, pObDataSet->cMax * sizeof(VMMDATALIST), NULL, NULL);
    if(!pObDataSet->pObData) {
        VmmOb_DECREF(pObDataSet);
        return NULL;
    }
    return pObDataSet;
}

/*
* Insert a value into a VmmObDataSet. This function is not meant to be called
* in a multi-threaded context.
* -- pDataSet
* -- v
* -- return = insertion was successful.
*/
BOOL VmmObDataSet_Put(_In_ PVMMOB_DATASET pDataSet, _In_ QWORD v)
{
    PVMMOB_PDATA pObNextData = NULL;
    PVMMDATALIST pDataNew, pDataCurrent = NULL, pDataNext = NULL;
    // 1: increase storage space if required
    if(pDataSet->c == pDataSet->cMax) {
        pObNextData = VmmOb_Alloc('dl', 0, (QWORD)pDataSet->pObData->cbData << 1, NULL, NULL);
        if(!pObNextData) { return FALSE; }
        memcpy(pObNextData->pbData, pDataSet->pObData->pbData, pDataSet->pObData->cbData);
        VmmOb_DECREF(pDataSet->pObData);
        pDataSet->pObData = pObNextData;
        pDataSet->cMax <<= 1;
    }
    // 2: set up new item and check initial conditions
    pDataNew = pDataSet->pObData->pList + pDataSet->c;
    pDataNew->iNext = (DWORD)-1;
    pDataNew->Value = v;
    if(pDataSet->c == 0) {
        pDataSet->c++;
        return TRUE;
    }
    pDataCurrent = pDataSet->pObData->pList + pDataSet->iListStart;
    if(pDataCurrent->Value >= v) {
        if(pDataSet->fUnique && (pDataCurrent->Value == v)) {
            return FALSE;
        }
        pDataNew->iNext = pDataSet->iListStart;
        pDataSet->iListStart = pDataSet->c;
        pDataSet->c++;
        return TRUE;
    }
    // 3: walk list
    while(pDataCurrent->iNext != (DWORD)-1) {
        pDataNext = pDataSet->pObData->pList + pDataCurrent->iNext;
        if(pDataNext->Value >= v) {
            if(pDataSet->fUnique && (pDataNext->Value == v)) {
                return FALSE;
            }
            pDataNew->iNext = pDataCurrent->iNext;
            pDataCurrent->iNext = pDataSet->c;
            pDataSet->c++;
            return TRUE;
        }
        pDataCurrent = pDataNext;
    }
    // 4: insert at tail (not found previously)
    pDataCurrent->iNext = pDataSet->c;
    pDataSet->c++;
    return TRUE;
}

// ----------------------------------------------------------------------------
// CACHE FUNCTIONALITY:
// PHYSICAL MEMORY CACHING FOR READS AND PAGE TABLES
// ----------------------------------------------------------------------------

/*
* Retrieve cache table from ctxVmm given a specific tag.
*/
PVMM_CACHE_TABLE VmmCacheTableGet(_In_ WORD wTblTag)
{
    switch(wTblTag) {
        case VMM_CACHE_TAG_PHYS:
            return &ctxVmm->PHYS;
        case VMM_CACHE_TAG_TLB:
            return &ctxVmm->TLB;
        default:
            return NULL;
    }
}

#define VMM_CACHE2_GET_REGION(qwA)      ((qwA >> 12) % VMM_CACHE2_REGIONS)
#define VMM_CACHE2_GET_BUCKET(qwA)      ((qwA >> 12) % VMM_CACHE2_BUCKETS)

/*
* Invalidate a cache entry (if exists)
*/
VOID VmmCacheInvalidate_2(_In_ WORD wTblTag, _In_ QWORD qwA)
{
    DWORD iR, iB;
    PVMM_CACHE_TABLE t;
    PVMMOB_MEM pOb, pObNext;
    t = VmmCacheTableGet(wTblTag);
    if(!t || !t->fActive) { return; }
    iR = VMM_CACHE2_GET_REGION(qwA);
    iB = VMM_CACHE2_GET_BUCKET(qwA);
    EnterCriticalSection(&t->R[iR].Lock);
    pOb = t->R[iR].B[iB];
    while(pOb) {
        pObNext = pOb->FLink;
        if(pOb->h.qwA == qwA) {
            // detach bucket
            if(pOb->BLink) {
                pOb->BLink->FLink = pOb->FLink;
            } else {
                t->R[iR].B[iB] = pOb->FLink;
            }
            if(pOb->FLink) {
                pOb->FLink->BLink = pOb->BLink;
            }
            // detach age list
            if(pOb->AgeBLink) {
                pOb->AgeBLink->AgeFLink = pOb->AgeFLink;
            } else {
                t->R[iR].AgeFLink = pOb->AgeFLink;
            }
            if(pOb->AgeFLink) {
                pOb->AgeFLink->AgeBLink = pOb->AgeBLink;
            } else {
                t->R[iR].AgeBLink = pOb->AgeBLink;
            }
            // decrease count & decref
            InterlockedDecrement(&t->R[iR].c);
            VmmOb_DECREF(pOb);
        }
        pOb = pObNext;
    }
    LeaveCriticalSection(&t->R[iR].Lock);
}

VOID VmmCacheInvalidate(_In_ QWORD pa)
{
    VmmCacheInvalidate_2(VMM_CACHE_TAG_TLB, pa);
    VmmCacheInvalidate_2(VMM_CACHE_TAG_PHYS, pa);
}

VOID VmmCacheReclaim(_In_ PVMM_CACHE_TABLE t, _In_ DWORD iR, _In_ BOOL fTotal)
{
    DWORD cThreshold;
    PVMMOB_MEM pOb;
    EnterCriticalSection(&t->R[iR].Lock);
    cThreshold = fTotal ? 0 : max(0x10, t->R[iR].c >> 1);
    while(t->R[iR].c > cThreshold) {
        // get
        pOb = t->R[iR].AgeBLink;
        if(!pOb) {
            vmmprintf_fn("ERROR - SHOULD NOT HAPPEN - NULL OBJECT RETRIEVED\n");
            break;
        }
        // detach from age list
        t->R[iR].AgeBLink = pOb->AgeBLink;
        if(pOb->AgeBLink) {
            pOb->AgeBLink->AgeFLink = NULL;
        } else {
            t->R[iR].AgeFLink = NULL;
        }
        // detach from bucket list
        if(pOb->BLink) {
            pOb->BLink->FLink = NULL;
        } else {
            t->R[iR].B[VMM_CACHE2_GET_BUCKET(pOb->h.qwA)] = NULL;
        }
        // remove region refcount of object - callback will take care of
        // re-insertion into empty list when refcount becomes low enough.
        VmmOb_DECREF(pOb);
        InterlockedDecrement(&t->R[iR].c);
    }
    LeaveCriticalSection(&t->R[iR].Lock);
}

/*
* Clear the specified cache from all entries.
* -- wTblTag
*/
VOID VmmCacheClear(_In_ WORD wTblTag)
{
    DWORD i;
    PVMM_CACHE_TABLE t;
    PVMM_PROCESS pObProcess = NULL;
    // 1: clear cache
    t = VmmCacheTableGet(wTblTag);
    for(i = 0; i < VMM_CACHE2_REGIONS; i++) {
        VmmCacheReclaim(t, i, TRUE);
    }
    // 2: if tlb cache clear -> update process 'is spider done' flag
    if(wTblTag == VMM_CACHE_TAG_TLB) {
        while((pObProcess = VmmProcessGetNext(pObProcess))) {
            if(pObProcess->fTlbSpiderDone) {
                EnterCriticalSection(&pObProcess->LockUpdate);
                pObProcess->fTlbSpiderDone = FALSE;
                LeaveCriticalSection(&pObProcess->LockUpdate);
            }
        }
    }
}

VOID VmmCache_CallbackRefCount1(PVMMOB_MEM pOb)
{
    PVMM_CACHE_TABLE t;
    t = VmmCacheTableGet(((PVMMOB_HEADER)pOb)->tag);
    if(!t) {
        vmmprintf_fn("ERROR - SHOULD NOT HAPPEN - INVALID OBJECT TAG %02X\n", ((PVMMOB_HEADER)pOb)->tag);
        return;
    }
    if(!t->fActive) { return; }
    VmmOb_INCREF(pOb);
    InterlockedPushEntrySList(&t->ListHeadEmpty, &pOb->SListEmpty);
    InterlockedIncrement(&t->cEmpty);
}

/*
* Return an entry retrieved with VmmCacheReserve to the cache.
* NB! no other items may be returned with this function!
* FUNCTION DECREF: pOb
* -- pOb
*/
VOID VmmCacheReserveReturn(_In_opt_ PVMMOB_MEM pOb)
{
    DWORD iR, iB;
    PVMM_CACHE_TABLE t;
    if(!pOb) { return; }
    t = VmmCacheTableGet(((PVMMOB_HEADER)pOb)->tag);
    if(!t) {
        vmmprintf_fn("ERROR - SHOULD NOT HAPPEN - INVALID OBJECT TAG %02X\n", ((PVMMOB_HEADER)pOb)->tag);
        return;
    }
    if((pOb->h.cb != 0x1000) || (pOb->h.qwA == (QWORD)-1) || !t->fActive) {
        // decrement refcount of object - callback will take care of
        // re-insertion into empty list when refcount becomes low enough.
        VmmOb_DECREF(pOb);
        return;
    }
    // insert into map - refcount will be overtaken by "cache region".
    iR = VMM_CACHE2_GET_REGION(pOb->h.qwA);
    iB = VMM_CACHE2_GET_BUCKET(pOb->h.qwA);
    EnterCriticalSection(&t->R[iR].Lock);
    // insert into "bucket"
    pOb->BLink = NULL;
    pOb->FLink = t->R[iR].B[iB];
    if(pOb->FLink) { pOb->FLink->BLink = pOb; }
    t->R[iR].B[iB] = pOb;
    // insert into "age list"
    pOb->AgeFLink = t->R[iR].AgeFLink;
    if(pOb->AgeFLink) { pOb->AgeFLink->AgeBLink = pOb; }
    pOb->AgeBLink = NULL;
    t->R[iR].AgeFLink = pOb;
    if(!t->R[iR].AgeBLink) { t->R[iR].AgeBLink = pOb; }
    InterlockedIncrement(&t->R[iR].c);
    LeaveCriticalSection(&t->R[iR].Lock);
}

PVMMOB_MEM VmmCacheReserve(_In_ WORD wTblTag)
{
    PVMM_CACHE_TABLE t;
    PVMMOB_MEM pOb;
    PSLIST_ENTRY e;
    WORD iReclaimLast, cLoopProtect = 0;
    t = VmmCacheTableGet(wTblTag);
    if(!t || !t->fActive) { return NULL; }
    while(!(e = InterlockedPopEntrySList(&t->ListHeadEmpty))) {
        if(t->cTotal < VMM_CACHE2_MAX_ENTRIES) {
            // below max threshold -> create new
            pOb = VmmOb_Alloc(t->tag, LMEM_ZEROINIT, sizeof(VMMOB_MEM), NULL, VmmCache_CallbackRefCount1);
            if(!pOb) { return NULL; }
            pOb->h.magic = MEM_IO_SCATTER_HEADER_MAGIC;
            pOb->h.version = MEM_IO_SCATTER_HEADER_VERSION;
            pOb->h.cbMax = 0x1000;
            pOb->h.pb = pOb->pb;
            pOb->h.qwA = (QWORD)-1;
            VmmOb_INCREF(pOb);  // "total list" reference
            InterlockedPushEntrySList(&t->ListHeadTotal, &pOb->SListTotal);
            InterlockedIncrement(&t->cTotal);
            return pOb;         // return fresh object - refcount = 2.
        }
        // reclaim existing entries
        iReclaimLast = InterlockedIncrement16(&t->iReclaimLast);
        VmmCacheReclaim(t, iReclaimLast % VMM_CACHE2_REGIONS, FALSE);
        if(++cLoopProtect == VMM_CACHE2_REGIONS) {
            vmmprintf_fn("ERROR - SHOULD NOT HAPPEN - CACHE %02X DRAINED OF ENTRIES\n", wTblTag);
            Sleep(10);
        }
    }
    InterlockedDecrement(&t->cEmpty);
    pOb = CONTAINING_RECORD(e, VMMOB_MEM, SListEmpty);
    pOb->h.qwA = (QWORD)-1;
    pOb->h.cb = 0;
    return pOb; // reference overtaken by callee (from EmptyList)
}

PVMMOB_MEM VmmCacheGet(_In_ WORD wTblTag, _In_ QWORD qwA)
{
    PVMM_CACHE_TABLE t;
    DWORD iR;
    PVMMOB_MEM pOb;
    t = VmmCacheTableGet(wTblTag);
    if(!t || !t->fActive) { return NULL; }
    iR = VMM_CACHE2_GET_REGION(qwA);
    EnterCriticalSection(&t->R[iR].Lock);
    pOb = t->R[iR].B[VMM_CACHE2_GET_BUCKET(qwA)];
    while(pOb && (qwA != pOb->h.qwA)) {
        pOb = pOb->FLink;
    }
    VmmOb_INCREF(pOb);
    LeaveCriticalSection(&t->R[iR].Lock);
    return pOb;
}

PVMMOB_MEM VmmCacheGet_FromDeviceOnMiss(_In_ WORD wTblTag, _In_ QWORD qwA)
{
    PVMMOB_MEM pObMEM, pObReservedMEM;
    PMEM_IO_SCATTER_HEADER pMEM;
    pObMEM = VmmCacheGet(wTblTag, qwA);
    if(pObMEM) { return pObMEM; }
    pObReservedMEM = VmmCacheReserve(wTblTag);
    if(pObReservedMEM) {
        pMEM = &pObReservedMEM->h;
        pMEM->qwA = qwA;
        LeechCore_ReadScatter(&pMEM, 1);
        if(pMEM->cb == 0x1000) {
            VmmOb_INCREF(pObReservedMEM);
            VmmCacheReserveReturn(pObReservedMEM);
            return pObReservedMEM;
        }
    }
    VmmCacheReserveReturn(pObReservedMEM);
    return NULL;
}

BOOL VmmCacheExists(_In_ WORD wTblTag, _In_ QWORD qwA)
{
    BOOL result;
    PVMMOB_MEM pOb;
    pOb = VmmCacheGet(wTblTag, qwA);
    result = pOb != NULL;
    VmmOb_DECREF(pOb);
    return result;
}

/*
* Retrieve a page table from a given physical address (if possible).
* CALLER DECREF: return
* -- pa
* -- fCacheOnly
* -- return = Cache entry on success, NULL on fail.
*/
PVMMOB_MEM VmmTlbGetPageTable(_In_ QWORD pa, _In_ BOOL fCacheOnly)
{
    PVMMOB_MEM pObMEM;
    pObMEM = VmmCacheGet(VMM_CACHE_TAG_TLB, pa);
    if(pObMEM) {
        InterlockedIncrement64(&ctxVmm->stat.cTlbCacheHit);
        return pObMEM;
    }
    if(fCacheOnly) { return NULL; }
    pObMEM = VmmCacheGet_FromDeviceOnMiss(VMM_CACHE_TAG_TLB, pa);
    if(!pObMEM) {
        InterlockedIncrement64(&ctxVmm->stat.cTlbReadFail);
        return NULL;
    }
    InterlockedIncrement64(&ctxVmm->stat.cTlbReadSuccess);
    if(VmmTlbPageTableVerify(pObMEM->h.pb, pObMEM->h.qwA, FALSE)) {
        return pObMEM;
    }
    VmmOb_DECREF(pObMEM);
    return NULL;
}

VOID VmmCache2Close(_In_ WORD wTblTag)
{
    PVMM_CACHE_TABLE t;
    PVMMOB_MEM pOb;
    PSLIST_ENTRY e;
    DWORD i;
    t = VmmCacheTableGet(wTblTag);
    if(!t || !t->fActive) { return; }
    t->fActive = FALSE;
    // remove from "regions"
    for(i = 0; i < VMM_CACHE2_REGIONS; i++) {
        VmmCacheReclaim(t, i, TRUE);
        DeleteCriticalSection(&t->R[i].Lock);
    }
    // remove from "empty list"
    while(e = InterlockedPopEntrySList(&t->ListHeadEmpty)) {
        pOb = CONTAINING_RECORD(e, VMMOB_MEM, SListEmpty);
        VmmOb_DECREF(pOb);
        InterlockedDecrement(&t->cEmpty);
    }
    // remove from "total list"
    while(e = InterlockedPopEntrySList(&t->ListHeadTotal)) {
        pOb = CONTAINING_RECORD(e, VMMOB_MEM, SListTotal);
        VmmOb_DECREF(pOb);
        InterlockedDecrement(&t->cTotal);
    }
}

VOID VmmCache2Initialize(_In_ WORD wTblTag)
{
    DWORD i;
    PVMM_CACHE_TABLE t;
    t = VmmCacheTableGet(wTblTag);
    if(!t || t->fActive) { return; }
    for(i = 0; i < VMM_CACHE2_REGIONS; i++) {
        InitializeCriticalSection(&t->R[i].Lock);
    }
    InitializeSListHead(&t->ListHeadEmpty);
    InitializeSListHead(&t->ListHeadTotal);
    t->fActive = TRUE;
    t->tag = wTblTag;
}

/*
* Prefetch a set of addresses contained in pObPrefetchAddresses into the cache.
* This is useful when reading data from somewhat known addresses over higher
* latency connections.
* -- pProcess
* -- pObPrefetchAddresses
*/
VOID VmmCachePrefetchPages(_In_opt_ PVMM_PROCESS pProcess, _In_opt_ PVMMOB_DATASET pObPrefetchAddresses)
{
    QWORD va;
    DWORD i, c = 0;
    PPMEM_IO_SCATTER_HEADER ppMEMs = NULL;
    if(!pObPrefetchAddresses || !pObPrefetchAddresses->c || (ctxVmm->flags & VMM_FLAG_NOCACHE)) { return; }
    if(!LeechCore_AllocScatterEmpty(pObPrefetchAddresses->c, &ppMEMs)) { return; }
    for(i = 0; i < pObPrefetchAddresses->c; i++) {
        va = pObPrefetchAddresses->pObData->pList[i].Value & ~0xfff;
        if(!(c && i && (ppMEMs[c]->qwA == va))) {
            ppMEMs[c]->qwA = va;
            c++;
        }
    }
    if(pProcess) {
        VmmReadScatterVirtual(pProcess, ppMEMs, c, 0);
    } else {
        VmmReadScatterPhysical(ppMEMs, c, 0);
    }
    LocalFree(ppMEMs);
}

// ----------------------------------------------------------------------------
// PROCESS MANAGEMENT FUNCTIONALITY:
//
// The process 'object' represents a process in the analyzed system.
//
// The process 'object' is an object manager refcount object. The processes may
// contain, in addition to values, sub-objects such as maps of loaded modules
// and memory.
//
// Before updates to the process object happens the 'LockUpdate' generally
// should be acquired.
//
// The active processes are contained in a 'process table' which is also an
// object manager refcount object. Atmoic access (get and increase refcount) is
// guarded by a object manager container which allows for easy retrieval of the
// process table. The process table may also contain a process table for new
// not yet committed process objects. When processes are refreshed in the back-
// ground they are created (or copied by refcount increase) into the new table.
// Once all processes are enumerated the function 'VmmProcessCreateFinish' is
// called and replaces the 'old' table with the 'new' table which becomes the
// active table. The 'old' replaced table is refcount-decreased and possibly
// free'd as a result.
//
// The process object: VMM_PROCESS
// The process table object (only used internally): VMMOB_PROCESS_TABLE
// ----------------------------------------------------------------------------

typedef struct tdVMMOB_PROCESS_TABLE {
    VMMOB ObHdr;
    SIZE_T c;
    WORD _iFLink;
    WORD _iFLinkM[VMM_PROCESSTABLE_ENTRIES_MAX];
    PVMM_PROCESS _M[VMM_PROCESSTABLE_ENTRIES_MAX];
    VMMOBCONTAINER NewPROC;         // contains VMM_PROCESS_TABLE
} VMMOB_PROCESS_TABLE, *PVMMOB_PROCESS_TABLE;

/*
* Retrieve pProcess for a given PVMMOB_PROCESS_TABLE.
* CALLER DECREF: return
* -- pt
* -- dwPID
* -- return
*/
PVMM_PROCESS VmmProcessGetEx(_In_ PVMMOB_PROCESS_TABLE pt, _In_ DWORD dwPID)
{
    DWORD i, iStart;
    i = iStart = dwPID % VMM_PROCESSTABLE_ENTRIES_MAX;
    while(TRUE) {
        if(!pt->_M[i]) { return NULL; }
        if(pt->_M[i]->dwPID == dwPID) {
            return VmmOb_TpINCREF(pt->_M[i], VMM_PROCESS);
        }
        if(++i == VMM_PROCESSTABLE_ENTRIES_MAX) { i = 0; }
        if(i == iStart) { return NULL; }
    }
}

/*
* Retrieve an existing process given a process id (PID).
* CALLER DECREF: return
* -- dwPID
* -- return = a process struct, or NULL if not found.
*/
PVMM_PROCESS VmmProcessGet(_In_ DWORD dwPID)
{
    PVMM_PROCESS pProcess;
    PVMMOB_PROCESS_TABLE pt = (PVMMOB_PROCESS_TABLE)VmmObContainer_GetOb(&ctxVmm->PROC);
    pProcess = VmmProcessGetEx(pt, dwPID);
    VmmOb_DECREF(pt);
    return pProcess;
}

/*
* Retrieve the next process given a process. This may be useful when iterating
* over a process list. NB! Listing of next item may fail prematurely if the
* previous process is terminated while having a reference to it.
* FUNCTION DECREF: pProcess
* CALLER DECREF: return
* -- pProcess = a process struct, or NULL if first.
     NB! function DECREF's  pProcess and must not be used after call!
* -- return = a process struct, or NULL if not found.
*/
PVMM_PROCESS VmmProcessGetNext(_In_opt_ PVMM_PROCESS pProcess)
{
    PVMMOB_PROCESS_TABLE pt = (PVMMOB_PROCESS_TABLE)VmmObContainer_GetOb(&ctxVmm->PROC);
    PVMM_PROCESS pProcessNew;
    DWORD i, iStart;
    if(!pt) { goto fail; }
    if(!pProcess) {
        i = pt->_iFLink;
        if(!pt->_M[i]) { goto fail; }
        pProcessNew = VmmOb_TpINCREF(pt->_M[i], VMM_PROCESS);
        VmmOb_DECREF(pProcess);
        VmmOb_DECREF(pt);
        return pProcessNew;
    }
    i = iStart = pProcess->dwPID % VMM_PROCESSTABLE_ENTRIES_MAX;
    while(TRUE) {
        if(!pt->_M[i]) { goto fail; }
        if(pt->_M[i]->dwPID == pProcess->dwPID) {
            // current process -> retrieve next!
            i = pt->_iFLinkM[i];
            if(!pt->_M[i]) { goto fail; }
            pProcessNew = VmmOb_TpINCREF(pt->_M[i], VMM_PROCESS);
            VmmOb_DECREF(pProcess);
            VmmOb_DECREF(pt);
            return pProcessNew;
        }
        if(++i == VMM_PROCESSTABLE_ENTRIES_MAX) { i = 0; }
        if(i == iStart) { goto fail; }
    }
fail:
    VmmOb_DECREF(pProcess);
    VmmOb_DECREF(pt);
    return NULL;
}

/*
* Object manager callback before 'static process' object cleanup
* decrease refcount of any internal objects.
*/
VOID VmmProcessStatic_CloseObCallback(_In_ PVOID pVmmOb)
{
    PVMMOB_PROCESS_PERSISTENT pProcessStatic = (PVMMOB_PROCESS_PERSISTENT)pVmmOb;
    VmmObContainer_Close(&pProcessStatic->ObCLdrModulesCachePrefetch32);
    VmmObContainer_Close(&pProcessStatic->ObCLdrModulesCachePrefetch64);
}

/*
* Object manager callback before 'static process' object cleanup
* decrease refcount of any internal objects.
*/
VOID VmmProcessStatic_Initialize(_In_ PVMM_PROCESS pProcess)
{
    EnterCriticalSection(&pProcess->LockUpdate);
    VmmOb_DECREF(&pProcess->pObProcessPersistent);
    pProcess->pObProcessPersistent = VmmOb_Alloc('PS', LMEM_ZEROINIT, sizeof(VMMOB_PROCESS_PERSISTENT), VmmProcessStatic_CloseObCallback, NULL);
    if(pProcess->pObProcessPersistent) {
        VmmObContainer_Initialize(&pProcess->pObProcessPersistent->ObCLdrModulesCachePrefetch32, NULL);
        VmmObContainer_Initialize(&pProcess->pObProcessPersistent->ObCLdrModulesCachePrefetch64, NULL);
    }
    LeaveCriticalSection(&pProcess->LockUpdate);
}

/*
* Object manager callback before 'process' object cleanup - decrease refcount
* of any internal 'memory map' and 'module map' objects.
*/
VOID VmmProcess_CloseObCallback(_In_ PVOID pVmmOb)
{
    PVMM_PROCESS pProcess = (PVMM_PROCESS)pVmmOb;
    // general cleanup below
    VmmOb_DECREF(pProcess->pObMemMap);
    VmmOb_DECREF(pProcess->pObModuleMap);
    VmmOb_DECREF(pProcess->pObProcessPersistent);
    // plugin cleanup below
    VmmObContainer_Close(&pProcess->Plugin.ObCLdrModulesDisplayCache);
    VmmObContainer_Close(&pProcess->Plugin.ObCPeDumpDirCache);
    // delete lock
    DeleteCriticalSection(&pProcess->LockUpdate);
}

/*
* Object manager callback before 'process table' object cleanup - decrease
* refcount of all contained 'process' objects.
*/
VOID VmmProcessTable_CloseObCallback(_In_ PVOID pVmmOb)
{
    PVMMOB_PROCESS_TABLE pt = (PVMMOB_PROCESS_TABLE)pVmmOb;
    PVMM_PROCESS pProcess;
    WORD iProcess;
    // Close NewPROC
    VmmObContainer_Close(&pt->NewPROC);
    // DECREF all pProcess in table
    iProcess = pt->_iFLink;
    pProcess = pt->_M[iProcess];
    while(pProcess) {
        VmmOb_DECREF(pProcess);
        iProcess = pt->_iFLinkM[iProcess];
        pProcess = pt->_M[iProcess];
        if(!pProcess || iProcess == pt->_iFLink) { break; }
    }
}

/*
* Create a new process object. New process object are created in a separate
* data structure and won't become visible to the "Process" functions until
* after the VmmProcessCreateFinish have been called.
* CALLER DECREF: return
* -- fTotalRefresh = create a completely new entry - i.e. do not copy any form
*                    of data from the old entry such as module and memory maps.
* -- dwPID
* -- dwState
* -- paDTB
* -- paDTB_UserOpt
* -- szName
* -- fUserOnly = user mode process (hide supervisor pages from view)
*/
PVMM_PROCESS VmmProcessCreateEntry(_In_ BOOL fTotalRefresh, _In_ DWORD dwPID, _In_ DWORD dwState, _In_ QWORD paDTB, _In_ QWORD paDTB_UserOpt, _In_ CHAR szName[16], _In_ BOOL fUserOnly)
{
    PVMMOB_PROCESS_TABLE ptOld = NULL, ptNew = NULL;
    QWORD i, iStart, cEmpty = 0, cValid = 0;
    PVMM_PROCESS pProcess = NULL, pProcessOld = NULL;
    PVMMOB_MEM pObDTB = NULL;
    BOOL result;
    // 1: Sanity check DTB
    pObDTB = VmmTlbGetPageTable(paDTB, FALSE);
    if(!pObDTB) { goto fail; }
    result = VmmTlbPageTableVerify(pObDTB->h.pb, paDTB, (ctxVmm->tpSystem == VMM_SYSTEM_WINDOWS_X64));
    VmmOb_DECREF(pObDTB);
    if(!result) { goto fail; }
    // 2: Allocate new 'Process Table' (if not already existing)
    ptOld = (PVMMOB_PROCESS_TABLE)VmmObContainer_GetOb(&ctxVmm->PROC);
    if(!ptOld) { goto fail; }
    ptNew = (PVMMOB_PROCESS_TABLE)VmmObContainer_GetOb(&ptOld->NewPROC);
    if(!ptNew) {
        ptNew = (PVMMOB_PROCESS_TABLE)VmmOb_Alloc('PT', LMEM_ZEROINIT, sizeof(VMMOB_PROCESS_TABLE), VmmProcessTable_CloseObCallback, NULL);
        if(!ptNew) { goto fail; }
        VmmObContainer_Initialize(&ptNew->NewPROC, NULL);
        VmmObContainer_SetOb(&ptOld->NewPROC, ptNew);
    }
    // 3: Sanity check - process to create not already in 'new' table.
    pProcess = VmmProcessGetEx(ptNew, dwPID);
    if(pProcess) { goto fail; }
    // 4: Prepare existing item, or create new item, for new PID
    if(!fTotalRefresh) {
        pProcess = VmmProcessGetEx(ptOld, dwPID);
    }
    if(!pProcess) {
        pProcess = (PVMM_PROCESS)VmmOb_Alloc('PR', LMEM_ZEROINIT, sizeof(VMM_PROCESS), VmmProcess_CloseObCallback, NULL);
        if(!pProcess) { goto fail; }
        InitializeCriticalSectionAndSpinCount(&pProcess->LockUpdate, 4096);
        memcpy(pProcess->szName, szName, 16);
        pProcess->szName[15] = 0;
        pProcess->dwPID = dwPID;
        pProcess->dwState = dwState;
        pProcess->paDTB = paDTB;
        pProcess->paDTB_UserOpt = paDTB_UserOpt;
        pProcess->fUserOnly = fUserOnly;
        pProcess->fTlbSpiderDone = pProcess->fTlbSpiderDone;
        VmmObContainer_Initialize(&pProcess->Plugin.ObCLdrModulesDisplayCache, NULL);
        VmmObContainer_Initialize(&pProcess->Plugin.ObCPeDumpDirCache, NULL);
        // attach pre-existing static process info entry or create new
        pProcessOld = VmmProcessGet(dwPID);
        if(pProcessOld) {
            pProcess->pObProcessPersistent = VmmOb_TpINCREF(pProcessOld->pObProcessPersistent, VMMOB_PROCESS_PERSISTENT);
        } else {
            VmmProcessStatic_Initialize(pProcess);
        }
        VmmOb_DECREF(pProcessOld);
        pProcessOld = NULL;
    }
    // 5: Install new PID
    i = iStart = dwPID % VMM_PROCESSTABLE_ENTRIES_MAX;
    while(TRUE) {
        if(!ptNew->_M[i]) {
            ptNew->_M[i] = pProcess;
            ptNew->_iFLinkM[i] = ptNew->_iFLink;
            ptNew->_iFLink = (WORD)i;
            ptNew->c++;
            VmmOb_DECREF(ptOld);
            VmmOb_DECREF(ptNew);
            // pProcess already "consumed" by table insertion so increase before returning ... 
            return VmmOb_TpINCREF(pProcess, VMM_PROCESS);
        }
        if(++i == VMM_PROCESSTABLE_ENTRIES_MAX) { i = 0; }
        if(i == iStart) { goto fail; }
    }
fail:
    VmmOb_DECREF(pProcess);
    VmmOb_DECREF(ptOld);
    VmmOb_DECREF(ptNew);
    return NULL;
}

/*
* Activate the pending, not yet active, processes added by VmmProcessCreateEntry.
* This will also clear any previous processes.
*/
VOID VmmProcessCreateFinish()
{
    PVMMOB_PROCESS_TABLE ptNew, ptOld;
    if(!(ptOld = VmmObContainer_GetOb(&ctxVmm->PROC))) {
        return;
    }
    if(!(ptNew = VmmObContainer_GetOb(&ptOld->NewPROC))) {
        VmmOb_DECREF(ptOld);
        return;
    }
    // Replace "existing" old process table with new.
    VmmObContainer_SetOb(&ctxVmm->PROC, ptNew);
    VmmOb_DECREF(ptNew);
    VmmOb_DECREF(ptOld);
}

/*
* Clear the TLB spider flag in all process objects.
*/
VOID VmmProcessTlbClear()
{
    PVMMOB_PROCESS_TABLE pt = (PVMMOB_PROCESS_TABLE)VmmObContainer_GetOb(&ctxVmm->PROC);
    PVMM_PROCESS pProcess;
    WORD iProcess;
    if(!pt) { return; }
    iProcess = pt->_iFLink;
    pProcess = pt->_M[iProcess];
    while(pProcess) {
        pProcess->fTlbSpiderDone = FALSE;
        iProcess = pt->_iFLinkM[iProcess];
        pProcess = pt->_M[iProcess];
        if(!pProcess || iProcess == pt->_iFLink) { break; }
    }
    VmmOb_DECREF(pt);
}

/*
* List the PIDs and put them into the supplied table.
* -- pPIDs = user allocated DWORD array to receive result, or NULL.
* -- pcPIDs = ptr to number of DWORDs in pPIDs on entry - number of PIDs in system on exit.
*/
VOID VmmProcessListPIDs(_Out_writes_opt_(*pcPIDs) PDWORD pPIDs, _Inout_ PSIZE_T pcPIDs)
{
    PVMMOB_PROCESS_TABLE pt = (PVMMOB_PROCESS_TABLE)VmmObContainer_GetOb(&ctxVmm->PROC);
    PVMM_PROCESS pProcess;
    WORD iProcess;
    DWORD i = 0;
    if(!pPIDs) {
        *pcPIDs = pt->c;
        VmmOb_DECREF(pt);
        return;
    }
    if(*pcPIDs < pt->c) {
        *pcPIDs = 0;
        VmmOb_DECREF(pt);
        return;
    }
    // copy all PIDs
    iProcess = pt->_iFLink;
    pProcess = pt->_M[iProcess];
    while(pProcess) {
        *(pPIDs + i) = pProcess->dwPID;
        i++;
        iProcess = pt->_iFLinkM[iProcess];
        pProcess = pt->_M[iProcess];
        if(!pProcess || (iProcess == pt->_iFLink)) { break; }
    }
    *pcPIDs = i;
    VmmOb_DECREF(pt);
}

/*
* Create the initial process table at startup.
*/
BOOL VmmProcessTableCreateInitial()
{
    PVMMOB_PROCESS_TABLE pt = (PVMMOB_PROCESS_TABLE)VmmOb_Alloc('PT', LMEM_ZEROINIT, sizeof(VMMOB_PROCESS_TABLE), VmmProcessTable_CloseObCallback, NULL);
    if(!pt) { return FALSE; }
    VmmObContainer_Initialize(&pt->NewPROC, NULL);
    VmmObContainer_Initialize(&ctxVmm->PROC, pt);
    VmmOb_DECREF(pt);
    return TRUE;
}

// ----------------------------------------------------------------------------
// INTERNAL VMMU FUNCTIONALITY: VIRTUAL MEMORY ACCESS.
// ----------------------------------------------------------------------------

VOID VmmWriteScatterVirtual(_In_ PVMM_PROCESS pProcess, _Inout_ PPMEM_IO_SCATTER_HEADER ppMEMsVirt, _In_ DWORD cpMEMsVirt)
{
    BOOL result;
    QWORD i, qwPA;
    PMEM_IO_SCATTER_HEADER pMEM_Virt;
    // loop over the items, this may not be very efficient compared to a true
    // scatter write, but since underlying hardware implementation does not
    // support it yet this will be fine ...
    if(!ctxMain->dev.fWritable) { return; }
    for(i = 0; i < cpMEMsVirt; i++) {
        pMEM_Virt = ppMEMsVirt[i];
        pMEM_Virt->cb = 0;
        result = VmmVirt2Phys(pProcess, pMEM_Virt->qwA, &qwPA);
        if(!result) { continue; }
        InterlockedIncrement64(&ctxVmm->stat.cPhysWrite);
        result = LeechCore_Write(qwPA, pMEM_Virt->pb, pMEM_Virt->cbMax);
        if(result) {
            pMEM_Virt->cb = pMEM_Virt->cbMax;
            VmmCacheInvalidate(qwPA & ~0xfff);
        }
    }
}

VOID VmmWriteScatterPhysical(_Inout_ PPMEM_IO_SCATTER_HEADER ppMEMsPhys, _In_ DWORD cpMEMsPhys)
{
    BOOL result;
    QWORD i;
    PMEM_IO_SCATTER_HEADER pMEM_Phys;
    // loop over the items, this may not be very efficient compared to a true
    // scatter write, but since underlying hardware implementation does not
    // support it yet this will be fine ...
    if(!ctxMain->dev.fWritable) { return; }
    for(i = 0; i < cpMEMsPhys; i++) {
        pMEM_Phys = ppMEMsPhys[i];
        InterlockedIncrement64(&ctxVmm->stat.cPhysWrite);
        result = LeechCore_Write(pMEM_Phys->qwA, pMEM_Phys->pb, pMEM_Phys->cbMax);
        if(result) {
            pMEM_Phys->cb = pMEM_Phys->cbMax;
            VmmCacheInvalidate(pMEM_Phys->qwA & ~0xfff);
        }
    }
}

BOOL VmmWritePhysical(_In_ QWORD pa, _In_ PBYTE pb, _In_ DWORD cb)
{
    QWORD paPage;
    // 1: invalidate any physical pages from cache
    paPage = pa & ~0xfff;
    do {
        InterlockedIncrement64(&ctxVmm->stat.cPhysWrite);
        VmmCacheInvalidate(paPage);
        paPage += 0x1000;
    } while(paPage < pa + cb);
    // 2: perform write
    return LeechCore_Write(pa, pb, cb);
}

BOOL VmmReadPhysicalPage(_In_ QWORD qwPA, _Inout_bytecount_(4096) PBYTE pbPage)
{
    BOOL result;
    PVMMOB_MEM pObMEM, pObReservedEntry;
    PMEM_IO_SCATTER_HEADER pMEM;
    qwPA &= ~0xfff;
    pObMEM = VmmCacheGet(VMM_CACHE_TAG_PHYS, qwPA);
    if(pObMEM) {
        memcpy(pbPage, pObMEM->pb, 0x1000);
        VmmOb_DECREF(pObMEM);
        return TRUE;
    }
    pObReservedEntry = VmmCacheReserve(VMM_CACHE_TAG_PHYS);
    pMEM = &pObReservedEntry->h;
    pMEM->qwA = qwPA;
    LeechCore_ReadScatter(&pMEM, 1);
    result = pMEM->cb == 0x1000;
    if(result) {
        memcpy(pbPage, pMEM->pb, 0x1000);
    } else {
        ZeroMemory(pbPage, 0x1000);
    }
    VmmCacheReserveReturn(pObReservedEntry);
    return result;
}

VOID VmmReadScatterPhysical(_Inout_ PPMEM_IO_SCATTER_HEADER ppMEMsPhys, _In_ DWORD cpMEMsPhys, _In_ QWORD flags)
{
    DWORD i, c;
    BOOL fCache;
    PMEM_IO_SCATTER_HEADER pMEM;
    PVMMOB_MEM pObCacheEntry, pObReservedMEM;
    DWORD cSpeculative;
    PMEM_IO_SCATTER_HEADER ppMEMsSpeculative[0x18];
    PVMMOB_MEM ppObCacheSpeculative[0x18];
    fCache = !(VMM_FLAG_NOCACHE & (flags | ctxVmm->flags));
    // 1: cache read
    if(fCache) {
        c = 0, cSpeculative = 0;
        for(i = 0; i < cpMEMsPhys; i++) {
            pMEM = ppMEMsPhys[i];
            pMEM->pvReserved2 = (PVOID)0;
            if(pMEM->cb == pMEM->cbMax) {
                // already valid -> skip
                pMEM->pvReserved2 = (PVOID)1;  // 1 == already read
                c++;
                continue;
            }
            // retrieve from cache (if found)
            if((pMEM->cbMax == 0x1000) && (pObCacheEntry = VmmCacheGet(VMM_CACHE_TAG_PHYS, pMEM->qwA))) {
                // in cache - copy data into requester and set as completed!
                pMEM->pvReserved2 = (PVOID)2;  // 2 == cache hit
                pMEM->cb = 0x1000;
                memcpy(pMEM->pb, pObCacheEntry->pb, 0x1000);
                VmmOb_DECREF(pObCacheEntry);
                InterlockedIncrement64(&ctxVmm->stat.cPhysCacheHit);
                c++;
                continue;
            }
            // add to potential speculative read map if read is small enough...
            if(cSpeculative < 0x18) {
                ppMEMsSpeculative[cSpeculative++] = pMEM;
            }
        }
        if(c == cpMEMsPhys) { return; }                     // all found in cache -> return!
        if(VMM_FLAG_FORCECACHE_READ & flags) { return; }    // only cached reads allowed -> return!
    }
    // 2: speculative future read if negligible performance loss
    if(fCache && cSpeculative && (cSpeculative < 0x18)) {
        while(cSpeculative < 0x18) {
            ppObCacheSpeculative[cSpeculative] = VmmCacheReserve(VMM_CACHE_TAG_PHYS);
            ppMEMsSpeculative[cSpeculative] = &ppObCacheSpeculative[cSpeculative]->h;
            ppMEMsSpeculative[cSpeculative]->cb = 0;
            ppMEMsSpeculative[cSpeculative]->qwA = ((QWORD)ppMEMsSpeculative[cSpeculative - 1]->qwA & ~0xfff) + 0x1000;
            ppMEMsSpeculative[cSpeculative]->pvReserved2 = (PVOID)3;  // 3 == speculative & backed by cache reserved
            cSpeculative++;
        }
        ppMEMsPhys = ppMEMsSpeculative;
        cpMEMsPhys = cSpeculative;
    }
    // 3: read!
    LeechCore_ReadScatter(ppMEMsPhys, cpMEMsPhys);
    // 4: statistics and read fail zero fixups (if required)
    for(i = 0; i < cpMEMsPhys; i++) {
        pMEM = ppMEMsPhys[i];
        if(pMEM->cb == pMEM->cbMax) {
            // success
            InterlockedIncrement64(&ctxVmm->stat.cPhysReadSuccess);
        } else {
            // fail
            InterlockedIncrement64(&ctxVmm->stat.cPhysReadFail);
            if((flags & VMM_FLAG_ZEROPAD_ON_FAIL) && (pMEM->qwA < ctxMain->dev.paMax)) {
                ZeroMemory(pMEM->pb, pMEM->cbMax);
                pMEM->cb = pMEM->cbMax;
            }
        }
    }
    // 5: cache put
    if(fCache) {
        for(i = 0; i < cpMEMsPhys; i++) {
            pMEM = ppMEMsPhys[i];
            if(3 == (QWORD)pMEM->pvReserved2) { // 3 == speculative & backed by cache reserved
                VmmCacheReserveReturn(ppObCacheSpeculative[i]);
            }
            if((0 == (QWORD)pMEM->pvReserved2) && (pMEM->cb == 0x1000)) { // 0 = default
                pObReservedMEM = VmmCacheReserve(VMM_CACHE_TAG_PHYS);
                pObReservedMEM->h.qwA = pMEM->qwA;
                pObReservedMEM->h.cb = 0x1000;
                memcpy(pObReservedMEM->h.pb, pMEM->pb, 0x1000);
                VmmCacheReserveReturn(pObReservedMEM);
            }
        }
    }
}

VOID VmmReadScatterVirtual(_In_ PVMM_PROCESS pProcess, _Inout_ PPMEM_IO_SCATTER_HEADER ppMEMsVirt, _In_ DWORD cpMEMsVirt, _In_ QWORD flags)
{
    DWORD i = 0, iVA, iPA;
    QWORD qwPA;
    BYTE pbBufferSmall[0x20 * (sizeof(MEM_IO_SCATTER_HEADER) + sizeof(PMEM_IO_SCATTER_HEADER))];
    PBYTE pbBufferMEMs, pbBufferLarge = NULL;
    PMEM_IO_SCATTER_HEADER pIoPA, pIoVA;
    PPMEM_IO_SCATTER_HEADER ppMEMsPhys = NULL;
    // 1: allocate / set up buffers (if needed)
    if(cpMEMsVirt < 0x20) {
        ppMEMsPhys = (PPMEM_IO_SCATTER_HEADER)pbBufferSmall;
        pbBufferMEMs = pbBufferSmall + cpMEMsVirt * sizeof(PMEM_IO_SCATTER_HEADER);
    } else {
        if(!(pbBufferLarge = LocalAlloc(0, cpMEMsVirt * (sizeof(MEM_IO_SCATTER_HEADER) + sizeof(PMEM_IO_SCATTER_HEADER))))) { return; }
        ppMEMsPhys = (PPMEM_IO_SCATTER_HEADER)pbBufferLarge;
        pbBufferMEMs = pbBufferLarge + cpMEMsVirt * sizeof(PMEM_IO_SCATTER_HEADER);
    }
    // 2: translate virt2phys
    for(iVA = 0, iPA = 0; iVA < cpMEMsVirt; iVA++) {
        pIoVA = ppMEMsVirt[iVA];
        if(VmmVirt2Phys(pProcess, pIoVA->qwA, &qwPA)) {
            pIoPA = ppMEMsPhys[iPA] = (PMEM_IO_SCATTER_HEADER)pbBufferMEMs + iPA;
            iPA++;
            pIoPA->magic = MEM_IO_SCATTER_HEADER_MAGIC;
            pIoPA->version = MEM_IO_SCATTER_HEADER_VERSION;
            pIoPA->qwA = qwPA;
            pIoPA->cbMax = 0x1000;
            pIoPA->cb = 0;
            pIoPA->pb = pIoVA->pb;
            pIoPA->pvReserved1 = (PVOID)pIoVA;
        } else {
            pIoVA->cb = 0;
        }
    }
    // 3: read and check result
    VmmReadScatterPhysical(ppMEMsPhys, iPA, flags);
    while(iPA > 0) {
        iPA--;
        ((PMEM_IO_SCATTER_HEADER)ppMEMsPhys[iPA]->pvReserved1)->cb = ppMEMsPhys[iPA]->cb;
    }
    LocalFree(pbBufferLarge);
}

// ----------------------------------------------------------------------------
// PUBLICALLY VISIBLE FUNCTIONALITY RELATED TO VMMU.
// ----------------------------------------------------------------------------

VOID VmmClose()
{
    if(!ctxVmm) { return; }
    if(ctxVmm->pVmmVfsModuleList) { PluginManager_Close(); }
    if(ctxVmm->ThreadProcCache.fEnabled) {
        ctxVmm->ThreadProcCache.fEnabled = FALSE;
        while(ctxVmm->ThreadProcCache.hThread) {
            SwitchToThread();
        }
    }
    VmmObContainer_Close(&ctxVmm->PROC);
    if(ctxVmm->fnMemoryModel.pfnClose) {
        ctxVmm->fnMemoryModel.pfnClose();
    }
    VmmCache2Close(VMM_CACHE_TAG_PHYS);
    VmmCache2Close(VMM_CACHE_TAG_TLB);
    VmmObContainer_Close(&ctxVmm->ObCEPROCESSCachePrefetch);
    DeleteCriticalSection(&ctxVmm->MasterLock);
    LocalFree(ctxVmm);
    ctxVmm = NULL;
}

VOID VmmWriteEx(_In_opt_ PVMM_PROCESS pProcess, _In_ QWORD qwVA, _In_ PBYTE pb, _In_ DWORD cb, _Out_opt_ PDWORD pcbWrite)
{
    DWORD i = 0, oVA = 0, cbWrite = 0, cbP, cMEMs;
    PBYTE pbBuffer;
    PMEM_IO_SCATTER_HEADER pMEMs, *ppMEMs;
    if(pcbWrite) { *pcbWrite = 0; }
    // allocate
    cMEMs = (DWORD)(((qwVA & 0xfff) + cb + 0xfff) >> 12);
    pbBuffer = (PBYTE)LocalAlloc(LMEM_ZEROINIT, cMEMs * (sizeof(MEM_IO_SCATTER_HEADER) + sizeof(PMEM_IO_SCATTER_HEADER)));
    if(!pbBuffer) { return; }
    pMEMs = (PMEM_IO_SCATTER_HEADER)pbBuffer;
    ppMEMs = (PPMEM_IO_SCATTER_HEADER)(pbBuffer + cMEMs * sizeof(MEM_IO_SCATTER_HEADER));
    // prepare pages
    while(oVA < cb) {
        ppMEMs[i] = &pMEMs[i];
        pMEMs[i].version = MEM_IO_SCATTER_HEADER_VERSION;
        pMEMs[i].qwA = qwVA + oVA;
        cbP = 0x1000 - ((qwVA + oVA) & 0xfff);
        cbP = min(cbP, cb - oVA);
        pMEMs[i].cbMax = cbP;
        pMEMs[i].pb = pb + oVA;
        oVA += cbP;
        i++;
    }
    // write and count result
    if(pProcess) {
        VmmWriteScatterVirtual(pProcess, ppMEMs, cMEMs);
    } else {
        VmmWriteScatterPhysical(ppMEMs, cMEMs);
    }
    if(pcbWrite) {
        for(i = 0; i < cMEMs; i++) {
            cbWrite += pMEMs[i].cb;
        }
        *pcbWrite = cbWrite;
    }
    LocalFree(pbBuffer);
}

BOOL VmmWrite(_In_opt_ PVMM_PROCESS pProcess, _In_ QWORD qwVA, _In_ PBYTE pb, _In_ DWORD cb)
{
    DWORD cbWrite;
    VmmWriteEx(pProcess, qwVA, pb, cb, &cbWrite);
    return (cbWrite == cb);
}

VOID VmmReadEx(_In_opt_ PVMM_PROCESS pProcess, _In_ QWORD qwVA, _Out_ PBYTE pb, _In_ DWORD cb, _Out_opt_ PDWORD pcbReadOpt, _In_ QWORD flags)
{
    DWORD cbP, cMEMs, cbRead = 0;
    PBYTE pbBuffer;
    PMEM_IO_SCATTER_HEADER pMEMs, *ppMEMs;
    QWORD i, oVA;
    if(pcbReadOpt) { *pcbReadOpt = 0; }
    if(!cb) { return; }
    cMEMs = (DWORD)(((qwVA & 0xfff) + cb + 0xfff) >> 12);
    pbBuffer = (PBYTE)LocalAlloc(LMEM_ZEROINIT, 0x2000 + cMEMs * (sizeof(MEM_IO_SCATTER_HEADER) + sizeof(PMEM_IO_SCATTER_HEADER)));
    if(!pbBuffer) { return; }
    pMEMs = (PMEM_IO_SCATTER_HEADER)(pbBuffer + 0x2000);
    ppMEMs = (PPMEM_IO_SCATTER_HEADER)(pbBuffer + 0x2000 + cMEMs * sizeof(MEM_IO_SCATTER_HEADER));
    oVA = qwVA & 0xfff;
    // prepare "middle" pages
    for(i = 0; i < cMEMs; i++) {
        ppMEMs[i] = &pMEMs[i];
        pMEMs[i].magic = MEM_IO_SCATTER_HEADER_MAGIC;
        pMEMs[i].version = MEM_IO_SCATTER_HEADER_VERSION;
        pMEMs[i].qwA = qwVA - oVA + (i << 12);
        pMEMs[i].cbMax = 0x1000;
        pMEMs[i].pb = pb - oVA + (i << 12);
    }
    // fixup "first/last" pages
    pMEMs[0].pb = pbBuffer;
    if(cMEMs > 1) {
        pMEMs[cMEMs - 1].pb = pbBuffer + 0x1000;
    }
    // Read VMM and handle result
    if(pProcess) {
        VmmReadScatterVirtual(pProcess, ppMEMs, cMEMs, flags);
    } else {
        VmmReadScatterPhysical(ppMEMs, cMEMs, flags);
    }
    for(i = 0; i < cMEMs; i++) {
        if(pMEMs[i].cb == 0x1000) {
            cbRead += 0x1000;
        } else {
            ZeroMemory(pMEMs[i].pb, 0x1000);
        }
    }
    cbRead -= (pMEMs[0].cb == 0x1000) ? 0x1000 : 0;                             // adjust byte count for first page (if needed)
    cbRead -= ((cMEMs > 1) && (pMEMs[cMEMs - 1].cb == 0x1000)) ? 0x1000 : 0;    // adjust byte count for last page (if needed)
    // Handle first page
    cbP = (DWORD)min(cb, 0x1000 - oVA);
    if(pMEMs[0].cb == 0x1000) {
        memcpy(pb, pMEMs[0].pb + oVA, cbP);
        cbRead += cbP;
    } else {
        ZeroMemory(pb, cbP);
    }
    // Handle last page
    if(cMEMs > 1) {
        cbP = (((qwVA + cb) & 0xfff) ? ((qwVA + cb) & 0xfff) : 0x1000);
        if(pMEMs[cMEMs - 1].cb == 0x1000) {
            memcpy(pb + ((QWORD)cMEMs << 12) - oVA - 0x1000, pMEMs[cMEMs - 1].pb, cbP);
            cbRead += cbP;
        } else {
            ZeroMemory(pb + ((QWORD)cMEMs << 12) - oVA - 0x1000, cbP);
        }
    }
    if(pcbReadOpt) { *pcbReadOpt = cbRead; }
    LocalFree(pbBuffer);
}

_Success_(return)
BOOL VmmReadString_Unicode2Ansi(_In_ PVMM_PROCESS pProcess, _In_ QWORD qwVA, _Out_writes_(cch) LPSTR sz, _In_ DWORD cch, _Out_opt_ PBOOL pfDefaultChar)
{
    DWORD i = 0;
    BOOL result;
    int iResult;
    WCHAR wsz[0x1000];
    if(cch) { sz[0] = 0; }
    if((cch < 2) || (cch > 0x1000)) { return FALSE; }
    result = VmmRead(pProcess, qwVA, (PBYTE)wsz, cch << 1);
    if(!result) { return FALSE; }
    wsz[cch - 1] = 0;
    iResult = WideCharToMultiByte(CP_ACP, 0, wsz, -1, sz, cch, NULL, pfDefaultChar);
    if(!iResult) { return FALSE; }
    sz[cch - 1] = 0;
    return TRUE;
}

BOOL VmmRead(_In_opt_ PVMM_PROCESS pProcess, _In_ QWORD qwA, _Out_ PBYTE pb, _In_ DWORD cb)
{
    DWORD cbRead;
    VmmReadEx(pProcess, qwA, pb, cb, &cbRead, 0);
    return (cbRead == cb);
}

BOOL VmmReadPage(_In_opt_ PVMM_PROCESS pProcess, _In_ QWORD qwA, _Inout_bytecount_(4096) PBYTE pbPage)
{
    DWORD cb;
    VmmReadEx(pProcess, qwA, pbPage, 0x1000, &cb, 0);
    return cb == 0x1000;
}

VOID VmmInitializeMemoryModel(_In_ VMM_MEMORYMODEL_TP tp)
{
    switch(tp) {
        case VMM_MEMORYMODEL_X64:
            MmX64_Initialize();
            break;
        case VMM_MEMORYMODEL_X86PAE:
            MmX86PAE_Initialize();
            break;
        case VMM_MEMORYMODEL_X86:
            MmX86_Initialize();
            break;
        default:
            if(ctxVmm->fnMemoryModel.pfnClose) {
                ctxVmm->fnMemoryModel.pfnClose();
            }
    }
}

VOID VmmInitializeFunctions()
{
    HMODULE hNtDll = NULL;
    if((hNtDll = LoadLibraryA("ntdll.dll"))) {
        ctxVmm->fn.RtlDecompressBuffer = (VMMFN_RtlDecompressBuffer*)GetProcAddress(hNtDll, "RtlDecompressBuffer");
        FreeLibrary(hNtDll);
    }
}

BOOL VmmInitialize()
{
    // 1: allocate & initialize
    if(ctxVmm) { VmmClose(); }
    ctxVmm = (PVMM_CONTEXT)LocalAlloc(LMEM_ZEROINIT, sizeof(VMM_CONTEXT));
    if(!ctxVmm) { goto fail; }
    // 2: CACHE INIT: Process Table
    if(!VmmProcessTableCreateInitial()) { goto fail; }
    // 3: CACHE INIT: Translation Lookaside Buffer (TLB) Cache Table
    VmmCache2Initialize(VMM_CACHE_TAG_TLB);
    if(!ctxVmm->TLB.fActive) { goto fail; }
    // 4: CACHE INIT: Physical Memory Cache Table
    VmmCache2Initialize(VMM_CACHE_TAG_PHYS);
    if(!ctxVmm->PHYS.fActive) { goto fail; }
    // 5: OTHER INIT:
    VmmObContainer_Initialize(&ctxVmm->ObCEPROCESSCachePrefetch, NULL);
    InitializeCriticalSection(&ctxVmm->MasterLock);
    VmmInitializeFunctions();
    return TRUE;
fail:
    VmmClose();
    return FALSE;
}
