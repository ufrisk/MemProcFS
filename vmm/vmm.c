// vmm.c : implementation of functions related to virtual memory management support.
//
// (c) Ulf Frisk, 2018-2021
// Author: Ulf Frisk, pcileech@frizk.net
//

#include "vmm.h"
#include "mm.h"
#include "pdb.h"
#include "vmmproc.h"
#include "vmmwin.h"
#include "vmmwindef.h"
#include "vmmwinobj.h"
#include "vmmwinreg.h"
#include "vmmwinsvc.h"
#include "vmmevil.h"
#include "vmmnet.h"
#include "pluginmanager.h"
#include "charutil.h"
#include "util.h"
#ifdef _WIN32
#include <sddl.h>
#endif /* _WIN32 */

// ----------------------------------------------------------------------------
// VMM global variables below:
// ----------------------------------------------------------------------------

PVMM_CONTEXT ctxVmm = NULL;
PVMM_MAIN_CONTEXT ctxMain = NULL;



// ----------------------------------------------------------------------------
// CACHE FUNCTIONALITY:
// PHYSICAL MEMORY CACHING FOR READS AND PAGE TABLES
// ----------------------------------------------------------------------------

#define VMM_CACHE_GET_BUCKET(qwA)      ((VMM_CACHE_BUCKETS - 1) & ((qwA >> 12) + 13 * (qwA + _rotr16((WORD)qwA, 9) + _rotr((DWORD)qwA, 17) + _rotr64(qwA, 31))))

/*
* Retrieve cache table from ctxVmm given a specific tag.
*/
PVMM_CACHE_TABLE VmmCacheTableGet(_In_ DWORD wTblTag)
{
    switch(wTblTag) {
        case VMM_CACHE_TAG_PHYS:
            return &ctxVmm->Cache.PHYS;
        case VMM_CACHE_TAG_TLB:
            return &ctxVmm->Cache.TLB;
        case VMM_CACHE_TAG_PAGING:
            return &ctxVmm->Cache.PAGING;
        default:
            return NULL;
    }
}

/*
* Clear the oldest region of all InUse entries and make it the new active region.
* -- wTblTag
*/
VOID VmmCacheClearPartial(_In_ DWORD dwTblTag)
{
    PVMM_CACHE_TABLE t;
    PVMMOB_CACHE_MEM pOb;
    PSLIST_ENTRY e;
    DWORD iR;
    PVMM_PROCESS pObProcess = NULL;
    t = VmmCacheTableGet(dwTblTag);
    if(!t || !t->fActive) { return; }
    EnterCriticalSection(&t->Lock);
    iR = (t->iR + (VMM_CACHE_REGIONS - 1)) % VMM_CACHE_REGIONS;
    // 1: clear all entries from region
    AcquireSRWLockExclusive(&t->R[iR].LockSRW);
    while((e = InterlockedPopEntrySList(&t->R[iR].ListHeadInUse))) {
        pOb = CONTAINING_RECORD(e, VMMOB_CACHE_MEM, SListInUse);
        // remove region refcount of object - callback will take care of
        // re-insertion into empty list when refcount becomes low enough.
        Ob_DECREF(pOb);
    }
    ZeroMemory(t->R[iR].B, VMM_CACHE_BUCKETS * sizeof(PVMMOB_CACHE_MEM));
    ReleaseSRWLockExclusive(&t->R[iR].LockSRW);
    t->iR = iR;
    t->fAllActiveRegions = t->fAllActiveRegions || (t->iR == 0);
    LeaveCriticalSection(&t->Lock);
    // 2: if tlb cache clear -> update process 'is spider done' flag
    if(t->fAllActiveRegions && (dwTblTag == VMM_CACHE_TAG_TLB)) {
        while((pObProcess = VmmProcessGetNext(pObProcess, 0))) {
            if(pObProcess->fTlbSpiderDone) {
                EnterCriticalSection(&pObProcess->LockUpdate);
                pObProcess->fTlbSpiderDone = FALSE;
                LeaveCriticalSection(&pObProcess->LockUpdate);
            }
        }
    }
}

/*
* Clear the specified cache from all entries.
* -- dwTblTag
*/
VOID VmmCacheClear(_In_ DWORD dwTblTag)
{
    DWORD i;
    for(i = 0; i < VMM_CACHE_REGIONS; i++) {
        VmmCacheClearPartial(dwTblTag);
    }
}

/*
* Retrieve an item from the cache.
* CALLER DECREF: return
* -- dwTblTag
* -- qwA
* -- fCurrentRegionOnly = only retrieve from the currently active cache region.
* -- return
*/
PVMMOB_CACHE_MEM VmmCacheGetEx(_In_ DWORD dwTblTag, _In_ QWORD qwA, _In_ BOOL fCurrentRegionOnly)
{
    PVMM_CACHE_TABLE t;
    DWORD iB, iR, iRB, iRC;
    PVMMOB_CACHE_MEM pOb;
    t = VmmCacheTableGet(dwTblTag);
    if(!t || !t->fActive) { return NULL; }
    iB = VMM_CACHE_GET_BUCKET(qwA);
    iRB = t->iR;
    for(iRC = 0; iRC < VMM_CACHE_REGIONS; iRC++) {
        iR = (iRB + iRC) % VMM_CACHE_REGIONS;
        AcquireSRWLockShared(&t->R[iR].LockSRW);
        pOb = t->R[iR].B[iB];
        while(pOb && (pOb->h.qwA != qwA)) {
            pOb = pOb->FLink;
        }
        if(pOb) {
            Ob_INCREF(pOb);
            ReleaseSRWLockShared(&t->R[iR].LockSRW);
            return pOb;
        }
        ReleaseSRWLockShared(&t->R[iR].LockSRW);
        if(fCurrentRegionOnly) { break; }
    }
    return NULL;
}

/*
* Retrieve an item from the cache.
* CALLER DECREF: return
* -- dwTblTag
* -- qwA
* -- return
*/
PVMMOB_CACHE_MEM VmmCacheGet(_In_ DWORD dwTblTag, _In_ QWORD qwA)
{
    return VmmCacheGetEx(dwTblTag, qwA, FALSE);
}

BOOL VmmCacheExists(_In_ DWORD dwTblTag, _In_ QWORD qwA)
{
    BOOL result;
    PVMMOB_CACHE_MEM pOb;
    pOb = VmmCacheGetEx(dwTblTag, qwA, FALSE);
    result = pOb != NULL;
    Ob_DECREF(pOb);
    return result;
}

VOID VmmCache_CallbackRefCount1(PVMMOB_CACHE_MEM pOb)
{
    PVMM_CACHE_TABLE t;
    t = VmmCacheTableGet(((POB)pOb)->_tag);
    if(!t) {
        vmmprintf_fn("ERROR - SHOULD NOT HAPPEN - INVALID OBJECT TAG %02X\n", ((POB)pOb)->_tag);
        return;
    }
    if(!t->fActive) { return; }
    Ob_INCREF(pOb);
    InterlockedPushEntrySList(&t->R[pOb->iR].ListHeadEmpty, &pOb->SListEmpty);
}

PVMMOB_CACHE_MEM VmmCacheReserve(_In_ DWORD dwTblTag)
{
    PVMM_CACHE_TABLE t;
    PVMMOB_CACHE_MEM pOb;
    PSLIST_ENTRY e;
    WORD cLoopProtect = 0;
    t = VmmCacheTableGet(dwTblTag);
    if(!t || !t->fActive) { return NULL; }
    while(!(e = InterlockedPopEntrySList(&t->R[t->iR].ListHeadEmpty))) {
        if(QueryDepthSList(&t->R[t->iR].ListHeadTotal) < VMM_CACHE_REGION_MEMS) {
            // below max threshold -> create new
            pOb = Ob_Alloc(t->tag, LMEM_ZEROINIT, sizeof(VMMOB_CACHE_MEM), NULL, (OB_CLEANUP_CB)VmmCache_CallbackRefCount1);
            if(!pOb) { return NULL; }
            pOb->iR = t->iR;
            pOb->h.version = MEM_SCATTER_VERSION;
            pOb->h.cb = 0x1000;
            pOb->h.pb = pOb->pb;
            pOb->h.qwA = MEM_SCATTER_ADDR_INVALID;
            Ob_INCREF(pOb);  // "total list" reference
            InterlockedPushEntrySList(&t->R[pOb->iR].ListHeadTotal, &pOb->SListTotal);
            return pOb;         // return fresh object - refcount = 2.
        }
        // reclaim existing entries by clearing the oldest cache region.
        VmmCacheClearPartial(dwTblTag);
        if(++cLoopProtect == VMM_CACHE_REGIONS) {
            vmmprintf_fn("ERROR - SHOULD NOT HAPPEN - CACHE %04X DRAINED OF ENTRIES\n", dwTblTag);
            Sleep(10);
        }
    }
    pOb = CONTAINING_RECORD(e, VMMOB_CACHE_MEM, SListEmpty);
    pOb->h.qwA = MEM_SCATTER_ADDR_INVALID;
    pOb->h.f = FALSE;
    return pOb; // reference overtaken by callee (from EmptyList)
}

/*
* Return an entry retrieved with VmmCacheReserve to the cache.
* NB! no other items may be returned with this function!
* FUNCTION DECREF: pOb
* -- pOb
*/
VOID VmmCacheReserveReturn(_In_opt_ PVMMOB_CACHE_MEM pOb)
{
    PVMM_CACHE_TABLE t;
    if(!pOb) { return; }
    t = VmmCacheTableGet(((POB)pOb)->_tag);
    if(!t) {
        vmmprintf_fn("ERROR - SHOULD NOT HAPPEN - INVALID OBJECT TAG %02X\n", ((POB)pOb)->_tag);
        return;
    }
    if(!t->fActive || !pOb->h.f || (pOb->h.qwA == MEM_SCATTER_ADDR_INVALID)) {
        // decrement refcount of object - callback will take care of
        // re-insertion into empty list when refcount becomes low enough.
        Ob_DECREF(pOb);
        return;
    }
    // insert into map - refcount will be overtaken by "cache region".
    pOb->iB = VMM_CACHE_GET_BUCKET(pOb->h.qwA);
    AcquireSRWLockExclusive(&t->R[pOb->iR].LockSRW);
    InterlockedPushEntrySList(&t->R[pOb->iR].ListHeadInUse, &pOb->SListInUse);
    // insert into "bucket"
    pOb->BLink = NULL;
    pOb->FLink = t->R[pOb->iR].B[pOb->iB];
    if(pOb->FLink) { pOb->FLink->BLink = pOb; }
    t->R[pOb->iR].B[pOb->iB] = pOb;
    ReleaseSRWLockExclusive(&t->R[pOb->iR].LockSRW);
}

VOID VmmCacheClose(_In_ DWORD dwTblTag)
{
    PVMM_CACHE_TABLE t;
    PVMMOB_CACHE_MEM pOb;
    PSLIST_ENTRY e;
    DWORD iR;
    t = VmmCacheTableGet(dwTblTag);
    if(!t || !t->fActive) { return; }
    t->fActive = FALSE;
    EnterCriticalSection(&t->Lock);
    for(iR = 0; iR < VMM_CACHE_REGIONS; iR++) {
        AcquireSRWLockExclusive(&t->R[iR].LockSRW);
        // remove from "empty list"
        while((e = InterlockedPopEntrySList(&t->R[iR].ListHeadEmpty))) {
            pOb = CONTAINING_RECORD(e, VMMOB_CACHE_MEM, SListEmpty);
            Ob_DECREF(pOb);
        }
        // remove from "in use list"
        while((e = InterlockedPopEntrySList(&t->R[iR].ListHeadInUse))) {
            pOb = CONTAINING_RECORD(e, VMMOB_CACHE_MEM, SListInUse);
            Ob_DECREF(pOb);
        }
        // remove from "total list"
        while((e = InterlockedPopEntrySList(&t->R[iR].ListHeadTotal))) {
            pOb = CONTAINING_RECORD(e, VMMOB_CACHE_MEM, SListTotal);
            Ob_DECREF(pOb);
        }
    }
    DeleteCriticalSection(&t->Lock);
}

VOID VmmCacheInitialize(_In_ DWORD dwTblTag)
{
    DWORD iR;
    PVMM_CACHE_TABLE t;
    t = VmmCacheTableGet(dwTblTag);
    if(!t || t->fActive) { return; }
    for(iR = 0; iR < VMM_CACHE_REGIONS; iR++) {
        InitializeSRWLock(&t->R[iR].LockSRW);
        InitializeSListHead(&t->R[iR].ListHeadEmpty);
        InitializeSListHead(&t->R[iR].ListHeadInUse);
        InitializeSListHead(&t->R[iR].ListHeadTotal);
    }
    InitializeCriticalSection(&t->Lock);
    t->tag = dwTblTag;
    t->fActive = TRUE;
}

/*
* Invalidate a cache entry (if exists)
*/
VOID VmmCacheInvalidate_2(_In_ DWORD dwTblTag, _In_ QWORD qwA)
{
    PVMM_CACHE_TABLE t;
    PVMMOB_CACHE_MEM pOb;
    t = VmmCacheTableGet(dwTblTag);
    if(!t || !t->fActive) { return; }
    while((pOb = VmmCacheGet(dwTblTag, qwA))) {
        AcquireSRWLockExclusive(&t->R[pOb->iR].LockSRW);
        // remove from bucket list
        if(pOb->FLink) {
            pOb->FLink->BLink = pOb->BLink;
        }
        if(pOb->BLink) {
            pOb->BLink->FLink = pOb->FLink;
        } else {
            t->R[pOb->iR].B[pOb->iB] = pOb->FLink;
        }
        // NB! "leak" object - i.e. keep it on InUse list until the cache
        //     region itself gets cleared. somewhat ugly, but simple...
        ReleaseSRWLockExclusive(&t->R[pOb->iR].LockSRW);
        Ob_DECREF(pOb);
    }
}

VOID VmmCacheInvalidate(_In_ QWORD pa)
{
    VmmCacheInvalidate_2(VMM_CACHE_TAG_TLB, pa);
    VmmCacheInvalidate_2(VMM_CACHE_TAG_PHYS, pa);
}

PVMMOB_CACHE_MEM VmmCacheGet_FromDeviceOnMiss(_In_ DWORD dwTblTag, _In_ DWORD dwTblTagSecondaryOpt, _In_ QWORD qwA)
{
    PVMMOB_CACHE_MEM pObMEM, pObReservedMEM;
    PMEM_SCATTER pMEM;
    pObMEM = VmmCacheGet(dwTblTag, qwA);
    if(pObMEM) { return pObMEM; }
    if((pObReservedMEM = VmmCacheReserve(dwTblTag))) {
        pMEM = &pObReservedMEM->h;
        pMEM->qwA = qwA;
        if(dwTblTagSecondaryOpt && (pObMEM = VmmCacheGet(dwTblTagSecondaryOpt, qwA))) {
            pMEM->f = TRUE;
            memcpy(pMEM->pb, pObMEM->pb, 0x1000);
            Ob_DECREF(pObMEM);
            pObMEM = NULL;
        }
        if(!pMEM->f) {
            LcReadScatter(ctxMain->hLC, 1, &pMEM);
        }
        if(pMEM->f) {
            Ob_INCREF(pObReservedMEM);
            VmmCacheReserveReturn(pObReservedMEM);
            return pObReservedMEM;
        }
        VmmCacheReserveReturn(pObReservedMEM);
    }
    return NULL;
}

/*
* Retrieve a page table from a given physical address (if possible).
* CALLER DECREF: return
* -- pa
* -- fCacheOnly
* -- return = Cache entry on success, NULL on fail.
*/
PVMMOB_CACHE_MEM VmmTlbGetPageTable(_In_ QWORD pa, _In_ BOOL fCacheOnly)
{
    PVMMOB_CACHE_MEM pObMEM;
    pObMEM = VmmCacheGet(VMM_CACHE_TAG_TLB, pa);
    if(pObMEM) {
        InterlockedIncrement64(&ctxVmm->stat.cTlbCacheHit);
        return pObMEM;
    }
    if(fCacheOnly) { return NULL; }
    // try retrieve from (1) TLB cache, (2) PHYS cache, (3) device
    pObMEM = VmmCacheGet_FromDeviceOnMiss(VMM_CACHE_TAG_TLB, VMM_CACHE_TAG_PHYS, pa);
    if(!pObMEM) {
        InterlockedIncrement64(&ctxVmm->stat.cTlbReadFail);
        return NULL;
    }
    InterlockedIncrement64(&ctxVmm->stat.cTlbReadSuccess);
    if(VmmTlbPageTableVerify(pObMEM->h.pb, pObMEM->h.qwA, FALSE)) {
        return pObMEM;
    }
    Ob_DECREF(pObMEM);
    return NULL;
}

/*
* Translate a virtual address to a physical address by walking the page tables.
* The successfully translated Physical Address (PA) is returned in ppa.
* Upon fail the PTE will be returned in ppa (if possible) - which may be used
* to further lookup virtual memory in case of PageFile or Win10 MemCompression.
* -- paDTB
* -- fUserOnly
* -- va
* -- ppa
* -- return
*/
_Success_(return)
BOOL VmmVirt2PhysEx(_In_ QWORD paDTB, _In_ BOOL fUserOnly, _In_ QWORD va, _Out_ PQWORD ppa)
{
    *ppa = 0;
    if(ctxVmm->tpMemoryModel == VMM_MEMORYMODEL_NA) { return FALSE; }
    return ctxVmm->fnMemoryModel.pfnVirt2Phys(paDTB, fUserOnly, -1, va, ppa);
}

/*
* Translate a virtual address to a physical address by walking the page tables.
* The successfully translated Physical Address (PA) is returned in ppa.
* Upon fail the PTE will be returned in ppa (if possible) - which may be used
* to further lookup virtual memory in case of PageFile or Win10 MemCompression.
* -- pProcess
* -- va
* -- ppa
* -- return
*/
_Success_(return)
BOOL VmmVirt2Phys(_In_opt_ PVMM_PROCESS pProcess, _In_ QWORD va, _Out_ PQWORD ppa)
{
    *ppa = 0;
    if(!pProcess || (ctxVmm->tpMemoryModel == VMM_MEMORYMODEL_NA)) { return FALSE; }
    return ctxVmm->fnMemoryModel.pfnVirt2Phys(pProcess->paDTB, pProcess->fUserOnly, -1, va, ppa);
}

/*
* Spider the TLB (page table cache) to load all page table pages into the cache.
* This is done to speed up various subsequent virtual memory accesses.
* NB! pages may fall out of the cache if it's in heavy use or doe to timing.
* -- pProcess
*/
VOID VmmTlbSpider(_In_ PVMM_PROCESS pProcess)
{
    if(ctxVmm->tpMemoryModel == VMM_MEMORYMODEL_NA) { return; }
    ctxVmm->fnMemoryModel.pfnTlbSpider(pProcess);
}

/*
* Try verify that a supplied page table in pb is valid by analyzing it.
* -- pb = 0x1000 bytes containing the page table page.
* -- pa = physical address if the page table page.
* -- fSelfRefReq = is a self referential entry required to be in the map? (PML4 for Windows).
*/
BOOL VmmTlbPageTableVerify(_Inout_ PBYTE pb, _In_ QWORD pa, _In_ BOOL fSelfRefReq)
{
    if(ctxVmm->tpMemoryModel == VMM_MEMORYMODEL_NA) { return FALSE; }
    return ctxVmm->fnMemoryModel.pfnTlbPageTableVerify(pb, pa, fSelfRefReq);
}

/*
* Prefetch a set of physical addresses contained in pTlbPrefetch into the Tlb.
* NB! pTlbPrefetch must not be updated/altered during the function call.
* -- pProcess
* -- pTlbPrefetch = the page table addresses to prefetch (on entry) and empty set on exit.
*/
VOID VmmTlbPrefetch(_In_ POB_SET pTlbPrefetch)
{
    QWORD pbTlb = 0;
    DWORD cTlbs, i = 0;
    PPVMMOB_CACHE_MEM ppObMEMs = NULL;
    PPMEM_SCATTER ppMEMs = NULL;
    if(!(cTlbs = ObSet_Size(pTlbPrefetch))) { goto fail; }
    if(!(ppMEMs = LocalAlloc(0, cTlbs * sizeof(PMEM_SCATTER)))) { goto fail; }
    if(!(ppObMEMs = LocalAlloc(0, cTlbs * sizeof(PVMMOB_CACHE_MEM)))) { goto fail; }
    while((cTlbs = min(0x2000, ObSet_Size(pTlbPrefetch)))) {   // protect cache bleed -> max 0x2000 pages/round
        for(i = 0; i < cTlbs; i++) {
            ppObMEMs[i] = VmmCacheReserve(VMM_CACHE_TAG_TLB);
            ppMEMs[i] = &ppObMEMs[i]->h;
            ppMEMs[i]->qwA = ObSet_Pop(pTlbPrefetch);
        }
        LcReadScatter(ctxMain->hLC, cTlbs, ppMEMs);
        for(i = 0; i < cTlbs; i++) {
            if(ppMEMs[i]->f && !VmmTlbPageTableVerify(ppMEMs[i]->pb, ppMEMs[i]->qwA, FALSE)) {
                ppMEMs[i]->f = FALSE;  // "fail" invalid page table read
            }
            VmmCacheReserveReturn(ppObMEMs[i]);
        }
    }
fail:
    LocalFree(ppMEMs);
    LocalFree(ppObMEMs);
}

/*
* Prefetch a set of addresses contained in pPrefetchPages into the cache. This
* is useful when reading data from somewhat known addresses over higher latency
* connections.
* NB! pPrefetchPages must not be updated/altered during the function call.
* -- pProcess
* -- pPrefetchPages
* -- flags
*/
VOID VmmCachePrefetchPages(_In_opt_ PVMM_PROCESS pProcess, _In_opt_ POB_SET pPrefetchPages, _In_ QWORD flags)
{
    QWORD qwA = 0;
    DWORD cPages, iMEM = 0;
    PPMEM_SCATTER ppMEMs = NULL;
    cPages = ObSet_Size(pPrefetchPages);
    if(!cPages || (ctxVmm->flags & VMM_FLAG_NOCACHE)) { return; }
    if(!LcAllocScatter1(cPages, &ppMEMs)) { return; }
    while((qwA = ObSet_GetNext(pPrefetchPages, qwA))) {
        ppMEMs[iMEM++]->qwA = qwA & ~0xfff;
    }
    if(pProcess) {
        VmmReadScatterVirtual(pProcess, ppMEMs, iMEM, flags | VMM_FLAG_CACHE_RECENT_ONLY);
    } else {
        VmmReadScatterPhysical(ppMEMs, iMEM, flags | VMM_FLAG_CACHE_RECENT_ONLY);
    }
    LcMemFree(ppMEMs);
}

/*
* Prefetch a set of addresses. This is useful when reading data from somewhat
* known addresses over higher latency connections.
* -- pProcess
* -- cAddresses
* -- ... = variable list of total cAddresses of addresses of type QWORD.
*/
VOID VmmCachePrefetchPages2(_In_opt_ PVMM_PROCESS pProcess, _In_ DWORD cAddresses, ...)
{
    va_list arguments;
    POB_SET pObSet = NULL;
    if(!cAddresses || !(pObSet = ObSet_New())) { return; }
    va_start(arguments, cAddresses);
    while(cAddresses) {
        ObSet_Push(pObSet, va_arg(arguments, QWORD) & ~0xfff);
        cAddresses--;
    }
    va_end(arguments);
    VmmCachePrefetchPages(pProcess, pObSet, 0);
    Ob_DECREF(pObSet);
}

/*
* Prefetch a set of addresses contained in pPrefetchPagesNonPageAligned into
* the cache by first converting them to page aligned pages. This is used when
* reading data from somewhat known addresses over higher latency connections.
* NB! pPrefetchPagesNonPageAligned must not be altered during the function call.
* -- pProcess
* -- pPrefetchPagesNonPageAligned
* -- cb
* -- flags
*/
VOID VmmCachePrefetchPages3(_In_opt_ PVMM_PROCESS pProcess, _In_opt_ POB_SET pPrefetchPagesNonPageAligned, _In_ DWORD cb, _In_ QWORD flags)
{
    QWORD qwA = 0;
    POB_SET pObSetAlign;
    if(!cb || !pPrefetchPagesNonPageAligned) { return; }
    if(0 == ObSet_Size(pPrefetchPagesNonPageAligned)) { return; }
    if(!(pObSetAlign = ObSet_New())) { return; }
    while((qwA = ObSet_GetNext(pPrefetchPagesNonPageAligned, qwA))) {
        ObSet_Push_PageAlign(pObSetAlign, qwA, cb);
    }
    VmmCachePrefetchPages(pProcess, pObSetAlign, flags);
    Ob_DECREF(pObSetAlign);
}

/*
* Prefetch an array of optionally non-page aligned addresses. This is useful
* when reading data from somewhat known addresses over higher latency connections.
* -- pProcess
* -- cAddresses
* -- pqwAddresses = array of addresses to fetch
* -- cb
* -- flags
*/
VOID VmmCachePrefetchPages4(_In_opt_ PVMM_PROCESS pProcess, _In_ DWORD cAddresses, _In_ PQWORD pqwAddresses, _In_ DWORD cb, _In_ QWORD flags)
{
    POB_SET pObSet = NULL;
    if(!cAddresses || !(pObSet = ObSet_New())) { return; }
    while(cAddresses) {
        cAddresses--;
        if(pqwAddresses[cAddresses]) {
            ObSet_Push_PageAlign(pObSet, pqwAddresses[cAddresses], cb);
        }
    }
    VmmCachePrefetchPages(pProcess, pObSet, 0);
    Ob_DECREF(pObSet);
}

/*
* Prefetch memory of optionally non-page aligned addresses which are derived
* from pmPrefetchObjects by the pfnFilter filter function.
* -- pProcess
* -- pmPrefetch = map of objects.
* -- cb
* -- flags
* -- pfnFilter = filter as required by ObMap_FilterSet function.
* -- return = at least one object is found to be prefetched into cache.
*/
BOOL VmmCachePrefetchPages5(_In_opt_ PVMM_PROCESS pProcess, _In_opt_ POB_MAP pmPrefetch, _In_ DWORD cb, _In_ QWORD flags, _In_ VOID(*pfnFilter)(_In_ QWORD k, _In_ PVOID v, _Inout_ POB_SET ps))
{
    POB_SET psObCache = ObMap_FilterSet(pmPrefetch, pfnFilter);
    BOOL fResult = ObSet_Size(psObCache) > 0;
    VmmCachePrefetchPages3(pProcess, psObCache, cb, flags);
    Ob_DECREF(psObCache);
    return fResult;
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

#ifdef _WIN32
VOID VmmProcess_TokenTryEnsure(_In_ PVMMOB_PROCESS_TABLE pt)
{
    BOOL f, f32 = ctxVmm->f32;
    DWORD j, i = 0, iM, cbHdr, cb;
    QWORD va, *pva = NULL;
    BYTE pb[0x1000];
    PVMM_PROCESS *ppProcess = NULL, pObSystemProcess = NULL;
    PVMM_OFFSET_EPROCESS oep = &ctxVmm->offset.EPROCESS;
    f = oep->opt.TOKEN_TokenId &&                                               // token offsets/symbols initialized.
        (pObSystemProcess = VmmProcessGet(4)) &&
        (pva = LocalAlloc(LMEM_ZEROINIT, pt->c * sizeof(QWORD))) &&
        (ppProcess = LocalAlloc(LMEM_ZEROINIT, pt->c * sizeof(PVMM_PROCESS)));
    if(!f) { goto fail; }
    cbHdr = f32 ? 0x2c : 0x5c;
    cb = cbHdr + oep->opt.TOKEN_UserAndGroups + 8;
    // 1: Get Process and Token VA:
    iM = pt->_iFLink;
    while(iM && i < pt->c) {
        if((ppProcess[i] = pt->_M[iM]) && !ppProcess[i]->win.TOKEN.fInitialized) {
            va = VMM_PTR_OFFSET(f32, ppProcess[i]->win.EPROCESS.pb, oep->opt.Token) & (f32 ? ~0x7 : ~0xf);
            if(VMM_KADDR(va)) {
                ppProcess[i]->win.TOKEN.va = va;
                pva[i] = va - cbHdr; // adjust for _OBJECT_HEADER and Pool Header
            }
        }
        iM = pt->_iFLinkM[iM];
        i++;
    }
    // 2: Read Token:
    VmmCachePrefetchPages4(pObSystemProcess, (DWORD)pt->c, pva, cb, 0);
    for(i = 0; i < pt->c; i++) {
        f = pva[i] && VmmRead2(pObSystemProcess, pva[i], pb, cb, VMM_FLAG_FORCECACHE_READ) &&
            (pva[i] = VMM_PTR_OFFSET(f32, pb, cb - 8)) &&
            VMM_KADDR(pva[i]);
        if(f) {
            for(j = 0, f = FALSE; !f && (j < cbHdr); j += (f32 ? 0x08 : 0x10)) {
                f = VMM_POOLTAG_SHORT(*(PDWORD)(pb + j), 'Toke');
            }
            if(f) {
                ppProcess[i]->win.TOKEN.qwLUID = *(PQWORD)(pb + cbHdr + ctxVmm->offset.EPROCESS.opt.TOKEN_TokenId);
                ppProcess[i]->win.TOKEN.dwSessionId = *(PDWORD)(pb + cbHdr + ctxVmm->offset.EPROCESS.opt.TOKEN_SessionId);
            }
        }
        if(!f) { pva[i] = 0; }
    }
    // 3: Read SID ptr:
    VmmCachePrefetchPages4(pObSystemProcess, (DWORD)pt->c, pva, 8, 0);
    for(i = 0; i < pt->c; i++) {
        f = pva[i] && VmmRead2(pObSystemProcess, pva[i], pb, 8, VMM_FLAG_FORCECACHE_READ) &&
            (pva[i] = VMM_PTR_OFFSET(f32, pb, 0)) &&
            VMM_KADDR(pva[i]);
        if(!f) { pva[i] = 0; };
    }
    // 4: Get SID:
    VmmCachePrefetchPages4(pObSystemProcess, (DWORD)pt->c, pva, SECURITY_MAX_SID_SIZE, 0);
    for(i = 0; i < pt->c; i++) {
        if(!ppProcess[i]) { continue; }
        ppProcess[i]->win.TOKEN.fSID =
            (va = pva[i]) &&
            VmmRead2(pObSystemProcess, va, (PBYTE)&ppProcess[i]->win.TOKEN.pbSID, SECURITY_MAX_SID_SIZE, VMM_FLAG_FORCECACHE_READ) &&
            IsValidSid(&ppProcess[i]->win.TOKEN.SID);
    }
    // 5: finish up:
    for(i = 0; i < pt->c; i++) {
        if(!ppProcess[i]) { continue; }
        ppProcess[i]->win.TOKEN.fSID =
            ppProcess[i]->win.TOKEN.fSID &&
            ConvertSidToStringSidA(&ppProcess[i]->win.TOKEN.SID, &ppProcess[i]->win.TOKEN.szSID) &&
            (ppProcess[i]->win.TOKEN.dwHashSID = Util_HashStringA(ppProcess[i]->win.TOKEN.szSID));
        ppProcess[i]->win.TOKEN.fInitialized = TRUE;
    }
fail:
    LocalFree(pva);
    LocalFree(ppProcess);
    Ob_DECREF(pObSystemProcess);
}
#endif /* _WIN32 */
#ifdef LINUX
VOID VmmProcess_TokenTryEnsure(_In_ PVMMOB_PROCESS_TABLE pt) { return; }
#endif /* LINUX */

/*
* Global Synchronization/Lock of VmmProcess_TokenTryEnsure()
* -- pt
* -- pProcess
*/
VOID VmmProcess_TokenTryEnsureLock(_In_ PVMMOB_PROCESS_TABLE pt, _In_ PVMM_PROCESS pProcess)
{
    if(pProcess->win.TOKEN.fInitialized) { return; }
    EnterCriticalSection(&ctxVmm->LockMaster);
    if(!pProcess->win.TOKEN.fInitialized) {
        VmmProcess_TokenTryEnsure(pt);
    }
    LeaveCriticalSection(&ctxVmm->LockMaster);
}

/*
* Retrieve a process for a given PID and optional PVMMOB_PROCESS_TABLE.
* CALLER DECREF: return
* -- pt
* -- dwPID
* -- flags = 0 (recommended) or VMM_FLAG_PROCESS_TOKEN.
* -- return
*/
PVMM_PROCESS VmmProcessGetEx(_In_opt_ PVMMOB_PROCESS_TABLE pt, _In_ DWORD dwPID, _In_ QWORD flags)
{
    BOOL fToken = ((flags | ctxVmm->flags) & VMM_FLAG_PROCESS_TOKEN);
    PVMM_PROCESS pObProcess, pObProcessClone;
    PVMMOB_PROCESS_TABLE pObTable;
    DWORD i, iStart;
    if(!pt) {
        pObTable = (PVMMOB_PROCESS_TABLE)ObContainer_GetOb(ctxVmm->pObCPROC);
        pObProcess = VmmProcessGetEx(pObTable, dwPID, flags);
        Ob_DECREF(pObTable);
        return pObProcess;
    }
    i = iStart = dwPID % VMM_PROCESSTABLE_ENTRIES_MAX;
    while(TRUE) {
        if(!pt->_M[i]) { goto fail; }
        if(pt->_M[i]->dwPID == dwPID) {
            pObProcess = (PVMM_PROCESS)Ob_INCREF(pt->_M[i]);
            if(pObProcess && fToken && !pObProcess->win.TOKEN.fInitialized) { VmmProcess_TokenTryEnsureLock(pt, pObProcess); }
            return pObProcess;
        }
        if(++i == VMM_PROCESSTABLE_ENTRIES_MAX) { i = 0; }
        if(i == iStart) { goto fail; }
    }
fail:
    if(dwPID & VMM_PID_PROCESS_CLONE_WITH_KERNELMEMORY) {
        if((pObProcess = VmmProcessGetEx(pt, dwPID & ~VMM_PID_PROCESS_CLONE_WITH_KERNELMEMORY, flags))) {
            if((pObProcessClone = VmmProcessClone(pObProcess))) {
                pObProcessClone->fUserOnly = FALSE;
            }
            Ob_DECREF(pObProcess);
            return pObProcessClone;
        }
    }
    return NULL;
}

/*
* Retrieve a process for a given PID.
* CALLER DECREF: return
* -- dwPID
* -- return = a process struct, or NULL if not found.
*/
inline PVMM_PROCESS VmmProcessGet(_In_ DWORD dwPID)
{
    return VmmProcessGetEx(NULL, dwPID, 0);
}

/*
* Retrieve the next process given a process and a process table. This may be
* useful when iterating over a process list. NB! Listing of next item may fail
* prematurely if the previous process is terminated while having a reference
* to it.
* FUNCTION DECREF: pProcess
* CALLER DECREF: return
* -- pt
* -- pProcess = a process struct, or NULL if first.
*    NB! function DECREF's  pProcess and must not be used after call!
* -- flags = 0 (recommended) or VMM_FLAG_PROCESS_[TOKEN|SHOW_TERMINATED].
* -- return = a process struct, or NULL if not found.
*/
PVMM_PROCESS VmmProcessGetNextEx(_In_opt_ PVMMOB_PROCESS_TABLE pt, _In_opt_ PVMM_PROCESS pProcess, _In_ QWORD flags)
{
    BOOL fToken = ((flags | ctxVmm->flags) & VMM_FLAG_PROCESS_TOKEN);
    BOOL fShowTerminated = ((flags | ctxVmm->flags) & VMM_FLAG_PROCESS_SHOW_TERMINATED);
    PVMM_PROCESS pProcessNew;
    DWORD i, iStart;
    if(!pt) {
        pt = (PVMMOB_PROCESS_TABLE)ObContainer_GetOb(ctxVmm->pObCPROC);
        if(!pt) { goto fail; }
        pProcessNew = VmmProcessGetNextEx(pt, pProcess, flags);
        Ob_DECREF(pt);
        return pProcessNew;
    }
restart:
    if(!pProcess) {
        i = pt->_iFLink;
        if(!pt->_M[i]) { goto fail; }
        pProcessNew = (PVMM_PROCESS)Ob_INCREF(pt->_M[i]);
        Ob_DECREF(pProcess);
        pProcess = pProcessNew;
        if(pProcess && pProcess->dwState && !fShowTerminated) { goto restart; }
        if(pProcess && fToken && !pProcess->win.TOKEN.fInitialized) { VmmProcess_TokenTryEnsureLock(pt, pProcess); }
        return pProcess;
    }
    i = iStart = pProcess->dwPID % VMM_PROCESSTABLE_ENTRIES_MAX;
    while(TRUE) {
        if(!pt->_M[i]) { goto fail; }
        if(pt->_M[i]->dwPID == pProcess->dwPID) {
            // current process -> retrieve next!
            i = pt->_iFLinkM[i];
            if(!pt->_M[i]) { goto fail; }
            pProcessNew = (PVMM_PROCESS)Ob_INCREF(pt->_M[i]);
            Ob_DECREF(pProcess);
            pProcess = pProcessNew;
            if(pProcess && pProcess->dwState && !fShowTerminated) { goto restart; }
            if(pProcess && fToken && !pProcess->win.TOKEN.fInitialized) { VmmProcess_TokenTryEnsureLock(pt, pProcess); }
            return pProcess;
        }
        if(++i == VMM_PROCESSTABLE_ENTRIES_MAX) { i = 0; }
        if(i == iStart) { goto fail; }
    }
fail:
    Ob_DECREF(pProcess);
    return NULL;
}

/*
* Retrieve the next process given a process. This may be useful when iterating
* over a process list. NB! Listing of next item may fail prematurely if the
* previous process is terminated while having a reference to it.
* FUNCTION DECREF: pProcess
* CALLER DECREF: return
* -- pProcess = a process struct, or NULL if first.
*    NB! function DECREF's  pProcess and must not be used after call!
* -- flags = 0 (recommended) or VMM_FLAG_PROCESS_[TOKEN|SHOW_TERMINATED]
* -- return = a process struct, or NULL if not found.
*/
PVMM_PROCESS VmmProcessGetNext(_In_opt_ PVMM_PROCESS pProcess, _In_ QWORD flags)
{
    return VmmProcessGetNextEx(NULL, pProcess, flags);
}

/*
* Object manager callback before 'static process' object cleanup
* decrease refcount of any internal objects.
*/
VOID VmmProcessStatic_CloseObCallback(_In_ PVOID pVmmOb)
{
    PVMMOB_PROCESS_PERSISTENT pProcessStatic = (PVMMOB_PROCESS_PERSISTENT)pVmmOb;
    Ob_DECREF_NULL(&pProcessStatic->pObCMapVadPrefetch);
    Ob_DECREF_NULL(&pProcessStatic->pObCLdrModulesPrefetch32);
    Ob_DECREF_NULL(&pProcessStatic->pObCLdrModulesPrefetch64);
    Ob_DECREF_NULL(&pProcessStatic->pObCLdrModulesInjected);
    Ob_DECREF_NULL(&pProcessStatic->pObCMapThreadPrefetch);
    LocalFree(pProcessStatic->uszPathKernel);
    LocalFree(pProcessStatic->UserProcessParams.uszCommandLine);
    LocalFree(pProcessStatic->UserProcessParams.uszImagePathName);
}

/*
* Object manager callback before 'static process' object cleanup
* decrease refcount of any internal objects.
*/
VOID VmmProcessStatic_Initialize(_In_ PVMM_PROCESS pProcess)
{
    EnterCriticalSection(&pProcess->LockUpdate);
    Ob_DECREF_NULL(&pProcess->pObPersistent);
    pProcess->pObPersistent = Ob_Alloc(OB_TAG_VMM_PROCESS_PERSISTENT, LMEM_ZEROINIT, sizeof(VMMOB_PROCESS_PERSISTENT), VmmProcessStatic_CloseObCallback, NULL);
    if(pProcess->pObPersistent) {
        pProcess->pObPersistent->pObCMapVadPrefetch = ObContainer_New();
        pProcess->pObPersistent->pObCLdrModulesPrefetch32 = ObContainer_New();
        pProcess->pObPersistent->pObCLdrModulesPrefetch64 = ObContainer_New();
        pProcess->pObPersistent->pObCLdrModulesInjected = ObContainer_New();
        pProcess->pObPersistent->pObCMapThreadPrefetch = ObContainer_New();
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
    Ob_DECREF(pProcess->Map.pObPte);
    Ob_DECREF(pProcess->Map.pObVad);
    Ob_DECREF(pProcess->Map.pObModule);
    Ob_DECREF(pProcess->Map.pObUnloadedModule);
    Ob_DECREF(pProcess->Map.pObHeap);
    Ob_DECREF(pProcess->Map.pObThread);
    Ob_DECREF(pProcess->Map.pObHandle);
    Ob_DECREF(pProcess->Map.pObEvil);
    Ob_DECREF(pProcess->pObPersistent);
    LocalFree(pProcess->win.TOKEN.szSID);
    // plugin cleanup below
    Ob_DECREF(pProcess->Plugin.pObCLdrModulesDisplayCache);
    Ob_DECREF(pProcess->Plugin.pObCPeDumpDirCache);
    Ob_DECREF(pProcess->Plugin.pObCPhys2Virt);
    // delete lock
    DeleteCriticalSection(&pProcess->LockUpdate);
    DeleteCriticalSection(&pProcess->LockPlugin);
    DeleteCriticalSection(&pProcess->Map.LockUpdateThreadExtendedInfo);
    DeleteCriticalSection(&pProcess->Map.LockUpdateMapEvil);
}

VOID VmmProcessClone_CloseObCallback(_In_ PVOID pVmmOb)
{
    PVMM_PROCESS pProcessClone = (PVMM_PROCESS)pVmmOb;
    // decref clone parent
    Ob_DECREF(pProcessClone->pObProcessCloneParent);
    // delete lock
    DeleteCriticalSection(&pProcessClone->LockUpdate);
    DeleteCriticalSection(&pProcessClone->LockPlugin);
    DeleteCriticalSection(&pProcessClone->Map.LockUpdateThreadExtendedInfo);
    DeleteCriticalSection(&pProcessClone->Map.LockUpdateMapEvil);
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
    Ob_DECREF_NULL(&pt->pObCNewPROC);
    // DECREF all pProcess in table
    iProcess = pt->_iFLink;
    pProcess = pt->_M[iProcess];
    while(pProcess) {
        Ob_DECREF(pProcess);
        iProcess = pt->_iFLinkM[iProcess];
        pProcess = pt->_M[iProcess];
        if(!pProcess || iProcess == pt->_iFLink) { break; }
    }
}

/*
* Clone an original process entry creating a shallow clone. The user of this
* shallow clone may use it to set the fUserOnly flag to FALSE on an otherwise
* user-mode process to be able to access the whole kernel space for a standard
* user-mode process.
* NB! USE WITH EXTREME CARE - MAY CRASH VMM IF USED MORE GENERALLY!
* CALLER DECREF: return
* -- pProcess
* -- return
*/
PVMM_PROCESS VmmProcessClone(_In_ PVMM_PROCESS pProcess)
{
    PVMM_PROCESS pObProcessClone;
    if(pProcess->pObProcessCloneParent) { return NULL; }
    pObProcessClone = (PVMM_PROCESS)Ob_Alloc(OB_TAG_VMM_PROCESS_CLONE, LMEM_ZEROINIT, sizeof(VMM_PROCESS), VmmProcessClone_CloseObCallback, NULL);
    if(!pObProcessClone) { return NULL; }
    memcpy((PBYTE)pObProcessClone + sizeof(OB), (PBYTE)pProcess + sizeof(OB), pProcess->ObHdr.cbData);
    pObProcessClone->pObProcessCloneParent = Ob_INCREF(pProcess);
    InitializeCriticalSection(&pObProcessClone->LockUpdate);
    InitializeCriticalSection(&pObProcessClone->LockPlugin);
    InitializeCriticalSection(&pObProcessClone->Map.LockUpdateThreadExtendedInfo);
    InitializeCriticalSection(&pObProcessClone->Map.LockUpdateMapEvil);
    return pObProcessClone;
}

/*
* Create a new process object. New process object are created in a separate
* data structure and won't become visible to the "Process" functions until
* after the VmmProcessCreateFinish have been called.
* CALLER DECREF: return
* -- fTotalRefresh = create a completely new entry - i.e. do not copy any form
*                    of data from the old entry such as module and memory maps.
* -- dwPID
* -- dwPPID = parent PID (if any)
* -- dwState
* -- paDTB
* -- paDTB_UserOpt
* -- szName
* -- fUserOnly = user mode process (hide supervisor pages from view)
* -- pbEPROCESS
* -- cbEPROCESS
* -- return
*/
PVMM_PROCESS VmmProcessCreateEntry(_In_ BOOL fTotalRefresh, _In_ DWORD dwPID, _In_ DWORD dwPPID, _In_ DWORD dwState, _In_ QWORD paDTB, _In_ QWORD paDTB_UserOpt, _In_ CHAR szName[16], _In_ BOOL fUserOnly, _In_reads_opt_(cbEPROCESS) PBYTE pbEPROCESS, _In_ DWORD cbEPROCESS)
{
    PVMMOB_PROCESS_TABLE ptOld = NULL, ptNew = NULL;
    QWORD i, iStart, cEmpty = 0, cValid = 0;
    PVMM_PROCESS pProcess = NULL, pProcessOld = NULL;
    PVMMOB_CACHE_MEM pObDTB = NULL;
    BOOL result;
    // 1: Sanity check DTB
    if(dwState == 0) {
        pObDTB = VmmTlbGetPageTable(paDTB & ~0xfff, FALSE);
        if(!pObDTB) { goto fail; }
        result = VmmTlbPageTableVerify(pObDTB->h.pb, paDTB, (ctxVmm->tpSystem == VMM_SYSTEM_WINDOWS_X64));
        Ob_DECREF(pObDTB);
        if(!result) { goto fail; }
    }
    // 2: Allocate new 'Process Table' (if not already existing)
    ptOld = (PVMMOB_PROCESS_TABLE)ObContainer_GetOb(ctxVmm->pObCPROC);
    if(!ptOld) { goto fail; }
    ptNew = (PVMMOB_PROCESS_TABLE)ObContainer_GetOb(ptOld->pObCNewPROC);
    if(!ptNew) {
        ptNew = (PVMMOB_PROCESS_TABLE)Ob_Alloc(OB_TAG_VMM_PROCESSTABLE, LMEM_ZEROINIT, sizeof(VMMOB_PROCESS_TABLE), VmmProcessTable_CloseObCallback, NULL);
        if(!ptNew) { goto fail; }
        ptNew->pObCNewPROC = ObContainer_New();
        ObContainer_SetOb(ptOld->pObCNewPROC, ptNew);
    }
    // 3: Sanity check - process to create not already in 'new' table.
    pProcess = VmmProcessGetEx(ptNew, dwPID, 0);
    if(pProcess) { goto fail; }
    // 4: Prepare existing item, or create new item, for new PID
    if(!fTotalRefresh) {
        pProcess = VmmProcessGetEx(ptOld, dwPID, 0);
    }
    if(!pProcess) {
        pProcess = (PVMM_PROCESS)Ob_Alloc(OB_TAG_VMM_PROCESS, LMEM_ZEROINIT, sizeof(VMM_PROCESS), VmmProcess_CloseObCallback, NULL);
        if(!pProcess) { goto fail; }
        InitializeCriticalSectionAndSpinCount(&pProcess->LockUpdate, 4096);
        InitializeCriticalSection(&pProcess->LockPlugin);
        InitializeCriticalSection(&pProcess->Map.LockUpdateThreadExtendedInfo);
        InitializeCriticalSection(&pProcess->Map.LockUpdateMapEvil);
        memcpy(pProcess->szName, szName, 16);
        pProcess->szName[15] = 0;
        pProcess->dwPID = dwPID;
        pProcess->dwPPID = dwPPID;
        pProcess->dwState = dwState;
        pProcess->paDTB = paDTB;
        pProcess->paDTB_UserOpt = paDTB_UserOpt;
        pProcess->fUserOnly = fUserOnly;
        pProcess->fTlbSpiderDone = pProcess->fTlbSpiderDone;
        pProcess->Plugin.pObCLdrModulesDisplayCache = ObContainer_New();
        pProcess->Plugin.pObCPeDumpDirCache = ObContainer_New();
        pProcess->Plugin.pObCPhys2Virt = ObContainer_New();
        if(pbEPROCESS && cbEPROCESS) {
            pProcess->win.EPROCESS.cb = min(sizeof(pProcess->win.EPROCESS.pb), cbEPROCESS);
            memcpy(pProcess->win.EPROCESS.pb, pbEPROCESS, pProcess->win.EPROCESS.cb);
        }
        // attach pre-existing static process info entry or create new
        pProcessOld = VmmProcessGet(dwPID);
        if(pProcessOld) {
            pProcess->pObPersistent = (PVMMOB_PROCESS_PERSISTENT)Ob_INCREF(pProcessOld->pObPersistent);
        } else {
            VmmProcessStatic_Initialize(pProcess);
        }
        Ob_DECREF(pProcessOld);
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
            ptNew->cActive += (pProcess->dwState == 0) ? 1 : 0;
            Ob_DECREF(ptOld);
            Ob_DECREF(ptNew);
            // pProcess already "consumed" by table insertion so increase before returning ... 
            return (PVMM_PROCESS)Ob_INCREF(pProcess);
        }
        if(++i == VMM_PROCESSTABLE_ENTRIES_MAX) { i = 0; }
        if(i == iStart) { goto fail; }
    }
fail:
    Ob_DECREF(pProcess);
    Ob_DECREF(ptOld);
    Ob_DECREF(ptNew);
    return NULL;
}

/*
* Activate the pending, not yet active, processes added by VmmProcessCreateEntry.
* This will also clear any previous processes.
*/
VOID VmmProcessCreateFinish()
{
    PVMMOB_PROCESS_TABLE ptNew, ptOld;
    if(!(ptOld = ObContainer_GetOb(ctxVmm->pObCPROC))) {
        return;
    }
    if(!(ptNew = ObContainer_GetOb(ptOld->pObCNewPROC))) {
        Ob_DECREF(ptOld);
        return;
    }
    // Replace "existing" old process table with new.
    ObContainer_SetOb(ctxVmm->pObCPROC, ptNew);
    Ob_DECREF(ptNew);
    Ob_DECREF(ptOld);
}

/*
* Clear the TLB spider flag in all process objects.
*/
VOID VmmProcessTlbClear()
{
    PVMMOB_PROCESS_TABLE pt = (PVMMOB_PROCESS_TABLE)ObContainer_GetOb(ctxVmm->pObCPROC);
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
    Ob_DECREF(pt);
}

/*
* Query process for its creation time.
* -- pProcess
* -- return = time as FILETIME or 0 on error.
*/
QWORD VmmProcess_GetCreateTimeOpt(_In_opt_ PVMM_PROCESS pProcess)
{
    return (pProcess && ctxVmm->offset.EPROCESS.opt.CreateTime) ? *(PQWORD)(pProcess->win.EPROCESS.pb + ctxVmm->offset.EPROCESS.opt.CreateTime) : 0;
}

/*
* Query process for its exit time.
* -- pProcess
* -- return = time as FILETIME or 0 on error.
*/
QWORD VmmProcess_GetExitTimeOpt(_In_opt_ PVMM_PROCESS pProcess)
{
    return (pProcess && ctxVmm->offset.EPROCESS.opt.ExitTime) ? *(PQWORD)(pProcess->win.EPROCESS.pb + ctxVmm->offset.EPROCESS.opt.ExitTime) : 0;
}

/*
* List the PIDs and put them into the supplied table.
* -- pPIDs = user allocated DWORD array to receive result, or NULL.
* -- pcPIDs = ptr to number of DWORDs in pPIDs on entry - number of PIDs in system on exit.
* -- flags = 0 (recommended) or VMM_FLAG_PROCESS_SHOW_TERMINATED (_only_ if default setting in ctxVmm->flags should be overridden)
*/
VOID VmmProcessListPIDs(_Out_writes_opt_(*pcPIDs) PDWORD pPIDs, _Inout_ PSIZE_T pcPIDs, _In_ QWORD flags)
{
    PVMMOB_PROCESS_TABLE pt = (PVMMOB_PROCESS_TABLE)ObContainer_GetOb(ctxVmm->pObCPROC);
    BOOL fShowTerminated = ((flags | ctxVmm->flags) & VMM_FLAG_PROCESS_SHOW_TERMINATED);
    PVMM_PROCESS pProcess;
    WORD iProcess;
    DWORD i = 0;
    if(!pPIDs) {
        *pcPIDs = fShowTerminated ? pt->c : pt->cActive;
        Ob_DECREF(pt);
        return;
    }
    if(*pcPIDs < (fShowTerminated ? pt->c : pt->cActive)) {
        *pcPIDs = 0;
        Ob_DECREF(pt);
        return;
    }
    // copy all PIDs
    iProcess = pt->_iFLink;
    pProcess = pt->_M[iProcess];
    while(pProcess) {
        if(!pProcess->dwState || fShowTerminated) {
            *(pPIDs + i) = pProcess->dwPID;
            i++;
        }
        iProcess = pt->_iFLinkM[iProcess];
        pProcess = pt->_M[iProcess];
        if(!pProcess || (iProcess == pt->_iFLink)) { break; }
    }
    *pcPIDs = i;
    Ob_DECREF(pt);
}

/*
* Create the initial process table at startup.
*/
BOOL VmmProcessTableCreateInitial()
{
    PVMMOB_PROCESS_TABLE pt = (PVMMOB_PROCESS_TABLE)Ob_Alloc(OB_TAG_VMM_PROCESSTABLE, LMEM_ZEROINIT, sizeof(VMMOB_PROCESS_TABLE), VmmProcessTable_CloseObCallback, NULL);
    if(!pt) { return FALSE; }
    pt->pObCNewPROC = ObContainer_New();
    ctxVmm->pObCPROC = ObContainer_New();
    ObContainer_SetOb(ctxVmm->pObCPROC, pt);
    Ob_DECREF(pt);
    return TRUE;
}

// ----------------------------------------------------------------------------
// WORK (THREAD POOL) API:
// The 'Work' thread pool contain by default 32 threads which is waiting to
// receive work scheduled by calling the VmmWork function.
// ----------------------------------------------------------------------------

typedef struct tdVMMWORK_UNIT {
    LPTHREAD_START_ROUTINE pfn;     // function to call
    PVOID ctx;                      // optional function parameter
    HANDLE hEventFinish;            // optional event to set when upon work completion
} VMMWORK_UNIT, *PVMMWORK_UNIT;

typedef struct tdVMMWORK_THREAD_CONTEXT {
    HANDLE hEventWakeup;
    HANDLE hThread;
} VMMWORK_THREAD_CONTEXT, *PVMMWORK_THREAD_CONTEXT;

DWORD VmmWork_MainWorkerLoop_ThreadProc(PVMMWORK_THREAD_CONTEXT ctx)
{
    PVMMWORK_UNIT pu;
    while(ctxVmm->Work.fEnabled) {
        if((pu = (PVMMWORK_UNIT)ObSet_Pop(ctxVmm->Work.psUnit))) {
            pu->pfn(pu->ctx);
            if(pu->hEventFinish) {
                SetEvent(pu->hEventFinish);
            }
            LocalFree(pu);
        } else {
            ResetEvent(ctx->hEventWakeup);
            ObSet_Push(ctxVmm->Work.psThreadAvail, (QWORD)ctx);
            WaitForSingleObject(ctx->hEventWakeup, INFINITE);
        }
    }
    ObSet_Remove(ctxVmm->Work.psThreadAll, (QWORD)ctx);
    CloseHandle(ctx->hEventWakeup);
    CloseHandle(ctx->hThread);
    LocalFree(ctx);
    return 1;
}

VOID VmmWork_Initialize()
{
    PVMMWORK_THREAD_CONTEXT p;
    ctxVmm->Work.fEnabled = TRUE;
    ctxVmm->Work.psUnit = ObSet_New();
    ctxVmm->Work.psThreadAll = ObSet_New();
    ctxVmm->Work.psThreadAvail = ObSet_New();
    while(ObSet_Size(ctxVmm->Work.psThreadAll) < VMM_WORK_THREADPOOL_NUM_THREADS) {
        if((p = LocalAlloc(LMEM_ZEROINIT, sizeof(VMMWORK_THREAD_CONTEXT)))) {
            p->hEventWakeup = CreateEvent(NULL, TRUE, FALSE, NULL);
            p->hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)VmmWork_MainWorkerLoop_ThreadProc, p, 0, NULL);
            ObSet_Push(ctxVmm->Work.psThreadAll, (QWORD)p);
        }
    }
}

VOID VmmWork_Close()
{
    PVMMWORK_UNIT pu;
    PVMMWORK_THREAD_CONTEXT pt = NULL;
    ctxVmm->Work.fEnabled = FALSE;
    while(ObSet_Size(ctxVmm->Work.psThreadAll)) {
        while((pt = (PVMMWORK_THREAD_CONTEXT)ObSet_GetNext(ctxVmm->Work.psThreadAll, (QWORD)pt))) {
            SetEvent(pt->hEventWakeup);
        }
        SwitchToThread();
    }
    while((pu = (PVMMWORK_UNIT)ObSet_Pop(ctxVmm->Work.psUnit))) {
        if(pu->hEventFinish) {
            SetEvent(pu->hEventFinish);
        }
        LocalFree(pu);
    }
    Ob_DECREF_NULL(&ctxVmm->Work.psUnit);
    Ob_DECREF_NULL(&ctxVmm->Work.psThreadAll);
    Ob_DECREF_NULL(&ctxVmm->Work.psThreadAvail);
}

VOID VmmWork(_In_ LPTHREAD_START_ROUTINE pfn, _In_opt_ PVOID ctx, _In_opt_ HANDLE hEventFinish)
{
    PVMMWORK_UNIT pu;
    PVMMWORK_THREAD_CONTEXT pt;
    if((pu = LocalAlloc(0, sizeof(VMMWORK_UNIT)))) {
        pu->pfn = pfn;
        pu->ctx = ctx;
        pu->hEventFinish = hEventFinish;
        ObSet_Push(ctxVmm->Work.psUnit, (QWORD)pu);
        if((pt = (PVMMWORK_THREAD_CONTEXT)ObSet_Pop(ctxVmm->Work.psThreadAvail))) {
            SetEvent(pt->hEventWakeup);
        }
    }
}

VOID VmmWorkWaitMultiple(_In_opt_ PVOID ctx, _In_ DWORD cWork, ...)
{
    DWORD i;
    va_list arguments;
    HANDLE hEventFinish[MAXIMUM_WAIT_OBJECTS] = { 0 };
    if(cWork > MAXIMUM_WAIT_OBJECTS) { return; }
    va_start(arguments, cWork);
    for(i = 0; i < cWork; i++) {
        hEventFinish[i] = CreateEvent(NULL, TRUE, FALSE, NULL);
        VmmWork(va_arg(arguments, LPTHREAD_START_ROUTINE), ctx, hEventFinish[i]);
    }
    va_end(arguments);
    WaitForMultipleObjects(cWork, hEventFinish, TRUE, INFINITE);
    for(i = 0; i < cWork; i++) {
        if(hEventFinish[i]) {
            CloseHandle(hEventFinish[i]);
        }
    }
}

// ----------------------------------------------------------------------------
// PROCESS PARALLELIZATION FUNCTIONALITY:
// ----------------------------------------------------------------------------

typedef struct tdVMM_PROCESS_ACTION_FOREACH {
    HANDLE hEventFinish;
    VOID(*pfnAction)(_In_ PVMM_PROCESS pProcess, _In_ PVOID ctx);
    PVOID ctxAction;
    DWORD cRemainingWork;       // set to dwPIDs count on entry and decremented as-goes - when zero FinishEvent is set.
    DWORD iPID;                 // set to dwPIDs count on entry and decremented as-goes
    DWORD dwPIDs[];
} VMM_PROCESS_ACTION_FOREACH, *PVMM_PROCESS_ACTION_FOREACH;

DWORD VmmProcessActionForeachParallel_ThreadProc(PVMM_PROCESS_ACTION_FOREACH ctx)
{
    PVMM_PROCESS pObProcess = VmmProcessGet(ctx->dwPIDs[InterlockedDecrement(&ctx->iPID)]);
    if(pObProcess) {
        ctx->pfnAction(pObProcess, ctx->ctxAction);
        Ob_DECREF(pObProcess);
    }
    if(0 == InterlockedDecrement(&ctx->cRemainingWork)) {
        SetEvent(ctx->hEventFinish);
    }
    return 1;
}

BOOL VmmProcessActionForeachParallel_CriteriaActiveOnly(_In_ PVMM_PROCESS pProcess, _In_opt_ PVOID ctx)
{
    return pProcess->dwState == 0;
}

BOOL VmmProcessActionForeachParallel_CriteriaActiveUserOnly(_In_ PVMM_PROCESS pProcess, _In_opt_ PVOID ctx)
{
    return (pProcess->dwState == 0) && pProcess->fUserOnly;
}

VOID VmmProcessActionForeachParallel(_In_opt_ PVOID ctxAction, _In_opt_ BOOL(*pfnCriteria)(_In_ PVMM_PROCESS pProcess, _In_opt_ PVOID ctx), _In_ VOID(*pfnAction)(_In_ PVMM_PROCESS pProcess, _In_opt_ PVOID ctx))
{
    DWORD i, cProcess;
    PVMM_PROCESS pObProcess = NULL;
    POB_SET pObProcessSelectedSet = NULL;
    PVMM_PROCESS_ACTION_FOREACH ctx = NULL;
    // 1: select processes to queue using criteria function
    if(!(pObProcessSelectedSet = ObSet_New())) { goto fail; }
    while((pObProcess = VmmProcessGetNext(pObProcess, VMM_FLAG_PROCESS_SHOW_TERMINATED))) {
        if(!pfnCriteria || pfnCriteria(pObProcess, ctx)) {
            ObSet_Push(pObProcessSelectedSet, pObProcess->dwPID);
        }
    }
    if(!(cProcess = ObSet_Size(pObProcessSelectedSet))) { goto fail; }
    // 2: set up context for worker function
    if(!(ctx = LocalAlloc(LMEM_ZEROINIT, sizeof(VMM_PROCESS_ACTION_FOREACH) + cProcess * sizeof(DWORD)))) { goto fail; }
    if(!(ctx->hEventFinish = CreateEvent(NULL, TRUE, FALSE, NULL))) { goto fail; }
    ctx->pfnAction = pfnAction;
    ctx->ctxAction = ctxAction;
    ctx->cRemainingWork = cProcess;
    ctx->iPID = cProcess;
    for(i = 0; i < cProcess; i++) {
        ctx->dwPIDs[i] = (DWORD)ObSet_Pop(pObProcessSelectedSet);
    }
    // 3: parallelize onto worker threads and wait for completion
    for(i = 0; i < cProcess; i++) {
        VmmWork((PTHREAD_START_ROUTINE)VmmProcessActionForeachParallel_ThreadProc, ctx, NULL);
    }
    WaitForSingleObject(ctx->hEventFinish, INFINITE);
fail:
    Ob_DECREF(pObProcessSelectedSet);
    if(ctx) {
        if(ctx->hEventFinish) {
            CloseHandle(ctx->hEventFinish);
        }
        LocalFree(ctx);
    }
}

// ----------------------------------------------------------------------------
// INTERNAL VMMU FUNCTIONALITY: VIRTUAL MEMORY ACCESS.
// ----------------------------------------------------------------------------

VOID VmmWriteScatterPhysical(_Inout_ PPMEM_SCATTER ppMEMsPhys, _In_ DWORD cpMEMsPhys)
{
    DWORD i;
    PMEM_SCATTER pMEM;
    LcWriteScatter(ctxMain->hLC, cpMEMsPhys, ppMEMsPhys);
    for(i = 0; i < cpMEMsPhys; i++) {
        pMEM = ppMEMsPhys[i];
        InterlockedIncrement64(&ctxVmm->stat.cPhysWrite);
        if(pMEM->f && MEM_SCATTER_ADDR_ISVALID(pMEM)) {
            VmmCacheInvalidate(pMEM->qwA & ~0xfff);
        }
    }
}

VOID VmmWriteScatterVirtual(_In_ PVMM_PROCESS pProcess, _Inout_ PPMEM_SCATTER ppMEMsVirt, _In_ DWORD cpMEMsVirt)
{
    DWORD i;
    QWORD qwPA_PTE = 0, qwPagedPA = 0;
    PMEM_SCATTER pMEM;
    BOOL fProcessMagicHandle = ((QWORD)pProcess >= 0xffffffff00000000);
    // 0: 'magic' process handle
    if(fProcessMagicHandle && !(pProcess = VmmProcessGet((DWORD)(0-(QWORD)pProcess)))) { return; }
    // 1: virt2phys translation
    for(i = 0; i < cpMEMsVirt; i++) {
        pMEM = ppMEMsVirt[i];
        MEM_SCATTER_STACK_PUSH(pMEM, pMEM->qwA);
        if(pMEM->f || (pMEM->qwA == -1)) {
            pMEM->qwA = -1;
            continue;
        }
        if(VmmVirt2Phys(pProcess, pMEM->qwA, &qwPA_PTE)) {
            pMEM->qwA = qwPA_PTE;
            continue;
        }
        // paged "read" also translate virtual -> physical for some
        // types of paged memory such as transition and prototype.
        ctxVmm->fnMemoryModel.pfnPagedRead(pProcess, pMEM->qwA, qwPA_PTE, NULL, &qwPagedPA, NULL, 0);
        pMEM->qwA = qwPagedPA ? qwPagedPA : -1;
    }
    // write to physical addresses
    VmmWriteScatterPhysical(ppMEMsVirt, cpMEMsVirt);
    for(i = 0; i < cpMEMsVirt; i++) {
        ppMEMsVirt[i]->qwA = MEM_SCATTER_STACK_POP(ppMEMsVirt[i]);
    }
    if(fProcessMagicHandle) { Ob_DECREF(pProcess); }
}

VOID VmmReadScatterPhysical(_Inout_ PPMEM_SCATTER ppMEMsPhys, _In_ DWORD cpMEMsPhys, _In_ QWORD flags)
{
    QWORD tp;   // 0 = normal, 1 = already read, 2 = cache hit, 3 = speculative read
    BOOL fCache, fCacheRecent;
    PMEM_SCATTER pMEM;
    DWORD i, c, cSpeculative;
    PVMMOB_CACHE_MEM pObCacheEntry, pObReservedMEM;
    PMEM_SCATTER ppMEMsSpeculative[0x18];
    PVMMOB_CACHE_MEM ppObCacheSpeculative[0x18];
    fCache = !(VMM_FLAG_NOCACHE & (flags | ctxVmm->flags));
    fCacheRecent = fCache && (VMM_FLAG_CACHE_RECENT_ONLY & flags);
    // 1: cache read
    if(fCache) {
        c = 0, cSpeculative = 0;
        for(i = 0; i < cpMEMsPhys; i++) {
            pMEM = ppMEMsPhys[i];
            if(pMEM->f) {
                // already valid -> skip
                MEM_SCATTER_STACK_PUSH(pMEM, 3);    // 3: already finished
                c++;
                continue;
            }
            // retrieve from cache (if found)
            if((pMEM->cb == 0x1000) && (pObCacheEntry = VmmCacheGetEx(VMM_CACHE_TAG_PHYS, pMEM->qwA, fCacheRecent))) {
                // in cache - copy data into requester and set as completed!
                MEM_SCATTER_STACK_PUSH(pMEM, 2);    // 2: cache read
                pMEM->f = TRUE;
                memcpy(pMEM->pb, pObCacheEntry->pb, 0x1000);
                Ob_DECREF(pObCacheEntry);
                InterlockedIncrement64(&ctxVmm->stat.cPhysCacheHit);
                c++;
                continue;
            }
            MEM_SCATTER_STACK_PUSH(pMEM, 1);        // 1: normal read
            // add to potential speculative read map if read is small enough...
            if(cSpeculative < 0x18) {
                ppMEMsSpeculative[cSpeculative++] = pMEM;
            }
        }
        // all found in cache _OR_ only cached reads allowed -> restore mem stack and return!
        if((c == cpMEMsPhys) || (VMM_FLAG_FORCECACHE_READ & flags)) {
            for(i = 0; i < cpMEMsPhys; i++) {
                MEM_SCATTER_STACK_POP(ppMEMsPhys[i]);
            }
            return;
        }
    }
    // 2: speculative future read if negligible performance loss
    if(fCache && cSpeculative && (cSpeculative < 0x18) && !(flags & VMMDLL_FLAG_NO_PREDICTIVE_READ)) {
        for(i = 0; i < cpMEMsPhys; i++) {
            pMEM = ppMEMsPhys[i];
            if(1 != MEM_SCATTER_STACK_PEEK(pMEM, 1)) {
                MEM_SCATTER_STACK_POP(pMEM);
            }
        }
        while(cSpeculative < 0x18) {
            if((ppObCacheSpeculative[cSpeculative] = VmmCacheReserve(VMM_CACHE_TAG_PHYS))) {
                pMEM = ppMEMsSpeculative[cSpeculative] = &ppObCacheSpeculative[cSpeculative]->h;
                MEM_SCATTER_STACK_PUSH(pMEM, 4);
                pMEM->f = FALSE;
                pMEM->qwA = ((QWORD)ppMEMsSpeculative[cSpeculative - 1]->qwA & ~0xfff) + 0x1000;
                cSpeculative++;
            }
        }
        ppMEMsPhys = ppMEMsSpeculative;
        cpMEMsPhys = cSpeculative;
    }
    // 3: read!
    LcReadScatter(ctxMain->hLC, cpMEMsPhys, ppMEMsPhys);
    // 4: cache put
    if(fCache) {
        for(i = 0; i < cpMEMsPhys; i++) {
            pMEM = ppMEMsPhys[i];
            tp = MEM_SCATTER_STACK_POP(pMEM);
            if(!(VMM_FLAG_NOCACHEPUT & flags)) {
                if(tp == 4) {   // 4 == speculative & backed by cache reserved
                    VmmCacheReserveReturn(ppObCacheSpeculative[i]);
                }
                if((tp == 1) && pMEM->f) { // 1 = normal read
                    if((pObReservedMEM = VmmCacheReserve(VMM_CACHE_TAG_PHYS))) {
                        pObReservedMEM->h.f = TRUE;
                        pObReservedMEM->h.qwA = pMEM->qwA;
                        memcpy(pObReservedMEM->h.pb, pMEM->pb, 0x1000);
                        VmmCacheReserveReturn(pObReservedMEM);
                    }
                }
            }
        }
    }
    // 5: statistics and read fail zero fixups (if required)
    for(i = 0; i < cpMEMsPhys; i++) {
        pMEM = ppMEMsPhys[i];
        if(pMEM->f) {
            // success
            InterlockedIncrement64(&ctxVmm->stat.cPhysReadSuccess);
        } else {
            // fail
            InterlockedIncrement64(&ctxVmm->stat.cPhysReadFail);
            if((flags & VMM_FLAG_ZEROPAD_ON_FAIL) && (pMEM->qwA < ctxMain->dev.paMax)) {
                ZeroMemory(pMEM->pb, pMEM->cb);
                pMEM->f = TRUE;
            }
        }
    }
}

VOID VmmReadScatterVirtual(_In_ PVMM_PROCESS pProcess, _Inout_updates_(cpMEMsVirt) PPMEM_SCATTER ppMEMsVirt, _In_ DWORD cpMEMsVirt, _In_ QWORD flags)
{
    // NB! the buffers pIoPA / ppMEMsPhys are used for both:
    //     - physical memory (grows from 0 upwards)
    //     - paged memory (grows from top downwards).
    BOOL fVirt2Phys;
    DWORD i = 0, iVA, iPA;
    QWORD qwPA, qwPagedPA = 0;
    BYTE pbBufferSmall[0x20 * (sizeof(MEM_SCATTER) + sizeof(PMEM_SCATTER))];
    PBYTE pbBufferMEMs, pbBufferLarge = NULL;
    PMEM_SCATTER pIoPA, pIoVA;
    PPMEM_SCATTER ppMEMsPhys = NULL;
    BOOL fPaging = !(VMM_FLAG_NOPAGING & (flags | ctxVmm->flags));
    BOOL fAltAddrPte = VMM_FLAG_ALTADDR_VA_PTE & flags;
    BOOL fZeropadOnFail = VMM_FLAG_ZEROPAD_ON_FAIL & (flags | ctxVmm->flags);
    BOOL fProcessMagicHandle = ((QWORD)pProcess >= 0xffffffff00000000);
    // 0: 'magic' process handle
    if(fProcessMagicHandle && !(pProcess = VmmProcessGet((DWORD)(0-(QWORD)pProcess)))) { return; }
    // 1: allocate / set up buffers (if needed)
    if(cpMEMsVirt < 0x20) {
        ZeroMemory(pbBufferSmall, sizeof(pbBufferSmall));
        ppMEMsPhys = (PPMEM_SCATTER)pbBufferSmall;
        pbBufferMEMs = pbBufferSmall + cpMEMsVirt * sizeof(PMEM_SCATTER);
    } else {
        if(!(pbBufferLarge = LocalAlloc(LMEM_ZEROINIT, cpMEMsVirt * (sizeof(MEM_SCATTER) + sizeof(PMEM_SCATTER))))) {
            if(fProcessMagicHandle) { Ob_DECREF(pProcess); }
            return;
        }
        ppMEMsPhys = (PPMEM_SCATTER)pbBufferLarge;
        pbBufferMEMs = pbBufferLarge + cpMEMsVirt * sizeof(PMEM_SCATTER);
    }
    // 2: translate virt2phys
    for(iVA = 0, iPA = 0; iVA < cpMEMsVirt; iVA++) {
        pIoVA = ppMEMsVirt[iVA];
        // MEMORY READ ALREADY COMPLETED
        if(pIoVA->f || (pIoVA->qwA == 0) || (pIoVA->qwA == -1)) {
            if(!pIoVA->f && fZeropadOnFail) {
                ZeroMemory(pIoVA->pb, pIoVA->cb);
            }
            continue;
        }
        // PHYSICAL MEMORY
        qwPA = 0;
        fVirt2Phys = !fAltAddrPte && VmmVirt2Phys(pProcess, pIoVA->qwA, &qwPA);
        // PAGED MEMORY
        if(!fVirt2Phys && fPaging && (pIoVA->cb == 0x1000) && ctxVmm->fnMemoryModel.pfnPagedRead) {
            if(ctxVmm->fnMemoryModel.pfnPagedRead(pProcess, (fAltAddrPte ? 0 : pIoVA->qwA), (fAltAddrPte ? pIoVA->qwA : qwPA), pIoVA->pb, &qwPagedPA, NULL, flags)) {
                pIoVA->f = TRUE;
                continue;
            }
            if(qwPagedPA) {
                qwPA = qwPagedPA;
                fVirt2Phys = TRUE;
            }
        }
        if(!fVirt2Phys) {   // NO TRANSLATION MEMORY / FAILED PAGED MEMORY
            if(fZeropadOnFail) {
                ZeroMemory(pIoVA->pb, pIoVA->cb);
            }
            continue;
        }
        // PHYS MEMORY
        pIoPA = ppMEMsPhys[iPA] = (PMEM_SCATTER)pbBufferMEMs + iPA;
        iPA++;
        pIoPA->version = MEM_SCATTER_VERSION;
        pIoPA->qwA = qwPA;
        pIoPA->cb = 0x1000;
        pIoPA->pb = pIoVA->pb;
        pIoPA->f = FALSE;
        MEM_SCATTER_STACK_PUSH(pIoPA, (QWORD)pIoVA);
    }
    // 3: read and check result
    if(iPA) {
        VmmReadScatterPhysical(ppMEMsPhys, iPA, flags);
        while(iPA > 0) {
            iPA--;
            ((PMEM_SCATTER)MEM_SCATTER_STACK_POP(ppMEMsPhys[iPA]))->f = ppMEMsPhys[iPA]->f;
        }
    }
    LocalFree(pbBufferLarge);
    if(fProcessMagicHandle) { Ob_DECREF(pProcess); }
}

/*
* Retrieve information of the virtual2physical address translation for the
* supplied process. The Virtual address must be supplied in pVirt2PhysInfo upon
* entry.
* -- pProcess
* -- pVirt2PhysInfo
*/
VOID VmmVirt2PhysGetInformation(_Inout_ PVMM_PROCESS pProcess, _Inout_ PVMM_VIRT2PHYS_INFORMATION pVirt2PhysInfo)
{
    if(ctxVmm->tpMemoryModel == VMM_MEMORYMODEL_NA) { return; }
    ctxVmm->fnMemoryModel.pfnVirt2PhysGetInformation(pProcess, pVirt2PhysInfo);
}

/*
* Retrieve information of the physical2virtual address translation for the
* supplied process. This function may take time on larger address spaces -
* such as the kernel adderss space due to extensive page walking. If a new
* address is to be used please supply it in paTarget. If paTarget == 0 then
* a previously stored address will be used.
* It's not possible to use this function to retrieve multiple targeted
* addresses in parallell.
* -- CALLER DECREF: return
* -- pProcess
* -- paTarget = targeted physical address (or 0 if use previously saved).
* -- return
*/
PVMMOB_PHYS2VIRT_INFORMATION VmmPhys2VirtGetInformation(_In_ PVMM_PROCESS pProcess, _In_ QWORD paTarget)
{
    PVMMOB_PHYS2VIRT_INFORMATION pObP2V = NULL;
    if(paTarget) {
        pProcess->pObPersistent->Plugin.paPhys2Virt = paTarget;
    } else {
        paTarget = pProcess->pObPersistent->Plugin.paPhys2Virt;
    }
    pObP2V = ObContainer_GetOb(pProcess->Plugin.pObCPhys2Virt);
    if(paTarget && (!pObP2V || (pObP2V->paTarget != paTarget))) {
        Ob_DECREF_NULL(&pObP2V);
        EnterCriticalSection(&pProcess->LockUpdate);
        pObP2V = ObContainer_GetOb(pProcess->Plugin.pObCPhys2Virt);
        if(paTarget && (!pObP2V || (pObP2V->paTarget != paTarget))) {
            Ob_DECREF_NULL(&pObP2V);
            pObP2V = Ob_Alloc('PAVA', LMEM_ZEROINIT, sizeof(VMMOB_PHYS2VIRT_INFORMATION), NULL, NULL);
            pObP2V->paTarget = paTarget;
            pObP2V->dwPID = pProcess->dwPID;
            if(ctxVmm->fnMemoryModel.pfnPhys2VirtGetInformation) {
                ctxVmm->fnMemoryModel.pfnPhys2VirtGetInformation(pProcess, pObP2V);
                ObContainer_SetOb(pProcess->Plugin.pObCPhys2Virt, pObP2V);
            }
        }
        LeaveCriticalSection(&pProcess->LockUpdate);
    }
    if(!pObP2V) {
        EnterCriticalSection(&pProcess->LockUpdate);
        pObP2V = ObContainer_GetOb(pProcess->Plugin.pObCPhys2Virt);
        if(!pObP2V) {
            pObP2V = Ob_Alloc('PAVA', LMEM_ZEROINIT, sizeof(VMMOB_PHYS2VIRT_INFORMATION), NULL, NULL);
            pObP2V->dwPID = pProcess->dwPID;
            ObContainer_SetOb(pProcess->Plugin.pObCPhys2Virt, pObP2V);
        }
        LeaveCriticalSection(&pProcess->LockUpdate);
    }
    return pObP2V;
}

// ----------------------------------------------------------------------------
// PUBLICALLY VISIBLE FUNCTIONALITY RELATED TO VMMU.
// ----------------------------------------------------------------------------

VOID VmmClose()
{
    if(!ctxVmm) { return; }
    if(ctxVmm->PluginManager.FLinkAll) { PluginManager_Close(); }
    VmmWork_Close();
    VmmWinObj_Close();
    VmmWinReg_Close();
    VmmNet_Close();
    PDB_Close();
    Ob_DECREF_NULL(&ctxVmm->pObVfsDumpContext);
    Ob_DECREF_NULL(&ctxVmm->pObPfnContext);
    Ob_DECREF_NULL(&ctxVmm->pObCPROC);
    if(ctxVmm->fnMemoryModel.pfnClose) {
        ctxVmm->fnMemoryModel.pfnClose();
    }
    MmWin_PagingClose();
    VmmCacheClose(VMM_CACHE_TAG_PHYS);
    VmmCacheClose(VMM_CACHE_TAG_TLB);
    VmmCacheClose(VMM_CACHE_TAG_PAGING);
    Ob_DECREF_NULL(&ctxVmm->Cache.PAGING_FAILED);
    Ob_DECREF_NULL(&ctxVmm->Cache.pmPrototypePte);
    Ob_DECREF_NULL(&ctxVmm->pObCMapPhysMem);
    Ob_DECREF_NULL(&ctxVmm->pObCMapEvil);
    Ob_DECREF_NULL(&ctxVmm->pObCMapUser);
    Ob_DECREF_NULL(&ctxVmm->pObCMapNet);
    Ob_DECREF_NULL(&ctxVmm->pObCMapObject);
    Ob_DECREF_NULL(&ctxVmm->pObCMapKDriver);
    Ob_DECREF_NULL(&ctxVmm->pObCMapService);
    Ob_DECREF_NULL(&ctxVmm->pObCInfoDB);
    Ob_DECREF_NULL(&ctxVmm->pObCCachePrefetchEPROCESS);
    Ob_DECREF_NULL(&ctxVmm->pObCCachePrefetchRegistry);
    Ob_DECREF_NULL(&ctxVmm->pObCacheMapEAT);
    Ob_DECREF_NULL(&ctxVmm->pObCacheMapIAT);
    Ob_DECREF_NULL(&ctxVmm->pObCacheMapWinObjDisplay);
    DeleteCriticalSection(&ctxVmm->LockMaster);
    DeleteCriticalSection(&ctxVmm->LockPlugin);
    DeleteCriticalSection(&ctxVmm->LockUpdateMap);
    DeleteCriticalSection(&ctxVmm->LockUpdateModule);
    LocalFree(ctxVmm->ObjectTypeTable.pbMultiText);
    LocalFree(ctxVmm);
    ctxVmm = NULL;
}

VOID VmmWriteEx(_In_opt_ PVMM_PROCESS pProcess, _In_ QWORD qwA, _In_ PBYTE pb, _In_ DWORD cb, _Out_opt_ PDWORD pcbWrite)
{
    DWORD i = 0, oA = 0, cbWrite = 0, cbP, cMEMs;
    PBYTE pbBuffer;
    PMEM_SCATTER pMEM, pMEMs, *ppMEMs;
    if(pcbWrite) { *pcbWrite = 0; }
    // allocate
    cMEMs = (DWORD)(((qwA & 0xfff) + cb + 0xfff) >> 12);
    if(!(pbBuffer = (PBYTE)LocalAlloc(LMEM_ZEROINIT, cMEMs * (sizeof(MEM_SCATTER) + sizeof(PMEM_SCATTER))))) { return; }
    pMEMs = (PMEM_SCATTER)pbBuffer;
    ppMEMs = (PPMEM_SCATTER)(pbBuffer + cMEMs * sizeof(MEM_SCATTER));
    // prepare pages
    while(oA < cb) {
        cbP = 0x1000 - ((qwA + oA) & 0xfff);
        cbP = min(cbP, cb - oA);
        ppMEMs[i] = pMEM = pMEMs + i; i++;
        pMEM->version = MEM_SCATTER_VERSION;
        pMEM->qwA = qwA + oA;
        pMEM->cb = cbP;
        pMEM->pb = pb + oA;
        oA += cbP;
    }
    // write and count result
    if(pProcess) {
        VmmWriteScatterVirtual(pProcess, ppMEMs, cMEMs);
    } else {
        VmmWriteScatterPhysical(ppMEMs, cMEMs);
    }
    if(pcbWrite) {
        for(i = 0; i < cMEMs; i++) {
            if(pMEMs[i].f) {
                cbWrite += pMEMs[i].cb;
            }
        }
        *pcbWrite = cbWrite;
    }
    LocalFree(pbBuffer);
}

BOOL VmmWrite(_In_opt_ PVMM_PROCESS pProcess, _In_ QWORD qwA, _In_reads_(cb) PBYTE pb, _In_ DWORD cb)
{
    DWORD cbWrite;
    VmmWriteEx(pProcess, qwA, pb, cb, &cbWrite);
    return (cbWrite == cb);
}

VOID VmmReadEx(_In_opt_ PVMM_PROCESS pProcess, _In_ QWORD qwA, _Out_writes_(cb) PBYTE pb, _In_ DWORD cb, _Out_opt_ PDWORD pcbReadOpt, _In_ QWORD flags)
{
    DWORD cbP, cMEMs, cbRead = 0;
    PBYTE pbBuffer;
    PMEM_SCATTER pMEMs, *ppMEMs;
    QWORD i, oA;
    if(pcbReadOpt) { *pcbReadOpt = 0; }
    if(!cb) { return; }
    cMEMs = (DWORD)(((qwA & 0xfff) + cb + 0xfff) >> 12);
    pbBuffer = (PBYTE)LocalAlloc(LMEM_ZEROINIT, 0x2000 + cMEMs * (sizeof(MEM_SCATTER) + sizeof(PMEM_SCATTER)));
    if(!pbBuffer) {
        ZeroMemory(pb, cb);
        return;
    }
    pMEMs = (PMEM_SCATTER)(pbBuffer + 0x2000);
    ppMEMs = (PPMEM_SCATTER)(pbBuffer + 0x2000 + cMEMs * sizeof(MEM_SCATTER));
    oA = qwA & 0xfff;
    // prepare "middle" pages
    for(i = 0; i < cMEMs; i++) {
        ppMEMs[i] = &pMEMs[i];
        pMEMs[i].version = MEM_SCATTER_VERSION;
        pMEMs[i].qwA = qwA - oA + (i << 12);
        pMEMs[i].cb = 0x1000;
        pMEMs[i].pb = pb - oA + (i << 12);
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
        if(pMEMs[i].f) {
            cbRead += 0x1000;
        } else {
            ZeroMemory(pMEMs[i].pb, 0x1000);
        }
    }
    cbRead -= pMEMs[0].f ? 0x1000 : 0;                             // adjust byte count for first page (if needed)
    cbRead -= ((cMEMs > 1) && pMEMs[cMEMs - 1].f) ? 0x1000 : 0;    // adjust byte count for last page (if needed)
    // Handle first page
    cbP = (DWORD)min(cb, 0x1000 - oA);
    if(pMEMs[0].f) {
        memcpy(pb, pMEMs[0].pb + oA, cbP);
        cbRead += cbP;
    } else {
        ZeroMemory(pb, cbP);
    }
    // Handle last page
    if(cMEMs > 1) {
        cbP = (((qwA + cb) & 0xfff) ? ((qwA + cb) & 0xfff) : 0x1000);
        if(pMEMs[cMEMs - 1].f) {
            memcpy(pb + ((QWORD)cMEMs << 12) - oA - 0x1000, pMEMs[cMEMs - 1].pb, cbP);
            cbRead += cbP;
        } else {
            ZeroMemory(pb + ((QWORD)cMEMs << 12) - oA - 0x1000, cbP);
        }
    }
    if(pcbReadOpt) { *pcbReadOpt = cbRead; }
    LocalFree(pbBuffer);
}

#define STATUS_SUCCESS                   ((NTSTATUS)0x00000000L)
#define STATUS_END_OF_FILE               ((NTSTATUS)0xC0000011L)

NTSTATUS VmmReadAsFile(_In_opt_ PVMM_PROCESS pProcess, _In_ QWORD qwMemoryAddress, _In_ QWORD cbMemorySize, _Out_writes_(cb) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset)
{
    QWORD cbMax;
    if(cbMemorySize <= cbOffset) {
        *pcbRead = 0;
        return STATUS_END_OF_FILE;
    }
    cbMax = min(qwMemoryAddress + cbMemorySize, (qwMemoryAddress + cb + cbOffset)) - (qwMemoryAddress + cbOffset);   // min(entry_top_addr, request_top_addr) - request_start_addr
    *pcbRead = (DWORD)min(cb, cbMax);
    if(!*pcbRead) {
        return STATUS_END_OF_FILE;
    }
    VmmReadEx(pProcess, qwMemoryAddress + cbOffset, pb, *pcbRead, NULL, VMM_FLAG_ZEROPAD_ON_FAIL);
    return STATUS_SUCCESS;
}

NTSTATUS VmmWriteAsFile(_In_opt_ PVMM_PROCESS pProcess, _In_ QWORD qwMemoryAddress, _In_ QWORD cbMemorySize, _In_reads_(cb) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbWrite, _In_ QWORD cbOffset)
{
    QWORD cbMax;
    if(cbMemorySize <= cbOffset) {
        *pcbWrite = 0;
        return STATUS_END_OF_FILE;
    }
    cbMax = min(qwMemoryAddress + cbMemorySize, (qwMemoryAddress + cb + cbOffset)) - (qwMemoryAddress + cbOffset);   // min(entry_top_addr, request_top_addr) - request_start_addr
    *pcbWrite = (DWORD)min(cb, cbMax);
    if(!*pcbWrite) {
        return STATUS_END_OF_FILE;
    }
    VmmWriteEx(pProcess, qwMemoryAddress + cbOffset, pb, *pcbWrite, NULL);
    return STATUS_SUCCESS;
}


_Success_(return)
BOOL VmmReadWtoU(_In_opt_ PVMM_PROCESS pProcess, _In_ QWORD qwA, _In_ DWORD cb, _In_ QWORD flagsRead, _Maybenull_ _Writable_bytes_(cbBuffer) PBYTE pbBuffer, _In_ DWORD cbBuffer, _Out_opt_ LPSTR *pusz, _Out_opt_ PDWORD pcbu, _In_ DWORD flagsChar)
{
    BOOL fResult = FALSE;
    BYTE pbBufferTMP[2 * MAX_PATH + 2] = { 0 };
    PBYTE pb = pbBufferTMP;
    DWORD cbRead = 0;
    if(cb > sizeof(pbBufferTMP)) {
        if(!(pb = LocalAlloc(0, cb))) { goto fail; }
    }
    VmmReadEx(pProcess, qwA, pb, cb, &cbRead, flagsRead);
    if(cbRead != cb) {
        if(cbBuffer && pbBuffer) { pbBuffer[0] = 0; }
        goto fail;
    }
    fResult = CharUtil_WtoU((LPWSTR)pb, cb >> 1, pbBuffer, cbBuffer, pusz, pcbu, flagsChar);
fail:
    if(pb != pbBufferTMP) { LocalFree(pb); }
    if(!fResult) {
        if(pbBuffer && cbBuffer) { pbBuffer[0] = 0; }
        if(pusz) { *pusz = NULL; }
        if(pcbu) { *pcbu = 0; }
    }
    return fResult;
}

_Success_(return)
BOOL VmmReadAlloc(_In_opt_ PVMM_PROCESS pProcess, _In_ QWORD qwA, _Out_ PBYTE *ppb, _In_ DWORD cb, _In_ QWORD flags)
{
    PBYTE pb;
    if(!(pb = LocalAlloc(0, cb + 2ULL))) { return FALSE; }
    if(!VmmRead2(pProcess, qwA, pb, cb, flags)) {
        LocalFree(pb);
        return FALSE;
    }
    pb[cb] = 0;
    pb[cb + 1] = 0;
    *ppb = pb;
    return TRUE;
}

_Success_(return)
BOOL VmmReadAllocUnicodeString_Size(_In_ PVMM_PROCESS pProcess, _In_ BOOL f32, _In_ QWORD flags, _In_ QWORD vaUS, _Out_ PQWORD pvaStr, _Out_ PWORD pcbStr)
{
    BYTE pb[16];
    DWORD cbRead;
    VmmReadEx(pProcess, vaUS, pb, (f32 ? 8 : 16), &cbRead, flags);
    return
        (cbRead == (f32 ? 8 : 16)) &&                               // read ok
        (*(PWORD)pb <= *(PWORD)(pb + 2)) &&                         // size max >= size
        (*pcbStr = *(PWORD)pb) &&                                   // size != 0
        (*pcbStr > 1) &&                                            // size > 1
        (*pvaStr = f32 ? *(PDWORD)(pb + 4) : *(PQWORD)(pb + 8)) &&  // string address != 0
        !(*pvaStr & (f32 ? 3 : 7));                                 // non alignment
}

_Success_(return)
BOOL VmmReadAllocUnicodeString(_In_ PVMM_PROCESS pProcess, _In_ BOOL f32, _In_ QWORD flags, _In_ QWORD vaUS, _In_ DWORD cchMax, _Out_opt_ LPWSTR *pwsz, _Out_opt_ PDWORD pcch)
{
    WORD cbStr;
    QWORD vaStr;
    if(pcch) { *pcch = 0; }
    if(pwsz) { *pwsz = NULL; }
    if(VmmReadAllocUnicodeString_Size(pProcess, f32, 0, vaUS, &vaStr, &cbStr)) {
        if(cchMax && (cbStr > (cchMax << 1))) {
            cbStr = (WORD)(cchMax << 1);
        }
        if(!pwsz || VmmReadAlloc(pProcess, vaStr, (PBYTE *)pwsz, cbStr, flags)) {
            if(pcch) { *pcch = cbStr >> 1; }
            return TRUE;
        }
    }
    return FALSE;
}

_Success_(return)
BOOL VmmRead(_In_opt_ PVMM_PROCESS pProcess, _In_ QWORD qwA, _Out_writes_(cb) PBYTE pb, _In_ DWORD cb)
{
    DWORD cbRead;
    VmmReadEx(pProcess, qwA, pb, cb, &cbRead, 0);
    return (cbRead == cb);
}

_Success_(return)
BOOL VmmRead2(_In_opt_ PVMM_PROCESS pProcess, _In_ QWORD qwA, _Out_writes_(cb) PBYTE pb, _In_ DWORD cb, _In_ QWORD flags)
{
    DWORD cbRead;
    VmmReadEx(pProcess, qwA, pb, cb, &cbRead, flags);
    return (cbRead == cb);
}

_Success_(return)
BOOL VmmReadPage(_In_opt_ PVMM_PROCESS pProcess, _In_ QWORD qwA, _Out_writes_(4096) PBYTE pbPage)
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
        ctxVmm->fn.RtlDecompressBufferOpt = (VMMFN_RtlDecompressBuffer*)GetProcAddress(hNtDll, "RtlDecompressBuffer");
        FreeLibrary(hNtDll);
    }
    return;
}

BOOL VmmInitialize()
{
    // 1: allocate & initialize
    if(ctxVmm) { VmmClose(); }
    ctxVmm = (PVMM_CONTEXT)LocalAlloc(LMEM_ZEROINIT, sizeof(VMM_CONTEXT));
    if(!ctxVmm) { goto fail; }
    ctxVmm->hModuleVmmOpt = GetModuleHandleA("vmm");
    // 2: CACHE INIT: Process Table
    if(!VmmProcessTableCreateInitial()) { goto fail; }
    // 3: CACHE INIT: Translation Lookaside Buffer (TLB) Cache Table
    VmmCacheInitialize(VMM_CACHE_TAG_TLB);
    if(!ctxVmm->Cache.TLB.fActive) { goto fail; }
    // 4: CACHE INIT: Physical Memory Cache Table
    VmmCacheInitialize(VMM_CACHE_TAG_PHYS);
    if(!ctxVmm->Cache.PHYS.fActive) { goto fail; }
    // 5: CACHE INIT: Paged Memory Cache Table
    VmmCacheInitialize(VMM_CACHE_TAG_PAGING);
    if(!ctxVmm->Cache.PAGING.fActive) { goto fail; }
    if(!(ctxVmm->Cache.PAGING_FAILED = ObSet_New())) { goto fail; }
    // 6: CACHE INIT: Prototype PTE Cache Map
    if(!(ctxVmm->Cache.pmPrototypePte = ObMap_New(OB_MAP_FLAGS_OBJECT_OB))) { goto fail; }
    // 7: WORKER THREADS INIT:
    VmmWork_Initialize();
    // 8: OTHER INIT:
    ctxVmm->pObCMapPhysMem = ObContainer_New();
    ctxVmm->pObCMapEvil = ObContainer_New();
    ctxVmm->pObCMapUser = ObContainer_New();
    ctxVmm->pObCMapNet = ObContainer_New();
    ctxVmm->pObCMapObject = ObContainer_New();
    ctxVmm->pObCMapKDriver = ObContainer_New();
    ctxVmm->pObCMapService = ObContainer_New();
    ctxVmm->pObCInfoDB = ObContainer_New();
    ctxVmm->pObCCachePrefetchEPROCESS = ObContainer_New();
    ctxVmm->pObCCachePrefetchRegistry = ObContainer_New();
    InitializeCriticalSection(&ctxVmm->LockMaster);
    InitializeCriticalSection(&ctxVmm->LockPlugin);
    InitializeCriticalSection(&ctxVmm->LockUpdateMap);
    InitializeCriticalSection(&ctxVmm->LockUpdateModule);
    VmmInitializeFunctions();
    return TRUE;
fail:
    VmmClose();
    return FALSE;
}



// ----------------------------------------------------------------------------
// MAP FUNCTIONALITY BELOW: 
// SUPPORTED MAPS: PTE, VAD, MODULE, HEAP
// ----------------------------------------------------------------------------

/*
* Retrieve the PTE hardware page table memory map.
* CALLER DECREF: ppObPteMap
* -- pProcess
* -- ppObPteMap
* -- fExtendedText
* -- return
*/
_Success_(return)
BOOL VmmMap_GetPte(_In_ PVMM_PROCESS pProcess, _Out_ PVMMOB_MAP_PTE *ppObPteMap, _In_ BOOL fExtendedText)
{
    return
        (ctxVmm->tpMemoryModel != VMM_MEMORYMODEL_NA) &&
        ctxVmm->fnMemoryModel.pfnPteMapInitialize(pProcess) &&
        (!fExtendedText || VmmWinPte_InitializeMapText(pProcess)) &&
        (*ppObPteMap = Ob_INCREF(pProcess->Map.pObPte));
}

/*
* Retrieve the VAD extended memory map by range specified by iPage and cPage.
* CALLER DECREF: ppObVadExMap
* -- pProcess
* -- ppObVadExMap
* -- tpVmmVadMap = VMM_VADMAP_TP_*
* -- iPage = index of range start in vad map.
* -- cPage = number of pages, starting at iPage.
* -- return
*/
_Success_(return)
BOOL VmmMap_GetVadEx(_In_ PVMM_PROCESS pProcess, _Out_ PVMMOB_MAP_VADEX *ppObVadExMap, _In_ VMM_VADMAP_TP tpVmmVadMap, _In_ DWORD iPage, _In_ DWORD cPage)
{
    *ppObVadExMap = MmVadEx_MapInitialize(pProcess, tpVmmVadMap, iPage, cPage);
    return *ppObVadExMap != NULL;
}

/*
* Retrieve the VAD memory map.
* CALLER DECREF: ppObVadMap
* -- pProcess
* -- ppObVadMap
* -- tpVmmVadMap = VMM_VADMAP_TP_*
* -- return
*/
_Success_(return)
BOOL VmmMap_GetVad(_In_ PVMM_PROCESS pProcess, _Out_ PVMMOB_MAP_VAD *ppObVadMap, _In_ VMM_VADMAP_TP tpVmmVadMap)
{
    if(!MmVad_MapInitialize(pProcess, tpVmmVadMap, 0)) { return FALSE; }
    *ppObVadMap = Ob_INCREF(pProcess->Map.pObVad);
    return *ppObVadMap != NULL;
}

int VmmMap_GetVadEntry_CmpFind(_In_ QWORD vaFind, _In_ PVMM_MAP_VADENTRY pEntry)
{
    if(pEntry->vaStart > vaFind) { return -1; }
    if(pEntry->vaEnd < vaFind) { return 1; }
    return 0;
}

/*
* Retrieve a single PVMM_MAP_VADENTRY for a given VadMap and address inside it.
* -- pVadMap
* -- va
* -- return = PTR to VADENTRY or NULL on fail. Must not be used out of pVadMap scope.
*/
PVMM_MAP_VADENTRY VmmMap_GetVadEntry(_In_opt_ PVMMOB_MAP_VAD pVadMap, _In_ QWORD va)
{
    if(!pVadMap) { return NULL; }
    return Util_qfind((PVOID)va, pVadMap->cMap, pVadMap->pMap, sizeof(VMM_MAP_VADENTRY), (int(*)(PVOID, PVOID))VmmMap_GetVadEntry_CmpFind);
}

/*
* Retrieve the process module map.
* CALLER DECREF: ppObModuleMap
* -- pProcess
* -- ppObModuleMap
* -- return
*/
_Success_(return)
BOOL VmmMap_GetModule(_In_ PVMM_PROCESS pProcess, _Out_ PVMMOB_MAP_MODULE *ppObModuleMap)
{
    if(!pProcess->Map.pObModule && !VmmWinLdrModule_Initialize(pProcess, NULL)) { return FALSE; }
    *ppObModuleMap = Ob_INCREF(pProcess->Map.pObModule);
    return *ppObModuleMap != NULL;
}

int VmmMap_HashTableLookup_CmpFind(_In_ DWORD qwHash, _In_ PDWORD pdwEntry)
{
    if(*pdwEntry > qwHash) { return -1; }
    if(*pdwEntry < qwHash) { return 1; }
    return 0;
}

/*
* Retrieve a single PVMM_MAP_MODULEENTRY for a given ModuleMap and module name inside it.
* -- pModuleMap
* -- uszModuleName
* -- return = PTR to VMM_MAP_MODULEENTRY or NULL on fail. Must not be used out of pModuleMap scope.
*/
PVMM_MAP_MODULEENTRY VmmMap_GetModuleEntry(_In_ PVMMOB_MAP_MODULE pModuleMap, _In_ LPSTR uszModuleName)
{
    QWORD qwHash, *pqwHashIndex;
    qwHash = CharUtil_HashNameFsU(uszModuleName, 0);
    pqwHashIndex = (PQWORD)Util_qfind((PVOID)qwHash, pModuleMap->cMap, pModuleMap->pHashTableLookup, sizeof(QWORD), (int(*)(PVOID, PVOID))VmmMap_HashTableLookup_CmpFind);
    return pqwHashIndex ? &pModuleMap->pMap[*pqwHashIndex >> 32] : NULL;
}

/*
* Retrieve a single VMM_MAP_MODULEENTRY for a given process and module name.
* CALLER DECREF: ppObModuleMap
* -- pProcessOpt
* -- dwPidOpt
* -- wszModuleName
* -- ppObModuleMap
* -- pModuleEntry
* -- return
*/
_Success_(return)
BOOL VmmMap_GetModuleEntryEx(_In_opt_ PVMM_PROCESS pProcessOpt, _In_opt_ DWORD dwPidOpt, _In_ LPSTR uszModuleName, _Out_ PVMMOB_MAP_MODULE *ppObModuleMap, _Out_ PVMM_MAP_MODULEENTRY *pModuleEntry)
{
    PVMM_PROCESS pObProcess = pProcessOpt ? Ob_INCREF(pProcessOpt) : VmmProcessGet(dwPidOpt);
    *ppObModuleMap = NULL;
    *pModuleEntry = NULL;
    if(VmmMap_GetModule(pObProcess, ppObModuleMap)) {
        *pModuleEntry = VmmMap_GetModuleEntry(*ppObModuleMap, uszModuleName);
        Ob_DECREF_NULL(&pObProcess);
    }
    return *pModuleEntry != NULL;
}

/*
* Retrieve the process unloaded module map.
* CALLER DECREF: ppObUnloadedModuleMap
* -- pProcess
* -- ppObUnloadedModuleMap
* -- return
*/
_Success_(return)
BOOL VmmMap_GetUnloadedModule(_In_ PVMM_PROCESS pProcess, _Out_ PVMMOB_MAP_UNLOADEDMODULE *ppObUnloadedModuleMap)
{
    if(!pProcess->Map.pObUnloadedModule && !VmmWinUnloadedModule_Initialize(pProcess)) { return FALSE; }
    *ppObUnloadedModuleMap = Ob_INCREF(pProcess->Map.pObUnloadedModule);
    return *ppObUnloadedModuleMap != NULL;
}

/*
* Retrieve the process module export address table (EAT) map.
* CALLER DECREF: ppObEatMap
* -- pProcess
* -- pModule
* -- ppObEatMap
* -- return
*/
_Success_(return)
BOOL VmmMap_GetEAT(_In_ PVMM_PROCESS pProcess, _In_ PVMM_MAP_MODULEENTRY pModuleEntry, _Out_ PVMMOB_MAP_EAT *ppObEatMap)
{
    *ppObEatMap = VmmWinEAT_Initialize(pProcess, pModuleEntry);
    return *ppObEatMap != NULL;
}

/*
* Retrieve the export entry index in pEatMap->pMap by function name.
* -- pEatMap
* -- uszFunctionName
* -- pdwEntryIndex = pointer to receive the pEatMap->pMap index.
* -- return
*/
_Success_(return)
BOOL VmmMap_GetEATEntryIndexU(_In_ PVMMOB_MAP_EAT pEatMap, _In_ LPSTR uszFunctionName, _Out_ PDWORD pdwEntryIndex)
{
    QWORD qwHash, *pqwHashIndex;
    qwHash = (DWORD)CharUtil_Hash64U(uszFunctionName, TRUE);
    pqwHashIndex = (PQWORD)Util_qfind((PVOID)qwHash, pEatMap->cMap, pEatMap->pHashTableLookup, sizeof(QWORD), (int(*)(PVOID, PVOID))VmmMap_HashTableLookup_CmpFind);
    *pdwEntryIndex = pqwHashIndex ? *pqwHashIndex >> 32 : 0;
    return (pqwHashIndex != NULL) && (*pdwEntryIndex < pEatMap->cMap);
}

/*
* Retrieve the process module import address table (IAT) map.
* CALLER DECREF: ppObIatMap
* -- pProcess
* -- pModule
* -- ppObIatMap
* -- return
*/
_Success_(return)
BOOL VmmMap_GetIAT(_In_ PVMM_PROCESS pProcess, _In_ PVMM_MAP_MODULEENTRY pModuleEntry, _Out_ PVMMOB_MAP_IAT *ppObIatMap)
{
    *ppObIatMap = VmmWinIAT_Initialize(pProcess, pModuleEntry);
    return *ppObIatMap != NULL;
}

/*
* Retrieve the heap map.
* CALLER DECREF: ppObHeapMap
* -- pProcess
* -- ppObHeapMap
* -- return
*/
_Success_(return)
BOOL VmmMap_GetHeap(_In_ PVMM_PROCESS pProcess, _Out_ PVMMOB_MAP_HEAP *ppObHeapMap)
{
    if(!pProcess->Map.pObHeap && !VmmWinHeap_Initialize(pProcess)) { return FALSE; }
    *ppObHeapMap = Ob_INCREF(pProcess->Map.pObHeap);
    return *ppObHeapMap != NULL;
}

/*
* Retrieve the thread map.
* CALLER DECREF: ppObThreadMap
* -- pProcess
* -- ppObThreadMap
* -- return
*/
_Success_(return)
BOOL VmmMap_GetThread(_In_ PVMM_PROCESS pProcess, _Out_ PVMMOB_MAP_THREAD *ppObThreadMap)
{
    if(!pProcess->Map.pObThread && !VmmWinThread_Initialize(pProcess)) { return FALSE; }
    *ppObThreadMap = Ob_INCREF(pProcess->Map.pObThread);
    return *ppObThreadMap ? TRUE : FALSE;
}

int VmmMap_GetThreadEntry_CmpFind(_In_ DWORD dwTID, _In_ PVMM_MAP_THREADENTRY pEntry)
{
    if(pEntry->dwTID > dwTID) { return -1; }
    if(pEntry->dwTID < dwTID) { return 1; }
    return 0;
}

/*
* Retrieve a single PVMM_MAP_THREADENTRY for a given ThreadMap and ThreadID.
* -- pThreadMap
* -- dwTID
* -- return = PTR to VMM_MAP_THREADENTRY or NULL on fail. Must not be used out of pThreadMap scope.
*/
PVMM_MAP_THREADENTRY VmmMap_GetThreadEntry(_In_ PVMMOB_MAP_THREAD pThreadMap, _In_ DWORD dwTID)
{
    QWORD qwTID = dwTID;
    return Util_qfind((PVOID)qwTID, pThreadMap->cMap, pThreadMap->pMap, sizeof(VMM_MAP_THREADENTRY), (int(*)(PVOID, PVOID))VmmMap_GetThreadEntry_CmpFind);
}

/*
* Retrieve the HANDLE map
* CALLER DECREF: ppObHandleMap
* -- pProcess
* -- ppObHandleMap
* -- fExtendedText
* -- return
*/
_Success_(return)
BOOL VmmMap_GetHandle(_In_ PVMM_PROCESS pProcess, _Out_ PVMMOB_MAP_HANDLE *ppObHandleMap, _In_ BOOL fExtendedText)
{
    if(!VmmWinHandle_Initialize(pProcess, fExtendedText)) { return FALSE; }
    *ppObHandleMap = Ob_INCREF(pProcess->Map.pObHandle);
    return *ppObHandleMap != NULL;
}

/*
* Retrieve the EVIL map
* CALLER DECREF: ppObEvilMap
* -- pProcess = retrieve for specific process, or if NULL for all processes.
* -- ppObEvilMap
* -- return
*/
_Success_(return)
BOOL VmmMap_GetEvil(_In_opt_ PVMM_PROCESS pProcess, _Out_ PVMMOB_MAP_EVIL *ppObEvilMap)
{
    *ppObEvilMap = VmmEvil_Initialize(pProcess);
    return *ppObEvilMap != NULL;
}

/*
* Retrieve the Physical Memory Map.
* CALLER DECREF: ppObPhysMem
* -- ppObPhysMem
* -- return
*/
_Success_(return)
BOOL VmmMap_GetPhysMem(_Out_ PVMMOB_MAP_PHYSMEM *ppObPhysMem)
{
    if(!(*ppObPhysMem = ObContainer_GetOb(ctxVmm->pObCMapPhysMem))) {
        *ppObPhysMem = VmmWinPhysMemMap_Initialize();
    }
    return *ppObPhysMem != NULL;
}

/*
* Retrieve the USER map
* CALLER DECREF: ppObUserMap
* -- ppObUserMap
* -- return
*/
_Success_(return)
BOOL VmmMap_GetUser(_Out_ PVMMOB_MAP_USER *ppObUserMap)
{
    if(!(*ppObUserMap = ObContainer_GetOb(ctxVmm->pObCMapUser))) {
        *ppObUserMap = VmmWinUser_Initialize();
    }
    return *ppObUserMap != NULL;
}

/*
* Retrieve the OBJECT MANAGER map
* CALLER DECREF: ppObObjectMap
* -- ppObObjectMap
* -- return
*/
_Success_(return)
BOOL VmmMap_GetObject(_Out_ PVMMOB_MAP_OBJECT *ppObObjectMap)
{
    if(!(*ppObObjectMap = ObContainer_GetOb(ctxVmm->pObCMapObject))) {
        *ppObObjectMap = VmmWinObjMgr_Initialize();
    }
    return *ppObObjectMap != NULL;
}

/*
* Retrieve the KERNEL DRIVER map
* CALLER DECREF: ppObKDriverMap
* -- ppObKDriverMap
* -- return
*/
_Success_(return)
BOOL VmmMap_GetKDriver(_Out_ PVMMOB_MAP_KDRIVER *ppObKDriverMap)
{
    if(!(*ppObKDriverMap = ObContainer_GetOb(ctxVmm->pObCMapKDriver))) {
        *ppObKDriverMap = VmmWinObjKDrv_Initialize();
    }
    return *ppObKDriverMap != NULL;
}

/*
* Retrieve the NETWORK CONNECTION map
* CALLER DECREF: ppObNetMap
* -- ppObNetMap
* -- return
*/
_Success_(return)
BOOL VmmMap_GetNet(_Out_ PVMMOB_MAP_NET *ppObNetMap)
{
    if(!(*ppObNetMap = ObContainer_GetOb(ctxVmm->pObCMapNet))) {
        *ppObNetMap = VmmNet_Initialize();
    }
    return *ppObNetMap != NULL;
}

/*
* Retrieve the SERVICES map
* CALLER DECREF: ppObServiceMap
* -- ppObServiceMap
* -- return
*/
_Success_(return)
BOOL VmmMap_GetService(_Out_ PVMMOB_MAP_SERVICE *ppObServiceMap)
{
    if(!(*ppObServiceMap = ObContainer_GetOb(ctxVmm->pObCMapService))) {
        *ppObServiceMap = VmmWinSvc_Initialize();
    }
    return *ppObServiceMap != NULL;
}
