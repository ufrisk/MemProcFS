// vmm.c : implementation of functions related to virtual memory management support.
//
// (c) Ulf Frisk, 2018-2025
// Author: Ulf Frisk, pcileech@frizk.net
//

#include "vmm.h"
#include "mm/mm.h"
#include "mm/mm_pfn.h"
#include "pdb.h"
#include "vmmheap.h"
#include "vmmproc.h"
#include "vmmvm.h"
#include "vmmwin.h"
#include "vmmwindef.h"
#include "vmmwinobj.h"
#include "vmmwinpool.h"
#include "vmmwinreg.h"
#include "vmmwinsvc.h"
#include "vmmwinthread.h"
#include "vmmnet.h"
#include "pluginmanager.h"
#include "charutil.h"
#include "util.h"
#ifdef _WIN32
#include <sddl.h>
#endif /* _WIN32 */

// ----------------------------------------------------------------------------
// CACHE FUNCTIONALITY:
// PHYSICAL MEMORY CACHING FOR READS AND PAGE TABLES
// ----------------------------------------------------------------------------

#define VMM_CACHE_GET_BUCKET(qwA)      ((VMM_CACHE_BUCKETS - 1) & ((qwA >> 12) + 13 * (qwA + _rotr16((WORD)qwA, 9) + _rotr((DWORD)qwA, 17) + _rotr64(qwA, 31))))

/*
* Retrieve cache table from ctxVmm given a specific tag.
*/
PVMM_CACHE_TABLE VmmCacheTableGet(_In_ VMM_HANDLE H, _In_ DWORD wTblTag)
{
    switch(wTblTag) {
        case VMM_CACHE_TAG_PHYS:
            H->vmm.Cache.PHYS.cMaxMems = VMM_CACHE_REGION_MEMS_PHYS;
            return &H->vmm.Cache.PHYS;
        case VMM_CACHE_TAG_TLB:
            H->vmm.Cache.TLB.cMaxMems = VMM_CACHE_REGION_MEMS_TLB;
            return &H->vmm.Cache.TLB;
        case VMM_CACHE_TAG_PAGING:
            H->vmm.Cache.PAGING.cMaxMems = VMM_CACHE_REGION_MEMS_PAGING;
            return &H->vmm.Cache.PAGING;
        default:
            return NULL;
    }
}

/*
* Clear the oldest region of all InUse entries and make it the new active region.
* -- wTblTag
*/
VOID VmmCacheClearPartial(_In_ VMM_HANDLE H, _In_ DWORD dwTblTag)
{
    PVMM_CACHE_TABLE t;
    PVMMOB_CACHE_MEM pOb;
    PSLIST_ENTRY e;
    DWORD iR;
    PVMM_PROCESS pObProcess = NULL;
    t = VmmCacheTableGet(H, dwTblTag);
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
        while((pObProcess = VmmProcessGetNext(H, pObProcess, 0))) {
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
VOID VmmCacheClear(_In_ VMM_HANDLE H, _In_ DWORD dwTblTag)
{
    DWORD i;
    for(i = 0; i < VMM_CACHE_REGIONS; i++) {
        VmmCacheClearPartial(H, dwTblTag);
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
PVMMOB_CACHE_MEM VmmCacheGetEx(_In_ VMM_HANDLE H, _In_ DWORD dwTblTag, _In_ QWORD qwA, _In_ BOOL fCurrentRegionOnly)
{
    PVMM_CACHE_TABLE t;
    DWORD iB, iR, iRB, iRC;
    PVMMOB_CACHE_MEM pOb;
    t = VmmCacheTableGet(H, dwTblTag);
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
PVMMOB_CACHE_MEM VmmCacheGet(_In_ VMM_HANDLE H, _In_ DWORD dwTblTag, _In_ QWORD qwA)
{
    return VmmCacheGetEx(H, dwTblTag, qwA, FALSE);
}

VOID VmmCache_CallbackRefCount1(PVMMOB_CACHE_MEM pOb)
{
    VMM_HANDLE H = ((POB)pOb)->H;
    PVMM_CACHE_TABLE t = VmmCacheTableGet(H, ((POB)pOb)->_tag);
    if(!t) {
        VmmLog(H, MID_VMM, LOGLEVEL_CRITICAL, "ERROR - SHOULD NOT HAPPEN - INVALID OBJECT TAG %02X", ((POB)pOb)->_tag);
        return;
    }
    if(!t->fActive) { return; }
    Ob_INCREF(pOb);
    InterlockedPushEntrySList(&t->R[pOb->iR].ListHeadEmpty, &pOb->SListEmpty);
}

PVMMOB_CACHE_MEM VmmCacheReserve(_In_ VMM_HANDLE H, _In_ DWORD dwTblTag)
{
    PVMM_CACHE_TABLE t;
    PVMMOB_CACHE_MEM pOb;
    PSLIST_ENTRY e;
    WORD cLoopProtect = 0;
    t = VmmCacheTableGet(H, dwTblTag);
    if(!t || !t->fActive) { return NULL; }
    while(!(e = InterlockedPopEntrySList(&t->R[t->iR].ListHeadEmpty))) {
        if(QueryDepthSList(&t->R[t->iR].ListHeadTotal) < t->cMaxMems) {
            // below max threshold -> create new
            pOb = Ob_AllocEx(H, t->tag, LMEM_ZEROINIT, sizeof(VMMOB_CACHE_MEM), NULL, (OB_CLEANUP_CB)VmmCache_CallbackRefCount1);
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
        VmmCacheClearPartial(H, dwTblTag);
        if(++cLoopProtect == VMM_CACHE_REGIONS) {
            VmmLog(H, MID_VMM, LOGLEVEL_WARNING, "SHOULD NOT HAPPEN - CACHE %04X DRAINED OF ENTRIES", dwTblTag);
            return NULL;
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
* -- H
* -- pOb
*/
VOID VmmCacheReserveReturn(_In_ VMM_HANDLE H, _In_opt_ PVMMOB_CACHE_MEM pOb)
{
    PVMM_CACHE_TABLE t;
    if(!pOb) { return; }
    t = VmmCacheTableGet(H, ((POB)pOb)->_tag);
    if(!t) {
        VmmLog(H, MID_VMM, LOGLEVEL_CRITICAL, "ERROR - SHOULD NOT HAPPEN - INVALID OBJECT TAG %02X", ((POB)pOb)->_tag);
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

VOID VmmCacheClose(_In_ VMM_HANDLE H, _In_ DWORD dwTblTag)
{
    PVMM_CACHE_TABLE t;
    PVMMOB_CACHE_MEM pOb;
    PSLIST_ENTRY e;
    DWORD iR;
    t = VmmCacheTableGet(H, dwTblTag);
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

VOID VmmCacheInitialize(_In_ VMM_HANDLE H, _In_ DWORD dwTblTag)
{
    DWORD iR, iMEM;
    PVMM_CACHE_TABLE t;
    PVMMOB_CACHE_MEM pOb;
    t = VmmCacheTableGet(H, dwTblTag);
    if(!t || t->fActive) { return; }
    for(iR = 0; iR < VMM_CACHE_REGIONS; iR++) {
        InitializeSRWLock(&t->R[iR].LockSRW);
        InitializeSListHead(&t->R[iR].ListHeadEmpty);
        InitializeSListHead(&t->R[iR].ListHeadInUse);
        InitializeSListHead(&t->R[iR].ListHeadTotal);
        if(VMM_CACHE_REGION_MEMS_INITALLOC) {
            for(iMEM = 0; iMEM < t->cMaxMems; iMEM++) {
                pOb = Ob_AllocEx(H, dwTblTag, LMEM_ZEROINIT, sizeof(VMMOB_CACHE_MEM), NULL, (OB_CLEANUP_CB)VmmCache_CallbackRefCount1);
                if(!pOb) { continue; }
                pOb->iR = iR;
                pOb->h.version = MEM_SCATTER_VERSION;
                pOb->h.cb = 0x1000;
                pOb->h.pb = pOb->pb;
                pOb->h.qwA = MEM_SCATTER_ADDR_INVALID;
                Ob_INCREF(pOb);
                InterlockedPushEntrySList(&t->R[iR].ListHeadEmpty, &pOb->SListEmpty);
                InterlockedPushEntrySList(&t->R[iR].ListHeadTotal, &pOb->SListTotal);
            }
        }
    }
    InitializeCriticalSection(&t->Lock);
    t->tag = dwTblTag;
    t->fActive = TRUE;
}

/*
* Invalidate a cache entry (if exists)
*/
VOID VmmCacheInvalidate_2(_In_ VMM_HANDLE H, _In_ DWORD dwTblTag, _In_ QWORD qwA)
{
    PVMM_CACHE_TABLE t;
    PVMMOB_CACHE_MEM pOb;
    t = VmmCacheTableGet(H, dwTblTag);
    if(!t || !t->fActive) { return; }
    while((pOb = VmmCacheGet(H, dwTblTag, qwA))) {
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

VOID VmmCacheInvalidate(_In_ VMM_HANDLE H, _In_ QWORD pa)
{
    VmmCacheInvalidate_2(H, VMM_CACHE_TAG_TLB, pa);
    VmmCacheInvalidate_2(H, VMM_CACHE_TAG_PHYS, pa);
}

PVMMOB_CACHE_MEM VmmCacheGet_FromDeviceOnMiss(_In_ VMM_HANDLE H, _In_ DWORD dwTblTag, _In_ DWORD dwTblTagSecondaryOpt, _In_ QWORD qwA)
{
    PVMMOB_CACHE_MEM pObMEM, pObReservedMEM;
    PMEM_SCATTER pMEM;
    pObMEM = VmmCacheGet(H, dwTblTag, qwA);
    if(pObMEM) { return pObMEM; }
    if((pObReservedMEM = VmmCacheReserve(H, dwTblTag))) {
        pMEM = &pObReservedMEM->h;
        pMEM->qwA = qwA;
        if(dwTblTagSecondaryOpt && (pObMEM = VmmCacheGet(H, dwTblTagSecondaryOpt, qwA))) {
            pMEM->f = TRUE;
            memcpy(pMEM->pb, pObMEM->pb, 0x1000);
            Ob_DECREF(pObMEM);
            pObMEM = NULL;
        }
        if(!pMEM->f) {
            LcReadScatter(H->hLC, 1, &pMEM);
        }
        if(pMEM->f) {
            Ob_INCREF(pObReservedMEM);
            VmmCacheReserveReturn(H, pObReservedMEM);
            return pObReservedMEM;
        }
        VmmCacheReserveReturn(H, pObReservedMEM);
    }
    return NULL;
}

#define VMM_TLB_PARALLEL_MAX        0x20

/*
* Helper function for VmmTlbGetPageTableEx.
* Function retrieves physical memory pages in parallel and puts them into the
* TLB cache upon success.
*/
VOID VmmTlbGetPageTableEx_RetrievePhysical(_In_ VMM_HANDLE H, _In_ PVMM_V2P_ENTRY *ppV2Ps, _In_ DWORD cV2Ps)
{
    DWORD i;
    PVMM_V2P_ENTRY pV2P;
    PVMMOB_CACHE_MEM pObPTE_Prev = NULL;
    PMEM_SCATTER pMEM, ppMEMs[VMM_TLB_PARALLEL_MAX] = { 0 };
    for(i = 0; i < cV2Ps; i++) {
        pV2P = ppV2Ps[i];
        if((pV2P->pObPTE = VmmCacheReserve(H, VMM_CACHE_TAG_TLB))) {
            pMEM = &pV2P->pObPTE->h;
            pMEM->qwA = pV2P->paPT;
            ppMEMs[i] = pMEM;
        }
    }
    LcReadScatter(H->hLC, cV2Ps, ppMEMs);
    for(i = 0; i < cV2Ps; i++) {
        pV2P = ppV2Ps[i];
        pMEM = ppMEMs[i];
        if(!pMEM || !pMEM->f || !VmmTlbPageTableVerify(H, pMEM->pb, pMEM->qwA, FALSE)) {
            // read failed:
            InterlockedIncrement64(&H->vmm.stat.cTlbReadFail);
            if(pMEM) { pMEM->f = FALSE; }
            VmmCacheReserveReturn(H, pV2P->pObPTE);
            pV2P->pObPTE = NULL;
            continue;
        }
        // read successful:
        Ob_INCREF(pV2P->pObPTE);
        VmmCacheReserveReturn(H, pV2P->pObPTE);
        InterlockedIncrement64(&H->vmm.stat.cTlbReadSuccess);
        pObPTE_Prev = pV2P->pObPTE;
        while((pV2P = pV2P->FLink)) {
            pV2P->pObPTE = Ob_INCREF(pObPTE_Prev);
            InterlockedIncrement64(&H->vmm.stat.cTlbCacheHit);
        }
    }
}

/*
* Retrieve multiple page tables (0x1000 bytes) via the TLB cache in parallel.
* Page table address is retrieved from pV2Ps[i].paPT
* Result is put into pV2Ps[i].pObPTE
* CALLER DECREF pV2Ps[0..N]->pObPTE
* -- H
* -- pV2Ps
* -- cV2Ps
* -- fCacheOnly
*/
VOID VmmTlbGetPageTableEx(_In_ VMM_HANDLE H, _In_ PVMM_V2P_ENTRY pV2Ps, _In_ DWORD cV2Ps, _In_ BOOL fCacheOnly)
{
    DWORD i, cPhys = 0;
    QWORD paPT = 0;
    PVMM_V2P_ENTRY pV2P;
    PVMMOB_CACHE_MEM pObPTE = NULL;
    PVMM_V2P_ENTRY ppV2Ps_Phys[VMM_TLB_PARALLEL_MAX];
    for(i = 0; i < cV2Ps; i++) {
        pV2P = pV2Ps + i;
        if(!pV2P->paPT) {
            continue;
        }
        if(pV2P->paPT == paPT) {
            pV2P->pObPTE = Ob_INCREF(pObPTE);
        }
        if(!pV2P->pObPTE) {
            paPT = pV2P->paPT;
            pV2P->pObPTE = VmmCacheGet(H, VMM_CACHE_TAG_TLB, paPT);
            pObPTE = pV2P->pObPTE;
        }
        if(pV2P->pObPTE) {
            InterlockedIncrement64(&H->vmm.stat.cTlbCacheHit);
        } else if(fCacheOnly || !paPT) {
            InterlockedIncrement64(&H->vmm.stat.cTlbReadFail);
        } else {
            if(cPhys && (paPT == ppV2Ps_Phys[cPhys - 1]->paPT)) {
                pV2P->FLink = ppV2Ps_Phys[cPhys - 1]->FLink;
                ppV2Ps_Phys[cPhys - 1]->FLink = pV2P;
            } else {
                pV2P->FLink = NULL;
                ppV2Ps_Phys[cPhys] = pV2P;
                cPhys++;
                if(cPhys >= VMM_TLB_PARALLEL_MAX) {
                    VmmTlbGetPageTableEx_RetrievePhysical(H, ppV2Ps_Phys, cPhys);
                    cPhys = 0;
                }
            }
        }
    }
    if(cPhys) {
        VmmTlbGetPageTableEx_RetrievePhysical(H, ppV2Ps_Phys, cPhys);
    }
}

/*
* Retrieve a page table from a given physical address (if possible).
* CALLER DECREF: return
* -- H
* -- pa
* -- fCacheOnly
* -- return = Cache entry on success, NULL on fail.
*/
PVMMOB_CACHE_MEM VmmTlbGetPageTable(_In_ VMM_HANDLE H, _In_ QWORD pa, _In_ BOOL fCacheOnly)
{
    PVMMOB_CACHE_MEM pObMEM;
    pObMEM = VmmCacheGet(H, VMM_CACHE_TAG_TLB, pa);
    if(pObMEM) {
        InterlockedIncrement64(&H->vmm.stat.cTlbCacheHit);
        return pObMEM;
    }
    if(fCacheOnly) { return NULL; }
    // try retrieve from (1) TLB cache, (2) PHYS cache, (3) device
    pObMEM = VmmCacheGet_FromDeviceOnMiss(H, VMM_CACHE_TAG_TLB, 0, pa);
    if(!pObMEM) {
        InterlockedIncrement64(&H->vmm.stat.cTlbReadFail);
        return NULL;
    }
    InterlockedIncrement64(&H->vmm.stat.cTlbReadSuccess);
    if(VmmTlbPageTableVerify(H, pObMEM->h.pb, pObMEM->h.qwA, FALSE)) {
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
* -- H
* -- paDTB
* -- fUserOnly
* -- va
* -- ppa
* -- return
*/
_Success_(return)
BOOL VmmVirt2PhysEx(_In_ VMM_HANDLE H, _In_ QWORD paDTB, _In_ BOOL fUserOnly, _In_ QWORD va, _Out_ PQWORD ppa)
{
    *ppa = 0;
    if(H->vmm.tpMemoryModel == VMM_MEMORYMODEL_NA) { return FALSE; }
    return H->vmm.fnMemoryModel.pfnVirt2Phys(H, paDTB, fUserOnly, -1, va, ppa);
}

/*
* Translate a virtual address to a physical address by walking the page tables.
* The successfully translated Physical Address (PA) is returned in ppa.
* Upon fail the PTE will be returned in ppa (if possible) - which may be used
* to further lookup virtual memory in case of PageFile or Win10 MemCompression.
* -- H
* -- pProcess
* -- va
* -- ppa
* -- return
*/
_Success_(return)
BOOL VmmVirt2Phys(_In_ VMM_HANDLE H, _In_opt_ PVMM_PROCESS pProcess, _In_ QWORD va, _Out_ PQWORD ppa)
{
    *ppa = 0;
    if(!pProcess || (H->vmm.tpMemoryModel == VMM_MEMORYMODEL_NA)) { return FALSE; }
    return H->vmm.fnMemoryModel.pfnVirt2Phys(H, pProcess->paDTB, pProcess->fUserOnly, -1, va, ppa);
}

/*
* Spider the TLB (page table cache) to load all page table pages into the cache.
* This is done to speed up various subsequent virtual memory accesses.
* NB! pages may fall out of the cache if it's in heavy use or doe to timing.
* -- H
* -- pProcess
*/
VOID VmmTlbSpider(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess)
{
    if(H->vmm.tpMemoryModel == VMM_MEMORYMODEL_NA) { return; }
    H->vmm.fnMemoryModel.pfnTlbSpider(H, pProcess);
}

/*
* Try verify that a supplied page table in pb is valid by analyzing it.
* -- H
* -- pb = 0x1000 bytes containing the page table page.
* -- pa = physical address if the page table page.
* -- fSelfRefReq = is a self referential entry required to be in the map? (PML4 for Windows).
*/
BOOL VmmTlbPageTableVerify(_In_ VMM_HANDLE H, _Inout_ PBYTE pb, _In_ QWORD pa, _In_ BOOL fSelfRefReq)
{
    if(H->vmm.tpMemoryModel == VMM_MEMORYMODEL_NA) { return FALSE; }
    return H->vmm.fnMemoryModel.pfnTlbPageTableVerify(H, pb, pa, fSelfRefReq);
}

/*
* Prefetch a set of physical addresses contained in pTlbPrefetch into the Tlb.
* NB! pTlbPrefetch must not be updated/altered during the function call.
* -- H
* -- pProcess
* -- pTlbPrefetch = the page table addresses to prefetch (on entry) and empty set on exit.
*/
VOID VmmTlbPrefetch(_In_ VMM_HANDLE H, _In_ POB_SET pTlbPrefetch)
{
    QWORD pbTlb = 0;
    DWORD cTlbs, cTlbsMax, i = 0;
    PPVMMOB_CACHE_MEM ppObMEMs = NULL;
    PPMEM_SCATTER ppMEMs = NULL;
    cTlbsMax = VMM_CACHE_REGION_MEMS_TLB >> 1;
    if(!(cTlbs = min(cTlbsMax, ObSet_Size(pTlbPrefetch)))) { goto fail; }
    if(!(ppMEMs = LocalAlloc(0, cTlbs * sizeof(PMEM_SCATTER)))) { goto fail; }
    if(!(ppObMEMs = LocalAlloc(0, cTlbs * sizeof(PVMMOB_CACHE_MEM)))) { goto fail; }
    while((cTlbs = min(cTlbsMax, ObSet_Size(pTlbPrefetch)))) {   // protect cache bleed -> max cTlbsMax pages/round
        for(i = 0; i < cTlbs; i++) {
            if((ppObMEMs[i] = VmmCacheReserve(H, VMM_CACHE_TAG_TLB))) {
                ppMEMs[i] = &ppObMEMs[i]->h;
                ppMEMs[i]->qwA = ObSet_Pop(pTlbPrefetch);
            } else {
                cTlbs = i;
                break;
            }
        }
        LcReadScatter(H->hLC, cTlbs, ppMEMs);
        for(i = 0; i < cTlbs; i++) {
            if(ppMEMs[i]->f && !VmmTlbPageTableVerify(H, ppMEMs[i]->pb, ppMEMs[i]->qwA, FALSE)) {
                ppMEMs[i]->f = FALSE;  // "fail" invalid page table read
            }
            VmmCacheReserveReturn(H, ppObMEMs[i]);
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
* -- H
* -- pProcess
* -- pPrefetchPages
* -- flags
*/
VOID VmmCachePrefetchPages(_In_ VMM_HANDLE H, _In_opt_ PVMM_PROCESS pProcess, _In_opt_ POB_SET pPrefetchPages, _In_ QWORD flags)
{
    QWORD qwA = 0;
    DWORD cPages, iMEM = 0;
    PPMEM_SCATTER ppMEMs = NULL;
    cPages = min(VMM_CACHE_REGION_MEMS_PHYS, ObSet_Size(pPrefetchPages));
    if(!cPages || (H->vmm.flags & VMM_FLAG_NOCACHE)) { return; }
    if(!LcAllocScatter1(cPages, &ppMEMs)) { return; }
    for(iMEM = 0; iMEM < cPages; iMEM++) {
        qwA = ObSet_Get(pPrefetchPages, iMEM);
        ppMEMs[iMEM]->qwA = qwA & ~0xfff;
    }
    if(pProcess) {
        VmmReadScatterVirtual(H, pProcess, ppMEMs, iMEM, flags | VMM_FLAG_CACHE_RECENT_ONLY);
    } else {
        VmmReadScatterPhysical(H, ppMEMs, iMEM, flags | VMM_FLAG_CACHE_RECENT_ONLY);
    }
    LcMemFree(ppMEMs);
}

/*
* Prefetch a set of addresses. This is useful when reading data from somewhat
* known addresses over higher latency connections.
* -- H
* -- pProcess
* -- cAddresses
* -- ... = variable list of total cAddresses of addresses of type QWORD.
*/
VOID VmmCachePrefetchPages2(_In_ VMM_HANDLE H, _In_opt_ PVMM_PROCESS pProcess, _In_ DWORD cAddresses, ...)
{
    va_list arguments;
    POB_SET pObSet = NULL;
    if(!cAddresses || !(pObSet = ObSet_New(H))) { return; }
    va_start(arguments, cAddresses);
    while(cAddresses) {
        ObSet_Push(pObSet, va_arg(arguments, QWORD) & ~0xfff);
        cAddresses--;
    }
    va_end(arguments);
    VmmCachePrefetchPages(H, pProcess, pObSet, 0);
    Ob_DECREF(pObSet);
}

/*
* Prefetch a set of addresses contained in pPrefetchPagesNonPageAligned into
* the cache by first converting them to page aligned pages. This is used when
* reading data from somewhat known addresses over higher latency connections.
* NB! pPrefetchPagesNonPageAligned must not be altered during the function call.
* -- H
* -- pProcess
* -- pPrefetchPagesNonPageAligned
* -- cb
* -- flags
*/
VOID VmmCachePrefetchPages3(_In_ VMM_HANDLE H, _In_opt_ PVMM_PROCESS pProcess, _In_opt_ POB_SET pPrefetchPagesNonPageAligned, _In_ DWORD cb, _In_ QWORD flags)
{
    QWORD qwA = 0;
    POB_SET pObSetAlign;
    if(!cb || !pPrefetchPagesNonPageAligned) { return; }
    if(0 == ObSet_Size(pPrefetchPagesNonPageAligned)) { return; }
    if(!(pObSetAlign = ObSet_New(H))) { return; }
    while((qwA = ObSet_GetNext(pPrefetchPagesNonPageAligned, qwA))) {
        ObSet_Push_PageAlign(pObSetAlign, qwA, cb);
    }
    VmmCachePrefetchPages(H, pProcess, pObSetAlign, flags);
    Ob_DECREF(pObSetAlign);
}

/*
* Prefetch an array of optionally non-page aligned addresses. This is useful
* when reading data from somewhat known addresses over higher latency connections.
* -- H
* -- pProcess
* -- cAddresses
* -- pqwAddresses = array of addresses to fetch
* -- cb
* -- flags
*/
VOID VmmCachePrefetchPages4(_In_ VMM_HANDLE H, _In_opt_ PVMM_PROCESS pProcess, _In_ DWORD cAddresses, _In_ PQWORD pqwAddresses, _In_ DWORD cb, _In_ QWORD flags)
{
    POB_SET pObSet = NULL;
    if(!cAddresses || !(pObSet = ObSet_New(H))) { return; }
    while(cAddresses) {
        cAddresses--;
        if(pqwAddresses[cAddresses]) {
            ObSet_Push_PageAlign(pObSet, pqwAddresses[cAddresses], cb);
        }
    }
    VmmCachePrefetchPages(H, pProcess, pObSet, 0);
    Ob_DECREF(pObSet);
}

/*
* Prefetch memory of optionally non-page aligned addresses which are derived
* from pmPrefetchObjects by the pfnFilter filter function.
* -- H
* -- pProcess
* -- pmPrefetch = map of objects.
* -- cb
* -- flags
* -- pfnFilterCB = filter as required by ObMap_FilterSet function.
* -- return = at least one object is found to be prefetched into cache.
*/
BOOL VmmCachePrefetchPages5(_In_ VMM_HANDLE H, _In_opt_ PVMM_PROCESS pProcess, _In_opt_ POB_MAP pmPrefetch, _In_ DWORD cb, _In_ QWORD flags, _In_ OB_MAP_FILTERSET_PFN_CB pfnFilterCB)
{
    POB_SET psObCache = ObMap_FilterSet(pmPrefetch, NULL, pfnFilterCB);
    BOOL fResult = ObSet_Size(psObCache) > 0;
    VmmCachePrefetchPages3(H, pProcess, psObCache, cb, flags);
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

VOID VmmProcess_TokenTryEnsure(_In_ VMM_HANDLE H, _In_ PVMMOB_PROCESS_TABLE pt)
{
    BOOL f, f32 = H->vmm.f32;
    DWORD i = 0, cTokens = 0;
    QWORD va, *pvaTokens = NULL;
    PVMM_PROCESS pProcess = NULL;
    PVMM_PROCESS *ppProcess = NULL;
    PVMMOB_TOKEN *ppObTokens = NULL;
    PVMM_OFFSET_EPROCESS poe = &H->vmm.offset.EPROCESS;
    // Init:
    f = poe->opt.TOKEN_TokenId &&
        (pvaTokens = LocalAlloc(LMEM_ZEROINIT, pt->c * sizeof(QWORD))) &&
        (ppProcess = LocalAlloc(LMEM_ZEROINIT, pt->c * sizeof(PVMM_PROCESS))) &&
        (ppObTokens = LocalAlloc(LMEM_ZEROINIT, pt->c * sizeof(PVMMOB_TOKEN)));
    if(!f) { goto fail; }
    // 2: Get Processes and Token VAs:
    while((pProcess = ObMap_GetNext(pt->pObProcessMap, pProcess))) {
        if(!pProcess->win.Token) {
            va = VMM_PTR_OFFSET(f32, pProcess->win.EPROCESS.pb, poe->opt.Token) & (f32 ? ~0x7 : ~0xf);
            if(VMM_KADDR(f32, va)) {
                ppProcess[cTokens] = pProcess;
                pvaTokens[cTokens] = va;
                cTokens++;
            }
        }
    }
    // 3: Read Tokens:
    if(!VmmWinToken_Initialize(H, cTokens, pvaTokens, ppObTokens)) { goto fail; }
    // 4: Assign Tokens:
    for(i = 0; i < cTokens; i++) {
        ppProcess[i]->win.Token = ppObTokens[i];
    }
fail:
    LocalFree(pvaTokens);
    LocalFree(ppProcess);
    LocalFree(ppObTokens);
}

/*
* Global Synchronization/Lock of VmmProcess_TokenTryEnsure()
* -- H
* -- pt
* -- pProcess
*/
VOID VmmProcess_TokenTryEnsureLock(_In_ VMM_HANDLE H)
{
    PVMMOB_PROCESS_TABLE ptOb = (PVMMOB_PROCESS_TABLE)ObContainer_GetOb(H->vmm.pObCPROC);
    if(ptOb && !ptOb->fTokenInit) {
        EnterCriticalSection(&H->vmm.LockMaster);
        if(!ptOb->fTokenInit) {
            VmmProcess_TokenTryEnsure(H, ptOb);
            ptOb->fTokenInit = TRUE;
        }
        LeaveCriticalSection(&H->vmm.LockMaster);
    }
    Ob_DECREF(ptOb);
}

/*
* Retrieve a process for a given PID and optional PVMMOB_PROCESS_TABLE.
* CALLER DECREF: return
* -- H
* -- pt
* -- dwPID
* -- flags = 0 (recommended) or VMM_FLAG_PROCESS_TOKEN.
* -- return
*/
PVMM_PROCESS VmmProcessGetEx(_In_ VMM_HANDLE H, _In_opt_ PVMMOB_PROCESS_TABLE pt, _In_ DWORD dwPID, _In_ QWORD flags)
{
    BOOL fToken = ((flags | H->vmm.flags) & VMM_FLAG_PROCESS_TOKEN);
    PVMM_PROCESS pObProcess, pObProcessClone;
    PVMMOB_PROCESS_TABLE ptOb = NULL;
    // 1: ensure process table:
    if(!pt) {
        ptOb = (PVMMOB_PROCESS_TABLE)ObContainer_GetOb(H->vmm.pObCPROC);
        if(!ptOb) { return NULL; }
        pObProcess = VmmProcessGetEx(H, ptOb, dwPID, flags);
        Ob_DECREF(ptOb);
        return pObProcess;
    }
    // 2: get process:
    if((pObProcess = ObMap_GetByKey(pt->pObProcessMap, (QWORD)dwPID))) {
        if(fToken && !pt->fTokenInit) { VmmProcess_TokenTryEnsureLock(H); }
        return pObProcess;
    }
    // 3: try get process with kernel memory (if requested in flags):
    if(dwPID & VMM_PID_PROCESS_CLONE_WITH_KERNELMEMORY) {
        if((pObProcess = VmmProcessGetEx(H, pt, dwPID & ~VMM_PID_PROCESS_CLONE_WITH_KERNELMEMORY, flags))) {
            if((pObProcessClone = VmmProcessClone(H, pObProcess))) {
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
* -- H
* -- dwPID
* -- return = a process struct, or NULL if not found.
*/
__forceinline PVMM_PROCESS VmmProcessGet(_In_ VMM_HANDLE H, _In_ DWORD dwPID)
{
    return VmmProcessGetEx(H, NULL, dwPID, 0);
}

/*
* Retrieve processes sorted in a map keyed by either EPROCESS or PID.
* CALLER DECREF: return
* -- H
* -- fByEPROCESS = TRUE: keyed by vaEPROCESS, FALSE: keyed by PID.
* -- flags = 0 (recommended) or VMM_FLAG_PROCESS_[TOKEN|SHOW_TERMINATED].
* -- return
*/
_Success_(return != NULL)
POB_MAP VmmProcessGetAll(_In_ VMM_HANDLE H, _In_ BOOL fByEPROCESS, _In_ QWORD flags)
{
    BOOL fShowTerminated = ((flags | H->vmm.flags) & VMM_FLAG_PROCESS_SHOW_TERMINATED);
    BOOL fToken = ((flags | H->vmm.flags) & VMM_FLAG_PROCESS_TOKEN);
    PVMMOB_PROCESS_TABLE ptOb = NULL;
    POB_MAP pmOb = NULL;
    PVMM_PROCESS pProcess = NULL;
    QWORD qwKey = 0;
    if(!(pmOb = ObMap_New(H, OB_MAP_FLAGS_OBJECT_OB))) { goto fail; }
    if(!(ptOb = (PVMMOB_PROCESS_TABLE)ObContainer_GetOb(H->vmm.pObCPROC))) { goto fail; }
    while((pProcess = ObMap_GetNext(ptOb->pObProcessMap, pProcess))) {
        if(!pProcess->dwState || fShowTerminated) {
            if(fToken && !ptOb->fTokenInit) { VmmProcess_TokenTryEnsureLock(H); }
            qwKey = fByEPROCESS ? pProcess->win.EPROCESS.va : pProcess->dwPID;
            ObMap_Push(pmOb, qwKey, pProcess);
        }
    }
    Ob_INCREF(pmOb);
fail:
    Ob_DECREF(ptOb);
    return Ob_DECREF(pmOb);
}

/*
* Retrieve the next process given a process and a process table. This may be
* useful when iterating over a process list.
* FUNCTION DECREF: pObProcess
* CALLER DECREF: return
* -- H
* -- pt = the process table to iterate over (only taken into account when pProcess is NULL).
* -- pObProcess = a process struct, or NULL if first.
*    NB! function DECREF's  pProcess and must not be used after call!
* -- flags = 0 (recommended) or VMM_FLAG_PROCESS_[TOKEN|SHOW_TERMINATED].
* -- return = a process struct, or NULL if not found.
*/
PVMM_PROCESS VmmProcessGetNextEx(_In_ VMM_HANDLE H, _In_opt_ PVMMOB_PROCESS_TABLE pt, _In_opt_ PVMM_PROCESS pObProcess, _In_ QWORD flags)
{
    BOOL fToken = ((flags | H->vmm.flags) & VMM_FLAG_PROCESS_TOKEN);
    BOOL fShowTerminated = ((flags | H->vmm.flags) & VMM_FLAG_PROCESS_SHOW_TERMINATED);
    PVMMOB_PROCESS_TABLE ptOb = NULL;
    PVMM_PROCESS pProcessNext = NULL;
    DWORD dwPID = 0;
    // 1: ensure process table:
    if(!pt) {
        ptOb = (PVMMOB_PROCESS_TABLE)ObContainer_GetOb(H->vmm.pObCPROC);
        if(!ptOb) {
            Ob_DECREF(pObProcess);
            return NULL;
        }
        pObProcess = VmmProcessGetNextEx(H, ptOb, pObProcess, flags);
        Ob_DECREF(ptOb);
        return pObProcess;
    }
    // 2: get next process:
    dwPID = pObProcess ? pObProcess->dwPID : 0;
    while((pObProcess = ObMap_GetNextByKeySorted(pt->pObProcessMap, (QWORD)dwPID, pObProcess))) {
        if(!pObProcess->dwState || fShowTerminated) {
            if(fToken && !pt->fTokenInit) { VmmProcess_TokenTryEnsureLock(H); }
            return pObProcess;
        }
        dwPID = pObProcess->dwPID;
    }
    return NULL;
}

/*
* Retrieve the next process given a process. This may be useful when iterating
* over a process list.
* FUNCTION DECREF: pObProcess
* CALLER DECREF: return
* -- H
* -- pObProcess = a process struct, or NULL if first.
*    NB! function DECREF's  pObProcess and must not be used after call!
* -- flags = 0 (recommended) or VMM_FLAG_PROCESS_[TOKEN|SHOW_TERMINATED]
* -- return = a process struct, or NULL if not found.
*/
PVMM_PROCESS VmmProcessGetNext(_In_ VMM_HANDLE H, _In_opt_ PVMM_PROCESS pObProcess, _In_ QWORD flags)
{
    return VmmProcessGetNextEx(H, NULL, pObProcess, flags);
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
    LocalFree(pProcessStatic->UserProcessParams.uszWindowTitle);
    LocalFree(pProcessStatic->UserProcessParams.uszEnvironment);
}

/*
* Initialize a new static context that will remain between process refreshes.
* This should only be done at first process initialization of that PID.
*/
_Success_(return)
BOOL VmmProcessStatic_Initialize(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess)
{
    if(pProcess->pObPersistent) { return FALSE; }
    if(!(pProcess->pObPersistent = Ob_AllocEx(H, OB_TAG_VMM_PROCESS_PERSISTENT, LMEM_ZEROINIT, sizeof(VMMOB_PROCESS_PERSISTENT), VmmProcessStatic_CloseObCallback, NULL))) { goto fail; }
    if(!(pProcess->pObPersistent->pObCMapVadPrefetch = ObContainer_New())) { goto fail; }
    if(!(pProcess->pObPersistent->pObCLdrModulesPrefetch32 = ObContainer_New())) { goto fail; }
    if(!(pProcess->pObPersistent->pObCLdrModulesPrefetch64 = ObContainer_New())) { goto fail; }
    if(!(pProcess->pObPersistent->pObCLdrModulesInjected = ObContainer_New())) { goto fail; }
    if(!(pProcess->pObPersistent->pObCMapThreadPrefetch = ObContainer_New())) { goto fail; }
    return TRUE;
fail:
    Ob_DECREF_NULL(&pProcess->pObPersistent);
    return FALSE;
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
    Ob_DECREF(pProcess->pObPersistent);
    Ob_DECREF(pProcess->win.Token);
    // plugin cleanup below
    Ob_DECREF(pProcess->Plugin.pObCLdrModulesDisplayCache);
    Ob_DECREF(pProcess->Plugin.pObCPeDumpDirCache);
    Ob_DECREF(pProcess->Plugin.pObCPhys2Virt);
    // delete lock
    DeleteCriticalSection(&pProcess->LockUpdate);
    DeleteCriticalSection(&pProcess->LockPlugin);
}

VOID VmmProcessClone_CloseObCallback(_In_ PVOID pVmmOb)
{
    PVMM_PROCESS pProcessClone = (PVMM_PROCESS)pVmmOb;
    // decref clone parent
    Ob_DECREF(pProcessClone->VmmInternal.pObProcessCloneParent);
    // delete lock
    DeleteCriticalSection(&pProcessClone->LockUpdate);
    DeleteCriticalSection(&pProcessClone->LockPlugin);
}

/*
* Object manager callback before 'process table' object cleanup - decrease
* refcount of all contained 'process' objects.
*/
VOID VmmProcessTable_CloseObCallback(_In_ PVMMOB_PROCESS_TABLE pt)
{
    Ob_DECREF(pt->pObCNewPROC);
    Ob_DECREF(pt->pObProcessMap);
}

/*
* Clone an original process entry creating a shallow clone. The user of this
* shallow clone may use it to set the fUserOnly flag to FALSE on an otherwise
* user-mode process to be able to access the whole kernel space for a standard
* user-mode process.
* NB! USE WITH EXTREME CARE - MAY CRASH VMM IF USED MORE GENERALLY!
* CALLER DECREF: return
* -- H
* -- pProcess
* -- return
*/
PVMM_PROCESS VmmProcessClone(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess)
{
    PVMM_PROCESS pObProcessClone;
    if(pProcess->VmmInternal.pObProcessCloneParent) { return NULL; }
    pObProcessClone = (PVMM_PROCESS)Ob_AllocEx(H, OB_TAG_VMM_PROCESS_CLONE, LMEM_ZEROINIT, sizeof(VMM_PROCESS), VmmProcessClone_CloseObCallback, NULL);
    if(!pObProcessClone) { return NULL; }
    memcpy((PBYTE)pObProcessClone + sizeof(OB), (PBYTE)pProcess + sizeof(OB), pProcess->ObHdr.cbData);
    pObProcessClone->VmmInternal.pObProcessCloneParent = Ob_INCREF(pProcess);
    InitializeCriticalSection(&pObProcessClone->LockUpdate);
    InitializeCriticalSection(&pObProcessClone->LockPlugin);
    return pObProcessClone;
}

#define VFSLIST_ASCII      "________________________________ !_#$%&'()_+,-._0123456789_;_=__@ABCDEFGHIJKLMNOPQRSTUVWXYZ[_]^_`abcdefghijklmnopqrstuvwxyz{_}~ "

/*
* Create a new process object. New process object are created in a separate
* data structure and won't become visible to the "Process" functions until
* after the VmmProcessCreateFinish have been called.
* NB! REQUIRE SINGLE THREAD: [H->vmm.LockMaster]
* CALLER DECREF: return
* -- H
* -- fTotalRefresh = create a completely new entry - i.e. do not copy any form
*                    of data from the old entry such as module and memory maps.
* -- dwPID
* -- dwPPID = parent PID (if any)
* -- dwState
* -- paDTB_Kernel
* -- paDTB_UserOpt
* -- szName
* -- fUserOnly = user mode process (hide supervisor pages from view)
* -- pbEPROCESS
* -- cbEPROCESS
* -- return
*/
PVMM_PROCESS VmmProcessCreateEntry(_In_ VMM_HANDLE H, _In_ BOOL fTotalRefresh, _In_ DWORD dwPID, _In_ DWORD dwPPID, _In_ DWORD dwState, _In_ QWORD paDTB_Kernel, _In_ QWORD paDTB_UserOpt, _In_ CHAR szName[16], _In_ BOOL fUserOnly, _In_reads_opt_(cbEPROCESS) PBYTE pbEPROCESS, _In_ DWORD cbEPROCESS)
{
    UCHAR ch, ich;
    PVMMOB_PROCESS_TABLE ptOld = NULL, ptNew = NULL;
    QWORD cEmpty = 0, cValid = 0;
    PVMM_PROCESS pProcess = NULL, pProcessOld = NULL;
    PVMMOB_CACHE_MEM pObDTB = NULL;
    BOOL fValidDTB = FALSE;
    // 1: Sanity check DTB
    if(dwState == 0) {
        if((pObDTB = VmmTlbGetPageTable(H, paDTB_Kernel & ~0xfff, FALSE))) {
            fValidDTB = VmmTlbPageTableVerify(H, pObDTB->h.pb, paDTB_Kernel, (H->vmm.tpSystem == VMM_SYSTEM_WINDOWS_64));
            Ob_DECREF(pObDTB);
        }
        if(!fValidDTB) {
            VmmLog(H, MID_PROCESS, LOGLEVEL_4_VERBOSE, "BAD DTB: PID=%i DTB=%016llx", dwPID, paDTB_Kernel);
        }
    }
    // 2: Allocate new 'Process Table' (if not already existing)
    ptOld = (PVMMOB_PROCESS_TABLE)ObContainer_GetOb(H->vmm.pObCPROC);
    if(!ptOld) { goto fail; }
    ptNew = (PVMMOB_PROCESS_TABLE)ObContainer_GetOb(ptOld->pObCNewPROC);
    if(!ptNew) {
        ptNew = (PVMMOB_PROCESS_TABLE)Ob_AllocEx(H, OB_TAG_VMM_PROCESSTABLE, LMEM_ZEROINIT, sizeof(VMMOB_PROCESS_TABLE), (OB_CLEANUP_CB)VmmProcessTable_CloseObCallback, NULL);
        if(!ptNew) { goto fail; }
        ptNew->pObCNewPROC = ObContainer_New();
        ptNew->pObProcessMap = ObMap_New(H, OB_MAP_FLAGS_OBJECT_OB);
        if(!ptNew->pObCNewPROC || !ptNew->pObProcessMap) { goto fail; }
        ObContainer_SetOb(ptOld->pObCNewPROC, ptNew);
    }
    // 3: Sanity check - process to create not already in 'new' table.
    pProcess = VmmProcessGetEx(H, ptNew, dwPID, 0);
    if(pProcess) { goto fail; }
    // 4: Prepare existing item, or create new item, for new PID
    if(!fTotalRefresh) {
        pProcess = VmmProcessGetEx(H, ptOld, dwPID, 0);
    }
    if(!pProcess) {
        pProcess = (PVMM_PROCESS)Ob_AllocEx(H, OB_TAG_VMM_PROCESS, LMEM_ZEROINIT, sizeof(VMM_PROCESS), VmmProcess_CloseObCallback, NULL);
        if(!pProcess) { goto fail; }
        if(!InitializeCriticalSectionAndSpinCount(&pProcess->LockUpdate, 4096)) { goto fail; }
        InitializeCriticalSection(&pProcess->LockPlugin);
        // copy process short name in a nice way substituting any corrupt chars:
        for(ich = 0; ich < 15; ich++) {
            ch = szName[ich];
            if(ch < 128) {
                if(ch == 0) { break; }
                ch = VFSLIST_ASCII[ch];
            } else {
                ch = '_';
            }
            pProcess->szName[ich] = ch;
        }
        pProcess->dwPID = dwPID;
        pProcess->dwPPID = dwPPID;
        pProcess->dwState = dwState;
        pProcess->paDTB = fValidDTB ? paDTB_Kernel : 0;
        pProcess->paDTB_Kernel = paDTB_Kernel;
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
        if((pProcessOld = VmmProcessGet(H, dwPID))) {
            pProcess->pObPersistent = (PVMMOB_PROCESS_PERSISTENT)Ob_INCREF(pProcessOld->pObPersistent);
            Ob_DECREF_NULL(&pProcessOld);
        } else {
            if(!VmmProcessStatic_Initialize(H, pProcess)) { goto fail; }
        }
    }
    // 5: Optional DTB user override:
    if(pProcess->pObPersistent->paDTB_Override) {
        pProcess->paDTB = pProcess->pObPersistent->paDTB_Override;
        VmmLog(H, MID_PROCESS, LOGLEVEL_6_TRACE, "DTB OVERRIDE: PID=%i DTB=%016llx OLD_DTB=%016llx", dwPID, pProcess->paDTB, pProcess->paDTB_Kernel);
    }
    // 6: Install new PID
    if(ObMap_Push(ptNew->pObProcessMap, (QWORD)pProcess->dwPID, pProcess)) {
        ptNew->cActive += (pProcess->dwState == 0) ? 1 : 0;
        ptNew->c++;
    }
    Ob_DECREF(ptOld);
    Ob_DECREF(ptNew);
    return pProcess;
fail:
    Ob_DECREF(pProcess);
    Ob_DECREF(ptOld);
    Ob_DECREF(ptNew);
    return NULL;
}

/*
* Create a new "fake" terminated process entry. This is useful when terminated
* processes are not available in the system but can be discovered by other means.
* -- H
* -- dwPID
* -- dwPPID
* -- ftCreate
* -- ftExit
* -- szShortName
* -- uszLongName
* -- return
*/
_Success_(return)
BOOL VmmProcessCreateTerminatedFakeEntry(_In_ VMM_HANDLE H, _In_ DWORD dwPID, _In_ DWORD dwPPID, _In_ QWORD ftCreate, _In_ QWORD ftExit, _In_reads_(15) LPSTR szShortName, _In_ LPSTR uszLongName)
{
    PVMM_PROCESS pTProc = NULL;
    PVMMOB_PROCESS_PERSISTENT pProcPers = NULL;
    PVMMOB_PROCESS_TABLE ptOld = NULL, ptNew = NULL;
    BYTE pbE[0x1000] = { 0 };
    if(!H->vmm.offset.EPROCESS.opt.CreateTime || !H->vmm.offset.EPROCESS.opt.ExitTime) { return FALSE; }
    if(!dwPID || !dwPPID || !ftCreate || !ftExit || !szShortName || !uszLongName || !szShortName[0] || !uszLongName[0]) { return FALSE; }
    // 1: Fake EPROCESS:
    *(PBYTE)(pbE + H->vmm.offset.EPROCESS.State) = 0xff;
    *(PDWORD)(pbE + H->vmm.offset.EPROCESS.PID) = dwPID;
    *(PDWORD)(pbE + H->vmm.offset.EPROCESS.PPID) = dwPPID;
    *(PQWORD)(pbE + H->vmm.offset.EPROCESS.opt.CreateTime) = ftCreate;
    *(PQWORD)(pbE + H->vmm.offset.EPROCESS.opt.ExitTime) = ftExit;
    memcpy(pbE + H->vmm.offset.EPROCESS.Name, szShortName, 15);
    // 2: Allocate new 'Process Table' (if not already existing) and copy over all existing processes:
    ptOld = (PVMMOB_PROCESS_TABLE)ObContainer_GetOb(H->vmm.pObCPROC);
    if(!ptOld) { return FALSE; }
    ptNew = (PVMMOB_PROCESS_TABLE)ObContainer_GetOb(ptOld->pObCNewPROC);
    if(!ptNew) {
        ptNew = (PVMMOB_PROCESS_TABLE)Ob_AllocEx(H, OB_TAG_VMM_PROCESSTABLE, LMEM_ZEROINIT, sizeof(VMMOB_PROCESS_TABLE), (OB_CLEANUP_CB)VmmProcessTable_CloseObCallback, NULL);
        if(!ptNew) { return FALSE; }
        ptNew->pObCNewPROC = ObContainer_New();
        ptNew->pObProcessMap = ObMap_New(H, OB_MAP_FLAGS_OBJECT_OB);
        if(!ptNew->pObCNewPROC || !ptNew->pObProcessMap) { return FALSE; }
        ObContainer_SetOb(ptOld->pObCNewPROC, ptNew);
        // move all old processes to new table:
        ObMap_PushAll(ptNew->pObProcessMap, ptOld->pObProcessMap);
        ptNew->cActive = ptOld->cActive;
        ptNew->c = ptOld->c;
    }
    // 3: Push new fake process:
    pTProc = VmmProcessCreateEntry(H, FALSE, dwPID, dwPPID, 0xff, 0, 0, szShortName, TRUE, pbE, H->vmm.offset.EPROCESS.cbMaxOffset + 0x10);
    // 4: Update static process info with long name:
    if(pTProc && !pTProc->pObPersistent->uszNameLong) {
        pProcPers = pTProc->pObPersistent;
        CharUtil_UtoU(uszLongName, -1, NULL, 0, &pProcPers->uszPathKernel, NULL, CHARUTIL_FLAG_ALLOC);
        pProcPers->cuszPathKernel = (WORD)strlen(pProcPers->uszPathKernel);
        // locate FullName by skipping to last \ character.
        pProcPers->uszNameLong = (LPSTR)CharUtil_PathSplitLast(pProcPers->uszPathKernel);
        pProcPers->cuszNameLong = (WORD)strlen(pProcPers->uszNameLong);
    }
    Ob_DECREF(pTProc);
    return TRUE;
}

/*
* Try to force clear the internal state of a process object without refreshing
* the whole process list.
* This may be useful when a quick update of a process must take place.
* This is may however lead to potential race conditions and possible corrpution!
* Use with extreme care at own risk!
* -- H
* -- pProcess
*/
VOID VmmProcessForceClearState_DoNotUse(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess)
{
    EnterCriticalSection(&pProcess->LockUpdate);
    EnterCriticalSection(&H->vmm.LockMaster);
    if(pProcess->pObPersistent->paDTB_Override && (pProcess->paDTB != pProcess->pObPersistent->paDTB_Override)) {
        pProcess->paDTB = pProcess->pObPersistent->paDTB_Override;
        pProcess->fTlbSpiderDone = FALSE;
    }
    Ob_DECREF_NULL(&pProcess->Map.pObPte);
    Ob_DECREF_NULL(&pProcess->Map.pObVad);
    Ob_DECREF_NULL(&pProcess->Map.pObModule);
    Ob_DECREF_NULL(&pProcess->Map.pObUnloadedModule);
    Ob_DECREF_NULL(&pProcess->Map.pObHeap);
    Ob_DECREF_NULL(&pProcess->Map.pObThread);
    Ob_DECREF_NULL(&pProcess->Map.pObHandle);
    ObContainer_SetOb(pProcess->Plugin.pObCLdrModulesDisplayCache, NULL);
    ObContainer_SetOb(pProcess->Plugin.pObCPeDumpDirCache, NULL);
    ObContainer_SetOb(pProcess->Plugin.pObCPhys2Virt, NULL);
    LeaveCriticalSection(&H->vmm.LockMaster);
    LeaveCriticalSection(&pProcess->LockUpdate);
}

/*
* Activate the pending, not yet active, processes added by VmmProcessCreateEntry.
* This will also clear any previous processes.
* -- H
*/
VOID VmmProcessCreateFinish(_In_ VMM_HANDLE H)
{
    PVMMOB_PROCESS_TABLE ptNew, ptOld;
    if(!(ptOld = ObContainer_GetOb(H->vmm.pObCPROC))) {
        return;
    }
    if(!(ptNew = ObContainer_GetOb(ptOld->pObCNewPROC))) {
        Ob_DECREF(ptOld);
        return;
    }
    // Replace "existing" old process table with new.
    ObMap_SortEntryIndexByKey(ptNew->pObProcessMap);
    ObContainer_SetOb(H->vmm.pObCPROC, ptNew);
    Ob_DECREF(ptNew);
    Ob_DECREF(ptOld);
}

/*
* Clear the TLB spider flag in all process objects.
* -- H
*/
VOID VmmProcessTlbClear(_In_ VMM_HANDLE H)
{
    PVMMOB_PROCESS_TABLE pt = (PVMMOB_PROCESS_TABLE)ObContainer_GetOb(H->vmm.pObCPROC);
    PVMM_PROCESS pProcess = NULL;
    if(!pt) { return; }
    while((pProcess = ObMap_GetNext(pt->pObProcessMap, pProcess))) {
        pProcess->fTlbSpiderDone = FALSE;
    }
    Ob_DECREF(pt);
}

/*
* Query process for its creation time.
* -- H
* -- pProcess
* -- return = time as FILETIME or 0 on error.
*/
QWORD VmmProcess_GetCreateTimeOpt(_In_ VMM_HANDLE H, _In_opt_ PVMM_PROCESS pProcess)
{
    return (pProcess && H->vmm.offset.EPROCESS.opt.CreateTime) ? *(PQWORD)(pProcess->win.EPROCESS.pb + H->vmm.offset.EPROCESS.opt.CreateTime) : 0;
}

/*
* Query process for its exit time.
* -- H
* -- pProcess
* -- return = time as FILETIME or 0 on error.
*/
QWORD VmmProcess_GetExitTimeOpt(_In_ VMM_HANDLE H, _In_opt_ PVMM_PROCESS pProcess)
{
    return (pProcess && H->vmm.offset.EPROCESS.opt.ExitTime) ? *(PQWORD)(pProcess->win.EPROCESS.pb + H->vmm.offset.EPROCESS.opt.ExitTime) : 0;
}

/*
* List the PIDs and put them into the supplied table.
* -- H
* -- pPIDs = user allocated DWORD array to receive result, or NULL.
* -- pcPIDs = ptr to number of DWORDs in pPIDs on entry - number of PIDs in system on exit.
* -- flags = 0 (recommended) or VMM_FLAG_PROCESS_SHOW_TERMINATED (_only_ if default setting in H->vmm.flags should be overridden)
*/
VOID VmmProcessListPIDs(_In_ VMM_HANDLE H, _Out_writes_opt_(*pcPIDs) PDWORD pPIDs, _Inout_ PSIZE_T pcPIDs, _In_ QWORD flags)
{
    PVMMOB_PROCESS_TABLE pt = (PVMMOB_PROCESS_TABLE)ObContainer_GetOb(H->vmm.pObCPROC);
    BOOL fShowTerminated = ((flags | H->vmm.flags) & VMM_FLAG_PROCESS_SHOW_TERMINATED);
    PVMM_PROCESS pProcess = NULL;
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
    while((pProcess = ObMap_GetNext(pt->pObProcessMap, pProcess))) {
        if(!pProcess->dwState || fShowTerminated) {
            *(pPIDs + i) = pProcess->dwPID;
            i++;
        }
    }
    *pcPIDs = i;
    Ob_DECREF(pt);
}

/*
* Create the initial process table at startup.
* -- H
*/
BOOL VmmProcessTableCreateInitial(_In_ VMM_HANDLE H)
{
    PVMMOB_PROCESS_TABLE pt = (PVMMOB_PROCESS_TABLE)Ob_AllocEx(H, OB_TAG_VMM_PROCESSTABLE, LMEM_ZEROINIT, sizeof(VMMOB_PROCESS_TABLE), (OB_CLEANUP_CB)VmmProcessTable_CloseObCallback, NULL);
    if(!pt) { return FALSE; }
    pt->pObCNewPROC = ObContainer_New();
    pt->pObProcessMap = ObMap_New(H, OB_MAP_FLAGS_OBJECT_OB);
    H->vmm.pObCPROC = ObContainer_New();
    if(!pt->pObCNewPROC || !pt->pObProcessMap || !H->vmm.pObCPROC) { Ob_DECREF(pt); return FALSE; }
    ObContainer_SetOb(H->vmm.pObCPROC, pt);
    Ob_DECREF(pt);
    return TRUE;
}



// ----------------------------------------------------------------------------
// INTERNAL VMMU FUNCTIONALITY: VIRTUAL MEMORY ACCESS.
// ----------------------------------------------------------------------------

VOID VmmWriteScatterPhysical(_In_ VMM_HANDLE H, _Inout_ PPMEM_SCATTER ppMEMsPhys, _In_ DWORD cpMEMsPhys)
{
    DWORD i;
    PMEM_SCATTER pMEM;
    // 1: pre-callback
    if(H->vmm.MemUserCB.pfnWritePhysicalPreCB) {
        H->vmm.MemUserCB.pfnWritePhysicalPreCB(H->vmm.MemUserCB.ctxWritePhysicalPre, (DWORD)-1, cpMEMsPhys, ppMEMsPhys);
    }
    // 2: write:
    LcWriteScatter(H->hLC, cpMEMsPhys, ppMEMsPhys);
    InterlockedAdd64(&H->vmm.stat.cPhysWrite, cpMEMsPhys);
    for(i = 0; i < cpMEMsPhys; i++) {
        pMEM = ppMEMsPhys[i];
        if(pMEM->f && MEM_SCATTER_ADDR_ISVALID(pMEM)) {
            VmmCacheInvalidate(H, pMEM->qwA & ~0xfff);
        }
    }
}

VOID VmmWriteScatterVirtual(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess, _Inout_ PPMEM_SCATTER ppMEMsVirt, _In_ DWORD cpMEMsVirt)
{
    DWORD i;
    QWORD qwPA_PTE = 0, qwPagedPA = 0;
    PMEM_SCATTER pMEM;
    BOOL fProcessMagicHandle = ((SIZE_T)pProcess >= PROCESS_MAGIC_HANDLE_THRESHOLD);
    // 1: 'magic' process handle
    if(fProcessMagicHandle && !(pProcess = VmmProcessGet(H, (DWORD)(0-(SIZE_T)pProcess)))) { return; }
    // 2: pre-callback
    if(H->vmm.MemUserCB.pfnWriteVirtualPreCB) {
        H->vmm.MemUserCB.pfnWriteVirtualPreCB(H->vmm.MemUserCB.ctxWriteVirtualPre, pProcess->dwPID, cpMEMsVirt, ppMEMsVirt);
    }
    // 3: virt2phys translation
    for(i = 0; i < cpMEMsVirt; i++) {
        pMEM = ppMEMsVirt[i];
        MEM_SCATTER_STACK_PUSH(pMEM, pMEM->qwA);
        if(pMEM->f || (pMEM->qwA == (QWORD)-1)) {
            pMEM->qwA = (QWORD)-1;
            continue;
        }
        if(VmmVirt2Phys(H, pProcess, pMEM->qwA, &qwPA_PTE)) {
            pMEM->qwA = qwPA_PTE;
            continue;
        }
        // paged "read" also translate virtual -> physical for some
        // types of paged memory such as transition and prototype.
        H->vmm.fnMemoryModel.pfnPagedRead(H, pProcess, pMEM->qwA, qwPA_PTE, NULL, &qwPagedPA, NULL, 0);
        pMEM->qwA = qwPagedPA ? qwPagedPA : (QWORD)-1;
    }
    // 4: write to physical addresses
    VmmWriteScatterPhysical(H, ppMEMsVirt, cpMEMsVirt);
    for(i = 0; i < cpMEMsVirt; i++) {
        ppMEMsVirt[i]->qwA = MEM_SCATTER_STACK_POP(ppMEMsVirt[i]);
    }
    if(fProcessMagicHandle) { Ob_DECREF(pProcess); }
}

#define VMM_READ_PHYSICAL_SPECULATIVE_PAGES     8

VOID VmmReadScatterPhysical(_In_ VMM_HANDLE H, _Inout_ PPMEM_SCATTER ppMEMsPhys, _In_ DWORD cpMEMsPhys, _In_ QWORD flags)
{
    QWORD tp;   // 0 = normal, 1 = already read, 2 = cache hit, 3 = speculative read
    BOOL fCache, fCacheRecent, fCachePut, fCacheForce;
    PMEM_SCATTER pMEM;
    DWORD i, c, iPA;
    PVMMOB_CACHE_MEM pObCacheEntry, pObReservedMEM;
    fCache = !(VMM_FLAG_NOCACHE & (flags | H->vmm.flags));
    fCacheRecent = fCache && (VMM_FLAG_CACHE_RECENT_ONLY & flags);
    fCachePut = !(VMM_FLAG_NOCACHEPUT & flags);
    fCacheForce = (VMM_FLAG_FORCECACHE_READ & flags) && !(VMM_FLAG_FORCECACHE_READ_DISABLE & (flags | H->vmm.flags));
    // 0: split very large reads
    if(cpMEMsPhys > 0x2000) {
        for(iPA = 0; iPA < cpMEMsPhys; iPA += 0x2000) {
            VmmReadScatterPhysical(H, ppMEMsPhys + iPA, min(0x2000, cpMEMsPhys - iPA), flags);
        }
        return;
    }
    // 1: pre-callback
    if(H->vmm.MemUserCB.pfnReadPhysicalPreCB && !(flags & VMM_FLAG_NOMEMCALLBACK)) {
        H->vmm.MemUserCB.pfnReadPhysicalPreCB(H->vmm.MemUserCB.ctxReadPhysicalPre, (DWORD)-1, cpMEMsPhys, ppMEMsPhys);
    }
    // 2: cache read
    if(fCache) {
        c = 0;
        for(i = 0; i < cpMEMsPhys; i++) {
            pMEM = ppMEMsPhys[i];
            if(pMEM->f) {
                // already valid -> skip
                MEM_SCATTER_STACK_PUSH(pMEM, 3);    // 3: already finished
                c++;
                continue;
            }
            // retrieve from cache (if found)
            if((pMEM->cb == 0x1000) && (pObCacheEntry = VmmCacheGetEx(H, VMM_CACHE_TAG_PHYS, pMEM->qwA, fCacheRecent))) {
                // in cache - copy data into requester and set as completed!
                MEM_SCATTER_STACK_PUSH(pMEM, 2);    // 2: cache read
                pMEM->f = TRUE;
                memcpy(pMEM->pb, pObCacheEntry->pb, 0x1000);
                Ob_DECREF(pObCacheEntry);
                InterlockedIncrement64(&H->vmm.stat.cPhysCacheHit);
                c++;
                continue;
            }
            MEM_SCATTER_STACK_PUSH(pMEM, 1);        // 1: normal read
        }
        // all found in cache _OR_ only cached reads allowed -> restore mem stack and return!
        if((c == cpMEMsPhys) || fCacheForce) {
            for(i = 0; i < cpMEMsPhys; i++) {
                MEM_SCATTER_STACK_POP(ppMEMsPhys[i]);
            }
            return;
        }
    }
    // 3: read!
    LcReadScatter(H->hLC, cpMEMsPhys, ppMEMsPhys);
    // 4: post-callback
    if(H->vmm.MemUserCB.pfnReadPhysicalPostCB && !(flags & VMM_FLAG_NOMEMCALLBACK)) {
        H->vmm.MemUserCB.pfnReadPhysicalPostCB(H->vmm.MemUserCB.ctxReadPhysicalPost, (DWORD)-1, cpMEMsPhys, ppMEMsPhys);
    }
    // 5: cache put
    if(fCache) {
        for(i = 0; i < cpMEMsPhys; i++) {
            pMEM = ppMEMsPhys[i];
            tp = MEM_SCATTER_STACK_POP(pMEM);
            if(fCachePut) {
                if((tp == 1) && pMEM->f) { // 1 = normal read
                    if((pObReservedMEM = VmmCacheReserve(H, VMM_CACHE_TAG_PHYS))) {
                        pObReservedMEM->h.f = TRUE;
                        pObReservedMEM->h.qwA = pMEM->qwA;
                        memcpy(pObReservedMEM->h.pb, pMEM->pb, 0x1000);
                        VmmCacheReserveReturn(H, pObReservedMEM);
                    }
                }
            }
        }
    }
    // 6: statistics and read fail zero fixups (if required)
    for(i = 0; i < cpMEMsPhys; i++) {
        pMEM = ppMEMsPhys[i];
        if(pMEM->f) {
            // success
            InterlockedIncrement64(&H->vmm.stat.cPhysReadSuccess);
        } else {
            // fail
            InterlockedIncrement64(&H->vmm.stat.cPhysReadFail);
            if((flags & VMM_FLAG_ZEROPAD_ON_FAIL) && (pMEM->qwA < H->dev.paMax)) {
                ZeroMemory(pMEM->pb, pMEM->cb);
                pMEM->f = TRUE;
            }
        }
    }
}

VOID VmmReadScatterVirtual_Old(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess, _Inout_updates_(cpMEMsVirt) PPMEM_SCATTER ppMEMsVirt, _In_ DWORD cpMEMsVirt, _In_ QWORD flags)
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
    BOOL fPaging = !(VMM_FLAG_NOPAGING & (flags | H->vmm.flags));
    BOOL fAltAddrPte = VMM_FLAG_ALTADDR_VA_PTE & flags;
    BOOL fZeropadOnFail = VMM_FLAG_ZEROPAD_ON_FAIL & (flags | H->vmm.flags);
    BOOL fProcessMagicHandle = ((SIZE_T)pProcess >= PROCESS_MAGIC_HANDLE_THRESHOLD);
    // 1: 'magic' process handle
    if(fProcessMagicHandle && !(pProcess = VmmProcessGet(H, (DWORD)(0-(SIZE_T)pProcess)))) { return; }
    // 2: pre-callback
    if(H->vmm.MemUserCB.pfnReadVirtualPreCB && !(flags & VMM_FLAG_NOMEMCALLBACK)) {
        H->vmm.MemUserCB.pfnReadVirtualPreCB(H->vmm.MemUserCB.ctxReadVirtualPre, pProcess->dwPID, cpMEMsVirt, ppMEMsVirt);
    }
    // 3: allocate / set up buffers (if needed)
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
    // 4: translate virt2phys
    for(iVA = 0, iPA = 0; iVA < cpMEMsVirt; iVA++) {
        pIoVA = ppMEMsVirt[iVA];
        // MEMORY READ ALREADY COMPLETED
        if(pIoVA->f || (pIoVA->qwA == 0) || (pIoVA->qwA == (QWORD)-1)) {
            if(!pIoVA->f && fZeropadOnFail) {
                ZeroMemory(pIoVA->pb, pIoVA->cb);
            }
            continue;
        }
        // PHYSICAL MEMORY
        qwPA = 0;
        fVirt2Phys = !fAltAddrPte && VmmVirt2Phys(H, pProcess, pIoVA->qwA, &qwPA);
        // PAGED MEMORY
        if(!fVirt2Phys && fPaging && (pIoVA->cb == 0x1000) && H->vmm.fnMemoryModel.pfnPagedRead) {
            if(H->vmm.fnMemoryModel.pfnPagedRead(H, pProcess, (fAltAddrPte ? 0 : pIoVA->qwA), (fAltAddrPte ? pIoVA->qwA : qwPA), pIoVA->pb, &qwPagedPA, NULL, flags)) {
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
        pIoPA->cb = pIoVA->cb;
        pIoPA->pb = pIoVA->pb;
        pIoPA->f = FALSE;
        MEM_SCATTER_STACK_PUSH(pIoPA, (QWORD)pIoVA);
    }
    // 5: read and check result
    if(iPA) {
        VmmReadScatterPhysical(H, ppMEMsPhys, iPA, flags);
        while(iPA > 0) {
            iPA--;
            ((PMEM_SCATTER)MEM_SCATTER_STACK_POP(ppMEMsPhys[iPA]))->f = ppMEMsPhys[iPA]->f;
        }
    }
    // 6: post-callback
    if(H->vmm.MemUserCB.pfnReadVirtualPostCB && !(flags & VMM_FLAG_NOMEMCALLBACK)) {
        H->vmm.MemUserCB.pfnReadVirtualPostCB(H->vmm.MemUserCB.ctxReadVirtualPost, pProcess->dwPID, cpMEMsVirt, ppMEMsVirt);
    }
    // 7: cleanup
    LocalFree(pbBufferLarge);
    if(fProcessMagicHandle) { Ob_DECREF(pProcess); }
}

VOID VmmReadScatterVirtual_New(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess, _Inout_updates_(cpMEMsVirt) PPMEM_SCATTER ppMEMsVirt, _In_ DWORD cpMEMsVirt, _In_ QWORD flags)
{
    DWORD iVA, iV2P, cV2P = 0, cPhys = 0;
    PVMM_V2P_ENTRY pV2P, pV2Ps;
    PMEM_SCATTER *ppMEMs, pMEMs_Phys, pMEM_Phys, pMEM_Virt;
    // buffer layout:
    //   array_pMEMs_V2P union_shared_with array_pMEMs_PA
    //   array_V2P_ENTRY union_shared_with array_MEM_SCATTER_PA
    BYTE *pbBuffer = NULL, pbBufferSmall[0x20 * (sizeof(PMEM_SCATTER) + sizeof(MEM_SCATTER))];
    BOOL fPaging = !(VMM_FLAG_NOPAGING & (flags | H->vmm.flags));
    BOOL fAltAddrPte = VMM_FLAG_ALTADDR_VA_PTE & flags;
    BOOL fZeropadOnFail = VMM_FLAG_ZEROPAD_ON_FAIL & (flags | H->vmm.flags);
    BOOL fProcessMagicHandle = ((SIZE_T)pProcess >= PROCESS_MAGIC_HANDLE_THRESHOLD);
    // 1: split very large reads:
    if(cpMEMsVirt > 0x2000) {
        for(iVA = 0; iVA < cpMEMsVirt; iVA += 0x2000) {
            VmmReadScatterVirtual_New(H, pProcess, ppMEMsVirt + iVA, min(0x2000, cpMEMsVirt - iVA), flags);
        }
        return;
    }
    // 2: 'magic' process handle:
    if(fProcessMagicHandle && !(pProcess = VmmProcessGet(H, (DWORD)(0 - (SIZE_T)pProcess)))) { goto finish; }
    // 3: pre-callback
    if(H->vmm.MemUserCB.pfnReadVirtualPreCB && !(flags & VMM_FLAG_NOMEMCALLBACK)) {
        H->vmm.MemUserCB.pfnReadVirtualPreCB(H->vmm.MemUserCB.ctxReadVirtualPre, pProcess->dwPID, cpMEMsVirt, ppMEMsVirt);
    }
    // 4: allocate / set up buffers:
    if(cpMEMsVirt < 0x20) {
        ZeroMemory(pbBufferSmall, sizeof(pbBufferSmall));
        pbBuffer = pbBufferSmall;
    } else {
        pbBuffer = LocalAlloc(LMEM_ZEROINIT, cpMEMsVirt * (sizeof(MEM_SCATTER) + sizeof(PMEM_SCATTER)));
        if(!pbBuffer) { goto finish; }
    }
    ppMEMs = (PPMEM_SCATTER)pbBuffer;
    pV2Ps = (PVMM_V2P_ENTRY)(pbBuffer + cpMEMsVirt * sizeof(PMEM_SCATTER));
    pMEMs_Phys = (PMEM_SCATTER)pV2Ps;
    // 5: translate virt2phys: prepare:
    for(iVA = 0; iVA < cpMEMsVirt; iVA++) {
        pMEM_Virt = ppMEMsVirt[iVA];
        // memory read already completed -> skip
        if(pMEM_Virt->f || (pMEM_Virt->qwA == 0) || (pMEM_Virt->qwA == (QWORD)-1)) {
            if(!pMEM_Virt->f && fZeropadOnFail) {
                ZeroMemory(pMEM_Virt->pb, pMEM_Virt->cb);
            }
            continue;
        }
        // prepare virtual2physical translation entry
        pV2Ps[cV2P].paPT = pProcess->paDTB;
        pV2Ps[cV2P].va = pMEM_Virt->qwA;
        ppMEMs[cV2P] = pMEM_Virt;
        cV2P++;
    }
    if(!cV2P) { goto finish; }
    // 6: dispatch to Virt2PhysEx translation function:
    if(fAltAddrPte) {
        for(iV2P = 0; iV2P < cV2P; iV2P++) {
            pV2Ps[iV2P].fPaging = TRUE;
        }
    } else {
        H->vmm.fnMemoryModel.pfnVirt2PhysEx(H, pV2Ps, cV2P, pProcess->fUserOnly, -1);
    }
    // 7: interpret V2P translation results and fetch paged memory:
    for(iV2P = 0; iV2P < cV2P; iV2P++) {
        pV2P = pV2Ps + iV2P;
        pMEM_Virt = ppMEMs[iV2P];
        // PAGED MEMORY
        if(pV2P->fPaging && fPaging && (pMEM_Virt->cb == 0x1000) && H->vmm.fnMemoryModel.pfnPagedRead) {
            if(H->vmm.fnMemoryModel.pfnPagedRead(H, pProcess, (fAltAddrPte ? 0 : pMEM_Virt->qwA), (fAltAddrPte ? pMEM_Virt->qwA : pV2P->pte), pMEM_Virt->pb, &pV2P->pa, NULL, flags)) {
                pMEM_Virt->f = TRUE;
                continue;
            }
            if(pV2P->pa) {
                pV2P->fPhys = TRUE;
            }
        }
        if(!pV2P->fPhys) {   // NO TRANSLATION MEMORY / FAILED PAGED MEMORY
            if(fZeropadOnFail) {
                ZeroMemory(pMEM_Virt->pb, pMEM_Virt->cb);
            }
            continue;
        }
        // PHYSICAL BACKED MEMORY
        pMEM_Phys = pMEMs_Phys + cPhys;
        ppMEMs[cPhys] = pMEM_Phys;
        cPhys++;
        pMEM_Phys->version = MEM_SCATTER_VERSION;
        pMEM_Phys->qwA = pV2P->pa;
        pMEM_Phys->cb = pMEM_Virt->cb;
        pMEM_Phys->pb = pMEM_Virt->pb;
        pMEM_Phys->iStack = 0;
        pMEM_Phys->f = FALSE;
        MEM_SCATTER_STACK_PUSH(pMEM_Phys, (QWORD)pMEM_Virt);
    }
    if(!cPhys) { goto finish; }
    // 8: read physical pages and check result:
    VmmReadScatterPhysical(H, ppMEMs, cPhys, flags);
    while(cPhys > 0) {
        cPhys--;
        ((PMEM_SCATTER)MEM_SCATTER_STACK_POP(ppMEMs[cPhys]))->f = ppMEMs[cPhys]->f;
    }
    // 9: post-callback
    if(H->vmm.MemUserCB.pfnReadVirtualPostCB && !(flags & VMM_FLAG_NOMEMCALLBACK)) {
        H->vmm.MemUserCB.pfnReadVirtualPostCB(H->vmm.MemUserCB.ctxReadVirtualPost, pProcess->dwPID, cpMEMsVirt, ppMEMsVirt);
    }
finish:
    if(pbBuffer != pbBufferSmall) { LocalFree(pbBuffer); }
    if(fProcessMagicHandle) { Ob_DECREF(pProcess); }
}

VOID VmmReadScatterVirtual(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess, _Inout_updates_(cpMEMsVirt) PPMEM_SCATTER ppMEMsVirt, _In_ DWORD cpMEMsVirt, _In_ QWORD flags)
{
    if(cpMEMsVirt >= 2) {
        VmmReadScatterVirtual_New(H, pProcess, ppMEMsVirt, cpMEMsVirt, flags);
    } else {
        VmmReadScatterVirtual_Old(H, pProcess, ppMEMsVirt, cpMEMsVirt, flags);
    }
}

/*
* Retrieve information of the virtual2physical address translation for the
* supplied process. The Virtual address must be supplied in pVirt2PhysInfo upon
* entry.
* -- pProcess
* -- pVirt2PhysInfo
*/
VOID VmmVirt2PhysGetInformation(_In_ VMM_HANDLE H, _Inout_ PVMM_PROCESS pProcess, _Inout_ PVMM_VIRT2PHYS_INFORMATION pVirt2PhysInfo)
{
    if(H->vmm.tpMemoryModel == VMM_MEMORYMODEL_NA) { return; }
    H->vmm.fnMemoryModel.pfnVirt2PhysGetInformation(H, pProcess, pVirt2PhysInfo);
}

/*
* Retrieve information of the physical2virtual address translation for the
* supplied process. This function may take time on larger address spaces -
* such as the kernel adderss space due to extensive page walking. If a new
* address is to be used please supply it in paTarget. If paTarget == 0 then
* a previously stored address will be used.
* It's not possible to use this function to retrieve multiple targeted
* addresses in parallell.
* CALLER DECREF: return
* -- H
* -- pProcess
* -- paTarget = targeted physical address (or 0 if use previously saved).
* -- return
*/
PVMMOB_PHYS2VIRT_INFORMATION VmmPhys2VirtGetInformation(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess, _In_ QWORD paTarget)
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
            pObP2V = Ob_AllocEx(H, OB_TAG_VMM_VIRT2PHYS, LMEM_ZEROINIT, sizeof(VMMOB_PHYS2VIRT_INFORMATION), NULL, NULL);
            pObP2V->paTarget = paTarget;
            pObP2V->dwPID = pProcess->dwPID;
            if(H->vmm.fnMemoryModel.pfnPhys2VirtGetInformation) {
                H->vmm.fnMemoryModel.pfnPhys2VirtGetInformation(H, pProcess, pObP2V);
                ObContainer_SetOb(pProcess->Plugin.pObCPhys2Virt, pObP2V);
            }
        }
        LeaveCriticalSection(&pProcess->LockUpdate);
    }
    if(!pObP2V) {
        EnterCriticalSection(&pProcess->LockUpdate);
        pObP2V = ObContainer_GetOb(pProcess->Plugin.pObCPhys2Virt);
        if(!pObP2V) {
            pObP2V = Ob_AllocEx(H, OB_TAG_VMM_VIRT2PHYS, LMEM_ZEROINIT, sizeof(VMMOB_PHYS2VIRT_INFORMATION), NULL, NULL);
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

VOID VmmClose(_In_ VMM_HANDLE H)
{
    static SRWLOCK LockSRW = SRWLOCK_INIT;
    if(!H || !H->vmm.fInitializationStatus) { return; }
    AcquireSRWLockExclusive(&LockSRW);
    if(H->vmm.PluginManager.FLinkAll) { PluginManager_Close(H); }
    VmmVm_Close(H);
    VmmWinReg_Close(H);
    VmmNet_Close(H);
    PDB_Close(H);
    Ob_DECREF_NULL(&H->vmm.pObVfsDumpContext);
    Ob_DECREF_NULL(&H->vmm.pObCPROC);
    if(H->vmm.fnMemoryModel.pfnClose) {
        H->vmm.fnMemoryModel.pfnClose(H);
    }
    MmPfn_Close(H);
    MmWin_PagingClose(H);
    VmmCacheClose(H, VMM_CACHE_TAG_PHYS);
    VmmCacheClose(H, VMM_CACHE_TAG_TLB);
    VmmCacheClose(H, VMM_CACHE_TAG_PAGING);
    Ob_DECREF_NULL(&H->vmm.Cache.PAGING_FAILED);
    Ob_DECREF_NULL(&H->vmm.Cache.pmPrototypePte);
    Ob_DECREF_NULL(&H->vmm.pObCMapPhysMem);
    Ob_DECREF_NULL(&H->vmm.pObCMapEvil);
    Ob_DECREF_NULL(&H->vmm.pObCMapUser);
    Ob_DECREF_NULL(&H->vmm.pObCMapVM);
    Ob_DECREF_NULL(&H->vmm.pObCMapNet);
    Ob_DECREF_NULL(&H->vmm.pObCMapObjMgr);
    Ob_DECREF_NULL(&H->vmm.pObCMapKDevice);
    Ob_DECREF_NULL(&H->vmm.pObCMapKDriver);
    Ob_DECREF_NULL(&H->vmm.pObCMapPoolAll);
    Ob_DECREF_NULL(&H->vmm.pObCMapPoolBig);
    Ob_DECREF_NULL(&H->vmm.pObCMapService);
    Ob_DECREF_NULL(&H->vmm.pObCInfoDB);
    Ob_DECREF_NULL(&H->vmm.pObCWinObj);
    Ob_DECREF_NULL(&H->vmm.pObCCachePrefetchEPROCESS);
    Ob_DECREF_NULL(&H->vmm.pObCCachePrefetchRegistry);
    Ob_DECREF_NULL(&H->vmm.pObCacheMapEAT);
    Ob_DECREF_NULL(&H->vmm.pObCacheMapIAT);
    Ob_DECREF_NULL(&H->vmm.pObCacheMapHeapAlloc);
    Ob_DECREF_NULL(&H->vmm.pObCacheMapWinObjDisplay);
    Ob_DECREF_NULL(&H->vmm.pObCacheMapObCompressedShared);
    Ob_DECREF_NULL(&H->vmm.pmObThreadCallback);
    DeleteCriticalSection(&H->vmm.LockMaster);
    DeleteCriticalSection(&H->vmm.LockPlugin);
    DeleteCriticalSection(&H->vmm.LockUpdateVM);
    DeleteCriticalSection(&H->vmm.LockUpdateMap);
    DeleteCriticalSection(&H->vmm.LockUpdateModule);
    LocalFree(H->vmm.ObjectTypeTable.pbMultiText);
    ZeroMemory(&H->vmm, sizeof(VMM_CONTEXT));
    ReleaseSRWLockExclusive(&LockSRW);
}

VOID VmmWriteEx(_In_ VMM_HANDLE H, _In_opt_ PVMM_PROCESS pProcess, _In_ QWORD qwA, _In_ PBYTE pb, _In_ DWORD cb, _Out_opt_ PDWORD pcbWrite)
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
        VmmWriteScatterVirtual(H, pProcess, ppMEMs, cMEMs);
    } else {
        VmmWriteScatterPhysical(H, ppMEMs, cMEMs);
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

BOOL VmmWrite(_In_ VMM_HANDLE H, _In_opt_ PVMM_PROCESS pProcess, _In_ QWORD qwA, _In_reads_(cb) PBYTE pb, _In_ DWORD cb)
{
    DWORD cbWrite;
    VmmWriteEx(H, pProcess, qwA, pb, cb, &cbWrite);
    return (cbWrite == cb);
}

VOID VmmReadEx(_In_ VMM_HANDLE H, _In_opt_ PVMM_PROCESS pProcess, _In_ QWORD qwA, _Out_writes_(cb) PBYTE pb, _In_ DWORD cb, _Out_opt_ PDWORD pcbReadOpt, _In_ QWORD flags)
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
        VmmReadScatterVirtual(H, pProcess, ppMEMs, cMEMs, flags);
    } else {
        VmmReadScatterPhysical(H, ppMEMs, cMEMs, flags);
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

NTSTATUS VmmReadAsFile(_In_ VMM_HANDLE H, _In_opt_ PVMM_PROCESS pProcess, _In_ QWORD qwMemoryAddress, _In_ QWORD cbMemorySize, _Out_writes_(cb) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset)
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
    VmmReadEx(H, pProcess, qwMemoryAddress + cbOffset, pb, *pcbRead, NULL, VMM_FLAG_ZEROPAD_ON_FAIL);
    return STATUS_SUCCESS;
}

NTSTATUS VmmWriteAsFile(_In_ VMM_HANDLE H, _In_opt_ PVMM_PROCESS pProcess, _In_ QWORD qwMemoryAddress, _In_ QWORD cbMemorySize, _In_reads_(cb) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbWrite, _In_ QWORD cbOffset)
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
    VmmWriteEx(H, pProcess, qwMemoryAddress + cbOffset, pb, *pcbWrite, NULL);
    return STATUS_SUCCESS;
}


_Success_(return)
BOOL VmmReadWtoU(_In_ VMM_HANDLE H, _In_opt_ PVMM_PROCESS pProcess, _In_ QWORD qwA, _In_ DWORD cb, _In_ QWORD flagsRead, _Maybenull_ _Writable_bytes_(cbBuffer) PBYTE pbBuffer, _In_ DWORD cbBuffer, _Out_opt_ LPSTR *pusz, _Out_opt_ PDWORD pcbu, _In_ DWORD flagsChar)
{
    BOOL fResult = FALSE;
    BYTE pbBufferTMP[2 * MAX_PATH + 2] = { 0 };
    PBYTE pb = pbBufferTMP;
    DWORD cbRead = 0;
    if(cb > sizeof(pbBufferTMP)) {
        if(!(pb = LocalAlloc(0, cb))) { goto fail; }
    }
    VmmReadEx(H, pProcess, qwA, pb, cb, &cbRead, flagsRead);
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
BOOL VmmReadAlloc(_In_ VMM_HANDLE H, _In_opt_ PVMM_PROCESS pProcess, _In_ QWORD qwA, _Out_ PBYTE *ppb, _In_ DWORD cb, _In_ QWORD flags)
{
    PBYTE pb;
    if(!(pb = LocalAlloc(0, cb + 2ULL))) { return FALSE; }
    if(!VmmRead2(H, pProcess, qwA, pb, cb, flags)) {
        LocalFree(pb);
        return FALSE;
    }
    pb[cb] = 0;
    pb[cb + 1] = 0;
    *ppb = pb;
    return TRUE;
}

_Success_(return)
BOOL VmmReadAllocUnicodeString_Size(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess, _In_ BOOL f32, _In_ QWORD flags, _In_ QWORD vaUS, _Out_ PQWORD pvaStr, _Out_ PWORD pcbStr)
{
    BYTE pb[16];
    DWORD cbRead;
    VmmReadEx(H, pProcess, vaUS, pb, (f32 ? 8 : 16), &cbRead, flags);
    return
        (cbRead == (f32 ? 8 : 16)) &&                               // read ok
        (*(PWORD)pb <= *(PWORD)(pb + 2)) &&                         // size max >= size
        (*pcbStr = *(PWORD)pb) &&                                   // size != 0
        (*pcbStr > 1) &&                                            // size > 1
        (*pvaStr = f32 ? *(PDWORD)(pb + 4) : *(PQWORD)(pb + 8)) &&  // string address != 0
        !(*pvaStr & 1);                                             // non alignment
}

_Success_(return)
BOOL VmmReadAllocUnicodeString(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess, _In_ BOOL f32, _In_ QWORD flags, _In_ QWORD vaUS, _In_ DWORD cchMax, _Out_opt_ LPWSTR *pwsz, _Out_opt_ PDWORD pcch)
{
    WORD cbStr;
    QWORD vaStr;
    if(pcch) { *pcch = 0; }
    if(pwsz) { *pwsz = NULL; }
    if(VmmReadAllocUnicodeString_Size(H, pProcess, f32, 0, vaUS, &vaStr, &cbStr)) {
        if(cchMax && (cbStr > (cchMax << 1))) {
            cbStr = (WORD)(cchMax << 1);
        }
        if(!pwsz || VmmReadAlloc(H, pProcess, vaStr, (PBYTE *)pwsz, cbStr, flags)) {
            if(pcch) { *pcch = cbStr >> 1; }
            return TRUE;
        }
    }
    return FALSE;
}

_Success_(return)
BOOL VmmReadAllocUnicodeStringAsUTF8(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess, _In_ BOOL f32, _In_ QWORD flags, _In_ QWORD vaUS, _In_ DWORD cchMax, _Out_opt_ LPSTR *pusz, _Out_opt_ PDWORD pcbu)
{
    BOOL f;
    LPWSTR wszTMP = NULL;
    f = VmmReadAllocUnicodeString(H, pProcess, f32, 0, vaUS, cchMax, &wszTMP, NULL) &&
        CharUtil_WtoU(wszTMP, cchMax, NULL, 0, pusz, pcbu, CHARUTIL_FLAG_ALLOC);
    LocalFree(wszTMP);
    return f;
}

_Success_(return)
BOOL VmmRead(_In_ VMM_HANDLE H, _In_opt_ PVMM_PROCESS pProcess, _In_ QWORD qwA, _Out_writes_(cb) PBYTE pb, _In_ DWORD cb)
{
    DWORD cbRead;
    VmmReadEx(H, pProcess, qwA, pb, cb, &cbRead, 0);
    return (cbRead == cb);
}

_Success_(return)
BOOL VmmRead2(_In_ VMM_HANDLE H, _In_opt_ PVMM_PROCESS pProcess, _In_ QWORD qwA, _Out_writes_(cb) PBYTE pb, _In_ DWORD cb, _In_ QWORD flags)
{
    DWORD cbRead;
    VmmReadEx(H, pProcess, qwA, pb, cb, &cbRead, flags);
    return (cbRead == cb);
}

_Success_(return)
BOOL VmmReadPage(_In_ VMM_HANDLE H, _In_opt_ PVMM_PROCESS pProcess, _In_ QWORD qwA, _Out_writes_(4096) PBYTE pbPage)
{
    DWORD cb;
    VmmReadEx(H, pProcess, qwA, pbPage, 0x1000, &cb, 0);
    return cb == 0x1000;
}

VOID VmmInitializeMemoryModel(_In_ VMM_HANDLE H, _In_ VMM_MEMORYMODEL_TP tp)
{
    switch(tp) {
        case VMM_MEMORYMODEL_ARM64:
            MmARM64_Initialize(H);
            break;
        case VMM_MEMORYMODEL_X64:
            MmX64_Initialize(H);
            break;
        case VMM_MEMORYMODEL_X86PAE:
            MmX86PAE_Initialize(H);
            break;
        case VMM_MEMORYMODEL_X86:
            MmX86_Initialize(H);
            break;
        default:
            if(H->vmm.fnMemoryModel.pfnClose) {
                H->vmm.fnMemoryModel.pfnClose(H);
            }
    }
}

VOID VmmInitializeFunctions(_In_ VMM_HANDLE H)
{
    HMODULE hNtDll = NULL;
    if((hNtDll = LoadLibraryU("ntdll.dll"))) {
        H->vmm.fn.RtlDecompressBufferOpt = (VMMFN_RtlDecompressBuffer*)GetProcAddress(hNtDll, "RtlDecompressBuffer");
        H->vmm.fn.RtlDecompressBufferExOpt = (VMMFN_RtlDecompressBufferEx*)GetProcAddress(hNtDll, "RtlDecompressBufferEx");
        FreeLibrary(hNtDll);
    }
    return;
}

BOOL VmmInitialize(_In_ VMM_HANDLE H)
{
    static SRWLOCK LockSRW = SRWLOCK_INIT;
    AcquireSRWLockExclusive(&LockSRW);
    // 1: allocate & initialize
    if(H->vmm.fInitializationStatus) { VmmClose(H); }
    ZeroMemory(&H->vmm, sizeof(VMM_CONTEXT));
    H->vmm.hModuleVmmOpt = GetModuleHandleA("vmm");
    if(H->cfg.tpForensicMode && !H->dev.fVolatile && !H->dev.fRemote) {
        // forensic mode for local static files disables the forcache
        // read pattern to achieve greater forensic file consistency.
        H->vmm.flags |= VMM_FLAG_FORCECACHE_READ_DISABLE;
    }

    //H->vmm.flags |= VMMDLL_FLAG_NO_PREDICTIVE_READ;
    //H->vmm.flags |= VMMDLL_FLAG_NOPAGING;


    // 2: CACHE INIT: Process Table
    if(!VmmProcessTableCreateInitial(H)) { goto fail; }
    // 3: CACHE INIT: Translation Lookaside Buffer (TLB) Cache Table
    VmmCacheInitialize(H, VMM_CACHE_TAG_TLB);
    if(!H->vmm.Cache.TLB.fActive) { goto fail; }
    // 4: CACHE INIT: Physical Memory Cache Table
    VmmCacheInitialize(H, VMM_CACHE_TAG_PHYS);
    if(!H->vmm.Cache.PHYS.fActive) { goto fail; }
    // 5: CACHE INIT: Paged Memory Cache Table
    VmmCacheInitialize(H, VMM_CACHE_TAG_PAGING);
    if(!H->vmm.Cache.PAGING.fActive) { goto fail; }
    if(!(H->vmm.Cache.PAGING_FAILED = ObSet_New(H))) { goto fail; }
    // 6: CACHE INIT: Prototype PTE Cache Map
    if(!(H->vmm.Cache.pmPrototypePte = ObMap_New(H, OB_MAP_FLAGS_OBJECT_OB))) { goto fail; }
    // 7: OTHER INIT:
    H->vmm.pObCMapPhysMem = ObContainer_New();
    H->vmm.pObCMapEvil = ObContainer_New();
    H->vmm.pObCMapUser = ObContainer_New();
    H->vmm.pObCMapVM = ObContainer_New();
    H->vmm.pObCMapNet = ObContainer_New();
    H->vmm.pObCMapObjMgr = ObContainer_New();
    H->vmm.pObCMapKDevice = ObContainer_New();
    H->vmm.pObCMapKDriver = ObContainer_New();
    H->vmm.pObCMapPoolAll = ObContainer_New();
    H->vmm.pObCMapPoolBig = ObContainer_New();
    H->vmm.pObCMapService = ObContainer_New();
    H->vmm.pObCInfoDB = ObContainer_New();
    H->vmm.pObCWinObj = ObContainer_New();
    H->vmm.pObCCachePrefetchEPROCESS = ObContainer_New();
    H->vmm.pObCCachePrefetchRegistry = ObContainer_New();
    H->vmm.pObCacheMapObCompressedShared = ObCacheMap_New(H, OB_COMPRESSED_CACHED_ENTRIES_MAX, NULL, OB_CACHEMAP_FLAGS_OBJECT_OB);
    H->vmm.pmObThreadCallback = ObMap_New(H, OB_MAP_FLAGS_OBJECT_OB);
    InitializeCriticalSection(&H->vmm.LockMaster);
    InitializeCriticalSection(&H->vmm.LockPlugin);
    InitializeCriticalSection(&H->vmm.LockUpdateVM);
    InitializeCriticalSection(&H->vmm.LockUpdateMap);
    InitializeCriticalSection(&H->vmm.LockUpdateModule);
    VmmInitializeFunctions(H);
    H->vmm.fInitializationStatus = TRUE;
    ReleaseSRWLockExclusive(&LockSRW);
    return TRUE;
fail:
    VmmClose(H);
    ReleaseSRWLockExclusive(&LockSRW);
    return FALSE;
}



// ----------------------------------------------------------------------------
// SCATTER READ MEMORY FUNCTIONALITY BELOW:
// ----------------------------------------------------------------------------

#ifdef VMM_64BIT
#define VMM_SCATTER_MAX_SIZE_TOTAL      0x40000000000
#else /* VMM_64BIT */
#define VMM_SCATTER_MAX_SIZE_TOTAL      0x40000000
#endif /* VMM_64BIT */

#define VMM_SCATTER_MAX_SIZE_SINGLE     0x40000000

typedef struct tdVMM_SCATTER_RANGE {
    struct tdVMM_SCATTER_RANGE *FLink;
    QWORD va;
    PDWORD pcbRead;
    PBYTE pb;
    DWORD cb;
    DWORD cMEMs;
    MEM_SCATTER MEMs[0];
} VMM_SCATTER_RANGE, *PVMM_SCATTER_RANGE;

typedef struct tdVMMOB_SCATTER {
    OB ObHdr;
    VMM_HANDLE H;
    DWORD flags;
    BOOL fExecute;          // read/write is already executed
    DWORD cPageTotal;
    DWORD cPageAlloc;
    POB_MAP pmMEMs;
    PBYTE pbBuffer;
    PVMM_SCATTER_RANGE pRanges;
} VMMOB_SCATTER, *PVMMOB_SCATTER;

_Success_(return)
BOOL VmmScatter_PrepareInternal(_In_ PVMMOB_SCATTER hS, _In_ QWORD va, _In_ DWORD cb, _Out_writes_opt_(cb) PBYTE pb, _Out_opt_ PDWORD pcbRead)
{
    QWORD vaMEM;
    PMEM_SCATTER pMEM;
    PVMM_SCATTER_RANGE pr = NULL;
    DWORD i, iNewMEM = 0, cMEMsRequired, cMEMsPre = 0;
    BOOL fForcePageRead = hS->flags & VMM_FLAG_SCATTER_FORCE_PAGEREAD;
    // zero out any buffer received
    if(pb && !(hS->flags & VMM_FLAG_SCATTER_PREPAREEX_NOMEMZERO)) {
        ZeroMemory(pb, cb);
    }
    if(pcbRead) { *pcbRead = 0; }
    // validity checks
    if(va + cb < va) { return FALSE; }
    if(hS->fExecute) { return FALSE; }
    if(!cb) { return TRUE; }
    if((cb >= VMM_SCATTER_MAX_SIZE_SINGLE) || (((SIZE_T)hS->cPageTotal << 12) + cb > VMM_SCATTER_MAX_SIZE_TOTAL)) { return FALSE; }
    // count MEMs (required and pre-existing)
    cMEMsRequired = ((va & 0xfff) + cb + 0xfff) >> 12;
    vaMEM = va & ~0xfff;
    for(i = 0; i < cMEMsRequired; i++) {
        if(ObMap_ExistsKey(hS->pmMEMs, vaMEM | 1)) {
            cMEMsPre++;
        }
        vaMEM += 0x1000;
    }
    // alloc scatter range (including any new MEMs required)
    if(pb || pcbRead || (cMEMsRequired > cMEMsPre)) {
        if(!(pr = LocalAlloc(LMEM_ZEROINIT, sizeof(VMM_SCATTER_RANGE) + (cMEMsRequired - cMEMsPre) * sizeof(MEM_SCATTER)))) { return FALSE; }
        pr->va = va;
        pr->cb = cb;
        pr->pb = pb;
        pr->pcbRead = pcbRead;
        pr->cMEMs = cMEMsRequired - cMEMsPre;
        for(i = 0; i < pr->cMEMs; i++) {
            pMEM = pr->MEMs + i;
            pMEM->version = MEM_SCATTER_VERSION;
            pMEM->cb = 0x1000;
        }
        pr->FLink = hS->pRanges;
        hS->pRanges = pr;
    }
    // assign addresses and/or buffers to MEMs
    vaMEM = va & ~0xfff;
    for(i = 0; i < cMEMsRequired; i++) {
        if((pMEM = ObMap_GetByKey(hS->pmMEMs, vaMEM | 1))) {
            // pre-existing MEM
            if(pMEM->cb != 0x1000) {
                // pre-existing MEM was a tiny MEM -> since we have two reads
                // subscribing to this MEM we 'upgrade' it to a full MEM.
                pMEM->qwA = pMEM->qwA & ~0xfff;
                pMEM->cb = 0x1000;
            }
        } else {
            // new MEM
            if(!pr || (pr->cMEMs <= iNewMEM)) {
                // should never happen!
                return FALSE;
            }
            pMEM = pr->MEMs + iNewMEM;
            iNewMEM++;
            pMEM->qwA = vaMEM;
            if((cMEMsRequired == 1) && (cb <= 0x400) && !fForcePageRead) {
                // single-page small read -> optimize MEM for small read.
                // NB! buffer allocation still remains 0x1000 even if not all is used for now.
                pMEM->cb = (cb + 15) & ~0x7;
                pMEM->qwA = va & ~0x7;
                if((pMEM->qwA & 0xfff) + pMEM->cb > 0x1000) {
                    pMEM->qwA = (pMEM->qwA & ~0xfff) + 0x1000 - pMEM->cb;
                }
            }
            if(!ObMap_Push(hS->pmMEMs, vaMEM | 1, pMEM)) {
                // should never happen!
                return FALSE;
            }
            hS->cPageTotal++;
        }
        if(pb && !pMEM->pb && (vaMEM >= va) && (vaMEM + 0xfff < va + cb)) {
            pMEM->pb = pb + vaMEM - va;
            hS->cPageAlloc++;
        }
        vaMEM += 0x1000;
    }
    return TRUE;
}

/*
* Prepare (add) a memory range for reading. The buffer pb and the read length
* *pcbRead will be populated when VmmScatter_Execute() is later called.
* NB! the buffer pb must not be deallocated when VmmScatter_Execute() is called.
* -- hS
* -- va = start address of the memory range to read.
* -- cb = size of memory range to read.
* -- pb = buffer to populate with read memory when calling VmmScatter_Execute()
* -- pcbRead = optional pointer to be populated with number of bytes successfully read.
* -- return
*/
_Success_(return)
BOOL VmmScatter_PrepareEx(_In_ PVMMOB_SCATTER hS, _In_ QWORD va, _In_ DWORD cb, _Out_writes_opt_(cb) PBYTE pb, _Out_opt_ PDWORD pcbRead)
{
    return VmmScatter_PrepareInternal(hS, va, cb, pb, pcbRead);
}

/*
* Prepare (add) a memory range for reading. The memory may after a call to
* VmmScatter_Execute() be retrieved with VmmScatter_Read().
* -- hS
* -- va = start address of the memory range to read.
* -- cb = size of memory range to read.
* -- return
*/
_Success_(return)
BOOL VmmScatter_Prepare(_In_ PVMMOB_SCATTER hS, _In_ QWORD va, _In_ DWORD cb)
{
    return VmmScatter_PrepareInternal(hS, va, cb, NULL, NULL);
}

/*
* Prepare (add) multiple memory ranges. The memory may after a call to
* VmmScatter_Execute() be retrieved with VmmScatter_Read().
* -- hS
* -- psva = set with addresses to read.
* -- cb = size of memory range to read.
* -- return
*/
_Success_(return)
BOOL VmmScatter_Prepare3(_In_ PVMMOB_SCATTER hS, _In_opt_ POB_SET psva, _In_ DWORD cb)
{
    QWORD va = 0;
    BOOL f = TRUE;
    while((va = ObSet_GetNext(psva, va))) {
        f = VmmScatter_PrepareInternal(hS, va, cb, NULL, NULL) && f;
    }
    return f;
}

/*
* Prepare (add) multiple memory ranges. The memory may after a call to
* VmmScatter_Execute() be retrieved with VmmScatter_Read().
* -- hS
* -- pm = map of objects.
* -- cb = size of memory range to read.
* -- pfnFilterCB = filter as required by ObMap_FilterSet function.
* -- return
*/
_Success_(return)
BOOL VmmScatter_Prepare5(_In_ PVMMOB_SCATTER hS, _In_opt_ POB_MAP pm, _In_ DWORD cb, _In_ OB_MAP_FILTERSET_PFN_CB pfnFilterCB)
{
    BOOL f;
    POB_SET psObA = ObMap_FilterSet(pm, NULL, pfnFilterCB);
    f = VmmScatter_Prepare3(hS, psObA, cb);
    Ob_DECREF(psObA);
    return f;

}

/*
* Clear/Reset the handle for use in another subsequent read scatter operation.
* -- hS = the scatter handle to clear for reuse.
* -- return
*/
_Success_(return)
BOOL VmmScatter_Clear(_In_ PVMMOB_SCATTER hS)
{
    PVMM_SCATTER_RANGE pRangeRd, pRangeRdNext = hS->pRanges;
    hS->fExecute = FALSE;
    hS->cPageTotal = 0;
    hS->cPageAlloc = 0;
    hS->pRanges = NULL;
    ObMap_Clear(hS->pmMEMs);
    LocalFree(hS->pbBuffer);
    hS->pbBuffer = NULL;
    while(pRangeRdNext) {
        pRangeRd = pRangeRdNext;
        pRangeRdNext = pRangeRd->FLink;
        LocalFree(pRangeRd);
    }
    return TRUE;
}

/*
* Read out memory in previously populated ranges. This function should only be
* called after the memory has been retrieved using VmmScatter_Execute().
* -- hS
* -- va
* -- cb
* -- pb
* -- pcbRead
* -- return
*/
_Success_(return)
BOOL VmmScatter_Read(_In_ PVMMOB_SCATTER hS, _In_ QWORD va, _In_ DWORD cb, _Out_writes_opt_(cb) PBYTE pb, _Out_opt_ PDWORD pcbRead)
{
    PMEM_SCATTER pMEM;
    BOOL fResultFirst = FALSE;
    DWORD cbChunk, cbReadTotal = 0;
    if(pcbRead) { *pcbRead = 0; }
    if(va + cb < va) { return FALSE; }
    if(!hS->fExecute) { return FALSE; }
    // 1st item may not be page aligned or may be 'tiny' sized MEM:
    {
        cbChunk = min(cb, 0x1000 - (va & 0xfff));
        pMEM = ObMap_GetByKey(hS->pmMEMs, (va & ~0xfff) | 1);
        if(pMEM && pMEM->f) {
            if(pMEM->cb == 0x1000) {
                // normal page-sized MEM:
                if(pb) {
                    memcpy(pb, pMEM->pb + (va & 0xfff), cbChunk);
                    pb += cbChunk;
                }
                cbReadTotal += cbChunk;
                fResultFirst = TRUE;
            } else if((va >= pMEM->qwA) && (va + cb <= pMEM->qwA + pMEM->cb)) {
                // tiny MEM with in-range read:
                if(pb) {
                    memcpy(pb, pMEM->pb + (va - pMEM->qwA), cbChunk);
                    pb += cbChunk;
                }
                cbReadTotal += cbChunk;
                fResultFirst = TRUE;
            }
        }
        if(!fResultFirst && pb) {
            ZeroMemory(pb, cbChunk);
            pb += cbChunk;
        }
        va += cbChunk;
        cb -= cbChunk;
    }
    // page aligned va onwards (read from normal page-sized MEMs):
    while(cb) {
        cbChunk = min(cb, 0x1000);
        pMEM = ObMap_GetByKey(hS->pmMEMs, va | 1);
        if(pMEM && pMEM->f && (pMEM->cb == 0x1000)) {
            cbReadTotal += cbChunk;
            if(pb) {
                if(pb != pMEM->pb) {
                    memcpy(pb, pMEM->pb, cbChunk);
                }
                pb += cbChunk;
            }
        } else {
            if(pb) {
                if(pMEM && (pb != pMEM->pb)) {
                    ZeroMemory(pb, cbChunk);
                }
                pb += cbChunk;
            }
        }
        va += cbChunk;
        cb -= cbChunk;
    }
    if(pcbRead) { *pcbRead = cbReadTotal; }
    return (cbReadTotal > 0);
}

/*
* Retrieve the memory ranges previously populated with calls to the
* VmmScatter_Prepare* functions.
* -- hS
* -- pProcess = the process to read from, NULL = physical memory.
* -- return
*/
_Success_(return)
BOOL VmmScatter_Execute(_In_ PVMMOB_SCATTER hS, _In_ PVMM_PROCESS pProcess)
{
    DWORD i, cbBuffer, cbBufferAlloc, oBufferAllocMEM = 0;
    PMEM_SCATTER pMEM;
    PPMEM_SCATTER ppMEMs;
    PVMM_SCATTER_RANGE pRange;
    // validate
    if(!hS->cPageTotal || (hS->cPageTotal != ObMap_Size(hS->pmMEMs))) { return FALSE; }
    // alloc (if required)
    cbBuffer = (hS->cPageTotal - hS->cPageAlloc) * 0x1000;
    if(!hS->fExecute) {
        cbBufferAlloc = cbBuffer + hS->cPageTotal * sizeof(PMEM_SCATTER);
        if(!(hS->pbBuffer = LocalAlloc(LMEM_ZEROINIT, cbBufferAlloc))) { return FALSE; }
    }
    ppMEMs = (PPMEM_SCATTER)(hS->pbBuffer + cbBuffer);
    // fixup MEMs
    for(i = 0; i < hS->cPageTotal; i++) {
        pMEM = ObMap_GetByIndex(hS->pmMEMs, i);
        ppMEMs[i] = pMEM;
        if(!pMEM->pb) {
            pMEM->pb = hS->pbBuffer + oBufferAllocMEM;
            oBufferAllocMEM += 0x1000;
        } else if(hS->fExecute) {
            pMEM->f = FALSE;
            ZeroMemory(pMEM->pb, 0x1000);
        }
    }
    // read scatter
    if(pProcess) {
        VmmReadScatterVirtual(hS->H, pProcess, ppMEMs, hS->cPageTotal, hS->flags);
    } else {
        VmmReadScatterPhysical(hS->H, ppMEMs, hS->cPageTotal, hS->flags);
    }
    hS->fExecute = TRUE;
    // range fixup (if required)
    pRange = hS->pRanges;
    while(pRange) {
        if(pRange->pb || pRange->pcbRead) {
            VmmScatter_Read(hS, pRange->va, pRange->cb, pRange->pb, pRange->pcbRead);
        }
        pRange = pRange->FLink;
    }
    return TRUE;
}

VOID VmmScatter_CleanupCB(PVMMOB_SCATTER hS)
{
    PVMM_SCATTER_RANGE pRangeRd, pRangeRdNext;
    // dealloc / free
    Ob_DECREF(hS->pmMEMs);
    LocalFree(hS->pbBuffer);
    pRangeRdNext = hS->pRanges;
    while(pRangeRdNext) {
        pRangeRd = pRangeRdNext;
        pRangeRdNext = pRangeRd->FLink;
        LocalFree(pRangeRd);
    }
}

/*
* Initialize a scatter handle which is used to call VmmScatter* functions.
* CALLER DECREF: return
* -- H
* -- flags = flags as in VMM_FLAG_*
* -- return = handle to be used in VmmScatter_* functions.
*/
_Success_(return != NULL)
PVMMOB_SCATTER VmmScatter_Initialize(_In_ VMM_HANDLE H, _In_ DWORD flags)
{
    PVMMOB_SCATTER hS = NULL;
    if(!(hS = Ob_AllocEx(H, OB_TAG_VMM_SCATTER, LMEM_ZEROINIT, sizeof(VMMOB_SCATTER), (OB_CLEANUP_CB)VmmScatter_CleanupCB, NULL))) {
        return NULL;
    }
    if(!(hS->pmMEMs = ObMap_New(H, OB_MAP_FLAGS_OBJECT_VOID))) {
        Ob_DECREF(hS);
        return NULL;
    }
    hS->H = H;
    hS->flags = flags;
    return hS;
}



// ----------------------------------------------------------------------------
// SEARCH MEMORY FUNCTIONALITY BELOW:
// ----------------------------------------------------------------------------

typedef struct tdVMM_MEMORY_SEARCH_INTERNAL_CONTEXT {
    PVMM_PROCESS pProcess;
    POB_SET psvaResult;
    DWORD cSearch;
    DWORD cb;
    BYTE pb[0x00100000];    // 1MB
    BOOL fMask[0];          // cSearch elements
} VMM_MEMORY_SEARCH_INTERNAL_CONTEXT, *PVMM_MEMORY_SEARCH_INTERNAL_CONTEXT;

/*
* Search data inside region.
*/
_Success_(return)
BOOL VmmSearch_SearchRegion(_In_ VMM_HANDLE H, _In_ PVMM_MEMORY_SEARCH_INTERNAL_CONTEXT ctxi, _In_ PVMM_MEMORY_SEARCH_CONTEXT ctxs)
{
    BYTE v;
    QWORD va, oMax;
    DWORD o, i, iS, cbRead;
    BOOL fMaskFail, f4;
    PVMM_MEMORY_SEARCH_CONTEXT_SEARCHENTRY pS;
    if(ctxs->fAbortRequested || H->fAbort) {
        ctxs->fAbortRequested = TRUE;
        return FALSE;
    }
    ctxs->cbReadTotal += ctxi->cb;
    VmmReadEx(H, ctxi->pProcess, ctxs->vaCurrent, ctxi->pb, ctxi->cb, &cbRead, ctxs->ReadFlags | VMM_FLAG_ZEROPAD_ON_FAIL);
    if(!cbRead) { return TRUE; }
    for(iS = 0; iS < ctxs->cSearch; iS++) {
        pS = ctxs->pSearch + iS;
        f4 = (pS->cb >= 4);
        if(ctxi->fMask[iS]) {
            // mask search
            f4 = f4 && (0 == *(PDWORD)pS->pbSkipMask);
            oMax = ctxi->cb - pS->cb;
            for(o = 0; o <= oMax; o += pS->cbAlign) {
                if(f4) {
                    if(*(PDWORD)pS->pb != *(PDWORD)(ctxi->pb + o)) { continue; }
                } else {
                    v = pS->pbSkipMask[0];
                    if((pS->pb[0] | v) != (ctxi->pb[o] | v)) { continue; }
                }
                fMaskFail = FALSE;
                for(i = 0; i < pS->cb; i++) {
                    v = pS->pbSkipMask[i];
                    if((pS->pb[i] | v) != (ctxi->pb[o + i] | v)) {
                        fMaskFail = TRUE;
                        break;
                    }
                }
                if(fMaskFail) { continue; }
                // match located!
                va = ctxs->vaCurrent + o;
                if(ctxs->pfnResultOptCB) {
                    if(!ctxs->pfnResultOptCB(ctxs, va, iS)) { return FALSE; }
                } else {
                    ctxs->cResult++;
                    if(ctxs->cResult < 0x00100000) {
                        if(!ObSet_Push(ctxi->psvaResult, va)) { return FALSE; }
                    }
                }
            }
        } else {
            // no-mask search
            oMax = ctxi->cb - pS->cb;
            for(o = 0; o <= oMax; o += pS->cbAlign) {
                if(f4) {
                    if(*(PDWORD)pS->pb != *(PDWORD)(ctxi->pb + o)) { continue; }
                } else {
                    if(pS->pb[0] != ctxi->pb[o]) { continue; }
                }
                if(memcmp(ctxi->pb + o, pS->pb, pS->cb)) { continue; }
                // match located!
                va = ctxs->vaCurrent + o;
                if(ctxs->pfnResultOptCB) {
                    if(!ctxs->pfnResultOptCB(ctxs, va, iS)) { return FALSE; }
                } else {
                    ctxs->cResult++;
                    if(ctxs->cResult < 0x00100000) {
                        if(!ObSet_Push(ctxi->psvaResult, va)) { return FALSE; }
                    }
                }
            }
        }
    }
    return TRUE;
}

/*
* Search a physical/virtual address range.
*/
_Success_(return)
BOOL VmmSearch_SearchRange(_In_ VMM_HANDLE H, _In_ PVMM_MEMORY_SEARCH_INTERNAL_CONTEXT ctxi, _In_ PVMM_MEMORY_SEARCH_CONTEXT ctxs, _In_ QWORD vaMax)
{
    while(ctxs->vaCurrent < vaMax) {
        ctxi->cb = (DWORD)min(0x00100000, vaMax + 1 - ctxs->vaCurrent);
        if(!ctxi->cb) { break; }
        if(!VmmSearch_SearchRegion(H, ctxi, ctxs)) { return FALSE; }
        ctxs->vaCurrent += ctxi->cb;
        if(!ctxs->vaCurrent) {
            ctxs->vaCurrent = 0xfffffffffffff000;
            break;
        }
    }
    return TRUE;
}

/*
* Search virtual address space by walking either PTEs or VADs.
*/
_Success_(return)
BOOL VmmSearch_VirtPteVad(_In_ VMM_HANDLE H, _In_ PVMM_MEMORY_SEARCH_INTERNAL_CONTEXT ctxi, _In_ PVMM_MEMORY_SEARCH_CONTEXT ctxs)
{
    BOOL fResult = FALSE;
    DWORD ie = 0;
    QWORD cbPTE, vaMax;
    PVMMOB_MAP_PTE pObPTE = NULL;
    PVMMOB_MAP_VAD pObVAD = NULL;
    PVMM_MAP_PTEENTRY pePTE;
    PVMM_MAP_VADENTRY peVAD;
    ctxs->cResult = 0;
    ctxs->cbReadTotal = 0;
    ctxs->vaCurrent = ctxs->vaMin;
    if(ctxs->fForceVAD || (ctxi->pProcess->fUserOnly && !ctxs->fForcePTE)) {
        // VAD method:
        if(!VmmMap_GetVad(H, ctxi->pProcess, &pObVAD, VMM_VADMAP_TP_CORE)) { goto fail; }
        for(ie = 0; ie < pObVAD->cMap; ie++) {
            peVAD = pObVAD->pMap + ie;
            if(peVAD->vaStart + peVAD->vaEnd < ctxs->vaMin) { continue; }   // skip entries below min address
            if(peVAD->vaStart > ctxs->vaMax) { break; }                     // break if entry above max address
            if(peVAD->vaEnd - peVAD->vaStart > 0x40000000) { continue; }    // don't process 1GB+ entries
            if(ctxs->pfnFilterOptCB && !ctxs->pfnFilterOptCB(ctxs, NULL, peVAD)) { continue; }
            // TODO: is peVAD->vaEnd == 0xfff ????
            ctxs->vaCurrent = max(ctxs->vaCurrent, peVAD->vaStart);
            vaMax = min(ctxs->vaMax, peVAD->vaEnd);
            if(!VmmSearch_SearchRange(H, ctxi, ctxs, vaMax)) { goto fail; }
        }
    } else {
        // PTE method:
        if(!VmmMap_GetPte(H, ctxi->pProcess, &pObPTE, FALSE)) { goto fail; }
        for(ie = 0; ie < pObPTE->cMap; ie++) {
            pePTE = pObPTE->pMap + ie;
            cbPTE = pePTE->cPages << 12;
            if(pePTE->vaBase + cbPTE < ctxs->vaMin) { continue; }           // skip entries below min address
            if(pePTE->vaBase > ctxs->vaMax) { break; }                      // break if entry above max address
            if(cbPTE > 0x40000000) { continue; }                            // don't process 1GB+ entries
            if(ctxs->pfnFilterOptCB && !ctxs->pfnFilterOptCB(ctxs, pePTE, NULL)) { continue; }
            ctxs->vaCurrent = max(ctxs->vaCurrent, pePTE->vaBase);
            vaMax = min(ctxs->vaMax, pePTE->vaBase + cbPTE - 1);
            if(!VmmSearch_SearchRange(H, ctxi, ctxs, vaMax)) { goto fail; }
        }
    }
    fResult = TRUE;
fail:
    Ob_DECREF(pObPTE);
    Ob_DECREF(pObVAD);
    return fResult;
}

/*
* Search for binary data in an address space specified by the parameter pctx.
* For more information about the different search parameters please see the
* struct definition: VMM_MEMORY_SEARCH_CONTEXT
* Search may take a long time. It's not recommended to run this interactively.
* To cancel a search prematurely set the fAbortRequested flag in pctx and
* wait a short while.
* NB! This function is similar to VmmYaraUtil_SearchSingleProcess()
* CALLER DECREF: ppObAddressResult
* -- pProcess
* -- ctxs
* -- ppObAddress
* -- return
*/
_Success_(return)
BOOL VmmSearch(_In_ VMM_HANDLE H, _In_opt_ PVMM_PROCESS pProcess, _Inout_ PVMM_MEMORY_SEARCH_CONTEXT ctxs, _Out_opt_ POB_DATA *ppObAddressResult)
{
    static BYTE pbZERO[sizeof(ctxs->pSearch[0].pb)] = { 0 };
    DWORD iS;
    BOOL fResult = FALSE;
    PVMM_MEMORY_SEARCH_INTERNAL_CONTEXT ctxi = NULL;
    // 1: sanity checks and fix-ups
    if(ppObAddressResult) { *ppObAddressResult = NULL; }
    ctxs->vaMin = ctxs->vaMin & ~0xfff;
    ctxs->vaMax = (ctxs->vaMax - 1) | 0xfff;
    if(H->fAbort || ctxs->fAbortRequested || (ctxs->vaMax < ctxs->vaMin)) { goto fail; }
    if(!ctxs->cSearch || (ctxs->cSearch > 0x01000000)) { goto fail; }
    for(iS = 0; iS < ctxs->cSearch; iS++) {
        if(!ctxs->pSearch[iS].cb || (ctxs->pSearch[iS].cb > sizeof(ctxs->pSearch[iS].pb))) { goto fail; }
        if(!memcmp(ctxs->pSearch[iS].pb, pbZERO, ctxs->pSearch[iS].cb)) { goto fail; }
        if(!ctxs->pSearch[iS].cbAlign) { ctxs->pSearch[iS].cbAlign = 1; }
    }
    if(!ctxs->vaMax) {
        if(!pProcess) {
            ctxs->vaMax = H->dev.paMax;
        } else if(H->vmm.tpMemoryModel == VMMDLL_MEMORYMODEL_X64) {
            ctxs->vaMax = (QWORD)-1;
        } else {
            ctxs->vaMax = (DWORD)-1;
        }
    }
    ctxs->vaMax = min(ctxs->vaMax, 0xfffffffffffff000);
    if(!pProcess) {
        ctxs->vaMax = min(ctxs->vaMax, H->dev.paMax);
    }
    // 2: allocate
    if(!(ctxi = LocalAlloc(0, sizeof(VMM_MEMORY_SEARCH_INTERNAL_CONTEXT) + sizeof(BOOL) * ctxs->cSearch))) { goto fail; }
    if(!(ctxi->psvaResult = ObSet_New(H))) { goto fail; }
    ctxi->cSearch = ctxs->cSearch;
    ctxi->pProcess = pProcess;
    for(iS = 0; iS < ctxs->cSearch; iS++) {
        ctxi->fMask[iS] = (memcmp(ctxs->pSearch[iS].pbSkipMask, pbZERO, ctxs->pSearch[iS].cb) ? TRUE : FALSE);
    }
    // 3: perform search
    if(pProcess && (ctxs->fForcePTE || ctxs->fForceVAD || (H->vmm.tpMemoryModel == VMMDLL_MEMORYMODEL_X64))) {
        fResult = VmmSearch_VirtPteVad(H, ctxi, ctxs);
    } else {
        ctxs->vaCurrent = ctxs->vaMin;
        fResult = VmmSearch_SearchRange(H, ctxi, ctxs, ctxs->vaMax);
    }
    // 4: finish
    if(fResult && ppObAddressResult) {
        *ppObAddressResult = ObSet_GetAll(ctxi->psvaResult);
        fResult = (*ppObAddressResult ? TRUE : FALSE);
    }
fail:
    if(ctxi) {
        Ob_DECREF(ctxi->psvaResult);
        LocalFree(ctxi);
    }
    return fResult;
}



// ----------------------------------------------------------------------------
// MAP FUNCTIONALITY BELOW: 
// SUPPORTED MAPS: PTE, VAD, MODULE, HEAP
// ----------------------------------------------------------------------------

/*
* Retrieve the PTE hardware page table memory map.
* CALLER DECREF: ppObPteMap
* -- H
* -- pProcess
* -- ppObPteMap
* -- fExtendedText
* -- return
*/
_Success_(return)
BOOL VmmMap_GetPte(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess, _Out_ PVMMOB_MAP_PTE *ppObPteMap, _In_ BOOL fExtendedText)
{
    return
        (H->vmm.tpMemoryModel != VMM_MEMORYMODEL_NA) &&
        H->vmm.fnMemoryModel.pfnPteMapInitialize(H, pProcess) &&
        (!fExtendedText || VmmWinPte_InitializeMapText(H, pProcess)) &&
        (*ppObPteMap = Ob_INCREF(pProcess->Map.pObPte));
}

/*
* Comparison function to efficiently locate a single PTE given address and map.
*/
int VmmMap_GetPteEntry_CmpFind(_In_ QWORD va, _In_ QWORD qwEntry)
{
    PVMM_MAP_PTEENTRY pEntry = (PVMM_MAP_PTEENTRY)qwEntry;
    if(va < pEntry->vaBase) { return -1; }
    if(va > pEntry->vaBase + (pEntry->cPages << 12) - 1) { return 1; }
    return 0;
}

/*
* Retrieve a single PVMM_MAP_PTEENTRY for a given PteMap and address inside it.
* -- H
* -- pPteMap
* -- va
* -- return = PTR to PTEENTRY or NULL on fail. Must not be used out of pPteMap scope.
*/
_Success_(return != NULL)
PVMM_MAP_PTEENTRY VmmMap_GetPteEntry(_In_ VMM_HANDLE H, _In_opt_ PVMMOB_MAP_PTE pPteMap, _In_ QWORD va)
{
    if(!pPteMap) { return NULL; }
    return Util_qfind(va, pPteMap->cMap, pPteMap->pMap, sizeof(VMM_MAP_PTEENTRY), VmmMap_GetPteEntry_CmpFind);
}

/*
* Retrieve the VAD extended memory map by range specified by iPage and cPage.
* CALLER DECREF: ppObVadExMap
* -- H
* -- pProcess
* -- ppObVadExMap
* -- tpVmmVadMap = VMM_VADMAP_TP_*
* -- iPage = index of range start in vad map.
* -- cPage = number of pages, starting at iPage.
* -- return
*/
_Success_(return)
BOOL VmmMap_GetVadEx(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess, _Out_ PVMMOB_MAP_VADEX *ppObVadExMap, _In_ VMM_VADMAP_TP tpVmmVadMap, _In_ DWORD iPage, _In_ DWORD cPage)
{
    *ppObVadExMap = MmVadEx_MapInitialize(H, pProcess, tpVmmVadMap, iPage, cPage);
    return *ppObVadExMap != NULL;
}

/*
* Retrieve the VAD memory map.
* CALLER DECREF: ppObVadMap
* -- H
* -- pProcess
* -- ppObVadMap
* -- tpVmmVadMap = VMM_VADMAP_TP_*
* -- return
*/
_Success_(return)
BOOL VmmMap_GetVad(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess, _Out_ PVMMOB_MAP_VAD *ppObVadMap, _In_ VMM_VADMAP_TP tpVmmVadMap)
{
    if(!MmVad_MapInitialize(H, pProcess, tpVmmVadMap, 0)) { return FALSE; }
    *ppObVadMap = Ob_INCREF(pProcess->Map.pObVad);
    return *ppObVadMap != NULL;
}

int VmmMap_GetVadEntry_CmpFind(_In_ QWORD vaFind, _In_ QWORD qwEntry)
{
    PVMM_MAP_VADENTRY pEntry = (PVMM_MAP_VADENTRY)qwEntry;
    if(pEntry->vaStart > vaFind) { return -1; }
    if(pEntry->vaEnd < vaFind) { return 1; }
    return 0;
}

/*
* Retrieve a single PVMM_MAP_VADENTRY for a given VadMap and address inside it.
* -- H
* -- pVadMap
* -- va
* -- return = PTR to VADENTRY or NULL on fail. Must not be used out of pVadMap scope.
*/
_Success_(return != NULL)
PVMM_MAP_VADENTRY VmmMap_GetVadEntry(_In_ VMM_HANDLE H, _In_opt_ PVMMOB_MAP_VAD pVadMap, _In_ QWORD va)
{
    if(!pVadMap) { return NULL; }
    return Util_qfind(va, pVadMap->cMap, pVadMap->pMap, sizeof(VMM_MAP_VADENTRY), VmmMap_GetVadEntry_CmpFind);
}

/*
* Retrieve the process module map.
* CALLER DECREF: ppObModuleMap
* -- H
* -- pProcess
* -- flags = optional flag: VMM_MODULE_FLAG_*
* -- ppObModuleMap
* -- return
*/
_Success_(return)
BOOL VmmMap_GetModule(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess, _In_ DWORD flags, _Out_ PVMMOB_MAP_MODULE *ppObModuleMap)
{
    if(!pProcess->Map.pObModule && !VmmWinLdrModule_Initialize(H, pProcess, NULL)) { return FALSE; }
    if(flags) {
        if((flags & VMM_MODULE_FLAG_DEBUGINFO) && pProcess->Map.pObModule && !pProcess->Map.pObModule->fDebugInfo) {
            VmmWinLdrModule_EnrichDebugInfo(H, pProcess);
            if(!pProcess->Map.pObModule->fDebugInfo) {
                return FALSE;
            }
        }
        if((flags & VMM_MODULE_FLAG_VERSIONINFO) && pProcess->Map.pObModule && !pProcess->Map.pObModule->fVersionInfo) {
            VmmWinLdrModule_EnrichVersionInfo(H, pProcess);
            if(!pProcess->Map.pObModule->fVersionInfo) {
                return FALSE;
            }
        }
    }
    *ppObModuleMap = Ob_INCREF(pProcess->Map.pObModule);
    return *ppObModuleMap != NULL;
}

int VmmMap_HashTableLookup_CmpFind(_In_ QWORD qwHash, _In_ QWORD qwEntry)
{
    DWORD dwHash = (DWORD)qwHash;
    PDWORD pdwEntry = (PDWORD)qwEntry;
    if(*pdwEntry > dwHash) { return -1; }
    if(*pdwEntry < dwHash) { return 1; }
    return 0;
}

/*
* Retrieve a single PVMM_MAP_MODULEENTRY for a given ModuleMap and module name inside it.
* -- H
* -- pModuleMap
* -- uszModuleName
* -- return = PTR to VMM_MAP_MODULEENTRY or NULL on fail. Must not be used out of pModuleMap scope.
*/
_Success_(return != NULL)
PVMM_MAP_MODULEENTRY VmmMap_GetModuleEntry(_In_ VMM_HANDLE H, _In_ PVMMOB_MAP_MODULE pModuleMap, _In_ LPCSTR uszModuleName)
{
    QWORD qwHash, *pqwHashIndex;
    qwHash = CharUtil_HashNameFsU(uszModuleName, 0);
    pqwHashIndex = (PQWORD)Util_qfind(qwHash, pModuleMap->cMap, pModuleMap->pHashTableLookup, sizeof(QWORD), VmmMap_HashTableLookup_CmpFind);
    return pqwHashIndex ? &pModuleMap->pMap[*pqwHashIndex >> 32] : NULL;
}

/*
* Retrieve a single VMM_MAP_MODULEENTRY for a given process and module name.
* CALLER DECREF: ppObModuleMap
* -- H
* -- pProcessOpt
* -- dwPidOpt
* -- uszModuleName
* -- flags = optional flag: VMM_MODULE_FLAG_*
* -- ppObModuleMap
* -- pModuleEntry
* -- return
*/
_Success_(return)
BOOL VmmMap_GetModuleEntryEx(_In_ VMM_HANDLE H, _In_opt_ PVMM_PROCESS pProcessOpt, _In_opt_ DWORD dwPidOpt, _In_opt_ LPCSTR uszModuleName, _In_ DWORD flags, _Out_ PVMMOB_MAP_MODULE *ppObModuleMap, _Out_ PVMM_MAP_MODULEENTRY *pModuleEntry)
{
    PVMM_PROCESS pObProcess = pProcessOpt ? Ob_INCREF(pProcessOpt) : VmmProcessGet(H, dwPidOpt);
    *ppObModuleMap = NULL;
    *pModuleEntry = NULL;
    if(pObProcess && VmmMap_GetModule(H, pObProcess, flags, ppObModuleMap)) {
        if(uszModuleName && uszModuleName[0]) {
            *pModuleEntry = VmmMap_GetModuleEntry(H, *ppObModuleMap, uszModuleName);
        } else if((*ppObModuleMap)->cMap) {
            *pModuleEntry = (*ppObModuleMap)->pMap;
        }
    }
    Ob_DECREF(pObProcess);
    if(*pModuleEntry) { return TRUE; }
    Ob_DECREF_NULL(ppObModuleMap);
    return FALSE;
}

/*
* Retrieve a single PVMM_MAP_MODULEENTRY for a given ModuleMap and virtual address inside it.
* -- H
* -- pModuleMap
* -- va = virtual address within the module range.
* -- return = PTR to VMM_MAP_MODULEENTRY or NULL on fail. Must not be used out of pModuleMap scope.
*/
_Success_(return != NULL)
PVMM_MAP_MODULEENTRY VmmMap_GetModuleEntryEx2(_In_ VMM_HANDLE H, _In_ PVMMOB_MAP_MODULE pModuleMap, _In_ QWORD va)
{
    DWORD i;
    for(i = 0; i < pModuleMap->cMap; i++) {
        if((pModuleMap->pMap[i].vaBase <= va) && (pModuleMap->pMap[i].vaBase + pModuleMap->pMap[i].cbImageSize > va)) {
            return pModuleMap->pMap + i;
        }
    }
    return NULL;
}

/*
* Retrieve POB_MAP<k=vaBase, v=VMM_MAP_MODULEENTRY> for a given ModuleMap.
* CALLER DECREF: *ppmObModuleEntryByVA
* -- H
* -- pModuleMap
* -- ppmObModuleEntryByVA = map consisting of module entries keyed by va (only valid for duration of pModuleMap).
* -- return
*/
_Success_(return)
BOOL VmmMap_GetModuleEntryEx3(_In_ VMM_HANDLE H, _In_ PVMMOB_MAP_MODULE pModuleMap, _Out_ POB_MAP *ppmObModuleEntryByVA)
{
    DWORD i;
    POB_MAP pmOb = NULL;
    PVMM_MAP_MODULEENTRY pe;
    if(!(pmOb = ObMap_New(H, OB_MAP_FLAGS_OBJECT_VOID))) { return FALSE; }
    for(i = 0; i < pModuleMap->cMap; i++) {
        pe = pModuleMap->pMap + i;
        ObMap_Push(pmOb, pe->vaBase, pe);
    }
    *ppmObModuleEntryByVA = pmOb;
    return TRUE;
}

/*
* Retrieve the process unloaded module map.
* CALLER DECREF: ppObUnloadedModuleMap
* -- H
* -- pProcess
* -- ppObUnloadedModuleMap
* -- return
*/
_Success_(return)
BOOL VmmMap_GetUnloadedModule(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess, _Out_ PVMMOB_MAP_UNLOADEDMODULE *ppObUnloadedModuleMap)
{
    if(!pProcess->Map.pObUnloadedModule && !VmmWinUnloadedModule_Initialize(H, pProcess)) { return FALSE; }
    *ppObUnloadedModuleMap = Ob_INCREF(pProcess->Map.pObUnloadedModule);
    return *ppObUnloadedModuleMap != NULL;
}

/*
* Retrieve the process module export address table (EAT) map.
* CALLER DECREF: ppObEatMap
* -- H
* -- pProcess
* -- pModule
* -- ppObEatMap
* -- return
*/
_Success_(return)
BOOL VmmMap_GetEAT(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess, _In_ PVMM_MAP_MODULEENTRY pModuleEntry, _Out_ PVMMOB_MAP_EAT *ppObEatMap)
{
    *ppObEatMap = VmmWinEAT_Initialize(H, pProcess, pModuleEntry);
    return *ppObEatMap != NULL;
}

/*
* Retrieve the export entry index in pEatMap->pMap by function name.
* -- H
* -- pEatMap
* -- uszFunctionName
* -- pdwEntryIndex = pointer to receive the pEatMap->pMap index.
* -- return
*/
_Success_(return)
BOOL VmmMap_GetEATEntryIndexU(_In_ VMM_HANDLE H, _In_ PVMMOB_MAP_EAT pEatMap, _In_ LPCSTR uszFunctionName, _Out_ PDWORD pdwEntryIndex)
{
    QWORD qwHash, *pqwHashIndex;
    qwHash = (DWORD)CharUtil_Hash64U(uszFunctionName, TRUE);
    pqwHashIndex = (PQWORD)Util_qfind(qwHash, pEatMap->cMap, pEatMap->pHashTableLookup, sizeof(QWORD), VmmMap_HashTableLookup_CmpFind);
    *pdwEntryIndex = pqwHashIndex ? *pqwHashIndex >> 32 : 0;
    return (pqwHashIndex != NULL) && (*pdwEntryIndex < pEatMap->cMap);
}

/*
* Retrieve the process module import address table (IAT) map.
* CALLER DECREF: ppObIatMap
* -- H
* -- pProcess
* -- pModule
* -- ppObIatMap
* -- return
*/
_Success_(return)
BOOL VmmMap_GetIAT(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess, _In_ PVMM_MAP_MODULEENTRY pModuleEntry, _Out_ PVMMOB_MAP_IAT *ppObIatMap)
{
    *ppObIatMap = VmmWinIAT_Initialize(H, pProcess, pModuleEntry);
    return *ppObIatMap != NULL;
}

/*
* Retrieve the heap map.
* CALLER DECREF: ppObHeapMap
* -- H
* -- pProcess
* -- ppObHeapMap
* -- return
*/
_Success_(return)
BOOL VmmMap_GetHeap(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess, _Out_ PVMMOB_MAP_HEAP *ppObHeapMap)
{
    if(!pProcess->Map.pObHeap && !VmmHeap_Initialize(H, pProcess)) { return FALSE; }
    *ppObHeapMap = Ob_INCREF(pProcess->Map.pObHeap);
    return *ppObHeapMap != NULL;
}

int VmmMap_GetHeapEntry_CmpFind(_In_ QWORD va, _In_ QWORD qwEntry)
{
    PVMM_MAP_HEAPENTRY pEntry = (PVMM_MAP_HEAPENTRY)qwEntry;
    return (pEntry->va > va) ? -1 : ((pEntry->va < va) ? 1 : 0);
}

/*
* Retrieve a single PVMM_MAP_HEAPENTRY for a given HeapMap and heap virtual address.
* -- H
* -- pHeapMap
* -- vaHeap = virtual address of heap OR heap id.
* -- return = PTR to VMM_MAP_HEAPENTRY or NULL on fail. Must not be used out of pHeapMap scope.
*/
PVMM_MAP_HEAPENTRY VmmMap_GetHeapEntry(_In_ VMM_HANDLE H, _In_ PVMMOB_MAP_HEAP pHeapMap, _In_ QWORD vaHeap)
{
    DWORD i;
    if(vaHeap > 0x1000) {
        return Util_qfind(vaHeap, pHeapMap->cMap, pHeapMap->pMap, sizeof(VMM_MAP_HEAPENTRY), VmmMap_GetHeapEntry_CmpFind);
    }
    for(i = 0; i < pHeapMap->cMap; i++) {
        if(pHeapMap->pMap[i].iHeap == (DWORD)vaHeap) { return pHeapMap->pMap + i; }
    }
    return NULL;
}

/*
* Retrieve the heap alloc map. (memory allocations in the specified heap).
* CALLER DECREF: ppObHeapAllocMap
* -- H
* -- pProcess
* -- vaHeap = va of heap or heap id.
* -- ppObHeapAllocMap
* -- return
*/
_Success_(return)
BOOL VmmMap_GetHeapAlloc(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess, _In_ QWORD vaHeap, _Out_ PVMMOB_MAP_HEAPALLOC *ppObHeapAllocMap)
{
    *ppObHeapAllocMap = VmmHeapAlloc_Initialize(H, pProcess, vaHeap);
    return *ppObHeapAllocMap != NULL;
}

int VmmMap_GetHeapAllocEntry_CmpFind(_In_ QWORD va, _In_ QWORD qwEntry)
{
    PVMM_MAP_HEAPALLOCENTRY pEntry = (PVMM_MAP_HEAPALLOCENTRY)qwEntry;
    return (pEntry->va > va) ? -1 : ((pEntry->va < va) ? 1 : 0);
}

/*
* Retrieve a single PVMM_MAP_HEAPALLOCENTRY for a given HeapAllocMap and a memory allocation address.
* -- H
* -- pHeapAllocMap
* -- vaAlloc
* -- return = PTR to PVMM_MAP_HEAPALLOCENTRY or NULL on fail. Must not be used out of pHeapAllocMap scope.
*/
PVMM_MAP_HEAPALLOCENTRY VmmMap_GetHeapAllocEntry(_In_ VMM_HANDLE H, _In_ PVMMOB_MAP_HEAPALLOC pHeapAllocMap, _In_ QWORD vaAlloc)
{
    return Util_qfind(vaAlloc, pHeapAllocMap->cMap, pHeapAllocMap->pMap, sizeof(VMM_MAP_HEAPALLOCENTRY), VmmMap_GetHeapAllocEntry_CmpFind);
}

/*
* Retrieve the thread map.
* CALLER DECREF: ppObThreadMap
* -- H
* -- pProcess
* -- ppObThreadMap
* -- return
*/
_Success_(return)
BOOL VmmMap_GetThread(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess, _Out_ PVMMOB_MAP_THREAD *ppObThreadMap)
{
    if(!pProcess->Map.pObThread && !VmmWinThread_Initialize(H, pProcess)) { return FALSE; }
    *ppObThreadMap = Ob_INCREF(pProcess->Map.pObThread);
    return *ppObThreadMap ? TRUE : FALSE;
}

int VmmMap_GetThreadEntry_CmpFind(_In_ QWORD dwTID, _In_ QWORD qwEntry)
{
    PVMM_MAP_THREADENTRY pEntry = (PVMM_MAP_THREADENTRY)qwEntry;
    return (pEntry->dwTID > dwTID) ? -1 : ((pEntry->dwTID < dwTID) ? 1 : 0);
}

/*
* Retrieve a single PVMM_MAP_THREADENTRY for a given ThreadMap and ThreadID.
* -- H
* -- pThreadMap
* -- dwTID
* -- return = PTR to VMM_MAP_THREADENTRY or NULL on fail. Must not be used out of pThreadMap scope.
*/
PVMM_MAP_THREADENTRY VmmMap_GetThreadEntry(_In_ VMM_HANDLE H, _In_ PVMMOB_MAP_THREAD pThreadMap, _In_ DWORD dwTID)
{
    return Util_qfind((QWORD)dwTID, pThreadMap->cMap, pThreadMap->pMap, sizeof(VMM_MAP_THREADENTRY), VmmMap_GetThreadEntry_CmpFind);
}

/*
* Retrieve the callstack for the specified thread. Callstack parsing is:
* - only supported for x64 user-mode threads.
* - best-effort and is very resource intense since it may
* - may download a large amounts of PDB symbol data from the Microsoft symbol server.
* Use with caution!
* CALLER DECREF: *ppObThreadCallstackMap
* -- H
* -- pProcess
* -- pThread
* -- flags = VMM_FLAG_NOCACHE (do not use cache)
* -- ppObThreadCallstackMap
* -- return
*/
_Success_(return)
BOOL VmmMap_GetThreadCallstack(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess, _In_ PVMM_MAP_THREADENTRY pThread, _In_ DWORD flags, _Out_ PVMMOB_MAP_THREADCALLSTACK *ppObThreadCallstackMap)
{
    return VmmWinThreadCs_GetCallstack(H, pProcess, pThread, flags, ppObThreadCallstackMap);
}

/*
* Retrieve the HANDLE map
* CALLER DECREF: ppObHandleMap
* -- H
* -- pProcess
* -- ppObHandleMap
* -- fExtendedText
* -- return
*/
_Success_(return)
BOOL VmmMap_GetHandle(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess, _Out_ PVMMOB_MAP_HANDLE *ppObHandleMap, _In_ BOOL fExtendedText)
{
    if(!VmmWinHandle_Initialize(H, pProcess, fExtendedText)) { return FALSE; }
    *ppObHandleMap = Ob_INCREF(pProcess->Map.pObHandle);
    return *ppObHandleMap != NULL;
}

/*
* Retrieve the Physical Memory Map.
* CALLER DECREF: ppObPhysMem
* -- H
* -- ppObPhysMem
* -- return
*/
_Success_(return)
BOOL VmmMap_GetPhysMem(_In_ VMM_HANDLE H, _Out_ PVMMOB_MAP_PHYSMEM *ppObPhysMem)
{
    if(!(*ppObPhysMem = ObContainer_GetOb(H->vmm.pObCMapPhysMem))) {
        *ppObPhysMem = VmmWinPhysMemMap_Initialize(H);
    }
    return *ppObPhysMem != NULL;
}

/*
* Retrieve the USER map
* CALLER DECREF: ppObUserMap
* -- H
* -- ppObUserMap
* -- return
*/
_Success_(return)
BOOL VmmMap_GetUser(_In_ VMM_HANDLE H, _Out_ PVMMOB_MAP_USER *ppObUserMap)
{
    if(!(*ppObUserMap = ObContainer_GetOb(H->vmm.pObCMapUser))) {
        *ppObUserMap = VmmWinUser_Initialize(H);
    }
    return *ppObUserMap != NULL;
}

/*
* Retrieve the VM map
* CALLER DECREF: ppObVmMap
* -- H
* -- ppObVmMap
* -- return
*/
_Success_(return)
BOOL VmmMap_GetVM(_In_ VMM_HANDLE H, _Out_ PVMMOB_MAP_VM *ppObVmMap)
{
    if(!(*ppObVmMap = ObContainer_GetOb(H->vmm.pObCMapVM))) {
        *ppObVmMap = VmmVm_Initialize(H);
    }
    return *ppObVmMap != NULL;
}

/*
* Retrieve the OBJECT MANAGER map
* CALLER DECREF: ppObObjectMap
* -- H
* -- ppObObjectMap
* -- return
*/
_Success_(return)
BOOL VmmMap_GetObject(_In_ VMM_HANDLE H, _Out_ PVMMOB_MAP_OBJECT *ppObObjectMap)
{
    if(!(*ppObObjectMap = ObContainer_GetOb(H->vmm.pObCMapObjMgr))) {
        *ppObObjectMap = VmmWinObjMgr_Initialize(H);
    }
    return *ppObObjectMap != NULL;
}

/*
* Retrieve the KERNEL DEVICE map
* CALLER DECREF: ppObKDeviceMap
* -- H
* -- ppObKDeviceMap
* -- return
*/
_Success_(return)
BOOL VmmMap_GetKDevice(_In_ VMM_HANDLE H, _Out_ PVMMOB_MAP_KDEVICE *ppObKDeviceMap)
{
    if(!(*ppObKDeviceMap = ObContainer_GetOb(H->vmm.pObCMapKDevice))) {
        *ppObKDeviceMap = VmmWinObjKDev_Initialize(H);
    }
    return *ppObKDeviceMap != NULL;
}

/*
* Retrieve the KERNEL DRIVER map
* CALLER DECREF: ppObKDriverMap
* -- H
* -- ppObKDriverMap
* -- return
*/
_Success_(return)
BOOL VmmMap_GetKDriver(_In_ VMM_HANDLE H, _Out_ PVMMOB_MAP_KDRIVER *ppObKDriverMap)
{
    if(!(*ppObKDriverMap = ObContainer_GetOb(H->vmm.pObCMapKDriver))) {
        *ppObKDriverMap = VmmWinObjKDrv_Initialize(H);
    }
    return *ppObKDriverMap != NULL;
}

int VmmMap_GetKDriverEntry_CmpFind(_In_ QWORD vaFind, _In_ QWORD qwEntry)
{
    PVMM_MAP_KDRIVERENTRY pEntry = (PVMM_MAP_KDRIVERENTRY)qwEntry;
    if(vaFind < pEntry->vaStart) { return -1; }
    if(vaFind >= pEntry->vaStart + pEntry->cbDriverSize) { return 1; }
    return 0;
}

/*
* Retrieve a single PVMM_MAP_KDRIVERENTRY for a given KDriverMap and virtual address.
* The virtual address may be address of _DRIVER_OBJECT or inside the driver module range.
* -- H
* -- pKDriverMap
* -- va = virtual address of the object to retrieve.
* -- return = PTR to VMM_MAP_KDRIVERENTRY or NULL on fail. Must not be used out of pKDriverMap scope.
*/
_Success_(return != NULL)
PVMM_MAP_KDRIVERENTRY VmmMap_GetKDriverEntry(_In_ VMM_HANDLE H, _In_ PVMMOB_MAP_KDRIVER pKDriverMap, _In_ QWORD va)
{
    DWORD i;
    PVMM_MAP_KDRIVERENTRY pe;
    if((pe = (PVMM_MAP_KDRIVERENTRY)Util_qfind(va, pKDriverMap->cMap, pKDriverMap->pMap, sizeof(VMM_MAP_KDRIVERENTRY), VmmMap_GetKDriverEntry_CmpFind))) { return pe; }
    for(i = 0; i < pKDriverMap->cMap; i++) {
        if(pKDriverMap->pMap[i].va == va) {
            return pKDriverMap->pMap + i;
        }
    }
    return NULL;
}

/*
* Retrieve VMM_MAP_POOLENTRYTAG within the PVMMOB_MAP_POOL.
* -- H
* -- pPoolMap
* -- dwPoolTag
* -- ppePoolTag
* -- return
*/
_Success_(return)
BOOL VmmMap_GetPoolTag(_In_ VMM_HANDLE H, _In_ PVMMOB_MAP_POOL pPoolMap, _In_ DWORD dwPoolTag, _Out_ PVMM_MAP_POOLENTRYTAG *ppePoolTag)
{
    PVMM_MAP_POOLENTRYTAG pet;
    if(!(pet = Util_qfind((QWORD)dwPoolTag, pPoolMap->cTag, pPoolMap->pTag, sizeof(VMM_MAP_POOLENTRYTAG), Util_qfind_CmpFindTableDWORD))) {
        dwPoolTag = _byteswap_ulong(dwPoolTag);
        pet = Util_qfind((QWORD)dwPoolTag, pPoolMap->cTag, pPoolMap->pTag, sizeof(VMM_MAP_POOLENTRYTAG), Util_qfind_CmpFindTableDWORD);
    }
    *ppePoolTag = pet;
    return pet ? TRUE : FALSE;
}

/*
* Retrieve the index of a VMM_MAP_POOLENTRY within the PVMMOB_MAP_POOL.
* -- H
* -- pPoolMap
* -- vaPoolEntry
* -- ppePoolEntry
* -- return
*/
_Success_(return)
BOOL VmmMap_GetPoolEntry(_In_ VMM_HANDLE H, _In_ PVMMOB_MAP_POOL pPoolMap, _In_ QWORD vaPoolEntry, _Out_ PVMM_MAP_POOLENTRY *ppePoolEntry)
{
    *ppePoolEntry = Util_qfind(vaPoolEntry, pPoolMap->cMap, pPoolMap->pMap, sizeof(VMM_MAP_POOLENTRY), Util_qfind_CmpFindTableQWORD);
    return *ppePoolEntry ? TRUE : FALSE;
}

/*
* Retrieve the POOL map.
* CALLER DECREF: ppObPoolMap
* -- H
* -- ppObPoolMap
* -- fAll = TRUE: retrieve all pools; FALSE: retrieve big page pool only.
* -- return
*/
_Success_(return)
BOOL VmmMap_GetPool(_In_ VMM_HANDLE H, _Out_ PVMMOB_MAP_POOL *ppObPoolMap, _In_ BOOL fAll)
{
    *ppObPoolMap = fAll ? ObContainer_GetOb(H->vmm.pObCMapPoolAll) : ObContainer_GetOb(H->vmm.pObCMapPoolBig);
    if(!*ppObPoolMap) {
        *ppObPoolMap = VmmWinPool_Initialize(H, fAll);
    }
    return *ppObPoolMap != NULL;
}

/*
* Retrieve the NETWORK CONNECTION map
* CALLER DECREF: ppObNetMap
* -- H
* -- ppObNetMap
* -- return
*/
_Success_(return)
BOOL VmmMap_GetNet(_In_ VMM_HANDLE H, _Out_ PVMMOB_MAP_NET *ppObNetMap)
{
    if(!(*ppObNetMap = ObContainer_GetOb(H->vmm.pObCMapNet))) {
        *ppObNetMap = VmmNet_Initialize(H);
    }
    return *ppObNetMap != NULL;
}

/*
* Retrieve the SERVICES map
* CALLER DECREF: ppObServiceMap
* -- H
* -- ppObServiceMap
* -- return
*/
_Success_(return)
BOOL VmmMap_GetService(_In_ VMM_HANDLE H, _Out_ PVMMOB_MAP_SERVICE *ppObServiceMap)
{
    if(!(*ppObServiceMap = ObContainer_GetOb(H->vmm.pObCMapService))) {
        *ppObServiceMap = VmmWinSvc_Initialize(H);
    }
    return *ppObServiceMap != NULL;
}
