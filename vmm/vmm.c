// vmm.c : implementation of functions related to virtual memory management support.
//
// (c) Ulf Frisk, 2018-2019
// Author: Ulf Frisk, pcileech@frizk.net
//

#include "vmm.h"
#include "mm.h"
#include "ob.h"
#include "pdb.h"
#include "vmmproc.h"
#include "vmmwin.h"
#include "vmmwinreg.h"
#include "pluginmanager.h"
#include "util.h"

// ----------------------------------------------------------------------------
// CACHE FUNCTIONALITY:
// PHYSICAL MEMORY CACHING FOR READS AND PAGE TABLES
// ----------------------------------------------------------------------------

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

#define VMM_CACHE2_GET_REGION(qwA)      ((qwA >> 12) % VMM_CACHE2_REGIONS)
#define VMM_CACHE2_GET_BUCKET(qwA)      ((qwA >> 12) % VMM_CACHE2_BUCKETS)

/*
* Invalidate a cache entry (if exists)
*/
VOID VmmCacheInvalidate_2(_In_ DWORD dwTblTag, _In_ QWORD qwA)
{
    DWORD iR, iB;
    PVMM_CACHE_TABLE t;
    PVMMOB_MEM pOb, pObNext;
    t = VmmCacheTableGet(dwTblTag);
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
            Ob_DECREF(pOb);
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
        Ob_DECREF(pOb);
        InterlockedDecrement(&t->R[iR].c);
    }
    LeaveCriticalSection(&t->R[iR].Lock);
}

/*
* Clear the specified cache from all entries.
* -- wTblTag
*/
VOID VmmCacheClear(_In_ DWORD dwTblTag)
{
    DWORD i;
    PVMM_CACHE_TABLE t;
    PVMM_PROCESS pObProcess = NULL;
    // 1: clear cache
    t = VmmCacheTableGet(dwTblTag);
    for(i = 0; i < VMM_CACHE2_REGIONS; i++) {
        VmmCacheReclaim(t, i, TRUE);
    }
    // 2: if tlb cache clear -> update process 'is spider done' flag
    if(dwTblTag == VMM_CACHE_TAG_TLB) {
        while((pObProcess = VmmProcessGetNext(pObProcess, 0))) {
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
    t = VmmCacheTableGet(((POB)pOb)->_tag);
    if(!t) {
        vmmprintf_fn("ERROR - SHOULD NOT HAPPEN - INVALID OBJECT TAG %02X\n", ((POB)pOb)->_tag);
        return;
    }
    if(!t->fActive) { return; }
    Ob_INCREF(pOb);
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
    t = VmmCacheTableGet(((POB)pOb)->_tag);
    if(!t) {
        vmmprintf_fn("ERROR - SHOULD NOT HAPPEN - INVALID OBJECT TAG %02X\n", ((POB)pOb)->_tag);
        return;
    }
    if((pOb->h.cb != 0x1000) || (pOb->h.qwA == (QWORD)-1) || !t->fActive) {
        // decrement refcount of object - callback will take care of
        // re-insertion into empty list when refcount becomes low enough.
        Ob_DECREF(pOb);
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

PVMMOB_MEM VmmCacheReserve(_In_ DWORD dwTblTag)
{
    PVMM_CACHE_TABLE t;
    PVMMOB_MEM pOb;
    PSLIST_ENTRY e;
    WORD iReclaimLast, cLoopProtect = 0;
    t = VmmCacheTableGet(dwTblTag);
    if(!t || !t->fActive) { return NULL; }
    while(!(e = InterlockedPopEntrySList(&t->ListHeadEmpty))) {
        if(t->cTotal < VMM_CACHE2_MAX_ENTRIES) {
            // below max threshold -> create new
            pOb = Ob_Alloc(t->tag, LMEM_ZEROINIT, sizeof(VMMOB_MEM), NULL, VmmCache_CallbackRefCount1);
            if(!pOb) { return NULL; }
            pOb->h.magic = MEM_IO_SCATTER_HEADER_MAGIC;
            pOb->h.version = MEM_IO_SCATTER_HEADER_VERSION;
            pOb->h.cbMax = 0x1000;
            pOb->h.pb = pOb->pb;
            pOb->h.qwA = (QWORD)-1;
            Ob_INCREF(pOb);  // "total list" reference
            InterlockedPushEntrySList(&t->ListHeadTotal, &pOb->SListTotal);
            InterlockedIncrement(&t->cTotal);
            return pOb;         // return fresh object - refcount = 2.
        }
        // reclaim existing entries
        iReclaimLast = InterlockedIncrement16(&t->iReclaimLast);
        VmmCacheReclaim(t, iReclaimLast % VMM_CACHE2_REGIONS, FALSE);
        if(++cLoopProtect == VMM_CACHE2_REGIONS) {
            vmmprintf_fn("ERROR - SHOULD NOT HAPPEN - CACHE %04X DRAINED OF ENTRIES\n", dwTblTag);
            Sleep(10);
        }
    }
    InterlockedDecrement(&t->cEmpty);
    pOb = CONTAINING_RECORD(e, VMMOB_MEM, SListEmpty);
    pOb->h.qwA = (QWORD)-1;
    pOb->h.cb = 0;
    return pOb; // reference overtaken by callee (from EmptyList)
}

PVMMOB_MEM VmmCacheGet(_In_ DWORD dwTblTag, _In_ QWORD qwA)
{
    PVMM_CACHE_TABLE t;
    DWORD iR;
    PVMMOB_MEM pOb;
    t = VmmCacheTableGet(dwTblTag);
    if(!t || !t->fActive) { return NULL; }
    iR = VMM_CACHE2_GET_REGION(qwA);
    EnterCriticalSection(&t->R[iR].Lock);
    pOb = t->R[iR].B[VMM_CACHE2_GET_BUCKET(qwA)];
    while(pOb && (qwA != pOb->h.qwA)) {
        pOb = pOb->FLink;
    }
    Ob_INCREF(pOb);
    LeaveCriticalSection(&t->R[iR].Lock);
    return pOb;
}

PVMMOB_MEM VmmCacheGet_FromDeviceOnMiss(_In_ DWORD dwTblTag, _In_ DWORD dwTblTagSecondaryOpt, _In_ QWORD qwA)
{
    PVMMOB_MEM pObMEM, pObReservedMEM;
    PMEM_IO_SCATTER_HEADER pMEM;
    pObMEM = VmmCacheGet(dwTblTag, qwA);
    if(pObMEM) { return pObMEM; }
    if((pObReservedMEM = VmmCacheReserve(dwTblTag))) {
        pMEM = &pObReservedMEM->h;
        pMEM->qwA = qwA;
        if(dwTblTagSecondaryOpt && (pObMEM = VmmCacheGet(dwTblTagSecondaryOpt, qwA))) {
            pMEM->cb = 0x1000;
            memcpy(pMEM->pb, pObMEM->pb, 0x1000);
            Ob_DECREF(pObMEM);
            pObMEM = NULL;
        }
        if(pMEM->cb != 0x1000) {
            LeechCore_ReadScatter(&pMEM, 1);
        }
        if(pMEM->cb == 0x1000) {
            Ob_INCREF(pObReservedMEM);
            VmmCacheReserveReturn(pObReservedMEM);
            return pObReservedMEM;
        }
        VmmCacheReserveReturn(pObReservedMEM);
    }
    return NULL;
}

BOOL VmmCacheExists(_In_ DWORD dwTblTag, _In_ QWORD qwA)
{
    BOOL result;
    PVMMOB_MEM pOb;
    pOb = VmmCacheGet(dwTblTag, qwA);
    result = pOb != NULL;
    Ob_DECREF(pOb);
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

VOID VmmCache2Close(_In_ DWORD dwTblTag)
{
    PVMM_CACHE_TABLE t;
    PVMMOB_MEM pOb;
    PSLIST_ENTRY e;
    DWORD i;
    t = VmmCacheTableGet(dwTblTag);
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
        Ob_DECREF(pOb);
        InterlockedDecrement(&t->cEmpty);
    }
    // remove from "total list"
    while(e = InterlockedPopEntrySList(&t->ListHeadTotal)) {
        pOb = CONTAINING_RECORD(e, VMMOB_MEM, SListTotal);
        Ob_DECREF(pOb);
        InterlockedDecrement(&t->cTotal);
    }
}

VOID VmmCache2Initialize(_In_ DWORD dwTblTag)
{
    DWORD i;
    PVMM_CACHE_TABLE t;
    t = VmmCacheTableGet(dwTblTag);
    if(!t || t->fActive) { return; }
    for(i = 0; i < VMM_CACHE2_REGIONS; i++) {
        InitializeCriticalSection(&t->R[i].Lock);
    }
    InitializeSListHead(&t->ListHeadEmpty);
    InitializeSListHead(&t->ListHeadTotal);
    t->fActive = TRUE;
    t->tag = dwTblTag;
}

/*
* Prefetch a set of physical addresses contained in pTlbPrefetch into the Tlb.
* NB! pTlbPrefetch must not be updated/altered during the function call.
* -- pProcess
* -- pTlbPrefetch = the page table addresses to prefetch (on entry) and empty set on exit.
*/
VOID VmmTlbPrefetch(_In_ POB_VSET pTlbPrefetch)
{
    QWORD pbTlb = 0;
    DWORD cTlbs, i = 0;
    PPVMMOB_MEM ppObMEMs = NULL;
    PPMEM_IO_SCATTER_HEADER ppMEMs = NULL;
    if(!(cTlbs = ObVSet_Size(pTlbPrefetch))) { goto fail; }
    if(!(ppMEMs = LocalAlloc(0, cTlbs * sizeof(PMEM_IO_SCATTER_HEADER)))) { goto fail; }
    if(!(ppObMEMs = LocalAlloc(0, cTlbs * sizeof(PVMMOB_MEM)))) { goto fail; }
    while((cTlbs = min(0x2000, ObVSet_Size(pTlbPrefetch)))) {   // protect cache bleed -> max 0x2000 pages/round
        for(i = 0; i < cTlbs; i++) {
            ppObMEMs[i] = VmmCacheReserve(VMM_CACHE_TAG_TLB);
            ppMEMs[i] = &ppObMEMs[i]->h;
            ppMEMs[i]->qwA = ObVSet_Pop(pTlbPrefetch);
        }
        LeechCore_ReadScatter(ppMEMs, cTlbs);
        for(i = 0; i < cTlbs; i++) {
            if((ppMEMs[i]->cb == 0x1000) && !VmmTlbPageTableVerify(ppMEMs[i]->pb, ppMEMs[i]->qwA, FALSE)) {
                ppMEMs[i]->cb = 0;  // "fail" invalid page table read
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
VOID VmmCachePrefetchPages(_In_opt_ PVMM_PROCESS pProcess, _In_opt_ POB_VSET pPrefetchPages, _In_ QWORD flags)
{
    QWORD qwA = 0;
    DWORD cPages, iMEM = 0;
    PPMEM_IO_SCATTER_HEADER ppMEMs = NULL;
    cPages = ObVSet_Size(pPrefetchPages);
    if(!cPages || (ctxVmm->flags & VMM_FLAG_NOCACHE)) { return; }
    if(!LeechCore_AllocScatterEmpty(cPages, &ppMEMs)) { return; }
    while((qwA = ObVSet_GetNext(pPrefetchPages, qwA))) {
        ppMEMs[iMEM++]->qwA = qwA & ~0xfff;
    }
    if(pProcess) {
        VmmReadScatterVirtual(pProcess, ppMEMs, iMEM, flags);
    } else {
        VmmReadScatterPhysical(ppMEMs, iMEM, flags);
    }
    LeechCore_MemFree(ppMEMs);
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
    POB_VSET pObVSet = NULL;
    if(!cAddresses || !(pObVSet = ObVSet_New())) { return; }
    va_start(arguments, cAddresses);
    while(cAddresses) {
        ObVSet_Push(pObVSet, va_arg(arguments, QWORD) & ~0xfff);
        cAddresses--;
    }
    va_end(arguments);
    VmmCachePrefetchPages(pProcess, pObVSet, 0);
    Ob_DECREF(pObVSet);
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
VOID VmmCachePrefetchPages3(_In_opt_ PVMM_PROCESS pProcess, _In_opt_ POB_VSET pPrefetchPagesNonPageAligned, _In_ DWORD cb, _In_ QWORD flags)
{
    QWORD qwA = 0;
    POB_VSET pObSetAlign;
    if(!cb || !pPrefetchPagesNonPageAligned) { return; }
    if(!(pObSetAlign = ObVSet_New())) { return; }
    while((qwA = ObVSet_GetNext(pPrefetchPagesNonPageAligned, qwA))) {
        ObVSet_Push_PageAlign(pObSetAlign, qwA, cb);
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
    POB_VSET pObVSet = NULL;
    if(!cAddresses || !(pObVSet = ObVSet_New())) { return; }
    while(cAddresses) {
        cAddresses--;
        if(pqwAddresses[cAddresses]) {
            ObVSet_Push_PageAlign(pObVSet, pqwAddresses[cAddresses], cb);
        }
    }
    VmmCachePrefetchPages(pProcess, pObVSet, 0);
    Ob_DECREF(pObVSet);
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
        (!fExtendedText || VmmWin_InitializePteMapText(pProcess)) &&
        (*ppObPteMap = Ob_INCREF(pProcess->Map.pObPte));
}

int VmmMap_GetPteEntry_CmpFind(_In_ QWORD vaFind, _In_ PVMM_MAP_PTEENTRY pEntry)
{
    if(pEntry->vaBase > vaFind) { return -1; }
    if(pEntry->vaBase + (pEntry->cPages << 12) - 1 < vaFind) { return 1; }
    return 0;
}

/*
* Retrieve a single PVMM_MAP_PTEENTRY from the PTE hardware page table memory map.
* -- pProcess
* -- ppObPteMap
* -- fExtendedText
* -- return = PTR to PTEENTRY or NULL on fail. Must not be used out of pPteMap scope.
*/
PVMM_MAP_PTEENTRY VmmMap_GetPteEntry(_In_ PVMMOB_MAP_PTE pPteMap, _In_ QWORD va)
{
    if(!pPteMap) { return NULL; }
    return Util_qfind((PVOID)va, pPteMap->cMap, pPteMap->pMap, sizeof(VMM_MAP_PTEENTRY), (int(*)(PVOID, PVOID))VmmMap_GetPteEntry_CmpFind);
}

/*
* Retrieve the VAD memory map.
* CALLER DECREF: ppObVadMap
* -- pProcess
* -- ppObVadMap
* -- fExtendedText
* -- return
*/
_Success_(return)
BOOL VmmMap_GetVad(_In_ PVMM_PROCESS pProcess, _Out_ PVMMOB_MAP_VAD *ppObVadMap, _In_ BOOL fExtendedText)
{
    if(!MmVad_MapInitialize(pProcess, fExtendedText, 0)) { return FALSE; }
    *ppObVadMap = Ob_INCREF(pProcess->Map.pObVad);
    return TRUE;
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
    if(!pProcess->Map.pObModule && !VmmWin_InitializeLdrModules(pProcess)) { return FALSE; }
    *ppObModuleMap = Ob_INCREF(pProcess->Map.pObModule);
    return TRUE;
}

int VmmMap_GetModuleEntry_CmpFind(_In_ DWORD qwHash, _In_ PDWORD pdwEntry)
{
    if(*pdwEntry > qwHash) { return -1; }
    if(*pdwEntry < qwHash) { return 1; }
    return 0;
}

/*
* Retrieve a single PVMM_MAP_MODULEENTRY for a given ModuleMap and module name inside it.
* -- pModuleMap
* -- wszModuleName
* -- return = PTR to VMM_MAP_MODULEENTRY or NULL on fail. Must not be used out of pModuleMap scope.
*/
PVMM_MAP_MODULEENTRY VmmMap_GetModuleEntry(_In_ PVMMOB_MAP_MODULE pModuleMap, _In_ LPWSTR wszModuleName)
{
    QWORD qwHash, *pqwHashIndex;
    WCHAR wsz[MAX_PATH];
    Util_PathFileNameFixW(wsz, wszModuleName, 0);
    qwHash = Util_HashStringUpperW(wsz);
    pqwHashIndex = (PQWORD)Util_qfind((PVOID)qwHash, pModuleMap->cMap, pModuleMap->pHashTableLookup, sizeof(QWORD), (int(*)(PVOID, PVOID))VmmMap_GetModuleEntry_CmpFind);
    return pqwHashIndex ? &pModuleMap->pMap[*pqwHashIndex >> 32] : NULL;
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
    return TRUE;
}

/*
* LPTHREAD_START_ROUTINE for VmmMap_GetThreadAsync.
*/
DWORD VmmMap_GetThreadAsync_Thread(_In_ PVMM_PROCESS pProcess)
{
    if(ctxVmm->ThreadWorkers.fEnabled) {
        InterlockedIncrement(&ctxVmm->ThreadWorkers.c);
        VmmWinThread_Initialize(pProcess, TRUE);
        InterlockedDecrement(&ctxVmm->ThreadWorkers.c);
    }
    return 1;
}

/*
* Start async initialization of the thread map. This may be done to speed up
* retrieval of the thread map in the future since processing to retrieve it
* has already been progressing for a while. This may be useful for processes
* with large amount of threads - such as the system process.
* -- pProcess
*/
VOID VmmMap_GetThreadAsync(_In_ PVMM_PROCESS pProcess)
{
    HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)VmmMap_GetThreadAsync_Thread, pProcess, 0, NULL);
    if(hThread) { CloseHandle(hThread); }
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
    if(!pProcess->Map.pObThread && !VmmWinThread_Initialize(pProcess, FALSE)) { return FALSE; }
    *ppObThreadMap = Ob_INCREF(pProcess->Map.pObThread);
    return TRUE;
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
    return TRUE;
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
            return (PVMM_PROCESS)Ob_INCREF(pt->_M[i]);
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
    PVMMOB_PROCESS_TABLE pt = (PVMMOB_PROCESS_TABLE)ObContainer_GetOb(ctxVmm->pObCPROC);
    pProcess = VmmProcessGetEx(pt, dwPID);
    Ob_DECREF(pt);
    return pProcess;
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
* -- flags = 0 (recommended) or VMM_FLAG_PROCESS_SHOW_TERMINATED (_only_ if default setting in ctxVmm->flags should be overridden)
* -- return = a process struct, or NULL if not found.
*/
PVMM_PROCESS VmmProcessGetNextEx(_In_opt_ PVMMOB_PROCESS_TABLE pt, _In_opt_ PVMM_PROCESS pProcess, _In_ QWORD flags)
{
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
* Object manager callback before 'static process' object cleanup
* decrease refcount of any internal objects.
*/
VOID VmmProcessStatic_CloseObCallback(_In_ PVOID pVmmOb)
{
    PVMMOB_PROCESS_PERSISTENT pProcessStatic = (PVMMOB_PROCESS_PERSISTENT)pVmmOb;
    Ob_DECREF_NULL(&pProcessStatic->pObCMapVadPrefetch);
    Ob_DECREF_NULL(&pProcessStatic->pObCLdrModulesPrefetch32);
    Ob_DECREF_NULL(&pProcessStatic->pObCLdrModulesPrefetch64);
    Ob_DECREF_NULL(&pProcessStatic->pObCMapThreadPrefetch);
    LocalFree(pProcessStatic->UserProcessParams.szCommandLine);
    LocalFree(pProcessStatic->UserProcessParams.szImagePathName);
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
        pProcess->pObPersistent->pObCMapVadPrefetch = ObContainer_New(NULL);
        pProcess->pObPersistent->pObCLdrModulesPrefetch32 = ObContainer_New(NULL);
        pProcess->pObPersistent->pObCLdrModulesPrefetch64 = ObContainer_New(NULL);
        pProcess->pObPersistent->pObCMapThreadPrefetch = ObContainer_New(NULL);
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
    Ob_DECREF(pProcess->Map.pObHeap);
    Ob_DECREF(pProcess->Map.pObThread);
    Ob_DECREF(pProcess->Map.pObHandle);
    Ob_DECREF(pProcess->pObPersistent);
    // plugin cleanup below
    Ob_DECREF(pProcess->Plugin.pObCLdrModulesDisplayCache);
    Ob_DECREF(pProcess->Plugin.pObCPeDumpDirCache);
    Ob_DECREF(pProcess->Plugin.pObCPhys2Virt);
    // delete lock
    DeleteCriticalSection(&pProcess->LockUpdate);
    DeleteCriticalSection(&pProcess->Map.LockUpdateThreadMap);
    DeleteCriticalSection(&pProcess->Map.LockUpdateExtendedInfo);
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
    PVMMOB_MEM pObDTB = NULL;
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
        ptNew->pObCNewPROC = ObContainer_New(NULL);
        ObContainer_SetOb(ptOld->pObCNewPROC, ptNew);
    }
    // 3: Sanity check - process to create not already in 'new' table.
    pProcess = VmmProcessGetEx(ptNew, dwPID);
    if(pProcess) { goto fail; }
    // 4: Prepare existing item, or create new item, for new PID
    if(!fTotalRefresh) {
        pProcess = VmmProcessGetEx(ptOld, dwPID);
    }
    if(!pProcess) {
        pProcess = (PVMM_PROCESS)Ob_Alloc(OB_TAG_VMM_PROCESS, LMEM_ZEROINIT, sizeof(VMM_PROCESS), VmmProcess_CloseObCallback, NULL);
        if(!pProcess) { goto fail; }
        InitializeCriticalSectionAndSpinCount(&pProcess->LockUpdate, 4096);
        InitializeCriticalSection(&pProcess->Map.LockUpdateThreadMap);
        InitializeCriticalSection(&pProcess->Map.LockUpdateExtendedInfo);
        memcpy(pProcess->szName, szName, 16);
        pProcess->szName[15] = 0;
        pProcess->dwPID = dwPID;
        pProcess->dwPPID = dwPPID;
        pProcess->dwState = dwState;
        pProcess->paDTB = paDTB;
        pProcess->paDTB_UserOpt = paDTB_UserOpt;
        pProcess->fUserOnly = fUserOnly;
        pProcess->fTlbSpiderDone = pProcess->fTlbSpiderDone;
        pProcess->Plugin.pObCLdrModulesDisplayCache = ObContainer_New(NULL);
        pProcess->Plugin.pObCPeDumpDirCache = ObContainer_New(NULL);
        pProcess->Plugin.pObCPhys2Virt = ObContainer_New(NULL);
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
    pt->pObCNewPROC = ObContainer_New(NULL);
    ctxVmm->pObCPROC = ObContainer_New(pt);
    Ob_DECREF(pt);
    return TRUE;
}

// ----------------------------------------------------------------------------
// PROCESS PARALLELIZATION FUNCTIONALITY:
// ----------------------------------------------------------------------------

#define VMM_PROCESS_ACTION_FOREACH_THREADS_PARALLEL     0x00c

typedef struct tdVMMOB_PROCESS_ACTION_FOREACH {
    OB ObHdr;
    DWORD Reserved;
    DWORD cProcess;
    HANDLE hSemaphore;
    VOID(*pfnAction)(_In_ PVMM_PROCESS pProcess, _In_ PVOID ctx);
    PVOID ctx;
    PVMM_PROCESS pProcesses[];
} VMMOB_PROCESS_ACTION_FOREACH, *PVMMOB_PROCESS_ACTION_FOREACH;

DWORD VmmProcessActionForeachParallel_ThreadProc(PVMMOB_PROCESS_ACTION_FOREACH ctxObForeach)
{
    DWORD i;
    WaitForSingleObject(ctxObForeach->hSemaphore, INFINITE);
    for(i = 0; i < ctxObForeach->cProcess && ctxVmm->ThreadWorkers.fEnabled; i++) {
        ctxObForeach->pfnAction(ctxObForeach->pProcesses[i], ctxObForeach->ctx);
    }
    ReleaseSemaphore(ctxObForeach->hSemaphore, 1, NULL);
    Ob_DECREF(ctxObForeach);
    return 1;
}

VOID VmmProcessActionForeachParallel_CloseObCallback(_In_ PVMMOB_PROCESS_ACTION_FOREACH ctxObForeach)
{
    DWORD i;
    for(i = 0; i < ctxObForeach->cProcess; i++) {
        Ob_DECREF(ctxObForeach->pProcesses[i]);
    }
}

BOOL VmmProcessActionForeachParallel_CriteriaActiveOnly(_In_ PVMM_PROCESS pProcess, _In_opt_ PVOID ctx)
{
    return pProcess->dwState == 0;
}

VOID VmmProcessActionForeachParallel(_In_opt_ PVOID ctx, _In_opt_ DWORD dwThreadLoadFactor, _In_opt_ BOOL(*pfnCriteria)(_In_ PVMM_PROCESS pProcess, _In_opt_ PVOID ctx), _In_ VOID(*pfnAction)(_In_ PVMM_PROCESS pProcess, _In_opt_ PVOID ctx))
{
    HANDLE hSemaphore;
    DWORD dwPID, cThreads = 0;
    HANDLE hThreads[MAXIMUM_WAIT_OBJECTS];
    PVMMOB_PROCESS_ACTION_FOREACH ctxObForeach = NULL;
    PVMM_PROCESS pObProcess = NULL;
    POB_VSET pObProcessSelectedSet = NULL;
    InterlockedIncrement(&ctxVmm->ThreadWorkers.c);
    hSemaphore = CreateSemaphore(NULL, VMM_PROCESS_ACTION_FOREACH_THREADS_PARALLEL, VMM_PROCESS_ACTION_FOREACH_THREADS_PARALLEL, NULL);
    if(!hSemaphore) { goto fail; }
    if(!(pObProcessSelectedSet = ObVSet_New())) { goto fail; }
    // 1: select processes to queue using criteria function
    while(pObProcess = VmmProcessGetNext(pObProcess, VMM_FLAG_PROCESS_SHOW_TERMINATED)) {
        if(!pfnCriteria || pfnCriteria(pObProcess, ctx)) {
            ObVSet_Push(pObProcessSelectedSet, pObProcess->dwPID);
        }
    }
    if(!ObVSet_Size(pObProcessSelectedSet)) { goto fail; }
    dwThreadLoadFactor = max(dwThreadLoadFactor, 1 + (ObVSet_Size(pObProcessSelectedSet) / MAXIMUM_WAIT_OBJECTS));
    // 2: queue selected processes onto threads and start execute
    while(ctxVmm->ThreadWorkers.fEnabled && (dwPID = (DWORD)ObVSet_Pop(pObProcessSelectedSet))) {
        pObProcess = VmmProcessGet(dwPID);
        if(pObProcess) {
            if(!ctxObForeach) {
                ctxObForeach = Ob_Alloc('ea__', 0, sizeof(VMMOB_PROCESS_ACTION_FOREACH) + dwThreadLoadFactor * sizeof(PVMM_PROCESS), VmmProcessActionForeachParallel_CloseObCallback, NULL);
                if(!ctxObForeach) { goto fail; }
                ctxObForeach->ctx = ctx;
                ctxObForeach->hSemaphore = hSemaphore;
                ctxObForeach->pfnAction = pfnAction;
                ctxObForeach->Reserved = cThreads;
                ctxObForeach->cProcess = 0;
            }
            ctxObForeach->pProcesses[ctxObForeach->cProcess++] = pObProcess;
            pObProcess = NULL;          // object reference responsibility already passed on to ctxObForeach object.
            if(ctxObForeach->cProcess == dwThreadLoadFactor) {
                hThreads[cThreads] = CreateThread(NULL, 0, VmmProcessActionForeachParallel_ThreadProc, ctxObForeach, 0, NULL);
                if(!hThreads[cThreads]) { goto fail; }
                cThreads++;
                ctxObForeach = NULL;    // object reference responsibility already passed on to CreateThread function call.
            }
        }
    }
    if(ctxObForeach) {          // process any remaining objects
        hThreads[cThreads] = CreateThread(NULL, 0, VmmProcessActionForeachParallel_ThreadProc, ctxObForeach, 0, NULL);
        if(!hThreads[cThreads]) { goto fail; }
        cThreads++;
        ctxObForeach = NULL;    // object reference responsibility already passed on to CreateThread function call.
    }
fail:
    WaitForMultipleObjects(cThreads, hThreads, TRUE, INFINITE);
    while(cThreads) {
        cThreads--;
        if(hThreads[cThreads]) { CloseHandle(hThreads[cThreads]); }
    }
    if(hSemaphore) { CloseHandle(hSemaphore); }
    Ob_DECREF(pObProcess);
    Ob_DECREF(pObProcessSelectedSet);
    Ob_DECREF(ctxObForeach);
    InterlockedDecrement(&ctxVmm->ThreadWorkers.c);
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
                Ob_DECREF(pObCacheEntry);
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
            if((ppObCacheSpeculative[cSpeculative] = VmmCacheReserve(VMM_CACHE_TAG_PHYS))) {
                ppMEMsSpeculative[cSpeculative] = &ppObCacheSpeculative[cSpeculative]->h;
                ppMEMsSpeculative[cSpeculative]->cb = 0;
                ppMEMsSpeculative[cSpeculative]->qwA = ((QWORD)ppMEMsSpeculative[cSpeculative - 1]->qwA & ~0xfff) + 0x1000;
                ppMEMsSpeculative[cSpeculative]->pvReserved2 = (PVOID)3;  // 3 == speculative & backed by cache reserved
                cSpeculative++;
            }
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
                if((pObReservedMEM = VmmCacheReserve(VMM_CACHE_TAG_PHYS))) {
                    pObReservedMEM->h.qwA = pMEM->qwA;
                    pObReservedMEM->h.cb = 0x1000;
                    memcpy(pObReservedMEM->h.pb, pMEM->pb, 0x1000);
                    VmmCacheReserveReturn(pObReservedMEM);
                }
            }
        }
    }
}

VOID VmmReadScatterVirtual(_In_ PVMM_PROCESS pProcess, _Inout_updates_(cpMEMsVirt) PPMEM_IO_SCATTER_HEADER ppMEMsVirt, _In_ DWORD cpMEMsVirt, _In_ QWORD flags)
{
    // NB! the buffers pIoPA / ppMEMsPhys are used for both:
    //     - physical memory (grows from 0 upwards)
    //     - paged memory (grows from top downwards).
    BOOL fVirt2Phys;
    DWORD i = 0, iVA, iPA;
    QWORD qwPA, qwPagedPA = 0;
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
        qwPA = 0;
        fVirt2Phys = VmmVirt2Phys(pProcess, pIoVA->qwA, &qwPA);
        // PAGED MEMORY
        if(!fVirt2Phys && !(VMM_FLAG_NOPAGING & (flags | ctxVmm->flags)) && (pIoVA->cbMax == 0x1000) && ctxVmm->fnMemoryModel.pfnPagedRead) {
            if(ctxVmm->fnMemoryModel.pfnPagedRead(pProcess, pIoVA->qwA, qwPA, pIoVA->pb, &qwPagedPA, flags)) {
                pIoVA->cb = 0x1000;
                continue;
            }
            if(qwPagedPA) {
                qwPA = qwPagedPA;
                fVirt2Phys = TRUE;
            }
        }
        if(fVirt2Phys) {    // PHYS MEMORY
            pIoPA = ppMEMsPhys[iPA] = (PMEM_IO_SCATTER_HEADER)pbBufferMEMs + iPA;
            iPA++;
        } else {            // NO TRANSLATION MEMORY / FAILED PAGED MEMORY
            pIoVA->cb = 0;
            if(VMM_FLAG_ZEROPAD_ON_FAIL & (flags | ctxVmm->flags)) {
                ZeroMemory(pIoVA->pb, pIoVA->cbMax);
            }
            continue;
        }
        pIoPA->magic = MEM_IO_SCATTER_HEADER_MAGIC;
        pIoPA->version = MEM_IO_SCATTER_HEADER_VERSION;
        pIoPA->qwA = qwPA;
        pIoPA->cbMax = 0x1000;
        pIoPA->cb = 0;
        pIoPA->pb = pIoVA->pb;
        pIoPA->pvReserved1 = (PVOID)pIoVA;
    }
    // 3: read and check result
    if(iPA) {
        VmmReadScatterPhysical(ppMEMsPhys, iPA, flags);
        while(iPA > 0) {
            iPA--;
            ((PMEM_IO_SCATTER_HEADER)ppMEMsPhys[iPA]->pvReserved1)->cb = ppMEMsPhys[iPA]->cb;
        }
    }
    LocalFree(pbBufferLarge);
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
    if(ctxVmm->pVmmVfsModuleList) { PluginManager_Close(); }
    ctxVmm->ThreadWorkers.fEnabled = FALSE;
    if(ctxVmm->ThreadProcCache.fEnabled) {
        ctxVmm->ThreadProcCache.fEnabled = FALSE;
        while(ctxVmm->ThreadProcCache.hThread) {
            SwitchToThread();
        }
    }
    while(ctxVmm->ThreadWorkers.c) {
        SwitchToThread();
    }
    VmmWinReg_Close();
    PDB_Close();
    Ob_DECREF_NULL(&ctxVmm->pObVfsDumpContext);
    Ob_DECREF_NULL(&ctxVmm->pObCPROC);
    if(ctxVmm->fnMemoryModel.pfnClose) {
        ctxVmm->fnMemoryModel.pfnClose();
    }
    MmWin_PagingClose();
    VmmCache2Close(VMM_CACHE_TAG_PHYS);
    VmmCache2Close(VMM_CACHE_TAG_TLB);
    VmmCache2Close(VMM_CACHE_TAG_PAGING);
    Ob_DECREF_NULL(&ctxVmm->Cache.PAGING_FAILED);
    Ob_DECREF_NULL(&ctxVmm->Cache.pmPrototypePte);
    Ob_DECREF_NULL(&ctxVmm->pObCCachePrefetchEPROCESS);
    Ob_DECREF_NULL(&ctxVmm->pObCCachePrefetchRegistry);
    DeleteCriticalSection(&ctxVmm->TcpIp.LockUpdate);
    DeleteCriticalSection(&ctxVmm->MasterLock);
    LocalFree(ctxVmm->ObjectTypeTable.wszMultiText);
    LocalFree(ctxVmm);
    ctxVmm = NULL;
}

VOID VmmWriteEx(_In_opt_ PVMM_PROCESS pProcess, _In_ QWORD qwA, _In_ PBYTE pb, _In_ DWORD cb, _Out_opt_ PDWORD pcbWrite)
{
    DWORD i = 0, oA = 0, cbWrite = 0, cbP, cMEMs;
    PBYTE pbBuffer;
    PMEM_IO_SCATTER_HEADER pMEMs, *ppMEMs;
    if(pcbWrite) { *pcbWrite = 0; }
    // allocate
    cMEMs = (DWORD)(((qwA & 0xfff) + cb + 0xfff) >> 12);
    pbBuffer = (PBYTE)LocalAlloc(LMEM_ZEROINIT, cMEMs * (sizeof(MEM_IO_SCATTER_HEADER) + sizeof(PMEM_IO_SCATTER_HEADER)));
    if(!pbBuffer) { return; }
    pMEMs = (PMEM_IO_SCATTER_HEADER)pbBuffer;
    ppMEMs = (PPMEM_IO_SCATTER_HEADER)(pbBuffer + cMEMs * sizeof(MEM_IO_SCATTER_HEADER));
    // prepare pages
    while(oA < cb) {
        ppMEMs[i] = &pMEMs[i];
        pMEMs[i].version = MEM_IO_SCATTER_HEADER_VERSION;
        pMEMs[i].qwA = qwA + oA;
        cbP = 0x1000 - ((qwA + oA) & 0xfff);
        cbP = min(cbP, cb - oA);
        pMEMs[i].cbMax = cbP;
        pMEMs[i].pb = pb + oA;
        oA += cbP;
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
    PMEM_IO_SCATTER_HEADER pMEMs, *ppMEMs;
    QWORD i, oA;
    if(pcbReadOpt) { *pcbReadOpt = 0; }
    if(!cb) { return; }
    cMEMs = (DWORD)(((qwA & 0xfff) + cb + 0xfff) >> 12);
    pbBuffer = (PBYTE)LocalAlloc(LMEM_ZEROINIT, 0x2000 + cMEMs * (sizeof(MEM_IO_SCATTER_HEADER) + sizeof(PMEM_IO_SCATTER_HEADER)));
    if(!pbBuffer) {
        ZeroMemory(pb, cb);
        return;
    }
    pMEMs = (PMEM_IO_SCATTER_HEADER)(pbBuffer + 0x2000);
    ppMEMs = (PPMEM_IO_SCATTER_HEADER)(pbBuffer + 0x2000 + cMEMs * sizeof(MEM_IO_SCATTER_HEADER));
    oA = qwA & 0xfff;
    // prepare "middle" pages
    for(i = 0; i < cMEMs; i++) {
        ppMEMs[i] = &pMEMs[i];
        pMEMs[i].magic = MEM_IO_SCATTER_HEADER_MAGIC;
        pMEMs[i].version = MEM_IO_SCATTER_HEADER_VERSION;
        pMEMs[i].qwA = qwA - oA + (i << 12);
        pMEMs[i].cbMax = 0x1000;
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
        if(pMEMs[i].cb == 0x1000) {
            cbRead += 0x1000;
        } else {
            ZeroMemory(pMEMs[i].pb, 0x1000);
        }
    }
    cbRead -= (pMEMs[0].cb == 0x1000) ? 0x1000 : 0;                             // adjust byte count for first page (if needed)
    cbRead -= ((cMEMs > 1) && (pMEMs[cMEMs - 1].cb == 0x1000)) ? 0x1000 : 0;    // adjust byte count for last page (if needed)
    // Handle first page
    cbP = (DWORD)min(cb, 0x1000 - oA);
    if(pMEMs[0].cb == 0x1000) {
        memcpy(pb, pMEMs[0].pb + oA, cbP);
        cbRead += cbP;
    } else {
        ZeroMemory(pb, cbP);
    }
    // Handle last page
    if(cMEMs > 1) {
        cbP = (((qwA + cb) & 0xfff) ? ((qwA + cb) & 0xfff) : 0x1000);
        if(pMEMs[cMEMs - 1].cb == 0x1000) {
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
BOOL VmmRead_U2A_Size(_In_ PVMM_PROCESS pProcess, _In_ BOOL f32, _In_ QWORD flags, _In_ QWORD vaUS, _Out_ PQWORD pvaStr, _Out_ PWORD pcbStr)
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
BOOL VmmRead_U2A_RawStr(_In_ PVMM_PROCESS pProcess, _In_ QWORD flags, _In_ QWORD vaStr, _In_ WORD cbStr, _Out_writes_(cch) LPSTR sz, _In_ DWORD cch, _Out_opt_ PDWORD pcch, _Out_opt_ PBOOL pfDefaultChar)
{
    BOOL fResult = FALSE;
    DWORD cbRead, cchWrite;
    BYTE pbBuffer[0x1000], *pbStr;
    if(!cbStr) { return FALSE; }
    cbStr = (WORD)min(cbStr, (cch - 1) << 1);
    pbStr = (cbStr <= 0x1000) ? pbBuffer : LocalAlloc(0, cbStr);
    if(!pbStr) { goto fail; }
    VmmReadEx(pProcess, vaStr, pbStr, cbStr, &cbRead, flags);
    if(cbRead != cbStr) { goto fail; }
    cchWrite = WideCharToMultiByte(CP_ACP, 0, (LPWSTR)pbStr, cbStr >> 1, sz, cch - 1, NULL, pfDefaultChar);
    if(!cchWrite || !sz[0]) { goto fail; }
    sz[min(cchWrite, cch - 1)] = 0;
    if(pcch) { *pcch = cchWrite; }
    fResult = TRUE;
fail:
    if(pbStr != pbBuffer) { LocalFree(pbStr); }
    return fResult;
}

_Success_(return)
BOOL VmmRead_U2A(_In_ PVMM_PROCESS pProcess, _In_ BOOL f32, _In_ QWORD flags, _In_ QWORD vaUS, _Out_writes_opt_(cch) LPSTR sz, _In_ DWORD cch, _Out_opt_ PDWORD pcch, _Out_opt_ PBOOL pfDefaultChar)
{
    BOOL f;
    WORD cbStr;
    QWORD vaStr;
    f = VmmRead_U2A_Size(pProcess, f32, 0, vaUS, &vaStr, &cbStr);
    if(!f) { return FALSE; }
    if(!sz) {
        if(!pcch) { return FALSE; }
        if(pfDefaultChar) { *pfDefaultChar = FALSE; }
        *pcch = cbStr >> 1;
        return TRUE;
    }
    return VmmRead_U2A_RawStr(pProcess, flags, vaStr, cbStr, sz, cch, pcch, pfDefaultChar);
}

_Success_(return)
BOOL VmmRead_U2A_Alloc(_In_ PVMM_PROCESS pProcess, _In_ BOOL f32, _In_ QWORD flags, _In_ QWORD vaUS, _Out_ LPSTR *psz, _Out_ PDWORD pcch, _Out_opt_ PBOOL pfDefaultChar)
{
    BOOL f;
    WORD cbStr, cch;
    QWORD vaStr;
    LPSTR sz = NULL;
    f = VmmRead_U2A_Size(pProcess, f32, flags, vaUS, &vaStr, &cbStr) &&
        (cch = cbStr >> 1) &&
        (cch = cch + 1) &&
        (sz = LocalAlloc(0, cch)) &&
        VmmRead_U2A_RawStr(pProcess, flags, vaStr, cbStr, sz, cch, pcch, pfDefaultChar);
    if(!f) {
        LocalFree(sz);
        *psz = 0;
        *pcch = 0;
        return FALSE;
    }
    *psz = sz;
    return TRUE;
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
    ctxVmm->hModuleVmm = GetModuleHandleA("vmm");
    // 2: CACHE INIT: Process Table
    if(!VmmProcessTableCreateInitial()) { goto fail; }
    // 3: CACHE INIT: Translation Lookaside Buffer (TLB) Cache Table
    VmmCache2Initialize(VMM_CACHE_TAG_TLB);
    if(!ctxVmm->Cache.TLB.fActive) { goto fail; }
    // 4: CACHE INIT: Physical Memory Cache Table
    VmmCache2Initialize(VMM_CACHE_TAG_PHYS);
    if(!ctxVmm->Cache.PHYS.fActive) { goto fail; }
    // 5: CACHE INIT: Paged Memory Cache Table
    VmmCache2Initialize(VMM_CACHE_TAG_PAGING);
    if(!ctxVmm->Cache.PAGING.fActive) { goto fail; }
    if(!(ctxVmm->Cache.PAGING_FAILED = ObVSet_New())) { goto fail; }
    // 6: CACHE INIT: Prototype PTE Cache Map
    if(!(ctxVmm->Cache.pmPrototypePte = ObMap_New(OB_MAP_FLAGS_OBJECT_OB))) { goto fail; }
    // 7: OTHER INIT:
    ctxVmm->pObCCachePrefetchEPROCESS = ObContainer_New(NULL);
    ctxVmm->pObCCachePrefetchRegistry = ObContainer_New(NULL);
    InitializeCriticalSection(&ctxVmm->MasterLock);
    InitializeCriticalSection(&ctxVmm->TcpIp.LockUpdate);
    VmmInitializeFunctions();
    return TRUE;
fail:
    VmmClose();
    return FALSE;
}
