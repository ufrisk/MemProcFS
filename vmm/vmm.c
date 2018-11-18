// vmm.c : implementation of functions related to virtual memory management support.
//
// (c) Ulf Frisk, 2018
// Author: Ulf Frisk, pcileech@frizk.net
//

#include "vmm.h"
#include "vmmproc.h"
#include "pluginmanager.h"
#include "device.h"
#include "util.h"

// ----------------------------------------------------------------------------
// MASTER LOCK FUNCTIONALITY BELOW:
// ----------------------------------------------------------------------------

VOID VmmLockAcquire()
{
    EnterCriticalSection(&ctxVmm->MasterLock);
}

VOID VmmLockRelease()
{
    LeaveCriticalSection(&ctxVmm->MasterLock);
}

// ----------------------------------------------------------------------------
// INTERNAL VMMU FUNCTIONALITY: PAGE TABLES.
// ----------------------------------------------------------------------------

VOID VmmCacheClose(_In_ PVMM_CACHE_TABLE t)
{
    if(!t) { return; }
    LocalFree(t->S);
    LocalFree(t);
}

PVMM_CACHE_TABLE VmmCacheInitialize(_In_ QWORD cEntries)
{
    QWORD i;
    PVMM_CACHE_TABLE t;
    t = LocalAlloc(LMEM_ZEROINIT, sizeof(VMM_CACHE_TABLE));
    if(!t) { return NULL; }
    t->S = LocalAlloc(LMEM_ZEROINIT, cEntries * sizeof(VMM_CACHE_ENTRY));
    if(!t->S) {
        LocalFree(t);
        return NULL;
    }
    for(i = 0; i < cEntries; i++) {
        t->S[i].qwMAGIC = VMM_CACHE_ENTRY_MAGIC;
        t->S[i].h.cbMax = 0x1000;
        t->S[i].h.pb = t->S[i].pb;
        if(i > 0) {
            t->S[i].AgeBLink = &t->S[i - 1];
        }
        if(i < cEntries - 1) {
            t->S[i].AgeFLink = &t->S[i + 1];
        }
    }
    t->AgeFLink = &t->S[0];
    t->AgeBLink = &t->S[cEntries - 1];
    return t;
}

PMEM_IO_SCATTER_HEADER VmmCacheGet(_In_ PVMM_CACHE_TABLE t, _In_ QWORD qwA)
{
    PVMM_CACHE_ENTRY e;
    WORD h;
    h = (qwA >> 12) % VMM_CACHE_TABLESIZE;
    e = t->M[h];
    while(e) {
        if(e->h.qwA == qwA) {
            if(e->AgeBLink) {
                // disconnect from age list
                if(e->AgeFLink) {
                    e->AgeFLink->AgeBLink = e->AgeBLink;
                } else {
                    t->AgeBLink = e->AgeBLink;
                }
                e->AgeBLink->AgeFLink = e->AgeFLink;
                // put entry at front in age list
                e->AgeFLink = t->AgeFLink;
                e->AgeFLink->AgeBLink = e;
                e->AgeBLink = NULL;
                t->AgeFLink = e;
            }
            return &e->h;
        }
        e = e->FLink;
    }
    return NULL;
}

VOID VmmCachePut(_Inout_ PVMM_CACHE_TABLE t, _In_ PVMM_CACHE_ENTRY e)
{
    WORD h;
    if(e->qwMAGIC != VMM_CACHE_ENTRY_MAGIC) {
        vmmprintf("VMM: WARN: vmm.c!VmmCachePut: BAD ITEM PUT INTO CACHE - SHOULD NOT HAPPEN!\n");
    }
    if(e->h.cb == 0x1000) { // valid
                            // calculate bucket hash and insert
        h = (e->h.qwA >> 12) % VMM_CACHE_TABLESIZE;
        if(t->M[h]) {
            // previous entry exists - insert new at front of list
            t->M[h]->BLink = e;
            e->FLink = t->M[h];
        }
        t->M[h] = e;
        // put entry at front in age list
        e->AgeFLink = t->AgeFLink;
        e->AgeFLink->AgeBLink = e;
        e->AgeBLink = NULL;
        t->AgeFLink = e;
    } else {
        // invalid, put entry at last in age list
        e->AgeBLink = t->AgeBLink;
        e->AgeBLink->AgeFLink = e;
        e->AgeFLink = NULL;
        t->AgeBLink = e;
    }
}

PVMM_CACHE_ENTRY VmmCacheReserve(_Inout_ PVMM_CACHE_TABLE t)
{
    PVMM_CACHE_ENTRY e;
    WORD h;
    // retrieve and disconnect entry from age list
    e = t->AgeBLink;
    e->AgeBLink->AgeFLink = NULL;
    t->AgeBLink = e->AgeBLink;
    // disconnect entry from hash table. since most aged item is retrieved this
    // should always be last in any potential hash table bucket list.
    if(e->BLink) {
        e->BLink->FLink = NULL;
    }
    h = (e->h.qwA >> 12) % VMM_CACHE_TABLESIZE;
    if(t->M[h] == e) {
        t->M[h] = NULL;
    }
    // null list links and return item
    e->FLink = NULL;
    e->FLink = NULL;
    e->AgeFLink = NULL;
    e->AgeBLink = NULL;
    e->tm = 0;
    e->h.cb = 0;
    e->h.qwA = 0;
    return e;
}

/*
* Invalidate a cache entry (if exists)
*/
VOID VmmCacheInvalidate_2(_Inout_ PVMM_CACHE_TABLE t, _In_ QWORD pa)
{
    WORD h;
    PVMM_CACHE_ENTRY e;
    h = (pa >> 12) % VMM_CACHE_TABLESIZE;
    // invalidate all items in h bucket while letting them remain in age list
    e = t->M[h];
    t->M[h] = NULL;
    while(e) {
        if(e->BLink) {
            e->BLink->FLink = NULL;
            e->BLink = NULL;
        }
        e = e->FLink;
    }
}

VOID VmmCacheInvalidate(_In_ QWORD pa)
{
    VmmCacheInvalidate_2(ctxVmm->ptTLB, pa);
    VmmCacheInvalidate_2(ctxVmm->ptPHYS, pa);
}


VOID VmmCacheClear(_In_ BOOL fTLB, _In_ BOOL fPHYS)
{
    if(fTLB && ctxVmm->ptTLB) {
        VmmCacheClose(ctxVmm->ptTLB);
        ctxVmm->ptTLB = VmmCacheInitialize(VMM_CACHE_TLB_ENTRIES);
    }
    if(fPHYS && ctxVmm->ptPHYS) {
        VmmCacheClose(ctxVmm->ptPHYS);
        ctxVmm->ptPHYS = VmmCacheInitialize(VMM_CACHE_PHYS_ENTRIES);
    }
}

PMEM_IO_SCATTER_HEADER VmmCacheGet_FromDeviceOnMiss(_In_ PVMM_CACHE_TABLE t, _In_ QWORD qwA)
{
    PVMM_CACHE_ENTRY pe;
    PMEM_IO_SCATTER_HEADER pMEM;
    pMEM = VmmCacheGet(t, qwA);
    if(pMEM) { return pMEM; }
    pe = VmmCacheReserve(t);
    pMEM = &pe->h;
    pMEM->qwA = qwA;
    DeviceReadScatterMEM(&pMEM, 1, NULL);
    VmmCachePut(t, pe);
    return (pMEM->cb == 0x1000) ? pMEM : NULL;
}

/*
* Tries to verify that a loaded page table is correct. If just a bit strange
* bytes/ptes supplied in pb will be altered to look better.
*/
BOOL VmmTlbPageTableVerify(_Inout_ PBYTE pb, _In_ QWORD pa, _In_ BOOL fSelfRefReq)
{
    DWORD i;
    QWORD *ptes, c = 0, pte;
    BOOL fSelfRef = FALSE;
    if(!pb) { return FALSE; }
    ptes = (PQWORD)pb;
    for(i = 0; i < 512; i++) {
        pte = *(ptes + i);
        if((pte & 0x01) && ((0x000fffffffffffff & pte) > ctxMain->cfg.paAddrMax)) {
            // A bad PTE, or memory allocated above the physical address max
            // limit. This may be just trash in the page table in which case
            // we clear this faulty entry. If too may bad PTEs are found this
            // is most probably not a page table - zero it out but let it
            // remain in cache to prevent performance degrading reloads...
            if(ctxVmm) {
                vmmprintfvv("VMM: vmm.c!VmmTlbPageTableVerify: BAD PTE %016llx at PA: %016llx i: %i\n", *(ptes + i), pa, i);
            }
            *(ptes + i) = (QWORD)0;
            c++;
            if(c > 16) { break; }
        }
        if(pa == (0x0000fffffffff000 & pte)) {
            fSelfRef = TRUE;
        }
    }
    if((c > 16) || (fSelfRefReq && !fSelfRef)) {
        if(ctxVmm) {
            vmmprintfvv("VMM: vmm.c!VmmTlbPageTableVerify: BAD PT PAGE at PA: %016llx\n", pa);
        }
        ZeroMemory(pb, 4096);
        return FALSE;
    }
    return TRUE;
}

PBYTE VmmTlbGetPageTable(_In_ QWORD qwPA, _In_ BOOL fCacheOnly)
{
    BOOL result;
    PMEM_IO_SCATTER_HEADER pDMA;
    pDMA = VmmCacheGet(ctxVmm->ptTLB, qwPA);
    if(pDMA) {
        ctxVmm->stat.cTlbCacheHit++;
        return pDMA->pb;
    }
    if(fCacheOnly) { return NULL; }
    pDMA = VmmCacheGet_FromDeviceOnMiss(ctxVmm->ptTLB, qwPA);
    if(!pDMA) { 
        ctxVmm->stat.cTlbReadFail++;
        return NULL;
    }
    ctxVmm->stat.cTlbReadSuccess++;
    result = VmmTlbPageTableVerify(pDMA->pb, pDMA->qwA, FALSE);
    if(!result) { return NULL; }
    return pDMA->pb;
}

PVMM_PROCESS VmmProcessGetEx(_In_ PVMM_PROCESS_TABLE pt, _In_ DWORD dwPID)
{
    DWORD i, iStart;
    i = iStart = dwPID % VMM_PROCESSTABLE_ENTRIES_MAX;
    while(TRUE) {
        if(!pt->M[i]) { return NULL; }
        if(pt->M[i]->dwPID == dwPID) {
            return pt->M[i];
        }
        if(++i == VMM_PROCESSTABLE_ENTRIES_MAX) { i = 0; }
        if(i == iStart) { return NULL; }
    }
}

PVMM_PROCESS VmmProcessGet(_In_ DWORD dwPID)
{
    return VmmProcessGetEx(ctxVmm->ptPROC, dwPID);
}

PVMM_PROCESS VmmProcessCreateEntry(_In_ DWORD dwPID, _In_ DWORD dwState, _In_ QWORD paPML4, _In_ QWORD paPML4_UserOpt, _In_ CHAR szName[16], _In_ BOOL fUserOnly, _In_ BOOL fSpiderPageTableDone)
{
    QWORD i, iStart, cEmpty = 0, cValid = 0;
    PVMM_PROCESS pNewProcess;
    PBYTE pbPML4;
    // 1: Sanity check PML4
    pbPML4 = VmmTlbGetPageTable(paPML4, FALSE);
    if(!pbPML4) { return NULL; }
    if(!VmmTlbPageTableVerify(pbPML4, paPML4, (ctxVmm->fTargetSystem & VMM_TARGET_WINDOWS_X64))) { return NULL; }
    // 2: Allocate new PID table (if not already existing)
    if(ctxVmm->ptPROC->ptNew == NULL) {
        if(!(ctxVmm->ptPROC->ptNew = LocalAlloc(LMEM_ZEROINIT, sizeof(VMM_PROCESS_TABLE)))) { return NULL; }
    }
    // 3: Prepare existing item, or create new item, for new PID
    pNewProcess = VmmProcessGetEx(ctxVmm->ptPROC, dwPID);
    if(!pNewProcess) {
        if(!(pNewProcess = LocalAlloc(LMEM_ZEROINIT, sizeof(VMM_PROCESS)))) { return NULL; }
    }
    memcpy(pNewProcess->szName, szName, 16);
    pNewProcess->dwPID = dwPID;
    pNewProcess->dwState = dwState;
    pNewProcess->paPML4 = paPML4;
    pNewProcess->paPML4_UserOpt = paPML4_UserOpt;
    pNewProcess->fUserOnly = fUserOnly;
    pNewProcess->fSpiderPageTableDone = pNewProcess->fSpiderPageTableDone || fSpiderPageTableDone;
    pNewProcess->_i_fMigrated = TRUE;
    // 4: Install new PID
    i = iStart = dwPID % VMM_PROCESSTABLE_ENTRIES_MAX;
    while(TRUE) {
        if(!ctxVmm->ptPROC->ptNew->M[i]) {
            ctxVmm->ptPROC->ptNew->M[i] = pNewProcess;
            ctxVmm->ptPROC->ptNew->iFLinkM[i] = ctxVmm->ptPROC->ptNew->iFLink;
            ctxVmm->ptPROC->ptNew->iFLink = (WORD)i;
            ctxVmm->ptPROC->ptNew->c++;
            return pNewProcess;
        }
        if(++i == VMM_PROCESSTABLE_ENTRIES_MAX) { i = 0; }
        if(i == iStart) { return NULL; }
    }
}

VOID VmmProcessCloseTable(_In_ PVMM_PROCESS_TABLE pt, _In_ BOOL fForceFreeAll)
{
    PVMM_PROCESS pProcess;
    WORD i, iProcess;
    if(!pt) { return; }
    VmmProcessCloseTable(pt->ptNew, fForceFreeAll);
    iProcess = pt->iFLink;
    pProcess = pt->M[iProcess];
    while(pProcess) {
        if(fForceFreeAll || !pProcess->_i_fMigrated) {
            LocalFree(pProcess->pMemMap);
            LocalFree(pProcess->pModuleMap);
            LocalFree(pProcess->pbMemMapDisplayCache);
            for(i = 0; i < VMM_PROCESS_OS_ALLOC_PTR_MAX; i++) {
                LocalFree(pProcess->os.unk.pvReserved[i]);
            }
            LocalFree(pProcess);
        }
        iProcess = pt->iFLinkM[iProcess];
        pProcess = pt->M[iProcess];
        if(!pProcess || iProcess == pt->iFLink) { break; }
    }
    LocalFree(pt);
}

BOOL VmmProcessCreateTable()
{
    if(ctxVmm->ptPROC) {
        VmmProcessCloseTable(ctxVmm->ptPROC, TRUE);
    }
    ctxVmm->ptPROC = (PVMM_PROCESS_TABLE)LocalAlloc(LMEM_ZEROINIT, sizeof(VMM_PROCESS_TABLE));
    return (ctxVmm->ptPROC != NULL);
}

VOID VmmProcessCreateFinish()
{
    WORD iProcess;
    PVMM_PROCESS pProcess;
    PVMM_PROCESS_TABLE pt, ptOld;
    ptOld = ctxVmm->ptPROC;
    pt = ctxVmm->ptPROC = ptOld->ptNew;
    if(!pt) { return; }
    ptOld->ptNew = NULL;
    // close old table and free memory
    VmmProcessCloseTable(ptOld, FALSE);
    // set migrated to false for all entries in new table
    iProcess = pt->iFLink;
    pProcess = pt->M[iProcess];
    while(pProcess) {
        pProcess->_i_fMigrated = FALSE;
        iProcess = pt->iFLinkM[iProcess];
        pProcess = pt->M[iProcess];
        if(!pProcess || (iProcess == pt->iFLink)) { break; }
    }
}

VOID VmmProcessListPIDs(_Out_ PDWORD pPIDs, _Inout_ PSIZE_T pcPIDs)
{
    DWORD i = 0;
    WORD iProcess;
    PVMM_PROCESS pProcess;
    PVMM_PROCESS_TABLE pt = ctxVmm->ptPROC;
    if(!pPIDs) {
        *pcPIDs = pt->c;
        return;
    }
    if(*pcPIDs < pt->c) {
        *pcPIDs = 0;
        return;
    }
    // copy all PIDs
    iProcess = pt->iFLink;
    pProcess = pt->M[iProcess];
    while(pProcess) {
        *(pPIDs + i) = pProcess->dwPID;
        i++;
        iProcess = pt->iFLinkM[iProcess];
        pProcess = pt->M[iProcess];
        if(!pProcess || (iProcess == pt->iFLink)) { break; }
    }
    *pcPIDs = i;
}

#define VMM_TLB_SIZE_STAGEBUF   0x200

typedef struct tdVMM_TLB_SPIDER_STAGE_INTERNAL {
    QWORD c;
    PMEM_IO_SCATTER_HEADER ppDMAs[VMM_TLB_SIZE_STAGEBUF];
    PVMM_CACHE_ENTRY ppEntrys[VMM_TLB_SIZE_STAGEBUF];
} VMM_TLB_SPIDER_STAGE_INTERNAL, *PVMM_TLB_SPIDER_STAGE_INTERNAL;

VOID VmmTlbSpider_ReadToCache(PVMM_TLB_SPIDER_STAGE_INTERNAL pTlbSpiderStage)
{
    QWORD i;
    DeviceReadScatterMEM(pTlbSpiderStage->ppDMAs, (DWORD)pTlbSpiderStage->c, NULL);
    for(i = 0; i < pTlbSpiderStage->c; i++) {
        VmmTlbPageTableVerify(pTlbSpiderStage->ppEntrys[i]->h.pb, pTlbSpiderStage->ppEntrys[i]->h.qwA, FALSE);
        VmmCachePut(ctxVmm->ptTLB, pTlbSpiderStage->ppEntrys[i]);
    }
    pTlbSpiderStage->c = 0;
}

BOOL VmmTlbSpider_Stage(_In_ QWORD qwPA, _In_ QWORD qwPML, _In_ BOOL fUserOnly, PVMM_TLB_SPIDER_STAGE_INTERNAL pTlbSpiderStage)
{
    BOOL fSpiderComplete = TRUE;
    PMEM_IO_SCATTER_HEADER pt;
    QWORD i, pe;
    // 1: retrieve from cache, add to staging if not found
    pt = VmmCacheGet(ctxVmm->ptTLB, qwPA);
    if(!pt) {
        pTlbSpiderStage->ppEntrys[pTlbSpiderStage->c] = VmmCacheReserve(ctxVmm->ptTLB);
        pTlbSpiderStage->ppDMAs[pTlbSpiderStage->c] = &pTlbSpiderStage->ppEntrys[pTlbSpiderStage->c]->h;
        pTlbSpiderStage->ppDMAs[pTlbSpiderStage->c]->qwA = qwPA;
        pTlbSpiderStage->c++;
        if(pTlbSpiderStage->c == VMM_TLB_SIZE_STAGEBUF) {
            VmmTlbSpider_ReadToCache( pTlbSpiderStage);
        }
        return FALSE;
    }
    // 2: walk trough all entries for PML4, PDPT, PD
    if(qwPML == 1) { return TRUE; }
    for(i = 0; i < 0x1000; i += 8) {
        pe = *(PQWORD)(pt->pb + i);
        if(!(pe & 0x01)) { continue; }  // not valid
        if(pe & 0x80) { continue; }     // not valid ptr to (PDPT || PD || PT)
        if(fUserOnly && !(pe & 0x04)) { continue; } // supervisor page when fUserOnly -> not valid
        fSpiderComplete = VmmTlbSpider_Stage(pe & 0x0000fffffffff000, qwPML - 1, fUserOnly, pTlbSpiderStage) && fSpiderComplete;
    }
    return fSpiderComplete;
}

/*
* Iterate over PML4, PTPT, PD (3 times in total) to first stage uncached pages
* and then commit them to the cache.
*/
VOID VmmTlbSpider(_In_ QWORD qwPML4, _In_ BOOL fUserOnly)
{
    BOOL result;
    QWORD i = 0;
    PVMM_TLB_SPIDER_STAGE_INTERNAL pTlbSpiderStage;
    if(!(pTlbSpiderStage = (PVMM_TLB_SPIDER_STAGE_INTERNAL)LocalAlloc(LMEM_ZEROINIT, sizeof(VMM_TLB_SPIDER_STAGE_INTERNAL)))) { return; }
    while(TRUE) {
        i++;
        result = VmmTlbSpider_Stage(qwPML4, 4, fUserOnly, pTlbSpiderStage);
        if(pTlbSpiderStage->c) {
            VmmTlbSpider_ReadToCache(pTlbSpiderStage);
        }
        if(result || (i == 3)) {
            LocalFree(pTlbSpiderStage);
            return;
        }
    }
}

const QWORD VMM_PAGETABLEMAP_PML_REGION_SIZE[5] = { 0, 12, 21, 30, 39 };

VOID VmmMapInitialize_Index(_In_ PVMM_PROCESS pProcess, _In_ QWORD qwVABase, _In_ QWORD qwPML, _In_ QWORD PTEs[512], _In_ BOOL fSupervisorPML, _In_ QWORD paMax)
{
    PBYTE pbNextPageTable;
    QWORD i, pte, qwVA, qwNextVA, qwNextPA = 0;
    BOOL fUserOnly, fNextSupervisorPML;
    QWORD cMemMap = pProcess->cMemMap;
    PVMM_MEMMAP_ENTRY pMemMap = pProcess->pMemMap;
    PVMM_MEMMAP_ENTRY pMemMapEntry = pMemMap + cMemMap - 1;
    fUserOnly = pProcess->fUserOnly;
    for(i = 0; i < 512; i++) {
        pte = PTEs[i];
        if(!(pte & 0x01)) { continue; }
        qwNextPA = pte & 0x0000fffffffff000;
        if(qwNextPA > paMax) { continue; }
        if(fSupervisorPML) { pte = pte & 0xfffffffffffffffb; }
        if(fUserOnly && !(pte & 0x04)) { continue; }
        qwVA = qwVABase + (i << VMM_PAGETABLEMAP_PML_REGION_SIZE[qwPML]);
        // maps page
        if((qwPML == 1) || (pte & 0x80) /* PS */) {
            if(qwPML == 4) { continue; } // not supported - PML4 cannot map page directly
            if((cMemMap == 0) ||
                (pMemMapEntry->fPage != (pte & VMM_MEMMAP_FLAG_PAGE_MASK)) ||
                (qwVA != pMemMapEntry->AddrBase + (pMemMapEntry->cPages << 12)))
            {
                if(cMemMap + 1 >= VMM_MEMMAP_ENTRIES_MAX) { return; }
                pMemMapEntry = pProcess->pMemMap + cMemMap;
                pMemMapEntry->AddrBase = qwVA;
                pMemMapEntry->fPage = pte & VMM_MEMMAP_FLAG_PAGE_MASK;
                pMemMapEntry->cPages = 1ULL << (VMM_PAGETABLEMAP_PML_REGION_SIZE[qwPML] - 12);
                pProcess->cMemMap++;
                cMemMap++;
                continue;
            }
            pMemMapEntry->cPages += 1ULL << (VMM_PAGETABLEMAP_PML_REGION_SIZE[qwPML] - 12);
            continue;
        }
        // maps page table (PDPT, PD, PT)
        qwNextVA = qwVA;
        pbNextPageTable = VmmTlbGetPageTable(qwNextPA, FALSE);
        if(!pbNextPageTable) { continue; }
        fNextSupervisorPML = !(pte & 0x04);
        VmmMapInitialize_Index( pProcess, qwNextVA, qwPML - 1, (PQWORD)pbNextPageTable, fNextSupervisorPML, paMax);
        cMemMap = pProcess->cMemMap;
        pMemMapEntry = pProcess->pMemMap + cMemMap - 1;
    }
}

VOID VmmMapInitialize(_In_ PVMM_PROCESS pProcess)
{
    QWORD i, cMemMap;
    PBYTE pbPML4;
    pProcess->cbMemMapDisplayCache = 0;
    LocalFree(pProcess->pbMemMapDisplayCache);
    pProcess->pbMemMapDisplayCache = NULL;
    LocalFree(pProcess->pMemMap);
    pProcess->cMemMap = 0;
    pProcess->pMemMap = (PVMM_MEMMAP_ENTRY)LocalAlloc(LMEM_ZEROINIT, VMM_MEMMAP_ENTRIES_MAX * sizeof(VMM_MEMMAP_ENTRY));
    if(!pProcess->pMemMap) { return; }
    pbPML4 = VmmTlbGetPageTable(pProcess->paPML4, FALSE);
    if(!pbPML4) { return; }
    VmmMapInitialize_Index(pProcess, 0, 4, (PQWORD)pbPML4, FALSE, ctxMain->cfg.paAddrMax);
    cMemMap = pProcess->cMemMap;
    for(i = 0; i < cMemMap; i++) { // fixup sign extension for kernel addresses
        if(pProcess->pMemMap[i].AddrBase & 0x0000800000000000) {
            pProcess->pMemMap[i].AddrBase |= 0xffff000000000000;
        }
    }
}

/*
* Map a tag into the sorted memory map in O(log2) operations. Supply only one
* of szTag or wszTag.
* -- pProcess
* -- vaBase
* -- vaLimit = limit == vaBase + size (== top address in range +1)
* -- szTag
* -- wszTag
*/
VOID VmmMapTag(_In_ PVMM_PROCESS pProcess, _In_ QWORD vaBase, _In_ QWORD vaLimit, _In_opt_ LPSTR szTag, _In_opt_ LPWSTR wszTag, _In_opt_ BOOL fWoW64)
{
    PVMM_MEMMAP_ENTRY pMap;
    QWORD i, lvl, cMap;
    pMap = pProcess->pMemMap;
    cMap = pProcess->cMemMap;
    if(!pMap || !cMap) { return; }
    // 1: locate base
    lvl = 1;
    i = cMap >> lvl;
    while(TRUE) {
        lvl++;
        if((cMap >> lvl) == 0) {
            break;
        }
        if(pMap[i].AddrBase > vaBase) {
            i -= (cMap >> lvl);
        } else {
            i += (cMap >> lvl);
        }
    }
    // 2: scan back if needed
    while(i && (pMap[i].AddrBase > vaBase)) {
        i--;
    }
    // 3: fill in tag
    while((i < cMap) && (pMap[i].AddrBase + (pMap[i].cPages << 12) <= vaLimit)) {
        if(pMap[i].AddrBase >= vaBase) {
            pMap[i].fWoW64 = fWoW64;
            if(wszTag) {
                snprintf(pMap[i].szTag, 31, "%S", wszTag);
            }
            if(szTag) {
                snprintf(pMap[i].szTag, 31, "%s", szTag);
            }
        }
        i++;
    }
}

VOID VmmMapDisplayBufferGenerate(_In_ PVMM_PROCESS pProcess)
{
    DWORD i, o = 0;
    PBYTE pbBuffer;
    if(!pProcess->cMemMap || !pProcess->pMemMap) { return; }
    pProcess->cbMemMapDisplayCache = 0;
    LocalFree(pProcess->pbMemMapDisplayCache);
    pProcess->pbMemMapDisplayCache = NULL;
    pbBuffer = LocalAlloc(LMEM_ZEROINIT, 89 * pProcess->cMemMap);
    if(!pbBuffer) { return; }
    for(i = 0; i < pProcess->cMemMap; i++) {
        o += snprintf(
            pbBuffer + o,
            89,
            "%04x %8x %016llx-%016llx %sr%s%s%s%s\n",
            i,
            (DWORD)pProcess->pMemMap[i].cPages,
            pProcess->pMemMap[i].AddrBase,
            pProcess->pMemMap[i].AddrBase + (pProcess->pMemMap[i].cPages << 12) - 1,
            pProcess->pMemMap[i].fPage & VMM_MEMMAP_FLAG_PAGE_NS ? "-" : "s",
            pProcess->pMemMap[i].fPage & VMM_MEMMAP_FLAG_PAGE_W ? "w" : "-",
            pProcess->pMemMap[i].fPage & VMM_MEMMAP_FLAG_PAGE_NX ? "-" : "x",
            pProcess->pMemMap[i].szTag[0] ? (pProcess->pMemMap[i].fWoW64 ? " 32 " : "    ") : "",
            pProcess->pMemMap[i].szTag
        );
    }
    pProcess->pbMemMapDisplayCache = LocalAlloc(0, o);
    if(!pProcess->pbMemMapDisplayCache) { goto fail; }
    memcpy(pProcess->pbMemMapDisplayCache, pbBuffer, o);
    pProcess->cbMemMapDisplayCache = o;
fail:
    LocalFree(pbBuffer);
}

PVMM_MEMMAP_ENTRY VmmMapGetEntry(_In_ PVMM_PROCESS pProcess, _In_ QWORD qwVA)
{
    QWORD i, ce;
    PVMM_MEMMAP_ENTRY pe;
    if(!pProcess->pMemMap) { return NULL; }
    ce = pProcess->cMemMap;
    for(i = 0; i < ce; i++) {
        pe = pProcess->pMemMap + i;
        if((pe->AddrBase >= qwVA) && (qwVA <= pe->AddrBase + (pe->cPages << 12))) {
            return pe;
        }
    }
    return NULL;
}

_Success_(return)
BOOL VmmVirt2PhysEx(_In_ BOOL fUserOnly, _In_ QWORD va, _In_ QWORD iPML, _In_ QWORD PTEs[512], _Out_ PQWORD ppa)
{
    QWORD pte, i, qwMask;
    PBYTE pbNextPageTable;
    i = 0x1ff & (va >> VMM_PAGETABLEMAP_PML_REGION_SIZE[iPML]);
    pte = PTEs[i];
    if(!(pte & 0x01)) { return FALSE; }                 // NOT VALID
    if(fUserOnly && !(pte & 0x04)) { return FALSE; }    // SUPERVISOR PAGE & USER MODE REQ
    if(pte & 0x000f000000000000) { return FALSE; }      // RESERVED
    if((iPML == 1) || (pte & 0x80) /* PS */) {
        if(iPML == 4) { return FALSE; }                // NO SUPPORT IN PML4
        qwMask = 0xffffffffffffffff << VMM_PAGETABLEMAP_PML_REGION_SIZE[iPML];
        *ppa = pte & 0x0000fffffffff000 & qwMask;   // MASK AWAY BITS FOR 4kB/2MB/1GB PAGES
        qwMask = qwMask ^ 0xffffffffffffffff;
        *ppa = *ppa | (qwMask & va);            // FILL LOWER ADDRESS BITS
        return TRUE;
    }
    pbNextPageTable = VmmTlbGetPageTable(pte & 0x0000fffffffff000, FALSE);
    if(!pbNextPageTable) { return FALSE; }
    return VmmVirt2PhysEx(fUserOnly, va, iPML - 1, (PQWORD)pbNextPageTable, ppa);
}

_Success_(return)
BOOL VmmVirt2Phys(_In_ PVMM_PROCESS pProcess, _In_ QWORD qwVA, _Out_ PQWORD pqwPA)
{
    PBYTE pbPML4 = VmmTlbGetPageTable(pProcess->paPML4, FALSE);
    if(!pbPML4) { return FALSE; }
    *pqwPA = 0;
    return VmmVirt2PhysEx(pProcess->fUserOnly, qwVA, 4, (PQWORD)pbPML4, pqwPA);
}

VOID VmmVirt2PhysGetInformation_DoWork(_Inout_ PVMM_PROCESS pProcess, _Inout_ PVMM_VIRT2PHYS_INFORMATION pVirt2PhysInfo, _In_ QWORD qwPML, _In_ QWORD PTEs[512])
{
    QWORD pte, i, qwMask;
    PBYTE pbNextPageTable;
    i = 0x1ff & (pVirt2PhysInfo->va >> VMM_PAGETABLEMAP_PML_REGION_SIZE[qwPML]);
    pte = PTEs[i];
    pVirt2PhysInfo->iPTEs[qwPML] = (WORD)i;
    pVirt2PhysInfo->PTEs[qwPML] = pte;
    if(!(pte & 0x01)) { return; }                           // NOT VALID
    if(pProcess->fUserOnly && !(pte & 0x04)) { return; }    // SUPERVISOR PAGE & USER MODE REQ
    if(pte & 0x000f000000000000) { return; }                // RESERVED
    if((qwPML == 1) || (pte & 0x80) /* PS */) {
        if(qwPML == 4) { return; }                          // NO SUPPORT IN PML4
        qwMask = 0xffffffffffffffff << VMM_PAGETABLEMAP_PML_REGION_SIZE[qwPML];
        pVirt2PhysInfo->pas[0] = pte & 0x0000fffffffff000 & qwMask;     // MASK AWAY BITS FOR 4kB/2MB/1GB PAGES
        qwMask = qwMask ^ 0xffffffffffffffff;
        pVirt2PhysInfo->pas[0] = pVirt2PhysInfo->pas[0] | (qwMask & pVirt2PhysInfo->va);    // FILL LOWER ADDRESS BITS
        return;
    }
    if(!(pbNextPageTable = VmmTlbGetPageTable(pte & 0x0000fffffffff000, FALSE))) { return; }
    pVirt2PhysInfo->pas[qwPML - 1] = pte & 0x0000fffffffff000;
    VmmVirt2PhysGetInformation_DoWork(pProcess, pVirt2PhysInfo, qwPML - 1, (PQWORD)pbNextPageTable);
}

VOID VmmVirt2PhysGetInformation(_Inout_ PVMM_PROCESS pProcess, _Inout_ PVMM_VIRT2PHYS_INFORMATION pVirt2PhysInfo)
{
    QWORD va;
    PBYTE pbPML4;
    va = pVirt2PhysInfo->va;
    ZeroMemory(pVirt2PhysInfo, sizeof(VMM_VIRT2PHYS_INFORMATION));
    pVirt2PhysInfo->va = va;
    pVirt2PhysInfo->pas[4] = pProcess->paPML4;
    if(!(pbPML4 = VmmTlbGetPageTable(pProcess->paPML4, FALSE))) { return; }
    VmmVirt2PhysGetInformation_DoWork(pProcess, pVirt2PhysInfo, 4, (PQWORD)pbPML4);
}

// ----------------------------------------------------------------------------
// INTERNAL VMMU FUNCTIONALITY: VIRTUAL MEMORY ACCESS.
// ----------------------------------------------------------------------------

VOID VmmWriteScatterVirtual(_In_ PVMM_PROCESS pProcess, _Inout_ PPMEM_IO_SCATTER_HEADER ppDMAsVirt, _In_ DWORD cpDMAsVirt)
{
    BOOL result;
    QWORD i, qwPA;
    PMEM_IO_SCATTER_HEADER pMEM_Virt;
    // loop over the items, this may not be very efficient compared to a true
    // scatter write, but since underlying hardware implementation does not
    // support it yet this will be fine ...
    if(ctxVmm->fReadOnly) { return; }
    for(i = 0; i < cpDMAsVirt; i++) {
        pMEM_Virt = ppDMAsVirt[i];
        pMEM_Virt->cb = 0;
        result = VmmVirt2Phys(pProcess, pMEM_Virt->qwA, &qwPA);
        if(!result) { continue; }
        ctxVmm->stat.cPhysWrite++;
        result = DeviceWriteMEM(qwPA, pMEM_Virt->pb, pMEM_Virt->cbMax);
        if(result) {
            pMEM_Virt->cb = pMEM_Virt->cbMax;
            VmmCacheInvalidate(qwPA & ~0xfff);
        }
    }
}

VOID VmmWriteScatterPhysical(_Inout_ PPMEM_IO_SCATTER_HEADER ppDMAsPhys, _In_ DWORD cpDMAsPhys)
{
    BOOL result;
    QWORD i;
    PMEM_IO_SCATTER_HEADER pMEM_Phys;
    // loop over the items, this may not be very efficient compared to a true
    // scatter write, but since underlying hardware implementation does not
    // support it yet this will be fine ...
    if(ctxVmm->fReadOnly) { return; }
    for(i = 0; i < cpDMAsPhys; i++) {
        pMEM_Phys = ppDMAsPhys[i];
        ctxVmm->stat.cPhysWrite++;
        result = DeviceWriteMEM(pMEM_Phys->qwA, pMEM_Phys->pb, pMEM_Phys->cbMax);
        if(result) {
            pMEM_Phys->cb = pMEM_Phys->cbMax;
            VmmCacheInvalidate(pMEM_Phys->qwA & ~0xfff);
        }
    }
}

BOOL VmmWritePhysical(_In_ QWORD pa, _Out_ PBYTE pb, _In_ DWORD cb)
{
    QWORD paPage;
    // 1: invalidate any physical pages from cache
    paPage = pa & ~0xfff;
    do {
        ctxVmm->stat.cPhysWrite++;
        VmmCacheInvalidate(paPage);
        paPage += 0x1000;
    } while(paPage < pa + cb);
    // 2: perform write
    return DeviceWriteMEM(pa, pb, cb);
}

BOOL VmmReadPhysicalPage(_In_ QWORD qwPA, _Inout_bytecount_(4096) PBYTE pbPage)
{
    PMEM_IO_SCATTER_HEADER pMEM_Phys;
    PVMM_CACHE_ENTRY pMEMPhysCacheEntry;
    DWORD cReadMEMs = 0;
    qwPA &= ~0xfff;
    pMEM_Phys = VmmCacheGet(ctxVmm->ptPHYS, qwPA);
    if(pMEM_Phys) {
        memcpy(pbPage, pMEM_Phys->pb, 0x1000);
        return TRUE;
    }
    pMEMPhysCacheEntry = VmmCacheReserve(ctxVmm->ptPHYS);
    pMEM_Phys = &pMEMPhysCacheEntry->h;
    pMEM_Phys->cb = 0;
    pMEM_Phys->qwA = qwPA;
    DeviceReadScatterMEM(&pMEM_Phys, 1, &cReadMEMs);
    VmmCachePut(ctxVmm->ptPHYS, pMEMPhysCacheEntry);
    if(cReadMEMs) {
        memcpy(pbPage, pMEM_Phys->pb, 0x1000);
        return TRUE;
    }
    ZeroMemory(pbPage, 0x1000);
    return FALSE;
}

VOID VmmReadScatterPhysical( _Inout_ PPMEM_IO_SCATTER_HEADER ppMEMsPhys, _In_ DWORD cpMEMsPhys, _In_ QWORD flags)
{
    DWORD i, j, cPagesPerScatterRead, cMEMsPhysCache;
    PVMM_CACHE_ENTRY ppMEMsPhysCacheEntry[0x48];
    PMEM_IO_SCATTER_HEADER ppMEMsPhysCacheIo[0x48];
    PMEM_IO_SCATTER_HEADER pMEM_Src, pMEM_Dst;
    // 2.1: retrieve data loop - read strategy: non-cached read
    if(VMM_FLAG_NOCACHE & (flags | ctxVmm->flags)) {
        DeviceReadScatterMEM(ppMEMsPhys, cpMEMsPhys, NULL);
        return;
    }
    // 2.2: retrieve data loop - read strategy: cached read (standard/preferred)
    cPagesPerScatterRead = min(0x48, ((ctxMain->dev.qwMaxSizeMemIo & ~0xfff) >> 12));
    cMEMsPhysCache = 0;
    for(i = 0; i < cpMEMsPhys; i++) {
        // retrieve from cache (if found)
        pMEM_Src = VmmCacheGet(ctxVmm->ptPHYS, ppMEMsPhys[i]->qwA);
        if(pMEM_Src) {
            // in cache - copy data into requester and set as completed!
            ppMEMsPhys[i]->cb = 0x1000;
            memcpy(ppMEMsPhys[i]->pb, pMEM_Src->pb, 0x1000);
            ctxVmm->stat.cPhysCacheHit++;
        } else {
            // not in cache - add to requesting queue
            ppMEMsPhysCacheEntry[cMEMsPhysCache] = VmmCacheReserve(ctxVmm->ptPHYS);
            ppMEMsPhysCacheIo[cMEMsPhysCache] = &ppMEMsPhysCacheEntry[cMEMsPhysCache]->h;
            ppMEMsPhysCacheIo[cMEMsPhysCache]->cb = 0;
            ppMEMsPhysCacheIo[cMEMsPhysCache]->qwA = ppMEMsPhys[i]->qwA;
            ppMEMsPhysCacheIo[cMEMsPhysCache]->pvReserved1 = (PVOID)ppMEMsPhys[i];
            cMEMsPhysCache++;
        }
        // physical read if requesting queue is full or if this is last
        if(cMEMsPhysCache && ((cMEMsPhysCache == cPagesPerScatterRead) || (i == cpMEMsPhys - 1))) {
            // SPECULATIVE FUTURE READ IF NEGLIGIBLE PERFORMANCE LOSS
            while(cMEMsPhysCache < min(0x18, cPagesPerScatterRead)) {
                ppMEMsPhysCacheEntry[cMEMsPhysCache] = VmmCacheReserve(ctxVmm->ptPHYS);
                ppMEMsPhysCacheIo[cMEMsPhysCache] = &ppMEMsPhysCacheEntry[cMEMsPhysCache]->h;
                ppMEMsPhysCacheIo[cMEMsPhysCache]->cb = 0;
                ppMEMsPhysCacheIo[cMEMsPhysCache]->qwA = (QWORD)ppMEMsPhysCacheIo[cMEMsPhysCache - 1]->qwA + 0x1000;
                ppMEMsPhysCacheIo[cMEMsPhysCache]->pvReserved1 = NULL;
                cMEMsPhysCache++;
            }
            // physical memory access
            DeviceReadScatterMEM(ppMEMsPhysCacheIo, cMEMsPhysCache, NULL);
            for(j = 0; j < cMEMsPhysCache; j++) {
                VmmCachePut(ctxVmm->ptPHYS, ppMEMsPhysCacheEntry[j]);
                pMEM_Src = &ppMEMsPhysCacheEntry[j]->h;
                pMEM_Dst = (PMEM_IO_SCATTER_HEADER)pMEM_Src->pvReserved1;
                if(pMEM_Dst) {
                    if(pMEM_Src->cb) {
                        pMEM_Dst->cb = pMEM_Src->cb;
                        memcpy(pMEM_Dst->pb, pMEM_Src->pb, 0x1000);
                    } else if((flags & VMM_FLAG_ZEROPAD_ON_FAIL) && (pMEM_Src->qwA < ctxMain->cfg.paAddrMax)) {
                        pMEM_Dst->cb = 0x1000;
                        ZeroMemory(pMEM_Dst->pb, 0x1000);
                    } else {
                        pMEM_Dst->cb = 0;
                    }
                }
                if(pMEM_Src->cb == 0x1000) {
                    ctxVmm->stat.cPhysReadSuccess++;
                } else {
                    ctxVmm->stat.cPhysReadFail++;
                }
            }
            cMEMsPhysCache = 0;
        }
    }
}

VOID VmmReadScatterVirtual(_In_ PVMM_PROCESS pProcess, _Inout_ PPMEM_IO_SCATTER_HEADER ppMEMsVirt, _In_ DWORD cpMEMsVirt, _In_ QWORD flags)
{
    DWORD i = 0, iVA, iPA;
    QWORD qwPA;
    MEM_IO_SCATTER_HEADER oMEMsPhys[0x48];
    PMEM_IO_SCATTER_HEADER pIoPA, pIoVA, ppMEMsPhys[0x48];
    // if chunk is larger than threshold (0x48) - split it into workitems
    if(cpMEMsVirt > 0x48) {
        while(i < cpMEMsVirt) {
            VmmReadScatterVirtual(pProcess, ppMEMsVirt + i, min(0x48, cpMEMsVirt - i), flags);
            i += 0x48;
        }
        return;
    }
    // 1: translate virt2phys
    for(iVA = 0, iPA = 0; iVA < cpMEMsVirt; iVA++) {
        pIoVA = ppMEMsVirt[iVA];
        if(VmmVirt2Phys(pProcess, pIoVA->qwA, &qwPA)) {
            pIoPA = ppMEMsPhys[iPA] = &oMEMsPhys[iPA];
            iPA++;
            pIoPA->qwA = qwPA;
            pIoPA->cbMax = 0x1000;
            pIoPA->cb = 0;
            pIoPA->pb = pIoVA->pb;
            pIoPA->pvReserved1 = (PVOID)pIoVA;
        } else {
            pIoVA->cb = 0;
        }
    }
    VmmReadScatterPhysical(ppMEMsPhys, iPA, flags);
    while(iPA > 0) {
        iPA--;
        ((PMEM_IO_SCATTER_HEADER)ppMEMsPhys[iPA]->pvReserved1)->cb = ppMEMsPhys[iPA]->cb;
    }
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
    VmmProcessCloseTable(ctxVmm->ptPROC, TRUE);
    VmmCacheClose(ctxVmm->ptTLB);
    VmmCacheClose(ctxVmm->ptPHYS);
    DeleteCriticalSection(&ctxVmm->MasterLock);
    LocalFree(ctxVmm);
    ctxVmm = NULL;
}

VOID VmmWriteEx(_In_opt_ PVMM_PROCESS pProcess, _In_ QWORD qwVA, _Out_ PBYTE pb, _In_ DWORD cb, _Out_opt_ PDWORD pcbWrite)
{
    DWORD i = 0, oVA = 0, cbWrite = 0, cbP, cDMAs;
    PBYTE pbBuffer;
    PMEM_IO_SCATTER_HEADER pDMAs, *ppDMAs;
    if(pcbWrite) { *pcbWrite = 0; }
    // allocate
    cDMAs = (DWORD)(((qwVA & 0xfff) + cb + 0xfff) >> 12);
    pbBuffer = (PBYTE)LocalAlloc(LMEM_ZEROINIT, cDMAs * (sizeof(MEM_IO_SCATTER_HEADER) + sizeof(PMEM_IO_SCATTER_HEADER)));
    if(!pbBuffer) { return; }
    pDMAs = (PMEM_IO_SCATTER_HEADER)pbBuffer;
    ppDMAs = (PPMEM_IO_SCATTER_HEADER)(pbBuffer + cDMAs * sizeof(MEM_IO_SCATTER_HEADER));
    // prepare pages
    while(oVA < cb) {
        ppDMAs[i] = &pDMAs[i];
        pDMAs[i].qwA = qwVA + oVA;
        cbP = 0x1000 - ((qwVA + oVA) & 0xfff);
        cbP = min(cbP, cb - oVA);
        pDMAs[i].cbMax = cbP;
        pDMAs[i].pb = pb + oVA;
        oVA += cbP;
        i++;
    }
    // write and count result
    if(pProcess) {
        VmmWriteScatterVirtual(pProcess, ppDMAs, cDMAs);
    } else {
        VmmWriteScatterPhysical(ppDMAs, cDMAs);
    }
    if(pcbWrite) {
        for(i = 0; i < cDMAs; i++) {
            cbWrite += pDMAs[i].cb;
        }
        *pcbWrite = cbWrite;
    }
    LocalFree(pbBuffer);
}

BOOL VmmWrite(_In_opt_ PVMM_PROCESS pProcess, _In_ QWORD qwVA, _Out_ PBYTE pb, _In_ DWORD cb)
{
    DWORD cbWrite;
    VmmWriteEx(pProcess, qwVA, pb, cb, &cbWrite);
    return (cbWrite == cb);
}

VOID VmmReadEx(_In_opt_ PVMM_PROCESS pProcess, _In_ QWORD qwVA, _Inout_ PBYTE pb, _In_ DWORD cb, _Out_opt_ PDWORD pcbReadOpt, _In_ QWORD flags)
{
    DWORD cbP, cDMAs, cbRead = 0;
    PBYTE pbBuffer;
    PMEM_IO_SCATTER_HEADER pDMAs, *ppDMAs;
    QWORD i, oVA;
    if(pcbReadOpt) { *pcbReadOpt = 0; }
    if(!cb) { return; }
    cDMAs = (DWORD)(((qwVA & 0xfff) + cb + 0xfff) >> 12);
    pbBuffer = (PBYTE)LocalAlloc(LMEM_ZEROINIT, 0x2000 + cDMAs * (sizeof(MEM_IO_SCATTER_HEADER) + sizeof(PMEM_IO_SCATTER_HEADER)));
    if(!pbBuffer) { return; }
    pDMAs = (PMEM_IO_SCATTER_HEADER)(pbBuffer + 0x2000);
    ppDMAs = (PPMEM_IO_SCATTER_HEADER)(pbBuffer + 0x2000 + cDMAs * sizeof(MEM_IO_SCATTER_HEADER));
    oVA = qwVA & 0xfff;
    // prepare "middle" pages
    for(i = 0; i < cDMAs; i++) {
        ppDMAs[i] = &pDMAs[i];
        pDMAs[i].qwA = qwVA - oVA + (i << 12);
        pDMAs[i].cbMax = 0x1000;
        pDMAs[i].pb = pb - oVA + (i << 12);
    }
    // fixup "first/last" pages
    pDMAs[0].pb = pbBuffer;
    if(cDMAs > 1) {
        pDMAs[cDMAs - 1].pb = pbBuffer + 0x1000;
    }
    // Read VMM and handle result
    if(pProcess) {
        VmmReadScatterVirtual(pProcess, ppDMAs, cDMAs, flags);
    } else {
        VmmReadScatterPhysical(ppDMAs, cDMAs, flags);
    }
    for(i = 0; i < cDMAs; i++) {
        if(pDMAs[i].cb == 0x1000) {
            cbRead += 0x1000;
        } else {
            ZeroMemory(pDMAs[i].pb, 0x1000);
        }
    }
    cbRead -= (pDMAs[0].cb == 0x1000) ? 0x1000 : 0;                             // adjust byte count for first page (if needed)
    cbRead -= ((cDMAs > 1) && (pDMAs[cDMAs - 1].cb == 0x1000)) ? 0x1000 : 0;    // adjust byte count for last page (if needed)
    // Handle first page
    cbP = (DWORD)min(cb, 0x1000 - oVA);
    if(pDMAs[0].cb == 0x1000) {
        memcpy(pb, pDMAs[0].pb + oVA, cbP);
        cbRead += cbP;
    } else {
        ZeroMemory(pb, cbP);
    }
    // Handle last page
    if(cDMAs > 1) {
        cbP = (((qwVA + cb) & 0xfff) ? ((qwVA + cb) & 0xfff) : 0x1000);
        if(pDMAs[cDMAs - 1].cb == 0x1000) {
            memcpy(pb + ((QWORD)cDMAs << 12) - oVA - 0x1000, pDMAs[cDMAs - 1].pb, cbP);
            cbRead += cbP;
        } else {
            ZeroMemory(pb + ((QWORD)cDMAs << 12) - oVA - 0x1000, cbP);
        }
    }
    if(pcbReadOpt) { *pcbReadOpt = cbRead; }
    LocalFree(pbBuffer);
}

BOOL VmmReadString_Unicode2Ansi(_In_ PVMM_PROCESS pProcess, _In_ QWORD qwVA, _Out_ LPSTR sz, _In_ DWORD cch)
{
    DWORD i = 0;
    BOOL result;
    WCHAR wsz[0x1000];
    if(cch > 0x1000) { return FALSE; }
    result = VmmRead(pProcess, qwVA, (PBYTE)wsz, cch << 1);
    if(!result) { return FALSE; }
    for(i = 0; i < cch; i++) {
        sz[i] = ((WORD)wsz[i] <= 0xff) ? (CHAR)wsz[i] : '?';
        if(sz[i] == 0) { return TRUE; }
    }
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

BOOL VmmInitialize()
{
    // 1: allocate & initialize
    if(ctxVmm) { VmmClose(); }
    ctxVmm = (PVMM_CONTEXT)LocalAlloc(LMEM_ZEROINIT, sizeof(VMM_CONTEXT));
    if(!ctxVmm) { goto fail; }
    // 2: CACHE INIT: Process Table
    VmmProcessCreateTable();
    if(!ctxVmm->ptPROC) { goto fail; }
    // 3: CACHE INIT: Translation Lookaside Buffer (TLB) Cache Table
    ctxVmm->ptTLB = VmmCacheInitialize(VMM_CACHE_TLB_ENTRIES);
    if(!ctxVmm->ptTLB) { goto fail; }
    // 3: CACHE INIT: Physical Memory Cache Table
    ctxVmm->ptPHYS = VmmCacheInitialize(VMM_CACHE_PHYS_ENTRIES);
    if(!ctxVmm->ptPHYS) { goto fail; }
    // 4: OTHER INIT:
    ctxVmm->fReadOnly = (ctxMain->dev.tp == VMM_DEVICE_FILE);
    InitializeCriticalSection(&ctxVmm->MasterLock);
    return TRUE;
fail:
    VmmClose();
    return FALSE;
}
