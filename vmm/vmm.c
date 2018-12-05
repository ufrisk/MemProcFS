// vmm.c : implementation of functions related to virtual memory management support.
//
// (c) Ulf Frisk, 2018
// Author: Ulf Frisk, pcileech@frizk.net
//

#include "vmm.h"
#include "mm_x86.h"
#include "mm_x86pae.h"
#include "mm_x64.h"
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

PBYTE VmmTlbGetPageTable(_In_ QWORD pa, _In_ BOOL fCacheOnly)
{
    BOOL result;
    PMEM_IO_SCATTER_HEADER pDMA;
    pDMA = VmmCacheGet(ctxVmm->ptTLB, pa);
    if(pDMA) {
        ctxVmm->stat.cTlbCacheHit++;
        return pDMA->pb;
    }
    if(fCacheOnly) { return NULL; }
    pDMA = VmmCacheGet_FromDeviceOnMiss(ctxVmm->ptTLB, pa);
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

PVMM_PROCESS VmmProcessCreateEntry(_In_ DWORD dwPID, _In_ DWORD dwState, _In_ QWORD paDTB, _In_ QWORD paDTB_UserOpt, _In_ CHAR szName[16], _In_ BOOL fUserOnly, _In_ BOOL fSpiderPageTableDone)
{
    QWORD i, iStart, cEmpty = 0, cValid = 0;
    PVMM_PROCESS pNewProcess;
    PBYTE pbDTB;
    // 1: Sanity check PML4
    pbDTB = VmmTlbGetPageTable(paDTB, FALSE);
    if(!pbDTB) { return NULL; }
    if(!VmmTlbPageTableVerify(pbDTB, paDTB, (ctxVmm->tpSystem == VMM_SYSTEM_WINDOWS_X64))) { return NULL; }
    // 2: Allocate new PID table (if not already existing)
    if(ctxVmm->ptPROC->ptNew == NULL) {
        if(!(ctxVmm->ptPROC->ptNew = LocalAlloc(LMEM_ZEROINIT, sizeof(VMM_PROCESS_TABLE)))) { return NULL; }
    }
    // 3: Sanity check - process to create not already in 'new' table.
    if(VmmProcessGetEx(ctxVmm->ptPROC->ptNew, dwPID)) {
        return NULL;
    }
    // 4: Prepare existing item, or create new item, for new PID
    pNewProcess = VmmProcessGetEx(ctxVmm->ptPROC, dwPID);
    if(!pNewProcess) {
        if(!(pNewProcess = LocalAlloc(LMEM_ZEROINIT, sizeof(VMM_PROCESS)))) { return NULL; }
    }
    memcpy(pNewProcess->szName, szName, 16);
    pNewProcess->dwPID = dwPID;
    pNewProcess->dwState = dwState;
    pNewProcess->paDTB = paDTB;
    pNewProcess->paDTB_UserOpt = paDTB_UserOpt;
    pNewProcess->fUserOnly = fUserOnly;
    pNewProcess->fSpiderPageTableDone = pNewProcess->fSpiderPageTableDone || fSpiderPageTableDone;
    pNewProcess->_i_fMigrated = TRUE;
    // 5: Install new PID
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

VOID VmmProcessListPIDs(_Out_opt_ PDWORD pPIDs, _Inout_ PSIZE_T pcPIDs)
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

BOOL VmmWritePhysical(_In_ QWORD pa, _In_ PBYTE pb, _In_ DWORD cb)
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
    if(ctxVmm->fnMemoryModel.pfnClose) {
        ctxVmm->fnMemoryModel.pfnClose();
    }
    VmmCacheClose(ctxVmm->ptTLB);
    VmmCacheClose(ctxVmm->ptPHYS);
    DeleteCriticalSection(&ctxVmm->MasterLock);
    LocalFree(ctxVmm);
    ctxVmm = NULL;
}

VOID VmmWriteEx(_In_opt_ PVMM_PROCESS pProcess, _In_ QWORD qwVA, _In_ PBYTE pb, _In_ DWORD cb, _Out_opt_ PDWORD pcbWrite)
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
        pDMAs[i].version = MEM_IO_SCATTER_HEADER_VERSION;
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

BOOL VmmWrite(_In_opt_ PVMM_PROCESS pProcess, _In_ QWORD qwVA, _In_ PBYTE pb, _In_ DWORD cb)
{
    DWORD cbWrite;
    VmmWriteEx(pProcess, qwVA, pb, cb, &cbWrite);
    return (cbWrite == cb);
}

VOID VmmReadEx(_In_opt_ PVMM_PROCESS pProcess, _In_ QWORD qwVA, _Out_ PBYTE pb, _In_ DWORD cb, _Out_opt_ PDWORD pcbReadOpt, _In_ QWORD flags)
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
        pDMAs[i].version = MEM_IO_SCATTER_HEADER_VERSION;
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

_Success_(return)
BOOL VmmReadString_Unicode2Ansi(_In_ PVMM_PROCESS pProcess, _In_ QWORD qwVA, _Out_writes_(cch) LPSTR sz, _In_ DWORD cch)
{
    DWORD i = 0;
    BOOL result;
    WCHAR wsz[0x1000];
    if(cch) { sz[0] = 0; }
    if(!cch || cch > 0x1000) { return FALSE; }
    result = VmmRead(pProcess, qwVA, (PBYTE)wsz, cch << 1);
    if(!result) { return FALSE; }
    for(i = 0; i < cch - 1; i++) {
        sz[i] = (CHAR)(((WORD)wsz[i] <= 0xff) ? wsz[i] : '?');
        if(sz[i] == 0) { return TRUE; }
    }
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
    // 4: CACHE INIT: Physical Memory Cache Table
    ctxVmm->ptPHYS = VmmCacheInitialize(VMM_CACHE_PHYS_ENTRIES);
    if(!ctxVmm->ptPHYS) { goto fail; }
    // 5: OTHER INIT:
    ctxVmm->fReadOnly = (ctxMain->dev.tp == VMM_DEVICE_FILE);
    InitializeCriticalSection(&ctxVmm->MasterLock);
    return TRUE;
fail:
    VmmClose();
    return FALSE;
}
