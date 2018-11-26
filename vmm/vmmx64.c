// vmmx64.c : implementation of the x64 / IA32e / long-mode paging / memory model.
//
// (c) Ulf Frisk, 2018
// Author: Ulf Frisk, pcileech@frizk.net
//
#include "device.h"
#include "vmm.h"

/*
* Tries to verify that a loaded page table is correct. If just a bit strange
* bytes/ptes supplied in pb will be altered to look better.
*/
BOOL VmmX64_TlbPageTableVerify(_Inout_ PBYTE pb, _In_ QWORD pa, _In_ BOOL fSelfRefReq)
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

#define VMMX64_TLB_SIZE_STAGEBUF   0x200

typedef struct tdVMMX64_TLB_SPIDER_STAGE_INTERNAL {
    QWORD c;
    PMEM_IO_SCATTER_HEADER ppDMAs[VMMX64_TLB_SIZE_STAGEBUF];
    PVMM_CACHE_ENTRY ppEntrys[VMMX64_TLB_SIZE_STAGEBUF];
} VMMX64_TLB_SPIDER_STAGE_INTERNAL, *PVMMX64_TLB_SPIDER_STAGE_INTERNAL;

VOID VmmX64_TlbSpider_ReadToCache(PVMMX64_TLB_SPIDER_STAGE_INTERNAL pTlbSpiderStage)
{
    QWORD i;
    DeviceReadScatterMEM(pTlbSpiderStage->ppDMAs, (DWORD)pTlbSpiderStage->c, NULL);
    for(i = 0; i < pTlbSpiderStage->c; i++) {
        VmmX64_TlbPageTableVerify(pTlbSpiderStage->ppEntrys[i]->h.pb, pTlbSpiderStage->ppEntrys[i]->h.qwA, FALSE);
        VmmCachePut(ctxVmm->ptTLB, pTlbSpiderStage->ppEntrys[i]);
    }
    pTlbSpiderStage->c = 0;
}

BOOL VmmX64_TlbSpider_Stage(_In_ QWORD qwPA, _In_ QWORD qwPML, _In_ BOOL fUserOnly, PVMMX64_TLB_SPIDER_STAGE_INTERNAL pTlbSpiderStage)
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
        if(pTlbSpiderStage->c == VMMX64_TLB_SIZE_STAGEBUF) {
            VmmX64_TlbSpider_ReadToCache(pTlbSpiderStage);
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
        fSpiderComplete = VmmX64_TlbSpider_Stage(pe & 0x0000fffffffff000, qwPML - 1, fUserOnly, pTlbSpiderStage) && fSpiderComplete;
    }
    return fSpiderComplete;
}

/*
* Iterate over PML4, PTPT, PD (3 times in total) to first stage uncached pages
* and then commit them to the cache.
*/
VOID VmmX64_TlbSpider(_In_ QWORD paDTB, _In_ BOOL fUserOnly)
{
    BOOL result;
    QWORD i = 0;
    PVMMX64_TLB_SPIDER_STAGE_INTERNAL pTlbSpiderStage;
    if(!(pTlbSpiderStage = (PVMMX64_TLB_SPIDER_STAGE_INTERNAL)LocalAlloc(LMEM_ZEROINIT, sizeof(VMMX64_TLB_SPIDER_STAGE_INTERNAL)))) { return; }
    while(TRUE) {
        i++;
        result = VmmX64_TlbSpider_Stage(paDTB, 4, fUserOnly, pTlbSpiderStage);
        if(pTlbSpiderStage->c) {
            VmmX64_TlbSpider_ReadToCache(pTlbSpiderStage);
        }
        if(result || (i == 3)) {
            LocalFree(pTlbSpiderStage);
            return;
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
VOID VmmX64_MapTag(_In_ PVMM_PROCESS pProcess, _In_ QWORD vaBase, _In_ QWORD vaLimit, _In_opt_ LPSTR szTag, _In_opt_ LPWSTR wszTag, _In_opt_ BOOL fWoW64)
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

VOID VmmX64_MapDisplayBufferGenerate(_In_ PVMM_PROCESS pProcess)
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

PVMM_MEMMAP_ENTRY VmmX64_MapGetEntry(_In_ PVMM_PROCESS pProcess, _In_ QWORD va)
{
    QWORD i, ce;
    PVMM_MEMMAP_ENTRY pe;
    if(!pProcess->pMemMap) { return NULL; }
    ce = pProcess->cMemMap;
    for(i = 0; i < ce; i++) {
        pe = pProcess->pMemMap + i;
        if((pe->AddrBase >= va) && (va <= pe->AddrBase + (pe->cPages << 12))) {
            return pe;
        }
    }
    return NULL;
}

const QWORD VMMX64_PAGETABLEMAP_PML_REGION_SIZE[5] = { 0, 12, 21, 30, 39 };

VOID VmmX64_MapInitialize_Index(_In_ PVMM_PROCESS pProcess, _In_ QWORD qwVABase, _In_ QWORD qwPML, _In_ QWORD PTEs[512], _In_ BOOL fSupervisorPML, _In_ QWORD paMax)
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
        qwVA = qwVABase + (i << VMMX64_PAGETABLEMAP_PML_REGION_SIZE[qwPML]);
        // maps page
        if((qwPML == 1) || (pte & 0x80) /* PS */) {
            if(qwPML == 4) { continue; } // not supported - PML4 cannot map page directly
            if((cMemMap == 0) ||
                (pMemMapEntry->fPage != (pte & VMM_MEMMAP_FLAG_PAGE_MASK)) ||
                (qwVA != pMemMapEntry->AddrBase + (pMemMapEntry->cPages << 12))) {
                if(cMemMap + 1 >= VMM_MEMMAP_ENTRIES_MAX) { return; }
                pMemMapEntry = pProcess->pMemMap + cMemMap;
                pMemMapEntry->AddrBase = qwVA;
                pMemMapEntry->fPage = pte & VMM_MEMMAP_FLAG_PAGE_MASK;
                pMemMapEntry->cPages = 1ULL << (VMMX64_PAGETABLEMAP_PML_REGION_SIZE[qwPML] - 12);
                pProcess->cMemMap++;
                cMemMap++;
                continue;
            }
            pMemMapEntry->cPages += 1ULL << (VMMX64_PAGETABLEMAP_PML_REGION_SIZE[qwPML] - 12);
            continue;
        }
        // maps page table (PDPT, PD, PT)
        qwNextVA = qwVA;
        pbNextPageTable = VmmTlbGetPageTable(qwNextPA, FALSE);
        if(!pbNextPageTable) { continue; }
        fNextSupervisorPML = !(pte & 0x04);
        VmmX64_MapInitialize_Index(pProcess, qwNextVA, qwPML - 1, (PQWORD)pbNextPageTable, fNextSupervisorPML, paMax);
        cMemMap = pProcess->cMemMap;
        pMemMapEntry = pProcess->pMemMap + cMemMap - 1;
    }
}

VOID VmmX64_MapInitialize(_In_ PVMM_PROCESS pProcess)
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
    VmmX64_MapInitialize_Index(pProcess, 0, 4, (PQWORD)pbPML4, FALSE, ctxMain->cfg.paAddrMax);
    cMemMap = pProcess->cMemMap;
    for(i = 0; i < cMemMap; i++) { // fixup sign extension for kernel addresses
        if(pProcess->pMemMap[i].AddrBase & 0x0000800000000000) {
            pProcess->pMemMap[i].AddrBase |= 0xffff000000000000;
        }
    }
}

_Success_(return)
BOOL VmmX64_Virt2PhysEx(_In_ BOOL fUserOnly, _In_ QWORD va, _In_ BYTE iPML, _In_reads_(4096) PBYTE pbPTEs, _Out_ PQWORD ppa)
{
    QWORD pte, i, qwMask;
    PBYTE pbNextPageTable;
    if(iPML == (BYTE)-1) { iPML = 4; }
    i = 0x1ff & (va >> VMMX64_PAGETABLEMAP_PML_REGION_SIZE[iPML]);
    pte = ((PQWORD)pbPTEs)[i];
    if(!(pte & 0x01)) { return FALSE; }                 // NOT VALID
    if(fUserOnly && !(pte & 0x04)) { return FALSE; }    // SUPERVISOR PAGE & USER MODE REQ
    if(pte & 0x000f000000000000) { return FALSE; }      // RESERVED
    if((iPML == 1) || (pte & 0x80) /* PS */) {
        if(iPML == 4) { return FALSE; }                // NO SUPPORT IN PML4
        qwMask = 0xffffffffffffffff << VMMX64_PAGETABLEMAP_PML_REGION_SIZE[iPML];
        *ppa = pte & 0x0000fffffffff000 & qwMask;   // MASK AWAY BITS FOR 4kB/2MB/1GB PAGES
        qwMask = qwMask ^ 0xffffffffffffffff;
        *ppa = *ppa | (qwMask & va);            // FILL LOWER ADDRESS BITS
        return TRUE;
    }
    pbNextPageTable = VmmTlbGetPageTable(pte & 0x0000fffffffff000, FALSE);
    if(!pbNextPageTable) { return FALSE; }
    return VmmX64_Virt2PhysEx(fUserOnly, va, iPML - 1, pbNextPageTable, ppa);
}

_Success_(return)
BOOL VmmX64_Virt2Phys(_In_ PVMM_PROCESS pProcess, _In_ QWORD va, _Out_ PQWORD ppa)
{
    PBYTE pbPML4 = VmmTlbGetPageTable(pProcess->paPML4, FALSE);
    if(!pbPML4) { return FALSE; }
    *ppa = 0;
    return VmmX64_Virt2PhysEx(pProcess->fUserOnly, va, 4, pbPML4, ppa);
}

VOID VmmX64_Virt2PhysGetInformation_DoWork(_Inout_ PVMM_PROCESS pProcess, _Inout_ PVMM_VIRT2PHYS_INFORMATION pVirt2PhysInfo, _In_ BYTE iPML, _In_ QWORD PTEs[512])
{
    QWORD pte, i, qwMask;
    PBYTE pbNextPageTable;
    i = 0x1ff & (pVirt2PhysInfo->va >> VMMX64_PAGETABLEMAP_PML_REGION_SIZE[iPML]);
    pte = PTEs[i];
    pVirt2PhysInfo->x64.iPTEs[iPML] = (WORD)i;
    pVirt2PhysInfo->x64.PTEs[iPML] = pte;
    if(!(pte & 0x01)) { return; }                           // NOT VALID
    if(pProcess->fUserOnly && !(pte & 0x04)) { return; }    // SUPERVISOR PAGE & USER MODE REQ
    if(pte & 0x000f000000000000) { return; }                // RESERVED
    if((iPML == 1) || (pte & 0x80) /* PS */) {
        if(iPML == 4) { return; }                          // NO SUPPORT IN PML4
        qwMask = 0xffffffffffffffff << VMMX64_PAGETABLEMAP_PML_REGION_SIZE[iPML];
        pVirt2PhysInfo->x64.pas[0] = pte & 0x0000fffffffff000 & qwMask;     // MASK AWAY BITS FOR 4kB/2MB/1GB PAGES
        qwMask = qwMask ^ 0xffffffffffffffff;
        pVirt2PhysInfo->x64.pas[0] = pVirt2PhysInfo->x64.pas[0] | (qwMask & pVirt2PhysInfo->va);    // FILL LOWER ADDRESS BITS
        return;
    }
    if(!(pbNextPageTable = VmmTlbGetPageTable(pte & 0x0000fffffffff000, FALSE))) { return; }
    pVirt2PhysInfo->x64.pas[iPML - 1] = pte & 0x0000fffffffff000;
    VmmX64_Virt2PhysGetInformation_DoWork(pProcess, pVirt2PhysInfo, iPML - 1, (PQWORD)pbNextPageTable);
}

VOID VmmX64_Virt2PhysGetInformation(_Inout_ PVMM_PROCESS pProcess, _Inout_ PVMM_VIRT2PHYS_INFORMATION pVirt2PhysInfo)
{
    QWORD va;
    PBYTE pbPML4;
    va = pVirt2PhysInfo->va;
    ZeroMemory(pVirt2PhysInfo, sizeof(VMM_VIRT2PHYS_INFORMATION));
    pVirt2PhysInfo->tpMemoryModel = X64;
    pVirt2PhysInfo->va = va;
    pVirt2PhysInfo->x64.pas[4] = pProcess->paPML4;
    if(!(pbPML4 = VmmTlbGetPageTable(pProcess->paPML4, FALSE))) { return; }
    VmmX64_Virt2PhysGetInformation_DoWork(pProcess, pVirt2PhysInfo, 4, (PQWORD)pbPML4);
}

VOID VmmX64_Close()
{
    ZeroMemory(&ctxVmm->MemoryModel, sizeof(VMM_MEMORYMODEL));
}

VOID VmmX64_Initialize()
{
    if(ctxVmm->MemoryModel.pfnClose) {
        ctxVmm->MemoryModel.pfnClose();
    }
    ctxVmm->MemoryModel.pfnInitialize = VmmX64_Initialize;
    ctxVmm->MemoryModel.pfnClose = VmmX64_Close;
    ctxVmm->MemoryModel.pfnVirt2Phys = VmmX64_Virt2Phys;
    ctxVmm->MemoryModel.pfnVirt2PhysEx = VmmX64_Virt2PhysEx;
    ctxVmm->MemoryModel.pfnVirt2PhysGetInformation = VmmX64_Virt2PhysGetInformation;
    ctxVmm->MemoryModel.pfnMapInitialize = VmmX64_MapInitialize;
    ctxVmm->MemoryModel.pfnMapTag = VmmX64_MapTag;
    ctxVmm->MemoryModel.pfnMapGetEntry = VmmX64_MapGetEntry;
    ctxVmm->MemoryModel.pfnMapDisplayBufferGenerate = VmmX64_MapDisplayBufferGenerate;
    ctxVmm->MemoryModel.pfnTlbSpider = VmmX64_TlbSpider;
    ctxVmm->MemoryModel.pfnTlbPageTableVerify = VmmX64_TlbPageTableVerify;
    ctxVmm->MemoryModel.tp = X64;
}
