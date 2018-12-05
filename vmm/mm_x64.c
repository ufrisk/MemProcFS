// mm_x64.c : implementation of the x64 / IA32e / long-mode paging / memory model.
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
BOOL MmX64_TlbPageTableVerify(_Inout_ PBYTE pb, _In_ QWORD pa, _In_ BOOL fSelfRefReq)
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

#define MMX64_TLB_SIZE_STAGEBUF   0x200

typedef struct tdMMX64_TLB_SPIDER_STAGE_INTERNAL {
    QWORD c;
    PMEM_IO_SCATTER_HEADER ppDMAs[MMX64_TLB_SIZE_STAGEBUF];
    PVMM_CACHE_ENTRY ppEntrys[MMX64_TLB_SIZE_STAGEBUF];
} MMX64_TLB_SPIDER_STAGE_INTERNAL, *PMMX64_TLB_SPIDER_STAGE_INTERNAL;

VOID MmX64_TlbSpider_ReadToCache(PMMX64_TLB_SPIDER_STAGE_INTERNAL pTlbSpiderStage)
{
    QWORD i;
    DeviceReadScatterMEM(pTlbSpiderStage->ppDMAs, (DWORD)pTlbSpiderStage->c, NULL);
    for(i = 0; i < pTlbSpiderStage->c; i++) {
        MmX64_TlbPageTableVerify(pTlbSpiderStage->ppEntrys[i]->h.pb, pTlbSpiderStage->ppEntrys[i]->h.qwA, FALSE);
        VmmCachePut(ctxVmm->ptTLB, pTlbSpiderStage->ppEntrys[i]);
    }
    pTlbSpiderStage->c = 0;
}

BOOL MmX64_TlbSpider_Stage(_In_ QWORD pa, _In_ BYTE iPML, _In_ BOOL fUserOnly, PMMX64_TLB_SPIDER_STAGE_INTERNAL pTlbSpiderStage)
{
    BOOL fSpiderComplete = TRUE;
    PMEM_IO_SCATTER_HEADER pt;
    QWORD i, pe;
    // 1: retrieve from cache, add to staging if not found
    pt = VmmCacheGet(ctxVmm->ptTLB, pa);
    if(!pt) {
        pTlbSpiderStage->ppEntrys[pTlbSpiderStage->c] = VmmCacheReserve(ctxVmm->ptTLB);
        pTlbSpiderStage->ppDMAs[pTlbSpiderStage->c] = &pTlbSpiderStage->ppEntrys[pTlbSpiderStage->c]->h;
        pTlbSpiderStage->ppDMAs[pTlbSpiderStage->c]->qwA = pa;
        pTlbSpiderStage->c++;
        if(pTlbSpiderStage->c == MMX64_TLB_SIZE_STAGEBUF) {
            MmX64_TlbSpider_ReadToCache(pTlbSpiderStage);
        }
        return FALSE;
    }
    // 2: walk trough all entries for PML4, PDPT, PD
    if(iPML == 1) { return TRUE; }
    for(i = 0; i < 0x1000; i += 8) {
        pe = *(PQWORD)(pt->pb + i);
        if(!(pe & 0x01)) { continue; }  // not valid
        if(pe & 0x80) { continue; }     // not valid ptr to (PDPT || PD || PT)
        if(fUserOnly && !(pe & 0x04)) { continue; } // supervisor page when fUserOnly -> not valid
        fSpiderComplete = MmX64_TlbSpider_Stage(pe & 0x0000fffffffff000, iPML - 1, fUserOnly, pTlbSpiderStage) && fSpiderComplete;
    }
    return fSpiderComplete;
}

/*
* Iterate over PML4, PTPT, PD (3 times in total) to first stage uncached pages
* and then commit them to the cache.
*/
VOID MmX64_TlbSpider(_In_ QWORD paDTB, _In_ BOOL fUserOnly)
{
    DWORD i = 0;
    BOOL result = FALSE;
    PMMX64_TLB_SPIDER_STAGE_INTERNAL pTlbSpiderStage;
    if(!(pTlbSpiderStage = (PMMX64_TLB_SPIDER_STAGE_INTERNAL)LocalAlloc(LMEM_ZEROINIT, sizeof(MMX64_TLB_SPIDER_STAGE_INTERNAL)))) { return; }
    while(!result && (i < 3)) {
        result = MmX64_TlbSpider_Stage(paDTB, 4, fUserOnly, pTlbSpiderStage);
        if(pTlbSpiderStage->c) {
            MmX64_TlbSpider_ReadToCache(pTlbSpiderStage);
        }
        i++;
    }
    LocalFree(pTlbSpiderStage);
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
VOID MmX64_MapTag(_In_ PVMM_PROCESS pProcess, _In_ QWORD vaBase, _In_ QWORD vaLimit, _In_opt_ LPSTR szTag, _In_opt_ LPWSTR wszTag, _In_opt_ BOOL fWoW64)
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

VOID MmX64_MapDisplayBufferGenerate(_In_ PVMM_PROCESS pProcess)
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

PVMM_MEMMAP_ENTRY MmX64_MapGetEntry(_In_ PVMM_PROCESS pProcess, _In_ QWORD va)
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

const QWORD MMX64_PAGETABLEMAP_PML_REGION_SIZE[5] = { 0, 12, 21, 30, 39 };

VOID MmX64_MapInitialize_Index(_In_ PVMM_PROCESS pProcess, _In_ QWORD vaBase, _In_ BYTE iPML, _In_ QWORD PTEs[512], _In_ BOOL fSupervisorPML, _In_ QWORD paMax)
{
    PBYTE pbNextPageTable;
    QWORD i, pte, va;
    BOOL fUserOnly, fNextSupervisorPML;
    QWORD cMemMap = pProcess->cMemMap;
    PVMM_MEMMAP_ENTRY pMemMap = pProcess->pMemMap;
    PVMM_MEMMAP_ENTRY pMemMapEntry = pMemMap + cMemMap - 1;
    fUserOnly = pProcess->fUserOnly;
    for(i = 0; i < 512; i++) {
        pte = PTEs[i];
        if(!(pte & 0x01)) { continue; }
        if((pte & 0x0000fffffffff000) > paMax) { continue; }
        if(fSupervisorPML) { pte = pte & 0xfffffffffffffffb; }
        if(fUserOnly && !(pte & 0x04)) { continue; }
        va = vaBase + (i << MMX64_PAGETABLEMAP_PML_REGION_SIZE[iPML]);
        // maps page
        if((iPML == 1) || (pte & 0x80) /* PS */) {
            if(iPML == 4) { continue; } // not supported - PML4 cannot map page directly
            if((cMemMap == 0) ||
                (pMemMapEntry->fPage != (pte & VMM_MEMMAP_FLAG_PAGE_MASK)) ||
                (va != pMemMapEntry->AddrBase + (pMemMapEntry->cPages << 12))) {
                if(cMemMap + 1 >= VMM_MEMMAP_ENTRIES_MAX) { return; }
                pMemMapEntry = pProcess->pMemMap + cMemMap;
                pMemMapEntry->AddrBase = va;
                pMemMapEntry->fPage = pte & VMM_MEMMAP_FLAG_PAGE_MASK;
                pMemMapEntry->cPages = 1ULL << (MMX64_PAGETABLEMAP_PML_REGION_SIZE[iPML] - 12);
                pProcess->cMemMap++;
                cMemMap++;
                continue;
            }
            pMemMapEntry->cPages += 1ULL << (MMX64_PAGETABLEMAP_PML_REGION_SIZE[iPML] - 12);
            continue;
        }
        // maps page table (PDPT, PD, PT)
        fNextSupervisorPML = !(pte & 0x04);
        if(!(pbNextPageTable = VmmTlbGetPageTable(pte & 0x0000fffffffff000, FALSE))) { continue; }
        MmX64_MapInitialize_Index(pProcess, va, iPML - 1, (PQWORD)pbNextPageTable, fNextSupervisorPML, paMax);
        cMemMap = pProcess->cMemMap;
        pMemMapEntry = pProcess->pMemMap + cMemMap - 1;
    }
}

VOID MmX64_MapInitialize(_In_ PVMM_PROCESS pProcess)
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
    pbPML4 = VmmTlbGetPageTable(pProcess->paDTB, FALSE);
    if(!pbPML4) { return; }
    MmX64_MapInitialize_Index(pProcess, 0, 4, (PQWORD)pbPML4, FALSE, ctxMain->cfg.paAddrMax);
    cMemMap = pProcess->cMemMap;
    for(i = 0; i < cMemMap; i++) { // fixup sign extension for kernel addresses
        if(pProcess->pMemMap[i].AddrBase & 0x0000800000000000) {
            pProcess->pMemMap[i].AddrBase |= 0xffff000000000000;
        }
    }
}

_Success_(return)
BOOL MmX64_Virt2Phys(_In_ QWORD paPT, _In_ BOOL fUserOnly, _In_ BYTE iPML, _In_ QWORD va, _Out_ PQWORD ppa)
{
    QWORD pte, i, qwMask;
    PBYTE pbPTEs;
    if(iPML == (BYTE)-1) { iPML = 4; }
    if(!(pbPTEs = VmmTlbGetPageTable(paPT & 0x0000fffffffff000, FALSE))) { return FALSE; }
    i = 0x1ff & (va >> MMX64_PAGETABLEMAP_PML_REGION_SIZE[iPML]);
    pte = ((PQWORD)pbPTEs)[i];
    if(!(pte & 0x01)) { return FALSE; }                 // NOT VALID
    if(fUserOnly && !(pte & 0x04)) { return FALSE; }    // SUPERVISOR PAGE & USER MODE REQ
    if(pte & 0x000f000000000000) { return FALSE; }      // RESERVED
    if((iPML == 1) || (pte & 0x80) /* PS */) {
        if(iPML == 4) { return FALSE; }                 // NO SUPPORT IN PML4
        qwMask = 0xffffffffffffffff << MMX64_PAGETABLEMAP_PML_REGION_SIZE[iPML];
        *ppa = pte & 0x0000fffffffff000 & qwMask;       // MASK AWAY BITS FOR 4kB/2MB/1GB PAGES
        qwMask = qwMask ^ 0xffffffffffffffff;
        *ppa = *ppa | (qwMask & va);                    // FILL LOWER ADDRESS BITS
        return TRUE;
    }
    return MmX64_Virt2Phys(pte, fUserOnly, iPML - 1, va, ppa);
}

VOID MmX64_Virt2PhysGetInformation_DoWork(_Inout_ PVMM_PROCESS pProcess, _Inout_ PVMM_VIRT2PHYS_INFORMATION pVirt2PhysInfo, _In_ BYTE iPML, _In_ QWORD PTEs[512])
{
    QWORD pte, i, qwMask;
    PBYTE pbNextPageTable;
    i = 0x1ff & (pVirt2PhysInfo->va >> MMX64_PAGETABLEMAP_PML_REGION_SIZE[iPML]);
    pte = PTEs[i];
    pVirt2PhysInfo->iPTEs[iPML] = (WORD)i;
    pVirt2PhysInfo->PTEs[iPML] = pte;
    if(!(pte & 0x01)) { return; }                           // NOT VALID
    if(pProcess->fUserOnly && !(pte & 0x04)) { return; }    // SUPERVISOR PAGE & USER MODE REQ
    if(pte & 0x000f000000000000) { return; }                // RESERVED
    if((iPML == 1) || (pte & 0x80) /* PS */) {
        if(iPML == 4) { return; }                          // NO SUPPORT IN PML4
        qwMask = 0xffffffffffffffff << MMX64_PAGETABLEMAP_PML_REGION_SIZE[iPML];
        pVirt2PhysInfo->pas[0] = pte & 0x0000fffffffff000 & qwMask;     // MASK AWAY BITS FOR 4kB/2MB/1GB PAGES
        qwMask = qwMask ^ 0xffffffffffffffff;
        pVirt2PhysInfo->pas[0] = pVirt2PhysInfo->pas[0] | (qwMask & pVirt2PhysInfo->va);    // FILL LOWER ADDRESS BITS
        return;
    }
    if(!(pbNextPageTable = VmmTlbGetPageTable(pte & 0x0000fffffffff000, FALSE))) { return; }
    pVirt2PhysInfo->pas[iPML - 1] = pte & 0x0000fffffffff000;
    MmX64_Virt2PhysGetInformation_DoWork(pProcess, pVirt2PhysInfo, iPML - 1, (PQWORD)pbNextPageTable);
}

VOID MmX64_Virt2PhysGetInformation(_Inout_ PVMM_PROCESS pProcess, _Inout_ PVMM_VIRT2PHYS_INFORMATION pVirt2PhysInfo)
{
    QWORD va;
    PBYTE pbPML4;
    va = pVirt2PhysInfo->va;
    ZeroMemory(pVirt2PhysInfo, sizeof(VMM_VIRT2PHYS_INFORMATION));
    pVirt2PhysInfo->tpMemoryModel = VMM_MEMORYMODEL_X64;
    pVirt2PhysInfo->va = va;
    pVirt2PhysInfo->pas[4] = pProcess->paDTB;
    if(!(pbPML4 = VmmTlbGetPageTable(pProcess->paDTB, FALSE))) { return; }
    MmX64_Virt2PhysGetInformation_DoWork(pProcess, pVirt2PhysInfo, 4, (PQWORD)pbPML4);
}

VOID MmX64_Close()
{
    ctxVmm->f32 = FALSE;
    ctxVmm->tpMemoryModel = VMM_MEMORYMODEL_NA;
    ZeroMemory(&ctxVmm->fnMemoryModel, sizeof(VMM_MEMORYMODEL_FUNCTIONS));
}

VOID MmX64_Initialize()
{
    if(ctxVmm->fnMemoryModel.pfnClose) {
        ctxVmm->fnMemoryModel.pfnClose();
    }
    ctxVmm->fnMemoryModel.pfnInitialize = MmX64_Initialize;
    ctxVmm->fnMemoryModel.pfnClose = MmX64_Close;
    ctxVmm->fnMemoryModel.pfnVirt2Phys = MmX64_Virt2Phys;
    ctxVmm->fnMemoryModel.pfnVirt2PhysGetInformation = MmX64_Virt2PhysGetInformation;
    ctxVmm->fnMemoryModel.pfnMapInitialize = MmX64_MapInitialize;
    ctxVmm->fnMemoryModel.pfnMapTag = MmX64_MapTag;
    ctxVmm->fnMemoryModel.pfnMapGetEntry = MmX64_MapGetEntry;
    ctxVmm->fnMemoryModel.pfnMapDisplayBufferGenerate = MmX64_MapDisplayBufferGenerate;
    ctxVmm->fnMemoryModel.pfnTlbSpider = MmX64_TlbSpider;
    ctxVmm->fnMemoryModel.pfnTlbPageTableVerify = MmX64_TlbPageTableVerify;
    ctxVmm->tpMemoryModel = VMM_MEMORYMODEL_X64;
    ctxVmm->f32 = FALSE;
}
