// mm_x86pae.c : implementation of the x86 PAE (Physical Address Extension) 32-bit protected mode memory model.
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
BOOL MmX86PAE_TlbPageTableVerify(_Inout_ PBYTE pb, _In_ QWORD pa, _In_ BOOL fSelfRefReq)
{
    return TRUE;
}

#define VMMX64_TLB_SIZE_STAGEBUF   0x200

typedef struct tdMMX86PAE_TLB_SPIDER_STAGE_INTERNAL {
    QWORD c;
    PMEM_IO_SCATTER_HEADER ppDMAs[VMMX64_TLB_SIZE_STAGEBUF];
    PVMM_CACHE_ENTRY ppEntrys[VMMX64_TLB_SIZE_STAGEBUF];
} MMX86PAE_TLB_SPIDER_STAGE_INTERNAL, *PMMX86PAE_TLB_SPIDER_STAGE_INTERNAL;

VOID MmX86PAE_TlbSpider_ReadToCache(PMMX86PAE_TLB_SPIDER_STAGE_INTERNAL pTlbSpiderStage)
{
    QWORD i;
    DeviceReadScatterMEM(pTlbSpiderStage->ppDMAs, (DWORD)pTlbSpiderStage->c, NULL);
    for(i = 0; i < pTlbSpiderStage->c; i++) {
        MmX86PAE_TlbPageTableVerify(pTlbSpiderStage->ppEntrys[i]->h.pb, pTlbSpiderStage->ppEntrys[i]->h.qwA, FALSE);
        VmmCachePut(ctxVmm->ptTLB, pTlbSpiderStage->ppEntrys[i]);
    }
    pTlbSpiderStage->c = 0;
}

BOOL MmX86PAE_TlbSpider_PD_PT(_In_ QWORD pa, _In_ BYTE iPML, _In_ BOOL fUserOnly, PMMX86PAE_TLB_SPIDER_STAGE_INTERNAL pTlbSpiderStage)
{
    BOOL fSpiderComplete = TRUE;
    PMEM_IO_SCATTER_HEADER pt;
    QWORD i, pte;
    // 1: retrieve from cache, add to staging if not found
    pt = VmmCacheGet(ctxVmm->ptTLB, pa);
    if(!pt) {
        pTlbSpiderStage->ppEntrys[pTlbSpiderStage->c] = VmmCacheReserve(ctxVmm->ptTLB);
        pTlbSpiderStage->ppDMAs[pTlbSpiderStage->c] = &pTlbSpiderStage->ppEntrys[pTlbSpiderStage->c]->h;
        pTlbSpiderStage->ppDMAs[pTlbSpiderStage->c]->qwA = pa;
        pTlbSpiderStage->c++;
        if(pTlbSpiderStage->c == VMMX64_TLB_SIZE_STAGEBUF) {
            MmX86PAE_TlbSpider_ReadToCache(pTlbSpiderStage);
        }
        return FALSE;
    }
    if(iPML == 1) { return TRUE; }
    // 2: walk trough all entries for PD
    for(i = 0; i < 0x1000; i += 8) {
        pte = *(PQWORD)(pt->pb + i);
        if(!(pte & 0x01)) { continue; }                 // not valid
        if(pte & 0x80) { continue; }                    // not valid ptr to PT
        if(fUserOnly && !(pte & 0x04)) { continue; }    // supervisor page when fUserOnly -> not valid
        fSpiderComplete = MmX86PAE_TlbSpider_PD_PT(pte & 0x0000fffffffff000, 1, fUserOnly, pTlbSpiderStage) && fSpiderComplete;
    }
    return fSpiderComplete;
}

BOOL MmX86PAE_TlbSpider_PDPT(_In_ QWORD paDTB, _In_ BOOL fUserOnly, PMMX86PAE_TLB_SPIDER_STAGE_INTERNAL pTlbSpiderStage)
{
    BOOL fSpiderComplete = TRUE;
    QWORD i, pte;
    PBYTE pbPDPT;
    // 1: retrieve PDPT
    pbPDPT = VmmTlbGetPageTable(paDTB & 0xfffff000, FALSE);
    if(!pbPDPT) { return FALSE; }
    pbPDPT += paDTB & 0xfe0;
    // 2: walk through all four (4) PDPTEs
    for(i = 0; i < 0x20; i += 8) {
        pte = *(PQWORD)(pbPDPT + i);
        if(!(pte & 0x01)) { continue; }             // not valid
        if(pte & 0xffff0000000001e6) { continue; }  // RESERVED BITS IN PDPTE
        fSpiderComplete = MmX86PAE_TlbSpider_PD_PT(pte & 0x0000fffffffff000, 2, fUserOnly, pTlbSpiderStage) && fSpiderComplete;
    }
    return fSpiderComplete;
}

/*
* Iterate over PTPT, PD (3 times in total) to first stage uncached pages
* and then commit them to the cache.
*/
VOID MmX86PAE_TlbSpider(_In_ QWORD paDTB, _In_ BOOL fUserOnly)
{
    DWORD i = 0;
    BOOL result = FALSE;
    PMMX86PAE_TLB_SPIDER_STAGE_INTERNAL pTlbSpiderStage;
    if(!(pTlbSpiderStage = (PMMX86PAE_TLB_SPIDER_STAGE_INTERNAL)LocalAlloc(LMEM_ZEROINIT, sizeof(MMX86PAE_TLB_SPIDER_STAGE_INTERNAL)))) { return; }
    while(!result && (i < 3)) {
        result = MmX86PAE_TlbSpider_PDPT(paDTB, fUserOnly, pTlbSpiderStage);
        if(pTlbSpiderStage->c) {
            MmX86PAE_TlbSpider_ReadToCache(pTlbSpiderStage);
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
VOID MmX86PAE_MapTag(_In_ PVMM_PROCESS pProcess, _In_ QWORD vaBase, _In_ QWORD vaLimit, _In_opt_ LPSTR szTag, _In_opt_ LPWSTR wszTag, _In_opt_ BOOL fWoW64)
{
    PVMM_MEMMAP_ENTRY pMap;
    QWORD i, lvl, cMap;
    if((vaBase > 0xffffffff) || (vaLimit > 0xffffffff)) { return; }
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

VOID MmX86PAE_MapDisplayBufferGenerate(_In_ PVMM_PROCESS pProcess)
{
    DWORD i, o = 0;
    PBYTE pbBuffer;
    if(!pProcess->cMemMap || !pProcess->pMemMap) { return; }
    pProcess->cbMemMapDisplayCache = 0;
    LocalFree(pProcess->pbMemMapDisplayCache);
    pProcess->pbMemMapDisplayCache = NULL;
    pbBuffer = LocalAlloc(LMEM_ZEROINIT, 70 * pProcess->cMemMap);
    if(!pbBuffer) { return; }
    for(i = 0; i < pProcess->cMemMap; i++) {
        o += snprintf(
            pbBuffer + o,
            70,
            "%04x %8x %08x-%08x %sr%s%s %s\n",
            i,
            (DWORD)pProcess->pMemMap[i].cPages,
            (DWORD)pProcess->pMemMap[i].AddrBase,
            (DWORD)(pProcess->pMemMap[i].AddrBase + (pProcess->pMemMap[i].cPages << 12) - 1),
            pProcess->pMemMap[i].fPage & VMM_MEMMAP_FLAG_PAGE_NS ? "-" : "s",
            pProcess->pMemMap[i].fPage & VMM_MEMMAP_FLAG_PAGE_W ? "w" : "-",
            pProcess->pMemMap[i].fPage & VMM_MEMMAP_FLAG_PAGE_NX ? "-" : "x",
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

PVMM_MEMMAP_ENTRY MmX86PAE_MapGetEntry(_In_ PVMM_PROCESS pProcess, _In_ QWORD va)
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

const QWORD MMX86PAE_PAGETABLEMAP_PML_REGION_SIZE[4] = { 0, 12, 21, 30 };

VOID MmX86PAE_MapInitialize_Index(_In_ PVMM_PROCESS pProcess, _In_ DWORD vaBase, _In_ BYTE iPML, _In_ QWORD PTEs[512], _In_ BOOL fSupervisorPML, _In_ QWORD paMax)
{
    PBYTE pbNextPageTable;
    DWORD i, va;
    QWORD pte;
    BOOL fUserOnly, fNextSupervisorPML;
    QWORD cMemMap = pProcess->cMemMap;
    PVMM_MEMMAP_ENTRY pMemMap = pProcess->pMemMap;
    PVMM_MEMMAP_ENTRY pMemMapEntry = pMemMap + cMemMap - 1;
    fUserOnly = pProcess->fUserOnly;
    for(i = 0; i < 512; i++) {
        if((iPML == 3) && (i > 3)) { break; }                      // MAX 4 ENTRIES IN PDPT
        pte = PTEs[i];
        if(!(pte & 0x01)) { continue; }
        if((pte & 0x0000fffffffff000) > paMax) { continue; }
        if(iPML == 3) {
            // PDPT: (iPML = 3)
            if(pte & 0xffff0000000001e6) { continue; }        // RESERVED BITS IN PDPTE
            va = i * 0x40000000;
        } else {
            // PT or PD: (iPML = 1..2)
            if(fSupervisorPML) { pte = pte & 0xfffffffffffffffb; }
            if(fUserOnly && !(pte & 0x04)) { continue; }
            va = vaBase + (i << MMX86PAE_PAGETABLEMAP_PML_REGION_SIZE[iPML]);
            // maps page
            if((iPML == 1) || (pte & 0x80) /* PS */) {
                if((cMemMap == 0) ||
                    (pMemMapEntry->fPage != (pte & VMM_MEMMAP_FLAG_PAGE_MASK)) ||
                    (va != pMemMapEntry->AddrBase + (pMemMapEntry->cPages << 12))) {
                    if(cMemMap + 1 >= VMM_MEMMAP_ENTRIES_MAX) { return; }
                    pMemMapEntry = pProcess->pMemMap + cMemMap;
                    pMemMapEntry->AddrBase = va;
                    pMemMapEntry->fPage = pte & VMM_MEMMAP_FLAG_PAGE_MASK;
                    pMemMapEntry->cPages = 1ULL << (MMX86PAE_PAGETABLEMAP_PML_REGION_SIZE[iPML] - 12);
                    pProcess->cMemMap++;
                    cMemMap++;
                    continue;
                }
                pMemMapEntry->cPages += 1ULL << (MMX86PAE_PAGETABLEMAP_PML_REGION_SIZE[iPML] - 12);
                continue;
            }
        }
        // maps page table (PD, PT)
        fNextSupervisorPML = (iPML != 3) && !(pte & 0x04);
        if(!(pbNextPageTable = VmmTlbGetPageTable(pte & 0x0000fffffffff000, FALSE))) { continue; }
        MmX86PAE_MapInitialize_Index(pProcess, va, iPML - 1, (PQWORD)pbNextPageTable, fNextSupervisorPML, paMax);
        cMemMap = pProcess->cMemMap;
        pMemMapEntry = pProcess->pMemMap + cMemMap - 1;
    }
}

VOID MmX86PAE_MapInitialize(_In_ PVMM_PROCESS pProcess)
{
    PBYTE pbPDPT;
    pProcess->cbMemMapDisplayCache = 0;
    LocalFree(pProcess->pbMemMapDisplayCache);
    pProcess->pbMemMapDisplayCache = NULL;
    LocalFree(pProcess->pMemMap);
    pProcess->cMemMap = 0;
    pProcess->pMemMap = (PVMM_MEMMAP_ENTRY)LocalAlloc(LMEM_ZEROINIT, VMM_MEMMAP_ENTRIES_MAX * sizeof(VMM_MEMMAP_ENTRY));
    if(!pProcess->pMemMap) { return; }
    if(!(pbPDPT = VmmTlbGetPageTable(pProcess->paDTB & 0xfffff000, FALSE))) { return; }
    pbPDPT += pProcess->paDTB & 0xfe0;       // ADJUST PDPT TO 32-BYTE BOUNDARY
    MmX86PAE_MapInitialize_Index(pProcess, 0, 3, (PQWORD)pbPDPT, FALSE, ctxMain->cfg.paAddrMax);
}

_Success_(return)
BOOL MmX86PAE_Virt2Phys(_In_ QWORD paPT, _In_ BOOL fUserOnly, _In_ BYTE iPML, _In_ QWORD va, _Out_ PQWORD ppa)
{
    QWORD pte, i, qwMask;
    PBYTE pbPTEs;
    if(va > 0xffffffff) { return FALSE; }
    if(iPML == (BYTE)-1) { iPML = 3; }
    if(!(pbPTEs = VmmTlbGetPageTable(paPT & 0x0000fffffffff000, FALSE))) { return FALSE; }
    i = 0x1ff & (va >> MMX86PAE_PAGETABLEMAP_PML_REGION_SIZE[iPML]);
    if(iPML == 3) {
        // PDPT
        if(i > 3) { return FALSE; }                     // MAX 4 ENTRIES IN PDPT
        pbPTEs += paPT & 0xfe0;                         // ADJUST PDPT TO 32-BYTE BOUNDARY
        pte = ((PQWORD)pbPTEs)[i];
        if(!(pte & 0x01)) { return FALSE; }             // NOT VALID
        if(pte & 0xffff0000000001e6) { return FALSE; }  // RESERVED BITS IN PDPTE
        return MmX86PAE_Virt2Phys(pte, fUserOnly, 2, va, ppa);
    }
    // PT or PD
    pte = ((PQWORD)pbPTEs)[i];
    if(!(pte & 0x01)) { return FALSE; }                 // NOT VALID
    if(fUserOnly && !(pte & 0x04)) { return FALSE; }    // SUPERVISOR PAGE & USER MODE REQ
    if(pte & 0x000f000000000000) { return FALSE; }      // RESERVED
    if((iPML == 1) || (pte & 0x80) /* PS */) {
        qwMask = 0xffffffffffffffff << MMX86PAE_PAGETABLEMAP_PML_REGION_SIZE[iPML];
        *ppa = pte & 0x0000fffffffff000 & qwMask;       // MASK AWAY BITS FOR 4kB/2MB/1GB PAGES
        qwMask = qwMask ^ 0xffffffffffffffff;
        *ppa = *ppa | (qwMask & va);                    // FILL LOWER ADDRESS BITS
        return TRUE;
    }
    return MmX86PAE_Virt2Phys(pte, fUserOnly, 1, va, ppa);
}

VOID MmX86PAE_Virt2PhysGetInformation_DoWork(_Inout_ PVMM_PROCESS pProcess, _Inout_ PVMM_VIRT2PHYS_INFORMATION pVirt2PhysInfo, _In_ BYTE iPML, _In_ QWORD PTEs[512])
{
    QWORD pte, i, qwMask;
    PBYTE pbNextPageTable;
    i = 0x1ff & (pVirt2PhysInfo->va >> MMX86PAE_PAGETABLEMAP_PML_REGION_SIZE[iPML]);
    if((iPML == 3) && (i > 3)) { return; }                      // MAX 4 ENTRIES IN PDPT
    pte = PTEs[i];
    pVirt2PhysInfo->iPTEs[iPML] = (WORD)i;
    pVirt2PhysInfo->PTEs[iPML] = pte;
    if(!(pte & 0x01)) { return; }                               // NOT VALID
    if(iPML == 3) {
        // PDPT: (iPML = 3)
        if(pte & 0xffff0000000001e6) { return; }                // RESERVED BITS IN PDPTE
    } else {
        // PT or PD: (iPML = 1..2)
        if(pProcess->fUserOnly && !(pte & 0x04)) { return; }    // SUPERVISOR PAGE & USER MODE REQ
        if(pte & 0x000f000000000000) { return; }                // RESERVED
        if((iPML == 1) || (pte & 0x80) /* PS */) {
            qwMask = 0xffffffffffffffff << MMX86PAE_PAGETABLEMAP_PML_REGION_SIZE[iPML];
            pVirt2PhysInfo->pas[0] = pte & 0x0000fffffffff000 & qwMask;     // MASK AWAY BITS FOR 4kB/2MB PAGES
            qwMask = qwMask ^ 0xffffffffffffffff;
            pVirt2PhysInfo->pas[0] = pVirt2PhysInfo->pas[0] | (qwMask & pVirt2PhysInfo->va);    // FILL LOWER ADDRESS BITS
            return;
        }
    }
    if(!(pbNextPageTable = VmmTlbGetPageTable(pte & 0x0000fffffffff000, FALSE))) { return; }
    pVirt2PhysInfo->pas[iPML - 1] = pte & 0x0000fffffffff000;
    MmX86PAE_Virt2PhysGetInformation_DoWork(pProcess, pVirt2PhysInfo, iPML - 1, (PQWORD)pbNextPageTable);
}

VOID MmX86PAE_Virt2PhysGetInformation(_Inout_ PVMM_PROCESS pProcess, _Inout_ PVMM_VIRT2PHYS_INFORMATION pVirt2PhysInfo)
{
    QWORD va;
    PBYTE pbPDPT;
    if(pVirt2PhysInfo->va > 0xffffffff) { return; }
    va = pVirt2PhysInfo->va;
    ZeroMemory(pVirt2PhysInfo, sizeof(VMM_VIRT2PHYS_INFORMATION));
    pVirt2PhysInfo->tpMemoryModel = VMM_MEMORYMODEL_X86PAE;
    pVirt2PhysInfo->va = va;
    pVirt2PhysInfo->pas[3] = pProcess->paDTB;
    if(!(pbPDPT = VmmTlbGetPageTable(pProcess->paDTB & 0xfffff000, FALSE))) { return; }
    MmX86PAE_Virt2PhysGetInformation_DoWork(pProcess, pVirt2PhysInfo, 3, (PQWORD)(pbPDPT + (pProcess->paDTB & 0xfe0)));
}

VOID MmX86PAE_Close()
{
    ctxVmm->f32 = FALSE;
    ctxVmm->tpMemoryModel = VMM_MEMORYMODEL_NA;
    ZeroMemory(&ctxVmm->fnMemoryModel, sizeof(VMM_MEMORYMODEL_FUNCTIONS));
}

VOID MmX86PAE_Initialize()
{
    if(ctxVmm->fnMemoryModel.pfnClose) {
        ctxVmm->fnMemoryModel.pfnClose();
    }
    ctxVmm->fnMemoryModel.pfnInitialize = MmX86PAE_Initialize;
    ctxVmm->fnMemoryModel.pfnClose = MmX86PAE_Close;
    ctxVmm->fnMemoryModel.pfnVirt2Phys = MmX86PAE_Virt2Phys;
    ctxVmm->fnMemoryModel.pfnVirt2PhysGetInformation = MmX86PAE_Virt2PhysGetInformation;
    ctxVmm->fnMemoryModel.pfnMapInitialize = MmX86PAE_MapInitialize;
    ctxVmm->fnMemoryModel.pfnMapTag = MmX86PAE_MapTag;
    ctxVmm->fnMemoryModel.pfnMapGetEntry = MmX86PAE_MapGetEntry;
    ctxVmm->fnMemoryModel.pfnMapDisplayBufferGenerate = MmX86PAE_MapDisplayBufferGenerate;
    ctxVmm->fnMemoryModel.pfnTlbSpider = MmX86PAE_TlbSpider;
    ctxVmm->fnMemoryModel.pfnTlbPageTableVerify = MmX86PAE_TlbPageTableVerify;
    ctxVmm->tpMemoryModel = VMM_MEMORYMODEL_X86PAE;
    ctxVmm->f32 = TRUE;
}
