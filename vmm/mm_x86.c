// mm_x86.c : implementation of the x86 32-bit protected mode memory model.
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
BOOL MmX86_TlbPageTableVerify(_Inout_ PBYTE pb, _In_ QWORD pa, _In_ BOOL fSelfRefReq)
{
    return TRUE;
}

#define VMMX64_TLB_SIZE_STAGEBUF   0x400

typedef struct tdMMX86_TLB_SPIDER_STAGE_INTERNAL {
    QWORD c;
    PMEM_IO_SCATTER_HEADER ppDMAs[VMMX64_TLB_SIZE_STAGEBUF];
    PVMM_CACHE_ENTRY ppEntrys[VMMX64_TLB_SIZE_STAGEBUF];
} MMX86_TLB_SPIDER_STAGE_INTERNAL, *PMMX86_TLB_SPIDER_STAGE_INTERNAL;

VOID MmX86_TlbSpider_ReadToCache(PMMX86_TLB_SPIDER_STAGE_INTERNAL pTlbSpiderStage)
{
    QWORD i;
    DeviceReadScatterMEM(pTlbSpiderStage->ppDMAs, (DWORD)pTlbSpiderStage->c, NULL);
    for(i = 0; i < pTlbSpiderStage->c; i++) {
        MmX86_TlbPageTableVerify(pTlbSpiderStage->ppEntrys[i]->h.pb, pTlbSpiderStage->ppEntrys[i]->h.qwA, FALSE);
        VmmCachePut(ctxVmm->ptTLB, pTlbSpiderStage->ppEntrys[i]);
    }
    pTlbSpiderStage->c = 0;
}

/*
* Iterate over the PD to retrieve uncached PT pages and then commit them to the cache.
*/
VOID MmX86_TlbSpider(_In_ QWORD paDTB, _In_ BOOL fUserOnly)
{
    PBYTE pbPD;
    DWORD i, pte;
    PMEM_IO_SCATTER_HEADER pt;
    PMMX86_TLB_SPIDER_STAGE_INTERNAL pTlbSpiderStage;
    if(!(pTlbSpiderStage = (PMMX86_TLB_SPIDER_STAGE_INTERNAL)LocalAlloc(LMEM_ZEROINIT, sizeof(MMX86_TLB_SPIDER_STAGE_INTERNAL)))) { return; }
    pbPD = VmmTlbGetPageTable(paDTB & 0xfffff000, FALSE);
    if(!pbPD) { return; }
    for(i = 0; i < 0x1000; i += 8) {
        pte = *(PDWORD)(pbPD + i);
        if(!(pte & 0x01)) { continue; }                 // not valid
        if(pte & 0x80) { continue; }                    // not valid ptr to PT
        if(fUserOnly && !(pte & 0x04)) { continue; }    // supervisor page when fUserOnly -> not valid
        pt = VmmCacheGet(ctxVmm->ptTLB, pte & 0xfffff000);
        if(!pt) {
            pTlbSpiderStage->ppEntrys[pTlbSpiderStage->c] = VmmCacheReserve(ctxVmm->ptTLB);
            pTlbSpiderStage->ppDMAs[pTlbSpiderStage->c] = &pTlbSpiderStage->ppEntrys[pTlbSpiderStage->c]->h;
            pTlbSpiderStage->ppDMAs[pTlbSpiderStage->c]->qwA = pte & 0xfffff000;
            pTlbSpiderStage->c++;
        }
    }
    MmX86_TlbSpider_ReadToCache(pTlbSpiderStage);
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
VOID MmX86_MapTag(_In_ PVMM_PROCESS pProcess, _In_ QWORD vaBase, _In_ QWORD vaLimit, _In_opt_ LPSTR szTag, _In_opt_ LPWSTR wszTag, _In_opt_ BOOL fWoW64)
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

VOID MmX86_MapDisplayBufferGenerate(_In_ PVMM_PROCESS pProcess)
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
            "%04x %8x %08x-%08x %sr%sx %s\n",
            i,
            (DWORD)pProcess->pMemMap[i].cPages,
            (DWORD)pProcess->pMemMap[i].AddrBase,
            (DWORD)(pProcess->pMemMap[i].AddrBase + (pProcess->pMemMap[i].cPages << 12) - 1),
            pProcess->pMemMap[i].fPage & VMM_MEMMAP_FLAG_PAGE_NS ? "-" : "s",
            pProcess->pMemMap[i].fPage & VMM_MEMMAP_FLAG_PAGE_W ? "w" : "-",
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

PVMM_MEMMAP_ENTRY MmX86_MapGetEntry(_In_ PVMM_PROCESS pProcess, _In_ QWORD va)
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

const QWORD MMX86_PAGETABLEMAP_PML_REGION_SIZE[3] = { 0, 12, 22 };

VOID MmX86_MapInitialize_Index(_In_ PVMM_PROCESS pProcess, _In_ DWORD vaBase, _In_ BYTE iPML, _In_ DWORD PTEs[1024], _In_ BOOL fSupervisorPML, _In_ QWORD paMax)
{
    PBYTE pbNextPageTable;
    DWORD i, va, pte;
    BOOL fUserOnly, fNextSupervisorPML;
    QWORD cMemMap = pProcess->cMemMap;
    PVMM_MEMMAP_ENTRY pMemMap = pProcess->pMemMap;
    PVMM_MEMMAP_ENTRY pMemMapEntry = pMemMap + cMemMap - 1;
    fUserOnly = pProcess->fUserOnly;
    for(i = 0; i < 1024; i++) {
        pte = PTEs[i];
        if(!(pte & 0x01)) { continue; }
        if((pte & 0xfffff000) > paMax) { continue; }
        if(fSupervisorPML) { pte = pte & 0xfffffffb; }
        if(fUserOnly && !(pte & 0x04)) { continue; }
        va = vaBase + (i << MMX86_PAGETABLEMAP_PML_REGION_SIZE[iPML]);
        if((iPML == 1) || (pte & 0x80) /* PS */) {
            if((cMemMap == 0) ||
                (pMemMapEntry->fPage != (pte & VMM_MEMMAP_FLAG_PAGE_MASK)) ||
                (va != pMemMapEntry->AddrBase + (pMemMapEntry->cPages << 12))) {
                if(cMemMap + 1 >= VMM_MEMMAP_ENTRIES_MAX) { return; }
                pMemMapEntry = pProcess->pMemMap + cMemMap;
                pMemMapEntry->AddrBase = va;
                pMemMapEntry->fPage = pte & VMM_MEMMAP_FLAG_PAGE_MASK;
                pMemMapEntry->cPages = 1ULL << (MMX86_PAGETABLEMAP_PML_REGION_SIZE[iPML] - 12);
                pProcess->cMemMap++;
                cMemMap++;
                continue;
            }
            pMemMapEntry->cPages += 1ULL << (MMX86_PAGETABLEMAP_PML_REGION_SIZE[iPML] - 12);
            continue;
        }
        // maps page table
        fNextSupervisorPML = !(pte & 0x04);
        if(!(pbNextPageTable = VmmTlbGetPageTable(pte & 0xfffff000, FALSE))) { continue; }
        MmX86_MapInitialize_Index(pProcess, va, 1, (PDWORD)pbNextPageTable, fNextSupervisorPML, paMax);
        cMemMap = pProcess->cMemMap;
        pMemMapEntry = pProcess->pMemMap + cMemMap - 1;
    }
}

VOID MmX86_MapInitialize(_In_ PVMM_PROCESS pProcess)
{
    PBYTE pbPD;
    pProcess->cbMemMapDisplayCache = 0;
    LocalFree(pProcess->pbMemMapDisplayCache);
    pProcess->pbMemMapDisplayCache = NULL;
    LocalFree(pProcess->pMemMap);
    pProcess->cMemMap = 0;
    pProcess->pMemMap = (PVMM_MEMMAP_ENTRY)LocalAlloc(LMEM_ZEROINIT, VMM_MEMMAP_ENTRIES_MAX * sizeof(VMM_MEMMAP_ENTRY));
    if(!pProcess->pMemMap) { return; }
    if(!(pbPD = VmmTlbGetPageTable(pProcess->paDTB & 0xfffff000, FALSE))) { return; }
    MmX86_MapInitialize_Index(pProcess, 0, 2, (PDWORD)pbPD, FALSE, ctxMain->cfg.paAddrMax);
}

_Success_(return)
BOOL MmX86_Virt2Phys(_In_ QWORD paPT, _In_ BOOL fUserOnly, _In_ BYTE iPML, _In_ QWORD va, _Out_ PQWORD ppa)
{
    DWORD pte, i;
    PBYTE pbPTEs;
    if(va > 0xffffffff) { return FALSE; }
    if(paPT > 0xffffffff) { return FALSE; }
    if(iPML == (BYTE)-1) { iPML = 2; }
    if(!(pbPTEs = VmmTlbGetPageTable(paPT & 0xfffff000, FALSE))) { return FALSE; }
    i = 0x3ff & (va >> MMX86_PAGETABLEMAP_PML_REGION_SIZE[iPML]);
    pte = ((PDWORD)pbPTEs)[i];
    if(!(pte & 0x01)) { return FALSE; }                 // NOT VALID
    if(fUserOnly && !(pte & 0x04)) { return FALSE; }    // SUPERVISOR PAGE & USER MODE REQ
    if((iPML == 2) && !(pte & 0x80) /* PS */) {
        return MmX86_Virt2Phys(pte, fUserOnly, 1, va, ppa);
    }
    if(iPML == 1) { // 4kB PAGE
        *ppa = pte & 0xfffff000;
        return TRUE;
    }
    // 4MB PAGE
    if(pte & 0x003e0000) { return FALSE; }              // RESERVED
    *ppa = (((QWORD)(pte & 0x0001e000)) << (32 - 13)) + (pte & 0xffc00000) + (va & 0x003ff000);
    return TRUE;
}

VOID MmX86_Virt2PhysGetInformation_DoWork(_Inout_ PVMM_PROCESS pProcess, _Inout_ PVMM_VIRT2PHYS_INFORMATION pVirt2PhysInfo, _In_ BYTE iPML, _In_ QWORD paPT)
{
    PDWORD PTEs;
    DWORD pte, i;
    if(!(PTEs = (PDWORD)VmmTlbGetPageTable(paPT, FALSE))) { return; }
    i = 0x3ff & (pVirt2PhysInfo->va >> MMX86_PAGETABLEMAP_PML_REGION_SIZE[iPML]);
    pte = PTEs[i];
    pVirt2PhysInfo->pas[iPML] = paPT;
    pVirt2PhysInfo->iPTEs[iPML] = (WORD)i;
    pVirt2PhysInfo->PTEs[iPML] = pte;
    if(!(pte & 0x01)) { return; }                           // NOT VALID
    if(pProcess->fUserOnly && !(pte & 0x04)) { return; }    // SUPERVISOR PAGE & USER MODE REQ
    if(iPML == 1) {     // 4kB page
        pVirt2PhysInfo->pas[0] = pte & 0xfffff000;
        return;
    }
    if(pte & 0x80) {    // 4MB page
        if(pte & 0x003e0000) { return; }                    // RESERVED
        pVirt2PhysInfo->pas[0] = (pte & 0xffc00000) + (((QWORD)(pte & 0x0001e000)) << (32 - 13));
        return;
    }
    MmX86_Virt2PhysGetInformation_DoWork(pProcess, pVirt2PhysInfo, 1, pte & 0xffff000); // PDE
}

VOID MmX86_Virt2PhysGetInformation(_Inout_ PVMM_PROCESS pProcess, _Inout_ PVMM_VIRT2PHYS_INFORMATION pVirt2PhysInfo)
{
    QWORD va;
    if(pVirt2PhysInfo->va > 0xffffffff) { return; }
    va = pVirt2PhysInfo->va;
    ZeroMemory(pVirt2PhysInfo, sizeof(VMM_VIRT2PHYS_INFORMATION));
    pVirt2PhysInfo->tpMemoryModel = VMM_MEMORYMODEL_X86;
    pVirt2PhysInfo->va = va;
    MmX86_Virt2PhysGetInformation_DoWork(pProcess, pVirt2PhysInfo, 2, pProcess->paDTB & 0xfffff000);
}

VOID MmX86_Close()
{
    ctxVmm->f32 = FALSE;
    ctxVmm->tpMemoryModel = VMM_MEMORYMODEL_NA;
    ZeroMemory(&ctxVmm->fnMemoryModel, sizeof(VMM_MEMORYMODEL_FUNCTIONS));
}

VOID MmX86_Initialize()
{
    if(ctxVmm->fnMemoryModel.pfnClose) {
        ctxVmm->fnMemoryModel.pfnClose();
    }
    ctxVmm->fnMemoryModel.pfnInitialize = MmX86_Initialize;
    ctxVmm->fnMemoryModel.pfnClose = MmX86_Close;
    ctxVmm->fnMemoryModel.pfnVirt2Phys = MmX86_Virt2Phys;
    ctxVmm->fnMemoryModel.pfnVirt2PhysGetInformation = MmX86_Virt2PhysGetInformation;
    ctxVmm->fnMemoryModel.pfnMapInitialize = MmX86_MapInitialize;
    ctxVmm->fnMemoryModel.pfnMapTag = MmX86_MapTag;
    ctxVmm->fnMemoryModel.pfnMapGetEntry = MmX86_MapGetEntry;
    ctxVmm->fnMemoryModel.pfnMapDisplayBufferGenerate = MmX86_MapDisplayBufferGenerate;
    ctxVmm->fnMemoryModel.pfnTlbSpider = MmX86_TlbSpider;
    ctxVmm->fnMemoryModel.pfnTlbPageTableVerify = MmX86_TlbPageTableVerify;
    ctxVmm->tpMemoryModel = VMM_MEMORYMODEL_X86;
    ctxVmm->f32 = TRUE;
}
