// mm_x86pae.c : implementation of the x86 PAE (Physical Address Extension) 32-bit protected mode memory model.
//
// (c) Ulf Frisk, 2018-2019
// Author: Ulf Frisk, pcileech@frizk.net
//
#include "vmm.h"
#include "vmmproc.h"

#define MMX86PAE_MEMMAP_DISPLAYBUFFER_LINE_LENGTH      70

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
    PMEM_IO_SCATTER_HEADER ppMEMs[VMMX64_TLB_SIZE_STAGEBUF];
    PVMMOB_MEM ppObMEMs[VMMX64_TLB_SIZE_STAGEBUF];
} MMX86PAE_TLB_SPIDER_STAGE_INTERNAL, *PMMX86PAE_TLB_SPIDER_STAGE_INTERNAL;

VOID MmX86PAE_TlbSpider_ReadToCache(PMMX86PAE_TLB_SPIDER_STAGE_INTERNAL pTlbSpiderStage)
{
    QWORD i;
    LeechCore_ReadScatter(pTlbSpiderStage->ppMEMs, (DWORD)pTlbSpiderStage->c);
    for(i = 0; i < pTlbSpiderStage->c; i++) {
        MmX86PAE_TlbPageTableVerify(pTlbSpiderStage->ppObMEMs[i]->h.pb, pTlbSpiderStage->ppObMEMs[i]->h.qwA, FALSE);
        VmmCacheReserveReturn(pTlbSpiderStage->ppObMEMs[i]);
    }
    pTlbSpiderStage->c = 0;
}

BOOL MmX86PAE_TlbSpider_PD_PT(_In_ QWORD pa, _In_ BYTE iPML, _In_ BOOL fUserOnly, PMMX86PAE_TLB_SPIDER_STAGE_INTERNAL pTlbSpiderStage)
{
    BOOL fSpiderComplete = TRUE;
    PVMMOB_MEM pObPT;
    QWORD i, pte;
    // 1: retrieve from cache, add to staging if not found
    pObPT = VmmCacheGet(VMM_CACHE_TAG_TLB, pa);
    if(!pObPT) {
        pTlbSpiderStage->ppObMEMs[pTlbSpiderStage->c] = VmmCacheReserve(VMM_CACHE_TAG_TLB);
        pTlbSpiderStage->ppMEMs[pTlbSpiderStage->c] = &pTlbSpiderStage->ppObMEMs[pTlbSpiderStage->c]->h;
        pTlbSpiderStage->ppMEMs[pTlbSpiderStage->c]->qwA = pa;
        pTlbSpiderStage->c++;
        if(pTlbSpiderStage->c == VMMX64_TLB_SIZE_STAGEBUF) {
            MmX86PAE_TlbSpider_ReadToCache(pTlbSpiderStage);
        }
        return FALSE;
    }
    if(iPML == 1) {
        VmmOb_DECREF(pObPT);
        return TRUE;
    }
    // 2: walk trough all entries for PD
    for(i = 0; i < 512; i++) {
        pte = pObPT->pqw[i];
        if(!(pte & 0x01)) { continue; }                 // not valid
        if(pte & 0x80) { continue; }                    // not valid ptr to PT
        if(fUserOnly && !(pte & 0x04)) { continue; }    // supervisor page when fUserOnly -> not valid
        fSpiderComplete = MmX86PAE_TlbSpider_PD_PT(pte & 0x0000fffffffff000, 1, fUserOnly, pTlbSpiderStage) && fSpiderComplete;
    }
    VmmOb_DECREF(pObPT);
    return fSpiderComplete;
}

BOOL MmX86PAE_TlbSpider_PDPT(_In_ QWORD paDTB, _In_ BOOL fUserOnly, PMMX86PAE_TLB_SPIDER_STAGE_INTERNAL pTlbSpiderStage)
{
    BOOL fSpiderComplete = TRUE;
    PVMMOB_MEM pObPDPT;
    PBYTE pbPDPT;
    QWORD i, pte;
    // 1: retrieve PDPT
    pObPDPT = VmmTlbGetPageTable(paDTB & 0xfffff000, FALSE);
    if(!pObPDPT) { return FALSE; }
    pbPDPT = pObPDPT->pb + (paDTB & 0xfe0);
    // 2: walk through all four (4) PDPTEs
    for(i = 0; i < 0x20; i += 8) {
        pte = *(PQWORD)(pbPDPT + i);
        if(!(pte & 0x01)) { continue; }             // not valid
        if(pte & 0xffff0000000001e6) { continue; }  // RESERVED BITS IN PDPTE
        fSpiderComplete = MmX86PAE_TlbSpider_PD_PT(pte & 0x0000fffffffff000, 2, fUserOnly, pTlbSpiderStage) && fSpiderComplete;
    }
    VmmOb_DECREF(pObPDPT);
    return fSpiderComplete;
}

/*
* Iterate over PTPT, PD (3 times in total) to first stage uncached pages
* and then commit them to the cache.
*/
VOID MmX86PAE_TlbSpider(_In_ PVMM_PROCESS pProcess)
{
    DWORD i = 0;
    BOOL result = FALSE;
    PMMX86PAE_TLB_SPIDER_STAGE_INTERNAL pTlbSpiderStage;
    if(pProcess->fTlbSpiderDone) { return; }
    if(!(pTlbSpiderStage = (PMMX86PAE_TLB_SPIDER_STAGE_INTERNAL)LocalAlloc(LMEM_ZEROINIT, sizeof(MMX86PAE_TLB_SPIDER_STAGE_INTERNAL)))) { return; }
    while(!result && (i < 3)) {
        result = MmX86PAE_TlbSpider_PDPT(pProcess->paDTB, pProcess->fUserOnly, pTlbSpiderStage);
        if(pTlbSpiderStage->c) {
            MmX86PAE_TlbSpider_ReadToCache(pTlbSpiderStage);
        }
        i++;
    }
    LocalFree(pTlbSpiderStage);
    pProcess->fTlbSpiderDone = TRUE;
}

const QWORD MMX86PAE_PAGETABLEMAP_PML_REGION_SIZE[4] = { 0, 12, 21, 30 };

VOID MmX86PAE_MapInitialize_Index(_In_ PVMM_PROCESS pProcess, _In_ PVMM_MEMMAP_ENTRY pMemMap, _In_ PDWORD pcMemMap, _In_ DWORD vaBase, _In_ BYTE iPML, _In_ QWORD PTEs[512], _In_ BOOL fSupervisorPML, _In_ QWORD paMax)
{
    PVMMOB_MEM pObNextPT;
    DWORD i, va;
    QWORD pte;
    BOOL fUserOnly, fNextSupervisorPML;
    PVMM_MEMMAP_ENTRY pMemMapEntry = pMemMap + *pcMemMap - 1;
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
                if((*pcMemMap == 0) ||
                    (pMemMapEntry->fPage != (pte & VMM_MEMMAP_PAGE_MASK)) ||
                    (va != pMemMapEntry->AddrBase + (pMemMapEntry->cPages << 12))) {
                    if(*pcMemMap + 1 >= VMM_MEMMAP_ENTRIES_MAX) { return; }
                    pMemMapEntry = pMemMap + *pcMemMap;
                    pMemMapEntry->AddrBase = va;
                    pMemMapEntry->fPage = pte & VMM_MEMMAP_PAGE_MASK;
                    pMemMapEntry->cPages = 1ULL << (MMX86PAE_PAGETABLEMAP_PML_REGION_SIZE[iPML] - 12);
                    *pcMemMap = *pcMemMap + 1;
                    if(*pcMemMap >= VMM_MEMMAP_ENTRIES_MAX - 1) { return; }
                    continue;
                }
                pMemMapEntry->cPages += 1ULL << (MMX86PAE_PAGETABLEMAP_PML_REGION_SIZE[iPML] - 12);
                continue;
            }
        }
        // maps page table (PD, PT)
        fNextSupervisorPML = (iPML != 3) && !(pte & 0x04);
        pObNextPT = VmmTlbGetPageTable(pte & 0x0000fffffffff000, FALSE);
        if(!pObNextPT) { continue; }
        MmX86PAE_MapInitialize_Index(pProcess, pMemMap, pcMemMap, va, iPML - 1, pObNextPT->pqw, fNextSupervisorPML, paMax);
        VmmOb_DECREF(pObNextPT);
        pMemMapEntry = pMemMap + *pcMemMap - 1;
    }
}

VOID MmX86PAE_MapCloseObCallback(_In_ PVOID pVmmOb)
{
    PVMMOB_MEMMAP pObMemMap = (PVMMOB_MEMMAP)pVmmOb;
    if(pObMemMap->pObDisplay) {
        VmmOb_DECREF(pObMemMap->pObDisplay);
    }
}

_Success_(return)
BOOL MmX86PAE_MapInitialize(_In_ PVMM_PROCESS pProcess)
{
    DWORD cMemMap = 0;
    PBYTE pbPDPT;
    PVMMOB_MEM pObPDPT;
    PVMM_MEMMAP_ENTRY pMemMap = NULL;
    PVMMOB_MEMMAP pObMemMap = NULL;
    // already existing?
    if(pProcess && pProcess->pObMemMap) {
        return pProcess->pObMemMap->fValid;
    }
    EnterCriticalSection(&pProcess->LockUpdate);
    if(pProcess && pProcess->pObMemMap) {
        LeaveCriticalSection(&pProcess->LockUpdate);
        return pProcess->pObMemMap->fValid;
    }
    // allocate temporary buffer and walk page tables
    VmmTlbSpider(pProcess);
    pObPDPT = VmmTlbGetPageTable(pProcess->paDTB & 0xfffff000, FALSE);
    if(pObPDPT) {
        pMemMap = (PVMM_MEMMAP_ENTRY)LocalAlloc(LMEM_ZEROINIT, VMM_MEMMAP_ENTRIES_MAX * sizeof(VMM_MEMMAP_ENTRY));
        if(pMemMap) {
            pbPDPT = pObPDPT->pb + (pProcess->paDTB & 0xfe0);     // ADJUST PDPT TO 32-BYTE BOUNDARY
            MmX86PAE_MapInitialize_Index(pProcess, pMemMap, &cMemMap, 0, 3, (PQWORD)pbPDPT, FALSE, ctxMain->dev.paMax);
        }
        VmmOb_DECREF(pObPDPT);
    }
    // allocate VmmOb depending on result
    pObMemMap = VmmOb_Alloc('MM', 0, sizeof(VMMOB_MEMMAP) + cMemMap * sizeof(VMM_MEMMAP_ENTRY), MmX86PAE_MapCloseObCallback, NULL);
    if(!pObMemMap) {
        LeaveCriticalSection(&pProcess->LockUpdate);
        LocalFree(pMemMap);
        return FALSE;
    }
    pObMemMap->fValid = cMemMap > 0;
    pObMemMap->fTagModules = FALSE;
    pObMemMap->fTagScan = FALSE;
    pObMemMap->cMap = cMemMap;
    pObMemMap->cbDisplay = cMemMap * MMX86PAE_MEMMAP_DISPLAYBUFFER_LINE_LENGTH;
    pObMemMap->pObDisplay = NULL;
    if(cMemMap > 0) {
        memcpy(pObMemMap->pMap, pMemMap, cMemMap * sizeof(VMM_MEMMAP_ENTRY));
    }
    LocalFree(pMemMap);
    pProcess->pObMemMap = pObMemMap;
    LeaveCriticalSection(&pProcess->LockUpdate);
    return pObMemMap->fValid;
}

/*
* Map a tag into the sorted memory map in O(log2) operations. Supply only one of szTag or wszTag.
* -- pProcess
* -- vaBase
* -- vaLimit = limit == vaBase + size (== top address in range +1)
* -- szTag
* -- wszTag
* -- fWoW64
* -- fOverwrite
*/
VOID MmX86PAE_MapTag(_In_ PVMM_PROCESS pProcess, _In_ QWORD vaBase, _In_ QWORD vaLimit, _In_opt_ LPSTR szTag, _In_opt_ LPWSTR wszTag, _In_ BOOL fWoW64, _In_ BOOL fOverwrite)
{
    // NB! update here may take placey without acquiring the process 'LockUpdate'
    // Data is not super important so it should be ok. Also, in many cases the
    // lock will already be acquired by MapGetEntries function.
    PVMM_MEMMAP_ENTRY pMap;
    QWORD i, lvl, cMap;
    if(!MmX86PAE_MapInitialize(pProcess)) { return; }
    if((vaBase > 0xffffffff) || (vaLimit > 0xffffffff)) { return; }
    pMap = pProcess->pObMemMap->pMap;
    cMap = pProcess->pObMemMap->cMap;
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
        if((pMap[i].AddrBase >= vaBase) && (fOverwrite || !pMap[i].szTag[0])) {
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

_Success_(return)
BOOL MmX86PAE_MapGetEntries(_In_ PVMM_PROCESS pProcess, _In_ DWORD flags, _Out_ PVMMOB_MEMMAP *ppObMemMap)
{
    DWORD i;
    PVMM_MODULEMAP_ENTRY pModule;
    PVMMOB_MODULEMAP pObModuleMap;
    if(!MmX86PAE_MapInitialize(pProcess)) { return FALSE; }
    if((!pProcess->pObMemMap->fTagModules && (flags & VMM_MEMMAP_FLAG_MODULES)) || (!pProcess->pObMemMap->fTagScan && (flags & VMM_MEMMAP_FLAG_SCAN))) {
        EnterCriticalSection(&pProcess->LockUpdate);
        if(!pProcess->pObMemMap->fTagModules && (flags & VMM_MEMMAP_FLAG_MODULES)) {
            pProcess->pObMemMap->fTagModules = TRUE;
            if(VmmProc_ModuleMapGet(pProcess, &pObModuleMap)) {
                // update memory map with names
                for(i = 0; i < pObModuleMap->cMap; i++) {
                    pModule = pObModuleMap->pMap + i;
                    MmX86PAE_MapTag(pProcess, pModule->BaseAddress, pModule->BaseAddress + pModule->SizeOfImage, pModule->szName, NULL, FALSE, FALSE);
                }
                VmmOb_DECREF(pObModuleMap);
            }
        }
        if(!pProcess->pObMemMap->fTagScan && (flags & VMM_MEMMAP_FLAG_SCAN)) {
            pProcess->pObMemMap->fTagScan = TRUE;
            VmmProc_ScanTagsMemMap(pProcess);
        }
        LeaveCriticalSection(&pProcess->LockUpdate);
    }
    *ppObMemMap = VmmOb_INCREF(pProcess->pObMemMap);
    return TRUE;
}

_Success_(return)
BOOL MmX86PAE_MapGetDisplay(_In_ PVMM_PROCESS pProcess, _In_ DWORD flags, _Out_ PVMMOB_PDATA *ppObDisplay)
{
    DWORD i, o = 0;
    PVMMOB_MEMMAP pObMemMap = NULL;
    PVMMOB_PDATA pObDisplay = NULL;
    // memory map display data already exists
    if(!MmX86PAE_MapInitialize(pProcess)) { return FALSE; }
    if(pProcess->pObMemMap->pObDisplay) {
        *ppObDisplay = VmmOb_INCREF(pProcess->pObMemMap->pObDisplay);
        return TRUE;
    }
    // create new memory map display data
    EnterCriticalSection(&pProcess->LockUpdate);
    if(!pProcess->pObMemMap->pObDisplay) {
        if(MmX86PAE_MapGetEntries(pProcess, flags, &pObMemMap)) {
            pObDisplay = VmmOb_Alloc('MD', LMEM_ZEROINIT, pObMemMap->cbDisplay, NULL, NULL);
            if(pObDisplay) {
                for(i = 0; i < pObMemMap->cMap; i++) {
                    if(o + MMX86PAE_MEMMAP_DISPLAYBUFFER_LINE_LENGTH > pObMemMap->cbDisplay) {
                        vmmprintf_fn("ERROR: SHOULD NOT HAPPEN! LENGTH DIFFERS #1: %i %i\n", o + MMX86PAE_MEMMAP_DISPLAYBUFFER_LINE_LENGTH, pObMemMap->cbDisplay);
                        VmmOb_DECREF(pObDisplay);
                        pObDisplay = NULL;
                        goto fail;
                    }
                    o += snprintf(
                        pObDisplay->pbData + o,
                        pObMemMap->cbDisplay - o,
                        "%04x %8x %08x-%08x %sr%s%s %-32s\n",
                        i,
                        (DWORD)pObMemMap->pMap[i].cPages,
                        (DWORD)pObMemMap->pMap[i].AddrBase,
                        (DWORD)(pObMemMap->pMap[i].AddrBase + (pObMemMap->pMap[i].cPages << 12) - 1),
                        pObMemMap->pMap[i].fPage & VMM_MEMMAP_PAGE_NS ? "-" : "s",
                        pObMemMap->pMap[i].fPage & VMM_MEMMAP_PAGE_W ? "w" : "-",
                        pObMemMap->pMap[i].fPage & VMM_MEMMAP_PAGE_NX ? "-" : "x",
                        pObMemMap->pMap[i].szTag
                    );
                }
                if(o != pObMemMap->cbDisplay) {
                    vmmprintf_fn("ERROR: SHOULD NOT HAPPEN! LENGTH DIFFERS #2: %i %i\n", o, pObMemMap->cbDisplay);
                    VmmOb_DECREF(pObDisplay);
                    pObDisplay = NULL;
                    goto fail;
                }
                pObDisplay->pbData[o - 1] = '\n';
            }
        }
        pProcess->pObMemMap->pObDisplay = pObDisplay;
    }
fail:
    VmmOb_DECREF(pObMemMap);
    LeaveCriticalSection(&pProcess->LockUpdate);
    if(pProcess->pObMemMap->pObDisplay) {
        *ppObDisplay = VmmOb_INCREF(pProcess->pObMemMap->pObDisplay);
        return TRUE;
    }
    return FALSE;
}

_Success_(return)
BOOL MmX86PAE_Virt2Phys(_In_ QWORD paPT, _In_ BOOL fUserOnly, _In_ BYTE iPML, _In_ QWORD va, _Out_ PQWORD ppa)
{
    PBYTE pbPTEs;
    QWORD pte, i, qwMask;
    PVMMOB_MEM pObPTEs;
    if(va > 0xffffffff) { return FALSE; }
    if(iPML == (BYTE)-1) { iPML = 3; }
    pObPTEs = VmmTlbGetPageTable(paPT & 0x0000fffffffff000, FALSE);
    if(!pObPTEs) { return FALSE; }
    i = 0x1ff & (va >> MMX86PAE_PAGETABLEMAP_PML_REGION_SIZE[iPML]);
    if(iPML == 3) {
        // PDPT
        if(i > 3) {                                     // MAX 4 ENTRIES IN PDPT
            VmmOb_DECREF(pObPTEs);
            return FALSE;
        }                     
        pbPTEs = pObPTEs->pb + (paPT & 0xfe0);          // ADJUST PDPT TO 32-BYTE BOUNDARY
        pte = ((PQWORD)pbPTEs)[i];
        VmmOb_DECREF(pObPTEs);
        if(!(pte & 0x01)) { return FALSE; }             // NOT VALID
        if(pte & 0xffff0000000001e6) { return FALSE; }  // RESERVED BITS IN PDPTE
        return MmX86PAE_Virt2Phys(pte, fUserOnly, 2, va, ppa);
    }
    // PT or PD
    pte = pObPTEs->pqw[i];
    VmmOb_DECREF(pObPTEs);
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
    PVMMOB_MEM pObNextPT;
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
    pObNextPT = VmmTlbGetPageTable(pte & 0x0000fffffffff000, FALSE);
    if(!pObNextPT) { return; }
    pVirt2PhysInfo->pas[iPML - 1] = pte & 0x0000fffffffff000;
    MmX86PAE_Virt2PhysGetInformation_DoWork(pProcess, pVirt2PhysInfo, iPML - 1, pObNextPT->pqw);
    VmmOb_DECREF(pObNextPT);
}

VOID MmX86PAE_Virt2PhysGetInformation(_Inout_ PVMM_PROCESS pProcess, _Inout_ PVMM_VIRT2PHYS_INFORMATION pVirt2PhysInfo)
{
    QWORD va;
    PVMMOB_MEM pObPML4;
    if(pVirt2PhysInfo->va > 0xffffffff) { return; }
    va = pVirt2PhysInfo->va;
    ZeroMemory(pVirt2PhysInfo, sizeof(VMM_VIRT2PHYS_INFORMATION));
    pVirt2PhysInfo->tpMemoryModel = VMM_MEMORYMODEL_X86PAE;
    pVirt2PhysInfo->va = va;
    pVirt2PhysInfo->pas[3] = pProcess->paDTB;
    pObPML4 = VmmTlbGetPageTable(pProcess->paDTB & 0xfffff000, FALSE);
    if(!pObPML4) { return; }
    MmX86PAE_Virt2PhysGetInformation_DoWork(pProcess, pVirt2PhysInfo, 3, (PQWORD)(pObPML4->pb + (pProcess->paDTB & 0xfe0)));
    VmmOb_DECREF(pObPML4);
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
    ctxVmm->fnMemoryModel.pfnClose = MmX86PAE_Close;
    ctxVmm->fnMemoryModel.pfnVirt2Phys = MmX86PAE_Virt2Phys;
    ctxVmm->fnMemoryModel.pfnVirt2PhysGetInformation = MmX86PAE_Virt2PhysGetInformation;
    ctxVmm->fnMemoryModel.pfnMapInitialize = MmX86PAE_MapInitialize;
    ctxVmm->fnMemoryModel.pfnMapTag = MmX86PAE_MapTag;
    ctxVmm->fnMemoryModel.pfnMapGetEntries = MmX86PAE_MapGetEntries;
    ctxVmm->fnMemoryModel.pfnMapGetDisplay = MmX86PAE_MapGetDisplay;
    ctxVmm->fnMemoryModel.pfnTlbSpider = MmX86PAE_TlbSpider;
    ctxVmm->fnMemoryModel.pfnTlbPageTableVerify = MmX86PAE_TlbPageTableVerify;
    ctxVmm->tpMemoryModel = VMM_MEMORYMODEL_X86PAE;
    ctxVmm->f32 = TRUE;
}
