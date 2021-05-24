// mm_x64.c : implementation of the x64 / IA32e / long-mode paging / memory model.
//
// (c) Ulf Frisk, 2018-2021
// Author: Ulf Frisk, pcileech@frizk.net
//
#include "vmm.h"
#include "vmmproc.h"

#define MMX64_MEMMAP_DISPLAYBUFFER_LINE_LENGTH      89
#define MMX64_PTE_IS_TRANSITION(pte, iPML)          ((((pte & 0x0c01) == 0x0800) && (iPML == 1) && ctxVmm && (ctxVmm->tpSystem == VMM_SYSTEM_WINDOWS_X64)) ? ((pte & 0xffffdffffffff000) | 0x005) : 0)
#define MMX64_PTE_IS_VALID(pte, iPML)               (pte & 0x01)

/*
* Tries to verify that a loaded page table is correct. If just a bit strange
* bytes/ptes supplied in pb will be altered to look better.
*/
BOOL MmX64_TlbPageTableVerify(_Inout_ PBYTE pb, _In_ QWORD pa, _In_ BOOL fSelfRefReq)
{
    DWORD i;
    QWORD *ptes, c = 0, pte, paMax;
    BOOL fSelfRef = FALSE;
    if(!pb) { return FALSE; }
    ptes = (PQWORD)pb;
    paMax = max(0xffffffff, ctxMain->dev.paMax);
    for(i = 0; i < 512; i++) {
        pte = *(ptes + i);
        if((pte & 0x01) && ((0x000fffffffffffff & pte) > paMax)) {
            // A bad PTE, or memory allocated above the physical address max
            // limit. This may be just trash in the page table in which case
            // we clear this faulty entry. If too may bad PTEs are found this
            // is most probably not a page table - zero it out but let it
            // remain in cache to prevent performance degrading reloads...
            vmmprintfvv_fn("VMM: BAD PTE %016llx at PA: %016llx i: %i\n", *(ptes + i), pa, i);
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
            vmmprintfvv_fn("VMM: BAD PT PAGE at PA: %016llx\n", pa);
        }
        ZeroMemory(pb, 4096);
        return FALSE;
    }
    return TRUE;
}

VOID MmX64_TlbSpider_Stage(_In_ QWORD pa, _In_ BYTE iPML, _In_ BOOL fUserOnly, _In_ POB_SET pPageSet)
{
    QWORD i, pe;
    PVMMOB_CACHE_MEM ptObMEM = NULL;
    // 1: retrieve from cache, add to staging if not found
    ptObMEM = VmmCacheGet(VMM_CACHE_TAG_TLB, pa);
    if(!ptObMEM) {
        ObSet_Push(pPageSet, pa);
        return;
    }
    if(iPML == 1) {
        Ob_DECREF(ptObMEM);
        return;
    }
    // 2: walk trough all entries for PML4, PDPT, PD
    for(i = 0; i < 512; i++) {
        pe = ptObMEM->pqw[i];
        if(!(pe & 0x01)) { continue; }  // not valid
        if(pe & 0x80) { continue; }     // not valid ptr to (PDPT || PD || PT)
        if(fUserOnly && !(pe & 0x04)) { continue; } // supervisor page when fUserOnly -> not valid
        MmX64_TlbSpider_Stage(pe & 0x0000fffffffff000, iPML - 1, fUserOnly, pPageSet);
    }
    Ob_DECREF(ptObMEM);
}

/*
* Iterate over PML4, PTPT, PD (3 times in total) to first stage uncached pages
* and then commit them to the cache.
*/
VOID MmX64_TlbSpider(_In_ PVMM_PROCESS pProcess)
{
    DWORD i;
    POB_SET pObPageSet = NULL;
    if(pProcess->fTlbSpiderDone) { return; }
    if(!(pObPageSet = ObSet_New())) { return; }
    Ob_DECREF(VmmTlbGetPageTable(pProcess->paDTB, FALSE));
    for(i = 0; i < 3; i++) {
        MmX64_TlbSpider_Stage(pProcess->paDTB, 4, pProcess->fUserOnly, pObPageSet);
        VmmTlbPrefetch(pObPageSet);
    }
    pProcess->fTlbSpiderDone = TRUE;
    Ob_DECREF(pObPageSet);
}

const QWORD MMX64_PAGETABLEMAP_PML_REGION_SIZE[5] = { 0, 12, 21, 30, 39 };
const QWORD MMX64_PAGETABLEMAP_PML_REGION_MASK_PG[5] = { 0, 0x0000fffffffff000, 0x0000ffffffe00000, 0x0000ffffc0000000, 0 };
const QWORD MMX64_PAGETABLEMAP_PML_REGION_MASK_AD[5] = { 0, 0xfff, 0x1fffff, 0x3fffffff, 0 };

VOID MmX64_MapInitialize_Index(_In_ PVMM_PROCESS pProcess, _In_ PVMM_MAP_PTEENTRY pMemMap, _In_ PDWORD pcMemMap, _In_ QWORD vaBase, _In_ BYTE iPML, _In_ QWORD PTEs[512], _In_ BOOL fSupervisorPML, _In_ QWORD paMax)
{
    PVMMOB_CACHE_MEM pObNextPT;
    QWORD i, pte, va, cPages;
    BOOL fUserOnly, fNextSupervisorPML, fPagedOut = FALSE;
    PVMM_MAP_PTEENTRY pMemMapEntry = pMemMap + *pcMemMap - 1;
    if(!pProcess->fTlbSpiderDone) {
        VmmTlbSpider(pProcess);
    }
    fUserOnly = pProcess->fUserOnly;
    for(i = 0; i < 512; i++) {
        pte = PTEs[i];
        if(!MMX64_PTE_IS_VALID(pte, iPML)) {
            if(!pte) { continue; }
            if(iPML != 1) { continue; }
            pte = MMX64_PTE_IS_TRANSITION(pte, iPML);
            pte = 0x8000000000000005 | (pte ? (pte & 0x8000fffffffff000 ) : 0); // GUESS READ-ONLY USER PAGE IF NON TRANSITION
            fPagedOut = TRUE;
        } else {
            fPagedOut = FALSE;
        }
        if((pte & 0x0000fffffffff000) > paMax) { continue; }
        if(fSupervisorPML) { pte = pte & 0xfffffffffffffffb; }
        if(fUserOnly && !(pte & 0x04)) { continue; }
        va = vaBase + (i << MMX64_PAGETABLEMAP_PML_REGION_SIZE[iPML]);
        // maps page
        if((iPML == 1) || (pte & 0x80) /* PS */) {
            if(iPML == 4) { continue; } // not supported - PML4 cannot map page directly
            if((*pcMemMap == 0) ||
                ((pMemMapEntry->fPage != (pte & VMM_MEMMAP_PAGE_MASK)) && !fPagedOut) ||
                (va != pMemMapEntry->vaBase + (pMemMapEntry->cPages << 12))) {
                if(*pcMemMap + 1 >= VMM_MEMMAP_ENTRIES_MAX) { return; }
                pMemMapEntry = pMemMap + *pcMemMap;
                pMemMapEntry->vaBase = va;
                pMemMapEntry->fPage = pte & VMM_MEMMAP_PAGE_MASK;
                cPages = 1ULL << (MMX64_PAGETABLEMAP_PML_REGION_SIZE[iPML] - 12);
                if(fPagedOut) { pMemMapEntry->cSoftware += (DWORD)cPages; }
                pMemMapEntry->cPages = cPages;
                *pcMemMap = *pcMemMap + 1;
                if(*pcMemMap >= VMM_MEMMAP_ENTRIES_MAX - 1) {
                    return;
                }
                continue;
            }
            cPages = 1ULL << (MMX64_PAGETABLEMAP_PML_REGION_SIZE[iPML] - 12);
            if(fPagedOut) { pMemMapEntry->cSoftware += (DWORD)cPages; }
            pMemMapEntry->cPages += cPages;
            continue;
        }
        // optimization - same PT in multiple consecutive PDe
        if((iPML == 2) && i && (pte == PTEs[i - 1]) && (pMemMapEntry->cPages >= 512) && (va == pMemMapEntry->vaBase + (pMemMapEntry->cPages << 12))) {
            pMemMapEntry->cPages += 1ULL << (MMX64_PAGETABLEMAP_PML_REGION_SIZE[iPML] - 12);
            continue;
        }
        // maps page table (PDPT, PD, PT)
        fNextSupervisorPML = !(pte & 0x04);
        pObNextPT = VmmTlbGetPageTable(pte & 0x0000fffffffff000, FALSE);
        if(!pObNextPT) { continue; }
        MmX64_MapInitialize_Index(pProcess, pMemMap, pcMemMap, va, iPML - 1, pObNextPT->pqw, fNextSupervisorPML, paMax);
        Ob_DECREF(pObNextPT);
        pMemMapEntry = pMemMap + *pcMemMap - 1;
    }
}

VOID MmX64_CallbackCleanup_ObPteMap(PVMMOB_MAP_PTE pOb)
{
    LocalFree(pOb->pbMultiText);
}

_Success_(return)
BOOL MmX64_PteMapInitialize(_In_ PVMM_PROCESS pProcess)
{
    QWORD i;
    DWORD cMemMap = 0;
    PVMMOB_CACHE_MEM pObPML4;
    PVMM_MAP_PTEENTRY pMemMap = NULL;
    PVMMOB_MAP_PTE pObMap = NULL;
    // already existing?
    if(pProcess->Map.pObPte) { return TRUE; }
    EnterCriticalSection(&pProcess->LockUpdate);
    if(pProcess->Map.pObPte) {
        LeaveCriticalSection(&pProcess->LockUpdate);
        return TRUE;
    }
    // allocate temporary buffer and walk page tables
    pObPML4 = VmmTlbGetPageTable(pProcess->paDTB, FALSE);
    if(pObPML4) {
        pMemMap = (PVMM_MAP_PTEENTRY)LocalAlloc(LMEM_ZEROINIT, VMM_MEMMAP_ENTRIES_MAX * sizeof(VMM_MAP_PTEENTRY));
        if(pMemMap) {
            MmX64_MapInitialize_Index(pProcess, pMemMap, &cMemMap, 0, 4, pObPML4->pqw, FALSE, ctxMain->dev.paMax);
            for(i = 0; i < cMemMap; i++) { // fixup sign extension for kernel addresses
                if(pMemMap[i].vaBase & 0x0000800000000000) {
                    pMemMap[i].vaBase |= 0xffff000000000000;
                }
            }
        }
        Ob_DECREF(pObPML4);
    }
    // allocate VmmOb depending on result
    pObMap = Ob_Alloc(OB_TAG_MAP_PTE, 0, sizeof(VMMOB_MAP_PTE) + cMemMap * sizeof(VMM_MAP_PTEENTRY), (OB_CLEANUP_CB)MmX64_CallbackCleanup_ObPteMap, NULL);
    if(!pObMap) {
        pProcess->Map.pObPte = Ob_Alloc(OB_TAG_MAP_PTE, LMEM_ZEROINIT, sizeof(VMMOB_MAP_PTE), NULL, NULL);
        LeaveCriticalSection(&pProcess->LockUpdate);
        LocalFree(pMemMap);
        return TRUE;
    }
    pObMap->pbMultiText = NULL;
    pObMap->cbMultiText = 0;
    pObMap->fTagScan = FALSE;
    pObMap->cMap = cMemMap;
    memcpy(pObMap->pMap, pMemMap, cMemMap * sizeof(VMM_MAP_PTEENTRY));
    LocalFree(pMemMap);
    pProcess->Map.pObPte = pObMap;
    LeaveCriticalSection(&pProcess->LockUpdate);
    return TRUE;
}

_Success_(return)
BOOL MmX64_Virt2Phys(_In_ QWORD paPT, _In_ BOOL fUserOnly, _In_ BYTE iPML, _In_ QWORD va, _Out_ PQWORD ppa)
{
    QWORD pte, i, qwMask;
    PVMMOB_CACHE_MEM pObPTEs;
    if(iPML == (BYTE)-1) { iPML = 4; }
    pObPTEs = VmmTlbGetPageTable(paPT & 0x0000fffffffff000, FALSE);
    if(!pObPTEs) { return FALSE; }
    i = 0x1ff & (va >> MMX64_PAGETABLEMAP_PML_REGION_SIZE[iPML]);
    pte = pObPTEs->pqw[i];
    Ob_DECREF(pObPTEs);
    if(!MMX64_PTE_IS_VALID(pte, iPML)) {
        if(iPML == 1) { *ppa = pte; }                       // NOT VALID
        return FALSE;
    }
    if(fUserOnly && !(pte & 0x04)) { return FALSE; }        // SUPERVISOR PAGE & USER MODE REQ
    if(pte & 0x000f000000000000) { return FALSE; }          // RESERVED
    if((iPML == 1) || (pte & 0x80) /* PS */) {
        if(iPML == 4) { return FALSE; }                     // NO SUPPORT IN PML4
        qwMask = 0xffffffffffffffff << MMX64_PAGETABLEMAP_PML_REGION_SIZE[iPML];
        *ppa = pte & 0x0000fffffffff000 & qwMask;           // MASK AWAY BITS FOR 4kB/2MB/1GB PAGES
        qwMask = qwMask ^ 0xffffffffffffffff;
        *ppa = *ppa | (qwMask & va);                        // FILL LOWER ADDRESS BITS
        return TRUE;
    }
    return MmX64_Virt2Phys(pte, fUserOnly, iPML - 1, va, ppa);
}

VOID MmX64_Virt2PhysVadEx(_In_ QWORD paPT, _Inout_ PVMMOB_MAP_VADEX pVadEx, _In_ BYTE iPML, _Inout_ PDWORD piVadEx)
{
    QWORD pa, pte, iPte, iVadEx, qwMask;
    PVMMOB_CACHE_MEM pObPTEs = NULL;
    if(iPML == (BYTE)-1) { iPML = 4; }
    if(!(pObPTEs = VmmTlbGetPageTable(paPT & 0x0000fffffffff000, FALSE))) {
        *piVadEx = *piVadEx + 1;
        return;
    }
next_entry:
    iVadEx = *piVadEx;
    iPte = 0x1ff & (pVadEx->pMap[iVadEx].va >> MMX64_PAGETABLEMAP_PML_REGION_SIZE[iPML]);
    pte = pObPTEs->pqw[iPte];
    if(!MMX64_PTE_IS_VALID(pte, iPML)) { goto next_check; } // NOT VALID
    if(!(pte & 0x04)) { goto next_check; }                  // SUPERVISOR PAGE & USER MODE REQ
    if(pte & 0x000f000000000000) { goto next_check; }       // RESERVED
    if((iPML == 1) || (pte & 0x80) /* PS */) {
        if(iPML == 4) { goto next_check; }                  // NO SUPPORT IN PML4
        qwMask = 0xffffffffffffffff << MMX64_PAGETABLEMAP_PML_REGION_SIZE[iPML];
        pa = pte & 0x0000fffffffff000 & qwMask;             // MASK AWAY BITS FOR 4kB/2MB/1GB PAGES
        qwMask = qwMask ^ 0xffffffffffffffff;
        pVadEx->pMap[iVadEx].pa = pa | (qwMask & pVadEx->pMap[iVadEx].va);  // FILL LOWER ADDRESS BITS
        pVadEx->pMap[iVadEx].tp = VMM_PTE_TP_HARDWARE;
        goto next_check;
    }    
    MmX64_Virt2PhysVadEx(pte, pVadEx, iPML - 1, piVadEx);
    Ob_DECREF(pObPTEs);
    return;
next_check:
    pVadEx->pMap[iVadEx].pte = pte;
    pVadEx->pMap[iVadEx].iPML = iPML;
    *piVadEx = *piVadEx + 1;
    if((iPML == 1) && (iPte < 0x1ff) && (iVadEx + 1 < pVadEx->cMap) && (pVadEx->pMap[iVadEx].va + 0x1000 == pVadEx->pMap[iVadEx + 1].va)) { goto next_entry; }
    Ob_DECREF(pObPTEs);
}

VOID MmX64_Virt2PhysGetInformation_DoWork(_Inout_ PVMM_PROCESS pProcess, _Inout_ PVMM_VIRT2PHYS_INFORMATION pVirt2PhysInfo, _In_ BYTE iPML, _In_ QWORD PTEs[512])
{
    QWORD pte, i, qwMask;
    PVMMOB_CACHE_MEM pObNextPT;
    i = 0x1ff & (pVirt2PhysInfo->va >> MMX64_PAGETABLEMAP_PML_REGION_SIZE[iPML]);
    pte = PTEs[i];
    pVirt2PhysInfo->iPTEs[iPML] = (WORD)i;
    pVirt2PhysInfo->PTEs[iPML] = pte;
    if(!MMX64_PTE_IS_VALID(pte, iPML)) { return; }          // NOT VALID
    if(pProcess->fUserOnly && !(pte & 0x04)) { return; }    // SUPERVISOR PAGE & USER MODE REQ
    if(pte & 0x000f000000000000) { return; }                // RESERVED
    if((iPML == 1) || (pte & 0x80) /* PS */) {
        if(iPML == 4) { return; }                           // NO SUPPORT IN PML4
        qwMask = 0xffffffffffffffff << MMX64_PAGETABLEMAP_PML_REGION_SIZE[iPML];
        pVirt2PhysInfo->pas[0] = pte & 0x0000fffffffff000 & qwMask;     // MASK AWAY BITS FOR 4kB/2MB/1GB PAGES
        qwMask = qwMask ^ 0xffffffffffffffff;
        pVirt2PhysInfo->pas[0] = pVirt2PhysInfo->pas[0] | (qwMask & pVirt2PhysInfo->va);    // FILL LOWER ADDRESS BITS
        return;
    }
    pObNextPT = VmmTlbGetPageTable(pte & 0x0000fffffffff000, FALSE);
    if(!pObNextPT) { return; }
    pVirt2PhysInfo->pas[iPML - 1] = pte & 0x0000fffffffff000;
    MmX64_Virt2PhysGetInformation_DoWork(pProcess, pVirt2PhysInfo, iPML - 1, pObNextPT->pqw);
    Ob_DECREF(pObNextPT);
}

VOID MmX64_Virt2PhysGetInformation(_Inout_ PVMM_PROCESS pProcess, _Inout_ PVMM_VIRT2PHYS_INFORMATION pVirt2PhysInfo)
{
    QWORD va;
    PVMMOB_CACHE_MEM pObPML4;
    va = pVirt2PhysInfo->va;
    ZeroMemory(pVirt2PhysInfo, sizeof(VMM_VIRT2PHYS_INFORMATION));
    pVirt2PhysInfo->tpMemoryModel = VMM_MEMORYMODEL_X64;
    pVirt2PhysInfo->va = va;
    pVirt2PhysInfo->pas[4] = pProcess->paDTB;
    pObPML4 = VmmTlbGetPageTable(pProcess->paDTB, FALSE);
    if(!pObPML4) { return; }
    MmX64_Virt2PhysGetInformation_DoWork(pProcess, pVirt2PhysInfo, 4, pObPML4->pqw);
    Ob_DECREF(pObPML4);
}

VOID MmX64_Phys2VirtGetInformation_Index(_In_ PVMM_PROCESS pProcess, _In_ QWORD vaBase, _In_ BYTE iPML, _In_ QWORD PTEs[512], _In_ QWORD paMax, _Inout_ PVMMOB_PHYS2VIRT_INFORMATION pP2V)
{
    BOOL fUserOnly;
    QWORD i, pte, va;
    PVMMOB_CACHE_MEM pObNextPT;
    if(!pProcess->fTlbSpiderDone) {
        VmmTlbSpider(pProcess);
    }
    fUserOnly = pProcess->fUserOnly;
    for(i = 0; i < 512; i++) {
        pte = PTEs[i];
        if(!MMX64_PTE_IS_VALID(pte, iPML)) { continue; }
        if((pte & 0x0000fffffffff000) > paMax) { continue; }
        if(fUserOnly && !(pte & 0x04)) { continue; }
        // maps page
        if((iPML == 1) || (pte & 0x80) /* PS */) {
            if(iPML == 4) { continue; } // not supported - PML4 cannot map page directly
            if((pte & MMX64_PAGETABLEMAP_PML_REGION_MASK_PG[iPML]) == (pP2V->paTarget & MMX64_PAGETABLEMAP_PML_REGION_MASK_PG[iPML])) {
                va = vaBase + (i << MMX64_PAGETABLEMAP_PML_REGION_SIZE[iPML]);
                pP2V->pvaList[pP2V->cvaList] = va | ((va >> 47) ? 0xffff000000000000 : 0) | (pP2V->paTarget & MMX64_PAGETABLEMAP_PML_REGION_MASK_AD[iPML]);
                pP2V->cvaList++;
                if(pP2V->cvaList == VMM_PHYS2VIRT_INFORMATION_MAX_PROCESS_RESULT) { return; }
            }
            continue;
        }
        // maps page table (PDPT, PD, PT)
        if(fUserOnly && !(pte & 0x04)) { continue; }    // do not go into supervisor pages if user-only adderss space
        pObNextPT = VmmTlbGetPageTable(pte & 0x0000fffffffff000, FALSE);
        if(!pObNextPT) { continue; }
        va = vaBase + (i << MMX64_PAGETABLEMAP_PML_REGION_SIZE[iPML]);
        MmX64_Phys2VirtGetInformation_Index(pProcess, va, iPML - 1, pObNextPT->pqw, paMax, pP2V);
        Ob_DECREF(pObNextPT);
        if(pP2V->cvaList == VMM_PHYS2VIRT_INFORMATION_MAX_PROCESS_RESULT) { return; }
    }
}

VOID MmX64_Phys2VirtGetInformation(_In_ PVMM_PROCESS pProcess, _Inout_ PVMMOB_PHYS2VIRT_INFORMATION pP2V)
{
    PVMMOB_CACHE_MEM pObPML4;
    if((pP2V->cvaList == VMM_PHYS2VIRT_INFORMATION_MAX_PROCESS_RESULT) || (pP2V->paTarget > ctxMain->dev.paMax)) { return; }
    pObPML4 = VmmTlbGetPageTable(pProcess->paDTB, FALSE);
    if(!pObPML4) { return; }
    MmX64_Phys2VirtGetInformation_Index(pProcess, 0, 4, pObPML4->pqw, ctxMain->dev.paMax, pP2V);
    Ob_DECREF(pObPML4);
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
    ctxVmm->fnMemoryModel.pfnClose = MmX64_Close;
    ctxVmm->fnMemoryModel.pfnVirt2Phys = MmX64_Virt2Phys;
    ctxVmm->fnMemoryModel.pfnVirt2PhysVadEx = MmX64_Virt2PhysVadEx;
    ctxVmm->fnMemoryModel.pfnVirt2PhysGetInformation = MmX64_Virt2PhysGetInformation;
    ctxVmm->fnMemoryModel.pfnPhys2VirtGetInformation = MmX64_Phys2VirtGetInformation;
    ctxVmm->fnMemoryModel.pfnPteMapInitialize = MmX64_PteMapInitialize;
    ctxVmm->fnMemoryModel.pfnTlbSpider = MmX64_TlbSpider;
    ctxVmm->fnMemoryModel.pfnTlbPageTableVerify = MmX64_TlbPageTableVerify;
    ctxVmm->tpMemoryModel = VMM_MEMORYMODEL_X64;
    ctxVmm->f32 = FALSE;
}
