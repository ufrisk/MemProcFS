// mm_x64.c : implementation of the x64 / IA32e / long-mode paging / memory model.
//
// (c) Ulf Frisk, 2018-2025
// Author: Ulf Frisk, pcileech@frizk.net
//

#include "mm.h"

#define MMX64_MEMMAP_DISPLAYBUFFER_LINE_LENGTH      89
#define MMX64_PTE_IS_TRANSITION(H, pte, iPML)       ((((pte & 0x0c01) == 0x0800) && (iPML == 1)) ? ((pte & 0xffffdffffffff000) | 0x005) : 0)
#define MMX64_PTE_IS_VALID(pte, iPML)               (pte & 0x01)

/*
* Tries to verify that a loaded page table is correct. If just a bit strange
* bytes/ptes supplied in pb will be altered to look better.
*/
BOOL MmX64_TlbPageTableVerify(_In_ VMM_HANDLE H, _Inout_ PBYTE pb, _In_ QWORD pa, _In_ BOOL fSelfRefReq)
{
    DWORD i, cBad = 0;
    QWORD *ptes, pte, paMax;
    BOOL fSelfRef = FALSE;
    if(!pb) { return FALSE; }
    ptes = (PQWORD)pb;
    paMax = max(0xffffffff, H->dev.paMax);
    for(i = 0; i < 512; i++) {
        pte = *(ptes + i);
        if((pte & 0x01) && ((0x0000ffffffffffff & pte) > paMax)) {
            // A bad PTE, or memory allocated above the physical address max
            // limit. This may be just trash in the page table in which case
            // we clear this faulty entry. If too may bad PTEs are found this
            // is most probably not a page table - zero it out but let it
            // remain in cache to prevent performance degrading reloads...
            *(ptes + i) = (QWORD)0;
            // avoid counting some special cases which may have plenty of entries.
            if(((pte & 0x80ffff000000000f) == 0x800000000000000f)) { continue; }
            // count as a bad page - if over threshold -> abort!
            cBad++;
            if(cBad > H->cfg.dwPteQualityThreshold) { break; }
        }
        if(fSelfRefReq && (pa == (0x0000fffffffff000 & pte))) {
            fSelfRef = TRUE;
        }
    }
    if((cBad > H->cfg.dwPteQualityThreshold) || (fSelfRefReq && !fSelfRef)) {
        ZeroMemory(pb, 4096);
        return FALSE;
    }
    return TRUE;
}

VOID MmX64_TlbSpider_Stage(_In_ VMM_HANDLE H, _In_ QWORD pa, _In_ BYTE iPML, _In_ BOOL fUserOnly, _In_ POB_SET pPageSet)
{
    QWORD i, pe;
    PVMMOB_CACHE_MEM ptObMEM = NULL;
    // 1: retrieve from cache, add to staging if not found
    ptObMEM = VmmCacheGet(H, VMM_CACHE_TAG_TLB, pa);
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
        MmX64_TlbSpider_Stage(H, pe & 0x0000fffffffff000, iPML - 1, fUserOnly, pPageSet);
    }
    Ob_DECREF(ptObMEM);
}

/*
* Iterate over PML4, PTPT, PD (3 times in total) to first stage uncached pages
* and then commit them to the cache.
* -- H
* -- pProcess
*/
VOID MmX64_TlbSpider(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess)
{
    DWORD i;
    POB_SET pObPageSet = NULL;
    if(pProcess->fTlbSpiderDone) { return; }
    if(!(pObPageSet = ObSet_New(H))) { return; }
    Ob_DECREF(VmmTlbGetPageTable(H, pProcess->paDTB, FALSE));
    for(i = 0; i < 3; i++) {
        MmX64_TlbSpider_Stage(H, pProcess->paDTB, 4, pProcess->fUserOnly, pObPageSet);
        VmmTlbPrefetch(H, pObPageSet);
    }
    pProcess->fTlbSpiderDone = TRUE;
    Ob_DECREF(pObPageSet);
}

const QWORD MMX64_PAGETABLEMAP_PML_REGION_SIZE[5] = { 0, 12, 21, 30, 39 };
const QWORD MMX64_PAGETABLEMAP_PML_REGION_MASK_PG[5] = { 0, 0x0000fffffffff000, 0x0000ffffffe00000, 0x0000ffffc0000000, 0 };
const QWORD MMX64_PAGETABLEMAP_PML_REGION_MASK_AD[5] = { 0, 0xfff, 0x1fffff, 0x3fffffff, 0 };

VOID MmX64_MapInitialize_Index(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess, _In_ PVMM_MAP_PTEENTRY pMemMap, _In_ PDWORD pcMemMap, _In_ QWORD vaBase, _In_ BYTE iPML, _In_ QWORD PTEs[512], _In_ BOOL fSupervisorPML, _In_ QWORD paMax)
{
    PVMMOB_CACHE_MEM pObNextPT;
    QWORD i, pte, va, cPages;
    BOOL fUserOnly, fNextSupervisorPML, fPagedOut = FALSE;
    PVMM_MAP_PTEENTRY pMemMapEntry = pMemMap + *pcMemMap - 1;
    if(!pProcess->fTlbSpiderDone) {
        VmmTlbSpider(H, pProcess);
    }
    fUserOnly = pProcess->fUserOnly;
    for(i = 0; i < 512; i++) {
        pte = PTEs[i];
        if(!MMX64_PTE_IS_VALID(pte, iPML)) {
            if(!pte) { continue; }
            if(iPML != 1) { continue; }
            pte = MMX64_PTE_IS_TRANSITION(H, pte, iPML);
            pte = 0x8000000000000005 | (pte & 0x0000fffffffff000);  // GUESS READ-ONLY USER PAGE IF NON TRANSITION
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
        pObNextPT = VmmTlbGetPageTable(H, pte & 0x0000fffffffff000, FALSE);
        if(!pObNextPT) { continue; }
        MmX64_MapInitialize_Index(H, pProcess, pMemMap, pcMemMap, va, iPML - 1, pObNextPT->pqw, fNextSupervisorPML, paMax);
        Ob_DECREF(pObNextPT);
        pMemMapEntry = pMemMap + *pcMemMap - 1;
    }
}

VOID MmX64_CallbackCleanup_ObPteMap(PVMMOB_MAP_PTE pOb)
{
    LocalFree(pOb->pbMultiText);
}

_Success_(return)
BOOL MmX64_PteMapInitialize(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess)
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
    pObPML4 = VmmTlbGetPageTable(H, pProcess->paDTB, FALSE);
    if(pObPML4) {
        pMemMap = (PVMM_MAP_PTEENTRY)LocalAlloc(LMEM_ZEROINIT, VMM_MEMMAP_ENTRIES_MAX * sizeof(VMM_MAP_PTEENTRY));
        if(pMemMap) {
            MmX64_MapInitialize_Index(H, pProcess, pMemMap, &cMemMap, 0, 4, pObPML4->pqw, FALSE, H->dev.paMax);
            for(i = 0; i < cMemMap; i++) { // fixup sign extension for kernel addresses
                if(pMemMap[i].vaBase & 0x0000800000000000) {
                    pMemMap[i].vaBase |= 0xffff000000000000;
                }
            }
        }
        Ob_DECREF(pObPML4);
    }
    // allocate VmmOb depending on result
    pObMap = Ob_AllocEx(H, OB_TAG_MAP_PTE, 0, sizeof(VMMOB_MAP_PTE) + cMemMap * sizeof(VMM_MAP_PTEENTRY), (OB_CLEANUP_CB)MmX64_CallbackCleanup_ObPteMap, NULL);
    if(!pObMap) {
        pProcess->Map.pObPte = Ob_AllocEx(H, OB_TAG_MAP_PTE, LMEM_ZEROINIT, sizeof(VMMOB_MAP_PTE), NULL, NULL);
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

VOID MmX64_Virt2PhysEx(_In_ VMM_HANDLE H, _In_ PVMM_V2P_ENTRY pV2Ps, _In_ DWORD cV2Ps, _In_ BOOL fUserOnly, _In_ BYTE iPML)
{
    BOOL fValidNextPT = FALSE;
    DWORD iV2P;
    QWORD pte, i, qwMask;
    PVMM_V2P_ENTRY pV2P;
    if(iPML == (BYTE)-1) { iPML = 4; }
    VmmTlbGetPageTableEx(H, pV2Ps, cV2Ps, FALSE);
    for(iV2P = 0; iV2P < cV2Ps; iV2P++) {
        pV2P = pV2Ps + iV2P;
        pV2P->paPT = 0;
        if(!pV2P->pObPTE) {
            continue;
        }
        if(pV2P->pa) {
            Ob_DECREF_NULL(&pV2P->pObPTE);
            continue;
        }
        i = 0x1ff & (pV2P->va >> MMX64_PAGETABLEMAP_PML_REGION_SIZE[iPML]);
        pte = pV2P->pObPTE->pqw[i];
        Ob_DECREF_NULL(&pV2P->pObPTE);
        if(!MMX64_PTE_IS_VALID(pte, iPML)) {
            if(iPML == 1) {
                pV2P->pte = pte;
                pV2P->fPaging = TRUE;
            }
            continue;
        }
        if(fUserOnly && !(pte & 0x04)) { continue; }            // SUPERVISOR PAGE & USER MODE REQ
        if(pte & 0x000f000000000000) { continue; }              // RESERVED
        if((iPML == 1) || (pte & 0x80) /* PS */) {
            if(iPML == 4) { continue; }                         // NO SUPPORT IN PML4
            qwMask = 0xffffffffffffffff << MMX64_PAGETABLEMAP_PML_REGION_SIZE[iPML];
            pV2P->pa = pte & 0x0000fffffffff000 & qwMask;       // MASK AWAY BITS FOR 4kB/2MB/1GB PAGES
            qwMask = qwMask ^ 0xffffffffffffffff;
            pV2P->pa = pV2P->pa | (qwMask & pV2P->va);          // FILL LOWER ADDRESS BITS
            pV2P->fPhys = TRUE;
            continue;
        }
        pV2P->paPT = pte & 0x0000fffffffff000;
        fValidNextPT = TRUE;
    }
    if(fValidNextPT && (iPML > 1)) {
        MmX64_Virt2PhysEx(H, pV2Ps, cV2Ps, fUserOnly, iPML - 1);
    }
}

_Success_(return)
BOOL MmX64_Virt2Phys(_In_ VMM_HANDLE H, _In_ QWORD paPT, _In_ BOOL fUserOnly, _In_ BYTE iPML, _In_ QWORD va, _Out_ PQWORD ppa)
{
    QWORD pte, i, qwMask;
    PVMMOB_CACHE_MEM pObPTEs;
    if(iPML == (BYTE)-1) { iPML = 4; }
    pObPTEs = VmmTlbGetPageTable(H, paPT & 0x0000fffffffff000, FALSE);
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
    return MmX64_Virt2Phys(H, pte, fUserOnly, iPML - 1, va, ppa);
}

VOID MmX64_Virt2PhysVadEx(_In_ VMM_HANDLE H, _In_ QWORD paPT, _Inout_ PVMMOB_MAP_VADEX pVadEx, _In_ BYTE iPML, _Inout_ PDWORD piVadEx)
{
    BYTE flags;
    PVMM_MAP_VADEXENTRY peVadEx;
    QWORD pa, pte, iPte, iVadEx, qwMask;
    PVMMOB_CACHE_MEM pObPTEs = NULL;
    if(iPML == (BYTE)-1) { iPML = 4; }
    if(!(pObPTEs = VmmTlbGetPageTable(H, paPT & 0x0000fffffffff000, FALSE))) {
        *piVadEx = *piVadEx + 1;
        return;
    }
next_entry:
    iVadEx = *piVadEx;
    peVadEx = &pVadEx->pMap[iVadEx];
    peVadEx->flags = 0;
    iPte = 0x1ff & (peVadEx->va >> MMX64_PAGETABLEMAP_PML_REGION_SIZE[iPML]);
    pte = pObPTEs->pqw[iPte];
    if(!MMX64_PTE_IS_VALID(pte, iPML)) { goto next_check; } // NOT VALID
    if(!(pte & 0x04)) { goto next_check; }                  // SUPERVISOR PAGE & USER MODE REQ
    if(pte & 0x000f000000000000) { goto next_check; }       // RESERVED
    if((iPML == 1) || (pte & 0x80) /* PS */) {
        if(iPML == 4) { goto next_check; }                  // NO SUPPORT IN PML4
        flags = VADEXENTRY_FLAG_HARDWARE;
        flags |= (pte & VMM_MEMMAP_PAGE_W) ? VADEXENTRY_FLAG_W : 0;
        flags |= (pte & VMM_MEMMAP_PAGE_NX) ? VADEXENTRY_FLAG_NX : 0;
        flags |= (pte & VMM_MEMMAP_PAGE_NS) ? 0 : VADEXENTRY_FLAG_K;
        peVadEx->flags = flags;
        qwMask = 0xffffffffffffffff << MMX64_PAGETABLEMAP_PML_REGION_SIZE[iPML];
        pa = pte & 0x0000fffffffff000 & qwMask;             // MASK AWAY BITS FOR 4kB/2MB/1GB PAGES
        qwMask = qwMask ^ 0xffffffffffffffff;
        peVadEx->pa = pa | (qwMask & peVadEx->va);  // FILL LOWER ADDRESS BITS
        peVadEx->tp = VMM_PTE_TP_HARDWARE;
        goto next_check;
    }    
    MmX64_Virt2PhysVadEx(H, pte, pVadEx, iPML - 1, piVadEx);
    Ob_DECREF(pObPTEs);
    return;
next_check:
    peVadEx->pte = pte;
    peVadEx->iPML = iPML;
    *piVadEx = *piVadEx + 1;
    if((iPML == 1) && (iPte < 0x1ff) && (iVadEx + 1 < pVadEx->cMap) && (pVadEx->pMap[iVadEx].va + 0x1000 == pVadEx->pMap[iVadEx + 1].va)) { goto next_entry; }
    Ob_DECREF(pObPTEs);
}

VOID MmX64_Virt2PhysGetInformation_DoWork(_In_ VMM_HANDLE H, _Inout_ PVMM_PROCESS pProcess, _Inout_ PVMM_VIRT2PHYS_INFORMATION pVirt2PhysInfo, _In_ BYTE iPML, _In_ QWORD PTEs[512])
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
    pObNextPT = VmmTlbGetPageTable(H, pte & 0x0000fffffffff000, FALSE);
    if(!pObNextPT) { return; }
    pVirt2PhysInfo->pas[iPML - 1] = pte & 0x0000fffffffff000;
    MmX64_Virt2PhysGetInformation_DoWork(H, pProcess, pVirt2PhysInfo, iPML - 1, pObNextPT->pqw);
    Ob_DECREF(pObNextPT);
}

VOID MmX64_Virt2PhysGetInformation(_In_ VMM_HANDLE H, _Inout_ PVMM_PROCESS pProcess, _Inout_ PVMM_VIRT2PHYS_INFORMATION pVirt2PhysInfo)
{
    QWORD va;
    PVMMOB_CACHE_MEM pObPML4;
    va = pVirt2PhysInfo->va;
    ZeroMemory(pVirt2PhysInfo, sizeof(VMM_VIRT2PHYS_INFORMATION));
    pVirt2PhysInfo->tpMemoryModel = VMM_MEMORYMODEL_X64;
    pVirt2PhysInfo->va = va;
    pVirt2PhysInfo->pas[4] = pProcess->paDTB;
    pObPML4 = VmmTlbGetPageTable(H, pProcess->paDTB, FALSE);
    if(!pObPML4) { return; }
    MmX64_Virt2PhysGetInformation_DoWork(H, pProcess, pVirt2PhysInfo, 4, pObPML4->pqw);
    Ob_DECREF(pObPML4);
}

VOID MmX64_Phys2VirtGetInformation_Index(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess, _In_ QWORD vaBase, _In_ BYTE iPML, _In_ QWORD PTEs[512], _In_ QWORD paMax, _Inout_ PVMMOB_PHYS2VIRT_INFORMATION pP2V)
{
    BOOL fUserOnly;
    QWORD i, pte, va;
    PVMMOB_CACHE_MEM pObNextPT;
    if(!pProcess->fTlbSpiderDone) {
        VmmTlbSpider(H, pProcess);
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
        if(fUserOnly && !(pte & 0x04)) { continue; }    // do not go into supervisor pages if user-only address space
        pObNextPT = VmmTlbGetPageTable(H, pte & 0x0000fffffffff000, FALSE);
        if(!pObNextPT) { continue; }
        va = vaBase + (i << MMX64_PAGETABLEMAP_PML_REGION_SIZE[iPML]);
        MmX64_Phys2VirtGetInformation_Index(H, pProcess, va, iPML - 1, pObNextPT->pqw, paMax, pP2V);
        Ob_DECREF(pObNextPT);
        if(pP2V->cvaList == VMM_PHYS2VIRT_INFORMATION_MAX_PROCESS_RESULT) { return; }
    }
}

VOID MmX64_Phys2VirtGetInformation(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess, _Inout_ PVMMOB_PHYS2VIRT_INFORMATION pP2V)
{
    PVMMOB_CACHE_MEM pObPML4;
    if((pP2V->cvaList == VMM_PHYS2VIRT_INFORMATION_MAX_PROCESS_RESULT) || (pP2V->paTarget > H->dev.paMax)) { return; }
    pObPML4 = VmmTlbGetPageTable(H, pProcess->paDTB, FALSE);
    if(!pObPML4) { return; }
    MmX64_Phys2VirtGetInformation_Index(H, pProcess, 0, 4, pObPML4->pqw, H->dev.paMax, pP2V);
    Ob_DECREF(pObPML4);
}

VOID MmX64_Close(_In_ VMM_HANDLE H)
{
    H->vmm.f32 = FALSE;
    H->vmm.tpMemoryModel = VMM_MEMORYMODEL_NA;
    ZeroMemory(&H->vmm.fnMemoryModel, sizeof(VMM_MEMORYMODEL_FUNCTIONS));
}

VOID MmX64_Initialize(_In_ VMM_HANDLE H)
{
    PVMM_MEMORYMODEL_FUNCTIONS pfnsMemoryModel = &H->vmm.fnMemoryModel;
    if(pfnsMemoryModel->pfnClose) {
        pfnsMemoryModel->pfnClose(H);
    }
    pfnsMemoryModel->pfnClose = MmX64_Close;
    pfnsMemoryModel->pfnVirt2Phys = MmX64_Virt2Phys;
    pfnsMemoryModel->pfnVirt2PhysEx = MmX64_Virt2PhysEx;
    pfnsMemoryModel->pfnVirt2PhysVadEx = MmX64_Virt2PhysVadEx;
    pfnsMemoryModel->pfnVirt2PhysGetInformation = MmX64_Virt2PhysGetInformation;
    pfnsMemoryModel->pfnPhys2VirtGetInformation = MmX64_Phys2VirtGetInformation;
    pfnsMemoryModel->pfnPteMapInitialize = MmX64_PteMapInitialize;
    pfnsMemoryModel->pfnTlbSpider = MmX64_TlbSpider;
    pfnsMemoryModel->pfnTlbPageTableVerify = MmX64_TlbPageTableVerify;
    H->vmm.tpMemoryModel = VMM_MEMORYMODEL_X64;
    H->vmm.f32 = FALSE;
}
