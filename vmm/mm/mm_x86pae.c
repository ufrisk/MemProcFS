// mm_x86pae.c : implementation of the x86 PAE (Physical Address Extension) 32-bit protected mode memory model.
//
// (c) Ulf Frisk, 2018-2025
// Author: Ulf Frisk, pcileech@frizk.net
//

#include "mm.h"

#define MMX86PAE_MEMMAP_DISPLAYBUFFER_LINE_LENGTH      70
#define MMX86PAE_PTE_IS_TRANSITION(H, pte, iPML)       ((((pte & 0x0c01) == 0x0800) && (iPML == 1) && (H->vmm.tpSystem == VMM_SYSTEM_WINDOWS_32)) ? ((pte & 0xffffdffffffff000) | 0x005) : 0)
#define MMX86PAE_PTE_IS_VALID(pte, iPML)               (pte & 0x01)

/*
* Tries to verify that a loaded page table is correct. If just a bit strange
* bytes/ptes supplied in pb will be altered to look better.
*/
BOOL MmX86PAE_TlbPageTableVerify(_In_ VMM_HANDLE H, _Inout_ PBYTE pb, _In_ QWORD pa, _In_ BOOL fSelfRefReq)
{
    return TRUE;
}

VOID MmX86PAE_TlbSpider_PD_PT(_In_ VMM_HANDLE H, _In_ QWORD pa, _In_ BYTE iPML, _In_ BOOL fUserOnly, _In_ POB_SET pPageSet)
{
    QWORD i, pte;
    PVMMOB_CACHE_MEM pObPT = NULL;
    // 1: retrieve from cache, add to staging if not found
    pObPT = VmmCacheGet(H, VMM_CACHE_TAG_TLB, pa);
    if(!pObPT) {
        ObSet_Push(pPageSet, pa);
        return;
    }
    if(iPML == 1) {
        Ob_DECREF(pObPT);
        return;
    }
    // 2: walk trough all entries for PD
    for(i = 0; i < 512; i++) {
        pte = pObPT->pqw[i];
        if(!(pte & 0x01)) { continue; }                 // not valid
        if(pte & 0x80) { continue; }                    // not valid ptr to PT
        if(fUserOnly && !(pte & 0x04)) { continue; }    // supervisor page when fUserOnly -> not valid
        MmX86PAE_TlbSpider_PD_PT(H, pte & 0x0000fffffffff000, 1, fUserOnly, pPageSet);
    }
    Ob_DECREF(pObPT);
}

VOID MmX86PAE_TlbSpider_PDPT(_In_ VMM_HANDLE H, _In_ QWORD paDTB, _In_ BOOL fUserOnly, _In_ POB_SET pPageSet)
{
    BOOL fSpiderComplete = TRUE;
    PVMMOB_CACHE_MEM pObPDPT;
    PBYTE pbPDPT;
    QWORD i, pte;
    // 1: retrieve PDPT
    pObPDPT = VmmTlbGetPageTable(H, paDTB & 0xfffff000, FALSE);
    if(!pObPDPT) { return; }
    pbPDPT = pObPDPT->pb + (paDTB & 0xfe0);
    // 2: walk through all four (4) PDPTEs
    for(i = 0; i < 0x20; i += 8) {
        pte = *(PQWORD)(pbPDPT + i);
        if(!(pte & 0x01)) { continue; }             // not valid
        if(pte & 0xffff0000000001e6) { continue; }  // RESERVED BITS IN PDPTE
        MmX86PAE_TlbSpider_PD_PT(H, pte & 0x0000fffffffff000, 2, fUserOnly, pPageSet);
    }
    Ob_DECREF(pObPDPT);
}

/*
* Iterate over PTPT, PD (3 times in total) to first stage uncached pages
* and then commit them to the cache.
*/
VOID MmX86PAE_TlbSpider(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess)
{
    DWORD i;
    POB_SET pObPageSet = NULL;
    if(pProcess->fTlbSpiderDone) { return; }
    if(!(pObPageSet = ObSet_New(H))) { return; }
    for(i = 0; i < 3; i++) {
        MmX86PAE_TlbSpider_PDPT(H, pProcess->paDTB, pProcess->fUserOnly, pObPageSet);
        VmmTlbPrefetch(H, pObPageSet);
    }
    pProcess->fTlbSpiderDone = TRUE;
    Ob_DECREF(pObPageSet);
}

const DWORD MMX86PAE_PAGETABLEMAP_PML_REGION_SIZE[4] = { 0, 12, 21, 30 };
const DWORD MMX86PAE_PAGETABLEMAP_PML_REGION_MASK_PG[4] = { 0, 0xfffff000, 0xffe00000, 0 };
const DWORD MMX86PAE_PAGETABLEMAP_PML_REGION_MASK_AD[4] = { 0, 0xfff, 0x1fffff, 0 };


VOID MmX86PAE_MapInitialize_Index(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess, _In_ PVMM_MAP_PTEENTRY pMemMap, _In_ PDWORD pcMemMap, _In_ DWORD vaBase, _In_ BYTE iPML, _In_ QWORD PTEs[512], _In_ BOOL fSupervisorPML, _In_ QWORD paMax)
{
    PVMMOB_CACHE_MEM pObNextPT;
    DWORD i, va;
    QWORD cPages, pte;
    BOOL fUserOnly, fNextSupervisorPML, fPagedOut = FALSE;
    PVMM_MAP_PTEENTRY pMemMapEntry = pMemMap + *pcMemMap - 1;
    fUserOnly = pProcess->fUserOnly;
    for(i = 0; i < 512; i++) {
        if((iPML == 3) && (i > 3)) { break; }                   // MAX 4 ENTRIES IN PDPT
        pte = PTEs[i];
        if(!MMX86PAE_PTE_IS_VALID(pte, iPML)) {
            if(!pte) { continue; }
            if(iPML != 1) { continue; }
            pte = MMX86PAE_PTE_IS_TRANSITION(H, pte, iPML);
            pte = 0x8000000000000005 | (pte ? (pte & 0x8000fffffffff000) : 0); // GUESS READ-ONLY USER PAGE IF NON TRANSITION
            fPagedOut = TRUE;
        } else {
            fPagedOut = FALSE;
        }
        if((pte & 0x0000fffffffff000) > paMax) { continue; }
        if(iPML == 3) {
            // PDPT: (iPML = 3)
            if(pte & 0xffff0000000001e6) { continue; }          // RESERVED BITS IN PDPTE
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
                    ((va != pMemMapEntry->vaBase + (pMemMapEntry->cPages << 12)) && !fPagedOut)) {
                    if(*pcMemMap + 1 >= VMM_MEMMAP_ENTRIES_MAX) { return; }
                    pMemMapEntry = pMemMap + *pcMemMap;
                    pMemMapEntry->vaBase = va;
                    pMemMapEntry->fPage = pte & VMM_MEMMAP_PAGE_MASK;
                    cPages = 1ULL << (MMX86PAE_PAGETABLEMAP_PML_REGION_SIZE[iPML] - 12);
                    if(fPagedOut) { pMemMapEntry->cSoftware += (DWORD)cPages; }
                    pMemMapEntry->cPages = cPages;
                    *pcMemMap = *pcMemMap + 1;
                    if(*pcMemMap >= VMM_MEMMAP_ENTRIES_MAX - 1) { return; }
                    continue;
                }
                cPages = 1ULL << (MMX86PAE_PAGETABLEMAP_PML_REGION_SIZE[iPML] - 12);
                if(fPagedOut) { pMemMapEntry->cSoftware += (DWORD)cPages; }
                pMemMapEntry->cPages += cPages;
                continue;
            }
        }
        // maps page table (PD, PT)
        fNextSupervisorPML = (iPML != 3) && !(pte & 0x04);
        pObNextPT = VmmTlbGetPageTable(H, pte & 0x0000fffffffff000, FALSE);
        if(!pObNextPT) { continue; }
        MmX86PAE_MapInitialize_Index(H, pProcess, pMemMap, pcMemMap, va, iPML - 1, pObNextPT->pqw, fNextSupervisorPML, paMax);
        Ob_DECREF(pObNextPT);
        pMemMapEntry = pMemMap + *pcMemMap - 1;
    }
}

VOID MmX86PAE_CallbackCleanup_ObPteMap(PVMMOB_MAP_PTE pOb)
{
    LocalFree(pOb->pbMultiText);
}

_Success_(return)
BOOL MmX86PAE_PteMapInitialize(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess)
{
    DWORD cMemMap = 0;
    PBYTE pbPDPT;
    PVMMOB_CACHE_MEM pObPDPT;
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
    VmmTlbSpider(H, pProcess);
    pObPDPT = VmmTlbGetPageTable(H, pProcess->paDTB & 0xfffff000, FALSE);
    if(pObPDPT) {
        pMemMap = (PVMM_MAP_PTEENTRY)LocalAlloc(LMEM_ZEROINIT, VMM_MEMMAP_ENTRIES_MAX * sizeof(VMM_MAP_PTEENTRY));
        if(pMemMap) {
            pbPDPT = pObPDPT->pb + (pProcess->paDTB & 0xfe0);     // ADJUST PDPT TO 32-BYTE BOUNDARY
            MmX86PAE_MapInitialize_Index(H, pProcess, pMemMap, &cMemMap, 0, 3, (PQWORD)pbPDPT, FALSE, H->dev.paMax);
        }
        Ob_DECREF(pObPDPT);
    }
    // allocate VmmOb depending on result
    pObMap = Ob_AllocEx(H, OB_TAG_MAP_PTE, 0, sizeof(VMMOB_MAP_PTE) + cMemMap * sizeof(VMM_MAP_PTEENTRY), (OB_CLEANUP_CB)MmX86PAE_CallbackCleanup_ObPteMap, NULL);
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

VOID MmX86PAE_Virt2PhysEx(_In_ VMM_HANDLE H, _In_ PVMM_V2P_ENTRY pV2Ps, _In_ DWORD cV2Ps, _In_ BOOL fUserOnly, _In_ BYTE iPML)
{
    BOOL fValidNextPT = FALSE;
    PBYTE pbPTEs;
    DWORD iV2P;
    QWORD pte, i, qwMask;
    PVMM_V2P_ENTRY pV2P;
    if(iPML == (BYTE)-1) { iPML = 3; }
    if(iPML == 3) {
        // PDPT:
        for(iV2P = 0; iV2P < cV2Ps; iV2P++) {
            pV2P = pV2Ps + iV2P;
            pV2P->_paPDPT_PAE = pV2P->paPT;
            pV2P->paPT = pV2P->paPT & 0x0000fffffffff000;
        }
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
            i = 0x1ff & (pV2P->va >> MMX86PAE_PAGETABLEMAP_PML_REGION_SIZE[iPML]);
            if(i > 3) {                                         // MAX 4 ENTRIES IN PDPT
                Ob_DECREF_NULL(&pV2P->pObPTE);
                continue;
            }
            pbPTEs = pV2P->pObPTE->pb + (pV2P->_paPDPT_PAE & 0xfe0);    // ADJUST PDPT TO 32-BYTE BOUNDARY
            pte = ((PQWORD)pbPTEs)[i];
            Ob_DECREF_NULL(&pV2P->pObPTE);
            if(!(pte & 0x01)) { continue; }                     // NOT VALID
            if(pte & 0xffff0000000001e6) { continue; }          // RESERVED BITS IN PDPTE
            pV2P->paPT = pte & 0x0000fffffffff000;
            continue;
        }
        MmX86PAE_Virt2PhysEx(H, pV2Ps, cV2Ps, fUserOnly, 2);
        return;
    }
    // PD and PT:
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
        i = 0x1ff & (pV2P->va >> MMX86PAE_PAGETABLEMAP_PML_REGION_SIZE[iPML]);
        pte = pV2P->pObPTE->pqw[i];
        Ob_DECREF_NULL(&pV2P->pObPTE);
        if(!MMX86PAE_PTE_IS_VALID(pte, iPML)) {
            if(iPML == 1) {
                pV2P->pte = pte;
                pV2P->fPaging = TRUE;
            }
            continue;
        }
        if(fUserOnly && !(pte & 0x04)) { continue; }            // SUPERVISOR PAGE & USER MODE REQ
        if(pte & 0x000f000000000000) { continue; }              // RESERVED
        if((iPML == 1) || (pte & 0x80) /* PS */) {
            qwMask = 0xffffffffffffffff << MMX86PAE_PAGETABLEMAP_PML_REGION_SIZE[iPML];
            pV2P->pa = pte & 0x0000fffffffff000 & qwMask;       // MASK AWAY BITS FOR 4kB/2MB/1GB PAGES
            qwMask = qwMask ^ 0xffffffffffffffff;
            pV2P->pa = pV2P->pa | (qwMask & pV2P->va);          // FILL LOWER ADDRESS BITS
            pV2P->fPhys = TRUE;
            continue;
        }
        pV2P->paPT = pte & 0x0000fffffffff000;
        fValidNextPT = TRUE;
    }
    if(fValidNextPT && (iPML == 2)) {
        MmX86PAE_Virt2PhysEx(H, pV2Ps, cV2Ps, fUserOnly, 1);
    }
}

_Success_(return)
BOOL MmX86PAE_Virt2Phys(_In_ VMM_HANDLE H, _In_ QWORD paPT, _In_ BOOL fUserOnly, _In_ BYTE iPML, _In_ QWORD va, _Out_ PQWORD ppa)
{
    PBYTE pbPTEs;
    QWORD pte, i, qwMask;
    PVMMOB_CACHE_MEM pObPTEs;
    if(va > 0xffffffff) { return FALSE; }
    if(iPML == (BYTE)-1) { iPML = 3; }
    pObPTEs = VmmTlbGetPageTable(H, paPT & 0x0000fffffffff000, FALSE);
    if(!pObPTEs) { return FALSE; }
    i = 0x1ff & (va >> MMX86PAE_PAGETABLEMAP_PML_REGION_SIZE[iPML]);
    if(iPML == 3) {
        // PDPT
        if(i > 3) {                                         // MAX 4 ENTRIES IN PDPT
            Ob_DECREF(pObPTEs);
            return FALSE;
        }                     
        pbPTEs = pObPTEs->pb + (paPT & 0xfe0);              // ADJUST PDPT TO 32-BYTE BOUNDARY
        pte = ((PQWORD)pbPTEs)[i];
        Ob_DECREF(pObPTEs);
        if(!(pte & 0x01)) { return FALSE; }                 // NOT VALID
        if(pte & 0xffff0000000001e6) { return FALSE; }      // RESERVED BITS IN PDPTE
        return MmX86PAE_Virt2Phys(H, pte, fUserOnly, 2, va, ppa);
    }
    // PT or PD
    pte = pObPTEs->pqw[i];
    Ob_DECREF(pObPTEs);
    if(!MMX86PAE_PTE_IS_VALID(pte, iPML)) {
        if(iPML == 1) { *ppa = pte; }                       // NOT VALID
        return FALSE;
    }
    if(fUserOnly && !(pte & 0x04)) { return FALSE; }        // SUPERVISOR PAGE & USER MODE REQ
    if(pte & 0x000f000000000000) { return FALSE; }          // RESERVED
    if((iPML == 1) || (pte & 0x80) /* PS */) {
        qwMask = 0xffffffffffffffff << MMX86PAE_PAGETABLEMAP_PML_REGION_SIZE[iPML];
        *ppa = pte & 0x0000fffffffff000 & qwMask;           // MASK AWAY BITS FOR 4kB/2MB/1GB PAGES
        qwMask = qwMask ^ 0xffffffffffffffff;
        *ppa = *ppa | (qwMask & va);                        // FILL LOWER ADDRESS BITS
        return TRUE;
    }
    return MmX86PAE_Virt2Phys(H, pte, fUserOnly, 1, va, ppa);
}

VOID MmX86PAE_Virt2PhysVadEx(_In_ VMM_HANDLE H, _In_ QWORD paPT, _Inout_ PVMMOB_MAP_VADEX pVadEx, _In_ BYTE iPML, _Inout_ PDWORD piVadEx)
{
    BYTE flags;
    PVMM_MAP_VADEXENTRY peVadEx;
    PBYTE pbPTEs;
    QWORD pa, pte, iPte, iVadEx, qwMask;
    PVMMOB_CACHE_MEM pObPTEs = NULL;
    if(iPML == (BYTE)-1) { iPML = 3; }
    if((pVadEx->pMap[*piVadEx].va > 0xffffffff) || !(pObPTEs = VmmTlbGetPageTable(H, paPT & 0x0000fffffffff000, FALSE))) {
        *piVadEx = *piVadEx + 1;
        return;
    }
next_entry:
    iVadEx = *piVadEx;
    peVadEx = &pVadEx->pMap[iVadEx];
    peVadEx->flags = 0;
    iPte = 0x1ff & (peVadEx->va >> MMX86PAE_PAGETABLEMAP_PML_REGION_SIZE[iPML]);
    pte = pObPTEs->pqw[iPte];
    if(iPML == 3) {
        // PDPT
        if(iPte > 3) { goto next_check; }                   // MAX 4 ENTRIES IN PDPT
        pbPTEs = pObPTEs->pb + (paPT & 0xfe0);              // ADJUST PDPT TO 32-BYTE BOUNDARY
        pte = ((PQWORD)pbPTEs)[iPte];
        if(!(pte & 0x01)) { goto next_check; }              // NOT VALID
        if(pte & 0xffff0000000001e6) { goto next_check; }   // RESERVED BITS IN PDPTE
        MmX86PAE_Virt2PhysVadEx(H, pte, pVadEx, 2, piVadEx);
        Ob_DECREF(pObPTEs);
        return;
    }
    // PT or PD
    if(!MMX86PAE_PTE_IS_VALID(pte, iPML)) { goto next_check; }  // NOT VALID
    if(!(pte & 0x04)) { goto next_check; }                  // SUPERVISOR PAGE & USER MODE REQ
    if(pte & 0x000f000000000000) { goto next_check; }       // RESERVED
    if((iPML == 1) || (pte & 0x80) /* PS */) {
        flags = VADEXENTRY_FLAG_HARDWARE;
        flags |= (pte & VMM_MEMMAP_PAGE_W) ? VADEXENTRY_FLAG_W : 0;
        flags |= (pte & VMM_MEMMAP_PAGE_NX) ? VADEXENTRY_FLAG_NX : 0;
        flags |= (pte & VMM_MEMMAP_PAGE_NS) ? 0 : VADEXENTRY_FLAG_K;
        peVadEx->flags = flags;
        qwMask = 0xffffffffffffffff << MMX86PAE_PAGETABLEMAP_PML_REGION_SIZE[iPML];
        pa = pte & 0x0000fffffffff000 & qwMask;             // MASK AWAY BITS FOR 4kB/2MB/1GB PAGES
        qwMask = qwMask ^ 0xffffffffffffffff;
        peVadEx->pa = pa | (qwMask & peVadEx->va);  // FILL LOWER ADDRESS BITS
        peVadEx->tp = VMM_PTE_TP_HARDWARE;
        goto next_check;
    }
    MmX86PAE_Virt2PhysVadEx(H, pte, pVadEx, 1, piVadEx);
    Ob_DECREF(pObPTEs);
    return;
next_check:
    peVadEx->pte = pte;
    peVadEx->iPML = iPML;
    *piVadEx = *piVadEx + 1;
    if((iPML == 1) && (iPte < 0x3ff) && (iVadEx + 1 < pVadEx->cMap) && (peVadEx->va + 0x1000 == pVadEx->pMap[iVadEx + 1].va)) { goto next_entry; }
    Ob_DECREF(pObPTEs);
}

VOID MmX86PAE_Virt2PhysGetInformation_DoWork(_In_ VMM_HANDLE H, _Inout_ PVMM_PROCESS pProcess, _Inout_ PVMM_VIRT2PHYS_INFORMATION pVirt2PhysInfo, _In_ BYTE iPML, _In_ QWORD PTEs[512])
{
    QWORD pte, i, qwMask;
    PVMMOB_CACHE_MEM pObNextPT;
    i = 0x1ff & (pVirt2PhysInfo->va >> MMX86PAE_PAGETABLEMAP_PML_REGION_SIZE[iPML]);
    if((iPML == 3) && (i > 3)) { return; }                      // MAX 4 ENTRIES IN PDPT
    pte = PTEs[i];
    pVirt2PhysInfo->iPTEs[iPML] = (WORD)i;
    pVirt2PhysInfo->PTEs[iPML] = pte;
    if(!MMX86PAE_PTE_IS_VALID(pte, iPML)) { return; }           // NOT VALID
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
    pObNextPT = VmmTlbGetPageTable(H, pte & 0x0000fffffffff000, FALSE);
    if(!pObNextPT) { return; }
    pVirt2PhysInfo->pas[iPML - 1] = pte & 0x0000fffffffff000;
    MmX86PAE_Virt2PhysGetInformation_DoWork(H, pProcess, pVirt2PhysInfo, iPML - 1, pObNextPT->pqw);
    Ob_DECREF(pObNextPT);
}

VOID MmX86PAE_Virt2PhysGetInformation(_In_ VMM_HANDLE H, _Inout_ PVMM_PROCESS pProcess, _Inout_ PVMM_VIRT2PHYS_INFORMATION pVirt2PhysInfo)
{
    QWORD va;
    PVMMOB_CACHE_MEM pObPDPT;
    if(pVirt2PhysInfo->va > 0xffffffff) { return; }
    va = pVirt2PhysInfo->va;
    ZeroMemory(pVirt2PhysInfo, sizeof(VMM_VIRT2PHYS_INFORMATION));
    pVirt2PhysInfo->tpMemoryModel = VMM_MEMORYMODEL_X86PAE;
    pVirt2PhysInfo->va = va;
    pVirt2PhysInfo->pas[3] = pProcess->paDTB;
    pObPDPT = VmmTlbGetPageTable(H, pProcess->paDTB & 0xfffff000, FALSE);
    if(!pObPDPT) { return; }
    MmX86PAE_Virt2PhysGetInformation_DoWork(H, pProcess, pVirt2PhysInfo, 3, (PQWORD)(pObPDPT->pb + (pProcess->paDTB & 0xfe0)));
    Ob_DECREF(pObPDPT);
}

VOID MmX86PAE_Phys2VirtGetInformation_Index(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess, _In_ DWORD vaBase, _In_ BYTE iPML, _In_ QWORD PTEs[512], _In_ QWORD paMax, _Inout_ PVMMOB_PHYS2VIRT_INFORMATION pP2V)
{
    BOOL fUserOnly;
    QWORD pte;
    DWORD i, va;
    PVMMOB_CACHE_MEM pObNextPT;
    if(!pProcess->fTlbSpiderDone) {
        VmmTlbSpider(H, pProcess);
    }
    fUserOnly = pProcess->fUserOnly;
    for(i = 0; i < 512; i++) {
        if((iPML == 3) && (i > 3)) { break; }                      // MAX 4 ENTRIES IN PDPT
        pte = PTEs[i];
        if(!MMX86PAE_PTE_IS_VALID(pte, iPML)) { continue; }
        if((pte & 0x0000fffffffff000) > paMax) { continue; }
        if(iPML == 3) {
            // PDPT: (iPML = 3)
            if(pte & 0xffff0000000001e6) { continue; }        // RESERVED BITS IN PDPTE
            va = i * 0x40000000;
        } else {
            // PT or PD: (iPML = 1..2)
            if(fUserOnly && !(pte & 0x04)) { continue; }
            va = vaBase + (i << MMX86PAE_PAGETABLEMAP_PML_REGION_SIZE[iPML]);
            // maps page
            if((iPML == 1) || (pte & 0x80) /* PS */) {
                if((pte & MMX86PAE_PAGETABLEMAP_PML_REGION_MASK_PG[iPML]) == (pP2V->paTarget & MMX86PAE_PAGETABLEMAP_PML_REGION_MASK_PG[iPML])) {
                    va = vaBase + (i << MMX86PAE_PAGETABLEMAP_PML_REGION_SIZE[iPML]);
                    pP2V->pvaList[pP2V->cvaList] = va | (pP2V->paTarget & MMX86PAE_PAGETABLEMAP_PML_REGION_MASK_AD[iPML]);
                    pP2V->cvaList++;
                    if(pP2V->cvaList == VMM_PHYS2VIRT_INFORMATION_MAX_PROCESS_RESULT) { return; }
                }
                continue;
            }
        }
        // maps page table (PD, PT)
        if((iPML != 3) && fUserOnly && !(pte & 0x04)) { continue; }    // do not go into supervisor pages if user-only adderss space
        pObNextPT = VmmTlbGetPageTable(H, pte & 0x0000fffffffff000, FALSE);
        if(!pObNextPT) { continue; }
        MmX86PAE_Phys2VirtGetInformation_Index(H, pProcess, va, iPML - 1, pObNextPT->pqw, paMax, pP2V);
        Ob_DECREF(pObNextPT);
        if(pP2V->cvaList == VMM_PHYS2VIRT_INFORMATION_MAX_PROCESS_RESULT) { return; }
    }
}

VOID MmX86PAE_Phys2VirtGetInformation(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess, _Inout_ PVMMOB_PHYS2VIRT_INFORMATION pP2V)
{
    PVMMOB_CACHE_MEM pObPDPT;
    if((pP2V->cvaList == VMM_PHYS2VIRT_INFORMATION_MAX_PROCESS_RESULT) || (pP2V->paTarget > H->dev.paMax)) { return; }
    pObPDPT = VmmTlbGetPageTable(H, pProcess->paDTB & ~0xfff, FALSE);
    if(!pObPDPT) { return; }
    MmX86PAE_Phys2VirtGetInformation_Index(H, pProcess, 0, 3, (PQWORD)(pObPDPT->pb + (pProcess->paDTB & 0xfe0)), H->dev.paMax, pP2V);
    Ob_DECREF(pObPDPT);
}

VOID MmX86PAE_Close(_In_ VMM_HANDLE H)
{
    H->vmm.f32 = FALSE;
    H->vmm.tpMemoryModel = VMM_MEMORYMODEL_NA;
    ZeroMemory(&H->vmm.fnMemoryModel, sizeof(VMM_MEMORYMODEL_FUNCTIONS));
}

VOID MmX86PAE_Initialize(_In_ VMM_HANDLE H)
{
    PVMM_MEMORYMODEL_FUNCTIONS pfnsMemoryModel = &H->vmm.fnMemoryModel;
    if(pfnsMemoryModel->pfnClose) {
        pfnsMemoryModel->pfnClose(H);
    }
    pfnsMemoryModel->pfnClose = MmX86PAE_Close;
    pfnsMemoryModel->pfnVirt2Phys = MmX86PAE_Virt2Phys;
    pfnsMemoryModel->pfnVirt2PhysEx = MmX86PAE_Virt2PhysEx;
    pfnsMemoryModel->pfnVirt2PhysVadEx = MmX86PAE_Virt2PhysVadEx;
    pfnsMemoryModel->pfnVirt2PhysGetInformation = MmX86PAE_Virt2PhysGetInformation;
    pfnsMemoryModel->pfnPhys2VirtGetInformation = MmX86PAE_Phys2VirtGetInformation;
    pfnsMemoryModel->pfnPteMapInitialize = MmX86PAE_PteMapInitialize;
    pfnsMemoryModel->pfnTlbSpider = MmX86PAE_TlbSpider;
    pfnsMemoryModel->pfnTlbPageTableVerify = MmX86PAE_TlbPageTableVerify;
    H->vmm.tpMemoryModel = VMM_MEMORYMODEL_X86PAE;
    H->vmm.f32 = TRUE;
}
