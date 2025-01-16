// mm_arm64.c : implementation of the ARM64 memory model.
//
// (c) Ulf Frisk, 2018-2025
// Author: Ulf Frisk, pcileech@frizk.net
//

#include "mm.h"

// TODO: FIX THIS ARM64
#define MMARM64_MEMMAP_DISPLAYBUFFER_LINE_LENGTH      89
#define MMARM64_PTE_IS_TRANSITION(pte, iPML)          (((pte & 0x0c01) == 0x0800) && (iPML == 1))
#define MMARM64_PTE_IS_VALID(pte, iPML)               ((pte & 0x01) && ((pte & 0x02) || (iPML == 3) || (iPML == 2)))

#define MMARM64_PTE_IS_WRITABLE(pte)                  (pte & 0x0080000000000000)
#define MMARM64_PTE_IS_NOEXECUTE(pte, va)             ((va & 0x0000800000000000) ? (pte & 0x0020000000000000) : (pte & 0x0040000000000000))
#define MMARM64_PTE_IS_PRIVILEGED(pte, va)            ((va & 0x0000800000000000))

#define MMARM64_PTE_IS_USER(pte, va)                  (!(va & 0x0000800000000000))

/*
* Tries to verify that a loaded page table is correct. If just a bit strange
* bytes/ptes supplied in pb will be altered to look better.
*/
BOOL MmARM64_TlbPageTableVerify(_In_ VMM_HANDLE H, _Inout_ PBYTE pb, _In_ QWORD pa, _In_ BOOL fSelfRefReq)
{
    DWORD i, cBad = 0;
    QWORD *ptes, pte, paMax;
    BOOL fSelfRef = FALSE;
    if(!pb) { return FALSE; }
    ptes = (PQWORD)pb;
    paMax = max(0xffffffff, H->dev.paMax);
    for(i = 0; i < 512; i++) {
        pte = *(ptes + i);
        if((pte & 0x01) && ((0x0003fffffffff000 & pte) > paMax)) {
            // A bad PTE, or memory allocated above the physical address max
            // limit. This may be just trash in the page table in which case
            // we clear this faulty entry. If too may bad PTEs are found this
            // is most probably not a page table - zero it out but let it
            // remain in cache to prevent performance degrading reloads...
            *(ptes + i) = (QWORD)0;
            // count as a bad page - if over threshold -> abort!
            cBad++;
            if(cBad > H->cfg.dwPteQualityThreshold) { break; }
        }
        if(fSelfRefReq && ((ptes[i] & 0x0063fffffffff073) == pa + 0x0060000000000003)) {
            fSelfRef = TRUE;
        }
    }
    if((cBad > H->cfg.dwPteQualityThreshold) || (fSelfRefReq && !fSelfRef)) {
        ZeroMemory(pb, 4096);
        return FALSE;
    }
    return TRUE;
}

/*
* Iterate over PX, PP, PD (3 times in total) to first stage uncached pages
* and then commit them to the cache.
* -- H
* -- pProcess
*/
VOID MmARM64_TlbSpider(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess)
{
    // NOT SUPPORTED (YET) ON ARM64
    ;
}

const QWORD MMARM64_PAGETABLEMAP_PML_REGION_SIZE[5] = { 0, 12, 21, 30, 39 };
const QWORD MMARM64_PAGETABLEMAP_PML_REGION_MASK_PG[5] = { 0, 0x0003fffffffff000, 0x0003ffffffe00000, 0x0003ffffc0000000, 0 };
const QWORD MMARM64_PAGETABLEMAP_PML_REGION_MASK_AD[5] = { 0, 0xfff, 0x1fffff, 0x3fffffff, 0 };

VOID MmARM64_MapInitialize_Index(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess, _In_ PVMM_MAP_PTEENTRY pMemMap, _In_ PDWORD pcMemMap, _In_ QWORD vaBase, _In_ BYTE iPML, _In_ QWORD PTEs[512], _In_ BOOL fSupervisorPML, _In_ QWORD paMax)
{
    PVMMOB_CACHE_MEM pObNextPT;
    QWORD i, pte, va, cPages, fPage = 0;
    BOOL fUserOnly, fNextSupervisorPML, fPagedOut = FALSE;
    PVMM_MAP_PTEENTRY pMemMapEntry = pMemMap + *pcMemMap - 1;
    if(!pProcess->fTlbSpiderDone) {
        VmmTlbSpider(H, pProcess);
    }
    fUserOnly = pProcess->fUserOnly;
    for(i = 0; i < 512; i++) {
        pte = PTEs[i];
        if(!MMARM64_PTE_IS_VALID(pte, iPML)) {
            if(!pte) { continue; }
            if(iPML != 1) { continue; }
            pte = MMARM64_PTE_IS_TRANSITION(pte, iPML) ? ((pte & 0x0003fffffffff000) | 0x0060000000000003) : 0;     // GUESS NX/RO PAGE IF TRANSITION
            fPagedOut = TRUE;
        } else {
            fPagedOut = FALSE;
        }
        if((pte & 0x0003fffffffff000) > paMax) { continue; }
        va = vaBase + (i << MMARM64_PAGETABLEMAP_PML_REGION_SIZE[iPML]);
        if(fUserOnly && !MMARM64_PTE_IS_USER(pte, va)) { continue; }    // USER-MODE REQUIREMENT
        // maps page
        if((iPML == 1) || !(pte & 2)) {
            if(iPML == 4) { continue; } // not supported - PX cannot map page directly
            if(fPagedOut && !pte) {
                fPage = VMM_MEMMAP_PAGE_A | VMM_MEMMAP_PAGE_NX | (MMARM64_PTE_IS_PRIVILEGED(pte, va) ? 0 : VMM_MEMMAP_PAGE_NS);
            } else {
                fPage = VMM_MEMMAP_PAGE_A | (MMARM64_PTE_IS_WRITABLE(pte) ? VMM_MEMMAP_PAGE_W : 0) | (MMARM64_PTE_IS_NOEXECUTE(pte, va) ? VMM_MEMMAP_PAGE_NX : 0) | (MMARM64_PTE_IS_PRIVILEGED(pte, va) ? 0 : VMM_MEMMAP_PAGE_NS);
            }
            if((*pcMemMap == 0) ||
                ((pMemMapEntry->fPage != fPage) && !fPagedOut) ||
                (va != pMemMapEntry->vaBase + (pMemMapEntry->cPages << 12))) {
                if(*pcMemMap + 1 >= VMM_MEMMAP_ENTRIES_MAX) { return; }
                pMemMapEntry = pMemMap + *pcMemMap;
                pMemMapEntry->vaBase = va;
                pMemMapEntry->fPage = fPage;
                cPages = 1ULL << (MMARM64_PAGETABLEMAP_PML_REGION_SIZE[iPML] - 12);
                if(fPagedOut) { pMemMapEntry->cSoftware += (DWORD)cPages; }
                pMemMapEntry->cPages = cPages;
                *pcMemMap = *pcMemMap + 1;
                if(*pcMemMap >= VMM_MEMMAP_ENTRIES_MAX - 1) {
                    return;
                }
                continue;
            }
            cPages = 1ULL << (MMARM64_PAGETABLEMAP_PML_REGION_SIZE[iPML] - 12);
            if(fPagedOut) { pMemMapEntry->cSoftware += (DWORD)cPages; }
            pMemMapEntry->cPages += cPages;
            continue;
        }
        // optimization - same PT in multiple consecutive PDe
        if((iPML == 2) && i && (pte == PTEs[i - 1]) && (pMemMapEntry->cPages >= 512) && (va == pMemMapEntry->vaBase + (pMemMapEntry->cPages << 12))) {
            pMemMapEntry->cPages += 1ULL << (MMARM64_PAGETABLEMAP_PML_REGION_SIZE[iPML] - 12);
            continue;
        }
        // maps page table (PDPT, PD, PT)
        fNextSupervisorPML = !(pte & 0x04);
        pObNextPT = VmmTlbGetPageTable(H, pte & 0x0003fffffffff000, FALSE);
        if(!pObNextPT) { continue; }
        MmARM64_MapInitialize_Index(H, pProcess, pMemMap, pcMemMap, va, iPML - 1, pObNextPT->pqw, fNextSupervisorPML, paMax);
        Ob_DECREF(pObNextPT);
        pMemMapEntry = pMemMap + *pcMemMap - 1;
    }
}

VOID MmARM64_CallbackCleanup_ObPteMap(PVMMOB_MAP_PTE pOb)
{
    LocalFree(pOb->pbMultiText);
}

_Success_(return)
BOOL MmARM64_PteMapInitialize(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess)
{
    QWORD i;
    DWORD cMemMap = 0;
    PVMMOB_CACHE_MEM pObPX;
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
    pObPX = VmmTlbGetPageTable(H, pProcess->paDTB, FALSE);
    if(pObPX) {
        pMemMap = (PVMM_MAP_PTEENTRY)LocalAlloc(LMEM_ZEROINIT, VMM_MEMMAP_ENTRIES_MAX * sizeof(VMM_MAP_PTEENTRY));
        if(pMemMap) {
            MmARM64_MapInitialize_Index(H, pProcess, pMemMap, &cMemMap, 0, 4, pObPX->pqw, FALSE, H->dev.paMax);
            for(i = 0; i < cMemMap; i++) { // fixup sign extension for kernel addresses
                if(pMemMap[i].vaBase & 0x0000800000000000) {
                    pMemMap[i].vaBase |= 0xffff000000000000;
                }
            }
        }
        Ob_DECREF(pObPX);
    }
    // allocate VmmOb depending on result
    pObMap = Ob_AllocEx(H, OB_TAG_MAP_PTE, 0, sizeof(VMMOB_MAP_PTE) + cMemMap * sizeof(VMM_MAP_PTEENTRY), (OB_CLEANUP_CB)MmARM64_CallbackCleanup_ObPteMap, NULL);
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

VOID MmARM64_Virt2PhysEx(_In_ VMM_HANDLE H, _In_ PVMM_V2P_ENTRY pV2Ps, _In_ DWORD cV2Ps, _In_ BOOL fUserOnly, _In_ BYTE iPML)
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
        i = 0x1ff & (pV2P->va >> MMARM64_PAGETABLEMAP_PML_REGION_SIZE[iPML]);
        pte = pV2P->pObPTE->pqw[i];
        Ob_DECREF_NULL(&pV2P->pObPTE);
        if(!MMARM64_PTE_IS_VALID(pte, iPML)) {
            if(iPML == 1) {
                pV2P->pte = pte;
                pV2P->fPaging = TRUE;
            }
            continue;
        }
        if((iPML == 1) || !(pte & 2)) {
            if(fUserOnly && !MMARM64_PTE_IS_USER(pte, pV2P->va)) { continue; }    // USER-MODE REQUIREMENT
            qwMask = 0xffffffffffffffff << MMARM64_PAGETABLEMAP_PML_REGION_SIZE[iPML];
            pV2P->pa = pte & 0x0003fffffffff000 & qwMask;       // MASK AWAY BITS FOR 4kB/2MB/1GB PAGES
            qwMask = qwMask ^ 0xffffffffffffffff;
            pV2P->pa = pV2P->pa | (qwMask & pV2P->va);          // FILL LOWER ADDRESS BITS
            pV2P->fPhys = TRUE;
            continue;
        }
        pV2P->paPT = pte & 0x0003fffffffff000;
        fValidNextPT = TRUE;
    }
    if(fValidNextPT && (iPML > 1)) {
        MmARM64_Virt2PhysEx(H, pV2Ps, cV2Ps, fUserOnly, iPML - 1);
    }
}

_Success_(return)
BOOL MmARM64_Virt2Phys(_In_ VMM_HANDLE H, _In_ QWORD paPT, _In_ BOOL fUserOnly, _In_ BYTE iPML, _In_ QWORD va, _Out_ PQWORD ppa)
{
    QWORD pte, i, qwMask;
    PVMMOB_CACHE_MEM pObPTEs;
    if(iPML == (BYTE)-1) { iPML = 4; }
    pObPTEs = VmmTlbGetPageTable(H, paPT & 0x0003fffffffff000, FALSE);
    if(!pObPTEs) { return FALSE; }
    i = 0x1ff & (va >> MMARM64_PAGETABLEMAP_PML_REGION_SIZE[iPML]);
    pte = pObPTEs->pqw[i];
    Ob_DECREF(pObPTEs);
    if(!MMARM64_PTE_IS_VALID(pte, iPML)) {
        if(iPML == 1) { *ppa = pte; }                       // NOT VALID
        return FALSE;
    }
    if((iPML == 1) || !(pte & 2)) {
        if(fUserOnly && !MMARM64_PTE_IS_USER(pte, va)) { return FALSE; }    // USER-MODE REQUIREMENT
        qwMask = 0xffffffffffffffff << MMARM64_PAGETABLEMAP_PML_REGION_SIZE[iPML];
        *ppa = pte & 0x0003fffffffff000 & qwMask;           // MASK AWAY BITS FOR 4kB/2MB/1GB PAGES
        qwMask = qwMask ^ 0xffffffffffffffff;
        *ppa = *ppa | (qwMask & va);                        // FILL LOWER ADDRESS BITS
        return TRUE;
    }
    return MmARM64_Virt2Phys(H, pte, fUserOnly, iPML - 1, va, ppa);
}

VOID MmARM64_Virt2PhysVadEx(_In_ VMM_HANDLE H, _In_ QWORD paPT, _Inout_ PVMMOB_MAP_VADEX pVadEx, _In_ BYTE iPML, _Inout_ PDWORD piVadEx)
{
    BYTE flags;
    PVMM_MAP_VADEXENTRY peVadEx;
    QWORD pa, pte, iPte, iVadEx, qwMask;
    PVMMOB_CACHE_MEM pObPTEs = NULL;
    if(iPML == (BYTE)-1) { iPML = 4; }
    if(!(pObPTEs = VmmTlbGetPageTable(H, paPT & 0x0003fffffffff000, FALSE))) {
        *piVadEx = *piVadEx + 1;
        return;
    }
next_entry:
    iVadEx = *piVadEx;
    peVadEx = &pVadEx->pMap[iVadEx];
    peVadEx->flags = 0;
    iPte = 0x1ff & (peVadEx->va >> MMARM64_PAGETABLEMAP_PML_REGION_SIZE[iPML]);
    pte = pObPTEs->pqw[iPte];
    if(!MMARM64_PTE_IS_VALID(pte, iPML)) { goto next_check; } // NOT VALID
    if((iPML == 1) || !(pte & 2)) {
        flags = VADEXENTRY_FLAG_HARDWARE;
        flags |= MMARM64_PTE_IS_WRITABLE(pte) ? VADEXENTRY_FLAG_W : 0;
        flags |= MMARM64_PTE_IS_NOEXECUTE(pte, peVadEx->va) ? VADEXENTRY_FLAG_NX : 0;
        flags |= MMARM64_PTE_IS_PRIVILEGED(pte, peVadEx->va) ? VADEXENTRY_FLAG_K : 0;
        peVadEx->flags = flags;
        qwMask = 0xffffffffffffffff << MMARM64_PAGETABLEMAP_PML_REGION_SIZE[iPML];
        pa = pte & 0x0003fffffffff000 & qwMask;             // MASK AWAY BITS FOR 4kB/2MB/1GB PAGES
        qwMask = qwMask ^ 0xffffffffffffffff;
        peVadEx->pa = pa | (qwMask & peVadEx->va);       // FILL LOWER ADDRESS BITS
        peVadEx->tp = VMM_PTE_TP_HARDWARE;
        goto next_check;
    }    
    MmARM64_Virt2PhysVadEx(H, pte, pVadEx, iPML - 1, piVadEx);
    Ob_DECREF(pObPTEs);
    return;
next_check:
    peVadEx->pte = pte;
    peVadEx->iPML = iPML;
    *piVadEx = *piVadEx + 1;
    if((iPML == 1) && (iPte < 0x1ff) && (iVadEx + 1 < pVadEx->cMap) && (peVadEx->va + 0x1000 == pVadEx->pMap[iVadEx + 1].va)) { goto next_entry; }
    Ob_DECREF(pObPTEs);
}

VOID MmARM64_Virt2PhysGetInformation_DoWork(_In_ VMM_HANDLE H, _Inout_ PVMM_PROCESS pProcess, _Inout_ PVMM_VIRT2PHYS_INFORMATION pVirt2PhysInfo, _In_ BYTE iPML, _In_ QWORD PTEs[512])
{
    QWORD pte, i, qwMask;
    PVMMOB_CACHE_MEM pObNextPT;
    i = 0x1ff & (pVirt2PhysInfo->va >> MMARM64_PAGETABLEMAP_PML_REGION_SIZE[iPML]);
    pte = PTEs[i];
    pVirt2PhysInfo->iPTEs[iPML] = (WORD)i;
    pVirt2PhysInfo->PTEs[iPML] = pte;
    if(!MMARM64_PTE_IS_VALID(pte, iPML)) { return; }        // NOT VALID
    if(pProcess->fUserOnly && !MMARM64_PTE_IS_USER(pte, pVirt2PhysInfo->va)) { return; }    // USER-MODE REQUIREMENT
    if((iPML == 1) || !(pte & 2)) {
        qwMask = 0xffffffffffffffff << MMARM64_PAGETABLEMAP_PML_REGION_SIZE[iPML];
        pVirt2PhysInfo->pas[0] = pte & 0x0000fffffffff000 & qwMask;     // MASK AWAY BITS FOR 4kB/2MB/1GB PAGES
        qwMask = qwMask ^ 0xffffffffffffffff;
        pVirt2PhysInfo->pas[0] = pVirt2PhysInfo->pas[0] | (qwMask & pVirt2PhysInfo->va);    // FILL LOWER ADDRESS BITS
        return;
    }
    pObNextPT = VmmTlbGetPageTable(H, pte & 0x0003fffffffff000, FALSE);
    if(!pObNextPT) { return; }
    pVirt2PhysInfo->pas[iPML - 1] = pte & 0x0003fffffffff000;
    MmARM64_Virt2PhysGetInformation_DoWork(H, pProcess, pVirt2PhysInfo, iPML - 1, pObNextPT->pqw);
    Ob_DECREF(pObNextPT);
}

VOID MmARM64_Virt2PhysGetInformation(_In_ VMM_HANDLE H, _Inout_ PVMM_PROCESS pProcess, _Inout_ PVMM_VIRT2PHYS_INFORMATION pVirt2PhysInfo)
{
    QWORD va;
    PVMMOB_CACHE_MEM pObPX;
    va = pVirt2PhysInfo->va;
    ZeroMemory(pVirt2PhysInfo, sizeof(VMM_VIRT2PHYS_INFORMATION));
    pVirt2PhysInfo->tpMemoryModel = VMM_MEMORYMODEL_ARM64;
    pVirt2PhysInfo->va = va;
    pVirt2PhysInfo->pas[4] = pProcess->paDTB;
    pObPX = VmmTlbGetPageTable(H, pProcess->paDTB, FALSE);
    if(!pObPX) { return; }
    MmARM64_Virt2PhysGetInformation_DoWork(H, pProcess, pVirt2PhysInfo, 4, pObPX->pqw);
    Ob_DECREF(pObPX);
}

VOID MmARM64_Phys2VirtGetInformation_Index(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess, _In_ QWORD vaBase, _In_ BYTE iPML, _In_ QWORD PTEs[512], _In_ QWORD paMax, _Inout_ PVMMOB_PHYS2VIRT_INFORMATION pP2V)
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
        if(!MMARM64_PTE_IS_VALID(pte, iPML)) { continue; }
        if((pte & 0x0003fffffffff000) > paMax) { continue; }
        if(fUserOnly && !MMARM64_PTE_IS_USER(pte, vaBase)) { continue; }    // USER-MODE REQUIREMENT
        // maps page
        if((iPML == 1) || !(pte & 2)) {
            if((pte & MMARM64_PAGETABLEMAP_PML_REGION_MASK_PG[iPML]) == (pP2V->paTarget & MMARM64_PAGETABLEMAP_PML_REGION_MASK_PG[iPML])) {
                va = vaBase + (i << MMARM64_PAGETABLEMAP_PML_REGION_SIZE[iPML]);
                pP2V->pvaList[pP2V->cvaList] = va | ((va >> 47) ? 0xffff000000000000 : 0) | (pP2V->paTarget & MMARM64_PAGETABLEMAP_PML_REGION_MASK_AD[iPML]);
                pP2V->cvaList++;
                if(pP2V->cvaList == VMM_PHYS2VIRT_INFORMATION_MAX_PROCESS_RESULT) { return; }
            }
            continue;
        }
        // maps page table (PP, PD, PT)
        if(fUserOnly && !MMARM64_PTE_IS_USER(pte, vaBase)) { continue; }    // USER-MODE REQUIREMENT
        pObNextPT = VmmTlbGetPageTable(H, pte & 0x0003fffffffff000, FALSE);
        if(!pObNextPT) { continue; }
        va = vaBase + (i << MMARM64_PAGETABLEMAP_PML_REGION_SIZE[iPML]);
        MmARM64_Phys2VirtGetInformation_Index(H, pProcess, va, iPML - 1, pObNextPT->pqw, paMax, pP2V);
        Ob_DECREF(pObNextPT);
        if(pP2V->cvaList == VMM_PHYS2VIRT_INFORMATION_MAX_PROCESS_RESULT) { return; }
    }
}

VOID MmARM64_Phys2VirtGetInformation(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess, _Inout_ PVMMOB_PHYS2VIRT_INFORMATION pP2V)
{
    PVMMOB_CACHE_MEM pObPX;
    if((pP2V->cvaList == VMM_PHYS2VIRT_INFORMATION_MAX_PROCESS_RESULT) || (pP2V->paTarget > H->dev.paMax)) { return; }
    pObPX = VmmTlbGetPageTable(H, pProcess->paDTB, FALSE);
    if(!pObPX) { return; }
    MmARM64_Phys2VirtGetInformation_Index(H, pProcess, 0, 4, pObPX->pqw, H->dev.paMax, pP2V);
    Ob_DECREF(pObPX);
}

VOID MmARM64_Close(_In_ VMM_HANDLE H)
{
    H->vmm.f32 = FALSE;
    H->vmm.tpMemoryModel = VMM_MEMORYMODEL_NA;
    ZeroMemory(&H->vmm.fnMemoryModel, sizeof(VMM_MEMORYMODEL_FUNCTIONS));
}

VOID MmARM64_Initialize(_In_ VMM_HANDLE H)
{
    PVMM_MEMORYMODEL_FUNCTIONS pfnsMemoryModel = &H->vmm.fnMemoryModel;
    if(pfnsMemoryModel->pfnClose) {
        pfnsMemoryModel->pfnClose(H);
    }
    pfnsMemoryModel->pfnClose = MmARM64_Close;
    pfnsMemoryModel->pfnVirt2Phys = MmARM64_Virt2Phys;
    pfnsMemoryModel->pfnVirt2PhysEx = MmARM64_Virt2PhysEx;
    pfnsMemoryModel->pfnVirt2PhysVadEx = MmARM64_Virt2PhysVadEx;
    pfnsMemoryModel->pfnVirt2PhysGetInformation = MmARM64_Virt2PhysGetInformation;
    pfnsMemoryModel->pfnPhys2VirtGetInformation = MmARM64_Phys2VirtGetInformation;
    pfnsMemoryModel->pfnPteMapInitialize = MmARM64_PteMapInitialize;
    pfnsMemoryModel->pfnTlbSpider = MmARM64_TlbSpider;
    pfnsMemoryModel->pfnTlbPageTableVerify = MmARM64_TlbPageTableVerify;
    H->vmm.tpMemoryModel = VMM_MEMORYMODEL_ARM64;
    H->vmm.f32 = FALSE;
}
