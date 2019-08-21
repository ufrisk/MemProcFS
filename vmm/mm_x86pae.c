// mm_x86pae.c : implementation of the x86 PAE (Physical Address Extension) 32-bit protected mode memory model.
//
// (c) Ulf Frisk, 2018-2019
// Author: Ulf Frisk, pcileech@frizk.net
//
#include "vmm.h"
#include "vmmproc.h"

#define MMX86PAE_MEMMAP_DISPLAYBUFFER_LINE_LENGTH      70
#define MMX86PAE_PTE_IS_TRANSITION(pte, iPML)          ((((pte & 0x0c01) == 0x0800) && (iPML == 1) && ctxVmm && (ctxVmm->tpSystem == VMM_SYSTEM_WINDOWS_X86)) ? ((pte & 0xffffdfff'fffff000) | 0x005) : 0)
#define MMX86PAE_PTE_IS_VALID(pte, iPML)               (pte & 0x01)

/*
* Tries to verify that a loaded page table is correct. If just a bit strange
* bytes/ptes supplied in pb will be altered to look better.
*/
BOOL MmX86PAE_TlbPageTableVerify(_Inout_ PBYTE pb, _In_ QWORD pa, _In_ BOOL fSelfRefReq)
{
    return TRUE;
}

VOID MmX86PAE_TlbSpider_PD_PT(_In_ QWORD pa, _In_ BYTE iPML, _In_ BOOL fUserOnly, _In_ POB_VSET pPageSet)
{
    QWORD i, pte;
    PVMMOB_MEM pObPT = NULL;
    // 1: retrieve from cache, add to staging if not found
    pObPT = VmmCacheGet(VMM_CACHE_TAG_TLB, pa);
    if(!pObPT) {
        ObVSet_Push(pPageSet, pa);
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
        MmX86PAE_TlbSpider_PD_PT(pte & 0x0000fffffffff000, 1, fUserOnly, pPageSet);
    }
    Ob_DECREF(pObPT);
}

VOID MmX86PAE_TlbSpider_PDPT(_In_ QWORD paDTB, _In_ BOOL fUserOnly, _In_ POB_VSET pPageSet)
{
    BOOL fSpiderComplete = TRUE;
    PVMMOB_MEM pObPDPT;
    PBYTE pbPDPT;
    QWORD i, pte;
    // 1: retrieve PDPT
    pObPDPT = VmmTlbGetPageTable(paDTB & 0xfffff000, FALSE);
    if(!pObPDPT) { return; }
    pbPDPT = pObPDPT->pb + (paDTB & 0xfe0);
    // 2: walk through all four (4) PDPTEs
    for(i = 0; i < 0x20; i += 8) {
        pte = *(PQWORD)(pbPDPT + i);
        if(!(pte & 0x01)) { continue; }             // not valid
        if(pte & 0xffff0000000001e6) { continue; }  // RESERVED BITS IN PDPTE
        MmX86PAE_TlbSpider_PD_PT(pte & 0x0000fffffffff000, 2, fUserOnly, pPageSet);
    }
    Ob_DECREF(pObPDPT);
}

/*
* Iterate over PTPT, PD (3 times in total) to first stage uncached pages
* and then commit them to the cache.
*/
VOID MmX86PAE_TlbSpider(_In_ PVMM_PROCESS pProcess)
{
    DWORD i;
    POB_VSET pObPageSet = NULL;
    if(pProcess->fTlbSpiderDone) { return; }
    if(!(pObPageSet = ObVSet_New())) { return; }
    for(i = 0; i < 3; i++) {
        MmX86PAE_TlbSpider_PDPT(pProcess->paDTB, pProcess->fUserOnly, pObPageSet);
        VmmTlbPrefetch(pObPageSet);
    }
    pProcess->fTlbSpiderDone = TRUE;
    Ob_DECREF(pObPageSet);
}

const DWORD MMX86PAE_PAGETABLEMAP_PML_REGION_SIZE[4] = { 0, 12, 21, 30 };
const DWORD MMX86PAE_PAGETABLEMAP_PML_REGION_MASK_PG[4] = { 0, 0xfffff000, 0xffe00000, 0 };
const DWORD MMX86PAE_PAGETABLEMAP_PML_REGION_MASK_AD[4] = { 0, 0xfff, 0x1fffff, 0 };


VOID MmX86PAE_MapInitialize_Index(_In_ PVMM_PROCESS pProcess, _In_ PVMM_MEMMAP_ENTRY pMemMap, _In_ PDWORD pcMemMap, _In_ DWORD vaBase, _In_ BYTE iPML, _In_ QWORD PTEs[512], _In_ BOOL fSupervisorPML, _In_ QWORD paMax)
{
    PVMMOB_MEM pObNextPT;
    DWORD i, va;
    QWORD pte;
    BOOL fUserOnly, fNextSupervisorPML, fTransition = FALSE;
    PVMM_MEMMAP_ENTRY pMemMapEntry = pMemMap + *pcMemMap - 1;
    fUserOnly = pProcess->fUserOnly;
    for(i = 0; i < 512; i++) {
        if((iPML == 3) && (i > 3)) { break; }                   // MAX 4 ENTRIES IN PDPT
        pte = PTEs[i];
        if(!MMX86PAE_PTE_IS_VALID(pte, iPML)) {
            if(pte && MMX86PAE_PTE_IS_TRANSITION(pte, iPML)) {
                pte = MMX86PAE_PTE_IS_TRANSITION(pte, iPML);    // TRANSITION PAGE
                fTransition = TRUE;
            } else {
                continue;                                       // INVALID
            }
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
                    ((va != pMemMapEntry->AddrBase + (pMemMapEntry->cPages << 12))) && !fTransition) {
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
        Ob_DECREF(pObNextPT);
        pMemMapEntry = pMemMap + *pcMemMap - 1;
    }
}

VOID MmX86PAE_MapCloseObCallback(_In_ PVOID pVmmOb)
{
    PVMMOB_MEMMAP pObMemMap = (PVMMOB_MEMMAP)pVmmOb;
    if(pObMemMap->pObDisplay) {
        Ob_DECREF(pObMemMap->pObDisplay);
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
        Ob_DECREF(pObPDPT);
    }
    // allocate VmmOb depending on result
    pObMemMap = Ob_Alloc('MM', 0, sizeof(VMMOB_MEMMAP) + cMemMap * sizeof(VMM_MEMMAP_ENTRY), MmX86PAE_MapCloseObCallback, NULL);
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
                Ob_DECREF(pObModuleMap);
            }
        }
        if(!pProcess->pObMemMap->fTagScan && (flags & VMM_MEMMAP_FLAG_SCAN)) {
            pProcess->pObMemMap->fTagScan = TRUE;
            VmmProc_ScanTagsMemMap(pProcess);
        }
        LeaveCriticalSection(&pProcess->LockUpdate);
    }
    *ppObMemMap = Ob_INCREF(pProcess->pObMemMap);
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
        *ppObDisplay = Ob_INCREF(pProcess->pObMemMap->pObDisplay);
        return TRUE;
    }
    // create new memory map display data
    EnterCriticalSection(&pProcess->LockUpdate);
    if(!pProcess->pObMemMap->pObDisplay) {
        if(MmX86PAE_MapGetEntries(pProcess, flags, &pObMemMap)) {
            pObDisplay = Ob_Alloc('MD', LMEM_ZEROINIT, pObMemMap->cbDisplay, NULL, NULL);
            if(pObDisplay) {
                for(i = 0; i < pObMemMap->cMap; i++) {
                    if(o + MMX86PAE_MEMMAP_DISPLAYBUFFER_LINE_LENGTH > pObMemMap->cbDisplay) {
                        vmmprintf_fn("ERROR: SHOULD NOT HAPPEN! LENGTH DIFFERS #1: %i %i\n", o + MMX86PAE_MEMMAP_DISPLAYBUFFER_LINE_LENGTH, pObMemMap->cbDisplay);
                        Ob_DECREF(pObDisplay);
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
                    Ob_DECREF(pObDisplay);
                    pObDisplay = NULL;
                    goto fail;
                }
                pObDisplay->pbData[o - 1] = '\n';
            }
        }
        pProcess->pObMemMap->pObDisplay = pObDisplay;
    }
fail:
    Ob_DECREF(pObMemMap);
    LeaveCriticalSection(&pProcess->LockUpdate);
    if(pProcess->pObMemMap->pObDisplay) {
        *ppObDisplay = Ob_INCREF(pProcess->pObMemMap->pObDisplay);
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
        if(i > 3) {                                         // MAX 4 ENTRIES IN PDPT
            Ob_DECREF(pObPTEs);
            return FALSE;
        }                     
        pbPTEs = pObPTEs->pb + (paPT & 0xfe0);              // ADJUST PDPT TO 32-BYTE BOUNDARY
        pte = ((PQWORD)pbPTEs)[i];
        Ob_DECREF(pObPTEs);
        if(!(pte & 0x01)) { return FALSE; }                 // NOT VALID
        if(pte & 0xffff0000000001e6) { return FALSE; }      // RESERVED BITS IN PDPTE
        return MmX86PAE_Virt2Phys(pte, fUserOnly, 2, va, ppa);
    }
    // PT or PD
    pte = pObPTEs->pqw[i];
    Ob_DECREF(pObPTEs);
    if(!MMX86PAE_PTE_IS_VALID(pte, iPML)) {
        if(pte && MMX86PAE_PTE_IS_TRANSITION(pte, iPML)) {
            pte = MMX86PAE_PTE_IS_TRANSITION(pte, iPML);    // TRANSITION
        } else {
            if(iPML == 1) { *ppa = pte; }                   // NOT VALID
            return FALSE;
        }
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
    pObNextPT = VmmTlbGetPageTable(pte & 0x0000fffffffff000, FALSE);
    if(!pObNextPT) { return; }
    pVirt2PhysInfo->pas[iPML - 1] = pte & 0x0000fffffffff000;
    MmX86PAE_Virt2PhysGetInformation_DoWork(pProcess, pVirt2PhysInfo, iPML - 1, pObNextPT->pqw);
    Ob_DECREF(pObNextPT);
}

VOID MmX86PAE_Virt2PhysGetInformation(_Inout_ PVMM_PROCESS pProcess, _Inout_ PVMM_VIRT2PHYS_INFORMATION pVirt2PhysInfo)
{
    QWORD va;
    PVMMOB_MEM pObPDPT;
    if(pVirt2PhysInfo->va > 0xffffffff) { return; }
    va = pVirt2PhysInfo->va;
    ZeroMemory(pVirt2PhysInfo, sizeof(VMM_VIRT2PHYS_INFORMATION));
    pVirt2PhysInfo->tpMemoryModel = VMM_MEMORYMODEL_X86PAE;
    pVirt2PhysInfo->va = va;
    pVirt2PhysInfo->pas[3] = pProcess->paDTB;
    pObPDPT = VmmTlbGetPageTable(pProcess->paDTB & 0xfffff000, FALSE);
    if(!pObPDPT) { return; }
    MmX86PAE_Virt2PhysGetInformation_DoWork(pProcess, pVirt2PhysInfo, 3, (PQWORD)(pObPDPT->pb + (pProcess->paDTB & 0xfe0)));
    Ob_DECREF(pObPDPT);
}

VOID MmX86PAE_Phys2VirtGetInformation_Index(_In_ PVMM_PROCESS pProcess, _In_ DWORD vaBase, _In_ BYTE iPML, _In_ QWORD PTEs[512], _In_ QWORD paMax, _Inout_ PVMMOB_PHYS2VIRT_INFORMATION pP2V)
{
    BOOL fUserOnly;
    QWORD pte;
    DWORD i, va;
    PVMMOB_MEM pObNextPT;
    if(!pProcess->fTlbSpiderDone) {
        VmmTlbSpider(pProcess);
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
        pObNextPT = VmmTlbGetPageTable(pte & 0x0000fffffffff000, FALSE);
        if(!pObNextPT) { continue; }
        MmX86PAE_Phys2VirtGetInformation_Index(pProcess, va, iPML - 1, pObNextPT->pqw, paMax, pP2V);
        Ob_DECREF(pObNextPT);
        if(pP2V->cvaList == VMM_PHYS2VIRT_INFORMATION_MAX_PROCESS_RESULT) { return; }
    }
}

VOID MmX86PAE_Phys2VirtGetInformation(_In_ PVMM_PROCESS pProcess, _Inout_ PVMMOB_PHYS2VIRT_INFORMATION pP2V)
{
    PVMMOB_MEM pObPDPT;
    if((pP2V->cvaList == VMM_PHYS2VIRT_INFORMATION_MAX_PROCESS_RESULT) || (pP2V->paTarget > ctxMain->dev.paMax)) { return; }
    pObPDPT = VmmTlbGetPageTable(pProcess->paDTB & ~0xfff, FALSE);
    if(!pObPDPT) { return; }
    MmX86PAE_Phys2VirtGetInformation_Index(pProcess, 0, 3, (PQWORD)(pObPDPT->pb + (pProcess->paDTB & 0xfe0)), ctxMain->dev.paMax, pP2V);
    Ob_DECREF(pObPDPT);
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
    ctxVmm->fnMemoryModel.pfnPhys2VirtGetInformation = MmX86PAE_Phys2VirtGetInformation;
    ctxVmm->fnMemoryModel.pfnMapInitialize = MmX86PAE_MapInitialize;
    ctxVmm->fnMemoryModel.pfnMapTag = MmX86PAE_MapTag;
    ctxVmm->fnMemoryModel.pfnMapGetEntries = MmX86PAE_MapGetEntries;
    ctxVmm->fnMemoryModel.pfnMapGetDisplay = MmX86PAE_MapGetDisplay;
    ctxVmm->fnMemoryModel.pfnTlbSpider = MmX86PAE_TlbSpider;
    ctxVmm->fnMemoryModel.pfnTlbPageTableVerify = MmX86PAE_TlbPageTableVerify;
    ctxVmm->tpMemoryModel = VMM_MEMORYMODEL_X86PAE;
    ctxVmm->f32 = TRUE;
}
