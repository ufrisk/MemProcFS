// mm_pfn.c : implementation of Windows PFN (page frame number) functionality and
//            related physical memory functionality.
//
// (c) Ulf Frisk, 2020-2022
// Author: Ulf Frisk, pcileech@frizk.net
//
#include "vmm.h"
#include "mm_pfn.h"
#include "pdb.h"
#include "util.h"

typedef struct tdOB_MMPFN_CONTEXT {
    OB ObHdr;
    QWORD vaPfnDatabase;
    CRITICAL_SECTION Lock;
    POB_CONTAINER pObCProcTableDTB;
    struct {
        WORD cb;
        WORD oOriginalPte;
        WORD oPteAddress;
        WORD ou2;
        WORD ou3;
        WORD ou4;
    } _MMPFN;
    DWORD iPfnMax;
} OB_MMPFN_CONTEXT, *POB_MMPFN_CONTEXT;

#define MMPFN_PFN_TO_VA(ctx, i)     (ctx->vaPfnDatabase + (QWORD)i * ctx->_MMPFN.cb)

VOID MmPfn_CallbackCleanup_ObContext(POB_MMPFN_CONTEXT ctx)
{
    Ob_DECREF(ctx->pObCProcTableDTB);
    DeleteCriticalSection(&ctx->Lock);
}

VOID MmPfn_Refresh(_In_ VMM_HANDLE H)
{
    POB_MMPFN_CONTEXT ctx = (POB_MMPFN_CONTEXT)H->vmm.pObPfnContext;
    if(!ctx) { return; }
    ObContainer_SetOb(ctx->pObCProcTableDTB, NULL);
}

_Success_(return)
BOOL MmPfn_Initialize_X64_Static(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pSystemProcess, _In_ POB_MMPFN_CONTEXT ctx)
{
    DWORD i, j, dwVersionBuild = H->vmm.kernel.dwVersionBuild;
    PVMMOB_MAP_PTE pObMapPte = NULL;
    PVMM_MAP_PTEENTRY pe1, pe2;
    if(dwVersionBuild < 6000) { return FALSE; }
    ctx->vaPfnDatabase = 0xFFFFFA8000000000;
    ctx->_MMPFN.oOriginalPte = 0x020;
    ctx->_MMPFN.oPteAddress = 0x010;
    ctx->_MMPFN.cb = 0x030;
    ctx->_MMPFN.ou2 = 0x008;
    ctx->_MMPFN.ou3 = 0x018;
    ctx->_MMPFN.ou4 = 0x028;
    if(dwVersionBuild >= 10240) {
        ctx->_MMPFN.oOriginalPte = 0x010;
        ctx->_MMPFN.oPteAddress = 0x08;
        ctx->_MMPFN.ou2 = 0x018;
        ctx->_MMPFN.ou3 = 0x020;
    }
    if(dwVersionBuild < 14393) { return TRUE; }
    // search for MmPfnDatabase virtual address on 14393+
    if(VmmMap_GetPte(H, pSystemProcess, &pObMapPte, FALSE) && pObMapPte->cMap) {
        for(i = pObMapPte->cMap; i; i--) {
            pe1 = pObMapPte->pMap + i;
            if(pe1->cPages > 0x10000000) {
                for(j = i; j; j--) {
                    pe2 = pObMapPte->pMap + j;
                    if((pe1->vaBase & 0xfffffff000000000) != (pe2->vaBase & 0xfffffff000000000)) { break; }
                    if((pe2->vaBase & 0x0000000fffffffff) == 0) {
                        ctx->vaPfnDatabase = pe2->vaBase;
                        Ob_DECREF(pObMapPte);
                        return TRUE;
                    }
                }
            }
        }
    }
    Ob_DECREF(pObMapPte);
    return FALSE;
}

VOID MmPfn_Initialize(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pSystemProcess)
{
    BOOL f;
    POB_MMPFN_CONTEXT ctx;
    if(!(ctx = Ob_AllocEx(H, OB_TAG_PFN_CONTEXT, LMEM_ZEROINIT, sizeof(OB_MMPFN_CONTEXT), (OB_CLEANUP_CB)MmPfn_CallbackCleanup_ObContext, NULL))) { return; }
    InitializeCriticalSection(&ctx->Lock);
    ctx->pObCProcTableDTB = ObContainer_New();
    f = PDB_GetSymbolPTR(H, PDB_HANDLE_KERNEL, "MmPfnDatabase", pSystemProcess, &ctx->vaPfnDatabase) &&
        PDB_GetTypeSizeShort(H, PDB_HANDLE_KERNEL, "_MMPFN", &ctx->_MMPFN.cb) &&
        PDB_GetTypeChildOffsetShort(H, PDB_HANDLE_KERNEL, "_MMPFN", "OriginalPte", &ctx->_MMPFN.oOriginalPte) &&
        PDB_GetTypeChildOffsetShort(H, PDB_HANDLE_KERNEL, "_MMPFN", "PteAddress", &ctx->_MMPFN.oPteAddress) &&
        PDB_GetTypeChildOffsetShort(H, PDB_HANDLE_KERNEL, "_MMPFN", "u2", &ctx->_MMPFN.ou2) &&
        PDB_GetTypeChildOffsetShort(H, PDB_HANDLE_KERNEL, "_MMPFN", "u3", &ctx->_MMPFN.ou3) &&
        PDB_GetTypeChildOffsetShort(H, PDB_HANDLE_KERNEL, "_MMPFN", "u4", &ctx->_MMPFN.ou4);
    if(!f && (H->vmm.tpMemoryModel == VMM_MEMORYMODEL_X64)) {
        f = MmPfn_Initialize_X64_Static(H, pSystemProcess, ctx);
    }
    if(f && ctx->pObCProcTableDTB) {
        ctx->iPfnMax = (DWORD)(H->dev.paMax >> 12);
        H->vmm.pObPfnContext = Ob_INCREF(ctx);
    }
    Ob_DECREF(ctx);
}

/*
* Create a new process data table sorted on DTB PFN.
* CALLER DECREF: return
* -- H
* -- ctx
* -- return
*/
POB_MAP MmPfn_ProcDTB_Create(_In_ VMM_HANDLE H, _In_ POB_MMPFN_CONTEXT ctx)
{
    POB_MAP pmOb = NULL;
    PVMM_PROCESS pObProcess = NULL;
    if(!(pmOb = ObMap_New(H, OB_CACHEMAP_FLAGS_OBJECT_VOID))) { return NULL; }
    while((pObProcess = VmmProcessGetNext(H, pObProcess, VMM_FLAG_PROCESS_SHOW_TERMINATED))) {
        if(pObProcess->paDTB_Kernel) {
            ObMap_Push(pmOb, pObProcess->paDTB_Kernel >> 12, (PVOID)(SIZE_T)pObProcess->dwPID);
        }
        if(pObProcess->paDTB_UserOpt) {
            ObMap_Push(pmOb, pObProcess->paDTB_UserOpt >> 12, (PVOID)(SIZE_T)(pObProcess->dwPID | 0x80000000));
        }
    }
    return pmOb;
}

/*
* Retrieve a process PID given a prcess DTB pfn.
* -- H
* -- ctx
* -- return
*/
DWORD MmPfn_GetPidFromDTB(_In_ VMM_HANDLE H, _In_ POB_MMPFN_CONTEXT ctx, _In_ PVMM_PROCESS pSystemProcess, _In_ QWORD qwPfnDTB)
{
    DWORD dwPID = 0;
    POB_MAP pmObDtbPfn2Pid = NULL;
    if(!(pmObDtbPfn2Pid = ObContainer_GetOb(ctx->pObCProcTableDTB))) {
        EnterCriticalSection(&ctx->Lock);
        if(!(pmObDtbPfn2Pid = ObContainer_GetOb(ctx->pObCProcTableDTB))) {
            pmObDtbPfn2Pid = MmPfn_ProcDTB_Create(H, ctx);
        }
        LeaveCriticalSection(&ctx->Lock);
    }
    dwPID = 0x7fffffff & (DWORD)(SIZE_T)ObMap_GetByKey(pmObDtbPfn2Pid, qwPfnDTB);
    Ob_DECREF(pmObDtbPfn2Pid);
    return dwPID;
}

VOID MmPfn_Map_GetPfn_GetVaX64(_In_ VMM_HANDLE H, _In_ POB_MMPFN_CONTEXT ctx, _In_ PVMM_PROCESS pSystemProcess, _In_ POB_SET psPte, _In_ POB_SET psPrefetch, _In_ BYTE iPML)
{
    BOOL f;
    BYTE tp, pbPfn[0x30];
    PMMPFN_MAP_ENTRY pe;
    DWORD i, c, iPfnNext;
    QWORD pa, vaPfn;
    struct {
        QWORD va;
        BYTE pb[0x1000];
    } PageCache;
restart_new_pml_level:
    PageCache.va = 0;
    VmmCachePrefetchPages(H, pSystemProcess, psPrefetch, 0);
    ObSet_Clear(psPrefetch);
    for(i = 0, c = ObSet_Size(psPte); i < c; i++) {
        pe = (PMMPFN_MAP_ENTRY)ObSet_Get(psPte, i);
        if(!pe || !pe->AddressInfo.va) { continue; }
        vaPfn = MMPFN_PFN_TO_VA(ctx, pe->AddressInfo.dwPfnPte[iPML]);
        if(((vaPfn & 0xfff) + ctx->_MMPFN.cb) > 0x1000) {
            // page-boundary pfn read -> perform single pfn read:
            f = VmmRead(H, pSystemProcess, vaPfn, pbPfn, ctx->_MMPFN.cb);
        } else {
            // in-page pfn read -> perform page buffered read:
            f = TRUE;
            if(PageCache.va != (vaPfn & ~0xfff)) {
                PageCache.va = vaPfn & ~0xfff;
                if(!VmmRead(H, pSystemProcess, PageCache.va, PageCache.pb, 0x1000)) {
                    PageCache.va = 0;
                    f = FALSE;
                }
            }
            memcpy(pbPfn, PageCache.pb + (vaPfn & 0xfff), ctx->_MMPFN.cb);
        }
        f = f &&
            (tp = (pbPfn[ctx->_MMPFN.ou3 + 2] & 0x7)) &&                                    // "PageLocation"
            ((tp == MmPfnTypeActive) || (pe->PageLocation == MmPfnTypeStandby) || (tp == MmPfnTypeModified) || (tp == MmPfnTypeModifiedNoWrite)) &&
            (iPfnNext = *(PDWORD)(pbPfn + ctx->_MMPFN.ou4)) &&                              // "Containing" PTE
            (iPfnNext <= ctx->iPfnMax) && (pe->AddressInfo.dwPfnPte[iPML + 1] = iPfnNext);
        if(f) {
            pe->AddressInfo.va += (*(PQWORD)(pbPfn + ctx->_MMPFN.oPteAddress) & 0xff8) << (iPML + 1) * 9;
            if(iPML == 3) {
                pe->AddressInfo.va = pe->AddressInfo.va & ~0xfff;
                if(pe->AddressInfo.va >> 47) {
                    pe->AddressInfo.va = pe->AddressInfo.va | 0xffff000000000000;
                }
                if(pe->AddressInfo.va) {
                    pe->AddressInfo.dwPid = MmPfn_GetPidFromDTB(H, ctx, pSystemProcess, (QWORD)pe->AddressInfo.dwPfnPte[4]);
                    if(pe->AddressInfo.dwPid && (pe->AddressInfo.dwPid != 4)) {
                        pe->tpExtended = MmPfnExType_ProcessPrivate;
                    }
                    if(!pe->AddressInfo.dwPid && (!VmmVirt2Phys(H, pSystemProcess, pe->AddressInfo.va, &pa) || (pe->dwPfn != pa >> 12))) {
                        pe->AddressInfo.va = 0;
                    }
                    if(pe->AddressInfo.va && (pe->AddressInfo.dwPfnPte[3] == pe->AddressInfo.dwPfnPte[4])) {
                        pe->tpExtended = MmPfnExType_PageTable;
                    }
                }
            } else {
                ObSet_Push_PageAlign(psPrefetch, MMPFN_PFN_TO_VA(ctx, iPfnNext), ctx->_MMPFN.cb);
            }
        } else {
            pe->AddressInfo.va = 0;
        }
    }
    if(iPML < 3) {
        iPML++;
        goto restart_new_pml_level;
    }
}

VOID MmPfn_Map_GetPfn_GetVaX86PAE(_In_ VMM_HANDLE H, _In_ POB_MMPFN_CONTEXT ctx, _In_ PVMM_PROCESS pSystemProcess, _In_ POB_SET psPte, _In_ POB_SET psPrefetch, _In_ BYTE iPML)
{
    BOOL f;
    BYTE tp, pbPfn[0x30];
    PMMPFN_MAP_ENTRY pe;
    QWORD pa;
    DWORD i, c, iPfnNext, cbRead, dwPidEx, iPfn, dwPid;
    VmmCachePrefetchPages(H, pSystemProcess, psPrefetch, 0);
    ObSet_Clear(psPrefetch);
    for(i = 0, c = ObSet_Size(psPte); i < c; i++) {
        pe = (PMMPFN_MAP_ENTRY)ObSet_Get(psPte, i);
        if(!pe || !pe->AddressInfo.va) { continue; }
        if(iPML == 2) {
            dwPidEx = MmPfn_GetPidFromDTB(H, ctx, pSystemProcess, (QWORD)pe->AddressInfo.dwPfnPte[2]);
            dwPid = dwPidEx & 0x3fffffff;
            iPfn = dwPidEx >> 30;
            if(dwPid && (dwPid != 4) && (iPfn < 2)) {
                pe->AddressInfo.dwPid = dwPid;
                pe->tpExtended = MmPfnExType_ProcessPrivate;
                pe->AddressInfo.va = (pe->AddressInfo.va & ~0xfff) + ((QWORD)iPfn << 30);
            } else {
                pe->AddressInfo.va = (pe->AddressInfo.va & ~0xfff) + ((QWORD)iPfn << 30);
                if(!VmmVirt2Phys(H, pSystemProcess, pe->AddressInfo.va, &pa) || (pe->dwPfn != pa >> 12)) {
                    pe->AddressInfo.va = 0;
                }
            }
            continue;
        }
        VmmReadEx(H, pSystemProcess, MMPFN_PFN_TO_VA(ctx, pe->AddressInfo.dwPfnPte[iPML]), pbPfn, ctx->_MMPFN.cb, &cbRead, 0);
        f = cbRead &&
            (tp = (pbPfn[ctx->_MMPFN.ou3 + 2] & 0x7)) &&                                    // "PageLocation"
            ((tp == MmPfnTypeActive) || (pe->PageLocation == MmPfnTypeStandby) || (tp == MmPfnTypeModified) || (tp == MmPfnTypeModifiedNoWrite)) &&
            (iPfnNext = *(PDWORD)(pbPfn + ctx->_MMPFN.ou4) & 0x00ffffff) &&                 // "Containing" PTE
            (iPfnNext <= ctx->iPfnMax) && (pe->AddressInfo.dwPfnPte[iPML + 1] = iPfnNext);
        if(f) {
            pe->AddressInfo.va += (QWORD)((*(PDWORD)(pbPfn + ctx->_MMPFN.oPteAddress) & 0xff8)) << (iPML + 1) * 9;
            ObSet_Push_PageAlign(psPrefetch, MMPFN_PFN_TO_VA(ctx, iPfnNext), ctx->_MMPFN.cb);
        } else {
            pe->AddressInfo.va = 0;
        }
    }
    if(iPML < 2) {
        MmPfn_Map_GetPfn_GetVaX86PAE(H, ctx, pSystemProcess, psPte, psPrefetch, iPML + 1);
    }
}

VOID MmPfn_Map_GetPfn_GetVaX86(_In_ VMM_HANDLE H, _In_ POB_MMPFN_CONTEXT ctx, _In_ PVMM_PROCESS pSystemProcess, _In_ POB_SET psPte, _In_ POB_SET psPrefetch)
{
    BOOL f;
    BYTE tp, pbPfn[0x30];
    PMMPFN_MAP_ENTRY pe;
    DWORD i, c, iPfnNext, cbRead, dwPID, dwPte;
    QWORD pa;
    PVMMOB_CACHE_MEM pObPD = NULL;
    VmmCachePrefetchPages(H, pSystemProcess, psPrefetch, 0);
    ObSet_Clear(psPrefetch);
    for(i = 0, c = ObSet_Size(psPte); i < c; i++) {
        pe = (PMMPFN_MAP_ENTRY)ObSet_Get(psPte, i);
        if(!pe) { continue; }
        pe->AddressInfo.va = 0;
        VmmReadEx(H, pSystemProcess, MMPFN_PFN_TO_VA(ctx, pe->AddressInfo.dwPfnPte[1]), pbPfn, ctx->_MMPFN.cb, &cbRead, 0);
        f = cbRead &&
            (tp = (pbPfn[ctx->_MMPFN.ou3 + 2] & 0x7)) &&                                    // "PageLocation"
            ((tp == MmPfnTypeActive) || (pe->PageLocation == MmPfnTypeStandby) || (tp == MmPfnTypeModified) || (tp == MmPfnTypeModifiedNoWrite)) &&
            (iPfnNext = *(PDWORD)(pbPfn + ctx->_MMPFN.ou4)) &&                              // "Containing" PTE
            (iPfnNext <= ctx->iPfnMax) && (pe->AddressInfo.dwPfnPte[2] = iPfnNext);
        if(!f) { continue; }
        pe->AddressInfo.va += ((QWORD)(*(PDWORD)(pbPfn + ctx->_MMPFN.oPteAddress) & 0xffc) << 20) + ((pe->vaPte & 0xffc) << 10);
        dwPID = MmPfn_GetPidFromDTB(H, ctx, pSystemProcess, (QWORD)pe->AddressInfo.dwPfnPte[2]);
        if(dwPID && (dwPID != 4)) {
            pe->AddressInfo.dwPid = dwPID;
            pe->tpExtended = MmPfnExType_ProcessPrivate;
        } else {
            if(pe->AddressInfo.dwPfnPte[1] == pe->AddressInfo.dwPfnPte[2]) {
                if((pObPD = VmmTlbGetPageTable(H, (QWORD)pe->AddressInfo.dwPfnPte[2] << 12, FALSE))) {
                    dwPte = pObPD->pdw[pe->AddressInfo.va >> 22];
                    Ob_DECREF_NULL(&pObPD);
                    if(dwPte & 0x01) {
                        pe->tpExtended = ((dwPte & 0x81) == 0x81) ? MmPfnExType_LargePage : MmPfnExType_PageTable;
                    } else {
                        pe->AddressInfo.va = 0;
                    }
                }
            }
            if(!VmmVirt2Phys(H, pSystemProcess, pe->AddressInfo.va, &pa) || (pe->dwPfn != pa >> 12)) {
                pe->AddressInfo.va = 0;
            }
        }
    }
}

_Success_(return)
BOOL MmPfn_Map_GetPfnScatter(_In_ VMM_HANDLE H, _In_ POB_SET psPfn, _Out_ PMMPFNOB_MAP *ppObPfnMap, _In_ BOOL fExtended)
{
    POB_MMPFN_CONTEXT ctx = (POB_MMPFN_CONTEXT)H->vmm.pObPfnContext;
    BOOL f32 = H->vmm.f32;
    BYTE pbPfn[0x30] = { 0 };
    PVMM_PROCESS pObSystemProcess = NULL;
    PMMPFNOB_MAP pObPfnMap = NULL;
    PMMPFN_MAP_ENTRY pe;
    QWORD qw, vaPfn;
    DWORD cPfn, i, tp;
    POB_SET psObEnrichAddress = NULL, psObPrefetch = NULL;
    struct {
        QWORD va;
        BYTE pb[0x1000];
    } PageCache;
    if(!ctx) { goto fail; }
    // initialization
    PageCache.va = 0;
    if(!(cPfn = ObSet_Size(psPfn))) { goto fail; }
    if(!(pObSystemProcess = VmmProcessGet(H, 4))) { goto fail; }
    if(!(psObPrefetch = ObSet_New(H))) { goto fail; }
    if(!(pObPfnMap = Ob_AllocEx(H, OB_TAG_MAP_PFN, LMEM_ZEROINIT, sizeof(MMPFNOB_MAP) + cPfn * sizeof(MMPFN_MAP_ENTRY), NULL, NULL))) { goto fail; }
    pObPfnMap->cMap = cPfn;
    if(fExtended) {
        if(!(psObEnrichAddress = ObSet_New(H))) { goto fail; }
    }
    // translate pfn# to pfn va and prefetch
    for(i = 0; i < cPfn; i++) {
        pe = pObPfnMap->pMap + i;
        pe->dwPfn = (DWORD)ObSet_Get(psPfn, i);
        ObSet_Push_PageAlign(psObPrefetch, MMPFN_PFN_TO_VA(ctx, pe->dwPfn), ctx->_MMPFN.cb);
    }
    VmmCachePrefetchPages(H, pObSystemProcess, psObPrefetch, 0);
    ObSet_Clear(psObPrefetch);
    // iterate and fetch pfns
    for(i = 0; i < cPfn; i++) {
        pe = pObPfnMap->pMap + i;
        if(pe->dwPfn > ctx->iPfnMax) { continue; }
        vaPfn = MMPFN_PFN_TO_VA(ctx, pe->dwPfn);
        if(((vaPfn & 0xfff) + ctx->_MMPFN.cb) > 0x1000) {
            // page-boundary pfn read -> perform single pfn read:
            if(!VmmRead(H, pObSystemProcess, vaPfn, pbPfn, ctx->_MMPFN.cb)) { continue; }
        } else {
            // in-page pfn read -> perform page buffered read:
            if(PageCache.va != (vaPfn & ~0xfff)) {
                PageCache.va = vaPfn & ~0xfff;
                if(!VmmRead(H, pObSystemProcess, PageCache.va, PageCache.pb, 0x1000)) {
                    PageCache.va = 0;
                    continue;
                }
            }
            memcpy(pbPfn, PageCache.pb + (vaPfn & 0xfff), ctx->_MMPFN.cb);
        }
        pe->_u3 = *(PDWORD)(pbPfn + ctx->_MMPFN.ou3);
        qw = *(PQWORD)(pbPfn + ctx->_MMPFN.ou4);
        if(f32) {
            pe->PteFrame = qw & 0x00ffffff;
            pe->PteFrameHigh = (qw >> 20) & 0xf;
            pe->PrototypePte = (qw >> 27) & 0x1;
            pe->PageColor = (qw >> 28) & 0xf;
        } else {
            pe->_u4 = qw;
        }
        pe->vaPte = VMM_PTR_OFFSET(f32, pbPfn, ctx->_MMPFN.oPteAddress);
        pe->OriginalPte = VMM_PTR_OFFSET(f32, pbPfn, ctx->_MMPFN.oOriginalPte);
        tp = pe->PageLocation;
        if(fExtended && ((tp == MmPfnTypeActive) || (tp == MmPfnTypeStandby) || (tp == MmPfnTypeModified) || (tp == MmPfnTypeModifiedNoWrite))) {
            if(!pe->PrototypePte && !pe->PteFrameHigh && (pe->PteFrame <= ctx->iPfnMax)) {
                pe->AddressInfo.va = ((pe->vaPte << 9) & 0x1ff000) | 0xfff;
                pe->AddressInfo.dwPfnPte[1] = pe->PteFrame;
                ObSet_Push(psObEnrichAddress, (QWORD)pe);
                ObSet_Push_PageAlign(psObPrefetch, MMPFN_PFN_TO_VA(ctx, pe->AddressInfo.dwPfnPte[1]), ctx->_MMPFN.cb);
            } else if((tp == MmPfnTypeActive) && (pe->PteFrameHigh == 0xf)) {
                pe->tpExtended = MmPfnExType_DriverLocked;
            } else if(pe->PrototypePte) {
                if(pe->Modified) {
                    pe->tpExtended = MmPfnExType_Shareable;
                } else {
                    pe->tpExtended = MmPfnExType_File;
                }
            }
        } else if((tp == MmPfnTypeZero) || (tp == MmPfnTypeFree) || (tp == MmPfnTypeBad)) {
            pe->tpExtended = MmPfnExType_Unused;
        }
    }
    // encrich result with virtual addresses and additional info
    if(fExtended && ObSet_Size(psObEnrichAddress)) {
        if(H->vmm.tpMemoryModel == VMMDLL_MEMORYMODEL_X64) {
            MmPfn_Map_GetPfn_GetVaX64(H, ctx, pObSystemProcess, psObEnrichAddress, psObPrefetch, 1);
        } else if(H->vmm.tpMemoryModel == VMMDLL_MEMORYMODEL_X86PAE) {
            MmPfn_Map_GetPfn_GetVaX86PAE(H, ctx, pObSystemProcess, psObEnrichAddress, psObPrefetch, 1);
        } else if(H->vmm.tpMemoryModel == VMMDLL_MEMORYMODEL_X86) {
            MmPfn_Map_GetPfn_GetVaX86(H, ctx, pObSystemProcess, psObEnrichAddress, psObPrefetch);
        }
    }
    // fall through to cleanup
    Ob_INCREF(pObPfnMap);
fail:
    Ob_DECREF(pObSystemProcess);
    Ob_DECREF(psObPrefetch);
    Ob_DECREF(psObEnrichAddress);
    *ppObPfnMap = Ob_DECREF(pObPfnMap);
    return *ppObPfnMap ? TRUE : FALSE;
}

_Success_(return)
BOOL MmPfn_Map_GetPfn(_In_ VMM_HANDLE H, _In_ DWORD dwPfnStart, _In_ DWORD cPfn, _Out_ PMMPFNOB_MAP *ppObPfnMap, _In_ BOOL fExtended)
{
    BOOL fResult;
    POB_SET psObPfn;
    QWORD iPfn, iPfnEnd;
    if(!(psObPfn = ObSet_New(H))) { return FALSE; }
    for(iPfn = dwPfnStart, iPfnEnd = (QWORD)dwPfnStart + cPfn; iPfn < iPfnEnd; iPfn++) {
        ObSet_Push(psObPfn, 0x8000000000000000 | iPfn);
    }
    fResult = MmPfn_Map_GetPfnScatter(H, psObPfn, ppObPfnMap, fExtended);
    Ob_DECREF(psObPfn);
    return fResult;
}
