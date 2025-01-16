// mm_pfn.c : implementation of Windows PFN (page frame number) functionality and
//            related physical memory functionality.
//
// (c) Ulf Frisk, 2020-2025
// Author: Ulf Frisk, pcileech@frizk.net
//

#include "mm.h"
#include "mm_pfn.h"
#include "../pdb.h"

typedef struct tdMMPFN_CONTEXT {
    BOOL fValid;
    SRWLOCK LockSRW;
    QWORD vaPfnDatabase;
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
} MMPFN_CONTEXT, *PMMPFN_CONTEXT;

#define MMPFN_PFN_TO_VA(ctx, i)     (ctx->vaPfnDatabase + (QWORD)i * ctx->_MMPFN.cb)

VOID MmPfn_Close(_In_ VMM_HANDLE H)
{
    PMMPFN_CONTEXT ctx = (PMMPFN_CONTEXT)H->vmm.pMmPfnContext;
    if(!ctx) { return; }
    H->vmm.pMmPfnContext = NULL;
    Ob_DECREF(ctx->pObCProcTableDTB);
    LocalFree(ctx);
}

VOID MmPfn_Refresh(_In_ VMM_HANDLE H)
{
    PMMPFN_CONTEXT ctx = (PMMPFN_CONTEXT)H->vmm.pMmPfnContext;
    if(ctx) {
        ObContainer_SetOb(ctx->pObCProcTableDTB, NULL);
    }
}

VOID MmPfn_InitializeContext_StaticX64(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pSystemProcess, _In_ PMMPFN_CONTEXT ctx)
{
    DWORD iPte, dwVersionBuild = H->vmm.kernel.dwVersionBuild;
    QWORD iPfnSystem, vaPteSystem, paDtbSystem, vaDtbSystem;
    POB_SET psvaOb = NULL;
    PVMMOB_MAP_PTE pObMapPte = NULL;
    if(dwVersionBuild < 6000) { return; }
    // 1: static offsets
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
    if(dwVersionBuild < 14393) {
        ctx->fValid = TRUE;
        return;
    }
    // 2: MmPfnDatabase virtual address is randomized on 14393+
    //    Search for candidates amongst PTEs starting at 4GB boundaries:
    //    Verify candidates by using known kernel PML4 PFN as oracle:
    if(!VmmMap_GetPte(H, pSystemProcess, &pObMapPte, FALSE)) { goto fail; }
    if(!(psvaOb = ObSet_New(H))) { goto fail; }
    // 2.1: search for candidates starting 4GB boundaries:
    iPfnSystem = H->vmm.kernel.paDTB >> 12;
    for(iPte = 0; iPte < pObMapPte->cMap; iPte++) {
        if(!(DWORD)pObMapPte->pMap[iPte].vaBase) {
            ObSet_Push(psvaOb, pObMapPte->pMap[iPte].vaBase + iPfnSystem * ctx->_MMPFN.cb);
        }
    }
    // 2.2: verify candidate is correct by using kernel PML4 PTE as oracle:
    VmmCachePrefetchPages3(H, pSystemProcess, psvaOb, ctx->_MMPFN.cb, 0);
    while((vaPteSystem = ObSet_Pop(psvaOb))) {
        if(VmmRead(H, pSystemProcess, vaPteSystem + ctx->_MMPFN.oPteAddress, (PBYTE)&vaDtbSystem, 8) && VMM_KADDR64_8(vaDtbSystem)) {
            vaDtbSystem = vaDtbSystem & ~0xfff;
            if(VmmVirt2Phys(H, pSystemProcess, vaDtbSystem, &paDtbSystem) && (paDtbSystem == pSystemProcess->paDTB)) {
                ctx->vaPfnDatabase = vaPteSystem - iPfnSystem * ctx->_MMPFN.cb;
                ctx->fValid = TRUE;
                break;
            }
        }
    }
fail:
    Ob_DECREF(pObMapPte);
    Ob_DECREF(psvaOb);
}

VOID MmPfn_InitializeContext(_In_ VMM_HANDLE H)
{
    PMMPFN_CONTEXT ctx = NULL;
    PVMM_PROCESS pObSystemProcess = NULL;
    if(!(pObSystemProcess = VmmProcessGet(H, 4))) { goto fail; }
    if(!(ctx = LocalAlloc(LMEM_ZEROINIT, sizeof(MMPFN_CONTEXT)))) { goto fail; }
    if(!(ctx->pObCProcTableDTB = ObContainer_New())) { goto fail; }
    ctx->iPfnMax = (DWORD)(H->dev.paMax >> 12);
    ctx->fValid = PDB_GetSymbolPTR(H, PDB_HANDLE_KERNEL, "MmPfnDatabase", pObSystemProcess, &ctx->vaPfnDatabase) &&
        PDB_GetTypeSizeShort(H, PDB_HANDLE_KERNEL, "_MMPFN", &ctx->_MMPFN.cb) &&
        PDB_GetTypeChildOffsetShort(H, PDB_HANDLE_KERNEL, "_MMPFN", "OriginalPte", &ctx->_MMPFN.oOriginalPte) &&
        PDB_GetTypeChildOffsetShort(H, PDB_HANDLE_KERNEL, "_MMPFN", "PteAddress", &ctx->_MMPFN.oPteAddress) &&
        PDB_GetTypeChildOffsetShort(H, PDB_HANDLE_KERNEL, "_MMPFN", "u2", &ctx->_MMPFN.ou2) &&
        PDB_GetTypeChildOffsetShort(H, PDB_HANDLE_KERNEL, "_MMPFN", "u3", &ctx->_MMPFN.ou3) &&
        PDB_GetTypeChildOffsetShort(H, PDB_HANDLE_KERNEL, "_MMPFN", "u4", &ctx->_MMPFN.ou4);
    if(!ctx->fValid && (H->vmm.tpMemoryModel == VMM_MEMORYMODEL_X64)) {
        MmPfn_InitializeContext_StaticX64(H, pObSystemProcess, ctx);
    }
    H->vmm.pMmPfnContext = ctx;
fail:
    Ob_DECREF(pObSystemProcess);
    if(ctx && (ctx != H->vmm.pMmPfnContext)) {
        Ob_DECREF(ctx->pObCProcTableDTB);
        LocalFree(ctx);
    }
}

_Success_(return != NULL)
PMMPFN_CONTEXT MmPfn_GetContext(_In_ VMM_HANDLE H)
{
    PMMPFN_CONTEXT ctx;
    static SRWLOCK LockSRW = SRWLOCK_INIT;
    if(!H->vmm.pMmPfnContext) {
        AcquireSRWLockExclusive(&LockSRW);
        if(!H->vmm.pMmPfnContext) {
            MmPfn_InitializeContext(H);
        }
        ReleaseSRWLockExclusive(&LockSRW);
    }
    ctx = (PMMPFN_CONTEXT)H->vmm.pMmPfnContext;
    return (ctx && ctx->fValid) ? ctx : NULL;
}

/*
* Create a new process data table sorted on DTB PFN.
* CALLER DECREF: return
* -- H
* -- ctx
* -- return
*/
POB_MAP MmPfn_ProcDTB_Create(_In_ VMM_HANDLE H, _In_ PMMPFN_CONTEXT ctx)
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
DWORD MmPfn_GetPidFromDTB(_In_ VMM_HANDLE H, _In_ PMMPFN_CONTEXT ctx, _In_ PVMM_PROCESS pSystemProcess, _In_ QWORD qwPfnDTB)
{
    DWORD dwPID = 0;
    POB_MAP pmObDtbPfn2Pid = NULL;
    if(!(pmObDtbPfn2Pid = ObContainer_GetOb(ctx->pObCProcTableDTB))) {
        AcquireSRWLockExclusive(&ctx->LockSRW);
        if(!(pmObDtbPfn2Pid = ObContainer_GetOb(ctx->pObCProcTableDTB))) {
            pmObDtbPfn2Pid = MmPfn_ProcDTB_Create(H, ctx);
            ObContainer_SetOb(ctx->pObCProcTableDTB, pmObDtbPfn2Pid);
        }
        ReleaseSRWLockExclusive(&ctx->LockSRW);
    }
    dwPID = 0x7fffffff & (DWORD)(SIZE_T)ObMap_GetByKey(pmObDtbPfn2Pid, qwPfnDTB);
    Ob_DECREF(pmObDtbPfn2Pid);
    return dwPID;
}

VOID MmPfn_Map_GetPfn_GetVaX64(_In_ VMM_HANDLE H, _In_ PMMPFN_CONTEXT ctx, _In_ PVMM_PROCESS pSystemProcess, _In_ POB_SET psPte, _In_ POB_SET psPrefetch, _In_ BYTE iPML)
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

VOID MmPfn_Map_GetPfn_GetVaX86PAE(_In_ VMM_HANDLE H, _In_ PMMPFN_CONTEXT ctx, _In_ PVMM_PROCESS pSystemProcess, _In_ POB_SET psPte, _In_ POB_SET psPrefetch, _In_ BYTE iPML)
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

VOID MmPfn_Map_GetPfn_GetVaX86(_In_ VMM_HANDLE H, _In_ PMMPFN_CONTEXT ctx, _In_ PVMM_PROCESS pSystemProcess, _In_ POB_SET psPte, _In_ POB_SET psPrefetch)
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
    PMMPFN_CONTEXT ctx;
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
    // initialization
    if(!(ctx = MmPfn_GetContext(H))) { goto fail; }
    if(!(cPfn = ObSet_Size(psPfn))) { goto fail; }
    if(!(pObSystemProcess = VmmProcessGet(H, 4))) { goto fail; }
    if(!(psObPrefetch = ObSet_New(H))) { goto fail; }
    if(!(pObPfnMap = Ob_AllocEx(H, OB_TAG_MAP_PFN, LMEM_ZEROINIT, sizeof(MMPFNOB_MAP) + cPfn * sizeof(MMPFN_MAP_ENTRY), NULL, NULL))) { goto fail; }
    pObPfnMap->cMap = cPfn;
    PageCache.va = 0;
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
        if((H->vmm.tpMemoryModel == VMMDLL_MEMORYMODEL_X64) || (H->vmm.tpMemoryModel == VMMDLL_MEMORYMODEL_ARM64)) {
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

/*
* Retrieve the system PTEs aka DTB PFNs in a fairly optimized way.
* -- H
* -- ppObPfnMap
* -- fExtended = extended information such as process id's.
* -- ppcProgress = optional progress counter to be updated continuously within function.
* -- return
*/
_Success_(return)
BOOL MmPfn_Map_GetPfnSystem(_In_ VMM_HANDLE H, _Out_ PMMPFNOB_MAP *ppObPfnMap, _In_ BOOL fExtended, _Out_opt_ PDWORD ppcProgress)
{
    BOOL f32 = H->vmm.f32;
    BOOL fResult = FALSE;
    BYTE pbDTB[0x1000];
    PMMPFN_CONTEXT ctx;
    DWORD iPfn, cPfnMax, cPfnChunk;
    POB_SET psPfn = NULL, pspaDtb = NULL;
    PVMM_PROCESS pObSystemProcess = NULL;
    QWORD vaPfnPteSystem;
    PMMPFNOB_MAP pObPfnMap = NULL;
    PBYTE pbPfn, pb16M = NULL;
    QWORD pa;
    // 1: initialization
    *ppObPfnMap = NULL;
    if(ppcProgress) { *ppcProgress = 0; }
    if(!(ctx = MmPfn_GetContext(H))) { goto fail; }
    if(!(pObSystemProcess = VmmProcessGet(H, 4))) { goto fail; }
    if(!(psPfn = ObSet_New(H))) { goto fail; }
    if(!(pspaDtb = ObSet_New(H))) { goto fail; }
    if(!(pb16M = LocalAlloc(0, 0x01000000))) { goto fail; }
    // 2: Get System DTB PFN:
    if(!MmPfn_Map_GetPfn(H, (DWORD)(pObSystemProcess->paDTB >> 12), 1, &pObPfnMap, FALSE) || (pObPfnMap->cMap != 1)) { goto fail; }
    vaPfnPteSystem = pObPfnMap->pMap[0].vaPte;
    Ob_DECREF_NULL(&pObPfnMap);
    if(!vaPfnPteSystem) { goto fail; }
    // 3: Get all DTB PFN candidates:
    cPfnMax = (DWORD)(H->dev.paMax >> 12);
    cPfnChunk = 0x01000000 / ctx->_MMPFN.cb;
    for(iPfn = 0; iPfn < cPfnMax; iPfn++) {
        if(iPfn % cPfnChunk == 0) {
            cPfnChunk = min(cPfnChunk, cPfnMax - iPfn);
            VmmRead2(H, pObSystemProcess, ctx->vaPfnDatabase + (QWORD)iPfn * ctx->_MMPFN.cb, pb16M, cPfnChunk * ctx->_MMPFN.cb, VMM_FLAG_ZEROPAD_ON_FAIL);
            if(ppcProgress) { *ppcProgress = min(99, ((100ULL * iPfn) / cPfnMax)); }
        }
        pbPfn = pb16M + (SIZE_T)(iPfn % cPfnChunk) * ctx->_MMPFN.cb;
        if(vaPfnPteSystem != VMM_PTR_OFFSET(f32, pbPfn, ctx->_MMPFN.oPteAddress)) {
            continue;
        }
        if(MmPfnTypeActive != (*(PBYTE)(pbPfn + ctx->_MMPFN.ou3 + 2) & 0x7)) {
            continue;
        }
        ObSet_Push(pspaDtb, (QWORD)iPfn * 0x1000);
    }
    // 4: Validate candidate DTBs:
    VmmCachePrefetchPages(H, NULL, pspaDtb, 0);
    for(iPfn = 0; iPfn < ObSet_Size(pspaDtb); iPfn++) {
        pa = ObSet_Get(pspaDtb, iPfn);
        if(!VmmRead(H, NULL, pa, pbDTB, 0x1000)) { continue; }
        if(!VmmTlbPageTableVerify(H, pbDTB, pa, TRUE)) { continue; }
        ObSet_Push(psPfn, pa >> 12);
    }
    // 5: Retrieve PFNs:
    fResult = MmPfn_Map_GetPfnScatter(H, psPfn, ppObPfnMap, fExtended);
fail:
    LocalFree(pb16M);
    Ob_DECREF(psPfn);
    Ob_DECREF(pspaDtb);
    Ob_DECREF(pObSystemProcess);
    return fResult;
}
