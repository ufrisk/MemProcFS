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

VOID MmPfn_Refresh()
{
    POB_MMPFN_CONTEXT ctx = (POB_MMPFN_CONTEXT)ctxVmm->pObPfnContext;
    if(!ctx) { return; }
    ObContainer_SetOb(ctx->pObCProcTableDTB, NULL);
}

VOID MmPfn_Initialize(_In_ PVMM_PROCESS pSystemProcess)
{
    BOOL f;
    POB_MMPFN_CONTEXT ctx;
    if(!(ctx = Ob_Alloc(OB_TAG_PFN_CONTEXT, LMEM_ZEROINIT, sizeof(OB_MMPFN_CONTEXT), (OB_CLEANUP_CB)MmPfn_CallbackCleanup_ObContext, NULL))) { return; }
    InitializeCriticalSection(&ctx->Lock);
    f = (ctx->pObCProcTableDTB = ObContainer_New()) &&
        PDB_GetSymbolPTR(PDB_HANDLE_KERNEL, "MmPfnDatabase", pSystemProcess, &ctx->vaPfnDatabase) &&
        PDB_GetTypeSizeShort(PDB_HANDLE_KERNEL, "_MMPFN", &ctx->_MMPFN.cb) &&
        PDB_GetTypeChildOffsetShort(PDB_HANDLE_KERNEL, "_MMPFN", "OriginalPte", &ctx->_MMPFN.oOriginalPte) &&
        PDB_GetTypeChildOffsetShort(PDB_HANDLE_KERNEL, "_MMPFN", "PteAddress", &ctx->_MMPFN.oPteAddress) &&
        PDB_GetTypeChildOffsetShort(PDB_HANDLE_KERNEL, "_MMPFN", "u2", &ctx->_MMPFN.ou2) &&
        PDB_GetTypeChildOffsetShort(PDB_HANDLE_KERNEL, "_MMPFN", "u3", &ctx->_MMPFN.ou3) &&
        PDB_GetTypeChildOffsetShort(PDB_HANDLE_KERNEL, "_MMPFN", "u4", &ctx->_MMPFN.ou4) &&
        (ctx->iPfnMax = (DWORD)(ctxMain->dev.paMax >> 12)) &&
        (ctxVmm->pObPfnContext = Ob_INCREF(ctx));
    Ob_DECREF(ctx);
}

/*
* Create a new process data table sorted on DTB PFN.
* CALLER DECREF: return
* -- ctx
* -- return
*/
POB_DATA MmPfn_ProcDTB_Create(_In_ POB_MMPFN_CONTEXT ctx)
{
    SIZE_T i, cPIDs = 0, cEntries;
    POB_DATA pObData = NULL;
    PVMM_PROCESS pObProcess = NULL;
    PVMMOB_CACHE_MEM pObPDPT = NULL;
    QWORD j, qwPte;
    VmmProcessListPIDs(NULL, &cPIDs, 0);
    cEntries = cPIDs * ((ctxVmm->tpMemoryModel == VMM_MEMORYMODEL_X86PAE) ? 4 : 1);
    if(!(pObData = Ob_Alloc(OB_TAG_PFN_PROC_TABLE, LMEM_ZEROINIT, sizeof(OB) + cEntries * sizeof(QWORD), NULL, NULL))) { return NULL; }
    VmmProcessListPIDs(pObData->pdw, &cPIDs, 0);
    for(i = 0; i < cPIDs; i++) {
        if((pObProcess = VmmProcessGet(pObData->pdw[cPIDs - i - 1]))) {
            if((ctxVmm->tpMemoryModel == VMM_MEMORYMODEL_X64) || (ctxVmm->tpMemoryModel == VMM_MEMORYMODEL_X86)) {
                if(pObProcess->fUserOnly) {
                    pObData->pqw[cPIDs - i - 1] = pObProcess->dwPID | (pObProcess->paDTB << 20);
                }
            } else if(ctxVmm->tpMemoryModel == VMM_MEMORYMODEL_X86PAE) {
                if((pObPDPT = VmmTlbGetPageTable(pObProcess->paDTB & ~0xfff, FALSE))) {
                    for(j = 0; j < 4; j++) {
                        if((qwPte = pObPDPT->pqw[((pObProcess->paDTB & 0xfff) >> 3) + j])) {
                            pObData->pqw[(cPIDs - i - 1) * 4 + j] = pObProcess->dwPID | ((qwPte & 0x00000ffffffff000) << 20) | (j << 30);
                        }
                    }
                    Ob_DECREF_NULL(&pObPDPT);
                }
            }
            Ob_DECREF_NULL(&pObProcess);
        }
    }
    qsort(pObData->pqw, cEntries, sizeof(QWORD), Util_qsort_QWORD);
    ObContainer_SetOb(ctx->pObCProcTableDTB, pObData);
    return pObData;
}

int MmPfn_GetPidFromDTB_qfind(_In_ QWORD pvFind, _In_ QWORD pvEntry)
{
    DWORD dwKey = (DWORD)pvFind;
    DWORD dwEntry = (*(PQWORD)pvEntry) >> 32;
    if(dwEntry > dwKey) { return -1; }
    if(dwEntry < dwKey) { return 1; }
    return 0;
}

/*
* Retrieve a process PID given a prcess DTB.
* -- ctx
* -- return
*/
DWORD MmPfn_GetPidFromDTB(_In_ POB_MMPFN_CONTEXT ctx, _In_ PVMM_PROCESS pSystemProcess, _In_ QWORD qwPfnDTB)
{
    DWORD dwPID;
    PVOID pvFind;
    POB_DATA pObData = NULL;
    if(qwPfnDTB == (pSystemProcess->paDTB >> 12)) { return 0; }
    if(!(pObData = ObContainer_GetOb(ctx->pObCProcTableDTB))) {
        EnterCriticalSection(&ctx->Lock);
        if(!(pObData = ObContainer_GetOb(ctx->pObCProcTableDTB))) {
            pObData = MmPfn_ProcDTB_Create(ctx);
        }
        LeaveCriticalSection(&ctx->Lock);
    }
    if(!pObData) { return 0; }
    pvFind = Util_qfind(qwPfnDTB, pObData->ObHdr.cbData / sizeof(QWORD), pObData->pqw, sizeof(QWORD), MmPfn_GetPidFromDTB_qfind);
    dwPID = pvFind ? (DWORD)*(PQWORD)pvFind : 0;
    Ob_DECREF(pObData);
    return dwPID;
}

VOID MmPfn_Map_GetPfn_GetVaX64(_In_ POB_MMPFN_CONTEXT ctx, _In_ PVMM_PROCESS pSystemProcess, _In_ POB_SET psPte, _In_ POB_SET psPrefetch, _In_ BYTE iPML)
{
    BOOL f;
    BYTE tp, pbPfn[0x30];
    PMMPFN_MAP_ENTRY pe;
    DWORD i, c, iPfnNext, cbRead;
    QWORD pa;
    PVMMOB_CACHE_MEM pObPD = NULL;
    VmmCachePrefetchPages(pSystemProcess, psPrefetch, 0);
    ObSet_Clear(psPrefetch);
    for(i = 0, c = ObSet_Size(psPte); i < c; i++) {
        pe = (PMMPFN_MAP_ENTRY)ObSet_Get(psPte, i);
        if(!pe || !pe->AddressInfo.va) { continue; }
        VmmReadEx(pSystemProcess, MMPFN_PFN_TO_VA(ctx, pe->AddressInfo.dwPfnPte[iPML]), pbPfn, ctx->_MMPFN.cb, &cbRead, 0);
        f = cbRead &&
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
                    pe->AddressInfo.dwPid = MmPfn_GetPidFromDTB(ctx, pSystemProcess, (QWORD)pe->AddressInfo.dwPfnPte[4]);
                    if(pe->AddressInfo.dwPid && (pe->AddressInfo.dwPid != 4)) {
                        pe->tpExtended = MmPfnExType_ProcessPrivate;
                    }
                    if(!pe->AddressInfo.dwPid && (!VmmVirt2Phys(pSystemProcess, pe->AddressInfo.va, &pa) || (pe->dwPfn != pa >> 12))) {
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
        MmPfn_Map_GetPfn_GetVaX64(ctx, pSystemProcess, psPte, psPrefetch, iPML + 1);
    }
}

VOID MmPfn_Map_GetPfn_GetVaX86PAE(_In_ POB_MMPFN_CONTEXT ctx, _In_ PVMM_PROCESS pSystemProcess, _In_ POB_SET psPte, _In_ POB_SET psPrefetch, _In_ BYTE iPML)
{
    BOOL f;
    BYTE tp, pbPfn[0x30];
    PMMPFN_MAP_ENTRY pe;
    QWORD pa;
    DWORD i, c, iPfnNext, cbRead, dwPidEx, iPfn, dwPid;
    VmmCachePrefetchPages(pSystemProcess, psPrefetch, 0);
    ObSet_Clear(psPrefetch);
    for(i = 0, c = ObSet_Size(psPte); i < c; i++) {
        pe = (PMMPFN_MAP_ENTRY)ObSet_Get(psPte, i);
        if(!pe || !pe->AddressInfo.va) { continue; }
        if(iPML == 2) {
            dwPidEx = MmPfn_GetPidFromDTB(ctx, pSystemProcess, (QWORD)pe->AddressInfo.dwPfnPte[2]);
            dwPid = dwPidEx & 0x3fffffff;
            iPfn = dwPidEx >> 30;
            if(dwPid && (dwPid != 4) && (iPfn < 2)) {
                pe->AddressInfo.dwPid = dwPid;
                pe->tpExtended = MmPfnExType_ProcessPrivate;
                pe->AddressInfo.va = (pe->AddressInfo.va & ~0xfff) + ((QWORD)iPfn << 30);
            } else {
                pe->AddressInfo.va = (pe->AddressInfo.va & ~0xfff) + ((QWORD)iPfn << 30);
                if(!VmmVirt2Phys(pSystemProcess, pe->AddressInfo.va, &pa) || (pe->dwPfn != pa >> 12)) {
                    pe->AddressInfo.va = 0;
                }
            }
            continue;
        }
        VmmReadEx(pSystemProcess, MMPFN_PFN_TO_VA(ctx, pe->AddressInfo.dwPfnPte[iPML]), pbPfn, ctx->_MMPFN.cb, &cbRead, 0);
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
        MmPfn_Map_GetPfn_GetVaX86PAE(ctx, pSystemProcess, psPte, psPrefetch, iPML + 1);
    }
}

VOID MmPfn_Map_GetPfn_GetVaX86(_In_ POB_MMPFN_CONTEXT ctx, _In_ PVMM_PROCESS pSystemProcess, _In_ POB_SET psPte, _In_ POB_SET psPrefetch)
{
    BOOL f;
    BYTE tp, pbPfn[0x30];
    PMMPFN_MAP_ENTRY pe;
    DWORD i, c, iPfnNext, cbRead, dwPID, dwPte;
    QWORD pa;
    PVMMOB_CACHE_MEM pObPD = NULL;
    VmmCachePrefetchPages(pSystemProcess, psPrefetch, 0);
    ObSet_Clear(psPrefetch);
    for(i = 0, c = ObSet_Size(psPte); i < c; i++) {
        pe = (PMMPFN_MAP_ENTRY)ObSet_Get(psPte, i);
        if(!pe) { continue; }
        pe->AddressInfo.va = 0;
        VmmReadEx(pSystemProcess, MMPFN_PFN_TO_VA(ctx, pe->AddressInfo.dwPfnPte[1]), pbPfn, ctx->_MMPFN.cb, &cbRead, 0);
        f = cbRead &&
            (tp = (pbPfn[ctx->_MMPFN.ou3 + 2] & 0x7)) &&                                    // "PageLocation"
            ((tp == MmPfnTypeActive) || (pe->PageLocation == MmPfnTypeStandby) || (tp == MmPfnTypeModified) || (tp == MmPfnTypeModifiedNoWrite)) &&
            (iPfnNext = *(PDWORD)(pbPfn + ctx->_MMPFN.ou4)) &&                              // "Containing" PTE
            (iPfnNext <= ctx->iPfnMax) && (pe->AddressInfo.dwPfnPte[2] = iPfnNext);
        if(!f) { continue; }
        pe->AddressInfo.va += ((QWORD)(*(PDWORD)(pbPfn + ctx->_MMPFN.oPteAddress) & 0xffc) << 20) + ((pe->vaPte & 0xffc) << 10);
        dwPID = MmPfn_GetPidFromDTB(ctx, pSystemProcess, (QWORD)pe->AddressInfo.dwPfnPte[2]);
        if(dwPID && (dwPID != 4)) {
            pe->AddressInfo.dwPid = dwPID;
            pe->tpExtended = MmPfnExType_ProcessPrivate;
        } else {
            if(pe->AddressInfo.dwPfnPte[1] == pe->AddressInfo.dwPfnPte[2]) {
                if((pObPD = VmmTlbGetPageTable((QWORD)pe->AddressInfo.dwPfnPte[2] << 12, FALSE))) {
                    dwPte = pObPD->pdw[pe->AddressInfo.va >> 22];
                    Ob_DECREF_NULL(&pObPD);
                    if(dwPte & 0x01) {
                        pe->tpExtended = ((dwPte & 0x81) == 0x81) ? MmPfnExType_LargePage : MmPfnExType_PageTable;
                    } else {
                        pe->AddressInfo.va = 0;
                    }
                }
            }
            if(!VmmVirt2Phys(pSystemProcess, pe->AddressInfo.va, &pa) || (pe->dwPfn != pa >> 12)) {
                pe->AddressInfo.va = 0;
            }
        }
    }
}

_Success_(return)
BOOL MmPfn_Map_GetPfnScatter(_In_ POB_SET psPfn, _Out_ PMMPFNOB_MAP *ppObPfnMap, _In_ BOOL fExtended)
{
    POB_MMPFN_CONTEXT ctx = (POB_MMPFN_CONTEXT)ctxVmm->pObPfnContext;
    BOOL f32 = ctxVmm->f32;
    BYTE pbPfn[0x30] = { 0 };
    PVMM_PROCESS pObSystemProcess = NULL;
    PMMPFNOB_MAP pObPfnMap = NULL;
    PMMPFN_MAP_ENTRY pe;
    QWORD qw;
    DWORD cPfn, i, tp, cbRead;
    POB_SET psObEnrichAddress = NULL, psObPrefetch = NULL;
    if(!ctx) { goto fail; }
    // initialization
    if(!(cPfn = ObSet_Size(psPfn))) { goto fail; }
    if(!(pObSystemProcess = VmmProcessGet(4))) { goto fail; }
    if(!(psObEnrichAddress = ObSet_New())) { goto fail; }
    if(!(psObPrefetch = ObSet_New())) { goto fail; }
    if(!(pObPfnMap = Ob_Alloc(OB_TAG_MAP_PFN, LMEM_ZEROINIT, sizeof(MMPFNOB_MAP) + cPfn * sizeof(MMPFN_MAP_ENTRY), NULL, NULL))) { goto fail; }
    pObPfnMap->cMap = cPfn;
    // translate pfn# to pfn va and prefetch
    for(i = 0; i < cPfn; i++) {
        pe = pObPfnMap->pMap + i;
        pe->dwPfn = (DWORD)ObSet_Get(psPfn, i);
        ObSet_Push_PageAlign(psObPrefetch, MMPFN_PFN_TO_VA(ctx, pe->dwPfn), ctx->_MMPFN.cb);
    }
    VmmCachePrefetchPages(pObSystemProcess, psObPrefetch, 0);
    ObSet_Clear(psObPrefetch);
    // iterate and fetch pfns
    for(i = 0; i < cPfn; i++) {
        pe = pObPfnMap->pMap + i;
        if(pe->dwPfn > ctx->iPfnMax) { continue; }
        VmmReadEx(pObSystemProcess, MMPFN_PFN_TO_VA(ctx, pe->dwPfn), pbPfn, ctx->_MMPFN.cb, &cbRead, 0);
        if(!cbRead) { continue; }
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
    if(ObSet_Size(psObEnrichAddress)) {
        if(ctxVmm->tpMemoryModel == VMMDLL_MEMORYMODEL_X64) {
            MmPfn_Map_GetPfn_GetVaX64(ctx, pObSystemProcess, psObEnrichAddress, psObPrefetch, 1);
        } else if(ctxVmm->tpMemoryModel == VMMDLL_MEMORYMODEL_X86PAE) {
            MmPfn_Map_GetPfn_GetVaX86PAE(ctx, pObSystemProcess, psObEnrichAddress, psObPrefetch, 1);
        } else if(ctxVmm->tpMemoryModel == VMMDLL_MEMORYMODEL_X86) {
            MmPfn_Map_GetPfn_GetVaX86(ctx, pObSystemProcess, psObEnrichAddress, psObPrefetch);
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
BOOL MmPfn_Map_GetPfn(_In_ DWORD dwPfnStart, _In_ DWORD cPfn, _Out_ PMMPFNOB_MAP *ppObPfnMap, _In_ BOOL fExtended)
{
    BOOL fResult;
    POB_SET psObPfn;
    QWORD iPfn, iPfnEnd;
    if(!(psObPfn = ObSet_New())) { return FALSE; }
    for(iPfn = dwPfnStart, iPfnEnd = (QWORD)dwPfnStart + cPfn; iPfn < iPfnEnd; iPfn++) {
        ObSet_Push(psObPfn, 0x8000000000000000 | iPfn);
    }
    fResult = MmPfn_Map_GetPfnScatter(psObPfn, ppObPfnMap, fExtended);
    Ob_DECREF(psObPfn);
    return fResult;
}
