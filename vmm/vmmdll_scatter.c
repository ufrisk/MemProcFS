// vmmdll_scatter.c : implementation of the exported VMMDLL_Scatter_* functions.
// 
// This API is a wrapper API around the VMMDLL_MemReadScatter API call.
//
// (c) Ulf Frisk, 2021-2024
// Author: Ulf Frisk, pcileech@frizk.net
//

#include "vmmdll.h"
#include "ob/ob.h"
#include "oscompatibility.h"

#ifdef VMM_64BIT
#define SCATTER_MAX_SIZE_TOTAL      0x40000000000
#else /* VMM_64BIT */
#define SCATTER_MAX_SIZE_TOTAL      0x40000000
#endif /* VMM_64BIT */

#define SCATTER_MAX_SIZE_SINGLE     0x40000000
#define SCATTER_CONTEXT_MAGIC       0x5a5d65c8465a32d5

typedef struct tdSCATTER_RANGE {
    struct tdSCATTER_RANGE *FLink;
    QWORD va;
    PDWORD pcbRead;
    PBYTE pb;
    DWORD cb;
    DWORD cMEMs;
    MEM_SCATTER MEMs[0];
} SCATTER_RANGE, *PSCATTER_RANGE;

typedef struct tdSCATTER_RANGE_WRITE {
    struct tdSCATTER_RANGE_WRITE *FLink;
    QWORD va;
    DWORD cb;
    PBYTE pbExternal;       // external buffer (if null, use internal buffer instead)
    BYTE pbInternal[0];     // internal buffer (if external buffer is null)
} SCATTER_RANGE_WRITE, *PSCATTER_RANGE_WRITE;

typedef struct tdSCATTER_CONTEXT {
    QWORD qwMagic;
    SRWLOCK LockSRW;
    VMM_HANDLE H;
    VMMVM_HANDLE HVM;
    DWORD dwPID;
    DWORD dwReadFlags;
    BOOL fExecute;          // read/write is already executed
    DWORD cPageTotal;
    DWORD cPageAlloc;
    POB_MAP pmMEMs;
    PBYTE pbBuffer;
    PSCATTER_RANGE pRanges;
    struct {
        DWORD cPage;
        PSCATTER_RANGE_WRITE pRanges;
    } wr;
} SCATTER_CONTEXT, *PSCATTER_CONTEXT;

#define SCATTER_CALL_SYNCHRONIZED_IMPLEMENTATION(hS, fn) {                                      \
    if(!hS || (((PSCATTER_CONTEXT)hS)->qwMagic != SCATTER_CONTEXT_MAGIC)) { return FALSE; }     \
    BOOL fResult;                                                                               \
    AcquireSRWLockExclusive(&((PSCATTER_CONTEXT)hS)->LockSRW);                                  \
    fResult = fn;                                                                               \
    ReleaseSRWLockExclusive(&((PSCATTER_CONTEXT)hS)->LockSRW);                                  \
    return fResult;                                                                             \
}

_Success_(return)
BOOL VMMDLL_Scatter_PrepareInternal(_In_ PSCATTER_CONTEXT ctx, _In_ QWORD va, _In_ DWORD cb, _Out_writes_opt_(cb) PBYTE pb, _Out_opt_ PDWORD pcbRead)
{
    QWORD vaMEM;
    PMEM_SCATTER pMEM;
    PSCATTER_RANGE pr = NULL;
    DWORD i, iNewMEM = 0, cMEMsRequired, cMEMsPre = 0;
    BOOL fForcePageRead = ctx->dwReadFlags & VMMDLL_FLAG_SCATTER_FORCE_PAGEREAD;
    // zero out any buffer received
    if(pb && !(ctx->dwReadFlags & VMMDLL_FLAG_SCATTER_PREPAREEX_NOMEMZERO)) {
        ZeroMemory(pb, cb);
    }
    if(pcbRead) { *pcbRead = 0; }
    // validity checks
    if(va + cb < va) { return FALSE; }
    if(ctx->fExecute) { return FALSE; }
    if(!cb) { return TRUE; }
    if((cb >= SCATTER_MAX_SIZE_SINGLE) || (((SIZE_T)ctx->cPageTotal << 12) + cb > SCATTER_MAX_SIZE_TOTAL)) { return FALSE; }
    // count MEMs (required and pre-existing)
    cMEMsRequired = ((va & 0xfff) + cb + 0xfff) >> 12;
    vaMEM = va & ~0xfff;
    for(i = 0; i < cMEMsRequired; i++) {
        if(ObMap_ExistsKey(ctx->pmMEMs, vaMEM | 1)) {
            cMEMsPre++;
        }
        vaMEM += 0x1000;
    }
    // alloc scatter range (including any new MEMs required)
    if(pb || pcbRead || (cMEMsRequired > cMEMsPre)) {
        if(!(pr = LocalAlloc(LMEM_ZEROINIT, sizeof(SCATTER_RANGE) + (cMEMsRequired - cMEMsPre) * sizeof(MEM_SCATTER)))) { return FALSE; }
        pr->va = va;
        pr->cb = cb;
        pr->pb = pb;
        pr->pcbRead = pcbRead;
        pr->cMEMs = cMEMsRequired - cMEMsPre;
        for(i = 0; i < pr->cMEMs; i++) {
            pMEM = pr->MEMs + i;
            pMEM->version = MEM_SCATTER_VERSION;
            pMEM->cb = 0x1000;
        }
        pr->FLink = ctx->pRanges;
        ctx->pRanges = pr;
    }
    // assign addresses and/or buffers to MEMs
    vaMEM = va & ~0xfff;
    for(i = 0; i < cMEMsRequired; i++) {
        if((pMEM = ObMap_GetByKey(ctx->pmMEMs, vaMEM | 1))) {
            // pre-existing MEM
            if(pMEM->cb != 0x1000) {
                // pre-existing MEM was a tiny MEM -> since we have two reads
                // subscribing to this MEM we 'upgrade' it to a full MEM.
                pMEM->qwA = pMEM->qwA & ~0xfff;
                pMEM->cb = 0x1000;
            }
        } else {
            // new MEM
            if(!pr || (pr->cMEMs <= iNewMEM)) {
                // should never happen!
                return FALSE;
            }
            pMEM = pr->MEMs + iNewMEM;
            iNewMEM++;
            pMEM->qwA = vaMEM;
            if((cMEMsRequired == 1) && (cb <= 0x400) && !fForcePageRead) {
                // single-page small read -> optimize MEM for small read.
                // NB! buffer allocation still remains 0x1000 even if not all is used for now.
                pMEM->cb = (cb + 15) & ~0x7;
                pMEM->qwA = va & ~0x7;
                if((pMEM->qwA & 0xfff) + pMEM->cb > 0x1000) {
                    pMEM->qwA = (pMEM->qwA & ~0xfff) + 0x1000 - pMEM->cb;
                }
            }
            if(!ObMap_Push(ctx->pmMEMs, vaMEM | 1, pMEM)) {
                // should never happen!
                return FALSE;
            }
            ctx->cPageTotal++;
        }
        if(pb && !pMEM->pb && (vaMEM >= va) && (vaMEM + 0xfff < va + cb)) {
            pMEM->pb = pb + vaMEM - va;
            ctx->cPageAlloc++;
        }
        vaMEM += 0x1000;
    }
    return TRUE;
}

_Success_(return)
BOOL VMMDLL_Scatter_PrepareWriteInternal(_In_ PSCATTER_CONTEXT ctx, _In_ QWORD va, _In_reads_(cb) PBYTE pb, _In_ DWORD cb, _In_ BOOL fBufferExternal)
{
    DWORD cMEMsRequired;
    PSCATTER_RANGE_WRITE pRangeWr;
    // validity checks
    if(va + cb < va) { return FALSE; }
    if(ctx->fExecute) { return FALSE; }
    if(!cb) { return TRUE; }
    if((cb >= SCATTER_MAX_SIZE_SINGLE) || (((SIZE_T)ctx->wr.cPage << 12) + cb > SCATTER_MAX_SIZE_TOTAL)) { return FALSE; }
    // alloc and store in context
    if(fBufferExternal) {
        if(!(pRangeWr = LocalAlloc(0, sizeof(SCATTER_RANGE_WRITE)))) { return FALSE; }
        pRangeWr->pbExternal = pb;
    } else {
        if(!(pRangeWr = LocalAlloc(0, sizeof(SCATTER_RANGE_WRITE) + cb))) { return FALSE; }
        memcpy(pRangeWr->pbInternal, pb, cb);
        pRangeWr->pbExternal = NULL;
    }
    pRangeWr->cb = cb;
    pRangeWr->va = va;
    pRangeWr->FLink = ctx->wr.pRanges;
    ctx->wr.pRanges = pRangeWr;
    // up # of write MEMs required
    cMEMsRequired = 1;                      // First MEM
    cb -= min(cb, 0x1000 - (va & 0xfff));   // First MEM
    if(cb & 0xfff) { cMEMsRequired++; }     // Last MEM
    cMEMsRequired += cb >> 12;              // Middle MEMs
    ctx->wr.cPage += cMEMsRequired;
    return TRUE;
}

/*
* Prepare (add) a memory range for reading. The buffer pb and the read length
* *pcbRead will be populated when VMMDLL_Scatter_Execute*() is later called.
* NB! the buffer pb must not be deallocated before VMMDLL_Scatter_CloseHandle()
*     has been called since it's used internally by the scatter functionality!
* -- hS
* -- va = start address of the memory range to read.
* -- cb = size of memory range to read.
* -- pb = buffer to populate with read memory when calling VMMDLL_Scatter_ExecuteRead()
* -- pcbRead = optional pointer to be populated with number of bytes successfully read.
* -- return
*/
_Success_(return)
BOOL VMMDLL_Scatter_PrepareEx(_In_ VMMDLL_SCATTER_HANDLE hS, _In_ QWORD va, _In_ DWORD cb, _Out_writes_opt_(cb) PBYTE pb, _Out_opt_ PDWORD pcbRead)
{
    SCATTER_CALL_SYNCHRONIZED_IMPLEMENTATION(hS, VMMDLL_Scatter_PrepareInternal((PSCATTER_CONTEXT)hS, va, cb, pb, pcbRead));
}

/*
* Prepare (add) a memory range for reading. The memory may after a call to
* VMMDLL_Scatter_Execute*() be retrieved with VMMDLL_Scatter_Read().
* -- hS
* -- va = start address of the memory range to read.
* -- cb = size of memory range to read.
* -- return
*/
_Success_(return)
BOOL VMMDLL_Scatter_Prepare(_In_ VMMDLL_SCATTER_HANDLE hS, _In_ QWORD va, _In_ DWORD cb)
{
    SCATTER_CALL_SYNCHRONIZED_IMPLEMENTATION(hS, VMMDLL_Scatter_PrepareInternal((PSCATTER_CONTEXT)hS, va, cb, NULL, NULL));
}

/*
* Prepare (add) a memory range for writing.
* The memory contents to write is read and cached in this function call.
* Any changes to va/pb/cb after this call will not be reflected in the write.
* The memory is later written when calling VMMDLL_Scatter_Execute().
* Writing takes place before reading.
* -- hS
* -- va = start address of the memory range to write.
* -- pb = data to write.
* -- cb = size of memory range to write.
* -- return
*/
_Success_(return)
BOOL VMMDLL_Scatter_PrepareWrite(_In_ VMMDLL_SCATTER_HANDLE hS, _In_ QWORD va, _In_reads_(cb) PBYTE pb, _In_ DWORD cb)
{
    SCATTER_CALL_SYNCHRONIZED_IMPLEMENTATION(hS, VMMDLL_Scatter_PrepareWriteInternal((PSCATTER_CONTEXT)hS, va, pb, cb, FALSE));
}

/*
* Prepare (add) a memory range for writing.
* Memory contents to write is processed when calling VMMDLL_Scatter_Execute().
* The buffer in pb must ve valid when VMMDLL_Scatter_Execute() is called.
* The memory is later written when calling VMMDLL_Scatter_Execute().
* Writing takes place before reading.
* -- hS
* -- va = start address of the memory range to write.
* -- pb = data to write. Buffer must be valid when VMMDLL_Scatter_Execute() is called.
* -- cb = size of memory range to write.
* -- return
*/
EXPORTED_FUNCTION _Success_(return)
BOOL VMMDLL_Scatter_PrepareWriteEx(_In_ VMMDLL_SCATTER_HANDLE hS, _In_ QWORD va, _In_reads_(cb) PBYTE pb, _In_ DWORD cb)
{
    SCATTER_CALL_SYNCHRONIZED_IMPLEMENTATION(hS, VMMDLL_Scatter_PrepareWriteInternal((PSCATTER_CONTEXT)hS, va, pb, cb, TRUE));
}

_Success_(return)
BOOL VMMDLL_Scatter_ClearInternal(_In_ PSCATTER_CONTEXT ctx, _In_opt_ DWORD dwPID, _In_ DWORD flags)
{
    PSCATTER_RANGE pRangeRd, pRangeRdNext = ctx->pRanges;
    PSCATTER_RANGE_WRITE pRangeWr, pRangeWrNext = ctx->wr.pRanges;
    ctx->fExecute = FALSE;
    if(dwPID && !ctx->HVM) {
        ctx->dwPID = dwPID;
    }
    ctx->dwReadFlags = flags;
    ctx->cPageTotal = 0;
    ctx->cPageAlloc = 0;
    ctx->pRanges = NULL;
    ctx->wr.cPage = 0;
    ctx->wr.pRanges = NULL;
    ObMap_Clear(ctx->pmMEMs);
    LocalFree(ctx->pbBuffer);
    ctx->pbBuffer = NULL;
    while(pRangeRdNext) {
        pRangeRd = pRangeRdNext;
        pRangeRdNext = pRangeRd->FLink;
        LocalFree(pRangeRd);
    }
    while(pRangeWrNext) {
        pRangeWr = pRangeWrNext;
        pRangeWrNext = pRangeWr->FLink;
        LocalFree(pRangeWr);
    }
    return TRUE;
}

/*
* Clear/Reset the handle for use in another subsequent read scatter operation.
* -- hS = the scatter handle to clear for reuse.
* -- dwPID = optional PID change.
* -- flags
* -- return
*/
_Success_(return)
BOOL VMMDLL_Scatter_Clear(_In_ VMMDLL_SCATTER_HANDLE hS, _In_opt_ DWORD dwPID, _In_ DWORD flags)
{
    SCATTER_CALL_SYNCHRONIZED_IMPLEMENTATION(hS, VMMDLL_Scatter_ClearInternal((PSCATTER_CONTEXT)hS, dwPID, flags));
}

/*
* Close the scatter handle and free the resources it uses.
* -- hS = the scatter handle to close.
*/
VOID VMMDLL_Scatter_CloseHandle(_In_opt_ _Post_ptr_invalid_ VMMDLL_SCATTER_HANDLE hS)
{
    PSCATTER_CONTEXT ctx = (PSCATTER_CONTEXT)hS;
    PSCATTER_RANGE pRangeRd, pRangeRdNext;
    PSCATTER_RANGE_WRITE pRangeWr, pRangeWrNext;
    if(!ctx || (ctx->qwMagic != SCATTER_CONTEXT_MAGIC)) { return; }
    AcquireSRWLockExclusive(&ctx->LockSRW);
    if(ctx->qwMagic != SCATTER_CONTEXT_MAGIC) {
        // this should never happen ideally - it means user closed handle twice and won the race!
        ReleaseSRWLockExclusive(&ctx->LockSRW);
        return;
    }
    ctx->qwMagic = 0;
    ReleaseSRWLockExclusive(&ctx->LockSRW);
    // dealloc / free
    Ob_DECREF(ctx->pmMEMs);
    LocalFree(ctx->pbBuffer);
    pRangeRdNext = ctx->pRanges;
    while(pRangeRdNext) {
        pRangeRd = pRangeRdNext;
        pRangeRdNext = pRangeRd->FLink;
        LocalFree(pRangeRd);
    }
    pRangeWrNext = ctx->wr.pRanges;
    while(pRangeWrNext) {
        pRangeWr = pRangeWrNext;
        pRangeWrNext = pRangeWr->FLink;
        LocalFree(pRangeWr);
    }
    LocalFree(ctx);
}

_Success_(return)
BOOL VMMDLL_Scatter_ReadInternal(_In_ PSCATTER_CONTEXT ctx, _In_ QWORD va, _In_ DWORD cb, _Out_writes_opt_(cb) PBYTE pb, _Out_opt_ PDWORD pcbRead)
{
    PMEM_SCATTER pMEM;
    BOOL fResultFirst = FALSE;
    DWORD cbChunk, cbReadTotal = 0;
    if(pcbRead) { *pcbRead = 0; }
    if(va + cb < va) { return FALSE; }
    if(!ctx->fExecute) { return FALSE; }
    // 1st item may not be page aligned or may be 'tiny' sized MEM:
    {
        cbChunk = min(cb, 0x1000 - (va & 0xfff));
        pMEM = ObMap_GetByKey(ctx->pmMEMs, (va & ~0xfff) | 1);
        if(pMEM && pMEM->f) {
            if(pMEM->cb == 0x1000) {
                // normal page-sized MEM:
                if(pb) {
                    memcpy(pb, pMEM->pb + (va & 0xfff), cbChunk);
                    pb += cbChunk;
                }
                cbReadTotal += cbChunk;
                fResultFirst = TRUE;
            } else if((va >= pMEM->qwA) && (va + cb <= pMEM->qwA + pMEM->cb)) {
                // tiny MEM with in-range read:
                if(pb) {
                    memcpy(pb, pMEM->pb + (va - pMEM->qwA), cbChunk);
                    pb += cbChunk;
                }
                cbReadTotal += cbChunk;
                fResultFirst = TRUE;
            }
        }
        if(!fResultFirst && pb) {
            ZeroMemory(pb, cbChunk);
            pb += cbChunk;
        }
        va += cbChunk;
        cb -= cbChunk;
    }
    // page aligned va onwards (read from normal page-sized MEMs):
    while(cb) {
        cbChunk = min(cb, 0x1000);
        pMEM = ObMap_GetByKey(ctx->pmMEMs, va | 1);
        if(pMEM && pMEM->f && (pMEM->cb == 0x1000)) {
            cbReadTotal += cbChunk;
            if(pb) {
                if(pb != pMEM->pb) {
                    memcpy(pb, pMEM->pb, cbChunk);
                }
                pb += cbChunk;
            }
        } else {
            if(pb) {
                if(pMEM && (pb != pMEM->pb)) {
                    ZeroMemory(pb, cbChunk);
                }
                pb += cbChunk;
            }
        }
        va += cbChunk;
        cb -= cbChunk;
    }
    if(pcbRead) { *pcbRead = cbReadTotal; }
    return TRUE;
}

/*
* Read out memory in previously populated ranges. This function should only be
* called after the memory has been retrieved using VMMDLL_Scatter_ExecuteRead().
* -- hS
* -- va
* -- cb
* -- pb
* -- pcbRead
* -- return
*/
_Success_(return)
BOOL VMMDLL_Scatter_Read(_In_ VMMDLL_SCATTER_HANDLE hS, _In_ QWORD va, _In_ DWORD cb, _Out_writes_opt_(cb) PBYTE pb, _Out_opt_ PDWORD pcbRead)
{
    SCATTER_CALL_SYNCHRONIZED_IMPLEMENTATION(hS, VMMDLL_Scatter_ReadInternal((PSCATTER_CONTEXT)hS, va, cb, pb, pcbRead));
}

/*
* ExecuteReadInternal - internal synchronized function.
*/
_Success_(return)
BOOL VMMDLL_Scatter_ExecuteReadInternal(_In_ PSCATTER_CONTEXT ctx)
{
    DWORD i, cbBuffer, cbBufferAlloc, oBufferAllocMEM = 0;
    PMEM_SCATTER pMEM;
    PPMEM_SCATTER ppMEMs;
    PSCATTER_RANGE pRange;
    // validate
    if(!ctx->cPageTotal || (ctx->cPageTotal != ObMap_Size(ctx->pmMEMs))) { return FALSE; }
    // alloc (if required)
    cbBuffer = (ctx->cPageTotal - ctx->cPageAlloc) * 0x1000;
    if(!ctx->fExecute) {
        cbBufferAlloc = cbBuffer + ctx->cPageTotal * sizeof(PMEM_SCATTER);
        if(!(ctx->pbBuffer = LocalAlloc(LMEM_ZEROINIT, cbBufferAlloc))) { return FALSE; }
    }
    ppMEMs = (PPMEM_SCATTER)(ctx->pbBuffer + cbBuffer);
    // fixup MEMs
    for(i = 0; i < ctx->cPageTotal; i++) {
        pMEM = ObMap_GetByIndex(ctx->pmMEMs, i);
        ppMEMs[i] = pMEM;
        if(!pMEM->pb) {
            pMEM->pb = ctx->pbBuffer + oBufferAllocMEM;
            oBufferAllocMEM += 0x1000;
        } else if(ctx->fExecute) {
            pMEM->f = FALSE;
            ZeroMemory(pMEM->pb, 0x1000);
        }
    }
    // read scatter
    if(ctx->HVM) {
        VMMDLL_VmMemReadScatter(ctx->H, ctx->HVM, ppMEMs, ctx->cPageTotal, 0);
    } else {
        VMMDLL_MemReadScatter(ctx->H, ctx->dwPID, ppMEMs, ctx->cPageTotal, ctx->dwReadFlags);
    }
    ctx->fExecute = TRUE;
    // range fixup (if required)
    pRange = ctx->pRanges;
    while(pRange) {
        if(pRange->pb || pRange->pcbRead) {
            VMMDLL_Scatter_ReadInternal(ctx, pRange->va, pRange->cb, pRange->pb, pRange->pcbRead);
        }
        pRange = pRange->FLink;
    }
    return TRUE;
}

/*
* ExecuteWriteInternal - internal synchronized function.
*/
_Success_(return)
BOOL VMMDLL_Scatter_ExecuteWriteInternal(_In_ PSCATTER_CONTEXT ctx)
{
    PBYTE pbBuffer = NULL;
    DWORD i, cMEMs;
    PMEM_SCATTER pMEM, pMEMs;
    PPMEM_SCATTER ppMEMs;
    QWORD va = 0;
    DWORD cb = 0;
    PBYTE pb = NULL;
    PSCATTER_RANGE_WRITE pRange;
    // validate
    if(!ctx->wr.cPage) { return FALSE; }
    // alloc
    cMEMs = ctx->wr.cPage;
    if(!(pbBuffer = LocalAlloc(LMEM_ZEROINIT, cMEMs * (sizeof(PMEM_SCATTER) + sizeof(MEM_SCATTER))))) { return FALSE; }
    ppMEMs = (PPMEM_SCATTER)pbBuffer;
    pMEMs = (PMEM_SCATTER)(pbBuffer + cMEMs * (sizeof(PMEM_SCATTER)));
    // populate MEMs
    pRange = ctx->wr.pRanges;
    va = pRange->va;
    cb = pRange->cb;
    pb = pRange->pbExternal ? pRange->pbExternal : pRange->pbInternal;
    for(i = 0; i < cMEMs; i++) {
        if(!cb) {
            pRange = pRange->FLink;
            if(!pRange) { goto fail; }  // MEM depletion should not happen!
            va = pRange->va;
            cb = pRange->cb;
            pb = pRange->pbExternal ? pRange->pbExternal : pRange->pbInternal;
        }
        pMEM = pMEMs + i;
        ppMEMs[i] = pMEM;
        pMEM->version = MEM_SCATTER_VERSION;
        pMEM->qwA = va;
        pMEM->pb = pb;
        if(va & 0xfff) {
            pMEM->cb = min(cb, 0x1000 - (va & 0xfff));
        } else {
            pMEM->cb = min(cb, 0x1000);
        }
        va += pMEM->cb;
        cb -= pMEM->cb;
        pb += pMEM->cb;
    }
    if(cb || (pRange && pRange->FLink)) { goto fail; }  // leftover data should not happen!
    // write scatter
    if(ctx->HVM) {
        VMMDLL_VmMemWriteScatter(ctx->H, ctx->HVM, ppMEMs, cMEMs);
    } else {
        VMMDLL_MemWriteScatter(ctx->H, ctx->dwPID, ppMEMs, cMEMs);
    }
    // finish
    LocalFree(pbBuffer);
    return TRUE;
fail:
    LocalFree(pbBuffer);
    return FALSE;
}

/*
* ExecuteInternal - internal synchronized function for both read/write.
*/
_Success_(return)
BOOL VMMDLL_Scatter_ExecuteInternal(_In_ PSCATTER_CONTEXT ctx)
{
    BOOL fRd, fWr;
    fWr = VMMDLL_Scatter_ExecuteWriteInternal(ctx);
    fRd = VMMDLL_Scatter_ExecuteReadInternal(ctx);
    return fRd || fWr;
}

/*
* Retrieve the memory ranges previously populated with calls to the
* VMMDLL_Scatter_Prepare* functions.
* -- hS
* -- return
*/
_Success_(return)
BOOL VMMDLL_Scatter_ExecuteRead(_In_ VMMDLL_SCATTER_HANDLE hS)
{
    SCATTER_CALL_SYNCHRONIZED_IMPLEMENTATION(hS, VMMDLL_Scatter_ExecuteReadInternal((PSCATTER_CONTEXT)hS));
}

/*
* Retrieve and Write memory previously populated.
* Write any memory prepared with VMMDLL_Scatter_PrepareWrite function (1st).
* Retrieve the memory ranges previously populated with calls to the
* VMMDLL_Scatter_Prepare* functions (2nd).
* -- hS
* -- return
*/
_Success_(return)
BOOL VMMDLL_Scatter_Execute(_In_ VMMDLL_SCATTER_HANDLE hS)
{
    SCATTER_CALL_SYNCHRONIZED_IMPLEMENTATION(hS, VMMDLL_Scatter_ExecuteInternal((PSCATTER_CONTEXT)hS));
}

/*
* Initialize a scatter handle which is used to call VMMDLL_Scatter_* functions.
* CALLER CLOSE: VMMDLL_Scatter_CloseHandle(return)
* -- H
* -- dwPID - PID of target process, (DWORD)-1 to read physical memory.
* -- flags = optional flags as given by VMMDLL_FLAG_*
* -- return = handle to be used in VMMDLL_Scatter_* functions.
*/
_Success_(return != NULL)
VMMDLL_SCATTER_HANDLE VMMDLL_Scatter_Initialize(_In_ VMM_HANDLE H, _In_ DWORD dwPID, _In_ DWORD flags)
{
    PSCATTER_CONTEXT ctx = NULL;
    if(!(ctx = LocalAlloc(LMEM_ZEROINIT, sizeof(SCATTER_CONTEXT)))) { goto fail; }
    ctx->qwMagic = SCATTER_CONTEXT_MAGIC;
    ctx->H = H;
    ctx->dwPID = dwPID;
    ctx->dwReadFlags = flags;
    if(!(ctx->pmMEMs = ObMap_New(NULL, OB_MAP_FLAGS_OBJECT_VOID))) { goto fail; }
    return ctx;
fail:
    VMMDLL_Scatter_CloseHandle((VMMDLL_SCATTER_HANDLE)ctx);
    return NULL;
}

/*
* Initialize a scatter handle which is used to efficiently read/write memory in
* virtual machines (VMs).
* CALLER CLOSE: VMMDLL_Scatter_CloseHandle(return)
* -- hVMM
* -- hVM = virtual machine handle; acquired from VMMDLL_Map_GetVM*)
* -- flags = optional flags as given by VMMDLL_FLAG_*
* -- return = handle to be used in VMMDLL_Scatter_* functions.
*/
EXPORTED_FUNCTION _Success_(return != NULL)
VMMDLL_SCATTER_HANDLE VMMDLL_VmScatterInitialize(_In_ VMM_HANDLE H, _In_ VMMVM_HANDLE HVM)
{
    PSCATTER_CONTEXT ctx = NULL;
    if(!(ctx = LocalAlloc(LMEM_ZEROINIT, sizeof(SCATTER_CONTEXT)))) { goto fail; }
    ctx->qwMagic = SCATTER_CONTEXT_MAGIC;
    ctx->H = H;
    ctx->HVM = HVM;
    if(!(ctx->pmMEMs = ObMap_New(NULL, OB_MAP_FLAGS_OBJECT_VOID))) { goto fail; }
    return ctx;
fail:
    VMMDLL_Scatter_CloseHandle((VMMDLL_SCATTER_HANDLE)ctx);
    return NULL;
}
