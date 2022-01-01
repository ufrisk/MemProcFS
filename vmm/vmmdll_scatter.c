// vmmdll_scatter.c : implementation of the exported VMMDDLL_Scatter_* functions.
// 
// This API is a wrapper API around the VMMDLL_MemReadScatter API call.
//
// (c) Ulf Frisk, 2021-2022
// Author: Ulf Frisk, pcileech@frizk.net
//

#include "vmmdll.h"
#include "ob/ob.h"

#define SCATTER_MAX_SIZE            0x40000000
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

typedef struct tdSCATTER_CONTEXT {
    QWORD qwMagic;
    SRWLOCK LockSRW;
    DWORD dwReadFlags;
    BOOL fExecuteRead;
    DWORD dwPID;
    DWORD cPageTotal;
    DWORD cPageAlloc;
    POB_MAP pmMEMs;
    PBYTE pbBuffer;
    PSCATTER_RANGE pRanges;
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
    // zero out any buffer received
    if(pb) { ZeroMemory(pb, cb); }
    if(pcbRead) { *pcbRead = 0; }
    // validity checks
    if(va + cb < va) { return FALSE; }
    if(ctx->fExecuteRead) { return FALSE; }
    if(!cb) { return TRUE; }
    if((cb >= SCATTER_MAX_SIZE) || ((ctx->cPageTotal << 12) + cb > SCATTER_MAX_SIZE)) { return FALSE; }
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
            if((cMEMsRequired == 1) && (cb <= 0x400)) {
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

/*
* Prepare (add) a memory range for reading. The buffer pb and the read length
* *pcbRead will be populated when VMMDLL_Scatter_ExecuteRead() is later called.
* NB! the buffer pb must not be deallocated before VMMDLL_Scatter_CloseHandle()
*     has been called since it's used internally by the scatter functionality!
* -- hS
* -- va = start address of the memory range to read.
* -- cb = size of memory range to read.
* -- pb = buffer to populate with read memory when calling VMMDLL_Scatter_ExecuteRead()
* -- pcbRead = pointer to be populated with number of bytes successfully read.
* -- return
*/
_Success_(return)
BOOL VMMDLL_Scatter_PrepareEx(_In_ VMMDLL_SCATTER_HANDLE hS, _In_ QWORD va, _In_ DWORD cb, _Out_writes_opt_(cb) PBYTE pb, _Out_opt_ PDWORD pcbRead)
{
    SCATTER_CALL_SYNCHRONIZED_IMPLEMENTATION(hS, VMMDLL_Scatter_PrepareInternal((PSCATTER_CONTEXT)hS, va, cb, pb, pcbRead));
}

/*
* Prepare (add) a memory range for reading. The memory may after a call to
* VMMDLL_Scatter_ExecuteRead() be retrieved with VMMDLL_Scatter_Read().
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

_Success_(return)
BOOL VMMDLL_Scatter_ClearInternal(_In_ PSCATTER_CONTEXT ctx, _In_ DWORD dwPID, _In_ DWORD flags)
{
    PSCATTER_RANGE pRange, pRangeNext = ctx->pRanges;
    ctx->fExecuteRead = FALSE;
    ctx->dwPID = dwPID;
    ctx->dwReadFlags = flags;
    ctx->cPageTotal = 0;
    ctx->cPageAlloc = 0;
    ctx->pRanges = NULL;
    ObMap_Clear(ctx->pmMEMs);
    LocalFree(ctx->pbBuffer);
    ctx->pbBuffer = NULL;
    while(pRangeNext) {
        pRange = pRangeNext;
        pRangeNext = pRange->FLink;
        LocalFree(pRange);
    }
    return TRUE;
}

/*
* Clear/Reset the handle for use in another subsequent read scatter operation.
* -- hS = the scatter handle to clear for reuse.
* -- dwPID
* -- flags
* -- return
*/
_Success_(return)
BOOL VMMDLL_Scatter_Clear(_In_ VMMDLL_SCATTER_HANDLE hS, _In_ DWORD dwPID, _In_ DWORD flags)
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
    PSCATTER_RANGE pRange, pRangeNext;
    if(!ctx || (ctx->qwMagic != SCATTER_CONTEXT_MAGIC)) { return; }
    AcquireSRWLockExclusive(&ctx->LockSRW);
    ctx->qwMagic = 0;
    ReleaseSRWLockExclusive(&ctx->LockSRW);
    // dealloc / free
    Ob_DECREF(ctx->pmMEMs);
    LocalFree(ctx->pbBuffer);
    pRangeNext = ctx->pRanges;
    while(pRangeNext) {
        pRange = pRangeNext;
        pRangeNext = pRange->FLink;
        LocalFree(pRange);
    }
    LocalFree(ctx);
}

_Success_(return)
BOOL VMMDLL_Scatter_ReadInternal(_In_ PSCATTER_CONTEXT ctx, _In_ QWORD va, _In_ DWORD cb, _Out_writes_opt_(cb) PBYTE pb, _Out_opt_ PDWORD pcbRead)
{
    PMEM_SCATTER pMEM;
    BOOL fResultFirst = FALSE;
    DWORD cbChunk, cbReadTotal = 0;
    if(va + cb < va) { return FALSE; }
    if(!ctx->fExecuteRead) { return FALSE; }
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
            } else if((va >= pMEM->qwA) && (va + cb <= pMEM->qwA + pMEM->cb) && (va - pMEM->qwA <= cb)) {
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
* ExecuteRead - internal synchronized function.
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
    if(!ctx->fExecuteRead) {
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
        } else if(ctx->fExecuteRead) {
            pMEM->f = FALSE;
            ZeroMemory(pMEM->pb, 0x1000);
        }
    }
    // read scatter
    VMMDLL_MemReadScatter(ctx->dwPID, ppMEMs, ctx->cPageTotal, ctx->dwReadFlags | VMMDLL_FLAG_NO_PREDICTIVE_READ);
    ctx->fExecuteRead = TRUE;
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
* Initialize a scatter handle which is used to call VMMDLL_Scatter_* functions.
* CALLER CLOSE: VMMDLL_Scatter_CloseHandle(return)
* -- dwPID - PID of target process, (DWORD)-1 to read physical memory.
* -- flags = optional flags as given by VMMDLL_FLAG_*
* -- return = handle to be used in VMMDLL_Scatter_* functions.
*/
_Success_(return != NULL)
VMMDLL_SCATTER_HANDLE VMMDLL_Scatter_Initialize(_In_ DWORD dwPID, _In_ DWORD flags)
{
    PSCATTER_CONTEXT ctx = NULL;
    if(!(ctx = LocalAlloc(LMEM_ZEROINIT, sizeof(SCATTER_CONTEXT)))) { goto fail; }
    ctx->qwMagic = SCATTER_CONTEXT_MAGIC;
    ctx->dwPID = dwPID;
    ctx->dwReadFlags = flags;
    if(!(ctx->pmMEMs = ObMap_New(OB_MAP_FLAGS_OBJECT_VOID))) { goto fail; }
    return ctx;
fail:
    VMMDLL_Scatter_CloseHandle((VMMDLL_SCATTER_HANDLE)ctx);
    return NULL;
}
