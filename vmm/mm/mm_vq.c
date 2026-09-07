// mm_vq.c : reconstruction of Windows VirtualQuery regions.
//
// (c) Ulf Frisk, 2026
// Author: Ulf Frisk, pcileech@frizk.net
//
// This walks allocation metadata and raw page tables. The display PTE/VadEx maps
// deliberately omit information required to distinguish reserve from commit.
// Supported targets: Windows 7+ x86/PAE/x64, ordinary private/section views.
// Unreadable metadata and unsupported VAD kinds fail the query, including when
// a later unreadable page prevents establishing the exact end of a region.

#include "mm_vq.h"
#include "../pdb.h"

#define VQ_COMMIT       0x1000
#define VQ_RESERVE      0x2000
#define VQ_FREE         0x10000
#define VQ_PRIVATE      0x20000
#define VQ_MAPPED       0x40000
#define VQ_IMAGE        0x1000000
#define VQ_PA_MASK      0x0000fffffffff000ULL

typedef struct tdVQ_CACHE {
    QWORD key;
    DWORD kind;
    BOOL valid;
    BYTE pb[0x1000];
} VQ_CACHE, *PVQ_CACHE;

typedef struct tdVQ_CONTEXT {
    VMM_HANDLE H;
    PVMM_PROCESS pProcess;
    PVMM_PROCESS pSystem;
    PVMM_PROCESS pObProcessKernel;
    PVMM_MAP_VADENTRY pVad;
    BOOL f32;
    BOOL fMemCommit;
    DWORD cbPte;
    QWORD vaPfnDatabase;
    DWORD cbPfn;
    DWORD oPfnOriginal;
    DWORD oPfnPteAddress;
    DWORD oPfnU4;
    BOOL fLegacyWsle;
    DWORD dwCombinedMask;
    DWORD cbWsle;
    QWORD vaWsle;
    QWORD vaWsHash;
    QWORD vaWsHashStart;
    QWORD vaWsLowest;
    DWORD cWsle;
    DWORD oSubBase;
    DWORD oSubCount;
    DWORD oSubNext;
    QWORD vaSubsection;
    QWORD vaSubBase;
    QWORD iSubFirst;
    QWORD iSubEnd;
    BOOL fPrototypeIndexReady;
    QWORD qwProtoInvalidMask;
    QWORD qwProtoClearMask;
    QWORD vaProtoPool[2];
    QWORD cbProtoPool[2];
    QWORD vaPrefetchEnd;
    POB_SET pObPrefetch;
    POB_SET pObPrototype;
    POB_SET pObSubsection;
    VQ_CACHE cache[8];
} VQ_CONTEXT, *PVQ_CONTEXT;

static const DWORD VQ_PROTECT[32] = {
    0x01, 0x02, 0x10, 0x20, 0x04, 0x08, 0x40, 0x80,
    0x01, 0x202, 0x210, 0x220, 0x204, 0x208, 0x240, 0x280,
    0x01, 0x102, 0x110, 0x120, 0x104, 0x108, 0x140, 0x180,
    0x01, 0x402, 0x410, 0x420, 0x404, 0x408, 0x440, 0x480
};

// Memory combining can make a private page internally copy-on-write. Windows
// still reports the private allocation's writable protection to VirtualQuery.
// Section/image views retain their actual copy-on-write protection.
static DWORD MmVqProtection(_In_ PVQ_CONTEXT ctx, _In_ DWORD dwValue)
{
    if(ctx->pVad->fPrivateMemory && ((dwValue & 5) == 5)) { dwValue &= ~1U; }
    return VQ_PROTECT[dwValue];
}

static BOOL MmVqKernelRange(_In_ PVQ_CONTEXT ctx, _In_ QWORD va, _In_ QWORD cb)
{
    QWORD vaMin = ctx->f32 ? 0x80000000 : 0xffff800000000000ULL;
    QWORD vaMax = ctx->f32 ? 0xffffffff : ~0ULL;
    return cb && (va >= vaMin) && (va <= vaMax) && (cb - 1 <= vaMax - va);
}

/*
* Per - query page buffers avoid repeated translations and object - manager lookups.
* kind 1 = physical, 2 = system virtual, 3 = paged-out page-table contents,
* kind 4 = kernel virtual in the target process (process-specific working set).
*/
_Success_(return)
static BOOL MmVqRead(_In_ PVQ_CONTEXT ctx, _In_ DWORD dwKind, _In_ QWORD qwA, _Out_writes_(cb) PBYTE pb, _In_ DWORD cb, _In_ DWORD dwSlot)
{
    DWORD o, c;
    QWORD qwPage;
    PVQ_CACHE pCache = &ctx->cache[dwSlot];
    if((dwKind != 1) && !MmVqKernelRange(ctx, qwA, cb)) { return FALSE; }
    while(cb) {
        qwPage = qwA & ~0xfffULL;
        o = (DWORD)(qwA & 0xfff);
        c = min(cb, 0x1000 - o);
        if(!pCache->valid || (pCache->key != qwPage) || (pCache->kind != dwKind)) {
            pCache->valid = FALSE;
            if(dwKind == 4) {
                if(!VmmReadPage(ctx->H, ctx->pObProcessKernel, qwPage, pCache->pb)) { return FALSE; }
            } else if(!VmmReadPage(ctx->H, (dwKind == 1) ? NULL : ctx->pSystem, qwPage, pCache->pb)) { return FALSE; }
            pCache->key = qwPage;
            pCache->kind = dwKind;
            pCache->valid = TRUE;
        }
        memcpy(pb, pCache->pb + o, c);
        qwA += c;
        pb += c;
        cb -= c;
    }
    return TRUE;
}

_Success_(return)
static BOOL MmVqReadPointer(_In_ PVQ_CONTEXT ctx, _In_ QWORD qwA, _Out_ PQWORD pqwValue, _In_ DWORD dwSlot)
{
    *pqwValue = 0;
    return MmVqRead(ctx, 2, qwA, (PBYTE)pqwValue, ctx->f32 ? 4 : 8, dwSlot);
}

/*
* Return the leaf PTE, or a known zero entry at a higher level.next identifies
* the end of that entry's coverage, allowing untouched reservations to be skipped.
*/
_Success_(return)
static BOOL MmVqPte(_In_ PVQ_CONTEXT ctx, _In_ QWORD va, _Out_ PQWORD pqwResult, _Out_ PQWORD pqwNext, _Out_ PBOOL pfLarge)
{
    DWORD dwLvl, dwCount, dwShift, dwIndex, dwMask, dwOffset;
    DWORD shifts[4] = { 39, 30, 21, 12 };
    QWORD qwTable, qwPte = 0, pa;
    BOOL paged = FALSE;
    VMM_PTE_TP tp;
    PVQ_CACHE pCache;
    dwCount = 4;
    qwTable = ctx->pProcess->paDTB & VQ_PA_MASK;
    if(ctx->H->vmm.tpMemoryModel == VMM_MEMORYMODEL_X86PAE) {
        shifts[0] = 30; shifts[1] = 21; shifts[2] = 12;
        dwCount = 3;
        qwTable = ctx->pProcess->paDTB & ~0x1fULL;
    } else if(ctx->H->vmm.tpMemoryModel == VMM_MEMORYMODEL_X86) {
        shifts[0] = 22; shifts[1] = 12;
        dwCount = 2;
    }
    *pfLarge = FALSE;
    for(dwLvl = 0; dwLvl < dwCount; dwLvl++) {
        dwShift = shifts[dwLvl];
        dwMask = (ctx->cbPte == 4) ? 0x3ff : 0x1ff;
        if((dwCount == 3) && !dwLvl) { dwMask = 3; }
        dwIndex = (DWORD)((va >> dwShift) & dwMask);
        dwOffset = dwIndex * ctx->cbPte;
        if(paged) {
            pCache = &ctx->cache[dwLvl];
            if(!pCache->valid || (pCache->kind != 3) || (pCache->key != qwTable)) {
                pCache->valid = FALSE;
                tp = VMM_PTE_TP_NA;
                pa = 0;
                if(!ctx->H->vmm.fnMemoryModel.pfnPagedRead) { return FALSE; }
                if(!ctx->H->vmm.fnMemoryModel.pfnPagedRead(ctx->H, ctx->pProcess, 0, qwTable, pCache->pb, &pa, &tp, VMM_FLAG_NOVAD)) {
                    if(!pa || !VmmReadPage(ctx->H, NULL, pa & ~0xfffULL, pCache->pb)) { return FALSE; }
                }
                if(tp == VMM_PTE_TP_DEMANDZERO) { return FALSE; }
                pCache->key = qwTable;
                pCache->kind = 3;
                pCache->valid = TRUE;
            }
            qwPte = 0;
            memcpy(&qwPte, pCache->pb + dwOffset, ctx->cbPte);
        } else {
            qwPte = 0;
            if(!MmVqRead(ctx, 1, qwTable + dwOffset, (PBYTE)&qwPte, ctx->cbPte, dwLvl)) { return FALSE; }
        }
        *pqwNext = (va & ~((1ULL << dwShift) - 1)) + (1ULL << dwShift);
        if(!qwPte || (dwLvl == dwCount - 1)) { *pqwResult = qwPte; return TRUE; }
        if((qwPte & 0x81) == 0x81) {
            if((dwCount == 4) && !dwLvl) { return FALSE; }
            *pqwResult = qwPte;
            *pfLarge = TRUE;
            return TRUE;
        }
        paged = !(qwPte & 1) && ((qwPte & 0xc01) != 0x800);
        qwTable = paged ? qwPte : (qwPte & VQ_PA_MASK);
    }
    return FALSE;
}

_Success_(return)
static BOOL MmVqInitializeLegacyWsle(_In_ PVQ_CONTEXT ctx)
{
    DWORD oVm, oWsl, oWsle, oLast, oHash, oHashStart, oLowest, oShared = 0, oSize;
    QWORD vaWsl = 0;
    LPCSTR szType = "_MMWSL";
    BOOL f;
    if(ctx->vaWsle) { return TRUE; }
    f = PDB_GetTypeChildOffset(ctx->H, PDB_HANDLE_KERNEL, "_EPROCESS", "Vm", &oVm);
    if(!PDB_GetTypeChildOffset(ctx->H, PDB_HANDLE_KERNEL, "_MMSUPPORT", "VmWorkingSetList", &oWsl)) {
        szType = "_MMWSL_SHARED";
        f = f && PDB_GetTypeChildOffset(ctx->H, PDB_HANDLE_KERNEL, "_MMSUPPORT_INSTANCE", "VmWorkingSetList", &oWsl);
        f = f && PDB_GetTypeChildOffset(ctx->H, PDB_HANDLE_KERNEL, "_MMWSL_FULL", "Shared", &oShared);
    }
    f = f && PDB_GetTypeChildOffset(ctx->H, PDB_HANDLE_KERNEL, szType, "Wsle", &oWsle);
    f = f && PDB_GetTypeChildOffset(ctx->H, PDB_HANDLE_KERNEL, szType, "LastInitializedWsle", &oLast);
    f = f && PDB_GetTypeChildOffset(ctx->H, PDB_HANDLE_KERNEL, szType, "NonDirectHash", &oHash);
    f = f && PDB_GetTypeChildOffset(ctx->H, PDB_HANDLE_KERNEL, szType, "HashTableStart", &oHashStart);
    f = f && PDB_GetTypeChildOffset(ctx->H, PDB_HANDLE_KERNEL, szType, "LowestPagableAddress", &oLowest);
    f = f && (oVm < 0x1000) && (oWsl < 0x1000) && (oWsle < 0x1000) && (oLast < 0x1000);
    f = f && (oHash < 0x1000) && (oHashStart < 0x1000) && (oLowest < 0x1000) && (oShared < 0x1000);
    f = f && MmVqReadPointer(ctx, ctx->pProcess->win.EPROCESS.va + oVm + oWsl, &vaWsl, 6);
    if(!f) { return FALSE; }
    if(!ctx->pObProcessKernel) { ctx->pObProcessKernel = VmmProcessGet(ctx->H, ctx->pProcess->dwPID | VMM_PID_PROCESS_CLONE_WITH_KERNELMEMORY); }
    if(!ctx->pObProcessKernel) { return FALSE; }
    if(!MmVqKernelRange(ctx, vaWsl, oShared + 0x1000)) { return FALSE; }
    vaWsl += oShared;
    ctx->cbWsle = ctx->f32 ? 4 : 8;
    if(ctx->H->vmm.kernel.dwVersionBuild >= 9200) {
        f = PDB_GetTypeChildOffset(ctx->H, PDB_HANDLE_KERNEL, szType, "WsleSize", &oSize);
        f = f && (oSize < 0x1000) && MmVqRead(ctx, 4, vaWsl + oSize, (PBYTE)&ctx->cbWsle, 4, 7);
        if(!f || (ctx->cbWsle < (ctx->f32 ? 4U : 8U)) || (ctx->cbWsle > 16) || (ctx->cbWsle & (ctx->cbWsle - 1))) { return FALSE; }
    }
    f = MmVqRead(ctx, 4, vaWsl + oLast, (PBYTE)&ctx->cWsle, 4, 7);
    f = f && (ctx->cWsle < 0x1000000);
    f = f && MmVqRead(ctx, 4, vaWsl + oHash, (PBYTE)&ctx->vaWsHash, ctx->f32 ? 4 : 8, 7);
    f = f && MmVqRead(ctx, 4, vaWsl + oHashStart, (PBYTE)&ctx->vaWsHashStart, ctx->f32 ? 4 : 8, 7);
    f = f && MmVqRead(ctx, 4, vaWsl + oLowest, (PBYTE)&ctx->vaWsLowest, ctx->f32 ? 4 : 8, 7);
    f = f && MmVqRead(ctx, 4, vaWsl + oWsle, (PBYTE)&ctx->vaWsle, ctx->f32 ? 4 : 8, 7);
    ctx->cWsle++;
    f = f && !(ctx->vaWsle & (ctx->cbWsle - 1)) && MmVqKernelRange(ctx, ctx->vaWsle, (QWORD)ctx->cWsle * ctx->cbWsle);
    if(!f) { ctx->vaWsle = 0; }
    return f;
}

// Hints and hash entries are only candidates: always verify the valid bit and VA.
static BOOL MmVqMatchWsle(_In_ PVQ_CONTEXT ctx, _In_ DWORD i, _In_ QWORD va, _Out_ PDWORD pdwValue)
{
    QWORD entry = 0;
    DWORD cb = ctx->f32 ? 4 : 8;
    if((i >= ctx->cWsle) || !MmVqRead(ctx, 4, ctx->vaWsle + (QWORD)i * ctx->cbWsle, (PBYTE)&entry, cb, 7)) { return FALSE; }
    if((entry & ~0xffeULL) != (va | 1)) { return FALSE; }
    *pdwValue = (DWORD)((entry >> 4) & 31);
    return TRUE;
}

_Success_(return)
static BOOL MmVqLegacyProtection(_In_ PVQ_CONTEXT ctx, _In_ QWORD va, _In_ QWORD pte, _In_ QWORD vaPfn, _Out_ PDWORD pdwValue)
{
    QWORD key, slot, entry[2];
    DWORD i, n, hint, cb = ctx->f32 ? 4 : 8;
    DWORD cHash = 0x1000 / (2 * cb);
    if(!MmVqInitializeLegacyWsle(ctx)) { return FALSE; }
    if(!MmVqRead(ctx, 2, vaPfn, (PBYTE)&hint, 4, 4)) { return FALSE; }
    if(MmVqMatchWsle(ctx, hint, va, pdwValue)) { return TRUE; }
    if(!ctx->f32) {
        hint = (DWORD)((pte >> 52) & 0x7ff);
        if(hint) {
            ObSet_Clear(ctx->pObPrefetch);
            for(i = hint, n = 0; (i < ctx->cWsle) && (n < 16); i += 0x800, n++) {
                ObSet_Push_PageAlign(ctx->pObPrefetch, ctx->vaWsle + (QWORD)i * ctx->cbWsle, cb);
            }
            VmmCachePrefetchPages(ctx->H, ctx->pObProcessKernel, ctx->pObPrefetch, 0);
            for(i = hint, n = 0; (i < ctx->cWsle) && (n < 16); i += 0x800, n++) {
                if(MmVqMatchWsle(ctx, i, va, pdwValue)) { return TRUE; }
            }
        }
    }
    if(ctx->vaWsHash && !(ctx->vaWsHash & 1) && MmVqKernelRange(ctx, ctx->vaWsHash, 0x1000)) {
        for(n = 0; n < cHash; n++) {
            slot = ctx->vaWsHash + (((va >> 12) + n) & (cHash - 1)) * cb * 2;
            entry[0] = entry[1] = 0;
            if(!MmVqRead(ctx, 4, slot, (PBYTE)entry, cb * 2, 7)) { break; }
            key = ctx->f32 ? (DWORD)entry[0] : entry[0];
            if(!key) { break; }
            i = ctx->f32 ? (DWORD)(entry[0] >> 32) : (DWORD)entry[1];
            if((key == (va | 1)) && MmVqMatchWsle(ctx, i, va, pdwValue)) { return TRUE; }
        }
    } else if(!ctx->vaWsHash && (va >= ctx->vaWsLowest)) {
        slot = ctx->vaWsHashStart + ((va - ctx->vaWsLowest) >> 12) * 4;
        if((slot >= ctx->vaWsHashStart) && MmVqRead(ctx, 4, slot, (PBYTE)&i, 4, 7) && MmVqMatchWsle(ctx, i, va, pdwValue)) { return TRUE; }
    }
    // Windows also scans when a hint/hash is absent or stale. Read pages in
    // bounded batches; a missing entry never supplies a guessed protection.
    for(i = 0; i < ctx->cWsle; i++) {
        if(ctx->H->fAbort) { return FALSE; }
        if(!(i & 0xfff)) {
            ObSet_Clear(ctx->pObPrefetch);
            ObSet_Push_PageAlign(ctx->pObPrefetch, ctx->vaWsle + (QWORD)i * ctx->cbWsle, min(0x1000, ctx->cWsle - i) * ctx->cbWsle);
            VmmCachePrefetchPages(ctx->H, ctx->pObProcessKernel, ctx->pObPrefetch, 0);
        }
        if(MmVqMatchWsle(ctx, i, va, pdwValue)) { return TRUE; }
    }
    return FALSE;
}

/*
* Native x86 keeps modern shared - page protection in a process - specific byte array.
* Locate it only when a shared resident page requires that additional metadata.
*/
_Success_(return)
static BOOL MmVqInitializeWsle(_In_ PVQ_CONTEXT ctx)
{
    BOOL f;
    BYTE flags, code[0x500];
    DWORD oVm, oFlags, i, cMatches = 0;
    QWORD vaCode, vaArray = 0, vaWsle;
    if(ctx->vaWsle) { return TRUE; }
    f = PDB_GetTypeChildOffset(ctx->H, PDB_HANDLE_KERNEL, "_EPROCESS", "Vm", &oVm);
    f = f && PDB_GetTypeChildOffset(ctx->H, PDB_HANDLE_KERNEL, "_MMSUPPORT_INSTANCE", "Flags", &oFlags);
    f = f && (oVm < 0x1000) && (oFlags < 0x1000);
    f = f && MmVqRead(ctx, 2, ctx->pProcess->win.EPROCESS.va + oVm + oFlags, &flags, 1, 6) && ((flags & 7) < 5);
    if(!f) { return FALSE; }
    // Public PAE type layouts can disagree with the array actually used by the
    // kernel. Accept only these bounded, exact access sequences.
    f = PDB_GetSymbolAddress(ctx->H, PDB_HANDLE_KERNEL, "MiGetPageProtection", &vaCode);
    if(f && MmVqKernelRange(ctx, vaCode, sizeof(code)) && VmmRead(ctx->H, ctx->pSystem, vaCode, code, sizeof(code))) {
        for(i = 0; i + 15 <= sizeof(code); i++) {
            f = !memcmp(code + i, "\x03\x0c\x85", 3) && !memcmp(code + i + 7, "\x8a\x21\x8a\xc4\x24\x0f\x3c\x0a", 8);
            f = f || (!memcmp(code + i, "\x03\x14\x85", 3) && !memcmp(code + i + 7, "\x8a\x22\x8a\xc4\x24\x0f\x3c\x0a", 8));
            f = f || (!memcmp(code + i, "\x03\x0c\x85", 3) && !memcmp(code + i + 7, "\x8a\x19\x8a\xc3\x24\x0f\x3c\x0a", 8));
            f = f || (!memcmp(code + i, "\x03\x14\x85", 3) && !memcmp(code + i + 7, "\x8a\x1a\x8a\xc3\x24\x0f\x3c\x0a", 8));
            if(!f) { continue; }
            memcpy(&vaArray, code + i + 3, 4);
            cMatches++;
        }
    }
    if(!cMatches && PDB_GetSymbolAddress(ctx->H, PDB_HANDLE_KERNEL, "MiLocateWsle", &vaCode)) {
        f = MmVqKernelRange(ctx, vaCode, 36) && VmmRead(ctx->H, ctx->pSystem, vaCode, code, 36);
        f = f && (oFlags <= 0x7f) && !memcmp(code, "\x0f\xb6\x41", 3) && ((DWORD)code[3] == oFlags);
        f = f && !memcmp(code + 4, "\x83\xe0\x07\x56\x8b\xf2\xc1\xee\x0c\x03\x34\x85", 12);
        f = f && !memcmp(code + 20, "\x8a\x06\x24\x0f\x3c\x0a\x0f\x84", 8) && !memcmp(code + 32, "\x8b\xc6\x5e\xc3", 4);
        if(f) { memcpy(&vaArray, code + 16, 4); cMatches = 1; }
    }
    if((cMatches != 1) || !MmVqKernelRange(ctx, vaArray, 20)) { return FALSE; }
    f = MmVqReadPointer(ctx, vaArray + (flags & 7) * 4, &vaWsle, 6);
    if(!f || (vaWsle < 0x80000000) || (vaWsle > 0xfff00000) || (vaWsle & 0xfff)) { return FALSE; }
    ctx->pObProcessKernel = VmmProcessGet(ctx->H, ctx->pProcess->dwPID | VMM_PID_PROCESS_CLONE_WITH_KERNELMEMORY);
    if(!ctx->pObProcessKernel) { return FALSE; }
    ctx->vaWsle = vaWsle;
    return TRUE;
}

_Success_(return)
static BOOL MmVqPfnProtection(_In_ PVQ_CONTEXT ctx, _In_ QWORD qwPte, _In_ QWORD qwAddress, _Out_ PDWORD pdwProt)
{
    QWORD qwOriginal = 0, va, qwPteAddress = 0, qwU4 = 0;
    DWORD value = 0, u4;
    BYTE wsle;
    // Windows x64 stores per-view protection for shared resident pages in bits
    // 60..62. Zero means the PFN's original protection is authoritative.
    va = ctx->vaPfnDatabase + ((qwPte & VQ_PA_MASK) >> 12) * ctx->cbPfn;
    if(qwAddress != ~0ULL) {
        if(ctx->fLegacyWsle) {
            if(!MmVqRead(ctx, 2, va + ctx->oPfnU4, (PBYTE)&qwU4, ctx->f32 ? 4 : 8, 4)) { return FALSE; }
            if(qwU4 & (ctx->f32 ? 0x08000000ULL : 0x0200000000000000ULL)) {
                if(!MmVqLegacyProtection(ctx, qwAddress, qwPte, va, &value)) { return FALSE; }
                if(value) { *pdwProt = MmVqProtection(ctx, value); return TRUE; }
            }
        } else if(!ctx->f32) { value = (DWORD)((qwPte >> 60) & 7); }
        else {
            if(!MmVqRead(ctx, 2, va + ctx->oPfnU4, (PBYTE)&u4, 4, 4)) { return FALSE; }
            // Windows 10 2004 moved native x86 PFN.u4.PrototypePte from bit 27 to 31.
            if(u4 & ((ctx->H->vmm.kernel.dwVersionBuild >= 19041) ? 0x80000000 : 0x08000000)) {
                // Native x86 keeps per-view shared protection in the process's
                // working-set byte array, rather than the hardware PTE.
                if(!MmVqInitializeWsle(ctx)) { return FALSE; }
                if(!MmVqRead(ctx, 4, ctx->vaWsle + (qwAddress >> 12), &wsle, 1, 7) || ((wsle & 15) == 10)) { return FALSE; }
                value = (wsle >> 4) & 7;
            }
        }
    }
    if(value) {
        if(qwPte & 0x10) { value |= 8; }
        else if(qwPte & 8) { value |= 24; }
        *pdwProt = MmVqProtection(ctx, value);
        return TRUE;
    }
    if(!MmVqRead(ctx, 2, va + ctx->oPfnOriginal, (PBYTE)&qwOriginal, ctx->cbPte, 4)) { return FALSE; }
    value = (DWORD)((qwOriginal >> 5) & 31);
    if((ctx->H->vmm.kernel.dwVersionBuild >= 9200) && ((value & 5) == 5)) {
        // A combined private copy can also belong to an image/section VAD.
        // Its PFN's PteAddress has the sign bit cleared, unlike a normal PTE
        // pointer. Preserve the allocation type but recover writable access.
        if(!MmVqReadPointer(ctx, va + ctx->oPfnPteAddress, &qwPteAddress, 4)) { return FALSE; }
        if(ctx->f32 ? ((LONG)qwPteAddress > 0) : ((LONGLONG)qwPteAddress > 0)) { value &= ~1U; }
    }
    *pdwProt = MmVqProtection(ctx, value);
    return TRUE;
}

/*
* A section's prototype PTEs need not form one physically or virtually contiguous
* array. Follow subsection extents, including a view starting partway into one.
*/
_Success_(return)
static BOOL MmVqPrototypeAddress(_In_ PVQ_CONTEXT ctx, _In_ QWORD va, _Out_ PQWORD pqwAddress)
{
    QWORD qwSubsection, qwBase, qwFirst, qwIndex, qwNext, qwStart = 0;
    DWORD c, i;
    qwSubsection = ctx->pVad->vaSubsection;
    qwFirst = ctx->pVad->vaPrototypePte;
    qwIndex = (va - ctx->pVad->vaStart) >> 12;
    if(!qwSubsection || !qwFirst) { return FALSE; }
    // Keep the current subsection extent while walking forward. Restart when
    // lookahead has advanced past the page actually requested by the caller.
    if(ctx->vaSubsection && (qwIndex >= ctx->iSubFirst)) {
        if(qwIndex < ctx->iSubEnd) {
            *pqwAddress = ctx->vaSubBase + (qwIndex - ctx->iSubFirst) * ctx->cbPte;
            return TRUE;
        }
        if(!MmVqReadPointer(ctx, ctx->vaSubsection + ctx->oSubNext, &qwSubsection, 6) || (qwSubsection == ctx->vaSubsection)) { return FALSE; }
        if(!qwSubsection) { *pqwAddress = 0; return ctx->pVad->VadType == 2; }
        qwStart = ctx->iSubEnd;
        qwIndex -= qwStart;
    } else {
        ObSet_Clear(ctx->pObSubsection);
        ctx->vaSubsection = 0;
    }
    for(i = 0; i < 4096; i++) {
        if(ctx->H->fAbort || ObSet_Exists(ctx->pObSubsection, qwSubsection)) { return FALSE; }
        if(!MmVqReadPointer(ctx, qwSubsection + ctx->oSubBase, &qwBase, 6)) { return FALSE; }
        if(!MmVqRead(ctx, 2, qwSubsection + ctx->oSubCount, (PBYTE)&c, 4, 6) || !c || (c > 0x40000000)) { return FALSE; }
        if((qwBase & (ctx->cbPte - 1)) || !MmVqKernelRange(ctx, qwBase, (QWORD)c * ctx->cbPte)) { return FALSE; }
        if(!i && !qwStart) {
            if((qwFirst < qwBase) || ((qwFirst - qwBase) % ctx->cbPte) || ((qwFirst - qwBase) / ctx->cbPte >= c)) { return FALSE; }
            c -= (DWORD)((qwFirst - qwBase) / ctx->cbPte);
            qwBase = qwFirst;
        }
        if(!ObSet_Push(ctx->pObSubsection, qwSubsection)) { return FALSE; }
        ctx->vaSubsection = qwSubsection;
        ctx->vaSubBase = qwBase;
        ctx->iSubFirst = qwStart;
        ctx->iSubEnd = qwStart + c;
        if(qwIndex < c) {
            *pqwAddress = qwBase + qwIndex * ctx->cbPte;
            return TRUE;
        }
        qwIndex -= c;
        qwStart += c;
        if(!MmVqReadPointer(ctx, qwSubsection + ctx->oSubNext, &qwNext, 6) || (qwNext == qwSubsection)) { return FALSE; }
        if(!qwNext) {
            // Image VADs may extend past the final subsection. Those trailing
            // pages are reserved unless a process PTE supplies a mapping.
            if(ctx->pVad->VadType != 2) { return FALSE; }
            *pqwAddress = 0;
            return TRUE;
        }
        qwSubsection = qwNext;
    }
    return FALSE;
}

_Success_(return)
static BOOL MmVqPrototype(_In_ PVQ_CONTEXT ctx, _In_ QWORD va, _Out_ PQWORD pqwPte)
{
    QWORD qwA;
    *pqwPte = 0;
    if(!MmVqPrototypeAddress(ctx, va, &qwA)) { return FALSE; }
    return !qwA || MmVqRead(ctx, 2, qwA, (PBYTE)pqwPte, ctx->cbPte, 5);
}

/*
* New prototype PTEs contain an index relative to one of two pool regions.
* Resolve these bounds only when a direct prototype reference is encountered.
*/
_Success_(return)
static BOOL MmVqInitializePrototypeIndex(_In_ PVQ_CONTEXT ctx)
{
    BOOL f;
    QWORD vaState, va, qwInvalid, qwClear, vaPool[2], cbPool[2];
    DWORD oHardware, oInvalid, oClear, oVisible, oRegions, cbRegion, oBase, oSize, i;
    if(ctx->fPrototypeIndexReady) { return TRUE; }
    f = PDB_GetSymbolAddress(ctx->H, PDB_HANDLE_KERNEL, "MiState", &vaState);
    f = f && PDB_GetTypeChildOffset(ctx->H, PDB_HANDLE_KERNEL, "_MI_SYSTEM_INFORMATION", "Hardware", &oHardware);
    f = f && PDB_GetTypeChildOffset(ctx->H, PDB_HANDLE_KERNEL, "_MI_HARDWARE_STATE", "InvalidPteMask", &oInvalid);
    f = f && PDB_GetTypeChildOffset(ctx->H, PDB_HANDLE_KERNEL, "_MI_HARDWARE_STATE", "ClearInvalidBitPteMask", &oClear);
    f = f && PDB_GetTypeChildOffset(ctx->H, PDB_HANDLE_KERNEL, "_MI_SYSTEM_INFORMATION", "Vs", &oVisible);
    f = f && PDB_GetTypeChildOffset(ctx->H, PDB_HANDLE_KERNEL, "_MI_VISIBLE_STATE", "SystemVaRegions", &oRegions);
    f = f && PDB_GetTypeSize(ctx->H, PDB_HANDLE_KERNEL, "_MI_SYSTEM_VA_ASSIGNMENT", &cbRegion);
    f = f && PDB_GetTypeChildOffset(ctx->H, PDB_HANDLE_KERNEL, "_MI_SYSTEM_VA_ASSIGNMENT", "BaseAddress", &oBase);
    f = f && PDB_GetTypeChildOffset(ctx->H, PDB_HANDLE_KERNEL, "_MI_SYSTEM_VA_ASSIGNMENT", "NumberOfBytes", &oSize);
    f = f && (oHardware < 0x10000) && (oInvalid < 0x1000) && (oClear < 0x1000) && (oVisible < 0x20000) && (oRegions < 0x10000);
    f = f && (cbRegion >= 16) && (cbRegion <= 0x100) && (oBase <= cbRegion - 8) && (oSize <= cbRegion - 8);
    if(!f || !MmVqKernelRange(ctx, vaState, max(oHardware + max(oInvalid, oClear) + 8, oVisible + oRegions + 4 * cbRegion))) { return FALSE; }
    if(!MmVqRead(ctx, 2, vaState + oHardware + oInvalid, (PBYTE)&qwInvalid, 8, 6)) { return FALSE; }
    if(!MmVqRead(ctx, 2, vaState + oHardware + oClear, (PBYTE)&qwClear, 8, 6)) { return FALSE; }
    for(i = 0; i < 2; i++) {
        va = vaState + oVisible + oRegions + (i + 2) * cbRegion;
        if(!MmVqRead(ctx, 2, va + oBase, (PBYTE)&vaPool[i], 8, 6) || !MmVqRead(ctx, 2, va + oSize, (PBYTE)&cbPool[i], 8, 6)) { return FALSE; }
        if((vaPool[i] & 7) || (cbPool[i] < 8) || !MmVqKernelRange(ctx, vaPool[i], cbPool[i])) { return FALSE; }
    }
    ctx->qwProtoInvalidMask = qwInvalid;
    ctx->qwProtoClearMask = qwClear;
    memcpy(ctx->vaProtoPool, vaPool, sizeof(vaPool));
    memcpy(ctx->cbProtoPool, cbPool, sizeof(cbPool));
    ctx->fPrototypeIndexReady = TRUE;
    return TRUE;
}

_Success_(return != 0)
static QWORD MmVqPrototypePointer(_In_ PVQ_CONTEXT ctx, _In_ QWORD qwPte)
{
    QWORD qwOffset;
    DWORD i;
    if(!ctx->f32 && (ctx->H->vmm.kernel.dwVersionBuild >= 28000)) {
        if(!MmVqInitializePrototypeIndex(ctx)) { return 0; }
        if(ctx->qwProtoInvalidMask && !(qwPte & 0x10)) { qwPte &= ctx->qwProtoClearMask; }
        i = (qwPte & 0x0800000000000000ULL) ? 0 : 1;
        qwOffset = (qwPte >> 9) & 0x00001ffffffffff8ULL;
        if(qwOffset > ctx->cbProtoPool[i] - 8) { return 0; }
        return ctx->vaProtoPool[i] + qwOffset;
    }
    if(!ctx->f32) { return (QWORD)((LONGLONG)qwPte >> 16); }
    if(ctx->cbPte == 8) { return qwPte >> 32; }
    return 0x80000000 | ((qwPte >> 1) & 0x7ffffc00) | ((qwPte << 1) & 0x3ff);
}

static BOOL MmVqPrototypeLookup(_In_ PVQ_CONTEXT ctx, _In_ QWORD qwPte)
{
    if(!ctx->f32 && (ctx->H->vmm.kernel.dwVersionBuild >= 28000)) {
        return (qwPte & 0x400) && ((qwPte & 0x003ffffffffff000ULL) == 0x003ffffffffff000ULL);
    }
    return (ctx->cbPte == 8) ? ((qwPte >> 32) == 0xffffffff) : ((qwPte >> 12) == 0xfffff);
}

static VOID MmVqPrefetchPfn(_In_ PVQ_CONTEXT ctx, _In_ QWORD pte)
{
    QWORD va;
    va = ctx->vaPfnDatabase + ((pte & VQ_PA_MASK) >> 12) * ctx->cbPfn;
    if(MmVqKernelRange(ctx, va, ctx->cbPfn)) { ObSet_Push_PageAlign(ctx->pObPrefetch, va, ctx->cbPfn); }
}

/*
* Batch metadata for at most one 2 - MB span within this allocation.The first
* scatter obtains PFNs and prototype PTEs; the second obtains PFNs referenced
* by resident prototypes. Native x86 also needs working-set protection bytes.
* Lookahead is only a cache hint: an unreadable later page must not invalidate
* a region which ends before that page, and required reads still check success.
*/
static VOID MmVqPrefetch(_In_ PVQ_CONTEXT ctx, _In_ QWORD va)
{
    QWORD qwAddress, qwPte, qwNext, qwProto, qwEnd;
    BOOL fLarge, fWsle = FALSE;
    DWORD i;
    if(va < ctx->vaPrefetchEnd) { return; }
    qwEnd = min(ctx->pVad->vaEnd + 1, (va | 0x1fffff) + 1);
    ctx->vaPrefetchEnd = qwEnd;
    ObSet_Clear(ctx->pObPrefetch);
    ObSet_Clear(ctx->pObPrototype);
    for(qwAddress = va; qwAddress < qwEnd; qwAddress = qwNext) {
        if(ctx->H->fAbort || !MmVqPte(ctx, qwAddress, &qwPte, &qwNext, &fLarge) || fLarge || (qwNext <= qwAddress)) { break; }
        if(qwPte & 1) {
            if(ctx->fLegacyWsle || ctx->f32 || !((qwPte >> 60) & 7)) { MmVqPrefetchPfn(ctx, qwPte); }
            fWsle = ctx->f32 && !ctx->fLegacyWsle;
        } else if((!qwPte && !ctx->pVad->fPrivateMemory) || ((qwPte & 0x400) && MmVqPrototypeLookup(ctx, qwPte))) {
            qwNext = qwAddress + 0x1000;
            if(!MmVqPrototypeAddress(ctx, qwAddress, &qwProto)) { break; }
            if(qwProto) { ObSet_Push(ctx->pObPrototype, qwProto); }
        } else if(qwPte & 0x400) {
            qwProto = MmVqPrototypePointer(ctx, qwPte);
            if(MmVqKernelRange(ctx, qwProto, ctx->cbPte)) { ObSet_Push(ctx->pObPrototype, qwProto); }
        }
    }
    for(i = 0; i < ObSet_Size(ctx->pObPrototype); i++) {
        ObSet_Push_PageAlign(ctx->pObPrefetch, ObSet_Get(ctx->pObPrototype, i), ctx->cbPte);
    }
    VmmCachePrefetchPages(ctx->H, ctx->pSystem, ctx->pObPrefetch, 0);
    ObSet_Clear(ctx->pObPrefetch);
    for(i = 0; i < ObSet_Size(ctx->pObPrototype); i++) {
        qwProto = 0;
        qwAddress = ObSet_Get(ctx->pObPrototype, i);
        // Cache-only lookahead never retries an unreadable prototype here.
        if(VmmRead2(ctx->H, ctx->pSystem, qwAddress, (PBYTE)&qwProto, ctx->cbPte, VMM_FLAG_FORCECACHE_READ) && (qwProto & 1)) {
            MmVqPrefetchPfn(ctx, qwProto);
        }
    }
    VmmCachePrefetchPages(ctx->H, ctx->pSystem, ctx->pObPrefetch, 0);
    if(fWsle && ctx->vaWsle) {
        ObSet_Clear(ctx->pObPrefetch);
        ObSet_Push_PageAlign(ctx->pObPrefetch, ctx->vaWsle + (va >> 12), (DWORD)((qwEnd - va) >> 12));
        VmmCachePrefetchPages(ctx->H, ctx->pObProcessKernel, ctx->pObPrefetch, 0);
    }
}

_Success_(return)
static BOOL MmVqPrototypeProtection(_In_ PVQ_CONTEXT ctx, _In_ QWORD qwPte, _Out_ PDWORD pdwProt)
{
    if(qwPte & 1) { return MmVqPfnProtection(ctx, qwPte, ~0ULL, pdwProt); }
    *pdwProt = MmVqProtection(ctx, (DWORD)((qwPte >> 5) & 31));
    return TRUE;
}

_Success_(return)
static BOOL MmVqPageState(_In_ PVQ_CONTEXT ctx, _In_ QWORD va, _Out_ PDWORD pdwState, _Out_ PDWORD pdwProt, _Out_ PQWORD pdwNext)
{
    QWORD qwPte, qwProto, qwAddress;
    DWORD dwValue;
    BOOL fLarge;
    *pdwState = VQ_RESERVE;
    *pdwProt = 0;
    if(!MmVqPte(ctx, va, &qwPte, pdwNext, &fLarge) || fLarge) { return FALSE; }
    MmVqPrefetch(ctx, va);
    if(qwPte & 1) {
        *pdwState = VQ_COMMIT;
        return MmVqPfnProtection(ctx, qwPte, va, pdwProt);
    }
    if(!qwPte) {
        if(ctx->pVad->fPrivateMemory) {
            if(ctx->fMemCommit) {
                *pdwState = VQ_COMMIT;
                *pdwProt = VQ_PROTECT[ctx->pVad->Protection];
            }
            return TRUE;
        }
        *pdwNext = va + 0x1000;
        if(!MmVqPrototype(ctx, va, &qwProto)) { return FALSE; }
        if(!qwProto) { return TRUE; }
        *pdwState = VQ_COMMIT;
        if(ctx->pVad->VadType == 2) { return MmVqPrototypeProtection(ctx, qwProto, pdwProt); }
        *pdwProt = VQ_PROTECT[ctx->pVad->Protection];
        return TRUE;
    }
    dwValue = (DWORD)((qwPte >> 5) & 31);
    if(!(qwPte & 0x400)) {
        if(dwValue == 16) { return TRUE; } // MM_DECOMMIT overrides a fully committed VAD.
        if(!dwValue) { return FALSE; }
        *pdwState = VQ_COMMIT;
        *pdwProt = MmVqProtection(ctx, dwValue);
        return TRUE;
    }
    // Prototype lookup-needed entries retain the view's current protection.
    if(MmVqPrototypeLookup(ctx, qwPte)) {
        if(dwValue == 16) { return TRUE; }
        if(!MmVqPrototype(ctx, va, &qwProto)) { return FALSE; }
        if(!qwProto) { return TRUE; }
        *pdwState = VQ_COMMIT;
        *pdwProt = MmVqProtection(ctx, dwValue);
        return TRUE;
    }
    // A process PTE can also directly reference a prototype PTE.
    qwAddress = MmVqPrototypePointer(ctx, qwPte);
    qwProto = 0;
    if(!MmVqRead(ctx, 2, qwAddress, (PBYTE)&qwProto, ctx->cbPte, 5) || !qwProto) { return FALSE; }
    *pdwState = VQ_COMMIT;
    if(!MmVqPrototypeProtection(ctx, qwProto, pdwProt)) { return FALSE; }
    if((ctx->cbPte == 8) && (qwPte & ctx->dwCombinedMask)) {
        // Combined prototype PTE: convert WRITECOPY to READWRITE, retaining
        // execute/cache/guard modifiers and the enclosing allocation's type.
        *pdwProt = (*pdwProt & ~0x88U) | ((*pdwProt & 0x88) >> 1);
    }
    return TRUE;
}

_Success_(return)
static BOOL MmVqInitialize(_In_ PVQ_CONTEXT ctx)
{
    BOOL f;
    DWORD oFlags, vadFlags;
    if(ctx->H->vmm.kernel.dwVersionBuild >= 9200) {
        ctx->dwCombinedMask = PDB_GetTypeChildOffset(ctx->H, PDB_HANDLE_KERNEL, "_MMPTE_PROTOTYPE", "SwizzleBit", &oFlags) ? 0x800 : 0x200;
    }
    f = PDB_GetSymbolPTR(ctx->H, PDB_HANDLE_KERNEL, "MmPfnDatabase", ctx->pSystem, &ctx->vaPfnDatabase);
    f = f && PDB_GetTypeSize(ctx->H, PDB_HANDLE_KERNEL, "_MMPFN", &ctx->cbPfn);
    f = f && PDB_GetTypeChildOffset(ctx->H, PDB_HANDLE_KERNEL, "_MMPFN", "OriginalPte", &ctx->oPfnOriginal);
    f = f && PDB_GetTypeChildOffset(ctx->H, PDB_HANDLE_KERNEL, "_MMPFN", "PteAddress", &ctx->oPfnPteAddress);
    f = f && (ctx->cbPfn >= ctx->cbPte) && (ctx->cbPfn <= 0x100) && (ctx->oPfnOriginal <= ctx->cbPfn - ctx->cbPte);
    f = f && (ctx->oPfnPteAddress <= ctx->cbPfn - ctx->cbPte);
    f = f && MmVqKernelRange(ctx, ctx->vaPfnDatabase, ctx->cbPfn);
    ctx->fMemCommit = ctx->pVad->MemCommit;
    if(ctx->pVad->fPrivateMemory && (ctx->H->vmm.kernel.dwVersionBuild >= 26100)) {
        // Recent builds store MemCommit in _MM_PRIVATE_VAD_FLAGS; the display
        // VAD map retains the older CommitCharge interpretation.
        f = f && PDB_GetTypeChildOffset(ctx->H, PDB_HANDLE_KERNEL, "_MMVAD_SHORT", "u", &oFlags);
        f = f && MmVqRead(ctx, 2, ctx->pVad->vaVad + oFlags, (PBYTE)&vadFlags, 4, 6);
        if(f) { ctx->fMemCommit = (vadFlags & ((ctx->H->vmm.kernel.dwVersionBuild >= 28000) ? 0x00400000 : 0x02000000)) != 0; }
    }
    if(ctx->f32 || ctx->fLegacyWsle) {
        f = f && PDB_GetTypeChildOffset(ctx->H, PDB_HANDLE_KERNEL, "_MMPFN", "u4", &ctx->oPfnU4);
        f = f && (ctx->oPfnU4 <= ctx->cbPfn - (ctx->f32 ? 4 : 8));
    }
    if(!ctx->pVad->fPrivateMemory) {
        f = f && PDB_GetTypeChildOffset(ctx->H, PDB_HANDLE_KERNEL, "_SUBSECTION", "SubsectionBase", &ctx->oSubBase);
        f = f && PDB_GetTypeChildOffset(ctx->H, PDB_HANDLE_KERNEL, "_SUBSECTION", "PtesInSubsection", &ctx->oSubCount);
        f = f && PDB_GetTypeChildOffset(ctx->H, PDB_HANDLE_KERNEL, "_SUBSECTION", "NextSubsection", &ctx->oSubNext);
        f = f && (ctx->oSubBase < 0x100) && (ctx->oSubCount < 0x100) && (ctx->oSubNext < 0x100);
        f = f && (ctx->pObSubsection = ObSet_New(ctx->H));
    }
    f = f && (ctx->pObPrefetch = ObSet_New(ctx->H)) && (ctx->pObPrototype = ObSet_New(ctx->H));
    return f;
}

_Success_(return)
static BOOL MmVqGetAddressLimit(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pSystem, _In_ PVMM_PROCESS pProcess, _Out_ PQWORD pqwLimit)
{
    DWORD oFlags;
    *pqwLimit = 0;
    if(pProcess->win.fWow64) {
        if(!PDB_GetTypeChildOffset(H, PDB_HANDLE_KERNEL, "_EPROCESS", "Wow64VaSpace4Gb", &oFlags)) { return FALSE; }
        if((oFlags & 3) || (oFlags > sizeof(pProcess->win.EPROCESS.pb) - sizeof(DWORD))) { return FALSE; }
        if(oFlags + sizeof(DWORD) > pProcess->win.EPROCESS.cb) { return FALSE; }
        // Wow64VaSpace4Gb is bit 9 in Windows 7 and later EPROCESS.Flags.
        *pqwLimit = (VMM_EPROCESS_DWORD(pProcess, oFlags) & 0x200) ? 0xfffeffff : 0x7ffeffff;
        return TRUE;
    }
    if(!PDB_GetSymbolPTR(H, PDB_HANDLE_KERNEL, "MmHighestUserAddress", pSystem, pqwLimit) || !*pqwLimit) { return FALSE; }
    return TRUE;
}

_Success_(return)
BOOL MmVqQuery(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess, _In_ QWORD va, _Out_ PVMMDLL_MEMORY_BASIC_INFORMATION pInfo)
{
    PVMM_PROCESS pObSystem = NULL;
    PVMMOB_MAP_VAD pObVad = NULL;
    PVMM_MAP_VADENTRY pVad;
    PVQ_CONTEXT ctx = NULL;
    VMMDLL_MEMORY_BASIC_INFORMATION oInfo = { 0 };
    QWORD qwLimit, qwEnd, qwNext, qwAddress, dwCount;
    DWORD i, dwLow, dwHigh, dwState, dwProt;
    BOOL result = FALSE;
    BOOL f32, f, fLegacyWsle, fOldAddressLimit;
    if(H->vmm.kernel.dwVersionBuild < 7600 || pProcess->dwState) { return FALSE; }
    if((H->vmm.tpSystem != VMM_SYSTEM_WINDOWS_32) && (H->vmm.tpSystem != VMM_SYSTEM_WINDOWS_64)) { return FALSE; }
    f = (H->vmm.tpMemoryModel == VMM_MEMORYMODEL_X64);
    f = f || (H->vmm.tpMemoryModel == VMM_MEMORYMODEL_X86PAE);
    f = f || (H->vmm.tpMemoryModel == VMM_MEMORYMODEL_X86);
    if(!f) { return FALSE; }
    if(!(pObSystem = VmmProcessGet(H, 4))) { goto fail; }
    if(!MmVqGetAddressLimit(H, pObSystem, pProcess, &qwLimit) || (va > qwLimit) || (qwLimit > 0x7fffffffffffULL)) { goto fail; }
    fLegacyWsle = PDB_GetTypeSize(H, PDB_HANDLE_KERNEL, "_MMWSLE", &i);
    if(fLegacyWsle && (i != (H->vmm.f32 ? 4U : 8U))) { goto fail; }
    // Windows 10 1803 removed the synthetic final allocation window.
    fOldAddressLimit = H->vmm.kernel.dwVersionBuild < 17134;
    if(!VmmMap_GetVad(H, pProcess, &pObVad, VMM_VADMAP_TP_CORE)) { goto fail; }
    va &= ~0xfffULL;
    oInfo.BaseAddress = va;
    qwEnd = qwLimit + 1;
    // Older Windows reserves the final allocation-granularity window separately
    // from the VAD tree. The shared user-data page, when in this window, is live.
    if(fOldAddressLimit && (va >= (qwLimit & ~0xffffULL))) {
        oInfo.AllocationBase = qwLimit & ~0xffffULL;
        oInfo.AllocationProtect = 2;
        oInfo.State = VQ_RESERVE;
        // Windows 8 through Windows 10 1709 report zero protection for this WOW64 reservation.
        oInfo.Protect = (pProcess->win.fWow64 && (H->vmm.kernel.dwVersionBuild >= 9200)) ? 0 : 1;
        oInfo.Type = VQ_PRIVATE;
        oInfo.RegionSize = qwEnd - va;
        if(va == 0x7ffe0000) {
            oInfo.State = VQ_COMMIT;
            oInfo.Protect = 2;
            oInfo.RegionSize = 0x1000;
        }
        // Windows 10 1703/1709 WOW64 separates the reservation from shared user data.
        f = pProcess->win.fWow64 && (H->vmm.kernel.dwVersionBuild >= 15063);
        if(f && (oInfo.AllocationBase == 0x7ffe0000) && (va >= 0x7ffe1000)) { oInfo.AllocationBase = 0x7ffe1000; }
        *pInfo = oInfo;
        result = TRUE;
        goto fail;
    }
    if(fOldAddressLimit) { qwEnd = min(qwEnd, qwLimit & ~0xffffULL); }
    // Find the containing allocation or its successor in one binary search.
    dwLow = 0;
    dwHigh = pObVad->cMap;
    while(dwLow < dwHigh) {
        i = dwLow + ((dwHigh - dwLow) >> 1);
        if(pObVad->pMap[i].vaEnd < va) { dwLow = i + 1; }
        else { dwHigh = i; }
    }
    pVad = (dwLow < pObVad->cMap) ? pObVad->pMap + dwLow : NULL;
    if(pVad && (pVad->vaStart > va)) {
        qwEnd = min(qwEnd, pVad->vaStart);
        pVad = NULL;
    }
    if(!pVad) {
        // A partial VAD traversal must not manufacture free address space.
        f32 = H->vmm.tpSystem == VMM_SYSTEM_WINDOWS_32;
        if(H->vmm.kernel.dwVersionBuild >= 9600) {
            dwCount = VMM_EPROCESS_PTR(f32, pProcess, H->vmm.offset.EPROCESS.VadRoot + (f32 ? 8 : 0x10));
        } else {
            i = (H->vmm.kernel.dwVersionBuild < 9200) ? (f32 ? 0x14 : 0x28) : (f32 ? 0x0c : 0x18);
            dwCount = (DWORD)VMM_EPROCESS_PTR(f32, pProcess, H->vmm.offset.EPROCESS.VadRoot + i) >> 8;
        }
        if(dwCount != pObVad->cMap) { goto fail; }
        oInfo.State = VQ_FREE;
        oInfo.Protect = 1;
    } else {
        if((pVad->VadType != 0) && (pVad->VadType != 2) && (pVad->VadType != 4)) { goto fail; }
        if(pVad->vaEnd == ~0ULL) { goto fail; }
        qwEnd = min(qwEnd, pVad->vaEnd + 1);
        oInfo.AllocationBase = pVad->vaStart;
        oInfo.AllocationProtect = VQ_PROTECT[pVad->Protection];
        oInfo.Type = pVad->fPrivateMemory ? VQ_PRIVATE : ((pVad->VadType == 2) ? VQ_IMAGE : VQ_MAPPED);
        if(!(ctx = LocalAlloc(LMEM_ZEROINIT, sizeof(VQ_CONTEXT)))) { goto fail; }
        ctx->H = H;
        ctx->pProcess = pProcess;
        ctx->pSystem = pObSystem;
        ctx->pVad = pVad;
        ctx->f32 = H->vmm.tpSystem == VMM_SYSTEM_WINDOWS_32;
        ctx->fLegacyWsle = fLegacyWsle;
        ctx->cbPte = (H->vmm.tpMemoryModel == VMM_MEMORYMODEL_X86) ? 4 : 8;
        if(!MmVqInitialize(ctx)) { goto fail; }
        if(!MmVqPageState(ctx, va, &oInfo.State, &oInfo.Protect, &qwNext)) { goto fail; }
        for(qwAddress = qwNext; qwAddress < qwEnd; qwAddress = qwNext) {
            if(H->fAbort) { goto fail; }
            if(!MmVqPageState(ctx, qwAddress, &dwState, &dwProt, &qwNext) || (qwNext <= qwAddress)) { goto fail; }
            if((dwState != oInfo.State) || (dwProt != oInfo.Protect)) { qwEnd = qwAddress; break; }
        }
    }
    if(qwEnd <= va) { goto fail; }
    oInfo.RegionSize = qwEnd - va;
    *pInfo = oInfo;
    result = TRUE;
fail:
    if(ctx) {
        Ob_DECREF(ctx->pObProcessKernel);
        Ob_DECREF(ctx->pObPrefetch);
        Ob_DECREF(ctx->pObPrototype);
        Ob_DECREF(ctx->pObSubsection);
    }
    LocalFree(ctx);
    Ob_DECREF(pObVad);
    Ob_DECREF(pObSystem);
    return result;
}
