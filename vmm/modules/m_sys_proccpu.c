// m_sys_proccpu.c : Windows process CPU accounting and sampled CPU usage.
//
// (c) Ulf Frisk, 2026
// Author: Ulf Frisk, pcileech@frizk.net
//

#include "modules.h"

#define MPERF_LINE_LENGTH       120
#define MPERF_LINE_HEADER       "    PID Process                 Kernel(s)           User(s)          Total(s)   CPU% Delta(s)  Thrd Status"
#define MPERF_MAX_PROCESSES     0x4000
#define MPERF_MAX_THREADS       0x10000
#define MPERF_MAX_PROC_THREADS  0x4000
#define MPERF_READ_FLAGS        (VMM_FLAG_NOCACHE | VMM_FLAG_NOCACHEPUT | VMM_FLAG_NOPAGING)

static const CHAR szMPerfReadme[] =
    "Windows process CPU accounting\n"
    "==============================\n"
    "cpu.txt lists cumulative kernel/user CPU seconds and sampled CPU percent.     \n"
    "The tables are available at /sys/proc/cpu.                                    \n"
    "                                                                              \n"
    "cpu.txt is sorted by PID.                                                     \n"
    "cpu-time is sorted by active time.                                            \n"
    "cpu-usage.txt is sorted by active time since last refresh on live targets.    \n"
    "                                                                              \n"
    "More information: https://github.com/ufrisk/MemProcFS-dev/wiki/FS_Sys_Cpu     \n";

typedef struct tdMCPU_OFFSETS {
    BOOL fValid;
    WORD cbProcess;
    WORD cbThread;
    WORD cbCounter;
    WORD oPID;
    WORD oCreate;
    WORD oExit;
    WORD oHead;
    WORD oKernel;
    WORD oUser;
    WORD oThreadLink;
    WORD oThreadCID;
    WORD oThreadKernel;
    WORD oThreadUser;
    QWORD vaIncrement;
} MCPU_OFFSETS, *PMCPU_OFFSETS;

typedef struct tdMCPU_ENTRY {
    DWORD dwPID;
    DWORD cThreads;
    CHAR szName[16];
    QWORD vaProcess;
    QWORD ftCreate;
    QWORD ftExit;
    QWORD vaHead;
    QWORD vaFirst;
    QWORD vaNext;
    QWORD vaPrev;
    QWORD vaTail;
    QWORD cKernel;
    QWORD cUser;
    QWORD cKernelProcess;
    QWORD cUserProcess;
    BOOL fValid;
    BOOL fDone;
    BOOL fPercent;
    double cpu;
    double seconds;
    LPCSTR szStatus;
} MCPU_ENTRY, *PMCPU_ENTRY;

typedef struct tdMCPU_THREAD {
    BOOL fValid;
    DWORD dwPID;
    DWORD cKernel;
    DWORD cUser;
    QWORD vaNext;
    QWORD vaPrev;
} MCPU_THREAD, *PMCPU_THREAD;

typedef struct tdMCPU_SNAPSHOT {
    OB ObHdr;
    POB_MAP pmProcess;
    POB_SET psThread;
    PMCPU_ENTRY *ppTime;
    PMCPU_ENTRY *ppUsage;
    QWORD timeStart;
    QWORD timeEnd;
    DWORD dwIncrement;
    DWORD cCPUs;
} MCPU_SNAPSHOT, *PMCPU_SNAPSHOT;

typedef struct tdMCPU_CONTEXT {
    OB ObHdr;
    SRWLOCK LockSRW;
    QWORD qwRefresh;
    QWORD qwRefreshSeen;
    MCPU_OFFSETS o;
    PMCPU_SNAPSHOT pSnapshot;
} MCPU_CONTEXT, *PMCPU_CONTEXT;

VOID MSysProcCpu_SnapshotCleanupCB(_In_ PMCPU_SNAPSHOT pObSnapshot)
{
    LocalFree(pObSnapshot->ppTime);
    LocalFree(pObSnapshot->ppUsage);
    Ob_DECREF(pObSnapshot->pmProcess);
    Ob_DECREF(pObSnapshot->psThread);
}

VOID MSysProcCpu_ContextCleanupCB(_In_ PMCPU_CONTEXT pObContext)
{
    Ob_DECREF(pObContext->pSnapshot);
}

/*
* Resolve only accounting fields; no dependency on optional stack/thread maps.
* -- H
* -- po
*/
_Success_(return)
BOOL MSysProcCpu_Offsets(_In_ VMM_HANDLE H, _Inout_ PMCPU_OFFSETS po)
{
    BOOL f;
    if(po->fValid) { return TRUE; }
    ZeroMemory(po, sizeof(*po));
    po->cbCounter = (H->vmm.f32 || (H->vmm.kernel.dwVersionBuild < 26100)) ? 4 : 8;
    f = PDB_GetTypeChildOffsetShort(H, PDB_HANDLE_KERNEL, "_EPROCESS", "UniqueProcessId", &po->oPID);
    f = f && PDB_GetTypeChildOffsetShort(H, PDB_HANDLE_KERNEL, "_EPROCESS", "CreateTime", &po->oCreate);
    f = f && PDB_GetTypeChildOffsetShort(H, PDB_HANDLE_KERNEL, "_EPROCESS", "ExitTime", &po->oExit);
    f = f && PDB_GetTypeChildOffsetShort(H, PDB_HANDLE_KERNEL, "_EPROCESS", "ThreadListHead", &po->oHead);
    f = f && PDB_GetTypeChildOffsetShort(H, PDB_HANDLE_KERNEL, "_KPROCESS", "KernelTime", &po->oKernel);
    f = f && PDB_GetTypeChildOffsetShort(H, PDB_HANDLE_KERNEL, "_KPROCESS", "UserTime", &po->oUser);
    f = f && PDB_GetTypeChildOffsetShort(H, PDB_HANDLE_KERNEL, "_ETHREAD", "ThreadListEntry", &po->oThreadLink);
    f = f && PDB_GetTypeChildOffsetShort(H, PDB_HANDLE_KERNEL, "_ETHREAD", "Cid", &po->oThreadCID);
    f = f && PDB_GetTypeChildOffsetShort(H, PDB_HANDLE_KERNEL, "_KTHREAD", "KernelTime", &po->oThreadKernel);
    f = f && PDB_GetTypeChildOffsetShort(H, PDB_HANDLE_KERNEL, "_KTHREAD", "UserTime", &po->oThreadUser);
    f = f && PDB_GetSymbolAddress(H, PDB_HANDLE_KERNEL, "KeMaximumIncrement", &po->vaIncrement);
    if(!f) { return FALSE; }
    f = po->oCreate && (po->oUser == po->oKernel + po->cbCounter) && !(po->vaIncrement & 3);
    f = f && VMM_KADDR_DUAL(H->vmm.f32, po->vaIncrement);
    if(!f) { return FALSE; }
    po->cbProcess = max(max(max(po->oPID, po->oCreate), max(po->oExit, po->oHead)), max(po->oKernel, po->oUser));
    po->cbThread = max(max(po->oThreadLink, po->oThreadCID), max(po->oThreadKernel, po->oThreadUser));
    if((po->cbProcess > 0x1000 - 16) || (po->cbThread > 0x1000 - 16)) { return FALSE; }
    po->cbProcess += 16;
    po->cbThread += 16;
    po->fValid = TRUE;
    return TRUE;
}

VOID MSysProcCpu_Calculate(_In_ BOOL fLive, _In_ PMCPU_SNAPSHOT pSnap, _In_opt_ PMCPU_SNAPSHOT pPrev, _Inout_ PMCPU_ENTRY pe)
{
    PMCPU_ENTRY old;
    QWORD delta, elapsed, time, oldTime, limit;
    double cpu;
    if(!pe->fValid) { return; }
    limit = 0xffffffffffffffffULL / max(1, pSnap->dwIncrement);
    if((pe->cUser > limit) || (pe->cKernel > limit - pe->cUser)) {
        pe->fValid = FALSE;
        pe->szStatus = "counter-overflow";
        return;
    }
    pe->szStatus = "no-clock";
    if(!pSnap->dwIncrement) { pe->fValid = FALSE; return; }
    if(!fLive) { pe->szStatus = "static"; return; }
    if(pe->ftExit) { pe->szStatus = "exited"; return; }
    if(!pSnap->timeStart || (pSnap->timeEnd < pSnap->timeStart) || !pSnap->cCPUs) { return; }
    pe->szStatus = "first-sample";
    if(!pPrev || !pPrev->timeStart || (pPrev->timeEnd < pPrev->timeStart) || (pPrev->dwIncrement != pSnap->dwIncrement) || (pPrev->cCPUs != pSnap->cCPUs)) { return; }
    old = ObMap_GetByKey(pPrev->pmProcess, pe->dwPID);
    if(!old || !old->fValid) { return; }
    pe->szStatus = "identity-changed";
    if(!pe->ftCreate || (old->ftCreate != pe->ftCreate) || (old->vaProcess != pe->vaProcess) || old->ftExit) { return; }
    pe->szStatus = "counter-reset";
    if((pe->cKernel < old->cKernel) || (pe->cUser < old->cUser)) { return; }
    pe->szStatus = "no-clock";
    if(pSnap->timeStart <= pPrev->timeEnd) { return; }
    time = pSnap->timeStart + (pSnap->timeEnd - pSnap->timeStart) / 2;
    oldTime = pPrev->timeStart + (pPrev->timeEnd - pPrev->timeStart) / 2;
    elapsed = time - oldTime;
    delta = (pe->cKernel - old->cKernel) + (pe->cUser - old->cUser);
    cpu = 100.0 * (double)delta * pSnap->dwIncrement / (double)elapsed / pSnap->cCPUs;
    pe->szStatus = "inconsistent";
    // Permit two ticks of acquisition/rounding skew; reject implausible jumps.
    if(cpu > 100.0 + 200.0 * pSnap->dwIncrement / elapsed) { return; }
    pe->cpu = min(cpu, 100.0);
    pe->seconds = elapsed / 10000000.0;
    pe->fPercent = TRUE;
    pe->szStatus = "ok";
}

/* Walk each process ring against private, freshly read scatter data. Unknown
 * nodes are read together in the next batch; known nodes arrive in the first
 * process batch. Never sum a partial ring as a complete process. */
BOOL MSysProcCpu_Threads(_In_ VMM_HANDLE H, _In_ PMCPU_OFFSETS po, _Inout_ PMCPU_SNAPSHOT pSnap, _In_opt_ PMCPU_SNAPSHOT prev, _In_opt_ PVMMOB_SCATTER hS)
{
    POB_MAP pObMapThread = NULL;
    POB_SET pObSetPending = NULL;
    PVMMOB_SCATTER pObScatter = Ob_INCREF(hS);
    PMCPU_ENTRY e;
    PMCPU_THREAD t;
    MCPU_THREAD entry;
    BYTE pb[0x1000];
    DWORD i;
    QWORD va, qwPID;
    BOOL f, fResult = FALSE;
    if(!(pObMapThread = ObMap_New(H, OB_MAP_FLAGS_OBJECT_LOCALFREE)) || !(pObSetPending = ObSet_New(H))) { goto finish; }
    if(prev && !ObSet_PushSet(pObSetPending, prev->psThread)) { goto finish; }
    while(TRUE) {
        while((va = ObSet_Pop(pObSetPending))) {
            ZeroMemory(&entry, sizeof(entry));
            entry.fValid = VmmScatter_Read(pObScatter, va, po->cbThread, pb);
            if(entry.fValid) {
                qwPID = VMM_PTR_OFFSET(H->vmm.f32, pb, po->oThreadCID);
                entry.dwPID = (DWORD)qwPID;
                entry.fValid = qwPID == entry.dwPID;
                entry.cKernel = *(PDWORD)(pb + po->oThreadKernel);
                entry.cUser = *(PDWORD)(pb + po->oThreadUser);
                entry.vaNext = VMM_PTR_OFFSET(H->vmm.f32, pb, po->oThreadLink);
                entry.vaPrev = VMM_PTR_OFFSET(H->vmm.f32, pb, po->oThreadLink + (H->vmm.f32 ? 4 : 8));
            }
            if(!ObMap_PushCopy(pObMapThread, va, &entry, sizeof(entry))) { goto finish; }
        }
        Ob_DECREF_NULL(&pObScatter);
        for(i = 0; i < ObMap_Size(pSnap->pmProcess); i++) {
            e = ObMap_GetByIndex(pSnap->pmProcess, i);
            while(e->fValid && !e->fDone) {
                if(e->vaNext == e->vaHead) {
                    e->fDone = TRUE;
                    e->fValid = e->vaPrev == e->vaTail;
                    break;
                }
                // Embedded list entries need only pointer alignment; ETHREAD needs 8/16.
                va = e->vaNext - po->oThreadLink;
                f = VMM_KADDR_DUAL_4_8(H->vmm.f32, e->vaNext) && VMM_KADDR_DUAL_8_16(H->vmm.f32, va);
                f = f && (e->cThreads < MPERF_MAX_PROC_THREADS) && (ObSet_Size(pSnap->psThread) < MPERF_MAX_THREADS);
                if(!f) { e->fValid = FALSE; break; }
                if(!(t = ObMap_GetByKey(pObMapThread, va))) {
                    if(!ObSet_Push(pObSetPending, va) && !ObSet_Exists(pObSetPending, va)) { goto finish; }
                    break;
                }
                f = t->fValid && (t->dwPID == e->dwPID) && (t->vaPrev == e->vaPrev);
                f = f && !ObSet_Exists(pSnap->psThread, va) && ObSet_Push(pSnap->psThread, va);
                f = f && (e->cKernel <= 0xffffffffffffffffULL - t->cKernel) && (e->cUser <= 0xffffffffffffffffULL - t->cUser);
                if(!f) {
                    e->fValid = FALSE;
                    break;
                }
                e->cKernel += t->cKernel;
                e->cUser += t->cUser;
                e->cThreads++;
                e->vaPrev = e->vaNext;
                e->vaNext = t->vaNext;
            }
        }
        if(!ObSet_Size(pObSetPending)) { break; }
        if(ObMap_Size(pObMapThread) + ObSet_Size(pObSetPending) > MPERF_MAX_THREADS) { goto finish; }
        f = (pObScatter = VmmScatter_Initialize(H, MPERF_READ_FLAGS)) != NULL;
        f = f && VmmScatter_Prepare3(pObScatter, pObSetPending, po->cbThread) && VmmScatter_Execute(pObScatter, PVMM_PROCESS_SYSTEM);
        if(!f) { goto finish; }
    }
    fResult = TRUE;
finish:
    Ob_DECREF(pObScatter);
    Ob_DECREF(pObMapThread);
    Ob_DECREF(pObSetPending);
    return fResult;
}

/* CALLER DECREF: return. Batch the process fields and target clock with optional known threads. */
_Success_(return != NULL)
PVMMOB_SCATTER MSysProcCpu_ReadProcesses(_In_ VMM_HANDLE H, _In_ PMCPU_OFFSETS po, _Inout_ PMCPU_SNAPSHOT pSnap, _In_opt_ POB_SET psThread, _Out_ PQWORD pTime)
{
    PVMMOB_SCATTER pObScatter = VmmScatter_Initialize(H, MPERF_READ_FLAGS);
    PMCPU_ENTRY e;
    DWORD i, t[3];
    BOOL f;
    *pTime = 0;
    if(!pObScatter) { return NULL; }
    for(i = 0; i < ObMap_Size(pSnap->pmProcess); i++) {
        e = ObMap_GetByIndex(pSnap->pmProcess, i);
        if(VMM_KADDR_DUAL_8_16(H->vmm.f32, e->vaProcess) && !VmmScatter_Prepare(pObScatter, e->vaProcess, po->cbProcess)) { goto fail; }
    }
    f = VmmScatter_Prepare3(pObScatter, psThread, po->cbThread);
    f = f && VmmScatter_PrepareEx(pObScatter, po->vaIncrement, sizeof(DWORD), (PBYTE)&pSnap->dwIncrement, NULL);
    f = f && VmmScatter_Prepare(pObScatter, H->vmm.f32 ? 0xffdf0008 : 0xfffff78000000008, sizeof(t));
    if(!f || !VmmScatter_Execute(pObScatter, PVMM_PROCESS_SYSTEM)) { goto fail; }
    f = VmmScatter_Read(pObScatter, H->vmm.f32 ? 0xffdf0008 : 0xfffff78000000008, sizeof(t), (PBYTE)t) && (t[1] == t[2]);
    *pTime = f ? ((QWORD)t[1] << 32) | t[0] : 0;
    return pObScatter;
fail:
    Ob_DECREF(pObScatter);
    return NULL;
}

_Success_(return != NULL)
PMCPU_SNAPSHOT MSysProcCpu_Capture(_In_ VMM_HANDLE H, _Inout_ PMCPU_CONTEXT ctx)
{
    PMCPU_SNAPSHOT pObSnapshot = NULL;
    PVMM_PROCESS pObProcess = NULL;
    PVMMOB_SCATTER pObScatter = NULL;
    PMCPU_OFFSETS o = &ctx->o;
    MCPU_ENTRY entry;
    PMCPU_ENTRY e;
    DWORD i;
    BYTE pb[0x1000];
    BOOL f, fThreads;
    pObSnapshot = Ob_AllocEx(H, OB_TAG_MOD_CPU, LMEM_ZEROINIT, sizeof(*pObSnapshot), (OB_CLEANUP_CB)MSysProcCpu_SnapshotCleanupCB, NULL);
    if(!pObSnapshot) { goto fail; }
    if(!(pObSnapshot->pmProcess = ObMap_New(H, OB_MAP_FLAGS_OBJECT_LOCALFREE)) || !(pObSnapshot->psThread = ObSet_New(H))) { goto fail; }
    MSysProcCpu_Offsets(H, o);
    while((pObProcess = VmmProcessGetNext(H, pObProcess, VMM_FLAG_PROCESS_SHOW_TERMINATED))) {
        if(ObMap_Size(pObSnapshot->pmProcess) >= MPERF_MAX_PROCESSES) { goto fail; }
        ZeroMemory(&entry, sizeof(entry));
        entry.dwPID = pObProcess->dwPID;
        entry.vaProcess = pObProcess->win.EPROCESS.va;
        entry.ftCreate = VmmProcess_GetCreateTimeOpt(H, pObProcess);
        memcpy(entry.szName, pObProcess->szName, sizeof(entry.szName));
        entry.szName[15] = 0;
        entry.szStatus = o->fValid ? "incomplete" : "no-symbols";
        if(!ObMap_PushCopy(pObSnapshot->pmProcess, entry.dwPID, &entry, sizeof(entry))) { goto fail; }
    }
    if(!o->fValid) { return pObSnapshot; }
    pObSnapshot->cCPUs = H->vmm.kernel.opt.cCPUs;
    if(pObSnapshot->cCPUs > 4096) { pObSnapshot->cCPUs = 0; }
    pObScatter = MSysProcCpu_ReadProcesses(H, o, pObSnapshot, ctx->pSnapshot ? ctx->pSnapshot->psThread : NULL, &pObSnapshot->timeStart);
    if(!pObScatter) { goto fail; }
    for(i = 0; i < ObMap_Size(pObSnapshot->pmProcess); i++) {
        e = ObMap_GetByIndex(pObSnapshot->pmProcess, i);
        f = VmmScatter_Read(pObScatter, e->vaProcess, o->cbProcess, pb) && (VMM_PTR_OFFSET(H->vmm.f32, pb, o->oPID) == e->dwPID);
        f = f && (!e->ftCreate || (e->ftCreate == *(PQWORD)(pb + o->oCreate)));
        if(!f) { continue; }
        e->ftCreate = *(PQWORD)(pb + o->oCreate);
        e->ftExit   = *(PQWORD)(pb + o->oExit);
        e->cKernel  = e->cKernelProcess = (o->cbCounter == 8) ? *(PQWORD)(pb + o->oKernel) : *(PDWORD)(pb + o->oKernel);
        e->cUser    = e->cUserProcess = (o->cbCounter == 8) ? *(PQWORD)(pb + o->oUser) : *(PDWORD)(pb + o->oUser);
        e->vaHead   = e->vaPrev = e->vaProcess + o->oHead;
        e->vaFirst  = e->vaNext = VMM_PTR_OFFSET(H->vmm.f32, pb, o->oHead);
        e->vaTail   = VMM_PTR_OFFSET(H->vmm.f32, pb, o->oHead + (H->vmm.f32 ? 4 : 8));
        e->fValid   = VMM_KADDR_DUAL_4_8(H->vmm.f32, e->vaNext) && VMM_KADDR_DUAL_4_8(H->vmm.f32, e->vaTail);
    }
    fThreads = MSysProcCpu_Threads(H, o, pObSnapshot, ctx->pSnapshot, pObScatter);
    Ob_DECREF_NULL(&pObScatter);
    // A thread may exit and transfer its ticks while we read its process ring.
    // Reject such samples instead of counting transferred ticks twice/partially.
    if(!(pObScatter = MSysProcCpu_ReadProcesses(H, o, pObSnapshot, NULL, &pObSnapshot->timeEnd))) { fThreads = FALSE; }
    if((pObSnapshot->dwIncrement < 1000) || (pObSnapshot->dwIncrement > 10000000)) { pObSnapshot->dwIncrement = 0; }
    for(i = 0; pObScatter && (i < ObMap_Size(pObSnapshot->pmProcess)); i++) {
        e = ObMap_GetByIndex(pObSnapshot->pmProcess, i);
        if(!e->fValid) { continue; }
        f = VmmScatter_Read(pObScatter, e->vaProcess, o->cbProcess, pb) && (VMM_PTR_OFFSET(H->vmm.f32, pb, o->oPID) == e->dwPID);
        f = f && (*(PQWORD)(pb + o->oCreate) == e->ftCreate) && (*(PQWORD)(pb + o->oExit) == e->ftExit);
        f = f && (VMM_PTR_OFFSET(H->vmm.f32, pb, o->oHead) == e->vaFirst);
        f = f && (VMM_PTR_OFFSET(H->vmm.f32, pb, o->oHead + (H->vmm.f32 ? 4 : 8)) == e->vaTail);
        f = f && (((o->cbCounter == 8) ? *(PQWORD)(pb + o->oKernel) : *(PDWORD)(pb + o->oKernel)) == e->cKernelProcess);
        f = f && (((o->cbCounter == 8) ? *(PQWORD)(pb + o->oUser) : *(PDWORD)(pb + o->oUser)) == e->cUserProcess);
        if(!f) {
            e->fValid = FALSE;
            e->szStatus = "inconsistent";
        }
    }
    for(i = 0; i < ObMap_Size(pObSnapshot->pmProcess); i++) {
        e = ObMap_GetByIndex(pObSnapshot->pmProcess, i);
        e->fValid = e->fValid && e->fDone && fThreads;
        if(o->cbCounter == 4) { e->cKernel = (DWORD)e->cKernel; e->cUser = (DWORD)e->cUser; }
        MSysProcCpu_Calculate(H->dev.fVolatile, pObSnapshot, ctx->pSnapshot, e);
    }
    Ob_DECREF(pObScatter);
    return pObSnapshot;
fail:
    Ob_DECREF(pObProcess);
    Ob_DECREF(pObScatter);
    Ob_DECREF(pObSnapshot);
    return NULL;
}

/* CALLER DECREF: return. Refresh notifications only invalidate; no target I/O. */
PMCPU_SNAPSHOT MSysProcCpu_GetSnapshot(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_CONTEXT ctxP)
{
    PMCPU_CONTEXT ctx = (PMCPU_CONTEXT)ctxP->ctxM;
    PMCPU_SNAPSHOT pObSnapshot;
    QWORD qwRefresh;
    AcquireSRWLockExclusive(&ctx->LockSRW);
    qwRefresh = InterlockedAdd64(&ctx->qwRefresh, 0);
    if(!ctx->pSnapshot || (qwRefresh != ctx->qwRefreshSeen)) {
        ctx->qwRefreshSeen = qwRefresh;
        pObSnapshot = MSysProcCpu_Capture(H, ctx);
        Ob_DECREF(ctx->pSnapshot);
        ctx->pSnapshot = pObSnapshot;
    }
    pObSnapshot = Ob_INCREF(ctx->pSnapshot);
    ReleaseSRWLockExclusive(&ctx->LockSRW);
    return pObSnapshot;
}

int MSysProcCpu_CompareTime(_In_ const void *p1, _In_ const void *p2)
{
    PMCPU_ENTRY e1 = *(PMCPU_ENTRY *)p1, e2 = *(PMCPU_ENTRY *)p2;
    QWORD t1, t2;
    if(e1->fValid != e2->fValid) { return e1->fValid ? -1 : 1; }
    if(e1->fValid) {
        t1 = e1->cKernel + e1->cUser;
        t2 = e2->cKernel + e2->cUser;
        if(t1 != t2) { return (t1 < t2) ? 1 : -1; }
    }
    return (e1->dwPID > e2->dwPID) - (e1->dwPID < e2->dwPID);
}

int MSysProcCpu_CompareUsage(_In_ const void *p1, _In_ const void *p2)
{
    PMCPU_ENTRY e1 = *(PMCPU_ENTRY *)p1, e2 = *(PMCPU_ENTRY *)p2;
    if(e1->fPercent != e2->fPercent) { return e1->fPercent ? -1 : 1; }
    if(e1->fPercent && (e1->cpu != e2->cpu)) { return (e1->cpu < e2->cpu) ? 1 : -1; }
    return (e1->dwPID > e2->dwPID) - (e1->dwPID < e2->dwPID);
}

/* Borrowed from s. Only readers of a sorted file build its order; the source map stays unchanged. */
_Success_(return != NULL)
PMCPU_ENTRY *MSysProcCpu_GetSorted(_In_ PMCPU_CONTEXT ctx, _In_ PMCPU_SNAPSHOT pS, _In_ BOOL fUsage)
{
    PMCPU_ENTRY *pp;
    DWORD i, c = ObMap_Size(pS->pmProcess);
    AcquireSRWLockExclusive(&ctx->LockSRW);
    pp = fUsage ? pS->ppUsage : pS->ppTime;
    if(!pp && (pp = LocalAlloc(LMEM_ZEROINIT, max(1, c) * sizeof(*pp)))) {
        for(i = 0; i < c; i++) { pp[i] = ObMap_GetByIndex(pS->pmProcess, i); }
        qsort(pp, c, sizeof(*pp), fUsage ? MSysProcCpu_CompareUsage : MSysProcCpu_CompareTime);
        if(fUsage) { pS->ppUsage = pp; } else { pS->ppTime = pp; }
    }
    ReleaseSRWLockExclusive(&ctx->LockSRW);
    return pp;
}

VOID MSysProcCpu_ReadLine(_In_ VMM_HANDLE H, _In_ PMCPU_SNAPSHOT pS, _In_ DWORD cbLine, _In_ DWORD i, _In_ PMCPU_ENTRY pe, _Out_ LPSTR sz)
{
    CHAR kernel[32] = "---", user[32] = "---", total[32] = "---", cpu[16] = "---", interval[24] = "---";
    if(pe->fValid) {
        snprintf(kernel, sizeof(kernel), "%.3f", (double)pe->cKernel * pS->dwIncrement / 10000000.0);
        snprintf(user, sizeof(user), "%.3f", (double)pe->cUser * pS->dwIncrement / 10000000.0);
        snprintf(total, sizeof(total), "%.3f", (double)(pe->cKernel + pe->cUser) * pS->dwIncrement / 10000000.0);
    }
    if(pe->fPercent) {
        snprintf(cpu, sizeof(cpu), "%.2f", pe->cpu);
        snprintf(interval, sizeof(interval), "%.3f", pe->seconds);
    }
    Util_usnprintf_ln(sz, cbLine, "%7u %-15s %17s %17s %17s %6s %8s %5u %s",
        pe->dwPID, pe->szName, kernel, user, total, cpu, interval, pe->cThreads, pe->szStatus);
}

PVOID MSysProcCpu_SortedEntry(_In_ VMM_HANDLE H, _In_ PMCPU_ENTRY *pp, _In_ DWORD i)
{
    return pp[i];
}

PVOID MSysProcCpu_MapEntry(_In_ VMM_HANDLE H, _In_ POB_MAP pm, _In_ DWORD i)
{
    return ObMap_GetByIndex(pm, i);
}

NTSTATUS MSysProcCpu_Read(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_CONTEXT ctxP, _Out_writes_(cb) PBYTE pb, _In_ DWORD cb,
    _Out_ PDWORD pcbRead, _In_ QWORD cbOffset)
{
    NTSTATUS nt = VMMDLL_STATUS_FILE_INVALID;
    PMCPU_SNAPSHOT pObSnapshot;
    PVOID pvMap;
    UTIL_VFSLINEFIXED_MAP_PFN_CB pfnMap = (UTIL_VFSLINEFIXED_MAP_PFN_CB)MSysProcCpu_SortedEntry;
    DWORD c;
    BOOL f, fTime, fUsage;
    *pcbRead = 0;
    if(!_stricmp(ctxP->uszPath, "readme.txt")) {
        return Util_VfsReadFile_FromPBYTE((PBYTE)szMPerfReadme, sizeof(szMPerfReadme) - 1, pb, cb, pcbRead, cbOffset);
    }
    fTime = !_stricmp(ctxP->uszPath, "cpu-time.txt");
    fUsage = !_stricmp(ctxP->uszPath, "cpu-usage.txt");
    f = !_stricmp(ctxP->uszPath, "cpu.txt") || fTime || (fUsage && H->dev.fVolatile);
    if(!f) { return nt; }
    if(!cb) { return VMMDLL_STATUS_END_OF_FILE; }
    if(!(pObSnapshot = MSysProcCpu_GetSnapshot(H, ctxP))) { return nt; }
    c = ObMap_Size(pObSnapshot->pmProcess);
    if(cbOffset >= UTIL_VFSLINEFIXED_LINECOUNT(H, c) * MPERF_LINE_LENGTH) { nt = VMMDLL_STATUS_END_OF_FILE; goto finish; }
    if(fTime || fUsage) {
        if(!(pvMap = MSysProcCpu_GetSorted((PMCPU_CONTEXT)ctxP->ctxM, pObSnapshot, fUsage))) { goto finish; }
    } else {
        pvMap = pObSnapshot->pmProcess;
        pfnMap = (UTIL_VFSLINEFIXED_MAP_PFN_CB)MSysProcCpu_MapEntry;
    }
    nt = Util_VfsLineFixedMapCustom_Read(H, (UTIL_VFSLINEFIXED_PFN_CB)MSysProcCpu_ReadLine, pObSnapshot, MPERF_LINE_LENGTH, MPERF_LINE_HEADER,
        pvMap, c, pfnMap, pb, cb, pcbRead, cbOffset);
finish:
    Ob_DECREF(pObSnapshot);
    return nt;
}

BOOL MSysProcCpu_List(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_CONTEXT ctxP, _Inout_ PHANDLE pFileList)
{
    PMCPU_SNAPSHOT pObSnapshot;
    QWORD cbFile;
    if(ctxP->uszPath[0]) { return FALSE; }
    VMMDLL_VfsList_AddFile(pFileList, "readme.txt", sizeof(szMPerfReadme) - 1, NULL);
    if((pObSnapshot = MSysProcCpu_GetSnapshot(H, ctxP))) {
        cbFile = UTIL_VFSLINEFIXED_LINECOUNT(H, ObMap_Size(pObSnapshot->pmProcess)) * MPERF_LINE_LENGTH;
        VMMDLL_VfsList_AddFile(pFileList, "cpu.txt", cbFile, NULL);
        VMMDLL_VfsList_AddFile(pFileList, "cpu-time.txt", cbFile, NULL);
        if(H->dev.fVolatile) { VMMDLL_VfsList_AddFile(pFileList, "cpu-usage.txt", cbFile, NULL); }
        Ob_DECREF(pObSnapshot);
    }
    return TRUE;
}

VOID MSysProcCpu_Notify(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_CONTEXT ctxP, _In_ DWORD fEvent, _In_opt_ PVOID pvEvent, _In_ DWORD cbEvent)
{
    if((fEvent == VMMDLL_PLUGIN_NOTIFY_REFRESH_FAST) || (fEvent == VMMDLL_PLUGIN_NOTIFY_REFRESH_MEDIUM)) {
        InterlockedIncrement64(&((PMCPU_CONTEXT)ctxP->ctxM)->qwRefresh);
    }
}

VOID MSysProcCpu_Close(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_CONTEXT ctxP)
{
    Ob_DECREF(ctxP->ctxM);
}

VOID M_SysProcCpu_Initialize(_In_ VMM_HANDLE H, _Inout_ PVMMDLL_PLUGIN_REGINFO pRI)
{
    PMCPU_CONTEXT pObContext;
    if((pRI->magic != VMMDLL_PLUGIN_REGINFO_MAGIC) || (pRI->wVersion != VMMDLL_PLUGIN_REGINFO_VERSION)) { return; }
    if((pRI->tpSystem != VMMDLL_SYSTEM_WINDOWS_64) && (pRI->tpSystem != VMMDLL_SYSTEM_WINDOWS_32)) { return; }
    if(pRI->sysinfo.dwVersionBuild < 6000) { return; }              // Vista+ required.
    if(H->vmm.tpMemoryModel == VMM_MEMORYMODEL_ARM64) { return; }
    if(!(pObContext = Ob_AllocEx(H, OB_TAG_MOD_CPU, LMEM_ZEROINIT, sizeof(*pObContext), (OB_CLEANUP_CB)MSysProcCpu_ContextCleanupCB, NULL))) { return; }
    InitializeSRWLock(&pObContext->LockSRW);
    pRI->reg_info.ctxM = (PVMMDLL_PLUGIN_INTERNAL_CONTEXT)pObContext;
    strcpy_s(pRI->reg_info.uszPathName, 128, "\\sys\\proc\\cpu");
    pRI->reg_info.fRootModule = TRUE;
    pRI->reg_fn.pfnList = MSysProcCpu_List;
    pRI->reg_fn.pfnRead = MSysProcCpu_Read;
    pRI->reg_fn.pfnNotify = MSysProcCpu_Notify;
    pRI->reg_fn.pfnClose = MSysProcCpu_Close;
    if(!pRI->pfnPluginManager_Register(H, pRI)) { Ob_DECREF(pObContext); }
}
