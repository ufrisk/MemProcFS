// vmmwork.c : implementation of the internal MemprocFS 'work' threading solution.
//
// (c) Ulf Frisk, 2022-2023
// Author: Ulf Frisk, pcileech@frizk.net
//

#include "vmm.h"
#include "ob/ob.h"
#include "ob/ob_tag.h"

// ----------------------------------------------------------------------------
// WORK (THREAD POOL) API:
// The 'Work' thread pool contain by default 16 threads which is waiting to
// receive work scheduled by calling the VmmWork function.
// ----------------------------------------------------------------------------

typedef struct tdVMMWORK_CONTEXT {
    POB_SET psThreadAvail;      // available (sleeping) threads
    POB_SET psThreadAll;        // all (alive non exited) threads
    POB_SET psThreadExit;       // exited (dead) threads
    POB_MAP pmUnit;             // normal prio work units
    POB_MAP pmUnitLow;          // low prio work units (per-process actions)
} VMMWORK_CONTEXT, *PVMMWORK_CONTEXT;

typedef struct tdVMMWORK_THREAD_CONTEXT {
    VMM_HANDLE H;                           // VMM handle
    HANDLE hEventWakeup;                    // wakeup event for the thread
    HANDLE hThread;                         // thread handle
} VMMWORK_THREAD_CONTEXT, *PVMMWORK_THREAD_CONTEXT;

typedef struct tdOB_VMMWORK_UNIT {
    OB ObHdr;
    VMM_HANDLE H;                               // VMM handle
    PVMM_WORK_START_ROUTINE_PVOID_PFN pfnVoid;  // by-void function to call
    PVOID ctxVoid;                              // by-void optional function parameter
    PVMM_WORK_START_ROUTINE_VALUE_PFN pfnValue; // by-value function to call
    QWORD ctxValue;                             // by-value context/value.
    PVMM_WORK_START_ROUTINE_OB_PFN pfnOb;       // by-object function to call
    POB ctxOb;                                  // by-object context/object.
    HANDLE hEventFinish;                        // optional event to set when upon work completion
} OB_VMMWORK_UNIT, *POB_VMMWORK_UNIT;

VOID VmmWork_CallbackCleanup_ObVmmWorkUnit(_In_ PVOID pOb)
{
    POB_VMMWORK_UNIT pObWorkUnit = pOb;
    Ob_DECREF(pObWorkUnit->ctxOb);
    if(pObWorkUnit->hEventFinish) {
        SetEvent(pObWorkUnit->hEventFinish);
    }
}

/*
* Main worker thread loop. It will perform a work unit if available otherwise
* sleep until work becomes available.
*/
DWORD VmmWork_MainWorkerLoop_ThreadProc(PVMMWORK_THREAD_CONTEXT ctx)
{
    POB_VMMWORK_UNIT puOb;
    VMM_HANDLE H = ctx->H;
    InterlockedIncrement(&H->cThreadInternal);
    while(!H->fAbort) {
        puOb = (POB_VMMWORK_UNIT)ObMap_Pop(H->work->pmUnit);
        if(!puOb && (ObSet_Size(H->work->psThreadAvail) > (VMM_WORK_THREADPOOL_NUM_THREADS / 2))) {
            puOb = (POB_VMMWORK_UNIT)ObMap_Pop(H->work->pmUnitLow);
        }
        if(puOb) {
            if(puOb->pfnVoid) {
                puOb->pfnVoid(puOb->H, puOb->ctxVoid);
            }
            if(puOb->pfnValue) {
                puOb->pfnValue(puOb->H, puOb->ctxValue);
            }
            if(puOb->pfnOb) {
                puOb->pfnOb(puOb->H, puOb->ctxOb);
            }
            Ob_DECREF_NULL(&puOb);
        } else {
            ResetEvent(ctx->hEventWakeup);
            ObSet_Push(H->work->psThreadAvail, (QWORD)ctx);
            WaitForSingleObject(ctx->hEventWakeup, INFINITE);
        }
    }
    ObSet_Remove(H->work->psThreadAll, (QWORD)ctx);
    ObSet_Push(H->work->psThreadExit, (QWORD)ctx);
    InterlockedDecrement(&H->cThreadInternal);
    return 1;
}

/*
* Initialize the VmmWork sub-system. This should only be done at handle init.
* -- H
* -- return
*/
_Success_(return)
BOOL VmmWork_Initialize(_In_ VMM_HANDLE H)
{
    PVMMWORK_THREAD_CONTEXT p;
    PVMMWORK_CONTEXT ctx = NULL;
    if(!(ctx = (PVMMWORK_CONTEXT)LocalAlloc(LMEM_ZEROINIT, sizeof(VMMWORK_CONTEXT)))) { goto fail; }
    if(!(ctx->pmUnit = ObMap_New(H, OB_MAP_FLAGS_OBJECT_OB | OB_MAP_FLAGS_NOKEY)))    { goto fail; }
    if(!(ctx->pmUnitLow = ObMap_New(H, OB_MAP_FLAGS_OBJECT_OB | OB_MAP_FLAGS_NOKEY))) { goto fail; }
    if(!(ctx->psThreadAll = ObSet_New(H)))   { goto fail; }
    if(!(ctx->psThreadExit = ObSet_New(H)))  { goto fail; }
    if(!(ctx->psThreadAvail = ObSet_New(H))) { goto fail; }
    H->work = ctx;
    while(ObSet_Size(ctx->psThreadAll) < VMM_WORK_THREADPOOL_NUM_THREADS) {
        if((p = LocalAlloc(LMEM_ZEROINIT, sizeof(VMMWORK_THREAD_CONTEXT)))) {
            p->H = H;
            p->hEventWakeup = CreateEvent(NULL, TRUE, FALSE, NULL);
            p->hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)VmmWork_MainWorkerLoop_ThreadProc, p, 0, NULL);
            ObSet_Push(ctx->psThreadAll, (QWORD)p);
        }
    }
    return TRUE;
fail:
    LocalFree(ctx);
    return FALSE;
}

/*
* Interrupt the VmmWork sub-system (exit threads pre-maturely). This is
* done early in the cleanup process before VmmWork_Close() is called.
* -- H
*/
VOID VmmWork_Interrupt(_In_ VMM_HANDLE H)
{
    PVMMWORK_THREAD_CONTEXT pt;
    if(H->work) {
        // 1: set wakeup event for all available (waiting) threads
        while((pt = (PVMMWORK_THREAD_CONTEXT)ObSet_Pop(H->work->psThreadAvail))) {
            SetEvent(pt->hEventWakeup);
        }
        // 2: cleanup still queued work units
        ObMap_Clear(H->work->pmUnit);
        ObMap_Clear(H->work->pmUnitLow);
    }
}

/*
* Close the VmmWork sub-system. Wait until all worker threads have exited.
* -- H
*/
VOID VmmWork_Close(_In_ VMM_HANDLE H)
{
    PVMMWORK_THREAD_CONTEXT pt = NULL;
    if(H->work) {
        // 1: wait for exit of all threads
        while(ObSet_Size(H->work->psThreadAll)) {
            while((pt = (PVMMWORK_THREAD_CONTEXT)ObSet_GetNext(H->work->psThreadAll, (QWORD)pt))) {
                SetEvent(pt->hEventWakeup);
            }
            SwitchToThread();
        }
        // 2: cleanup still queued work units
        ObMap_Clear(H->work->pmUnit);
        ObMap_Clear(H->work->pmUnitLow);
        // 3: cleanup exited threads and their contexts
        while((pt = (PVMMWORK_THREAD_CONTEXT)ObSet_Pop(H->work->psThreadExit))) {
            CloseHandle(pt->hEventWakeup);
            CloseHandle(pt->hThread);
            LocalFree(pt);
        }
        // 4: cleanup main work context
        Ob_DECREF(H->work->pmUnit);
        Ob_DECREF(H->work->pmUnitLow);
        Ob_DECREF(H->work->psThreadAll);
        Ob_DECREF(H->work->psThreadExit);
        Ob_DECREF(H->work->psThreadAvail);
        LocalFree(H->work); H->work = NULL;
    }
}

/*
* Queue a work item object.
* -- H
* -- flags = VMMWORK_FLAG_*
* -- ppu
*/
VOID VmmWork_QueueWorkUnit_DECREF_NULL(_In_ VMM_HANDLE H, _In_ DWORD flags, _In_ POB_VMMWORK_UNIT *ppu)
{
    PVMMWORK_THREAD_CONTEXT pt;
    if(!H->fAbort) {
        if(flags & VMMWORK_FLAG_PRIO_LOW) {
            if((*ppu)->hEventFinish) { ResetEvent((*ppu)->hEventFinish); }
            ObMap_Push(H->work->pmUnitLow, 0, *ppu);        
        } else {
            if((*ppu)->hEventFinish) { ResetEvent((*ppu)->hEventFinish); }
            ObMap_Push(H->work->pmUnit, 0, *ppu);
        }
        if((pt = (PVMMWORK_THREAD_CONTEXT)ObSet_Pop(H->work->psThreadAvail))) {
            SetEvent(pt->hEventWakeup);
        }
    }
    Ob_DECREF_NULL(ppu);
}

VOID VmmWork_Value(_In_ VMM_HANDLE H, _In_ PVMM_WORK_START_ROUTINE_VALUE_PFN pfn, _In_ QWORD ctx, _In_opt_ HANDLE hEventFinish, _In_ DWORD flags)
{
    POB_VMMWORK_UNIT pObU;
    if((pObU = Ob_AllocEx(H, OB_TAG_WORK_WORKUNIT, LMEM_ZEROINIT, sizeof(OB_VMMWORK_UNIT), VmmWork_CallbackCleanup_ObVmmWorkUnit, NULL))) {
        pObU->H = H;
        pObU->pfnValue = pfn;
        pObU->ctxValue = ctx;
        pObU->hEventFinish = hEventFinish;
        VmmWork_QueueWorkUnit_DECREF_NULL(H, flags, &pObU);
    }
}

VOID VmmWork_Ob(_In_ VMM_HANDLE H, _In_ PVMM_WORK_START_ROUTINE_OB_PFN pfn, _In_ POB ctx, _In_opt_ HANDLE hEventFinish, _In_ DWORD flags)
{
    POB_VMMWORK_UNIT pObU;
    if((pObU = Ob_AllocEx(H, OB_TAG_WORK_WORKUNIT, LMEM_ZEROINIT, sizeof(OB_VMMWORK_UNIT), VmmWork_CallbackCleanup_ObVmmWorkUnit, NULL))) {
        pObU->H = H;
        pObU->pfnOb = pfn;
        pObU->ctxOb = Ob_INCREF(ctx);
        pObU->hEventFinish = hEventFinish;
        VmmWork_QueueWorkUnit_DECREF_NULL(H, flags, &pObU);
    }
}

VOID VmmWork_Void(_In_ VMM_HANDLE H, _In_ PVMM_WORK_START_ROUTINE_PVOID_PFN pfn, _In_ PVOID ctx, _In_opt_ HANDLE hEventFinish, _In_ DWORD flags)
{
    POB_VMMWORK_UNIT pObU;
    if((pObU = Ob_AllocEx(H, OB_TAG_WORK_WORKUNIT, LMEM_ZEROINIT, sizeof(OB_VMMWORK_UNIT), VmmWork_CallbackCleanup_ObVmmWorkUnit, NULL))) {
        pObU->H = H;
        pObU->pfnVoid = pfn;
        pObU->ctxVoid = ctx;
        pObU->hEventFinish = hEventFinish;
        VmmWork_QueueWorkUnit_DECREF_NULL(H, flags, &pObU);
    }
}

VOID VmmWorkWaitMultiple2_Void(_In_ VMM_HANDLE H, _In_ DWORD cWork, _In_count_(cWork) PVMM_WORK_START_ROUTINE_PVOID_PFN *pfns, _In_count_(cWork) PVOID *ctxs)
{
    DWORD i;
    HANDLE hEventFinish[MAXIMUM_WAIT_OBJECTS];
    if(H->fAbort || (cWork == 0) || (cWork > MAXIMUM_WAIT_OBJECTS)) { return; }
    for(i = 1; i < cWork; i++) {
        hEventFinish[i] = CreateEvent(NULL, TRUE, FALSE, NULL);
        VmmWork_Void(H, pfns[i], ctxs[i], hEventFinish[i], VMMWORK_FLAG_PRIO_NORMAL);
    }
    pfns[0](H, ctxs[0]);
    WaitForMultipleObjects(cWork - 1, hEventFinish + 1, TRUE, INFINITE);
    for(i = 1; i < cWork; i++) {
        if(hEventFinish[i]) {
            CloseHandle(hEventFinish[i]);
        }
    }
}

VOID VmmWorkWaitMultiple_Void(_In_ VMM_HANDLE H, _In_ PVOID ctx, _In_ DWORD cWork, ...)
{
    DWORD i;
    va_list arguments;
    PVOID ctxs[MAXIMUM_WAIT_OBJECTS];
    PVMM_WORK_START_ROUTINE_PVOID_PFN pfns[MAXIMUM_WAIT_OBJECTS];
    if(H->fAbort || (cWork == 0) || (cWork > MAXIMUM_WAIT_OBJECTS)) { return; }
    va_start(arguments, cWork);
    for(i = 0; i < cWork; i++) {
        ctxs[i] = ctx;
        pfns[i] = va_arg(arguments, PVMM_WORK_START_ROUTINE_PVOID_PFN);
    }
    va_end(arguments);
    VmmWorkWaitMultiple2_Void(H, cWork, pfns, ctxs);
}



// ----------------------------------------------------------------------------
// PROCESS PARALLELIZATION FUNCTIONALITY:
// ----------------------------------------------------------------------------

typedef struct tdOB_VMMWORK_FOREACH_PROCESS {
    OB ObHdr;
    VMM_HANDLE H;
    HANDLE hEventFinish;
    VOID(*pfnAction)(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess, _In_ PVOID ctx);
    PVOID ctxAction;
    DWORD iPID;                 // set to dwPIDs count on entry and decremented as-goes
    DWORD dwPIDs[];
} OB_VMMWORK_FOREACH_PROCESS, *POB_VMMWORK_FOREACH_PROCESS;

VOID VmmWork_CallbackCleanup0_ObVmmWorkForeachProcess(_In_ PVOID pOb)
{
    POB_VMMWORK_FOREACH_PROCESS pObProc = pOb;
    if(pObProc->hEventFinish) {
        CloseHandle(pObProc->hEventFinish);
    }
}

VOID VmmWork_CallbackCleanup1_ObVmmWorkForeachProcess(_In_ PVOID pOb)
{
    POB_VMMWORK_FOREACH_PROCESS pObProc = pOb;
    SetEvent(pObProc->hEventFinish);
}

VOID VmmWork_ProcessActionForeachParallel_ThreadProc(_In_ VMM_HANDLE H, _In_ POB_VMMWORK_FOREACH_PROCESS ctx)
{
    PVMM_PROCESS pObProcess = VmmProcessGet(H, ctx->dwPIDs[InterlockedDecrement(&ctx->iPID)]);
    if(pObProcess) {
        ctx->pfnAction(H, pObProcess, ctx->ctxAction);
        Ob_DECREF(pObProcess);
    }
}

BOOL VmmWork_ProcessActionForeachParallel_CriteriaActiveOnly(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess, _In_opt_ PVOID ctx)
{
    return pProcess->dwState == 0;
}

BOOL VmmWork_ProcessActionForeachParallel_CriteriaActiveUserOnly(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess, _In_opt_ PVOID ctx)
{
    return (pProcess->dwState == 0) && pProcess->fUserOnly;
}

_Success_(return)
BOOL VmmWork_ProcessActionForeachParallel_Void(
    _In_ VMM_HANDLE H,
    _In_opt_ DWORD cMaxThread,
    _In_opt_ PVOID ctxAction,
    _In_opt_ PVMM_WORK_PROCESS_CRITERIA_PVOID_PFN pfnCriteria,
    _In_ PVMM_WORK_PROCESS_START_ROUTINE_PVOID_PFN pfnAction
) {
    BOOL fResult = FALSE;
    DWORD i, cProcess;
    PVMM_PROCESS pObProcess = NULL;
    POB_SET pObProcessSelectedSet = NULL;
    POB_VMMWORK_FOREACH_PROCESS ctxOb = NULL;
    cMaxThread = max(2, cMaxThread);
    cMaxThread = min(cMaxThread, VMM_WORK_THREADPOOL_NUM_THREADS / 4);
    // 1: select processes to queue using criteria function
    if(!(pObProcessSelectedSet = ObSet_New(H))) { goto fail; }
    while((pObProcess = VmmProcessGetNext(H, pObProcess, VMM_FLAG_PROCESS_SHOW_TERMINATED))) {
        if(!pfnCriteria || pfnCriteria(H, pObProcess, ctxOb)) {
            ObSet_Push(pObProcessSelectedSet, pObProcess->dwPID);
        }
    }
    // 2: set up context for worker function
    ctxOb = Ob_AllocEx(
        H,
        OB_TAG_WORK_PER_PROCESS,
        LMEM_ZEROINIT,
        sizeof(OB_VMMWORK_FOREACH_PROCESS) + cMaxThread * sizeof(DWORD),
        VmmWork_CallbackCleanup0_ObVmmWorkForeachProcess,
        VmmWork_CallbackCleanup1_ObVmmWorkForeachProcess);
    if(!ctxOb) { goto fail; }
    if(!(ctxOb->hEventFinish = CreateEvent(NULL, TRUE, FALSE, NULL))) { goto fail; }
    ctxOb->H = H;
    ctxOb->pfnAction = pfnAction;
    ctxOb->ctxAction = ctxAction;
    while((cProcess = ObSet_Size(pObProcessSelectedSet))) {
        cProcess = min(cProcess, cMaxThread);
        ctxOb->iPID = cProcess;
        for(i = 0; i < cProcess; i++) {
            ctxOb->dwPIDs[i] = (DWORD)ObSet_Pop(pObProcessSelectedSet);
        }
        // 3: parallelize onto worker threads and wait for completion
        Ob_INCREF(ctxOb);
        for(i = 0; i < cProcess; i++) {
            VmmWork_Ob(H, (PVMM_WORK_START_ROUTINE_OB_PFN)VmmWork_ProcessActionForeachParallel_ThreadProc, (POB)ctxOb, NULL, VMMWORK_FLAG_PRIO_LOW);
        }
        Ob_DECREF(ctxOb);
        WaitForSingleObject(ctxOb->hEventFinish, INFINITE);
        ResetEvent(ctxOb->hEventFinish);
        if(H->fAbort) { goto fail; }
    }
    fResult = TRUE;
fail:
    Ob_DECREF(pObProcessSelectedSet);
    Ob_DECREF(ctxOb);
    return fResult;
}
