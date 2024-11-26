// vmmwinthread.c : implementations related to windows threading.
//
// (c) Ulf Frisk, 2024
// Author: Ulf Frisk, pcileech@frizk.net
//

#include "vmmwinthread.h"
#include "vmm.h"
#include "vmmwin.h"
#include "charutil.h"
#include "pdb.h"
#include "pe.h"

// ----------------------------------------------------------------------------
// THREADING FUNCTIONALITY BELOW:
//
// The threading subsystem is dependent on loaded kernel pdb symbols and being
// initialized asynchronously at startup. i.e. it may not be immediately avail-
// able at startup time or not available at all. Loading threads may be slow
// the first time if many threads exist in a process since a list have to be
// traversed - hence functionality exists to start a load asynchronously.
// ----------------------------------------------------------------------------

typedef struct tdVMMWIN_INITIALIZETHREAD_CONTEXT {
    POB_MAP pmThread;
    POB_SET psObTeb;
    POB_SET psObTrapFrame;
    PVMM_PROCESS pProcess;
} VMMWIN_INITIALIZETHREAD_CONTEXT, *PVMMWIN_INITIALIZETHREAD_CONTEXT;

int VmmWinThread_Initialize_CmpThreadEntry(PVMM_MAP_THREADENTRY v1, PVMM_MAP_THREADENTRY v2)
{
    return
        (v1->dwTID < v2->dwTID) ? -1 :
        (v1->dwTID > v2->dwTID) ? 1 : 0;
}

VOID VmmWinThread_Initialize_DoWork_Pre(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pSystemProcess, _In_opt_ PVMMWIN_INITIALIZETHREAD_CONTEXT ctx, _In_ QWORD va, _In_ PBYTE pb, _In_ DWORD cb, _In_ QWORD vaFLink, _In_ QWORD vaBLink, _In_ POB_SET pVSetAddress, _Inout_ PBOOL pfValidEntry, _Inout_ PBOOL pfValidFLink, _Inout_ PBOOL pfValidBLink)
{
    BOOL f, f32 = H->vmm.f32;
    DWORD dwTID;
    PVMM_MAP_THREADENTRY e;
    PVMM_OFFSET_ETHREAD ot = &H->vmm.offset.ETHREAD;
    // 1: sanity check
    f = ctx &&
        (f32 ? VMM_KADDR32_4(vaFLink) : VMM_KADDR64_8(vaFLink)) &&
        (f32 ? VMM_KADDR32_4(vaBLink) : VMM_KADDR64_8(vaBLink)) &&
        (!ot->oProcessOpt || (VMM_PTR_OFFSET(f32, pb, ot->oProcessOpt) == ctx->pProcess->win.EPROCESS.va)) &&
        (dwTID = (DWORD)VMM_PTR_OFFSET(f32, pb, ot->oCid + (f32 ? 4ULL : 8ULL)));
    if(!f) { return; }
    *pfValidEntry = *pfValidFLink = *pfValidBLink = TRUE;
    // 2: allocate and populate thread entry with info.
    if(!(e = LocalAlloc(LMEM_ZEROINIT, sizeof(VMM_MAP_THREADENTRY)))) { return; }
    e->vaETHREAD = va;
    e->dwTID = dwTID;
    e->dwPID = (DWORD)VMM_PTR_OFFSET(f32, pb, ot->oCid);
    e->dwExitStatus = *(PDWORD)(pb + ot->oExitStatus);
    e->bState = *(PUCHAR)(pb + ot->oState);
    e->bSuspendCount = *(PUCHAR)(pb + ot->oSuspendCount);
    if(ot->oRunningOpt) { e->bRunning = *(PUCHAR)(pb + ot->oRunningOpt); }
    e->bPriority = *(PUCHAR)(pb + ot->oPriority);
    e->bBasePriority = *(PUCHAR)(pb + ot->oBasePriority);
    e->bWaitReason = *(PUCHAR)(pb + ot->oWaitReason);
    e->vaTeb = VMM_PTR_OFFSET(f32, pb, ot->oTeb);
    e->ftCreateTime = *(PQWORD)(pb + ot->oCreateTime);
    e->ftExitTime = *(PQWORD)(pb + ot->oExitTime);
    e->vaStartAddress = VMM_PTR_OFFSET(f32, pb, ot->oStartAddress);
    e->vaImpersonationToken = ot->oClientSecurityOpt ? VMM_PTR_EX_FAST_REF(f32, VMM_PTR_OFFSET(f32, pb, ot->oClientSecurityOpt)) : 0;
    e->vaWin32StartAddress = VMM_PTR_OFFSET(f32, pb, ot->oWin32StartAddress);
    e->vaStackBaseKernel = VMM_PTR_OFFSET(f32, pb, ot->oStackBase);
    e->vaStackLimitKernel = VMM_PTR_OFFSET(f32, pb, ot->oStackLimit);
    e->vaTrapFrame = VMM_PTR_OFFSET(f32, pb, ot->oTrapFrame);
    e->qwAffinity = VMM_PTR_OFFSET(f32, pb, ot->oAffinity);
    e->dwKernelTime = *(PDWORD)(pb + ot->oKernelTime);
    e->dwUserTime = *(PDWORD)(pb + ot->oUserTime);
    if(e->ftExitTime > 0x0200000000000000) { e->ftExitTime = 0; }
    ObSet_Push(ctx->psObTeb, e->vaTeb);
    ObSet_Push(ctx->psObTrapFrame, e->vaTrapFrame);
    ObMap_Push(ctx->pmThread, e->dwTID, e);  // map will free allocation when cleared
}

VOID VmmWinThread_Initialize_DoWork(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess)
{
    BOOL f, f32 = H->vmm.f32;
    BYTE pb[0x200];
    DWORD i, cMap, cbTrapFrame = 0;
    QWORD va, vaThreadListEntry;
    POB_SET psObTeb = NULL, psObTrapFrame = NULL;
    POB_MAP pmObThreads = NULL;
    PVMMOB_MAP_THREAD pObThreadMap = NULL;
    PVMM_MAP_THREADENTRY pThreadEntry;
    PVMM_PROCESS pObSystemProcess = NULL;
    VMMWIN_INITIALIZETHREAD_CONTEXT ctx = { 0 };
    PVMM_OFFSET_ETHREAD ot = &H->vmm.offset.ETHREAD;
    // 1: set up and perform list traversal call.
    vaThreadListEntry = VMM_PTR_OFFSET(f32, pProcess->win.EPROCESS.pb, H->vmm.offset.ETHREAD.oThreadListHeadKP);
    if(f32 ? !VMM_KADDR32_4(vaThreadListEntry) : !VMM_KADDR64_8(vaThreadListEntry)) { goto fail; }
    if(!(pObSystemProcess = VmmProcessGet(H, 4))) { goto fail; }
    if(!(psObTeb = ObSet_New(H))) { goto fail; }
    if(!(psObTrapFrame = ObSet_New(H))) { goto fail; }
    if(!(pmObThreads = ObMap_New(H, OB_MAP_FLAGS_OBJECT_LOCALFREE))) { goto fail; }
    ctx.pmThread = pmObThreads;
    ctx.psObTeb = psObTeb;
    ctx.psObTrapFrame = psObTrapFrame;
    ctx.pProcess = pProcess;
    va = vaThreadListEntry - H->vmm.offset.ETHREAD.oThreadListEntry;
    VmmWin_ListTraversePrefetch(
        H,
        pObSystemProcess,
        f32,
        &ctx,
        1,
        &va,
        H->vmm.offset.ETHREAD.oThreadListEntry,
        H->vmm.offset.ETHREAD.oMax,
        (VMMWIN_LISTTRAVERSE_PRE_CB)VmmWinThread_Initialize_DoWork_Pre,
        NULL,
        pProcess->pObPersistent->pObCMapThreadPrefetch);
    // 2: transfer result from generic map into PVMMOB_MAP_THREAD
    if(!(cMap = ObMap_Size(pmObThreads))) { goto fail; }
    if(!(pObThreadMap = Ob_AllocEx(H, OB_TAG_MAP_THREAD, 0, sizeof(VMMOB_MAP_THREAD) + cMap * sizeof(VMM_MAP_THREADENTRY), NULL, NULL))) { goto fail; }
    pObThreadMap->cMap = cMap;
    cbTrapFrame = ((ot->oTrapRsp < 0x200 - 8) && (ot->oTrapRip < 0x200 - 8)) ? 8 + max(ot->oTrapRsp, ot->oTrapRip) : 0;
    VmmCachePrefetchPages3(H, pObSystemProcess, psObTrapFrame, cbTrapFrame, 0);
    VmmCachePrefetchPages3(H, pProcess, psObTeb, 0x20, 0);
    for(i = 0; i < cMap; i++) {
        pThreadEntry = (PVMM_MAP_THREADENTRY)ObMap_GetByIndex(pmObThreads, i);
        // fetch Teb
        if(VmmRead2(H, pProcess, pThreadEntry->vaTeb, pb, 0x20, VMM_FLAG_FORCECACHE_READ)) {
            pThreadEntry->vaStackBaseUser = VMM_PTR_OFFSET_DUAL(f32, pb, 4, 8);
            pThreadEntry->vaStackLimitUser = VMM_PTR_OFFSET_DUAL(f32, pb, 8, 16);
        }
        // fetch TrapFrame (RSP/RIP)
        if(cbTrapFrame && VmmRead2(H, pObSystemProcess, pThreadEntry->vaTrapFrame, pb, cbTrapFrame, VMM_FLAG_FORCECACHE_READ)) {
            pThreadEntry->vaRIP = VMM_PTR_OFFSET(f32, pb, ot->oTrapRip);
            pThreadEntry->vaRSP = VMM_PTR_OFFSET(f32, pb, ot->oTrapRsp);
            f = ((pThreadEntry->vaStackBaseUser > pThreadEntry->vaRSP) && (pThreadEntry->vaStackLimitUser < pThreadEntry->vaRSP)) ||
                ((pThreadEntry->vaStackBaseKernel > pThreadEntry->vaRSP) && (pThreadEntry->vaStackLimitKernel < pThreadEntry->vaRSP));
            if(!f) {
                pThreadEntry->vaRIP = 0;
                pThreadEntry->vaRSP = 0;
            }
        }
        // commit
        memcpy(pObThreadMap->pMap + i, pThreadEntry, sizeof(VMM_MAP_THREADENTRY));
    }
    // 3: sort on thread id (TID) and assign result to process object.
    qsort(pObThreadMap->pMap, cMap, sizeof(VMM_MAP_THREADENTRY), (int(*)(const void *, const void *))VmmWinThread_Initialize_CmpThreadEntry);
    pProcess->Map.pObThread = pObThreadMap;     // pProcess take reference responsibility
fail:
    Ob_DECREF(psObTeb);
    Ob_DECREF(psObTrapFrame);
    Ob_DECREF(pmObThreads);
    Ob_DECREF(pObSystemProcess);
}

/*
* Initialize the thread map for a specific process.
* NB! The threading sub-system is dependent on pdb symbols and may take a small
* amount of time before it's available after system startup.
* -- H
* -- pProcess
* -- return
*/
_Success_(return)
BOOL VmmWinThread_Initialize(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess)
{
    if(pProcess->Map.pObThread) { return TRUE; }
    if(!H->vmm.fThreadMapEnabled) { return FALSE; }
    VmmTlbSpider(H, pProcess);
    EnterCriticalSection(&pProcess->LockUpdate);
    if(!pProcess->Map.pObThread) {
        VmmWinThread_Initialize_DoWork(H, pProcess);
        if(!pProcess->Map.pObThread) {
            pProcess->Map.pObThread = Ob_AllocEx(H, OB_TAG_MAP_THREAD, LMEM_ZEROINIT, sizeof(VMMOB_MAP_THREAD), NULL, NULL);
        }
    }
    LeaveCriticalSection(&pProcess->LockUpdate);
    return pProcess->Map.pObThread ? TRUE : FALSE;
}



// ----------------------------------------------------------------------------
// CallStack unwinding features for threads in memory dumps
//
// Contributed under BSD 0-Clause License (0BSD)
// Author: MattCore71
// ----------------------------------------------------------------------------

#define UWOP_PUSH_NONVOL        0x0   
#define UWOP_ALLOC_LARGE        0x01     
#define UWOP_ALLOC_SMALL        0x02    
#define UWOP_SET_FPREG          0x03     
#define UWOP_SAVE_NONVOL        0x04    
#define UWOP_SAVE_NONVOL_FAR    0x05
#define UWOP_SAVE_XMM128        0x08    
#define UWOP_SAVE_XMM128_FAR    0x09 
#define UWOP_PUSH_MACHFRAME     0x0a

#define UNW_FLAG_NHANDLER       0x0
#define UNW_FLAG_EHANDLER       0x1
#define UNW_FLAG_UHANDLER       0x2
#define UNW_FLAG_CHAININFO      0x4

#define VMMWINTHREADCS_MAX_DEPTH 0x80

typedef struct tdVMMWINTHREAD_SYMBOL {
    CHAR szModule[MAX_PATH];
    CHAR szFunction[MAX_PATH];
    BOOL fSymbolLookupFailed;
    DWORD displacement;
    QWORD retaddress;
} VMMWINTHREAD_SYMBOL, *PVMMWINTHREAD_SYMBOL;

typedef struct tdVMMWINTHREAD_MODULE_SECTION {
    CHAR uszModuleName[MAX_PATH];       // TODO: remove
    QWORD vaModuleBase;
    DWORD size_vad;
    struct {
        CHAR szSectionName[IMAGE_SIZEOF_SHORT_NAME];
        DWORD dwZERO;
        DWORD Address;
        DWORD Size;
    } text;
    struct {
        DWORD Address;
        DWORD Size;
    } pdata;
} VMMWINTHREAD_MODULE_SECTION, *PVMMWINTHREAD_MODULE_SECTION;

typedef struct tdVMMWINTHREAD_FRAME {
    BOOL fRegPresent;
    QWORD vaRetAddr;
    QWORD vaRSP;
    QWORD vaBaseSP;
} VMMWINTHREAD_FRAME, *PVMMWINTHREAD_FRAME;

typedef struct tdVMMWINTHREAD_RSP_UNWINDER {
    QWORD unwind_address;
    QWORD RSP_in;
    QWORD RSP_out;
    BOOL chained;
    DWORD nb_slot_chained;
} VMMWINTHREAD_RSP_UNWINDER, *PVMMWINTHREAD_RSP_UNWINDER;

typedef struct _FRAME_OFFSET_SH {
    USHORT FrameOffset;
} FRAME_OFFSET_SH, *PFRAME_OFFSET_SH;

typedef struct _FRAME_OFFSET_L {
    DWORD FrameOffset;
} FRAME_OFFSET_L, *PFRAME_OFFSET_L;

typedef struct _UNWIND_INFO {
    BYTE Version : 3;
    BYTE Flags : 5;
    BYTE SizeOfProlog;
    BYTE CountOfCodes;
    BYTE FrameRegister_offset;
} UNWIND_INFO, *PUNWIND_INFO;

typedef union _UNWIND_CODE {
    struct {
        BYTE CodeOffset;
        BYTE UnwindOp : 4;
        BYTE OpInfo : 4;
    };
} UNWIND_CODE, *PUNWIND_CODE;

// RUNTIME_FUNCTION_X64
typedef struct _IMAGE_RUNTIME_FUNCTION_ENTRY_X64 {
    DWORD BeginAddress;
    DWORD EndAddress;
    union {
        DWORD UnwindInfoAddress;
        DWORD UnwindData;
    };
} _IMAGE_RUNTIME_FUNCTION_ENTRY_X64, *_PIMAGE_RUNTIME_FUNCTION_ENTRY_X64;

typedef struct _IMAGE_RUNTIME_FUNCTION_ENTRY_X64 RUNTIME_FUNCTION_X64, *PRUNTIME_FUNCTION_X64;

// Forward declarations:
DWORD VmmWinThreadCs_GetModuleSectionFromAddress(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess, _In_ QWORD va, _Out_ PVMMWINTHREAD_MODULE_SECTION pModuleSection);
_Success_(return) BOOL VmmWinThreadCs_GetSymbolFromAddr(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess, _In_ QWORD qwReturnAddress, _Out_ PVMMWINTHREAD_SYMBOL pSymbol);
_Success_(return) BOOL VmmWinThreadCs_HeuristicScanForFrame(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess, _In_ PVMM_MAP_THREADENTRY pThread, _In_ PVMMWINTHREAD_FRAME pCurrentFrame, _Out_ PVMMWINTHREAD_FRAME pReturnScanFrame);
_Success_(return) BOOL VmmWinThreadCs_PopReturnAddress(VMM_HANDLE H, _In_ PVMM_PROCESS pProcess, _In_ QWORD va, _Out_ PQWORD pqwBufferCandidate, _Out_opt_ PVMMWINTHREAD_MODULE_SECTION pModuleSectionOpt);
_Success_(return) BOOL VmmWinThreadCs_RspUnwinder(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess, _In_ PVMM_MAP_THREADENTRY pThread, _Inout_ PVMMWINTHREAD_RSP_UNWINDER pInRSPOut);
_Success_(return) BOOL VmmWinThreadCs_ValidateCandidate(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess, _In_ PVMM_MAP_THREADENTRY pThread, _In_ QWORD vaCandidate, _In_ PVMMWINTHREAD_FRAME pCurrentFrame, _Out_ PVMMWINTHREAD_FRAME pValidationTempFrame);
_Success_(return) BOOL VmmWinThreadCs_ValidateThreadBeforeUnwind(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess, _In_ PVMM_MAP_THREADENTRY pThread);

_Success_(return)
BOOL VmmWinThreadCs_UnwindFrame(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess, _In_ PVMM_MAP_THREADENTRY pThread, _In_ PVMMWINTHREAD_FRAME pCurrentFrame, _Out_ PVMMWINTHREAD_FRAME pFrameOut)
{
    BOOL fResult = FALSE;
    QWORD qwCurrentAddress;
    PBYTE pbPdata = NULL;

    VMMWINTHREAD_MODULE_SECTION sModuleSectionInfo;
    QWORD qwCurrentRSP = 0, vaModuleBase = 0, qwRvaAddress = 0, qwRetAddress = 0;
    DWORD dwResultFromAddress, dwPdataSize;
    DWORD iRuntime, cRuntimeFunctions;

    PRUNTIME_FUNCTION_X64 pRuntimeIter;
    BYTE pbUnwindInfoRead[4];
    UNWIND_INFO* pUnwindInfo = NULL;
    VMMWINTHREAD_RSP_UNWINDER sInRSPOut, sInRSPOutChained;
    DWORD dwUnwindAddress = 0;

    // initial sanity checks:
    // unwinding from metadata is unavailable if not PE or if function fails, exiting
    if(!pCurrentFrame) { goto end; }
    qwCurrentAddress = pCurrentFrame->vaRetAddr;
    dwResultFromAddress = VmmWinThreadCs_GetModuleSectionFromAddress(H, pProcess, qwCurrentAddress, &sModuleSectionInfo);
    if(!dwResultFromAddress) { goto end; }

    // reading all the pdata section containing the RUNTIME_FUNCTION_X64
    vaModuleBase = sModuleSectionInfo.vaModuleBase;
    dwPdataSize = sModuleSectionInfo.pdata.Size;
    pbPdata = LocalAlloc(0, dwPdataSize);
    if(!pbPdata || !VmmRead(H, pProcess, vaModuleBase + sModuleSectionInfo.pdata.Address, pbPdata, dwPdataSize)) { goto end; }
    pRuntimeIter = (PRUNTIME_FUNCTION_X64)pbPdata;
    qwRvaAddress = qwCurrentAddress - vaModuleBase ;
    cRuntimeFunctions = dwPdataSize / sizeof(RUNTIME_FUNCTION_X64); 

    // finding where the previous Return address is located among runtime functions and getting the unwindInfo structure address
    int dwMaxCountRuntime = 0;
    for(iRuntime = 0; iRuntime < cRuntimeFunctions; iRuntime++) {
        if((qwRvaAddress >= pRuntimeIter[iRuntime].BeginAddress) && (qwRvaAddress < pRuntimeIter[iRuntime].EndAddress) && pRuntimeIter[iRuntime].BeginAddress) {
            dwUnwindAddress = pRuntimeIter[iRuntime].UnwindInfoAddress;
            VmmLog(H, MID_THREADCS, LOGLEVEL_6_TRACE, "  UNWIND RUNTIME STRUCT: BEGIN:[%08x] END:[%08x] UNWIND_INFO:[%08x] UNWIND_INFO_ADDR:[%016llx] PID:[%u] TID:[%u]", pRuntimeIter[iRuntime].BeginAddress, pRuntimeIter[iRuntime].EndAddress, (DWORD)dwUnwindAddress, vaModuleBase + dwUnwindAddress, pProcess->dwPID, pThread->dwTID);
            // issue if finding multiple runtime functions corresponding, exiting..
            if (dwMaxCountRuntime > 1) { goto end; }
            dwMaxCountRuntime++;
        }
    }
    if(dwUnwindAddress == 0) { goto end; }
    
    // Reading UNWIND INFO structure
    pUnwindInfo = (PUNWIND_INFO)pbUnwindInfoRead;
    if(!VmmRead(H, pProcess, vaModuleBase + dwUnwindAddress, pbUnwindInfoRead, 4)) { goto end; }
    VmmLog(H, MID_THREADCS, LOGLEVEL_6_TRACE, "  UNWIND INFO: VERSION:[%02x] FLAGS:[%02x] PID:[%u] TID:[%u]", pUnwindInfo->Version, pUnwindInfo->Flags, pProcess->dwPID, pThread->dwTID);
    // retreiving the number of slot for the current UNWIND_INFO
    DWORD dwNbslot = pUnwindInfo->CountOfCodes;
    // finding out if UNWIND INFO is not conventional, exiting if not.
    if((pUnwindInfo->Version != 0x01 && pUnwindInfo->Version != 0x02) || (pUnwindInfo->Flags > 0x04)) {
        goto end;
    }
    // If the CountOfCodes is NULL and the vaBaseSP is null we are at the beginning of the unwind process, therefore the returnAddress is on top of the stack, no need to restore anything
    if((pUnwindInfo->CountOfCodes == 0x00) && (pCurrentFrame->vaBaseSP == 0) && (pUnwindInfo->Flags != 0x04)) {
        // We can get the return address of top by passing pThread->vaRSP
        if(!VmmWinThreadCs_PopReturnAddress(H, pProcess, pThread->vaRSP, &qwRetAddress, NULL)) {
            pFrameOut->vaRSP = pThread->vaRSP;
            pFrameOut->vaRetAddr = 0;
            goto end;
        }
        VmmLog(H, MID_THREADCS, LOGLEVEL_6_TRACE, "  UNWIND SUCCESS #1: RETADDR:[%016llx] PID:[%u] TID:[%u]", qwRetAddress, pProcess->dwPID, pThread->dwTID);
        pFrameOut->vaRetAddr = qwRetAddress;
        pFrameOut->vaRSP = pThread->vaRSP;
        pFrameOut->vaBaseSP = pThread->vaRSP + 8;
        fResult = TRUE; goto end;
    }
    // if we find a leaf function without being at the beginning
    if((pUnwindInfo->CountOfCodes == 0x00) && (pCurrentFrame->vaBaseSP != 0) && (pUnwindInfo->Flags != 0x04)) {
        qwCurrentRSP = pCurrentFrame->vaBaseSP;
        //printf("No Prolog is present, it is a leaf function, the return address is on top of stack but we are not at the beginning\n");
        if (!VmmWinThreadCs_PopReturnAddress(H, pProcess, qwCurrentRSP, &qwRetAddress, NULL)) { goto end; }
        VmmLog(H, MID_THREADCS, LOGLEVEL_6_TRACE, "  UNWIND SUCCESS #2: RETADDR:[%016llx] PID:[%u] TID:[%u]", qwRetAddress, pProcess->dwPID, pThread->dwTID);
        pFrameOut->vaRetAddr = qwRetAddress;
        pFrameOut->vaBaseSP = qwCurrentRSP + 8;
        pFrameOut->vaRSP = qwCurrentRSP;
        fResult = TRUE; goto end;
    }
    // we need to unwind each code to restore RSP and pop the return address
    {
        VmmLog(H, MID_THREADCS, LOGLEVEL_6_TRACE, "  UNWIND Normal function, Continuing... PID:[%u] TID:[%u]", pProcess->dwPID, pThread->dwTID);
        sInRSPOut.unwind_address = vaModuleBase + dwUnwindAddress;
        pFrameOut->vaRSP = qwCurrentRSP;
        sInRSPOut.RSP_in = pCurrentFrame->vaBaseSP;
        if(!VmmWinThreadCs_RspUnwinder(H, pProcess, pThread, &sInRSPOut)) { goto end; }
        qwCurrentRSP = sInRSPOut.RSP_out;
        VmmLog(H, MID_THREADCS, LOGLEVEL_6_TRACE, "  UNWIND New RSP:[%016llx] PID:[%u] TID:[%u]", qwCurrentRSP, pProcess->dwPID, pThread->dwTID);
        if(pUnwindInfo->Flags == 0x04) {
            QWORD qwRuntimeChainAddr;
            RUNTIME_FUNCTION_X64* pRuntimeChained;
            BYTE pbReadRtime[sizeof(RUNTIME_FUNCTION_X64)];
            QWORD qwUwdChainedAddr;
chain:
            pRuntimeChained = NULL;
            // RUNTIME struct for chained is after previous unwind structure + 4 + 2bytes for each UNWIND_CODES
            // we read RUNTIME_FUNCTION_X64 for chained steps
            qwRuntimeChainAddr = vaModuleBase + dwUnwindAddress + 4 + (2 * dwNbslot);
            if(!VmmRead(H, pProcess, qwRuntimeChainAddr, pbReadRtime, sizeof(RUNTIME_FUNCTION_X64))) { goto end; }
            pRuntimeChained = (RUNTIME_FUNCTION_X64 *)pbReadRtime;
            qwUwdChainedAddr = pRuntimeChained[0].UnwindInfoAddress;
            if(qwUwdChainedAddr == 0) { goto end; }
            VmmLog(H, MID_THREADCS, LOGLEVEL_6_TRACE, "  UNWIND CHAINED CHAINED_RUNTIME:[%016llx] UNWIND_INFO_ADDR:[%016llx] PID:[%u] TID:[%u]", qwRuntimeChainAddr, vaModuleBase + qwUwdChainedAddr, pProcess->dwPID, pThread->dwTID);
            // preparing second structure pInRSPOutChained for new call to VmmWinThreadCs_RspUnwinder in order to resolve chain.
            ZeroMemory(&sInRSPOutChained, sizeof(VMMWINTHREAD_RSP_UNWINDER));
            sInRSPOutChained.unwind_address = vaModuleBase+qwUwdChainedAddr;
            sInRSPOutChained.RSP_in = qwCurrentRSP;
            if(!VmmWinThreadCs_RspUnwinder(H, pProcess, pThread, &sInRSPOutChained)) { goto end; }
            // updating current RSP
            VmmLog(H, MID_THREADCS, LOGLEVEL_6_TRACE, "  UNWIND New RSP:[%016llx] PID:[%u] TID:[%u]", sInRSPOutChained.RSP_out, pProcess->dwPID, pThread->dwTID);
            qwCurrentRSP = sInRSPOutChained.RSP_out;
            // if chained function was also chained, redoing chained step (goto chain)
            if(sInRSPOutChained.chained) {
                // updating current UnwindAddress before jumping
                dwUnwindAddress = (DWORD)qwUwdChainedAddr;
                dwNbslot = sInRSPOutChained.nb_slot_chained;
                goto chain;
            }
        }
        if(!VmmWinThreadCs_PopReturnAddress(H, pProcess, qwCurrentRSP, &qwRetAddress, NULL)) { goto end; }
        qwCurrentRSP = qwCurrentRSP + 8;
        VmmLog(H, MID_THREADCS, LOGLEVEL_6_TRACE, "  UNWIND FINAL_RSP:[%016llx] RETURN_ADDR:[%016llx] PID:[%u] TID:[%u]", qwCurrentRSP, qwRetAddress, pProcess->dwPID, pThread->dwTID);
        //preparing return argument structure
        pFrameOut->vaRetAddr = qwRetAddress;
        pFrameOut->vaBaseSP = qwCurrentRSP;
        pFrameOut->vaRSP = pCurrentFrame->vaBaseSP;
        fResult = TRUE; goto end;
    }
end:
    LocalFree(pbPdata);
    return fResult;
}

_Success_(return)
BOOL VmmWinThreadCs_RspUnwinder(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess, _In_ PVMM_MAP_THREADENTRY pThread, _Inout_ PVMMWINTHREAD_RSP_UNWINDER pInRSPOut)
{
    BOOL fResult = FALSE;
    BYTE pUnwindInfoRead[4];
    PUNWIND_INFO pUnwindInfo = (PUNWIND_INFO)pUnwindInfoRead;
    DWORD dwUnwdIter, dwNbslot;
    QWORD qwCurrentRSP, pReadUnwind = pInRSPOut->unwind_address + 4;
    USHORT FrameOffset;
    PUNWIND_CODE pUnwindCodes = NULL;
    PFRAME_OFFSET_L offset_l;
    PFRAME_OFFSET_SH offset;
    if(!pInRSPOut) { goto end; }
    qwCurrentRSP = pInRSPOut->RSP_in;
    VmmLog(H, MID_THREADCS, LOGLEVEL_6_TRACE, "  RSPUnwinder: Reading UNWIND_INFO for unwind address passed in structure at %016llx PID:[%u] TID:[%u]", pInRSPOut->unwind_address, pProcess->dwPID, pThread->dwTID);
    if(!VmmRead(H, pProcess, pInRSPOut->unwind_address, pUnwindInfoRead, 4)) { goto end; }
    // reading UNWIND CODES for dwNbslot 
    dwNbslot = pUnwindInfo->CountOfCodes;
    pUnwindCodes = LocalAlloc(LMEM_ZEROINIT, dwNbslot * sizeof(UNWIND_CODE));
    if(!pUnwindCodes) { goto end; }
    // detecting multiple chained function 
    if(pUnwindInfo->Flags == 0x04) {
        pInRSPOut->chained = TRUE;
        pInRSPOut->nb_slot_chained = dwNbslot;
    }
    if(pUnwindInfo->CountOfCodes == 0x00) {
        pInRSPOut->RSP_out = pInRSPOut->RSP_in;
        goto end;
    }
    if(!VmmRead(H, pProcess, pReadUnwind, (PBYTE)pUnwindCodes, 2 * dwNbslot)) { goto end; }
    VmmLog(H, MID_THREADCS, LOGLEVEL_6_TRACE, "  RSPUnwinder: Enumerating each UNWIND CODES - RSP at begenning is %016llx PID:[%u] TID:[%u]", pInRSPOut->RSP_in, pProcess->dwPID, pThread->dwTID); 
    // for each slot, testing type of OpInfo 
    for(dwUnwdIter = 0; dwUnwdIter < dwNbslot; dwUnwdIter++) {
        switch (pUnwindCodes[dwUnwdIter].UnwindOp) {
            //we pop a registry, the stack need to grow down
            case UWOP_PUSH_NONVOL:
                qwCurrentRSP = qwCurrentRSP + 8;
                VmmLog(H, MID_THREADCS, LOGLEVEL_6_TRACE, "  RSPUnwinder: New RSP: %016llx CODE:[%02x] PID:[%u] TID:[%u]", qwCurrentRSP, UWOP_PUSH_NONVOL, pProcess->dwPID, pThread->dwTID);
                break;
            //Restoring former stack allocation, (the number of bytes is given by new slot and carried by FrameOffset)
            case UWOP_ALLOC_LARGE:
                if(pUnwindCodes[dwUnwdIter].OpInfo == 0x00) {
                    offset = (PFRAME_OFFSET_SH)&pUnwindCodes[dwUnwdIter + 1];
                    FrameOffset = (offset->FrameOffset)*8;
                    qwCurrentRSP = qwCurrentRSP + FrameOffset;
                    VmmLog(H, MID_THREADCS, LOGLEVEL_6_TRACE, "  RSPUnwinder: New RSP: %016llx FRAME_OFFSET:[%02x] CODE:[%02x] PID:[%u] TID:[%u]", qwCurrentRSP, FrameOffset, UWOP_ALLOC_LARGE, pProcess->dwPID, pThread->dwTID);
                    dwUnwdIter++;
                    break;
                }
                else if(pUnwindCodes[dwUnwdIter].OpInfo == 0x01) {
                    offset_l = (PFRAME_OFFSET_L)&pUnwindCodes[dwUnwdIter + 1];
                    FrameOffset = (USHORT)offset_l->FrameOffset;
                    printf("Frame offset is %02x\n", FrameOffset);
                    qwCurrentRSP = qwCurrentRSP + FrameOffset;
                    printf("NEW RSP :  %016llx\n", qwCurrentRSP);
                    VmmLog(H, MID_THREADCS, LOGLEVEL_6_TRACE, "  RSPUnwinder: New RSP: %016llx FRAME_OFFSET:[%02x] CODE:[%02x] PID:[%u] TID:[%u]", qwCurrentRSP, FrameOffset, UWOP_ALLOC_LARGE, pProcess->dwPID, pThread->dwTID);
                    dwUnwdIter=dwUnwdIter + 2;
                    break;
                }
                break;                
            case UWOP_ALLOC_SMALL:
                FrameOffset = (pUnwindCodes[dwUnwdIter].OpInfo)*8 +8;
                qwCurrentRSP = qwCurrentRSP + FrameOffset;
                VmmLog(H, MID_THREADCS, LOGLEVEL_6_TRACE, "  RSPUnwinder: New RSP: %016llx FRAME_OFFSET:[%02x] CODE:[%02x] PID:[%u] TID:[%u]", qwCurrentRSP, FrameOffset, UWOP_ALLOC_SMALL, pProcess->dwPID, pThread->dwTID);
                break;
            //  vaRSP is left untouched 
            case UWOP_SET_FPREG:
                break;
            // the save is only made on stack space already allocated, RSP is left untouched but next slot is used for this register so we go over it
            case UWOP_SAVE_NONVOL:
                dwUnwdIter++;
                break;
            // the save is only made on stack already allocated, RSP is left untouched 
            case UWOP_SAVE_NONVOL_FAR:
                break;
            // the save is only made on stack already allocated, RSP is left untouched 
            case UWOP_SAVE_XMM128:
                break;
            // the save is only made on stack already allocated, RSP is left untouched 
            case UWOP_SAVE_XMM128_FAR:
                break;
            case UWOP_PUSH_MACHFRAME:
                if(pUnwindCodes[dwUnwdIter].OpInfo == 0x00) {
                    qwCurrentRSP = qwCurrentRSP + 40;
                    VmmLog(H, MID_THREADCS, LOGLEVEL_6_TRACE, "  RSPUnwinder: New RSP: %016llx CODE:[%02x] PID:[%u] TID:[%u]", qwCurrentRSP, UWOP_PUSH_MACHFRAME, pProcess->dwPID, pThread->dwTID);
                    break;
                }
                else if(pUnwindCodes[dwUnwdIter].OpInfo == 0x01) {
                    qwCurrentRSP = qwCurrentRSP + 48;
                    VmmLog(H, MID_THREADCS, LOGLEVEL_6_TRACE, "  RSPUnwinder: New RSP: %016llx CODE:[%02x] PID:[%u] TID:[%u]", qwCurrentRSP, UWOP_PUSH_MACHFRAME, pProcess->dwPID, pThread->dwTID);
                    break;
                }
                break;
                
            default:
                VmmLog(H, MID_THREADCS, LOGLEVEL_6_TRACE, "  RSPUnwinder: Unknown Code CODE:[%02x] PID:[%u] TID:[%u]", pUnwindCodes[dwUnwdIter].UnwindOp, pProcess->dwPID, pThread->dwTID);
                break;
        }
        pInRSPOut->RSP_out = qwCurrentRSP;
    }
    fResult = TRUE;
end: 
    LocalFree(pUnwindCodes);
    return fResult;
}

VOID VmmWinThreadCs_CleanupCB(PVMMOB_MAP_THREADCALLSTACK pOb)
{
    LocalFree(pOb->pbMultiText);
}

#define VMMWINTHREADCS_BUFFER_USERTEXT 0x10000

/*
* Retrieve a new callstack object for the specified thread.
* CALLER DECREF: return
* -- H
* -- pProcess
* -- pThread
* -- return
*/
PVMMOB_MAP_THREADCALLSTACK VmmWinThreadCs_UnwindScanCallstack(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess, _In_ PVMM_MAP_THREADENTRY pThread)
{
    VMMWINTHREAD_FRAME sFrameInit, sCurrentFrame = { 0 };
    DWORD i, dwIterFrame, cboText = 0;
    PVMMWINTHREAD_FRAME peSrc, pFullCallStack = NULL; 
    BOOL fResultDisplay = FALSE;
    QWORD qwLimitKernel = 0x00007FFFFFFF0000;
    PVMMOB_MAP_THREADCALLSTACK pObCS = NULL;
    PVMM_MAP_THREADCALLSTACKENTRY peDst;
    POB_STRMAP psmOb = NULL;
    VMMWINTHREAD_SYMBOL sCurrentSymbol;
    LPSTR uszText = NULL;

    if(H->vmm.tpMemoryModel != VMM_MEMORYMODEL_X64) { return NULL; }

    pFullCallStack = LocalAlloc(LMEM_ZEROINIT, VMMWINTHREADCS_MAX_DEPTH * sizeof(VMMWINTHREAD_FRAME));
    if(!pFullCallStack) { return NULL; }

    // checking condition before starting to unwind
    if(!VmmWinThreadCs_ValidateThreadBeforeUnwind(H, pProcess, pThread)) { goto end; }

    VmmLog(H, MID_THREADCS, LOGLEVEL_6_TRACE, " START: RIP:[%016llx] PID:[%u] TID:[%u]", pThread->vaRIP, pProcess->dwPID, pThread->dwTID);
    sFrameInit.vaRetAddr = pThread->vaRIP;
    // setting RSP as 0 as we are not unwinding kernel stack
    sFrameInit.vaRSP = 0;
    sFrameInit.vaBaseSP = 0;
    pFullCallStack[0] = sFrameInit;
    
    for(dwIterFrame = 0; dwIterFrame < VMMWINTHREADCS_MAX_DEPTH - 2; dwIterFrame++) {
        VmmLog(H, MID_THREADCS, LOGLEVEL_6_TRACE, " START: RIP:[%016llx] RSP:[%016llx] ADDR:[%016llx] PID:[%u] TID:[%u]", pThread->vaRIP, pThread->vaRSP, pFullCallStack[dwIterFrame].vaRetAddr, pProcess->dwPID, pThread->dwTID);
        if(pFullCallStack[dwIterFrame].vaRetAddr > qwLimitKernel) {
            VmmLog(H, MID_THREADCS, LOGLEVEL_6_TRACE, " END: (kernel address not supported) RIP:[%016llx] ADDR:[%016llx] PID:[%u] TID:[%u]", pThread->vaRIP, pFullCallStack[dwIterFrame].vaRetAddr, pProcess->dwPID, pThread->dwTID);
            break;
        }
        // try to unwind frame:
        if(VmmWinThreadCs_UnwindFrame(H, pProcess, pThread, &pFullCallStack[dwIterFrame], &sCurrentFrame)) {
            pFullCallStack[dwIterFrame + 1] = sCurrentFrame;
            continue;
        }
        // unwind frame failed, trying heuristic technique:
        if(VmmWinThreadCs_HeuristicScanForFrame(H, pProcess, pThread, &pFullCallStack[dwIterFrame], &sCurrentFrame)) {
            pFullCallStack[dwIterFrame + 1] = sCurrentFrame;
        }
        // both techniques failed, stopping
        VmmLog(H, MID_THREADCS, LOGLEVEL_6_TRACE, " END: (unwind+heuristics fail) RIP:[%016llx] ADDR:[%016llx] PID:[%u] TID:[%u]", pThread->vaRIP, pFullCallStack[dwIterFrame].vaRetAddr, pProcess->dwPID, pThread->dwTID);
        break;
    }
    // setting the last frame before display
    if(pFullCallStack[dwIterFrame].vaRetAddr) {
        dwIterFrame = dwIterFrame + 1;
        pFullCallStack[dwIterFrame].vaRSP = pFullCallStack[dwIterFrame - 1].vaBaseSP;
        pFullCallStack[dwIterFrame].vaRetAddr = 0;
    }
    dwIterFrame++;

    // create ob object:
    if(!(psmOb = ObStrMap_New(H, OB_STRMAP_FLAGS_CASE_SENSITIVE))) { goto end; }
    if(!(pObCS = Ob_AllocEx(H, OB_TAG_THREAD_CALLSTACK, LMEM_ZEROINIT, sizeof(VMMOB_MAP_THREADCALLSTACK) + dwIterFrame * sizeof(VMM_MAP_THREADCALLSTACKENTRY), (OB_CLEANUP_CB)VmmWinThreadCs_CleanupCB, NULL))) { goto end; }
    if(!(uszText = LocalAlloc(LMEM_ZEROINIT, VMMWINTHREADCS_BUFFER_USERTEXT))) { goto end; }
    if(H->cfg.fFileInfoHeader) {
        cboText += (DWORD)_snprintf_s(uszText + cboText, VMMWINTHREADCS_BUFFER_USERTEXT - cboText, _TRUNCATE, "Index            RSP          RetAddr Module!Function+Displacement\n==================================================================\n");
    }
    for(i = 0; i < dwIterFrame; i++) {
        peSrc = &pFullCallStack[i];
        peDst = &pObCS->pMap[i];
        peDst->i = i;
        peDst->fRegPresent = peSrc->fRegPresent;
        peDst->vaRetAddr = peSrc->vaRetAddr;
        peDst->vaRSP = peSrc->vaRSP;
        peDst->vaBaseSP = peSrc->vaBaseSP;
        if(i && pFullCallStack[i - 1].vaRetAddr && VmmWinThreadCs_GetSymbolFromAddr(H, pProcess, pFullCallStack[i - 1].vaRetAddr, &sCurrentSymbol)) {
            peDst->cbDisplacement = sCurrentSymbol.displacement;
            ObStrMap_PushPtrUU(psmOb, sCurrentSymbol.szFunction, &peDst->uszFunction, NULL);
            ObStrMap_PushPtrUU(psmOb, sCurrentSymbol.szModule, &peDst->uszModule, NULL);
            cboText += (DWORD)_snprintf_s(uszText + cboText, VMMWINTHREADCS_BUFFER_USERTEXT - cboText, _TRUNCATE, "%02u: %016llx %016llx %s!%s+%x\n", peDst->i, peDst->vaRSP, peDst->vaRetAddr, sCurrentSymbol.szModule, sCurrentSymbol.szFunction, sCurrentSymbol.displacement);
        } else {
            ObStrMap_PushPtrUU(psmOb, "", &peDst->uszFunction, NULL);
            ObStrMap_PushPtrUU(psmOb, "", &peDst->uszModule, NULL);
            cboText += (DWORD)_snprintf_s(uszText + cboText, VMMWINTHREADCS_BUFFER_USERTEXT - cboText, _TRUNCATE, "%02u: %016llx %016llx\n", peDst->i, peDst->vaRSP, peDst->vaRetAddr);
        }
    }
    ObStrMap_PushPtrUU(psmOb, uszText, &pObCS->uszText, NULL);
    pObCS->cbText = cboText;
    pObCS->dwPID = pProcess->dwPID;
    pObCS->dwTID = pThread->dwTID;
    pObCS->cMap = dwIterFrame;
    ObStrMap_FinalizeAllocU_DECREF_NULL(&psmOb, &pObCS->pbMultiText, &pObCS->cbMultiText);
    if(VmmLogIsActive(H, MID_THREADCS, LOGLEVEL_5_DEBUG)) {
        VmmLog(H, MID_THREADCS, LOGLEVEL_5_DEBUG, "CALLSTACK PRINTOUT PID:[%u] TID:[%u]", pObCS->dwPID, pObCS->dwTID);
        for(i = 0; i < pObCS->cMap; i++) {
            peDst = &pObCS->pMap[i];
            VmmLog(H, MID_THREADCS, LOGLEVEL_5_DEBUG, "  [%02u] RSP:[%016llx] RET:[%016llx] SITE:[%s!%s+%x]", peDst->i, peDst->vaRSP, peDst->vaRetAddr, peDst->uszModule, peDst->uszFunction, peDst->cbDisplacement);
        }
        VmmLog(H, MID_THREADCS, LOGLEVEL_5_DEBUG, "\n%s", uszText);
    }
end: 
    LocalFree(pFullCallStack);
    LocalFree(uszText);
    return pObCS;
}

_Success_(return)
BOOL VmmWinThreadCs_PopReturnAddress(VMM_HANDLE H, _In_ PVMM_PROCESS pProcess, _In_ QWORD va, _Out_ PQWORD pqwBufferCandidate, _Out_opt_ PVMMWINTHREAD_MODULE_SECTION pModuleSectionOpt)
{
    VMMWINTHREAD_MODULE_SECTION ModuleSection;
    if(!pModuleSectionOpt) { pModuleSectionOpt = &ModuleSection; }
    if(!VmmRead(H, pProcess, va, (PBYTE)pqwBufferCandidate, sizeof(QWORD))) { return FALSE; }
    if(!VmmWinThreadCs_GetModuleSectionFromAddress(H, pProcess, *pqwBufferCandidate, pModuleSectionOpt)) { return FALSE; }
    return TRUE;
}

_Success_(return)
BOOL VmmWinThreadCs_HeuristicScanForFrame(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess, _In_ PVMM_MAP_THREADENTRY pThread, _In_ PVMMWINTHREAD_FRAME pCurrentFrame, _Out_ PVMMWINTHREAD_FRAME pReturnScanFrame)
{
    VMMWINTHREAD_MODULE_SECTION sModuleSection;
    VMMWINTHREAD_FRAME sValidationTempFrame, sRegistryTempFrame = { 0 };
    QWORD qwAddressCandidate, qwCurrentRSP = pCurrentFrame->vaBaseSP;
    DWORD dwCounterReg = 0, dwLoopProtect = 0;

    VmmLog(H, MID_THREADCS, LOGLEVEL_6_TRACE, " Heuristic scan START. RSP:[%016llx] PID:[%u] TID:[%u]", qwCurrentRSP, pProcess->dwPID, pThread->dwTID);
    // Getting previous RSP and ret address as input for ValidateCandidate:
    pReturnScanFrame->vaRetAddr = pCurrentFrame->vaRetAddr;
    pReturnScanFrame->vaRSP = pCurrentFrame->vaBaseSP;
    sRegistryTempFrame.fRegPresent = FALSE;

    // Reading 8 bytes by 8 bytes and decreasing RSP at the same time (which increase addresses)
    for(qwCurrentRSP = pCurrentFrame->vaBaseSP; qwCurrentRSP != pThread->vaStackBaseUser && dwLoopProtect < 50; qwCurrentRSP = qwCurrentRSP + 8) {
        dwLoopProtect++;
        if(!VmmRead(H, pProcess, qwCurrentRSP, (PBYTE)&qwAddressCandidate, sizeof(QWORD))) { return FALSE; }
        if(!VmmWinThreadCs_GetModuleSectionFromAddress(H, pProcess, qwAddressCandidate, &sModuleSection)) { continue; }
        if(VmmWinThreadCs_ValidateCandidate(H, pProcess, pThread, qwAddressCandidate, pReturnScanFrame, &sValidationTempFrame)) {
            // Reserving call registry in case we do not find another candidate
            if(sValidationTempFrame.fRegPresent == TRUE && dwCounterReg == 0) {
                VmmLog(H, MID_THREADCS, LOGLEVEL_6_TRACE, " Heuristic scan (reserving candidate). RSP:[%016llx] RET:[%016llx] PID:[%u] TID:[%u]", qwCurrentRSP, sRegistryTempFrame.vaRetAddr, pProcess->dwPID, pThread->dwTID);
                sRegistryTempFrame.vaBaseSP = qwCurrentRSP + 8;
                sRegistryTempFrame.vaRetAddr = sValidationTempFrame.vaRetAddr;
                sRegistryTempFrame.fRegPresent = TRUE;
                dwCounterReg = dwCounterReg+1;
                continue;
            }
            // Not a call by registry we found a candidate, we can update the structure and return
            else{
                VmmLog(H, MID_THREADCS, LOGLEVEL_6_TRACE, " Heuristic scan SUCCESS. RSP:[%016llx] (direct candidate) RET:[%016llx] PID:[%u] TID:[%u]", pReturnScanFrame->vaBaseSP, pReturnScanFrame->vaRetAddr, pProcess->dwPID, pThread->dwTID);
                pReturnScanFrame->vaBaseSP = qwCurrentRSP + 8;
                pReturnScanFrame->vaRetAddr = sValidationTempFrame.vaRetAddr;
                return TRUE;
            }
        }
    }
    if(sRegistryTempFrame.fRegPresent) {
        // Updating return structure pReturnScanFrame with values
        pReturnScanFrame->vaBaseSP = sRegistryTempFrame.vaBaseSP;
        pReturnScanFrame->vaRetAddr  = sRegistryTempFrame.vaRetAddr;
        VmmLog(H, MID_THREADCS, LOGLEVEL_6_TRACE, " Heuristic scan SUCCESS. RSP:[%016llx] (reserved candidate) RET:[%016llx] PID:[%u] TID:[%u]", pReturnScanFrame->vaBaseSP, pReturnScanFrame->vaRetAddr, pProcess->dwPID, pThread->dwTID);
        return TRUE;
    }
    // We reached the end and did not find any candidate
    VmmLog(H, MID_THREADCS, LOGLEVEL_6_TRACE, " Heuristic scan FAIL. PID:[%u] TID:[%u]",  pProcess->dwPID, pThread->dwTID);
    return FALSE;
}

//FF D0 : call rax
//FF D3 : call rbx
//FF 15 : call [RIP+x]
//E8 : call xxxxxx
//FF 90 : call[RAX+x]

_Success_(return)
BOOL VmmWinThreadCs_ValidateCandidate(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess, _In_ PVMM_MAP_THREADENTRY pThread, _In_ QWORD vaCandidate, _In_ PVMMWINTHREAD_FRAME pCurrentFrame, _Out_ PVMMWINTHREAD_FRAME pValidationTempFrame)
{
    static BYTE DCALL = 0xe8;
    static BYTE ICALL = 0xff;
    static BYTE MRIPI = 0x15;
    static BYTE MRAXI = 0x90;
    static BYTE RAXI = 0xD0;
    static BYTE RBXI = 0xD3;
    BYTE pbOpcodesIndirectRead[6];
    PBYTE pbOpcodesDirectRead = pbOpcodesIndirectRead + 1;
    QWORD qwDirectCallAddress, qwIndirectCallAddress, qwIndirectStoredAddress, qwCurrentRIP = pCurrentFrame->vaRetAddr;
    VMMWINTHREAD_MODULE_SECTION sModuleSectionRIP, sModuleSectionTargetCall;
    DWORD dwOffset;

    // 1: read opcode:
    pValidationTempFrame->fRegPresent = FALSE;
    if(!VmmRead(H, pProcess, vaCandidate - 6, pbOpcodesIndirectRead, 6)) { return FALSE; }

    // 2: finding zone for RIP:
    if(!VmmWinThreadCs_GetModuleSectionFromAddress(H, pProcess, qwCurrentRIP, &sModuleSectionRIP)) { return FALSE; }
    VmmLog(H, MID_THREADCS, LOGLEVEL_6_TRACE, "  RIP %016llx is zone starting at %016llx PID:[%u] TID:[%u]", qwCurrentRIP, sModuleSectionRIP.vaModuleBase, pProcess->dwPID, pThread->dwTID);

    // 3: direct call:
    if(DCALL == pbOpcodesDirectRead[0]) {
        dwOffset = *(PDWORD)(pbOpcodesDirectRead + 1);
        qwDirectCallAddress = vaCandidate + dwOffset;
        VmmLog(H, MID_THREADCS, LOGLEVEL_6_TRACE, "  DIRECT CALL instruction at %016llx OFF:[%08x] TARGET:[%016llx] PID:[%u] TID:[%u]", vaCandidate - 5, dwOffset, qwDirectCallAddress, pProcess->dwPID, pThread->dwTID);
        // we retreive the module info for the target of the call and store it
        if(!VmmWinThreadCs_GetModuleSectionFromAddress(H, pProcess, qwDirectCallAddress, &sModuleSectionTargetCall)) {
            VmmLog(H, MID_THREADCS, LOGLEVEL_6_TRACE, "   Could not find appropriate module for the direct adress PID:[%u] TID:[%u]", pProcess->dwPID, pThread->dwTID);
            return FALSE;
        }
        // we check that the target for the direct call is in the same VAD as the previous return address i.e RIP
        if((sModuleSectionRIP.vaModuleBase != 0) && (sModuleSectionRIP.vaModuleBase == sModuleSectionTargetCall.vaModuleBase)) {
            VmmLog(H, MID_THREADCS, LOGLEVEL_6_TRACE, "   RIP %016llx is in range with %016llx PID:[%u] TID:[%u]", vaCandidate, sModuleSectionTargetCall.vaModuleBase, pProcess->dwPID, pThread->dwTID);
            pValidationTempFrame->vaRetAddr = vaCandidate;
            return TRUE;
        }
        return FALSE;
    }

    // 4: indirect call:
    if(ICALL == pbOpcodesIndirectRead[0]) {
        // FF 15 : call [RIP+x]
        if(MRIPI == pbOpcodesIndirectRead[1]) {
            dwOffset = *(PDWORD)(pbOpcodesIndirectRead + 2);
            qwIndirectCallAddress = vaCandidate + dwOffset;
            VmmLog(H, MID_THREADCS, LOGLEVEL_6_TRACE, "  INDIRECT CALL instruction at %016llx OFF:[%08x] INDIRECT:[%016llx] PID:[%u] TID:[%u]", vaCandidate - 6, dwOffset, qwIndirectCallAddress, pProcess->dwPID, pThread->dwTID);
            if(!VmmWinThreadCs_PopReturnAddress(H, pProcess, qwIndirectCallAddress, &qwIndirectStoredAddress, &sModuleSectionTargetCall)) {
                VmmLog(H, MID_THREADCS, LOGLEVEL_6_TRACE, "   Could not read indirect target address PID:[%u] TID:[%u]", pProcess->dwPID, pThread->dwTID);
                return FALSE;
            };
            if(sModuleSectionRIP.vaModuleBase && (sModuleSectionRIP.vaModuleBase == sModuleSectionTargetCall.vaModuleBase)) {
                VmmLog(H, MID_THREADCS, LOGLEVEL_6_TRACE, "   RIP %016llx is in same module as indirect jump %016llx MODULE_BASE:[%016llx] PID:[%u] TID:[%u]", vaCandidate - 6, qwIndirectCallAddress, sModuleSectionRIP.vaModuleBase,  pProcess->dwPID, pThread->dwTID);
                pValidationTempFrame->vaRetAddr = vaCandidate;
                return TRUE;

            }
            VmmLog(H, MID_THREADCS, LOGLEVEL_6_TRACE, "   RIP %016llx is NOT in same module as indirect jump %016llx PID:[%u] TID:[%u]", vaCandidate - 6, qwIndirectCallAddress, pProcess->dwPID, pThread->dwTID);
            return FALSE;
        }
        // Not able to check jump address but storing it in case we don't have anything else
        if(MRAXI == pbOpcodesIndirectRead[1]) {
            VmmLog(H, MID_THREADCS, LOGLEVEL_6_TRACE, "  INDIRECT CALL via memory RAX PID:[%u] TID:[%u]", pProcess->dwPID, pThread->dwTID);
            pValidationTempFrame->fRegPresent = TRUE;
            pValidationTempFrame->vaRetAddr = vaCandidate;
            return TRUE;
        }
        if(RAXI == pbOpcodesIndirectRead[1]) {
            VmmLog(H, MID_THREADCS, LOGLEVEL_6_TRACE, "  INDIRECT CALL via RAX PID:[%u] TID:[%u]", pProcess->dwPID, pThread->dwTID);
            pValidationTempFrame->fRegPresent = TRUE;
            pValidationTempFrame->vaRetAddr = vaCandidate;
            return TRUE;
        }
        if(RBXI == pbOpcodesIndirectRead[1]) {
            VmmLog(H, MID_THREADCS, LOGLEVEL_6_TRACE, "  INDIRECT CALL via RBX PID:[%u] TID:[%u]", pProcess->dwPID, pThread->dwTID);
            pValidationTempFrame->fRegPresent = TRUE;
            pValidationTempFrame->vaRetAddr = vaCandidate;
            return TRUE;
        }
        VmmLog(H, MID_THREADCS, LOGLEVEL_6_TRACE, "  INDIRECT CALL unknown PID:[%u] TID:[%u]", pProcess->dwPID, pThread->dwTID);
        return FALSE;
    }

    // 5: unknown opcode:
    VmmLog(H, MID_THREADCS, LOGLEVEL_6_TRACE, "  UNKNOWN OPCODE:[%02X%02X%02X%02X%02X%02X] PID:[%u] TID:[%u]", pbOpcodesIndirectRead[0], pbOpcodesIndirectRead[1], pbOpcodesIndirectRead[2], pbOpcodesIndirectRead[3], pbOpcodesIndirectRead[4], pbOpcodesIndirectRead[5], pProcess->dwPID, pThread->dwTID);
    return FALSE;
}

_Success_(return)
BOOL VmmWinThreadCs_ValidateThreadBeforeUnwind(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess, _In_ PVMM_MAP_THREADENTRY pThread)
{
    QWORD vaCurrentRIP;
    VMMWINTHREAD_MODULE_SECTION ModuleSection;
    vaCurrentRIP = pThread->vaRIP;
    if((pThread->vaRSP > pThread->vaStackBaseUser) || (pThread->vaRSP < pThread->vaStackLimitUser)) {
        VmmLog(H, MID_THREADCS, LOGLEVEL_6_TRACE, "  SP for thread is invalid. RSP:[%016llx] PID:[%u] TID:[%u]", pThread->vaRSP, pProcess->dwPID, pThread->dwTID);
        return FALSE;
    }
    return VmmWinThreadCs_GetModuleSectionFromAddress(H, pProcess, vaCurrentRIP, &ModuleSection);
}

// Issues with some modules PDB loading such as KERNELBASE, win32u and some others.. address are left without symbols for these.
_Success_(return)
BOOL VmmWinThreadCs_GetSymbolFromAddr(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess, _In_ QWORD qwReturnAddress, _Out_ PVMMWINTHREAD_SYMBOL pSymbol)
{
    PDB_HANDLE hPDB;
    VMMWINTHREAD_MODULE_SECTION sModule;
    if(!qwReturnAddress || !VmmWinThreadCs_GetModuleSectionFromAddress(H, pProcess, qwReturnAddress, &sModule)) { return FALSE; }
    // load the PDB for the module:
    if(!(hPDB = PDB_GetHandleFromModuleAddress(H, pProcess, sModule.vaModuleBase))) { goto fail; }
    if(!PDB_LoadEnsure(H, hPDB) || !PDB_GetModuleInfo(H, hPDB, pSymbol->szModule, NULL, NULL)) { goto fail; }
    // lookup the symbol:
    if(!PDB_GetSymbolFromOffset(H, hPDB, (DWORD)(qwReturnAddress - sModule.vaModuleBase), pSymbol->szFunction, &pSymbol->displacement)) { goto fail; }
    // return the symbol:
    pSymbol->retaddress = qwReturnAddress;
    return TRUE;
fail:
    // PDB symbol lookup failed, but we still have the module & section name:
    _snprintf_s(pSymbol->szModule, sizeof(pSymbol->szModule), _TRUNCATE, "[%s]", sModule.uszModuleName);
    _snprintf_s(pSymbol->szFunction, sizeof(pSymbol->szFunction), _TRUNCATE, "[%s]", sModule.text.szSectionName);
    pSymbol->retaddress = qwReturnAddress;
    pSymbol->displacement = (DWORD)(qwReturnAddress - sModule.vaModuleBase);
    return TRUE;
}

DWORD VmmWinThreadCs_GetModuleSectionFromAddress(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess, _In_ QWORD va, _Out_ PVMMWINTHREAD_MODULE_SECTION pModuleSection)
{
    DWORD i, dwResult = 0;
    QWORD vaBase;
    PVMMOB_MAP_VAD pObVadMap = NULL;
    PVMM_MAP_VADENTRY peVad;
    VMM_MEMORY_SEARCH_CONTEXT_SEARCHENTRY SearchEntry[1] = {0};
    VMM_MEMORY_SEARCH_CONTEXT ctxSearch = { 0 };
    PVMMOB_MAP_MODULE pObModuleMap = NULL;
    PVMM_MAP_MODULEENTRY peModule;
    IMAGE_SECTION_HEADER Section = { 0 };
    POB_DATA pObDataSearchResult = NULL;
    ZeroMemory(pModuleSection, sizeof(VMMWINTHREAD_MODULE_SECTION));
    if(!va) { dwResult = 0; goto end; }
    // try module map first:
    if(VmmMap_GetModule(H, pProcess, VMM_MODULE_FLAG_NORMAL, &pObModuleMap) && (peModule = VmmMap_GetModuleEntryEx2(H, pObModuleMap, va))) {
        // ".text":
        if(!PE_SectionGetFromAddressOffset(H, pProcess, peModule->vaBase, (DWORD)(va - peModule->vaBase), &Section)) { dwResult = 0; goto end; }
        *(PQWORD)pModuleSection->text.szSectionName = *(PQWORD)Section.Name;
        pModuleSection->text.Address = Section.VirtualAddress;
        pModuleSection->text.Size = Section.Misc.VirtualSize;
        // .pdata:
        if(!PE_SectionGetFromName(H, pProcess, peModule->vaBase, ".pdata", &Section)) { dwResult = 0; goto end; }
        pModuleSection->pdata.Address = Section.VirtualAddress;
        pModuleSection->pdata.Size = Section.Misc.VirtualSize;
        // module info:
        strncpy_s(pModuleSection->uszModuleName, sizeof(pModuleSection->uszModuleName), peModule->uszText, _TRUNCATE);
        CharUtil_ReplaceAllA(pModuleSection->uszModuleName, '.', '\0');
        pModuleSection->vaModuleBase = peModule->vaBase;
        dwResult = 1; goto end;
    }
    // try vad map secondly:
    if(VmmMap_GetVad(H, pProcess, &pObVadMap, VMM_VADMAP_TP_FULL)) {
        for(i = 0; i < pObVadMap->cMap; i++) {
            peVad = pObVadMap->pMap + i;
            if((va >= peVad->vaStart) && (va < peVad->vaEnd)) {
                // we prepare structure for searching MZ in VAD
                ctxSearch.pSearch = SearchEntry;
                ctxSearch.pSearch[0].cb = 4;
                memcpy(ctxSearch.pSearch[0].pb, (BYTE[4]) { 0x4d, 0x5a, 0x90, 0x00 }, 4);
                memcpy(ctxSearch.pSearch[0].pbSkipMask, (BYTE[4]) { 0x00, 0x00, 0xff, 0x00 }, 4);
                ctxSearch.pSearch[0].cbAlign = 0x1000;
                ctxSearch.cSearch++;
                ctxSearch.vaMin = peVad->vaStart;
                ctxSearch.vaMax = peVad->vaEnd;
                // MZ header found in VAD
                if(VmmSearch(H, pProcess, &ctxSearch, &pObDataSearchResult) && ctxSearch.cResult) {
                    vaBase = pObDataSearchResult->pqw[0];
                    // ".text":
                    if(!PE_SectionGetFromAddressOffset(H, pProcess, vaBase, (DWORD)(va - vaBase), &Section)) { dwResult = 0; goto end; }
                    *(PQWORD)pModuleSection->text.szSectionName = *(PQWORD)Section.Name;
                    pModuleSection->text.Address = Section.VirtualAddress;
                    pModuleSection->text.Size = Section.Misc.VirtualSize;
                    // .pdata:
                    if(!PE_SectionGetFromName(H, pProcess, vaBase, ".pdata", &Section)) { dwResult = 0; goto end; }
                    pModuleSection->pdata.Address = Section.VirtualAddress;
                    pModuleSection->pdata.Size = Section.Misc.VirtualSize;
                    // module info:
                    strncpy_s(pModuleSection->uszModuleName, sizeof(pModuleSection->uszModuleName), CharUtil_PathSplitLast(peVad->uszText), _TRUNCATE);
                    CharUtil_ReplaceAllA(pModuleSection->uszModuleName, '.', '\0');
                    pModuleSection->vaModuleBase = peVad->vaStart;
                    pModuleSection->size_vad = (DWORD)(peVad->vaEnd - peVad->vaStart);
                    dwResult = 2;
                    goto end;
                }
                break;
            }
        }
    }
    dwResult = 0;
    pModuleSection->vaModuleBase = 0;
    pModuleSection->size_vad = 0;
end:
    Ob_DECREF(pObDataSearchResult);
    Ob_DECREF(pObModuleMap);
    Ob_DECREF(pObVadMap);
    return dwResult;
}

/*
* Refresh the callstack cache.
* -- H
*/
VOID VmmWinThreadCs_Refresh(_In_ VMM_HANDLE H)
{
    ObMap_Clear(H->vmm.pmObThreadCallback);
}

/*
* Retrieve the callstack for the specified thread.
* Callback parsing is only supported for x64 user-mode threads.
* Callback parsing is best-effort and is very resource intense since it may
* download a large amounts of PDB symbol data from the Microsoft symbol server.
* Use with caution!
* CALLER DECREF: *ppObCS
* -- H
* -- pProcess
* -- pThread
* -- flags = VMM_FLAG_NOCACHE (do not use cache) or VMM_FLAG_FORCECACHE_READ (require cache)
* -- ppObCS
* -- return
*/
_Success_(return)
BOOL VmmWinThreadCs_GetCallstack(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess, _In_ PVMM_MAP_THREADENTRY pThread, _In_ DWORD flags, _Out_ PVMMOB_MAP_THREADCALLSTACK *ppObCS)
{
    PVMMOB_MAP_THREADCALLSTACK pObCS = NULL;
    BOOL fNoCache = (flags & VMM_FLAG_NOCACHE) ? TRUE : FALSE;
    BOOL fRequireCache = (flags & VMM_FLAG_FORCECACHE_READ) ? TRUE : FALSE;
    QWORD qwKey = ((QWORD)pProcess->dwPID << 32) | pThread->dwTID;
    if(fNoCache || !(pObCS = ObMap_GetByKey(H->vmm.pmObThreadCallback, qwKey)) || fRequireCache) {
        AcquireSRWLockExclusive(&H->vmm.LockSRW.ThreadCallback);
        if(fNoCache || !(pObCS = ObMap_GetByKey(H->vmm.pmObThreadCallback, qwKey))) {
            pObCS = VmmWinThreadCs_UnwindScanCallstack(H, pProcess, pThread);       // fetch the callstack
            if(!pObCS && (pObCS = Ob_AllocEx(H, OB_TAG_THREAD_CALLSTACK, LMEM_ZEROINIT, sizeof(VMMOB_MAP_THREADCALLSTACK), NULL, NULL))) {
                pObCS->dwPID = pProcess->dwPID;
                pObCS->dwTID = pThread->dwTID;
            }
            if(pObCS) {
                ObMap_Push(H->vmm.pmObThreadCallback, qwKey, pObCS);
            }
        }
        ReleaseSRWLockExclusive(&H->vmm.LockSRW.ThreadCallback);
    }
    *ppObCS = pObCS;
    return pObCS ? TRUE : FALSE;
}
