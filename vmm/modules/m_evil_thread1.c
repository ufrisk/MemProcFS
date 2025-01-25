// m_evil_thrd1.c : evil detectors for potentially evil threads.
// 
// Largely based on: https://www.elastic.co/de/security-labs/get-injectedthreadex-detection-thread-creation-trampolines
//
// Detections:
//  - THREAD_START
// 
// (c) Ulf Frisk, 2023-2025
// Author: Ulf Frisk, pcileech@frizk.net
//

#include "modules.h"
#include "../vmmwin.h"
#include "../sysquery.h"

typedef struct tdMEVIL_THREAD1_ENTRY {
    QWORD vaETHREAD;
    QWORD vaWin32StartAddress;
    DWORD dwPID;
    DWORD dwTID;
    // detections below:
    BOOL fNoImage;
    BOOL fPrivate;
    BOOL fBadModule;
    BOOL fLoadLibrary;
    BOOL fSystemImpersonation;
    BOOL fNoRtlUserThreadStart;
} MEVIL_THREAD1_ENTRY, *PMEVIL_THREAD1_ENTRY;

typedef struct tdMEVIL_THREAD1_CONTEXT {
    // full lifetime fields below:
    POB_MAP pm;
    QWORD vaLoadLibrary;
    QWORD vaRtlUserThreadStart;
    BOOL fNtdllStartAddresses;
    QWORD vaTppWorkerThread;
    QWORD vaEtwpLogger;
    QWORD vaDbgUiRemoteBreakin;
    QWORD vaRtlpQueryProcessDebugInformationRemote;
    // temporary fields below:
    PVMM_PROCESS pProcess;
    PVMMOB_MAP_VAD pVadMap;
    PVMMOB_MAP_MODULE pModuleMap;
} MEVIL_THREAD1_CONTEXT, *PMEVIL_THREAD1_CONTEXT;

_Success_(return)
BOOL MEvilThread1_InitContext(_In_ VMM_HANDLE H, _Inout_ PMEVIL_THREAD1_CONTEXT ctx)
{
    PDB_HANDLE hPDB_NTDLL;
    PVMM_PROCESS pObProcessSMSS = NULL;
    PVMMOB_MAP_MODULE pObModuleMap = NULL;
    PVMM_MAP_MODULEENTRY peModule = NULL;
    while((pObProcessSMSS = VmmProcessGetNext(H, pObProcessSMSS, 0))) {
        if(!pObProcessSMSS->dwState && CharUtil_StrEquals(pObProcessSMSS->szName, "smss.exe", FALSE)) {
            break;
        }
    }
    if(!pObProcessSMSS) { return FALSE; }
    if(!(ctx->pm = ObMap_New(H, OB_MAP_FLAGS_OBJECT_LOCALFREE))) { return FALSE; }
    ctx->vaLoadLibrary = SysQuery_GetProcAddress(H, pObProcessSMSS, "kernel32.dll", "LoadLibrary");
    ctx->vaRtlUserThreadStart = SysQuery_GetProcAddress(H, pObProcessSMSS, "ntdll.dll", "RtlUserThreadStart");
    if(VmmMap_GetModuleEntryEx(H, pObProcessSMSS, 0, "ntdll.dll", 0, &pObModuleMap, &peModule)) {
        if((hPDB_NTDLL = PDB_GetHandleFromModuleAddress(H, pObProcessSMSS, peModule->vaBase))) {
            ctx->fNtdllStartAddresses =
                PDB_GetSymbolAddress(H, hPDB_NTDLL, "TppWorkerThread", &ctx->vaTppWorkerThread) &&
                PDB_GetSymbolAddress(H, hPDB_NTDLL, "EtwpLogger", &ctx->vaEtwpLogger) &&
                PDB_GetSymbolAddress(H, hPDB_NTDLL, "DbgUiRemoteBreakin", &ctx->vaDbgUiRemoteBreakin) &&
                PDB_GetSymbolAddress(H, hPDB_NTDLL, "RtlpQueryProcessDebugInformationRemote", &ctx->vaRtlpQueryProcessDebugInformationRemote);
        }
    }
    Ob_DECREF(pObModuleMap);
    Ob_DECREF(pObProcessSMSS);
    return TRUE;
}

/*
* Get a evil thread entry. If the entry does not exist it will be created.
* NB! Do not free the returned entry - it is owned by the context.
*/
_Success_(return != NULL)
PMEVIL_THREAD1_ENTRY MEvilThread1_GetEntry(_In_ VMM_HANDLE H, _Inout_ PMEVIL_THREAD1_CONTEXT ctx, _In_ PVMM_MAP_THREADENTRY pThreadEntry)
{
    PMEVIL_THREAD1_ENTRY pe;
    if((pe = ObMap_GetByKey(ctx->pm, pThreadEntry->vaETHREAD))) {
        return pe;
    }
    if((pe = LocalAlloc(LMEM_ZEROINIT, sizeof(MEVIL_THREAD1_ENTRY)))) {
        pe->vaWin32StartAddress = pThreadEntry->vaWin32StartAddress;
        pe->vaETHREAD = pThreadEntry->vaETHREAD;
        pe->dwPID = pThreadEntry->dwPID;
        pe->dwTID = pThreadEntry->dwTID;
        ObMap_Push(ctx->pm, pe->vaETHREAD, pe);
    }
    return pe;
}



//-----------------------------------------------------------------------------
// FINDEVIL DETECTIONS:
//-----------------------------------------------------------------------------

VOID MEvilThread1_DetectEvil_1(_In_ VMM_HANDLE H, _Inout_ PMEVIL_THREAD1_CONTEXT ctx, _In_ PVMM_MAP_THREADENTRY pThreadEntry)
{
    BOOL f;
    PMEVIL_THREAD1_ENTRY pEvilEntry;
    PVMM_MAP_MODULEENTRY pModuleEntry = NULL;
    // Initialization:
    if(ctx->pModuleMap) {
        pModuleEntry = VmmMap_GetModuleEntryEx2(H, ctx->pModuleMap, pThreadEntry->vaWin32StartAddress);
    }
    // Bad NoRtlUserThreadStart():
    if((pThreadEntry->vaStartAddress != ctx->vaRtlUserThreadStart) && ctx->vaRtlUserThreadStart && VMM_UADDR64(pThreadEntry->vaStartAddress)) {
        if((pEvilEntry = MEvilThread1_GetEntry(H, ctx, pThreadEntry))) {
            pEvilEntry->fNoRtlUserThreadStart = TRUE;
        }
    }
    // LoadLibrary:
    if(pThreadEntry->vaWin32StartAddress == ctx->vaLoadLibrary) {
        if((pEvilEntry = MEvilThread1_GetEntry(H, ctx, pThreadEntry))) {
            pEvilEntry->fLoadLibrary = TRUE;
        }
    }
    // Bad Module (kernel32):
    if(pModuleEntry && CharUtil_StrEquals(pModuleEntry->uszText, "kernel32.dll", TRUE) && ctx->vaLoadLibrary) {
        if((pEvilEntry = MEvilThread1_GetEntry(H, ctx, pThreadEntry))) {
            if(!pEvilEntry->fBadModule) {
                pEvilEntry->fBadModule = TRUE;
            }
        }
    }
    // Bad Module (kernelbase/user32/advapi32):
    if(pModuleEntry) {
        if(CharUtil_StrEquals(pModuleEntry->uszText, "kernelbase.dll", TRUE) || CharUtil_StrEquals(pModuleEntry->uszText, "user32.dll", TRUE) || CharUtil_StrEquals(pModuleEntry->uszText, "advapi32.dll", TRUE)) {
            if((pEvilEntry = MEvilThread1_GetEntry(H, ctx, pThreadEntry))) {
                pEvilEntry->fBadModule = TRUE;
            }
        }
    }
    // Bad Module (ntdll):
    if(pModuleEntry && CharUtil_StrEquals(pModuleEntry->uszText, "ntdll.dll", TRUE)) {
        f = ctx->pProcess->win.fWow64 || (ctx->fNtdllStartAddresses == 0) ||
            (pThreadEntry->vaWin32StartAddress == ctx->vaTppWorkerThread) ||
            (pThreadEntry->vaWin32StartAddress == ctx->vaEtwpLogger) ||
            (pThreadEntry->vaWin32StartAddress == ctx->vaDbgUiRemoteBreakin) ||
            (pThreadEntry->vaWin32StartAddress == ctx->vaRtlpQueryProcessDebugInformationRemote);
        if(!f) {
            if((pEvilEntry = MEvilThread1_GetEntry(H, ctx, pThreadEntry))) {
                if(!pEvilEntry->fBadModule) {
                    pEvilEntry->fBadModule = TRUE;
                }
            }
        }
    }
}

VOID MEvilThread1_DetectEvil_2(_In_ VMM_HANDLE H, _Inout_ PMEVIL_THREAD1_CONTEXT ctx, _In_ PVMM_MAP_THREADENTRY pThreadEntry)
{
    PMEVIL_THREAD1_ENTRY pEvilEntry;
    PVMMOB_TOKEN pObToken = NULL;
    // Thread impersonation (as system):
    // This is unfortunately fairly noisy.
    if(pThreadEntry->vaImpersonationToken && ctx->pProcess->win.Token && !ctx->pProcess->win.Token->fSidUserSYSTEM && (ctx->pProcess->win.Token->IntegrityLevel != VMMDLL_PROCESS_INTEGRITY_LEVEL_SYSTEM)) {
        if(VmmWinToken_Initialize(H, 1, &pThreadEntry->vaImpersonationToken, &pObToken)) {
            if(pObToken->fSidUserSYSTEM) {
                if((pEvilEntry = MEvilThread1_GetEntry(H, ctx, pThreadEntry))) {
                    pEvilEntry->fSystemImpersonation = TRUE;
                }
            }
            Ob_DECREF_NULL(&pObToken);
        }
    }
}

VOID MEvilThread1_DetectEvil_3(_In_ VMM_HANDLE H, _Inout_ PMEVIL_THREAD1_CONTEXT ctx, _In_ PVMM_MAP_THREADENTRY pThreadEntry)
{
    PMEVIL_THREAD1_ENTRY pEvilEntry;
    PVMM_MAP_VADENTRY pVadEntry = NULL;
    PVMMOB_MAP_VADEX pObVadExMap = NULL;
    DWORD oVadEx;
    // Initialization:
    pVadEntry = VmmMap_GetVadEntry(H, ctx->pVadMap, pThreadEntry->vaWin32StartAddress);
    if(!pVadEntry) { return; }
    oVadEx = (DWORD)((pThreadEntry->vaWin32StartAddress - pVadEntry->vaStart) >> 12);
    VmmMap_GetVadEx(H, ctx->pProcess, &pObVadExMap, VMM_VADMAP_TP_FULL, pVadEntry->cVadExPagesBase + oVadEx, 1);
    // NoImage:
    if(!pVadEntry->fImage) {
        if((pEvilEntry = MEvilThread1_GetEntry(H, ctx, pThreadEntry))) {
            pEvilEntry->fNoImage = TRUE;
        }
    }
    // Private Memory:
    if(pObVadExMap && pObVadExMap->cMap && pObVadExMap->pMap[0].pa && pObVadExMap->pMap[0].proto.pa && (pObVadExMap->pMap[0].pa != pObVadExMap->pMap[0].proto.pa)) {
        if((pEvilEntry = MEvilThread1_GetEntry(H, ctx, pThreadEntry))) {
            pEvilEntry->fPrivate = TRUE;
        }
    }
    Ob_DECREF(pObVadExMap);
}

VOID MEvilThread1_LogEntry(_In_ VMM_HANDLE H, _In_ PMEVIL_THREAD1_ENTRY pe)
{
    int o;
    CHAR usz[MAX_PATH];
    PVMM_PROCESS pObProcess = NULL;
    o = _snprintf_s(usz, _countof(usz), _TRUNCATE, "TID:%i", pe->dwTID);
    if(pe->fNoImage) {
        o += _snprintf_s(usz + o, _countof(usz) - o, _TRUNCATE, " NO_IMAGE");
    }
    if(pe->fPrivate) {
        o += _snprintf_s(usz + o, _countof(usz) - o, _TRUNCATE, " PRIVATE_MEMORY");
    }
    if(pe->fBadModule) {
        o += _snprintf_s(usz + o, _countof(usz) - o, _TRUNCATE, " BAD_MODULE");
    }
    if(pe->fLoadLibrary) {
        o += _snprintf_s(usz + o, _countof(usz) - o, _TRUNCATE, " LOAD_LIBRARY");
    }
    if(pe->fSystemImpersonation) {
        o += _snprintf_s(usz + o, _countof(usz) - o, _TRUNCATE, " SYSTEM_IMPERSONATION");
    }
    if(pe->fNoRtlUserThreadStart) {
        o += _snprintf_s(usz + o, _countof(usz) - o, _TRUNCATE, " NO_RTLUSERTHREADSTART");
    }
    pObProcess = VmmProcessGet(H, pe->dwPID);
    FcEvilAdd(H, EVIL_THREAD, pObProcess, pe->vaWin32StartAddress, "%s", usz);
}



//-----------------------------------------------------------------------------
// COMMON:
//-----------------------------------------------------------------------------

VOID MEvilThread1_DoWork(_In_ VMM_HANDLE H, _In_ VMMDLL_MODULE_ID MID, _In_opt_ PVOID ctxfc)
{
    DWORD i;
    PMEVIL_THREAD1_ENTRY peEvil;
    MEVIL_THREAD1_CONTEXT ctx = { 0 };
    PVMM_MAP_THREADENTRY pThreadEntry;
    PVMM_PROCESS pObProcess = NULL;
    PVMMOB_MAP_THREAD pObThreadMap = NULL;
    // 1: initialize context:
    if(!MEvilThread1_InitContext(H, &ctx)) { goto fail; }
    // 2: scan user-mode processes for evil threads:
    while((pObProcess = VmmProcessGetNext(H, pObProcess, VMM_FLAG_PROCESS_TOKEN))) {
        if(H->fAbort) { goto fail; }
        if(pObProcess->dwState || VmmProcess_IsKernelOnly(pObProcess)) { continue; }
        if(FcIsProcessSkip(H, pObProcess)) { continue; }
        if(VmmMap_GetThread(H, pObProcess, &pObThreadMap)) {
            VmmMap_GetModule(H, pObProcess, 0, &ctx.pModuleMap);
            VmmMap_GetVad(H, pObProcess, &ctx.pVadMap, VMM_VADMAP_TP_FULL);
            ctx.pProcess = pObProcess;

            for(i = 0; i < pObThreadMap->cMap; i++) {
                if(H->fAbort) { goto fail; }
                pThreadEntry = pObThreadMap->pMap + i;
                if(VMM_KADDR64(pThreadEntry->vaWin32StartAddress)) { continue; }    // skip kernel threads

                MEvilThread1_DetectEvil_1(H, &ctx, pThreadEntry);
                MEvilThread1_DetectEvil_2(H, &ctx, pThreadEntry);
                MEvilThread1_DetectEvil_3(H, &ctx, pThreadEntry);
            }
        }
        Ob_DECREF_NULL(&ctx.pModuleMap);
        Ob_DECREF_NULL(&ctx.pVadMap);
        Ob_DECREF_NULL(&pObThreadMap);
    }
    // 3: log result:
    while((peEvil = ObMap_Pop(ctx.pm))) {
        MEvilThread1_LogEntry(H, peEvil);
        LocalFree(peEvil);
    }
    VmmLog(H, MID, LOGLEVEL_6_TRACE, "COMPLETED FINDEVIL SCAN");
fail:
    Ob_DECREF_NULL(&ctx.pm);
    Ob_DECREF_NULL(&ctx.pModuleMap);
    Ob_DECREF(pObThreadMap);
    Ob_DECREF(pObProcess);
}

VOID M_Evil_Thread1(_In_ VMM_HANDLE H, _Inout_ PVMMDLL_PLUGIN_REGINFO pRI)
{
    if((pRI->magic != VMMDLL_PLUGIN_REGINFO_MAGIC) || (pRI->wVersion != VMMDLL_PLUGIN_REGINFO_VERSION)) { return; }
    if(pRI->sysinfo.f32 || (pRI->sysinfo.dwVersionBuild < 9600)) { return; }    // only support 64-bit Win8.1+ for now
    // register findevil plugin:
    strcpy_s(pRI->reg_info.uszPathName, 128, "\\findevil\\EvTHRD1");
    pRI->reg_info.fRootModule = TRUE;
    pRI->reg_info.fRootModuleHidden = TRUE;
    pRI->reg_fnfc.pfnFindEvil = MEvilThread1_DoWork;
    pRI->pfnPluginManager_Register(H, pRI);
}
