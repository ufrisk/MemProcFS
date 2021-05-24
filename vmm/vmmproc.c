// vmmproc.c : implementation of functions related to operating system and process parsing of virtual memory.
//
// (c) Ulf Frisk, 2018-2021
// Author: Ulf Frisk, pcileech@frizk.net
//

#include "vmmdll.h"
#include "vmmproc.h"
#include "vmmwin.h"
#include "vmmwininit.h"
#include "vmmnet.h"
#include "vmmwinobj.h"
#include "vmmwinreg.h"
#include "vmmwinsvc.h"
#include "mm_pfn.h"
#include "pluginmanager.h"
#include "statistics.h"
#include "util.h"

// ----------------------------------------------------------------------------
// GENERIC PROCESS RELATED FUNCTIONALITY BELOW:
// ----------------------------------------------------------------------------

/*
* Try initialize from user supplied CR3/PML4 supplied in parameter at startup.
* -- ctx
* -- return
*/
BOOL VmmProcUserCR3TryInitialize64()
{
    PVMM_PROCESS pObProcess;
    VmmInitializeMemoryModel(VMM_MEMORYMODEL_X64);
    pObProcess = VmmProcessCreateEntry(TRUE, 1, 0, 0, ctxMain->cfg.paCR3, 0, "unknown_process", FALSE, NULL, 0);
    VmmProcessCreateFinish();
    if(!pObProcess) {
        vmmprintfv("VmmProc: FAIL: Initialization of Process failed from user-defined CR3 %016llx.\n", ctxMain->cfg.paCR3);
        VmmInitializeMemoryModel(VMM_MEMORYMODEL_NA);
        return FALSE;
    }
    VmmTlbSpider(pObProcess);
    Ob_DECREF(pObProcess);
    ctxVmm->tpSystem = VMM_SYSTEM_UNKNOWN_X64;
    ctxVmm->kernel.paDTB = ctxMain->cfg.paCR3;
    return TRUE;
}

BOOL VmmProc_RefreshProcesses(_In_ BOOL fRefreshTotal)
{
    BOOL fResult = FALSE;
    PVMM_PROCESS pObProcessSystem;
    // statistic count
    if(!fRefreshTotal) { InterlockedIncrement64(&ctxVmm->stat.cProcessRefreshPartial); }
    if(fRefreshTotal) { InterlockedIncrement64(&ctxVmm->stat.cProcessRefreshFull); }
    // Single user-defined X64 process
    if(fRefreshTotal && (ctxVmm->tpSystem == VMM_SYSTEM_UNKNOWN_X64)) {
        fResult = VmmProcUserCR3TryInitialize64();
    }
    // Windows OS
    if((ctxVmm->tpSystem == VMM_SYSTEM_WINDOWS_X64) || (ctxVmm->tpSystem == VMM_SYSTEM_WINDOWS_X86)) {
        vmmprintfvv_fn("ProcessRefresh: %s\n", (fRefreshTotal ? "Total" : "Partial"));
        pObProcessSystem = VmmProcessGet(4);
        if(!pObProcessSystem) {
            vmmprintf_fn("FAIL - SYSTEM PROCESS NOT FOUND - SHOULD NOT HAPPEN\n");
            return FALSE;
        }
        fResult = VmmWinProcess_Enumerate(pObProcessSystem, fRefreshTotal, NULL);
        Ob_DECREF(pObProcessSystem);
    }
    return fResult;
}

// Initial hard coded values that seems to be working nicely below. These values
// may be changed in config options or by editing files in the .status directory.

#define VMMPROC_UPDATERTHREAD_LOCAL_PERIOD              100
#define VMMPROC_UPDATERTHREAD_LOCAL_MEM                 (300 / VMMPROC_UPDATERTHREAD_LOCAL_PERIOD)                // 0.3s
#define VMMPROC_UPDATERTHREAD_LOCAL_TLB                 (2 * 1000 / VMMPROC_UPDATERTHREAD_LOCAL_PERIOD)           // 2s
#define VMMPROC_UPDATERTHREAD_LOCAL_PROC_REFRESHLIST    (5 * 1000 / VMMPROC_UPDATERTHREAD_LOCAL_PERIOD)           // 5s
#define VMMPROC_UPDATERTHREAD_LOCAL_PROC_REFRESHTOTAL   (15 * 1000 / VMMPROC_UPDATERTHREAD_LOCAL_PERIOD)          // 15s
#define VMMPROC_UPDATERTHREAD_LOCAL_REGISTRY            (5 * 60 * 1000 / VMMPROC_UPDATERTHREAD_LOCAL_PERIOD)      // 5m

#define VMMPROC_UPDATERTHREAD_REMOTE_PERIOD             100
#define VMMPROC_UPDATERTHREAD_REMOTE_MEM                (5 * 1000 / VMMPROC_UPDATERTHREAD_REMOTE_PERIOD)         // 5s
#define VMMPROC_UPDATERTHREAD_REMOTE_TLB                (2 * 60 * 1000 / VMMPROC_UPDATERTHREAD_REMOTE_PERIOD)    // 2m
#define VMMPROC_UPDATERTHREAD_REMOTE_PROC_REFRESHLIST   (15 * 1000 / VMMPROC_UPDATERTHREAD_REMOTE_PERIOD)        // 15s
#define VMMPROC_UPDATERTHREAD_REMOTE_PROC_REFRESHTOTAL  (3 * 60 * 1000 / VMMPROC_UPDATERTHREAD_REMOTE_PERIOD)    // 3m
#define VMMPROC_UPDATERTHREAD_REMOTE_REGISTRY           (10 * 60 * 1000 / VMMPROC_UPDATERTHREAD_LOCAL_PERIOD)    // 10m

/*
* Refresh functions refreshes aspects of MemProcFS at different intervals.
* Frequency from frequent to less frequent is as:
* 1. VmmProcRefresh_MEM()    = refresh memory cache (except page tables).
* 2. VmmProcRefresh_TLB()    = refresh page table cache.
* 3. VmmProcRefresh_Fast()   = fast refresh incl. partial process refresh.
* 4. VmmProcRefresh_Medium() = medium refresh incl. full process refresh.
* 5. VmmProcRefresh_Slow()   = slow refresh.
* A slower more comprehensive refresh layer does not equal that the lower
* faster refresh layers are run automatically - user has to refresh them too.
*/
_Success_(return)
BOOL VmmProcRefresh_MEM()
{
    EnterCriticalSection(&ctxVmm->LockMaster);
    ctxVmm->tcRefreshMEM++;
    VmmCacheClearPartial(VMM_CACHE_TAG_PHYS);
    InterlockedIncrement64(&ctxVmm->stat.cPhysRefreshCache);
    VmmCacheClearPartial(VMM_CACHE_TAG_PAGING);
    InterlockedIncrement64(&ctxVmm->stat.cPageRefreshCache);
    ObSet_Clear(ctxVmm->Cache.PAGING_FAILED);
    LeaveCriticalSection(&ctxVmm->LockMaster);
    return TRUE;
}

_Success_(return)
BOOL VmmProcRefresh_TLB()
{
    EnterCriticalSection(&ctxVmm->LockMaster);
    ctxVmm->tcRefreshTLB++;
    VmmCacheClearPartial(VMM_CACHE_TAG_TLB);
    InterlockedIncrement64(&ctxVmm->stat.cTlbRefreshCache);
    LeaveCriticalSection(&ctxVmm->LockMaster);
    return TRUE;
}

_Success_(return)
BOOL VmmProcRefresh_Fast()
{
    EnterCriticalSection(&ctxVmm->LockMaster);
    ctxVmm->tcRefreshFast++;
    if(!VmmProc_RefreshProcesses(FALSE)) {
        LeaveCriticalSection(&ctxVmm->LockMaster);
        vmmprintf("VmmProc: Failed to refresh MemProcFS - aborting.\n");
        return FALSE;
    }
    PluginManager_Notify(VMMDLL_PLUGIN_NOTIFY_REFRESH_FAST, NULL, 0);
    LeaveCriticalSection(&ctxVmm->LockMaster);
    return TRUE;
}

_Success_(return)
BOOL VmmProcRefresh_Medium()
{
    EnterCriticalSection(&ctxVmm->LockMaster);
    ctxVmm->tcRefreshMedium++;
    if(!VmmProc_RefreshProcesses(TRUE)) {
        LeaveCriticalSection(&ctxVmm->LockMaster);
        vmmprintf("VmmProc: Failed to refresh MemProcFS - aborting.\n");
        return FALSE;
    }
    VmmNet_Refresh();
    VmmWinObj_Refresh();
    MmPfn_Refresh();
    PluginManager_Notify(VMMDLL_PLUGIN_NOTIFY_REFRESH_MEDIUM, NULL, 0);
    LeaveCriticalSection(&ctxVmm->LockMaster);
    return TRUE;
}

_Success_(return)
BOOL VmmProcRefresh_Slow()
{
    EnterCriticalSection(&ctxVmm->LockMaster);
    ctxVmm->tcRefreshSlow++;
    VmmWinReg_Refresh();
    VmmWinUser_Refresh();
    VmmWinSvc_Refresh();
    VmmWinPhysMemMap_Refresh();
    PluginManager_Notify(VMMDLL_PLUGIN_NOTIFY_REFRESH_SLOW, NULL, 0);
    LeaveCriticalSection(&ctxVmm->LockMaster);
    return TRUE;
}

DWORD VmmProcCacheUpdaterThread()
{
    QWORD i = 0;
    BOOL fRefreshMEM, fRefreshTLB, fRefreshFast, fRefreshMedium, fRefreshSlow;
    vmmprintfv("VmmProc: Start periodic cache flushing.\n");
    if(ctxMain->dev.fRemote) {
        ctxVmm->ThreadProcCache.cMs_TickPeriod = VMMPROC_UPDATERTHREAD_REMOTE_PERIOD;
        ctxVmm->ThreadProcCache.cTick_MEM = VMMPROC_UPDATERTHREAD_REMOTE_MEM;
        ctxVmm->ThreadProcCache.cTick_TLB = VMMPROC_UPDATERTHREAD_REMOTE_TLB;
        ctxVmm->ThreadProcCache.cTick_Fast = VMMPROC_UPDATERTHREAD_REMOTE_PROC_REFRESHLIST;
        ctxVmm->ThreadProcCache.cTick_Medium = VMMPROC_UPDATERTHREAD_REMOTE_PROC_REFRESHTOTAL;
        ctxVmm->ThreadProcCache.cTick_Slow = VMMPROC_UPDATERTHREAD_REMOTE_REGISTRY;
    } else {
        ctxVmm->ThreadProcCache.cMs_TickPeriod = VMMPROC_UPDATERTHREAD_LOCAL_PERIOD;
        ctxVmm->ThreadProcCache.cTick_MEM = VMMPROC_UPDATERTHREAD_LOCAL_MEM;
        ctxVmm->ThreadProcCache.cTick_TLB = VMMPROC_UPDATERTHREAD_LOCAL_TLB;
        ctxVmm->ThreadProcCache.cTick_Fast = VMMPROC_UPDATERTHREAD_LOCAL_PROC_REFRESHLIST;
        ctxVmm->ThreadProcCache.cTick_Medium = VMMPROC_UPDATERTHREAD_LOCAL_PROC_REFRESHTOTAL;
        ctxVmm->ThreadProcCache.cTick_Slow = VMMPROC_UPDATERTHREAD_LOCAL_REGISTRY;
    }
    while(ctxVmm->Work.fEnabled && ctxVmm->ThreadProcCache.fEnabled) {
        Sleep(ctxVmm->ThreadProcCache.cMs_TickPeriod);
        i++;
        fRefreshTLB = !(i % ctxVmm->ThreadProcCache.cTick_TLB);
        fRefreshMEM = !(i % ctxVmm->ThreadProcCache.cTick_MEM);
        fRefreshSlow = !(i % ctxVmm->ThreadProcCache.cTick_Slow);
        fRefreshMedium = !(i % ctxVmm->ThreadProcCache.cTick_Medium);
        fRefreshFast = !(i % ctxVmm->ThreadProcCache.cTick_Fast) && !fRefreshMedium;
        // PHYS / TLB cache clear
        EnterCriticalSection(&ctxVmm->LockMaster);
        if(fRefreshMEM) {
            VmmProcRefresh_MEM();
        }
        if(fRefreshTLB) {
            VmmProcRefresh_TLB();
        }
        if(fRefreshFast) {
            VmmProcRefresh_Fast();      // incl. partial process refresh
        }
        if(fRefreshMedium) {
            VmmProcRefresh_Medium();    // incl. full process refresh
        }
        if(fRefreshSlow) {
            VmmProcRefresh_Slow();
        }
        LeaveCriticalSection(&ctxVmm->LockMaster);
    }
    vmmprintfv("VmmProc: Exit periodic cache flushing.\n");
    return 0;
}

BOOL VmmProcInitialize()
{
    BOOL result = FALSE;
    if(!VmmInitialize()) { return FALSE; }
    // 1: try initialize 'windows' with an optionally supplied CR3
    result = VmmWinInit_TryInitialize(ctxMain->cfg.paCR3);
    if(!result) {
        result = ctxMain->cfg.paCR3 && VmmProcUserCR3TryInitialize64();
        if(!result) {
            vmmprintf(
                "VmmProc: Unable to auto-identify operating system for PROC file system mount.   \n" \
                "         Specify PageDirectoryBase (DTB/CR3) in -cr3 option if value if known.  \n");
        }
    }
    // set up cache maintenance in the form of a separate eternally running
    // worker thread in case the backend is a volatile device (FPGA).
    // If the underlying device isn't volatile then there is no need to update!
    // NB! Files are not considered to be volatile.
    if(result && ctxMain->dev.fVolatile && !ctxMain->cfg.fDisableBackgroundRefresh) {
        ctxVmm->ThreadProcCache.fEnabled = TRUE;
        VmmWork((LPTHREAD_START_ROUTINE)VmmProcCacheUpdaterThread, NULL, 0);
    }
    return result;
}

// ----------------------------------------------------------------------------
// SCAN/SEARCH TO IDENTIFY IMAGE:
// - Currently Windows PageDirectoryBase/CR3/PML4 detection is supported only
// ----------------------------------------------------------------------------

_Success_(return)
BOOL VmmProcPHYS_VerifyWindowsEPROCESS(_In_ PBYTE pb, _In_ QWORD cb, _In_ QWORD cbOffset, _Out_ PQWORD ppaPML4)
{
    QWORD i;
    if(cb < cbOffset + 8) { return FALSE; }
    if((cb & 0x07) || (cb < 0x500) || (cbOffset < 0x500)) { return FALSE; }
    if(*(PQWORD)(pb + cbOffset) != 0x00006D6574737953) { return FALSE; }        // not matching System00
    if(*(PQWORD)(pb + cbOffset + 8) & 0x00ffffffffffffff) { return FALSE; }     // not matching 0000000
                                                                                // maybe we have EPROCESS struct here, scan back to see if we can find
                                                                                // 4 kernel addresses in a row and a potential PML4 after that and zero
                                                                                // DWORD before that. (EPROCESS HDR).
    for(i = cbOffset; i > cbOffset - 0x500; i -= 8) {
        if((*(PQWORD)(pb + i - 0x00) & 0xfffff00000000000)) { continue; };                          // DirectoryTableBase
        if(!*(PQWORD)(pb + i - 0x00)) { continue; };                                                // DirectoryTableBase
        if((*(PQWORD)(pb + i - 0x08) & 0xffff800000000000) != 0xffff800000000000) { continue; };    // PTR
        if((*(PQWORD)(pb + i - 0x10) & 0xffff800000000000) != 0xffff800000000000) { continue; };    // PTR
        if((*(PQWORD)(pb + i - 0x18) & 0xffff800000000000) != 0xffff800000000000) { continue; };    // PTR
        if((*(PQWORD)(pb + i - 0x20) & 0xffff800000000000) != 0xffff800000000000) { continue; };    // PTR
        if((*(PDWORD)(pb + i - 0x24) != 0x00000000)) { continue; };                                 // SignalState
        *ppaPML4 = *(PQWORD)(pb + i - 0x00) & ~0xfff;
        return TRUE;
    }
    return FALSE;
}
