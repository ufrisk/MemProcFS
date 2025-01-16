// vmmproc.c : implementation of functions related to operating system and process parsing of virtual memory.
//
// (c) Ulf Frisk, 2018-2025
// Author: Ulf Frisk, pcileech@frizk.net
//

#include "vmmdll.h"
#include "vmmproc.h"
#include "vmmvm.h"
#include "vmmwin.h"
#include "vmmwininit.h"
#include "vmmheap.h"
#include "vmmnet.h"
#include "vmmwinobj.h"
#include "vmmwinpool.h"
#include "vmmwinreg.h"
#include "vmmwinsvc.h"
#include "vmmwinthread.h"
#include "mm/mm_pfn.h"
#include "pluginmanager.h"
#include "statistics.h"
#include "util.h"

// ----------------------------------------------------------------------------
// GENERIC PROCESS RELATED FUNCTIONALITY BELOW:
// ----------------------------------------------------------------------------

/*
* Initialize a "Physical Only" instance with extremely limited analysis capabilities.
* -- H
* -- return
*/
BOOL VmmProcUserTryInitializePhysical(_In_ VMM_HANDLE H)
{
    VmmInitializeMemoryModel(H, VMM_MEMORYMODEL_NA);
    H->vmm.tpSystem = VMM_SYSTEM_UNKNOWN_PHYSICAL;
    return TRUE;
}

/*
* Try initialize from user supplied CR3/PML4 supplied in parameter at startup.
* -- H
* -- return
*/
BOOL VmmProcUserCR3TryInitialize64(_In_ VMM_HANDLE H)
{
    PVMM_PROCESS pObProcess;
    VmmInitializeMemoryModel(H, VMM_MEMORYMODEL_X64);
    pObProcess = VmmProcessCreateEntry(H, TRUE, 1, 0, 0, H->cfg.paCR3, 0, "unknown_process", FALSE, NULL, 0);
    VmmProcessCreateFinish(H);
    if(!pObProcess) {
        VmmLog(H, MID_CORE, LOGLEVEL_VERBOSE, "FAIL: Initialization of Process failed from user-defined CR3 %016llx", H->cfg.paCR3);
        VmmInitializeMemoryModel(H, VMM_MEMORYMODEL_NA);
        return FALSE;
    }
    VmmTlbSpider(H, pObProcess);
    Ob_DECREF(pObProcess);
    H->vmm.tpSystem = VMM_SYSTEM_UNKNOWN_64;
    H->vmm.kernel.paDTB = H->cfg.paCR3;
    return TRUE;
}

BOOL VmmProc_RefreshProcesses(_In_ VMM_HANDLE H, _In_ BOOL fRefreshTotal)
{
    BOOL fResult = FALSE;
    PVMM_PROCESS pObProcessSystem;
    // statistic count
    if(!fRefreshTotal) { InterlockedIncrement64(&H->vmm.stat.cProcessRefreshPartial); }
    if(fRefreshTotal) { InterlockedIncrement64(&H->vmm.stat.cProcessRefreshFull); }
    // Single user-defined X64 process
    if(fRefreshTotal && (H->vmm.tpSystem == VMM_SYSTEM_UNKNOWN_64)) {
        fResult = VmmProcUserCR3TryInitialize64(H);
    }
    // Windows OS
    if((H->vmm.tpSystem == VMM_SYSTEM_WINDOWS_64) || (H->vmm.tpSystem == VMM_SYSTEM_WINDOWS_32)) {
        VmmLog(H, MID_CORE, LOGLEVEL_DEBUG, "PROCESS_REFRESH: %s", (fRefreshTotal ? "Total" : "Partial"));
        pObProcessSystem = VmmProcessGet(H, 4);
        if(!pObProcessSystem) {
            VmmLog(H, MID_CORE, LOGLEVEL_CRITICAL, "SYSTEM PROCESS NOT FOUND - SHOULD NOT HAPPEN");
            return FALSE;
        }
        fResult = VmmWinProcess_Enumerate(H, pObProcessSystem, fRefreshTotal, NULL);
        Ob_DECREF(pObProcessSystem);
    }
    return fResult;
}

// Initial hard coded values that seems to be working nicely below. These values
// may be changed in config options or by editing files in the .status directory.

#define VMMPROC_UPDATERTHREAD_LOCAL_PERIOD              100
#define VMMPROC_UPDATERTHREAD_LOCAL_MEM                 (300 / VMMPROC_UPDATERTHREAD_LOCAL_PERIOD)              // 0.3s
#define VMMPROC_UPDATERTHREAD_LOCAL_TLB                 (2 * 1000 / VMMPROC_UPDATERTHREAD_LOCAL_PERIOD)         // 2s
#define VMMPROC_UPDATERTHREAD_LOCAL_FAST                (5 * 1000 / VMMPROC_UPDATERTHREAD_LOCAL_PERIOD)         // 5s
#define VMMPROC_UPDATERTHREAD_LOCAL_MEDIUM              (15 * 1000 / VMMPROC_UPDATERTHREAD_LOCAL_PERIOD)        // 15s
#define VMMPROC_UPDATERTHREAD_LOCAL_SLOW                (5 * 60 * 1000 / VMMPROC_UPDATERTHREAD_LOCAL_PERIOD)    // 5m

#define VMMPROC_UPDATERTHREAD_REMOTE_PERIOD             100
#define VMMPROC_UPDATERTHREAD_REMOTE_MEM                (5 * 1000 / VMMPROC_UPDATERTHREAD_REMOTE_PERIOD)        // 5s
#define VMMPROC_UPDATERTHREAD_REMOTE_TLB                (2 * 60 * 1000 / VMMPROC_UPDATERTHREAD_REMOTE_PERIOD)   // 2m
#define VMMPROC_UPDATERTHREAD_REMOTE_FAST               (15 * 1000 / VMMPROC_UPDATERTHREAD_REMOTE_PERIOD)       // 15s
#define VMMPROC_UPDATERTHREAD_REMOTE_MEDIUM             (3 * 60 * 1000 / VMMPROC_UPDATERTHREAD_REMOTE_PERIOD)   // 3m
#define VMMPROC_UPDATERTHREAD_REMOTE_SLOW               (10 * 60 * 1000 / VMMPROC_UPDATERTHREAD_LOCAL_PERIOD)   // 10m

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
* -- H
*/
_Success_(return)
BOOL VmmProcRefresh_MEM(_In_ VMM_HANDLE H)
{
    EnterCriticalSection(&H->vmm.LockMaster);
    H->vmm.tcRefreshMEM++;
    VmmCacheClearPartial(H, VMM_CACHE_TAG_PHYS);
    InterlockedIncrement64(&H->vmm.stat.cPhysRefreshCache);
    VmmCacheClearPartial(H, VMM_CACHE_TAG_PAGING);
    InterlockedIncrement64(&H->vmm.stat.cPageRefreshCache);
    ObSet_Clear(H->vmm.Cache.PAGING_FAILED);
    LeaveCriticalSection(&H->vmm.LockMaster);
    return TRUE;
}

_Success_(return)
BOOL VmmProcRefresh_TLB(_In_ VMM_HANDLE H)
{
    EnterCriticalSection(&H->vmm.LockMaster);
    H->vmm.tcRefreshTLB++;
    VmmCacheClearPartial(H, VMM_CACHE_TAG_TLB);
    InterlockedIncrement64(&H->vmm.stat.cTlbRefreshCache);
    LeaveCriticalSection(&H->vmm.LockMaster);
    return TRUE;
}

_Success_(return)
BOOL VmmProcRefresh_Fast(_In_ VMM_HANDLE H)
{
    EnterCriticalSection(&H->vmm.LockMaster);
    H->vmm.tcRefreshFast++;
    if(!VmmProc_RefreshProcesses(H, FALSE)) {
        LeaveCriticalSection(&H->vmm.LockMaster);
        VmmLog(H, MID_CORE, LOGLEVEL_CRITICAL, "Failed to refresh MemProcFS - aborting!");
        return FALSE;
    }
    PluginManager_Notify(H, VMMDLL_PLUGIN_NOTIFY_REFRESH_FAST, NULL, 0);
    LeaveCriticalSection(&H->vmm.LockMaster);
    return TRUE;
}

_Success_(return)
BOOL VmmProcRefresh_Medium(_In_ VMM_HANDLE H)
{
    EnterCriticalSection(&H->vmm.LockMaster);
    H->vmm.tcRefreshMedium++;
    if(!VmmProc_RefreshProcesses(H, TRUE)) {
        LeaveCriticalSection(&H->vmm.LockMaster);
        VmmLog(H, MID_CORE, LOGLEVEL_CRITICAL, "Failed to refresh MemProcFS - aborting!");
        return FALSE;
    }
    VmmNet_Refresh(H);
    VmmWinObj_Refresh(H);
    MmPfn_Refresh(H);
    VmmHeapAlloc_Refresh(H);
    PluginManager_Notify(H, VMMDLL_PLUGIN_NOTIFY_REFRESH_MEDIUM, NULL, 0);
    LeaveCriticalSection(&H->vmm.LockMaster);
    return TRUE;
}

_Success_(return)
BOOL VmmProcRefresh_Slow(_In_ VMM_HANDLE H)
{
    VmmProcRefresh_Medium(H);
    EnterCriticalSection(&H->vmm.LockMaster);
    H->vmm.tcRefreshSlow++;
    VmmWinReg_Refresh(H);
    VmmWinUser_Refresh(H);
    VmmWinSvc_Refresh(H);
    VmmWinPool_Refresh(H);
    VmmWinPhysMemMap_Refresh(H);
    VmmVm_Refresh(H);
    VmmWinThreadCs_Refresh(H);
    PluginManager_Notify(H, VMMDLL_PLUGIN_NOTIFY_REFRESH_SLOW, NULL, 0);
    LeaveCriticalSection(&H->vmm.LockMaster);
    return TRUE;
}

#define VMMPROCCACHE_SETDEFAULT(dwDst, dwSrc)       (dwDst = (DWORD)(dwDst ? dwDst : dwSrc))

VOID VmmProcCacheUpdaterThread(_In_ VMM_HANDLE H, _In_ QWORD qwNotUsed)
{
    QWORD i = 0, qwTickPeriodCount;
    BOOL fRefreshMEM, fRefreshTLB, fRefreshFast, fRefreshMedium, fRefreshSlow;
    VmmLog(H, MID_CORE, LOGLEVEL_VERBOSE, "VmmProc: Start periodic cache flushing");
    if(H->dev.fRemote) {
        VMMPROCCACHE_SETDEFAULT(H->vmm.ThreadProcCache.cMs_TickPeriod,  VMMPROC_UPDATERTHREAD_REMOTE_PERIOD);
        VMMPROCCACHE_SETDEFAULT(H->vmm.ThreadProcCache.cTick_MEM,       VMMPROC_UPDATERTHREAD_REMOTE_MEM);
        VMMPROCCACHE_SETDEFAULT(H->vmm.ThreadProcCache.cTick_TLB,       VMMPROC_UPDATERTHREAD_REMOTE_TLB);
        VMMPROCCACHE_SETDEFAULT(H->vmm.ThreadProcCache.cTick_Fast,      VMMPROC_UPDATERTHREAD_REMOTE_FAST);
        VMMPROCCACHE_SETDEFAULT(H->vmm.ThreadProcCache.cTick_Medium,    VMMPROC_UPDATERTHREAD_REMOTE_MEDIUM);
        VMMPROCCACHE_SETDEFAULT(H->vmm.ThreadProcCache.cTick_Slow,      VMMPROC_UPDATERTHREAD_REMOTE_SLOW);
    } else {
        VMMPROCCACHE_SETDEFAULT(H->vmm.ThreadProcCache.cMs_TickPeriod,  VMMPROC_UPDATERTHREAD_LOCAL_PERIOD);
        VMMPROCCACHE_SETDEFAULT(H->vmm.ThreadProcCache.cTick_MEM,       VMMPROC_UPDATERTHREAD_LOCAL_MEM);
        VMMPROCCACHE_SETDEFAULT(H->vmm.ThreadProcCache.cTick_TLB,       VMMPROC_UPDATERTHREAD_LOCAL_TLB);
        VMMPROCCACHE_SETDEFAULT(H->vmm.ThreadProcCache.cTick_Fast,      VMMPROC_UPDATERTHREAD_LOCAL_FAST);
        VMMPROCCACHE_SETDEFAULT(H->vmm.ThreadProcCache.cTick_Medium,    VMMPROC_UPDATERTHREAD_LOCAL_MEDIUM);
        VMMPROCCACHE_SETDEFAULT(H->vmm.ThreadProcCache.cTick_Slow,      VMMPROC_UPDATERTHREAD_LOCAL_SLOW);
    }
    while(!H->fAbort && H->vmm.ThreadProcCache.fEnabled) {
        if(H->vmm.ThreadProcCache.cMs_TickPeriod > 100) {
            qwTickPeriodCount = 0;
            while((qwTickPeriodCount < H->vmm.ThreadProcCache.cMs_TickPeriod) && !H->fAbort) {
                qwTickPeriodCount += 25;
                Sleep(25);
            }
        } else {
            Sleep(H->vmm.ThreadProcCache.cMs_TickPeriod);
        }
        if(H->fAbort) { break; }
        i++;
        fRefreshTLB = !(i % H->vmm.ThreadProcCache.cTick_TLB);
        fRefreshMEM = !(i % H->vmm.ThreadProcCache.cTick_MEM);
        fRefreshSlow = !(i % H->vmm.ThreadProcCache.cTick_Slow);
        fRefreshMedium = !(i % H->vmm.ThreadProcCache.cTick_Medium) && !fRefreshSlow;
        fRefreshFast = !(i % H->vmm.ThreadProcCache.cTick_Fast) && !fRefreshSlow && !fRefreshMedium;
        // PHYS / TLB cache clear
        EnterCriticalSection(&H->vmm.LockMaster);
        if(fRefreshMEM) {
            VmmProcRefresh_MEM(H);
        }
        if(fRefreshTLB) {
            VmmProcRefresh_TLB(H);
        }
        if(fRefreshFast) {
            VmmProcRefresh_Fast(H);      // incl. partial process refresh
        }
        if(fRefreshMedium) {
            VmmProcRefresh_Medium(H);    // incl. full process refresh
        }
        if(fRefreshSlow) {
            VmmProcRefresh_Slow(H);
        }
        LeaveCriticalSection(&H->vmm.LockMaster);
    }
    VmmLog(H, MID_CORE, LOGLEVEL_VERBOSE, "Exit periodic cache flushing");
}

BOOL VmmProcInitialize(_In_ VMM_HANDLE H)
{
    BOOL result = FALSE;
    if(!VmmInitialize(H)) { return FALSE; }
    if(H->cfg.fPhysicalOnlyMemory) {
        return VmmProcUserTryInitializePhysical(H);
    }
    // 1: try initialize 'windows' with an optionally supplied CR3
    result = VmmWinInit_TryInitialize(H, H->cfg.paCR3);
    if(!result) {
        result = H->cfg.paCR3 && VmmProcUserCR3TryInitialize64(H);
        if(!result) {
            VmmLog(H, MID_CORE, LOGLEVEL_CRITICAL, "Unable to auto-identify operating system.    \n" \
                "           Specify PageDirectoryBase (DTB/CR3) in -dtb option if value if known.\n" \
                "           If arm64 dump, specify architecture: -arch arm64                     \n"

            );
        }
    }
    // set up cache maintenance in the form of a separate eternally running
    // worker thread in case the backend is a volatile device (FPGA).
    // If the underlying device isn't volatile then there is no need to update!
    // NB! Files are not considered to be volatile.
    if(result && H->dev.fVolatile && !H->cfg.fDisableBackgroundRefresh) {
        H->vmm.ThreadProcCache.fEnabled = TRUE;
        VmmWork_Value(H, VmmProcCacheUpdaterThread, 0, 0, VMMWORK_FLAG_PRIO_NORMAL);
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
