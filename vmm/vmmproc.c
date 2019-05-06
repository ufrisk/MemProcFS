// vfsproc.c : implementation of functions related to operating system and process parsing of virtual memory.
//
// (c) Ulf Frisk, 2018-2019
// Author: Ulf Frisk, pcileech@frizk.net
//

#include "vmmdll.h"
#include "vmmproc.h"
#include "vmmwin.h"
#include "vmmwininit.h"
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
    pObProcess = VmmProcessCreateEntry(TRUE, 0, 0, ctxMain->cfg.paCR3, 0, "unknown_process", FALSE);
    VmmProcessCreateFinish();
    if(!pObProcess) {
        vmmprintfv("VmmProc: FAIL: Initialization of Process failed from user-defined CR3 %016llx.\n", ctxMain->cfg.paCR3);
        VmmInitializeMemoryModel(VMM_MEMORYMODEL_NA);
        return FALSE;
    }
    VmmTlbSpider(pObProcess);
    VmmOb_DECREF(pObProcess);
    ctxVmm->tpSystem = VMM_SYSTEM_UNKNOWN_X64;
    ctxVmm->kernel.paDTB = ctxMain->cfg.paCR3;
    return TRUE;
}

BOOL VmmProc_RefreshProcesses(_In_ BOOL fRefreshTotal)
{
    BOOL result;
    PVMM_PROCESS pObProcessSystem;
    // statistic count
    if(!fRefreshTotal) { InterlockedIncrement64(&ctxVmm->stat.cRefreshProcessPartial); }
    if(fRefreshTotal) { InterlockedIncrement64(&ctxVmm->stat.cRefreshProcessFull); }
    // Single user-defined X64 process
    if(fRefreshTotal) {
        if(ctxVmm->tpSystem == VMM_SYSTEM_UNKNOWN_X64) {
            VmmProcUserCR3TryInitialize64();
        }
    }
    // Windows OS
    if((ctxVmm->tpSystem == VMM_SYSTEM_WINDOWS_X64) || (ctxVmm->tpSystem == VMM_SYSTEM_WINDOWS_X86)) {
        vmmprintfvv_fn("ProcessRefresh: %s\n", (fRefreshTotal ? "Total" : "Partial"));
        pObProcessSystem = VmmProcessGet(4);
        if(!pObProcessSystem) {
            vmmprintf_fn("FAIL - SYSTEM PROCESS NOT FOUND - SHOULD NOT HAPPEN\n");
            return FALSE;
        }
        result = VmmWin_EnumerateEPROCESS(pObProcessSystem, fRefreshTotal);
        VmmOb_DECREF(pObProcessSystem);
    }
    return TRUE;
}

// Initial hard coded values that seems to be working nicely below. These values
// may be changed in config options or by editing files in the .status directory.

#define VMMPROC_UPDATERTHREAD_LOCAL_PERIOD                100
#define VMMPROC_UPDATERTHREAD_LOCAL_PHYSCACHE             (500 / VMMPROC_UPDATERTHREAD_LOCAL_PERIOD)                // 0.5s
#define VMMPROC_UPDATERTHREAD_LOCAL_TLB                   (5 * 1000 / VMMPROC_UPDATERTHREAD_LOCAL_PERIOD)           // 5s
#define VMMPROC_UPDATERTHREAD_LOCAL_PROC_REFRESHLIST      (5 * 1000 / VMMPROC_UPDATERTHREAD_LOCAL_PERIOD)           // 5s
#define VMMPROC_UPDATERTHREAD_LOCAL_PROC_REFRESHTOTAL     (15 * 1000 / VMMPROC_UPDATERTHREAD_LOCAL_PERIOD)          // 15s

#define VMMPROC_UPDATERTHREAD_REMOTE_PERIOD                100
#define VMMPROC_UPDATERTHREAD_REMOTE_PHYSCACHE             (15 * 1000 / VMMPROC_UPDATERTHREAD_REMOTE_PERIOD)        // 15s
#define VMMPROC_UPDATERTHREAD_REMOTE_TLB                   (3 * 60 * 1000 / VMMPROC_UPDATERTHREAD_REMOTE_PERIOD)    // 3m
#define VMMPROC_UPDATERTHREAD_REMOTE_PROC_REFRESHLIST      (15 * 1000 / VMMPROC_UPDATERTHREAD_REMOTE_PERIOD)        // 15s
#define VMMPROC_UPDATERTHREAD_REMOTE_PROC_REFRESHTOTAL     (3 * 60 * 1000 / VMMPROC_UPDATERTHREAD_REMOTE_PERIOD)    // 3m

DWORD VmmProcCacheUpdaterThread()
{
    QWORD i = 0, paMax;
    BOOL fPHYS, fTLB, fProcPartial, fProcTotal;
    vmmprintfv("VmmProc: Start periodic cache flushing.\n");
    if(ctxMain->dev.fRemote) {
        ctxVmm->ThreadProcCache.cMs_TickPeriod = VMMPROC_UPDATERTHREAD_REMOTE_PERIOD;
        ctxVmm->ThreadProcCache.cTick_Phys = VMMPROC_UPDATERTHREAD_REMOTE_PHYSCACHE;
        ctxVmm->ThreadProcCache.cTick_TLB = VMMPROC_UPDATERTHREAD_REMOTE_TLB;
        ctxVmm->ThreadProcCache.cTick_ProcPartial = VMMPROC_UPDATERTHREAD_REMOTE_PROC_REFRESHLIST;
        ctxVmm->ThreadProcCache.cTick_ProcTotal = VMMPROC_UPDATERTHREAD_REMOTE_PROC_REFRESHTOTAL;
    } else {
        ctxVmm->ThreadProcCache.cMs_TickPeriod = VMMPROC_UPDATERTHREAD_LOCAL_PERIOD;
        ctxVmm->ThreadProcCache.cTick_Phys = VMMPROC_UPDATERTHREAD_LOCAL_PHYSCACHE;
        ctxVmm->ThreadProcCache.cTick_TLB = VMMPROC_UPDATERTHREAD_LOCAL_TLB;
        ctxVmm->ThreadProcCache.cTick_ProcPartial = VMMPROC_UPDATERTHREAD_LOCAL_PROC_REFRESHLIST;
        ctxVmm->ThreadProcCache.cTick_ProcTotal = VMMPROC_UPDATERTHREAD_LOCAL_PROC_REFRESHTOTAL;
    }
    while(ctxVmm->ThreadProcCache.fEnabled) {
        Sleep(ctxVmm->ThreadProcCache.cMs_TickPeriod);
        i++;
        fTLB = !(i % ctxVmm->ThreadProcCache.cTick_TLB);
        fPHYS = !(i % ctxVmm->ThreadProcCache.cTick_Phys);
        fProcTotal = !(i % ctxVmm->ThreadProcCache.cTick_ProcTotal);
        fProcPartial = !(i % ctxVmm->ThreadProcCache.cTick_ProcPartial) && !fProcTotal;
        EnterCriticalSection(&ctxVmm->MasterLock);
        // PHYS / TLB cache clear
        if(fPHYS) {
            VmmCacheClear(VMM_CACHE_TAG_PHYS);
            InterlockedIncrement64(&ctxVmm->stat.cRefreshPhys);
        }
        if(fTLB) {
            VmmCacheClear(VMM_CACHE_TAG_TLB);
            InterlockedIncrement64(&ctxVmm->stat.cRefreshTlb);
        }
        // refresh proc list
        if(fProcPartial || fProcTotal) {
            if(!VmmProc_RefreshProcesses(fProcTotal)) {
                vmmprintf("VmmProc: Failed to refresh memory process file system - aborting.\n");
                LeaveCriticalSection(&ctxVmm->MasterLock);
                goto fail;
            }
            // update max physical address (if volatile).
            if(ctxMain->dev.fVolatileMaxAddress) {
                if(LeechCore_GetOption(LEECHCORE_OPT_MEMORYINFO_ADDR_MAX, &paMax) && (paMax > 0x01000000)) {
                    ctxMain->dev.paMax = paMax;
                }
            }
            // send notify
            if(fProcTotal) {
                PluginManager_Notify(VMMDLL_PLUGIN_EVENT_TOTALREFRESH, NULL, 0);
            }
        }
        LeaveCriticalSection(&ctxVmm->MasterLock);
    }
fail:
    vmmprintfv("VmmProc: Exit periodic cache flushing.\n");
    ctxVmm->ThreadProcCache.hThread = NULL;
    return 0;
}

VOID VmmProc_ModuleMapInitialize(_In_ PVMM_PROCESS pProcess)
{
    if((ctxVmm->tpSystem == VMM_SYSTEM_WINDOWS_X64) || (ctxVmm->tpSystem == VMM_SYSTEM_WINDOWS_X86)) {
        VmmTlbSpider(pProcess);
        VmmWin_ModuleMapInitialize(pProcess);
    }
}

_Success_(return)
BOOL VmmProc_ModuleMapGet(_In_ PVMM_PROCESS pProcess, _Out_ PVMMOB_MODULEMAP *ppObModuleMap)
{
    if(!pProcess->pObModuleMap) {
        VmmProc_ModuleMapInitialize(pProcess);
    }
    if(pProcess->pObModuleMap && pProcess->pObModuleMap->fValid) {
        *ppObModuleMap = VmmOb_INCREF(pProcess->pObModuleMap);
        return TRUE;
    }
    return FALSE;
}

_Success_(return)
BOOL VmmProc_ModuleMapGetSingleEntry(_In_ PVMM_PROCESS pProcess, _In_ LPSTR szModuleName, _Out_ PVMMOB_MODULEMAP *ppObModuleMap, _Out_ PVMM_MODULEMAP_ENTRY *ppModuleMapEntry)
{
    DWORD iModule;
    PVMMOB_MODULEMAP pObModuleMap = NULL;
    if(!VmmProc_ModuleMapGet(pProcess, &pObModuleMap)) { return FALSE; }
    for(iModule = 0; iModule < pObModuleMap->cMap; iModule++) {
        if(0 == strcmp(szModuleName, pObModuleMap->pMap[iModule].szName)) {
            *ppObModuleMap = pObModuleMap;
            *ppModuleMapEntry = pObModuleMap->pMap + iModule;
            return TRUE;
        }
    }
    VmmOb_DECREF(pObModuleMap);
    return FALSE;
}

VOID VmmProc_ScanTagsMemMap(_In_ PVMM_PROCESS pProcess)
{
    if((ctxVmm->tpSystem == VMM_SYSTEM_WINDOWS_X64) || (ctxVmm->tpSystem == VMM_SYSTEM_WINDOWS_X86)) {
        VmmWin_ScanTagsMemMap(pProcess);
    }
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
                "         Please specify PageDirectoryBase (DTB/CR3) in the -cr3 option if value \n" \
                "         is known. If unknown it may be recoverable with command 'identify'.    \n");
        }
    }
    // set up cache maintenance in the form of a separate worker thread in case
    // the backend is a writeable device (FPGA). If the underlying device isn't
    // volatile then there is no need to update! NB! Files are not considered
    // to be volatile.
    if(result && ctxMain->dev.fVolatile && !ctxMain->cfg.fDisableBackgroundRefresh) {
        ctxVmm->ThreadProcCache.fEnabled = TRUE;
        ctxVmm->ThreadProcCache.hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)VmmProcCacheUpdaterThread, ctxVmm, 0, NULL);
        if(!ctxVmm->ThreadProcCache.hThread) { ctxVmm->ThreadProcCache.fEnabled = FALSE; }
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

_Success_(return)
BOOL VmmProcPHYS_ScanForKernel(_Out_ PQWORD ppaPML4, _In_ QWORD paBase, _In_ QWORD paMax, _In_ LPSTR szDescription)
{
    QWORD o, i, paCurrent;
    PBYTE pbBuffer8M = NULL;
    PPAGE_STATISTICS pPageStat = NULL;
    LEECHCORE_PAGESTAT_MINIMAL PageStatMinimal;
    BOOL result;
    // initialize / allocate memory
    paCurrent = paBase;
    if(!(pbBuffer8M = LocalAlloc(0, 0x800000))) { goto fail; }
    if(!PageStatInitialize(&pPageStat, paCurrent, paMax, szDescription, FALSE, FALSE)) { goto fail; }
    PageStatMinimal.h = (HANDLE)pPageStat;
    PageStatMinimal.pfnPageStatUpdate = PageStatUpdate;
    // loop kmd-find
    for(; paCurrent < paMax; paCurrent += 0x00800000) {
        if(!LeechCore_ReadEx(paCurrent, pbBuffer8M, 0x00800000, 0, &PageStatMinimal)) { continue; }
        for(o = 0; o < 0x00800000; o += 0x1000) {
            // Scan for windows EPROCESS (to get DirectoryBase/PML4)
            for(i = 0; i < 0x1000; i += 8) {
                if(*(PQWORD)(pbBuffer8M + o + i) == 0x00006D6574737953) {
                    result = VmmProcPHYS_VerifyWindowsEPROCESS(pbBuffer8M, 0x00800000, o + i, ppaPML4);
                    if(result) {
                        pPageStat->szAction = "Windows System PageDirectoryBase/PML4 located";
                        PageStatClose(&pPageStat);
                        LocalFree(pbBuffer8M);
                        return TRUE;
                    }
                }
            }
        }
    }
fail:
    PageStatClose(&pPageStat);
    LocalFree(pbBuffer8M);
    *ppaPML4 = 0;
    return FALSE;
}

BOOL VmmProcIdentify()
{
    QWORD paPML4;
    BOOL result = FALSE;
    vmmprintf(
        "IDENTIFY: Scanning to identify target operating system and page directories...\n"
        "  Currently supported oprerating systems:\n"
        "     - Windows (64-bit).\n");
    if(ctxMain->dev.paMax > 0x100000000) {
        result = VmmProcPHYS_ScanForKernel(&paPML4, 0x100000000, ctxMain->dev.paMax, "Scanning 4GB+ to Identify (1/2) ...");
    }
    if(!result) {
        result = VmmProcPHYS_ScanForKernel(&paPML4, 0x01000000, 0x100000000, "Scanning 0-4GB to Identify (2/2) ...");
    }
    if(result) {
        vmmprintf("IDENTIFY: Succeeded: Windows System page directory base is located at: 0x%llx\n", paPML4);
        ctxMain->cfg.paCR3 = paPML4;
        return TRUE;
    }
    vmmprintf("IDENTIFY: Failed. No fully supported operating system detected.\n");
    return FALSE;
}
