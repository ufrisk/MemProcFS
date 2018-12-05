// vfsproc.c : implementation of functions related to operating system and process parsing of virtual memory.
//
// (c) Ulf Frisk, 2018
// Author: Ulf Frisk, pcileech@frizk.net
//

#include "vmmproc.h"
#include "vmmwin.h"
#include "vmmwininit.h"
#include "device.h"
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
    PVMM_PROCESS pProcess;
    VmmInitializeMemoryModel(VMM_MEMORYMODEL_X64);
    pProcess = VmmProcessCreateEntry(0, 0, ctxMain->cfg.paCR3, 0, "unknown_process", FALSE, TRUE);
    VmmProcessCreateFinish();
    if(!pProcess) {
        vmmprintfv("VmmProc: FAIL: Initialization of Process failed from user-defined CR3 %016llx.\n", ctxMain->cfg.paCR3);
        VmmInitializeMemoryModel(VMM_MEMORYMODEL_NA);
        return FALSE;
    }
    VmmTlbSpider(pProcess->paDTB, FALSE);
    ctxVmm->tpSystem = VMM_SYSTEM_UNKNOWN_X64;
    ctxVmm->kernel.paDTB = ctxMain->cfg.paCR3;
    return TRUE;
}

BOOL VmmProc_Refresh(_In_ BOOL fProcessList, _In_ BOOL fProcessFull)
{
    PVMM_PROCESS pSystemProcess;
    QWORD paSystemPML4, vaSystemEPROCESS;
    if(fProcessList) {
        ctxVmm->stat.cRefreshProcessPartial++;
        // Windows OS
        if((ctxVmm->tpSystem == VMM_SYSTEM_WINDOWS_X64) || (ctxVmm->tpSystem == VMM_SYSTEM_WINDOWS_X86)) {
            pSystemProcess = VmmProcessGet(4);
            if(pSystemProcess) {
                VmmWin_EnumerateEPROCESS(pSystemProcess);
                vmmprintfvv("VmmProc: vmmproc.c!VmmProcCacheUpdaterThread FlushProcessList\n");
            }
        }
    }
    if(fProcessFull) {
        ctxVmm->stat.cRefreshProcessFull++;
        // Windows OS
        if((ctxVmm->tpSystem == VMM_SYSTEM_WINDOWS_X64) || (ctxVmm->tpSystem == VMM_SYSTEM_WINDOWS_X86)) {
            pSystemProcess = VmmProcessGet(4);
            if(pSystemProcess) {
                paSystemPML4 = pSystemProcess->paDTB;
                vaSystemEPROCESS = pSystemProcess->os.win.vaEPROCESS;
                // spider TLB and set up initial system process and enumerate EPROCESS
                VmmTlbSpider(paSystemPML4, FALSE);
                pSystemProcess = VmmProcessCreateEntry(4, 0, paSystemPML4, 0, "System", FALSE, TRUE);
                if(!pSystemProcess) { return FALSE; }
                pSystemProcess->os.win.vaEPROCESS = vaSystemEPROCESS;
                VmmWin_EnumerateEPROCESS(pSystemProcess);
                vmmprintfvv("vmmproc.c!VmmProc_Refresh FlushProcessListAndBuffers\n");
            }
        }
        // Single user-defined X64 process
        if(ctxVmm->tpSystem == VMM_SYSTEM_UNKNOWN_X64) {
            VmmProcessCreateTable();
            VmmProcUserCR3TryInitialize64();
        }
    }
    return TRUE;
}

#define VMMPROC_UPDATERTHREAD_PERIOD                100
#define VMMPROC_UPDATERTHREAD_PHYSCACHE             (500 / VMMPROC_UPDATERTHREAD_PERIOD)            // 0.5s
#define VMMPROC_UPDATERTHREAD_TLB                   (5 * 1000 / VMMPROC_UPDATERTHREAD_PERIOD)       // 5s
#define VMMPROC_UPDATERTHREAD_PROC_REFRESHLIST      (5 * 1000 / VMMPROC_UPDATERTHREAD_PERIOD)       // 5s
#define VMMPROC_UPDATERTHREAD_PROC_REFRESHTOTAL     (15 * 1000 / VMMPROC_UPDATERTHREAD_PERIOD)      // 15s

DWORD VmmProcCacheUpdaterThread()
{
    QWORD i = 0;
    BOOL fPHYS, fTLB, fProcList, fProcTotal;
    vmmprintfv("VmmProc: Start periodic cache flushing.\n");
    ctxVmm->ThreadProcCache.cMs_TickPeriod = VMMPROC_UPDATERTHREAD_PERIOD;
    ctxVmm->ThreadProcCache.cTick_Phys = VMMPROC_UPDATERTHREAD_PHYSCACHE;
    ctxVmm->ThreadProcCache.cTick_TLB = VMMPROC_UPDATERTHREAD_TLB;
    ctxVmm->ThreadProcCache.cTick_ProcPartial = VMMPROC_UPDATERTHREAD_PROC_REFRESHLIST;
    ctxVmm->ThreadProcCache.cTick_ProcTotal = VMMPROC_UPDATERTHREAD_PROC_REFRESHTOTAL;
    while(ctxVmm->ThreadProcCache.fEnabled) {
        Sleep(ctxVmm->ThreadProcCache.cMs_TickPeriod);
        i++;
        fTLB = !(i % ctxVmm->ThreadProcCache.cTick_TLB);
        fPHYS = !(i % ctxVmm->ThreadProcCache.cTick_Phys);
        fProcTotal = !(i % ctxVmm->ThreadProcCache.cTick_ProcTotal);
        fProcList = !(i % ctxVmm->ThreadProcCache.cTick_ProcPartial) && !fProcTotal;
        EnterCriticalSection(&ctxVmm->MasterLock);
        // PHYS / TLB cache clear
        if(fPHYS || fTLB) {
            VmmCacheClear(fTLB, fPHYS);
            ctxVmm->stat.cRefreshPhys += fPHYS ? 1 : 0;
            ctxVmm->stat.cRefreshTlb += fTLB ? 1 : 0;
        }
        // refresh proc list
        if(fProcList) {
            VmmProc_Refresh(TRUE, FALSE);
        }
        // total refresh of entire proc cache
        if(fProcTotal) {
            if(!VmmProc_Refresh(FALSE, TRUE)) {
                vmmprintf("VmmProc: Failed to refresh memory process file system - aborting.\n");
                VmmProcessCreateFinish();
                ctxVmm->ThreadProcCache.fEnabled = FALSE;
                LeaveCriticalSection(&ctxVmm->MasterLock);
                goto fail;
            }
        }
        LeaveCriticalSection(&ctxVmm->MasterLock);
    }
fail:
    vmmprintfv("VmmProc: Exit periodic cache flushing.\n");
    ctxVmm->ThreadProcCache.hThread = NULL;
    return 0;
}

VOID VmmProc_InitializeModuleNames(_In_ PVMM_PROCESS pProcess)
{
    if((ctxVmm->tpSystem == VMM_SYSTEM_WINDOWS_X64) || (ctxVmm->tpSystem == VMM_SYSTEM_WINDOWS_X86)) {
        VmmWin_InitializeModuleNames(pProcess);
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
    // the backend is a writeable device (FPGA). File devices are read-only so
    // far so full caching is enabled since they are considered to be read-only.
    if(result && !ctxVmm->fReadOnly) {
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
    BOOL result;
    // initialize / allocate memory
    pbBuffer8M = LocalAlloc(0, 0x800000);
    pPageStat = (PPAGE_STATISTICS)LocalAlloc(LMEM_ZEROINIT, sizeof(PAGE_STATISTICS));
    if(!pbBuffer8M || !pPageStat) { goto fail; }
    paCurrent = paBase;
    PageStatInitialize(pPageStat, paCurrent, paMax, szDescription, FALSE, FALSE);
    // loop kmd-find
    for(; paCurrent < paMax; paCurrent += 0x00800000) {
        if(!DeviceReadMEMEx(paCurrent, pbBuffer8M, 0x00800000, pPageStat)) { continue; }
        for(o = 0; o < 0x00800000; o += 0x1000) {
            // Scan for windows EPROCESS (to get DirectoryBase/PML4)
            for(i = 0; i < 0x1000; i += 8) {
                if(*(PQWORD)(pbBuffer8M + o + i) == 0x00006D6574737953) {
                    result = VmmProcPHYS_VerifyWindowsEPROCESS(pbBuffer8M, 0x00800000, o + i, ppaPML4);
                    if(result) {
                        pPageStat->szAction = "Windows System PageDirectoryBase/PML4 located";
                        PageStatClose(pPageStat);
                        LocalFree(pPageStat);
                        LocalFree(pbBuffer8M);
                        return TRUE;
                    }
                }
            }
        }
    }
fail:
    if(pPageStat) { PageStatClose(pPageStat); }
    LocalFree(pPageStat);
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
    if(ctxMain->cfg.paAddrMax > 0x100000000) {
        result = VmmProcPHYS_ScanForKernel(&paPML4, 0x100000000, ctxMain->cfg.paAddrMax, "Scanning 4GB+ to Identify (1/2) ...");
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
