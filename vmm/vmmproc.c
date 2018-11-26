// vfsproc.c : implementation of functions related to operating system and process parsing of virtual memory.
//
// (c) Ulf Frisk, 2018
// Author: Ulf Frisk, pcileech@frizk.net
//

#include "vmmproc.h"
#include "vmmproc_windows.h"
#include "device.h"
#include "statistics.h"
#include "util.h"

// ----------------------------------------------------------------------------
// GENERIC PROCESS RELATED FUNCTIONALITY BELOW:
// ----------------------------------------------------------------------------

/*
* see VmmProcPHYS_ScanWindowsKernel_LargePages for more information!
* Scan a page table hierarchy between virtual addresses between vaMin and vaMax
* for the first occurence of large 2MB pages. This is usually the ntoskrnl.exe
* if the OS is Windows. Ntoskrnl.exe is loaded between the virtual addresses:
* 0xFFFFF80000000000-0xFFFFF803FFFFFFFF
* -- ctxVmm,
* -- paTable = set to: physical address of PML4
* -- vaBase = set to 0
* -- vaMin = 0xFFFFF80000000000 (if windows kernel)
* -- vaMax = 0xFFFFF803FFFFFFFF (if windows kernel)
* -- cPML = set to 4
* -- pvaBase
* -- pcbSize
*/
VOID VmmProcPHYS_ScanWindowsKernel_LargePages_PageTableWalk(_In_ QWORD paTable, _In_ QWORD vaBase, _In_ QWORD vaMin, _In_ QWORD vaMax, _In_ BYTE cPML, _Inout_ PQWORD pvaBase, _Inout_ PQWORD pcbSize)
{
    const QWORD PML_REGION_SIZE[5] = { 0, 12, 21, 30, 39 };
    QWORD i, pte, *ptes, vaCurrent, vaSizeRegion;
    ptes = (PQWORD)VmmTlbGetPageTable(paTable, FALSE);
    if(!ptes) { return; }
    if(cPML == 4) {
        *pvaBase = 0;
        *pcbSize = 0;
        if(!VmmTlbPageTableVerify((PBYTE)ptes, paTable, TRUE)) { return; }
        vaBase = 0;
    }
    for(i = 0; i < 512; i++) {
        // address in range
        vaSizeRegion = 1ULL << PML_REGION_SIZE[cPML];
        vaCurrent = vaBase + (i << PML_REGION_SIZE[cPML]);
        vaCurrent |= (vaCurrent & 0x0000800000000000) ? 0xffff000000000000 : 0; // sign extend
        if(*pvaBase && (vaCurrent >(*pvaBase + *pcbSize))) { return; }
        if(vaCurrent < vaMin) { continue; }
        if(vaCurrent > vaMax) { return; }
        // check PTEs
        pte = ptes[i];
        if(!(pte & 0x01)) { continue; }     // NOT VALID
        if(cPML == 2) {
            if(!(pte & 0x80)) { continue; }
            if(!*pvaBase) { *pvaBase = vaCurrent; }
            *pcbSize += 0x200000;
            continue;
        } else {
            if(pte & 0x80) { continue; }    // PS = 1
            VmmProcPHYS_ScanWindowsKernel_LargePages_PageTableWalk(pte & 0x0000fffffffff000, vaCurrent, vaMin, vaMax, cPML - 1, pvaBase, pcbSize);
        }
    }
}

/*
* Sometimes the PageDirectoryBase (PML4) is known, but the kernel location may
* be unknown. This functions walks the page table in the area in which ntoskrnl
* is loaded (0xFFFFF80000000000-0xFFFFF803FFFFFFFF) looking for 2MB large pages
* If an area in 2MB pages are found it is scanned for the ntoskrnl.exe base.
* -- paPML4
* -- return = virtual address of ntoskrnl.exe base if successful, otherwise 0.
*/
QWORD VmmProcPHYS_ScanWindowsKernel_LargePages(_In_ QWORD paPML4)
{
    PBYTE pbBuffer;
    QWORD p, o, vaCurrentMin, vaBase, cbSize;
    PVMM_PROCESS pSystemProcess = NULL;
    BOOL fINITKDBG, fPOOLCODE;
    vaCurrentMin = 0xFFFFF80000000000;     // base of windows kernel possible location
    while(TRUE) {
        VmmProcPHYS_ScanWindowsKernel_LargePages_PageTableWalk(paPML4, 0, vaCurrentMin, 0xFFFFF803FFFFFFFF, 4, &vaBase, &cbSize);
        if(!vaBase) { return 0; }
        vaCurrentMin = vaBase + cbSize;
        if(cbSize <= 0x00400000) { continue; }  // too small
        if(cbSize >= 0x01000000) { continue; }  // too big
        if(!pSystemProcess) {
            pSystemProcess = VmmProcessCreateEntry(4, 0, paPML4, 0, "System", FALSE, FALSE);
            if(!pSystemProcess) { return 0; }
            VmmProcessCreateFinish();
        }
        // try locate ntoskrnl.exe base inside suggested area
        pbBuffer = (PBYTE)LocalAlloc(0, cbSize);
        if(!pbBuffer) { return 0; }
        VmmReadEx(pSystemProcess, vaBase, pbBuffer, (DWORD)cbSize, NULL, 0);
        for(p = 0; p < cbSize; p += 0x1000) {
            if(*(PWORD)(pbBuffer + p) != 0x5a4d) { continue; }
            // check if module header contains INITKDBG and POOLCODE
            fINITKDBG = FALSE;
            fPOOLCODE = FALSE;
            for(o = 0; o < 0x1000; o += 8) {
                if(*(PQWORD)(pbBuffer + p + o) == 0x4742444B54494E49) { // INITKDBG
                    fINITKDBG = TRUE;
                }
                if(*(PQWORD)(pbBuffer + p + o) == 0x45444F434C4F4F50) { // POOLCODE
                    fPOOLCODE = TRUE;
                }
                if(fINITKDBG && fPOOLCODE) {
                    LocalFree(pbBuffer);
                    return vaBase + p;
                }
            }
        }
        LocalFree(pbBuffer);
    }
}

// ----------------------------------------------------------------------------
// GENERIC PROCESS RELATED FUNCTIONALITY BELOW:
// ----------------------------------------------------------------------------

/*
* Try initialize from user supplied CR3/PML4 supplied in parameter at startup.
* -- ctx
* -- return
*/
BOOL VmmProcUserCR3TryInitialize()
{
    PVMM_PROCESS pProcess;
    pProcess = VmmProcessCreateEntry(0, 0, ctxMain->cfg.paCR3, 0, "unknown_process", FALSE, TRUE);
    VmmProcessCreateFinish();
    if(!pProcess) {
        vmmprintfv("VmmProc: FAIL: Initialization of Process failed from user-defined CR3 %016llx. #4.\n", ctxMain->cfg.paCR3);
        return FALSE;
    }
    VmmTlbSpider(pProcess->paPML4, FALSE);
    ctxVmm->fTargetSystem = VMM_TARGET_UNKNOWN_X64;
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
    PVMM_PROCESS pSystemProcess;
    QWORD paSystemPML4, vaSystemEPROCESS;
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
            ctxVmm->stat.cRefreshProcessPartial++;
            // Windows OS
            if(ctxVmm->fTargetSystem & VMM_TARGET_WINDOWS_X64) {
                pSystemProcess = VmmProcessGet(4);
                if(pSystemProcess) {
                    VmmProcWindows_EnumerateEPROCESS(pSystemProcess);
                    vmmprintfvv("VmmProc: vmmproc.c!VmmProcCacheUpdaterThread FlushProcessList\n");
                }
            }
        }
        // total refresh of entire proc cache
        if(fProcTotal) {
            ctxVmm->stat.cRefreshProcessFull++;
            // Windows OS
            if(ctxVmm->fTargetSystem & VMM_TARGET_WINDOWS_X64) {
                pSystemProcess = VmmProcessGet(4);
                if(pSystemProcess) {
                    paSystemPML4 = pSystemProcess->paPML4;
                    vaSystemEPROCESS = pSystemProcess->os.win.vaEPROCESS;
                    // spider TLB and set up initial system process and enumerate EPROCESS
                    VmmTlbSpider(paSystemPML4, FALSE);
                    pSystemProcess = VmmProcessCreateEntry(4, 0, paSystemPML4, 0, "System", FALSE, TRUE);
                    if(!pSystemProcess) {
                        vmmprintf("VmmProc: Failed to refresh memory process file system - aborting.\n");
                        VmmProcessCreateFinish();
                        ctxVmm->ThreadProcCache.fEnabled = FALSE;
                        LeaveCriticalSection(&ctxVmm->MasterLock);
                        goto fail;
                    }
                    pSystemProcess->os.win.vaEPROCESS = vaSystemEPROCESS;
                    VmmProcWindows_EnumerateEPROCESS(pSystemProcess);
                    vmmprintfvv("VmmProc: vmmproc.c!VmmProcCacheUpdaterThread FlushProcessListAndBuffers\n");
                }
            }
            // Single user-defined X64 process
            if(ctxVmm->fTargetSystem & VMM_TARGET_UNKNOWN_X64) {
                VmmProcessCreateTable();
                VmmProcUserCR3TryInitialize(ctxVmm);
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
    if(ctxVmm->fTargetSystem & VMM_TARGET_WINDOWS_X64) {
        VmmProcWindows_InitializeModuleNames(pProcess);
    }
}

BOOL VmmProcInitialize()
{
    BOOL result;
    QWORD vaKernelBase;
    if(!VmmInitialize()) { return FALSE; }
    // user supplied a CR3 - use it!
    if(ctxMain->cfg.paCR3) {
        // if VmmProcPHYS_ScanWindowsKernel_LargePages returns a value this is a
        // Windows system - initialize it, otherwise initialize the generic x64
        // single process more basic mode.
        result = FALSE;
        vaKernelBase = VmmProcPHYS_ScanWindowsKernel_LargePages(ctxMain->cfg.paCR3);
        if(vaKernelBase) {
            result = VmmProcWindows_TryInitialize(ctxMain->cfg.paCR3, vaKernelBase);
        }
        if(!vaKernelBase) {
            result = VmmProcUserCR3TryInitialize(ctxVmm);
            if(!result) {
                VmmInitialize(); // re-initialize VMM to clear state
            }
        }
        if(!result) {
            result = VmmProcUserCR3TryInitialize(ctxVmm);
        }
    } else {
        // no page directory was found, so try initialize it by looking if the
        // "low stub" exists on a Windows sytem and use it. Otherwise fail.
        result = VmmProcWindows_TryInitialize(0, 0);
        if(!result) {
            vmmprintf(
                "VmmProc: Unable to auto-identify operating system for PROC file system mount.   \n" \
                "         Please specify PageDirectoryBase (CR3/PML4) in the -cr3 option if value\n" \
                "         is known. If unknown it may be recoverable with command 'identify'.    \n");
        }
    }
    // set up cache mainenance in the form of a separate worker thread in case
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
    PAGE_STATISTICS pageStat;
    PBYTE pbBuffer8M;
    BOOL result;
    // initialize / allocate memory
    if(!(pbBuffer8M = LocalAlloc(0, 0x800000))) { return FALSE; }
    ZeroMemory(&pageStat, sizeof(PAGE_STATISTICS));
    paCurrent = paBase;
    PageStatInitialize(&pageStat, paCurrent, paMax, szDescription, FALSE, FALSE);
    // loop kmd-find
    for(; paCurrent < paMax; paCurrent += 0x00800000) {
        if(!DeviceReadMEMEx(paCurrent, pbBuffer8M, 0x00800000, &pageStat)) { continue; }
        for(o = 0; o < 0x00800000; o += 0x1000) {
            // Scan for windows EPROCESS (to get DirectoryBase/PML4)
            for(i = 0; i < 0x1000; i += 8) {
                if(*(PQWORD)(pbBuffer8M + o + i) == 0x00006D6574737953) {
                    result = VmmProcPHYS_VerifyWindowsEPROCESS(pbBuffer8M, 0x00800000, o + i, ppaPML4);
                    if(result) {
                        pageStat.szAction = "Windows System PageDirectoryBase/PML4 located";
                        LocalFree(pbBuffer8M);
                        PageStatClose(&pageStat);
                        return TRUE;
                    }
                }
            }
        }
    }
    LocalFree(pbBuffer8M);
    PageStatClose(&pageStat);
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
