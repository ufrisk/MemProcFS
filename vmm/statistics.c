// statistics.c : implementation of statistics related functionality.
//
// (c) Ulf Frisk, 2016-2019
// Author: Ulf Frisk, pcileech@frizk.net
//
#include "statistics.h"
#include "vmm.h"

// ----------------------------------------------------------------------------
// PAGE READ STATISTICAL FUNCTIONALITY BELOW:
// ----------------------------------------------------------------------------

VOID _PageStatPrintMemMap(_Inout_ PPAGE_STATISTICS ps)
{
    BOOL fIsLinePrinted = FALSE;
    QWORD i, qwAddrBase, qwAddrEnd;
    if(!ps->i.fIsFirstPrintCompleted) {
        vmmprintf(" Memory Map:                                     \n START              END               #PAGES   \n");
    }
    if(!ps->i.MemMapIdx && !ps->i.MemMap[0]) {
        vmmprintf("                                                 \n                                                 \n");
        return;
    }
    if(ps->i.MemMapPrintCommitIdx >= PAGE_STATISTICS_MEM_MAP_MAX_ENTRY - 4) {
        vmmprintf(" Maximum number of memory map entries reached.   \n                                                 \n");
        return;
    }
    qwAddrBase = ps->i.qwAddrBase + ps->i.MemMapPrintCommitPages * 0x1000;
    for(i = ps->i.MemMapPrintCommitIdx; i < PAGE_STATISTICS_MEM_MAP_MAX_ENTRY; i++) {
        if(!ps->i.MemMap[i] && i == 0) {
            continue;
        }
        if(!ps->i.MemMap[i] || (i == PAGE_STATISTICS_MEM_MAP_MAX_ENTRY - 1)) {
            break;
        }
        qwAddrEnd = qwAddrBase + 0x1000 * (QWORD)ps->i.MemMap[i];
        if((i % 2) == 0) {
            fIsLinePrinted = TRUE;
            vmmprintf(
                " %016llx - %016llx  %08x   \n",
                qwAddrBase,
                qwAddrEnd - 1,
                ps->i.MemMap[i]);
            if(i >= ps->i.MemMapPrintCommitIdx + 2) {
                ps->i.MemMapPrintCommitPages += ps->i.MemMap[ps->i.MemMapPrintCommitIdx++];
                ps->i.MemMapPrintCommitPages += ps->i.MemMap[ps->i.MemMapPrintCommitIdx++];

            }
        }
        qwAddrBase = qwAddrEnd;
    }
    if(!fIsLinePrinted) { // print extra line for formatting reasons.
        vmmprintf(" (No memory successfully read yet)               \n");
    }
    vmmprintf("                                                 \n");
}

VOID _PageStatShowUpdate(_Inout_ PPAGE_STATISTICS ps)
{
    if(0 == ps->cPageTotal) { return; }
    QWORD qwPercentTotal = ((ps->cPageSuccess + ps->cPageFail) * 100) / ps->cPageTotal;
    QWORD qwPercentSuccess = (ps->cPageSuccess * 200 + 1) / (ps->cPageTotal * 2);
    QWORD qwPercentFail = (ps->cPageFail * 200 + 1) / (ps->cPageTotal * 2);
    QWORD qwTickCountElapsed = GetTickCount64() - ps->i.qwTickCountStart;
    QWORD qwSpeed = ((ps->cPageSuccess + ps->cPageFail) * 4) / (1 + (qwTickCountElapsed / 1000));
    HANDLE hConsole;
    CONSOLE_SCREEN_BUFFER_INFO consoleInfo;
    BOOL isMBs = qwSpeed >= 1024;
    if(ps->i.fIsFirstPrintCompleted) {
#ifdef WIN32
        hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
        GetConsoleScreenBufferInfo(hConsole, &consoleInfo);
        consoleInfo.dwCursorPosition.Y -= ps->i.fMemMap ? 9 : 7;
        SetConsoleCursorPosition(hConsole, consoleInfo.dwCursorPosition);
#endif /* WIN32 */
#if defined(LINUX) || defined(ANDROID)
        vmmprintf(ps->i.fMemMap ? "\033[9A" : "\033[7A"); // move cursor up 7/9 positions
#endif /* LINUX || ANDROID */
    }
    if(ps->i.fMemMap) {
        _PageStatPrintMemMap(ps);
    }
    if(ps->cPageTotal < 0x0000000fffffffff) {
        vmmprintf(
            " Current Action: %s                             \n" \
            " Access Mode:    %s                             \n" \
            " Progress:       %llu / %llu (%llu%%)           \n" \
            " Speed:          %llu %s                        \n" \
            " Address:        0x%016llX                      \n" \
            " Pages read:     %llu / %llu (%llu%%)           \n" \
            " Pages failed:   %llu (%llu%%)                  \n",
            ps->szAction,
            ps->fKMD ? "KMD (kernel module assisted DMA)" : "DMA (hardware only)             ",
            (ps->cPageSuccess + ps->cPageFail) / 256,
            ps->cPageTotal / 256,
            qwPercentTotal,
            (isMBs ? qwSpeed >> 10 : qwSpeed),
            (isMBs ? "MB/s" : "kB/s"),
            ps->qwAddr,
            ps->cPageSuccess,
            ps->cPageTotal,
            qwPercentSuccess,
            ps->cPageFail,
            qwPercentFail);
    } else {
        vmmprintf(
            " Current Action: %s                             \n" \
            " Access Mode:    %s                             \n" \
            " Progress:       %llu / (unknown)               \n" \
            " Speed:          %llu %s                        \n" \
            " Address:        0x%016llX                      \n" \
            " Pages read:     %llu                           \n" \
            " Pages failed:   %llu                           \n",
            ps->szAction,
            ps->fKMD ? "KMD (kernel module assisted DMA)" : "DMA (hardware only)             ",
            (ps->cPageSuccess + ps->cPageFail) / 256,
            (isMBs ? qwSpeed >> 10 : qwSpeed),
            (isMBs ? "MB/s" : "kB/s"),
            ps->qwAddr,
            ps->cPageSuccess,
            ps->cPageFail);
    }
    ps->i.fIsFirstPrintCompleted = TRUE;
}

VOID _PageStatThreadLoop(_In_ PPAGE_STATISTICS ps)
{
    while(!ps->i.fThreadExit) {
        Sleep(100);
        if(ps->i.fUpdate) {
            ps->i.fUpdate = FALSE;
            _PageStatShowUpdate(ps);
        }
    }
    ExitThread(0);
}

VOID PageStatClose(_Inout_ PPAGE_STATISTICS ps)
{
    BOOL status;
    DWORD dwExitCode;
    ps->i.fUpdate = TRUE;
    ps->i.fThreadExit = TRUE;
    while((status = GetExitCodeThread(ps->i.hThread, &dwExitCode)) && STILL_ACTIVE == dwExitCode) {
        SwitchToThread();
    }
    if(!status) {
        Sleep(200);
    }
}

VOID PageStatInitialize(_Inout_ PPAGE_STATISTICS ps, _In_ QWORD qwAddrBase, _In_ QWORD qwAddrMax, _In_ LPSTR szAction, _In_ BOOL fKMD, _In_ BOOL fMemMap)
{
    memset(ps, 0, sizeof(PAGE_STATISTICS));
    ps->qwAddr = qwAddrBase;
    ps->cPageTotal = (qwAddrMax - qwAddrBase + 1) / 4096;
    ps->szAction = szAction;
    ps->fKMD = fKMD;
    ps->i.fMemMap = fMemMap;
    ps->i.qwAddrBase = qwAddrBase;
    ps->i.qwTickCountStart = GetTickCount64();
    ps->i.hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)_PageStatThreadLoop, ps, 0, NULL);
}

VOID PageStatUpdate(_Inout_opt_ PPAGE_STATISTICS ps, _In_ QWORD qwAddr, _In_ QWORD cPageSuccessAdd, _In_ QWORD cPageFailAdd)
{
    if(!ps) { return; }
    ps->qwAddr = qwAddr;
    ps->cPageSuccess += cPageSuccessAdd;
    ps->cPageFail += cPageFailAdd;
    // add to memory map, even == success, odd = fail.
    if(ps->i.MemMapIdx < PAGE_STATISTICS_MEM_MAP_MAX_ENTRY - 2) {
        if(cPageSuccessAdd) {
            if(ps->i.MemMapIdx % 2 == 1) {
                ps->i.MemMapIdx++;
            }
            ps->i.MemMap[ps->i.MemMapIdx] += (DWORD)cPageSuccessAdd;
        }
        if(cPageFailAdd) {
            if(ps->i.MemMapIdx % 2 == 0) {
                ps->i.MemMapIdx++;
            }
            ps->i.MemMap[ps->i.MemMapIdx] += (DWORD)cPageFailAdd;
        }
    }
    ps->i.fUpdate = TRUE;
}

// ----------------------------------------------------------------------------
// FUNCTION CALL STATISTICAL FUNCTIONALITY BELOW:
// ----------------------------------------------------------------------------

const LPSTR NAMES_VMM_STATISTICS_CALL[] = {
    "INITIALIZE",
    "VMMDLL_VfsList",
    "VMMDLL_VfsRead",
    "VMMDLL_VfsWrite",
    "VMMDLL_VfsInitializePlugins",
    "VMMDLL_MemReadEx",
    "VMMDLL_MemWrite",
    "VMMDLL_MemVirt2Phys",
    "VMMDLL_PidList",
    "VMMDLL_PidGetFromName",
    "VMMDLL_ProcessGetInformation",
    "VMMDLL_ProcessGetMemoryMap",
    "VMMDLL_ProcessGetMemoryMapEntry",
    "VMMDLL_ProcessGetModuleMap",
    "VMMDLL_ProcessGetModuleFromName",
    "VMMDLL_ProcessGetDirectories",
    "VMMDLL_ProcessGetSections",
    "VMMDLL_ProcessGetEAT",
    "VMMDLL_ProcessGetIAT",
    "PluginManager_List",
    "PluginManager_Read",
    "PluginManager_Write",
    "PluginManager_Notify"
};

typedef struct tdCALLSTAT {
    QWORD c;
    QWORD tm;
} CALLSTAT, *PCALLSTAT;

VOID Statistics_CallSetEnabled(_In_ BOOL fEnabled)
{
    if(fEnabled && ctxMain->pvStatistics) { return; }
    if(!fEnabled && !ctxMain->pvStatistics) { return; }
    if(fEnabled) {
        ctxMain->pvStatistics = LocalAlloc(LMEM_ZEROINIT, (STATISTICS_ID_MAX + 1) * sizeof(CALLSTAT));
    } else {
        LocalFree(ctxMain->pvStatistics);
        ctxMain->pvStatistics = NULL;
    }
}

BOOL Statistics_CallGetEnabled()
{
    return ctxMain->pvStatistics != NULL;
}

QWORD Statistics_CallStart()
{
    QWORD tmNow;
    if(!ctxMain->pvStatistics) { return 0; }
    QueryPerformanceCounter((PLARGE_INTEGER)&tmNow);
    return tmNow;
}

VOID Statistics_CallEnd(_In_ DWORD fId, QWORD tmCallStart)
{
    QWORD tmNow;
    PCALLSTAT pStat;
    if(!ctxMain->pvStatistics) { return; }
    if(fId > STATISTICS_ID_MAX) { return; }
    if(tmCallStart == 0) { return; }
    pStat = ((PCALLSTAT)ctxMain->pvStatistics) + fId;
    InterlockedIncrement64(&pStat->c);
    QueryPerformanceCounter((PLARGE_INTEGER)&tmNow);
    InterlockedAdd64(&pStat->tm, tmNow - tmCallStart);
}

VOID Statistics_CallToString(_In_opt_ PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcb)
{
    BOOL result;
    QWORD qwFreq, uS;
    DWORD i, o = 0;
    PCALLSTAT pStat;
    LEECHCORE_STATISTICS LeechCoreStatistics = { 0 };
    DWORD cbLeechCoreStatistics = sizeof(LEECHCORE_STATISTICS);
    if(!pb) { 
        *pcb = 71 * (STATISTICS_ID_MAX + LEECHCORE_STATISTICS_ID_MAX + 6);
        return;
    }
    QueryPerformanceFrequency((PLARGE_INTEGER)&qwFreq);
    o += snprintf(
        pb + o,
        cb - o,
        "FUNCTION CALL STATISTICS:                                             \n" \
        "VALUES IN DECIMAL, TIME IN MICROSECONDS uS, STATISTICS = %s     \n" \
        "FUNCTION CALL NAME                   CALLS  TIME AVG        TIME TOTAL\n" \
        "======================================================================\n",
        ctxMain->pvStatistics ? "ENABLED " : "DISABLED"
        );
    // statistics
    for(i = 0; i <= STATISTICS_ID_MAX; i++) {
        if(ctxMain->pvStatistics) {
            pStat = ((PCALLSTAT)ctxMain->pvStatistics) + i;
            if(pStat->c) {
                uS = (pStat->tm * 1000000ULL) / qwFreq;
                o += snprintf(
                    pb + o,
                    cb - o,
                    "%-32.32s  %8i  %8i  %16lli\n",
                    NAMES_VMM_STATISTICS_CALL[i],
                    (DWORD)pStat->c,
                    (DWORD)(uS / pStat->c),
                    uS
                );
                continue;
            }
        }
        o += snprintf(
            pb + o,
            cb - o,
            "%-32.32s  %8i  %8i  %16lli\n",
            NAMES_VMM_STATISTICS_CALL[i],
            0, 0, 0ULL);
    }
    // leechcore statistics
    result = LeechCore_CommandData(LEECHCORE_COMMANDDATA_STATISTICS_GET, NULL, 0, (PBYTE)&LeechCoreStatistics, cbLeechCoreStatistics, &cbLeechCoreStatistics);
    if(result && (LeechCoreStatistics.magic == LEECHCORE_STATISTICS_MAGIC) && (LeechCoreStatistics.version == LEECHCORE_STATISTICS_VERSION) && LeechCoreStatistics.qwFreq) {
        for(i = 0; i <= LEECHCORE_STATISTICS_ID_MAX; i++) {
            if(LeechCoreStatistics.Call[i].c) {
                uS = (LeechCoreStatistics.Call[i].tm * 1000000ULL) / LeechCoreStatistics.qwFreq;
                o += snprintf(
                    pb + o,
                    cb - o,
                    "%-32.32s  %8i  %8i  %16lli\n",
                    LEECHCORE_STATISTICS_NAME[i],
                    (DWORD)LeechCoreStatistics.Call[i].c,
                    (DWORD)(uS / LeechCoreStatistics.Call[i].c),
                    uS
                );
            } else {
                o += snprintf(
                    pb + o,
                    cb - o,
                    "%-32.32s  %8i  %8i  %16lli\n",
                    LEECHCORE_STATISTICS_NAME[i],
                    0, 0, 0ULL);
            }
        }
    }
    *pcb = o;
}
