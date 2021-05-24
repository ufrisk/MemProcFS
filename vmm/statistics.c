// statistics.c : implementation of statistics related functionality.
//
// (c) Ulf Frisk, 2016-2021
// Author: Ulf Frisk, pcileech@frizk.net
//
#include "statistics.h"
#include "vmm.h"
#include "util.h"

// ----------------------------------------------------------------------------
// PAGE READ STATISTICAL FUNCTIONALITY BELOW:
// ----------------------------------------------------------------------------

VOID _PageStatPrintMemMap(_Inout_ PPAGE_STATISTICS ps)
{
    QWORD i, qwAddrEnd;
    if(!ps->i.fIsFirstPrintCompleted) {
        printf(" Memory Map:                                     \n START              END               #PAGES   \n");
    }
    if(!ps->i.MemMapIdx) {
        printf("                                                 \n                                                 \n");
        return;
    }
    if(ps->i.MemMapIdx >= PAGE_STATISTICS_MEM_MAP_MAX_ENTRY - 2) {
        printf(" Maximum number of memory map entries reached.   \n                                                 \n");
        return;
    }
    for(i = max(1, ps->i.MemMapPrintIdx); i <= ps->i.MemMapIdx; i++) {
        if(!ps->i.MemMap[i].cPages) {
            break;
        }
        qwAddrEnd = ps->i.MemMap[i].qwAddrBase + ((QWORD)ps->i.MemMap[i].cPages << 12);
        printf(
            " %016llx - %016llx  %08x   \n",
            ps->i.MemMap[i].qwAddrBase,
            qwAddrEnd - 1,
            ps->i.MemMap[i].cPages);
    }
    ps->i.MemMapPrintIdx = ps->i.MemMapIdx;
    if(!ps->i.MemMap[1].cPages) { // print extra line for formatting reasons.
        printf(" (No memory successfully read yet)               \n");
    }
    printf("                                                 \n");
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
    BOOL isMBs = qwSpeed >= 2048;
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
            ps->fKMD ? "KMD (kernel module assisted DMA)" : "Normal                          ",
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
            ps->fKMD ? "KMD (kernel module assisted DMA)" : "Normal                          ",
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

VOID PageStatClose(_In_opt_ PPAGE_STATISTICS *ppPageStat)
{
    BOOL status;
    DWORD dwExitCode;
    PPAGE_STATISTICS ps;
    if(!ppPageStat || !*ppPageStat) { return; }
    ps = *ppPageStat;
    ps->i.fUpdate = TRUE;
    ps->i.fThreadExit = TRUE;
    while((status = GetExitCodeThread(ps->i.hThread, &dwExitCode)) && STILL_ACTIVE == dwExitCode) {
        SwitchToThread();
    }
    if(!status) {
        Sleep(200);
    }
    if(ps->i.hThread) { CloseHandle(ps->i.hThread); }
    LocalFree(*ppPageStat);
    *ppPageStat = NULL;
}

_Success_(return)
BOOL PageStatInitialize(_Out_ PPAGE_STATISTICS *ppPageStat, _In_ QWORD qwAddrBase, _In_ QWORD qwAddrMax, _In_ LPSTR szAction, _In_ BOOL fKMD, _In_ BOOL fMemMap)
{
    PPAGE_STATISTICS ps;
    ps = *ppPageStat = LocalAlloc(LMEM_ZEROINIT, sizeof(PAGE_STATISTICS));
    if(!ps) { return FALSE; }
    ps->qwAddr = qwAddrBase;
    ps->cPageTotal = (qwAddrMax - qwAddrBase + 1) / 4096;
    ps->szAction = szAction;
    ps->fKMD = fKMD;
    ps->i.fMemMap = fMemMap;
    ps->i.qwTickCountStart = GetTickCount64();
    ps->i.hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)_PageStatThreadLoop, ps, 0, NULL);
    return TRUE;
}

VOID PageStatUpdate(_In_opt_ PPAGE_STATISTICS pPageStat, _In_ QWORD qwAddr, _In_ QWORD cPageSuccessAdd, _In_ QWORD cPageFailAdd)
{
    if(!pPageStat) { return; }
    pPageStat->qwAddr = qwAddr;
    pPageStat->cPageSuccess += cPageSuccessAdd;
    pPageStat->cPageFail += cPageFailAdd;
    // add to memory map
    if(cPageSuccessAdd && (pPageStat->i.MemMapIdx < PAGE_STATISTICS_MEM_MAP_MAX_ENTRY - 1)) {
        if(!pPageStat->i.MemMapIdx || (qwAddr - (cPageSuccessAdd << 12)) != (pPageStat->i.MemMap[pPageStat->i.MemMapIdx].qwAddrBase + ((QWORD)pPageStat->i.MemMap[pPageStat->i.MemMapIdx].cPages << 12))) {
            pPageStat->i.MemMapIdx++;
            pPageStat->i.MemMap[pPageStat->i.MemMapIdx].qwAddrBase = qwAddr - (cPageSuccessAdd << 12);
        }
        pPageStat->i.MemMap[pPageStat->i.MemMapIdx].cPages += (DWORD)cPageSuccessAdd;
    }
    pPageStat->i.fUpdate = TRUE;
}

// ----------------------------------------------------------------------------
// FUNCTION CALL STATISTICAL FUNCTIONALITY BELOW:
// ----------------------------------------------------------------------------

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

QWORD Statistics_CallEnd(_In_ DWORD fId, QWORD tmCallStart)
{
    QWORD tmNow;
    PCALLSTAT pStat;
    if(!ctxMain->pvStatistics) { return 0; }
    if(fId > STATISTICS_ID_MAX) { return 0; }
    if(tmCallStart == 0) { return 0; }
    pStat = ((PCALLSTAT)ctxMain->pvStatistics) + fId;
    InterlockedIncrement64(&pStat->c);
    QueryPerformanceCounter((PLARGE_INTEGER)&tmNow);
    InterlockedAdd64(&pStat->tm, tmNow - tmCallStart);
    return tmNow - tmCallStart;
}

#define STATISTICS_CALL_LINELENGTH      79
#define STATISTICS_CALL_BUFFERSIZE      (STATISTICS_CALL_LINELENGTH * (4 + STATISTICS_ID_MAX + 1 + LC_STATISTICS_ID_MAX + 1) + 1)

/*
* Retrieve call statistics as a string buffer and size. If psz is not supplied
* only retrieve size.
* CALLER LocalFree: psz
* -- psz
* -- pcsz
* -- return
*/
_Success_(return)
BOOL Statistics_CallToString(_Out_opt_ LPSTR *psz, _Out_ PDWORD pcsz)
{
    LPSTR sz;
    BOOL result;
    QWORD i, o = 0, qwFreq, qwCallCount, qwCallTimeAvg_uS, qwCallTimeTotal_uS;
    PCALLSTAT pStat;
    PLC_STATISTICS pLcStatistics = NULL;
    *pcsz = STATISTICS_CALL_BUFFERSIZE - 1;
    if(!psz) { return TRUE; }
    if(!(*psz = sz = LocalAlloc(0, STATISTICS_CALL_BUFFERSIZE))) { return FALSE; }
    QueryPerformanceFrequency((PLARGE_INTEGER)&qwFreq);
    // header
    o += Util_usnprintf_ln(sz + o, STATISTICS_CALL_LINELENGTH, "FUNCTION CALL STATISTICS:");
    o += Util_usnprintf_ln(sz + o, STATISTICS_CALL_LINELENGTH, "VALUES IN DECIMAL, TIME IN MICROSECONDS uS, STATISTICS = %s", ctxMain->pvStatistics ? "ENABLED " : "DISABLED");
    o += Util_usnprintf_ln(sz + o, STATISTICS_CALL_LINELENGTH, "FUNCTION CALL NAME                           CALLS  TIME AVG        TIME TOTAL");
    o += Util_usnprintf_ln(sz + o, STATISTICS_CALL_LINELENGTH, "==============================================================================");
    // vmm statistics
    for(i = 0; i <= STATISTICS_ID_MAX; i++) {
        qwCallCount = qwCallTimeAvg_uS = qwCallTimeTotal_uS = 0;
        if((pStat = ((PCALLSTAT)ctxMain->pvStatistics) + i) && pStat->c) {
            qwCallCount = pStat->c;
            qwCallTimeTotal_uS = (pStat->tm * 1000000ULL) / qwFreq;
            qwCallTimeAvg_uS = (qwCallTimeTotal_uS / qwCallCount);
        }
        o += Util_usnprintf_ln(
            sz + o,
            STATISTICS_CALL_LINELENGTH,
            "%-40.40s %9lli %9lli %17lli",
            STATISTICS_ID_STR[i],
            qwCallCount,
            qwCallTimeAvg_uS,
            qwCallTimeTotal_uS
        );
    }
    // leechcore statistics
    result = LcCommand(ctxMain->hLC, LC_CMD_STATISTICS_GET, 0, NULL, (PBYTE*)&pLcStatistics, NULL);
    if(result && (pLcStatistics->dwVersion == LC_STATISTICS_VERSION) && pLcStatistics->qwFreq) {
        for(i = 0; i <= LC_STATISTICS_ID_MAX; i++) {
            qwCallCount = qwCallTimeAvg_uS = qwCallTimeTotal_uS = 0;
            if(pLcStatistics->Call[i].c) {
                qwCallCount = pLcStatistics->Call[i].c;
                qwCallTimeTotal_uS = (pLcStatistics->Call[i].tm * 1000000ULL) / qwFreq;
                qwCallTimeAvg_uS = (qwCallTimeTotal_uS / qwCallCount);
            }
           o += Util_usnprintf_ln(
                sz + o,
                STATISTICS_CALL_LINELENGTH,
                "%-40.40s %9lli %9lli %17lli",
                LC_STATISTICS_NAME[i],
                qwCallCount,
                qwCallTimeAvg_uS,
                qwCallTimeTotal_uS
            );
        }
    }
    LocalFree(pLcStatistics);
    return TRUE;
}
