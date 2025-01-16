// statistics.c : implementation of statistics related functionality.
//
// (c) Ulf Frisk, 2016-2025
// Author: Ulf Frisk, pcileech@frizk.net
//
#include "statistics.h"
#include "vmm.h"
#include "util.h"

// ----------------------------------------------------------------------------
// FUNCTION CALL STATISTICAL FUNCTIONALITY BELOW:
// ----------------------------------------------------------------------------

typedef struct tdVMMSTATISTICS_ENTRY {
    QWORD c;
    QWORD tm;
} VMMSTATISTICS_ENTRY, *PVMMSTATISTICS_ENTRY;

typedef struct tdVMMSTATISTICS_CALL_CONTEXT {
    VMMSTATISTICS_ENTRY e[STATISTICS_ID_MAX];
} VMMSTATISTICS_CALL_CONTEXT, *PVMMSTATISTICS_CALL_CONTEXT;

VOID Statistics_CallSetEnabled(_In_ VMM_HANDLE H, _In_ BOOL fEnabled)
{
    if(fEnabled && H->statistics_call) { return; }
    if(!fEnabled && !H->statistics_call) { return; }
    if(fEnabled) {
        H->statistics_call = LocalAlloc(LMEM_ZEROINIT, sizeof(VMMSTATISTICS_CALL_CONTEXT));
    } else {
        LocalFree(H->statistics_call);
        H->statistics_call = NULL;
    }
}

BOOL Statistics_CallGetEnabled(_In_ VMM_HANDLE H)
{
    return H->statistics_call != NULL;
}

QWORD Statistics_CallStart(_In_ VMM_HANDLE H)
{
    QWORD tmNow;
    if(!H->statistics_call) { return 0; }
    QueryPerformanceCounter((PLARGE_INTEGER)&tmNow);
    return tmNow;
}

QWORD Statistics_CallEnd(_In_ VMM_HANDLE H, _In_ DWORD fId, QWORD tmCallStart)
{
    QWORD tmNow;
    PVMMSTATISTICS_ENTRY pStat;
    if(!H->statistics_call) { return 0; }
    if(fId >= STATISTICS_ID_MAX) { return 0; }
    if(tmCallStart == 0) { return 0; }
    pStat = H->statistics_call->e + fId;
    InterlockedIncrement64(&pStat->c);
    QueryPerformanceCounter((PLARGE_INTEGER)&tmNow);
    InterlockedAdd64(&pStat->tm, tmNow - tmCallStart);
    return tmNow - tmCallStart;
}

#define STATISTICS_CALL_LINELENGTH      79
#define STATISTICS_CALL_BUFFERSIZE      (STATISTICS_CALL_LINELENGTH * (4 + STATISTICS_ID_MAX + LC_STATISTICS_ID_MAX + 1) + 1)

/*
* Retrieve call statistics as a string buffer and size. If psz is not supplied
* only retrieve size.
* CALLER LocalFree: psz
* -- H
* -- psz
* -- pcsz
* -- return
*/
_Success_(return)
BOOL Statistics_CallToString(_In_ VMM_HANDLE H, _Out_opt_ LPSTR *psz, _Out_ PDWORD pcsz)
{
    LPSTR sz;
    BOOL result;
    QWORD i, o = 0, qwFreq, qwCallCount, qwCallTimeAvg_uS, qwCallTimeTotal_uS;
    PVMMSTATISTICS_ENTRY pStat;
    PLC_STATISTICS pLcStatistics = NULL;
    *pcsz = STATISTICS_CALL_BUFFERSIZE - 1;
    if(!psz) { return TRUE; }
    if(!(*psz = sz = LocalAlloc(0, STATISTICS_CALL_BUFFERSIZE))) { return FALSE; }
    QueryPerformanceFrequency((PLARGE_INTEGER)&qwFreq);
    // header
    o += Util_usnprintf_ln(sz + o, STATISTICS_CALL_LINELENGTH, "FUNCTION CALL STATISTICS:");
    o += Util_usnprintf_ln(sz + o, STATISTICS_CALL_LINELENGTH, "VALUES IN DECIMAL, TIME IN MICROSECONDS uS, STATISTICS = %s", H->statistics_call ? "ENABLED " : "DISABLED");
    o += Util_usnprintf_ln(sz + o, STATISTICS_CALL_LINELENGTH, "FUNCTION CALL NAME                           CALLS  TIME AVG        TIME TOTAL");
    o += Util_usnprintf_ln(sz + o, STATISTICS_CALL_LINELENGTH, "==============================================================================");
    // vmm statistics
    if(H->statistics_call) {
        for(i = 0; i < STATISTICS_ID_MAX; i++) {
            qwCallCount = qwCallTimeAvg_uS = qwCallTimeTotal_uS = 0;
            if((pStat = H->statistics_call->e + i) && pStat->c) {
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
    }
    // leechcore statistics
    result = LcCommand(H->hLC, LC_CMD_STATISTICS_GET, 0, NULL, (PBYTE*)&pLcStatistics, NULL);
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
    LcMemFree(pLcStatistics);
    return TRUE;
}



// ----------------------------------------------------------------------------
// CALL STATISTICS DEBUG/TRACE LOGGING BELOW:
// ----------------------------------------------------------------------------

/*
* Start a call statistics logging session.
* -- H
* -- MID = module ID (MID)
* -- dwLogLevel = log level as defined by LOGLEVEL_*
* -- pProcess
* -- ps
* -- uszText
*/
VOID VmmStatisticsLogStart(_In_ VMM_HANDLE H, _In_ VMM_MODULE_ID MID, _In_ VMMLOG_LEVEL dwLogLevel, _In_opt_ PVMM_PROCESS pProcess, _Out_ PVMMSTATISTICS_LOG ps, _In_ LPCSTR uszText)
{
    ps->f = VmmLogIsActive(H, MID, dwLogLevel);
    if(H->fAbort || !ps->f) { return; }
    ps->fShowReads = TRUE;
    ps->dwPID = pProcess ? pProcess->dwPID : 0;
    ps->MID = MID;
    ps->dwLogLevel = dwLogLevel;
    ps->v[0] = GetTickCount64();
    LcGetOption(H->hLC, LC_OPT_CORE_STATISTICS_CALL_COUNT | LC_STATISTICS_ID_READSCATTER, &ps->v[1]);
    ps->v[2] = H->vmm.stat.cPhysReadSuccess;
    if(ps->dwPID) {
        VmmLog(H, ps->MID, ps->dwLogLevel, "%s START: [pid=%i]", uszText, ps->dwPID);
    } else {
        VmmLog(H, ps->MID, ps->dwLogLevel, "%s START:", uszText);
    }
}

/*
* End a statistics logging session.
* -- H
* -- ps
* -- uszText
*/
VOID VmmStatisticsLogEnd(_In_ VMM_HANDLE H, _In_ PVMMSTATISTICS_LOG ps, _In_ LPCSTR uszText)
{
    QWORD v[3];
    if(H->fAbort || !ps->f) { return; }
    v[0] = GetTickCount64();
    if(ps->fShowReads) {
        LcGetOption(H->hLC, LC_OPT_CORE_STATISTICS_CALL_COUNT | LC_STATISTICS_ID_READSCATTER, &v[1]);
        v[2] = H->vmm.stat.cPhysReadSuccess;
        if(ps->dwPID) {
            VmmLog(H, ps->MID, ps->dwLogLevel, "%s END:   [pid=%i time=%llims scatter=0x%llx pages=0x%llx]", uszText, ps->dwPID, (v[0] - ps->v[0]), (v[1] - ps->v[1]), (v[2] - ps->v[2]));
        } else {
            VmmLog(H, ps->MID, ps->dwLogLevel, "%s END:   [time=%llims scatter=0x%llx pages=0x%llx]", uszText, (v[0] - ps->v[0]), (v[1] - ps->v[1]), (v[2] - ps->v[2]));
        }
    } else {
        if(ps->dwPID) {
            VmmLog(H, ps->MID, ps->dwLogLevel, "%s END:   [pid=%i time=%llims]", uszText, ps->dwPID, (v[0] - ps->v[0]));
        } else {
            VmmLog(H, ps->MID, ps->dwLogLevel, "%s END:   [time=%llims]", uszText, (v[0] - ps->v[0]));
        }
    }
}
