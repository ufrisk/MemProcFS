// sysquery.c : implementations of various system queries that may be performed.
//
// (c) Ulf Frisk, 2019-2020
// Author: Ulf Frisk, pcileech@frizk.net
//
#include "sysquery.h"

/*
* Query all processes for the minimum create and termination time.
* -- pftMin
* -- pftMax
* -- return
*/
_Success_(return)
BOOL SysQuery_TimeProcessMinMax(_Out_ PQWORD pftMin, _Out_ PQWORD pftMax)
{
    PVMM_PROCESS pObProcess = NULL;
    QWORD ft, ftMin = -1, ftMax = 0;
    while((pObProcess = VmmProcessGetNext(pObProcess, VMM_FLAG_PROCESS_SHOW_TERMINATED))) {
        ft = VmmProcess_GetCreateTimeOpt(pObProcess);
        if(!ft) { continue; }
        ftMin = min(ft, ftMin);
        ftMax = max(ft, ftMax);
        ft = VmmProcess_GetExitTimeOpt(pObProcess);
        if(!ft) { continue; }
        ftMin = min(ft, ftMin);
        ftMax = max(ft, ftMax);
    }
    *pftMin = ftMin;
    *pftMax = ftMax;
    return (ftMax != 0) && (ftMin != -1);
}
