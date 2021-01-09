// sysquery.c : implementations of various system queries that may be performed.
//
// (c) Ulf Frisk, 2019-2021
// Author: Ulf Frisk, pcileech@frizk.net
//
#include "sysquery.h"
#include "vmmwinreg.h"

/*
* Retrieve the current system time as FILETIME.
* -- return
*/
_Success_(return != 0)
QWORD SysQuery_TimeCurrent()
{
    // data is fetched from fixed memory address as defined in wdm.h
    // this applies even to the most recent windows version ...
    // #define KI_USER_SHARED_DATA 0xffdf0000
    // #define KI_USER_SHARED_DATA 0xFFFFF78000000000UI64
    // #define SharedSystemTime (KI_USER_SHARED_DATA + 0x14)
    QWORD ft = 0;
    VmmRead(PVMM_PROCESS_SYSTEM, ctxVmm->f32 ? 0xFFDF0014 : 0xFFFFF78000000014, (PBYTE)&ft, sizeof(QWORD));
    return ft;
}

/*
* Query the system for current time zone and its bias in minutes against UCT.
* NB! individual sessions connected remotely may have other time zones.
* -- wszTimeZone = full name text representation - ex: 'Eastern Standard Time'.
* -- piActiveBias = bias against UCT in minutes - ex: (CET=UCT+1=-60).
* -- return
*/
_Success_(return)
BOOL SysQuery_TimeZone(_Out_writes_opt_(32) LPWSTR wszTimeZone, _Out_opt_ int *piActiveBias)
{
    if(wszTimeZone) {
        if(!VmmWinReg_ValueQuery2(L"HKLM\\SYSTEM\\ControlSet001\\Control\\TimeZoneInformation\\TimeZoneKeyName", NULL, (PBYTE)wszTimeZone, 31 * sizeof(WCHAR), NULL)) { return FALSE; }
        wszTimeZone[31] = 0;
    }
    if(piActiveBias) {
        if(!VmmWinReg_ValueQuery2(L"HKLM\\SYSTEM\\ControlSet001\\Control\\TimeZoneInformation\\ActiveTimeBias", NULL, (PBYTE)piActiveBias, sizeof(DWORD), NULL)) { return FALSE; }
        if((*piActiveBias > 24 * 60) && (*piActiveBias < -(24 * 60))) { return FALSE; }
    }
    return TRUE;
}
