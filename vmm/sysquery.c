// sysquery.c : implementations of various system queries that may be performed.
//
// (c) Ulf Frisk, 2019-2023
// Author: Ulf Frisk, pcileech@frizk.net
//
#include "sysquery.h"
#include "vmmwinreg.h"
#include "charutil.h"
#include "pe.h"

/*
* Retrieve the current system time as FILETIME.
* -- H
* -- return
*/
_Success_(return != 0)
QWORD SysQuery_TimeCurrent(_In_ VMM_HANDLE H)
{
    // data is fetched from fixed memory address as defined in wdm.h
    // this applies even to the most recent windows version ...
    // #define KI_USER_SHARED_DATA 0xffdf0000
    // #define KI_USER_SHARED_DATA 0xFFFFF78000000000UI64
    // #define SharedSystemTime (KI_USER_SHARED_DATA + 0x14)
    QWORD ft = 0;
    VmmRead(H, PVMM_PROCESS_SYSTEM, H->vmm.f32 ? 0xFFDF0014 : 0xFFFFF78000000014, (PBYTE)&ft, sizeof(QWORD));
    return ft;
}

/*
* Query the system for current time zone and its bias in minutes against UCT.
* NB! individual sessions connected remotely may have other time zones.
* -- H
* -- wszTimeZone = full name text representation - ex: 'Eastern Standard Time'.
* -- piActiveBias = bias against UCT in minutes - ex: (CET=UCT+1=-60).
* -- return
*/
_Success_(return)
BOOL SysQuery_TimeZone(_In_ VMM_HANDLE H, _Out_writes_opt_(32) LPSTR uszTimeZone, _Out_opt_ int *piActiveBias)
{
    BYTE pbTimeZone[64];
    if(uszTimeZone) {
        if(!VmmWinReg_ValueQuery2(H, "HKLM\\SYSTEM\\ControlSet001\\Control\\TimeZoneInformation\\TimeZoneKeyName", NULL, pbTimeZone, sizeof(pbTimeZone), NULL)) { return FALSE; }
        CharUtil_WtoU((LPWSTR)pbTimeZone, 32, uszTimeZone, 32, NULL, NULL, CHARUTIL_FLAG_TRUNCATE_ONFAIL_NULLSTR | CHARUTIL_FLAG_STR_BUFONLY);
    }
    if(piActiveBias) {
        if(!VmmWinReg_ValueQuery2(H, "HKLM\\SYSTEM\\ControlSet001\\Control\\TimeZoneInformation\\ActiveTimeBias", NULL, (PBYTE)piActiveBias, sizeof(DWORD), NULL)) { return FALSE; }
        if((*piActiveBias > 24 * 60) && (*piActiveBias < -(24 * 60))) { return FALSE; }
    }
    return TRUE;
}

_Success_(return)
QWORD SysQuery_GetProcAddress_Impl(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess, _In_ LPSTR uszModuleName, _In_ LPSTR szFunctionName, _In_ DWORD iLevel)
{
    PVMMOB_MAP_EAT pObEatMap = NULL;
    PVMMOB_MAP_MODULE pObModuleMap = NULL;
    PVMM_MAP_MODULEENTRY peModule;
    QWORD va = 0;
    DWORD i;
    LPSTR uszForwardFunctionName;
    CHAR uszForwardModuleName[MAX_PATH];
    if(!VmmMap_GetModuleEntryEx(H, pProcess, 0, uszModuleName, 0, &pObModuleMap, &peModule)) { goto fail; }
    if(!VmmMap_GetEAT(H, pProcess, peModule, &pObEatMap)) { goto fail; }
    if(!VmmMap_GetEATEntryIndexU(H, pObEatMap, szFunctionName, &i)) { goto fail; }
    va = pObEatMap->pMap[i].vaFunction;
    if(!va && pObEatMap->pMap[i].uszForwardedFunction && (iLevel < 5)) {
        if((uszForwardFunctionName = PE_EatForwardedFunctionNameValidate(pObEatMap->pMap[i].uszForwardedFunction, uszForwardModuleName, MAX_PATH, NULL))) {
            va = SysQuery_GetProcAddress_Impl(H, pProcess, uszForwardModuleName, uszForwardFunctionName, iLevel + 1);
        }
    }
fail:
    Ob_DECREF(pObEatMap);
    Ob_DECREF(pObModuleMap);
    return va;
}

/*
* Retrieve an exported function address similar to kernel32!GetProcAddress().
* -- H
* -- pProcess
* -- uszModuleName
* -- szFunctionName
* -- return
*/
_Success_(return)
QWORD SysQuery_GetProcAddress(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess, _In_ LPSTR uszModuleName, _In_ LPSTR szFunctionName)
{
    return SysQuery_GetProcAddress_Impl(H, pProcess, uszModuleName, szFunctionName, 0);
}
