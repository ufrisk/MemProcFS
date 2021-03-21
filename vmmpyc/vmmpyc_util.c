// vmmpyc_util.c : various utility functions used.
//
// (c) Ulf Frisk, 2021
// Author: Ulf Frisk, pcileech@frizk.net
//
#include "vmmpyc.h"

VOID Util_FileTime2String(_In_ QWORD ft, _Out_writes_(24) LPSTR szTime)
{
    SYSTEMTIME SystemTime;
    if(!ft || (ft > 0x0200000000000000)) {
        strcpy_s(szTime, 24, "                    ***");
        return;
    }
    FileTimeToSystemTime((PFILETIME)&ft, &SystemTime);
    sprintf_s(
        szTime,
        24,
        "%04i-%02i-%02i %02i:%02i:%02i UTC",
        SystemTime.wYear,
        SystemTime.wMonth,
        SystemTime.wDay,
        SystemTime.wHour,
        SystemTime.wMinute,
        SystemTime.wSecond
    );
}

LPWSTR Util_PathSplitLastW(_In_ LPWSTR wsz)
{
    LPWSTR wszResult = wsz;
    WCHAR ch;
    DWORD i = 0;
    while(TRUE) {
        ch = wsz[i++];
        if(ch == '\0') {
            return wszResult;
        }
        if(ch == '\\') {
            wszResult = wsz + i;
        }
    }
}

LPWSTR Util_PathFileSplitW(_In_ LPWSTR wsz, _Out_writes_(MAX_PATH) LPWSTR wszPath)
{
    DWORD i, iBackSlash = -1;
    WCHAR ch = -1;
    for(i = 0; ch && i < MAX_PATH; i++) {
        ch = wsz[i];
        wszPath[i] = ch;
        if(ch == '\\') {
            iBackSlash = i;
        }
    }
    wszPath[MAX_PATH - 1] = 0;
    if(iBackSlash == -1) { return NULL; }
    wszPath[iBackSlash] = 0;
    return wszPath + iBackSlash + 1;
}
