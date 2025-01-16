// util.c : implementation of various utility functions.
//
// (c) Ulf Frisk, 2018-2025
// Author: Ulf Frisk, pcileech@frizk.net
//
#include "util.h"
#include "charutil.h"
#include "ext/miniz.h"
#include "ext/sha256.h"
#include <math.h>

/*
* Calculate the number of digits of an integer number.
*/
DWORD Util_GetNumDigits(_In_ DWORD dwNumber)
{
    return (DWORD)max(1, floor(log10(dwNumber) + 1));
}

QWORD Util_GetNumericA(_In_ LPCSTR sz)
{
    if((strlen(sz) > 1) && (sz[0] == '0') && ((sz[1] == 'x') || (sz[1] == 'X'))) {
        return strtoull(sz, NULL, 16); // Hex (starts with 0x)
    } else {
        return strtoull(sz, NULL, 10); // Not Hex -> try Decimal
    }
}

#define Util_2HexChar(x) (((((x) & 0xf) <= 9) ? '0' : ('a' - 10)) + ((x) & 0xf))

_Success_(return)
BOOL Util_FillHexAscii(_In_reads_opt_(cb) PBYTE pb, _In_ DWORD cb, _In_ DWORD cbInitialOffset, _Out_writes_opt_(*pcsz) LPSTR sz, _Inout_ PDWORD pcsz)
{
    DWORD i, j, o = 0, iMod, cRows;
    // checks
    if((cbInitialOffset > cb) || (cbInitialOffset > 0x1000) || (cbInitialOffset & 0xf)) { return FALSE; }
    cRows = (cb + 0xf) >> 4;
    if(!sz) {
        *pcsz = 1 + cRows * 76;
        return TRUE;
    }
    if(!pb || (*pcsz <= cRows * 76)) { return FALSE; }
    // fill buffer with bytes
    for(i = cbInitialOffset; i < cb + ((cb % 16) ? (16 - cb % 16) : 0); i++)
    {
        // address
        if(0 == i % 16) {
            iMod = i % 0x10000;
            sz[o++] = Util_2HexChar(iMod >> 12);
            sz[o++] = Util_2HexChar(iMod >> 8);
            sz[o++] = Util_2HexChar(iMod >> 4);
            sz[o++] = Util_2HexChar(iMod);
            sz[o++] = ' ';
            sz[o++] = ' ';
            sz[o++] = ' ';
            sz[o++] = ' ';
        } else if(0 == i % 8) {
            sz[o++] = ' ';
        }
        // hex
        if(i < cb) {
            sz[o++] = Util_2HexChar(pb[i] >> 4);
            sz[o++] = Util_2HexChar(pb[i]);
            sz[o++] = ' ';
        } else {
            sz[o++] = ' ';
            sz[o++] = ' ';
            sz[o++] = ' ';
        }
        // ascii
        if(15 == i % 16) {
            sz[o++] = ' ';
            sz[o++] = ' ';
            for(j = i - 15; j <= i; j++) {
                if(j >= cb) {
                    sz[o++] = ' ';
                } else {
                    sz[o++] = UTIL_PRINTASCII[pb[j]];
                }
            }
            sz[o++] = '\n';
        }
    }
    sz[o] = 0;
    *pcsz = o;
    return TRUE;
}

_Success_(return)
BOOL Util_FillHexAscii_WithAddress(_In_reads_opt_(cb) PBYTE pb, _In_ DWORD cb, _In_ QWORD qwAddress, _Out_writes_opt_(*pcsz) LPSTR sz, _Inout_ PDWORD pcsz)
{
    QWORD va;
    DWORD i, j, o = 0, cRows;
    // checks
    cRows = (cb + 0xf) >> 4;
    if(!sz) {
        *pcsz = 1 + cRows * 88;
        return TRUE;
    }
    if(!pb || (*pcsz <= cRows * 88)) { return FALSE; }
    // fill buffer with bytes
    for(i = 0; i < cb + ((cb % 16) ? (16 - cb % 16) : 0); i++) {
        // address
        if(0 == i % 16) {
            va = qwAddress + i;
            for(j = 0; j < 64; j += 4) {
                sz[o++] = Util_2HexChar(va >> (60 - j));
            }
            sz[o++] = ' ';
            sz[o++] = ' ';
            sz[o++] = ' ';
            sz[o++] = ' ';
        } else if(0 == i % 8) {
            sz[o++] = ' ';
        }
        // hex
        if(i < cb) {
            sz[o++] = Util_2HexChar(pb[i] >> 4);
            sz[o++] = Util_2HexChar(pb[i]);
            sz[o++] = ' ';
        } else {
            sz[o++] = ' ';
            sz[o++] = ' ';
            sz[o++] = ' ';
        }
        // ascii
        if(15 == i % 16) {
            sz[o++] = ' ';
            sz[o++] = ' ';
            for(j = i - 15; j <= i; j++) {
                if(j >= cb) {
                    sz[o++] = ' ';
                } else {
                    sz[o++] = UTIL_PRINTASCII[pb[j]];
                }
            }
            sz[o++] = '\n';
        }
    }
    sz[o] = 0;
    *pcsz = o;
    return TRUE;
}

VOID Util_AsciiFileNameFix(_Inout_ LPSTR sz, _In_ CHAR chDefault)
{
    DWORD i = 0;
    while(sz[i]) {
        if(UTIL_ASCIIFILENAME_ALLOW[(UCHAR)sz[i]] == '0') { sz[i] = chDefault; }
        i++;
    }
}

VOID Util_PathPrependVA(_Out_writes_(MAX_PATH) LPSTR uszDstBuffer, _In_ QWORD va, _In_ BOOL f32, _In_ LPCSTR uszText)
{
    _snprintf_s(uszDstBuffer, MAX_PATH, _TRUNCATE, (f32 ? "%08llx%s%s" : "%016llx%s%s"), va, (uszText[0] ? "-" : ""), uszText);
}

_Success_(return >= 0)
size_t Util_usnprintf_ln_impl(
    _Out_writes_(cszLineLength + 1) LPSTR uszBuffer,
    _In_ QWORD cszLineLength,
    _In_z_ _Printf_format_string_ LPCSTR uszFormat,
    _In_ va_list arglist
)
{
    int csz = 0;
    // 2: write to buffer
    csz = _vsnprintf_s(uszBuffer, (SIZE_T)cszLineLength, _TRUNCATE, uszFormat, arglist);
    if((csz < 0) && (csz != -1)) { csz = 0; }   // error & not _TRUNCATE
    if((QWORD)csz < cszLineLength - 1) {
        memset(uszBuffer + csz, ' ', (SIZE_T)(cszLineLength - 1 - csz));
    }
    uszBuffer[cszLineLength - 1] = '\n';
    uszBuffer[cszLineLength] = '\0';
    return (SIZE_T)cszLineLength;
}

_Success_(return >= 0)
size_t Util_usnprintf_ln(
    _Out_writes_(cszLineLength + 1) LPSTR uszBuffer,
    _In_ QWORD cszLineLength,
    _In_z_ _Printf_format_string_ LPCSTR uszFormat,
    ...
) {
    size_t ret;
    va_list arglist;
    va_start(arglist, uszFormat);
    ret = Util_usnprintf_ln_impl(uszBuffer, cszLineLength, uszFormat, arglist);
    va_end(arglist);
    return ret;
}

#define UTIL_NTSTATUS_SUCCESS                      ((NTSTATUS)0x00000000L)
#define UTIL_NTSTATUS_FILE_INVALID                 ((NTSTATUS)0xC0000098L)
#define UTIL_NTSTATUS_END_OF_FILE                  ((NTSTATUS)0xC0000011L)

NTSTATUS Util_VfsReadFile_FromZERO(_In_ QWORD cbFile, _Out_writes_to_(cb, *pcbRead) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset)
{
    if(cbOffset > cbFile) { *pcbRead = 0; return UTIL_NTSTATUS_END_OF_FILE; }
    *pcbRead = (DWORD)min(cb, cbFile - cbOffset);
    ZeroMemory(pb, *pcbRead);
    return *pcbRead ? UTIL_NTSTATUS_SUCCESS : UTIL_NTSTATUS_END_OF_FILE;
}

NTSTATUS Util_VfsReadFile_FromPBYTE(_In_opt_ PBYTE pbFile, _In_ QWORD cbFile, _Out_writes_to_(cb, *pcbRead) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset)
{
    if(!pbFile || (cbOffset > cbFile)) { *pcbRead = 0; return UTIL_NTSTATUS_END_OF_FILE; }
    *pcbRead = (DWORD)min(cb, cbFile - cbOffset);
    memcpy(pb, pbFile + cbOffset, *pcbRead);
    return *pcbRead ? UTIL_NTSTATUS_SUCCESS : UTIL_NTSTATUS_END_OF_FILE;
}

NTSTATUS Util_VfsReadFile_FromHEXASCII(_In_opt_ PBYTE pbFile, _In_ QWORD cbFile, _Out_writes_to_(cb, *pcbRead) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset)
{
    BYTE v;
    QWORD cbFileHex, oHex, oTarget;
    static LPCSTR szALPHABET= "0123456789abcdef";
    cbFileHex = (QWORD)cbFile << 1;
    if(!pbFile || (cbOffset > cbFileHex)) { *pcbRead = 0; return UTIL_NTSTATUS_END_OF_FILE; }
    if(cbOffset + cb > cbFileHex) {
        cb = (DWORD)(cbFileHex - cbOffset);
    }
    for(oHex = 0; oHex < cb; oHex++) {
        oTarget = (cbOffset + oHex) >> 1;
        v = pbFile[oTarget];
        if((cbOffset + oHex) & 1) {
            v = v & 0xf;
        } else {
            v = v >> 4;
        }
        pb[oHex] = szALPHABET[v];
    }
    *pcbRead = cb;
    return *pcbRead ? UTIL_NTSTATUS_SUCCESS : UTIL_NTSTATUS_END_OF_FILE;
}

NTSTATUS Util_VfsReadFile_FromStrA(_In_opt_ LPCSTR szFile, _Out_writes_to_(cb, *pcbRead) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset)
{
    if(!szFile) { return UTIL_NTSTATUS_END_OF_FILE; }
    return Util_VfsReadFile_FromPBYTE((PBYTE)szFile, strlen(szFile), pb, cb, pcbRead, cbOffset);
}

NTSTATUS Util_VfsReadFile_FromMEM(_In_ VMM_HANDLE H, _In_opt_ PVMM_PROCESS pProcess, _In_ QWORD vaMEM, _In_ QWORD cbMEM, _In_ QWORD flags, _Out_writes_to_(cb, *pcbRead) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset)
{
    NTSTATUS nt = UTIL_NTSTATUS_END_OF_FILE;
    PBYTE pbMEM;
    if(cbOffset < cbMEM) {
        vaMEM += cbOffset;
        cbMEM -= cbOffset;
        if((cbMEM < 0x04000000) && (pbMEM = LocalAlloc(0, (SIZE_T)cbMEM))) {
            if(VmmRead2(H, pProcess, vaMEM, pbMEM, (DWORD)cbMEM, flags)) {
                nt = Util_VfsReadFile_FromPBYTE(pbMEM, cbMEM, pb, cb, pcbRead, 0);
            }
            LocalFree(pbMEM);
        }
    }
    return nt;
}

NTSTATUS Util_VfsReadFile_FromObData(_In_opt_ POB_DATA pData, _Out_writes_to_(cb, *pcbRead) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset)
{
    if(!pData) { return UTIL_NTSTATUS_END_OF_FILE; }
    return Util_VfsReadFile_FromPBYTE(pData->pb, pData->ObHdr.cbData, pb, cb, pcbRead, cbOffset);
}

NTSTATUS Util_VfsReadFile_FromObDataStrA(_In_opt_ POB_DATA pData, _Out_writes_to_(cb, *pcbRead) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset)
{
    if(!pData) { return UTIL_NTSTATUS_END_OF_FILE; }
    return Util_VfsReadFile_FromPBYTE(pData->pb, (pData->ObHdr.cbData ? pData->ObHdr.cbData - 1 : 0), pb, cb, pcbRead, cbOffset);
}

NTSTATUS Util_VfsReadFile_FromObCompressed(_In_opt_ POB_COMPRESSED pdc, _Out_writes_to_(cb, *pcbRead) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset)
{
    NTSTATUS nt = UTIL_NTSTATUS_END_OF_FILE;
    POB_DATA pObData;
    if((pObData = ObCompressed_GetData(pdc))) {
        nt = Util_VfsReadFile_FromObData(pObData, pb, cb, pcbRead, cbOffset);
        Ob_DECREF(pObData);
    }
    return nt;
}

NTSTATUS Util_VfsReadFile_FromObCompressedStrA(_In_opt_ POB_COMPRESSED pdc, _Out_writes_to_(cb, *pcbRead) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset)
{
    NTSTATUS nt = UTIL_NTSTATUS_END_OF_FILE;
    POB_DATA pObData;
    if((pObData = ObCompressed_GetData(pdc))) {
        nt = Util_VfsReadFile_FromObDataStrA(pObData, pb, cb, pcbRead, cbOffset);
        Ob_DECREF(pObData);
    }
    return nt;
}

NTSTATUS Util_VfsReadFile_FromNumber(_In_ QWORD qwValue, _Out_writes_to_(cb, *pcbRead) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset)
{
    BYTE pbBuffer[32];
    DWORD cbBuffer;
    cbBuffer = snprintf(pbBuffer, 32, "%lli", qwValue);
    return Util_VfsReadFile_FromPBYTE(pbBuffer, cbBuffer, pb, cb, pcbRead, cbOffset);
}

NTSTATUS Util_VfsReadFile_FromQWORD(_In_ QWORD qwValue, _Out_writes_to_(cb, *pcbRead) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset, _In_ BOOL fPrefix)
{
    BYTE pbBuffer[32];
    DWORD cbBuffer;
    cbBuffer = snprintf(pbBuffer, 32, (fPrefix ? "0x%016llx" : "%016llx"), qwValue);
    return Util_VfsReadFile_FromPBYTE(pbBuffer, cbBuffer, pb, cb, pcbRead, cbOffset);
}

NTSTATUS Util_VfsReadFile_FromDWORD(_In_ DWORD dwValue, _Out_writes_to_(cb, *pcbRead) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset, _In_ BOOL fPrefix)
{
    BYTE pbBuffer[32];
    DWORD cbBuffer;
    cbBuffer = snprintf(pbBuffer, 32, (fPrefix ? "0x%08x" : "%08x"), dwValue);
    return Util_VfsReadFile_FromPBYTE(pbBuffer, cbBuffer, pb, cb, pcbRead, cbOffset);
}

NTSTATUS Util_VfsReadFile_FromBOOL(_In_ BOOL fValue, _Out_writes_to_(cb, *pcbRead) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset)
{
    BYTE pbBuffer[1];
    pbBuffer[0] = fValue ? '1' : '0';
    return Util_VfsReadFile_FromPBYTE(pbBuffer, 1, pb, cb, pcbRead, cbOffset);
}

NTSTATUS Util_VfsReadFile_FromFILETIME(_In_ QWORD ftValue, _Out_writes_to_(cb, *pcbRead) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset)
{
    CHAR szTime[24];
    Util_FileTime2String(ftValue, szTime);
    szTime[23] = '\n';
    return Util_VfsReadFile_FromPBYTE(szTime, 24, pb, cb, pcbRead, cbOffset);
}

NTSTATUS Util_VfsReadFile_usnprintf_ln(_Out_writes_to_(cb, *pcbRead) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset, _In_ QWORD cszLineLength, _In_z_ _Printf_format_string_ LPCSTR uszFormat, ...)
{
    NTSTATUS nt = UTIL_NTSTATUS_END_OF_FILE;
    DWORD ret;
    va_list arglist;
    LPSTR szBuffer;
    if(!(szBuffer = LocalAlloc(0, (SIZE_T)(cszLineLength + 1)))) { goto fail; }
    va_start(arglist, uszFormat);
    ret = (DWORD)Util_usnprintf_ln_impl(szBuffer, cszLineLength, uszFormat, arglist);
    va_end(arglist);
    if(!ret) { goto fail; }
    nt = Util_VfsReadFile_FromPBYTE(szBuffer, cszLineLength, pb, cb, pcbRead, cbOffset);
fail:
    LocalFree(szBuffer);
    return nt;
}

NTSTATUS Util_VfsWriteFile_PBYTE(_Inout_ PBYTE pbTarget, _In_ DWORD cbTarget, _In_reads_(cb) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbWrite, _In_ QWORD cbOffset, _In_ BOOL fTerminatingNULL)
{
    if(cbOffset >= cbTarget) {
        *pcbWrite = 0;
        return UTIL_NTSTATUS_END_OF_FILE;
    }
    if(cbOffset + cb > cbTarget) {
        cb = (DWORD)(cbTarget - cbOffset);
    }
    memcpy(pbTarget + cbOffset, pb, cb);
    if(fTerminatingNULL) {
        pbTarget[min(cbTarget - 1, cb)] = 0;
    }
    *pcbWrite = cb;
    return UTIL_NTSTATUS_SUCCESS;
}

NTSTATUS Util_VfsWriteFile_HEXASCII(_Inout_ PBYTE pbTarget, _In_ DWORD cbTarget, _In_reads_(cb) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbWrite, _In_ QWORD cbOffset)
{
    BYTE v;
    DWORD cbWrite = 0;
    QWORD cbTargetHex, oHex, oTarget;
    cbTargetHex = (QWORD)cbTarget << 1;
    if(cbOffset >= cbTargetHex) {
        *pcbWrite = 0;
        return UTIL_NTSTATUS_END_OF_FILE;
    }
    if(cbOffset + cb > cbTargetHex) {
        cb = (DWORD)(cbTargetHex - cbOffset);
    }
    for(oHex = 0; oHex < cb; oHex++) {
        oTarget = (cbOffset + oHex) >> 1;
        v = pb[oHex];
        if((v >= '0') && (v <= '9')) {
            v = v - '0';
        } else if((v >= 'a') && (v <= 'f')) {
            v = v + 10 - 'a';
        } else if((v >= 'A') && (v <= 'F')) {
            v = v + 10 - 'A';
        } else {
            break;
        }
        if((cbOffset + oHex) & 1) {
            pbTarget[oTarget] = (pbTarget[oTarget] & 0xf0) | v;
        } else {
            pbTarget[oTarget] = (pbTarget[oTarget] & 0x0f) | (v << 4);
        }
        cbWrite++;
    }
    *pcbWrite = cbWrite;
    return UTIL_NTSTATUS_SUCCESS;
}

NTSTATUS Util_VfsWriteFile_BOOL(_Inout_ PBOOL pfTarget, _In_reads_(cb) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbWrite, _In_ QWORD cbOffset)
{
    CHAR ch;
    if(cbOffset) { return UTIL_NTSTATUS_END_OF_FILE; }
    if((cb > 0) && (cbOffset == 0)) {
        ch = *(PCHAR)pb;
        *pfTarget = (ch == 0 || ch == '0') ? FALSE : TRUE;
    }
    *pcbWrite = cb;
    return UTIL_NTSTATUS_SUCCESS;
}

NTSTATUS Util_VfsWriteFile_09(_Inout_ PDWORD pdwTarget, _In_reads_(cb) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbWrite, _In_ QWORD cbOffset)
{
    if(cbOffset) { return UTIL_NTSTATUS_END_OF_FILE; }
    if(cb && (pb[0] >= '0') && (pb[0] <= '9')) {
        *pdwTarget = pb[0] - '0';
    }
    *pcbWrite = cb;
    return UTIL_NTSTATUS_SUCCESS;
}

NTSTATUS Util_VfsWriteFile_DWORD(_Inout_ PDWORD pdwTarget, _In_reads_(cb) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbWrite, _In_ QWORD cbOffset, _In_ DWORD dwMinAllow, _In_opt_ DWORD dwMaxAllow)
{
    DWORD dw;
    BYTE pbBuffer[9];
    if(cbOffset > 8) { return UTIL_NTSTATUS_END_OF_FILE; }
    if(cbOffset < 8) {
        snprintf(pbBuffer, 9, "%08x", *pdwTarget);
        cb = (DWORD)min(8 - cbOffset, cb);
        memcpy(pbBuffer + cbOffset, pb, cb);
        pbBuffer[8] = 0;
        dw = strtoul(pbBuffer, NULL, 16);
        dw = max(dw, dwMinAllow);
        if(dwMaxAllow) {
            dw = min(dw, dwMaxAllow);
        }
        *pdwTarget = dw;
    }
    *pcbWrite = cb;
    return UTIL_NTSTATUS_SUCCESS;
}

NTSTATUS Util_VfsWriteFile_QWORD(_Inout_ PQWORD pqwTarget, _In_reads_(cb) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbWrite, _In_ QWORD cbOffset, _In_ QWORD qwMinAllow, _In_opt_ QWORD qwMaxAllow)
{
    QWORD qw;
    BYTE pbBuffer[17];
    if(cbOffset > 16) { return UTIL_NTSTATUS_END_OF_FILE; }
    if(cbOffset < 16) {
        snprintf(pbBuffer, 17, "%016llx", *pqwTarget);
        cb = (DWORD)min(16 - cbOffset, cb);
        memcpy(pbBuffer + cbOffset, pb, cb);
        pbBuffer[16] = 0;
        qw = strtoull(pbBuffer, NULL, 16);
        qw = max(qw, qwMinAllow);
        if(qwMaxAllow) {
            qw = min(qw, qwMaxAllow);
        }
        *pqwTarget = qw;
    }
    *pcbWrite = cb;
    return UTIL_NTSTATUS_SUCCESS;
}

VOID Util_VfsTimeStampFile(_In_ VMM_HANDLE H, _In_opt_ PVMM_PROCESS pProcess, _Out_ PVMMDLL_VFS_FILELIST_EXINFO pExInfo)
{
    pExInfo->dwVersion = VMMDLL_VFS_FILELIST_EXINFO_VERSION;
    pExInfo->fCompressed = pProcess && pProcess->dwState;
    pExInfo->qwCreationTime = VmmProcess_GetCreateTimeOpt(H, pProcess);
    pExInfo->qwLastWriteTime = (pProcess && pProcess->dwState) ? VmmProcess_GetExitTimeOpt(H, pProcess) : 0;
    if(!pExInfo->qwLastWriteTime) {
        pExInfo->qwLastWriteTime = pExInfo->qwCreationTime;
    }
}

LPSTR Util_StrDupA(_In_opt_ LPCSTR sz)
{
    SIZE_T cch;
    LPSTR szDup;
    if(!sz) { return NULL; }
    cch = 1 + strlen(sz);
    szDup = LocalAlloc(0, cch);
    if(szDup) {
        memcpy(szDup, sz, cch);
    }
    return szDup;
}

QWORD Util_FileTimeNow()
{
    QWORD ftNow;
#ifdef _WIN32
    SYSTEMTIME SystemTimeNow;
    GetSystemTime(&SystemTimeNow);
    SystemTimeToFileTime(&SystemTimeNow, (LPFILETIME)&ftNow);
#else
    ftNow = (time(NULL) * 10000000) + 116444736000000000;
#endif /* _WIN32 */
    return (QWORD)ftNow;
}

VOID Util_FileTime2String(_In_ QWORD ft, _Out_writes_(24) LPSTR szTime)
{
    SYSTEMTIME SystemTime;
    if(!ft || (ft > 0x0200000000000000)) {
        strcpy_s(szTime, 24, "                    ***");
        return;
    }
    FileTimeToSystemTime((PFILETIME)&ft, &SystemTime);
    sprintf_s(szTime, 24, "%04i-%02i-%02i %02i:%02i:%02i UTC",
        SystemTime.wYear,
        SystemTime.wMonth,
        SystemTime.wDay,
        SystemTime.wHour,
        SystemTime.wMinute,
        SystemTime.wSecond
    );
}

BOOL Util_FileTime2JSON(_In_ QWORD ft, _Out_writes_(21) LPSTR szTime)
{
    SYSTEMTIME SystemTime;
    if(!ft || (ft > 0x0200000000000000)) {
        sprintf_s(szTime, 21, "1601-01-01T00:00:00Z");
        return FALSE;
    }
    FileTimeToSystemTime((PFILETIME)&ft, &SystemTime);
    sprintf_s(szTime, 21, "%04i-%02i-%02iT%02i:%02i:%02iZ",
        SystemTime.wYear,
        SystemTime.wMonth,
        SystemTime.wDay,
        SystemTime.wHour,
        SystemTime.wMinute,
        SystemTime.wSecond
    );
    return TRUE;
}

VOID Util_FileTime2CSV(_In_ QWORD ft, _Out_writes_(22) LPSTR szTime)
{
    SYSTEMTIME SystemTime;
    if((ft < 0x0100000000000000) || (ft > 0x0200000000000000)) {
        szTime[0] = 0;
        return;
    }
    FileTimeToSystemTime((PFILETIME)&ft, &SystemTime);
    sprintf_s(szTime, 22, "\"%04i-%02i-%02i %02i:%02i:%02i\"",
        SystemTime.wYear,
        SystemTime.wMonth,
        SystemTime.wDay,
        SystemTime.wHour,
        SystemTime.wMinute,
        SystemTime.wSecond
    );
}

_Success_(return != 0)
QWORD Util_TimeIso8601ToFileTime(_In_ LPSTR szIso8601)
{
    QWORD ft = 0;
    SYSTEMTIME sSystemTime = { 0 };
    int iYear = 0, iMonth = 0, iDay = 0, iHour = 0, iMinute = 0, iSecond = 0, iMs = 0, iUs = 0;
    if(sscanf_s(szIso8601, "%4d-%2d-%2dT%2d:%2d:%2d.%3d%dZ", &iYear, &iMonth, &iDay, &iHour, &iMinute, &iSecond, &iMs, &iUs) != 8) { return 0; }
    sSystemTime.wYear = (WORD)iYear;
    sSystemTime.wMonth = (WORD)iMonth;
    sSystemTime.wDay = (WORD)iDay;
    sSystemTime.wHour = (WORD)iHour;
    sSystemTime.wMinute = (WORD)iMinute;
    sSystemTime.wSecond = (WORD)iSecond;
    sSystemTime.wMilliseconds = (WORD)iMs;
    SystemTimeToFileTime(&sSystemTime, (PFILETIME)&ft);
    return ft;
}

VOID Util_GuidToString(_In_reads_(16) PBYTE pb, _Out_writes_(37) LPSTR szGUID)
{
    typedef struct tdGUID {
        DWORD v1;
        WORD  v2;
        WORD  v3;
        BYTE  v4[8];
    } *PGUID;
    PGUID g = (PGUID)pb;
    _snprintf_s(szGUID, 37, _TRUNCATE,
        "%08X-%04hX-%04hX-%02hhX%02hhX-%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX",
        g->v1, g->v2, g->v3,
        g->v4[0], g->v4[1], g->v4[2], g->v4[3], g->v4[4], g->v4[5], g->v4[6], g->v4[7]
    );
}

int Util_qsort_DWORD(const void *pdw1, const void *pdw2)
{
    DWORD dw1 = *(PDWORD)pdw1;
    DWORD dw2 = *(PDWORD)pdw2;
    return
        (dw1 < dw2) ? -1 :
        (dw1 > dw2) ? 1 : 0;
}

int Util_qsort_QWORD(const void *pqw1, const void *pqw2)
{
    QWORD qw1 = *(PQWORD)pqw1;
    QWORD qw2 = *(PQWORD)pqw2;
    return
        (qw1 < qw2) ? -1 :
        (qw1 > qw2) ? 1 : 0;
}

int Util_qfind_CmpFindTableDWORD(_In_ QWORD qwFindIn, _In_ QWORD qwEntryIn)
{
    DWORD dwKey = (DWORD)qwFindIn;
    DWORD dwEntry = *(PDWORD)qwEntryIn;
    if(dwEntry > dwKey) { return -1; }
    if(dwEntry < dwKey) { return 1; }
    return 0;
}

int Util_qfind_CmpFindTableQWORD(_In_ QWORD qwFindIn, _In_ QWORD qwEntryIn)
{
    QWORD qwKey = (QWORD)qwFindIn;
    QWORD qwEntry = *(PQWORD)qwEntryIn;
    if(qwEntry > qwKey) { return -1; }
    if(qwEntry < qwKey) { return 1; }
    return 0;
}

_Success_(return != NULL)
PVOID Util_qfind_ex(_In_ QWORD qwFind, _In_ DWORD cMap, _In_ PVOID pvMap, _In_ DWORD cbEntry, _In_ UTIL_QFIND_CMP_PFN pfnCmp, _Out_opt_ PDWORD piMapOpt)
{
    int f;
    DWORD i, cbSearch, cbStep, cbMap;
    PBYTE pbMap = pvMap;
    if(!cMap || !cbEntry) { return NULL; }
    for(i = 1; ((cMap - 1) >> i); i++);
    cbMap = cMap * cbEntry;
    cbSearch = cbEntry * min(1UL << (i - 1), cMap - 1);
    cbStep = max(cbEntry, cbSearch >> 1);
    while(cbStep >= cbEntry) {
        f = pfnCmp(qwFind, (QWORD)(pbMap + cbSearch));
        if(f < 0) {
            cbSearch -= cbStep;
        } else if(f > 0) {
            if(cbSearch + cbStep < cbMap) {
                cbSearch += cbStep;
            }
        } else {
            if(piMapOpt) { *piMapOpt = cbSearch / cbEntry; }
            return pbMap + cbSearch;
        }
        cbStep = cbStep >> 1;
    }
    if(cbSearch < cbMap) {
        if(!pfnCmp(qwFind, (QWORD)(pbMap + cbSearch))) {
            if(piMapOpt) { *piMapOpt = cbSearch / cbEntry; }
            return pbMap + cbSearch;
        }
        if((cbSearch >= cbEntry) && !pfnCmp(qwFind, (QWORD)(pbMap + cbSearch - cbEntry))) {
            if(piMapOpt) { *piMapOpt = (cbSearch - cbEntry) / cbEntry; }
            return pbMap + cbSearch - cbEntry;
        }
    }
    return NULL;
}

/*
* Find an entry in a sorted array in an efficient way - O(log2(n)).
* -- pvFind
* -- cMap
* -- pvMap
* -- cbEntry
* -- pfnCmp
* -- return = the entry found or NULL on failure.
*/
_Success_(return != NULL)
PVOID Util_qfind(_In_ QWORD qwFind, _In_ DWORD cMap, _In_ PVOID pvMap, _In_ DWORD cbEntry, _In_ UTIL_QFIND_CMP_PFN pfnCmp)
{
    return Util_qfind_ex(qwFind, cMap, pvMap, cbEntry, pfnCmp, NULL);
}

_Success_(return)
BOOL Util_VfsHelper_GetIdDir(_In_ LPCSTR uszPath, _In_ BOOL fHex, _Out_ PDWORD pdwID, _Out_opt_ LPCSTR *puszSubPath)
{
    CHAR c;
    DWORD i = 0, iSubPath = 0;
    // 1: Check if starting with PID/NAME/BY-ID/BY-NAME
    if(!_strnicmp(uszPath, "pid\\", 4)) {
        i = 4;
    } else if(!_strnicmp(uszPath, "name\\", 5)) {
        i = 5;
    } else if(!_strnicmp(uszPath, "by-id\\", 6)) {
        i = 6;
    } else if(!_strnicmp(uszPath, "by-name\\", 8)) {
        i = 8;
    } else if(!_strnicmp(uszPath, "by-tag\\", 7)) {
        i = 7;
    } else {
        return FALSE;
    }
    // 3: Locate start of PID/ID number and 1st Path item (if any)
    while((i < MAX_PATH) && uszPath[i] && (uszPath[i] != '\\')) { i++; }
    iSubPath = ((i < MAX_PATH - 1) && (uszPath[i] == '\\')) ? (i + 1) : i;
    i--;
    if(fHex) {
        while((c = uszPath[i]) && (((c >= '0') && (c <= '9')) || ((c >= 'a') && (c <= 'f')) || ((c >= 'A') && (c <= 'F')))) { i--; }
        i++;
        if(!((c = uszPath[i]) && (((c >= '0') && (c <= '9')) || ((c >= 'a') && (c <= 'f')) || ((c >= 'A') && (c <= 'F'))))) { return FALSE; }
        *pdwID = strtoul(uszPath + i, NULL, 16);
    } else {
        while((c = uszPath[i]) && (c >= '0') && (c <= '9')) { i--; }
        i++;
        if(!((c = uszPath[i]) && (c >= '0') && (c <= '9'))) { return FALSE; }
        *pdwID = strtoul(uszPath + i, NULL, 10);
    }
    if(puszSubPath) {
        *puszSubPath = uszPath + iSubPath;
    }
    return TRUE;
}

#define UTIL_VFSLINEFIXED_LINEPAD512 \
    "----------------------------------------------------------------" \
    "----------------------------------------------------------------" \
    "----------------------------------------------------------------" \
    "----------------------------------------------------------------" \
    "----------------------------------------------------------------" \
    "----------------------------------------------------------------" \
    "----------------------------------------------------------------" \
    "----------------------------------------------------------------"

/*
* VariableLineRead: Read from a file dynamically created from a map/array object
* using a callback function to populate individual lines (excluding header).
* -- H = VMM handle.
* -- pfnCallback = callback function to populate individual lines.
* -- ctx = optional context to 'pfn' callback function.
* -- uszHeader = optional header line.
* -- pMap = an array of entries (usually 'pMap' in a map).
* -- cMap = number of pMap entries.
* -- cbEntry = byte length of each entry.
* -- pdwLineOffset = array of line end offsets (excl. header).
* -- pb
* -- cb
* -- pcbRead
* -- cbOffset
* -- return
*/
NTSTATUS Util_VfsLineVariable_Read(
    _In_ VMM_HANDLE H,
    _In_ UTIL_VFSLINEFIXED_PFN_CB pfnCallback,
    _Inout_opt_ PVOID ctx,
    _In_opt_ LPCSTR uszHeader,
    _In_ PVOID pMap,
    _In_ DWORD cMap,
    _In_ DWORD cbEntry,
    _In_reads_(cMap + 1) PDWORD pdwLineOffset,
    _Out_writes_to_(cb, *pcbRead) PBYTE pb,
    _In_ DWORD cb,
    _Out_ PDWORD pcbRead,
    _In_ QWORD cbOffset
) {
    NTSTATUS nt = UTIL_NTSTATUS_SUCCESS;
    DWORD ie, iStep;
    DWORD cbLineLength, cbLineStartOffset;
    DWORD cbHeaderLine;
    DWORD cbRead, cbReadTotal = 0;
    CHAR szu[0x1000];
    PVOID pvMapEntry;
    *pcbRead = 0;
    // header parse
    if(uszHeader && H->cfg.fFileInfoHeader && (cbOffset < 0x400)) {
        cbHeaderLine = uszHeader ? ((DWORD)strlen(uszHeader) + 1) : 0;
        if(cbOffset < 2ULL * cbHeaderLine) {
            _snprintf_s(szu, sizeof(szu), _TRUNCATE, "%s\n%.*s\n", uszHeader, cbHeaderLine - 1, UTIL_VFSLINEFIXED_LINEPAD512);
            nt = Util_VfsReadFile_FromPBYTE(szu, 2ULL * cbHeaderLine, pb, cb, &cbRead, cbOffset);
            pb += cbRead;
            cb -= cbRead;
            cbOffset += cbRead;
            cbReadTotal += cbRead;
            if(!cb) {
                *pcbRead = cbReadTotal;
                return nt;
            }
        }
        cbOffset -= 2ULL * cbHeaderLine;
    }
    // find base efficiently
    if(!cMap) { goto finish; }
    if(cbOffset >= pdwLineOffset[cMap - 1]) { nt = STATUS_END_OF_FILE;  goto finish; }
    ie = cMap / 2;
    iStep = cMap / 4;
    while(iStep > 1) {
        if(cbOffset <= pdwLineOffset[ie]) {
            if((ie >= iStep) && (cbOffset <= pdwLineOffset[ie - iStep])) { ie -= iStep; }
        } else {
            if((ie + iStep < cMap) && (cbOffset > pdwLineOffset[ie + iStep])) { ie += iStep; }
        }
        iStep = iStep / 2;
    }
    while(TRUE) {
        if(ie) {
            if(cbOffset == pdwLineOffset[ie - 1]) { break; }
            if(cbOffset < pdwLineOffset[ie - 1]) { ie--; continue; }
        }
        if((ie < cMap - 1) && (cbOffset > pdwLineOffset[ie])) { ie++; continue; }
        break;
    }
    // parse lines
    while(cb && (ie < cMap)) {
        pvMapEntry = (PBYTE)pMap + ie * (QWORD)cbEntry;
        cbLineStartOffset = ie ? pdwLineOffset[ie - 1] : 0;
        cbLineLength = pdwLineOffset[ie] - cbLineStartOffset;
        if((cbOffset == cbLineStartOffset) && (cb > cbLineLength)) {
            // entry fits into line
            pfnCallback(H, ctx, cbLineLength, ie, pvMapEntry, (LPSTR)pb);
            pb += cbLineLength;
            cb -= cbLineLength;
            cbOffset += cbLineLength;
            cbReadTotal += cbLineLength;
            nt = UTIL_NTSTATUS_SUCCESS;
        } else {
            // partial line
            if(cbLineLength + 1ULL > sizeof(szu)) { return UTIL_NTSTATUS_FILE_INVALID; }
            pfnCallback(H, ctx, cbLineLength, ie, pvMapEntry, szu);
            nt = Util_VfsReadFile_FromPBYTE(szu, cbLineLength, pb, cb, &cbRead, cbOffset - cbLineStartOffset);
            pb += cbRead;
            cb -= cbRead;
            cbOffset += cbRead;
            cbReadTotal += cbRead;
        }
        ie++;
    }
finish:
    *pcbRead = cbReadTotal;
    return nt;
}

/*
* FixedLineRead: Read from a file dynamically created from a map/array object
* using a callback function to populate individual lines (excluding header).
* -- H = VMM handle.
* -- pfnCallback = callback function to populate individual lines.
* -- ctx = optional context to 'pfn' callback function.
* -- cbLineLength = line length, including newline, excluding null terminator.
* -- uszHeader = optional header line.
* -- pMap = an array of entries (usually 'pMap' in a map).
* -- cMap = number of pMap entries.
* -- cbEntry = byte length of each entry.
* -- pb
* -- cb
* -- pcbRead
* -- cbOffset
* -- return
*/
NTSTATUS Util_VfsLineFixed_Read(
    _In_ VMM_HANDLE H,
    _In_ UTIL_VFSLINEFIXED_PFN_CB pfnCallback,
    _Inout_opt_ PVOID ctx,
    _In_ DWORD cbLineLength,
    _In_opt_ LPCSTR uszHeader,
    _In_ PVOID pMap,
    _In_ DWORD cMap,
    _In_ DWORD cbEntry,
    _Out_writes_to_(cb, *pcbRead) PBYTE pb,
    _In_ DWORD cb,
    _Out_ PDWORD pcbRead,
    _In_ QWORD cbOffset
) {
    LPSTR usz;
    NTSTATUS nt;
    PVOID pvMapEntry;
    QWORD i, iMapEntry, o = 0, cbMax, cStart, cEnd, cHeader;
    cHeader = (uszHeader && H->cfg.fFileInfoHeader) ? 2 : 0;
    cStart = (DWORD)(cbOffset / cbLineLength);
    cEnd = (DWORD)min(cHeader + cMap - 1, (cb + cbOffset + cbLineLength - 1) / cbLineLength);
    cbMax = 1 + (1 + cEnd - cStart) * cbLineLength;
    if(!cHeader && !cMap) { return VMMDLL_STATUS_END_OF_FILE; }
    if((cStart > cHeader + cMap)) { return VMMDLL_STATUS_END_OF_FILE; }
    if(!(usz = LocalAlloc(LMEM_ZEROINIT, (SIZE_T)cbMax))) { return VMMDLL_STATUS_FILE_INVALID; }
    for(i = cStart; i <= cEnd; i++) {
        // header:
        if(i < cHeader) {
            o += i ?
                Util_usnprintf_ln(usz + o, cbLineLength, "%.*s", (DWORD)strlen(uszHeader), UTIL_VFSLINEFIXED_LINEPAD512) :
                Util_usnprintf_ln(usz + o, cbLineLength, "%s", uszHeader);
            continue;
        }
        // line:
        iMapEntry = i - cHeader;
        pvMapEntry = (PBYTE)pMap + iMapEntry * cbEntry;
        pfnCallback(H, ctx, cbLineLength, (DWORD)iMapEntry, pvMapEntry, usz + o);
        o += cbLineLength;
    }
    nt = Util_VfsReadFile_FromPBYTE(usz, cbMax - 1, pb, cb, pcbRead, cbOffset - cStart * cbLineLength);
    LocalFree(usz);
    return nt;
}

/*
* FixedLineRead: Read from a file dynamically created from a custom generator
* callback function using using a callback function to populate individual lines
* (excluding header).
* -- H = VMM handle.
* -- pfnCallback = callback function to populate individual lines.
* -- ctx = optional context to 'pfn' callback function.
* -- cbLineLength = line length, including newline, excluding null terminator.
* -- wszHeader = optional header line.
* -- pMap = 'map context' for single entry callback function.
* -- cMap = max number of entries entry callback function will generate.
* -- pfnMap = callback function to retrieve entry.
* -- pb
* -- cb
* -- pcbRead
* -- cbOffset
* -- return
*/
NTSTATUS Util_VfsLineFixedMapCustom_Read(
    _In_ VMM_HANDLE H,
    _In_ UTIL_VFSLINEFIXED_PFN_CB pfnCallback,
    _Inout_opt_ PVOID ctx,
    _In_ DWORD cbLineLength,
    _In_opt_ LPCSTR uszHeader,
    _In_ PVOID ctxMap,
    _In_ DWORD cMap,
    _In_ UTIL_VFSLINEFIXED_MAP_PFN_CB pfnMap,
    _Out_writes_to_(cb, *pcbRead) PBYTE pb,
    _In_ DWORD cb,
    _Out_ PDWORD pcbRead,
    _In_ QWORD cbOffset
) {
    LPSTR usz;
    NTSTATUS nt;
    PVOID pvMapEntry;
    QWORD i, iMapEntry, o = 0, cbMax, cStart, cEnd, cHeader;
    cHeader = (uszHeader && H->cfg.fFileInfoHeader) ? 2 : 0;
    cStart = (DWORD)(cbOffset / cbLineLength);
    cEnd = (DWORD)min(cHeader + cMap - 1, (cb + cbOffset + cbLineLength - 1) / cbLineLength);
    cbMax = 1 + (1 + cEnd - cStart) * cbLineLength;
    if(!cHeader && !cMap) { return VMMDLL_STATUS_END_OF_FILE; }
    if((cStart > cHeader + cMap)) { return VMMDLL_STATUS_END_OF_FILE; }
    if(!(usz = LocalAlloc(LMEM_ZEROINIT, (SIZE_T)cbMax))) { return VMMDLL_STATUS_FILE_INVALID; }
    for(i = cStart; i <= cEnd; i++) {
        // header:
        if(i < cHeader) {
            o += i ?
                Util_usnprintf_ln(usz + o, cbLineLength, "%.*s", (DWORD)strlen(uszHeader), UTIL_VFSLINEFIXED_LINEPAD512) :
                Util_usnprintf_ln(usz + o, cbLineLength, "%s", uszHeader);
            continue;
        }
        // line:
        iMapEntry = i - cHeader;
        pvMapEntry = pfnMap(H, ctxMap, (DWORD)iMapEntry);
        pfnCallback(H, ctx, cbLineLength, (DWORD)iMapEntry, pvMapEntry, usz + o);
        o += cbLineLength;
    }
    nt = Util_VfsReadFile_FromPBYTE(usz, cbMax - 1, pb, cb, pcbRead, cbOffset - cStart * cbLineLength);
    LocalFree(usz);
    return nt;
}

/*
* Retrieve the operating system path of the directory which is containing this:
* .dll/.so file.
* -- szPath
*/
VOID Util_GetPathLib(_Out_writes_(MAX_PATH) PCHAR szPath)
{
    SIZE_T i;
    ZeroMemory(szPath, MAX_PATH);
#ifdef _WIN32
    HMODULE hModuleVmm;
    WCHAR wszPath[MAX_PATH] = { 0 };
    hModuleVmm = LoadLibraryU("vmm.dll");
    GetModuleFileNameW(hModuleVmm, wszPath, MAX_PATH - 4);
    CharUtil_WtoU(wszPath, -1, (PBYTE)szPath, MAX_PATH, NULL, NULL, CHARUTIL_FLAG_STR_BUFONLY | CHARUTIL_FLAG_TRUNCATE);
    if(hModuleVmm) { FreeLibrary(hModuleVmm); }
#endif /* _WIN32 */
#if defined(LINUX) || defined(MACOS)
    Dl_info Info = { 0 };
    if(!dladdr((void *)Util_GetPathLib, &Info) || !Info.dli_fname) {
        GetModuleFileNameA(NULL, szPath, MAX_PATH - 4);
    } else {
        strncpy(szPath, Info.dli_fname, MAX_PATH - 1);
    }
#endif /* LINUX || MACOS */
    for(i = strlen(szPath) - 1; i > 0; i--) {
        if(szPath[i] == '/' || szPath[i] == '\\') {
            szPath[i + 1] = '\0';
            return;
        }
    }
}

VOID Util_GetPathDll(_Out_writes_(MAX_PATH) PCHAR szPath, _In_opt_ HMODULE hModule)
{
    SIZE_T i;
    GetModuleFileNameA(hModule, szPath, MAX_PATH - 4);
    for(i = strlen(szPath) - 1; i > 0; i--) {
        if(szPath[i] == '/' || szPath[i] == '\\') {
            szPath[i + 1] = '\0';
            return;
        }
    }
}

/*
* Utility function to check whether a buffer is zeroed.
* -- pb
* -- cb
* -- return
*/
BOOL Util_IsZeroBuffer(_In_ PBYTE pb, _In_ DWORD cb)
{
    static const BYTE pbZERO[0x1000] = { 0 };
    while(cb >= 0x1000) {
        if(memcmp(pb, pbZERO, 0x1000)) { return FALSE; }
        pb += 0x1000;
        cb -= 0x1000;
    }
    if(cb) {
        if(memcmp(pb, pbZERO, cb)) { return FALSE; }
    }
    return TRUE;
}

/*
* GZIP decompresses a buffer of known length.
* NOTE! Function does not guarantee that the buffer is null-terminated.
* -- cbCompressed = binary gzipped data.
* -- cbCompressed = length of gzipped data.
* -- cbDecompressed = length of decompressed data. NB! must exactly match the length of the decompressed data.
* -- pbDecompressed = buffer to store decompressed data.
* -- return
*/
_Success_(return)
BOOL Util_DecompressGz(_In_ PBYTE pbCompressed, _In_ DWORD cbCompressed, _In_ DWORD cbDecompressed, _Out_writes_(cbDecompressed) PBYTE pbDecompressed)
{
    z_stream stream = { 0 };
    stream.next_in = pbCompressed;
    stream.avail_in = cbCompressed;
    stream.next_out = pbDecompressed;
    stream.avail_out = cbDecompressed;
    if(Z_OK != inflateInit(&stream)) { return FALSE; }
    if(Z_STREAM_END != inflate(&stream, Z_FINISH)) { return FALSE; }
    return (Z_OK == inflateEnd(&stream)) && (stream.avail_out == 0);
}

/*
* GZIP decompresses a buffer of known length and allocated the decompressed
* data into a null-terminated string.
* CALLER LocalFree: *pszDecompressed
* -- pbCompressed = binary gzipped data.
* -- cbCompressed = length of gzipped data.
* -- cbDecompressed = length of decompressed data (excl. null terminator).
* -- pszDecompressed
* -- return
*/
_Success_(return)
BOOL Util_DecompressGzToStringAlloc(_In_ PBYTE pbCompressed, _In_ DWORD cbCompressed, _In_ DWORD cbDecompressed, _Out_ LPSTR * pszDecompressed)
{
    LPSTR szDecompressed = LocalAlloc(0, (SIZE_T)cbDecompressed + 1);
    if(!szDecompressed) { return FALSE; }
    if(!Util_DecompressGz(pbCompressed, cbCompressed, cbDecompressed, (PBYTE)szDecompressed)) {
        LocalFree(szDecompressed);
        return FALSE;
    }
    szDecompressed[cbDecompressed] = 0;
    *pszDecompressed = szDecompressed;
    return TRUE;
}

#ifdef _WIN32

/*
* SHA256 hash data.
* -- pbData
* -- cbData
* -- pbHash
* -- return
*/
_Success_(return)
BOOL Util_HashSHA256(_In_reads_(cbData) PBYTE pbData, _In_ DWORD cbData, _Out_writes_(32) PBYTE pbHash)
{
    BOOL fResult = FALSE;
    DWORD cbHashObject, cbHashObjectLen;
    PBYTE pbHashObject = NULL;
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    if(BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, 0)) { goto fail; }
    if(BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PBYTE)&cbHashObject, sizeof(DWORD), &cbHashObjectLen, 0)) { goto fail; }
    if(!(pbHashObject = LocalAlloc(LMEM_ZEROINIT, cbHashObject))) { goto fail; }
    if(BCryptCreateHash(hAlg, &hHash, pbHashObject, cbHashObject, NULL, 0, 0)) { goto fail; }
    if(BCryptHashData(hHash, pbData, cbData, 0)) { goto fail; }
    if(BCryptFinishHash(hHash, pbHash, 32, 0)) { goto fail; }
    fResult = TRUE;
fail:
    if(hHash) { BCryptDestroyHash(hHash); }
    LocalFree(pbHashObject);
    if(hAlg) { BCryptCloseAlgorithmProvider(hAlg, 0); }
    return fResult;
}

DWORD Util_ResourceSize(_In_ VMM_HANDLE H, _In_ LPWSTR wszResourceName)
{
    HRSRC hRes;
    if(!(hRes = FindResource(H->vmm.hModuleVmmOpt, wszResourceName, RT_RCDATA))) { return 0; }
    return SizeofResource(H->vmm.hModuleVmmOpt, hRes);
}

NTSTATUS Util_VfsReadFile_FromResource(_In_ VMM_HANDLE H, _In_ LPWSTR wszResourceName, _Out_writes_to_(cb, *pcbRead) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset)
{
    HRSRC hRes;
    HGLOBAL hResGlobal;
    DWORD cbRes;
    PBYTE pbRes;
    if(!(hRes = FindResource(H->vmm.hModuleVmmOpt, wszResourceName, RT_RCDATA))) { goto fail; }
    if(!(hResGlobal = LoadResource(H->vmm.hModuleVmmOpt, hRes))) { goto fail; }
    if(!(pbRes = (PBYTE)LockResource(hResGlobal))) { goto fail; }
    cbRes = SizeofResource(H->vmm.hModuleVmmOpt, hRes);
    return Util_VfsReadFile_FromPBYTE(pbRes, cbRes, pb, cb, pcbRead, cbOffset);
fail:
    return VMMDLL_STATUS_FILE_INVALID;
}

/*
* Delete a file denoted by its utf-8 full path.
* -- uszPathFile
*/
VOID Util_DeleteFileU(_In_ LPCSTR uszPathFile)
{
    WCHAR wszWinPath[MAX_PATH];
    if(CharUtil_UtoW(uszPathFile, -1, (PBYTE)wszWinPath, sizeof(wszWinPath), NULL, NULL, CHARUTIL_FLAG_STR_BUFONLY)) {
        DeleteFileW(wszWinPath);
    }
}

#endif /* _WIN32 */
#if defined(LINUX) || defined(MACOS)

/*
* SHA256 hash data.
* (implementation is quite slow)
* -- pbData
* -- cbData
* -- pbHash
* -- return
*/
_Success_(return)
BOOL Util_HashSHA256(_In_reads_(cbData) PBYTE pbData, _In_ DWORD cbData, _Out_writes_(32) PBYTE pbHash)
{
    SHA256_CTX sha256;
    ZeroMemory(pbHash, 32);
    sha256_init(&sha256);
    sha256_update(&sha256, pbData, cbData);
    sha256_final(&sha256, pbHash);
    return TRUE;
}

/*
* Delete a file denoted by its utf-8 full path.
* -- uszPathFile
*/
VOID Util_DeleteFileU(_In_ LPCSTR uszPathFile)
{
    remove(uszPathFile);
}

DWORD Util_ResourceSize(_In_ VMM_HANDLE H, _In_ LPWSTR wszResourceName) { return 0; }
NTSTATUS Util_VfsReadFile_FromResource(_In_ VMM_HANDLE H, _In_ LPWSTR wszResourceName, _Out_writes_to_(cb, *pcbRead) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset) { return VMMDLL_STATUS_FILE_INVALID; }
#endif /* LINUX || MACOS */