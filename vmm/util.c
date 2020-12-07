// util.c : implementation of various utility functions.
//
// (c) Ulf Frisk, 2018-2020
// Author: Ulf Frisk, pcileech@frizk.net
//
#include "util.h"
#include <math.h>

/*
* Calculate the number of digits of an integer number.
*/
DWORD Util_GetNumDigits(_In_ DWORD dwNumber)
{
    return (DWORD)max(1, floor(log10(dwNumber) + 1));
}

QWORD Util_GetNumericA(_In_ LPSTR sz)
{
    if((strlen(sz) > 1) && (sz[0] == '0') && ((sz[1] == 'x') || (sz[1] == 'X'))) {
        return strtoull(sz, NULL, 16); // Hex (starts with 0x)
    } else {
        return strtoull(sz, NULL, 10); // Not Hex -> try Decimal
    }
}

QWORD Util_GetNumericW(_In_ LPWSTR wsz)
{
    if((wcslen(wsz) > 1) && (wsz[0] == '0') && ((wsz[1] == 'x') || (wsz[1] == 'X'))) {
        return wcstoull(wsz, NULL, 16); // Hex (starts with 0x)
    } else {
        return wcstoull(wsz, NULL, 10); // Not Hex -> try Decimal
    }
}

DWORD Util_HashStringA(_In_opt_ LPCSTR sz)
{
    CHAR c;
    DWORD i = 0, dwHash = 0;
    if(!sz) { return 0; }
    while(TRUE) {
        c = sz[i++];
        if(!c) { return dwHash; }
        dwHash = ((dwHash >> 13) | (dwHash << 19)) + c;
    }
}

DWORD Util_HashStringUpperA(_In_opt_ LPCSTR sz)
{
    CHAR c;
    DWORD i = 0, dwHash = 0;
    if(!sz) { return 0; }
    while(TRUE) {
        c = sz[i++];
        if(!c) { return dwHash; }
        if(c >= 'a' && c <= 'z') {
            c += 'A' - 'a';
        }
        dwHash = ((dwHash >> 13) | (dwHash << 19)) + c;
    }
}

DWORD Util_HashStringUpperW(_In_opt_ LPCWSTR wsz)
{
    WCHAR c;
    DWORD i = 0, dwHash = 0;
    if(!wsz) { return 0; }
    while(TRUE) {
        c = wsz[i++];
        if(!c) { return dwHash; }
        if(c >= 'a' && c <= 'z') {
            c += 'A' - 'a';
        }
        dwHash = ((dwHash >> 13) | (dwHash << 19)) + c;
    }
}

/*
* Hash a registry key name in a way that is supported by the file system.
* NB! this is not the same hash as the Windows registry uses.
* -- wsz
* -- iSuffix
* -- return
*/
DWORD Util_HashNameW_Registry(_In_ LPCWSTR wsz, _In_opt_ DWORD iSuffix)
{
    DWORD i, c, dwHash = 0;
    WCHAR wszBuffer[MAX_PATH];
    c = Util_PathFileNameFix_Registry(wszBuffer, NULL, wsz, 0, iSuffix, TRUE);
    for(i = 0; i < c; i++) {
        dwHash = ((dwHash >> 13) | (dwHash << 19)) + wszBuffer[i];
    }
    return dwHash;
}

/*
* Hash a path. Used to calculate a registry key hash from a file system path.
* -- wszPath
* -- return
*/
QWORD Util_HashPathW_Registry(_In_ LPWSTR wszPath)
{
    DWORD dwHashName;
    QWORD qwHashTotal = 0;
    WCHAR wsz1[MAX_PATH];
    while(wszPath && wszPath[0]) {
        wszPath = Util_PathSplit2_ExWCHAR(wszPath, wsz1, _countof(wsz1));
        dwHashName = Util_HashNameW_Registry(wsz1, 0);
        qwHashTotal = dwHashName + ((qwHashTotal >> 13) | (qwHashTotal << 51));
    }
    return qwHashTotal;
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

VOID Util_PrintHexAscii(_In_reads_(cb) PBYTE pb, _In_ DWORD cb, _In_ DWORD cbInitialOffset)
{
    DWORD szMax = 0;
    LPSTR sz;
    if(cb > 0x10000) {
        vmmprintf("Large output. Only displaying first 65kB.\n");
        cb = 0x10000 - cbInitialOffset;
    }
    Util_FillHexAscii(pb, cb, cbInitialOffset, NULL, &szMax);
    if(!(sz = LocalAlloc(0, szMax))) { return; }
    Util_FillHexAscii(pb, cb, cbInitialOffset, sz, &szMax);
    vmmprintf("%s", sz);
    LocalFree(sz);
}

VOID Util_AsciiFileNameFix(_In_ LPSTR sz, _In_ CHAR chDefault)
{
    DWORD i = 0;
    while(sz[i]) {
        if(UTIL_ASCIIFILENAME_ALLOW[sz[i]] == '0') { sz[i] = chDefault; }
        i++;
    }
}

DWORD Util_PathFileNameFixA(_Out_writes_(MAX_PATH) LPWSTR wszOut, _In_ LPCSTR sz, _In_opt_ DWORD csz)
{
    WCHAR ch;
    DWORD i = 0, iMax = (csz ? min(csz, MAX_PATH - 1) : (MAX_PATH - 1));
    while((ch = sz[i]) && (i < iMax)) {
        wszOut[i] = ((ch < 128) && (UTIL_ASCIIFILENAME_ALLOW[ch] == '0')) ? '_' : ch;
        i++;
    }
    if(i && (wszOut[i - 1] == '.')) { wszOut[i - 1] = '_'; }
    wszOut[i] = 0;
    return i;
}

DWORD Util_PathFileNameFixW(_Out_writes_(MAX_PATH) LPWSTR wszOut, _In_ LPCWSTR wsz, _In_opt_ DWORD cwsz)
{
    WCHAR ch;
    DWORD i = 0, iMax = (cwsz ? min(cwsz, MAX_PATH - 1) : (MAX_PATH - 1));
    while((ch = wsz[i]) && (i < iMax)) {
        wszOut[i] = ((ch < 128) && (UTIL_ASCIIFILENAME_ALLOW[ch] == '0')) ? '_' : ch;
        i++;
    }
    if(i && (wszOut[i - 1] == '.')) { wszOut[i - 1] = '_'; }
    wszOut[i] = 0;
    return i;
}

DWORD Util_PathFileNameFix_Registry(_Out_writes_(MAX_PATH) LPWSTR wszOut, _In_opt_ LPCSTR sz, _In_opt_ LPCWSTR wsz, _In_opt_ DWORD cwsz, _In_opt_ DWORD iSuffix, _In_ BOOL fUpper)
{
    WCHAR ch;
    DWORD i = 0, iMax = (cwsz ? min(cwsz, MAX_PATH - 1) : (MAX_PATH - 1));
    if(sz || wsz) {
        while((ch = (sz ? sz[i] : wsz[i])) && (i < iMax)) {
            if(fUpper && ch >= 'a' && ch <= 'z') {
                ch += 'A' - 'a';
            } else if(ch < 128) {
                ch = (UTIL_ASCIIFILENAME_ALLOW[ch] == '0') ? '_' : ch;
            }
            wszOut[i] = ch;
            i++;
        }
    }
    if(iSuffix) {
        if((iSuffix < 10) && (i < MAX_PATH - 3)) {
            wszOut[i++] = '-';
            wszOut[i++] = '0' + (WCHAR)iSuffix;
        } else if((iSuffix < 100) && (i < MAX_PATH - 4)) {
            wszOut[i++] = '-';
            wszOut[i++] = '0' + (WCHAR)(iSuffix / 10);
            wszOut[i++] = '0' + (WCHAR)(iSuffix % 10);
        }
    }
    if(i && (wszOut[i - 1] == '.')) { wszOut[i - 1] = '_'; }
    wszOut[i] = 0;
    return i;
}

QWORD Util_PathGetBaseFromW(_In_ LPWSTR wsz)
{
    if((wcslen(wsz) < 15) || (wsz[0] != '0') || (wsz[1] != 'x')) { return (ULONG64)-1; }
    return wcstoull(wsz, NULL, 16);
}

LPWSTR Util_PathSplitNextW(_In_ LPWSTR wsz)
{
    WCHAR ch;
    DWORD i = 0;
    while(TRUE) {
        ch = wsz[i++];
        if(ch == '\0') {
            return wsz + i - 1;
        }
        if(ch == '\\') {
            return wsz + i;
        }
    }
}

LPSTR Util_PathSplitLastA(_In_ LPSTR sz)
{
    LPSTR szResult = sz;
    WCHAR ch;
    DWORD i = 0;
    while(TRUE) {
        ch = sz[i++];
        if(ch == '\0') {
            return szResult;
        }
        if(ch == '\\') {
            szResult = sz + i;
        }
    }
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

LPWSTR Util_PathSplit2_ExWCHAR(_In_ LPWSTR wsz, _Out_writes_(cwsz1) LPWSTR wsz1, _In_ DWORD cwsz1)
{
    WCHAR wch;
    DWORD i = 0;
    while((wch = wsz[i]) && (wch != '\\') && (i < cwsz1 - 1)) {
        wsz1[i++] = wch;
    }
    wsz1[i] = 0;
    return wsz[i] ? &wsz[i + 1] : L"";
}

VOID Util_PathPrependVA(_Out_writes_(MAX_PATH) LPWSTR wszDstBuffer, _In_ QWORD va, _In_ BOOL f32, _In_ LPWSTR wszText)
{
    _snwprintf_s(wszDstBuffer, MAX_PATH, _TRUNCATE, (f32 ? L"%08x-%s" : L"%016llx-%s"), va, wszText);
}

int Util_wcsstrncmp(_In_ LPSTR sz, _In_ LPWSTR wsz, _In_opt_ DWORD cMax)
{
    DWORD i;
    cMax = cMax ? cMax : (DWORD)-1;
    for(i = 0; i < cMax; i++) {
        if(sz[i] != wsz[i]) { return 1; }
        if(!sz[i]) { return 0; }
    }
    return 0;
}

_Success_(return >= 0)
size_t Util_snwprintf_u8(
    _Out_writes_(cbBuffer) LPSTR szBuffer,
    _In_ QWORD cbBuffer,
    _In_z_ _Printf_format_string_ LPWSTR wszFormat,
    ...
)
{
    int cch;
    va_list arglist;
    WCHAR wszBufferTiny[MAX_PATH];
    LPWSTR wszBuffer;
    if(cbBuffer == 0) { return 0; }
    if(cbBuffer == 1) {
        szBuffer[0] = '\0';
        return 0;
    }
    // 1: alloc/assign wchar buffer
    if(cbBuffer < _countof(wszBufferTiny)) {
        wszBuffer = wszBufferTiny;
    } else {
        wszBuffer = LocalAlloc(0, cbBuffer * sizeof(WCHAR));
        if(!wszBuffer) {
            szBuffer[0] = '\0';
            goto fail;
        }
    }
    // 2: write to whar buffer
    va_start(arglist, wszFormat);
    cch = _vsnwprintf_s(wszBuffer, cbBuffer, _TRUNCATE, wszFormat, arglist);
    va_end(arglist);
    if(cch < 0) { cch = (int)cbBuffer - 1; }
    // 3: convert to utf-8
    while((0 == WideCharToMultiByte(CP_UTF8, 0, wszBuffer, -1, szBuffer, (int)cbBuffer, NULL, NULL)) && cch) {
        wszBuffer[--cch] = '\0';
    }
fail:
    if(wszBuffer != wszBufferTiny) { LocalFree(wszBuffer); }
    return strlen(szBuffer);
}

_Success_(return >= 0)
DWORD Util_snwprintf_u8ln(
    _Out_writes_(cszLineLength+1) LPSTR szBuffer,
    _In_ QWORD cszLineLength,
    _In_z_ _Printf_format_string_ LPWSTR wszFormat,
    ...
)
{
    int cch, csz = 0;
    va_list arglist;
    WCHAR wszBufferTiny[MAX_PATH];
    LPWSTR wszBuffer;
    if(0 == cszLineLength) { 
        szBuffer[0] = '\0';
        return 0;
    }
    // 1: alloc/assign wchar buffer
    if(cszLineLength < _countof(wszBufferTiny)) {
        wszBuffer = wszBufferTiny;
    } else {
        wszBuffer = LocalAlloc(0, cszLineLength * sizeof(WCHAR));
        if(!wszBuffer) { goto fail; }
    }
    // 2: write to whar buffer
    va_start(arglist, wszFormat);
    cch = _vsnwprintf_s(wszBuffer, cszLineLength, _TRUNCATE, wszFormat, arglist);
    va_end(arglist);
    if(cch < 0) { cch = (int)cszLineLength - 1; }
    // 3: convert to utf-8
    while((0 == (csz = WideCharToMultiByte(CP_UTF8, 0, wszBuffer, -1, szBuffer, (int)cszLineLength, NULL, NULL))) && cch) {
        wszBuffer[--cch] = '\0';
    }
    csz--;
fail:
    if(csz < cszLineLength - 1) {
        memset(szBuffer + csz, ' ', cszLineLength - 1 - csz);
    }
    szBuffer[cszLineLength - 1] = '\n';
    szBuffer[cszLineLength] = '\0';
    if(wszBuffer != wszBufferTiny) { LocalFree(wszBuffer); }
    return (DWORD)cszLineLength;
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

#define UTIL_NTSTATUS_SUCCESS                      ((NTSTATUS)0x00000000L)
#define UTIL_NTSTATUS_END_OF_FILE                  ((NTSTATUS)0xC0000011L)

NTSTATUS Util_VfsReadFile_FromZERO(_In_ QWORD cbFile, _Out_writes_to_(cb, *pcbRead) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset)
{
    if(cbOffset > cbFile) { return UTIL_NTSTATUS_END_OF_FILE; }
    *pcbRead = (DWORD)min(cb, cbFile - cbOffset);
    ZeroMemory(pb, *pcbRead);
    return *pcbRead ? UTIL_NTSTATUS_SUCCESS : UTIL_NTSTATUS_END_OF_FILE;
}

NTSTATUS Util_VfsReadFile_FromPBYTE(_In_opt_ PBYTE pbFile, _In_ QWORD cbFile, _Out_writes_to_(cb, *pcbRead) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset)
{
    if(!pbFile || (cbOffset > cbFile)) { return UTIL_NTSTATUS_END_OF_FILE; }
    *pcbRead = (DWORD)min(cb, cbFile - cbOffset);
    memcpy(pb, pbFile + cbOffset, *pcbRead);
    return *pcbRead ? UTIL_NTSTATUS_SUCCESS : UTIL_NTSTATUS_END_OF_FILE;
}

NTSTATUS Util_VfsReadFile_FromTextWtoU8(_In_opt_ LPWSTR wszValue, _Out_writes_to_(cb, *pcbRead) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset)
{
    NTSTATUS nt;
    LPSTR szTMP = Util_StrDupW2U8(wszValue);
    nt = Util_VfsReadFile_FromPBYTE(szTMP, (szTMP ? strlen(szTMP) : 0), pb, cb, pcbRead, cbOffset);
    LocalFree(szTMP);
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

NTSTATUS Util_VfsWriteFile_PBYTE(_Inout_ PBYTE pbTarget, _In_ DWORD cbTarget, _In_reads_(cb) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbWrite, _In_ QWORD cbOffset, _In_ BOOL fTerminatingNULL)
{
    if(cbOffset >= cbTarget) {
        *pcbWrite = 0;
        return UTIL_NTSTATUS_END_OF_FILE;
    }
    if(cbOffset + cb > cbTarget) {
        cb = (DWORD)(cbTarget - cbOffset);
    }
    memcpy(pbTarget, pb, cb);
    if(fTerminatingNULL) {
        pbTarget[min(cbTarget - 1, cb)] = 0;
    }
    *pcbWrite = cb;
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

VOID Util_VfsTimeStampFile(_In_opt_ PVMM_PROCESS pProcess, _Out_ PVMMDLL_VFS_FILELIST_EXINFO pExInfo)
{
    pExInfo->dwVersion = VMMDLL_VFS_FILELIST_EXINFO_VERSION;
    pExInfo->fCompressed = pProcess && pProcess->dwState;
    pExInfo->qwCreationTime = VmmProcess_GetCreateTimeOpt(pProcess);
    pExInfo->qwLastWriteTime = (pProcess && pProcess->dwState) ? VmmProcess_GetExitTimeOpt(pProcess) : 0;
    if(!pExInfo->qwLastWriteTime) {
        pExInfo->qwLastWriteTime = pExInfo->qwCreationTime;
    }
}

LPSTR Util_StrDupA(_In_opt_ LPSTR sz)
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

LPWSTR Util_StrDupW(_In_opt_ LPWSTR wsz)
{
    SIZE_T cch;
    LPWSTR wszDup;
    if(!wsz) { return NULL; }
    cch = 1 + wcslen(wsz);
    wszDup = LocalAlloc(0, cch * 2);
    if(wszDup) {
        memcpy(wszDup, wsz, cch * 2);
    }
    return wszDup;
}

LPSTR Util_StrDupW2U8(_In_opt_ LPWSTR wsz)
{
    DWORD cchUTF8;
    LPSTR szUTF8;
    if(!wsz) { return NULL; }
    cchUTF8 = wcslen_u8(wsz);
    if(!cchUTF8 || (cchUTF8 > 0x01000000) || !(szUTF8 = LocalAlloc(0, cchUTF8 + 1ULL))) {
        return LocalAlloc(LMEM_ZEROINIT, 1);
    }
    WideCharToMultiByte(CP_UTF8, 0, wsz, -1, szUTF8, cchUTF8, NULL, NULL);
    szUTF8[cchUTF8] = 0;
    return szUTF8;
}

VOID Util_FileTime2String(_In_ PFILETIME pFileTime, _Out_writes_(24) LPSTR szTime)
{
    SYSTEMTIME SystemTime;
    if(!*(PQWORD)pFileTime || (*(PQWORD)pFileTime > 0x0200000000000000)) {
        strcpy_s(szTime, 24, "                    ***");
        return;
    }
    FileTimeToSystemTime(pFileTime, &SystemTime);
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

int Util_qsort_QWORD(const void *pqw1, const void *pqw2)
{
    QWORD qw1 = *(PQWORD)pqw1;
    QWORD qw2 = *(PQWORD)pqw2;
    return
        (qw1 < qw2) ? -1 :
        (qw1 > qw2) ? 1 : 0;
}

int Util_qfind_CmpFindTableQWORD(_In_ PVOID pvFind, _In_ PVOID pvEntry)
{
    QWORD qwKey = (QWORD)pvFind;
    QWORD qwEntry = *(PQWORD)pvEntry;
    if(qwEntry > qwKey) { return -1; }
    if(qwEntry < qwKey) { return 1; }
    return 0;
}

_Success_(return != NULL)
PVOID Util_qfind_ex(_In_ PVOID pvFind, _In_ DWORD cMap, _In_ PVOID pvMap, _In_ DWORD cbEntry, _In_ int(*pfnCmp)(_In_ PVOID pvFind, _In_ PVOID pvEntry), _Out_opt_ PDWORD piMapOpt)
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
        f = pfnCmp(pvFind, pbMap + cbSearch);
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
        if(!pfnCmp(pvFind, pbMap + cbSearch)) {
            if(piMapOpt) { *piMapOpt = cbSearch / cbEntry; }
            return pbMap + cbSearch;
        }
        if((cbSearch >= cbEntry) && !pfnCmp(pvFind, pbMap + cbSearch - cbEntry)) {
            if(piMapOpt) { *piMapOpt = (cbSearch - cbEntry) / cbEntry; }
            return pbMap + cbSearch - cbEntry;
        }
    }
    return NULL;
}
