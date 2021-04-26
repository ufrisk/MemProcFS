// util.c : implementation of various utility functions.
//
// (c) Ulf Frisk, 2018-2021
// Author: Ulf Frisk, pcileech@frizk.net
//
#include "util.h"
#include <math.h>
#include <ntstatus.h>

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

/*
* SHA256 hash some data.
* -- pbData
* -- cbData
* -- pbHash
* -- return
*/
_Success_(return)
BOOL Util_HashSHA256(_In_reads_(cbData) PBYTE pbData, _In_ DWORD cbData, _Out_writes_(32) PBYTE pbHash)
{
    BOOL fResult = FALSE;
    DWORD cbHashObject;
    PBYTE pbHashObject = NULL;
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    if(BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, 0)) { goto fail; }
    if(BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PBYTE)&cbHashObject, sizeof(DWORD), &cbData, 0)) { goto fail; }
    if(!(pbHashObject = LocalAlloc(0, cbHashObject))) { goto fail;}
    if(BCryptCreateHash(hAlg, &hHash, pbHashObject, cbHashObject, NULL, 0, 0)) { goto fail; }
    if(BCryptHashData(hHash, pbData, cbData, 0)) { goto fail; }
    if(BCryptFinishHash(hHash, pbHash, 32, 0)) { goto fail; }
    fResult = TRUE;
fail:
    if(hAlg) { BCryptCloseAlgorithmProvider(hAlg, 0); }
    if(hHash) { BCryptDestroyHash(hHash); }
    LocalFree(pbHashObject);
    return fResult;
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

/*
* Number of extra bytes required to represent a JSON string as compared to the
* number of original utf-8 bytes in the string.
* -- szu = utf-8 encoded string
* -- return = number of additional bytes needed to account for JSON escape chars.
*/
DWORD Util_JsonEscapeByteCountExtra(_In_ LPSTR szu)
{
    UCHAR ch;
    DWORD n = 0, i = 0;
    while((ch = szu[i++])) {
        if(ch < 0x20 || ch == '"' || ch == '\\') {
            n += (ch == '"' || ch == '\\' || ch == '\b' || ch == '\f' || ch == '\n' || ch == '\r' || ch == '\t') ? 1 : 5;
        }
    }
    return n;
}

/*
* Escape utf-8 text into json text. The number of bytes in the resulting string
* is returned whilst the szj buffer is updated with the escaped string.
* -- szu = utf-8 string to escape.
* -- cbj = byte length of szj buffer (including null terminator).
* -- szj = buffer to receive json-escaped string
* -- return = number of bytes written (excluding null terminator).
*/
DWORD Util_JsonEscape(_In_ LPSTR szu, _In_ DWORD cbj, _Out_writes_z_(cbj) LPSTR szj)
{
    UCHAR ch, chh;
    DWORD i = 0, j = 0;
    if(cbj == 0) { return 0; }
    cbj--;      // target byte count excl. null terminator
    while((ch = szu[i++]) && (j < cbj)) {
        if(ch < 0x20 || ch == '"' || ch == '\\') {
            if(ch == '"' || ch == '\\' || ch == '\b' || ch == '\f' || ch == '\n' || ch == '\r' || ch == '\t') {
                if(cbj < j + 1) { break; }
                szj[j++] = '\\';
                switch(ch) {
                    case '"': szj[j++] = '"'; break;
                    case '\\': szj[j++] = '\\'; break;
                    case '\b': szj[j++] = 'b'; break;
                    case '\f': szj[j++] = 'f'; break;
                    case '\n': szj[j++] = 'n'; break;
                    case '\r': szj[j++] = 'r'; break;
                    case '\t': szj[j++] = 't'; break;
                }
            } else {
                if(cbj < j + 5) { break; }
                szj[j++] = '\\';
                szj[j++] = 'u';
                szj[j++] = '0';
                szj[j++] = '0';
                chh = (ch >> 4) & 0xf;
                szj[j++] = (chh < 10) ? '0' + chh : 'a' - 10 + chh;
                chh = ch & 0xf;
                szj[j++] = (chh < 10) ? '0' + chh : 'a' - 10 + chh;
            }
        } else {
            szj[j++] = ch;
        }
    }
    szj[min(j, cbj)] = 0;
    return j;
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
size_t Util_snwprintf_u8_impl(
    _Out_writes_z_(cbBuffer) LPSTR szuBuffer,
    _In_ size_t cbBuffer,
    _In_z_ _Printf_format_string_ LPWSTR wszFormat,
    _In_ va_list arglist
) {
    int cch;
    WCHAR wszBufferTiny[MAX_PATH+1];
    LPWSTR wszBuffer = wszBufferTiny;
    if(cbBuffer < 2) {
        if(cbBuffer) { szuBuffer[0] = '\0'; };
        return 0;
    }
    // 1: alloc/assign wchar buffer
    if(cbBuffer >= _countof(wszBufferTiny)) {
        wszBuffer = LocalAlloc(0, cbBuffer * sizeof(WCHAR));
        if(!wszBuffer) {
            szuBuffer[0] = '\0';
            goto fail;
        }
    }
    // 2: write to whar buffer
    cch = _vsnwprintf_s(wszBuffer, cbBuffer, _TRUNCATE, wszFormat, arglist);
    if(cch < 0) { cch = (int)cbBuffer - 1; }
    // 3: convert to utf-8
    while((0 == WideCharToMultiByte(CP_UTF8, 0, wszBuffer, -1, szuBuffer, (int)cbBuffer, NULL, NULL)) && cch) {
        wszBuffer[--cch] = '\0';
    }
fail:
    if(wszBuffer != wszBufferTiny) { LocalFree(wszBuffer); }
    return strlen(szuBuffer);
}

_Success_(return >= 0)
size_t Util_snwprintf_u8(
    _Out_writes_z_(cbBuffer) LPSTR szuBuffer,
    _In_ size_t cbBuffer,
    _In_z_ _Printf_format_string_ LPWSTR wszFormat,
    ...
) {
    size_t ret;
    va_list arglist;
    va_start(arglist, wszFormat);
    ret = Util_snwprintf_u8_impl(szuBuffer, cbBuffer, wszFormat, arglist);
    va_end(arglist);
    return ret;
}

_Success_(return >= 0)
size_t Util_snwprintf_u8j(
    _Out_writes_z_(cbBuffer) LPSTR szjBuffer,
    _In_ size_t cbBuffer,
    _In_z_ _Printf_format_string_ LPWSTR wszFormat,
    ...
) {
    size_t cbu, cbj;
    va_list arglist;
    CHAR szuBufferTiny[MAX_PATH+1];
    LPSTR szuBuffer = szuBufferTiny;
    va_start(arglist, wszFormat);
    cbu = Util_snwprintf_u8_impl(szjBuffer, cbBuffer, wszFormat, arglist);
    va_end(arglist);
    // json escape chars if required:
    if(!cbu || !Util_JsonEscapeByteCountExtra(szjBuffer)) { return cbu; }
    if(cbu >= _countof(szuBufferTiny)) {
        if(!(szuBuffer = LocalAlloc(0, cbu + 1))) {
            szjBuffer[0] = '\0';
            return 0;
        }
    }
    memcpy(szuBuffer, szjBuffer, cbu); szuBuffer[cbu] = 0;
    cbj = Util_JsonEscape(szuBuffer, (DWORD)cbBuffer, szjBuffer);
    if(szuBuffer != szuBufferTiny) { LocalFree(szuBuffer); }
    return cbj;
}

_Success_(return >= 0)
DWORD Util_snwprintf_u8ln_impl(
    _Out_writes_(cszLineLength+1) LPSTR szBuffer,
    _In_ QWORD cszLineLength,
    _In_z_ _Printf_format_string_ LPWSTR wszFormat,
    _In_ va_list arglist
)
{
    int cch, csz = 0;
    WCHAR wszBufferTiny[MAX_PATH+1];
    LPWSTR wszBuffer = wszBufferTiny;
    if(0 == cszLineLength) { 
        szBuffer[0] = '\0';
        return 0;
    }
    // 1: alloc/assign wchar buffer
    if(cszLineLength >= _countof(wszBufferTiny)) {
        wszBuffer = LocalAlloc(0, cszLineLength * sizeof(WCHAR));
        if(!wszBuffer) { goto fail; }
    }
    // 2: write to whar buffer
    cch = _vsnwprintf_s(wszBuffer, cszLineLength, _TRUNCATE, wszFormat, arglist);
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

_Success_(return >= 0)
DWORD Util_snwprintf_u8ln(
    _Out_writes_z_(cszLineLength + 1) LPSTR szBuffer,
    _In_ QWORD cszLineLength,
    _In_z_ _Printf_format_string_ LPWSTR wszFormat,
    ...
)
{
    DWORD ret;
    va_list arglist;
    va_start(arglist, wszFormat);
    ret = Util_snwprintf_u8ln_impl(szBuffer, cszLineLength, wszFormat, arglist);
    va_end(arglist);
    return ret;
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
#define VMMDLL_STATUS_FILE_INVALID                 ((NTSTATUS)0xC0000098L)
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

NTSTATUS Util_VfsReadFile_FromMEM(_In_opt_ PVMM_PROCESS pProcess, _In_ QWORD vaMEM, _In_ QWORD cbMEM, _In_ QWORD flags, _Out_writes_to_(cb, *pcbRead) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset)
{
    NTSTATUS nt = UTIL_NTSTATUS_END_OF_FILE;
    PBYTE pbMEM;
    if(cbOffset < cbMEM) {
        vaMEM += cbOffset;
        cbMEM -= cbOffset;
        if((cbMEM < 0x04000000) && (pbMEM = LocalAlloc(0, cbMEM))) {
            if(VmmRead2(pProcess, vaMEM, pbMEM, (DWORD)cbMEM, flags)) {
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

NTSTATUS Util_VfsReadFile_FromFILETIME(_In_ QWORD ftValue, _Out_writes_to_(cb, *pcbRead) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset)
{
    CHAR szTime[24];
    Util_FileTime2String(ftValue, szTime);
    szTime[23] = '\n';
    return Util_VfsReadFile_FromPBYTE(szTime, 24, pb, cb, pcbRead, cbOffset);
}

NTSTATUS Util_VfsReadFile_FromResource(_In_ LPWSTR wszResourceName, _Out_writes_to_(cb, *pcbRead) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset)
{
    HRSRC hRes;
    HGLOBAL hResGlobal;
    DWORD cbRes;
    PBYTE pbRes;
    if(!(hRes = FindResource(ctxVmm->hModuleVmm, wszResourceName, RT_RCDATA))) { goto fail; }
    if(!(hResGlobal = LoadResource(ctxVmm->hModuleVmm, hRes))) { goto fail; }
    if(!(pbRes = (PBYTE)LockResource(hResGlobal))) { goto fail; }
    cbRes = SizeofResource(ctxVmm->hModuleVmm, hRes);
    return Util_VfsReadFile_FromPBYTE(pbRes, cbRes, pb, cb, pcbRead, cbOffset);
fail:
    return VMMDLL_STATUS_FILE_INVALID;
}

NTSTATUS Util_VfsReadFile_snwprintf_u8ln(_Out_writes_to_(cb, *pcbRead) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset, _In_ QWORD cszLineLength, _In_z_ _Printf_format_string_ LPWSTR wszFormat, ...)
{
    NTSTATUS nt = UTIL_NTSTATUS_END_OF_FILE;
    DWORD ret;
    va_list arglist;
    LPSTR szBuffer;
    if(!(szBuffer = LocalAlloc(0, cszLineLength + 1))) { goto fail; }
    va_start(arglist, wszFormat);
    ret = Util_snwprintf_u8ln_impl(szBuffer, cszLineLength, wszFormat, arglist);
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

DWORD Util_ResourceSize(_In_ LPWSTR wszResourceName)
{
    HRSRC hRes;
    if(!(hRes = FindResource(ctxVmm->hModuleVmm, wszResourceName, RT_RCDATA))) { return 0; }
    return SizeofResource(ctxVmm->hModuleVmm, hRes);
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

BOOL Util_StrEndsWithW(_In_opt_ LPWSTR wsz, _In_opt_ LPWSTR wszEndsWith, _In_ BOOL fCaseInsensitive)
{
    SIZE_T cch, cchEndsWith;
    if(!wsz || !wszEndsWith) { return FALSE; }
    cch = wcslen(wsz);
    cchEndsWith = wcslen(wszEndsWith);
    if(cch < cchEndsWith) { return FALSE; }
    return fCaseInsensitive ?
        (0 == _wcsicmp(wsz + cch - cchEndsWith, wszEndsWith)) :
        (0 == wcscmp(wsz + cch - cchEndsWith, wszEndsWith));
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

VOID Util_GuidToString(_In_reads_(16) PBYTE pb, _Out_writes_(37) LPSTR szGUID)
{
    typedef struct tdGUID {
        DWORD v1;
        WORD  v2;
        WORD  v3;
        BYTE  v4[8];
    } GUID, *PGUID;
    PGUID g = (PGUID)pb;
    _snprintf_s(szGUID, 37, _TRUNCATE,
        "%08lX-%04hX-%04hX-%02hhX%02hhX-%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX",
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

_Success_(return)
BOOL Util_VfsHelper_GetIdDir(_In_ LPWSTR wszPath, _Out_ PDWORD pdwID, _Out_ LPWSTR *pwszSubPath)
{
    DWORD i = 0, iSubPath = 0;
    // 1: Check if starting with PID/NAME/BY-ID/BY-NAME
    if(!_wcsnicmp(wszPath, L"pid\\", 4)) {
        i = 4;
    } else if(!_wcsnicmp(wszPath, L"name\\", 5)) {
        i = 5;
    } else if(!_wcsnicmp(wszPath, L"by-id\\", 6)) {
        i = 6;
    } else if(!_wcsnicmp(wszPath, L"by-name\\", 8)) {
        i = 8;
    } else {
        return FALSE;
    }
    // 3: Locate start of PID/ID number and 1st Path item (if any)
    while((i < MAX_PATH) && wszPath[i] && (wszPath[i] != '\\')) { i++; }
    iSubPath = ((i < MAX_PATH - 1) && (wszPath[i] == '\\')) ? (i + 1) : i;
    i--;
    while((wszPath[i] >= '0') && (wszPath[i] <= '9')) { i--; }
    i++;
    if(!((wszPath[i] >= '0') && (wszPath[i] <= '9'))) { return FALSE; }
    *pdwID = wcstoul(wszPath + i, NULL, 10);
    *pwszSubPath = wszPath + iSubPath;
    return TRUE;
}

#define UTIL_VFSLINEFIXED_LINEPAD512 \
    L"-----------------------------------------------------" \
    L"-----------------------------------------------------" \
    L"-----------------------------------------------------" \
    L"-----------------------------------------------------"

/*
* FixedLineRead: Read from a file dynamically created from a map/array object
* using a callback function to populate individual lines (excluding header).
* -- pfnCallback = callback function to populate individual lines.
* -- ctx = optional context to 'pfn' callback function.
* -- cbLineLength = line length, including newline, excluding null terminator.
* -- wszHeader = optional header line.
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
    _In_ UTIL_VFSLINEFIXED_PFN_CALLBACK pfnCallback,
    _Inout_opt_ PVOID ctx,
    _In_ DWORD cbLineLength,
    _In_opt_ LPWSTR wszHeader,
    _In_ PVOID pMap,
    _In_ DWORD cMap,
    _In_ DWORD cbEntry,
    _Out_writes_to_(cb, *pcbRead) PBYTE pb,
    _In_ DWORD cb,
    _Out_ PDWORD pcbRead,
    _In_ QWORD cbOffset
) {
    LPSTR sz;
    NTSTATUS nt;
    PVOID pvMapEntry;
    QWORD i, iMapEntry, o = 0, cbMax, cStart, cEnd, cHeader;
    cHeader = (wszHeader && ctxMain->cfg.fFileInfoHeader) ? 2 : 0;
    cStart = (DWORD)(cbOffset / cbLineLength);
    cEnd = (DWORD)min(cHeader + cMap - 1, (cb + cbOffset + cbLineLength - 1) / cbLineLength);
    cbMax = 1 + (1 + cEnd - cStart) * cbLineLength;
    if(!cHeader && !cMap) { return VMMDLL_STATUS_END_OF_FILE; }
    if((cStart > cHeader + cMap)) { return VMMDLL_STATUS_END_OF_FILE; }
    if(!(sz = LocalAlloc(LMEM_ZEROINIT, cbMax))) { return VMMDLL_STATUS_FILE_INVALID; }
    for(i = cStart; i <= cEnd; i++) {
        // header:
        if(i < cHeader) {
            o += i ?
                Util_snwprintf_u8ln(sz + o, cbLineLength, L"%.*s", (DWORD)wcslen(wszHeader), UTIL_VFSLINEFIXED_LINEPAD512) :
                Util_snwprintf_u8ln(sz + o, cbLineLength, L"%s", wszHeader);
            continue;
        }
        // line:
        iMapEntry = i - cHeader;
        pvMapEntry = (PBYTE)pMap + (i - cHeader) * cbEntry;
        pfnCallback(ctx, cbLineLength, (DWORD)iMapEntry, pvMapEntry, sz + o);
        o += cbLineLength;
    }
    nt = Util_VfsReadFile_FromPBYTE(sz, cbMax - 1, pb, cb, pcbRead, cbOffset - cStart * cbLineLength);
    LocalFree(sz);
    return nt;
}
