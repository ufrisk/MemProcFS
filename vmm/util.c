// util.c : implementation of various utility functions.
//
// (c) Ulf Frisk, 2018-2019
// Author: Ulf Frisk, pcileech@frizk.net
//
#include "util.h"

QWORD Util_GetNumeric(_In_ LPSTR sz)
{
    if((strlen(sz) > 1) && (sz[0] == '0') && ((sz[1] == 'x') || (sz[1] == 'X'))) {
        return strtoull(sz, NULL, 16); // Hex (starts with 0x)
    } else {
        return strtoull(sz, NULL, 10); // Not Hex -> try Decimal
    }
}

#define Util_2HexChar(x) (((((x) & 0xf) <= 9) ? '0' : ('a' - 10)) + ((x) & 0xf))

#define UTIL_PRINTASCII \
    "................................ !\"#$%&'()*+,-./0123456789:;<=>?" \
    "@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz`{|}~" \
    "................................................................" \
    "................................................................" \

BOOL Util_FillHexAscii(_In_ PBYTE pb, _In_ DWORD cb, _In_ DWORD cbInitialOffset, _Inout_opt_ LPSTR sz, _Out_ PDWORD pcsz)
{
    DWORD i, j, o = 0, szMax, iMod;
    // checks
    if((cbInitialOffset > cb) || (cbInitialOffset > 0x1000) || (cbInitialOffset & 0xf)) { return FALSE; }
    *pcsz = szMax = cb * 5 + 80;
    if(cb > szMax) { return FALSE; }
    if(!sz) { return TRUE; }
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
    sz[o++] = 0;
    return TRUE;
}

VOID Util_PrintHexAscii(_In_ PBYTE pb, _In_ DWORD cb, _In_ DWORD cbInitialOffset)
{
    DWORD szMax;
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

VOID Util_PathSplit2(_In_ LPSTR sz, _Out_writes_(MAX_PATH) PCHAR _szBuf, _Out_ LPSTR *psz1, _Out_ LPSTR *psz2)
{
    DWORD i;
    strcpy_s(_szBuf, MAX_PATH, sz);
    *psz1 = _szBuf;
    for(i = 0; i < MAX_PATH; i++) {
        if('\0' == _szBuf[i]) {
            *psz2 = _szBuf + i;
            return;
        }
        if('\\' == _szBuf[i]) {
            _szBuf[i] = '\0';
            *psz2 = _szBuf + i + 1;
            return;
        }
    }
}

VOID Util_PathSplit2_WCHAR(_In_ LPWSTR wsz, _Out_writes_(MAX_PATH) PCHAR _szBuf, _Out_ LPSTR *psz1, _Out_ LPSTR *psz2)
{
    DWORD i;
    for(i = 0; i < MAX_PATH; i++) {
        _szBuf[i] = (CHAR)wsz[i];
        if(!_szBuf[i]) { break; }
    }
    _szBuf[i] = 0;
    *psz1 = _szBuf;
    for(i = 0; i < MAX_PATH; i++) {
        if('\0' == _szBuf[i]) {
            *psz2 = _szBuf + i;
            return;
        }
        if('\\' == _szBuf[i]) {
            _szBuf[i] = '\0';
            *psz2 = _szBuf + i + 1;
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

#define UTIL_NTSTATUS_SUCCESS                      ((NTSTATUS)0x00000000L)
#define UTIL_NTSTATUS_END_OF_FILE                  ((NTSTATUS)0xC0000011L)

NTSTATUS Util_VfsReadFile_FromPBYTE(_In_ PBYTE pbFile, _In_ QWORD cbFile, _Out_ LPVOID pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset)
{
    if(cbOffset > cbFile) { return UTIL_NTSTATUS_END_OF_FILE; }
    *pcbRead = (DWORD)min(cb, cbFile - cbOffset);
    memcpy(pb, pbFile + cbOffset, *pcbRead);
    return *pcbRead ? UTIL_NTSTATUS_SUCCESS : UTIL_NTSTATUS_END_OF_FILE;
}

NTSTATUS Util_VfsReadFile_FromQWORD(_In_ QWORD qwValue, _Out_ LPVOID pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset, _In_ BOOL fPrefix)
{
    BYTE pbBuffer[32];
    DWORD cbBuffer;
    cbBuffer = snprintf(pbBuffer, 32, (fPrefix ? "0x%016llx" : "%016llx"), qwValue);
    return Util_VfsReadFile_FromPBYTE(pbBuffer, cbBuffer, pb, cb, pcbRead, cbOffset);
}

NTSTATUS Util_VfsReadFile_FromDWORD(_In_ DWORD dwValue, _Out_ LPVOID pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset, _In_ BOOL fPrefix)
{
    BYTE pbBuffer[32];
    DWORD cbBuffer;
    cbBuffer = snprintf(pbBuffer, 32, (fPrefix ? "0x%08x" : "%08x"), dwValue);
    return Util_VfsReadFile_FromPBYTE(pbBuffer, cbBuffer, pb, cb, pcbRead, cbOffset);
}

NTSTATUS Util_VfsReadFile_FromBOOL(_In_ BOOL fValue, _Out_ LPVOID pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset)
{
    BYTE pbBuffer[1];
    pbBuffer[0] = fValue ? '1' : '0';
    return Util_VfsReadFile_FromPBYTE(pbBuffer, 1, pb, cb, pcbRead, cbOffset);
}

NTSTATUS Util_VfsWriteFile_BOOL(_Inout_ PBOOL pfTarget, _In_ LPVOID pb, _In_ DWORD cb, _Out_ PDWORD pcbWrite, _In_ QWORD cbOffset)
{
    CHAR ch;
    if((cb > 0) && (cbOffset == 0)) {
        ch = *(PCHAR)pb;
        *pfTarget = (ch == 0 || ch == '0') ? FALSE : TRUE;
    }
    *pcbWrite = cb;
    return UTIL_NTSTATUS_SUCCESS;
}

NTSTATUS Util_VfsWriteFile_DWORD(_Inout_ PDWORD pdwTarget, _In_ LPVOID pb, _In_ DWORD cb, _Out_ PDWORD pcbWrite, _In_ QWORD cbOffset, _In_ DWORD dwMinAllow)
{
    DWORD dw;
    BYTE pbBuffer[9];
    if(cbOffset < 8) {
        snprintf(pbBuffer, 9, "%08x", *pdwTarget);
        cb = (DWORD)min(8 - cbOffset, cb);
        memcpy(pbBuffer + cbOffset, pb, cb);
        pbBuffer[8] = 0;
        dw = strtoul(pbBuffer, NULL, 16);
        dw = max(dw, dwMinAllow);
        *pdwTarget = dw;
    }
    *pcbWrite = cb;
    return UTIL_NTSTATUS_SUCCESS;
}
