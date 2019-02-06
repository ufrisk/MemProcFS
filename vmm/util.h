// util.h : definitions of various utility functions.
//
// (c) Ulf Frisk, 2018-2019
// Author: Ulf Frisk, pcileech@frizk.net
//
#ifndef __UTIL_H__
#define __UTIL_H__
#include "vmm.h"

/*
* Parse a string returning the QWORD representing the string. The string may
* consist of a decimal or hexadecimal integer string. Hexadecimals must begin
* with 0x.
* -- sz
* -- return
*/
QWORD Util_GetNumeric(_In_ LPSTR sz);

/*
* Print a maximum of 8192 bytes of binary data as hexascii on the screen.
* -- pb
* -- cb
* -- cbInitialOffset = offset, must be max 0x1000 and multiple of 0x10.
*/
VOID Util_PrintHexAscii(_In_ PBYTE pb, _In_ DWORD cb, _In_ DWORD cbInitialOffset);

/*
* Fill a human readable hex ascii memory dump into the caller supplied sz buffer.
* -- pb
* -- cb
* -- cbInitialOffset = offset, must be max 0x1000 and multiple of 0x10.
* -- sz = buffer to fill, NULL to retrieve size in pcsz parameter.
* -- pcsz = ptr to size of buffer on entry, size of characters on exit.
*/
BOOL Util_FillHexAscii(_In_ PBYTE pb, _In_ DWORD cb, _In_ DWORD cbInitialOffset, _Inout_opt_ LPSTR sz, _Out_ PDWORD pcsz);

/*
* Split a "path" string into two at the first '\' character. If no 2nd string
* is not found then it's returned as null character '\0' (i.e. not as NULL).
* -- sz = the original string to split (of maximum MAX_PATH length)
* -- _szBuf = MAX_PATH sized buffer that will be overwritten and used throughout the lifetime of psz1/psz2 outputs.
* -- psz1
* -- psz2
*/
VOID Util_PathSplit2(_In_ LPSTR sz, _Out_writes_(MAX_PATH) PCHAR _szBuf, _Out_ LPSTR *psz1, _Out_ LPSTR *psz2);

/*
* Split a "path" string into two at the first '\' character. If no 2nd string
* is not found then it's returned as null character '\0' (i.e. not as NULL).
* -- wsz = the original string to split (of maximum MAX_PATH length)
* -- _szBuf = MAX_PATH sized buffer that will be overwritten and used throughout the lifetime of psz1/psz2 outputs.
* -- psz1
* -- psz2
*/
VOID Util_PathSplit2_WCHAR(_In_ LPWSTR wsz, _Out_writes_(MAX_PATH) PCHAR _szBuf, _Out_ LPSTR *psz1, _Out_ LPSTR *psz2);

/*
* Return the path of the specified hModule (DLL) - ending with a backslash, or current Executable.
* -- szPath
* -- hModule = Optional, HMODULE handle for path to DLL, NULL for path to EXE.
*/
VOID Util_GetPathDll(_Out_writes_(MAX_PATH) PCHAR szPath, _In_opt_ HMODULE hModule);

/*
* Utility functions for read/write towards different underlying data representations.
*/
NTSTATUS Util_VfsReadFile_FromPBYTE(_In_ PBYTE pbFile, _In_ QWORD cbFile, _Out_ LPVOID pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset);
NTSTATUS Util_VfsReadFile_FromQWORD(_In_ QWORD qwValue, _Out_ LPVOID pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset, _In_ BOOL fPrefix);
NTSTATUS Util_VfsReadFile_FromDWORD(_In_ DWORD dwValue, _Out_ LPVOID pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset, _In_ BOOL fPrefix);
NTSTATUS Util_VfsReadFile_FromBOOL(_In_ BOOL fValue, _Out_ LPVOID pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset);
NTSTATUS Util_VfsWriteFile_BOOL(_Inout_ PBOOL pfTarget, _In_ LPVOID pb, _In_ DWORD cb, _Out_ PDWORD pcbWrite, _In_ QWORD cbOffset);
NTSTATUS Util_VfsWriteFile_DWORD(_Inout_ PDWORD pdwTarget, _In_ LPVOID pb, _In_ DWORD cb, _Out_ PDWORD pcbWrite, _In_ QWORD cbOffset, _In_ DWORD dwMinAllow);

#endif /* __UTIL_H__ */
