// util.h : definitions of various utility functions.
//
// (c) Ulf Frisk, 2018-2020
// Author: Ulf Frisk, pcileech@frizk.net
//
#ifndef __UTIL_H__
#define __UTIL_H__
#include "vmm.h"
#include "vmmdll.h"

#define UTIL_ASCIIFILENAME_ALLOW \
    "0000000000000000000000000000000011011111110111101111111111010100" \
    "1111111111111111111111111111011111111111111111111111111111110111" \
    "0000000000000000000000000000000000000000000000000000000000000000" \
    "0000000000000000000000000000000000000000000000000000000000000000"

#define UTIL_PRINTASCII \
    "................................ !\"#$%&'()*+,-./0123456789:;<=>?" \
    "@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~ " \
    "................................................................" \
    "................................................................"

#define UTIL_CHAR_ASCII_TO_OKFILE(w)        (((w < 0) || (w >= 0x80)) ? w : ((UTIL_ASCIIFILENAME_ALLOW[w] == '1') ? w : 0))
#define UTIL_CHAR_ASCII_TO_UPPER(w)         (((w >= 0x61 && w <= 0x7a)) ? (w - 0x20) : w)

/*
* Calculate the number of digits of an integer number.
*/
DWORD Util_GetNumDigits(_In_ DWORD dwNumber);

/*
* Parse a string returning the QWORD representing the string. The string may
* consist of a decimal or hexadecimal integer string. Hexadecimals must begin
* with 0x.
* -- sz/wsz
* -- return
*/
QWORD Util_GetNumericA(_In_ LPSTR sz);
QWORD Util_GetNumericW(_In_ LPWSTR wsz);

/*
* Hash a string with the ROT13 algorithm.
* -- sz
* -- return
*/
DWORD Util_HashStringA(_In_opt_ LPCSTR sz);

/*
* Hash the uppercase version of a string with the ROT13 algorithm.
* -- sz/wsz
* -- return
*/
DWORD Util_HashStringUpperA(_In_opt_ LPCSTR sz);
DWORD Util_HashStringUpperW(_In_opt_ LPCWSTR wsz);

/*
* Hash a registry key name in a way that is supported by the file system.
* NB! this is not the same hash as the Windows registry uses.
* -- wsz
* -- iSuffix
* -- return
*/
DWORD Util_HashNameW_Registry(_In_ LPCWSTR wsz, _In_opt_ DWORD iSuffix);

/*
* Hash a path. Used to calculate a registry key hash from a file system path.
* -- wszPath
* -- return
*/
QWORD Util_HashPathW_Registry(_In_ LPWSTR wszPath);

/*
* Print a maximum of 8192 bytes of binary data as hexascii on the screen.
* -- pb
* -- cb
* -- cbInitialOffset = offset, must be max 0x1000 and multiple of 0x10.
*/
VOID Util_PrintHexAscii(
    _In_reads_(cb) PBYTE pb,
    _In_ DWORD cb,
    _In_ DWORD cbInitialOffset
);

/*
* Fill a human readable hex ascii memory dump into the caller supplied sz buffer.
* -- pb = bytes (may only be NULL if sz is NULL for size query).
* -- cb
* -- cbInitialOffset = offset, must be max 0x1000 and multiple of 0x10.
* -- sz = buffer to fill, NULL to retrieve buffer size in pcsz parameter.
* -- pcsz = IF sz==NULL :: size of buffer (including space for terminating NULL) on exit
*           IF sz!=NULL :: size of buffer on entry, size of characters (excluding terminating NULL) on exit.
*/
_Success_(return)
BOOL Util_FillHexAscii(
    _In_reads_opt_(cb) PBYTE pb,
    _In_ DWORD cb,
    _In_ DWORD cbInitialOffset,
    _Out_writes_opt_(*pcsz) LPSTR sz,
    _Inout_ PDWORD pcsz
);

/*
* Replaces ascii characters not allowed in file names in the NULL-terminated
* string sz.
* -- sz
* -- chDefault
*/
VOID Util_AsciiFileNameFix(_In_ LPSTR sz, _In_ CHAR chDefault);

/*
* Convert a string to a file name compatible string by replacing illegal
* characters with '_'.
* -- wszOut = buffer to receive resulting string.
* -- sz/wsz
* -- csz/cwsz = number of chars if in-string is not NULL terminated.
* -- return = number of characters written (not including terminating NULL).
*/
DWORD Util_PathFileNameFixA(_Out_writes_(MAX_PATH) LPWSTR wszOut, _In_ LPCSTR sz, _In_opt_ DWORD csz);
DWORD Util_PathFileNameFixW(_Out_writes_(MAX_PATH) LPWSTR wszOut, _In_ LPCWSTR wsz, _In_opt_ DWORD cwsz);

/*
* Convert a registry key name into a file name compatible string by replacing
* illegal characters with '_'. Also optionally add a suffix between 1-9 and do
* upper-case letters.
* -- wszOut
* -- sz
* -- wsz
* -- cwsz
* -- iSuffix
* -- fUpper
* -- return = number of characters written (not including terminating NULL).
*/
DWORD Util_PathFileNameFix_Registry(_Out_writes_(MAX_PATH) LPWSTR wszOut, _In_opt_ LPCSTR sz, _In_opt_ LPCWSTR wsz, _In_opt_ DWORD cwsz, _In_opt_ DWORD iSuffix, _In_ BOOL fUpper);

/*
* Return the sub-string after the first '\' character in the sz NULL terminated
* string. If no '\' is found the empty NULL terminated string is returned. The
* returned value must not be free'd and is only valid as long as the wsz param-
* eter is valid.
* -- wsz
* -- return
*/
LPWSTR Util_PathSplitNextW(_In_ LPWSTR wsz);

/*
* Return the sub-string after the last '\' character in the wsz NULL terminated
* string. If no '\' is found original wsz string is returned. The returned data
* must not be free'd and is only valid as long as the wsz parameter is valid.
* -- sz/wsz
* -- return
*/
LPSTR Util_PathSplitLastA(_In_ LPSTR sz);

/*
* Return the sub-string after the last '\' character in the wsz NULL terminated
* string. If no '\' is found original wsz string is returned. The returned data
* must not be free'd and is only valid as long as the wsz parameter is valid.
* -- sz/wsz
* -- return
*/
LPWSTR Util_PathSplitLastW(_In_ LPWSTR wsz);

/*
* Get the 64-bit address value from a path string that starts with 0x.
* -- wsz
* -- return
*/
QWORD Util_PathGetBaseFromW(_In_ LPWSTR wsz);

/*
* Split a "path" string into two at the first L'\' character. The 1st string is
* returned in the pwsz1 caller-allocated buffer. The 2nd string (after the L'\'
* character is returned as return data (is a sub-string of wsz). If no 2nd string
* is not found then it's returned as null character L'\0' (i.e. not as NULL).
* -- wsz
* -- wsz1
* -- cwsz1
* -- return
*/
LPWSTR Util_PathSplit2_ExWCHAR(_In_ LPWSTR wsz, _Out_writes_(cwsz1) LPWSTR wsz1, _In_ DWORD cwsz1);

/*
* Split the string wsz into two at the last backslash which is removed. Ex:
* wsz: XXX\YYY\ZZZ\AAA -> wszPath: XXX\YYY\ZZZ + return: AAA
* -- wsz
* -- wszPath
* -- return = NULL if no split is found.
*/
LPWSTR Util_PathFileSplitW(_In_ LPWSTR wsz, _Out_writes_(MAX_PATH) LPWSTR wszPath);

/*
* Prepend a path with a hexascii address value.
* -- wszDstBuffer
* -- va
* -- f32
* -- wszText
*/
VOID Util_PathPrependVA(_Out_writes_(MAX_PATH) LPWSTR wszDstBuffer, _In_ QWORD va, _In_ BOOL f32, _In_ LPWSTR wszText);

/*
* Compare ANSI string with WIDE string with an optional max length; otherwise
* comparison will stop at first difference or when strings are NULL terminated.
* -- sz
* -- wsz
* -- cMax
* -- return
*/
int Util_wcsstrncmp(_In_ LPSTR sz, _In_ LPWSTR wsz, _In_opt_ DWORD cMax);

/*
* snwprintf to a utf-8 buffer. The result is guaranteed to be NULL terminated.
* -- szBuffer
* -- cbBuffer
* -- wszFormat = printf format string.
* -- ... = printf varargs.
* -- return
*/
_Success_(return >= 0)
size_t Util_snwprintf_u8(
    _Out_writes_(cbBuffer) LPSTR szBuffer,
    _In_ QWORD cbBuffer,
    _In_z_ _Printf_format_string_ LPWSTR wszFormat,
    ...
);

/*
* snwprintf to a utf-8 fixed line length, space padded to meet line length
* requirement and terminated with newline '\n' (at last char in line length)
* and NULL char (linelength + 1).
* -- szBuffer
* -- cszLineLength = line length in bytes including newline, excluding NULL.
* -- wszFormat = printf format string without "terminating" spaces+newline.
* -- ... = printf varargs.
* -- return
*/
_Success_(return >= 0)
DWORD Util_snwprintf_u8ln(
    _Out_writes_(cszLineLength + 1) LPSTR szBuffer,
    _In_ QWORD cszLineLength,
    _In_z_ _Printf_format_string_ LPWSTR wszFormat,
    ...
);

/*
* Return the path of the specified hModule (DLL) - ending with a backslash, or current Executable.
* -- szPath
* -- hModule = Optional, HMODULE handle for path to DLL, NULL for path to EXE.
*/
VOID Util_GetPathDll(_Out_writes_(MAX_PATH) PCHAR szPath, _In_opt_ HMODULE hModule);

/*
* Return the UTF-8 length of a LPWSTR.
* -- wsz
* -- return
*/
inline DWORD wcslen_u8(_In_z_ LPWSTR wsz)
{
    DWORD dw = wsz ? WideCharToMultiByte(CP_UTF8, 0, wsz, -1, NULL, 0, NULL, NULL) : 0;
    return dw ? dw - 1 : 0;
}

/*
* Duplicates a string.
* CALLER LocalFree return
* -- sz/wsz
* -- return fail: null, success: duplicated string - caller responsible for free with LocalFree()
*/
LPSTR Util_StrDupA(_In_opt_ LPSTR sz);
LPWSTR Util_StrDupW(_In_opt_ LPWSTR wsz);
LPSTR Util_StrDupW2U8(_In_opt_ LPWSTR wsz);

/*
* Convert a FILETIME into a human readable string.
* -- pFileTime
* -- szTime
*/
VOID Util_FileTime2String(_In_ PFILETIME pFileTime, _Out_writes_(24) LPSTR szTime);

/*
* Generic sort function to be used together with qsort. Sorts QWORD.
*/
int Util_qsort_QWORD(const void *pqw1, const void *pqw2);

/*
* Generic table search function to be used together with Util_qfind.
* Finds an entry in a sorted QWORD table.
*/
int Util_qfind_CmpFindTableQWORD(_In_ PVOID pvFind, _In_ PVOID pvEntry);

/*
* Find an entry in a sorted array in an efficient way - O(log2(n)).
* -- pvFind
* -- cMap
* -- pvMap
* -- cbEntry
* -- pfnCmp
* -- piMapOpt = pointer to receive the map index of the located item
* -- return = the entry found or NULL on failure.
*/
_Success_(return != NULL)
PVOID Util_qfind_ex(_In_ PVOID pvFind, _In_ DWORD cMap, _In_ PVOID pvMap, _In_ DWORD cbEntry, _In_ int(*pfnCmp)(_In_ PVOID pvFind, _In_ PVOID pvEntry), _Out_opt_ PDWORD piMapOpt);

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
inline PVOID Util_qfind(_In_ PVOID pvFind, _In_ DWORD cMap, _In_ PVOID pvMap, _In_ DWORD cbEntry, _In_ int(*pfnCmp)(_In_ PVOID pvFind, _In_ PVOID pvEntry))
{
    return Util_qfind_ex(pvFind, cMap, pvMap, cbEntry, pfnCmp, NULL);
}

/*
* Utility functions for read/write towards different underlying data representations.
*/
NTSTATUS Util_VfsReadFile_FromZERO(_In_ QWORD cbFile, _Out_writes_to_(cb, *pcbRead) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset);
NTSTATUS Util_VfsReadFile_FromPBYTE(_In_opt_ PBYTE pbFile, _In_ QWORD cbFile, _Out_writes_to_(cb, *pcbRead) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset);
NTSTATUS Util_VfsReadFile_FromTextWtoU8(_In_opt_ LPWSTR wszValue, _Out_writes_to_(cb, *pcbRead) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset);
NTSTATUS Util_VfsReadFile_FromNumber(_In_ QWORD qwValue, _Out_writes_to_(cb, *pcbRead) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset);
NTSTATUS Util_VfsReadFile_FromQWORD(_In_ QWORD qwValue, _Out_writes_to_(cb, *pcbRead) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset, _In_ BOOL fPrefix);
NTSTATUS Util_VfsReadFile_FromDWORD(_In_ DWORD dwValue, _Out_writes_to_(cb, *pcbRead) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset, _In_ BOOL fPrefix);
NTSTATUS Util_VfsReadFile_FromBOOL(_In_ BOOL fValue, _Out_writes_to_(cb, *pcbRead) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset);
NTSTATUS Util_VfsWriteFile_BOOL(_Inout_ PBOOL pfTarget, _In_reads_(cb) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbWrite, _In_ QWORD cbOffset);
NTSTATUS Util_VfsWriteFile_09(_Inout_ PDWORD pdwTarget, _In_reads_(cb) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbWrite, _In_ QWORD cbOffset);
NTSTATUS Util_VfsWriteFile_DWORD(_Inout_ PDWORD pdwTarget, _In_reads_(cb) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbWrite, _In_ QWORD cbOffset, _In_ DWORD dwMinAllow, _In_opt_ DWORD dwMaxAllow);
NTSTATUS Util_VfsWriteFile_PBYTE(_Inout_ PBYTE pbTarget, _In_ DWORD cbTarget, _In_reads_(cb) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbWrite, _In_ QWORD cbOffset, _In_ BOOL fTerminatingNULL);
VOID Util_VfsTimeStampFile(_In_opt_ PVMM_PROCESS pProcess, _Out_ PVMMDLL_VFS_FILELIST_EXINFO pExInfo);

#endif /* __UTIL_H__ */
