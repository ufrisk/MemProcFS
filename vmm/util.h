// util.h : definitions of various utility functions.
//
// (c) Ulf Frisk, 2018-2025
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
* -- sz
* -- return
*/
QWORD Util_GetNumericA(_In_ LPCSTR sz);

/*
* SHA256 hash data.
* -- pbData
* -- cbData
* -- pbHash
* -- return
*/
_Success_(return)
BOOL Util_HashSHA256(_In_reads_(cbData) PBYTE pbData, _In_ DWORD cbData, _Out_writes_(32) PBYTE pbHash);

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
BOOL Util_DecompressGz(_In_ PBYTE pbCompressed, _In_ DWORD cbCompressed, _In_ DWORD cbDecompressed, _Out_writes_(cbDecompressed) PBYTE pbDecompressed);

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
BOOL Util_DecompressGzToStringAlloc(_In_ PBYTE pbCompressed, _In_ DWORD cbCompressed, _In_ DWORD cbDecompressed, _Out_ LPSTR *pszDecompressed);

/*
* Delete a file denoted by its utf-8 full path.
* -- uszPathFile
*/
VOID Util_DeleteFileU(_In_ LPCSTR uszPathFile);

/*
* Utility function to check whether a buffer is zeroed.
* -- pb
* -- cb
* -- return
*/
BOOL Util_IsZeroBuffer(_In_ PBYTE pb, _In_ DWORD cb);

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
* Fill a human readable hex ascii memory dump into the caller supplied sz buffer.
* -- pb = bytes (may only be NULL if sz is NULL for size query).
* -- cb
* -- qwAddress = the start address in the address column.
* -- sz = buffer to fill, NULL to retrieve buffer size in pcsz parameter.
* -- pcsz = IF sz==NULL :: size of buffer (including space for terminating NULL) on exit
*           IF sz!=NULL :: size of buffer on entry, size of characters (excluding terminating NULL) on exit.
*/
_Success_(return)
BOOL Util_FillHexAscii_WithAddress(
    _In_reads_opt_(cb) PBYTE pb,
    _In_ DWORD cb,
    _In_ QWORD qwAddress,
    _Out_writes_opt_(*pcsz) LPSTR sz,
    _Inout_ PDWORD pcsz
);

/*
* Replaces ascii characters not allowed in file names in the NULL-terminated
* string sz.
* -- sz
* -- chDefault
*/
VOID Util_AsciiFileNameFix(_Inout_ LPSTR sz, _In_ CHAR chDefault);

/*
* Prepend a path with a hexascii address value.
* -- uszDstBuffer
* -- va
* -- f32
* -- uszText
*/
VOID Util_PathPrependVA(_Out_writes_(MAX_PATH) LPSTR uszDstBuffer, _In_ QWORD va, _In_ BOOL f32, _In_ LPCSTR uszText);

/*
* snprintf to a utf-8. The result is guaranteed to be NULL terminated.
* -- uszBuffer
* -- cszLineLength
* -- uszFormat = printf format string.
* -- ... = printf varargs.
* -- return = the number of bytes written (excluding terminating null).
*/
_Success_(return >= 0)
size_t Util_usnprintf_ln(
    _Out_writes_(cszLineLength + 1) LPSTR uszBuffer,
    _In_ QWORD cszLineLength,
    _In_z_ _Printf_format_string_ LPCSTR uszFormat,
    ...
);

/*
* Return the path of the specified hModule (DLL) - ending with a backslash, or current Executable.
* -- szPath
* -- hModule = Optional, HMODULE handle for path to DLL, NULL for path to EXE.
*/
VOID Util_GetPathDll(_Out_writes_(MAX_PATH) PCHAR szPath, _In_opt_ HMODULE hModule);

/*
* Retrieve the operating system path of the directory which is containing this:
* .dll/.so file.
* -- szPath
*/
VOID Util_GetPathLib(_Out_writes_(MAX_PATH) PCHAR szPath);

/*
* Duplicates a string.
* CALLER LocalFree return
* -- sz/wsz
* -- return fail: null, success: duplicated string - caller responsible for free with LocalFree()
*/
LPSTR Util_StrDupA(_In_opt_ LPCSTR sz);

/*
* Retrieve the current time as FILETIME.
*/
QWORD Util_FileTimeNow();

/*
* Convert a FILETIME (ft) into a human readable string.
* -- ft = the FILETIME in UTC time zone.
* -- szTime = time in format '2020-01-01 23:59:59 UCT' (23 chars).
*/
VOID Util_FileTime2String(_In_ QWORD ft, _Out_writes_(24) LPSTR szTime);

/*
* Convert a FILETIME (ft) into a JSON string.
* -- ft = the FILETIME in UTC time zone.
* -- szTime = time in format '2020-01-01T23:59:59Z' (20 chars).
* -- return
*/
BOOL Util_FileTime2JSON(_In_ QWORD ft, _Out_writes_(21) LPSTR szTime);

/*
* Convert a FILETIME (ft) into a CSV string.
* -- ft = the FILETIME in UTC time zone.
* -- szTime = time in format '"2020-01-01 23:59:59"' (21 chars).
* -- return
*/
VOID Util_FileTime2CSV(_In_ QWORD ft, _Out_writes_(22) LPSTR szTime);

/*
* Convert a ISO8601 time string on the format '2021-04-02T07:17:02.1569629Z' to
* a Windows FILETIME format.
* -- szIso8601
* -- return
*/
_Success_(return != 0)
QWORD Util_TimeIso8601ToFileTime(_In_ LPSTR szIso8601);

/*
* Convert a GUID in byte format to a GUID in string format.
* -- pbGUID = 16-byte GUID value.
* -- szGUID = 37-byte buffer to receive GUID string.
*/
VOID Util_GuidToString(_In_reads_(16) PBYTE pb, _Out_writes_(37) LPSTR szGUID);

/*
* Generic sort function to be used together with qsort. Sorts DWORD/QWORD.
*/
int Util_qsort_DWORD(const void *pdw1, const void *pdw2);
int Util_qsort_QWORD(const void *pqw1, const void *pqw2);

typedef int(*UTIL_QFIND_CMP_PFN)(_In_ QWORD qwFind, _In_ QWORD qwEntry);

/*
* Generic table search function to be used together with Util_qfind.
* Finds an entry in a sorted DWORD table.
*/
int Util_qfind_CmpFindTableDWORD(_In_ QWORD qwFind, _In_ QWORD qwEntry);

/*
* Generic table search function to be used together with Util_qfind.
* Finds an entry in a sorted QWORD table.
*/
int Util_qfind_CmpFindTableQWORD(_In_ QWORD pvFind, _In_ QWORD pvEntry);

/*
* Find an entry in a sorted array in an efficient way - O(log2(n)).
* -- qwFind
* -- cMap
* -- pvMap
* -- cbEntry
* -- pfnCmp
* -- piMapOpt = pointer to receive the map index of the located item
* -- return = the entry found or NULL on failure.
*/
_Success_(return != NULL)
PVOID Util_qfind_ex(_In_ QWORD qwFind, _In_ DWORD cMap, _In_ PVOID pvMap, _In_ DWORD cbEntry, _In_ UTIL_QFIND_CMP_PFN pfnCmp, _Out_opt_ PDWORD piMapOpt);

/*
* Find an entry in a sorted array in an efficient way - O(log2(n)).
* -- qwFind
* -- cMap
* -- pvMap
* -- cbEntry
* -- pfnCmp
* -- return = the entry found or NULL on failure.
*/
_Success_(return != NULL)
PVOID Util_qfind(_In_ QWORD qwFind, _In_ DWORD cMap, _In_ PVOID pvMap, _In_ DWORD cbEntry, _In_ UTIL_QFIND_CMP_PFN pfnCmp);

/*
* Utility functions for read/write towards different underlying data representations.
*/
NTSTATUS Util_VfsReadFile_FromZERO(_In_ QWORD cbFile, _Out_writes_to_(cb, *pcbRead) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset);
NTSTATUS Util_VfsReadFile_FromPBYTE(_In_opt_ PBYTE pbFile, _In_ QWORD cbFile, _Out_writes_to_(cb, *pcbRead) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset);
NTSTATUS Util_VfsReadFile_FromHEXASCII(_In_opt_ PBYTE pbFile, _In_ QWORD cbFile, _Out_writes_to_(cb, *pcbRead) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset);
NTSTATUS Util_VfsReadFile_FromStrA(_In_opt_ LPCSTR szFile, _Out_writes_to_(cb, *pcbRead) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset);
NTSTATUS Util_VfsReadFile_FromMEM(_In_ VMM_HANDLE H, _In_opt_ PVMM_PROCESS pProcess, _In_ QWORD vaMEM, _In_ QWORD cbMEM, _In_ QWORD flags, _Out_writes_to_(cb, *pcbRead) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset);
NTSTATUS Util_VfsReadFile_FromObData(_In_opt_ POB_DATA pData, _Out_writes_to_(cb, *pcbRead) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset);
NTSTATUS Util_VfsReadFile_FromObCompressed(_In_opt_ POB_COMPRESSED pdc, _Out_writes_to_(cb, *pcbRead) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset);
NTSTATUS Util_VfsReadFile_FromObCompressedStrA(_In_opt_ POB_COMPRESSED pdc, _Out_writes_to_(cb, *pcbRead) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset);
NTSTATUS Util_VfsReadFile_FromNumber(_In_ QWORD qwValue, _Out_writes_to_(cb, *pcbRead) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset);
NTSTATUS Util_VfsReadFile_FromQWORD(_In_ QWORD qwValue, _Out_writes_to_(cb, *pcbRead) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset, _In_ BOOL fPrefix);
NTSTATUS Util_VfsReadFile_FromDWORD(_In_ DWORD dwValue, _Out_writes_to_(cb, *pcbRead) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset, _In_ BOOL fPrefix);
NTSTATUS Util_VfsReadFile_FromBOOL(_In_ BOOL fValue, _Out_writes_to_(cb, *pcbRead) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset);
NTSTATUS Util_VfsReadFile_FromFILETIME(_In_ QWORD ftValue, _Out_writes_to_(cb, *pcbRead) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset);
NTSTATUS Util_VfsReadFile_FromResource(_In_ VMM_HANDLE H, _In_ LPWSTR wszResourceName, _Out_writes_to_(cb, *pcbRead) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset);
NTSTATUS Util_VfsReadFile_usnprintf_ln(_Out_writes_to_(cb, *pcbRead) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset, _In_ QWORD cszLineLength, _In_z_ _Printf_format_string_ LPCSTR uszFormat, ...);
NTSTATUS Util_VfsWriteFile_BOOL(_Inout_ PBOOL pfTarget, _In_reads_(cb) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbWrite, _In_ QWORD cbOffset);
NTSTATUS Util_VfsWriteFile_09(_Inout_ PDWORD pdwTarget, _In_reads_(cb) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbWrite, _In_ QWORD cbOffset);
NTSTATUS Util_VfsWriteFile_DWORD(_Inout_ PDWORD pdwTarget, _In_reads_(cb) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbWrite, _In_ QWORD cbOffset, _In_ DWORD dwMinAllow, _In_opt_ DWORD dwMaxAllow);
NTSTATUS Util_VfsWriteFile_QWORD(_Inout_ PQWORD pqwTarget, _In_reads_(cb) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbWrite, _In_ QWORD cbOffset, _In_ QWORD qwMinAllow, _In_opt_ QWORD qwMaxAllow);
NTSTATUS Util_VfsWriteFile_PBYTE(_Inout_ PBYTE pbTarget, _In_ DWORD cbTarget, _In_reads_(cb) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbWrite, _In_ QWORD cbOffset, _In_ BOOL fTerminatingNULL);
NTSTATUS Util_VfsWriteFile_HEXASCII(_Inout_ PBYTE pbTarget, _In_ DWORD cbTarget, _In_reads_(cb) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbWrite, _In_ QWORD cbOffset);
DWORD Util_ResourceSize(_In_ VMM_HANDLE H, _In_ LPWSTR wszResourceName);
VOID Util_VfsTimeStampFile(_In_ VMM_HANDLE H, _In_opt_ PVMM_PROCESS pProcess, _Out_ PVMMDLL_VFS_FILELIST_EXINFO pExInfo);

/*
* Retrieve PID / ID number from path (in base10). This is commonly used to
* parse pid from process name in the 'name' / 'pid' folders.
* -- uszPath
* -- fHex
* -- pdwID
* -- puszSubPath
* -- return
*/
_Success_(return)
BOOL Util_VfsHelper_GetIdDir(_In_ LPCSTR uszPath, _In_ BOOL fHex, _Out_ PDWORD pdwID, _Out_opt_ LPCSTR *puszSubPath);

#define UTIL_VFSLINEFIXED_LINECOUNT(H, c)                  (c + (H->cfg.fFileInfoHeader ? 2ULL : 0ULL))
#define UTIL_VFSLINEVARIABLE_BYTECOUNT(H, c, pdwo, szHdr)  ((c ? (pdwo[c - 1]) : 0) + (H->cfg.fFileInfoHeader ? 2 * strlen(szHdr) + 2 : 0ULL))

/*
* FixedLineRead: Callback function to populate a fixed-length line in a
* dynamically created file. Line data should be written in utf-8 with the
* function: Util_snwprintf_u8ln(). Line data MUST ALWAYS be written!
* -- H = VMM handle.
* -- ctx = optional context.
* -- cbLineLength = line length including newline, excluding null terminator.
* -- ie = line index.
* -- pe = the single entry to process.
* -- szu8 = utf-8 string to write line data into.
*/
typedef VOID(*UTIL_VFSLINEFIXED_PFN_CB)(
    _In_ VMM_HANDLE H,
    _Inout_opt_ PVOID ctx,
    _In_ DWORD cbLineLength,
    _In_ DWORD ie,
    _In_ PVOID pe,
    _Out_writes_(cbLineLength + 1) LPSTR szu8
    );

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
);

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
);

/*
* Util_VfsLineFixedMapCustom_Read: Callback function to retrieve an entry.
* -- H
* -- pMap
* -- iMap
*/
typedef PVOID(*UTIL_VFSLINEFIXED_MAP_PFN_CB)(
    _In_ VMM_HANDLE H,
    _In_ PVOID ctxMap,
    _In_ DWORD iMap
    );

/*
* Util_VfsLineFixedMapCustom_Read: Read from a file dynamically created from a
* custom generator callback function using using a callback function to
* populate individual lines (excluding header).
* -- H = VMM handle.
* -- pfnCallback = callback function to populate individual lines.
* -- ctx = optional context to 'pfn' callback function.
* -- cbLineLength = line length, including newline, excluding null terminator.
* -- wszHeader = optional header line.
* -- ctxMap = 'map context' for single entry callback function.
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
);

#endif /* __UTIL_H__ */
