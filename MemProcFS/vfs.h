// vfs.h : definitions related to virtual file system support.
//
// (c) Ulf Frisk, 2018-2021
// Author: Ulf Frisk, pcileech@frizk.net
//
#ifndef __VFS_H__
#define __VFS_H__
#include <windows.h>
#include <vmmdll.h>

typedef unsigned __int64                QWORD, *PQWORD;

typedef int(*PFN_VFSLIST_CALLBACK)(_In_ PWIN32_FIND_DATAW pFindData, _In_opt_ PVOID ctx);

#define CHARUTIL_FLAG_NONE                      0x0000
#define CHARUTIL_FLAG_ALLOC                     0x0001
#define CHARUTIL_FLAG_TRUNCATE                  0x0002
#define CHARUTIL_FLAG_TRUNCATE_ONFAIL_NULLSTR   0x0006
#define CHARUTIL_FLAG_STR_BUFONLY               0x0008
#define CHARUTIL_CONVERT_MAXSIZE                0x40000000

/*
* WRAPPER FUNCTION AROUND LOCAL/REMOTE VMMDLL_ConfigGet
* Set a device specific option value. Please see defines VMMDLL_OPT_* for infor-
* mation about valid option values. Please note that option values may overlap
* between different device types with different meanings.
* -- fOption
* -- pqwValue = pointer to ULONG64 to receive option value.
* -- return = success/fail.
*/
_Success_(return)
BOOL MemProcFS_ConfigGet(_In_ ULONG64 fOption, _Out_ PULONG64 pqwValue);

/*
* WRAPPER FUNCTION AROUND LOCAL/REMOTE VMMDLL_ConfigSet
* Set a device specific option value. Please see defines VMMDLL_OPT_* for infor-
* mation about valid option values. Please note that option values may overlap
* between different device types with different meanings.
* -- fOption
* -- qwValue
* -- return = success/fail.
*/
_Success_(return)
BOOL MemProcFS_ConfigSet(_In_ ULONG64 fOption, _In_ ULONG64 qwValue);

/*
* WRAPPER FUNCTION AROUND LOCAL/REMOTE VMMDLL_VfsListW
* List a directory of files in MemProcFS. Directories and files will be listed
* by callbacks into functions supplied in the pFileList parameter.
* If information of an individual file is needed it's neccessary to list all
* files in its directory.
* -- wszPath
* -- pFileList
* -- return
*/
_Success_(return) BOOL MemProcFS_VfsListW(_In_ LPWSTR wszPath, _Inout_ PVMMDLL_VFS_FILELIST2 pFileList);

/*
* WRAPPER FUNCTION AROUND LOCAL/REMOTE VMMDLL_VfsReadW
* Read select parts of a file in MemProcFS.
* -- wszFileName
* -- pb
* -- cb
* -- pcbRead
* -- cbOffset
* -- return
*
*/
NTSTATUS MemProcFS_VfsReadW(_In_ LPWSTR wszFileName, _Out_writes_to_(cb, *pcbRead) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ ULONG64 cbOffset);

/*
* WRAPPER FUNCTION AROUND LOCAL/REMOTE VMMDLL_VfsWriteW
* Write select parts to a file in MemProcFS.
* -- wszFileName
* -- pb
* -- cb
* -- pcbWrite
* -- cbOffset
* -- return
*/
NTSTATUS MemProcFS_VfsWriteW(_In_ LPWSTR wszFileName, _In_reads_(cb) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbWrite, _In_ ULONG64 cbOffset);

/*
* Convert UTF-8 string into a Windows Wide-Char string.
* Function support usz == pbBuffer - usz will then become overwritten.
* CALLER LOCALFREE (if *pusz != pbBuffer): *pusz
* -- [uw]sz = the string to convert.
* -- cch = -1 for null-terminated string; or max number of chars (excl. null).
* -- pbBuffer = optional buffer to place the result in.
* -- cbBuffer
* -- pusz = if set to null: function calculate length only and return TRUE.
            result wide-string, either as (*pwsz == pbBuffer) or LocalAlloc'ed
*           buffer that caller is responsible for free.
* -- pcbu = byte length (including terminating null) of wide-char string.
* -- flags = CHARUTIL_FLAG_NONE, CHARUTIL_FLAG_ALLOC or CHARUTIL_FLAG_TRUNCATE
* -- return
*/
_Success_(return)
BOOL CharUtil_UtoW(_In_opt_ LPSTR usz, _In_ DWORD cch, _Maybenull_ _Writable_bytes_(cbBuffer) PBYTE pbBuffer, _In_ DWORD cbBuffer, _Out_opt_ LPWSTR *pwsz, _Out_opt_ PDWORD pcbw, _In_ DWORD flags);
_Success_(return)
BOOL CharUtil_WtoU(_In_opt_ LPWSTR wsz, _In_ DWORD cch, _Maybenull_ _Writable_bytes_(cbBuffer) PBYTE pbBuffer, _In_ DWORD cbBuffer, _Out_opt_ LPSTR *pusz, _Out_opt_ PDWORD pcbu, _In_ DWORD flags);

/*
* Split a path into path + filename.
* -- wszPath
* -- pwcsFile
* -- wcsFileName
*/
VOID Util_SplitPathFile(_Out_writes_(MAX_PATH) PWCHAR wszPath, _Out_ LPWSTR *pwcsFile, _In_ LPCWSTR wcsFileName);

/*
* Hash a path in uppercase.
* -- wszPath
* -- return
*/
QWORD Util_HashPathW(_In_ LPWSTR wszPath);

/*
* Hash a string in uppercase.
* -- wsz
* -- return
*/
DWORD Util_HashStringUpperW(_In_opt_ LPWSTR wsz);

/*
* Retrieve information about a single entry inside a directory.
* -- wszPath
* -- wszFile
* -- pFindData
* -- pfPathValid = receives if wszPath is valid or not.
* -- return
*/
_Success_(return)
BOOL VfsList_GetSingle(_In_ LPWSTR wszPath, _In_ LPWSTR wszFile, _Out_ PWIN32_FIND_DATAW pFindData, _Out_ PBOOL pfPathValid);

/*
* List a directory using a callback function
* -- wszPath
* -- ctx = optional context to pass along to callback function.
* -- pfnListCallback = callback function called one time per directory entry.
* -- return = TRUE if directory exists, otherwise FALSE.
*/
BOOL VfsList_ListDirectory(_In_ LPWSTR wszPath, _In_opt_ PVOID ctx, _In_opt_ PFN_VFSLIST_CALLBACK pfnListCallback);

/*
* Initialize the vfs list functionality.
* -- dwCacheValidMs
* -- cCacheMaxEntries
* -- return
*/
_Success_(return)
BOOL VfsList_Initialize(_In_ DWORD dwCacheValidMs, _In_ DWORD dwCacheMaxEntries);

/*
* Close and clean up the vfs list functionality.
*/
VOID VfsList_Close();

typedef struct tdVMMVFS_CONFIG {
    FILETIME ftDefaultTime;
    NTSTATUS(*DokanNtStatusFromWin32)(DWORD Error);
    BOOL fInitialized;
} VMMVFS_CONFIG, *PVMMVFS_CONFIG;

PVMMVFS_CONFIG ctxVfs;
HANDLE g_hLC_RemoteFS;

/*
* Mount a drive backed by the Memory Process File System. The mounted file system
* will contain both a memory mapped ram files and the file system as seen from
* the target system kernel. NB! This action requires a loaded kernel module and
* that the Dokany file system library and driver have been installed. Please
* see: https://github.com/dokan-dev/dokany/releases
* This also initializes the globalcontext ctxVfs that should be closed by
* calling VfsClose on exit.
* -- chMountPoint
*/
VOID VfsDokan_InitializeAndMount(_In_ CHAR chMountPoint);

/*
* Close a vfs sub-context in ctxVfs - if exists.
* -- chMountPoint
*/
VOID VfsDokan_Close(_In_ CHAR chMountPoint);

#endif /* __VFS_H__ */
