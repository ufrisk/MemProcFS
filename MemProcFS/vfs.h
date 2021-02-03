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

/*
* Split a path into path + filename.
* -- wszPath
* -- pwcsFile
* -- wcsFileName
*/
VOID Util_SplitPathFile(_Out_writes_(MAX_PATH) PWCHAR wszPath, _Out_ LPWSTR *pwcsFile, _In_ LPCWSTR wcsFileName);

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
* -- hModuleVmm
* -- dwCacheValidMs
* -- cCacheMaxEntries
* -- return
*/
_Success_(return)
BOOL VfsList_Initialize(_In_ HMODULE hModuleVmm, _In_ DWORD dwCacheValidMs, _In_ DWORD dwCacheMaxEntries);

/*
* Close and clean up the vfs list functionality.
*/
VOID VfsList_Close();

typedef struct tdVMMDLL_FUNCTIONS {
    BOOL(*Initialize)(_In_ DWORD argc, _In_ LPSTR argv[]);
    BOOL(*InitializePlugins)();
    BOOL(*VfsList)(_In_ LPCWSTR wcsPath, _Inout_ PVMMDLL_VFS_FILELIST pFileList);
    DWORD(*VfsRead)(LPCWSTR wcsFileName, _Out_ LPVOID pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ ULONG64 cbOffset);
    DWORD(*VfsWrite)(_In_ LPCWSTR wcsFileName, _In_ LPVOID pb, _In_ DWORD cb, _Out_ PDWORD pcbWrite, _In_ ULONG64 cbOffset);
    BOOL(*ConfigGet)(_In_ ULONG64 fOption, _Out_ PULONG64 pqwValue);
    BOOL(*ConfigSet)(_In_ ULONG64 fOption, _In_ ULONG64 qwValue);
} VMMDLL_FUNCTIONS, *PVMMDLL_FUNCTIONS;

typedef struct tdVMMVFS_CONFIG {
    PVMMDLL_FUNCTIONS pVmmDll;
    FILETIME ftDefaultTime;
    NTSTATUS(*DokanNtStatusFromWin32)(DWORD Error);
    BOOL fInitialized;
} VMMVFS_CONFIG, *PVMMVFS_CONFIG;

PVMMVFS_CONFIG ctxVfs;

/*
* Mount a drive backed by the Memory Process File System. The mounted file system
* will contain both a memory mapped ram files and the file system as seen from
* the target system kernel. NB! This action requires a loaded kernel module and
* that the Dokany file system library and driver have been installed. Please
* see: https://github.com/dokan-dev/dokany/releases
* This also initializes the globalcontext ctxVfs that should be closed by
* calling VfsClose on exit.
* -- chMountPoint
* -- pVmmDll
*/
VOID VfsDokan_InitializeAndMount(_In_ CHAR chMountPoint, _In_ PVMMDLL_FUNCTIONS pVmmDll);

/*
* Close a vfs sub-context in ctxVfs - if exists.
* -- chMountPoint
*/
VOID VfsDokan_Close(_In_ CHAR chMountPoint);

#endif /* __VFS_H__ */
