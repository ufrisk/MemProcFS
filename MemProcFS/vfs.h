// vfs.h : definitions related to virtual file system support.
//
// (c) Ulf Frisk, 2018
// Author: Ulf Frisk, pcileech@frizk.net
//
#ifndef __VFS_H__
#define __VFS_H__
#include <windows.h>
#include "vmmdll.h"

typedef unsigned __int64                QWORD, *PQWORD;

#define VMMVFS_CACHE_DIRECTORY_ENTRIES          15
#define VMMVFS_CACHE_DIRECTORY_LIFETIME_PROC_MS 500

typedef struct tdVMMDLL_FUNCTIONS {
    BOOL(*Initialize)(_In_ DWORD argc, _In_ LPSTR argv[]);
    BOOL(*VfsList)(_In_ LPCWSTR wcsPath, _Inout_ PVMMDLL_VFS_FILELIST pFileList);
    DWORD(*VfsRead)(LPCWSTR wcsFileName, _Out_ LPVOID pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ ULONG64 cbOffset);
    DWORD(*VfsWrite)(_In_ LPCWSTR wcsFileName, _In_ LPVOID pb, _In_ DWORD cb, _Out_ PDWORD pcbWrite, _In_ ULONG64 cbOffset);
    BOOL(*VfsInitializePlugins)();
    BOOL(*ConfigGet)(_In_ ULONG64 fOption, _Out_ PULONG64 pqwValue);
    BOOL(*ConfigSet)(_In_ ULONG64 fOption, _In_ ULONG64 qwValue);
} VMMDLL_FUNCTIONS, *PVMMDLL_FUNCTIONS;

typedef struct tdVMMVFS_CONFIG {
    PVMMDLL_FUNCTIONS pVmmDll;
    FILETIME ftDefaultTime;
    NTSTATUS(*DokanNtStatusFromWin32)(DWORD Error);
    CRITICAL_SECTION CacheDirectoryLock;
    BOOL fInitialized;
    QWORD CacheDirectoryIndex;
    struct {
        QWORD qwExpireTickCount64;
        WCHAR wszDirectoryName[MAX_PATH];
        PVOID pFileList;
    } CacheDirectory[VMMVFS_CACHE_DIRECTORY_ENTRIES];
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
VOID VfsInitializeAndMount(_In_ CHAR chMountPoint, _In_ PVMMDLL_FUNCTIONS pVmmDll);

/*
* Close a vfs sub-context in ctxVfs - if exists.
*/
VOID VfsClose();

#endif /* __VFS_H__ */
