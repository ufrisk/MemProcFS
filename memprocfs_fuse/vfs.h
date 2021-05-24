// vfs.h : definitions related to virtual file system support.
//
// (c) Ulf Frisk, 2018-2021
// Author: Ulf Frisk, pcileech@frizk.net
//
#ifndef __VFS_H__
#define __VFS_H__
#include <vmmdll.h>
#include "oscompatibility.h"

typedef struct tdVFS_ENTRY {
    FILETIME ftCreationTime;
    FILETIME ftLastAccessTime;
    FILETIME ftLastWriteTime;
    QWORD cbFileSize;
    DWORD dwFileAttributes;
    BOOL fDirectory;
    CHAR uszName[2 * MAX_PATH];
} VFS_ENTRY, *PVFS_ENTRY;

typedef void(*PFN_VFSLIST_CALLBACK)(_In_ PVFS_ENTRY pVfsEntry, _In_opt_ PVOID ctx);

/*
* Retrieve information about a single entry inside a directory.
* -- uszPath
* -- uszFile
* -- pVfsEntry
* -- pfPathValid = receives if wszPath is valid or not.
* -- return
*/
_Success_(return)
BOOL VfsList_GetSingle(_In_ LPSTR uszPath, _In_ LPSTR uszFile, _Out_ PVFS_ENTRY pVfsEntry, _Out_ PBOOL pfPathValid);

/*
* List a directory using a callback function
* -- uszPath
* -- ctx = optional context to pass along to callback function.
* -- pfnListCallback = callback function called one time per directory entry.
* -- return = TRUE if directory exists, otherwise FALSE.
*/
BOOL VfsList_ListDirectory(_In_ LPSTR uszPath, _In_opt_ PVOID ctx, _In_opt_ PFN_VFSLIST_CALLBACK pfnListCallback);

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

int vfs_initialize_and_mount_displayinfo(int argc, char *argv[]);

#endif /* __VFS_H__ */
