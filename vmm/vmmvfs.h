// vmmvfs.h : definitions related to virtual memory management / virtual file system interfacing.
//
// (c) Ulf Frisk, 2018-2019
// Author: Ulf Frisk, pcileech@frizk.net
//
#ifndef __VMMVFS_H__
#define __VMMVFS_H__
#include "vmm.h"

/*
* List files in the virtual file system directory specified by the path name.
* -- wcsPath
* -- pFileList
* -- return
*/
BOOL VmmVfs_List(_In_ LPCWSTR wcsPath, _Inout_ PHANDLE pFileList);

/*
* Read the contents of a file into the caller supplied buffer. This file may be
* a memory file or any other file in the "proc" virtual file system.
* -- wcsFileName = full path file name
* -- pb          = buffer
* -- cb          = bytes to read/size of pb
* -- pcbRead     = bytes actually read
* -- cbOffset    = offset where to start read compared to file start
*/
NTSTATUS VmmVfs_Read(_In_ LPCWSTR wcsFileName, _Out_ LPVOID pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset);

/*
* Write the contents of a file into the caller supplied buffer. This file may be
* a memory file or any other file in the "proc" virtual file system.
* -- wcsFileName = full path file name
* -- pb          = buffer
* -- cb          = bytes to read/size of pb
* -- pcbWrite    = bytes actually read
* -- cbOffset    = offset where to start read compared to file start
*/
NTSTATUS VmmVfs_Write(_In_ LPCWSTR wcsFileName, _In_ LPVOID pb, _In_ DWORD cb, _Out_ PDWORD pcbWrite, _In_ QWORD cbOffset);

#endif /* __VMMVFS_H__ */
