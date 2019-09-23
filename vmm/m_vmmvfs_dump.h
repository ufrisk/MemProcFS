// m_vmmvfs_dump.h : declaration of vmmvfs memory dump file functionality which
//                   shows the raw memory dump microsoft crash dump files in
//                   the virtual file system root.
// NB! this is not a normal plugin.
//
// (c) Ulf Frisk, 2019
// Author: Ulf Frisk, pcileech@frizk.net
//
#ifndef __M_VMMVFS_DUMP_H__
#define __M_VMMVFS_DUMP_H__
#include <Windows.h>
#include "vmmdll.h"

/*
* Read from memory dump files in the virtual file system root.
* -- wcsFileName
* -- pb
* -- cb
* -- pcbRead
* -- cbOffset
* -- return
*/
NTSTATUS MVmmVfsDump_Read(_In_ LPCWSTR wcsFileName, _Out_writes_(cb) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset);

/*
* Write to memory dump files in the virtual file system root. This requires a
* write-capable backend device/driver. Also the crash dump header in microsoft
* crash dumps aren't writable.
* -- wcsFileName
* -- pb
* -- cb
* -- pcbWrite
* -- cbOffset
* -- return
*/
NTSTATUS MVmmVfsDump_Write(_In_ LPCWSTR wcsFileName, _In_reads_(cb) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbWrite, _In_ QWORD cbOffset);

/*
* List dump files in the virtual file system root.
* -- pFileList
*/
VOID MVmmVfsDump_List(_Inout_ PHANDLE pFileList);

#endif /* __M_VMMVFS_DUMP_H__ */
