// vmmdll_remote.h : definitions of remote library functionality:
//     proxying calls to a remote VMMDLL instance hosted by a LeechAgent.
//
// (c) Ulf Frisk, 2023-2025
// Author: Ulf Frisk, pcileech@frizk.net
//
#ifndef __VMMDLL_REMOTE_H__
#define __VMMDLL_REMOTE_H__
#include "vmm.h"

/*
* Initialize a remote MemProcFS from user parameters. Upon success a VMM_HANDLE is returned.
* -- argc
* -- argv
* -- ppLcErrorInfo
* -- return
*/
_Success_(return != NULL)
VMM_HANDLE VmmDllRemote_Initialize(_In_ DWORD argc, _In_ LPCSTR argv[], _Out_opt_ PPLC_CONFIG_ERRORINFO ppLcErrorInfo);

/*
* Close all remote VMM_HANDLE and clean up everything!
* No remote VMM_HANDLE will be valid after this function has been called.
*/
VOID VmmDllRemote_CloseAll();

/*
* Close a remote VMM_HANDLE and clean up everything!
* The remote VMM_HANDLE will not be valid after this function has been called.
* -- H
*/
VOID VmmDllRemote_Close(_In_opt_ _Post_ptr_invalid_ VMM_HANDLE H);

/*
* Remote VMMDLL_ConfigGet().
*/
_Success_(return)
BOOL VmmDllRemote_ConfigGet(_In_ VMM_HANDLE H, _In_ ULONG64 fOption, _Out_ PULONG64 pqwValue);

/*
* Remote VMMDLL_ConfigSet().
*/
_Success_(return)
BOOL VmmDllRemote_ConfigSet(_In_ VMM_HANDLE H, _In_ ULONG64 fOption, _In_ ULONG64 qwValue);

/*
* Remote VMMDLL_VfsListU().
*/
_Success_(return)
BOOL VmmDllRemote_VfsListU(_In_ VMM_HANDLE H, _In_ LPCSTR uszPath, _Inout_ PVMMDLL_VFS_FILELIST2 pFileList);

/*
* Remote VMMDLL_VfsReadU().
*/
NTSTATUS VmmDllRemote_VfsReadU(_In_ VMM_HANDLE H, _In_ LPCSTR uszFileName, _Out_writes_to_(cb, *pcbRead) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ ULONG64 cbOffset);

/*
* Remote VMMDLL_VfsWriteU().
*/
NTSTATUS VmmDllRemote_VfsWriteU(_In_ VMM_HANDLE H, _In_ LPCSTR uszFileName, _In_reads_(cb) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbWrite, _In_ ULONG64 cbOffset);

#endif /* __VMMDLL_REMOTE_H__ */
