// vmmlx_loader.h : definitions related to transparent loading of vmm (Windows) or vmmlx (Linux) memory parsing engines.
//
// (c) Ulf Frisk, 2026
// Author: Ulf Frisk, pcileech@frizk.net
//
#ifndef __VMMLOADER_H__
#define __VMMLOADER_H__

#include <vmmdll.h>

/*
* Initialize the vmm loader (required to load the linux engine, vmmlx).
*/
_Success_(return) BOOL VmmlxLoader_Initialize();

/*
* Wrapper functions around the vmm / vmmlx counterparts.
*/
VMM_HANDLE VmmlxLoader_VmmInitialize(_In_ DWORD argc, _In_ LPCSTR argv[]);
VOID VmmlxLoader_VmmCloseAll();
VOID VmmlxLoader_VmmMemFree(_Frees_ptr_opt_ PVOID pvMem);
BOOL VmmlxLoader_VmmConfigGet(_In_ VMM_HANDLE hVMM, _In_ ULONG64 fOption, _Out_ PULONG64 pqwValue);
BOOL VmmlxLoader_VmmConfigSet(_In_ VMM_HANDLE hVMM, _In_ ULONG64 fOption, _In_ ULONG64 qwValue);
BOOL VmmlxLoader_VmmInitializePlugins(_In_ VMM_HANDLE hVMM);
BOOL VmmlxLoader_VmmVfsListU(_In_ VMM_HANDLE hVMM, _In_ LPCSTR uszPath, _Inout_ PVMMDLL_VFS_FILELIST2 pFileList);
NTSTATUS VmmlxLoader_VmmVfsReadU(_In_ VMM_HANDLE hVMM, _In_ LPCSTR uszFileName, _Out_writes_to_(cb, *pcbRead) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ ULONG64 cbOffset);
NTSTATUS VmmlxLoader_VmmVfsWriteU(_In_ VMM_HANDLE hVMM, _In_ LPCSTR uszFileName, _In_reads_(cb) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbWrite, _In_ ULONG64 cbOffset);
NTSTATUS VmmlxLoader_VmmVfsReadW(_In_ VMM_HANDLE hVMM, _In_ LPCWSTR wszFileName, _Out_writes_to_(cb, *pcbRead) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ ULONG64 cbOffset);
NTSTATUS VmmlxLoader_VmmVfsWriteW(_In_ VMM_HANDLE hVMM, _In_ LPCWSTR wszFileName, _In_reads_(cb) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbWrite, _In_ ULONG64 cbOffset);
LPSTR VmmlxLoader_VmmLicensedTo();

/*
* Defines of the original VMMDLL functionality which are forwarded to the wrapper functions.
*/
#ifndef VMMLOADER_NO_REMAP
#define VMMDLL_Initialize          VmmlxLoader_VmmInitialize
#define VMMDLL_CloseAll            VmmlxLoader_VmmCloseAll
#define VMMDLL_MemFree             VmmlxLoader_VmmMemFree
#define VMMDLL_ConfigGet           VmmlxLoader_VmmConfigGet
#define VMMDLL_ConfigSet           VmmlxLoader_VmmConfigSet
#define VMMDLL_InitializePlugins   VmmlxLoader_VmmInitializePlugins
#define VMMDLL_VfsListU            VmmlxLoader_VmmVfsListU
#define VMMDLL_VfsReadU            VmmlxLoader_VmmVfsReadU
#define VMMDLL_VfsWriteU           VmmlxLoader_VmmVfsWriteU
#define VMMDLL_VfsReadW            VmmlxLoader_VmmVfsReadW
#define VMMDLL_VfsWriteW           VmmlxLoader_VmmVfsWriteW
#define VMMDLL_LicensedTo          VmmlxLoader_VmmLicensedTo
#endif /* VMMLOADER_NO_REMAP */

#endif /* __VMMLOADER_H__ */
