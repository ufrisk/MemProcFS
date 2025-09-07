// vmmdll_core.h : definitions of core library functionality which mainly
//      consists of library initialization and cleanup/close functionality.
//
// (c) Ulf Frisk, 2022-2025
// Author: Ulf Frisk, pcileech@frizk.net
//
#ifndef __VMMDLL_CORE_H__
#define __VMMDLL_CORE_H__
#include "vmm.h"

/*
* Query the size of memory allocated by the VMMDLL.
* -- pvMem
* -- return = number of bytes required to hold memory allocation.
*/
_Success_(return != 0)
SIZE_T VmmDllCore_MemSizeExternal(_In_ PVOID pvMem);

/*
* Free memory allocated by the VMMDLL.
* -- pvMem
*/
VOID VmmDllCore_MemFreeExternal(_Frees_ptr_opt_ PVOID pvMem);

/*
* Allocate "external" memory to be free'd only by VMMDLL_MemFree // VmmDllCore_MemFreeExternal.
* CALLER VMMDLL_MemFree(return)
* -- H
* -- tag = tag identifying the type of object.
* -- cb = total size to allocate (not guaranteed to be zero-filled).
* -- cbHdr = size of header (guaranteed to be zero-filled).
* -- return
*/
_Success_(return != NULL)
PVOID VmmDllCore_MemAllocExternal(_In_ VMM_HANDLE H, _In_ DWORD tag, _In_ SIZE_T cb, _In_ SIZE_T cbHdr);

/*
* Copy internal memory to freshly allocated "external" memory to be free'd only
* by VMMDLL_MemFree // VmmDllCore_MemFreeExternal.
* CALLER VMMDLL_MemFree(return)
* -- H
* -- tag = tag identifying the type of object.
* -- pb = source memory to copy.
* -- cb = size of memory to allocation and copy.
* -- return
*/
_Success_(return != NULL)
PVOID VmmDllCore_MemAllocExternalAndCopy(_In_ VMM_HANDLE H, _In_ DWORD tag, _In_reads_bytes_(cb) PBYTE pb, _In_ SIZE_T cb);



/*
* Verify that the supplied handle is valid and also check it out.
* This must be called by each external access which requires a VMM_HANDLE.
* Each successful VmmDllCore_HandleReserveExternal() call must be matched by
* a matched call to VmmDllCore_HandleReturnExternal() after completion.
* -- H
* -- return
*/
_Success_(return)
BOOL VmmDllCore_HandleReserveExternal(_In_opt_ VMM_HANDLE H);

/*
* Return a handle successfully reserved with a previous call to the function:
* VmmDllCore_HandleReserveExternal()
* -- H
*/
VOID VmmDllCore_HandleReturnExternal(_In_opt_ VMM_HANDLE H);

/*
* Duplicate a VMM_HANDLE (increase its handle count).
* NB! this does not "reserve" the handle itself!.
* -- H
* -- return = duplicated handle (with increased dwHandleCount).
*/
_Success_(return != NULL)
VMM_HANDLE VmmDllCore_HandleDuplicate(_In_ VMM_HANDLE H);



/*
* Initialize MemProcFS from user parameters. Upon success a VMM_HANDLE is returned.
* -- argc
* -- argv
* -- ppLcErrorInfo
* -- return
*/
_Success_(return != NULL)
VMM_HANDLE VmmDllCore_Initialize(_In_ DWORD argc, _In_ LPCSTR argv[], _Out_opt_ PPLC_CONFIG_ERRORINFO ppLcErrorInfo);

/*
* Close all VMM_HANDLE and clean up everything! No VMM_HANDLE will be valid
* after this function has been called.
*/
VOID VmmDllCore_CloseAll();

/*
* Close a VMM_HANDLE and clean up everything! The VMM_HANDLE will not be valid
* after this function has been called.
* -- H
*/
VOID VmmDllCore_Close(_In_opt_ _Post_ptr_invalid_ VMM_HANDLE H);

#endif /* __VMMDLL_CORE_H__ */
