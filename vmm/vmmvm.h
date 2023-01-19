// vmmvm.h : definitions related to virtual machine parsing functionality.
//
// (c) Ulf Frisk, 2022-2023
// Author: Ulf Frisk, pcileech@frizk.net
//
#ifndef __VMMVM_H__
#define __VMMVM_H__
#include "vmm.h"

/*
* Translate a virtual machine (VM) guest physical address (GPA) to:
* (1) Physical Address (PA) _OR_ (2) Virtual Address (VA) in 'vmmem' process.
* -- hVMM
* -- HVM
* -- qwGPA = guest physical address to translate.
* -- pPA = translated physical address (if exists).
* -- pVA = translated virtual address inside 'vmmem' process (if exists).
* -- return = success/fail.
*/
_Success_(return)
BOOL VmmVm_TranslateGPA(_In_ VMM_HANDLE H, _In_ VMMVM_HANDLE HVM, _In_ ULONG64 qwGPA, _Out_opt_ PULONG64 pPA, _Out_opt_ PULONG64 pVA);

/*
* Read guest physical address (GPA) memory.
* -- H
* -- HVM
* -- pb
* -- cb
* -- pcbReadOpt
*/
VOID VmmVm_Read(_In_ VMM_HANDLE H, _In_ VMMVM_HANDLE HVM, _In_ QWORD qwA, _Out_writes_(cb) PBYTE pb, _In_ DWORD cb, _Out_opt_ PDWORD pcbReadOpt);

/*
* Write guest physical address (GPA) memory.
* -- H
* -- HVM
* -- pb
* -- cb
* -- pcbWrite
*/
VOID VmmVm_Write(_In_ VMM_HANDLE H, _In_ VMMVM_HANDLE HVM, _In_ QWORD qwA, _In_ PBYTE pb, _In_ DWORD cb, _Out_opt_ PDWORD pcbWrite);

/*
* Scatter read guest physical address (GPA) memory. Non contiguous 4096-byte pages.
* -- H
* -- HVM
* -- ppMEMsGPA
* -- cpMEMsGPA
*/
VOID VmmVm_ReadScatterGPA(_In_ VMM_HANDLE H, _In_ VMMVM_HANDLE HVM, _Inout_ PPMEM_SCATTER ppMEMsGPA, _In_ DWORD cpMEMsGPA);

/*
* Scatter write guest physical address (GPA) memory. Non contiguous 4096-byte pages.
* -- H
* -- HVM
* -- ppMEMsGPA
* -- cpMEMsGPA
*/
VOID VmmVm_WriteScatterGPA(_In_ VMM_HANDLE H, _In_ VMMVM_HANDLE HVM, _Inout_ PPMEM_SCATTER ppMEMsGPA, _In_ DWORD cpMEMsGPA);

/*
* Retrieve the VMM_HANDLE handle for a VMMVM_HANDLE.
* Also increase the VMM_HANDLE refcount.
* This is not allowed on physical memory only VMs.
* NB! The returned VMM_HANDLE is not "reserved".
* NB! The returned VMM_HANDLE must be closed by VMMDLL_Close().
* -- H
* -- HVM
* -- return
*/
_Success_(return != NULL)
VMM_HANDLE VmmVm_RetrieveNewVmmHandle(_In_ VMM_HANDLE H, _In_ VMMVM_HANDLE HVM);

/*
* Cleanup the VM sub-system. This should ideally be done on Vmm Close().
* -- H
*/
VOID VmmVm_Close(_In_ VMM_HANDLE H);

/*
* Refresh the VM sub-system.
* VM refresh should be called after pool map refresh.
* -- H
*/
VOID VmmVm_Refresh(_In_ VMM_HANDLE H);

/*
* Create a VM map and assign it to the global context upon success.
* CALLER DECREF: return
* -- H
* -- return
*/
PVMMOB_MAP_VM VmmVm_Initialize(_In_ VMM_HANDLE H);

#endif /* __VMMVM_H__ */
