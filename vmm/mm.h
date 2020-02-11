// mm.h : definitions related to the core memory manager.
//
// (c) Ulf Frisk, 2018-2020
// Author: Ulf Frisk, pcileech@frizk.net
//
#ifndef __MM_H__
#define __MM_H__
#include "vmm.h"

/*
* Initialize the X86 32-bit protected mode memory model.
* If a previous memory model exists that memory model is first closed before
* the new X86 memory model is initialized.
*/
VOID MmX86_Initialize();

/*
* Initialize the X86 PAE 32-bit protected mode memory model.
* If a previous memory model exists that memory model is first closed before
* the new X86 PAE memory model is initialized.
*/
VOID MmX86PAE_Initialize();

/*
* Initialize the X64 / IA32e / Long-Mode paging / memory model.
* If a previous memory model exists that memory model is first closed before
* the new X64 memory model is initialized.
*/
VOID MmX64_Initialize();

/*
* Initialize the paging sub-system for Windows in a limited or full fashion.
* In full mode Win10 memory decompression will be initialized.
* -- fModeFull
*/
VOID MmWin_PagingInitialize(_In_ BOOL fModeFull);

/*
* Close / Shutdown the paging subsystem. This function should not be called
* when there is an active thread executing inside the sub-system - ideally
* it should only be called on shutdown.
*/
VOID MmWin_PagingClose();

/*
* Initialize / Ensure that a VAD map is initialized for the specific process.
* -- pProcess
* -- fExtendedText = also fetch extended info such as module names.
* -- fVmmRead = VMM_FLAGS_* flags.
* -- return
*/
_Success_(return)
BOOL MmVad_MapInitialize(_In_ PVMM_PROCESS pProcess, _In_ BOOL fExtendedText, _In_ QWORD fVmmRead);

/*
* Try to read a prototype page table entry (PTE).
* -- pProcess
* -- va
* -- pfInRange
* -- fVmmRead = VMM_FLAGS_* flags.
* -- return = prototype pte or zero on fail.
*/
QWORD MmVad_PrototypePte(_In_ PVMM_PROCESS pProcess, _In_ QWORD va, _Out_opt_ PBOOL pfInRange, _In_ QWORD fVmmRead);

#endif /* __MM_H__ */
