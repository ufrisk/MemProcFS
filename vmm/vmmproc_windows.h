// vmmproc_windows.h : definitions related to windows operating system and processes.
// parsing of virtual memory. Windows related features only.
//
// (c) Ulf Frisk, 2018
// Author: Ulf Frisk, pcileech@frizk.net
//
#ifndef __VMMPROC_WINDOWS_H__
#define __VMMPROC_WINDOWS_H__
#include "vmm.h"

typedef struct tdVMMPROC_WINDOWS_EAT_ENTRY {
    QWORD vaFunction;
    DWORD vaFunctionOffset;
    CHAR szFunction[40];
} VMMPROC_WINDOWS_EAT_ENTRY, *PVMMPROC_WINDOWS_EAT_ENTRY;

typedef struct tdVMMPROC_WINDOWS_IAT_ENTRY {
    ULONG64 vaFunction;
    CHAR szFunction[40];
    CHAR szModule[64];
} VMMPROC_WINDOWS_IAT_ENTRY, *PVMMPROC_WINDOWS_IAT_ENTRY;

/*
* Load the size of the required display buffer for sections, imports and export
* into the pModule struct. The size is a direct consequence of the number of
* functions since fixed line sizes are used for all these types. Loading is
* done in a recource efficient way to minimize I/O as much as possible.
* -- pProcess
* -- pModule
*/
VOID VmmProcWindows_PE_SetSizeSectionIATEAT_DisplayBuffer(_In_ PVMM_PROCESS pProcess, _Inout_ PVMM_MODULEMAP_ENTRY pModule);

/*
* Walk the export address table (EAT) from a given pProcess and store it in the
* in the caller supplied pEATs/pcEATs structures.
* -- pProcess
* -- pModule
* -- pEATs
* -- pcEATs = number max items of pEATs on entry, number of actual items of pEATs on exit
*/
VOID VmmProcWindows_PE_LoadEAT_DisplayBuffer(_Inout_ PVMM_PROCESS pProcess, _Inout_ PVMM_MODULEMAP_ENTRY pModule, _Out_ PVMMPROC_WINDOWS_EAT_ENTRY pEATs, _Inout_ PDWORD pcEATs);

/*
* Walk the import address table (IAT) from a given pProcess and store it in the
* in the caller supplied pIATs/pcIATs structures.
* -- pProcess
* -- pModule
* -- pIATs
* -- pcIATs = number max items of pIATs on entry, number of actual items of pIATs on exit
*/
VOID VmmProcWindows_PE_LoadIAT_DisplayBuffer(_Inout_ PVMM_PROCESS pProcess, _Inout_ PVMM_MODULEMAP_ENTRY pModule, _Out_ PVMMPROC_WINDOWS_IAT_ENTRY pIATs, _Inout_ PDWORD pcIATs);

/*
* Fill the pbDisplayBuffer with a human readable version of the data directories.
* This is guaranteed to be exactly 864 bytes (excluding NULL terminator).
* Alternatively copy the 16 data directories into pDataDirectoryOpt.
* -- pProcess
* -- pModule
* -- pbDisplayBufferOpt
* -- cbDisplayBufferMax
* -- pcbDisplayBuffer
* -- pDataDirectoryOpt
*/
VOID VmmProcWindows_PE_DIRECTORY_DisplayBuffer(_In_ PVMM_PROCESS pProcess, _In_ PVMM_MODULEMAP_ENTRY pModule, _Out_opt_ PBYTE pbDisplayBufferOpt, _In_ DWORD cbDisplayBufferMax, _Out_ PDWORD pcbDisplayBuffer, _Out_opt_ PIMAGE_DATA_DIRECTORY pDataDirectoryOpt);

/*
* Fill the pbDisplayBuffer with a human readable version of the PE sections.
* Alternatively copy the sections into the pSectionsOpt buffer.
* -- pProcess
* -- pModule
* -- pbDisplayBufferOpt
* -- cbDisplayBufferMax
* -- pcbDisplayBuffer
* -- pSectionsOpt
*/
VOID VmmProcWindows_PE_SECTION_DisplayBuffer(_In_ PVMM_PROCESS pProcess, _In_ PVMM_MODULEMAP_ENTRY pModule, _Out_opt_ PBYTE pbDisplayBufferOpt, _In_ DWORD cbDisplayBufferMax, _Out_ PDWORD pcbDisplayBuffer, _Out_opt_ PIMAGE_SECTION_HEADER pSectionsOpt);

/*
* Retrieve the number of: sections, EAT entries or IAT entries depending on the
* function that is called.
* -- pProcess
* -- pModule
* -- pbModuleHeaderOpt = optional PIMAGE_NT_HEADERS structure (either 32 or 64-bit)
* -- fHdr32 = specified whether pbModuleHeaderOpt is a 32-bit or 64-bit header.
* -- return = the number of entries
*/
WORD  VmmProcWindows_PE_GetNumberOfSection(_In_ PVMM_PROCESS pProcess, _Inout_ PVMM_MODULEMAP_ENTRY pModule, _In_opt_ PIMAGE_NT_HEADERS pbModuleHeaderOpt, _In_opt_ BOOL fHdr32);
DWORD VmmProcWindows_PE_GetNumberOfEAT(_In_ PVMM_PROCESS pProcess, _Inout_ PVMM_MODULEMAP_ENTRY pModule, _In_opt_ PIMAGE_NT_HEADERS pbModuleHeaderOpt, _In_opt_ BOOL fHdr32);
DWORD VmmProcWindows_PE_GetNumberOfIAT(_In_ PVMM_PROCESS pProcess, _Inout_ PVMM_MODULEMAP_ENTRY pModule, _In_opt_ PIMAGE_NT_HEADERS pbModuleHeaderOpt, _In_opt_ BOOL fHdr32);

/*
* Initialize the module names into the ctxVMM. This is performed by a PEB/Ldr
* scan of in-process memory structures. This may be unreliable of process is
* obfuscated.
* -- pProcess
*/
VOID VmmProcWindows_InitializeModuleNames(_In_ PVMM_PROCESS pProcess);

/*
* Try walk the EPROCESS list in the Windows kernel to enumerate processes into
* the VMM/PROC file system.
* NB! This may be done to refresh an existing PID cache hence migration code.
* -- pSystemProcess
* -- return
*/
BOOL VmmProcWindows_EnumerateEPROCESS(_In_ PVMM_PROCESS pSystemProcess);

/*
* Try initialize the VMM from scratch with new WINDOWS support.
* -- paPML4Opt
* -- vaKernelBaseOpt
* -- return
*/
BOOL VmmProcWindows_TryInitialize(_In_opt_ QWORD paPML4Opt, _In_opt_ QWORD vaKernelBaseOpt);

#endif /* __VMMPROC_WINDOWS_H__ */
