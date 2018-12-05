// vmmwin.h : definitions related to windows operating system and processes.
// parsing of virtual memory. Windows related features only.
//
// (c) Ulf Frisk, 2018
// Author: Ulf Frisk, pcileech@frizk.net
//
#ifndef __VMMWIN_H__
#define __VMMWIN_H__
#include "vmm.h"

typedef struct tdVMMWIN_EAT_ENTRY {
    QWORD vaFunction;
    DWORD vaFunctionOffset;
    CHAR szFunction[40];
} VMMPROC_WINDOWS_EAT_ENTRY, *PVMMPROC_WINDOWS_EAT_ENTRY;

typedef struct tdVMMWIN_IAT_ENTRY {
    ULONG64 vaFunction;
    CHAR szFunction[40];
    CHAR szModule[64];
} VMMWIN_IAT_ENTRY, *PVMMWIN_IAT_ENTRY;

/*
* Load the size of the required display buffer for sections, imports and export
* into the pModule struct. The size is a direct consequence of the number of
* functions since fixed line sizes are used for all these types. Loading is
* done in a recource efficient way to minimize I/O as much as possible.
* -- pProcess
* -- pModule
*/
VOID VmmWin_PE_SetSizeSectionIATEAT_DisplayBuffer(_In_ PVMM_PROCESS pProcess, _Inout_ PVMM_MODULEMAP_ENTRY pModule);

/*
* Walk the export address table (EAT) from a given pProcess and store it in the
* in the caller supplied pEATs/pcEATs structures.
* -- pProcess
* -- pModule
* -- pEATs
* -- pcEATs = number max items of pEATs on entry, number of actual items of pEATs on exit
*/
VOID VmmWin_PE_LoadEAT_DisplayBuffer(_Inout_ PVMM_PROCESS pProcess, _Inout_ PVMM_MODULEMAP_ENTRY pModule, _Out_ PVMMPROC_WINDOWS_EAT_ENTRY pEATs, _Inout_ PDWORD pcEATs);

/*
* Walk the import address table (IAT) from a given pProcess and store it in the
* in the caller supplied pIATs/pcIATs structures.
* -- pProcess
* -- pModule
* -- pIATs
* -- pcIATs = number max items of pIATs on entry, number of actual items of pIATs on exit
*/
VOID VmmWin_PE_LoadIAT_DisplayBuffer(_Inout_ PVMM_PROCESS pProcess, _Inout_ PVMM_MODULEMAP_ENTRY pModule, _Out_ PVMMWIN_IAT_ENTRY pIATs, _Inout_ PDWORD pcIATs);

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
VOID VmmWin_PE_DIRECTORY_DisplayBuffer(_In_ PVMM_PROCESS pProcess, _In_ PVMM_MODULEMAP_ENTRY pModule, _Out_opt_ PBYTE pbDisplayBufferOpt, _In_ DWORD cbDisplayBufferMax, _Out_opt_ PDWORD pcbDisplayBuffer, _Out_writes_opt_(16) PIMAGE_DATA_DIRECTORY pDataDirectoryOpt);

/*
* Fill the pbDisplayBuffer with a human readable version of the PE sections.
* Alternatively copy the sections into the pSectionsOpt buffer.
* -- pProcess
* -- pModule
* -- pbDisplayBufferOpt
* -- cbDisplayBufferMax
* -- pcbDisplayBuffer
* -- pcSectionsOpt = size of buffer pSectionsOpt on entry, # returned entries on exit
* -- pSectionsOpt
*/
VOID VmmWin_PE_SECTION_DisplayBuffer(_In_ PVMM_PROCESS pProcess, _In_ PVMM_MODULEMAP_ENTRY pModule, _Out_opt_ PBYTE pbDisplayBufferOpt, _In_ DWORD cbDisplayBufferMax, _Out_opt_ PDWORD pcbDisplayBuffer, _Inout_opt_ PDWORD pcSectionsOpt, _Out_opt_ PIMAGE_SECTION_HEADER pSectionsOpt);

/*
* Initialize the module names into the ctxVMM. This is performed by a PEB/Ldr
* scan of in-process memory structures. This may be unreliable of process is
* obfuscated.
* -- pProcess
*/
VOID VmmWin_InitializeModuleNames(_In_ PVMM_PROCESS pProcess);

/*
* Try walk the EPROCESS list in the Windows kernel to enumerate processes into
* the VMM/PROC file system.
* NB! This may be done to refresh an existing PID cache hence migration code.
* -- pSystemProcess
* -- return
*/
BOOL VmmWin_EnumerateEPROCESS(_In_ PVMM_PROCESS pSystemProcess);

#endif /* __VMMWIN_H__ */
