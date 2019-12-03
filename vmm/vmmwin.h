// vmmwin.h : definitions related to windows operating system and processes.
// parsing of virtual memory. Windows related features only.
//
// (c) Ulf Frisk, 2018-2019
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
* into the pModuleEx struct. The size is a direct consequence of the number of
* functions since fixed line sizes are used for all these types. Loading is
* done in a recource efficient way to minimize I/O as much as possible.
* -- pProcess
* -- pModule
*/
VOID VmmWin_PE_SetSizeSectionIATEAT_DisplayBuffer(_In_ PVMM_PROCESS pProcess, _In_ PVMM_MAP_MODULEENTRY pModule);

/*
* Walk the export address table (EAT) from a given pProcess and store it in the
* in the caller supplied pEATs/pcEATs structures.
* -- pProcess
* -- pModule
* -- pEATs
* -- cEATs
* -- pcEATs = number of actual items of pEATs written.
* -- return
*/
_Success_(return)
BOOL VmmWin_PE_LoadEAT_DisplayBuffer(_In_ PVMM_PROCESS pProcess, _In_ PVMM_MAP_MODULEENTRY pModule, _Out_writes_opt_(cEATs) PVMMPROC_WINDOWS_EAT_ENTRY pEATs, _In_ DWORD cEATs, _Out_ PDWORD pcEATs);

/*
* Walk the import address table (IAT) from a given pProcess and store it in the
* in the caller supplied pIATs/pcIATs structures.
* -- pProcess
* -- pModule
* -- pIATs
* -- cIATs
* -- pcIATs = number of actual items of pIATs on exit
*/
VOID VmmWin_PE_LoadIAT_DisplayBuffer(_In_ PVMM_PROCESS pProcess, _In_ PVMM_MAP_MODULEENTRY pModule, _Out_writes_(*pcIATs) PVMMWIN_IAT_ENTRY pIATs, _In_ DWORD cIATs, _Out_ PDWORD pcIATs);

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
VOID VmmWin_PE_DIRECTORY_DisplayBuffer(
    _In_ PVMM_PROCESS pProcess,
    _In_ PVMM_MAP_MODULEENTRY pModule,
    _Out_writes_bytes_opt_(*pcbDisplayBuffer) PBYTE pbDisplayBufferOpt,
    _In_ DWORD cbDisplayBufferMax,
    _Out_opt_ PDWORD pcbDisplayBuffer,
    _Out_writes_opt_(16) PIMAGE_DATA_DIRECTORY pDataDirectoryOpt);

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
VOID VmmWin_PE_SECTION_DisplayBuffer(
    _In_ PVMM_PROCESS pProcess,
    _In_ PVMM_MAP_MODULEENTRY pModule,
    _Out_writes_bytes_opt_(*pcbDisplayBuffer) PBYTE pbDisplayBufferOpt,
    _In_ DWORD cbDisplayBufferMax,
    _Out_opt_ PDWORD pcbDisplayBuffer,
    _Inout_opt_ PDWORD pcSectionsOpt,
    _Out_writes_opt_(*pcSectionsOpt) PIMAGE_SECTION_HEADER pSectionsOpt);

/*
* Try initialize PteMap text descriptions. This function will first try to pop-
* ulate the pre-existing VMMOB_MAP_PTE object in pProcess with module names and
* then, if failed or partially failed, try to initialize from PE file headers.
* -- pProcess
*/
BOOL VmmWin_InitializePteMapText(_In_ PVMM_PROCESS pProcess);

/*
* Initialize the module map containing information about loaded modules in the
* system. This is performed by a PEB/Ldr walk/scan of in-process memory
* structures. This may be unreliable if a process is obfuscated or tampered.
* -- pProcess
* -- return
*/
_Success_(return)
BOOL VmmWin_InitializeLdrModules(_In_ PVMM_PROCESS pProcess);

/*
* Initialize the meap map containing information about the process heaps in the
* specific process. This is performed by a PEB walk/scan of in-process memory
* structures. This may be unreliable if a process is obfuscated or tampered.
* -- pProcess
* -- return
*/
BOOL VmmWinHeap_Initialize(_In_ PVMM_PROCESS pProcess);

/*
* Initialize the thread map for a specific process.
* NB! The threading sub-system is dependent on pdb symbols and may take a small
* amount of time before it's available after system startup.
* -- pProcess
* -- fNonBlocking
* -- return
*/
BOOL VmmWinThread_Initialize(_In_ PVMM_PROCESS pProcess, _In_ BOOL fNonBlocking);

/*
* Initialize Handles for a specific process. Extended information text may take
* extra time to initialize.
* -- pProcess
* -- fExtendedText = also fetch extended info such as handle paths/names.
* -- return
*/
_Success_(return)
BOOL VmmWinHandle_Initialize(_In_ PVMM_PROCESS pProcess, _In_ BOOL fExtendedText);

/*
* Retrieve a pointer to a VMMWIN_OBJECT_TYPE if possible. Initialization of the
* table takes place on first use. The table only exists in Win7+ and is is
* dependant on PDB symbol functionality for initialization.
* -- iObjectType
* -- return
*/
_Success_(return != NULL)
PVMMWIN_OBJECT_TYPE VmmWin_ObjectTypeGet(_In_ BYTE iObjectType);

/*
* Try walk the EPROCESS list in the Windows kernel to enumerate processes into
* the VMM/PROC file system.
* NB! This may be done to refresh an existing PID cache hence migration code.
* -- fTotalRefresh = create completely new process entries (instead of updating).
* -- pSystemProcess
* -- return
*/
BOOL VmmWin_EnumerateEPROCESS(_In_ PVMM_PROCESS pSystemProcess, _In_ BOOL fRefreshTotal);

/*
* Walk a windows linked list in an efficient way that minimize IO requests to
* the the device. This is advantageous for latency reasons. The function return
* a set of the addresses used - this may be used to prefetch pages in advance
* if the list should be walked again at a later time.
* The callback function must only return FALSE on severe errors when the list
* should no longer be continued to be walked in the direction.
* CALLER_DECREF: return
* -- pProcess
* -- f32 = TRUE if 32-bit, FALSE if 64-bit
* -- ctx = ctx to pass along to callback function (if any)
* -- cvaDataStart
* -- pvaDataStart
* -- oListStart = offset (in bytes) to _LIST_ENTRY from vaDataStart
* -- cbData
* -- pfnCallback_Pre = optional callback function to gather additional addresses.
* -- pfnCallback_Post = optional callback function called after all pages fetched into cache.
* -- pContainerPrefetch = optional pointer to a PVMMOBCONTAINER containing a POB_VSET of prefetch addresses to use/update.
*/
VOID VmmWin_ListTraversePrefetch(
    _In_ PVMM_PROCESS pProcess,
    _In_ BOOL f32,
    _In_opt_ PVOID ctx,
    _In_ DWORD cvaDataStart,
    _In_ PQWORD pvaDataStart,
    _In_ DWORD oListStart,
    _In_ DWORD cbData,
    _In_opt_ VOID(*pfnCallback_Pre)(_In_ PVMM_PROCESS pProcess, _In_opt_ PVOID ctx, _In_ QWORD va, _In_ PBYTE pb, _In_ DWORD cb, _In_ QWORD vaFLink, _In_ QWORD vaBLink, _In_ POB_VSET pVSetAddress, _Inout_ PBOOL pfValidEntry, _Inout_ PBOOL pfValidFLink, _Inout_ PBOOL pfValidBLink),
    _In_opt_ VOID(*pfnCallback_Post)(_In_ PVMM_PROCESS pProcess, _In_opt_ PVOID ctx, _In_ QWORD va, _In_ PBYTE pb, _In_ DWORD cb),
    _In_opt_ POB_CONTAINER pPrefetchAddressContainer
);

/*
* Retrieve user process parameters - such as the command line (if existing).
* NB! PVMMWIN_USER_PROCESS_PARAMETERS points into pProcess and must not be
*     free'd or used after pProcess goes out of scope or are DECREF'ed.
* -- pProcess
* -- return
*/
PVMMWIN_USER_PROCESS_PARAMETERS VmmWin_UserProcessParameters_Get(_In_ PVMM_PROCESS pProcess);

#endif /* __VMMWIN_H__ */
