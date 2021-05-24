// vmmwin.h : definitions related to windows operating system and processes.
// parsing of virtual memory. Windows related features only.
//
// (c) Ulf Frisk, 2018-2021
// Author: Ulf Frisk, pcileech@frizk.net
//
#ifndef __VMMWIN_H__
#define __VMMWIN_H__
#include "vmm.h"

/*
* Initialize EAT (exported functions) for a specific module.
* CALLER DECREF: return
* -- pProcess
* -- pModule
* -- return
*/
PVMMOB_MAP_EAT VmmWinEAT_Initialize(_In_ PVMM_PROCESS pProcess, _In_ PVMM_MAP_MODULEENTRY pModule);

/*
* Initialize IAT (imported functions) for a specific module.
* CALLER DECREF: return
* -- pProcess
* -- pModule
* -- return
*/
PVMMOB_MAP_IAT VmmWinIAT_Initialize(_In_ PVMM_PROCESS pProcess, _In_ PVMM_MAP_MODULEENTRY pModule);

/*
* Try initialize PteMap text descriptions. This function will first try to pop-
* ulate the pre-existing VMMOB_MAP_PTE object in pProcess with module names and
* then, if failed or partially failed, try to initialize from PE file headers.
* -- pProcess
* -- return
*/
_Success_(return)
BOOL VmmWinPte_InitializeMapText(_In_ PVMM_PROCESS pProcess);

/*
* Initialize the module map containing information about loaded modules in the
* system. This is performed by a PEB/Ldr walk/scan of in-process memory
* structures. This may be unreliable if a process is obfuscated or tampered.
* -- pProcess
* -- psvaInjected = optional set of injected addresses, updated on exit.
* -- return
*/
_Success_(return)
BOOL VmmWinLdrModule_Initialize(_In_ PVMM_PROCESS pProcess, _Inout_opt_ POB_SET psvaInjected);

/*
* Initialize the unloaded module map containing information about unloaded modules.
* -- pProcess
* -- return
*/
_Success_(return)
BOOL VmmWinUnloadedModule_Initialize(_In_ PVMM_PROCESS pProcess);

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
* -- return
*/
BOOL VmmWinThread_Initialize(_In_ PVMM_PROCESS pProcess);

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
* _OBJECT_HEADER.TypeIndex is encoded on Windows 10 - this function decodes it.
* https://medium.com/@ashabdalhalim/e8f907e7073a
* -- vaObjectHeader
* -- iTypeIndexTableEncoded
* -- return
*/
BYTE VmmWin_ObjectTypeGetIndexFromEncoded(_In_ QWORD vaObjectHeader, _In_ BYTE iTypeIndexTableEncoded);

/*
* Try walk the EPROCESS list in the Windows kernel to enumerate processes into
* the VMM/PROC file system.
* NB! This may be done to refresh an existing PID cache hence migration code.
* -- pSystemProcess
* -- fTotalRefresh = create completely new process entries (instead of updating).
* -- psvaNoLinkEPROCESS = optional set of no-link EPROCESS virtual addresses.
* -- return
*/
BOOL VmmWinProcess_Enumerate(_In_ PVMM_PROCESS pSystemProcess, _In_ BOOL fRefreshTotal, _In_opt_ POB_SET psvaNoLinkEPROCESS);

/*
* Locate EPROCESS objects not linked by the EPROCESS list.
* This is achieved by analyzing the object table for the SYSTEM process.
* CALLER DECREF: return
* -- return = Set of vaEPROCESS if no-link addresses exist. NULL otherwise.
*/
POB_SET VmmWinProcess_Enumerate_FindNoLinkProcesses();

typedef VOID(*VMMWIN_LISTTRAVERSE_PRE_CB)(_In_ PVMM_PROCESS pProcess, _In_opt_ PVOID ctx, _In_ QWORD va, _In_ PBYTE pb, _In_ DWORD cb, _In_ QWORD vaFLink, _In_ QWORD vaBLink, _In_ POB_SET pVSetAddress, _Inout_ PBOOL pfValidEntry, _Inout_ PBOOL pfValidFLink, _Inout_ PBOOL pfValidBLink);
typedef VOID(*VMMWIN_LISTTRAVERSE_POST_CB)(_In_ PVMM_PROCESS pProcess, _In_opt_ PVOID ctx, _In_ QWORD va, _In_ PBYTE pb, _In_ DWORD cb);

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
* -- pPrefetchAddressContainer = optional pointer to a PVMMOBCONTAINER containing a POB_VSET of prefetch addresses to use/update.
*/
VOID VmmWin_ListTraversePrefetch(
    _In_ PVMM_PROCESS pProcess,
    _In_ BOOL f32,
    _In_opt_ PVOID ctx,
    _In_ DWORD cvaDataStart,
    _In_ PQWORD pvaDataStart,
    _In_ DWORD oListStart,
    _In_ DWORD cbData,
    _In_opt_ VMMWIN_LISTTRAVERSE_PRE_CB pfnCallback_Pre,
    _In_opt_ VMMWIN_LISTTRAVERSE_POST_CB pfnCallback_Post,
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

/*
* Create a physical memory map and assign to the global context upon success.
* CALLER DECREF: return
* -- return
*/
PVMMOB_MAP_PHYSMEM VmmWinPhysMemMap_Initialize();

/*
* Refresh the physical memory map.
*/
VOID VmmWinPhysMemMap_Refresh();

/*
* Retrieve the account name of the user account given a SID.
* NB! Names for well known SIDs will be given in the language of the system
* running MemProcFS and not in the name of the analyzed system.
* -- pSID
* -- uszName
* -- cbuName
* -- fAccountWellKnown
* -- return
*/
_Success_(return)
BOOL VmmWinUser_GetName(_In_opt_ PSID pSID, _Out_writes_(cbuName) LPSTR uszName, _In_ DWORD cbuName, _Out_opt_ PBOOL pfAccountWellKnown);

/*
* Create a user map and assign to the global context upon success.
* CALLER DECREF: return
* -- return
*/
PVMMOB_MAP_USER VmmWinUser_Initialize();

/*
* Refresh the user map.
*/
VOID VmmWinUser_Refresh();

#endif /* __VMMWIN_H__ */
