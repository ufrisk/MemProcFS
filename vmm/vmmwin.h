// vmmwin.h : definitions related to windows operating system and processes.
// parsing of virtual memory. Windows related features only.
//
// (c) Ulf Frisk, 2018-2025
// Author: Ulf Frisk, pcileech@frizk.net
//
#ifndef __VMMWIN_H__
#define __VMMWIN_H__
#include "vmm.h"

/*
* Initialize EAT (exported functions) for a specific module.
* CALLER DECREF: return
* -- H
* -- pProcess
* -- pModule
* -- return
*/
_Success_(return != NULL)
PVMMOB_MAP_EAT VmmWinEAT_Initialize(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess, _In_ PVMM_MAP_MODULEENTRY pModule);

/*
* Initialize IAT (imported functions) for a specific module.
* CALLER DECREF: return
* -- H
* -- pProcess
* -- pModule
* -- return
*/
_Success_(return != NULL)
PVMMOB_MAP_IAT VmmWinIAT_Initialize(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess, _In_ PVMM_MAP_MODULEENTRY pModule);

/*
* Try initialize PteMap text descriptions. This function will first try to pop-
* ulate the pre-existing VMMOB_MAP_PTE object in pProcess with module names and
* then, if failed or partially failed, try to initialize from PE file headers.
* -- H
* -- pProcess
* -- return
*/
_Success_(return)
BOOL VmmWinPte_InitializeMapText(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess);

/*
* Initialize the module map containing information about loaded modules in the
* system. This is performed by a PEB/Ldr walk/scan of in-process memory
* structures. This may be unreliable if a process is obfuscated or tampered.
* -- H
* -- pProcess
* -- psvaInjected = optional set of injected addresses, updated on exit.
* -- return
*/
_Success_(return)
BOOL VmmWinLdrModule_Initialize(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess, _Inout_opt_ POB_SET psvaInjected);

/*
* Add DebugInfo to the modules unless already added.
* -- H
* -- pProcess
*/
VOID VmmWinLdrModule_EnrichDebugInfo(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess);

/*
* Add VersionInfo to the modules unless already added.
* -- H
* -- pProcess
*/
VOID VmmWinLdrModule_EnrichVersionInfo(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess);

/*
* Retrieve the symbol server for a specific module (Microsoft only).
* Resulting szSymbolServer will be NULL-terminated even on fail.
* -- H
* -- pe
* -- fExtendedChecks = check if VersionInfo is a Microsoft module.
* -- cbSymbolServer
* -- szSymbolServer
* -- return
*/
_Success_(return)
BOOL VmmWinLdrModule_SymbolServer(
    _In_ VMM_HANDLE H,
    _In_ PVMM_MAP_MODULEENTRY pe,
    _In_ BOOL fExtendedChecks,
    _In_ DWORD cbSymbolServer,
    _Out_writes_(cbSymbolServer) LPSTR szSymbolServer
);

/*
* Initialize the unloaded module map containing information about unloaded modules.
* -- H
* -- pProcess
* -- return
*/
_Success_(return)
BOOL VmmWinUnloadedModule_Initialize(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess);

/*
* Initialize tokens for specific processes.
* CALLER DECREF: *ppObTokens (each individual token).
* -- H
* -- cTokens = number of tokens to initialize.
* -- pvaTokens
* -- ppObTokens = buffer of size cToken to receive pointers to initialized tokens.
* -- return
*/
_Success_(return)
BOOL VmmWinToken_Initialize(
    _In_ VMM_HANDLE H,
    _In_ DWORD cTokens,
    _In_reads_(cTokens) QWORD *pvaTokens,
    _Out_writes_(cTokens) PVMMOB_TOKEN *ppObTokens
);

/*
* Initialize Handles for a specific process. Extended information text may take
* extra time to initialize.
* -- H
* -- pProcess
* -- fExtendedText = also fetch extended info such as handle paths/names.
* -- return
*/
_Success_(return)
BOOL VmmWinHandle_Initialize(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess, _In_ BOOL fExtendedText);

/*
* Retrieve a pointer to a VMMWIN_OBJECT_TYPE if possible. Initialization of the
* table takes place on first use. The table only exists in Win7+ and is is
* dependant on PDB symbol functionality for initialization.
* -- H
* -- iObjectType
* -- return
*/
_Success_(return != NULL)
PVMMWIN_OBJECT_TYPE VmmWin_ObjectTypeGet(_In_ VMM_HANDLE H, _In_ BYTE iObjectType);

/*
* _OBJECT_HEADER.TypeIndex is encoded on Windows 10 - this function decodes it.
* https://medium.com/@ashabdalhalim/e8f907e7073a
* -- H
* -- vaObjectHeader
* -- iTypeIndexTableEncoded
* -- return
*/
BYTE VmmWin_ObjectTypeGetIndexFromEncoded(_In_ VMM_HANDLE H, _In_ QWORD vaObjectHeader, _In_ BYTE iTypeIndexTableEncoded);

/*
* Try walk the EPROCESS list in the Windows kernel to enumerate processes into
* the VMM/PROC file system.
* NB! This may be done to refresh an existing PID cache hence migration code.
* -- H
* -- pSystemProcess
* -- fTotalRefresh = create completely new process entries (instead of updating).
* -- psvaNoLinkEPROCESS = optional set of no-link EPROCESS virtual addresses.
* -- return
*/
BOOL VmmWinProcess_Enumerate(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pSystemProcess, _In_ BOOL fRefreshTotal, _In_opt_ POB_SET psvaNoLinkEPROCESS);

/*
* Locate EPROCESS objects not linked by the EPROCESS list.
* This is achieved by analyzing the object table for the SYSTEM process.
* CALLER DECREF: return
* -- H
* -- return = Set of vaEPROCESS if no-link addresses exist. NULL otherwise.
*/
POB_SET VmmWinProcess_Enumerate_FindNoLinkProcesses(_In_ VMM_HANDLE H);

typedef VOID(*VMMWIN_LISTTRAVERSE_PRE_CB)(
    _In_ VMM_HANDLE H,
    _In_ PVMM_PROCESS pProcess,
    _In_opt_ PVOID ctx,
    _In_ QWORD va,
    _In_ PBYTE pb,
    _In_ DWORD cb,
    _In_ QWORD vaFLink,
    _In_ QWORD vaBLink,
    _In_ POB_SET pVSetAddress,
    _Inout_ PBOOL pfValidEntry,
    _Inout_ PBOOL pfValidFLink,
    _Inout_ PBOOL pfValidBLink,
    _In_ WORD iInitialEntry         // entry is from index: iInitialEntry in array pvaDataStart
);
typedef VOID(*VMMWIN_LISTTRAVERSE_POST_CB)(
    _In_ VMM_HANDLE H,
    _In_ PVMM_PROCESS pProcess,
    _In_opt_ PVOID ctx,
    _In_ QWORD va,
    _In_ PBYTE pb,
    _In_ DWORD cb,
    _In_ WORD iInitialEntry         // entry is from index: iInitialEntry in array pvaDataStart
);

/*
* Walk a windows linked list in an efficient way that minimize IO requests to
* the the device. This is advantageous for latency reasons. The function return
* a set of the addresses used - this may be used to prefetch pages in advance
* if the list should be walked again at a later time.
* The callback function must only return FALSE on severe errors when the list
* should no longer be continued to be walked in the direction.
* CALLER_DECREF: return
* -- H
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
    _In_ VMM_HANDLE H,
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
* -- H
* -- pProcess
* -- return
*/
PVMMWIN_USER_PROCESS_PARAMETERS VmmWin_UserProcessParameters_Get(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess);

/*
* Create a physical memory map and assign to the global context upon success.
* CALLER DECREF: return
* -- H
* -- return
*/
PVMMOB_MAP_PHYSMEM VmmWinPhysMemMap_Initialize(_In_ VMM_HANDLE H);

/*
* Refresh the physical memory map.
* -- H
*/
VOID VmmWinPhysMemMap_Refresh(_In_ VMM_HANDLE H);

/*
* Retrieve the account name of the user account given a SID.
* NB! Names for well known SIDs will be given in the language of the system
* running MemProcFS and not in the name of the analyzed system.
* -- H
* -- pSID
* -- uszName
* -- cbuName
* -- fAccountWellKnown
* -- return
*/
_Success_(return)
BOOL VmmWinUser_GetName(_In_ VMM_HANDLE H, _In_opt_ PSID pSID, _Out_writes_(cbuName) LPSTR uszName, _In_ DWORD cbuName, _Out_opt_ PBOOL pfAccountWellKnown);

/*
* Create a user map and assign to the global context upon success.
* CALLER DECREF: return
* -- H
* -- return
*/
PVMMOB_MAP_USER VmmWinUser_Initialize(_In_ VMM_HANDLE H);

/*
* Refresh the user map.
* -- H
*/
VOID VmmWinUser_Refresh(_In_ VMM_HANDLE H);

#endif /* __VMMWIN_H__ */
