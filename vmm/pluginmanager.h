// pluginmanager.h : definitions for the plugin manager for MemProcFS plugins.
//
// (c) Ulf Frisk, 2018-2025
// Author: Ulf Frisk, pcileech@frizk.net
//
#ifndef __PLUGINMANAGER_H__
#define __PLUGINMANAGER_H__

#include "oscompatibility.h"
#include "vmm.h"
#include "vmmdll.h"

/*
* Initialize built-in and external modules.
* -- H
* -- return
*/
BOOL PluginManager_Initialize(_In_ VMM_HANDLE H);

/*
* Close built-in and external modules, free their resources and unload loaded
* DLLs from memory.
* -- H
*/
VOID PluginManager_Close(_In_ VMM_HANDLE H);

/*
* Set/Change the visibility of an already registered plugin. Depending on other
* plugins registered in the path parent paths may change as well.
* -- H
* -- fRoot = TRUE: root, FALSE: process.
* -- uszPluginPath
* -- fVisible
*/
VOID PluginManager_SetVisibility(_In_ VMM_HANDLE H, _In_ BOOL fRoot, _In_ LPCSTR uszPluginPath, _In_ BOOL fVisible);

/*
* Send a List command down the module chain to the appropriate module.
* -- H
* -- pProcess
* -- uszPath
* -- pFileList
* -- return
*/
VOID PluginManager_List(_In_ VMM_HANDLE H, _In_opt_ PVMM_PROCESS pProcess, _In_ LPCSTR uszPath, _Inout_ PHANDLE pFileList);

/*
* Send a Read command down the module chain to the appropriate module.
* -- H
* -- pProcess
* -- uszPath
* -- pb
* -- cb
* -- pcbRead
* -- cbOffset
* -- return
*/
NTSTATUS PluginManager_Read(_In_ VMM_HANDLE H, _In_opt_ PVMM_PROCESS pProcess, _In_ LPCSTR uszPath, _Out_writes_to_(cb, *pcbRead) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset);

/*
* Send a Write command down the module chain to the appropriate module.
* -- H
* -- pProcess
* -- uszPath
* -- pb
* -- cb
* -- pcbWrite
* -- cbOffset
* -- return
*/
NTSTATUS PluginManager_Write(_In_ VMM_HANDLE H, _In_opt_ PVMM_PROCESS pProcess, _In_ LPCSTR uszPath, _In_reads_(cb) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbWrite, _In_ QWORD cbOffset);

/*
* Send a notification event to plugins that registered to receive notifications.
* Officially supported events are listed in vmmdll.h!VMMDLL_PLUGIN_EVENT_*
* -- H
* -- fEvent = the event to send.
* -- pvEvent = optional binary object related to the event.
* -- cbEvent = length in bytes of pvEvent (if any).
* -- return = (always return TRUE).
*/
BOOL PluginManager_Notify(_In_ VMM_HANDLE H, _In_ DWORD fEvent, _In_opt_ PVOID pvEvent, _In_opt_ DWORD cbEvent);

/*
* Initialize plugins with forensic mode capabilities.
* -- H
*/
VOID PluginManager_FcInitialize(_In_ VMM_HANDLE H);

/*
* Finalize plugins with forensic mode capabilities.
* -- H
*/
VOID PluginManager_FcFinalize(_In_ VMM_HANDLE H);

/*
* Ingest an object into plugins with forensic mode capabilities.
* -- H
* -- pIngestVirtmem
*/
VOID PluginManager_FcIngestObject(_In_ VMM_HANDLE H, _In_ PVMMDLL_FORENSIC_INGEST_OBJECT pIngestObject);

/*
* Ingest physical memory into plugins with forensic mode capabilities.
* NB! must only be called in single-threaded context!
* -- H
* -- pIngestPhysmem
*/
VOID PluginManager_FcIngestPhysmem(_In_ VMM_HANDLE H, _In_ PVMMDLL_FORENSIC_INGEST_PHYSMEM pIngestPhysmem);

/*
* Ingest virtual memory into plugins with forensic mode capabilities.
* -- H
* -- pIngestVirtmem
*/
VOID PluginManager_FcIngestVirtmem(_In_ VMM_HANDLE H, _In_ PVMMDLL_FORENSIC_INGEST_VIRTMEM pIngestVirtmem);

/*
* All ingestion actions (physical & virtual) are completed.
* -- H
*/
VOID PluginManager_FcIngestFinalize(_In_ VMM_HANDLE H);

/*
* Register plugins with timelining capabilities with the timeline manager
* and call into each plugin to allow them to add their timelining entries.
* NB! This function is meant to be called by the core forensic subsystem only.
* -- H
* -- pfnRegister = callback function to register timeline module.
* -- pfnClose = function to close the timeline handle.
* -- pfnEntryAdd = callback function to call to add a timelining entry.
* -- pfnEntryAddBySql = callback function to call to add timelining data by
*      insert by partial sql select sub-query - data selected should be:
*      id_str, ft, ac, pid, data32, data64 (in order and without SELECT statement).
*/
VOID PluginManager_FcTimeline(
    _In_ VMM_HANDLE H,
    _In_ HANDLE(*pfnRegister)(_In_ VMM_HANDLE H, _In_reads_(6) LPCSTR sNameShort, _In_reads_(32) LPCSTR szFileUTF8),
    _In_ VOID(*pfnClose)(_In_ VMM_HANDLE H, _In_ HANDLE hTimeline),
    _In_ VOID(*pfnEntryAdd)(_In_ VMM_HANDLE H, _In_ HANDLE hTimeline, _In_ QWORD ft, _In_ DWORD dwAction, _In_ DWORD dwPID, _In_ DWORD dwData32, _In_ QWORD qwData64, _In_ LPCSTR uszText),
    _In_ VOID(*pfnEntryAddBySql)(_In_ VMM_HANDLE H, _In_ HANDLE hTimeline, _In_ DWORD cEntrySql, _In_ LPCSTR *pszEntrySql)
);

/*
* Call each plugin capable of forensic csv log. Plugins may be process or global.
* NB! This function is meant to be called by the core forensic subsystem only.
* -- H
* -- hCSV
* -- return = 0 (to make function compatible with LPTHREAD_START_ROUTINE).
*/
DWORD PluginManager_FcLogCSV(_In_ VMM_HANDLE H, _In_ VMMDLL_CSV_HANDLE hCSV);

/*
* Call each plugin capable of forensic json log. Plugins may be process or global.
* NB! This function is meant to be called by the core forensic subsystem only.
* -- H
* -- pfnAddEntry = callback function to call to add a json entry.
* -- return = 0 (to make function compatible with LPTHREAD_START_ROUTINE).
*/
DWORD PluginManager_FcLogJSON(_In_ VMM_HANDLE H, _In_ VOID(*pfnAddEntry)(_In_ VMM_HANDLE H, _In_ PVMMDLL_FORENSIC_JSONDATA pData));

/*
* Call each plugin capable of FindEvil functionality.
* NB! This function is meant to be called by the core forensic subsystem only.
* -- H
*/
VOID PluginManager_FcFindEvil(_In_ VMM_HANDLE H);

/*
* Execute python code in the python plugin sub-system and print it's result on-screen.
* -- H
* -- szPythonFileToExec
*/
VOID PluginManager_PythonExecFile(_In_ VMM_HANDLE H, _In_ LPCSTR szPythonFileToExec);

#endif /* __PLUGINMANAGER_H__ */
