// pluginmanager.h : definitions for the plugin manager for MemProcFS plugins.
//
// (c) Ulf Frisk, 2018-2020
// Author: Ulf Frisk, pcileech@frizk.net
//
#ifndef __PLUGINMANAGER_H__
#define __PLUGINMANAGER_H__

#include <Windows.h>
#include "vmm.h"
#include "vmmdll.h"

/*
* Initialize built-in and external modules.
*/
BOOL PluginManager_Initialize();

/*
* Close built-in and external modules, free their resources and unload loaded
* DLLs from memory.
*/
VOID PluginManager_Close();

/*
* Set/Change the visibility of an already registered plugin. Depending on other
* plugins registered in the path parent paths may change as well.
* -- fRoot = TRUE: root, FALSE: process.
* -- wszPluginPath
* -- fVisible
*/
VOID PluginManager_SetVisibility(_In_ BOOL fRoot, _In_ LPWSTR wszPluginPath, _In_ BOOL fVisible);

/*
* Send a List command down the module chain to the appropriate module.
* -- pProcess
* -- wszPath
* -- pFileList
* -- return
*/
VOID PluginManager_List(_In_opt_ PVMM_PROCESS pProcess, _In_ LPWSTR wszPath, _Inout_ PHANDLE pFileList);

/*
* Send a Read command down the module chain to the appropriate module.
* -- pProcess
* -- wszPath
* -- pb
* -- cb
* -- pcbRead
* -- cbOffset
* -- return
*/
NTSTATUS PluginManager_Read(_In_opt_ PVMM_PROCESS pProcess, _In_ LPWSTR wszPath, _Out_writes_(cb) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset);

/*
* Send a Write command down the module chain to the appropriate module.
* -- pProcess
* -- wszPath
* -- pb
* -- cb
* -- pcbWrite
* -- cbOffset
* -- return
*/
NTSTATUS PluginManager_Write(_In_opt_ PVMM_PROCESS pProcess, _In_ LPWSTR wszPath, _In_reads_(cb) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbWrite, _In_ QWORD cbOffset);

/*
* Send a notification event to plugins that registered to receive notifications.
* Officially supported events are listed in vmmdll.h!VMMDLL_PLUGIN_EVENT_*
* -- fEvent = the event to send.
* -- pvEvent = optional binary object related to the event.
* -- cbEvent = length in bytes of pvEvent (if any).
* -- return = (always return TRUE).
*/
BOOL PluginManager_Notify(_In_ DWORD fEvent, _In_opt_ PVOID pvEvent, _In_opt_ DWORD cbEvent);

/*
* Register plugins with timelining capabilities with the timeline manager
* and call into each plugin to allow them to add their timelining entries.
* -- pfnRegister = callback function to register timeline module.
* -- pfnClose = function to close the timeline handle.
* -- pfnAddEntry = callback function to call to add a timelining entry.
*/
VOID PluginManager_Timeline(
    _In_ HANDLE(*pfnRegister)(_In_reads_(6) LPSTR sNameShort, _In_reads_(32) LPSTR szFileUTF8, _In_reads_(32) LPSTR szFileJSON),
    _In_ VOID(*pfnClose)(_In_ HANDLE hTimeline),
    _In_ VOID(*pfnAddEntry)(_In_ HANDLE hTimeline, _In_ QWORD ft, _In_ DWORD dwAction, _In_ DWORD dwPID, _In_ QWORD qwValue, _In_ LPWSTR wszText)
);

#endif /* __PLUGINMANAGER_H__ */
