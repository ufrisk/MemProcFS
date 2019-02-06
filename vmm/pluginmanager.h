// pluginmanager.h : definitions for the plugin manager for memory process file system plugins.
//
// (c) Ulf Frisk, 2018-2019
// Author: Ulf Frisk, pcileech@frizk.net
//
#ifndef __PLUGINMANAGER_H__
#define __PLUGINMANAGER_H__

#include <Windows.h>
#include "vmm.h"

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
* Enumerate modules in a process directory (insert directories of module names).
* -- pProcess
* -- pFileList
*/
VOID PluginManager_ListAll(_In_opt_ PVMM_PROCESS pProcess, _Inout_ PHANDLE pFileList);

/*
* Send a List command down the module chain to the appropriate module.
* -- pProcess
* -- szModule
* -- szPath
* -- pFileList
* -- return
*/
BOOL PluginManager_List(_In_opt_ PVMM_PROCESS pProcess, _In_ LPSTR szModule, _In_ LPSTR szPath, _Inout_ PHANDLE pFileList);

/*
* Send a Read command down the module chain to the appropriate module.
* -- pProcess
* -- szModule
* -- szPath
* -- pb
* -- cb
* -- pcbRead
* -- cbOffset
* -- return
*/
NTSTATUS PluginManager_Read(_In_opt_ PVMM_PROCESS pProcess, _In_ LPSTR szModule, _In_ LPSTR szPath, _Out_ LPVOID pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset);

/*
* Send a Write command down the module chain to the appropriate module.
* -- pProcess
* -- szModule
* -- szPath
* -- pb
* -- cb
* -- pcbWrite
* -- cbOffset
* -- return
*/
NTSTATUS PluginManager_Write(_In_opt_ PVMM_PROCESS pProcess, _In_ LPSTR szModule, _In_ LPSTR szPath, _In_ LPVOID pb, _In_ DWORD cb, _Out_ PDWORD pcbWrite, _In_ QWORD cbOffset);

/*
* Send a notification event to plugins that registered to receive notifications.
* Officially supported events are listed in vmmdll.h!VMMDLL_PLUGIN_EVENT_*
* -- fEvent = the event to send.
* -- pvEvent = optional binary object related to the event.
* -- cbEvent = length in bytes of pvEvent (if any).
* -- return = (always return TRUE).
*/
BOOL PluginManager_Notify(_In_ DWORD fEvent, _In_opt_ PVOID pvEvent, _In_opt_ DWORD cbEvent);

#endif /* __PLUGINMANAGER_H__ */
