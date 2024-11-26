// statistics.h : definitions of statistics related functionality.
//
// (c) Ulf Frisk, 2016-2024
// Author: Ulf Frisk, pcileech@frizk.net
//
#ifndef __STATISTICS_H__
#define __STATISTICS_H__
#include "vmm.h"

// NB! also update STATISTICS_ID_STR
typedef enum tdSTATISTICS_ID {
    STATISTICS_ID_INITIALIZE,
    STATISTICS_ID_PluginManager_List,
    STATISTICS_ID_PluginManager_Read,
    STATISTICS_ID_PluginManager_Write,
    STATISTICS_ID_PluginManager_Notify,
    STATISTICS_ID_PluginManager_FcInitialize,
    STATISTICS_ID_PluginManager_FcFinalize,
    STATISTICS_ID_PluginManager_FcTimeline,
    STATISTICS_ID_PluginManager_FcLogCSV,
    STATISTICS_ID_PluginManager_FcLogJSON,
    STATISTICS_ID_PluginManager_FcFindEvil,
    STATISTICS_ID_PluginManager_FcIngestObject,
    STATISTICS_ID_PluginManager_FcIngestPhysmem,
    STATISTICS_ID_PluginManager_FcIngestVirtmem,
    STATISTICS_ID_PluginManager_FcIngestFinalize,
    STATISTICS_ID_FORENSIC_FcInitialize,
    STATISTICS_ID_VMMDLL_VfsList,
    STATISTICS_ID_VMMDLL_VfsListBlob,
    STATISTICS_ID_VMMDLL_VfsRead,
    STATISTICS_ID_VMMDLL_VfsWrite,
    STATISTICS_ID_VMMDLL_ConfigGet,
    STATISTICS_ID_VMMDLL_ConfigSet,
    STATISTICS_ID_VMMDLL_InitializePlugins,
    STATISTICS_ID_VMMDLL_MemReadEx,
    STATISTICS_ID_VMMDLL_MemReadScatter,
    STATISTICS_ID_VMMDLL_MemWriteScatter,
    STATISTICS_ID_VMMDLL_MemWrite,
    STATISTICS_ID_VMMDLL_MemVirt2Phys,
    STATISTICS_ID_VMMDLL_MemCallback,
    STATISTICS_ID_VMMDLL_MemSearch,
    STATISTICS_ID_VMMDLL_MemPrefetchPages,
    STATISTICS_ID_VMMDLL_PidList,
    STATISTICS_ID_VMMDLL_PidGetFromName,
    STATISTICS_ID_VMMDLL_ProcessGetInformation,
    STATISTICS_ID_VMMDLL_ProcessGetInformationAll,
    STATISTICS_ID_VMMDLL_ProcessGetInformationString,
    STATISTICS_ID_VMMDLL_Log,
    STATISTICS_ID_VMMDLL_Map_GetPte,
    STATISTICS_ID_VMMDLL_Map_GetVad,
    STATISTICS_ID_VMMDLL_Map_GetVadEx,
    STATISTICS_ID_VMMDLL_Map_GetModule,
    STATISTICS_ID_VMMDLL_Map_GetModuleFromName,
    STATISTICS_ID_VMMDLL_Map_GetUnloadedModule,
    STATISTICS_ID_VMMDLL_Map_GetEAT,
    STATISTICS_ID_VMMDLL_Map_GetIAT,
    STATISTICS_ID_VMMDLL_Map_GetHeapEx,
    STATISTICS_ID_VMMDLL_Map_GetHeapAllocEx,
    STATISTICS_ID_VMMDLL_Map_GetThread,
    STATISTICS_ID_VMMDLL_Map_GetThreadCallstack,
    STATISTICS_ID_VMMDLL_Map_GetHandle,
    STATISTICS_ID_VMMDLL_Map_GetPhysMem,
    STATISTICS_ID_VMMDLL_Map_GetPool,
    STATISTICS_ID_VMMDLL_Map_GetKObject,
    STATISTICS_ID_VMMDLL_Map_GetKDriver,
    STATISTICS_ID_VMMDLL_Map_GetKDevice,
    STATISTICS_ID_VMMDLL_Map_GetNet,
    STATISTICS_ID_VMMDLL_Map_GetUsers,
    STATISTICS_ID_VMMDLL_Map_GetVM,
    STATISTICS_ID_VMMDLL_Map_GetServices,
    STATISTICS_ID_VMMDLL_Map_GetPfn,
    STATISTICS_ID_VMMDLL_Map_GetPfnEx,
    STATISTICS_ID_VMMDLL_ProcessGetDirectories,
    STATISTICS_ID_VMMDLL_ProcessGetSections,
    STATISTICS_ID_VMMDLL_ProcessGetProcAddress,
    STATISTICS_ID_VMMDLL_ProcessGetModuleBase,
    STATISTICS_ID_VMMDLL_VmGetVmmHandle,
    STATISTICS_ID_VMMDLL_VmMemTranslateGPA,
    STATISTICS_ID_VMMDLL_VmMemRead,
    STATISTICS_ID_VMMDLL_VmMemReadScatter,
    STATISTICS_ID_VMMDLL_VmMemWrite,
    STATISTICS_ID_VMMDLL_VmMemWriteScatter,
    STATISTICS_ID_VMMDLL_WinGetThunkIAT,
    STATISTICS_ID_VMMDLL_WinMemCompression_DecompressPage,
    STATISTICS_ID_VMMDLL_WinRegHive_List,
    STATISTICS_ID_VMMDLL_WinRegHive_ReadEx,
    STATISTICS_ID_VMMDLL_WinRegHive_Write,
    STATISTICS_ID_VMMDLL_WinReg_EnumKeyExW,
    STATISTICS_ID_VMMDLL_WinReg_EnumValueW,
    STATISTICS_ID_VMMDLL_WinReg_QueryValueEx,
    STATISTICS_ID_VMMDLL_YaraSearch,
    STATISTICS_ID_VMMDLL_PdbLoad,
    STATISTICS_ID_VMMDLL_PdbSymbolName,
    STATISTICS_ID_VMMDLL_PdbSymbolAddress,
    STATISTICS_ID_VMMDLL_PdbTypeSize,
    STATISTICS_ID_VMMDLL_PdbTypeChildOffset,
    STATISTICS_ID_VMMDLL_ForensicFileAppend,
    STATISTICS_ID_VMM_PagedCompressedMemory,
    STATISTICS_ID_MAX
} STATISTICS_ID;

static LPCSTR STATISTICS_ID_STR[STATISTICS_ID_MAX] = {
    [STATISTICS_ID_INITIALIZE]                      = "INITIALIZE",
    [STATISTICS_ID_PluginManager_List]              = "PluginManager_List",
    [STATISTICS_ID_PluginManager_Read]              = "PluginManager_Read",
    [STATISTICS_ID_PluginManager_Write]             = "PluginManager_Write",
    [STATISTICS_ID_PluginManager_Notify]            = "PluginManager_Notify",
    [STATISTICS_ID_PluginManager_FcInitialize]      = "PluginManager_FcInitialize",
    [STATISTICS_ID_PluginManager_FcFinalize]        = "PluginManager_FcFinalize",
    [STATISTICS_ID_PluginManager_FcTimeline]        = "PluginManager_FcTimeline",
    [STATISTICS_ID_PluginManager_FcLogCSV]          = "PluginManager_FcLogCSV",
    [STATISTICS_ID_PluginManager_FcLogJSON]         = "PluginManager_FcLogJSON",
    [STATISTICS_ID_PluginManager_FcFindEvil]        = "PluginManager_FcFindEvil",
    [STATISTICS_ID_PluginManager_FcIngestObject]    = "PluginManager_FcIngestObject",
    [STATISTICS_ID_PluginManager_FcIngestPhysmem]   = "PluginManager_FcIngestPhysmem",
    [STATISTICS_ID_PluginManager_FcIngestVirtmem]   = "PluginManager_FcIngestVirtmem",
    [STATISTICS_ID_PluginManager_FcIngestFinalize]  = "PluginManager_FcIngestFinalize",
    [STATISTICS_ID_FORENSIC_FcInitialize]           = "FORENSIC_FcInitialize",
    [STATISTICS_ID_VMMDLL_VfsList]                  = "VMMDLL_VfsList",
    [STATISTICS_ID_VMMDLL_VfsListBlob]              = "VMMDLL_VfsListBlob",
    [STATISTICS_ID_VMMDLL_VfsRead]                  = "VMMDLL_VfsRead",
    [STATISTICS_ID_VMMDLL_VfsWrite]                 = "VMMDLL_VfsWrite",
    [STATISTICS_ID_VMMDLL_ConfigGet]                = "VMMDLL_ConfigGet",
    [STATISTICS_ID_VMMDLL_ConfigSet]                = "VMMDLL_ConfigSet",
    [STATISTICS_ID_VMMDLL_InitializePlugins]        = "VMMDLL_InitializePlugins",
    [STATISTICS_ID_VMMDLL_MemReadEx]                = "VMMDLL_MemReadEx",
    [STATISTICS_ID_VMMDLL_MemReadScatter]           = "VMMDLL_MemReadScatter",
    [STATISTICS_ID_VMMDLL_MemWriteScatter]          = "VMMDLL_MemWriteScatter",
    [STATISTICS_ID_VMMDLL_MemWrite]                 = "VMMDLL_MemWrite",
    [STATISTICS_ID_VMMDLL_MemVirt2Phys]             = "VMMDLL_MemVirt2Phys",
    [STATISTICS_ID_VMMDLL_MemCallback]              = "VMMDLL_MemCallback",
    [STATISTICS_ID_VMMDLL_MemSearch]                = "VMMDLL_MemSearch",
    [STATISTICS_ID_VMMDLL_MemPrefetchPages]         = "VMMDLL_MemPrefetchPages",
    [STATISTICS_ID_VMMDLL_PidList]                  = "VMMDLL_PidList",
    [STATISTICS_ID_VMMDLL_PidGetFromName]           = "VMMDLL_PidGetFromName",
    [STATISTICS_ID_VMMDLL_ProcessGetInformation]    = "VMMDLL_ProcessGetInformation",
    [STATISTICS_ID_VMMDLL_ProcessGetInformationAll] = "VMMDLL_ProcessGetInformationAll",
    [STATISTICS_ID_VMMDLL_ProcessGetInformationString] = "VMMDLL_ProcessGetInformationString",
    [STATISTICS_ID_VMMDLL_Log]                      = "VMMDLL_Log",
    [STATISTICS_ID_VMMDLL_Map_GetPte]               = "VMMDLL_Map_GetPte",
    [STATISTICS_ID_VMMDLL_Map_GetVad]               = "VMMDLL_Map_GetVad",
    [STATISTICS_ID_VMMDLL_Map_GetVadEx]             = "VMMDLL_Map_GetVadEx",
    [STATISTICS_ID_VMMDLL_Map_GetModule]            = "VMMDLL_Map_GetModule",
    [STATISTICS_ID_VMMDLL_Map_GetModuleFromName]    = "VMMDLL_Map_GetModuleFromName",
    [STATISTICS_ID_VMMDLL_Map_GetUnloadedModule]    = "VMMDLL_Map_GetUnloadedModule",
    [STATISTICS_ID_VMMDLL_Map_GetEAT]               = "VMMDLL_Map_GetEAT",
    [STATISTICS_ID_VMMDLL_Map_GetIAT]               = "VMMDLL_Map_GetIAT",
    [STATISTICS_ID_VMMDLL_Map_GetHeapEx]            = "VMMDLL_Map_GetHeapEx",
    [STATISTICS_ID_VMMDLL_Map_GetHeapAllocEx]       = "VMMDLL_Map_GetHeapAllocEx",
    [STATISTICS_ID_VMMDLL_Map_GetThread]            = "VMMDLL_Map_GetThread",
    [STATISTICS_ID_VMMDLL_Map_GetThreadCallstack]   = "VMMDLL_Map_GetThreadCallstack",
    [STATISTICS_ID_VMMDLL_Map_GetHandle]            = "VMMDLL_Map_GetHandle",
    [STATISTICS_ID_VMMDLL_Map_GetPhysMem]           = "VMMDLL_Map_GetPhysMem",
    [STATISTICS_ID_VMMDLL_Map_GetPool]              = "VMMDLL_Map_GetPool",
    [STATISTICS_ID_VMMDLL_Map_GetKObject]           = "VMMDLL_Map_GetKObject",
    [STATISTICS_ID_VMMDLL_Map_GetKDriver]           = "VMMDLL_Map_GetKDriver",
    [STATISTICS_ID_VMMDLL_Map_GetKDevice]           = "VMMDLL_Map_GetKDevice",
    [STATISTICS_ID_VMMDLL_Map_GetNet]               = "VMMDLL_Map_GetNet",
    [STATISTICS_ID_VMMDLL_Map_GetUsers]             = "VMMDLL_Map_GetUsers",
    [STATISTICS_ID_VMMDLL_Map_GetVM]                = "MMDLL_Map_GetVM",
    [STATISTICS_ID_VMMDLL_Map_GetServices]          = "VMMDLL_Map_GetServices",
    [STATISTICS_ID_VMMDLL_Map_GetPfn]               = "VMMDLL_Map_GetPfn",
    [STATISTICS_ID_VMMDLL_Map_GetPfnEx]             = "VMMDLL_Map_GetPfnEx",
    [STATISTICS_ID_VMMDLL_ProcessGetDirectories]    = "VMMDLL_ProcessGetDirectories",
    [STATISTICS_ID_VMMDLL_ProcessGetSections]       = "VMMDLL_ProcessGetSections",
    [STATISTICS_ID_VMMDLL_ProcessGetProcAddress]    = "VMMDLL_ProcessGetProcAddress",
    [STATISTICS_ID_VMMDLL_ProcessGetModuleBase]     = "VMMDLL_ProcessGetModuleBase",
    [STATISTICS_ID_VMMDLL_WinGetThunkIAT]           = "VMMDLL_WinGetThunkIAT",
    [STATISTICS_ID_VMMDLL_WinMemCompression_DecompressPage] = "VMMDLL_WinMemCompression_DecompressPage",
    [STATISTICS_ID_VMMDLL_WinRegHive_List]          = "VMMDLL_WinRegHive_List",
    [STATISTICS_ID_VMMDLL_WinRegHive_ReadEx]        = "VMMDLL_WinRegHive_ReadEx",
    [STATISTICS_ID_VMMDLL_WinRegHive_Write]         = "VMMDLL_WinRegHive_Write",
    [STATISTICS_ID_VMMDLL_WinReg_EnumKeyExW]        = "VMMDLL_WinReg_EnumKeyExW",
    [STATISTICS_ID_VMMDLL_WinReg_EnumValueW]        = "VMMDLL_WinReg_EnumValueW",
    [STATISTICS_ID_VMMDLL_WinReg_QueryValueEx]      = "VMMDLL_WinReg_QueryValueEx",
    [STATISTICS_ID_VMMDLL_VmGetVmmHandle]           = "VMMDLL_VmGetVmmHandle",
    [STATISTICS_ID_VMMDLL_VmMemTranslateGPA]        = "VMMDLL_VmMemTranslateGPA",
    [STATISTICS_ID_VMMDLL_VmMemRead]                = "VMMDLL_VmMemRead",
    [STATISTICS_ID_VMMDLL_VmMemReadScatter]         = "VMMDLL_VmMemReadScatter",
    [STATISTICS_ID_VMMDLL_VmMemWrite]               = "VMMDLL_VmMemWrite",
    [STATISTICS_ID_VMMDLL_VmMemWriteScatter]        = "VMMDLL_VmMemWriteScatter",
    [STATISTICS_ID_VMMDLL_YaraSearch]               = "STATISTICS_ID_VMMDLL_YaraSearch",
    [STATISTICS_ID_VMMDLL_PdbLoad]                  = "VMMDLL_PdbLoad",
    [STATISTICS_ID_VMMDLL_PdbSymbolName]            = "VMMDLL_PdbSymbolName",
    [STATISTICS_ID_VMMDLL_PdbSymbolAddress]         = "VMMDLL_PdbSymbolAddress",
    [STATISTICS_ID_VMMDLL_PdbTypeSize]              = "VMMDLL_PdbTypeSize",
    [STATISTICS_ID_VMMDLL_PdbTypeChildOffset]       = "VMMDLL_PdbTypeChildOffset",
    [STATISTICS_ID_VMMDLL_ForensicFileAppend]       = "VMMDLL_ForensicFileAppend",
    [STATISTICS_ID_VMM_PagedCompressedMemory]       = "VMM_PagedCompressedMemory"
};

VOID Statistics_CallSetEnabled(_In_ VMM_HANDLE H, _In_ BOOL fEnabled);
BOOL Statistics_CallGetEnabled(_In_ VMM_HANDLE H);
QWORD Statistics_CallStart(_In_ VMM_HANDLE H);

/*
* Log the completion of a statistics-measured function call.
* Log the time spend in the call and return it.
* -- H
* -- fId
* -- tmCallStart
* -- return = time spend in call in ticks of QueryPerformanceCounter()
*/
QWORD Statistics_CallEnd(_In_ VMM_HANDLE H, _In_ DWORD fId, QWORD tmCallStart);

/*
* Retrieve call statistics as a string buffer and size. If psz is not supplied
* only retrieve size.
* CALLER LocalFree: psz
* -- H
* -- psz
* -- pcsz
* -- return
*/
_Success_(return)
BOOL Statistics_CallToString(_In_ VMM_HANDLE H, _Out_opt_ LPSTR *psz, _Out_ PDWORD pcsz);



// ----------------------------------------------------------------------------
// CALL STATISTICS DEBUG/TRACE LOGGING BELOW:
// ----------------------------------------------------------------------------

typedef struct tdVMMSTATISTICS_LOG {
    BOOL f;
    BOOL fShowReads;
    DWORD dwPID;
    DWORD MID;
    VMMLOG_LEVEL dwLogLevel;
    QWORD v[3];
} VMMSTATISTICS_LOG, *PVMMSTATISTICS_LOG;

/*
* Start a call statistics logging session.
* -- H
* -- MID = module ID (MID)
* -- dwLogLevel = log level as defined by LOGLEVEL_*
* -- pProcess
* -- pLogStatistics
* -- uszText
*/
VOID VmmStatisticsLogStart(_In_ VMM_HANDLE H, _In_ VMM_MODULE_ID MID, _In_ VMMLOG_LEVEL dwLogLevel, _In_opt_ PVMM_PROCESS pProcess, _Out_ PVMMSTATISTICS_LOG pStatisticsLog, _In_ LPCSTR uszText);

/*
* End a statistics logging session.
* -- H
* -- pLogStatistics
* -- uszText
*/
VOID VmmStatisticsLogEnd(_In_ VMM_HANDLE H, _In_ PVMMSTATISTICS_LOG pStatisticsLog, _In_ LPCSTR uszText);

#endif /* __STATISTICS_H__ */
