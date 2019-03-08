// m_status.c : implementation of the .status built-in module.
//
// (c) Ulf Frisk, 2018-2019
// Author: Ulf Frisk, pcileech@frizk.net
//

/*
* The m_status module registers itself with the name '.status' with the plugin manager.
* 
* The module showcases both a "root" "process" directory module as well as a
* stateless module. It neither holds state in its "global" HandleModule context
* nor in the per-process specific HandleProcess contexts.
*
* The module implements listing of directories as well as read and write.
* Read/Write happens, if allowed, to various configuration and status settings
* related to the VMM and Memory Process File System.
*/

#include "m_virt2phys.h"
#include "pluginmanager.h"
#include "util.h"
#include "vmm.h"
#include "vmmproc.h"
#include "vmmvfs.h"
#include "statistics.h"

/*
* Read : function as specified by the module manager. The module manager will
* call into this callback function whenever a read shall occur from a "file".
* -- ctx
* -- pb
* -- cb
* -- pcbRead
* -- cbOffset
* -- return
*/
NTSTATUS MStatus_Read(_In_ PVMMDLL_PLUGIN_CONTEXT ctx, _Out_ LPVOID pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset)
{
    PVMM_PROCESS pProcess = (PVMM_PROCESS)ctx->pProcess;
    DWORD cchBuffer;
    CHAR szBuffer[0x400];
    DWORD cbCallStatistics = 0;
    PBYTE pbCallStatistics = NULL;
    NTSTATUS nt;
    // "PROCESS"
    if(pProcess) {
        if(!_stricmp(ctx->szPath, "cache_file_enable")) {
            return Util_VfsReadFile_FromBOOL(!pProcess->fFileCacheDisabled, pb, cb, pcbRead, cbOffset);
        }
    }
    // "ROOT"
    if(!pProcess) {
        if(!_stricmp(ctx->szPath, "config_process_show_terminated")) {
            return Util_VfsReadFile_FromBOOL(ctxVmm->flags & VMM_FLAG_PROCESS_SHOW_TERMINATED, pb, cb, pcbRead, cbOffset);
        }
        if(!_stricmp(ctx->szPath, "config_cache_enable")) {
            return Util_VfsReadFile_FromBOOL(!(ctxVmm->flags & VMM_FLAG_NOCACHE), pb, cb, pcbRead, cbOffset);
        }
        if(!_stricmp(ctx->szPath, "config_statistics_fncall")) {
            return Util_VfsReadFile_FromBOOL(Statistics_CallGetEnabled(), pb, cb, pcbRead, cbOffset);
        }
        if(!_stricmp(ctx->szPath, "config_refresh_enable")) {
            return Util_VfsReadFile_FromBOOL(ctxVmm->ThreadProcCache.fEnabled, pb, cb, pcbRead, cbOffset);
        }
        if(!_stricmp(ctx->szPath, "config_refresh_tick_period_ms")) {
            return Util_VfsReadFile_FromDWORD(ctxVmm->ThreadProcCache.cMs_TickPeriod, pb, cb, pcbRead, cbOffset, FALSE);
        }
        if(!_stricmp(ctx->szPath, "config_refresh_read")) {
            return Util_VfsReadFile_FromDWORD(ctxVmm->ThreadProcCache.cTick_Phys, pb, cb, pcbRead, cbOffset, FALSE);
        }
        if(!_stricmp(ctx->szPath, "config_refresh_tlb")) {
            return Util_VfsReadFile_FromDWORD(ctxVmm->ThreadProcCache.cTick_TLB, pb, cb, pcbRead, cbOffset, FALSE);
        }
        if(!_stricmp(ctx->szPath, "config_refresh_proc_partial")) {
            return Util_VfsReadFile_FromDWORD(ctxVmm->ThreadProcCache.cTick_ProcPartial, pb, cb, pcbRead, cbOffset, FALSE);
        }
        if(!_stricmp(ctx->szPath, "config_refresh_proc_total")) {
            return Util_VfsReadFile_FromDWORD(ctxVmm->ThreadProcCache.cTick_ProcTotal, pb, cb, pcbRead, cbOffset, FALSE);
        }
        if(!_stricmp(ctx->szPath, "statistics")) {
            cchBuffer = snprintf(szBuffer, 0x400,
                "VMM STATISTICS   (4kB PAGES / COUNTS - HEXADECIMAL)\n" \
                "===================================================\n" \
                "PHYSICAL MEMORY READ CACHE HIT: %16llx\n" \
                "PHYSICAL MEMORY READ RETRIEVED: %16llx\n" \
                "PHYSICAL MEMORY READ FAILED:    %16llx\n" \
                "PHYSICAL MEMORY WRITE:          %16llx\n" \
                "TLB CACHE HIT:                  %16llx\n" \
                "TLB RETRIEVED:                  %16llx\n" \
                "TLB FAILED:                     %16llx\n" \
                "PHYSICAL MEMORY REFRESH:        %16llx\n" \
                "TLB MEMORY REFRESH:             %16llx\n" \
                "PROCESS PARTIAL REFRESH:        %16llx\n" \
                "PROCESS FULL REFRESH:           %16llx\n",
                ctxVmm->stat.cPhysCacheHit, ctxVmm->stat.cPhysReadSuccess, ctxVmm->stat.cPhysReadFail,
                ctxVmm->stat.cPhysWrite,
                ctxVmm->stat.cTlbCacheHit, ctxVmm->stat.cTlbReadSuccess, ctxVmm->stat.cTlbReadFail,
                ctxVmm->stat.cRefreshPhys, ctxVmm->stat.cRefreshTlb, ctxVmm->stat.cRefreshProcessPartial, ctxVmm->stat.cRefreshProcessFull
            );
            return Util_VfsReadFile_FromPBYTE(szBuffer, cchBuffer, pb, cb, pcbRead, cbOffset);
        }
        if(!_stricmp(ctx->szPath, "statistics_fncall")) {
            Statistics_CallToString(NULL, 0, &cbCallStatistics);
            pbCallStatistics = LocalAlloc(0, cbCallStatistics);
            if(!pbCallStatistics) { return VMMDLL_STATUS_FILE_INVALID; }
            Statistics_CallToString(pbCallStatistics, cbCallStatistics, &cbCallStatistics);
            nt = Util_VfsReadFile_FromPBYTE(pbCallStatistics, cbCallStatistics, pb, cb, pcbRead, cbOffset);
            LocalFree(pbCallStatistics);
            return nt;
        }
        if(!_stricmp(ctx->szPath, "config_printf_enable")) {
            return Util_VfsReadFile_FromBOOL(ctxMain->cfg.fVerboseDll, pb, cb, pcbRead, cbOffset);
        }
        if(!_stricmp(ctx->szPath, "config_printf_v")) {
            return Util_VfsReadFile_FromBOOL(ctxMain->cfg.fVerbose, pb, cb, pcbRead, cbOffset);
        }
        if(!_stricmp(ctx->szPath, "config_printf_vv")) {
            return Util_VfsReadFile_FromBOOL(ctxMain->cfg.fVerboseExtra, pb, cb, pcbRead, cbOffset);
        }
        if(!_stricmp(ctx->szPath, "config_printf_vvv")) {
            return Util_VfsReadFile_FromBOOL(ctxMain->cfg.fVerboseExtraTlp, pb, cb, pcbRead, cbOffset);
        }
        if(!_stricmp(ctx->szPath, "native_max_address")) {
            return Util_VfsReadFile_FromQWORD(ctxMain->dev.paMaxNative, pb, cb, pcbRead, cbOffset, FALSE);
        }
        if(!_stricmp(ctx->szPath, "native_max_iosize")) {
            return Util_VfsReadFile_FromQWORD(ctxMain->dev.cbMaxSizeMemIo, pb, cb, pcbRead, cbOffset, FALSE);
        }
    }
    return VMMDLL_STATUS_FILE_INVALID;
}

NTSTATUS MStatus_Write_NotifyVerbosityChange(_In_ NTSTATUS nt)
{
    if(nt == VMMDLL_STATUS_SUCCESS) {
        PluginManager_Notify(VMMDLL_PLUGIN_EVENT_VERBOSITYCHANGE, NULL, 0);
    }
    return nt;
}

/*
* Write : function as specified by the module manager. The module manager will
* call into this callback function whenever a write shall occur from a "file".
* -- ctx
* -- pb
* -- cb
* -- pcbWrite
* -- cbOffset
* -- return
*/
NTSTATUS MStatus_Write(_In_ PVMMDLL_PLUGIN_CONTEXT ctx, _In_ LPVOID pb, _In_ DWORD cb, _Out_ PDWORD pcbWrite, _In_ QWORD cbOffset)
{
    PVMM_PROCESS pProcess = (PVMM_PROCESS)ctx->pProcess;
    NTSTATUS nt;
    BOOL fEnable = FALSE;
    // "PROCESS"
    if(pProcess) {
        if(!_stricmp(ctx->szPath, "cache_file_enable")) {
            if((cbOffset == 0) && (cb > 0)) {
                if(((PCHAR)pb)[0] == '1') { pProcess->fFileCacheDisabled = FALSE; }
                if(((PCHAR)pb)[0] == '0') { pProcess->fFileCacheDisabled = TRUE; }
            }
            *pcbWrite = cb;
            return VMMDLL_STATUS_SUCCESS;
        }
    }
    // "ROOT"
    if(!pProcess) {

        if(!_stricmp(ctx->szPath, "config_process_show_terminated")) {
            nt = Util_VfsWriteFile_BOOL(&fEnable, pb, cb, pcbWrite, cbOffset);
            if(nt == VMMDLL_STATUS_SUCCESS) {
                ctxVmm->flags &= ~VMM_FLAG_PROCESS_SHOW_TERMINATED;
                ctxVmm->flags |= fEnable ? VMM_FLAG_PROCESS_SHOW_TERMINATED : 0;
                VmmProc_RefreshProcesses(TRUE);
            }
            return nt;
        }
        if(!_stricmp(ctx->szPath, "config_cache_enable")) {
            nt = Util_VfsWriteFile_BOOL(&fEnable, pb, cb, pcbWrite, cbOffset);
            if(nt == VMMDLL_STATUS_SUCCESS) {
                ctxVmm->flags &= ~VMM_FLAG_NOCACHE;
                ctxVmm->flags |= fEnable ? 0 : VMM_FLAG_NOCACHE;
            }
            return nt;
        }
        if(!_stricmp(ctx->szPath, "config_statistics_fncall")) {
            nt = Util_VfsWriteFile_BOOL(&fEnable, pb, cb, pcbWrite, cbOffset);
            if(nt == VMMDLL_STATUS_SUCCESS) {
                Statistics_CallSetEnabled(fEnable);
            }
            return nt;
        }
        if(!_stricmp(ctx->szPath, "config_refresh_tick_period_ms")) {
            return Util_VfsWriteFile_DWORD(&ctxVmm->ThreadProcCache.cMs_TickPeriod, pb, cb, pcbWrite, cbOffset, 50);
        }
        if(!_stricmp(ctx->szPath, "config_refresh_read")) {
            return Util_VfsWriteFile_DWORD(&ctxVmm->ThreadProcCache.cTick_Phys, pb, cb, pcbWrite, cbOffset, 1);
        }
        if(!_stricmp(ctx->szPath, "config_refresh_tlb")) {
            return Util_VfsWriteFile_DWORD(&ctxVmm->ThreadProcCache.cTick_TLB, pb, cb, pcbWrite, cbOffset, 1);
        }
        if(!_stricmp(ctx->szPath, "config_refresh_proc_partial")) {
            return Util_VfsWriteFile_DWORD(&ctxVmm->ThreadProcCache.cTick_ProcPartial, pb, cb, pcbWrite, cbOffset, 1);
        }
        if(!_stricmp(ctx->szPath, "config_refresh_proc_total")) {
            return Util_VfsWriteFile_DWORD(&ctxVmm->ThreadProcCache.cTick_ProcTotal, pb, cb, pcbWrite, cbOffset, 1);
        }
        if(!_stricmp(ctx->szPath, "config_printf_enable")) {
            return MStatus_Write_NotifyVerbosityChange(
                Util_VfsWriteFile_BOOL(&ctxMain->cfg.fVerboseDll, pb, cb, pcbWrite, cbOffset));
        }
        if(!_stricmp(ctx->szPath, "config_printf_v")) {
            return MStatus_Write_NotifyVerbosityChange(
                Util_VfsWriteFile_BOOL(&ctxMain->cfg.fVerbose, pb, cb, pcbWrite, cbOffset));
        }
        if(!_stricmp(ctx->szPath, "config_printf_vv")) {
            return MStatus_Write_NotifyVerbosityChange(
                Util_VfsWriteFile_BOOL(&ctxMain->cfg.fVerboseExtra, pb, cb, pcbWrite, cbOffset));
        }
        if(!_stricmp(ctx->szPath, "config_printf_vvv")) {
            return MStatus_Write_NotifyVerbosityChange(
                Util_VfsWriteFile_BOOL(&ctxMain->cfg.fVerboseExtraTlp, pb, cb, pcbWrite, cbOffset));
        }
    }
    return VMMDLL_STATUS_FILE_INVALID;
}

/*
* List : function as specified by the module manager. The module manager will
* call into this callback function whenever a list directory shall occur from
* the given module.
* -- ctx
* -- pFileList
* -- return
*/
BOOL MStatus_List(_In_ PVMMDLL_PLUGIN_CONTEXT ctx, _Inout_ PHANDLE pFileList)
{
    DWORD cbCallStatistics = 0;
    PVMM_PROCESS pProcess = (PVMM_PROCESS)ctx->pProcess;
    // not module root directory -> fail!
    if(ctx->szPath[0]) { return FALSE; }
    // "root" view
    if(!ctx->pProcess) {
        VMMDLL_VfsList_AddFile(pFileList, "config_cache_enable", 1);
        VMMDLL_VfsList_AddFile(pFileList, "config_statistics_fncall", 1);
        VMMDLL_VfsList_AddFile(pFileList, "config_refresh_enable", 1);
        VMMDLL_VfsList_AddFile(pFileList, "config_refresh_tick_period_ms", 8);
        VMMDLL_VfsList_AddFile(pFileList, "config_refresh_read", 8);
        VMMDLL_VfsList_AddFile(pFileList, "config_refresh_tlb", 8);
        VMMDLL_VfsList_AddFile(pFileList, "config_refresh_proc_partial", 8);
        VMMDLL_VfsList_AddFile(pFileList, "config_refresh_proc_total", 8);
        VMMDLL_VfsList_AddFile(pFileList, "statistics", 0x283);
        VMMDLL_VfsList_AddFile(pFileList, "config_printf_enable", 1);
        VMMDLL_VfsList_AddFile(pFileList, "config_printf_v", 1);
        VMMDLL_VfsList_AddFile(pFileList, "config_printf_vv", 1);
        VMMDLL_VfsList_AddFile(pFileList, "config_printf_vvv", 1);
        VMMDLL_VfsList_AddFile(pFileList, "config_process_show_terminated", 1);
        VMMDLL_VfsList_AddFile(pFileList, "native_max_address", 16);
        VMMDLL_VfsList_AddFile(pFileList, "native_max_iosize", 16);
        Statistics_CallToString(NULL, 0, &cbCallStatistics);
        VMMDLL_VfsList_AddFile(pFileList, "statistics_fncall", cbCallStatistics);
    }
    // "process" view
    if(pProcess) {
        VMMDLL_VfsList_AddFile(pFileList, "cache_file_enable", 1);
    }
    return TRUE;
}

/*
* Initialization function. The module manager shall call into this function
* when the module shall be initialized. If the module wish to initialize it
* shall call the supplied pfnPluginManager_Register function.
* NB! the module does not have to register itself - for example if the target
* operating system or architecture is unsupported.
* -- pPluginRegInfo
*/
VOID M_Status_Initialize(_Inout_ PVMMDLL_PLUGIN_REGINFO pRI)
{
    if((pRI->magic != VMMDLL_PLUGIN_REGINFO_MAGIC) || (pRI->wVersion != VMMDLL_PLUGIN_REGINFO_VERSION)) { return; }
    // .status module is always valid - no check against pPluginRegInfo->tpMemoryModel, tpSystem
    strcpy_s(pRI->reg_info.szModuleName, 32, ".status"); // module name
    pRI->reg_info.fRootModule = TRUE;                    // module shows in root directory
    pRI->reg_info.fProcessModule = TRUE;                 // module shows in process directory
    pRI->reg_fn.pfnList = MStatus_List;                  // List function supported
    pRI->reg_fn.pfnRead = MStatus_Read;                  // Read function supported
    pRI->reg_fn.pfnWrite = MStatus_Write;                // Write function supported
    pRI->pfnPluginManager_Register(pRI);
}
