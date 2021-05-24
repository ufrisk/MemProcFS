// m_conf.c : implementation of the conf (configuration) built-in module.
//
// (c) Ulf Frisk, 2018-2021
// Author: Ulf Frisk, pcileech@frizk.net
//

/*
* The m_conf module registers itself with the name 'conf' with the plugin manager.
* 
* The module showcase a "root" directory module as well as a stateless module.
*
* The module implements listing of directories as well as read and write.
* Read/Write happens, if allowed, to various configuration and status settings
* related to the VMM and Memory Process File System.
*/

#include "pdb.h"
#include "pluginmanager.h"
#include "util.h"
#include "vmm.h"
#include "vmmproc.h"
#include "vmmwinreg.h"
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
NTSTATUS MConf_Read(_In_ PVMMDLL_PLUGIN_CONTEXT ctx, _Out_writes_to_(cb, *pcbRead) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset)
{
    DWORD cchBuffer;
    CHAR szBuffer[0x800];
    DWORD cbCallStatistics = 0;
    LPSTR szCallStatistics = NULL;
    QWORD cPageReadTotal, cPageFailTotal;
    NTSTATUS nt = VMMDLL_STATUS_FILE_INVALID;
    if(!_stricmp(ctx->uszPath, "config_process_show_terminated.txt")) {
        return Util_VfsReadFile_FromBOOL(ctxVmm->flags & VMM_FLAG_PROCESS_SHOW_TERMINATED, pb, cb, pcbRead, cbOffset);
    }
    if(!_stricmp(ctx->uszPath, "config_cache_enable.txt")) {
        return Util_VfsReadFile_FromBOOL(!(ctxVmm->flags & VMM_FLAG_NOCACHE), pb, cb, pcbRead, cbOffset);
    }
    if(!_stricmp(ctx->uszPath, "config_paging_enable.txt")) {
        return Util_VfsReadFile_FromBOOL(!(ctxVmm->flags & VMM_FLAG_NOPAGING), pb, cb, pcbRead, cbOffset);
    }
    if(!_stricmp(ctx->uszPath, "config_statistics_fncall.txt")) {
        return Util_VfsReadFile_FromBOOL(Statistics_CallGetEnabled(), pb, cb, pcbRead, cbOffset);
    }
    if(!_stricmp(ctx->uszPath, "config_refresh_enable.txt")) {
        return Util_VfsReadFile_FromBOOL(ctxVmm->ThreadProcCache.fEnabled, pb, cb, pcbRead, cbOffset);
    }
    if(!_stricmp(ctx->uszPath, "config_refresh_tick_period_ms.txt")) {
        return Util_VfsReadFile_FromDWORD(ctxVmm->ThreadProcCache.cMs_TickPeriod, pb, cb, pcbRead, cbOffset, FALSE);
    }
    if(!_stricmp(ctx->uszPath, "config_refresh_read.txt")) {
        return Util_VfsReadFile_FromDWORD(ctxVmm->ThreadProcCache.cTick_MEM, pb, cb, pcbRead, cbOffset, FALSE);
    }
    if(!_stricmp(ctx->uszPath, "config_refresh_tlb.txt")) {
        return Util_VfsReadFile_FromDWORD(ctxVmm->ThreadProcCache.cTick_TLB, pb, cb, pcbRead, cbOffset, FALSE);
    }
    if(!_stricmp(ctx->uszPath, "config_refresh_proc_partial.txt")) {
        return Util_VfsReadFile_FromDWORD(ctxVmm->ThreadProcCache.cTick_Fast, pb, cb, pcbRead, cbOffset, FALSE);
    }
    if(!_stricmp(ctx->uszPath, "config_refresh_proc_total.txt")) {
        return Util_VfsReadFile_FromDWORD(ctxVmm->ThreadProcCache.cTick_Medium, pb, cb, pcbRead, cbOffset, FALSE);
    }
    if(!_stricmp(ctx->uszPath, "config_refresh_registry.txt")) {
        return Util_VfsReadFile_FromDWORD(ctxVmm->ThreadProcCache.cTick_Slow, pb, cb, pcbRead, cbOffset, FALSE);
    }
    if(!_stricmp(ctx->uszPath, "statistics.txt")) {
        cPageReadTotal = ctxVmm->stat.page.cPrototype + ctxVmm->stat.page.cTransition + ctxVmm->stat.page.cDemandZero + ctxVmm->stat.page.cVAD + ctxVmm->stat.page.cCacheHit + ctxVmm->stat.page.cPageFile + ctxVmm->stat.page.cCompressed;
        cPageFailTotal = ctxVmm->stat.page.cFailCacheHit + ctxVmm->stat.page.cFailVAD + ctxVmm->stat.page.cFailPageFile + ctxVmm->stat.page.cFailCompressed + ctxVmm->stat.page.cFail;
        cchBuffer = snprintf(szBuffer, 0x800,
            "VMM STATISTICS   (4kB PAGES / COUNTS - HEXADECIMAL)\n" \
            "===================================================\n" \
            "PHYSICAL MEMORY:                      \n" \
            "  READ CACHE HIT:               %16llx\n" \
            "  READ RETRIEVED:               %16llx\n" \
            "  READ FAIL:                    %16llx\n" \
            "  WRITE:                        %16llx\n" \
            "PAGED VIRTUAL MEMORY:                 \n" \
            "  READ SUCCESS:                 %16llx\n" \
            "    Prototype:                  %16llx\n" \
            "    Transition:                 %16llx\n" \
            "    DemandZero:                 %16llx\n" \
            "    VAD:                        %16llx\n" \
            "    Cache:                      %16llx\n" \
            "    PageFile:                   %16llx\n" \
            "    Compressed:                 %16llx\n" \
            "  READ FAIL:                    %16llx\n" \
            "    Cache:                      %16llx\n" \
            "    VAD:                        %16llx\n" \
            "    PageFile:                   %16llx\n" \
            "    Compressed:                 %16llx\n" \
            "TLB (PAGE TABLES):                    \n" \
            "  CACHE HIT:                    %16llx\n" \
            "  RETRIEVED:                    %16llx\n" \
            "  FAILED:                       %16llx\n" \
            "PHYSICAL MEMORY REFRESH:        %16llx\n" \
            "TLB MEMORY REFRESH:             %16llx\n" \
            "PROCESS PARTIAL REFRESH:        %16llx\n" \
            "PROCESS FULL REFRESH:           %16llx\n",
            ctxVmm->stat.cPhysCacheHit, ctxVmm->stat.cPhysReadSuccess, ctxVmm->stat.cPhysReadFail, ctxVmm->stat.cPhysWrite,
            cPageReadTotal, ctxVmm->stat.page.cPrototype, ctxVmm->stat.page.cTransition, ctxVmm->stat.page.cDemandZero, ctxVmm->stat.page.cVAD, ctxVmm->stat.page.cCacheHit, ctxVmm->stat.page.cPageFile, ctxVmm->stat.page.cCompressed,
            cPageFailTotal, ctxVmm->stat.page.cFailCacheHit, ctxVmm->stat.page.cFailVAD, ctxVmm->stat.page.cFailPageFile, ctxVmm->stat.page.cFailCompressed,
            ctxVmm->stat.cTlbCacheHit, ctxVmm->stat.cTlbReadSuccess, ctxVmm->stat.cTlbReadFail,
            ctxVmm->stat.cPhysRefreshCache, ctxVmm->stat.cTlbRefreshCache, ctxVmm->stat.cProcessRefreshPartial, ctxVmm->stat.cProcessRefreshFull
        );
        return Util_VfsReadFile_FromPBYTE(szBuffer, cchBuffer, pb, cb, pcbRead, cbOffset);
    }
    if(!_stricmp(ctx->uszPath, "statistics_fncall.txt")) {
        if(Statistics_CallToString(&szCallStatistics, &cbCallStatistics)) {
            nt = Util_VfsReadFile_FromPBYTE(szCallStatistics, cbCallStatistics, pb, cb, pcbRead, cbOffset);
            LocalFree(szCallStatistics);
        }
        return nt;
    }
    if(!_stricmp(ctx->uszPath, "config_fileinfoheader_enable.txt")) {
        return Util_VfsReadFile_FromBOOL(ctxMain->cfg.fFileInfoHeader, pb, cb, pcbRead, cbOffset);
    }
    if(!_stricmp(ctx->uszPath, "config_printf_enable.txt")) {
        return Util_VfsReadFile_FromBOOL(ctxMain->cfg.fVerboseDll, pb, cb, pcbRead, cbOffset);
    }
    if(!_stricmp(ctx->uszPath, "config_printf_v.txt")) {
        return Util_VfsReadFile_FromBOOL(ctxMain->cfg.fVerbose, pb, cb, pcbRead, cbOffset);
    }
    if(!_stricmp(ctx->uszPath, "config_printf_vv.txt")) {
        return Util_VfsReadFile_FromBOOL(ctxMain->cfg.fVerboseExtra, pb, cb, pcbRead, cbOffset);
    }
    if(!_stricmp(ctx->uszPath, "config_printf_vvv.txt")) {
        return Util_VfsReadFile_FromBOOL(ctxMain->cfg.fVerboseExtraTlp, pb, cb, pcbRead, cbOffset);
    }
    if(!_stricmp(ctx->uszPath, "native_max_address.txt")) {
        return Util_VfsReadFile_FromQWORD(ctxMain->dev.paMax, pb, cb, pcbRead, cbOffset, FALSE);
    }
    if(!_strnicmp(ctx->uszPath, "config_symbol.txt", 13)) {
        if(!_stricmp(ctx->uszPath, "config_symbol_enable.txt")) {
            return Util_VfsReadFile_FromBOOL(ctxMain->pdb.fEnable, pb, cb, pcbRead, cbOffset);
        }
        if(!_stricmp(ctx->uszPath, "config_symbolcache.txt")) {
            return Util_VfsReadFile_FromPBYTE(ctxMain->pdb.szLocal, strlen(ctxMain->pdb.szLocal), pb, cb, pcbRead, cbOffset);
        }
        if(!_stricmp(ctx->uszPath, "config_symbolserver.txt")) {
            return Util_VfsReadFile_FromPBYTE(ctxMain->pdb.szServer, strlen(ctxMain->pdb.szServer), pb, cb, pcbRead, cbOffset);
        }
        if(!_stricmp(ctx->uszPath, "config_symbolserver_enable.txt")) {
            return Util_VfsReadFile_FromBOOL(ctxMain->pdb.fServerEnable, pb, cb, pcbRead, cbOffset);
        }
    }
    return VMMDLL_STATUS_FILE_INVALID;
}

NTSTATUS MConf_Write_NotifyVerbosityChange(_In_ NTSTATUS nt)
{
    if(nt == VMMDLL_STATUS_SUCCESS) {
        PluginManager_Notify(VMMDLL_PLUGIN_NOTIFY_VERBOSITYCHANGE, NULL, 0);
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
NTSTATUS MConf_Write(_In_ PVMMDLL_PLUGIN_CONTEXT ctx, _In_reads_(cb) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbWrite, _In_ QWORD cbOffset)
{
    NTSTATUS nt;
    BOOL fEnable = FALSE;
    if(!_stricmp(ctx->uszPath, "config_process_show_terminated.txt")) {
        nt = Util_VfsWriteFile_BOOL(&fEnable, pb, cb, pcbWrite, cbOffset);
        if(nt == VMMDLL_STATUS_SUCCESS) {
            ctxVmm->flags &= ~VMM_FLAG_PROCESS_SHOW_TERMINATED;
            ctxVmm->flags |= fEnable ? VMM_FLAG_PROCESS_SHOW_TERMINATED : 0;
        }
        return nt;
    }
    if(!_stricmp(ctx->uszPath, "config_cache_enable.txt")) {
        nt = Util_VfsWriteFile_BOOL(&fEnable, pb, cb, pcbWrite, cbOffset);
        if(nt == VMMDLL_STATUS_SUCCESS) {
            ctxVmm->flags &= ~VMM_FLAG_NOCACHE;
            ctxVmm->flags |= fEnable ? 0 : VMM_FLAG_NOCACHE;
        }
        return nt;
    }
    if(!_stricmp(ctx->uszPath, "config_paging_enable.txt")) {
        nt = Util_VfsWriteFile_BOOL(&fEnable, pb, cb, pcbWrite, cbOffset);
        if(nt == VMMDLL_STATUS_SUCCESS) {
            ctxVmm->flags &= ~VMM_FLAG_NOPAGING;
            ctxVmm->flags |= fEnable ? 0 : VMM_FLAG_NOPAGING;
        }
        return nt;
    }
    if(!_stricmp(ctx->uszPath, "config_statistics_fncall.txt")) {
        nt = Util_VfsWriteFile_BOOL(&fEnable, pb, cb, pcbWrite, cbOffset);
        if(nt == VMMDLL_STATUS_SUCCESS) {
            Statistics_CallSetEnabled(fEnable);
        }
        return nt;
    }
    if(!_stricmp(ctx->uszPath, "config_refresh_tick_period_ms.txt")) {
        return Util_VfsWriteFile_DWORD(&ctxVmm->ThreadProcCache.cMs_TickPeriod, pb, cb, pcbWrite, cbOffset, 50, 0);
    }
    if(!_stricmp(ctx->uszPath, "config_refresh_read.txt")) {
        return Util_VfsWriteFile_DWORD(&ctxVmm->ThreadProcCache.cTick_MEM, pb, cb, pcbWrite, cbOffset, 1, 0);
    }
    if(!_stricmp(ctx->uszPath, "config_refresh_tlb.txt")) {
        return Util_VfsWriteFile_DWORD(&ctxVmm->ThreadProcCache.cTick_TLB, pb, cb, pcbWrite, cbOffset, 1, 0);
    }
    if(!_stricmp(ctx->uszPath, "config_refresh_proc_partial.txt")) {
        return Util_VfsWriteFile_DWORD(&ctxVmm->ThreadProcCache.cTick_Fast, pb, cb, pcbWrite, cbOffset, 1, 0);
    }
    if(!_stricmp(ctx->uszPath, "config_refresh_proc_total.txt")) {
        return Util_VfsWriteFile_DWORD(&ctxVmm->ThreadProcCache.cTick_Medium, pb, cb, pcbWrite, cbOffset, 1, 0);
    }
    if(!_stricmp(ctx->uszPath, "config_refresh_registry.txt")) {
        VmmWinReg_Refresh();
        return Util_VfsWriteFile_DWORD(&ctxVmm->ThreadProcCache.cTick_Slow, pb, cb, pcbWrite, cbOffset, 1, 0);
    }
    if(!_stricmp(ctx->uszPath, "config_fileinfoheader_enable.txt")) {
        Util_VfsWriteFile_BOOL(&ctxMain->cfg.fFileInfoHeader, pb, cb, pcbWrite, cbOffset);
    }
    if(!_stricmp(ctx->uszPath, "config_printf_enable.txt")) {
        return MConf_Write_NotifyVerbosityChange(
            Util_VfsWriteFile_BOOL(&ctxMain->cfg.fVerboseDll, pb, cb, pcbWrite, cbOffset));
    }
    if(!_stricmp(ctx->uszPath, "config_printf_v.txt")) {
        return MConf_Write_NotifyVerbosityChange(
            Util_VfsWriteFile_BOOL(&ctxMain->cfg.fVerbose, pb, cb, pcbWrite, cbOffset));
    }
    if(!_stricmp(ctx->uszPath, "config_printf_vv.txt")) {
        return MConf_Write_NotifyVerbosityChange(
            Util_VfsWriteFile_BOOL(&ctxMain->cfg.fVerboseExtra, pb, cb, pcbWrite, cbOffset));
    }
    if(!_stricmp(ctx->uszPath, "config_printf_vvv.txt")) {
        return MConf_Write_NotifyVerbosityChange(
            Util_VfsWriteFile_BOOL(&ctxMain->cfg.fVerboseExtraTlp, pb, cb, pcbWrite, cbOffset));
    }
    if(!_strnicmp(ctx->uszPath, "config_symbol.txt", 13)) {
        nt = VMMDLL_STATUS_FILE_INVALID;
        if(!_stricmp(ctx->uszPath, "config_symbol_enable.txt")) {
            nt = Util_VfsWriteFile_DWORD(&ctxMain->pdb.fEnable, pb, cb, pcbWrite, cbOffset, 1, 0);
        }
        if(!_stricmp(ctx->uszPath, "config_symbolcache.txt")) {
            nt = Util_VfsWriteFile_PBYTE(ctxMain->pdb.szLocal, _countof(ctxMain->pdb.szLocal) - 1, pb, cb, pcbWrite, cbOffset, TRUE);
        }
        if(!_stricmp(ctx->uszPath, "config_symbolserver.txt")) {
            nt = Util_VfsWriteFile_PBYTE(ctxMain->pdb.szServer, _countof(ctxMain->pdb.szServer) - 1, pb, cb, pcbWrite, cbOffset, TRUE);
        }
        if(!_stricmp(ctx->uszPath, "config_symbolserver_enable.txt")) {
            nt = Util_VfsWriteFile_DWORD(&ctxMain->pdb.fServerEnable, pb, cb, pcbWrite, cbOffset, 1, 0);
        }
        PDB_ConfigChange();
        return nt;
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
BOOL MConf_List(_In_ PVMMDLL_PLUGIN_CONTEXT ctx, _Inout_ PHANDLE pFileList)
{
    DWORD cbCallStatistics = 0;
    // not module root directory -> fail!
    if(ctx->uszPath[0]) { return FALSE; }
    // "root" view
    if(!ctx->pProcess) {
        Statistics_CallToString(NULL, &cbCallStatistics);
        VMMDLL_VfsList_AddFile(pFileList, "config_fileinfoheader_enable.txt", 1, NULL);
        VMMDLL_VfsList_AddFile(pFileList, "config_cache_enable.txt", 1, NULL);
        VMMDLL_VfsList_AddFile(pFileList, "config_paging_enable.txt", 1, NULL);
        VMMDLL_VfsList_AddFile(pFileList, "config_statistics_fncall.txt", 1, NULL);
        VMMDLL_VfsList_AddFile(pFileList, "config_refresh_enable.txt", 1, NULL);
        VMMDLL_VfsList_AddFile(pFileList, "config_refresh_tick_period_ms.txt", 8, NULL);
        VMMDLL_VfsList_AddFile(pFileList, "config_refresh_read.txt", 8, NULL);
        VMMDLL_VfsList_AddFile(pFileList, "config_refresh_tlb.txt", 8, NULL);
        VMMDLL_VfsList_AddFile(pFileList, "config_refresh_proc_partial.txt", 8, NULL);
        VMMDLL_VfsList_AddFile(pFileList, "config_refresh_proc_total.txt", 8, NULL);
        VMMDLL_VfsList_AddFile(pFileList, "config_refresh_registry.txt", 8, NULL);
        VMMDLL_VfsList_AddFile(pFileList, "config_symbol_enable.txt", 1, NULL);
        VMMDLL_VfsList_AddFile(pFileList, "config_symbolcache.txt", strlen(ctxMain->pdb.szLocal), NULL);
        VMMDLL_VfsList_AddFile(pFileList, "config_symbolserver.txt", strlen(ctxMain->pdb.szServer), NULL);
        VMMDLL_VfsList_AddFile(pFileList, "config_symbolserver_enable.txt", 1, NULL);
        VMMDLL_VfsList_AddFile(pFileList, "statistics.txt", 1103, NULL);
        VMMDLL_VfsList_AddFile(pFileList, "config_printf_enable.txt", 1, NULL);
        VMMDLL_VfsList_AddFile(pFileList, "config_printf_v.txt", 1, NULL);
        VMMDLL_VfsList_AddFile(pFileList, "config_printf_vv.txt", 1, NULL);
        VMMDLL_VfsList_AddFile(pFileList, "config_printf_vvv.txt", 1, NULL);
        VMMDLL_VfsList_AddFile(pFileList, "config_process_show_terminated.txt", 1, NULL);
        VMMDLL_VfsList_AddFile(pFileList, "native_max_address.txt", 16, NULL);
        VMMDLL_VfsList_AddFile(pFileList, "statistics_fncall.txt", cbCallStatistics, NULL);
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
VOID M_Conf_Initialize(_Inout_ PVMMDLL_PLUGIN_REGINFO pRI)
{
    if((pRI->magic != VMMDLL_PLUGIN_REGINFO_MAGIC) || (pRI->wVersion != VMMDLL_PLUGIN_REGINFO_VERSION)) { return; }
    // .status module is always valid - no check against pPluginRegInfo->tpMemoryModel, tpSystem
    strcpy_s(pRI->reg_info.uszPathName, 128, "\\conf");       // module name
    pRI->reg_info.fRootModule = TRUE;                         // module shows in root directory
    pRI->reg_fn.pfnList = MConf_List;                         // List function supported
    pRI->reg_fn.pfnRead = MConf_Read;                         // Read function supported
    pRI->reg_fn.pfnWrite = MConf_Write;                       // Write function supported
    pRI->pfnPluginManager_Register(pRI);
}
