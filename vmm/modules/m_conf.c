// m_conf.c : implementation of the conf (configuration) built-in module.
//
// (c) Ulf Frisk, 2018-2025
// Author: Ulf Frisk, pcileech@frizk.net
//

#include "modules.h"
#include "../vmmwinreg.h"

// Forward declarations:
_Success_(return)
BOOL VMMDLL_ConfigSet_Impl(_In_ VMM_HANDLE H, _In_ ULONG64 fOption, _In_ ULONG64 qwValue);

/*
* Read : function as specified by the module manager. The module manager will
* call into this callback function whenever a read shall occur from a "file".
* -- H
* -- ctxP
* -- pb
* -- cb
* -- pcbRead
* -- cbOffset
* -- return
*/
NTSTATUS MConf_Read(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_CONTEXT ctxP, _Out_writes_to_(cb, *pcbRead) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset)
{
    DWORD cchBuffer;
    CHAR szBuffer[0x800];
    DWORD cbCallStatistics = 0;
    LPSTR szCallStatistics = NULL;
    QWORD cPageReadTotal, cPageFailTotal;
    NTSTATUS nt = VMMDLL_STATUS_FILE_INVALID;
    if(!_stricmp(ctxP->uszPath, "config_process_show_terminated.txt")) {
        return Util_VfsReadFile_FromBOOL(H->vmm.flags & VMM_FLAG_PROCESS_SHOW_TERMINATED, pb, cb, pcbRead, cbOffset);
    }
    if(!_stricmp(ctxP->uszPath, "config_cache_enable.txt")) {
        return Util_VfsReadFile_FromBOOL(!(H->vmm.flags & VMM_FLAG_NOCACHE), pb, cb, pcbRead, cbOffset);
    }
    if(!_stricmp(ctxP->uszPath, "config_paging_enable.txt")) {
        return Util_VfsReadFile_FromBOOL(!(H->vmm.flags & VMM_FLAG_NOPAGING), pb, cb, pcbRead, cbOffset);
    }
    if(!_stricmp(ctxP->uszPath, "config_statistics_fncall.txt")) {
        return Util_VfsReadFile_FromBOOL(Statistics_CallGetEnabled(H), pb, cb, pcbRead, cbOffset);
    }
    if(!_stricmp(ctxP->uszPath, "config_refresh_enable.txt")) {
        return Util_VfsReadFile_FromBOOL(H->vmm.ThreadProcCache.fEnabled, pb, cb, pcbRead, cbOffset);
    }
    if(!_stricmp(ctxP->uszPath, "config_refresh_tick_period_ms.txt")) {
        return Util_VfsReadFile_FromDWORD(H->vmm.ThreadProcCache.cMs_TickPeriod, pb, cb, pcbRead, cbOffset, FALSE);
    }
    if(!_stricmp(ctxP->uszPath, "config_refresh_period_mem.txt")) {
        return Util_VfsReadFile_FromDWORD(H->vmm.ThreadProcCache.cTick_MEM, pb, cb, pcbRead, cbOffset, FALSE);
    }
    if(!_stricmp(ctxP->uszPath, "config_refresh_period_tlb.txt")) {
        return Util_VfsReadFile_FromDWORD(H->vmm.ThreadProcCache.cTick_TLB, pb, cb, pcbRead, cbOffset, FALSE);
    }
    if(!_stricmp(ctxP->uszPath, "config_refresh_period_fast.txt")) {
        return Util_VfsReadFile_FromDWORD(H->vmm.ThreadProcCache.cTick_Fast, pb, cb, pcbRead, cbOffset, FALSE);
    }
    if(!_stricmp(ctxP->uszPath, "config_refresh_period_medium.txt")) {
        return Util_VfsReadFile_FromDWORD(H->vmm.ThreadProcCache.cTick_Medium, pb, cb, pcbRead, cbOffset, FALSE);
    }
    if(!_stricmp(ctxP->uszPath, "config_refresh_period_slow.txt")) {
        return Util_VfsReadFile_FromDWORD(H->vmm.ThreadProcCache.cTick_Slow, pb, cb, pcbRead, cbOffset, FALSE);
    }
    if(!_stricmp(ctxP->uszPath, "config_refresh_force_all.txt")) {
        return Util_VfsReadFile_FromNumber(0, pb, cb, pcbRead, cbOffset);
    }
    if(!_stricmp(ctxP->uszPath, "config_refresh_force_mem.txt")) {
        return Util_VfsReadFile_FromNumber(0, pb, cb, pcbRead, cbOffset);
    }
    if(!_stricmp(ctxP->uszPath, "config_refresh_force_tlb.txt")) {
        return Util_VfsReadFile_FromNumber(0, pb, cb, pcbRead, cbOffset);
    }
    if(!_stricmp(ctxP->uszPath, "config_refresh_force_fast.txt")) {
        return Util_VfsReadFile_FromNumber(0, pb, cb, pcbRead, cbOffset);
    }
    if(!_stricmp(ctxP->uszPath, "config_refresh_force_medium.txt")) {
        return Util_VfsReadFile_FromNumber(0, pb, cb, pcbRead, cbOffset);
    }
    if(!_stricmp(ctxP->uszPath, "config_refresh_force_slow.txt")) {
        return Util_VfsReadFile_FromNumber(0, pb, cb, pcbRead, cbOffset);
    }
    if(!_stricmp(ctxP->uszPath, "statistics.txt")) {
        cPageReadTotal = H->vmm.stat.page.cPrototype + H->vmm.stat.page.cTransition + H->vmm.stat.page.cDemandZero + H->vmm.stat.page.cVAD + H->vmm.stat.page.cCacheHit + H->vmm.stat.page.cPageFile + H->vmm.stat.page.cCompressed;
        cPageFailTotal = H->vmm.stat.page.cFailCacheHit + H->vmm.stat.page.cFailVAD + H->vmm.stat.page.cFailFileMapped + H->vmm.stat.page.cFailPageFile + H->vmm.stat.page.cFailCompressed + H->vmm.stat.page.cFail;
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
            "    FileMapped:                 %16llx\n" \
            "    PageFile:                   %16llx\n" \
            "    Compressed:                 %16llx\n" \
            "TLB (PAGE TABLES):                    \n" \
            "  CACHE HIT:                    %16llx\n" \
            "  RETRIEVED:                    %16llx\n" \
            "  FAILED:                       %16llx\n" \
            "GUEST-PHYSICAL MEMORY:                \n" \
            "  READ SUCESS:                  %16llx\n" \
            "  READ FAIL:                    %16llx\n" \
            "  WRITE:                        %16llx\n" \
            "PHYSICAL MEMORY REFRESH:        %16llx\n" \
            "TLB MEMORY REFRESH:             %16llx\n" \
            "PROCESS PARTIAL REFRESH:        %16llx\n" \
            "PROCESS FULL REFRESH:           %16llx\n",
            H->vmm.stat.cPhysCacheHit, H->vmm.stat.cPhysReadSuccess, H->vmm.stat.cPhysReadFail, H->vmm.stat.cPhysWrite,
            cPageReadTotal, H->vmm.stat.page.cPrototype, H->vmm.stat.page.cTransition, H->vmm.stat.page.cDemandZero, H->vmm.stat.page.cVAD, H->vmm.stat.page.cCacheHit, H->vmm.stat.page.cPageFile, H->vmm.stat.page.cCompressed,
            cPageFailTotal, H->vmm.stat.page.cFailCacheHit, H->vmm.stat.page.cFailVAD, H->vmm.stat.page.cFailFileMapped, H->vmm.stat.page.cFailPageFile, H->vmm.stat.page.cFailCompressed,
            H->vmm.stat.cTlbCacheHit, H->vmm.stat.cTlbReadSuccess, H->vmm.stat.cTlbReadFail,
            H->vmm.stat.cGpaReadSuccess, H->vmm.stat.cGpaReadFail, H->vmm.stat.cGpaWrite,
            H->vmm.stat.cPhysRefreshCache, H->vmm.stat.cTlbRefreshCache, H->vmm.stat.cProcessRefreshPartial, H->vmm.stat.cProcessRefreshFull
        );
        return Util_VfsReadFile_FromPBYTE(szBuffer, cchBuffer, pb, cb, pcbRead, cbOffset);
    }
    if(!_stricmp(ctxP->uszPath, "statistics_fncall.txt")) {
        if(Statistics_CallToString(H, &szCallStatistics, &cbCallStatistics)) {
            nt = Util_VfsReadFile_FromPBYTE(szCallStatistics, cbCallStatistics, pb, cb, pcbRead, cbOffset);
            LocalFree(szCallStatistics);
        }
        return nt;
    }
    if(!_stricmp(ctxP->uszPath, "config_fileinfoheader_enable.txt")) {
        return Util_VfsReadFile_FromBOOL(H->cfg.fFileInfoHeader, pb, cb, pcbRead, cbOffset);
    }
    if(!_stricmp(ctxP->uszPath, "config_printf_enable.txt")) {
        return Util_VfsReadFile_FromBOOL(H->cfg.fVerboseDll, pb, cb, pcbRead, cbOffset);
    }
    if(!_stricmp(ctxP->uszPath, "config_printf_v.txt")) {
        return Util_VfsReadFile_FromBOOL(H->cfg.fVerbose, pb, cb, pcbRead, cbOffset);
    }
    if(!_stricmp(ctxP->uszPath, "config_printf_vv.txt")) {
        return Util_VfsReadFile_FromBOOL(H->cfg.fVerboseExtra, pb, cb, pcbRead, cbOffset);
    }
    if(!_stricmp(ctxP->uszPath, "config_printf_vvv.txt")) {
        return Util_VfsReadFile_FromBOOL(H->cfg.fVerboseExtraTlp, pb, cb, pcbRead, cbOffset);
    }
    if(!_stricmp(ctxP->uszPath, "native_max_address.txt")) {
        return Util_VfsReadFile_FromQWORD(H->dev.paMax, pb, cb, pcbRead, cbOffset, FALSE);
    }
    if(!_strnicmp(ctxP->uszPath, "config_symbol.txt", 13)) {
        if(!_stricmp(ctxP->uszPath, "config_symbol_enable.txt")) {
            return Util_VfsReadFile_FromBOOL(H->pdb.fEnable, pb, cb, pcbRead, cbOffset);
        }
        if(!_stricmp(ctxP->uszPath, "config_symbolcache.txt")) {
            return Util_VfsReadFile_FromPBYTE(H->pdb.szLocal, strlen(H->pdb.szLocal), pb, cb, pcbRead, cbOffset);
        }
        if(!_stricmp(ctxP->uszPath, "config_symbolserver.txt")) {
            return Util_VfsReadFile_FromPBYTE(H->pdb.szServer, strlen(H->pdb.szServer), pb, cb, pcbRead, cbOffset);
        }
        if(!_stricmp(ctxP->uszPath, "config_symbolserver_enable.txt")) {
            return Util_VfsReadFile_FromBOOL(H->pdb.fServerEnable, pb, cb, pcbRead, cbOffset);
        }
    }
    return VMMDLL_STATUS_FILE_INVALID;
}

NTSTATUS MConf_Write_NotifyVerbosityChange(_In_ VMM_HANDLE H, _In_ NTSTATUS nt)
{
    if(nt == VMMDLL_STATUS_SUCCESS) {
        PluginManager_Notify(H, VMMDLL_PLUGIN_NOTIFY_VERBOSITYCHANGE, NULL, 0);
    }
    return nt;
}

/*
* Write : function as specified by the module manager. The module manager will
* call into this callback function whenever a write shall occur from a "file".
* -- H
* -- ctxP
* -- pb
* -- cb
* -- pcbWrite
* -- cbOffset
* -- return
*/
NTSTATUS MConf_Write(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_CONTEXT ctxP, _In_reads_(cb) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbWrite, _In_ QWORD cbOffset)
{
    NTSTATUS nt;
    DWORD dw = 0;
    BOOL fEnable = FALSE;
    if(!_stricmp(ctxP->uszPath, "config_process_show_terminated.txt")) {
        nt = Util_VfsWriteFile_BOOL(&fEnable, pb, cb, pcbWrite, cbOffset);
        if(nt == VMMDLL_STATUS_SUCCESS) {
            H->vmm.flags &= ~VMM_FLAG_PROCESS_SHOW_TERMINATED;
            H->vmm.flags |= fEnable ? VMM_FLAG_PROCESS_SHOW_TERMINATED : 0;
        }
        return nt;
    }
    if(!_stricmp(ctxP->uszPath, "config_cache_enable.txt")) {
        nt = Util_VfsWriteFile_BOOL(&fEnable, pb, cb, pcbWrite, cbOffset);
        if(nt == VMMDLL_STATUS_SUCCESS) {
            H->vmm.flags &= ~VMM_FLAG_NOCACHE;
            H->vmm.flags |= fEnable ? 0 : VMM_FLAG_NOCACHE;
        }
        return nt;
    }
    if(!_stricmp(ctxP->uszPath, "config_paging_enable.txt")) {
        nt = Util_VfsWriteFile_BOOL(&fEnable, pb, cb, pcbWrite, cbOffset);
        if(nt == VMMDLL_STATUS_SUCCESS) {
            H->vmm.flags &= ~VMM_FLAG_NOPAGING;
            H->vmm.flags |= fEnable ? 0 : VMM_FLAG_NOPAGING;
        }
        return nt;
    }
    if(!_stricmp(ctxP->uszPath, "config_statistics_fncall.txt")) {
        nt = Util_VfsWriteFile_BOOL(&fEnable, pb, cb, pcbWrite, cbOffset);
        if(nt == VMMDLL_STATUS_SUCCESS) {
            Statistics_CallSetEnabled(H, fEnable);
        }
        return nt;
    }
    if(!_stricmp(ctxP->uszPath, "config_refresh_tick_period_ms.txt")) {
        return Util_VfsWriteFile_DWORD(&H->vmm.ThreadProcCache.cMs_TickPeriod, pb, cb, pcbWrite, cbOffset, 50, 0);
    }
    if(!_stricmp(ctxP->uszPath, "config_refresh_period_mem.txt")) {
        return Util_VfsWriteFile_DWORD(&H->vmm.ThreadProcCache.cTick_MEM, pb, cb, pcbWrite, cbOffset, 1, 0);
    }
    if(!_stricmp(ctxP->uszPath, "config_refresh_period_tlb.txt")) {
        return Util_VfsWriteFile_DWORD(&H->vmm.ThreadProcCache.cTick_TLB, pb, cb, pcbWrite, cbOffset, 1, 0);
    }
    if(!_stricmp(ctxP->uszPath, "config_refresh_period_fast.txt")) {
        return Util_VfsWriteFile_DWORD(&H->vmm.ThreadProcCache.cTick_Fast, pb, cb, pcbWrite, cbOffset, 1, 0);
    }
    if(!_stricmp(ctxP->uszPath, "config_refresh_period_medium.txt")) {
        return Util_VfsWriteFile_DWORD(&H->vmm.ThreadProcCache.cTick_Medium, pb, cb, pcbWrite, cbOffset, 1, 0);
    }
    if(!_stricmp(ctxP->uszPath, "config_refresh_period_slow.txt")) {
        return Util_VfsWriteFile_DWORD(&H->vmm.ThreadProcCache.cTick_Slow, pb, cb, pcbWrite, cbOffset, 1, 0);
    }
    if(!_stricmp(ctxP->uszPath, "config_refresh_force_all.txt")) {
        Util_VfsWriteFile_DWORD(&dw, pb, cb, pcbWrite, cbOffset, 0, 0);
        if(dw) { VMMDLL_ConfigSet_Impl(H, VMMDLL_OPT_REFRESH_ALL, 1); }
        return VMMDLL_STATUS_SUCCESS;
    }
    if(!_stricmp(ctxP->uszPath, "config_refresh_force_mem.txt")) {
        Util_VfsWriteFile_DWORD(&dw, pb, cb, pcbWrite, cbOffset, 0, 0);
        if(dw) { VMMDLL_ConfigSet_Impl(H, VMMDLL_OPT_REFRESH_FREQ_MEM, 1); }
        return VMMDLL_STATUS_SUCCESS;
    }
    if(!_stricmp(ctxP->uszPath, "config_refresh_force_tlb.txt")) {
        Util_VfsWriteFile_DWORD(&dw, pb, cb, pcbWrite, cbOffset, 0, 0);
        if(dw) { VMMDLL_ConfigSet_Impl(H, VMMDLL_OPT_REFRESH_FREQ_TLB, 1); }
        return VMMDLL_STATUS_SUCCESS;
    }
    if(!_stricmp(ctxP->uszPath, "config_refresh_force_fast.txt")) {
        Util_VfsWriteFile_DWORD(&dw, pb, cb, pcbWrite, cbOffset, 0, 0);
        if(dw) { VMMDLL_ConfigSet_Impl(H, VMMDLL_OPT_REFRESH_FREQ_FAST, 1); }
        return VMMDLL_STATUS_SUCCESS;
    }
    if(!_stricmp(ctxP->uszPath, "config_refresh_force_medium.txt")) {
        Util_VfsWriteFile_DWORD(&dw, pb, cb, pcbWrite, cbOffset, 0, 0);
        if(dw) { VMMDLL_ConfigSet_Impl(H, VMMDLL_OPT_REFRESH_FREQ_MEDIUM, 1); }
        return VMMDLL_STATUS_SUCCESS;
    }
    if(!_stricmp(ctxP->uszPath, "config_refresh_force_slow.txt")) {
        Util_VfsWriteFile_DWORD(&dw, pb, cb, pcbWrite, cbOffset, 0, 0);
        if(dw) { VMMDLL_ConfigSet_Impl(H, VMMDLL_OPT_REFRESH_FREQ_SLOW, 1); }
        return VMMDLL_STATUS_SUCCESS;
    }
    if(!_stricmp(ctxP->uszPath, "config_fileinfoheader_enable.txt")) {
        Util_VfsWriteFile_BOOL(&H->cfg.fFileInfoHeader, pb, cb, pcbWrite, cbOffset);
    }
    if(!_stricmp(ctxP->uszPath, "config_printf_enable.txt")) {
        return MConf_Write_NotifyVerbosityChange(
            H, Util_VfsWriteFile_BOOL(&H->cfg.fVerboseDll, pb, cb, pcbWrite, cbOffset));
    }
    if(!_stricmp(ctxP->uszPath, "config_printf_v.txt")) {
        return MConf_Write_NotifyVerbosityChange(
            H, Util_VfsWriteFile_BOOL(&H->cfg.fVerbose, pb, cb, pcbWrite, cbOffset));
    }
    if(!_stricmp(ctxP->uszPath, "config_printf_vv.txt")) {
        return MConf_Write_NotifyVerbosityChange(
            H, Util_VfsWriteFile_BOOL(&H->cfg.fVerboseExtra, pb, cb, pcbWrite, cbOffset));
    }
    if(!_stricmp(ctxP->uszPath, "config_printf_vvv.txt")) {
        return MConf_Write_NotifyVerbosityChange(
            H, Util_VfsWriteFile_BOOL(&H->cfg.fVerboseExtraTlp, pb, cb, pcbWrite, cbOffset));
    }
    if(!_strnicmp(ctxP->uszPath, "config_symbol.txt", 13)) {
        nt = VMMDLL_STATUS_FILE_INVALID;
        if(!_stricmp(ctxP->uszPath, "config_symbol_enable.txt")) {
            nt = Util_VfsWriteFile_DWORD(&H->pdb.fEnable, pb, cb, pcbWrite, cbOffset, 1, 0);
        }
        if(!_stricmp(ctxP->uszPath, "config_symbolcache.txt")) {
            nt = Util_VfsWriteFile_PBYTE(H->pdb.szLocal, _countof(H->pdb.szLocal) - 1, pb, cb, pcbWrite, cbOffset, TRUE);
        }
        if(!_stricmp(ctxP->uszPath, "config_symbolserver.txt")) {
            nt = Util_VfsWriteFile_PBYTE(H->pdb.szServer, _countof(H->pdb.szServer) - 1, pb, cb, pcbWrite, cbOffset, TRUE);
        }
        if(!_stricmp(ctxP->uszPath, "config_symbolserver_enable.txt")) {
            nt = Util_VfsWriteFile_DWORD(&H->pdb.fServerEnable, pb, cb, pcbWrite, cbOffset, 1, 0);
        }
        PDB_ConfigChange(H);
        return nt;
    }
    return VMMDLL_STATUS_FILE_INVALID;
}

/*
* List : function as specified by the module manager. The module manager will
* call into this callback function whenever a list directory shall occur from
* the given module.
* -- H
* -- ctxP
* -- pFileList
* -- return
*/
BOOL MConf_List(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_CONTEXT ctxP, _Inout_ PHANDLE pFileList)
{
    DWORD cbCallStatistics = 0;
    // not module root directory -> fail!
    if(ctxP->uszPath[0]) { return FALSE; }
    // "root" view
    if(!ctxP->pProcess) {
        Statistics_CallToString(H, NULL, &cbCallStatistics);
        VMMDLL_VfsList_AddFile(pFileList, "config_fileinfoheader_enable.txt", 1, NULL);
        VMMDLL_VfsList_AddFile(pFileList, "config_cache_enable.txt", 1, NULL);
        VMMDLL_VfsList_AddFile(pFileList, "config_paging_enable.txt", 1, NULL);
        VMMDLL_VfsList_AddFile(pFileList, "config_statistics_fncall.txt", 1, NULL);
        VMMDLL_VfsList_AddFile(pFileList, "config_refresh_enable.txt", 1, NULL);
        VMMDLL_VfsList_AddFile(pFileList, "config_refresh_tick_period_ms.txt", 8, NULL);
        VMMDLL_VfsList_AddFile(pFileList, "config_refresh_force_all.txt", 1, NULL);
        VMMDLL_VfsList_AddFile(pFileList, "config_refresh_force_mem.txt", 1, NULL);
        VMMDLL_VfsList_AddFile(pFileList, "config_refresh_force_tlb.txt", 1, NULL);
        VMMDLL_VfsList_AddFile(pFileList, "config_refresh_force_fast.txt", 1, NULL);
        VMMDLL_VfsList_AddFile(pFileList, "config_refresh_force_medium.txt", 1, NULL);
        VMMDLL_VfsList_AddFile(pFileList, "config_refresh_force_slow.txt", 1, NULL);
        VMMDLL_VfsList_AddFile(pFileList, "config_refresh_period_mem.txt", 8, NULL);
        VMMDLL_VfsList_AddFile(pFileList, "config_refresh_period_tlb.txt", 8, NULL);
        VMMDLL_VfsList_AddFile(pFileList, "config_refresh_period_fast.txt", 8, NULL);
        VMMDLL_VfsList_AddFile(pFileList, "config_refresh_period_medium.txt", 8, NULL);
        VMMDLL_VfsList_AddFile(pFileList, "config_refresh_period_slow.txt", 8, NULL);
        VMMDLL_VfsList_AddFile(pFileList, "config_symbol_enable.txt", 1, NULL);
        VMMDLL_VfsList_AddFile(pFileList, "config_symbolcache.txt", strlen(H->pdb.szLocal), NULL);
        VMMDLL_VfsList_AddFile(pFileList, "config_symbolserver.txt", strlen(H->pdb.szServer), NULL);
        VMMDLL_VfsList_AddFile(pFileList, "config_symbolserver_enable.txt", 1, NULL);
        VMMDLL_VfsList_AddFile(pFileList, "statistics.txt", 1632, NULL);
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
* -- H
* -- pRI
*/
VOID M_Conf_Initialize(_In_ VMM_HANDLE H, _Inout_ PVMMDLL_PLUGIN_REGINFO pRI)
{
    if((pRI->magic != VMMDLL_PLUGIN_REGINFO_MAGIC) || (pRI->wVersion != VMMDLL_PLUGIN_REGINFO_VERSION)) { return; }
    // .status module is always valid - no check against pPluginRegInfo->tpMemoryModel, tpSystem
    strcpy_s(pRI->reg_info.uszPathName, 128, "\\conf");       // module name
    pRI->reg_info.fRootModule = TRUE;                         // module shows in root directory
    pRI->reg_fn.pfnList = MConf_List;                         // List function supported
    pRI->reg_fn.pfnRead = MConf_Read;                         // Read function supported
    pRI->reg_fn.pfnWrite = MConf_Write;                       // Write function supported
    pRI->pfnPluginManager_Register(H, pRI);
}
