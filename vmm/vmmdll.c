// vmmdll.h : implementation of core dynamic link library (dll) functionality
// of the virtual memory manager (VMM) for The Memory Process File System.
//
// (c) Ulf Frisk, 2018-2019
// Author: Ulf Frisk, pcileech@frizk.net
//

#include "vmmdll.h"
#include "pluginmanager.h"
#include "util.h"
#include "pe.h"
#include "statistics.h"
#include "version.h"
#include "vmm.h"
#include "vmmproc.h"
#include "vmmwin.h"
#include "vmmvfs.h"
#include "mm_x64_winpaged.h"

// ----------------------------------------------------------------------------
// Synchronization macro below. The VMM isn't thread safe so it's important to
// serialize access to it over the VMM MasterLock. This master lock is shared
// with internal VMM housekeeping functionality.
// ----------------------------------------------------------------------------

#define CALL_SYNCHRONIZED_IMPLEMENTATION_VMM(id, fn) {                      \
    QWORD tm;                                                               \
    BOOL result;                                                            \
    if(!ctxVmm) { return FALSE; }                                           \
    tm = Statistics_CallStart();                                            \
    VmmLockAcquire();                                                       \
    result = fn;                                                            \
    VmmLockRelease();                                                       \
    Statistics_CallEnd(id, tm);                                             \
    return result;                                                          \
}

#define CALL_SYNCHRONIZED_IMPLEMENTATION_VMM_RETURN(id, RetTp, RetValFail, fn) { \
    QWORD tm;                                                                    \
    RetTp retVal;                                                                \
    if(!ctxVmm) { return ((RetTp)RetValFail); } /* UNSUCCESSFUL */               \
    tm = Statistics_CallStart();                                                 \
    VmmLockAcquire();                                                            \
    retVal = fn;                                                                 \
    VmmLockRelease();                                                            \
    Statistics_CallEnd(id, tm);                                                  \
    return retVal;                                                               \
}

//-----------------------------------------------------------------------------
// INITIALIZATION FUNCTIONALITY BELOW:
//-----------------------------------------------------------------------------

_Success_(return)
BOOL VmmDll_ConfigIntialize(_In_ DWORD argc, _In_ char* argv[])
{
    char* argv2[3];
    CHAR chMountMount = '\0';
    DWORD i = 0;
    if((argc == 2) && argv[1][0] && (argv[1][0] != '-')) {
        // click to open -> only 1 argument ...
        argv2[0] = argv[0];
        argv2[1] = "-device";
        argv2[2] = argv[1];
        return VmmDll_ConfigIntialize(3, argv2);
    }
    while(i < argc) {
        if(0 == _stricmp(argv[i], "")) {
            i++;
            continue;
        } else if(0 == _stricmp(argv[i], "-printf")) {
            ctxMain->cfg.fVerboseDll = TRUE;
            i++;
            continue;
        } else if(0 == _stricmp(argv[i], "-v")) {
            ctxMain->cfg.fVerbose = TRUE;
            i++;
            continue;
        } else if(0 == _stricmp(argv[i], "-vv")) {
            ctxMain->cfg.fVerboseExtra = TRUE;
            i++;
            continue;
        } else if(0 == _stricmp(argv[i], "-vvv")) {
            ctxMain->cfg.fVerboseExtraTlp = TRUE;
            i++;
            continue;
        } else if(0 == _stricmp(argv[i], "-identify")) {
            ctxMain->cfg.fCommandIdentify = TRUE;
            i++;
            continue;
        } else if(0 == _stricmp(argv[i], "-norefresh")) {
            ctxMain->cfg.fDisableBackgroundRefresh = TRUE;
            i++;
            continue;
        } else if(i + 1 >= argc) {
            return FALSE;
        } else if(0 == strcmp(argv[i], "-cr3")) {
            ctxMain->cfg.paCR3 = Util_GetNumeric(argv[i + 1]);
            i += 2;
            continue;
        } else if(0 == strcmp(argv[i], "-max")) {
            ctxMain->dev.paMax = Util_GetNumeric(argv[i + 1]);
            i += 2;
            continue;
        } else if((0 == strcmp(argv[i], "-device")) || (0 == strcmp(argv[i], "-z"))) {
            strcpy_s(ctxMain->dev.szDevice, MAX_PATH, argv[i + 1]);
            i += 2;
            continue;
        } else if(0 == strcmp(argv[i], "-remote")) {
            strcpy_s(ctxMain->dev.szRemote, MAX_PATH, argv[i + 1]);
            i += 2;
            continue;
        } else if(0 == strcmp(argv[i], "-pythonpath")) {
            strcpy_s(ctxMain->cfg.szPythonPath, MAX_PATH, argv[i + 1]);
            i += 2;
            continue;
        } else if(0 == strcmp(argv[i], "-mount")) {
            chMountMount = argv[i + 1][0];
            i += 2;
            continue;
        } else {
            return FALSE;
        }
    }
    if((chMountMount > 'A' && chMountMount < 'Z') || (chMountMount > 'a' && chMountMount < 'z')) {
        ctxMain->cfg.szMountPoint[0] = chMountMount;
    } else {
        ctxMain->cfg.szMountPoint[0] = 'M';
    }
    if(ctxMain->dev.paMax == 0) { ctxMain->dev.paMax = 0x0000ffffffffffff; }
    if(ctxMain->dev.paMax < 0x00100000) { return FALSE; }
    ctxMain->cfg.fVerbose = ctxMain->cfg.fVerbose && ctxMain->cfg.fVerboseDll;
    ctxMain->cfg.fVerboseExtra = ctxMain->cfg.fVerboseExtra && ctxMain->cfg.fVerboseDll;
    ctxMain->cfg.fVerboseExtraTlp = ctxMain->cfg.fVerboseExtraTlp && ctxMain->cfg.fVerboseDll;
    ctxMain->dev.magic = LEECHCORE_CONFIG_MAGIC;
    ctxMain->dev.version = LEECHCORE_CONFIG_VERSION;
    ctxMain->dev.flags |= ctxMain->cfg.fVerboseDll ? LEECHCORE_CONFIG_FLAG_PRINTF : 0;
    ctxMain->dev.flags |= ctxMain->cfg.fVerbose ? LEECHCORE_CONFIG_FLAG_PRINTF_VERBOSE_1 : 0;
    ctxMain->dev.flags |= ctxMain->cfg.fVerboseExtra ? LEECHCORE_CONFIG_FLAG_PRINTF_VERBOSE_2 : 0;
    ctxMain->dev.flags |= ctxMain->cfg.fVerboseExtraTlp ? LEECHCORE_CONFIG_FLAG_PRINTF_VERBOSE_3 : 0;
    return (ctxMain->dev.szDevice[0] != 0);
}

VOID VmmDll_PrintHelp()
{
    vmmprintf(
        "                                                                               \n" \
        " THE MEMORY PROCESS FILE SYSTEM v%i.%i.%i COMMAND LINE REFERENCE:              \n" \
        " The Memory Process File System may be used in stand-alone mode with support   \n" \
        " for memory dump files, local memory via rekall winpmem driver or together with\n" \
        " PCILeech if pcileech.dll is placed in the application directory. For infor-   \n" \
        " mation about PCILeech please consult the separate PCILeech documentation.     \n" \
        " -----                                                                         \n" \
        " The Memory Process File System (c) 2018-2019 Ulf Frisk                        \n" \
        " License: GNU GENERAL PUBLIC LICENSE - Version 3, 29 June 2007                 \n" \
        " Contact information: pcileech@frizk.net                                       \n" \
        " The Memory Process File System: https://github.com/ufrisk/MemProcFS           \n" \
        " PCILeech:                       https://github.com/ufrisk/pcileech            \n" \
        " -----                                                                         \n" \
        " The recommended way to use the Memory Process File System is to specify the   \n" \
        " memory acquisition device in the -device option and possibly more options.    \n" \
        " Example 1: MemProcFS.exe -device c:\\temp\\memdump-win10x64.pmem              \n" \
        " Example 2: MemProcFS.exe -device c:\\temp\\memdump-winXPx86.dumpit -v -vv     \n" \
        " Example 3: MemProcFS.exe -device FPGA                                         \n" \
        " Example 4: MemProcFS.exe -device PMEM://c:\\temp\\winpmem_x64.sys             \n" \
        " The Memory Process File System may also be started the memory dump file name  \n" \
        " as the only option. This allows to make file extensions associated so that    \n" \
        " they may be opened by double-clicking on them. This mode allows no options.   \n" \
        " Example 4: MemProcFS.exe c:\\dumps\\memdump-win7x64.dumpit                    \n" \
        " -----                                                                         \n" \
        " Valid options:                                                                \n" \
        "   -device: select memory acquisition device or memory dump file to use.       \n" \
        "          Valid options: <memory_dump_file>, PMEM, FPGA, TOTALMELTDOWN         \n" \
        "          ---                                                                  \n" \
        "          <memory_dump_file> = memory dump file name optionally including path.\n" \
        "          PMEM = use winpmem 'winpmem_64.sys' to acquire live memory.          \n" \
        "          PMEM://c:\\path\\to\\winpmem_64.sys = path to winpmem driver.        \n" \
        "          ---                                                                  \n" \
        "          Below acquisition devices require pcileech.dll and are not built-in: \n" \
        "          TOTALMELTDOWN = use CVE-2018-1038 (vulnerable windows 7 only)        \n" \
        "          FPGA = use PCILeech PCIe DMA hardware memory acquisition device.     \n" \
        "   -v   : verbose option. Additional information is displayed in the output.   \n" \
        "          Option has no value. Example: -v                                     \n" \
        "   -vv  : extra verbose option. More detailed additional information is shown  \n" \
        "          in output. Option has no value. Example: -vv                         \n" \
        "   -vvv : super verbose option. Show all data transferred such as PCIe TLPs.   \n" \
        "          Option has no value. Example: -vvv                                   \n" \
        "   -cr3 : base address of kernel/process page table (PML4) / CR3 CPU register. \n" \
        "   -max : memory max address, valid range: 0x0 .. 0xffffffffffffffff           \n" \
        "          default: auto-detect (max supported by device / target system).      \n" \
        "   -pythonpath : specify the path to a python 3 installation for Windows.      \n" \
        "          The path given should be to the directory that contain: python.dll   \n" \
        "          Example: -pythonpath \"C:\\Program Files\\Python37\"                 \n" \
        "   -mount : drive letter to mount The Memory Process File system at.           \n" \
        "          default: M   Example: -mount Q                                       \n" \
        "   -identify : scan memory for the operating system and the kernel page table. \n" \
        "          This may help if the default auto-detect is not working.             \n" \
        "          Option has no value. Example: -identify                              \n" \
        "                                                                               \n",
        VERSION_MAJOR, VERSION_MINOR, VERSION_REVISION
    );
}

VOID VmmDll_FreeContext()
{
    if(ctxVmm) {
        VmmClose();
    }
    if(ctxMain) {
        Statistics_CallSetEnabled(FALSE);
        if(!ctxMain->cfg.fDisableLeechCoreClose) {
            LeechCore_Close();
        }
        LocalFree(ctxMain);
        ctxMain = NULL;
    }
}

_Success_(return)
BOOL VMMDLL_Initialize(_In_ DWORD argc, _In_ LPSTR argv[])
{
    ctxMain = LocalAlloc(LMEM_ZEROINIT, sizeof(VMM_MAIN_CONTEXT));
    if(!ctxMain) {
        return FALSE;
    }
    // initialize configuration
    if(!VmmDll_ConfigIntialize((DWORD)argc, argv)) {
        VmmDll_PrintHelp();
        VmmDll_FreeContext();
        return FALSE;
    }
    // ctxMain.cfg context is inintialized from here onwards - vmmprintf is working!
    if(0 == _stricmp(ctxMain->dev.szDevice, "existing")) {
        ctxMain->cfg.fDisableLeechCoreClose = TRUE;
    }
    if(!LeechCore_Open(&ctxMain->dev)) {
        vmmprintf("MemProcFS: Failed to connect to memory acquisition device.\n");
        VmmDll_FreeContext();
        return FALSE;
    }
    // ctxMain.dev context is initialized from here onwards - device functionality is working!
    if(ctxMain->cfg.fCommandIdentify) {
        // if identify option is supplied try scan for page directory base...
        VmmProcIdentify();
    }
    if(!VmmProcInitialize()) {
        vmmprintf("MOUNT: INFO: PROC file system not mounted.\n");
        VmmDll_FreeContext();
        return FALSE;
    }
    // ctxVmm context is initialized from here onwards - vmm functionality is working!
    return TRUE;
}

_Success_(return)
BOOL VMMDLL_Close()
{
    VmmDll_FreeContext();
    return TRUE;
}

//-----------------------------------------------------------------------------
// CONFIGURATION SETTINGS BELOW:
//-----------------------------------------------------------------------------

_Success_(return)
BOOL VMMDLL_ConfigGet_VmmCore(_In_ ULONG64 fOption, _Out_ PULONG64 pqwValue)
{
    switch(fOption) {
        case VMMDLL_OPT_CONFIG_IS_REFRESH_ENABLED:
            *pqwValue = ctxVmm->ThreadProcCache.fEnabled ? 1 : 0;
            break;
        case VMMDLL_OPT_CONFIG_TICK_PERIOD:
            *pqwValue = ctxVmm->ThreadProcCache.cMs_TickPeriod;
            break;
        case VMMDLL_OPT_CONFIG_READCACHE_TICKS:
            *pqwValue = ctxVmm->ThreadProcCache.cTick_Phys;
            break;
        case VMMDLL_OPT_CONFIG_TLBCACHE_TICKS:
            *pqwValue = ctxVmm->ThreadProcCache.cTick_TLB;
            break;
        case VMMDLL_OPT_CONFIG_PROCCACHE_TICKS_PARTIAL:
            *pqwValue = ctxVmm->ThreadProcCache.cTick_ProcPartial;
            break;
        case VMMDLL_OPT_CONFIG_PROCCACHE_TICKS_TOTAL:
            *pqwValue = ctxVmm->ThreadProcCache.cTick_ProcTotal;
            break;
        case VMMDLL_OPT_CONFIG_STATISTICS_FUNCTIONCALL:
            *pqwValue = Statistics_CallGetEnabled() ? 1 : 0;
            return TRUE;
        default:
            return FALSE;
    }
    return TRUE;
}

_Success_(return)
BOOL VMMDLL_ConfigGet(_In_ ULONG64 fOption, _Out_ PULONG64 pqwValue)
{
    if(!pqwValue) { return FALSE; }
    if(fOption & 0x40000000) {
        if(fOption == VMMDLL_OPT_CONFIG_VMM_VERSION_MAJOR) {
            *pqwValue = VERSION_MAJOR;
            return TRUE;
        } else if(fOption == VMMDLL_OPT_CONFIG_VMM_VERSION_MINOR) {
            *pqwValue = VERSION_MINOR;
            return TRUE;
        } else if(fOption == VMMDLL_OPT_CONFIG_VMM_VERSION_REVISION) {
            *pqwValue = VERSION_REVISION;
            return TRUE;
        }
    }
    if(!ctxVmm) { return FALSE; }
    // core options affecting only vmm.dll
    if(fOption & 0x40000000) {
        return VMMDLL_ConfigGet_VmmCore(fOption, pqwValue);
    }
    // core options affecting both vmm.dll and pcileech.dll
    if(fOption & 0x80000000) {
        switch(fOption) {
            case VMMDLL_OPT_CORE_PRINTF_ENABLE:
                *pqwValue = ctxMain->cfg.fVerboseDll ? 1 : 0;
                return TRUE;
            case VMMDLL_OPT_CORE_VERBOSE:
                *pqwValue = ctxMain->cfg.fVerbose ? 1 : 0;
                return TRUE;
            case VMMDLL_OPT_CORE_VERBOSE_EXTRA:
                *pqwValue = ctxMain->cfg.fVerboseExtra ? 1 : 0;
                return TRUE;
            case VMMDLL_OPT_CORE_VERBOSE_EXTRA_TLP:
                *pqwValue = ctxMain->cfg.fVerboseExtraTlp ? 1 : 0;
                return TRUE;
            case VMMDLL_OPT_CORE_MAX_NATIVE_ADDRESS:
                *pqwValue = ctxMain->dev.paMaxNative;
                return TRUE;
            case VMMDLL_OPT_CORE_MAX_NATIVE_IOSIZE:
                *pqwValue = ctxMain->dev.cbMaxSizeMemIo;
                return TRUE;
            case VMMDLL_OPT_CORE_SYSTEM:
                *pqwValue = ctxVmm->tpSystem;
                return TRUE;
            case VMMDLL_OPT_CORE_MEMORYMODEL:
                *pqwValue = ctxVmm->tpMemoryModel;
                return TRUE;
            default:
                return FALSE;
        }
    }
    // non-recognized option - possibly a device option to pass along to pcileech.dll
    return LeechCore_GetOption(fOption, pqwValue);
}

_Success_(return)
BOOL VMMDLL_ConfigSet_VmmCore(_In_ ULONG64 fOption, _In_ ULONG64 qwValue)
{
    switch(fOption) {
        case VMMDLL_OPT_CONFIG_TICK_PERIOD:
            ctxVmm->ThreadProcCache.cMs_TickPeriod = (DWORD)qwValue;
            break;
        case VMMDLL_OPT_CONFIG_READCACHE_TICKS:
            ctxVmm->ThreadProcCache.cTick_Phys = (DWORD)qwValue;
            break;
        case VMMDLL_OPT_CONFIG_TLBCACHE_TICKS:
            ctxVmm->ThreadProcCache.cTick_TLB = (DWORD)qwValue;
            break;
        case VMMDLL_OPT_CONFIG_PROCCACHE_TICKS_PARTIAL:
            ctxVmm->ThreadProcCache.cTick_ProcPartial = (DWORD)qwValue;
            break;
        case VMMDLL_OPT_CONFIG_PROCCACHE_TICKS_TOTAL:
            ctxVmm->ThreadProcCache.cTick_ProcTotal = (DWORD)qwValue;
            break;
        case VMMDLL_OPT_CONFIG_STATISTICS_FUNCTIONCALL:
            Statistics_CallSetEnabled(qwValue ? TRUE : FALSE);
            return TRUE;
        default:
            return FALSE;
    }
    return TRUE;
}

_Success_(return)
BOOL VMMDLL_ConfigSet(_In_ ULONG64 fOption, _In_ ULONG64 qwValue)
{
    if(!ctxVmm) { return FALSE; }
    // core options affecting only vmm.dll
    if(fOption & 0x40000000) {
        return VMMDLL_ConfigSet_VmmCore(fOption, qwValue);
    }
    // core options affecting both vmm.dll and leechcore.dll
    if(fOption & 0x80000000) {
        LeechCore_SetOption(fOption, qwValue);
        switch(fOption) {
            case VMMDLL_OPT_CORE_PRINTF_ENABLE:
                ctxMain->cfg.fVerboseDll = qwValue ? TRUE : FALSE;
                CALL_SYNCHRONIZED_IMPLEMENTATION_VMM(
                    STATISTICS_ID_NOLOG,
                    PluginManager_Notify(VMMDLL_PLUGIN_EVENT_VERBOSITYCHANGE, NULL, 0))
                return TRUE;
            case VMMDLL_OPT_CORE_VERBOSE:
                ctxMain->cfg.fVerbose = qwValue ? TRUE : FALSE;
                CALL_SYNCHRONIZED_IMPLEMENTATION_VMM(
                    STATISTICS_ID_NOLOG,
                    PluginManager_Notify(VMMDLL_PLUGIN_EVENT_VERBOSITYCHANGE, NULL, 0))
                return TRUE;
            case VMMDLL_OPT_CORE_VERBOSE_EXTRA:
                ctxMain->cfg.fVerboseExtra = qwValue ? TRUE : FALSE;
                CALL_SYNCHRONIZED_IMPLEMENTATION_VMM(
                    STATISTICS_ID_NOLOG,
                    PluginManager_Notify(VMMDLL_PLUGIN_EVENT_VERBOSITYCHANGE, NULL, 0))
                return TRUE;
            case VMMDLL_OPT_CORE_VERBOSE_EXTRA_TLP:
                ctxMain->cfg.fVerboseExtraTlp = qwValue ? TRUE : FALSE;
                CALL_SYNCHRONIZED_IMPLEMENTATION_VMM(
                    STATISTICS_ID_NOLOG,
                    PluginManager_Notify(VMMDLL_PLUGIN_EVENT_VERBOSITYCHANGE, NULL, 0))
                return TRUE;
            default:
                return FALSE;
        }
    }
    // non-recognized option - possibly a device option to pass along to memdevice.dll
    return LeechCore_SetOption(fOption, qwValue);
}

//-----------------------------------------------------------------------------
// VFS - VIRTUAL FILE SYSTEM FUNCTIONALITY BELOW:
//-----------------------------------------------------------------------------

_Success_(return)
BOOL VMMDLL_VfsList(_In_ LPCWSTR wcsPath, _Inout_ PVMMDLL_VFS_FILELIST pFileList)
{
    CALL_SYNCHRONIZED_IMPLEMENTATION_VMM(
        STATISTICS_ID_VMMDLL_VfsList,
        VmmVfs_List(wcsPath, (PHANDLE)pFileList))
}

NTSTATUS VMMDLL_VfsRead(_In_ LPCWSTR wcsFileName, _Out_ LPVOID pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ ULONG64 cbOffset)
{
    CALL_SYNCHRONIZED_IMPLEMENTATION_VMM_RETURN(
        STATISTICS_ID_VMMDLL_VfsRead,
        NTSTATUS,
        VMMDLL_STATUS_UNSUCCESSFUL,
        VmmVfs_Read(wcsFileName, pb, cb, pcbRead, cbOffset))
}

NTSTATUS VMMDLL_VfsWrite(_In_ LPCWSTR wcsFileName, _In_ LPVOID pb, _In_ DWORD cb, _Out_ PDWORD pcbWrite, _In_ ULONG64 cbOffset)
{
    CALL_SYNCHRONIZED_IMPLEMENTATION_VMM_RETURN(
        STATISTICS_ID_VMMDLL_VfsWrite,
        NTSTATUS,
        VMMDLL_STATUS_UNSUCCESSFUL,
        VmmVfs_Write(wcsFileName, pb, cb, pcbWrite, cbOffset))
}

NTSTATUS VMMDLL_UtilVfsReadFile_FromPBYTE(_In_ PBYTE pbFile, _In_ ULONG64 cbFile, _Out_ LPVOID pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ ULONG64 cbOffset)
{
    return Util_VfsReadFile_FromPBYTE(pbFile, cbFile, pb, cb, pcbRead, cbOffset);
}

NTSTATUS VMMDLL_UtilVfsReadFile_FromQWORD(_In_ ULONG64 qwValue, _Out_ LPVOID pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ ULONG64 cbOffset, _In_ BOOL fPrefix)
{
    return Util_VfsReadFile_FromQWORD(qwValue, pb, cb, pcbRead, cbOffset, fPrefix);
}

NTSTATUS VMMDLL_UtilVfsReadFile_FromDWORD(_In_ DWORD dwValue, _Out_ LPVOID pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ ULONG64 cbOffset, _In_ BOOL fPrefix)
{
    return Util_VfsReadFile_FromDWORD(dwValue, pb, cb, pcbRead, cbOffset, fPrefix);
}

NTSTATUS VMMDLL_UtilVfsReadFile_FromBOOL(_In_ BOOL fValue, _Out_ LPVOID pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ ULONG64 cbOffset)
{
    return Util_VfsReadFile_FromBOOL(fValue, pb, cb, pcbRead, cbOffset);
}

NTSTATUS VMMDLL_UtilVfsWriteFile_BOOL(_Inout_ PBOOL pfTarget, _In_ LPVOID pb, _In_ DWORD cb, _Out_ PDWORD pcbWrite, _In_ ULONG64 cbOffset)
{
    return Util_VfsWriteFile_BOOL(pfTarget, pb, cb, pcbWrite, cbOffset);
}

NTSTATUS VMMDLL_UtilVfsWriteFile_DWORD(_Inout_ PDWORD pdwTarget, _In_ LPVOID pb, _In_ DWORD cb, _Out_ PDWORD pcbWrite, _In_ ULONG64 cbOffset, _In_ DWORD dwMinAllow)
{
    return Util_VfsWriteFile_DWORD(pdwTarget, pb, cb, pcbWrite, cbOffset, dwMinAllow);
}



//-----------------------------------------------------------------------------
// PLUGIN MANAGER FUNCTIONALITY BELOW:
//-----------------------------------------------------------------------------

_Success_(return)
BOOL VMMDLL_VfsInitializePlugins()
{
    CALL_SYNCHRONIZED_IMPLEMENTATION_VMM(
        STATISTICS_ID_VMMDLL_VfsInitializePlugins,
        PluginManager_Initialize())
}



//-----------------------------------------------------------------------------
// REFRESH FUNCTIONALITY BELOW:
//-----------------------------------------------------------------------------

_Success_(return)
BOOL VMMDLL_Refresh_Impl(_In_ DWORD dwReserved)
{
    ULONG64 paMax;
    // enforce global lock even if 'multi thread' is enabled
    // we wish to avoid parallel process refreshes ...
    EnterCriticalSection(&ctxVmm->MasterLock);
    VmmCacheClear(VMM_CACHE_TAG_PHYS);
    VmmCacheClear(VMM_CACHE_TAG_TLB);
    VmmProc_RefreshProcesses(TRUE);
    // update max physical address (if volatile).
    if(ctxMain->dev.fVolatileMaxAddress) {
        if(LeechCore_GetOption(LEECHCORE_OPT_MEMORYINFO_ADDR_MAX, &paMax) && (paMax > 0x01000000)) {
            ctxMain->dev.paMax = paMax;
        }
    }
    LeaveCriticalSection(&ctxVmm->MasterLock);
    return TRUE;
}

_Success_(return)
BOOL VMMDLL_Refresh(_In_ DWORD dwReserved)
{
    CALL_SYNCHRONIZED_IMPLEMENTATION_VMM(
        STATISTICS_ID_VMMDLL_Refresh,
        VMMDLL_Refresh_Impl(dwReserved))
}



//-----------------------------------------------------------------------------
// VMM CORE FUNCTIONALITY BELOW:
//-----------------------------------------------------------------------------

DWORD VMMDLL_MemReadScatter_Impl(_In_ DWORD dwPID, _Inout_ PPMEM_IO_SCATTER_HEADER ppMEMs, _In_ DWORD cpMEMs, _In_ DWORD flags)
{
    DWORD i, cMEMs;
    PVMM_PROCESS pObProcess = NULL;
    if(!ctxVmm) { return 0; }
    VmmLockAcquire();
    if(dwPID == -1) {
        VmmReadScatterPhysical(ppMEMs, cpMEMs, flags);
    } else {
        pObProcess = VmmProcessGet(dwPID);
        if(!pObProcess) {
            VmmLockRelease();
            return FALSE;
        }
        VmmReadScatterVirtual(pObProcess, ppMEMs, cpMEMs, flags);
        VmmOb_DECREF(pObProcess);
    }
    for(i = 0, cMEMs = 0; i < cpMEMs; i++) {
        if(ppMEMs[i]->cb == ppMEMs[i]->cbMax) {
            cMEMs++;
        }
    }
    VmmLockRelease();
    return cMEMs;
}

DWORD VMMDLL_MemReadScatter(_In_ DWORD dwPID, _Inout_ PPMEM_IO_SCATTER_HEADER ppMEMs, _In_ DWORD cpMEMs, _In_ DWORD flags)
{
    CALL_SYNCHRONIZED_IMPLEMENTATION_VMM_RETURN(
        STATISTICS_ID_VMMDLL_MemReadScatter,
        DWORD,
        0,
        VMMDLL_MemReadScatter_Impl(dwPID, ppMEMs, cpMEMs, flags))
}

_Success_(return)
BOOL VMMDLL_MemReadEx_Impl(_In_ DWORD dwPID, _In_ ULONG64 qwVA, _Out_ PBYTE pb, _In_ DWORD cb, _Out_opt_ PDWORD pcbReadOpt, _In_ ULONG64 flags)
{
    PVMM_PROCESS pObProcess = NULL;
    if(dwPID != -1) {
        pObProcess = VmmProcessGet(dwPID);
        if(!pObProcess) { return FALSE; }
    }
    VmmReadEx(pObProcess, qwVA, pb, cb, pcbReadOpt, flags);
    VmmOb_DECREF(pObProcess);
    return TRUE;
}

_Success_(return)
BOOL VMMDLL_MemReadEx(_In_ DWORD dwPID, _In_ ULONG64 qwVA, _Out_ PBYTE pb, _In_ DWORD cb, _Out_opt_ PDWORD pcbReadOpt, _In_ ULONG64 flags)
{
    CALL_SYNCHRONIZED_IMPLEMENTATION_VMM(
        STATISTICS_ID_VMMDLL_MemReadEx,
        VMMDLL_MemReadEx_Impl(dwPID, qwVA, pb, cb, pcbReadOpt, flags))
}

_Success_(return)
BOOL VMMDLL_MemRead(_In_ DWORD dwPID, _In_ ULONG64 qwVA, _Out_ PBYTE pb, _In_ DWORD cb)
{
    DWORD dwRead;
    return VMMDLL_MemReadEx(dwPID, qwVA, pb, cb, &dwRead, 0) && (dwRead == cb);
}

_Success_(return)
BOOL VMMDLL_MemReadPage(_In_ DWORD dwPID, _In_ ULONG64 qwVA, _Inout_bytecount_(4096) PBYTE pbPage)
{
    DWORD dwRead;
    return VMMDLL_MemReadEx(dwPID, qwVA, pbPage, 4096, &dwRead, 0) && (dwRead == 4096);
}

_Success_(return)
BOOL VMMDLL_MemPrefetchPages_Impl(_In_ DWORD dwPID, _In_reads_(cPrefetchAddresses) PULONG64 pPrefetchAddresses, _In_ DWORD cPrefetchAddresses)
{
    DWORD i;
    BOOL result = FALSE;
    PVMM_PROCESS pObProcess = NULL;
    PVMMOB_DATASET pObPrefetchAddresses = NULL;
    if(dwPID != (DWORD)-1) {
        pObProcess = VmmProcessGet(dwPID);
        if(!pObProcess) { goto fail; }
    }
    pObPrefetchAddresses = VmmObDataSet_Alloc(TRUE);
    if(!pObPrefetchAddresses) { goto fail; }
    for(i = 0; i < cPrefetchAddresses; i++) {
        VmmObDataSet_Put(pObPrefetchAddresses, pPrefetchAddresses[i] & ~0xfff);
    }
    VmmCachePrefetchPages(pObProcess, pObPrefetchAddresses);
    result = TRUE;
fail:
    VmmOb_DECREF(pObPrefetchAddresses);
    VmmOb_DECREF(pObProcess);
    return result;
}

_Success_(return)
BOOL VMMDLL_MemPrefetchPages(_In_ DWORD dwPID, _In_reads_(cPrefetchAddresses) PULONG64 pPrefetchAddresses, _In_ DWORD cPrefetchAddresses)
{
    CALL_SYNCHRONIZED_IMPLEMENTATION_VMM(
        STATISTICS_ID_VMMDLL_MemPrefetchPages,
        VMMDLL_MemPrefetchPages_Impl(dwPID, pPrefetchAddresses, cPrefetchAddresses))
}

_Success_(return)
BOOL VMMDLL_MemWrite_Impl(_In_ DWORD dwPID, _In_ ULONG64 qwVA, _In_ PBYTE pb, _In_ DWORD cb)
{
    BOOL result;
    PVMM_PROCESS pObProcess = NULL;
    if(dwPID != -1) {
        pObProcess = VmmProcessGet(dwPID);
        if(!pObProcess) { return FALSE; }
    }
    result = VmmWrite(pObProcess, qwVA, pb, cb);
    VmmOb_DECREF(pObProcess);
    return result;
}

_Success_(return)
BOOL VMMDLL_MemWrite(_In_ DWORD dwPID, _In_ ULONG64 qwVA, _In_ PBYTE pb, _In_ DWORD cb)
{
    CALL_SYNCHRONIZED_IMPLEMENTATION_VMM(
        STATISTICS_ID_VMMDLL_MemWrite,
        VMMDLL_MemWrite_Impl(dwPID, qwVA, pb, cb))
}

_Success_(return)
BOOL VMMDLL_MemVirt2Phys_Impl(_In_ DWORD dwPID, _In_ ULONG64 qwVA, _Out_ PULONG64 pqwPA)
{
    BOOL result;
    PVMM_PROCESS pObProcess = VmmProcessGet(dwPID);
    if(!pObProcess) { return FALSE; }
    result = VmmVirt2Phys(pObProcess, qwVA, pqwPA);
    VmmOb_DECREF(pObProcess);
    return result;
}

_Success_(return)
BOOL VMMDLL_MemVirt2Phys(_In_ DWORD dwPID, _In_ ULONG64 qwVA, _Out_ PULONG64 pqwPA)
{
    CALL_SYNCHRONIZED_IMPLEMENTATION_VMM(
        STATISTICS_ID_VMMDLL_MemVirt2Phys,
        VMMDLL_MemVirt2Phys_Impl(dwPID, qwVA, pqwPA))
}

//-----------------------------------------------------------------------------
// VMM PROCESS FUNCTIONALITY BELOW:
//-----------------------------------------------------------------------------

_Success_(return)
BOOL VMMDLL_ProcessGetMemoryMap_Impl(_In_ DWORD dwPID, _Out_opt_ PVMMDLL_MEMMAP_ENTRY pMemMapEntries, _Inout_ PULONG64 pcMemMapEntries, _In_ BOOL fIdentifyModules)
{
    PVMM_PROCESS pObProcess = NULL;
    PVMMOB_MEMMAP pObMap = NULL;
    pObProcess = VmmProcessGet(dwPID);
    if(!pObProcess) { return FALSE; }
    if(!VmmMemMapGetEntries(pObProcess, fIdentifyModules ? VMM_MEMMAP_FLAG_ALL : 0, &pObMap)) { goto fail; }
    if(!pMemMapEntries) {
        *pcMemMapEntries = pObMap->cMap;
    } else {
        if(!pObMap->cMap || (*pcMemMapEntries < pObMap->cMap)) { goto fail; }
        memcpy(pMemMapEntries, pObMap->pMap, sizeof(VMMDLL_MEMMAP_ENTRY) * pObMap->cMap);
        *pcMemMapEntries = pObMap->cMap;
    }
    VmmOb_DECREF(pObMap);
    VmmOb_DECREF(pObProcess);
    return TRUE;
fail:
    VmmOb_DECREF(pObMap);
    VmmOb_DECREF(pObProcess);
    return FALSE;
}

_Success_(return)
BOOL VMMDLL_ProcessGetMemoryMap(_In_ DWORD dwPID, _Out_opt_ PVMMDLL_MEMMAP_ENTRY pMemMapEntries, _Inout_ PULONG64 pcMemMapEntries, _In_ BOOL fIdentifyModules)
{
    CALL_SYNCHRONIZED_IMPLEMENTATION_VMM(
        STATISTICS_ID_VMMDLL_ProcessGetMemoryMap,
        VMMDLL_ProcessGetMemoryMap_Impl(dwPID, pMemMapEntries, pcMemMapEntries, fIdentifyModules))
}

_Success_(return)
BOOL VMMDLL_ProcessGetMemoryMapEntry_Impl(_In_ DWORD dwPID, _Out_ PVMMDLL_MEMMAP_ENTRY pMemMapEntry, _In_ ULONG64 va, _In_ BOOL fIdentifyModules)
{
    PVMM_PROCESS pObProcess = NULL;
    DWORD i;
    PVMMOB_MEMMAP pObMap = NULL;
    PVMM_MEMMAP_ENTRY pe;
    pObProcess = VmmProcessGet(dwPID);
    if(!pObProcess) { return FALSE; }
    if(!VmmMemMapGetEntries(pObProcess, fIdentifyModules ? VMM_MEMMAP_FLAG_ALL : 0, &pObMap)) {goto fail; }
    for(i = 0; i < pObMap->cMap; i++) {
        pe = pObMap->pMap + i;
        if((pe->AddrBase >= va) && (va <= pe->AddrBase + (pe->cPages << 12))) {
            memcpy(pMemMapEntry, pe, sizeof(VMM_MEMMAP_ENTRY));
            VmmOb_DECREF(pObMap);
            VmmOb_DECREF(pObProcess);
            return TRUE;
        }
    }
fail:
    VmmOb_DECREF(pObMap);
    VmmOb_DECREF(pObProcess);
    return FALSE;
}

_Success_(return)
BOOL VMMDLL_ProcessGetMemoryMapEntry(_In_ DWORD dwPID, _Out_ PVMMDLL_MEMMAP_ENTRY pMemMapEntry, _In_ ULONG64 va, _In_ BOOL fIdentifyModules)
{
    CALL_SYNCHRONIZED_IMPLEMENTATION_VMM(
        STATISTICS_ID_VMMDLL_ProcessGetMemoryMapEntry,
        VMMDLL_ProcessGetMemoryMapEntry_Impl(dwPID, pMemMapEntry, va, fIdentifyModules))
}

_Success_(return)
BOOL VMMDLL_ProcessGetModuleMap_Impl(_In_ DWORD dwPID, _Out_writes_opt_(*pcModuleEntries) PVMMDLL_MODULEMAP_ENTRY pModuleEntries, _Inout_ PULONG64 pcModuleEntries)
{
    ULONG64 i;
    PVMM_PROCESS pObProcess = NULL;
    PVMMOB_MODULEMAP pObModuleMap;
    if(!pcModuleEntries) { return FALSE; }
    pObProcess = VmmProcessGet(dwPID);
    if(!pObProcess) { return FALSE; }
    if(VmmProc_ModuleMapGet(pObProcess, &pObModuleMap)) {
        if(!pModuleEntries) {
            *pcModuleEntries = pObModuleMap->cMap;
        } else {
            if(!pObModuleMap->pMap || (*pcModuleEntries < pObModuleMap->cMap)) {
                VmmOb_DECREF(pObModuleMap);
                VmmOb_DECREF(pObProcess);
                return FALSE;
            }
            for(i = 0; i < pObModuleMap->cMap; i++) {
                memcpy(pModuleEntries + i, pObModuleMap->pMap + i, sizeof(VMMDLL_MODULEMAP_ENTRY));
            }
            *pcModuleEntries = pObModuleMap->cMap;
        }
        VmmOb_DECREF(pObModuleMap);
    } else {
        *pcModuleEntries = 0;
    }
    VmmOb_DECREF(pObProcess);
    return TRUE;
}

_Success_(return)
BOOL VMMDLL_ProcessGetModuleMap(_In_ DWORD dwPID, _Out_opt_ PVMMDLL_MODULEMAP_ENTRY pModuleEntries, _Inout_ PULONG64 pcModuleEntries)
{
    CALL_SYNCHRONIZED_IMPLEMENTATION_VMM(
        STATISTICS_ID_VMMDLL_ProcessGetModuleMap,
        VMMDLL_ProcessGetModuleMap_Impl(dwPID, pModuleEntries, pcModuleEntries))
}

_Success_(return)
BOOL VMMDLL_ProcessGetModuleFromName_Impl(_In_ DWORD dwPID, _In_ LPSTR szModuleName, _Out_ PVMMDLL_MODULEMAP_ENTRY pModuleEntry)
{
    BOOL result;
    ULONG64 i, cModuleEntries = 0;
    PVMMDLL_MODULEMAP_ENTRY pModuleEntries = NULL;
    result = VMMDLL_ProcessGetModuleMap_Impl(dwPID, NULL, &cModuleEntries);
    if(!result || !cModuleEntries) { return FALSE; }
    pModuleEntries = (PVMMDLL_MODULEMAP_ENTRY)LocalAlloc(0, sizeof(VMMDLL_MODULEMAP_ENTRY) * cModuleEntries);
    if(!pModuleEntries) { return FALSE; }
    result = VMMDLL_ProcessGetModuleMap_Impl(dwPID, pModuleEntries, &cModuleEntries);
    if(result && cModuleEntries) {
        for(i = 0; i < cModuleEntries; i++) {
            if(!_strnicmp(szModuleName, pModuleEntries[i].szName, 31)) {
                memcpy(pModuleEntry, pModuleEntries + i, sizeof(VMMDLL_MODULEMAP_ENTRY));
                LocalFree(pModuleEntries);
                return TRUE;
            }
        }
    }
    LocalFree(pModuleEntries);
    return FALSE;
}

_Success_(return)
BOOL VMMDLL_ProcessGetModuleFromName(_In_ DWORD dwPID, _In_ LPSTR szModuleName, _Out_ PVMMDLL_MODULEMAP_ENTRY pModuleEntry)
{
    CALL_SYNCHRONIZED_IMPLEMENTATION_VMM(
        STATISTICS_ID_VMMDLL_ProcessGetModuleFromName,
        VMMDLL_ProcessGetModuleFromName_Impl(dwPID, szModuleName, pModuleEntry))
}

_Success_(return)
BOOL VMMDLL_PidList_Impl(_Out_opt_ PDWORD pPIDs, _Inout_ PULONG64 pcPIDs)
{
    VmmProcessListPIDs(pPIDs, pcPIDs);
    return TRUE;
}

_Success_(return)
BOOL VMMDLL_PidList(_Out_opt_ PDWORD pPIDs, _Inout_ PULONG64 pcPIDs)
{
    CALL_SYNCHRONIZED_IMPLEMENTATION_VMM(
        STATISTICS_ID_VMMDLL_PidList,
        VMMDLL_PidList_Impl(pPIDs, pcPIDs))
}

_Success_(return)
BOOL VMMDLL_PidGetFromName_Impl(_In_ LPSTR szProcName, _Out_ PDWORD pdwPID)
{
    PVMM_PROCESS pObProcess = NULL;
    while((pObProcess = VmmProcessGetNext(pObProcess))) {
        if(_strnicmp(szProcName, pObProcess->szName, 15)) { continue; }
        if(pObProcess->dwState) { continue; }
        *pdwPID = pObProcess->dwPID;
        VmmOb_DECREF(pObProcess);
        return TRUE;
    }
    return FALSE;
}

_Success_(return)
BOOL VMMDLL_PidGetFromName(_In_ LPSTR szProcName, _Out_ PDWORD pdwPID)
{
    CALL_SYNCHRONIZED_IMPLEMENTATION_VMM(
        STATISTICS_ID_VMMDLL_PidGetFromName,
        VMMDLL_PidGetFromName_Impl(szProcName, pdwPID))
}

_Success_(return)
BOOL VMMDLL_ProcessGetInformation_Impl(_In_ DWORD dwPID, _Inout_opt_ PVMMDLL_PROCESS_INFORMATION pInfo, _In_ PSIZE_T pcbProcessInfo)
{
    PVMM_PROCESS pObProcess = NULL;
    if(!pcbProcessInfo) { return FALSE; }
    if(!pInfo) {
        *pcbProcessInfo = sizeof(VMMDLL_PROCESS_INFORMATION);
        return TRUE;
    }
    if(*pcbProcessInfo < sizeof(VMMDLL_PROCESS_INFORMATION)) { return FALSE; }
    if(pInfo->magic != VMMDLL_PROCESS_INFORMATION_MAGIC) { return FALSE; }
    if(pInfo->wVersion != VMMDLL_PROCESS_INFORMATION_VERSION) { return FALSE; }
    if(!(pObProcess = VmmProcessGet(dwPID))) { return FALSE; }
    ZeroMemory(pInfo, sizeof(VMMDLL_PROCESS_INFORMATION_MAGIC));
    // set general parameters
    pInfo->wVersion = VMMDLL_PROCESS_INFORMATION_VERSION;
    pInfo->wSize = sizeof(VMMDLL_PROCESS_INFORMATION);
    pInfo->tpMemoryModel = ctxVmm->tpMemoryModel;
    pInfo->tpSystem = ctxVmm->tpSystem;
    pInfo->fUserOnly = pObProcess->fUserOnly;
    pInfo->dwPID = dwPID;
    pInfo->dwState = pObProcess->dwState;
    pInfo->paDTB = pObProcess->paDTB;
    pInfo->paDTB_UserOpt = pObProcess->paDTB_UserOpt;
    memcpy(pInfo->szName, pObProcess->szName, sizeof(pInfo->szName));
    // set operating system specific parameters
    switch(ctxVmm->tpSystem) {
        case VMM_SYSTEM_WINDOWS_X64:
            pInfo->os.win.fWow64 = pObProcess->os.win.fWow64;
            pInfo->os.win.vaENTRY = pObProcess->os.win.vaENTRY;
            pInfo->os.win.vaEPROCESS = pObProcess->os.win.vaEPROCESS;
            pInfo->os.win.vaPEB = pObProcess->os.win.vaPEB;
            pInfo->os.win.vaPEB32 = pObProcess->os.win.vaPEB32;
            break;
        case VMM_SYSTEM_WINDOWS_X86:
            pInfo->os.win.vaENTRY = pObProcess->os.win.vaENTRY;
            pInfo->os.win.vaEPROCESS = pObProcess->os.win.vaEPROCESS;
            pInfo->os.win.vaPEB = pObProcess->os.win.vaPEB;
            break;
    }
    VmmOb_DECREF(pObProcess);
    return TRUE;
}

_Success_(return)
BOOL VMMDLL_ProcessGetInformation(_In_ DWORD dwPID, _Inout_opt_ PVMMDLL_PROCESS_INFORMATION pProcessInformation, _In_ PSIZE_T pcbProcessInformation)
{
    CALL_SYNCHRONIZED_IMPLEMENTATION_VMM(
        STATISTICS_ID_VMMDLL_ProcessGetInformation,
        VMMDLL_ProcessGetInformation_Impl(dwPID, pProcessInformation, pcbProcessInformation))
}

_Success_(return)
BOOL VMMDLL_ProcessGet_Directories_Sections_IAT_EAT_Impl(
    _In_ DWORD dwPID,
    _In_ LPSTR szModule,
    _In_ DWORD cData,
    _Out_ PDWORD pcData,
    _Out_writes_opt_(16) PIMAGE_DATA_DIRECTORY pDataDirectory,
    _Out_opt_ PIMAGE_SECTION_HEADER pSections,
    _Out_opt_ PVMMDLL_EAT_ENTRY pEAT,
    _Out_opt_ PVOID pIAT,
    BOOL _In_ fDataDirectory,
    BOOL _In_ fSections,
    BOOL _In_ fEAT,
    BOOL _In_ fIAT
)
{
    DWORD i;
    PVMMOB_MODULEMAP pObModuleMap = NULL;
    PVMM_MODULEMAP_ENTRY pModule = NULL;
    PVMM_PROCESS pObProcess = NULL;
    pObProcess = VmmProcessGet(dwPID);
    if(!pObProcess) { goto fail; }
    // fetch requested module
    if(!VmmProc_ModuleMapGet(pObProcess, &pObModuleMap)) { goto fail; }
    for(i = 0; i < pObModuleMap->cMap; i++) {
        if(!_stricmp(pObModuleMap->pMap[i].szName, szModule)) {
            pModule = pObModuleMap->pMap + i;
        }
    }
    if(!pModule) { goto fail; }
    // data directories
    if(fDataDirectory) {
        if(!pDataDirectory) { *pcData = 16; goto success; }
        if(cData < 16) { goto fail; }
        VmmWin_PE_DIRECTORY_DisplayBuffer(pObProcess, pModule, NULL, 0, NULL, pDataDirectory);
        *pcData = 16;
        goto success;
    }
    // sections
    if(fSections) {
        i = PE_SectionGetNumberOf(pObProcess, pModule->BaseAddress);
        if(!pSections) { *pcData = i; goto success; }
        if(cData < i) { goto fail; }
        VmmWin_PE_SECTION_DisplayBuffer(pObProcess, pModule, NULL, 0, NULL, &cData, pSections);
        *pcData = cData;
        goto success;
    }
    // export address table (EAT)
    if(fEAT) {
        i = PE_EatGetNumberOf(pObProcess, pModule->BaseAddress);
        if(!pEAT) { *pcData = i; goto success; }
        if(cData < i) { goto fail; }
        VmmWin_PE_LoadEAT_DisplayBuffer(pObProcess, pModule, (PVMMPROC_WINDOWS_EAT_ENTRY)pEAT, cData, &cData);
        *pcData = cData;
        goto success;
    }
    // import address table (IAT)
    if(fIAT) {
        i = PE_IatGetNumberOf(pObProcess, pModule->BaseAddress);
        if(!pIAT) { *pcData = i; goto success; }
        if(cData < i) { goto fail; }
        VmmWin_PE_LoadIAT_DisplayBuffer(pObProcess, pModule, (PVMMWIN_IAT_ENTRY)pIAT, cData, &cData);
        *pcData = cData;
        goto success;
    }
fail:
    VmmOb_DECREF(pObModuleMap);
    VmmOb_DECREF(pObProcess);
    return FALSE;
success:
    VmmOb_DECREF(pObModuleMap);
    VmmOb_DECREF(pObProcess);
    return TRUE;
}

_Success_(return)
BOOL VMMDLL_ProcessGetDirectories(_In_ DWORD dwPID, _In_ LPSTR szModule, _Out_writes_(16) PIMAGE_DATA_DIRECTORY pData, _In_ DWORD cData, _Out_ PDWORD pcData)
{
    CALL_SYNCHRONIZED_IMPLEMENTATION_VMM(
        STATISTICS_ID_VMMDLL_ProcessGetDirectories,
        VMMDLL_ProcessGet_Directories_Sections_IAT_EAT_Impl(dwPID, szModule, cData, pcData, pData, NULL, NULL, NULL, TRUE, FALSE, FALSE, FALSE))
}

_Success_(return)
BOOL VMMDLL_ProcessGetSections(_In_ DWORD dwPID, _In_ LPSTR szModule, _Out_opt_ PIMAGE_SECTION_HEADER pData, _In_ DWORD cData, _Out_ PDWORD pcData)
{
    CALL_SYNCHRONIZED_IMPLEMENTATION_VMM(
        STATISTICS_ID_VMMDLL_ProcessGetSections,
        VMMDLL_ProcessGet_Directories_Sections_IAT_EAT_Impl(dwPID, szModule, cData, pcData, NULL, pData, NULL, NULL, FALSE, TRUE, FALSE, FALSE))
}

_Success_(return)
BOOL VMMDLL_ProcessGetEAT(_In_ DWORD dwPID, _In_ LPSTR szModule, _Out_opt_ PVMMDLL_EAT_ENTRY pData, _In_ DWORD cData, _Out_ PDWORD pcData)
{
    CALL_SYNCHRONIZED_IMPLEMENTATION_VMM(
        STATISTICS_ID_VMMDLL_ProcessGetEAT,
        VMMDLL_ProcessGet_Directories_Sections_IAT_EAT_Impl(dwPID, szModule, cData, pcData, NULL, NULL, pData, NULL, FALSE, FALSE, TRUE, FALSE))
}

_Success_(return)
BOOL VMMDLL_ProcessGetIAT(_In_ DWORD dwPID, _In_ LPSTR szModule, _Out_opt_ PVMMDLL_IAT_ENTRY pData, _In_ DWORD cData, _Out_ PDWORD pcData)
{
    CALL_SYNCHRONIZED_IMPLEMENTATION_VMM(
        STATISTICS_ID_VMMDLL_ProcessGetIAT,
        VMMDLL_ProcessGet_Directories_Sections_IAT_EAT_Impl(dwPID, szModule, cData, pcData, NULL, NULL, NULL, pData, FALSE, FALSE, FALSE, TRUE))
}

ULONG64 VMMDLL_ProcessGetProcAddress_Impl(_In_ DWORD dwPID, _In_ LPSTR szModuleName, _In_ LPSTR szFunctionName)
{
    QWORD vaFn = 0;
    VMMDLL_MODULEMAP_ENTRY oModuleEntry = { 0 };
    PVMM_PROCESS pObProcess = NULL;
    pObProcess = VmmProcessGet(dwPID);
    if(!pObProcess) { return 0; }
    if(VMMDLL_ProcessGetModuleFromName_Impl(dwPID, szModuleName, &oModuleEntry)) {
        vaFn = PE_GetProcAddress(pObProcess, oModuleEntry.BaseAddress, szFunctionName);
    }
    VmmOb_DECREF(pObProcess);
    return vaFn;
}

ULONG64 VMMDLL_ProcessGetProcAddress(_In_ DWORD dwPID, _In_ LPSTR szModuleName, _In_ LPSTR szFunctionName)
{
    CALL_SYNCHRONIZED_IMPLEMENTATION_VMM_RETURN(
        STATISTICS_ID_VMMDLL_ProcessGetIAT,
        ULONG64,
        0,
        VMMDLL_ProcessGetProcAddress_Impl(dwPID, szModuleName, szFunctionName))
}

ULONG64 VMMDLL_ProcessGetModuleBase_Impl(_In_ DWORD dwPID, _In_ LPSTR szModuleName)
{
    QWORD vaModuleBase = 0;
    VMMDLL_MODULEMAP_ENTRY oModuleEntry = { 0 };
    PVMM_PROCESS pObProcess = NULL;
    pObProcess = VmmProcessGet(dwPID);
    if(!pObProcess) { return 0; }
    if(VMMDLL_ProcessGetModuleFromName_Impl(dwPID, szModuleName, &oModuleEntry)) {
        vaModuleBase = oModuleEntry.BaseAddress;
    }
    VmmOb_DECREF(pObProcess);
    return vaModuleBase;
}

ULONG64 VMMDLL_ProcessGetModuleBase(_In_ DWORD dwPID, _In_ LPSTR szModuleName)
{
    CALL_SYNCHRONIZED_IMPLEMENTATION_VMM_RETURN(
        STATISTICS_ID_VMMDLL_ProcessGetModuleBase,
        ULONG64,
        0,
        VMMDLL_ProcessGetModuleBase_Impl(dwPID, szModuleName))
}

_Success_(return)
BOOL VMMDLL_WinGetThunkInfoEAT_Impl(_In_ DWORD dwPID, _In_ LPSTR szModuleName, _In_ LPSTR szExportFunctionName, _Out_ PVMMDLL_WIN_THUNKINFO_EAT pThunkInfoEAT)
{
    BOOL result;
    VMMDLL_MODULEMAP_ENTRY oModuleEntry = { 0 };
    PVMM_PROCESS pObProcess = NULL;
    pObProcess = VmmProcessGet(dwPID);
    if(!pObProcess) { return 0; }
    if(VMMDLL_ProcessGetModuleFromName_Impl(dwPID, szModuleName, &oModuleEntry)) {
        result = PE_GetThunkInfoEAT(pObProcess, oModuleEntry.BaseAddress, szExportFunctionName, (PPE_THUNKINFO_EAT)pThunkInfoEAT);
    }
    VmmOb_DECREF(pObProcess);
    return result;
}

_Success_(return)
BOOL VMMDLL_WinGetThunkInfoEAT(_In_ DWORD dwPID, _In_ LPSTR szModuleName, _In_ LPSTR szExportFunctionName, _Out_ PVMMDLL_WIN_THUNKINFO_EAT pThunkInfoEAT)
{
    CALL_SYNCHRONIZED_IMPLEMENTATION_VMM(
        STATISTICS_ID_VMMDLL_WinGetThunkEAT,
        VMMDLL_WinGetThunkInfoEAT_Impl(dwPID, szModuleName, szExportFunctionName, pThunkInfoEAT))
}

_Success_(return)
BOOL VMMDLL_WinGetThunkInfoIAT_Impl(_In_ DWORD dwPID, _In_ LPSTR szModuleName, _In_ LPSTR szImportModuleName, _In_ LPSTR szImportFunctionName, _Out_ PVMMDLL_WIN_THUNKINFO_IAT pThunkInfoIAT)
{
    BOOL result = FALSE;
    VMMDLL_MODULEMAP_ENTRY oModuleEntry = { 0 };
    PVMM_PROCESS pObProcess = NULL;
    if(sizeof(VMMDLL_WIN_THUNKINFO_IAT) != sizeof(PE_THUNKINFO_IAT)) { return FALSE; }
    pObProcess = VmmProcessGet(dwPID);
    if(!pObProcess) { return 0; }
    if(VMMDLL_ProcessGetModuleFromName_Impl(dwPID, szModuleName, &oModuleEntry)) {
        result = PE_GetThunkInfoIAT(pObProcess, oModuleEntry.BaseAddress, szImportModuleName, szImportFunctionName, (PPE_THUNKINFO_IAT)pThunkInfoIAT);
    }
    VmmOb_DECREF(pObProcess);
    return result;
}

_Success_(return)
BOOL VMMDLL_WinGetThunkInfoIAT(_In_ DWORD dwPID, _In_ LPSTR szModuleName, _In_ LPSTR szImportModuleName, _In_ LPSTR szImportFunctionName, _Out_ PVMMDLL_WIN_THUNKINFO_IAT pThunkInfoIAT)
{
    CALL_SYNCHRONIZED_IMPLEMENTATION_VMM(
        STATISTICS_ID_VMMDLL_WinGetThunkIAT,
        VMMDLL_WinGetThunkInfoIAT_Impl(dwPID, szModuleName, szImportModuleName, szImportFunctionName, pThunkInfoIAT))
}

_Success_(return)
BOOL VMMDLL_WinMemCompression_DecompressPage(_In_ ULONG64 vaCompressedData, _In_opt_ DWORD cbCompressedData, _Out_writes_(4096) PBYTE pbDecompressedPage, _Out_opt_ PDWORD pcbCompressedData)
{
    CALL_SYNCHRONIZED_IMPLEMENTATION_VMM(
        STATISTICS_ID_VMMDLL_WinMemCompression_DecompressPage,
        MmX64WinPaged_MemCompression_DecompressPage(vaCompressedData, cbCompressedData, pbDecompressedPage, pcbCompressedData))
}

_Success_(return)
BOOL VMMDLL_UtilFillHexAscii(_In_ PBYTE pb, _In_ DWORD cb, _In_ DWORD cbInitialOffset, _Inout_opt_ LPSTR sz, _Out_ PDWORD pcsz)
{
    return Util_FillHexAscii(pb, cb, cbInitialOffset, sz, pcsz);
}
