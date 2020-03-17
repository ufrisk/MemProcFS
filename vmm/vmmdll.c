// vmmdll.c : implementation of core dynamic link library (dll) functionality
// of the virtual memory manager (VMM) for The Memory Process File System.
//
// (c) Ulf Frisk, 2018-2020
// Author: Ulf Frisk, pcileech@frizk.net
//

#include "vmmdll.h"
#include "pluginmanager.h"
#include "util.h"
#include "pdb.h"
#include "pe.h"
#include "statistics.h"
#include "version.h"
#include "vmm.h"
#include "vmmproc.h"
#include "vmmwin.h"
#include "vmmwinreg.h"
#include "vmmwintcpip.h"
#include "mm_pfn.h"

// ----------------------------------------------------------------------------
// Synchronization macro below. The VMM isn't thread safe so it's important to
// serialize access to it over the VMM MasterLock. This master lock is shared
// with internal VMM housekeeping functionality.
// ----------------------------------------------------------------------------

#define CALL_IMPLEMENTATION_VMM(id, fn) {                               \
    QWORD tm;                                                           \
    BOOL result;                                                        \
    if(!ctxVmm) { return FALSE; }                                       \
    tm = Statistics_CallStart();                                        \
    result = fn;                                                        \
    Statistics_CallEnd(id, tm);                                         \
    return result;                                                      \
}

#define CALL_IMPLEMENTATION_VMM_RETURN(id, RetTp, RetValFail, fn) {     \
    QWORD tm;                                                           \
    RetTp retVal;                                                       \
    if(!ctxVmm) { return ((RetTp)RetValFail); } /* UNSUCCESSFUL */      \
    tm = Statistics_CallStart();                                        \
    retVal = fn;                                                        \
    Statistics_CallEnd(id, tm);                                         \
    return retVal;                                                      \
}

//-----------------------------------------------------------------------------
// INITIALIZATION FUNCTIONALITY BELOW:
//-----------------------------------------------------------------------------

_Success_(return)
BOOL VmmDll_ConfigIntialize(_In_ DWORD argc, _In_ char* argv[])
{
    char* argv2[3];
    CHAR chMountMount = '\0';
    DWORD i = 0, iPageFile;
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
        } else if(0 == _stricmp(argv[i], "-symbolserverdisable")) {
            ctxMain->cfg.fDisableSymbolServerOnStartup = TRUE;
            i++;
            continue;
        } else if(0 == _stricmp(argv[i], "-norefresh")) {
            ctxMain->cfg.fDisableBackgroundRefresh = TRUE;
            i++;
            continue;
        } else if(0 == _stricmp(argv[i], "-waitinitialize")) {
            ctxMain->cfg.fWaitInitialize = TRUE;
            i++;
            continue;
        } else if(i + 1 >= argc) {
            return FALSE;
        } else if(0 == _stricmp(argv[i], "-cr3")) {
            ctxMain->cfg.paCR3 = Util_GetNumericA(argv[i + 1]);
            i += 2;
            continue;
        } else if(0 == _stricmp(argv[i], "-max")) {
            ctxMain->dev.paMax = Util_GetNumericA(argv[i + 1]);
            i += 2;
            continue;
        } else if((0 == _stricmp(argv[i], "-device")) || (0 == strcmp(argv[i], "-z"))) {
            strcpy_s(ctxMain->dev.szDevice, MAX_PATH, argv[i + 1]);
            i += 2;
            continue;
        } else if(0 == _stricmp(argv[i], "-remote")) {
            strcpy_s(ctxMain->dev.szRemote, MAX_PATH, argv[i + 1]);
            i += 2;
            continue;
        } else if(0 == _stricmp(argv[i], "-pythonpath")) {
            strcpy_s(ctxMain->cfg.szPythonPath, MAX_PATH, argv[i + 1]);
            i += 2;
            continue;
        } else if(0 == _stricmp(argv[i], "-mount")) {
            chMountMount = argv[i + 1][0];
            i += 2;
            continue;
        } else if(0 == _strnicmp(argv[i], "-pagefile", 9)) {
            iPageFile = argv[i][9] - '0';
            if(iPageFile < 10) {
                strcpy_s(ctxMain->cfg.szPageFile[iPageFile], MAX_PATH, argv[i + 1]);
            }
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
        " LeechCore:                      https://github.com/ufrisk/LeechCore           \n" \
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
        "   -device : select memory acquisition device or memory dump file to use.      \n" \
        "          Valid options: <any device supported by the leechcore library>       \n" \
        "          such as, but not limited to: <memory_dump_file>, PMEM, FPGA          \n" \
        "          ---                                                                  \n" \
        "          <memory_dump_file> = memory dump file name optionally including path.\n" \
        "          PMEM = use winpmem 'winpmem_64.sys' to acquire live memory.          \n" \
        "          PMEM://c:\\path\\to\\winpmem_64.sys = path to winpmem driver.        \n" \
        "          ---                                                                  \n" \
        "          Please see https://github.com/ufrisk/LeechCore for additional info.  \n" \
        "   -remote : connect to a remote host running the LeechAgent. Please see the   \n" \
        "          LeechCore documentation for more information.                        \n" \
        "   -v   : verbose option. Additional information is displayed in the output.   \n" \
        "          Option has no value. Example: -v                                     \n" \
        "   -vv  : extra verbose option. More detailed additional information is shown  \n" \
        "          in output. Option has no value. Example: -vv                         \n" \
        "   -vvv : super verbose option. Show all data transferred such as PCIe TLPs.   \n" \
        "          Option has no value. Example: -vvv                                   \n" \
        "   -cr3 : base address of kernel/process page table (PML4) / CR3 CPU register. \n" \
        "   -max : memory max address, valid range: 0x0 .. 0xffffffffffffffff           \n" \
        "          default: auto-detect (max supported by device / target system).      \n" \
        "   -pagefile0..9 : specify specify page file / swap file. By default pagefile  \n" \
        "          have index 0 - example: -pagefile0 pagefile.sys while swapfile have  \n" \
        "          have index 1 - example: -pagefile1 swapfile.sys                      \n" \
        "   -pythonpath : specify the path to a python 3 installation for Windows.      \n" \
        "          The path given should be to the directory that contain: python.dll   \n" \
        "          Example: -pythonpath \"C:\\Program Files\\Python37\"                 \n" \
        "   -mount : drive letter to mount The Memory Process File system at.           \n" \
        "          default: M   Example: -mount Q                                       \n" \
        "   -norefresh : disable automatic cache and processes refreshes even when      \n" \
        "          running against a live memory target - such as PCIe FPGA or live     \n" \
        "          driver acquired memory. This is not recommended. Example: -norefresh \n" \
        "   -symbolserverdisable : disable any integrations with the Microsoft Symbol   \n" \
        "          Server used by the debugging .pdb symbol subsystem. Functionality    \n" \
        "          will be limited if this is activated. Example: -symbolserverdisable  \n" \
        "   -waitinitialize : wait debugging .pdb symbol subsystem to fully start before\n" \
        "          mounting file system and fully starting MemProcFS.                   \n" \
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
        case VMMDLL_OPT_CONFIG_IS_PAGING_ENABLED:
            *pqwValue = (ctxVmm->flags & VMM_FLAG_NOPAGING) ? 0 : 1;
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
            break;
        case VMMDLL_OPT_WIN_VERSION_MAJOR:
            *pqwValue = ctxVmm->kernel.dwVersionMajor;
            break;
        case VMMDLL_OPT_WIN_VERSION_MINOR:
            *pqwValue = ctxVmm->kernel.dwVersionMinor;
            break;
        case VMMDLL_OPT_WIN_VERSION_BUILD:
            *pqwValue = ctxVmm->kernel.dwVersionBuild;
            break;
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
        case VMMDLL_OPT_CONFIG_IS_PAGING_ENABLED:
            ctxVmm->flags = (ctxVmm->flags & ~VMM_FLAG_NOPAGING) | (qwValue ? 0 : 1);
            break;
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
                CALL_IMPLEMENTATION_VMM(
                    STATISTICS_ID_NOLOG,
                    PluginManager_Notify(VMMDLL_PLUGIN_EVENT_VERBOSITYCHANGE, NULL, 0))
                return TRUE;
            case VMMDLL_OPT_CORE_VERBOSE:
                ctxMain->cfg.fVerbose = qwValue ? TRUE : FALSE;
                CALL_IMPLEMENTATION_VMM(
                    STATISTICS_ID_NOLOG,
                    PluginManager_Notify(VMMDLL_PLUGIN_EVENT_VERBOSITYCHANGE, NULL, 0))
                return TRUE;
            case VMMDLL_OPT_CORE_VERBOSE_EXTRA:
                ctxMain->cfg.fVerboseExtra = qwValue ? TRUE : FALSE;
                CALL_IMPLEMENTATION_VMM(
                    STATISTICS_ID_NOLOG,
                    PluginManager_Notify(VMMDLL_PLUGIN_EVENT_VERBOSITYCHANGE, NULL, 0))
                return TRUE;
            case VMMDLL_OPT_CORE_VERBOSE_EXTRA_TLP:
                ctxMain->cfg.fVerboseExtraTlp = qwValue ? TRUE : FALSE;
                CALL_IMPLEMENTATION_VMM(
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
BOOL VMMDLL_VfsHelper_GetPidDir(_In_ LPWSTR wszPath, _Out_ PDWORD pdwPID, _Out_ LPWSTR * pwszSubPath)
{
    DWORD i = 0, iSubPath = 0;
    // 1: Check if starting with PID or NAME
    if(!wcsncmp(wszPath, L"pid\\", 4)) {
        i = 4;
    } else if(!wcsncmp(wszPath, L"name\\", 5)) {
        i = 5;
    } else {
        return FALSE;
    }
    // 3: Locate start of PID number and 1st Path item (if any)
    while((i < MAX_PATH) && wszPath[i] && (wszPath[i] != '\\')) { i++; }
    iSubPath = ((i < MAX_PATH - 1) && (wszPath[i] == '\\')) ? (i + 1) : i;
    i--;
    while((wszPath[i] >= '0') && (wszPath[i] <= '9')) { i--; }
    i++;
    if(!((wszPath[i] >= '0') && (wszPath[i] <= '9'))) { return FALSE; }
    *pdwPID = wcstoul(wszPath + i, NULL, 10);
    *pwszSubPath = wszPath + iSubPath;
    return TRUE;
}

_Success_(return)
BOOL VMMDLL_VfsList_Impl_ProcessRoot(_In_ BOOL fNamePID, _Inout_ PHANDLE pFileList)
{
    PVMM_PROCESS pObProcess = NULL;
    WCHAR wszBufferFileName[MAX_PATH];
    VMMDLL_VFS_FILELIST_EXINFO ExInfo = { 0 };
    while((pObProcess = VmmProcessGetNext(pObProcess, 0))) {
        if(fNamePID) {
            if(pObProcess->dwState) {
                swprintf_s(wszBufferFileName, MAX_PATH - 1, L"%S-(%x)-%i", pObProcess->szName, pObProcess->dwState, pObProcess->dwPID);
            } else {
                swprintf_s(wszBufferFileName, MAX_PATH - 1, L"%S-%i", pObProcess->szName, pObProcess->dwPID);
            }
        } else {
            swprintf_s(wszBufferFileName, MAX_PATH - 1, L"%i", pObProcess->dwPID);
        }
        Util_VfsTimeStampFile(pObProcess, &ExInfo);
        VMMDLL_VfsList_AddDirectory(pFileList, wszBufferFileName, &ExInfo);
    }
    return TRUE;
}


BOOL VMMDLL_VfsList_Impl(_In_ LPWSTR wszPath, _Inout_ PHANDLE pFileList)
{
    BOOL result = FALSE;
    DWORD dwPID;
    LPWSTR wszSubPath;
    PVMM_PROCESS pObProcess;
    if(!ctxVmm || !VMMDLL_VfsList_IsHandleValid(pFileList)) { return FALSE; }
    if(wszPath[0] == '\\') { wszPath++; }
    if(VMMDLL_VfsHelper_GetPidDir(wszPath, &dwPID, &wszSubPath)) {
        if(!(pObProcess = VmmProcessGet(dwPID))) { return FALSE; }
        PluginManager_List(pObProcess, wszSubPath, pFileList);
        Ob_DECREF(pObProcess);
        return TRUE;
    }
    if(!_wcsnicmp(wszPath, L"name", 4)) {
        if(wcslen(wszPath) > 5) { return FALSE; }
        return VMMDLL_VfsList_Impl_ProcessRoot(TRUE, pFileList);
    }
    if(!_wcsnicmp(wszPath, L"pid", 3)) {
        if(wcslen(wszPath) > 4) { return FALSE; }
        return VMMDLL_VfsList_Impl_ProcessRoot(FALSE, pFileList);
    }
    PluginManager_List(NULL, wszPath, pFileList);
    return TRUE;
}

_Success_(return)
BOOL VMMDLL_VfsList(_In_ LPCWSTR wcsPath, _Inout_ PVMMDLL_VFS_FILELIST pFileList)
{
    CALL_IMPLEMENTATION_VMM(
        STATISTICS_ID_VMMDLL_VfsList,
        VMMDLL_VfsList_Impl((LPWSTR)wcsPath, (PHANDLE)pFileList))
}

NTSTATUS VMMDLL_VfsRead_Impl(LPWSTR wszPath, _Out_writes_(cb) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset)
{
    NTSTATUS nt;
    DWORD dwPID;
    LPWSTR wszSubPath;
    PVMM_PROCESS pObProcess;
    if(!ctxVmm) { return VMM_STATUS_FILE_INVALID; }
    if(wszPath[0] == '\\') { wszPath++; }
    if(VMMDLL_VfsHelper_GetPidDir(wszPath, &dwPID, &wszSubPath)) {
        if(!(pObProcess = VmmProcessGet(dwPID))) { return VMM_STATUS_FILE_INVALID; }
        nt = PluginManager_Read(pObProcess, wszSubPath, pb, cb, pcbRead, cbOffset);
        Ob_DECREF(pObProcess);
        return nt;
    }
    return PluginManager_Read(NULL, wszPath, pb, cb, pcbRead, cbOffset);
}

NTSTATUS VMMDLL_VfsRead(_In_ LPCWSTR wcsFileName, _Out_ LPVOID pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ ULONG64 cbOffset)
{
    CALL_IMPLEMENTATION_VMM_RETURN(
        STATISTICS_ID_VMMDLL_VfsRead,
        NTSTATUS,
        VMMDLL_STATUS_UNSUCCESSFUL,
        VMMDLL_VfsRead_Impl((LPWSTR)wcsFileName, pb, cb, pcbRead, cbOffset))
}

NTSTATUS VMMDLL_VfsWrite_Impl(_In_ LPWSTR wszPath, _In_reads_(cb) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbWrite, _In_ QWORD cbOffset)
{
    NTSTATUS nt;
    DWORD dwPID;
    LPWSTR wszSubPath;
    PVMM_PROCESS pObProcess;
    if(!ctxVmm) { return VMM_STATUS_FILE_INVALID; }
    if(wszPath[0] == '\\') { wszPath++; }
    if(VMMDLL_VfsHelper_GetPidDir(wszPath, &dwPID, &wszSubPath)) {
        if(!(pObProcess = VmmProcessGet(dwPID))) { return VMM_STATUS_FILE_INVALID; }
        nt = PluginManager_Write(pObProcess, wszSubPath, pb, cb, pcbWrite, cbOffset);
        Ob_DECREF(pObProcess);
        return nt;
    }
    return PluginManager_Write(NULL, wszPath, pb, cb, pcbWrite, cbOffset);
}

NTSTATUS VMMDLL_VfsWrite(_In_ LPCWSTR wcsFileName, _In_ LPVOID pb, _In_ DWORD cb, _Out_ PDWORD pcbWrite, _In_ ULONG64 cbOffset)
{
    CALL_IMPLEMENTATION_VMM_RETURN(
        STATISTICS_ID_VMMDLL_VfsWrite,
        NTSTATUS,
        VMMDLL_STATUS_UNSUCCESSFUL,
        VMMDLL_VfsWrite_Impl((LPWSTR)wcsFileName, pb, cb, pcbWrite, cbOffset))
}

NTSTATUS VMMDLL_UtilVfsReadFile_FromPBYTE(_In_ PBYTE pbFile, _In_ ULONG64 cbFile, _Out_ PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ ULONG64 cbOffset)
{
    return Util_VfsReadFile_FromPBYTE(pbFile, cbFile, pb, cb, pcbRead, cbOffset);
}

NTSTATUS VMMDLL_UtilVfsReadFile_FromQWORD(_In_ ULONG64 qwValue, _Out_ PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ ULONG64 cbOffset, _In_ BOOL fPrefix)
{
    return Util_VfsReadFile_FromQWORD(qwValue, pb, cb, pcbRead, cbOffset, fPrefix);
}

NTSTATUS VMMDLL_UtilVfsReadFile_FromDWORD(_In_ DWORD dwValue, _Out_ PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ ULONG64 cbOffset, _In_ BOOL fPrefix)
{
    return Util_VfsReadFile_FromDWORD(dwValue, pb, cb, pcbRead, cbOffset, fPrefix);
}

NTSTATUS VMMDLL_UtilVfsReadFile_FromBOOL(_In_ BOOL fValue, _Out_ PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ ULONG64 cbOffset)
{
    return Util_VfsReadFile_FromBOOL(fValue, pb, cb, pcbRead, cbOffset);
}

NTSTATUS VMMDLL_UtilVfsWriteFile_BOOL(_Inout_ PBOOL pfTarget, _In_ PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbWrite, _In_ ULONG64 cbOffset)
{
    return Util_VfsWriteFile_BOOL(pfTarget, pb, cb, pcbWrite, cbOffset);
}

NTSTATUS VMMDLL_UtilVfsWriteFile_DWORD(_Inout_ PDWORD pdwTarget, _In_ PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbWrite, _In_ ULONG64 cbOffset, _In_ DWORD dwMinAllow)
{
    return Util_VfsWriteFile_DWORD(pdwTarget, pb, cb, pcbWrite, cbOffset, dwMinAllow);
}



//-----------------------------------------------------------------------------
// PLUGIN MANAGER FUNCTIONALITY BELOW:
//-----------------------------------------------------------------------------

_Success_(return)
BOOL VMMDLL_VfsInitializePlugins()
{
    CALL_IMPLEMENTATION_VMM(
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
    CALL_IMPLEMENTATION_VMM(
        STATISTICS_ID_VMMDLL_Refresh,
        VMMDLL_Refresh_Impl(dwReserved))
}

/*
* Free memory allocated by the VMMDLL.
* -- pvMem
*/
VOID VMMDLL_MemFree(_Frees_ptr_opt_ PVOID pvMem)
{
    LocalFree(pvMem);
}



//-----------------------------------------------------------------------------
// VMM CORE FUNCTIONALITY BELOW:
//-----------------------------------------------------------------------------

DWORD VMMDLL_MemReadScatter_Impl(_In_ DWORD dwPID, _Inout_ PPMEM_IO_SCATTER_HEADER ppMEMs, _In_ DWORD cpMEMs, _In_ DWORD flags)
{
    DWORD i, cMEMs;
    PVMM_PROCESS pObProcess = NULL;
    if(!ctxVmm) { return 0; }
    if(dwPID == -1) {
        VmmReadScatterPhysical(ppMEMs, cpMEMs, flags);
    } else {
        pObProcess = VmmProcessGet(dwPID);
        if(!pObProcess) { return FALSE; }
        VmmReadScatterVirtual(pObProcess, ppMEMs, cpMEMs, flags);
        Ob_DECREF(pObProcess);
    }
    for(i = 0, cMEMs = 0; i < cpMEMs; i++) {
        if(ppMEMs[i]->cb == ppMEMs[i]->cbMax) {
            cMEMs++;
        }
    }
    return cMEMs;
}

DWORD VMMDLL_MemReadScatter(_In_ DWORD dwPID, _Inout_ PPMEM_IO_SCATTER_HEADER ppMEMs, _In_ DWORD cpMEMs, _In_ DWORD flags)
{
    CALL_IMPLEMENTATION_VMM_RETURN(
        STATISTICS_ID_VMMDLL_MemReadScatter,
        DWORD,
        0,
        VMMDLL_MemReadScatter_Impl(dwPID, ppMEMs, cpMEMs, flags))
}

_Success_(return)
BOOL VMMDLL_MemReadEx_Impl(_In_ DWORD dwPID, _In_ ULONG64 qwA, _Out_writes_(cb) PBYTE pb, _In_ DWORD cb, _Out_opt_ PDWORD pcbReadOpt, _In_ ULONG64 flags)
{
    PVMM_PROCESS pObProcess = NULL;
    if(dwPID != -1) {
        pObProcess = VmmProcessGet(dwPID);
        if(!pObProcess) { return FALSE; }
    }
    VmmReadEx(pObProcess, qwA, pb, cb, pcbReadOpt, flags);
    Ob_DECREF(pObProcess);
    return TRUE;
}

_Success_(return)
BOOL VMMDLL_MemReadEx(_In_ DWORD dwPID, _In_ ULONG64 qwA, _Out_writes_(cb) PBYTE pb, _In_ DWORD cb, _Out_opt_ PDWORD pcbReadOpt, _In_ ULONG64 flags)
{
    CALL_IMPLEMENTATION_VMM(
        STATISTICS_ID_VMMDLL_MemReadEx,
        VMMDLL_MemReadEx_Impl(dwPID, qwA, pb, cb, pcbReadOpt, flags))
}

_Success_(return)
BOOL VMMDLL_MemRead(_In_ DWORD dwPID, _In_ ULONG64 qwA, _Out_writes_(cb) PBYTE pb, _In_ DWORD cb)
{
    DWORD dwRead;
    return VMMDLL_MemReadEx(dwPID, qwA, pb, cb, &dwRead, 0) && (dwRead == cb);
}

_Success_(return)
BOOL VMMDLL_MemReadPage(_In_ DWORD dwPID, _In_ ULONG64 qwA, _Inout_bytecount_(4096) PBYTE pbPage)
{
    DWORD dwRead;
    return VMMDLL_MemReadEx(dwPID, qwA, pbPage, 4096, &dwRead, 0) && (dwRead == 4096);
}

_Success_(return)
BOOL VMMDLL_MemPrefetchPages_Impl(_In_ DWORD dwPID, _In_reads_(cPrefetchAddresses) PULONG64 pPrefetchAddresses, _In_ DWORD cPrefetchAddresses)
{
    DWORD i;
    BOOL result = FALSE;
    PVMM_PROCESS pObProcess = NULL;
    POB_SET pObSet_PrefetchAddresses = NULL;
    if(dwPID != (DWORD)-1) {
        pObProcess = VmmProcessGet(dwPID);
        if(!pObProcess) { goto fail; }
    }
    if(!(pObSet_PrefetchAddresses = ObSet_New())) { goto fail; }
    for(i = 0; i < cPrefetchAddresses; i++) {
        ObSet_Push(pObSet_PrefetchAddresses, pPrefetchAddresses[i] & ~0xfff);
    }
    VmmCachePrefetchPages(pObProcess, pObSet_PrefetchAddresses, 0);
    result = TRUE;
fail:
    Ob_DECREF(pObSet_PrefetchAddresses);
    Ob_DECREF(pObProcess);
    return result;
}

_Success_(return)
BOOL VMMDLL_MemPrefetchPages(_In_ DWORD dwPID, _In_reads_(cPrefetchAddresses) PULONG64 pPrefetchAddresses, _In_ DWORD cPrefetchAddresses)
{
    CALL_IMPLEMENTATION_VMM(
        STATISTICS_ID_VMMDLL_MemPrefetchPages,
        VMMDLL_MemPrefetchPages_Impl(dwPID, pPrefetchAddresses, cPrefetchAddresses))
}

_Success_(return)
BOOL VMMDLL_MemWrite_Impl(_In_ DWORD dwPID, _In_ ULONG64 qwA, _In_reads_(cb) PBYTE pb, _In_ DWORD cb)
{
    BOOL result;
    PVMM_PROCESS pObProcess = NULL;
    if(dwPID != -1) {
        pObProcess = VmmProcessGet(dwPID);
        if(!pObProcess) { return FALSE; }
    }
    result = VmmWrite(pObProcess, qwA, pb, cb);
    Ob_DECREF(pObProcess);
    return result;
}

_Success_(return)
BOOL VMMDLL_MemWrite(_In_ DWORD dwPID, _In_ ULONG64 qwA, _In_reads_(cb) PBYTE pb, _In_ DWORD cb)
{
    CALL_IMPLEMENTATION_VMM(
        STATISTICS_ID_VMMDLL_MemWrite,
        VMMDLL_MemWrite_Impl(dwPID, qwA, pb, cb))
}

_Success_(return)
BOOL VMMDLL_MemVirt2Phys_Impl(_In_ DWORD dwPID, _In_ ULONG64 qwVA, _Out_ PULONG64 pqwPA)
{
    BOOL result;
    PVMM_PROCESS pObProcess = VmmProcessGet(dwPID);
    if(!pObProcess) { return FALSE; }
    result = VmmVirt2Phys(pObProcess, qwVA, pqwPA);
    Ob_DECREF(pObProcess);
    return result;
}

_Success_(return)
BOOL VMMDLL_MemVirt2Phys(_In_ DWORD dwPID, _In_ ULONG64 qwVA, _Out_ PULONG64 pqwPA)
{
    CALL_IMPLEMENTATION_VMM(
        STATISTICS_ID_VMMDLL_MemVirt2Phys,
        VMMDLL_MemVirt2Phys_Impl(dwPID, qwVA, pqwPA))
}

//-----------------------------------------------------------------------------
// VMM PROCESS FUNCTIONALITY BELOW:
//-----------------------------------------------------------------------------

_Success_(return)
BOOL VMMDLL_ProcessMap_GetPte_Impl(_In_ DWORD dwPID, _Out_writes_bytes_opt_(*pcbPteMap) PVMMDLL_MAP_PTE pPteMap, _Inout_ PDWORD pcbPteMap, _In_ BOOL fIdentifyModules)
{
    BOOL fResult = FALSE;
    QWORD i, cbData = 0, cbDataMap, cbMultiTextDiff;
    PVMMOB_MAP_PTE pObMap = NULL;
    PVMM_PROCESS pObProcess = NULL;
    if(!(pObProcess = VmmProcessGet(dwPID))) { goto fail; }
    if(!VmmMap_GetPte(pObProcess, &pObMap, fIdentifyModules)) { goto fail; }
    cbDataMap = pObMap->cMap * sizeof(VMMDLL_MAP_PTEENTRY);
    cbData = sizeof(VMMDLL_MAP_PTE) + cbDataMap + max(2, pObMap->cbMultiText);
    if(pPteMap) {
        if(*pcbPteMap < cbData) { goto fail; }
        ZeroMemory(pPteMap, sizeof(VMMDLL_MAP_PTE));
        pPteMap->dwVersion = VMMDLL_MAP_PTE_VERSION;
        pPteMap->cMap = pObMap->cMap;
        memcpy(pPteMap->pMap, pObMap->pMap, cbDataMap);
        pPteMap->cbMultiText = pObMap->cbMultiText;
        pPteMap->wszMultiText = (LPWSTR)(pPteMap->pMap + pPteMap->cMap);
        if(fIdentifyModules) {
            memcpy(pPteMap->wszMultiText, pObMap->wszMultiText, pPteMap->cbMultiText);
            cbMultiTextDiff = (QWORD)pPteMap->wszMultiText - (QWORD)pObMap->wszMultiText;
            for(i = 0; i < pPteMap->cMap; i++) {
                if(pPteMap->pMap[i].cwszText) {
                    pPteMap->pMap[i].wszText = (LPWSTR)((QWORD)pObMap->pMap[i].wszText - (QWORD)pObMap->wszMultiText + (QWORD)pPteMap->wszMultiText);
                } else {
                    pPteMap->pMap[i].wszText = pPteMap->wszMultiText;
                }
            }
        } else {
            pPteMap->wszMultiText[0] = 0;
            for(i = 0; i < pPteMap->cMap; i++) {
                pPteMap->pMap[i].wszText = pPteMap->wszMultiText;
            }
        }
    }
    fResult = TRUE;
fail:
    *pcbPteMap = (DWORD)cbData;
    Ob_DECREF(pObProcess);
    Ob_DECREF(pObMap);
    return fResult;
}

_Success_(return)
BOOL VMMDLL_ProcessMap_GetPte(_In_ DWORD dwPID, _Out_writes_bytes_opt_(*pcbPteMap) PVMMDLL_MAP_PTE pPteMap, _Inout_ PDWORD pcbPteMap, _In_ BOOL fIdentifyModules)
{
    CALL_IMPLEMENTATION_VMM(
        STATISTICS_ID_VMMDLL_ProcessMap_GetPte,
        VMMDLL_ProcessMap_GetPte_Impl(dwPID, pPteMap, pcbPteMap, fIdentifyModules))
}

_Success_(return)
BOOL VMMDLL_ProcessMap_GetVad_Impl(_In_ DWORD dwPID, _Out_writes_bytes_opt_(*pcbVadMap) PVMMDLL_MAP_VAD pVadMap, _Inout_ PDWORD pcbVadMap, _In_ BOOL fIdentifyModules)
{
    BOOL fResult = FALSE;
    DWORD i, cbData = 0, cbDataMap;
    QWORD cbMultiTextDiff;
    PVMMOB_MAP_VAD pObMap = NULL;
    PVMM_PROCESS pObProcess = NULL;
    if(!(pObProcess = VmmProcessGet(dwPID))) { goto fail; }
    if(!VmmMap_GetVad(pObProcess, &pObMap, fIdentifyModules)) { goto fail; }
    cbDataMap = pObMap->cMap * sizeof(VMMDLL_MAP_VADENTRY);
    cbData = sizeof(VMMDLL_MAP_VAD) + cbDataMap + max(2, pObMap->cbMultiText);
    if(pVadMap) {
        if(*pcbVadMap < cbData) { goto fail; }
        ZeroMemory(pVadMap, sizeof(VMMDLL_MAP_VAD));
        pVadMap->dwVersion = VMMDLL_MAP_VAD_VERSION;
        pVadMap->cMap = pObMap->cMap;
        memcpy(pVadMap->pMap, pObMap->pMap, cbDataMap);
        pVadMap->cbMultiText = pObMap->cbMultiText;
        pVadMap->wszMultiText = (LPWSTR)(pVadMap->pMap + pVadMap->cMap);
        if(fIdentifyModules) {
            memcpy(pVadMap->wszMultiText, pObMap->wszMultiText, pVadMap->cbMultiText);
            cbMultiTextDiff = (QWORD)pVadMap->wszMultiText - (QWORD)pObMap->wszMultiText;
            for(i = 0; i < pVadMap->cMap; i++) {
                if(pVadMap->pMap[i].cwszText) {
                    pVadMap->pMap[i].wszText = (LPWSTR)(cbMultiTextDiff + (QWORD)pObMap->pMap[i].wszText);
                } else {
                    pVadMap->pMap[i].wszText = pVadMap->wszMultiText;
                }
            }
        } else {
            pVadMap->wszMultiText[0] = 0;
            for(i = 0; i < pVadMap->cMap; i++) {
                pVadMap->pMap[i].wszText = pVadMap->wszMultiText;
            }
        }
    }
    fResult = TRUE;
fail:
    *pcbVadMap = cbData;
    Ob_DECREF(pObProcess);
    Ob_DECREF(pObMap);
    return fResult;
}

_Success_(return)
BOOL VMMDLL_ProcessMap_GetVad(_In_ DWORD dwPID, _Out_writes_bytes_opt_(*pcbVadMap) PVMMDLL_MAP_VAD pVadMap, _Inout_ PDWORD pcbVadMap, _In_ BOOL fIdentifyModules)
{
    CALL_IMPLEMENTATION_VMM(
        STATISTICS_ID_VMMDLL_ProcessMap_GetVad,
        VMMDLL_ProcessMap_GetVad_Impl(dwPID, pVadMap, pcbVadMap, fIdentifyModules))
}

_Success_(return)
BOOL VMMDLL_ProcessMap_GetModule_Impl(_In_ DWORD dwPID, _Out_writes_bytes_opt_(*pcbModuleMap) PVMMDLL_MAP_MODULE pModuleMap, _Inout_ PDWORD pcbModuleMap)
{
    BOOL fResult = FALSE;
    QWORD i, cbData = 0, cbDataMap, cbMultiTextDiff;
    PVMMOB_MAP_MODULE pObMap = NULL;
    PVMM_PROCESS pObProcess = NULL;
    if(!(pObProcess = VmmProcessGet(dwPID))) { goto fail; }
    if(!VmmMap_GetModule(pObProcess, &pObMap)) { goto fail; }
    cbDataMap = pObMap->cMap * sizeof(VMMDLL_MAP_MODULEENTRY);
    cbData = sizeof(VMMDLL_MAP_MODULE) + cbDataMap + pObMap->cbMultiText;
    if(pModuleMap) {
        if(*pcbModuleMap < cbData) { goto fail; }
        ZeroMemory(pModuleMap, sizeof(VMMDLL_MAP_MODULE));
        pModuleMap->dwVersion = VMMDLL_MAP_MODULE_VERSION;
        pModuleMap->wszMultiText = (LPWSTR)(((PBYTE)pModuleMap->pMap) + cbDataMap);
        pModuleMap->cbMultiText = pObMap->cbMultiText;
        pModuleMap->cMap = pObMap->cMap;
        memcpy(pModuleMap->pMap, pObMap->pMap, cbDataMap);
        memcpy(pModuleMap->wszMultiText, pObMap->wszMultiText, pObMap->cbMultiText);
        cbMultiTextDiff = (QWORD)pModuleMap->wszMultiText - (QWORD)pObMap->wszMultiText;
        for(i = 0; i < pModuleMap->cMap; i++) {
            pModuleMap->pMap[i].wszText = (LPWSTR)(cbMultiTextDiff + (QWORD)pObMap->pMap[i].wszText);
        }
    }
    fResult = TRUE;
fail:
    *pcbModuleMap = (DWORD)cbData;
    Ob_DECREF(pObProcess);
    Ob_DECREF(pObMap);
    return fResult;
}

_Success_(return)
BOOL VMMDLL_ProcessMap_GetModule(_In_ DWORD dwPID, _Out_writes_bytes_opt_(*pcbModuleMap) PVMMDLL_MAP_MODULE pModuleMap, _Inout_ PDWORD pcbModuleMap)
{
    CALL_IMPLEMENTATION_VMM(
        STATISTICS_ID_VMMDLL_ProcessMap_GetModule,
        VMMDLL_ProcessMap_GetModule_Impl(dwPID, pModuleMap, pcbModuleMap))
}

_Success_(return)
BOOL VMMDLL_ProcessMap_GetModuleFromName_Impl(_In_ DWORD dwPID, _In_ LPWSTR wszModuleName, _Out_ PVMMDLL_MAP_MODULEENTRY pModuleMapEntry)
{
    BOOL fResult;
    PVMM_PROCESS pObProcess = NULL;
    PVMMOB_MAP_MODULE pObMap = NULL;
    PVMM_MAP_MODULEENTRY pVmmModuleMapEntry = NULL;
    fResult =
        (pObProcess = VmmProcessGet(dwPID)) &&
        VmmMap_GetModule(pObProcess, &pObMap) &&
        (pVmmModuleMapEntry = VmmMap_GetModuleEntry(pObMap, wszModuleName));
    if(fResult) {
        memcpy(pModuleMapEntry, pVmmModuleMapEntry, sizeof(VMMDLL_MAP_MODULEENTRY));
        // no mem allocation for module name in single item.
        pModuleMapEntry->_Reserved1[0] = 0;
        pModuleMapEntry->wszText = (LPWSTR)pModuleMapEntry->_Reserved1;
    }
    Ob_DECREF(pObProcess);
    Ob_DECREF(pObMap);
    return fResult;
}

_Success_(return)
BOOL VMMDLL_ProcessMap_GetModuleFromName(_In_ DWORD dwPID, _In_ LPWSTR wszModuleName, _Out_ PVMMDLL_MAP_MODULEENTRY pModuleMapEntry)
{
    CALL_IMPLEMENTATION_VMM(
        STATISTICS_ID_VMMDLL_ProcessMap_GetModuleFromName,
        VMMDLL_ProcessMap_GetModuleFromName_Impl(dwPID, wszModuleName, pModuleMapEntry))
}

_Success_(return)
BOOL VMMDLL_ProcessMap_GetHeap_Impl(_In_ DWORD dwPID, _Out_writes_bytes_opt_(*pcbHeapMap) PVMMDLL_MAP_HEAP pHeapMap, _Inout_ PDWORD pcbHeapMap)
{
    BOOL fResult = FALSE;
    DWORD cbData = 0, cbDataMap;
    PVMMOB_MAP_HEAP pObMap = NULL;
    PVMM_PROCESS pObProcess = NULL;
    if(!(pObProcess = VmmProcessGet(dwPID))) { goto fail; }
    if(!VmmMap_GetHeap(pObProcess, &pObMap)) { goto fail; }
    cbDataMap = pObMap->cMap * sizeof(VMMDLL_MAP_HEAPENTRY);
    cbData = sizeof(VMMDLL_MAP_HEAP) + cbDataMap;
    if(pHeapMap) {
        if(*pcbHeapMap < cbData) { goto fail; }
        ZeroMemory(pHeapMap, sizeof(VMMDLL_MAP_HEAP));
        pHeapMap->dwVersion = VMMDLL_MAP_HEAP_VERSION;
        pHeapMap->cMap = pObMap->cMap;
        memcpy(pHeapMap->pMap, pObMap->pMap, cbDataMap);
    }
    fResult = TRUE;
fail:
    *pcbHeapMap = cbData;
    Ob_DECREF(pObProcess);
    Ob_DECREF(pObMap);
    return fResult;
}

_Success_(return)
BOOL VMMDLL_ProcessMap_GetHeap(_In_ DWORD dwPID, _Out_writes_bytes_opt_(*pcbHeapMap) PVMMDLL_MAP_HEAP pHeapMap, _Inout_ PDWORD pcbHeapMap)
{
    CALL_IMPLEMENTATION_VMM(
        STATISTICS_ID_VMMDLL_ProcessMap_GetHeap,
        VMMDLL_ProcessMap_GetHeap_Impl(dwPID, pHeapMap, pcbHeapMap))
}

_Success_(return)
BOOL VMMDLL_ProcessMap_GetThread_Impl(_In_ DWORD dwPID, _Out_writes_bytes_opt_(*pcbThreadMap) PVMMDLL_MAP_THREAD pThreadMap, _Inout_ PDWORD pcbThreadMap)
{
    BOOL fResult = FALSE;
    DWORD cbData = 0, cbDataMap;
    PVMMOB_MAP_THREAD pObMap = NULL;
    PVMM_PROCESS pObProcess = NULL;
    if(!(pObProcess = VmmProcessGet(dwPID))) { goto fail; }
    if(!VmmMap_GetThread(pObProcess, &pObMap)) { goto fail; }
    cbDataMap = pObMap->cMap * sizeof(VMMDLL_MAP_THREADENTRY);
    cbData = sizeof(VMMDLL_MAP_THREAD) + cbDataMap;
    if(pThreadMap) {
        if(*pcbThreadMap < cbData) { goto fail; }
        ZeroMemory(pThreadMap, sizeof(VMMDLL_MAP_HEAP));
        pThreadMap->dwVersion = VMMDLL_MAP_VAD_VERSION;
        pThreadMap->cMap = pObMap->cMap;
        memcpy(pThreadMap->pMap, pObMap->pMap, cbDataMap);
    }
    fResult = TRUE;
fail:
    *pcbThreadMap = cbData;
    Ob_DECREF(pObProcess);
    Ob_DECREF(pObMap);
    return fResult;
}

_Success_(return)
BOOL VMMDLL_ProcessMap_GetThread(_In_ DWORD dwPID, _Out_writes_bytes_opt_(*pcbThreadMap) PVMMDLL_MAP_THREAD pThreadMap, _Inout_ PDWORD pcbThreadMap)
{
    CALL_IMPLEMENTATION_VMM(
        STATISTICS_ID_VMMDLL_ProcessMap_GetThread,
        VMMDLL_ProcessMap_GetThread_Impl(dwPID, pThreadMap, pcbThreadMap))
}

_Success_(return)
BOOL VMMDLL_ProcessMap_GetHandle_Impl(_In_ DWORD dwPID, _Out_writes_bytes_opt_(*pcbHandleMap) PVMMDLL_MAP_HANDLE pHandleMap, _Inout_ PDWORD pcbHandleMap)
{
    BOOL fResult = FALSE;
    QWORD i, cbData = 0, cbDataMap, cbMultiTextDiff;
    PVMMDLL_MAP_HANDLEENTRY pe;
    PVMMWIN_OBJECT_TYPE pOT;
    PVMMOB_MAP_HANDLE pObMap = NULL;
    PVMM_PROCESS pObProcess = NULL;
    LPWSTR wszTypeMultiText;
    if(!(pObProcess = VmmProcessGet(dwPID))) { goto fail; }
    if(!VmmMap_GetHandle(pObProcess, &pObMap, TRUE)) { goto fail; }
    VmmWin_ObjectTypeGet(2);
    cbDataMap = pObMap->cMap * sizeof(VMMDLL_MAP_HANDLEENTRY);
    cbData = sizeof(VMMDLL_MAP_HANDLE) + cbDataMap + pObMap->cbMultiText + ctxVmm->ObjectTypeTable.cbMultiText;
    if(pHandleMap) {
        if(*pcbHandleMap < cbData) { goto fail; }
        ZeroMemory(pHandleMap, sizeof(VMMDLL_MAP_HANDLE));
        pHandleMap->dwVersion = VMMDLL_MAP_HANDLE_VERSION;
        pHandleMap->wszMultiText = (LPWSTR)(((PBYTE)pHandleMap->pMap) + cbDataMap);
        pHandleMap->cbMultiText = pObMap->cbMultiText;
        wszTypeMultiText = (LPWSTR)(((PBYTE)pHandleMap->wszMultiText) + pObMap->cbMultiText);
        pHandleMap->cMap = pObMap->cMap;
        memcpy(pHandleMap->pMap, pObMap->pMap, cbDataMap);
        memcpy(pHandleMap->wszMultiText, pObMap->wszMultiText, pObMap->cbMultiText);
        memcpy(wszTypeMultiText, ctxVmm->ObjectTypeTable.wszMultiText, ctxVmm->ObjectTypeTable.cbMultiText);
        cbMultiTextDiff = (QWORD)pHandleMap->wszMultiText - (QWORD)pObMap->wszMultiText;
        for(i = 0; i < pHandleMap->cMap; i++) {
            pe = pHandleMap->pMap + i;
            pe->wszText = (LPWSTR)(cbMultiTextDiff + (QWORD)pObMap->pMap[i].wszText);
            if((pOT = VmmWin_ObjectTypeGet((BYTE)pe->iType))) {
                pe->cwszType = pOT->cwsz;
                pe->wszType = wszTypeMultiText + pOT->owsz;
            } else {
                pe->cwszType = 0;
                pe->wszType = pHandleMap->wszMultiText;
            }
        }
    }
    fResult = TRUE;
fail:
    *pcbHandleMap = (DWORD)cbData;
    Ob_DECREF(pObProcess);
    Ob_DECREF(pObMap);
    return fResult;
}

_Success_(return)
BOOL VMMDLL_ProcessMap_GetHandle(_In_ DWORD dwPID, _Out_writes_bytes_opt_(*pcbHandleMap) PVMMDLL_MAP_HANDLE pHandleMap, _Inout_ PDWORD pcbHandleMap)
{
    CALL_IMPLEMENTATION_VMM(
        STATISTICS_ID_VMMDLL_ProcessMap_GetHandle,
        VMMDLL_ProcessMap_GetHandle_Impl(dwPID, pHandleMap, pcbHandleMap))
}

_Success_(return)
BOOL VMMDLL_Map_GetPhysMem_Impl(_Out_writes_bytes_opt_(*pcbPhysMemMap) PVMMDLL_MAP_PHYSMEM pPhysMemMap, _Inout_ PDWORD pcbPhysMemMap)
{
    BOOL fResult = FALSE;
    DWORD cbData = 0, cbDataMap;
    PVMMOB_MAP_PHYSMEM pObMap = NULL;
    if(!VmmMap_GetPhysMem(&pObMap)) { goto fail; }
    cbDataMap = pObMap->cMap * sizeof(VMMDLL_MAP_PHYSMEMENTRY);
    cbData = sizeof(VMMDLL_MAP_PHYSMEM) + cbDataMap;
    if(pPhysMemMap) {
        if(*pcbPhysMemMap < cbData) { goto fail; }
        ZeroMemory(pPhysMemMap, cbData);
        pPhysMemMap->dwVersion = VMMDLL_MAP_PHYSMEM_VERSION;
        pPhysMemMap->cMap = pObMap->cMap;
        memcpy(pPhysMemMap->pMap, pObMap->pMap, cbDataMap);
    }
    fResult = TRUE;
fail:
    *pcbPhysMemMap = cbData;
    Ob_DECREF(pObMap);
    return fResult;
}

_Success_(return)
BOOL VMMDLL_Map_GetPhysMem(_Out_writes_bytes_opt_(*pcbPhysMemMap) PVMMDLL_MAP_PHYSMEM pPhysMemMap, _Inout_ PDWORD pcbPhysMemMap)
{
    CALL_IMPLEMENTATION_VMM(
        STATISTICS_ID_VMMDLL_Map_GetPhysMem,
        VMMDLL_Map_GetPhysMem_Impl(pPhysMemMap, pcbPhysMemMap))
}

_Success_(return)
BOOL VMMDLL_Map_GetUsers_Impl(_Out_writes_bytes_opt_(*pcbUserMap) PVMMDLL_MAP_USER pUserMap, _Inout_ PDWORD pcbUserMap)
{
    BOOL fResult = FALSE;
    QWORD i, cbData = 0, cbDataMap, cbMultiTextDiff;
    PVMMDLL_MAP_USERENTRY pe;
    PVMMOB_MAP_USER pObMap = NULL;
    if(!VmmMap_GetUser(&pObMap)) { goto fail; }
    cbDataMap = pObMap->cMap * sizeof(VMMDLL_MAP_USERENTRY);
    cbData = sizeof(VMMDLL_MAP_USER) + cbDataMap + pObMap->cbMultiText;
    if(pUserMap) {
        if(*pcbUserMap < cbData) { goto fail; }
        ZeroMemory(pUserMap, cbData);
        pUserMap->dwVersion = VMMDLL_MAP_USER_VERSION;
        pUserMap->wszMultiText = (LPWSTR)(((PBYTE)pUserMap->pMap) + cbDataMap);
        pUserMap->cbMultiText = pObMap->cbMultiText;
        pUserMap->cMap = pObMap->cMap;
        memcpy(pUserMap->wszMultiText, pObMap->wszMultiText, pObMap->cbMultiText);
        cbMultiTextDiff = (QWORD)pUserMap->wszMultiText - (QWORD)pObMap->wszMultiText;
        for(i = 0; i < pUserMap->cMap; i++) {
            pe = pUserMap->pMap + i;
            if(pObMap->pMap[i].szSID) {
                strncpy_s(pe->szSID, sizeof(pe->szSID), pObMap->pMap[i].szSID, _TRUNCATE);
            }
            pe->cwszText = pObMap->pMap[i].cwszText;
            pe->vaRegHive = pObMap->pMap[i].vaRegHive;
            pe->wszText = (LPWSTR)(cbMultiTextDiff + (QWORD)pObMap->pMap[i].wszText);
        }
    }
    fResult = TRUE;
fail:
    *pcbUserMap = (DWORD)cbData;
    Ob_DECREF(pObMap);
    return fResult;
}

_Success_(return)
BOOL VMMDLL_Map_GetUsers(_Out_writes_bytes_opt_(*pcbUserMap) PVMMDLL_MAP_USER pUserMap, _Inout_ PDWORD pcbUserMap)
{
    CALL_IMPLEMENTATION_VMM(
        STATISTICS_ID_VMMDLL_Map_GetUsers,
        VMMDLL_Map_GetUsers_Impl(pUserMap, pcbUserMap))
}

_Success_(return)
BOOL VMMDLL_Map_GetPfn_Impl(_In_ DWORD pPfns[], _In_ DWORD cPfns, _Out_writes_bytes_opt_(*pcbPfnMap) PVMMDLL_MAP_PFN pPfnMap, _Inout_ PDWORD pcbPfnMap)
{
    BOOL fResult = FALSE;
    POB_SET psObPfns = NULL;
    PMMPFNOB_MAP pObMap = NULL;
    DWORD i, cbData = 0, cbDataMap;
    cbDataMap = cPfns * sizeof(VMMDLL_MAP_PFNENTRY);
    cbData = sizeof(VMMDLL_MAP_PFN) + cbDataMap;
    if(pPfnMap) {
        if(*pcbPfnMap < cbData) { goto fail; }
        if(!(psObPfns = ObSet_New())) { goto fail; }
        for(i = 0; i < cPfns; i++) {
            ObSet_Push(psObPfns, pPfns[i]);
        }
        if(!MmPfn_Map_GetPfnScatter(psObPfns, &pObMap)) { goto fail; }
        ZeroMemory(pPfnMap, cbData);
        pPfnMap->dwVersion = VMMDLL_MAP_PFN_VERSION;
        pPfnMap->cMap = pObMap->cMap;
        cbDataMap = pObMap->cMap * sizeof(VMMDLL_MAP_PFNENTRY);
        cbData = sizeof(VMMDLL_MAP_PFN) + cbDataMap;
        memcpy(pPfnMap->pMap, pObMap->pMap, cbDataMap);
    }
    fResult = TRUE;
fail:
    *pcbPfnMap = cbData;
    Ob_DECREF(psObPfns);
    Ob_DECREF(pObMap);
    return fResult;
}

_Success_(return)
BOOL VMMDLL_Map_GetPfn(_In_ DWORD pPfns[], _In_ DWORD cPfns, _Out_writes_bytes_opt_(*pcbPfnMap) PVMMDLL_MAP_PFN pPfnMap, _Inout_ PDWORD pcbPfnMap)
{
    CALL_IMPLEMENTATION_VMM(
        STATISTICS_ID_VMMDLL_Map_GetPfn,
        VMMDLL_Map_GetPfn_Impl(pPfns, cPfns, pPfnMap, pcbPfnMap))
}

_Success_(return)
BOOL VMMDLL_PidList_Impl(_Out_writes_opt_(*pcPIDs) PDWORD pPIDs, _Inout_ PULONG64 pcPIDs)
{
    VmmProcessListPIDs(pPIDs, pcPIDs, 0);
    return TRUE;
}

_Success_(return)
BOOL VMMDLL_PidList(_Out_writes_opt_(*pcPIDs) PDWORD pPIDs, _Inout_ PULONG64 pcPIDs)
{
    CALL_IMPLEMENTATION_VMM(
        STATISTICS_ID_VMMDLL_PidList,
        VMMDLL_PidList_Impl(pPIDs, pcPIDs))
}

_Success_(return)
BOOL VMMDLL_PidGetFromName_Impl(_In_ LPSTR szProcName, _Out_ PDWORD pdwPID)
{
    PVMM_PROCESS pObProcess = NULL;
    // 1: try locate process using long (full) name
    while((pObProcess = VmmProcessGetNext(pObProcess, 0))) {
        if(pObProcess->dwState) { continue; }
        if(!pObProcess->pObPersistent->szNameLong || _stricmp(szProcName, pObProcess->pObPersistent->szNameLong)) { continue; }
        *pdwPID = pObProcess->dwPID;
        Ob_DECREF(pObProcess);
        return TRUE;
    }
    // 2: try locate process using short (eprocess) name
    while((pObProcess = VmmProcessGetNext(pObProcess, 0))) {
        if(pObProcess->dwState) { continue; }
        if(_strnicmp(szProcName, pObProcess->szName, 15)) { continue; }
        *pdwPID = pObProcess->dwPID;
        Ob_DECREF(pObProcess);
        return TRUE;
    }
    return FALSE;
}

_Success_(return)
BOOL VMMDLL_PidGetFromName(_In_ LPSTR szProcName, _Out_ PDWORD pdwPID)
{
    CALL_IMPLEMENTATION_VMM(
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
    if(!(pObProcess = VmmProcessGetEx(NULL, dwPID, VMM_FLAG_PROCESS_TOKEN))) { return FALSE; }
    ZeroMemory(pInfo, sizeof(VMMDLL_PROCESS_INFORMATION_MAGIC));
    // set general parameters
    pInfo->wVersion = VMMDLL_PROCESS_INFORMATION_VERSION;
    pInfo->wSize = sizeof(VMMDLL_PROCESS_INFORMATION);
    pInfo->tpMemoryModel = ctxVmm->tpMemoryModel;
    pInfo->tpSystem = ctxVmm->tpSystem;
    pInfo->fUserOnly = pObProcess->fUserOnly;
    pInfo->dwPID = dwPID;
    pInfo->dwPPID = pObProcess->dwPPID;
    pInfo->dwState = pObProcess->dwState;
    pInfo->paDTB = pObProcess->paDTB;
    pInfo->paDTB_UserOpt = pObProcess->paDTB_UserOpt;
    memcpy(pInfo->szName, pObProcess->szName, sizeof(pInfo->szName));
    strncpy_s(pInfo->szNameLong, sizeof(pInfo->szNameLong), pObProcess->pObPersistent->szNameLong, _TRUNCATE);
    // set operating system specific parameters
    if((ctxVmm->tpSystem == VMM_SYSTEM_WINDOWS_X64) || (ctxVmm->tpSystem == VMM_SYSTEM_WINDOWS_X86)) {
        if(ctxVmm->tpSystem == VMM_SYSTEM_WINDOWS_X64) {
            pInfo->win.fWow64 = pObProcess->win.fWow64;
            pInfo->win.vaPEB32 = pObProcess->win.vaPEB32;
        }
        pInfo->win.vaEPROCESS = pObProcess->win.EPROCESS.va;
        pInfo->win.vaPEB = pObProcess->win.vaPEB;
        pInfo->win.qwLUID = pObProcess->win.TOKEN.qwLUID;
        pInfo->win.dwSessionId = pObProcess->win.TOKEN.dwSessionId;
        if(pObProcess->win.TOKEN.szSID) {
            strncpy_s(pInfo->win.szSID, sizeof(pInfo->win.szSID), pObProcess->win.TOKEN.szSID, _TRUNCATE);
        }
    }
    Ob_DECREF(pObProcess);
    return TRUE;
}

_Success_(return)
BOOL VMMDLL_ProcessGetInformation(_In_ DWORD dwPID, _Inout_opt_ PVMMDLL_PROCESS_INFORMATION pProcessInformation, _In_ PSIZE_T pcbProcessInformation)
{
    CALL_IMPLEMENTATION_VMM(
        STATISTICS_ID_VMMDLL_ProcessGetInformation,
        VMMDLL_ProcessGetInformation_Impl(dwPID, pProcessInformation, pcbProcessInformation))
}

BOOL VMMDLL_ProcessGetInformationString_Impl_CallbackCriteria(_In_ PVMM_PROCESS pProcess, _In_ PVOID ctx)
{
    return !pProcess->pObPersistent->UserProcessParams.fProcessed;
}

VOID VMMDLL_ProcessGetInformationString_Impl_CallbackAction(_In_ PVMM_PROCESS pProcess, _In_ PVOID ctx)
{
    VmmWin_UserProcessParameters_Get(pProcess);
}

LPSTR VMMDLL_ProcessGetInformationString_Impl(_In_ DWORD dwPID, _In_ DWORD fOptionString)
{
    LPSTR sz = NULL, szStrDup = NULL;
    PVMM_PROCESS pObProcess = NULL;
    if(!(pObProcess = VmmProcessGet(dwPID))) { return FALSE; }
    switch(fOptionString) {
        case VMMDLL_PROCESS_INFORMATION_OPT_STRING_PATH_USER_IMAGE:
        case VMMDLL_PROCESS_INFORMATION_OPT_STRING_CMDLINE:
            if(!pObProcess->pObPersistent->UserProcessParams.fProcessed) {
                VmmProcessActionForeachParallel(NULL, 5, VMMDLL_ProcessGetInformationString_Impl_CallbackCriteria, VMMDLL_ProcessGetInformationString_Impl_CallbackAction);
            }
    }
    switch(fOptionString) {
        case VMMDLL_PROCESS_INFORMATION_OPT_STRING_PATH_KERNEL:
            sz = pObProcess->pObPersistent->szPathKernel;
            break;
        case VMMDLL_PROCESS_INFORMATION_OPT_STRING_PATH_USER_IMAGE:
            sz = pObProcess->pObPersistent->UserProcessParams.szImagePathName;
            break;
        case VMMDLL_PROCESS_INFORMATION_OPT_STRING_CMDLINE:
            sz = pObProcess->pObPersistent->UserProcessParams.szCommandLine;
            break;
    }
    szStrDup = Util_StrDupA(sz);
    Ob_DECREF(pObProcess);
    return szStrDup;
}

LPSTR VMMDLL_ProcessGetInformationString(_In_ DWORD dwPID, _In_ DWORD fOptionString)
{
    CALL_IMPLEMENTATION_VMM_RETURN(
        STATISTICS_ID_VMMDLL_ProcessGetInformationString,
        LPSTR,
        NULL,
        VMMDLL_ProcessGetInformationString_Impl(dwPID, fOptionString))
}

_Success_(return)
BOOL VMMDLL_ProcessGet_Directories_Sections_IAT_EAT_Impl(
    _In_ DWORD dwPID,
    _In_ LPWSTR wszModule,
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
    PVMMOB_MAP_MODULE pObModuleMap = NULL;
    PVMM_MAP_MODULEENTRY pModule = NULL;
    PVMM_PROCESS pObProcess = NULL;
    pObProcess = VmmProcessGet(dwPID);
    if(!pObProcess) { goto fail; }
    // fetch requested module
    if(!VmmMap_GetModule(pObProcess, &pObModuleMap)) { goto fail; }
    if(!(pModule = VmmMap_GetModuleEntry(pObModuleMap, wszModule))) { goto fail; }
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
        i = PE_SectionGetNumberOf(pObProcess, pModule->vaBase);
        if(!pSections) { *pcData = i; goto success; }
        if(cData < i) { goto fail; }
        VmmWin_PE_SECTION_DisplayBuffer(pObProcess, pModule, NULL, 0, NULL, &cData, pSections);
        *pcData = cData;
        goto success;
    }
    // export address table (EAT)
    if(fEAT) {
        i = PE_EatGetNumberOf(pObProcess, pModule->vaBase);
        if(!pEAT) { *pcData = i; goto success; }
        if(cData < i) { goto fail; }
        VmmWin_PE_LoadEAT_DisplayBuffer(pObProcess, pModule, (PVMMPROC_WINDOWS_EAT_ENTRY)pEAT, cData, &cData);
        *pcData = cData;
        goto success;
    }
    // import address table (IAT)
    if(fIAT) {
        i = PE_IatGetNumberOf(pObProcess, pModule->vaBase);
        if(!pIAT) { *pcData = i; goto success; }
        if(cData < i) { goto fail; }
        VmmWin_PE_LoadIAT_DisplayBuffer(pObProcess, pModule, (PVMMWIN_IAT_ENTRY)pIAT, cData, &cData);
        *pcData = cData;
        goto success;
    }
fail:
    Ob_DECREF(pObModuleMap);
    Ob_DECREF(pObProcess);
    return FALSE;
success:
    Ob_DECREF(pObModuleMap);
    Ob_DECREF(pObProcess);
    return TRUE;
}

_Success_(return)
BOOL VMMDLL_ProcessGetDirectories(_In_ DWORD dwPID, _In_ LPWSTR wszModule, _Out_writes_(16) PIMAGE_DATA_DIRECTORY pData, _In_ DWORD cData, _Out_ PDWORD pcData)
{
    CALL_IMPLEMENTATION_VMM(
        STATISTICS_ID_VMMDLL_ProcessGetDirectories,
        VMMDLL_ProcessGet_Directories_Sections_IAT_EAT_Impl(dwPID, wszModule, cData, pcData, pData, NULL, NULL, NULL, TRUE, FALSE, FALSE, FALSE))
}

_Success_(return)
BOOL VMMDLL_ProcessGetSections(_In_ DWORD dwPID, _In_ LPWSTR wszModule, _Out_opt_ PIMAGE_SECTION_HEADER pData, _In_ DWORD cData, _Out_ PDWORD pcData)
{
    CALL_IMPLEMENTATION_VMM(
        STATISTICS_ID_VMMDLL_ProcessGetSections,
        VMMDLL_ProcessGet_Directories_Sections_IAT_EAT_Impl(dwPID, wszModule, cData, pcData, NULL, pData, NULL, NULL, FALSE, TRUE, FALSE, FALSE))
}

_Success_(return)
BOOL VMMDLL_ProcessGetEAT(_In_ DWORD dwPID, _In_ LPWSTR wszModule, _Out_opt_ PVMMDLL_EAT_ENTRY pData, _In_ DWORD cData, _Out_ PDWORD pcData)
{
    CALL_IMPLEMENTATION_VMM(
        STATISTICS_ID_VMMDLL_ProcessGetEAT,
        VMMDLL_ProcessGet_Directories_Sections_IAT_EAT_Impl(dwPID, wszModule, cData, pcData, NULL, NULL, pData, NULL, FALSE, FALSE, TRUE, FALSE))
}

_Success_(return)
BOOL VMMDLL_ProcessGetIAT(_In_ DWORD dwPID, _In_ LPWSTR wszModule, _Out_opt_ PVMMDLL_IAT_ENTRY pData, _In_ DWORD cData, _Out_ PDWORD pcData)
{
    CALL_IMPLEMENTATION_VMM(
        STATISTICS_ID_VMMDLL_ProcessGetIAT,
        VMMDLL_ProcessGet_Directories_Sections_IAT_EAT_Impl(dwPID, wszModule, cData, pcData, NULL, NULL, NULL, pData, FALSE, FALSE, FALSE, TRUE))
}

ULONG64 VMMDLL_ProcessGetProcAddress_Impl(_In_ DWORD dwPID, _In_ LPWSTR wszModuleName, _In_ LPSTR szFunctionName)
{
    QWORD vaFn = 0;
    VMMDLL_MAP_MODULEENTRY oModuleEntry = { 0 };
    PVMM_PROCESS pObProcess = NULL;
    pObProcess = VmmProcessGet(dwPID);
    if(!pObProcess) { return 0; }
    if(VMMDLL_ProcessMap_GetModuleFromName_Impl(dwPID, wszModuleName, &oModuleEntry)) {
        vaFn = PE_GetProcAddress(pObProcess, oModuleEntry.vaBase, szFunctionName);
    }
    Ob_DECREF(pObProcess);
    return vaFn;
}

ULONG64 VMMDLL_ProcessGetProcAddress(_In_ DWORD dwPID, _In_ LPWSTR wszModuleName, _In_ LPSTR szFunctionName)
{
    CALL_IMPLEMENTATION_VMM_RETURN(
        STATISTICS_ID_VMMDLL_ProcessGetIAT,
        ULONG64,
        0,
        VMMDLL_ProcessGetProcAddress_Impl(dwPID, wszModuleName, szFunctionName))
}

ULONG64 VMMDLL_ProcessGetModuleBase_Impl(_In_ DWORD dwPID, _In_ LPWSTR wszModuleName)
{
    QWORD vaModuleBase = 0;
    PVMM_PROCESS pObProcess = NULL;
    VMMDLL_MAP_MODULEENTRY oModuleEntry = { 0 };
    if(!(pObProcess = VmmProcessGet(dwPID))) { return 0; }
    if(VMMDLL_ProcessMap_GetModuleFromName_Impl(dwPID, wszModuleName, &oModuleEntry)) {
        vaModuleBase = oModuleEntry.vaBase;
    }
    Ob_DECREF(pObProcess);
    return vaModuleBase;
}

ULONG64 VMMDLL_ProcessGetModuleBase(_In_ DWORD dwPID, _In_ LPWSTR wszModuleName)
{
    CALL_IMPLEMENTATION_VMM_RETURN(
        STATISTICS_ID_VMMDLL_ProcessGetModuleBase,
        ULONG64,
        0,
        VMMDLL_ProcessGetModuleBase_Impl(dwPID, wszModuleName))
}



//-----------------------------------------------------------------------------
// WINDOWS SPECIFIC REGISTRY FUNCTIONALITY BELOW:
//-----------------------------------------------------------------------------

/*
* Retrieve information about the registry hives in the target system.
* -- pHives = buffer of cHives * sizeof(VMMDLL_REGISTRY_HIVE_INFORMATION) to receive information about all hives. NULL to receive # hives in pcHives.
* -- cHives
* -- pcHives = if pHives == NULL: # total hives. if pHives: # read hives.
* -- return
*/
_Success_(return)
BOOL VMMDLL_WinReg_HiveList_Impl(_Out_writes_(cHives) PVMMDLL_REGISTRY_HIVE_INFORMATION pHives, _In_ DWORD cHives, _Out_ PDWORD pcHives)
{
    BOOL fResult = TRUE;
    POB_REGISTRY_HIVE pObHive = NULL;
    if(!pHives) {
        *pcHives = VmmWinReg_HiveCount();
        goto cleanup;
    }
    *pcHives = 0;
    while((pObHive = VmmWinReg_HiveGetNext(pObHive))) {
        if(*pcHives == cHives) {
            fResult = FALSE;
            goto cleanup;
        }
        memcpy(pHives + *pcHives, pObHive, sizeof(VMMDLL_REGISTRY_HIVE_INFORMATION));
        pHives->magic = VMMDLL_REGISTRY_HIVE_INFORMATION_MAGIC;
        pHives->wVersion = VMMDLL_REGISTRY_HIVE_INFORMATION_VERSION;
        pHives->wSize = sizeof(VMMDLL_REGISTRY_HIVE_INFORMATION);
        *pcHives += 1;
    }
cleanup:
    Ob_DECREF(pObHive);
    return fResult;
}

_Success_(return)
BOOL VMMDLL_WinReg_HiveList(_Out_writes_(cHives) PVMMDLL_REGISTRY_HIVE_INFORMATION pHives, _In_ DWORD cHives, _Out_ PDWORD pcHives)
{
    CALL_IMPLEMENTATION_VMM(
        STATISTICS_ID_VMMDLL_WinRegHive_List,
        VMMDLL_WinReg_HiveList_Impl(pHives, cHives, pcHives))
}

/*
* Read a contigious arbitrary amount of registry hive memory and report the
* number of bytes read in pcbRead.
* NB! Address space does not include regf registry hive file header!
* -- vaCMHive
* -- ra
* -- pb
* -- cb
* -- pcbRead
* -- flags = flags as in VMMDLL_FLAG_*
*/
_Success_(return)
BOOL VMMDLL_WinReg_HiveReadEx_Impl(_In_ ULONG64 vaCMHive, _In_ DWORD ra, _Out_ PBYTE pb, _In_ DWORD cb, _Out_opt_ PDWORD pcbReadOpt, _In_ ULONG64 flags)
{
    POB_REGISTRY_HIVE pObHive = VmmWinReg_HiveGetByAddress(vaCMHive);
    if(!pObHive) { return FALSE; }
    VmmWinReg_HiveReadEx(pObHive, ra, pb, cb, pcbReadOpt, flags);
    Ob_DECREF(pObHive);
    return TRUE;
}

_Success_(return)
BOOL VMMDLL_WinReg_HiveReadEx(_In_ ULONG64 vaCMHive, _In_ DWORD ra, _Out_ PBYTE pb, _In_ DWORD cb, _Out_opt_ PDWORD pcbReadOpt, _In_ ULONG64 flags)
{
    CALL_IMPLEMENTATION_VMM(
        STATISTICS_ID_VMMDLL_WinRegHive_ReadEx,
        VMMDLL_WinReg_HiveReadEx_Impl(vaCMHive, ra, pb, cb, pcbReadOpt, flags))
}

/*
* Write a virtually contigious arbitrary amount of memory to a registry hive.
* NB! Address space does not include regf registry hive file header!
* -- vaCMHive
* -- ra
* -- pb
* -- cb
* -- return = TRUE on success, FALSE on partial or zero write.
*/
_Success_(return)
BOOL VMMDLL_WinReg_HiveWrite_Impl(_In_ ULONG64 vaCMHive, _In_ DWORD ra, _In_ PBYTE pb, _In_ DWORD cb)
{
    BOOL f;
    POB_REGISTRY_HIVE pObHive = VmmWinReg_HiveGetByAddress(vaCMHive);
    if(!pObHive) { return FALSE; }
    f = VmmWinReg_HiveWrite(pObHive, ra, pb, cb);
    Ob_DECREF(pObHive);
    return f;
}

_Success_(return)
BOOL VMMDLL_WinReg_HiveWrite(_In_ ULONG64 vaCMHive, _In_ DWORD ra, _In_ PBYTE pb, _In_ DWORD cb)
{
    CALL_IMPLEMENTATION_VMM(
        STATISTICS_ID_VMMDLL_WinRegHive_Write,
        VMMDLL_WinReg_HiveWrite_Impl(vaCMHive, ra, pb, cb))
}

_Success_(return)
BOOL VMMDLL_WinReg_EnumKeyExW_Impl(_In_ LPWSTR wszFullPathKey, _In_ DWORD dwIndex, _Out_writes_opt_(*lpcchName) LPWSTR lpName, _Inout_ LPDWORD lpcchName, _Out_opt_ PFILETIME lpftLastWriteTime)
{
    BOOL f;
    VMM_REGISTRY_KEY_INFO KeyInfo = { 0 };
    WCHAR wszPathKey[MAX_PATH];
    POB_REGISTRY_HIVE pObHive = NULL;
    POB_REGISTRY_KEY pObKey = NULL, pObSubKey = NULL;
    POB_MAP pmObSubKeys = NULL;
    if(lpName && !*lpcchName) {
        if(lpftLastWriteTime) { *(PQWORD)lpftLastWriteTime = 0; }
        return FALSE;
    }
    f = VmmWinReg_PathHiveGetByFullPath(wszFullPathKey, &pObHive, wszPathKey) &&
        (pObKey = VmmWinReg_KeyGetByPath(pObHive, wszPathKey)) &&
        (pmObSubKeys = VmmWinReg_KeyList(pObHive, pObKey)) &&
        (pObSubKey = ObMap_GetByIndex(pmObSubKeys, dwIndex));
    if(f) { VmmWinReg_KeyInfo(pObHive, pObSubKey, &KeyInfo); }
    f = f && (!lpName || (KeyInfo.cchName <= *lpcchName));
    if(lpName) { wcsncpy_s(lpName, *lpcchName, KeyInfo.wszName, _TRUNCATE); };
    if(lpftLastWriteTime) { *(PQWORD)lpftLastWriteTime = KeyInfo.ftLastWrite; }
    *lpcchName = KeyInfo.cchName;
    Ob_DECREF(pObSubKey);
    Ob_DECREF(pmObSubKeys);
    Ob_DECREF(pObKey);
    Ob_DECREF(pObHive);
    return f;
}

_Success_(return)
BOOL VMMDLL_WinReg_EnumValueW_Impl(_In_ LPWSTR wszFullPathKey, _In_ DWORD dwIndex, _Out_writes_opt_(*lpcchName) LPWSTR lpName, _Inout_ LPDWORD lpcchName, _Out_opt_ LPDWORD lpType, _Out_writes_opt_(*lpcbData) LPBYTE lpData, _Inout_opt_ LPDWORD lpcbData)
{
    BOOL f;
    VMM_REGISTRY_VALUE_INFO ValueInfo = { 0 };
    WCHAR wszPathKey[MAX_PATH];
    POB_REGISTRY_HIVE pObHive = NULL;
    POB_REGISTRY_KEY pObKey = NULL;
    POB_MAP pmObValues = NULL;
    POB_REGISTRY_VALUE pObValue = NULL;
    if((lpName && !*lpcchName) || (lpData && (!lpcbData || !*lpcbData))) {
        if(lpType) { *lpType = 0; }
        if(lpcbData) { *lpcbData = 0; }
        return FALSE;
    }
    f = VmmWinReg_PathHiveGetByFullPath(wszFullPathKey, &pObHive, wszPathKey) &&
        (pObKey = VmmWinReg_KeyGetByPath(pObHive, wszPathKey)) &&
        (pmObValues = VmmWinReg_KeyValueList(pObHive, pObKey)) &&
        (pObValue = ObMap_GetByIndex(pmObValues, dwIndex));
    if(f) { VmmWinReg_ValueInfo(pObHive, pObValue, &ValueInfo); }
    f = f && (!lpName || (ValueInfo.cchName <= *lpcchName));
    if(lpName) { wcsncpy_s(lpName, *lpcchName, ValueInfo.wszName, _TRUNCATE); };
    if(lpType) { *lpType = ValueInfo.dwType; }
    *lpcchName = ValueInfo.cchName;
    if(f && lpData) {
        f = VmmWinReg_ValueQuery4(pObHive, pObValue, NULL, lpData, *lpcbData, lpcbData);
    } else if(lpcbData) {
        *lpcbData = ValueInfo.cbData;
    }
    Ob_DECREF(pObValue);
    Ob_DECREF(pObKey);
    Ob_DECREF(pmObValues);
    Ob_DECREF(pObHive);
    return f;
}

_Success_(return)
BOOL VMMDLL_WinReg_EnumKeyExW(_In_ LPWSTR wszFullPathKey, _In_ DWORD dwIndex, _Out_writes_opt_(*lpcchName) LPWSTR lpName, _Inout_ LPDWORD lpcchName, _Out_opt_ PFILETIME lpftLastWriteTime)
{
    CALL_IMPLEMENTATION_VMM(
        STATISTICS_ID_VMMDLL_WinReg_EnumKeyExW,
        VMMDLL_WinReg_EnumKeyExW_Impl(wszFullPathKey, dwIndex, lpName, lpcchName, lpftLastWriteTime))
}

_Success_(return)
BOOL VMMDLL_WinReg_EnumValueW(_In_ LPWSTR wszFullPathKey, _In_ DWORD dwIndex, _Out_writes_opt_(*lpcchValueName) LPWSTR lpValueName, _Inout_ LPDWORD lpcchValueName, _Out_opt_ LPDWORD lpType, _Out_writes_opt_(*lpcbData) LPBYTE lpData, _Inout_opt_ LPDWORD lpcbData)
{
    CALL_IMPLEMENTATION_VMM(
        STATISTICS_ID_VMMDLL_WinReg_EnumValueW,
        VMMDLL_WinReg_EnumValueW_Impl(wszFullPathKey, dwIndex, lpValueName, lpcchValueName, lpType, lpData, lpcbData))
}

_Success_(return)
BOOL VMMDLL_WinReg_QueryValueExW( _In_ LPWSTR wszFullPathKeyValue, _Out_opt_ LPDWORD lpType, _Out_writes_opt_(*lpcbData) LPBYTE lpData, _When_(lpData == NULL, _Out_opt_) _When_(lpData != NULL, _Inout_opt_) LPDWORD lpcbData)
{
    CALL_IMPLEMENTATION_VMM(
        STATISTICS_ID_VMMDLL_WinReg_QueryValueExW,
        VmmWinReg_ValueQuery2(wszFullPathKeyValue, lpType, lpData, lpcbData ? *lpcbData : 0, lpcbData))
}



//-----------------------------------------------------------------------------
// WINDOWS SPECIFIC NETWORKING FUNCTIONALITY BELOW:
//-----------------------------------------------------------------------------

/*
* Retrieve networking information about network connections related to Windows TCP/IP stack.
* NB! CALLER IS RESPONSIBLE FOR LocalFree return value!
* CALLER LocalFree: return
* -- return - fail: NULL, success: a PVMMDLL_WIN_TCPIP struct scontaining the result - NB! Caller responsible for LocalFree!
*/
PVMMDLL_WIN_TCPIP VMMDLL_WinNet_Get_Impl()
{
    DWORD cTcpE;
    PVMMDLL_WIN_TCPIP pWinTcpIp;
    PVMMWIN_TCPIP_ENTRY pTcpE = NULL;
    if(!VmmWinTcpIp_TcpE_Get(&pTcpE, &cTcpE)) {
        return NULL;
    }
    if(!(pWinTcpIp = LocalAlloc(0, sizeof(VMMDLL_WIN_TCPIP) + cTcpE * sizeof(VMMDLL_WIN_TCPIP_ENTRY)))) {
        LocalFree(pTcpE);
        return NULL;
    }
    pWinTcpIp->magic = VMMDLL_WIN_TCPIP_MAGIC;
    pWinTcpIp->dwVersion = VMMDLL_WIN_TCPIP_VERSION;
    pWinTcpIp->cTcpE = cTcpE;
    memcpy(pWinTcpIp->pTcpE, pTcpE, cTcpE * sizeof(VMMDLL_WIN_TCPIP_ENTRY));
    LocalFree(pTcpE);
    return pWinTcpIp;
}

PVMMDLL_WIN_TCPIP VMMDLL_WinNet_Get()
{
    CALL_IMPLEMENTATION_VMM_RETURN(
        STATISTICS_ID_VMMDLL_WinNet_Get,
        PVMMDLL_WIN_TCPIP,
        NULL,
        VMMDLL_WinNet_Get_Impl())
}



//-----------------------------------------------------------------------------
// WINDOWS SPECIFIC UTILITY FUNCTIONS BELOW:
//-----------------------------------------------------------------------------

_Success_(return)
BOOL VMMDLL_WinGetThunkInfoEAT_Impl(_In_ DWORD dwPID, _In_ LPWSTR wszModuleName, _In_ LPSTR szExportFunctionName, _Out_ PVMMDLL_WIN_THUNKINFO_EAT pThunkInfoEAT)
{
    BOOL f;
    PVMM_PROCESS pObProcess = NULL;
    VMMDLL_MAP_MODULEENTRY oModuleEntry = { 0 };
    f = (pObProcess = VmmProcessGet(dwPID)) &&
        VMMDLL_ProcessMap_GetModuleFromName_Impl(dwPID, wszModuleName, &oModuleEntry) &&
        PE_GetThunkInfoEAT(pObProcess, oModuleEntry.vaBase, szExportFunctionName, (PPE_THUNKINFO_EAT)pThunkInfoEAT);
    Ob_DECREF(pObProcess);
    return f;
}

_Success_(return)
BOOL VMMDLL_WinGetThunkInfoEAT(_In_ DWORD dwPID, _In_ LPWSTR wszModuleName, _In_ LPSTR szExportFunctionName, _Out_ PVMMDLL_WIN_THUNKINFO_EAT pThunkInfoEAT)
{
    CALL_IMPLEMENTATION_VMM(
        STATISTICS_ID_VMMDLL_WinGetThunkEAT,
        VMMDLL_WinGetThunkInfoEAT_Impl(dwPID, wszModuleName, szExportFunctionName, pThunkInfoEAT))
}

_Success_(return)
BOOL VMMDLL_WinGetThunkInfoIAT_Impl(_In_ DWORD dwPID, _In_ LPWSTR wszModuleName, _In_ LPSTR szImportModuleName, _In_ LPSTR szImportFunctionName, _Out_ PVMMDLL_WIN_THUNKINFO_IAT pThunkInfoIAT)
{
    BOOL f = FALSE;
    PVMM_PROCESS pObProcess = NULL;
    VMMDLL_MAP_MODULEENTRY oModuleEntry = { 0 };
    f = (sizeof(VMMDLL_WIN_THUNKINFO_IAT) == sizeof(PE_THUNKINFO_IAT)) &&
        (pObProcess = VmmProcessGet(dwPID)) &&
        VMMDLL_ProcessMap_GetModuleFromName_Impl(dwPID, wszModuleName, &oModuleEntry) &&
        PE_GetThunkInfoIAT(pObProcess, oModuleEntry.vaBase, szImportModuleName, szImportFunctionName, (PPE_THUNKINFO_IAT)pThunkInfoIAT);
    Ob_DECREF(pObProcess);
    return f;
}

_Success_(return)
BOOL VMMDLL_WinGetThunkInfoIAT(_In_ DWORD dwPID, _In_ LPWSTR wszModuleName, _In_ LPSTR szImportModuleName, _In_ LPSTR szImportFunctionName, _Out_ PVMMDLL_WIN_THUNKINFO_IAT pThunkInfoIAT)
{
    CALL_IMPLEMENTATION_VMM(
        STATISTICS_ID_VMMDLL_WinGetThunkIAT,
        VMMDLL_WinGetThunkInfoIAT_Impl(dwPID, wszModuleName, szImportModuleName, szImportFunctionName, pThunkInfoIAT))
}



//-----------------------------------------------------------------------------
// WINDOWS SPECIFIC DEBUGGING / SYMBOL FUNCTIONALITY BELOW:
//-----------------------------------------------------------------------------

_Success_(return)
BOOL VMMDLL_PdbSymbolAddress_Impl(_In_ LPSTR szModule, _In_ LPSTR szSymbolName, _Out_ PULONG64 pvaSymbolAddress)
{
    VMMWIN_PDB_HANDLE hPdb = PDB_GetHandleFromModuleName(szModule);
    return PDB_GetSymbolAddress(hPdb, szSymbolName, pvaSymbolAddress);
}

_Success_(return)
BOOL VMMDLL_PdbSymbolAddress(_In_ LPSTR szModule, _In_ LPSTR szSymbolName, _Out_ PULONG64 pvaSymbolAddress)
{
    CALL_IMPLEMENTATION_VMM(
        STATISTICS_ID_VMMDLL_PdbSymbolAddress,
        VMMDLL_PdbSymbolAddress_Impl(szModule, szSymbolName, pvaSymbolAddress))
}

_Success_(return)
BOOL VMMDLL_PdbTypeSize_Impl(_In_ LPSTR szModule, _In_ LPSTR szTypeName, _Out_ PDWORD pcbTypeSize)
{
    VMMWIN_PDB_HANDLE hPdb = PDB_GetHandleFromModuleName(szModule);
    return PDB_GetTypeSize(hPdb, szTypeName, pcbTypeSize);
}

_Success_(return)
BOOL VMMDLL_PdbTypeSize(_In_ LPSTR szModule, _In_ LPSTR szTypeName, _Out_ PDWORD pcbTypeSize)
{
    CALL_IMPLEMENTATION_VMM(
        STATISTICS_ID_VMMDLL_PdbTypeSize,
        VMMDLL_PdbTypeSize_Impl(szModule, szTypeName, pcbTypeSize))
}

_Success_(return)
BOOL VMMDLL_PdbTypeChildOffset_Impl(_In_ LPSTR szModule, _In_ LPSTR szTypeName, _In_ LPWSTR wszTypeChildName, _Out_ PDWORD pcbTypeChildOffset)
{
    VMMWIN_PDB_HANDLE hPdb = PDB_GetHandleFromModuleName(szModule);
    return PDB_GetTypeChildOffset(hPdb, szTypeName, wszTypeChildName, pcbTypeChildOffset);
}

_Success_(return)
BOOL VMMDLL_PdbTypeChildOffset(_In_ LPSTR szModule, _In_ LPSTR szTypeName, _In_ LPWSTR wszTypeChildName, _Out_ PDWORD pcbTypeChildOffset)
{
    CALL_IMPLEMENTATION_VMM(
        STATISTICS_ID_VMMDLL_PdbTypeChildOffset,
        VMMDLL_PdbTypeChildOffset_Impl(szModule, szTypeName, wszTypeChildName, pcbTypeChildOffset))
}




//-----------------------------------------------------------------------------
// VMM UTIL FUNCTIONALITY BELOW:
//-----------------------------------------------------------------------------

_Success_(return)
BOOL VMMDLL_UtilFillHexAscii(_In_ PBYTE pb, _In_ DWORD cb, _In_ DWORD cbInitialOffset, _Out_opt_ LPSTR sz, _Inout_ PDWORD pcsz)
{
    CALL_IMPLEMENTATION_VMM(
        STATISTICS_ID_VMMDLL_UtilFillHexAscii,
        Util_FillHexAscii(pb, cb, cbInitialOffset, sz, pcsz))
}
