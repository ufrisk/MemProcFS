// vmmdll.h : implementation of core dynamic link library (dll) functionality
// of the virtual memory manager (VMM) for The Memory Process File System.
//
// (c) Ulf Frisk, 2018
// Author: Ulf Frisk, pcileech@frizk.net
//

#include "vmmdll.h"
#include "device.h"
#include "pluginmanager.h"
#include "util.h"
#include "pe.h"
#include "vmm.h"
#include "vmmproc.h"
#include "vmmwin.h"
#include "vmmvfs.h"

// ----------------------------------------------------------------------------
// Synchronization macro below. The VMM isn't thread safe so it's important to
// serialize access to it over the VMM MasterLock. This master lock is shared
// with internal VMM housekeeping functionality.
// ----------------------------------------------------------------------------

#define CALL_SYNCHRONIZED_IMPLEMENTATION_VMM(id, fn)   {                    \
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

#define CALL_SYNCHRONIZED_IMPLEMENTATION_VMM_NTSTATUS(id, fn)   {           \
    QWORD tm;                                                               \
    NTSTATUS nt;                                                            \
    if(!ctxVmm) { return ((NTSTATUS)0xC0000001L); } /* UNSUCCESSFUL */      \
    tm = Statistics_CallStart();                                            \
    VmmLockAcquire();                                                       \
    nt = fn;                                                                \
    VmmLockRelease();                                                       \
    Statistics_CallEnd(id, tm);                                             \
    return nt;                                                              \
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
        } else if(0 == _stricmp(argv[i], "-vdll")) {
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
        } else if(i + 1 >= argc) {
            return FALSE;
        } else if(0 == strcmp(argv[i], "-cr3")) {
            ctxMain->cfg.paCR3 = Util_GetNumeric(argv[i + 1]);
            i += 2;
            continue;
        } else if(0 == strcmp(argv[i], "-max")) {
            ctxMain->cfg.paAddrMax = Util_GetNumeric(argv[i + 1]);
            i += 2;
            continue;
        } else if(0 == strcmp(argv[i], "-device")) {
            strcpy_s(ctxMain->cfg.szDevTpOrFileName, MAX_PATH, argv[i + 1]);
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
    if(ctxMain->cfg.paAddrMax == 0) { ctxMain->cfg.paAddrMax = 0x0000ffffffffffff; }
    if(ctxMain->cfg.paAddrMax < 0x00100000) { return FALSE; }
    ctxMain->cfg.fVerbose = ctxMain->cfg.fVerbose && ctxMain->cfg.fVerboseDll;
    ctxMain->cfg.fVerboseExtra = ctxMain->cfg.fVerboseExtra && ctxMain->cfg.fVerboseDll;
    ctxMain->cfg.fVerboseExtraTlp = ctxMain->cfg.fVerboseExtraTlp && ctxMain->cfg.fVerboseDll;
    return (ctxMain->cfg.szDevTpOrFileName[0] != 0);
}

VOID VmmDll_PrintHelp()
{
    vmmprintf(
        "                                                                               \n" \
        " THE MEMORY PROCESS FILE SYSTEM v%i.%i.%i COMMAND LINE REFERENCE:              \n" \
        " The Memory Process File System may be used in stand-alone mode with support   \n" \
        " for memory dump files or together with PCILeech if pcileech.dll is placed in  \n" \
        " the application directory.   For information about PCILeech and requirements  \n" \
        " please consult the separate PCILeech documenation.                            \n" \
        " -----                                                                         \n" \
        " The Memory Process File System (c) 2018 Ulf Frisk                             \n" \
        " License: GNU GENERAL PUBLIC LICENSE - Version 3, 29 June 2007                 \n" \
        " Contact information: pcileech@frizk.net                                       \n" \
        " The Memory Process File System: https://github.com/ufrisk/MemProcFS           \n" \
        " PCILeech:                       https://github.com/ufrisk/pcileech            \n" \
        " -----                                                                         \n" \
        " The recommended way to use the Memory Process File System is to specify the   \n" \
        " memory acquisition device in the -device option and possibly more options.    \n" \
        " Example 1: MemProcFS.exe -device c:\\temp\\memdump-win10x64.pmem              \n" \
        " Example 2: MemProcFS.exe -device c:\\temp\\memdump-winXPx86.pmem -v -vv       \n" \
        " Example 3: MemProcFS.exe -device FPGA                                         \n" \
        " The Memory Process File System may also be started the memory dump file name  \n" \
        " as the only option. This allows to make file extensions associated so that    \n" \
        " they may be opened by double-clicking on them. This mode allows no options.   \n" \
        " Example 4: MemProcFS.exe c:\\dumps\\memdump-win7x64.pmem                      \n" \
        " -----                                                                         \n" \
        " Valid options:                                                                \n" \
        "   -device: select memory acquisition device or raw memory dump file to use.   \n" \
        "          Valid options: <memory_dump_file>, FPGA, TOTALMELTDOWN               \n" \
        "          <memory_dump_file> = memory dump file name optionally including path.\n" \
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
        "   -pythonpath : specify the path to a python 3.6 installation for Windows.    \n" \
        "          The path given should be to the directory that contain: python36.dll \n" \
        "          Example: -pythonpath \"C:\\Program Files\\Python36\"                 \n" \
        "   -mount : drive letter to mount The Memory Process File system at.           \n" \
        "          default: M   Example: -mount Q                                       \n" \
        "   -identify : scan memory for the operating system and the kernel page table. \n" \
        "          This may help if the default auto-detect is not working.             \n" \
        "          Option has no value. Example: -identify                              \n" \
        "                                                                               \n",
        VMM_VERSION_MAJOR, VMM_VERSION_MINOR, VMM_VERSION_REVISION
    );
}

VOID VmmDll_FreeContext()
{
    if(ctxVmm) {
        VmmClose();
    }
    if(ctxMain) {
        Statistics_CallSetEnabled(FALSE);
        DeviceClose();
        LocalFree(ctxMain);
        ctxMain = NULL;
    }
}

_Success_(return)
BOOL VMMDLL_InitializeReserved(_In_ DWORD argc, _In_ LPSTR argv[])
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
    if(!DeviceOpen()) {
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
BOOL VMMDLL_InitializeFile(_In_ LPSTR szFileName, _In_opt_ LPSTR szPageTableBaseOpt)
{
    return VMMDLL_InitializeReserved(5, (LPSTR[]) { "", "-device", szFileName, "-cr3", (szPageTableBaseOpt ? szPageTableBaseOpt : "0") });
}

_Success_(return)
BOOL VMMDLL_InitializeFPGA(_In_opt_ LPSTR szMaxPhysicalAddressOpt, _In_opt_ LPSTR szPageTableBaseOpt)
{
    return VMMDLL_InitializeReserved(7, (LPSTR[]) { "", "-device", "fpga", "-cr3", (szPageTableBaseOpt ? szPageTableBaseOpt : "0", "-max", szMaxPhysicalAddressOpt) });
}

_Success_(return)
BOOL VMMDLL_InitializeTotalMeltdown()
{
    return VMMDLL_InitializeReserved(3, (LPSTR[]) { "", "-device", "totalmeltdown" });
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
            *pqwValue = VMM_VERSION_MAJOR;
            return TRUE;
        } else if(fOption == VMMDLL_OPT_CONFIG_VMM_VERSION_MINOR) {
            *pqwValue = VMM_VERSION_MINOR;
            return TRUE;
        } else if(fOption == VMMDLL_OPT_CONFIG_VMM_VERSION_REVISION) {
            *pqwValue = VMM_VERSION_REVISION;
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
                *pqwValue = ctxMain->dev.paAddrMaxNative;
                return TRUE;
            case VMMDLL_OPT_CORE_MAX_NATIVE_IOSIZE:
                *pqwValue = ctxMain->dev.qwMaxSizeMemIo;
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
    return DeviceGetOption(fOption, pqwValue);
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
    // core options affecting both vmm.dll and pcileech.dll
    if(fOption & 0x80000000) {
        DeviceSetOption(fOption, qwValue); // also set option in pcileech.dll (if existing).
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
    // non-recognized option - possibly a device option to pass along to pcileech.dll
    return DeviceSetOption(fOption, qwValue);
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
    CALL_SYNCHRONIZED_IMPLEMENTATION_VMM_NTSTATUS(
        STATISTICS_ID_VMMDLL_VfsRead,
        VmmVfs_Read(wcsFileName, pb, cb, pcbRead, cbOffset))
}

NTSTATUS VMMDLL_VfsWrite(_In_ LPCWSTR wcsFileName, _In_ LPVOID pb, _In_ DWORD cb, _Out_ PDWORD pcbWrite, _In_ ULONG64 cbOffset)
{
    CALL_SYNCHRONIZED_IMPLEMENTATION_VMM_NTSTATUS(
        STATISTICS_ID_VMMDLL_VfsWrite,
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
// VMM CORE FUNCTIONALITY BELOW:
//-----------------------------------------------------------------------------

DWORD VMMDLL_MemReadScatter(_In_ DWORD dwPID, _Inout_ PPVMMDLL_MEM_IO_SCATTER_HEADER ppMEMs, _In_ DWORD cpMEMs, _In_ DWORD flags)
{
    DWORD i, cMEMs;
    PVMM_PROCESS pProcess = NULL;
    if(!ctxVmm) { return 0; }
    VmmLockAcquire();
    if(dwPID == -1) {
        VmmReadScatterPhysical((PPMEM_IO_SCATTER_HEADER)ppMEMs, cpMEMs, flags);
    } else {
        pProcess = VmmProcessGet(dwPID);
        if(!pProcess) {
            VmmLockRelease();
            return FALSE;
        }
        VmmReadScatterVirtual(pProcess, (PPMEM_IO_SCATTER_HEADER)ppMEMs, cpMEMs, flags);
    }
    for(i = 0, cMEMs = 0; i < cpMEMs; i++) {
        if(ppMEMs[i]->cb == ppMEMs[i]->cbMax) {
            cMEMs++;
        }
    }
    VmmLockRelease();
    return cMEMs;
}

_Success_(return)
BOOL VMMDLL_MemReadEx_Impl(_In_ DWORD dwPID, _In_ ULONG64 qwVA, _Out_ PBYTE pb, _In_ DWORD cb, _Out_opt_ PDWORD pcbReadOpt, _In_ ULONG64 flags)
{
    PVMM_PROCESS pProcess = NULL;
    if(dwPID != -1) {
        pProcess = VmmProcessGet(dwPID);
        if(!pProcess) { return FALSE; }
    }
    VmmReadEx(pProcess, qwVA, pb, cb, pcbReadOpt, flags);
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
BOOL VMMDLL_MemWrite_Impl(_In_ DWORD dwPID, _In_ ULONG64 qwVA, _In_ PBYTE pb, _In_ DWORD cb)
{
    PVMM_PROCESS pProcess = NULL;
    if(dwPID != -1) {
        pProcess = VmmProcessGet(dwPID);
        if(!pProcess) { return FALSE; }
    }
    return VmmWrite(pProcess, qwVA, pb, cb);
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
    PVMM_PROCESS pProcess = VmmProcessGet(dwPID);
    if(!pProcess) { return FALSE; }
    return VmmVirt2Phys(pProcess, qwVA, pqwPA);
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
    PVMM_PROCESS pProcess = VmmProcessGet(dwPID);
    if(!pProcess) { return FALSE; }
    if(!pProcess->pMemMap || !pProcess->cMemMap) {
        if(!pProcess->fSpiderPageTableDone) {
            VmmTlbSpider(pProcess->paDTB, pProcess->fUserOnly);
            pProcess->fSpiderPageTableDone = TRUE;
        }
        VmmMapInitialize(pProcess);
        if(fIdentifyModules) {
            VmmProc_InitializeModuleNames(pProcess);
        }
    }
    if(!pMemMapEntries) {
        *pcMemMapEntries = pProcess->cMemMap;
    } else {
        if(!pProcess->pMemMap || (*pcMemMapEntries < pProcess->cMemMap)) { return FALSE; }
        memcpy(pMemMapEntries, pProcess->pMemMap, sizeof(VMMDLL_MEMMAP_ENTRY) * pProcess->cMemMap);
        *pcMemMapEntries = pProcess->cMemMap;
    }
    return TRUE;
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
    PVMM_PROCESS pProcess = VmmProcessGet(dwPID);
    PVMM_MEMMAP_ENTRY e;
    if(!pProcess) { return FALSE; }
    if(fIdentifyModules) {
        VmmMapInitialize(pProcess);
        VmmProc_InitializeModuleNames(pProcess);
    }
    if(!pProcess->pMemMap) {
        VmmMapInitialize(pProcess);
    }
    e = VmmMapGetEntry(pProcess, va);
    if(!e) { return FALSE; }
    memcpy(pMemMapEntry, e, sizeof(VMM_MEMMAP_ENTRY));
    return TRUE;
}

_Success_(return)
BOOL VMMDLL_ProcessGetMemoryMapEntry(_In_ DWORD dwPID, _Out_ PVMMDLL_MEMMAP_ENTRY pMemMapEntry, _In_ ULONG64 va, _In_ BOOL fIdentifyModules)
{
    CALL_SYNCHRONIZED_IMPLEMENTATION_VMM(
        STATISTICS_ID_VMMDLL_ProcessGetMemoryMapEntry,
        VMMDLL_ProcessGetMemoryMapEntry_Impl(dwPID, pMemMapEntry, va, fIdentifyModules))
}

_Success_(return)
BOOL VMMDLL_ProcessGetModuleMap_Impl(_In_ DWORD dwPID, _Out_opt_ PVMMDLL_MODULEMAP_ENTRY pModuleEntries, _Inout_ PULONG64 pcModuleEntries)
{
    ULONG64 i;
    PVMM_PROCESS pProcess = VmmProcessGet(dwPID);
    if(!pProcess) { return FALSE; }
    if(!pcModuleEntries) { return FALSE; }
    if(!pProcess->pModuleMap || !pProcess->cModuleMap) {
        if(!pProcess->fSpiderPageTableDone) {
            VmmTlbSpider(pProcess->paDTB, pProcess->fUserOnly);
            pProcess->fSpiderPageTableDone = TRUE;
        }
        VmmProc_InitializeModuleNames(pProcess);
    }
    if(!pModuleEntries) {
        *pcModuleEntries = pProcess->cModuleMap;
    } else {
        if(!pProcess->pModuleMap || (*pcModuleEntries < pProcess->cModuleMap)) { return FALSE; }
        for(i = 0; i < pProcess->cModuleMap; i++) {
            memcpy(pModuleEntries + i, pProcess->pModuleMap + i, sizeof(VMMDLL_MODULEMAP_ENTRY));
        }
        *pcModuleEntries = pProcess->cModuleMap;
    }
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
    DWORD i, pdwPIDs[1024];
    SIZE_T cPIDs = 1024;
    PVMM_PROCESS pProcess;
    VmmProcessListPIDs(pdwPIDs, &cPIDs);
    for(i = 0; i < cPIDs; i++) {
        pProcess = VmmProcessGet(pdwPIDs[i]);
        if(!pProcess) { return FALSE; }
        if(_strnicmp(szProcName, pProcess->szName, 15)) { continue; }
        if(pProcess->dwState) { continue; }
        *pdwPID = pdwPIDs[i];
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
    PVMM_PROCESS pProcess;
    if(!pcbProcessInfo) { return FALSE; }
    if(!pInfo) {
        *pcbProcessInfo = sizeof(VMMDLL_PROCESS_INFORMATION);
        return TRUE;
    }
    if(*pcbProcessInfo < sizeof(VMMDLL_PROCESS_INFORMATION)) { return FALSE; }
    if(pInfo->magic != VMMDLL_PROCESS_INFORMATION_MAGIC) { return FALSE; }
    if(pInfo->wVersion != VMMDLL_PROCESS_INFORMATION_VERSION) { return FALSE; }
    if(!(pProcess = VmmProcessGet(dwPID))) { return FALSE; }
    ZeroMemory(pInfo, sizeof(VMMDLL_PROCESS_INFORMATION_MAGIC));
    // set general parameters
    pInfo->wVersion = VMMDLL_PROCESS_INFORMATION_VERSION;
    pInfo->wSize = sizeof(VMMDLL_PROCESS_INFORMATION);
    pInfo->tpMemoryModel = ctxVmm->tpMemoryModel;
    pInfo->tpSystem = ctxVmm->tpSystem;
    pInfo->fUserOnly = pProcess->fUserOnly;
    pInfo->dwPID = dwPID;
    pInfo->dwState = pProcess->dwState;
    pInfo->paDTB = pProcess->paDTB;
    pInfo->paDTB_UserOpt = pProcess->paDTB_UserOpt;
    memcpy(pInfo->szName, pProcess->szName, sizeof(pInfo->szName));
    // set operating system specific parameters
    switch(ctxVmm->tpSystem) {
        case VMM_SYSTEM_WINDOWS_X64:
            pInfo->os.win.fWow64 = pProcess->os.win.fWow64;
            pInfo->os.win.vaENTRY = pProcess->os.win.vaENTRY;
            pInfo->os.win.vaEPROCESS = pProcess->os.win.vaEPROCESS;
            pInfo->os.win.vaPEB = pProcess->os.win.vaPEB;
            pInfo->os.win.vaPEB32 = pProcess->os.win.vaPEB32;
            break;
        case VMM_SYSTEM_WINDOWS_X86:
            pInfo->os.win.vaENTRY = pProcess->os.win.vaENTRY;
            pInfo->os.win.vaEPROCESS = pProcess->os.win.vaEPROCESS;
            pInfo->os.win.vaPEB = pProcess->os.win.vaPEB;
            break;
    }
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
    PVMM_MODULEMAP_ENTRY pModule = NULL;
    PVMM_PROCESS pProcess = VmmProcessGet(dwPID);
    if(!pProcess) { return FALSE; }
    // genereate module map (if required)
    if(!pProcess->pModuleMap || !pProcess->cModuleMap) {
        if(!pProcess->fSpiderPageTableDone) {
            VmmTlbSpider(pProcess->paDTB, pProcess->fUserOnly);
            pProcess->fSpiderPageTableDone = TRUE;
        }
        VmmProc_InitializeModuleNames(pProcess);
        if(!pProcess->pModuleMap || !pProcess->cModuleMap) { return FALSE; }
    }
    // fetch requested module
    for(i = 0; i < pProcess->cModuleMap; i++) {
        if(!_stricmp(pProcess->pModuleMap[i].szName, szModule)) {
            pModule = &pProcess->pModuleMap[i];
        }
    }
    if(!pModule) { return FALSE; }
    // data directories
    if(fDataDirectory) {
        if(!pDataDirectory) { *pcData = 16; return TRUE; }
        if(cData < 16) { return FALSE; }
        VmmWin_PE_DIRECTORY_DisplayBuffer(pProcess, pModule, NULL, 0, NULL, pDataDirectory);
        *pcData = 16;
        return TRUE;
    }
    // sections
    if(fSections) {
        i = PE_SectionGetNumberOf(pProcess, pModule->BaseAddress);
        if(!pSections) { *pcData = i; return TRUE; }
        if(cData < i) { return FALSE; }
        VmmWin_PE_SECTION_DisplayBuffer(pProcess, pModule, NULL, 0, NULL, &cData, pSections);
        *pcData = cData;
        return TRUE;
    }
    // export address table (EAT)
    if(fEAT) {
        i = PE_EatGetNumberOf(pProcess, pModule->BaseAddress);
        if(!pEAT) { *pcData = i; return TRUE; }
        if(cData < i) { return FALSE; }
        VmmWin_PE_LoadEAT_DisplayBuffer(pProcess, pModule, (PVMMPROC_WINDOWS_EAT_ENTRY)pEAT, &cData);
        *pcData = cData;
        return TRUE;
    }
    // import address table (IAT)
    if(fIAT) {
        i = PE_IatGetNumberOf(pProcess, pModule->BaseAddress);
        if(!pIAT) { *pcData = i; return TRUE; }
        if(cData < i) { return FALSE; }
        VmmWin_PE_LoadIAT_DisplayBuffer(pProcess, pModule, (PVMMWIN_IAT_ENTRY)pIAT, &cData);
        *pcData = cData;
        return TRUE;
    }
    return FALSE;
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

_Success_(return)
BOOL VMMDLL_UtilFillHexAscii(_In_ PBYTE pb, _In_ DWORD cb, _In_ DWORD cbInitialOffset, _Inout_opt_ LPSTR sz, _Out_ PDWORD pcsz)
{
    return Util_FillHexAscii(pb, cb, cbInitialOffset, sz, pcsz);
}
