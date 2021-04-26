// vmmdll.c : implementation of core dynamic link library (dll) functionality
// of the virtual memory manager (VMM) for The Memory Process File System.
//
// (c) Ulf Frisk, 2018-2021
// Author: Ulf Frisk, pcileech@frizk.net
//

#include "vmmdll.h"
#include "pluginmanager.h"
#include "util.h"
#include "pdb.h"
#include "pe.h"
#include "fc.h"
#include "statistics.h"
#include "version.h"
#include "vmm.h"
#include "vmmproc.h"
#include "vmmwin.h"
#include "vmmnet.h"
#include "vmmwinobj.h"
#include "vmmwinreg.h"
#include "mm_pfn.h"

// ----------------------------------------------------------------------------
// Synchronization macro below. The VMM isn't thread safe so it's important to
// serialize access to it over the VMM LockMaster. This master lock is shared
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
        } else if(0 == _stricmp(argv[i], "-userinteract")) {
            ctxMain->cfg.fUserInteract = TRUE;
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
        } else if(0 == _stricmp(argv[i], "-pythondisable")) {
            ctxMain->cfg.fDisablePython = TRUE;
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
        } else if(0 == _stricmp(argv[i], "-forensic")) {
            ctxMain->cfg.tpForensicMode = (DWORD)Util_GetNumericA(argv[i + 1]);
            if(ctxMain->cfg.tpForensicMode > FC_DATABASE_TYPE_MAX) { return FALSE; }
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
        } else if(0 == _stricmp(argv[i], "-memmap")) {
            strcpy_s(ctxMain->cfg.szMemMap, MAX_PATH, argv[i + 1]);
            i += 2;
            continue;
        } else if(0 == _stricmp(argv[i], "-memmap-str")) {
            strcpy_s(ctxMain->cfg.szMemMapStr, _countof(ctxMain->cfg.szMemMapStr), argv[i + 1]);
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
    if(ctxMain->dev.paMax && (ctxMain->dev.paMax < 0x00100000)) { return FALSE; }
    if(!ctxMain->dev.paMax && (ctxMain->cfg.szMemMap[0] || ctxMain->cfg.szMemMapStr[0])) {
        // disable memory auto-detect when memmap is specified
        ctxMain->dev.paMax = -1;
    }
    ctxMain->cfg.fFileInfoHeader = TRUE;
    ctxMain->cfg.fVerbose = ctxMain->cfg.fVerbose && ctxMain->cfg.fVerboseDll;
    ctxMain->cfg.fVerboseExtra = ctxMain->cfg.fVerboseExtra && ctxMain->cfg.fVerboseDll;
    ctxMain->cfg.fVerboseExtraTlp = ctxMain->cfg.fVerboseExtraTlp && ctxMain->cfg.fVerboseDll;
    ctxMain->dev.dwVersion = LC_CONFIG_VERSION;
    ctxMain->dev.dwPrintfVerbosity |= ctxMain->cfg.fVerboseDll ? LC_CONFIG_PRINTF_ENABLED : 0;
    ctxMain->dev.dwPrintfVerbosity |= ctxMain->cfg.fVerbose ? LC_CONFIG_PRINTF_V : 0;
    ctxMain->dev.dwPrintfVerbosity |= ctxMain->cfg.fVerboseExtra ? LC_CONFIG_PRINTF_VV : 0;
    ctxMain->dev.dwPrintfVerbosity |= ctxMain->cfg.fVerboseExtraTlp ? LC_CONFIG_PRINTF_VVV : 0;
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
        " The Memory Process File System (c) 2018-2021 Ulf Frisk                        \n" \
        " License: GNU Affero General Public License v3.0                               \n" \
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
        "   -memmap-str : specify a physical memory map in parameter agrument text.     \n" \
        "   -memmap : specify a physical memory map given in a file or specify 'auto'.  \n" \
        "          example: -memmap c:\\temp\\my_custom_memory_map.txt                  \n" \
        "          example: -memmap auto                                                \n" \
        "   -pagefile0..9 : specify specify page file / swap file. By default pagefile  \n" \
        "          have index 0 - example: -pagefile0 pagefile.sys while swapfile have  \n" \
        "          have index 1 - example: -pagefile1 swapfile.sys                      \n" \
        "   -pythonpath : specify the path to a python 3 installation for Windows.      \n" \
        "          The path given should be to the directory that contain: python.dll   \n" \
        "          Example: -pythonpath \"C:\\Program Files\\Python37\"                 \n" \
        "   -pythondisable : prevent/disable the python plugin sub-system from loading. \n" \
        "          Example: -pythondisable                                              \n" \
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
        "   -userinteract = allow vmm.dll to, on the console, query the user for        \n" \
        "          information such as, but not limited to, leechcore device options.   \n" \
        "          Default: user interaction = disabled.                                \n" \
        "   -forensic : start a forensic scan of the physical memory immediately after  \n" \
        "          startup if possible. Allowed parameter values range from 0-4.        \n" \
        "          Note! forensic mode is not available for live memory.                \n" \
        "          0 = not enabled (default value)                                      \n" \
        "          1 = forensic mode with in-memory sqlite database.                    \n" \
        "          2 = forensic mode with temp sqlite database deleted upon exit.       \n" \
        "          3 = forensic mode with temp sqlite database remaining upon exit.     \n" \
        "          4 = forensic mode with static named sqlite database (vmm.sqlite3).   \n" \
        "          default: 0  Example -forensic 4                                      \n" \
        "                                                                               \n",
        VERSION_MAJOR, VERSION_MINOR, VERSION_REVISION
    );
}

VOID VmmDll_FreeContext()
{
    if(ctxFc) {
        FcClose();
    }
    if(ctxVmm) {
        VmmClose();
    }
    if(ctxMain) {
        Statistics_CallSetEnabled(FALSE);
        LcClose(ctxMain->hLC);
        LocalFree(ctxMain);
        ctxMain = NULL;
    }
}

/*
* Initialize memory map auto - i.e. retrieve it from the registry and load it into LeechCore.
* -- return
*/
_Success_(return)
BOOL VMMDLL_Initialize_MemMapAuto()
{
    BOOL fResult = FALSE;
    DWORD i, cbMemMap = 0;
    LPSTR szMemMap = NULL;
    PVMMOB_MAP_PHYSMEM pObMap = NULL;
    if(!VmmMap_GetPhysMem(&pObMap)) { goto fail; }
    if(!(szMemMap = LocalAlloc(LMEM_ZEROINIT, 0x01000000))) { goto fail; }
    for(i = 0; i < pObMap->cMap; i++) {
        cbMemMap += snprintf(szMemMap + cbMemMap, 0x01000000 - cbMemMap - 1, "%016llx %016llx\n", pObMap->pMap[i].pa, pObMap->pMap[i].pa + pObMap->pMap[i].cb - 1);
    }
    fResult = 
        LcCommand(ctxMain->hLC, LC_CMD_MEMMAP_SET, cbMemMap, (PBYTE)szMemMap, NULL, NULL) &&
        LcGetOption(ctxMain->hLC, LC_OPT_CORE_ADDR_MAX, &ctxMain->dev.paMax);
fail:
    Ob_DECREF(pObMap);
    LocalFree(szMemMap);
    return fResult;
}

_Success_(return)
BOOL VMMDLL_Initialize_RequestUserInput(_In_ DWORD argc, _In_ LPSTR argv[])
{
    BOOL fResult;
    LPSTR szProto;
    DWORD i, cbRead = 0;
    CHAR szInput[33] = { 0 };
    CHAR szDevice[MAX_PATH] = { 0 };
    HANDLE hStdIn = GetStdHandle(STD_INPUT_HANDLE);     // must not be closed.
    // 1: read input
    vmmprintf("\n?> ");
    fResult = ReadConsoleA(hStdIn, szInput, 32, &cbRead, NULL);
    for(i = 0; i < _countof(szInput); i++) {
        if((szInput[i] == '\r') || (szInput[i] == '\n')) { szInput[i] = 0; }
    }
    cbRead = (DWORD)strlen(szInput);
    if(!cbRead) { return FALSE; }
    // 2: clear "userinput" option and update "device" option
    for(i = 0; i < argc; i++) {
        if(0 == _stricmp(argv[i], "-userinteract")) {
            argv[i] = "";
        }
        if((i + 1 < argc) && ((0 == _stricmp(argv[i], "-device")) || (0 == strcmp(argv[i], "-z")))) {
            szProto = strstr(argv[i + 1], "://");
            snprintf(
                szDevice,
                MAX_PATH - 1,
                "%s%s%sid=%s",
                argv[i + 1],
                szProto ? "" : "://",
                szProto && szProto[3] ? "," : "",
                szInput);
            argv[i + 1] = szDevice;
        }
    }
    // 3: try re-initialize with new user input
    return VMMDLL_InitializeEx(argc, argv, NULL);
}

_Success_(return)
BOOL VMMDLL_InitializeEx(_In_ DWORD argc, _In_ LPSTR argv[], _Out_opt_ PPLC_CONFIG_ERRORINFO ppLcErrorInfo)
{
    FILE *hFile = NULL;
    BOOL f;
    DWORD cbMemMap = 0;
    PBYTE pbMemMap = NULL;
    PLC_CONFIG_ERRORINFO pLcErrorInfo = NULL;
    if(ppLcErrorInfo) { *ppLcErrorInfo = NULL; }
    if(!(ctxMain = LocalAlloc(LMEM_ZEROINIT, sizeof(VMM_MAIN_CONTEXT)))) { return FALSE; }
    // initialize configuration
    if(!VmmDll_ConfigIntialize((DWORD)argc, argv)) {
        VmmDll_PrintHelp();
        goto fail;
    }
    // ctxMain.cfg context is inintialized from here onwards - vmmprintf is working!
    if(!(ctxMain->hLC = LcCreateEx(&ctxMain->dev, &pLcErrorInfo))) {
        if(pLcErrorInfo && (pLcErrorInfo->dwVersion == LC_CONFIG_ERRORINFO_VERSION)) {
            if(pLcErrorInfo->cwszUserText) {
                vmmwprintf(L"MESSAGE FROM MEMORY ACQUISITION DEVICE:\n=======================================\n%s\n", pLcErrorInfo->wszUserText);
            }
            if(ctxMain->cfg.fUserInteract && pLcErrorInfo->fUserInputRequest) {
                LcMemFree(pLcErrorInfo);
                return VMMDLL_Initialize_RequestUserInput(argc, argv);
            }
        }
        vmmprintf("MemProcFS: Failed to connect to memory acquisition device.\n");
        goto fail;
    }
    // Set LeechCore MemMap (if exists and not auto - i.e. from file)
    if(ctxMain->cfg.szMemMap[0] && _stricmp(ctxMain->cfg.szMemMap, "auto")) {
        f = (pbMemMap = LocalAlloc(LMEM_ZEROINIT, 0x01000000)) &&
            !fopen_s(&hFile, ctxMain->cfg.szMemMap, "rb") && hFile &&
            (cbMemMap = (DWORD)fread(pbMemMap, 1, 0x01000000, hFile)) && (cbMemMap < 0x01000000) &&
            LcCommand(ctxMain->hLC, LC_CMD_MEMMAP_SET, cbMemMap, pbMemMap, NULL, NULL) &&
            LcGetOption(ctxMain->hLC, LC_OPT_CORE_ADDR_MAX, &ctxMain->dev.paMax);
        LocalFree(pbMemMap);
        if(hFile) { fclose(hFile); }
        if(!f) {
            vmmprintf("MemProcFS: Failed to load initial memory map from: '%s'.\n", ctxMain->cfg.szMemMap);
            goto fail;
        }
    }
    if(ctxMain->cfg.szMemMapStr[0]) {
        f = LcCommand(ctxMain->hLC, LC_CMD_MEMMAP_SET, (DWORD)strlen(ctxMain->cfg.szMemMapStr), ctxMain->cfg.szMemMapStr, NULL, NULL) &&
            LcGetOption(ctxMain->hLC, LC_OPT_CORE_ADDR_MAX, &ctxMain->dev.paMax);
        if(!f) {
            vmmprintf("MemProcFS: Failed to load command line argument memory map.\n");
            goto fail;
        }
    }
    // ctxMain.dev context is initialized from here onwards - device functionality is working!
    if(!VmmProcInitialize()) {
        vmmprintf("MOUNT: INFO: PROC file system not mounted.\n");
        goto fail;
    }
    // ctxVmm context is initialized from here onwards - vmm functionality is working!
    // Set LeechCore MemMap (if auto)
    if(ctxMain->cfg.szMemMap[0] && !_stricmp(ctxMain->cfg.szMemMap, "auto")) {
        if(!VMMDLL_Initialize_MemMapAuto()) {
            vmmprintf("MemProcFS: Failed to load initial memory map from: '%s'.\n", ctxMain->cfg.szMemMap);
            goto fail;
        }
    }
    // Initialize forensic mode (if set by user parameter)
    if(ctxMain->cfg.tpForensicMode) {
        if(!FcInitialize(ctxMain->cfg.tpForensicMode, FALSE)) {
            if(ctxMain->dev.fVolatile) {
                vmmprintf("MemProcFS: Failed to initialize forensic mode - volatile (live) memory not supported - please use memory dump!\n");
            } else {
                vmmprintf("MemProcFS: Failed to initialize forensic mode.\n");
            }
            goto fail;
        }
    }
    return TRUE;
fail:
    if(ppLcErrorInfo) {
        *ppLcErrorInfo = pLcErrorInfo;
    } else {
        LcMemFree(pLcErrorInfo);
    }
    VmmDll_FreeContext();
    return FALSE;
}

_Success_(return)
BOOL VMMDLL_Initialize(_In_ DWORD argc, _In_ LPSTR argv[])
{
    return VMMDLL_InitializeEx(argc, argv, NULL);
}

_Success_(return)
BOOL VMMDLL_Close()
{
    VmmDll_FreeContext();
    return TRUE;
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
// PLUGIN MANAGER FUNCTIONALITY BELOW:
//-----------------------------------------------------------------------------

_Success_(return)
BOOL VMMDLL_InitializePlugins()
{
    CALL_IMPLEMENTATION_VMM(
        STATISTICS_ID_VMMDLL_InitializePlugins,
        PluginManager_Initialize())
}



//-----------------------------------------------------------------------------
// CONFIGURATION SETTINGS BELOW:
//-----------------------------------------------------------------------------

#define VMMDLL_REFRESH_CHECK(fOption, mask)      (fOption & mask & 0xffff'00000000)

_Success_(return)
BOOL VMMDLL_ConfigGet(_In_ ULONG64 fOption, _Out_ PULONG64 pqwValue)
{
    if(!fOption || !pqwValue) { return FALSE; }
    switch(fOption & 0xffffffff'00000000) {
        case VMMDLL_OPT_CORE_SYSTEM:
            *pqwValue = ctxVmm->tpSystem;
            return TRUE;
        case VMMDLL_OPT_CORE_MEMORYMODEL:
            *pqwValue = ctxVmm->tpMemoryModel;
            return TRUE;
        case VMMDLL_OPT_CONFIG_VMM_VERSION_MAJOR:
            *pqwValue = VERSION_MAJOR;
            return TRUE;
        case VMMDLL_OPT_CONFIG_VMM_VERSION_MINOR:
            *pqwValue = VERSION_MINOR;
            return TRUE;
        case VMMDLL_OPT_CONFIG_VMM_VERSION_REVISION:
            *pqwValue = VERSION_REVISION;
            return TRUE;
        case VMMDLL_OPT_CONFIG_IS_REFRESH_ENABLED:
            *pqwValue = ctxVmm->ThreadProcCache.fEnabled ? 1 : 0;
            return TRUE;
        case VMMDLL_OPT_CONFIG_IS_PAGING_ENABLED:
            *pqwValue = (ctxVmm->flags & VMM_FLAG_NOPAGING) ? 0 : 1;
            return TRUE;
        case VMMDLL_OPT_CONFIG_TICK_PERIOD:
            *pqwValue = ctxVmm->ThreadProcCache.cMs_TickPeriod;
            return TRUE;
        case VMMDLL_OPT_CONFIG_READCACHE_TICKS:
            *pqwValue = ctxVmm->ThreadProcCache.cTick_MEM;
            return TRUE;
        case VMMDLL_OPT_CONFIG_TLBCACHE_TICKS:
            *pqwValue = ctxVmm->ThreadProcCache.cTick_TLB;
            return TRUE;
        case VMMDLL_OPT_CONFIG_PROCCACHE_TICKS_PARTIAL:
            *pqwValue = ctxVmm->ThreadProcCache.cTick_Fast;
            return TRUE;
        case VMMDLL_OPT_CONFIG_PROCCACHE_TICKS_TOTAL:
            *pqwValue = ctxVmm->ThreadProcCache.cTick_Medium;
            return TRUE;
        case VMMDLL_OPT_CONFIG_STATISTICS_FUNCTIONCALL:
            *pqwValue = Statistics_CallGetEnabled() ? 1 : 0;
            return TRUE;
        case VMMDLL_OPT_WIN_VERSION_MAJOR:
            *pqwValue = ctxVmm->kernel.dwVersionMajor;
            return TRUE;
        case VMMDLL_OPT_WIN_VERSION_MINOR:
            *pqwValue = ctxVmm->kernel.dwVersionMinor;
            return TRUE;
        case VMMDLL_OPT_WIN_VERSION_BUILD:
            *pqwValue = ctxVmm->kernel.dwVersionBuild;
            return TRUE;
        case VMMDLL_OPT_WIN_SYSTEM_UNIQUE_ID:
            *pqwValue = ctxVmm->dwSystemUniqueId;
            return TRUE;
        case VMMDLL_OPT_FORENSIC_MODE:
            *pqwValue = ctxFc ? (BYTE)ctxFc->db.tp : 0;
            return TRUE;
        // core options affecting both vmm.dll and pcileech.dll
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
            *pqwValue = ctxMain->dev.paMax;
            return TRUE;
        default:
            // non-recognized option - possibly a device option to pass along to leechcore.dll
            return LcGetOption(ctxMain->hLC, fOption, pqwValue);
    }
}

_Success_(return)
BOOL VMMDLL_ConfigSet(_In_ ULONG64 fOption, _In_ ULONG64 qwValue)
{
    // user-initiated refresh / cache flushes
    if((fOption & 0xffff0000'00000000) == 0x20010000'00000000) {
        if(VMMDLL_REFRESH_CHECK(fOption, VMMDLL_OPT_REFRESH_FREQ_MEM)) {
            VmmProcRefresh_MEM();
        }
        if(VMMDLL_REFRESH_CHECK(fOption, VMMDLL_OPT_REFRESH_FREQ_TLB)) {
            VmmProcRefresh_TLB();
        }
        if(VMMDLL_REFRESH_CHECK(fOption, VMMDLL_OPT_REFRESH_FREQ_FAST)) {
            VmmProcRefresh_Fast();
        }
        if(VMMDLL_REFRESH_CHECK(fOption, VMMDLL_OPT_REFRESH_FREQ_MEDIUM)) {
            VmmProcRefresh_Medium();
        }
        if(VMMDLL_REFRESH_CHECK(fOption, VMMDLL_OPT_REFRESH_FREQ_SLOW)) {
            VmmProcRefresh_Slow();
        }
        if(VMMDLL_REFRESH_CHECK(fOption, VMMDLL_OPT_REFRESH_PAGING)) {
            VmmCacheClear(VMM_CACHE_TAG_PAGING);
        }
        if(VMMDLL_REFRESH_CHECK(fOption, VMMDLL_OPT_REFRESH_USER)) {
            VmmWinUser_Refresh();
        }
        if(VMMDLL_REFRESH_CHECK(fOption, VMMDLL_OPT_REFRESH_PHYSMEMMAP)) {
            VmmWinPhysMemMap_Refresh();
        }
        if(VMMDLL_REFRESH_CHECK(fOption, VMMDLL_OPT_REFRESH_PFN)) {
            MmPfn_Refresh();
        }
        if(VMMDLL_REFRESH_CHECK(fOption, VMMDLL_OPT_REFRESH_OBJ)) {
            VmmWinObj_Refresh();
        }
        if(VMMDLL_REFRESH_CHECK(fOption, VMMDLL_OPT_REFRESH_NET)) {
            VmmNet_Refresh();
        }
        return TRUE;
    }
    switch(fOption & 0xffffffff'00000000) {
        case VMMDLL_OPT_CORE_PRINTF_ENABLE:
            LcSetOption(ctxMain->hLC, fOption, qwValue);
            ctxMain->cfg.fVerboseDll = qwValue ? TRUE : FALSE;
            PluginManager_Notify(VMMDLL_PLUGIN_NOTIFY_VERBOSITYCHANGE, NULL, 0);
            return TRUE;
        case VMMDLL_OPT_CORE_VERBOSE:
            LcSetOption(ctxMain->hLC, fOption, qwValue);
            ctxMain->cfg.fVerbose = qwValue ? TRUE : FALSE;
            PluginManager_Notify(VMMDLL_PLUGIN_NOTIFY_VERBOSITYCHANGE, NULL, 0);
            return TRUE;
        case VMMDLL_OPT_CORE_VERBOSE_EXTRA:
            LcSetOption(ctxMain->hLC, fOption, qwValue);
            ctxMain->cfg.fVerboseExtra = qwValue ? TRUE : FALSE;
            PluginManager_Notify(VMMDLL_PLUGIN_NOTIFY_VERBOSITYCHANGE, NULL, 0);
            return TRUE;
        case VMMDLL_OPT_CORE_VERBOSE_EXTRA_TLP:
            LcSetOption(ctxMain->hLC, fOption, qwValue);
            ctxMain->cfg.fVerboseExtraTlp = qwValue ? TRUE : FALSE;
            PluginManager_Notify(VMMDLL_PLUGIN_NOTIFY_VERBOSITYCHANGE, NULL, 0);
            return TRUE;
        case VMMDLL_OPT_CONFIG_IS_PAGING_ENABLED:
            ctxVmm->flags = (ctxVmm->flags & ~VMM_FLAG_NOPAGING) | (qwValue ? 0 : 1);
            return TRUE;
        case VMMDLL_OPT_CONFIG_TICK_PERIOD:
            ctxVmm->ThreadProcCache.cMs_TickPeriod = (DWORD)qwValue;
            return TRUE;
        case VMMDLL_OPT_CONFIG_READCACHE_TICKS:
            ctxVmm->ThreadProcCache.cTick_MEM = (DWORD)qwValue;
            return TRUE;
        case VMMDLL_OPT_CONFIG_TLBCACHE_TICKS:
            ctxVmm->ThreadProcCache.cTick_TLB = (DWORD)qwValue;
            return TRUE;
        case VMMDLL_OPT_CONFIG_PROCCACHE_TICKS_PARTIAL:
            ctxVmm->ThreadProcCache.cTick_Fast = (DWORD)qwValue;
            return TRUE;
        case VMMDLL_OPT_CONFIG_PROCCACHE_TICKS_TOTAL:
            ctxVmm->ThreadProcCache.cTick_Medium = (DWORD)qwValue;
            return TRUE;
        case VMMDLL_OPT_CONFIG_STATISTICS_FUNCTIONCALL:
            Statistics_CallSetEnabled(qwValue ? TRUE : FALSE);
            return TRUE;
        case VMMDLL_OPT_FORENSIC_MODE:
            return FcInitialize((DWORD)qwValue, FALSE);
        default:
            // non-recognized option - possibly a device option to pass along to leechcore.dll
            return LcSetOption(ctxMain->hLC, fOption, qwValue);
    }
}

//-----------------------------------------------------------------------------
// VFS - VIRTUAL FILE SYSTEM FUNCTIONALITY BELOW:
//-----------------------------------------------------------------------------

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
    if(Util_VfsHelper_GetIdDir(wszPath, &dwPID, &wszSubPath)) {
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

NTSTATUS VMMDLL_VfsRead_Impl(LPWSTR wszPath, _Out_writes_to_(cb, *pcbRead) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset)
{
    NTSTATUS nt;
    DWORD dwPID;
    LPWSTR wszSubPath;
    PVMM_PROCESS pObProcess;
    if(!ctxVmm) { return VMM_STATUS_FILE_INVALID; }
    if(wszPath[0] == '\\') { wszPath++; }
    if(Util_VfsHelper_GetIdDir(wszPath, &dwPID, &wszSubPath)) {
        if(!(pObProcess = VmmProcessGet(dwPID))) { return VMM_STATUS_FILE_INVALID; }
        nt = PluginManager_Read(pObProcess, wszSubPath, pb, cb, pcbRead, cbOffset);
        Ob_DECREF(pObProcess);
        return nt;
    }
    return PluginManager_Read(NULL, wszPath, pb, cb, pcbRead, cbOffset);
}

NTSTATUS VMMDLL_VfsRead(_In_ LPCWSTR wcsFileName, _Out_writes_to_(cb, *pcbRead) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ ULONG64 cbOffset)
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
    if(Util_VfsHelper_GetIdDir(wszPath, &dwPID, &wszSubPath)) {
        if(!(pObProcess = VmmProcessGet(dwPID))) { return VMM_STATUS_FILE_INVALID; }
        nt = PluginManager_Write(pObProcess, wszSubPath, pb, cb, pcbWrite, cbOffset);
        Ob_DECREF(pObProcess);
        return nt;
    }
    return PluginManager_Write(NULL, wszPath, pb, cb, pcbWrite, cbOffset);
}

NTSTATUS VMMDLL_VfsWrite(_In_ LPCWSTR wcsFileName, _In_reads_(cb) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbWrite, _In_ ULONG64 cbOffset)
{
    CALL_IMPLEMENTATION_VMM_RETURN(
        STATISTICS_ID_VMMDLL_VfsWrite,
        NTSTATUS,
        VMMDLL_STATUS_UNSUCCESSFUL,
        VMMDLL_VfsWrite_Impl((LPWSTR)wcsFileName, pb, cb, pcbWrite, cbOffset))
}

NTSTATUS VMMDLL_UtilVfsReadFile_FromPBYTE(_In_ PBYTE pbFile, _In_ ULONG64 cbFile, _Out_writes_to_(cb, *pcbRead) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ ULONG64 cbOffset)
{
    return Util_VfsReadFile_FromPBYTE(pbFile, cbFile, pb, cb, pcbRead, cbOffset);
}

NTSTATUS VMMDLL_UtilVfsReadFile_FromQWORD(_In_ ULONG64 qwValue, _Out_writes_to_(cb, *pcbRead) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ ULONG64 cbOffset, _In_ BOOL fPrefix)
{
    return Util_VfsReadFile_FromQWORD(qwValue, pb, cb, pcbRead, cbOffset, fPrefix);
}

NTSTATUS VMMDLL_UtilVfsReadFile_FromDWORD(_In_ DWORD dwValue, _Out_writes_to_(cb, *pcbRead) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ ULONG64 cbOffset, _In_ BOOL fPrefix)
{
    return Util_VfsReadFile_FromDWORD(dwValue, pb, cb, pcbRead, cbOffset, fPrefix);
}

NTSTATUS VMMDLL_UtilVfsReadFile_FromBOOL(_In_ BOOL fValue, _Out_writes_to_(cb, *pcbRead) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ ULONG64 cbOffset)
{
    return Util_VfsReadFile_FromBOOL(fValue, pb, cb, pcbRead, cbOffset);
}

NTSTATUS VMMDLL_UtilVfsWriteFile_BOOL(_Inout_ PBOOL pfTarget, _In_reads_(cb) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbWrite, _In_ ULONG64 cbOffset)
{
    return Util_VfsWriteFile_BOOL(pfTarget, pb, cb, pcbWrite, cbOffset);
}

NTSTATUS VMMDLL_UtilVfsWriteFile_DWORD(_Inout_ PDWORD pdwTarget, _In_reads_(cb) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbWrite, _In_ ULONG64 cbOffset, _In_ DWORD dwMinAllow)
{
    return Util_VfsWriteFile_DWORD(pdwTarget, pb, cb, pcbWrite, cbOffset, dwMinAllow, 0);
}



//-----------------------------------------------------------------------------
// VMM CORE FUNCTIONALITY BELOW:
//-----------------------------------------------------------------------------

DWORD VMMDLL_MemReadScatter_Impl(_In_ DWORD dwPID, _Inout_ PPMEM_SCATTER ppMEMs, _In_ DWORD cpMEMs, _In_ DWORD flags)
{
    DWORD i, cMEMs;
    PVMM_PROCESS pObProcess = NULL;
    if(!ctxVmm) { return 0; }
    if(dwPID == -1) {
        VmmReadScatterPhysical(ppMEMs, cpMEMs, flags);
    } else {
        pObProcess = VmmProcessGet(dwPID);
        if(!pObProcess) { return 0; }
        VmmReadScatterVirtual(pObProcess, ppMEMs, cpMEMs, flags);
        Ob_DECREF(pObProcess);
    }
    for(i = 0, cMEMs = 0; i < cpMEMs; i++) {
        if(ppMEMs[i]->f) {
            cMEMs++;
        }
    }
    return cMEMs;
}

DWORD VMMDLL_MemReadScatter(_In_ DWORD dwPID, _Inout_ PPMEM_SCATTER ppMEMs, _In_ DWORD cpMEMs, _In_ DWORD flags)
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
BOOL VMMDLL_Map_GetPte_Impl(_In_ DWORD dwPID, _Out_writes_bytes_opt_(*pcbPteMap) PVMMDLL_MAP_PTE pPteMap, _Inout_ PDWORD pcbPteMap, _In_ BOOL fIdentifyModules)
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
BOOL VMMDLL_Map_GetPte(_In_ DWORD dwPID, _Out_writes_bytes_opt_(*pcbPteMap) PVMMDLL_MAP_PTE pPteMap, _Inout_ PDWORD pcbPteMap, _In_ BOOL fIdentifyModules)
{
    CALL_IMPLEMENTATION_VMM(
        STATISTICS_ID_VMMDLL_Map_GetPte,
        VMMDLL_Map_GetPte_Impl(dwPID, pPteMap, pcbPteMap, fIdentifyModules))
}

_Success_(return)
BOOL VMMDLL_Map_GetVad_Impl(_In_ DWORD dwPID, _Out_writes_bytes_opt_(*pcbVadMap) PVMMDLL_MAP_VAD pVadMap, _Inout_ PDWORD pcbVadMap, _In_ BOOL fIdentifyModules)
{
    BOOL fResult = FALSE;
    DWORD i, cbData = 0, cbDataMap;
    QWORD cbMultiTextDiff;
    PVMMOB_MAP_VAD pObMap = NULL;
    PVMM_PROCESS pObProcess = NULL;
    if(!(pObProcess = VmmProcessGet(dwPID))) { goto fail; }
    if(!VmmMap_GetVad(pObProcess, &pObMap, (fIdentifyModules ? VMM_VADMAP_TP_FULL : VMM_VADMAP_TP_PARTIAL))) { goto fail; }
    cbDataMap = pObMap->cMap * sizeof(VMMDLL_MAP_VADENTRY);
    cbData = sizeof(VMMDLL_MAP_VAD) + cbDataMap + max(2, pObMap->cbMultiText);
    if(pVadMap) {
        if(*pcbVadMap < cbData) { goto fail; }
        ZeroMemory(pVadMap, sizeof(VMMDLL_MAP_VAD));
        pVadMap->dwVersion = VMMDLL_MAP_VAD_VERSION;
        pVadMap->cPage = pObMap->cPage;
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
BOOL VMMDLL_Map_GetVad(_In_ DWORD dwPID, _Out_writes_bytes_opt_(*pcbVadMap) PVMMDLL_MAP_VAD pVadMap, _Inout_ PDWORD pcbVadMap, _In_ BOOL fIdentifyModules)
{
    CALL_IMPLEMENTATION_VMM(
        STATISTICS_ID_VMMDLL_Map_GetVad,
        VMMDLL_Map_GetVad_Impl(dwPID, pVadMap, pcbVadMap, fIdentifyModules))
}

_Success_(return)
BOOL VMMDLL_Map_GetVadEx_Impl(_In_ DWORD dwPID, _Out_writes_bytes_opt_(*pcbVadExMap) PVMMDLL_MAP_VADEX pVadExMap, _Inout_ PDWORD pcbVadExMap, _In_ DWORD oPage, _In_ DWORD cPage)
{
    BOOL fResult = FALSE;
    DWORD i, cbData = 0, cbDataMap;
    PVMMOB_MAP_VADEX pObMap = NULL;
    PVMM_PROCESS pObProcess = NULL;
    if(!pVadExMap) {
        *pcbVadExMap = sizeof(VMMDLL_MAP_VADEX) + cPage * sizeof(VMMDLL_MAP_VADEXENTRY);
        return TRUE;
    }
    if(!(pObProcess = VmmProcessGet(dwPID))) { goto fail; }
    if(!VmmMap_GetVadEx(pObProcess, &pObMap, VMM_VADMAP_TP_FULL, oPage, cPage)) { goto fail; }
    cbDataMap = pObMap->cMap * sizeof(VMMDLL_MAP_VADEXENTRY);
    cbData = sizeof(VMMDLL_MAP_VADEX) + cbDataMap;
    if(*pcbVadExMap < cbData) { goto fail; }
    ZeroMemory(pVadExMap, sizeof(VMMDLL_MAP_VADEX));
    pVadExMap->dwVersion = VMMDLL_MAP_VADEX_VERSION;
    pVadExMap->cMap = pObMap->cMap;
    memcpy(pVadExMap->pMap, pObMap->pMap, cbDataMap);
    for(i = 0; i < pObMap->cMap; i++) {
        pVadExMap->pMap[i].vaVadBase = pObMap->pMap[i].peVad->vaStart;
    }
    fResult = TRUE;
fail:
    *pcbVadExMap = cbData;
    Ob_DECREF(pObProcess);
    Ob_DECREF(pObMap);
    return fResult;
}

_Success_(return)
BOOL VMMDLL_Map_GetVadEx(_In_ DWORD dwPID, _Out_writes_bytes_opt_(*pcbVadExMap) PVMMDLL_MAP_VADEX pVadExMap, _Inout_ PDWORD pcbVadExMap, _In_ DWORD oPage, _In_ DWORD cPage)
{
    CALL_IMPLEMENTATION_VMM(
        STATISTICS_ID_VMMDLL_Map_GetVadEx,
        VMMDLL_Map_GetVadEx_Impl(dwPID, pVadExMap, pcbVadExMap, oPage, cPage))
}

_Success_(return)
BOOL VMMDLL_Map_GetModule_Impl(_In_ DWORD dwPID, _Out_writes_bytes_opt_(*pcbModuleMap) PVMMDLL_MAP_MODULE pModuleMap, _Inout_ PDWORD pcbModuleMap)
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
        memcpy(pModuleMap->wszMultiText, pObMap->wszMultiText, pObMap->cbMultiText);
        cbMultiTextDiff = (QWORD)pModuleMap->wszMultiText - (QWORD)pObMap->wszMultiText;
        for(i = 0; i < pModuleMap->cMap; i++) {
            memcpy(pModuleMap->pMap + i, pObMap->pMap + i, sizeof(VMMDLL_MAP_MODULEENTRY));
            pModuleMap->pMap[i].wszText = (LPWSTR)(cbMultiTextDiff + (QWORD)pObMap->pMap[i].wszText);
            pModuleMap->pMap[i].wszFullName = (LPWSTR)(cbMultiTextDiff + (QWORD)pObMap->pMap[i].wszFullName);
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
BOOL VMMDLL_Map_GetModule(_In_ DWORD dwPID, _Out_writes_bytes_opt_(*pcbModuleMap) PVMMDLL_MAP_MODULE pModuleMap, _Inout_ PDWORD pcbModuleMap)
{
    CALL_IMPLEMENTATION_VMM(
        STATISTICS_ID_VMMDLL_Map_GetModule,
        VMMDLL_Map_GetModule_Impl(dwPID, pModuleMap, pcbModuleMap))
}

_Success_(return)
BOOL VMMDLL_Map_GetModuleFromName_Impl(_In_ DWORD dwPID, _In_ LPWSTR wszModuleName, _Out_writes_bytes_opt_(*pcbModuleMapEntry) PVMMDLL_MAP_MODULEENTRY pModuleMapEntry, _Inout_opt_ PDWORD pcbModuleMapEntry)
{
    BOOL fResult = FALSE;
    DWORD o = 0, cbData = 0;
    PVMMOB_MAP_MODULE pObMap = NULL;
    PVMM_MAP_MODULEENTRY pMapEntry = NULL;
    if(!pModuleMapEntry && !pcbModuleMapEntry) { goto fail; }
    if(!VmmMap_GetModuleEntryEx(NULL, dwPID, wszModuleName, &pObMap, &pMapEntry)) { goto fail; }
    cbData = sizeof(VMMDLL_MAP_MODULEENTRY) + (2ULL + pMapEntry->cwszText + pMapEntry->cwszFullName) * sizeof(WCHAR);
    if(pModuleMapEntry) {
        if(pcbModuleMapEntry && (*pcbModuleMapEntry < sizeof(VMMDLL_MAP_MODULEENTRY))) { goto fail; }
        ZeroMemory(pModuleMapEntry, (pcbModuleMapEntry ? *pcbModuleMapEntry : sizeof(VMMDLL_MAP_MODULEENTRY)));
        memcpy(pModuleMapEntry, pMapEntry, sizeof(VMMDLL_MAP_MODULEENTRY));
        if(pcbModuleMapEntry  && (*pcbModuleMapEntry <= cbData)) {
            pModuleMapEntry->wszText = (LPWSTR)((PBYTE)pModuleMapEntry + sizeof(VMMDLL_MAP_MODULEENTRY));
            pModuleMapEntry->wszFullName = pModuleMapEntry->wszText + pMapEntry->cwszText + 1;
            errno_t t = 0;
            t = wcsncpy_s(pModuleMapEntry->wszText, pMapEntry->cwszText + 1ULL, pMapEntry->wszText, _TRUNCATE);
            t = wcsncpy_s(pModuleMapEntry->wszFullName, pMapEntry->cwszFullName + 1ULL, pMapEntry->wszFullName, _TRUNCATE);
        } else {
            pModuleMapEntry->wszText = pModuleMapEntry->wszFullName = L"";
            pModuleMapEntry->cwszText = pModuleMapEntry->cwszFullName = 0;
        }
    }
    fResult = TRUE;
fail:
    if(pcbModuleMapEntry) { *pcbModuleMapEntry = cbData; }
    Ob_DECREF(pObMap);
    return fResult;
}

_Success_(return)
BOOL VMMDLL_Map_GetModuleFromName(_In_ DWORD dwPID, _In_ LPWSTR wszModuleName, _Out_writes_bytes_opt_(*pcbModuleMapEntry) PVMMDLL_MAP_MODULEENTRY pModuleMapEntry, _Inout_opt_ PDWORD pcbModuleMapEntry)
{
    CALL_IMPLEMENTATION_VMM(
        STATISTICS_ID_VMMDLL_Map_GetModuleFromName,
        VMMDLL_Map_GetModuleFromName_Impl(dwPID, wszModuleName, pModuleMapEntry, pcbModuleMapEntry))
}

_Success_(return)
BOOL VMMDLL_Map_GetUnloadedModule_Impl(_In_ DWORD dwPID, _Out_writes_bytes_opt_(*pcbUnloadedMap) PVMMDLL_MAP_UNLOADEDMODULE pUnloadedMap, _Inout_ PDWORD pcbUnloadedMap)
{
    BOOL fResult = FALSE;
    QWORD i, cbData = 0, cbDataMap, cbMultiTextDiff;
    PVMMOB_MAP_UNLOADEDMODULE pObMap = NULL;
    PVMM_PROCESS pObProcess = NULL;
    if(!(pObProcess = VmmProcessGet(dwPID))) { goto fail; }
    if(!VmmMap_GetUnloadedModule(pObProcess, &pObMap)) { goto fail; }
    cbDataMap = pObMap->cMap * sizeof(VMMDLL_MAP_MODULEENTRY);
    cbData = sizeof(VMMDLL_MAP_UNLOADEDMODULE) + cbDataMap + pObMap->cbMultiText;
    if(pUnloadedMap) {
        if(*pcbUnloadedMap < cbData) { goto fail; }
        ZeroMemory(pUnloadedMap, sizeof(VMMDLL_MAP_MODULE));
        pUnloadedMap->dwVersion = VMMDLL_MAP_UNLOADEDMODULE_VERSION;
        pUnloadedMap->wszMultiText = (LPWSTR)(((PBYTE)pUnloadedMap->pMap) + cbDataMap);
        pUnloadedMap->cbMultiText = pObMap->cbMultiText;
        pUnloadedMap->cMap = pObMap->cMap;
        memcpy(pUnloadedMap->wszMultiText, pObMap->wszMultiText, pObMap->cbMultiText);
        cbMultiTextDiff = (QWORD)pUnloadedMap->wszMultiText - (QWORD)pObMap->wszMultiText;
        for(i = 0; i < pUnloadedMap->cMap; i++) {
            memcpy(pUnloadedMap->pMap + i, pObMap->pMap + i, sizeof(VMMDLL_MAP_UNLOADEDMODULEENTRY));
            pUnloadedMap->pMap[i].wszText = (LPWSTR)(cbMultiTextDiff + (QWORD)pObMap->pMap[i].wszText);
        }
    }
    fResult = TRUE;
fail:
    *pcbUnloadedMap = (DWORD)cbData;
    Ob_DECREF(pObProcess);
    Ob_DECREF(pObMap);
    return fResult;
}

_Success_(return)
BOOL VMMDLL_Map_GetUnloadedModule(_In_ DWORD dwPID, _Out_writes_bytes_opt_(*pcbUnloadedModuleMap) PVMMDLL_MAP_UNLOADEDMODULE pUnloadedModuleMap, _Inout_ PDWORD pcbUnloadedModuleMap)
{
    CALL_IMPLEMENTATION_VMM(
        STATISTICS_ID_VMMDLL_Map_GetUnloadedModule,
        VMMDLL_Map_GetUnloadedModule_Impl(dwPID, pUnloadedModuleMap, pcbUnloadedModuleMap))
}

_Success_(return)
BOOL VMMDLL_Map_GetEAT_Impl(_In_ DWORD dwPID, _In_ LPWSTR wszModuleName, _Out_writes_bytes_opt_(*pcbEatMap) PVMMDLL_MAP_EAT pEatMap, _Inout_ PDWORD pcbEatMap)
{
    BOOL fResult = FALSE;
    QWORD i, cbData = 0, cbDataMap, cbMultiTextDiff;
    PVMMDLL_MAP_EATENTRY pe;
    PVMMOB_MAP_EAT pObMap = NULL;
    PVMM_PROCESS pObProcess = NULL;
    PVMMOB_MAP_MODULE pObModuleMap = NULL;
    PVMM_MAP_MODULEENTRY pModuleEntry = NULL;
    if(!(pObProcess = VmmProcessGet(dwPID))) { goto fail; }
    if(!VmmMap_GetModuleEntryEx(pObProcess, 0, wszModuleName, &pObModuleMap, &pModuleEntry)) { goto fail; }
    if(!VmmMap_GetEAT(pObProcess, pModuleEntry, &pObMap)) { goto fail; }
    cbDataMap = pObMap->cMap * sizeof(VMMDLL_MAP_EATENTRY);
    cbData = sizeof(VMMDLL_MAP_EAT) + cbDataMap + pObMap->cbMultiText;
    if(pEatMap) {
        if(*pcbEatMap < cbData) { goto fail; }
        pEatMap->dwVersion = VMMDLL_MAP_EAT_VERSION;
        pEatMap->vaModuleBase = pObMap->vaModuleBase;
        pEatMap->vaAddressOfFunctions = pObMap->vaAddressOfFunctions;
        pEatMap->vaAddressOfNames = pObMap->vaAddressOfNames;
        pEatMap->cNumberOfFunctions = pObMap->cNumberOfFunctions;
        pEatMap->cNumberOfNames = pObMap->cNumberOfNames;
        pEatMap->dwOrdinalBase = pObMap->dwOrdinalBase;
        pEatMap->wszMultiText = (LPWSTR)(((PBYTE)pEatMap->pMap) + cbDataMap);
        pEatMap->cbMultiText = pObMap->cbMultiText;
        pEatMap->cMap = pObMap->cMap;
        memcpy(pEatMap->pMap, pObMap->pMap, cbDataMap);
        memcpy(pEatMap->wszMultiText, pObMap->wszMultiText, pObMap->cbMultiText);
        cbMultiTextDiff = (QWORD)pEatMap->wszMultiText - (QWORD)pObMap->wszMultiText;
        for(i = 0; i < pEatMap->cMap; i++) {
            pe = pEatMap->pMap + i;
            pe->wszFunction = (LPWSTR)(cbMultiTextDiff + (QWORD)pe->wszFunction);
        }
    }
    fResult = TRUE;
fail:
    *pcbEatMap = (DWORD)cbData;
    Ob_DECREF(pObModuleMap);
    Ob_DECREF(pObProcess);
    Ob_DECREF(pObMap);
    return fResult;
}

_Success_(return)
BOOL VMMDLL_Map_GetIAT_Impl(_In_ DWORD dwPID, _In_ LPWSTR wszModuleName, _Out_writes_bytes_opt_(*pcbIatMap) PVMMDLL_MAP_IAT pIatMap, _Inout_ PDWORD pcbIatMap)
{
    BOOL fResult = FALSE;
    QWORD i, cbData = 0, cbDataMap, cbMultiTextDiff;
    PVMMDLL_MAP_IATENTRY pe;
    PVMMOB_MAP_IAT pObMap = NULL;
    PVMM_PROCESS pObProcess = NULL;
    PVMMOB_MAP_MODULE pObModuleMap = NULL;
    PVMM_MAP_MODULEENTRY pModuleEntry = NULL;
    if(!(pObProcess = VmmProcessGet(dwPID))) { goto fail; }
    if(!VmmMap_GetModuleEntryEx(pObProcess, 0, wszModuleName, &pObModuleMap, &pModuleEntry)) { goto fail; }
    if(!VmmMap_GetIAT(pObProcess, pModuleEntry, &pObMap)) { goto fail; }
    cbDataMap = pObMap->cMap * sizeof(VMMDLL_MAP_IATENTRY);
    cbData = sizeof(VMMDLL_MAP_IAT) + cbDataMap + pObMap->cbMultiText;
    if(pIatMap) {
        if(*pcbIatMap < cbData) { goto fail; }
        pIatMap->dwVersion = VMMDLL_MAP_IAT_VERSION;
        pIatMap->vaModuleBase = pObMap->vaModuleBase;
        pIatMap->wszMultiText = (LPWSTR)(((PBYTE)pIatMap->pMap) + cbDataMap);
        pIatMap->cbMultiText = pObMap->cbMultiText;
        pIatMap->cMap = pObMap->cMap;
        memcpy(pIatMap->pMap, pObMap->pMap, cbDataMap);
        memcpy(pIatMap->wszMultiText, pObMap->wszMultiText, pObMap->cbMultiText);
        cbMultiTextDiff = (QWORD)pIatMap->wszMultiText - (QWORD)pObMap->wszMultiText;
        for(i = 0; i < pIatMap->cMap; i++) {
            pe = pIatMap->pMap + i;
            pe->wszFunction = (LPWSTR)(cbMultiTextDiff + (QWORD)pe->wszFunction);
        }
    }
    fResult = TRUE;
fail:
    *pcbIatMap = (DWORD)cbData;
    Ob_DECREF(pObModuleMap);
    Ob_DECREF(pObProcess);
    Ob_DECREF(pObMap);
    return fResult;
}

_Success_(return)
BOOL VMMDLL_Map_GetEAT(_In_ DWORD dwPID, _In_ LPWSTR wszModuleName, _Out_writes_bytes_opt_(*pcbEatMap) PVMMDLL_MAP_EAT pEatMap, _Inout_ PDWORD pcbEatMap)
{
    CALL_IMPLEMENTATION_VMM(
        STATISTICS_ID_VMMDLL_Map_GetEAT,
        VMMDLL_Map_GetEAT_Impl(dwPID, wszModuleName, pEatMap, pcbEatMap))
}

_Success_(return)
BOOL VMMDLL_Map_GetIAT(_In_ DWORD dwPID, _In_ LPWSTR wszModuleName, _Out_writes_bytes_opt_(*pcbIatMap) PVMMDLL_MAP_IAT pIatMap, _Inout_ PDWORD pcbIatMap)
{
    CALL_IMPLEMENTATION_VMM(
        STATISTICS_ID_VMMDLL_Map_GetIAT,
        VMMDLL_Map_GetIAT_Impl(dwPID, wszModuleName, pIatMap, pcbIatMap))
}

_Success_(return)
BOOL VMMDLL_Map_GetHeap_Impl(_In_ DWORD dwPID, _Out_writes_bytes_opt_(*pcbHeapMap) PVMMDLL_MAP_HEAP pHeapMap, _Inout_ PDWORD pcbHeapMap)
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
BOOL VMMDLL_Map_GetHeap(_In_ DWORD dwPID, _Out_writes_bytes_opt_(*pcbHeapMap) PVMMDLL_MAP_HEAP pHeapMap, _Inout_ PDWORD pcbHeapMap)
{
    CALL_IMPLEMENTATION_VMM(
        STATISTICS_ID_VMMDLL_Map_GetHeap,
        VMMDLL_Map_GetHeap_Impl(dwPID, pHeapMap, pcbHeapMap))
}

_Success_(return)
BOOL VMMDLL_Map_GetThread_Impl(_In_ DWORD dwPID, _Out_writes_bytes_opt_(*pcbThreadMap) PVMMDLL_MAP_THREAD pThreadMap, _Inout_ PDWORD pcbThreadMap)
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
        pThreadMap->dwVersion = VMMDLL_MAP_THREAD_VERSION;
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
BOOL VMMDLL_Map_GetThread(_In_ DWORD dwPID, _Out_writes_bytes_opt_(*pcbThreadMap) PVMMDLL_MAP_THREAD pThreadMap, _Inout_ PDWORD pcbThreadMap)
{
    CALL_IMPLEMENTATION_VMM(
        STATISTICS_ID_VMMDLL_Map_GetThread,
        VMMDLL_Map_GetThread_Impl(dwPID, pThreadMap, pcbThreadMap))
}

_Success_(return)
BOOL VMMDLL_Map_GetHandle_Impl(_In_ DWORD dwPID, _Out_writes_bytes_opt_(*pcbHandleMap) PVMMDLL_MAP_HANDLE pHandleMap, _Inout_ PDWORD pcbHandleMap)
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
                pe->wszType = (LPWSTR)((QWORD)wszTypeMultiText + (QWORD)pOT->wsz - (QWORD)wszTypeMultiText);
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
BOOL VMMDLL_Map_GetHandle(_In_ DWORD dwPID, _Out_writes_bytes_opt_(*pcbHandleMap) PVMMDLL_MAP_HANDLE pHandleMap, _Inout_ PDWORD pcbHandleMap)
{
    CALL_IMPLEMENTATION_VMM(
        STATISTICS_ID_VMMDLL_Map_GetHandle,
        VMMDLL_Map_GetHandle_Impl(dwPID, pHandleMap, pcbHandleMap))
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
BOOL VMMDLL_Map_GetNet_Impl(_Out_writes_bytes_opt_(*pcbNetMap) PVMMDLL_MAP_NET pNetMap, _Inout_ PDWORD pcbNetMap)
{
    BOOL fResult = FALSE;
    QWORD i, cbData = 0, cbDataMap, cbMultiTextDiff;
    PVMMDLL_MAP_NETENTRY pe;
    PVMMOB_MAP_NET pObMap = NULL;
    if(!VmmMap_GetNet(&pObMap)) { goto fail; }
    cbDataMap = pObMap->cMap * sizeof(VMMDLL_MAP_NETENTRY);
    cbData = sizeof(VMMDLL_MAP_NET) + cbDataMap + pObMap->cbMultiText;
    if(pNetMap) {
        if(*pcbNetMap < cbData) { goto fail; }
        ZeroMemory(pNetMap, cbData);
        pNetMap->dwVersion = VMMDLL_MAP_NET_VERSION;
        pNetMap->wszMultiText = (LPWSTR)(((PBYTE)pNetMap->pMap) + cbDataMap);
        pNetMap->cbMultiText = pObMap->cbMultiText;
        pNetMap->cMap = pObMap->cMap;
        memcpy(pNetMap->pMap, pObMap->pMap, cbDataMap);
        memcpy(pNetMap->wszMultiText, pObMap->wszMultiText, pObMap->cbMultiText);
        cbMultiTextDiff = (QWORD)pNetMap->wszMultiText - (QWORD)pObMap->wszMultiText;
        for(i = 0; i < pNetMap->cMap; i++) {
            pe = pNetMap->pMap + i;
            pe->Src.wszText = (LPWSTR)(cbMultiTextDiff + (QWORD)pe->Src.wszText);
            pe->Dst.wszText = (LPWSTR)(cbMultiTextDiff + (QWORD)pe->Dst.wszText);
            pe->wszText = (LPWSTR)(cbMultiTextDiff + (QWORD)pe->wszText);
        }
    }
    fResult = TRUE;
fail:
    *pcbNetMap = (DWORD)cbData;
    Ob_DECREF(pObMap);
    return fResult;
}

_Success_(return)
BOOL VMMDLL_Map_GetNet(_Out_writes_bytes_opt_(*pcbNetMap) PVMMDLL_MAP_NET pNetMap, _Inout_ PDWORD pcbNetMap)
{
    CALL_IMPLEMENTATION_VMM(
        STATISTICS_ID_VMMDLL_Map_GetNet,
        VMMDLL_Map_GetNet_Impl(pNetMap, pcbNetMap))
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
BOOL VMMDLL_Map_GetServices_Impl(_Out_writes_bytes_opt_(*pcbServiceMap) PVMMDLL_MAP_SERVICE pServiceMap, _Inout_ PDWORD pcbServiceMap)
{
    BOOL fResult = FALSE;
    QWORD i, cbData = 0, cbDataMap, cbMultiTextDiff;
    PVMMDLL_MAP_SERVICEENTRY peDst;
    PVMM_MAP_SERVICEENTRY peSrc;
    PVMMOB_MAP_SERVICE pObMap = NULL;
    if(!VmmMap_GetService(&pObMap)) { goto fail; }
    cbDataMap = pObMap->cMap * sizeof(VMMDLL_MAP_SERVICEENTRY);
    cbData = sizeof(VMMDLL_MAP_USER) + cbDataMap + pObMap->cbMultiText;
    if(pServiceMap) {
        if(*pcbServiceMap < cbData) { goto fail; }
        ZeroMemory(pServiceMap, cbData);
        pServiceMap->dwVersion = VMMDLL_MAP_SERVICE_VERSION;
        pServiceMap->wszMultiText = (LPWSTR)(((PBYTE)pServiceMap->pMap) + cbDataMap);
        pServiceMap->cbMultiText = pObMap->cbMultiText;
        pServiceMap->cMap = pObMap->cMap;
        memcpy(pServiceMap->wszMultiText, pObMap->wszMultiText, pObMap->cbMultiText);
        cbMultiTextDiff = (QWORD)pServiceMap->wszMultiText - (QWORD)pObMap->wszMultiText;
        for(i = 0; i < pServiceMap->cMap; i++) {
            peDst = pServiceMap->pMap + i;
            peSrc = pObMap->pMap + i;
            memcpy(peDst, pObMap->pMap + i, sizeof(VMM_MAP_SERVICEENTRY));
            peDst->wszServiceName = (LPWSTR)(cbMultiTextDiff + (QWORD)peSrc->wszServiceName);
            peDst->wszDisplayName = (LPWSTR)(cbMultiTextDiff + (QWORD)peSrc->wszDisplayName);
            peDst->wszPath        = (LPWSTR)(cbMultiTextDiff + (QWORD)peSrc->wszPath);
            peDst->wszUserTp      = (LPWSTR)(cbMultiTextDiff + (QWORD)peSrc->wszUserTp);
            peDst->wszUserAcct    = (LPWSTR)(cbMultiTextDiff + (QWORD)peSrc->wszUserAcct);
            peDst->wszImagePath   = (LPWSTR)(cbMultiTextDiff + (QWORD)peSrc->wszImagePath);
        }
    }
    fResult = TRUE;
fail:
    *pcbServiceMap = (DWORD)cbData;
    Ob_DECREF(pObMap);
    return fResult;
}

_Success_(return)
BOOL VMMDLL_Map_GetServices(_Out_writes_bytes_opt_(*pcbServiceMap) PVMMDLL_MAP_SERVICE pServiceMap, _Inout_ PDWORD pcbServiceMap)
{
    CALL_IMPLEMENTATION_VMM(
        STATISTICS_ID_VMMDLL_Map_GetServices,
        VMMDLL_Map_GetServices_Impl(pServiceMap, pcbServiceMap))
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
        if(!MmPfn_Map_GetPfnScatter(psObPfns, &pObMap, TRUE)) { goto fail; }
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
        if(!pObProcess->pObPersistent->uszNameLong || _stricmp(szProcName, pObProcess->pObPersistent->uszNameLong)) { continue; }
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
    pInfo->magic = VMMDLL_PROCESS_INFORMATION_MAGIC;
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
    strncpy_s(pInfo->szNameLong, sizeof(pInfo->szNameLong), pObProcess->pObPersistent->uszNameLong, _TRUNCATE);
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
                VmmProcessActionForeachParallel(NULL, VMMDLL_ProcessGetInformationString_Impl_CallbackCriteria, VMMDLL_ProcessGetInformationString_Impl_CallbackAction);
            }
    }
    switch(fOptionString) {
        case VMMDLL_PROCESS_INFORMATION_OPT_STRING_PATH_KERNEL:
            sz = pObProcess->pObPersistent->uszPathKernel;
            break;
        case VMMDLL_PROCESS_INFORMATION_OPT_STRING_PATH_USER_IMAGE:
            sz = pObProcess->pObPersistent->UserProcessParams.uszImagePathName;
            break;
        case VMMDLL_PROCESS_INFORMATION_OPT_STRING_CMDLINE:
            sz = pObProcess->pObPersistent->UserProcessParams.uszCommandLine;
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
BOOL VMMDLL_ProcessGet_Directories_Sections_Impl(
    _In_ DWORD dwPID,
    _In_ LPWSTR wszModule,
    _In_ DWORD cData,
    _Out_ PDWORD pcData,
    _Out_writes_opt_(16) PIMAGE_DATA_DIRECTORY pDataDirectory,
    _Out_opt_ PIMAGE_SECTION_HEADER pSections,
    BOOL _In_ fDataDirectory,
    BOOL _In_ fSections
)
{
    DWORD i;
    PVMMOB_MAP_MODULE pObModuleMap = NULL;
    PVMM_MAP_MODULEENTRY pModule = NULL;
    PVMM_PROCESS pObProcess = NULL;
    if(!(pObProcess = VmmProcessGet(dwPID))) { goto fail; }
    // fetch requested module
    if(!VmmMap_GetModuleEntryEx(pObProcess, 0, wszModule, &pObModuleMap, &pModule)) { goto fail; }
    // data directories
    if(fDataDirectory) {
        if(!pDataDirectory) { *pcData = IMAGE_NUMBEROF_DIRECTORY_ENTRIES; goto success; }
        if(cData < 16) { goto fail; }
        if(!PE_DirectoryGetAll(pObProcess, pModule->vaBase, NULL, pDataDirectory)) { goto fail; }
        *pcData = 16;
        goto success;
    }
    // sections
    if(fSections) {
        i = PE_SectionGetNumberOf(pObProcess, pModule->vaBase);
        if(!pSections) { *pcData = i; goto success; }
        if(cData < i) { goto fail; }
        if(!PE_SectionGetAll(pObProcess, pModule->vaBase, i, pSections)) { goto fail; }
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
        VMMDLL_ProcessGet_Directories_Sections_Impl(dwPID, wszModule, cData, pcData, pData, NULL, TRUE, FALSE))
}

_Success_(return)
BOOL VMMDLL_ProcessGetSections(_In_ DWORD dwPID, _In_ LPWSTR wszModule, _Out_opt_ PIMAGE_SECTION_HEADER pData, _In_ DWORD cData, _Out_ PDWORD pcData)
{
    CALL_IMPLEMENTATION_VMM(
        STATISTICS_ID_VMMDLL_ProcessGetSections,
        VMMDLL_ProcessGet_Directories_Sections_Impl(dwPID, wszModule, cData, pcData, NULL, pData, FALSE, TRUE))
}

ULONG64 VMMDLL_ProcessGetModuleBase_Impl(_In_ DWORD dwPID, _In_ LPWSTR wszModuleName)
{
    QWORD vaModuleBase = 0;
    PVMM_MAP_MODULEENTRY peModule;
    PVMMOB_MAP_MODULE pObModuleMap = NULL;
    if(VmmMap_GetModuleEntryEx(NULL, dwPID, wszModuleName, &pObModuleMap, &peModule)) {
        vaModuleBase = peModule->vaBase;
        Ob_DECREF(pObModuleMap);
    }
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

ULONG64 VMMDLL_ProcessGetProcAddress_Impl(_In_ DWORD dwPID, _In_ LPWSTR wszModuleName, _In_ LPSTR szFunctionName)
{
    PVMM_PROCESS pObProcess = NULL;
    PVMMOB_MAP_EAT pObEatMap = NULL;
    PVMMOB_MAP_MODULE pObModuleMap = NULL;
    PVMM_MAP_MODULEENTRY peModule;
    QWORD va = 0;
    DWORD i;
    if(!(pObProcess = VmmProcessGet(dwPID))) { goto fail; }
    if(!VmmMap_GetModuleEntryEx(NULL, dwPID, wszModuleName, &pObModuleMap, &peModule)) { goto fail; }
    if(!VmmMap_GetEAT(pObProcess, peModule, &pObEatMap)) { goto fail; }
    if(!VmmMap_GetEATEntryIndexA(pObEatMap, szFunctionName, &i)) { goto fail; }
    va = pObEatMap->pMap[i].vaFunction;
fail:
    Ob_DECREF(pObEatMap);
    Ob_DECREF(pObModuleMap);
    Ob_DECREF(pObProcess);
    return va;
}

ULONG64 VMMDLL_ProcessGetProcAddress(_In_ DWORD dwPID, _In_ LPWSTR wszModuleName, _In_ LPSTR szFunctionName)
{
    CALL_IMPLEMENTATION_VMM_RETURN(
        STATISTICS_ID_VMMDLL_ProcessGetProcAddress,
        ULONG64,
        0,
        VMMDLL_ProcessGetProcAddress_Impl(dwPID, wszModuleName, szFunctionName))
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
        (pObKey = VmmWinReg_KeyGetByPath(pObHive, wszPathKey));
    if(f) {
        if(f && (dwIndex == (DWORD)-1)) {
            // actual key
            VmmWinReg_KeyInfo(pObHive, pObKey, &KeyInfo);
        } else {
            // subkeys
            f = (pmObSubKeys = VmmWinReg_KeyList(pObHive, pObKey)) &&
                (pObSubKey = ObMap_GetByIndex(pmObSubKeys, dwIndex));
            if(f) { VmmWinReg_KeyInfo(pObHive, pObSubKey, &KeyInfo); }
        }
    }
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
// WINDOWS SPECIFIC UTILITY FUNCTIONS BELOW:
//-----------------------------------------------------------------------------

_Success_(return)
BOOL VMMDLL_WinGetThunkInfoIAT_Impl(_In_ DWORD dwPID, _In_ LPWSTR wszModuleName, _In_ LPSTR szImportModuleName, _In_ LPSTR szImportFunctionName, _Out_ PVMMDLL_WIN_THUNKINFO_IAT pThunkInfoIAT)
{
    BOOL f = FALSE;
    QWORD vaModuleBase;
    PVMM_PROCESS pObProcess = NULL;
    f = (sizeof(VMMDLL_WIN_THUNKINFO_IAT) == sizeof(PE_THUNKINFO_IAT)) &&
        (pObProcess = VmmProcessGet(dwPID)) &&
        (vaModuleBase = VMMDLL_ProcessGetModuleBase_Impl(dwPID, wszModuleName)) &&
        PE_GetThunkInfoIAT(pObProcess, vaModuleBase, szImportModuleName, szImportFunctionName, (PPE_THUNKINFO_IAT)pThunkInfoIAT);
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
BOOL VMMDLL_PdbLoad_Impl(_In_ DWORD dwPID, _In_ ULONG64 vaModuleBase, _Out_writes_(MAX_PATH) LPSTR szModuleName)
{
    BOOL fResult;
    PDB_HANDLE hPdb;
    PVMM_PROCESS pObProcess;
    if(!(pObProcess = VmmProcessGet(dwPID))) { return FALSE; }
    fResult =
        (hPdb = PDB_GetHandleFromModuleAddress(pObProcess, vaModuleBase)) &&
        PDB_LoadEnsure(hPdb) &&
        PDB_GetModuleInfo(hPdb, szModuleName, NULL, NULL);
    Ob_DECREF(pObProcess);
    return fResult;
}

_Success_(return)
BOOL VMMDLL_PdbLoad(_In_ DWORD dwPID, _In_ ULONG64 vaModuleBase, _Out_writes_(MAX_PATH) LPSTR szModuleName)
{
    CALL_IMPLEMENTATION_VMM(
        STATISTICS_ID_VMMDLL_PdbLoad,
        VMMDLL_PdbLoad_Impl(dwPID, vaModuleBase, szModuleName))
}

_Success_(return)
BOOL VMMDLL_PdbSymbolName_Impl(_In_ LPSTR szModule, _In_ QWORD cbSymbolAddressOrOffset, _Out_writes_(MAX_PATH) LPSTR szSymbolName, _Out_opt_ PDWORD pdwSymbolDisplacement)
{
    DWORD cbPdbModuleSize = 0;
    QWORD vaPdbModuleBase = 0;
    PDB_HANDLE hPdb = PDB_GetHandleFromModuleName(szModule);
    if(PDB_GetModuleInfo(hPdb, NULL, &vaPdbModuleBase, &cbPdbModuleSize)) {
        if((vaPdbModuleBase <= cbSymbolAddressOrOffset) && (vaPdbModuleBase + cbPdbModuleSize >= cbSymbolAddressOrOffset)) {
            cbSymbolAddressOrOffset -= vaPdbModuleBase;     // cbSymbolAddressOrOffset is absolute address
        }
    }
    return PDB_GetSymbolFromOffset(hPdb, (DWORD)cbSymbolAddressOrOffset, szSymbolName, pdwSymbolDisplacement);
}

_Success_(return)
BOOL VMMDLL_PdbSymbolName(_In_ LPSTR szModule, _In_ QWORD cbSymbolAddressOrOffset, _Out_writes_(MAX_PATH) LPSTR szSymbolName, _Out_opt_ PDWORD pdwSymbolDisplacement)
{
    CALL_IMPLEMENTATION_VMM(
        STATISTICS_ID_VMMDLL_PdbSymbolName,
        VMMDLL_PdbSymbolName_Impl(szModule, cbSymbolAddressOrOffset, szSymbolName, pdwSymbolDisplacement))
}

_Success_(return)
BOOL VMMDLL_PdbSymbolAddress_Impl(_In_ LPSTR szModule, _In_ LPSTR szSymbolName, _Out_ PULONG64 pvaSymbolAddress)
{
    PDB_HANDLE hPdb = PDB_GetHandleFromModuleName(szModule);
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
    PDB_HANDLE hPdb = PDB_GetHandleFromModuleName(szModule);
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
    PDB_HANDLE hPdb = PDB_GetHandleFromModuleName(szModule);
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
BOOL VMMDLL_UtilFillHexAscii(_In_reads_opt_(cb) PBYTE pb, _In_ DWORD cb, _In_ DWORD cbInitialOffset, _Out_writes_opt_(*pcsz) LPSTR sz, _Inout_ PDWORD pcsz)
{
    CALL_IMPLEMENTATION_VMM(
        STATISTICS_ID_VMMDLL_UtilFillHexAscii,
        Util_FillHexAscii(pb, cb, cbInitialOffset, sz, pcsz))
}
