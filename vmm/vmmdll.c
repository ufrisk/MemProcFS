// vmmdll.c : implementation of core dynamic link library (dll) functionality
// of the virtual memory manager (VMM) for The Memory Process File System.
//
// (c) Ulf Frisk, 2018-2021
// Author: Ulf Frisk, pcileech@frizk.net
//

#include "vmmdll.h"
#include "pluginmanager.h"
#include "charutil.h"
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

#ifdef _WIN32

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

#endif /* _WIN32 */

EXPORTED_FUNCTION _Success_(return)
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
#ifdef _WIN32
        if(pLcErrorInfo && (pLcErrorInfo->dwVersion == LC_CONFIG_ERRORINFO_VERSION)) {
            if(pLcErrorInfo->cwszUserText) {
                vmmwprintf(L"MESSAGE FROM MEMORY ACQUISITION DEVICE:\n=======================================\n%s\n", pLcErrorInfo->wszUserText);
            }
            if(ctxMain->cfg.fUserInteract && pLcErrorInfo->fUserInputRequest) {
                LcMemFree(pLcErrorInfo);
                return VMMDLL_Initialize_RequestUserInput(argc, argv);
            }
        }
#endif /* _WIN32 */
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

EXPORTED_FUNCTION _Success_(return)
BOOL VMMDLL_Initialize(_In_ DWORD argc, _In_ LPSTR argv[])
{
    return VMMDLL_InitializeEx(argc, argv, NULL);
}

EXPORTED_FUNCTION _Success_(return)
BOOL VMMDLL_Close()
{
    VmmDll_FreeContext();
    return TRUE;
}

/*
* Free memory allocated by the VMMDLL.
* -- pvMem
*/
EXPORTED_FUNCTION VOID VMMDLL_MemFree(_Frees_ptr_opt_ PVOID pvMem)
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

#define VMMDLL_REFRESH_CHECK(fOption, mask)      (fOption & mask & 0xffff00000000)

_Success_(return)
BOOL VMMDLL_ConfigGet(_In_ ULONG64 fOption, _Out_ PULONG64 pqwValue)
{
    if(!fOption || !pqwValue) { return FALSE; }
    switch(fOption & 0xffffffff00000000) {
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
    if((fOption & 0xffff000000000000) == 0x2001000000000000) {
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
    switch(fOption & 0xffffffff00000000) {
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
    CHAR uszBufferFileName[MAX_PATH];
    VMMDLL_VFS_FILELIST_EXINFO ExInfo = { 0 };
    while((pObProcess = VmmProcessGetNext(pObProcess, 0))) {
        if(fNamePID) {
            if(pObProcess->dwState) {
                sprintf_s(uszBufferFileName, MAX_PATH - 1, "%s-(%x)-%i", pObProcess->szName, pObProcess->dwState, pObProcess->dwPID);
            } else {
                sprintf_s(uszBufferFileName, MAX_PATH - 1, "%s-%i", pObProcess->szName, pObProcess->dwPID);
            }
        } else {
            sprintf_s(uszBufferFileName, MAX_PATH - 1, "%i", pObProcess->dwPID);
        }
        Util_VfsTimeStampFile(pObProcess, &ExInfo);
        VMMDLL_VfsList_AddDirectory(pFileList, uszBufferFileName, &ExInfo);
    }
    return TRUE;
}


BOOL VMMDLL_VfsList_Impl(_In_ LPSTR uszPath, _Inout_ PHANDLE pFileList)
{
    BOOL result = FALSE;
    DWORD dwPID;
    LPSTR wszSubPath;
    PVMM_PROCESS pObProcess;
    if(!ctxVmm || !VMMDLL_VfsList_IsHandleValid(pFileList)) { return FALSE; }
    if(uszPath[0] == '\\') { uszPath++; }
    if(Util_VfsHelper_GetIdDir(uszPath, &dwPID, &wszSubPath)) {
        if(!(pObProcess = VmmProcessGet(dwPID))) { return FALSE; }
        PluginManager_List(pObProcess, wszSubPath, pFileList);
        Ob_DECREF(pObProcess);
        return TRUE;
    }
    if(!_strnicmp(uszPath, "name", 4)) {
        if(strlen(uszPath) > 5) { return FALSE; }
        return VMMDLL_VfsList_Impl_ProcessRoot(TRUE, pFileList);
    }
    if(!_strnicmp(uszPath, "pid", 3)) {
        if(strlen(uszPath) > 4) { return FALSE; }
        return VMMDLL_VfsList_Impl_ProcessRoot(FALSE, pFileList);
    }
    PluginManager_List(NULL, uszPath, pFileList);
    return TRUE;
}

_Success_(return)
BOOL VMMDLL_VfsListU(_In_ LPSTR uszPath, _Inout_ PVMMDLL_VFS_FILELIST2 pFileList)
{
    CALL_IMPLEMENTATION_VMM(
        STATISTICS_ID_VMMDLL_VfsList,
        VMMDLL_VfsList_Impl(uszPath, (PHANDLE)pFileList))
}

_Success_(return)
BOOL VMMDLL_VfsListW(_In_ LPWSTR wszPath, _Inout_ PVMMDLL_VFS_FILELIST2 pFileList)
{
    LPSTR uszPath;
    BYTE pbBuffer[3 * MAX_PATH];
    if(!CharUtil_WtoU(wszPath, -1, pbBuffer, sizeof(pbBuffer), &uszPath, NULL, 0)) { return FALSE; }
    return VMMDLL_VfsListU(uszPath, pFileList);
}

typedef struct tdVMMDLL_VFS_FILELISTBLOB_CREATE_CONTEXT {
    POB_MAP pme;
    POB_STRMAP psm;
} VMMDLL_VFS_FILELISTBLOB_CREATE_CONTEXT, *PVMMDLL_VFS_FILELISTBLOB_CREATE_CONTEXT;

VOID VMMDLL_VfsListBlob_Impl_AddFile(_Inout_ HANDLE h, _In_ LPSTR uszName, _In_ ULONG64 cb, _In_opt_ PVMMDLL_VFS_FILELIST_EXINFO pExInfo)
{
    PVMMDLL_VFS_FILELISTBLOB_CREATE_CONTEXT ctx = (PVMMDLL_VFS_FILELISTBLOB_CREATE_CONTEXT)h;
    PVMMDLL_VFS_FILELISTBLOB_ENTRY pe = NULL;
    if(!(pe = LocalAlloc(LMEM_ZEROINIT, sizeof(VMMDLL_VFS_FILELISTBLOB_ENTRY)))) { return; }
    if(!ObStrMap_PushPtrUU(ctx->psm, uszName, (LPSTR*)&pe->ouszName, NULL)) {
        LocalFree(pe);
        return;
    }
    if(pExInfo) {
        memcpy(&pe->ExInfo, pExInfo, sizeof(VMMDLL_VFS_FILELIST_EXINFO));
    }
    pe->cbFileSize = cb;
    ObMap_Push(ctx->pme, (QWORD)pe, pe);    // reference to pe overtaken by ctx->pme
}

VOID VMMDLL_VfsListBlob_Impl_AddDirectory(_Inout_ HANDLE h, _In_ LPSTR uszName, _In_opt_ PVMMDLL_VFS_FILELIST_EXINFO pExInfo)
{
    VMMDLL_VfsListBlob_Impl_AddFile(h, uszName, (ULONG64)-1, pExInfo);
}

_Success_(return != NULL)
PVMMDLL_VFS_FILELISTBLOB VMMDLL_VfsListBlob_Impl(_In_ LPSTR uszPath)
{
    BOOL fResult = FALSE;
    VMMDLL_VFS_FILELISTBLOB_CREATE_CONTEXT ctx = { 0 };
    VMMDLL_VFS_FILELIST2 FL2;
    DWORD i = 0, cbStruct, cFileEntry, cbMultiText;
    PVMMDLL_VFS_FILELISTBLOB pFLB = NULL;
    PVMMDLL_VFS_FILELISTBLOB_ENTRY pe;
    // 1: init
    if(!(ctx.pme = ObMap_New(OB_MAP_FLAGS_OBJECT_LOCALFREE))) { goto fail; }
    if(!(ctx.psm = ObStrMap_New(OB_STRMAP_FLAGS_STR_ASSIGN_OFFSET))) { goto fail; }
    // 2: call
    FL2.dwVersion = VMMDLL_VFS_FILELIST_VERSION;
    FL2.pfnAddFile = VMMDLL_VfsListBlob_Impl_AddFile;
    FL2.pfnAddDirectory = VMMDLL_VfsListBlob_Impl_AddDirectory;
    FL2.h = &ctx;
    if(!VMMDLL_VfsList_Impl(uszPath, (PHANDLE)&FL2)) { goto fail; }
    // 3: assign result blob
    cFileEntry = ObMap_Size(ctx.pme);
    if(!ObStrMap_FinalizeBufferU(ctx.psm, 0, NULL, &cbMultiText)) { goto fail; }
    cbStruct = sizeof(VMMDLL_VFS_FILELISTBLOB) + cFileEntry * sizeof(VMMDLL_VFS_FILELISTBLOB_ENTRY) + cbMultiText;
    if(!(pFLB = LocalAlloc(0, cbStruct))) { goto fail; }
    ZeroMemory(pFLB, sizeof(VMMDLL_VFS_FILELISTBLOB));
    pFLB->dwVersion = VMMDLL_VFS_FILELISTBLOB_VERSION;
    pFLB->cbStruct = cbStruct;
    pFLB->cFileEntry = cFileEntry;
    pFLB->uszMultiText = (LPSTR)((QWORD)pFLB + sizeof(VMMDLL_VFS_FILELISTBLOB) + cFileEntry * sizeof(VMMDLL_VFS_FILELISTBLOB_ENTRY));
    if(!ObStrMap_FinalizeBufferU(ctx.psm, cbMultiText, pFLB->uszMultiText, &pFLB->cbMultiText)) { goto fail; }
    for(i = 0; i < cFileEntry; i++) {
        pe = ObMap_GetByIndex(ctx.pme, i);
        if(!pe) { goto fail; }
        memcpy(pFLB->FileEntry + i, pe, sizeof(VMMDLL_VFS_FILELISTBLOB_ENTRY));
    }
    fResult = TRUE;
fail:
    Ob_DECREF(ctx.pme);
    Ob_DECREF(ctx.psm);
    if(!fResult) { LocalFree(pFLB); }
    return fResult ? pFLB : NULL;
}

_Success_(return != NULL)
PVMMDLL_VFS_FILELISTBLOB VMMDLL_VfsListBlobU(_In_ LPSTR uszPath)
{
    CALL_IMPLEMENTATION_VMM_RETURN(
        STATISTICS_ID_VMMDLL_VfsListBlob,
        PVMMDLL_VFS_FILELISTBLOB,
        NULL,
        VMMDLL_VfsListBlob_Impl(uszPath))
}

NTSTATUS VMMDLL_VfsRead_Impl(LPSTR uszPath, _Out_writes_to_(cb, *pcbRead) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset)
{
    NTSTATUS nt;
    DWORD dwPID;
    LPSTR uszSubPath;
    PVMM_PROCESS pObProcess;
    if(!ctxVmm) { return VMM_STATUS_FILE_INVALID; }
    if(uszPath[0] == '\\') { uszPath++; }
    if(Util_VfsHelper_GetIdDir(uszPath, &dwPID, &uszSubPath)) {
        if(!(pObProcess = VmmProcessGet(dwPID))) { return VMM_STATUS_FILE_INVALID; }
        nt = PluginManager_Read(pObProcess, uszSubPath, pb, cb, pcbRead, cbOffset);
        Ob_DECREF(pObProcess);
        return nt;
    }
    return PluginManager_Read(NULL, uszPath, pb, cb, pcbRead, cbOffset);
}

NTSTATUS VMMDLL_VfsReadU(_In_ LPSTR uszFileName, _Out_writes_to_(cb, *pcbRead) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ ULONG64 cbOffset)
{
    CALL_IMPLEMENTATION_VMM_RETURN(
        STATISTICS_ID_VMMDLL_VfsRead,
        NTSTATUS,
        VMMDLL_STATUS_UNSUCCESSFUL,
        VMMDLL_VfsRead_Impl(uszFileName, pb, cb, pcbRead, cbOffset))
}

NTSTATUS VMMDLL_VfsReadW(_In_ LPWSTR wszFileName, _Out_writes_to_(cb, *pcbRead) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ ULONG64 cbOffset)
{
    LPSTR uszFileName;
    BYTE pbBuffer[3 * MAX_PATH];
    if(!CharUtil_WtoU(wszFileName, -1, pbBuffer, sizeof(pbBuffer), &uszFileName, NULL, 0)) { return VMM_STATUS_FILE_INVALID; }
    return VMMDLL_VfsReadU(uszFileName, pb, cb, pcbRead, cbOffset);
}

NTSTATUS VMMDLL_VfsWrite_Impl(_In_ LPSTR uszPath, _In_reads_(cb) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbWrite, _In_ QWORD cbOffset)
{
    NTSTATUS nt;
    DWORD dwPID;
    LPSTR uszSubPath;
    PVMM_PROCESS pObProcess;
    if(!ctxVmm) { return VMM_STATUS_FILE_INVALID; }
    if(uszPath[0] == '\\') { uszPath++; }
    if(Util_VfsHelper_GetIdDir(uszPath, &dwPID, &uszSubPath)) {
        if(!(pObProcess = VmmProcessGet(dwPID))) { return VMM_STATUS_FILE_INVALID; }
        nt = PluginManager_Write(pObProcess, uszSubPath, pb, cb, pcbWrite, cbOffset);
        Ob_DECREF(pObProcess);
        return nt;
    }
    return PluginManager_Write(NULL, uszPath, pb, cb, pcbWrite, cbOffset);
}

NTSTATUS VMMDLL_VfsWriteU(_In_ LPSTR uszFileName, _In_reads_(cb) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbWrite, _In_ ULONG64 cbOffset)
{
    CALL_IMPLEMENTATION_VMM_RETURN(
        STATISTICS_ID_VMMDLL_VfsWrite,
        NTSTATUS,
        VMMDLL_STATUS_UNSUCCESSFUL,
        VMMDLL_VfsWrite_Impl(uszFileName, pb, cb, pcbWrite, cbOffset))
}

NTSTATUS VMMDLL_VfsWriteW(_In_ LPWSTR wszFileName, _In_reads_(cb) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbWrite, _In_ ULONG64 cbOffset)
{
    LPSTR uszFileName;
    BYTE pbBuffer[3 * MAX_PATH];
    if(!CharUtil_WtoU(wszFileName, -1, pbBuffer, sizeof(pbBuffer), &uszFileName, NULL, 0)) { return VMM_STATUS_FILE_INVALID; }
    return VMMDLL_VfsWriteU(uszFileName, pb, cb, pcbWrite, cbOffset);
}

EXPORTED_FUNCTION NTSTATUS VMMDLL_UtilVfsReadFile_FromPBYTE(_In_ PBYTE pbFile, _In_ ULONG64 cbFile, _Out_writes_to_(cb, *pcbRead) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ ULONG64 cbOffset)
{
    return Util_VfsReadFile_FromPBYTE(pbFile, cbFile, pb, cb, pcbRead, cbOffset);
}

EXPORTED_FUNCTION NTSTATUS VMMDLL_UtilVfsReadFile_FromQWORD(_In_ ULONG64 qwValue, _Out_writes_to_(cb, *pcbRead) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ ULONG64 cbOffset, _In_ BOOL fPrefix)
{
    return Util_VfsReadFile_FromQWORD(qwValue, pb, cb, pcbRead, cbOffset, fPrefix);
}

EXPORTED_FUNCTION NTSTATUS VMMDLL_UtilVfsReadFile_FromDWORD(_In_ DWORD dwValue, _Out_writes_to_(cb, *pcbRead) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ ULONG64 cbOffset, _In_ BOOL fPrefix)
{
    return Util_VfsReadFile_FromDWORD(dwValue, pb, cb, pcbRead, cbOffset, fPrefix);
}

EXPORTED_FUNCTION NTSTATUS VMMDLL_UtilVfsReadFile_FromBOOL(_In_ BOOL fValue, _Out_writes_to_(cb, *pcbRead) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ ULONG64 cbOffset)
{
    return Util_VfsReadFile_FromBOOL(fValue, pb, cb, pcbRead, cbOffset);
}

EXPORTED_FUNCTION NTSTATUS VMMDLL_UtilVfsWriteFile_BOOL(_Inout_ PBOOL pfTarget, _In_reads_(cb) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbWrite, _In_ ULONG64 cbOffset)
{
    return Util_VfsWriteFile_BOOL(pfTarget, pb, cb, pcbWrite, cbOffset);
}

EXPORTED_FUNCTION NTSTATUS VMMDLL_UtilVfsWriteFile_DWORD(_Inout_ PDWORD pdwTarget, _In_reads_(cb) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbWrite, _In_ ULONG64 cbOffset, _In_ DWORD dwMinAllow)
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
BOOL VMMDLL_Map_GetPte_Impl(_In_ DWORD dwPID, _Out_writes_bytes_opt_(*pcbMapDst) PVMMDLL_MAP_PTE pMapDst, _Inout_ PDWORD pcbMapDst, _In_ BOOL fIdentifyModules, _In_ BOOL fWideChar)
{
    BOOL f, fResult = FALSE;
    PVMM_PROCESS pObProcess = NULL;
    DWORD i, cbDst = 0, cbDstData, cbDstStr;
    PVMMDLL_MAP_PTEENTRY peDst;
    PVMM_MAP_PTEENTRY peSrc;
    PVMMOB_MAP_PTE pObMapSrc = NULL;
    POB_STRMAP psmOb = NULL;
    // 0: sanity check:
    if(sizeof(VMM_MAP_PTEENTRY) != sizeof(VMMDLL_MAP_PTEENTRY)) { goto fail; }
    // 1: fetch map [and populate strings]:
    if(!(psmOb = ObStrMap_New(0))) { goto fail; }
    if(!(pObProcess = VmmProcessGet(dwPID))) { goto fail; }
    if(!VmmMap_GetPte(pObProcess, &pObMapSrc, fIdentifyModules)) { goto fail; }
    for(i = 0; i < pObMapSrc->cMap; i++) {
        peSrc = pObMapSrc->pMap + i;
        ObStrMap_PushU(psmOb, peSrc->uszText);
    }
    // 2: byte count:
    if(!ObStrMap_FinalizeBufferXUW(psmOb, 0, NULL, &cbDstStr, fWideChar)) { goto fail; }
    cbDstData = pObMapSrc->cMap * sizeof(VMMDLL_MAP_PTEENTRY);
    cbDst = sizeof(VMMDLL_MAP_PTE) + cbDstData + cbDstStr;
    // 3: fill map [if required]:
    if(pMapDst) {
        if(*pcbMapDst < cbDst) { goto fail; }
        ZeroMemory(pMapDst, sizeof(VMMDLL_MAP_PTE));
        pMapDst->dwVersion = VMMDLL_MAP_PTE_VERSION;
        pMapDst->cMap = pObMapSrc->cMap;
        memcpy(pMapDst->pMap, pObMapSrc->pMap, cbDstData);
        // strmap below:
        for(i = 0; i < pMapDst->cMap; i++) {
            peSrc = pObMapSrc->pMap + i;
            peDst = pMapDst->pMap + i;
            f = ObStrMap_PushPtrUXUW(psmOb, peSrc->uszText, &peDst->uszText, NULL, fWideChar);
            if(!f) { goto fail; }
        }
        pMapDst->pbMultiText = ((PBYTE)pMapDst->pMap) + cbDstData;
        ObStrMap_FinalizeBufferXUW(psmOb, cbDstStr, pMapDst->pbMultiText, &pMapDst->cbMultiText, fWideChar);
    }
    fResult = TRUE;
fail:
    *pcbMapDst = (DWORD)cbDst;
    Ob_DECREF(pObProcess);
    Ob_DECREF(pObMapSrc);
    Ob_DECREF(psmOb);
    return fResult;
}

_Success_(return) BOOL VMMDLL_Map_GetPteU(_In_ DWORD dwPID, _Out_writes_bytes_opt_(*pcbPteMap) PVMMDLL_MAP_PTE pPteMap, _Inout_ PDWORD pcbPteMap, _In_ BOOL fIdentifyModules)
{
    CALL_IMPLEMENTATION_VMM(STATISTICS_ID_VMMDLL_Map_GetPte, VMMDLL_Map_GetPte_Impl(dwPID, pPteMap, pcbPteMap, fIdentifyModules, FALSE))
}

_Success_(return) BOOL VMMDLL_Map_GetPteW(_In_ DWORD dwPID, _Out_writes_bytes_opt_(*pcbPteMap) PVMMDLL_MAP_PTE pPteMap, _Inout_ PDWORD pcbPteMap, _In_ BOOL fIdentifyModules)
{
    CALL_IMPLEMENTATION_VMM(STATISTICS_ID_VMMDLL_Map_GetPte, VMMDLL_Map_GetPte_Impl(dwPID, pPteMap, pcbPteMap, fIdentifyModules, TRUE))
}

_Success_(return)
BOOL VMMDLL_Map_GetVad_Impl(_In_ DWORD dwPID, _Out_writes_bytes_opt_(*pcbMapDst) PVMMDLL_MAP_VAD pMapDst, _Inout_ PDWORD pcbMapDst, _In_ BOOL fIdentifyModules, _In_ BOOL fWideChar)
{
    BOOL f, fResult = FALSE;
    PVMM_PROCESS pObProcess = NULL;
    DWORD i, cbDst = 0, cbDstData, cbDstStr;
    PVMMDLL_MAP_VADENTRY peDst;
    PVMM_MAP_VADENTRY peSrc;
    PVMMOB_MAP_VAD pObMapSrc = NULL;
    POB_STRMAP psmOb = NULL;
    // 0: sanity check:
    if(sizeof(VMM_MAP_VADENTRY) != sizeof(VMMDLL_MAP_VADENTRY)) { goto fail; }
    // 1: fetch map [and populate strings]:
    if(!(psmOb = ObStrMap_New(0))) { goto fail; }
    if(!(pObProcess = VmmProcessGet(dwPID))) { goto fail; }
    if(!VmmMap_GetVad(pObProcess, &pObMapSrc, (fIdentifyModules ? VMM_VADMAP_TP_FULL : VMM_VADMAP_TP_PARTIAL))) { goto fail; }
    for(i = 0; i < pObMapSrc->cMap; i++) {
        peSrc = pObMapSrc->pMap + i;
        ObStrMap_PushU(psmOb, peSrc->uszText);
    }
    // 2: byte count:
    if(!ObStrMap_FinalizeBufferXUW(psmOb, 0, NULL, &cbDstStr, fWideChar)) { goto fail; }
    cbDstData = pObMapSrc->cMap * sizeof(VMMDLL_MAP_VADENTRY);
    cbDst = sizeof(VMMDLL_MAP_VAD) + cbDstData + cbDstStr;
    // 3: fill map [if required]:
    if(pMapDst) {
        if(*pcbMapDst < cbDst) { goto fail; }
        ZeroMemory(pMapDst, sizeof(VMMDLL_MAP_VAD));
        pMapDst->dwVersion = VMMDLL_MAP_VAD_VERSION;
        pMapDst->cPage = pObMapSrc->cPage;
        pMapDst->cMap = pObMapSrc->cMap;
        memcpy(pMapDst->pMap, pObMapSrc->pMap, cbDstData);
        // strmap below:
        for(i = 0; i < pMapDst->cMap; i++) {
            peSrc = pObMapSrc->pMap + i;
            peDst = pMapDst->pMap + i;
            f = ObStrMap_PushPtrUXUW(psmOb, peSrc->uszText, &peDst->uszText, NULL, fWideChar);
            if(!f) { goto fail; }
        }
        pMapDst->pbMultiText = ((PBYTE)pMapDst->pMap) + cbDstData;
        ObStrMap_FinalizeBufferXUW(psmOb, cbDstStr, pMapDst->pbMultiText, &pMapDst->cbMultiText, fWideChar);
    }
    fResult = TRUE;
fail:
    *pcbMapDst = cbDst;
    Ob_DECREF(pObProcess);
    Ob_DECREF(pObMapSrc);
    Ob_DECREF(psmOb);
    return fResult;
}

_Success_(return) BOOL VMMDLL_Map_GetVadU(_In_ DWORD dwPID, _Out_writes_bytes_opt_(*pcbVadMap) PVMMDLL_MAP_VAD pVadMap, _Inout_ PDWORD pcbVadMap, _In_ BOOL fIdentifyModules)
{
    CALL_IMPLEMENTATION_VMM(STATISTICS_ID_VMMDLL_Map_GetVad, VMMDLL_Map_GetVad_Impl(dwPID, pVadMap, pcbVadMap, fIdentifyModules, FALSE))
}

_Success_(return) BOOL VMMDLL_Map_GetVadW(_In_ DWORD dwPID, _Out_writes_bytes_opt_(*pcbVadMap) PVMMDLL_MAP_VAD pVadMap, _Inout_ PDWORD pcbVadMap, _In_ BOOL fIdentifyModules)
{
    CALL_IMPLEMENTATION_VMM(STATISTICS_ID_VMMDLL_Map_GetVad, VMMDLL_Map_GetVad_Impl(dwPID, pVadMap, pcbVadMap, fIdentifyModules, TRUE))
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
BOOL VMMDLL_Map_GetModule_Impl(_In_ DWORD dwPID, _Out_writes_bytes_opt_(*pcbMapDst) PVMMDLL_MAP_MODULE pMapDst, _Inout_ PDWORD pcbMapDst, _In_ BOOL fWideChar)
{
    BOOL f, fResult = FALSE;
    PVMM_PROCESS pObProcess = NULL;
    DWORD i, cbDst = 0, cbDstData, cbDstStr;
    PVMMDLL_MAP_MODULEENTRY peDst;
    PVMM_MAP_MODULEENTRY peSrc;
    PVMMOB_MAP_MODULE pObMapSrc = NULL;
    POB_STRMAP psmOb = NULL;
    // 0: sanity check:
    if(sizeof(VMM_MAP_MODULEENTRY) != sizeof(VMMDLL_MAP_MODULEENTRY)) { goto fail; }
    // 1: fetch map [and populate strings]:
    if(!(psmOb = ObStrMap_New(0))) { goto fail; }
    if(!(pObProcess = VmmProcessGet(dwPID))) { goto fail; }
    if(!VmmMap_GetModule(pObProcess, &pObMapSrc)) { goto fail; }
    for(i = 0; i < pObMapSrc->cMap; i++) {
        peSrc = pObMapSrc->pMap + i;
        ObStrMap_PushU(psmOb, peSrc->uszText);
        ObStrMap_PushU(psmOb, peSrc->uszFullName);
    }
    // 2: byte count:
    if(!ObStrMap_FinalizeBufferXUW(psmOb, 0, NULL, &cbDstStr, fWideChar)) { goto fail; }
    cbDstData = pObMapSrc->cMap * sizeof(VMMDLL_MAP_MODULEENTRY);
    cbDst = sizeof(VMMDLL_MAP_MODULE) + cbDstData + cbDstStr;
    // 3: fill map [if required]:
    if(pMapDst) {
        if(*pcbMapDst < cbDst) { goto fail; }
        ZeroMemory(pMapDst, sizeof(VMMDLL_MAP_MODULE));
        pMapDst->dwVersion = VMMDLL_MAP_MODULE_VERSION;
        pMapDst->cMap = pObMapSrc->cMap;
        memcpy(pMapDst->pMap, pObMapSrc->pMap, cbDstData);
        // strmap below:
        for(i = 0; i < pMapDst->cMap; i++) {
            peSrc = pObMapSrc->pMap + i;
            peDst = pMapDst->pMap + i;
            f = ObStrMap_PushPtrUXUW(psmOb, peSrc->uszText, &peDst->uszText, NULL, fWideChar) &&
                ObStrMap_PushPtrUXUW(psmOb, peSrc->uszFullName, &peDst->uszFullName, NULL, fWideChar);
            if(!f) { goto fail; }
        }
        pMapDst->pbMultiText = ((PBYTE)pMapDst->pMap) + cbDstData;
        ObStrMap_FinalizeBufferXUW(psmOb, cbDstStr, pMapDst->pbMultiText, &pMapDst->cbMultiText, fWideChar);
    }
    fResult = TRUE;
fail:
    *pcbMapDst = cbDst;
    Ob_DECREF(pObProcess);
    Ob_DECREF(pObMapSrc);
    Ob_DECREF(psmOb);
    return fResult;
}

_Success_(return) BOOL VMMDLL_Map_GetModuleU(_In_ DWORD dwPID, _Out_writes_bytes_opt_(*pcbModuleMap) PVMMDLL_MAP_MODULE pModuleMap, _Inout_ PDWORD pcbModuleMap)
{
    CALL_IMPLEMENTATION_VMM(STATISTICS_ID_VMMDLL_Map_GetModule, VMMDLL_Map_GetModule_Impl(dwPID, pModuleMap, pcbModuleMap, FALSE))
}

_Success_(return) BOOL VMMDLL_Map_GetModuleW(_In_ DWORD dwPID, _Out_writes_bytes_opt_(*pcbModuleMap) PVMMDLL_MAP_MODULE pModuleMap, _Inout_ PDWORD pcbModuleMap)
{
    CALL_IMPLEMENTATION_VMM(STATISTICS_ID_VMMDLL_Map_GetModule, VMMDLL_Map_GetModule_Impl(dwPID, pModuleMap, pcbModuleMap, TRUE))
}

_Success_(return)
BOOL VMMDLL_Map_GetModuleFromName_Impl(_In_ DWORD dwPID, _In_opt_ LPSTR uszModuleName, _Out_writes_bytes_opt_(*pcbDst) PVMMDLL_MAP_MODULEENTRY peDst, _Inout_opt_ PDWORD pcbDst, _In_ BOOL fWideChar)
{
    BOOL f, fResult = FALSE;
    DWORD o = 0, cbDst = 0, cbDstStr, cbTMP;
    PVMMOB_MAP_MODULE pObMapSrc = NULL;
    PVMM_MAP_MODULEENTRY peSrc = NULL;
    POB_STRMAP psmOb = NULL;
    PBYTE pbMultiText;
    // 0: sanity check:
    if(!peDst && !pcbDst) { goto fail; }
    if(sizeof(VMM_MAP_MODULEENTRY) != sizeof(VMMDLL_MAP_MODULEENTRY)) { goto fail; }
    if(!VmmMap_GetModuleEntryEx(NULL, dwPID, uszModuleName, &pObMapSrc, &peSrc)) { goto fail; }
    if(!pcbDst) {       // case of no name module data request.
        memcpy(peDst, peSrc, sizeof(VMMDLL_MAP_MODULEENTRY));
        peDst->wszText = NULL;
        peDst->wszFullName = NULL;
        return TRUE;
    }
    // 1: fetch map [and populate strings]:
    if(!(psmOb = ObStrMap_New(0))) { goto fail; }
    ObStrMap_PushU(psmOb, peSrc->uszText);
    ObStrMap_PushU(psmOb, peSrc->uszFullName);
    // 2: byte count:
    if(!ObStrMap_FinalizeBufferXUW(psmOb, 0, NULL, &cbDstStr, fWideChar)) { goto fail; }
    cbDst = sizeof(VMMDLL_MAP_MODULEENTRY) + cbDstStr;
    if(peDst) {
        if(*pcbDst < cbDst) { goto fail; }
        memcpy(peDst, peSrc, sizeof(VMMDLL_MAP_MODULEENTRY));
        // strmap below:
        f = ObStrMap_PushPtrUXUW(psmOb, peSrc->uszText, &peDst->uszText, NULL, fWideChar) &&
            ObStrMap_PushPtrUXUW(psmOb, peSrc->uszFullName, &peDst->uszFullName, NULL, fWideChar);
        if(!f) { goto fail; }
        pbMultiText = ((PBYTE)peDst) + sizeof(VMMDLL_MAP_MODULEENTRY);
        ObStrMap_FinalizeBufferXUW(psmOb, cbDstStr, pbMultiText, &cbTMP, fWideChar);
    }
    fResult = TRUE;
fail:
    if(pcbDst) { *pcbDst = cbDst; }
    Ob_DECREF(pObMapSrc);
    return fResult;
}

_Success_(return) BOOL VMMDLL_Map_GetModuleFromNameU(_In_ DWORD dwPID, _In_opt_ LPSTR uszModuleName, _Out_writes_bytes_opt_(*pcbModuleMapEntry) PVMMDLL_MAP_MODULEENTRY pModuleMapEntry, _Inout_opt_ PDWORD pcbModuleMapEntry)
{
    CALL_IMPLEMENTATION_VMM(STATISTICS_ID_VMMDLL_Map_GetModuleFromName, VMMDLL_Map_GetModuleFromName_Impl(dwPID, uszModuleName, pModuleMapEntry, pcbModuleMapEntry, FALSE))
}

_Success_(return) BOOL VMMDLL_Map_GetModuleFromNameW(_In_ DWORD dwPID, _In_opt_ LPWSTR wszModuleName, _Out_writes_bytes_opt_(*pcbModuleMapEntry) PVMMDLL_MAP_MODULEENTRY pModuleMapEntry, _Inout_opt_ PDWORD pcbModuleMapEntry)
{
    LPSTR uszModuleName = NULL;
    BYTE pbBuffer[MAX_PATH];
    if(wszModuleName) {
        if(!CharUtil_WtoU(wszModuleName, -1, pbBuffer, sizeof(pbBuffer), &uszModuleName, NULL, 0)) { return FALSE; }
    }
    CALL_IMPLEMENTATION_VMM(STATISTICS_ID_VMMDLL_Map_GetModuleFromName, VMMDLL_Map_GetModuleFromName_Impl(dwPID, uszModuleName, pModuleMapEntry, pcbModuleMapEntry, TRUE))
}

_Success_(return)
BOOL VMMDLL_Map_GetUnloadedModule_Impl(_In_ DWORD dwPID, _Out_writes_bytes_opt_(*pcbMapDst) PVMMDLL_MAP_UNLOADEDMODULE pMapDst, _Inout_ PDWORD pcbMapDst, _In_ BOOL fWideChar)
{
    BOOL f, fResult = FALSE;
    PVMM_PROCESS pObProcess = NULL;
    DWORD i, cbDst = 0, cbDstData, cbDstStr;
    PVMMDLL_MAP_UNLOADEDMODULEENTRY peDst;
    PVMM_MAP_UNLOADEDMODULEENTRY peSrc;
    PVMMOB_MAP_UNLOADEDMODULE pObMapSrc = NULL;
    POB_STRMAP psmOb = NULL;
    // 0: sanity check:
    if(sizeof(VMM_MAP_UNLOADEDMODULEENTRY) != sizeof(VMMDLL_MAP_UNLOADEDMODULEENTRY)) { goto fail; }
    // 1: fetch map [and populate strings]:
    if(!(psmOb = ObStrMap_New(0))) { goto fail; }
    if(!(pObProcess = VmmProcessGet(dwPID))) { goto fail; }
    if(!VmmMap_GetUnloadedModule(pObProcess, &pObMapSrc)) { goto fail; }
    for(i = 0; i < pObMapSrc->cMap; i++) {
        peSrc = pObMapSrc->pMap + i;
        ObStrMap_PushU(psmOb, peSrc->uszText);
    }
    // 2: byte count:
    if(!ObStrMap_FinalizeBufferXUW(psmOb, 0, NULL, &cbDstStr, fWideChar)) { goto fail; }
    cbDstData = pObMapSrc->cMap * sizeof(VMMDLL_MAP_UNLOADEDMODULEENTRY);
    cbDst = sizeof(VMMDLL_MAP_UNLOADEDMODULE) + cbDstData + cbDstStr;
    // 3: fill map [if required]:
    if(pMapDst) {
        if(*pcbMapDst < cbDst) { goto fail; }
        ZeroMemory(pMapDst, sizeof(VMMDLL_MAP_UNLOADEDMODULE));
        pMapDst->dwVersion = VMMDLL_MAP_UNLOADEDMODULE_VERSION;
        pMapDst->cMap = pObMapSrc->cMap;
        memcpy(pMapDst->pMap, pObMapSrc->pMap, cbDstData);
        // strmap below:
        for(i = 0; i < pMapDst->cMap; i++) {
            peSrc = pObMapSrc->pMap + i;
            peDst = pMapDst->pMap + i;
            f = ObStrMap_PushPtrUXUW(psmOb, peSrc->uszText, &peDst->uszText, NULL, fWideChar);
            if(!f) { goto fail; }
        }
        pMapDst->pbMultiText = ((PBYTE)pMapDst->pMap) + cbDstData;
        ObStrMap_FinalizeBufferXUW(psmOb, cbDstStr, pMapDst->pbMultiText, &pMapDst->cbMultiText, fWideChar);
    }
    fResult = TRUE;
fail:
    *pcbMapDst = cbDst;
    Ob_DECREF(pObProcess);
    Ob_DECREF(pObMapSrc);
    Ob_DECREF(psmOb);
    return fResult;
}

_Success_(return) BOOL VMMDLL_Map_GetUnloadedModuleU(_In_ DWORD dwPID, _Out_writes_bytes_opt_(*pcbUnloadedModuleMap) PVMMDLL_MAP_UNLOADEDMODULE pUnloadedModuleMap, _Inout_ PDWORD pcbUnloadedModuleMap)
{
    CALL_IMPLEMENTATION_VMM(STATISTICS_ID_VMMDLL_Map_GetUnloadedModule, VMMDLL_Map_GetUnloadedModule_Impl(dwPID, pUnloadedModuleMap, pcbUnloadedModuleMap, FALSE))
}

_Success_(return) BOOL VMMDLL_Map_GetUnloadedModuleW(_In_ DWORD dwPID, _Out_writes_bytes_opt_(*pcbUnloadedModuleMap) PVMMDLL_MAP_UNLOADEDMODULE pUnloadedModuleMap, _Inout_ PDWORD pcbUnloadedModuleMap)
{
    CALL_IMPLEMENTATION_VMM(STATISTICS_ID_VMMDLL_Map_GetUnloadedModule, VMMDLL_Map_GetUnloadedModule_Impl(dwPID, pUnloadedModuleMap, pcbUnloadedModuleMap, TRUE))
}

_Success_(return)
BOOL VMMDLL_Map_GetEAT_Impl(_In_ DWORD dwPID, _In_ LPSTR uszModuleName, _Out_writes_bytes_opt_(*pcbMapDst) PVMMDLL_MAP_EAT pMapDst, _Inout_ PDWORD pcbMapDst, _In_ BOOL fWideChar)
{
    BOOL f, fResult = FALSE;
    PVMM_PROCESS pObProcess = NULL;
    PVMMOB_MAP_MODULE pObModuleMap = NULL;
    PVMM_MAP_MODULEENTRY pModuleEntry = NULL;
    DWORD i, cbDst = 0, cbDstData, cbDstStr;
    PVMMDLL_MAP_EATENTRY peDst;
    PVMM_MAP_EATENTRY peSrc;
    PVMMOB_MAP_EAT pObMapSrc = NULL;
    POB_STRMAP psmOb = NULL;
    // 0: sanity check:
    if(sizeof(VMM_MAP_EATENTRY) != sizeof(VMMDLL_MAP_EATENTRY)) { goto fail; }
    // 1: fetch map [and populate strings]:
    if(!(psmOb = ObStrMap_New(0))) { goto fail; }
    if(!(pObProcess = VmmProcessGet(dwPID))) { goto fail; }
    if(!VmmMap_GetModuleEntryEx(pObProcess, 0, uszModuleName, &pObModuleMap, &pModuleEntry)) { goto fail; }
    if(!VmmMap_GetEAT(pObProcess, pModuleEntry, &pObMapSrc)) { goto fail; }
    for(i = 0; i < pObMapSrc->cMap; i++) {
        peSrc = pObMapSrc->pMap + i;
        ObStrMap_PushU(psmOb, peSrc->uszFunction);
    }
    // 2: byte count:
    if(!ObStrMap_FinalizeBufferXUW(psmOb, 0, NULL, &cbDstStr, fWideChar)) { goto fail; }
    cbDstData = pObMapSrc->cMap * sizeof(VMMDLL_MAP_EATENTRY);
    cbDst = sizeof(VMMDLL_MAP_EAT) + cbDstData + cbDstStr;
    // 3: fill map [if required]:
    if(pMapDst) {
        if(*pcbMapDst < cbDst) { goto fail; }
        pMapDst->dwVersion = VMMDLL_MAP_EAT_VERSION;
        pMapDst->vaModuleBase = pObMapSrc->vaModuleBase;
        pMapDst->vaAddressOfFunctions = pObMapSrc->vaAddressOfFunctions;
        pMapDst->vaAddressOfNames = pObMapSrc->vaAddressOfNames;
        pMapDst->cNumberOfFunctions = pObMapSrc->cNumberOfFunctions;
        pMapDst->cNumberOfNames = pObMapSrc->cNumberOfNames;
        pMapDst->dwOrdinalBase = pObMapSrc->dwOrdinalBase;
        pMapDst->cMap = pObMapSrc->cMap;
        memcpy(pMapDst->pMap, pObMapSrc->pMap, cbDstData);
        // strmap below:
        for(i = 0; i < pMapDst->cMap; i++) {
            peSrc = pObMapSrc->pMap + i;
            peDst = pMapDst->pMap + i;
            f = ObStrMap_PushPtrUXUW(psmOb, peSrc->uszFunction, &peDst->uszFunction, NULL, fWideChar);
            if(!f) { goto fail; }
        }
        pMapDst->pbMultiText = ((PBYTE)pMapDst->pMap) + cbDstData;
        ObStrMap_FinalizeBufferXUW(psmOb, cbDstStr, pMapDst->pbMultiText, &pMapDst->cbMultiText, fWideChar);
    }
    fResult = TRUE;
fail:
    *pcbMapDst = cbDst;
    Ob_DECREF(pObModuleMap);
    Ob_DECREF(pObProcess);
    Ob_DECREF(pObMapSrc);
    Ob_DECREF(psmOb);
    return fResult;
}

_Success_(return)
BOOL VMMDLL_Map_GetIAT_Impl(_In_ DWORD dwPID, _In_ LPSTR uszModuleName, _Out_writes_bytes_opt_(*pcbMapDst) PVMMDLL_MAP_IAT pMapDst, _Inout_ PDWORD pcbMapDst, _In_ BOOL fWideChar)
{
    BOOL f, fResult = FALSE;
    PVMM_PROCESS pObProcess = NULL;
    PVMMOB_MAP_MODULE pObModuleMap = NULL;
    PVMM_MAP_MODULEENTRY pModuleEntry = NULL;
    DWORD i, cbDst = 0, cbDstData, cbDstStr;
    PVMMDLL_MAP_IATENTRY peDst;
    PVMM_MAP_IATENTRY peSrc;
    PVMMOB_MAP_IAT pObMapSrc = NULL;
    POB_STRMAP psmOb = NULL;
    // 0: sanity check:
    if(sizeof(VMM_MAP_IATENTRY) != sizeof(VMMDLL_MAP_IATENTRY)) { goto fail; }
    // 1: fetch map [and populate strings]:
    if(!(psmOb = ObStrMap_New(0))) { goto fail; }
    if(!(pObProcess = VmmProcessGet(dwPID))) { goto fail; }
    if(!VmmMap_GetModuleEntryEx(pObProcess, 0, uszModuleName, &pObModuleMap, &pModuleEntry)) { goto fail; }
    if(!VmmMap_GetIAT(pObProcess, pModuleEntry, &pObMapSrc)) { goto fail; }
    for(i = 0; i < pObMapSrc->cMap; i++) {
        peSrc = pObMapSrc->pMap + i;
        ObStrMap_PushU(psmOb, peSrc->uszModule);
        ObStrMap_PushU(psmOb, peSrc->uszFunction);
    }
    // 2: byte count:
    if(!ObStrMap_FinalizeBufferXUW(psmOb, 0, NULL, &cbDstStr, fWideChar)) { goto fail; }
    cbDstData = pObMapSrc->cMap * sizeof(VMMDLL_MAP_IATENTRY);
    cbDst = sizeof(VMMDLL_MAP_IAT) + cbDstData + cbDstStr;
    // 3: fill map [if required]:
    if(pMapDst) {
        if(*pcbMapDst < cbDst) { goto fail; }
        pMapDst->dwVersion = VMMDLL_MAP_IAT_VERSION;
        pMapDst->vaModuleBase = pObMapSrc->vaModuleBase;
        pMapDst->cMap = pObMapSrc->cMap;
        memcpy(pMapDst->pMap, pObMapSrc->pMap, cbDstData);
        // strmap below:
        for(i = 0; i < pMapDst->cMap; i++) {
            peSrc = pObMapSrc->pMap + i;
            peDst = pMapDst->pMap + i;
            f = ObStrMap_PushPtrUXUW(psmOb, peSrc->uszModule, &peDst->uszModule, NULL, fWideChar) &&
                ObStrMap_PushPtrUXUW(psmOb, peSrc->uszFunction, &peDst->uszFunction, NULL, fWideChar);
            if(!f) { goto fail; }
        }
        pMapDst->pbMultiText = ((PBYTE)pMapDst->pMap) + cbDstData;
        ObStrMap_FinalizeBufferXUW(psmOb, cbDstStr, pMapDst->pbMultiText, &pMapDst->cbMultiText, fWideChar);
    }
    fResult = TRUE;
fail:
    *pcbMapDst = cbDst;
    Ob_DECREF(pObModuleMap);
    Ob_DECREF(pObProcess);
    Ob_DECREF(pObMapSrc);
    Ob_DECREF(psmOb);
    return fResult;
}

_Success_(return) BOOL VMMDLL_Map_GetEATU(_In_ DWORD dwPID, _In_ LPSTR uszModuleName, _Out_writes_bytes_opt_(*pcbEatMap) PVMMDLL_MAP_EAT pEatMap, _Inout_ PDWORD pcbEatMap)
{
    CALL_IMPLEMENTATION_VMM(STATISTICS_ID_VMMDLL_Map_GetEAT, VMMDLL_Map_GetEAT_Impl(dwPID, uszModuleName, pEatMap, pcbEatMap, FALSE))
}

_Success_(return) BOOL VMMDLL_Map_GetEATW(_In_ DWORD dwPID, _In_ LPWSTR wszModuleName, _Out_writes_bytes_opt_(*pcbEatMap) PVMMDLL_MAP_EAT pEatMap, _Inout_ PDWORD pcbEatMap)
{
    LPSTR uszModuleName;
    BYTE pbBuffer[MAX_PATH];
    if(!CharUtil_WtoU(wszModuleName, -1, pbBuffer, sizeof(pbBuffer), &uszModuleName, NULL, 0)) { return FALSE; }
    CALL_IMPLEMENTATION_VMM(STATISTICS_ID_VMMDLL_Map_GetEAT, VMMDLL_Map_GetEAT_Impl(dwPID, uszModuleName, pEatMap, pcbEatMap, TRUE))
}

_Success_(return) BOOL VMMDLL_Map_GetIATU(_In_ DWORD dwPID, _In_ LPSTR uszModuleName, _Out_writes_bytes_opt_(*pcbIatMap) PVMMDLL_MAP_IAT pIatMap, _Inout_ PDWORD pcbIatMap)
{
    CALL_IMPLEMENTATION_VMM(STATISTICS_ID_VMMDLL_Map_GetIAT, VMMDLL_Map_GetIAT_Impl(dwPID, uszModuleName, pIatMap, pcbIatMap, FALSE))
}

_Success_(return) BOOL VMMDLL_Map_GetIATW(_In_ DWORD dwPID, _In_ LPWSTR wszModuleName, _Out_writes_bytes_opt_(*pcbIatMap) PVMMDLL_MAP_IAT pIatMap, _Inout_ PDWORD pcbIatMap)
{
    LPSTR uszModuleName;
    BYTE pbBuffer[MAX_PATH];
    if(!CharUtil_WtoU(wszModuleName, -1, pbBuffer, sizeof(pbBuffer), &uszModuleName, NULL, 0)) { return FALSE; }
    CALL_IMPLEMENTATION_VMM(STATISTICS_ID_VMMDLL_Map_GetIAT, VMMDLL_Map_GetIAT_Impl(dwPID, uszModuleName, pIatMap, pcbIatMap, TRUE))
}

_Success_(return)
BOOL VMMDLL_Map_GetHeap_Impl(_In_ DWORD dwPID, _Out_writes_bytes_opt_(*pcbMapDst) PVMMDLL_MAP_HEAP pMapDst, _Inout_ PDWORD pcbMapDst)
{
    BOOL fResult = FALSE;
    DWORD cbDst = 0, cbDstData;
    PVMMOB_MAP_HEAP pObMapSrc = NULL;
    PVMM_PROCESS pObProcess = NULL;
    if(!(pObProcess = VmmProcessGet(dwPID))) { goto fail; }
    if(!VmmMap_GetHeap(pObProcess, &pObMapSrc)) { goto fail; }
    cbDstData = pObMapSrc->cMap * sizeof(VMMDLL_MAP_HEAPENTRY);
    cbDst = sizeof(VMMDLL_MAP_HEAP) + cbDstData;
    if(pMapDst) {
        if(*pcbMapDst < cbDst) { goto fail; }
        ZeroMemory(pMapDst, sizeof(VMMDLL_MAP_HEAP));
        pMapDst->dwVersion = VMMDLL_MAP_HEAP_VERSION;
        pMapDst->cMap = pObMapSrc->cMap;
        memcpy(pMapDst->pMap, pObMapSrc->pMap, cbDstData);
    }
    fResult = TRUE;
fail:
    *pcbMapDst = cbDst;
    Ob_DECREF(pObProcess);
    Ob_DECREF(pObMapSrc);
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
BOOL VMMDLL_Map_GetThread_Impl(_In_ DWORD dwPID, _Out_writes_bytes_opt_(*pcbMapDst) PVMMDLL_MAP_THREAD pMapDst, _Inout_ PDWORD pcbMapDst)
{
    BOOL fResult = FALSE;
    DWORD cbDst = 0, cbDstData;
    PVMMOB_MAP_THREAD pObMapSrc = NULL;
    PVMM_PROCESS pObProcess = NULL;
    if(!(pObProcess = VmmProcessGet(dwPID))) { goto fail; }
    if(!VmmMap_GetThread(pObProcess, &pObMapSrc)) { goto fail; }
    cbDstData = pObMapSrc->cMap * sizeof(VMMDLL_MAP_THREADENTRY);
    cbDst = sizeof(VMMDLL_MAP_THREAD) + cbDstData;
    if(pMapDst) {
        if(*pcbMapDst < cbDst) { goto fail; }
        ZeroMemory(pMapDst, sizeof(VMMDLL_MAP_HEAP));
        pMapDst->dwVersion = VMMDLL_MAP_THREAD_VERSION;
        pMapDst->cMap = pObMapSrc->cMap;
        memcpy(pMapDst->pMap, pObMapSrc->pMap, cbDstData);
    }
    fResult = TRUE;
fail:
    *pcbMapDst = cbDst;
    Ob_DECREF(pObProcess);
    Ob_DECREF(pObMapSrc);
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
BOOL VMMDLL_Map_GetHandle_Impl(_In_ DWORD dwPID, _Out_writes_bytes_opt_(*pcbMapDst) PVMMDLL_MAP_HANDLE pMapDst, _Inout_ PDWORD pcbMapDst, _In_ BOOL fWideChar)
{
    BOOL f, fResult = FALSE;
    PVMMWIN_OBJECT_TYPE pOT;
    PVMM_PROCESS pObProcess = NULL;
    DWORD i, cbDst = 0, cbDstData, cbDstStr;
    PVMMDLL_MAP_HANDLEENTRY peDst;
    PVMM_MAP_HANDLEENTRY peSrc;
    PVMMOB_MAP_HANDLE pObMapSrc = NULL;
    POB_STRMAP psmOb = NULL;
    // 0: sanity check:
    if(sizeof(VMM_MAP_HANDLEENTRY) != sizeof(VMMDLL_MAP_HANDLEENTRY)) { goto fail; }
    // 1: fetch map [and populate strings]:
    if(!(psmOb = ObStrMap_New(0))) { goto fail; }
    if(!(pObProcess = VmmProcessGet(dwPID))) { goto fail; }
    if(!VmmMap_GetHandle(pObProcess, &pObMapSrc, TRUE)) { goto fail; }
    for(i = 0; i < pObMapSrc->cMap; i++) {
        peSrc = pObMapSrc->pMap + i;
        pOT = VmmWin_ObjectTypeGet((BYTE)peSrc->iType);
        ObStrMap_PushU(psmOb, (pOT ? pOT->usz : NULL));
        ObStrMap_PushU(psmOb, peSrc->uszText);
    }
    // 2: byte count:
    if(!ObStrMap_FinalizeBufferXUW(psmOb, 0, NULL, &cbDstStr, fWideChar)) { goto fail; }
    cbDstData = pObMapSrc->cMap * sizeof(VMMDLL_MAP_HANDLEENTRY);
    cbDst = sizeof(VMMDLL_MAP_HANDLE) + cbDstData + cbDstStr;
    // 3: fill map [if required]:
    if(pMapDst) {
        if(*pcbMapDst < cbDst) { goto fail; }
        ZeroMemory(pMapDst, sizeof(VMMDLL_MAP_HANDLE));
        pMapDst->dwVersion = VMMDLL_MAP_HANDLE_VERSION;
        pMapDst->cMap = pObMapSrc->cMap;
        memcpy(pMapDst->pMap, pObMapSrc->pMap, cbDstData);
        // strmap below:
        for(i = 0; i < pMapDst->cMap; i++) {
            peSrc = pObMapSrc->pMap + i;
            peDst = pMapDst->pMap + i;
            pOT = VmmWin_ObjectTypeGet((BYTE)peDst->iType);
            f = ObStrMap_PushPtrUXUW(psmOb, (pOT ? pOT->usz : NULL), &peDst->uszType, NULL, fWideChar) &&
                ObStrMap_PushPtrUXUW(psmOb, peSrc->uszText, &peDst->uszText, NULL, fWideChar);
            if(!f) { goto fail; }
        }
        pMapDst->pbMultiText = ((PBYTE)pMapDst->pMap) + cbDstData;
        ObStrMap_FinalizeBufferXUW(psmOb, cbDstStr, pMapDst->pbMultiText, &pMapDst->cbMultiText, fWideChar);
    }
    fResult = TRUE;
fail:
    *pcbMapDst = cbDst;
    Ob_DECREF(pObProcess);
    Ob_DECREF(pObMapSrc);
    Ob_DECREF(psmOb);
    return fResult;
}

_Success_(return) BOOL VMMDLL_Map_GetHandleU(_In_ DWORD dwPID, _Out_writes_bytes_opt_(*pcbHandleMap) PVMMDLL_MAP_HANDLE pHandleMap, _Inout_ PDWORD pcbHandleMap)
{
    CALL_IMPLEMENTATION_VMM(STATISTICS_ID_VMMDLL_Map_GetHandle, VMMDLL_Map_GetHandle_Impl(dwPID, pHandleMap, pcbHandleMap, FALSE))
}

_Success_(return) BOOL VMMDLL_Map_GetHandleW(_In_ DWORD dwPID, _Out_writes_bytes_opt_(*pcbHandleMap) PVMMDLL_MAP_HANDLE pHandleMap, _Inout_ PDWORD pcbHandleMap)
{
    CALL_IMPLEMENTATION_VMM(STATISTICS_ID_VMMDLL_Map_GetHandle, VMMDLL_Map_GetHandle_Impl(dwPID, pHandleMap, pcbHandleMap, TRUE))
}

_Success_(return)
BOOL VMMDLL_Map_GetPhysMem_Impl(_Out_writes_bytes_opt_(*pcbMapDst) PVMMDLL_MAP_PHYSMEM pMapDst, _Inout_ PDWORD pcbMapDst)
{
    BOOL fResult = FALSE;
    DWORD cbDst = 0, cbDstData;
    PVMMOB_MAP_PHYSMEM pObMap = NULL;
    if(!VmmMap_GetPhysMem(&pObMap)) { goto fail; }
    cbDstData = pObMap->cMap * sizeof(VMMDLL_MAP_PHYSMEMENTRY);
    cbDst = sizeof(VMMDLL_MAP_PHYSMEM) + cbDstData;
    if(pMapDst) {
        if(*pcbMapDst < cbDst) { goto fail; }
        ZeroMemory(pMapDst, cbDst);
        pMapDst->dwVersion = VMMDLL_MAP_PHYSMEM_VERSION;
        pMapDst->cMap = pObMap->cMap;
        memcpy(pMapDst->pMap, pObMap->pMap, cbDstData);
    }
    fResult = TRUE;
fail:
    *pcbMapDst = cbDst;
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
BOOL VMMDLL_Map_GetNet_Impl(_Out_writes_bytes_opt_(*pcbMapDst) PVMMDLL_MAP_NET pMapDst, _Inout_ PDWORD pcbMapDst, _In_ BOOL fWideChar)
{
    BOOL f, fResult = FALSE;
    DWORD i, cbDst = 0, cbDstData, cbDstStr;
    PVMMDLL_MAP_NETENTRY peDst;
    PVMM_MAP_NETENTRY peSrc;
    PVMMOB_MAP_NET pObMapSrc = NULL;
    POB_STRMAP psm = NULL;
    // 0: sanity check:
    if(sizeof(VMM_MAP_NETENTRY) != sizeof(VMMDLL_MAP_NETENTRY)) { goto fail; }
    // 1: fetch map [and populate strings]:
    if(!(psm = ObStrMap_New(0))) { goto fail; }
    if(!VmmMap_GetNet(&pObMapSrc)) { goto fail; }
    for(i = 0; i < pObMapSrc->cMap; i++) {
        peSrc = pObMapSrc->pMap + i;
        ObStrMap_PushU(psm, peSrc->Src.uszText);
        ObStrMap_PushU(psm, peSrc->Dst.uszText);
        ObStrMap_PushU(psm, peSrc->uszText);
    }
    // 2: byte count:
    if(!ObStrMap_FinalizeBufferXUW(psm, 0, NULL, &cbDstStr, fWideChar)) { goto fail; }
    cbDstData = pObMapSrc->cMap * sizeof(VMMDLL_MAP_NETENTRY);
    cbDst = sizeof(VMMDLL_MAP_NET) + cbDstData + cbDstStr;
    // 3: fill map [if required]:
    if(pMapDst) {
        if(*pcbMapDst < cbDst) { goto fail; }
        ZeroMemory(pMapDst, cbDst);
        pMapDst->dwVersion = VMMDLL_MAP_NET_VERSION;
        pMapDst->cMap = pObMapSrc->cMap;
        memcpy(pMapDst->pMap, pObMapSrc->pMap, cbDstData);
        // strmap below:
        for(i = 0; i < pMapDst->cMap; i++) {
            peSrc = pObMapSrc->pMap + i;
            peDst = pMapDst->pMap + i;
            f = ObStrMap_PushPtrUXUW(psm, peSrc->Src.uszText, &peDst->Src.uszText, NULL, fWideChar) &&
                ObStrMap_PushPtrUXUW(psm, peSrc->Dst.uszText, &peDst->Dst.uszText, NULL, fWideChar) &&
                ObStrMap_PushPtrUXUW(psm, peSrc->uszText, &peDst->uszText, NULL, fWideChar);
            if(!f) { goto fail; }
        }
        pMapDst->pbMultiText = ((PBYTE)pMapDst->pMap) + cbDstData;
        ObStrMap_FinalizeBufferXUW(psm, cbDstStr, pMapDst->pbMultiText, &pMapDst->cbMultiText, fWideChar);
    }
    fResult = TRUE;
fail:
    *pcbMapDst = cbDst;
    Ob_DECREF(pObMapSrc);
    Ob_DECREF(psm);
    return fResult;
}

_Success_(return) BOOL VMMDLL_Map_GetNetU(_Out_writes_bytes_opt_(*pcbNetMap) PVMMDLL_MAP_NET pNetMap, _Inout_ PDWORD pcbNetMap)
{
    CALL_IMPLEMENTATION_VMM(STATISTICS_ID_VMMDLL_Map_GetNet, VMMDLL_Map_GetNet_Impl(pNetMap, pcbNetMap, FALSE))
}

_Success_(return) BOOL VMMDLL_Map_GetNetW(_Out_writes_bytes_opt_(*pcbNetMap) PVMMDLL_MAP_NET pNetMap, _Inout_ PDWORD pcbNetMap)
{
    CALL_IMPLEMENTATION_VMM(STATISTICS_ID_VMMDLL_Map_GetNet, VMMDLL_Map_GetNet_Impl(pNetMap, pcbNetMap, TRUE))
}

_Success_(return)
BOOL VMMDLL_Map_GetUsers_Impl(_Out_writes_bytes_opt_(*pcbMapDst) PVMMDLL_MAP_USER pMapDst, _Inout_ PDWORD pcbMapDst, _In_ BOOL fWideChar)
{
    BOOL f, fResult = FALSE;
    DWORD i, cbDst = 0, cbDstData, cbDstStr;
    PVMMDLL_MAP_USERENTRY peDst;
    PVMM_MAP_USERENTRY peSrc;
    PVMMOB_MAP_USER pObMapSrc = NULL;
    POB_STRMAP psmOb = NULL;
    // 1: fetch map [and populate strings]:
    if(!(psmOb = ObStrMap_New(0))) { goto fail; }
    if(!VmmMap_GetUser(&pObMapSrc)) { goto fail; }
    for(i = 0; i < pObMapSrc->cMap; i++) {
        peSrc = pObMapSrc->pMap + i;
        ObStrMap_PushU(psmOb, peSrc->szSID);
        ObStrMap_PushU(psmOb, peSrc->uszText);
    }
    // 2: byte count:
    if(!ObStrMap_FinalizeBufferXUW(psmOb, 0, NULL, &cbDstStr, fWideChar)) { goto fail; }
    cbDstData = pObMapSrc->cMap * sizeof(VMMDLL_MAP_USERENTRY);
    cbDst = sizeof(VMMDLL_MAP_USER) + cbDstData + cbDstStr;
    // 3: fill map [if required]:
    if(pMapDst) {
        if(*pcbMapDst < cbDst) { goto fail; }
        ZeroMemory(pMapDst, cbDst);
        pMapDst->dwVersion = VMMDLL_MAP_USER_VERSION;
        pMapDst->cMap = pObMapSrc->cMap;
        for(i = 0; i < pMapDst->cMap; i++) {
            peDst = pMapDst->pMap + i;
            peDst->vaRegHive = pObMapSrc->pMap[i].vaRegHive;
            // strmap below:
            for(i = 0; i < pMapDst->cMap; i++) {
                peSrc = pObMapSrc->pMap + i;
                peDst = pMapDst->pMap + i;
                f = ObStrMap_PushPtrUXUW(psmOb, peSrc->uszText, &peDst->uszText, NULL, fWideChar) &&
                    ObStrMap_PushPtrUXUW(psmOb, peSrc->szSID, &peDst->uszSID, NULL, fWideChar);
                if(!f) { goto fail; }
            }
        }
        pMapDst->pbMultiText = ((PBYTE)pMapDst->pMap) + cbDstData;
        ObStrMap_FinalizeBufferXUW(psmOb, cbDstStr, pMapDst->pbMultiText, &pMapDst->cbMultiText, fWideChar);
    }
    fResult = TRUE;
fail:
    *pcbMapDst = cbDst;
    Ob_DECREF(pObMapSrc);
    Ob_DECREF(psmOb);
    return fResult;
}

_Success_(return) BOOL VMMDLL_Map_GetUsersU(_Out_writes_bytes_opt_(*pcbUserMap) PVMMDLL_MAP_USER pUserMap, _Inout_ PDWORD pcbUserMap)
{
    CALL_IMPLEMENTATION_VMM(STATISTICS_ID_VMMDLL_Map_GetUsers, VMMDLL_Map_GetUsers_Impl(pUserMap, pcbUserMap, FALSE))
}

_Success_(return) BOOL VMMDLL_Map_GetUsersW(_Out_writes_bytes_opt_(*pcbUserMap) PVMMDLL_MAP_USER pUserMap, _Inout_ PDWORD pcbUserMap)
{
    CALL_IMPLEMENTATION_VMM(STATISTICS_ID_VMMDLL_Map_GetUsers, VMMDLL_Map_GetUsers_Impl(pUserMap, pcbUserMap, TRUE))
}

_Success_(return)
BOOL VMMDLL_Map_GetServices_Impl(_Out_writes_bytes_opt_(*pcbMapDst) PVMMDLL_MAP_SERVICE pMapDst, _Inout_ PDWORD pcbMapDst, _In_ BOOL fWideChar)
{
    BOOL f, fResult = FALSE;
    DWORD i, cbDst = 0, cbDstData, cbDstStr;
    PVMMDLL_MAP_SERVICEENTRY peDst;
    PVMM_MAP_SERVICEENTRY peSrc;
    PVMMOB_MAP_SERVICE pObMapSrc = NULL;
    POB_STRMAP psmOb = NULL;
    // 0: sanity check:
    if(sizeof(VMM_MAP_SERVICEENTRY) != sizeof(VMMDLL_MAP_SERVICEENTRY)) { goto fail; }
    // 1: fetch map [and populate strings]:
    if(!(psmOb = ObStrMap_New(0))) { goto fail; }
    if(!VmmMap_GetService(&pObMapSrc)) { goto fail; }
    for(i = 0; i < pObMapSrc->cMap; i++) {
        peSrc = pObMapSrc->pMap + i;
        ObStrMap_PushU(psmOb, peSrc->uszServiceName);
        ObStrMap_PushU(psmOb, peSrc->uszDisplayName);
        ObStrMap_PushU(psmOb, peSrc->uszPath);
        ObStrMap_PushU(psmOb, peSrc->uszUserTp);
        ObStrMap_PushU(psmOb, peSrc->uszUserAcct);
        ObStrMap_PushU(psmOb, peSrc->uszImagePath);
    }
    // 2: byte count:
    if(!ObStrMap_FinalizeBufferXUW(psmOb, 0, NULL, &cbDstStr, fWideChar)) { goto fail; }
    cbDstData = pObMapSrc->cMap * sizeof(VMMDLL_MAP_SERVICEENTRY);
    cbDst = sizeof(VMMDLL_MAP_SERVICE) + cbDstData + cbDstStr;
    // 3: fill map [if required]:
    if(pMapDst) {
        if(*pcbMapDst < cbDst) { goto fail; }
        ZeroMemory(pMapDst, sizeof(VMMDLL_MAP_SERVICE));
        pMapDst->dwVersion = VMMDLL_MAP_SERVICE_VERSION;
        pMapDst->cMap = pObMapSrc->cMap;
        memcpy(pMapDst->pMap, pObMapSrc->pMap, cbDstData);
        // strmap below:
        for(i = 0; i < pMapDst->cMap; i++) {
            peSrc = pObMapSrc->pMap + i;
            peDst = pMapDst->pMap + i;
            f = ObStrMap_PushPtrUXUW(psmOb, peSrc->uszServiceName, &peDst->uszServiceName, NULL, fWideChar) &&
                ObStrMap_PushPtrUXUW(psmOb, peSrc->uszDisplayName, &peDst->uszDisplayName, NULL, fWideChar) &&
                ObStrMap_PushPtrUXUW(psmOb, peSrc->uszPath, &peDst->uszPath, NULL, fWideChar) &&
                ObStrMap_PushPtrUXUW(psmOb, peSrc->uszUserTp, &peDst->uszUserTp, NULL, fWideChar) &&
                ObStrMap_PushPtrUXUW(psmOb, peSrc->uszUserAcct, &peDst->uszUserAcct, NULL, fWideChar) &&
                ObStrMap_PushPtrUXUW(psmOb, peSrc->uszImagePath, &peDst->uszImagePath, NULL, fWideChar);
            if(!f) { goto fail; }
        }
        pMapDst->pbMultiText = ((PBYTE)pMapDst->pMap) + cbDstData;
        ObStrMap_FinalizeBufferXUW(psmOb, cbDstStr, pMapDst->pbMultiText, &pMapDst->cbMultiText, fWideChar);
    }
    fResult = TRUE;
fail:
    *pcbMapDst = (DWORD)cbDst;
    Ob_DECREF(pObMapSrc);
    Ob_DECREF(psmOb);
    return fResult;
}

_Success_(return) BOOL VMMDLL_Map_GetServicesU(_Out_writes_bytes_opt_(*pcbServiceMap) PVMMDLL_MAP_SERVICE pServiceMap, _Inout_ PDWORD pcbServiceMap)
{
    CALL_IMPLEMENTATION_VMM(STATISTICS_ID_VMMDLL_Map_GetServices, VMMDLL_Map_GetServices_Impl(pServiceMap, pcbServiceMap, FALSE))
}

_Success_(return) BOOL VMMDLL_Map_GetServicesW(_Out_writes_bytes_opt_(*pcbServiceMap) PVMMDLL_MAP_SERVICE pServiceMap, _Inout_ PDWORD pcbServiceMap)
{
    CALL_IMPLEMENTATION_VMM(STATISTICS_ID_VMMDLL_Map_GetServices, VMMDLL_Map_GetServices_Impl(pServiceMap, pcbServiceMap, TRUE))
}

_Success_(return)
BOOL VMMDLL_Map_GetPfn_Impl(_In_ DWORD pPfns[], _In_ DWORD cPfns, _Out_writes_bytes_opt_(*pcbMapDst) PVMMDLL_MAP_PFN pMapDst, _Inout_ PDWORD pcbMapDst)
{
    BOOL fResult = FALSE;
    POB_SET psObPfns = NULL;
    PMMPFNOB_MAP pObMapSrc = NULL;
    DWORD i, cbDst = 0, cbDstData;
    cbDstData = cPfns * sizeof(VMMDLL_MAP_PFNENTRY);
    cbDst = sizeof(VMMDLL_MAP_PFN) + cbDstData;
    if(pMapDst) {
        if(*pcbMapDst < cbDst) { goto fail; }
        if(!(psObPfns = ObSet_New())) { goto fail; }
        for(i = 0; i < cPfns; i++) {
            ObSet_Push(psObPfns, pPfns[i]);
        }
        if(!MmPfn_Map_GetPfnScatter(psObPfns, &pObMapSrc, TRUE)) { goto fail; }
        ZeroMemory(pMapDst, cbDst);
        pMapDst->dwVersion = VMMDLL_MAP_PFN_VERSION;
        pMapDst->cMap = pObMapSrc->cMap;
        cbDstData = pObMapSrc->cMap * sizeof(VMMDLL_MAP_PFNENTRY);
        cbDst = sizeof(VMMDLL_MAP_PFN) + cbDstData;
        memcpy(pMapDst->pMap, pObMapSrc->pMap, cbDstData);
    }
    fResult = TRUE;
fail:
    *pcbMapDst = cbDst;
    Ob_DECREF(psObPfns);
    Ob_DECREF(pObMapSrc);
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
    VmmProcessListPIDs(pPIDs, (PSIZE_T)pcPIDs, 0);
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
    _In_ LPSTR uszModule,
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
    if(!VmmMap_GetModuleEntryEx(pObProcess, 0, uszModule, &pObModuleMap, &pModule)) { goto fail; }
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
BOOL VMMDLL_ProcessGetDirectoriesU(_In_ DWORD dwPID, _In_ LPSTR uszModule, _Out_writes_(16) PIMAGE_DATA_DIRECTORY pData, _In_ DWORD cData, _Out_ PDWORD pcData)
{
    CALL_IMPLEMENTATION_VMM(
        STATISTICS_ID_VMMDLL_ProcessGetDirectories,
        VMMDLL_ProcessGet_Directories_Sections_Impl(dwPID, uszModule, cData, pcData, pData, NULL, TRUE, FALSE))
}

_Success_(return)
BOOL VMMDLL_ProcessGetDirectoriesW(_In_ DWORD dwPID, _In_ LPWSTR wszModule, _Out_writes_(16) PIMAGE_DATA_DIRECTORY pData, _In_ DWORD cData, _Out_ PDWORD pcData)
{
    LPSTR uszModule;
    BYTE pbBuffer[MAX_PATH];
    if(!CharUtil_WtoU(wszModule, -1, pbBuffer, sizeof(pbBuffer), &uszModule, NULL, 0)) { return FALSE; }
    return VMMDLL_ProcessGetDirectoriesU(dwPID, uszModule, pData, cData, pcData);
}

_Success_(return)
BOOL VMMDLL_ProcessGetSectionsU(_In_ DWORD dwPID, _In_ LPSTR uszModule, _Out_opt_ PIMAGE_SECTION_HEADER pData, _In_ DWORD cData, _Out_ PDWORD pcData)
{
    CALL_IMPLEMENTATION_VMM(
        STATISTICS_ID_VMMDLL_ProcessGetSections,
        VMMDLL_ProcessGet_Directories_Sections_Impl(dwPID, uszModule, cData, pcData, NULL, pData, FALSE, TRUE))
}

_Success_(return)
BOOL VMMDLL_ProcessGetSectionsW(_In_ DWORD dwPID, _In_ LPWSTR wszModule, _Out_opt_ PIMAGE_SECTION_HEADER pData, _In_ DWORD cData, _Out_ PDWORD pcData)
{
    LPSTR uszModule;
    BYTE pbBuffer[MAX_PATH];
    if(!CharUtil_WtoU(wszModule, -1, pbBuffer, sizeof(pbBuffer), &uszModule, NULL, 0)) { return FALSE; }
    return VMMDLL_ProcessGetSectionsU(dwPID, uszModule, pData, cData, pcData);
}

ULONG64 VMMDLL_ProcessGetModuleBase_Impl(_In_ DWORD dwPID, _In_ LPSTR uszModuleName)
{
    QWORD vaModuleBase = 0;
    PVMM_MAP_MODULEENTRY peModule;
    PVMMOB_MAP_MODULE pObModuleMap = NULL;
    if(VmmMap_GetModuleEntryEx(NULL, dwPID, uszModuleName, &pObModuleMap, &peModule)) {
        vaModuleBase = peModule->vaBase;
        Ob_DECREF(pObModuleMap);
    }
    return vaModuleBase;
}

ULONG64 VMMDLL_ProcessGetModuleBaseU(_In_ DWORD dwPID, _In_ LPSTR uszModuleName)
{
    CALL_IMPLEMENTATION_VMM_RETURN(
        STATISTICS_ID_VMMDLL_ProcessGetModuleBase,
        ULONG64,
        0,
        VMMDLL_ProcessGetModuleBase_Impl(dwPID, uszModuleName))
}

ULONG64 VMMDLL_ProcessGetModuleBaseW(_In_ DWORD dwPID, _In_ LPWSTR wszModuleName)
{
    LPSTR uszModuleName;
    BYTE pbBuffer[MAX_PATH];
    if(!CharUtil_WtoU(wszModuleName, -1, pbBuffer, sizeof(pbBuffer), &uszModuleName, NULL, 0)) { return FALSE; }
    return VMMDLL_ProcessGetModuleBaseU(dwPID, uszModuleName);
}

ULONG64 VMMDLL_ProcessGetProcAddress_Impl(_In_ DWORD dwPID, _In_ LPSTR uszModuleName, _In_ LPSTR szFunctionName)
{
    PVMM_PROCESS pObProcess = NULL;
    PVMMOB_MAP_EAT pObEatMap = NULL;
    PVMMOB_MAP_MODULE pObModuleMap = NULL;
    PVMM_MAP_MODULEENTRY peModule;
    QWORD va = 0;
    DWORD i;
    if(!(pObProcess = VmmProcessGet(dwPID))) { goto fail; }
    if(!VmmMap_GetModuleEntryEx(NULL, dwPID, uszModuleName, &pObModuleMap, &peModule)) { goto fail; }
    if(!VmmMap_GetEAT(pObProcess, peModule, &pObEatMap)) { goto fail; }
    if(!VmmMap_GetEATEntryIndexU(pObEatMap, szFunctionName, &i)) { goto fail; }
    va = pObEatMap->pMap[i].vaFunction;
fail:
    Ob_DECREF(pObEatMap);
    Ob_DECREF(pObModuleMap);
    Ob_DECREF(pObProcess);
    return va;
}

ULONG64 VMMDLL_ProcessGetProcAddressU(_In_ DWORD dwPID, _In_ LPSTR uszModuleName, _In_ LPSTR szFunctionName)
{
    CALL_IMPLEMENTATION_VMM_RETURN(
        STATISTICS_ID_VMMDLL_ProcessGetProcAddress,
        ULONG64,
        0,
        VMMDLL_ProcessGetProcAddress_Impl(dwPID, uszModuleName, szFunctionName))
}

ULONG64 VMMDLL_ProcessGetProcAddressW(_In_ DWORD dwPID, _In_ LPWSTR wszModuleName, _In_ LPSTR szFunctionName)
{
    LPSTR uszModuleName;
    BYTE pbBuffer[MAX_PATH];
    if(!CharUtil_WtoU(wszModuleName, -1, pbBuffer, sizeof(pbBuffer), &uszModuleName, NULL, 0)) { return FALSE; }
    return VMMDLL_ProcessGetProcAddressU(dwPID, uszModuleName, szFunctionName);
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
BOOL VMMDLL_WinReg_EnumKeyEx_Impl(_In_opt_ LPSTR uszFullPathKey, _In_opt_ LPWSTR wszFullPathKey, _In_ DWORD dwIndex, _Out_writes_opt_(cbName) PBYTE pbName, _In_ DWORD cbName, _Out_ PDWORD pcchName, _Out_opt_ PFILETIME lpftLastWriteTime)
{
    BOOL f;
    VMM_REGISTRY_KEY_INFO KeyInfo = { 0 };
    CHAR uszPathKey[MAX_PATH];
    POB_REGISTRY_HIVE pObHive = NULL;
    POB_REGISTRY_KEY pObKey = NULL, pObSubKey = NULL;
    POB_MAP pmObSubKeys = NULL;
    BYTE pbBuffer[2 * MAX_PATH];
    *pcchName = 0;
    if(wszFullPathKey) {
        if(!CharUtil_WtoU(wszFullPathKey, -1, pbBuffer, sizeof(pbBuffer), &uszFullPathKey, NULL, 0)) { return FALSE; }
    }
    if(!uszFullPathKey) { return FALSE; }
    if(pbName && !cbName) {
        if(lpftLastWriteTime) { *(PQWORD)lpftLastWriteTime = 0; }
        return FALSE;
    }
    f = VmmWinReg_PathHiveGetByFullPath(uszFullPathKey, &pObHive, uszPathKey) &&
        (pObKey = VmmWinReg_KeyGetByPath(pObHive, uszPathKey));
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
    if(wszFullPathKey) {
        f = f && CharUtil_UtoW(KeyInfo.uszName, -1, pbName, cbName, NULL, pcchName, (pbName ? CHARUTIL_FLAG_STR_BUFONLY : 0));
        *pcchName = *pcchName >> 1;
    } else {
        f = f && CharUtil_UtoU(KeyInfo.uszName, -1, pbName, cbName, NULL, pcchName, (pbName ? CHARUTIL_FLAG_STR_BUFONLY : 0));
    }
    if(lpftLastWriteTime) { *(PQWORD)lpftLastWriteTime = KeyInfo.ftLastWrite; }
    Ob_DECREF(pObSubKey);
    Ob_DECREF(pmObSubKeys);
    Ob_DECREF(pObKey);
    Ob_DECREF(pObHive);
    return f;
}

_Success_(return)
BOOL VMMDLL_WinReg_EnumValue_Impl(_In_opt_ LPSTR uszFullPathKey, _In_opt_ LPWSTR wszFullPathKey, _In_ DWORD dwIndex, _Out_writes_opt_(cbName) PBYTE pbName, _In_ DWORD cbName, _Out_ PDWORD pcchName, _Out_opt_ PDWORD lpType, _Out_writes_opt_(*lpcbData) PBYTE lpData, _Inout_opt_ PDWORD lpcbData)
{
    BOOL f;
    VMM_REGISTRY_VALUE_INFO ValueInfo = { 0 };
    CHAR uszPathKey[MAX_PATH];
    POB_REGISTRY_HIVE pObHive = NULL;
    POB_REGISTRY_KEY pObKey = NULL;
    POB_MAP pmObValues = NULL;
    POB_REGISTRY_VALUE pObValue = NULL;
    BYTE pbBuffer[2 * MAX_PATH];
    *pcchName = 0;
    if(wszFullPathKey) {
        if(!CharUtil_WtoU(wszFullPathKey, -1, pbBuffer, sizeof(pbBuffer), &uszFullPathKey, NULL, 0)) { return FALSE; }
    }
    if(!uszFullPathKey) { return FALSE; }
    if((pbName && !cbName) || (lpData && (!lpcbData || !*lpcbData))) {
        if(lpType) { *lpType = 0; }
        if(lpcbData) { *lpcbData = 0; }
        return FALSE;
    }
    f = VmmWinReg_PathHiveGetByFullPath(uszFullPathKey, &pObHive, uszPathKey) &&
        (pObKey = VmmWinReg_KeyGetByPath(pObHive, uszPathKey)) &&
        (pmObValues = VmmWinReg_KeyValueList(pObHive, pObKey)) &&
        (pObValue = ObMap_GetByIndex(pmObValues, dwIndex));
    if(f) {
        VmmWinReg_ValueInfo(pObHive, pObValue, &ValueInfo);
        if(wszFullPathKey) {
            f = CharUtil_UtoW(ValueInfo.uszName, -1, pbName, cbName, NULL, pcchName, (pbName ? CHARUTIL_FLAG_STR_BUFONLY : 0));
            *pcchName = *pcchName >> 1;
        } else {
            CharUtil_UtoU(ValueInfo.uszName, -1, pbName, cbName, NULL, pcchName, (pbName ? CHARUTIL_FLAG_STR_BUFONLY : 0));
        }
    }
    if(lpType) { *lpType = ValueInfo.dwType; }
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

_Success_(return) BOOL VMMDLL_WinReg_EnumKeyExU(_In_ LPSTR uszFullPathKey, _In_ DWORD dwIndex, _Out_writes_opt_(*lpcchName) LPSTR lpName, _Inout_ LPDWORD lpcchName, _Out_opt_ PFILETIME lpftLastWriteTime)
{
    CALL_IMPLEMENTATION_VMM(STATISTICS_ID_VMMDLL_WinReg_EnumValueW, VMMDLL_WinReg_EnumKeyEx_Impl(uszFullPathKey, NULL, dwIndex, (PBYTE)lpName, *lpcchName, lpcchName, lpftLastWriteTime))
}

_Success_(return) BOOL VMMDLL_WinReg_EnumKeyExW(_In_ LPWSTR wszFullPathKey, _In_ DWORD dwIndex, _Out_writes_opt_(*lpcchName) LPWSTR lpName, _Inout_ LPDWORD lpcchName, _Out_opt_ PFILETIME lpftLastWriteTime)
{
    CALL_IMPLEMENTATION_VMM(STATISTICS_ID_VMMDLL_WinReg_EnumValueW, VMMDLL_WinReg_EnumKeyEx_Impl(NULL, wszFullPathKey, dwIndex, (PBYTE)lpName, *lpcchName << 1, lpcchName, lpftLastWriteTime))
}

_Success_(return) BOOL VMMDLL_WinReg_EnumValueU(_In_ LPSTR uszFullPathKey, _In_ DWORD dwIndex, _Out_writes_opt_(*lpcchValueName) LPSTR lpValueName, _Inout_ LPDWORD lpcchValueName, _Out_opt_ LPDWORD lpType, _Out_writes_opt_(*lpcbData) LPBYTE lpData, _Inout_opt_ LPDWORD lpcbData)
{
    CALL_IMPLEMENTATION_VMM(STATISTICS_ID_VMMDLL_WinReg_EnumValueW, VMMDLL_WinReg_EnumValue_Impl(uszFullPathKey, NULL, dwIndex, (PBYTE)lpValueName, *lpcchValueName, lpcchValueName, lpType, lpData, lpcbData))
}

_Success_(return) BOOL VMMDLL_WinReg_EnumValueW(_In_ LPWSTR wszFullPathKey, _In_ DWORD dwIndex, _Out_writes_opt_(*lpcchValueName) LPWSTR lpValueName, _Inout_ LPDWORD lpcchValueName, _Out_opt_ LPDWORD lpType, _Out_writes_opt_(*lpcbData) LPBYTE lpData, _Inout_opt_ LPDWORD lpcbData)
{
    CALL_IMPLEMENTATION_VMM(STATISTICS_ID_VMMDLL_WinReg_EnumValueW, VMMDLL_WinReg_EnumValue_Impl(NULL, wszFullPathKey, dwIndex, (PBYTE)lpValueName, *lpcchValueName << 1, lpcchValueName, lpType, lpData, lpcbData))
}

_Success_(return) BOOL VMMDLL_WinReg_QueryValueExU(_In_ LPSTR uszFullPathKeyValue, _Out_opt_ LPDWORD lpType, _Out_writes_opt_(*lpcbData) LPBYTE lpData, _When_(lpData == NULL, _Out_opt_) _When_(lpData != NULL, _Inout_opt_) LPDWORD lpcbData)
{
    CALL_IMPLEMENTATION_VMM(STATISTICS_ID_VMMDLL_WinReg_QueryValueEx, VmmWinReg_ValueQuery2(uszFullPathKeyValue, lpType, lpData, lpcbData ? *lpcbData : 0, lpcbData))
}

_Success_(return) BOOL VMMDLL_WinReg_QueryValueExW(_In_ LPWSTR wszFullPathKeyValue, _Out_opt_ LPDWORD lpType, _Out_writes_opt_(*lpcbData) LPBYTE lpData, _When_(lpData == NULL, _Out_opt_) _When_(lpData != NULL, _Inout_opt_) LPDWORD lpcbData)
{
    LPSTR uszFullPathKeyValue;
    BYTE pbBuffer[2 * MAX_PATH];
    if(!CharUtil_WtoU(wszFullPathKeyValue, -1, pbBuffer, sizeof(pbBuffer), &uszFullPathKeyValue, NULL, 0)) { return FALSE; }
    CALL_IMPLEMENTATION_VMM(STATISTICS_ID_VMMDLL_WinReg_QueryValueEx, VmmWinReg_ValueQuery2(uszFullPathKeyValue, lpType, lpData, lpcbData ? *lpcbData : 0, lpcbData))
}



//-----------------------------------------------------------------------------
// WINDOWS SPECIFIC UTILITY FUNCTIONS BELOW:
//-----------------------------------------------------------------------------

_Success_(return)
BOOL VMMDLL_WinGetThunkInfoIAT_Impl(_In_ DWORD dwPID, _In_ LPSTR uszModuleName, _In_ LPSTR szImportModuleName, _In_ LPSTR szImportFunctionName, _Out_ PVMMDLL_WIN_THUNKINFO_IAT pThunkInfoIAT)
{
    BOOL f = FALSE;
    QWORD vaModuleBase;
    PVMM_PROCESS pObProcess = NULL;
    f = (sizeof(VMMDLL_WIN_THUNKINFO_IAT) == sizeof(PE_THUNKINFO_IAT)) &&
        (pObProcess = VmmProcessGet(dwPID)) &&
        (vaModuleBase = VMMDLL_ProcessGetModuleBase_Impl(dwPID, uszModuleName)) &&
        PE_GetThunkInfoIAT(pObProcess, vaModuleBase, szImportModuleName, szImportFunctionName, (PPE_THUNKINFO_IAT)pThunkInfoIAT);
    Ob_DECREF(pObProcess);
    return f;
}

_Success_(return)
BOOL VMMDLL_WinGetThunkInfoIATU(_In_ DWORD dwPID, _In_ LPSTR uszModuleName, _In_ LPSTR szImportModuleName, _In_ LPSTR szImportFunctionName, _Out_ PVMMDLL_WIN_THUNKINFO_IAT pThunkInfoIAT)
{
    CALL_IMPLEMENTATION_VMM(
        STATISTICS_ID_VMMDLL_WinGetThunkIAT,
        VMMDLL_WinGetThunkInfoIAT_Impl(dwPID, uszModuleName, szImportModuleName, szImportFunctionName, pThunkInfoIAT))
}

_Success_(return)
BOOL VMMDLL_WinGetThunkInfoIATW(_In_ DWORD dwPID, _In_ LPWSTR wszModuleName, _In_ LPSTR szImportModuleName, _In_ LPSTR szImportFunctionName, _Out_ PVMMDLL_WIN_THUNKINFO_IAT pThunkInfoIAT)
{
    LPSTR uszModuleName;
    BYTE pbBuffer[MAX_PATH];
    if(!CharUtil_WtoU(wszModuleName, -1, pbBuffer, sizeof(pbBuffer), &uszModuleName, NULL, 0)) { return FALSE; }
    return VMMDLL_WinGetThunkInfoIATU(dwPID, uszModuleName, szImportModuleName, szImportFunctionName, pThunkInfoIAT);
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
    PDB_HANDLE hPdb = (strcmp(szModule, "nt") && strcmp(szModule, "ntoskrnl")) ? PDB_GetHandleFromModuleName(szModule) : PDB_HANDLE_KERNEL;
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
    PDB_HANDLE hPdb = (strcmp(szModule, "nt") && strcmp(szModule, "ntoskrnl")) ? PDB_GetHandleFromModuleName(szModule) : PDB_HANDLE_KERNEL;
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
BOOL VMMDLL_PdbTypeChildOffset_Impl(_In_ LPSTR szModule, _In_ LPSTR uszTypeName, _In_ LPSTR uszTypeChildName, _Out_ PDWORD pcbTypeChildOffset)
{
    PDB_HANDLE hPdb = (strcmp(szModule, "nt") && strcmp(szModule, "ntoskrnl")) ? PDB_GetHandleFromModuleName(szModule) : PDB_HANDLE_KERNEL;
    return PDB_GetTypeChildOffset(hPdb, uszTypeName, uszTypeChildName, pcbTypeChildOffset);
}

_Success_(return)
BOOL VMMDLL_PdbTypeChildOffset(_In_ LPSTR szModule, _In_ LPSTR uszTypeName, _In_ LPSTR uszTypeChildName, _Out_ PDWORD pcbTypeChildOffset)
{
    CALL_IMPLEMENTATION_VMM(
        STATISTICS_ID_VMMDLL_PdbTypeChildOffset,
        VMMDLL_PdbTypeChildOffset_Impl(szModule, uszTypeName, uszTypeChildName, pcbTypeChildOffset))
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




//-----------------------------------------------------------------------------
// INTERNAL USE ONLY HELPER FUNCTIONS BELOW:
//-----------------------------------------------------------------------------
VOID VMMDLL_VfsList_AddFile(_In_ HANDLE pFileList, _In_ LPSTR uszName, _In_ ULONG64 cb, _In_opt_ PVMMDLL_VFS_FILELIST_EXINFO pExInfo)
{
    ((PVMMDLL_VFS_FILELIST2)pFileList)->pfnAddFile(((PVMMDLL_VFS_FILELIST2)pFileList)->h, uszName, cb, pExInfo);
}
VOID VMMDLL_VfsList_AddDirectory(_In_ HANDLE pFileList, _In_ LPSTR uszName, _In_opt_ PVMMDLL_VFS_FILELIST_EXINFO pExInfo)
{
    ((PVMMDLL_VFS_FILELIST2)pFileList)->pfnAddDirectory(((PVMMDLL_VFS_FILELIST2)pFileList)->h, uszName, pExInfo);
}

/*
* Helper functions for callbacks into the VMM_VFS_FILELIST structure.
*/
VOID VMMDLL_VfsList_AddFileW(_In_ HANDLE pFileList, _In_ LPWSTR wszName, _In_ ULONG64 cb, _In_opt_ PVMMDLL_VFS_FILELIST_EXINFO pExInfo)
{
    LPSTR uszName;
    BYTE pbBuffer[3 * MAX_PATH];
    if(!CharUtil_WtoU(wszName, -1, pbBuffer, sizeof(pbBuffer), &uszName, NULL, CHARUTIL_FLAG_TRUNCATE)) { return; }
    ((PVMMDLL_VFS_FILELIST2)pFileList)->pfnAddFile(((PVMMDLL_VFS_FILELIST2)pFileList)->h, uszName, cb, pExInfo);
}

VOID VMMDLL_VfsList_AddDirectoryW(_In_ HANDLE pFileList, _In_ LPWSTR wszName, _In_opt_ PVMMDLL_VFS_FILELIST_EXINFO pExInfo)
{
    LPSTR uszName;
    BYTE pbBuffer[3 * MAX_PATH];
    if(!CharUtil_WtoU(wszName, -1, pbBuffer, sizeof(pbBuffer), &uszName, NULL, CHARUTIL_FLAG_TRUNCATE)) { return; }
    ((PVMMDLL_VFS_FILELIST2)pFileList)->pfnAddDirectory(((PVMMDLL_VFS_FILELIST2)pFileList)->h, uszName, pExInfo);
}

BOOL VMMDLL_VfsList_IsHandleValid(_In_ HANDLE pFileList)
{
    return ((PVMMDLL_VFS_FILELIST2)pFileList)->dwVersion == VMMDLL_VFS_FILELIST_VERSION;
}
