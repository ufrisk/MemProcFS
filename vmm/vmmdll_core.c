// vmmdll_core.c : implementation of core library functionality which mainly
//      consists of library initialization and cleanup/close functionality.
//
// (c) Ulf Frisk, 2022-2025
// Author: Ulf Frisk, pcileech@frizk.net
//

#include "vmm.h"
#include "vmmex.h"
#include "vmmdll.h"
#include "vmmdll_remote.h"
#include "vmmlog.h"
#include "vmmproc.h"
#include "vmmwork.h"
#include "vmmuserconfig.h"
#include "ob/ob.h"
#include "ob/ob_tag.h"
#include "charutil.h"
#include "util.h"
#include "fc.h"
#include "statistics.h"
#include "version.h"
#include "pluginmanager.h"

//-----------------------------------------------------------------------------
// INITIALIZATION AND CLOSE FUNCTIONALITY BELOW:
// 
// Initialize and Close functionality is put behind a single shared global lock.
//-----------------------------------------------------------------------------

// globals below:
#define VMM_HANDLE_MAX_COUNT                64
static BOOL g_VMMDLL_INITIALIZED            = FALSE;
static POB_MAP g_VMMDLL_ALLOCMAP_EXT        = NULL;
static CRITICAL_SECTION g_VMMDLL_CORE_LOCK  = { 0 };
static DWORD g_VMMDLL_CORE_HANDLE_COUNT     = 0;
static VMM_HANDLE g_VMMDLL_CORE_HANDLES[VMM_HANDLE_MAX_COUNT] = { 0 };

// forward declarations below:
VOID VmmDllRemote_InitializeGlobals();
VOID VmmDllCore_MemLeakFindExternal(_In_ VMM_HANDLE H);
VOID VmmDllCore_CloseHandle(_In_opt_ _Post_ptr_invalid_ VMM_HANDLE H, _In_ BOOL fForceCloseAll);

/*
* Initialize the global variables g_VMMDLL_*.
* This function should only be called from DllMain.
* NB! it's ok to leak the initialized globals since the leak will be minor only.
*/
VOID VmmDllCore_InitializeGlobals()
{
    if(!g_VMMDLL_INITIALIZED) {
        g_VMMDLL_INITIALIZED = TRUE;
        InitializeCriticalSection(&g_VMMDLL_CORE_LOCK);
        g_VMMDLL_ALLOCMAP_EXT = ObMap_New(NULL, OB_MAP_FLAGS_OBJECT_OB);
    }
}

#ifdef _WIN32
BOOL WINAPI DllMain(_In_ HINSTANCE hinstDLL, _In_ DWORD fdwReason, _In_ PVOID lpvReserved)
{    
    if(fdwReason == DLL_PROCESS_ATTACH) {
        VmmDllCore_InitializeGlobals();
        VmmDllRemote_InitializeGlobals();
    }
    return TRUE;
}
#endif /* _WIN32 */
#if defined(LINUX) || defined(MACOS)
__attribute__((constructor)) VOID VmmAttach()
{
    VmmDllCore_InitializeGlobals();
    VmmDllRemote_InitializeGlobals();
}
#endif /* LINUX || MACOS */

/*
* Verify that the supplied handle is valid and also check it out.
* This must be called by each external access which requires a VMM_HANDLE.
* Each successful VmmDllCore_HandleReserveExternal() call must be matched by
* a matched call to VmmDllCore_HandleReturnExternal() after completion.
* -- H
* -- return
*/
_Success_(return)
BOOL VmmDllCore_HandleReserveExternal(_In_opt_ VMM_HANDLE H)
{
    DWORD i = 0;
    if(!H || ((SIZE_T)H < 0x10000)) { return FALSE;}
    EnterCriticalSection(&g_VMMDLL_CORE_LOCK);
    for(i = 0; i < g_VMMDLL_CORE_HANDLE_COUNT; i++) {
        if(g_VMMDLL_CORE_HANDLES[i] == H) {
            if((H->magic == VMM_MAGIC) && !H->fAbort) {
                InterlockedIncrement(&H->cThreadExternal);
                LeaveCriticalSection(&g_VMMDLL_CORE_LOCK);
                return TRUE;
            }
        }
    }
    LeaveCriticalSection(&g_VMMDLL_CORE_LOCK);
    return FALSE;
}

/*
* Return a handle successfully reserved with a previous call to the function:
* VmmDllCore_HandleReserveExternal()
* -- H
*/
VOID VmmDllCore_HandleReturnExternal(_In_opt_ VMM_HANDLE H)
{
    if(H) {
        InterlockedDecrement(&H->cThreadExternal);
    }
}

/*
* Duplicate a VMM_HANDLE (increase its handle count).
* NB! this does not "reserve" the handle itself!.
* -- H
* -- return = duplicated handle (with increased dwHandleCount).
*/
_Success_(return != NULL)
VMM_HANDLE VmmDllCore_HandleDuplicate(_In_ VMM_HANDLE H)
{
    if(VmmDllCore_HandleReserveExternal(H)) {
        if(H->dwHandleCount > 0xFFFFFFF0) {
            VmmDllCore_HandleReturnExternal(H);
            return NULL;
        }
        InterlockedIncrement(&H->dwHandleCount);
        VmmDllCore_HandleReturnExternal(H);
        return H;
    }
    return NULL;
}

/*
* Remove a handle from the external handle array.
* NB! Function is to be called behind exclusive lock g_VMMDLL_CORE_LOCK.
* -- H
*/
VOID VmmDllCore_HandleRemove(_In_ VMM_HANDLE H)
{
    DWORD i;
    if(H && (H->magic == VMM_MAGIC)) {
        for(i = 0; i < g_VMMDLL_CORE_HANDLE_COUNT; i++) {
            if(g_VMMDLL_CORE_HANDLES[i] == H) {
                g_VMMDLL_CORE_HANDLE_COUNT--;
                if(i < g_VMMDLL_CORE_HANDLE_COUNT) {
                    g_VMMDLL_CORE_HANDLES[i] = g_VMMDLL_CORE_HANDLES[g_VMMDLL_CORE_HANDLE_COUNT];
                    g_VMMDLL_CORE_HANDLES[g_VMMDLL_CORE_HANDLE_COUNT] = NULL;
                } else {
                    g_VMMDLL_CORE_HANDLES[i] = NULL;
                }
                break;
            }
        }
    }
}

/*
* Add a new handle to the external handle array.
* NB! Function is to be called behind exclusive lock g_VMMDLL_CORE_LOCK.
* -- H
*/
_Success_(return)
BOOL VmmDllCore_HandleAdd(_In_ VMM_HANDLE H)
{
    if(g_VMMDLL_CORE_HANDLE_COUNT < VMM_HANDLE_MAX_COUNT) {
        g_VMMDLL_CORE_HANDLES[g_VMMDLL_CORE_HANDLE_COUNT] = H;
        g_VMMDLL_CORE_HANDLE_COUNT++;
        return TRUE;
    }
    return FALSE;
}

/*
* Close all instances of a single child VMM. This is done async speed up closing
* of multiple child VMMs and also support timout messages in caller function.
*/
VOID VmmDllCore_CloseHandle_VmmChildCloseSingle_ThreadProc(_In_ VMM_HANDLE H, _In_ PVOID hChildVmm)
{
    VmmDllCore_CloseHandle((VMM_HANDLE)hChildVmm, TRUE);
}

/*
* Close/shutdown all child VMMs. Also wait for the child VMMs to shutdown.
* -- H
*/
VOID VmmDllCore_CloseHandle_VmmChildCloseAll(_In_ VMM_HANDLE H)
{
    QWORD i, tc, tcStart;
    VMM_HANDLE hChild = NULL;
    AcquireSRWLockExclusive(&H->childvmm.LockSRW);
    // Only call function once per VMM_HANDLE (fAbort flag).
    if(H->childvmm.fAbort) { goto finish; }
    H->childvmm.fAbort = TRUE;
    if(H->childvmm.c == 0) { goto finish; }
    // Initiate close/shutdown of child VMMs.
    for(i = 0; i < VMM_HANDLE_VM_CHILD_MAX_COUNT; i++) {
        if(H->childvmm.h[i]) {
            VmmWork_Void(H, VmmDllCore_CloseHandle_VmmChildCloseSingle_ThreadProc, H->childvmm.h[i], NULL, VMMWORK_FLAG_PRIO_NORMAL);
        }
    }
    // Wait for child VMMs to close/shutdown.
    tcStart = GetTickCount64();
    while(H->childvmm.c) {
        tc = GetTickCount64();
        if((tc - tcStart) > 45000) {
            tcStart = GetTickCount64();
            VmmLog(H, MID_CORE, LOGLEVEL_1_CRITICAL, "Shutdown waiting for long running child VMMs (%i).", H->childvmm.c);
        }
        ReleaseSRWLockExclusive(&H->childvmm.LockSRW);
        SwitchToThread();
        AcquireSRWLockExclusive(&H->childvmm.LockSRW);
    }
finish:
    ReleaseSRWLockExclusive(&H->childvmm.LockSRW);
}

/*
* Detach this VMM instance from the parent VMM (if any).
* -- H
*/
VOID VmmDllCore_CloseHandle_VmmParentDetach(_In_ VMM_HANDLE H)
{
    DWORD i, iMax = 0;
    // VMM_HANDLE of parent is always valid since parent shutdown will
    // wait for its child count to reach zero before doing a shutdown.
    // NB! after decrement of hParent->childvmm.c parent may not be valid.
    VMM_HANDLE hParent = H->childvmm.hParent;
    if(hParent) {
        AcquireSRWLockExclusive(&hParent->childvmm.LockSRW);
        for(i = 0; i < VMM_HANDLE_VM_CHILD_MAX_COUNT; i++) {
            if(H == hParent->childvmm.h[i]) {
                hParent->childvmm.h[i] = 0;
                if(hParent->childvmm.iMax == i) {
                    hParent->childvmm.iMax = iMax;
                }
                hParent->childvmm.c--;
                H->childvmm.hParent = NULL;
                ReleaseSRWLockExclusive(&hParent->childvmm.LockSRW);
                PluginManager_Notify(hParent, VMMDLL_PLUGIN_NOTIFY_VM_ATTACH_DETACH, NULL, 0);
                return;
            }
            if(hParent->childvmm.h[i]) {
                iMax = i;
            }
        }
        H->childvmm.hParent = NULL;
        ReleaseSRWLockExclusive(&hParent->childvmm.LockSRW);
    }
}

/*
* Close a VMM_HANDLE and clean up everything! The VMM_HANDLE will not be valid
* after this function has been called. Function call may take some time since
* it's dependent on thread-stoppage (which may take time) to do a clean cleanup.
* The strategy is:
*   (1) disable external calls (set magic and abort flag)
*   (2) wait for worker threads to exit (done on abort) when completed no
*       threads except this one should access the handle.
*   (3) shut down Forensic > Vmm > LeechCore > Threading > Log
* -- H = a VMM_HANDLE fully or partially initialized
* -- fForceCloseAll = TRUE: disregard handle count. FALSE: adhere to handle count.
*/
VOID VmmDllCore_CloseHandle(_In_opt_ _Post_ptr_invalid_ VMM_HANDLE H, _In_ BOOL fForceCloseAll)
{
    BOOL fCloseHandle = FALSE;
    QWORD tc, tcStart;
    CHAR szTime[24];
    // Verify & decrement handle count.
    // If handle count > 0 (after decrement) return.
    // If handle count == 0 -> close and clean-up.
    // (this is done with help of HandleReserveExternal//HandleReturnExternal logic).
    if(!H) { return; }
    EnterCriticalSection(&g_VMMDLL_CORE_LOCK);
    if(!VmmDllCore_HandleReserveExternal(H)) {
        LeaveCriticalSection(&g_VMMDLL_CORE_LOCK);
        return;
    }
    InterlockedDecrement(&H->dwHandleCount);
    if(fForceCloseAll || (0 == H->dwHandleCount)) {
        fCloseHandle = TRUE;
        H->dwHandleCount = 0;
        // Remove handle from external allow-list.
        // This will stop external API calls using the handle.
        // This will also stop additional close calls using the handle.
        VmmDllCore_HandleRemove(H);
    }
    VmmDllCore_HandleReturnExternal(H);
    LeaveCriticalSection(&g_VMMDLL_CORE_LOCK);
    // Return if handle should not be closed - i.e. if handle count is > 0.
    if(!fCloseHandle) { return; }
    // Close/shutdown child VMMs and wait for all to close.
    // This should be done _before_ main fAbort is set (due to work use).
    VmmDllCore_CloseHandle_VmmChildCloseAll(H);
    tcStart = GetTickCount64();
    while(H->childvmm.c) {
        tc = GetTickCount64();
        if((tc - tcStart) > 30000) {
            tcStart = GetTickCount64();
            VmmLog(H, MID_CORE, LOGLEVEL_1_CRITICAL, "Shutdown waiting for long running VM childs (%i).", H->childvmm.c);
        }
        SwitchToThread();
    }
    // Set the abort flag. This will cause internal threading shutdown.
    H->fAbort = TRUE;
    H->magic = 0;
    // Abort work multithreading & forensic database queries (to speed up termination)
    VmmWork_Interrupt(H);
    FcInterrupt(H);
    // Wait for multi-threading to shut down.
    tcStart = GetTickCount64();
    while(H->cThreadExternal) {
        tc = GetTickCount64();
        if((tc - tcStart) > 30000) {
            tcStart = GetTickCount64();
            VmmLog(H, MID_CORE, LOGLEVEL_1_CRITICAL, "Shutdown waiting for long running external thread (%i).", H->cThreadExternal);
            VmmWork_Interrupt(H);
            FcInterrupt(H);
        }
        SwitchToThread();
    }
    tcStart = GetTickCount64();
    while(H->cThreadInternal) {
        tc = GetTickCount64();
        if((tc - tcStart) > 30000) {
            tcStart = GetTickCount64();
            VmmLog(H, MID_CORE, LOGLEVEL_1_CRITICAL, "Shutdown waiting for long running internal thread (%i).", H->cThreadInternal);
            VmmWork_Interrupt(H);
            FcInterrupt(H);
        }
        SwitchToThread();
    }
    // Close forensic sub-system.
    FcClose(H);
    // Close vmm sub-system.
    VmmClose(H);
    // Close leechcore
    LcClose(H->hLC);
    // Close work (multi-threading)
    VmmWork_Close(H);
    // Warn external (api-user) memory leaks
    VmmDllCore_MemLeakFindExternal(H);
    // Detach this VMM instance from parent VMM (if any)
    VmmDllCore_CloseHandle_VmmParentDetach(H);
    // Close logging (last)
    Statistics_CallSetEnabled(H, FALSE);
    Util_FileTime2String(Util_FileTimeNow(), szTime);
    VmmLog(H, MID_CORE, LOGLEVEL_VERBOSE, "SHUTDOWN COMPLETED (%p).", H);
    VmmLog(H, MID_CORE, LOGLEVEL_VERBOSE, "  TIME: %s.", szTime);
    VmmLog(H, MID_CORE, LOGLEVEL_VERBOSE, "  RUNTIME: %llus.\n", ((GetTickCount64() - H->cfg.tcTimeStart) / 1000));
    VmmLog_Close(H);
    LocalFree(H->cfg.ForensicProcessSkipList.pusz);
    LocalFree(H);
}

/*
* Close a VMM_HANDLE and clean up everything! The VMM_HANDLE will not be valid
* after this function has been called.
* -- H
*/
VOID VmmDllCore_Close(_In_opt_ _Post_ptr_invalid_ VMM_HANDLE H)
{
    VmmDllCore_CloseHandle(H, FALSE);
}

/*
* Close all VMM_HANDLE and clean up everything! No VMM_HANDLE will be valid
* after this function has been called.
*/
VOID VmmDllCore_CloseAll()
{
    VMM_HANDLE H;
    while(TRUE) {
        EnterCriticalSection(&g_VMMDLL_CORE_LOCK);
        H = g_VMMDLL_CORE_HANDLES[0];
        LeaveCriticalSection(&g_VMMDLL_CORE_LOCK);
        if(!H) { return; }
        VmmDllCore_CloseHandle(H, TRUE);
    }
}

/*
* Print the help. This requires a partially initialized VMM_HANDLE.
* -- H
*/
VOID VmmDllCore_PrintHelp(_In_ VMM_HANDLE H)
{
    vmmprintf(H,
        "                                                                               \n" \
        " MemProcFS v%i.%i.%i COMMAND LINE REFERENCE:                                   \n" \
        " MemProcFS may be used in stand-alone mode with support for memory dump files, \n" \
        " local memory via winpmem driver or together with PCILeech DMA devices.        \n" \
        " -----                                                                         \n",
        VERSION_MAJOR, VERSION_MINOR, VERSION_REVISION
    );
    VmmEx_InitializePrintSplashCopyright(H);
    vmmprintf(H,
        " -----                                                                         \n" \
        " The recommended way to use MemProcFS is to specify a memory acquisition device\n" \
        " in the -device option. Options -f and -z equals -device.                      \n" \
        " Example 1: MemProcFS.exe -f c:\\temp\\memdump-win10x64.raw                    \n" \
        " Example 2: MemProcFS.exe -device c:\\temp\\memdump-win10x64.dmp -forensic 1   \n" \
        " Example 3: MemProcFS.exe -device FPGA                                         \n" \
        " Example 4: MemProcFS.exe -device PMEM://c:\\temp\\winpmem_x64.sys             \n" \
        " -----                                                                         \n" \
        " Valid options:                                                                \n" \
        "   -device : select memory acquisition device or memory dump file to use.      \n" \
        "          Valid options: <any device supported by the leechcore library>       \n" \
        "          such as, but not limited to: <memory_dump_file>, PMEM, FPGA          \n" \
        "          ---                                                                  \n" \
        "          Options -f and -z equals -device.                                    \n" \
        "          Please see https://github.com/ufrisk/LeechCore for additional info.  \n" \
        "   -remote : connect to a remote host running the LeechAgent. Please see the   \n" \
        "          LeechCore documentation for more information.                        \n" \
        "   -remotefs : connect to a remote LeechAgent hosting a remote MemProcFS.      \n" \
        "   -v   : verbose option. Additional information is displayed in the output.   \n" \
        "          Option has no value. Example: -v                                     \n" \
        "   -vv  : extra verbose option. More detailed additional information is shown  \n" \
        "          in output. Option has no value. Example: -vv                         \n" \
        "   -vvv : super verbose option. Show all data transferred such as PCIe TLPs.   \n" \
        "          Option has no value. Example: -vvv                                   \n" \
        "   -version : display version.                                                 \n" \
        "   -logfile : specify an optional log file.                                    \n" \
        "   -loglevel : specify the log verbosity level as a comma-separated list.      \n" \
        "          Please consult https://github.com/ufrisk/MemProcFS/wiki for details. \n" \
        "          example: -loglevel 4,f:5,f:VMM:6                                     \n" \
        "   -max : memory max address, valid range: 0x0 .. 0xffffffffffffffff           \n" \
        "          default: auto-detect (max supported by device / target system).      \n" \
        "   -memmap-str : specify a physical memory map in parameter argument text.     \n" \
        "   -memmap : specify a physical memory map given in a file or specify 'auto'.  \n" \
        "          example: -memmap c:\\temp\\my_custom_memory_map.txt                  \n" \
        "          example: -memmap auto                                                \n" \
        "   -pagefile0..9 : specify page file / swap file. By default pagefile have     \n" \
        "          index 0 - example: -pagefile0 pagefile.sys while swapfile have       \n" \
        "          index 1 - example: -pagefile1 swapfile.sys                           \n" \
        "   -pythonexec : execute a python program in the memprocfs context at start-up.\n" \
        "          If forensic mode is enabled wait for it to complete first.           \n" \
        "          Example: -pythonexec C:\\Temp\\mypythonprogram.py                    \n" \
        "   -pythonpath : specify the path to a python 3 installation for Windows.      \n" \
        "          The path given should be to the directory that contain: python.dll   \n" \
        "          Example: -pythonpath \"C:\\Program Files\\Python37\"                 \n" \
        "   -disable-python : prevent/disable the python plugin sub-system from loading.\n" \
        "          Example: -disable-python                                             \n" \
        "   -disable-symbolserver : disable any integrations with the Microsoft Symbol  \n" \
        "          Server used by the debugging .pdb symbol subsystem. Functionality    \n" \
        "          will be limited if this is activated. Example: -disable-symbolserver \n" \
        "   -disable-symbols : disable symbol lookups from .pdb files.                  \n" \
        "          Example: -disable-symbols                                            \n" \
        "   -disable-infodb : disable the infodb and any symbol lookups via it.         \n" \
        "          Example: -disable-infodb                                             \n" \
        "   -mount : drive letter/path to mount MemProcFS at.                           \n" \
        "          default: M   Example: -mount Q                                       \n" \
        "   -norefresh : disable automatic cache and processes refreshes even when      \n" \
        "          running against a live memory target - such as PCIe FPGA or live     \n" \
        "          driver acquired memory. This is not recommended. Example: -norefresh \n" \
        "   -waitinitialize : wait debugging .pdb symbol subsystem to fully start before\n" \
        "          mounting file system and fully starting MemProcFS.                   \n" \
        "   -userinteract = allow vmm.dll to, on the console, query the user for        \n" \
        "          information such as, but not limited to, leechcore device options.   \n" \
        "          Default: user interaction = disabled. Combine with -forensic option. \n" \
        "   -vm        : virtual machine (VM) parsing.                                  \n" \
        "   -vm-basic  : virtual machine (VM) parsing (physical memory only).           \n" \
        "   -vm-nested : virtual machine (VM) parsing (including nested VMs).           \n" \
        "   -license-accept-elastic-license-2-0 : accept the Elastic License 2.0 to     \n" \
        "          enable built-in yara rules from Elastic.                             \n" \
        "   -forensic-process-skip : comma-separated list of process names to skip.     \n" \
        "   -forensic-yara-rules : perfom a forensic yara scan with specified rules.    \n" \
        "          Full path to source or compiled yara rules should be specified.      \n" \
        "          Example: -forensic-yara-rules \"C:\\Temp\\my_yara_rules.yar\"        \n" \
        "   -forensic : start a forensic scan of the physical memory immediately after  \n" \
        "          startup if possible. Allowed parameter values range from 0-4.        \n" \
        "          Note! forensic mode is not available for live memory.                \n" \
        "          0 = not enabled (default value)                                      \n" \
        "          1 = forensic mode with in-memory sqlite database.                    \n" \
        "          2 = forensic mode with temp sqlite database deleted upon exit.       \n" \
        "          3 = forensic mode with temp sqlite database remaining upon exit.     \n" \
        "          4 = forensic mode with static named sqlite database (vmm.sqlite3).   \n" \
        "          default: 0  Example -forensic 4                                      \n"
    );
}

/*
* Initialize command line config settings in H->cfg and H->dev.
* Upon failure the VMM_HANDLE will be partially intiialized. This is important
* since the '-printf' command line option is required to print info on-screen.
* It's recommended to put the '-printf' option as the first argument!
* -- H = a cleared fresh VMM_HANDLE not yet fully initialized.
* -- argc
* -- argv
* -- return
*/
_Success_(return)
BOOL VmmDllCore_InitializeConfig(_In_ VMM_HANDLE H, _In_ DWORD argc, _In_ const char *argv[])
{
    const char *argv2[3], *argvext;
    DWORD i = 0, dw, iPageFile;
    if((argc == 2) && ((0 == _stricmp(argv[0], "-printf")) || (argv[0][0] != '-')) && argv[1][0] && (argv[1][0] != '-')) {
        // click to open -> only 1 argument ...
        argv2[0] = argv[0];
        argv2[1] = "-device";
        argv2[2] = argv[1];
        return VmmDllCore_InitializeConfig(H, 3, argv2);
    }
    H->cfg.dwPteQualityThreshold = 0x20;
    H->cfg.tcTimeStart = GetTickCount64();
    while(i < argc) {
        // "single argument" parameters below:
        if(0 == _stricmp(argv[i], "")) {
            i++; continue;
        } else if(0 == _stricmp(argv[i], "-_internal_physical_memory_only")) {
            H->cfg.fPhysicalOnlyMemory = TRUE;
            i++; continue;
        } else if(0 == _stricmp(argv[i], "-disable-infodb")) {
            H->cfg.fDisableInfoDB = TRUE;
            i++; continue;
        } else if(0 == _stricmp(argv[i], "-disable-python")) {
            H->cfg.fDisablePython = TRUE;
            i++; continue;
        } else if(0 == _stricmp(argv[i], "-disable-symbols")) {
            H->cfg.fDisableSymbolServerOnStartup = TRUE;
            H->cfg.fDisableSymbols = TRUE;
            i++; continue;
        } else if(0 == _stricmp(argv[i], "-disable-symbolserver")) {
            H->cfg.fDisableSymbolServerOnStartup = TRUE;
            i++; continue;
        } else if(0 == _stricmp(argv[i], "-disable-yara")) {
            H->cfg.fDisableYara = TRUE;
            i++; continue;
        } else if(0 == _stricmp(argv[i], "-disable-yara-builtin")) {
            H->cfg.fDisableYaraBuiltin = TRUE;
            i++; continue;
        } else if((0 == _stricmp(argv[i], "-license-accept-elastic-license-2.0")) || (0 == _stricmp(argv[i], "-license-accept-elastic-license-2-0"))) {
            H->cfg.fLicenseAcceptElasticV2 = TRUE;
            i++; continue;
        } else if(0 == _stricmp(argv[i], "-norefresh")) {
            H->cfg.fDisableBackgroundRefresh = TRUE;
            i++; continue;
        } else if(0 == _stricmp(argv[i], "-printf")) {
            H->cfg.fVerboseDll = TRUE;
            i++; continue;
        } else if(0 == _stricmp(argv[i], "-remotefs")) {
            H->cfg.fRemoteFS = TRUE;
            i++; continue;
        } else if(0 == _stricmp(argv[i], "-userinteract")) {
            H->cfg.fUserInteract = TRUE;
            i++; continue;
        } else if(0 == _stricmp(argv[i], "-v")) {
            H->cfg.fVerbose = TRUE;
            i++; continue;
        } else if(0 == _stricmp(argv[i], "-vv")) {
            H->cfg.fVerboseExtra = TRUE;
            i++; continue;
        } else if(0 == _stricmp(argv[i], "-vvv")) {
            H->cfg.fVerboseExtraTlp = TRUE;
            i++; continue;
        } else if(0 == _stricmp(argv[i], "-version")) {
            H->cfg.fDisplayVersion = TRUE;
            i++; continue;
        } else if(0 == _stricmp(argv[i], "-waitinitialize")) {
            H->cfg.fWaitInitialize = TRUE;
            i++; continue;
        } else if(0 == _stricmp(argv[i], "-vm")) {
            H->cfg.fVM = TRUE;
            H->cfg.fVMNested = FALSE;
            H->cfg.fVMPhysicalOnly = FALSE;
            i++; continue;
        } else if(0 == _stricmp(argv[i], "-vm-basic")) {
            H->cfg.fVM = TRUE;
            H->cfg.fVMNested = FALSE;
            H->cfg.fVMPhysicalOnly = TRUE;
            i++; continue;
        } else if(0 == _stricmp(argv[i], "-vm-nested")) {
            H->cfg.fVM = TRUE;
            H->cfg.fVMNested = TRUE;
            H->cfg.fVMPhysicalOnly = FALSE;
            i++; continue;
        // "dual argument" parameters below:
        } else if(i + 1 >= argc) {
            return FALSE;
        } else if(0 == _stricmp(argv[i], "-_internal_vmm_parent")) {
            H->cfg.qwParentVmmHandle = Util_GetNumericA(argv[i + 1]);
            H->cfg.fDisablePython = TRUE;
            i += 2; continue;
        } else if((0 == _stricmp(argv[i], "-arch")) || 0 == _stricmp(argv[i], "-architecture")) {
            if(CharUtil_StrEquals(argv[i + 1], "x86", TRUE))    { H->cfg.tpMemoryModel = VMM_MEMORYMODEL_X86; }
            if(CharUtil_StrEquals(argv[i + 1], "x86pae", TRUE)) { H->cfg.tpMemoryModel = VMM_MEMORYMODEL_X86PAE; }
            if(CharUtil_StrEquals(argv[i + 1], "x64", TRUE))    { H->cfg.tpMemoryModel = VMM_MEMORYMODEL_X64; }
            if(CharUtil_StrEquals(argv[i + 1], "arm64", TRUE))  { H->cfg.tpMemoryModel = VMM_MEMORYMODEL_ARM64; }
            i += 2; continue;
        } else if((0 == _stricmp(argv[i], "-cr3") || (0 == _stricmp(argv[i], "-dtb")))) {
            H->cfg.paCR3 = Util_GetNumericA(argv[i + 1]);
            i += 2; continue;
        } else if(0 == _stricmp(argv[i], "-dtb-range")) {
            argvext = strstr(argv[i + 1], "-");
            if(!argvext) { return FALSE; }
            H->cfg.DTBRange.paStart = Util_GetNumericA(argv[i + 1]);
            H->cfg.DTBRange.paEnd = (Util_GetNumericA(argvext + 1) + 1) & ~0xfff;
            if((H->cfg.DTBRange.paStart >= H->cfg.DTBRange.paEnd)) { return FALSE; }
            i += 2; continue;
        } else if(0 == _stricmp(argv[i], "-create-from-vmmid")) {
            H->cfg.qwVmmID = Util_GetNumericA(argv[i + 1]);
            return TRUE;    // special case: this parameter takes priority over all other parameters -> return TRUE now.
        } else if(0 == _stricmp(argv[i], "-debug-pte-quality-threshold")) {
            H->cfg.dwPteQualityThreshold = (DWORD)Util_GetNumericA(argv[i + 1]);
            i += 2; continue;
        } else if((0 == _stricmp(argv[i], "-device")) || (0 == strcmp(argv[i], "-f")) || (0 == strcmp(argv[i], "-z"))) {
            strcpy_s(H->dev.szDevice, MAX_PATH, argv[i + 1]);
            i += 2; continue;
        } else if(0 == _stricmp(argv[i], "-forensic")) {
            H->cfg.tpForensicMode = (DWORD)Util_GetNumericA(argv[i + 1]);
            if(H->cfg.tpForensicMode > FC_DATABASE_TYPE_MAX) { return FALSE; }
            i += 2; continue;
        } else if(0 == _stricmp(argv[i], "-logfile")) {
            strcpy_s(H->cfg.szLogFile, MAX_PATH, argv[i + 1]);
            i += 2; continue;
        } else if(0 == _stricmp(argv[i], "-loglevel")) {
            strcpy_s(H->cfg.szLogLevel, MAX_PATH, argv[i + 1]);
            i += 2; continue;
        } else if(0 == _stricmp(argv[i], "-forensic-yara-rules")) {
            strcpy_s(H->cfg.szForensicYaraRules, MAX_PATH, argv[i + 1]);
            i += 2; continue;
        } else if(0 == _stricmp(argv[i], "-forensic-process-skip")) {
            CharUtil_SplitList((LPSTR)argv[i + 1], ',', &H->cfg.ForensicProcessSkipList.cusz, &H->cfg.ForensicProcessSkipList.pusz);
            i += 2; continue;
        } else if(0 == _stricmp(argv[i], "-max")) {
            H->dev.paMax = Util_GetNumericA(argv[i + 1]);
            i += 2; continue;
        } else if(0 == _stricmp(argv[i], "-memmap")) {
            strcpy_s(H->cfg.szMemMap, MAX_PATH, argv[i + 1]);
            if(!_stricmp(H->cfg.szMemMap, "auto")) { H->cfg.fMemMapAuto = TRUE; }
            if(!_stricmp(H->cfg.szMemMap, "none")) { H->cfg.fMemMapNone = TRUE; }
            i += 2; continue;
        } else if(0 == _stricmp(argv[i], "-memmap-str")) {
            strcpy_s(H->cfg.szMemMapStr, _countof(H->cfg.szMemMapStr), argv[i + 1]);
            i += 2; continue;
        } else if(0 == _stricmp(argv[i], "-mount")) {
            i += 2; continue;
        } else if(0 == _strnicmp(argv[i], "-pagefile", 9)) {
            iPageFile = argv[i][9] - '0';
            if(iPageFile < 10) {
                strcpy_s(H->cfg.szPageFile[iPageFile], MAX_PATH, argv[i + 1]);
            }
            i += 2; continue;
        } else if(0 == _stricmp(argv[i], "-pythonexec")) {
            H->cfg.fWaitInitialize = TRUE;
            strcpy_s(H->cfg.szPythonExecuteFile, MAX_PATH, argv[i + 1]);
            i += 2; continue;
        } else if(0 == _stricmp(argv[i], "-pythonpath")) {
            strcpy_s(H->cfg.szPythonPath, MAX_PATH, argv[i + 1]);
            i += 2; continue;
        } else if(0 == _stricmp(argv[i], "-remote")) {
            strcpy_s(H->dev.szRemote, MAX_PATH, argv[i + 1]);
            i += 2; continue;
        } else {
            return FALSE;
        }
    }
    if(H->dev.paMax && (H->dev.paMax < 0x00100000)) { return FALSE; }
    // disable memory auto-detect when memmap is specified:
    if(!H->dev.paMax && (H->cfg.szMemMap[0] || H->cfg.szMemMapStr[0])) {
        H->dev.paMax = -1;
    }
    // yara rules implies forensic mode:
    if(H->cfg.szForensicYaraRules[0] && !H->cfg.tpForensicMode) {
        H->cfg.tpForensicMode = 1;
    }
    // forensic mode implies VM detection & wait for initialize:
    if(H->cfg.tpForensicMode) {
        H->cfg.fWaitInitialize = TRUE;
        H->cfg.fVM = TRUE;
    }
    // cache license acceptance for forensic mode yara rules:
    if(H->cfg.fLicenseAcceptElasticV2) {
        VmmUserConfig_SetNumber("LicenseAcceptElasticLicense2.0", 1);
    } else if(H->cfg.tpForensicMode) {
        H->cfg.fLicenseAcceptElasticV2 = (VmmUserConfig_GetNumber("LicenseAcceptElasticLicense2.0", &dw) && (dw == 1));
    }
    // set other config values:
    H->cfg.fFileInfoHeader = TRUE;
    H->cfg.fVerbose = H->cfg.fVerbose && H->cfg.fVerboseDll;
    H->cfg.fVerboseExtra = H->cfg.fVerboseExtra && H->cfg.fVerboseDll;
    H->cfg.fVerboseExtraTlp = H->cfg.fVerboseExtraTlp && H->cfg.fVerboseDll;
    H->dev.dwVersion = LC_CONFIG_VERSION;
    H->dev.dwPrintfVerbosity |= H->cfg.fVerboseDll ? LC_CONFIG_PRINTF_ENABLED : 0;
    H->dev.dwPrintfVerbosity |= H->cfg.fVerbose ? LC_CONFIG_PRINTF_V : 0;
    H->dev.dwPrintfVerbosity |= H->cfg.fVerboseExtra ? LC_CONFIG_PRINTF_VV : 0;
    H->dev.dwPrintfVerbosity |= H->cfg.fVerboseExtraTlp ? LC_CONFIG_PRINTF_VVV : 0;
    Util_GetPathLib(H->cfg.szPathLibraryVmm);
    strncat_s(H->cfg.szPathLibraryVmm, _countof(H->cfg.szPathLibraryVmm), "vmm", _TRUNCATE);
    strncat_s(H->cfg.szPathLibraryVmm, _countof(H->cfg.szPathLibraryVmm), VMM_LIBRARY_FILETYPE, _TRUNCATE);
    return (H->dev.szDevice[0] != 0);
}

#ifdef _WIN32

/*
* Request user input. This is done upon a request from LeechCore. User input is
* only requested in interactive user contexts.
* -- H = partially initialized VMM_HANDLE.
* -- argc
* -- argv
* -- return
*/
_Success_(return != NULL)
VMM_HANDLE VmmDllCore_InitializeRequestUserInput(_In_ _Post_ptr_invalid_ VMM_HANDLE H, _In_ DWORD argc, _In_ LPSTR argv[])
{
    LPSTR szProto;
    DWORD i, cbRead = 0;
    CHAR szInput[33] = { 0 };
    CHAR szDevice[MAX_PATH] = { 0 };
    HANDLE hStdIn = GetStdHandle(STD_INPUT_HANDLE);     // must not be closed.
    // 1: read input
    vmmprintf(H, "\n?> ");
    ReadConsoleA(hStdIn, szInput, 32, &cbRead, NULL);
    for(i = 0; i < _countof(szInput); i++) {
        if((szInput[i] == '\r') || (szInput[i] == '\n')) { szInput[i] = 0; }
    }
    cbRead = (DWORD)strlen(szInput);
    if(!cbRead) { return NULL; }
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
    // 3: try re-initialize with new user input.
    //    (and close earlier partially initialized handle).
    VmmDllCore_CloseHandle(H, FALSE);
    return VMMDLL_InitializeEx(argc, argv, NULL);
}

#endif /* _WIN32 */

/*
* Attach a VMM_HANDLE to its parent.
* (This may fail if parent already have VMM_HANDLE_VM_CHILD_MAX_COUNT attached).
* -- H
* -- hParent
* -- return
*/
_Success_(return)
BOOL VmmDllCore_Initialize_HandleAttachParent(_In_ VMM_HANDLE H, _In_ VMM_HANDLE hParent)
{
    DWORD iBase, iChild;
    BOOL fResult = FALSE;
    if(!VmmDllCore_HandleReserveExternal(hParent)) { return FALSE; }
    AcquireSRWLockExclusive(&H->childvmm.LockSRW);
    AcquireSRWLockExclusive(&hParent->childvmm.LockSRW);
    if(!H->fAbort && !H->childvmm.fAbort && !hParent->fAbort && !hParent->childvmm.fAbort) {
        hParent->childvmm.dwCreateCount++;
        for(iBase = 0; iBase < VMM_HANDLE_VM_CHILD_MAX_COUNT; iBase++) {
            iChild = (iBase + hParent->childvmm.dwCreateCount) % VMM_HANDLE_VM_CHILD_MAX_COUNT;
            if(!hParent->childvmm.h[iChild]) {
                H->childvmm.hParent = hParent;
                H->childvmm.dwParentIndex = iChild;
                hParent->childvmm.iMax = max(hParent->childvmm.iMax, iChild);
                hParent->childvmm.h[iChild] = H;
                hParent->childvmm.c++;
                fResult = TRUE;
                break;
            }
        }
    }
    ReleaseSRWLockExclusive(&hParent->childvmm.LockSRW);
    ReleaseSRWLockExclusive(&H->childvmm.LockSRW);
    VmmDllCore_HandleReturnExternal(hParent);
    if(fResult) {
        PluginManager_Notify(hParent, VMMDLL_PLUGIN_NOTIFY_VM_ATTACH_DETACH, H, 0);
    }
    return fResult;
}

/*
* Initialize MemProcFS from user parameters. Upon success a VMM_HANDLE is returned.
* The returned VMM_HANDLE will not yet be in any required external info maps.
* -- argc
* -- argv
* -- ppLcErrorInfo
* -- return
*/
_Success_(return != NULL)
VMM_HANDLE VmmDllCore_Initialize(_In_ DWORD argc, _In_ LPCSTR argv[], _Out_opt_ PPLC_CONFIG_ERRORINFO ppLcErrorInfo)
{
    VMM_HANDLE H = NULL;
    FILE *hFile = NULL;
    BOOL f;
    DWORD cbMemMap = 0;
    PBYTE pbMemMap = NULL;
    PLC_CONFIG_ERRORINFO pLcErrorInfo = NULL;
    LPSTR uszUserText;
    BYTE pbBuffer[3 * MAX_PATH];
    QWORD qwVmmID;
    if(ppLcErrorInfo) { *ppLcErrorInfo = NULL; }
    // 1: allocate VMM_HANDLE object and initialize command line configuration.
    //    After config initialization call vmmprintf should work regardless of
    //    success/fail.
    if(!(H = LocalAlloc(LMEM_ZEROINIT, sizeof(struct tdVMM_HANDLE)))) { goto fail_prelock; }
    H->magic = VMM_MAGIC;
    H->dwHandleCount = 1;
    f = VmmDllCore_InitializeConfig(H, (DWORD)argc, argv);
    if(H->cfg.fDisplayVersion) {
        vmmprintf(H, "MemProcFS v%i.%i.%i\n", VERSION_MAJOR, VERSION_MINOR, VERSION_REVISION);
    }
    if(!f) {
        if(!H->cfg.fDisplayVersion) {
            VmmDllCore_PrintHelp(H);
        }
        goto fail_prelock;
    }
    if(!VmmEx_InitializeVerifyConfig(H)) {
        vmmprintf(H, "\n");
        goto fail_prelock;
    }
    // 2.0: If -create-from-vmmid is specified, duplicate the parent VMM_HANDLE
    //      increasing its refcount. This also disregards any other parameters
    //      that may be specified.
    if(H->cfg.qwVmmID) {
        qwVmmID = H->cfg.qwVmmID;
        LocalFree(H->cfg.ForensicProcessSkipList.pusz);
        LocalFree(H);
        return VmmDllCore_HandleDuplicate((VMM_HANDLE)qwVmmID);
    }
    // 2.1: If -remotefs is specified, try to connect to the remote MemProcFS
    //      instance running under the remote LeechAgent. This is a special
    //      case and will return a special VMM_HANDLE.
    if(H->cfg.fRemoteFS) {
        LocalFree(H);
        return VmmDllRemote_Initialize(argc, argv, ppLcErrorInfo);
    }
    // 2.2: If vmm is supposed to be created with a parent check conditions and retrieve the parent handle.
    if(H->cfg.fVM && (sizeof(PVOID) < 8)) {
        vmmprintf(H, "MemProcFS: VM parsing is only available on 64-bit due to resource constraints.\n");
        goto fail_prelock;
    }
    if(H->cfg.qwParentVmmHandle) {
        if(sizeof(PVOID) < 8) {
            vmmprintf(H, "MemProcFS: Failed to create child VMM: Only allowed in 64-bit mode).\n");
            goto fail_prelock;
        }
        if(!VmmDllCore_HandleReserveExternal((VMM_HANDLE)H->cfg.qwParentVmmHandle)) {
            vmmprintf(H, "MemProcFS: Failed to create child VMM: Bad parent handle).\n");
            goto fail_prelock;
        }
        VmmDllCore_HandleReturnExternal((VMM_HANDLE)H->cfg.qwParentVmmHandle);
    }
    // 3: Acquire global shared lock (for remainder of initialization).
    EnterCriticalSection(&g_VMMDLL_CORE_LOCK);
    // 4: upon success add handle to external allow-list.
    if(!VmmDllCore_HandleAdd(H)) {
        vmmprintf(H, "MemProcFS: Failed to add handle to external allow-list (max %i concurrent tasks allowed).\n", g_VMMDLL_CORE_HANDLE_COUNT);
        goto fail;
    }
    // 5: initialize LeechCore memory acquisition device
    if(!(H->hLC = LcCreateEx(&H->dev, &pLcErrorInfo))) {
#ifdef _WIN32
        if(pLcErrorInfo && (pLcErrorInfo->dwVersion == LC_CONFIG_ERRORINFO_VERSION)) {
            if(pLcErrorInfo->cwszUserText && CharUtil_WtoU(pLcErrorInfo->wszUserText, -1, pbBuffer, sizeof(pbBuffer), &uszUserText, NULL, 0)) {
                vmmprintf(H, "MESSAGE FROM MEMORY ACQUISITION DEVICE:\n=======================================\n%s\n", uszUserText);
            }
            if(H->cfg.fUserInteract && pLcErrorInfo->fUserInputRequest) {
                LcMemFree(pLcErrorInfo);
                LeaveCriticalSection(&g_VMMDLL_CORE_LOCK);
                // the request user input function will force a re-initialization upon
                // success and free/discard the earlier partially initialized handle.
                return VmmDllCore_InitializeRequestUserInput(H, argc, argv);
            }
        }
#endif /* _WIN32 */
        vmmprintf(H, "MemProcFS: Failed to connect to memory acquisition device.\n");
        goto fail;
    }
    // 6: initialize/(refresh) the logging sub-system
    VmmLog_LevelRefresh(H);
    // 7: Set LeechCore MemMap (if exists and not auto - i.e. from file)
    if(H->cfg.szMemMap[0] && !H->cfg.fMemMapAuto) {
        f = (pbMemMap = LocalAlloc(LMEM_ZEROINIT, 0x01000000)) &&
            !fopen_s(&hFile, H->cfg.szMemMap, "rb") && hFile &&
            (cbMemMap = (DWORD)fread(pbMemMap, 1, 0x01000000, hFile)) && (cbMemMap < 0x01000000) &&
            LcCommand(H->hLC, LC_CMD_MEMMAP_SET, cbMemMap, pbMemMap, NULL, NULL) &&
            LcGetOption(H->hLC, LC_OPT_CORE_ADDR_MAX, &H->dev.paMax);
        LocalFree(pbMemMap);
        if(hFile) { fclose(hFile); }
        if(!f) {
            VmmLog(H, MID_CORE, LOGLEVEL_CRITICAL, "Failed to load initial memory map from: '%s'.\n", H->cfg.szMemMap);
            goto fail;
        }
    }
    if(H->cfg.szMemMapStr[0]) {
        f = LcCommand(H->hLC, LC_CMD_MEMMAP_SET, (DWORD)strlen(H->cfg.szMemMapStr), H->cfg.szMemMapStr, NULL, NULL) &&
            LcGetOption(H->hLC, LC_OPT_CORE_ADDR_MAX, &H->dev.paMax);
        if(!f) {
            VmmLog(H, MID_CORE, LOGLEVEL_CRITICAL, "Failed to load command line argument memory map.\n");
            goto fail;
        }
    }
    // 8: initialize work (multi-threading sub-system).
    if(!VmmWork_Initialize(H)) {
        VmmLog(H, MID_CORE, LOGLEVEL_CRITICAL, "Failed to initialize work multi-threading.\n");
        goto fail;
    }
    // 9: device context (H->dev) is initialized from here onwards - device functionality is working!
    //    try initialize vmm subsystem.
    //    If '-memmap auto' is specified it will be initialized here as well.
    if(!VmmProcInitialize(H)) {
        VmmLog(H, MID_CORE, LOGLEVEL_CRITICAL, "Failed to initialize.\n");
        goto fail;
    }
    // 10: vmm context (H->vmm) is initialized from here onwards - vmm functionality is working!
    // 11: add this vmm instance to the parent vmm instance (if any)
    if(H->cfg.qwParentVmmHandle) {
        if(!VmmDllCore_Initialize_HandleAttachParent(H, (VMM_HANDLE)H->cfg.qwParentVmmHandle)) {
            VmmLog(H, MID_CORE, LOGLEVEL_CRITICAL, "Failed attaching to parent VMM.\n");
            goto fail;
        }
    }
    // 12: initialize forensic mode (if set by user parameter).
    if(H->cfg.tpForensicMode) {
        if(!FcInitialize(H, H->cfg.tpForensicMode, FALSE)) {
            VmmLog(H, MID_CORE, LOGLEVEL_CRITICAL, "Failed to initialize forensic mode.\n");
            goto fail;
        }
    }
    // 13: leave global lock to avoid deadlocks in remaining tasks.
    LeaveCriticalSection(&g_VMMDLL_CORE_LOCK);
    // 14: execute python code (if user option is set).
    if(H->cfg.szPythonExecuteFile[0] && VmmDllCore_HandleReserveExternal(H)) {
        PluginManager_PythonExecFile(H, H->cfg.szPythonExecuteFile);
        VmmDllCore_HandleReturnExternal(H);
    }
    return H;
fail:
    if(ppLcErrorInfo) {
        *ppLcErrorInfo = pLcErrorInfo;
    } else {
        LcMemFree(pLcErrorInfo);
    }
    LeaveCriticalSection(&g_VMMDLL_CORE_LOCK);
    VmmDllCore_CloseHandle(H, FALSE);
    return NULL;
fail_prelock:
    if(H) {
        LocalFree(H->cfg.ForensicProcessSkipList.pusz);
        LocalFree(H);
    }
    return NULL;
}



//-----------------------------------------------------------------------------
// EXTERNAL MEMORY ALLOCATION / DEALLOCATION FUNCTIONALITY BELOW:
//-----------------------------------------------------------------------------

typedef struct tdVMMDLLCORE_MEMLEAKEXTERNAL_CONTEXT {
    VMM_HANDLE H;
    DWORD c;
} VMMDLLCORE_MEMLEAKEXTERNAL_CONTEXT, *PVMMDLLCORE_MEMLEAKEXTERNAL_CONTEXT;

VOID VmmDllCore_MemLeakFindExternal_MapFilterCB(_In_ PVMMDLLCORE_MEMLEAKEXTERNAL_CONTEXT ctx, _In_ QWORD k, _In_ POB v)
{
    if((v->H != ctx->H) || (ctx->c >= 10)) { return; }
    ctx->c++;
    VmmLog(ctx->H, MID_API, LOGLEVEL_2_WARNING, "MEMORY NOT DEALLOCATED AT CLOSE: va=0x%llx size=0x%x tag=%c%c%c%c", (QWORD)v + sizeof(OB), v->cbData, v->_tagCh[3], v->_tagCh[2], v->_tagCh[1], v->_tagCh[0]);
    if(ctx->c == 10) {
        VmmLog(ctx->H, MID_API, LOGLEVEL_2_WARNING, "MEMORY NOT DEALLOCATED AT CLOSE: FIRST %i ENTRIES SHOWN - WARNING MUTED!", ctx->c);
    }
}

/*
* Warn/Log potential user memory leaks at handle close.
* This is done by walking the external handle map.
* -- H
*/
VOID VmmDllCore_MemLeakFindExternal(_In_ VMM_HANDLE H)
{
    VMMDLLCORE_MEMLEAKEXTERNAL_CONTEXT ctxFilter = { 0 };
    ctxFilter.H = H;
    if(VmmLogIsActive(H, MID_API, LOGLEVEL_2_WARNING)) {
        ObMap_Filter(g_VMMDLL_ALLOCMAP_EXT, &ctxFilter, (OB_MAP_FILTER_PFN_CB)VmmDllCore_MemLeakFindExternal_MapFilterCB);
    }
}

/*
* Query the size of memory allocated by the VMMDLL.
* -- pvMem
* -- return = number of bytes required to hold memory allocation.
*/
_Success_(return != 0)
SIZE_T VmmDllCore_MemSizeExternal(_In_ PVOID pvMem)
{
    POB pObMem;
    if(ObMap_ExistsKey(g_VMMDLL_ALLOCMAP_EXT, (QWORD)pvMem)) {
        pObMem = (POB)((SIZE_T)pvMem - sizeof(OB));
        if((pObMem->_magic2 == OB_HEADER_MAGIC) && (pObMem->_magic1 == OB_HEADER_MAGIC)) {
            return pObMem->cbData;
        }
    }
    return 0;
}

/*
* Free memory allocated by the VMMDLL.
* -- pvMem
*/
VOID VmmDllCore_MemFreeExternal(_Frees_ptr_opt_ PVOID pvMem)
{
    POB pObMem;
    if((pObMem = ObMap_RemoveByKey(g_VMMDLL_ALLOCMAP_EXT, (QWORD)pvMem))) {
        Ob_DECREF(pObMem);
    }
}

/*
* Allocate "external" memory to be free'd only by VMMDLL_MemFree // VmmDllCore_MemFreeExternal.
* CALLER VMMDLL_MemFree(return)
* -- H
* -- tag = tag identifying the type of object.
* -- cb = total size to allocate (not guaranteed to be zero-filled).
* -- cbHdr = size of header (guaranteed to be zero-filled).
* -- return
*/
_Success_(return != NULL)
PVOID VmmDllCore_MemAllocExternal(_In_ VMM_HANDLE H, _In_ DWORD tag, _In_ SIZE_T cb, _In_ SIZE_T cbHdr)
{
    POB_DATA pObData;
    if((cb > 0x40000000) || (cb < cbHdr)) { return NULL; }
    if(!(pObData = (POB_DATA)Ob_AllocEx(H, tag, 0, cb + sizeof(OB), NULL, NULL))) { return NULL; }
    ZeroMemory(pObData->pb, cbHdr);
    ObMap_Push(g_VMMDLL_ALLOCMAP_EXT, (QWORD)pObData + sizeof(OB), pObData);    // map will INCREF on success
    pObData = Ob_DECREF(pObData);
    return pObData ? pObData->pb : NULL;
}

/*
* Copy internal memory to freshly allocated "external" memory to be free'd only
* by VMMDLL_MemFree // VmmDllCore_MemFreeExternal.
* CALLER VMMDLL_MemFree(return)
* -- H
* -- tag = tag identifying the type of object.
* -- pb = source memory to copy.
* -- cb = size of memory to allocation and copy.
* -- return
*/
_Success_(return != NULL)
PVOID VmmDllCore_MemAllocExternalAndCopy(_In_ VMM_HANDLE H, _In_ DWORD tag, _In_reads_bytes_(cb) PBYTE pb, _In_ SIZE_T cb)
{
    PVOID pv = VmmDllCore_MemAllocExternal(H, tag, cb, 0);
    if(pv) {
        memcpy(pv, pb, cb);
    }
    return pv;
}
