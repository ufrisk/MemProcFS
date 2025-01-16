// vmmlog.h : definitions of the vmm logging functionality.
//
// (c) Ulf Frisk, 2022-2025
// Author: Ulf Frisk, pcileech@frizk.net
//
#ifndef __VMMLOG_H__
#define __VMMLOG_H__
#include "vmm.h"

typedef DWORD                       VMM_MODULE_ID;

typedef enum tdVMMLOG_LEVEL {
    LOGLEVEL_NONE       = 0, // do not use!
    LOGLEVEL_0_NONE     = 0,
    LOGLEVEL_CRITICAL   = 1, // critical stopping error
    LOGLEVEL_1_CRITICAL = 1,
    LOGLEVEL_WARNING    = 2, // severe warning error
    LOGLEVEL_2_WARNING  = 2,
    LOGLEVEL_INFO       = 3, // normal message
    LOGLEVEL_3_INFO     = 3,
    LOGLEVEL_VERBOSE    = 4, // verbose message (visible with -v)
    LOGLEVEL_4_VERBOSE  = 4,
    LOGLEVEL_DEBUG      = 5, // debug message (visible with -vv)
    LOGLEVEL_5_DEBUG    = 5,
    LOGLEVEL_TRACE      = 6, // trace message
    LOGLEVEL_6_TRACE    = 6,
    LOGLEVEL_ALL        = 7, // do not use!
    LOGLEVEL_7_ALL      = 7,
} VMMLOG_LEVEL;

// NB! also update VMMLOG_MID_STR when adding new built-in types.
#define MID_NA           0x80000000
// externally exposed built-in modules:
#define MID_MAIN         0x80000001
#define MID_PYTHON       0x80000002
#define MID_DEBUG        0x80000003
#define MID_RUST         0x80000004
// vmm internal built-in modules:
#define MID_CORE         0x80000010
#define MID_API          0x80000011
#define MID_VMM          0x80000012
#define MID_PROCESS      0x80000013
#define MID_FORENSIC     0x80000014
#define MID_REGISTRY     0x80000015
#define MID_PLUGIN       0x80000016
#define MID_NET          0x80000017
#define MID_PE           0x80000018
#define MID_SYMBOL       0x80000019
#define MID_INFODB       0x8000001a
#define MID_HEAP         0x8000001b
#define MID_OFFSET       0x8000001c
#define MID_EVIL         0x8000001d
#define MID_OBJECT       0x8000001e
#define MID_VM           0x8000001f
#define MID_MODULE       0x80000020
#define MID_POOL         0x80000021
#define MID_THREAD       0x80000022
#define MID_THREADCS     0x80000023
#define MID_MAX          0x80000023

static LPCSTR VMMLOG_MID_STR[] = {
    [MID_NA       & 0xFF] = "N/A",
    // externally exposed built-in modules:
    [MID_MAIN     & 0xFF] = "MAIN",
    [MID_PYTHON   & 0xFF] = "PYTHON",
    [MID_DEBUG    & 0xFF] = "DEBUG",
    [MID_RUST     & 0xFF] = "RUST",
    [0x05               ] = "N/A",
    [0x06               ] = "N/A",
    [0x07               ] = "N/A",
    [0x08               ] = "N/A",
    [0x09               ] = "N/A",
    [0x0A               ] = "N/A",
    [0x0B               ] = "N/A",
    [0x0C               ] = "N/A",
    [0x0D               ] = "N/A",
    [0x0E               ] = "N/A",
    [0x0F               ] = "N/A",
    // vmm internal built-in modules:
    [MID_CORE     & 0xFF] = "CORE",
    [MID_API      & 0xFF] = "API",
    [MID_VMM      & 0xFF] = "VMM",
    [MID_PROCESS  & 0xFF] = "PROCESS",
    [MID_FORENSIC & 0xFF] = "FORENSIC",
    [MID_REGISTRY & 0xFF] = "REGISTRY",
    [MID_PLUGIN   & 0xFF] = "PLUGIN",
    [MID_NET      & 0xFF] = "NET",
    [MID_PE       & 0xFF] = "PE",
    [MID_SYMBOL   & 0xFF] = "SYMBOL",
    [MID_INFODB   & 0xFF] = "INFODB",
    [MID_HEAP     & 0xFF] = "HEAP",
    [MID_OFFSET   & 0xFF] = "OFFSET",
    [MID_EVIL     & 0xFF] = "EVIL",
    [MID_OBJECT   & 0xFF] = "OBJECT",
    [MID_VM       & 0xFF] = "VM",
    [MID_MODULE   & 0xFF] = "MODULE",
    [MID_POOL     & 0xFF] = "POOL",
    [MID_THREAD   & 0xFF] = "THREAD",
    [MID_THREADCS & 0xFF] = "THREADCS",
};

/*
* Refresh the display logging settings from settings.
* NB! This function must be called at least once _before_ logging anything!
* -- H
*/
VOID VmmLog_LevelRefresh(_In_ VMM_HANDLE H);

/*
* Close and clean-up internal logging data structures.
* This should only be done last at system exit before shut-down.
* -- H
*/
VOID VmmLog_Close(_In_ VMM_HANDLE H);

/*
* Get the log level for either display (on-screen) or file.
* -- H
* -- MID = specify MID (other than 0) to get specific module level override.
* -- fDisplay
* -- return
*/
VMMLOG_LEVEL VmmLog_LevelGet(_In_ VMM_HANDLE H, _In_opt_ VMM_MODULE_ID MID, _In_ BOOL fDisplay);

/*
* Set the log level for either display (on-screen) or file.
* -- H
* -- MID = specify MID (other than 0) to set specific module level override.
* -- dwLogLevel
* -- fDisplay = TRUE(display), FALSE(file)
* -- fSetOrIncrease = TRUE(set), FALSE(increase)
*/
VOID VmmLog_LevelSet(_In_ VMM_HANDLE H, _In_opt_ VMM_MODULE_ID MID, _In_ VMMLOG_LEVEL dwLogLevel, _In_ BOOL fDisplay, _In_ BOOL fSetOrIncrease);

/*
* Register a new module ID (MID) with the log database.
* This function should be called in a single-threaded context by the plugin manager.
* -- H
* -- MID = the module ID (MID) to register
* -- uszModuleName
* -- fExternal = externally loaded module (dll/so).
*/
VOID VmmLog_RegisterModule(_In_ VMM_HANDLE H, _In_ VMM_MODULE_ID MID, _In_ LPCSTR uszModuleName, _In_ BOOL fExternal);

/*
* Check whether the MID/LogLevel will log to any output.
* -- H
* -- MID = module ID (MID)
* -- dwLogLevel = log level as defined by LOGLEVEL_*
* -- return = TRUE(will log), FALSE(will NOT log).
*/
BOOL VmmLogIsActive(_In_ VMM_HANDLE H, _In_ VMM_MODULE_ID MID, _In_ VMMLOG_LEVEL dwLogLevel);

/*
* Log a message "printf" style followed by a hexascii printout.
* -- H
* -- MID = module ID (MID)
* -- dwLogLevel = log level as defined by LOGLEVEL_*
* -- pb = binary to log
* -- cb = size of binary to log
* -- cbInitialOffset
* -- uszFormat
* -- ...
*/
VOID VmmLogHexAsciiEx(
    _In_ VMM_HANDLE H,
    _In_ VMM_MODULE_ID MID,
    _In_ VMMLOG_LEVEL dwLogLevel,
    _In_reads_(cb) PBYTE pb,
    _In_ DWORD cb,
    _In_ DWORD cbInitialOffset,
    _In_z_ _Printf_format_string_ LPCSTR uszFormat,
    ...
);

/*
* Log a message "printf" style. Whether the message is displayed and/or saved
* to log file depends on the internal logging setup.
* -- H
* -- MID = module ID (MID)
* -- dwLogLevel = log level as defined by LOGLEVEL_*
* -- uszFormat
* -- ...
*/
VOID VmmLogEx(_In_ VMM_HANDLE H, _In_ VMM_MODULE_ID MID, _In_ VMMLOG_LEVEL dwLogLevel, _In_z_ _Printf_format_string_ LPCSTR uszFormat, ...);

/*
* Log a message using a va_list. Whether the message is displayed and/or saved
* to log file depends on the internal logging setup.
* -- H
* -- MID = module ID (MID)
* -- dwLogLevel = log level as defined by LOGLEVEL_*
* -- uszFormat
* -- arglist
*/
VOID VmmLogEx2(_In_ VMM_HANDLE H, _In_ VMM_MODULE_ID MID, _In_ VMMLOG_LEVEL dwLogLevel, _In_z_ _Printf_format_string_ LPCSTR uszFormat, va_list arglist);

/*
* Log amessage "printf" style.
* -- H
* -- MID
* -- dwLogLevel
* -- format
* -- ...
*/
#define VmmLog(H, MID, dwLogLevel, format, ...)          { if(dwLogLevel <= (VMMLOG_LEVEL)H->logfilter) { VmmLogEx(H, MID, dwLogLevel, format, ##__VA_ARGS__); } }

/*
* printf a message to the console if allowed (i.e. not suppressed in a dll context).
* NB! VmmLog* functions are preferred if possible!
*/
#define vmmprintf(H, format, ...)          { if(H->cfg.fVerboseDll)       { printf(format, ##__VA_ARGS__); } }

#endif /* __VMMLOG_H__ */
