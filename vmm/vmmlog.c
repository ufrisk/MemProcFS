// vmmlog.c : implementation of the vmm logging functionality.
//
// (c) Ulf Frisk, 2022
// Author: Ulf Frisk, pcileech@frizk.net
//
#include "vmmlog.h"
#include "charutil.h"
#include "util.h"

#define VMMLOG_MID_MODULE_MAX           128

static LPCSTR VMMLOG_LEVEL_STR[] = {
    "NONE",
    "CRIT",
    "WARN",
    "INFO",
    "VERB",
    "DBG ",
    "TRCE",
    "ALL "
};

// max 8 chars long!
static LPCSTR VMMLOG_MID_STR[] = {
    "N/A",
    // externally exposed built-in modules:
    "MAIN",
    "PYTHON",
    "N/A", "N/A", "N/A", "N/A", "N/A", "N/A", "N/A", "N/A", "N/A", "N/A", "N/A", "N/A", "N/A",
    // vmm internal built-in module:
    "CORE",
    "VMMDLL",
    "VMM",
    "PROCESS",
    "FORENSIC",
    "REGISTRY",
    "PLUGIN",
    "NET",
    "PE",
    "PDB",
    "INFODB"
};

typedef struct tdVMMLOG_MODULE_MODULEINFO {
    DWORD dwMID;            // module id
    VMMLOG_LEVEL dwLevelD;  // log level display (other than default)
    VMMLOG_LEVEL dwLevelF;  // log level file    (other than default)
    LPSTR uszName;
} VMMLOG_CONTEXT_MODULEINFO, *PVMMLOG_CONTEXT_MODULEINFO;

typedef struct tdVMMLOG_CONTEXT {
    BOOL fInitialized;
    FILE* pFile;
    VMMLOG_LEVEL dwLevelD;      // log level display (default)
    VMMLOG_LEVEL dwLevelF;      // log level file    (default)
    VMMLOG_LEVEL dwLevelMID;    // max log level of all module specific overrides
    DWORD iModuleNameNext;
    VMMLOG_CONTEXT_MODULEINFO ModuleInfo[VMMLOG_MID_MODULE_MAX];
    VMMLOG_CONTEXT_MODULEINFO CoreInfo[(MID_MAX & 0x7fffffff) + 1];
} VMMLOG_CONTEXT;

VMMLOG_CONTEXT ctxLog = { 0 };
VMMLOG_LEVEL g_VmmLogLevelFilter = LOGLEVEL_NONE;

/*
* Helper function to get a log module info object.
*/
inline PVMMLOG_CONTEXT_MODULEINFO VmmLog_GetModuleInfo(_In_ DWORD dwMID)
{
    if(dwMID & 0x80000000) {
        return (dwMID <= MID_MAX) ? &ctxLog.CoreInfo[dwMID & 0x7fffffff] : NULL;
    } else {
        return (dwMID < ctxLog.iModuleNameNext) ? &ctxLog.ModuleInfo[dwMID] : NULL;
    }
}

/*
* Close and clean-up internal logging data structures.
*/
VOID VmmLog_Close()
{
    DWORD dwMID;
    PVMMLOG_CONTEXT_MODULEINFO pmi;
    g_VmmLogLevelFilter = LOGLEVEL_NONE;
    if(ctxLog.pFile) {
        fclose(ctxLog.pFile);
        ctxLog.pFile = NULL;
    }
    for(dwMID = 1; dwMID < ctxLog.iModuleNameNext; dwMID++) {
        pmi = VmmLog_GetModuleInfo(dwMID);
        LocalFree(pmi->uszName);
    }
    ZeroMemory(&ctxLog, sizeof(VMMLOG_CONTEXT));
}

/*
* Get the log level for either display (on-screen) or file.
* -- dwMID = specify MID to get specific level override (i.e. not default MID)
* -- fDisplay
* -- return
*/
VMMLOG_LEVEL VmmLog_LevelGet(_In_opt_ DWORD dwMID, _In_ BOOL fDisplay)
{
    PVMMLOG_CONTEXT_MODULEINFO pmi;
    if(dwMID) {
        pmi = VmmLog_GetModuleInfo(dwMID);
        if(!pmi) { return LOGLEVEL_NONE; }
        return fDisplay ? pmi->dwLevelD : pmi->dwLevelF;
    } else {
        return fDisplay ? ctxLog.dwLevelD : ctxLog.dwLevelF;
    }
}

/*
* Set the log level for either display (on-screen) or file.
* -- dwMID = specify MID (other than 0) to set specific module level override.
* -- dwLogLevel
* -- fDisplay = TRUE(display), FALSE(file)
* -- fSetOrIncrease = TRUE(set), FALSE(increase)
*/
VOID VmmLog_LevelSet(_In_opt_ DWORD dwMID, _In_ VMMLOG_LEVEL dwLogLevel, _In_ BOOL fDisplay, _In_ BOOL fSetOrIncrease)
{
    PVMMLOG_CONTEXT_MODULEINFO pmi = NULL;
    if((dwLogLevel < 0) || (dwLogLevel > LOGLEVEL_ALL)) { return; }
    if(dwMID) {
        if(!(pmi = VmmLog_GetModuleInfo(dwMID))) { return; }
        if(fDisplay) {
            pmi->dwLevelD = fSetOrIncrease ? dwLogLevel : max(dwLogLevel, pmi->dwLevelD);
        } else {
            pmi->dwLevelF = fSetOrIncrease ? dwLogLevel : max(dwLogLevel, pmi->dwLevelF);
        }
        // recalculate max log level of all module specific overrides
        if(ctxLog.dwLevelMID <= dwLogLevel) {
            ctxLog.dwLevelMID = max(ctxLog.dwLevelMID, dwLogLevel);
        } else {
            ctxLog.dwLevelMID = 0;
            for(dwMID = 1; dwMID < ctxLog.iModuleNameNext; dwMID++) {
                pmi = VmmLog_GetModuleInfo(dwMID);
                ctxLog.dwLevelMID = max(ctxLog.dwLevelMID, max(pmi->dwLevelD, pmi->dwLevelF));
            }
            for(dwMID = MID_NA; dwMID <= MID_MAX; dwMID++) {
                pmi = VmmLog_GetModuleInfo(dwMID);
                ctxLog.dwLevelMID = max(ctxLog.dwLevelMID, max(pmi->dwLevelD, pmi->dwLevelF));
            }
        }
    } else {
        if(fDisplay) {
            ctxLog.dwLevelD = fSetOrIncrease ? dwLogLevel : max(dwLogLevel, ctxLog.dwLevelD);
        } else {
            ctxLog.dwLevelF = fSetOrIncrease ? dwLogLevel : max(dwLogLevel, ctxLog.dwLevelF);
        }
    }
    g_VmmLogLevelFilter = max(ctxLog.dwLevelMID, max(ctxLog.dwLevelD, ctxLog.dwLevelF));
}

/*
* Refresh the display logging settings from settings.
*/
VOID VmmLog_LevelRefresh()
{
    DWORD i, dwMID, dwTokenMID;
    PVMMLOG_CONTEXT_MODULEINFO pmi;
    CHAR ch, szModuleName[9], szTokenBuffer[MAX_PATH];
    LPSTR szToken, szTokenInitial, szTokenContext = NULL;
    BOOL fModuleName, fDisplay;
    VMMLOG_LEVEL dwLogLevel;
    // initialize built-in log entries
    if(!ctxLog.fInitialized) {
        for(dwMID = MID_NA; dwMID <= MID_MAX; dwMID++) {
            pmi = VmmLog_GetModuleInfo(dwMID);
            pmi->dwMID = dwMID;
            pmi->uszName = (LPSTR)VMMLOG_MID_STR[dwMID & 0x7fffffff];
        }
        ctxLog.fInitialized = TRUE;
    }
    // clear module overrides (if any):
    for(dwMID = 1; dwMID < ctxLog.iModuleNameNext; dwMID++) {
        pmi = VmmLog_GetModuleInfo(dwMID);
        pmi->dwLevelD = LOGLEVEL_NONE;
        pmi->dwLevelF = LOGLEVEL_NONE;
    }
    for(dwMID = MID_NA; dwMID <= MID_MAX; dwMID++) {
        pmi = VmmLog_GetModuleInfo(dwMID);
        pmi->dwLevelD = LOGLEVEL_NONE;
        pmi->dwLevelF = LOGLEVEL_NONE;
    }
    // legacy settings (use as base settings):
    if(ctxMain->cfg.fVerboseDll) {
        VmmLog_LevelSet(0, LOGLEVEL_INFO, TRUE, FALSE);
        if(ctxMain->cfg.fVerbose) { VmmLog_LevelSet(0, LOGLEVEL_VERBOSE, TRUE, FALSE); }
        if(ctxMain->cfg.fVerboseExtra) { VmmLog_LevelSet(0, LOGLEVEL_DEBUG, TRUE, FALSE); }
        if(ctxMain->cfg.fVerboseExtraTlp) { VmmLog_LevelSet(0, LOGLEVEL_TRACE, TRUE, FALSE); }
    } else {
        VmmLog_LevelSet(0, LOGLEVEL_NONE, TRUE, FALSE);
    }
    // open file (if log file specified and file handle not already open):
    if(ctxMain->cfg.szLogFile[0] && !ctxLog.pFile) {
        ctxLog.pFile = _fsopen(ctxMain->cfg.szLogFile, "a", 0x20 /* _SH_DENYWR */);
    }
    ctxLog.dwLevelF = ctxLog.pFile ? ctxLog.dwLevelD : LOGLEVEL_NONE;
    // new settings (specified in -loglevel parameter):
    if(!ctxMain->cfg.szLogLevel[0]) { return; }
    strncpy_s(szTokenBuffer, sizeof(szTokenBuffer), ctxMain->cfg.szLogLevel, _TRUNCATE);
    szTokenInitial = szTokenBuffer;
    while((szToken = strtok_s(szTokenInitial, ",", &szTokenContext))) {
        szTokenInitial = NULL;
        dwTokenMID = 0;
        fModuleName = FALSE;
        // parse file or display (default):
        if((szToken[0] == 'f') && (szToken[1] == ':')) {
            if(!ctxLog.pFile) { continue; }
            fDisplay = FALSE;
            szToken += 2;
        } else {
            fDisplay = TRUE;
        }
        // parse module id (MID) (0 = default):
        i = 0;
        while(TRUE) {
            ch = szToken[i];
            if(ch == 0) { break; };
            if(ch == ':') {
                szToken += i + (SIZE_T)1;
                szModuleName[min(8, i)] = 0;
                fModuleName = TRUE;
                break;
            }
            if(i < 8) {
                szModuleName[i] = ch;
            }
            i++;
        } 
        if(fModuleName) {
            for(dwMID = 1; dwMID < ctxLog.iModuleNameNext; dwMID++) {
                pmi = VmmLog_GetModuleInfo(dwMID);
                if(pmi->uszName && !strcmp(pmi->uszName, szModuleName)) {
                    dwTokenMID = dwMID;
                    break;
                }
            }
            for(dwMID = MID_NA; dwMID <= MID_MAX; dwMID++) {
                pmi = VmmLog_GetModuleInfo(dwMID);
                if(pmi->uszName && !strcmp(pmi->uszName, szModuleName)) {
                    dwTokenMID = dwMID;
                    break;
                }
            }
            if(!dwTokenMID) { return; }
        }
        // parse log level & apply:
        if((szToken[0] >= '0') && (szToken[0] <= '7') && (szToken[1] == 0)) {
            dwLogLevel = szToken[0] - '0';
            VmmLog_LevelSet(dwTokenMID, dwLogLevel, fDisplay, TRUE);
        }
    }
}

/*
* Register a new module ID (MID) with the log database.
* This function should be called in a single-threaded context by the plugin manager.
* -- dwMID = the module ID (MID) to register
* -- uszModuleName
* -- fExternal = externally loaded module (dll/so).
*/
VOID VmmLog_RegisterModule(_In_ DWORD dwMID, _In_ LPSTR uszModuleName, _In_ BOOL fExternal)
{
    PVMMLOG_CONTEXT_MODULEINFO pmi;
    if(dwMID >= VMMLOG_MID_MODULE_MAX) { return; }
    if(ctxLog.iModuleNameNext == VMMLOG_MID_MODULE_MAX) { return; }
    pmi = ctxLog.ModuleInfo + dwMID;
    if(pmi->uszName) {
        LocalFree(pmi->uszName);
        ZeroMemory(pmi, sizeof(VMMLOG_CONTEXT_MODULEINFO));
    }
    if(CharUtil_UtoU(uszModuleName, 8, NULL, 0, &pmi->uszName, NULL, CHARUTIL_FLAG_ALLOC)) {
        ctxLog.iModuleNameNext++;
    }
    pmi->dwMID = dwMID;
}

/*
* Log a message "printf" style. Whether the message is displayed and/or saved
* to log file depends on the internal logging setup.
* -- dwMID = module ID (MID)
* -- dwLogLevel = log level as defined by LOGLEVEL_*
* -- uszFormat
* -- ...
*/
VOID VmmLogEx(_In_ DWORD dwMID, _In_ VMMLOG_LEVEL dwLogLevel, _In_z_ _Printf_format_string_ LPSTR uszFormat, ...)
{
    va_list arglist;
    va_start(arglist, uszFormat);
    VmmLogEx2(dwMID, dwLogLevel, uszFormat, arglist);
    va_end(arglist);
}

/*
* Log a message "printf" style followed by a hexascii printout.
* -- dwMID = module ID (MID)
* -- dwLogLevel = log level as defined by LOGLEVEL_*
* -- pb = binary to log
* -- cb = size of binary to log
* -- cbInitialOffset
* -- uszFormat
* -- ...
*/
VOID VmmLogHexAsciiEx(_In_ DWORD dwMID, _In_ VMMLOG_LEVEL dwLogLevel, _In_reads_(cb) PBYTE pb, _In_ DWORD cb, _In_ DWORD cbInitialOffset, _In_z_ _Printf_format_string_ LPSTR uszFormat, ...)
{
    LPSTR usz;
    va_list arglist;
    DWORD cchHexAscii = 0;
    SIZE_T i, cchTotal, cchFormat = strlen(uszFormat);
    // 1: cap at first 65k (if required)
    if(cb > 0x10000) { cb = 0x10000 - cbInitialOffset; }
    // 2: create extended format string with hexascii at the end
    Util_FillHexAscii(pb, cb, cbInitialOffset, NULL, &cchHexAscii);
    cchTotal = cchFormat + 1 + cchHexAscii;
    if(!(usz = LocalAlloc(0, cchTotal))) { return; }
    strcpy_s(usz, cchFormat + 1, uszFormat);
    usz[cchFormat] = '\n';
    Util_FillHexAscii(pb, cb, cbInitialOffset, usz + cchFormat + 1, &cchHexAscii);
    // 3: replace any '%' in hexascii text
    for(i = cchFormat; i < cchTotal; i++) {
        if(usz[i] == '%') { usz[i] = '.'; }
    }
    if(cchTotal > 2) {
        usz[cchTotal - 2] = 0;
    }
    // 4: log
    va_start(arglist, uszFormat);
    VmmLogEx2(dwMID, dwLogLevel, usz, arglist);
    va_end(arglist);
    LocalFree(usz);
}

/*
* Log a message using a va_list. Whether the message is displayed and/or saved
* to log file depends on the internal logging setup.
* -- dwMID = module ID (MID)
* -- dwLogLevel = log level as defined by LOGLEVEL_*
* -- uszFormat
* -- arglist
*/
VOID VmmLogEx2(_In_ DWORD dwMID, _In_ VMMLOG_LEVEL dwLogLevel, _In_z_ _Printf_format_string_ LPSTR uszFormat, va_list arglist)
{
    PVMMLOG_CONTEXT_MODULEINFO pmi;
    BOOL fD = FALSE, fF = FALSE;
    CHAR uszBufferSmall[3 * MAX_PATH];
    CHAR szHead[11], szTime[24];
    LPSTR uszBuffer = uszBufferSmall;
    DWORD cchBuffer = sizeof(uszBufferSmall);
    DWORD i = 0, cchFormat;
    int cch;
    // sanity checks, get module info object and check if logs should happen to display/file:
    if((dwLogLevel < LOGLEVEL_NONE) || (dwLogLevel > LOGLEVEL_ALL) || (dwLogLevel > g_VmmLogLevelFilter)) { return; }
    if(!(pmi = VmmLog_GetModuleInfo(dwMID))) { return; }
    fD = ((dwLogLevel <= ctxLog.dwLevelD) || (dwLogLevel <= pmi->dwLevelD));                    // log to displayh
    fF = ((dwLogLevel <= ctxLog.dwLevelF) || (dwLogLevel <= pmi->dwLevelF)) && ctxLog.pFile;    // log to file
    if(!fD && !fF) { return; }
    // create message part of the log (allocate buffer if required)
    cch = _vsnprintf_s(uszBuffer, cchBuffer, _TRUNCATE, uszFormat, arglist);
    if((cch < 0) || (cch > sizeof(uszBufferSmall) - 2)) {
        cchFormat = (DWORD)strlen(uszFormat);
        cchBuffer = cchFormat + 3 * MAX_PATH;
        uszBuffer = LocalAlloc(0, cchBuffer);
        if(!uszBuffer) { return; }
        _vsnprintf_s(uszBuffer, cchBuffer, _TRUNCATE, uszFormat, arglist);
    }
    // construct log module name (used in both display/file logging)
    szHead[0] = '[';
    while(pmi->uszName[i++]) {
        szHead[i] = pmi->uszName[i - 1];
    }
    szHead[i++] = ']';
    szHead[i++] = 0;
    // log to display
    if(fD) {
        printf("%-10s %s\n", szHead, uszBuffer);
    }
    // log to file
    if(fF) {
        Util_FileTime2String(Util_FileTimeNow(), szTime);
        fprintf(ctxLog.pFile, "%s %s %-10s %s\n", szTime, VMMLOG_LEVEL_STR[dwLogLevel], szHead, uszBuffer);
    }
    // cleanup
    if(uszBuffer != uszBufferSmall) { LocalFree(uszBuffer); }
}
