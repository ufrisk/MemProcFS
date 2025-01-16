// vmmlog.c : implementation of the vmm logging functionality.
//
// (c) Ulf Frisk, 2022-2025
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

typedef struct tdVMMLOG_MODULE_MODULEINFO {
    DWORD MID;            // module id
    VMMLOG_LEVEL dwLevelD;  // log level display (other than default)
    VMMLOG_LEVEL dwLevelF;  // log level file    (other than default)
    LPSTR uszName;
} VMMLOG_CONTEXT_MODULEINFO, *PVMMLOG_CONTEXT_MODULEINFO;

typedef struct tdVMMLOG_CONTEXT {
    BOOL fFileFlush;
    FILE* pFile;
    VMMLOG_LEVEL dwLevelD;      // log level display (default)
    VMMLOG_LEVEL dwLevelF;      // log level file    (default)
    VMMLOG_LEVEL dwLevelMID;    // max log level of all module specific overrides
    DWORD iNextMID;             // max MID+1in ModuleInfo
    VMMLOG_CONTEXT_MODULEINFO ModuleInfo[VMMLOG_MID_MODULE_MAX];
    VMMLOG_CONTEXT_MODULEINFO CoreInfo[(MID_MAX & 0x7fffffff) + 1];
} VMMLOG_CONTEXT, *PVMMLOG_CONTEXT;

/*
* Helper function to get a log module info object.
*/
__forceinline PVMMLOG_CONTEXT_MODULEINFO VmmLog_GetModuleInfo(_In_ VMM_HANDLE H, _In_ VMM_MODULE_ID MID)
{
    PVMMLOG_CONTEXT ctxLog = H->log;
    if(!ctxLog) { return NULL; }
    if(MID & 0x80000000) {
        return (MID <= MID_MAX) ? &ctxLog->CoreInfo[MID & 0x7fffffff] : NULL;
    } else {
        return (MID < ctxLog->iNextMID) ? &ctxLog->ModuleInfo[MID] : NULL;
    }
}

/*
* Close and clean-up internal logging data structures.
* This should only be done last at system exit before shut-down.
* -- H
*/
VOID VmmLog_Close(_In_ VMM_HANDLE H)
{
    PVMMLOG_CONTEXT_MODULEINFO pmi;
    VMM_MODULE_ID MID;
    H->logfilter = (DWORD)LOGLEVEL_NONE;
    if(H->log) {
        if(H->log->pFile) {
            fclose(H->log->pFile);
        }
        for(MID = 0; MID < H->log->iNextMID; MID++) {
            if((pmi = VmmLog_GetModuleInfo(H, MID))) {
                LocalFree(pmi->uszName);
            }
        }
        LocalFree(H->log);
        H->log = NULL;
    }
}

/*
* Get the log level for either display (on-screen) or file.
* -- H
* -- MID = specify MID to get specific level override (i.e. not default MID)
* -- fDisplay
* -- return
*/
VMMLOG_LEVEL VmmLog_LevelGet(_In_ VMM_HANDLE H, _In_opt_ VMM_MODULE_ID MID, _In_ BOOL fDisplay)
{
    PVMMLOG_CONTEXT ctxLog = H->log;
    PVMMLOG_CONTEXT_MODULEINFO pmi;
    if(!ctxLog) { return LOGLEVEL_NONE; }
    if(MID) {
        pmi = VmmLog_GetModuleInfo(H, MID);
        if(!pmi) { return LOGLEVEL_NONE; }
        return fDisplay ? pmi->dwLevelD : pmi->dwLevelF;
    } else {
        return fDisplay ? ctxLog->dwLevelD : ctxLog->dwLevelF;
    }
}

/*
* Set the log level for either display (on-screen) or file.
* -- H
* -- MID = specify MID (other than 0) to set specific module level override.
* -- dwLogLevel
* -- fDisplay = TRUE(display), FALSE(file)
* -- fSetOrIncrease = TRUE(set), FALSE(increase)
*/
VOID VmmLog_LevelSet(_In_ VMM_HANDLE H, _In_opt_ VMM_MODULE_ID MID, _In_ VMMLOG_LEVEL dwLogLevel, _In_ BOOL fDisplay, _In_ BOOL fSetOrIncrease)
{
    PVMMLOG_CONTEXT ctxLog = H->log;
    PVMMLOG_CONTEXT_MODULEINFO pmi = NULL;
    if(!ctxLog || (dwLogLevel < 0) || (dwLogLevel > LOGLEVEL_ALL)) { return; }
    if(MID) {
        if(!(pmi = VmmLog_GetModuleInfo(H, MID))) { return; }
        if(fDisplay) {
            pmi->dwLevelD = fSetOrIncrease ? dwLogLevel : max(dwLogLevel, pmi->dwLevelD);
        } else {
            pmi->dwLevelF = fSetOrIncrease ? dwLogLevel : max(dwLogLevel, pmi->dwLevelF);
        }
        // recalculate max log level of all module specific overrides
        if(ctxLog->dwLevelMID <= dwLogLevel) {
            ctxLog->dwLevelMID = max(ctxLog->dwLevelMID, dwLogLevel);
        } else {
            ctxLog->dwLevelMID = 0;
            for(MID = 1; MID < ctxLog->iNextMID; MID++) {
                pmi = VmmLog_GetModuleInfo(H, MID);
                ctxLog->dwLevelMID = max(ctxLog->dwLevelMID, max(pmi->dwLevelD, pmi->dwLevelF));
            }
            for(MID = MID_NA; MID <= MID_MAX; MID++) {
                pmi = VmmLog_GetModuleInfo(H, MID);
                ctxLog->dwLevelMID = max(ctxLog->dwLevelMID, max(pmi->dwLevelD, pmi->dwLevelF));
            }
        }
    } else {
        if(fDisplay) {
            ctxLog->dwLevelD = fSetOrIncrease ? dwLogLevel : max(dwLogLevel, ctxLog->dwLevelD);
        } else {
            ctxLog->dwLevelF = fSetOrIncrease ? dwLogLevel : max(dwLogLevel, ctxLog->dwLevelF);
        }
    }
    H->logfilter = (DWORD)max(ctxLog->dwLevelMID, max(ctxLog->dwLevelD, ctxLog->dwLevelF));
}

/*
* Refresh the display logging settings from settings.
*/
VOID VmmLog_LevelRefresh(_In_ VMM_HANDLE H)
{
    PVMMLOG_CONTEXT ctxLog = H->log;
    VMM_MODULE_ID MID;
    DWORD i;
    PVMMLOG_CONTEXT_MODULEINFO pmi;
    CHAR ch, szModuleName[9], szTokenBuffer[MAX_PATH];
    LPSTR szToken, szTokenInitial, szTokenContext = NULL;
    BOOL fModuleName, fDisplay;
    VMMLOG_LEVEL dwLogLevel;
    // initialize built-in log entries
    if(!ctxLog) {
        H->log = LocalAlloc(LMEM_ZEROINIT, sizeof(VMMLOG_CONTEXT));
        if(!(ctxLog = H->log)) { return; }
        for(MID = MID_NA; MID <= MID_MAX; MID++) {
            pmi = VmmLog_GetModuleInfo(H, MID);
            pmi->MID = MID;
            pmi->uszName = (LPSTR)VMMLOG_MID_STR[MID & 0x7fffffff];
        }
    }
    // clear module overrides (if any):
    for(MID = 1; MID < ctxLog->iNextMID; MID++) {
        pmi = VmmLog_GetModuleInfo(H, MID);
        pmi->dwLevelD = LOGLEVEL_NONE;
        pmi->dwLevelF = LOGLEVEL_NONE;
    }
    for(MID = MID_NA; MID <= MID_MAX; MID++) {
        pmi = VmmLog_GetModuleInfo(H, MID);
        pmi->dwLevelD = LOGLEVEL_NONE;
        pmi->dwLevelF = LOGLEVEL_NONE;
    }
    // legacy settings (use as base settings):
    if(H->cfg.fVerboseDll) {
        VmmLog_LevelSet(H, 0, LOGLEVEL_INFO, TRUE, FALSE);
        if(H->cfg.fVerbose) { VmmLog_LevelSet(H, 0, LOGLEVEL_VERBOSE, TRUE, FALSE); }
        if(H->cfg.fVerboseExtra) { VmmLog_LevelSet(H, 0, LOGLEVEL_DEBUG, TRUE, FALSE); }
        if(H->cfg.fVerboseExtraTlp) { VmmLog_LevelSet(H, 0, LOGLEVEL_TRACE, TRUE, FALSE); }
    } else {
        VmmLog_LevelSet(H, 0, LOGLEVEL_NONE, TRUE, FALSE);
    }
    // open file (if log file specified and file handle not already open):
    if(H->cfg.szLogFile[0] && !ctxLog->pFile) {
        ctxLog->pFile = _fsopen(H->cfg.szLogFile, "a", 0x20 /* _SH_DENYWR */);
    }
    ctxLog->dwLevelF = ctxLog->pFile ? ctxLog->dwLevelD : LOGLEVEL_NONE;
    // new settings (specified in -loglevel parameter):
    if(!H->cfg.szLogLevel[0]) { return; }
    strncpy_s(szTokenBuffer, sizeof(szTokenBuffer), H->cfg.szLogLevel, _TRUNCATE);
    szTokenInitial = szTokenBuffer;
    while((szToken = strtok_s(szTokenInitial, ",", &szTokenContext))) {
        szTokenInitial = NULL;
        fModuleName = FALSE;
        // parse file flush option (if any):
        if(!_stricmp(szToken, "fflush")) {
            ctxLog->fFileFlush = TRUE;
            continue;
        }
        // parse file or display (default):
        if((szToken[0] == 'f') && (szToken[1] == ':')) {
            if(!ctxLog->pFile) { continue; }
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
            for(MID = 1; MID < ctxLog->iNextMID; MID++) {
                pmi = VmmLog_GetModuleInfo(H, MID);
                if(pmi->uszName && !_stricmp(pmi->uszName, szModuleName)) {
                    // parse log level & apply:
                    if((szToken[0] >= '0') && (szToken[0] <= '7') && (szToken[1] == 0)) {
                        dwLogLevel = szToken[0] - '0';
                        VmmLog_LevelSet(H, MID, dwLogLevel, fDisplay, TRUE);
                    }
                }
            }
            for(MID = MID_NA; MID <= MID_MAX; MID++) {
                pmi = VmmLog_GetModuleInfo(H, MID);
                if(pmi->uszName && !_stricmp(pmi->uszName, szModuleName)) {
                    // parse log level & apply:
                    if((szToken[0] >= '0') && (szToken[0] <= '7') && (szToken[1] == 0)) {
                        dwLogLevel = szToken[0] - '0';
                        VmmLog_LevelSet(H, MID, dwLogLevel, fDisplay, TRUE);
                    }
                }
            }
        } else {
            // parse log level & apply:
            if((szToken[0] >= '0') && (szToken[0] <= '7') && (szToken[1] == 0)) {
                dwLogLevel = szToken[0] - '0';
                VmmLog_LevelSet(H, 0, dwLogLevel, fDisplay, TRUE);
            }
        }
    }
}

/*
* Register a new module ID (MID) with the log database.
* This function should be called in a single-threaded context by the plugin manager.
* -- H
* -- MID = the module ID (MID) to register
* -- uszModuleName
* -- fExternal = externally loaded module (dll/so).
*/
VOID VmmLog_RegisterModule(_In_ VMM_HANDLE H, _In_ VMM_MODULE_ID MID, _In_ LPCSTR uszModuleName, _In_ BOOL fExternal)
{
    PVMMLOG_CONTEXT_MODULEINFO pmi;
    if(!H->log) { return; }
    if(MID >= VMMLOG_MID_MODULE_MAX) { return; }
    pmi = H->log->ModuleInfo + MID;
    if(pmi->uszName) {
        LocalFree(pmi->uszName);
        ZeroMemory(pmi, sizeof(VMMLOG_CONTEXT_MODULEINFO));
    }
    if(CharUtil_UtoU(uszModuleName, 8, NULL, 0, &pmi->uszName, NULL, CHARUTIL_FLAG_ALLOC)) {
        pmi->MID = MID;
        H->log->iNextMID = MID + 1;
    }
}

/*
* Log a message "printf" style. Whether the message is displayed and/or saved
* to log file depends on the internal logging setup.
* -- H
* -- MID = module ID (MID)
* -- dwLogLevel = log level as defined by LOGLEVEL_*
* -- uszFormat
* -- ...
*/
VOID VmmLogEx(_In_ VMM_HANDLE H, _In_ VMM_MODULE_ID MID, _In_ VMMLOG_LEVEL dwLogLevel, _In_z_ _Printf_format_string_ LPCSTR uszFormat, ...)
{
    va_list arglist;
    va_start(arglist, uszFormat);
    VmmLogEx2(H, MID, dwLogLevel, uszFormat, arglist);
    va_end(arglist);
}

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
VOID VmmLogHexAsciiEx(_In_ VMM_HANDLE H, _In_ VMM_MODULE_ID MID, _In_ VMMLOG_LEVEL dwLogLevel, _In_reads_(cb) PBYTE pb, _In_ DWORD cb, _In_ DWORD cbInitialOffset, _In_z_ _Printf_format_string_ LPCSTR uszFormat, ...)
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
    VmmLogEx2(H, MID, dwLogLevel, usz, arglist);
    va_end(arglist);
    LocalFree(usz);
}

/*
* Check whether the MID/LogLevel will log to any output.
* -- H
* -- MID = module ID (MID)
* -- dwLogLevel = log level as defined by LOGLEVEL_*
* -- return = TRUE(will log), FALSE(will NOT log).
*/
BOOL VmmLogIsActive(_In_ VMM_HANDLE H, _In_ VMM_MODULE_ID MID, _In_ VMMLOG_LEVEL dwLogLevel)
{
    PVMMLOG_CONTEXT ctxLog = H->log;
    PVMMLOG_CONTEXT_MODULEINFO pmi;
    BOOL fD = FALSE, fF = FALSE;
    if(!ctxLog) { return FALSE; }
    // sanity checks, get module info object and check if logs should happen to display/file:
    if((dwLogLevel < LOGLEVEL_NONE) || (dwLogLevel > LOGLEVEL_ALL) || (dwLogLevel > (VMMLOG_LEVEL)H->logfilter)) { return FALSE; }
    if(!(pmi = VmmLog_GetModuleInfo(H, MID))) { return FALSE; }
    fD = ((dwLogLevel <= ctxLog->dwLevelD) || (dwLogLevel <= pmi->dwLevelD));                       // log to display
    fF = ((dwLogLevel <= ctxLog->dwLevelF) || (dwLogLevel <= pmi->dwLevelF)) && ctxLog->pFile;      // log to file
    return fD || fF;
}

/*
* Log a message using a va_list. Whether the message is displayed and/or saved
* to log file depends on the internal logging setup.
* -- H
* -- MID = module ID (MID)
* -- dwLogLevel = log level as defined by LOGLEVEL_*
* -- uszFormat
* -- arglist
*/
VOID VmmLogEx2(_In_ VMM_HANDLE H, _In_ VMM_MODULE_ID MID, _In_ VMMLOG_LEVEL dwLogLevel, _In_z_ _Printf_format_string_ LPCSTR uszFormat, va_list arglist)
{
    PVMMLOG_CONTEXT ctxLog = H->log;
    PVMMLOG_CONTEXT_MODULEINFO pmi;
    BOOL fD = FALSE, fF = FALSE;
    CHAR uszBufferSmall[3 * MAX_PATH];
    CHAR szHead[11], szTime[24];
    LPSTR uszBuffer = uszBufferSmall;
    DWORD cchBuffer = sizeof(uszBufferSmall);
    DWORD i = 0, cchFormat;
    int cch;
    if(!ctxLog) { return; }
    // sanity checks, get module info object and check if logs should happen to display/file:
    if((dwLogLevel < LOGLEVEL_NONE) || (dwLogLevel > LOGLEVEL_ALL) || (dwLogLevel > (VMMLOG_LEVEL)H->logfilter)) { return; }
    if(!(pmi = VmmLog_GetModuleInfo(H, MID))) { return; }
    fD = ((dwLogLevel <= ctxLog->dwLevelD) || (dwLogLevel <= pmi->dwLevelD));                    // log to display
    fF = ((dwLogLevel <= ctxLog->dwLevelF) || (dwLogLevel <= pmi->dwLevelF)) && ctxLog->pFile;    // log to file
    if(!fD && !fF) { return; }
    // create message part of the log (allocate buffer if required)
    cch = _vsnprintf_s(uszBuffer, cchBuffer, _TRUNCATE, uszFormat, arglist);
    if((cch < 0) || ((SIZE_T)cch > sizeof(uszBufferSmall) - 2)) {
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
        fflush(stdout);
    }
    // log to file
    if(fF) {
        Util_FileTime2String(Util_FileTimeNow(), szTime);
        fprintf(ctxLog->pFile, "%s %s %-10s %s\n", szTime, VMMLOG_LEVEL_STR[dwLogLevel], szHead, uszBuffer);
        if(ctxLog->fFileFlush) {
            fflush(ctxLog->pFile);
        }
    }
    // cleanup
    if(uszBuffer != uszBufferSmall) { LocalFree(uszBuffer); }
}
