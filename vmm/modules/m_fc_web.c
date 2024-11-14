// m_fc_web.c : web browsing forensic module.
// 
// Module supports:
//  - Brave
//  - Google Chrome
//  - Microsoft Edge (Chromium based)
//  - Mozilla Firefox
//
// (c) Ulf Frisk, 2022-2024
// Author: Ulf Frisk, pcileech@frizk.net
//

#include "modules.h"
#include "../ext/sqlite3.h"
#include "../vmmwinobj.h"

LPSTR szMWEB_README =
"Web plugin for MemProcFS:                                                   \n" \
"=========================                                                   \n" \
"                                                                            \n" \
"The web plugin tries to recover select web activity from supported browsers.\n" \
"Supported browsers: Chrome, Edge, Firefox.                                  \n" \
"                                                                            \n" \
"The plugin does not recover all activities. Activities such as Cookies,     \n" \
"Favicons and Form fill data is currently not recovered.                     \n" \
"                                                                            \n" \
"The plugin tries to recover data on a best-effort and recovery may fail.    \n" \
"---                                                                         \n" \
"Documentation: https://github.com/ufrisk/MemProcFS/wiki/FS_Web              \n";

#define MWEB_LINELENGTH_BASE    59ULL
#define MWEB_LINEHEADER         "     #    PID                    Time  Browser Type     Url :: Info"

typedef enum tdVMM_MAP_WEB_TPACTION {
    VMM_MAP_WEB_TPACTION_NA         = 0,
    VMM_MAP_WEB_TPACTION_BROWSE     = 1,
    VMM_MAP_WEB_TPACTION_DOWNLOAD   = 2,
    VMM_MAP_WEB_TPACTION_LOGIN_PWD  = 3
} VMM_MAP_WEB_TPACTION;

// action string name - max 8 chars
static LPCSTR VMM_MAP_WEB_TPACTION_STR[] = {
    "N/A",
    "VISIT",
    "DOWNLOAD",
    "LOGINPWD"
};

typedef enum tdVMM_MAP_WEB_TPBROWSER {
    VMM_MAP_WEB_TPBROWSER_NA        = 0,
    VMM_MAP_WEB_TPBROWSER_FIREFOX   = 1,
    VMM_MAP_WEB_TPBROWSER_CHROME    = 2,
    VMM_MAP_WEB_TPBROWSER_MSEDGE    = 3,
    VMM_MAP_WEB_TPBROWSER_BRAVE     = 4,
} VMM_MAP_WEB_TPBROWSER;

// browser string name - max 7 chars
static LPCSTR VMM_MAP_WEB_TPBROWSER_STR[] = {
    "N/A",
    "FIREFOX",
    "CHROME",
    "EDGE",
    "BRAVE"
};

typedef struct tdVMM_MAP_WEBENTRY {
    VMM_MAP_WEB_TPACTION  tpAction;
    VMM_MAP_WEB_TPBROWSER tpBrowser;
    DWORD dwPID;
    DWORD _Reserved;
    QWORD ftCreate;
    QWORD ftAccess;
    DWORD cbUrl;
    DWORD cbInfo;
    LPSTR uszUrl;
    LPSTR uszInfo;
} VMM_MAP_WEBENTRY, *PVMM_MAP_WEBENTRY;

typedef struct tdVMMOB_MAP_WEB {
    OB ObHdr;
    PDWORD pdwLineOffset;       // array of line ends in bytes
    PBYTE pbMultiText;
    DWORD cbMultiText;
    DWORD cMap;                 // # map entries.
    VMM_MAP_WEBENTRY pMap[0];   // map entries.
} VMMOB_MAP_WEB, *PVMMOB_MAP_WEB;



// ----------------------------------------------------------------------------
// WEB INITIALIZATION below:
// ----------------------------------------------------------------------------

typedef struct tdMWEB_CONTEXT {
    VMMDLL_MODULE_ID MID;
    POB_MAP pm;                 // result map
    POB_STRMAP psm;             // result string map
    POB_MAP pmFileObjects;      // k = _FILE_OBJECT va, v = POB_VMMWINOBJ_FILE
    POB_SET psDuplicate;
    // per-file analyzed below:
    PVMM_PROCESS pProcessOpt;
    POB_VMMWINOBJ_FILE pFile;
    QWORD qwHashFile;
    sqlite3 *hDB;
    VMM_MAP_WEB_TPBROWSER tpBrowser;
} MWEB_CONTEXT, *PMWEB_CONTEXT;

#define FCWEB_TIME2FT_FIREFOX(fft)      (fft ? ((fft * 10) + 116444736000000000) : 0)
#define FCWEB_TIME2FT_CHROMIUM(fft)     (fft * 10)

/*
* Add browser entries from sqlite database to the initialization context.
* -- ctx
* -- szSql = sql clause to run against the data, should return as following:
*            1: create time (int64)
*            2: access time (int64)
*            3: url (text)
*            4: info (text)
*/
VOID FcWeb_AddEntryFromDB(_In_ VMM_HANDLE H, _In_ PMWEB_CONTEXT ctx, _In_ VMM_MAP_WEB_TPACTION tpAction, _In_ LPSTR szSql)
{
    QWORD qwHash;
    PVMM_MAP_WEBENTRY pe;
    LPSTR uszUrl, uszInfo;
    QWORD ftCreate, ftAccess;
    sqlite3_stmt *hStmt = NULL;
    if(SQLITE_OK == sqlite3_prepare_v2(ctx->hDB, szSql, -1, &hStmt, 0)) {
        while(SQLITE_ROW == sqlite3_step(hStmt)) {
            // 1: fetch from sqlite
            ftCreate = sqlite3_column_int64(hStmt, 0);
            ftAccess = sqlite3_column_int64(hStmt, 1);
            uszUrl = (LPSTR)sqlite3_column_text(hStmt, 2);
            uszInfo = (LPSTR)sqlite3_column_text(hStmt, 3);
            if(!uszUrl && !uszInfo) { continue; }
            if(ctx->tpBrowser == VMM_MAP_WEB_TPBROWSER_FIREFOX) {
                ftCreate = FCWEB_TIME2FT_FIREFOX(ftCreate);
                ftAccess = FCWEB_TIME2FT_FIREFOX(ftAccess);
            } else {
                ftCreate = FCWEB_TIME2FT_CHROMIUM(ftCreate);
                ftAccess = FCWEB_TIME2FT_CHROMIUM(ftAccess);
            }
            // 2: add entry object
            if((pe = LocalAlloc(LMEM_ZEROINIT, sizeof(VMM_MAP_WEBENTRY)))) {
                qwHash = ctx->qwHashFile + ftCreate + ftAccess + CharUtil_Hash64U(uszUrl, FALSE) + CharUtil_Hash64U(uszInfo, FALSE);
                pe->tpAction = tpAction;
                pe->tpBrowser = ctx->tpBrowser;
                pe->dwPID = ctx->pProcessOpt ? ctx->pProcessOpt->dwPID : 0;
                pe->ftCreate = ftCreate;
                pe->ftAccess = ftAccess;
                if(ObMap_Push(ctx->pm, qwHash, pe)) {
                    ObStrMap_PushPtrUU(ctx->psm, uszUrl, &pe->uszUrl, &pe->cbUrl);
                    ObStrMap_PushPtrUU(ctx->psm, uszInfo, &pe->uszInfo, &pe->cbInfo);
                } else {
                    // fail insert into map == object alread exists -> free it!
                    LocalFree(pe);
                }
            }
        }
        sqlite3_finalize(hStmt); hStmt = NULL;
    }
}

/*
* Return a chromium compatible browser from the process name.
* If no process is provided default to chrome.
* -- H
* -- ctx
* -- return = chromium compatible browser.
*/
VMM_MAP_WEB_TPBROWSER FcWeb_GetChromiumBrowser(_In_ VMM_HANDLE H, _In_ PMWEB_CONTEXT ctx)
{
    if(!ctx->pProcessOpt) {
        return VMM_MAP_WEB_TPBROWSER_CHROME;
    }
    if(strstr(ctx->pProcessOpt->szName, "edge")) {
        return VMM_MAP_WEB_TPBROWSER_MSEDGE;
    }
    if(strstr(ctx->pProcessOpt->szName, "brave")) {
        return VMM_MAP_WEB_TPBROWSER_BRAVE;
    }
    return VMM_MAP_WEB_TPBROWSER_CHROME;
}



// ----------------------------------------------------------------------------
// WEB BROWSER SPECIFIC PARSING below:
// ----------------------------------------------------------------------------

typedef VOID(*FCWEB_SQLITE_PFN_CB)(_In_ VMM_HANDLE H, _In_ PMWEB_CONTEXT ctx);

VOID FcWeb_FF_Places_CB(_In_ VMM_HANDLE H, _In_ PMWEB_CONTEXT ctx)
{
    ctx->tpBrowser = VMM_MAP_WEB_TPBROWSER_FIREFOX;
    FcWeb_AddEntryFromDB(
        H,
        ctx,
        VMM_MAP_WEB_TPACTION_BROWSE,
        "SELECT 0, last_visit_date, url, title from moz_places WHERE last_visit_date > 0"
    );
    FcWeb_AddEntryFromDB(
        H,
        ctx,
        VMM_MAP_WEB_TPACTION_DOWNLOAD,
        "SELECT dateAdded, lastModified, content, '' from moz_annos WHERE anno_attribute_id = 4 AND dateAdded > 0"
    );
}

VOID FcWeb_Chromium_History_CB(_In_ VMM_HANDLE H, _In_ PMWEB_CONTEXT ctx)
{
    ctx->tpBrowser = FcWeb_GetChromiumBrowser(H, ctx);
    FcWeb_AddEntryFromDB(
        H,
        ctx,
        VMM_MAP_WEB_TPACTION_BROWSE,
        "SELECT v.visit_time, 0, u.url, u.title FROM visits v, urls u WHERE v.url = u.id AND v.visit_time > 0"
    );
    FcWeb_AddEntryFromDB(
        H,
        ctx,
        VMM_MAP_WEB_TPACTION_DOWNLOAD,
        "SELECT last_access_time, 0, tab_url, current_path FROM downloads WHERE last_access_time > 0"
    );
}

VOID FcWeb_Chromium_LoginData_CB(_In_ VMM_HANDLE H, _In_ PMWEB_CONTEXT ctx)
{
    ctx->tpBrowser = FcWeb_GetChromiumBrowser(H, ctx);
    FcWeb_AddEntryFromDB(
        H,
        ctx,
        VMM_MAP_WEB_TPACTION_LOGIN_PWD,
        "SELECT date_password_modified, date_last_used, origin_url, username_value FROM logins"
    );
}



// ----------------------------------------------------------------------------
// WEB INITIALIZATION (contd) below:
// ----------------------------------------------------------------------------

/*
* Dispatch a file for analysis to the appropriate browser tanalysis functions.
* -- H
* -- ctx
* -- pfnCB = browser-dependent analysis callback function.
*/
VOID FcWeb_LoadSqliteDispatch(_In_ VMM_HANDLE H, _In_ PMWEB_CONTEXT ctx, _In_ FCWEB_SQLITE_PFN_CB pfnCB)
{
    int rc;
    DWORD cbDB;
    PBYTE pbDB = NULL;
    BYTE pbTest[0x10] = { 0 };
    CHAR szFile[MAX_PATH], szURI[MAX_PATH];
    FILE *phFile = NULL;
    // 1: sanity checks
    if((ctx->pFile->cb < 0x1000) || (ctx->pFile->cb > 0x04000000)) { goto fail; }
    VmmWinObjFile_Read(H, ctx->pFile, 0, pbTest, sizeof(pbTest) - 1, 0, VMMWINOBJ_FILE_TP_DEFAULT);
    if(pbTest != (PBYTE)strstr((LPCSTR)pbTest, "SQLite ")) { goto fail; }
    // 2: read file handle into memory
    cbDB = (DWORD)ctx->pFile->cb;
    if(!(pbDB = LocalAlloc(0, cbDB))) { goto fail; }
    cbDB = VmmWinObjFile_Read(H, ctx->pFile, 0, pbDB, cbDB, 0, VMMWINOBJ_FILE_TP_DEFAULT);
    // 3: create and write to temp file
    if(tmpnam_s(szFile, MAX_PATH)) { goto fail; }
    strncat_s(szFile, _countof(szFile), ".vmmsqlite3.tmp", _TRUNCATE);
    if(fopen_s(&phFile, szFile, "wb")) {
        VmmLog(H, ctx->MID, LOGLEVEL_DEBUG, "fail open temp file: %s", szFile);
        goto fail;
    }
    fwrite(pbDB, 1, cbDB, phFile);
    fclose(phFile);
    // 4: open sqlite and dispatch
    sprintf_s(szURI, _countof(szURI), "file:///%s", szFile);
    CharUtil_ReplaceAllA(szURI, '\\', '/');
    rc = sqlite3_open_v2(szURI, &ctx->hDB, SQLITE_OPEN_URI | SQLITE_OPEN_READONLY | SQLITE_OPEN_NOMUTEX | SQLITE_OPEN_EXCLUSIVE, NULL);
    if(rc == SQLITE_OK) {
        sqlite3_db_config(ctx->hDB, SQLITE_DBCONFIG_ENABLE_TRIGGER, 0, 0);
        sqlite3_db_config(ctx->hDB, SQLITE_DBCONFIG_ENABLE_VIEW, 0, 0);
        pfnCB(H, ctx);
    } else {
        VmmLog(H, ctx->MID, LOGLEVEL_DEBUG, "fail sqlite3 open: rc=%i db='%s'", rc, ctx->pFile->uszName);
    }
fail:
    sqlite3_close(ctx->hDB); ctx->hDB = NULL;
    if(phFile) { remove(szFile); }
    LocalFree(pbDB);
}

int MWeb_Initialize_CmpSort(_In_ POB_MAP_ENTRY p1, _In_ POB_MAP_ENTRY p2)
{
    PVMM_MAP_WEBENTRY e1 = p1->v;
    PVMM_MAP_WEBENTRY e2 = p2->v;
    QWORD ft1 = max(e1->ftAccess, e1->ftCreate);
    QWORD ft2 = max(e2->ftAccess, e2->ftCreate);
    if(ft1 != ft2) {
        return (ft1 < ft2) ? 1 : -1;
    }
    return e1->dwPID - e2->dwPID;
}

/*
* Initialize a new web map in a single-threaded context.
* -- H
* -- ctxP
*/
PVMMOB_MAP_WEB MWeb_Initialize_DoWork(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_CONTEXT ctxP)
{
    DWORD i, cbDataStr = 0, cMap, cbData, cbOffset = 0;
    FCWEB_SQLITE_PFN_CB pfnCB;
    PVMM_MAP_WEBENTRY peWeb;
    PVMMOB_MAP_WEB pObMap = NULL;
    MWEB_CONTEXT ctxInit = { 0 };
    PVMM_PROCESS pObProcessOpt = NULL;
    POB_VMMWINOBJ_FILE pObFile = NULL;
    // 1: Initialize and get all file handles:
    //    getting all file handles have the advantage of potentially hitting a
    //    file handle belonging to a terminated process which is not yet closed
    ctxInit.MID = ctxP->MID;
    if(!(ctxInit.psDuplicate = ObSet_New(H))) { goto fail; }
    if(!(ctxInit.pm = ObMap_New(H, OB_MAP_FLAGS_OBJECT_LOCALFREE))) { goto fail; }
    if(!(ctxInit.psm = ObStrMap_New(H, OB_STRMAP_FLAGS_CASE_SENSITIVE))) { goto fail; }
    if(!VmmWinObjFile_GetAll(H, &ctxInit.pmFileObjects)) { goto fail; }
    if(H->fAbort) { goto fail; }
    // 2: Analyze interesting file handles:
    while((pObFile = ObMap_GetNext(ctxInit.pmFileObjects, pObFile))) {
        // Duplicate check and init analyze context:
        if(!pObFile->vaSectionObjectPointers || !pObFile->pData || ObSet_Exists(ctxInit.psDuplicate, pObFile->vaSectionObjectPointers)) {
            continue;
        }
        pfnCB = NULL;
        // Firefox:
        if(CharUtil_StrEquals(pObFile->uszName, "places.sqlite", FALSE)) {
            pfnCB = FcWeb_FF_Places_CB;
        }
        // Chrome/Edge:
        if(CharUtil_StrEquals(pObFile->uszName, "History", FALSE)) {
            pfnCB = FcWeb_Chromium_History_CB;
        }
        if(CharUtil_StrEquals(pObFile->uszName, "Login Data", FALSE)) {
            pfnCB = FcWeb_Chromium_LoginData_CB;
        }
        // Dispatch to analysis:
        if(pfnCB) {
            ObSet_Push(ctxInit.psDuplicate, pObFile->vaSectionObjectPointers);
            pObProcessOpt = VmmWinObj_GetProcessAssociated(H, pObFile->va);
            ctxInit.pProcessOpt = pObProcessOpt;
            ctxInit.pFile = pObFile;
            ctxInit.qwHashFile = CharUtil_Hash64U(pObFile->uszPath, TRUE);
            FcWeb_LoadSqliteDispatch(H, &ctxInit, pfnCB);
            VmmLog(H, ctxP->MID, LOGLEVEL_DEBUG, "analyze: pid=%i db=%s", (pObProcessOpt ? pObProcessOpt->dwPID : 0), pObFile->uszName);
            Ob_DECREF_NULL(&pObProcessOpt);
        }
    }
    // 3: CREATE MAP / FINALIZE:
    if(!ObStrMap_FinalizeBufferU(ctxInit.psm, 0, NULL, &cbDataStr)) { goto fail; }
    cMap = ObMap_Size(ctxInit.pm);
    cbData = sizeof(VMMOB_MAP_WEB) + cMap * (sizeof(VMM_MAP_WEBENTRY) + sizeof(DWORD)) + cbDataStr;
    if(!(pObMap = Ob_AllocEx(H, OB_TAG_MAP_WEB, LMEM_ZEROINIT, cbData, NULL, NULL))) { goto fail; }
    pObMap->cMap = cMap;
    pObMap->pdwLineOffset = (PDWORD)(pObMap->pMap + pObMap->cMap);
    pObMap->pbMultiText = (LPSTR)((QWORD)pObMap + cbData - cbDataStr);
    ObStrMap_FinalizeBufferU(ctxInit.psm, cbDataStr, pObMap->pbMultiText, &pObMap->cbMultiText);
    ObMap_SortEntryIndex(ctxInit.pm, MWeb_Initialize_CmpSort);
    for(i = 0; i < pObMap->cMap; i++) {     // COPY WEBENTRY TO MAP
        if(!(peWeb = ObMap_GetByIndex(ctxInit.pm, i))) { goto fail; }
        memcpy(pObMap->pMap + i, peWeb, sizeof(VMM_MAP_WEBENTRY));
        cbOffset += MWEB_LINELENGTH_BASE + peWeb->cbUrl + peWeb->cbInfo;
        pObMap->pdwLineOffset[i] = cbOffset;
    }
    Ob_INCREF(pObMap);
fail:
    Ob_DECREF(ctxInit.pm);
    Ob_DECREF(ctxInit.psm);
    Ob_DECREF(ctxInit.psDuplicate);
    Ob_DECREF(ctxInit.pmFileObjects);
    return Ob_DECREF(pObMap);
}

/*
* Fetch the 'WebMap' object.
* CALLER DECREF: return
* -- H
* -- ctxP
* -- return
*/
PVMMOB_MAP_WEB MWeb_GetWebMap(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_CONTEXT ctxP)
{
    PVMMOB_MAP_WEB pObMap = NULL;
    pObMap = ObContainer_GetOb((POB_CONTAINER)ctxP->ctxM);
    if(!pObMap) {
        AcquireSRWLockExclusive(&H->vmm.LockSRW.ModuleMiscWeb);
        pObMap = ObContainer_GetOb((POB_CONTAINER)ctxP->ctxM);
        if(!pObMap) {
            pObMap = MWeb_Initialize_DoWork(H, ctxP);
            ObContainer_SetOb((POB_CONTAINER)ctxP->ctxM, pObMap);
        }
        ReleaseSRWLockExclusive(&H->vmm.LockSRW.ModuleMiscWeb);
    }
    return pObMap;
}



// ----------------------------------------------------------------------------
// WEB MODULE ACCESS FUNCTIONALITY BELOW:
// ----------------------------------------------------------------------------

/*
* Generate a single line in the web.txt file.
*/
VOID MWeb_ReadLine_CB(_In_ VMM_HANDLE H, _In_ PVMMOB_MAP_WEB pObWebMap, _In_ DWORD cbLineLength, _In_ DWORD ie, _In_ PVOID pv, _Out_writes_(cbLineLength + 1) LPSTR szu8)
{
    PVMM_MAP_WEBENTRY pe = pObWebMap->pMap + ie;
    CHAR szTime[24];
    QWORD ftMax = max(pe->ftCreate, pe->ftAccess);
    Util_FileTime2String(ftMax, szTime);
    Util_usnprintf_ln(szu8, cbLineLength,
        "%6x%7i %s  %-7s %-8s %s :: %s",
        ie,
        pe->dwPID,
        szTime,
        VMM_MAP_WEB_TPBROWSER_STR[pe->tpBrowser],
        VMM_MAP_WEB_TPACTION_STR[pe->tpAction],
        pe->uszUrl,
        pe->uszInfo
    );
}

NTSTATUS MWeb_Read(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_CONTEXT ctxP, _Out_writes_to_(cb, *pcbRead) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset)
{
    NTSTATUS nt = VMMDLL_STATUS_FILE_INVALID;
    PVMMOB_MAP_WEB pObWebMap = NULL;
    if(!(pObWebMap = MWeb_GetWebMap(H, ctxP))) { goto finish; }
    if(!_stricmp("readme.txt", ctxP->uszPath)) {
        return VMMDLL_UtilVfsReadFile_FromPBYTE(szMWEB_README, strlen(szMWEB_README), pb, cb, pcbRead, cbOffset);
    }
    if(!_stricmp(ctxP->uszPath, "web.txt")) {
        nt = Util_VfsLineVariable_Read(
            H, (UTIL_VFSLINEFIXED_PFN_CB)MWeb_ReadLine_CB, pObWebMap, MWEB_LINEHEADER,
            pObWebMap->pMap, pObWebMap->cMap, sizeof(VMM_MAP_WEBENTRY), pObWebMap->pdwLineOffset,
            pb, cb, pcbRead, cbOffset
        );
        goto finish;
    }
finish:
    Ob_DECREF(pObWebMap);
    return nt;
}

BOOL MWeb_List(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_CONTEXT ctxP, _Inout_ PHANDLE pFileList)
{
    PVMMOB_MAP_WEB pObWebMap = NULL;
    if(!(pObWebMap = MWeb_GetWebMap(H, ctxP))) { goto finish; }
    if(!ctxP->uszPath[0]) {
        VMMDLL_VfsList_AddFile(pFileList, "readme.txt", strlen(szMWEB_README), NULL);
        VMMDLL_VfsList_AddFile(pFileList, "web.txt", UTIL_VFSLINEVARIABLE_BYTECOUNT(H, pObWebMap->cMap, pObWebMap->pdwLineOffset, MWEB_LINEHEADER), NULL);
        goto finish;
    }
finish:
    Ob_DECREF(pObWebMap);
    return TRUE;
}

VOID MWeb_Notify(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_CONTEXT ctxP, _In_ DWORD fEvent, _In_opt_ PVOID pvEvent, _In_opt_ DWORD cbEvent)
{
    if(fEvent == VMMDLL_PLUGIN_NOTIFY_FORENSIC_INIT_COMPLETE) {
        PluginManager_SetVisibility(H, TRUE, "\\forensic\\web", TRUE);
    }
}

VOID MWeb_Close(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_CONTEXT ctxP)
{
    Ob_DECREF(ctxP->ctxM);
}

VOID MWeb_FcLogJSON(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_CONTEXT ctxP, _In_ VOID(*pfnLogJSON)(_In_ VMM_HANDLE H, _In_ PVMMDLL_FORENSIC_JSONDATA pData))
{
    DWORD ie;
    PVMM_MAP_WEBENTRY pe = NULL;
    PVMMOB_MAP_WEB pObWebMap = NULL;
    PVMMDLL_FORENSIC_JSONDATA pd = NULL;
    CHAR usz[2048], szTime[24];
    if(ctxP->pProcess) { return; }
    if(!(pObWebMap = MWeb_GetWebMap(H, ctxP))) { goto fail; }
    if(!(pd = LocalAlloc(LMEM_ZEROINIT, sizeof(VMMDLL_FORENSIC_JSONDATA)))) { goto fail; }
    pd->dwVersion = VMMDLL_FORENSIC_JSONDATA_VERSION;
    pd->szjType = "web";
    for(ie = 0; ie < pObWebMap->cMap; ie++) {
        pe = pObWebMap->pMap + ie;
        Util_FileTime2String(max(pe->ftAccess, pe->ftCreate), szTime);
        _snprintf_s(usz, _countof(usz), _TRUNCATE, "type:[%s] time:[%s] info:[%s]",
            VMM_MAP_WEB_TPACTION_STR[pe->tpAction],
            szTime,
            pe->uszInfo
        );
        pd->i = ie;
        pd->dwPID = pe->dwPID;
        pd->usz[0] = pe->uszUrl;
        pd->usz[1] = usz;
        pfnLogJSON(H, pd);
    }
fail:
    Ob_DECREF(pObWebMap);
    LocalFree(pd);
}

VOID MWeb_FcTimeline(
    _In_ VMM_HANDLE H,
    _In_opt_ PVOID ctxfc,
    _In_ HANDLE hTimeline,
    _In_ VOID(*pfnAddEntry)(_In_ VMM_HANDLE H, _In_ HANDLE hTimeline, _In_ QWORD ft, _In_ DWORD dwAction, _In_ DWORD dwPID, _In_ DWORD dwData32, _In_ QWORD qwData64, _In_ LPCSTR uszText),
    _In_ VOID(*pfnEntryAddBySql)(_In_ VMM_HANDLE H, _In_ HANDLE hTimeline, _In_ DWORD cEntrySql, _In_ LPCSTR *pszEntrySql)
) {
    PVMMOB_MAP_WEB pWebMap = (PVMMOB_MAP_WEB)ctxfc;
    PVMM_MAP_WEBENTRY pe;
    DWORD i;
    int cch;
    CHAR usz[2048];
    if(!pWebMap) { return; }
    for(i = 0; i < pWebMap->cMap; i++) {
        pe = pWebMap->pMap + i;
        cch = _snprintf_s(usz, _countof(usz), _TRUNCATE, "browser:[%s] type:[%s] url:[%s] info:[%s]",
            VMM_MAP_WEB_TPBROWSER_STR[pe->tpBrowser],
            VMM_MAP_WEB_TPACTION_STR[pe->tpAction],
            pe->uszUrl,
            pe->uszInfo);
        if(cch > 10) {
            if(pe->ftCreate) {
                pfnAddEntry(H, hTimeline, pe->ftCreate, FC_TIMELINE_ACTION_CREATE, pe->dwPID, 0, 0, usz);
            }
            if(pe->ftAccess && (pe->ftAccess != pe->ftCreate)) {
                pfnAddEntry(H, hTimeline, pe->ftAccess, FC_TIMELINE_ACTION_READ, pe->dwPID, 0, 0, usz);
            }
        }
    }
}

VOID MWeb_FcFinalize(_In_ VMM_HANDLE H, _In_opt_ PVOID ctxfc)
{
    Ob_DECREF(ctxfc);
}

PVOID MWeb_FcInitialize(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_CONTEXT ctxP)
{
    return MWeb_GetWebMap(H, ctxP);
}

VOID M_FcWeb_Initialize(_In_ VMM_HANDLE H, _Inout_ PVMMDLL_PLUGIN_REGINFO pRI)
{
    if((pRI->magic != VMMDLL_PLUGIN_REGINFO_MAGIC) || (pRI->wVersion != VMMDLL_PLUGIN_REGINFO_VERSION)) { return; }
    if((pRI->tpSystem != VMM_SYSTEM_WINDOWS_64) && (pRI->tpSystem != VMM_SYSTEM_WINDOWS_32)) { return; }
    if(!(pRI->reg_info.ctxM = (PVMMDLL_PLUGIN_INTERNAL_CONTEXT)ObContainer_New())) { return; }
    strcpy_s(pRI->reg_info.uszPathName, 128, "\\forensic\\web");                // module name
    pRI->reg_info.fRootModule = TRUE;                                           // module shows in root directory
    pRI->reg_info.fRootModuleHidden = TRUE;                                     // module hidden by default
    // functions supported:
    pRI->reg_fn.pfnList = MWeb_List;
    pRI->reg_fn.pfnRead = MWeb_Read;
    pRI->reg_fn.pfnNotify = MWeb_Notify;
    pRI->reg_fn.pfnClose = MWeb_Close;
    pRI->reg_fnfc.pfnLogJSON = MWeb_FcLogJSON;                                  // JSON log function supported
    // timelining support:
    pRI->reg_fnfc.pfnInitialize = MWeb_FcInitialize;                            // Forensic initialize function supported
    pRI->reg_fnfc.pfnTimeline = MWeb_FcTimeline;                                // Forensic timelining supported
    pRI->reg_fnfc.pfnFinalize = MWeb_FcFinalize;                                // Forensic finalize function supported
    memcpy(pRI->reg_info.sTimelineNameShort, "WEB", 4);
    strncpy_s(pRI->reg_info.uszTimelineFile, 32, "timeline_web", _TRUNCATE);
    pRI->pfnPluginManager_Register(H, pRI);
}
