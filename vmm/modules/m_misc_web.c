// m_misc_web.c : web browsing misc & forensic module.
//
// (c) Ulf Frisk, 2022-2023
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
    VMM_MAP_WEB_TPACTION_DOWNLOAD   = 2
} VMM_MAP_WEB_TPACTION;

typedef enum tdVMM_MAP_WEB_TPBROWSER {
    VMM_MAP_WEB_TPBROWSER_NA        = 0,
    VMM_MAP_WEB_TPBROWSER_FIREFOX   = 1,
    VMM_MAP_WEB_TPBROWSER_CHROME    = 2,
    VMM_MAP_WEB_TPBROWSER_MSEDGE    = 3,
} VMM_MAP_WEB_TPBROWSER;

static LPCSTR VMM_MAP_WEB_TPACTION_STR[] = { "N/A", "VISIT", "DOWNLOAD" };              // max 8 chars
static LPCSTR VMM_MAP_WEB_TPBROWSER_STR[] = { "N/A", "FIREFOX", "CHROME", "EDGE"};      // max 7 chars

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
    POB_MAP pm;
    POB_STRMAP psm;
    POB_SET psFileProcessed;
    SRWLOCK LockSRW;
    // single-threaded analysis below:
    PVMM_PROCESS pProcess;
    POB_VMMWINOBJ_FILE pFile;
    sqlite3 *hDB;
    QWORD qwHashFile;
} MWEB_CONTEXT, *PMWEB_CONTEXT;

#define FCWEB_TIME2FT_FIREFOX(fft)      (fft ? ((fft * 10) + 116444736000000000) : 0)
#define FCWEB_TIME2FT_CHROMIUM(fft)     (fft * 10)

/*
* Add browser entries from sqlite database to the initialization context.
* -- ctx
* -- tpBrowser
* -- tpAction
* -- szSql
*/
VOID FcWeb_AddEntryFromDB(_In_ VMM_HANDLE H, _In_ PMWEB_CONTEXT ctx, VMM_MAP_WEB_TPBROWSER tpBrowser, VMM_MAP_WEB_TPACTION tpAction, _In_ LPSTR szSql)
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
            if(tpBrowser == VMM_MAP_WEB_TPBROWSER_FIREFOX) {
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
                pe->tpBrowser = tpBrowser;
                pe->dwPID = ctx->pProcess->dwPID;
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



// ----------------------------------------------------------------------------
// WEB BROWSER SPECIFIC PARSING below:
// ----------------------------------------------------------------------------

VOID FcWeb_FF_Places(_In_ VMM_HANDLE H, _In_ PMWEB_CONTEXT ctx)
{
    FcWeb_AddEntryFromDB(
        H,
        ctx,
        VMM_MAP_WEB_TPBROWSER_FIREFOX,
        VMM_MAP_WEB_TPACTION_BROWSE,
        "SELECT 0, last_visit_date, url, title from moz_places WHERE last_visit_date > 0"
    );
    FcWeb_AddEntryFromDB(
        H,
        ctx,
        VMM_MAP_WEB_TPBROWSER_FIREFOX,
        VMM_MAP_WEB_TPACTION_DOWNLOAD,
        "SELECT dateAdded, lastModified, content, '' from moz_annos WHERE anno_attribute_id = 4 AND dateAdded > 0"
    );
}

VOID FcWeb_Chrome_History(_In_ VMM_HANDLE H, _In_ PMWEB_CONTEXT ctx)
{
    VMM_MAP_WEB_TPBROWSER tpBrowser = strstr(ctx->pProcess->szName, "chrome") ? VMM_MAP_WEB_TPBROWSER_CHROME : VMM_MAP_WEB_TPBROWSER_MSEDGE;
    FcWeb_AddEntryFromDB(
        H,
        ctx,
        tpBrowser,
        VMM_MAP_WEB_TPACTION_BROWSE,
        "SELECT v.visit_time, 0, u.url, u.title FROM visits v, urls u WHERE v.url = u.id AND v.visit_time > 0"
    );
    FcWeb_AddEntryFromDB(
        H,
        ctx,
        tpBrowser,
        VMM_MAP_WEB_TPACTION_DOWNLOAD,
        "SELECT last_access_time, 0, tab_url, current_path FROM downloads WHERE last_access_time > 0"
    );
}



// ----------------------------------------------------------------------------
// WEB INITIALIZATION (contd) below:
// ----------------------------------------------------------------------------

/*
* Dispatch a file for analysis to the appropriate browser tanalysis functions.
* -- H
* -- ctx
* -- pfnCB = analysis callback function.
*/
VOID FcWeb_LoadSqliteDispatch(_In_ VMM_HANDLE H, _In_ PMWEB_CONTEXT ctx, _In_ VOID(*pfnCB)(_In_ VMM_HANDLE H, _In_ PMWEB_CONTEXT ctx))
{
    int rc;
    DWORD cbDB;
    PBYTE pbDB = NULL;
    BYTE pbTest[0x10] = { 0 };
    CHAR szFile[MAX_PATH], szURI[MAX_PATH];
    FILE *phFile = NULL;
    // 1: sanity checks
    if((ctx->pFile->cb < 0x1000) || (ctx->pFile->cb > 0x04000000)) { goto fail; }
    VmmWinObjFile_Read(H, ctx->pFile, 0, pbTest, sizeof(pbTest) - 1, 0);
    if(pbTest != (PBYTE)strstr((LPCSTR)pbTest, "SQLite ")) { goto fail; }
    // 2: read file handle into memory
    cbDB = (DWORD)ctx->pFile->cb;
    if(!(pbDB = LocalAlloc(0, cbDB))) { goto fail; }
    cbDB = VmmWinObjFile_Read(H, ctx->pFile, 0, pbDB, cbDB, 0);
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
        pfnCB(H, ctx);
    } else {
        VmmLog(H, ctx->MID, LOGLEVEL_DEBUG, "fail sqlite3 open: rc=%i db='%s'", rc, ctx->pFile->uszName);
    }
fail:
    sqlite3_close(ctx->hDB); ctx->hDB = NULL;
    if(phFile) { remove(szFile); }
    LocalFree(pbDB);
}

/*
* Analyze a process that matches the process critera for any browser data.
* This may be called in a multi-threaded context.
* -- pProcess
* -- ctx
*/
VOID MWeb_Initialize_ThreadProc(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess, _In_ PVOID pvCtxInit)
{
    BOOL fAnalyze;
    QWORD qwHashFile;
    POB_MAP pmObFiles;
    POB_VMMWINOBJ_FILE pObFile;
    PMWEB_CONTEXT ctx = pvCtxInit;
    if(!VmmWinObjFile_GetByProcess(H, pProcess, &pmObFiles, TRUE)) { return; }
    VmmLog(H, ctx->MID, LOGLEVEL_TRACE, "process: pid=%i", pProcess->dwPID);
    while((pObFile = ObMap_Pop(pmObFiles))) {
        if(pObFile->pSectionObjectPointers->fData) {
            VmmLog(H, ctx->MID, LOGLEVEL_TRACE, "handle:  pid=%i handle=%s", pProcess->dwPID, pObFile->uszName);
            // check if already processed (multiple handles often exists)
            qwHashFile = pObFile->cb + pProcess->dwPID;
            qwHashFile = qwHashFile + (qwHashFile << 32) + CharUtil_Hash64U(pObFile->uszName, FALSE);
            if(!ObSet_Push(ctx->psFileProcessed, qwHashFile)) {
                // already processed another handle to same file
                Ob_DECREF(pObFile);
                continue;
            }
            // lock & prepare:
            AcquireSRWLockExclusive(&ctx->LockSRW);
            ctx->qwHashFile = qwHashFile;
            ctx->pProcess = pProcess;
            ctx->pFile = pObFile;
            // dispatch to analysis:
            fAnalyze = FALSE;
            if((fAnalyze = !strcmp(pObFile->uszName, "places.sqlite"))) {    // firefox 'places.sqlite'
                FcWeb_LoadSqliteDispatch(H, ctx, FcWeb_FF_Places);
            }
            //if((fAnalyze = !strcmp(pObFile->uszName, "cookies.sqlite"))) {    // firefox cookies.sqlite
            //    FcWeb_LoadSqliteDispatch(&ctx, FcWeb_FF_Cookies);
            //}
            if((fAnalyze = !strcmp(pObFile->uszName, "History"))) {          // chrome/edge 'History'
                FcWeb_LoadSqliteDispatch(H, ctx, FcWeb_Chrome_History);
            }
            if(fAnalyze) {
                VmmLog(H, ctx->MID, LOGLEVEL_DEBUG, "analyze: pid=%i db=%s", pProcess->dwPID, pObFile->uszName);
            }
            // finish:
            ctx->pFile = NULL;
            ctx->pProcess = NULL;
            qwHashFile = 0;
            ReleaseSRWLockExclusive(&ctx->LockSRW);
        }
        Ob_DECREF(pObFile);
    }
    Ob_DECREF(pmObFiles);
}

BOOL MWeb_CriteriaSupportedBrowserProcess(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess, _In_opt_ PVOID ctx)
{
    if(pProcess->dwState != 0) { return FALSE; }
    return
        !_stricmp(pProcess->szName, "chrome.exe") ||
        !_stricmp(pProcess->szName, "firefox.exe") ||
        !_stricmp(pProcess->szName, "msedge.exe");
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
VOID MWeb_Initialize_DoWork(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_CONTEXT ctxP)
{
    BOOL fResult = FALSE;
    DWORD i, cMap, cbDataStr, cbData, cbOffset = 0;
    MWEB_CONTEXT ctxInit = { 0 };
    PVMM_MAP_WEBENTRY peWeb;
    PVMMOB_MAP_WEB pObMap = NULL;
    // 1: INIT:
    ctxInit.MID = ctxP->MID;
    if(!(ctxInit.psFileProcessed = ObSet_New(H))) { goto fail; }
    if(!(ctxInit.pm = ObMap_New(H, OB_MAP_FLAGS_OBJECT_LOCALFREE))) { goto fail; }
    if(!(ctxInit.psm = ObStrMap_New(H, OB_STRMAP_FLAGS_CASE_SENSITIVE))) { goto fail; }
    // 2: DISPATCH TO ANALYSIS:
    if(!VmmWork_ProcessActionForeachParallel_Void(H, 0, &ctxInit, MWeb_CriteriaSupportedBrowserProcess, MWeb_Initialize_ThreadProc)) { goto fail; }
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
    // 4: FINISH
    ObContainer_SetOb((POB_CONTAINER)ctxP->ctxM, pObMap);
    fResult = TRUE;
fail:
    Ob_DECREF(pObMap);
    Ob_DECREF(ctxInit.pm);
    Ob_DECREF(ctxInit.psm);
    Ob_DECREF(ctxInit.psFileProcessed);
    if(!fResult && (pObMap = Ob_AllocEx(H, OB_TAG_MAP_WEB, LMEM_ZEROINIT, sizeof(VMMOB_MAP_WEB), NULL, NULL))) {
        pObMap->pdwLineOffset = &pObMap->cMap;
        ObContainer_SetOb((POB_CONTAINER)ctxP->ctxM, pObMap);
        Ob_DECREF(pObMap);
    }
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
    static SRWLOCK LockSRW = SRWLOCK_INIT;
    PVMMOB_MAP_WEB pOb;
    if((pOb = ObContainer_GetOb((POB_CONTAINER)ctxP->ctxM))) { return pOb; }
    AcquireSRWLockExclusive(&LockSRW);
    MWeb_Initialize_DoWork(H, ctxP);
    ReleaseSRWLockExclusive(&LockSRW);
    return ObContainer_GetOb((POB_CONTAINER)ctxP->ctxM);
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
    if(fEvent == VMMDLL_PLUGIN_NOTIFY_REFRESH_SLOW) {
        ObContainer_SetOb((POB_CONTAINER)ctxP->ctxM, NULL);
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
    _In_ VOID(*pfnAddEntry)(_In_ VMM_HANDLE H, _In_ HANDLE hTimeline, _In_ QWORD ft, _In_ DWORD dwAction, _In_ DWORD dwPID, _In_ DWORD dwData32, _In_ QWORD qwData64, _In_ LPSTR uszText),
    _In_ VOID(*pfnEntryAddBySql)(_In_ VMM_HANDLE H, _In_ HANDLE hTimeline, _In_ DWORD cEntrySql, _In_ LPSTR *pszEntrySql)
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

VOID M_MiscWeb_Initialize(_In_ VMM_HANDLE H, _Inout_ PVMMDLL_PLUGIN_REGINFO pRI)
{
    if((pRI->magic != VMMDLL_PLUGIN_REGINFO_MAGIC) || (pRI->wVersion != VMMDLL_PLUGIN_REGINFO_VERSION)) { return; }
    if((pRI->tpSystem != VMM_SYSTEM_WINDOWS_64) && (pRI->tpSystem != VMM_SYSTEM_WINDOWS_32)) { return; }
    if(!(pRI->reg_info.ctxM = (PVMMDLL_PLUGIN_INTERNAL_CONTEXT)ObContainer_New())) { return; }
    strcpy_s(pRI->reg_info.uszPathName, 128, "\\misc\\web");                    // module name
    pRI->reg_info.fRootModule = TRUE;                                           // module shows in root directory
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
