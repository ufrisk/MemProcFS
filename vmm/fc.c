// fc.c : implementation related to memory forensic support.
//
//      Memory analysis in vmm.c is generally instant and work on both live and
//      static memory.
//
//      Forensic memory analysis is more thorough and batch-oriented and is
//      only available for static memory. After general startup a single pass
//      of consisting of multiple forensic activities will start. The result
//      is generally stored in an sqlite database with may be used to query
//      the results.
//
// (c) Ulf Frisk, 2020-2021
// Author: Ulf Frisk, pcileech@frizk.net
//

#include "fc.h"
#include "vmmdll.h"
#include "pdb.h"
#include "vmmwin.h"
#include "vmmwinreg.h"
#include "pluginmanager.h"
#include "sqlite/sqlite3.h"
#include "statistics.h"
#include "charutil.h"
#include "util.h"
#include "version.h"

static LPSTR FC_SQL_SCHEMA_STR =
    "DROP TABLE IF EXISTS str; " \
    "CREATE TABLE str ( id INTEGER PRIMARY KEY, cbu INT, cbj INT, sz TEXT ); ";



// ----------------------------------------------------------------------------
// FC global variable below:
// ----------------------------------------------------------------------------

PFC_CONTEXT ctxFc = NULL;



// ----------------------------------------------------------------------------
// SQLITE GENERAL FUNCTIONALITY:
// ----------------------------------------------------------------------------

/*
* Retrieve an SQLITE database handle. The retrieved handle must be
* returned with Fc_SqlReserveReturn().
* -- return = an SQLITE handle, or NULL on error.
*/
_Success_(return != NULL)
sqlite3* Fc_SqlReserve()
{
    DWORD iWaitNum = 0;
    if(ctxFc->db.fSingleThread) {
        WaitForSingleObject(ctxFc->db.hEvent[0], INFINITE);
    } else {
        iWaitNum = WaitForMultipleObjects(FC_SQL_POOL_CONNECTION_NUM, ctxFc->db.hEvent, FALSE, INFINITE) - WAIT_OBJECT_0;
    }
    if(iWaitNum >= FC_SQL_POOL_CONNECTION_NUM) {
        vmmprintf_fn("FATAL DATABASE ERROR: WaitForMultipleObjects ERROR: 0x%08x\n", (DWORD)(iWaitNum + WAIT_OBJECT_0));
        return NULL;
    }
    return ctxFc->db.hSql[iWaitNum];
}

/*
* Return a SQLITE database handle previously retrieved with Fc_SqlReserve()
* so that other threads may use it.
* -- hSql = the SQLITE database handle.
* -- return = always NULL.
*/
_Success_(return != NULL)
sqlite3* Fc_SqlReserveReturn(_In_opt_ sqlite3 *hSql)
{
    DWORD i;
    if(!hSql) { return NULL; }
    for(i = 0; i < FC_SQL_POOL_CONNECTION_NUM; i++) {
        if(ctxFc->db.hSql[i] == hSql) {
            SetEvent(ctxFc->db.hEvent[i]);
            break;
        }
    }
    return NULL;
}

/*
* Execute a single SQLITE database SQL query and return the SQLITE result code.
* -- szSql
* -- return = sqlite return code.
*/
_Success_(return == SQLITE_OK)
int Fc_SqlExec(_In_ LPSTR szSql)
{
    int rc = SQLITE_ERROR;
    sqlite3 *hSql = Fc_SqlReserve();
    if(hSql) {
        rc = sqlite3_exec(hSql, szSql, NULL, NULL, NULL);
        Fc_SqlReserveReturn(hSql);
    }
    return rc;
}

/*
* Execute a single SQLITE database SQL query and return all results as numeric
* 64-bit results in an array that must have capacity to hold all values.
* result and the SQLITE result code.
* -- szSql
* -- cQueryValue = nummber of numeric query arguments-
* -- pqwQueryValues = array of 64-bit query arguments-
* -- cResultValues = max number of numeric query results.
* -- pqwResultValues = array to receive 64-bit query results.
* -- pcResultValues = optional to receive number of query results read.
* -- return = sqlite return code.
*/
_Success_(return == SQLITE_OK)
int Fc_SqlQueryN(_In_ LPSTR szSql, _In_ DWORD cQueryValues, _In_reads_(cQueryValues) PQWORD pqwQueryValues, _In_ DWORD cResultValues, _Out_writes_(cResultValues) PQWORD pqwResultValues, _Out_opt_ PDWORD pcResultValues)
{
    int rc = SQLITE_ERROR;
    DWORD i, iMax;
    sqlite3 *hSql = Fc_SqlReserve();
    sqlite3_stmt *hStmt = NULL;
    if(hSql) {
        rc = sqlite3_prepare_v2(hSql, szSql, -1, &hStmt, 0);
        if(rc != SQLITE_OK) { goto fail; }
        for(i = 0; i < cQueryValues; i++) {
            sqlite3_bind_int64(hStmt, i + 1, pqwQueryValues[i]);
        }
        rc = sqlite3_step(hStmt);
        if(rc != SQLITE_ROW) { goto fail; }
        iMax = sqlite3_column_count(hStmt);
        if(pcResultValues) {
            *pcResultValues = iMax;
        }
        if(iMax > cResultValues) {
            rc = SQLITE_ERROR;
            goto fail;
        }
        for(i = 0; i < iMax; i++) {
            pqwResultValues[i] = sqlite3_column_int64(hStmt, i);
        }
        rc = SQLITE_OK;
    }
fail:
    sqlite3_finalize(hStmt);
    Fc_SqlReserveReturn(hSql);
    if(pcResultValues) { *pcResultValues = 0; }
    return rc;
}

_Success_(return)
BOOL Fc_SqlInsertStr(_In_ sqlite3_stmt *hStmt, _In_ LPSTR usz, _Out_ PFCSQL_INSERTSTRTABLE pThis)
{
    if(!CharUtil_UtoU(usz, -1, NULL, 0, NULL, &pThis->cbu, 0)) { return FALSE; }
    pThis->cbu--;               // don't count null terminator.
    CharUtil_UtoJ(usz, -1, NULL, 0, NULL, &pThis->cbj, 0);   // # of bytes to represent JSON string (incl. null-terminator)
    if(pThis->cbj) { pThis->cbj--; }
    pThis->id = InterlockedIncrement64(&ctxFc->db.qwIdStr);
    sqlite3_reset(hStmt);
    sqlite3_bind_int64(hStmt, 1, pThis->id);
    sqlite3_bind_int(hStmt, 2, pThis->cbu);
    sqlite3_bind_int(hStmt, 3, pThis->cbj);
    sqlite3_bind_text(hStmt, 4, usz, -1, NULL);
    sqlite3_step(hStmt);
    return TRUE;
}

/*
* Database helper function to do multiple 64-bit binds towards a statement in a
* convenient way. NB! 32-bit DWORDs must be casted to 64-bit QWORD to avoid
* padding of 0xcccccccc in the high-part.
* -- hStmt
* -- iFirstBind
* -- cInt64
* -- ... = vararg of cInt64 QWORDs to bind to hStmt.
* -- return
*/
_Success_(return == SQLITE_OK)
int Fc_SqlBindMultiInt64(_In_ sqlite3_stmt *hStmt, _In_ DWORD iFirstBind, _In_ DWORD cInt64, ...)
{
    int rc = SQLITE_OK;
    DWORD i;
    QWORD v;
    va_list arglist;
    va_start(arglist, cInt64);
    for(i = 0; i < cInt64; i++) {
        v = va_arg(arglist, QWORD);
        rc = sqlite3_bind_int64(hStmt, iFirstBind + i, v);
        if(rc != SQLITE_OK) { break; }
    }
    va_end(arglist);
    return rc;
}



// ----------------------------------------------------------------------------
// TIMELINING FUNCTIONALITY BELOW:
// ----------------------------------------------------------------------------

typedef struct tdFCTIMELINE_PLUGIN_CONTEXT {
    DWORD dwId;
    sqlite3 *hSql;
    sqlite3_stmt *hStmt;
    sqlite3_stmt *hStmtStr;
} FCTIMELINE_PLUGIN_CONTEXT, *PFCTIMELINE_PLUGIN_CONTEXT;

/*
* Callback function to add a single plugin module timeline entry.
* -- hTimeline
* -- ft
* -- dwAction
* -- dwPID
* -- qwValue
* -- wszText
*/
VOID FcTimeline_Callback_PluginEntryAdd(_In_ HANDLE hTimeline, _In_ QWORD ft, _In_ DWORD dwAction, _In_ DWORD dwPID, _In_ DWORD dwData32, _In_ QWORD qwData64, _In_ LPSTR uszText)
{
    PFCTIMELINE_PLUGIN_CONTEXT ctx = (PFCTIMELINE_PLUGIN_CONTEXT)hTimeline;
    FCSQL_INSERTSTRTABLE SqlStrInsert;
    // build and insert string data into 'str' table.
    if(!Fc_SqlInsertStr(ctx->hStmtStr, uszText, &SqlStrInsert)) { return; }
    // insert into 'timeline_data' table.
    sqlite3_reset(ctx->hStmt);
    Fc_SqlBindMultiInt64(ctx->hStmt, 1, 7,
        SqlStrInsert.id,
        (QWORD)ctx->dwId,
        ft,
        (QWORD)dwAction,
        (QWORD)dwPID,
        (QWORD)dwData32,
        qwData64
    );
    sqlite3_step(ctx->hStmt);
}

/*
* Callback function to add timelining entries by partial select query.
* -- hTimeline
* -- cEntrySql
* -- pszEntrySql
*/
VOID FcTimeline_Callback_PluginEntryAddBySQL(_In_ HANDLE hTimeline, _In_ DWORD cEntrySql, _In_ LPSTR *pszEntrySql)
{
    int rc;
    DWORD i;
    CHAR szSql[2048];
    PFCTIMELINE_PLUGIN_CONTEXT ctx = (PFCTIMELINE_PLUGIN_CONTEXT)hTimeline;
    for(i = 0; i < cEntrySql; i++) {
        ZeroMemory(szSql, sizeof(szSql));
        snprintf(szSql, sizeof(szSql), "INSERT INTO timeline_data(tp, id_str, ft, ac, pid, data32, data64) SELECT %i, %s;", ctx->dwId, pszEntrySql[i]);
        rc = sqlite3_exec(ctx->hSql, szSql, NULL, NULL, NULL);
        if(rc != SQLITE_OK) {
            vmmprintfvv_fn("BAD SQL CODE=0x%x SQL=%s\n", rc, szSql);
        }
    }
}

/*
* Callback function to close an existing timeline plugin module handle.
* -- hTimeline
*/
VOID FcTimeline_Callback_PluginClose(_In_ HANDLE hTimeline)
{
    PFCTIMELINE_PLUGIN_CONTEXT ctxPlugin = (PFCTIMELINE_PLUGIN_CONTEXT)hTimeline;
    sqlite3_exec(ctxPlugin->hSql, "COMMIT TRANSACTION", NULL, NULL, NULL);
    sqlite3_finalize(ctxPlugin->hStmtStr);
    sqlite3_finalize(ctxPlugin->hStmt);
    Fc_SqlReserveReturn(ctxPlugin->hSql);
}

/*
* Callback function to register a new timeline plugin module.
* -- sNameShort = a 6 char non-null terminated string.
* -- szFileUTF8 = utf-8 file name (if exists)
* -- return = handle, should be closed with callback function.
*/
HANDLE FcTimeline_Callback_PluginRegister(_In_reads_(6) LPSTR sNameShort, _In_reads_(32) LPSTR szFileUTF8)
{
    QWORD v;
    sqlite3 *hSql = NULL;
    sqlite3_stmt *hStmt = NULL;
    PFCTIMELINE_PLUGIN_CONTEXT ctxPlugin = NULL;
    if(!(hSql = Fc_SqlReserve())) { goto fail; }
    if(SQLITE_OK != sqlite3_prepare_v2(hSql, "INSERT INTO timeline_info (short_name, file_name_u, file_name_j) VALUES (?, ?, '');", -1, &hStmt, 0)) { goto fail; }
    if(SQLITE_OK != sqlite3_bind_text(hStmt, 1, sNameShort, 6, NULL)) { goto fail; }
    if(SQLITE_OK != sqlite3_bind_text(hStmt, 2, szFileUTF8, -1, NULL)) { goto fail; }
    if(SQLITE_DONE != sqlite3_step(hStmt)) { goto fail; }
    hSql = Fc_SqlReserveReturn(hSql);
    Fc_SqlQueryN("SELECT MAX(id) FROM timeline_info;", 0, NULL, 1, &v, NULL);
    if(!(ctxPlugin = LocalAlloc(LMEM_ZEROINIT, sizeof(FCTIMELINE_PLUGIN_CONTEXT)))) { goto fail; }
    ctxPlugin->dwId = (DWORD)v;
    ctxPlugin->hSql = Fc_SqlReserve();
    sqlite3_prepare_v2(ctxPlugin->hSql, "INSERT INTO timeline_data (id_str, tp, ft, ac, pid, data32, data64) VALUES (?, ?, ?, ?, ?, ?, ?);", -1, &ctxPlugin->hStmt, NULL);
    sqlite3_prepare_v2(ctxPlugin->hSql, "INSERT INTO str (id, cbu, cbj, sz) VALUES (?, ?, ?, ?);", -1, &ctxPlugin->hStmtStr, NULL);
    sqlite3_exec(ctxPlugin->hSql, "BEGIN TRANSACTION", NULL, NULL, NULL);
fail:
    sqlite3_finalize(hStmt);
    if(ctxPlugin) {
        return (HANDLE)ctxPlugin;
    }
    Fc_SqlReserveReturn(hSql);
    return NULL;
}

/*
* Initialize the timelining functionality. Before the timelining functionality
* is initialized processes, threads, registry and ntfs must be initialized.
* Initialization may take some time.
* -- return
*/
_Success_(return)
BOOL FcTimeline_Initialize()
{
    BOOL fResult = FALSE;
    int rc;
    DWORD i;
    QWORD k, v = 0;
    sqlite3 *hSql = NULL;
    sqlite3_stmt *hStmt = NULL;
    PFC_TIMELINE_INFO pi;
    LPSTR szTIMELINE_SQL1[] = {
        // populate timeline_info with basic information:
        "DROP TABLE IF EXISTS timeline_info;",
        "CREATE TABLE timeline_info (id INTEGER PRIMARY KEY, short_name TEXT, file_name_u TEXT, file_name_j TEXT, file_size_u INTEGER DEFAULT 0, file_size_j INTEGER DEFAULT 0);",
        "INSERT INTO timeline_info VALUES(0, ''    , 'timeline_all.txt',      'timeline_all.json',      0, 0); ",
        // populate timeline_data temporary table - with basic data.
        "DROP TABLE IF EXISTS timeline_data;",
        "CREATE TABLE timeline_data ( id INTEGER PRIMARY KEY AUTOINCREMENT, id_str INTEGER, tp INT, ft INTEGER, ac INT, pid INT, data32 INT, data64 INTEGER );"
    };
    for(i = 0; i < sizeof(szTIMELINE_SQL1) / sizeof(LPCSTR); i++) {
        if(SQLITE_OK != (rc = Fc_SqlExec(szTIMELINE_SQL1[i]))) {
            vmmprintf_fn("FAIL INITIALIZE TIMELINE WITH SQLITE ERROR CODE %i, QUERY: %s\n", rc, szTIMELINE_SQL1[i]);
            goto fail;
        }
    }
    // populate timeline_data temporary table - with plugins.
    PluginManager_FcTimeline(FcTimeline_Callback_PluginRegister, FcTimeline_Callback_PluginClose, FcTimeline_Callback_PluginEntryAdd, FcTimeline_Callback_PluginEntryAddBySQL);
    LPSTR szTIMELINE_SQL2[] = {
        // populate main timeline table:
        "DROP TABLE IF EXISTS timeline;",
        "DROP VIEW IF EXISTS v_timeline;",
        "CREATE TABLE timeline ( id INTEGER PRIMARY KEY AUTOINCREMENT, tp INT, tp_id INTEGER, id_str INTEGER, ft INTEGER, ac INT, pid INT, data32 INT, data64 INTEGER, oln_u INTEGER, oln_j INTEGER, oln_utp INTEGER );"
        "CREATE VIEW v_timeline AS SELECT * FROM timeline, str WHERE timeline.id_str = str.id;",
        "CREATE UNIQUE INDEX idx_timeline_tpid     ON timeline(tp, tp_id);",
        "CREATE UNIQUE INDEX idx_timeline_oln_u    ON timeline(oln_u);",
        "CREATE UNIQUE INDEX idx_timeline_oln_j    ON timeline(oln_j);"
        "CREATE UNIQUE INDEX idx_timeline_oln_utp  ON timeline(tp, oln_utp);",
        "INSERT INTO timeline (tp, tp_id, id_str, ft, ac, pid, data32, data64, oln_u, oln_j, oln_utp) SELECT td.tp, (SUM(1) OVER (PARTITION BY td.tp ORDER BY td.ft DESC, td.id)), td.id_str, td.ft, td.ac, td.pid, td.data32, td.data64, (SUM(str.cbu+"STRINGIZE(FC_LINELENGTH_TIMELINE_UTF8)")  OVER (ORDER BY td.ft DESC, td.id) - str.cbu-"STRINGIZE(FC_LINELENGTH_TIMELINE_UTF8)"), (SUM(str.cbj+"STRINGIZE(FC_LINELENGTH_TIMELINE_JSON)") OVER (ORDER BY td.ft DESC, td.id) - str.cbj-"STRINGIZE(FC_LINELENGTH_TIMELINE_JSON)"), (SUM(str.cbu+"STRINGIZE(FC_LINELENGTH_TIMELINE_UTF8)")  OVER (PARTITION BY td.tp ORDER BY td.ft DESC, td.id) - str.cbu-"STRINGIZE(FC_LINELENGTH_TIMELINE_UTF8)") FROM timeline_data td, str WHERE str.id = td.id_str ORDER BY td.ft DESC, td.id;",
        "DROP TABLE timeline_data;"
        // update timeline_info with sizes for 'all' file (utf8 and json).
        "UPDATE timeline_info SET file_size_u = (SELECT oln_u+cbu+"STRINGIZE(FC_LINELENGTH_TIMELINE_UTF8)" AS cbu_tot FROM v_timeline WHERE id = (SELECT MAX(id) FROM v_timeline)) WHERE id = 0;",
        "UPDATE timeline_info SET file_size_j = (SELECT oln_j+cbj+"STRINGIZE(FC_LINELENGTH_TIMELINE_JSON)" AS cbj_tot FROM v_timeline WHERE id = (SELECT MAX(id) FROM v_timeline)) WHERE id = 0;",
    };
    for(i = 0; i < sizeof(szTIMELINE_SQL2) / sizeof(LPCSTR); i++) {
        if(SQLITE_OK != (rc = Fc_SqlExec(szTIMELINE_SQL2[i]))) {
            vmmprintf_fn("FAIL INITIALIZE TIMELINE WITH SQLITE ERROR CODE %i, QUERY: %s\n", rc, szTIMELINE_SQL2[i]);
            goto fail;
        }
    }
    // update progress percent counter.
    ctxFc->cProgressPercent = 80;
    // update timeline_info with sizes for individual types for utf-8 only.
    LPSTR szTIMELINE_SQL_TIMELINE_UPD_UTF8 =
        "UPDATE timeline_info SET file_size_u = IFNULL((SELECT oln_utp+cbu+"STRINGIZE(FC_LINELENGTH_TIMELINE_UTF8)" FROM v_timeline WHERE tp = ? AND tp_id = (SELECT MAX(tp_id) FROM v_timeline WHERE tp = ?)), 0) WHERE id = ?;";
    Fc_SqlQueryN("SELECT MAX(id) FROM timeline_info;", 0, NULL, 1, &v, NULL);
    ctxFc->Timeline.cTp = (DWORD)v + 1;
    for(k = 1; k < ctxFc->Timeline.cTp; k++) {
        if(SQLITE_DONE != (rc = Fc_SqlQueryN(szTIMELINE_SQL_TIMELINE_UPD_UTF8, 3, (QWORD[]) { k, k, k }, 0, NULL, NULL))) {
            vmmprintf_fn("FAIL INITIALIZE TIMELINE WITH SQLITE ERROR CODE %i, QUERY: %s\n", rc, szTIMELINE_SQL_TIMELINE_UPD_UTF8);
            goto fail;
        }
    }
    // populate timeline info struct
    if(!(ctxFc->Timeline.pInfo = LocalAlloc(LMEM_ZEROINIT, (ctxFc->Timeline.cTp) * sizeof(FC_TIMELINE_INFO)))) { goto fail; }
    if(!(hSql = Fc_SqlReserve())) { goto fail; }
    if(SQLITE_OK != sqlite3_prepare_v2(hSql, "SELECT * FROM timeline_info", -1, &hStmt, 0)) { goto fail; }
    for(i = 0; i < ctxFc->Timeline.cTp; i++) {
        pi = ctxFc->Timeline.pInfo + i;
        if(SQLITE_ROW != sqlite3_step(hStmt)) { goto fail; }
        pi->dwId = sqlite3_column_int(hStmt, 0);
        pi->szNameShort[0] = 0;
        strncpy_s(pi->szNameShort, _countof(pi->szNameShort), sqlite3_column_text(hStmt, 1), _TRUNCATE);
        pi->szNameShort[_countof(pi->szNameShort) - 1] = 0;
        strncpy_s(pi->uszNameFile, _countof(pi->uszNameFile), sqlite3_column_text(hStmt, 2), _TRUNCATE);
        pi->dwFileSizeUTF8 = sqlite3_column_int(hStmt, 4);
        pi->dwFileSizeJSON = sqlite3_column_int(hStmt, 5);
    }
    fResult = TRUE;
fail:
    sqlite3_finalize(hStmt);
    Fc_SqlReserveReturn(hSql);
    return fResult;
}

#define FCTIMELINE_SQL_SELECT_FIELDS_ALL " cbu, sz,    id, ft, tp, ac, pid, data32, data64, oln_u,   oln_j   "
#define FCTIMELINE_SQL_SELECT_FIELDS_TP  " cbu, sz, tp_id, ft, tp, ac, pid, data32, data64, oln_utp, 0 "

/*
* Internal function to create a PFCOB_MAP_TIMELINE map from given sql queries.
* -- szSqlCount
* -- szSqlSelect
* -- cQueryValues
* -- pqwQueryValues
* -- ppObNtfsMap
* -- return
*/
_Success_(return)
BOOL FcTimelineMap_CreateInternal(_In_ LPSTR szSqlCount, _In_ LPSTR szSqlSelect, _In_ DWORD cQueryValues, _In_reads_(cQueryValues) PQWORD pqwQueryValues, _Out_ PFCOB_MAP_TIMELINE *ppObNtfsMap)
{
    int rc;
    QWORD pqwResult[2];
    DWORD i, cchMultiText;
    LPSTR szuMultiText, szuEntryText;
    PFCOB_MAP_TIMELINE pObTimelineMap = NULL;
    PFC_MAP_TIMELINEENTRY pe;
    sqlite3 *hSql = NULL;
    sqlite3_stmt *hStmt = NULL;
    rc = Fc_SqlQueryN(szSqlCount, cQueryValues, pqwQueryValues, 2, pqwResult, NULL);
    if((rc != SQLITE_OK) || (pqwResult[0] > 0x00010000) || (pqwResult[1] > 0x01000000)) { goto fail; }
    cchMultiText = (DWORD)(1 + 2 * pqwResult[0] + pqwResult[1]);
    pObTimelineMap = Ob_Alloc('Mtml', LMEM_ZEROINIT, sizeof(FCOB_MAP_TIMELINE) + pqwResult[0] * sizeof(FC_MAP_TIMELINEENTRY) + cchMultiText, NULL, NULL);
    if(!pObTimelineMap) { goto fail; }
    pObTimelineMap->uszMultiText = (LPSTR)((PBYTE)pObTimelineMap + sizeof(FCOB_MAP_TIMELINE) + pqwResult[0] * sizeof(FC_MAP_TIMELINEENTRY));
    pObTimelineMap->cbuMultiText = cchMultiText;
    pObTimelineMap->cMap = (DWORD)pqwResult[0];
    cchMultiText--;
    szuMultiText = pObTimelineMap->uszMultiText + 1;
    if(!(hSql = Fc_SqlReserve())) { goto fail; }
    rc = sqlite3_prepare_v2(hSql, szSqlSelect, -1, &hStmt, 0);
    if(rc != SQLITE_OK) { goto fail; }
    for(i = 0; i < cQueryValues; i++) {
        sqlite3_bind_int64(hStmt, i + 1, pqwQueryValues[i]);
    }
    for(i = 0; i < pObTimelineMap->cMap; i++) {
        rc = sqlite3_step(hStmt);
        if(rc != SQLITE_ROW) { goto fail; }
        pe = pObTimelineMap->pMap + i;
        // populate text related data: path+name
        pe->cuszText = sqlite3_column_int(hStmt, 0);
        szuEntryText = (LPSTR)sqlite3_column_text(hStmt, 1);
        if(!szuEntryText || (pe->cuszText != strlen(szuEntryText)) || (pe->cuszText > cchMultiText - 1)) { goto fail; }
        pe->uszText = szuMultiText;
        memcpy(szuMultiText, szuEntryText, pe->cuszText);
        szuMultiText = szuMultiText + pe->cuszText + 1;
        cchMultiText += pe->cuszText + 1;
        // populate numeric data
        pe->id = sqlite3_column_int64(hStmt, 2);
        pe->ft = sqlite3_column_int64(hStmt, 3);
        pe->tp = sqlite3_column_int(hStmt, 4);
        pe->ac = sqlite3_column_int(hStmt, 5);
        pe->pid = sqlite3_column_int(hStmt, 6);
        pe->data32 = sqlite3_column_int(hStmt, 7);
        pe->data64 = sqlite3_column_int64(hStmt, 8);
        pe->cuszOffset = sqlite3_column_int64(hStmt, 9);
        pe->cjszOffset = sqlite3_column_int64(hStmt, 10);
    }
    Ob_INCREF(pObTimelineMap);
fail:
    sqlite3_finalize(hStmt);
    Fc_SqlReserveReturn(hSql);
    *ppObNtfsMap = Ob_DECREF(pObTimelineMap);
    return (*ppObNtfsMap != NULL);
}

/*
* Retrieve a timeline map object consisting of timeline data.
* -- dwTimelineType = the timeline type, 0 for all.
* -- qwId = the minimum timeline id of the entries to retrieve.
* -- cId = the number of timeline entries to retrieve.
* -- ppObTimelineMap
* -- return
*/
_Success_(return)
BOOL FcTimelineMap_GetFromIdRange(_In_ DWORD dwTimelineType, _In_ QWORD qwId, _In_ QWORD cId, _Out_ PFCOB_MAP_TIMELINE * ppObTimelineMap)
{
    QWORD v[] = { qwId, qwId + cId, dwTimelineType };
    DWORD iSQL = dwTimelineType ? 2 : 0;
    LPSTR szSQL[] = {
        "SELECT COUNT(*), SUM(cbu) FROM v_timeline WHERE id >= ? AND id < ?",
        "SELECT "FCTIMELINE_SQL_SELECT_FIELDS_ALL" FROM v_timeline WHERE id >= ? AND id < ? ORDER BY id",
        "SELECT COUNT(*), SUM(cbu) FROM v_timeline WHERE tp_id >= ? AND tp_id < ? AND tp = ?",
        "SELECT "FCTIMELINE_SQL_SELECT_FIELDS_TP" FROM v_timeline WHERE tp_id >= ? AND tp_id < ? AND tp = ? ORDER BY tp_id"
    };
    return FcTimelineMap_CreateInternal(szSQL[iSQL], szSQL[iSQL + 1], (dwTimelineType ? 3 : 2), v, ppObTimelineMap);
}

/*
* Retrieve the minimum timeline id that exists within a byte range inside a
* timeline file of a specific type.
* -- dwTimelineType = the timeline type, 0 for all - has no meaning in json mode.
* -- fJSON = is JSON type, otherwise UTF8 type.
* -- qwFilePos = the file position.
* -- pqwId = pointer to receive the result id.
* -- return
*/
_Success_(return)
BOOL FcTimeline_GetIdFromPosition(_In_ DWORD dwTimelineType, _In_ BOOL fJSON, _In_ QWORD qwFilePos, _Out_ PQWORD pqwId)
{
    QWORD v[] = { max(2048, qwFilePos) - 2048, qwFilePos, dwTimelineType };
    DWORD iSQL = fJSON ? 1 : ((dwTimelineType ? 2 : 0));
    LPSTR szSQL[3] = {
        "SELECT MAX(id) FROM timeline WHERE oln_u >= ? AND oln_u <= ?",
        "SELECT MAX(id) FROM timeline WHERE oln_j >= ? AND oln_j <= ?",
        "SELECT MAX(tp_id) FROM timeline WHERE oln_utp >= ? AND oln_utp <= ? AND tp = ?"
    };
    return (SQLITE_OK == Fc_SqlQueryN(szSQL[iSQL], (dwTimelineType ? 3 : 2), v, 1, pqwId, NULL));
}



// ----------------------------------------------------------------------------
// PHYSICAL MEMORY SCAN FUNCTIONALITY BELOW:
// Physical memory is scanned and analyzed in parallel via registered plugins
// though the plugin manager - such as, but not limited to, NTFS plugin.
// ----------------------------------------------------------------------------

typedef struct tdFC_SCANPHYSMEM_CONTEXT {
    HANDLE hEvent;
    VMMDLL_PLUGIN_FORENSIC_INGEST_PHYSMEM e;
} FC_SCANPHYSMEM_CONTEXT, *PFC_SCANPHYSMEM_CONTEXT;


VOID FcScanPhysmem_ThreadProc(_Inout_ PVMMDLL_PLUGIN_FORENSIC_INGEST_PHYSMEM ctx)
{
    DWORD dwPfnBase, cbPfnMap;
    QWORD i, pa;
    BOOL fValidMEMs, fValidAddr;
    PDWORD pPfns = NULL;
    PVMMDLL_MAP_PFNENTRY pePfn;
    ctx->fValid = FALSE;
    // 1: fetch and setup PFN map by calling VMMDLL API
    //    (somewhat ugly to call external api, but it provides required data).
    if(!ctxVmm->Work.fEnabled) { goto fail; }
    dwPfnBase = (DWORD)(ctx->paBase >> 12);
    if(!(pPfns = LocalAlloc(0, FC_PHYSMEM_NUM_CHUNKS * sizeof(DWORD)))) { goto fail; }
    for(i = 0; i < FC_PHYSMEM_NUM_CHUNKS; i++) {
        pPfns[i] = dwPfnBase + (DWORD)i;
    }
    cbPfnMap = sizeof(VMMDLL_MAP_PFN) + FC_PHYSMEM_NUM_CHUNKS * sizeof(VMMDLL_MAP_PFNENTRY);
    if(!VMMDLL_Map_GetPfn(pPfns, FC_PHYSMEM_NUM_CHUNKS, ctx->pPfnMap, &cbPfnMap)) { goto fail; }
    if(ctx->pPfnMap->cMap < FC_PHYSMEM_NUM_CHUNKS) { goto fail; }
    // 2: set up MEMs
    if(!ctxVmm->Work.fEnabled) { goto fail; }
    for(i = 0, fValidMEMs = FALSE; i < FC_PHYSMEM_NUM_CHUNKS; i++) {
        pa = ctx->paBase + (i << 12);
        fValidAddr = (pa <= ctxMain->dev.paMax);
        if(fValidAddr) {
            pePfn = &ctx->pPfnMap->pMap[i];
            fValidAddr =
                (pePfn->PageLocation == MmPfnTypeStandby) ||
                (pePfn->PageLocation == MmPfnTypeModified) ||
                (pePfn->PageLocation == MmPfnTypeModifiedNoWrite) ||
                (pePfn->PageLocation == MmPfnTypeTransition) ||
                (pePfn->PageLocation == MmPfnTypeActive);
        }
        ctx->ppMEMs[i]->qwA = fValidAddr ? pa : (QWORD)-1;
        ctx->ppMEMs[i]->cb = 0x1000;
        ctx->ppMEMs[i]->f = FALSE;
        fValidMEMs = fValidMEMs || fValidAddr;
    }
    // 3: read physical memory
    if(fValidMEMs) {
        VmmReadScatterPhysical(ctx->ppMEMs, FC_PHYSMEM_NUM_CHUNKS, VMM_FLAG_NOCACHEPUT);
    }
    ctx->fValid = TRUE;
fail:
    LocalFree(pPfns);
}

/*
* Physical Memory Scan Loop - function is meant to be running in asynchronously
* with one thread calling only. The function allocates two 16MB chunks and will
* begin to loop-read physical memory into chunks (in separate thread) and call
* the plugin manager for processing by forensic consumer plugins.
*/
VOID FcScanPhysmem()
{
    QWORD i, iChunk = 0, paBase;
    FC_SCANPHYSMEM_CONTEXT ctx2[2] = { 0 };
    PFC_SCANPHYSMEM_CONTEXT ctx;
    // 1: initialize two 16MB physical memory scan chunks
    for(i = 0; i < 2; i++) {
        ctx = ctx2 + i;
        if(!(ctx->hEvent = CreateEvent(NULL, TRUE, TRUE, NULL))) { goto fail; }
        if(!LcAllocScatter1(FC_PHYSMEM_NUM_CHUNKS, &ctx->e.ppMEMs)) { goto fail; }
        if(!(ctx->e.pPfnMap = LocalAlloc(LMEM_ZEROINIT, sizeof(VMMDLL_MAP_PFN) + FC_PHYSMEM_NUM_CHUNKS * sizeof(VMMDLL_MAP_PFNENTRY)))) { goto fail; }
        ctx->e.cMEMs = FC_PHYSMEM_NUM_CHUNKS;
    }
    // 2: main physical memory scan loop
    for(paBase = 0; paBase < ctxMain->dev.paMax; paBase += 0x1000 * FC_PHYSMEM_NUM_CHUNKS) {
        iChunk++;
        if(!ctxVmm->Work.fEnabled) { goto fail; }
        vmmprintfvv_fn("PhysicalAddress=%016llx\n", paBase);
        // 2.1: fetch new physical data in separate thread:
        ctx = ctx2 + (iChunk % 2);
        ctx->e.paBase = paBase;
        ResetEvent(ctx->hEvent);
        VmmWork((LPTHREAD_START_ROUTINE)FcScanPhysmem_ThreadProc, &ctx->e, ctx->hEvent);
        // 2.2: process previously scheduled work item (unless first):
        if(paBase == 0) { continue; }
        ctx = ctx2 + ((iChunk - 1) % 2);
        WaitForSingleObject(ctx->hEvent, INFINITE);
        if(!ctxVmm->Work.fEnabled) { goto fail; }
        if(ctx->e.fValid) {
            PluginManager_FcIngestPhysmem(&ctx->e);
        }
        ctxFc->cProgressPercent = 10 + (BYTE)((50 * paBase) / ctxMain->dev.paMax);
    }
    // 2.3: process last read chunk
    if(iChunk) {
        ctx = ctx2 + ((iChunk - 1) % 2);
        WaitForSingleObject(ctx->hEvent, INFINITE);
        if(!ctxVmm->Work.fEnabled) { goto fail; }
        if(ctx->e.fValid) {
            PluginManager_FcIngestPhysmem(&ctx->e);
        }
    }
fail:
    for(i = 0; i < 2; i++) {
        ctx = ctx2 + i;
        if(ctx->hEvent) {
            WaitForSingleObject(ctx->hEvent, INFINITE);
        }
        if(ctx->hEvent) { CloseHandle(ctx->hEvent); }
        LcMemFree(ctx->e.ppMEMs);
        LocalFree(ctx->e.pPfnMap);
    }
}



// ----------------------------------------------------------------------------
// GENERAL JSON DATA LOG BELOW:
// ----------------------------------------------------------------------------

/*
* Callback function to add a json log line to 'general.json'
* -- pDataJSON
*/
VOID FcJson_Callback_EntryAdd(_In_ PVMMDLL_PLUGIN_FORENSIC_JSONDATA pDataJSON)
{
    LPSTR szj;
    QWORD i, o = 0;
    PVMM_PROCESS pObProcess = NULL;
    typedef struct tdBUFFER {
        CHAR szj[0x1000];
        CHAR szln[0x3000];
        // header+type cache
        CHAR szjHdrType[128];
        DWORD dwHdrType;
        DWORD cchHdrType;
        // pid-procname cache
        DWORD dwPID;
        DWORD cchPidProcName;
        CHAR szjProcName[32];
        CHAR szjPidProcName[64];
    } *PBUFFER;
    PBUFFER buf = (PBUFFER)pDataJSON->_Reserved;
    if(pDataJSON->dwVersion != VMMDLL_PLUGIN_FORENSIC_JSONDATA_VERSION) { return; }
    // general/base:
    {
        if(buf->dwHdrType != *(PDWORD)pDataJSON->szjType) {
            buf->dwHdrType = *(PDWORD)pDataJSON->szjType;
            buf->cchHdrType = snprintf(buf->szjHdrType, sizeof(buf->szjHdrType),
                "{\"class\":\"GEN\",\"ver\":\"%i.%i\",\"sys\":\"%s\",\"type\":\"%s\"",
                VERSION_MAJOR, VERSION_MINOR,
                ctxVmm->szSystemUniqueTag,
                pDataJSON->szjType
            );
        }
        memcpy(buf->szln + o, buf->szjHdrType, buf->cchHdrType + 1ULL); o += buf->cchHdrType;
    }
    // pid & process:
    if(pDataJSON->dwPID) {
        if(buf->dwPID != pDataJSON->dwPID) {
            buf->dwPID = pDataJSON->dwPID;
            if((pObProcess = VmmProcessGetEx(NULL, pDataJSON->dwPID, VMM_FLAG_PROCESS_SHOW_TERMINATED))) {
                CharUtil_UtoJ(pObProcess->pObPersistent->uszNameLong, -1, buf->szjProcName, sizeof(buf->szjProcName), &szj, NULL, CHARUTIL_FLAG_TRUNCATE_ONFAIL_NULLSTR);
                buf->cchPidProcName = snprintf(buf->szjPidProcName, sizeof(buf->szjPidProcName), ",\"pid\":%i,\"proc\":\"%s\"", pDataJSON->dwPID, buf->szjProcName);
                Ob_DECREF_NULL(&pObProcess);
            } else {
                buf->cchPidProcName = snprintf(buf->szjPidProcName, sizeof(buf->szjPidProcName), ",\"pid\":%i", pDataJSON->dwPID);
            }
        }
        memcpy(buf->szln + o, buf->szjPidProcName, buf->cchPidProcName + 1ULL); o += buf->cchPidProcName;
    }
    // index:
    o += snprintf(buf->szln + o, sizeof(buf->szln) - o, ",\"i\":%i", pDataJSON->i);
    // obj:
    if(pDataJSON->vaObj) {
        o += snprintf(buf->szln + o, sizeof(buf->szln) - o, ",\"obj\":\"%llx\"", pDataJSON->vaObj);
    }
    // addr:
    for(i = 0; i < 2; i++) {
        if(pDataJSON->fva[i] || pDataJSON->va[i]) {
            o += snprintf(buf->szln + o, sizeof(buf->szln) - o, ",\"addr%s\":\"%llx\"", (i ? "2" : ""), pDataJSON->va[i]);
        }
    }
    // size/num:
    if(pDataJSON->fNum[0] || pDataJSON->qwNum[0]) {
        o += snprintf(buf->szln + o, sizeof(buf->szln) - o, ",\"size\":%lli", pDataJSON->qwNum[0]);
    }
    if(pDataJSON->fNum[1] || pDataJSON->qwNum[1]) {
        o += snprintf(buf->szln + o, sizeof(buf->szln) - o, ",\"num\":%lli", pDataJSON->qwNum[1]);
    }
    // hex:
    for(i = 0; i < 2; i++) {
        if(pDataJSON->fHex[i] || pDataJSON->qwHex[i]) {
            o += snprintf(buf->szln + o, sizeof(buf->szln) - o, ",\"hex%s\":\"%llx\"", (i ? "2" : ""), pDataJSON->qwHex[i]);
        }
    }
    // desc:
    for(i = 0; i < 2; i++) {
        szj = NULL;
        if(pDataJSON->usz[i]) {
            CharUtil_UtoJ((LPSTR)pDataJSON->usz[i], -1, buf->szj, sizeof(buf->szj), &szj, NULL, CHARUTIL_FLAG_TRUNCATE_ONFAIL_NULLSTR);
        } else if(pDataJSON->wsz[i]) {
            CharUtil_WtoJ((LPWSTR)pDataJSON->wsz[i], -1, buf->szj, sizeof(buf->szj), &szj, NULL, CHARUTIL_FLAG_TRUNCATE_ONFAIL_NULLSTR);
        }
        if(szj) {
            o += snprintf(buf->szln + o, sizeof(buf->szln) - o, ",\"desc%s\":\"%s\"", (i ? "2" : ""), szj);
        }
    }
    // commit to json file:
    if(sizeof(buf->szln) - o > 3) {
        memcpy(buf->szln + o, "}\n", 3);
        if(pDataJSON->fVerbose) {
            ObMemFile_AppendString(ctxFc->FileJSON.pGenVerbose, buf->szln);
        } else {
            ObMemFile_AppendString(ctxFc->FileJSON.pGen, buf->szln);
        }
    }
}



// ----------------------------------------------------------------------------
// FORENSIC INITIALIZATION FUNCTIONALITY BELOW:
// ----------------------------------------------------------------------------

/*
* The core asynchronous forensic initialization function.
*/
VOID FcInitialize_ThreadProc(_In_ PVOID pvContext)
{
    PVMMOB_MAP_EVIL pObEvilMap = NULL;
    HANDLE hEventAsyncLogJSON = 0;
    QWORD tmStart = Statistics_CallStart();
    if(SQLITE_OK != Fc_SqlExec(FC_SQL_SCHEMA_STR)) { goto fail; }
    if(!ctxVmm->Work.fEnabled) { goto fail; }
    if(!(hEventAsyncLogJSON = CreateEvent(NULL, TRUE, FALSE, NULL))) { goto fail; }
    PluginManager_Notify(VMMDLL_PLUGIN_NOTIFY_FORENSIC_INIT, NULL, 0);
    VmmMap_GetEvil(NULL, &pObEvilMap);  // start findevil (in 'async' mode)
    Ob_DECREF_NULL(&pObEvilMap);
    PluginManager_FcInitialize();       // 0-10%
    ctxFc->cProgressPercent = 10;
    if(!ctxVmm->Work.fEnabled) { goto fail; }
    VmmWork(
        (LPTHREAD_START_ROUTINE)PluginManager_FcLogJSON,
        FcJson_Callback_EntryAdd,
        hEventAsyncLogJSON
    ); // parallel async init of json log
    FcScanPhysmem();                    // 11-60%
    ctxFc->cProgressPercent = 60;
    if(!ctxVmm->Work.fEnabled) { goto fail; }
    PluginManager_FcIngestFinalize();   // 61-70%
    ctxFc->cProgressPercent = 70;
    if(!ctxVmm->Work.fEnabled) { goto fail; }
    FcTimeline_Initialize();            // 71-90%
    ctxFc->cProgressPercent = 90;
    if(!ctxVmm->Work.fEnabled) { goto fail; }
    WaitForSingleObject(hEventAsyncLogJSON, INFINITE);
    PluginManager_FcFinalize();         // 91-100%
    ctxFc->cProgressPercent = 100;
    ctxFc->db.fSingleThread = FALSE;
    ctxFc->fInitFinish = TRUE;
    PluginManager_Notify(VMMDLL_PLUGIN_NOTIFY_FORENSIC_INIT, NULL, 100);
    PluginManager_Notify(VMMDLL_PLUGIN_NOTIFY_FORENSIC_INIT_COMPLETE, NULL, 0);
    Statistics_CallEnd(STATISTICS_ID_FORENSIC_FcInitialize, tmStart);
fail:
    if(hEventAsyncLogJSON) { CloseHandle(hEventAsyncLogJSON); }
    if(ctxFc->cProgressPercent != 100) {
        ctxFc->cProgressPercent = 0;
    }
}

/*
* Close the forensic sub-system.
*/
VOID FcClose()
{
    DWORD i;
    if(!ctxFc) { return; }
    EnterCriticalSection(&ctxFc->Lock);
    for(i = 0; i < FC_SQL_POOL_CONNECTION_NUM; i++) {
        if(ctxFc->db.hEvent[i]) {
            WaitForSingleObject(ctxFc->db.hEvent[i], INFINITE);
            CloseHandle(ctxFc->db.hEvent[i]);
            ctxFc->db.hEvent[i] = NULL;
        }
        if(ctxFc->db.hSql[i]) { sqlite3_close(ctxFc->db.hSql[i]); }
    }
    if(ctxFc->db.tp == FC_DATABASE_TYPE_TEMPFILE_CLOSE) {
        Util_DeleteFileU(ctxFc->db.uszDatabasePath);
    }
    Ob_DECREF_NULL(&ctxFc->FileJSON.pGen);
    Ob_DECREF_NULL(&ctxFc->FileJSON.pGenVerbose);
    Ob_DECREF_NULL(&ctxFc->FileJSON.pReg);
    LocalFree(ctxFc->Timeline.pInfo);
    LeaveCriticalSection(&ctxFc->Lock);
    DeleteCriticalSection(&ctxFc->Lock);
}

/*
* Helper function to set the path of the database file.
* The different paths are saved to the global ctxFc.
* -- dwDatabaseType = database type as specified by: FC_DATABASE_TYPE_*
* -- return
*/
_Success_(return)
BOOL FcInitialize_SetPath(_In_ DWORD dwDatabaseType)
{
    DWORD i, cch;
    CHAR uszTemp[MAX_PATH];
    WCHAR wszTemp[MAX_PATH], wszTempShort[MAX_PATH];
    SYSTEMTIME st;
    if(dwDatabaseType == FC_DATABASE_TYPE_MEMORY) {
        ctxFc->db.tp = FC_DATABASE_TYPE_MEMORY;
        strcpy_s(ctxFc->db.szuDatabase, _countof(ctxFc->db.szuDatabase), "file:///memorydb?mode=memory");
        return TRUE;
    }
#ifdef _WIN32
    cch = GetTempPathW(_countof(wszTempShort), wszTempShort);
    if(!cch || cch > 128) { return FALSE; }
    cch = GetLongPathNameW(wszTempShort, wszTemp, _countof(wszTemp));
    if(!cch || cch > 128) { return FALSE; }
    if(!CharUtil_WtoU(wszTemp, -1, uszTemp, sizeof(uszTemp), NULL, NULL, CHARUTIL_FLAG_STR_BUFONLY)) { return FALSE; }
#endif /* _WIN32 */
#ifdef LINUX
    strcpy_s(uszTemp, sizeof(uszTemp), "/tmp/");
#endif /* LINUX */
    if((dwDatabaseType == FC_DATABASE_TYPE_TEMPFILE_CLOSE) || (dwDatabaseType == FC_DATABASE_TYPE_TEMPFILE_NOCLOSE)) {
        GetLocalTime(&st);
        _snprintf_s(
            uszTemp + strlen(uszTemp),
            _countof(uszTemp) - strlen(uszTemp),
            _TRUNCATE,
            "vmm-%i%02i%02i-%02i%02i%02i.sqlite3",
            st.wYear,
            st.wMonth,
            st.wDay,
            st.wHour,
            st.wMinute,
            st.wSecond);
    } else {
        strcat_s(uszTemp, _countof(wszTemp), "vmm.sqlite3");
    }
    // check length, copy into ctxFc and finish
    if(strlen(uszTemp) > MAX_PATH - 10) { return FALSE; }
    strncpy_s(ctxFc->db.uszDatabasePath, _countof(ctxFc->db.uszDatabasePath), uszTemp, _TRUNCATE);
    for(i = 0; i < MAX_PATH; i++) {
        if(uszTemp[i] == '\\') { uszTemp[i] = '/'; }
    }
    strcpy_s(ctxFc->db.szuDatabase, _countof(ctxFc->db.szuDatabase), "file:///");
    strncpy_s(ctxFc->db.szuDatabase + 8, _countof(ctxFc->db.szuDatabase) - 8, uszTemp, _TRUNCATE);
    ctxFc->db.tp = dwDatabaseType;
    return TRUE;
}

/*
* Core non-threaded forensic initialization function. Allocates and sets up the
* database and kicks off an asynchronous initialization thread for the rest of
* the forensic activities.
* -- dwDatabaseType
* -- fForceReInit
* -- return
*/
_Success_(return)
BOOL FcInitialize_Impl(_In_ DWORD dwDatabaseType, _In_ BOOL fForceReInit)
{
    DWORD i;
    if(ctxMain->dev.fVolatile) {
        vmmprintf("WARNING: FORENSIC mode on volatile memory is not recommended due to memory drift/smear.\n");
    }
    if(!dwDatabaseType || (dwDatabaseType > FC_DATABASE_TYPE_MAX)) { return FALSE; }
    if(ctxFc && !fForceReInit) { return FALSE; }
    PDB_Initialize_WaitComplete();
    // 1: ALLOCATE AND INITIALIZE.
    if(ctxFc) { FcClose(); }
    if(!(ctxFc = (PFC_CONTEXT)LocalAlloc(LMEM_ZEROINIT, sizeof(FC_CONTEXT)))) { goto fail; }
    InitializeCriticalSection(&ctxFc->Lock);
    if(!(ctxFc->FileJSON.pGen = ObMemFile_New())) { goto fail; }
    if(!(ctxFc->FileJSON.pGenVerbose = ObMemFile_New())) { goto fail; }
    if(!(ctxFc->FileJSON.pReg = ObMemFile_New())) { goto fail; }
    // 2: SQLITE INIT:
    if(SQLITE_CONFIG_MULTITHREAD != sqlite3_threadsafe()) {
        vmmprintf_fn("CRITICAL: WRONG SQLITE THREADING MODE - TERMINATING!\n");
        ExitProcess(0);
    }
    if(!FcInitialize_SetPath(dwDatabaseType)) {
        vmmprintf("FORENSIC: Fail. Unable to set Sqlite path.\n");
        goto fail;
    }
    ctxFc->db.fSingleThread = TRUE;     // single thread during INSERT-bound init phase
    for(i = 0; i < FC_SQL_POOL_CONNECTION_NUM; i++) {
        if(!(ctxFc->db.hEvent[i] = CreateEvent(NULL, FALSE, TRUE, NULL))) { goto fail; }
        if(SQLITE_OK != sqlite3_open_v2(ctxFc->db.szuDatabase, &ctxFc->db.hSql[i], SQLITE_OPEN_URI | SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_SHAREDCACHE | SQLITE_OPEN_NOMUTEX, NULL)) { goto fail; }
    }
    VmmWork((LPTHREAD_START_ROUTINE)FcInitialize_ThreadProc, NULL, 0);
    ctxFc->fInitStart = TRUE;
    return TRUE;
fail:
    FcClose();
    return FALSE;
}

/*
* Initialize (or re-initialize) the forensic sub-system.
* -- dwDatabaseType = database type as specified by: FC_DATABASE_TYPE_*
* -- fForceReInit
* -- return
*/
_Success_(return)
BOOL FcInitialize(_In_ DWORD dwDatabaseType, _In_ BOOL fForceReInit)
{
    BOOL fResult;
    EnterCriticalSection(&ctxVmm->LockMaster);
    fResult = FcInitialize_Impl(dwDatabaseType, FALSE);
    LeaveCriticalSection(&ctxVmm->LockMaster);
    return fResult;
}
