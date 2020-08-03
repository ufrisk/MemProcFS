// fc_timeline.c : implementation of functions related to timelining.
//
// The timeline initialization should be run after all other forensic database
// table populating actions have been run. The initialization process merges
// various results into multiple timelines mostly by relying on sqlite queries.
// Once the timeline is initialized various modules may query the timeline.
//
// (c) Ulf Frisk, 2020
// Author: Ulf Frisk, pcileech@frizk.net
//
#include "fc.h"
#include "pluginmanager.h"

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
VOID FcTimeline_Callback_PluginAddEntry(_In_ HANDLE hTimeline, _In_ QWORD ft, _In_ DWORD dwAction, _In_ DWORD dwPID, _In_ QWORD qwValue, _In_ LPWSTR wszText)
{
    PFCTIMELINE_PLUGIN_CONTEXT ctxPlugin = (PFCTIMELINE_PLUGIN_CONTEXT)hTimeline;
    FCSQL_INSERTSTRTABLE SqlStrInsert;
    // build and insert string data into 'str' table.
    if(!Fc_SqlInsertStr(ctxPlugin->hStmtStr, wszText, 0, &SqlStrInsert)) { return; }
    // insert into 'timeline_data' table.
    sqlite3_reset(ctxPlugin->hStmt);
    Fc_SqlBindMultiInt64(ctxPlugin->hStmt, 1, 6,
        SqlStrInsert.id,
        (QWORD)ctxPlugin->dwId,
        ft,
        (QWORD)dwAction,
        (QWORD)dwPID,
        qwValue
    );
    sqlite3_step(ctxPlugin->hStmt);
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
* -- szFileJSON = utf-8 file name (if exists)
* -- return = handle, should be closed with callback function.
*/
HANDLE FcTimeline_Callback_PluginRegister(_In_reads_(6) LPSTR sNameShort, _In_reads_(32) LPSTR szFileUTF8, _In_reads_(32) LPSTR szFileJSON)
{
    QWORD v;
    sqlite3 *hSql = NULL;
    sqlite3_stmt *hStmt = NULL;
    PFCTIMELINE_PLUGIN_CONTEXT ctxPlugin = NULL;
    if(!(hSql = Fc_SqlReserve())) { goto fail; }
    if(SQLITE_OK != sqlite3_prepare_v2(hSql, "INSERT INTO timeline_info (short_name, file_name_u, file_name_j) VALUES (?, ?, ?);", -1, &hStmt, 0)) { goto fail; }
    if(SQLITE_OK != sqlite3_bind_text(hStmt, 1, sNameShort, 6, NULL)) { goto fail; }
    if(SQLITE_OK != sqlite3_bind_text(hStmt, 2, szFileUTF8, -1, NULL)) { goto fail; }
    if(SQLITE_OK != sqlite3_bind_text(hStmt, 3, szFileJSON, -1, NULL)) { goto fail; }
    if(SQLITE_DONE != sqlite3_step(hStmt)) { goto fail; }
    hSql = Fc_SqlReserveReturn(hSql);
    Fc_SqlQueryN("SELECT MAX(id) FROM timeline_info;", 0, NULL, 1, &v, NULL);
    if(!(ctxPlugin = LocalAlloc(LMEM_ZEROINIT, sizeof(FCTIMELINE_PLUGIN_CONTEXT)))) { goto fail; }
    ctxPlugin->dwId = (DWORD)v;
    ctxPlugin->hSql = Fc_SqlReserve();
    sqlite3_prepare_v2(ctxPlugin->hSql, "INSERT INTO timeline_data (id_str, tp, ft, ac, pid, data64) VALUES (?, ?, ?, ?, ?, ?);", -1, &ctxPlugin->hStmt, NULL);
    sqlite3_prepare_v2(ctxPlugin->hSql, "INSERT INTO str (id, osz, csz, cbu, cbj, sz) VALUES (?, ?, ?, ?, ?, ?);", -1, &ctxPlugin->hStmtStr, NULL);
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
    BOOL f, fResult = FALSE;
    int rc;
    DWORD i, j;
    QWORD k, v = 0;
    sqlite3 *hSql = NULL;
    sqlite3_stmt *hStmt = NULL;
    PFC_TIMELINE_INFO pi;
    LPSTR szTIMELINE_SQL1[] = {
        // populate timeline_info with basic information:
        "DROP TABLE IF EXISTS timeline_info;",
        "CREATE TABLE timeline_info (id INTEGER PRIMARY KEY, short_name TEXT, file_name_u TEXT, file_name_j TEXT, file_size_u INTEGER DEFAULT 0, file_size_j INTEGER DEFAULT 0);",
        "INSERT INTO timeline_info VALUES(0, ''    , 'timeline_all.txt',      'timeline_all.json',      0, 0); ",
        "INSERT INTO timeline_info VALUES(1, 'PROC', 'timeline_process.txt',  'timeline_process.json',  0, 0); ",
        "INSERT INTO timeline_info VALUES(2, 'THRD', 'timeline_thread.txt',   'timeline_thread.json',   0, 0); ",
        "INSERT INTO timeline_info VALUES(3, 'REG' , 'timeline_registry.txt', 'timeline_registry.json', 0, 0); ",
        "INSERT INTO timeline_info VALUES(4, 'NTFS', 'timeline_ntfs.txt',     'timeline_ntfs.json',     0, 0); ",
        // populate timeline_data temporary table - with basic data.
        "DROP TABLE IF EXISTS timeline_data;",
        "CREATE TABLE timeline_data ( id INTEGER PRIMARY KEY AUTOINCREMENT, id_str INTEGER, tp INT, ft INTEGER, ac INT, pid INT, data64 INTEGER );",
        "INSERT INTO timeline_data (id_str, tp, ft, ac, pid, data64) SELECT id_str_all, 1, time_create, "STRINGIZE(FC_TIMELINE_ACTION_CREATE)", pid, eprocess FROM process WHERE time_create > 0;",
        "INSERT INTO timeline_data (id_str, tp, ft, ac, pid, data64) SELECT id_str_all, 1, time_exit,   "STRINGIZE(FC_TIMELINE_ACTION_DELETE)", pid, eprocess FROM process WHERE time_exit > 0;",
        "INSERT INTO timeline_data (id_str, tp, ft, ac, pid, data64) SELECT id_str,     2, time_create, "STRINGIZE(FC_TIMELINE_ACTION_CREATE)", pid, ethread FROM thread WHERE time_create > 0;",
        "INSERT INTO timeline_data (id_str, tp, ft, ac, pid, data64) SELECT id_str,     2, time_exit,   "STRINGIZE(FC_TIMELINE_ACTION_DELETE)", pid, ethread FROM thread WHERE time_exit > 0;",
        "INSERT INTO timeline_data (id_str, tp, ft, ac, pid, data64) SELECT id_str,     3, time,        "STRINGIZE(FC_TIMELINE_ACTION_MODIFY)", 0, 0 FROM registry WHERE time > 0;",
        "INSERT INTO timeline_data (id_str, tp, ft, ac, pid, data64) SELECT id_str,     4, time_create, "STRINGIZE(FC_TIMELINE_ACTION_CREATE)", 0, size_file FROM ntfs WHERE time_create > 0;",
        "INSERT INTO timeline_data (id_str, tp, ft, ac, pid, data64) SELECT id_str,     4, time_modify, "STRINGIZE(FC_TIMELINE_ACTION_MODIFY)", 0, size_file FROM ntfs WHERE time_modify > 0 AND time_modify != time_create;",
        "INSERT INTO timeline_data (id_str, tp, ft, ac, pid, data64) SELECT id_str,     4, time_read,   "STRINGIZE(FC_TIMELINE_ACTION_READ)"  , 0, size_file FROM ntfs WHERE time_read   > 0 AND time_read != time_create AND time_read != time_modify;"
    };
    for(i = 0; i < sizeof(szTIMELINE_SQL1) / sizeof(LPCSTR); i++) {
        if(SQLITE_OK != (rc = Fc_SqlExec(szTIMELINE_SQL1[i]))) {
            vmmprintf_fn("FAIL INITIALIZE TIMELINE WITH SQLITE ERROR CODE %i, QUERY: %s\n", rc, szTIMELINE_SQL1[i]);
            goto fail;
        }
    }
    // populate timeline_data temporary table - with plugins.
    PluginManager_Timeline(FcTimeline_Callback_PluginRegister, FcTimeline_Callback_PluginClose, FcTimeline_Callback_PluginAddEntry);
    LPSTR szTIMELINE_SQL2[] = {
        // populate main timeline table:
        "DROP TABLE IF EXISTS timeline;",
        "DROP VIEW IF EXISTS v_timeline;",
        "CREATE TABLE timeline ( id INTEGER PRIMARY KEY AUTOINCREMENT, tp INT, tp_id INTEGER, id_str INTEGER, ft INTEGER, ac INT, pid INT, data64 INTEGER, oln_u INTEGER, oln_j INTEGER, oln_utp INTEGER, oln_jtp INTEGER );"
        "CREATE VIEW v_timeline AS SELECT * FROM timeline, str WHERE timeline.id_str = str.id;",
        "CREATE UNIQUE INDEX idx_timeline_tpid     ON timeline(tp, tp_id);",
        "CREATE UNIQUE INDEX idx_timeline_oln_u    ON timeline(oln_u);",
        "CREATE UNIQUE INDEX idx_timeline_oln_j    ON timeline(oln_j);"
        "CREATE UNIQUE INDEX idx_timeline_oln_utp  ON timeline(tp, oln_utp);",
        "CREATE UNIQUE INDEX idx_timeline_oln_jtp  ON timeline(tp, oln_jtp);",
        "INSERT INTO timeline (tp, tp_id, id_str, ft, ac, pid, data64, oln_u, oln_j, oln_utp, oln_jtp) SELECT td.tp, (SUM(1) OVER (PARTITION BY td.tp ORDER BY td.ft DESC, td.id)), td.id_str, td.ft, td.ac, td.pid, td.data64, (SUM(str.cbu+"STRINGIZE(FC_LINELENGTH_TIMELINE_UTF8)")  OVER (ORDER BY td.ft DESC, td.id) - str.cbu-"STRINGIZE(FC_LINELENGTH_TIMELINE_UTF8)"), (SUM(str.cbj+"STRINGIZE(FC_LINELENGTH_TIMELINE_JSON)") OVER (ORDER BY td.ft DESC, td.id) - str.cbj-"STRINGIZE(FC_LINELENGTH_TIMELINE_JSON)"), (SUM(str.cbu+"STRINGIZE(FC_LINELENGTH_TIMELINE_UTF8)")  OVER (PARTITION BY td.tp ORDER BY td.ft DESC, td.id) - str.cbu-"STRINGIZE(FC_LINELENGTH_TIMELINE_UTF8)"), (SUM(str.cbj+"STRINGIZE(FC_LINELENGTH_TIMELINE_JSON)") OVER (PARTITION BY td.tp ORDER BY td.ft DESC, td.id) - str.cbj-"STRINGIZE(FC_LINELENGTH_TIMELINE_JSON)") FROM timeline_data td, str WHERE str.id = td.id_str ORDER BY td.ft DESC, td.id;",
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
    // update timeline_info with sizes for individual types (utf8 and json).
    LPSTR szTIMELINE_SQL_TIMELINE_UPD[] = {
        "UPDATE timeline_info SET file_size_u = (SELECT oln_utp+cbu+"STRINGIZE(FC_LINELENGTH_TIMELINE_UTF8)" FROM v_timeline WHERE tp = ? AND tp_id = (SELECT MAX(tp_id) FROM v_timeline WHERE tp = ?)) WHERE id = ?;",
        "UPDATE timeline_info SET file_size_j = (SELECT oln_jtp+cbj+"STRINGIZE(FC_LINELENGTH_TIMELINE_JSON)" FROM v_timeline WHERE tp = ? AND tp_id = (SELECT MAX(tp_id) FROM v_timeline WHERE tp = ?)) WHERE id = ?;",
    };
    Fc_SqlQueryN("SELECT MAX(id) FROM timeline_info;", 0, NULL, 1, &v, NULL);
    ctxFc->Timeline.cTp = (DWORD)v + 1;
    for(k = 1; k < ctxFc->Timeline.cTp; k++) {
        for(j = 0; j < 2; j++) {
            if(SQLITE_DONE != (rc = Fc_SqlQueryN(szTIMELINE_SQL_TIMELINE_UPD[j], 3, (QWORD[]) { k, k, k }, 0, NULL, NULL))) {
                vmmprintf_fn("FAIL INITIALIZE TIMELINE WITH SQLITE ERROR CODE %i, QUERY: %s\n", rc, szTIMELINE_SQL_TIMELINE_UPD[j]);
                goto fail;
            }
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
        strncpy_s(pi->szNameShort, _countof(pi->szNameShort), sqlite3_column_text(hStmt, 1), _TRUNCATE);
        for(j = 0, f = FALSE; j < _countof(pi->szNameShort) - 1; j++) {
            if(f || (pi->szNameShort[j] == 0)) {
                pi->szNameShort[j] = ' ';
                f = TRUE;
            }
        }
        pi->szNameShort[_countof(pi->szNameShort) - 1] = 0;
        wcsncpy_s(pi->wszNameFileUTF8, _countof(pi->wszNameFileUTF8), sqlite3_column_text16(hStmt, 2), _TRUNCATE);
        wcsncpy_s(pi->wszNameFileJSON, _countof(pi->wszNameFileJSON), sqlite3_column_text16(hStmt, 3), _TRUNCATE);
        pi->dwFileSizeUTF8 = sqlite3_column_int(hStmt, 4);
        pi->dwFileSizeJSON = sqlite3_column_int(hStmt, 5);
    }
    ctxFc->fEnableTimeline = TRUE;
    fResult = TRUE;
fail:
    sqlite3_finalize(hStmt);
    Fc_SqlReserveReturn(hSql);
    return fResult;
}

#define FCTIMELINE_SQL_SELECT_FIELDS_ALL " csz, osz, sz, id, ft, tp, ac, pid, data64, oln_u, oln_j "
#define FCTIMELINE_SQL_SELECT_FIELDS_TP  " csz, osz, sz, tp_id, ft, tp, ac, pid, data64, oln_utp, oln_jtp "

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
    DWORD i, cchMultiText, owszName;
    LPWSTR wszMultiText, wszEntryText;
    PFCOB_MAP_TIMELINE pObTimelineMap = NULL;
    PFC_MAP_TIMELINEENTRY pe;
    sqlite3 *hSql = NULL;
    sqlite3_stmt *hStmt = NULL;
    rc = Fc_SqlQueryN(szSqlCount, cQueryValues, pqwQueryValues, 2, pqwResult, NULL);
    if((rc != SQLITE_OK) || (pqwResult[0] > 0x00010000) || (pqwResult[1] > 0x01000000)) { goto fail; }
    cchMultiText = (DWORD)(1 + 2 * pqwResult[0] + pqwResult[1]);
    pObTimelineMap = Ob_Alloc('Mtml', LMEM_ZEROINIT, sizeof(FCOB_MAP_TIMELINE) + pqwResult[0] * sizeof(FC_MAP_TIMELINEENTRY) + cchMultiText * sizeof(WCHAR), NULL, NULL);
    if(!pObTimelineMap) { goto fail; }
    pObTimelineMap->wszMultiText = (LPWSTR)((PBYTE)pObTimelineMap + sizeof(FCOB_MAP_TIMELINE) + pqwResult[0] * sizeof(FC_MAP_TIMELINEENTRY));
    pObTimelineMap->cbMultiText = cchMultiText * sizeof(WCHAR);
    pObTimelineMap->cMap = (DWORD)pqwResult[0];
    cchMultiText--;
    wszMultiText = pObTimelineMap->wszMultiText + 1;
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
        pe->cwszText = sqlite3_column_int(hStmt, 0);
        owszName = sqlite3_column_int(hStmt, 1);
        wszEntryText = (LPWSTR)sqlite3_column_text16(hStmt, 2);
        if(!wszEntryText || (pe->cwszText != wcslen(wszEntryText)) || (pe->cwszText > cchMultiText - 1) || (owszName > pe->cwszText)) { goto fail; }
        pe->wszText = wszMultiText;
        pe->wszTextSub = wszMultiText + owszName;
        memcpy(wszMultiText, wszEntryText, pe->cwszText * sizeof(WCHAR));
        wszMultiText = wszMultiText + pe->cwszText + 1;
        cchMultiText += pe->cwszText + 1;
        // populate numeric data
        pe->id = sqlite3_column_int64(hStmt, 3);
        pe->ft = sqlite3_column_int64(hStmt, 4);
        pe->tp = sqlite3_column_int(hStmt, 5);
        pe->ac = sqlite3_column_int(hStmt, 6);
        pe->pid = sqlite3_column_int(hStmt, 7);
        pe->data64 = sqlite3_column_int64(hStmt, 8);
        pe->cszuOffset = sqlite3_column_int64(hStmt, 9);
        pe->cszjOffset = sqlite3_column_int64(hStmt, 10);
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
BOOL FcTimelineMap_GetFromIdRange(_In_ DWORD dwTimelineType, _In_ QWORD qwId, _In_ QWORD cId, _Out_ PFCOB_MAP_TIMELINE *ppObTimelineMap)
{
    QWORD v[] = { qwId, qwId + cId, dwTimelineType };
    DWORD iSQL = dwTimelineType ? 2 : 0;
    LPSTR szSQL[] = {
        "SELECT COUNT(*), SUM(csz) FROM v_timeline WHERE id >= ? AND id < ?",
        "SELECT "FCTIMELINE_SQL_SELECT_FIELDS_ALL" FROM v_timeline WHERE id >= ? AND id < ? ORDER BY id",
        "SELECT COUNT(*), SUM(csz) FROM v_timeline WHERE tp_id >= ? AND tp_id < ? AND tp = ?",
        "SELECT "FCTIMELINE_SQL_SELECT_FIELDS_TP" FROM v_timeline WHERE tp_id >= ? AND tp_id < ? AND tp = ? ORDER BY tp_id"
    };
    return FcTimelineMap_CreateInternal(szSQL[iSQL], szSQL[iSQL + 1], (dwTimelineType ? 3 : 2), v, ppObTimelineMap);
}

/*
* Retrieve the minimum timeline id that exists within a byte range inside a
* timeline file of a specific type.
* -- dwTimelineType = the timeline type, 0 for all.
* -- fJSON = is JSON type, otherwise UTF8 type.
* -- qwFilePos = the file position.
* -- pqwId = pointer to receive the result id.
* -- return
*/
_Success_(return)
BOOL FcTimeline_GetIdFromPosition(_In_ DWORD dwTimelineType, _In_ BOOL fJSON, _In_ QWORD qwFilePos, _Out_ PQWORD pqwId)
{
    QWORD v[] = { max(2048, qwFilePos) - 2048, qwFilePos, dwTimelineType };
    DWORD iSQL = (dwTimelineType ? 2 : 0) + (fJSON ? 1 : 0);
    LPSTR szSQL[4] = {
        "SELECT MAX(id) FROM timeline WHERE oln_u >= ? AND oln_u <= ?",
        "SELECT MAX(id) FROM timeline WHERE oln_j >= ? AND oln_j <= ?",
        "SELECT MAX(tp_id) FROM timeline WHERE oln_utp >= ? AND oln_utp <= ? AND tp = ?",
        "SELECT MAX(tp_id) FROM timeline WHERE oln_jtp >= ? AND oln_jtp <= ? AND tp = ?"
    };
    return (SQLITE_OK == Fc_SqlQueryN(szSQL[iSQL], (dwTimelineType ? 3 : 2), v, 1, pqwId, NULL));
}
