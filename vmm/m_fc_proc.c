// m_fc_proc.c : process forensic module.
//
// REQUIRE: FORENSIC SUB-SYSTEM INIT.
//
// NB! module generate forensic data only - no file system presence!
//
// (c) Ulf Frisk, 2020-2021
// Author: Ulf Frisk, pcileech@frizk.net
//

#include "fc.h"
#include "vmm.h"
#include "vmmwin.h"
#include "pluginmanager.h"

static LPSTR FC_SQL_SCHEMA_PROCESS =
    "DROP TABLE IF EXISTS process; " \
    "CREATE TABLE process(id INTEGER PRIMARY KEY AUTOINCREMENT, id_str_name INTEGER, id_str_path INTEGER, id_str_user INTEGER, id_str_all INTEGER, pid INT, ppid INT, eprocess INTEGER, dtb INTEGER, dtb_user INTEGER, state INTEGER, wow64 INT, peb INTEGER, peb32 INTEGER, time_create INTEGER, time_exit INTEGER); " \
    "DROP VIEW IF EXISTS v_process; " \
    "CREATE VIEW v_process AS SELECT p.*, sn.csz AS csz_name, sn.cbu AS cbu_name, sn.cbj AS cbj_name, sn.sz AS sz_name, sp.csz AS csz_path, sp.cbu AS cbu_path, sp.cbj AS cbj_path, sp.sz AS sz_path, su.csz AS csz_user, su.cbu AS cbu_user, su.cbj AS cbj_user, su.sz AS sz_user, sa.csz AS csz_all, sa.cbu AS cbu_all, sa.cbj AS cbj_all, sa.sz AS sz_all FROM process p, str sn, str sp, str su, str sa WHERE p.id_str_name = sn.id AND p.id_str_path = sp.id AND p.id_str_user = su.id AND  p.id_str_all = sa.id; ";

/*
* Forensic initialization function called when the forensic sub-system is initializing.
*/
PVOID M_FcProc_FcInitialize()
{
    int rc;
    BOOL fWellKnownAccount = FALSE;
    PVMM_PROCESS pObProcess = NULL;
    sqlite3 *hSql = NULL;
    sqlite3_stmt *hStmt = NULL, *hStmtStr = NULL;
    FCSQL_INSERTSTRTABLE SqlStrInsert[4];
    WCHAR wszUserName[MAX_PATH], wszFullInfo[2048];
    if(SQLITE_OK != Fc_SqlExec(FC_SQL_SCHEMA_PROCESS)) { goto fail; }
    if(!(hSql = Fc_SqlReserve())) { goto fail; }
    if(SQLITE_OK != sqlite3_prepare_v2(hSql, "INSERT INTO process (id_str_name, id_str_path, id_str_user, id_str_all, pid, ppid, eprocess, dtb, dtb_user, state, wow64, peb, peb32, time_create, time_exit) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);", -1, &hStmt, NULL)) { goto fail; }
    if(SQLITE_OK != sqlite3_prepare_v2(hSql, "INSERT INTO str (id, osz, csz, cbu, cbj, sz) VALUES (?, ?, ?, ?, ?, ?);", -1, &hStmtStr, NULL)) { goto fail; }
    sqlite3_exec(hSql, "BEGIN TRANSACTION", NULL, NULL, NULL);
    while(pObProcess = VmmProcessGetNext(pObProcess, VMM_FLAG_PROCESS_TOKEN | VMM_FLAG_PROCESS_SHOW_TERMINATED)) {
        // build and insert string data into 'str' table.
        if(!Fc_SqlInsertStr(hStmtStr, pObProcess->pObPersistent->wszNameLong, 0, &SqlStrInsert[0])) { goto fail_transact; }
        if(!Fc_SqlInsertStr(hStmtStr, pObProcess->pObPersistent->wszPathKernel, 0, &SqlStrInsert[1])) { goto fail_transact; }
        if(!pObProcess->win.TOKEN.fSID || !VmmWinUser_GetNameW(&pObProcess->win.TOKEN.SID, wszUserName, MAX_PATH, NULL, &fWellKnownAccount)) { wszUserName[0] = 0; }
        if(!Fc_SqlInsertStr(hStmtStr, wszUserName, 0, &SqlStrInsert[2])) { goto fail_transact; }
        _snwprintf_s(wszFullInfo, 2048 - 2, 2048 - 3, L"%s [%s%s] %s", pObProcess->pObPersistent->wszNameLong, (fWellKnownAccount ? L"*" : L""), wszUserName, pObProcess->pObPersistent->wszPathKernel);
        if(!Fc_SqlInsertStr(hStmtStr, wszFullInfo, 0, &SqlStrInsert[3])) { goto fail_transact; }
        // insert into 'process' table.
        sqlite3_reset(hStmt);
        rc = Fc_SqlBindMultiInt64(hStmt, 1, 15,
            SqlStrInsert[0].id,
            SqlStrInsert[1].id,
            SqlStrInsert[2].id,
            SqlStrInsert[3].id,
            (QWORD)pObProcess->dwPID,
            (QWORD)pObProcess->dwPPID,
            pObProcess->win.EPROCESS.va,
            pObProcess->paDTB,
            pObProcess->paDTB_UserOpt,
            (QWORD)pObProcess->dwState,
            (QWORD)(pObProcess->win.fWow64 ? 1 : 0),
            pObProcess->win.vaPEB,
            (QWORD)pObProcess->win.vaPEB32,
            VmmProcess_GetCreateTimeOpt(pObProcess),
            VmmProcess_GetExitTimeOpt(pObProcess)
        );
        if(SQLITE_OK != rc) { goto fail_transact; }
        sqlite3_step(hStmt);
    }
    sqlite3_exec(hSql, "COMMIT TRANSACTION", NULL, NULL, NULL);
fail:
    Ob_DECREF(pObProcess);
    sqlite3_finalize(hStmt);
    sqlite3_finalize(hStmtStr);
    Fc_SqlReserveReturn(hSql);
    return NULL;
fail_transact:
    sqlite3_exec(hSql, "COMMIT TRANSACTION", NULL, NULL, NULL);
    goto fail;
}

/*
* Timeline data by executing a partial SQL query on pre-existing data.
* -- ctxfc
* -- hTimeline
* -- pfnAddEntry
* -- pfnEntryAddBySql
*/
VOID M_FcProc_FcTimeline(
    _In_opt_ PVOID ctxfc,
    _In_ HANDLE hTimeline,
    _In_ VOID(*pfnAddEntry)(_In_ HANDLE hTimeline, _In_ QWORD ft, _In_ DWORD dwAction, _In_ DWORD dwPID, _In_ QWORD qwValue, _In_ LPWSTR wszText),
    _In_ VOID(*pfnEntryAddBySql)(_In_ HANDLE hTimeline, _In_ DWORD cEntrySql, _In_ LPSTR *pszEntrySql)
) {
    LPSTR pszSql[] = {
        "id_str_all, time_create, "STRINGIZE(FC_TIMELINE_ACTION_CREATE)", pid, eprocess FROM process WHERE time_create > 0;",
        "id_str_all, time_exit,   "STRINGIZE(FC_TIMELINE_ACTION_DELETE)", pid, eprocess FROM process WHERE time_exit > 0;"
    };
    pfnEntryAddBySql(hTimeline, sizeof(pszSql) / sizeof(LPSTR), pszSql);
}

/*
* Plugin initialization / registration function called by the plugin manager.
* -- pRI
*/
VOID M_FcProc_Initialize(_Inout_ PVMMDLL_PLUGIN_REGINFO pRI)
{
    if((pRI->magic != VMMDLL_PLUGIN_REGINFO_MAGIC) || (pRI->wVersion != VMMDLL_PLUGIN_REGINFO_VERSION)) { return; }
    if((pRI->tpSystem != VMM_SYSTEM_WINDOWS_X64) && (pRI->tpSystem != VMM_SYSTEM_WINDOWS_X86)) { return; }
    if(ctxMain->dev.fVolatile) { return; }
    wcscpy_s(pRI->reg_info.wszPathName, 128, L"\\forensic\\hidden\\proc");      // module name
    pRI->reg_info.fRootModule = TRUE;                                           // module shows in root directory
    pRI->reg_info.fRootModuleHidden = TRUE;                                     // module hidden by default
    pRI->reg_fnfc.pfnInitialize = M_FcProc_FcInitialize;                        // Forensic initialize function supported
    pRI->reg_fnfc.pfnTimeline = M_FcProc_FcTimeline;                            // Forensic timelining supported
    memcpy(pRI->reg_info.sTimelineNameShort, "PROC  ", 6);
    strncpy_s(pRI->reg_info.szTimelineFileUTF8, 32, "timeline_process.txt", _TRUNCATE);
    strncpy_s(pRI->reg_info.szTimelineFileJSON, 32, "timeline_process.json", _TRUNCATE);
    pRI->pfnPluginManager_Register(pRI);
}
