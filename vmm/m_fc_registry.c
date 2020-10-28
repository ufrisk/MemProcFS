// m_fc_registry.c : registry forensic module.
//
// REQUIRE: FORENSIC SUB-SYSTEM INIT.
//
// NB! module generate forensic data only - no file system presence!
//
// (c) Ulf Frisk, 2020
// Author: Ulf Frisk, pcileech@frizk.net
//

#include "fc.h"
#include "vmm.h"
#include "vmmwinreg.h"
#include "pluginmanager.h"

static LPSTR FC_SQL_SCHEMA_REGISTRY =
    "DROP VIEW IF EXISTS v_registry; " \
    "DROP TABLE IF EXISTS registry; " \
    "CREATE TABLE registry ( id INTEGER PRIMARY KEY AUTOINCREMENT, id_str INTEGER, hive INTEGER, cell INTEGER, cell_parent INTEGER, time INTEGER ); " \
    "CREATE VIEW v_registry AS SELECT *, SUBSTR(sz, osz+1) AS sz_sub FROM registry, str WHERE registry.id_str = str.id; ";

VOID M_FcRegistry_FcInitialize_Callback(_In_ HANDLE hCallback1, _In_ HANDLE hCallback2, _In_ LPWSTR wszPathName, _In_ DWORD owszName, _In_ QWORD vaHive, _In_ DWORD dwCell, _In_ DWORD dwCellParent, _In_ QWORD ftLastWrite)
{
    FCSQL_INSERTSTRTABLE SqlStrInsert;
    sqlite3_stmt *hStmt = (sqlite3_stmt*)hCallback1;
    sqlite3_stmt *hStmtStr = (sqlite3_stmt *)hCallback2;
    // build and insert string data into 'str' table.
    if(!Fc_SqlInsertStr(hStmtStr, wszPathName, owszName, &SqlStrInsert)) { return; }
    // insert into 'process' table.
    sqlite3_reset(hStmt);
    Fc_SqlBindMultiInt64(hStmt, 1, 5,
        SqlStrInsert.id,
        vaHive,
        (QWORD)dwCell,
        (QWORD)dwCellParent,
        ftLastWrite
    );
    sqlite3_step(hStmt);
}

/*
* Forensic initialization function called when the forensic sub-system is initializing.
*/
PVOID M_FcRegistry_FcInitialize()
{
    POB_REGISTRY_HIVE pObHive = NULL;
    sqlite3 *hSql = NULL;
    sqlite3_stmt *hStmt = NULL, *hStmtStr = NULL;
    if(SQLITE_OK != Fc_SqlExec(FC_SQL_SCHEMA_REGISTRY)) { goto fail; }
    if(!(hSql = Fc_SqlReserve())) { goto fail; }
    if(SQLITE_OK != sqlite3_prepare_v2(hSql, "INSERT INTO registry (id_str, hive, cell, cell_parent, time) VALUES (?, ?, ?, ?, ?);", -1, &hStmt, NULL)) { goto fail; }
    if(SQLITE_OK != sqlite3_prepare_v2(hSql, "INSERT INTO str (id, osz, csz, cbu, cbj, sz) VALUES (?, ?, ?, ?, ?, ?);", -1, &hStmtStr, NULL)) { goto fail; }
    sqlite3_exec(hSql, "BEGIN TRANSACTION", NULL, NULL, NULL);
    while(pObHive = VmmWinReg_HiveGetNext(pObHive)) {
        VmmWinReg_ForensicGetAllKeys(pObHive, hStmt, hStmtStr, M_FcRegistry_FcInitialize_Callback);
    }
    sqlite3_exec(hSql, "COMMIT TRANSACTION", NULL, NULL, NULL);
fail:
    Ob_DECREF(pObHive);
    sqlite3_finalize(hStmt);
    sqlite3_finalize(hStmtStr);
    Fc_SqlReserveReturn(hSql);
    return NULL;
}

/*
* Timeline data by executing a partial SQL query on pre-existing data.
* -- ctxfc
* -- hTimeline
* -- pfnAddEntry
* -- pfnEntryAddBySql
*/
VOID M_FcRegistry_FcTimeline(
    _In_opt_ PVOID ctxfc,
    _In_ HANDLE hTimeline,
    _In_ VOID(*pfnAddEntry)(_In_ HANDLE hTimeline, _In_ QWORD ft, _In_ DWORD dwAction, _In_ DWORD dwPID, _In_ QWORD qwValue, _In_ LPWSTR wszText),
    _In_ VOID(*pfnEntryAddBySql)(_In_ HANDLE hTimeline, _In_ DWORD cEntrySql, _In_ LPSTR *pszEntrySql)
) {
    LPSTR pszSql[] = {
        "id_str, time, "STRINGIZE(FC_TIMELINE_ACTION_MODIFY)", 0, 0 FROM registry WHERE time > 0;"
    };
    pfnEntryAddBySql(hTimeline, sizeof(pszSql) / sizeof(LPSTR), pszSql);
}

/*
* Plugin initialization / registration function called by the plugin manager.
* -- pRI
*/
VOID M_FcRegistry_Initialize(_Inout_ PVMMDLL_PLUGIN_REGINFO pRI)
{
    if((pRI->magic != VMMDLL_PLUGIN_REGINFO_MAGIC) || (pRI->wVersion != VMMDLL_PLUGIN_REGINFO_VERSION)) { return; }
    if((pRI->tpSystem != VMM_SYSTEM_WINDOWS_X64) && (pRI->tpSystem != VMM_SYSTEM_WINDOWS_X86)) { return; }
    if(ctxMain->dev.fVolatile) { return; }
    wcscpy_s(pRI->reg_info.wszPathName, 128, L"\\forensic\\hidden\\registry");  // module name
    pRI->reg_info.fRootModule = TRUE;                                           // module shows in root directory
    pRI->reg_info.fRootModuleHidden = TRUE;                                     // module hidden by default
    pRI->reg_fnfc.pfnInitialize = M_FcRegistry_FcInitialize;                    // Forensic initialize function supported
    pRI->reg_fnfc.pfnTimeline = M_FcRegistry_FcTimeline;                        // Forensic timelining supported
    memcpy(pRI->reg_info.sTimelineNameShort, "REG   ", 6);
    strncpy_s(pRI->reg_info.szTimelineFileUTF8, 32, "timeline_registry.txt", _TRUNCATE);
    strncpy_s(pRI->reg_info.szTimelineFileJSON, 32, "timeline_registry.json", _TRUNCATE);
    pRI->pfnPluginManager_Register(pRI);
}
