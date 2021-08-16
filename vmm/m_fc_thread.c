// m_fc_thread.c : thread forensic module.
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
#include "pluginmanager.h"
#include "util.h"

static LPSTR FC_SQL_SCHEMA_THREAD =
    "DROP TABLE IF EXISTS thread; " \
    "CREATE TABLE thread(id INTEGER PRIMARY KEY AUTOINCREMENT, id_str INTEGER, pid INT, tid INT, ethread INTEGER, teb INTEGER, state INT, exitstatus INT, running INT, prio INT, priobase INT, startaddr INTEGER, stackbase_u INTEGER, stacklimit_u INTEGER, stackbase_k INTEGER, stacklimit_k INTEGER, trapframe INTEGER, sp INTEGER, ip INTEGER, time_create INTEGER, time_exit INTEGER); " \
    "DROP VIEW IF EXISTS v_thread; " \
    "CREATE VIEW v_thread AS SELECT t.*, str.* FROM thread t, str WHERE t.id_str = str.id; ";

VOID M_FcThread_FcInitialize_ThreadProc(_In_ PVMM_PROCESS pProcess, _In_ PVOID pv)
{
    int rc;
    sqlite3 *hSql = NULL;
    sqlite3_stmt *hStmt = NULL, *hStmtStr = NULL;
    DWORD i;
    PVMMOB_MAP_THREAD pObThreadMap = NULL;
    PVMM_MAP_THREADENTRY pe;
    CHAR szStr[MAX_PATH];
    FCSQL_INSERTSTRTABLE SqlStrInsert;
    if(!VmmMap_GetThread(pProcess, &pObThreadMap)) { goto fail; }
    if(!(hSql = Fc_SqlReserve())) { goto fail; }
    if(SQLITE_OK != sqlite3_prepare_v2(hSql, "INSERT INTO thread (id_str, pid, tid, ethread, teb, state, exitstatus, running, prio, priobase, startaddr, stackbase_u, stacklimit_u, stackbase_k, stacklimit_k, trapframe, sp, ip, time_create, time_exit) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);", -1, &hStmt, NULL)) { goto fail; }
    if(SQLITE_OK != sqlite3_prepare_v2(hSql, "INSERT INTO str (id, cbu, cbj, sz) VALUES (?, ?, ?, ?);", -1, &hStmtStr, NULL)) { goto fail; }
    sqlite3_exec(hSql, "BEGIN TRANSACTION", NULL, NULL, NULL);
    for(i = 0; i < pObThreadMap->cMap; i++) {
        pe = pObThreadMap->pMap + i;
        snprintf(szStr, _countof(szStr), "TID: %i", pe->dwTID);
        if(!Fc_SqlInsertStr(hStmtStr, szStr, &SqlStrInsert)) { goto fail_transact; }
        sqlite3_reset(hStmt);
        rc = Fc_SqlBindMultiInt64(hStmt, 1, 20,
            SqlStrInsert.id,
            (QWORD)pe->dwPID,
            (QWORD)pe->dwTID,
            pe->vaETHREAD,
            pe->vaTeb,
            (QWORD)pe->bState,
            (QWORD)pe->dwExitStatus,
            (QWORD)pe->bRunning,
            (QWORD)pe->bPriority,
            (QWORD)pe->bBasePriority,
            pe->vaStartAddress,
            pe->vaStackBaseUser,
            pe->vaStackLimitUser,
            pe->vaStackBaseKernel,
            pe->vaStackLimitKernel,
            pe->vaTrapFrame,
            pe->vaRSP,
            pe->vaRIP,
            pe->ftCreateTime,
            pe->ftExitTime
        );
        if(SQLITE_OK != rc) { goto fail_transact; }
        sqlite3_step(hStmt);
    }
fail_transact:
    sqlite3_exec(hSql, "COMMIT TRANSACTION", NULL, NULL, NULL);
fail:
    sqlite3_finalize(hStmt);
    sqlite3_finalize(hStmtStr);
    Fc_SqlReserveReturn(hSql);
    Ob_DECREF(pObThreadMap);
    return;
}

/*
* Forensic initialization function called when the forensic sub-system is initializing.
*/
PVOID M_FcThread_FcInitialize(_In_ PVMMDLL_PLUGIN_CONTEXT ctxP)
{
    if(SQLITE_OK != Fc_SqlExec(FC_SQL_SCHEMA_THREAD)) { return NULL; }
    VmmProcessActionForeachParallel(NULL, VmmProcessActionForeachParallel_CriteriaActiveOnly, M_FcThread_FcInitialize_ThreadProc);
    return NULL;
}

/*
* Timeline data by executing a partial SQL query on pre-existing data.
* -- ctxfc
* -- hTimeline
* -- pfnAddEntry
* -- pfnEntryAddBySql
*/
VOID M_FcThread_FcTimeline(
    _In_opt_ PVOID ctxfc,
    _In_ HANDLE hTimeline,
    _In_ VOID(*pfnAddEntry)(_In_ HANDLE hTimeline, _In_ QWORD ft, _In_ DWORD dwAction, _In_ DWORD dwPID, _In_ DWORD dwData32, _In_ QWORD qwData64, _In_ LPSTR uszText),
    _In_ VOID(*pfnEntryAddBySql)(_In_ HANDLE hTimeline, _In_ DWORD cEntrySql, _In_ LPSTR *pszEntrySql)
) {
    LPSTR pszSql[] = {
        "id_str, time_create, "STRINGIZE(FC_TIMELINE_ACTION_CREATE)", pid, tid, ethread FROM thread WHERE time_create > 0;",
        "id_str, time_exit,   "STRINGIZE(FC_TIMELINE_ACTION_DELETE)", pid, tid, ethread FROM thread WHERE time_exit > 0;",
    };
    pfnEntryAddBySql(hTimeline, sizeof(pszSql) / sizeof(LPSTR), pszSql);
}

VOID M_FcThread_FcLogJSON(_In_ PVMMDLL_PLUGIN_CONTEXT ctxP, _In_ VOID(*pfnLogJSON)(_In_ PVMMDLL_PLUGIN_FORENSIC_JSONDATA pData))
{
    PVMM_PROCESS pProcess = ctxP->pProcess;
    PVMMDLL_PLUGIN_FORENSIC_JSONDATA pd;
    PVMMOB_MAP_THREAD pObThreadMap = NULL;
    PVMM_MAP_THREADENTRY pe;
    DWORD i, o;
    CHAR szTime[24];
    CHAR usz[MAX_PATH] = { 0 };
    if(!pProcess || !(pd = LocalAlloc(LMEM_ZEROINIT, sizeof(VMMDLL_PLUGIN_FORENSIC_JSONDATA)))) { return; }
    pd->dwVersion = VMMDLL_PLUGIN_FORENSIC_JSONDATA_VERSION;
    pd->dwPID = pProcess->dwPID;
    pd->szjType = "thread";
    if(VmmMap_GetThread(pProcess, &pObThreadMap)) {
        for(i = 0; i < pObThreadMap->cMap; i++) {
            pe = pObThreadMap->pMap + i;
            Util_FileTime2String(pe->ftCreateTime, szTime);
            o = snprintf(usz, _countof(usz), "state:[%x %x %x] prio:[%x %x] start:[%s]", pe->bState, pe->bRunning, pe->dwExitStatus, pe->bBasePriority, pe->bPriority, szTime);
            if(pe->ftExitTime) {
                Util_FileTime2String(pe->ftExitTime, szTime);
                snprintf(usz + o, _countof(usz) - 0, " stop:[%s]", szTime);
            }
            // assign:
            pd->i = i;
            pd->vaObj = pe->vaETHREAD;
            pd->qwHex[0] = pe->dwTID;
            pd->qwHex[1] = pe->vaTeb;
            pd->va[0] = pe->vaStackBaseUser ? pe->vaStackBaseUser : pe->vaStackBaseKernel;
            pd->va[1] = pe->vaStackBaseUser ? pe->vaStackLimitUser : pe->vaStackLimitKernel;
            pd->usz[0] = usz;
            pfnLogJSON(pd);
        }
    }
    Ob_DECREF(pObThreadMap);
    LocalFree(pd);
}

/*
* Plugin initialization / registration function called by the plugin manager.
* -- pRI
*/
VOID M_FcThread_Initialize(_Inout_ PVMMDLL_PLUGIN_REGINFO pRI)
{
    if((pRI->magic != VMMDLL_PLUGIN_REGINFO_MAGIC) || (pRI->wVersion != VMMDLL_PLUGIN_REGINFO_VERSION)) { return; }
    if((pRI->tpSystem != VMM_SYSTEM_WINDOWS_X64) && (pRI->tpSystem != VMM_SYSTEM_WINDOWS_X86)) { return; }
    strcpy_s(pRI->reg_info.uszPathName, 128, "\\forensic\\hidden\\thread");     // module name
    pRI->reg_info.fRootModule = TRUE;                                           // module shows in root directory
    pRI->reg_info.fRootModuleHidden = TRUE;                                     // module hidden by default
    pRI->reg_fnfc.pfnInitialize = M_FcThread_FcInitialize;                      // Forensic initialize function supported
    pRI->reg_fnfc.pfnTimeline = M_FcThread_FcTimeline;                          // Forensic timelining supported
    pRI->reg_fnfc.pfnLogJSON = M_FcThread_FcLogJSON;                            // JSON log function supported
    memcpy(pRI->reg_info.sTimelineNameShort, "THREAD", 6);
    strncpy_s(pRI->reg_info.uszTimelineFile, 32, "timeline_thread.txt", _TRUNCATE);
    pRI->pfnPluginManager_Register(pRI);
}
