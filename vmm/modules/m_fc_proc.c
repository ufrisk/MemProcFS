// m_fc_proc.c : process forensic module.
//
// REQUIRE: FORENSIC SUB-SYSTEM INIT.
//
// NB! module generate forensic data only - no file system presence!
//
// (c) Ulf Frisk, 2020-2025
// Author: Ulf Frisk, pcileech@frizk.net
//

#include "modules.h"
#include "../vmmwin.h"

static LPSTR MFCPROC_CSV_PROCESS = "PID,PPID,State,ShortName,Name,IntegrityLevel,User,CreateTime,ExitTime,Wow64,EPROCESS,PEB,PEB32,DTB,UserDTB,UserPath,KernelPath,CommandLine,Flag\n";

static LPSTR FC_SQL_SCHEMA_PROCESS =
    "DROP TABLE IF EXISTS process; " \
    "CREATE TABLE process(id INTEGER PRIMARY KEY AUTOINCREMENT, id_str_name INTEGER, id_str_path INTEGER, id_str_user INTEGER, id_str_all INTEGER, pid INT, ppid INT, eprocess INTEGER, dtb INTEGER, dtb_user INTEGER, state INTEGER, wow64 INT, peb INTEGER, peb32 INTEGER, time_create INTEGER, time_exit INTEGER); " \
    "DROP VIEW IF EXISTS v_process; " \
    "CREATE VIEW v_process AS SELECT p.*, sn.cbu AS cbu_name, sn.cbj AS cbj_name, sn.sz AS sz_name, sp.cbu AS cbu_path, sp.cbj AS cbj_path, sp.sz AS sz_path, su.cbu AS cbu_user, su.cbj AS cbj_user, su.sz AS sz_user, sa.cbu AS cbu_all, sa.cbj AS cbj_all, sa.sz AS sz_all FROM process p, str sn, str sp, str su, str sa WHERE p.id_str_name = sn.id AND p.id_str_path = sp.id AND p.id_str_user = su.id AND  p.id_str_all = sa.id; ";

/*
* Forensic initialization function called when the forensic sub-system is initializing.
*/
PVOID MFcProc_FcInitialize(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_CONTEXT ctxP)
{
    int rc;
    BOOL fWellKnownAccount = FALSE;
    PVMM_PROCESS pObProcess = NULL;
    sqlite3 *hSql = NULL;
    sqlite3_stmt *hStmt = NULL, *hStmtStr = NULL;
    FCSQL_INSERTSTRTABLE SqlStrInsert[4];
    CHAR uszUserName[MAX_PATH], uszFullInfo[2048];
    // 1: initialize csv
    FcFileAppend(H, "process.csv", MFCPROC_CSV_PROCESS);
    // 2: initialize timelining (sql)
    if(SQLITE_OK != Fc_SqlExec(H, FC_SQL_SCHEMA_PROCESS)) { goto fail; }
    if(!(hSql = Fc_SqlReserve(H))) { goto fail; }
    if(SQLITE_OK != sqlite3_prepare_v2(hSql, "INSERT INTO process (id_str_name, id_str_path, id_str_user, id_str_all, pid, ppid, eprocess, dtb, dtb_user, state, wow64, peb, peb32, time_create, time_exit) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);", -1, &hStmt, NULL)) { goto fail; }
    if(SQLITE_OK != sqlite3_prepare_v2(hSql, szFC_SQL_STR_INSERT, -1, &hStmtStr, NULL)) { goto fail; }
    sqlite3_exec(hSql, "BEGIN TRANSACTION", NULL, NULL, NULL);
    while((pObProcess = VmmProcessGetNext(H, pObProcess, VMM_FLAG_PROCESS_TOKEN | VMM_FLAG_PROCESS_SHOW_TERMINATED))) {
        // build and insert string data into 'str' table.
        if(!Fc_SqlInsertStr(H, hStmtStr, pObProcess->pObPersistent->uszNameLong, &SqlStrInsert[0])) { goto fail_transact; }
        if(!Fc_SqlInsertStr(H, hStmtStr, pObProcess->pObPersistent->uszPathKernel, &SqlStrInsert[1])) { goto fail_transact; }
        if(!pObProcess->win.Token || !pObProcess->win.Token->fSidUserValid || !VmmWinUser_GetName(H, &pObProcess->win.Token->SidUser.SID, uszUserName, MAX_PATH, &fWellKnownAccount)) { uszUserName[0] = 0; }
        if(!Fc_SqlInsertStr(H, hStmtStr, uszUserName, &SqlStrInsert[2])) { goto fail_transact; }
        _snprintf_s(uszFullInfo, 2048 - 2, 2048 - 3, "%s [%s%s] %s", pObProcess->pObPersistent->uszNameLong, (fWellKnownAccount ? "*" : ""), uszUserName, pObProcess->pObPersistent->uszPathKernel);
        if(!Fc_SqlInsertStr(H, hStmtStr, uszFullInfo, &SqlStrInsert[3])) { goto fail_transact; }
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
            VmmProcess_GetCreateTimeOpt(H, pObProcess),
            VmmProcess_GetExitTimeOpt(H, pObProcess)
        );
        if(SQLITE_OK != rc) { goto fail_transact; }
        sqlite3_step(hStmt);
    }
    sqlite3_exec(hSql, "COMMIT TRANSACTION", NULL, NULL, NULL);
fail:
    Ob_DECREF(pObProcess);
    sqlite3_finalize(hStmt);
    sqlite3_finalize(hStmtStr);
    Fc_SqlReserveReturn(H, hSql);
    return NULL;
fail_transact:
    sqlite3_exec(hSql, "COMMIT TRANSACTION", NULL, NULL, NULL);
    goto fail;
}

/*
* Timeline data by executing a partial SQL query on pre-existing data.
* -- H
* -- ctxfc
* -- hTimeline
* -- pfnAddEntry
* -- pfnEntryAddBySql
*/
VOID MFcProc_FcTimeline(
    _In_ VMM_HANDLE H,
    _In_opt_ PVOID ctxfc,
    _In_ HANDLE hTimeline,
    _In_ VOID(*pfnAddEntry)(_In_ VMM_HANDLE H, _In_ HANDLE hTimeline, _In_ QWORD ft, _In_ DWORD dwAction, _In_ DWORD dwPID, _In_ DWORD dwData32, _In_ QWORD qwData64, _In_ LPCSTR uszText),
    _In_ VOID(*pfnEntryAddBySql)(_In_ VMM_HANDLE H, _In_ HANDLE hTimeline, _In_ DWORD cEntrySql, _In_ LPCSTR *pszEntrySql)
) {
    LPCSTR pszSql[] = {
        "id_str_all, time_create, "STRINGIZE(FC_TIMELINE_ACTION_CREATE)", pid, ppid, eprocess FROM process WHERE time_create > 0;",
        "id_str_all, time_exit,   "STRINGIZE(FC_TIMELINE_ACTION_DELETE)", pid, ppid, eprocess FROM process WHERE time_exit > 0;"
    };
    pfnEntryAddBySql(H, hTimeline, sizeof(pszSql) / sizeof(LPSTR), pszSql);
}

VOID MFcProc_LogHeap(_In_ VMM_HANDLE H, _In_ PVMMDLL_FORENSIC_JSONDATA pd, _In_ VOID(*pfnLogJSON)(_In_ VMM_HANDLE H, _In_ PVMMDLL_FORENSIC_JSONDATA pData), _In_ PVMMOB_MAP_HEAP pMap)
{
    DWORD i;
    PVMM_MAP_HEAP_SEGMENTENTRY peR;
    for(i = 0; i < pMap->cSegments; i++) {
        peR = pMap->pSegments + i;
        pd->i = i;
        pd->va[0] = peR->va;
        pd->va[1] = pMap->pMap[peR->iHeap].va;
        pd->qwNum[0] = peR->cb;
        pfnLogJSON(H, pd);
    }
}

VOID MFcProc_LogProcess_GetUserName(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess, _Out_writes_(17) LPSTR uszUserName, _Out_ PBOOL fAccountUser)
{
    BOOL f, fWellKnownAccount = FALSE;
    uszUserName[0] = 0;
    f = pProcess->win.Token &&
        pProcess->win.Token->fSidUserValid &&
        VmmWinUser_GetName(H, &pProcess->win.Token->SidUser.SID, uszUserName, 17, &fWellKnownAccount);
    *fAccountUser = f && !fWellKnownAccount;
}

VOID MFcProc_LogProcess(_In_ VMM_HANDLE H, _In_ PVMMDLL_FORENSIC_JSONDATA pd, _In_ VOID(*pfnLogJSON)(_In_ VMM_HANDLE H, _In_ PVMMDLL_FORENSIC_JSONDATA pData), PVMM_PROCESS pProcess)
{
    SIZE_T o;
    BOOL fStateTerminated, fAccountUser = FALSE;
    CHAR uszBuffer[1024], szUserName[17], szTimeCRE[24], szTimeEXIT[24];
    PVMMWIN_USER_PROCESS_PARAMETERS pu = VmmWin_UserProcessParameters_Get(H, pProcess);
    SIZE_T cbu = sizeof(uszBuffer);
    LPSTR usz = uszBuffer;
    if((SIZE_T)pu->cbuImagePathName + pu->cbuCommandLine > sizeof(uszBuffer) - 512) {
        cbu = (SIZE_T)pu->cbuImagePathName + pu->cbuCommandLine + 512;
        usz = LocalAlloc(0, cbu);
        if(!usz) { return; }
    }
    pd->i = pProcess->dwPID;
    pd->vaObj = pProcess->win.EPROCESS.va;
    pd->qwNum[1] = pProcess->dwPPID;
    pd->qwHex[0] = pProcess->paDTB;
    pd->qwHex[1] = pProcess->paDTB_UserOpt;
    pd->usz[0] = pProcess->pObPersistent->uszPathKernel;
    fStateTerminated = (pProcess->dwState != 0);
    MFcProc_LogProcess_GetUserName(H, pProcess, szUserName, &fAccountUser);
    Util_FileTime2String(VmmProcess_GetCreateTimeOpt(H, pProcess), szTimeCRE);
    o = _snprintf_s(usz, cbu, _TRUNCATE, "flags:[%s%c%c%c] user:[%s] upath:[%s] cmd:[%s] createtime:[%s]",
        pProcess->win.fWow64 ? "32" : "  ",
        pProcess->win.EPROCESS.fNoLink ? 'E' : ' ',
        fStateTerminated ? 'T' : ' ',
        fAccountUser ? 'U' : ' ',
        szUserName,
        pu->uszImagePathName ? pu->uszImagePathName : "",
        pu->uszCommandLine ? pu->uszCommandLine : "",
        szTimeCRE
    );
    if(VmmProcess_GetExitTimeOpt(H, pProcess)) {
        Util_FileTime2String(VmmProcess_GetExitTimeOpt(H, pProcess), szTimeEXIT);
        o += _snprintf_s(usz + o, cbu - o, _TRUNCATE, " exittime:[%s]", szTimeEXIT);
    }
    if(pProcess->win.Token && pProcess->win.Token->IntegrityLevel) {
        o += _snprintf_s(usz + o, cbu - o, _TRUNCATE, " integrity:[%s]", VMM_TOKEN_INTEGRITY_LEVEL_STR[pProcess->win.Token->IntegrityLevel]);
    }
    pd->usz[1] = usz;
    pfnLogJSON(H, pd);
    if(usz != uszBuffer) { LocalFree(usz); }
}

VOID MFcProc_FcLogJSON(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_CONTEXT ctxP, _In_ VOID(*pfnLogJSON)(_In_ VMM_HANDLE H, _In_ PVMMDLL_FORENSIC_JSONDATA pData))
{
    PVMM_PROCESS pProcess = ctxP->pProcess;
    PVMMDLL_FORENSIC_JSONDATA pd;
    PVMMOB_MAP_HEAP pObHeapMap = NULL;
    if(!pProcess || !(pd = LocalAlloc(LMEM_ZEROINIT, sizeof(VMMDLL_FORENSIC_JSONDATA)))) { return; }
    // process:
    FC_JSONDATA_INIT_PIDTYPE(pd, pProcess->dwPID, "process");
    MFcProc_LogProcess(H, pd, pfnLogJSON, pProcess);
    // heap:
    FC_JSONDATA_INIT_PIDTYPE(pd, pProcess->dwPID, "heap");
    if(VmmMap_GetHeap(H, pProcess, &pObHeapMap)) {
        MFcProc_LogHeap(H, pd, pfnLogJSON, pObHeapMap);
    }
    Ob_DECREF(pObHeapMap);
    LocalFree(pd);
}

static VOID MFcProc_BuildFlagString(_In_ PVMM_PROCESS pProcess, _In_ BOOL fAccountUser, _Out_writes_(8) LPSTR szFlag)
{
    SIZE_T o = 0;
    if(pProcess->win.fWow64) { szFlag[o++] = '3'; szFlag[o++] = '2'; }
    if(pProcess->win.EPROCESS.fNoLink) { szFlag[o++] = 'E'; }
    if(pProcess->dwState != 0) { szFlag[o++] = 'T'; }
    if(fAccountUser) { szFlag[o++] = 'U'; }
    if(o == 0) {
        szFlag[o++] = '-';
    }
    szFlag[o] = '\0';
}

VOID MFcProc_FcLogCSV(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_CONTEXT ctxP, _In_ VMMDLL_CSV_HANDLE hCSV)
{
    PVMM_PROCESS pProcess = ctxP->pProcess;
    PVMMWIN_USER_PROCESS_PARAMETERS pu;
    BOOL fAccountUser = FALSE;
    CHAR szUserName[17];
    CHAR szFlag[8];
    if(!pProcess) { return; }
    pu = VmmWin_UserProcessParameters_Get(H, pProcess);
    MFcProc_BuildFlagString(pProcess, fAccountUser, szFlag);
    MFcProc_LogProcess_GetUserName(H, pProcess, szUserName, &fAccountUser);
    FcCsv_Reset(hCSV);
    FcFileAppend(H, "process.csv", "%i,%i,%i,%s,%s,%s,%s,%s,%s,%i,0x%llx,0x%llx,0x%x,0x%llx,0x%llx,%s,%s,%s,%s\n",
        pProcess->dwPID,
        pProcess->dwPPID,
        pProcess->dwState,
        FcCsv_String(hCSV, pProcess->szName),
        FcCsv_String(hCSV, pProcess->pObPersistent->uszNameLong),
        FcCsv_String(hCSV, (LPSTR)VMM_TOKEN_INTEGRITY_LEVEL_STR[pProcess->win.Token ? pProcess->win.Token->IntegrityLevel : 0]),
        FcCsv_String(hCSV, szUserName),
        FcCsv_FileTime(hCSV, VmmProcess_GetCreateTimeOpt(H, pProcess)),
        FcCsv_FileTime(hCSV, VmmProcess_GetExitTimeOpt(H, pProcess)),
        pProcess->win.fWow64 ? 1 : 0,
        pProcess->win.EPROCESS.va,
        pProcess->win.vaPEB,
        pProcess->win.vaPEB32,
        pProcess->paDTB,
        pProcess->paDTB_UserOpt,
        FcCsv_String(hCSV, pu->uszImagePathName),
        FcCsv_String(hCSV, pProcess->pObPersistent->uszPathKernel),
        FcCsv_String(hCSV, pu->uszCommandLine),
        FcCsv_String(hCSV, szFlag)
    );
}

/*
* Plugin initialization / registration function called by the plugin manager.
* -- H
* -- pRI
*/
VOID M_FcProc_Initialize(_In_ VMM_HANDLE H, _Inout_ PVMMDLL_PLUGIN_REGINFO pRI)
{
    if((pRI->magic != VMMDLL_PLUGIN_REGINFO_MAGIC) || (pRI->wVersion != VMMDLL_PLUGIN_REGINFO_VERSION)) { return; }
    if((pRI->tpSystem != VMM_SYSTEM_WINDOWS_64) && (pRI->tpSystem != VMM_SYSTEM_WINDOWS_32)) { return; }
    strcpy_s(pRI->reg_info.uszPathName, 128, "\\forensic\\hidden\\proc");       // module name
    pRI->reg_info.fRootModule = TRUE;                                           // module shows in root directory
    pRI->reg_info.fRootModuleHidden = TRUE;                                     // module hidden by default
    pRI->reg_fnfc.pfnInitialize = MFcProc_FcInitialize;                         // Forensic initialize function supported
    pRI->reg_fnfc.pfnTimeline = MFcProc_FcTimeline;                             // Forensic timelining supported
    pRI->reg_fnfc.pfnLogCSV = MFcProc_FcLogCSV;                                 // CSV log function supported
    pRI->reg_fnfc.pfnLogJSON = MFcProc_FcLogJSON;                               // JSON log function supported
    memcpy(pRI->reg_info.sTimelineNameShort, "PROC", 5);
    strncpy_s(pRI->reg_info.uszTimelineFile, 32, "timeline_process", _TRUNCATE);
    pRI->pfnPluginManager_Register(H, pRI);
}
