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
// (c) Ulf Frisk, 2020
// Author: Ulf Frisk, pcileech@frizk.net
//

#include "fc.h"
#include "vmmdll.h"
#include "pdb.h"
#include "vmmwin.h"
#include "vmmwinreg.h"
#include "pluginmanager.h"
#include "include/sqlite3.h"
#include "util.h"
#include <bcrypt.h>

static LPSTR FC_SQL_SCHEMA_PFN =
    "DROP TABLE IF EXISTS pfn; " \
    "CREATE TABLE pfn ( pfn INTEGER PRIMARY KEY, tp INTEGER, tpex INTEGER, pid INTEGER, va INTEGER, hash BLOB ); ";
static LPSTR FC_SQL_SCHEMA_STR =
    "DROP TABLE IF EXISTS str; " \
    "CREATE TABLE str ( id INTEGER PRIMARY KEY, osz, csz INT, cbu INT, cbj INT, sz TEXT ); ";
static LPSTR FC_SQL_SCHEMA_NTFS =
    "DROP VIEW IF EXISTS v_ntfs; " \
    "DROP TABLE IF EXISTS ntfs; " \
    "CREATE TABLE ntfs ( id INTEGER PRIMARY KEY, id_parent INTEGER, id_str INTEGER, hash INTEGER, hash_parent INTEGER, addr_phys INTEGER, inode INTEGER, mft_flags INTEGER, depth INTEGER, size_file INTEGER, size_fileres INTEGER, time_create INTEGER, time_modify INTEGER, time_read INTEGER, name_seq INTEGER, oln_u INTEGER, oln_j INTEGER );" \
    "CREATE INDEX idx_ntfs_hash ON ntfs(hash); " \
    "CREATE INDEX idx_ntfs_hash_parent ON ntfs(hash_parent); " \
    "CREATE INDEX idx_oln_u ON ntfs(oln_u); " \
    "CREATE VIEW v_ntfs AS SELECT *, SUBSTR(sz, osz+1) AS sz_sub FROM ntfs, str WHERE ntfs.id_str = str.id; ";
static LPSTR FC_SQL_SCHEMA_PROCESS =
    "DROP TABLE IF EXISTS process; " \
    "CREATE TABLE process(id INTEGER PRIMARY KEY AUTOINCREMENT, id_str_name INTEGER, id_str_path INTEGER, id_str_user INTEGER, id_str_all INTEGER, pid INT, ppid INT, eprocess INTEGER, dtb INTEGER, dtb_user INTEGER, state INTEGER, wow64 INT, peb INTEGER, peb32 INTEGER, time_create INTEGER, time_exit INTEGER); " \
    "DROP VIEW IF EXISTS v_process; " \
    "CREATE VIEW v_process AS SELECT p.*, sn.csz AS csz_name, sn.cbu AS cbu_name, sn.cbj AS cbj_name, sn.sz AS sz_name, sp.csz AS csz_path, sp.cbu AS cbu_path, sp.cbj AS cbj_path, sp.sz AS sz_path, su.csz AS csz_user, su.cbu AS cbu_user, su.cbj AS cbj_user, su.sz AS sz_user, sa.csz AS csz_all, sa.cbu AS cbu_all, sa.cbj AS cbj_all, sa.sz AS sz_all FROM process p, str sn, str sp, str su, str sa WHERE p.id_str_name = sn.id AND p.id_str_path = sp.id AND p.id_str_user = su.id AND  p.id_str_all = sa.id; ";
static LPSTR FC_SQL_SCHEMA_THREAD =
    "DROP TABLE IF EXISTS thread; " \
    "CREATE TABLE thread(id INTEGER PRIMARY KEY AUTOINCREMENT, id_str INTEGER, pid INT, tid INT, ethread INTEGER, teb INTEGER, state INT, exitstatus INT, running INT, prio INT, priobase INT, startaddr INTEGER, stackbase_u INTEGER, stacklimit_u INTEGER, stackbase_k INTEGER, stacklimit_k INTEGER, trapframe INTEGER, sp INTEGER, ip INTEGER, time_create INTEGER, time_exit INTEGER); " \
    "DROP VIEW IF EXISTS v_thread; " \
    "CREATE VIEW v_thread AS SELECT t.*, str.* FROM thread t, str WHERE t.id_str = str.id; ";
static LPSTR FC_SQL_SCHEMA_REGISTRY =
    "DROP VIEW IF EXISTS v_registry; " \
    "DROP TABLE IF EXISTS registry; " \
    "CREATE TABLE registry ( id INTEGER PRIMARY KEY AUTOINCREMENT, id_str INTEGER, hive INTEGER, cell INTEGER, cell_parent INTEGER, time INTEGER ); " \
    "CREATE VIEW v_registry AS SELECT *, SUBSTR(sz, osz+1) AS sz_sub FROM registry, str WHERE registry.id_str = str.id; ";



// ----------------------------------------------------------------------------
// FORWARD DECLARATIONS FORENSIC INTERNAL FUNCTIONALITY:
// ----------------------------------------------------------------------------

/*
* Initialize a new empty PFCNTFS_SETUP_CONTEXT.
* -- return = the initialized context, or NULL on fail.
*/
PVOID FcNtfs_SetupInitialize();

/*
* Analyze a POB_FC_SCANPHYSMEM_CHUNK 16MB memory chunk for MFT file candidates
* and add any found to the internal data sets. This function is meant to be
* called asynchronously by a worker thread (VmmWork). Function is thread-safe.
* -- pc
*/
VOID FcNtfs_Setup_ThreadProc(_In_ POB_FC_SCANPHYSMEM_CHUNK pc);

/*
* Finalize the NTFS setup/initialization phase. Try to put re-assemble the NTFS
* MFT file fragments into some kind of usable file-system approximation using
* heuristics and save it to the forensic database.
* -- pvSetupContextNtfs
* -- fScanSuccess
*/
VOID FcNtfs_SetupFinalize(_In_opt_ PVOID pvSetupContextNtfs, _In_ BOOL fScanSuccess);

/*
* Initialize the timelining functionality. Before the timelining functionality
* is initialized processes, threads, registry and ntfs must be initialized.
* Initialization may take some time.
* -- return
*/
_Success_(return)
BOOL FcTimeline_Initialize();



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
        vmmprintf_fn("FATAL DATABASE ERROR: WaitForMultipleObjects ERROR: 0x%08x\n", iWaitNum + WAIT_OBJECT_0);
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
BOOL Fc_SqlInsertStr(_In_ sqlite3_stmt *hStmt, _In_ LPWSTR wsz, _In_ DWORD owszSub, _Out_ PFCSQL_INSERTSTRTABLE pThis)
{
    CHAR szUTF8[2048];
    pThis->cwsz = (DWORD)wcslen(wsz);
    if(pThis->cwsz < owszSub) { return FALSE; }
    pThis->cbu = WideCharToMultiByte(CP_UTF8, 0, wsz, -1, szUTF8, sizeof(szUTF8), NULL, NULL);
    if(!pThis->cbu) { return FALSE; }
    pThis->cbu--;               // don't count null terminator.
    pThis->cbj = pThis->cbu;    // TODO: FIX THIS - CALCULATE FOR JSON ESPAPE CHARS !!!
    pThis->id = InterlockedIncrement64(&ctxFc->db.qwIdStr);
    sqlite3_reset(hStmt);
    sqlite3_bind_int64(hStmt, 1, pThis->id);
    sqlite3_bind_int(hStmt, 2, owszSub);
    sqlite3_bind_int(hStmt, 3, pThis->cwsz);
    sqlite3_bind_int(hStmt, 4, pThis->cbu);
    sqlite3_bind_int(hStmt, 5, pThis->cbj);
    sqlite3_bind_text(hStmt, 6, szUTF8, -1, NULL);
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

_Success_(return)
BOOL Fc_SqlInitializeDatabaseTables()
{
    if(SQLITE_OK != Fc_SqlExec(FC_SQL_SCHEMA_PFN)) { return FALSE; }
    if(SQLITE_OK != Fc_SqlExec(FC_SQL_SCHEMA_STR)) { return FALSE; }
    if(SQLITE_OK != Fc_SqlExec(FC_SQL_SCHEMA_NTFS)) { return FALSE; }
    if(SQLITE_OK != Fc_SqlExec(FC_SQL_SCHEMA_PROCESS)) { return FALSE; }
    if(SQLITE_OK != Fc_SqlExec(FC_SQL_SCHEMA_THREAD)) { return FALSE; }
    if(SQLITE_OK != Fc_SqlExec(FC_SQL_SCHEMA_REGISTRY)) { return FALSE; }
    return TRUE;
}



// ----------------------------------------------------------------------------
// PFN / PAGE HASHING FUNCTIONALITY:
// ----------------------------------------------------------------------------

typedef struct tdFCPFN_SETUP_CONTEXT {
    BCRYPT_HASH_HANDLE hMultiHash;
} FCPFN_SETUP_CONTEXT, *PFCPFN_SETUP_CONTEXT;

VOID FcPfn_InitializeClose(_Frees_ptr_opt_ PFCPFN_SETUP_CONTEXT ctx)
{
    if(ctx && ctx->hMultiHash) {
        BCryptDestroyHash(ctx->hMultiHash);
    }
    LocalFree(ctx);
}

VOID FcPfn_Finalize(_In_opt_ PVOID pvSetupContextPfn, _In_ BOOL fScanSuccess)
{
    FcPfn_InitializeClose((PFCPFN_SETUP_CONTEXT)pvSetupContextPfn);
    ctxFc->fEnablePfn = fScanSuccess;
}

/*
* Initialize a PFN setup context.
* -- return = the initialized context, or NULL on fail.
*/
PVOID FcPfn_Initialize()
{
    NTSTATUS nt;
    PFCPFN_SETUP_CONTEXT ctx = NULL;
    if(!(ctx = LocalAlloc(LMEM_ZEROINIT, sizeof(FCPFN_SETUP_CONTEXT)))) { goto fail; }
    // CREATE BCRYPT MULTI HASH
    nt = BCryptCreateMultiHash(
        BCRYPT_SHA256_ALG_HANDLE,
        &ctx->hMultiHash,
        FC_PHYSMEM_NUM_CHUNKS,
        NULL,
        0,
        NULL,
        0,
        BCRYPT_HASH_REUSABLE_FLAG
    );
    if(nt != STATUS_SUCCESS) { goto fail; }
    return ctx;
fail:
    FcPfn_InitializeClose(ctx);
    return NULL;
}

/*
* Analyze a POB_FC_SCANPHYSMEM_CHUNK 16MB memory chunk for MFT file candidates
* and add any found to the internal data sets. This function is meant to be
* called asynchronously by a worker thread (VmmWork). This function is thread-safe.
* -- pc
*/
VOID FcPfn_Setup_ThreadProc(_In_ POB_FC_SCANPHYSMEM_CHUNK pc)
{
    PFCPFN_SETUP_CONTEXT ctx = (PFCPFN_SETUP_CONTEXT)pc->ctx_PFN;
    BCRYPT_MULTI_HASH_OPERATION *pMultiFinishOps, *pMultiHashOps = NULL;
    PBYTE pbMultiHash = NULL;
    DWORD i, iHash = 0;
    NTSTATUS nt;
    int rc;
    sqlite3 *hSql = NULL;
    sqlite3_stmt *hSqlStmt = NULL;
    PMMPFN_MAP_ENTRY pePfn;
    // 1: INITIALIZE HASHING
    if(!(pbMultiHash = LocalAlloc(0, 32 * FC_PHYSMEM_NUM_CHUNKS))) { goto fail; }
    if(!(pMultiHashOps = LocalAlloc(0, 2 * FC_PHYSMEM_NUM_CHUNKS * sizeof(BCRYPT_MULTI_HASH_OPERATION)))) { goto fail; }
    pMultiFinishOps = pMultiHashOps + FC_PHYSMEM_NUM_CHUNKS;
    for(i = 0; i < FC_PHYSMEM_NUM_CHUNKS; i++) {
        if((pc->ppMEMs[i]->qwA != (QWORD)-1) && pc->ppMEMs[i]->f && (pc->ppMEMs[i]->cb == 0x1000)) {
            pMultiHashOps[iHash].iHash = iHash;
            pMultiHashOps[iHash].hashOperation = BCRYPT_OPERATION_TYPE_HASH;
            pMultiHashOps[iHash].pbBuffer = pc->ppMEMs[i]->pb;
            pMultiHashOps[iHash].cbBuffer = 0x1000;
            pMultiFinishOps[iHash].iHash = iHash;
            pMultiFinishOps[iHash].hashOperation = BCRYPT_HASH_OPERATION_FINISH_HASH;
            pMultiFinishOps[iHash].pbBuffer = pbMultiHash + 32ULL * i;
            pMultiFinishOps[iHash].cbBuffer = 32;
            iHash++;
        }
    }
    // 2: HASH
    nt = BCryptProcessMultiOperations(ctx->hMultiHash, BCRYPT_OPERATION_TYPE_HASH, pMultiHashOps, iHash * sizeof(BCRYPT_MULTI_HASH_OPERATION), 0);
    if(nt != STATUS_SUCCESS) { goto fail; }
    nt = BCryptProcessMultiOperations(ctx->hMultiHash, BCRYPT_OPERATION_TYPE_HASH, pMultiFinishOps, iHash * sizeof(BCRYPT_MULTI_HASH_OPERATION), 0);
    if(nt != STATUS_SUCCESS) { goto fail; }
    // 3: INSERT INTO DATABASE
    if(!(hSql = Fc_SqlReserve())) { goto fail; }
    rc = sqlite3_prepare_v2(hSql, "INSERT INTO pfn (pfn, tp, tpex, pid, va, hash) VALUES (?, ?, ?, ?, ?, ?);", -1, &hSqlStmt, NULL);
    if(rc != SQLITE_OK) { goto fail; }
    sqlite3_exec(hSql, "BEGIN TRANSACTION", NULL, NULL, NULL);
    for(i = 0; i < pc->pPfnMap->cMap; i++) {
        pePfn = pc->pPfnMap->pMap + i;
        sqlite3_reset(hSqlStmt);
        sqlite3_bind_int(hSqlStmt, 1, pePfn->dwPfn);
        sqlite3_bind_int(hSqlStmt, 2, pePfn->PageLocation);
        sqlite3_bind_int(hSqlStmt, 3, pePfn->tpExtended);
        sqlite3_bind_int(hSqlStmt, 4, pePfn->AddressInfo.dwPid);
        sqlite3_bind_int64(hSqlStmt, 5, pePfn->AddressInfo.va);
        if((pc->ppMEMs[i]->qwA != (QWORD)-1) && pc->ppMEMs[i]->f && (pc->ppMEMs[i]->cb == 0x1000)) {
            sqlite3_bind_blob(hSqlStmt, 6, pbMultiHash + 32ULL * i, 32, NULL);
        } else {
            sqlite3_bind_null(hSqlStmt, 6);
        }
        sqlite3_step(hSqlStmt);
    }
    sqlite3_exec(hSql, "COMMIT TRANSACTION", NULL, NULL, NULL);
fail:
    sqlite3_finalize(hSqlStmt);
    Fc_SqlReserveReturn(hSql);
    LocalFree(pMultiHashOps);
    LocalFree(pbMultiHash);
}



// ----------------------------------------------------------------------------
// REGISTRY FUNCTIONALITY BELOW:
// ----------------------------------------------------------------------------

VOID FcWinReg_Initialize_CallbackAddEntry(_In_ HANDLE hCallback1, _In_ HANDLE hCallback2, _In_ LPWSTR wszPathName, _In_ DWORD owszName, _In_ QWORD vaHive, _In_ DWORD dwCell, _In_ DWORD dwCellParent, _In_ QWORD ftLastWrite)
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

_Success_(return)
BOOL FcWinReg_Initialize()
{
    BOOL fResult = FALSE;
    POB_REGISTRY_HIVE pObHive = NULL;
    sqlite3 *hSql = NULL;
    sqlite3_stmt *hStmt = NULL, *hStmtStr = NULL;
    if(!(hSql = Fc_SqlReserve())) { goto fail; }
    if(SQLITE_OK != sqlite3_prepare_v2(hSql, "INSERT INTO registry (id_str, hive, cell, cell_parent, time) VALUES (?, ?, ?, ?, ?);", -1, &hStmt, NULL)) { goto fail; }
    if(SQLITE_OK != sqlite3_prepare_v2(hSql, "INSERT INTO str (id, osz, csz, cbu, cbj, sz) VALUES (?, ?, ?, ?, ?, ?);", -1, &hStmtStr, NULL)) { goto fail; }
    sqlite3_exec(hSql, "BEGIN TRANSACTION", NULL, NULL, NULL);
    while(pObHive = VmmWinReg_HiveGetNext(pObHive)) {
        VmmWinReg_ForensicGetAllKeys(pObHive, hStmt, hStmtStr, FcWinReg_Initialize_CallbackAddEntry);
    }
    sqlite3_exec(hSql, "COMMIT TRANSACTION", NULL, NULL, NULL);
    ctxFc->fEnableRegistry = TRUE;
    fResult = TRUE;
fail:
    Ob_DECREF(pObHive);
    sqlite3_finalize(hStmt);
    sqlite3_finalize(hStmtStr);
    Fc_SqlReserveReturn(hSql);
    return fResult;
}



// ----------------------------------------------------------------------------
// PROCESS AND THREAD FUNCTIONALITY BELOW:
// ----------------------------------------------------------------------------

_Success_(return)
BOOL FcProcess_Initialize()
{
    int rc;
    BOOL fResult = FALSE, fWellKnownAccount = FALSE;
    PVMM_PROCESS pObProcess = NULL;
    sqlite3 *hSql = NULL;
    sqlite3_stmt *hStmt = NULL, *hStmtStr = NULL;
    FCSQL_INSERTSTRTABLE SqlStrInsert[4];
    WCHAR wszUserName[MAX_PATH], wszFullInfo[2048];
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
    ctxFc->fEnableProcess = TRUE;
    fResult = TRUE;
fail:
    Ob_DECREF(pObProcess);
    sqlite3_finalize(hStmt);
    sqlite3_finalize(hStmtStr);
    Fc_SqlReserveReturn(hSql);
    return fResult;
fail_transact:
    sqlite3_exec(hSql, "COMMIT TRANSACTION", NULL, NULL, NULL);
    goto fail;
}

VOID FcThread_ThreadProc(_In_ PVMM_PROCESS pProcess, _In_ PVOID pv)
{
    int rc;
    sqlite3 *hSql = NULL;
    sqlite3_stmt *hStmt = NULL, *hStmtStr = NULL;
    DWORD i;
    PVMMOB_MAP_THREAD pObThreadMap = NULL;
    PVMM_MAP_THREADENTRY pe;
    WCHAR wszStr[MAX_PATH];
    FCSQL_INSERTSTRTABLE SqlStrInsert;
    if(!VmmMap_GetThread(pProcess, &pObThreadMap)) { goto fail; }
    if(!(hSql = Fc_SqlReserve())) { goto fail; }
    if(SQLITE_OK != sqlite3_prepare_v2(hSql, "INSERT INTO thread (id_str, pid, tid, ethread, teb, state, exitstatus, running, prio, priobase, startaddr, stackbase_u, stacklimit_u, stackbase_k, stacklimit_k, trapframe, sp, ip, time_create, time_exit) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);", -1, &hStmt, NULL)) { goto fail; }
    if(SQLITE_OK != sqlite3_prepare_v2(hSql, "INSERT INTO str (id, osz, csz, cbu, cbj, sz) VALUES (?, ?, ?, ?, ?, ?);", -1, &hStmtStr, NULL)) { goto fail; }
    sqlite3_exec(hSql, "BEGIN TRANSACTION", NULL, NULL, NULL);
    for(i = 0; i < pObThreadMap->cMap; i++) {
        pe = pObThreadMap->pMap + i;
        swprintf(wszStr, _countof(wszStr), L"TID: %i", pe->dwTID);
        if(!Fc_SqlInsertStr(hStmtStr, wszStr, 0, &SqlStrInsert)) { goto fail_transact; }
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

_Success_(return)
BOOL FcThread_Initialize()
{
    VmmProcessActionForeachParallel(NULL, VmmProcessActionForeachParallel_CriteriaActiveOnly, FcThread_ThreadProc);
    ctxFc->fEnableThread = TRUE;
    return TRUE;
}



// ----------------------------------------------------------------------------
// PHYSICAL MEMORY SCAN FUNCTIONALITY BELOW:
// Physical memory is scanned and analyzed in parallel. Currently
// the physical memory consumers are:
// - PFN / HASH
// - NTFS MFT ANALYZE
// ----------------------------------------------------------------------------

VOID FcScanPhysMem_CallbackCleanup_ObChunk(POB_FC_SCANPHYSMEM_CHUNK pOb)
{
    for(DWORD i = 0; i < sizeof(pOb->hEventFinish) / sizeof(HANDLE); i++) {
        if(pOb->hEventFinish[i]) {
            CloseHandle(pOb->hEventFinish[i]);
        }
    }
    LcMemFree(pOb->ppMEMs);
}

/*
* Physical Memory Scan Loop - function is meant to be running in asynchronously
* with one thread calling only. The function allocates two 16MB chunks and will
* begin to loop-read physical memory into a chunk, call consumers asynchronously
* and continue to read next 16MB chunk (if consumers are finished processing).
* Currently the consumers are:
* - NTFS MFT SCAN
* - SHA256 PAGE HASHING
*/
VOID FcScanPhysMem()
{
    BOOL fValidMEMs, fValidAddr, fScanSuccess = FALSE;
    QWORD i, j, iChunk = 0, pa, paBase;
    POB_FC_SCANPHYSMEM_CHUNK pc, pObScanChunk[2] = { 0 };
    PVOID ctx_Pfn = NULL, ctx_Ntfs = NULL;
    PMMPFN_MAP_ENTRY pePfn;
    // 1: initialize two 16MB physical memory scan chunks
    for(i = 0; i < 2; i++) {
        if(!(pObScanChunk[i] = Ob_Alloc('FSCN', LMEM_ZEROINIT, sizeof(OB_FC_SCANPHYSMEM_CHUNK), FcScanPhysMem_CallbackCleanup_ObChunk, NULL))) { goto fail; }
        if(!LcAllocScatter1(FC_PHYSMEM_NUM_CHUNKS, &pObScanChunk[i]->ppMEMs)) { goto fail; }
        for(j = 0; j < FC_PHYSMEMSCAN_CONSUMERS; j++) {
            if(!(pObScanChunk[i]->hEventFinish[j] = CreateEvent(NULL, TRUE, TRUE, NULL))) { goto fail; }
        }
    }
    // 2: initialize scan consumers
    ctx_Pfn = FcPfn_Initialize();
    ctx_Ntfs = FcNtfs_SetupInitialize();
    for(i = 0; i < 2; i++) {
        pObScanChunk[i]->ctx_PFN = ctx_Pfn;
        pObScanChunk[i]->ctx_NTFS = ctx_Ntfs;
    }
    // 3: main physical memory scan loop
    for(paBase = 0; paBase < ctxMain->dev.paMax; paBase += 0x1000 * FC_PHYSMEM_NUM_CHUNKS) {
        vmmprintfvv_fn("PhysicalAddress=%016llx\n", paBase);
        // 3.1: get entry and wait for previous consumers to finish
        pc = pObScanChunk[++iChunk % 2];
        WaitForMultipleObjects(FC_PHYSMEMSCAN_CONSUMERS, pc->hEventFinish, TRUE, INFINITE);
        if(!ctxVmm->Work.fEnabled) { goto fail; }
        // 3.2: init pfn map
        Ob_DECREF_NULL(&pc->pPfnMap);
        MmPfn_Map_GetPfn((DWORD)(paBase >> 12), FC_PHYSMEM_NUM_CHUNKS, &pc->pPfnMap, TRUE);
        // 3.3: init addresses & read
        for(i = 0, fValidMEMs = FALSE; i < FC_PHYSMEM_NUM_CHUNKS; i++) {
            pa = paBase + (i << 12);
            fValidAddr = (pa <= ctxMain->dev.paMax);
            if(fValidAddr) {
                pePfn = (pc->pPfnMap && (i < pc->pPfnMap->cMap)) ? (pc->pPfnMap->pMap + i) : NULL;
                fValidAddr =
                    !pePfn ||
                    (pePfn->PageLocation == MmPfnTypeStandby) ||
                    (pePfn->PageLocation == MmPfnTypeModified) ||
                    (pePfn->PageLocation == MmPfnTypeModifiedNoWrite) ||
                    (pePfn->PageLocation == MmPfnTypeTransition) ||
                    (pePfn->PageLocation == MmPfnTypeActive);
            }
            pc->ppMEMs[i]->qwA = fValidAddr ? pa : (QWORD)-1;
            pc->ppMEMs[i]->cb = 0x1000;
            pc->ppMEMs[i]->f = FALSE;
            fValidMEMs = fValidMEMs || fValidAddr;
        }
        if(fValidMEMs) {
            VmmReadScatterPhysical(pc->ppMEMs, FC_PHYSMEM_NUM_CHUNKS, VMM_FLAG_NOCACHEPUT);
        }
        if(!ctxVmm->Work.fEnabled) { goto fail; }
        // 3.4: schedule work onto consumers
        //if(pc->ctx_PFN) {
        //    ResetEvent(pc->hEventFinish_PFN);
        //    VmmWork((LPTHREAD_START_ROUTINE)FcPfn_Setup_ThreadProc, pc, pc->hEventFinish_PFN);
        //}
        if(pc->ctx_NTFS) {
            ResetEvent(pc->hEventFinish_NTFS);
            VmmWork((LPTHREAD_START_ROUTINE)FcNtfs_Setup_ThreadProc, pc, pc->hEventFinish_NTFS);
        }
    }
    // 4: finalize scan consumers
    fScanSuccess = TRUE;
fail:
    // 5: wait for any worker sub-threads to finish
    for(i = 0; i < 2; i++) {
        if(pObScanChunk[i] && pObScanChunk[i]->hEventFinish[FC_PHYSMEMSCAN_CONSUMERS - 1]) {
            WaitForMultipleObjects(FC_PHYSMEMSCAN_CONSUMERS, pObScanChunk[i]->hEventFinish, TRUE, INFINITE);
        }
    }
    // 6: call work customer finalize functionality
    FcPfn_Finalize(ctx_Pfn, fScanSuccess);
    FcNtfs_SetupFinalize(ctx_Ntfs, fScanSuccess);
    // 7: clean up / close
    for(i = 0; i < 2; i++) {
        if(!(pc = pObScanChunk[i])) { continue; }
        for(j = 0; j < FC_PHYSMEMSCAN_CONSUMERS; j++) {
            if(pc->hEventFinish[j]) {
                CloseHandle(pc->hEventFinish[j]);
            }
        }
        LcMemFree(pc->ppMEMs);
        Ob_DECREF(pc->pPfnMap);
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
    Fc_SqlInitializeDatabaseTables();
    FcProcess_Initialize();
    FcThread_Initialize();
    FcWinReg_Initialize();
    FcScanPhysMem();
    FcTimeline_Initialize();
    ctxFc->db.fSingleThread = FALSE;
    ctxFc->fInitFinish = TRUE;
    PluginManager_Notify(VMMDLL_PLUGIN_EVENT_FORENSIC_INIT, NULL, 100);
    PluginManager_Notify(VMMDLL_PLUGIN_EVENT_FORENSIC_INIT_COMPLETE, NULL, 0);
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
        DeleteFileW(ctxFc->db.wszDatabaseWinPath);
    }
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
    LPSTR szu8;
    DWORD i, cch;
    WCHAR wszTemp[MAX_PATH], wszTempShort[MAX_PATH];
    SYSTEMTIME st;
    if(dwDatabaseType == FC_DATABASE_TYPE_MEMORY) {
        ctxFc->db.tp = FC_DATABASE_TYPE_MEMORY;
        strcpy_s(ctxFc->db.szuDatabase, _countof(ctxFc->db.szuDatabase), "file:///memorydb?mode=memory");
        return TRUE;
    }
    cch = GetTempPathW(_countof(wszTempShort), wszTempShort);
    if(!cch || cch > 128) { return FALSE; }
    cch = GetLongPathNameW(wszTempShort, wszTemp, _countof(wszTemp));
    if(!cch || cch > 128) { return FALSE; }
    if((dwDatabaseType == FC_DATABASE_TYPE_TEMPFILE_CLOSE) || (dwDatabaseType == FC_DATABASE_TYPE_TEMPFILE_NOCLOSE)) {
        GetLocalTime(&st);
        _snwprintf_s(
            wszTemp + wcslen(wszTemp),
            _countof(wszTemp) - wcslen(wszTemp),
            _TRUNCATE,
            L"vmm-%i%02i%02i-%02i%02i%02i.sqlite3",
            st.wYear,
            st.wMonth,
            st.wDay,
            st.wHour,
            st.wMinute,
            st.wSecond);
    } else {
        wcscat_s(wszTemp, _countof(wszTemp), L"vmm.sqlite3");
    }
    // check length, copy into ctxFc and finish
    if(wcslen_u8(wszTemp) > MAX_PATH - 10) { return FALSE; }
    wcscpy_s(ctxFc->db.wszDatabaseWinPath, _countof(ctxFc->db.wszDatabaseWinPath), wszTemp);
    for(i = 0; i < MAX_PATH; i++) {
        if(wszTemp[i] == '\\') { wszTemp[i] = '/'; }
    }
    szu8 = Util_StrDupW2U8(wszTemp);
    strcpy_s(ctxFc->db.szuDatabase, _countof(ctxFc->db.szuDatabase), "file:///");
    strcat_s(ctxFc->db.szuDatabase, _countof(ctxFc->db.szuDatabase), szu8);
    LocalFree(szu8);
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
    if(ctxMain->dev.fVolatile) { return FALSE; }
    if(!dwDatabaseType || (dwDatabaseType > FC_DATABASE_TYPE_MAX)) { return FALSE; }
    if(ctxFc && !fForceReInit) { return FALSE; }
    PDB_Initialize_WaitComplete();
    // 1: ALLOCATE AND INITIALIZE.
    if(ctxFc) { FcClose(); }
    if(!(ctxFc = (PFC_CONTEXT)LocalAlloc(LMEM_ZEROINIT, sizeof(FC_CONTEXT)))) { goto fail; }
    InitializeCriticalSection(&ctxFc->Lock);
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
