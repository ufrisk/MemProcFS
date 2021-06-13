// infodb.c : implementation of the information read-only sqlite database.
//
// (c) Ulf Frisk, 2021
// Author: Ulf Frisk, pcileech@frizk.net
//
#include "infodb.h"
#include "pe.h"
#include "charutil.h"
#include "util.h"
#include "sqlite/sqlite3.h"

#define INFODB_SQL_POOL_CONNECTION_NUM          4

typedef struct tdOB_INFODB_CONTEXT {
    OB ObHdr;
    DWORD dwPdbId_NT;
    DWORD dwPdbId_TcpIp;
    BOOL fPdbId_TcpIp_TryComplete;
    HANDLE hEvent[INFODB_SQL_POOL_CONNECTION_NUM];
    sqlite3 *hSql[INFODB_SQL_POOL_CONNECTION_NUM];
} OB_INFODB_CONTEXT, *POB_INFODB_CONTEXT;


// ----------------------------------------------------------------------------
// SQLITE GENERAL FUNCTIONALITY:
// ----------------------------------------------------------------------------

/*
* Retrieve an SQLITE database handle. The retrieved handle must be
* returned with Fc_SqlReserveReturn().
* -- ctx
* -- return = an SQLITE handle, or NULL on error.
*/
_Success_(return != NULL)
sqlite3 *InfoDB_SqlReserve(_In_ POB_INFODB_CONTEXT ctx)
{
    DWORD iWaitNum = 0;
    iWaitNum = WaitForMultipleObjects(INFODB_SQL_POOL_CONNECTION_NUM, ctx->hEvent, FALSE, INFINITE) - WAIT_OBJECT_0;
    if(iWaitNum >= INFODB_SQL_POOL_CONNECTION_NUM) {
        vmmprintf_fn("FATAL DATABASE ERROR: WaitForMultipleObjects ERROR: 0x%08x\n", (DWORD)(iWaitNum + WAIT_OBJECT_0));
        return NULL;
    }
    return ctx->hSql[iWaitNum];
}

/*
* Return a SQLITE database handle previously retrieved with Fc_SqlReserve()
* so that other threads may use it.
* -- ctx
* -- hSql = the SQLITE database handle.
* -- return = always NULL.
*/
_Success_(return != NULL)
sqlite3 *InfoDB_SqlReserveReturn(_In_ POB_INFODB_CONTEXT ctx, _In_opt_ sqlite3 *hSql)
{
    DWORD i;
    if(!hSql) { return NULL; }
    for(i = 0; i < INFODB_SQL_POOL_CONNECTION_NUM; i++) {
        if(ctx->hSql[i] == hSql) {
            SetEvent(ctx->hEvent[i]);
            break;
        }
    }
    return NULL;
}

/*
* Execute a single SQLITE database SQL query and return the SQLITE result code.
* -- ctx
* -- szSql
* -- return = sqlite return code.
*/
_Success_(return == SQLITE_OK)
int InfoDB_SqlExec(_In_ POB_INFODB_CONTEXT ctx, _In_ LPSTR szSql)
{
    int rc = SQLITE_ERROR;
    sqlite3 *hSql = InfoDB_SqlReserve(ctx);
    if(hSql) {
        rc = sqlite3_exec(hSql, szSql, NULL, NULL, NULL);
        InfoDB_SqlReserveReturn(ctx, hSql);
    }
    return rc;
}

/*
* Execute a single SQLITE database SQL query and return all results as numeric
* 64-bit results in an array that must have capacity to hold all values.
* result and the SQLITE result code.
* -- ctx
* -- szSql
* -- cQueryValue = nummber of numeric query arguments-
* -- pqwQueryValues = array of 64-bit query arguments-
* -- cResultValues = max number of numeric query results.
* -- pqwResultValues = array to receive 64-bit query results.
* -- pcResultValues = optional to receive number of query results read.
* -- return = sqlite return code.
*/
_Success_(return == SQLITE_OK)
int InfoDB_SqlQueryN(_In_ POB_INFODB_CONTEXT ctx, _In_ LPSTR szSql, _In_ DWORD cQueryValues, _In_reads_(cQueryValues) PQWORD pqwQueryValues, _In_ DWORD cResultValues, _Out_writes_(cResultValues) PQWORD pqwResultValues, _Out_opt_ PDWORD pcResultValues)
{
    int rc = SQLITE_ERROR;
    DWORD i, iMax;
    sqlite3 *hSql = InfoDB_SqlReserve(ctx);
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
    InfoDB_SqlReserveReturn(ctx, hSql);
    if(pcResultValues) { *pcResultValues = 0; }
    return rc;
}



// ----------------------------------------------------------------------------
// GENERAL INTERNAL FUNCTIONALITY BELOW:
// ----------------------------------------------------------------------------

DWORD InfoDB_GetPdbId(_In_ POB_INFODB_CONTEXT ctx, _In_ QWORD vaModuleBase)
{
    PVMM_PROCESS pObSystemProcess = NULL;
    PE_CODEVIEW_INFO CodeViewInfo = { 0 };
    QWORD qwEndGUID;
    DWORD dwPdbId = 0;
    CHAR szAgeGUID[0x40] = { 0 };
    int rc;
    sqlite3_stmt *hStmt = NULL;
    sqlite3 *hSql = InfoDB_SqlReserve(ctx);
    if(!(pObSystemProcess = VmmProcessGet(4))) { goto fail; }
    if(!PE_GetCodeViewInfo(pObSystemProcess, vaModuleBase, NULL, &CodeViewInfo)) { goto fail; }
    qwEndGUID = *(PQWORD)(CodeViewInfo.CodeView.Guid + 8);
    _snprintf_s(szAgeGUID, sizeof(szAgeGUID), _TRUNCATE, "%08X%02X%02X%16llX%X",
        *(PDWORD)(CodeViewInfo.CodeView.Guid + 0),
        *(PWORD)(CodeViewInfo.CodeView.Guid + 4),
        *(PWORD)(CodeViewInfo.CodeView.Guid + 6),
        (QWORD)_byteswap_uint64(qwEndGUID),
        CodeViewInfo.CodeView.Age);
    rc = sqlite3_prepare_v2(hSql, "SELECT id FROM pdb WHERE guidage = ?", -1, &hStmt, 0);
    if(rc != SQLITE_OK) { goto fail; }
    sqlite3_bind_text(hStmt, 1, szAgeGUID, -1, NULL);
    rc = sqlite3_step(hStmt);
    if(rc != SQLITE_ROW) { goto fail; }
    dwPdbId = (DWORD)sqlite3_column_int(hStmt, 0);
fail:
    sqlite3_finalize(hStmt);
    InfoDB_SqlReserveReturn(ctx, hSql);
    Ob_DECREF(pObSystemProcess);
    return dwPdbId;
}

DWORD InfoDB_EnsureTcpIp(_In_ POB_INFODB_CONTEXT ctx)
{
    PVMMOB_MAP_MODULE pObModuleMap = NULL;
    PVMM_MAP_MODULEENTRY peModuleTcpip;
    if(!ctx->fPdbId_TcpIp_TryComplete) {
        EnterCriticalSection(&ctxVmm->LockMaster);
        if(!ctx->fPdbId_TcpIp_TryComplete && VmmMap_GetModuleEntryEx(NULL, 4, "tcpip.sys", &pObModuleMap, &peModuleTcpip)) {
            ctx->dwPdbId_TcpIp = InfoDB_GetPdbId(ctx, peModuleTcpip->vaBase);
            ctx->fPdbId_TcpIp_TryComplete = TRUE;
            Ob_DECREF_NULL(&pObModuleMap);
        }
        LeaveCriticalSection(&ctxVmm->LockMaster);
    }
    return ctx->dwPdbId_TcpIp;
}



// ----------------------------------------------------------------------------
// INFO QUERY FUNCTIONALITY BELOW:
// ----------------------------------------------------------------------------

/*
* Check if a certificate is well know against the database.
* -- qwThumbprintEndSHA1 = QWORD representation of the last 64 bits of the SHA-1 certificate thumbprint.
* -- return
*/
_Success_(return)
BOOL InfoDB_CertIsWellKnown(_In_ QWORD qwThumbprintEndSHA1)
{
    QWORD qwResult = 0;
    POB_INFODB_CONTEXT pObCtx = NULL;
    qwThumbprintEndSHA1 = qwThumbprintEndSHA1 & 0x7fffffffffffffff;
    if(!(pObCtx = ObContainer_GetOb(ctxVmm->pObCInfoDB)) || !pObCtx->dwPdbId_NT) { goto fail; }
    InfoDB_SqlQueryN(pObCtx, "SELECT count(*) FROM cert WHERE hash = ?", 1, &qwThumbprintEndSHA1, 1, &qwResult, NULL);
fail:
    Ob_DECREF(pObCtx);
    return (1 == qwResult);
}

/*
* Query the InfoDB for the offset of a symbol.
* Currently only szModule values of 'nt', 'ntoskrnl', 'tcpip' is supported.
* -- szModule
* -- szSymbolName
* -- pdwSymbolOffset
* -- return
*/
_Success_(return)
BOOL InfoDB_SymbolOffset(_In_ LPSTR szModule, _In_ LPSTR szSymbolName, _Out_ PDWORD pdwSymbolOffset)
{
    BOOL fResult = FALSE;
    POB_INFODB_CONTEXT pObCtx = NULL;
    QWORD qwHash, qwResult = 0, qwPdbId = 0;
    *pdwSymbolOffset = 0;
    if(!(pObCtx = ObContainer_GetOb(ctxVmm->pObCInfoDB))) { goto fail; }
    if(!strcmp(szModule, "nt") || !strcmp(szModule, "ntoskrnl")) {
        qwPdbId = pObCtx->dwPdbId_NT;
    } else if(!strcmp(szModule, "tcpip")) {
        qwPdbId = InfoDB_EnsureTcpIp(pObCtx);
    }
    if(!qwPdbId) { goto fail; }
    qwHash = CharUtil_Hash32A(szSymbolName, FALSE) + (qwPdbId << 32);
    if(SQLITE_OK == InfoDB_SqlQueryN(pObCtx, "SELECT data FROM symbol_offset WHERE hash = ?", 1, &qwHash, 1, &qwResult, NULL)) {
        *pdwSymbolOffset = (DWORD)qwResult;
        fResult = TRUE;
    }
fail:
    Ob_DECREF(pObCtx);
    return fResult;
}

/*
* Read memory at the symbol offset.
* -- szModule
* -- vaModuleBase
* -- szSymbolName
* -- pProcess
* -- pb
* -- cb
* -- return
*/
_Success_(return)
BOOL InfoDB_SymbolPBYTE(_In_ LPSTR szModule, _In_ QWORD vaModuleBase, _In_ LPSTR szSymbolName, _In_ PVMM_PROCESS pProcess, _Out_writes_(cb) PBYTE pb, _In_ DWORD cb)
{
    DWORD dwSymbolOffset = 0;
    if(!InfoDB_SymbolOffset(szModule, szSymbolName, &dwSymbolOffset)) { return FALSE; }
    return VmmRead(pProcess, vaModuleBase + dwSymbolOffset, pb, cb);
}

/*
* Read memory pointed to at the symbol offset.
* -- szModule
* -- vaModuleBase
* -- szSymbolName
* -- pProcess
* -- pqw
* -- return
*/
_Success_(return)
BOOL InfoDB_GetSymbolQWORD(_In_ LPSTR szModule, _In_ QWORD vaModuleBase, _In_ LPSTR szSymbolName, _In_ PVMM_PROCESS pProcess, _Out_ PQWORD pqw)
{
    return InfoDB_SymbolPBYTE(szModule, vaModuleBase, szSymbolName, pProcess, (PBYTE)pqw, sizeof(QWORD));
}

/*
* Read memory pointed to at the symbol offset.
* -- szModule
* -- vaModuleBase
* -- szSymbolName
* -- pProcess
* -- pdw
* -- return
*/
_Success_(return)
BOOL InfoDB_SymbolDWORD(_In_ LPSTR szModule, _In_ QWORD vaModuleBase, _In_ LPSTR szSymbolName, _In_ PVMM_PROCESS pProcess, _Out_ PDWORD pdw)
{
    return InfoDB_SymbolPBYTE(szModule, vaModuleBase, szSymbolName, pProcess, (PBYTE)pdw, sizeof(DWORD));
}

/*
* Read memory pointed to at the symbol offset.
* -- szModule
* -- vaModuleBase
* -- szSymbolName
* -- pProcess
* -- pv = PDWORD on 32-bit and PQWORD on 64-bit _operating_system_ architecture.
* -- return
*/
_Success_(return)
BOOL InfoDB_SymbolPTR(_In_ LPSTR szModule, _In_ QWORD vaModuleBase, _In_ LPSTR szSymbolName, _In_ PVMM_PROCESS pProcess, _Out_ PVOID pv)
{
    return InfoDB_SymbolPBYTE(szModule, vaModuleBase, szSymbolName, pProcess, (PBYTE)pv, (ctxVmm->f32 ? sizeof(DWORD) : sizeof(QWORD)));
}

/*
* Query the InfoDB for the size of a type. Currently only szModule values
* of 'nt' or 'ntoskrnl' is supported.
* -- szModule
* -- szTypeName
* -- pdwTypeSize
* -- return
*/
_Success_(return)
BOOL InfoDB_TypeSize(_In_ LPSTR szModule, _In_ LPSTR szTypeName, _Out_ PDWORD pdwTypeSize)
{
    BOOL fResult = FALSE;
    POB_INFODB_CONTEXT pObCtx = NULL;
    QWORD qwHash, qwResult = 0;
    if(strcmp(szModule, "nt") && strcmp(szModule, "ntoskrnl")) { goto fail; }
    if(!(pObCtx = ObContainer_GetOb(ctxVmm->pObCInfoDB)) || !pObCtx->dwPdbId_NT) { goto fail; }
    qwHash = CharUtil_Hash32A(szTypeName, FALSE) + ((QWORD)pObCtx->dwPdbId_NT << 32);
    if(SQLITE_OK == InfoDB_SqlQueryN(pObCtx, "SELECT data FROM type_size WHERE hash = ?", 1, &qwHash, 1, &qwResult, NULL)) {
        *pdwTypeSize = (DWORD)qwResult;
        fResult = TRUE;
    }
fail:
    Ob_DECREF(pObCtx);
    return fResult;
}

/*
* Query the InfoDB for the offset of a child inside a type - often inside a struct.
* Currently only szModule values of 'nt' or 'ntoskrnl' is supported.
* -- szModule
* -- szTypeName
* -- uszTypeChildName
* -- pdwTypeOffset = offset relative to type base.
* -- return
*/
_Success_(return)
BOOL InfoDB_TypeChildOffset(_In_ LPSTR szModule, _In_ LPSTR szTypeName, _In_ LPSTR uszTypeChildName, _Out_ PDWORD pdwTypeOffset)
{
    BOOL fResult = FALSE;
    POB_INFODB_CONTEXT pObCtx = NULL;
    QWORD qwHash, qwHash1, qwHash2, qwResult = 0;
    if(strcmp(szModule, "nt") && strcmp(szModule, "ntoskrnl")) { goto fail; }
    if(!(pObCtx = ObContainer_GetOb(ctxVmm->pObCInfoDB)) || !pObCtx->dwPdbId_NT) { goto fail; }
    qwHash1 = CharUtil_Hash32A(szTypeName, FALSE);
    qwHash2 = CharUtil_Hash32U(uszTypeChildName, FALSE);
    qwHash = ((qwHash2 << 32) + qwHash1 + ((QWORD)pObCtx->dwPdbId_NT << 32)) & 0x7fffffffffffffff;
    if(SQLITE_OK == InfoDB_SqlQueryN(pObCtx, "SELECT data FROM type_child WHERE hash = ?", 1, &qwHash, 1, &qwResult, NULL)) {
        *pdwTypeOffset = (DWORD)qwResult;
        fResult = TRUE;
    }

fail:
    Ob_DECREF(pObCtx);
    return fResult;
}

/*
* Return whether the InfoDB symbols are ok or not.
* -- pfNtos
* -- pfTcpIp
*/
VOID InfoDB_IsValidSymbols(_Out_opt_ PBOOL pfNtos, _Out_opt_ PBOOL pfTcpIp)
{
    BOOL fNtos = FALSE, fTcpIp = FALSE;
    POB_INFODB_CONTEXT pObCtx = NULL;
    if((pObCtx = ObContainer_GetOb(ctxVmm->pObCInfoDB))) {
        fNtos = pObCtx->dwPdbId_NT ? TRUE : FALSE;
        fTcpIp = pObCtx->dwPdbId_TcpIp ? TRUE : FALSE;
    }
    if(pfNtos) { *pfNtos = fNtos; }
    if(pfTcpIp) { *pfTcpIp = fTcpIp; }
    Ob_DECREF(pObCtx);
}

/*
* Return if the InfoDB have been successfully initialized.
* Will return fail on no-init or failure to init (missing info.db file).
* -- return;
*/
BOOL InfoDB_IsInitialized()
{
    return ObContainer_Exists(ctxVmm->pObCInfoDB);
}

/*
* Object cleanup callback for the InfoDB context.
*/
VOID InfoDB_Context_CleanupCB(POB_INFODB_CONTEXT pOb)
{
    DWORD i;
    for(i = 0; i < INFODB_SQL_POOL_CONNECTION_NUM; i++) {
        if(pOb->hEvent[i]) {
            WaitForSingleObject(pOb->hEvent[i], INFINITE);
            CloseHandle(pOb->hEvent[i]);
            pOb->hEvent[i] = NULL;
        }
        if(pOb->hSql[i]) { sqlite3_close(pOb->hSql[i]); }
    }
}

VOID InfoDB_Initialize_DoWork()
{
    DWORD i;
    POB_INFODB_CONTEXT pObCtx = NULL;
    CHAR szDbPathFile[MAX_PATH] = { 0 };
    // 1: INIT
    if(!(pObCtx = Ob_Alloc(OB_TAG_INFODB_CTX, LMEM_ZEROINIT, sizeof(OB_INFODB_CONTEXT), (OB_CLEANUP_CB)InfoDB_Context_CleanupCB, NULL))) { goto fail; }
    // 2: SQLITE INIT:
    Util_GetPathLib(szDbPathFile);
    strncat_s(szDbPathFile, sizeof(szDbPathFile), "info.db", _TRUNCATE);
    if(SQLITE_CONFIG_MULTITHREAD != sqlite3_threadsafe()) {
        vmmprintf_fn("CRITICAL: WRONG SQLITE THREADING MODE - TERMINATING!\n");
        ExitProcess(0);
    }
    for(i = 0; i < INFODB_SQL_POOL_CONNECTION_NUM; i++) {
        if(!(pObCtx->hEvent[i] = CreateEvent(NULL, FALSE, TRUE, NULL))) { goto fail; }
        if(SQLITE_OK != sqlite3_open_v2(szDbPathFile, &pObCtx->hSql[i], SQLITE_OPEN_URI | SQLITE_OPEN_READONLY | SQLITE_OPEN_SHAREDCACHE | SQLITE_OPEN_NOMUTEX, NULL)) { goto fail; }
    }
    // 3: QUERY CURRENT 'NTOSKRNL.EXE' IMAGE
    pObCtx->dwPdbId_NT = InfoDB_GetPdbId(pObCtx, ctxVmm->kernel.vaBase);
    ObContainer_SetOb(ctxVmm->pObCInfoDB, pObCtx);
fail:
    Ob_DECREF(pObCtx);
}

/*
* Initialize the InfoDB (if possible):
*/
VOID InfoDB_Initialize()
{
    if(ObContainer_Exists(ctxVmm->pObCInfoDB)) { return; }
    EnterCriticalSection(&ctxVmm->LockMaster);
    if(!ObContainer_Exists(ctxVmm->pObCInfoDB)) {
        InfoDB_Initialize_DoWork();
    }
    LeaveCriticalSection(&ctxVmm->LockMaster);
}
