// infodb.c : implementation of the information read-only sqlite database.
//
// (c) Ulf Frisk, 2021-2023
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
    HANDLE hEventIngestPhys[INFODB_SQL_POOL_CONNECTION_NUM];
    sqlite3 *hSql[INFODB_SQL_POOL_CONNECTION_NUM];
} OB_INFODB_CONTEXT, *POB_INFODB_CONTEXT;


// ----------------------------------------------------------------------------
// SQLITE GENERAL FUNCTIONALITY:
// ----------------------------------------------------------------------------

/*
* Retrieve an SQLITE database handle. The retrieved handle must be
* returned with Fc_SqlReserveReturn(H, ).
* -- H
* -- ctx
* -- return = an SQLITE handle, or NULL on error.
*/
_Success_(return != NULL)
sqlite3 *InfoDB_SqlReserve(_In_ VMM_HANDLE H, _In_ POB_INFODB_CONTEXT ctx)
{
    DWORD iWaitNum = 0;
    iWaitNum = WaitForMultipleObjects(INFODB_SQL_POOL_CONNECTION_NUM, ctx->hEventIngestPhys, FALSE, INFINITE) - WAIT_OBJECT_0;
    if(iWaitNum >= INFODB_SQL_POOL_CONNECTION_NUM) {
        VmmLog(H, MID_INFODB, LOGLEVEL_CRITICAL, "DATABASE ERROR: WaitForMultipleObjects ERROR: 0x%08x", (DWORD)(iWaitNum + WAIT_OBJECT_0));
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
sqlite3 *InfoDB_SqlReserveReturn(_In_opt_ POB_INFODB_CONTEXT ctx, _In_opt_ sqlite3 *hSql)
{
    DWORD i;
    if(!ctx || !hSql) { return NULL; }
    for(i = 0; i < INFODB_SQL_POOL_CONNECTION_NUM; i++) {
        if(ctx->hSql[i] == hSql) {
            SetEvent(ctx->hEventIngestPhys[i]);
            break;
        }
    }
    return NULL;
}

/*
* Execute a single SQLITE database SQL query and return the SQLITE result code.
* -- H
* -- ctx
* -- szSql
* -- return = sqlite return code.
*/
_Success_(return == SQLITE_OK)
int InfoDB_SqlExec(_In_ VMM_HANDLE H, _In_ POB_INFODB_CONTEXT ctx, _In_ LPSTR szSql)
{
    int rc = SQLITE_ERROR;
    sqlite3 *hSql = InfoDB_SqlReserve(H, ctx);
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
* -- H
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
int InfoDB_SqlQueryN(_In_ VMM_HANDLE H, _In_ POB_INFODB_CONTEXT ctx, _In_ LPSTR szSql, _In_ DWORD cQueryValues, _In_reads_(cQueryValues) PQWORD pqwQueryValues, _In_ DWORD cResultValues, _Out_writes_(cResultValues) PQWORD pqwResultValues, _Out_opt_ PDWORD pcResultValues)
{
    int rc = SQLITE_ERROR;
    DWORD i, iMax;
    sqlite3 *hSql = InfoDB_SqlReserve(H, ctx);
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

DWORD InfoDB_GetPdbId(_In_ VMM_HANDLE H, _In_ POB_INFODB_CONTEXT ctx, _In_ QWORD vaModuleBase)
{
    PVMM_PROCESS pObSystemProcess = NULL;
    PE_CODEVIEW_INFO CodeViewInfo = { 0 };
    QWORD qwEndGUID;
    DWORD dwPdbId = 0;
    CHAR szAgeGUID[0x40] = { 0 };
    int rc;
    sqlite3_stmt *hStmt = NULL;
    sqlite3 *hSql = InfoDB_SqlReserve(H, ctx);
    if(!(pObSystemProcess = VmmProcessGet(H, 4))) { goto fail; }
    if(!PE_GetCodeViewInfo(H, pObSystemProcess, vaModuleBase, NULL, &CodeViewInfo)) { goto fail; }
    qwEndGUID = *(PQWORD)(CodeViewInfo.CodeView.Guid + 8);
    _snprintf_s(szAgeGUID, sizeof(szAgeGUID), _TRUNCATE, "%08X%04X%04X%016llX%X",
        *(PDWORD)(CodeViewInfo.CodeView.Guid + 0),
        *(PWORD)(CodeViewInfo.CodeView.Guid + 4),
        *(PWORD)(CodeViewInfo.CodeView.Guid + 6),
        (QWORD)_byteswap_uint64(qwEndGUID),
        CodeViewInfo.CodeView.Age);
    VmmLog(H, MID_INFODB, LOGLEVEL_TRACE, "AGEGUID=%s va=0x%llx", szAgeGUID, vaModuleBase);
    rc = sqlite3_prepare_v2(hSql, "SELECT id FROM pdb WHERE guidage = ?", -1, &hStmt, 0);
    if(rc != SQLITE_OK) { goto fail; }
    sqlite3_bind_text(hStmt, 1, szAgeGUID, -1, NULL);
    rc = sqlite3_step(hStmt);
    if(rc != SQLITE_ROW) { goto fail; }
    dwPdbId = (DWORD)sqlite3_column_int(hStmt, 0);
fail:
    VmmLog(H, MID_INFODB, LOGLEVEL_VERBOSE, "INIT: %s: va=0x%llx", (dwPdbId ? "SUCCESS" : "FAIL"), vaModuleBase);
    sqlite3_finalize(hStmt);
    InfoDB_SqlReserveReturn(ctx, hSql);
    Ob_DECREF(pObSystemProcess);
    return dwPdbId;
}

DWORD InfoDB_EnsureTcpIp(_In_ VMM_HANDLE H, _In_ POB_INFODB_CONTEXT ctx)
{
    PVMMOB_MAP_MODULE pObModuleMap = NULL;
    PVMM_MAP_MODULEENTRY peModuleTcpip;
    if(!ctx->fPdbId_TcpIp_TryComplete) {
        EnterCriticalSection(&H->vmm.LockMaster);
        if(!ctx->fPdbId_TcpIp_TryComplete && VmmMap_GetModuleEntryEx(H, NULL, 4, "tcpip.sys", 0, &pObModuleMap, &peModuleTcpip)) {
            ctx->dwPdbId_TcpIp = InfoDB_GetPdbId(H, ctx, peModuleTcpip->vaBase);
            ctx->fPdbId_TcpIp_TryComplete = TRUE;
            Ob_DECREF_NULL(&pObModuleMap);
        }
        LeaveCriticalSection(&H->vmm.LockMaster);
    }
    return ctx->dwPdbId_TcpIp;
}



// ----------------------------------------------------------------------------
// INFO QUERY FUNCTIONALITY BELOW:
// ----------------------------------------------------------------------------

/*
* Check if a certificate is well know against the database.
* -- H
* -- qwThumbprintEndSHA1 = QWORD representation of the last 64 bits of the SHA-1 certificate thumbprint.
* -- return
*/
_Success_(return)
BOOL InfoDB_CertIsWellKnown(_In_ VMM_HANDLE H, _In_ QWORD qwThumbprintEndSHA1)
{
    QWORD qwResult = 0;
    POB_INFODB_CONTEXT pObCtx = NULL;
    qwThumbprintEndSHA1 = qwThumbprintEndSHA1 & 0x7fffffffffffffff;
    if(!(pObCtx = ObContainer_GetOb(H->vmm.pObCInfoDB)) || !pObCtx->dwPdbId_NT) { goto fail; }
    InfoDB_SqlQueryN(H, pObCtx, "SELECT count(*) FROM cert WHERE hash = ?", 1, &qwThumbprintEndSHA1, 1, &qwResult, NULL);
fail:
    Ob_DECREF(pObCtx);
    return (1 == qwResult);
}

/*
* Query the InfoDB for the offset of a symbol.
* Currently only szModule values of 'nt', 'ntoskrnl', 'tcpip' is supported.
* -- H
* -- szModule
* -- szSymbolName
* -- pdwSymbolOffset
* -- return
*/
_Success_(return)
BOOL InfoDB_SymbolOffset(_In_ VMM_HANDLE H, _In_ LPSTR szModule, _In_ LPSTR szSymbolName, _Out_ PDWORD pdwSymbolOffset)
{
    BOOL fResult = FALSE;
    POB_INFODB_CONTEXT pObCtx = NULL;
    QWORD qwHash, qwResult = 0, qwPdbId = 0;
    *pdwSymbolOffset = 0;
    if(!(pObCtx = ObContainer_GetOb(H->vmm.pObCInfoDB))) { goto fail; }
    if(!strcmp(szModule, "nt") || !strcmp(szModule, "ntoskrnl")) {
        qwPdbId = pObCtx->dwPdbId_NT;
    } else if(!strcmp(szModule, "tcpip")) {
        qwPdbId = InfoDB_EnsureTcpIp(H, pObCtx);
    }
    if(!qwPdbId) { goto fail; }
    qwHash = CharUtil_Hash32A(szSymbolName, FALSE) + (qwPdbId << 32);
    if(SQLITE_OK == InfoDB_SqlQueryN(H, pObCtx, "SELECT data FROM symbol_offset WHERE hash = ?", 1, &qwHash, 1, &qwResult, NULL)) {
        *pdwSymbolOffset = (DWORD)qwResult;
        fResult = TRUE;
    }
fail:
    Ob_DECREF(pObCtx);
    if(!fResult) {
        VmmLog(H, MID_INFODB, LOGLEVEL_TRACE, "Missing SymbolOffset: %s", szSymbolName);
    }
    return fResult;
}

/*
* Read memory at the symbol offset.
* -- H
* -- szModule
* -- vaModuleBase
* -- szSymbolName
* -- pProcess
* -- pb
* -- cb
* -- return
*/
_Success_(return)
BOOL InfoDB_SymbolPBYTE(_In_ VMM_HANDLE H, _In_ LPSTR szModule, _In_ QWORD vaModuleBase, _In_ LPSTR szSymbolName, _In_ PVMM_PROCESS pProcess, _Out_writes_(cb) PBYTE pb, _In_ DWORD cb)
{
    DWORD dwSymbolOffset = 0;
    if(!InfoDB_SymbolOffset(H, szModule, szSymbolName, &dwSymbolOffset)) { return FALSE; }
    return VmmRead(H, pProcess, vaModuleBase + dwSymbolOffset, pb, cb);
}

/*
* Read memory pointed to at the symbol offset.
* -- H
* -- szModule
* -- vaModuleBase
* -- szSymbolName
* -- pProcess
* -- pqw
* -- return
*/
_Success_(return)
BOOL InfoDB_GetSymbolQWORD(_In_ VMM_HANDLE H, _In_ LPSTR szModule, _In_ QWORD vaModuleBase, _In_ LPSTR szSymbolName, _In_ PVMM_PROCESS pProcess, _Out_ PQWORD pqw)
{
    return InfoDB_SymbolPBYTE(H, szModule, vaModuleBase, szSymbolName, pProcess, (PBYTE)pqw, sizeof(QWORD));
}

/*
* Read memory pointed to at the symbol offset.
* -- H
* -- szModule
* -- vaModuleBase
* -- szSymbolName
* -- pProcess
* -- pdw
* -- return
*/
_Success_(return)
BOOL InfoDB_SymbolDWORD(_In_ VMM_HANDLE H, _In_ LPSTR szModule, _In_ QWORD vaModuleBase, _In_ LPSTR szSymbolName, _In_ PVMM_PROCESS pProcess, _Out_ PDWORD pdw)
{
    return InfoDB_SymbolPBYTE(H, szModule, vaModuleBase, szSymbolName, pProcess, (PBYTE)pdw, sizeof(DWORD));
}

/*
* Read memory pointed to at the symbol offset.
* -- H
* -- szModule
* -- vaModuleBase
* -- szSymbolName
* -- pProcess
* -- pv = PDWORD on 32-bit and PQWORD on 64-bit _operating_system_ architecture.
* -- return
*/
_Success_(return)
BOOL InfoDB_SymbolPTR(_In_ VMM_HANDLE H, _In_ LPSTR szModule, _In_ QWORD vaModuleBase, _In_ LPSTR szSymbolName, _In_ PVMM_PROCESS pProcess, _Out_ PVOID pv)
{
    return InfoDB_SymbolPBYTE(H, szModule, vaModuleBase, szSymbolName, pProcess, (PBYTE)pv, (H->vmm.f32 ? sizeof(DWORD) : sizeof(QWORD)));
}

/*
* Query the InfoDB for a static size populated in the static_type_size table.
* -- H
* -- szModule
* -- szTypeName
* -- pdwTypeSize
* -- return
*/
_Success_(return)
BOOL InfoDB_TypeSize_Static(_In_ VMM_HANDLE H, _In_ LPSTR szModule, _In_ LPSTR szTypeName, _Out_ PDWORD pdwTypeSize)
{
    int r, rc = SQLITE_ERROR;
    sqlite3_stmt *hStmt = NULL;
    sqlite3 *hSql = NULL;
    POB_INFODB_CONTEXT pObCtx = NULL;
    DWORD dwArch = H->vmm.f32 ? 32 : 64;
    *pdwTypeSize = 0;
    if(!(pObCtx = ObContainer_GetOb(H->vmm.pObCInfoDB))) { goto fail; }
    hSql = InfoDB_SqlReserve(H, pObCtx);
    if(!H->vmm.f32 && (szModule[0] == 'w')) {
        // wow64 modules start with 'w' (wntdll == 32-bit ntdll on a 64-bit system) -> use the 32-bit offset instead.
        szModule = szModule + 1;
        dwArch = 32;
    }
    if(hSql) {
        rc = sqlite3_prepare_v2(hSql, "SELECT value FROM static_type_size WHERE module = ? AND type = ? AND arch = ? AND build <= ? ORDER BY build DESC LIMIT 1", -1, &hStmt, 0);
        if(rc != SQLITE_OK) { goto fail; }
        sqlite3_bind_text(hStmt, 1, szModule, -1, NULL);
        sqlite3_bind_text(hStmt, 2, szTypeName, -1, NULL);
        sqlite3_bind_int(hStmt, 3, dwArch);
        sqlite3_bind_int(hStmt, 4, H->vmm.kernel.dwVersionBuild);
        rc = sqlite3_step(hStmt);
        if(rc != SQLITE_ROW) { goto fail; }
        r = sqlite3_column_int(hStmt, 0);
        if(r < 0) { rc = SQLITE_ERROR; goto fail; }
        *pdwTypeSize = r;
        rc = SQLITE_OK;
    }
fail:
    sqlite3_finalize(hStmt);
    InfoDB_SqlReserveReturn(pObCtx, hSql);
    Ob_DECREF(pObCtx);
    if(rc == SQLITE_OK) {
        return TRUE;
    }
    VmmLog(H, MID_INFODB, LOGLEVEL_TRACE, "Missing TypeSize(Static): %s!%s", szModule, szTypeName);
    return FALSE;
}

/*
* Query the InfoDB for the size of a type.
* Support for 'nt', 'tcpip'.
* -- H
* -- szModule
* -- szTypeName
* -- pdwTypeSize
* -- return
*/
_Success_(return)
BOOL InfoDB_TypeSize_Dynamic(_In_ VMM_HANDLE H, _In_ LPSTR szModule, _In_ LPSTR szTypeName, _Out_ PDWORD pdwTypeSize)
{
    DWORD dwPdbId = 0;
    QWORD qwHash, qwResult = 0;
    POB_INFODB_CONTEXT pObCtx = NULL;
    if(!(pObCtx = ObContainer_GetOb(H->vmm.pObCInfoDB))) { goto fail; }
    if(!strcmp(szModule, "nt") || !strcmp(szModule, "ntoskrnl")) {
        dwPdbId = pObCtx->dwPdbId_NT;
    } else if(!strcmp(szModule, "tcpip")) {
        dwPdbId = InfoDB_EnsureTcpIp(H, pObCtx);
    }
    if(!dwPdbId) { goto fail; }
    qwHash = CharUtil_Hash32A(szTypeName, FALSE) + ((QWORD)dwPdbId << 32);
    if(SQLITE_OK == InfoDB_SqlQueryN(H, pObCtx, "SELECT data FROM type_size WHERE hash = ?", 1, &qwHash, 1, &qwResult, NULL)) {
        *pdwTypeSize = (DWORD)qwResult;
        Ob_DECREF(pObCtx);
        return TRUE;
    }
fail:
    VmmLog(H, MID_INFODB, LOGLEVEL_TRACE, "Missing TypeSize(Dynamic): %s!%s", szModule, szTypeName);
    Ob_DECREF(pObCtx);
    return FALSE;
}

/*
* Query the InfoDB for the static offset of a child inside a type - often inside a struct.
* Support for nt/ntoskrnl/tcpip.
* -- H
* -- szModule
* -- szTypeName
* -- uszTypeChildName
* -- pdwTypeOffset = offset relative to type base.
* -- return
*/
_Success_(return)
BOOL InfoDB_TypeChildOffset_Static(_In_ VMM_HANDLE H, _In_ LPSTR szModule, _In_ LPSTR szTypeName, _In_ LPSTR uszTypeChildName, _Out_ PDWORD pdwTypeOffset)
{
    int r, rc = SQLITE_ERROR;
    sqlite3_stmt *hStmt = NULL;
    sqlite3 *hSql = NULL;
    POB_INFODB_CONTEXT pObCtx = NULL;
    DWORD dwArch = H->vmm.f32 ? 32 : 64;
    *pdwTypeOffset = 0;
    if(!(pObCtx = ObContainer_GetOb(H->vmm.pObCInfoDB))) { goto fail; }
    hSql = InfoDB_SqlReserve(H, pObCtx);
    if(!H->vmm.f32 && (szModule[0] == 'w')) {
        // wow64 modules start with 'w' (wntdll == 32-bit ntdll on a 64-bit system) -> use the 32-bit offset instead.
        szModule = szModule + 1;
        dwArch = 32;
    }
    if(hSql) {
        rc = sqlite3_prepare_v2(hSql, "SELECT value FROM static_type_child WHERE module = ? AND type = ? AND child = ? AND arch = ? AND build <= ? ORDER BY build DESC LIMIT 1", -1, &hStmt, 0);
        if(rc != SQLITE_OK) { goto fail; }
        rc = sqlite3_bind_text(hStmt, 1, szModule, -1, NULL);
        rc = sqlite3_bind_text(hStmt, 2, szTypeName, -1, NULL);
        rc = sqlite3_bind_text(hStmt, 3, uszTypeChildName, -1, NULL);
        rc = sqlite3_bind_int(hStmt, 4, dwArch);
        rc = sqlite3_bind_int(hStmt, 5, H->vmm.kernel.dwVersionBuild);
        rc = sqlite3_step(hStmt);
        if(rc != SQLITE_ROW) { goto fail; }
        r = sqlite3_column_int(hStmt, 0);
        if(r < 0) { rc = SQLITE_ERROR; goto fail; }
        *pdwTypeOffset = r;
        rc = SQLITE_OK;
    }
fail:
    sqlite3_finalize(hStmt);
    InfoDB_SqlReserveReturn(pObCtx, hSql);
    Ob_DECREF(pObCtx);
    if(rc == SQLITE_OK) {
        return TRUE;
    }
    VmmLog(H, MID_INFODB, LOGLEVEL_TRACE, "Missing TypeChildOffset(Static): %s.%s", szTypeName, uszTypeChildName);
    return FALSE;
}

/*
* Query the InfoDB for the offset of a child inside a type - often inside a struct.
* Support for nt/ntoskrnl/tcpip.
* -- H
* -- szModule
* -- szTypeName
* -- uszTypeChildName
* -- pdwTypeOffset = offset relative to type base.
* -- return
*/
_Success_(return)
BOOL InfoDB_TypeChildOffset_Dynamic(_In_ VMM_HANDLE H, _In_ LPSTR szModule, _In_ LPSTR szTypeName, _In_ LPSTR uszTypeChildName, _Out_ PDWORD pdwTypeOffset)
{
    DWORD dwPdbId = 0;
    POB_INFODB_CONTEXT pObCtx = NULL;
    QWORD qwHash, qwHash1, qwHash2, qwResult = 0;
    if(!(pObCtx = ObContainer_GetOb(H->vmm.pObCInfoDB))) { goto fail; }
    if(!strcmp(szModule, "nt") || !strcmp(szModule, "ntoskrnl")) {
        dwPdbId = pObCtx->dwPdbId_NT;
    } else if(!strcmp(szModule, "tcpip")) {
        dwPdbId = InfoDB_EnsureTcpIp(H, pObCtx);
    }
    if(!dwPdbId) { goto fail; }
    qwHash1 = CharUtil_Hash32A(szTypeName, FALSE);
    qwHash2 = CharUtil_Hash32U(uszTypeChildName, FALSE);
    qwHash = ((qwHash2 << 32) + qwHash1 + dwPdbId + ((QWORD)dwPdbId << 32)) & 0x7fffffffffffffff;
    if(SQLITE_OK == InfoDB_SqlQueryN(H, pObCtx, "SELECT data FROM type_child WHERE hash = ?", 1, &qwHash, 1, &qwResult, NULL)) {
        *pdwTypeOffset = (DWORD)qwResult;
        Ob_DECREF(pObCtx);
        return TRUE;
    }
fail:
    VmmLog(H, MID_INFODB, LOGLEVEL_TRACE, "Missing TypeChildOffset(Dynamic): %s.%s", szTypeName, uszTypeChildName);
    Ob_DECREF(pObCtx);
    return FALSE;
}

/*
* Return whether the InfoDB symbols are ok or not.
* -- H
* -- pfNtos
* -- pfTcpIp
*/
VOID InfoDB_IsValidSymbols(_In_ VMM_HANDLE H, _Out_opt_ PBOOL pfNtos, _Out_opt_ PBOOL pfTcpIp)
{
    BOOL fNtos = FALSE, fTcpIp = FALSE;
    POB_INFODB_CONTEXT pObCtx = NULL;
    if((pObCtx = ObContainer_GetOb(H->vmm.pObCInfoDB))) {
        fNtos = pObCtx->dwPdbId_NT ? TRUE : FALSE;
        fTcpIp = pObCtx->dwPdbId_TcpIp ? TRUE : FALSE;
    }
    if(pfNtos) { *pfNtos = fNtos; }
    if(pfTcpIp) { *pfTcpIp = fTcpIp; }
    Ob_DECREF(pObCtx);
}

/*
* Lookup well known SIDs from the database.
* This is preferred over system lookups due to english names.
* -- H
* -- szSID = a SID in string format (i.e. S-1-5-19)
* -- szName = buffer of length *pcbName to receive user name on success.
* -- pcbName
* -- szDomain = buffer of length *pcbDomain to receive domain name on success.
* -- pcbDomain
* -- return = the well known username on success, NULL on fail.
*/
_Success_(return)
BOOL InfoDB_SidToUser_Wellknown(
    _In_ VMM_HANDLE H,
    _In_ LPSTR szSID,
    _Out_writes_to_opt_(*pcbName, *pcbName + 1) LPSTR szName,
    _Inout_ LPDWORD pcbName,
    _Out_writes_to_opt_(*pcbDomain, *pcbDomain + 1) LPSTR szDomain,
    _Inout_ LPDWORD pcbDomain
) {
    BOOL fResult = FALSE;
    int rc = SQLITE_ERROR;
    POB_INFODB_CONTEXT pObCtx = NULL;
    sqlite3 *hSql = NULL;
    sqlite3_stmt *hStmt = NULL;
    DWORD cbDomain = 0, cbName = 0;
    LPSTR szRID, szQueryResult;
    // 1: check built-in well known domain RIDs
    if(CharUtil_StrStartsWith(szSID, "S-1-5-21-", FALSE)) {
        szRID = NULL;
        if(!szRID && CharUtil_StrEndsWith(szSID, "-500", FALSE)) { szRID = "DOMAIN_USER_RID_ADMIN"; }
        if(!szRID && CharUtil_StrEndsWith(szSID, "-501", FALSE)) { szRID = "DOMAIN_USER_RID_GUEST"; }
        if(!szRID && CharUtil_StrEndsWith(szSID, "-513", FALSE)) { szRID = "DOMAIN_GROUP_RID_USERS"; }
        if(!szRID && CharUtil_StrEndsWith(szSID, "-514", FALSE)) { szRID = "DOMAIN_GROUP_RID_GUESTS"; }
        if(!szRID && CharUtil_StrEndsWith(szSID, "-515", FALSE)) { szRID = "DOMAIN_GROUP_RID_COMPUTERS"; }
        if(!szRID && CharUtil_StrEndsWith(szSID, "-516", FALSE)) { szRID = "DOMAIN_GROUP_RID_CONTROLLERS"; }
        if(!szRID && CharUtil_StrEndsWith(szSID, "-517", FALSE)) { szRID = "DOMAIN_GROUP_RID_CERT_ADMINS"; }
        if(!szRID && CharUtil_StrEndsWith(szSID, "-518", FALSE)) { szRID = "DOMAIN_GROUP_RID_SCHEMA_ADMINS"; }
        if(!szRID && CharUtil_StrEndsWith(szSID, "-519", FALSE)) { szRID = "DOMAIN_GROUP_RID_ENTERPRISE_ADMINS"; }
        if(!szRID && CharUtil_StrEndsWith(szSID, "-520", FALSE)) { szRID = "DOMAIN_GROUP_RID_POLICY_ADMINS"; }
        if(szRID) {
            cbDomain = (DWORD)strlen("DOMAIN") + 1;
            cbName = (DWORD)strlen(szRID) + 1;
            if((szName && (*pcbName < cbName)) || (szDomain && (*pcbDomain < cbDomain))) {
                goto fail_size;
            }
            if(szDomain) {
                strncpy_s(szDomain, *pcbDomain, "DOMAIN", cbDomain);
            }
            if(szName) {
                szQueryResult = (LPSTR)sqlite3_column_text(hStmt, 1);
                strncpy_s(szName, *pcbName, szRID, cbName);
            }
            goto finish;
        }
    }
    // 2: lookup from well known SIDs in database
    if(!(pObCtx = ObContainer_GetOb(H->vmm.pObCInfoDB))) { goto fail; }
    if(!(hSql = InfoDB_SqlReserve(H, pObCtx))) { goto fail; }
    rc = sqlite3_prepare_v2(hSql, "SELECT domain, name FROM sid WHERE sid = ?", -1, &hStmt, 0);
    if(rc != SQLITE_OK) { goto fail; }
    rc = sqlite3_bind_text(hStmt, 1, szSID, -1, NULL);
    rc = sqlite3_step(hStmt);
    if(rc != SQLITE_ROW) { goto fail; }
    cbDomain = sqlite3_column_bytes(hStmt, 0) + 1;
    cbName = sqlite3_column_bytes(hStmt, 1) + 1;
    if((szName && (*pcbName < cbName)) || (szDomain && (*pcbDomain < cbDomain))) {
        goto fail_size;
    }
    if(szDomain) {
        szQueryResult = (LPSTR)sqlite3_column_text(hStmt, 0);
        strncpy_s(szDomain, *pcbDomain, szQueryResult, cbDomain);
    }
    if(szName) {
        szQueryResult = (LPSTR)sqlite3_column_text(hStmt, 1);
        strncpy_s(szName, *pcbName, szQueryResult, cbName);
    }
finish:
    fResult = TRUE;
fail_size:
    *pcbName = cbName;
    *pcbDomain = cbDomain;
fail:
    sqlite3_finalize(hStmt);
    InfoDB_SqlReserveReturn(pObCtx, hSql);
    Ob_DECREF(pObCtx);
    return fResult;
}

/*
* Return if the InfoDB have been successfully initialized.
* Will return fail on no-init or failure to init (missing info.db file).
* -- H
* -- return;
*/
BOOL InfoDB_IsInitialized(_In_ VMM_HANDLE H)
{
    return ObContainer_Exists(H->vmm.pObCInfoDB);
}

/*
* Object cleanup callback for the InfoDB context.
*/
VOID InfoDB_Context_CleanupCB(POB_INFODB_CONTEXT pOb)
{
    DWORD i;
    for(i = 0; i < INFODB_SQL_POOL_CONNECTION_NUM; i++) {
        if(pOb->hEventIngestPhys[i]) {
            WaitForSingleObject(pOb->hEventIngestPhys[i], INFINITE);
            CloseHandle(pOb->hEventIngestPhys[i]);
            pOb->hEventIngestPhys[i] = NULL;
        }
        if(pOb->hSql[i]) { sqlite3_close(pOb->hSql[i]); }
    }
}

VOID InfoDB_Initialize_DoWork(_In_ VMM_HANDLE H)
{
    DWORD i;
    POB_INFODB_CONTEXT pObCtx = NULL;
    CHAR szDbPathFile[MAX_PATH] = { 0 };
    // 1: INIT
    if(!(pObCtx = Ob_AllocEx(H, OB_TAG_INFODB_CTX, LMEM_ZEROINIT, sizeof(OB_INFODB_CONTEXT), (OB_CLEANUP_CB)InfoDB_Context_CleanupCB, NULL))) { goto fail; }
    // 2: SQLITE INIT:
    Util_GetPathLib(szDbPathFile);
    strncat_s(szDbPathFile, sizeof(szDbPathFile), "info.db", _TRUNCATE);
    if(SQLITE_CONFIG_MULTITHREAD != sqlite3_threadsafe()) {
        VmmLog(H, MID_INFODB, LOGLEVEL_CRITICAL, "WRONG SQLITE THREADING MODE - TERMINATING!");
        ExitProcess(0);
    }
    for(i = 0; i < INFODB_SQL_POOL_CONNECTION_NUM; i++) {
        if(!(pObCtx->hEventIngestPhys[i] = CreateEvent(NULL, FALSE, TRUE, NULL))) { goto fail; }
        if(SQLITE_OK != sqlite3_open_v2(szDbPathFile, &pObCtx->hSql[i], SQLITE_OPEN_URI | SQLITE_OPEN_READONLY | SQLITE_OPEN_SHAREDCACHE | SQLITE_OPEN_NOMUTEX, NULL)) { goto fail; }
    }
    // 3: QUERY CURRENT 'NTOSKRNL.EXE' IMAGE
    pObCtx->dwPdbId_NT = InfoDB_GetPdbId(H, pObCtx, H->vmm.kernel.vaBase);
    ObContainer_SetOb(H->vmm.pObCInfoDB, pObCtx);
fail:
    Ob_DECREF(pObCtx);
}

/*
* Initialize the InfoDB (if possible):
*/
VOID InfoDB_Initialize(_In_ VMM_HANDLE H)
{
    if(ObContainer_Exists(H->vmm.pObCInfoDB)) { return; }
    if(H->cfg.fDisableInfoDB) {
        VmmLog(H, MID_INFODB, LOGLEVEL_INFO, "Info database disabled by user");
        return;
    }
    EnterCriticalSection(&H->vmm.LockMaster);
    if(!ObContainer_Exists(H->vmm.pObCInfoDB)) {
        InfoDB_Initialize_DoWork(H);
    }
    LeaveCriticalSection(&H->vmm.LockMaster);
}
