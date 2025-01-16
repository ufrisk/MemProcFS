// m_fc_registry.c : registry forensic module.
//
// REQUIRE: FORENSIC SUB-SYSTEM INIT.
//
// NB! module generate forensic data only - no file system presence!
//
// (c) Ulf Frisk, 2020-2025
// Author: Ulf Frisk, pcileech@frizk.net
//

#include "modules.h"
#include "../version.h"
#include "../vmmwinreg.h"

static LPSTR FC_SQL_SCHEMA_REGISTRY =
    "DROP VIEW IF EXISTS v_registry; " \
    "DROP TABLE IF EXISTS registry; " \
    "CREATE TABLE registry ( id INTEGER PRIMARY KEY AUTOINCREMENT, id_str INTEGER, hive INTEGER, cell INTEGER, cell_parent INTEGER, time INTEGER ); " \
    "CREATE VIEW v_registry AS SELECT * FROM registry, str WHERE registry.id_str = str.id; ";

static LPCSTR MFCREGISTRY_TYPE_NAMES[] = {
    "REG_NONE",
    "REG_SZ",
    "REG_EXPAND_SZ",
    "REG_BINARY",
    "REG_DWORD",
    "REG_DWORD_BIG_ENDIAN",
    "REG_LINK",
    "REG_MULTI_SZ",
    "REG_RESOURCE_LIST",
    "REG_FULL_RESOURCE_DESCRIPTOR",
    "REG_RESOURCE_REQUIREMENTS_LIST",
    "REG_QWORD"
};

VOID MFcRegistry_JsonKeyCB(_In_ VMM_HANDLE H, _Inout_ PVMMWINREG_FORENSIC_CONTEXT ctx, _In_z_ LPCSTR uszPathName, _In_ QWORD ftLastWrite)
{
    PFC_CONTEXT ctxFc = H->fc;
    SIZE_T o = 0;
    CHAR szKeyLastWrite[21];
    // 1: create json 'base/prefix' to re-use with values:
    o += snprintf(ctx->szjBase, sizeof(ctx->szjBase) - o,
        "{\"class\":\"REG\",\"ver\":\"%i.%i\",\"sys\":\"%s\",\"key\":\"",
        VERSION_MAJOR, VERSION_MINOR,
        H->vmm.szSystemUniqueTag
    );
    CharUtil_UtoJ(uszPathName, -1, ctx->szjBase + o, (DWORD)(sizeof(ctx->szjBase) - o), NULL, NULL, CHARUTIL_FLAG_TRUNCATE_ONFAIL_NULLSTR | CHARUTIL_FLAG_STR_BUFONLY);
    // 2: write key json line
    Util_FileTime2JSON(ftLastWrite, szKeyLastWrite);
    snprintf(ctx->sz, sizeof(ctx->sz),
        "%s\",\"type\":\"key\",\"lastwrite\":\"%s\"}\n",
        ctx->szjBase,
        szKeyLastWrite
    );
    ObMemFile_AppendString(ctxFc->FileJSON.pReg, ctx->sz);
}

VOID MFcRegistry_JsonValueCB(_In_ VMM_HANDLE H, _Inout_ PVMMWINREG_FORENSIC_CONTEXT ctx)
{
    QWORD i;
    DWORD cch;
    LPSTR szj;
    CharUtil_UtoJ(ctx->value.info.uszName, -1, ctx->value.szjName, sizeof(ctx->value.szjName), NULL, NULL, CHARUTIL_FLAG_TRUNCATE_ONFAIL_NULLSTR | CHARUTIL_FLAG_STR_BUFONLY);
    if(ctx->value.info.dwType >= sizeof(MFCREGISTRY_TYPE_NAMES) / sizeof(LPCSTR)) { ctx->value.info.dwType = 0; }
    ctx->value.szjValue[0] = 0;
    switch(ctx->value.info.dwType) {
        case REG_NONE:
        case REG_BINARY:
        case REG_RESOURCE_LIST:
        case REG_FULL_RESOURCE_DESCRIPTOR:
        case REG_RESOURCE_REQUIREMENTS_LIST:
            cch = _countof(ctx->value.sz);
            Util_FillHexAscii(ctx->value.pb, min(0x100, ctx->value.cb), 0, ctx->value.sz, &cch);
            CharUtil_AtoJ(
                ctx->value.sz,
                ctx->value.cb,
                ctx->value.szjValue,
                sizeof(ctx->value.szjValue),
                &szj,
                NULL,
                CHARUTIL_FLAG_TRUNCATE_ONFAIL_NULLSTR);
            break;
        case REG_DWORD:
        case REG_DWORD_BIG_ENDIAN:
            snprintf(ctx->value.szjValue, 0x20, "%08x", *(PDWORD)ctx->value.pb);
            break;
        case REG_QWORD:
            snprintf(ctx->value.szjValue, 0x20, "%016llx", *(PQWORD)ctx->value.pb);
            break;
        case REG_MULTI_SZ:
            for(i = 0; (ctx->value.cb >= 6) && (i < ctx->value.cb - 4); i += 2) { // replace NULL WCHAR between strings with newline
                if(!*(LPWSTR)(ctx->value.pb + i)) {
                    *(LPWSTR)(ctx->value.pb + i) = '\n';
                }
            }
            // fall-through
        case REG_SZ:
        case REG_EXPAND_SZ:
            CharUtil_WtoJ(
                (LPWSTR)ctx->value.pb,
                (ctx->value.cb / 2),
                (PBYTE)ctx->value.szjValue,
                sizeof(ctx->value.szjValue),
                &szj,
                NULL,
                CHARUTIL_FLAG_TRUNCATE_ONFAIL_NULLSTR);
            break;
    }
    snprintf(ctx->sz, sizeof(ctx->sz),
        "%s\",\"type\":\"value\",\"value\":{\"name\":\"%s\",\"type\":\"%s\",\"size\":%i,\"data\":\"%s\"}}\n",
        ctx->szjBase,
        ctx->value.szjName,
        MFCREGISTRY_TYPE_NAMES[ctx->value.info.dwType],
        ctx->value.info.cbData,
        ctx->value.szjValue
    );
    ObMemFile_AppendString(H->fc->FileJSON.pReg, ctx->sz);
}

/*
* Callback for registry key information destined for forensic database.
*/
VOID MFcRegistry_KeyCB(_In_ VMM_HANDLE H, _In_ HANDLE hCallback1, _In_ HANDLE hCallback2, _In_ LPCSTR uszPathName, _In_ QWORD vaHive, _In_ DWORD dwCell, _In_ DWORD dwCellParent, _In_ QWORD ftLastWrite)
{
    FCSQL_INSERTSTRTABLE SqlStrInsert;
    sqlite3_stmt *hStmt = (sqlite3_stmt *)hCallback1;
    sqlite3_stmt *hStmtStr = (sqlite3_stmt *)hCallback2;
    // build and insert string data into 'str' table.
    if(!Fc_SqlInsertStr(H, hStmtStr, uszPathName, &SqlStrInsert)) { return; }
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
PVOID M_FcRegistry_FcInitialize(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_CONTEXT ctxP)
{
    POB_REGISTRY_HIVE pObHive = NULL;
    sqlite3 *hSql = NULL;
    sqlite3_stmt *hStmt = NULL, *hStmtStr = NULL;
    if(SQLITE_OK != Fc_SqlExec(H, FC_SQL_SCHEMA_REGISTRY)) { goto fail; }
    if(!(hSql = Fc_SqlReserve(H))) { goto fail; }
    if(SQLITE_OK != sqlite3_prepare_v2(hSql, "INSERT INTO registry (id_str, hive, cell, cell_parent, time) VALUES (?, ?, ?, ?, ?);", -1, &hStmt, NULL)) { goto fail; }
    if(SQLITE_OK != sqlite3_prepare_v2(hSql, szFC_SQL_STR_INSERT, -1, &hStmtStr, NULL)) { goto fail; }
    sqlite3_exec(hSql, "BEGIN TRANSACTION", NULL, NULL, NULL);
    while((pObHive = VmmWinReg_HiveGetNext(H, pObHive))) {
        VmmWinReg_ForensicGetAllKeysAndValues(H, pObHive, hStmt, hStmtStr, MFcRegistry_KeyCB, MFcRegistry_JsonKeyCB, MFcRegistry_JsonValueCB);
    }
    sqlite3_exec(hSql, "COMMIT TRANSACTION", NULL, NULL, NULL);
fail:
    sqlite3_finalize(hStmt);
    sqlite3_finalize(hStmtStr);
    Fc_SqlReserveReturn(H, hSql);
    return NULL;
}

/*
* Timeline data by executing a partial SQL query on pre-existing data.
* -- H
* -- ctxfc
* -- hTimeline
* -- pfnAddEntry
* -- pfnEntryAddBySql
*/
VOID M_FcRegistry_FcTimeline(
    _In_ VMM_HANDLE H,
    _In_opt_ PVOID ctxfc,
    _In_ HANDLE hTimeline,
    _In_ VOID(*pfnAddEntry)(_In_ VMM_HANDLE H, _In_ HANDLE hTimeline, _In_ QWORD ft, _In_ DWORD dwAction, _In_ DWORD dwPID, _In_ DWORD dwData32, _In_ QWORD qwData64, _In_ LPCSTR uszText),
    _In_ VOID(*pfnEntryAddBySql)(_In_ VMM_HANDLE H, _In_ HANDLE hTimeline, _In_ DWORD cEntrySql, _In_ LPCSTR *pszEntrySql)
) {
    LPCSTR pszSql[] = {
        "id_str, time, "STRINGIZE(FC_TIMELINE_ACTION_MODIFY)", 0, 0, 0 FROM registry WHERE time > 0;"
    };
    pfnEntryAddBySql(H, hTimeline, sizeof(pszSql) / sizeof(LPSTR), pszSql);
}

/*
* Plugin initialization / registration function called by the plugin manager.
* -- H
* -- pRI
*/
VOID M_FcRegistry_Initialize(_In_ VMM_HANDLE H, _Inout_ PVMMDLL_PLUGIN_REGINFO pRI)
{
    if((pRI->magic != VMMDLL_PLUGIN_REGINFO_MAGIC) || (pRI->wVersion != VMMDLL_PLUGIN_REGINFO_VERSION)) { return; }
    if((pRI->tpSystem != VMM_SYSTEM_WINDOWS_64) && (pRI->tpSystem != VMM_SYSTEM_WINDOWS_32)) { return; }
    strcpy_s(pRI->reg_info.uszPathName, 128, "\\forensic\\hidden\\registry");   // module name
    pRI->reg_info.fRootModule = TRUE;                                           // module shows in root directory
    pRI->reg_info.fRootModuleHidden = TRUE;                                     // module hidden by default
    pRI->reg_fnfc.pfnInitialize = M_FcRegistry_FcInitialize;                    // Forensic initialize function supported
    pRI->reg_fnfc.pfnTimeline = M_FcRegistry_FcTimeline;                        // Forensic timelining supported
    memcpy(pRI->reg_info.sTimelineNameShort, "REG", 4);
    strncpy_s(pRI->reg_info.uszTimelineFile, 32, "timeline_registry", _TRUNCATE);
    pRI->pfnPluginManager_Register(H, pRI);
}
