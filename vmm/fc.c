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
// (c) Ulf Frisk, 2020-2025
// Author: Ulf Frisk, pcileech@frizk.net
//

#include "fc.h"
#include "vmmdll.h"
#include "pdb.h"
#include "vmmwin.h"
#include "vmmwinobj.h"
#include "vmmwinreg.h"
#include "pluginmanager.h"
#include "ext/sqlite3.h"
#include "statistics.h"
#include "charutil.h"
#include "infodb.h"
#include "util.h"
#include "version.h"

#define FC_SCAN_VIRTMEM_WORKER_THREADS          (max(1, VMM_WORK_THREADPOOL_NUM_THREADS / 3))
#define FC_SCAN_VIRTMEM_MAX_CHUNK_SIZE          (0x02000000) // 32MB

static LPSTR FC_SQL_SCHEMA_STR =
    "DROP TABLE IF EXISTS str; " \
    "CREATE TABLE str ( id INTEGER PRIMARY KEY, cbu INT, cbj INT, cbv INT, sz TEXT ); ";



// ----------------------------------------------------------------------------
// SQLITE GENERAL FUNCTIONALITY:
// ----------------------------------------------------------------------------

/*
* Retrieve an SQLITE database handle. The retrieved handle must be
* returned with Fc_SqlReserveReturn(H, ).
* -- H
* -- return = an SQLITE handle, or NULL on error.
*/
_Success_(return != NULL)
sqlite3* Fc_SqlReserve(_In_ VMM_HANDLE H)
{
    DWORD iWaitNum = 0;
    if(H->fAbort) { return NULL; }
    if(H->fc->db.fSingleThread) {
        WaitForSingleObject(H->fc->db.hEventIngestPhys[0], INFINITE);
    } else {
        iWaitNum = WaitForMultipleObjects(FC_SQL_POOL_CONNECTION_NUM, H->fc->db.hEventIngestPhys, FALSE, INFINITE) - WAIT_OBJECT_0;
    }
    if(iWaitNum >= FC_SQL_POOL_CONNECTION_NUM) {
        VmmLog(H, MID_FORENSIC, LOGLEVEL_CRITICAL, "FATAL DATABASE ERROR: WaitForMultipleObjects ERROR: 0x%08x", (DWORD)(iWaitNum + WAIT_OBJECT_0));
        return NULL;
    }
    return H->fc->db.hSql[iWaitNum];
}

/*
* Return a SQLITE database handle previously retrieved with Fc_SqlReserve()
* so that other threads may use it.
* -- H
* -- hSql = the SQLITE database handle.
* -- return = always NULL.
*/
_Success_(return != NULL)
sqlite3* Fc_SqlReserveReturn(_In_ VMM_HANDLE H, _In_opt_ sqlite3 *hSql)
{
    DWORD i;
    if(!hSql) { return NULL; }
    for(i = 0; i < FC_SQL_POOL_CONNECTION_NUM; i++) {
        if(H->fc->db.hSql[i] == hSql) {
            SetEvent(H->fc->db.hEventIngestPhys[i]);
            break;
        }
    }
    return NULL;
}

/*
* Execute a single SQLITE database SQL query and return the SQLITE result code.
* -- H
* -- szSql
* -- return = sqlite return code.
*/
_Success_(return == SQLITE_OK)
int Fc_SqlExec(_In_ VMM_HANDLE H, _In_ LPCSTR szSql)
{
    int rc = SQLITE_ERROR;
    sqlite3 *hSql = Fc_SqlReserve(H);
    if(hSql) {
        rc = sqlite3_exec(hSql, szSql, NULL, NULL, NULL);
        Fc_SqlReserveReturn(H, hSql);
    }
    return rc;
}

/*
* Execute a single SQLITE database SQL query and return all results as numeric
* 64-bit results in an array that must have capacity to hold all values.
* result and the SQLITE result code.
* -- H
* -- szSql
* -- cQueryValue = nummber of numeric query arguments-
* -- pqwQueryValues = array of 64-bit query arguments-
* -- cResultValues = max number of numeric query results.
* -- pqwResultValues = array to receive 64-bit query results.
* -- pcResultValues = optional to receive number of query results read.
* -- return = sqlite return code.
*/
_Success_(return == SQLITE_OK)
int Fc_SqlQueryN(_In_ VMM_HANDLE H, _In_ LPCSTR szSql, _In_ DWORD cQueryValues, _In_reads_(cQueryValues) PQWORD pqwQueryValues, _In_ DWORD cResultValues, _Out_writes_(cResultValues) PQWORD pqwResultValues, _Out_opt_ PDWORD pcResultValues)
{
    int rc = SQLITE_ERROR;
    DWORD i, iMax;
    sqlite3 *hSql = Fc_SqlReserve(H);
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
    Fc_SqlReserveReturn(H, hSql);
    if(pcResultValues) { *pcResultValues = 0; }
    return rc;
}

_Success_(return)
BOOL Fc_SqlInsertStr(_In_ VMM_HANDLE H, _In_ sqlite3_stmt *hStmt, _In_ LPCSTR usz, _Out_ PFCSQL_INSERTSTRTABLE pThis)
{
    if(!CharUtil_UtoU(usz, -1, NULL, 0, NULL, &pThis->cbu, 0)) { return FALSE; }
    pThis->cbu--;               // don't count null terminator.
    CharUtil_UtoJ(usz, -1, NULL, 0, NULL, &pThis->cbj, 0);      // # of bytes to represent JSON string (incl. null-terminator)
    if(pThis->cbj) { pThis->cbj--; }
    CharUtil_UtoCSV(usz, -1, NULL, 0, NULL, &pThis->cbv, 0);    // # of bytes to represent CSV string (incl. null-terminator)
    if(pThis->cbv) { pThis->cbv--; }
    pThis->id = InterlockedIncrement64(&H->fc->db.qwIdStr);
    sqlite3_reset(hStmt);
    sqlite3_bind_int64(hStmt, 1, pThis->id);
    sqlite3_bind_int(hStmt, 2, pThis->cbu);
    sqlite3_bind_int(hStmt, 3, pThis->cbj);
    sqlite3_bind_int(hStmt, 4, pThis->cbv);
    sqlite3_bind_text(hStmt, 5, usz, -1, NULL);
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



//-----------------------------------------------------------------------------
// FC FILE FUNCTIONALITY BELOW:
//-----------------------------------------------------------------------------

VOID FcCsv_Reset(_In_ VMMDLL_CSV_HANDLE h)
{
    if(h) { h->o = 0; }
}

LPSTR FcCsv_FileTime(_In_ VMMDLL_CSV_HANDLE h, _In_ QWORD ft)
{
    DWORD o;
    if(h && (sizeof(h->pb) - h->o > 22)) {
        o = h->o;
        Util_FileTime2CSV(ft, h->pb + o);
        h->o += 22;
        return h->pb + o;
    }
    return "";
}

LPSTR FcCsv_String(_In_ VMMDLL_CSV_HANDLE h, _In_opt_ LPCSTR usz)
{
    DWORD o, cbv = 0;
    if(!usz) { usz = ""; }
    if(!CharUtil_UtoCSV(usz, -1, NULL, 0, NULL, &cbv, 0)) { return ""; }
    if(h && (sizeof(h->pb) - h->o > cbv)) {
        o = h->o;
        if(!CharUtil_UtoCSV(usz, -1, h->pb + o, sizeof(h->pb) - h->o, NULL, &cbv, CHARUTIL_FLAG_STR_BUFONLY)) { return ""; }
        h->o += cbv;
        return h->pb + o;
    }
    return "";
}

VOID FcFile_CleanupCB(_In_ PVOID pOb)
{
    Ob_DECREF(((PFCOB_FILE)pOb)->pmf);
}

/*
* Append text data to a memory-backed forensics file.
* All text should be UTF-8 encoded.
* -- H
* -- uszFileName
* -- uszFormat
* -- ..
* -- return = the number of bytes appended (excluding terminating null).
*/
_Success_(return != 0)
SIZE_T FcFileAppend(_In_ VMM_HANDLE H, _In_ LPCSTR uszFileName, _In_z_ _Printf_format_string_ LPCSTR uszFormat, ...)
{
    SIZE_T ret;
    va_list arglist;
    va_start(arglist, uszFormat);
    ret = FcFileAppendEx(H, uszFileName, uszFormat, arglist);
    va_end(arglist);
    return ret;
}

/*
* Append text data to a memory-backed forensics file.
* All text should be UTF-8 encoded.
* -- H
* -- uszFileName
* -- uszFormat
* -- arglist
* -- return = the number of bytes appended (excluding terminating null).
*/
_Success_(return != 0)
SIZE_T FcFileAppendEx(_In_ VMM_HANDLE H, _In_ LPCSTR uszFileName, _In_z_ _Printf_format_string_ LPCSTR uszFormat, _In_ va_list arglist)
{
    SIZE_T ret = 0;
    PFCOB_FILE pObFcFile = NULL;
    QWORD qwFileNameHash = CharUtil_Hash64U(uszFileName, TRUE);
    if(!H->fc || !H->fc->fInitStart || H->fc->fInitFinish) { goto fail; }
    if(!(pObFcFile = ObMap_GetByKey(H->fc->FileCSV.pm, qwFileNameHash))) {
        // add/allocate new file:
        if(!(pObFcFile = Ob_AllocEx(H, OB_TAG_FC_FILE, LMEM_ZEROINIT, sizeof(FCOB_FILE), FcFile_CleanupCB, NULL))) { goto fail; }
        if(!CharUtil_UtoU(uszFileName, -1, (PBYTE)pObFcFile->uszName, _countof(pObFcFile->uszName), NULL, NULL, CHARUTIL_FLAG_STR_BUFONLY)) { goto fail; }
        if(!(pObFcFile->pmf = ObMemFile_New(H, H->vmm.pObCacheMapObCompressedShared))) { goto fail; }
        if(!ObMap_Push(H->fc->FileCSV.pm, qwFileNameHash, pObFcFile)) { goto fail; }
    }
    ret = ObMemFile_AppendStringEx2(pObFcFile->pmf, uszFormat, arglist);
fail:
    Ob_DECREF(pObFcFile);
    return ret;
}



// ----------------------------------------------------------------------------
// GENERAL JSON DATA LOG BELOW:
// ----------------------------------------------------------------------------

/*
* Callback function to add a json log line to 'general.json'
* -- H
* -- pDataJSON
*/
VOID FcJson_Callback_EntryAdd(_In_ VMM_HANDLE H, _In_ PVMMDLL_FORENSIC_JSONDATA pDataJSON)
{
    LPSTR szj;
    DWORD i;
    SIZE_T o = 0;
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
    if(H->fAbort) { return; }
    if(pDataJSON->dwVersion != VMMDLL_FORENSIC_JSONDATA_VERSION) { return; }
    // general/base:
    {
        if(buf->dwHdrType != *(PDWORD)pDataJSON->szjType) {
            buf->dwHdrType = *(PDWORD)pDataJSON->szjType;
            buf->cchHdrType = snprintf(buf->szjHdrType, sizeof(buf->szjHdrType),
                "{\"class\":\"GEN\",\"ver\":\"%i.%i\",\"sys\":\"%s\",\"type\":\"%s\"",
                VERSION_MAJOR, VERSION_MINOR,
                H->vmm.szSystemUniqueTag,
                pDataJSON->szjType
            );
        }
        memcpy(buf->szln + o, buf->szjHdrType, buf->cchHdrType + 1ULL); o += buf->cchHdrType;
    }
    // pid & process:
    if(pDataJSON->dwPID) {
        if(buf->dwPID != pDataJSON->dwPID) {
            buf->dwPID = pDataJSON->dwPID;
            if((pObProcess = VmmProcessGetEx(H, NULL, pDataJSON->dwPID, VMM_FLAG_PROCESS_SHOW_TERMINATED))) {
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
        ObMemFile_AppendString(H->fc->FileJSON.pGen, buf->szln);
    }
}



// ----------------------------------------------------------------------------
// FINDEVIL FUNCTIONALITY BELOW:
// ----------------------------------------------------------------------------

#define FCEVIL_LINEHEADER       "   #    PID Process        Type            Address          Description\n" \
                                "-----------------------------------------------------------------------\n"
static LPSTR FCEVIL_CSV_HEADER = "PID,ProcessName,Type,Address,Description\n";

static LPSTR FCEVIL_YARA_NO_BUILTIN_RULES = 
    "BuiltIn FindEvil YARA rules are NOT enabled! FindEvil results may be degraded.\n" \
    "---                                                                           \n" \
    "Some YARA rules require acceptance of the Elastic License 2.0.                \n" \
    "https://www.elastic.co/licensing/elastic-license                              \n" \
    "The Elastic License 2.0 applies to some built-in FindEvil YARA rules.         \n" \
    "The Elastic License 2.0 does not apply to MemProcFS itself.                   \n" \
    "Accept with startup option: -license-accept-elastic-license-2.0               \n" \
    "License Acceptance Status: %s                                     \n" \
    "---                                                                           \n" \
    "If the license has been accepted ensure the required info.db database exists  \n" \
    "alongside the MemProcFS binary.                                               \n";

typedef struct tdFC_FINDEVIL_ENTRY {
    DWORD dwSeverity;
    DWORD dwPID;
    QWORD va;
    CHAR uszType[16];
    CHAR usz[];
} FC_FINDEVIL_ENTRY, *PFC_FINDEVIL_ENTRY;

/*
* FindEvil main processing function (processed in async thread).
* Takes care of generating the FindEvil data by calling forensic plugins.
* -- H
* -- qwNotUsed
*/
VOID FcEvilInitialize_ThreadProc(_In_ VMM_HANDLE H, _In_ QWORD qwNotUsed)
{
    if(H->fAbort) { return; }
    if(!(H->fc->FindEvil.pm = ObMap_New(H, OB_MAP_FLAGS_NOKEY | OB_MAP_FLAGS_OBJECT_LOCALFREE))) { return; }
    if(!(H->fc->FindEvil.pmf = ObMemFile_New(H, H->vmm.pObCacheMapObCompressedShared))) { return; }
    if(!(H->fc->FindEvil.pmfYara = ObMemFile_New(H, H->vmm.pObCacheMapObCompressedShared))) { return; }
    if(!(H->fc->FindEvil.pmfYaraRules = ObMemFile_New(H, H->vmm.pObCacheMapObCompressedShared))) { return; }
    if(!InfoDB_YaraRulesBuiltIn_Exists(H)) {
        ObMemFile_AppendStringEx(H->fc->FindEvil.pmfYara, FCEVIL_YARA_NO_BUILTIN_RULES, (H->cfg.fLicenseAcceptElasticV2 ? "ACCEPTED    " : "NOT ACCEPTED"));
    }
    PluginManager_FcFindEvil(H);
}

/*
* FindEvil compare / sort function.
* Sorts on Severity, PID, Address.
*/
int FcEvilFinalize_CmpSort(_In_ POB_MAP_ENTRY e1, _In_ POB_MAP_ENTRY e2)
{
    PFC_FINDEVIL_ENTRY pe1 = (PFC_FINDEVIL_ENTRY)e1->v;
    PFC_FINDEVIL_ENTRY pe2 = (PFC_FINDEVIL_ENTRY)e2->v;
    // 1: Severity
    if(pe1->dwSeverity < pe2->dwSeverity) { return 1; }
    if(pe1->dwSeverity > pe2->dwSeverity) { return -1; }
    // 2: PID
    if(pe1->dwPID < pe2->dwPID) { return -1; }
    if(pe1->dwPID > pe2->dwPID) { return 1; }
    // 3: Address
    if(pe1->va < pe2->va) { return -1; }
    if(pe1->va > pe2->va) { return 1; }
    // 4: Hash of Description
    return CharUtil_Hash32U(pe1->usz, FALSE) - CharUtil_Hash32U(pe2->usz, FALSE);
}

/*
* Finalize evil - i.e. sort it and generate output files.
* -- H
*/
VOID FcEvilFinalize(_In_ VMM_HANDLE H, _In_opt_ VMMDLL_CSV_HANDLE hCSV)
{
    DWORD i, cMap;
    CHAR uszTEXT[1024];
    PFC_FINDEVIL_ENTRY pe;
    PVMMDLL_FORENSIC_JSONDATA pdJSON = NULL;
    PVMM_PROCESS pObProcess = NULL;
    if(H->fAbort) { goto fail; }
    if(!hCSV || !H->fc->FindEvil.pm) { goto fail; }
    // TEXT init:
    ObMemFile_AppendString(H->fc->FindEvil.pmf, FCEVIL_LINEHEADER);
    // JSON init:
    if(!(pdJSON = LocalAlloc(LMEM_ZEROINIT, sizeof(VMMDLL_FORENSIC_JSONDATA)))) { goto fail; }
    pdJSON->dwVersion = VMMDLL_FORENSIC_JSONDATA_VERSION;
    pdJSON->szjType = "evil";
    // CSV init:
    FcFileAppend(H, "findevil.csv", FCEVIL_CSV_HEADER);
    // Sort & Populate:
    ObMap_SortEntryIndex(H->fc->FindEvil.pm, FcEvilFinalize_CmpSort);
    for(i = 0, cMap = ObMap_Size(H->fc->FindEvil.pm); i < cMap; i++) {
        if(H->fAbort) { goto fail; }
        pe = ObMap_GetByIndex(H->fc->FindEvil.pm, i);
        if(pe->dwPID) {
            pObProcess = VmmProcessGet(H, pe->dwPID);
        }
        // TEXT log:
        _snprintf_s(uszTEXT, _countof(uszTEXT), _TRUNCATE, "%04x%7i %-15s%-15s %016llx %s\n",
            i,
            pe->dwPID,
            pObProcess ? pObProcess->szName : "---",
            pe->uszType,
            pe->va,
            pe->usz
        );
        ObMemFile_AppendString(H->fc->FindEvil.pmf, uszTEXT);
        // JSON log:
        pdJSON->i = i;
        pdJSON->dwPID = pe->dwPID;
        pdJSON->va[0] = pe->va;
        pdJSON->usz[0] = pe->uszType;
        pdJSON->usz[1] = pe->usz;
        FcJson_Callback_EntryAdd(H, pdJSON);
        // CSV log:
        FcCsv_Reset(hCSV);
        FcFileAppend(H, "findevil.csv", "%i,%s,%s,0x%llx,%s\n",
            pe->dwPID,
            FcCsv_String(hCSV, pObProcess ? pObProcess->pObPersistent->uszNameLong : ""),
            FcCsv_String(hCSV, pe->uszType),
            pe->va,
            FcCsv_String(hCSV, pe->usz)
        );
        Ob_DECREF_NULL(&pObProcess);
    }
fail:
    Ob_DECREF_NULL(&H->fc->FindEvil.pm);
    LocalFree(pdJSON);
}

/*
* Add a "findevil" entry. Take great care not spamming this function by mistake.
* Ordering when adding evil does not matter.
* -- H
* -- tpEvil
* -- pProcess = associated process (if applicable).
* -- va = virtual address.
* -- uszFormat
* -- ...
*/
VOID FcEvilAdd(_In_ VMM_HANDLE H, _In_ VMMEVIL_TYPE tpEvil, _In_opt_ PVMM_PROCESS pProcess, _In_opt_ QWORD va, _In_z_ _Printf_format_string_ LPCSTR uszFormat, ...)
{
    va_list arglist;
    va_start(arglist, uszFormat);
    FcEvilAddEx(H, tpEvil.Name, tpEvil.Severity, pProcess, va, uszFormat, arglist);
    va_end(arglist);
}

/*
* Add a "findevil" entry. Take great care not spamming this function by mistake.
* -- H
* -- uszType = evil type. max 15 chars, uppercase, no spaces.
* -- dwSeverity = the more severe the higher up in the FindEvil listings.
* -- pProcess = associated process (if applicable).
* -- va = virtual address.
* -- uszFormat
* -- arglist
*/
VOID FcEvilAddEx(_In_ VMM_HANDLE H, _In_ LPSTR uszType, _In_ DWORD dwSeverity, _In_opt_ PVMM_PROCESS pProcess, _In_opt_ QWORD va, _In_z_ _Printf_format_string_ LPCSTR uszFormat, _In_ va_list arglist)
{
    int cchBuffer;
    SIZE_T cbBuffer;
    CHAR uszBuffer[0x1000];
    PFC_FINDEVIL_ENTRY pe;
    cchBuffer = _vsnprintf_s(uszBuffer, _countof(uszBuffer), _TRUNCATE, uszFormat, arglist);
    if(cchBuffer >= 0) {
        cbBuffer = (SIZE_T)cchBuffer + 1;
        if((pe = LocalAlloc(0, sizeof(FC_FINDEVIL_ENTRY) + cbBuffer))) {
            pe->dwPID = pProcess ? pProcess->dwPID : 0;
            pe->dwSeverity = dwSeverity;
            pe->va = va;
            strncpy_s(pe->uszType, _countof(pe->uszType), uszType, _TRUNCATE);
            memcpy(pe->usz, uszBuffer, cbBuffer);
            if(!ObMap_Push(H->fc->FindEvil.pm, 0, pe)) {
                LocalFree(pe);
            }
        }
    }
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
VOID FcTimeline_Callback_PluginEntryAdd(_In_ VMM_HANDLE H, _In_ HANDLE hTimeline, _In_ QWORD ft, _In_ DWORD dwAction, _In_ DWORD dwPID, _In_ DWORD dwData32, _In_ QWORD qwData64, _In_ LPCSTR uszText)
{
    PFCTIMELINE_PLUGIN_CONTEXT ctx = (PFCTIMELINE_PLUGIN_CONTEXT)hTimeline;
    FCSQL_INSERTSTRTABLE SqlStrInsert;
    // build and insert string data into 'str' table.
    if(!Fc_SqlInsertStr(H, ctx->hStmtStr, uszText, &SqlStrInsert)) { return; }
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
VOID FcTimeline_Callback_PluginEntryAddBySQL(_In_ VMM_HANDLE H, _In_ HANDLE hTimeline, _In_ DWORD cEntrySql, _In_ LPCSTR *pszEntrySql)
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
            VmmLog(H, MID_FORENSIC, LOGLEVEL_DEBUG, "BAD SQL CODE=0x%x SQL=%s\n", rc, szSql);
        }
    }
}

/*
* Callback function to close an existing timeline plugin module handle.
* -- hTimeline
*/
VOID FcTimeline_Callback_PluginClose(_In_ VMM_HANDLE H, _In_ HANDLE hTimeline)
{
    PFCTIMELINE_PLUGIN_CONTEXT ctxPlugin = (PFCTIMELINE_PLUGIN_CONTEXT)hTimeline;
    sqlite3_exec(ctxPlugin->hSql, "COMMIT TRANSACTION", NULL, NULL, NULL);
    sqlite3_finalize(ctxPlugin->hStmtStr);
    sqlite3_finalize(ctxPlugin->hStmt);
    Fc_SqlReserveReturn(H, ctxPlugin->hSql);
    LocalFree(ctxPlugin);
}

/*
* Callback function to register a new timeline plugin module.
* -- sNameShort = a 6 char non-null terminated string.
* -- szFileUTF8 = utf-8 file name (if exists)
* -- return = handle, should be closed with callback function.
*/
HANDLE FcTimeline_Callback_PluginRegister(_In_ VMM_HANDLE H, _In_reads_(6) LPCSTR sNameShort, _In_reads_(32) LPCSTR szFileUTF8)
{
    QWORD v;
    sqlite3 *hSql = NULL;
    sqlite3_stmt *hStmt = NULL;
    PFCTIMELINE_PLUGIN_CONTEXT ctxPlugin = NULL;
    if(!(hSql = Fc_SqlReserve(H))) { goto fail; }
    if(SQLITE_OK != sqlite3_prepare_v2(hSql, "INSERT INTO timeline_info (short_name, file_name) VALUES (?, ?);", -1, &hStmt, 0)) { goto fail; }
    if(SQLITE_OK != sqlite3_bind_text(hStmt, 1, sNameShort, 6, NULL)) { goto fail; }
    if(SQLITE_OK != sqlite3_bind_text(hStmt, 2, szFileUTF8, -1, NULL)) { goto fail; }
    if(SQLITE_DONE != sqlite3_step(hStmt)) { goto fail; }
    hSql = Fc_SqlReserveReturn(H, hSql);
    Fc_SqlQueryN(H, "SELECT MAX(id) FROM timeline_info;", 0, NULL, 1, &v, NULL);
    if(!(ctxPlugin = LocalAlloc(LMEM_ZEROINIT, sizeof(FCTIMELINE_PLUGIN_CONTEXT)))) { goto fail; }
    ctxPlugin->dwId = (DWORD)v;
    ctxPlugin->hSql = Fc_SqlReserve(H);
    sqlite3_prepare_v2(ctxPlugin->hSql, "INSERT INTO timeline_data (id_str, tp, ft, ac, pid, data32, data64) VALUES (?, ?, ?, ?, ?, ?, ?);", -1, &ctxPlugin->hStmt, NULL);
    sqlite3_prepare_v2(ctxPlugin->hSql, szFC_SQL_STR_INSERT, -1, &ctxPlugin->hStmtStr, NULL);
    sqlite3_exec(ctxPlugin->hSql, "BEGIN TRANSACTION", NULL, NULL, NULL);
fail:
    sqlite3_finalize(hStmt);
    if(ctxPlugin) {
        return (HANDLE)ctxPlugin;
    }
    Fc_SqlReserveReturn(H, hSql);
    return NULL;
}

/*
* Initialize the timelining functionality. Before the timelining functionality
* is initialized processes, threads, registry and ntfs must be initialized.
* Initialization may take some time.
* -- H
* -- return
*/
_Success_(return)
BOOL FcTimeline_Initialize(_In_ VMM_HANDLE H)
{
    BOOL fResult = FALSE;
    int rc;
    DWORD i;
    QWORD k, v = 0;
    sqlite3 *hSql = NULL;
    sqlite3_stmt *hStmt = NULL;
    PFC_TIMELINE_INFO pi;
    if(H->fAbort) { goto fail; }
    LPSTR szTIMELINE_SQL1[] = {
        // populate timeline_info with basic information:
        "DROP TABLE IF EXISTS timeline_info;",
        "CREATE TABLE timeline_info (id INTEGER PRIMARY KEY, short_name TEXT, file_name TEXT, file_size_u INTEGER DEFAULT 0, file_size_j INTEGER DEFAULT 0, file_size_v INTEGER DEFAULT 0);",
        "INSERT INTO timeline_info VALUES(0, '', 'timeline_all', 0, 0, 0);",
        // populate timeline_data temporary table - with basic data.
        "DROP TABLE IF EXISTS timeline_data;",
        "CREATE TABLE timeline_data ( id INTEGER PRIMARY KEY AUTOINCREMENT, id_str INTEGER, tp INT, ft INTEGER, ac INT, pid INT, data32 INT, data64 INTEGER );"
    };
    for(i = 0; i < sizeof(szTIMELINE_SQL1) / sizeof(LPCSTR); i++) {
        if(SQLITE_OK != (rc = Fc_SqlExec(H, szTIMELINE_SQL1[i]))) {
            VmmLog(H, MID_FORENSIC, LOGLEVEL_WARNING, "FAIL INITIALIZE TIMELINE WITH SQLITE ERROR CODE %i, QUERY: %s", rc, szTIMELINE_SQL1[i]);
            goto fail;
        }
    }
    // populate timeline_data temporary table - with plugins.
    PluginManager_FcTimeline(H, FcTimeline_Callback_PluginRegister, FcTimeline_Callback_PluginClose, FcTimeline_Callback_PluginEntryAdd, FcTimeline_Callback_PluginEntryAddBySQL);
    if(H->fAbort) { goto fail; }
    LPSTR szTIMELINE_SQL2[] = {
        // populate main timeline table:
        "DROP TABLE IF EXISTS timeline;",
        "DROP VIEW IF EXISTS v_timeline;",
        "CREATE TABLE timeline ( id INTEGER PRIMARY KEY AUTOINCREMENT, tp INT, tp_id INTEGER, id_str INTEGER, ft INTEGER, ac INT, pid INT, data32 INT, data64 INTEGER, oln_u INTEGER, oln_j INTEGER, oln_v INTEGER, oln_utp INTEGER, oln_vtp INTEGER );",
        "CREATE VIEW v_timeline AS SELECT * FROM timeline, str WHERE timeline.id_str = str.id;",
        "CREATE UNIQUE INDEX idx_timeline_tpid     ON timeline(tp, tp_id);",
        "CREATE UNIQUE INDEX idx_timeline_oln_u    ON timeline(oln_u);",
        "CREATE UNIQUE INDEX idx_timeline_oln_j    ON timeline(oln_j);",
        "CREATE UNIQUE INDEX idx_timeline_oln_v    ON timeline(oln_v);",
        "CREATE UNIQUE INDEX idx_timeline_oln_utp  ON timeline(tp, oln_utp);",
        "CREATE UNIQUE INDEX idx_timeline_oln_vtp  ON timeline(tp, oln_vtp);",
        "INSERT INTO timeline (tp, tp_id, id_str, ft, ac, pid, data32, data64, oln_u, oln_j, oln_v, oln_utp, oln_vtp) SELECT td.tp, (SUM(1) OVER (PARTITION BY td.tp ORDER BY td.ft DESC, td.id)), td.id_str, td.ft, td.ac, td.pid, td.data32, td.data64, (SUM(str.cbu+"STRINGIZE(FC_LINELENGTH_TIMELINE_UTF8)") OVER (ORDER BY td.ft DESC, td.id) - str.cbu-"STRINGIZE(FC_LINELENGTH_TIMELINE_UTF8)"), (SUM(str.cbj+"STRINGIZE(FC_LINELENGTH_TIMELINE_JSON)") OVER (ORDER BY td.ft DESC, td.id) - str.cbj-"STRINGIZE(FC_LINELENGTH_TIMELINE_JSON)"), (SUM(str.cbv+"STRINGIZE(FC_LINELENGTH_TIMELINE_CSV)")  OVER (ORDER BY td.ft DESC, td.id) - str.cbv-"STRINGIZE(FC_LINELENGTH_TIMELINE_CSV)"), (SUM(str.cbu+"STRINGIZE(FC_LINELENGTH_TIMELINE_UTF8)") OVER (PARTITION BY td.tp ORDER BY td.ft DESC, td.id) - str.cbu-"STRINGIZE(FC_LINELENGTH_TIMELINE_UTF8)"), (SUM(str.cbv+"STRINGIZE(FC_LINELENGTH_TIMELINE_CSV)")  OVER (PARTITION BY td.tp ORDER BY td.ft DESC, td.id) - str.cbv-"STRINGIZE(FC_LINELENGTH_TIMELINE_CSV)") FROM timeline_data td, str WHERE str.id = td.id_str ORDER BY td.ft DESC, td.id;",
        "DROP TABLE timeline_data;"
        // update timeline_info with sizes for 'all' file (utf8, json, csv).
        "UPDATE timeline_info SET file_size_u = (SELECT oln_u+cbu+"STRINGIZE(FC_LINELENGTH_TIMELINE_UTF8)" AS cbu_tot FROM v_timeline WHERE id = (SELECT MAX(id) FROM v_timeline)) WHERE id = 0;",
        "UPDATE timeline_info SET file_size_j = (SELECT oln_j+cbj+"STRINGIZE(FC_LINELENGTH_TIMELINE_JSON)" AS cbj_tot FROM v_timeline WHERE id = (SELECT MAX(id) FROM v_timeline)) WHERE id = 0;",
        "UPDATE timeline_info SET file_size_v = (SELECT oln_v+cbv+"STRINGIZE(FC_LINELENGTH_TIMELINE_CSV)"  AS cbv_tot FROM v_timeline WHERE id = (SELECT MAX(id) FROM v_timeline)) WHERE id = 0;",
    };
    for(i = 0; i < sizeof(szTIMELINE_SQL2) / sizeof(LPCSTR); i++) {
        if(SQLITE_OK != (rc = Fc_SqlExec(H, szTIMELINE_SQL2[i]))) {
            VmmLog(H, MID_FORENSIC, LOGLEVEL_WARNING, "FAIL INITIALIZE TIMELINE WITH SQLITE ERROR CODE %i, QUERY: %s", rc, szTIMELINE_SQL2[i]);
            goto fail;
        }
    }
    // update progress percent counter.
    if(H->fAbort) { goto fail; }
    H->fc->cProgressPercent = 80;
    // update timeline_info with sizes for individual types for utf-8 and csv only.
    LPSTR szTIMELINE_SQL_TIMELINE_UPD[2] = {
        "UPDATE timeline_info SET file_size_u = IFNULL((SELECT oln_utp+cbu+"STRINGIZE(FC_LINELENGTH_TIMELINE_UTF8)" FROM v_timeline WHERE tp = ? AND tp_id = (SELECT MAX(tp_id) FROM v_timeline WHERE tp = ?)), 0) WHERE id = ?;",
        "UPDATE timeline_info SET file_size_v = IFNULL((SELECT oln_vtp+cbv+"STRINGIZE(FC_LINELENGTH_TIMELINE_CSV)"  FROM v_timeline WHERE tp = ? AND tp_id = (SELECT MAX(tp_id) FROM v_timeline WHERE tp = ?)), 0) WHERE id = ?;",
    };
    Fc_SqlQueryN(H, "SELECT MAX(id) FROM timeline_info;", 0, NULL, 1, &v, NULL);
    H->fc->Timeline.cTp = (DWORD)v + 1;
    for(k = 1; k < H->fc->Timeline.cTp; k++) {
        for(i = 0; i < sizeof(szTIMELINE_SQL_TIMELINE_UPD) / sizeof(LPSTR); i++) {
            if(SQLITE_DONE != (rc = Fc_SqlQueryN(H, szTIMELINE_SQL_TIMELINE_UPD[i], 3, (QWORD[]) { k, k, k }, 0, NULL, NULL))) {
                VmmLog(H, MID_FORENSIC, LOGLEVEL_WARNING, "FAIL INITIALIZE TIMELINE WITH SQLITE ERROR CODE %i, QUERY: %s", rc, szTIMELINE_SQL_TIMELINE_UPD[i]);
                goto fail;
            }
        }
    }
    // populate timeline info struct
    if(H->fAbort) { goto fail; }
    if(!(H->fc->Timeline.pInfo = LocalAlloc(LMEM_ZEROINIT, (H->fc->Timeline.cTp) * sizeof(FC_TIMELINE_INFO)))) { goto fail; }
    if(!(hSql = Fc_SqlReserve(H))) { goto fail; }
    if(SQLITE_OK != sqlite3_prepare_v2(hSql, "SELECT id, short_name, file_name, file_size_u, file_size_j, file_size_v FROM timeline_info", -1, &hStmt, 0)) { goto fail; }
    for(i = 0; i < H->fc->Timeline.cTp; i++) {
        pi = H->fc->Timeline.pInfo + i;
        if(SQLITE_ROW != sqlite3_step(hStmt)) { goto fail; }
        pi->dwId = sqlite3_column_int(hStmt, 0);
        pi->szNameShort[0] = 0;
        strncpy_s(pi->szNameShort, _countof(pi->szNameShort), sqlite3_column_text(hStmt, 1), _TRUNCATE);
        pi->szNameShort[_countof(pi->szNameShort) - 1] = 0;
        strncpy_s(pi->uszNameFileTXT, _countof(pi->uszNameFileTXT), sqlite3_column_text(hStmt, 2), _TRUNCATE);
        strncpy_s(pi->uszNameFileCSV, _countof(pi->uszNameFileCSV), pi->uszNameFileTXT, _TRUNCATE);
        strncat_s(pi->uszNameFileTXT, _countof(pi->uszNameFileTXT), ".txt", _TRUNCATE);
        strncat_s(pi->uszNameFileCSV, _countof(pi->uszNameFileCSV), ".csv", _TRUNCATE);
        pi->dwFileSizeUTF8 = sqlite3_column_int(hStmt, 3);
        pi->dwFileSizeJSON = sqlite3_column_int(hStmt, 4);
        pi->dwFileSizeCSV  = sqlite3_column_int(hStmt, 5);
    }
    fResult = TRUE;
fail:
    sqlite3_finalize(hStmt);
    Fc_SqlReserveReturn(H, hSql);
    return fResult;
}

#define FCTIMELINE_SQL_SELECT_FIELDS_ALL " cbu, sz,    id, ft, tp, ac, pid, data32, data64, oln_u,   oln_j,   oln_v  , cbv"
#define FCTIMELINE_SQL_SELECT_FIELDS_TP  " cbu, sz, tp_id, ft, tp, ac, pid, data32, data64, oln_utp, 0,       oln_vtp, cbv"

/*
* Internal function to create a PFCOB_MAP_TIMELINE map from given sql queries.
* -- H
* -- szSqlCount
* -- szSqlSelect
* -- cQueryValues
* -- pqwQueryValues
* -- ppObNtfsMap
* -- return
*/
_Success_(return)
BOOL FcTimelineMap_CreateInternal(_In_ VMM_HANDLE H, _In_ LPSTR szSqlCount, _In_ LPSTR szSqlSelect, _In_ DWORD cQueryValues, _In_reads_(cQueryValues) PQWORD pqwQueryValues, _Out_ PFCOB_MAP_TIMELINE *ppObNtfsMap)
{
    int rc;
    QWORD pqwResult[2];
    DWORD i, cchMultiText;
    LPSTR szuMultiText, szuEntryText;
    PFCOB_MAP_TIMELINE pObTimelineMap = NULL;
    PFC_MAP_TIMELINEENTRY pe;
    sqlite3 *hSql = NULL;
    sqlite3_stmt *hStmt = NULL;
    rc = Fc_SqlQueryN(H, szSqlCount, cQueryValues, pqwQueryValues, 2, pqwResult, NULL);
    if((rc != SQLITE_OK) || (pqwResult[0] > 0x00010000) || (pqwResult[1] > 0x01000000)) { goto fail; }
    cchMultiText = (DWORD)(1 + 2 * pqwResult[0] + pqwResult[1]);
    pObTimelineMap = Ob_AllocEx(H, OB_TAG_MOD_FCTIMELINE, LMEM_ZEROINIT, (SIZE_T)(sizeof(FCOB_MAP_TIMELINE) + pqwResult[0] * sizeof(FC_MAP_TIMELINEENTRY) + cchMultiText), NULL, NULL);
    if(!pObTimelineMap) { goto fail; }
    pObTimelineMap->uszMultiText = (LPSTR)((PBYTE)pObTimelineMap + sizeof(FCOB_MAP_TIMELINE) + pqwResult[0] * sizeof(FC_MAP_TIMELINEENTRY));
    pObTimelineMap->cbuMultiText = cchMultiText;
    pObTimelineMap->cMap = (DWORD)pqwResult[0];
    cchMultiText--;
    szuMultiText = pObTimelineMap->uszMultiText + 1;
    if(!(hSql = Fc_SqlReserve(H))) { goto fail; }
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
        pe->cvszOffset = sqlite3_column_int64(hStmt, 11);
        pe->cvszText = sqlite3_column_int(hStmt, 12);
    }
    Ob_INCREF(pObTimelineMap);
fail:
    sqlite3_finalize(hStmt);
    Fc_SqlReserveReturn(H, hSql);
    *ppObNtfsMap = Ob_DECREF(pObTimelineMap);
    return (*ppObNtfsMap != NULL);
}

/*
* Retrieve a timeline map object consisting of timeline data.
* -- H
* -- dwTimelineType = the timeline type, 0 for all.
* -- qwId = the minimum timeline id of the entries to retrieve.
* -- cId = the number of timeline entries to retrieve.
* -- ppObTimelineMap
* -- return
*/
_Success_(return)
BOOL FcTimelineMap_GetFromIdRange(_In_ VMM_HANDLE H, _In_ DWORD dwTimelineType, _In_ QWORD qwId, _In_ QWORD cId, _Out_ PFCOB_MAP_TIMELINE *ppObTimelineMap)
{
    QWORD v[] = { qwId, qwId + cId, dwTimelineType };
    DWORD iSQL = dwTimelineType ? 2 : 0;
    LPSTR szSQL[] = {
        "SELECT COUNT(*), SUM(cbu) FROM v_timeline WHERE id >= ? AND id < ?",
        "SELECT "FCTIMELINE_SQL_SELECT_FIELDS_ALL" FROM v_timeline WHERE id >= ? AND id < ? ORDER BY id",
        "SELECT COUNT(*), SUM(cbu) FROM v_timeline WHERE tp_id >= ? AND tp_id < ? AND tp = ?",
        "SELECT "FCTIMELINE_SQL_SELECT_FIELDS_TP" FROM v_timeline WHERE tp_id >= ? AND tp_id < ? AND tp = ? ORDER BY tp_id"
    };
    return FcTimelineMap_CreateInternal(H, szSQL[iSQL], szSQL[iSQL + 1], (dwTimelineType ? 3 : 2), v, ppObTimelineMap);
}

/*
* Retrieve the minimum timeline id that exists within a byte range inside a
* timeline file of a specific type.
* -- H
* -- dwTimelineType = the timeline type, 0 for all.
* -- tpFormat = FC_FORMAT_TYPE_UTF8, FC_FORMAT_TYPE_JSON or FC_FORMAT_TYPE_CSV.
* -- qwFilePos = the file position.
* -- pqwId = pointer to receive the result id.
* -- return
*/
_Success_(return)
BOOL FcTimeline_GetIdFromPosition(_In_ VMM_HANDLE H, _In_ DWORD dwTimelineType, _In_ FC_FORMAT_TYPE tpFormat, _In_ QWORD qwFilePos, _Out_ PQWORD pqwId)
{
    QWORD v[] = { max(4096, qwFilePos) - 4096, qwFilePos, dwTimelineType };
    if(dwTimelineType) {
        switch(tpFormat) {
            case FC_FORMAT_TYPE_UTF8:
                return (SQLITE_OK == Fc_SqlQueryN(H, "SELECT MAX(tp_id) FROM timeline WHERE oln_utp >= ? AND oln_utp <= ? AND tp = ?", 3, v, 1, pqwId, NULL));
            case FC_FORMAT_TYPE_JSON:
                return FALSE;
            case FC_FORMAT_TYPE_CSV:
                return (SQLITE_OK == Fc_SqlQueryN(H, "SELECT MAX(tp_id) FROM timeline WHERE oln_vtp >= ? AND oln_vtp <= ? AND tp = ?", 3, v, 1, pqwId, NULL));
        }
    } else {
        switch(tpFormat) {
            case FC_FORMAT_TYPE_UTF8:
                return (SQLITE_OK == Fc_SqlQueryN(H, "SELECT MAX(id) FROM timeline WHERE oln_u >= ? AND oln_u <= ?", 2, v, 1, pqwId, NULL));
            case FC_FORMAT_TYPE_JSON:
                return (SQLITE_OK == Fc_SqlQueryN(H, "SELECT MAX(id) FROM timeline WHERE oln_j >= ? AND oln_j <= ?", 2, v, 1, pqwId, NULL));
            case FC_FORMAT_TYPE_CSV:
                return (SQLITE_OK == Fc_SqlQueryN(H, "SELECT MAX(id) FROM timeline WHERE oln_v >= ? AND oln_v <= ?", 2, v, 1, pqwId, NULL));
        }
    }
    return FALSE;
}



// ----------------------------------------------------------------------------
// PHYSICAL MEMORY SCAN FUNCTIONALITY BELOW:
// Physical memory is scanned and analyzed in parallel via registered plugins
// though the plugin manager - such as, but not limited to, NTFS plugin.
// ----------------------------------------------------------------------------

typedef struct tdFC_SCANPHYSMEM_CONTEXT {
    HANDLE hEventIngestPhys;
    VMMDLL_FORENSIC_INGEST_PHYSMEM e;
} FC_SCANPHYSMEM_CONTEXT, *PFC_SCANPHYSMEM_CONTEXT;


VOID FcScanPhysmem_ThreadProc(_In_ VMM_HANDLE H, _In_ PVMMDLL_FORENSIC_INGEST_PHYSMEM ctx)
{
    DWORD dwPfnBase, cbPfnMap;
    QWORD i, pa;
    BOOL fValidMEMs, fValidAddr;
    PDWORD pPfns = NULL;
    PVMMDLL_MAP_PFNENTRY pePfn;
    if(H->fAbort) { return; }
    ctx->fValid = FALSE;
    // 1: fetch and setup PFN map by calling VMMDLL API
    //    (somewhat ugly to call external api, but it provides required data).
    if(H->fAbort) { goto fail; }
    dwPfnBase = (DWORD)(ctx->pa >> 12);
    if(!(pPfns = LocalAlloc(0, FC_PHYSMEM_NUM_CHUNKS * sizeof(DWORD)))) { goto fail; }
    for(i = 0; i < FC_PHYSMEM_NUM_CHUNKS; i++) {
        pPfns[i] = dwPfnBase + (DWORD)i;
    }
    cbPfnMap = sizeof(VMMDLL_MAP_PFN) + FC_PHYSMEM_NUM_CHUNKS * sizeof(VMMDLL_MAP_PFNENTRY);
    if(!VMMDLL_Map_GetPfn(H, pPfns, FC_PHYSMEM_NUM_CHUNKS, ctx->pPfnMap, &cbPfnMap)) { goto fail; }
    if(ctx->pPfnMap->cMap < FC_PHYSMEM_NUM_CHUNKS) { goto fail; }
    // 2: set up MEMs
    if(H->fAbort) { goto fail; }
    for(i = 0, fValidMEMs = FALSE; i < FC_PHYSMEM_NUM_CHUNKS; i++) {
        pa = ctx->pa + (i << 12);
        fValidAddr = (pa <= H->dev.paMax);
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
        ZeroMemory(ctx->pb, FC_PHYSMEM_NUM_CHUNKS << 12);
        VmmReadScatterPhysical(H, ctx->ppMEMs, FC_PHYSMEM_NUM_CHUNKS, VMM_FLAG_NOCACHEPUT);
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
* -- H
*/
VOID FcScanPhysmem(_In_ VMM_HANDLE H)
{
    BYTE bProgressPercent;
    QWORD i, iChunk = 0, paBase;
    FC_SCANPHYSMEM_CONTEXT ctx2[2] = { 0 };
    PFC_SCANPHYSMEM_CONTEXT ctx;
    // 1: initialize two 16MB physical memory scan chunks
    for(i = 0; i < 2; i++) {
        ctx = ctx2 + i;
        ctx->e.cMEMs = FC_PHYSMEM_NUM_CHUNKS;
        ctx->e.cb = ctx->e.cMEMs * 0x1000;
        if(!(ctx->hEventIngestPhys = CreateEvent(NULL, TRUE, TRUE, NULL))) { goto fail; }
        if(!(ctx->e.pPfnMap = LocalAlloc(LMEM_ZEROINIT, sizeof(VMMDLL_MAP_PFN) + FC_PHYSMEM_NUM_CHUNKS * sizeof(VMMDLL_MAP_PFNENTRY)))) { goto fail; }
        if(!(ctx->e.pb = LocalAlloc(LMEM_ZEROINIT, ctx->e.cb))) { goto fail; }
        if(!LcAllocScatter2(ctx->e.cb, ctx->e.pb, ctx->e.cMEMs, &ctx->e.ppMEMs)) { goto fail; }
    }
    // 2: main physical memory scan loop
    for(paBase = 0; paBase < H->dev.paMax; paBase += 0x1000 * FC_PHYSMEM_NUM_CHUNKS) {
        iChunk++;
        if(H->fAbort) { goto fail; }
        VmmLog(H, MID_FORENSIC, LOGLEVEL_6_TRACE, "PhysicalAddress=%016llx", paBase);
        // 2.1: fetch new physical data in separate thread:
        ctx = ctx2 + (iChunk % 2);
        ctx->e.pa = paBase;
        VmmWork_Void(H, (PVMM_WORK_START_ROUTINE_PVOID_PFN)FcScanPhysmem_ThreadProc, &ctx->e, ctx->hEventIngestPhys, VMMWORK_FLAG_PRIO_LOW);
        // 2.2: process previously scheduled work item (unless first):
        if(paBase == 0) { continue; }
        ctx = ctx2 + ((iChunk - 1) % 2);
        WaitForSingleObject(ctx->hEventIngestPhys, INFINITE);
        if(H->fAbort) { goto fail; }
        if(ctx->e.fValid) {
            PluginManager_FcIngestPhysmem(H, &ctx->e);
        }
        // 2.3: update progress:
        bProgressPercent = (BYTE)((100 * paBase) / H->dev.paMax);
        if(bProgressPercent != H->fc->cProgressPercentScanPhysical) {
            H->fc->cProgressPercentScanPhysical = bProgressPercent;
            H->fc->cProgressPercent = 10 + (min(H->fc->cProgressPercentScanPhysical, H->fc->cProgressPercentScanVirtual) / 2);
        }
    }
    // 2.3: process last read chunk
    if(iChunk) {
        ctx = ctx2 + ((iChunk - 1) % 2);
        WaitForSingleObject(ctx->hEventIngestPhys, INFINITE);
        if(H->fAbort) { goto fail; }
        if(ctx->e.fValid) {
            PluginManager_FcIngestPhysmem(H, &ctx->e);
        }
    }
fail:
    for(i = 0; i < 2; i++) {
        ctx = ctx2 + i;
        if(ctx->hEventIngestPhys) {
            WaitForSingleObject(ctx->hEventIngestPhys, INFINITE);
            CloseHandle(ctx->hEventIngestPhys);
        }
        LcMemFree(ctx->e.ppMEMs);
        LocalFree(ctx->e.pPfnMap);
        LocalFree(ctx->e.pb);
    }
}



// ----------------------------------------------------------------------------
// VIRTUAL MEMORY SCAN FUNCTIONALITY BELOW:
// Virtual memory is scanned and analyzed in parallel per-process via plugins
// though the plugin manager.
// User mode processes are supported and are based on VAD enumeration.
// A special case for the kernel exists which is based on PTE scannint.
// ----------------------------------------------------------------------------

typedef struct tdFCOB_SCAN_VIRTMEM_CONTEXT {
    OB ObHdr;
    POB_MAP pmScanItems;
    struct {
        struct {
            QWORD c;
            QWORD cb;
        } Object;
        struct {
            QWORD c;
            QWORD cb;
        } Kernel;
        struct {
            QWORD c;
            QWORD cb;
        } User;
        QWORD c;
        QWORD cb;
    } Ranges;
    struct {
        QWORD cIngest;
        QWORD cbIngest;
        QWORD tcIngest;
        QWORD cZero;
        QWORD cbZero;
    } Statistics;
} FCOB_SCAN_VIRTMEM_CONTEXT, *PFCOB_SCAN_VIRTMEM_CONTEXT;

int FcScanVirtmem_CmpSort(_In_ POB_MAP_ENTRY e1, _In_ POB_MAP_ENTRY e2)
{
    if(e1->k < e2->k) { return -1; }
    if(e1->k > e2->k) { return 1; }
    return 0;
}

VOID FcScanVirtmem_EntryCleanupCB(_In_ PVMMDLL_FORENSIC_INGEST_VIRTMEM pOb)
{
    Ob_DECREF(pOb->pvProcess);
}

VOID FcScanVirtmem_ContextCleanupCB(_In_ PFCOB_SCAN_VIRTMEM_CONTEXT pOb)
{    
    Ob_DECREF(pOb->pmScanItems);
}

/*
* Add virtual memory to the virtual memory scan list.
*/
VOID FcScanVirtmem_AddRange(_In_ VMM_HANDLE H, _In_ PFCOB_SCAN_VIRTMEM_CONTEXT ctx, _In_ PVMM_PROCESS pProcess, _In_ QWORD va, _In_ DWORD cb)
{
    QWORD qwKey;
    PVMMDLL_FORENSIC_INGEST_VIRTMEM pObScanItem;
    if(ObMap_Size(ctx->pmScanItems) < 0x00100000) {
        if((pObScanItem = Ob_AllocEx(H, OB_TAG_FC_SCANVIRTMEM_ENTRY, LMEM_ZEROINIT, sizeof(VMMDLL_FORENSIC_INGEST_VIRTMEM), (OB_CLEANUP_CB)FcScanVirtmem_EntryCleanupCB, NULL))) {
            pObScanItem->dwVersion = VMMDLL_FORENSIC_INGEST_VIRTMEM_VERSION;
            pObScanItem->dwPID = pProcess->dwPID;
            pObScanItem->pvProcess = Ob_INCREF(pProcess);
            pObScanItem->fPte = !pProcess->fUserOnly;
            pObScanItem->fVad = pProcess->fUserOnly;
            pObScanItem->va = va;
            pObScanItem->cb = cb;
            qwKey = (va << 16) | (pProcess->dwPID >> 2);
            ObMap_Push(ctx->pmScanItems, qwKey, pObScanItem);
            Ob_DECREF(pObScanItem);
        }
    }
}

/*
* Add a object (such as a file) to the virtual memory scan list.
*/
VOID FcScanVirtmem_AddObject(
    _In_ VMM_HANDLE H,
    _In_ PFCOB_SCAN_VIRTMEM_CONTEXT ctx,
    _In_ VMMDLL_FORENSIC_INGEST_OBJECT_TYPE tpObject,
    _In_ QWORD vaObject,
    _In_ DWORD cb,
    _In_z_ _Printf_format_string_ LPSTR uszFormatText,
    ...
) {
    va_list arglist;
    QWORD qwKey;
    SIZE_T cbText;
    PVMMDLL_FORENSIC_INGEST_OBJECT pObScanItem;
    CHAR uszTextBuffer[0x1000];
    if(ObMap_Size(ctx->pmScanItems) < 0x00100000) {
        // format text:
        if(!uszFormatText) { uszFormatText = ""; }
        va_start(arglist, uszFormatText);
        cbText = (SIZE_T)_vsnprintf_s(uszTextBuffer, sizeof(uszTextBuffer), _TRUNCATE, uszFormatText, arglist) + 1;
        va_end(arglist);
        if(cbText > sizeof(uszTextBuffer)) { return; }
        // allocate scan object and add to map:
        if((pObScanItem = Ob_AllocEx(H, OB_TAG_FC_SCANOBJECT_ENTRY, LMEM_ZEROINIT, sizeof(VMMDLL_FORENSIC_INGEST_OBJECT) + cbText, NULL, NULL))) {
            pObScanItem->dwVersion = VMMDLL_FORENSIC_INGEST_OBJECT_VERSION;
            pObScanItem->tp = tpObject;
            pObScanItem->vaObject = vaObject;
            pObScanItem->cb = cb;
            pObScanItem->uszText = (LPSTR)(pObScanItem + 1);
            strncpy_s(pObScanItem->uszText, cbText, uszTextBuffer, _TRUNCATE);
            qwKey = 0xffff000000000000 | vaObject;
            ObMap_Push(ctx->pmScanItems, qwKey, pObScanItem);
            Ob_DECREF(pObScanItem);
        }
    }
}

/*
* Walks a kernel process for entries to add to the scan map. All entries for
* the system process (PID 4) should be added, but only entries not found in
* PID 4 should be added for the csrss.exe processes (i.e. kernel session space).
*/
VOID FcScanVirtmem_AddRangeKernelProcess(_In_ VMM_HANDLE H, _In_ PFCOB_SCAN_VIRTMEM_CONTEXT ctx, _In_ PVMM_PROCESS pProcess, _In_ QWORD va)
{
    QWORD vaMax;
    DWORD iPTE = 0, cbPTE;
    PVMM_MAP_PTEENTRY pePTE;
    PVMMOB_MAP_PTE pObPTE = NULL;
    // 1: init and fetch PTEs:
    if(H->fAbort) { goto fail; }
    if(!VmmMap_GetPte(H, pProcess, &pObPTE, FALSE)) { goto fail; }
    // 2: loop over PTEs and prepare for scanning:
    while(iPTE < pObPTE->cMap) {
        if(H->fAbort) { goto fail; }
        pePTE = pObPTE->pMap + iPTE;
        cbPTE = (DWORD)(pePTE->cPages << 12);
        if(pePTE->vaBase < va) { iPTE++; continue; }        // don't process PTEs before va
        if(cbPTE > 0x20000000) { iPTE++; continue; }        // don't process 512MB+ PTE entries
        va = max(va, pePTE->vaBase);
        vaMax = pePTE->vaBase + cbPTE;
        // merge following PTEs (if adjacent and not too large)
        iPTE++;
        while(iPTE < pObPTE->cMap) {
            pePTE = pObPTE->pMap + iPTE;
            cbPTE = (DWORD)(pePTE->cPages << 12);
            if(vaMax != pePTE->vaBase) { break; }           // don't merge non-adjacent PTEs.
            if(cbPTE > 0x20000000) { break; }               // don't process 512MB+ PTE entries
            if(vaMax - va + cbPTE > 0x20000000) { break; }  // don't merge if chunk becomes 512MB+
            // merge adjacent PTEs
            vaMax += cbPTE;
            iPTE++;
        }
        // add entry to scanning map.
        if((pProcess->dwPID == 4) || !ObMap_ExistsKey(ctx->pmScanItems, ((va << 16) | (4 >> 2)))) {
            FcScanVirtmem_AddRange(H, ctx, pProcess, va, (DWORD)(vaMax - va));
            ctx->Ranges.Kernel.cb += (QWORD)(DWORD)(vaMax - va);
            ctx->Ranges.Kernel.c++;
        }
    }
fail:
    Ob_DECREF(pObPTE);
}

/*
* Prepare scanning of kernel virtual address space (PID 4) and kernel session
* space (csrss.exe ranges differing from PID 4).
*/
VOID FcScanVirtmem_AddRangeKernel(_In_ VMM_HANDLE H, _In_ PFCOB_SCAN_VIRTMEM_CONTEXT ctx)
{
    PVMM_PROCESS pObProcess = NULL;
    if(!(pObProcess = VmmProcessGet(H, 4))) { goto fail; }
    if(FcIsProcessSkip(H, pObProcess)) { goto fail; }
    FcScanVirtmem_AddRangeKernelProcess(H, ctx, pObProcess, 0);
    Ob_DECREF_NULL(&pObProcess);
    while((pObProcess = VmmProcessGetNext(H, pObProcess, 0))) {
        if(H->fAbort) { goto fail; }
        if(!pObProcess->fUserOnly && CharUtil_StrEquals(pObProcess->szName, "csrss.exe", TRUE)) {
            FcScanVirtmem_AddRangeKernelProcess(H, ctx, pObProcess, (H->vmm.f32 ? 0x80000000 : 0xffff000000000000));
        }
    }
fail:
    Ob_DECREF(pObProcess);
}

VOID FcScanVirtmem_AddRangeUserProcess(_In_ VMM_HANDLE H, _In_ PFCOB_SCAN_VIRTMEM_CONTEXT ctx, _In_ PVMM_PROCESS pProcess)
{
    DWORD cbVAD, ie = 0;
    PVMM_MAP_VADENTRY peVAD;
    PVMMOB_MAP_VAD pObVAD = NULL;
    if(!VmmMap_GetVad(H, pProcess, &pObVAD, VMM_VADMAP_TP_CORE)) { goto fail; }
    for(ie = 0; ie < pObVAD->cMap; ie++) {
        peVAD = pObVAD->pMap + ie;
        cbVAD = (DWORD)(peVAD->vaEnd - peVAD->vaStart + 1);
        if(cbVAD > 0x20000000) { continue; }    // don't process 512MB+ entries
        FcScanVirtmem_AddRange(H, ctx, pProcess, peVAD->vaStart, cbVAD);
        ctx->Ranges.User.cb += cbVAD;
        ctx->Ranges.User.c++;
    }
fail:
    Ob_DECREF(pObVAD);
}

/*
* Prepare scanning of user-mode virtual address space.
*/
VOID FcScanVirtmem_AddRangeUser(_In_ VMM_HANDLE H, _In_ PFCOB_SCAN_VIRTMEM_CONTEXT ctx)
{
    PVMM_PROCESS pObProcess = NULL;
    while((pObProcess = VmmProcessGetNext(H, pObProcess, 0))) {
        if(H->fAbort) { goto fail; }
        if(!pObProcess->fUserOnly) { continue; }            // don't scan kernel processes
        if(!pObProcess->win.vaPEB) { continue; }            // don't scan special user-mode processes without PEB (such as MemCompression)
        if(FcIsProcessSkip(H, pObProcess)) { continue; }    // don't scan problematic processes
        FcScanVirtmem_AddRangeUserProcess(H, ctx, pObProcess);
    }
fail:
    Ob_DECREF(pObProcess);
}

/*
* Add object related ranges (such as file objects) to the scanning map.
*/
VOID FcScanVirtmem_AddRangeObjectFile(_In_ VMM_HANDLE H, _In_ PFCOB_SCAN_VIRTMEM_CONTEXT ctx)
{
    POB_MAP pmObFiles = NULL;
    POB_VMMWINOBJ_FILE pObFile;
    VmmWinObjFile_GetAll(H, &pmObFiles);
    while((pObFile = ObMap_Pop(pmObFiles))) {
        if(pObFile->cb && (pObFile->cb <= FC_SCAN_VIRTMEM_MAX_CHUNK_SIZE)) {
            FcScanVirtmem_AddObject(H, ctx, VMMDLL_FORENSIC_INGEST_OBJECT_TYPE_FILE, pObFile->va, (DWORD)pObFile->cb, "FILE:[%s]", pObFile->uszPath);
            ctx->Ranges.Object.cb += pObFile->cb;
            ctx->Ranges.Object.c++;
        }
        Ob_DECREF(pObFile);
    }
    Ob_DECREF(pmObFiles);
}

VOID FcScanVirtmem_ScanRanges_Object(_In_ VMM_HANDLE H, _In_ PFCOB_SCAN_VIRTMEM_CONTEXT ctx, _In_ PVMMDLL_FORENSIC_INGEST_OBJECT pe)
{
    QWORD tcStart;
    if(pe->tp == VMMDLL_FORENSIC_INGEST_OBJECT_TYPE_FILE) {
        pe->cbReadActual = VmmWinObjFile_ReadFromObjectAddress(H, pe->vaObject, 0, pe->pb, min(pe->cb, FC_SCAN_VIRTMEM_MAX_CHUNK_SIZE), VMM_FLAG_ZEROPAD_ON_FAIL, VMMWINOBJ_FILE_TP_DEFAULT);
    }
    if(!pe->cbReadActual || Util_IsZeroBuffer(pe->pb, pe->cb)) {
        InterlockedIncrement64(&ctx->Statistics.cZero);
        InterlockedAdd64(&ctx->Statistics.cbZero, pe->cb);
    } else {
        tcStart = GetTickCount64();
        PluginManager_FcIngestObject(H, pe);
        InterlockedIncrement64(&ctx->Statistics.cIngest);
        InterlockedAdd64(&ctx->Statistics.cbIngest, pe->cb);
        InterlockedAdd64(&ctx->Statistics.tcIngest, GetTickCount64() - tcStart);
    }
}

VOID FcScanVirtmem_ScanRanges_Virtmem(_In_ VMM_HANDLE H, _In_ PFCOB_SCAN_VIRTMEM_CONTEXT ctx, _In_ PVMMDLL_FORENSIC_INGEST_VIRTMEM pe)
{
    QWORD va, tcStart;
    DWORD cb, cbRead;
    va = pe->va;
    cb = pe->cb;
    while(cb) {
        cbRead = min(cb, FC_SCAN_VIRTMEM_MAX_CHUNK_SIZE);
        pe->va = va;
        pe->cb = cbRead;
        VmmReadEx(H, pe->pvProcess, pe->va, pe->pb, pe->cb, &pe->cbReadActual, VMM_FLAG_ZEROPAD_ON_FAIL);
        if(!pe->cbReadActual || Util_IsZeroBuffer(pe->pb, pe->cb)) {
            InterlockedIncrement64(&ctx->Statistics.cZero);
            InterlockedAdd64(&ctx->Statistics.cbZero, pe->cb);
        } else {
            tcStart = GetTickCount64();
            PluginManager_FcIngestVirtmem(H, pe);
            InterlockedIncrement64(&ctx->Statistics.cIngest);
            InterlockedAdd64(&ctx->Statistics.cbIngest, pe->cb);
            InterlockedAdd64(&ctx->Statistics.tcIngest, GetTickCount64() - tcStart);
        }
        va += cbRead;
        cb -= cbRead;
    }
}

VOID FcScanVirtmem_ScanRanges_ThreadProc(_In_ VMM_HANDLE H, _In_ PFCOB_SCAN_VIRTMEM_CONTEXT ctx)
{
    BYTE bProgressPercent;
    PVMMDLL_FORENSIC_INGEST_VIRTMEM pe;
    PBYTE pbBuffer = NULL;
    if(!(pbBuffer = LocalAlloc(LMEM_ZEROINIT, FC_SCAN_VIRTMEM_MAX_CHUNK_SIZE))) { goto fail; }
    while((pe = ObMap_Pop(ctx->pmScanItems))) {
        if(H->fAbort) { goto fail; }
        if(pe->dwVersion == VMMDLL_FORENSIC_INGEST_VIRTMEM_VERSION) {
            pe->pb = pbBuffer;
            FcScanVirtmem_ScanRanges_Virtmem(H, ctx, pe);
        }
        if(pe->dwVersion == VMMDLL_FORENSIC_INGEST_OBJECT_VERSION) {
            ((PVMMDLL_FORENSIC_INGEST_OBJECT)pe)->pb = pbBuffer;
            FcScanVirtmem_ScanRanges_Object(H, ctx, (PVMMDLL_FORENSIC_INGEST_OBJECT)pe);
        }
        Ob_DECREF(pe);
        // 4: update progress.
        bProgressPercent = (BYTE)((100 * (ctx->Ranges.c - ObMap_Size(ctx->pmScanItems))) / ctx->Ranges.c);
        if(bProgressPercent != H->fc->cProgressPercentScanVirtual) {
            H->fc->cProgressPercentScanVirtual = bProgressPercent;
            H->fc->cProgressPercent = 10 + (min(H->fc->cProgressPercentScanPhysical, H->fc->cProgressPercentScanVirtual) / 2);
        }
    }
fail:
    LocalFree(pbBuffer);
}

/*
* Scan virtual memory and select objects (files) for forensic data.
*/
VOID FcScanObjectAndVirtmem_ThreadProc(_In_ VMM_HANDLE H, _In_ QWORD qwNotUsed)
{
    DWORD i;
    PFCOB_SCAN_VIRTMEM_CONTEXT ctx = NULL;
    HANDLE hEventFinish[FC_SCAN_VIRTMEM_WORKER_THREADS] = { 0 };
    // 1: initialize context
    if(!(ctx = Ob_AllocEx(H, OB_TAG_FC_SCANVIRTMEM_CTX, LMEM_ZEROINIT, sizeof(FCOB_SCAN_VIRTMEM_CONTEXT), (OB_CLEANUP_CB)FcScanVirtmem_ContextCleanupCB, NULL))) { goto fail; }
    if(!(ctx->pmScanItems = ObMap_New(H, OB_MAP_FLAGS_OBJECT_OB))) { goto fail; }
    // 2: fetch objects to scan:
    FcScanVirtmem_AddRangeObjectFile(H, ctx);
    VmmLog(H, MID_FORENSIC, LOGLEVEL_5_DEBUG, "FC_VIRTMEM_SCAN: INIT OBJECT: ranges=%lli, bytes=%llx", ctx->Ranges.Object.c, ctx->Ranges.Object.cb);
    // 3: fetch kernel ranges to scan:
    FcScanVirtmem_AddRangeKernel(H, ctx);
    VmmLog(H, MID_FORENSIC, LOGLEVEL_5_DEBUG, "FC_VIRTMEM_SCAN: INIT KERNEL: ranges=%lli, bytes=%llx", ctx->Ranges.Kernel.c, ctx->Ranges.Kernel.cb);
    // 4: fetch user ranges to scan:
    FcScanVirtmem_AddRangeUser(H, ctx);
    VmmLog(H, MID_FORENSIC, LOGLEVEL_5_DEBUG, "FC_VIRTMEM_SCAN: INIT USER:   ranges=%lli, bytes=%llx", ctx->Ranges.User.c, ctx->Ranges.User.cb);
    // 5: sort scan item map - this will arrange it by memory address -
    //    which will give cache locality for image/prototype ranges.
    ctx->Ranges.c = ctx->Ranges.Kernel.c + ctx->Ranges.User.c;
    ctx->Ranges.cb = ctx->Ranges.Kernel.cb + ctx->Ranges.User.cb;
    ObMap_SortEntryIndex(ctx->pmScanItems, FcScanVirtmem_CmpSort);
    VmmLog(H, MID_FORENSIC, LOGLEVEL_4_VERBOSE, "FC_VIRTMEM_SCAN: INIT TOTAL:  ranges=%lli, bytes=%llx", ctx->Ranges.c, ctx->Ranges.cb);
    // 6: start scan in multiple threads (worker threads + main thread)
    ZeroMemory(hEventFinish, sizeof(hEventFinish));
    for(i = 1; i < FC_SCAN_VIRTMEM_WORKER_THREADS; i++) {
        if(!(hEventFinish[i] = CreateEvent(NULL, TRUE, TRUE, NULL))) { goto fail; }
        VmmWork_Ob(H, (PVMM_WORK_START_ROUTINE_OB_PFN)FcScanVirtmem_ScanRanges_ThreadProc, (POB)ctx, hEventFinish[i], VMMWORK_FLAG_PRIO_LOW);
    }
    FcScanVirtmem_ScanRanges_ThreadProc(H, ctx);
    if(FC_SCAN_VIRTMEM_WORKER_THREADS > 1) {
        WaitForMultipleObjects(FC_SCAN_VIRTMEM_WORKER_THREADS - 1, hEventFinish + 1, TRUE, INFINITE);
    }
    VmmLog(H, MID_FORENSIC, LOGLEVEL_4_VERBOSE, "FC_VIRTMEM_SCAN: FINISH");
    VmmLog(H, MID_FORENSIC, LOGLEVEL_5_DEBUG, "FC_VIRTMEM_SCAN: STATISTICS: Zero:    ranges=%lli, bytes=%llx", ctx->Statistics.cZero, ctx->Statistics.cbZero);
    VmmLog(H, MID_FORENSIC, LOGLEVEL_5_DEBUG, "FC_VIRTMEM_SCAN: STATISTICS: Ingest:  ranges=%lli, bytes=%llx", ctx->Statistics.cIngest, ctx->Statistics.cbIngest);
    VmmLog(H, MID_FORENSIC, LOGLEVEL_5_DEBUG, "FC_VIRTMEM_SCAN: STATISTICS: Stats:   threads=%u, time(all_thread)=%llis, scan_speed=%lliMB/s",
        FC_SCAN_VIRTMEM_WORKER_THREADS,
        ctx->Statistics.tcIngest / 1000,
        ((ctx->Statistics.cbIngest * 1000) / (ctx->Statistics.tcIngest * 1024 * 1024))
    );
fail:
    for(i = 1; i < FC_SCAN_VIRTMEM_WORKER_THREADS; i++) {
        if(hEventFinish[i]) { CloseHandle(hEventFinish[i]); }
    }
    H->fc->cProgressPercentScanVirtual = 100;
    Ob_DECREF(ctx);
}


// ----------------------------------------------------------------------------
// FC GENERAL FUNCTIONALITY BELOW:
// ----------------------------------------------------------------------------

BOOL FcIsProcessSkip(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess)
{
    return
        CharUtil_StrCmpAny(CharUtil_StrEquals, pProcess->szName, FALSE, 4, "MsMpEng.exe", "MemCompression", "Registry", "vmmem", "vmware-vmx.exe") ||
        (H->cfg.ForensicProcessSkipList.cusz && CharUtil_StrCmpAnyEx(CharUtil_StrEquals, pProcess->szName, TRUE, H->cfg.ForensicProcessSkipList.cusz, (LPCSTR*)H->cfg.ForensicProcessSkipList.pusz));
}



// ----------------------------------------------------------------------------
// FORENSIC INITIALIZATION FUNCTIONALITY BELOW:
// ----------------------------------------------------------------------------

#define FCINITIALIZE_PROGRESS_UPDATE(dwProgressPercent)   {                                                                                 \
    if(H->fAbort) { goto fail; }                                                                                                            \
    H->fc->cProgressPercent = dwProgressPercent;                                                                                                           \
    VmmLog(H, MID_FORENSIC, LOGLEVEL_5_DEBUG, "INIT %i%% time=%llis", H->fc->cProgressPercent, ((GetTickCount64() - tcStart) / 1000));      \
}

/*
* The core asynchronous forensic initialization function.
*/
VOID FcInitialize_ThreadProc(_In_ VMM_HANDLE H, _In_ QWORD qwNotUsed)
{
    DWORD i;
    BOOL fResult = FALSE;
    VMMDLL_CSV_HANDLE hCSV = NULL;
    PVMMOB_MAP_VM pObVmMap = NULL;
    HANDLE hEventAsyncEvil = 0, hEventAsyncLogCSV = 0, hEventAsyncLogJSON = 0, hEventAsyncIngestObjectAndVirtmem = 0;
    QWORD tmStart = Statistics_CallStart(H);
    QWORD tcStart = GetTickCount64();
    VmmLog(H, MID_FORENSIC, LOGLEVEL_4_VERBOSE, "INIT START");
    VmmLog(H, MID_FORENSIC, LOGLEVEL_4_VERBOSE, "  YARA BUILTIN RULES: %s", H->cfg.fLicenseAcceptElasticV2 ? "ACTIVE" : "INACTIVE");
    VmmLog(H, MID_FORENSIC, LOGLEVEL_4_VERBOSE, "  YARA CUSTOM RULES:  %s", H->cfg.szForensicYaraRules[0] ? H->cfg.szForensicYaraRules : "INACTIVE");
    VmmLog(H, MID_FORENSIC, LOGLEVEL_4_VERBOSE, "  PROCESS SKIPLIST:   %s", H->cfg.ForensicProcessSkipList.cusz ? "ACTIVE" : "INACTIVE");
    for(i = 0; i < H->cfg.ForensicProcessSkipList.cusz; i++) {
        VmmLog(H, MID_FORENSIC, LOGLEVEL_5_DEBUG, "    SKIP PROCESS: %s", H->cfg.ForensicProcessSkipList.pusz[i]);
    }
    VmmLog(H, MID_FORENSIC, LOGLEVEL_5_DEBUG, "INIT %i%% time=%llis", H->fc->cProgressPercent, ((GetTickCount64() - tcStart) / 1000));
    if(SQLITE_OK != Fc_SqlExec(H, FC_SQL_SCHEMA_STR)) { goto fail; }
    if(H->fAbort) { goto fail; }
    if(!(hCSV = LocalAlloc(LMEM_ZEROINIT, sizeof(struct tdVMMDLL_CSV_HANDLE)))) { goto fail; }
    if(!(hEventAsyncEvil = CreateEvent(NULL, TRUE, TRUE, NULL))) { goto fail; }
    if(!(hEventAsyncLogCSV = CreateEvent(NULL, TRUE, TRUE, NULL))) { goto fail; }
    if(!(hEventAsyncLogJSON = CreateEvent(NULL, TRUE, TRUE, NULL))) { goto fail; }
    if(!(hEventAsyncIngestObjectAndVirtmem = CreateEvent(NULL, TRUE, TRUE, NULL))) { goto fail; }
    PluginManager_Notify(H, VMMDLL_PLUGIN_NOTIFY_FORENSIC_INIT, NULL, 0);
    VmmMap_GetVM(H, &pObVmMap);                 // force fetch VMs before starting forensic actions.
    Ob_DECREF_NULL(&pObVmMap);
    PluginManager_FcInitialize(H);
    VmmWork_Value(H, FcEvilInitialize_ThreadProc, 0, hEventAsyncEvil, VMMWORK_FLAG_PRIO_NORMAL);
    // 10-59% (updated by FcScanPhysmem()/FcScanObjectAndVirtmem_ThreadProc()  functions).
    FCINITIALIZE_PROGRESS_UPDATE(10);
    // parallel async init of: scan virtual per-process/kernel address space & init of log for CSV/JSON.
    VmmWork_Value(H, FcScanObjectAndVirtmem_ThreadProc, 0, hEventAsyncIngestObjectAndVirtmem, VMMWORK_FLAG_PRIO_NORMAL);
    VmmWork_Void(H, (PVMM_WORK_START_ROUTINE_PVOID_PFN)PluginManager_FcLogCSV, hCSV, hEventAsyncLogCSV, VMMWORK_FLAG_PRIO_LOW);
    VmmWork_Void(H, (PVMM_WORK_START_ROUTINE_PVOID_PFN)PluginManager_FcLogJSON, FcJson_Callback_EntryAdd, hEventAsyncLogJSON, VMMWORK_FLAG_PRIO_LOW);
    FcScanPhysmem(H);
    WaitForSingleObject(hEventAsyncIngestObjectAndVirtmem, INFINITE);
    // 60%
    FCINITIALIZE_PROGRESS_UPDATE(60);
    PluginManager_FcIngestFinalize(H);
    // 70%
    FCINITIALIZE_PROGRESS_UPDATE(70);
    FcTimeline_Initialize(H);
    // 90%
    FCINITIALIZE_PROGRESS_UPDATE(90);
    WaitForSingleObject(hEventAsyncEvil, INFINITE);
    WaitForSingleObject(hEventAsyncLogCSV, INFINITE);
    WaitForSingleObject(hEventAsyncLogJSON, INFINITE);
    if(H->fAbort) { goto fail; }
    PluginManager_FcFinalize(H);
    // 95%
    FCINITIALIZE_PROGRESS_UPDATE(95);
    FcEvilFinalize(H, hCSV);
    // 100% - finish!
    FCINITIALIZE_PROGRESS_UPDATE(100);
    H->fc->db.fSingleThread = FALSE;
    H->fc->fInitFinish = TRUE;
    PluginManager_Notify(H, VMMDLL_PLUGIN_NOTIFY_FORENSIC_INIT, NULL, 0);
    PluginManager_Notify(H, VMMDLL_PLUGIN_NOTIFY_FORENSIC_INIT_COMPLETE, NULL, 0);
    Statistics_CallEnd(H, STATISTICS_ID_FORENSIC_FcInitialize, tmStart);
    fResult = TRUE;
fail:
    // finalize required even on error (including on H->fAbort) to clean up.
    PluginManager_FcFinalize(H);
    if(hEventAsyncEvil) {
        WaitForSingleObject(hEventAsyncEvil, INFINITE);
        CloseHandle(hEventAsyncEvil);
    }
    FcEvilFinalize(H, hCSV);
    if(hEventAsyncLogCSV) {
        WaitForSingleObject(hEventAsyncLogCSV, INFINITE);
        CloseHandle(hEventAsyncLogCSV);
    }
    if(hEventAsyncLogJSON) {
        WaitForSingleObject(hEventAsyncLogJSON, INFINITE);
        CloseHandle(hEventAsyncLogJSON);
    }
    if(hEventAsyncIngestObjectAndVirtmem) {
        WaitForSingleObject(hEventAsyncIngestObjectAndVirtmem, INFINITE);
        CloseHandle(hEventAsyncIngestObjectAndVirtmem);
    }
    if(H->fc->cProgressPercent != 100) {
        H->fc->cProgressPercent = 0;
    }
    LocalFree(hCSV);
    VmmLog(H, MID_FORENSIC, LOGLEVEL_3_INFO, "Forensic mode completed in %llis%s.", ((GetTickCount64() - tcStart) / 1000), (fResult ? "" : " (FAIL)"));
}

/*
* Interrupt forensic sub-system sql queries (to allow for smooth termination)
* Cleanup will still have to be done by FcClose() once threads are shutdown.
* -- H
*/
VOID FcInterrupt(_In_ VMM_HANDLE H)
{
    DWORD i;
    if(H->fc) {
        EnterCriticalSection(&H->fc->Lock);
        for(i = 0; i < FC_SQL_POOL_CONNECTION_NUM; i++) {
            sqlite3_interrupt(H->fc->db.hSql[i]);
        }
        LeaveCriticalSection(&H->fc->Lock);
    }
}

/*
* Close the forensic sub-system.
* This should be done after threading has been shut down.
* -- H
*/
VOID FcClose(_In_ VMM_HANDLE H)
{
    PFC_CONTEXT ctxFc = H->fc;
    DWORD i;
    if(!ctxFc) { return; }
    EnterCriticalSection(&ctxFc->Lock);
    // 1: interrupt any ongoing database queries.
    for(i = 0; i < FC_SQL_POOL_CONNECTION_NUM; i++) {
        sqlite3_interrupt(ctxFc->db.hSql[i]);
    }
    // 2: wait for query completion (to close handles).
    for(i = 0; i < FC_SQL_POOL_CONNECTION_NUM; i++) {
        if(ctxFc->db.hEventIngestPhys[i]) {
            WaitForSingleObject(ctxFc->db.hEventIngestPhys[i], INFINITE);
            CloseHandle(ctxFc->db.hEventIngestPhys[i]);
            ctxFc->db.hEventIngestPhys[i] = NULL;
        }
        if(ctxFc->db.hSql[i]) {
            sqlite3_close_v2(ctxFc->db.hSql[i]);
        }
    }
    // clean up
    H->fc = NULL;
    if(ctxFc->db.tp == FC_DATABASE_TYPE_TEMPFILE_CLOSE) {
        Util_DeleteFileU(ctxFc->db.uszDatabasePath);
    }
    Ob_DECREF_NULL(&ctxFc->FileJSON.pGen);
    Ob_DECREF_NULL(&ctxFc->FileJSON.pReg);
    Ob_DECREF_NULL(&ctxFc->FileCSV.pm);
    Ob_DECREF_NULL(&ctxFc->FindEvil.pm);
    Ob_DECREF_NULL(&ctxFc->FindEvil.pmf);
    Ob_DECREF_NULL(&ctxFc->FindEvil.pmfYara);
    Ob_DECREF_NULL(&ctxFc->FindEvil.pmfYaraRules);
    LocalFree(ctxFc->Timeline.pInfo);
    LeaveCriticalSection(&ctxFc->Lock);
    DeleteCriticalSection(&ctxFc->Lock);
    LocalFree(ctxFc);
}

/*
* Helper function to set the path of the database file.
* The different paths are saved to the H->fc context.
* -- H
* -- dwDatabaseType = database type as specified by: FC_DATABASE_TYPE_*
* -- return
*/
_Success_(return)
BOOL FcInitialize_SetPath(_In_ VMM_HANDLE H, _In_ DWORD dwDatabaseType)
{
    static LONG dwInMemoryDBCounter = 0;        // global increasing counter to allow for multiple in-memory dbs.
    DWORD i, cch;
    CHAR uszTemp[MAX_PATH];
    WCHAR wszTemp[MAX_PATH], wszTempShort[MAX_PATH];
    SYSTEMTIME st;
    if(dwDatabaseType == FC_DATABASE_TYPE_MEMORY) {
        H->fc->db.tp = FC_DATABASE_TYPE_MEMORY;
        return _snprintf_s(H->fc->db.szuDatabase, _countof(H->fc->db.szuDatabase), _TRUNCATE, "file:///memorydb%i?mode=memory", InterlockedIncrement(&dwInMemoryDBCounter)) > 0;
    }
#ifdef _WIN32
    cch = GetTempPathW(_countof(wszTempShort), wszTempShort);
    if(!cch || cch > 128) { return FALSE; }
    cch = GetLongPathNameW(wszTempShort, wszTemp, _countof(wszTemp));
    if(!cch || cch > 128) { return FALSE; }
    if(!CharUtil_WtoU(wszTemp, -1, uszTemp, sizeof(uszTemp), NULL, NULL, CHARUTIL_FLAG_STR_BUFONLY)) { return FALSE; }
#endif /* _WIN32 */
#if defined(LINUX) || defined(MACOS)
    strcpy_s(uszTemp, sizeof(uszTemp), "/tmp/");
#endif /* LINUX || MACOS */
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
    strncpy_s(H->fc->db.uszDatabasePath, _countof(H->fc->db.uszDatabasePath), uszTemp, _TRUNCATE);
    for(i = 0; i < MAX_PATH; i++) {
        if(uszTemp[i] == '\\') { uszTemp[i] = '/'; }
    }
    strcpy_s(H->fc->db.szuDatabase, _countof(H->fc->db.szuDatabase), "file:///");
    strncpy_s(H->fc->db.szuDatabase + 8, _countof(H->fc->db.szuDatabase) - 8, uszTemp, _TRUNCATE);
    H->fc->db.tp = dwDatabaseType;
    return TRUE;
}

/*
* Core non-threaded forensic initialization function. Allocates and sets up the
* database and kicks off an asynchronous initialization thread for the rest of
* the forensic activities.
* -- H
* -- dwDatabaseType
* -- fForceReInit
* -- return
*/
_Success_(return)
BOOL FcInitialize_Impl(_In_ VMM_HANDLE H, _In_ DWORD dwDatabaseType, _In_ BOOL fForceReInit)
{
    DWORD i;
    if(!dwDatabaseType || (dwDatabaseType > FC_DATABASE_TYPE_MAX)) { return FALSE; }
    if(H->fc && !fForceReInit) { return FALSE; }
    if(H->dev.fVolatile) {
        VmmLog(H, MID_FORENSIC, LOGLEVEL_WARNING, "FORENSIC mode on volatile memory is not recommended due to memory drift/smear.");
    }
    if(!H->cfg.fLicenseAcceptElasticV2 && !H->cfg.fDisableYara && !H->cfg.fDisableInfoDB) {
        VmmLog(H, MID_FORENSIC, LOGLEVEL_WARNING, "Built-in Yara rules from Elastic are disabled. Enable with: -license-accept-elastic-license-2-0");
    }
    H->cfg.tpForensicMode = dwDatabaseType;
    PDB_Initialize_WaitComplete(H);
    if(!PluginManager_Initialize(H)) { goto fail; }
    // 1: ALLOCATE AND INITIALIZE.
    if(H->fc) { FcClose(H); }
    if(!(H->fc = (PFC_CONTEXT)LocalAlloc(LMEM_ZEROINIT, sizeof(FC_CONTEXT)))) { goto fail; }
    InitializeCriticalSection(&H->fc->Lock);
    if(!(H->fc->FileJSON.pGen = ObMemFile_New(H, H->vmm.pObCacheMapObCompressedShared))) { goto fail; }
    if(!(H->fc->FileJSON.pReg = ObMemFile_New(H, H->vmm.pObCacheMapObCompressedShared))) { goto fail; }
    if(!(H->fc->FileCSV.pm = ObMap_New(H, OB_MAP_FLAGS_OBJECT_OB))) { goto fail; }
    // 2: SQLITE INIT:
    if(SQLITE_CONFIG_MULTITHREAD != sqlite3_threadsafe()) {
        VmmLog(H, MID_FORENSIC, LOGLEVEL_CRITICAL, "WRONG SQLITE THREADING MODE - TERMINATING!");
        ExitProcess(0);
    }
    if(!FcInitialize_SetPath(H, dwDatabaseType)) {
        VmmLog(H, MID_FORENSIC, LOGLEVEL_WARNING, "Unable to set Sqlite path.");
        goto fail;
    }
    H->fc->db.fSingleThread = TRUE;     // single thread during INSERT-bound init phase
    for(i = 0; i < FC_SQL_POOL_CONNECTION_NUM; i++) {
        if(!(H->fc->db.hEventIngestPhys[i] = CreateEvent(NULL, FALSE, TRUE, NULL))) { goto fail; }
        if(SQLITE_OK != sqlite3_open_v2(H->fc->db.szuDatabase, &H->fc->db.hSql[i], SQLITE_OPEN_URI | SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_SHAREDCACHE | SQLITE_OPEN_NOMUTEX, NULL)) { goto fail; }
    }
    H->fc->fInitStart = TRUE;
    VmmWork_Value(H, FcInitialize_ThreadProc, 0, 0, VMMWORK_FLAG_PRIO_LOW);
    return TRUE;
fail:
    FcClose(H);
    return FALSE;
}

/*
* Initialize (or re-initialize) the forensic sub-system.
* -- H
* -- dwDatabaseType = database type as specified by: FC_DATABASE_TYPE_*
* -- fForceReInit
* -- return
*/
_Success_(return)
BOOL FcInitialize(_In_ VMM_HANDLE H, _In_ DWORD dwDatabaseType, _In_ BOOL fForceReInit)
{
    BOOL fResult;
    EnterCriticalSection(&H->vmm.LockMaster);
    fResult = FcInitialize_Impl(H, dwDatabaseType, FALSE);
    LeaveCriticalSection(&H->vmm.LockMaster);
    return fResult;
}
