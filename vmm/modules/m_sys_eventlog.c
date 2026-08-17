// m_sys_eventlog.c : implementation of the sys/eventlog built-in module.
//
// The '/sys/eventlog' module enumerates, repairs, parses and exposes Windows
// event log files. All EVTX implementation details are private to this module.
//
// (c) Ulf Frisk, 2026
// Author: Ulf Frisk, pcileech@frizk.net
//

#include "modules.h"
#include "../vmmwinobj.h"
#include "../charutil.h"
#include "../util.h"
#include "../ext/miniz.h"
#ifdef _WIN32
#include <sddl.h>
#endif /* _WIN32 */

// ============================================================================
// PRIVATE EVENT LOG MAP TYPES
// ============================================================================

typedef struct tdVMM_MAP_EVENTLOG_ENUMENTRY {
    DWORD dwPID;                    // Event Log service process PID.
    DWORD dwHandle;                 // Handle in the Event Log service process.
    QWORD vaFileObject;             // Virtual address of the backing _FILE_OBJECT.
    QWORD cbFile;                   // Recovered event log file size.
    LPSTR uszName;                  // UTF-8 file name pointed into VMMOB_MAP_EVENTLOG_ENUM.pbMultiText.
    LPSTR uszPath;                  // UTF-8 object path pointed into VMMOB_MAP_EVENTLOG_ENUM.pbMultiText.
    PVOID _pObFile;                 // Optional retained POB_VMMWINOBJ_FILE used for reads.
    PVOID _pObCParsed;              // Private lazy VMMOB_MAP_EVENTLOG container.
} VMM_MAP_EVENTLOG_ENUMENTRY, *PVMM_MAP_EVENTLOG_ENUMENTRY;

typedef struct tdVMMOB_MAP_EVENTLOG_ENUM {
    OB ObHdr;
    PBYTE pbMultiText;
    DWORD cbMultiText;
    DWORD cMap;
    PVOID _pObCRepair;              // Private lazy VMMOB_MAP_EVENTLOG_REPAIR container.
    VMM_MAP_EVENTLOG_ENUMENTRY pMap[];
} VMMOB_MAP_EVENTLOG_ENUM, *PVMMOB_MAP_EVENTLOG_ENUM;

typedef enum tdVMM_EVENTLOG_REPAIR_STATUS {
    VMM_EVENTLOG_REPAIR_STATUS_UNAVAILABLE = 0,
    VMM_EVENTLOG_REPAIR_STATUS_ORIGINAL    = 1,
    VMM_EVENTLOG_REPAIR_STATUS_REPAIRED    = 2,
} VMM_EVENTLOG_REPAIR_STATUS;

typedef struct tdVMM_MAP_EVENTLOG_REPAIRENTRY {
    VMM_EVENTLOG_REPAIR_STATUS tp;
    DWORD cChunk;                   // Number of 64KiB chunk slots scanned.
    DWORD cChunkValid;              // Number of checksum and record-chain valid chunks.
    DWORD cChunkRetained;           // Number of chunks present in the exposed file.
    QWORD cRecord;                  // Number of structurally valid record instances.
    QWORD cRecordUnique;            // Number of unique record identifiers, if complete.
    QWORD cbFile;                   // Size of the exposed repaired/original file.
    BOOL fRecordIdComplete;         // Unique record identifier accounting is complete.
    PBYTE _pbHeader;                // Private synthesized 4KiB EVTX file header.
    PQWORD _pqwChunkOffset;         // Private ordered source offsets of retained chunks.
} VMM_MAP_EVENTLOG_REPAIRENTRY, *PVMM_MAP_EVENTLOG_REPAIRENTRY;

typedef struct tdVMMOB_MAP_EVENTLOG_REPAIR {
    OB ObHdr;
    DWORD cMap;                     // Entries correspond by index to VMMOB_MAP_EVENTLOG_ENUM.
    VMM_MAP_EVENTLOG_REPAIRENTRY pMap[];
} VMMOB_MAP_EVENTLOG_REPAIR, *PVMMOB_MAP_EVENTLOG_REPAIR;

#define VMM_EVENTLOG_ENTRY_FLAG_CHUNK_HEADER_CRC  0x00000001U
#define VMM_EVENTLOG_ENTRY_FLAG_CHUNK_DATA_CRC    0x00000002U

typedef struct tdVMM_MAP_EVENTLOG_DATAENTRY {
    DWORD iEvent;                   // Index into VMMOB_MAP_EVENTLOG.pMap.
    DWORD iOrdinal;                 // Payload item ordinal within the event.
    BYTE tp;                        // BinXML value type.
    BYTE _Reserved[3];
    LPSTR uszPath;                  // Generic XML path, for example EventData/Data.
    LPSTR uszName;                  // Provider-defined field name.
    LPSTR uszValue;                 // UTF-8 rendered value.
} VMM_MAP_EVENTLOG_DATAENTRY, *PVMM_MAP_EVENTLOG_DATAENTRY;

typedef struct tdVMM_MAP_EVENTLOG_ENTRY {
    QWORD ftRecord;                 // EVTX record-header FILETIME.
    QWORD ftTimeCreated;            // System/TimeCreated FILETIME, if present.
    QWORD qwRecordId;
    QWORD cbOffset;                 // Original event record file offset.
    QWORD qwKeywords;
    DWORD dwEventId;
    DWORD dwQualifiers;
    DWORD dwVersion;
    DWORD dwLevel;
    DWORD dwTask;
    DWORD dwOpcode;
    DWORD dwPID;
    DWORD dwTID;
    DWORD dwFlags;                  // VMM_EVENTLOG_ENTRY_FLAG_*.
    DWORD iData;                    // First payload item in VMMOB_MAP_EVENTLOG.pData.
    DWORD cData;
    LPSTR uszProvider;
    LPSTR uszProviderGuid;
    LPSTR uszEventSource;
    LPSTR uszChannel;
    LPSTR uszComputer;
    LPSTR uszUserSid;
    LPSTR uszActivityId;
    LPSTR uszRelatedActivityId;
    LPSTR uszPayload;               // Compact provider payload.
    LPSTR uszText;                  // Single-line investigator-oriented text.
} VMM_MAP_EVENTLOG_ENTRY, *PVMM_MAP_EVENTLOG_ENTRY;

typedef struct tdVMMOB_MAP_EVENTLOG {
    OB ObHdr;
    PBYTE pbMultiText;
    DWORD cbMultiText;
    LPSTR uszLogName;
    LPSTR uszLogPath;
    QWORD cbText;
    QWORD ftMin;
    QWORD ftMax;
    DWORD cChunk;
    DWORD cChunkHeaderValid;
    DWORD cChunkDataValid;
    DWORD cRecordCandidate;
    DWORD cRecordParsed;
    DWORD cRecordSkipped;
    DWORD cMap;
    DWORD cData;
    PVMM_MAP_EVENTLOG_DATAENTRY pData;
    PDWORD pdwLineOffset;           // Cumulative text line end offsets.
    VMM_MAP_EVENTLOG_ENTRY pMap[];
} VMMOB_MAP_EVENTLOG, *PVMMOB_MAP_EVENTLOG;

// ============================================================================
// EVTX CONSTANTS AND PRIVATE WORK TYPES
// ============================================================================

#define OB_TAG_MAP_EVENTLOG_ENUM                'Mvel'
#define OB_TAG_MAP_EVENTLOG_REPAIR              'Rvel'
#define OB_TAG_MAP_EVENTLOG_PARSED              'Pvel'

#define VMM_EVENTLOG_FILE_HEADER_SIZE           0x00001000U
#define VMM_EVENTLOG_CHUNK_SIZE                 0x00010000U
#define VMM_EVENTLOG_CHUNK_HEADER_SIZE          0x00000200U
#define VMM_EVENTLOG_REPAIR_SCAN_CHUNKS         128U
#define VMM_EVENTLOG_REPAIR_PREFETCH_BATCH_MAX  0x02000000U
#define VMM_EVENTLOG_REPAIR_FILE_OFFSET_MASK    0x0000ffffffffffffULL
#define VMM_EVENTLOG_FILE_FLAG_DIRTY            0x00000001U
#define VMM_EVENTLOG_RECORD_SIGNATURE           0x00002a2aU
#define VMM_EVENTLOG_BINXML_MAX_DEPTH           16U
#define VMM_EVENTLOG_BINXML_MAX_SUBSTITUTIONS   4096U
#define VMM_EVENTLOG_PROCESS_MAX_CHUNKS         0x00002000U
#define VMM_EVENTLOG_PARSE_MAX_EVENTS           0x00040000U
#define VMM_EVENTLOG_PARSE_MAX_DATA_PER_EVENT   256U
#define VMM_EVENTLOG_PARSE_MAX_DATA_BYTES       0x00100000U
#define VMM_EVENTLOG_PARSE_MAX_MAP_BYTES        0x08000000ULL
#define VMM_EVENTLOG_REPAIR_MAX_RECORD_IDS      0x00100000U
#define VMM_EVENTLOG_TEXT_MAX                   0x00000c00U
#define VMM_EVENTLOG_PAYLOAD_MAX                0x00010000U
#define VMM_EVENTLOG_VALUE_BINARY_MAX           0x00001000U

typedef struct tdVMM_EVENTLOG_REPAIR_CHUNK {
    QWORD cbOffset;
    QWORD qwRecordIdFirst;
    QWORD qwRecordIdLast;
    DWORD cRecord;
} VMM_EVENTLOG_REPAIR_CHUNK, *PVMM_EVENTLOG_REPAIR_CHUNK;

// ============================================================================
// EVENT LOG ENUMERATION AND RAW FILE ACCESS
// ============================================================================

/*
* Ensure recovered text is terminated within the module's supported display
* length and cannot inject control characters into line-oriented output.
*/
static BOOL VmmEventLog_Enum_IsSafeText(_In_opt_ LPCSTR usz, _In_ DWORD cchMax, _In_ BOOL fEmpty)
{
    DWORD i;
    UCHAR ch;
    if(!usz || !cchMax) { return FALSE; }
    for(i = 0; i < cchMax; i++) {
        ch = (UCHAR)usz[i];
        if(!ch) { return fEmpty || i; }
        if((ch < 0x20) || (ch == 0x7f)) { return FALSE; }
    }
    return FALSE;
}

static DWORD VmmEventLog_Crc32(_In_reads_(cb) PBYTE pb, _In_ DWORD cb)
{
    return (DWORD)mz_crc32(MZ_CRC32_INIT, pb, cb);
}

static DWORD VmmEventLog_ChunkHeaderCrc32(_In_reads_(VMM_EVENTLOG_CHUNK_HEADER_SIZE) PBYTE pb)
{
    DWORD dwCrc = VmmEventLog_Crc32(pb, 120);
    return (DWORD)mz_crc32(dwCrc, pb + 128, VMM_EVENTLOG_CHUNK_HEADER_SIZE - 128);
}

/*
* Test whether a handle entry represents an event log file.
*/
static BOOL VmmEventLog_Enum_IsHandleEntry(_In_opt_ PVMM_MAP_HANDLEENTRY pe)
{
    return pe &&
        pe->vaObject &&
        pe->uszText &&
        pe->cbuText &&
        (pe->cbuText <= 3 * MAX_PATH) &&
        !pe->uszText[pe->cbuText - 1] &&
        CharUtil_StrEndsWith(pe->uszText, ".evtx", TRUE);
}

/*
* Count event log file handles in a fully initialized handle map.
*/
static DWORD VmmEventLog_Enum_CountHandleEntries(_In_opt_ PVMMOB_MAP_HANDLE pHandleMap)
{
    DWORD i, cEventLog = 0;
    if(!pHandleMap) { return 0; }
    for(i = 0; i < pHandleMap->cMap; i++) {
        if(VmmEventLog_Enum_IsHandleEntry(pHandleMap->pMap + i)) {
            cEventLog++;
        }
    }
    return cEventLog;
}

/*
* Resolve the display name and path from an event log handle and its optional
* recovered file object.
*/
_Success_(return)
static BOOL VmmEventLog_Enum_GetFileInfo(_In_opt_ POB_VMMWINOBJ_FILE pFile, _In_opt_ PVMM_MAP_HANDLEENTRY peHandle, _Out_ LPCSTR *puszName, _Out_ LPCSTR *puszPath)
{
    LPCSTR uszName, uszPath;
    if(!puszName || !puszPath) { return FALSE; }
    *puszName = "";
    *puszPath = "";
    if(!peHandle || !peHandle->uszText || !peHandle->cbuText) { return FALSE; }
    if((peHandle->cbuText > 3 * MAX_PATH) || peHandle->uszText[peHandle->cbuText - 1]) { return FALSE; }
    uszName = pFile ? pFile->uszName : NULL;
    uszPath = pFile ? pFile->uszPath : NULL;
    if(!CharUtil_StrEndsWith(uszName, ".evtx", TRUE)) {
        uszName = CharUtil_PathSplitLast(peHandle->uszText);
    }
    if(!CharUtil_StrEndsWith(uszName, ".evtx", TRUE)) { return FALSE; }
    if(!uszPath || !uszPath[0]) {
        uszPath = peHandle->uszText;
    }
    if(!VmmEventLog_Enum_IsSafeText(uszPath, 3 * MAX_PATH, TRUE)) { return FALSE; }
    *puszName = uszName;
    *puszPath = uszPath ? uszPath : "";
    return TRUE;
}

/*
* Retrieve the svchost.exe process hosting the Windows Event Log service.
* Prefer the authoritative service PID so only one expensive full-text handle
* map is initialized. Fall back to selecting the process with the most open
* .evtx files when the service map is unavailable or incomplete.
* CALLER DECREF: return, *ppObHandleMap
*/
static PVMM_PROCESS VmmEventLog_Enum_GetProcess(_In_ VMM_HANDLE H, _Out_ PVMMOB_MAP_HANDLE *ppObHandleMap)
{
    BOOL f;
    DWORD i, cEventLog, cEventLogMax = 0;
    PVMM_PROCESS pObProcess = NULL, pObProcessEventLog = NULL;
    PVMMOB_MAP_HANDLE pObHandleMap = NULL, pObHandleMapEventLog = NULL;
    PVMMOB_MAP_SERVICE pObServiceMap = NULL;
    PVMM_MAP_SERVICEENTRY peService;
    *ppObHandleMap = NULL;
    // by services map:
    if(VmmMap_GetService(H, &pObServiceMap)) {
        for(i = 0; i < pObServiceMap->cMap; i++) {
            peService = pObServiceMap->pMap + i;
            if(!peService->dwPID || !CharUtil_StrEquals(peService->uszServiceName, "EventLog", TRUE)) { continue; }
            pObProcess = VmmProcessGet(H, peService->dwPID);
            f = pObProcess &&
                CharUtil_StrEquals(pObProcess->szName, "svchost.exe", TRUE) &&
                VmmMap_GetHandle(H, pObProcess, &pObHandleMap, VMM_HANDLE_FLAG_FULLTEXT) &&
                VmmEventLog_Enum_CountHandleEntries(pObHandleMap);
            if(f) {
                *ppObHandleMap = pObHandleMap;
                Ob_DECREF(pObServiceMap);
                return pObProcess;
            }
            Ob_DECREF_NULL(&pObHandleMap);
            Ob_DECREF_NULL(&pObProcess);
            break;
        }
    }
    Ob_DECREF_NULL(&pObServiceMap);
    // by handles:
    while((pObProcess = VmmProcessGetNext(H, pObProcess, 0))) {
        if(!CharUtil_StrEquals(pObProcess->szName, "svchost.exe", TRUE)) { continue; }
        if(!VmmMap_GetHandle(H, pObProcess, &pObHandleMap, VMM_HANDLE_FLAG_FULLTEXT)) { continue; }
        cEventLog = VmmEventLog_Enum_CountHandleEntries(pObHandleMap);
        if(cEventLog > cEventLogMax) {
            Ob_DECREF_NULL(&pObProcessEventLog);
            Ob_DECREF_NULL(&pObHandleMapEventLog);
            pObProcessEventLog = Ob_INCREF(pObProcess);
            pObHandleMapEventLog = pObHandleMap;
            pObHandleMap = NULL;
            cEventLogMax = cEventLog;
        }
        Ob_DECREF_NULL(&pObHandleMap);
    }
    if(!cEventLogMax) {
        Ob_DECREF_NULL(&pObProcessEventLog);
        Ob_DECREF_NULL(&pObHandleMapEventLog);
        return NULL;
    }
    *ppObHandleMap = pObHandleMapEventLog;
    return pObProcessEventLog;
}

/*
* Object cleanup callback.
*/
static VOID VmmEventLog_Enum_CleanupCB(_In_ PVMMOB_MAP_EVENTLOG_ENUM pEventEnumMap)
{
    DWORD i;
    Ob_DECREF_NULL(&pEventEnumMap->_pObCRepair);
    for(i = 0; i < pEventEnumMap->cMap; i++) {
        Ob_DECREF_NULL(&pEventEnumMap->pMap[i]._pObFile);
        Ob_DECREF_NULL(&pEventEnumMap->pMap[i]._pObCParsed);
    }
    LocalFree(pEventEnumMap->pbMultiText);
}

/*
* Allocate an event log enumeration map and its private lazy repair container.
* CALLER DECREF: return
*/
static PVMMOB_MAP_EVENTLOG_ENUM VmmEventLog_Enum_Alloc(_In_ VMM_HANDLE H, _In_ DWORD cMap)
{
    SIZE_T cbMap = sizeof(VMMOB_MAP_EVENTLOG_ENUM) + (SIZE_T)cMap * sizeof(VMM_MAP_EVENTLOG_ENUMENTRY);
    PVMMOB_MAP_EVENTLOG_ENUM pObEventLogMap;
    if((cbMap < sizeof(VMMOB_MAP_EVENTLOG_ENUM)) ||
       (cMap && (((cbMap - sizeof(VMMOB_MAP_EVENTLOG_ENUM)) / sizeof(VMM_MAP_EVENTLOG_ENUMENTRY)) != cMap))) {
        return NULL;
    }
    pObEventLogMap = Ob_AllocEx(H, OB_TAG_MAP_EVENTLOG_ENUM, LMEM_ZEROINIT, cbMap, (OB_CLEANUP_CB)VmmEventLog_Enum_CleanupCB, NULL);
    if(!pObEventLogMap) { return NULL; }
    if(!(pObEventLogMap->_pObCRepair = ObContainer_New())) {
        Ob_DECREF(pObEventLogMap);
        return NULL;
    }
    return pObEventLogMap;
}

/*
* qsort comparator: file name, preferred non-duplicate file object, recovered
* size and finally file object address.
*/
static int VmmEventLog_Enum_CmpSort(_In_ PVMM_MAP_EVENTLOG_ENUMENTRY a, _In_ PVMM_MAP_EVENTLOG_ENUMENTRY b)
{
    int iResult;
    POB_VMMWINOBJ_FILE pObFileA = (POB_VMMWINOBJ_FILE)a->_pObFile;
    POB_VMMWINOBJ_FILE pObFileB = (POB_VMMWINOBJ_FILE)b->_pObFile;
    if((iResult = _stricmp(a->uszName, b->uszName))) { return iResult; }
    if((pObFileA != NULL) != (pObFileB != NULL)) { return pObFileA ? -1 : 1; }
    if(pObFileA && (pObFileA->fDuplicate != pObFileB->fDuplicate)) { return pObFileA->fDuplicate ? 1 : -1; }
    if(a->cbFile != b->cbFile) { return (a->cbFile > b->cbFile) ? -1 : 1; }
    if(a->vaFileObject < b->vaFileObject) { return -1; }
    if(a->vaFileObject > b->vaFileObject) { return 1; }
    return 0;
}

/*
* Remove duplicate original file names from a sorted map. The preferred entry
* is retained by the sort order above.
*/
static VOID VmmEventLog_Enum_RemoveDuplicateNames(_Inout_ PVMMOB_MAP_EVENTLOG_ENUM pEventEnumMap)
{
    DWORD i, iDst = 0;
    PVMM_MAP_EVENTLOG_ENUMENTRY pe;
    for(i = 0; i < pEventEnumMap->cMap; i++) {
        pe = pEventEnumMap->pMap + i;
        if(iDst && CharUtil_StrEquals(pEventEnumMap->pMap[iDst - 1].uszName, pe->uszName, TRUE)) {
            Ob_DECREF_NULL(&pe->_pObFile);
            continue;
        }
        if(iDst != i) {
            memcpy(pEventEnumMap->pMap + iDst, pe, sizeof(VMM_MAP_EVENTLOG_ENUMENTRY));
            ZeroMemory(pe, sizeof(VMM_MAP_EVENTLOG_ENUMENTRY));
        }
        iDst++;
    }
    pEventEnumMap->cMap = iDst;
}

/*
* Locked worker function that creates the event log enumeration map.
* CALLER DECREF: return
*/
static PVMMOB_MAP_EVENTLOG_ENUM VmmEventLog_Enum_DoWork(_In_ VMM_HANDLE H)
{
    DWORD i, cEventLogMax = 0;
    LPCSTR uszName, uszPath;
    PVMM_PROCESS pObProcess = NULL;
    PVMMOB_MAP_HANDLE pObHandleMap = NULL;
    PVMM_MAP_HANDLEENTRY peHandle;
    POB_MAP pmObFiles = NULL;
    POB_VMMWINOBJ_FILE pObFile = NULL;
    POB_STRMAP psmOb = NULL;
    PVMMOB_MAP_EVENTLOG_ENUM pObEventLogMap = NULL;
    PVMM_MAP_EVENTLOG_ENUMENTRY pe;
    if(!(pObProcess = VmmEventLog_Enum_GetProcess(H, &pObHandleMap))) { goto fail; }
    for(i = 0; i < pObHandleMap->cMap; i++) {
        if(VmmEventLog_Enum_IsHandleEntry(pObHandleMap->pMap + i)) {
            cEventLogMax++;
        }
    }
    // Batch-initialize ordinary file objects when available. Handle entries
    // remain authoritative since bulk file recovery may reject valid handles.
    VmmWinObjFile_GetByProcess(H, pObProcess, &pmObFiles, TRUE);
    if(!(pObEventLogMap = VmmEventLog_Enum_Alloc(H, cEventLogMax))) { goto fail; }
    if(cEventLogMax && !(psmOb = ObStrMap_New(H, OB_STRMAP_FLAGS_CASE_SENSITIVE | OB_STRMAP_FLAGS_STR_ASSIGN_TEMPORARY))) { goto fail; }
    for(i = 0; i < pObHandleMap->cMap; i++) {
        peHandle = pObHandleMap->pMap + i;
        if(!VmmEventLog_Enum_IsHandleEntry(peHandle)) { continue; }
        pObFile = ObMap_GetByKey(pmObFiles, peHandle->vaObject);
        if(!pObFile) {
            pObFile = VmmWinObjFile_GetByVa(H, peHandle->vaObject);
        }
        if(!VmmEventLog_Enum_GetFileInfo(pObFile, peHandle, &uszName, &uszPath)) {
            Ob_DECREF_NULL(&pObFile);
            continue;
        }
        pe = pObEventLogMap->pMap + pObEventLogMap->cMap++;
        pe->dwPID = pObProcess->dwPID;
        pe->dwHandle = peHandle->dwHandle;
        pe->vaFileObject = peHandle->vaObject;
        pe->cbFile = (pObFile && pObFile->cb)
            ? pObFile->cb
            : ((peHandle->tpInfoEx == HANDLEENTRY_TP_INFO_FILE) ? peHandle->_InfoFile.cb : 0);
        pe->_pObFile = pObFile;
        pObFile = NULL;
        if(!ObStrMap_PushPtrUU(psmOb, uszName, &pe->uszName, NULL) || !ObStrMap_PushPtrUU(psmOb, uszPath, &pe->uszPath, NULL)) {
            goto fail;
        }
    }
    if(pObEventLogMap->cMap) {
        if(!ObStrMap_FinalizeAllocU_DECREF_NULL(&psmOb, &pObEventLogMap->pbMultiText, &pObEventLogMap->cbMultiText)) { goto fail; }
        qsort(pObEventLogMap->pMap, pObEventLogMap->cMap, sizeof(VMM_MAP_EVENTLOG_ENUMENTRY), (int(*)(void const *, void const *))VmmEventLog_Enum_CmpSort);
        VmmEventLog_Enum_RemoveDuplicateNames(pObEventLogMap);
        for(i = 0; i < pObEventLogMap->cMap; i++) {
            if(!(pObEventLogMap->pMap[i]._pObCParsed = ObContainer_New())) { goto fail; }
        }
    }
    Ob_DECREF(psmOb);
    Ob_DECREF(pObProcess);
    Ob_DECREF(pObHandleMap);
    Ob_DECREF(pmObFiles);
    return pObEventLogMap;
fail:
    Ob_DECREF(pObFile);
    Ob_DECREF(pObProcess);
    Ob_DECREF(pObHandleMap);
    Ob_DECREF(pmObFiles);
    Ob_DECREF(psmOb);
    Ob_DECREF(pObEventLogMap);
    return NULL;
}

_Success_(return)
static BOOL VmmEventLog_Enum(_In_ VMM_HANDLE H, _In_ POB_CONTAINER pC, _Out_ PVMMOB_MAP_EVENTLOG_ENUM *ppObEventLogMap)
{
    PVMMOB_MAP_EVENTLOG_ENUM pObEventLogMap;
    *ppObEventLogMap = NULL;
    if(!pC) { return FALSE; }
    if((pObEventLogMap = ObContainer_GetOb(pC))) {
        *ppObEventLogMap = pObEventLogMap;
        return TRUE;
    }
    EnterCriticalSection(&H->vmm.LockUpdateMap);
    if(!(pObEventLogMap = ObContainer_GetOb(pC))) {
        pObEventLogMap = VmmEventLog_Enum_DoWork(H);
        if(!pObEventLogMap) {
            pObEventLogMap = VmmEventLog_Enum_Alloc(H, 0);
        }
        if(pObEventLogMap) {
            ObContainer_SetOb(pC, pObEventLogMap);
        }
    }
    LeaveCriticalSection(&H->vmm.LockUpdateMap);
    *ppObEventLogMap = pObEventLogMap;
    return pObEventLogMap != NULL;
}

_Success_(return != NULL)
static PVMM_MAP_EVENTLOG_ENUMENTRY VmmEventLog_Enum_GetEntry(_In_opt_ PVMMOB_MAP_EVENTLOG_ENUM pEventEnumMap, _In_ LPCSTR uszName)
{
    DWORD i;
    if(!pEventEnumMap || !uszName || !uszName[0]) { return NULL; }
    for(i = 0; i < pEventEnumMap->cMap; i++) {
        if(CharUtil_StrEquals(pEventEnumMap->pMap[i].uszName, uszName, TRUE)) {
            return pEventEnumMap->pMap + i;
        }
    }
    return NULL;
}

static NTSTATUS VmmEventLog_Read(_In_ VMM_HANDLE H, _In_ PVMM_MAP_EVENTLOG_ENUMENTRY pe, _Out_writes_to_(cb, *pcbRead) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset)
{
    DWORD cbRead;
    POB_VMMWINOBJ_FILE pObFile;
    *pcbRead = 0;
    if(pb && cb) { ZeroMemory(pb, cb); }
    if(!pe || !pb) { return VMM_STATUS_FILE_INVALID; }
    if(cbOffset >= pe->cbFile) { return VMM_STATUS_END_OF_FILE; }
    cbRead = (DWORD)min((QWORD)cb, pe->cbFile - cbOffset);
    if(!cbRead) { return VMM_STATUS_SUCCESS; }
    pObFile = (POB_VMMWINOBJ_FILE)pe->_pObFile;
    *pcbRead = pObFile
        ? VmmWinObjFile_Read(H, pObFile, cbOffset, pb, cbRead, 0, VMMWINOBJ_FILE_TP_DEFAULT)
        : VmmWinObjFile_ReadFromObjectAddress(H, pe->vaFileObject, cbOffset, pb, cbRead, 0, VMMWINOBJ_FILE_TP_DEFAULT);
    return *pcbRead ? VMM_STATUS_SUCCESS : VMM_STATUS_FILE_INVALID;
}

// ============================================================================
// EVTX BINXML PARSING AND TEXT OUTPUT
// ============================================================================

// EVTX BinXML parsing. The parser is intentionally fail-closed at record
// granularity. It accepts records from checksum-damaged chunks when the record
// framing, template and complete substitution stream remain structurally valid.
// --------------------------------------------------------------------------

#define VMM_EVENTLOG_VALUE_NULL         0x00U
#define VMM_EVENTLOG_VALUE_WSTRING      0x01U
#define VMM_EVENTLOG_VALUE_STRING       0x02U
#define VMM_EVENTLOG_VALUE_INT8         0x03U
#define VMM_EVENTLOG_VALUE_UINT8        0x04U
#define VMM_EVENTLOG_VALUE_INT16        0x05U
#define VMM_EVENTLOG_VALUE_UINT16       0x06U
#define VMM_EVENTLOG_VALUE_INT32        0x07U
#define VMM_EVENTLOG_VALUE_UINT32       0x08U
#define VMM_EVENTLOG_VALUE_INT64        0x09U
#define VMM_EVENTLOG_VALUE_UINT64       0x0aU
#define VMM_EVENTLOG_VALUE_REAL32       0x0bU
#define VMM_EVENTLOG_VALUE_REAL64       0x0cU
#define VMM_EVENTLOG_VALUE_BOOL         0x0dU
#define VMM_EVENTLOG_VALUE_BINARY       0x0eU
#define VMM_EVENTLOG_VALUE_GUID         0x0fU
#define VMM_EVENTLOG_VALUE_SIZET        0x10U
#define VMM_EVENTLOG_VALUE_FILETIME     0x11U
#define VMM_EVENTLOG_VALUE_SYSTEMTIME   0x12U
#define VMM_EVENTLOG_VALUE_SID          0x13U
#define VMM_EVENTLOG_VALUE_HEX32        0x14U
#define VMM_EVENTLOG_VALUE_HEX64        0x15U
#define VMM_EVENTLOG_VALUE_BINXML       0x21U
#define VMM_EVENTLOG_VALUE_ARRAY        0x80U

typedef struct tdVMM_EVENTLOG_PARSE_DATA {
    BYTE tp;
    LPSTR uszPath;
    LPSTR uszName;
    LPSTR uszValue;
} VMM_EVENTLOG_PARSE_DATA, *PVMM_EVENTLOG_PARSE_DATA;

typedef struct tdVMM_EVENTLOG_PARSE_EVENT {
    VMM_MAP_EVENTLOG_ENTRY e;
    DWORD cData;
    DWORD cDataMax;
    DWORD cbDataText;
    PVMM_EVENTLOG_PARSE_DATA pData;
    BOOL fEvent;
    BOOL fSystem;
    BOOL fProvider;
    BOOL fEventId;
    BOOL fTimeCreated;
    BOOL fRecordId;
} VMM_EVENTLOG_PARSE_EVENT, *PVMM_EVENTLOG_PARSE_EVENT;

typedef struct tdVMM_EVENTLOG_PARSE_MAP {
    DWORD cEvent;
    DWORD cEventMax;
    PVMM_EVENTLOG_PARSE_EVENT pEvent;
    QWORD cbEvent;
    DWORD cChunk;
    DWORD cChunkHeaderValid;
    DWORD cChunkDataValid;
    DWORD cRecordCandidate;
    DWORD cRecordSkipped;
} VMM_EVENTLOG_PARSE_MAP, *PVMM_EVENTLOG_PARSE_MAP;

typedef struct tdVMM_EVENTLOG_BINXML_SUBSTITUTION {
    PBYTE pb;
    WORD cb;
    BYTE tp;
} VMM_EVENTLOG_BINXML_SUBSTITUTION, *PVMM_EVENTLOG_BINXML_SUBSTITUTION;

typedef struct tdVMM_EVENTLOG_BINXML_CONTEXT {
    PBYTE pbChunk;
    DWORD cbChunk;
    PVMM_EVENTLOG_BINXML_SUBSTITUTION pSub;
    DWORD cSub;
    PVMM_EVENTLOG_PARSE_EVENT pEvent;
    DWORD cDepth;
    BOOL fSystemEnvelope;
} VMM_EVENTLOG_BINXML_CONTEXT, *PVMM_EVENTLOG_BINXML_CONTEXT;

typedef struct tdVMM_EVENTLOG_STRBUF {
    LPSTR usz;
    DWORD cch;
    DWORD cchMax;
    DWORD cchLimit;
    BOOL fTruncated;
} VMM_EVENTLOG_STRBUF, *PVMM_EVENTLOG_STRBUF;

static LPSTR VmmEventLog_Parse_StrDup(_In_opt_ LPCSTR usz)
{
    SIZE_T cb;
    LPSTR uszDst;
    if(!usz) { usz = ""; }
    cb = strlen(usz) + 1;
    if(!(uszDst = LocalAlloc(0, cb))) { return NULL; }
    memcpy(uszDst, usz, cb);
    return uszDst;
}

static PVOID VmmEventLog_Parse_Grow(_In_opt_ PVOID pv, _In_ DWORD cOld, _In_ DWORD cNew, _In_ SIZE_T cbEntry)
{
    SIZE_T cb;
    PVOID pvNew;
    if((cNew <= cOld) || (cbEntry && ((SIZE_T)cNew > ((SIZE_T)-1) / cbEntry))) { return NULL; }
    cb = (SIZE_T)cNew * cbEntry;
    if(!(pvNew = LocalAlloc(LMEM_ZEROINIT, cb))) { return NULL; }
    if(pv && cOld) { memcpy(pvNew, pv, (SIZE_T)cOld * cbEntry); }
    LocalFree(pv);
    return pvNew;
}

static BOOL VmmEventLog_Parse_StrBufEnsure(_Inout_ PVMM_EVENTLOG_STRBUF p, _In_ DWORD cchAdd)
{
    DWORD cchNew;
    LPSTR uszNew;
    if(cchAdd > p->cchLimit - min(p->cch, p->cchLimit)) { cchAdd = p->cchLimit - min(p->cch, p->cchLimit); }
    if((p->cch + cchAdd + 1 <= p->cchMax) || !cchAdd) { return TRUE; }
    cchNew = p->cchMax ? p->cchMax : 256;
    while(cchNew < p->cch + cchAdd + 1) {
        if(cchNew >= p->cchLimit + 1 || cchNew > 0x7fffffffU / 2) {
            cchNew = p->cchLimit + 1;
            break;
        }
        cchNew *= 2;
    }
    if(!(uszNew = VmmEventLog_Parse_Grow(p->usz, p->cchMax, cchNew, 1))) { return FALSE; }
    p->usz = uszNew;
    p->cchMax = cchNew;
    return TRUE;
}

static BOOL VmmEventLog_Parse_StrBufAdd(_Inout_ PVMM_EVENTLOG_STRBUF p, _In_opt_ LPCSTR usz, _In_ BOOL fSingleLine)
{
    DWORD i, cch, cchCopy;
    CHAR ch;
    if(!usz || !usz[0]) { return TRUE; }
    if(p->cch >= p->cchLimit) { p->fTruncated = TRUE; return TRUE; }
    cch = (DWORD)strlen(usz);
    cchCopy = min(cch, p->cchLimit - p->cch);
    if(cchCopy < cch) { p->fTruncated = TRUE; }
    if(!VmmEventLog_Parse_StrBufEnsure(p, cchCopy)) { return FALSE; }
    for(i = 0; i < cchCopy; i++) {
        ch = usz[i];
        if(fSingleLine && ((UCHAR)ch < 0x20)) { ch = ' '; }
        p->usz[p->cch++] = ch;
    }
    p->usz[p->cch] = 0;
    return TRUE;
}

static LPSTR VmmEventLog_Parse_StrBufTake(_Inout_ PVMM_EVENTLOG_STRBUF p)
{
    static const CHAR szTruncated[] = "...[truncated]";
    DWORD cchTruncated = sizeof(szTruncated) - 1;
    LPSTR usz = p->usz;
    if(usz && p->fTruncated && (p->cchLimit >= cchTruncated) && (p->cchMax > p->cchLimit)) {
        p->cch = min(p->cch, p->cchLimit - cchTruncated);
        memcpy(usz + p->cch, szTruncated, (SIZE_T)cchTruncated + 1);
        p->cch += cchTruncated;
    }
    if(!usz) { usz = VmmEventLog_Parse_StrDup(""); }
    ZeroMemory(p, sizeof(VMM_EVENTLOG_STRBUF));
    return usz;
}

static VOID VmmEventLog_Parse_EventCleanup(_Inout_ PVMM_EVENTLOG_PARSE_EVENT pEvent)
{
    DWORD i;
    VMM_EVENTLOG_PARSE_DATA Data = { 0 };
    PVMM_EVENTLOG_PARSE_DATA pData;
    if(!pEvent) { return; }
    LocalFree(pEvent->e.uszProvider);
    LocalFree(pEvent->e.uszProviderGuid);
    LocalFree(pEvent->e.uszEventSource);
    LocalFree(pEvent->e.uszChannel);
    LocalFree(pEvent->e.uszComputer);
    LocalFree(pEvent->e.uszUserSid);
    LocalFree(pEvent->e.uszActivityId);
    LocalFree(pEvent->e.uszRelatedActivityId);
    LocalFree(pEvent->e.uszPayload);
    LocalFree(pEvent->e.uszText);
    pData = pEvent->pData;
    for(i = 0; pData && (i < pEvent->cData); i++, pData++) {
        // Keep MSVC analysis aware that every dynamically grown entry is initialized.
        memcpy(&Data, pData, sizeof(VMM_EVENTLOG_PARSE_DATA));
        if(Data.uszPath) { LocalFree(Data.uszPath); }
        if(Data.uszName) { LocalFree(Data.uszName); }
        if(Data.uszValue) { LocalFree(Data.uszValue); }
    }
    LocalFree(pEvent->pData);
    ZeroMemory(pEvent, sizeof(VMM_EVENTLOG_PARSE_EVENT));
}

static VOID VmmEventLog_Parse_MapCleanup(_Inout_ PVMM_EVENTLOG_PARSE_MAP pMap)
{
    DWORD i;
    for(i = 0; i < pMap->cEvent; i++) {
        VmmEventLog_Parse_EventCleanup(pMap->pEvent + i);
    }
    LocalFree(pMap->pEvent);
    ZeroMemory(pMap, sizeof(VMM_EVENTLOG_PARSE_MAP));
}

static BOOL VmmEventLog_Parse_EventSetString(_Inout_ LPSTR *puszDst, _In_opt_ LPCSTR usz)
{
    LPSTR uszNew = VmmEventLog_Parse_StrDup(usz);
    if(!uszNew) { return FALSE; }
    LocalFree(*puszDst);
    *puszDst = uszNew;
    return TRUE;
}

static BOOL VmmEventLog_Parse_EventAddData(_Inout_ PVMM_EVENTLOG_PARSE_EVENT pEvent, _In_ BYTE tp, _In_ LPCSTR uszPath, _In_opt_ LPCSTR uszName, _In_ LPSTR uszValue)
{
    DWORD cNew;
    SIZE_T cbDataText;
    LPCSTR uszNameUse;
    PVMM_EVENTLOG_PARSE_DATA pData;
    if(!pEvent || !uszPath || !uszValue) { LocalFree(uszValue); return FALSE; }
    if(pEvent->cData >= VMM_EVENTLOG_PARSE_MAX_DATA_PER_EVENT) {
        LocalFree(uszValue);
        return TRUE;
    }
    uszNameUse = (uszName && uszName[0]) ? uszName : CharUtil_PathSplitLast(uszPath);
    cbDataText = strlen(uszPath) + strlen(uszNameUse) + strlen(uszValue) + 3;
    if((cbDataText > VMM_EVENTLOG_PARSE_MAX_DATA_BYTES) ||
       (cbDataText > VMM_EVENTLOG_PARSE_MAX_DATA_BYTES - min(pEvent->cbDataText, VMM_EVENTLOG_PARSE_MAX_DATA_BYTES))) {
        LocalFree(uszValue);
        return TRUE;
    }
    if(pEvent->cData == pEvent->cDataMax) {
        cNew = pEvent->cDataMax ? pEvent->cDataMax * 2 : 16;
        pData = VmmEventLog_Parse_Grow(pEvent->pData, pEvent->cDataMax, cNew, sizeof(VMM_EVENTLOG_PARSE_DATA));
        if(!pData) { LocalFree(uszValue); return FALSE; }
        pEvent->pData = pData;
        pEvent->cDataMax = cNew;
    }
    pData = pEvent->pData + pEvent->cData;
    ZeroMemory(pData, sizeof(VMM_EVENTLOG_PARSE_DATA));
    pData->tp = tp;
    pData->uszPath = VmmEventLog_Parse_StrDup(uszPath);
    pData->uszName = VmmEventLog_Parse_StrDup(uszNameUse);
    pData->uszValue = uszValue;
    if(!pData->uszPath || !pData->uszName || !pData->uszValue) {
        LocalFree(pData->uszPath);
        LocalFree(pData->uszName);
        LocalFree(pData->uszValue);
        ZeroMemory(pData, sizeof(VMM_EVENTLOG_PARSE_DATA));
        return FALSE;
    }
    pEvent->cbDataText += (DWORD)cbDataText;
    pEvent->cData++;
    return TRUE;
}

static BOOL VmmEventLog_Parse_MapAddEvent(_Inout_ PVMM_EVENTLOG_PARSE_MAP pMap, _Inout_ PVMM_EVENTLOG_PARSE_EVENT pEvent)
{
    DWORD cNew;
    PVMM_EVENTLOG_PARSE_EVENT pEvents;
    if(pMap->cEvent >= VMM_EVENTLOG_PARSE_MAX_EVENTS) { return FALSE; }
    if(pMap->cEvent == pMap->cEventMax) {
        cNew = pMap->cEventMax ? pMap->cEventMax * 2 : 256;
        pEvents = VmmEventLog_Parse_Grow(pMap->pEvent, pMap->cEventMax, cNew, sizeof(VMM_EVENTLOG_PARSE_EVENT));
        if(!pEvents) { return FALSE; }
        pMap->pEvent = pEvents;
        pMap->cEventMax = cNew;
    }
    memcpy(pMap->pEvent + pMap->cEvent++, pEvent, sizeof(VMM_EVENTLOG_PARSE_EVENT));
    ZeroMemory(pEvent, sizeof(VMM_EVENTLOG_PARSE_EVENT));
    return TRUE;
}

static LPSTR VmmEventLog_Parse_Utf16(_In_reads_bytes_(cb) PBYTE pb, _In_ DWORD cb)
{
    DWORD i, cch;
    LPWSTR wsz = NULL;
    LPSTR usz = NULL;
    if(cb & 1) { return NULL; }
    cch = cb >> 1;
    while(cch && !*(PWORD)(pb + ((SIZE_T)cch - 1) * 2)) { cch--; }
    if(!cch) { return VmmEventLog_Parse_StrDup(""); }
    if((SIZE_T)cch + 1 > ((SIZE_T)-1) / sizeof(WCHAR)) { return NULL; }
    if(!(wsz = LocalAlloc(LMEM_ZEROINIT, ((SIZE_T)cch + 1) * sizeof(WCHAR)))) { return NULL; }
    for(i = 0; i < cch; i++) { wsz[i] = (WCHAR)*(PWORD)(pb + (SIZE_T)i * 2); }
    if(!CharUtil_WtoU(wsz, cch, NULL, 0, &usz, NULL, CHARUTIL_FLAG_ALLOC)) {
        LocalFree(wsz);
        return NULL;
    }
    LocalFree(wsz);
    return usz;
}

static LPSTR VmmEventLog_Parse_Ansi(_In_reads_bytes_(cb) PBYTE pb, _In_ DWORD cb)
{
    DWORD i;
    LPSTR usz;
    while(cb && !pb[cb - 1]) { cb--; }
    if(!(usz = LocalAlloc(0, (SIZE_T)cb + 1))) { return NULL; }
    for(i = 0; i < cb; i++) {
        usz[i] = ((pb[i] >= 0x20) && (pb[i] < 0x7f)) || (pb[i] == '\r') || (pb[i] == '\n') || (pb[i] == '\t')
            ? (CHAR)pb[i]
            : '?';
    }
    usz[cb] = 0;
    return usz;
}

static LPSTR VmmEventLog_Parse_Hex(_In_reads_bytes_(cb) PBYTE pb, _In_ DWORD cb, _In_ BOOL fPrefix)
{
    static const CHAR szHex[] = "0123456789abcdef";
    DWORD i, cbUse = min(cb, VMM_EVENTLOG_VALUE_BINARY_MAX);
    SIZE_T cch = (fPrefix ? 2 : 0) + (SIZE_T)cbUse * 2 + ((cbUse < cb) ? 16 : 0) + 1;
    LPSTR usz, p;
    if(!(usz = LocalAlloc(0, cch))) { return NULL; }
    p = usz;
    if(fPrefix) { *p++ = '0'; *p++ = 'x'; }
    for(i = 0; i < cbUse; i++) {
        *p++ = szHex[pb[i] >> 4];
        *p++ = szHex[pb[i] & 0x0f];
    }
    if(cbUse < cb) { memcpy(p, "...[truncated]", 15); p += 15; }
    *p = 0;
    return usz;
}

static LPSTR VmmEventLog_Parse_Format(_In_z_ _Printf_format_string_ LPCSTR uszFormat, ...)
{
    CHAR sz[256];
    va_list arglist;
    va_start(arglist, uszFormat);
    _vsnprintf_s(sz, sizeof(sz), _TRUNCATE, uszFormat, arglist);
    va_end(arglist);
    return VmmEventLog_Parse_StrDup(sz);
}

static LPSTR VmmEventLog_Parse_Guid(_In_reads_(16) PBYTE pb)
{
    return VmmEventLog_Parse_Format(
        "%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
        *(PDWORD)pb, *(PWORD)(pb + 4), *(PWORD)(pb + 6),
        pb[8], pb[9], pb[10], pb[11], pb[12], pb[13], pb[14], pb[15]
    );
}

static LPSTR VmmEventLog_Parse_Sid(_In_reads_bytes_(cb) PBYTE pb, _In_ DWORD cb)
{
    DWORD cbSid;
    LPSTR uszSid = NULL;
    if(cb < 8) { return NULL; }
    cbSid = 8 + (DWORD)pb[1] * 4;
    if((cbSid > cb) || !ConvertSidToStringSidA((PSID)pb, &uszSid)) { return NULL; }
    return uszSid;
}

static LPCSTR VmmEventLog_Parse_TypeName(_In_ BYTE tp)
{
    BOOL fArray = (tp & VMM_EVENTLOG_VALUE_ARRAY) != 0;
    switch(tp & ~VMM_EVENTLOG_VALUE_ARRAY) {
        case VMM_EVENTLOG_VALUE_NULL:       return "null";
        case VMM_EVENTLOG_VALUE_WSTRING:    return fArray ? "string[]" : "string";
        case VMM_EVENTLOG_VALUE_STRING:     return fArray ? "ansi[]" : "ansi";
        case VMM_EVENTLOG_VALUE_INT8:       return fArray ? "int8[]" : "int8";
        case VMM_EVENTLOG_VALUE_UINT8:      return fArray ? "uint8[]" : "uint8";
        case VMM_EVENTLOG_VALUE_INT16:      return fArray ? "int16[]" : "int16";
        case VMM_EVENTLOG_VALUE_UINT16:     return fArray ? "uint16[]" : "uint16";
        case VMM_EVENTLOG_VALUE_INT32:      return fArray ? "int32[]" : "int32";
        case VMM_EVENTLOG_VALUE_UINT32:     return fArray ? "uint32[]" : "uint32";
        case VMM_EVENTLOG_VALUE_INT64:      return fArray ? "int64[]" : "int64";
        case VMM_EVENTLOG_VALUE_UINT64:     return fArray ? "uint64[]" : "uint64";
        case VMM_EVENTLOG_VALUE_REAL32:     return fArray ? "float[]" : "float";
        case VMM_EVENTLOG_VALUE_REAL64:     return fArray ? "double[]" : "double";
        case VMM_EVENTLOG_VALUE_BOOL:       return fArray ? "bool[]" : "bool";
        case VMM_EVENTLOG_VALUE_BINARY:     return "binary";
        case VMM_EVENTLOG_VALUE_GUID:       return fArray ? "guid[]" : "guid";
        case VMM_EVENTLOG_VALUE_SIZET:      return fArray ? "size[]" : "size";
        case VMM_EVENTLOG_VALUE_FILETIME:   return fArray ? "filetime[]" : "filetime";
        case VMM_EVENTLOG_VALUE_SYSTEMTIME: return fArray ? "systemtime[]" : "systemtime";
        case VMM_EVENTLOG_VALUE_SID:        return fArray ? "sid[]" : "sid";
        case VMM_EVENTLOG_VALUE_HEX32:      return fArray ? "hex32[]" : "hex32";
        case VMM_EVENTLOG_VALUE_HEX64:      return fArray ? "hex64[]" : "hex64";
        case VMM_EVENTLOG_VALUE_BINXML:     return "binxml";
        default:                            return "unknown";
    }
}

static DWORD VmmEventLog_Parse_ValueScalarSize(_In_ BYTE tp)
{
    switch(tp) {
        case VMM_EVENTLOG_VALUE_INT8:
        case VMM_EVENTLOG_VALUE_UINT8:      return 1;
        case VMM_EVENTLOG_VALUE_INT16:
        case VMM_EVENTLOG_VALUE_UINT16:     return 2;
        case VMM_EVENTLOG_VALUE_INT32:
        case VMM_EVENTLOG_VALUE_UINT32:
        case VMM_EVENTLOG_VALUE_REAL32:
        case VMM_EVENTLOG_VALUE_BOOL:
        case VMM_EVENTLOG_VALUE_HEX32:      return 4;
        case VMM_EVENTLOG_VALUE_INT64:
        case VMM_EVENTLOG_VALUE_UINT64:
        case VMM_EVENTLOG_VALUE_REAL64:
        case VMM_EVENTLOG_VALUE_FILETIME:
        case VMM_EVENTLOG_VALUE_HEX64:      return 8;
        case VMM_EVENTLOG_VALUE_GUID:
        case VMM_EVENTLOG_VALUE_SYSTEMTIME: return 16;
        default:                            return 0;
    }
}

static LPSTR VmmEventLog_Parse_ValueToStringScalar(_In_ BYTE tp, _In_reads_bytes_(cb) PBYTE pb, _In_ DWORD cb)
{
    CHAR szTime[24];
    float f;
    double d;
    QWORD qw;
    DWORD dw;
    if(tp == VMM_EVENTLOG_VALUE_NULL) { return VmmEventLog_Parse_StrDup(""); }
    switch(tp) {
        case VMM_EVENTLOG_VALUE_WSTRING:
            return VmmEventLog_Parse_Utf16(pb, cb);
        case VMM_EVENTLOG_VALUE_STRING:
            return VmmEventLog_Parse_Ansi(pb, cb);
        case VMM_EVENTLOG_VALUE_INT8:
            if(cb < 1) { return NULL; }
            return VmmEventLog_Parse_Format("%i", (int)(signed char)pb[0]);
        case VMM_EVENTLOG_VALUE_UINT8:
            if(cb < 1) { return NULL; }
            return VmmEventLog_Parse_Format("%u", (unsigned int)pb[0]);
        case VMM_EVENTLOG_VALUE_INT16:
            if(cb < 2) { return NULL; }
            return VmmEventLog_Parse_Format("%i", (int)(short)*(PWORD)pb);
        case VMM_EVENTLOG_VALUE_UINT16:
            if(cb < 2) { return NULL; }
            return VmmEventLog_Parse_Format("%u", (unsigned int)*(PWORD)pb);
        case VMM_EVENTLOG_VALUE_INT32:
            if(cb < 4) { return NULL; }
            return VmmEventLog_Parse_Format("%i", (int)*(PDWORD)pb);
        case VMM_EVENTLOG_VALUE_UINT32:
            if(cb < 4) { return NULL; }
            return VmmEventLog_Parse_Format("%u", *(PDWORD)pb);
        case VMM_EVENTLOG_VALUE_INT64:
            if(cb < 8) { return NULL; }
            return VmmEventLog_Parse_Format("%lld", (long long)*(PQWORD)pb);
        case VMM_EVENTLOG_VALUE_UINT64:
            if(cb < 8) { return NULL; }
            return VmmEventLog_Parse_Format("%llu", *(PQWORD)pb);
        case VMM_EVENTLOG_VALUE_REAL32:
            if(cb < 4) { return NULL; }
            dw = *(PDWORD)pb;
            memcpy(&f, &dw, sizeof(f));
            return VmmEventLog_Parse_Format("%.9g", f);
        case VMM_EVENTLOG_VALUE_REAL64:
            if(cb < 8) { return NULL; }
            qw = *(PQWORD)pb;
            memcpy(&d, &qw, sizeof(d));
            return VmmEventLog_Parse_Format("%.17g", d);
        case VMM_EVENTLOG_VALUE_BOOL:
            if(cb < 4) { return NULL; }
            return VmmEventLog_Parse_StrDup(*(PDWORD)pb ? "true" : "false");
        case VMM_EVENTLOG_VALUE_BINARY:
            return VmmEventLog_Parse_Hex(pb, cb, FALSE);
        case VMM_EVENTLOG_VALUE_GUID:
            if(cb < 16) { return NULL; }
            return VmmEventLog_Parse_Guid(pb);
        case VMM_EVENTLOG_VALUE_SIZET:
            if(cb == 4) { return VmmEventLog_Parse_Format("0x%08x", *(PDWORD)pb); }
            if(cb >= 8) { return VmmEventLog_Parse_Format("0x%016llx", *(PQWORD)pb); }
            return NULL;
        case VMM_EVENTLOG_VALUE_FILETIME:
            if(cb < 8) { return NULL; }
            Util_FileTime2String(*(PQWORD)pb, szTime);
            return VmmEventLog_Parse_StrDup(szTime);
        case VMM_EVENTLOG_VALUE_SYSTEMTIME:
            if(cb < 16) { return NULL; }
            return VmmEventLog_Parse_Format(
                "%04u-%02u-%02uT%02u:%02u:%02u.%03uZ",
                *(PWORD)pb, *(PWORD)(pb + 2), *(PWORD)(pb + 6),
                *(PWORD)(pb + 8), *(PWORD)(pb + 10), *(PWORD)(pb + 12),
                *(PWORD)(pb + 14)
            );
        case VMM_EVENTLOG_VALUE_SID:
            return VmmEventLog_Parse_Sid(pb, cb);
        case VMM_EVENTLOG_VALUE_HEX32:
            if(cb < 4) { return NULL; }
            return VmmEventLog_Parse_Format("0x%08x", *(PDWORD)pb);
        case VMM_EVENTLOG_VALUE_HEX64:
            if(cb < 8) { return NULL; }
            return VmmEventLog_Parse_Format("0x%016llx", *(PQWORD)pb);
        default:
            return NULL;
    }
}

static LPSTR VmmEventLog_Parse_ValueStringArray(_In_ BYTE tp, _In_reads_bytes_(cb) PBYTE pb, _In_ DWORD cb)
{
    DWORD i = 0, iStart;
    LPSTR uszPart = NULL;
    VMM_EVENTLOG_STRBUF sb = { 0 };
    sb.cchLimit = VMM_EVENTLOG_PAYLOAD_MAX;
    while(i < cb) {
        iStart = i;
        if(tp == VMM_EVENTLOG_VALUE_WSTRING) {
            while((i + 1 < cb) && *(PWORD)(pb + i)) { i += 2; }
            if(i + 1 >= cb) { LocalFree(sb.usz); return NULL; }
            uszPart = VmmEventLog_Parse_Utf16(pb + iStart, i - iStart);
            i += 2;
        } else {
            while((i < cb) && pb[i]) { i++; }
            if(i >= cb) { LocalFree(sb.usz); return NULL; }
            uszPart = VmmEventLog_Parse_Ansi(pb + iStart, i - iStart);
            i++;
        }
        if(!uszPart || (sb.cch && !VmmEventLog_Parse_StrBufAdd(&sb, " | ", FALSE)) ||
           !VmmEventLog_Parse_StrBufAdd(&sb, uszPart, FALSE)) {
            LocalFree(uszPart);
            LocalFree(sb.usz);
            return NULL;
        }
        LocalFree(uszPart);
    }
    return VmmEventLog_Parse_StrBufTake(&sb);
}

static LPSTR VmmEventLog_Parse_ValueToString(_In_ BYTE tp, _In_reads_bytes_opt_(cb) PBYTE pb, _In_ DWORD cb)
{
    BYTE tpBase;
    DWORD i, cbItem;
    LPSTR uszPart;
    VMM_EVENTLOG_STRBUF sb = { 0 };
    if(!cb && (tp == VMM_EVENTLOG_VALUE_NULL)) { return VmmEventLog_Parse_StrDup(""); }
    if(!pb) { return NULL; }
    if(!(tp & VMM_EVENTLOG_VALUE_ARRAY)) {
        return VmmEventLog_Parse_ValueToStringScalar(tp, pb, cb);
    }
    tpBase = tp & ~VMM_EVENTLOG_VALUE_ARRAY;
    if((tpBase == VMM_EVENTLOG_VALUE_WSTRING) || (tpBase == VMM_EVENTLOG_VALUE_STRING)) {
        return VmmEventLog_Parse_ValueStringArray(tpBase, pb, cb);
    }
    cbItem = VmmEventLog_Parse_ValueScalarSize(tpBase);
    if(!cbItem || (cb % cbItem)) { return NULL; }
    sb.cchLimit = VMM_EVENTLOG_PAYLOAD_MAX;
    for(i = 0; i < cb; i += cbItem) {
        if(!(uszPart = VmmEventLog_Parse_ValueToStringScalar(tpBase, pb + i, cbItem))) {
            LocalFree(sb.usz);
            return NULL;
        }
        if((sb.cch && !VmmEventLog_Parse_StrBufAdd(&sb, " | ", FALSE)) ||
           !VmmEventLog_Parse_StrBufAdd(&sb, uszPart, FALSE)) {
            LocalFree(uszPart);
            LocalFree(sb.usz);
            return NULL;
        }
        LocalFree(uszPart);
    }
    return VmmEventLog_Parse_StrBufTake(&sb);
}

static BOOL VmmEventLog_Parse_ValueAsQWORD(_In_ BYTE tp, _In_reads_bytes_(cb) PBYTE pb, _In_ DWORD cb, _Out_ PQWORD pqw)
{
    *pqw = 0;
    switch(tp) {
        case VMM_EVENTLOG_VALUE_INT8:
        case VMM_EVENTLOG_VALUE_UINT8:
            if(cb < 1) { return FALSE; }
            *pqw = pb[0]; return TRUE;
        case VMM_EVENTLOG_VALUE_INT16:
        case VMM_EVENTLOG_VALUE_UINT16:
            if(cb < 2) { return FALSE; }
            *pqw = *(PWORD)pb; return TRUE;
        case VMM_EVENTLOG_VALUE_INT32:
        case VMM_EVENTLOG_VALUE_UINT32:
        case VMM_EVENTLOG_VALUE_BOOL:
        case VMM_EVENTLOG_VALUE_HEX32:
            if(cb < 4) { return FALSE; }
            *pqw = *(PDWORD)pb; return TRUE;
        case VMM_EVENTLOG_VALUE_INT64:
        case VMM_EVENTLOG_VALUE_UINT64:
        case VMM_EVENTLOG_VALUE_FILETIME:
        case VMM_EVENTLOG_VALUE_HEX64:
            if(cb < 8) { return FALSE; }
            *pqw = *(PQWORD)pb; return TRUE;
        case VMM_EVENTLOG_VALUE_SIZET:
            if(cb == 4) { *pqw = *(PDWORD)pb; return TRUE; }
            if(cb >= 8) { *pqw = *(PQWORD)pb; return TRUE; }
            return FALSE;
        default:
            return FALSE;
    }
}

static BOOL VmmEventLog_BinXml_Name(_In_ PVMM_EVENTLOG_BINXML_CONTEXT ctx, _In_ DWORD oName, _Out_ PDWORD pcbName, _Out_ LPSTR *puszName)
{
    DWORD cch, cbName;
    *pcbName = 0;
    *puszName = NULL;
    if((oName > ctx->cbChunk) || (ctx->cbChunk - oName < 10)) { return FALSE; }
    cch = *(PWORD)(ctx->pbChunk + oName + 6);
    if(cch > (ctx->cbChunk - oName - 10) / 2) { return FALSE; }
    cbName = 10 + cch * 2;
    if(*(PWORD)(ctx->pbChunk + oName + 8 + (SIZE_T)cch * 2)) { return FALSE; }
    if(!(*puszName = VmmEventLog_Parse_Utf16(ctx->pbChunk + oName + 8, cch * 2))) { return FALSE; }
    *pcbName = cbName;
    return TRUE;
}

static BOOL VmmEventLog_BinXml_TokenHasFlag(_In_ BYTE token, _In_ BYTE tokenBase)
{
    return (token == tokenBase) || (token == (tokenBase | 0x40));
}

static BOOL VmmEventLog_BinXml_FragmentHeader(_In_reads_bytes_(cb) PBYTE pb, _In_ DWORD cb, _In_ DWORD o)
{
    return (o <= cb) && (cb - o >= 4) &&
           (pb[o] == 0x0f) && (pb[o + 1] == 1) &&
           (pb[o + 2] == 1) && !pb[o + 3];
}

static BOOL VmmEventLog_BinXml_LiteralValue(
    _In_ PVMM_EVENTLOG_BINXML_CONTEXT ctx,
    _In_ DWORD o,
    _In_ DWORD oEnd,
    _Out_ PDWORD poNext,
    _Out_ PBYTE ptp,
    _Out_ PBYTE *ppb,
    _Out_ PDWORD pcb
)
{
    BYTE tp;
    DWORD cbValue, cch, oData;
    *poNext = 0;
    *ptp = 0;
    *ppb = NULL;
    *pcb = 0;
    if((o > oEnd) || (oEnd - o < 2) || !VmmEventLog_BinXml_TokenHasFlag(ctx->pbChunk[o], 0x05)) { return FALSE; }
    tp = ctx->pbChunk[o + 1];
    oData = o + 2;
    if(oData > oEnd) { return FALSE; }
    if(tp == VMM_EVENTLOG_VALUE_NULL) {
        *poNext = oData;
        *ptp = tp;
        return TRUE;
    }
    if((tp == VMM_EVENTLOG_VALUE_WSTRING) || (tp == VMM_EVENTLOG_VALUE_STRING)) {
        if(oEnd - oData < 2) { return FALSE; }
        cch = *(PWORD)(ctx->pbChunk + oData);
        oData += 2;
        cbValue = (tp == VMM_EVENTLOG_VALUE_WSTRING) ? cch * 2 : cch;
    } else if(tp == VMM_EVENTLOG_VALUE_BINARY) {
        if(oEnd - oData < 4) { return FALSE; }
        cbValue = *(PDWORD)(ctx->pbChunk + oData);
        oData += 4;
    } else if(tp & VMM_EVENTLOG_VALUE_ARRAY) {
        if(oEnd - oData < 2) { return FALSE; }
        cbValue = *(PWORD)(ctx->pbChunk + oData);
        oData += 2;
    } else if(tp == VMM_EVENTLOG_VALUE_SIZET) {
        cbValue = 8;
    } else if(tp == VMM_EVENTLOG_VALUE_SID) {
        if(oEnd - oData < 8) { return FALSE; }
        cbValue = 8 + (DWORD)ctx->pbChunk[oData + 1] * 4;
    } else {
        cbValue = VmmEventLog_Parse_ValueScalarSize(tp);
    }
    if(!cbValue || (oData > oEnd) || (cbValue > oEnd - oData)) { return FALSE; }
    *poNext = oData + cbValue;
    *ptp = tp;
    *ppb = ctx->pbChunk + oData;
    *pcb = cbValue;
    return TRUE;
}

_Success_(return)
static BOOL VmmEventLog_BinXml_ResolveValue(
    _In_ PVMM_EVENTLOG_BINXML_CONTEXT ctx,
    _In_ DWORD o,
    _In_ DWORD oEnd,
    _Out_ PDWORD poNext,
    _Out_ PBYTE ptp,
    _Out_ PBYTE *ppb,
    _Out_ PDWORD pcb,
    _Out_ PBOOL pfSuppress
)
{
    BYTE token;
    WORD iSub;
    PVMM_EVENTLOG_BINXML_SUBSTITUTION pSub;
    if(!poNext || !ptp || !ppb || !pcb || !pfSuppress) { return FALSE; }
    *poNext = 0;
    *ptp = 0;
    *ppb = NULL;
    *pcb = 0;
    *pfSuppress = FALSE;
    if(!ctx) { return FALSE; }
    if(o >= oEnd) { return FALSE; }
    token = ctx->pbChunk[o];
    if(VmmEventLog_BinXml_TokenHasFlag(token, 0x05)) {
        return VmmEventLog_BinXml_LiteralValue(ctx, o, oEnd, poNext, ptp, ppb, pcb);
    }
    if((token != 0x0d) && (token != 0x0e)) { return FALSE; }
    if(oEnd - o < 4) { return FALSE; }
    iSub = *(PWORD)(ctx->pbChunk + o + 1);
    if(iSub >= ctx->cSub) { return FALSE; }
    pSub = ctx->pSub + iSub;
    if((pSub->tp != ctx->pbChunk[o + 3]) &&
       !((token == 0x0e) && (pSub->tp == VMM_EVENTLOG_VALUE_NULL))) {
        return FALSE;
    }
    *poNext = o + 4;
    *ptp = pSub->tp;
    *ppb = pSub->pb;
    *pcb = pSub->cb;
    *pfSuppress = (token == 0x0e) && (pSub->tp == VMM_EVENTLOG_VALUE_NULL);
    return TRUE;
}

static BOOL VmmEventLog_BinXml_IsSystemPath(_In_ LPCSTR uszPath)
{
    static const CHAR szSystem[] = "/Event/System";
    SIZE_T cch = sizeof(szSystem) - 1;
    return !_strnicmp(uszPath, szSystem, cch) && (!uszPath[cch] || (uszPath[cch] == '/'));
}

static BOOL VmmEventLog_BinXml_ApplySystem(
    _Inout_ PVMM_EVENTLOG_PARSE_EVENT pEvent,
    _In_ LPCSTR uszPath,
    _In_opt_ LPCSTR uszAttribute,
    _In_ BYTE tp,
    _In_reads_bytes_opt_(cb) PBYTE pb,
    _In_ DWORD cb
)
{
    QWORD qw;
    LPSTR usz = NULL;
    if(!_stricmp(uszPath, "/Event/System/Provider")) {
        if(!uszAttribute) { return TRUE; }
        if(!(usz = VmmEventLog_Parse_ValueToString(tp, pb, cb))) { return FALSE; }
        if(!_stricmp(uszAttribute, "Name")) {
            if(!VmmEventLog_Parse_EventSetString(&pEvent->e.uszProvider, usz)) { LocalFree(usz); return FALSE; }
            pEvent->fProvider = pEvent->e.uszProvider[0] != 0;
        } else if(!_stricmp(uszAttribute, "Guid")) {
            if(!VmmEventLog_Parse_EventSetString(&pEvent->e.uszProviderGuid, usz)) { LocalFree(usz); return FALSE; }
        } else if(!_stricmp(uszAttribute, "EventSourceName")) {
            if(!VmmEventLog_Parse_EventSetString(&pEvent->e.uszEventSource, usz)) { LocalFree(usz); return FALSE; }
        }
        LocalFree(usz);
        return TRUE;
    }
    if(!_stricmp(uszPath, "/Event/System/EventID")) {
        if(!VmmEventLog_Parse_ValueAsQWORD(tp, pb, cb, &qw)) { return tp == VMM_EVENTLOG_VALUE_NULL; }
        if(uszAttribute && !_stricmp(uszAttribute, "Qualifiers")) { pEvent->e.dwQualifiers = (DWORD)qw; }
        else if(!uszAttribute) { pEvent->e.dwEventId = (DWORD)qw; pEvent->fEventId = TRUE; }
        return TRUE;
    }
    if(!_stricmp(uszPath, "/Event/System/Version") && !uszAttribute) {
        if(VmmEventLog_Parse_ValueAsQWORD(tp, pb, cb, &qw)) { pEvent->e.dwVersion = (DWORD)qw; }
        return TRUE;
    }
    if(!_stricmp(uszPath, "/Event/System/Level") && !uszAttribute) {
        if(VmmEventLog_Parse_ValueAsQWORD(tp, pb, cb, &qw)) { pEvent->e.dwLevel = (DWORD)qw; }
        return TRUE;
    }
    if(!_stricmp(uszPath, "/Event/System/Task") && !uszAttribute) {
        if(VmmEventLog_Parse_ValueAsQWORD(tp, pb, cb, &qw)) { pEvent->e.dwTask = (DWORD)qw; }
        return TRUE;
    }
    if(!_stricmp(uszPath, "/Event/System/Opcode") && !uszAttribute) {
        if(VmmEventLog_Parse_ValueAsQWORD(tp, pb, cb, &qw)) { pEvent->e.dwOpcode = (DWORD)qw; }
        return TRUE;
    }
    if(!_stricmp(uszPath, "/Event/System/Keywords") && !uszAttribute) {
        if(VmmEventLog_Parse_ValueAsQWORD(tp, pb, cb, &qw)) { pEvent->e.qwKeywords = qw; }
        return TRUE;
    }
    if(!_stricmp(uszPath, "/Event/System/TimeCreated") && uszAttribute && !_stricmp(uszAttribute, "SystemTime")) {
        if(VmmEventLog_Parse_ValueAsQWORD(tp, pb, cb, &qw)) {
            pEvent->e.ftTimeCreated = qw;
            pEvent->fTimeCreated = qw != 0;
        } else if((usz = VmmEventLog_Parse_ValueToString(tp, pb, cb))) {
            pEvent->e.ftTimeCreated = Util_TimeIso8601ToFileTime(usz);
            pEvent->fTimeCreated = pEvent->e.ftTimeCreated != 0;
            LocalFree(usz);
        }
        return TRUE;
    }
    if(!_stricmp(uszPath, "/Event/System/EventRecordID") && !uszAttribute) {
        if(VmmEventLog_Parse_ValueAsQWORD(tp, pb, cb, &qw)) { pEvent->e.qwRecordId = qw; pEvent->fRecordId = TRUE; }
        return TRUE;
    }
    if(!_stricmp(uszPath, "/Event/System/Execution") && uszAttribute) {
        if(VmmEventLog_Parse_ValueAsQWORD(tp, pb, cb, &qw)) {
            if(!_stricmp(uszAttribute, "ProcessID")) { pEvent->e.dwPID = (DWORD)qw; }
            if(!_stricmp(uszAttribute, "ThreadID")) { pEvent->e.dwTID = (DWORD)qw; }
        }
        return TRUE;
    }
    if(!_stricmp(uszPath, "/Event/System/Channel") && !uszAttribute) {
        if(!(usz = VmmEventLog_Parse_ValueToString(tp, pb, cb))) { return FALSE; }
        if(!VmmEventLog_Parse_EventSetString(&pEvent->e.uszChannel, usz)) { LocalFree(usz); return FALSE; }
        LocalFree(usz);
        return TRUE;
    }
    if(!_stricmp(uszPath, "/Event/System/Computer") && !uszAttribute) {
        if(!(usz = VmmEventLog_Parse_ValueToString(tp, pb, cb))) { return FALSE; }
        if(!VmmEventLog_Parse_EventSetString(&pEvent->e.uszComputer, usz)) { LocalFree(usz); return FALSE; }
        LocalFree(usz);
        return TRUE;
    }
    if(!_stricmp(uszPath, "/Event/System/Security") && uszAttribute && !_stricmp(uszAttribute, "UserID")) {
        if(!(usz = VmmEventLog_Parse_ValueToString(tp, pb, cb))) { return FALSE; }
        if(!VmmEventLog_Parse_EventSetString(&pEvent->e.uszUserSid, usz)) { LocalFree(usz); return FALSE; }
        LocalFree(usz);
        return TRUE;
    }
    if(!_stricmp(uszPath, "/Event/System/Correlation") && uszAttribute) {
        if(!(usz = VmmEventLog_Parse_ValueToString(tp, pb, cb))) { return FALSE; }
        if(!_stricmp(uszAttribute, "ActivityID")) {
            if(!VmmEventLog_Parse_EventSetString(&pEvent->e.uszActivityId, usz)) { LocalFree(usz); return FALSE; }
        } else if(!_stricmp(uszAttribute, "RelatedActivityID")) {
            if(!VmmEventLog_Parse_EventSetString(&pEvent->e.uszRelatedActivityId, usz)) { LocalFree(usz); return FALSE; }
        }
        LocalFree(usz);
        return TRUE;
    }
    return TRUE;
}

static BOOL VmmEventLog_BinXml_ParseRoot(
    _In_ PBYTE pbChunk,
    _In_ DWORD cbChunk,
    _In_ DWORD oRoot,
    _In_ DWORD cbRoot,
    _Inout_ PVMM_EVENTLOG_PARSE_EVENT pEvent,
    _In_ DWORD cDepth,
    _In_ BOOL fSystemEnvelope
);

static BOOL VmmEventLog_BinXml_ProcessValue(
    _In_ PVMM_EVENTLOG_BINXML_CONTEXT ctx,
    _In_ LPCSTR uszPath,
    _In_opt_ LPCSTR uszName,
    _In_opt_ LPCSTR uszAttribute,
    _In_ BYTE tp,
    _In_reads_bytes_opt_(cb) PBYTE pb,
    _In_ DWORD cb
)
{
    CHAR szAttribute[160];
    LPSTR usz;
    if(tp == VMM_EVENTLOG_VALUE_BINXML) {
        if(!pb || !cb || (pb < ctx->pbChunk) || ((SIZE_T)(pb - ctx->pbChunk) > ctx->cbChunk)) { return FALSE; }
        return VmmEventLog_BinXml_ParseRoot(
            ctx->pbChunk, ctx->cbChunk, (DWORD)(pb - ctx->pbChunk), cb,
            ctx->pEvent, ctx->cDepth + 1, FALSE
        );
    }
    if(ctx->fSystemEnvelope && VmmEventLog_BinXml_IsSystemPath(uszPath)) {
        return VmmEventLog_BinXml_ApplySystem(ctx->pEvent, uszPath, uszAttribute, tp, pb, cb);
    }
    if(uszAttribute) {
        if(!_stricmp(uszAttribute, "xmlns") || !_stricmp(uszAttribute, "Name")) { return TRUE; }
        _snprintf_s(szAttribute, sizeof(szAttribute), _TRUNCATE, "@%s", uszAttribute);
        uszName = szAttribute;
    }
    if(!(usz = VmmEventLog_Parse_ValueToString(tp, pb, cb))) { return FALSE; }
    return VmmEventLog_Parse_EventAddData(ctx->pEvent, tp, uszPath, uszName, usz);
}

static BOOL VmmEventLog_BinXml_ParseElement(_In_ PVMM_EVENTLOG_BINXML_CONTEXT ctx, _Inout_ PDWORD po, _In_ DWORD oEnd, _In_ LPCSTR uszParentPath)
{
    BYTE token, tokenAttribute, tp;
    BOOL fSuppress, fSystemPath;
    DWORD o = *po, oName, cbName, cbInline, oValue, cbValue;
    LPSTR uszElement = NULL, uszAttribute = NULL, uszValue = NULL;
    PBYTE pbValue;
    CHAR szPath[512], szDataName[160] = { 0 };
    if((ctx->cDepth >= VMM_EVENTLOG_BINXML_MAX_DEPTH) || (o > oEnd) || (oEnd - o < 11) || !VmmEventLog_BinXml_TokenHasFlag(ctx->pbChunk[o], 0x01)) { return FALSE; }
    token = ctx->pbChunk[o];
    oName = *(PDWORD)(ctx->pbChunk + o + 7);
    cbInline = 11;
    if(!VmmEventLog_BinXml_Name(ctx, oName, &cbName, &uszElement)) { return FALSE; }
    if(oName > o) {
        if(oName != o + 11) { goto fail; }
        cbInline += cbName;
    }
    if(token & 0x40) { cbInline += 4; }
    if((cbInline > oEnd - o) || (_snprintf_s(szPath, sizeof(szPath), _TRUNCATE, "%s/%s", uszParentPath, uszElement) < 0)) { goto fail; }
    if(ctx->fSystemEnvelope && !ctx->cDepth) {
        if(_stricmp(szPath, "/Event") || ctx->pEvent->fEvent) { goto fail; }
        ctx->pEvent->fEvent = TRUE;
    }
    fSystemPath = ctx->fSystemEnvelope && VmmEventLog_BinXml_IsSystemPath(szPath);
    if(ctx->fSystemEnvelope && !_stricmp(szPath, "/Event/System")) {
        if(ctx->pEvent->fSystem) { goto fail; }
        ctx->pEvent->fSystem = TRUE;
    }
    o += cbInline;
    if(((token == 0x41) ? TRUE : FALSE) != ((o < oEnd) && VmmEventLog_BinXml_TokenHasFlag(ctx->pbChunk[o], 0x06))) { goto fail; }
    while((o < oEnd) && VmmEventLog_BinXml_TokenHasFlag(ctx->pbChunk[o], 0x06)) {
        DWORD oAttribute = o;
        tokenAttribute = ctx->pbChunk[o];
        if(oEnd - o < 5) { goto fail; }
        oName = *(PDWORD)(ctx->pbChunk + o + 1);
        cbInline = 5;
        if(!VmmEventLog_BinXml_Name(ctx, oName, &cbName, &uszAttribute)) { goto fail; }
        if(oName > oAttribute) {
            if(oName != oAttribute + cbInline) { goto fail; }
            cbInline += cbName;
        }
        if(cbInline > oEnd - o) { goto fail; }
        o += cbInline;
        if(!VmmEventLog_BinXml_ResolveValue(ctx, o, oEnd, &oValue, &tp, &pbValue, &cbValue, &fSuppress)) { goto fail; }
        if(!fSuppress) {
            if(!_stricmp(uszAttribute, "Name") && !fSystemPath) {
                if(!(uszValue = VmmEventLog_Parse_ValueToString(tp, pbValue, cbValue))) { goto fail; }
                strncpy_s(szDataName, sizeof(szDataName), uszValue, _TRUNCATE);
                LocalFree(uszValue);
                uszValue = NULL;
            }
            if(!VmmEventLog_BinXml_ProcessValue(ctx, szPath, szDataName, uszAttribute, tp, pbValue, cbValue)) { goto fail; }
        }
        LocalFree(uszAttribute);
        uszAttribute = NULL;
        o = oValue;
        if(((tokenAttribute == 0x46) ? TRUE : FALSE) != ((o < oEnd) && VmmEventLog_BinXml_TokenHasFlag(ctx->pbChunk[o], 0x06))) { goto fail; }
    }
    if(o >= oEnd) { goto fail; }
    token = ctx->pbChunk[o];
    if(token == 0x03) {
        *po = o + 1;
        LocalFree(uszElement);
        return TRUE;
    }
    if(token != 0x02) { goto fail; }
    o++;
    while(o < oEnd) {
        token = ctx->pbChunk[o];
        if(VmmEventLog_BinXml_TokenHasFlag(token, 0x01)) {
            VMM_EVENTLOG_BINXML_CONTEXT ctxChild = *ctx;
            ctxChild.cDepth++;
            if(!VmmEventLog_BinXml_ParseElement(&ctxChild, &o, oEnd, szPath)) { goto fail; }
            continue;
        }
        if(token == 0x04) {
            *po = o + 1;
            LocalFree(uszElement);
            return TRUE;
        }
        if(VmmEventLog_BinXml_TokenHasFlag(token, 0x05) || (token == 0x0d) || (token == 0x0e)) {
            if(!VmmEventLog_BinXml_ResolveValue(ctx, o, oEnd, &oValue, &tp, &pbValue, &cbValue, &fSuppress)) { goto fail; }
            if(!fSuppress && !VmmEventLog_BinXml_ProcessValue(ctx, szPath, szDataName, NULL, tp, pbValue, cbValue)) { goto fail; }
            o = oValue;
            continue;
        }
        if(VmmEventLog_BinXml_TokenHasFlag(token, 0x07)) {
            if(oEnd - o < 3) { goto fail; }
            cbValue = (DWORD)*(PWORD)(ctx->pbChunk + o + 1) * 2;
            if(cbValue > oEnd - o - 3) { goto fail; }
            if(!(uszValue = VmmEventLog_Parse_Utf16(ctx->pbChunk + o + 3, cbValue))) { goto fail; }
            if(!fSystemPath && !VmmEventLog_Parse_EventAddData(ctx->pEvent, VMM_EVENTLOG_VALUE_WSTRING, szPath, szDataName, uszValue)) { uszValue = NULL; goto fail; }
            if(fSystemPath) { LocalFree(uszValue); }
            uszValue = NULL;
            o += 3 + cbValue;
            continue;
        }
        if(VmmEventLog_BinXml_TokenHasFlag(token, 0x08)) {
            if(oEnd - o < 3) { goto fail; }
            o += 3;
            continue;
        }
        if(VmmEventLog_BinXml_TokenHasFlag(token, 0x09) || (token == 0x0a)) {
            if(oEnd - o < 5) { goto fail; }
            oName = *(PDWORD)(ctx->pbChunk + o + 1);
            cbInline = 5;
            if(!VmmEventLog_BinXml_Name(ctx, oName, &cbName, &uszValue)) { goto fail; }
            if(oName > o) {
                if(oName != o + cbInline) { goto fail; }
                cbInline += cbName;
            }
            LocalFree(uszValue);
            uszValue = NULL;
            if(cbInline > oEnd - o) { goto fail; }
            o += cbInline;
            continue;
        }
        if(token == 0x0b) {
            if(oEnd - o < 3) { goto fail; }
            cbValue = (DWORD)*(PWORD)(ctx->pbChunk + o + 1) * 2;
            if(cbValue > oEnd - o - 3) { goto fail; }
            o += 3 + cbValue;
            continue;
        }
        goto fail;
    }
fail:
    LocalFree(uszElement);
    LocalFree(uszAttribute);
    LocalFree(uszValue);
    return FALSE;
}

static BOOL VmmEventLog_BinXml_ParseTemplate(_In_ PVMM_EVENTLOG_BINXML_CONTEXT ctx, _In_ DWORD oTemplate, _In_ DWORD cbTemplate)
{
    DWORD o = oTemplate, oEnd;
    BYTE token;
    if((oTemplate > ctx->cbChunk) || (cbTemplate > ctx->cbChunk - oTemplate)) { return FALSE; }
    oEnd = oTemplate + cbTemplate;
    while(o < oEnd) {
        token = ctx->pbChunk[o];
        if(token == 0x00) { return (o + 1 == oEnd); }
        if(token == 0x0f) {
            if(!VmmEventLog_BinXml_FragmentHeader(ctx->pbChunk, oEnd, o)) { return FALSE; }
            o += 4;
            continue;
        }
        if(!VmmEventLog_BinXml_TokenHasFlag(token, 0x01)) { return FALSE; }
        if(!VmmEventLog_BinXml_ParseElement(ctx, &o, oEnd, "")) { return FALSE; }
    }
    return FALSE;
}

static BOOL VmmEventLog_BinXml_ParseRoot(
    _In_ PBYTE pbChunk,
    _In_ DWORD cbChunk,
    _In_ DWORD oRoot,
    _In_ DWORD cbRoot,
    _Inout_ PVMM_EVENTLOG_PARSE_EVENT pEvent,
    _In_ DWORD cDepth,
    _In_ BOOL fSystemEnvelope
)
{
    BOOL fResult = FALSE, fResident;
    BYTE token;
    DWORD i, o, oEnd, oInstance, oTemplate, cbTemplateData, cbTemplate, oSub, cSub, oValue;
    PVMM_EVENTLOG_BINXML_SUBSTITUTION pSub = NULL;
    VMM_EVENTLOG_BINXML_CONTEXT ctx = { 0 };
    if((cDepth >= VMM_EVENTLOG_BINXML_MAX_DEPTH) || (oRoot > cbChunk) || (cbRoot > cbChunk - oRoot)) { return FALSE; }
    oEnd = oRoot + cbRoot;
    o = oRoot;
    if((o < oEnd) && (pbChunk[o] == 0x0f)) {
        if(!VmmEventLog_BinXml_FragmentHeader(pbChunk, oEnd, o)) { return FALSE; }
        o += 4;
    }
    if((oEnd - o < 10) || (pbChunk[o] != 0x0c)) { return FALSE; }
    oInstance = o;
    oTemplate = *(PDWORD)(pbChunk + o + 6);
    if((oTemplate > cbChunk) || (cbChunk - oTemplate < 24)) { return FALSE; }
    cbTemplateData = *(PDWORD)(pbChunk + oTemplate + 20);
    if(!cbTemplateData || (cbTemplateData > cbChunk - oTemplate - 24)) { return FALSE; }
    cbTemplate = 24 + cbTemplateData;
    fResident = oTemplate > oInstance;
    if(fResident && (oTemplate != oInstance + 10)) { return FALSE; }
    oSub = oInstance + 10 + (fResident ? cbTemplate : 0);
    if((oSub > oEnd) || (oEnd - oSub < 4)) { return FALSE; }
    cSub = *(PDWORD)(pbChunk + oSub);
    if((cSub > VMM_EVENTLOG_BINXML_MAX_SUBSTITUTIONS) || (cSub > (oEnd - oSub - 4) / 4)) { return FALSE; }
    if(cSub && !(pSub = LocalAlloc(LMEM_ZEROINIT, (SIZE_T)cSub * sizeof(VMM_EVENTLOG_BINXML_SUBSTITUTION)))) { return FALSE; }
    oValue = oSub + 4 + cSub * 4;
    for(i = 0; i < cSub; i++) {
        pSub[i].cb = *(PWORD)(pbChunk + (SIZE_T)oSub + 4 + (SIZE_T)i * 4);
        pSub[i].tp = pbChunk[(SIZE_T)oSub + 6 + (SIZE_T)i * 4];
        if(pbChunk[(SIZE_T)oSub + 7 + (SIZE_T)i * 4]) { goto finish; }
        if((oValue > oEnd) || (pSub[i].cb > oEnd - oValue)) { goto finish; }
        pSub[i].pb = pbChunk + oValue;
        oValue += pSub[i].cb;
    }
    // EVTX writers may leave up to one alignment unit of unspecified bytes
    // between the BinXML stream and the trailing record size.
    if(oEnd - oValue > 8) { goto finish; }
    ctx.pbChunk = pbChunk;
    ctx.cbChunk = cbChunk;
    ctx.pSub = pSub;
    ctx.cSub = cSub;
    ctx.pEvent = pEvent;
    ctx.cDepth = cDepth;
    ctx.fSystemEnvelope = fSystemEnvelope;
    token = pbChunk[oTemplate + 24];
    if(!VmmEventLog_BinXml_TokenHasFlag(token, 0x01) && (token != 0x0f)) { goto finish; }
    fResult = VmmEventLog_BinXml_ParseTemplate(&ctx, oTemplate + 24, cbTemplateData);
finish:
    LocalFree(pSub);
    return fResult;
}

#define VMM_EVENTLOG_TEXT_HEADER "Time                    Record ID    Event ID Level PID      Provider :: Payload"

static BOOL VmmEventLog_Parse_StrBufAddFormat(_Inout_ PVMM_EVENTLOG_STRBUF p, _In_z_ _Printf_format_string_ LPCSTR uszFormat, ...)
{
    BOOL fResult;
    CHAR sz[1024];
    va_list arglist;
    va_start(arglist, uszFormat);
    _vsnprintf_s(sz, sizeof(sz), _TRUNCATE, uszFormat, arglist);
    va_end(arglist);
    fResult = VmmEventLog_Parse_StrBufAdd(p, sz, TRUE);
    return fResult;
}

/*
* Build compact payload and investigator-oriented text for one parsed record.
*/
static BOOL VmmEventLog_Parse_RecordBuildText(_Inout_ PVMM_EVENTLOG_PARSE_EVENT pEvent)
{
    BOOL f;
    DWORD i;
    QWORD ft = pEvent->e.ftTimeCreated ? pEvent->e.ftTimeCreated : pEvent->e.ftRecord;
    CHAR szTime[24];
    VMM_EVENTLOG_STRBUF sbPayload = { 0 }, sbText = { 0 };
    sbPayload.cchLimit = VMM_EVENTLOG_PAYLOAD_MAX;
    sbText.cchLimit = VMM_EVENTLOG_TEXT_MAX;
    for(i = 0; i < pEvent->cData; i++) {
        if(i && !VmmEventLog_Parse_StrBufAdd(&sbPayload, "; ", FALSE)) { goto fail; }
        f = VmmEventLog_Parse_StrBufAdd(&sbPayload, pEvent->pData[i].uszName, TRUE) &&
            VmmEventLog_Parse_StrBufAdd(&sbPayload, "=", FALSE) &&
            VmmEventLog_Parse_StrBufAdd(&sbPayload, pEvent->pData[i].uszValue, TRUE);
        if(!f) { goto fail; }
    }
    if(!(pEvent->e.uszPayload = VmmEventLog_Parse_StrBufTake(&sbPayload))) { goto fail; }
    Util_FileTime2String(ft, szTime);
    f = VmmEventLog_Parse_StrBufAddFormat(
        &sbText,
        "%s %12llu %8u %5u %8u %-32s ",
        szTime,
        pEvent->e.qwRecordId,
        pEvent->e.dwEventId,
        pEvent->e.dwLevel,
        pEvent->e.dwPID,
        pEvent->e.uszProvider ? pEvent->e.uszProvider : "");
    if(!f) { goto fail; }
    if((pEvent->e.dwFlags & (VMM_EVENTLOG_ENTRY_FLAG_CHUNK_HEADER_CRC | VMM_EVENTLOG_ENTRY_FLAG_CHUNK_DATA_CRC)) != (VMM_EVENTLOG_ENTRY_FLAG_CHUNK_HEADER_CRC | VMM_EVENTLOG_ENTRY_FLAG_CHUNK_DATA_CRC)) {
        f = VmmEventLog_Parse_StrBufAddFormat(
            &sbText,
            "[chunk-crc:%s/%s] ",
            (pEvent->e.dwFlags & VMM_EVENTLOG_ENTRY_FLAG_CHUNK_HEADER_CRC) ? "header-ok" : "header-bad",
            (pEvent->e.dwFlags & VMM_EVENTLOG_ENTRY_FLAG_CHUNK_DATA_CRC) ? "data-ok" : "data-bad");
        if(!f) { goto fail; }
    }
    f = VmmEventLog_Parse_StrBufAdd(&sbText, ":: ", FALSE) &&
        VmmEventLog_Parse_StrBufAdd(&sbText, pEvent->e.uszPayload, TRUE);
    if(!f) { goto fail; }
    if(!(pEvent->e.uszText = VmmEventLog_Parse_StrBufTake(&sbText))) { goto fail; }
    return TRUE;
fail:
    LocalFree(sbPayload.usz);
    LocalFree(sbText.usz);
    return FALSE;
}

/*
* Approximate retained parser memory before transferring an event to the map.
* Provider-data strings are tracked as they are added; the remaining strings
* are bounded renderings created while parsing this one 64KiB record.
*/
static QWORD VmmEventLog_Parse_EventSize(_In_ PVMM_EVENTLOG_PARSE_EVENT pEvent)
{
    QWORD cb = sizeof(VMM_EVENTLOG_PARSE_EVENT) + (QWORD)pEvent->cDataMax * sizeof(VMM_EVENTLOG_PARSE_DATA) + pEvent->cbDataText;
    cb += pEvent->e.uszProvider ? strlen(pEvent->e.uszProvider) + 1 : 0;
    cb += pEvent->e.uszProviderGuid ? strlen(pEvent->e.uszProviderGuid) + 1 : 0;
    cb += pEvent->e.uszEventSource ? strlen(pEvent->e.uszEventSource) + 1 : 0;
    cb += pEvent->e.uszChannel ? strlen(pEvent->e.uszChannel) + 1 : 0;
    cb += pEvent->e.uszComputer ? strlen(pEvent->e.uszComputer) + 1 : 0;
    cb += pEvent->e.uszUserSid ? strlen(pEvent->e.uszUserSid) + 1 : 0;
    cb += pEvent->e.uszActivityId ? strlen(pEvent->e.uszActivityId) + 1 : 0;
    cb += pEvent->e.uszRelatedActivityId ? strlen(pEvent->e.uszRelatedActivityId) + 1 : 0;
    cb += pEvent->e.uszPayload ? strlen(pEvent->e.uszPayload) + 1 : 0;
    cb += pEvent->e.uszText ? strlen(pEvent->e.uszText) + 1 : 0;
    return cb;
}

/*
* Parse a completely framed record. The BinXML parser must consume and validate
* the complete template/substitution stream and find the standard Event/System
* envelope before the record is accepted.
*/
static BOOL VmmEventLog_Parse_Record(
    _In_reads_(VMM_EVENTLOG_CHUNK_SIZE) PBYTE pbChunk,
    _In_ DWORD oRecord,
    _In_ DWORD cbRecord,
    _In_ QWORD cbChunkFileOffset,
    _In_ DWORD dwFlags,
    _Out_ PVMM_EVENTLOG_PARSE_EVENT pEvent
)
{
    BOOL f;
    QWORD qwRecordIdHeader;
    ZeroMemory(pEvent, sizeof(VMM_EVENTLOG_PARSE_EVENT));
    qwRecordIdHeader = *(PQWORD)(pbChunk + oRecord + 8);
    pEvent->e.qwRecordId = qwRecordIdHeader;
    pEvent->e.ftRecord = *(PQWORD)(pbChunk + oRecord + 16);
    pEvent->e.cbOffset = cbChunkFileOffset + oRecord;
    pEvent->e.dwFlags = dwFlags;
    f = !VmmEventLog_BinXml_ParseRoot(pbChunk, VMM_EVENTLOG_CHUNK_SIZE, oRecord + 24, cbRecord - 28, pEvent, 0, TRUE);
    f = f || !pEvent->fEvent || !pEvent->fSystem || !pEvent->fProvider || !pEvent->fEventId || !pEvent->fTimeCreated || !pEvent->fRecordId;
    f = f || (pEvent->e.qwRecordId != qwRecordIdHeader);
    if(f) {
        VmmEventLog_Parse_EventCleanup(pEvent);
        return FALSE;
    }
    if(!VmmEventLog_Parse_RecordBuildText(pEvent)) {
        VmmEventLog_Parse_EventCleanup(pEvent);
        return FALSE;
    }
    return TRUE;
}

/*
* Scan one event log. Chunk CRC failures are provenance, not an automatic
* rejection: each independently framed record is still parsed fail-closed.
*/
static BOOL VmmEventLog_Parse_Scan(_In_ VMM_HANDLE H, _In_ PVMM_MAP_EVENTLOG_ENUMENTRY pe, _Inout_ PVMM_EVENTLOG_PARSE_MAP pMap)
{
    BOOL fChunkSignature, fHeaderValid, fDataValid, fFreeValid;
    DWORD i, cSlot, cbRead, oRecord, oScanEnd, oFree, cbRecord, dwFlags;
    QWORD cSlot64, cbChunkFileOffset, cbEvent;
    PBYTE pbChunk = NULL;
    NTSTATUS nt;
    VMM_EVENTLOG_PARSE_EVENT Event = { 0 };
    if(pe->cbFile <= VMM_EVENTLOG_FILE_HEADER_SIZE) { return TRUE; }
    cSlot64 = (pe->cbFile - VMM_EVENTLOG_FILE_HEADER_SIZE) / VMM_EVENTLOG_CHUNK_SIZE;
    if(cSlot64 > VMM_EVENTLOG_PROCESS_MAX_CHUNKS) { return FALSE; }
    cSlot = (DWORD)cSlot64;
    pMap->cChunk = cSlot;
    if(cSlot && !(pbChunk = LocalAlloc(0, VMM_EVENTLOG_CHUNK_SIZE))) { return FALSE; }
    for(i = 0; (i < cSlot) && !H->fAbort; i++) {
        cbChunkFileOffset = VMM_EVENTLOG_FILE_HEADER_SIZE + (QWORD)i * VMM_EVENTLOG_CHUNK_SIZE;
        nt = VmmEventLog_Read(H, pe, pbChunk, VMM_EVENTLOG_CHUNK_SIZE, &cbRead, cbChunkFileOffset);
        if((nt != VMM_STATUS_SUCCESS) || (cbRead != VMM_EVENTLOG_CHUNK_SIZE)) { continue; }
        fChunkSignature = !memcmp(pbChunk, "ElfChnk\0", 8);
        oFree = *(PDWORD)(pbChunk + 48);
        fFreeValid = (oFree >= VMM_EVENTLOG_CHUNK_HEADER_SIZE) && (oFree <= VMM_EVENTLOG_CHUNK_SIZE);
        fHeaderValid = fChunkSignature && (*(PDWORD)(pbChunk + 124) == VmmEventLog_ChunkHeaderCrc32(pbChunk));
        fDataValid = fChunkSignature && fFreeValid && (*(PDWORD)(pbChunk + 52) == VmmEventLog_Crc32(pbChunk + VMM_EVENTLOG_CHUNK_HEADER_SIZE, oFree - VMM_EVENTLOG_CHUNK_HEADER_SIZE));
        if(fHeaderValid) { pMap->cChunkHeaderValid++; }
        if(fDataValid) { pMap->cChunkDataValid++; }
        dwFlags = (fHeaderValid ? VMM_EVENTLOG_ENTRY_FLAG_CHUNK_HEADER_CRC : 0) | (fDataValid ? VMM_EVENTLOG_ENTRY_FLAG_CHUNK_DATA_CRC : 0);
        // A valid header authenticates oFree. Otherwise scan the full slot so
        // intact records following a damaged header/free-space field survive.
        oScanEnd = (fHeaderValid && fFreeValid) ? oFree : VMM_EVENTLOG_CHUNK_SIZE;
        oRecord = VMM_EVENTLOG_CHUNK_HEADER_SIZE;
        while(oRecord + 28 <= oScanEnd) {
            if(*(PDWORD)(pbChunk + oRecord) != VMM_EVENTLOG_RECORD_SIGNATURE) {
                oRecord += 4;
                continue;
            }
            if(pMap->cRecordCandidate != 0xffffffffU) { pMap->cRecordCandidate++; }
            cbRecord = *(PDWORD)(pbChunk + oRecord + 4);
            if((cbRecord < 28) || (cbRecord > oScanEnd - oRecord) || (*(PDWORD)(pbChunk + oRecord + cbRecord - 4) != cbRecord)) {
                if(pMap->cRecordSkipped != 0xffffffffU) { pMap->cRecordSkipped++; }
                oRecord += 4;
                continue;
            }
            if(pMap->cEvent >= VMM_EVENTLOG_PARSE_MAX_EVENTS) {
                LocalFree(pbChunk);
                return TRUE;
            }
            if(VmmEventLog_Parse_Record(pbChunk, oRecord, cbRecord, cbChunkFileOffset, dwFlags, &Event)) {
                cbEvent = VmmEventLog_Parse_EventSize(&Event);
                if(cbEvent > VMM_EVENTLOG_PARSE_MAX_MAP_BYTES - min(pMap->cbEvent, VMM_EVENTLOG_PARSE_MAX_MAP_BYTES)) {
                    VmmEventLog_Parse_EventCleanup(&Event);
                    LocalFree(pbChunk);
                    return TRUE;
                }
                if(!VmmEventLog_Parse_MapAddEvent(pMap, &Event)) {
                    VmmEventLog_Parse_EventCleanup(&Event);
                    LocalFree(pbChunk);
                    return FALSE;
                }
                pMap->cbEvent += cbEvent;
            } else if(pMap->cRecordSkipped != 0xffffffffU) {
                pMap->cRecordSkipped++;
            }
            oRecord += cbRecord;
        }
    }
    LocalFree(pbChunk);
    return !H->fAbort;
}

static VOID VmmEventLog_Parse_CleanupCB(_In_ PVMMOB_MAP_EVENTLOG pObEventMap)
{
    LocalFree(pObEventMap->pbMultiText);
}

static int VmmEventLog_Parse_EventCmpSort(_In_ PVMM_EVENTLOG_PARSE_EVENT a, _In_ PVMM_EVENTLOG_PARSE_EVENT b)
{
    QWORD ftA = a->e.ftTimeCreated ? a->e.ftTimeCreated : a->e.ftRecord;
    QWORD ftB = b->e.ftTimeCreated ? b->e.ftTimeCreated : b->e.ftRecord;
    if((ftA != 0) != (ftB != 0)) { return ftA ? -1 : 1; }
    if(ftA < ftB) { return -1; }
    if(ftA > ftB) { return 1; }
    if(a->e.qwRecordId < b->e.qwRecordId) { return -1; }
    if(a->e.qwRecordId > b->e.qwRecordId) { return 1; }
    if(a->e.cbOffset < b->e.cbOffset) { return -1; }
    if(a->e.cbOffset > b->e.cbOffset) { return 1; }
    return 0;
}

/*
* Parsed EVTX strings are copied linearly instead of being keyed only by the
* non-cryptographic CharUtil hash. This avoids both hash-collision substitution
* and the quadratic destination-list behavior of ObStrMap for common values.
*/
static BOOL VmmEventLog_Parse_StringSizeAdd(_In_opt_ LPCSTR usz, _Inout_ PQWORD pcb)
{
    QWORD cbString = usz ? (QWORD)strlen(usz) + 1 : 1;
    if(cbString > VMM_EVENTLOG_PARSE_MAX_MAP_BYTES - min(*pcb, VMM_EVENTLOG_PARSE_MAX_MAP_BYTES)) { return FALSE; }
    *pcb += cbString;
    return TRUE;
}

static LPSTR VmmEventLog_Parse_StringCopy(_Out_writes_bytes_(cbMultiText) PBYTE pbMultiText, _In_ DWORD cbMultiText, _Inout_ PDWORD poMultiText, _In_opt_ LPCSTR usz)
{
    DWORD cbString;
    LPSTR uszDst;
    if(!usz) { usz = ""; }
    cbString = (DWORD)strlen(usz) + 1;
    if((*poMultiText > cbMultiText) || (cbString > cbMultiText - *poMultiText)) { return NULL; }
    uszDst = (LPSTR)pbMultiText + *poMultiText;
    memcpy(uszDst, usz, cbString);
    *poMultiText += cbString;
    return uszDst;
}

static BOOL VmmEventLog_Parse_EventStringSizeAdd(_In_ PVMM_MAP_EVENTLOG_ENTRY pe, _Inout_ PQWORD pcb)
{
    return
        VmmEventLog_Parse_StringSizeAdd(pe->uszProvider, pcb) &&
        VmmEventLog_Parse_StringSizeAdd(pe->uszProviderGuid, pcb) &&
        VmmEventLog_Parse_StringSizeAdd(pe->uszEventSource, pcb) &&
        VmmEventLog_Parse_StringSizeAdd(pe->uszChannel, pcb) &&
        VmmEventLog_Parse_StringSizeAdd(pe->uszComputer, pcb) &&
        VmmEventLog_Parse_StringSizeAdd(pe->uszUserSid, pcb) &&
        VmmEventLog_Parse_StringSizeAdd(pe->uszActivityId, pcb) &&
        VmmEventLog_Parse_StringSizeAdd(pe->uszRelatedActivityId, pcb) &&
        VmmEventLog_Parse_StringSizeAdd(pe->uszPayload, pcb) &&
        VmmEventLog_Parse_StringSizeAdd(pe->uszText, pcb);
}

static BOOL VmmEventLog_Parse_EventStringCopy(_Out_writes_bytes_(cbMultiText) PBYTE pbMultiText, _In_ DWORD cbMultiText, _Inout_ PDWORD poMultiText, _In_ PVMM_MAP_EVENTLOG_ENTRY peSrc, _Inout_ PVMM_MAP_EVENTLOG_ENTRY peDst)
{
    return
        (peDst->uszProvider = VmmEventLog_Parse_StringCopy(pbMultiText, cbMultiText, poMultiText, peSrc->uszProvider)) &&
        (peDst->uszProviderGuid = VmmEventLog_Parse_StringCopy(pbMultiText, cbMultiText, poMultiText, peSrc->uszProviderGuid)) &&
        (peDst->uszEventSource = VmmEventLog_Parse_StringCopy(pbMultiText, cbMultiText, poMultiText, peSrc->uszEventSource)) &&
        (peDst->uszChannel = VmmEventLog_Parse_StringCopy(pbMultiText, cbMultiText, poMultiText, peSrc->uszChannel)) &&
        (peDst->uszComputer = VmmEventLog_Parse_StringCopy(pbMultiText, cbMultiText, poMultiText, peSrc->uszComputer)) &&
        (peDst->uszUserSid = VmmEventLog_Parse_StringCopy(pbMultiText, cbMultiText, poMultiText, peSrc->uszUserSid)) &&
        (peDst->uszActivityId = VmmEventLog_Parse_StringCopy(pbMultiText, cbMultiText, poMultiText, peSrc->uszActivityId)) &&
        (peDst->uszRelatedActivityId = VmmEventLog_Parse_StringCopy(pbMultiText, cbMultiText, poMultiText, peSrc->uszRelatedActivityId)) &&
        (peDst->uszPayload = VmmEventLog_Parse_StringCopy(pbMultiText, cbMultiText, poMultiText, peSrc->uszPayload)) &&
        (peDst->uszText = VmmEventLog_Parse_StringCopy(pbMultiText, cbMultiText, poMultiText, peSrc->uszText));
}

/*
* Convert temporary parser allocations into the ordinary immutable VMM map
* layout and one shared string allocation.
* CALLER DECREF: return
*/
static PVMMOB_MAP_EVENTLOG VmmEventLog_Parse_Finalize(_In_ VMM_HANDLE H, _In_ PVMM_MAP_EVENTLOG_ENUMENTRY peLog, _In_ PVMM_EVENTLOG_PARSE_MAP pTemp)
{
    BOOL f;
    DWORD i, j, iData = 0, cData = 0, cbLineOffset = 0, cbLine, oMultiText = 0;
    QWORD ft, cbMultiText = 0;
    SIZE_T cbMap = sizeof(VMMOB_MAP_EVENTLOG);
    PVMMOB_MAP_EVENTLOG pObEventMap = NULL;
    PVMM_MAP_EVENTLOG_ENTRY peSrc, peDst;
    PVMM_EVENTLOG_PARSE_DATA peDataSrc;
    PVMM_MAP_EVENTLOG_DATAENTRY peDataDst;
    if(pTemp->cEvent > (((SIZE_T)-1) - cbMap) / sizeof(VMM_MAP_EVENTLOG_ENTRY)) { return NULL; }
    cbMap += (SIZE_T)pTemp->cEvent * sizeof(VMM_MAP_EVENTLOG_ENTRY);
    if(!VmmEventLog_Parse_StringSizeAdd(peLog->uszName, &cbMultiText) || !VmmEventLog_Parse_StringSizeAdd(peLog->uszPath, &cbMultiText)) {
        return NULL;
    }
    for(i = 0; i < pTemp->cEvent; i++) {
        if(pTemp->pEvent[i].cData > 0xffffffffU - cData) { return NULL; }
        cData += pTemp->pEvent[i].cData;
        if(!VmmEventLog_Parse_EventStringSizeAdd(&pTemp->pEvent[i].e, &cbMultiText)) { return NULL; }
        for(j = 0; j < pTemp->pEvent[i].cData; j++) {
            peDataSrc = pTemp->pEvent[i].pData + j;
            f = VmmEventLog_Parse_StringSizeAdd(peDataSrc->uszPath, &cbMultiText) &&
                VmmEventLog_Parse_StringSizeAdd(peDataSrc->uszName, &cbMultiText) &&
                VmmEventLog_Parse_StringSizeAdd(peDataSrc->uszValue, &cbMultiText);
            if(!f) { return NULL; }
        }
    }
    if(cData > (((SIZE_T)-1) - cbMap) / sizeof(VMM_MAP_EVENTLOG_DATAENTRY)) { return NULL; }
    cbMap += (SIZE_T)cData * sizeof(VMM_MAP_EVENTLOG_DATAENTRY);
    if(pTemp->cEvent > (((SIZE_T)-1) - cbMap) / sizeof(DWORD)) { return NULL; }
    cbMap += (SIZE_T)pTemp->cEvent * sizeof(DWORD);
    if(!cbMultiText || (cbMultiText > 0xffffffffULL)) { goto fail; }
    if(!(pObEventMap = Ob_AllocEx(H, OB_TAG_MAP_EVENTLOG_PARSED, LMEM_ZEROINIT, cbMap, (OB_CLEANUP_CB)VmmEventLog_Parse_CleanupCB, NULL))) { goto fail; }
    pObEventMap->cbMultiText = (DWORD)cbMultiText;
    if(!(pObEventMap->pbMultiText = LocalAlloc(0, pObEventMap->cbMultiText))) { goto fail; }
    pObEventMap->cMap = pTemp->cEvent;
    pObEventMap->cData = cData;
    pObEventMap->pData = (PVMM_MAP_EVENTLOG_DATAENTRY)(pObEventMap->pMap + pTemp->cEvent);
    pObEventMap->pdwLineOffset = (PDWORD)(pObEventMap->pData + cData);
    pObEventMap->cChunk = pTemp->cChunk;
    pObEventMap->cChunkHeaderValid = pTemp->cChunkHeaderValid;
    pObEventMap->cChunkDataValid = pTemp->cChunkDataValid;
    pObEventMap->cRecordCandidate = pTemp->cRecordCandidate;
    pObEventMap->cRecordParsed = pTemp->cEvent;
    pObEventMap->cRecordSkipped = pTemp->cRecordSkipped;
    pObEventMap->uszLogName = VmmEventLog_Parse_StringCopy(pObEventMap->pbMultiText, pObEventMap->cbMultiText, &oMultiText, peLog->uszName);
    pObEventMap->uszLogPath = VmmEventLog_Parse_StringCopy(pObEventMap->pbMultiText, pObEventMap->cbMultiText, &oMultiText, peLog->uszPath);
    if(!pObEventMap->uszLogName || !pObEventMap->uszLogPath) {
        goto fail;
    }
    for(i = 0; i < pTemp->cEvent; i++) {
        peSrc = &pTemp->pEvent[i].e;
        peDst = pObEventMap->pMap + i;
        memcpy(peDst, peSrc, sizeof(VMM_MAP_EVENTLOG_ENTRY));
        peDst->iData = iData;
        peDst->cData = pTemp->pEvent[i].cData;
        if(!VmmEventLog_Parse_EventStringCopy(pObEventMap->pbMultiText, pObEventMap->cbMultiText, &oMultiText, peSrc, peDst)) {
            goto fail;
        }
        cbLine = (DWORD)strlen(peSrc->uszText) + 1;
        if(cbLine > 0xffffffffU - cbLineOffset) { goto fail; }
        cbLineOffset += cbLine;
        pObEventMap->pdwLineOffset[i] = cbLineOffset;
        ft = peDst->ftTimeCreated ? peDst->ftTimeCreated : peDst->ftRecord;
        if(ft && (!pObEventMap->ftMin || (ft < pObEventMap->ftMin))) { pObEventMap->ftMin = ft; }
        if(ft > pObEventMap->ftMax) { pObEventMap->ftMax = ft; }
        for(j = 0; j < pTemp->pEvent[i].cData; j++, iData++) {
            peDataDst = pObEventMap->pData + iData;
            peDataDst->iEvent = i;
            peDataDst->iOrdinal = j;
            peDataSrc = pTemp->pEvent[i].pData + j;
            peDataDst->tp = peDataSrc->tp;
            peDataDst->uszPath = VmmEventLog_Parse_StringCopy(pObEventMap->pbMultiText, pObEventMap->cbMultiText, &oMultiText, peDataSrc->uszPath);
            peDataDst->uszName = VmmEventLog_Parse_StringCopy(pObEventMap->pbMultiText, pObEventMap->cbMultiText, &oMultiText, peDataSrc->uszName);
            peDataDst->uszValue = VmmEventLog_Parse_StringCopy(pObEventMap->pbMultiText, pObEventMap->cbMultiText, &oMultiText, peDataSrc->uszValue);
            if(!peDataDst->uszPath || !peDataDst->uszName || !peDataDst->uszValue) {
                goto fail;
            }
        }
    }
    pObEventMap->cbText = cbLineOffset;
    if(oMultiText != pObEventMap->cbMultiText) { goto fail; }
    return pObEventMap;
fail:
    Ob_DECREF(pObEventMap);
    return NULL;
}

/*
* Locked worker function creating one lazily cached parsed log map.
* CALLER DECREF: return
*/
static PVMMOB_MAP_EVENTLOG VmmEventLog_Parse_DoWork(_In_ VMM_HANDLE H, _In_ PVMM_MAP_EVENTLOG_ENUMENTRY pe)
{
    VMM_EVENTLOG_PARSE_MAP Temp = { 0 };
    PVMMOB_MAP_EVENTLOG pObEventMap = NULL;
    if(VmmEventLog_Parse_Scan(H, pe, &Temp)) {
        if(Temp.cEvent > 1) {
            qsort(Temp.pEvent, Temp.cEvent, sizeof(VMM_EVENTLOG_PARSE_EVENT), (int(*)(void const *, void const *))VmmEventLog_Parse_EventCmpSort);
        }
        pObEventMap = VmmEventLog_Parse_Finalize(H, pe, &Temp);
    }
    VmmEventLog_Parse_MapCleanup(&Temp);
    return pObEventMap;
}

_Success_(return)
static BOOL VmmEventLog_Parse(_In_ VMM_HANDLE H, _In_ PVMMOB_MAP_EVENTLOG_ENUM pEventEnumMap, _In_ PVMM_MAP_EVENTLOG_ENUMENTRY pe, _Out_ PVMMOB_MAP_EVENTLOG *ppObEventMap)
{
    PBYTE pbEntry, pbMap, pbMapEnd;
    POB_CONTAINER pObContainer;
    PVMMOB_MAP_EVENTLOG pObEventMap;
    *ppObEventMap = NULL;
    if(!pEventEnumMap || !pe) { return FALSE; }
    pbEntry = (PBYTE)pe;
    pbMap = (PBYTE)pEventEnumMap->pMap;
    pbMapEnd = pbMap + (SIZE_T)pEventEnumMap->cMap * sizeof(VMM_MAP_EVENTLOG_ENUMENTRY);
    if((pbEntry < pbMap) || (pbEntry >= pbMapEnd) || ((SIZE_T)(pbEntry - pbMap) % sizeof(VMM_MAP_EVENTLOG_ENUMENTRY)) || !(pObContainer = (POB_CONTAINER)pe->_pObCParsed)) {
        return FALSE;
    }
    if((pObEventMap = ObContainer_GetOb(pObContainer))) {
        *ppObEventMap = pObEventMap;
        return TRUE;
    }
    EnterCriticalSection(&H->vmm.LockUpdateMap);
    if(!(pObEventMap = ObContainer_GetOb(pObContainer))) {
        pObEventMap = VmmEventLog_Parse_DoWork(H, pe);
        if(pObEventMap) { ObContainer_SetOb(pObContainer, pObEventMap); }
    }
    LeaveCriticalSection(&H->vmm.LockUpdateMap);
    *ppObEventMap = pObEventMap;
    return pObEventMap != NULL;
}

static VOID VmmEventLog_Parse_ReadLineCB(_In_ VMM_HANDLE H, _Inout_opt_ PVOID ctx, _In_ DWORD cbLL, _In_ DWORD ie, _In_ PVMM_MAP_EVENTLOG_ENTRY pe, _Out_writes_(cbLL + 1) LPSTR usz)
{
    Util_usnprintf_ln(usz, cbLL, "%s", pe->uszText);
}

static QWORD VmmEventLog_Parse_TextSize(_In_ VMM_HANDLE H, _In_ PVMMOB_MAP_EVENTLOG pEventMap)
{
    if(!pEventMap) { return 0; }
    return pEventMap->cbText + (H->cfg.fFileInfoHeader ? 2 * strlen(VMM_EVENTLOG_TEXT_HEADER) + 2 : 0ULL);
}

static NTSTATUS VmmEventLog_Parse_ReadText(_In_ VMM_HANDLE H, _In_ PVMMOB_MAP_EVENTLOG pEventMap, _Out_writes_to_(cb, *pcbRead) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset)
{
    if(!pEventMap || !pb || !pcbRead) { return VMM_STATUS_FILE_INVALID; }
    return Util_VfsLineVariable_Read(
        H,
        (UTIL_VFSLINEFIXED_PFN_CB)VmmEventLog_Parse_ReadLineCB,
        pEventMap,
        VMM_EVENTLOG_TEXT_HEADER,
        pEventMap->pMap,
        pEventMap->cMap,
        sizeof(VMM_MAP_EVENTLOG_ENTRY),
        pEventMap->pdwLineOffset,
        pb,
        cb,
        pcbRead,
        cbOffset
    );
}

// ============================================================================
// EVTX REPAIR AND RECOVERY
// ============================================================================

/*
* Object cleanup callback for the lazily created repair map.
*/
static VOID VmmEventLog_Repair_CleanupCB(_In_ PVMMOB_MAP_EVENTLOG_REPAIR pObRepairMap)
{
    DWORD i;
    PVMM_MAP_EVENTLOG_REPAIRENTRY pe;
    if(!pObRepairMap) { return; }
    for(i = 0; i < pObRepairMap->cMap; i++) {
        pe = pObRepairMap->pMap + i;
        if(pe->_pbHeader) { LocalFree(pe->_pbHeader); }
        if(pe->_pqwChunkOffset) { LocalFree(pe->_pqwChunkOffset); }
    }
}

/*
* Test whether an EVTX file header is structurally valid.
*/
static BOOL VmmEventLog_Repair_FileHeaderIsValid(_In_reads_(VMM_EVENTLOG_FILE_HEADER_SIZE) PBYTE pb)
{
    return !memcmp(pb, "ElfFile\0", 8) &&
        (*(PDWORD)(pb + 32) == 128) &&
        (*(PWORD)(pb + 40) == VMM_EVENTLOG_FILE_HEADER_SIZE) &&
        (*(PDWORD)(pb + 124) == VmmEventLog_Crc32(pb, 120));
}

/*
* Test whether all bytes in a range are zero.
*/
static BOOL VmmEventLog_Repair_IsZero(_In_reads_(cb) PBYTE pb, _In_ DWORD cb)
{
    DWORD i;
    for(i = 0; i < cb; i++) {
        if(pb[i]) { return FALSE; }
    }
    return TRUE;
}

/*
* Validate a complete 64KiB EVTX chunk. Valid chunks retain their original
* bytes so internal BinXML string and template offsets remain unchanged.
*/
static BOOL VmmEventLog_Repair_ChunkValidate(
    _In_reads_(VMM_EVENTLOG_CHUNK_SIZE) PBYTE pb,
    _Out_ PVMM_EVENTLOG_REPAIR_CHUNK pChunk,
    _In_opt_ POB_SET psRecordId,
    _Inout_ PQWORD pcRecord,
    _Inout_ PQWORD pcRecordUnique,
    _Inout_ PBOOL pfRecordIdZero,
    _Inout_ PBOOL pfRecordIdComplete
)
{
    DWORD i, oRecord, cbRecord, oFree, cRecord = 0;
    QWORD qwRecordId;
    ZeroMemory(pChunk, sizeof(VMM_EVENTLOG_REPAIR_CHUNK));
    if(memcmp(pb, "ElfChnk\0", 8)) { return FALSE; }
    if(*(PDWORD)(pb + 124) != VmmEventLog_ChunkHeaderCrc32(pb)) { return FALSE; }
    oFree = *(PDWORD)(pb + 48);
    if((oFree < VMM_EVENTLOG_CHUNK_HEADER_SIZE) || (oFree > VMM_EVENTLOG_CHUNK_SIZE)) { return FALSE; }
    if(*(PDWORD)(pb + 52) != VmmEventLog_Crc32(pb + VMM_EVENTLOG_CHUNK_HEADER_SIZE, oFree - VMM_EVENTLOG_CHUNK_HEADER_SIZE)) { return FALSE; }
    oRecord = VMM_EVENTLOG_CHUNK_HEADER_SIZE;
    while(oRecord < oFree) {
        if((oFree - oRecord < 4) || (*(PDWORD)(pb + oRecord) != VMM_EVENTLOG_RECORD_SIGNATURE)) {
            if(VmmEventLog_Repair_IsZero(pb + oRecord, oFree - oRecord)) {
                oRecord = oFree;
                break;
            }
            return FALSE;
        }
        if(oFree - oRecord < 28) { return FALSE; }
        cbRecord = *(PDWORD)(pb + oRecord + 4);
        if((cbRecord < 28) || (cbRecord > oFree - oRecord)) { return FALSE; }
        if(*(PDWORD)(pb + oRecord + cbRecord - 4) != cbRecord) { return FALSE; }
        qwRecordId = *(PQWORD)(pb + oRecord + 8);
        if(!cRecord) {
            pChunk->qwRecordIdFirst = qwRecordId;
            pChunk->qwRecordIdLast = qwRecordId;
        } else if(qwRecordId > pChunk->qwRecordIdLast) {
            pChunk->qwRecordIdLast = qwRecordId;
        }
        cRecord++;
        oRecord += cbRecord;
    }
    if(oRecord != oFree) { return FALSE; }
    pChunk->cRecord = cRecord;
    *pcRecord += cRecord;
    // Account for unique record identifiers only after the complete chunk has
    // passed validation so a later corrupt record cannot contaminate the set.
    oRecord = VMM_EVENTLOG_CHUNK_HEADER_SIZE;
    for(i = 0; i < cRecord; i++) {
        qwRecordId = *(PQWORD)(pb + oRecord + 8);
        if(!qwRecordId) {
            if(!*pfRecordIdZero) {
                *pfRecordIdZero = TRUE;
                (*pcRecordUnique)++;
            }
        } else if(*pfRecordIdComplete && psRecordId && !ObSet_Exists(psRecordId, qwRecordId)) {
            if((*pcRecordUnique < VMM_EVENTLOG_REPAIR_MAX_RECORD_IDS) && ObSet_Push(psRecordId, qwRecordId)) {
                (*pcRecordUnique)++;
            } else {
                *pfRecordIdComplete = FALSE;
            }
        } else if(!psRecordId) {
            *pfRecordIdComplete = FALSE;
        }
        cbRecord = *(PDWORD)(pb + oRecord + 4);
        oRecord += cbRecord;
    }
    return TRUE;
}

/*
* qsort comparator: first record identifier and then original file offset.
*/
static int VmmEventLog_Repair_ChunkCmpSort(_In_ PVMM_EVENTLOG_REPAIR_CHUNK a, _In_ PVMM_EVENTLOG_REPAIR_CHUNK b)
{
    if(a->qwRecordIdFirst < b->qwRecordIdFirst) { return -1; }
    if(a->qwRecordIdFirst > b->qwRecordIdFirst) { return 1; }
    if(a->cbOffset < b->cbOffset) { return -1; }
    if(a->cbOffset > b->cbOffset) { return 1; }
    return 0;
}

typedef struct tdVMM_EVENTLOG_REPAIR_PREFETCH_PAGE {
    QWORD qwFileAddress;
    QWORD iPte;
    QWORD qwPte;
    POB_VMMWINOBJ_FILE pFile;
    BYTE pbvaVacb[8];
    BYTE pbVacb[0x40];
} VMM_EVENTLOG_REPAIR_PREFETCH_PAGE, *PVMM_EVENTLOG_REPAIR_PREFETCH_PAGE;

typedef struct tdVMM_EVENTLOG_REPAIR_PREFETCH_CONTEXT {
    PVMMOB_MAP_EVENTLOG_ENUM pObEventLogMap;
    BOOL fInitialized;
} VMM_EVENTLOG_REPAIR_PREFETCH_CONTEXT, *PVMM_EVENTLOG_REPAIR_PREFETCH_CONTEXT;

/*
* Resolve cached/data-backed pages for several event-log files together. The
* ordinary single-file reader performs up to five backend scatter stages per
* file. Performing each stage for a bounded group of files lets all metadata
* and data pages share the same backend calls. Validation consumes the batch
* output directly, so missing pages are not retried by a second file read.
*/
static VOID VmmEventLog_Repair_PrefetchScatter(_In_ VMM_HANDLE H, _Inout_ PVMM_EVENTLOG_REPAIR_PREFETCH_CONTEXT ctx, _Inout_updates_(cpMEMs) PPMEM_SCATTER ppMEMs, _In_ DWORD cpMEMs, _In_ QWORD fVmmRead)
{
    BOOL f, f32 = H->vmm.f32;
    DWORD i, iLog, iSS, cAddressSaved = 0, cPrepare = 0, cStage = 0, cbPte = f32 ? 4 : 8;
    QWORD va, vaVacb, iPteSubsection;
    PMEM_SCATTER pMEM;
    POB_VMMWINOBJ_CONTROL_AREA pCA;
    PVMMWINOBJ_FILE_SUBSECTION pSS;
    PVMM_OFFSET_FILE po = &H->vmm.offset.FILE;
    PVMMOB_SCATTER hObScatter = NULL;
    PPMEM_SCATTER ppMEMsStage = NULL;
    PVMM_EVENTLOG_REPAIR_PREFETCH_PAGE pPages = NULL, pPage;
    PVMMOB_MAP_EVENTLOG_ENUM pObEventLogMap = ctx->pObEventLogMap;
    f = !cpMEMs ||
        !(pPages = LocalAlloc(LMEM_ZEROINIT, (SIZE_T)cpMEMs * sizeof(VMM_EVENTLOG_REPAIR_PREFETCH_PAGE))) ||
        !(ppMEMsStage = LocalAlloc(0, (SIZE_T)cpMEMs * sizeof(PMEM_SCATTER))) ||
        !(hObScatter = VmmScatter_Initialize(H, VMM_FLAG_SCATTER_FORCE_PAGEREAD));
    if(f) { goto finish; }
    // 1: resolve all shared-cache-map VACB array entries in one scatter.
    for(i = 0; i < cpMEMs; i++) {
        pMEM = ppMEMs[i];
        pPage = pPages + i;
        pPage->qwFileAddress = pMEM->qwA;
        iLog = (DWORD)(pMEM->qwA >> 48);
        pPage->iPte = (pMEM->qwA & VMM_EVENTLOG_REPAIR_FILE_OFFSET_MASK) >> 12;
        f = (iLog < pObEventLogMap->cMap) &&
            (pPage->pFile = (POB_VMMWINOBJ_FILE)pObEventLogMap->pMap[iLog]._pObFile) &&
            pPage->pFile->pCache && pPage->pFile->pCache->cbSectionSize;
        if(f) {
            va = pPage->pFile->pCache->vaVacbs +
                (((pPage->iPte << 12) / pPage->pFile->pCache->cbSectionSize) * cbPte);
            if(!VmmScatter_PrepareEx(hObScatter, va, cbPte, pPage->pbvaVacb, NULL)) { goto finish; }
            cPrepare++;
        }
        pMEM->qwA = 0;
        cAddressSaved++;
    }
    if(cPrepare && !VmmScatter_Execute(hObScatter, PVMM_PROCESS_SYSTEM)) { goto finish; }
    VmmScatter_Clear(hObScatter);
    // 2: resolve all VACB base addresses in one scatter.
    cPrepare = 0;
    for(i = 0; i < cpMEMs; i++) {
        pPage = pPages + i;
        if(!pPage->pFile || !pPage->pFile->pCache) { continue; }
        vaVacb = VMM_PTR_OFFSET(f32, pPage->pbvaVacb, 0);
        if(vaVacb && VMM_KADDR_4_8(f32, vaVacb)) {
            if(!VmmScatter_PrepareEx(hObScatter, vaVacb, po->_VACB.cb, pPage->pbVacb, NULL)) { goto finish; }
            cPrepare++;
        }
    }
    if(cPrepare && !VmmScatter_Execute(hObScatter, PVMM_PROCESS_SYSTEM)) { goto finish; }
    // 3: read all pages with a valid shared-cache-map translation together.
    for(i = 0; i < cpMEMs; i++) {
        pMEM = ppMEMs[i];
        pPage = pPages + i;
        f = pPage->pFile && pPage->pFile->pCache &&
            (pPage->pFile->pCache->va == VMM_PTR_OFFSET(f32, pPage->pbVacb, po->_VACB.oSharedCacheMap)) &&
            (va = VMM_PTR_OFFSET(f32, pPage->pbVacb, po->_VACB.oBaseAddress));
        if(f) {
            pMEM->qwA = va + (pPage->iPte << 12);
            ppMEMsStage[cStage++] = pMEM;
        }
    }
    if(cStage) {
        VmmReadScatterVirtual(H, PVMM_PROCESS_SYSTEM, ppMEMsStage, cStage, fVmmRead);
    }
    // 4: batch prototype-PTE lookup for pages not present in shared cache.
    VmmScatter_Clear(hObScatter);
    cStage = 0;
    for(i = 0; i < cpMEMs; i++) {
        pMEM = ppMEMs[i];
        pPage = pPages + i;
        if(pMEM->f || !pPage->pFile || !(pCA = pPage->pFile->pData)) { continue; }
        iSS = 0;
        while((iSS < pCA->cSUBSECTION) &&
              (pPage->iPte >= (QWORD)pCA->pSUBSECTION[iSS].dwStartingSector + pCA->pSUBSECTION[iSS].dwPtesInSubsection)) {
            iSS++;
        }
        if(iSS >= pCA->cSUBSECTION) { continue; }
        pSS = pCA->pSUBSECTION + iSS;
        if((pPage->iPte < pSS->dwStartingSector) || (pPage->iPte >= (QWORD)pSS->dwStartingSector + pSS->dwPtesInSubsection)) {
            continue;
        }
        iPteSubsection = pPage->iPte - pSS->dwStartingSector;
        if(iPteSubsection > ((QWORD)-1 - pSS->vaSubsectionBase) / cbPte) { continue; }
        va = pSS->vaSubsectionBase + iPteSubsection * cbPte;
        if(!VMM_KADDR_4_8(f32, va)) { continue; }
        if(!VmmScatter_PrepareEx(hObScatter, va, cbPte, (PBYTE)&pPage->qwPte, NULL)) { goto finish; }
        ppMEMsStage[cStage++] = pMEM;
    }
    if(cStage) {
        if(!VmmScatter_Execute(hObScatter, PVMM_PROCESS_SYSTEM)) { goto finish; }
        cStage = 0;
        for(i = 0; i < cpMEMs; i++) {
            pMEM = ppMEMs[i];
            pPage = pPages + i;
            if(!pMEM->f && pPage->qwPte) {
                pMEM->qwA = pPage->qwPte;
                ppMEMsStage[cStage++] = pMEM;
            }
        }
        if(cStage) {
            VmmReadScatterVirtual(H, PVMM_PROCESS_SYSTEM, ppMEMsStage, cStage, fVmmRead | VMM_FLAG_ALTADDR_VA_PTE);
        }
    }
    ctx->fInitialized = TRUE;
finish:
    if(cAddressSaved) {
        for(i = 0; i < cAddressSaved; i++) {
            ppMEMs[i]->qwA = pPages[i].qwFileAddress;
        }
    }
    Ob_DECREF(hObScatter);
    LocalFree(ppMEMsStage);
    LocalFree(pPages);
}

static QWORD VmmEventLog_Repair_PrefetchSize(_In_ PVMM_MAP_EVENTLOG_ENUMENTRY pe)
{
    if(!pe || (pe->cbFile < VMM_EVENTLOG_FILE_HEADER_SIZE)) { return 0; }
    return VMM_EVENTLOG_FILE_HEADER_SIZE + ((pe->cbFile - VMM_EVENTLOG_FILE_HEADER_SIZE) / VMM_EVENTLOG_CHUNK_SIZE) * VMM_EVENTLOG_CHUNK_SIZE;
}

_Success_(return)
static BOOL VmmEventLog_Repair_PrefetchRange(_In_ VMM_HANDLE H, _In_ PVMMOB_MAP_EVENTLOG_ENUM pEventEnumMap, _In_ DWORD iStart, _In_ DWORD iEnd, _Out_writes_bytes_(cbBuffer) PBYTE pbBuffer, _In_ DWORD cbBuffer)
{
    BOOL f = TRUE;
    DWORD i, oBuffer = 0;
    QWORD cbPrefetch;
    VMM_EVENTLOG_REPAIR_PREFETCH_CONTEXT ctx = { pEventEnumMap, FALSE };
    PVMMOB_SCATTER hObScatter;
    if(!H || !pEventEnumMap || !pbBuffer || !cbBuffer || (iStart >= iEnd) || (iEnd > pEventEnumMap->cMap)) { return FALSE; }
    if(!(hObScatter = VmmScatter_Initialize(H, VMM_FLAG_SCATTER_FORCE_PAGEREAD))) { return FALSE; }
    for(i = iStart; i < iEnd; i++) {
        cbPrefetch = VmmEventLog_Repair_PrefetchSize(pEventEnumMap->pMap + i);
        if(!cbPrefetch || (cbPrefetch > cbBuffer - oBuffer) ||
           !VmmScatter_PrepareEx(hObScatter, ((QWORD)i << 48), (DWORD)cbPrefetch, pbBuffer + oBuffer, NULL)) {
            f = FALSE;
            break;
        }
        oBuffer += (DWORD)cbPrefetch;
    }
    f = f && (oBuffer == cbBuffer) && VmmScatter_ExecuteEx(
            hObScatter,
            &ctx,
            (VMM_SCATTER_CUSTOM_EXECUTE_SCATTER_PFN)VmmEventLog_Repair_PrefetchScatter
        ) && ctx.fInitialized;
    Ob_DECREF(hObScatter);
    return f;
}

/*
* Build one repair descriptor. Complete clean files are exposed unchanged.
* Dirty or inconsistent files are reconstructed from checksum-valid non-empty
* chunks. No damaged bytes or checksums are synthesized.
*/
static BOOL VmmEventLog_Repair_BuildEntry(_In_ VMM_HANDLE H, _In_ PVMM_MAP_EVENTLOG_ENUMENTRY peOriginal, _Out_ PVMM_MAP_EVENTLOG_REPAIRENTRY peRepair, _In_reads_bytes_opt_(cbPrefetch) PBYTE pbPrefetch, _In_ DWORD cbPrefetch)
{
    BOOL f, fResult = FALSE, fPrefetched, fHeaderValid = FALSE, fDeclaredValid = FALSE, fRecordIdZero = FALSE, fRecordIdComplete = TRUE;
    BYTE pbFileHeader[VMM_EVENTLOG_FILE_HEADER_SIZE];
    DWORD i, j, cSlot, cBlock, cbBlock, cbRead, cbReadOffset, cDeclared = 0, cChunkValid = 0, cChunkRetained = 0;
    QWORD cSlot64, cbScan64, cRecord = 0, cRecordUnique = 0, qwRecordIdLast = 0;
    PBYTE pbScan = NULL, pbChunkBase, pbHeader = NULL;
    PQWORD pqwChunkOffset = NULL;
    POB_SET psRecordId = NULL;
    PVMM_EVENTLOG_REPAIR_CHUNK pChunks = NULL, pChunk;
    NTSTATUS nt;
    ZeroMemory(peRepair, sizeof(VMM_MAP_EVENTLOG_REPAIRENTRY));
    if(peOriginal->cbFile < VMM_EVENTLOG_FILE_HEADER_SIZE) { return TRUE; }
    cSlot64 = (peOriginal->cbFile - VMM_EVENTLOG_FILE_HEADER_SIZE) / VMM_EVENTLOG_CHUNK_SIZE;
    if(cSlot64 > VMM_EVENTLOG_PROCESS_MAX_CHUNKS) { return TRUE; }
    cSlot = (DWORD)cSlot64;
    cbScan64 = VMM_EVENTLOG_FILE_HEADER_SIZE + cSlot64 * VMM_EVENTLOG_CHUNK_SIZE;
    fPrefetched = pbPrefetch && (cbScan64 == cbPrefetch);
    if(fPrefetched) {
        memcpy(pbFileHeader, pbPrefetch, VMM_EVENTLOG_FILE_HEADER_SIZE);
    } else if(!cSlot) {
        nt = VmmEventLog_Read(H, peOriginal, pbFileHeader, sizeof(pbFileHeader), &cbRead, 0);
        if((nt != VMM_STATUS_SUCCESS) || (cbRead != sizeof(pbFileHeader))) { return FALSE; }
    }
    if(fPrefetched || !cSlot) {
        fHeaderValid = VmmEventLog_Repair_FileHeaderIsValid(pbFileHeader);
        if(fHeaderValid) { cDeclared = *(PDWORD)(pbFileHeader + 42); }
        fDeclaredValid = fHeaderValid && !((peOriginal->cbFile - VMM_EVENTLOG_FILE_HEADER_SIZE) % VMM_EVENTLOG_CHUNK_SIZE) && (cDeclared <= cSlot);
        if(fDeclaredValid && cDeclared &&
           ((*(PQWORD)(pbFileHeader + 8) >= cDeclared) ||
            (*(PQWORD)(pbFileHeader + 16) >= cDeclared))) {
            fDeclaredValid = FALSE;
        }
    }
    if(cSlot) {
        if((SIZE_T)cSlot > ((SIZE_T)-1) / sizeof(VMM_EVENTLOG_REPAIR_CHUNK)) { return FALSE; }
        pChunks = LocalAlloc(LMEM_ZEROINIT, (SIZE_T)cSlot * sizeof(VMM_EVENTLOG_REPAIR_CHUNK));
        cBlock = min(cSlot, VMM_EVENTLOG_REPAIR_SCAN_CHUNKS);
        cbBlock = VMM_EVENTLOG_FILE_HEADER_SIZE + cBlock * VMM_EVENTLOG_CHUNK_SIZE;
        if(!fPrefetched) { pbScan = LocalAlloc(0, cbBlock); }
        if(!pChunks || (!fPrefetched && !pbScan)) { goto finish; }
    }
    psRecordId = ObSet_New(H);
    if(!psRecordId) { fRecordIdComplete = FALSE; }
    for(i = 0; i < cSlot; i += cBlock) {
        cBlock = min(VMM_EVENTLOG_REPAIR_SCAN_CHUNKS, cSlot - i);
        if(fPrefetched) {
            pbChunkBase = pbPrefetch + VMM_EVENTLOG_FILE_HEADER_SIZE + (SIZE_T)i * VMM_EVENTLOG_CHUNK_SIZE;
        } else {
            cbBlock = cBlock * VMM_EVENTLOG_CHUNK_SIZE;
            cbReadOffset = i ? 0 : VMM_EVENTLOG_FILE_HEADER_SIZE;
            cbBlock += cbReadOffset;
            nt = VmmEventLog_Read(
                H, peOriginal, pbScan, cbBlock, &cbRead,
                i ? VMM_EVENTLOG_FILE_HEADER_SIZE + (QWORD)i * VMM_EVENTLOG_CHUNK_SIZE : 0
            );
            if((nt != VMM_STATUS_SUCCESS) || (cbRead != cbBlock)) { goto finish; }
            pbChunkBase = pbScan + cbReadOffset;
            if(!i) {
                memcpy(pbFileHeader, pbScan, VMM_EVENTLOG_FILE_HEADER_SIZE);
                fHeaderValid = VmmEventLog_Repair_FileHeaderIsValid(pbFileHeader);
                if(fHeaderValid) { cDeclared = *(PDWORD)(pbFileHeader + 42); }
                fDeclaredValid = fHeaderValid &&
                    !((peOriginal->cbFile - VMM_EVENTLOG_FILE_HEADER_SIZE) % VMM_EVENTLOG_CHUNK_SIZE) &&
                    (cDeclared <= cSlot);
                f = fDeclaredValid && cDeclared &&
                    ((*(PQWORD)(pbFileHeader + 8) >= cDeclared) || (*(PQWORD)(pbFileHeader + 16) >= cDeclared));
                if(f) {
                    fDeclaredValid = FALSE;
                }
            }
        }
        for(j = 0; j < cBlock; j++) {
            pChunk = pChunks + cChunkRetained;
            f = VmmEventLog_Repair_ChunkValidate(pbChunkBase + (SIZE_T)j * VMM_EVENTLOG_CHUNK_SIZE, pChunk, psRecordId, &cRecord, &cRecordUnique, &fRecordIdZero, &fRecordIdComplete);
            if(f) {
                cChunkValid++;
                if(pChunk->cRecord) {
                    pChunk->cbOffset = VMM_EVENTLOG_FILE_HEADER_SIZE + ((QWORD)i + j) * VMM_EVENTLOG_CHUNK_SIZE;
                    cChunkRetained++;
                }
            } else if((i + j) < cDeclared) {
                fDeclaredValid = FALSE;
            }
        }
    }
    peRepair->cChunk = cSlot;
    peRepair->cChunkValid = cChunkValid;
    peRepair->cRecord = cRecord;
    peRepair->fRecordIdComplete = fRecordIdComplete;
    peRepair->cRecordUnique = fRecordIdComplete ? cRecordUnique : 0;
    if(fDeclaredValid && (!(*(PDWORD)(pbFileHeader + 120) & VMM_EVENTLOG_FILE_FLAG_DIRTY) || !cChunkRetained)) {
        peRepair->tp = VMM_EVENTLOG_REPAIR_STATUS_ORIGINAL;
        peRepair->cChunkRetained = cDeclared;
        peRepair->cbFile = peOriginal->cbFile;
        fResult = TRUE;
        goto finish;
    }
    if(!cChunkRetained) {
        fResult = TRUE;
        goto finish;
    }
    qsort(pChunks, cChunkRetained, sizeof(VMM_EVENTLOG_REPAIR_CHUNK), (int(*)(void const *, void const *))VmmEventLog_Repair_ChunkCmpSort);
    if((SIZE_T)cChunkRetained > ((SIZE_T)-1) / sizeof(QWORD)) { goto finish; }
    pbHeader = LocalAlloc(LMEM_ZEROINIT, VMM_EVENTLOG_FILE_HEADER_SIZE);
    pqwChunkOffset = LocalAlloc(0, (SIZE_T)cChunkRetained * sizeof(QWORD));
    if(!pbHeader || !pqwChunkOffset) { goto finish; }
    if(fHeaderValid) {
        memcpy(pbHeader, pbFileHeader, VMM_EVENTLOG_FILE_HEADER_SIZE);
    } else {
        memcpy(pbHeader, "ElfFile\0", 8);
        *(PWORD)(pbHeader + 36) = 1;
        *(PWORD)(pbHeader + 38) = 3;
    }
    *(PQWORD)(pbHeader + 8) = 0;
    *(PQWORD)(pbHeader + 16) = cChunkRetained - 1;
    for(i = 0; i < cChunkRetained; i++) {
        pqwChunkOffset[i] = pChunks[i].cbOffset;
        qwRecordIdLast = max(qwRecordIdLast, pChunks[i].qwRecordIdLast);
    }
    *(PQWORD)(pbHeader + 24) = (qwRecordIdLast == 0xffffffffffffffffULL) ? qwRecordIdLast : qwRecordIdLast + 1;
    *(PDWORD)(pbHeader + 32) = 128;
    *(PWORD)(pbHeader + 40) = VMM_EVENTLOG_FILE_HEADER_SIZE;
    *(PDWORD)(pbHeader + 42) = cChunkRetained;
    *(PDWORD)(pbHeader + 120) = 0;
    *(PDWORD)(pbHeader + 124) = VmmEventLog_Crc32(pbHeader, 120);
    peRepair->tp = VMM_EVENTLOG_REPAIR_STATUS_REPAIRED;
    peRepair->cChunkRetained = cChunkRetained;
    peRepair->cbFile = VMM_EVENTLOG_FILE_HEADER_SIZE + (QWORD)cChunkRetained * VMM_EVENTLOG_CHUNK_SIZE;
    peRepair->_pbHeader = pbHeader;
    peRepair->_pqwChunkOffset = pqwChunkOffset;
    pbHeader = NULL;
    pqwChunkOffset = NULL;
    fResult = TRUE;
finish:
    LocalFree(pbScan);
    LocalFree(pbHeader);
    LocalFree(pqwChunkOffset);
    LocalFree(pChunks);
    Ob_DECREF(psRecordId);
    return fResult;
}

/*
* Locked worker function that creates the lazy event log repair map.
* CALLER DECREF: return
*/
static PVMMOB_MAP_EVENTLOG_REPAIR VmmEventLog_Repair_DoWork(_In_ VMM_HANDLE H, _In_ PVMMOB_MAP_EVENTLOG_ENUM pEventEnumMap)
{
    BOOL f;
    DWORD i = 0, j, iStart, cbBatch, oBatch;
    QWORD cbPrefetch;
    PBYTE pbBatch = NULL;
    POB_VMMWINOBJ_FILE pFile;
    SIZE_T cbMap = sizeof(VMMOB_MAP_EVENTLOG_REPAIR) + (SIZE_T)pEventEnumMap->cMap * sizeof(VMM_MAP_EVENTLOG_REPAIRENTRY);
    PVMMOB_MAP_EVENTLOG_REPAIR pObRepairMap;
    if((cbMap < sizeof(VMMOB_MAP_EVENTLOG_REPAIR)) ||
       (pEventEnumMap->cMap && (((cbMap - sizeof(VMMOB_MAP_EVENTLOG_REPAIR)) / sizeof(VMM_MAP_EVENTLOG_REPAIRENTRY)) != pEventEnumMap->cMap))) {
        return NULL;
    }
    pObRepairMap = Ob_AllocEx(H, OB_TAG_MAP_EVENTLOG_REPAIR, LMEM_ZEROINIT, cbMap, (OB_CLEANUP_CB)VmmEventLog_Repair_CleanupCB, NULL);
    if(!pObRepairMap) { return NULL; }
    if(pEventEnumMap->cMap) {
        ZeroMemory(pObRepairMap->pMap, (SIZE_T)pEventEnumMap->cMap * sizeof(VMM_MAP_EVENTLOG_REPAIRENTRY));
    }
    pObRepairMap->cMap = pEventEnumMap->cMap;
    while(i < pEventEnumMap->cMap) {
        iStart = i;
        cbBatch = 0;
        while(i < pEventEnumMap->cMap) {
            cbPrefetch = VmmEventLog_Repair_PrefetchSize(pEventEnumMap->pMap + i);
            pFile = (POB_VMMWINOBJ_FILE)pEventEnumMap->pMap[i]._pObFile;
            f = (i > 0xffffU) || !pFile ||
                (!pFile->pCache && (!pFile->pData || !pFile->pData->cSUBSECTION)) || !cbPrefetch ||
                (cbPrefetch > VMM_EVENTLOG_REPAIR_PREFETCH_BATCH_MAX) ||
                (cbBatch && (cbPrefetch > VMM_EVENTLOG_REPAIR_PREFETCH_BATCH_MAX - cbBatch));
            if(f) {
                break;
            }
            cbBatch += (DWORD)cbPrefetch;
            i++;
        }
        if(i > iStart) {
            pbBatch = LocalAlloc(0, cbBatch);
            if(pbBatch && VmmEventLog_Repair_PrefetchRange(H, pEventEnumMap, iStart, i, pbBatch, cbBatch)) {
                oBatch = 0;
                for(j = iStart; j < i; j++) {
                    cbPrefetch = VmmEventLog_Repair_PrefetchSize(pEventEnumMap->pMap + j);
                    VmmEventLog_Repair_BuildEntry(H, pEventEnumMap->pMap + j, pObRepairMap->pMap + j, pbBatch + oBatch, (DWORD)cbPrefetch);
                    oBatch += (DWORD)cbPrefetch;
                }
            } else {
                for(j = iStart; j < i; j++) {
                    VmmEventLog_Repair_BuildEntry(H, pEventEnumMap->pMap + j, pObRepairMap->pMap + j, NULL, 0);
                }
            }
            LocalFree(pbBatch); pbBatch = NULL;
        } else {
            VmmEventLog_Repair_BuildEntry(H, pEventEnumMap->pMap + i, pObRepairMap->pMap + i, NULL, 0);
            i++;
        }
    }
    return pObRepairMap;
}

_Success_(return)
static BOOL VmmEventLog_Repair_Enum(_In_ VMM_HANDLE H, _In_ PVMMOB_MAP_EVENTLOG_ENUM pEventEnumMap, _Out_ PVMMOB_MAP_EVENTLOG_REPAIR *ppObRepairMap)
{
    POB_CONTAINER pObContainer;
    PVMMOB_MAP_EVENTLOG_REPAIR pObRepairMap;
    *ppObRepairMap = NULL;
    if(!pEventEnumMap || !(pObContainer = (POB_CONTAINER)pEventEnumMap->_pObCRepair)) { return FALSE; }
    if((pObRepairMap = ObContainer_GetOb(pObContainer))) {
        *ppObRepairMap = pObRepairMap;
        return TRUE;
    }
    EnterCriticalSection(&H->vmm.LockUpdateMap);
    if(!(pObRepairMap = ObContainer_GetOb(pObContainer))) {
        pObRepairMap = VmmEventLog_Repair_DoWork(H, pEventEnumMap);
        if(pObRepairMap) {
            ObContainer_SetOb(pObContainer, pObRepairMap);
        }
    }
    LeaveCriticalSection(&H->vmm.LockUpdateMap);
    *ppObRepairMap = pObRepairMap;
    return pObRepairMap != NULL;
}

static LPCSTR VmmEventLog_Repair_StatusName(_In_ VMM_EVENTLOG_REPAIR_STATUS tp)
{
    switch(tp) {
        case VMM_EVENTLOG_REPAIR_STATUS_ORIGINAL: return "original";
        case VMM_EVENTLOG_REPAIR_STATUS_REPAIRED: return "repaired";
        default: return "unavailable";
    }
}

static NTSTATUS VmmEventLog_Repair_Read(_In_ VMM_HANDLE H, _In_ PVMM_MAP_EVENTLOG_ENUMENTRY peOriginal, _In_ PVMM_MAP_EVENTLOG_REPAIRENTRY peRepair, _Out_writes_to_(cb, *pcbRead) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset
)
{
    DWORD cbRead, cbReadPart, cbRemain, cbPart, iChunk, oChunk;
    QWORD cbReadMax, cbVirtualOffset;
    NTSTATUS nt;
    *pcbRead = 0;
    if(peRepair && (peRepair->tp == VMM_EVENTLOG_REPAIR_STATUS_ORIGINAL)) {
        return VmmEventLog_Read(H, peOriginal, pb, cb, pcbRead, cbOffset);
    }
    if(pb && cb) { ZeroMemory(pb, cb); }
    if(!peOriginal || !peRepair || !pb || (peRepair->tp != VMM_EVENTLOG_REPAIR_STATUS_REPAIRED) || !peRepair->_pbHeader || !peRepair->_pqwChunkOffset) {
        return VMM_STATUS_FILE_INVALID;
    }
    if(cbOffset >= peRepair->cbFile) { return VMM_STATUS_END_OF_FILE; }
    cbReadMax = min((QWORD)cb, peRepair->cbFile - cbOffset);
    cbRead = (DWORD)cbReadMax;
    cbRemain = cbRead;
    cbVirtualOffset = cbOffset;
    while(cbRemain) {
        if(cbVirtualOffset < VMM_EVENTLOG_FILE_HEADER_SIZE) {
            cbPart = (DWORD)min((QWORD)cbRemain, VMM_EVENTLOG_FILE_HEADER_SIZE - cbVirtualOffset);
            memcpy(pb + *pcbRead, peRepair->_pbHeader + (SIZE_T)cbVirtualOffset, cbPart);
        } else {
            iChunk = (DWORD)((cbVirtualOffset - VMM_EVENTLOG_FILE_HEADER_SIZE) / VMM_EVENTLOG_CHUNK_SIZE);
            oChunk = (DWORD)((cbVirtualOffset - VMM_EVENTLOG_FILE_HEADER_SIZE) % VMM_EVENTLOG_CHUNK_SIZE);
            if(iChunk >= peRepair->cChunkRetained) { return VMM_STATUS_FILE_INVALID; }
            cbPart = min(cbRemain, VMM_EVENTLOG_CHUNK_SIZE - oChunk);
            nt = VmmEventLog_Read(
                H,
                peOriginal,
                pb + *pcbRead,
                cbPart,
                &cbReadPart,
                peRepair->_pqwChunkOffset[iChunk] + oChunk
            );
            if((nt != VMM_STATUS_SUCCESS) || (cbReadPart != cbPart)) { return VMM_STATUS_FILE_INVALID; }
        }
        *pcbRead += cbPart;
        cbRemain -= cbPart;
        cbVirtualOffset += cbPart;
    }
    return VMM_STATUS_SUCCESS;
}

// ============================================================================
// VFS PRESENTATION
// ============================================================================
#define MSYSEVENTLOG_LINELENGTH         256ULL
#define MSYSEVENTLOG_LINEHEADER         "   #    PID   Handle      File Object         Size Name                                                             Path"
#define MSYSEVENTLOG_FILE_EVENTLOGS     "eventlogs.txt"
#define MSYSEVENTLOG_DIR_ORIGINAL       "eventlog_original"
#define MSYSEVENTLOG_DIR_ORIGINAL_LEN   VMM_STRLEN(MSYSEVENTLOG_DIR_ORIGINAL)
#define MSYSEVENTLOG_ORIGINAL_STATUS    "_summary.txt"
#define MSYSEVENTLOG_DIR_REPAIRED       "eventlog_repaired"
#define MSYSEVENTLOG_DIR_REPAIRED_LEN   VMM_STRLEN(MSYSEVENTLOG_DIR_REPAIRED)
#define MSYSEVENTLOG_REPAIR_STATUS      "_summary.txt"
#define MSYSEVENTLOG_REPAIR_LINELENGTH  256ULL
#define MSYSEVENTLOG_REPAIR_LINEHEADER  "   # Status          Original     Exposed Chunks  Valid   Kept    Records     Unique Duplicates IDs Name"
#define MSYSEVENTLOG_DIR_PARSED         "eventlog_parsed"
#define MSYSEVENTLOG_DIR_PARSED_LEN     VMM_STRLEN(MSYSEVENTLOG_DIR_PARSED)
#define MSYSEVENTLOG_PARSED_SUMMARY     "_summary.txt"
#define MSYSEVENTLOG_PARSED_LINELENGTH  320ULL
#define MSYSEVENTLOG_PARSED_LINEHEADER  "   # File                                                             Size Chunks HdrCRC DataCRC Candidates    Parsed   Skipped First                   Last"
#define MSYSEVENTLOG_CSV_HEADER         "Log,RecordID,TimeCreated,RecordTime,EventID,Qualifiers,Version,Level,Task,Opcode,Keywords,PID,TID,Provider,ProviderGuid,EventSource,Channel,Computer,UserSID,ActivityID,RelatedActivityID,FileOffset,ChunkHeaderCRC,ChunkDataCRC,Payload\n"
#define MSYSEVENTLOG_CSV_DATA_HEADER    "Log,RecordID,EventIndex,Ordinal,Path,Name,Type,Value\n"
#define MSYSEVENTLOG_CSV_SUMMARY_HEADER "Log,Path,FileSize,Chunks,ChunkHeaderCRCValid,ChunkDataCRCValid,RecordCandidates,RecordsParsed,RecordsSkipped,FirstTime,LastTime\n"

/*
* Line callback function to print one event log enumeration entry.
*/
static VOID MSysEventLog_ReadLineCB(_In_ VMM_HANDLE H, _Inout_opt_ PVOID ctx, _In_ DWORD cbLL, _In_ DWORD ie, _In_ PVMM_MAP_EVENTLOG_ENUMENTRY pe, _Out_writes_(cbLL + 1) LPSTR usz)
{
    Util_usnprintf_ln(usz, cbLL,
        "%04x %7u %8x %16llx %12llx %-64.64s %s",
        ie,
        pe->dwPID,
        pe->dwHandle,
        pe->vaFileObject,
        pe->cbFile,
        pe->uszName,
        pe->uszPath
    );
}

/*
* Line callback function to print one lazy repair-map entry.
*/
static VOID MSysEventLog_RepairReadLineCB(_In_ VMM_HANDLE H, _Inout_opt_ PVMMOB_MAP_EVENTLOG_ENUM pEvtEnumMap, _In_ DWORD cbLL, _In_ DWORD ie, _In_ PVMM_MAP_EVENTLOG_REPAIRENTRY pe, _Out_writes_(cbLL + 1) LPSTR usz)
{
    QWORD cDuplicate = (pe->fRecordIdComplete && (pe->cRecord >= pe->cRecordUnique)) ? pe->cRecord - pe->cRecordUnique : 0;
    QWORD cbOriginal = (pEvtEnumMap && (ie < pEvtEnumMap->cMap)) ? pEvtEnumMap->pMap[ie].cbFile : 0;
    LPCSTR uszName = (pEvtEnumMap && (ie < pEvtEnumMap->cMap)) ? pEvtEnumMap->pMap[ie].uszName : "";
    Util_usnprintf_ln(usz, cbLL,
        "%04x %-11s %12llx %12llx %6u %6u %6u %10llu %10llu %10llu %-3s %s",
        ie,
        VmmEventLog_Repair_StatusName(pe->tp),
        cbOriginal,
        pe->cbFile,
        pe->cChunk,
        pe->cChunkValid,
        pe->cChunkRetained,
        pe->cRecord,
        pe->fRecordIdComplete ? pe->cRecordUnique : 0,
        cDuplicate,
        pe->fRecordIdComplete ? "yes" : "no",
        uszName
    );
}

/*
* Line callback for parsed recovery statistics. Parsing remains lazy until the
* parsed directory or one of its files is first accessed.
*/
static VOID MSysEventLog_ParsedReadLineCB(_In_ VMM_HANDLE H, _Inout_opt_ PVMMOB_MAP_EVENTLOG_ENUM pEvtMap, _In_ DWORD cbLineLength, _In_ DWORD ie, _In_ PVMM_MAP_EVENTLOG_ENUMENTRY pe, _Out_writes_(cbLL + 1) LPSTR usz)
{
    CHAR szFirst[24] = { 0 }, szLast[24] = { 0 };
    PVMMOB_MAP_EVENTLOG pObEventMap = NULL;
    if(pEvtMap && VmmEventLog_Parse(H, pEvtMap, pe, &pObEventMap)) {
        Util_FileTime2String(pObEventMap->ftMin, szFirst);
        Util_FileTime2String(pObEventMap->ftMax, szLast);
        Util_usnprintf_ln(usz, cbLineLength,
            "%04x %-64.64s %10llx %6u %6u %7u %10u %9u %9u %s %s",
            ie,
            pe->uszName,
            pe->cbFile,
            pObEventMap->cChunk,
            pObEventMap->cChunkHeaderValid,
            pObEventMap->cChunkDataValid,
            pObEventMap->cRecordCandidate,
            pObEventMap->cRecordParsed,
            pObEventMap->cRecordSkipped,
            szFirst,
            szLast
        );
    } else {
        Util_usnprintf_ln(usz, cbLineLength, "%04x %-64.64s %10llx - parse unavailable", ie, pe->uszName, pe->cbFile);
    }
    Ob_DECREF(pObEventMap);
}

/*
* Convert an original .evtx name to the corresponding parsed .txt name.
*/
_Success_(return)
static BOOL MSysEventLog_ParsedName(_In_opt_ LPCSTR uszName, _Out_writes_z_(cbName) LPSTR uszParsedName, _In_ DWORD cbName)
{
    SIZE_T cch;
    if(!uszParsedName || !cbName) { return FALSE; }
    uszParsedName[0] = 0;
    if(!uszName || (cbName < 5)) { return FALSE; }
    cch = strlen(uszName);
    if((cch < 5) || (cch + 1 > cbName) || _stricmp(uszName + cch - 5, ".evtx")) { return FALSE; }
    memcpy(uszParsedName, uszName, cch - 5);
    memcpy(uszParsedName + cch - 5, ".txt", 5);
    return TRUE;
}

static NTSTATUS MSysEventLog_Read(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_CONTEXT ctxP, _Out_writes_to_(cb, *pcbRead) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset)
{
    NTSTATUS nt = VMM_STATUS_FILE_INVALID;
    DWORD i;
    LPCSTR uszName;
    PVMMOB_MAP_EVENTLOG_ENUM pObEventEnumMap = NULL;
    PVMMOB_MAP_EVENTLOG_REPAIR pObEventRepairMap = NULL;
    PVMMOB_MAP_EVENTLOG pObEventMap = NULL;
    PVMM_MAP_EVENTLOG_ENUMENTRY pe;
    PVMM_MAP_EVENTLOG_REPAIRENTRY peRepair;
    *pcbRead = 0;
    if(!VmmEventLog_Enum(H, (POB_CONTAINER)ctxP->ctxM, &pObEventEnumMap)) { return nt; }
    if(!_stricmp(ctxP->uszPath, MSYSEVENTLOG_FILE_EVENTLOGS)) {
        nt = Util_VfsLineFixed_Read(
            H, (UTIL_VFSLINEFIXED_PFN_CB)MSysEventLog_ReadLineCB, NULL,
            MSYSEVENTLOG_LINELENGTH, MSYSEVENTLOG_LINEHEADER,
            pObEventEnumMap->pMap, pObEventEnumMap->cMap, sizeof(VMM_MAP_EVENTLOG_ENUMENTRY),
            pb, cb, pcbRead, cbOffset
        );
        goto finish;
    }
    if(!_strnicmp(ctxP->uszPath, MSYSEVENTLOG_DIR_ORIGINAL "\\", MSYSEVENTLOG_DIR_ORIGINAL_LEN + 1)) {
        uszName = ctxP->uszPath + MSYSEVENTLOG_DIR_ORIGINAL_LEN + 1;
        if(!_stricmp(uszName, MSYSEVENTLOG_ORIGINAL_STATUS)) {
            nt = Util_VfsLineFixed_Read(
                H, (UTIL_VFSLINEFIXED_PFN_CB)MSysEventLog_ReadLineCB, NULL,
                MSYSEVENTLOG_LINELENGTH, MSYSEVENTLOG_LINEHEADER,
                pObEventEnumMap->pMap, pObEventEnumMap->cMap, sizeof(VMM_MAP_EVENTLOG_ENUMENTRY),
                pb, cb, pcbRead, cbOffset
            );
            goto finish;
        }
        if(uszName[0] && !strchr(uszName, '\\') && (pe = VmmEventLog_Enum_GetEntry(pObEventEnumMap, uszName))) {
            nt = VmmEventLog_Read(H, pe, pb, cb, pcbRead, cbOffset);
        }
        goto finish;
    }
    if(!_strnicmp(ctxP->uszPath, MSYSEVENTLOG_DIR_REPAIRED "\\", MSYSEVENTLOG_DIR_REPAIRED_LEN + 1)) {
        uszName = ctxP->uszPath + MSYSEVENTLOG_DIR_REPAIRED_LEN + 1;
        if(!VmmEventLog_Repair_Enum(H, pObEventEnumMap, &pObEventRepairMap)) { goto finish; }
        if(!_stricmp(uszName, MSYSEVENTLOG_REPAIR_STATUS)) {
            nt = Util_VfsLineFixed_Read(
                H, (UTIL_VFSLINEFIXED_PFN_CB)MSysEventLog_RepairReadLineCB, pObEventEnumMap,
                MSYSEVENTLOG_REPAIR_LINELENGTH, MSYSEVENTLOG_REPAIR_LINEHEADER,
                pObEventRepairMap->pMap, pObEventRepairMap->cMap, sizeof(VMM_MAP_EVENTLOG_REPAIRENTRY),
                pb, cb, pcbRead, cbOffset
            );
            goto finish;
        }
        if(uszName[0] && !strchr(uszName, '\\') && (pe = VmmEventLog_Enum_GetEntry(pObEventEnumMap, uszName))) {
            i = (DWORD)(pe - pObEventEnumMap->pMap);
            if((i < pObEventRepairMap->cMap) &&
               ((peRepair = pObEventRepairMap->pMap + i)->tp != VMM_EVENTLOG_REPAIR_STATUS_UNAVAILABLE)) {
                nt = VmmEventLog_Repair_Read(H, pe, peRepair, pb, cb, pcbRead, cbOffset);
            }
        }
        goto finish;
    }
    if(!_strnicmp(ctxP->uszPath, MSYSEVENTLOG_DIR_PARSED "\\", MSYSEVENTLOG_DIR_PARSED_LEN + 1)) {
        CHAR uszParsedName[MAX_PATH];
        uszName = ctxP->uszPath + MSYSEVENTLOG_DIR_PARSED_LEN + 1;
        if(!_stricmp(uszName, MSYSEVENTLOG_PARSED_SUMMARY)) {
            nt = Util_VfsLineFixed_Read(
                H, (UTIL_VFSLINEFIXED_PFN_CB)MSysEventLog_ParsedReadLineCB, pObEventEnumMap,
                MSYSEVENTLOG_PARSED_LINELENGTH, MSYSEVENTLOG_PARSED_LINEHEADER,
                pObEventEnumMap->pMap, pObEventEnumMap->cMap, sizeof(VMM_MAP_EVENTLOG_ENUMENTRY),
                pb, cb, pcbRead, cbOffset
            );
            goto finish;
        }
        if(uszName[0] && !strchr(uszName, '\\')) {
            for(i = 0; i < pObEventEnumMap->cMap; i++) {
                pe = pObEventEnumMap->pMap + i;
                if(MSysEventLog_ParsedName(pe->uszName, uszParsedName, sizeof(uszParsedName)) &&
                   !_stricmp(uszName, uszParsedName) &&
                   VmmEventLog_Parse(H, pObEventEnumMap, pe, &pObEventMap)) {
                    nt = VmmEventLog_Parse_ReadText(H, pObEventMap, pb, cb, pcbRead, cbOffset);
                    break;
                }
            }
        }
    }
finish:
    Ob_DECREF(pObEventMap);
    Ob_DECREF(pObEventRepairMap);
    Ob_DECREF(pObEventEnumMap);
    return nt;
}

static BOOL MSysEventLog_List(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_CONTEXT ctxP, _Inout_ PHANDLE pFileList)
{
    DWORD i;
    CHAR uszParsedName[MAX_PATH];
    PVMMOB_MAP_EVENTLOG pObEventMap = NULL;
    PVMMOB_MAP_EVENTLOG_ENUM pObEventEnumMap = NULL;
    PVMMOB_MAP_EVENTLOG_REPAIR pObRepairMap = NULL;
    if(!VmmEventLog_Enum(H, (POB_CONTAINER)ctxP->ctxM, &pObEventEnumMap)) { return TRUE; }
    if(!ctxP->uszPath[0]) {
        VMMDLL_VfsList_AddFile(pFileList, MSYSEVENTLOG_FILE_EVENTLOGS, UTIL_VFSLINEFIXED_LINECOUNT(H, pObEventEnumMap->cMap) * MSYSEVENTLOG_LINELENGTH, NULL);
        VMMDLL_VfsList_AddDirectory(pFileList, MSYSEVENTLOG_DIR_ORIGINAL, NULL);
        VMMDLL_VfsList_AddDirectory(pFileList, MSYSEVENTLOG_DIR_REPAIRED, NULL);
        VMMDLL_VfsList_AddDirectory(pFileList, MSYSEVENTLOG_DIR_PARSED, NULL);
        goto finish;
    }
    if(!_stricmp(ctxP->uszPath, MSYSEVENTLOG_DIR_ORIGINAL)) {
        VMMDLL_VfsList_AddFile(pFileList, MSYSEVENTLOG_ORIGINAL_STATUS, UTIL_VFSLINEFIXED_LINECOUNT(H, pObEventEnumMap->cMap) * MSYSEVENTLOG_LINELENGTH, NULL);
        for(i = 0; i < pObEventEnumMap->cMap; i++) {
            VMMDLL_VfsList_AddFile(pFileList, pObEventEnumMap->pMap[i].uszName, pObEventEnumMap->pMap[i].cbFile, NULL);
        }
        goto finish;
    }
    if(!_stricmp(ctxP->uszPath, MSYSEVENTLOG_DIR_REPAIRED)) {
        if(!VmmEventLog_Repair_Enum(H, pObEventEnumMap, &pObRepairMap)) { goto finish; }
        VMMDLL_VfsList_AddFile(pFileList, MSYSEVENTLOG_REPAIR_STATUS, UTIL_VFSLINEFIXED_LINECOUNT(H, pObRepairMap->cMap) * MSYSEVENTLOG_REPAIR_LINELENGTH, NULL);
        for(i = 0; (i < pObEventEnumMap->cMap) && (i < pObRepairMap->cMap); i++) {
            if(pObRepairMap->pMap[i].tp != VMM_EVENTLOG_REPAIR_STATUS_UNAVAILABLE) {
                VMMDLL_VfsList_AddFile(pFileList, pObEventEnumMap->pMap[i].uszName, pObRepairMap->pMap[i].cbFile, NULL);
            }
        }
        goto finish;
    }
    if(!_stricmp(ctxP->uszPath, MSYSEVENTLOG_DIR_PARSED)) {
        VMMDLL_VfsList_AddFile(pFileList, MSYSEVENTLOG_PARSED_SUMMARY, UTIL_VFSLINEFIXED_LINECOUNT(H, pObEventEnumMap->cMap) * MSYSEVENTLOG_PARSED_LINELENGTH, NULL);
        for(i = 0; i < pObEventEnumMap->cMap; i++) {
            if(MSysEventLog_ParsedName(pObEventEnumMap->pMap[i].uszName, uszParsedName, sizeof(uszParsedName)) &&
               VmmEventLog_Parse(H, pObEventEnumMap, pObEventEnumMap->pMap + i, &pObEventMap)) {
                VMMDLL_VfsList_AddFile(pFileList, uszParsedName, VmmEventLog_Parse_TextSize(H, pObEventMap), NULL);
                Ob_DECREF_NULL(&pObEventMap);
            }
        }
    }
finish:
    Ob_DECREF(pObEventMap);
    Ob_DECREF(pObRepairMap);
    Ob_DECREF(pObEventEnumMap);
    return TRUE;
}

// ============================================================================
// FORENSIC CSV AND TIMELINE OUTPUT
// ============================================================================
static VOID MSysEventLog_FcLogCSV(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_CONTEXT ctxP, _In_ VMMDLL_CSV_HANDLE hCSV)
{
    DWORD i, j;
    PVMMOB_MAP_EVENTLOG_ENUM pObEventLogMap = NULL;
    PVMMOB_MAP_EVENTLOG pObEventMap = NULL;
    PVMM_MAP_EVENTLOG_ENTRY pe;
    PVMM_MAP_EVENTLOG_DATAENTRY peData;
    if(ctxP->pProcess || !VmmEventLog_Enum(H, (POB_CONTAINER)ctxP->ctxM, &pObEventLogMap)) { return; }
    FcFileAppend(H, "eventlog.csv", MSYSEVENTLOG_CSV_HEADER);
    FcFileAppend(H, "eventlog_data.csv", MSYSEVENTLOG_CSV_DATA_HEADER);
    FcFileAppend(H, "eventlog_summary.csv", MSYSEVENTLOG_CSV_SUMMARY_HEADER);
    for(i = 0; i < pObEventLogMap->cMap; i++) {
        if(!VmmEventLog_Parse(H, pObEventLogMap, pObEventLogMap->pMap + i, &pObEventMap)) { continue; }
        FcCsv_Reset(hCSV);
        FcFileAppend(H, "eventlog_summary.csv", "%s,%s,%llu,%u,%u,%u,%u,%u,%u,%s,%s\n",
            FcCsv_String(hCSV, pObEventMap->uszLogName),
            FcCsv_String(hCSV, pObEventMap->uszLogPath),
            pObEventLogMap->pMap[i].cbFile,
            pObEventMap->cChunk,
            pObEventMap->cChunkHeaderValid,
            pObEventMap->cChunkDataValid,
            pObEventMap->cRecordCandidate,
            pObEventMap->cRecordParsed,
            pObEventMap->cRecordSkipped,
            FcCsv_FileTime(hCSV, pObEventMap->ftMin),
            FcCsv_FileTime(hCSV, pObEventMap->ftMax)
        );
        for(j = 0; j < pObEventMap->cMap; j++) {
            pe = pObEventMap->pMap + j;
            FcCsv_Reset(hCSV);
            FcFileAppend(H, "eventlog.csv", "%s,%llu,%s,%s,%u,%u,%u,%u,%u,%u,0x%016llx,%u,%u,%s,%s,%s,%s,%s,%s,%s,%s,0x%llx,%u,%u,%s\n",
                FcCsv_String(hCSV, pObEventMap->uszLogName),
                pe->qwRecordId,
                FcCsv_FileTime(hCSV, pe->ftTimeCreated),
                FcCsv_FileTime(hCSV, pe->ftRecord),
                pe->dwEventId,
                pe->dwQualifiers,
                pe->dwVersion,
                pe->dwLevel,
                pe->dwTask,
                pe->dwOpcode,
                pe->qwKeywords,
                pe->dwPID,
                pe->dwTID,
                FcCsv_String(hCSV, pe->uszProvider),
                FcCsv_String(hCSV, pe->uszProviderGuid),
                FcCsv_String(hCSV, pe->uszEventSource),
                FcCsv_String(hCSV, pe->uszChannel),
                FcCsv_String(hCSV, pe->uszComputer),
                FcCsv_String(hCSV, pe->uszUserSid),
                FcCsv_String(hCSV, pe->uszActivityId),
                FcCsv_String(hCSV, pe->uszRelatedActivityId),
                pe->cbOffset,
                (pe->dwFlags & VMM_EVENTLOG_ENTRY_FLAG_CHUNK_HEADER_CRC) ? 1 : 0,
                (pe->dwFlags & VMM_EVENTLOG_ENTRY_FLAG_CHUNK_DATA_CRC) ? 1 : 0,
                FcCsv_String(hCSV, pe->uszPayload)
            );
        }
        for(j = 0; j < pObEventMap->cData; j++) {
            peData = pObEventMap->pData + j;
            pe = pObEventMap->pMap + peData->iEvent;
            FcCsv_Reset(hCSV);
            FcFileAppend(H, "eventlog_data.csv", "%s,%llu,%u,%u,%s,%s,%s,%s\n",
                FcCsv_String(hCSV, pObEventMap->uszLogName),
                pe->qwRecordId,
                peData->iEvent,
                peData->iOrdinal,
                FcCsv_String(hCSV, peData->uszPath),
                FcCsv_String(hCSV, peData->uszName),
                FcCsv_String(hCSV, VmmEventLog_Parse_TypeName(peData->tp)),
                FcCsv_String(hCSV, peData->uszValue)
            );
        }
        Ob_DECREF_NULL(&pObEventMap);
    }
    Ob_DECREF(pObEventMap);
    Ob_DECREF(pObEventLogMap);
}

static VOID MSysEventLog_FcTimeline(
    _In_ VMM_HANDLE H,
    _In_opt_ PVOID ctxfc,
    _In_ HANDLE hTimeline,
    _In_ VOID(*pfnAddEntry)(_In_ VMM_HANDLE H, _In_ HANDLE hTimeline, _In_ QWORD ft, _In_ DWORD dwAction, _In_ DWORD dwPID, _In_ DWORD dwData32, _In_ QWORD qwData64, _In_ LPCSTR uszText),
    _In_ VOID(*pfnEntryAddBySql)(_In_ VMM_HANDLE H, _In_ HANDLE hTimeline, _In_ DWORD cEntrySql, _In_ LPCSTR *pszEntrySql)
)
{
    DWORD i, j;
    QWORD ft;
    CHAR usz[2048];
    PVMMOB_MAP_EVENTLOG_ENUM pObEventLogMap = NULL;
    PVMMOB_MAP_EVENTLOG pObEventMap = NULL;
    PVMM_MAP_EVENTLOG_ENTRY pe;
    if(!ctxfc || !VmmEventLog_Enum(H, (POB_CONTAINER)ctxfc, &pObEventLogMap)) { return; }
    for(i = 0; i < pObEventLogMap->cMap; i++) {
        if(!VmmEventLog_Parse(H, pObEventLogMap, pObEventLogMap->pMap + i, &pObEventMap)) { continue; }
        for(j = 0; j < pObEventMap->cMap; j++) {
            pe = pObEventMap->pMap + j;
            ft = pe->ftTimeCreated ? pe->ftTimeCreated : pe->ftRecord;
            if(!ft) { continue; }
            _snprintf_s(usz, sizeof(usz), _TRUNCATE,
                "log:[%s] provider:[%s] channel:[%s] event:%u level:%u record:%llu data:[%s]",
                pObEventMap->uszLogName,
                pe->uszProvider,
                pe->uszChannel,
                pe->dwEventId,
                pe->dwLevel,
                pe->qwRecordId,
                pe->uszPayload
            );
            pfnAddEntry(H, hTimeline, ft, FC_TIMELINE_ACTION_NONE, pe->dwPID, pe->dwEventId, pe->qwRecordId, usz);
        }
        Ob_DECREF_NULL(&pObEventMap);
    }
    Ob_DECREF(pObEventMap);
    Ob_DECREF(pObEventLogMap);
}

static PVOID MSysEventLog_FcInitialize(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_CONTEXT ctxP)
{
    return ctxP->ctxM;
}

// ============================================================================
// MODULE CACHE LIFECYCLE AND REGISTRATION
// ============================================================================

static VOID MSysEventLog_Notify(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_CONTEXT ctxP, _In_ DWORD fEvent, _In_opt_ PVOID pvEvent, _In_ DWORD cbEvent)
{
    if(fEvent == VMMDLL_PLUGIN_NOTIFY_REFRESH_SLOW) {
        ObContainer_SetOb((POB_CONTAINER)ctxP->ctxM, NULL);
    }
}

static VOID MSysEventLog_Close(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_CONTEXT ctxP)
{
    Ob_DECREF(ctxP->ctxM);
}

VOID M_SysEventLog_Initialize(_In_ VMM_HANDLE H, _Inout_ PVMMDLL_PLUGIN_REGINFO pRI)
{
    if((pRI->magic != VMMDLL_PLUGIN_REGINFO_MAGIC) || (pRI->wVersion != VMMDLL_PLUGIN_REGINFO_VERSION)) { return; }
    if((pRI->tpSystem != VMMDLL_SYSTEM_WINDOWS_64) && (pRI->tpSystem != VMMDLL_SYSTEM_WINDOWS_32)) { return; }
    if(pRI->sysinfo.dwVersionBuild < 6000) { return; }              // Vista+ (.evtx) required.
    if(!(pRI->reg_info.ctxM = (PVMMDLL_PLUGIN_INTERNAL_CONTEXT)ObContainer_New())) { return; }
    strcpy_s(pRI->reg_info.uszPathName, 128, "\\sys\\eventlog");
    pRI->reg_info.fRootModule = TRUE;
    pRI->reg_fn.pfnList = MSysEventLog_List;
    pRI->reg_fn.pfnRead = MSysEventLog_Read;
    pRI->reg_fn.pfnNotify = MSysEventLog_Notify;
    pRI->reg_fn.pfnClose = MSysEventLog_Close;
    pRI->reg_fnfc.pfnInitialize = MSysEventLog_FcInitialize;
    pRI->reg_fnfc.pfnTimeline = MSysEventLog_FcTimeline;
    pRI->reg_fnfc.pfnLogCSV = MSysEventLog_FcLogCSV;
    memcpy(pRI->reg_info.sTimelineNameShort, "EVTX", 5);
    strncpy_s(pRI->reg_info.uszTimelineFile, 32, "timeline_eventlog", _TRUNCATE);
    pRI->pfnPluginManager_Register(H, pRI);
}
