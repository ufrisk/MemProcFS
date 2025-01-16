// vmmyarautil.h : utility api with helper functions around the yara scanner.
// 
// This module contains utility functions to help with yara scanning.
// The function flow is typically as follows:
// (1) Initialize the yara context with VmmYaraUtil_Initialize().
// (2) Scan memory regions with VmmYara_ScanMemory() and the callback
//     VmmYaraUtil_MatchCB().
// (3) Finalize the yara context with VmmYaraUtil_Finalize().
// (4) Parse the results with VmmYaraUtil_ParseSingleResult().
//
// (c) Ulf Frisk, 2023-2025
// Author: Ulf Frisk, pcileech@frizk.net
//

#ifndef __VMMYARAUTIL_H__
#define __VMMYARAUTIL_H__
#include "vmm.h"
#include <vmmyara.h>

typedef struct tdVMMYARAUTILOB_CONTEXT      *PVMMYARAUTILOB_CONTEXT;

/*
* Scan context for a single memory region. This is passed to the yara callback
* function - typically VmmYaraUtil_MatchCB(). This context is not shared
* between multiple threads and is only used by a single thread.
* MUST EQUAL: tdVMMDLL_YARA_MEMORY_CALLBACK_CONTEXT
*/
typedef struct tdVMMYARAUTIL_SCAN_CONTEXT {
    DWORD dwVersion;
    DWORD dwPID;
    PVMMYARAUTILOB_CONTEXT ctx;
    QWORD vaObject;
    QWORD va;
    PBYTE pb;
    DWORD cb;
    CHAR uszTag[1];     // min 1 char (but may be more).
} VMMYARAUTIL_SCAN_CONTEXT, *PVMMYARAUTIL_SCAN_CONTEXT;

#define VMMYARAUTIL_CSV_HEADER          "MatchIndex,Tags,Description,RuleAuthor,RuleVersion,MemoryType,MemoryTag,MemoryBaseAddress,ObjectAddress,PID,ProcessName,ProcessPath,CommandLine,User,Created,AddressCount,String0,Address0,String1,Address1,String2,Address2,String3,Address3,String4,Address4\n"

/*
* Initialize the yara util context.
* CALLER DECREF: return
* -- H
* -- ppYrRules = loaded yara rules to use. Rules must not be used or free'd after this call.
* -- cMatchesMax = maximum number of matches to return.
* -- return
*/
_Success_(return != NULL)
PVMMYARAUTILOB_CONTEXT VmmYaraUtil_Initialize(
    _In_ VMM_HANDLE H,
    _In_opt_ _Post_ptr_invalid_ PVMMYARA_RULES *ppYrRules,
    _In_ DWORD cMatchesMax
);

/*
* Yara callback function to process a single match from the yara scanner.
* -- ctxScan
* -- pMatch
* -- pbBuffer
* -- cbBuffer
* -- return = TRUE to continue scanning, FALSE to stop scanning.
*/
BOOL VmmYaraUtil_MatchCB(
    _In_ PVMMYARAUTIL_SCAN_CONTEXT ctxScan,
    _In_ PVMMYARA_RULE_MATCH pMatch,
    _In_reads_bytes_(cbBuffer) PBYTE pbBuffer,
    _In_ SIZE_T cbBuffer
);

/*
* Retrieve the current match count.
* -- ctx
* -- return
*/
DWORD VmmYaraUtil_MatchCount(_In_ PVMMYARAUTILOB_CONTEXT ctx);

/*
* Retrieve the scanning rules.
* These rules:
*  - must not be used after ctx lifetime.
*  - must not be free'd by caller.
* -- ctx
* -- return
*/
_Success_(return != NULL)
PVMMYARA_RULES VmmYaraUtil_Rules(_In_ PVMMYARAUTILOB_CONTEXT ctx);

/*
* Finalize yara memory ingestion and prepare for parsing of results. Function
* must be called after all memory regions have been scanned and before
* VmmYaraUtil_ParseSingleResultNext() function is called.
* -- H
* -- ctx
* -- return
*/
_Success_(return)
BOOL VmmYaraUtil_IngestFinalize(_In_ VMM_HANDLE H, _In_ PVMMYARAUTILOB_CONTEXT ctx);

typedef struct tdVMMYARAUTIL_PARSE_RESULT_FINDEVIL {
    BOOL fValid;
    DWORD dwPID;
    QWORD va;
    VMMEVIL_TYPE EvilType;
    CHAR uszName[16];
    CHAR uszRuleName[MAX_PATH];
    DWORD dwRuleIndex;
} VMMYARAUTIL_PARSE_RESULT_FINDEVIL, *PVMMYARAUTIL_PARSE_RESULT_FINDEVIL;

/*
* Process a single YARA match entry into text and csv output.
* Function must be called in a single-threaded context.
* NB! Output is only valid until next call to this function.
* -- H
* -- ctx
* -- puszTXT = optional pointer to receive text output.
* -- puszCSV = optional pointer to receive csv output.
* -- pdwType = optional pointer to receive value of meta X_MEMPROCFS_TYPE.
* -- pFindEvil = optional pointer to receive find evil information.
* -- return = TRUE on success, FALSE on failure (out of entries).
*/
_Success_(return)
BOOL VmmYaraUtil_ParseSingleResultNext(
    _In_ VMM_HANDLE H,
    _In_ PVMMYARAUTILOB_CONTEXT ctx,
    _Out_opt_ LPSTR *puszTXT,
    _Out_opt_ LPSTR *puszCSV,
    _Out_opt_ PDWORD pdwType,
    _Out_opt_ PVMMYARAUTIL_PARSE_RESULT_FINDEVIL pFindEvil
);

/*
* Perform a yara search in the address space of a process.
* Search may take a long time. It's not recommended to run this interactively.
* To cancel a search prematurely set the fAbortRequested flag in pctx and
* wait a short while.
* NB! This function is similar to VmmSearch()
* -- H
* -- pProcess
* -- ctxs
* -- ppObAddressResult
* -- return
*/
_Success_(return)
BOOL VmmYaraUtil_SearchSingleProcess(
    _In_ VMM_HANDLE H,
    _In_opt_ PVMM_PROCESS pProcess,
    _Inout_ PVMMDLL_YARA_CONFIG ctxs,
    _Out_opt_ POB_DATA *ppObAddressResult
);

#endif /* __VMMYARAUTIL_H__ */
