// vmmyarautil.c : utility api with helper functions around the yara scanner.
// 
// (c) Ulf Frisk, 2023-2025
// Author: Ulf Frisk, pcileech@frizk.net
//
#include "vmm.h"
#include "vmmyarautil.h"
#include "charutil.h"
#include "fc.h"
#include "util.h"
#include "vmmwin.h"

// ----------------------------------------------------------------------------
// PARSE SINGLE RESULT FUNCTIONALITY BELOW:
// ----------------------------------------------------------------------------

#define VMMYARAUTIL_TEXT_ALLOW \
    "0000000000000000000000000000000011111111111111111111111111111111" \
    "1111111111111111111111111111111111111111111111111111111111111110"

typedef struct tdVMMYARAUTILOB_ENTRYPARSECONTEXT {
    OB ObHdr;
    // internal buffers:
    CHAR usz[0x10000];
    CHAR uszTagsTXT[0x1000];
    CHAR uszTagsCSV[0x1000];
    CHAR uszMetaTXT[0x1000];
    CHAR uszMetaCSV[0x1000];
    CHAR uszMemoryTag[0x1000];
    CHAR uszMemoryTXT[0x1000];
    CHAR uszMemoryCSV[0x1000];
    CHAR uszProcessTXT[0x4000];
    CHAR uszProcessCSV[0x4000];
    CHAR uszMatchTXT[0x1000];
    CHAR uszMatchContextTXT[0x8000];
    CHAR uszMatchContextCSV[0x1000];
    // result data:
    CHAR uszResultCSV[0x10000];
    CHAR uszResultTXT[0x00100000];
    // csv handle:
    struct tdVMMDLL_CSV_HANDLE hCSV;
} VMMYARAUTILOB_ENTRYPARSECONTEXT, *PVMMYARAUTILOB_ENTRYPARSECONTEXT;

/*
* Struct representing a single matching YARA rule.
*/
typedef struct tdVMMYARAUTIL_MATCH {
    DWORD dwPID;
    QWORD vaBase;
    QWORD vaObject;
    VMMYARA_RULE_MATCH RuleMatch;
    CHAR uszTag[1];     // min 1 char (but may be more).
} VMMYARAUTIL_MATCH, *PVMMYARAUTIL_MATCH;

/*
* Shared scan context for a single yara scan. The context is shared between
* multiple memory regions (VMMYARAUTIL_SCAN_CONTEXT) and may be used in a
* multi-threaded context.
*/
typedef struct tdVMMYARAUTILOB_CONTEXT {
    OB ObHdr;
    DWORD dwIdByType[0x20];
    BOOL fFinalized;
    PBYTE pbMultiStr;
    DWORD cbMultiStr;
    DWORD cMatchesMax;
    POB_MAP pmObMatches;
    POB_STRMAP psmOb;
    PVMMYARA_RULES pYrRules;
    PVMMYARAUTILOB_ENTRYPARSECONTEXT pObEPC;
} VMMYARAUTILOB_CONTEXT, *PVMMYARAUTILOB_CONTEXT;

VOID VmmYaraUtil_Context_CallbackCleanup(PVMMYARAUTILOB_CONTEXT pOb)
{
    Ob_DECREF(pOb->psmOb);
    Ob_DECREF(pOb->pObEPC);
    Ob_DECREF(pOb->pmObMatches);
    LocalFree(pOb->pbMultiStr);
    if(pOb->pYrRules) { VmmYara_RulesDestroy(pOb->pYrRules); }
}

/*
* Initialize the yara util context.
* CALLER DECREF: return
* -- H
* -- pYrRules = loaded yara rules to use. Rules must not be used or free'd after this call.
* -- cMatchesMax = maximum number of matches to return.
* -- return
*/
_Success_(return != NULL)
PVMMYARAUTILOB_CONTEXT VmmYaraUtil_Initialize(_In_ VMM_HANDLE H, _In_opt_ _Post_ptr_invalid_ PVMMYARA_RULES *ppYrRules, _In_ DWORD cMatchesMax)
{
    PVMMYARAUTILOB_CONTEXT ctx = NULL;
    if(!cMatchesMax) { return NULL; }
    if(!(ctx = Ob_AllocEx(H, OB_TAG_YARA_CONTEXT, LMEM_ZEROINIT, sizeof(VMMYARAUTILOB_CONTEXT), (OB_CLEANUP_CB)VmmYaraUtil_Context_CallbackCleanup, NULL))) { goto fail; }
    if(!(ctx->pmObMatches = ObMap_New(H, OB_MAP_FLAGS_OBJECT_LOCALFREE | OB_MAP_FLAGS_NOKEY))) { goto fail; }
    if(!(ctx->psmOb = ObStrMap_New(H, 0))) { goto fail; }
    ctx->cMatchesMax = cMatchesMax;
    if(ppYrRules) {
        ctx->pYrRules = *ppYrRules;
        *ppYrRules = NULL;
    }
    return ctx;
fail:
    Ob_DECREF(ctx);
    return NULL;
}

/*
* Retrieve the current match count.
* -- ctx
* -- return
*/
DWORD VmmYaraUtil_MatchCount(_In_ PVMMYARAUTILOB_CONTEXT ctx)
{
    return ObMap_Size(ctx->pmObMatches);
}

/*
* Retrieve the scanning rules.
* These rules:
*  - must not be used after ctx lifetime.
*  - must not be free'd by caller.
* -- ctx
* -- return
*/
_Success_(return != NULL)
PVMMYARA_RULES VmmYaraUtil_Rules(_In_ PVMMYARAUTILOB_CONTEXT ctx)
{
    return ctx->pYrRules;
}

/*
* Yara callback function to process a single match from the yara scanner.
* -- ctxScan
* -- pMatch
* -- pbBuffer
* -- cbBuffer
* -- return = TRUE to continue scanning, FALSE to stop scanning.
*/
BOOL VmmYaraUtil_MatchCB(_In_ PVMMYARAUTIL_SCAN_CONTEXT ctxScan, _In_ PVMMYARA_RULE_MATCH pMatch, _In_reads_bytes_(cbBuffer) PBYTE pbBuffer, _In_ SIZE_T cbBuffer)
{
    DWORD i, j, cbTag;
    PVMMYARAUTIL_MATCH pe = NULL;
    if(pMatch->dwVersion != VMMYARA_RULE_MATCH_VERSION) { return FALSE; }
    if(ObMap_Size(ctxScan->ctx->pmObMatches) >= ctxScan->ctx->cMatchesMax) { return FALSE; }
    cbTag = ctxScan->uszTag[1] ? (DWORD)strlen(ctxScan->uszTag) + 1 : 0;
    if(!(pe = LocalAlloc(LMEM_ZEROINIT, sizeof(VMMYARAUTIL_MATCH) + cbTag))) { return FALSE; }
    // general:
    pe->dwPID = ctxScan->dwPID;
    pe->vaBase = ctxScan->va;
    pe->vaObject = ctxScan->vaObject;
    if(cbTag) {
        strncpy_s(pe->uszTag, cbTag, ctxScan->uszTag, _TRUNCATE);
    }
    // rule identifier:
    ObStrMap_PushPtrUU(ctxScan->ctx->psmOb, pMatch->szRuleIdentifier, &pe->RuleMatch.szRuleIdentifier, NULL);
    // tags:
    pe->RuleMatch.cTags = pMatch->cTags;
    for(i = 0; i < pMatch->cTags; i++) {
        ObStrMap_PushPtrUU(ctxScan->ctx->psmOb, pMatch->szTags[i], &pe->RuleMatch.szTags[i], NULL);
    }
    // meta:
    pe->RuleMatch.cMeta = pMatch->cMeta;
    for(i = 0; i < pMatch->cMeta; i++) {
        ObStrMap_PushPtrUU(ctxScan->ctx->psmOb, pMatch->Meta[i].szIdentifier, &pe->RuleMatch.Meta[i].szIdentifier, NULL);
        ObStrMap_PushPtrUU(ctxScan->ctx->psmOb, pMatch->Meta[i].szString, &pe->RuleMatch.Meta[i].szString, NULL);
    }
    // strings:
    pe->RuleMatch.cStrings = pMatch->cStrings;
    for(i = 0; i < pMatch->cStrings; i++) {
        ObStrMap_PushPtrUU(ctxScan->ctx->psmOb, pMatch->Strings[i].szString, &pe->RuleMatch.Strings[i].szString, NULL);
        pe->RuleMatch.Strings[i].cMatch = pMatch->Strings[i].cMatch;
        for(j = 0; j < pMatch->Strings[i].cMatch; j++) {
            pe->RuleMatch.Strings[i].cbMatchOffset[j] = pMatch->Strings[i].cbMatchOffset[j];
        }
    }
    if(!ObMap_Push(ctxScan->ctx->pmObMatches, 0, pe)) {
        LocalFree(pe);
        return FALSE;
    }
    return TRUE;
}

int VmmYaraUtil_MatchCmpSort(_In_ POB_MAP_ENTRY pv1, _In_ POB_MAP_ENTRY pv2)
{
    PVMMYARAUTIL_MATCH e1 = (PVMMYARAUTIL_MATCH)pv1->v;
    PVMMYARAUTIL_MATCH e2 = (PVMMYARAUTIL_MATCH)pv2->v;
    if(e1->dwPID < e2->dwPID) { return 1; }
    if(e1->dwPID > e2->dwPID) { return -1; }
    if(e1->vaBase < e2->vaBase) { return 1; }
    if(e1->vaBase > e2->vaBase) { return -1; }
    if(e1->RuleMatch.Strings[0].cbMatchOffset[0] < e2->RuleMatch.Strings[0].cbMatchOffset[0]) { return 1; }
    if(e1->RuleMatch.Strings[0].cbMatchOffset[0] > e2->RuleMatch.Strings[0].cbMatchOffset[0]) { return -1; }
    return 0;
}

/*
* Finalize yara memory ingestion and prepare for parsing of results. Function
* must be called after all memory regions have been scanned and before
* VmmYaraUtil_ParseSingleResultNext() function is called.
* -- H
* -- ctx
* -- return
*/
_Success_(return)
BOOL VmmYaraUtil_IngestFinalize(_In_ VMM_HANDLE H, _In_ PVMMYARAUTILOB_CONTEXT ctx)
{
    if(ctx->fFinalized) { return FALSE; }
    ctx->fFinalized = TRUE;
    if(!ObStrMap_FinalizeAllocU_DECREF_NULL(&ctx->psmOb, &ctx->pbMultiStr, &ctx->cbMultiStr)) { return FALSE; }
    ObMap_SortEntryIndex(ctx->pmObMatches, VmmYaraUtil_MatchCmpSort);
    return TRUE;
}

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
) {
    PVMMYARAUTILOB_ENTRYPARSECONTEXT hEPC = NULL;
    PVMMYARAUTIL_MATCH peMatch = NULL;
    BOOL fFirst, f32 = H->vmm.f32;
    QWORD va, vaAlign;
    DWORD cch, cbRead, cbWrite, cAddresses = 0;
    DWORD i, j, o, o2, dwType = 0;
    DWORD oMatchCSV = 0, iMatchCSV = 0;
    LPSTR uszMetaDescription = NULL, uszMetaAuthor = NULL, uszMetaVersion = NULL;
    PVMMWIN_USER_PROCESS_PARAMETERS pu;
    LPSTR uszCommandLine = "", uszMemoryType = "", uszMemoryTag = "";
    LPCSTR uszFindEvilSeverity;
    BYTE pbBuffer[0x80];
    CHAR szTimeCRE[24] = { 0 }, uszUserName[0x20] = { 0 };
    PVMM_MAP_PTEENTRY pePte;
    PVMM_MAP_VADENTRY peVad;
    PVMMOB_MAP_PTE pObPteMap = NULL;
    PVMMOB_MAP_VAD pObVadMap = NULL;
    PVMM_PROCESS pObProcess = NULL;
    CHAR uszRuleMatchStringBuffer[MAX_PATH];
    // init:
    if(!ctx->pObEPC) {
        ctx->pObEPC = Ob_AllocEx(H, OB_TAG_YARA_PARSEHANDLE, 0, sizeof(VMMYARAUTILOB_ENTRYPARSECONTEXT), NULL, NULL);
        if(!ctx->pObEPC) { return FALSE; }
    }
    hEPC = ctx->pObEPC;
    if(!(peMatch = ObMap_Pop(ctx->pmObMatches))) { return FALSE; }
    FcCsv_Reset(&hEPC->hCSV);
    hEPC->uszResultCSV[0] = 0;
    hEPC->uszResultTXT[0] = 0;
    if(puszTXT) { *puszTXT = hEPC->uszResultTXT; }
    if(puszCSV) { *puszCSV = hEPC->uszResultCSV; }
    if(pdwType) { *pdwType = 0; }
    if(pFindEvil) { pFindEvil->fValid = FALSE; }
    // tags:
    hEPC->uszTagsTXT[0] = 0;
    hEPC->uszTagsCSV[0] = 0;
    for(i = 0; i < peMatch->RuleMatch.cTags; i++) {
        if(i) {
            strncat_s(hEPC->uszTagsTXT, _countof(hEPC->uszTagsTXT), ", ", _TRUNCATE);
            strncat_s(hEPC->uszTagsTXT, _countof(hEPC->uszTagsCSV), ";", _TRUNCATE);
        }
        strncat_s(hEPC->uszTagsTXT, _countof(hEPC->uszTagsTXT), peMatch->RuleMatch.szTags[i], _TRUNCATE);
        strncat_s(hEPC->uszTagsCSV, _countof(hEPC->uszTagsCSV), peMatch->RuleMatch.szTags[i], _TRUNCATE);
    }
    // meta:
    o = 0;
    for(i = 0; i < peMatch->RuleMatch.cMeta; i++) {
        if(CharUtil_StrStartsWith(peMatch->RuleMatch.Meta[i].szIdentifier, "X_MEMPROCFS", FALSE)) {
            // type:
            if(CharUtil_StrEquals(peMatch->RuleMatch.Meta[i].szIdentifier, "X_MEMPROCFS_TYPE", FALSE)) {
                dwType = *pdwType = strtoul(peMatch->RuleMatch.Meta[i].szString, NULL, 0);
                if(pdwType) { *pdwType = dwType; }
                continue;
            }
            // find evil:
            if(pFindEvil && CharUtil_StrEquals(peMatch->RuleMatch.Meta[i].szIdentifier, "X_MEMPROCFS_FINDEVIL", FALSE)) {
                uszFindEvilSeverity = CharUtil_SplitFirst(peMatch->RuleMatch.Meta[i].szString, ':', pFindEvil->uszName, sizeof(pFindEvil->uszName));
                pFindEvil->EvilType.Name = pFindEvil->uszName;
                pFindEvil->EvilType.Severity = strtoul(uszFindEvilSeverity, NULL, 16);
                if(!pFindEvil->EvilType.Severity) {
                    continue;
                }
                pFindEvil->dwRuleIndex = ctx->dwIdByType[1];
                strncpy_s(pFindEvil->uszRuleName, _countof(pFindEvil->uszRuleName), peMatch->RuleMatch.szRuleIdentifier, _TRUNCATE);
                pFindEvil->va = peMatch->vaObject ? peMatch->vaObject : (peMatch->vaBase + peMatch->RuleMatch.Strings[0].cbMatchOffset[0]);
                pFindEvil->dwPID = peMatch->dwPID;
                pFindEvil->fValid = TRUE;
                continue;
            }
            continue;
        }
        o2 = o;
        cch = (DWORD)strlen(peMatch->RuleMatch.Meta[i].szIdentifier);
        cch = 13 - min(12, cch);
        o += _snprintf_s(hEPC->uszMetaTXT + o, _countof(hEPC->uszMetaTXT) - o, _TRUNCATE, "%s:%*s%s\n", peMatch->RuleMatch.Meta[i].szIdentifier, cch, "", peMatch->RuleMatch.Meta[i].szString);
        if(o2 < o) {
            hEPC->uszMetaTXT[o2] = toupper(hEPC->uszMetaTXT[o2]);
        }
        if(CharUtil_StrEquals(peMatch->RuleMatch.Meta[i].szIdentifier, "description", TRUE)) {
            uszMetaDescription = peMatch->RuleMatch.Meta[i].szString;
        } else if(CharUtil_StrEquals(peMatch->RuleMatch.Meta[i].szIdentifier, "author", TRUE)) {
            uszMetaAuthor = peMatch->RuleMatch.Meta[i].szString;
        } else if(CharUtil_StrEquals(peMatch->RuleMatch.Meta[i].szIdentifier, "version", TRUE)) {
            uszMetaVersion = peMatch->RuleMatch.Meta[i].szString;
        }
    }
    _snprintf_s(hEPC->uszMetaCSV, _countof(hEPC->uszMetaCSV), _TRUNCATE,
        ",%s,%s,%s",
        FcCsv_String(&hEPC->hCSV, uszMetaDescription),
        FcCsv_String(&hEPC->hCSV, uszMetaAuthor),
        FcCsv_String(&hEPC->hCSV, uszMetaVersion)
    );
    // process info (if any):
    pObProcess = VmmProcessGet(hEPC->ObHdr.H, peMatch->dwPID);
    if(pObProcess) {
        uszUserName[0] = 0;
        if(pObProcess->win.Token) {
            VmmWinUser_GetName(H, &pObProcess->win.Token->SidUser.SID, uszUserName, _countof(uszUserName), NULL);
        }
        Util_FileTime2String(VmmProcess_GetCreateTimeOpt(H, pObProcess), szTimeCRE);
        if((pu = VmmWin_UserProcessParameters_Get(H, pObProcess))) {
            uszCommandLine = (pu->uszCommandLine ? pu->uszCommandLine : "");
        }
        _snprintf_s(hEPC->uszProcessTXT, _countof(hEPC->uszProcessTXT), _TRUNCATE,
            "PID:          %u\nProcess Name: %s\nProcess Path: %s\nCommandLine:  %s\nUser:         %s\nCreated:      %s\n",
            peMatch->dwPID,
            pObProcess->pObPersistent->uszNameLong,
            pObProcess->pObPersistent->uszPathKernel,
            uszCommandLine,
            uszUserName,
            szTimeCRE
        );
        _snprintf_s(hEPC->uszProcessCSV, _countof(hEPC->uszProcessCSV), _TRUNCATE,
            ",%i,%s,%s,%s,%s,%s",
            peMatch->dwPID,
            FcCsv_String(&hEPC->hCSV, pObProcess->pObPersistent->uszNameLong),
            FcCsv_String(&hEPC->hCSV, pObProcess->pObPersistent->uszPathKernel),
            FcCsv_String(&hEPC->hCSV, uszCommandLine),
            FcCsv_String(&hEPC->hCSV, uszUserName),
            FcCsv_FileTime(&hEPC->hCSV, VmmProcess_GetCreateTimeOpt(H, pObProcess))
        );
    } else {
        hEPC->uszProcessTXT[0] = 0;
        strncpy_s(hEPC->uszProcessCSV, _countof(hEPC->uszProcessCSV), ",\"\",\"\",\"\",\"\",\"\",\"\"", _TRUNCATE);
    }
    // populate memory info:
    if(peMatch->vaObject) {
        _snprintf_s(hEPC->uszMemoryTXT, _countof(hEPC->uszMemoryTXT), _TRUNCATE,
            "Type:         Object Memory\nMemory Tag:   %s\nBase Address: 0x%016llx\n",
            peMatch->uszTag,
            peMatch->vaObject
        );
        _snprintf_s(hEPC->uszMemoryCSV, _countof(hEPC->uszMemoryCSV), _TRUNCATE,
            ",Object Memory,%s,\"\",%llx",
            FcCsv_String(&hEPC->hCSV, peMatch->uszTag),
            peMatch->vaObject
        );
    } else if(pObProcess) {
        if(!pObProcess->fUserOnly && VMM_KADDR(f32, peMatch->vaBase)) {
            if(VmmMap_GetPte(H, pObProcess, &pObPteMap, TRUE) && (pePte = VmmMap_GetPteEntry(H, pObPteMap, peMatch->vaBase))) {
                uszMemoryTag = pePte->uszText;
            }
            uszMemoryType = "Virtual Memory (PTE)";
        } else {
            if(VmmMap_GetVad(H, pObProcess, &pObVadMap, VMM_VADMAP_TP_FULL) && (peVad = VmmMap_GetVadEntry(H, pObVadMap, peMatch->vaBase))) {
                uszMemoryTag = peVad->uszText;
            }
            uszMemoryType = "Virtual Memory (VAD)";
        }
        _snprintf_s(hEPC->uszMemoryTXT, _countof(hEPC->uszMemoryTXT), _TRUNCATE,
            "Memory Type:  %s\nMemory Tag:   %s\nBase Address: 0x%016llx\n",
            uszMemoryType,
            uszMemoryTag,
            peMatch->vaBase
        );
        _snprintf_s(hEPC->uszMemoryCSV, _countof(hEPC->uszMemoryCSV), _TRUNCATE,
            ",%s,%s,%llx,\"\"",
            FcCsv_String(&hEPC->hCSV, uszMemoryType),
            FcCsv_String(&hEPC->hCSV, uszMemoryTag),
            peMatch->vaBase
        );
    } else {
        strncpy_s(hEPC->uszMemoryTXT, _countof(hEPC->uszMemoryTXT), "Type:         Physical Memory\n", _TRUNCATE);
        strncpy_s(hEPC->uszMemoryCSV, _countof(hEPC->uszMemoryCSV), ",\"Physical Memory\",\"\",\"\",\"\"", _TRUNCATE);
    }
    // populate match strings:
    hEPC->uszMatchTXT[0] = 0;
    hEPC->uszMatchContextTXT[0] = 0;
    o2 = _snprintf_s(hEPC->uszMatchTXT, _countof(hEPC->uszMatchTXT), _TRUNCATE, "Matches:\n");
    for(i = 0; i < peMatch->RuleMatch.cStrings; i++) {
        fFirst = TRUE;
        hEPC->usz[0] = 0;
        uszRuleMatchStringBuffer[0] = 0;
        CharUtil_ReplaceMultiple(uszRuleMatchStringBuffer, sizeof(uszRuleMatchStringBuffer), NULL, peMatch->RuleMatch.Strings[i].szString, NULL, -1, VMMYARAUTIL_TEXT_ALLOW, '_');
        o = _snprintf_s(hEPC->usz, _countof(hEPC->usz), _TRUNCATE, "[%s]:", uszRuleMatchStringBuffer);
        for(j = 0; j < peMatch->RuleMatch.Strings[i].cMatch; j++) {
            o += _snprintf_s(hEPC->usz + o, _countof(hEPC->usz) - o, _TRUNCATE,
                "%s%llx", (fFirst ? " " : ", "), peMatch->vaBase + (QWORD)peMatch->RuleMatch.Strings[i].cbMatchOffset[j]);
            fFirst = FALSE;
        }
        o2 += _snprintf_s(hEPC->uszMatchTXT + o2, _countof(hEPC->uszMatchTXT) - o2, _TRUNCATE, "%s\n", hEPC->usz);
    }
    // detailed match strings - (physical/virtual memory only - not objects)
    if(!peMatch->vaObject) {
        o2 = 0;
        for(i = 0; i < peMatch->RuleMatch.cStrings; i++) {
            for(j = 0; j < peMatch->RuleMatch.Strings[i].cMatch; j++) {
                cAddresses++;
                hEPC->usz[0] = 0;
                va = peMatch->vaBase + (QWORD)peMatch->RuleMatch.Strings[i].cbMatchOffset[j];
                uszRuleMatchStringBuffer[0] = 0;
                CharUtil_ReplaceMultiple(uszRuleMatchStringBuffer, sizeof(uszRuleMatchStringBuffer), NULL, peMatch->RuleMatch.Strings[i].szString, NULL, -1, VMMYARAUTIL_TEXT_ALLOW, '_');
                o = _snprintf_s(hEPC->usz, _countof(hEPC->usz), _TRUNCATE, "[%s] %llx:\n", uszRuleMatchStringBuffer, va);
                vaAlign = (max(va, 0x40) - 0x40) & ~0xf;
                VmmReadEx(H, pObProcess, vaAlign, pbBuffer, sizeof(pbBuffer), &cbRead, VMM_FLAG_ZEROPAD_ON_FAIL);
                if(cbRead) {
                    cbWrite = (DWORD)_countof(hEPC->usz) - o;
                    Util_FillHexAscii_WithAddress(pbBuffer, sizeof(pbBuffer), vaAlign, hEPC->usz + o, &cbWrite);
                }
                o2 += _snprintf_s(hEPC->uszMatchContextTXT + o2, _countof(hEPC->uszMatchContextTXT) - o2, _TRUNCATE, "\n%s", hEPC->usz);
                if(iMatchCSV < 5) {
                    iMatchCSV++;
                    oMatchCSV += _snprintf_s(hEPC->uszMatchContextCSV + oMatchCSV, _countof(hEPC->uszMatchContextCSV) - oMatchCSV, _TRUNCATE,
                        ",%s,%llx",
                        FcCsv_String(&hEPC->hCSV, uszRuleMatchStringBuffer),
                        va
                    );
                }
            }
        }
    }
    while(iMatchCSV < 5) {
        iMatchCSV++;
        oMatchCSV += _snprintf_s(hEPC->uszMatchContextCSV + oMatchCSV, _countof(hEPC->uszMatchContextCSV) - oMatchCSV, _TRUNCATE, ",\"\",\"\"");
    }
    if(dwType > sizeof(ctx->dwIdByType) / sizeof(DWORD)) { dwType = 0; }
    // finalize result:
    _snprintf_s(hEPC->uszResultTXT, _countof(hEPC->uszResultTXT), _TRUNCATE,
        "Match Index:  %i\nRule:         %s\nTags:         %s\n%s%s%s\n%s%s\n---------------------------------------------------------------------------------------\n\n",
        ctx->dwIdByType[dwType],
        peMatch->RuleMatch.szRuleIdentifier,
        hEPC->uszTagsTXT,
        hEPC->uszMetaTXT,
        hEPC->uszMemoryTXT,
        hEPC->uszProcessTXT,
        hEPC->uszMatchTXT,
        hEPC->uszMatchContextTXT
    );
    _snprintf_s(hEPC->uszResultCSV, _countof(hEPC->uszResultCSV), _TRUNCATE,
        "%i,%s%s%s%s,%i%s\n",
        ctx->dwIdByType[dwType],
        FcCsv_String(&hEPC->hCSV, hEPC->uszTagsCSV),
        hEPC->uszMetaCSV,
        hEPC->uszMemoryCSV,
        hEPC->uszProcessCSV,
        cAddresses,
        hEPC->uszMatchContextCSV
    );
    ctx->dwIdByType[dwType]++;
    // cleanup:
    Ob_DECREF(pObPteMap);
    Ob_DECREF(pObVadMap);
    Ob_DECREF(pObProcess);
    LocalFree(peMatch);
    return TRUE;
}



// ----------------------------------------------------------------------------
// SINGLE PROCESS YARA SEARCH FUNCTIONALITY:
// This is quite similar to VmmSearch binary search functionality.
// ----------------------------------------------------------------------------

typedef struct tdVMMYARAUTIL_SEARCH_INTERNAL_CONTEXT {
    PVMMYARA_RULES hVmmYaraRules;
    PVMM_PROCESS pProcess;
    POB_SET psvaResult;
    DWORD cb;
    BYTE pb[0x00100000];    // 1MB
} VMMYARAUTIL_SEARCH_INTERNAL_CONTEXT, *PVMMYARAUTIL_SEARCH_INTERNAL_CONTEXT;

BOOL VmmSearch_SearchRegion_YaraCB(_In_ PVOID pvContext, _In_ PVMMYARA_RULE_MATCH pRuleMatch, _In_reads_bytes_(cbBuffer) PBYTE pbBuffer, _In_ SIZE_T cbBuffer)
{
    DWORD i, j;
    PVMMDLL_YARA_CONFIG ctxs = (PVMMDLL_YARA_CONFIG)pvContext;
    PVMMYARAUTIL_SEARCH_INTERNAL_CONTEXT ctxi = (PVMMYARAUTIL_SEARCH_INTERNAL_CONTEXT)(SIZE_T)ctxs->_Reserved;
    if(pRuleMatch->dwVersion != VMMYARA_RULE_MATCH_VERSION) { return FALSE; }
    for(i = 0; i < pRuleMatch->cStrings; i++) {
        for(j = 0; j < pRuleMatch->Strings[i].cMatch; j++) {
            ObSet_Push(ctxi->psvaResult, ctxs->vaCurrent + pRuleMatch->Strings[i].cbMatchOffset[j]);
        }
    }
    ctxs->cResult = ObSet_Size(ctxi->psvaResult);
    if(ctxs->cResult >= ctxs->cMaxResult) {
        ctxs->fAbortRequested = TRUE;
        return FALSE;
    }
    if(!ctxs->pfnScanMemoryCB) {
        return TRUE;
    }
    return ctxs->pfnScanMemoryCB(ctxs->pvUserPtrOpt, pRuleMatch, pbBuffer, cbBuffer);
}

/*
* Search data inside region.
*/
_Success_(return)
BOOL VmmYaraUtil_SearchRegion(_In_ VMM_HANDLE H, _In_ PVMMYARAUTIL_SEARCH_INTERNAL_CONTEXT ctxi, _In_ PVMMDLL_YARA_CONFIG ctxs)
{
    DWORD cbRead;
    VMMYARA_ERROR yrerr;
    if(ctxs->fAbortRequested || H->fAbort) {
        ctxs->fAbortRequested = TRUE;
        return FALSE;
    }
    ctxs->cbReadTotal += ctxi->cb;
    VmmReadEx(H, ctxi->pProcess, ctxs->vaCurrent, ctxi->pb, ctxi->cb, &cbRead, ctxs->ReadFlags | VMM_FLAG_ZEROPAD_ON_FAIL);
    if(!cbRead || Util_IsZeroBuffer(ctxi->pb, ctxi->cb)) {
        return TRUE;
    }
    if(Util_IsZeroBuffer(ctxi->pb, ctxi->cb)) {
        return TRUE;
    }
    yrerr = VmmYara_ScanMemory(
        ctxi->hVmmYaraRules,
        ctxi->pb,
        ctxi->cb,
        VMMYARA_SCAN_FLAGS_FAST_MODE | VMMYARA_SCAN_FLAGS_REPORT_RULES_MATCHING,
        VmmSearch_SearchRegion_YaraCB,
        ctxs,
        0
    );
    return yrerr == VMMYARA_ERROR_SUCCESS;
}

/*
* Search a physical/virtual address range.
*/
_Success_(return)
BOOL VmmYaraUtil_SearchRange(_In_ VMM_HANDLE H, _In_ PVMMYARAUTIL_SEARCH_INTERNAL_CONTEXT ctxi, _In_ PVMMDLL_YARA_CONFIG ctxs, _In_ QWORD vaMax)
{
    while(ctxs->vaCurrent < vaMax) {
        ctxi->cb = (DWORD)min(0x00100000, vaMax + 1 - ctxs->vaCurrent);
        if(!VmmYaraUtil_SearchRegion(H, ctxi, ctxs)) { return FALSE; }
        ctxs->vaCurrent += ctxi->cb;
        if(!ctxs->vaCurrent) {
            ctxs->vaCurrent = 0xfffffffffffff000;
            break;
        }
    }
    return TRUE;
}

/*
* Search virtual address space by walking either PTEs or VADs.
*/
_Success_(return)
BOOL VmmYaraUtil_VirtPteVad(_In_ VMM_HANDLE H, _In_ PVMMYARAUTIL_SEARCH_INTERNAL_CONTEXT ctxi, _In_ PVMMDLL_YARA_CONFIG ctxs)
{
    BOOL fResult = FALSE;
    DWORD ie = 0;
    QWORD cbPTE, vaMax;
    PVMMOB_MAP_PTE pObPTE = NULL;
    PVMMOB_MAP_VAD pObVAD = NULL;
    PVMM_MAP_PTEENTRY pePTE;
    PVMM_MAP_VADENTRY peVAD;
    ctxs->cResult = 0;
    ctxs->cbReadTotal = 0;
    ctxs->vaCurrent = ctxs->vaMin;
    if(ctxs->fForceVAD || (ctxi->pProcess->fUserOnly && !ctxs->fForcePTE)) {
        // VAD method:
        if(!VmmMap_GetVad(H, ctxi->pProcess, &pObVAD, VMM_VADMAP_TP_CORE)) { goto fail; }
        for(ie = 0; ie < pObVAD->cMap; ie++) {
            peVAD = pObVAD->pMap + ie;
            if(peVAD->vaStart + peVAD->vaEnd < ctxs->vaMin) { continue; }   // skip entries below min address
            if(peVAD->vaStart > ctxs->vaMax) { break; }                     // break if entry above max address
            if(peVAD->vaEnd - peVAD->vaStart > 0x40000000) { continue; }    // don't process 1GB+ entries
            if(ctxs->pfnFilterOptCB && !ctxs->pfnFilterOptCB(ctxs, NULL, (PVMMDLL_MAP_VADENTRY)peVAD)) { continue; }
            // TODO: is peVAD->vaEnd == 0xfff ????
            ctxs->vaCurrent = max(ctxs->vaCurrent, peVAD->vaStart);
            vaMax = min(ctxs->vaMax, peVAD->vaEnd);
            if(!VmmYaraUtil_SearchRange(H, ctxi, ctxs, vaMax)) { goto fail; }
        }
    } else {
        // PTE method:
        if(!VmmMap_GetPte(H, ctxi->pProcess, &pObPTE, FALSE)) { goto fail; }
        for(ie = 0; ie < pObPTE->cMap; ie++) {
            pePTE = pObPTE->pMap + ie;
            cbPTE = pePTE->cPages << 12;
            if(pePTE->vaBase + cbPTE < ctxs->vaMin) { continue; }           // skip entries below min address
            if(pePTE->vaBase > ctxs->vaMax) { break; }                      // break if entry above max address
            if(cbPTE > 0x40000000) { continue; }                            // don't process 1GB+ entries
            if(ctxs->pfnFilterOptCB && !ctxs->pfnFilterOptCB(ctxs, (PVMMDLL_MAP_PTEENTRY)pePTE, NULL)) { continue; }
            ctxs->vaCurrent = max(ctxs->vaCurrent, pePTE->vaBase);
            vaMax = min(ctxs->vaMax, pePTE->vaBase + cbPTE - 1);
            if(!VmmYaraUtil_SearchRange(H, ctxi, ctxs, vaMax)) { goto fail; }
        }
    }
    fResult = TRUE;
fail:
    Ob_DECREF(pObPTE);
    Ob_DECREF(pObVAD);
    return fResult;
}

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
BOOL VmmYaraUtil_SearchSingleProcess(_In_ VMM_HANDLE H, _In_opt_ PVMM_PROCESS pProcess, _Inout_ PVMMDLL_YARA_CONFIG ctxs, _Out_opt_ POB_DATA *ppObAddressResult)
{
    BOOL fResult = FALSE;
    PVMMYARAUTIL_SEARCH_INTERNAL_CONTEXT ctxi = NULL;
    // 1: sanity checks and fix-ups
    if(ppObAddressResult) { *ppObAddressResult = NULL; }
    ctxs->vaMin = ctxs->vaMin & ~0xfff;
    ctxs->vaMax = (ctxs->vaMax - 1) | 0xfff;
    if(!ctxs->cMaxResult || (ctxs->cMaxResult > VMMDLL_YARA_CONFIG_MAX_RESULT)) { ctxs->cMaxResult = VMMDLL_YARA_CONFIG_MAX_RESULT; }
    if(H->fAbort || ctxs->fAbortRequested || !ctxs->cRules || !ctxs->pszRules || (ctxs->vaMax < ctxs->vaMin)) { goto fail; }
    if(!ctxs->vaMax) {
        if(!pProcess) {
            ctxs->vaMax = H->dev.paMax;
        } else if(H->vmm.tpMemoryModel == VMMDLL_MEMORYMODEL_X64) {
            ctxs->vaMax = (QWORD)-1;
        } else {
            ctxs->vaMax = (DWORD)-1;
        }
    }
    // 2: allocate
    if(!(ctxi = LocalAlloc(LMEM_ZEROINIT, sizeof(VMMYARAUTIL_SEARCH_INTERNAL_CONTEXT)))) { goto fail; }
    if(!(ctxi->psvaResult = ObSet_New(H))) { goto fail; }
    ctxs->_Reserved = (QWORD)(SIZE_T)ctxi;
    ctxi->pProcess = pProcess;
    // 3: load yara rules
    if(ctxs->cRules == 1) {
        VmmYara_RulesLoadCompiled(ctxs->pszRules[0], &ctxi->hVmmYaraRules);
    }
    if(!ctxi->hVmmYaraRules) {
        VmmYara_RulesLoadSourceString(ctxs->cRules, ctxs->pszRules, &ctxi->hVmmYaraRules);
    }
    if(!ctxi->hVmmYaraRules) {
        VmmYara_RulesLoadSourceFile(ctxs->cRules, ctxs->pszRules, &ctxi->hVmmYaraRules);
    }
    if(!ctxi->hVmmYaraRules) { goto fail; }
    // 4: perform search
    if(pProcess && (ctxs->fForcePTE || ctxs->fForceVAD || (H->vmm.tpMemoryModel == VMMDLL_MEMORYMODEL_X64))) {
        fResult = VmmYaraUtil_VirtPteVad(H, ctxi, ctxs);
    } else {
        ctxs->vaCurrent = ctxs->vaMin;
        fResult = VmmYaraUtil_SearchRange(H, ctxi, ctxs, ctxs->vaMax);
    }
    fResult = fResult || (ctxs->cResult && (ctxs->cResult == ctxs->cMaxResult));
    // 5: finish
    if(fResult && ppObAddressResult) {
        *ppObAddressResult = ObSet_GetAll(ctxi->psvaResult);
        fResult = (*ppObAddressResult ? TRUE : FALSE);
    }
fail:
    if(ctxi) {
        if(ctxi->hVmmYaraRules) { VmmYara_RulesDestroy(ctxi->hVmmYaraRules); }
        Ob_DECREF(ctxi->psvaResult);
        LocalFree(ctxi);
    }
    ctxs->_Reserved = 0;
    return fResult;
}
