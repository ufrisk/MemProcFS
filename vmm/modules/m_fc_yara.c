// m_fc_yara.c : implementation of YARA scanning forensic module.
//
// REQUIRE: FORENSIC SUB-SYSTEM INIT
//
// (c) Ulf Frisk, 2023
// Author: Ulf Frisk, pcileech@frizk.net
//

#include "modules.h"
#include "../vmmyarautil.h"

#define MFC_YARA_MAX_MATCHES    0x10000

typedef struct tdMFCYARA_CONTEXT {
    DWORD cMatches;
    POB_MEMFILE pmfObMemFile;
    PVMMYARAUTILOB_CONTEXT ctxObInit;
} MFCYARA_CONTEXT, *PMFCYARA_CONTEXT;

VOID MFcYara_IngestVirtmem(_In_ VMM_HANDLE H, _In_opt_ PVOID ctxfc, _In_ PVMMDLL_PLUGIN_FORENSIC_INGEST_VIRTMEM pIngestVirtmem)
{
    PMFCYARA_CONTEXT ctx = (PMFCYARA_CONTEXT)ctxfc;
    VMMYARAUTIL_SCAN_CONTEXT ctxScan;
    if(!ctx || (VmmYaraUtil_MatchCount(ctx->ctxObInit) >= MFC_YARA_MAX_MATCHES)) { return; }
    ctxScan.ctx = ctx->ctxObInit;
    ctxScan.dwPID = pIngestVirtmem->dwPID;
    ctxScan.qwA = pIngestVirtmem->va;
    ctxScan.pb = pIngestVirtmem->pb;
    ctxScan.cb = pIngestVirtmem->cb;
    VmmYara_ScanMemory(
        VmmYaraUtil_Rules(ctx->ctxObInit),
        pIngestVirtmem->pb,
        pIngestVirtmem->cb,
        VMMYARA_SCAN_FLAGS_FAST_MODE | VMMYARA_SCAN_FLAGS_REPORT_RULES_MATCHING,
        (VMMYARA_SCAN_MEMORY_CALLBACK)VmmYaraUtil_MatchCB,
        &ctxScan,
        0
    );
}

VOID MFcYara_FcFinalize(_In_ VMM_HANDLE H, _In_opt_ PVOID ctxfc)
{
    PMFCYARA_CONTEXT ctx = (PMFCYARA_CONTEXT)ctxfc;
    LPSTR uszTXT, uszCSV;
    if(!ctx) { return; }
    if(!(VmmYaraUtil_IngestFinalize(H, ctx->ctxObInit))) { goto fail; }
    FcFileAppend(H, "yara.csv", VMMYARAUTIL_CSV_HEADER);
    while(VmmYaraUtil_ParseSingleResultNext(H, ctx->ctxObInit, &uszTXT, &uszCSV)) {
        ObMemFile_AppendString(ctx->pmfObMemFile, uszTXT);
        FcFileAppend(H, "yara.csv", "%s", uszCSV);
        ctx->cMatches++;
    }
    PluginManager_SetVisibility(H, TRUE, "\\forensic\\yara", TRUE);
fail:
    Ob_DECREF_NULL(&ctx->ctxObInit);
}

PVOID MFcYara_FcInitialize(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_CONTEXT ctxP)
{
    PMFCYARA_CONTEXT ctx = (PMFCYARA_CONTEXT)ctxP->ctxM;
    VMMYARA_ERROR err;
    PVMMYARA_RULES pYrRules = NULL;
    LPSTR szYaraRules = H->cfg.szForensicYaraRules;
    err = VmmYara_RulesLoadCompiled(szYaraRules, &pYrRules);
    if(VMMYARA_ERROR_SUCCESS != err) {
        err = VmmYara_RulesLoadSourceFile(1, &szYaraRules, &pYrRules);
    }
    if(VMMYARA_ERROR_SUCCESS != err) {
        VMMDLL_Log(H, ctxP->MID, LOGLEVEL_2_WARNING, "yr_initialize() failed with error code %i", err);
        return NULL;
    }
    ctx->ctxObInit = VmmYaraUtil_Initialize(H, &pYrRules, MFC_YARA_MAX_MATCHES);
    if(!ctx->ctxObInit) {
        VmmYara_RulesDestroy(pYrRules);
        return NULL;
    }
    return ctx;
}

NTSTATUS MFcYara_Read(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_CONTEXT ctxP, _Out_writes_to_(cb, *pcbRead) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset)
{
    PMFCYARA_CONTEXT ctx = (PMFCYARA_CONTEXT)ctxP->ctxM;
    if(CharUtil_StrEquals(ctxP->uszPath, "result.txt", TRUE)) {
        return ObMemFile_ReadFile(ctx->pmfObMemFile, pb, cb, pcbRead, cbOffset);
    }
    if(CharUtil_StrEquals(ctxP->uszPath, "match-count.txt", TRUE)) {
        return Util_VfsReadFile_FromNumber(ctx->cMatches, pb, cb, pcbRead, cbOffset);
    }
    return VMMDLL_STATUS_FILE_INVALID;
}

BOOL MFcYara_List(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_CONTEXT ctxP, _Inout_ PHANDLE pFileList)
{
    PMFCYARA_CONTEXT ctx = (PMFCYARA_CONTEXT)ctxP->ctxM;
    if(ctxP->uszPath[0]) { return FALSE; }

    VMMDLL_VfsList_AddFile(pFileList, "match-count.txt", Util_GetNumDigits(ctx->cMatches), NULL);
    VMMDLL_VfsList_AddFile(pFileList, "result.txt", ObMemFile_Size(ctx->pmfObMemFile), NULL);
    return TRUE;
}

VOID MFcYara_Close(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_CONTEXT ctxP)
{
    PMFCYARA_CONTEXT ctx = (PMFCYARA_CONTEXT)ctxP->ctxM;
    if(ctx) {
        Ob_DECREF(ctx->pmfObMemFile);
        Ob_DECREF(ctx->ctxObInit);
        LocalFree(ctx);
    }
}

VOID M_FcYara_Initialize(_In_ VMM_HANDLE H, _Inout_ PVMMDLL_PLUGIN_REGINFO pRI)
{
    PMFCYARA_CONTEXT ctx = NULL;
    if((pRI->magic != VMMDLL_PLUGIN_REGINFO_MAGIC) || (pRI->wVersion != VMMDLL_PLUGIN_REGINFO_VERSION)) { return; }
    if(!H->cfg.szForensicYaraRules[0]) { return; }
    if(!(ctx = LocalAlloc(LMEM_ZEROINIT, sizeof(MFCYARA_CONTEXT)))) { return; }
    if(!(ctx->pmfObMemFile = ObMemFile_New(H, H->vmm.pObCacheMapObCompressedShared))) { return; }
    pRI->reg_info.ctxM = (PVMMDLL_PLUGIN_INTERNAL_CONTEXT)ctx;
    strcpy_s(pRI->reg_info.uszPathName, 128, "\\forensic\\yara");
    pRI->reg_info.fRootModule = TRUE;
    pRI->reg_info.fRootModuleHidden = TRUE;
    pRI->reg_fn.pfnList = MFcYara_List;
    pRI->reg_fn.pfnRead = MFcYara_Read;
    pRI->reg_fn.pfnClose = MFcYara_Close;
    pRI->reg_fnfc.pfnInitialize = MFcYara_FcInitialize;
    pRI->reg_fnfc.pfnIngestVirtmem = MFcYara_IngestVirtmem;
    pRI->reg_fnfc.pfnFinalize = MFcYara_FcFinalize;
    pRI->pfnPluginManager_Register(H, pRI);
}
