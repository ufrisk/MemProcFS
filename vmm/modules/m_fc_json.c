// m_fc_json.c : implementation of JSON output.
//
// REQUIRE: FORENSIC SUB-SYSTEM INIT
//
// (c) Ulf Frisk, 2021-2025
// Author: Ulf Frisk, pcileech@frizk.net
//

#include "modules.h"
#include "../version.h"

/*
* Read the json version of the timeline info files.
*/
NTSTATUS M_FcJSON_TimelineReadInfo(_In_ VMM_HANDLE H, _Out_ PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset)
{
    PFC_CONTEXT ctxFc = H->fc;
    NTSTATUS nt = VMMDLL_STATUS_FILE_INVALID;
    PFC_MAP_TIMELINEENTRY pe;
    PFCOB_MAP_TIMELINE pObMap = NULL;
    QWORD i, qwIdBase, qwIdTop, cId, cbOffsetBuffer;
    SIZE_T o, cbln, cszuBuffer;
    LPSTR szj, szuBuffer = NULL;
    DWORD dwEntryType, dwEntryAction;
    CHAR szTime[21];
    if(!FcTimeline_GetIdFromPosition(H, 0, FC_FORMAT_TYPE_JSON, cbOffset, &qwIdBase)) { goto fail; }
    if(!FcTimeline_GetIdFromPosition(H, 0, FC_FORMAT_TYPE_JSON, cbOffset + cb, &qwIdTop)) { goto fail; }
    cId = min(cb / FC_LINELENGTH_TIMELINE_JSON, qwIdTop - qwIdBase) + 1;
    if(!FcTimelineMap_GetFromIdRange(H, 0, qwIdBase, cId, &pObMap) || !pObMap->cMap) { goto fail; }
    cbOffsetBuffer = pObMap->pMap[0].cjszOffset;
    if((cbOffsetBuffer > cbOffset) || (cbOffset - cbOffsetBuffer > 0x10000)) { goto fail; }
    cszuBuffer = 0x01000000;
    if(!(szuBuffer = LocalAlloc(0, cszuBuffer))) { goto fail; }
    for(i = 0, o = 0; (i < pObMap->cMap) && (o < cszuBuffer - 0x1000); i++) {
        pe = pObMap->pMap + i;
        Util_FileTime2JSON(pe->ft, szTime);
        dwEntryType = (pe->tp < ctxFc->Timeline.cTp) ? pe->tp : 0;
        dwEntryAction = (pe->ac <= FC_TIMELINE_ACTION_MAX) ? pe->ac : FC_TIMELINE_ACTION_NONE;
        o += cbln = snprintf(
            szuBuffer + o,
            cszuBuffer - o,
            "{\"class\":\"TL\",\"ver\":\"%i.%i\",\"sys\":\"%s\",\"date\":\"%s\",\"type\":\"%-3s\",\"action\":\"%s\",\"pid\":%u,\"num\":%u,\"hex\":\"%llx\",\"desc\":\"",
            VERSION_MAJOR, VERSION_MINOR,
            H->vmm.szSystemUniqueTag,
            szTime,
            ctxFc->Timeline.pInfo[dwEntryType].szNameShort,
            FC_TIMELINE_ACTION_STR[dwEntryAction],
            pe->pid,
            pe->data32,
            pe->data64
        );
        CharUtil_UtoJ(pe->uszText, -1, szuBuffer + o, (DWORD)(cszuBuffer - o), &szj, NULL, CHARUTIL_FLAG_TRUNCATE_ONFAIL_NULLSTR);
        o += strlen(szuBuffer + o);
        o += snprintf(szuBuffer + o, cszuBuffer - o, "\"}%*s\n", (DWORD)min(64, FC_LINELENGTH_TIMELINE_JSON - cbln - 3), "");
    }
    nt = Util_VfsReadFile_FromPBYTE(szuBuffer, o, pb, cb, pcbRead, cbOffset - cbOffsetBuffer);
fail:
    LocalFree(szuBuffer);
    Ob_DECREF(pObMap);
    return nt;
}

NTSTATUS M_FcJSON_Read(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_CONTEXT ctxP, _Out_writes_to_(cb, *pcbRead) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset)
{
    PFC_CONTEXT ctxFc = H->fc;
    NTSTATUS nt = STATUS_END_OF_FILE;
    DWORD cbRead = 0;
    QWORD cbGen = ObMemFile_Size(ctxFc->FileJSON.pGen);
#ifdef _WIN32
    if(!_stricmp(ctxP->uszPath, "elastic_import.ps1")) {
        return Util_VfsReadFile_FromResource(H, L"RCFILE_FC_JSON_ELASTIC_IMPORT", pb, cb, pcbRead, cbOffset);
    }
    if(!_stricmp(ctxP->uszPath, "elastic_import_unauth.ps1")) {
        return Util_VfsReadFile_FromResource(H, L"RCFILE_FC_JSON_ELASTIC_IMPORT_UNAUTH", pb, cb, pcbRead, cbOffset);
    }
#endif /* _WIN32 */
    if(!_stricmp(ctxP->uszPath, "general.json")) {
        return ObMemFile_ReadFile(ctxFc->FileJSON.pGen, pb, cb, pcbRead, cbOffset);
    }
    if(!_stricmp(ctxP->uszPath, "registry.json")) {
        return ObMemFile_ReadFile(ctxFc->FileJSON.pReg, pb, cb, pcbRead, cbOffset);
    }
    if(!_stricmp(ctxP->uszPath, "timeline.json")) {
        return M_FcJSON_TimelineReadInfo(H, pb, cb, pcbRead, cbOffset);
    }
    return VMMDLL_STATUS_FILE_INVALID;
}

BOOL M_FcJSON_List(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_CONTEXT ctxP, _Inout_ PHANDLE pFileList)
{
    PFC_CONTEXT ctxFc = H->fc;
    PFC_TIMELINE_INFO pi = ctxFc->Timeline.pInfo + 0;    
    if(ctxP->uszPath[0] || !pi) { return FALSE; }
#ifdef _WIN32
    DWORD cbElasticPs1;
    if((cbElasticPs1 = Util_ResourceSize(H, L"RCFILE_FC_JSON_ELASTIC_IMPORT"))) {
        VMMDLL_VfsList_AddFile(pFileList, "elastic_import.ps1", cbElasticPs1, NULL);
    }
    if((cbElasticPs1 = Util_ResourceSize(H, L"RCFILE_FC_JSON_ELASTIC_IMPORT_UNAUTH"))) {
        VMMDLL_VfsList_AddFile(pFileList, "elastic_import_unauth.ps1", cbElasticPs1, NULL);
    }
#endif /* _WIN32 */
    VMMDLL_VfsList_AddFile(pFileList, "general.json", ObMemFile_Size(ctxFc->FileJSON.pGen), NULL);
    VMMDLL_VfsList_AddFile(pFileList, "registry.json", ObMemFile_Size(ctxFc->FileJSON.pReg), NULL);
    VMMDLL_VfsList_AddFile(pFileList, "timeline.json", pi->dwFileSizeJSON, NULL);
    return TRUE;
}

VOID M_FcJSON_Notify(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_CONTEXT ctxP, _In_ DWORD fEvent, _In_opt_ PVOID pvEvent, _In_opt_ DWORD cbEvent)
{
    if(fEvent == VMMDLL_PLUGIN_NOTIFY_FORENSIC_INIT_COMPLETE) {
        PluginManager_SetVisibility(H, TRUE, "\\forensic\\json", TRUE);
    }
}

VOID M_FcJSON_Initialize(_In_ VMM_HANDLE H, _Inout_ PVMMDLL_PLUGIN_REGINFO pRI)
{
    if((pRI->magic != VMMDLL_PLUGIN_REGINFO_MAGIC) || (pRI->wVersion != VMMDLL_PLUGIN_REGINFO_VERSION)) { return; }
    if((pRI->tpSystem != VMMDLL_SYSTEM_WINDOWS_64) && (pRI->tpSystem != VMMDLL_SYSTEM_WINDOWS_32)) { return; }
    strcpy_s(pRI->reg_info.uszPathName, 128, "\\forensic\\json");               // module name
    pRI->reg_info.fRootModule = TRUE;                                           // module shows in root directory
    pRI->reg_info.fRootModuleHidden = TRUE;                                     // module hidden by default
    pRI->reg_fn.pfnList = M_FcJSON_List;                                        // List function supported
    pRI->reg_fn.pfnRead = M_FcJSON_Read;                                        // Read function supported
    pRI->reg_fn.pfnNotify = M_FcJSON_Notify;                                    // Notify function supported
    pRI->pfnPluginManager_Register(H, pRI);
}
