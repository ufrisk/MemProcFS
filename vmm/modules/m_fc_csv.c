// m_fc_csv.c : implementation of csv file functionality (general & timelining)
//
// REQUIRE: FORENSIC SUB-SYSTEM INIT: TIMELINE
//
// (c) Ulf Frisk, 2022-2025
// Author: Ulf Frisk, pcileech@frizk.net
//

#include "modules.h"

#define MFCCSV_TIMELINE_LINEHEADER      "Time,Type,Action,PID,Value32,Value64,Text,Pad\n"

/*
* Read the csv version of the timeline info files.
*/
NTSTATUS M_FcCSV_ReadTimeline2(_In_ VMM_HANDLE H, _In_ DWORD dwTimelineType, _Out_ PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset)
{
    NTSTATUS nt = VMMDLL_STATUS_END_OF_FILE;
    PFC_MAP_TIMELINEENTRY pe;
    PFCOB_MAP_TIMELINE pObMap = NULL;
    QWORD i, o, cch, qwIdBase, qwIdTop, cId, cszuBuffer, cbOffsetBuffer;
    LPSTR szuBuffer = NULL;
    DWORD cbv, dwEntryType, dwEntryAction;
    CHAR szTime[22];
    if(!FcTimeline_GetIdFromPosition(H, dwTimelineType, FC_FORMAT_TYPE_CSV, cbOffset, &qwIdBase)) { goto fail; }
    if(!FcTimeline_GetIdFromPosition(H, dwTimelineType, FC_FORMAT_TYPE_CSV, cbOffset + cb, &qwIdTop)) { goto fail; }
    cId = min(cb / FC_LINELENGTH_TIMELINE_CSV, qwIdTop - qwIdBase) + 1;
    if(!FcTimelineMap_GetFromIdRange(H, dwTimelineType, qwIdBase, cId, &pObMap) || !pObMap->cMap) { goto fail; }
    cbOffsetBuffer = pObMap->pMap[0].cvszOffset;
    if((cbOffsetBuffer > cbOffset) || (cbOffset - cbOffsetBuffer > 0x10000)) { goto fail; }
    cszuBuffer = 0x01000000;
    if(!(szuBuffer = LocalAlloc(0, (SIZE_T)cszuBuffer))) { goto fail; }
    for(i = 0, o = 0; (i < pObMap->cMap) && (o < cszuBuffer - 0x1000); i++) {
        pe = pObMap->pMap + i;
        Util_FileTime2CSV(pe->ft, szTime);
        dwEntryType = (pe->tp < H->fc->Timeline.cTp) ? pe->tp : 0;
        dwEntryAction = (pe->ac <= FC_TIMELINE_ACTION_MAX) ? pe->ac : FC_TIMELINE_ACTION_NONE;
        cch = snprintf(
            szuBuffer + o,
            (SIZE_T)(cszuBuffer - o),
            "%s,%s,%s,%u,0x%x,0x%llx,",
            szTime,
            H->fc->Timeline.pInfo[dwEntryType].szNameShort,
            FC_TIMELINE_ACTION_STR[dwEntryAction],
            pe->pid,
            pe->data32,
            pe->data64
        );
        o += cch;
        CharUtil_UtoCSV(pe->uszText, -1, szuBuffer + o, min((DWORD)(pe->cvszText + 1), (DWORD)(cszuBuffer - o)), NULL, &cbv, CHARUTIL_FLAG_STR_BUFONLY);
        o += cbv - 1;
        o += snprintf(
            szuBuffer + o,
            (SIZE_T)(cszuBuffer - o),
            ",\"%*s\"\n",
            (DWORD)(FC_LINELENGTH_TIMELINE_CSV - cch - 4),
            ""
        );
    }
    nt = Util_VfsReadFile_FromPBYTE(szuBuffer, o, pb, cb, pcbRead, cbOffset - cbOffsetBuffer);
fail:
    LocalFree(szuBuffer);
    Ob_DECREF(pObMap);
    return nt;
}

/*
* Read the csv version of the timeline info files.
*/
NTSTATUS M_FcCSV_ReadTimeline(_In_ VMM_HANDLE H, _In_ DWORD dwTimelineType, _Out_ PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset)
{
    NTSTATUS nt;
    DWORD cbHdr = 0, cbRead = 0;
    if(cbOffset < VMM_STRLEN(MFCCSV_TIMELINE_LINEHEADER)) {
        nt = Util_VfsReadFile_FromPBYTE((PBYTE)MFCCSV_TIMELINE_LINEHEADER, VMM_STRLEN(MFCCSV_TIMELINE_LINEHEADER), pb, cb, pcbRead, cbOffset);
        cbHdr = *pcbRead;
        if(cbHdr && (cb > cbHdr)) {
            M_FcCSV_ReadTimeline2(H, dwTimelineType, pb + cbHdr, cb - cbHdr, &cbRead, 0);
            *pcbRead = cbHdr + cbRead;
        }
        return nt;
    }
    return M_FcCSV_ReadTimeline2(H, dwTimelineType, pb, cb, pcbRead, cbOffset - VMM_STRLEN(MFCCSV_TIMELINE_LINEHEADER));
}

NTSTATUS M_FcCSV_Read(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_CONTEXT ctxP, _Out_writes_to_(cb, *pcbRead) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset)
{
    DWORD i;
    NTSTATUS nt;
    QWORD qwFileHash;
    PFC_TIMELINE_INFO pi;
    PFCOB_FILE pObFile = NULL;
    // 1: timeline
    for(i = 0; i < H->fc->Timeline.cTp; i++) {
        pi = H->fc->Timeline.pInfo + i;
        if(!_stricmp(ctxP->uszPath, pi->uszNameFileCSV)) {
            return M_FcCSV_ReadTimeline(H, pi->dwId, pb, cb, pcbRead, cbOffset);
        }
    }
    // 2: memory backed files:
    qwFileHash = CharUtil_Hash64U(ctxP->uszPath, TRUE);
    if((pObFile = ObMap_GetByKey(H->fc->FileCSV.pm, qwFileHash))) {
        nt = ObMemFile_ReadFile(pObFile->pmf, pb, cb, pcbRead, cbOffset);
        Ob_DECREF(pObFile);
        return nt;
    }
    return VMMDLL_STATUS_FILE_INVALID;
}

BOOL M_FcCSV_List(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_CONTEXT ctxP, _Inout_ PHANDLE pFileList)
{
    QWORD i;
    PFC_TIMELINE_INFO pi;
    PFCOB_FILE pObFile = NULL;
    if(ctxP->uszPath[0]) { return FALSE; }
    // 1: timeline
    for(i = 0; i < H->fc->Timeline.cTp; i++) {
        pi = H->fc->Timeline.pInfo + i;
        if(pi->uszNameFileTXT[0]) {
            VMMDLL_VfsList_AddFile(pFileList, pi->uszNameFileCSV, VMM_STRLEN(MFCCSV_TIMELINE_LINEHEADER) + pi->dwFileSizeCSV, NULL);
        }
    }
    // 2: memory backed files:
    while((pObFile = ObMap_GetNext(H->fc->FileCSV.pm, pObFile))) {
        VMMDLL_VfsList_AddFile(pFileList, pObFile->uszName, ObMemFile_Size(pObFile->pmf), NULL);
    }
    return TRUE;
}

VOID M_FcCSV_Notify(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_CONTEXT ctxP, _In_ DWORD fEvent, _In_opt_ PVOID pvEvent, _In_opt_ DWORD cbEvent)
{
    if(fEvent == VMMDLL_PLUGIN_NOTIFY_FORENSIC_INIT_COMPLETE) {
        PluginManager_SetVisibility(H, TRUE, "\\forensic\\csv", TRUE);
    }
}

VOID M_FcCSV_Initialize(_In_ VMM_HANDLE H, _Inout_ PVMMDLL_PLUGIN_REGINFO pRI)
{
    if((pRI->magic != VMMDLL_PLUGIN_REGINFO_MAGIC) || (pRI->wVersion != VMMDLL_PLUGIN_REGINFO_VERSION)) { return; }
    if((pRI->tpSystem != VMMDLL_SYSTEM_WINDOWS_64) && (pRI->tpSystem != VMMDLL_SYSTEM_WINDOWS_32)) { return; }
    strcpy_s(pRI->reg_info.uszPathName, 128, "\\forensic\\csv");                // module name
    pRI->reg_info.fRootModule = TRUE;                                           // module shows in root directory
    pRI->reg_info.fRootModuleHidden = TRUE;                                     // module hidden by default
    pRI->reg_fn.pfnList = M_FcCSV_List;                                         // List function supported
    pRI->reg_fn.pfnRead = M_FcCSV_Read;                                         // Read function supported
    pRI->reg_fn.pfnNotify = M_FcCSV_Notify;                                     // Notify function supported
    pRI->pfnPluginManager_Register(H, pRI);
}
