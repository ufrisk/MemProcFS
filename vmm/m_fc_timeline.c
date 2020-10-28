// m_fc_timeline.c : implementation of timelining functionality.
//
// REQUIRE: FORENSIC SUB-SYSTEM INIT: TIMELINE
//
// (c) Ulf Frisk, 2020
// Author: Ulf Frisk, pcileech@frizk.net
//

#include "fc.h"
#include "vmm.h"
#include "pluginmanager.h"
#include "util.h"

NTSTATUS M_FcTimeline_ReadInfo(_In_ DWORD dwTimelineType, _Out_ PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset)
{
    NTSTATUS nt = VMMDLL_STATUS_FILE_INVALID;
    PFC_MAP_TIMELINEENTRY pe;
    PFCOB_MAP_TIMELINE pObMap = NULL;
    QWORD i, o, qwIdBase, qwIdTop, cId, cszuBuffer, cbOffsetBuffer;
    LPSTR szuBuffer = NULL;
    DWORD dwEntryType, dwEntryAction;
    CHAR szTime[24];
    if(!FcTimeline_GetIdFromPosition(dwTimelineType, FALSE, cbOffset, &qwIdBase)) { goto fail; }
    if(!FcTimeline_GetIdFromPosition(dwTimelineType, FALSE, cbOffset + cb, &qwIdTop)) { goto fail; }
    cId = min(cb / FC_LINELENGTH_TIMELINE_UTF8, qwIdTop - qwIdBase) + 1;
    if(!FcTimelineMap_GetFromIdRange(dwTimelineType, qwIdBase, cId, &pObMap) || !pObMap->cMap) { goto fail; }
    cbOffsetBuffer = pObMap->pMap[0].cszuOffset;
    if((cbOffsetBuffer > cbOffset) || (cbOffset - cbOffsetBuffer > 0x10000)) { goto fail; }
    cszuBuffer = 0x01000000;
    if(!(szuBuffer = LocalAlloc(0, cszuBuffer))) { goto fail; }
    for(i = 0, o = 0; (i < pObMap->cMap) && (o < cszuBuffer - 0x1000); i++) {
        pe = pObMap->pMap + i;
        Util_FileTime2String((PFILETIME)&pe->ft, szTime);
        dwEntryType = (pe->tp < ctxFc->Timeline.cTp) ? pe->tp : 0;
        dwEntryAction = (pe->ac <= FC_TIMELINE_ACTION_MAX) ? pe->ac : FC_TIMELINE_ACTION_NONE;
        o += snprintf(
            szuBuffer + o,
            cszuBuffer - o,
            "%s  %s %s%10i %16llx ",
            szTime,
            ctxFc->Timeline.pInfo[dwEntryType].szNameShort,
            FC_TIMELINE_ACTION_STR[dwEntryAction],
            pe->pid,
            pe->data64
        );
        o += WideCharToMultiByte(CP_UTF8, 0, pe->wszText, -1, szuBuffer + o, (int)(cszuBuffer - o), NULL, NULL);
        if(o && (o <= cszuBuffer)) {
            szuBuffer[o - 1] = '\n';
        }
    }
    nt = Util_VfsReadFile_FromPBYTE(szuBuffer, o, pb, cb, pcbRead, cbOffset - cbOffsetBuffer);
fail:
    LocalFree(szuBuffer);
    Ob_DECREF(pObMap);
    return nt;
}

NTSTATUS M_FcTimeline_Read(_In_ PVMMDLL_PLUGIN_CONTEXT ctx, _Out_writes_to_(cb, *pcbRead) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset)
{
    DWORD i;
    PFC_TIMELINE_INFO pi;
    for(i = 0; i < ctxFc->Timeline.cTp; i++) {
        pi = ctxFc->Timeline.pInfo + i;
        if(!wcscmp(ctx->wszPath, pi->wszNameFileUTF8)) {
            return M_FcTimeline_ReadInfo(pi->dwId, pb, cb, pcbRead, cbOffset);
        }
        //if(!wcscmp(ctx->wszPath, ctxFc->Timeline.pInfo[i].szNameFileJSON)) {
        //    return M_FcTimeline_ReadInfo(ctxFc->Timeline.pInfo[i].dwId, pb, cb, pcbRead, cbOffset);
        //}
    }
    return VMMDLL_STATUS_FILE_INVALID;
}

BOOL M_FcTimeline_List(_In_ PVMMDLL_PLUGIN_CONTEXT ctx, _Inout_ PHANDLE pFileList)
{
    QWORD i;
    PFC_TIMELINE_INFO pi;
    if(ctx->wszPath[0]) { return FALSE; }
    for(i = 0; i < ctxFc->Timeline.cTp; i++) {
        pi = ctxFc->Timeline.pInfo + i;
        if(pi->wszNameFileUTF8[0]) {
            VMMDLL_VfsList_AddFile(pFileList, pi->wszNameFileUTF8, pi->dwFileSizeUTF8, NULL);
        }
        //if(pi->wszNameFileJSON[0]) {
        //    VMMDLL_VfsList_AddFile(pFileList, pi->wszNameFileJSON, pi->dwFileSizeJSON, NULL);
        //}
    }
    return TRUE;
}

VOID M_FcTimeline_Notify(_In_ DWORD fEvent, _In_opt_ PVOID pvEvent, _In_opt_ DWORD cbEvent)
{
    if(fEvent == VMMDLL_PLUGIN_NOTIFY_FORENSIC_INIT_COMPLETE) {
        PluginManager_SetVisibility(TRUE, L"\\forensic\\timeline", TRUE);
    }
}

VOID M_FcTimeline_Initialize(_Inout_ PVMMDLL_PLUGIN_REGINFO pRI)
{
    if((pRI->magic != VMMDLL_PLUGIN_REGINFO_MAGIC) || (pRI->wVersion != VMMDLL_PLUGIN_REGINFO_VERSION)) { return; }
    if((pRI->tpSystem != VMM_SYSTEM_WINDOWS_X64) && (pRI->tpSystem != VMM_SYSTEM_WINDOWS_X86)) { return; }
    if(ctxMain->dev.fVolatile) { return; }
    wcscpy_s(pRI->reg_info.wszPathName, 128, L"\\forensic\\timeline");          // module name
    pRI->reg_info.fRootModule = TRUE;                                           // module shows in root directory
    pRI->reg_info.fRootModuleHidden = TRUE;                                     // module hidden by default
    pRI->reg_fn.pfnList = M_FcTimeline_List;                                    // List function supported
    pRI->reg_fn.pfnRead = M_FcTimeline_Read;                                    // Read function supported
    pRI->reg_fn.pfnNotify = M_FcTimeline_Notify;                                // Notify function supported
    pRI->pfnPluginManager_Register(pRI);
}
