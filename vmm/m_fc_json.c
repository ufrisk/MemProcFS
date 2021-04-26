// m_fc_json.c : implementation of JSON output.
//
// REQUIRE: FORENSIC SUB-SYSTEM INIT
//
// (c) Ulf Frisk, 2021
// Author: Ulf Frisk, pcileech@frizk.net
//

#include "fc.h"
#include "vmm.h"
#include "pluginmanager.h"
#include "util.h"
#include "version.h"
#include "resource.h"

/*
* Read the json version of the timeline info files.
*/
NTSTATUS M_FcJSON_TimelineReadInfo(_Out_ PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset)
{
    NTSTATUS nt = VMMDLL_STATUS_FILE_INVALID;
    PFC_MAP_TIMELINEENTRY pe;
    PFCOB_MAP_TIMELINE pObMap = NULL;
    QWORD i, o, cbln, qwIdBase, qwIdTop, cId, cszuBuffer, cbOffsetBuffer;
    LPSTR szuBuffer = NULL;
    DWORD dwEntryType, dwEntryAction;
    CHAR szTime[21];
    if(!FcTimeline_GetIdFromPosition(0, TRUE, cbOffset, &qwIdBase)) { goto fail; }
    if(!FcTimeline_GetIdFromPosition(0, TRUE, cbOffset + cb, &qwIdTop)) { goto fail; }
    cId = min(cb / FC_LINELENGTH_TIMELINE_JSON, qwIdTop - qwIdBase) + 1;
    if(!FcTimelineMap_GetFromIdRange(0, qwIdBase, cId, &pObMap) || !pObMap->cMap) { goto fail; }
    cbOffsetBuffer = pObMap->pMap[0].cszjOffset;
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
            "{\"class\":\"TL\",\"ver\":\"%i.%i\",\"sys\":\"%s\",\"date\":\"%s\",\"type\":\"%s\",\"action\":\"%s\",\"pid\":%u,\"num\":%u,\"hex\":\"%llx\",\"desc\":\"",
            VERSION_MAJOR, VERSION_MINOR,
            ctxVmm->szSystemUniqueTag,
            szTime,
            ctxFc->Timeline.pInfo[dwEntryType].szNameShort,
            FC_TIMELINE_ACTION_STR[dwEntryAction],
            pe->pid,
            pe->data32,
            pe->data64
        );
        o += Util_JsonEscape(pe->szuText, (DWORD)(cszuBuffer - o), szuBuffer + o);
        o += snprintf(szuBuffer + o, cszuBuffer - o, "\"}%*s\n", (DWORD)min(64, FC_LINELENGTH_TIMELINE_JSON - cbln - 3), "");
    }
    nt = Util_VfsReadFile_FromPBYTE(szuBuffer, o, pb, cb, pcbRead, cbOffset - cbOffsetBuffer);
fail:
    LocalFree(szuBuffer);
    Ob_DECREF(pObMap);
    return nt;
}

NTSTATUS M_FcJSON_Read(_In_ PVMMDLL_PLUGIN_CONTEXT ctx, _Out_writes_to_(cb, *pcbRead) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset)
{
    NTSTATUS nt = STATUS_END_OF_FILE;
    DWORD cbRead = 0;
    QWORD cbGen = ObMemFile_Size(ctxFc->FileJSON.pGen);
    if(!_wcsicmp(ctx->wszPath, L"elastic_import.ps1")) {
        return Util_VfsReadFile_FromResource(L"RCFILE_FC_JSON_ELASTIC_IMPORT", pb, cb, pcbRead, cbOffset);
    }
    if(!_wcsicmp(ctx->wszPath, L"general.json")) {
        return ObMemFile_ReadFile(ctxFc->FileJSON.pGen, pb, cb, pcbRead, cbOffset);
    }
    if(!_wcsicmp(ctx->wszPath, L"general-v.json")) {
        *pcbRead = 0;
        if(cbOffset < cbGen) {
            nt = ObMemFile_ReadFile(ctxFc->FileJSON.pGen, pb, cb, &cbRead, cbOffset);
            pb += cbRead;
            cb -= cbRead;
            cbOffset += cbRead;
        }
        if(cb && (cbOffset >= cbGen)) {
            nt = ObMemFile_ReadFile(ctxFc->FileJSON.pGenVerbose, pb, cb, pcbRead, cbOffset - cbGen);
        }
        *pcbRead += cbRead;
        return nt;
    }
    if(!_wcsicmp(ctx->wszPath, L"registry.json")) {
        return ObMemFile_ReadFile(ctxFc->FileJSON.pReg, pb, cb, pcbRead, cbOffset);
    }
    if(!_wcsicmp(ctx->wszPath, L"timeline.json")) {
        return M_FcJSON_TimelineReadInfo(pb, cb, pcbRead, cbOffset);
    }
    return VMMDLL_STATUS_FILE_INVALID;
}

BOOL M_FcJSON_List(_In_ PVMMDLL_PLUGIN_CONTEXT ctx, _Inout_ PHANDLE pFileList)
{
    PFC_TIMELINE_INFO pi = ctxFc->Timeline.pInfo + 0;
    if(ctx->wszPath[0]) { return FALSE; }
    VMMDLL_VfsList_AddFile_NOZERO(pFileList, L"elastic_import.ps1", Util_ResourceSize(L"RCFILE_FC_JSON_ELASTIC_IMPORT"), NULL);
    VMMDLL_VfsList_AddFile(pFileList, L"general.json", ObMemFile_Size(ctxFc->FileJSON.pGen), NULL);
    VMMDLL_VfsList_AddFile(pFileList, L"general-v.json", ObMemFile_Size(ctxFc->FileJSON.pGen) + ObMemFile_Size(ctxFc->FileJSON.pGenVerbose), NULL);
    VMMDLL_VfsList_AddFile(pFileList, L"registry.json", ObMemFile_Size(ctxFc->FileJSON.pReg), NULL);
    VMMDLL_VfsList_AddFile(pFileList, L"timeline.json", pi->dwFileSizeJSON, NULL);
    return TRUE;
}

VOID M_FcJSON_Notify(_In_ PVMMDLL_PLUGIN_CONTEXT ctxP, _In_ DWORD fEvent, _In_opt_ PVOID pvEvent, _In_opt_ DWORD cbEvent)
{
    if(fEvent == VMMDLL_PLUGIN_NOTIFY_FORENSIC_INIT_COMPLETE) {
        PluginManager_SetVisibility(TRUE, L"\\forensic\\json", TRUE);
    }
}

VOID M_FcJSON_Initialize(_Inout_ PVMMDLL_PLUGIN_REGINFO pRI)
{
    if((pRI->magic != VMMDLL_PLUGIN_REGINFO_MAGIC) || (pRI->wVersion != VMMDLL_PLUGIN_REGINFO_VERSION)) { return; }
    if((pRI->tpSystem != VMM_SYSTEM_WINDOWS_X64) && (pRI->tpSystem != VMM_SYSTEM_WINDOWS_X86)) { return; }
    if(ctxMain->dev.fVolatile) { return; }
    wcscpy_s(pRI->reg_info.wszPathName, 128, L"\\forensic\\json");              // module name
    pRI->reg_info.fRootModule = TRUE;                                           // module shows in root directory
    pRI->reg_info.fRootModuleHidden = TRUE;                                     // module hidden by default
    pRI->reg_fn.pfnList = M_FcJSON_List;                                        // List function supported
    pRI->reg_fn.pfnRead = M_FcJSON_Read;                                        // Read function supported
    pRI->reg_fn.pfnNotify = M_FcJSON_Notify;                                    // Notify function supported
    pRI->pfnPluginManager_Register(pRI);
}
