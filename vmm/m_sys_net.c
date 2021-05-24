// m_sys_net.c : implementation related to the Sys/Net built-in module.
//
// The 'sys/net' module is responsible for displaying networking information
// in a 'netstat' like way at the path '/sys/net/'
//
// The module is a provider of forensic timelining information.
//
// (c) Ulf Frisk, 2020-2021
// Author: Ulf Frisk, pcileech@frizk.net
//
#include "vmm.h"
#include "util.h"
#include "fc.h"

LPCSTR szMSYSNET_README =
"Information about the sys net module                                         \n" \
"====================================                                         \n" \
"The sys/net module tries to enumerate and list active TCP connections in     \n" \
"Windows 7 and later (x64 only).  It currently does not support listening TCP \n" \
"ports or UDP ports. This functionality is planned for the future. Also, it's \n" \
"not supporting 32-bit or Windows Vista/XP (future support less likely).      \n" \
"For more information please visit: https://github.com/ufrisk/MemProcFS/wiki  \n";

// ----------------------------------------------------------------------------
// Net functionality below:
// Show information related to TCP/IP connectivity in the analyzed system.
// ----------------------------------------------------------------------------

#define MSYSNET_LINELENGTH                  128ULL
#define MSYSNET_LINELENGTH_VERBOSE          278ULL
#define MSYSNET_LINEHEADER                  "   #    PID Proto  State        Src                           Dst                          Process"
#define MSYSNET_LINEHEADER_VERBOSE          MSYSNET_LINEHEADER "              Time                     Object Address    Process Path"



VOID MSysNet_ReadLine_Callback(_Inout_opt_ PVOID ctx, _In_ DWORD cbLineLength, _In_ DWORD ie, _In_ PVMM_MAP_NETENTRY pe, _Out_writes_(cbLineLength + 1) LPSTR szu8)
{
    PVMM_PROCESS pObProcess = VmmProcessGet(pe->dwPID);
    Util_usnprintf_ln(szu8, cbLineLength,
        "%04x%7i %s %s",
        ie,
        pe->dwPID,
        pe->uszText,
        pObProcess ? pObProcess->pObPersistent->uszNameLong : ""
    );
    Ob_DECREF(pObProcess);
}

VOID MSysNet_ReadLineVerbose_Callback(_Inout_opt_ PVOID ctx, _In_ DWORD cbLineLength, _In_ DWORD ie, _In_ PVMM_MAP_NETENTRY pe, _Out_writes_(cbLineLength + 1) LPSTR szu8)
{
    CHAR szTime[24];
    PVMM_PROCESS pObProcess = VmmProcessGet(pe->dwPID);
    Util_FileTime2String(pe->ftTime, szTime);
    Util_usnprintf_ln(szu8, cbLineLength,
        "%04x%7i %s %-20s %s  %016llx  %s",
        ie,
        pe->dwPID,
        pe->uszText,
        pObProcess ? pObProcess->pObPersistent->uszNameLong : "",
        szTime,
        pe->vaObj,
        pObProcess ? pObProcess->pObPersistent->uszPathKernel : ""
    );
    Ob_DECREF(pObProcess);
}

NTSTATUS MSysNet_Read(_In_ PVMMDLL_PLUGIN_CONTEXT ctx, _Out_writes_to_(cb, *pcbRead) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset)
{
    NTSTATUS nt = VMMDLL_STATUS_FILE_INVALID;
    PVMMOB_MAP_NET pObNetMap;
    if(!_stricmp(ctx->uszPath, "readme.txt")) {
        return Util_VfsReadFile_FromPBYTE((PBYTE)szMSYSNET_README, strlen(szMSYSNET_README), pb, cb, pcbRead, cbOffset);
    }
    if(VmmMap_GetNet(&pObNetMap)) {
        if(!_stricmp(ctx->uszPath, "netstat.txt")) {
            nt = Util_VfsLineFixed_Read(
                (UTIL_VFSLINEFIXED_PFN_CB)MSysNet_ReadLine_Callback, NULL, MSYSNET_LINELENGTH, MSYSNET_LINEHEADER,
                pObNetMap->pMap, pObNetMap->cMap, sizeof(VMM_MAP_NETENTRY),
                pb, cb, pcbRead, cbOffset
            );
        }
        if(!_stricmp(ctx->uszPath, "netstat-v.txt")) {
            nt = Util_VfsLineFixed_Read(
                (UTIL_VFSLINEFIXED_PFN_CB)MSysNet_ReadLineVerbose_Callback, NULL, MSYSNET_LINELENGTH_VERBOSE, MSYSNET_LINEHEADER_VERBOSE,
                pObNetMap->pMap, pObNetMap->cMap, sizeof(VMM_MAP_NETENTRY),
                pb, cb, pcbRead, cbOffset
            );
        }
        Ob_DECREF(pObNetMap);
    }
    return nt;
}

BOOL MSysNet_List(_In_ PVMMDLL_PLUGIN_CONTEXT ctx, _Inout_ PHANDLE pFileList)
{
    PVMMOB_MAP_NET pObNetMap;
    if(ctx->uszPath[0]) { return FALSE; }
    VMMDLL_VfsList_AddFile(pFileList, "readme.txt", strlen(szMSYSNET_README), NULL);
    if(VmmMap_GetNet(&pObNetMap)) {
        VMMDLL_VfsList_AddFile(pFileList, "netstat.txt", UTIL_VFSLINEFIXED_LINECOUNT(pObNetMap->cMap) * MSYSNET_LINELENGTH, NULL);
        VMMDLL_VfsList_AddFile(pFileList, "netstat-v.txt", UTIL_VFSLINEFIXED_LINECOUNT(pObNetMap->cMap) * MSYSNET_LINELENGTH_VERBOSE, NULL);
        Ob_DECREF(pObNetMap);
    }
    return TRUE;
}

VOID MSysNet_Timeline(
    _In_opt_ PVOID ctxfc,
    _In_ HANDLE hTimeline,
    _In_ VOID(*pfnAddEntry)(_In_ HANDLE hTimeline, _In_ QWORD ft, _In_ DWORD dwAction, _In_ DWORD dwPID, _In_ DWORD dwData32, _In_ QWORD qwData64, _In_ LPSTR uszText),
    _In_ VOID(*pfnEntryAddBySql)(_In_ HANDLE hTimeline, _In_ DWORD cEntrySql, _In_ LPSTR *pszEntrySql)
) {
    DWORD i;
    PVMM_MAP_NETENTRY pe;
    PVMMOB_MAP_NET pObNetMap;
    if(VmmMap_GetNet(&pObNetMap)) {
        for(i = 0; i < pObNetMap->cMap; i++) {
            pe = pObNetMap->pMap + i;
            if(pe->ftTime && pe->uszText[0]) {
                pfnAddEntry(hTimeline, pe->ftTime, FC_TIMELINE_ACTION_CREATE, pe->dwPID, 0, pe->vaObj, pe->uszText);
            }
        }
        Ob_DECREF(pObNetMap);
    }
}

VOID MSysNet_FcLogJSON(_In_ PVMMDLL_PLUGIN_CONTEXT ctxP, _In_ VOID(*pfnLogJSON)(_In_ PVMMDLL_PLUGIN_FORENSIC_JSONDATA pData))
{
    PVMMDLL_PLUGIN_FORENSIC_JSONDATA pd;
    PVMMOB_MAP_NET pObNetMap = NULL;
    PVMM_MAP_NETENTRY pe;
    DWORD i;
    PVMM_PROCESS pObProcess = NULL;
    CHAR szTime[24], szu[MAX_PATH];
    if(ctxP->pProcess || !(pd = LocalAlloc(LMEM_ZEROINIT, sizeof(VMMDLL_PLUGIN_FORENSIC_JSONDATA)))) { return; }
    pd->dwVersion = VMMDLL_PLUGIN_FORENSIC_JSONDATA_VERSION;
    pd->szjType = "net";
    if(VmmMap_GetNet(&pObNetMap)) {
        for(i = 0; i < pObNetMap->cMap; i++) {
            pe = pObNetMap->pMap + i;
            szu[0] = 0;
            if((pObProcess = VmmProcessGet(pe->dwPID))) {
                Util_FileTime2String(pe->ftTime, szTime);
                snprintf(szu, _countof(szu), "proc:[%s] time:[%s] path:[%s]",
                    pObProcess ? pObProcess->pObPersistent->uszNameLong : "",
                    szTime,
                    pObProcess ? pObProcess->pObPersistent->uszPathKernel : "");
                Ob_DECREF_NULL(&pObProcess);
            }
            pd->i = i;
            pd->dwPID = pe->dwPID;
            pd->vaObj = pe->vaObj;
            pd->usz[0] = pe->uszText;
            pd->usz[1] = szu;
            pfnLogJSON(pd);
        }
    }
    Ob_DECREF(pObNetMap);
    LocalFree(pd);
}

VOID M_SysNet_Initialize(_Inout_ PVMMDLL_PLUGIN_REGINFO pRI)
{
    if((pRI->magic != VMMDLL_PLUGIN_REGINFO_MAGIC) || (pRI->wVersion != VMMDLL_PLUGIN_REGINFO_VERSION)) { return; }
    if((pRI->tpSystem != VMM_SYSTEM_WINDOWS_X64) && (pRI->tpSystem != VMM_SYSTEM_WINDOWS_X86)) { return; }
    strcpy_s(pRI->reg_info.uszPathName, 128, "\\sys\\net");     // module name
    pRI->reg_info.fRootModule = TRUE;                           // module shows in root directory
    pRI->reg_fn.pfnList = MSysNet_List;                         // List function supported
    pRI->reg_fn.pfnRead = MSysNet_Read;                         // Read function supported
    pRI->reg_fnfc.pfnTimeline = MSysNet_Timeline;               // Timeline supported
    pRI->reg_fnfc.pfnLogJSON = MSysNet_FcLogJSON;               // JSON log function supported
    memcpy(pRI->reg_info.sTimelineNameShort, "Net", 4);
    strncpy_s(pRI->reg_info.uszTimelineFile, 32, "timeline_net.txt", _TRUNCATE);
    pRI->pfnPluginManager_Register(pRI);
}
