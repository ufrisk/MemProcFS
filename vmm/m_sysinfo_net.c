// m_sysinfo_net.c : implementation related to the SysInfo/Net built-in module.
//
// The SysInfo/Net module is responsible for displaying networking information
// in a 'netstat' like way at the path '/sysinfo/net/'
//
// The module is a provider of forensic timelining information.
//
// (c) Ulf Frisk, 2020
// Author: Ulf Frisk, pcileech@frizk.net
//
#include "vmm.h"
#include "util.h"
#include "fc.h"

LPCSTR szMSYSINFONET_README =
"Information about the sysinfo net module                                     \n" \
"========================================                                     \n" \
"The sysinfo net module tries to enumerate and list active TCP connections in \n" \
"Windows 7 and later (x64 only).  It currently does not support listening TCP \n" \
"ports or UDP ports. This functionality is planned for the future. Also, it's \n" \
"not supporting 32-bit or Windows Vista/XP (future support less likely).      \n" \
"For more information please visit: https://github.com/ufrisk/MemProcFS/wiki  \n";

// ----------------------------------------------------------------------------
// Net functionality below:
// Show information related to TCP/IP connectivity in the analyzed system.
// ----------------------------------------------------------------------------

#define MSYSINFONET_LINELENGTH                  128ULL
#define MSYSINFONET_LINELENGTH_VERBOSE          260ULL

_Success_(return == 0)
NTSTATUS MSysInfoNet_Read_DoWork(_In_ PVMMOB_MAP_NET pNetMap, _In_ BOOL fVerbose, _Out_ PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset)
{
    NTSTATUS nt;
    LPSTR sz;
    QWORD i, o = 0, cbMax, cStart, cEnd, cbLINELENGTH;
    PVMM_MAP_NETENTRY pe;
    PVMM_PROCESS pObProcess;
    CHAR szTime[MAX_PATH];
    cbLINELENGTH = fVerbose ? MSYSINFONET_LINELENGTH_VERBOSE : MSYSINFONET_LINELENGTH;
    cStart = (DWORD)(cbOffset / cbLINELENGTH);
    cEnd = (DWORD)min(pNetMap->cMap - 1, (cb + cbOffset + cbLINELENGTH - 1) / cbLINELENGTH);
    cbMax = 1 + (1 + cEnd - cStart) * cbLINELENGTH;
    if(!pNetMap->cMap || (cStart > pNetMap->cMap)) { return VMMDLL_STATUS_END_OF_FILE; }
    if(!(sz = LocalAlloc(LMEM_ZEROINIT, cbMax))) { return VMMDLL_STATUS_FILE_INVALID; }
    for(i = cStart; i <= cEnd; i++) {
        pe = pNetMap->pMap + i;
        pObProcess = VmmProcessGet(pe->dwPID);
        if(fVerbose) {
            Util_FileTime2String((PFILETIME)&pe->ftTime, szTime);
            o += Util_snprintf_ln2(
                sz + o,
                cbLINELENGTH,
                "%04x%7i %S %-20s %s  %s",
                (DWORD)i,
                pe->dwPID,
                pe->wszText,
                pObProcess ? pObProcess->pObPersistent->uszNameLong : "",
                szTime,
                pObProcess ? pObProcess->pObPersistent->uszPathKernel : ""
            );

        } else {
            o += Util_snprintf_ln2(
                sz + o,
                cbLINELENGTH,
                "%04x%7i %S %s",
                (DWORD)i,
                pe->dwPID,
                pe->wszText,
                pObProcess ? pObProcess->pObPersistent->uszNameLong : ""
            );
        }
        Ob_DECREF(pObProcess);
    }
    nt = Util_VfsReadFile_FromPBYTE(sz, cbMax - 1, pb, cb, pcbRead, cbOffset - cStart * cbLINELENGTH);
    LocalFree(sz);
    return nt;
}

NTSTATUS MSysInfoNet_Read(_In_ PVMMDLL_PLUGIN_CONTEXT ctx, _Out_ PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset)
{
    NTSTATUS nt = VMMDLL_STATUS_FILE_INVALID;
    PVMMOB_MAP_NET pObNetMap;
    if(!wcscmp(ctx->wszPath, L"readme.txt")) {
        return Util_VfsReadFile_FromPBYTE((PBYTE)szMSYSINFONET_README, strlen(szMSYSINFONET_README), pb, cb, pcbRead, cbOffset);
    }
    if(VmmMap_GetNet(&pObNetMap)) {
        if(!wcscmp(ctx->wszPath, L"netstat.txt")) {
            nt = MSysInfoNet_Read_DoWork(pObNetMap, FALSE, pb, cb, pcbRead, cbOffset);
        }
        if(!wcscmp(ctx->wszPath, L"netstat-v.txt")) {
            nt = MSysInfoNet_Read_DoWork(pObNetMap, TRUE, pb, cb, pcbRead, cbOffset);
        }
        Ob_DECREF(pObNetMap);
    }
    return nt;
}

BOOL MSysInfoNet_List(_In_ PVMMDLL_PLUGIN_CONTEXT ctx, _Inout_ PHANDLE pFileList)
{
    PVMMOB_MAP_NET pObNetMap;
    if(ctx->wszPath[0]) { return FALSE; }
    VMMDLL_VfsList_AddFile(pFileList, L"readme.txt", strlen(szMSYSINFONET_README), NULL);
    if(VmmMap_GetNet(&pObNetMap)) {
        VMMDLL_VfsList_AddFile(pFileList, L"netstat.txt", pObNetMap->cMap * MSYSINFONET_LINELENGTH, NULL);
        VMMDLL_VfsList_AddFile(pFileList, L"netstat-v.txt", pObNetMap->cMap * MSYSINFONET_LINELENGTH_VERBOSE, NULL);
        Ob_DECREF(pObNetMap);
    }
    return TRUE;
}

VOID MSysInfoNet_Timeline(_In_ HANDLE hTimeline, _In_ VOID(*pfnAddEntry)(_In_ HANDLE hTimeline, _In_ QWORD ft, _In_ DWORD dwAction, _In_ DWORD dwPID, _In_ QWORD qwValue, _In_ LPWSTR wszText))
{
    DWORD i;
    PVMM_MAP_NETENTRY pe;
    PVMMOB_MAP_NET pObNetMap;
    if(VmmMap_GetNet(&pObNetMap)) {
        for(i = 0; i < pObNetMap->cMap; i++) {
            pe = pObNetMap->pMap + i;
            if(pe->ftTime && pe->wszText[0]) {
                pfnAddEntry(hTimeline, pe->ftTime, FC_TIMELINE_ACTION_CREATE, pe->dwPID, pe->vaObj, pe->wszText);
            }
        }
        Ob_DECREF(pObNetMap);
    }
}

VOID M_SysInfoNet_Initialize(_Inout_ PVMMDLL_PLUGIN_REGINFO pRI)
{
    if((pRI->magic != VMMDLL_PLUGIN_REGINFO_MAGIC) || (pRI->wVersion != VMMDLL_PLUGIN_REGINFO_VERSION)) { return; }
    if((pRI->tpSystem != VMM_SYSTEM_WINDOWS_X64) && (pRI->tpSystem != VMM_SYSTEM_WINDOWS_X86)) { return; }
    wcscpy_s(pRI->reg_info.wszPathName, 128, L"\\sysinfo\\net");    // module name
    pRI->reg_info.fRootModule = TRUE;                               // module shows in root directory
    pRI->reg_fn.pfnList = MSysInfoNet_List;                         // List function supported
    pRI->reg_fn.pfnRead = MSysInfoNet_Read;                         // Read function supported
    pRI->reg_fn.pfnTimeline = MSysInfoNet_Timeline;                 // Timeline supported
    memcpy(pRI->reg_info.sTimelineNameShort, "Net   ", 6);
    strncpy_s(pRI->reg_info.szTimelineFileUTF8, 32, "timeline_net.txt", _TRUNCATE);
    strncpy_s(pRI->reg_info.szTimelineFileJSON, 32, "timeline_net.json", _TRUNCATE);
    pRI->pfnPluginManager_Register(pRI);
}
