// m_sysinfo_svc.c : implementation related to the sysinfo/services built-in module.
//
// The sysinfo/services module is responsible for displaying information about
// system services retrieved from the service control manager (SCM).
//
// (c) Ulf Frisk, 2020
// Author: Ulf Frisk, pcileech@frizk.net
//
#include "vmm.h"
#include "util.h"
#include "fc.h"

#define MSYSINFOSVC_LINELENGTH                  224ULL

VOID MSysInfoSvc_GetSvcTypeLong(_In_ PVMM_MAP_SERVICEENTRY pe, _Out_writes_(MAX_PATH) LPSTR sz)
{
    DWORD tp = pe->ServiceStatus.dwServiceType;
    BOOL fUser = tp & SERVICE_USER_SERVICE;
    sz[0] = 0;
    if(tp & SERVICE_KERNEL_DRIVER) {
        strncpy_s(sz, MAX_PATH, "SERVICE_KERNEL_DRIVER", _TRUNCATE);
        return;
    }
    if(tp & SERVICE_FILE_SYSTEM_DRIVER) {
        strncpy_s(sz, MAX_PATH, "SERVICE_FILE_SYSTEM_DRIVER", _TRUNCATE);
        return;
    }
    if(tp & SERVICE_ADAPTER) {
        strncpy_s(sz, MAX_PATH, "SERVICE_ADAPTER", _TRUNCATE);
        return;
    }
    if(tp & SERVICE_RECOGNIZER_DRIVER) {
        strncpy_s(sz, MAX_PATH, "SERVICE_RECOGNIZER_DRIVER", _TRUNCATE);
        return;
    }
    if(tp & SERVICE_WIN32_OWN_PROCESS) {
        strncpy_s(sz, MAX_PATH, (fUser ? "SERVICE_USER_OWN_PROCESS" : "SERVICE_WIN32_OWN_PROCESS"), _TRUNCATE);
    }
    if(tp & SERVICE_WIN32_SHARE_PROCESS) {
        if(sz[0]) { strncat_s(sz, MAX_PATH, "|", _TRUNCATE); }
        strncat_s(sz, MAX_PATH, (fUser ? "SERVICE_USER_SHARE_PROCESS" : "SERVICE_WIN32_SHARE_PROCESS"), _TRUNCATE);
    }
    if(sz[0] && (tp & SERVICE_INTERACTIVE_PROCESS)) {
        strncat_s(sz, MAX_PATH, "|SERVICE_INTERACTIVE_PROCESS", _TRUNCATE);
    }
    if(sz[0] && (tp & SERVICE_PKG_SERVICE)) {
        strncat_s(sz, MAX_PATH, "|SERVICE_PKG_SERVICE", _TRUNCATE);
    }
    if(!sz[0]) {
        strncpy_s(sz, MAX_PATH, "N/A", _TRUNCATE);
    }
}

LPSTR MSysInfoSvc_GetSvcTypeShort(_In_ PVMM_MAP_SERVICEENTRY pe)
{
    DWORD tp = pe->ServiceStatus.dwServiceType;
    if(tp & SERVICE_KERNEL_DRIVER) {
        return "DRV  KERNEL ";
    } else if(tp & SERVICE_FILE_SYSTEM_DRIVER) {
        return "DRV  FS     ";
    } else if(tp & SERVICE_ADAPTER) {
        return "DRV  ADAPTER";
    } else if(tp & SERVICE_RECOGNIZER_DRIVER) {
        return "DRV  RECOGN ";
    } else if((tp & SERVICE_WIN32_OWN_PROCESS) && (tp & SERVICE_WIN32_SHARE_PROCESS)) {
        return "PROC OWN|SHR";
    } else if(tp & SERVICE_WIN32_OWN_PROCESS) {
        return "PROC OWN    ";
    } else if(tp & SERVICE_WIN32_SHARE_PROCESS) {
        return "PROC SHR    ";
    } else {
        return "---         ";
    }
}

LPSTR MSysInfoSvc_GetSvcStartType(_In_ PVMM_MAP_SERVICEENTRY pe, _In_ BOOL fLong)
{
    LPSTR szSVC_START_TYPE[][2] = {
        { "BOOT_START  ", "SERVICE_BOOT_START"      },
        { "SYSTEM_START", "SERVICE_SYSTEM_START"    },
        { "AUTO_START  ", "SERVICE_AUTO_START"      },
        { "DEMAND_START", "SERVICE_DEMAND_START"    },
        { "DISABLED    ", "SERVICE_DISABLED"        },
        { "---         ", "---"                     }
    };
    return szSVC_START_TYPE[min(5, pe->dwStartType)][fLong ? 1 : 0];
}

LPSTR MSysInfoSvc_GetSvcState(_In_ PVMM_MAP_SERVICEENTRY pe, _In_ BOOL fLong)
{
    LPSTR szSVC_STATE[][2] = {
        { "---       ", "---"                       },
        { "STOPPED   ", "SERVICE_STOPPED"           },
        { "START_PEND", "SERVICE_START_PENDING"     },
        { "STOP_PEND ", "SERVICE_STOP_PENDING"      },
        { "RUNNING   ", "SERVICE_RUNNING"           },
        { "CONT_PEND ", "SERVICE_CONTINUE_PENDING"  },
        { "PAUSE_PEND", "SERVICE_PAUSE_PENDING"     },
        { "PAUSED    ", "SERVICE_PAUSED"            },
        { "---       ", "---"                       }
    };
    return szSVC_STATE[min(8, pe->ServiceStatus.dwCurrentState)][fLong ? 1 : 0];
}

_Success_(return == 0)
NTSTATUS MSysInfoSvc_Read_DoWork(_In_ PVMMOB_MAP_SERVICE pSvcMap, _Out_writes_to_(cb, *pcbRead) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset)
{
    NTSTATUS nt;
    LPSTR sz;
    WCHAR wszUser[MAX_PATH + 1];
    WCHAR wszSvcName[MAX_PATH + 1];
    QWORD i, o = 0, cbMax, cStart, cEnd, cbLINELENGTH;
    PVMM_MAP_SERVICEENTRY pe;
    cbLINELENGTH = MSYSINFOSVC_LINELENGTH;
    cStart = (DWORD)(cbOffset / cbLINELENGTH);
    cEnd = (DWORD)min(pSvcMap->cMap - 1, (cb + cbOffset + cbLINELENGTH - 1) / cbLINELENGTH);
    cbMax = 1 + (1 + cEnd - cStart) * cbLINELENGTH;
    if(!pSvcMap->cMap || (cStart > pSvcMap->cMap)) { return VMMDLL_STATUS_END_OF_FILE; }
    if(!(sz = LocalAlloc(LMEM_ZEROINIT, cbMax))) { return VMMDLL_STATUS_FILE_INVALID; }
    for(i = cStart; i <= cEnd; i++) {
        pe = pSvcMap->pMap + i;
        wszUser[0] = '\0';
        wszSvcName[0] = '\0';
        wcsncat_s(wszSvcName, MAX_PATH, pe->wszServiceName, _TRUNCATE);
        if((pe->wszServiceName != pe->wszDisplayName) && pe->wszDisplayName[0]) {
            wcsncat_s(wszSvcName, MAX_PATH, L" / ", _TRUNCATE);
            wcsncat_s(wszSvcName, MAX_PATH, pe->wszDisplayName, _TRUNCATE);
        }
        if(pe->wszUserAcct[0]) {
            _snwprintf_s(wszUser, MAX_PATH, _TRUNCATE, L" :: %s", pe->wszUserAcct);
        }
        o += Util_snwprintf_u8ln(
            sz + o,
            cbLINELENGTH,
            L"%04i%7i %S %S %S %012llx %-60s :: %s%s",
            pe->dwOrdinal,
            pe->dwPID,
            MSysInfoSvc_GetSvcStartType(pe, FALSE),
            MSysInfoSvc_GetSvcState(pe, FALSE),
            MSysInfoSvc_GetSvcTypeShort(pe),
            pe->vaObj,
            wszSvcName,
            pe->wszPath,
            wszUser
        );
    }
    nt = Util_VfsReadFile_FromPBYTE(sz, cbMax - 1, pb, cb, pcbRead, cbOffset - cStart * cbLINELENGTH);
    LocalFree(sz);
    return nt;
}

DWORD MSysInfoSvc_InfoFromEntry(_In_ PVMM_MAP_SERVICEENTRY pe, _Out_writes_(cbszu8) LPSTR szu8, _In_ DWORD cbszu8)
{
    CHAR szSvcType[MAX_PATH];
    LPSTR szStartType = MSysInfoSvc_GetSvcStartType(pe, TRUE);
    LPSTR szState = MSysInfoSvc_GetSvcState(pe, TRUE);
    MSysInfoSvc_GetSvcTypeLong(pe, szSvcType);
    return (DWORD)Util_snwprintf_u8(szu8, cbszu8,
        L"Ordinal:          %i\n" \
        L"Service Name:     %s\n" \
        L"Display Name:     %s\n" \
        L"Record Address:   0x%012llx\n" \
        L"Service Type:     %S (0x%x)\n" \
        L"Service State:    %S (0x%x)\n" \
        L"Service Type:     %S (0x%x)\n" \
        L"Process ID (PID): %i\n" \
        L"Path:             %s\n" \
        L"User Type:        %s\n" \
        L"User Account:     %s\n",
        pe->dwOrdinal,
        pe->wszServiceName,
        pe->wszDisplayName,
        pe->vaObj,
        szStartType, pe->dwStartType,
        szState, pe->ServiceStatus.dwCurrentState,
        szSvcType, pe->ServiceStatus.dwServiceType,
        pe->dwPID,
        pe->wszPath,
        pe->wszUserTp,
        pe->wszUserAcct
    );
}

int MSysInfoSvc_InfoFromPath_Filter(_In_ QWORD pvFind, _In_ PVMM_MAP_SERVICEENTRY pvEntry)
{
    return (DWORD)pvFind - pvEntry->dwOrdinal;
}

DWORD MSysInfoSvc_InfoFromPath(_In_ PVMMDLL_PLUGIN_CONTEXT ctx, _In_ PVMMOB_MAP_SERVICE pSvcMap, _Out_writes_(cbszu8) LPSTR szu8, _In_ DWORD cbszu8)
{
    QWORD qwId;
    PVMM_MAP_SERVICEENTRY pe;
    szu8[0] = 0;
    if(!(qwId = Util_GetNumericW(ctx->wszPath + 6))) { return 0; }
    pe = Util_qfind((PVOID)qwId, pSvcMap->cMap, pSvcMap->pMap, sizeof(VMM_MAP_SERVICEENTRY), (int(*)(PVOID,PVOID))MSysInfoSvc_InfoFromPath_Filter);
    return pe ? (DWORD)MSysInfoSvc_InfoFromEntry(pe, szu8, cbszu8) : 0;
}

NTSTATUS MSysInfoSvc_Read(_In_ PVMMDLL_PLUGIN_CONTEXT ctx, _Out_writes_to_(cb, *pcbRead) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset)
{
    NTSTATUS nt = VMMDLL_STATUS_FILE_INVALID;
    PVMMOB_MAP_SERVICE pObSvcMap = NULL;
    DWORD cchPath, cbInfoFile;
    CHAR szu8InfoFile[0x1000];
    if(!VmmMap_GetService(&pObSvcMap)) { goto finish; }
    if(!wcscmp(ctx->wszPath, L"services.txt")) {
        nt = MSysInfoSvc_Read_DoWork(pObSvcMap, pb, cb, pcbRead, cbOffset);
        goto finish;
    }
    if(!_wcsnicmp(L"by-id\\", ctx->wszPath, 6)) {
        cchPath = (DWORD)wcslen(ctx->wszPath);
        LPWSTR wszTMP = ctx->wszPath + cchPath - _countof(L"svcinfo.txt");
        if((cchPath > 16) && !_wcsicmp(L"svcinfo.txt", ctx->wszPath + cchPath + 1 - _countof(L"svcinfo.txt"))) {
            cbInfoFile = MSysInfoSvc_InfoFromPath(ctx, pObSvcMap, szu8InfoFile, sizeof(szu8InfoFile));
            nt = Util_VfsReadFile_FromPBYTE((PBYTE)szu8InfoFile, cbInfoFile, pb, cb, pcbRead, cbOffset);
        }
        goto finish;
    }
finish:
    Ob_DECREF(pObSvcMap);
    return nt;
}

BOOL MSysInfoSvc_List(_In_ PVMMDLL_PLUGIN_CONTEXT ctx, _Inout_ PHANDLE pFileList)
{
    DWORD i, cbInfoFile;
    WCHAR wsz[5];
    CHAR szu8InfoFile[0x1000];
    PVMMOB_MAP_SERVICE pObSvcMap = NULL;
    if(!VmmMap_GetService(&pObSvcMap)) { goto finish; }
    if(0 == ctx->wszPath[0]) {
        VMMDLL_VfsList_AddDirectory(pFileList, L"by-id", NULL);
        VMMDLL_VfsList_AddFile(pFileList, L"services.txt", pObSvcMap->cMap * MSYSINFOSVC_LINELENGTH, NULL);
        goto finish;
    }
    if(0 == _wcsicmp(L"by-id", ctx->wszPath)) {
        for(i = 0; i < pObSvcMap->cMap; i++) {
            _snwprintf_s(wsz, 5, _TRUNCATE, L"%i", pObSvcMap->pMap[i].dwOrdinal);
            VMMDLL_VfsList_AddDirectory(pFileList, wsz, NULL);
        }
        goto finish;
    }
    if(!_wcsnicmp(L"by-id\\", ctx->wszPath, 6) && (wcslen(ctx->wszPath) < 12)) {
        cbInfoFile = MSysInfoSvc_InfoFromPath(ctx, pObSvcMap, szu8InfoFile, sizeof(szu8InfoFile));
        VMMDLL_VfsList_AddFile(pFileList, L"svcinfo.txt", cbInfoFile, NULL);
        goto finish;
    }
finish:
    Ob_DECREF(pObSvcMap);
    return TRUE;
}

VOID M_SysInfoSvc_Initialize(_Inout_ PVMMDLL_PLUGIN_REGINFO pRI)
{
    if((pRI->magic != VMMDLL_PLUGIN_REGINFO_MAGIC) || (pRI->wVersion != VMMDLL_PLUGIN_REGINFO_VERSION)) { return; }
    if((pRI->tpSystem != VMM_SYSTEM_WINDOWS_X64) && (pRI->tpSystem != VMM_SYSTEM_WINDOWS_X86)) { return; }
    wcscpy_s(pRI->reg_info.wszPathName, 128, L"\\sysinfo\\services");   // module name
    pRI->reg_info.fRootModule = TRUE;                                   // module shows in root directory
    pRI->reg_fn.pfnList = MSysInfoSvc_List;                             // List function supported
    pRI->reg_fn.pfnRead = MSysInfoSvc_Read;                             // Read function supported
    pRI->pfnPluginManager_Register(pRI);
}
