// m_sys_svc.c : implementation related to the sys/services built-in module.
//
// The '/sys/services' module is responsible for displaying information about
// system services retrieved from the service control manager (SCM).
//
// (c) Ulf Frisk, 2020-2025
// Author: Ulf Frisk, pcileech@frizk.net
//

#include "modules.h"

static LPSTR MSYSSVC_CSV_SERVICES = "PID,Ordinal,ServiceName,DisplayName,User,StartType,State,Type1,Type2,ObjectAddress,ImagePath,DriverpathOrCmdline\n";

#define MSYSSVC_LINELENGTH      288ULL
#define MSYSSVC_LINEHEADER      "   #    PID Start Type   State      Type Type    Obj Address  Name / Display Name                                              User                         Image Path                                          Object Name / Command Line"


VOID MSysSvc_GetSvcTypeLong(_In_ PVMM_MAP_SERVICEENTRY pe, _Out_writes_(MAX_PATH) LPSTR sz)
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

VOID MSysSvc_GetSvcTypeShort2(_In_ PVMM_MAP_SERVICEENTRY pe, _Out_ LPCSTR *psz1, _Out_ LPCSTR *psz2)
{
    DWORD tp = pe->ServiceStatus.dwServiceType;
    if(tp & SERVICE_KERNEL_DRIVER) {
        *psz1 = "Driver"; *psz2 = "KERNEL_DRIVER";
        return;
    } else if(tp & SERVICE_FILE_SYSTEM_DRIVER) {
        *psz1 = "Driver"; *psz2 = "FILE_SYSTEM_DRIVER";
        return;
    } else if(tp & SERVICE_ADAPTER) {
        *psz1 = "Driver"; *psz2 = "ADAPTER";
        return;
    } else if(tp & SERVICE_RECOGNIZER_DRIVER) {
        *psz1 = "Driver"; *psz2 = "RECOGNIZER_DRIVER";
        return;
    } else if((tp & SERVICE_WIN32_OWN_PROCESS) && (tp & SERVICE_WIN32_SHARE_PROCESS)) {
        *psz1 = "Process"; *psz2 = "OWN|SHR";
        return;
    } else if(tp & SERVICE_WIN32_OWN_PROCESS) {
        *psz1 = "Process"; *psz2 = "OWN";
        return;
    } else if(tp & SERVICE_WIN32_SHARE_PROCESS) {
        *psz1 = "Process"; *psz2 = "SHR";
        return;
    } else {
        *psz1 = ""; *psz2 = "";
        return;
    }
}

LPSTR MSysSvc_GetSvcTypeShort(_In_ PVMM_MAP_SERVICEENTRY pe)
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

LPSTR MSysSvc_GetSvcStartType(_In_ PVMM_MAP_SERVICEENTRY pe, _In_ BOOL fLong)
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

LPSTR MSysSvc_GetSvcState(_In_ PVMM_MAP_SERVICEENTRY pe, _In_ BOOL fLong)
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

VOID MSysSvc_ReadLineCB(_In_ VMM_HANDLE H, _Inout_opt_ PVOID ctx, _In_ DWORD cbLineLength, _In_ DWORD ie, _In_ PVMM_MAP_SERVICEENTRY pe, _Out_writes_(cbLineLength + 1) LPSTR szu8)
{
    CHAR uszSvcName[MAX_PATH + 1];
    uszSvcName[0] = '\0';
    strncat_s(uszSvcName, MAX_PATH, pe->uszServiceName, _TRUNCATE);
    if((pe->uszServiceName != pe->uszDisplayName) && pe->uszDisplayName[0]) {
        strncat_s(uszSvcName, MAX_PATH, " / ", _TRUNCATE);
        strncat_s(uszSvcName, MAX_PATH, pe->uszDisplayName, _TRUNCATE);
    }
    Util_usnprintf_ln(szu8, cbLineLength,
        "%04i%7i %s %s %s %012llx %-64.64s %-28.28s %-48s%s%s",
        pe->dwOrdinal,
        pe->dwPID,
        MSysSvc_GetSvcStartType(pe, FALSE),
        MSysSvc_GetSvcState(pe, FALSE),
        MSysSvc_GetSvcTypeShort(pe),
        pe->vaObj,
        uszSvcName,
        pe->uszUserAcct[0] ? pe->uszUserAcct : "---",
        pe->uszImagePath[0] ? pe->uszImagePath : "---",
        pe->uszPath[0] ? " :: " : "",
        pe->uszPath[0] ? pe->uszPath : ""
    );
}

DWORD MSysSvc_InfoFromEntry(_In_ PVMM_MAP_SERVICEENTRY pe, _Out_writes_(cbu) LPSTR usz, _In_ DWORD cbu)
{
    CHAR szSvcType[MAX_PATH];
    LPSTR szStartType = MSysSvc_GetSvcStartType(pe, TRUE);
    LPSTR szState = MSysSvc_GetSvcState(pe, TRUE);
    MSysSvc_GetSvcTypeLong(pe, szSvcType);
    return (DWORD)snprintf(usz, cbu,
        "Ordinal:          %i\n" \
        "Service Name:     %s\n" \
        "Display Name:     %s\n" \
        "Record Address:   0x%012llx\n" \
        "Start Type:       %s (0x%x)\n" \
        "Service State:    %s (0x%x)\n" \
        "Service Type:     %s (0x%x)\n" \
        "Process ID (PID): %i\n" \
        "Path:             %s\n" \
        "Image Path:       %s\n" \
        "User Type:        %s\n" \
        "User Account:     %s\n",
        pe->dwOrdinal,
        pe->uszServiceName,
        pe->uszDisplayName,
        pe->vaObj,
        szStartType, pe->dwStartType,
        szState, pe->ServiceStatus.dwCurrentState,
        szSvcType, pe->ServiceStatus.dwServiceType,
        pe->dwPID,
        pe->uszPath,
        pe->uszImagePath,
        pe->uszUserTp,
        pe->uszUserAcct
    );
}

int MSysSvc_InfoFromPath_Filter(_In_ QWORD pvFind, _In_ QWORD qwEntry)
{
    PVMM_MAP_SERVICEENTRY pvEntry = (PVMM_MAP_SERVICEENTRY)qwEntry;
    return (DWORD)pvFind - pvEntry->dwOrdinal;
}

NTSTATUS MSysSvc_Read(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_CONTEXT ctxP, _Out_writes_to_(cb, *pcbRead) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset)
{
    NTSTATUS nt = VMMDLL_STATUS_FILE_INVALID;
    PVMMOB_MAP_SERVICE pObSvcMap = NULL;
    PVMM_MAP_SERVICEENTRY pe;
    LPCSTR uszSvcSubPath;
    QWORD qwSvcId;
    DWORD i, cbInfoFile, dwSvcId;
    CHAR usz[MAX_PATH];
    CHAR szu8InfoFile[0x1000];
    if(!VmmMap_GetService(H, &pObSvcMap)) { goto finish; }
    if(!_stricmp(ctxP->uszPath, "services.txt")) {
        nt = Util_VfsLineFixed_Read(
            H, (UTIL_VFSLINEFIXED_PFN_CB)MSysSvc_ReadLineCB, NULL, MSYSSVC_LINELENGTH, MSYSSVC_LINEHEADER,
            pObSvcMap->pMap, pObSvcMap->cMap, sizeof(VMM_MAP_SERVICEENTRY),
            pb, cb, pcbRead, cbOffset
        );
        goto finish;
    }
    if(Util_VfsHelper_GetIdDir(ctxP->uszPath, FALSE, &dwSvcId, &uszSvcSubPath)) {
        qwSvcId = dwSvcId;
        pe = Util_qfind(qwSvcId, pObSvcMap->cMap, pObSvcMap->pMap, sizeof(VMM_MAP_SERVICEENTRY), MSysSvc_InfoFromPath_Filter);
        if(pe) {
            if(!_stricmp("svcinfo.txt", uszSvcSubPath)) {
                cbInfoFile = MSysSvc_InfoFromEntry(pe, szu8InfoFile, sizeof(szu8InfoFile));
                nt = Util_VfsReadFile_FromPBYTE((PBYTE)szu8InfoFile, cbInfoFile, pb, cb, pcbRead, cbOffset);
                goto finish;
            }
            if(!_strnicmp("registry", uszSvcSubPath, 8)) {
                i = (uszSvcSubPath[8] == '\\') ? 9 : 8;
                _snprintf_s(usz, MAX_PATH, _TRUNCATE, "registry\\HKLM\\SYSTEM\\ControlSet001\\Services\\%s\\%s", pe->uszServiceName, uszSvcSubPath + i);
                return PluginManager_Read(H, NULL, usz, pb, cb, pcbRead, cbOffset);
            }
        }
    }
finish:
    Ob_DECREF(pObSvcMap);
    return nt;
}

BOOL MSysSvc_List(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_CONTEXT ctxP, _Inout_ PHANDLE pFileList)
{
    QWORD qwSvcId;
    DWORD i, cbInfoFile, dwSvcId;
    LPCSTR uszSvcSubPath;
    PVMMOB_MAP_SERVICE pObSvcMap = NULL;
    PVMM_MAP_SERVICEENTRY pe;
    CHAR usz[MAX_PATH];
    CHAR szu8InfoFile[0x1000];
    if(!VmmMap_GetService(H, &pObSvcMap)) { goto finish; }
    if(0 == ctxP->uszPath[0]) {
        VMMDLL_VfsList_AddDirectory(pFileList, "by-id", NULL);
        VMMDLL_VfsList_AddDirectory(pFileList, "by-name", NULL);
        VMMDLL_VfsList_AddFile(pFileList, "services.txt", UTIL_VFSLINEFIXED_LINECOUNT(H, pObSvcMap->cMap) * MSYSSVC_LINELENGTH, NULL);
        goto finish;
    }
    if(!_stricmp(ctxP->uszPath, "by-id")) {
        for(i = 0; i < pObSvcMap->cMap; i++) {
            _snprintf_s(usz, 5, _TRUNCATE, "%i", pObSvcMap->pMap[i].dwOrdinal);
            VMMDLL_VfsList_AddDirectory(pFileList, usz, NULL);
        }
        goto finish;
    }
    if(!_stricmp(ctxP->uszPath, "by-name")) {
        for(i = 0; i < pObSvcMap->cMap; i++) {
            _snprintf_s(usz, _countof(usz), _TRUNCATE, "%s-%i", pObSvcMap->pMap[i].uszServiceName, pObSvcMap->pMap[i].dwOrdinal);
            VMMDLL_VfsList_AddDirectory(pFileList, usz, NULL);
        }
        goto finish;
    }
    if(Util_VfsHelper_GetIdDir(ctxP->uszPath, FALSE, &dwSvcId, &uszSvcSubPath)) {
        qwSvcId = dwSvcId;
        pe = Util_qfind(qwSvcId, pObSvcMap->cMap, pObSvcMap->pMap, sizeof(VMM_MAP_SERVICEENTRY), MSysSvc_InfoFromPath_Filter);
        if(pe) {
            if(0 == uszSvcSubPath[0]) {
                cbInfoFile = MSysSvc_InfoFromEntry(pe, szu8InfoFile, sizeof(szu8InfoFile));
                VMMDLL_VfsList_AddFile(pFileList, "svcinfo.txt", cbInfoFile, NULL);
                VMMDLL_VfsList_AddDirectory(pFileList, "registry", NULL);
                goto finish;
            }
            if(!_strnicmp(uszSvcSubPath, "registry", 8)) {
                i = (uszSvcSubPath[8] == '\\') ? 9 : 8;
                _snprintf_s(usz, _countof(usz), _TRUNCATE, "registry\\HKLM\\SYSTEM\\ControlSet001\\Services\\%s\\%s", pe->uszServiceName, uszSvcSubPath + i);
                PluginManager_List(H, NULL, usz, pFileList);
                goto finish;
            }
        }
    }
finish:
    Ob_DECREF(pObSvcMap);
    return TRUE;
}

/*
* Forensic JSON log:
*/
VOID MSysSvc_FcLogJSON(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_CONTEXT ctxP, _In_ VOID(*pfnLogJSON)(_In_ VMM_HANDLE H, _In_ PVMMDLL_FORENSIC_JSONDATA pData))
{
    PVMMDLL_FORENSIC_JSONDATA pd;
    PVMMOB_MAP_SERVICE pObSvcMap = NULL;
    PVMM_MAP_SERVICEENTRY pe;
    DWORD i;
    CHAR sz[MAX_PATH], usz[2][MAX_PATH];
    if(ctxP->pProcess || !(pd = LocalAlloc(LMEM_ZEROINIT, sizeof(VMMDLL_FORENSIC_JSONDATA)))) { return; }
    pd->dwVersion = VMMDLL_FORENSIC_JSONDATA_VERSION;
    pd->szjType = "service";
    if(VmmMap_GetService(H, &pObSvcMap)) {
        for(i = 0; i < pObSvcMap->cMap; i++) {
            pe = pObSvcMap->pMap + i;
            pd->i = i;
            pd->dwPID = pe->dwPID;
            pd->vaObj = pe->vaObj;
            MSysSvc_GetSvcTypeLong(pe, sz);
            snprintf(usz[0], _countof(usz[0]), "%s [%s]",
                pe->uszServiceName,
                pe->uszDisplayName);
            _snprintf_s(usz[1], _countof(usz[1]), _TRUNCATE, "start:[%s] state:[%s] type:[%s] user:[%s] image:[%s] path:[%s]",
                MSysSvc_GetSvcStartType(pe, FALSE), MSysSvc_GetSvcState(pe, FALSE), sz,
                (pe->uszUserAcct[0] ? pe->uszUserAcct : "---"),
                (pe->uszImagePath[0] ? pe->uszImagePath : "---"),
                (pe->uszPath[0] ? pe->uszPath : "---"));
            pd->usz[0] = usz[0];
            pd->usz[1] = usz[1];
            pfnLogJSON(H, pd);
        }
    }
    Ob_DECREF(pObSvcMap);
    LocalFree(pd);
}

PVOID MSysSvc_FcInitialize(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_CONTEXT ctxP)
{
    FcFileAppend(H, "services.csv", MSYSSVC_CSV_SERVICES);
    return NULL;
}

VOID MSysSvc_FcLogCSV(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_CONTEXT ctxP, _In_ VMMDLL_CSV_HANDLE hCSV)
{
    CHAR uszSvcName[MAX_PATH], uszSvcDisplayName[MAX_PATH];
    CHAR szSvcType[MAX_PATH];
    PVMMOB_MAP_SERVICE pObSvcMap = NULL;
    PVMM_MAP_SERVICEENTRY pe;
    LPCSTR szTp1, szTp2;
    DWORD i;
    if((ctxP->dwPID == 4) && VmmMap_GetService(H, &pObSvcMap)) {
        for(i = 0; i < pObSvcMap->cMap; i++) {
            pe = pObSvcMap->pMap + i;
            uszSvcName[0] = '\0';
            uszSvcDisplayName[0] = '\0';
            strncpy_s(uszSvcName, MAX_PATH, pe->uszServiceName, _TRUNCATE);
            strncpy_s(uszSvcDisplayName, MAX_PATH, pe->uszDisplayName, _TRUNCATE);
            MSysSvc_GetSvcTypeLong(pe, szSvcType);
            MSysSvc_GetSvcTypeShort2(pe, &szTp1, &szTp2);
            //"PID,Ordinal,ServiceName,DisplayName,User,StartType,State,Type1,Type2,ObjectAddress,ImagePath,DriverpathOrCmdline"
            FcCsv_Reset(hCSV);
            FcFileAppend(H, "services.csv", "%i,%i,%s,%s,%s,%s,%s,%s,%s,0x%llx,%s,%s\n",
                pe->dwPID,
                pe->dwOrdinal,
                FcCsv_String(hCSV, uszSvcName),
                FcCsv_String(hCSV, uszSvcDisplayName),
                FcCsv_String(hCSV, pe->uszUserAcct),
                MSysSvc_GetSvcStartType(pe, TRUE),
                MSysSvc_GetSvcState(pe, TRUE),
                szTp1,
                szTp2,
                pe->vaObj,
                FcCsv_String(hCSV, pe->uszImagePath),
                FcCsv_String(hCSV, pe->uszPath)
            );
        }
    }
}

VOID M_SysSvc_Initialize(_In_ VMM_HANDLE H, _Inout_ PVMMDLL_PLUGIN_REGINFO pRI)
{
    if((pRI->magic != VMMDLL_PLUGIN_REGINFO_MAGIC) || (pRI->wVersion != VMMDLL_PLUGIN_REGINFO_VERSION)) { return; }
    if((pRI->tpSystem != VMMDLL_SYSTEM_WINDOWS_64) && (pRI->tpSystem != VMMDLL_SYSTEM_WINDOWS_32)) { return; }
    strcpy_s(pRI->reg_info.uszPathName, 128, "\\sys\\services");    // module name
    pRI->reg_info.fRootModule = TRUE;                               // module shows in root directory
    pRI->reg_fn.pfnList = MSysSvc_List;                             // List function supported
    pRI->reg_fn.pfnRead = MSysSvc_Read;                             // Read function supported
    pRI->reg_fnfc.pfnInitialize = MSysSvc_FcInitialize;             // Forensic initialize supported
    pRI->reg_fnfc.pfnLogCSV = MSysSvc_FcLogCSV;                     // CSV log function supported
    pRI->reg_fnfc.pfnLogJSON = MSysSvc_FcLogJSON;                   // JSON log function supported
    pRI->pfnPluginManager_Register(H, pRI);
}
