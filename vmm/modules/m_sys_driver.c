// m_sys_driver.c : implementation related to the sys/drivers built-in module.
//
// The 'sys/drivers' module lists various aspects of drivers from the windows
// kernel object manager.
//
// (c) Ulf Frisk, 2022-2025
// Author: Ulf Frisk, pcileech@frizk.net
//

#include "modules.h"
#include "../vmmwinobj.h"

static LPSTR MSYSDRIVER_CSV_DRIVERS = "Name,ObjectAddress,Size,Start,End,ServiceKey,DriverName,DriverPath\n";
static LPSTR MSYSDRIVER_CSV_DEVICES = "Name,ObjectAddress,Depth,AttachedDeviceAddress,DriverName,DriverPath,DriverObjectAddress,ExtraInfo\n";

#define MSYSDRIVER_DRV_LINELENGTH                  256ULL
#define MSYSDRIVER_IRP_LINELENGTH                  88ULL
#define MSYSDRIVER_DEV_LINELENGTH                  200ULL
#define MSYSDRIVER_DRV_LINEHEADER     "   #   Object Address Driver               Size Drv Range: Start-End              Service Key      Driver Name                      Driver Path"
#define MSYSDRIVER_IRP_LINEHEADER     "   # Driver            # IRP_MJ_*                          Address Target Module"
#define MSYSDRIVER_DEV_LINEHEADER     "   # Depth DeviceAddress     DeviceName                          DriverAddress DriverName       DeviceType / ExtraInfo"

#define MSYSDRIVER_IRP_STR (LPCSTR[]){ \
    "CREATE",                   \
    "CREATE_NAMED_PIPE",        \
    "CLOSE",                    \
    "READ",                     \
    "WRITE",                    \
    "QUERY_INFORMATION",        \
    "SET_INFORMATION",          \
    "QUERY_EA",                 \
    "SET_EA",                   \
    "FLUSH_BUFFERS",            \
    "QUERY_VOLUME_INFORMATION", \
    "SET_VOLUME_INFORMATION",   \
    "DIRECTORY_CONTROL",        \
    "FILE_SYSTEM_CONTROL",      \
    "DEVICE_CONTROL",           \
    "INTERNAL_DEVICE_CONTROL",  \
    "SHUTDOWN",                 \
    "LOCK_CONTROL",             \
    "CLEANUP",                  \
    "CREATE_MAILSLOT",          \
    "QUERY_SECURITY",           \
    "SET_SECURITY",             \
    "POWER",                    \
    "SYSTEM_CONTROL",           \
    "DEVICE_CHANGE",            \
    "QUERY_QUOTA",              \
    "SET_QUOTA",                \
    "PNP" }

typedef struct tdMSYSDRIVER_IRP_CONTEXT {
    PVMMOB_MAP_PTE pPteMap;
    PVMMOB_MAP_KDRIVER pDrvMap;
} MSYSDRIVER_IRP_CONTEXT, *PMSYSDRIVER_IRP_CONTEXT;

/*
* Line callback function to print a single driver/irp line.
*/
VOID MSysDriver_IrpReadLineCB(_In_ VMM_HANDLE H, _In_ PMSYSDRIVER_IRP_CONTEXT ctx, _In_ DWORD cbLineLength, _In_ DWORD ie, _In_ PVOID pv, _Out_writes_(cbLineLength + 1) LPSTR usz)
{
    PVMM_MAP_PTEENTRY pePte;
    PVMM_MAP_KDRIVERENTRY pe;
    QWORD vaIrp;
    DWORD iDrv, iIrp;
    LPSTR uszTxt = "?";
    iDrv = ie / 28;
    iIrp = ie % 28;
    pe = ctx->pDrvMap->pMap + iDrv;
    vaIrp = pe->MajorFunction[iIrp];
    if(vaIrp == H->vmm.kernel.opt.vaIopInvalidDeviceRequest) {
        uszTxt = "---";
    } else if((vaIrp >= pe->vaStart) && (vaIrp < pe->vaStart + pe->cbDriverSize)) {
        uszTxt = pe->uszName;
    } else if((pePte = VmmMap_GetPteEntry(H, ctx->pPteMap, vaIrp))) {
        uszTxt = pePte->uszText;
    }
    Util_usnprintf_ln(usz, cbLineLength,
        "%04x %-16.16s %2i %-24.24s %16llx %s",
        ie,
        pe->uszName,
        iIrp,
        MSYSDRIVER_IRP_STR[iIrp],
        vaIrp,
        uszTxt
    );
}

VOID MSysDriver_DrvReadLineCB(_In_ VMM_HANDLE H, _In_ POB_MAP pmModuleByVA, _In_ DWORD cbLineLength, _In_ DWORD ie, _In_ PVMM_MAP_KDRIVERENTRY pe, _Out_writes_(cbLineLength + 1) LPSTR usz)
{
    PVMMOB_MAP_MODULE pObModuleMap = NULL;
    PVMM_MAP_MODULEENTRY peModule = ObMap_GetByKey(pmModuleByVA, pe->vaStart);
    Util_usnprintf_ln(usz, cbLineLength,
        "%04x %16llx %-16.16s %8llx %16llx-%16llx %-16.16s %-32.32s %s",
        ie,
        pe->va,
        pe->uszName,
        pe->cbDriverSize,
        pe->vaStart,
        pe->cbDriverSize ? (pe->vaStart + pe->cbDriverSize - 1) : pe->vaStart,
        pe->uszServiceKeyName,
        pe->uszPath,
        (peModule && peModule->uszFullName) ? peModule->uszFullName : ""
    );
}

/*
* Retrieve device extra info to display (if any).
* -- peDevice
* -- uszDeviceExtraInfo
* -- return = (same ptr as uszDeviceExtraInfo)
*/
LPSTR MSysDriver_DevGetExtraInfo(_In_ PVMM_MAP_KDEVICEENTRY peDevice, _Out_writes_(MAX_PATH) LPSTR uszDeviceExtraInfo)
{
    uszDeviceExtraInfo[0] = 0;
    if(peDevice->vaFileSystemDevice) {
        _snprintf_s(uszDeviceExtraInfo, MAX_PATH, _TRUNCATE,
            "DeviceFS:[%llx] VolumeLabel:[%s]",
            peDevice->vaFileSystemDevice,
            peDevice->uszVolumeInfo[0] ? peDevice->uszVolumeInfo : ""
        );
    }
    return uszDeviceExtraInfo;
}

/*
* Line callback function to print a single device line.
*/
VOID MSysDriver_DevReadLineCB(_In_ VMM_HANDLE H, _In_ PVOID ctx, _In_ DWORD cbLineLength, _In_ DWORD ie, _In_ PVMM_MAP_KDEVICEENTRY pe, _Out_writes_(cbLineLength + 1) LPSTR usz)
{
    CHAR szFileDevice[40];
    LPCSTR szINDENT[] = { "-", "--", "---", "----", "-----", "------" };
    CHAR uszDeviceExtraInfo[MAX_PATH];
    MSysDriver_DevGetExtraInfo(pe, uszDeviceExtraInfo);
    _snprintf_s(szFileDevice, _countof(szFileDevice), _TRUNCATE, "%s(%i)", pe->szDeviceType, pe->dwDeviceType);
    Util_usnprintf_ln(usz, cbLineLength,
        "%04x %s %16llx%*s %-32.32s %16llx %-16.16s %s %c %s",
        ie,
        szINDENT[min(5, pe->iDepth)],
        pe->va,
        5 - min(5, pe->iDepth),
        "",
        (pe->pObject && pe->pObject->uszName[0]) ? pe->pObject->uszName : "---",
        pe->pDriver->va,
        pe->pDriver->uszName,
        szFileDevice,
        uszDeviceExtraInfo[0] ? '/' : ' ',
        uszDeviceExtraInfo
    );
}

_Success_(return)
BOOL MSysDriver_EntryFromPath(_In_ LPCSTR uszPath, _In_ PVMMOB_MAP_KDRIVER pDrvMap, _Out_ PVMM_MAP_KDRIVERENTRY *ppDrvMapEntry, _Out_opt_ LPSTR *puszPath)
{
    DWORD i, dwHash;
    CHAR usz[MAX_PATH];
    if(_strnicmp(uszPath, "by-name\\", 8)) { return FALSE; }
    CharUtil_PathSplitFirst(uszPath + 8, usz, sizeof(usz));
    dwHash = CharUtil_HashNameFsU(usz, 0);
    for(i = 0; i < pDrvMap->cMap; i++) {
        if(dwHash == pDrvMap->pMap[i].dwHash) {
            if(puszPath) { *puszPath = (LPSTR)uszPath + 8; }
            *ppDrvMapEntry = pDrvMap->pMap + i;
            return TRUE;
        }
    }
    return FALSE;
}

NTSTATUS MSysDriver_Read(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_CONTEXT ctxP, _Out_writes_to_(cb, *pcbRead) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset)
{
    NTSTATUS nt = VMMDLL_STATUS_FILE_INVALID;
    PVMM_MAP_KDRIVERENTRY peDriver;
    PVMMOB_MAP_PTE pObPteMap = NULL;
    PVMMOB_MAP_KDRIVER pObDrvMap = NULL;
    PVMMOB_MAP_KDEVICE pObDevMap = NULL;
    PVMM_PROCESS pObSystemProcess = NULL;
    MSYSDRIVER_IRP_CONTEXT IrpCtx = { 0 };
    PVMMOB_MAP_MODULE pObModuleMap = NULL;
    POB_MAP pmObModuleByVA = NULL;
    CHAR uszBuffer[MAX_PATH];
    LPCSTR uszPath;
    if(!_stricmp(ctxP->uszPath, "devices.txt")) {
        if(!VmmMap_GetKDevice(H, &pObDevMap)) { goto cleanup; }
        nt = Util_VfsLineFixed_Read(
            H, (UTIL_VFSLINEFIXED_PFN_CB)MSysDriver_DevReadLineCB, NULL, MSYSDRIVER_DEV_LINELENGTH, MSYSDRIVER_DEV_LINEHEADER,
            pObDevMap->pMap, pObDevMap->cMap, sizeof(VMM_MAP_KDEVICEENTRY),
            pb, cb, pcbRead, cbOffset
        );
        goto cleanup;
    }
    if(!VmmMap_GetKDriver(H, &pObDrvMap)) { goto cleanup; }
    if(!(pObSystemProcess = VmmProcessGet(H, 4))) { goto cleanup; }
    if(!_stricmp(ctxP->uszPath, "drivers.txt")) {
        if(VmmMap_GetModule(H, pObSystemProcess, 0, &pObModuleMap)) {
            VmmMap_GetModuleEntryEx3(H, pObModuleMap, &pmObModuleByVA);
        }
        nt = Util_VfsLineFixed_Read(
            H, (UTIL_VFSLINEFIXED_PFN_CB)MSysDriver_DrvReadLineCB, pmObModuleByVA, MSYSDRIVER_DRV_LINELENGTH, MSYSDRIVER_DRV_LINEHEADER,
            pObDrvMap->pMap, pObDrvMap->cMap, sizeof(VMM_MAP_KDRIVERENTRY),
            pb, cb, pcbRead, cbOffset
        );
        goto cleanup;
    }
    if(!_stricmp(ctxP->uszPath, "driver_irp.txt")) {
        if(!VmmMap_GetPte(H, pObSystemProcess, &pObPteMap, TRUE)) { goto cleanup; }
        IrpCtx.pDrvMap = pObDrvMap;
        IrpCtx.pPteMap = pObPteMap;
        nt = Util_VfsLineFixed_Read(
            H, (UTIL_VFSLINEFIXED_PFN_CB)MSysDriver_IrpReadLineCB, &IrpCtx, MSYSDRIVER_IRP_LINELENGTH, MSYSDRIVER_IRP_LINEHEADER,
            pObDrvMap->pMap, pObDrvMap->cMap * 28ULL, 0,
            pb, cb, pcbRead, cbOffset
        );
        goto cleanup;
    }
    if(!_strnicmp("by-name\\", ctxP->uszPath, 8)) {
        if(MSysDriver_EntryFromPath(ctxP->uszPath, pObDrvMap, &peDriver, NULL)) {
            uszPath = CharUtil_PathSplitNext(ctxP->uszPath);
            uszPath = CharUtil_PathSplitNext(uszPath);
            if(strstr(uszPath, "\\")) {
                // module directory
                _snprintf_s(uszBuffer, _countof(uszBuffer), _TRUNCATE, "modules\\%s", uszPath);
                nt = PluginManager_Read(H, pObSystemProcess, uszBuffer, pb, cb, pcbRead, cbOffset);
            } else {
                // driver object directory
                nt = VmmWinObjDisplay_VfsRead(H, ctxP->uszPath, H->vmm.ObjectTypeTable.tpDriver, peDriver->va, pb, cb, pcbRead, cbOffset);
            }
        }
        goto cleanup;
    }
cleanup:
    Ob_DECREF(pObDevMap);
    Ob_DECREF(pObDrvMap);
    Ob_DECREF(pObPteMap);
    Ob_DECREF(pObModuleMap);
    Ob_DECREF(pmObModuleByVA);
    Ob_DECREF(pObSystemProcess);
    return nt;
}

BOOL MSysDriver_List(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_CONTEXT ctxP, _Inout_ PHANDLE pFileList)
{
    DWORD i;
    CHAR uszBuffer[MAX_PATH];
    LPCSTR uszPath;
    PVMM_MAP_KDRIVERENTRY peDriver;
    PVMMOB_MAP_KDEVICE pObDevMap = NULL;
    PVMMOB_MAP_KDRIVER pObDrvMap = NULL;
    PVMM_MAP_MODULEENTRY peModule;
    PVMMOB_MAP_MODULE pObModuleMap = NULL;
    PVMM_PROCESS pObSystemProcess = NULL;
    if(!VmmMap_GetKDevice(H, &pObDevMap)) { goto finish; }
    if(!VmmMap_GetKDriver(H, &pObDrvMap)) { goto finish; }
    if(!ctxP->uszPath[0]) {
        VMMDLL_VfsList_AddDirectory(pFileList, "by-name", NULL);
        VMMDLL_VfsList_AddFile(pFileList, "devices.txt", UTIL_VFSLINEFIXED_LINECOUNT(H, pObDevMap->cMap) * MSYSDRIVER_DEV_LINELENGTH, NULL);
        VMMDLL_VfsList_AddFile(pFileList, "drivers.txt", UTIL_VFSLINEFIXED_LINECOUNT(H, pObDrvMap->cMap) * MSYSDRIVER_DRV_LINELENGTH, NULL);
        VMMDLL_VfsList_AddFile(pFileList, "driver_irp.txt", UTIL_VFSLINEFIXED_LINECOUNT(H, pObDrvMap->cMap * 28ULL) * MSYSDRIVER_IRP_LINELENGTH, NULL);
        goto finish;
    }
    if(!_stricmp(ctxP->uszPath, "by-name")) {
        for(i = 0; i < pObDrvMap->cMap; i++) {
            VMMDLL_VfsList_AddDirectory(pFileList, pObDrvMap->pMap[i].uszName, NULL);
        }
        goto finish;
    }
    if(MSysDriver_EntryFromPath(ctxP->uszPath, pObDrvMap, &peDriver, (LPSTR*)&uszPath) && uszPath[0] && (pObSystemProcess = VmmProcessGet(H, 4))) {
        uszPath = CharUtil_PathSplitNext(uszPath);
        if(0 == uszPath[0]) {
            VmmWinObjDisplay_VfsList(H, H->vmm.ObjectTypeTable.tpDriver, peDriver->va, pFileList);
            if(VmmMap_GetModule(H, pObSystemProcess, 0, &pObModuleMap) && (peModule = VmmMap_GetModuleEntryEx2(H, pObModuleMap, peDriver->vaStart))) {
                VMMDLL_VfsList_AddDirectory(pFileList, peModule->uszText, NULL);
            }
        } else {
            // forward link to module:
            _snprintf_s(uszBuffer, _countof(uszBuffer), _TRUNCATE, "modules\\%s\\", uszPath);
            PluginManager_List(H, pObSystemProcess, uszBuffer, pFileList);
        }
        goto finish;
    }
finish:
    Ob_DECREF(pObDevMap);
    Ob_DECREF(pObDrvMap);
    Ob_DECREF(pObModuleMap);
    Ob_DECREF(pObSystemProcess);
    return TRUE;
}

VOID MSysDriver_FcLogJSON_Device(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_CONTEXT ctxP, _In_ VOID(*pfnLogJSON)(_In_ VMM_HANDLE H, _In_ PVMMDLL_FORENSIC_JSONDATA pData))
{
    PVMMDLL_FORENSIC_JSONDATA pd;
    PVMMOB_MAP_KDEVICE pObDevMap = NULL;
    PVMM_MAP_KDEVICEENTRY pe;
    DWORD i;
    CHAR usz[MAX_PATH];
    CHAR uszDeviceExtraInfoBuffer[MAX_PATH];
    if(ctxP->pProcess || !(pd = LocalAlloc(LMEM_ZEROINIT, sizeof(VMMDLL_FORENSIC_JSONDATA)))) { return; }
    pd->dwVersion = VMMDLL_FORENSIC_JSONDATA_VERSION;
    pd->szjType = "device";
    pd->fNum[0] = TRUE;
    if(VmmMap_GetKDevice(H, &pObDevMap)) {
        for(i = 0; i < pObDevMap->cMap; i++) {
            pe = pObDevMap->pMap + i;
            pd->i = i;
            pd->vaObj = pe->va;
            pd->qwNum[0] = pe->iDepth;
            pd->va[0] = pe->vaAttachedDevice;
            pd->va[1] = pe->pDriver->va;
            pd->usz[0] = ((pe->pObject && pe->pObject->uszName) ? pe->pObject->uszName : "");
            MSysDriver_DevGetExtraInfo(pe, uszDeviceExtraInfoBuffer);
            if(uszDeviceExtraInfoBuffer[0]) {
                snprintf(usz, sizeof(usz), "driver:[%s] extrainfo:[%s]", pe->pDriver->uszPath, uszDeviceExtraInfoBuffer);
            } else {
                snprintf(usz, sizeof(usz), "driver:[%s]", pe->pDriver->uszPath);
            }
            pd->usz[1] = usz;
            pfnLogJSON(H, pd);
        }
    }
    Ob_DECREF(pObDevMap);
    LocalFree(pd);
}

VOID MSysDriver_FcLogJSON_Driver(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_CONTEXT ctxP, _In_ VOID(*pfnLogJSON)(_In_ VMM_HANDLE H, _In_ PVMMDLL_FORENSIC_JSONDATA pData))
{
    PVMMDLL_FORENSIC_JSONDATA pd;
    PVMMOB_MAP_KDRIVER pObDrvMap = NULL;
    PVMM_MAP_KDRIVERENTRY pe;
    DWORD i;
    CHAR usz[MAX_PATH];
    if(ctxP->pProcess || !(pd = LocalAlloc(LMEM_ZEROINIT, sizeof(VMMDLL_FORENSIC_JSONDATA)))) { return; }
    pd->dwVersion = VMMDLL_FORENSIC_JSONDATA_VERSION;
    pd->szjType = "driver";
    if(VmmMap_GetKDriver(H, &pObDrvMap)) {
        for(i = 0; i < pObDrvMap->cMap; i++) {
            pe = pObDrvMap->pMap + i;
            pd->i = i;
            pd->vaObj = pe->va;
            pd->qwNum[0] = pe->cbDriverSize;
            pd->va[0] = pe->vaStart;
            pd->va[1] = pe->cbDriverSize ? (pe->vaStart + pe->cbDriverSize - 1) : pe->vaStart;
            pd->usz[0] = pe->uszName;
            snprintf(usz, sizeof(usz), "svc:[%s] path:[%s]", pe->uszServiceKeyName, pe->uszPath);
            pd->usz[1] = usz;
            pfnLogJSON(H, pd);
        }
    }
    Ob_DECREF(pObDrvMap);
    LocalFree(pd);
}

VOID MSysDriver_FcLogJSON(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_CONTEXT ctxP, _In_ VOID(*pfnLogJSON)(_In_ VMM_HANDLE H, _In_ PVMMDLL_FORENSIC_JSONDATA pData))
{
    if(ctxP->pProcess) { return; }
    MSysDriver_FcLogJSON_Driver(H, ctxP, pfnLogJSON);
    MSysDriver_FcLogJSON_Device(H, ctxP, pfnLogJSON);
}

PVOID MSysDriver_FcInitialize(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_CONTEXT ctxP)
{
    FcFileAppend(H, "drivers.csv", MSYSDRIVER_CSV_DRIVERS);
    FcFileAppend(H, "devices.csv", MSYSDRIVER_CSV_DEVICES);
    return NULL;
}

VOID MSysDriver_FcLogCSV_Device(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_CONTEXT ctxP, _In_ VMMDLL_CSV_HANDLE hCSV)
{
    DWORD i;
    PVMM_MAP_KDEVICEENTRY pe;
    PVMMOB_MAP_KDEVICE pObDeviceMap = NULL;
    CHAR uszDeviceExtraInfoBuffer[MAX_PATH];
    if(!VmmMap_GetKDevice(H, &pObDeviceMap)) { return; }
    for(i = 0; i < pObDeviceMap->cMap; i++) {
        pe = pObDeviceMap->pMap + i;
        //"Name,ObjectAddress,Depth,AttachedDeviceAddress,DriverName,DriverPath,DriverObjectAddress,ExtraInfo"
        FcCsv_Reset(hCSV);
        FcFileAppend(H, "devices.csv", "%s,0x%llx,%i,0x%llx,%s,%s,0x%llx,%s\n",
            FcCsv_String(hCSV, ((pe->pObject && pe->pObject->uszName) ? pe->pObject->uszName : "")),
            pe->va,
            pe->iDepth,
            pe->vaAttachedDevice,
            FcCsv_String(hCSV, pe->pDriver->uszName),
            FcCsv_String(hCSV, pe->pDriver->uszPath),
            pe->pDriver->va,
            MSysDriver_DevGetExtraInfo(pe, uszDeviceExtraInfoBuffer)
        );
    }
    Ob_DECREF(pObDeviceMap);
}

VOID MSysDriver_FcLogCSV_Driver(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_CONTEXT ctxP, _In_ VMMDLL_CSV_HANDLE hCSV)
{
    PVMM_MAP_KDRIVERENTRY pe;
    PVMMOB_MAP_KDRIVER pObDriverMap = NULL;
    PVMMOB_MAP_MODULE pObModuleMap = NULL;
    PVMM_MAP_MODULEENTRY peModule;
    POB_MAP pmObModuleByVA = NULL;
    DWORD i;
    if(!VmmMap_GetKDriver(H, &pObDriverMap)) { return; }
    if(VmmMap_GetModule(H, (PVMM_PROCESS)ctxP->pProcess, 0, &pObModuleMap)) {
        VmmMap_GetModuleEntryEx3(H, pObModuleMap, &pmObModuleByVA);
    }
    for(i = 0; i < pObDriverMap->cMap; i++) {
        pe = pObDriverMap->pMap + i;
        peModule = (PVMM_MAP_MODULEENTRY)ObMap_GetByKey(pmObModuleByVA, pe->vaStart);
        //"Name,ObjectAddress,Size,Start,End,ServiceKey,DriverName,DriverPath"
        FcCsv_Reset(hCSV);
        FcFileAppend(H, "drivers.csv", "%s,0x%llx,0x%llx,0x%llx,0x%llx,%s,%s,%s\n",
            FcCsv_String(hCSV, pe->uszName),
            pe->va,
            pe->cbDriverSize,
            pe->vaStart,
            pe->cbDriverSize ? (pe->vaStart + pe->cbDriverSize - 1) : pe->vaStart,
            FcCsv_String(hCSV, pe->uszServiceKeyName),
            FcCsv_String(hCSV, pe->uszPath),
            (peModule && peModule->uszFullName) ? FcCsv_String(hCSV, peModule->uszFullName) : ""
        );
    }
    Ob_DECREF(pObDriverMap);
    Ob_DECREF(pObModuleMap);
    Ob_DECREF(pmObModuleByVA);
}

VOID MSysDriver_FcLogCSV(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_CONTEXT ctxP, _In_ VMMDLL_CSV_HANDLE hCSV)
{
    PVMM_PROCESS pSystemProcess = (PVMM_PROCESS)ctxP->pProcess;
    if(pSystemProcess && (pSystemProcess->dwPID == 4)) {
        MSysDriver_FcLogCSV_Driver(H, ctxP, hCSV);
        MSysDriver_FcLogCSV_Device(H, ctxP, hCSV);
    }
}

VOID M_SysDriver_Initialize(_In_ VMM_HANDLE H, _Inout_ PVMMDLL_PLUGIN_REGINFO pRI)
{
    if((pRI->magic != VMMDLL_PLUGIN_REGINFO_MAGIC) || (pRI->wVersion != VMMDLL_PLUGIN_REGINFO_VERSION)) { return; }
    if((pRI->tpSystem != VMMDLL_SYSTEM_WINDOWS_64) && (pRI->tpSystem != VMMDLL_SYSTEM_WINDOWS_32)) { return; }
    if(pRI->sysinfo.dwVersionBuild < 7600) { return; }              // WIN7+ required
    strcpy_s(pRI->reg_info.uszPathName, 128, "\\sys\\drivers");     // module name
    pRI->reg_info.fRootModule = TRUE;                               // module shows in root directory
    pRI->reg_fn.pfnList = MSysDriver_List;                          // List function supported
    pRI->reg_fn.pfnRead = MSysDriver_Read;                          // Read function supported
    pRI->reg_fnfc.pfnInitialize = MSysDriver_FcInitialize;          // Forensic initialize function supported
    pRI->reg_fnfc.pfnLogCSV = MSysDriver_FcLogCSV;                  // CSV log function supported
    pRI->reg_fnfc.pfnLogJSON = MSysDriver_FcLogJSON;                // JSON log function supported
    pRI->pfnPluginManager_Register(H, pRI);
}
