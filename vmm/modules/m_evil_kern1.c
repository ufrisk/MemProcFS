// m_evil_kern1.c : evil detectors for various kernel issues #1.
// 
// Detections:
//  - DRIVER_PATH
//
// (c) Ulf Frisk, 2023-2025
// Author: Ulf Frisk, pcileech@frizk.net
//

#include "modules.h"

/*
* VMMEVIL_TYPE: DRIVER_PATH
* Locate kernel drivers loaded from non standard paths.
*/
VOID MEvilKern1_KDriverPath(_In_ VMM_HANDLE H, _In_ VMMDLL_MODULE_ID MID, _In_ PVMM_PROCESS pSystemProcess)
{
    // add more allowed paths to the list below:
    LPSTR szPATH_ALLOWLIST[] = {
        "\\SystemRoot\\system32\\DRIVERS\\",
        "\\SystemRoot\\System32\\DriverStore\\",
        "\\SystemRoot\\system32\\ntoskrnl.exe",
        "\\SystemRoot\\System32\\win32k",
        "\\SystemRoot\\system32\\hal.dll",
        "\\SystemRoot\\system32\\cdd.dll",
        "\\??\\C:\\Windows\\system32\\DRIVERS\\",
        "\\??\\C:\\Windows\\System32\\DriverStore\\",
        "\\??\\C:\\ProgramData\\Microsoft\\Windows Defender\\Definition Updates\\",
    };
    POB_MAP pmObModuleByVA = NULL;
    PVMMOB_MAP_MODULE pObModuleMap = NULL;
    PVMMOB_MAP_KDRIVER pObDriverMap = NULL;
    PVMM_MAP_KDRIVERENTRY peDriver;
    PVMM_MAP_MODULEENTRY peModule;
    DWORD iDriver, iPathAllow;
    BOOL fOK;
    if(!VmmMap_GetKDriver(H, &pObDriverMap)) { goto fail; }
    if(!VmmMap_GetModule(H, pSystemProcess, 0, &pObModuleMap)) { goto fail; }
    if(!VmmMap_GetModuleEntryEx3(H, pObModuleMap, &pmObModuleByVA)) { goto fail; }
    for(iDriver = 0; iDriver < pObDriverMap->cMap; iDriver++) {
        peDriver = pObDriverMap->pMap + iDriver;
        peModule = ObMap_GetByKey(pmObModuleByVA, peDriver->vaStart);
        if(!peModule) {
            if(CharUtil_StrStartsWith(peDriver->uszPath, "\\FileSystem\\RAW", TRUE)) { continue; }
            // evil: driver has no linked module:
            FcEvilAdd(H, EVIL_DRIVER_PATH, pSystemProcess, peDriver->va, "Driver:[%s] Module:[NOT_FOUND]", peDriver->uszName);
            VmmLog(H, MID, LOGLEVEL_5_DEBUG, "%s: Driver:[%s] Module:[NOT_FOUND]", EVIL_DRIVER_PATH.Name, peDriver->uszName);
            continue;
        }
        fOK = FALSE;
        for(iPathAllow = 0; iPathAllow < (sizeof(szPATH_ALLOWLIST) / sizeof(LPCSTR)); iPathAllow++) {
            if(CharUtil_StrStartsWith(peModule->uszFullName, szPATH_ALLOWLIST[iPathAllow], TRUE)) {
                fOK = TRUE;
                break;
            }
        }
        if(fOK) { continue; }
        // evil: driver module not loaded from path in allowlist:
        FcEvilAdd(H, EVIL_DRIVER_PATH, pSystemProcess, peDriver->va, "Driver:[%s] Module:[%s]", peDriver->uszName, peModule->uszFullName);
        VmmLog(H, MID, LOGLEVEL_5_DEBUG, "%s: Driver:[%s] Module:[%s] ", EVIL_DRIVER_PATH.Name, peDriver->uszName, peModule->uszFullName);
    }
fail:
    Ob_DECREF(pmObModuleByVA);
    Ob_DECREF(pObModuleMap);
    Ob_DECREF(pObDriverMap);
}

VOID MEvilKern1_DoWork(_In_ VMM_HANDLE H, _In_ VMMDLL_MODULE_ID MID, _In_opt_ PVOID ctxfc)
{
    PVMM_PROCESS pObSystemProcess = NULL;
    if(H->fAbort) { return; }
    if(!(pObSystemProcess = VmmProcessGet(H, 4))) { return; }
    MEvilKern1_KDriverPath(H, MID, pObSystemProcess);
    VmmLog(H, MID, LOGLEVEL_6_TRACE, "COMPLETED FINDEVIL SCAN");
    Ob_DECREF(pObSystemProcess);
}

VOID M_Evil_Kern1(_In_ VMM_HANDLE H, _Inout_ PVMMDLL_PLUGIN_REGINFO pRI)
{
    if((pRI->magic != VMMDLL_PLUGIN_REGINFO_MAGIC) || (pRI->wVersion != VMMDLL_PLUGIN_REGINFO_VERSION)) { return; }
    if(pRI->sysinfo.f32 || (pRI->sysinfo.dwVersionBuild < 9600)) { return; }    // only support 64-bit Win8.1+ for now
    // register findevil plugin:
    strcpy_s(pRI->reg_info.uszPathName, 128, "\\findevil\\EvKRNL1");
    pRI->reg_info.fRootModule = TRUE;
    pRI->reg_info.fRootModuleHidden = TRUE;
    pRI->reg_fnfc.pfnFindEvil = MEvilKern1_DoWork;
    pRI->pfnPluginManager_Register(H, pRI);
}
