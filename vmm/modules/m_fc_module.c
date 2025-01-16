// m_fc_module.c : module forensic module.
//
// REQUIRE: FORENSIC SUB-SYSTEM INIT.
//
// NB! module generate forensic data only - no file system presence!
//
// (c) Ulf Frisk, 2021-2025
// Author: Ulf Frisk, pcileech@frizk.net
//

#include "modules.h"

static LPSTR MFCMODULE_CSV_MODULES = "PID,Process,Name,Wow64,Size,Start,End,#Imports,#Exports,#Sections,Path,KernelPath,VerCompanyName,VerFileDescription,VerFileVersion,VerInternalName,VerLegalCopyright,VerOriginalFilename,VerProductName,VerProductVersion,PdbPath,PdbAge,PdbHexGUID,PdbSymbolServer\n";
static LPSTR MFCMODULE_CSV_UNLOADEDMODULES = "PID,Process,ModuleName,UnloadTime,Wow64,Size,Start,End\n";

VOID MFcModule_LogModule(_In_ VMM_HANDLE H, _In_ PVMMDLL_FORENSIC_JSONDATA pd, _In_ VOID(*pfnLogJSON)(_In_ VMM_HANDLE H, _In_ PVMMDLL_FORENSIC_JSONDATA pData), _In_ PVMMOB_MAP_MODULE pMap)
{
    DWORD i;
    PVMM_MAP_MODULEENTRY pe;
    for(i = 0; i < pMap->cMap; i++) {
        pe = pMap->pMap + i;
        pd->i = i;
        pd->qwNum[0] = pe->cbImageSize;
        pd->qwNum[1] = pe->fWoW64 ? 32 : 0;
        pd->qwHex[0] = pe->cbImageSize >> 12;
        pd->va[0] = pe->vaBase;
        pd->va[1] = pe->vaBase + pe->cbImageSize - 1;
        pd->usz[0] = pe->uszText;
        pfnLogJSON(H, pd);
    }
}

VOID MFcModule_LogModuleDebugInfo(_In_ VMM_HANDLE H, _In_ PVMMDLL_FORENSIC_JSONDATA pd, _In_ VOID(*pfnLogJSON)(_In_ VMM_HANDLE H, _In_ PVMMDLL_FORENSIC_JSONDATA pData), _In_ PVMMOB_MAP_MODULE pMap)
{
    DWORD i;
    CHAR usz[MAX_PATH];
    PVMM_MAP_MODULEENTRY pe;
    for(i = 0; i < pMap->cMap; i++) {
        pe = pMap->pMap + i;
        snprintf(usz, sizeof(usz), "AGE=[%i] GUID=[%s] PDB=[%s]", pe->pExDebugInfo->dwAge, pe->pExDebugInfo->uszGuid, pe->pExDebugInfo->uszPdbFilename);
        pd->i = i;
        pd->qwNum[0] = pe->pExDebugInfo->dwAge;
        pd->va[0] = pe->vaBase;
        pd->usz[0] = pe->uszText;
        pd->usz[1] = usz;
        pfnLogJSON(H, pd);
    }
}

VOID MFcModule_LogModuleVersionInfo(_In_ VMM_HANDLE H, _In_ PVMMDLL_FORENSIC_JSONDATA pd, _In_ VOID(*pfnLogJSON)(_In_ VMM_HANDLE H, _In_ PVMMDLL_FORENSIC_JSONDATA pData), _In_ PVMMOB_MAP_MODULE pMap)
{
    DWORD i;
    CHAR usz[0x1000];
    PVMM_MAP_MODULEENTRY pe;
    for(i = 0; i < pMap->cMap; i++) {
        pe = pMap->pMap + i;
        snprintf(usz, sizeof(usz), "CompanyName=[%s] FileDescription=[%s] FileVersion=[%s] InternalName=[%s] LegalCopyright=[%s] OriginalFilename=[%s] ProductName=[%s] ProductVersion=[%s]",
            pe->pExVersionInfo->uszCompanyName,
            pe->pExVersionInfo->uszFileDescription,
            pe->pExVersionInfo->uszFileVersion,
            pe->pExVersionInfo->uszInternalName,
            pe->pExVersionInfo->uszLegalCopyright,
            pe->pExVersionInfo->uszOriginalFilename,
            pe->pExVersionInfo->uszProductName,
            pe->pExVersionInfo->uszProductVersion
        );
        pd->i = i;
        pd->va[0] = pe->vaBase;
        pd->usz[0] = pe->uszText;
        pd->usz[1] = usz;
        pfnLogJSON(H, pd);
    }
}

VOID MFcModule_LogUnloadedModule(_In_ VMM_HANDLE H, _In_ PVMMDLL_FORENSIC_JSONDATA pd, _In_ VOID(*pfnLogJSON)(_In_ VMM_HANDLE H, _In_ PVMMDLL_FORENSIC_JSONDATA pData), PVMMOB_MAP_UNLOADEDMODULE pMap)
{
    DWORD i;
    PVMM_MAP_UNLOADEDMODULEENTRY pe;
    for(i = 0; i < pMap->cMap; i++) {
        pe = pMap->pMap + i;
        pd->i = i;
        pd->qwNum[0] = pe->cbImageSize;
        pd->qwNum[1] = pe->fWoW64 ? 32 : 0;
        pd->qwHex[0] = pe->cbImageSize >> 12;
        pd->va[0] = pe->vaBase;
        pd->va[1] = pe->vaBase + pe->cbImageSize - 1;
        pd->usz[0] = pe->uszText;
        pfnLogJSON(H, pd);
    }
}

VOID MFcModule_FcLogJSON(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_CONTEXT ctxP, _In_ VOID(*pfnLogJSON)(_In_ VMM_HANDLE H, _In_ PVMMDLL_FORENSIC_JSONDATA pData))
{
    PVMM_PROCESS pProcess = ctxP->pProcess;
    PVMMDLL_FORENSIC_JSONDATA pd;
    PVMMOB_MAP_UNLOADEDMODULE pObUnloadedModuleMap = NULL;
    PVMMOB_MAP_MODULE pObModuleMap = NULL, pObModuleMap_DebugInfo = NULL, pObModuleMap_VersionInfo = NULL;
    if(!pProcess || !(pd = LocalAlloc(LMEM_ZEROINIT, sizeof(VMMDLL_FORENSIC_JSONDATA)))) { return; }
    // loaded modules:
    FC_JSONDATA_INIT_PIDTYPE(pd, pProcess->dwPID, "module");
    if(VmmMap_GetModule(H, pProcess, 0, &pObModuleMap)) {
        if(H->fAbort) { goto fail; }
        MFcModule_LogModule(H, pd, pfnLogJSON, pObModuleMap);
    }
    // module pdb debuginfo / codeview:
    FC_JSONDATA_INIT_PIDTYPE(pd, pProcess->dwPID, "module-codeview");
    if(VmmMap_GetModule(H, pProcess, VMM_MODULE_FLAG_DEBUGINFO, &pObModuleMap_DebugInfo)) {
        if(H->fAbort) { goto fail; }
        MFcModule_LogModuleDebugInfo(H, pd, pfnLogJSON, pObModuleMap_DebugInfo);
    }
    // module versioninfo
    FC_JSONDATA_INIT_PIDTYPE(pd, pProcess->dwPID, "module-versioninfo");
    if(VmmMap_GetModule(H, pProcess, VMM_MODULE_FLAG_VERSIONINFO, &pObModuleMap_VersionInfo)) {
        if(H->fAbort) { goto fail; }
        MFcModule_LogModuleVersionInfo(H, pd, pfnLogJSON, pObModuleMap_VersionInfo);
    }
    // unloaded modules:
    FC_JSONDATA_INIT_PIDTYPE(pd, pProcess->dwPID, "unloadedmodule");
    if(VmmMap_GetUnloadedModule(H, pProcess, &pObUnloadedModuleMap)) {
        if(H->fAbort) { goto fail; }
        MFcModule_LogUnloadedModule(H, pd, pfnLogJSON, pObUnloadedModuleMap);
    }
fail:
    Ob_DECREF(pObModuleMap);
    Ob_DECREF(pObUnloadedModuleMap);
    Ob_DECREF(pObModuleMap_DebugInfo);
    Ob_DECREF(pObModuleMap_VersionInfo);
    LocalFree(pd);
}

VOID MFcModule_LogModuleCSV(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess, _In_ VMMDLL_CSV_HANDLE hCSV, _In_ PVMMOB_MAP_MODULE pMap)
{
    BOOL fSuppressDriver;
    DWORD i;
    PVMM_MAP_MODULEENTRY pe;
    PVMM_MAP_VADENTRY peVad = NULL;
    PVMMOB_MAP_VAD pObVadMap = NULL;
    CHAR szSymbolServer[MAX_PATH];
    VmmMap_GetVad(H, pProcess, &pObVadMap, VMM_VADMAP_TP_FULL);
    fSuppressDriver = !_stricmp(pProcess->szName, "csrss.exe") || !_stricmp(pProcess->szName, "Registry");
    for(i = 0; i < pMap->cMap; i++) {
        pe = pMap->pMap + i;
        if(fSuppressDriver && CharUtil_StrEndsWith(pe->uszText, ".sys", FALSE)) { continue; }
        peVad = VmmMap_GetVadEntry(H, pObVadMap, pe->vaBase);
        VmmWinLdrModule_SymbolServer(H, pe, TRUE, _countof(szSymbolServer), szSymbolServer);
        //"PID,Process,Name,Wow64,Size,Start,End,#Imports,#Exports,#Sections,Path,KernelPath,VerCompanyName,VerFileDescription,VerFileVersion,VerInternalName,VerLegalCopyright,VerOriginalFilename,VerProductName,VerProductVersion,PdbPath,PdbAge,PdbHexGUID,PdbSymbolServer"
        FcCsv_Reset(hCSV);
        FcFileAppend(H, "modules.csv", "%i,%s,%s,%i,0x%x,0x%llx,0x%llx,%i,%i,%i,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%i,%s,%s\n",
            pProcess->dwPID,
            FcCsv_String(hCSV, pProcess->pObPersistent->uszNameLong),
            FcCsv_String(hCSV, pe->uszText),
            pe->fWoW64 ? 1 : 0,
            pe->cbImageSize,
            pe->vaBase,
            pe->vaBase + pe->cbImageSize - 1,
            pe->cIAT,
            pe->cEAT,
            pe->cSection,
            FcCsv_String(hCSV, pe->uszFullName),
            peVad ? FcCsv_String(hCSV, peVad->uszText) : "",
            FcCsv_String(hCSV, pe->pExVersionInfo->uszCompanyName),
            FcCsv_String(hCSV, pe->pExVersionInfo->uszFileDescription),
            FcCsv_String(hCSV, pe->pExVersionInfo->uszFileVersion),
            FcCsv_String(hCSV, pe->pExVersionInfo->uszInternalName),
            FcCsv_String(hCSV, pe->pExVersionInfo->uszLegalCopyright),
            FcCsv_String(hCSV, pe->pExVersionInfo->uszOriginalFilename),
            FcCsv_String(hCSV, pe->pExVersionInfo->uszProductName),
            FcCsv_String(hCSV, pe->pExVersionInfo->uszProductVersion),
            FcCsv_String(hCSV, pe->pExDebugInfo->uszPdbFilename),
            pe->pExDebugInfo->dwAge,
            FcCsv_String(hCSV, pe->pExDebugInfo->uszGuid),
            FcCsv_String(hCSV, szSymbolServer)
        );
    }
    Ob_DECREF(pObVadMap);
}

VOID MFcModule_LogUnloadedModuleCSV(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess, _In_ VMMDLL_CSV_HANDLE hCSV, _In_ PVMMOB_MAP_UNLOADEDMODULE pMap)
{
    DWORD i;
    CHAR vszTimeUnload[24];
    PVMM_MAP_UNLOADEDMODULEENTRY pe;
    for(i = 0; i < pMap->cMap; i++) {
        pe = pMap->pMap + i;
        Util_FileTime2CSV(pe->ftUnload, vszTimeUnload);
        //"PID,Process,ModuleName,UnloadTime,Wow64,Size,Start,End"
        FcCsv_Reset(hCSV);
        FcFileAppend(H, "unloaded_modules.csv", "%i,%s,%s,%s,%i,0x%x,0x%llx,0x%llx\n",
            pProcess->dwPID,
            FcCsv_String(hCSV, pProcess->pObPersistent->uszNameLong),
            FcCsv_String(hCSV, pe->uszText),
            vszTimeUnload,
            pe->fWoW64 ? 1 : 0,
            pe->cbImageSize,
            pe->vaBase,
            pe->vaBase + pe->cbImageSize - 1
        );
    }
}

VOID MFcModule_FcLogCSV(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_CONTEXT ctxP, _In_ VMMDLL_CSV_HANDLE hCSV)
{
    PVMM_PROCESS pProcess = ctxP->pProcess;
    PVMMOB_MAP_UNLOADEDMODULE pObUnloadedModuleMap = NULL;
    PVMMOB_MAP_MODULE pObModuleMap = NULL;
    if(!pProcess) { return; }
    // loaded modules:
    if(VmmMap_GetModule(H, pProcess, VMM_MODULE_FLAG_DEBUGINFO | VMM_MODULE_FLAG_VERSIONINFO, &pObModuleMap)) {
        if(H->fAbort) { goto fail; }
        MFcModule_LogModuleCSV(H, pProcess, hCSV, pObModuleMap);
    }
    // unloaded modules:
    if(VmmMap_GetUnloadedModule(H, pProcess, &pObUnloadedModuleMap)) {
        if(H->fAbort) { goto fail; }
        if(_stricmp(pProcess->szName, "csrss.exe") && _stricmp(pProcess->szName, "Registry") && _stricmp(pProcess->szName, "vmmem")) {
            MFcModule_LogUnloadedModuleCSV(H, pProcess, hCSV, pObUnloadedModuleMap);
        }
    }
fail:
    Ob_DECREF(pObModuleMap);
    Ob_DECREF(pObUnloadedModuleMap);
}

PVOID MFcModule_FcInitialize(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_CONTEXT ctxP)
{
    FcFileAppend(H, "modules.csv", MFCMODULE_CSV_MODULES);
    FcFileAppend(H, "unloaded_modules.csv", MFCMODULE_CSV_UNLOADEDMODULES);
    return NULL;
}

/*
* Plugin initialization / registration function called by the plugin manager.
* -- H
* -- pRI
*/
VOID M_FcModule_Initialize(_In_ VMM_HANDLE H, _Inout_ PVMMDLL_PLUGIN_REGINFO pRI)
{
    if((pRI->magic != VMMDLL_PLUGIN_REGINFO_MAGIC) || (pRI->wVersion != VMMDLL_PLUGIN_REGINFO_VERSION)) { return; }
    if((pRI->tpSystem != VMM_SYSTEM_WINDOWS_64) && (pRI->tpSystem != VMM_SYSTEM_WINDOWS_32)) { return; }
    strcpy_s(pRI->reg_info.uszPathName, 128, "\\forensic\\hidden\\module");     // module name
    pRI->reg_info.fRootModule = TRUE;                                           // module shows in root directory
    pRI->reg_info.fRootModuleHidden = TRUE;                                     // module hidden by default
    pRI->reg_fnfc.pfnInitialize = MFcModule_FcInitialize;                       // Forensic initialize supported
    pRI->reg_fnfc.pfnLogCSV = MFcModule_FcLogCSV;                               // CSV log function supported
    pRI->reg_fnfc.pfnLogJSON = MFcModule_FcLogJSON;                             // JSON log function supported
    pRI->pfnPluginManager_Register(H, pRI);
}
