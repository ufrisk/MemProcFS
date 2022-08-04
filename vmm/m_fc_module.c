// m_fc_module.c : module forensic module.
//
// REQUIRE: FORENSIC SUB-SYSTEM INIT.
//
// NB! module generate forensic data only - no file system presence!
//
// (c) Ulf Frisk, 2021-2022
// Author: Ulf Frisk, pcileech@frizk.net
//

#include "fc.h"
#include "vmm.h"
#include "pe.h"
#include "pluginmanager.h"
#include "charutil.h"
#include "util.h"

static LPSTR MFCMODULE_CSV_MODULES = "PID,Name,Wow64,Size,Start,End,#Imports,#Exports,#Sections,Path,KernelPath,PdbPath,PdbAge,PdbHexGUID\n";
static LPSTR MFCMODULE_CSV_UNLOADEDMODULES = "PID,ModuleName,UnloadTime,Wow64,Size,Start,End\n";

_Success_(return)
BOOL MFcModule_GetCodeView(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess, PVMM_MAP_MODULEENTRY peM, _Out_writes_(33) LPSTR szGUID, _Out_writes_(MAX_PATH) LPSTR szPdbFileName, _Out_ PDWORD pdwAge)
{
    LPCSTR szHEX_ALPHABET = "0123456789ABCDEF";
    BYTE b;
    DWORD i, j;
    PE_CODEVIEW_INFO CodeViewInfo = { 0 };
    szGUID[0] = 0;
    szPdbFileName[0] = 0;
    *pdwAge = 0;
    if(!PE_GetCodeViewInfo(H, pProcess, peM->vaBase, NULL, &CodeViewInfo)) { return FALSE; }
    // guid -> hex
    for(i = 0, j = 0; i < 16; i++) {
        b = CodeViewInfo.CodeView.Guid[i];
        szGUID[j++] = szHEX_ALPHABET[b >> 4];
        szGUID[j++] = szHEX_ALPHABET[b & 7];
    }
    szGUID[32] = 0;
    strncpy_s(szPdbFileName, MAX_PATH, CodeViewInfo.CodeView.PdbFileName, _TRUNCATE);
    *pdwAge = CodeViewInfo.CodeView.Age;
    return TRUE;
}

VOID MFcModule_LogCodeView(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_FORENSIC_JSONDATA pd, _In_ VOID(*pfnLogJSON)(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_FORENSIC_JSONDATA pData), _In_ PVMM_PROCESS pProcess, _In_ PVMM_MAP_MODULEENTRY peM)
{
    DWORD dwAge;
    CHAR usz[MAX_PATH], szGUID[33], szPdbFileName[MAX_PATH];
    if(MFcModule_GetCodeView(H, pProcess, peM, szGUID, szPdbFileName, &dwAge)) {
        snprintf(usz, sizeof(usz), "AGE=[%i] GUID=[%s] PDB=[%s]", dwAge, szGUID, szPdbFileName);
        pd->qwNum[0] = dwAge;
        pd->usz[0] = peM->uszText;
        pd->usz[1] = usz;
        pfnLogJSON(H, pd);
    }
}

VOID MFcModule_LogModule(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_FORENSIC_JSONDATA pd, _In_ VOID(*pfnLogJSON)(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_FORENSIC_JSONDATA pData), _In_ PVMMOB_MAP_MODULE pMap)
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

VOID MFcModule_LogUnloadedModule(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_FORENSIC_JSONDATA pd, _In_ VOID(*pfnLogJSON)(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_FORENSIC_JSONDATA pData), PVMMOB_MAP_UNLOADEDMODULE pMap)
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

VOID MFcModule_FcLogJSON(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_CONTEXT ctxP, _In_ VOID(*pfnLogJSON)(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_FORENSIC_JSONDATA pData))
{
    PVMM_PROCESS pProcess = ctxP->pProcess;
    PVMMDLL_PLUGIN_FORENSIC_JSONDATA pd;
    PVMMOB_MAP_UNLOADEDMODULE pObUnloadedModuleMap = NULL;
    PVMMOB_MAP_MODULE pObModuleMap = NULL;
    PVMM_MAP_MODULEENTRY peM;
    DWORD i;
    if(!pProcess || !(pd = LocalAlloc(LMEM_ZEROINIT, sizeof(VMMDLL_PLUGIN_FORENSIC_JSONDATA)))) { return; }
    // loaded modules:
    FC_JSONDATA_INIT_PIDTYPE(pd, pProcess->dwPID, "module");
    if(VmmMap_GetModule(H, pProcess, &pObModuleMap)) {
        if(H->fAbort) { goto fail; }
        MFcModule_LogModule(H, pd, pfnLogJSON, pObModuleMap);
    }
    // unloaded modules:
    FC_JSONDATA_INIT_PIDTYPE(pd, pProcess->dwPID, "unloadedmodule");
    if(VmmMap_GetUnloadedModule(H, pProcess, &pObUnloadedModuleMap)) {
        if(H->fAbort) { goto fail; }
        MFcModule_LogUnloadedModule(H, pd, pfnLogJSON, pObUnloadedModuleMap);
    }
    // pdb debug info / codeview:
    FC_JSONDATA_INIT_PIDTYPE(pd, pProcess->dwPID, "codeview");
    for(i = 0; i < pObModuleMap->cMap; i++) {
        if(H->fAbort) { goto fail; }
        peM = pObModuleMap->pMap + i;
        MFcModule_LogCodeView(H, pd, pfnLogJSON, pProcess, peM);
    }
fail:
    Ob_DECREF(pObModuleMap);
    Ob_DECREF(pObUnloadedModuleMap);
    LocalFree(pd);
}

VOID MFcModule_LogModuleCSV(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess, _In_ VMMDLL_CSV_HANDLE hCSV, _In_ PVMMOB_MAP_MODULE pMap)
{
    BOOL fSuppressDriver;
    DWORD i;
    PVMM_MAP_MODULEENTRY pe;
    DWORD dwAge;
    CHAR szGUID[33], szPdbFileName[MAX_PATH];
    PVMM_MAP_VADENTRY peVad = NULL;
    PVMMOB_MAP_VAD pObVadMap = NULL;
    VmmMap_GetVad(H, pProcess, &pObVadMap, VMM_VADMAP_TP_FULL);
    fSuppressDriver = !_stricmp(pProcess->szName, "csrss.exe") || !_stricmp(pProcess->szName, "Registry");
    for(i = 0; i < pMap->cMap; i++) {
        pe = pMap->pMap + i;
        if(fSuppressDriver && CharUtil_StrEndsWith(pe->uszText, ".sys", FALSE)) { continue; }
        if(!MFcModule_GetCodeView(H, pProcess, pe, szGUID, szPdbFileName, &dwAge)) {
            dwAge = 0;
            szGUID[0] = 0;
            szPdbFileName[0] = 0;
        }
        peVad = VmmMap_GetVadEntry(H, pObVadMap, pe->vaBase);
        //"PID,Name,Wow64,Size,Start,End,#Imports,#Exports,#Sections,Path,KernelPath,PdbPath,PdbAge,PdbHexGUID"
        FcCsv_Reset(hCSV);
        FcFileAppend(H, "modules.csv", "%i,%s,%i,0x%x,0x%llx,0x%llx,%i,%i,%i,%s,%s,%s,%i,%s\n",
            pProcess->dwPID,
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
            FcCsv_String(hCSV, szPdbFileName),
            dwAge,
            FcCsv_String(hCSV, szGUID)
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
        //"PID,ModuleName,UnloadTime,Wow64,Size,Start,End"
        FcCsv_Reset(hCSV);
        FcFileAppend(H, "unloaded_modules.csv", "%i,%s,%s,%i,0x%x,0x%llx,0x%llx\n",
            pProcess->dwPID,
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
    if(VmmMap_GetModule(H, pProcess, &pObModuleMap)) {
        if(H->fAbort) { goto fail; }
        MFcModule_LogModuleCSV(H, pProcess, hCSV, pObModuleMap);
    }
    // unloaded modules:
    if(VmmMap_GetUnloadedModule(H, pProcess, &pObUnloadedModuleMap)) {
        if(H->fAbort) { goto fail; }
        if(_stricmp(pProcess->szName, "csrss.exe") && _stricmp(pProcess->szName, "Registry")) {
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
    if((pRI->tpSystem != VMM_SYSTEM_WINDOWS_X64) && (pRI->tpSystem != VMM_SYSTEM_WINDOWS_X86)) { return; }
    strcpy_s(pRI->reg_info.uszPathName, 128, "\\forensic\\hidden\\module");     // module name
    pRI->reg_info.fRootModule = TRUE;                                           // module shows in root directory
    pRI->reg_info.fRootModuleHidden = TRUE;                                     // module hidden by default
    pRI->reg_fnfc.pfnInitialize = MFcModule_FcInitialize;                       // Forensic initialize supported
    pRI->reg_fnfc.pfnLogCSV = MFcModule_FcLogCSV;                               // CSV log function supported
    pRI->reg_fnfc.pfnLogJSON = MFcModule_FcLogJSON;                             // JSON log function supported
    pRI->pfnPluginManager_Register(H, pRI);
}
