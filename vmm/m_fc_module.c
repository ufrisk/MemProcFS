// m_fc_module.c : module forensic module.
//
// REQUIRE: FORENSIC SUB-SYSTEM INIT.
//
// NB! module generate forensic data only - no file system presence!
//
// (c) Ulf Frisk, 2021
// Author: Ulf Frisk, pcileech@frizk.net
//

#include "fc.h"
#include "vmm.h"
#include "pe.h"
#include "pluginmanager.h"
#include "util.h"

VOID MFcModule_LogEAT(_In_ PVMMDLL_PLUGIN_FORENSIC_JSONDATA pd, _In_ VOID(*pfnLogJSON)(_In_ PVMMDLL_PLUGIN_FORENSIC_JSONDATA pData), _In_ PVMM_PROCESS pProcess, PVMM_MAP_MODULEENTRY peM)
{
    PVMMOB_MAP_EAT pObEatMap = NULL;
    PVMM_MAP_EATENTRY pe;
    DWORD i;
    if(VmmMap_GetEAT(pProcess, peM, &pObEatMap)) {
        for(i = 0; i < pObEatMap->cMap; i++) {
            pe = pObEatMap->pMap + i;
            pd->i = i;
            pd->va[0] = pe->vaFunction;
            pd->qwNum[1] = pe->dwOrdinal;
            pd->qwHex[0] = pe->vaFunction - peM->vaBase;
            pd->usz[0] = peM->uszText;
            pd->usz[1] = pe->uszFunction;
            pfnLogJSON(pd);
        }
    }
    Ob_DECREF(pObEatMap);
}

VOID MFcModule_LogIAT(_In_ PVMMDLL_PLUGIN_FORENSIC_JSONDATA pd, _In_ VOID(*pfnLogJSON)(_In_ PVMMDLL_PLUGIN_FORENSIC_JSONDATA pData), _In_ PVMM_PROCESS pProcess, PVMM_MAP_MODULEENTRY peM)
{
    PVMMOB_MAP_IAT pObIatMap = NULL;
    PVMM_MAP_IATENTRY pe;
    DWORD i;
    CHAR usz[MAX_PATH];
    if(VmmMap_GetIAT(pProcess, peM, &pObIatMap)) {
        for(i = 0; i < pObIatMap->cMap; i++) {
            pe = pObIatMap->pMap + i;
            snprintf(usz, _countof(usz), "%s!%s", pe->uszModule, pe->uszFunction);
            pd->i = i;
            pd->va[0] = pe->vaFunction;
            pd->usz[0] = peM->uszText;
            pd->usz[1] = usz;
            pfnLogJSON(pd);
        }
    }
    Ob_DECREF(pObIatMap);
}

VOID MFcModule_LogDirectory(_In_ PVMMDLL_PLUGIN_FORENSIC_JSONDATA pd, _In_ VOID(*pfnLogJSON)(_In_ PVMMDLL_PLUGIN_FORENSIC_JSONDATA pData), _In_ PVMM_PROCESS pProcess, PVMM_MAP_MODULEENTRY peM)
{
    DWORD i;
    PIMAGE_DATA_DIRECTORY pe;
    IMAGE_DATA_DIRECTORY Directory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
    if(!PE_DirectoryGetAll(pProcess, peM->vaBase, NULL, Directory)) { return; }
    for(i = 0; i < 16; i++) {
        pe = Directory + i;
        if(pe->VirtualAddress) {
            pd->va[0] = peM->vaBase + pe->VirtualAddress;
            pd->va[1] = pe->VirtualAddress;
            pd->qwNum[0] = pe->Size;
            pd->usz[0] = (LPSTR)PE_DATA_DIRECTORIES[i];
            pfnLogJSON(pd);
        }
    }
}

VOID MFcModule_LogSection(_In_ PVMMDLL_PLUGIN_FORENSIC_JSONDATA pd, _In_ VOID(*pfnLogJSON)(_In_ PVMMDLL_PLUGIN_FORENSIC_JSONDATA pData), _In_ PVMM_PROCESS pProcess, PVMM_MAP_MODULEENTRY peM)
{
    DWORD i, cSections;
    CHAR usz[32];
    PIMAGE_SECTION_HEADER pSections = NULL;
    PIMAGE_SECTION_HEADER pe;
    cSections = PE_SectionGetNumberOf(pProcess, peM->vaBase);
    if(!cSections || !(pSections = LocalAlloc(LMEM_ZEROINIT, cSections * sizeof(IMAGE_SECTION_HEADER)))) { return; }
    if(PE_SectionGetAll(pProcess, peM->vaBase, cSections, pSections)) {
        for(i = 0; i < cSections; i++) {
            pe = pSections + i;
            pd->i = i;
            pd->va[0] = peM->vaBase + pe->VirtualAddress;
            pd->qwNum[0] = pe->Misc.VirtualSize;
            pd->qwHex[0] = pe->VirtualAddress;
            pd->qwHex[1] = pe->Misc.VirtualSize;
            pe->Misc.VirtualSize = 0;   // effectively null-terminates pe->Name
            snprintf(usz, sizeof(usz), "%s %c%c%c",
                pe->Name,
                (pe->Characteristics & IMAGE_SCN_MEM_READ) ? 'r' : '-',
                (pe->Characteristics & IMAGE_SCN_MEM_WRITE) ? 'w' : '-',
                (pe->Characteristics & IMAGE_SCN_MEM_EXECUTE) ? 'x' : '-');
            pd->usz[0] = peM->uszText;
            pd->usz[1] = usz;
            pfnLogJSON(pd);
        }
    }
    LocalFree(pSections);
}

VOID MFcModule_LogCodeView(_In_ PVMMDLL_PLUGIN_FORENSIC_JSONDATA pd, _In_ VOID(*pfnLogJSON)(_In_ PVMMDLL_PLUGIN_FORENSIC_JSONDATA pData), _In_ PVMM_PROCESS pProcess, PVMM_MAP_MODULEENTRY peM)
{
    LPCSTR szHEX_ALPHABET = "0123456789ABCDEF";
    CHAR usz[MAX_PATH], szGuidHEX[33] = { 0 };
    DWORD i, j;
    BYTE b;
    PE_CODEVIEW_INFO CodeViewInfo = { 0 };
    if(!PE_GetCodeViewInfo(pProcess, peM->vaBase, NULL, &CodeViewInfo)) { return; }
    // guid -> hex
    for(i = 0, j = 0; i < 16; i++) {
        b = CodeViewInfo.CodeView.Guid[i];
        szGuidHEX[j++] = szHEX_ALPHABET[b >> 4];
        szGuidHEX[j++] = szHEX_ALPHABET[b & 7];
    }
    snprintf(usz, sizeof(usz), "AGE=[%i] GUID=[%s] PDB=[%s]", CodeViewInfo.CodeView.Age, szGuidHEX, CodeViewInfo.CodeView.PdbFileName);
    pd->qwNum[0] = CodeViewInfo.CodeView.Age;
    pd->usz[0] = peM->uszText;
    pd->usz[1] = usz;
    pfnLogJSON(pd);
}

VOID MFcModule_LogModule(_In_ PVMMDLL_PLUGIN_FORENSIC_JSONDATA pd, _In_ VOID(*pfnLogJSON)(_In_ PVMMDLL_PLUGIN_FORENSIC_JSONDATA pData), PVMMOB_MAP_MODULE pMap)
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
        pfnLogJSON(pd);
    }
}

VOID MFcModule_LogUnloadedModule(_In_ PVMMDLL_PLUGIN_FORENSIC_JSONDATA pd, _In_ VOID(*pfnLogJSON)(_In_ PVMMDLL_PLUGIN_FORENSIC_JSONDATA pData), PVMMOB_MAP_UNLOADEDMODULE pMap)
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
        pfnLogJSON(pd);
    }
}

VOID MFcModule_FcLogJSON(_In_ PVMMDLL_PLUGIN_CONTEXT ctxP, _In_ VOID(*pfnLogJSON)(_In_ PVMMDLL_PLUGIN_FORENSIC_JSONDATA pData))
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
    if(VmmMap_GetModule(pProcess, &pObModuleMap)) {
        MFcModule_LogModule(pd, pfnLogJSON, pObModuleMap);
    }
    // unloaded modules:
    FC_JSONDATA_INIT_PIDTYPE(pd, pProcess->dwPID, "unloadedmodule");
    if(VmmMap_GetUnloadedModule(pProcess, &pObUnloadedModuleMap)) {
        MFcModule_LogUnloadedModule(pd, pfnLogJSON, pObUnloadedModuleMap);
    }
    // pdb debug info / codeview:
    FC_JSONDATA_INIT_PIDTYPE(pd, pProcess->dwPID, "codeview");
    for(i = 0; i < pObModuleMap->cMap; i++) {
        peM = pObModuleMap->pMap + i;
        MFcModule_LogCodeView(pd, pfnLogJSON, pProcess, peM);
    }
    // data directories:
    FC_JSONDATA_INIT_PIDTYPE(pd, pProcess->dwPID, "datadir"); pd->fVerbose = TRUE;
    for(i = 0; i < pObModuleMap->cMap; i++) {
        peM = pObModuleMap->pMap + i;
        MFcModule_LogDirectory(pd, pfnLogJSON, pProcess, peM);
    }
    // sections:
    FC_JSONDATA_INIT_PIDTYPE(pd, pProcess->dwPID, "section"); pd->fVerbose = TRUE;
    for(i = 0; i < pObModuleMap->cMap; i++) {
        peM = pObModuleMap->pMap + i;
        MFcModule_LogSection(pd, pfnLogJSON, pProcess, peM);
    }
    // imports:
    FC_JSONDATA_INIT_PIDTYPE(pd, pProcess->dwPID, "import"); pd->fVerbose = TRUE;
    for(i = 0; i < pObModuleMap->cMap; i++) {
        peM = pObModuleMap->pMap + i;
        MFcModule_LogIAT(pd, pfnLogJSON, pProcess, peM);
    }
    // exports:
    FC_JSONDATA_INIT_PIDTYPE(pd, pProcess->dwPID, "export"); pd->fVerbose = TRUE;
    for(i = 0; i < pObModuleMap->cMap; i++) {
        peM = pObModuleMap->pMap + i;
        MFcModule_LogEAT(pd, pfnLogJSON, pProcess, peM);
    }
    Ob_DECREF(pObModuleMap);
    Ob_DECREF(pObUnloadedModuleMap);
    LocalFree(pd);
}

/*
* Plugin initialization / registration function called by the plugin manager.
* -- pRI
*/
VOID M_FcModule_Initialize(_Inout_ PVMMDLL_PLUGIN_REGINFO pRI)
{
    if((pRI->magic != VMMDLL_PLUGIN_REGINFO_MAGIC) || (pRI->wVersion != VMMDLL_PLUGIN_REGINFO_VERSION)) { return; }
    if((pRI->tpSystem != VMM_SYSTEM_WINDOWS_X64) && (pRI->tpSystem != VMM_SYSTEM_WINDOWS_X86)) { return; }
    strcpy_s(pRI->reg_info.uszPathName, 128, "\\forensic\\hidden\\module");     // module name
    pRI->reg_info.fRootModule = TRUE;                                           // module shows in root directory
    pRI->reg_info.fRootModuleHidden = TRUE;                                     // module hidden by default
    pRI->reg_fnfc.pfnLogJSON = MFcModule_FcLogJSON;                             // JSON log function supported
    pRI->pfnPluginManager_Register(pRI);
}
