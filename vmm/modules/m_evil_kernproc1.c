// m_evil_kernproc1.c : evil detectors common between user/kernel processes.
//
// Detections:
//  - PE_HDR_SPOOF
// 
// (c) Ulf Frisk, 2023-2025
// Author: Ulf Frisk, pcileech@frizk.net
//

#include "modules.h"
#include "../vmmwin.h"



//-----------------------------------------------------------------------------
// PE_HDR_SPOOF
//-----------------------------------------------------------------------------

/*
* Locate potentially spoofed PE headers.
* Detect PE 'LowAlign' mode in which PE section headers are disregarded.
*/
VOID MEvilKernProc1_PeHdrSpoof(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess)
{
    DWORD i;
    IMAGE_SECTION_HEADER Section;
    PVMM_MAP_MODULEENTRY peModule;
    PVMMOB_MAP_MODULE pObModuleMap = NULL;
    if(CharUtil_StrEquals(pProcess->szName, "csrss.exe", TRUE)) { goto fail; }
    if(!VmmMap_GetModule(H, pProcess, 0, &pObModuleMap)) { goto fail; }
    for(i = 0; i < pObModuleMap->cMap; i++) {
        peModule = pObModuleMap->pMap + i;
        // PE_HDR_SPOOF:
        if(PE_SectionGetFromName(H, pProcess, peModule->vaBase, "LOWALIGN", &Section) && (Section.VirtualAddress == 0)) {
            FcEvilAdd(H, EVIL_PE_HDR_SPOOF, pProcess, peModule->vaBase, "Module:[%s]", (peModule->uszFullName ? peModule->uszFullName : ""));
        }
    }
fail:
    Ob_DECREF(pObModuleMap);
}



//-----------------------------------------------------------------------------
// COMMON:
//-----------------------------------------------------------------------------

VOID MEvilKernProc1_DoWork(_In_ VMM_HANDLE H, _In_ VMMDLL_MODULE_ID MID, _In_opt_ PVOID ctxfc)
{
    PVMM_PROCESS pObProcess = NULL;
    while((pObProcess = VmmProcessGetNext(H, pObProcess, VMM_FLAG_PROCESS_TOKEN | VMM_FLAG_PROCESS_SHOW_TERMINATED))) {
        if(H->fAbort) { goto fail; }
        if(FcIsProcessSkip(H, pObProcess)) { continue; }
        MEvilKernProc1_PeHdrSpoof(H, pObProcess);
    }
    VmmLog(H, MID, LOGLEVEL_6_TRACE, "COMPLETED FINDEVIL SCAN");
fail:
    Ob_DECREF(pObProcess);
}

VOID M_Evil_KernProc1(_In_ VMM_HANDLE H, _Inout_ PVMMDLL_PLUGIN_REGINFO pRI)
{
    if((pRI->magic != VMMDLL_PLUGIN_REGINFO_MAGIC) || (pRI->wVersion != VMMDLL_PLUGIN_REGINFO_VERSION)) { return; }
    if(pRI->sysinfo.f32 || (pRI->sysinfo.dwVersionBuild < 9600)) { return; }    // only support 64-bit Win8.1+ for now
    // register findevil plugin:
    strcpy_s(pRI->reg_info.uszPathName, 128, "\\findevil\\EvKERNPROC1");
    pRI->reg_info.fRootModule = TRUE;
    pRI->reg_info.fRootModuleHidden = TRUE;
    pRI->reg_fnfc.pfnFindEvil = MEvilKernProc1_DoWork;
    pRI->pfnPluginManager_Register(H, pRI);
}
