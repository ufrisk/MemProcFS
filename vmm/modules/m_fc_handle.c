// m_fc_handle.c : handle forensic module.
//
// REQUIRE: FORENSIC SUB-SYSTEM INIT.
//
// NB! module generate forensic data only - no file system presence!
//
// (c) Ulf Frisk, 2022-2025
// Author: Ulf Frisk, pcileech@frizk.net
//

#include "modules.h"
#include "../vmmwin.h"

static LPSTR MFCHANDLE_CSV_HANDLE = "PID,Handle,Object,Access,Type,Tag,HandleCount,Device,Description\n";

PVOID MFcHandle_FcInitialize(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_CONTEXT ctxP)
{
    FcFileAppend(H, "handles.csv", MFCHANDLE_CSV_HANDLE);
    return NULL;
}

VOID MFcHandle_FcLogCSV(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_CONTEXT ctxP, _In_ VMMDLL_CSV_HANDLE hCSV)
{
    PVMM_PROCESS pProcess = ctxP->pProcess;
    PVMMOB_MAP_HANDLE pObHandleMap = NULL;
    PVMM_MAP_HANDLEENTRY pe;
    PVMMWIN_OBJECT_TYPE pOT;
    CHAR szType[32] = { 0 };
    CHAR szPoolTag[5] = { 0 };
    CHAR uszBufferDevName[MAX_PATH] = { 0 };
    DWORD i;
    if(pProcess && VmmMap_GetHandle(H, pProcess, &pObHandleMap, TRUE)) {
        for(i = 0; i < pObHandleMap->cMap; i++) {
            pe = pObHandleMap->pMap + i;
            // type&pool tag:
            *(PDWORD)szPoolTag = pe->dwPoolTag;
            if((pOT = VmmWin_ObjectTypeGet(H, (BYTE)pe->iType))) {
                snprintf(szType, _countof(szType), "%s", pOT->usz);
                szType[16] = 0;
            } else {
                *(PDWORD)szType = pe->dwPoolTag;
                szType[4] = 0;
            }
            // device object name:
            uszBufferDevName[0] = 0;
            if(pe->_InfoFile.dwoName) {
                strncpy_s(uszBufferDevName, sizeof(uszBufferDevName), pe->uszText + 1, pe->_InfoFile.dwoName - 1);
            }
            // csv file append:
            FcCsv_Reset(hCSV);
            FcFileAppend(H, "handles.csv", "%i,0x%x,0x%llx,%x,%s,%s,0x%llx,%s,%s\n",
                pProcess->dwPID,
                pe->dwHandle,
                pe->vaObject,
                pe->dwGrantedAccess,
                FcCsv_String(hCSV, szType),
                FcCsv_String(hCSV, szPoolTag),
                pe->qwHandleCount,
                FcCsv_String(hCSV, uszBufferDevName),
                FcCsv_String(hCSV, pe->uszText + pe->_InfoFile.dwoName)
            );
        }
    }
    Ob_DECREF(pObHandleMap);
}

VOID M_FcHandle_Initialize(_In_ VMM_HANDLE H, _Inout_ PVMMDLL_PLUGIN_REGINFO pRI)
{
    if((pRI->magic != VMMDLL_PLUGIN_REGINFO_MAGIC) || (pRI->wVersion != VMMDLL_PLUGIN_REGINFO_VERSION)) { return; }
    if((pRI->tpSystem != VMM_SYSTEM_WINDOWS_64) && (pRI->tpSystem != VMM_SYSTEM_WINDOWS_32)) { return; }
    strcpy_s(pRI->reg_info.uszPathName, 128, "\\forensic\\hidden\\handles");     // module name
    pRI->reg_info.fRootModule = TRUE;                                           // module shows in root directory
    pRI->reg_info.fRootModuleHidden = TRUE;                                     // module hidden by default
    pRI->reg_fnfc.pfnInitialize = MFcHandle_FcInitialize;                       // Forensic initialize function supported
    pRI->reg_fnfc.pfnLogCSV = MFcHandle_FcLogCSV;                               // CSV log function supported
    pRI->pfnPluginManager_Register(H, pRI);
}
