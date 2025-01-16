// m_evil_av1.c : various anti-virus detections.
//
// Detections:
//  - Windows Defender: Malware Detected
// 
// (c) Ulf Frisk, 2023-2025
// Author: Ulf Frisk, pcileech@frizk.net
//

#include "modules.h"
#include "../vmmwinobj.h"

#define MEVILAV1_MAX_FINDINGS_PER_FILE      64
#define MEVILAV1_MAX_FILE_SIZE              0x10000000       // 256MB

VOID MEvilAV1_DoWork_WinDefend_MPLog(_In_ VMM_HANDLE H, _In_ VMMDLL_MODULE_ID MID, _In_ POB_VMMWINOBJ_FILE pFile)
{
    SIZE_T oFile = 0, cbFile = 0, cbLine;
    PBYTE pbFile = NULL;
    LPSTR uszText = NULL, uszLine, szTokenizerContext;
    DWORD cProtect = 0;
    // read file:
    cbFile = min(MEVILAV1_MAX_FILE_SIZE, (SIZE_T)pFile->cb);
    if(!cbFile || !(pbFile = LocalAlloc(0, cbFile + sizeof(DWORD)))) { goto fail; }
    if(0 == VmmWinObjFile_Read(H, pFile, 0, pbFile, (DWORD)cbFile, VMMDLL_FLAG_ZEROPAD_ON_FAIL, VMMWINOBJ_FILE_TP_DEFAULT)) { goto fail; }
    *(PDWORD)(pbFile + cbFile) = 0;
    // data is likely to be zero-padded on a per-page basis and will be in UTF-16LE, convert to UTF-8:
    while(oFile < cbFile) {
        if(!pbFile[oFile]) {
            oFile = (oFile + 0x1000) & ~0xfff;
            continue;
        }
        if(CharUtil_WtoU((LPWSTR)(pbFile + oFile), (DWORD)-1, NULL, 0, &uszText, NULL, CHARUTIL_FLAG_ALLOC)) {
            // iterate per-line in text:
            szTokenizerContext = NULL;
            uszLine = strtok_s(uszText, "\r\n", &szTokenizerContext);
            while(uszLine) {
                cbLine = strlen(uszLine);
                if(cbLine > 25) {
                    if(CharUtil_StrStartsWith(uszLine + 25, "DETECTIONEVENT", FALSE) || CharUtil_StrStartsWith(uszLine + 25, "DETECTION_ADD", FALSE)) {
                        cProtect++;
                        if(cProtect < MEVILAV1_MAX_FINDINGS_PER_FILE) {
                            FcEvilAdd(H, EVIL_AV_DETECT, NULL, 0, "AV:[Windows Defender] EVENT:[%s]", uszLine);
                            VmmLog(H, MID, LOGLEVEL_5_DEBUG, "DETECTION: AV:[Windows Defender] EVENT:[%s]", uszLine);
                        }
                    }
                }
                uszLine = strtok_s(NULL, "\r\n", &szTokenizerContext);
            }
            LocalFree(uszText);
            uszText = NULL;
        }
        while((oFile < cbFile) && pbFile[oFile]) {
            oFile += 0x1000;
        }
    }
fail:
    LocalFree(pbFile);
}

VOID MEvilAV1_DoWork(_In_ VMM_HANDLE H, _In_ VMMDLL_MODULE_ID MID, _In_opt_ PVOID ctxfc)
{
    // Iterate all files to find anti-virus log files:
    POB_MAP pmObFiles = NULL;
    POB_SET psObDuplicates = NULL;
    POB_VMMWINOBJ_FILE pObFile = NULL;
    psObDuplicates = ObSet_New(H);
    if(VmmWinObjFile_GetAll(H, &pmObFiles)) {
        while((pObFile = ObMap_GetNext(pmObFiles, pObFile))) {
            // Windows Defender MPLog:
            if(CharUtil_StrStartsWith(pObFile->uszName, "MPLog-", FALSE) && CharUtil_StrStartsWith(pObFile->uszPath, "\\ProgramData\\Microsoft\\Windows Defender\\Support\\MPLog-", FALSE)) {
                if(ObSet_Push(psObDuplicates, CharUtil_Hash64U(pObFile->uszPath, FALSE))) {
                    VmmLog(H, MID, LOGLEVEL_5_DEBUG, "ANALYZE_FILE: AV:[Windows Defender] FILE:[%s]", pObFile->uszPath);
                    MEvilAV1_DoWork_WinDefend_MPLog(H, MID, pObFile);
                }
            }
        }
    }
    Ob_DECREF(psObDuplicates);
    Ob_DECREF(pmObFiles);
}

VOID M_Evil_AV1(_In_ VMM_HANDLE H, _Inout_ PVMMDLL_PLUGIN_REGINFO pRI)
{
    if((pRI->magic != VMMDLL_PLUGIN_REGINFO_MAGIC) || (pRI->wVersion != VMMDLL_PLUGIN_REGINFO_VERSION)) { return; }
    // register findevil plugin:
    strcpy_s(pRI->reg_info.uszPathName, 128, "\\findevil\\EvAV1");
    pRI->reg_info.fRootModule = TRUE;
    pRI->reg_info.fRootModuleHidden = TRUE;
    pRI->reg_fnfc.pfnFindEvil = MEvilAV1_DoWork;
    pRI->pfnPluginManager_Register(H, pRI);
}
