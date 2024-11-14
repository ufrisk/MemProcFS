// m_misc_eventlog.c : display event log files
//
// (c) Ulf Frisk, 2024
// Author: Ulf Frisk, pcileech@frizk.net
//

#include "modules.h"
#include "../vmmwinobj.h"

LPCSTR szMEVENTLOG_README =
"Information about the eventlog module                                        \n" \
"=====================================                                        \n" \
"The eventlog module retrieves event log files.                               \n" \
"                                                                             \n" \
"It's recommended to copy the event logs to a separate folder before opening  \n" \
"them, since the event viever will have issues opening them in the MemProcFS  \n" \
"folder due to the lack of write support.                                     \n" \
"                                                                             \n" \
"Event log files may be partially corrupt and may have to be repaired with    \n" \
"3rd party tools before being able to open.                                   \n" \
"                                                                             \n" \
"---                                                                          \n" \
"Documentation: https://github.com/ufrisk/MemProcFS/wiki/FS_Misc_Eventlog     \n";

/*
* Retrieve the process responsible for event logging.
* CALLER DECREF: return
* -- H
* -- ctxP
* -- return
*/
_Success_(return != NULL)
PVMM_PROCESS MEventlog_GetProcess(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_CONTEXT ctxP)
{
    DWORD i, c;
    PDWORD pdw = (PDWORD)ctxP->ctxM;
    PVMM_PROCESS pObProcess = NULL;
    PVMMOB_MAP_HANDLE pObHandleMap = NULL;
    PVMM_MAP_HANDLEENTRY pe;
    EnterCriticalSection(&H->vmm.LockPlugin);
    if(*pdw == 0) {
        while((pObProcess = VmmProcessGetNext(H, pObProcess, 0))) {
            if(CharUtil_StrEquals(pObProcess->szName, "svchost.exe", 0)) {
                c = 0;
                if(VmmMap_GetHandle(H, pObProcess, &pObHandleMap, TRUE)) {
                    for(i = 0; i < pObHandleMap->cMap; i++) {
                        pe = &pObHandleMap->pMap[i];
                        if(CharUtil_StrEndsWith(pe->uszText, ".evtx", FALSE)) {
                            c++;
                        }
                    }
                    Ob_DECREF_NULL(&pObHandleMap);
                }
                if(c >= 8) {
                    *pdw = pObProcess->dwPID;
                    break;
                }
            }
        }
        if(*pdw == 0) { *pdw = 0xffffffff; }
    }
    LeaveCriticalSection(&H->vmm.LockPlugin);
    Ob_DECREF(pObProcess);
    return (*pdw == 0xffffffff) ? NULL : VmmProcessGet(H, *pdw);
}

NTSTATUS MEventlog_Read(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_CONTEXT ctxP, _Out_writes_to_(cb, *pcbRead) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset)
{
    QWORD va;
    POB_VMMWINOBJ_FILE pObFile = NULL;
    if(CharUtil_StrEquals(ctxP->uszPath, "readme.txt", TRUE)) {
        return Util_VfsReadFile_FromStrA(szMEVENTLOG_README, pb, cb, pcbRead, cbOffset);
    }
    *pcbRead = 0;
    if(!(va = strtoull(ctxP->uszPath, NULL, 16))) { return VMMDLL_STATUS_FILE_INVALID; }
    if(!(pObFile = VmmWinObjFile_GetByVa(H, va))) { return VMMDLL_STATUS_FILE_INVALID; }
    *pcbRead = VmmWinObjFile_Read(H, pObFile, cbOffset, pb, cb, 0, VMMWINOBJ_FILE_TP_DEFAULT);
    Ob_DECREF(pObFile);
    return *pcbRead ? VMM_STATUS_SUCCESS : VMM_STATUS_END_OF_FILE;
}

BOOL MEventlog_List(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_CONTEXT ctxP, _Inout_ PHANDLE pFileList)
{
    POB_MAP pmObFiles = NULL;
    PVMM_PROCESS pObProcess = NULL;
    POB_VMMWINOBJ_FILE pObFile;
    CHAR uszAddressPath[MAX_PATH];
    if(ctxP->uszPath[0]) { return FALSE; }
    VMMDLL_VfsList_AddFile(pFileList, "readme.txt", strlen(szMEVENTLOG_README), NULL);
    if((pObProcess = MEventlog_GetProcess(H, ctxP))) {
        if(VmmWinObjFile_GetByProcess(H, pObProcess, &pmObFiles, TRUE)) {
            while((pObFile = ObMap_Pop(pmObFiles))) {
                if(CharUtil_StrEndsWith(pObFile->uszName, ".evtx", FALSE)) {
                    Util_PathPrependVA(uszAddressPath, pObFile->va, H->vmm.f32, pObFile->uszName);
                    VMMDLL_VfsList_AddFile(pFileList, uszAddressPath, pObFile->cb, NULL);
                }
                Ob_DECREF(pObFile);
            }
        }
    }
    Ob_DECREF(pmObFiles);
    Ob_DECREF(pObProcess);
    return TRUE;
}

VOID MEventlog_Close(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_CONTEXT ctxP)
{
    LocalFree(ctxP->ctxM);
}

VOID M_MiscEventlog_Initialize(_In_ VMM_HANDLE H, _Inout_ PVMMDLL_PLUGIN_REGINFO pRI)
{
    if((pRI->magic != VMMDLL_PLUGIN_REGINFO_MAGIC) || (pRI->wVersion != VMMDLL_PLUGIN_REGINFO_VERSION)) { return; }
    if(pRI->sysinfo.dwVersionBuild < 6000) { return; }      // XP not supported (.evt log files)
    if(!(pRI->reg_info.ctxM = (PVMMDLL_PLUGIN_INTERNAL_CONTEXT)LocalAlloc(LMEM_ZEROINIT, sizeof(DWORD)))) { return; }
    strcpy_s(pRI->reg_info.uszPathName, 128, "\\misc\\eventlog");               // module name
    pRI->reg_info.fRootModule = TRUE;                                           // module shows in root directory
    // functions supported:
    pRI->reg_fn.pfnList = MEventlog_List;
    pRI->reg_fn.pfnRead = MEventlog_Read;
    pRI->reg_fn.pfnClose = MEventlog_Close;
    pRI->pfnPluginManager_Register(H, pRI);
}
