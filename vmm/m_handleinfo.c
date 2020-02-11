// m_handleinfo.c : implementation of the handle info built-in module.
//
// (c) Ulf Frisk, 2019-2020
// Author: Ulf Frisk, pcileech@frizk.net
//
#include "pluginmanager.h"
#include "util.h"
#include "vmm.h"
#include "vmmdll.h"
#include "vmmwin.h"

#define HANDLEINFO_LINELENGTH       190ULL

_Success_(return == 0)
NTSTATUS HandleInfo_Read_HandleMap(_In_ PVMMOB_MAP_HANDLE pHandleMap, _Out_ PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset)
{
    NTSTATUS nt;
    LPSTR sz;
    QWORD i, o = 0, cbMax, cStart, cEnd, cbLINELENGTH;
    PVMM_MAP_HANDLEENTRY pH;
    PVMMWIN_OBJECT_TYPE pOT;
    CHAR szType[MAX_PATH] = { 0 };
    cbLINELENGTH = HANDLEINFO_LINELENGTH;
    cStart = (DWORD)(cbOffset / cbLINELENGTH);
    cEnd = (DWORD)min(pHandleMap->cMap - 1, (cb + cbOffset + cbLINELENGTH - 1) / cbLINELENGTH);
    cbMax = 1 + (1 + cEnd - cStart) * cbLINELENGTH;
    if(!pHandleMap->cMap || (cStart > pHandleMap->cMap)) { return VMMDLL_STATUS_END_OF_FILE; }
    if(!(sz = LocalAlloc(LMEM_ZEROINIT, cbMax))) { return VMMDLL_STATUS_FILE_INVALID; }
    for(i = cStart; i <= cEnd; i++) {
        pH = pHandleMap->pMap + i;
        if((pOT = VmmWin_ObjectTypeGet((BYTE)pH->iType))) {
            snprintf(szType, _MAX_PATH, "%S", pOT->wsz);
            szType[16] = 0;
        } else {
            *(PDWORD)szType = pH->dwPoolTag;
            szType[4] = 0;
        }
        o += Util_snprintf_ln(
            sz + o,
            cbMax - o,
            cbLINELENGTH,
            "%04x%7i%8x %16llx %6x %-16s %-128S\n",
            (DWORD)i,
            pH->dwPID,
            pH->dwHandle,
            pH->vaObject,
            pH->dwGrantedAccess,
            szType,
            pH->wszText + pH->cwszText - min(128, pH->cwszText)
        );
    }
    nt = Util_VfsReadFile_FromPBYTE(sz, cbMax - 1, pb, cb, pcbRead, cbOffset - cStart * cbLINELENGTH);
    LocalFree(sz);
    return nt;
}

/*
* Read : function as specified by the module manager. The module manager will
* call into this callback function whenever a read shall occur from a "file".
* -- ctx
* -- pb
* -- cb
* -- pcbRead
* -- cbOffset
* -- return
*/
_Success_(return == 0)
NTSTATUS HandleInfo_Read(_In_ PVMMDLL_PLUGIN_CONTEXT ctx, _Out_ PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset)
{
    NTSTATUS nt = VMMDLL_STATUS_FILE_INVALID;
    PVMMOB_MAP_HANDLE pObHandleMap = NULL;
    if(!_wcsicmp(ctx->wszPath, L"handles.txt") && VmmMap_GetHandle(ctx->pProcess, &pObHandleMap, TRUE)) {
        nt = HandleInfo_Read_HandleMap(pObHandleMap, pb, cb, pcbRead, cbOffset);
        Ob_DECREF(pObHandleMap);
    }
    return nt;
}

/*
* List : function as specified by the module manager. The module manager will
* call into this callback function whenever a list directory shall occur from
* the given module.
* -- ctx
* -- pFileList
* -- return
*/
BOOL HandleInfo_List(_In_ PVMMDLL_PLUGIN_CONTEXT ctx, _Inout_ PHANDLE pFileList)
{
    PVMMOB_MAP_HANDLE pObHandleMap = NULL;
    // list thread map
    if(ctx->wszPath[0]) { return FALSE; }
    if(VmmMap_GetHandle(ctx->pProcess, &pObHandleMap, FALSE)) {
        VMMDLL_VfsList_AddFile(pFileList, L"handles.txt", pObHandleMap->cMap * HANDLEINFO_LINELENGTH, NULL);
        Ob_DECREF_NULL(&pObHandleMap);
    }
    return TRUE;
}

/*
* Initialization function. The module manager shall call into this function
* when the module shall be initialized. If the module wish to initialize it
* shall call the supplied pfnPluginManager_Register function.
* NB! the module does not have to register itself - for example if the target
* operating system or architecture is unsupported.
* -- pPluginRegInfo
*/
VOID M_HandleInfo_Initialize(_Inout_ PVMMDLL_PLUGIN_REGINFO pRI)
{
    if((pRI->magic != VMMDLL_PLUGIN_REGINFO_MAGIC) || (pRI->wVersion != VMMDLL_PLUGIN_REGINFO_VERSION)) { return; }
    if(!((pRI->tpSystem == VMM_SYSTEM_WINDOWS_X64) || (pRI->tpSystem == VMM_SYSTEM_WINDOWS_X86))) { return; }
    wcscpy_s(pRI->reg_info.wszPathName, 128, L"\\handles");             // module name
    pRI->reg_info.fRootModule = FALSE;                                  // module shows in root directory
    pRI->reg_info.fProcessModule = TRUE;                                // module shows in process directory
    pRI->reg_fn.pfnList = HandleInfo_List;                              // List function supported
    pRI->reg_fn.pfnRead = HandleInfo_Read;                              // Read function supported
    pRI->pfnPluginManager_Register(pRI);
}
