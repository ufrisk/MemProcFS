// m_sys_user.c : implementation related to the sys/users built-in module.
//
// The '/sys/users' module is responsible for displaying the users of the system.
//
// (c) Ulf Frisk, 2022-2025
// Author: Ulf Frisk, pcileech@frizk.net
//

#include "modules.h"

#define MSYSUSER_LINELENGTH      120ULL
#define MSYSUSER_LINEHEADER       "   # Username                         SID"

VOID MSysUser_ReadLineCB(_In_ VMM_HANDLE H, _Inout_opt_ PVOID ctx, _In_ DWORD cbLineLength, _In_ DWORD ie, _In_ PVMM_MAP_USERENTRY pe, _Out_writes_(cbLineLength + 1) LPSTR usz)
{
    Util_usnprintf_ln(usz, cbLineLength,
        "%04x %-32s %s",
        ie,
        pe->uszText,
        pe->szSID ? pe->szSID : "***"
    );
}

NTSTATUS MSysUser_Read(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_CONTEXT ctxP, _Out_writes_to_(cb, *pcbRead) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset)
{
    NTSTATUS nt = VMMDLL_STATUS_FILE_INVALID;
    PVMMOB_MAP_USER pObUserMap = NULL;
    if(CharUtil_StrEquals(ctxP->uszPath, "users.txt", TRUE)) {
        if(VmmMap_GetUser(H, &pObUserMap)) {
            nt = Util_VfsLineFixed_Read(
                H, (UTIL_VFSLINEFIXED_PFN_CB)MSysUser_ReadLineCB, NULL, MSYSUSER_LINELENGTH, MSYSUSER_LINEHEADER,
                pObUserMap->pMap, pObUserMap->cMap, sizeof(VMM_MAP_USERENTRY),
                pb, cb, pcbRead, cbOffset
            );
            Ob_DECREF(pObUserMap);
        }
    }
    return nt;
}

BOOL MSysUser_List(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_CONTEXT ctxP, _Inout_ PHANDLE pFileList)
{
    PVMMOB_MAP_USER pObUserMap = NULL;
    if(VmmMap_GetUser(H, &pObUserMap)) {
        VMMDLL_VfsList_AddFile(pFileList, "users.txt", UTIL_VFSLINEFIXED_LINECOUNT(H, pObUserMap->cMap) * MSYSUSER_LINELENGTH, NULL);
    }
    Ob_DECREF(pObUserMap);
    return TRUE;
}

VOID M_SysUser_Initialize(_In_ VMM_HANDLE H, _Inout_ PVMMDLL_PLUGIN_REGINFO pRI)
{
    if((pRI->magic != VMMDLL_PLUGIN_REGINFO_MAGIC) || (pRI->wVersion != VMMDLL_PLUGIN_REGINFO_VERSION)) { return; }
    if((pRI->tpSystem != VMMDLL_SYSTEM_WINDOWS_64) && (pRI->tpSystem != VMMDLL_SYSTEM_WINDOWS_32)) { return; }
    strcpy_s(pRI->reg_info.uszPathName, 128, "\\sys\\users");           // module name
    pRI->reg_info.fRootModule = TRUE;                                   // module shows in root directory
    pRI->reg_fn.pfnList = MSysUser_List;                                 // List function supported
    pRI->reg_fn.pfnRead = MSysUser_Read;                                 // Read function supported
    pRI->pfnPluginManager_Register(H, pRI);
}
