// m_file_handles_vads.c : implementation of the 'files/handles/vads' built-in module.
//
// (c) Ulf Frisk, 2020-2021
// Author: Ulf Frisk, pcileech@frizk.net
//
#include "pluginmanager.h"
#include "util.h"
#include "vmm.h"
#include "vmmdll.h"
#include "vmmwin.h"
#include "vmmwinobj.h"

_Success_(return == 0)
NTSTATUS M_FileHandlesVads_Read(_In_ PVMMDLL_PLUGIN_CONTEXT ctx, _Out_writes_to_(cb, *pcbRead) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset, _In_ BOOL fHandles)
{
    QWORD va;
    POB_MAP pmObFiles = NULL;
    POB_VMMWINOBJ_OBJECT pOb = NULL;
    *pcbRead = 0;
    if(!(va = strtoull(ctx->uszPath, NULL, 16))) { return VMMDLL_STATUS_FILE_INVALID; }
    if(!(pOb = VmmWinObj_Get(va))) {
        VmmWinObjFile_GetByProcess(ctx->pProcess, &pmObFiles, fHandles);
        Ob_DECREF_NULL(&pmObFiles);
        pOb = VmmWinObj_Get(va);
    }
    if(!pOb) { return VMMDLL_STATUS_FILE_INVALID; }
    if(pOb->tp != VMMWINOBJ_TYPE_FILE) {
        Ob_DECREF(pOb);
        return VMMDLL_STATUS_FILE_INVALID;
    }
    *pcbRead = VmmWinObjFile_Read((POB_VMMWINOBJ_FILE)pOb, cbOffset, pb, cb, 0);
    Ob_DECREF(pOb);
    return *pcbRead ? VMM_STATUS_SUCCESS : VMM_STATUS_END_OF_FILE;
}

_Success_(return == 0)
NTSTATUS M_FileHandles_Read(_In_ PVMMDLL_PLUGIN_CONTEXT ctx, _Out_writes_to_(cb, *pcbRead) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset)
{
    return M_FileHandlesVads_Read(ctx, pb, cb, pcbRead, cbOffset, TRUE);
}

_Success_(return == 0)
NTSTATUS M_FileVads_Read(_In_ PVMMDLL_PLUGIN_CONTEXT ctx, _Out_writes_to_(cb, *pcbRead) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset)
{
    return M_FileHandlesVads_Read(ctx, pb, cb, pcbRead, cbOffset, FALSE);
}

BOOL M_FileHandlesVads_List(_In_ PVMMDLL_PLUGIN_CONTEXT ctx, _Inout_ PHANDLE pFileList, _In_ BOOL fHandles)
{
    POB_MAP pmObFiles;
    POB_VMMWINOBJ_FILE pObFile;
    CHAR uszAddressPath[MAX_PATH];
    if(ctx->uszPath[0]) { return FALSE; }
    if(VmmWinObjFile_GetByProcess(ctx->pProcess, &pmObFiles, fHandles)) {
        while((pObFile = ObMap_Pop(pmObFiles))) {
            Util_PathPrependVA(uszAddressPath, pObFile->va, ctxVmm->f32, pObFile->uszName);
            VMMDLL_VfsList_AddFile(pFileList, uszAddressPath, pObFile->cb, NULL);
        }
        Ob_DECREF_NULL(&pmObFiles);
    }
    return TRUE;
}

BOOL M_FileHandles_List(_In_ PVMMDLL_PLUGIN_CONTEXT ctx, _Inout_ PHANDLE pFileList)
{
    return M_FileHandlesVads_List(ctx, pFileList, TRUE);
}

BOOL M_FileVads_List(_In_ PVMMDLL_PLUGIN_CONTEXT ctx, _Inout_ PHANDLE pFileList)
{
    return M_FileHandlesVads_List(ctx, pFileList, FALSE);
}

VOID M_FileHandlesVads_Initialize(_Inout_ PVMMDLL_PLUGIN_REGINFO pRI)
{
    if((pRI->magic != VMMDLL_PLUGIN_REGINFO_MAGIC) || (pRI->wVersion != VMMDLL_PLUGIN_REGINFO_VERSION)) { return; }
    if(!((pRI->tpSystem == VMM_SYSTEM_WINDOWS_X64) || (pRI->tpSystem == VMM_SYSTEM_WINDOWS_X86))) { return; }
    // file handles
    strcpy_s(pRI->reg_info.uszPathName, 128, "\\files\\handles");       // module name
    pRI->reg_info.fRootModule = FALSE;                                  // module shows in root directory
    pRI->reg_info.fProcessModule = TRUE;                                // module shows in process directory
    pRI->reg_fn.pfnList = M_FileHandles_List;                           // List function supported
    pRI->reg_fn.pfnRead = M_FileHandles_Read;                           // Read function supported
    pRI->pfnPluginManager_Register(pRI);
    // file vads
    strcpy_s(pRI->reg_info.uszPathName, 128, "\\files\\vads");          // module name
    pRI->reg_info.fRootModule = FALSE;                                  // module shows in root directory
    pRI->reg_info.fProcessModule = TRUE;                                // module shows in process directory
    pRI->reg_fn.pfnList = M_FileVads_List;                              // List function supported
    pRI->reg_fn.pfnRead = M_FileVads_Read;                              // Read function supported
    pRI->pfnPluginManager_Register(pRI);
}
