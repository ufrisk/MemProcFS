// m_handleinfo.c : implementation of the handle info built-in module.
//
// (c) Ulf Frisk, 2019-2021
// Author: Ulf Frisk, pcileech@frizk.net
//
#include "pluginmanager.h"
#include "util.h"
#include "vmm.h"
#include "vmmdll.h"
#include "vmmwin.h"

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
NTSTATUS M_ProcUser_Read(_In_ PVMMDLL_PLUGIN_CONTEXT ctx, _Out_writes_to_(cb, *pcbRead) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset)
{
    NTSTATUS nt = VMMDLL_STATUS_FILE_INVALID;
    WCHAR wszBuffer[MAX_PATH + 1];
    PVMM_PROCESS pObProcess = NULL;
    if(!(pObProcess = VmmProcessGetEx(NULL, ctx->dwPID, VMM_FLAG_PROCESS_TOKEN))) { goto fail; }
    if(!pObProcess->win.TOKEN.fInitialized || !pObProcess->win.TOKEN.fSID) { goto fail; }
    if(!_wcsicmp(ctx->wszPath, L"sid.txt")) {
        nt = Util_VfsReadFile_FromPBYTE(
            (PBYTE)pObProcess->win.TOKEN.szSID,
            pObProcess->win.TOKEN.szSID ? strlen(pObProcess->win.TOKEN.szSID) : 0,
            pb, cb, pcbRead, cbOffset);
    } else if(!_wcsicmp(ctx->wszPath, L"user.txt")) {
        VmmWinUser_GetNameW(&pObProcess->win.TOKEN.SID, wszBuffer, MAX_PATH, NULL, NULL);
        nt = Util_VfsReadFile_FromTextWtoU8(wszBuffer, pb, cb, pcbRead, cbOffset);
    } else if(!_wcsicmp(ctx->wszPath, L"luid.txt")) {
        nt = Util_VfsReadFile_FromQWORD(pObProcess->win.TOKEN.qwLUID, pb, cb, pcbRead, cbOffset, FALSE);
    } else if(!_wcsicmp(ctx->wszPath, L"session.txt")) {
        nt = Util_VfsReadFile_FromDWORD(pObProcess->win.TOKEN.dwSessionId, pb, cb, pcbRead, cbOffset, FALSE);
    }
fail:
    Ob_DECREF(pObProcess);
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
BOOL M_ProcUser_List(_In_ PVMMDLL_PLUGIN_CONTEXT ctx, _Inout_ PHANDLE pFileList)
{
    BOOL fResult = FALSE;
    DWORD cuszName;
    WCHAR wszBuffer[MAX_PATH + 1] = { 0 };
    PVMM_PROCESS pObProcess = NULL;   
    if(!(pObProcess = VmmProcessGetEx(NULL, ctx->dwPID, VMM_FLAG_PROCESS_TOKEN))) { goto fail; }
    if(!pObProcess->win.TOKEN.fInitialized || !pObProcess->win.TOKEN.fSID) { goto fail; }
    if(pObProcess->win.TOKEN.szSID) {
        VMMDLL_VfsList_AddFile(pFileList, L"sid.txt", strlen(pObProcess->win.TOKEN.szSID), NULL);
    }
    if(VmmWinUser_GetNameW(&pObProcess->win.TOKEN.SID, wszBuffer, MAX_PATH, NULL, NULL)) {
        cuszName = wcslen_u8(wszBuffer);
        VMMDLL_VfsList_AddFile(pFileList, L"user.txt", cuszName, NULL);
    }
    VMMDLL_VfsList_AddFile(pFileList, L"luid.txt", 16, NULL);
    VMMDLL_VfsList_AddFile(pFileList, L"session.txt", 8, NULL);
    fResult = TRUE;
fail:
    Ob_DECREF(pObProcess);
    return fResult;
}

/*
* Initialization function. The module manager shall call into this function
* when the module shall be initialized. If the module wish to initialize it
* shall call the supplied pfnPluginManager_Register function.
* NB! the module does not have to register itself - for example if the target
* operating system or architecture is unsupported.
* -- pPluginRegInfo
*/
VOID M_ProcUser_Initialize(_Inout_ PVMMDLL_PLUGIN_REGINFO pRI)
{
    if((pRI->magic != VMMDLL_PLUGIN_REGINFO_MAGIC) || (pRI->wVersion != VMMDLL_PLUGIN_REGINFO_VERSION)) { return; }
    if(!((pRI->tpSystem == VMM_SYSTEM_WINDOWS_X64) || (pRI->tpSystem == VMM_SYSTEM_WINDOWS_X86))) { return; }
    wcscpy_s(pRI->reg_info.wszPathName, 128, L"\\user");                // module name
    pRI->reg_info.fRootModule = FALSE;                                  // module shows in root directory
    pRI->reg_info.fProcessModule = TRUE;                                // module shows in process directory
    pRI->reg_fn.pfnList = M_ProcUser_List;                              // List function supported
    pRI->reg_fn.pfnRead = M_ProcUser_Read;                              // Read function supported
    pRI->pfnPluginManager_Register(pRI);
}
