// m_proc_token.c : implementation of the proc/token info built-in module.
//
// (c) Ulf Frisk, 2019-2021
// Author: Ulf Frisk, pcileech@frizk.net
//
#include "pluginmanager.h"
#include "util.h"
#include "vmm.h"
#include "vmmdll.h"
#include "vmmwin.h"
#include "vmmwindef.h"

#define MPROCTOKEN_PRIVILEGE_LINELENGTH     60ULL
#define MPROCTOKEN_PRIVILEGE_LINEHEADER     L"   #    PID Flags Privilege Name"

static LPCWSTR szTOKEN_NAMES[] = {
    L"",
    L"",
    SE_CREATE_TOKEN_NAME,
    SE_ASSIGNPRIMARYTOKEN_NAME,
    SE_LOCK_MEMORY_NAME,
    SE_INCREASE_QUOTA_NAME,
    SE_MACHINE_ACCOUNT_NAME,
    SE_TCB_NAME,
    SE_SECURITY_NAME,
    SE_TAKE_OWNERSHIP_NAME,
    SE_LOAD_DRIVER_NAME,
    SE_SYSTEM_PROFILE_NAME,
    SE_SYSTEMTIME_NAME,
    SE_PROF_SINGLE_PROCESS_NAME,
    SE_INC_BASE_PRIORITY_NAME,
    SE_CREATE_PAGEFILE_NAME,
    SE_CREATE_PERMANENT_NAME,
    SE_BACKUP_NAME,
    SE_RESTORE_NAME,
    SE_SHUTDOWN_NAME,
    SE_DEBUG_NAME,
    SE_AUDIT_NAME,
    SE_SYSTEM_ENVIRONMENT_NAME,
    SE_CHANGE_NOTIFY_NAME,
    SE_REMOTE_SHUTDOWN_NAME,
    SE_UNDOCK_NAME,
    SE_SYNC_AGENT_NAME,
    SE_ENABLE_DELEGATION_NAME,
    SE_MANAGE_VOLUME_NAME,
    SE_IMPERSONATE_NAME,
    SE_CREATE_GLOBAL_NAME,
    SE_TRUSTED_CREDMAN_ACCESS_NAME,
    SE_RELABEL_NAME,
    SE_INC_WORKING_SET_NAME,
    SE_TIME_ZONE_NAME,
    SE_CREATE_SYMBOLIC_LINK_NAME,
    SE_DELEGATE_SESSION_USER_IMPERSONATE_NAME
};

_Success_(return)
BOOL MProcToken_PrivilegeGet(_In_ QWORD vaToken, _Out_ PSEP_TOKEN_PRIVILEGES pSepTokenPrivileges, _Out_ PDWORD cSepTokenPrivileges)
{
    QWORD v;
    DWORD i, c = 0;
    if(ctxVmm->kernel.dwVersionBuild < 6000) { return FALSE; }     // TOKEN PRIVILEGES ONLY IN VISTA+
    if(!VmmRead(PVMM_PROCESS_SYSTEM, vaToken + 0x40, (PBYTE)pSepTokenPrivileges, 0x18)) { return FALSE; }
    for(i = 2; i < sizeof(szTOKEN_NAMES) / sizeof(LPCWSTR); i++) {
        v = pSepTokenPrivileges->Enabled | pSepTokenPrivileges->EnabledByDefault | pSepTokenPrivileges->Present;
        c += (v >> i) & 1;
    }
    *cSepTokenPrivileges = c;
    return TRUE;
}

VOID MProcToken_PrivilegeReadLine_Callback(_In_ PVMM_PROCESS pProcess, _In_ DWORD cbLineLength, _In_ DWORD ie, _In_ PSEP_TOKEN_PRIVILEGES pPriv, _Out_writes_(cbLineLength + 1) LPSTR szu8)
{
    QWORD v;
    DWORD i, c = ie;
    v = pPriv->Enabled | pPriv->EnabledByDefault | pPriv->Present;
    for(i = 2; i < sizeof(szTOKEN_NAMES) / sizeof(LPCWSTR); i++) {
        if((v >> i) & 1) {
            if(c) {
                c--;
            } else {
                Util_snwprintf_u8ln(szu8, cbLineLength,
                    L"%04x%7i  %c%c%c  %s",
                    i,
                    pProcess->dwPID,
                    ((pPriv->Enabled >> i) & 1) ? 'e' : '-',
                    ((pPriv->Present >> i) & 1) ? 'p' : '-',
                    ((pPriv->EnabledByDefault >> i) & 1) ? 'd' : '-',
                    szTOKEN_NAMES[i]
                );
                return;
            }
        }
    }
    Util_snwprintf_u8ln(szu8, cbLineLength, L"");
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
NTSTATUS MProcToken_Read(_In_ PVMMDLL_PLUGIN_CONTEXT ctx, _Out_writes_to_(cb, *pcbRead) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset)
{
    NTSTATUS nt = VMMDLL_STATUS_FILE_INVALID;
    WCHAR wszBuffer[MAX_PATH + 1];
    PVMM_PROCESS pObProcess = NULL;
    SEP_TOKEN_PRIVILEGES SepTokenPrivileges;
    DWORD cSepTokenPrivileges;
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
    } else if(!_wcsicmp(ctx->wszPath, L"privileges.txt")) {
        if(MProcToken_PrivilegeGet(pObProcess->win.TOKEN.va, &SepTokenPrivileges, &cSepTokenPrivileges)) {
            nt = Util_VfsLineFixed_Read(
                MProcToken_PrivilegeReadLine_Callback, pObProcess, MPROCTOKEN_PRIVILEGE_LINELENGTH, MPROCTOKEN_PRIVILEGE_LINEHEADER,
                &SepTokenPrivileges, cSepTokenPrivileges, 0,
                pb, cb, pcbRead, cbOffset
            );
        }
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
BOOL MProcToken_List(_In_ PVMMDLL_PLUGIN_CONTEXT ctx, _Inout_ PHANDLE pFileList)
{
    BOOL fResult = FALSE;
    DWORD cuszName, cSepTokenPrivileges;
    WCHAR wszBuffer[MAX_PATH + 1] = { 0 };
    PVMM_PROCESS pObProcess = NULL;
    SEP_TOKEN_PRIVILEGES SepTokenPrivileges;
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
    if(MProcToken_PrivilegeGet(pObProcess->win.TOKEN.va, &SepTokenPrivileges, &cSepTokenPrivileges)) {
        VMMDLL_VfsList_AddFile(pFileList, L"privileges.txt", UTIL_VFSLINEFIXED_LINECOUNT(cSepTokenPrivileges) * MPROCTOKEN_PRIVILEGE_LINELENGTH, NULL);
    }
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
VOID M_ProcToken_Initialize(_Inout_ PVMMDLL_PLUGIN_REGINFO pRI)
{
    if((pRI->magic != VMMDLL_PLUGIN_REGINFO_MAGIC) || (pRI->wVersion != VMMDLL_PLUGIN_REGINFO_VERSION)) { return; }
    if(!((pRI->tpSystem == VMM_SYSTEM_WINDOWS_X64) || (pRI->tpSystem == VMM_SYSTEM_WINDOWS_X86))) { return; }
    wcscpy_s(pRI->reg_info.wszPathName, 128, L"\\token");               // module name
    pRI->reg_info.fRootModule = FALSE;                                  // module shows in root directory
    pRI->reg_info.fProcessModule = TRUE;                                // module shows in process directory
    pRI->reg_fn.pfnList = MProcToken_List;                              // List function supported
    pRI->reg_fn.pfnRead = MProcToken_Read;                              // Read function supported
    pRI->pfnPluginManager_Register(pRI);
}
