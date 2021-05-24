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
#define MPROCTOKEN_PRIVILEGE_LINEHEADER     "   #    PID Flags Privilege Name"

static LPCSTR szTOKEN_NAMES[] = {
    "",
    "",
    "SeCreateTokenPrivilege",           // SE_CREATE_TOKEN_NAME
    "SeAssignPrimaryTokenPrivilege",    // SE_ASSIGNPRIMARYTOKEN_NAME
    "SeLockMemoryPrivilege",            // SE_LOCK_MEMORY_NAME
    "SeIncreaseQuotaPrivilege",         // SE_INCREASE_QUOTA_NAME
    "SeMachineAccountPrivilege",        // SE_MACHINE_ACCOUNT_NAME
    "SeTcbPrivilege",                   // SE_TCB_NAME
    "SeSecurityPrivilege",              // SE_SECURITY_NAME
    "SeTakeOwnershipPrivilege",         // SE_TAKE_OWNERSHIP_NAME
    "SeLoadDriverPrivilege",            // SE_LOAD_DRIVER_NAME
    "SeSystemProfilePrivilege",         // SE_SYSTEM_PROFILE_NAME
    "SeSystemtimePrivilege",            // SE_SYSTEMTIME_NAME
    "SeProfileSingleProcessPrivilege",  // SE_PROF_SINGLE_PROCESS_NAME
    "SeIncreaseBasePriorityPrivilege",  // SE_INC_BASE_PRIORITY_NAME
    "SeCreatePagefilePrivilege",        // SE_CREATE_PAGEFILE_NAME
    "SeCreatePermanentPrivilege",       // SE_CREATE_PERMANENT_NAME
    "SeBackupPrivilege",                // SE_BACKUP_NAME
    "SeRestorePrivilege",               // SE_RESTORE_NAME
    "SeShutdownPrivilege",              // SE_SHUTDOWN_NAME
    "SeDebugPrivilege",                 // SE_DEBUG_NAME
    "SeAuditPrivilege",                 // SE_AUDIT_NAME
    "SeSystemEnvironmentPrivilege",     // SE_SYSTEM_ENVIRONMENT_NAME
    "SeChangeNotifyPrivilege",          // SE_CHANGE_NOTIFY_NAME
    "SeRemoteShutdownPrivilege",        // SE_REMOTE_SHUTDOWN_NAME
    "SeUndockPrivilege",                // SE_UNDOCK_NAME
    "SeSyncAgentPrivilege",             // SE_SYNC_AGENT_NAME
    "SeEnableDelegationPrivilege",      // SE_ENABLE_DELEGATION_NAME
    "SeManageVolumePrivilege",          // SE_MANAGE_VOLUME_NAME
    "SeImpersonatePrivilege",           // SE_IMPERSONATE_NAME
    "SeCreateGlobalPrivilege",          // SE_CREATE_GLOBAL_NAME
    "SeTrustedCredManAccessPrivilege",  // SE_TRUSTED_CREDMAN_ACCESS_NAME
    "SeRelabelPrivilege",               // SE_RELABEL_NAME
    "SeIncreaseWorkingSetPrivilege",    // SE_INC_WORKING_SET_NAME
    "SeTimeZonePrivilege",              // SE_TIME_ZONE_NAME
    "SeCreateSymbolicLinkPrivilege",    // SE_CREATE_SYMBOLIC_LINK_NAME
    "SeDelegateSessionUserImpersonatePrivilege"     // SE_DELEGATE_SESSION_USER_IMPERSONATE_NAME
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
                Util_usnprintf_ln(szu8, cbLineLength,
                    "%04x%7i  %c%c%c  %s",
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
    Util_usnprintf_ln(szu8, cbLineLength, "");
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
    CHAR uszBuffer[MAX_PATH + 1];
    PVMM_PROCESS pObProcess = NULL;
    SEP_TOKEN_PRIVILEGES SepTokenPrivileges;
    DWORD cSepTokenPrivileges;
    if(!(pObProcess = VmmProcessGetEx(NULL, ctx->dwPID, VMM_FLAG_PROCESS_TOKEN))) { goto fail; }
    if(!pObProcess->win.TOKEN.fInitialized || !pObProcess->win.TOKEN.fSID) { goto fail; }
    if(!_stricmp(ctx->uszPath, "sid.txt")) {
        nt = Util_VfsReadFile_FromPBYTE(
            (PBYTE)pObProcess->win.TOKEN.szSID,
            pObProcess->win.TOKEN.szSID ? strlen(pObProcess->win.TOKEN.szSID) : 0,
            pb, cb, pcbRead, cbOffset);
    } else if(!_stricmp(ctx->uszPath, "user.txt")) {
        VmmWinUser_GetName(&pObProcess->win.TOKEN.SID, uszBuffer, MAX_PATH, NULL);
        nt = Util_VfsReadFile_FromPBYTE(uszBuffer, strlen(uszBuffer), pb, cb, pcbRead, cbOffset);
    } else if(!_stricmp(ctx->uszPath, "luid.txt")) {
        nt = Util_VfsReadFile_FromQWORD(pObProcess->win.TOKEN.qwLUID, pb, cb, pcbRead, cbOffset, FALSE);
    } else if(!_stricmp(ctx->uszPath, "session.txt")) {
        nt = Util_VfsReadFile_FromDWORD(pObProcess->win.TOKEN.dwSessionId, pb, cb, pcbRead, cbOffset, FALSE);
    } else if(!_stricmp(ctx->uszPath, "privileges.txt")) {
        if(MProcToken_PrivilegeGet(pObProcess->win.TOKEN.va, &SepTokenPrivileges, &cSepTokenPrivileges)) {
            nt = Util_VfsLineFixed_Read(
                (UTIL_VFSLINEFIXED_PFN_CB)MProcToken_PrivilegeReadLine_Callback, pObProcess, MPROCTOKEN_PRIVILEGE_LINELENGTH, MPROCTOKEN_PRIVILEGE_LINEHEADER,
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
    DWORD cSepTokenPrivileges;
    CHAR uszBuffer[MAX_PATH + 1] = { 0 };
    PVMM_PROCESS pObProcess = NULL;
    SEP_TOKEN_PRIVILEGES SepTokenPrivileges;
    if(!(pObProcess = VmmProcessGetEx(NULL, ctx->dwPID, VMM_FLAG_PROCESS_TOKEN))) { goto fail; }
    if(!pObProcess->win.TOKEN.fInitialized || !pObProcess->win.TOKEN.fSID) { goto fail; }
    if(pObProcess->win.TOKEN.szSID) {
        VMMDLL_VfsList_AddFile(pFileList, "sid.txt", strlen(pObProcess->win.TOKEN.szSID), NULL);
    }
    if(VmmWinUser_GetName(&pObProcess->win.TOKEN.SID, uszBuffer, MAX_PATH, NULL)) {
        VMMDLL_VfsList_AddFile(pFileList, "user.txt", strlen(uszBuffer), NULL);
    }
    VMMDLL_VfsList_AddFile(pFileList, "luid.txt", 16, NULL);
    VMMDLL_VfsList_AddFile(pFileList, "session.txt", 8, NULL);
    if(MProcToken_PrivilegeGet(pObProcess->win.TOKEN.va, &SepTokenPrivileges, &cSepTokenPrivileges)) {
        VMMDLL_VfsList_AddFile(pFileList, "privileges.txt", UTIL_VFSLINEFIXED_LINECOUNT(cSepTokenPrivileges) * MPROCTOKEN_PRIVILEGE_LINELENGTH, NULL);
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
    strcpy_s(pRI->reg_info.uszPathName, 128, "\\token");                // module name
    pRI->reg_info.fRootModule = FALSE;                                  // module shows in root directory
    pRI->reg_info.fProcessModule = TRUE;                                // module shows in process directory
    pRI->reg_fn.pfnList = MProcToken_List;                              // List function supported
    pRI->reg_fn.pfnRead = MProcToken_Read;                              // Read function supported
    pRI->pfnPluginManager_Register(pRI);
}
