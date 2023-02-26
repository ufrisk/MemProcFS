// m_proc_token.c : implementation of the proc/token info built-in module.
//
// (c) Ulf Frisk, 2019-2023
// Author: Ulf Frisk, pcileech@frizk.net
//

#include "modules.h"
#include "../infodb.h"
#include "../vmmwin.h"
#ifdef _WIN32
#include <sddl.h>
#endif /* _WIN32 */

#define MPROCTOKEN_PRIVILEGE_LINELENGTH     60ULL
#define MPROCTOKEN_PRIVILEGE_LINEHEADER     "   #    PID Flags Privilege Name"

#define MPROCTOKEN_ALLSID_LINELENGTH     256ULL
#define MPROCTOKEN_ALLSID_LINEHEADER     "   #    PID Display Name                                                     SID"

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
BOOL MProcToken_PrivilegeGet(_In_ VMM_HANDLE H, _In_ QWORD vaToken, _Out_ PSEP_TOKEN_PRIVILEGES pSepTokenPrivileges, _Out_ PDWORD cSepTokenPrivileges)
{
    QWORD v;
    DWORD i, c = 0;
    if(H->vmm.kernel.dwVersionBuild < 6000) { return FALSE; }     // TOKEN PRIVILEGES ONLY IN VISTA+
    if(!VmmRead(H, PVMM_PROCESS_SYSTEM, vaToken + 0x40, (PBYTE)pSepTokenPrivileges, 0x18)) { return FALSE; }
    for(i = 2; i < sizeof(szTOKEN_NAMES) / sizeof(LPCWSTR); i++) {
        v = pSepTokenPrivileges->Enabled | pSepTokenPrivileges->EnabledByDefault | pSepTokenPrivileges->Present;
        c += (v >> i) & 1;
    }
    *cSepTokenPrivileges = c;
    return TRUE;
}

VOID MProcToken_PrivilegeReadLineCB(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess, _In_ DWORD cbLineLength, _In_ DWORD ie, _In_ PSEP_TOKEN_PRIVILEGES pPriv, _Out_writes_(cbLineLength + 1) LPSTR szu8)
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

typedef struct tdMPROCTOKEN_ALLSID_CONTEXT {
    PVMM_PROCESS pProcess;
    PVMM_PROCESS pSystemProcess;
    PVMMOB_MAP_USER pUserMap;
    PBYTE pbUserAndGroups;
} MPROCTOKEN_ALLSID_CONTEXT, *PMPROCTOKEN_ALLSID_CONTEXT;

VOID MProcToken_AllSidReadLineCB(_In_ VMM_HANDLE H, _In_ PMPROCTOKEN_ALLSID_CONTEXT ctx, _In_ DWORD cbLineLength, _In_ DWORD ie, _In_ PVOID pvNotUsed, _Out_writes_(cbLineLength + 1) LPSTR szu8)
{
    union {
        SID SID;
        BYTE pb[SECURITY_MAX_SID_SIZE];
    } Sid;
    QWORD vaSid;
    LPSTR szSid = NULL;
    SID_NAME_USE eUse;
    CHAR szNameBuffer[MAX_PATH], szBuffer[MAX_PATH] = { 0 };
    DWORD i, cszNameBuffer = _countof(szNameBuffer);
    DWORD cszBuffer = _countof(szBuffer);
    vaSid = VMM_PTR_OFFSET(H->vmm.f32, ctx->pbUserAndGroups, ie * (H->vmm.f32 ? 8ULL : 16ULL));
    if(!VmmRead(H, ctx->pSystemProcess, vaSid, Sid.pb, SECURITY_MAX_SID_SIZE)) { goto fail; }
    if(!ConvertSidToStringSidA(&Sid.SID, &szSid)) { goto fail; }
    // display name from infodb/winapi lookup:
    if(InfoDB_SidToUser_Wellknown(H, szSid, szNameBuffer, &cszNameBuffer, szBuffer, &cszBuffer) || LookupAccountSidA(NULL, &Sid.SID, szNameBuffer, &cszNameBuffer, szBuffer, &cszBuffer, &eUse)) {
        if(szBuffer[0]) { strncat_s(szBuffer, _countof(szBuffer), "\\", _TRUNCATE); }
        strncat_s(szBuffer, _countof(szBuffer), szNameBuffer, _TRUNCATE);
    }
    // display name from user:
    if(!szBuffer[0] && ctx->pUserMap) {
        for(i = 0; i < ctx->pUserMap->cMap; i++) {
            if(!strcmp(szSid, ctx->pUserMap->pMap[i].szSID)) {
                strncat_s(szBuffer, _countof(szBuffer), ctx->pUserMap->pMap[i].uszText, _TRUNCATE);
            }
        }
    }
fail:
    Util_usnprintf_ln(szu8, cbLineLength, "%04x%7i %-64.64s %s",
        ie,
        ctx->pProcess->dwPID,
        szBuffer[0] ? szBuffer : "---",
        szSid ? szSid : "---"
    );
    LocalFree(szSid);
}

/*
* Read : function as specified by the module manager. The module manager will
* call into this callback function whenever a read shall occur from a "file".
* -- H
* -- ctxP
* -- pb
* -- cb
* -- pcbRead
* -- cbOffset
* -- return
*/
_Success_(return == 0)
NTSTATUS MProcToken_Read(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_CONTEXT ctxP, _Out_writes_to_(cb, *pcbRead) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset)
{
    NTSTATUS nt = VMMDLL_STATUS_FILE_INVALID;
    CHAR uszBuffer[MAX_PATH + 1];
    PVMM_PROCESS pObProcess = NULL;
    SEP_TOKEN_PRIVILEGES SepTokenPrivileges;
    DWORD cSepTokenPrivileges;
    LPCSTR sz;
    MPROCTOKEN_ALLSID_CONTEXT ctxAllSid = { 0 };
    if(!(pObProcess = VmmProcessGetEx(H, NULL, ctxP->dwPID, VMM_FLAG_PROCESS_TOKEN))) { goto fail; }
    if(!pObProcess->win.TOKEN.fInitialized || !pObProcess->win.TOKEN.fSidUserValid) { goto fail; }
    if(!_stricmp(ctxP->uszPath, "sid.txt")) {
        nt = Util_VfsReadFile_FromPBYTE(
            (PBYTE)pObProcess->win.TOKEN.szSID,
            pObProcess->win.TOKEN.szSID ? strlen(pObProcess->win.TOKEN.szSID) : 0,
            pb, cb, pcbRead, cbOffset);
    } else if(!_stricmp(ctxP->uszPath, "sid-all.txt")) {
        if(pObProcess->win.TOKEN.dwUserAndGroupCount && VmmReadAlloc(H, PVMM_PROCESS_SYSTEM, pObProcess->win.TOKEN.vaUserAndGroups, &ctxAllSid.pbUserAndGroups, pObProcess->win.TOKEN.dwUserAndGroupCount * (H->vmm.f32 ? 8 : 16), 0)) {
            ctxAllSid.pProcess = pObProcess;
            ctxAllSid.pSystemProcess = VmmProcessGet(H, 4);
            VmmMap_GetUser(H, &ctxAllSid.pUserMap);
            nt = Util_VfsLineFixed_Read(
                H, (UTIL_VFSLINEFIXED_PFN_CB)MProcToken_AllSidReadLineCB, &ctxAllSid, MPROCTOKEN_ALLSID_LINELENGTH, MPROCTOKEN_ALLSID_LINEHEADER,
                (PVOID)ctxAllSid.pbUserAndGroups /*dummy*/, pObProcess->win.TOKEN.dwUserAndGroupCount, 0,
                pb, cb, pcbRead, cbOffset
            );
            Ob_DECREF(ctxAllSid.pSystemProcess);
            Ob_DECREF(ctxAllSid.pUserMap);
        }
    } else if(!_stricmp(ctxP->uszPath, "user.txt")) {
        VmmWinUser_GetName(H, &pObProcess->win.TOKEN.SidUser.SID, uszBuffer, MAX_PATH, NULL);
        nt = Util_VfsReadFile_FromPBYTE(uszBuffer, strlen(uszBuffer), pb, cb, pcbRead, cbOffset);
    } else if(!_stricmp(ctxP->uszPath, "luid.txt")) {
        nt = Util_VfsReadFile_FromQWORD(pObProcess->win.TOKEN.qwLUID, pb, cb, pcbRead, cbOffset, FALSE);
    } else if(!_stricmp(ctxP->uszPath, "session.txt")) {
        nt = Util_VfsReadFile_FromDWORD(pObProcess->win.TOKEN.dwSessionId, pb, cb, pcbRead, cbOffset, FALSE);
    } else if(!_stricmp(ctxP->uszPath, "privileges.txt")) {
        if(MProcToken_PrivilegeGet(H, pObProcess->win.TOKEN.va, &SepTokenPrivileges, &cSepTokenPrivileges)) {
            nt = Util_VfsLineFixed_Read(
                H, (UTIL_VFSLINEFIXED_PFN_CB)MProcToken_PrivilegeReadLineCB, pObProcess, MPROCTOKEN_PRIVILEGE_LINELENGTH, MPROCTOKEN_PRIVILEGE_LINEHEADER,
                &SepTokenPrivileges, cSepTokenPrivileges, 0,
                pb, cb, pcbRead, cbOffset
            );
        }
    } else if(!_stricmp(ctxP->uszPath, "integrity.txt")) {
        sz = VMM_PROCESS_INTEGRITY_LEVEL_STR[pObProcess->win.TOKEN.IntegrityLevel];
        nt = Util_VfsReadFile_FromPBYTE((PBYTE)sz, strlen(sz), pb, cb, pcbRead, cbOffset);
    }
fail:
    Ob_DECREF(pObProcess);
    return nt;
}

/*
* List : function as specified by the module manager. The module manager will
* call into this callback function whenever a list directory shall occur from
* the given module.
* -- ctxP
* -- pFileList
* -- return
*/
BOOL MProcToken_List(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_CONTEXT ctxP, _Inout_ PHANDLE pFileList)
{
    BOOL fResult = FALSE;
    DWORD cSepTokenPrivileges;
    CHAR uszBuffer[MAX_PATH + 1] = { 0 };
    PVMM_PROCESS pObProcess = NULL;
    SEP_TOKEN_PRIVILEGES SepTokenPrivileges;
    if(!(pObProcess = VmmProcessGetEx(H, NULL, ctxP->dwPID, VMM_FLAG_PROCESS_TOKEN))) { goto fail; }
    if(!pObProcess->win.TOKEN.fInitialized || !pObProcess->win.TOKEN.fSidUserValid) { goto fail; }
    if(pObProcess->win.TOKEN.szSID) {
        VMMDLL_VfsList_AddFile(pFileList, "sid.txt", strlen(pObProcess->win.TOKEN.szSID), NULL);
        VMMDLL_VfsList_AddFile(pFileList, "sid-all.txt", UTIL_VFSLINEFIXED_LINECOUNT(H, pObProcess->win.TOKEN.dwUserAndGroupCount) * MPROCTOKEN_ALLSID_LINELENGTH, NULL);
    }
    if(VmmWinUser_GetName(H, &pObProcess->win.TOKEN.SidUser.SID, uszBuffer, MAX_PATH, NULL)) {
        VMMDLL_VfsList_AddFile(pFileList, "user.txt", strlen(uszBuffer), NULL);
    }
    VMMDLL_VfsList_AddFile(pFileList, "luid.txt", 16, NULL);
    VMMDLL_VfsList_AddFile(pFileList, "session.txt", 8, NULL);
    if(MProcToken_PrivilegeGet(H, pObProcess->win.TOKEN.va, &SepTokenPrivileges, &cSepTokenPrivileges)) {
        VMMDLL_VfsList_AddFile(pFileList, "privileges.txt", UTIL_VFSLINEFIXED_LINECOUNT(H, cSepTokenPrivileges) * MPROCTOKEN_PRIVILEGE_LINELENGTH, NULL);
    }
    if(pObProcess->win.TOKEN.IntegrityLevel) {
        VMMDLL_VfsList_AddFile(pFileList, "integrity.txt", strlen(VMM_PROCESS_INTEGRITY_LEVEL_STR[pObProcess->win.TOKEN.IntegrityLevel]), NULL);
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
VOID M_ProcToken_Initialize(_In_ VMM_HANDLE H, _Inout_ PVMMDLL_PLUGIN_REGINFO pRI)
{
    if((pRI->magic != VMMDLL_PLUGIN_REGINFO_MAGIC) || (pRI->wVersion != VMMDLL_PLUGIN_REGINFO_VERSION)) { return; }
    if(!((pRI->tpSystem == VMM_SYSTEM_WINDOWS_X64) || (pRI->tpSystem == VMM_SYSTEM_WINDOWS_X86))) { return; }
    strcpy_s(pRI->reg_info.uszPathName, 128, "\\token");                // module name
    pRI->reg_info.fRootModule = FALSE;                                  // module shows in root directory
    pRI->reg_info.fProcessModule = TRUE;                                // module shows in process directory
    pRI->reg_fn.pfnList = MProcToken_List;                              // List function supported
    pRI->reg_fn.pfnRead = MProcToken_Read;                              // Read function supported
    pRI->pfnPluginManager_Register(H, pRI);
}
