// m_proc_token.c : implementation of the proc/token info built-in module.
//
// (c) Ulf Frisk, 2019-2025
// Author: Ulf Frisk, pcileech@frizk.net
//

#include "modules.h"
#include "../infodb.h"
#include "../vmmwin.h"
#ifdef _WIN32
#include <sddl.h>
#endif /* _WIN32 */

#define MPROCTOKEN_PRIVILEGE_LINELENGTH     60ULL
#define MPROCTOKEN_PRIVILEGE_LINEHEADER     "   # Flags Privilege Name"

#define MPROCTOKEN_ALLSID_LINELENGTH     256ULL
#define MPROCTOKEN_ALLSID_LINEHEADER     "   # Display Name                                                     SID"

_Success_(return)
BOOL MProcToken_PrivilegeGet(_In_ VMM_HANDLE H, _In_ PVMMOB_TOKEN pToken, _Out_ PDWORD cSepTokenPrivileges)
{
    QWORD v;
    DWORD i, c = 0;
    if(H->vmm.kernel.dwVersionBuild < 6000) { return FALSE; }     // TOKEN PRIVILEGES ONLY IN VISTA+
    for(i = 2; i < sizeof(SEP_TOKEN_PRIVILEGES_TYPE_STR) / sizeof(LPCWSTR); i++) {
        v = pToken->Privileges.Enabled.qwValue | pToken->Privileges.EnabledByDefault.qwValue | pToken->Privileges.Present.qwValue;
        c += (v >> i) & 1;
    }
    *cSepTokenPrivileges = c;
    return TRUE;
}

VOID MProcToken_PrivilegeReadLineCB(_In_ VMM_HANDLE H, _In_ PVMMOB_TOKEN pToken, _In_ DWORD cbLineLength, _In_ DWORD ie, _In_ PVOID pv, _Out_writes_(cbLineLength + 1) LPSTR szu8)
{
    QWORD v;
    DWORD i, c = ie;
    v = pToken->Privileges.Enabled.qwValue | pToken->Privileges.EnabledByDefault.qwValue | pToken->Privileges.Present.qwValue;
    for(i = 2; i < sizeof(SEP_TOKEN_PRIVILEGES_TYPE_STR) / sizeof(LPCWSTR); i++) {
        if((v >> i) & 1) {
            if(c) {
                c--;
            } else {
                Util_usnprintf_ln(szu8, cbLineLength,
                    "%04x  %c%c%c  %s",
                    i,
                    ((pToken->Privileges.Enabled.qwValue >> i) & 1) ? 'e' : '-',
                    ((pToken->Privileges.Present.qwValue >> i) & 1) ? 'p' : '-',
                    ((pToken->Privileges.EnabledByDefault.qwValue >> i) & 1) ? 'd' : '-',
                    SEP_TOKEN_PRIVILEGES_TYPE_STR[i]
                );
                return;
            }
        }
    }
    Util_usnprintf_ln(szu8, cbLineLength, "");
}

typedef struct tdMPROCTOKEN_ALLSID_CONTEXT {
    PVMMOB_TOKEN pToken;
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
    Util_usnprintf_ln(szu8, cbLineLength, "%04x %-64.64s %s",
        ie,
        szBuffer[0] ? szBuffer : "---",
        szSid ? szSid : "---"
    );
    LocalFree(szSid);
}

_Success_(return == 0)
NTSTATUS MProcToken_ReadToken(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_CONTEXT ctxP, _In_ PVMMOB_TOKEN pToken, _Out_writes_to_(cb, *pcbRead) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset)
{
    NTSTATUS nt = VMMDLL_STATUS_FILE_INVALID;
    CHAR uszBuffer[MAX_PATH + 1];
    DWORD cSepTokenPrivileges;
    LPCSTR sz;
    MPROCTOKEN_ALLSID_CONTEXT ctxAllSid = { 0 };
    if(!pToken->fSidUserValid) { return VMMDLL_STATUS_FILE_INVALID; }
    if(CharUtil_StrEndsWith(ctxP->uszPath, "sid.txt", TRUE)) {
        nt = Util_VfsReadFile_FromPBYTE(
            (PBYTE)pToken->szSID,
            pToken->szSID ? strlen(pToken->szSID) : 0,
            pb, cb, pcbRead, cbOffset);
    } else if(CharUtil_StrEndsWith(ctxP->uszPath, "sid-all.txt", TRUE)) {
        if(pToken->dwUserAndGroupCount && VmmReadAlloc(H, PVMM_PROCESS_SYSTEM, pToken->vaUserAndGroups, &ctxAllSid.pbUserAndGroups, pToken->dwUserAndGroupCount * (H->vmm.f32 ? 8 : 16), 0)) {
            ctxAllSid.pToken = pToken;
            ctxAllSid.pSystemProcess = VmmProcessGet(H, 4);
            VmmMap_GetUser(H, &ctxAllSid.pUserMap);
            nt = Util_VfsLineFixed_Read(
                H, (UTIL_VFSLINEFIXED_PFN_CB)MProcToken_AllSidReadLineCB, &ctxAllSid, MPROCTOKEN_ALLSID_LINELENGTH, MPROCTOKEN_ALLSID_LINEHEADER,
                (PVOID)ctxAllSid.pbUserAndGroups /*dummy*/, pToken->dwUserAndGroupCount, 0,
                pb, cb, pcbRead, cbOffset
            );
            Ob_DECREF(ctxAllSid.pSystemProcess);
            Ob_DECREF(ctxAllSid.pUserMap);
        }
    } else if(CharUtil_StrEndsWith(ctxP->uszPath, "user.txt", TRUE)) {
        VmmWinUser_GetName(H, &pToken->SidUser.SID, uszBuffer, MAX_PATH, NULL);
        nt = Util_VfsReadFile_FromPBYTE(uszBuffer, strlen(uszBuffer), pb, cb, pcbRead, cbOffset);
    } else if(CharUtil_StrEndsWith(ctxP->uszPath, "luid.txt", TRUE)) {
        nt = Util_VfsReadFile_FromQWORD(pToken->qwLUID, pb, cb, pcbRead, cbOffset, FALSE);
    } else if(CharUtil_StrEndsWith(ctxP->uszPath, "session.txt", TRUE)) {
        nt = Util_VfsReadFile_FromDWORD(pToken->dwSessionId, pb, cb, pcbRead, cbOffset, FALSE);
    } else if(CharUtil_StrEndsWith(ctxP->uszPath, "privileges.txt", TRUE)) {
        if(MProcToken_PrivilegeGet(H, pToken, &cSepTokenPrivileges)) {
            nt = Util_VfsLineFixed_Read(
                H, (UTIL_VFSLINEFIXED_PFN_CB)MProcToken_PrivilegeReadLineCB, pToken, MPROCTOKEN_PRIVILEGE_LINELENGTH, MPROCTOKEN_PRIVILEGE_LINEHEADER,
                (PVOID)1 /* dummy */, cSepTokenPrivileges, 0,
                pb, cb, pcbRead, cbOffset
            );
        }
    } else if(CharUtil_StrEndsWith(ctxP->uszPath, "integrity.txt", TRUE)) {
        sz = VMM_TOKEN_INTEGRITY_LEVEL_STR[pToken->IntegrityLevel];
        nt = Util_VfsReadFile_FromPBYTE((PBYTE)sz, strlen(sz), pb, cb, pcbRead, cbOffset);
    }
    return nt;
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
    PVMM_PROCESS pObProcess = NULL;
    pObProcess = VmmProcessGetEx(H, NULL, ctxP->dwPID, VMM_FLAG_PROCESS_TOKEN);
    if(pObProcess && pObProcess->win.Token) {
        nt = MProcToken_ReadToken(H, ctxP, pObProcess->win.Token, pb, cb, pcbRead, cbOffset);
    }
    Ob_DECREF(pObProcess);
    return nt;
}

VOID MProcToken_ListToken(_In_ VMM_HANDLE H, _Inout_ PHANDLE pFileList, _In_ PVMMOB_TOKEN pToken)
{
    DWORD cSepTokenPrivileges;
    CHAR uszBuffer[MAX_PATH + 1] = { 0 };
    if(!pToken->fSidUserValid) { return; }
    if(pToken->szSID) {
        VMMDLL_VfsList_AddFile(pFileList, "sid.txt", strlen(pToken->szSID), NULL);
        VMMDLL_VfsList_AddFile(pFileList, "sid-all.txt", UTIL_VFSLINEFIXED_LINECOUNT(H, pToken->dwUserAndGroupCount) * MPROCTOKEN_ALLSID_LINELENGTH, NULL);
    }
    if(VmmWinUser_GetName(H, &pToken->SidUser.SID, uszBuffer, MAX_PATH, NULL)) {
        VMMDLL_VfsList_AddFile(pFileList, "user.txt", strlen(uszBuffer), NULL);
    }
    VMMDLL_VfsList_AddFile(pFileList, "luid.txt", 16, NULL);
    VMMDLL_VfsList_AddFile(pFileList, "session.txt", 8, NULL);
    if(MProcToken_PrivilegeGet(H, pToken, &cSepTokenPrivileges)) {
        VMMDLL_VfsList_AddFile(pFileList, "privileges.txt", UTIL_VFSLINEFIXED_LINECOUNT(H, cSepTokenPrivileges) * MPROCTOKEN_PRIVILEGE_LINELENGTH, NULL);
    }
    if(pToken->IntegrityLevel) {
        VMMDLL_VfsList_AddFile(pFileList, "integrity.txt", strlen(VMM_TOKEN_INTEGRITY_LEVEL_STR[pToken->IntegrityLevel]), NULL);
    }
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

    PVMM_PROCESS pObProcess = NULL;
    pObProcess = VmmProcessGetEx(H, NULL, ctxP->dwPID, VMM_FLAG_PROCESS_TOKEN);
    if(pObProcess && pObProcess->win.Token) {
        MProcToken_ListToken(H, pFileList, pObProcess->win.Token);
    }
    Ob_DECREF(pObProcess);
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
VOID M_ProcToken_Initialize(_In_ VMM_HANDLE H, _Inout_ PVMMDLL_PLUGIN_REGINFO pRI)
{
    if((pRI->magic != VMMDLL_PLUGIN_REGINFO_MAGIC) || (pRI->wVersion != VMMDLL_PLUGIN_REGINFO_VERSION)) { return; }
    if(!((pRI->tpSystem == VMMDLL_SYSTEM_WINDOWS_64) || (pRI->tpSystem == VMMDLL_SYSTEM_WINDOWS_32))) { return; }
    strcpy_s(pRI->reg_info.uszPathName, 128, "\\token");                // module name
    pRI->reg_info.fRootModule = FALSE;                                  // module shows in root directory
    pRI->reg_info.fProcessModule = TRUE;                                // module shows in process directory
    pRI->reg_fn.pfnList = MProcToken_List;                              // List function supported
    pRI->reg_fn.pfnRead = MProcToken_Read;                              // Read function supported
    pRI->pfnPluginManager_Register(H, pRI);
}
