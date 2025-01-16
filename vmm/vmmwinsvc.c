// vmmwinsvc.c : implementation of functionality related to Windows service manager (SCM).
//
// (c) Ulf Frisk, 2020-2025
// Author: Ulf Frisk, pcileech@frizk.net
//
#include "vmmwinsvc.h"
#include "vmm.h"
#include "vmmwin.h"
#include "vmmwinreg.h"
#include "pdb.h"
#include "util.h"

typedef struct tdVMMWINSVC_OFFSET_SC19 {
    WORD _Size;
    WORD Tag;
    BOOL fTag;
    DWORD TagV;
    WORD FLink;
    WORD BLink;
    WORD Ordinal;
    WORD SvcTp;
    WORD NmShort;
    WORD NmLong;
    WORD SvcStatus;
    WORD ExtInfo;
} VMMWINSVC_OFFSET_SC19, *PVMMWINSVC_OFFSET_SC19;

typedef struct tdVMMWINSVC_OFFSET_SC16 {
    WORD _Size;
    WORD Tag;
    BOOL fTag;
    WORD StartupPath;
    WORD Pid;
    WORD UserTp;
    WORD UserAcct;
    WORD FLink;
    WORD BLink;
} VMMWINSVC_OFFSET_SC16, *PVMMWINSVC_OFFSET_SC16;

typedef struct tdVMMWINSVC_CONTEXT {
    BOOL fSc19;
    DWORD dwTag;
    VMMWINSVC_OFFSET_SC19 oSc19;
    VMMWINSVC_OFFSET_SC16 oSc16;
} VMMWINSVC_CONTEXT, *PVMMWINSVC_CONTEXT;

/*
* Retrieve required offsets for parsing services by os build version.
* -- ctx
*/
VOID VmmWinSvc_OffsetLocator(_In_ VMM_HANDLE H, _In_ PVMMWINSVC_CONTEXT ctx)
{
    BOOL f32 = H->vmm.f32;
    DWORD dwBuild = H->vmm.kernel.dwVersionBuild;
    VMMWINSVC_OFFSET_SC16 o16 = { 0 };
    VMMWINSVC_OFFSET_SC19 o19 = { 0 };
    if(f32) {
        if(dwBuild >= 15063) {          // WIN10 1703/15063 +
            ctx->fSc19 = TRUE;
            ctx->dwTag = 'Sc19';
            o16 = (VMMWINSVC_OFFSET_SC16){ ._Size = 0x40, .fTag = TRUE, .Tag = 0x00, .BLink = 0x04, .FLink = 0x08, .StartupPath = 0x0c, .UserTp = 0x10, .Pid = 0x14, .UserAcct = 0x34 };
            o19 = (VMMWINSVC_OFFSET_SC19){ ._Size = 0xd0, .fTag = TRUE, .TagV = 'Sc19', .Tag = 0x04, .BLink = 0x0c, .FLink = 0x10, .Ordinal = 0x14, .SvcTp = 0x18, .NmShort = 0x2c, .NmLong = 0x30, .SvcStatus = 0x34, .ExtInfo = 0x9c };
            if(dwBuild >= 17763) { o19.ExtInfo = 0xa0; }
            if(dwBuild >= 18362) { o19.ExtInfo = 0xa4; }
            if(dwBuild >= 19041) { o19.ExtInfo = 0xc0; }
        } else if(dwBuild >= 9200) {    // WIN 8.0 +
            ctx->fSc19 = TRUE;
            ctx->dwTag = 'sErv';
            o16 = (VMMWINSVC_OFFSET_SC16){ ._Size = 0x20, .fTag = TRUE, .Tag = 0x00, .BLink = 0x04, .FLink = 0x08, .StartupPath = 0x0c, .UserTp = 0x00, .Pid = 0x10, .UserAcct = 0x00 };
            o19 = (VMMWINSVC_OFFSET_SC19){ ._Size = 0x80, .fTag = TRUE, .TagV = 'sErv', .Tag = 0x00, .BLink = 0x04, .FLink = 0x68, .Ordinal = 0x10, .SvcTp = 0x44, .NmShort = 0x08, .NmLong = 0x0c, .SvcStatus = 0x28, .ExtInfo = 0x24 };
            if(dwBuild >= 9600) { o19.FLink = 0x6c; }
        } else if(dwBuild >= 6000) {    // VISTA, WIN7
            ctx->dwTag = 'serH';
            o16 = (VMMWINSVC_OFFSET_SC16){ ._Size = 0x20, .fTag = FALSE, .Tag = 0x00, .BLink = 0x00, .FLink = 0x04, .StartupPath = 0x08, .UserTp = 0x00, .Pid = 0x0c, .UserAcct = 0x00 };
            o19 = (VMMWINSVC_OFFSET_SC19){ ._Size = 0x80, .fTag = FALSE, .TagV = '----', .Tag = 0x00, .BLink = 0x00, .FLink = 0x60, .Ordinal = 0x0c, .SvcTp = 0x3c, .NmShort = 0x04, .NmLong = 0x08, .SvcStatus = 0x20, .ExtInfo = 0x1c };
        } else if(dwBuild >= 2600) {    // XP
            ctx->fSc19 = TRUE;
            ctx->dwTag = 'sErv';
            o16 = (VMMWINSVC_OFFSET_SC16){ ._Size = 0x20, .fTag = FALSE, .Tag = 0x00, .BLink = 0x00, .FLink = 0x04, .StartupPath = 0x08, .UserTp = 0x00, .Pid = 0x0c, .UserAcct = 0x00 };
            o19 = (VMMWINSVC_OFFSET_SC19){ ._Size = 0x80, .fTag = TRUE, .TagV = 'sErv', .Tag = 0x18, .BLink = 0x00, .FLink = 0x04, .Ordinal = 0x10, .SvcTp = 0x44, .NmShort = 0x08, .NmLong = 0x0c, .SvcStatus = 0x28, .ExtInfo = 0x24 };
        }
    } else {
        if(dwBuild >= 15063) {          // WIN10 1703/15063 +
            ctx->fSc19 = TRUE;
            ctx->dwTag = 'Sc19';
            o16 = (VMMWINSVC_OFFSET_SC16){ ._Size = 0x60, .fTag = TRUE, .Tag = 0x00, .BLink = 0x08, .FLink = 0x10, .StartupPath = 0x18, .UserTp = 0x00, .Pid = 0x20, .UserAcct = 0x58 };
            o19 = (VMMWINSVC_OFFSET_SC19){ ._Size = 0x130, .fTag = TRUE, .TagV = 'Sc19', .Tag = 0x08, .BLink = 0x10, .FLink = 0x18, .Ordinal = 0x20, .SvcTp = 0x24, .NmShort = 0x38, .NmLong = 0x40, .SvcStatus = 0x48, .ExtInfo = 0xe8 };
            if(dwBuild >= 16299) { o16.Pid = 0x28; o16.UserTp = 0x20; }
            if(dwBuild >= 18362) { o19.ExtInfo = 0xf0; }
            if(dwBuild >= 19041) { o19.ExtInfo = 0x128; }
            if(dwBuild >= 26100) { o19._Size = 0x158; o19.SvcStatus = 0x50; o19.ExtInfo = 0x150; }
        } else if(dwBuild >= 9200) {    // WIN 8.0 +
            ctx->fSc19 = TRUE;
            ctx->dwTag = 'sErv';
            o16 = (VMMWINSVC_OFFSET_SC16){ ._Size = 0x30, .fTag = TRUE, .Tag = 0x00, .BLink = 0x08, .FLink = 0x10, .StartupPath = 0x18, .UserTp = 0x00, .Pid = 0x20, .UserAcct = 0x00 };
            o19 = (VMMWINSVC_OFFSET_SC19){ ._Size = 0xa0, .fTag = TRUE, .TagV = 'sErv', .Tag = 0x00, .BLink = 0x08, .FLink = 0x90, .Ordinal = 0x20, .SvcTp = 0x5c, .NmShort = 0x10, .NmLong = 0x18, .SvcStatus = 0x40, .ExtInfo = 0x38 };
            if(dwBuild >= 9600) { o19.FLink = 0x98; }
        } else if(dwBuild >= 6000) {    // VISTA, WIN7
            ctx->dwTag = 'serH';
            o16 = (VMMWINSVC_OFFSET_SC16){ ._Size = 0x20, .fTag = FALSE, .Tag = 0x00, .BLink = 0x00, .FLink = 0x08, .StartupPath = 0x10, .UserTp = 0x00, .Pid = 0x18, .UserAcct = 0x00 };
            o19 = (VMMWINSVC_OFFSET_SC19){ ._Size = 0xa0, .fTag = FALSE, .TagV = '----', .Tag = 0x00, .BLink = 0x00, .FLink = 0x80, .Ordinal = 0x18, .SvcTp = 0x4c, .NmShort = 0x08, .NmLong = 0x10, .SvcStatus = 0x30, .ExtInfo = 0x28 };
        }
    }
    memcpy(&ctx->oSc16, &o16, sizeof(VMMWINSVC_OFFSET_SC16));
    memcpy(&ctx->oSc19, &o19, sizeof(VMMWINSVC_OFFSET_SC19));
}

/*
* Retrieve the services.exe process.
* CALLER DECREF: return
* -- H
* -- return
*/
PVMM_PROCESS VmmWinSvc_GetProcessServices(_In_ VMM_HANDLE H)
{
    BOOL f;
    LPSTR szPProc;
    PVMM_PROCESS pObProcess = NULL, pObProcessParent = NULL;
    while((pObProcess = VmmProcessGetNext(H, pObProcess, 0))) {
        if(!_stricmp("services.exe", pObProcess->szName)) {
            szPProc = (H->vmm.kernel.dwVersionBuild == 2600) ? "winlogon.exe" : "wininit.exe";
            f = (pObProcessParent = VmmProcessGet(H, pObProcess->dwPPID)) &&
                !_stricmp(szPProc, pObProcessParent->szName);
            Ob_DECREF_NULL(&pObProcessParent);
            if(f) { return pObProcess; }
        }
    }
    return NULL;
}

/*
* Retrieve services list start/end from services.exe!ServiceDatabase PDB symbol.
* -- H
* -- pProcessServices
* -- pvaListHead
*/
VOID VmmWinSvc_ListHeadFromPDB(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pSvcProcess, _Out_writes_(2) PQWORD pvaListHead)
{
    BOOL f32 = H->vmm.f32;
    PDB_HANDLE hPdbServices;
    PVMM_MAP_MODULEENTRY peModuleServices;
    PVMMOB_MAP_MODULE pObModuleMap = NULL;
    BYTE pbSymSvcDB[0x18] = { 0 };
    DWORD dwoSymSvcDB = 0;
    pvaListHead[0] = 0;
    pvaListHead[1] = 0;
    if(!VmmMap_GetModuleEntryEx(H, pSvcProcess, 0, "services.exe", 0, &pObModuleMap, &peModuleServices)) { goto fail; }
    if(!(hPdbServices = PDB_GetHandleFromModuleAddress(H, pSvcProcess, peModuleServices->vaBase))) { goto fail; }
    if(!PDB_GetSymbolOffset(H, hPdbServices, "ServiceDatabase", &dwoSymSvcDB)) { goto fail; }
    if(!VmmRead(H, pSvcProcess, peModuleServices->vaBase + dwoSymSvcDB, pbSymSvcDB, sizeof(pbSymSvcDB))) { goto fail; }
    pvaListHead[0] = (QWORD)VMM_PTR_OFFSET_DUAL(f32, pbSymSvcDB, 4, 8);
    pvaListHead[1] = (QWORD)VMM_PTR_OFFSET_DUAL(f32, pbSymSvcDB, 8, 16);
    if(!VMM_UADDR_4_8(f32, pvaListHead[0]) || !VMM_UADDR_4_8(f32, pvaListHead[1])) { goto fail; }
fail:
    Ob_DECREF(pObModuleMap);
}

/*
* Retrieve services objects from vad and prefetch vad into cache.
* -- H
* -- ctx
* -- pSvcProcess
* -- pvaListHead
*/
VOID VmmWinSvc_ListHeadFromVAD(_In_ VMM_HANDLE H, _In_ PVMMWINSVC_CONTEXT ctx, _In_ PVMM_PROCESS pSvcProcess, _Inout_updates_(2) PQWORD pvaListHead)
{
    BOOL f32 = H->vmm.f32;
    QWORD va1, va2;
    DWORD i, o, dwTag, cbVad;
    BYTE pb2[0x10], *pb = NULL;
    PVMM_MAP_VADENTRY pe;
    PVMMOB_MAP_VAD pObVadMap = NULL;
    if(!VmmMap_GetVad(H, pSvcProcess, &pObVadMap, VMM_VADMAP_TP_CORE)) { goto finish; }
    // 1: if address exist -> prefetch vad and finish
    if(pvaListHead[0] && (pe = VmmMap_GetVadEntry(H, pObVadMap, pvaListHead[0]))) {
        cbVad = (DWORD)(pe->vaEnd + 1 - pe->vaStart);
        if(cbVad <= 0x00200000) {
            VmmCachePrefetchPages4(H, pSvcProcess, 1, &pe->vaStart, cbVad, 0);
        }
        goto finish;
    }
    // 2: locate vad candidates and scan:
    if(!(pb = LocalAlloc(LMEM_ZEROINIT, 0x00200000))) { goto finish; }
    for(i = 0; i < pObVadMap->cMap; i++) {
        pe = pObVadMap->pMap + i;
        if(!pe->fPrivateMemory || (pe->CommitCharge < 0x10)) { continue; }
        cbVad = (DWORD)(pe->vaEnd + 1 - pe->vaStart);
        if((cbVad > 0x00200000) || (cbVad < 0x00010000)) { continue; }
        VmmReadEx(H, pSvcProcess, pe->vaStart, pb, cbVad, NULL, VMM_FLAG_ZEROPAD_ON_FAIL);
        dwTag = _byteswap_ulong(ctx->dwTag);
        for(o = 0x1000; o < 0x00200000; o += 4) {
            if(dwTag == *(PDWORD)(pb + o)) {
                if(ctx->fSc19) {    // sErv / Sc19 entry - Win8.0+
                    va1 = VMM_PTR_OFFSET(f32, pb + o - ctx->oSc19.Tag, ctx->oSc19.BLink);
                    va2 = VMM_PTR_OFFSET(f32, pb + o - ctx->oSc19.Tag, ctx->oSc19.FLink);
                } else {            // serH entry
                    va1 = VMM_PTR_OFFSET_DUAL(f32, pb + o, 0x0c, 0x10); // TODO: verify 32-bit version
                    if(!VMM_UADDR_4_8(f32, va1)) { continue; }
                    if(!VmmRead(H, pSvcProcess, va1, pb2, 0x10)) { continue; }
                    va1 = VMM_PTR_OFFSET(f32, pb2, 0);
                    va2 = VMM_PTR_OFFSET_DUAL(f32, pb2, 4, 8);
                }
                if((va1 < 0x10000) || !VMM_UADDR_4_8(f32, va1) || (va2 < 0x10000) || !VMM_UADDR_4_8(f32, va2)) { continue; }
                pvaListHead[0] = va1;
                pvaListHead[1] = va2;
                goto finish;
            }
        }
    }
finish:
    Ob_DECREF(pObVadMap);
    LocalFree(pb);
}

/*
* Retrieve services from the service database list structure.
* CALLER DECREF: return
* -- H
* -- ctx
* -- pProcessSvc
* -- cVaListHead
* -- pvaListHead
* -- return
*/
POB_MAP VmmWinSvc_MainListWalk(_In_ VMM_HANDLE H, _In_ PVMMWINSVC_CONTEXT ctx, _In_ PVMM_PROCESS pProcessSvc, _In_ DWORD cVaListHead, _In_reads_(cVaListHead) PQWORD pvaListHead)
{
    BOOL f32 = H->vmm.f32;
    DWORD dwOrdinal, dwStartType;
    QWORD i, va, va1, va2, va3;
    BYTE pb[0x200] = { 0 };
    POB_SET psA = NULL;
    POB_MAP pmSvc = NULL;
    PVMM_MAP_SERVICEENTRY pe;
    PVMMWINSVC_OFFSET_SC19 o = &ctx->oSc19;
    if(!(psA = ObSet_New(H))) { goto fail; }
    if(!(pmSvc = ObMap_New(H, OB_MAP_FLAGS_OBJECT_LOCALFREE))) { goto fail; }
    for(i = 0; i < cVaListHead; i++) {
        ObSet_Push(psA, pvaListHead[i]);
    }
    while((va = ObSet_Pop(psA))) {
        // read & sanity check
        if(ObMap_ExistsKey(pmSvc, va)) { continue; }
        if(!VmmRead(H, pProcessSvc, va, pb, o->_Size)) { continue; }
        if(o->fTag && !VMM_POOLTAG(*(PDWORD)(pb + o->Tag), o->TagV)) { continue; }
        if((dwOrdinal = *(PDWORD)(pb + o->Ordinal)) > 0xffff) { continue; }
        if((dwStartType = *(PDWORD)(pb + o->SvcTp)) > SERVICE_TYPE_ALL) { continue; }
        // BLink / FLink
        va1 = VMM_PTR_OFFSET(f32, pb, o->BLink);
        va2 = VMM_PTR_OFFSET(f32, pb, o->FLink);
        if(!VMM_UADDR_4_8(f32, va1)) { va1 = 0; }
        if(!VMM_UADDR_4_8(f32, va2)) { va2 = 0; }
        if(!va1 && !va2) { continue; }
        ObSet_Push(psA, va1);
        ObSet_Push(psA, va2);
        if(!VMM_UADDR(f32, VMM_PTR_OFFSET(f32, pb, o->NmShort))) { continue; }
        // allocate & assign
        if(!(pe = LocalAlloc(LMEM_ZEROINIT, sizeof(VMM_MAP_SERVICEENTRY)))) { continue; }
        ObMap_Push(pmSvc, va, pe);
        pe->vaObj = va;
        pe->dwOrdinal = dwOrdinal;
        pe->dwStartType = dwStartType;
        memcpy(&pe->ServiceStatus, pb + o->SvcStatus, sizeof(SERVICE_STATUS));
        pe->_vaReservedServiceName = VMM_PTR_OFFSET(f32, pb, o->NmShort);
        pe->_vaReservedDisplayName = VMM_PTR_OFFSET(f32, pb, o->NmLong);
        if((pe->ServiceStatus.dwServiceType & SERVICE_KERNEL_DRIVER) || (pe->ServiceStatus.dwServiceType & SERVICE_FILE_SYSTEM_DRIVER)) {
            pe->_vaReservedPath = VMM_PTR_OFFSET(f32, pb, o->ExtInfo);
        } else {
            va3 = VMM_PTR_OFFSET(f32, pb, o->ExtInfo);
            pe->_Reserved = VMM_UADDR_4_8(f32, va3) ? va3 : 0;
        }
    }
    Ob_INCREF(pmSvc);
fail:
    Ob_DECREF(psA);
    return Ob_DECREF(pmSvc);
}

/*
* Retrieve the extended service info such as service process id, service user
* and other data which is found in the 'Sc16' data structure.
* -- H
* -- ctx
* -- pProcessSvc
* -- pmSvc
*/
VOID VmmWinSvc_GetExtendedInfo(_In_ VMM_HANDLE H, _In_ PVMMWINSVC_CONTEXT ctx, _In_ PVMM_PROCESS pProcessSvc, _In_ POB_MAP pmSvc)
{
    BOOL f32 = H->vmm.f32;
    QWORD va;
    BYTE pb[0x80] = { 0 };
    POB_SET psObPrefetch = NULL;
    PVMM_MAP_SERVICEENTRY pe = NULL;
    PVMMWINSVC_OFFSET_SC16 o = &ctx->oSc16;
    if((psObPrefetch = ObSet_New(H))) {
        while((pe = ObMap_GetNext(pmSvc, pe))) {
            ObSet_Push(psObPrefetch, pe->_Reserved);
        }
        VmmCachePrefetchPages3(H, pProcessSvc, psObPrefetch, o->_Size, 0);
        Ob_DECREF_NULL(&psObPrefetch);
    }
    while((pe = ObMap_GetNext(pmSvc, pe))) {
        if((va = pe->_Reserved)) {
            pe->_Reserved = 0;
            if(!VmmRead2(H, pProcessSvc, va, pb, o->_Size, VMM_FLAG_FORCECACHE_READ)) { continue; }
            if(o->fTag) {
                if(!VMM_POOLTAG(*(PDWORD)(pb + o->Tag), 'Sc16')) { continue; }
            } else {
                if(!(va = VMM_PTR_OFFSET(f32, pb, o->BLink)) || !VMM_UADDR_4_8(f32, va)) { continue; }
                if(!(va = VMM_PTR_OFFSET(f32, pb, o->FLink)) || !VMM_UADDR_4_8(f32, va)) { continue; }
            }
            pe->dwPID = *(PDWORD)(pb + o->Pid);
            pe->_vaReservedPath = VMM_PTR_OFFSET(f32, pb, o->StartupPath);
            pe->_vaReservedUserTp = o->UserTp ? VMM_PTR_OFFSET(f32, pb, o->UserTp) : 0;
            pe->_vaReservedUserAcct = o->UserAcct ? VMM_PTR_OFFSET(f32, pb, o->UserAcct) : 0;
        }
    }
}

/*
* Add a string from an address uniquely to the ObStrMap.
* -- H
* -- pProcessSvc
* -- psm
* -- puszText
* -- qwA
* -- fNullOnFail = set pwszText to NULL on fail (i.e. don't include in OB_STRMAP psm)
*/
VOID VmmWinSvc_ResolveStrAddSingle(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcessSvc, _In_ POB_STRMAP psm, _Out_ LPSTR *puszText, _In_ QWORD qwA, _In_ BOOL fNullOnFail)
{
    WCHAR wsz[2048] = { 0 };
    if((qwA < 0x10000) || !VMM_UADDR(H->vmm.f32, qwA)) { goto fail; }
    VmmRead2(H, pProcessSvc, qwA, (PBYTE)wsz, sizeof(wsz) - 2, VMM_FLAG_FORCECACHE_READ);
    if(!wsz[0]) { goto fail; }
    if(wsz[0] > 0xff || wsz[1] > 0xff || wsz[2] > 0xff) { goto fail; }
    ObStrMap_PushPtrWU(psm, wsz, puszText, NULL);
    return;
fail:
    if(fNullOnFail) {
        *puszText = NULL;
    } else {
        ObStrMap_PushPtrWU(psm, NULL, puszText, NULL);
    }
}

VOID VmmWinSvc_ResolveStrRegistry(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcessSvc, _In_ PVMMOB_MAP_SERVICE pSvcMap, _In_ POB_STRMAP psm)
{
    DWORD i, dwType, cbData = 0;
    PVMM_MAP_SERVICEENTRY pe;
    POB_REGISTRY_HIVE pObHive = NULL;
    CHAR usz[MAX_PATH + 1];
    USHORT wsz[MAX_PATH + 1];
    VmmWinReg_KeyHiveGetByFullPath(H, "HKLM\\SYSTEM", &pObHive, NULL);
    for(i = 0; i < pSvcMap->cMap; i++) {
        pe = pSvcMap->pMap + i;
        cbData = 0;
        if(pObHive) {
            _snprintf_s(usz, MAX_PATH, _TRUNCATE, "ROOT\\ControlSet001\\Services\\%s\\parameters\\ServiceDll", pe->uszServiceName);
            if(!VmmWinReg_ValueQuery3(H, pObHive, usz, &dwType, (PBYTE)wsz, MAX_PATH * 2, &cbData) || (dwType != REG_EXPAND_SZ)) {
                _snprintf_s(usz, MAX_PATH, _TRUNCATE, "ROOT\\ControlSet001\\Services\\%s\\ImagePath", pe->uszServiceName);
                if(!VmmWinReg_ValueQuery3(H, pObHive, usz, &dwType, (PBYTE)wsz, MAX_PATH * 2, &cbData) || (dwType != REG_EXPAND_SZ)) {
                    cbData = 0;
                }
            }
        }
        wsz[cbData >> 1] = 0;
        ObStrMap_PushPtrWU(psm, wsz, &pe->uszImagePath, NULL);
    }
    Ob_DECREF(pObHive);
}

/*
* Resolve all "primordial" strings related to the services.
* -- H
* -- pProcessSvc
* -- pSvcMap
* -- return
*/
_Success_(return)
BOOL VmmWinSvc_ResolveStrAll(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcessSvc, _In_ PVMMOB_MAP_SERVICE pSvcMap)
{
    DWORD i;
    BOOL fProcessUser;
    CHAR usz[MAX_PATH];
    PVMM_PROCESS pObProcessUser = NULL;
    PVMM_MAP_SERVICEENTRY pe;
    POB_SET psObPrefetch;
    POB_STRMAP pObStrMap;
    // 1: initialize
    if(!(pObStrMap = ObStrMap_New(H, OB_STRMAP_FLAGS_CASE_SENSITIVE | OB_STRMAP_FLAGS_STR_ASSIGN_TEMPORARY))) { return FALSE; }
    // 2: prefetch for performance reasons
    if((psObPrefetch = ObSet_New(H))) {
        for(i = 0; i < pSvcMap->cMap; i++) {
            pe = pSvcMap->pMap + i;
            ObSet_Push(psObPrefetch, pe->_vaReservedServiceName);
            ObSet_Push(psObPrefetch, pe->_vaReservedDisplayName);
            ObSet_Push(psObPrefetch, pe->_vaReservedPath);
            ObSet_Push(psObPrefetch, pe->_vaReservedUserTp);
            ObSet_Push(psObPrefetch, pe->_vaReservedUserAcct);
        }
        VmmCachePrefetchPages3(H, pProcessSvc, psObPrefetch, 2 * 2048, 0);
        Ob_DECREF_NULL(&psObPrefetch);
    }
    // 3.1: fetch strings - general
    for(i = 0; i < pSvcMap->cMap; i++) {
        pe = pSvcMap->pMap + i;
        VmmWinSvc_ResolveStrAddSingle(H, pProcessSvc, pObStrMap, &pe->uszServiceName, pe->_vaReservedServiceName, FALSE);
        VmmWinSvc_ResolveStrAddSingle(H, pProcessSvc, pObStrMap, &pe->uszDisplayName, pe->_vaReservedDisplayName, FALSE);
        VmmWinSvc_ResolveStrAddSingle(H, pProcessSvc, pObStrMap, &pe->uszPath,        pe->_vaReservedPath,        FALSE);
        VmmWinSvc_ResolveStrAddSingle(H, pProcessSvc, pObStrMap, &pe->uszUserTp,      pe->_vaReservedUserTp,      FALSE);
        VmmWinSvc_ResolveStrAddSingle(H, pProcessSvc, pObStrMap, &pe->uszUserAcct,    pe->_vaReservedUserAcct,    TRUE);
    }
    // 3.2: fetch strings - user (if does not exist already)
    for(i = 0; i < pSvcMap->cMap; i++) {
        pe = pSvcMap->pMap + i;
        if(!pe->uszUserAcct) {
            fProcessUser =
                pe->dwPID &&
                (pObProcessUser = VmmProcessGetEx(H, NULL, pe->dwPID, VMM_FLAG_PROCESS_TOKEN)) &&
                pObProcessUser->win.Token && pObProcessUser->win.Token->fSidUserValid &&
                VmmWinUser_GetName(H, &pObProcessUser->win.Token->SidUser.SID, usz, sizeof(usz), NULL);
            ObStrMap_PushPtrUU(pObStrMap, fProcessUser ? usz : NULL, &pe->uszUserAcct, NULL);
            Ob_DECREF_NULL(&pObProcessUser);
        }
    }
    // 3.3: fetch strings - image path from registry
    VmmWinSvc_ResolveStrRegistry(H, pProcessSvc, pSvcMap, pObStrMap);
    // 4: resolve strmap and return
    ObStrMap_FinalizeAllocU_DECREF_NULL(&pObStrMap, &pSvcMap->pbMultiText, &pSvcMap->cbMultiText);
    return TRUE;
}

/*
* Object manager callback function for object cleanup tasks.
* -- pVmmServiceMap
*/
VOID VmmWinSvc_CloseObCallback(_In_ PVOID pVmmServiceMap)
{
    PVMMOB_MAP_SERVICE pOb = (PVMMOB_MAP_SERVICE)pVmmServiceMap;
    LocalFree(pOb->pbMultiText);
}

/*
* qsort compare function for sorting the services list by ordinal.
*/
int VmmWinSvc_CmpSort(PVMM_MAP_SERVICEENTRY a, PVMM_MAP_SERVICEENTRY b)
{
    if(a->dwOrdinal != b->dwOrdinal) {
        return a->dwOrdinal - b->dwOrdinal;
    }
    return (int)(a->vaObj - b->vaObj);
}

/*
* Prefetch registry system hive to speed things up at later lookup.
*/
VOID VmmWinSvc_PrefetchRegSystemHive_ThreadProc(_In_ VMM_HANDLE H, QWORD qwNotUsed)
{
    POB_REGISTRY_HIVE pObHive;
    if(VmmWinReg_KeyHiveGetByFullPath(H, "HKLM\\SYSTEM", &pObHive, NULL)) {
        Ob_DECREF(pObHive);
    }
}

/*
* Retrieve services list as a map object manager object.
* CALLER DECREF: return
* -- H
* -- return
*/
PVMMOB_MAP_SERVICE VmmWinSvc_Initialize_DoWork(_In_ VMM_HANDLE H)
{
    VMMWINSVC_CONTEXT InitCtx = { 0 };
    PVMM_PROCESS pObSvcProcess = NULL;
    QWORD vaSvcDatabase[2] = { 0 };
    POB_MAP pmObSvc = NULL;
    DWORD i, cSvc;
    PVMMOB_MAP_SERVICE pObServiceMap = NULL;
    PVMM_MAP_SERVICEENTRY pe = NULL;
    // 0: prefetch SYSTEM reg hive
    VmmWork_Value(H, VmmWinSvc_PrefetchRegSystemHive_ThreadProc, 0, 0, VMMWORK_FLAG_PRIO_NORMAL);
    // 1: initialize
    if(!(pObSvcProcess = VmmWinSvc_GetProcessServices(H))) { goto fail; }
    VmmWinSvc_OffsetLocator(H, &InitCtx);
    if(H->vmm.kernel.dwVersionBuild >= 15063) {
        VmmWinSvc_ListHeadFromPDB(H, pObSvcProcess, vaSvcDatabase);
    }
    VmmWinSvc_ListHeadFromVAD(H, &InitCtx, pObSvcProcess, vaSvcDatabase);
    if(!vaSvcDatabase[0] && !vaSvcDatabase[1]) { goto fail; }
    // 2: walk services list and resolve extended info
    if(!(pmObSvc = VmmWinSvc_MainListWalk(H, &InitCtx, pObSvcProcess, 2, vaSvcDatabase))) { goto fail; }
    VmmWinSvc_GetExtendedInfo(H, &InitCtx, pObSvcProcess, pmObSvc);
    // 3: allocate, assign and sort services map
    cSvc = ObMap_Size(pmObSvc);
    if(!(pObServiceMap = Ob_AllocEx(H, OB_TAG_MAP_SERVICE, 0, sizeof(VMMOB_MAP_SERVICE) + cSvc * sizeof(VMM_MAP_SERVICEENTRY), VmmWinSvc_CloseObCallback, NULL))) { goto fail; }
    pObServiceMap->cMap = cSvc;
    for(i = 0; i < cSvc; i++) {
        if((pe = ObMap_GetByIndex(pmObSvc, i))) {
            memcpy(pObServiceMap->pMap + i, pe, sizeof(VMM_MAP_SERVICEENTRY));
        }
    }
    qsort(pObServiceMap->pMap, pObServiceMap->cMap, sizeof(VMM_MAP_SERVICEENTRY), (int(*)(void const *, void const *))VmmWinSvc_CmpSort);
    // 4: resolve strings
    if(!VmmWinSvc_ResolveStrAll(H, pObSvcProcess, pObServiceMap)) {
        Ob_DECREF_NULL(&pObServiceMap);
        goto fail;
    }
fail:
    Ob_DECREF(pObSvcProcess);
    Ob_DECREF(pmObSvc);
    return pObServiceMap;
}

/*
* Create a service map and assign to the global context upon success.
* CALLER DECREF: return
* -- H
* -- return
*/
PVMMOB_MAP_SERVICE VmmWinSvc_Initialize(_In_ VMM_HANDLE H)
{
    PVMMOB_MAP_SERVICE pObSvc;
    if((pObSvc = ObContainer_GetOb(H->vmm.pObCMapService))) { return pObSvc; }
    EnterCriticalSection(&H->vmm.LockUpdateMap);
    if((pObSvc = ObContainer_GetOb(H->vmm.pObCMapService))) {
        LeaveCriticalSection(&H->vmm.LockUpdateMap);
        return pObSvc;
    }
    pObSvc = VmmWinSvc_Initialize_DoWork(H);
    if(!pObSvc) {
        pObSvc = Ob_AllocEx(H, OB_TAG_MAP_SERVICE, LMEM_ZEROINIT, sizeof(VMMOB_MAP_SERVICE), NULL, NULL);
    }
    ObContainer_SetOb(H->vmm.pObCMapService, pObSvc);
    LeaveCriticalSection(&H->vmm.LockUpdateMap);
    return pObSvc;
}

/*
* Refresh the service map.
*/
VOID VmmWinSvc_Refresh(_In_ VMM_HANDLE H)
{
    ObContainer_SetOb(H->vmm.pObCMapService, NULL);
}
