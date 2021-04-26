// m_sys_obj.c : implementation related to the sys/objects built-in module.
//
// The 'sys/objects' module is responsible for displaying information about
// the kernel object maanger.
//
// (c) Ulf Frisk, 2021
// Author: Ulf Frisk, pcileech@frizk.net
//
#include "vmm.h"
#include "fc.h"
#include "util.h"
#include "pluginmanager.h"
#include "vmmwinobj.h"

#define MSYSOBJ_LINELENGTH      200ULL
#define MSYSOBJ_LINEHEADER      L"   # Object Address   Type          Description"

/*
* Retrieve the sought after object manager object together with information
* about a possible meta-data directory '$_INFO'. And also of it points to a
* file as per below:
* -- pObjMap
* -- wszPath
* -- ppe = object manager object output
* -- pfMeta = path contains '\\$_INFO'
* -- pfEnd = path ends with '\\$_INFO'
* -- pfTxt = path ends with '\\obj-data.txt', '\\obj-header.txt', '\\obj-addr.txt', '\\obj-type.txt'
* -- pfMem = path ends with '\\obj-data.mem'
*/
_Success_(return)
BOOL MSysObj_Path2Entry(_In_ PVMMOB_MAP_OBJECT pObjMap, _In_ LPWSTR wszPath, _Out_ PVMM_MAP_OBJECTENTRY *ppe, _Out_ PBOOL pfMeta, _Out_ PBOOL pfEnd, _Out_ PBOOL pfTxt, _Out_ PBOOL pfMem)
{
    LPWSTR wsz;
    DWORD dwHash;
    WCHAR wsz1[MAX_PATH];
    PVMM_MAP_OBJECTENTRY pe;
    if(!pObjMap->cMap) { return FALSE; }
    pe = pObjMap->pMap;
    *pfTxt = Util_StrEndsWithW(wszPath, L"\\obj-data.txt", TRUE) || Util_StrEndsWithW(wszPath, L"\\obj-header.txt", TRUE) || Util_StrEndsWithW(wszPath, L"\\obj-address.txt", TRUE) || Util_StrEndsWithW(wszPath, L"\\obj-type.txt", TRUE);;
    *pfMem = Util_StrEndsWithW(wszPath, L"\\obj-data.mem", TRUE);
    *pfEnd = Util_StrEndsWithW(wszPath, L"\\$_INFO", TRUE);
    *pfMeta = *pfTxt || *pfMem || *pfEnd;
    wsz = Util_PathSplit2_ExWCHAR(wszPath, wsz1, MAX_PATH); dwHash = Util_HashNameW_Registry(wsz1, 0);
    while(pe) {
        if(!_wcsicmp(wsz1, L"$_INFO")) {
            *pfMeta = TRUE;
            if(wsz[0] == 0) { goto finish; }
            wsz = Util_PathSplit2_ExWCHAR(wsz, wsz1, MAX_PATH); dwHash = Util_HashNameW_Registry(wsz1, 0);
        }
        if(pe->dwHash == dwHash) {
            if(wsz[0] == 0) { goto finish; }
            if(!_wcsicmp(wsz, L"$_INFO") || !_wcsicmp(wsz, L"obj-data.mem") || !_wcsicmp(wsz, L"obj-data.txt") || !_wcsicmp(wsz, L"obj-header.txt") || !_wcsicmp(wsz, L"obj-address.txt") || !_wcsicmp(wsz, L"obj-type.txt")) { goto finish; }
            wsz = Util_PathSplit2_ExWCHAR(wsz, wsz1, MAX_PATH); dwHash = Util_HashNameW_Registry(wsz1, 0);
            pe = pe->pChild;
        } else {
            pe = pe->pNextByParent;
        }
    }
    return FALSE;
finish:
    *ppe = pe;
    return TRUE;
}

VOID MSysObj_GetFullPath(_In_ PVMM_MAP_OBJECTENTRY pe, _Out_writes_(MAX_PATH) LPWSTR wszPath)
{
    DWORD i = 0;
    PVMM_MAP_OBJECTENTRY pea[0x20];
    wszPath[0] = 0;
    pea[i++] = pe;
    while((pe = pe->pParent) && (pea[i++] = pe) && (i < 0x20));
    while(i && (pe = pea[--i])) {
        wcsncat_s(wszPath, MAX_PATH, pe->wszName, _TRUNCATE);
        if(i) { wcsncat_s(wszPath, MAX_PATH, L"\\", _TRUNCATE); }
    }
}

VOID MSysObj_ReadLine_Callback(_Inout_opt_ PVOID ctx, _In_ DWORD cbLineLength, _In_ DWORD ie, _In_ PVMM_MAP_OBJECTENTRY pe, _Out_writes_(cbLineLength + 1) LPSTR szu8)
{
    WCHAR wszPath[MAX_PATH];
    MSysObj_GetFullPath(pe, wszPath);
    Util_snwprintf_u8ln(szu8, cbLineLength,
        L"%04x %016llx %-13s %s%s%s%s",
        ie,
        pe->va,
        pe->pType->wsz,
        wszPath,
        pe->ExtInfo.wsz[0] ? L"  [" : L"",
        pe->ExtInfo.wsz,
        pe->ExtInfo.wsz[0] ? L"]" : L""
    );
}

NTSTATUS MSysObj_Read(_In_ PVMMDLL_PLUGIN_CONTEXT ctx, _Out_writes_to_(cb, *pcbRead) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset)
{
    NTSTATUS nt = VMMDLL_STATUS_FILE_INVALID;
    PVMMOB_MAP_OBJECT pObObjMap = NULL;
    PVMM_MAP_OBJECTENTRY pe;
    BOOL fMeta, fEnd, fTxt, fMem;
    if(!VmmMap_GetObject(&pObObjMap)) { goto finish; }
    if(!_wcsicmp(ctx->wszPath, L"objects.txt")) {
        nt = Util_VfsLineFixed_Read(
            MSysObj_ReadLine_Callback, NULL, MSYSOBJ_LINELENGTH, MSYSOBJ_LINEHEADER,
            pObObjMap->pMap, pObObjMap->cMap, sizeof(VMM_MAP_OBJECTENTRY),
            pb, cb, pcbRead, cbOffset
        );
        goto finish;
    }
    if(MSysObj_Path2Entry(pObObjMap, ctx->wszPath, &pe, &fMeta, &fEnd, &fTxt, &fMem)) {
        if(fMeta) {
            nt = VmmWinObjDisplay_VfsRead(ctx->wszPath, pe->pType->iType, pe->va, pb, cb, pcbRead, cbOffset);
        } else {
            nt = Util_VfsReadFile_FromMEM(PVMM_PROCESS_SYSTEM, pe->va, pe->pType->cb, VMM_FLAG_ZEROPAD_ON_FAIL, pb, cb, pcbRead, cbOffset);
        }
    }
finish:
    Ob_DECREF(pObObjMap);
    return nt;
}

VOID MSysObj_ListDirectory(_In_ PVMMOB_MAP_OBJECT pObjMap, _In_ LPWSTR wszPath, _Inout_ PHANDLE pFileList)
{
    PVMM_MAP_OBJECTENTRY pe;
    BOOL fMeta, fEnd, fTxt, fMem;
    if(!MSysObj_Path2Entry(pObjMap, wszPath, &pe, &fMeta, &fEnd, &fTxt, &fMem)) { return; }
    if(fMeta && !fEnd) {
        VmmWinObjDisplay_VfsList(pe->pType->iType, pe->va, pFileList);
        return;
    }
    pe = pe->pChild;
    if(!pe) { return; }
    if(!fMeta) {
        VMMDLL_VfsList_AddDirectory(pFileList, L"$_INFO", NULL);
    }
    while(pe) {
        if((pe->pType->iType == 3) || fEnd) {
            VMMDLL_VfsList_AddDirectory(pFileList, pe->wszName, NULL);
        } else {
            VMMDLL_VfsList_AddFile(pFileList, pe->wszName, pe->pType->cb, NULL);
        }
        pe = pe->pNextByParent;
    }
}

BOOL MSysObj_List(_In_ PVMMDLL_PLUGIN_CONTEXT ctx, _Inout_ PHANDLE pFileList)
{
    PVMMOB_MAP_OBJECT pObObjMap = NULL;
    if(!VmmMap_GetObject(&pObObjMap)) { goto finish; }
    if(!ctx->wszPath[0]) {
        VMMDLL_VfsList_AddDirectory(pFileList, L"ROOT", NULL);
        VMMDLL_VfsList_AddFile(pFileList, L"objects.txt", UTIL_VFSLINEFIXED_LINECOUNT(pObObjMap->cMap) * MSYSOBJ_LINELENGTH, NULL);
        goto finish;
    }
    if(!_wcsnicmp(ctx->wszPath, L"ROOT", 4)) {
        MSysObj_ListDirectory(pObObjMap, ctx->wszPath, pFileList);
        goto finish;
    }
finish:
    Ob_DECREF(pObObjMap);
    return TRUE;
}

VOID MSysObj_Timeline(
    _In_opt_ PVOID ctxfc,
    _In_ HANDLE hTimeline,
    _In_ VOID(*pfnAddEntry)(_In_ HANDLE hTimeline, _In_ QWORD ft, _In_ DWORD dwAction, _In_ DWORD dwPID, _In_ DWORD dwData32, _In_ QWORD qwData64, _In_ LPWSTR wszText),
    _In_ VOID(*pfnEntryAddBySql)(_In_ HANDLE hTimeline, _In_ DWORD cEntrySql, _In_ LPSTR *pszEntrySql)
) {
    DWORD i, cType, iTypeBase;
    WCHAR wszPath[MAX_PATH];
    PVMM_MAP_OBJECTENTRY pe;
    PVMMOB_MAP_OBJECT pObObjMap;
    if(VmmMap_GetObject(&pObObjMap)) {
        cType = pObObjMap->cType[ctxVmm->ObjectTypeTable.tpSymbolicLink];
        iTypeBase = pObObjMap->iTypeSortBase[ctxVmm->ObjectTypeTable.tpSymbolicLink];
        for(i = 0; i < cType; i++) {
            pe = &pObObjMap->pMap[iTypeBase + i];
            if(pe->ExtInfo.ft) {
                MSysObj_GetFullPath(pe, wszPath);
                pfnAddEntry(hTimeline, pe->ExtInfo.ft, FC_TIMELINE_ACTION_CREATE, 0, 0, pe->va, wszPath);
            }
        }
    }
}

VOID MSysObj_FcLogJSON(_In_ PVMMDLL_PLUGIN_CONTEXT ctxP, _In_ VOID(*pfnLogJSON)(_In_ PVMMDLL_PLUGIN_FORENSIC_JSONDATA pData))
{
    PVMMDLL_PLUGIN_FORENSIC_JSONDATA pd;
    PVMMOB_MAP_OBJECT pObObjMap = NULL;
    PVMM_MAP_OBJECTENTRY pe;
    DWORD i;
    CHAR szj[MAX_PATH];
    WCHAR wszPath[MAX_PATH];
    if(ctxP->pProcess || !(pd = LocalAlloc(LMEM_ZEROINIT, sizeof(VMMDLL_PLUGIN_FORENSIC_JSONDATA)))) { return; }
    pd->dwVersion = VMMDLL_PLUGIN_FORENSIC_JSONDATA_VERSION;
    pd->szjType = "kobj";
    if(VmmMap_GetObject(&pObObjMap)) {
        for(i = 0; i < pObObjMap->cMap; i++) {
            pe = pObObjMap->pMap + i;
            MSysObj_GetFullPath(pe, wszPath);
            Util_snwprintf_u8j(szj, _countof(szj), L"%s %s%s%s",
                wszPath,
                pe->ExtInfo.wsz[0] ? L"  [" : L"",
                pe->ExtInfo.wsz,
                pe->ExtInfo.wsz[0] ? L"]" : L"");
            pd->i = i;
            pd->vaObj = pe->va;
            pd->wsz[0] = pe->pType->wsz;
            pd->szj[1] = szj;
            pfnLogJSON(pd);
        }
    }
    Ob_DECREF(pObObjMap);
    LocalFree(pd);
}

VOID M_SysObj_Initialize(_Inout_ PVMMDLL_PLUGIN_REGINFO pRI)
{
    if((pRI->magic != VMMDLL_PLUGIN_REGINFO_MAGIC) || (pRI->wVersion != VMMDLL_PLUGIN_REGINFO_VERSION)) { return; }
    if((pRI->tpSystem != VMM_SYSTEM_WINDOWS_X64) && (pRI->tpSystem != VMM_SYSTEM_WINDOWS_X86)) { return; }
    if(pRI->sysinfo.dwVersionBuild < 7600) { return; }              // WIN7+ required
    wcscpy_s(pRI->reg_info.wszPathName, 128, L"\\sys\\objects");    // module name
    pRI->reg_info.fRootModule = TRUE;                               // module shows in root directory
    pRI->reg_fn.pfnList = MSysObj_List;                             // List function supported
    pRI->reg_fn.pfnRead = MSysObj_Read;                             // Read function supported
    pRI->reg_fnfc.pfnTimeline = MSysObj_Timeline;                   // Timeline supported
    pRI->reg_fnfc.pfnLogJSON = MSysObj_FcLogJSON;                   // JSON log function supported
    memcpy(pRI->reg_info.sTimelineNameShort, "KObj", 5);
    strncpy_s(pRI->reg_info.szTimelineFileUTF8, 32, "timeline_kernelobject.txt", _TRUNCATE);
    pRI->pfnPluginManager_Register(pRI);
}
