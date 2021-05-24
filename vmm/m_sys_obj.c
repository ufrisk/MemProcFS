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
#include "charutil.h"
#include "util.h"
#include "pluginmanager.h"
#include "vmmwinobj.h"

#define MSYSOBJ_LINELENGTH      200ULL
#define MSYSOBJ_LINEHEADER      "   # Object Address   Type          Description"

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
BOOL MSysObj_Path2Entry(_In_ PVMMOB_MAP_OBJECT pObjMap, _In_ LPSTR uszPath, _Out_ PVMM_MAP_OBJECTENTRY *ppe, _Out_ PBOOL pfMeta, _Out_ PBOOL pfEnd, _Out_ PBOOL pfTxt, _Out_ PBOOL pfMem)
{
    LPSTR usz;
    DWORD dwHash;
    CHAR usz1[MAX_PATH];
    PVMM_MAP_OBJECTENTRY pe;
    if(!pObjMap->cMap) { return FALSE; }
    pe = pObjMap->pMap;
    *pfTxt = CharUtil_StrEndsWith(uszPath, "\\obj-data.txt", TRUE) || CharUtil_StrEndsWith(uszPath, "\\obj-header.txt", TRUE) || CharUtil_StrEndsWith(uszPath, "\\obj-address.txt", TRUE) || CharUtil_StrEndsWith(uszPath, "\\obj-type.txt", TRUE);;
    *pfMem = CharUtil_StrEndsWith(uszPath, "\\obj-data.mem", TRUE);
    *pfEnd = CharUtil_StrEndsWith(uszPath, "\\$_INFO", TRUE);
    *pfMeta = *pfTxt || *pfMem || *pfEnd;
    usz = CharUtil_PathSplitFirst(uszPath, usz1, MAX_PATH); dwHash = CharUtil_HashNameFsU(usz1, 0);
    while(pe) {
        if(!_stricmp(usz1, "$_INFO")) {
            *pfMeta = TRUE;
            if(usz[0] == 0) { goto finish; }
            usz = CharUtil_PathSplitFirst(usz, usz1, MAX_PATH); dwHash = CharUtil_HashNameFsU(usz1, 0);
        }
        if(pe->dwHash == dwHash) {
            if(usz[0] == 0) { goto finish; }
            if(!_stricmp(usz, "$_INFO") || !_stricmp(usz, "obj-data.mem") || !_stricmp(usz, "obj-data.txt") || !_stricmp(usz, "obj-header.txt") || !_stricmp(usz, "obj-address.txt") || !_stricmp(usz, "obj-type.txt")) { goto finish; }
            usz = CharUtil_PathSplitFirst(usz, usz1, MAX_PATH); dwHash = CharUtil_HashNameFsU(usz1, 0);
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

VOID MSysObj_GetFullPath(_In_ PVMM_MAP_OBJECTENTRY pe, _Out_writes_(MAX_PATH) LPSTR uszPath)
{
    DWORD i = 0;
    PVMM_MAP_OBJECTENTRY pea[0x20];
    uszPath[0] = 0;
    pea[i++] = pe;
    while((pe = pe->pParent) && (pea[i++] = pe) && (i < 0x20));
    while(i && (pe = pea[--i])) {
        strncat_s(uszPath, MAX_PATH, pe->uszName, _TRUNCATE);
        if(i) { strncat_s(uszPath, MAX_PATH, "\\", _TRUNCATE); }
    }
}

VOID MSysObj_ReadLine_Callback(_Inout_opt_ PVOID ctx, _In_ DWORD cbLineLength, _In_ DWORD ie, _In_ PVMM_MAP_OBJECTENTRY pe, _Out_writes_(cbLineLength + 1) LPSTR usz)
{
    CHAR uszPath[MAX_PATH];
    MSysObj_GetFullPath(pe, uszPath);
    Util_usnprintf_ln(usz, cbLineLength,
        "%04x %016llx %-13s %s%s%s%s",
        ie,
        pe->va,
        pe->pType->usz,
        uszPath,
        pe->ExtInfo.usz[0] ? "  [" : "",
        pe->ExtInfo.usz,
        pe->ExtInfo.usz[0] ? "]" : ""
    );
}

NTSTATUS MSysObj_Read(_In_ PVMMDLL_PLUGIN_CONTEXT ctx, _Out_writes_to_(cb, *pcbRead) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset)
{
    NTSTATUS nt = VMMDLL_STATUS_FILE_INVALID;
    PVMMOB_MAP_OBJECT pObObjMap = NULL;
    PVMM_MAP_OBJECTENTRY pe;
    BOOL fMeta, fEnd, fTxt, fMem;
    if(!VmmMap_GetObject(&pObObjMap)) { goto finish; }
    if(!_stricmp(ctx->uszPath, "objects.txt")) {
        nt = Util_VfsLineFixed_Read(
            (UTIL_VFSLINEFIXED_PFN_CB)MSysObj_ReadLine_Callback, NULL, MSYSOBJ_LINELENGTH, MSYSOBJ_LINEHEADER,
            pObObjMap->pMap, pObObjMap->cMap, sizeof(VMM_MAP_OBJECTENTRY),
            pb, cb, pcbRead, cbOffset
        );
        goto finish;
    }
    if(MSysObj_Path2Entry(pObObjMap, ctx->uszPath, &pe, &fMeta, &fEnd, &fTxt, &fMem)) {
        if(fMeta) {
            nt = VmmWinObjDisplay_VfsRead(ctx->uszPath, pe->pType->iType, pe->va, pb, cb, pcbRead, cbOffset);
        } else {
            nt = Util_VfsReadFile_FromMEM(PVMM_PROCESS_SYSTEM, pe->va, pe->pType->cb, VMM_FLAG_ZEROPAD_ON_FAIL, pb, cb, pcbRead, cbOffset);
        }
    }
finish:
    Ob_DECREF(pObObjMap);
    return nt;
}

VOID MSysObj_ListDirectory(_In_ PVMMOB_MAP_OBJECT pObjMap, _In_ LPSTR uszPath, _Inout_ PHANDLE pFileList)
{
    PVMM_MAP_OBJECTENTRY pe;
    BOOL fMeta, fEnd, fTxt, fMem;
    if(!MSysObj_Path2Entry(pObjMap, uszPath, &pe, &fMeta, &fEnd, &fTxt, &fMem)) { return; }
    if(fMeta && !fEnd) {
        VmmWinObjDisplay_VfsList(pe->pType->iType, pe->va, pFileList);
        return;
    }
    pe = pe->pChild;
    if(!pe) { return; }
    if(!fMeta) {
        VMMDLL_VfsList_AddDirectory(pFileList, "$_INFO", NULL);
    }
    while(pe) {
        if((pe->pType->iType == 3) || fEnd) {
            VMMDLL_VfsList_AddDirectory(pFileList, pe->uszName, NULL);
        } else {
            VMMDLL_VfsList_AddFile(pFileList, pe->uszName, pe->pType->cb, NULL);
        }
        pe = pe->pNextByParent;
    }
}

BOOL MSysObj_List(_In_ PVMMDLL_PLUGIN_CONTEXT ctx, _Inout_ PHANDLE pFileList)
{
    PVMMOB_MAP_OBJECT pObObjMap = NULL;
    if(!VmmMap_GetObject(&pObObjMap)) { goto finish; }
    if(!ctx->uszPath[0]) {
        VMMDLL_VfsList_AddDirectory(pFileList, "ROOT", NULL);
        VMMDLL_VfsList_AddFile(pFileList, "objects.txt", UTIL_VFSLINEFIXED_LINECOUNT(pObObjMap->cMap) * MSYSOBJ_LINELENGTH, NULL);
        goto finish;
    }
    if(!_strnicmp(ctx->uszPath, "ROOT", 4)) {
        MSysObj_ListDirectory(pObObjMap, ctx->uszPath, pFileList);
        goto finish;
    }
finish:
    Ob_DECREF(pObObjMap);
    return TRUE;
}

VOID MSysObj_Timeline(
    _In_opt_ PVOID ctxfc,
    _In_ HANDLE hTimeline,
    _In_ VOID(*pfnAddEntry)(_In_ HANDLE hTimeline, _In_ QWORD ft, _In_ DWORD dwAction, _In_ DWORD dwPID, _In_ DWORD dwData32, _In_ QWORD qwData64, _In_ LPSTR uszText),
    _In_ VOID(*pfnEntryAddBySql)(_In_ HANDLE hTimeline, _In_ DWORD cEntrySql, _In_ LPSTR *pszEntrySql)
) {
    DWORD i, cType, iTypeBase;
    CHAR uszPath[MAX_PATH];
    PVMM_MAP_OBJECTENTRY pe;
    PVMMOB_MAP_OBJECT pObObjMap;
    if(VmmMap_GetObject(&pObObjMap)) {
        cType = pObObjMap->cType[ctxVmm->ObjectTypeTable.tpSymbolicLink];
        iTypeBase = pObObjMap->iTypeSortBase[ctxVmm->ObjectTypeTable.tpSymbolicLink];
        for(i = 0; i < cType; i++) {
            pe = &pObObjMap->pMap[iTypeBase + i];
            if(pe->ExtInfo.ft) {
                MSysObj_GetFullPath(pe, uszPath);
                pfnAddEntry(hTimeline, pe->ExtInfo.ft, FC_TIMELINE_ACTION_CREATE, 0, 0, pe->va, uszPath);
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
    CHAR usz[MAX_PATH];
    CHAR uszPath[MAX_PATH];
    if(ctxP->pProcess || !(pd = LocalAlloc(LMEM_ZEROINIT, sizeof(VMMDLL_PLUGIN_FORENSIC_JSONDATA)))) { return; }
    pd->dwVersion = VMMDLL_PLUGIN_FORENSIC_JSONDATA_VERSION;
    pd->szjType = "kobj";
    if(VmmMap_GetObject(&pObObjMap)) {
        for(i = 0; i < pObObjMap->cMap; i++) {
            pe = pObObjMap->pMap + i;
            MSysObj_GetFullPath(pe, uszPath);
            _snprintf_s(usz, _countof(usz), _TRUNCATE, "%s %s%s%s",
                uszPath,
                pe->ExtInfo.usz[0] ? "  [" : "",
                pe->ExtInfo.usz,
                pe->ExtInfo.usz[0] ? "]" : "");
            pd->i = i;
            pd->vaObj = pe->va;
            pd->usz[0] = pe->pType->usz;
            pd->usz[1] = usz;
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
    strcpy_s(pRI->reg_info.uszPathName, 128, "\\sys\\objects");     // module name
    pRI->reg_info.fRootModule = TRUE;                               // module shows in root directory
    pRI->reg_fn.pfnList = MSysObj_List;                             // List function supported
    pRI->reg_fn.pfnRead = MSysObj_Read;                             // Read function supported
    pRI->reg_fnfc.pfnTimeline = MSysObj_Timeline;                   // Timeline supported
    pRI->reg_fnfc.pfnLogJSON = MSysObj_FcLogJSON;                   // JSON log function supported
    memcpy(pRI->reg_info.sTimelineNameShort, "KObj", 5);
    strncpy_s(pRI->reg_info.uszTimelineFile, 32, "timeline_kernelobject.txt", _TRUNCATE);
    pRI->pfnPluginManager_Register(pRI);
}
