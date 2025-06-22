// m_sys_pool.c : implementation related to the kernel pool built-in module.
//
// The 'sys/pool' module displays information about the kernel pools and
// allocated objects inside it.
//
// (c) Ulf Frisk, 2021-2025
// Author: Ulf Frisk, pcileech@frizk.net
//

#include "modules.h"

LPCSTR szMSYSPOOL_README =
"Information about the pool module                                            \n" \
"=================================                                            \n" \
"The pool module displays information about allocations in the kernel pools.  \n" \
"NB! allocations may be faulty or missing. Recovery is best-effort!           \n" \
"                                                                             \n" \
"Support as follows:                                                          \n" \
"XP:               basic support only.                                        \n" \
"Vista-Win10_1809: partial support (pool type likely to be wrong).            \n" \
"Win10_1903+:      supported.                                                 \n" \
"                                                                             \n" \
"Win10_1903+ work is largely based on work by Yarden Shafir @yarden_shafir    \n" \
"Please check out the excellent blackhat talk and poolviwer tools at:         \n" \
"https://i.blackhat.com/USA21/Wednesday-Handouts/us-21-Windows-Heap-Backed-Pool-The-Good-The-Bad-And-The-Encoded.pdf \n" \
"https://github.com/yardenshafir/PoolViewer                                   \n" \
"---                                                                          \n" \
"Documentation: https://github.com/ufrisk/MemProcFS/wiki/FS_SysInfo_Pool      \n";

#define MSYSPOOL_LINELENGTH      58ULL
#define MSYSPOOL_LINEHEADER      "       #  Tag A         Address      Size Type Pool"

VOID MSysPool_ReadLineCB(_In_ VMM_HANDLE H, _Inout_opt_ PVOID ctx, _In_ DWORD cbLineLength, _In_ DWORD ie, _In_ PVMM_MAP_POOLENTRY pe, _Out_writes_(cbLineLength + 1) LPSTR usz)
{
    union { CHAR sz[5]; DWORD dw; } uTag;
    uTag.dw = pe->dwTag;
    if(uTag.sz[0] < 32 || uTag.sz[0] > 126) { uTag.sz[0] = '?'; }
    if(uTag.sz[1] < 32 || uTag.sz[1] > 126) { uTag.sz[1] = '?'; }
    if(uTag.sz[2] < 32 || uTag.sz[2] > 126) { uTag.sz[2] = '?'; }
    if(uTag.sz[3] < 32 || uTag.sz[3] > 126) { uTag.sz[3] = '?'; }
    uTag.sz[4] = 0;
    Util_usnprintf_ln(usz, cbLineLength,
        "%8x %s %c %16llx %8x %s  %s",
        ie,
        uTag.sz,
        pe->fAlloc ? 'A' : '-',
        pe->va,
        pe->cb,
        VMM_POOL_TPSS_STRING[pe->tpSS],
        VMM_POOL_TP_STRING[pe->tpPool]
    );
}

typedef struct tdMSYSPOOL_MAP_CONTEXT {
    PVMMOB_MAP_POOL pmPool;
    PVMM_MAP_POOLENTRYTAG pePoolTag;
} MSYSPOOL_MAP_CONTEXT, *PMSYSPOOL_MAP_CONTEXT;

PVOID MSysPool_ReadLineGetEntryCB(_In_ VMM_HANDLE H, _In_ PVOID ctxMap, _In_ DWORD iMap)
{
    PMSYSPOOL_MAP_CONTEXT ctx = (PMSYSPOOL_MAP_CONTEXT)ctxMap;
    if(iMap < ctx->pePoolTag->cEntry) {
        return ctx->pmPool->pMap + ctx->pmPool->piTag2Map[ctx->pePoolTag->iTag2Map + iMap];
    }
    return NULL;
}

NTSTATUS MSysPool_ReadSingle(_In_ VMM_HANDLE H, _In_ LPCSTR uszPathFile, _In_ PVMM_MAP_POOLENTRY pe, _Out_writes_to_(cb, *pcbRead) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset)
{
    if(CharUtil_StrEndsWith(uszPathFile, "pool-address.txt", TRUE)) {
        if(H->vmm.f32) {
            return Util_VfsReadFile_FromDWORD((DWORD)pe->va, pb, cb, pcbRead, cbOffset, FALSE);
        } else {
            return Util_VfsReadFile_FromQWORD(pe->va, pb, cb, pcbRead, cbOffset, FALSE);
        }
    }
    if(CharUtil_StrEndsWith(uszPathFile, "pool-tag.txt", TRUE)) {
        return Util_VfsReadFile_FromPBYTE((PBYTE)pe->szTag, 4, pb, cb, pcbRead, cbOffset);
    }
    if(CharUtil_StrEndsWith(uszPathFile, "pool-data.mem", TRUE)) {
        return Util_VfsReadFile_FromMEM(H, PVMM_PROCESS_SYSTEM, pe->va, pe->cb, VMM_FLAG_ZEROPAD_ON_FAIL, pb, cb, pcbRead, cbOffset);
    }
    return VMMDLL_STATUS_FILE_INVALID;
}

NTSTATUS MSysPool_Read2(_In_ VMM_HANDLE H, _In_ LPCSTR uszPath, _In_ PVMMOB_MAP_POOL pmPool, _Out_writes_to_(cb, *pcbRead) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset)
{
    DWORD dwTag = (DWORD)-1;
    QWORD vaEntry;
    CHAR usz[MAX_PATH];
    PVMM_MAP_POOLENTRY pePool;
    MSYSPOOL_MAP_CONTEXT ctxMap;
    if(uszPath[0] == '\\') { uszPath += 1; }
    // general allocations file
    if(!_stricmp(uszPath, "allocations.txt")) {
        return Util_VfsLineFixed_Read(
            H, (UTIL_VFSLINEFIXED_PFN_CB)MSysPool_ReadLineCB, NULL, MSYSPOOL_LINELENGTH, MSYSPOOL_LINEHEADER,
            pmPool->pMap, pmPool->cMap, sizeof(VMM_MAP_POOLENTRY),
            pb, cb, pcbRead, cbOffset
        );
    }
    // by-tag allocations file
    if(CharUtil_StrEndsWith(uszPath, "allocations.txt", TRUE)) {
        Util_VfsHelper_GetIdDir(uszPath, TRUE, &dwTag, NULL);
        if(!VmmMap_GetPoolTag(H, pmPool, dwTag, &ctxMap.pePoolTag)) { return VMMDLL_STATUS_FILE_INVALID; }
        ctxMap.pmPool = pmPool;
        return Util_VfsLineFixedMapCustom_Read(
            H, (UTIL_VFSLINEFIXED_PFN_CB)MSysPool_ReadLineCB, NULL, MSYSPOOL_LINELENGTH, MSYSPOOL_LINEHEADER,
            &ctxMap, ctxMap.pePoolTag->cEntry, MSysPool_ReadLineGetEntryCB,
            pb, cb, pcbRead, cbOffset
        );
    }
    // single entry
    uszPath = CharUtil_PathSplitNext(uszPath);
    uszPath = CharUtil_PathSplitNext(uszPath);
    uszPath = CharUtil_PathSplitFirst(uszPath, usz, _countof(usz));
    vaEntry = strtoull(usz, NULL, 16);
    if(!uszPath[0] || !VmmMap_GetPoolEntry(H, pmPool, vaEntry, &pePool)) { return VMMDLL_STATUS_FILE_INVALID; }
    return MSysPool_ReadSingle(H, uszPath, pePool, pb, cb, pcbRead, cbOffset);
}

NTSTATUS MSysPool_Read(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_CONTEXT ctxP, _Out_writes_to_(cb, *pcbRead) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset)
{
    NTSTATUS nt = VMMDLL_STATUS_FILE_INVALID;
    PVMMOB_MAP_POOL pmObPool = NULL;
    if(!_stricmp(ctxP->uszPath, "readme.txt")) {
        return Util_VfsReadFile_FromStrA(szMSYSPOOL_README, pb, cb, pcbRead, cbOffset);
    }
    // all pool directory
    if(!_strnicmp(ctxP->uszPath, "all", 3) && VmmMap_GetPool(H, &pmObPool, TRUE)) {
        nt = MSysPool_Read2(H, ctxP->uszPath + 3, pmObPool, pb, cb, pcbRead, cbOffset);
    }
    // big pool directory
    if(!_strnicmp(ctxP->uszPath, "big", 3) && VmmMap_GetPool(H, &pmObPool, FALSE)) {
        nt = MSysPool_Read2(H, ctxP->uszPath + 3, pmObPool, pb, cb, pcbRead, cbOffset);
    }
    Ob_DECREF(pmObPool);
    return nt;
}

BOOL MSysPool_ListSingle(_In_ VMM_HANDLE H, _In_ PVMM_MAP_POOLENTRY pe, _Inout_ PHANDLE pFileList)
{
    VMMDLL_VfsList_AddFile(pFileList, "pool-tag.txt", 4, NULL);
    VMMDLL_VfsList_AddFile(pFileList, "pool-address.txt", H->vmm.f32 ? 8 : 16, NULL);
    VMMDLL_VfsList_AddFile(pFileList, "pool-data.mem", pe->cb, NULL);
    return TRUE;
}

BOOL MSysPool_List2(_In_ VMM_HANDLE H, _In_ LPSTR uszPath, _In_ PVMMOB_MAP_POOL pmPool, _Inout_ PHANDLE pFileList)
{
    QWORD vaEntry;
    DWORD i, iEntry, iTagEntry, dwTag = (DWORD)-1;
    LPCSTR uszSubPath = NULL;
    CHAR usz[MAX_PATH], c1, c2, c3, c4;
    PVMM_MAP_POOLENTRYTAG pePoolTag;
    PVMM_MAP_POOLENTRY pePool;
    if(uszPath[0] == '\\') { uszPath += 1; }
    // root directory
    if(!uszPath[0]) {
        VMMDLL_VfsList_AddDirectory(pFileList, "by-tag", NULL);
        VMMDLL_VfsList_AddFile(pFileList, "allocations.txt", UTIL_VFSLINEFIXED_LINECOUNT(H, pmPool->cMap) * MSYSPOOL_LINELENGTH, NULL);
        return TRUE;
    }
    // by tag
    if(!_strnicmp(uszPath, "by-tag", 6)) {
        Util_VfsHelper_GetIdDir(uszPath, TRUE, &dwTag, &uszSubPath);
        // tag root directory
        if(dwTag == (DWORD)-1) {
            for(i = 0; i < pmPool->cTag; i++) {
                c1 = pmPool->pTag[i].szTag[0]; if(c1 < 0x20 || c1 > 0x7a) { c1 = ' '; }
                c2 = pmPool->pTag[i].szTag[1]; if(c2 < 0x20 || c2 > 0x7a) { c2 = ' '; }
                c3 = pmPool->pTag[i].szTag[2]; if(c3 < 0x20 || c3 > 0x7a) { c3 = ' '; }
                c4 = pmPool->pTag[i].szTag[3]; if(c4 < 0x20 || c4 > 0x7a) { c4 = ' '; }
                _snprintf_s(usz, MAX_PATH, _TRUNCATE, "%c%c%c%c-%08x", c1, c2, c3, c4, pmPool->pTag[i].dwTag);
                VMMDLL_VfsList_AddDirectory(pFileList, usz, NULL);
            }
            return TRUE;
        }
        if(!uszSubPath) { return FALSE; }
        // sub-path-dir
        if(!uszSubPath[0]) {
            if(!VmmMap_GetPoolTag(H, pmPool, dwTag, &pePoolTag)) { return FALSE; }
            for(iTagEntry = 0; iTagEntry < pePoolTag->cEntry; iTagEntry++) {
                iEntry = pmPool->piTag2Map[pePoolTag->iTag2Map + iTagEntry];
                _snprintf_s(usz, MAX_PATH, _TRUNCATE, "%llx", pmPool->pMap[iEntry].va);
                VMMDLL_VfsList_AddDirectory(pFileList, usz, NULL);
            }
            VMMDLL_VfsList_AddFile(pFileList, "allocations.txt", UTIL_VFSLINEFIXED_LINECOUNT(H, pePoolTag->cEntry) * MSYSPOOL_LINELENGTH, NULL);
            return TRUE;
        }
        // single
        uszSubPath = CharUtil_PathSplitFirst(uszSubPath, usz, _countof(usz));
        vaEntry = strtoull(usz, NULL, 16);
        if(uszSubPath[0] || !VmmMap_GetPoolEntry(H, pmPool, vaEntry, &pePool)) { return FALSE; }
        return MSysPool_ListSingle(H, pePool, pFileList);
    }
    return FALSE;
}

BOOL MSysPool_List(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_CONTEXT ctxP, _Inout_ PHANDLE pFileList)
{
    BOOL fResult = FALSE;
    PVMMOB_MAP_POOL pmObPool = NULL;
    // root directory
    if(!ctxP->uszPath[0]) {
        VMMDLL_VfsList_AddDirectory(pFileList, "all", NULL);
        VMMDLL_VfsList_AddDirectory(pFileList, "big", NULL);
        VMMDLL_VfsList_AddFile(pFileList, "readme.txt", strlen(szMSYSPOOL_README), NULL);
        return TRUE;
    }
    // all pool directory
    if(!_strnicmp(ctxP->uszPath, "all", 3) && VmmMap_GetPool(H, &pmObPool, TRUE)) {
        fResult = MSysPool_List2(H, ctxP->uszPath + 3, pmObPool, pFileList);
    }
    // big pool directory
    if(!_strnicmp(ctxP->uszPath, "big", 3) && VmmMap_GetPool(H, &pmObPool, FALSE)) {
        fResult = MSysPool_List2(H, ctxP->uszPath + 3, pmObPool, pFileList);
    }
    Ob_DECREF(pmObPool);
    return fResult;
}

VOID M_SysPool_Initialize(_In_ VMM_HANDLE H, _Inout_ PVMMDLL_PLUGIN_REGINFO pRI)
{
    if((pRI->magic != VMMDLL_PLUGIN_REGINFO_MAGIC) || (pRI->wVersion != VMMDLL_PLUGIN_REGINFO_VERSION)) { return; }
    if((pRI->tpSystem != VMMDLL_SYSTEM_WINDOWS_64) && (pRI->tpSystem != VMMDLL_SYSTEM_WINDOWS_32)) { return; }
    strcpy_s(pRI->reg_info.uszPathName, 128, "\\sys\\pool");        // module name
    pRI->reg_info.fRootModule = TRUE;                               // module shows in root directory
    pRI->reg_fn.pfnList = MSysPool_List;                            // List function supported
    pRI->reg_fn.pfnRead = MSysPool_Read;                            // Read function supported
    pRI->pfnPluginManager_Register(H, pRI);
}
