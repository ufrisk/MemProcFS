// m_fc_pretch.c : prefetch forensic module.
//
// REQUIRE: FORENSIC SUB-SYSTEM INIT.
//
// (c) Ulf Frisk, 2024-2025
// Author: Ulf Frisk, pcileech@frizk.net
//

#include "modules.h"
#include "../vmmwinobj.h"



//------------------------------------------------------------------------------
// Prefetch map generation functionality:
//------------------------------------------------------------------------------

static LPSTR MFCPREFETCH_CSV = "Process,RunCount,FileCount,PrefetchFile,RunTime1,RunTime2,RunTime3,RunTime4,RunTime5,RunTime6,RunTime7,RunTim8,FileObjectAddress\n";

#define MFCPREFETCH_MAXSIZE             0x00100000  // 1MB
#define MFCPREFETCH_COMPRESSED_MAGIC    0x044D414D  // MAM
#define MFCPREFETCH_MAGIC               0x41434353  // SCCA
#define MFCPREFETCH_MAX_FILEMETRICS     0x400
#define MFCPREFETCH_MAX_PREFETCHES      0x10000

#define MFCPREFETCH_VERSION_WIN8        26          // WIN8
#define MFCPREFETCH_VERSION_WIN10       30          // WIN10+

typedef struct tdVMM_MAP_PREFETCHENTRY_FILEMETRICSENTRY {
    DWORD dwIndex;
    LPSTR uszFileName;
    LPSTR uszPath;
    LPSTR uszVolume;
} VMM_MAP_PREFETCH_FILEMETRICSENTRY, *PVMM_MAP_PREFETCH_FILEMETRICSENTRY;

typedef struct tdVMM_MAP_PREFETCHENTRY {
    DWORD dwHash;                       // prefetch hash
    DWORD dwVersion;                    // prefetch version
    DWORD cbDecompressedFileSize;       // size of the decompressed prefetch file
    DWORD cbPrefetchFileSize;           // size of the original (on-disk) prefetch file
    QWORD vaPrefetchFile;               // prefetch file object virtual address
    LPSTR uszPrefetchFileName;          // prefetch file name
    LPSTR uszExecutableFileName;        // executable file name
    QWORD ftRunTimes[8];                // run times (last 8)
    DWORD cRunCount;                    // total run count
    // file info blocks:
    DWORD cFileMetrics;                                 // number of file metrics
    PVMM_MAP_PREFETCH_FILEMETRICSENTRY pFileMetrics;    // pointer to file metrics array
} VMM_MAP_PREFETCHENTRY, *PVMM_MAP_PREFETCHENTRY;

typedef struct tdVMMOB_MAP_PREFETCH {
    OB ObHdr;
    PBYTE pbMultiText;
    DWORD cbMultiText;
    DWORD cMap;
    VMM_MAP_PREFETCHENTRY pMap[];
} VMMOB_MAP_PREFETCH, *PVMMOB_MAP_PREFETCH;

typedef struct tdMFCPREFETCH_INIT_CONTEXT {
    POB_MAP pmPf;
    POB_SET psDuplicate;
    POB_STRMAP psm;
    DWORD cFileMetrics;
    DWORD cbPf;
    BYTE pbPf[MFCPREFETCH_MAXSIZE];
    BYTE pbBuffer1M_1[MFCPREFETCH_MAXSIZE];
    BYTE pbBuffer1M_2[MFCPREFETCH_MAXSIZE];
} MFCPREFETCH_INIT_CONTEXT, *PMFCPREFETCH_INIT_CONTEXT;

/*
* Parse a single prefetch file into a record.
* Max 0x1000 file metrics are supported.
* Any fails happens before anything is added to the string map.
*/
VOID MFcPrefetch_ParseSingle_V26_V30(_In_ VMM_HANDLE H, _In_ POB_MAP pmPf, _In_ POB_STRMAP psm, _In_ POB_SET psDuplicate, _In_ POB_VMMWINOBJ_FILE pFile, _In_ DWORD cbFile, _In_reads_bytes_(cbPf) PBYTE pbPf, _In_ DWORD cbPf, _Inout_ PDWORD pcFileMetrics)
{
    PVMM_MAP_PREFETCHENTRY pePf = NULL;
    DWORD i, dwHdrHash;
    CHAR usz[0x100];
    CHAR uszVolumeRaw[0x100];
    CHAR uszExecutableFileName[0x100] = { 0 };
    PBYTE pbFm;
    BYTE pbHashSHA256[32];
    LPCSTR uszPath, uszFile, uszVolume;
    DWORD oFileMetrics, cFileMetrics;
    DWORD oFileNameStrings = 0, oFileNameString, cchFileNameString;
    SIZE_T cch;
    // 1: sanity checks and duplicate checks:
    if(cbPf < 84 + 224) { return; }
    dwHdrHash = *(PDWORD)(pbPf + 76);
    if(!ObSet_Push(psDuplicate, dwHdrHash)) { return; }
    Util_HashSHA256(pbPf, cbPf, pbHashSHA256);
    if(!ObSet_Push(psDuplicate, *(PQWORD)pbHashSHA256)) { return; }
    // 2: alloc
    oFileMetrics = *(PDWORD)(pbPf + 84 + 0);
    cFileMetrics = min(MFCPREFETCH_MAX_FILEMETRICS, *(PDWORD)(pbPf + 84 + 4));
    if(oFileMetrics + cFileMetrics * 32 > cbPf) { return; }
    if(!(pePf = LocalAlloc(LMEM_ZEROINIT, sizeof(VMM_MAP_PREFETCHENTRY) + cFileMetrics * sizeof(VMM_MAP_PREFETCH_FILEMETRICSENTRY)))) { return; }
    pePf->cFileMetrics = cFileMetrics;
    pePf->pFileMetrics = (PVMM_MAP_PREFETCH_FILEMETRICSENTRY)(pePf + 1);
    // 3: header:
    {
        pePf->dwVersion = *(PDWORD)(pbPf + 0);
        pePf->cbDecompressedFileSize = *(PDWORD)(pbPf + 12);
        pePf->dwHash = *(PDWORD)(pbPf + 76);
        CharUtil_WtoU((LPCWSTR)(pbPf + 16), 30, (PBYTE)uszExecutableFileName, sizeof(uszExecutableFileName), NULL, NULL, CHARUTIL_FLAG_STR_BUFONLY);
        ObStrMap_PushPtrUU(psm, uszExecutableFileName, &pePf->uszExecutableFileName, NULL);
        pePf->vaPrefetchFile = pFile->va;
        pePf->cbPrefetchFileSize = cbFile;
        ObStrMap_PushPtrUU(psm, pFile->uszName, &pePf->uszPrefetchFileName, NULL);
    }
    // 3: file info blocks:
    {
        oFileNameStrings = *(PDWORD)(pbPf + 84 + 16);
        // run times:
        for(i = 0; i < 8; i++) {
            pePf->ftRunTimes[i] = *(PQWORD)(pbPf + 84 + 44 + i * 8);
            if((pePf->ftRunTimes[i] < 0x0100000000000000) || (pePf->ftRunTimes[i] > 0x0200000000000000)) { pePf->ftRunTimes[i] = 0; }
        }
        // run count:
        pePf->cRunCount = *(PDWORD)(pbPf + 84 + 120) ? *(PDWORD)(pbPf + 84 + 116) : *(PDWORD)(pbPf + 84 + 124);
    }
    // 4: file metrics:
    for(i = 0; i < cFileMetrics; i++) {
        pbFm = pbPf + oFileMetrics + i * 32;
        if(pePf->dwVersion == 17) {
            oFileNameString = *(PDWORD)(pbFm + 8);
            cchFileNameString = *(PDWORD)(pbFm + 12);
        } else {
            oFileNameString = *(PDWORD)(pbFm + 12);
            cchFileNameString = *(PDWORD)(pbFm + 16);
        }
        if(oFileNameStrings + oFileNameString + (cchFileNameString << 1) <= cbPf) {
            usz[0] = 0;
            CharUtil_WtoU((LPWSTR)(pbPf + oFileNameStrings + oFileNameString), cchFileNameString, (PBYTE)usz, sizeof(usz), NULL, NULL, CHARUTIL_FLAG_STR_BUFONLY | CHARUTIL_FLAG_TRUNCATE);
            if(pePf->dwVersion == MFCPREFETCH_VERSION_WIN10) {
                uszPath = CharUtil_SplitFirst(usz, '}', uszVolumeRaw, sizeof(uszVolumeRaw) - 1);
                uszVolumeRaw[strlen(uszVolumeRaw) - 1] = '}';
                uszVolume = uszVolumeRaw[0] == '\\' ? uszVolumeRaw + 1 : uszVolumeRaw;
            } else {
                uszPath = CharUtil_PathSplitNext(usz);
                uszPath = CharUtil_PathSplitNext(uszPath);
                uszPath = CharUtil_PathSplitNext(uszPath);
                if(uszPath != usz) { uszPath--; }
                cch = min(sizeof(uszVolumeRaw), (SIZE_T)(uszPath - usz));
                strncpy_s(uszVolumeRaw, sizeof(uszVolumeRaw), usz, cch);
                uszVolume = uszVolumeRaw;
            }
            uszFile = CharUtil_PathSplitLast(uszPath);
            pePf->pFileMetrics[i].dwIndex = i;
            ObStrMap_PushPtrUU(psm, uszFile, &pePf->pFileMetrics[i].uszFileName, NULL);
            ObStrMap_PushPtrUU(psm, uszPath, &pePf->pFileMetrics[i].uszPath, NULL);
            ObStrMap_PushPtrUU(psm, uszVolume, &pePf->pFileMetrics[i].uszVolume, NULL);
        }
    }
    // 5: commit result to map:
    ObMap_Push(pmPf, pePf->dwHash, pePf);
    *pcFileMetrics += cFileMetrics;
}

VOID MFcPrefetch_ParseSingle(_In_ VMM_HANDLE H, _In_ PMFCPREFETCH_INIT_CONTEXT ctx, _In_ POB_VMMWINOBJ_FILE pFile)
{
    NTSTATUS nt;
    DWORD dwVersion, dwSignature2;
    DWORD cch, cbFile, dwSignature, cbUncompressed;
    // 1: sanity checks:
    if(!CharUtil_StrEndsWith(pFile->uszName, ".pf", TRUE)) { return; }
    cch = (DWORD)strlen(pFile->uszName);
    if((cch < 12) || (pFile->uszName[cch - 12] != '-')) { return; }
    // 2: read file and decompress if needed:
    cbFile = VmmWinObjFile_Read(H, pFile, 0, ctx->pbBuffer1M_1, (DWORD)min(MFCPREFETCH_MAXSIZE, pFile->cb), 0, VMMWINOBJ_FILE_TP_DEFAULT);
    if(cbFile < 0x100) { return; }
    dwSignature = *(PDWORD)ctx->pbBuffer1M_1;
    if(dwSignature == MFCPREFETCH_COMPRESSED_MAGIC) {
        // file is compressed - uncompress it
        cbUncompressed = *(PDWORD)(ctx->pbBuffer1M_1 + 4);
        if(!H->vmm.fn.RtlDecompressBufferExOpt) { return; }
        if(cbUncompressed > MFCPREFETCH_MAXSIZE) { return; }
        // shrink file:
        // often the file size is incorrect and is zero-padded at the end.
        // this will cause the decompression to fail so account for it.
        if(cbFile > cbUncompressed) {
            cbFile = cbUncompressed;
            while((cbFile > 0x10) && (ctx->pbBuffer1M_1[cbFile - 1] == 0)) {
                cbFile--;
            }
        }
        // decompress:
        nt = H->vmm.fn.RtlDecompressBufferExOpt(COMPRESSION_FORMAT_XPRESS_HUFF, ctx->pbPf, cbUncompressed, ctx->pbBuffer1M_1 + 8, cbFile - 8, &ctx->cbPf, ctx->pbBuffer1M_2);
        if((nt != STATUS_SUCCESS) || (ctx->cbPf < 0x100)) { return; }
    } else {
        // file is not compressed
        ctx->cbPf = min(MFCPREFETCH_MAXSIZE, cbFile);
        memcpy(ctx->pbPf, ctx->pbBuffer1M_1, ctx->cbPf);
    }
    // 3: verify signature:
    dwVersion = *(PDWORD)ctx->pbPf;
    dwSignature2 = *(PDWORD)(ctx->pbPf + 4);
    if(dwSignature2 != MFCPREFETCH_MAGIC) { return; }
    // 4: dispatch to record parser:
    if((dwVersion == MFCPREFETCH_VERSION_WIN10) || (dwVersion == MFCPREFETCH_VERSION_WIN8)) {
        MFcPrefetch_ParseSingle_V26_V30(H, ctx->pmPf, ctx->psm, ctx->psDuplicate, pFile, cbFile, ctx->pbPf, ctx->cbPf, &ctx->cFileMetrics);
    }
}

/*
* Object manager callback function for object cleanup tasks.
* -- pOb
*/
VOID MFcPrefetch_CloseObCallback(_In_ PVMMOB_MAP_PREFETCH pOb)
{
    LocalFree(pOb->pbMultiText);
}

/*
* Create a new prefetch map (single-threaded context!)
* CALLER DECREF: return
* -- H
* -- return
*/
_Success_(return != NULL)
PVMMOB_MAP_PREFETCH MFcPrefetch_Initialize(_In_ VMM_HANDLE H)
{
    DWORD i, cMap, cbFileMetrics, cbMap, oFileMetrics = 0;
    POB_MAP pmObFiles = NULL;
    POB_VMMWINOBJ_FILE pObFile = NULL;
    PMFCPREFETCH_INIT_CONTEXT ctx = NULL;
    PVMMOB_MAP_PREFETCH pObMap = NULL;
    PVMM_MAP_PREFETCH_FILEMETRICSENTRY pFileMetrics;
    PVMM_MAP_PREFETCHENTRY peSrc, peDst;
    // 1: initialize:
    if(!(ctx = LocalAlloc(LMEM_ZEROINIT, sizeof(MFCPREFETCH_INIT_CONTEXT)))) { goto fail; }
    ctx->psm = ObStrMap_New(H, OB_STRMAP_FLAGS_CASE_SENSITIVE);
    ctx->pmPf = ObMap_New(H, OB_MAP_FLAGS_OBJECT_LOCALFREE);
    ctx->psDuplicate = ObSet_New(H);
    if(!ctx->psm || !ctx->pmPf || !ctx->psDuplicate) { goto fail; }
    // 2: iterate over all prefetch files:
    if(!VmmWinObjFile_GetAll(H, &pmObFiles)) { goto fail; }
    while((ObMap_Size(ctx->pmPf) < MFCPREFETCH_MAX_PREFETCHES) && (pObFile = ObMap_GetNext(pmObFiles, pObFile))) {
        MFcPrefetch_ParseSingle(H, ctx, pObFile);
    }
    Ob_DECREF_NULL(&pObFile);
    // 3: alloc result map:
    cMap = ObMap_Size(ctx->pmPf);
    cbMap = sizeof(VMMOB_MAP_PREFETCH) + cMap * sizeof(VMM_MAP_PREFETCHENTRY);
    cbFileMetrics = ctx->cFileMetrics * sizeof(VMM_MAP_PREFETCH_FILEMETRICSENTRY);
    pObMap = Ob_AllocEx(H, OB_TAG_MAP_PREFETCH, 0, cbMap + cbFileMetrics, (OB_CLEANUP_CB)MFcPrefetch_CloseObCallback, NULL);
    if(!pObMap) { goto fail; }
    pFileMetrics = (PVMM_MAP_PREFETCH_FILEMETRICSENTRY)(((PBYTE)pObMap) + cbMap);
    // 3: create result map:
    ObMap_SortEntryIndexByKey(ctx->pmPf);
    ObStrMap_FinalizeAllocU_DECREF_NULL(&ctx->psm, &pObMap->pbMultiText, &pObMap->cbMultiText);
    pObMap->cMap = cMap;
    for(i = 0; i < cMap; i++) {
        peSrc = ObMap_GetByIndex(ctx->pmPf, i);
        peDst = &pObMap->pMap[i];
        memcpy(peDst, peSrc, sizeof(VMM_MAP_PREFETCHENTRY));
        memcpy(pFileMetrics + oFileMetrics, peSrc->pFileMetrics, peSrc->cFileMetrics * sizeof(VMM_MAP_PREFETCH_FILEMETRICSENTRY));
        peDst->pFileMetrics = pFileMetrics + oFileMetrics;
        oFileMetrics += peSrc->cFileMetrics;
    }
fail:
    if(ctx) {
        Ob_DECREF(ctx->psm);
        Ob_DECREF(ctx->pmPf);
        Ob_DECREF(ctx->psDuplicate);
    }
    Ob_DECREF(pmObFiles);
    return pObMap;
}

/*
* Retrieve the prefetch map:
* CALLER DECREF: return
* -- H
* -- pContainer
* -- return
*/
_Success_(return != NULL)
PVMMOB_MAP_PREFETCH MFcPrefetch_GetMap(_In_ VMM_HANDLE H, _In_ POB_CONTAINER pContainer)
{
    static SRWLOCK LockSRW = SRWLOCK_INIT;
    PVMMOB_MAP_PREFETCH pObMap = NULL;
    if((pObMap = ObContainer_GetOb(pContainer))) { return pObMap; }
    AcquireSRWLockExclusive(&LockSRW);
    pObMap = ObContainer_GetOb(pContainer);
    if(!pObMap) {
        pObMap = MFcPrefetch_Initialize(H);
        if(!pObMap) {
            pObMap = Ob_AllocEx(H, OB_TAG_MAP_PREFETCH, 0, sizeof(VMMOB_MAP_PREFETCH), NULL, NULL);
        }
        ObContainer_SetOb(pContainer, pObMap);
    }
    ReleaseSRWLockExclusive(&LockSRW);
    return pObMap;
}



//------------------------------------------------------------------------------
// Forensic module functions:
//------------------------------------------------------------------------------

#define MFCPREFETCH_LINELENGTH              299ULL
#define MFCPREFETCH_LINEHEADER              "   # Process                          RunCount   #Files PrefetchFile                                RunTime1                 RunTime2                 RunTime3                 RunTime4                 RunTime5                 RunTime6                 RunTime7                 RunTime8"

#define MFCPREFETCH_FILELIST_LINELENGTH     300ULL
#define MFCPREFETCH_FILELIST_LINEHEADER     "   # FileName                                                         Volume                           Path"

/*
* Generate a single line in the file: 00-prefetch-summary.txt
*/
VOID MFcPrefetch_ReadLine_CB(_In_ VMM_HANDLE H, _In_ PVOID pv, _In_ DWORD cbLineLength, _In_ DWORD ie, _In_ PVMM_MAP_PREFETCHENTRY pe, _Out_writes_(cbLineLength + 1) LPSTR szu8)
{
    DWORD i;
    CHAR szTime[8][24];
    for(i = 0; i < 8; i++) {
        Util_FileTime2String(pe->ftRunTimes[i], szTime[i]);
    }
    Util_usnprintf_ln(szu8, cbLineLength,
        "%04x %-32.32s %8i %8i %-42.42s  %s  %s  %s  %s  %s  %s  %s  %s",
        ie,
        pe->uszExecutableFileName,
        pe->cRunCount,
        pe->cFileMetrics,
        pe->uszPrefetchFileName,
        szTime[0], szTime[1], szTime[2], szTime[3], szTime[4], szTime[5], szTime[6], szTime[7]
    );
}

/*
* Generate a single line in the <prefetchfile>.txt file list
*/
VOID MFcPrefetch_FileList_ReadLine_CB(_In_ VMM_HANDLE H, _In_ PVOID pv, _In_ DWORD cbLineLength, _In_ DWORD ie, _In_ PVMM_MAP_PREFETCH_FILEMETRICSENTRY pe, _Out_writes_(cbLineLength + 1) LPSTR szu8)
{
    Util_usnprintf_ln(szu8, cbLineLength,
        "%04x %-64.64s %-32.32s %s",
        ie,
        pe->uszFileName,
        pe->uszVolume,
        pe->uszPath
    );
}

NTSTATUS MFcPrefetch_Read(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_CONTEXT ctxP, _Out_writes_to_(cb, *pcbRead) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset)
{
    NTSTATUS nt = VMMDLL_STATUS_FILE_INVALID;
    PVMMOB_MAP_PREFETCH pObPfMap = NULL;
    DWORD idx, cbFile;
    PBYTE pbFile = NULL;
    if(!(pObPfMap = MFcPrefetch_GetMap(H, (POB_CONTAINER)ctxP->ctxM))) { goto finish; }
    if(CharUtil_StrEquals(ctxP->uszPath, "00-prefetch-summary.txt", TRUE)) {
        nt = Util_VfsLineFixed_Read(
            H, (UTIL_VFSLINEFIXED_PFN_CB)MFcPrefetch_ReadLine_CB, NULL, MFCPREFETCH_LINELENGTH, MFCPREFETCH_LINEHEADER,
            pObPfMap->pMap, pObPfMap->cMap, sizeof(VMM_MAP_PREFETCHENTRY),
            pb, cb, pcbRead, cbOffset
        );
        goto finish;
    }
    idx = (DWORD)Util_GetNumericA(ctxP->uszPath);
    if(idx >= pObPfMap->cMap) { goto finish; }
    if(CharUtil_StrEndsWith(ctxP->uszPath, ".txt", TRUE)) {
        nt = Util_VfsLineFixed_Read(
            H, (UTIL_VFSLINEFIXED_PFN_CB)MFcPrefetch_FileList_ReadLine_CB, NULL, MFCPREFETCH_FILELIST_LINELENGTH, MFCPREFETCH_FILELIST_LINEHEADER,
            pObPfMap->pMap[idx].pFileMetrics, pObPfMap->pMap[idx].cFileMetrics, sizeof(VMM_MAP_PREFETCH_FILEMETRICSENTRY),
            pb, cb, pcbRead, cbOffset
        );
        goto finish;
    }
    if(CharUtil_StrEndsWith(ctxP->uszPath, ".pf", TRUE)) {
        cbFile = pObPfMap->pMap[idx].cbPrefetchFileSize;
        if((pbFile = LocalAlloc(LMEM_ZEROINIT, cbFile))) {
            VmmWinObjFile_ReadFromObjectAddress(H, pObPfMap->pMap[idx].vaPrefetchFile, 0, pbFile, cbFile, 0, VMMWINOBJ_FILE_TP_DEFAULT);
            nt = Util_VfsReadFile_FromPBYTE(pbFile, cbFile, pb, cb, pcbRead, cbOffset);
            LocalFree(pbFile); pbFile = NULL;
            goto finish;
        }
    }
finish:
    Ob_DECREF(pObPfMap);
    return nt;
}

BOOL MFcPrefetch_List(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_CONTEXT ctxP, _Inout_ PHANDLE pFileList)
{
    PVMMOB_MAP_PREFETCH pObPfMap = NULL;
    CHAR szFileName[0x100];
    DWORD i;
    VMMDLL_VFS_FILELIST_EXINFO ExInfo = { 0 };
    pObPfMap = MFcPrefetch_GetMap(H, (POB_CONTAINER)ctxP->ctxM);
    if(!pObPfMap) { return FALSE; }
    VMMDLL_VfsList_AddFile(pFileList, "00-prefetch-summary.txt", UTIL_VFSLINEFIXED_LINECOUNT(H, pObPfMap->cMap) * MFCPREFETCH_LINELENGTH, NULL);
    ExInfo.dwVersion = VMMDLL_VFS_FILELIST_EXINFO_VERSION;
    for(i = 0; i < pObPfMap->cMap; i++) {
        ExInfo.qwLastWriteTime = pObPfMap->pMap[i].ftRunTimes[0];
        _snprintf_s(szFileName, sizeof(szFileName), _TRUNCATE, "%i-%.200s", i, pObPfMap->pMap[i].uszPrefetchFileName);
        VMMDLL_VfsList_AddFile(pFileList, szFileName, pObPfMap->pMap[i].cbPrefetchFileSize, &ExInfo);
        _snprintf_s(szFileName, sizeof(szFileName), _TRUNCATE, "%i-%.200s.txt", i, pObPfMap->pMap[i].uszPrefetchFileName);
        VMMDLL_VfsList_AddFile(pFileList, szFileName, UTIL_VFSLINEFIXED_LINECOUNT(H, pObPfMap->pMap[i].cFileMetrics) * MFCPREFETCH_FILELIST_LINELENGTH, &ExInfo);
    }
    Ob_DECREF(pObPfMap);
    return TRUE;
}

VOID MFcPrefetch_FcLogJSON(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_CONTEXT ctxP, _In_ VOID(*pfnLogJSON)(_In_ VMM_HANDLE H, _In_ PVMMDLL_FORENSIC_JSONDATA pData))
{
    DWORD i, j;
    CHAR szTime[8][24];
    CHAR usz[1024];
    PVMM_MAP_PREFETCHENTRY pe;
    PVMMDLL_FORENSIC_JSONDATA pd = NULL;
    PVMMOB_MAP_PREFETCH pObPfMap = NULL;
    if(!(pObPfMap = MFcPrefetch_GetMap(H, (POB_CONTAINER)ctxP->ctxM))) { goto fail; }
    if(!(pd = LocalAlloc(LMEM_ZEROINIT, sizeof(VMMDLL_FORENSIC_JSONDATA)))) { goto fail; }
    FC_JSONDATA_INIT_PIDTYPE(pd, 0, "prefetch");
    for(i = 0; i < pObPfMap->cMap; i++) {
        pe = &pObPfMap->pMap[i];
        pd->i = i;
        pd->qwNum[0] = pe->cRunCount;
        for(j = 0; j < 8; j++) {
            if(pe->ftRunTimes[j]) {
                Util_FileTime2String(pe->ftRunTimes[j], szTime[j]);
            } else {
                szTime[j][0] = 0;
            }
        }
        _snprintf_s(usz, sizeof(usz), _TRUNCATE, "run_count:[%i] file:[%s] run_times:[%s  %s  %s  %s  %s  %s  %s  %s]",
            pe->cRunCount,
            pe->uszPrefetchFileName,
            szTime[0], szTime[1], szTime[2], szTime[3], szTime[4], szTime[5], szTime[6], szTime[7]
        );
        pd->usz[0] = pe->uszExecutableFileName;
        pd->usz[1] = usz;
        pfnLogJSON(H, pd);
    }
fail:
    Ob_DECREF(pObPfMap);
    LocalFree(pd);
}

VOID MFcPrefetch_FcTimeline(
    _In_ VMM_HANDLE H,
    _In_opt_ PVOID ctxfc,
    _In_ HANDLE hTimeline,
    _In_ VOID(*pfnAddEntry)(_In_ VMM_HANDLE H, _In_ HANDLE hTimeline, _In_ QWORD ft, _In_ DWORD dwAction, _In_ DWORD dwPID, _In_ DWORD dwData32, _In_ QWORD qwData64, _In_ LPCSTR uszText),
    _In_ VOID(*pfnEntryAddBySql)(_In_ VMM_HANDLE H, _In_ HANDLE hTimeline, _In_ DWORD cEntrySql, _In_ LPCSTR *pszEntrySql)
) {
    DWORD i, j;
    CHAR usz[1024];
    PVMM_MAP_PREFETCHENTRY pe;
    PVMMOB_MAP_PREFETCH pObPfMap = NULL;
    if(ctxfc && (pObPfMap = MFcPrefetch_GetMap(H, (POB_CONTAINER)ctxfc))) {
        for(i = 0; i < pObPfMap->cMap; i++) {
            pe = &pObPfMap->pMap[i];
            for(j = 0; j < 8; j++) {
                if(pe->ftRunTimes[j]) {
                    _snprintf_s(usz, sizeof(usz), _TRUNCATE, "%-32s - run_count:%-4i file:[%s]",
                        pe->uszExecutableFileName,
                        pe->cRunCount,
                        pe->uszPrefetchFileName
                    );
                    pfnAddEntry(H, hTimeline, pe->ftRunTimes[j], FC_TIMELINE_ACTION_CREATE, 0, 0, 0, usz);
                }
            }
        }
        Ob_DECREF(pObPfMap);
    }
}

VOID MFcPrefetch_FcLogCSV(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_CONTEXT ctxP, _In_ VMMDLL_CSV_HANDLE hCSV)
{
    DWORD i;
    PVMM_MAP_PREFETCHENTRY pe;
    PVMMOB_MAP_PREFETCH pObPfMap = NULL;
    if(!ctxP->pProcess && ctxP->ctxM && (pObPfMap = MFcPrefetch_GetMap(H, (POB_CONTAINER)ctxP->ctxM))) {
        for(i = 0; i < pObPfMap->cMap; i++) {
            pe = &pObPfMap->pMap[i];
            FcCsv_Reset(hCSV);
            FcFileAppend(H, "prefetch.csv", "%s,%u,%u,%s,%s,%s,%s,%s,%s,%s,%s,%s,%llx\n",
                pe->uszExecutableFileName,
                pe->cRunCount,
                pe->cFileMetrics,
                pe->uszPrefetchFileName,
                FcCsv_FileTime(hCSV, pe->ftRunTimes[0]),
                FcCsv_FileTime(hCSV, pe->ftRunTimes[1]),
                FcCsv_FileTime(hCSV, pe->ftRunTimes[2]),
                FcCsv_FileTime(hCSV, pe->ftRunTimes[3]),
                FcCsv_FileTime(hCSV, pe->ftRunTimes[4]),
                FcCsv_FileTime(hCSV, pe->ftRunTimes[5]),
                FcCsv_FileTime(hCSV, pe->ftRunTimes[6]),
                FcCsv_FileTime(hCSV, pe->ftRunTimes[7]),
                pe->vaPrefetchFile
            );
        }
        Ob_DECREF(pObPfMap);
    }
}

PVOID MFcPrefetch_FcInitialize(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_CONTEXT ctxP)
{
    FcFileAppend(H, "prefetch.csv", MFCPREFETCH_CSV);
    return ctxP->ctxM;
}

VOID MFcPrefetch_Close(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_CONTEXT ctxP)
{
    Ob_DECREF((POB_CONTAINER)ctxP->ctxM);
}

VOID MFcPrefetch_Notify(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_CONTEXT ctxP, _In_ DWORD fEvent, _In_opt_ PVOID pvEvent, _In_opt_ DWORD cbEvent)
{
    if((fEvent == VMMDLL_PLUGIN_NOTIFY_FORENSIC_INIT_COMPLETE) && ObContainer_Exists((POB_CONTAINER)ctxP->ctxM)) {
        PluginManager_SetVisibility(H, TRUE, "\\forensic\\prefetch", TRUE);
    }
}

VOID M_FcPrefetch_Initialize(_In_ VMM_HANDLE H, _Inout_ PVMMDLL_PLUGIN_REGINFO pRI)
{
    if((pRI->magic != VMMDLL_PLUGIN_REGINFO_MAGIC) || (pRI->wVersion != VMMDLL_PLUGIN_REGINFO_VERSION)) { return; }
    if((pRI->tpSystem != VMM_SYSTEM_WINDOWS_64) && (pRI->tpSystem != VMM_SYSTEM_WINDOWS_32)) { return; }
    if(pRI->sysinfo.dwVersionBuild < 9200) { return; }                          // only win8 and later supported
    if(!(pRI->reg_info.ctxM = (PVMMDLL_PLUGIN_INTERNAL_CONTEXT)ObContainer_New())) { return; }
    strcpy_s(pRI->reg_info.uszPathName, 128, "\\forensic\\prefetch");           // module name
    pRI->reg_info.fRootModule = TRUE;                                           // module shows in root directory
    pRI->reg_info.fRootModuleHidden = TRUE;                                     // module hidden by default
    pRI->reg_fn.pfnList = MFcPrefetch_List;
    pRI->reg_fn.pfnRead = MFcPrefetch_Read;
    pRI->reg_fn.pfnNotify = MFcPrefetch_Notify;
    pRI->reg_fn.pfnClose = MFcPrefetch_Close;
    pRI->reg_fnfc.pfnInitialize = MFcPrefetch_FcInitialize;
    pRI->reg_fnfc.pfnTimeline = MFcPrefetch_FcTimeline;                         // Forensic timelining supported
    pRI->reg_fnfc.pfnLogJSON = MFcPrefetch_FcLogJSON;                           // JSON log function supported
    pRI->reg_fnfc.pfnLogCSV = MFcPrefetch_FcLogCSV;                             // CSV log function supported
    memcpy(pRI->reg_info.sTimelineNameShort, "PREF", 5);
    strncpy_s(pRI->reg_info.uszTimelineFile, 32, "timeline_prefetch", _TRUNCATE);
    pRI->pfnPluginManager_Register(H, pRI);
}
