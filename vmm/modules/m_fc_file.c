// m_fc_file.c : files forensic module.
//
// REQUIRE: FORENSIC SUB-SYSTEM INIT.
//
// (c) Ulf Frisk, 2020-2025
// Author: Ulf Frisk, pcileech@frizk.net
//

#include "modules.h"
#include "../vmmwinobj.h"

LPCSTR szMFCFILE_README =
"The files module tries to recover files from file handles in the system and  \n" \
"display them in a directory structure. File handles that cannot be recovered \n" \
"are not shown.                                                               \n" \
"Files that are shown may be partly or completely corrupt.                    \n" \
"---                                                                          \n" \
"In addition to the files recovered by this module there may be smaller files \n" \
"in the NTFS MFT in the '/forensic/ntfs' directory that are not shown here.   \n" \
"---                                                                          \n" \
"Documentation: https://github.com/ufrisk/MemProcFS/wiki/FS_Forensic_Files    \n";

static LPSTR MMFCFILE_CSV_FILES = "Object,Type,SignInfo,Size,File,Path\n";

typedef struct tdMFCFILE_ENTRY {
    LPSTR uszName;
    QWORD va;
    BOOL fDuplicate;
    union {
        QWORD cb;
        struct {
            DWORD cChild;
            DWORD cChildMax;
        };
    };
    struct tdMFCFILE_ENTRY *pChild[];
} MFCFILE_ENTRY, *PMFCFILE_ENTRY;

typedef struct tdMFCFILE_CONTEXT {
    BOOL fValid;
    BOOL fTry;
    SRWLOCK LockSRW;
    POB_MEMFILE pmfFiles;
    // file hierarchy below:
    PMFCFILE_ENTRY pRoot;
    POB_MAP pmDirs;                     // k = hash of path, v = PMFCFILE_ENTRY
    PBYTE pbMultiStr;
    DWORD cbMultiStr;
    // init object below:
    struct {
        POB_MAP pmFileObj;              // k = _FILE_OBJECT va, v = POB_VMMWINOBJ_FILE
        SIZE_T _cboFileEntryBuffer;     // only used during initialization
        DWORD iFileEntry;
    } Init;
} MFCFILE_CONTEXT, *PMFCFILE_CONTEXT;

VOID MFcFile_ContextInitialize_1_FileEntryAlloc_DirInit_FilterCount(POB_COUNTER pcObDirs, _In_ QWORD k, _In_ POB_VMMWINOBJ_FILE v)
{
    QWORD qwHash;
    CHAR uszPath[MAX_PATH * 2];
    if(CharUtil_UtoU(v->uszPath, -1, (PBYTE)uszPath, sizeof(uszPath), NULL, NULL, CHARUTIL_FLAG_STR_BUFONLY | CHARUTIL_FLAG_TRUNCATE)) {
        while(CharUtil_PathSplitLastInPlace(uszPath) && uszPath[0]) {
            qwHash = CharUtil_HashPathFsU(uszPath);
            if(ObCounter_Inc(pcObDirs, qwHash) > 1) {
                return;             // entry/dir in already existing directory -> return
            }
        }
        ObCounter_Inc(pcObDirs, 1);     // entry/dir in root directory -> return
    }
}

_Success_(return)
BOOL MFcFile_ContextInitialize_1_FileEntryAlloc_DirInit(_In_ VMM_HANDLE H, _In_ PMFCFILE_CONTEXT ctx)
{
    QWORD c, h;
    POB_MAP pmObDirs = NULL;
    POB_COUNTER pcObDirs = NULL;
    PBYTE pbFileEntryBuffer = NULL;
    SIZE_T cboFileEntryBuffer = 0;
    PMFCFILE_ENTRY pDir, pDirRoot;
    // count #directory entries and #files/dirs in each directory.
    if(!(pmObDirs = ObMap_New(H, 0))) { goto fail; }
    if(!(pcObDirs = ObCounter_New(H, 0))) { goto fail; }
    ObCounter_Inc(pcObDirs, 1);     // root directory
    ObMap_Filter(ctx->Init.pmFileObj, pcObDirs, (OB_MAP_FILTER_PFN_CB)MFcFile_ContextInitialize_1_FileEntryAlloc_DirInit_FilterCount);
    // allocate file entry structure
    if(!(pbFileEntryBuffer = LocalAlloc(LMEM_ZEROINIT, (SIZE_T)ObCounter_CountAll(pcObDirs) * (sizeof(MFCFILE_ENTRY) + sizeof(PMFCFILE_ENTRY))))) { goto fail; }
    // root directory allocation:
    h = 1;
    c = ObCounter_Del(pcObDirs, 1);
    pDirRoot = (PMFCFILE_ENTRY)pbFileEntryBuffer;
    cboFileEntryBuffer += sizeof(MFCFILE_ENTRY) + (SIZE_T)c * sizeof(PMFCFILE_ENTRY);
    pDirRoot->uszName = "ROOT";
    pDirRoot->cChildMax = (DWORD)c;
    ObMap_Push(pmObDirs, h, pDirRoot);
    // sub-directory allocations:
    while((c = ObCounter_PopWithKey(pcObDirs, &h))) {
        pDir = (PMFCFILE_ENTRY)(pbFileEntryBuffer + cboFileEntryBuffer);
        cboFileEntryBuffer += sizeof(MFCFILE_ENTRY) + (SIZE_T)c * sizeof(PMFCFILE_ENTRY);
        pDir->cChildMax = (DWORD)c;
        ObMap_Push(pmObDirs, h, pDir);
    }
    ctx->pRoot = pDirRoot;      // ctx overtakes alloc reference
    ctx->pmDirs = pmObDirs;     // ctx overtakes object reference
    ctx->Init._cboFileEntryBuffer = cboFileEntryBuffer;
    Ob_DECREF(pcObDirs);
    return TRUE;
fail:
    Ob_DECREF(pcObDirs);
    Ob_DECREF(pmObDirs);
    return FALSE;
}

_Success_(return)
BOOL MFcFile_ContextInitialize_2_FillFiles(_In_ VMM_HANDLE H, _In_ PMFCFILE_CONTEXT ctx)
{
    BOOL fResult = FALSE;
    QWORD qwHash;
    CHAR uszPath[MAX_PATH * 2];
    LPSTR uszName;
    POB_STRMAP psmOb = NULL;
    POB_VMMWINOBJ_FILE pObFileObj = NULL;
    PMFCFILE_ENTRY pDir, pEntry;
    SIZE_T cboFileEntryBuffer = ctx->Init._cboFileEntryBuffer;
    if(!(psmOb = ObStrMap_New(H, OB_STRMAP_FLAGS_CASE_SENSITIVE | OB_STRMAP_FLAGS_STR_ASSIGN_TEMPORARY))) { goto fail; }
    while((pObFileObj = ObMap_GetNext(ctx->Init.pmFileObj, pObFileObj))) {
        if(CharUtil_UtoU(pObFileObj->uszPath, -1, (PBYTE)uszPath, sizeof(uszPath), NULL, NULL, CHARUTIL_FLAG_STR_BUFONLY | CHARUTIL_FLAG_TRUNCATE)) {
            // fetch and set file entry:
            pEntry = (PMFCFILE_ENTRY)((PBYTE)ctx->pRoot + cboFileEntryBuffer);
            cboFileEntryBuffer += sizeof(MFCFILE_ENTRY);
            pEntry->va = pObFileObj->va;
            pEntry->cb = pObFileObj->cb;
            pEntry->fDuplicate = pObFileObj->fDuplicate;
            ObStrMap_PushPtrUU(psmOb, pObFileObj->uszName, &pEntry->uszName, NULL);
            // fetch and set parent directory entry (recursively):
            uszName = CharUtil_PathSplitLastInPlace(uszPath);
            while(TRUE) {
                if(!uszName || (0 == uszPath[0])) {
                    ctx->pRoot->pChild[ctx->pRoot->cChild++] = pEntry;
                    break;
                }
                qwHash = CharUtil_HashPathFsU(uszPath);
                pDir = ObMap_GetByKey(ctx->pmDirs, qwHash);
                if(!pDir) {
                    goto fail;
                }
                pDir->pChild[pDir->cChild++] = pEntry;
                if(pDir->cChild > 1) { break; }
                uszName = CharUtil_PathSplitLastInPlace(uszPath);
                ObStrMap_PushPtrUU(psmOb, (uszName ? uszName : uszPath), &pDir->uszName, NULL);
                pEntry = pDir;
            }
        }
    }
    if(!ObStrMap_FinalizeAllocU_DECREF_NULL(&psmOb, &ctx->pbMultiStr, &ctx->cbMultiStr)) { goto fail; }
    fResult = TRUE;
fail:
    Ob_DECREF(pObFileObj);
    Ob_DECREF(psmOb);
    return fResult;
}

VOID MFcFile_ContextInitialize_3_GenerateSummaryFile(_In_ VMM_HANDLE H, _In_ PMFCFILE_CONTEXT ctx, PMFCFILE_ENTRY pEntry)
{
    DWORD i;
    CHAR szType[5] = { 0 };
    POB_VMMWINOBJ_FILE pObFileObj = NULL;
    // file:
    if(pEntry->va && (pObFileObj = ObMap_GetByKey(ctx->Init.pmFileObj, pEntry->va))) {
        szType[0] = pObFileObj->pData ? 'D' : '-';
        szType[1] = pObFileObj->pCache ? 'C' : '-';
        szType[2] = pObFileObj->pImage ? 'I' : '-';
        szType[3] = pObFileObj->fDuplicate ? 'X' : '-';
        ObMemFile_AppendStringEx(ctx->pmfFiles, "%04x %016llx %s %10llu %-64.64s %s\n",
            ctx->Init.iFileEntry++,
            pObFileObj->va,
            szType,
            pObFileObj->cb,
            pObFileObj->uszName,
            pObFileObj->uszPath
        );
        Ob_DECREF(pObFileObj);
        return;
    }
    // directory / subdirectory:
    for(i = 0; i < pEntry->cChild; i++) {
        if(!pEntry->pChild[i]->va) {
            MFcFile_ContextInitialize_3_GenerateSummaryFile(H, ctx, pEntry->pChild[i]);
        }
    }
    // directory / file:
    for(i = 0; i < pEntry->cChild; i++) {
        if(pEntry->pChild[i]->va) {
            MFcFile_ContextInitialize_3_GenerateSummaryFile(H, ctx, pEntry->pChild[i]);
        }
    }
}

_Success_(return)
BOOL MFcFile_ContextInitialize(_In_ VMM_HANDLE H, _In_opt_ PMFCFILE_CONTEXT ctx)
{
    if(!ctx) { return FALSE; }
    if(ctx->fValid) { return TRUE; }
    AcquireSRWLockExclusive(&ctx->LockSRW);
    if(ctx->fValid || ctx->fTry) { goto fail; }
    ctx->fTry = TRUE;
    if(!VmmWinObjFile_GetAll(H, &ctx->Init.pmFileObj)) { goto fail; }
    ObMap_SortEntryIndexByKey(ctx->Init.pmFileObj);
    if(!MFcFile_ContextInitialize_1_FileEntryAlloc_DirInit(H, ctx)) { goto fail; }
    if(!MFcFile_ContextInitialize_2_FillFiles(H, ctx)) { goto fail; }
    if(!(ctx->pmfFiles = ObMemFile_New(H, H->vmm.pObCacheMapObCompressedShared))) { goto fail; }
    MFcFile_ContextInitialize_3_GenerateSummaryFile(H, ctx, ctx->pRoot);
    ctx->fValid = TRUE;
fail:
    ReleaseSRWLockExclusive(&ctx->LockSRW);
    return ctx->fValid;
}

VOID MFcFile_FcFinalize(_In_ VMM_HANDLE H, _In_opt_ PVOID ctxfc)
{
    PMFCFILE_CONTEXT ctx = (PMFCFILE_CONTEXT)ctxfc;
    MFcFile_ContextInitialize(H, ctx);
    if(ctx) { Ob_DECREF_NULL(&ctx->Init.pmFileObj); }
}

PVOID MFcFile_FcInitialize(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_CONTEXT ctxP)
{
    return ctxP->ctxM;
}

VOID MFcFile_FcLogCSV_DoWork(_In_ VMM_HANDLE H, _In_ PMFCFILE_CONTEXT ctx, PMFCFILE_ENTRY pEntry, _In_ VMMDLL_CSV_HANDLE hCSV)
{
    DWORD i;
    LPCSTR szSign = "";
    CHAR szType[MAX_PATH];
    POB_VMMWINOBJ_FILE pObFileObj = NULL;
    // file:
    if(pEntry->va && (pObFileObj = ObMap_GetByKey(ctx->Init.pmFileObj, pEntry->va))) {
        // type:
        szType[0] = '\0';
        szType[1] = '\0';
        if(pObFileObj->pData) { strcat_s(szType, _countof(szType), ",Data"); }
        if(pObFileObj->pCache) { strcat_s(szType, _countof(szType), ",Cache"); }
        if(pObFileObj->pImage) { strcat_s(szType, _countof(szType), ",Image"); }
        if(pObFileObj->fDuplicate) { strcat_s(szType, _countof(szType), ",Dup"); }
        // sign info:
        if(pObFileObj->pImage && pObFileObj->pImage->_SEGMENT.bImageSigningType && pObFileObj->pImage->_SEGMENT.bImageSigningLevel) {
            szSign = SE_SIGNING_LEVEL_STR[pObFileObj->pImage->_SEGMENT.bImageSigningLevel];
        }
        // csv file append:
        FcCsv_Reset(hCSV);
        FcFileAppend(H, "files.csv", "0x%llx,\"%s\",%s,%llu,%s,%s\n",
            pObFileObj->va,
            szType + 1,
            szSign,
            pObFileObj->cb,
            FcCsv_String(hCSV, pObFileObj->uszName),
            FcCsv_String(hCSV, pObFileObj->uszPath)
        );
        Ob_DECREF(pObFileObj);
        return;
    }
    // directory / subdirectory:
    for(i = 0; i < pEntry->cChild; i++) {
        if(!pEntry->pChild[i]->va) {
            MFcFile_FcLogCSV_DoWork(H, ctx, pEntry->pChild[i], hCSV);
        }
    }
    // directory / file:
    for(i = 0; i < pEntry->cChild; i++) {
        if(pEntry->pChild[i]->va) {
            MFcFile_FcLogCSV_DoWork(H, ctx, pEntry->pChild[i], hCSV);
        }
    }
}

VOID MFcFile_FcLogCSV(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_CONTEXT ctxP, _In_ VMMDLL_CSV_HANDLE hCSV)
{
    PMFCFILE_CONTEXT ctx = NULL;
    if(ctxP->pProcess) { return; }
    if(!(ctx = (PMFCFILE_CONTEXT)ctxP->ctxM)) { return; }
    if(!MFcFile_ContextInitialize(H, ctx)) { return; }
    FcFileAppend(H, "files.csv", "%s", MMFCFILE_CSV_FILES);
    MFcFile_FcLogCSV_DoWork(H, ctx, ctx->pRoot, hCSV);
}

NTSTATUS MFcFile_Read(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_CONTEXT ctxP, _Out_writes_to_(cb, *pcbRead) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset)
{
    POB_VMMWINOBJ_FILE pObFile = NULL;
    LPCSTR uszFile = NULL;
    QWORD va;
    *pcbRead = 0;
    if(CharUtil_StrEquals(ctxP->uszPath, "readme.txt", TRUE)) {
        return Util_VfsReadFile_FromStrA(szMFCFILE_README, pb, cb, pcbRead, cbOffset);
    }
    if(CharUtil_StrEquals(ctxP->uszPath, "files.txt", TRUE)) {
        return ObMemFile_ReadFile(((PMFCFILE_CONTEXT)ctxP->ctxM)->pmfFiles, pb, cb, pcbRead, cbOffset);
    }
    if(CharUtil_StrStartsWith(ctxP->uszPath, "ROOT", TRUE)) {
        uszFile = CharUtil_PathSplitLast(ctxP->uszPath);
        va = strtoull(uszFile, NULL, 16);
        if((pObFile = VmmWinObjFile_GetByVa(H, va))) {
            *pcbRead = VmmWinObjFile_Read(H, pObFile, cbOffset, pb, cb, 0, VMMWINOBJ_FILE_TP_DEFAULT);
            Ob_DECREF(pObFile);
            return *pcbRead ? VMM_STATUS_SUCCESS : VMM_STATUS_END_OF_FILE;
        }
        return VMMDLL_STATUS_FILE_INVALID;
    }
    return VMMDLL_STATUS_FILE_INVALID;
}

BOOL MFcFile_List(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_CONTEXT ctxP, _Inout_ PHANDLE pFileList)
{
    PMFCFILE_CONTEXT ctx = (PMFCFILE_CONTEXT)ctxP->ctxM;
    DWORD i;
    QWORD qwHash;
    LPCSTR uszPath;
    PMFCFILE_ENTRY pDir, pEntry;
    CHAR uszFileName[MAX_PATH];
    if(!ctxP->uszPath[0]) {
        VMMDLL_VfsList_AddDirectory(pFileList, "ROOT", NULL);
        VMMDLL_VfsList_AddFile(pFileList, "files.txt", ObMemFile_Size(ctx->pmfFiles), NULL);
        VMMDLL_VfsList_AddFile(pFileList, "readme.txt", strlen(szMFCFILE_README), NULL);
        return TRUE;
    }
    if(CharUtil_StrStartsWith(ctxP->uszPath, "ROOT", TRUE)) {
        uszPath = CharUtil_PathSplitNext(ctxP->uszPath);
        if(0 == uszPath[0]) {
            qwHash = 1;
        } else {
            qwHash = CharUtil_HashPathFsU(uszPath);
        }
        if((pDir = ObMap_GetByKey(ctx->pmDirs, qwHash))) {
            for(i = 0; i < pDir->cChild; i++) {
                pEntry = pDir->pChild[i];
                if(pEntry->va) {
                    if(!pEntry->fDuplicate) {
                        _snprintf_s(uszFileName, _countof(uszFileName), _TRUNCATE, "%llx-%s", pEntry->va, pEntry->uszName);
                        VMMDLL_VfsList_AddFile(pFileList, uszFileName, pEntry->cb, NULL);
                    }
                } else {
                    if(pEntry->uszName[0]) {
                        VMMDLL_VfsList_AddDirectory(pFileList, pEntry->uszName, NULL);
                    }
                }
            }
        }
        return TRUE;
    }
    return TRUE;
}

VOID MFcFile_Close(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_CONTEXT ctxP)
{
    PMFCFILE_CONTEXT ctx = (PMFCFILE_CONTEXT)ctxP->ctxM;
    if(ctx) {
        Ob_DECREF(ctx->pmfFiles);
        Ob_DECREF(ctx->Init.pmFileObj);
        LocalFree(ctx->pRoot);
        Ob_DECREF(ctx->pmDirs);
        LocalFree(ctx->pbMultiStr);
        LocalFree(ctx);
    }
}

VOID MFcFile_Notify(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_CONTEXT ctxP, _In_ DWORD fEvent, _In_opt_ PVOID pvEvent, _In_opt_ DWORD cbEvent)
{
    PMFCFILE_CONTEXT ctx = (PMFCFILE_CONTEXT)ctxP->ctxM;
    if((fEvent == VMMDLL_PLUGIN_NOTIFY_FORENSIC_INIT_COMPLETE) && ctx->fValid) {
        PluginManager_SetVisibility(H, TRUE, "\\forensic\\files", TRUE);
    }
}

VOID M_FcFile_Initialize(_In_ VMM_HANDLE H, _Inout_ PVMMDLL_PLUGIN_REGINFO pRI)
{
    if((pRI->magic != VMMDLL_PLUGIN_REGINFO_MAGIC) || (pRI->wVersion != VMMDLL_PLUGIN_REGINFO_VERSION)) { return; }
    if((pRI->tpSystem != VMMDLL_SYSTEM_WINDOWS_64) && (pRI->tpSystem != VMMDLL_SYSTEM_WINDOWS_32)) { return; }
    if(!(pRI->reg_info.ctxM = LocalAlloc(LMEM_ZEROINIT, sizeof(MFCFILE_CONTEXT)))) { return; }
    strcpy_s(pRI->reg_info.uszPathName, 128, "\\forensic\\files");              // module name
    pRI->reg_info.fRootModule = TRUE;                                           // module shows in root directory
    pRI->reg_info.fRootModuleHidden = TRUE;                                     // module hidden by default
    pRI->reg_fn.pfnList = MFcFile_List;
    pRI->reg_fn.pfnRead = MFcFile_Read;
    pRI->reg_fn.pfnNotify = MFcFile_Notify;
    pRI->reg_fn.pfnClose = MFcFile_Close;
    pRI->reg_fnfc.pfnInitialize = MFcFile_FcInitialize;
    pRI->reg_fnfc.pfnLogCSV = MFcFile_FcLogCSV;
    pRI->reg_fnfc.pfnFinalize = MFcFile_FcFinalize;
    pRI->pfnPluginManager_Register(H, pRI);
}
