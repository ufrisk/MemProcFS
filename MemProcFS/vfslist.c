// vfslist.h : definitions related to vfs directory listings.
//
// (c) Ulf Frisk, 2021
// Author: Ulf Frisk, pcileech@frizk.net
//
#include "vfs.h"
#include "ob/ob.h"

//-----------------------------------------------------------------------------
// UTILITY FUNCTIONS BELOW:
//-----------------------------------------------------------------------------

VOID Util_SplitPathFile(_Out_writes_(MAX_PATH) PWCHAR wszPath, _Out_ LPWSTR *pwcsFile, _In_ LPCWSTR wcsFileName)
{
    DWORD i, iSplitFilePath = 0;
    wcsncpy_s(wszPath, MAX_PATH, wcsFileName, _TRUNCATE);
    for(i = 0; i < MAX_PATH; i++) {
        if(wszPath[i] == '\\') {
            iSplitFilePath = i;
        }
        if(wszPath[i] == 0) {
            break;
        }
    }
    wszPath[iSplitFilePath] = 0;
    *pwcsFile = wszPath + iSplitFilePath + 1;
}

LPWSTR Util_PathSplit2_ExWCHAR(_In_ LPWSTR wsz, _Out_writes_(cwsz1) LPWSTR wsz1, _In_ DWORD cwsz1)
{
    WCHAR wch;
    DWORD i = 0;
    while((wch = wsz[i]) && (wch != '\\') && (i < cwsz1 - 1)) {
        wsz1[i++] = wch;
    }
    wsz1[i] = 0;
    return wsz[i] ? &wsz[i + 1] : L"";
}

/*
* Hash a string in uppercase.
* -- wsz
* -- return
*/
DWORD Util_HashStringUpperW(_In_opt_ LPWSTR wsz)
{
    WCHAR c;
    DWORD i = 0, dwHash = 0;
    if(!wsz) { return 0; }
    while(TRUE) {
        c = wsz[i++];
        if(!c) { return dwHash; }
        if(c >= 'a' && c <= 'z') {
            c += 'A' - 'a';
        }
        dwHash = ((dwHash >> 13) | (dwHash << 19)) + c;
    }
}

/*
* Hash a path in uppercase.
* -- wszPath
* -- return
*/
QWORD Util_HashPathW(_In_ LPWSTR wszPath)
{
    DWORD dwHashName;
    QWORD qwHashTotal = 0;
    WCHAR wsz1[MAX_PATH];
    while(wszPath && wszPath[0]) {
        wszPath = Util_PathSplit2_ExWCHAR(wszPath, wsz1, _countof(wsz1));
        dwHashName = Util_HashStringUpperW(wsz1);
        qwHashTotal = dwHashName + ((qwHashTotal >> 13) | (qwHashTotal << 51));
    }
    return qwHashTotal;
}

//-----------------------------------------------------------------------------
// VFS LIST FUNCTIONALITY BELOW:
//-----------------------------------------------------------------------------

typedef struct tdVFSLIST_CONTEXT {
    BOOL(*pfnVfsList)(_In_ LPCWSTR wcsPath, _Inout_ PVMMDLL_VFS_FILELIST pFileList);
    QWORD qwCacheValidMs;
    FILETIME ftDefaultTime;
    POB_CACHEMAP pcm;
} VFSLIST_CONTEXT, *PVFSLIST_CONTEXT;

VFSLIST_CONTEXT g_ctxVfsList = { 0 };

#define VFSLIST_CONFIG_FILELIST_ITEMS   12
#define VFSLIST_CONFIG_FILELIST_MAGIC   0x7f646555caffee77

typedef struct tdVFSLIST_DIRECTORY {
    QWORD magic;
    struct tdVFSLIST_DIRECTORY *FLink;
    DWORD cFiles;
    WIN32_FIND_DATAW pFiles[VFSLIST_CONFIG_FILELIST_ITEMS];
} VFSLIST_DIRECTORY, *PVFSLIST_DIRECTORY;

typedef struct tdVFSLISTOB_DIRECTORY {
    OB ObHdr;
    QWORD tc64;
    QWORD qwHash;
    VFSLIST_DIRECTORY Dir;
} VFSLISTOB_DIRECTORY, *PVFSLISTOB_DIRECTORY;

/*
* Object Manager cleanup callback function.
*/
VOID VfsList_CallbackCleanup_ObDirectory(PVFSLISTOB_DIRECTORY pObDir)
{
    PVFSLIST_DIRECTORY pDirNext, pDir = pObDir->Dir.FLink;
    while(pDir) {
        pDirNext = pDir->FLink;
        LocalFree(pDir);
        pDir = pDirNext;
    }
}

#define VFSLIST_ASCII      "________________________________ !_#$%&'()_+,-._0123456789_;_=__@ABCDEFGHIJKLMNOPQRSTUVWXYZ[_]^_`abcdefghijklmnopqrstuvwxyz{_}~ "

VOID VfsList_AddDirectoryFileInternal(_Inout_ PVFSLIST_DIRECTORY pFileList, _In_ DWORD dwFileAttributes, _In_ FILETIME ftCreationTime, _In_ FILETIME ftLastAccessTime, _In_ FILETIME ftLastWriteTime, _In_ DWORD nFileSizeHigh, _In_ DWORD nFileSizeLow, _In_ LPWSTR wszName)
{
    WCHAR c;
    DWORD i = 0;
    PWIN32_FIND_DATAW pFindData;
    // 1: check if required to allocate more FileList items
    while(pFileList->cFiles == VFSLIST_CONFIG_FILELIST_ITEMS) {
        if(pFileList->FLink) {
            pFileList = pFileList->FLink;
            continue;
        }
        pFileList->FLink = LocalAlloc(LMEM_ZEROINIT, sizeof(VFSLIST_DIRECTORY));
        if(!pFileList->FLink) { return; }
        pFileList = pFileList->FLink;
    }
    // 2: locate item to fill into
    pFindData = pFileList->pFiles + pFileList->cFiles;
    pFileList->cFiles++;
    // 3: fill
    pFindData->dwFileAttributes = dwFileAttributes;
    pFindData->ftCreationTime = ftCreationTime;
    pFindData->ftLastAccessTime = ftLastAccessTime;
    pFindData->ftLastWriteTime = ftLastWriteTime;
    pFindData->nFileSizeHigh = nFileSizeHigh;
    pFindData->nFileSizeLow = nFileSizeLow;
    while(i < MAX_PATH && (c = wszName[i])) {
        pFindData->cFileName[i++] = (c < 128) ? VFSLIST_ASCII[c] : c;
    }
    pFindData->cFileName[min(i, MAX_PATH - 1)] = 0;
}

VOID VfsList_AddFile(_Inout_ HANDLE hFileList, _In_ LPWSTR wszName, _In_ QWORD cb, _In_opt_ PVMMDLL_VFS_FILELIST_EXINFO pExInfo)
{
    PVFSLIST_DIRECTORY pFileList2 = (PVFSLIST_DIRECTORY)hFileList;
    BOOL fExInfo = pExInfo && (pExInfo->dwVersion == VMMDLL_VFS_FILELIST_EXINFO_VERSION);
    if(pFileList2 && (pFileList2->magic == VFSLIST_CONFIG_FILELIST_MAGIC)) {
        VfsList_AddDirectoryFileInternal(
            pFileList2,
            FILE_ATTRIBUTE_NOT_CONTENT_INDEXED | ((fExInfo && pExInfo->fCompressed) ? FILE_ATTRIBUTE_COMPRESSED : 0),
            (fExInfo && pExInfo->qwCreationTime) ? pExInfo->ftCreationTime : g_ctxVfsList.ftDefaultTime,
            (fExInfo && pExInfo->qwLastAccessTime) ? pExInfo->ftLastAccessTime : g_ctxVfsList.ftDefaultTime,
            (fExInfo && pExInfo->qwLastWriteTime) ? pExInfo->ftLastWriteTime : g_ctxVfsList.ftDefaultTime,
            (DWORD)(cb >> 32),
            (DWORD)cb,
            wszName
        );
    }
}

VOID VfsList_AddDirectory(_Inout_ HANDLE hFileList, _In_ LPWSTR wszName, _In_opt_ PVMMDLL_VFS_FILELIST_EXINFO pExInfo)
{
    PVFSLIST_DIRECTORY pFileList2 = (PVFSLIST_DIRECTORY)hFileList;
    BOOL fExInfo = pExInfo && (pExInfo->dwVersion == VMMDLL_VFS_FILELIST_EXINFO_VERSION);
    if(pFileList2 && (pFileList2->magic == VFSLIST_CONFIG_FILELIST_MAGIC)) {
        VfsList_AddDirectoryFileInternal(
            pFileList2,
            FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_NOT_CONTENT_INDEXED | ((fExInfo && pExInfo->fCompressed) ? FILE_ATTRIBUTE_COMPRESSED : 0),
            (fExInfo && pExInfo->qwCreationTime) ? pExInfo->ftCreationTime : g_ctxVfsList.ftDefaultTime,
            (fExInfo && pExInfo->qwLastAccessTime) ? pExInfo->ftLastAccessTime : g_ctxVfsList.ftDefaultTime,
            (fExInfo && pExInfo->qwLastWriteTime) ? pExInfo->ftLastWriteTime : g_ctxVfsList.ftDefaultTime,
            0,
            0,
            wszName
        );
    }
}

/*
* Retrieve a directory object given a path name.
* CALLER DECREF: return
* -- wszPath
* -- return
*/
PVFSLISTOB_DIRECTORY VfsList_GetDirectory(_In_ LPWSTR wszPath)
{
    QWORD qwHash;
    PVFSLISTOB_DIRECTORY pObDir;
    VMMDLL_VFS_FILELIST VfsFileList;
    // 1: try fetch from cache:
    qwHash = Util_HashPathW(wszPath);
    if((pObDir = ObCacheMap_GetByKey(g_ctxVfsList.pcm, qwHash))) {
        return pObDir;
    }
    // 2: create new:
    if(!(pObDir = Ob_Alloc('VFSD', LMEM_ZEROINIT, sizeof(VFSLISTOB_DIRECTORY), VfsList_CallbackCleanup_ObDirectory, NULL))) { return NULL; }
    pObDir->Dir.magic = VFSLIST_CONFIG_FILELIST_MAGIC;
    VfsFileList.dwVersion = VMMDLL_VFS_FILELIST_VERSION;
    VfsFileList.h = (HANDLE)&pObDir->Dir;
    VfsFileList.pfnAddFile = VfsList_AddFile;
    VfsFileList.pfnAddDirectory = VfsList_AddDirectory;
    if(ctxVfs->pVmmDll->VfsList(wszPath, &VfsFileList)) {
        pObDir->tc64 = GetTickCount64();
        pObDir->qwHash = qwHash;
        ObCacheMap_Push(g_ctxVfsList.pcm, qwHash, pObDir, 0);
        return pObDir;
    }
    Ob_DECREF(pObDir);
    return NULL;
}

/*
* List a directory using a callback function
* -- wszPath
* -- ctx = optional context to pass along to callback function.
* -- pfnListCallback = callback function called one time per directory entry.
* -- return = TRUE if directory exists, otherwise FALSE.
*/
BOOL VfsList_ListDirectory(_In_ LPWSTR wszPath, _In_opt_ PVOID ctx, _In_opt_ PFN_VFSLIST_CALLBACK pfnListCallback)
{
    DWORD i;
    PVFSLIST_DIRECTORY pDir;
    PVFSLISTOB_DIRECTORY pObDir;
    if(!(pObDir = VfsList_GetDirectory(wszPath))) { return FALSE; }
    if(pfnListCallback) {
        pDir = &pObDir->Dir;
        while(pDir) {
            for(i = 0; i < pDir->cFiles; i++) {
                pfnListCallback(pDir->pFiles + i, ctx);
            }
            pDir = pDir->FLink;
        }
    }
    Ob_DECREF(pObDir);
    return TRUE;
}

/*
* Retrieve information about a single entry inside a directory.
* -- wszPath
* -- wszFile
* -- pFindData
* -- pfPathValid = receives if wszPath is valid or not.
* -- return
*/
_Success_(return)
BOOL VfsList_GetSingle(_In_ LPWSTR wszPath, _In_ LPWSTR wszFile, _Out_ PWIN32_FIND_DATAW pFindData, _Out_ PBOOL pfPathValid)
{
    DWORD i;
    PVFSLIST_DIRECTORY pDir;
    PVFSLISTOB_DIRECTORY pObDir;
    *pfPathValid = FALSE;
    if((pObDir = VfsList_GetDirectory(wszPath))) {
        *pfPathValid = TRUE;
        pDir = &pObDir->Dir;
        while(pDir) {
            for(i = 0; i < pDir->cFiles; i++) {
                if(!wcscmp(wszFile, pDir->pFiles[i].cFileName)) {
                    memcpy(pFindData, pDir->pFiles + i, sizeof(WIN32_FIND_DATAW));
                    Ob_DECREF(pObDir);
                    return TRUE;
                }
            }
            pDir = pDir->FLink;
        }
        Ob_DECREF(pObDir);
    }
    return FALSE;
}

/*
* Evaluate whether a given cachemap entry is still valid time wise.
* -- qwContext
* -- qwKey
* -- pvObject
* -- return
*/
BOOL VfsList_ValidEntry(_Inout_ PQWORD qwContext, _In_ QWORD qwKey, _In_ PVFSLISTOB_DIRECTORY pvObject)
{
    return pvObject->tc64 + g_ctxVfsList.qwCacheValidMs > GetTickCount64();
}

/*
* Close and clean up the vfs list functionality.
*/
void VfsList_Close()
{
    Ob_DECREF(g_ctxVfsList.pcm);
    ZeroMemory(&g_ctxVfsList, sizeof(VFSLIST_CONTEXT));
}

/*
* Initialize the vfs list functionality.
* -- hModuleVmm
* -- dwCacheValidMs
* -- cCacheMaxEntries
* -- return
*/
_Success_(return)
BOOL VfsList_Initialize(_In_ HMODULE hModuleVmm, _In_ DWORD dwCacheValidMs, _In_ DWORD cCacheMaxEntries)
{
    SYSTEMTIME SystemTimeNow;
    if(!(g_ctxVfsList.pcm = ObCacheMap_New(cCacheMaxEntries, VfsList_ValidEntry, OB_CACHEMAP_FLAGS_OBJECT_OB))) { return FALSE; }
    g_ctxVfsList.pfnVfsList = (BOOL(*)(LPCWSTR, PVMMDLL_VFS_FILELIST))GetProcAddress(hModuleVmm, "VMMDLL_VfsList");
    g_ctxVfsList.qwCacheValidMs = dwCacheValidMs;
    GetSystemTime(&SystemTimeNow);
    SystemTimeToFileTime(&SystemTimeNow, &g_ctxVfsList.ftDefaultTime);
    return TRUE;
}
