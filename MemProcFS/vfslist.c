// vfslist.h : definitions related to vfs directory listings.
//
// (c) Ulf Frisk, 2021
// Author: Ulf Frisk, pcileech@frizk.net
//
#include "vfs.h"
#include "ob/ob.h"

//-----------------------------------------------------------------------------
// VFS LIST FUNCTIONALITY BELOW:
//-----------------------------------------------------------------------------

typedef struct tdVFSLIST_CONTEXT {
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

VOID VfsList_AddDirectoryFileInternal(_Inout_ PVFSLIST_DIRECTORY pFileList, _In_ DWORD dwFileAttributes, _In_ FILETIME ftCreationTime, _In_ FILETIME ftLastAccessTime, _In_ FILETIME ftLastWriteTime, _In_ DWORD nFileSizeHigh, _In_ DWORD nFileSizeLow, _In_ LPSTR uszName)
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
    CharUtil_UtoW(uszName, -1, (PBYTE)pFindData->cFileName, sizeof(pFindData->cFileName), NULL, NULL, CHARUTIL_FLAG_TRUNCATE_ONFAIL_NULLSTR | CHARUTIL_FLAG_STR_BUFONLY);
    while(i < MAX_PATH && (c = pFindData->cFileName[i])) {
        pFindData->cFileName[i++] = (c < 128) ? VFSLIST_ASCII[c] : c;
    }
    pFindData->cFileName[min(i, MAX_PATH - 1)] = 0;
}

VOID VfsList_AddFile(_Inout_ HANDLE hFileList, _In_ LPSTR uszName, _In_ QWORD cb, _In_opt_ PVMMDLL_VFS_FILELIST_EXINFO pExInfo)
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
            uszName
        );
    }
}

VOID VfsList_AddDirectory(_Inout_ HANDLE hFileList, _In_ LPSTR uszName, _In_opt_ PVMMDLL_VFS_FILELIST_EXINFO pExInfo)
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
            uszName
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
    VMMDLL_VFS_FILELIST2 VfsFileList;
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
    if(MemProcFS_VfsListW(wszPath, &VfsFileList)) {
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
* -- dwCacheValidMs
* -- cCacheMaxEntries
* -- return
*/
_Success_(return)
BOOL VfsList_Initialize(_In_ DWORD dwCacheValidMs, _In_ DWORD cCacheMaxEntries)
{
    SYSTEMTIME SystemTimeNow;
    if(!(g_ctxVfsList.pcm = ObCacheMap_New(cCacheMaxEntries, VfsList_ValidEntry, OB_CACHEMAP_FLAGS_OBJECT_OB))) { return FALSE; }
    g_ctxVfsList.qwCacheValidMs = dwCacheValidMs;
    GetSystemTime(&SystemTimeNow);
    SystemTimeToFileTime(&SystemTimeNow, &g_ctxVfsList.ftDefaultTime);
    return TRUE;
}
