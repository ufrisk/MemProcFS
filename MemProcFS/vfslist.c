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

/*
* Convert UTF-8 string into a Windows Wide-Char string.
* Function support usz == pbBuffer - usz will then become overwritten.
* CALLER LOCALFREE (if *pusz != pbBuffer): *pusz
* -- usz = the string to convert.
* -- cch = -1 for null-terminated string; or max number of chars (excl. null).
* -- pbBuffer = optional buffer to place the result in.
* -- cbBuffer
* -- pusz = if set to null: function calculate length only and return TRUE.
            result wide-string, either as (*pwsz == pbBuffer) or LocalAlloc'ed
*           buffer that caller is responsible for free.
* -- pcbu = byte length (including terminating null) of wide-char string.
* -- flags = CHARUTIL_FLAG_NONE, CHARUTIL_FLAG_ALLOC or CHARUTIL_FLAG_TRUNCATE
* -- return
*/
_Success_(return)
BOOL CharUtil_UtoW(_In_opt_ LPSTR usz, _In_ DWORD cch, _Maybenull_ _Writable_bytes_(cbBuffer) PBYTE pbBuffer, _In_ DWORD cbBuffer, _Out_opt_ LPWSTR * pwsz, _Out_opt_ PDWORD pcbw, _In_ DWORD flags)
{
    UCHAR c;
    LPWSTR wsz;
    DWORD i, j, n, cbu = 0, cbw = 0, ch;
    BOOL fTruncate = flags & CHARUTIL_FLAG_TRUNCATE;
    if(pcbw) { *pcbw = 0; }
    if(pwsz) { *pwsz = NULL; }
    if(!usz) { usz = ""; }
    if(cch > CHARUTIL_CONVERT_MAXSIZE) { cch = CHARUTIL_CONVERT_MAXSIZE; }
    // 1: utf-8 byte-length:
    cbBuffer = cbBuffer & ~1;       // multiple of 2-byte sizeof(WCHAR)
    if(fTruncate && (!cbBuffer || (flags & CHARUTIL_FLAG_ALLOC))) { goto fail; }
    while((c = usz[cbu]) && (cbu < cch)) {
        if(c & 0x80) {
            // utf-8 char:
            n = 0;
            if((c & 0xe0) == 0xc0) { n = 2; }
            if((c & 0xf0) == 0xe0) { n = 3; }
            if((c & 0xf8) == 0xf0) { n = 4; }
            if(!n || (cbu + n > cch)) { break; }
            if(fTruncate && (cbw + ((n == 4) ? 4 : 2) >= cbBuffer)) { break; }
            if((n > 1) && ((usz[cbu + 1] & 0xc0) != 0x80)) { goto fail; }   // invalid char-encoding
            if((n > 2) && ((usz[cbu + 2] & 0xc0) != 0x80)) { goto fail; }   // invalid char-encoding
            if((n > 3) && ((usz[cbu + 3] & 0xc0) != 0x80)) { goto fail; }   // invalid char-encoding
            cbw += (n == 4) ? 4 : 2;
            cbu += n;
        } else {
            if(fTruncate && (cbw + 2 >= cbBuffer)) { break; }
            cbw += 2;
            cbu += 1;
        }
    }
    cbu += 1;
    cbw += 2;
    if(pcbw) { *pcbw = cbw; }
    // 2: return on length-request or alloc-fail
    if(!pwsz) {
        if(!(flags & CHARUTIL_FLAG_STR_BUFONLY)) { return TRUE; }   // success: length request
        if(flags & CHARUTIL_FLAG_ALLOC) { return FALSE; }
    }
    if(!(flags & CHARUTIL_FLAG_ALLOC) && (!pbBuffer || (cbBuffer < cbw))) { goto fail; } // fail: insufficient buffer space
    wsz = (pbBuffer && (cbBuffer >= cbw)) ? pbBuffer : LocalAlloc(0, cbw);
    if(!wsz) { goto fail; }                                                 // fail: failed buffer space allocation
    // 3: Populate with wchar string. NB! algorithm works only on correctly
    //    formed UTF-8 - which has been verified in the count-step.
    i = cbu - 2; j = (cbw >> 1) - 1;
    wsz[j--] = 0;
    while(i < 0x7fffffff) {
        if(((c = usz[i--]) & 0xc0) == 0x80) {
            // 2-3-4 byte utf-8
            ch = c & 0x3f;
            if(((c = usz[i--]) & 0xc0) == 0x80) {
                // 3-4 byte utf-8
                ch += (c & 0x3f) << 6;
                if(((c = usz[i--]) & 0xc0) == 0x80) {
                    ch += (c & 0x3f) << 12;     // 4-byte utf-8
                    c = usz[i--];
                    ch += (c & 0x07) << 18;
                } else {
                    ch += (c & 0x0f) << 12;     // 3-byte utf-8
                }
            } else {
                ch += (c & 0x1f) << 6;          // 2-byte utf-8
            }
            if(ch >= 0x10000) {
                // surrogate pair:
                ch -= 0x10000;
                wsz[j--] = (ch & 0x3ff) + 0xdc00;
                wsz[j--] = (USHORT)((ch >> 10) + 0xd800);
            } else {
                wsz[j--] = (USHORT)ch;
            }
        } else {
            wsz[j--] = c;
        }
    }
    if(pwsz) { *pwsz = wsz; }
    return TRUE;
fail:
    if(!(flags ^ CHARUTIL_FLAG_TRUNCATE_ONFAIL_NULLSTR) && pbBuffer && (cbBuffer > 1)) {
        if(pwsz) { *pwsz = (LPWSTR)pbBuffer; }
        if(pcbw) { *pcbw = 2; }
        pbBuffer[0] = 0;
    }
    return FALSE;
}

//-----------------------------------------------------------------------------
// VFS LIST FUNCTIONALITY BELOW:
//-----------------------------------------------------------------------------

typedef struct tdVFSLIST_CONTEXT {
    BOOL(*pfnVfsList)(_In_ LPCWSTR wcsPath, _Inout_ PVMMDLL_VFS_FILELIST2 pFileList);
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
    g_ctxVfsList.pfnVfsList = (BOOL(*)(LPCWSTR, PVMMDLL_VFS_FILELIST2))GetProcAddress(hModuleVmm, "VMMDLL_VfsList");
    g_ctxVfsList.qwCacheValidMs = dwCacheValidMs;
    GetSystemTime(&SystemTimeNow);
    SystemTimeToFileTime(&SystemTimeNow, &g_ctxVfsList.ftDefaultTime);
    return TRUE;
}
