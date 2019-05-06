// vfs.c : implementation of functions related to virtual file system support.
//
// (c) Ulf Frisk, 2018
// Author: Ulf Frisk, pcileech@frizk.net
//
#include <Windows.h>
#include <stdio.h>
#include "vfs.h"
#include "vmmdll.h"
#pragma warning( push )  
#pragma warning( disable : 4005 )   
#include "dokan.h"
#pragma warning( pop )

DWORD g_dbg_c = 0;

//#define dbg_GetTickCount64()            GetTickCount64()
//#define dbg_wprintf_init(format, ...)   { wprintf(format, ++g_dbg_c, ##__VA_ARGS__); }
//#define dbg_wprintf(format, ...)        { wprintf(format, ++g_dbg_c, ##__VA_ARGS__); }
#define dbg_wprintf_init(format, ...)   {}
#define dbg_wprintf(format, ...)        {}
#define dbg_GetTickCount64()            0

//-------------------------------------------------------------------------------
// DEFINES, TYPEDEFS AND FORWARD DECLARATIONS BELOW:
//-------------------------------------------------------------------------------

#define VFS_CONFIG_FILELIST_ITEMS   12
#define VFS_CONFIG_FILELIST_MAGIC   0x7f646555caffee66
typedef struct tdVFS_FILELIST {
    QWORD magic;
    struct tdVFS_FILELIST* FLink;
    DWORD cFiles;
    WIN32_FIND_DATAW pFiles[VFS_CONFIG_FILELIST_ITEMS];
} VFS_FILELIST, *PVFS_FILELIST;

BOOL VfsListVmmDirectory(_In_ LPWSTR wszDirectoryName);

//-------------------------------------------------------------------------------
// FILELIST FUNCTIONALITY BELOW:
// (directory listing functions/structs for communicating between vfs and vfsproc).
//-------------------------------------------------------------------------------

PVFS_FILELIST VfsFileList_Alloc()
{
    PVFS_FILELIST pFileList = LocalAlloc(LMEM_ZEROINIT, sizeof(VFS_FILELIST));
    if(pFileList) {
        pFileList->magic = VFS_CONFIG_FILELIST_MAGIC;
    }
    return pFileList;
}

VOID VfsFileList_Free(_Inout_ PVFS_FILELIST pFileList)
{
    PVFS_FILELIST pFileListFlink;
    while(pFileList) {
        pFileListFlink = pFileList->FLink;
        LocalFree(pFileList);
        pFileList = pFileListFlink;
    }
}

VOID VfsFileList_AddDirectoryFileInternal(_Inout_ PVFS_FILELIST pFileList, _In_ DWORD dwFileAttributes, _In_ FILETIME ftCreationTime, _In_ FILETIME ftLastAccessTime, _In_ FILETIME ftLastWriteTime, _In_ DWORD nFileSizeHigh, _In_ DWORD nFileSizeLow, _In_ LPSTR szName)
{
    DWORD i = 0;
    PWIN32_FIND_DATAW pFindData;
    // 1: check if required to allocate more FileList items
    while(pFileList->cFiles == VFS_CONFIG_FILELIST_ITEMS) {
        if(pFileList->FLink) {
            pFileList = pFileList->FLink;
            continue;
        }
        pFileList->FLink = VfsFileList_Alloc();
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
    while(i < MAX_PATH && szName[i]) {
        pFindData->cFileName[i] = szName[i];
        i++;
    }
    pFindData->cFileName[i] = 0;
}

VOID VfsFileList_AddFile(_Inout_ HANDLE hFileList, _In_ LPSTR szName, _In_ QWORD cb, _In_ PVOID pvReserved)
{
    PVFS_FILELIST pFileList2 = (PVFS_FILELIST)hFileList;
    if(pFileList2 && (pFileList2->magic == VFS_CONFIG_FILELIST_MAGIC)) {
        VfsFileList_AddDirectoryFileInternal(
            pFileList2,
            FILE_ATTRIBUTE_NOT_CONTENT_INDEXED,
            ctxVfs->ftDefaultTime,
            ctxVfs->ftDefaultTime,
            ctxVfs->ftDefaultTime,
            (DWORD)(cb >> 32),
            (DWORD)cb,
            szName
        );
    }
}

VOID VfsFileList_AddDirectory(_Inout_ HANDLE hFileList, _In_ LPSTR szName, _In_ PVOID pvReserved)
{
    PVFS_FILELIST pFileList2 = (PVFS_FILELIST)hFileList;
    if(pFileList2 && (pFileList2->magic == VFS_CONFIG_FILELIST_MAGIC)) {
        VfsFileList_AddDirectoryFileInternal(
            pFileList2,
            FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_NOT_CONTENT_INDEXED,
            ctxVfs->ftDefaultTime,
            ctxVfs->ftDefaultTime,
            ctxVfs->ftDefaultTime,
            0,
            0,
            szName
        );
    }
}

VOID VfsFileList_DokanFillAll(PVFS_FILELIST pFileList, PDOKAN_FILE_INFO DokanFileInfo, PFillFindData FillFindData)
{
    DWORD i;
    do {
        for(i = 0; i < pFileList->cFiles; i++) {
            FillFindData(pFileList->pFiles + i, DokanFileInfo);
        }
        pFileList = pFileList->FLink;
    } while(pFileList);
}

PWIN32_FIND_DATAW VfsFileList_FindSingle(_In_ PVFS_FILELIST pFileList, _In_ LPWSTR wszFile)
{
    DWORD i;
    do {
        for(i = 0; i < pFileList->cFiles; i++) {
            if(!wcscmp(wszFile, pFileList->pFiles[i].cFileName)) {
                return pFileList->pFiles + i;
            }
        }
        pFileList = pFileList->FLink;
    } while(pFileList);
    return NULL;
}

//-------------------------------------------------------------------------------
// DIRECTORY LISTINGS READ CACHE BELOW:
// (caching is used to cache vmmproc directory listings for performance reasons)
//-------------------------------------------------------------------------------

_Success_(return)
BOOL VfsCacheDirectory_GetSingle2(_In_ LPWSTR wszPath, _In_ LPWSTR wszFile, _Out_ PWIN32_FIND_DATAW pFindData, _Out_ PBOOL pIsDirectoryExisting)
{
    QWORD i, qwCurrentTickCount;
    PWIN32_FIND_DATAW pFindDataCache;
    qwCurrentTickCount = GetTickCount64();
    *pIsDirectoryExisting = FALSE;
    EnterCriticalSection(&ctxVfs->CacheDirectoryLock);
    for(i = 0; i < VMMVFS_CACHE_DIRECTORY_ENTRIES; i++) {
        if(wcscmp(wszPath, ctxVfs->CacheDirectory[i].wszDirectoryName)) { continue; }
        if(qwCurrentTickCount > ctxVfs->CacheDirectory[i].qwExpireTickCount64) { continue; }
        *pIsDirectoryExisting = TRUE;
        pFindDataCache = VfsFileList_FindSingle(ctxVfs->CacheDirectory[i].pFileList, wszFile);
        if(!pFindDataCache) {
            LeaveCriticalSection(&ctxVfs->CacheDirectoryLock);
            return FALSE;
        }
        if(pFindData) {
            memcpy(pFindData, pFindDataCache, sizeof(WIN32_FIND_DATAW));
        }
        LeaveCriticalSection(&ctxVfs->CacheDirectoryLock);
        return TRUE;
    }
    LeaveCriticalSection(&ctxVfs->CacheDirectoryLock);
    return FALSE;
}

BOOL VfsCacheDirectory_GetSingle(_In_ LPWSTR wszPath, _In_ LPWSTR wszFile, _Out_ PWIN32_FIND_DATAW pFindData, _Out_ PBOOL pfIsDirectoryExisting)
{
    BOOL result;
    result = VfsCacheDirectory_GetSingle2(wszPath, wszFile, pFindData, pfIsDirectoryExisting);
    if(result) { return TRUE; }
    if(*pfIsDirectoryExisting) { return FALSE; }
    return VfsListVmmDirectory(wszPath) && VfsCacheDirectory_GetSingle2(wszPath, wszFile, pFindData, pfIsDirectoryExisting);
}

BOOL VfsCacheDirectory_DokanFillDirectory(_In_ LPCWSTR wcsPathFileName, _In_ PFillFindData FillFindData, _Inout_ PDOKAN_FILE_INFO DokanFileInfo)
{
    QWORD i, qwCurrentTickCount;
    qwCurrentTickCount = GetTickCount64();
    EnterCriticalSection(&ctxVfs->CacheDirectoryLock);
    for(i = 0; i < VMMVFS_CACHE_DIRECTORY_ENTRIES; i++) {
        if(wcscmp(wcsPathFileName, ctxVfs->CacheDirectory[i].wszDirectoryName)) { continue; }
        if(qwCurrentTickCount > ctxVfs->CacheDirectory[i].qwExpireTickCount64) { continue; }
        VfsFileList_DokanFillAll(ctxVfs->CacheDirectory[i].pFileList, DokanFileInfo, FillFindData);
        LeaveCriticalSection(&ctxVfs->CacheDirectoryLock);
        return TRUE;
    }
    LeaveCriticalSection(&ctxVfs->CacheDirectoryLock);
    return FALSE;
}

VOID VfsCacheDirectory_Put(_In_ LPCWSTR wcsDirectoryName, _In_ PVFS_FILELIST pFileList)
{
    EnterCriticalSection(&ctxVfs->CacheDirectoryLock);
    ctxVfs->CacheDirectory[ctxVfs->CacheDirectoryIndex].qwExpireTickCount64 = GetTickCount64() + VMMVFS_CACHE_DIRECTORY_LIFETIME_PROC_MS;
    wcscpy_s(ctxVfs->CacheDirectory[ctxVfs->CacheDirectoryIndex].wszDirectoryName, MAX_PATH, wcsDirectoryName);
    VfsFileList_Free(ctxVfs->CacheDirectory[ctxVfs->CacheDirectoryIndex].pFileList);
    ctxVfs->CacheDirectory[ctxVfs->CacheDirectoryIndex].pFileList = pFileList;
    ctxVfs->CacheDirectoryIndex = (ctxVfs->CacheDirectoryIndex + 1) % VMMVFS_CACHE_DIRECTORY_ENTRIES;
    LeaveCriticalSection(&ctxVfs->CacheDirectoryLock);
}

VOID VfsCacheDirectory_Close()
{
    DWORD i;
    EnterCriticalSection(&ctxVfs->CacheDirectoryLock);
    for(i = 0; i < VMMVFS_CACHE_DIRECTORY_ENTRIES; i++) {
        ctxVfs->CacheDirectory[i].qwExpireTickCount64 = 0;
        VfsFileList_Free(ctxVfs->CacheDirectory[i].pFileList);
        ctxVfs->CacheDirectory[i].pFileList = NULL;
    }
    LeaveCriticalSection(&ctxVfs->CacheDirectoryLock);
}

//-------------------------------------------------------------------------------
// UTILITY FUNCTIONS BELOW:
//-------------------------------------------------------------------------------

BOOL VfsListVmmDirectory(_In_ LPWSTR wszDirectoryName)
{
    BOOL result;
    PVFS_FILELIST pFileList = VfsFileList_Alloc(ctxVfs->ftDefaultTime);
    VMMDLL_VFS_FILELIST VfsFileList;
    if(!pFileList) { return FALSE; }
    VfsFileList.h = (HANDLE)pFileList;
    VfsFileList.pfnAddFile = VfsFileList_AddFile;
    VfsFileList.pfnAddDirectory = VfsFileList_AddDirectory;
    result = ctxVfs->pVmmDll->VfsList(wszDirectoryName, &VfsFileList);
    if(!result) {
        VfsFileList_Free(pFileList);
        return FALSE;
    }
    VfsCacheDirectory_Put(wszDirectoryName, pFileList); // do not free pFileList since it's put into the cache
    return TRUE;
}

VOID Vfs_UtilSplitPathFile(_Out_writes_(MAX_PATH) PWCHAR wszPath, _Out_ LPWSTR *pwcsFile, _In_ LPCWSTR wcsFileName)
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

//-------------------------------------------------------------------------------
// DOKAN CALLBACK FUNCTIONS BELOW:
//-------------------------------------------------------------------------------

NTSTATUS
VfsCallback_CreateFile_Impl(LPCWSTR wcsFileName, PDOKAN_IO_SECURITY_CONTEXT SecurityContext, ACCESS_MASK DesiredAccess, ULONG FileAttributes, ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions, PDOKAN_FILE_INFO DokanFileInfo)
{
    UINT64 tmStart = dbg_GetTickCount64();
    BOOL result;
    WIN32_FIND_DATAW FindData;
    WCHAR wszPath[MAX_PATH];
    LPWSTR wszFile;
    BOOL fIsDirectoryExisting = FALSE;
    UNREFERENCED_PARAMETER(SecurityContext);
    UNREFERENCED_PARAMETER(FileAttributes);
    // root directory
    if(!wcscmp(wcsFileName, L"\\")) {
        if(CreateDisposition == CREATE_ALWAYS) { return ctxVfs->DokanNtStatusFromWin32(ERROR_ACCESS_DENIED); }
        DokanFileInfo->IsDirectory = TRUE;
        return STATUS_SUCCESS;
    }
    // other files
    if(CreateDisposition == CREATE_ALWAYS) { return ctxVfs->DokanNtStatusFromWin32(ERROR_ACCESS_DENIED); }
    Vfs_UtilSplitPathFile(wszPath, &wszFile, wcsFileName);
    result = VfsCacheDirectory_GetSingle(wszPath[0] ? wszPath : L"\\", wszFile, &FindData, &fIsDirectoryExisting);
    if(!result) { return fIsDirectoryExisting ? STATUS_OBJECT_NAME_NOT_FOUND : STATUS_OBJECT_PATH_NOT_FOUND; }
    DokanFileInfo->IsDirectory = (FindData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) ? TRUE : FALSE;
    DokanFileInfo->Nocache = TRUE;
    if(!DokanFileInfo->IsDirectory && (CreateOptions & FILE_DIRECTORY_FILE)) { return STATUS_NOT_A_DIRECTORY; }     // fail upon open normal file as directory
    return (CreateDisposition == OPEN_ALWAYS) ? STATUS_OBJECT_NAME_COLLISION : STATUS_SUCCESS;
}

NTSTATUS DOKAN_CALLBACK
VfsCallback_CreateFile(LPCWSTR FileName, PDOKAN_IO_SECURITY_CONTEXT SecurityContext, ACCESS_MASK DesiredAccess, ULONG FileAttributes, ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions, PDOKAN_FILE_INFO DokanFileInfo)
{
    UINT64 tmStart = dbg_GetTickCount64();
    NTSTATUS nt = VfsCallback_CreateFile_Impl(FileName, SecurityContext, DesiredAccess, FileAttributes, ShareAccess, CreateDisposition, CreateOptions, DokanFileInfo);
    dbg_wprintf(L"DEBUG::%08x %8x VfsCallback_CreateFile:\t\t 0x%08x %s [ %08x %08x %08x %08x ]\n", (DWORD)(dbg_GetTickCount64() - tmStart), nt, FileName, FileAttributes, ShareAccess, CreateDisposition, CreateOptions);
    return nt;
}

NTSTATUS DOKAN_CALLBACK
VfsCallback_GetFileInformation(_In_ LPCWSTR wcsFileName, _Inout_ LPBY_HANDLE_FILE_INFORMATION hfi, _In_ PDOKAN_FILE_INFO DokanFileInfo)
{
    UINT64 tmStart = dbg_GetTickCount64();
    BOOL result;
    WIN32_FIND_DATAW FindData;
    WCHAR wszPath[MAX_PATH];
    LPWSTR wszFile;
    BOOL fIsDirectoryExisting = FALSE;
    dbg_wprintf_init(L"DEBUG::%08x -------- VfsCallback_GetFileInformation:\t 0x%08x %s\n", 0, wcsFileName);
    // matches: root directory
    if(!wcscmp(wcsFileName, L"\\")) {
        hfi->ftCreationTime = ctxVfs->ftDefaultTime;
        hfi->ftLastWriteTime = ctxVfs->ftDefaultTime;
        hfi->ftLastAccessTime = ctxVfs->ftDefaultTime;
        hfi->nFileSizeHigh = 0;
        hfi->nFileSizeLow = 0;
        hfi->dwFileAttributes = FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_NOT_CONTENT_INDEXED;
        dbg_wprintf(L"DEBUG::%08x %8x VfsCallback_GetFileInformation:\t 0x%08x %s\n", (DWORD)(dbg_GetTickCount64() - tmStart), STATUS_SUCCESS, wcsFileName);
        return STATUS_SUCCESS;
    }
    Vfs_UtilSplitPathFile(wszPath, &wszFile, wcsFileName);
    result = VfsCacheDirectory_GetSingle((wszPath[0] ? wszPath : L"\\"), wszFile, &FindData, &fIsDirectoryExisting);
    if(!result) { 
        dbg_wprintf(L"DEBUG::%08x %8x VfsCallback_GetFileInformation:\t 0x%08x %s\n", (DWORD)(dbg_GetTickCount64() - tmStart), STATUS_FILE_NOT_AVAILABLE, wcsFileName);
        return STATUS_FILE_NOT_AVAILABLE;
    }
    hfi->dwFileAttributes = FindData.dwFileAttributes;
    hfi->ftCreationTime = FindData.ftCreationTime;
    hfi->ftLastAccessTime = FindData.ftLastAccessTime;
    hfi->ftLastWriteTime = FindData.ftLastWriteTime;
    hfi->nFileSizeHigh = FindData.nFileSizeHigh;
    hfi->nFileSizeLow = FindData.nFileSizeLow;
    dbg_wprintf(L"DEBUG::%08x %8x VfsCallback_GetFileInformation:\t 0x%08x %s\t [ %08x %08x%08x %016llx %016llx %016llx ]\n",
        (DWORD)(dbg_GetTickCount64() - tmStart),
        STATUS_SUCCESS,
        wcsFileName,
        hfi->dwFileAttributes,
        hfi->nFileSizeHigh, hfi->nFileSizeLow,
        *(PQWORD)&hfi->ftCreationTime,
        *(PQWORD)&hfi->ftLastAccessTime,
        *(PQWORD)&hfi->ftLastWriteTime
        );
    return STATUS_SUCCESS;
}

NTSTATUS DOKAN_CALLBACK
VfsCallback_FindFiles(LPCWSTR wcsFileName, PFillFindData FillFindData, PDOKAN_FILE_INFO DokanFileInfo)
{
    UINT64 tmStart = dbg_GetTickCount64();
    BOOL result;
    dbg_wprintf_init(L"DEBUG::%08x -------- VfsCallback_FindFiles:\t\t\t 0x%08x %s\n", 0, wcsFileName);
    result = VfsCacheDirectory_DokanFillDirectory(wcsFileName, FillFindData, DokanFileInfo);
    if(result) {
        dbg_wprintf(L"DEBUG::%08x %8x VfsCallback_FindFiles:\t\t\t 0x%08x %s\n", (DWORD)(dbg_GetTickCount64() - tmStart), STATUS_SUCCESS, wcsFileName);
        return STATUS_SUCCESS;
    }
    VfsListVmmDirectory((LPWSTR)wcsFileName);
    VfsCacheDirectory_DokanFillDirectory(wcsFileName, FillFindData, DokanFileInfo);
    dbg_wprintf(L"DEBUG::%08x %8x VfsCallback_FindFiles:\t\t\t 0x%08x %s\n", (DWORD)(dbg_GetTickCount64() - tmStart), STATUS_SUCCESS, wcsFileName);
    return STATUS_SUCCESS;
}

NTSTATUS DOKAN_CALLBACK
VfsCallback_ReadFile(LPCWSTR wcsFileName, LPVOID Buffer, DWORD BufferLength, LPDWORD ReadLength, LONGLONG Offset, PDOKAN_FILE_INFO DokanFileInfo)
{
    UINT64 tmStart = dbg_GetTickCount64();
    NTSTATUS nt;
    dbg_wprintf_init(L"DEBUG:: -------- VfsCallback_ReadFile:\t\t\t 0x%08x %s\n", 0, wcsFileName);
    nt = ctxVfs->pVmmDll->VfsRead(wcsFileName, Buffer, BufferLength, ReadLength, Offset);
    dbg_wprintf(L"DEBUG::%08x %8x VfsCallback_ReadFile:\t\t\t 0x%08x %s\t [ %016llx %08x %08x ]\n", (DWORD)(dbg_GetTickCount64() - tmStart), nt, wcsFileName, Offset, BufferLength, *ReadLength);
    return nt;
}

NTSTATUS DOKAN_CALLBACK
VfsCallback_WriteFile(LPCWSTR wcsFileName, LPCVOID Buffer, DWORD NumberOfBytesToWrite, LPDWORD NumberOfBytesWritten, LONGLONG Offset, PDOKAN_FILE_INFO DokanFileInfo)
{
    UINT64 tmStart = dbg_GetTickCount64();
    NTSTATUS nt;
    dbg_wprintf_init(L"DEBUG:: -------- VfsCallback_WriteFile:\t\t\t 0x%08x %s\n", 0, wcsFileName);
    nt = ctxVfs->pVmmDll->VfsWrite(wcsFileName, (PBYTE)Buffer, NumberOfBytesToWrite, NumberOfBytesWritten, Offset);
    dbg_wprintf(L"DEBUG::%08x %8x VfsCallback_WriteFile:\t\t\t 0x%08x %s\t [ %016llx %08x %08x ]\n", (DWORD)(dbg_GetTickCount64() - tmStart), nt, wcsFileName, Offset, NumberOfBytesToWrite, *NumberOfBytesWritten);
    return nt;
}

//-------------------------------------------------------------------------------
// VFS INITIALIZATION FUNCTIONALITY BELOW:
//-------------------------------------------------------------------------------

VOID VfsClose()
{
    if(ctxVfs && ctxVfs->fInitialized) {
        VfsCacheDirectory_Close();
        DeleteCriticalSection(&ctxVfs->CacheDirectoryLock);
    }
    LocalFree(ctxVfs);
    ctxVfs = NULL;
}

VOID VfsInitializeAndMount(_In_ CHAR chMountPoint, _In_ PVMMDLL_FUNCTIONS pVmmDll)
{
    int status;
    HMODULE hModuleDokan = NULL;
    PDOKAN_OPTIONS pDokanOptions = NULL;
    PDOKAN_OPERATIONS pDokanOperations = NULL;
    WCHAR wszMountPoint[] = { 'M', ':', '\\', 0 };
    SYSTEMTIME SystemTimeNow;
    int(*fnDokanMain)(PDOKAN_OPTIONS, PDOKAN_OPERATIONS);
    ULONG64 qwVersionMajor = 0, qwVersionMinor = 0, qwVersionRevision = 0;
    // get versions
    pVmmDll->ConfigGet(VMMDLL_OPT_CONFIG_VMM_VERSION_MAJOR, &qwVersionMajor);
    pVmmDll->ConfigGet(VMMDLL_OPT_CONFIG_VMM_VERSION_MINOR, &qwVersionMinor);
    pVmmDll->ConfigGet(VMMDLL_OPT_CONFIG_VMM_VERSION_REVISION, &qwVersionRevision);
    // allocate
    hModuleDokan = LoadLibraryExA("dokan1.dll", NULL, LOAD_LIBRARY_SEARCH_SYSTEM32);
    if(!hModuleDokan) {
        printf("MOUNT: Failed. The required DOKANY file system library is not installed. \n");
        printf("Please download from : https://github.com/dokan-dev/dokany/releases/latest\n");
        goto fail; 
    }
    fnDokanMain = (int(*)(PDOKAN_OPTIONS, PDOKAN_OPERATIONS))GetProcAddress(hModuleDokan, "DokanMain");
    if(!fnDokanMain) {
        printf("MOUNT: Failed. The required DOKANY file system library is not installed. \n");
        printf("Please download from : https://github.com/dokan-dev/dokany/releases/latest\n");
        goto fail;
    }
    pDokanOptions = (PDOKAN_OPTIONS)LocalAlloc(LMEM_ZEROINIT, sizeof(DOKAN_OPTIONS));
    pDokanOperations = (PDOKAN_OPERATIONS)LocalAlloc(LMEM_ZEROINIT, sizeof(DOKAN_OPERATIONS));
    if(!pDokanOptions || !pDokanOperations) {
        printf("MOUNT: Failed (out of memory).\n");
        goto fail;
    }
    // allocate empty vfs context
    ctxVfs = (PVMMVFS_CONFIG)LocalAlloc(LMEM_ZEROINIT, sizeof(VMMVFS_CONFIG));
    if(!ctxVfs) { goto fail; }
    ctxVfs->pVmmDll = pVmmDll;
    // set vfs context
    GetSystemTime(&SystemTimeNow);
    SystemTimeToFileTime(&SystemTimeNow, &ctxVfs->ftDefaultTime);
    InitializeCriticalSection(&ctxVfs->CacheDirectoryLock);
    ctxVfs->DokanNtStatusFromWin32 = (NTSTATUS(*)(DWORD))GetProcAddress(hModuleDokan, "DokanNtStatusFromWin32");
    ctxVfs->fInitialized = TRUE;
    // set options
    pDokanOptions->Version = DOKAN_VERSION;
    pDokanOptions->Options |= DOKAN_OPTION_NETWORK;
    pDokanOptions->UNCName = L"MemoryProcessFileSystem";
    wszMountPoint[0] = chMountPoint;
    pDokanOptions->MountPoint = wszMountPoint;
    pDokanOptions->Timeout = 60000;
    // set callbacks
    pDokanOperations->ZwCreateFile = VfsCallback_CreateFile;
    pDokanOperations->GetFileInformation = VfsCallback_GetFileInformation;
    pDokanOperations->FindFiles = VfsCallback_FindFiles;
    pDokanOperations->ReadFile = VfsCallback_ReadFile;
    pDokanOperations->WriteFile = VfsCallback_WriteFile;
    // enable
    printf(
        "MOUNTING THE MEMORY PROCESS FILE SYSTEM                                        \n" \
        "===============================================================================\n" \
        "The Memory Process File System is mounted as: %S              \n" \
        "Loaded VmmDll Version: %i.%i.%i                               \n" \
        "Memory from dump files or PCILeech supported devices are analyzed to provide   \n" \
        "a convenient process file system for analysis purposes.                        \n" \
        " - File system is read-only when dump files are used.                          \n" \
        " - File system is read-write when FPGA hardware acquisition devices are used.  \n" \
        " - Full support exists for Windows XP to Windows 10 (x86 and x64).             \n" \
        " - Limited support for other x64 operating systems.                            \n" \
        " - Memory Process File System: https://github.com/ufrisk/MemProcFS             \n" \
        " - File system by: Ulf Frisk - pcileech@frizk.net - https://frizk.net          \n" \
        "===============================================================================\n",
        pDokanOptions->MountPoint, (DWORD)qwVersionMajor, (DWORD)qwVersionMinor, (DWORD)qwVersionRevision);
    status = fnDokanMain(pDokanOptions, pDokanOperations);
    while(status == DOKAN_SUCCESS) {
        printf("MOUNT: ReMounting as drive %S\n", pDokanOptions->MountPoint);
        status = fnDokanMain(pDokanOptions, pDokanOperations);
    }
    printf("MOUNT: Failed. Status Code: %i\n", status);
fail:
    if(hModuleDokan) { FreeLibrary(hModuleDokan); }
    LocalFree(pDokanOptions);
    LocalFree(pDokanOperations);
    VfsClose();
}
