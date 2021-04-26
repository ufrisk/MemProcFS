// vfsdokan.c : implementation of functions related to virtual file system support based on dokan.
//
// (c) Ulf Frisk, 2018-2021
// Author: Ulf Frisk, pcileech@frizk.net
//
#include <Windows.h>
#include <stdio.h>
#include <vmmdll.h>
#include "vfs.h"
#pragma warning( push )  
#pragma warning( disable : 4005 )   
#include <dokan.h>
#pragma warning( pop )

DWORD g_dbg_c = 0;

//#define dbg_GetTickCount64()            GetTickCount64()
//#define dbg_wprintf_init(format, ...)   { wprintf(format, ++g_dbg_c, ##__VA_ARGS__); }
//#define dbg_wprintf(format, ...)        { wprintf(format, ++g_dbg_c, ##__VA_ARGS__); }
#define dbg_wprintf_init(format, ...)   {}
#define dbg_wprintf(format, ...)        {}
#define dbg_GetTickCount64()            0

//-------------------------------------------------------------------------------
// DOKAN CALLBACK FUNCTIONS BELOW:
//-------------------------------------------------------------------------------

NTSTATUS
VfsDokanCallback_CreateFile_Impl(LPCWSTR wcsFileName, PDOKAN_IO_SECURITY_CONTEXT SecurityContext, ACCESS_MASK DesiredAccess, ULONG FileAttributes, ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions, PDOKAN_FILE_INFO DokanFileInfo)
{
    UINT64 tmStart = dbg_GetTickCount64();
    BOOL result;
    WIN32_FIND_DATAW FindData;
    WCHAR wszPath[MAX_PATH];
    LPWSTR wszFile;
    BOOL fIsDirectoryExisting = FALSE;
    UNREFERENCED_PARAMETER(SecurityContext);
    UNREFERENCED_PARAMETER(FileAttributes);
    if(!ctxVfs || !ctxVfs->fInitialized) { return STATUS_FILE_INVALID; }
    // root directory
    if(!wcscmp(wcsFileName, L"\\")) {
        if(CreateDisposition == CREATE_ALWAYS) { return ctxVfs->DokanNtStatusFromWin32(ERROR_ACCESS_DENIED); }
        DokanFileInfo->IsDirectory = TRUE;
        return STATUS_SUCCESS;
    }
    // other files
    if(CreateDisposition == CREATE_ALWAYS) { return ctxVfs->DokanNtStatusFromWin32(ERROR_ACCESS_DENIED); }
    Util_SplitPathFile(wszPath, &wszFile, wcsFileName);
    result = VfsList_GetSingle(wszPath[0] ? wszPath : L"\\", wszFile, &FindData, &fIsDirectoryExisting);
    if(!result) { return fIsDirectoryExisting ? STATUS_OBJECT_NAME_NOT_FOUND : STATUS_OBJECT_PATH_NOT_FOUND; }
    DokanFileInfo->IsDirectory = (FindData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) ? TRUE : FALSE;
    DokanFileInfo->Nocache = TRUE;
    if(!DokanFileInfo->IsDirectory && (CreateOptions & FILE_DIRECTORY_FILE)) { return STATUS_NOT_A_DIRECTORY; }     // fail upon open normal file as directory
    return (CreateDisposition == OPEN_ALWAYS) ? STATUS_OBJECT_NAME_COLLISION : STATUS_SUCCESS;
}

NTSTATUS DOKAN_CALLBACK
VfsDokanCallback_CreateFile(LPCWSTR FileName, PDOKAN_IO_SECURITY_CONTEXT SecurityContext, ACCESS_MASK DesiredAccess, ULONG FileAttributes, ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions, PDOKAN_FILE_INFO DokanFileInfo)
{
    UINT64 tmStart = dbg_GetTickCount64();
    NTSTATUS nt;
    if(!ctxVfs || !ctxVfs->fInitialized) { return STATUS_FILE_INVALID; }
    nt = VfsDokanCallback_CreateFile_Impl(FileName, SecurityContext, DesiredAccess, FileAttributes, ShareAccess, CreateDisposition, CreateOptions, DokanFileInfo);
    dbg_wprintf(L"DEBUG::%08x %8x VfsCallback_CreateFile:\t\t 0x%08x %s [ %08x %08x %08x %08x ]\n", (DWORD)(dbg_GetTickCount64() - tmStart), nt, FileName, FileAttributes, ShareAccess, CreateDisposition, CreateOptions);
    return nt;
}

NTSTATUS DOKAN_CALLBACK
VfsDokanCallback_GetFileInformation(_In_ LPCWSTR wcsFileName, _Inout_ LPBY_HANDLE_FILE_INFORMATION hfi, _In_ PDOKAN_FILE_INFO DokanFileInfo)
{
    UINT64 tmStart = dbg_GetTickCount64();
    BOOL result;
    WIN32_FIND_DATAW FindData;
    WCHAR wszPath[MAX_PATH];
    LPWSTR wszFile;
    BOOL fIsDirectoryExisting = FALSE;
    if(!ctxVfs || !ctxVfs->fInitialized) { return STATUS_FILE_INVALID; }
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
    Util_SplitPathFile(wszPath, &wszFile, wcsFileName);
    result = VfsList_GetSingle((wszPath[0] ? wszPath : L"\\"), wszFile, &FindData, &fIsDirectoryExisting);
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
    hfi->nFileIndexHigh = Util_HashStringUpperW((LPWSTR)wcsFileName);
    hfi->nFileIndexLow = Util_HashStringUpperW((LPWSTR)FindData.cFileName);
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
VfsDokanCallback_FindFiles(LPCWSTR wcsFileName, PFillFindData FillFindData, PDOKAN_FILE_INFO DokanFileInfo)
{
    UINT64 tmStart = dbg_GetTickCount64();
    if(!ctxVfs || !ctxVfs->fInitialized) { return STATUS_FILE_INVALID; }
    dbg_wprintf_init(L"DEBUG::%08x -------- VfsCallback_FindFiles:\t\t\t 0x%08x %s\n", 0, wcsFileName);
    VfsList_ListDirectory((LPWSTR)wcsFileName, DokanFileInfo, FillFindData);
    dbg_wprintf(L"DEBUG::%08x %8x VfsCallback_FindFiles:\t\t\t 0x%08x %s\n", (DWORD)(dbg_GetTickCount64() - tmStart), STATUS_SUCCESS, wcsFileName);
    return STATUS_SUCCESS;
}

NTSTATUS DOKAN_CALLBACK
VfsDokanCallback_ReadFile(LPCWSTR wcsFileName, LPVOID Buffer, DWORD BufferLength, LPDWORD ReadLength, LONGLONG Offset, PDOKAN_FILE_INFO DokanFileInfo)
{
    UINT64 tmStart = dbg_GetTickCount64();
    NTSTATUS nt;
    if(!ctxVfs || !ctxVfs->fInitialized) { return STATUS_FILE_INVALID; }
    dbg_wprintf_init(L"DEBUG::%08x -------- VfsCallback_ReadFile:\t\t\t 0x%08x %s\n", 0, wcsFileName);
    nt = ctxVfs->pVmmDll->VfsRead(wcsFileName, Buffer, BufferLength, ReadLength, Offset);
    dbg_wprintf(L"DEBUG::%08x %8x VfsCallback_ReadFile:\t\t\t 0x%08x %s\t [ %016llx %08x %08x ]\n", (DWORD)(dbg_GetTickCount64() - tmStart), nt, wcsFileName, Offset, BufferLength, *ReadLength);
    return nt;
}

NTSTATUS DOKAN_CALLBACK
VfsDokanCallback_WriteFile(LPCWSTR wcsFileName, LPCVOID Buffer, DWORD NumberOfBytesToWrite, LPDWORD NumberOfBytesWritten, LONGLONG Offset, PDOKAN_FILE_INFO DokanFileInfo)
{
    UINT64 tmStart = dbg_GetTickCount64();
    NTSTATUS nt;
    if(!ctxVfs || !ctxVfs->fInitialized) { return STATUS_FILE_INVALID; }
    dbg_wprintf_init(L"DEBUG::%08x -------- VfsCallback_WriteFile:\t\t\t 0x%08x %s\n", 0, wcsFileName);
    nt = ctxVfs->pVmmDll->VfsWrite(wcsFileName, (PBYTE)Buffer, NumberOfBytesToWrite, NumberOfBytesWritten, Offset);
    dbg_wprintf(L"DEBUG::%08x %8x VfsCallback_WriteFile:\t\t\t 0x%08x %s\t [ %016llx %08x %08x ]\n", (DWORD)(dbg_GetTickCount64() - tmStart), nt, wcsFileName, Offset, NumberOfBytesToWrite, *NumberOfBytesWritten);
    return nt;
}

//-------------------------------------------------------------------------------
// VFS INITIALIZATION FUNCTIONALITY BELOW:
//-------------------------------------------------------------------------------

VOID VfsDokan_Close(_In_ CHAR chMountPoint)
{
    HMODULE hModuleDokan = NULL;
    WCHAR wchMountPoint = chMountPoint;
    BOOL(*pfnDokanUnmount)(WCHAR DriveLetter);
    if(ctxVfs && ctxVfs->fInitialized) {
        ctxVfs->fInitialized = FALSE;
        if(wchMountPoint) {
            hModuleDokan = LoadLibraryExA("dokan1.dll", NULL, LOAD_LIBRARY_SEARCH_SYSTEM32);
            if(hModuleDokan) {
                pfnDokanUnmount = (BOOL(*)(WCHAR))GetProcAddress(hModuleDokan, "DokanUnmount");
                if(pfnDokanUnmount) {
                    pfnDokanUnmount(wchMountPoint);
                }
                FreeLibrary(hModuleDokan);
            }
        }
    }
    LocalFree(ctxVfs);
    ctxVfs = NULL;
}

VOID VfsDokan_InitializeAndMount_DisplayInfo(LPWSTR wszMountPoint, _In_ PVMMDLL_FUNCTIONS pVmmDll)
{
    ULONG64 qwVersionVmmMajor = 0, qwVersionVmmMinor = 0, qwVersionVmmRevision = 0;
    ULONG64 qwVersionWinMajor = 0, qwVersionWinMinor = 0, qwVersionWinBuild = 0;
    ULONG64 qwUniqueSystemId = 0, iMemoryModel;
    // get vmm.dll versions
    pVmmDll->ConfigGet(VMMDLL_OPT_CONFIG_VMM_VERSION_MAJOR, &qwVersionVmmMajor);
    pVmmDll->ConfigGet(VMMDLL_OPT_CONFIG_VMM_VERSION_MINOR, &qwVersionVmmMinor);
    pVmmDll->ConfigGet(VMMDLL_OPT_CONFIG_VMM_VERSION_REVISION, &qwVersionVmmRevision);
    // get operating system versions
    pVmmDll->ConfigGet(VMMDLL_OPT_CORE_MEMORYMODEL, &iMemoryModel);
    pVmmDll->ConfigGet(VMMDLL_OPT_WIN_VERSION_MAJOR, &qwVersionWinMajor);
    pVmmDll->ConfigGet(VMMDLL_OPT_WIN_VERSION_MINOR, &qwVersionWinMinor);
    pVmmDll->ConfigGet(VMMDLL_OPT_WIN_VERSION_BUILD, &qwVersionWinBuild);
    pVmmDll->ConfigGet(VMMDLL_OPT_WIN_SYSTEM_UNIQUE_ID, &qwUniqueSystemId);
    printf("\n" \
        "=============== MemProcFS - THE MEMORY PROCESS FILE SYSTEM ===============\n" \
        " - Author:           Ulf Frisk - pcileech@frizk.net                     \n" \
        " - Info:             https://github.com/ufrisk/MemProcFS                \n" \
        " - License:          GNU Affero General Public License v3.0             \n" \
        "   -------------------------------------------------------------------- \n" \
        "   MemProcFS is free open source software. If you find it useful please \n" \
        "   become a sponsor at: https://github.com/sponsors/ufrisk Thank You :) \n" \
        "   -------------------------------------------------------------------- \n" \
        " - Version:          %i.%i.%i                                           \n" \
        " - Mount Point:      %S                                                 \n" \
        " - Tag:              %i_%x                                              \n" ,
        (DWORD)qwVersionVmmMajor, (DWORD)qwVersionVmmMinor, (DWORD)qwVersionVmmRevision,
        wszMountPoint, (DWORD)qwVersionWinBuild, (DWORD)qwUniqueSystemId);
    if(qwVersionWinMajor && (iMemoryModel < (sizeof(VMMDLL_MEMORYMODEL_TOSTRING) / sizeof(LPSTR)))) {
        printf(" - Operating System: Windows %i.%i.%i (%s)\n",
            (DWORD)qwVersionWinMajor, (DWORD)qwVersionWinMinor, (DWORD)qwVersionWinBuild, VMMDLL_MEMORYMODEL_TOSTRING[iMemoryModel]);
    } else {
        printf(" - Operating System: Unknown\n");
    }
    printf("==========================================================================\n\n");
}

VOID VfsDokan_InitializeAndMount(_In_ CHAR chMountPoint, _In_ PVMMDLL_FUNCTIONS pVmmDll)
{
    int status;
    HMODULE hModuleDokan = NULL;
    PDOKAN_OPTIONS pDokanOptions = NULL;
    PDOKAN_OPERATIONS pDokanOperations = NULL;
    WCHAR wszMountPoint[] = { 'M', ':', '\\', 0 };
    SYSTEMTIME SystemTimeNow;
    int(*fnDokanMain)(PDOKAN_OPTIONS, PDOKAN_OPERATIONS);
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
    ctxVfs->DokanNtStatusFromWin32 = (NTSTATUS(*)(DWORD))GetProcAddress(hModuleDokan, "DokanNtStatusFromWin32");
    ctxVfs->fInitialized = TRUE;
    // set options
    pDokanOptions->Version = DOKAN_VERSION;
    pDokanOptions->Options |= DOKAN_OPTION_NETWORK;
    pDokanOptions->UNCName = L"MemProcFS";
    pDokanOptions->ThreadCount = 10;
    wszMountPoint[0] = chMountPoint;
    pDokanOptions->MountPoint = wszMountPoint;
    pDokanOptions->Timeout = 60000;
    // set callbacks
    pDokanOperations->ZwCreateFile = VfsDokanCallback_CreateFile;
    pDokanOperations->GetFileInformation = VfsDokanCallback_GetFileInformation;
    pDokanOperations->FindFiles = VfsDokanCallback_FindFiles;
    pDokanOperations->ReadFile = VfsDokanCallback_ReadFile;
    pDokanOperations->WriteFile = VfsDokanCallback_WriteFile;
    // print system information to console
    VfsDokan_InitializeAndMount_DisplayInfo(wszMountPoint, pVmmDll);
    // mount file system
    status = fnDokanMain(pDokanOptions, pDokanOperations);
    while(ctxVfs && ctxVfs->fInitialized && (status == DOKAN_SUCCESS)) {
        printf("MOUNT: ReMounting as drive %S\n", pDokanOptions->MountPoint);
        status = fnDokanMain(pDokanOptions, pDokanOperations);
    }
    if(status == -5) {
        printf("MOUNT: Failed: drive busy/already mounted.\n");
    } else {
        printf("MOUNT: Failed. Status Code: %i\n", status);
    }
fail:
    if(hModuleDokan) { FreeLibrary(hModuleDokan); }
    LocalFree(pDokanOptions);
    LocalFree(pDokanOperations);
    VfsDokan_Close(0);
}
