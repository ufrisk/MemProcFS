// memprocfs_dokan.c : implementation of core functionality for MemProcFS
// This is just a thin loader for the virtual memory manager dll which contains the logic.
//
// (c) Ulf Frisk, 2018-2025
// Author: Ulf Frisk, pcileech@frizk.net
//
#ifdef _WIN32

#include <Windows.h>
#include <stdio.h>
#include <vmmdll.h>
#include "charutil.h"
#include "vfslist.h"
#include "version.h"
#pragma warning( push )  
#pragma warning( disable : 4005 )   
#include <dokan.h>
#pragma warning( pop )

#define dbg_wprintf_init(format, ...)   {}
#define dbg_wprintf(format, ...)        {}
#define dbg_GetTickCount64()            0
#define VER_OSARCH                      "Windows"

typedef struct tdVMMVFS_CONFIG {
    FILETIME ftDefaultTime;
    NTSTATUS(*DokanNtStatusFromWin32)(DWORD Error);
    BOOL fInitialized;
} VMMVFS_CONFIG, *PVMMVFS_CONFIG;

PVMMVFS_CONFIG ctxVfs;
VMM_HANDLE g_hVMM;

CHAR g_VfsMountPoint = 'M';



//-------------------------------------------------------------------------------
// DOKAN CALLBACK FUNCTIONS BELOW:
//-------------------------------------------------------------------------------

NTSTATUS
VfsDokanCallback_CreateFile_Impl(_In_ LPSTR uszFullPath, PDOKAN_IO_SECURITY_CONTEXT SecurityContext, ACCESS_MASK DesiredAccess, ULONG FileAttributes, ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions, PDOKAN_FILE_INFO DokanFileInfo)
{
    VFS_ENTRY VfsEntry;
    CHAR uszPath[MAX_PATH];
    LPSTR uszFile;
    BOOL fIsDirectoryExisting = FALSE;
    UNREFERENCED_PARAMETER(SecurityContext);
    UNREFERENCED_PARAMETER(FileAttributes);
    if(!ctxVfs || !ctxVfs->fInitialized) { return STATUS_FILE_INVALID; }
    // root directory
    if(!strcmp(uszFullPath, "\\")) {
        if(CreateDisposition == CREATE_ALWAYS) { return ctxVfs->DokanNtStatusFromWin32(ERROR_ACCESS_DENIED); }
        DokanFileInfo->IsDirectory = TRUE;
        return STATUS_SUCCESS;
    }
    // other files
    if(CreateDisposition == CREATE_ALWAYS) { return ctxVfs->DokanNtStatusFromWin32(ERROR_ACCESS_DENIED); }
    uszFile = CharUtil_PathSplitLastEx(uszFullPath, uszPath, sizeof(uszPath));
    if(!VfsList_GetSingle(uszPath[0] ? uszPath : "\\", uszFile, &VfsEntry, &fIsDirectoryExisting)) {
        return fIsDirectoryExisting ? STATUS_OBJECT_NAME_NOT_FOUND : STATUS_OBJECT_PATH_NOT_FOUND;
    }
    DokanFileInfo->Nocache = TRUE;
    if(!DokanFileInfo->IsDirectory && (CreateOptions & FILE_DIRECTORY_FILE)) { return STATUS_NOT_A_DIRECTORY; }     // fail upon open normal file as directory
    return (CreateDisposition == OPEN_ALWAYS) ? STATUS_OBJECT_NAME_COLLISION : STATUS_SUCCESS;
}

NTSTATUS DOKAN_CALLBACK
VfsDokanCallback_CreateFile(LPCWSTR FileName, PDOKAN_IO_SECURITY_CONTEXT SecurityContext, ACCESS_MASK DesiredAccess, ULONG FileAttributes, ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions, PDOKAN_FILE_INFO DokanFileInfo)
{
    UINT64 tmStart = dbg_GetTickCount64();
    NTSTATUS nt;
    LPSTR uszFullPath;
    BYTE pbBuffer[3 * MAX_PATH];
    if(!CharUtil_WtoU((LPWSTR)FileName, -1, pbBuffer, sizeof(pbBuffer), &uszFullPath, NULL, 0)) { return STATUS_OBJECT_NAME_NOT_FOUND; }
    if(!ctxVfs || !ctxVfs->fInitialized) { return STATUS_FILE_INVALID; }
    nt = VfsDokanCallback_CreateFile_Impl(uszFullPath, SecurityContext, DesiredAccess, FileAttributes, ShareAccess, CreateDisposition, CreateOptions, DokanFileInfo);
    dbg_wprintf(L"DEBUG::%08x %8x VfsCallback_CreateFile:\t\t 0x%08x %s [ %08x %08x %08x %08x ]\n", (DWORD)(dbg_GetTickCount64() - tmStart), nt, FileName, FileAttributes, ShareAccess, CreateDisposition, CreateOptions);
    return nt;
}

NTSTATUS DOKAN_CALLBACK
VfsDokanCallback_GetFileInformation_Impl(_In_ LPSTR uszFullPath, _Inout_ LPBY_HANDLE_FILE_INFORMATION hfi, _In_ PDOKAN_FILE_INFO DokanFileInfo)
{
    UINT64 tmStart = dbg_GetTickCount64();
    VFS_ENTRY VfsEntry;
    CHAR uszPath[MAX_PATH];
    LPSTR uszFile;
    BOOL fIsDirectoryExisting = FALSE;
    if(!ctxVfs || !ctxVfs->fInitialized) { return STATUS_FILE_INVALID; }
    dbg_wprintf_init(L"DEBUG::%08x -------- VfsCallback_GetFileInformation:\t 0x%08x %s\n", 0, wcsFileName);
    // matches: root directory
    if(!strcmp(uszFullPath, "\\")) {
        hfi->ftCreationTime = ctxVfs->ftDefaultTime;
        hfi->ftLastWriteTime = ctxVfs->ftDefaultTime;
        hfi->ftLastAccessTime = ctxVfs->ftDefaultTime;
        hfi->nFileSizeHigh = 0;
        hfi->nFileSizeLow = 0;
        hfi->dwFileAttributes = FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_NOT_CONTENT_INDEXED;
        dbg_wprintf(L"DEBUG::%08x %8x VfsCallback_GetFileInformation:\t 0x%08x %S\n", (DWORD)(dbg_GetTickCount64() - tmStart), STATUS_SUCCESS, uszFullPath);
        return STATUS_SUCCESS;
    }
    uszFile = CharUtil_PathSplitLastEx(uszFullPath, uszPath, sizeof(uszPath));

    if(!VfsList_GetSingle((uszPath[0] ? uszPath : "\\"), uszFile, &VfsEntry, &fIsDirectoryExisting)) {
        dbg_wprintf(L"DEBUG::%08x %8x VfsCallback_GetFileInformation:\t 0x%08x %S\n", (DWORD)(dbg_GetTickCount64() - tmStart), STATUS_FILE_NOT_AVAILABLE, uszFullPath);
        return STATUS_FILE_NOT_AVAILABLE;
    }
    hfi->dwFileAttributes = VfsEntry.dwFileAttributes;
    hfi->ftCreationTime = VfsEntry.ftCreationTime;
    hfi->ftLastAccessTime = VfsEntry.ftLastAccessTime;
    hfi->ftLastWriteTime = VfsEntry.ftLastWriteTime;
    hfi->nFileSizeHigh = (DWORD)(VfsEntry.cbFileSize >> 32);
    hfi->nFileSizeLow = (DWORD)(VfsEntry.cbFileSize);
    hfi->nFileIndexHigh = CharUtil_Hash32U(uszFullPath, TRUE);
    hfi->nFileIndexLow = CharUtil_Hash32U(VfsEntry.uszName, TRUE);
    dbg_wprintf(L"DEBUG::%08x %8x VfsCallback_GetFileInformation:\t 0x%08x %S\t [ %08x %08x%08x %016llx %016llx %016llx ]\n",
        (DWORD)(dbg_GetTickCount64() - tmStart),
        STATUS_SUCCESS,
        uszFullPath,
        hfi->dwFileAttributes,
        hfi->nFileSizeHigh, hfi->nFileSizeLow,
        *(PQWORD)&hfi->ftCreationTime,
        *(PQWORD)&hfi->ftLastAccessTime,
        *(PQWORD)&hfi->ftLastWriteTime
    );
    return STATUS_SUCCESS;
}

NTSTATUS DOKAN_CALLBACK
VfsDokanCallback_GetFileInformation(_In_ LPCWSTR wcsFileName, _Inout_ LPBY_HANDLE_FILE_INFORMATION hfi, _In_ PDOKAN_FILE_INFO DokanFileInfo)
{
    LPSTR uszFullPath;
    BYTE pbBuffer[3 * MAX_PATH];
    if(!CharUtil_WtoU((LPWSTR)wcsFileName, -1, pbBuffer, sizeof(pbBuffer), &uszFullPath, NULL, 0)) { return STATUS_FILE_INVALID; }
    return VfsDokanCallback_GetFileInformation_Impl(uszFullPath, hfi, DokanFileInfo);
}

NTSTATUS DOKAN_CALLBACK
VfsDokanCallback_FindFiles(LPCWSTR wcsFileName, PFillFindData FillFindData, PDOKAN_FILE_INFO DokanFileInfo)
{
    UINT64 tmStart = dbg_GetTickCount64();
    if(!ctxVfs || !ctxVfs->fInitialized) { return STATUS_FILE_INVALID; }
    dbg_wprintf_init(L"DEBUG::%08x -------- VfsCallback_FindFiles:\t\t\t 0x%08x %s\n", 0, wcsFileName);
    VfsList_ListDirectoryW((LPWSTR)wcsFileName, DokanFileInfo, (PFN_VFSLISTW_CALLBACK)FillFindData);
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
    nt = VMMDLL_VfsReadW(g_hVMM, (LPWSTR)wcsFileName, Buffer, BufferLength, ReadLength, Offset);
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
    nt = VMMDLL_VfsWriteW(g_hVMM, (LPWSTR)wcsFileName, (PBYTE)Buffer, NumberOfBytesToWrite, NumberOfBytesWritten, Offset);
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
    BOOL(WINAPI * pfnDokanUnmount)(WCHAR DriveLetter);
    if(ctxVfs && ctxVfs->fInitialized) {
        ctxVfs->fInitialized = FALSE;
        if(wchMountPoint) {
            hModuleDokan = LoadLibraryExA("dokan2.dll", NULL, LOAD_LIBRARY_SEARCH_SYSTEM32);
            if(!hModuleDokan) {
                hModuleDokan = LoadLibraryA("dokan2.dll");
            }
            if(hModuleDokan) {
                pfnDokanUnmount = (BOOL(WINAPI *)(WCHAR))GetProcAddress(hModuleDokan, "DokanUnmount");
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

#ifdef VMM_PROFILE_FULL
#include "ex/memprocfs_ex.h"
#else /* VMM_PROFILE_FULL */
#define MEMPROCFS_IS_OPENSOURCE 1
#define MEMPROCFS_SPLASH \
    "==============================  MemProcFS  ==============================\n" \
    " - Author:           Ulf Frisk - pcileech@frizk.net                      \n" \
    " - Info:             https://github.com/ufrisk/MemProcFS                 \n" \
    " - Discord:          https://discord.gg/pcileech                         \n" \
    " - License:          GNU Affero General Public License v3.0              \n" \
    " - Licensed To:      %s\n"                                                   \
    "   --------------------------------------------------------------------- \n" \
    "   MemProcFS is free open source software. If you find it useful please  \n" \
    "   become a sponsor at: https://github.com/sponsors/ufrisk Thank You :)  \n" \
    "   --------------------------------------------------------------------- \n"
#endif /* VMM_PROFILE_FULL */

VOID VfsDokan_InitializeAndMount_DisplayInfo(LPWSTR wszMountPoint)
{
    ULONG64 qwVersionVmmMajor = 0, qwVersionVmmMinor = 0, qwVersionVmmRevision = 0;
    ULONG64 qwVersionWinMajor = 0, qwVersionWinMinor = 0, qwVersionWinBuild = 0;
    ULONG64 qwUniqueSystemId = 0, iMemoryModel;
    LPSTR uszLicensedTo = NULL;
    BOOL fGPL;
    // get vmm.dll versions
    VMMDLL_ConfigGet(g_hVMM, VMMDLL_OPT_CONFIG_VMM_VERSION_MAJOR, &qwVersionVmmMajor);
    VMMDLL_ConfigGet(g_hVMM, VMMDLL_OPT_CONFIG_VMM_VERSION_MINOR, &qwVersionVmmMinor);
    VMMDLL_ConfigGet(g_hVMM, VMMDLL_OPT_CONFIG_VMM_VERSION_REVISION, &qwVersionVmmRevision);
    // get operating system versions
    VMMDLL_ConfigGet(g_hVMM, VMMDLL_OPT_CORE_MEMORYMODEL, &iMemoryModel);
    VMMDLL_ConfigGet(g_hVMM, VMMDLL_OPT_WIN_VERSION_MAJOR, &qwVersionWinMajor);
    VMMDLL_ConfigGet(g_hVMM, VMMDLL_OPT_WIN_VERSION_MINOR, &qwVersionWinMinor);
    VMMDLL_ConfigGet(g_hVMM, VMMDLL_OPT_WIN_VERSION_BUILD, &qwVersionWinBuild);
    VMMDLL_ConfigGet(g_hVMM, VMMDLL_OPT_WIN_SYSTEM_UNIQUE_ID, &qwUniqueSystemId);
    uszLicensedTo = VMMDLL_LicensedTo();
    if(!uszLicensedTo) {
        printf("[CRITICAL] A valid license could not be found. Terminating.\n");
        exit(1);
        return;
    }
    fGPL = strstr(uszLicensedTo, "General Public License") != NULL;
    if((MEMPROCFS_IS_OPENSOURCE && !fGPL) || (!MEMPROCFS_IS_OPENSOURCE && fGPL)) {
        printf("[CRITICAL] License mis-match. Terminating.\n");
        exit(1);
        return;
    }
    printf("\n"MEMPROCFS_SPLASH \
        " - Version:          %i.%i.%i (%s)\n" \
        " - Mount Point:      %S           \n" \
        " - Tag:              %i_%x        \n",
        uszLicensedTo,
        (DWORD)qwVersionVmmMajor, (DWORD)qwVersionVmmMinor, (DWORD)qwVersionVmmRevision, VER_OSARCH,
        wszMountPoint, (DWORD)qwVersionWinBuild, (DWORD)qwUniqueSystemId);
    if(qwVersionWinMajor && (iMemoryModel < (sizeof(VMMDLL_MEMORYMODEL_TOSTRING) / sizeof(LPSTR)))) {
        printf(" - Operating System: Windows %i.%i.%i (%s)\n",
            (DWORD)qwVersionWinMajor, (DWORD)qwVersionWinMinor, (DWORD)qwVersionWinBuild, VMMDLL_MEMORYMODEL_TOSTRING[iMemoryModel]);
    } else {
        printf(" - Operating System: Unknown\n");
    }
    printf("==========================================================================\n\n");
    VMMDLL_MemFree(uszLicensedTo);
}

VOID VfsDokan_InitializeAndMount(_In_ CHAR chMountPoint)
{
    int status;
    HMODULE hModuleDokan = NULL;
    PDOKAN_OPTIONS pDokanOptions = NULL;
    PDOKAN_OPERATIONS pDokanOperations = NULL;
    WCHAR wszMountPoint[] = { 'M', ':', '\\', 0 };
    WCHAR wszUnc[] = { '\\', 'M', 'e', 'm', 'P', 'r', 'o', 'c', 'F', 'S', '\\', 'M', 0};
    SYSTEMTIME SystemTimeNow;
    VOID(WINAPI *pfnDokanInit)();
    int(WINAPI *pfnDokanMain)(PDOKAN_OPTIONS, PDOKAN_OPERATIONS);
    VOID(WINAPI *pfnDokanShutdown)();
    // allocate
    hModuleDokan = LoadLibraryExA("dokan2.dll", NULL, LOAD_LIBRARY_SEARCH_SYSTEM32);
    if(!hModuleDokan) {
        hModuleDokan = LoadLibraryA("dokan2.dll");
    }
    if(!hModuleDokan) {
        printf("MOUNT: Failed. The required DOKANY file system library is not installed. \n");
        printf("Please download from : https://github.com/dokan-dev/dokany/releases/latest\n");
        goto fail;
    }
    pfnDokanInit = (VOID(WINAPI*)())GetProcAddress(hModuleDokan, "DokanInit");
    pfnDokanMain = (int(WINAPI*)(PDOKAN_OPTIONS, PDOKAN_OPERATIONS))GetProcAddress(hModuleDokan, "DokanMain");
    pfnDokanShutdown = (VOID(WINAPI*)())GetProcAddress(hModuleDokan, "DokanShutdown");
    if(!pfnDokanMain || !pfnDokanInit || !pfnDokanShutdown) {
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
    // set vfs context
    GetSystemTime(&SystemTimeNow);
    SystemTimeToFileTime(&SystemTimeNow, &ctxVfs->ftDefaultTime);
    ctxVfs->DokanNtStatusFromWin32 = (NTSTATUS(*)(DWORD))GetProcAddress(hModuleDokan, "DokanNtStatusFromWin32");
    ctxVfs->fInitialized = TRUE;
    // set options
    pDokanOptions->Version = DOKAN_VERSION;
    pDokanOptions->Options |= DOKAN_OPTION_NETWORK;
    wszUnc[11] = chMountPoint;
    pDokanOptions->UNCName = wszUnc;
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
    VfsDokan_InitializeAndMount_DisplayInfo(wszMountPoint);
    // mount file system
    pfnDokanInit();
    status = pfnDokanMain(pDokanOptions, pDokanOperations);
    while(ctxVfs && ctxVfs->fInitialized && (status == DOKAN_SUCCESS)) {
        printf("MOUNT: ReMounting as drive %S\n", pDokanOptions->MountPoint);
        status = pfnDokanMain(pDokanOptions, pDokanOperations);
    }
    pfnDokanShutdown();
    if(status == -5) {
        printf("MOUNT: Failed: drive busy/already mounted.\n");
    } else if(status) {
        printf("MOUNT: Failed. Status Code: %i\n", status);
    }
fail:
    if(hModuleDokan) { FreeLibrary(hModuleDokan); }
    LocalFree(pDokanOptions);
    LocalFree(pDokanOperations);
    VfsDokan_Close(0);
}



//-----------------------------------------------------------------------------
// GENERAL INITIALIZATION FUNCTIONALITY BELOW:
//-----------------------------------------------------------------------------

_Success_(return) BOOL MemProcFS_VfsListU(_In_ LPSTR uszPath, _Inout_ PVMMDLL_VFS_FILELIST2 pFileList)
{
    return VMMDLL_VfsListU(g_hVMM, uszPath, pFileList);
}

/*
* Retrieve the mount point from the command line arguments.
* If no '-mount' command line argument is given the default mount point will be M:
* _EXCEPT_ if '-pythonexec' is also given in which case '\0' will be returned.
* -- argc
* -- argv
* -- pfMountSpecified
* -- pfPythonExec
* -- return = the mount point as a drive letter.
*/
CHAR GetMountPoint(_In_ DWORD argc, _In_ char* argv[], _Out_ PBOOL pfMountSpecified, _Out_ PBOOL pfPythonExec)
{
    CHAR chMountPoint = 'M';
    DWORD i = 1;
    *pfPythonExec = FALSE;
    *pfMountSpecified = FALSE;
    for(i = 0; i < argc - 1; i++) {
        if(0 == strcmp(argv[i], "-mount")) {
            chMountPoint = argv[i + 1][0];
            *pfMountSpecified = TRUE;
        }
        if(0 == strcmp(argv[i], "-pythonexec")) {
            *pfPythonExec = TRUE;
        }
    }
    if(chMountPoint >= 'a' && chMountPoint <= 'z') {
        chMountPoint = chMountPoint - 'a' + 'A';
    }
    return chMountPoint;
}

/*
* Call the VMMDLL_Close() function in a separate newly create thread.
* This will allow the main thread to exit even if the VMMDLL_Close()
* function should happen to get stuck.
* -- pv
*/
DWORD WINAPI MemProcFsCtrlHandler_TryShutdownThread(PVOID pv)
{
    __try {
        VfsDokan_Close(g_VfsMountPoint);
        VfsList_Close();
    } __except(EXCEPTION_EXECUTE_HANDLER) { ; }
    __try {
        VMMDLL_CloseAll();
    } __except(EXCEPTION_EXECUTE_HANDLER) { ; }
    return 1;
}

/*
* SetConsoleCtrlHandler for the MemProcFS - clean up whenever CTRL+C is pressed.
* If this is not here MemProcFS might not exit otherwise if there are lingering
* threads most notably in the Python plugin functionality.
* -- fdwCtrlType
* -- return
*/
BOOL WINAPI MemProcFsCtrlHandler(DWORD fdwCtrlType)
{
	HANDLE hThread;
    if (fdwCtrlType == CTRL_C_EVENT) {
        printf("CTRL+C detected - shutting down ...\n");
        hThread = CreateThread(NULL, 0, MemProcFsCtrlHandler_TryShutdownThread, NULL, 0, NULL);
		if(hThread) { WaitForSingleObject(hThread, INFINITE); }
        TerminateProcess(GetCurrentProcess(), 1);
        Sleep(1000);
        ExitProcess(1);
        return TRUE;
    }
    if(fdwCtrlType == CTRL_BREAK_EVENT) {
        printf("CTRL+BREAK detected - refresh/debug initated ...\n");
        VMMDLL_ConfigSet(g_hVMM, VMMDLL_OPT_CONFIG_DEBUG, 1);
        printf("CTRL+BREAK finished ...\n");
        return TRUE;
    }
    return FALSE;
}

/*
* Main entry point of MemProcFS. The main function will load and initialize
* VMM.DLL then initialize the VMM.DLL plugin manager and then hand over control
* to vfs.c!VfsInitializeAndMount which will start the virtual file system and
* mount it at the correct mount point.
* All 'interesting' functionality will take part in VMM.DLL - the memprocfs
* executable should be considered as a thin wrapper around VMM.DLL.
* -- argc
* -- argv
* -- return
*/
int main(_In_ int argc, _In_ char* argv[])
{
    // MAIN FUNCTION PROPER BELOW:
    int i;
    BOOL result, fMountSpecified, fPythonExec;
    LPSTR *szArgs = NULL;
    LC_CMD_AGENT_VFS_REQ Req = { 0 };
    g_VfsMountPoint = GetMountPoint(argc, argv, &fMountSpecified, &fPythonExec);
    if(g_VfsMountPoint < 'A' || g_VfsMountPoint > 'Z') {
        if(!fPythonExec || fMountSpecified) {
            printf("MemProcFS: Invalid -mount specified (only A-Z allowed).\n");
            return 1;
        }
    }
    LoadLibraryA("leechcore.dll");
    if(!(szArgs = LocalAlloc(LMEM_ZEROINIT, (argc + 1ULL) * sizeof(LPSTR)))) {
        printf("MemProcFS: Out of memory!\n");
        return 1;
    }
    SetConsoleCtrlHandler(MemProcFsCtrlHandler, TRUE);
    szArgs[0] = "-printf";
    for(i = 1; i < argc; i++) {
        szArgs[i] = argv[i];
    }
    if(argc > 2) {
        szArgs[argc++] = "-userinteract";
    }
    g_hVMM = VMMDLL_Initialize(argc, szArgs);
    if(!g_hVMM) {
        // any error message will already be shown by the InitializeReserved function.
        return 1;
    }
    if(fPythonExec && !fMountSpecified) {
        VMMDLL_CloseAll();
        return 0;
    }
    VMMDLL_ConfigSet(g_hVMM, VMMDLL_OPT_CONFIG_STATISTICS_FUNCTIONCALL, 1);
    result = VMMDLL_InitializePlugins(g_hVMM);
    if(!result) {
        printf("MemProcFS: Error file system plugins in vmm.dll!\n");
        return 1;
    }
    SetConsoleCtrlHandler(MemProcFsCtrlHandler, TRUE);
    VfsList_Initialize(MemProcFS_VfsListU, 500, 128, FALSE);
    VfsDokan_InitializeAndMount(g_VfsMountPoint);
    CreateThread(NULL, 0, MemProcFsCtrlHandler_TryShutdownThread, NULL, 0, NULL);
    Sleep(250);
    TerminateProcess(GetCurrentProcess(), 1);
    Sleep(500);
    ExitProcess(1);
    return 0;
}

#endif /* _WIN32 */
