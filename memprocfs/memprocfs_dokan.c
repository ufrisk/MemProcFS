// memprocfs_dokan.c : implementation of core functionality for the Memory Process File System
// This is just a thin loader for the virtual memory manager dll which contains the logic.
//
// (c) Ulf Frisk, 2018-2022
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

DWORD g_dbg_c = 0;

//#define dbg_GetTickCount64()            GetTickCount64()
//#define dbg_wprintf_init(format, ...)   { wprintf(format, ++g_dbg_c, ##__VA_ARGS__); }
//#define dbg_wprintf(format, ...)        { wprintf(format, ++g_dbg_c, ##__VA_ARGS__); }
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
HANDLE g_hLC_RemoteFS;

CHAR g_VfsMountPoint = 'M';



//-----------------------------------------------------------------------------
// LOCAL/REMOTE WRAPPER FUNCTIONS BELOW:
//-----------------------------------------------------------------------------

/*
* WRAPPER FUNCTION AROUND LOCAL/REMOTE VMMDLL_VfsListU
* List a directory of files in MemProcFS. Directories and files will be listed
* by callbacks into functions supplied in the pFileList parameter.
* If information of an individual file is needed it's neccessary to list all
* files in its directory.
* -- uszPath
* -- pFileList
* -- return
*/
_Success_(return) BOOL MemProcFS_VfsListU(_In_ LPSTR uszPath, _Inout_ PVMMDLL_VFS_FILELIST2 pFileList)
{
    DWORD i;
    LC_CMD_AGENT_VFS_REQ Req;
    PLC_CMD_AGENT_VFS_RSP pRsp = NULL;
    PVMMDLL_VFS_FILELISTBLOB pVfsList;
    PVMMDLL_VFS_FILELISTBLOB_ENTRY pe;
    if(!g_hLC_RemoteFS) {
        return VMMDLL_VfsListU(uszPath, pFileList);
    }
    ZeroMemory(&Req, sizeof(LC_CMD_AGENT_VFS_REQ));
    Req.dwVersion = LC_CMD_AGENT_VFS_REQ_VERSION;
    if(!CharUtil_UtoU(uszPath, -1, Req.uszPathFile, sizeof(Req.uszPathFile), NULL, NULL, CHARUTIL_FLAG_STR_BUFONLY)) { goto fail; }
    if(!LcCommand(g_hLC_RemoteFS, LC_CMD_AGENT_VFS_LIST, sizeof(LC_CMD_AGENT_VFS_REQ), (PBYTE)&Req, (PBYTE *)&pRsp, NULL) || !pRsp) { goto fail; }
    pVfsList = (PVMMDLL_VFS_FILELISTBLOB)pRsp->pb;      // sanity/security checks on remote deta done in leechcore
    pVfsList->uszMultiText = (LPSTR)pVfsList + (QWORD)pVfsList->uszMultiText;
    for(i = 0; i < pVfsList->cFileEntry; i++) {
        pe = pVfsList->FileEntry + i;
        if(pe->cbFileSize == (QWORD)-1) {
            pFileList->pfnAddDirectory(pFileList->h, pVfsList->uszMultiText + pe->ouszName, (PVMMDLL_VFS_FILELIST_EXINFO)&pe->ExInfo);
        } else {
            pFileList->pfnAddFile(pFileList->h, pVfsList->uszMultiText + pe->ouszName, pe->cbFileSize, (PVMMDLL_VFS_FILELIST_EXINFO)&pe->ExInfo);
        }
    }
fail:
    LocalFree(pRsp);
    return TRUE;
}

/*
* WRAPPER FUNCTION AROUND LOCAL/REMOTE VMMDLL_VfsReadW
* Read select parts of a file in MemProcFS.
* -- wszFileName
* -- pb
* -- cb
* -- pcbRead
* -- cbOffset
* -- return
*/
NTSTATUS MemProcFS_VfsReadW(_In_ LPWSTR wszFileName, _Out_writes_to_(cb, *pcbRead) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ ULONG64 cbOffset)
{
    NTSTATUS nt = VMMDLL_STATUS_FILE_INVALID;
    LC_CMD_AGENT_VFS_REQ Req;
    PLC_CMD_AGENT_VFS_RSP pRsp = NULL;
    if(!g_hLC_RemoteFS) {
        return VMMDLL_VfsReadW(wszFileName, pb, cb, pcbRead, cbOffset);
    }
    // Remote MemProcFS below:
    ZeroMemory(&Req, sizeof(LC_CMD_AGENT_VFS_REQ));
    Req.dwVersion = LC_CMD_AGENT_VFS_REQ_VERSION;
    Req.qwOffset = cbOffset;
    Req.dwLength = cb;
    if(!CharUtil_WtoU(wszFileName, -1, Req.uszPathFile, sizeof(Req.uszPathFile), NULL, NULL, CHARUTIL_FLAG_STR_BUFONLY)) { goto fail; }
    if(!LcCommand(g_hLC_RemoteFS, LC_CMD_AGENT_VFS_READ, sizeof(LC_CMD_AGENT_VFS_REQ), (PBYTE)&Req, (PBYTE *)&pRsp, NULL) || !pRsp) { goto fail; }
    nt = pRsp->dwStatus;
    *pcbRead = min(cb, pRsp->cb);
    memcpy(pb, pRsp->pb, *pcbRead);
fail:
    LocalFree(pRsp);
    return nt;
}

/*
* WRAPPER FUNCTION AROUND LOCAL/REMOTE VMMDLL_VfsWriteW
* Write select parts to a file in MemProcFS.
* -- wszFileName
* -- pb
* -- cb
* -- pcbWrite
* -- cbOffset
* -- return
*/
NTSTATUS MemProcFS_VfsWriteW(_In_ LPWSTR wszFileName, _In_reads_(cb) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbWrite, _In_ ULONG64 cbOffset)
{
    NTSTATUS nt = VMMDLL_STATUS_FILE_INVALID;
    PLC_CMD_AGENT_VFS_REQ pReq = NULL;
    PLC_CMD_AGENT_VFS_RSP pRsp = NULL;
    if(!g_hLC_RemoteFS) {
        return VMMDLL_VfsWriteW(wszFileName, pb, cb, pcbWrite, cbOffset);
    }
    // Remote MemProcFS below:
    *pcbWrite = 0;
    if(!(pReq = LocalAlloc(0, sizeof(LC_CMD_AGENT_VFS_REQ) + cb))) { goto fail; }
    ZeroMemory(pReq, sizeof(LC_CMD_AGENT_VFS_REQ));
    pReq->dwVersion = LC_CMD_AGENT_VFS_REQ_VERSION;
    pReq->qwOffset = cbOffset;
    pReq->dwLength = cb;
    pReq->cb = cb;
    memcpy(pReq->pb, pb, cb);
    if(!CharUtil_WtoU(wszFileName, -1, pReq->uszPathFile, sizeof(pReq->uszPathFile), NULL, NULL, CHARUTIL_FLAG_STR_BUFONLY)) { goto fail; }
    if(!LcCommand(g_hLC_RemoteFS, LC_CMD_AGENT_VFS_WRITE, sizeof(LC_CMD_AGENT_VFS_REQ) + cb, (PBYTE)pReq, (PBYTE *)&pRsp, NULL) || !pRsp) { goto fail; }
    nt = pRsp->dwStatus;
    *pcbWrite = min(cb, pRsp->cbReadWrite);
fail:
    LocalFree(pReq);
    LocalFree(pRsp);
    return nt;
}

/*
* WRAPPER FUNCTION AROUND LOCAL/REMOTE VMMDLL_ConfigGet
* Set a device specific option value. Please see defines VMMDLL_OPT_* for infor-
* mation about valid option values. Please note that option values may overlap
* between different device types with different meanings.
* -- fOption
* -- pqwValue = pointer to ULONG64 to receive option value.
* -- return = success/fail.
*/
_Success_(return)
BOOL MemProcFS_ConfigGet(_In_ ULONG64 fOption, _Out_ PULONG64 pqwValue)
{
    BOOL fResult;
    LC_CMD_AGENT_VFS_REQ Req = { 0 };
    PLC_CMD_AGENT_VFS_RSP pRsp = NULL;
    *pqwValue = 0;
    if(!g_hLC_RemoteFS) {
        return VMMDLL_ConfigGet(fOption, pqwValue);
    }
    // Remote MemProcFS below:
    Req.dwVersion = LC_CMD_AGENT_VFS_REQ_VERSION;
    Req.fOption = fOption;
    fResult = LcCommand(g_hLC_RemoteFS, LC_CMD_AGENT_VFS_OPT_GET, sizeof(LC_CMD_AGENT_VFS_REQ), (PBYTE)&Req, (PBYTE *)&pRsp, NULL);
    if(!fResult) { return FALSE; }
    if((fResult = (pRsp->cb == sizeof(QWORD)))) {
        *pqwValue = *(PQWORD)pRsp->pb;
    }
    LocalFree(pRsp);
    return fResult;
}

/*
* WRAPPER FUNCTION AROUND LOCAL/REMOTE VMMDLL_ConfigSet
* Set a device specific option value. Please see defines VMMDLL_OPT_* for infor-
* mation about valid option values. Please note that option values may overlap
* between different device types with different meanings.
* -- fOption
* -- qwValue
* -- return = success/fail.
*/
_Success_(return)
BOOL MemProcFS_ConfigSet(_In_ ULONG64 fOption, _In_ ULONG64 qwValue)
{
    BOOL fResult;
    PLC_CMD_AGENT_VFS_REQ pReq = NULL;
    if(!g_hLC_RemoteFS) {
        return VMMDLL_ConfigSet(fOption, qwValue);
    }
    // Remote MemProcFS below:
    if(!(pReq = LocalAlloc(LMEM_ZEROINIT, sizeof(LC_CMD_AGENT_VFS_REQ) + sizeof(QWORD)))) { return FALSE; }
    pReq->dwVersion = LC_CMD_AGENT_VFS_REQ_VERSION;
    pReq->fOption = fOption;
    pReq->cb = sizeof(QWORD);
    *(PQWORD)pReq->pb = 1ULL;
    fResult = LcCommand(g_hLC_RemoteFS, LC_CMD_AGENT_VFS_OPT_SET, sizeof(LC_CMD_AGENT_VFS_REQ) + sizeof(QWORD), (PBYTE)pReq, NULL, NULL);
    LocalFree(pReq);
    return fResult;
}



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
    nt = MemProcFS_VfsReadW((LPWSTR)wcsFileName, Buffer, BufferLength, ReadLength, Offset);
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
    nt = MemProcFS_VfsWriteW((LPWSTR)wcsFileName, (PBYTE)Buffer, NumberOfBytesToWrite, NumberOfBytesWritten, Offset);
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
            hModuleDokan = LoadLibraryExA("dokan1.dll", NULL, LOAD_LIBRARY_SEARCH_SYSTEM32);
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

VOID VfsDokan_InitializeAndMount_DisplayInfo(LPWSTR wszMountPoint)
{
    ULONG64 qwVersionVmmMajor = 0, qwVersionVmmMinor = 0, qwVersionVmmRevision = 0;
    ULONG64 qwVersionWinMajor = 0, qwVersionWinMinor = 0, qwVersionWinBuild = 0;
    ULONG64 qwUniqueSystemId = 0, iMemoryModel;
    // get vmm.dll versions
    MemProcFS_ConfigGet(VMMDLL_OPT_CONFIG_VMM_VERSION_MAJOR, &qwVersionVmmMajor);
    MemProcFS_ConfigGet(VMMDLL_OPT_CONFIG_VMM_VERSION_MINOR, &qwVersionVmmMinor);
    MemProcFS_ConfigGet(VMMDLL_OPT_CONFIG_VMM_VERSION_REVISION, &qwVersionVmmRevision);
    // get operating system versions
    MemProcFS_ConfigGet(VMMDLL_OPT_CORE_MEMORYMODEL, &iMemoryModel);
    MemProcFS_ConfigGet(VMMDLL_OPT_WIN_VERSION_MAJOR, &qwVersionWinMajor);
    MemProcFS_ConfigGet(VMMDLL_OPT_WIN_VERSION_MINOR, &qwVersionWinMinor);
    MemProcFS_ConfigGet(VMMDLL_OPT_WIN_VERSION_BUILD, &qwVersionWinBuild);
    MemProcFS_ConfigGet(VMMDLL_OPT_WIN_SYSTEM_UNIQUE_ID, &qwUniqueSystemId);
    printf("\n" \
        "=============== MemProcFS - THE MEMORY PROCESS FILE SYSTEM ===============\n" \
        " - Author:           Ulf Frisk - pcileech@frizk.net                     \n" \
        " - Info:             https://github.com/ufrisk/MemProcFS                \n" \
        " - License:          GNU Affero General Public License v3.0             \n" \
        "   -------------------------------------------------------------------- \n" \
        "   MemProcFS is free open source software. If you find it useful please \n" \
        "   become a sponsor at: https://github.com/sponsors/ufrisk Thank You :) \n" \
        "   -------------------------------------------------------------------- \n" \
        " - Version:          %i.%i.%i (%s)\n" \
        " - Mount Point:      %S           \n" \
        " - Tag:              %i_%x        \n",
        (DWORD)qwVersionVmmMajor, (DWORD)qwVersionVmmMinor, (DWORD)qwVersionVmmRevision, VER_OSARCH,
        wszMountPoint, (DWORD)qwVersionWinBuild, (DWORD)qwUniqueSystemId);
    if(qwVersionWinMajor && (iMemoryModel < (sizeof(VMMDLL_MEMORYMODEL_TOSTRING) / sizeof(LPSTR)))) {
        printf(" - Operating System: Windows %i.%i.%i (%s)\n",
            (DWORD)qwVersionWinMajor, (DWORD)qwVersionWinMinor, (DWORD)qwVersionWinBuild, VMMDLL_MEMORYMODEL_TOSTRING[iMemoryModel]);
    } else {
        printf(" - Operating System: Unknown\n");
    }
    printf("==========================================================================\n\n");
}

VOID VfsDokan_InitializeAndMount(_In_ CHAR chMountPoint)
{
    int status;
    HMODULE hModuleDokan = NULL;
    PDOKAN_OPTIONS pDokanOptions = NULL;
    PDOKAN_OPERATIONS pDokanOperations = NULL;
    WCHAR wszMountPoint[] = { 'M', ':', '\\', 0 };
    SYSTEMTIME SystemTimeNow;
    VOID(WINAPI *pfnDokanInit)();
    int(WINAPI *pfnDokanMain)(PDOKAN_OPTIONS, PDOKAN_OPERATIONS);
    VOID(WINAPI *pfnDokanShutdown)();
    // allocate
    hModuleDokan = LoadLibraryExA("dokan2.dll", NULL, LOAD_LIBRARY_SEARCH_SYSTEM32);
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
    pDokanOptions->UNCName = L"MemProcFS";
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
    } else {
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


/*
* Retrieve the mount point from the command line arguments. If no '-mount'
* command line argument is given the default mount point will be: M:
* -- argc
* -- argv
* -- return = the mount point as a drive letter.
*/
CHAR GetMountPoint(_In_ DWORD argc, _In_ char* argv[])
{
    CHAR chMountMount = 'M';
    DWORD i = 1;
    for(i = 0; i < argc - 1; i++) {
        if(0 == strcmp(argv[i], "-mount")) {
            chMountMount = argv[i + 1][0];
            break;
        }
    }
    if((chMountMount > 'A' && chMountMount < 'Z') || (chMountMount > 'a' && chMountMount < 'z')) {
        return chMountMount;
    }
    return 'M';
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
        if(g_hLC_RemoteFS) {
            LcClose(g_hLC_RemoteFS);
            g_hLC_RemoteFS = NULL;
        } else {
            VMMDLL_Close();
        }
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
    return FALSE;
}

/*
* Initialize a remote instance of VMM.DLL instead of loading it into the
* process as is the default and preferred way.
* -- argc
* -- argv
* -- return
*/
_Success_(return)
BOOL MemProcFS_InitializeRemoteFS(_In_ int argc, _In_ char *argv[])
{
    int i;
    LC_CONFIG Dev = { 0 };
    // connect to remote system using LeechCore
    Dev.dwVersion = LC_CONFIG_VERSION;
    if(argc == 0) { return FALSE; }
    for(i = 0; i < argc - 1; i++) {
        if(!_stricmp("-device", argv[i])) {
            strncpy_s(Dev.szDevice, MAX_PATH, argv[i + 1], _TRUNCATE);
        }
        if(!_stricmp("-remote", argv[i])) {
            strncpy_s(Dev.szRemote, MAX_PATH, argv[i + 1], _TRUNCATE);
        }
    }
    if(!Dev.szDevice[0]) {
        printf("MemProcFS: missing required option: -device\n");
        return FALSE;
    }
    if(!Dev.szRemote[0]) {
        printf("MemProcFS: missing required option: -remote\n");
        return FALSE;
    }
    if(!(g_hLC_RemoteFS = LcCreate(&Dev))) {
        printf("MemProcFS: Failed to connect to the remote system.\n  Device: %s\n  Remote: %s\n", Dev.szDevice, Dev.szRemote);
        return FALSE;
    }
    // perform set operation (this will trigger a load of remote memory analysis)
    if(!MemProcFS_ConfigSet(VMMDLL_OPT_CONFIG_STATISTICS_FUNCTIONCALL, 1)) {
        printf("MemProcFS: Failed to initialize remote memory analysis.\n  Device: %s\n  Remote: %s\n", Dev.szDevice, Dev.szRemote);
        return FALSE;
    }
    return TRUE;
}

/*
* Main entry point of the memory process file system. The main function will
* load and initialize VMM.DLL then initialize the VMM.DLL plugin manager and
* then hand over control to vfs.c!VfsInitializeAndMount which will start the
* dokany virtual file system and mount it at the correct mount point.
* All 'interesting' functionality will take part in VMM.DLL - the memprocfs
* executable should be considered as a thin wrapper around VMM.DLL.
* -- argc
* -- argv
* -- return
*/
int main(_In_ int argc, _In_ char* argv[])
{
    // MAIN FUNCTION PROPER BELOW:
    BOOL result, fRemoteFS = FALSE;
    int i;
    HANDLE hLC_RemoteFS = 0;
    LPSTR *szArgs = NULL;
    LC_CMD_AGENT_VFS_REQ Req = { 0 };
    g_hLC_RemoteFS = 0;
    LoadLibraryA("leechcore.dll");
    if(!(szArgs = LocalAlloc(LMEM_ZEROINIT, (argc + 1ULL) * sizeof(LPSTR)))) {
        printf("MemProcFS: Out of memory!\n");
        return 1;
    }
    for(i = 1; i < argc; i++) {
        szArgs[i] = argv[i];
        if(!_stricmp(argv[i], "-remotefs")) { fRemoteFS = TRUE; }
    }
    if(fRemoteFS) {
        if(!MemProcFS_InitializeRemoteFS(argc, argv)) {
            // error message already given by MemProcFS_InitializeRemoteFS()
            return 1;
        }
    } else {
        szArgs[0] = "-printf";
        if(argc > 2) {
            szArgs[argc++] = "-userinteract";
        }
        result = VMMDLL_Initialize(argc, szArgs);
        if(!result) {
            // any error message will already be shown by the InitializeReserved function.
            return 1;
        }
        VMMDLL_ConfigSet(VMMDLL_OPT_CONFIG_STATISTICS_FUNCTIONCALL, 1);
        result = VMMDLL_InitializePlugins();
        if(!result) {
            printf("MemProcFS: Error file system plugins in vmm.dll!\n");
            return 1;
        }
    }
    VfsList_Initialize(MemProcFS_VfsListU, 500, 128, FALSE);
    SetConsoleCtrlHandler(MemProcFsCtrlHandler, TRUE);
    g_VfsMountPoint = GetMountPoint(argc, argv);
    VfsDokan_InitializeAndMount(g_VfsMountPoint);
    if(g_hLC_RemoteFS) {
        LcClose(g_hLC_RemoteFS);
        g_hLC_RemoteFS = NULL;
    }
    CreateThread(NULL, 0, MemProcFsCtrlHandler_TryShutdownThread, NULL, 0, NULL);
    Sleep(250);
    TerminateProcess(GetCurrentProcess(), 1);
    Sleep(500);
    ExitProcess(1);
    return 0;
}

#endif /* _WIN32 */
