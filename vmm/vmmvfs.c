// vmmvfs.c : implementation related to virtual memory management / virtual file system interfacing.
//
// (c) Ulf Frisk, 2018-2019
// Author: Ulf Frisk, pcileech@frizk.net
//
#include "vmm.h"
#include "vmmdll.h"
#include "m_vmmvfs_dump.h"
#include "pluginmanager.h"
#include "util.h"

typedef struct tdVMMVFS_PATH {
    WCHAR _wsz[MAX_PATH];
    BOOL fRoot;
    BOOL fNamePID;
    DWORD dwPID;
    LPWSTR wszPath1;
    LPWSTR wszPath2;
} VMMVFS_PATH, *PVMMVFS_PATH;

BOOL VmmVfs_UtilVmmGetPidDirFile(_In_ LPCWSTR wcsFileName, _Out_ PVMMVFS_PATH pPath)
{
    DWORD i = 0, iPID, iPath1 = 0, iPath2 = 0;
    ZeroMemory(pPath, sizeof(VMMVFS_PATH));
    wcsncpy_s(pPath->_wsz, MAX_PATH, wcsFileName, _TRUNCATE);
    // 1: Check for root only item
    pPath->fNamePID = !_wcsicmp(pPath->_wsz, L"\\name");
    pPath->fRoot = pPath->fNamePID || !_wcsicmp(pPath->_wsz, L"\\pid");
    if(pPath->fRoot) { return TRUE; }
    // 2: Check if starting with PID or NAME and move start index
    if(!wcsncmp(pPath->_wsz, L"\\pid\\", 5)) { i = 5; }
    if(!wcsncmp(pPath->_wsz, L"\\name\\", 6)) { i = 6; }
    if(i == 0) { return FALSE; }
    // 3: Locate start of PID number and 1st Path item (if any)
    while((i < MAX_PATH) && pPath->_wsz[i] && (pPath->_wsz[i] != '\\')) { i++; }
    if(pPath->_wsz[i]) { iPath1 = i + 1; }
    pPath->_wsz[i] = 0;
    i--;
    while((i > 0) && (pPath->_wsz[i] >= '0') && (pPath->_wsz[i] <= '9')) { i--; }
    iPID = i + 1;
    pPath->dwPID = (DWORD)Util_GetNumericW(&pPath->_wsz[iPID]);
    if(!iPath1) { return TRUE; }
    // 4: Locate 2nd Path item (if any)
    i = iPath1;
    while((i < MAX_PATH) && pPath->_wsz[i] && (pPath->_wsz[i] != '\\')) { i++; }
    if(pPath->_wsz[i]) {
        iPath2 = i + 1;
        pPath->_wsz[i] = 0;
    }
    // 7: Finish
    pPath->wszPath1 = &pPath->_wsz[iPath1];
    if(iPath2) {
        pPath->wszPath2 = &pPath->_wsz[iPath2];
    }
    return TRUE;
}

/*
* Set file timestamp into the ExInfo struct if possible.
* -- pProcess
* -- pExInfo
*/
VOID VmmVfs_UtilTimeStampFile(_In_opt_ PVMM_PROCESS pProcess, _Out_ PVMMDLL_VFS_FILELIST_EXINFO pExInfo)
{
    pExInfo->dwVersion = VMMDLL_VFS_FILELIST_EXINFO_VERSION;
    pExInfo->fCompressed = pProcess && pProcess->dwState;
    pExInfo->qwCreationTime = VmmProcess_GetCreateTimeOpt(pProcess);
    pExInfo->qwLastWriteTime = (pProcess && pProcess->dwState) ? VmmProcess_GetExitTimeOpt(pProcess) : 0;
    if(!pExInfo->qwLastWriteTime) {
        pExInfo->qwLastWriteTime = pExInfo->qwCreationTime;
    }
}

// ----------------------------------------------------------------------------
// FUNCTIONALITY RELATED TO: READ
// ----------------------------------------------------------------------------

NTSTATUS VmmVfsReadFileProcess(_In_ PVMM_PROCESS pProcess, _In_ PVMMVFS_PATH pPath, _Out_writes_(cb) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset)
{
    QWORD cbMemSize;
    DWORD cbBuffer;
    BYTE pbBuffer[0x800];
    ZeroMemory(pbBuffer, 48);
    // read memory from "vmem" file
    if(!_wcsicmp(pPath->wszPath1, L"vmem")) {
        cbMemSize = (ctxVmm->tpMemoryModel == VMM_MEMORYMODEL_X64) ? 1ULL << 48 : 1ULL << 32;
        return VmmReadAsFile(pProcess, 0, cbMemSize, pb, cb, pcbRead, cbOffset);
    }
    // read genereal numeric values from files, pml4, pid, name, virt
    if(!_wcsicmp(pPath->wszPath1, L"dtb")) {
        if(ctxVmm->tpMemoryModel == VMM_MEMORYMODEL_X64) {
            return Util_VfsReadFile_FromQWORD(pProcess->paDTB, pb, cb, pcbRead, cbOffset, FALSE);
        } else if((ctxVmm->tpMemoryModel == VMM_MEMORYMODEL_X86) || (ctxVmm->tpMemoryModel == VMM_MEMORYMODEL_X86PAE)) {
            return Util_VfsReadFile_FromDWORD((DWORD)pProcess->paDTB, pb, cb, pcbRead, cbOffset, FALSE);
        }
    }
    if(!_wcsicmp(pPath->wszPath1, L"dtb-user")) {
        if(ctxVmm->tpMemoryModel == VMM_MEMORYMODEL_X64) {
            return Util_VfsReadFile_FromQWORD(pProcess->paDTB_UserOpt, pb, cb, pcbRead, cbOffset, FALSE);
        } else if((ctxVmm->tpMemoryModel == VMM_MEMORYMODEL_X86) || (ctxVmm->tpMemoryModel == VMM_MEMORYMODEL_X86PAE)) {
            return Util_VfsReadFile_FromDWORD((DWORD)pProcess->paDTB_UserOpt, pb, cb, pcbRead, cbOffset, FALSE);
        }
    }
    if(!_wcsicmp(pPath->wszPath1, L"pid")) {
        cbBuffer = snprintf(pbBuffer, 32, "%i", pProcess->dwPID);
        return Util_VfsReadFile_FromPBYTE(pbBuffer, cbBuffer, pb, cb, pcbRead, cbOffset);
    }
    if(!_wcsicmp(pPath->wszPath1, L"ppid")) {
        cbBuffer = snprintf(pbBuffer, 32, "%i", pProcess->dwPPID);
        return Util_VfsReadFile_FromPBYTE(pbBuffer, cbBuffer, pb, cb, pcbRead, cbOffset);
    }
    if(!_wcsicmp(pPath->wszPath1, L"state")) {
        cbBuffer = snprintf(pbBuffer, 32, "%i", pProcess->dwState);
        return Util_VfsReadFile_FromPBYTE(pbBuffer, cbBuffer, pb, cb, pcbRead, cbOffset);
    }
    if(!_wcsicmp(pPath->wszPath1, L"name")) {
        cbBuffer = snprintf(pbBuffer, 32, "%s", pProcess->szName);
        return Util_VfsReadFile_FromPBYTE(pbBuffer, cbBuffer, pb, cb, pcbRead, cbOffset);
    }
    // windows specific reads below:
    if((ctxVmm->tpSystem == VMM_SYSTEM_WINDOWS_X64) || (ctxVmm->tpSystem == VMM_SYSTEM_WINDOWS_X86)) {
        if(!_wcsicmp(pPath->wszPath1, L"name-long")) {
            return Util_VfsReadFile_FromPBYTE(pProcess->pObPersistent->szNameLong, pProcess->pObPersistent->cchNameLong, pb, cb, pcbRead, cbOffset);
        }
        if(!_wcsicmp(pPath->wszPath1, L"win-cmdline")) {
            return Util_VfsReadFile_FromPBYTE(pProcess->pObPersistent->UserProcessParams.szCommandLine, pProcess->pObPersistent->UserProcessParams.cchCommandLine, pb, cb, pcbRead, cbOffset);
        }
        if(!_wcsicmp(pPath->wszPath1, L"win-path")) {
            return Util_VfsReadFile_FromPBYTE(pProcess->pObPersistent->szPathKernel, pProcess->pObPersistent->cchPathKernel, pb, cb, pcbRead, cbOffset);
        }
    }
    if(ctxVmm->tpSystem == VMM_SYSTEM_WINDOWS_X64) {
        if(!_wcsicmp(pPath->wszPath1, L"win-eprocess")) {
            return Util_VfsReadFile_FromQWORD(pProcess->win.EPROCESS.va, pb, cb, pcbRead, cbOffset, FALSE);
        }
        if(!_wcsicmp(pPath->wszPath1, L"win-peb")) {
            return Util_VfsReadFile_FromQWORD(pProcess->win.vaPEB, pb, cb, pcbRead, cbOffset, FALSE);
        }
        if(!_wcsicmp(pPath->wszPath1, L"win-peb32")) {
            return Util_VfsReadFile_FromDWORD(pProcess->win.vaPEB32, pb, cb, pcbRead, cbOffset, FALSE);
        }
    }
    if(ctxVmm->tpSystem == VMM_SYSTEM_WINDOWS_X86) {
        if(!_wcsicmp(pPath->wszPath1, L"win-eprocess")) {
            return Util_VfsReadFile_FromDWORD((DWORD)pProcess->win.EPROCESS.va, pb, cb, pcbRead, cbOffset, FALSE);
        }
        if(!_wcsicmp(pPath->wszPath1, L"win-peb")) {
            return Util_VfsReadFile_FromDWORD((DWORD)pProcess->win.vaPEB, pb, cb, pcbRead, cbOffset, FALSE);
        }
    }
    // no hit - call down the loadable modules chain for potential hits
    return PluginManager_Read(pProcess, pPath->wszPath1, pPath->wszPath2, pb, cb, pcbRead, cbOffset);
}

NTSTATUS VmmVfs_Read(LPCWSTR wcsFileName, _Out_writes_(cb) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset)
{
    NTSTATUS nt = VMM_STATUS_FILE_INVALID;
    VMMVFS_PATH path;
    WCHAR wszModule[32];
    LPWSTR wszModulePath;
    PVMM_PROCESS pObProcess;
    if(!ctxVmm) { return nt; }
    // read files in process directories:
    if(!_wcsnicmp(wcsFileName, L"\\name", 5) || !_wcsnicmp(wcsFileName, L"\\pid", 4)) {
        if(!VmmVfs_UtilVmmGetPidDirFile(wcsFileName, &path)) { return nt; }
        pObProcess = VmmProcessGet(path.dwPID);
        if(!pObProcess) { return VMM_STATUS_FILE_INVALID; }
        nt = VmmVfsReadFileProcess(pObProcess, &path, pb, cb, pcbRead, cbOffset);
        Ob_DECREF(pObProcess);
        return nt;
    }
    // read '\\memory.pmem'/'\\memory.dmp' - physical memory file:
    if(!_wcsnicmp(wcsFileName, L"\\memory.", 8)) {
        return MVmmVfsDump_Read(wcsFileName, pb, cb, pcbRead, cbOffset);
    }
    // list files in any non-process modules directories
    wszModulePath = Util_PathSplit2_ExWCHAR((LPWSTR)(wcsFileName + 1), wszModule, _countof(wszModule));
    return PluginManager_Read(NULL, wszModule, wszModulePath, pb, cb, pcbRead, cbOffset);
}

// ----------------------------------------------------------------------------
// FUNCTIONALITY RELATED TO: WRITE
// ----------------------------------------------------------------------------

NTSTATUS VmmVfsWriteFileProcess(_In_ PVMM_PROCESS pProcess, _In_ PVMMVFS_PATH pPath, _In_ LPVOID pb, _In_ DWORD cb, _Out_ PDWORD pcbWrite, _In_ QWORD cbOffset)
{
    BOOL fFound;
    QWORD cbMemSize;
    // read only files - report zero bytes written
    fFound =
        !_wcsicmp(pPath->wszPath1, L"dtb") ||
        !_wcsicmp(pPath->wszPath1, L"name") ||
        !_wcsicmp(pPath->wszPath1, L"pid") ||
        !_wcsicmp(pPath->wszPath1, L"ppid") ||
        !_wcsicmp(pPath->wszPath1, L"state");
    if(fFound) {
        *pcbWrite = 0;
        return VMM_STATUS_SUCCESS;
    }
    // windows specific writes below:
    if((ctxVmm->tpSystem == VMM_SYSTEM_WINDOWS_X64) || (ctxVmm->tpSystem == VMM_SYSTEM_WINDOWS_X86)) {
        fFound =
            !_wcsicmp(pPath->wszPath1, L"name-long") ||
            !_wcsicmp(pPath->wszPath1, L"win-cmdline") ||
            !_wcsicmp(pPath->wszPath1, L"win-eprocess") ||
            !_wcsicmp(pPath->wszPath1, L"win-kpath") ||
            !_wcsicmp(pPath->wszPath1, L"win-peb");
        if(fFound) {
            *pcbWrite = 0;
            return VMM_STATUS_SUCCESS;
        }
    }
    // write memory to "vmem" file
    if(!_wcsicmp(pPath->wszPath1, L"vmem")) {
        cbMemSize = (ctxVmm->tpMemoryModel == VMM_MEMORYMODEL_X64) ? 1ULL << 48 : 1ULL << 32;
        return VmmWriteAsFile(pProcess, 0, cbMemSize, pb, cb, pcbWrite, cbOffset);
    }
    // no hit - call down the loadable modules chain for potential hits
    return PluginManager_Write(pProcess, pPath->wszPath1, pPath->wszPath2, pb, cb, pcbWrite, cbOffset);
}

NTSTATUS VmmVfs_Write(_In_ LPCWSTR wcsFileName, _In_reads_(cb) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbWrite, _In_ QWORD cbOffset)
{
    NTSTATUS nt = VMM_STATUS_FILE_INVALID;
    VMMVFS_PATH path;
    PVMM_PROCESS pObProcess;
    WCHAR wszModule[32];
    LPWSTR wszModulePath;
    if(!ctxVmm) { return nt; }
    // read files in process directories:
    if(!_wcsnicmp(wcsFileName, L"\\name", 5) || !_wcsnicmp(wcsFileName, L"\\pid", 4)) {
        if(!VmmVfs_UtilVmmGetPidDirFile(wcsFileName, &path) || !path.wszPath1) { return nt; }
        pObProcess = VmmProcessGet(path.dwPID);
        if(!pObProcess) { return VMM_STATUS_FILE_INVALID; }
        nt = VmmVfsWriteFileProcess(pObProcess, &path, pb, cb, pcbWrite, cbOffset);
        return nt;
    }
    // write '\\memory.pmem'/'\\memory.dmp' - physical memory file:
    if(!_wcsnicmp(wcsFileName, L"\\memory.", 8)) {
        return MVmmVfsDump_Write(wcsFileName, pb, cb, pcbWrite, cbOffset);
    }
    // list files in any non-process modules directories
    wszModulePath = Util_PathSplit2_ExWCHAR((LPWSTR)(wcsFileName + 1), wszModule, _countof(wszModule));
    return PluginManager_Write(NULL, wszModule, wszModulePath, pb, cb, pcbWrite, cbOffset);
}

// ----------------------------------------------------------------------------
// FUNCTIONALITY RELATED TO: LIST
// ----------------------------------------------------------------------------

VOID VmmVfsListFiles_OsSpecific(_In_ PVMM_PROCESS pProcess, _In_ PVMMDLL_VFS_FILELIST_EXINFO pExInfo, _Inout_ PHANDLE pFileList)
{
    // WINDOWS - 32 & 64-bit
    if((ctxVmm->tpSystem == VMM_SYSTEM_WINDOWS_X64) || (ctxVmm->tpSystem == VMM_SYSTEM_WINDOWS_X86)) {
        VMMDLL_VfsList_AddFileEx(pFileList, "name-long", NULL, pProcess->pObPersistent->cchNameLong, pExInfo);
        VMMDLL_VfsList_AddFileEx(pFileList, "win-path", NULL, pProcess->pObPersistent->cchPathKernel, pExInfo);
        if(pProcess->pObPersistent->UserProcessParams.cchCommandLine) {
            VMMDLL_VfsList_AddFileEx(pFileList, "win-cmdline", NULL, pProcess->pObPersistent->UserProcessParams.cchCommandLine, pExInfo);
        }
    }
    // WINDOWS - 64-bit specific
    if(ctxVmm->tpSystem == VMM_SYSTEM_WINDOWS_X64) {
        VMMDLL_VfsList_AddFileEx(pFileList, "win-eprocess", NULL, 16, pExInfo);
        // 64-bit PEB and modules
        if(pProcess->win.vaPEB) {
            VMMDLL_VfsList_AddFileEx(pFileList, "win-peb", NULL, 16, pExInfo);
        }
        // 32-bit PEB
        if(pProcess->win.vaPEB32) {
            VMMDLL_VfsList_AddFileEx(pFileList, "win-peb32", NULL, 8, pExInfo);
        }
    }
    // WINDOWS 32-bit specific
    if(ctxVmm->tpSystem == VMM_SYSTEM_WINDOWS_X86) {
        VMMDLL_VfsList_AddFileEx(pFileList, "win-eprocess", NULL, 8, pExInfo);
        // PEB
        if(pProcess->win.vaPEB) {
            VMMDLL_VfsList_AddFileEx(pFileList, "win-peb", NULL, 8, pExInfo);
        }
    }
}

_Success_(return)
BOOL VmmVfsListFilesProcessRoot(_In_ PVMMVFS_PATH pPath, _Inout_ PHANDLE pFileList)
{
    PVMM_PROCESS pObProcess = NULL;
    VMMDLL_VFS_FILELIST_EXINFO ExInfo = { 0 };
    CHAR szBufferFileName[MAX_PATH];
    while((pObProcess = VmmProcessGetNext(pObProcess, 0))) {
        if(pPath->fNamePID) {
            if(pObProcess->dwState) {
                sprintf_s(szBufferFileName, MAX_PATH - 1, "%s-(%x)-%i", pObProcess->szName, pObProcess->dwState, pObProcess->dwPID);
            } else {
                sprintf_s(szBufferFileName, MAX_PATH - 1, "%s-%i", pObProcess->szName, pObProcess->dwPID);
            }
        } else {
            sprintf_s(szBufferFileName, MAX_PATH - 1, "%i", pObProcess->dwPID);
        }
        VmmVfs_UtilTimeStampFile(pObProcess, &ExInfo);
        VMMDLL_VfsList_AddDirectoryEx(pFileList, szBufferFileName, NULL, &ExInfo);
    }
    return TRUE;
}

_Success_(return)
BOOL VmmVfsListFilesProcess(_In_ PVMM_PROCESS pProcess, _In_ PVMMVFS_PATH pPath, _Inout_ PHANDLE pFileList)
{
    VMMDLL_VFS_FILELIST_EXINFO ExInfo = { 0 };
    VmmVfs_UtilTimeStampFile(pProcess, &ExInfo);
    // populate process directory - list standard files and subdirectories
    if(!pPath->wszPath1) {
        VMMDLL_VfsList_AddFileEx(pFileList, "name", NULL, 16, &ExInfo);
        VMMDLL_VfsList_AddFileEx(pFileList, "pid", NULL, 10, &ExInfo);
        VMMDLL_VfsList_AddFileEx(pFileList, "ppid", NULL, 10, &ExInfo);
        VMMDLL_VfsList_AddFileEx(pFileList, "state", NULL, 10, &ExInfo);
        if(ctxVmm->tpMemoryModel == VMM_MEMORYMODEL_X64) {
            VMMDLL_VfsList_AddFileEx(pFileList, "vmem", NULL, 0x0001000000000000, &ExInfo);
            VMMDLL_VfsList_AddFileEx(pFileList, "dtb", NULL, 16, &ExInfo);
            if(pProcess->paDTB_UserOpt) { VMMDLL_VfsList_AddFileEx(pFileList, "dtb-user", NULL, 16, &ExInfo); }
        } else if(ctxVmm->tpMemoryModel == VMM_MEMORYMODEL_X86 || ctxVmm->tpMemoryModel == VMM_MEMORYMODEL_X86PAE) {
            VMMDLL_VfsList_AddFileEx(pFileList, "vmem", NULL, 0x100000000, &ExInfo);
            VMMDLL_VfsList_AddFileEx(pFileList, "dtb", NULL, 8, &ExInfo);
            if(pProcess->paDTB_UserOpt) { VMMDLL_VfsList_AddFileEx(pFileList, "dtb-user", NULL, 8, &ExInfo); }
        }
        VmmVfsListFiles_OsSpecific(pProcess, &ExInfo, pFileList);
        PluginManager_ListAll(pProcess, pFileList);
        return TRUE;
    }
    // no hit - call down the loadable modules chain for potential hits
    return PluginManager_List(pProcess, pPath->wszPath1, pPath->wszPath2, pFileList);
}

_Success_(return)
BOOL VmmVfsListFilesRoot(_Inout_ PHANDLE pFileList)
{
    VMMDLL_VfsList_AddDirectory(pFileList, "name");
    VMMDLL_VfsList_AddDirectory(pFileList, "pid");
    PluginManager_ListAll(NULL, pFileList);
    MVmmVfsDump_List(pFileList);
    return TRUE;
}

BOOL VmmVfs_List(_In_ LPCWSTR wcsPath, _Inout_ PHANDLE pFileList)
{
    BOOL result = FALSE;
    VMMVFS_PATH path;
    PVMM_PROCESS pObProcess;
    WCHAR wszModule[32];
    LPWSTR wszModulePath;
    if(!ctxVmm || !VMMDLL_VfsList_IsHandleValid(pFileList)) { return FALSE; }
    // list files in root directory
    if(!_wcsicmp(wcsPath, L"\\")) {
        return VmmVfsListFilesRoot(pFileList);
    }
    // list files in name or pid directories:
    if(!_wcsnicmp(wcsPath, L"\\name", 5) || !_wcsnicmp(wcsPath, L"\\pid", 4)) {
        if(!VmmVfs_UtilVmmGetPidDirFile(wcsPath, &path)) { return FALSE; }
        if(path.fRoot) {
            return VmmVfsListFilesProcessRoot(&path, pFileList);
        }
        pObProcess = VmmProcessGet(path.dwPID);
        if(!pObProcess) { return FALSE; }
        result = VmmVfsListFilesProcess(pObProcess, &path, pFileList);
        Ob_DECREF(pObProcess);
        return result;
    }
    // list files in any non-process modules directories
    wszModulePath = Util_PathSplit2_ExWCHAR((LPWSTR)(wcsPath + 1), wszModule, _countof(wszModule));
    return PluginManager_List(NULL, wszModule, wszModulePath, pFileList);
}
