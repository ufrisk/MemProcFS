// vmmvfs.c : implementation related to virtual memory management / virtual file system interfacing.
//
// (c) Ulf Frisk, 2018-2019
// Author: Ulf Frisk, pcileech@frizk.net
//
#include "vmm.h"
#include "vmmdll.h"
#include "pluginmanager.h"
#include "vmmproc.h"
#include "vmmwin.h"
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

// ----------------------------------------------------------------------------
// FUNCTIONALITY RELATED TO: READ
// ----------------------------------------------------------------------------

NTSTATUS VmmVfsReadFileProcess(_In_ PVMM_PROCESS pProcess, _In_ PVMMVFS_PATH pPath, _Out_ LPVOID pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset)
{
    NTSTATUS nt;
    BYTE pbBuffer[0x800];
    DWORD cbBuffer;
    PVMMOB_DATA pObMemMapDisplay = NULL;
    PVMMOB_MODULEMAP pObModuleMap = NULL;
    ZeroMemory(pbBuffer, 48);
    // read memory from "vmem" file
    if(!_wcsicmp(pPath->wszPath1, L"vmem")) {
        if((ctxVmm->tpMemoryModel != VMM_MEMORYMODEL_X64) && (cbOffset + cb >= 0x100000000)) {
            if(cbOffset >= 0x100000000) { return VMM_STATUS_END_OF_FILE; }
            cb = (DWORD)(0x100000000 - cbOffset);
        }
        VmmReadEx(pProcess, cbOffset, pb, cb, NULL, 0);
        *pcbRead = cb;
        return VMM_STATUS_SUCCESS;
    }
    // read the memory map
    if(!_wcsicmp(pPath->wszPath1, L"map")) {
        if(!VmmMemMapGetDisplay(pProcess, VMM_MEMMAP_FLAG_ALL, &pObMemMapDisplay)) { return VMMDLL_STATUS_FILE_INVALID; }
        nt = Util_VfsReadFile_FromPBYTE(pObMemMapDisplay->pbData, pObMemMapDisplay->ObHdr.cbData, pb, cb, pcbRead, cbOffset);
        Ob_DECREF(pObMemMapDisplay);
        return nt;
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
            return Util_VfsReadFile_FromPBYTE(pProcess->pObProcessPersistent->szNameLong, pProcess->pObProcessPersistent->cchNameLong, pb, cb, pcbRead, cbOffset);
        }
        if(!_wcsicmp(pPath->wszPath1, L"win-cmdline")) {
            return Util_VfsReadFile_FromPBYTE(pProcess->pObProcessPersistent->UserProcessParams.szCommandLine, pProcess->pObProcessPersistent->UserProcessParams.cchCommandLine, pb, cb, pcbRead, cbOffset);
        }
        if(!_wcsicmp(pPath->wszPath1, L"win-path")) {
            return Util_VfsReadFile_FromPBYTE(pProcess->pObProcessPersistent->szPathKernel, pProcess->pObProcessPersistent->cchPathKernel, pb, cb, pcbRead, cbOffset);
        }
        if(!_wcsicmp(pPath->wszPath1, L"win-modules") && VmmProc_ModuleMapGet(pProcess, &pObModuleMap)) {
            nt = Util_VfsReadFile_FromPBYTE(pObModuleMap->pbDisplay, pObModuleMap->cbDisplay, pb, cb, pcbRead, cbOffset);
            Ob_DECREF_NULL(&pObModuleMap);
            return nt;
        }

    }
    if(ctxVmm->tpSystem == VMM_SYSTEM_WINDOWS_X64) {
        if(!_wcsicmp(pPath->wszPath1, L"win-eprocess")) {
            return Util_VfsReadFile_FromQWORD(pProcess->win.vaEPROCESS, pb, cb, pcbRead, cbOffset, FALSE);
        }
        if(!_wcsicmp(pPath->wszPath1, L"win-entry")) {
            return Util_VfsReadFile_FromQWORD(pProcess->win.vaENTRY, pb, cb, pcbRead, cbOffset, FALSE);
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
            return Util_VfsReadFile_FromDWORD((DWORD)pProcess->win.vaEPROCESS, pb, cb, pcbRead, cbOffset, FALSE);
        }
        if(!_wcsicmp(pPath->wszPath1, L"win-entry")) {
            return Util_VfsReadFile_FromDWORD((DWORD)pProcess->win.vaENTRY, pb, cb, pcbRead, cbOffset, FALSE);
        }
        if(!_wcsicmp(pPath->wszPath1, L"win-peb")) {
            return Util_VfsReadFile_FromDWORD((DWORD)pProcess->win.vaPEB, pb, cb, pcbRead, cbOffset, FALSE);
        }
    }
    // no hit - call down the loadable modules chain for potential hits
    return PluginManager_Read(pProcess, pPath->wszPath1, pPath->wszPath2, pb, cb, pcbRead, cbOffset);
}

NTSTATUS VmmVfs_Read(LPCWSTR wcsFileName, _Out_ LPVOID pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset)
{
    NTSTATUS nt = VMM_STATUS_FILE_INVALID;
    VMMVFS_PATH path;
    WCHAR wszModule[32];
    LPWSTR wszModulePath;
    PVMM_PROCESS pObProcess;
    if(!ctxVmm) { return nt; }
    // read '\\pmem' - physical memory file:
    if(!_wcsicmp(wcsFileName, L"\\pmem")) {
        VmmReadEx(NULL, cbOffset, pb, cb, pcbRead, VMM_FLAG_ZEROPAD_ON_FAIL);
        return VMM_STATUS_SUCCESS;
    }
    // read files in process directories:
    if(!_wcsnicmp(wcsFileName, L"\\name", 5) || !_wcsnicmp(wcsFileName, L"\\pid", 4)) {
        if(!VmmVfs_UtilVmmGetPidDirFile(wcsFileName, &path)) { return nt; }
        pObProcess = VmmProcessGet(path.dwPID);
        if(!pObProcess) { return VMM_STATUS_FILE_INVALID; }
        nt = VmmVfsReadFileProcess(pObProcess, &path, pb, cb, pcbRead, cbOffset);
        Ob_DECREF(pObProcess);
        return nt;
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
    BOOL fFound, result;
    // read only files - report zero bytes written
    fFound =
        !_wcsicmp(pPath->wszPath1, L"dtb") ||
        !_wcsicmp(pPath->wszPath1, L"map") ||
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
            !_wcsicmp(pPath->wszPath1, L"win-entry") ||
            !_wcsicmp(pPath->wszPath1, L"win-eprocess") ||
            !_wcsicmp(pPath->wszPath1, L"win-kpath") ||
            !_wcsicmp(pPath->wszPath1, L"win-modules") ||
            !_wcsicmp(pPath->wszPath1, L"win-peb");
        if(fFound) {
            *pcbWrite = 0;
            return VMM_STATUS_SUCCESS;
        }
    }
    // write memory to "vmem" file
    if(!_wcsicmp(pPath->wszPath1, L"vmem")) {
        result = VmmWrite(pProcess, cbOffset, pb, cb);
        *pcbWrite = cb;
        return VMM_STATUS_SUCCESS;
    }
    // no hit - call down the loadable modules chain for potential hits
    return PluginManager_Write(pProcess, pPath->wszPath1, pPath->wszPath2, pb, cb, pcbWrite, cbOffset);
}

NTSTATUS VmmVfs_Write(LPCWSTR wcsFileName, _In_ LPVOID pb, _In_ DWORD cb, _Out_ PDWORD pcbWrite, _In_ QWORD cbOffset)
{
    NTSTATUS nt = VMM_STATUS_FILE_INVALID;
    BOOL result;
    VMMVFS_PATH path;
    PVMM_PROCESS pObProcess;
    WCHAR wszModule[32];
    LPWSTR wszModulePath;
    if(!ctxVmm) { return nt; }
    // read '\\pmem' - physical memory file:
    if(!_wcsicmp(wcsFileName, L"\\pmem")) {
        result = VmmWrite(NULL, cbOffset, pb, cb);
        *pcbWrite = cb;
        return result ? VMM_STATUS_SUCCESS : VMM_STATUS_FILE_SYSTEM_LIMITATION;
    }
    // read files in process directories:
    if(!_wcsnicmp(wcsFileName, L"\\name", 5) || !_wcsnicmp(wcsFileName, L"\\pid", 4)) {
        if(!VmmVfs_UtilVmmGetPidDirFile(wcsFileName, &path) || !path.wszPath1) { return nt; }
        pObProcess = VmmProcessGet(path.dwPID);
        if(!pObProcess) { return VMM_STATUS_FILE_INVALID; }
        nt = VmmVfsWriteFileProcess(pObProcess, &path, pb, cb, pcbWrite, cbOffset);
        return nt;
    }
    // list files in any non-process modules directories
    wszModulePath = Util_PathSplit2_ExWCHAR((LPWSTR)(wcsFileName + 1), wszModule, _countof(wszModule));
    return PluginManager_Write(NULL, wszModule, wszModulePath, pb, cb, pcbWrite, cbOffset);
}

// ----------------------------------------------------------------------------
// FUNCTIONALITY RELATED TO: LIST
// ----------------------------------------------------------------------------

VOID VmmVfsListFiles_OsSpecific(_In_ PVMM_PROCESS pProcess, _Inout_ PHANDLE pFileList)
{
    PVMMOB_MODULEMAP pObModuleMap;
    // WINDOWS - 32 & 64-bit
    if((ctxVmm->tpSystem == VMM_SYSTEM_WINDOWS_X64) || (ctxVmm->tpSystem == VMM_SYSTEM_WINDOWS_X86)) {
        VMMDLL_VfsList_AddFile(pFileList, "name-long", pProcess->pObProcessPersistent->cchNameLong);
        VMMDLL_VfsList_AddFile(pFileList, "win-path", pProcess->pObProcessPersistent->cchPathKernel);
        if(pProcess->pObProcessPersistent->UserProcessParams.cchCommandLine) {
            VMMDLL_VfsList_AddFile(pFileList, "win-cmdline", pProcess->pObProcessPersistent->UserProcessParams.cchCommandLine);
        }
        // modules
        if(VmmProc_ModuleMapGet(pProcess, &pObModuleMap)) {
            if(pObModuleMap->cbDisplay) {
                VMMDLL_VfsList_AddFile(pFileList, "win-modules", pObModuleMap->cbDisplay);
            }
            Ob_DECREF(pObModuleMap);
        }
    }
    // WINDOWS - 64-bit specific
    if(ctxVmm->tpSystem == VMM_SYSTEM_WINDOWS_X64) {
        VMMDLL_VfsList_AddFile(pFileList, "win-eprocess", 16);
        if(pProcess->win.vaENTRY) {
            VMMDLL_VfsList_AddFile(pFileList, "win-entry", 16);
        }
        // 64-bit PEB and modules
        if(pProcess->win.vaPEB) {
            VMMDLL_VfsList_AddFile(pFileList, "win-peb", 16);
        }
        // 32-bit PEB
        if(pProcess->win.vaPEB32) {
            VMMDLL_VfsList_AddFile(pFileList, "win-peb32", 8);
        }
    }
    // WINDOWS 32-bit specific
    if(ctxVmm->tpSystem == VMM_SYSTEM_WINDOWS_X86) {
        VMMDLL_VfsList_AddFile(pFileList, "win-eprocess", 8);
        if(pProcess->win.vaENTRY) {
            VMMDLL_VfsList_AddFile(pFileList, "win-entry", 8);
        }
        // PEB
        if(pProcess->win.vaPEB) {
            VMMDLL_VfsList_AddFile(pFileList, "win-peb", 8);
        }
    }
}

_Success_(return)
BOOL VmmVfsListFilesProcessRoot(_In_ PVMMVFS_PATH pPath, _Inout_ PHANDLE pFileList)
{
    PVMM_PROCESS pObProcess = NULL;
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
        VMMDLL_VfsList_AddDirectory(pFileList, szBufferFileName);
    }
    return TRUE;
}

_Success_(return)
BOOL VmmVfsListFilesProcess(_In_ PVMM_PROCESS pProcess, _In_ PVMMVFS_PATH pPath, _Inout_ PHANDLE pFileList)
{
    PVMMOB_MEMMAP pObMemMap = NULL;
    // populate process directory - list standard files and subdirectories
    if(!pPath->wszPath1) {
        VmmMemMapGetEntries(pProcess, 0, &pObMemMap);
        VMMDLL_VfsList_AddFile(pFileList, "map", (pObMemMap ? pObMemMap->cbDisplay : 0));
        Ob_DECREF(pObMemMap);
        VMMDLL_VfsList_AddFile(pFileList, "name", 16);
        VMMDLL_VfsList_AddFile(pFileList, "pid", 10);
        VMMDLL_VfsList_AddFile(pFileList, "ppid", 10);
        VMMDLL_VfsList_AddFile(pFileList, "state", 10);
        if(ctxVmm->tpMemoryModel == VMM_MEMORYMODEL_X64) {
            VMMDLL_VfsList_AddFile(pFileList, "vmem", 0x0001000000000000);
            VMMDLL_VfsList_AddFile(pFileList, "dtb", 16);
            if(pProcess->paDTB_UserOpt) { VMMDLL_VfsList_AddFile(pFileList, "dtb-user", 16); }
        } else if(ctxVmm->tpMemoryModel == VMM_MEMORYMODEL_X86 || ctxVmm->tpMemoryModel == VMM_MEMORYMODEL_X86PAE) {
            VMMDLL_VfsList_AddFile(pFileList, "vmem", 0x100000000);
            VMMDLL_VfsList_AddFile(pFileList, "dtb", 8);
            if(pProcess->paDTB_UserOpt) { VMMDLL_VfsList_AddFile(pFileList, "dtb-user", 8); }
        }
        VmmVfsListFiles_OsSpecific(pProcess, pFileList);
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
    VMMDLL_VfsList_AddFile(pFileList, "pmem", ctxMain->dev.paMax);
    PluginManager_ListAll(NULL, pFileList);
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
