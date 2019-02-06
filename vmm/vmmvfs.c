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
    CHAR _sz[MAX_PATH];
    BOOL fRoot;
    BOOL fNamePID;
    DWORD dwPID;
    LPSTR szPath1;
    LPSTR szPath2;
} VMMVFS_PATH, *PVMMVFS_PATH;

BOOL VmmVfs_UtilVmmGetPidDirFile(_In_ LPCWSTR wcsFileName, _Out_ PVMMVFS_PATH pPath)
{
    DWORD i = 0, iPID, iPath1 = 0, iPath2 = 0;
    // 1: convert to ascii string
    ZeroMemory(pPath, sizeof(VMMVFS_PATH));
    while(TRUE) {
        if(i >= MAX_PATH) { return FALSE; }
        if(wcsFileName[i] > 255) { return FALSE; }
        pPath->_sz[i] = (CHAR)wcsFileName[i];
        if(wcsFileName[i] == 0) { break; }
        i++;
    }
    // 1: Check for root only item
    pPath->fNamePID = !_stricmp(pPath->_sz, "\\name");
    pPath->fRoot = pPath->fNamePID || !_stricmp(pPath->_sz, "\\pid");
    if(pPath->fRoot) { return TRUE; }
    // 2: Check if starting with PID or NAME and move start index
    if(!strncmp(pPath->_sz, "\\pid\\", 5)) { i = 5; }
    if(!strncmp(pPath->_sz, "\\name\\", 6)) { i = 6; }
    if(i == 0) { return FALSE; }
    // 3: Locate start of PID number and 1st Path item (if any)
    while((i < MAX_PATH) && pPath->_sz[i] && (pPath->_sz[i] != '\\')) { i++; }
    if(pPath->_sz[i]) { iPath1 = i + 1; }
    pPath->_sz[i] = 0;
    i--;
    while((i > 0) && (pPath->_sz[i] >= '0') && (pPath->_sz[i] <= '9')) { i--; }
    iPID = i + 1;
    pPath->dwPID = (DWORD)Util_GetNumeric(&pPath->_sz[iPID]);
    if(!iPath1) { return TRUE; }
    // 4: Locate 2nd Path item (if any)
    i = iPath1;
    while((i < MAX_PATH) && pPath->_sz[i] && (pPath->_sz[i] != '\\')) { i++; }
    if(pPath->_sz[i]) {
        iPath2 = i + 1;
        pPath->_sz[i] = 0;
    }
    // 7: Finish
    pPath->szPath1 = &pPath->_sz[iPath1];
    if(iPath2) {
        pPath->szPath2 = &pPath->_sz[iPath2];
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
    PVMMOB_PDATA pObMemMapDisplay;
    PVMMOB_MODULEMAP pObModuleMap;
    ZeroMemory(pbBuffer, 48);
    // read memory from "vmem" file
    if(!_stricmp(pPath->szPath1, "vmem")) {
        if((ctxVmm->tpMemoryModel != VMM_MEMORYMODEL_X64) && (cbOffset + cb >= 0x100000000)) {
            if(cbOffset >= 0x100000000) { return VMM_STATUS_END_OF_FILE; }
            cb = (DWORD)(0x100000000 - cbOffset);
        }
        VmmReadEx(pProcess, cbOffset, pb, cb, NULL, 0);
        *pcbRead = cb;
        return VMM_STATUS_SUCCESS;
    }
    // read the memory map
    if(!_stricmp(pPath->szPath1, "map")) {
        if(!VmmMemMapGetDisplay(pProcess, VMM_MEMMAP_FLAG_ALL, &pObMemMapDisplay)) { return VMMDLL_STATUS_FILE_INVALID; }
        nt = Util_VfsReadFile_FromPBYTE(pObMemMapDisplay->pbData, pObMemMapDisplay->cbData, pb, cb, pcbRead, cbOffset);
        VmmOb_DECREF(pObMemMapDisplay);
        return nt;
    }
    // read genereal numeric values from files, pml4, pid, name, virt
    if(!_stricmp(pPath->szPath1, "dtb")) {
        if(ctxVmm->tpMemoryModel == VMM_MEMORYMODEL_X64) {
            return Util_VfsReadFile_FromQWORD(pProcess->paDTB, pb, cb, pcbRead, cbOffset, FALSE);
        } else if((ctxVmm->tpMemoryModel == VMM_MEMORYMODEL_X86) || (ctxVmm->tpMemoryModel == VMM_MEMORYMODEL_X86PAE)) {
            return Util_VfsReadFile_FromDWORD((DWORD)pProcess->paDTB, pb, cb, pcbRead, cbOffset, FALSE);
        }
    }
    if(!_stricmp(pPath->szPath1, "dtb-user")) {
        if(ctxVmm->tpMemoryModel == VMM_MEMORYMODEL_X64) {
            return Util_VfsReadFile_FromQWORD(pProcess->paDTB_UserOpt, pb, cb, pcbRead, cbOffset, FALSE);
        } else if((ctxVmm->tpMemoryModel == VMM_MEMORYMODEL_X86) || (ctxVmm->tpMemoryModel == VMM_MEMORYMODEL_X86PAE)) {
            return Util_VfsReadFile_FromDWORD((DWORD)pProcess->paDTB_UserOpt, pb, cb, pcbRead, cbOffset, FALSE);
        }
    }
    if(!_stricmp(pPath->szPath1, "pid")) {
        cbBuffer = snprintf(pbBuffer, 32, "%i", pProcess->dwPID);
        return Util_VfsReadFile_FromPBYTE(pbBuffer, cbBuffer, pb, cb, pcbRead, cbOffset);
    }
    if(!_stricmp(pPath->szPath1, "name")) {
        cbBuffer = snprintf(pbBuffer, 32, "%s", pProcess->szName);
        return Util_VfsReadFile_FromPBYTE(pbBuffer, cbBuffer, pb, cb, pcbRead, cbOffset);
    }
    // windows specific reads below:
    if(ctxVmm->tpSystem == VMM_SYSTEM_WINDOWS_X64) {
        if(!_stricmp(pPath->szPath1, "win-eprocess")) {
            return Util_VfsReadFile_FromQWORD(pProcess->os.win.vaEPROCESS, pb, cb, pcbRead, cbOffset, FALSE);
        }
        if(!_stricmp(pPath->szPath1, "win-entry")) {
            return Util_VfsReadFile_FromQWORD(pProcess->os.win.vaENTRY, pb, cb, pcbRead, cbOffset, FALSE);
        }
        if(!_stricmp(pPath->szPath1, "win-peb")) {
            return Util_VfsReadFile_FromQWORD(pProcess->os.win.vaPEB, pb, cb, pcbRead, cbOffset, FALSE);
        }
        if(!_stricmp(pPath->szPath1, "win-modules") && VmmProc_ModuleMapGet(pProcess, &pObModuleMap)) {
            nt = Util_VfsReadFile_FromPBYTE(pObModuleMap->pbDisplay, pObModuleMap->cbDisplay, pb, cb, pcbRead, cbOffset);
            VmmOb_DECREF(pObModuleMap);
            return nt;
        }
        if(!_stricmp(pPath->szPath1, "win-peb32")) {
            return Util_VfsReadFile_FromDWORD(pProcess->os.win.vaPEB32, pb, cb, pcbRead, cbOffset, FALSE);
        }
    }
    if(ctxVmm->tpSystem == VMM_SYSTEM_WINDOWS_X86) {
        if(!_stricmp(pPath->szPath1, "win-eprocess")) {
            return Util_VfsReadFile_FromDWORD((DWORD)pProcess->os.win.vaEPROCESS, pb, cb, pcbRead, cbOffset, FALSE);
        }
        if(!_stricmp(pPath->szPath1, "win-entry")) {
            return Util_VfsReadFile_FromDWORD((DWORD)pProcess->os.win.vaENTRY, pb, cb, pcbRead, cbOffset, FALSE);
        }
        if(!_stricmp(pPath->szPath1, "win-peb")) {
            return Util_VfsReadFile_FromDWORD((DWORD)pProcess->os.win.vaPEB, pb, cb, pcbRead, cbOffset, FALSE);
        }
        if(!_stricmp(pPath->szPath1, "win-modules") && VmmProc_ModuleMapGet(pProcess, &pObModuleMap)) {
            nt = Util_VfsReadFile_FromPBYTE(pObModuleMap->pbDisplay, pObModuleMap->cbDisplay, pb, cb, pcbRead, cbOffset);
            VmmOb_DECREF(pObModuleMap);
            return nt;
        }
    }
    // no hit - call down the loadable modules chain for potential hits
    return PluginManager_Read(pProcess, pPath->szPath1, pPath->szPath2, pb, cb, pcbRead, cbOffset);
}

NTSTATUS VmmVfs_Read(LPCWSTR wcsFileName, _Out_ LPVOID pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset)
{
    NTSTATUS nt = VMM_STATUS_FILE_INVALID;
    VMMVFS_PATH path;
    CHAR _szBuf[MAX_PATH];
    LPSTR szModule, szModulePath;
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
        VmmOb_DECREF(pObProcess);
        return nt;
    }
    // list files in any non-process modules directories
    Util_PathSplit2_WCHAR((LPWSTR)(wcsFileName + 1), _szBuf, &szModule, &szModulePath);
    return PluginManager_Read(NULL, szModule, szModulePath, pb, cb, pcbRead, cbOffset);
}

// ----------------------------------------------------------------------------
// FUNCTIONALITY RELATED TO: WRITE
// ----------------------------------------------------------------------------

NTSTATUS VmmVfsWriteFileProcess(_In_ PVMM_PROCESS pProcess, _In_ PVMMVFS_PATH pPath, _In_ LPVOID pb, _In_ DWORD cb, _Out_ PDWORD pcbWrite, _In_ QWORD cbOffset)
{
    BOOL fFound, result;
    // read only files - report zero bytes written
    fFound =
        !_stricmp(pPath->szPath1, "map") ||
        !_stricmp(pPath->szPath1, "pml4") ||
        !_stricmp(pPath->szPath1, "pid") ||
        !_stricmp(pPath->szPath1, "name");
    if(fFound) {
        *pcbWrite = 0;
        return VMM_STATUS_SUCCESS;
    }
    // windows specific writes below:
    if((ctxVmm->tpSystem == VMM_SYSTEM_WINDOWS_X64) || (ctxVmm->tpSystem == VMM_SYSTEM_WINDOWS_X86)) {
        fFound =
            !_stricmp(pPath->szPath1, "win-eprocess") ||
            !_stricmp(pPath->szPath1, "win-peb") ||
            !_stricmp(pPath->szPath1, "win-entry") ||
            !_stricmp(pPath->szPath1, "win-modules");
        if(fFound) {
            *pcbWrite = 0;
            return VMM_STATUS_SUCCESS;
        }
    }
    // write memory to "vmem" file
    if(!_stricmp(pPath->szPath1, "vmem")) {
        result = VmmWrite(pProcess, cbOffset, pb, cb);
        *pcbWrite = cb;
        return VMM_STATUS_SUCCESS;
    }
    // no hit - call down the loadable modules chain for potential hits
    return PluginManager_Write(pProcess, pPath->szPath1, pPath->szPath2, pb, cb, pcbWrite, cbOffset);
}

NTSTATUS VmmVfs_Write(LPCWSTR wcsFileName, _In_ LPVOID pb, _In_ DWORD cb, _Out_ PDWORD pcbWrite, _In_ QWORD cbOffset)
{
    NTSTATUS nt = VMM_STATUS_FILE_INVALID;
    BOOL result;
    VMMVFS_PATH path;
    CHAR _szBuf[MAX_PATH];
    PVMM_PROCESS pObProcess;
    LPSTR szModule, szModulePath;
    if(!ctxVmm) { return nt; }
    // read '\\pmem' - physical memory file:
    if(!_wcsicmp(wcsFileName, L"\\pmem")) {
        result = VmmWritePhysical(cbOffset, pb, cb);
        *pcbWrite = cb;
        return result ? VMM_STATUS_SUCCESS : VMM_STATUS_FILE_SYSTEM_LIMITATION;
    }
    // read files in process directories:
    if(!_wcsnicmp(wcsFileName, L"\\name", 5) || !_wcsnicmp(wcsFileName, L"\\pid", 4)) {
        if(!VmmVfs_UtilVmmGetPidDirFile(wcsFileName, &path) || !path.szPath1) { return nt; }
        pObProcess = VmmProcessGet(path.dwPID);
        if(!pObProcess) { return VMM_STATUS_FILE_INVALID; }
        nt = VmmVfsWriteFileProcess(pObProcess, &path, pb, cb, pcbWrite, cbOffset);
        return nt;
    }
    // list files in any non-process modules directories
    Util_PathSplit2_WCHAR((LPWSTR)(wcsFileName + 1), _szBuf, &szModule, &szModulePath);
    return PluginManager_Write(NULL, szModule, szModulePath, pb, cb, pcbWrite, cbOffset);
}

// ----------------------------------------------------------------------------
// FUNCTIONALITY RELATED TO: LIST
// ----------------------------------------------------------------------------

VOID VmmVfsListFiles_OsSpecific(_In_ PVMM_PROCESS pProcess, _Inout_ PHANDLE pFileList)
{
    PVMMOB_MODULEMAP pObModuleMap;
    // WINDOWS
    if(ctxVmm->tpSystem == VMM_SYSTEM_WINDOWS_X64) {
        VMMDLL_VfsList_AddFile(pFileList, "win-eprocess", 16);
        if(pProcess->os.win.vaENTRY) {
            VMMDLL_VfsList_AddFile(pFileList, "win-entry", 16);
        }
        // 64-bit PEB and modules
        if(pProcess->os.win.vaPEB) {
            VMMDLL_VfsList_AddFile(pFileList, "win-peb", 16);
        }
        if(VmmProc_ModuleMapGet(pProcess, &pObModuleMap)) {
            if(pObModuleMap->cbDisplay) {
                VMMDLL_VfsList_AddFile(pFileList, "win-modules", pObModuleMap->cbDisplay);
            }
            VmmOb_DECREF(pObModuleMap);
        }
        // 32-bit PEB and modules
        if(pProcess->os.win.vaPEB32) {
            VMMDLL_VfsList_AddFile(pFileList, "win-peb32", 8);
        }
    }
    if(ctxVmm->tpSystem == VMM_SYSTEM_WINDOWS_X86) {
        VMMDLL_VfsList_AddFile(pFileList, "win-eprocess", 8);
        if(pProcess->os.win.vaENTRY) {
            VMMDLL_VfsList_AddFile(pFileList, "win-entry", 8);
        }
        // PEB and modules
        if(pProcess->os.win.vaPEB) {
            VMMDLL_VfsList_AddFile(pFileList, "win-peb", 8);
        }
        if(VmmProc_ModuleMapGet(pProcess, &pObModuleMap)) {
            if(pObModuleMap->cbDisplay) {
                VMMDLL_VfsList_AddFile(pFileList, "win-modules", pObModuleMap->cbDisplay);
            }
            VmmOb_DECREF(pObModuleMap);
        }
    }
}

_Success_(return)
BOOL VmmVfsListFilesProcessRoot(_In_ PVMMVFS_PATH pPath, _Inout_ PHANDLE pFileList)
{
    PVMM_PROCESS pObProcess = NULL;
    CHAR szBufferFileName[MAX_PATH];
    while((pObProcess = VmmProcessGetNext(pObProcess))) {
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
    if(!pPath->szPath1) {
        VmmMemMapGetEntries(pProcess, 0, &pObMemMap);
        VMMDLL_VfsList_AddFile(pFileList, "map", (pObMemMap ? pObMemMap->cbDisplay : 0));
        VmmOb_DECREF(pObMemMap);
        VMMDLL_VfsList_AddFile(pFileList, "name", 16);
        VMMDLL_VfsList_AddFile(pFileList, "pid", 10);
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
    return PluginManager_List(pProcess, pPath->szPath1, pPath->szPath2, pFileList);
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
    CHAR _szBuf[MAX_PATH];
    PVMM_PROCESS pObProcess;
    LPSTR szModule, szModulePath;
    if(!ctxVmm) { return FALSE; }
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
        VmmOb_DECREF(pObProcess);
        return result;
    }
    // list files in any non-process modules directories
    Util_PathSplit2_WCHAR((LPWSTR)(wcsPath + 1), _szBuf, &szModule, &szModulePath);
    return PluginManager_List(NULL, szModule, szModulePath, pFileList);
}
