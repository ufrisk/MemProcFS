// vmmvfs.c : implementation related to virtual memory management / virtual file system interfacing.
//
// (c) Ulf Frisk, 2018
// Author: Ulf Frisk, pcileech@frizk.net
//
#include "vmm.h"
#include "vmmdll.h"
#include "pluginmanager.h"
#include "vmmproc.h"
#include "vmmproc_windows.h"
#include "util.h"

typedef struct tdVMMVFS_PATH {
    CHAR _sz[MAX_PATH];
    BOOL fRoot;
    BOOL fNamePID;
    DWORD dwPID;
    LPSTR szPath1;
    LPSTR szPath2;
} VMMVFS_PATH, *PVMMVFS_PATH;

BOOL VmmVfs_UtilVmmGetPidDirFile(_In_ LPCWSTR wcsFileName, _Inout_ PVMMVFS_PATH pPath)
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

NTSTATUS VmmVfsReadFileProcess(_In_ PVMMVFS_PATH pPath, _Out_ LPVOID pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset)
{
    PVMM_PROCESS pProcess;
    BYTE pbBuffer[0x800];
    DWORD cbBuffer;
    ZeroMemory(pbBuffer, 48);
    if(!ctxVmm) { return VMM_STATUS_FILE_INVALID; }
    pProcess = VmmProcessGet(pPath->dwPID);
    if(!pProcess) { return VMM_STATUS_FILE_INVALID; }
    // read memory from "vmem" file
    if(!_stricmp(pPath->szPath1, "vmem")) {
        VmmReadEx(pProcess, cbOffset, pb, cb, NULL, 0);
        *pcbRead = cb;
        return VMM_STATUS_SUCCESS;
    }
    // read the memory map
    if(!_stricmp(pPath->szPath1, "map")) {
        if(!pProcess->pbMemMapDisplayCache) {
            VmmMapDisplayBufferGenerate(pProcess);
            if(!pProcess->pbMemMapDisplayCache) {
                return VMM_STATUS_FILE_INVALID;
            }
        }
        return Util_VfsReadFile_FromPBYTE(pProcess->pbMemMapDisplayCache, pProcess->cbMemMapDisplayCache, pb, cb, pcbRead, cbOffset);
    }
    // read genereal numeric values from files, pml4, pid, name, virt
    if(!_stricmp(pPath->szPath1, "pml4")) {
        return Util_VfsReadFile_FromQWORD(pProcess->paPML4, pb, cb, pcbRead, cbOffset, FALSE);
    }
    if(!_stricmp(pPath->szPath1, "pml4-user")) {
        return Util_VfsReadFile_FromQWORD(pProcess->paPML4_UserOpt, pb, cb, pcbRead, cbOffset, FALSE);
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
    if(ctxVmm->fTargetSystem & VMM_TARGET_WINDOWS_X64) {
        if(!_stricmp(pPath->szPath1, "win-eprocess")) {
            return Util_VfsReadFile_FromQWORD(pProcess->os.win.vaEPROCESS, pb, cb, pcbRead, cbOffset, FALSE);
        }
        if(!_stricmp(pPath->szPath1, "win-entry")) {
            return Util_VfsReadFile_FromQWORD(pProcess->os.win.vaENTRY, pb, cb, pcbRead, cbOffset, FALSE);
        }
        if(!_stricmp(pPath->szPath1, "win-peb")) {
            return Util_VfsReadFile_FromQWORD(pProcess->os.win.vaPEB, pb, cb, pcbRead, cbOffset, FALSE);
        }
        if(!_stricmp(pPath->szPath1, "win-modules") && pProcess->os.win.pbLdrModulesDisplayCache) {
            return Util_VfsReadFile_FromPBYTE(pProcess->os.win.pbLdrModulesDisplayCache, pProcess->os.win.cbLdrModulesDisplayCache, pb, cb, pcbRead, cbOffset);
        }
        if(!_stricmp(pPath->szPath1, "win-peb32")) {
            return Util_VfsReadFile_FromDWORD(pProcess->os.win.vaPEB32, pb, cb, pcbRead, cbOffset, FALSE);
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
    if(!ctxVmm) { return nt; }
    // read '\\pmem' - physical memory file:
    if(!_wcsicmp(wcsFileName, L"\\pmem")) {
        VmmReadEx(NULL, cbOffset, pb, cb, pcbRead, VMM_FLAG_ZEROPAD_ON_FAIL);
        return VMM_STATUS_SUCCESS;
    }
    // read files in process directories:
    if(!_wcsnicmp(wcsFileName, L"\\name", 5) || !_wcsnicmp(wcsFileName, L"\\pid", 4)) {
        if(!ctxVmm->ptPROC) { return nt; }
        if(!VmmVfs_UtilVmmGetPidDirFile(wcsFileName, &path)) { return nt; }
        return VmmVfsReadFileProcess(&path, pb, cb, pcbRead, cbOffset);
    }
    // list files in any non-process modules directories
    Util_PathSplit2_WCHAR((LPWSTR)(wcsFileName + 1), _szBuf, &szModule, &szModulePath);
    return PluginManager_Read(NULL, szModule, szModulePath, pb, cb, pcbRead, cbOffset);
}

// ----------------------------------------------------------------------------
// FUNCTIONALITY RELATED TO: WRITE
// ----------------------------------------------------------------------------

NTSTATUS VmmVfsWriteFileProcess(_In_ PVMMVFS_PATH pPath, _In_ LPVOID pb, _In_ DWORD cb, _Out_ PDWORD pcbWrite, _In_ QWORD cbOffset)
{
    PVMM_PROCESS pProcess;
    BOOL fFound, result;
    if(!pPath->szPath1) { return VMM_STATUS_FILE_INVALID; }
    pProcess = VmmProcessGet(pPath->dwPID);
    if(!pProcess) { return VMM_STATUS_FILE_INVALID; }
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
    if(ctxVmm->fTargetSystem & VMM_TARGET_WINDOWS_X64) {
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
        if(!ctxVmm->ptPROC) { return nt; }
        if(!VmmVfs_UtilVmmGetPidDirFile(wcsFileName, &path)) { return nt; }
        return VmmVfsWriteFileProcess(&path, pb, cb, pcbWrite, cbOffset);
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
    // WINDOWS
    if(ctxVmm->fTargetSystem & VMM_TARGET_WINDOWS_X64) {
        VMMDLL_VfsList_AddFile(pFileList, "win-eprocess", 16);
        if(pProcess->os.win.vaENTRY) {
            VMMDLL_VfsList_AddFile(pFileList, "win-entry", 16);
        }
        // 64-bit PEB and modules
        VMMDLL_VfsList_AddFile(pFileList, "win-peb", 16);
        if(pProcess->os.win.cbLdrModulesDisplayCache) {
            VMMDLL_VfsList_AddFile(pFileList, "win-modules", pProcess->os.win.cbLdrModulesDisplayCache);
        }
        // 32-bit PEB and modules
        if(pProcess->os.win.vaPEB32) {
            VMMDLL_VfsList_AddFile(pFileList, "win-peb32", 8);
        }
    }
}

_Success_(return)
BOOL VmmVfsListFilesProcess(_In_ PVMMVFS_PATH pPath, _Inout_ PHANDLE pFileList)
{
    PVMM_PROCESS pProcess;
    WORD iProcess;
    CHAR szBufferFileName[MAX_PATH];
    if(!ctxVmm || !ctxVmm->ptPROC) { return FALSE; }
    // populate root node - list processes as directories
    if(pPath->fRoot) {
        iProcess = ctxVmm->ptPROC->iFLink;
        pProcess = ctxVmm->ptPROC->M[iProcess];
        while(pProcess) {
            {
                if(pPath->fNamePID) {
                    if(pProcess->dwState) {
                        sprintf_s(szBufferFileName, MAX_PATH - 1, "%s-(%x)-%i", pProcess->szName, pProcess->dwState, pProcess->dwPID);
                    } else {
                        sprintf_s(szBufferFileName, MAX_PATH - 1, "%s-%i", pProcess->szName, pProcess->dwPID);
                    }
                } else {
                    sprintf_s(szBufferFileName, MAX_PATH - 1, "%i", pProcess->dwPID);
                }
                VMMDLL_VfsList_AddDirectory(pFileList, szBufferFileName);
            }
            iProcess = ctxVmm->ptPROC->iFLinkM[iProcess];
            pProcess = ctxVmm->ptPROC->M[iProcess];
            if(!iProcess || iProcess == ctxVmm->ptPROC->iFLink) { break; }
        }
        return TRUE;
    }
    // generate memmap, if not already done. required by following steps
    pProcess = VmmProcessGet(pPath->dwPID);
    if(!pProcess) { return FALSE; }
    if(!pProcess->pMemMap || !pProcess->cMemMap) {
        if(!pProcess->fSpiderPageTableDone) {
            VmmTlbSpider(0, pProcess->fUserOnly);
            pProcess->fSpiderPageTableDone = TRUE;
        }
        VmmMapInitialize(pProcess);
        VmmProc_InitializeModuleNames(pProcess);
        VmmMapDisplayBufferGenerate(pProcess);
    }
    // populate process directory - list standard files and subdirectories
    if(!pPath->szPath1) {
        VMMDLL_VfsList_AddFile(pFileList, "map", pProcess->cbMemMapDisplayCache);
        VMMDLL_VfsList_AddFile(pFileList, "name", 16);
        VMMDLL_VfsList_AddFile(pFileList, "pid", 10);
        VMMDLL_VfsList_AddFile(pFileList, "pml4", 16);
        VMMDLL_VfsList_AddFile(pFileList, "vmem", 0x0001000000000000);
        if(pProcess->paPML4_UserOpt) {
            VMMDLL_VfsList_AddFile(pFileList, "pml4-user", 16);
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
    VMMDLL_VfsList_AddFile(pFileList, "pmem", ctxMain->cfg.paAddrMax);
    PluginManager_ListAll(NULL, pFileList);
    return TRUE;
}

BOOL VmmVfs_List(_In_ LPCWSTR wcsPath, _Inout_ PHANDLE pFileList)
{
    BOOL result = FALSE;
    VMMVFS_PATH path;
    CHAR _szBuf[MAX_PATH];
    LPSTR szModule, szModulePath;
    if(!ctxVmm) { return FALSE; }
    // list files in root directory
    if(!_wcsicmp(wcsPath, L"\\")) {
        return VmmVfsListFilesRoot(pFileList);
    }
    // list files in name or pid directories:
    if(!_wcsnicmp(wcsPath, L"\\name", 5) || !_wcsnicmp(wcsPath, L"\\pid", 4)) {
        if(!ctxVmm->ptPROC) { return FALSE; }
        if(!VmmVfs_UtilVmmGetPidDirFile(wcsPath, &path)) { return FALSE; }
        return VmmVfsListFilesProcess(&path, pFileList);
    }
    // list files in any non-process modules directories
    Util_PathSplit2_WCHAR((LPWSTR)(wcsPath + 1), _szBuf, &szModule, &szModulePath);
    return PluginManager_List(NULL, szModule, szModulePath, pFileList);
}
