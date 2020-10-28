// m_vfsproc.h : implementation of virtual file system process root.
//
// (c) Ulf Frisk, 2020
// Author: Ulf Frisk, pcileech@frizk.net
//
#include "pluginmanager.h"
#include "util.h"


/*
* Read process root file.
* -- ctx
* -- pb
* -- cb
* -- pcbRead
* -- cbOffset
* -- return
*/
NTSTATUS MVfsProc_Read(_In_ PVMMDLL_PLUGIN_CONTEXT ctx, _Out_writes_to_(cb, *pcbRead) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset)
{
    QWORD cbMemSize;
    DWORD cbBuffer;
    BYTE pbBuffer[0x800] = { 0 };
    LPWSTR wszPath = ctx->wszPath;
    PVMM_PROCESS pProcess = ctx->pProcess;
    // read memory from "vmem" file
    if(!_wcsicmp(wszPath, L"vmem")) {
        cbMemSize = (ctxVmm->tpMemoryModel == VMM_MEMORYMODEL_X64) ? 1ULL << 48 : 1ULL << 32;
        return VmmReadAsFile(pProcess, 0, cbMemSize, pb, cb, pcbRead, cbOffset);
    }
    // read genereal numeric values from files, pml4, pid, name, virt
    if(!_wcsicmp(wszPath, L"dtb")) {
        if(ctxVmm->tpMemoryModel == VMM_MEMORYMODEL_X64) {
            return Util_VfsReadFile_FromQWORD(pProcess->paDTB, pb, cb, pcbRead, cbOffset, FALSE);
        } else if((ctxVmm->tpMemoryModel == VMM_MEMORYMODEL_X86) || (ctxVmm->tpMemoryModel == VMM_MEMORYMODEL_X86PAE)) {
            return Util_VfsReadFile_FromDWORD((DWORD)pProcess->paDTB, pb, cb, pcbRead, cbOffset, FALSE);
        }
    }
    if(!_wcsicmp(wszPath, L"dtb-user")) {
        if(ctxVmm->tpMemoryModel == VMM_MEMORYMODEL_X64) {
            return Util_VfsReadFile_FromQWORD(pProcess->paDTB_UserOpt, pb, cb, pcbRead, cbOffset, FALSE);
        } else if((ctxVmm->tpMemoryModel == VMM_MEMORYMODEL_X86) || (ctxVmm->tpMemoryModel == VMM_MEMORYMODEL_X86PAE)) {
            return Util_VfsReadFile_FromDWORD((DWORD)pProcess->paDTB_UserOpt, pb, cb, pcbRead, cbOffset, FALSE);
        }
    }
    if(!_wcsicmp(wszPath, L"pid")) {
        cbBuffer = snprintf(pbBuffer, 32, "%i", pProcess->dwPID);
        return Util_VfsReadFile_FromPBYTE(pbBuffer, cbBuffer, pb, cb, pcbRead, cbOffset);
    }
    if(!_wcsicmp(wszPath, L"ppid")) {
        cbBuffer = snprintf(pbBuffer, 32, "%i", pProcess->dwPPID);
        return Util_VfsReadFile_FromPBYTE(pbBuffer, cbBuffer, pb, cb, pcbRead, cbOffset);
    }
    if(!_wcsicmp(wszPath, L"state")) {
        cbBuffer = snprintf(pbBuffer, 32, "%i", pProcess->dwState);
        return Util_VfsReadFile_FromPBYTE(pbBuffer, cbBuffer, pb, cb, pcbRead, cbOffset);
    }
    if(!_wcsicmp(wszPath, L"name")) {
        cbBuffer = snprintf(pbBuffer, 32, "%s", pProcess->szName);
        return Util_VfsReadFile_FromPBYTE(pbBuffer, cbBuffer, pb, cb, pcbRead, cbOffset);
    }
    // windows specific reads below:
    if((ctxVmm->tpSystem == VMM_SYSTEM_WINDOWS_X64) || (ctxVmm->tpSystem == VMM_SYSTEM_WINDOWS_X86)) {
        if(!_wcsicmp(wszPath, L"name-long")) {
            return Util_VfsReadFile_FromPBYTE(pProcess->pObPersistent->uszNameLong, pProcess->pObPersistent->cuszNameLong, pb, cb, pcbRead, cbOffset);
        }
        if(!_wcsicmp(wszPath, L"win-cmdline")) {
            return Util_VfsReadFile_FromPBYTE(pProcess->pObPersistent->UserProcessParams.uszCommandLine, pProcess->pObPersistent->UserProcessParams.cuszCommandLine, pb, cb, pcbRead, cbOffset);
        }
        if(!_wcsicmp(wszPath, L"win-path")) {
            return Util_VfsReadFile_FromPBYTE(pProcess->pObPersistent->uszPathKernel, pProcess->pObPersistent->cuszPathKernel, pb, cb, pcbRead, cbOffset);
        }
    }
    if(ctxVmm->tpSystem == VMM_SYSTEM_WINDOWS_X64) {
        if(!_wcsicmp(wszPath, L"win-eprocess")) {
            return Util_VfsReadFile_FromQWORD(pProcess->win.EPROCESS.va, pb, cb, pcbRead, cbOffset, FALSE);
        }
        if(!_wcsicmp(wszPath, L"win-peb")) {
            return Util_VfsReadFile_FromQWORD(pProcess->win.vaPEB, pb, cb, pcbRead, cbOffset, FALSE);
        }
        if(!_wcsicmp(wszPath, L"win-peb32")) {
            return Util_VfsReadFile_FromDWORD(pProcess->win.vaPEB32, pb, cb, pcbRead, cbOffset, FALSE);
        }
    }
    if(ctxVmm->tpSystem == VMM_SYSTEM_WINDOWS_X86) {
        if(!_wcsicmp(wszPath, L"win-eprocess")) {
            return Util_VfsReadFile_FromDWORD((DWORD)pProcess->win.EPROCESS.va, pb, cb, pcbRead, cbOffset, FALSE);
        }
        if(!_wcsicmp(wszPath, L"win-peb")) {
            return Util_VfsReadFile_FromDWORD((DWORD)pProcess->win.vaPEB, pb, cb, pcbRead, cbOffset, FALSE);
        }
    }
    return VMM_STATUS_FILE_INVALID;
}

/*
* Write process root file.
* -- ctx
* -- pb
* -- cb
* -- pcbWrite
* -- cbOffset
* -- return
*/
NTSTATUS MVfsProc_Write(_In_ PVMMDLL_PLUGIN_CONTEXT ctx, _In_reads_(cb) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbWrite, _In_ QWORD cbOffset)
{
    BOOL fFound;
    QWORD cbMemSize;
    LPWSTR wszPath = ctx->wszPath;
    PVMM_PROCESS pProcess = ctx->pProcess;
    // read only files - report zero bytes written
    fFound =
        !_wcsicmp(wszPath, L"dtb") ||
        !_wcsicmp(wszPath, L"name") ||
        !_wcsicmp(wszPath, L"pid") ||
        !_wcsicmp(wszPath, L"ppid") ||
        !_wcsicmp(wszPath, L"state") ||
        !_wcsicmp(wszPath, L"name-long") ||
        !_wcsicmp(wszPath, L"win-cmdline") ||
        !_wcsicmp(wszPath, L"win-eprocess") ||
        !_wcsicmp(wszPath, L"win-kpath") ||
        !_wcsicmp(wszPath, L"win-peb");
    if(fFound) {
        *pcbWrite = 0;
        return VMM_STATUS_SUCCESS;
    }
    // write memory to "vmem" file
    if(!_wcsicmp(wszPath, L"vmem")) {
        cbMemSize = (ctxVmm->tpMemoryModel == VMM_MEMORYMODEL_X64) ? 1ULL << 48 : 1ULL << 32;
        return VmmWriteAsFile(pProcess, 0, cbMemSize, pb, cb, pcbWrite, cbOffset);
    }
    return VMM_STATUS_FILE_INVALID;
}

VOID MVfsProc_List_OsSpecific(_In_ PVMM_PROCESS pProcess, _In_ PVMMDLL_VFS_FILELIST_EXINFO pExInfo, _Inout_ PHANDLE pFileList)
{
    // WINDOWS - 32 & 64-bit
    if((ctxVmm->tpSystem == VMM_SYSTEM_WINDOWS_X64) || (ctxVmm->tpSystem == VMM_SYSTEM_WINDOWS_X86)) {
        VMMDLL_VfsList_AddFile(pFileList, L"name-long", pProcess->pObPersistent->cuszNameLong, pExInfo);
        VMMDLL_VfsList_AddFile(pFileList, L"win-path", pProcess->pObPersistent->cuszPathKernel, pExInfo);
        if(pProcess->pObPersistent->UserProcessParams.cuszCommandLine) {
            VMMDLL_VfsList_AddFile(pFileList, L"win-cmdline", pProcess->pObPersistent->UserProcessParams.cuszCommandLine, pExInfo);
        }
    }
    // WINDOWS - 64-bit specific
    if(ctxVmm->tpSystem == VMM_SYSTEM_WINDOWS_X64) {
        VMMDLL_VfsList_AddFile(pFileList, L"win-eprocess", 16, pExInfo);
        // 64-bit PEB and modules
        if(pProcess->win.vaPEB) {
            VMMDLL_VfsList_AddFile(pFileList, L"win-peb", 16, pExInfo);
        }
        // 32-bit PEB
        if(pProcess->win.vaPEB32) {
            VMMDLL_VfsList_AddFile(pFileList, L"win-peb32", 8, pExInfo);
        }
    }
    // WINDOWS 32-bit specific
    if(ctxVmm->tpSystem == VMM_SYSTEM_WINDOWS_X86) {
        VMMDLL_VfsList_AddFile(pFileList, L"win-eprocess", 8, pExInfo);
        // PEB
        if(pProcess->win.vaPEB) {
            VMMDLL_VfsList_AddFile(pFileList, L"win-peb", 8, pExInfo);
        }
    }
}

/*
* List process root file.
* -- ctx
* -- pFileList
* -- return
*/
BOOL MVfsProc_List(_In_ PVMMDLL_PLUGIN_CONTEXT ctx, _Inout_ PHANDLE pFileList)
{
    PVMM_PROCESS pProcess = ctx->pProcess;
    VMMDLL_VFS_FILELIST_EXINFO ExInfo = { 0 };
    Util_VfsTimeStampFile(pProcess, &ExInfo);
    // populate process directory - list standard files and subdirectories
    if(!ctx->wszPath[0]) {
        VMMDLL_VfsList_AddFile(pFileList, L"name", 16, &ExInfo);
        VMMDLL_VfsList_AddFile(pFileList, L"pid", 10, &ExInfo);
        VMMDLL_VfsList_AddFile(pFileList, L"ppid", 10, &ExInfo);
        VMMDLL_VfsList_AddFile(pFileList, L"state", 10, &ExInfo);
        if(ctxVmm->tpMemoryModel == VMM_MEMORYMODEL_X64) {
            VMMDLL_VfsList_AddFile(pFileList, L"vmem", 0x0001000000000000, &ExInfo);
            VMMDLL_VfsList_AddFile(pFileList, L"dtb", 16, &ExInfo);
            if(pProcess->paDTB_UserOpt) { VMMDLL_VfsList_AddFile(pFileList, L"dtb-user", 16, &ExInfo); }
        } else if(ctxVmm->tpMemoryModel == VMM_MEMORYMODEL_X86 || ctxVmm->tpMemoryModel == VMM_MEMORYMODEL_X86PAE) {
            VMMDLL_VfsList_AddFile(pFileList, L"vmem", 0x100000000, &ExInfo);
            VMMDLL_VfsList_AddFile(pFileList, L"dtb", 8, &ExInfo);
            if(pProcess->paDTB_UserOpt) { VMMDLL_VfsList_AddFile(pFileList, L"dtb-user", 8, &ExInfo); }
        }
        MVfsProc_List_OsSpecific(pProcess, &ExInfo, pFileList);
    }
    return TRUE;
}

/*
* Initialize the process root plugin.
* -- pPluginRegInfo
*/
VOID M_VfsProc_Initialize(_Inout_ PVMMDLL_PLUGIN_REGINFO pRI)
{
    wcscpy_s(pRI->reg_info.wszPathName, 128, L"\\");                     // module name
    pRI->reg_info.fProcessModule = TRUE;                                 // process module
    pRI->reg_fn.pfnList = MVfsProc_List;                                 // List function supported
    pRI->reg_fn.pfnRead = MVfsProc_Read;                                 // Read function supported
    pRI->reg_fn.pfnWrite = MVfsProc_Write;                               // Write function supported
    pRI->pfnPluginManager_Register(pRI);
}
