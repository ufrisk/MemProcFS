// m_vfsproc.h : implementation of virtual file system process root.
//
// (c) Ulf Frisk, 2020-2021
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
    BYTE pbBuffer[0x800] = { 0 };
    LPWSTR wszPath = ctx->wszPath;
    PVMM_PROCESS pProcess = ctx->pProcess;
    // read memory from "memory.vmem" file
    if(!_wcsicmp(wszPath, L"memory.vmem")) {
        cbMemSize = (ctxVmm->tpMemoryModel == VMM_MEMORYMODEL_X64) ? 1ULL << 48 : 1ULL << 32;
        return VmmReadAsFile(pProcess, 0, cbMemSize, pb, cb, pcbRead, cbOffset);
    }
    // read genereal numeric values from files, pml4, pid, name, virt
    if(!_wcsicmp(wszPath, L"dtb.txt")) {
        if(ctxVmm->tpMemoryModel == VMM_MEMORYMODEL_X64) {
            return Util_VfsReadFile_FromQWORD(pProcess->paDTB, pb, cb, pcbRead, cbOffset, FALSE);
        } else if((ctxVmm->tpMemoryModel == VMM_MEMORYMODEL_X86) || (ctxVmm->tpMemoryModel == VMM_MEMORYMODEL_X86PAE)) {
            return Util_VfsReadFile_FromDWORD((DWORD)pProcess->paDTB, pb, cb, pcbRead, cbOffset, FALSE);
        }
    }
    if(!_wcsicmp(wszPath, L"dtb-user.txt")) {
        if(ctxVmm->tpMemoryModel == VMM_MEMORYMODEL_X64) {
            return Util_VfsReadFile_FromQWORD(pProcess->paDTB_UserOpt, pb, cb, pcbRead, cbOffset, FALSE);
        } else if((ctxVmm->tpMemoryModel == VMM_MEMORYMODEL_X86) || (ctxVmm->tpMemoryModel == VMM_MEMORYMODEL_X86PAE)) {
            return Util_VfsReadFile_FromDWORD((DWORD)pProcess->paDTB_UserOpt, pb, cb, pcbRead, cbOffset, FALSE);
        }
    }
    if(!_wcsicmp(wszPath, L"pid.txt")) {
        return Util_VfsReadFile_snwprintf_u8ln(pb, cb, pcbRead, cbOffset, 11, L"%i", pProcess->dwPID);
    }
    if(!_wcsicmp(wszPath, L"ppid.txt")) {
        return Util_VfsReadFile_snwprintf_u8ln(pb, cb, pcbRead, cbOffset, 11, L"%i", pProcess->dwPPID);
    }
    if(!_wcsicmp(wszPath, L"state.txt")) {
        return Util_VfsReadFile_snwprintf_u8ln(pb, cb, pcbRead, cbOffset, 11, L"%i", pProcess->dwState);
    }
    if(!_wcsicmp(wszPath, L"name.txt")) {
        return Util_VfsReadFile_snwprintf_u8ln(pb, cb, pcbRead, cbOffset, 16, L"%S", pProcess->szName);
    }
    if(!_wcsicmp(wszPath, L"time-create.txt")) {
        return Util_VfsReadFile_FromFILETIME(VmmProcess_GetCreateTimeOpt(pProcess), pb, cb, pcbRead, cbOffset);
    }
    if(!_wcsicmp(wszPath, L"time-exit.txt")) {
        return Util_VfsReadFile_FromFILETIME(VmmProcess_GetExitTimeOpt(pProcess), pb, cb, pcbRead, cbOffset);
    }
    // windows specific reads below:
    if((ctxVmm->tpSystem == VMM_SYSTEM_WINDOWS_X64) || (ctxVmm->tpSystem == VMM_SYSTEM_WINDOWS_X86)) {
        if(!_wcsicmp(wszPath, L"name-long.txt")) {
            return Util_VfsReadFile_FromPBYTE(pProcess->pObPersistent->uszNameLong, pProcess->pObPersistent->cuszNameLong, pb, cb, pcbRead, cbOffset);
        }
        if(!_wcsicmp(wszPath, L"win-cmdline.txt")) {
            return Util_VfsReadFile_FromPBYTE(pProcess->pObPersistent->UserProcessParams.uszCommandLine, pProcess->pObPersistent->UserProcessParams.cuszCommandLine, pb, cb, pcbRead, cbOffset);
        }
        if(!_wcsicmp(wszPath, L"win-path.txt")) {
            return Util_VfsReadFile_FromPBYTE(pProcess->pObPersistent->uszPathKernel, pProcess->pObPersistent->cuszPathKernel, pb, cb, pcbRead, cbOffset);
        }
    }
    if(ctxVmm->tpSystem == VMM_SYSTEM_WINDOWS_X64) {
        if(!_wcsicmp(wszPath, L"win-eprocess.txt")) {
            return Util_VfsReadFile_FromQWORD(pProcess->win.EPROCESS.va, pb, cb, pcbRead, cbOffset, FALSE);
        }
        if(!_wcsicmp(wszPath, L"win-peb.txt")) {
            return Util_VfsReadFile_FromQWORD(pProcess->win.vaPEB, pb, cb, pcbRead, cbOffset, FALSE);
        }
        if(!_wcsicmp(wszPath, L"win-peb32.txt")) {
            return Util_VfsReadFile_FromDWORD(pProcess->win.vaPEB32, pb, cb, pcbRead, cbOffset, FALSE);
        }
    }
    if(ctxVmm->tpSystem == VMM_SYSTEM_WINDOWS_X86) {
        if(!_wcsicmp(wszPath, L"win-eprocess.txt")) {
            return Util_VfsReadFile_FromDWORD((DWORD)pProcess->win.EPROCESS.va, pb, cb, pcbRead, cbOffset, FALSE);
        }
        if(!_wcsicmp(wszPath, L"win-peb.txt")) {
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
        !_wcsicmp(wszPath, L"dtb.txt") ||
        !_wcsicmp(wszPath, L"name.txt") ||
        !_wcsicmp(wszPath, L"pid.txt") ||
        !_wcsicmp(wszPath, L"ppid.txt") ||
        !_wcsicmp(wszPath, L"state.txt") ||
        !_wcsicmp(wszPath, L"name-long") ||
        !_wcsicmp(wszPath, L"win-cmdline.txt") ||
        !_wcsicmp(wszPath, L"win-eprocess.txt") ||
        !_wcsicmp(wszPath, L"win-path.txt") ||
        !_wcsicmp(wszPath, L"win-peb.txt");
    if(fFound) {
        *pcbWrite = 0;
        return VMM_STATUS_SUCCESS;
    }
    // write memory to "memory.vmem" file
    if(!_wcsicmp(wszPath, L"memory.vmem")) {
        cbMemSize = (ctxVmm->tpMemoryModel == VMM_MEMORYMODEL_X64) ? 1ULL << 48 : 1ULL << 32;
        return VmmWriteAsFile(pProcess, 0, cbMemSize, pb, cb, pcbWrite, cbOffset);
    }
    return VMM_STATUS_FILE_INVALID;
}

VOID MVfsProc_List_OsSpecific(_In_ PVMM_PROCESS pProcess, _In_ PVMMDLL_VFS_FILELIST_EXINFO pExInfo, _Inout_ PHANDLE pFileList)
{
    // WINDOWS - 32 & 64-bit
    if((ctxVmm->tpSystem == VMM_SYSTEM_WINDOWS_X64) || (ctxVmm->tpSystem == VMM_SYSTEM_WINDOWS_X86)) {
        VMMDLL_VfsList_AddFile(pFileList, L"name-long.txt", pProcess->pObPersistent->cuszNameLong, pExInfo);
        VMMDLL_VfsList_AddFile(pFileList, L"win-path.txt", pProcess->pObPersistent->cuszPathKernel, pExInfo);
        if(pProcess->pObPersistent->UserProcessParams.cuszCommandLine) {
            VMMDLL_VfsList_AddFile(pFileList, L"win-cmdline.txt", pProcess->pObPersistent->UserProcessParams.cuszCommandLine, pExInfo);
        }
        VMMDLL_VfsList_AddFile(pFileList, L"time-create.txt", 24, pExInfo);
        if(pProcess->dwState) {
            VMMDLL_VfsList_AddFile(pFileList, L"time-exit.txt", 24, pExInfo);
        }
    }
    // WINDOWS - 64-bit specific
    if(ctxVmm->tpSystem == VMM_SYSTEM_WINDOWS_X64) {
        VMMDLL_VfsList_AddFile(pFileList, L"win-eprocess.txt", 16, pExInfo);
        // 64-bit PEB and modules
        if(pProcess->win.vaPEB) {
            VMMDLL_VfsList_AddFile(pFileList, L"win-peb.txt", 16, pExInfo);
        }
        // 32-bit PEB
        if(pProcess->win.vaPEB32) {
            VMMDLL_VfsList_AddFile(pFileList, L"win-peb32.txt", 8, pExInfo);
        }
    }
    // WINDOWS 32-bit specific
    if(ctxVmm->tpSystem == VMM_SYSTEM_WINDOWS_X86) {
        VMMDLL_VfsList_AddFile(pFileList, L"win-eprocess.txt", 8, pExInfo);
        // PEB
        if(pProcess->win.vaPEB) {
            VMMDLL_VfsList_AddFile(pFileList, L"win-peb.txt", 8, pExInfo);
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
        VMMDLL_VfsList_AddFile(pFileList, L"name.txt", 16, &ExInfo);
        VMMDLL_VfsList_AddFile(pFileList, L"pid.txt", 11, &ExInfo);
        VMMDLL_VfsList_AddFile(pFileList, L"ppid.txt", 11, &ExInfo);
        VMMDLL_VfsList_AddFile(pFileList, L"state.txt", 11, &ExInfo);
        if(ctxVmm->tpMemoryModel == VMM_MEMORYMODEL_X64) {
            VMMDLL_VfsList_AddFile(pFileList, L"memory.vmem", 0x0001000000000000, &ExInfo);
            VMMDLL_VfsList_AddFile(pFileList, L"dtb.txt", 16, &ExInfo);
            if(pProcess->paDTB_UserOpt) { VMMDLL_VfsList_AddFile(pFileList, L"dtb-user.txt", 16, &ExInfo); }
        } else if(ctxVmm->tpMemoryModel == VMM_MEMORYMODEL_X86 || ctxVmm->tpMemoryModel == VMM_MEMORYMODEL_X86PAE) {
            VMMDLL_VfsList_AddFile(pFileList, L"memory.vmem", 0x100000000, &ExInfo);
            VMMDLL_VfsList_AddFile(pFileList, L"dtb.txt", 8, &ExInfo);
            if(pProcess->paDTB_UserOpt) { VMMDLL_VfsList_AddFile(pFileList, L"dtb-user.txt", 8, &ExInfo); }
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
