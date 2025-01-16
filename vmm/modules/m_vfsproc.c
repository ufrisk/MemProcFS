// m_vfsproc.h : implementation of virtual file system process root.
//
// (c) Ulf Frisk, 2020-2025
// Author: Ulf Frisk, pcileech@frizk.net
//

#include "modules.h"
#include "../vmmproc.h"
#include "../vmmwin.h"

/*
* Read process root file.
* -- H
* -- ctxP
* -- pb
* -- cb
* -- pcbRead
* -- cbOffset
* -- return
*/
NTSTATUS MVfsProc_Read(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_CONTEXT ctxP, _Out_writes_to_(cb, *pcbRead) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset)
{
    VMM_MEMORYMODEL_TP tpMemoryModel = H->vmm.tpMemoryModel;
    VMM_SYSTEM_TP tpSystem = H->vmm.tpSystem;
    QWORD cbMemSize;
    BYTE pbBuffer[0x800] = { 0 };
    LPSTR uszPath = ctxP->uszPath;
    PVMM_PROCESS pProcess = ctxP->pProcess;
    PVMMWIN_USER_PROCESS_PARAMETERS pUserProcessParams = VmmWin_UserProcessParameters_Get(H, pProcess);    // don't free
    // read memory from "memory.vmem" file
    if(!_stricmp(uszPath, "memory.vmem")) {
        cbMemSize = ((tpMemoryModel == VMM_MEMORYMODEL_X64) || (tpMemoryModel == VMM_MEMORYMODEL_ARM64)) ? 1ULL << 48 : 1ULL << 32;
        return VmmReadAsFile(H, pProcess, 0, cbMemSize, pb, cb, pcbRead, cbOffset);
    }
    // read genereal numeric values from files, pml4, pid, name, virt
    if(!_stricmp(uszPath, "dtb.txt")) {
        if((tpMemoryModel == VMM_MEMORYMODEL_X64) || (tpMemoryModel == VMM_MEMORYMODEL_ARM64)) {
            return Util_VfsReadFile_FromQWORD(pProcess->paDTB, pb, cb, pcbRead, cbOffset, FALSE);
        } else if((tpMemoryModel == VMM_MEMORYMODEL_X86) || (tpMemoryModel == VMM_MEMORYMODEL_X86PAE)) {
            return Util_VfsReadFile_FromDWORD((DWORD)pProcess->paDTB, pb, cb, pcbRead, cbOffset, FALSE);
        }
    }
    if(!_stricmp(uszPath, "dtb-kernel.txt")) {
        if((tpMemoryModel == VMM_MEMORYMODEL_X64) || (tpMemoryModel == VMM_MEMORYMODEL_ARM64)) {
            return Util_VfsReadFile_FromQWORD(pProcess->paDTB_Kernel, pb, cb, pcbRead, cbOffset, FALSE);
        } else if((tpMemoryModel == VMM_MEMORYMODEL_X86) || (tpMemoryModel == VMM_MEMORYMODEL_X86PAE)) {
            return Util_VfsReadFile_FromDWORD((DWORD)pProcess->paDTB_Kernel, pb, cb, pcbRead, cbOffset, FALSE);
        }
    }
    if(!_stricmp(uszPath, "dtb-user.txt")) {
        if((tpMemoryModel == VMM_MEMORYMODEL_X64) || (tpMemoryModel == VMM_MEMORYMODEL_ARM64)) {
            return Util_VfsReadFile_FromQWORD(pProcess->paDTB_UserOpt, pb, cb, pcbRead, cbOffset, FALSE);
        } else if((tpMemoryModel == VMM_MEMORYMODEL_X86) || (tpMemoryModel == VMM_MEMORYMODEL_X86PAE)) {
            return Util_VfsReadFile_FromDWORD((DWORD)pProcess->paDTB_UserOpt, pb, cb, pcbRead, cbOffset, FALSE);
        }
    }
    if(!_stricmp(uszPath, "pid.txt")) {
        return Util_VfsReadFile_usnprintf_ln(pb, cb, pcbRead, cbOffset, 11, "%i", pProcess->dwPID);
    }
    if(!_stricmp(uszPath, "ppid.txt")) {
        return Util_VfsReadFile_usnprintf_ln(pb, cb, pcbRead, cbOffset, 11, "%i", pProcess->dwPPID);
    }
    if(!_stricmp(uszPath, "state.txt")) {
        return Util_VfsReadFile_usnprintf_ln(pb, cb, pcbRead, cbOffset, 11, "%i", pProcess->dwState);
    }
    if(!_stricmp(uszPath, "name.txt")) {
        return Util_VfsReadFile_usnprintf_ln(pb, cb, pcbRead, cbOffset, 16, "%s", pProcess->szName);
    }
    if(!_stricmp(uszPath, "time-create.txt")) {
        return Util_VfsReadFile_FromFILETIME(VmmProcess_GetCreateTimeOpt(H, pProcess), pb, cb, pcbRead, cbOffset);
    }
    if(!_stricmp(uszPath, "time-exit.txt")) {
        return Util_VfsReadFile_FromFILETIME(VmmProcess_GetExitTimeOpt(H, pProcess), pb, cb, pcbRead, cbOffset);
    }
    // windows specific reads below:
    if((tpSystem == VMM_SYSTEM_WINDOWS_64) || (tpSystem == VMM_SYSTEM_WINDOWS_32)) {
        if(!_stricmp(uszPath, "name-long.txt")) {
            return Util_VfsReadFile_FromPBYTE(pProcess->pObPersistent->uszNameLong, pProcess->pObPersistent->cuszNameLong, pb, cb, pcbRead, cbOffset);
        }
        if(!_stricmp(uszPath, "win-path.txt")) {
            return Util_VfsReadFile_FromPBYTE(pProcess->pObPersistent->uszPathKernel, pProcess->pObPersistent->cuszPathKernel, pb, cb, pcbRead, cbOffset);
        }
        if(!_stricmp(uszPath, "win-cmdline.txt")) {
            return Util_VfsReadFile_FromPBYTE(pUserProcessParams->uszCommandLine, max(1, pUserProcessParams->cbuCommandLine) - 1, pb, cb, pcbRead, cbOffset);
        }
        if(!_stricmp(uszPath, "win-curdir.txt")) {
            return Util_VfsReadFile_FromPBYTE(pUserProcessParams->uszCurrentDirectory, max(1, pUserProcessParams->cbuCurrentDirectory) - 1, pb, cb, pcbRead, cbOffset);
        }
        if(!_stricmp(uszPath, "win-environment.txt")) {
            return Util_VfsReadFile_FromPBYTE(pUserProcessParams->uszEnvironment, max(1, pUserProcessParams->cbuEnvironment) - 1, pb, cb, pcbRead, cbOffset);
        }
        if(!_stricmp(uszPath, "win-title.txt")) {
            return Util_VfsReadFile_FromPBYTE(pUserProcessParams->uszWindowTitle, max(1, pUserProcessParams->cbuWindowTitle) - 1, pb, cb, pcbRead, cbOffset);
        }
    }
    if(tpSystem == VMM_SYSTEM_WINDOWS_64) {
        if(!_stricmp(uszPath, "win-eprocess.txt")) {
            return Util_VfsReadFile_FromQWORD(pProcess->win.EPROCESS.va, pb, cb, pcbRead, cbOffset, FALSE);
        }
        if(!_stricmp(uszPath, "win-peb.txt")) {
            return Util_VfsReadFile_FromQWORD(pProcess->win.vaPEB, pb, cb, pcbRead, cbOffset, FALSE);
        }
        if(!_stricmp(uszPath, "win-peb32.txt")) {
            return Util_VfsReadFile_FromDWORD(pProcess->win.vaPEB32, pb, cb, pcbRead, cbOffset, FALSE);
        }
    }
    if(H->vmm.tpSystem == VMM_SYSTEM_WINDOWS_32) {
        if(!_stricmp(uszPath, "win-eprocess.txt")) {
            return Util_VfsReadFile_FromDWORD((DWORD)pProcess->win.EPROCESS.va, pb, cb, pcbRead, cbOffset, FALSE);
        }
        if(!_stricmp(uszPath, "win-peb.txt")) {
            return Util_VfsReadFile_FromDWORD((DWORD)pProcess->win.vaPEB, pb, cb, pcbRead, cbOffset, FALSE);
        }
    }
    return VMM_STATUS_FILE_INVALID;
}

/*
* Write process root file.
* -- H
* -- ctxP
* -- pb
* -- cb
* -- pcbWrite
* -- cbOffset
* -- return
*/
NTSTATUS MVfsProc_Write(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_CONTEXT ctxP, _In_reads_(cb) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbWrite, _In_ QWORD cbOffset)
{
    VMM_MEMORYMODEL_TP tpMemoryModel = H->vmm.tpMemoryModel;
    NTSTATUS nt = VMM_STATUS_FILE_INVALID;
    BOOL fFound;
    QWORD cbMemSize;
    LPSTR uszPath = ctxP->uszPath;
    PVMM_PROCESS pProcess = ctxP->pProcess;
    // read only files - report zero bytes written:
    fFound =
        !_stricmp(uszPath, "dtb-kernel.txt") ||
        !_stricmp(uszPath, "dtb-user.txt") ||
        !_stricmp(uszPath, "name.txt") ||
        !_stricmp(uszPath, "pid.txt") ||
        !_stricmp(uszPath, "ppid.txt") ||
        !_stricmp(uszPath, "state.txt") ||
        !_stricmp(uszPath, "name-long") ||
        !_stricmp(uszPath, "win-cmdline.txt") ||
        !_stricmp(uszPath, "win-curdir.txt") ||
        !_stricmp(uszPath, "win-environment.txt") ||
        !_stricmp(uszPath, "win-eprocess.txt") ||
        !_stricmp(uszPath, "win-path.txt") ||
        !_stricmp(uszPath, "win-peb.txt") ||
        !_stricmp(uszPath, "win-title.txt");
    if(fFound) {
        *pcbWrite = 0;
        return VMM_STATUS_SUCCESS;
    }
    // write memory to "memory.vmem" file:
    if(!_stricmp(uszPath, "memory.vmem")) {
        cbMemSize = ((tpMemoryModel == VMM_MEMORYMODEL_X64) || (tpMemoryModel == VMM_MEMORYMODEL_ARM64)) ? 1ULL << 48 : 1ULL << 32;
        return VmmWriteAsFile(H, pProcess, 0, cbMemSize, pb, cb, pcbWrite, cbOffset);
    }
    // write to dtb (force set custom dtb):
    if(!_stricmp(uszPath, "dtb.txt")) {
        if((tpMemoryModel == VMM_MEMORYMODEL_X64) || (tpMemoryModel == VMM_MEMORYMODEL_ARM64)) {
            nt = Util_VfsWriteFile_QWORD(&pProcess->pObPersistent->paDTB_Override, pb, cb, pcbWrite, cbOffset, 0, 0);
        } else if((tpMemoryModel == VMM_MEMORYMODEL_X86) || (tpMemoryModel == VMM_MEMORYMODEL_X86PAE)) {
            nt = Util_VfsWriteFile_DWORD((PDWORD)&pProcess->pObPersistent->paDTB_Override, pb, cb, pcbWrite, cbOffset, 0, 0);
        }
        VmmProcRefresh_Slow(H);
        return nt;
    }
    return VMM_STATUS_FILE_INVALID;
}

VOID MVfsProc_List_OsSpecific(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess, _In_ PVMMDLL_VFS_FILELIST_EXINFO pExInfo, _Inout_ PHANDLE pFileList)
{
    PVMMWIN_USER_PROCESS_PARAMETERS pUserProcessParams = VmmWin_UserProcessParameters_Get(H, pProcess);    // don't free
    // WINDOWS - 32 & 64-bit
    if((H->vmm.tpSystem == VMM_SYSTEM_WINDOWS_64) || (H->vmm.tpSystem == VMM_SYSTEM_WINDOWS_32)) {
        VMMDLL_VfsList_AddFile(pFileList, "name-long.txt", pProcess->pObPersistent->cuszNameLong, pExInfo);
        VMMDLL_VfsList_AddFile(pFileList, "win-path.txt", pProcess->pObPersistent->cuszPathKernel, pExInfo);
        if(pUserProcessParams->uszCommandLine) {
            VMMDLL_VfsList_AddFile(pFileList, "win-cmdline.txt", max(1, pUserProcessParams->cbuCommandLine) - 1, pExInfo);
        }
        if(pUserProcessParams->uszCurrentDirectory) {
            VMMDLL_VfsList_AddFile(pFileList, "win-curdir.txt", max(1, pUserProcessParams->cbuCurrentDirectory) - 1, pExInfo);
        }
        if(pUserProcessParams->uszEnvironment) {
            VMMDLL_VfsList_AddFile(pFileList, "win-environment.txt", max(1, pUserProcessParams->cbuEnvironment) - 1, pExInfo);
        }
        if(pUserProcessParams->uszWindowTitle) {
            VMMDLL_VfsList_AddFile(pFileList, "win-title.txt", max(1, pUserProcessParams->cbuWindowTitle) - 1, pExInfo);
        }
        VMMDLL_VfsList_AddFile(pFileList, "time-create.txt", 24, pExInfo);
        if(pProcess->dwState) {
            VMMDLL_VfsList_AddFile(pFileList, "time-exit.txt", 24, pExInfo);
        }
    }
    // WINDOWS - 64-bit specific
    if(H->vmm.tpSystem == VMM_SYSTEM_WINDOWS_64) {
        VMMDLL_VfsList_AddFile(pFileList, "win-eprocess.txt", 16, pExInfo);
        // 64-bit PEB and modules
        if(pProcess->win.vaPEB) {
            VMMDLL_VfsList_AddFile(pFileList, "win-peb.txt", 16, pExInfo);
        }
        // 32-bit PEB
        if(pProcess->win.vaPEB32) {
            VMMDLL_VfsList_AddFile(pFileList, "win-peb32.txt", 8, pExInfo);
        }
    }
    // WINDOWS 32-bit specific
    if(H->vmm.tpSystem == VMM_SYSTEM_WINDOWS_32) {
        VMMDLL_VfsList_AddFile(pFileList, "win-eprocess.txt", 8, pExInfo);
        // PEB
        if(pProcess->win.vaPEB) {
            VMMDLL_VfsList_AddFile(pFileList, "win-peb.txt", 8, pExInfo);
        }
    }
}

/*
* List process root file.
* -- H
* -- ctxP
* -- pFileList
* -- return
*/
BOOL MVfsProc_List(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_CONTEXT ctxP, _Inout_ PHANDLE pFileList)
{
    PVMM_PROCESS pProcess = ctxP->pProcess;
    VMMDLL_VFS_FILELIST_EXINFO ExInfo = { 0 };
    VMM_MEMORYMODEL_TP tpMemoryModel = H->vmm.tpMemoryModel;
    Util_VfsTimeStampFile(H, pProcess, &ExInfo);
    // populate process directory - list standard files and subdirectories
    if(!ctxP->uszPath[0]) {
        VMMDLL_VfsList_AddFile(pFileList, "name.txt", 16, &ExInfo);
        VMMDLL_VfsList_AddFile(pFileList, "pid.txt", 11, &ExInfo);
        VMMDLL_VfsList_AddFile(pFileList, "ppid.txt", 11, &ExInfo);
        VMMDLL_VfsList_AddFile(pFileList, "state.txt", 11, &ExInfo);
        if((tpMemoryModel == VMM_MEMORYMODEL_X64) || (tpMemoryModel == VMM_MEMORYMODEL_ARM64)) {
            VMMDLL_VfsList_AddFile(pFileList, "memory.vmem", 0x0001000000000000, &ExInfo);
            VMMDLL_VfsList_AddFile(pFileList, "dtb.txt", 16, &ExInfo);
            if(pProcess->paDTB_UserOpt) { VMMDLL_VfsList_AddFile(pFileList, "dtb-user.txt", 16, &ExInfo); }
            if(pProcess->paDTB != pProcess->paDTB_Kernel) { VMMDLL_VfsList_AddFile(pFileList, "dtb-kernel.txt", 16, &ExInfo); }
        } else if(tpMemoryModel == VMM_MEMORYMODEL_X86 || tpMemoryModel == VMM_MEMORYMODEL_X86PAE) {
            VMMDLL_VfsList_AddFile(pFileList, "memory.vmem", 0x100000000, &ExInfo);
            VMMDLL_VfsList_AddFile(pFileList, "dtb.txt", 8, &ExInfo);
            if(pProcess->paDTB_UserOpt) { VMMDLL_VfsList_AddFile(pFileList, "dtb-user.txt", 8, &ExInfo); }
            if(pProcess->paDTB != pProcess->paDTB_Kernel) { VMMDLL_VfsList_AddFile(pFileList, "dtb-kernel.txt", 8, &ExInfo); }
        }
        MVfsProc_List_OsSpecific(H, pProcess, &ExInfo, pFileList);
    }
    return TRUE;
}

/*
* Initialize the process root plugin.
* -- H
* -- pRI
*/
VOID M_VfsProc_Initialize(_In_ VMM_HANDLE H, _Inout_ PVMMDLL_PLUGIN_REGINFO pRI)
{
    strcpy_s(pRI->reg_info.uszPathName, 128, "\\");                      // module name
    pRI->reg_info.fProcessModule = TRUE;                                 // process module
    pRI->reg_fn.pfnList = MVfsProc_List;                                 // List function supported
    pRI->reg_fn.pfnRead = MVfsProc_Read;                                 // Read function supported
    pRI->reg_fn.pfnWrite = MVfsProc_Write;                               // Write function supported
    pRI->pfnPluginManager_Register(H, pRI);
}
