// m_sysinfo.c : implementation related to the SysInfo built-in module.
//
// The SysInfo module is responsible for displaying various informational files
// at the path /sysinfo/
//
// (c) Ulf Frisk, 2019-2020
// Author: Ulf Frisk, pcileech@frizk.net
//
#include <ws2tcpip.h>
#include "vmm.h"
#include "vmmwin.h"
#include "vmmwinreg.h"
#include "util.h"

NTSTATUS MSysInfo_Read(_In_ PVMMDLL_PLUGIN_CONTEXT ctx, _Out_ PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset)
{
    DWORD cbBuffer;
    BYTE pbBuffer[34] = { 0 };
    BYTE pbRegData[0x42] = { 0 };
    // version.txt
    if(!wcscmp(ctx->wszPath, L"version.txt")) {
        cbBuffer = snprintf(pbBuffer, sizeof(pbBuffer), "%i.%i.%i", ctxVmm->kernel.dwVersionMajor, ctxVmm->kernel.dwVersionMinor, ctxVmm->kernel.dwVersionBuild);
        return Util_VfsReadFile_FromPBYTE(pbBuffer, cbBuffer, pb, cb, pcbRead, cbOffset);
    }
    if(!wcscmp(ctx->wszPath, L"version-major.txt")) {
        return Util_VfsReadFile_FromNumber(ctxVmm->kernel.dwVersionMajor, pb, cb, pcbRead, cbOffset);
    }
    if(!wcscmp(ctx->wszPath, L"version-minor.txt")) {
        return Util_VfsReadFile_FromNumber(ctxVmm->kernel.dwVersionMinor, pb, cb, pcbRead, cbOffset);
    }
    if(!wcscmp(ctx->wszPath, L"version-build.txt")) {
        return Util_VfsReadFile_FromNumber(ctxVmm->kernel.dwVersionBuild, pb, cb, pcbRead, cbOffset);
    }
    if(!wcscmp(ctx->wszPath, L"computername.txt")) {
        VmmWinReg_ValueQuery2(L"HKLM\\SYSTEM\\ControlSet001\\Control\\ComputerName\\ComputerName\\ComputerName", NULL, pbRegData, sizeof(pbRegData) - 2, NULL);
        Util_snprintf_ln((LPSTR)pbBuffer, 34, 33, "%-32S", (LPWSTR)pbRegData);
        return Util_VfsReadFile_FromPBYTE(pbBuffer, 32, pb, cb, pcbRead, cbOffset);
    }
    return VMMDLL_STATUS_FILE_INVALID;
}

BOOL MSysInfo_List(_In_ PVMMDLL_PLUGIN_CONTEXT ctx, _Inout_ PHANDLE pFileList)
{
    DWORD cchMajor, cchMinor, cchBuild;
    if(ctx->wszPath[0]) { return FALSE; }
    cchMajor = Util_GetNumDigits(ctxVmm->kernel.dwVersionMajor);
    cchMinor = Util_GetNumDigits(ctxVmm->kernel.dwVersionMinor);
    cchBuild = Util_GetNumDigits(ctxVmm->kernel.dwVersionBuild);
    VMMDLL_VfsList_AddFile(pFileList, L"version.txt", 2ULL + cchMajor + cchMinor + cchBuild, NULL);
    VMMDLL_VfsList_AddFile(pFileList, L"version-major.txt", cchMajor, NULL);
    VMMDLL_VfsList_AddFile(pFileList, L"version-minor.txt", cchMinor, NULL);
    VMMDLL_VfsList_AddFile(pFileList, L"version-build.txt", cchBuild, NULL);
    VMMDLL_VfsList_AddFile(pFileList, L"computername.txt", 32, NULL);
    return TRUE;
}

VOID M_SysInfo_Initialize(_Inout_ PVMMDLL_PLUGIN_REGINFO pRI)
{
    if((pRI->magic != VMMDLL_PLUGIN_REGINFO_MAGIC) || (pRI->wVersion != VMMDLL_PLUGIN_REGINFO_VERSION)) { return; }
    if((pRI->tpSystem != VMM_SYSTEM_WINDOWS_X64) && (pRI->tpSystem != VMM_SYSTEM_WINDOWS_X86)) { return; }
    wcscpy_s(pRI->reg_info.wszPathName, 128, L"\\sysinfo");     // module name
    pRI->reg_info.fRootModule = TRUE;                           // module shows in root directory
    pRI->reg_fn.pfnList = MSysInfo_List;                        // List function supported
    pRI->reg_fn.pfnRead = MSysInfo_Read;                        // Read function supported
    pRI->pfnPluginManager_Register(pRI);
}
