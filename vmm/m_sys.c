// m_sys.c : implementation related to the Sys built-in module.
//
// The '/sys' module is responsible for displaying various informational files
// at the path '/sys/'
//
// (c) Ulf Frisk, 2019-2021
// Author: Ulf Frisk, pcileech@frizk.net
//
#include <ws2tcpip.h>
#include "vmm.h"
#include "vmmwin.h"
#include "vmmwinreg.h"
#include "sysquery.h"
#include "util.h"

NTSTATUS MSys_Read(_In_ PVMMDLL_PLUGIN_CONTEXT ctx, _Out_writes_to_(cb, *pcbRead) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset)
{
    DWORD cbBuffer;
    int iTimeZoneActiveBias = 0;
    WCHAR wszTimeZoneName[0x20] = { 0 };
    BYTE pbBuffer[0x42] = { 0 };
    BYTE pbRegData[0x42] = { 0 };
    // version.txt
    if(!_wcsicmp(ctx->wszPath, L"version.txt")) {
        cbBuffer = snprintf(pbBuffer, sizeof(pbBuffer), "%i.%i.%i", ctxVmm->kernel.dwVersionMajor, ctxVmm->kernel.dwVersionMinor, ctxVmm->kernel.dwVersionBuild);
        return Util_VfsReadFile_FromPBYTE(pbBuffer, cbBuffer, pb, cb, pcbRead, cbOffset);
    }
    if(!_wcsicmp(ctx->wszPath, L"version-major.txt")) {
        return Util_VfsReadFile_FromNumber(ctxVmm->kernel.dwVersionMajor, pb, cb, pcbRead, cbOffset);
    }
    if(!_wcsicmp(ctx->wszPath, L"version-minor.txt")) {
        return Util_VfsReadFile_FromNumber(ctxVmm->kernel.dwVersionMinor, pb, cb, pcbRead, cbOffset);
    }
    if(!_wcsicmp(ctx->wszPath, L"version-build.txt")) {
        return Util_VfsReadFile_FromNumber(ctxVmm->kernel.dwVersionBuild, pb, cb, pcbRead, cbOffset);
    }
    if(!_wcsicmp(ctx->wszPath, L"computername.txt")) {
        VmmWinReg_ValueQuery2(L"HKLM\\SYSTEM\\ControlSet001\\Control\\ComputerName\\ComputerName\\ComputerName", NULL, pbRegData, sizeof(pbRegData) - 2, NULL);
        Util_snwprintf_u8ln((LPSTR)pbBuffer, 33, L"%s", (LPWSTR)pbRegData);
        return Util_VfsReadFile_FromPBYTE(pbBuffer, 32, pb, cb, pcbRead, cbOffset);
    }
    if(!_wcsicmp(ctx->wszPath, L"time-boot.txt")) {
        return Util_VfsReadFile_FromFILETIME(ctxVmm->kernel.opt.ftBootTime, pb, cb, pcbRead, cbOffset);
    }
    if(!_wcsicmp(ctx->wszPath, L"time-current.txt")) {
        return Util_VfsReadFile_FromFILETIME(SysQuery_TimeCurrent(), pb, cb, pcbRead, cbOffset);
    }
    if(!_wcsicmp(ctx->wszPath, L"timezone.txt")) {
        if(SysQuery_TimeZone(wszTimeZoneName, &iTimeZoneActiveBias)) {
            if(iTimeZoneActiveBias % 60) {
                Util_snwprintf_u8ln((LPSTR)pbBuffer, 0x40, L"%s [UCT%+i]", wszTimeZoneName, -iTimeZoneActiveBias);
            } else {
                Util_snwprintf_u8ln((LPSTR)pbBuffer, 48, L"%s : UTC%+i:%02i", wszTimeZoneName, -iTimeZoneActiveBias / 60, iTimeZoneActiveBias % 60);
            }
        } else {
            Util_snwprintf_u8ln((LPSTR)pbBuffer, 48, L"");
        }
        return Util_VfsReadFile_FromPBYTE(pbBuffer, 48, pb, cb, pcbRead, cbOffset);
    }
    return VMMDLL_STATUS_FILE_INVALID;
}

BOOL MSys_List(_In_ PVMMDLL_PLUGIN_CONTEXT ctx, _Inout_ PHANDLE pFileList)
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
    VMMDLL_VfsList_AddFile(pFileList, L"time-boot.txt", 24, NULL);
    VMMDLL_VfsList_AddFile(pFileList, L"time-current.txt", 24, NULL);
    VMMDLL_VfsList_AddFile(pFileList, L"timezone.txt", 48, NULL);
    return TRUE;
}

VOID M_Sys_Initialize(_Inout_ PVMMDLL_PLUGIN_REGINFO pRI)
{
    if((pRI->magic != VMMDLL_PLUGIN_REGINFO_MAGIC) || (pRI->wVersion != VMMDLL_PLUGIN_REGINFO_VERSION)) { return; }
    if((pRI->tpSystem != VMM_SYSTEM_WINDOWS_X64) && (pRI->tpSystem != VMM_SYSTEM_WINDOWS_X86)) { return; }
    wcscpy_s(pRI->reg_info.wszPathName, 128, L"\\sys");     // module name
    pRI->reg_info.fRootModule = TRUE;                       // module shows in root directory
    pRI->reg_fn.pfnList = MSys_List;                        // List function supported
    pRI->reg_fn.pfnRead = MSys_Read;                        // Read function supported
    pRI->pfnPluginManager_Register(pRI);
}
