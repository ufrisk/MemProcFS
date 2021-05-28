// m_sys.c : implementation related to the Sys built-in module.
//
// The '/sys' module is responsible for displaying various informational files
// at the path '/sys/'
//
// (c) Ulf Frisk, 2019-2021
// Author: Ulf Frisk, pcileech@frizk.net
//
#include "vmm.h"
#include "vmmwin.h"
#include "vmmwinreg.h"
#include "sysquery.h"
#include "util.h"
#include "charutil.h"

VOID MSys_QueryTimeZone(_Out_writes_(49) LPSTR uszTimeZone, _In_ BOOL fLine)
{
    int iTimeZoneActiveBias = 0;
    CHAR uszTimeZoneName[0x20] = { 0 };
    if(SysQuery_TimeZone(uszTimeZoneName, &iTimeZoneActiveBias)) {
        if(iTimeZoneActiveBias % 60) {
            if(fLine) {
                Util_usnprintf_ln(uszTimeZone, 48, "%s [UTC%+i]", uszTimeZoneName, -iTimeZoneActiveBias);
            } else {
                snprintf(uszTimeZone, 48, "%s [UTC%+i]", uszTimeZoneName, -iTimeZoneActiveBias);
            }
            
        } else {
            if(fLine) {
                Util_usnprintf_ln(uszTimeZone, 48, "%s : UTC%+i:%02i", uszTimeZoneName, -iTimeZoneActiveBias / 60, iTimeZoneActiveBias % 60);
            } else {
                snprintf(uszTimeZone, 48, "%s : UTC%+i:%02i", uszTimeZoneName, -iTimeZoneActiveBias / 60, iTimeZoneActiveBias % 60);
            }
        }
    } else if(fLine) {
        Util_usnprintf_ln(uszTimeZone, 48, "");
    }
    uszTimeZone[48] = 0;
}

NTSTATUS MSys_Read(_In_ PVMMDLL_PLUGIN_CONTEXT ctx, _Out_writes_to_(cb, *pcbRead) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset)
{
    DWORD cbBuffer, cbData;
    BYTE pbBuffer[0x42] = { 0 };
    BYTE pbRegData[0x42] = { 0 };
    CHAR szTimeZone[64] = { 0 };
    // version.txt
    if(!_stricmp(ctx->uszPath, "version.txt")) {
        cbBuffer = snprintf(pbBuffer, sizeof(pbBuffer), "%i.%i.%i", ctxVmm->kernel.dwVersionMajor, ctxVmm->kernel.dwVersionMinor, ctxVmm->kernel.dwVersionBuild);
        return Util_VfsReadFile_FromPBYTE(pbBuffer, cbBuffer, pb, cb, pcbRead, cbOffset);
    }
    if(!_stricmp(ctx->uszPath, "version-major.txt")) {
        return Util_VfsReadFile_FromNumber(ctxVmm->kernel.dwVersionMajor, pb, cb, pcbRead, cbOffset);
    }
    if(!_stricmp(ctx->uszPath, "version-minor.txt")) {
        return Util_VfsReadFile_FromNumber(ctxVmm->kernel.dwVersionMinor, pb, cb, pcbRead, cbOffset);
    }
    if(!_stricmp(ctx->uszPath, "version-build.txt")) {
        return Util_VfsReadFile_FromNumber(ctxVmm->kernel.dwVersionBuild, pb, cb, pcbRead, cbOffset);
    }
    if(!_stricmp(ctx->uszPath, "unique-tag.txt")) {
        return Util_VfsReadFile_FromPBYTE(ctxVmm->szSystemUniqueTag, strlen(ctxVmm->szSystemUniqueTag), pb, cb, pcbRead, cbOffset);
    }
    if(!_stricmp(ctx->uszPath, "architecture.txt")) {
        return Util_VfsReadFile_FromPBYTE(
            VMM_MEMORYMODEL_TOSTRING[ctxVmm->tpMemoryModel],
            strlen(VMM_MEMORYMODEL_TOSTRING[ctxVmm->tpMemoryModel]),
            pb, cb, pcbRead, cbOffset);
    }
    if(!_stricmp(ctx->uszPath, "computername.txt")) {
        VmmWinReg_ValueQuery2("HKLM\\SYSTEM\\ControlSet001\\Control\\ComputerName\\ComputerName\\ComputerName", NULL, pbRegData, sizeof(pbRegData) - 2, &cbData);
        CharUtil_WtoU((LPWSTR)pbRegData, cbData << 1, pbBuffer, sizeof(pbBuffer), NULL, NULL, CHARUTIL_FLAG_TRUNCATE_ONFAIL_NULLSTR | CHARUTIL_FLAG_STR_BUFONLY);
        return Util_VfsReadFile_FromPBYTE(pbBuffer, 32, pb, cb, pcbRead, cbOffset);
    }
    if(!_stricmp(ctx->uszPath, "time-boot.txt")) {
        return Util_VfsReadFile_FromFILETIME(ctxVmm->kernel.opt.ftBootTime, pb, cb, pcbRead, cbOffset);
    }
    if(!_stricmp(ctx->uszPath, "time-current.txt")) {
        return Util_VfsReadFile_FromFILETIME(SysQuery_TimeCurrent(), pb, cb, pcbRead, cbOffset);
    }
    if(!_stricmp(ctx->uszPath, "timezone.txt")) {
        MSys_QueryTimeZone(szTimeZone, TRUE);
        return Util_VfsReadFile_FromPBYTE(szTimeZone, 48, pb, cb, pcbRead, cbOffset);
    }
    return VMMDLL_STATUS_FILE_INVALID;
}

BOOL MSys_List(_In_ PVMMDLL_PLUGIN_CONTEXT ctx, _Inout_ PHANDLE pFileList)
{
    DWORD cchMajor, cchMinor, cchBuild;
    if(ctx->uszPath[0]) { return FALSE; }
    cchMajor = Util_GetNumDigits(ctxVmm->kernel.dwVersionMajor);
    cchMinor = Util_GetNumDigits(ctxVmm->kernel.dwVersionMinor);
    cchBuild = Util_GetNumDigits(ctxVmm->kernel.dwVersionBuild);
    VMMDLL_VfsList_AddFile(pFileList, "version.txt", 2ULL + cchMajor + cchMinor + cchBuild, NULL);
    VMMDLL_VfsList_AddFile(pFileList, "version-major.txt", cchMajor, NULL);
    VMMDLL_VfsList_AddFile(pFileList, "version-minor.txt", cchMinor, NULL);
    VMMDLL_VfsList_AddFile(pFileList, "version-build.txt", cchBuild, NULL);
    VMMDLL_VfsList_AddFile(pFileList, "unique-tag.txt", strlen(ctxVmm->szSystemUniqueTag), NULL);
    VMMDLL_VfsList_AddFile(pFileList, "architecture.txt", strlen(VMM_MEMORYMODEL_TOSTRING[ctxVmm->tpMemoryModel]), NULL);
    VMMDLL_VfsList_AddFile(pFileList, "computername.txt", 32, NULL);
    VMMDLL_VfsList_AddFile(pFileList, "time-boot.txt", 24, NULL);
    VMMDLL_VfsList_AddFile(pFileList, "time-current.txt", 24, NULL);
    VMMDLL_VfsList_AddFile(pFileList, "timezone.txt", 48, NULL);
    return TRUE;
}

VOID MSys_FcLogJSON(_In_ PVMMDLL_PLUGIN_CONTEXT ctxP, _In_ VOID(*pfnLogJSON)(_In_ PVMMDLL_PLUGIN_FORENSIC_JSONDATA pData))
{
    PVMMDLL_PLUGIN_FORENSIC_JSONDATA pd;
    CHAR usz[MAX_PATH], szTimeBoot[24], szTimeCurrent[24], szTimeZone[64];
    BYTE pbComputerName[0x42] = { 0 };
    if(ctxP->pProcess || !(pd = LocalAlloc(LMEM_ZEROINIT, sizeof(VMMDLL_PLUGIN_FORENSIC_JSONDATA)))) { return; }
    Util_FileTime2String(ctxVmm->kernel.opt.ftBootTime, szTimeBoot);
    Util_FileTime2String(SysQuery_TimeCurrent(), szTimeCurrent);
    MSys_QueryTimeZone(szTimeZone, FALSE);
    VmmWinReg_ValueQuery2("HKLM\\SYSTEM\\ControlSet001\\Control\\ComputerName\\ComputerName\\ComputerName", NULL, pbComputerName, sizeof(pbComputerName) - 2, NULL);
    snprintf(usz, sizeof(usz), "architecture:[%s] version:[%i.%i.%i] time-boot:[%s] time-current:[%s], timezone[%s]",
        VMM_MEMORYMODEL_TOSTRING[ctxVmm->tpMemoryModel],
        ctxVmm->kernel.dwVersionMajor, ctxVmm->kernel.dwVersionMinor, ctxVmm->kernel.dwVersionBuild,
        szTimeBoot, szTimeCurrent, szTimeZone
    );
    pd->dwVersion = VMMDLL_PLUGIN_FORENSIC_JSONDATA_VERSION;
    pd->szjType = "systeminformation";
    pd->vaObj = ctxVmm->kernel.vaBase;
    pd->va[0] = ctxVmm->kernel.opt.KDBG.va;
    pd->wsz[0] = (LPCWSTR)pbComputerName;
    pd->usz[1] = usz;
    pfnLogJSON(pd);
    LocalFree(pd);
}

VOID M_Sys_Initialize(_Inout_ PVMMDLL_PLUGIN_REGINFO pRI)
{
    if((pRI->magic != VMMDLL_PLUGIN_REGINFO_MAGIC) || (pRI->wVersion != VMMDLL_PLUGIN_REGINFO_VERSION)) { return; }
    if((pRI->tpSystem != VMM_SYSTEM_WINDOWS_X64) && (pRI->tpSystem != VMM_SYSTEM_WINDOWS_X86)) { return; }
    strcpy_s(pRI->reg_info.uszPathName, 128, "\\sys");      // module name
    pRI->reg_info.fRootModule = TRUE;                       // module shows in root directory
    pRI->reg_fn.pfnList = MSys_List;                        // List function supported
    pRI->reg_fn.pfnRead = MSys_Read;                        // Read function supported
    pRI->reg_fnfc.pfnLogJSON = MSys_FcLogJSON;              // JSON log function supported
    pRI->pfnPluginManager_Register(pRI);
}
