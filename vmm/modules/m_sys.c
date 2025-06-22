// m_sys.c : implementation related to the Sys built-in module.
//
// The '/sys' module is responsible for displaying various informational files
// at the path '/sys/'
//
// (c) Ulf Frisk, 2019-2025
// Author: Ulf Frisk, pcileech@frizk.net
//

#include "modules.h"
#include "../sysquery.h"
#include "../vmmwinreg.h"

NTSTATUS MSys_Read(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_CONTEXT ctxP, _Out_writes_to_(cb, *pcbRead) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset)
{
    DWORD i, cbBuffer;
    BYTE pbBuffer[0x42] = { 0 };
    BYTE pbRegData[0x42] = { 0 };
    CHAR szTimeZone[64] = { 0 };
    // version.txt
    if(!_stricmp(ctxP->uszPath, "version.txt")) {
        cbBuffer = snprintf(pbBuffer, sizeof(pbBuffer), "%i.%i.%i", H->vmm.kernel.dwVersionMajor, H->vmm.kernel.dwVersionMinor, H->vmm.kernel.dwVersionBuild);
        return Util_VfsReadFile_FromPBYTE(pbBuffer, cbBuffer, pb, cb, pcbRead, cbOffset);
    }
    if(!_stricmp(ctxP->uszPath, "version-major.txt")) {
        return Util_VfsReadFile_FromNumber(H->vmm.kernel.dwVersionMajor, pb, cb, pcbRead, cbOffset);
    }
    if(!_stricmp(ctxP->uszPath, "version-minor.txt")) {
        return Util_VfsReadFile_FromNumber(H->vmm.kernel.dwVersionMinor, pb, cb, pcbRead, cbOffset);
    }
    if(!_stricmp(ctxP->uszPath, "version-build.txt")) {
        return Util_VfsReadFile_FromNumber(H->vmm.kernel.dwVersionBuild, pb, cb, pcbRead, cbOffset);
    }
    if(!_stricmp(ctxP->uszPath, "unique-tag.txt")) {
        return Util_VfsReadFile_FromPBYTE(H->vmm.szSystemUniqueTag, strlen(H->vmm.szSystemUniqueTag), pb, cb, pcbRead, cbOffset);
    }
    if(!_stricmp(ctxP->uszPath, "architecture.txt")) {
        return Util_VfsReadFile_FromPBYTE(
            VMM_MEMORYMODEL_TOSTRING[H->vmm.tpMemoryModel],
            strlen(VMM_MEMORYMODEL_TOSTRING[H->vmm.tpMemoryModel]),
            pb, cb, pcbRead, cbOffset);
    }
    if(!_stricmp(ctxP->uszPath, "computername.txt")) {
        SysQuery_ComputerName(H, (LPSTR)pbBuffer, sizeof(pbBuffer));
        for(i = 0; i < 32; i++) {
            if(!pbBuffer[i]) {
                for(; i < 32; i++) {
                    pbBuffer[i] = ' ';
                }
            }
        }
        return Util_VfsReadFile_FromPBYTE(pbBuffer, 32, pb, cb, pcbRead, cbOffset);
    }
    if(!_stricmp(ctxP->uszPath, "time-boot.txt")) {
        return Util_VfsReadFile_FromFILETIME(H->vmm.kernel.opt.ftBootTime, pb, cb, pcbRead, cbOffset);
    }
    if(!_stricmp(ctxP->uszPath, "time-current.txt")) {
        return Util_VfsReadFile_FromFILETIME(SysQuery_TimeCurrent(H), pb, cb, pcbRead, cbOffset);
    }
    if(!_stricmp(ctxP->uszPath, "timezone.txt")) {
        SysQuery_TimeZoneEx(H, szTimeZone, TRUE);
        return Util_VfsReadFile_FromPBYTE(szTimeZone, 48, pb, cb, pcbRead, cbOffset);
    }
    return VMMDLL_STATUS_FILE_INVALID;
}

BOOL MSys_List(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_CONTEXT ctxP, _Inout_ PHANDLE pFileList)
{
    DWORD cchMajor, cchMinor, cchBuild;
    if(ctxP->uszPath[0]) { return FALSE; }
    cchMajor = Util_GetNumDigits(H->vmm.kernel.dwVersionMajor);
    cchMinor = Util_GetNumDigits(H->vmm.kernel.dwVersionMinor);
    cchBuild = Util_GetNumDigits(H->vmm.kernel.dwVersionBuild);
    VMMDLL_VfsList_AddFile(pFileList, "version.txt", 2ULL + cchMajor + cchMinor + cchBuild, NULL);
    VMMDLL_VfsList_AddFile(pFileList, "version-major.txt", cchMajor, NULL);
    VMMDLL_VfsList_AddFile(pFileList, "version-minor.txt", cchMinor, NULL);
    VMMDLL_VfsList_AddFile(pFileList, "version-build.txt", cchBuild, NULL);
    VMMDLL_VfsList_AddFile(pFileList, "unique-tag.txt", strlen(H->vmm.szSystemUniqueTag), NULL);
    VMMDLL_VfsList_AddFile(pFileList, "architecture.txt", strlen(VMM_MEMORYMODEL_TOSTRING[H->vmm.tpMemoryModel]), NULL);
    VMMDLL_VfsList_AddFile(pFileList, "computername.txt", 32, NULL);
    VMMDLL_VfsList_AddFile(pFileList, "time-boot.txt", 24, NULL);
    VMMDLL_VfsList_AddFile(pFileList, "time-current.txt", 24, NULL);
    VMMDLL_VfsList_AddFile(pFileList, "timezone.txt", 48, NULL);
    return TRUE;
}

VOID MSys_FcLogJSON(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_CONTEXT ctxP, _In_ VOID(*pfnLogJSON)(_In_ VMM_HANDLE H, _In_ PVMMDLL_FORENSIC_JSONDATA pData))
{
    PVMMDLL_FORENSIC_JSONDATA pd;
    CHAR usz[MAX_PATH], szTimeBoot[24], szTimeCurrent[24], szTimeZone[64];
    BYTE pbComputerName[0x42] = { 0 };
    if(ctxP->pProcess || !(pd = LocalAlloc(LMEM_ZEROINIT, sizeof(VMMDLL_FORENSIC_JSONDATA)))) { return; }
    Util_FileTime2String(H->vmm.kernel.opt.ftBootTime, szTimeBoot);
    Util_FileTime2String(SysQuery_TimeCurrent(H), szTimeCurrent);
    SysQuery_TimeZoneEx(H, szTimeZone, FALSE);
    VmmWinReg_ValueQuery2(H, "HKLM\\SYSTEM\\ControlSet001\\Control\\ComputerName\\ComputerName\\ComputerName", NULL, pbComputerName, sizeof(pbComputerName) - 2, NULL);
    snprintf(usz, sizeof(usz), "architecture:[%s] version:[%i.%i.%i] time-boot:[%s] time-current:[%s], timezone:[%s]",
        VMM_MEMORYMODEL_TOSTRING[H->vmm.tpMemoryModel],
        H->vmm.kernel.dwVersionMajor, H->vmm.kernel.dwVersionMinor, H->vmm.kernel.dwVersionBuild,
        szTimeBoot, szTimeCurrent, szTimeZone
    );
    pd->dwVersion = VMMDLL_FORENSIC_JSONDATA_VERSION;
    pd->szjType = "systeminformation";
    pd->vaObj = H->vmm.kernel.vaBase;
    pd->va[0] = H->vmm.kernel.opt.KDBG.va;
    pd->wsz[0] = (LPCWSTR)pbComputerName;
    pd->usz[1] = usz;
    pfnLogJSON(H, pd);
    LocalFree(pd);
}

VOID M_Sys_Initialize(_In_ VMM_HANDLE H, _Inout_ PVMMDLL_PLUGIN_REGINFO pRI)
{
    if((pRI->magic != VMMDLL_PLUGIN_REGINFO_MAGIC) || (pRI->wVersion != VMMDLL_PLUGIN_REGINFO_VERSION)) { return; }
    if((pRI->tpSystem != VMMDLL_SYSTEM_WINDOWS_64) && (pRI->tpSystem != VMMDLL_SYSTEM_WINDOWS_32)) { return; }
    strcpy_s(pRI->reg_info.uszPathName, 128, "\\sys");      // module name
    pRI->reg_info.fRootModule = TRUE;                       // module shows in root directory
    pRI->reg_fn.pfnList = MSys_List;                        // List function supported
    pRI->reg_fn.pfnRead = MSys_Read;                        // Read function supported
    pRI->reg_fnfc.pfnLogJSON = MSys_FcLogJSON;              // JSON log function supported
    pRI->pfnPluginManager_Register(H, pRI);
}
