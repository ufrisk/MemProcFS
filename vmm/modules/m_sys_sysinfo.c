// m_sys_sysinfo.c : implementation of easy-to-read system information.
//
// (c) Ulf Frisk, 2024-2025
// Author: Ulf Frisk, pcileech@frizk.net
//

#include "modules.h"
#include "../sysquery.h"
#include "../vmmwinreg.h"
#include "../version.h"

/*
* Helper information to display network interface information:
*/
VOID MSysInfo_GetContext_Network(_In_ VMM_HANDLE H, _In_ POB_MEMFILE pmfOb, POB_REGISTRY_HIVE pHive, _In_ POB_REGISTRY_KEY pInterfaceKey, _In_ DWORD iInterface)
{
    static LPSTR szVALUES_STRING[] = { "Domain", "NameServer", "DefaultGateway", "IPAddress", "SubnetMask", "DhcpIPAddress", "DhcpSubnetMask", "DhcpServer", "DhcpDefaultGateway", "DhcpNameServer", "DhcpDomain", "DhcpSubnetMaskOpt" };
    DWORD i;
    CHAR szData[128];
    BOOL fInterface = FALSE;
    POB_REGISTRY_VALUE pObValue = NULL;
    POB_MAP pmObInterfaceRegValues = NULL;
    VMM_REGISTRY_VALUE_INFO ValueInfo = { 0 };
    pmObInterfaceRegValues = VmmWinReg_KeyValueList(H, pHive, pInterfaceKey);
    while((pObValue = ObMap_Pop(pmObInterfaceRegValues))) {
        VmmWinReg_ValueInfo(pHive, pObValue, &ValueInfo);
        for(i = 0; i < sizeof(szVALUES_STRING) / sizeof(LPSTR); i++) {
            if(CharUtil_StrEquals(szVALUES_STRING[i], ValueInfo.uszName, FALSE)) {
                if(VmmWinReg_ValueQueryString4(H, pHive, pObValue, NULL, szData, sizeof(szData)) && (strlen(szData) > 2)) {
                    if(!fInterface) {
                        ObMemFile_AppendStringEx(pmfOb, "  Interface #%i:\n", iInterface);
                        fInterface = TRUE;
                    }
                    ObMemFile_AppendStringEx(pmfOb, "    %s:%*s%s\n", szVALUES_STRING[i], (DWORD)(19 - strlen(szVALUES_STRING[i])), "", szData);
                }
                break;
            }
        }
        Ob_DECREF(pObValue);
    }
    Ob_DECREF(pmObInterfaceRegValues);
}

/*
* Retrieve the info file.
* CALLER DECREF: return
* -- H
* -- ctxP
* -- return
*/
_Success_(return != NULL)
POB_MEMFILE MSysinfo_GetContext(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_CONTEXT ctxP)
{
    static SRWLOCK LockSRW = SRWLOCK_INIT;
    PVMM_MAP_PHYSMEMENTRY pePhysMem = NULL;
    PVMMOB_MAP_PHYSMEM pObMapPhysMem = NULL;
    PVMM_MAP_USERENTRY peUser = NULL;
    PVMMOB_MAP_USER pObMapUser = NULL;
    PVMM_PROCESS pObProcess = NULL;
    POB_REGISTRY_HIVE pObHive = NULL;
    POB_REGISTRY_KEY pObKey = NULL, pObInterfaceKey = NULL;
    POB_MAP pmObInterfaceRegKey = NULL;
    POB_MEMFILE pmfOb = NULL;
    QWORD cbPhysMem = 0;
    DWORD i, cProcActive = 0, cProcInactive = 0, cRegKey = 0;
    CHAR szTimeBoot[24] = { 0 }, szTimeNow[24] = { 0 }, szTime[24] = { 0 }, szTimeZone[64] = { 0 }, szComputername[64] = { 0 };
    CHAR uszHwCPU[128] = { 0 }, uszHwMBVendor[128] = { 0 }, uszHwMBProduct[128] = { 0 }, uszHwBIOS[128] = { 0 }, uszHwSystem[128] = { 0 };
    
    // Re-use context if already created:
    if((pmfOb = ObContainer_GetOb((POB_CONTAINER)ctxP->ctxM))) { return pmfOb; }
    AcquireSRWLockExclusive(&LockSRW);
    if((pmfOb = ObContainer_GetOb((POB_CONTAINER)ctxP->ctxM))) { goto finish; }
    if(!(pmfOb = ObMemFile_New(H, H->vmm.pObCacheMapObCompressedShared))) { goto finish; }

    // Windows info:
    Util_FileTime2String(H->vmm.kernel.opt.ftBootTime, szTimeBoot);
    Util_FileTime2String(SysQuery_TimeCurrent(H), szTimeNow);
    SysQuery_TimeZoneEx(H, szTimeZone, TRUE);
    SysQuery_ComputerName(H, szComputername, sizeof(szComputername));
    ObMemFile_AppendString(pmfOb, "Windows Information:\n");
    ObMemFile_AppendStringEx(pmfOb, "  Computer Name:   %s\n", szComputername);
    ObMemFile_AppendStringEx(pmfOb, "  Current Time:    %s\n", szTimeNow);
    ObMemFile_AppendStringEx(pmfOb, "  Boot Time:       %s\n", szTimeBoot);
    ObMemFile_AppendStringEx(pmfOb, "  Time Zone:       %s", szTimeZone);
    ObMemFile_AppendStringEx(pmfOb, "  Version:         %i.%i (build %i)\n", H->vmm.kernel.dwVersionMajor, H->vmm.kernel.dwVersionMinor, H->vmm.kernel.dwVersionBuild);

    // Memory & CPU: (size and architectore)
    VmmWinReg_ValueQueryString2(H, "HKLM\\HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0\\ProcessorNameString", NULL, uszHwCPU, sizeof(uszHwCPU));
    VmmWinReg_ValueQueryString2(H, "HKLM\\HARDWARE\\DESCRIPTION\\System\\BIOS\\BaseBoardManufacturer", NULL, uszHwMBVendor, sizeof(uszHwMBVendor));
    VmmWinReg_ValueQueryString2(H, "HKLM\\HARDWARE\\DESCRIPTION\\System\\BIOS\\BaseBoardProduct", NULL, uszHwMBProduct, sizeof(uszHwMBProduct));
    VmmWinReg_ValueQueryString2(H, "HKLM\\HARDWARE\\DESCRIPTION\\System\\BIOS\\BIOSVendor", NULL, uszHwBIOS, sizeof(uszHwBIOS));
    VmmWinReg_ValueQueryString2(H, "HKLM\\HARDWARE\\DESCRIPTION\\System\\BIOS\\SystemManufacturer", NULL, uszHwSystem, sizeof(uszHwSystem));
    ObMemFile_AppendString(pmfOb, "\nHardware Information:\n");
    ObMemFile_AppendStringEx(pmfOb, "  Architecture:    %s\n", VMM_MEMORYMODEL_TOSTRING[H->vmm.tpMemoryModel]);
    if((VmmMap_GetPhysMem(H, &pObMapPhysMem) && pObMapPhysMem->cMap)) {
        for(i = 0; i < pObMapPhysMem->cMap; i++) {
            pePhysMem = &pObMapPhysMem->pMap[i];
            cbPhysMem += pePhysMem->cb;
        }
        ObMemFile_AppendStringEx(pmfOb, "  Physical Memory: %llu GB\n", ((cbPhysMem + 0x20000000) / (1024 * 1024 * 1024)));
        ObMemFile_AppendStringEx(pmfOb, "  Max Address:     0x%llx\n", pePhysMem->pa + pePhysMem->cb - 1);
    }
    if(uszHwCPU[0])       { ObMemFile_AppendStringEx(pmfOb, "  CPU:             %s\n", uszHwCPU); }
    if(uszHwMBVendor[0])  { ObMemFile_AppendStringEx(pmfOb, "  MB Vendor:       %s\n", uszHwMBVendor); }
    if(uszHwMBProduct[0]) { ObMemFile_AppendStringEx(pmfOb, "  MB Product:      %s\n", uszHwMBProduct); }
    if(uszHwBIOS[0])      { ObMemFile_AppendStringEx(pmfOb, "  BIOS Vendor:     %s\n", uszHwBIOS); }
    if(uszHwSystem[0])    { ObMemFile_AppendStringEx(pmfOb, "  System Vendor:   %s\n", uszHwSystem); }

    // Users:
    if((VmmMap_GetUser(H, &pObMapUser) && pObMapUser->cMap)) {
        ObMemFile_AppendString(pmfOb, "\nUsers:\n");
        for(i = 0; i < pObMapUser->cMap; i++) {
            peUser = &pObMapUser->pMap[i];
            ObMemFile_AppendStringEx(pmfOb, "  %s  (%s)\n", peUser->uszText, peUser->szSID);
        }
    }

    // Processes:
    ObMemFile_AppendString(pmfOb, "\nProcess Information:\n");
    while((pObProcess = VmmProcessGetNext(H, pObProcess, VMM_FLAG_PROCESS_SHOW_TERMINATED))) {
        if(pObProcess->dwState) {
            cProcInactive++;
        } else {
            cProcActive++;
        }
    }
    ObMemFile_AppendStringEx(pmfOb, "  Active:          %u\n", cProcActive);
    ObMemFile_AppendStringEx(pmfOb, "  Inactive:        %u\n", cProcInactive);

    // Network:
    if(VmmWinReg_KeyHiveGetByFullPath(H, "HKLM\\SYSTEM\\ControlSet001\\Services\\Tcpip\\Parameters\\Interfaces", &pObHive, &pObKey) && (pmObInterfaceRegKey = VmmWinReg_KeyList(H, pObHive, pObKey)) && ObMap_Size(pmObInterfaceRegKey)) {
        ObMemFile_AppendString(pmfOb, "\nNetwork Interfaces:\n");
        while((pObInterfaceKey = ObMap_Pop(pmObInterfaceRegKey))) {
            MSysInfo_GetContext_Network(H, pmfOb, pObHive, pObInterfaceKey, ++cRegKey);
            Ob_DECREF(pObInterfaceKey);
        }
    }

    // MemProcFS info:
    Util_FileTime2String(Util_FileTimeNow(), szTime);
    ObMemFile_AppendString(pmfOb, "\nMemProcFS Information:\n");
    ObMemFile_AppendStringEx(pmfOb, "  Version:         %i.%i.%i (build %i)\n", VERSION_MAJOR, VERSION_MINOR, VERSION_REVISION, VERSION_BUILD);
    ObMemFile_AppendStringEx(pmfOb, "  Parse Time:      %s\n", szTime);
    ObMemFile_AppendStringEx(pmfOb, "  Memory Source:   %s, %s\n", (H->dev.fWritable ? "Read/Write" : "Read-only"), (H->dev.fVolatile ? "Volatile" : "Static"));
    ObMemFile_AppendStringEx(pmfOb, "  Unique Tag:      %s\n", H->vmm.szSystemUniqueTag);
    ObMemFile_AppendStringEx(pmfOb, "  Forensic Mode:   %s\n", (H->cfg.tpForensicMode ? "Enabled" : "Disabled"));
    ObMemFile_AppendStringEx(pmfOb, "  VM Parsing:      %s\n", (H->cfg.fVM ? "Enabled" : "Disabled"));

    // Finish:
    ObContainer_SetOb((POB_CONTAINER)ctxP->ctxM, pmfOb);
finish:
    ReleaseSRWLockExclusive(&LockSRW);
    Ob_DECREF(pmObInterfaceRegKey);
    Ob_DECREF(pObMapPhysMem);
    Ob_DECREF(pObMapUser);
    Ob_DECREF(pObHive);
    Ob_DECREF(pObKey);
    return pmfOb;
}

/*
* Read : function as specified by the module manager. The module manager will
* call into this callback function whenever a read shall occur from a "file".
* -- H
* -- ctxP
* -- pb
* -- cb
* -- pcbRead
* -- cbOffset
* -- return
*/
_Success_(return == 0)
NTSTATUS MSysinfo_Read(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_CONTEXT ctxP, _Out_writes_to_(cb, *pcbRead) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset)
{
    NTSTATUS nt;
    POB_MEMFILE pmfOb = NULL;
    if(CharUtil_StrEquals(ctxP->uszPath, "sysinfo.txt", TRUE)) {
        if((pmfOb = MSysinfo_GetContext(H, ctxP))) {
            nt = ObMemFile_ReadFile(pmfOb, pb, cb, pcbRead, cbOffset);
            Ob_DECREF(pmfOb);
            return nt;
        }
    }
    return VMMDLL_STATUS_FILE_INVALID;
}

/*
* List : function as specified by the module manager. The module manager will
* call into this callback function whenever a list directory shall occur from
* the given module.
* -- H
* -- ctxP
* -- pFileList
* -- return
*/
BOOL MSysinfo_List(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_CONTEXT ctxP, _Inout_ PHANDLE pFileList)
{
    POB_MEMFILE pmfOb = NULL;
    if(!ctxP->uszPath[0] && (pmfOb = MSysinfo_GetContext(H, ctxP))) {
        VMMDLL_VfsList_AddFile(pFileList, "sysinfo.txt", ObMemFile_Size(pmfOb), NULL);
    }
    Ob_DECREF(pmfOb);
    return TRUE;
}

VOID MSysinfo_Notify(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_CONTEXT ctxP, _In_ DWORD fEvent, _In_opt_ PVOID pvEvent, _In_opt_ DWORD cbEvent)
{
    if(fEvent == VMMDLL_PLUGIN_NOTIFY_REFRESH_SLOW) {
        ObContainer_SetOb((POB_CONTAINER)ctxP->ctxM, NULL);
    }
}

VOID MSysinfo_Close(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_CONTEXT ctxP)
{
    Ob_DECREF(ctxP->ctxM);
}

VOID M_SysSysinfo_Initialize(_In_ VMM_HANDLE H, _Inout_ PVMMDLL_PLUGIN_REGINFO pRI)
{
    if((pRI->magic != VMMDLL_PLUGIN_REGINFO_MAGIC) || (pRI->wVersion != VMMDLL_PLUGIN_REGINFO_VERSION)) { return; }
    if((pRI->tpSystem != VMM_SYSTEM_WINDOWS_64) && (pRI->tpSystem != VMM_SYSTEM_WINDOWS_32)) { return; }
    if(!(pRI->reg_info.ctxM = (PVMMDLL_PLUGIN_INTERNAL_CONTEXT)ObContainer_New())) { return; }  // internal module context
    strcpy_s(pRI->reg_info.uszPathName, 128, "\\sys\\sysinfo");     // module name
    pRI->reg_info.fRootModule = TRUE;                               // module shows in root directory
    pRI->reg_fn.pfnList = MSysinfo_List;                            // List function supported
    pRI->reg_fn.pfnRead = MSysinfo_Read;                            // Read function supported
    pRI->reg_fn.pfnNotify = MSysinfo_Notify;                        // Notify function supported
    pRI->reg_fn.pfnClose = MSysinfo_Close;                          // Close function supported
    pRI->pfnPluginManager_Register(H, pRI);
}
