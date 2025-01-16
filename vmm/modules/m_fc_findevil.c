// m_fc_findevil.c : implementation of the find evil built-in module.
//
// (c) Ulf Frisk, 2020-2025
// Author: Ulf Frisk, pcileech@frizk.net
//

#include "modules.h"
#include "../mm/mm.h"

LPCSTR szM_FC_FINDEVIL_README =
"Find Evil tries to identify and discover signs of malware infection.         \n" \
"Find Evil currently detect some types of malware infection by memory analysis\n" \
"and does not, at this moment, support anti-virus scans and custom yara rules.\n" \
"---                                                                          \n" \
"Find Evil is enabled for 64-bit Windows 10+ to keep false positive ratio low.\n" \
"Find Evil limit select findings per virtual address decriptor and process to \n" \
"keep output manageable. Find Evil also limit findings on select processes.   \n" \
"---                                                                          \n" \
"YARA: FindEvil tries to use built-in YARA rules, many which are from         \n" \
"Elastic Security. The Elastic License 2.0 must be accepted to use the rules. \n" \
"https://www.elastic.co/licensing/elastic-license                             \n" \
"Accept with command line option: '-license-accept-elastic-license-2.0'       \n" \
"---                                                                          \n" \
"Documentation:    https://github.com/ufrisk/MemProcFS/wiki/FS_FindEvil       \n" \
"---                                                                          \n" \
"Find Evil is a work in progress - post github issues for feature requests.   \n";

NTSTATUS MFcFindEvil_Read(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_CONTEXT ctxP, _Out_writes_to_(cb, *pcbRead) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset)
{
    if(!_stricmp(ctxP->uszPath, "readme.txt")) {
        return Util_VfsReadFile_FromPBYTE((PBYTE)szM_FC_FINDEVIL_README, strlen(szM_FC_FINDEVIL_README), pb, cb, pcbRead, cbOffset);
    }
    if(!_stricmp(ctxP->uszPath, "findevil.txt")) {
        return ObMemFile_ReadFile(H->fc->FindEvil.pmf, pb, cb, pcbRead, cbOffset);
    }
    if(!_stricmp(ctxP->uszPath, "yara.txt")) {
        return ObMemFile_ReadFile(H->fc->FindEvil.pmfYara, pb, cb, pcbRead, cbOffset);
    }
    if(!_stricmp(ctxP->uszPath, "yara_rules.txt")) {
        return ObMemFile_ReadFile(H->fc->FindEvil.pmfYaraRules, pb, cb, pcbRead, cbOffset);
    }
    return VMMDLL_STATUS_FILE_INVALID;
}

BOOL MFcFindEvil_List(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_CONTEXT ctxP, _Inout_ PHANDLE pFileList)
{
    if(ctxP->uszPath[0]) { return FALSE; }
    VMMDLL_VfsList_AddFile(pFileList, "readme.txt", strlen(szM_FC_FINDEVIL_README), NULL);
    VMMDLL_VfsList_AddFile(pFileList, "findevil.txt", ObMemFile_Size(H->fc->FindEvil.pmf), NULL);
    VMMDLL_VfsList_AddFile(pFileList, "yara.txt", ObMemFile_Size(H->fc->FindEvil.pmfYara), NULL);
    VMMDLL_VfsList_AddFile(pFileList, "yara_rules.txt", ObMemFile_Size(H->fc->FindEvil.pmfYaraRules), NULL);
    return TRUE;
}

VOID MFcFindEvil_Notify(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_CONTEXT ctxP, _In_ DWORD fEvent, _In_opt_ PVOID pvEvent, _In_opt_ DWORD cbEvent)
{
    if(fEvent == VMMDLL_PLUGIN_NOTIFY_FORENSIC_INIT_COMPLETE) {
        PluginManager_SetVisibility(H, TRUE, "\\forensic\\findevil", TRUE);
    }
}

VOID M_FcFindEvil_Initialize(_In_ VMM_HANDLE H, _Inout_ PVMMDLL_PLUGIN_REGINFO pRI)
{
    if((pRI->magic != VMMDLL_PLUGIN_REGINFO_MAGIC) || (pRI->wVersion != VMMDLL_PLUGIN_REGINFO_VERSION)) { return; }
    pRI->reg_fn.pfnList = MFcFindEvil_List;
    pRI->reg_fn.pfnRead = MFcFindEvil_Read;
    // register forensic plugin
    strcpy_s(pRI->reg_info.uszPathName, 128, "\\forensic\\findevil");
    pRI->reg_info.fRootModule = TRUE;
    pRI->reg_info.fRootModuleHidden = TRUE;
    pRI->reg_fn.pfnNotify = MFcFindEvil_Notify;
    pRI->pfnPluginManager_Register(H, pRI);
}
