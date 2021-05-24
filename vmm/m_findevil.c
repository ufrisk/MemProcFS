// m_findevil.c : implementation of the find evil built-in module.
//
// (c) Ulf Frisk, 2020-2021
// Author: Ulf Frisk, pcileech@frizk.net
//
#include "pluginmanager.h"
#include "charutil.h"
#include "util.h"
#include "mm.h"
#include "vmm.h"
#include "vmmevil.h"

#define MFINDEVIL_LINELENGTH_X64   214ULL
#define MFINDEVIL_LINEHEADER       "   #    PID Process         Type        Address          Description"

LPCSTR szM_FINDEVIL_README =
"Find Evil tries to identify and discover signs of malware infection.         \n" \
"Find Evil currently detect some types of malware infection by memory analysis\n" \
"and does not, at this moment, support anti-virus scans and custom yara rules.\n" \
"---                                                                          \n" \
"Find Evil is enabled for 64-bit Windows 10 to keep false positive ratio low. \n" \
"Find Evil limit select findings per virtual address decriptor and process to \n" \
"keep output manageable. Find Evil also limit findings on select processes.   \n" \
"---                                                                          \n" \
"Find Evil is currently able to detect:                                       \n" \
"- Injected PE:    Non-loader loaded .dll with intact PE header.              \n" \
"                  Low false positive ratio.                                  \n" \
"- NoLink PROC:    Processes not linked by the _EPROCESS linked list.         \n" \
"- Bad PEB/LDR:    No ordinary modules located in the PEB/LDR_DATA structures \n" \
"                  indicates corruption; due to malware or paged out memory.  \n" \
"- PEB Masquerade: PEB user-mode image path differs from kernel image path.   \n" \
"- No-Link PE:     Loader loaded .dll with intact PE header not in PEB.       \n" \
"                  May provide false positives on paged memory/corrupted PEB. \n" \
"- Patched PE:     Loader loaded .dll - but modified after load time.         \n" \
"                  High false positives on relocations on 32-bit binaries.    \n" \
"- Private RX/RWX: Executable pages in non-shared memory such as stacks and   \n" \
"                  heaps. May provide false positives on Just-In-Time (JIT)   \n" \
"                  compiled code and should be used as an indicator only.     \n" \
"- NoImage RX/RWX: Executable pages in shared memory other than loader-loaded \n" \
"                  .dll memory such file backed memory. May provide false     \n" \
"                  positives and should be used as an indicator only.         \n" \
"---                                                                          \n" \
"Documentation:    https://github.com/ufrisk/MemProcFS/wiki/FS_FindEvil       \n" \
"---                                                                          \n" \
"Find Evil is a work in progress - post github issues for feature requests.   \n";

VOID MFindEvil_Read_FindEvil_LnTpModule(_In_opt_ PVMM_PROCESS pProcess, _In_ PVMM_MAP_EVILENTRY peEvil, _In_ WORD iLine, _Inout_updates_(MFINDEVIL_LINELENGTH_X64) LPSTR usz)
{
    DWORD i;
    PVMMOB_MAP_MODULE pObModuleMap = NULL;
    LPSTR uszModuleName = NULL;
    if(!pProcess) { return; }
    if(VmmMap_GetModule(pProcess, &pObModuleMap)) {
        for(i = 0; i < pObModuleMap->cMap; i++) {
            if(pObModuleMap->pMap[i].vaBase == peEvil->va) {
                uszModuleName = pObModuleMap->pMap[i].uszFullName;
                break;
            }
        }
    }
    strncat_s(usz, MFINDEVIL_LINELENGTH_X64, uszModuleName ? uszModuleName : "", _TRUNCATE);
    Ob_DECREF(pObModuleMap);
}

VOID MFindEvil_Read_FindEvil_LnTpVadEx(_In_opt_ PVMM_PROCESS pProcess, _In_ PVMM_MAP_EVILENTRY peEvil, _In_ WORD iLine, _Inout_updates_(MFINDEVIL_LINELENGTH_X64) LPSTR usz)
{
    QWORD qwHwPte;
    PVMM_MAP_VADENTRY peVad;
    PVMM_MAP_VADEXENTRY pex;
    PVMMOB_MAP_VAD pObVadMap = NULL;
    PVMMOB_MAP_VADEX pObVadEx = NULL;
    CHAR szProtection[7] = { 0 };
    CHAR szPatchOffset[8];
    if(!pProcess) { return; }
    if(!VmmMap_GetVad(pProcess, &pObVadMap, VMM_VADMAP_TP_FULL)) { goto fail; }
    if(!(peVad = VmmMap_GetVadEntry(pObVadMap, peEvil->vaVad))) { goto fail; }
    if(!VmmMap_GetVadEx(pProcess, &pObVadEx, VMM_VADMAP_TP_FULL, peVad->cVadExPagesBase + peEvil->oVadEx, 1) || !pObVadEx->cMap) { goto fail; }
    pex = pObVadEx->pMap;
    MmVad_StrProtectionFlags(peVad, szProtection);
    qwHwPte = (pex->tp == VMM_PTE_TP_HARDWARE) ? pex->pte : 0;
    memcpy(szPatchOffset, "       ", 8);
    if(peEvil->tp == VMM_EVIL_TP_VAD_PATCHED_PE) {
        _snprintf_s(szPatchOffset, _countof(szPatchOffset), _TRUNCATE, "%03x:%03x", peEvil->VAD_PATCHED_PE.wPatchOffset, peEvil->VAD_PATCHED_PE.wPatchByteCount);
    }
    _snprintf_s(
        usz,
        MFINDEVIL_LINELENGTH_X64,
        _TRUNCATE,
        "%s %012llx %016llx %c %c%c%c %016llx %012llx %016llx %c %s %s %s",
        szPatchOffset,
        pex->pa,
        pex->pte,
        MmVadEx_StrType(pex->tp),
        qwHwPte ? 'r' : '-',
        (qwHwPte & VMM_MEMMAP_PAGE_W) ? 'w' : '-',
        (!qwHwPte || (qwHwPte & VMM_MEMMAP_PAGE_NX)) ? '-' : 'x',
        peVad->vaVad,
        pex->proto.pa,
        pex->proto.pte,
        MmVadEx_StrType(pex->proto.tp),
        MmVad_StrType(peVad),
        szProtection,
        peVad->uszText + peVad->cbuText - min(51, peVad->cbuText)
    );
fail:
    Ob_DECREF(pObVadMap);
    Ob_DECREF(pObVadEx);
}

VOID MFindEvil_ReadLineCB(_Inout_opt_ PVOID ctx, _In_ DWORD cbLineLength, _In_ DWORD ie, _In_ PVMM_MAP_EVILENTRY pe, _Out_writes_(cbLineLength + 1) LPSTR usz)
{
    VMM_EVIL_TP tp;
    CHAR uszBuffer[MFINDEVIL_LINELENGTH_X64] = { 0 };
    PVMM_PROCESS pObProcess = VmmProcessGet(pe->dwPID);
    switch(pe->tp) {
        case VMM_EVIL_TP_PE_NA:
            strncpy_s(uszBuffer, sizeof(uszBuffer), "__internal_error__", _TRUNCATE);
            break;
        case VMM_EVIL_TP_PE_INJECTED:
        case VMM_EVIL_TP_PE_NOTLINKED:
            MFindEvil_Read_FindEvil_LnTpModule(pObProcess, pe, (WORD)ie, uszBuffer);
            break;
        case VMM_EVIL_TP_VAD_PATCHED_PE:
        case VMM_EVIL_TP_VAD_PRIVATE_RX:
        case VMM_EVIL_TP_VAD_PRIVATE_RWX:
        case VMM_EVIL_TP_VAD_NOIMAGE_RX:
        case VMM_EVIL_TP_VAD_NOIMAGE_RWX:
            MFindEvil_Read_FindEvil_LnTpVadEx(pObProcess, pe, (WORD)ie, uszBuffer);
            break;
        case VMM_EVIL_TP_PROC_NOLINK:
        case VMM_EVIL_TP_PEB_MASQUERADE:
        case VMM_EVIL_TP_PEB_BAD_LDR:
            // no description on these
            break;
    }
    tp = min(pe->tp, sizeof(VMM_EVIL_TP_STRING) / sizeof(LPSTR) - 1);
    if(ctx) {
        // "fake" file read for json data
        CharUtil_UtoJ(uszBuffer, -1, usz, cbLineLength + 1, NULL, NULL, CHARUTIL_FLAG_TRUNCATE | CHARUTIL_FLAG_STR_BUFONLY);
    } else {
        // "ordinary" file read
        Util_usnprintf_ln(usz, cbLineLength,
            "%04x%7i %-15s%12s %016llx %s",
            ie,
            pe->dwPID,
            pObProcess ? pObProcess->szName : "_NA",
            VMM_EVIL_TP_STRING[tp],
            pe->va,
            uszBuffer
        );
    }
    Ob_DECREF(pObProcess);
}

VOID MFindEvil_FcLogJSON(_In_ PVMMDLL_PLUGIN_CONTEXT ctxP, _In_ VOID(*pfnLogJSON)(_In_ PVMMDLL_PLUGIN_FORENSIC_JSONDATA pData))
{
    PVMMDLL_PLUGIN_FORENSIC_JSONDATA pd;
    PVMMOB_MAP_EVIL pObEvilMap = NULL;
    PVMM_MAP_EVILENTRY pe;
    DWORD i;
    VMM_EVIL_TP tp;
    CHAR usz[MAX_PATH];
    if(ctxP->pProcess || !(pd = LocalAlloc(LMEM_ZEROINIT, sizeof(VMMDLL_PLUGIN_FORENSIC_JSONDATA)))) { return; }
    pd->dwVersion = VMMDLL_PLUGIN_FORENSIC_JSONDATA_VERSION;
    pd->szjType = "evil";
    if(VmmMap_GetEvil(NULL, &pObEvilMap)) {
        for(i = 0; i < pObEvilMap->cMap; i++) {
            pe = pObEvilMap->pMap + i;
            tp = min(pe->tp, sizeof(VMM_EVIL_TP_STRING) / sizeof(LPSTR) - 1);
            MFindEvil_ReadLineCB((PVOID)TRUE, _countof(usz) - 1, i, pe, usz);
            // assign:
            pd->i = i;
            pd->dwPID = pe->dwPID;
            pd->va[0] = pe->va;
            pd->usz[0] = VMM_EVIL_TP_STRING[tp];
            pd->usz[1] = usz;
            pfnLogJSON(pd);
        }
    }
    Ob_DECREF(pObEvilMap);
    LocalFree(pd);
}

NTSTATUS MFindEvil_Read(_In_ PVMMDLL_PLUGIN_CONTEXT ctx, _Out_writes_to_(cb, *pcbRead) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset)
{
    NTSTATUS nt;
    PVMMOB_MAP_EVIL pObEvilMap = NULL;
    PVMM_PROCESS pProcess = (PVMM_PROCESS)ctx->pProcess;
    if(!_stricmp(ctx->uszPath, "readme.txt")) {
        return Util_VfsReadFile_FromPBYTE((PBYTE)szM_FINDEVIL_README, strlen(szM_FINDEVIL_README), pb, cb, pcbRead, cbOffset);
    }
    if(!_stricmp(ctx->uszPath, "progress_percent.txt")) {
        return Util_VfsReadFile_FromNumber(ctxVmm->EvilContext.cProgressPercent, pb, cb, pcbRead, cbOffset);
    }
    if(!_stricmp(ctx->uszPath, "findevil.txt")) {
        if(VmmMap_GetEvil(pProcess, &pObEvilMap)) {
            nt = Util_VfsLineFixed_Read(
                (UTIL_VFSLINEFIXED_PFN_CB)MFindEvil_ReadLineCB, NULL, MFINDEVIL_LINELENGTH_X64, MFINDEVIL_LINEHEADER,
                pObEvilMap->pMap, pObEvilMap->cMap, sizeof(VMM_MAP_EVILENTRY),
                pb, cb, pcbRead, cbOffset
            );
            Ob_DECREF(pObEvilMap);
            return nt;
        } else {
            *pcbRead = 0;
            return VMMDLL_STATUS_END_OF_FILE;
        }
    }
    return VMMDLL_STATUS_FILE_INVALID;
}

BOOL MFindEvil_List(_In_ PVMMDLL_PLUGIN_CONTEXT ctx, _Inout_ PHANDLE pFileList)
{
    QWORD qwProgress;
    DWORD cbEvil;
    PVMMOB_MAP_EVIL pObEvilMap = NULL;
    PVMM_PROCESS pProcess = (PVMM_PROCESS)ctx->pProcess;
    if(ctx->uszPath[0]) { return FALSE; }
    VmmMap_GetEvil(pProcess, &pObEvilMap);
    cbEvil = pObEvilMap ? (UTIL_VFSLINEFIXED_LINECOUNT(pObEvilMap->cMap) * MFINDEVIL_LINELENGTH_X64) : 0;
    VMMDLL_VfsList_AddFile(pFileList, "findevil.txt", cbEvil, NULL);
    VMMDLL_VfsList_AddFile(pFileList, "readme.txt", strlen(szM_FINDEVIL_README), NULL);
    if(!ctx->pProcess) {
        qwProgress = ctxVmm->EvilContext.cProgressPercent;
        qwProgress = (qwProgress == 100) ? 3 : ((qwProgress >= 10) ? 2 : 1);
        VMMDLL_VfsList_AddFile(pFileList, "progress_percent.txt", qwProgress, NULL);
    }
    Ob_DECREF(pObEvilMap);
    return TRUE;
}

VOID MFindEvil_Notify(_In_ PVMMDLL_PLUGIN_CONTEXT ctxP, _In_ DWORD fEvent, _In_opt_ PVOID pvEvent, _In_opt_ DWORD cbEvent)
{
    if(fEvent == VMMDLL_PLUGIN_NOTIFY_FORENSIC_INIT_COMPLETE) {
        PluginManager_SetVisibility(TRUE, "\\forensic\\findevil", TRUE);
    }
}

VOID MFindEvil_FcFinalize(_In_opt_ PVOID ctxfc)
{
    VmmEvil_InitializeAll_WaitFinish();
}

BOOL MFindEvil_VisiblePlugin(_In_ PVMMDLL_PLUGIN_CONTEXT ctx)
{
    return !ctx->pProcess || ((PVMM_PROCESS)ctx->pProcess)->fUserOnly;
}

VOID M_FindEvil_Initialize(_Inout_ PVMMDLL_PLUGIN_REGINFO pRI)
{
    if((pRI->magic != VMMDLL_PLUGIN_REGINFO_MAGIC) || (pRI->wVersion != VMMDLL_PLUGIN_REGINFO_VERSION)) { return; }
    if(pRI->sysinfo.f32 || (pRI->sysinfo.dwVersionBuild < 9600)) { return; }    // only support 64-bit Win8.1+ for now
    pRI->reg_fn.pfnList = MFindEvil_List;
    pRI->reg_fn.pfnRead = MFindEvil_Read;
    pRI->reg_fn.pfnVisibleModule = MFindEvil_VisiblePlugin;                     // programmatic visibility
    // register process plugin
    strcpy_s(pRI->reg_info.uszPathName, 128, "\\findevil");
    pRI->reg_info.fRootModule = FALSE;
    pRI->reg_info.fProcessModule = TRUE;
    pRI->pfnPluginManager_Register(pRI);
    // register root plugin
    strcpy_s(pRI->reg_info.uszPathName, 128, "\\misc\\findevil");
    pRI->reg_info.fRootModule = TRUE;
    pRI->reg_info.fProcessModule = FALSE;
    pRI->pfnPluginManager_Register(pRI);
    // register forensic plugin
    strcpy_s(pRI->reg_info.uszPathName, 128, "\\forensic\\findevil");
    pRI->reg_info.fRootModuleHidden = TRUE;
    pRI->reg_fn.pfnNotify = MFindEvil_Notify;
    pRI->reg_fnfc.pfnFinalize = MFindEvil_FcFinalize;
    pRI->reg_fnfc.pfnLogJSON = MFindEvil_FcLogJSON;                             // JSON log function supported
    pRI->pfnPluginManager_Register(pRI);
}
