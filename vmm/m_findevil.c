// m_findevil.c : implementation of the find evil built-in module.
//
// (c) Ulf Frisk, 2020
// Author: Ulf Frisk, pcileech@frizk.net
//
#include "pluginmanager.h"
#include "util.h"
#include "mm.h"
#include "vmm.h"
#include "vmmevil.h"

#define M_FINDEVIL_LINELENGTH_X64           214ULL

LPCSTR szM_FINDEVIL_README =
"Find Evil tries to identify and discover signs of malsare infection.         \n" \
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
"- Bad PEB/LDR:    No ordinary modules located in the PEB/LDR_DATA structures \n" \
"                  indicates corruption; due to malware or paged out memory.  \n" \
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

VOID M_FindEvil_Read_FindEvil_LnTpModule(_In_opt_ PVMM_PROCESS pProcess, _In_ PVMM_MAP_EVILENTRY peEvil, _In_ WORD iLine, _Inout_updates_(M_FINDEVIL_LINELENGTH_X64) LPWSTR wsz)
{
    DWORD i;
    PVMMOB_MAP_MODULE pObModuleMap = NULL;
    LPWSTR wszModuleName = NULL;
    if(!pProcess) { return; }
    if(VmmMap_GetModule(pProcess, &pObModuleMap)) {
        for(i = 0; i < pObModuleMap->cMap; i++) {
            if(pObModuleMap->pMap[i].vaBase == peEvil->va) {
                wszModuleName = pObModuleMap->pMap[i].wszFullName;
                break;
            }
        }
    }
    wcsncat_s(wsz, M_FINDEVIL_LINELENGTH_X64, wszModuleName ? wszModuleName : L"", _TRUNCATE);
    Ob_DECREF(pObModuleMap);
}

VOID M_FindEvil_Read_FindEvil_LnTpVadEx(_In_opt_ PVMM_PROCESS pProcess, _In_ PVMM_MAP_EVILENTRY peEvil, _In_ WORD iLine, _Inout_updates_(M_FINDEVIL_LINELENGTH_X64) LPWSTR wsz)
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
    _snwprintf_s(
        wsz,
        M_FINDEVIL_LINELENGTH_X64,
        _TRUNCATE,
        L"%S %012llx %016llx %c %c%c%c %016llx %012llx %016llx %c %S %S %s",
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
        peVad->wszText + peVad->cwszText - min(50, peVad->cwszText)
    );
fail:
    Ob_DECREF(pObVadMap);
    Ob_DECREF(pObVadEx);
}

_Success_(return == 0)
NTSTATUS M_FindEvil_Read_FindEvil(_In_ PVMMOB_MAP_EVIL pEvilMap, _Out_writes_to_(cb, *pcbRead) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset)
{
    NTSTATUS nt;
    VMM_EVIL_TP tp;
    WCHAR wsz[M_FINDEVIL_LINELENGTH_X64];
    LPSTR sz;
    QWORD i, o = 0, cbMax, cStart, cEnd, cbLINELENGTH;
    PVMM_MAP_EVILENTRY pe;
    PVMM_PROCESS pObProcess = NULL;
    cbLINELENGTH = M_FINDEVIL_LINELENGTH_X64;
    cStart = (DWORD)(cbOffset / cbLINELENGTH);
    cEnd = (DWORD)min(pEvilMap->cMap - 1, (cb + cbOffset + cbLINELENGTH - 1) / cbLINELENGTH);
    cbMax = 1 + (1 + cEnd - cStart) * cbLINELENGTH;
    if(!pEvilMap->cMap || (cStart > pEvilMap->cMap)) { return VMMDLL_STATUS_END_OF_FILE; }
    if(!(sz = LocalAlloc(LMEM_ZEROINIT, cbMax))) { return VMMDLL_STATUS_FILE_INVALID; }
    for(i = cStart; i <= cEnd; i++) {
        pe = pEvilMap->pMap + i;
        if(!pObProcess || (pObProcess->dwPID != pe->dwPID)) {
            Ob_DECREF(pObProcess);
            pObProcess = VmmProcessGet(pe->dwPID);
        }
        wsz[0] = 0;
        switch(pe->tp) {
            case VMM_EVIL_TP_PE_INJECTED:
            case VMM_EVIL_TP_PE_NOTLINKED:
                M_FindEvil_Read_FindEvil_LnTpModule(pObProcess, pe, (WORD)i, wsz);
                break;
            case VMM_EVIL_TP_VAD_PATCHED_PE:
            case VMM_EVIL_TP_VAD_PRIVATE_RX:
            case VMM_EVIL_TP_VAD_PRIVATE_RWX:
            case VMM_EVIL_TP_VAD_NOIMAGE_RX:
            case VMM_EVIL_TP_VAD_NOIMAGE_RWX:
                M_FindEvil_Read_FindEvil_LnTpVadEx(pObProcess, pe, (WORD)i, wsz);
                break;
        }
        tp = min(pe->tp, sizeof(VMM_EVIL_TP_STRING) / sizeof(LPSTR) - 1);
        o += Util_snwprintf_u8ln(
            sz + o,
            cbLINELENGTH,
            L"%04x%7i %-15S%12S %016llx %s",
            (WORD)i,
            pe->dwPID,
            pObProcess ? pObProcess->szName : "_NA",
            VMM_EVIL_TP_STRING[tp],
            pe->va,
            wsz
        );
    }
    Ob_DECREF(pObProcess);
    nt = Util_VfsReadFile_FromPBYTE(sz, cbMax - 1, pb, cb, pcbRead, cbOffset - cStart * cbLINELENGTH);
    LocalFree(sz);
    return nt;
}

NTSTATUS M_FindEvil_Read(_In_ PVMMDLL_PLUGIN_CONTEXT ctx, _Out_writes_to_(cb, *pcbRead) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset)
{
    NTSTATUS nt;
    PVMMOB_MAP_EVIL pObEvilMap = NULL;
    PVMM_PROCESS pProcess = (PVMM_PROCESS)ctx->pProcess;
    if(!_wcsicmp(ctx->wszPath, L"readme.txt")) {
        return Util_VfsReadFile_FromPBYTE((PBYTE)szM_FINDEVIL_README, strlen(szM_FINDEVIL_README), pb, cb, pcbRead, cbOffset);
    }
    if(!_wcsicmp(ctx->wszPath, L"progress_percent.txt")) {
        return Util_VfsReadFile_FromNumber(ctxVmm->EvilContext.cProgressPercent, pb, cb, pcbRead, cbOffset);
    }
    if(!_wcsicmp(ctx->wszPath, L"findevil.txt")) {
        if(VmmMap_GetEvil(pProcess, &pObEvilMap)) {
            nt = M_FindEvil_Read_FindEvil(pObEvilMap, pb, cb, pcbRead, cbOffset);
            Ob_DECREF(pObEvilMap);
            return nt;
        } else {
            *pcbRead = 0;
            return VMMDLL_STATUS_END_OF_FILE;
        }
    }
    return VMMDLL_STATUS_FILE_INVALID;
}

BOOL M_FindEvil_List(_In_ PVMMDLL_PLUGIN_CONTEXT ctx, _Inout_ PHANDLE pFileList)
{
    QWORD qwProgress;
    DWORD cEvil;
    PVMMOB_MAP_EVIL pObEvilMap = NULL;
    PVMM_PROCESS pProcess = (PVMM_PROCESS)ctx->pProcess;
    if(ctx->wszPath[0]) { return FALSE; }
    VmmMap_GetEvil(pProcess, &pObEvilMap);
    cEvil = pObEvilMap ? pObEvilMap->cMap : 0;
    VMMDLL_VfsList_AddFile(pFileList, L"findevil.txt", cEvil * M_FINDEVIL_LINELENGTH_X64, NULL);
    VMMDLL_VfsList_AddFile(pFileList, L"readme.txt", strlen(szM_FINDEVIL_README), NULL);
    if(!ctx->pProcess) {
        qwProgress = ctxVmm->EvilContext.cProgressPercent;
        qwProgress = (qwProgress == 100) ? 3 : ((qwProgress >= 10) ? 2 : 1);
        VMMDLL_VfsList_AddFile(pFileList, L"progress_percent.txt", qwProgress, NULL);
    }
    Ob_DECREF(pObEvilMap);
    return TRUE;
}

VOID M_FindEvil_Notify(_In_ DWORD fEvent, _In_opt_ PVOID pvEvent, _In_opt_ DWORD cbEvent)
{
    if(fEvent == VMMDLL_PLUGIN_NOTIFY_FORENSIC_INIT_COMPLETE) {
        PluginManager_SetVisibility(TRUE, L"\\forensic\\findevil", TRUE);
    }
}

VOID M_FindEvil_FcFinalize(_In_opt_ PVOID ctxfc)
{
    VmmEvil_InitializeAll_WaitFinish();
}

BOOL M_FindEvil_VisiblePlugin(_In_ PVMMDLL_PLUGIN_CONTEXT ctx)
{
    return !ctx->pProcess || ((PVMM_PROCESS)ctx->pProcess)->fUserOnly;
}

VOID M_FindEvil_Initialize(_Inout_ PVMMDLL_PLUGIN_REGINFO pRI)
{
    if((pRI->magic != VMMDLL_PLUGIN_REGINFO_MAGIC) || (pRI->wVersion != VMMDLL_PLUGIN_REGINFO_VERSION)) { return; }
    if(pRI->sysinfo.f32 || (pRI->sysinfo.dwVersionBuild < 9600)) { return; }    // only support 64-bit Win8.1+ for now
    pRI->reg_fn.pfnList = M_FindEvil_List;
    pRI->reg_fn.pfnRead = M_FindEvil_Read;
    pRI->reg_fn.pfnVisibleModule = M_FindEvil_VisiblePlugin;                    // programmatic visibility
    // register process plugin
    wcscpy_s(pRI->reg_info.wszPathName, 128, L"\\findevil");
    pRI->reg_info.fRootModule = FALSE;
    pRI->reg_info.fProcessModule = TRUE;
    pRI->pfnPluginManager_Register(pRI);
    // register root plugin
    wcscpy_s(pRI->reg_info.wszPathName, 128, L"\\misc\\findevil");
    pRI->reg_info.fRootModule = TRUE;
    pRI->reg_info.fProcessModule = FALSE;
    pRI->pfnPluginManager_Register(pRI);
    // register forensic plugin
    wcscpy_s(pRI->reg_info.wszPathName, 128, L"\\forensic\\findevil");
    pRI->reg_info.fRootModuleHidden = TRUE;
    pRI->reg_fn.pfnNotify = M_FindEvil_Notify;
    pRI->reg_fnfc.pfnFinalize = M_FindEvil_FcFinalize;
    pRI->pfnPluginManager_Register(pRI);
}
