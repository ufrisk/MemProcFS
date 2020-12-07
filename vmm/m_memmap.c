// m_memmap.c : implementation of the memmap built-in module.
//
// (c) Ulf Frisk, 2019-2020
// Author: Ulf Frisk, pcileech@frizk.net
//
#include "pluginmanager.h"
#include "util.h"
#include "mm.h"
#include "vmm.h"
#include "vmmdll.h"

#define MEMMAP_PTE_LINELENGTH_X86       109ULL
#define MEMMAP_PTE_LINELENGTH_X64       128ULL
#define MEMMAP_VAD_LINELENGTH_X86       137ULL
#define MEMMAP_VAD_LINELENGTH_X64       161ULL

#define MEMMAP_VADEX_LINELENGTH         162ULL

_Success_(return == 0)
NTSTATUS MemMap_Read_VadMap(_In_ PVMM_PROCESS pProcess, _In_ PVMMOB_MAP_VAD pVadMap, _Out_writes_to_(cb, *pcbRead) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset)
{
    NTSTATUS nt;
    LPSTR sz;
    QWORD i, o = 0, cbMax, cStart, cVad, cbLINELENGTH;
    PVMM_MAP_VADENTRY pVad;
    CHAR szProtection[7] = { 0 };
    cbLINELENGTH = ctxVmm->f32 ? MEMMAP_VAD_LINELENGTH_X86 : MEMMAP_VAD_LINELENGTH_X64;
    cStart = (DWORD)(cbOffset / cbLINELENGTH);
    cVad = (DWORD)min(pVadMap->cMap - 1, (cb + cbOffset + cbLINELENGTH - 1) / cbLINELENGTH);
    cbMax = 1 + (1 + cVad - cStart) * cbLINELENGTH;
    if(!pVadMap->cMap || (cStart > pVadMap->cMap)) { return VMMDLL_STATUS_END_OF_FILE; }
    if(!(sz = LocalAlloc(LMEM_ZEROINIT, cbMax))) { return VMMDLL_STATUS_FILE_INVALID; }
    for(i = cStart; i <= cVad; i++) {
        pVad = pVadMap->pMap + i;
        MmVad_StrProtectionFlags(pVad, szProtection);
        if(ctxVmm->f32) {
            o += Util_snwprintf_u8ln(
                sz + o,
                cbLINELENGTH,
                L"%04x%7i %08x %8x %8x %i %08x-%08x %S %S %s",
                (DWORD)i,
                pProcess->dwPID,
                (DWORD)pVad->vaVad,
                (DWORD)((pVad->vaEnd - pVad->vaStart + 1) >> 12),
                pVad->CommitCharge,
                pVad->MemCommit ? 1 : 0,
                (DWORD)pVad->vaStart,
                (DWORD)pVad->vaEnd,
                MmVad_StrType(pVad),
                szProtection,
                pVad->wszText + pVad->cwszText - min(64, pVad->cwszText)
            );
        } else {
            o += Util_snwprintf_u8ln(
                sz + o,
                cbLINELENGTH,
                L"%04x%7i %016llx %8x %8x %i %016llx-%016llx %S %S %s",
                (DWORD)i,
                pProcess->dwPID,
                pVad->vaVad,
                (DWORD)((pVad->vaEnd - pVad->vaStart + 1) >> 12),
                pVad->CommitCharge,
                pVad->MemCommit ? 1 : 0,
                pVad->vaStart,
                pVad->vaEnd,
                MmVad_StrType(pVad),
                szProtection,
                pVad->wszText + pVad->cwszText - min(64, pVad->cwszText)
            );
        }
    }
    nt = Util_VfsReadFile_FromPBYTE(sz, cbMax - 1, pb, cb, pcbRead, cbOffset - cStart * cbLINELENGTH);
    LocalFree(sz);
    return nt;
}

_Success_(return == 0)
NTSTATUS MemMap_Read_VadExMap2(_In_ PVMM_PROCESS pProcess, _In_ DWORD oVadExPages, _In_ DWORD cVadExPagesMax, _Out_writes_to_(cb, *pcbRead) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset)
{
    NTSTATUS nt;
    LPSTR sz;
    QWORD qwHwPte;
    DWORD i, iPage, cPage;
    QWORD o = 0, cbMax, cbLINELENGTH;
    PVMMOB_MAP_VADEX pObMap = NULL;
    PVMM_MAP_VADEXENTRY pex;
    PVMM_MAP_VADENTRY pVad;
    CHAR szProtection[7] = { 0 };
    cbLINELENGTH = MEMMAP_VADEX_LINELENGTH;
    iPage = (DWORD)(cbOffset / cbLINELENGTH) + oVadExPages;
    cPage = (DWORD)min((cb + cbOffset + cbLINELENGTH - 1) / cbLINELENGTH, cVadExPagesMax - (iPage - oVadExPages));
    if(!VmmMap_GetVadEx(pProcess, &pObMap, VMM_VADMAP_TP_FULL, iPage, cPage)) { return VMMDLL_STATUS_FILE_INVALID; }
    cPage = pObMap->cMap;
    cbMax = 1 + pObMap->cMap * cbLINELENGTH;
    if(!(sz = LocalAlloc(LMEM_ZEROINIT, cbMax))) { Ob_DECREF(pObMap); return VMMDLL_STATUS_FILE_INVALID; }
    for(i = 0; i < pObMap->cMap; i++) {
        pex = pObMap->pMap + i;
        pVad = pex->peVad;
        qwHwPte = (pex->tp == VMM_PTE_TP_HARDWARE) ? pex->pte : 0;
        MmVad_StrProtectionFlags(pVad, szProtection);
        o += Util_snwprintf_u8ln(
            sz + o,
            cbLINELENGTH,
            L"%06x%7i %016llx %012llx %016llx %c %c%c%c %016llx %012llx %016llx %c %S %S %s",
            iPage + i,
            pProcess->dwPID,
            pex->va,
            pex->pa,
            pex->pte,
            MmVadEx_StrType(pex->tp),
            qwHwPte ? 'r' : '-',
            (qwHwPte & VMM_MEMMAP_PAGE_W) ? 'w' : '-',
            (!qwHwPte || (qwHwPte & VMM_MEMMAP_PAGE_NX)) ? '-' : 'x',
            pVad->vaVad,
            pex->proto.pa,
            pex->proto.pte,
            MmVadEx_StrType(pex->proto.tp),
            MmVad_StrType(pVad),
            szProtection,
            pVad->wszText + pVad->cwszText - min(32, pVad->cwszText)
        );
    }
    nt = Util_VfsReadFile_FromPBYTE(sz, cbMax - 1, pb, cb, pcbRead, cbOffset - (iPage - oVadExPages) * cbLINELENGTH);
    LocalFree(sz);
    Ob_DECREF(pObMap);
    return nt;
}

int MemMap_Read_VadExMap_CmpFind(_In_ QWORD vaBase, _In_ PVMM_MAP_VADENTRY pEntry)
{
    if(pEntry->vaStart < vaBase) { return 1; }
    if(pEntry->vaStart > vaBase) { return -1; }
    return 0;
}

_Success_(return == 0)
NTSTATUS MemMap_Read_VadExMap(_In_ PVMM_PROCESS pProcess, _In_ LPWSTR wszFile, _Out_writes_to_(cb, *pcbRead) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset)
{
    NTSTATUS nt = VMMDLL_STATUS_FILE_INVALID;
    QWORD vaVad;
    PVMM_MAP_VADENTRY peVad;
    PVMMOB_MAP_VAD pObVadMap = NULL;
    if(!_wcsicmp(wszFile, L"_vad-v.txt")) {
        return MemMap_Read_VadExMap2(pProcess, 0, 0xffffffff, pb, cb, pcbRead, cbOffset);
    }
    if(wszFile[0] == '0' && wszFile[1] == 'x' && VmmMap_GetVad(pProcess, &pObVadMap, VMM_VADMAP_TP_CORE)) {
        vaVad = Util_GetNumericW(wszFile);
        peVad = Util_qfind((PVOID)vaVad, pObVadMap->cMap, pObVadMap->pMap, sizeof(VMM_MAP_VADENTRY), (int(*)(PVOID, PVOID))MemMap_Read_VadExMap_CmpFind);
        if(peVad) {
            nt = MemMap_Read_VadExMap2(pProcess, peVad->cVadExPagesBase, peVad->cVadExPages, pb, cb, pcbRead, cbOffset);
        }
        Ob_DECREF_NULL(&pObVadMap);
        return nt;
    }
    return nt;
}

_Success_(return == 0)
NTSTATUS MemMap_Read_PteMap(_In_ PVMM_PROCESS pProcess, _In_ PVMMOB_MAP_PTE pPteMap, _Out_writes_to_(cb, *pcbRead) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset)
{
    NTSTATUS nt;
    LPSTR sz;
    QWORD i, o = 0, cbMax, cStart, cEnd, cbLINELENGTH;
    PVMM_MAP_PTEENTRY pPte;
    cbLINELENGTH = ctxVmm->f32 ? MEMMAP_PTE_LINELENGTH_X86 : MEMMAP_PTE_LINELENGTH_X64;
    cStart = (DWORD)(cbOffset / cbLINELENGTH);
    cEnd = (DWORD)min(pPteMap->cMap - 1, (cb + cbOffset + cbLINELENGTH - 1) / cbLINELENGTH);
    cbMax = 1 + (1 + cEnd - cStart) * cbLINELENGTH;
    if(!pPteMap->cMap || (cStart > pPteMap->cMap)) { return VMMDLL_STATUS_END_OF_FILE; }
    if(!(sz = LocalAlloc(LMEM_ZEROINIT, cbMax))) { return VMMDLL_STATUS_FILE_INVALID; }
    for(i = cStart; i <= cEnd; i++) {
        pPte = pPteMap->pMap + i;
        if(ctxVmm->f32) {
            o += Util_snwprintf_u8ln(
                sz + o,
                cbLINELENGTH,
                L"%04x%7i %8x %08x-%08x %cr%c%c %s",
                (DWORD)i,
                pProcess->dwPID,
                (DWORD)pPte->cPages,
                (DWORD)pPte->vaBase,
                (DWORD)(pPte->vaBase + (pPte->cPages << 12) - 1),
                pPte->fPage & VMM_MEMMAP_PAGE_NS ? '-' : 's',
                pPte->fPage & VMM_MEMMAP_PAGE_W ? 'w' : '-',
                pPte->fPage & VMM_MEMMAP_PAGE_NX ? '-' : 'x',
                pPte->wszText + pPte->cwszText - min(64, pPte->cwszText)
            );
        } else {
            o += Util_snwprintf_u8ln(
                sz + o,
                cbLINELENGTH,
                L"%04x%7i %8x %016llx-%016llx %cr%c%c%s%s",
                (DWORD)i,
                pProcess->dwPID,
                (DWORD)pPte->cPages,
                pPte->vaBase,
                pPte->vaBase + (pPte->cPages << 12) - 1,
                pPte->fPage & VMM_MEMMAP_PAGE_NS ? '-' : 's',
                pPte->fPage & VMM_MEMMAP_PAGE_W ? 'w' : '-',
                pPte->fPage & VMM_MEMMAP_PAGE_NX ? '-' : 'x',
                pPte->cwszText ? (pPte->fWoW64 ? L" 32 " : L"    ") : L"    ",
                pPte->wszText + pPte->cwszText - min(64, pPte->cwszText)
            );
        }
    }
    nt = Util_VfsReadFile_FromPBYTE(sz, cbMax - 1, pb, cb, pcbRead, cbOffset - cStart * cbLINELENGTH);
    LocalFree(sz);
    return nt;
}

/*
* Read : function as specified by the module manager. The module manager will
* call into this callback function whenever a read shall occur from a "file".
* -- ctx
* -- pb
* -- cb
* -- pcbRead
* -- cbOffset
* -- return
*/
_Success_(return == 0)
NTSTATUS MemMap_Read(_In_ PVMMDLL_PLUGIN_CONTEXT ctx, _Out_writes_to_(cb, *pcbRead) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset)
{
    NTSTATUS nt = VMMDLL_STATUS_FILE_INVALID;
    LPWSTR wszFile;
    WCHAR wszPath1[MAX_PATH];
    PVMMOB_MAP_PTE pObMemMapPte = NULL;
    PVMMOB_MAP_VAD pObMemMapVad = NULL;
    // read page table memory map.
    if(!_wcsicmp(ctx->wszPath, L"pte.txt")) {
        if(VmmMap_GetPte(ctx->pProcess, &pObMemMapPte, TRUE)) {
            nt = MemMap_Read_PteMap(ctx->pProcess, pObMemMapPte, pb, cb, pcbRead, cbOffset);
            Ob_DECREF(pObMemMapPte);
        }
        return nt;
    }
    if(!_wcsicmp(ctx->wszPath, L"vad.txt")) {
        if(VmmMap_GetVad(ctx->pProcess, &pObMemMapVad, VMM_VADMAP_TP_FULL)) {
            nt = MemMap_Read_VadMap(ctx->pProcess, pObMemMapVad, pb, cb, pcbRead, cbOffset);
            Ob_DECREF(pObMemMapVad);
        }
        return nt;
    }
    wszFile = Util_PathSplit2_ExWCHAR(ctx->wszPath, wszPath1, _countof(wszPath1));
    if(!_wcsicmp(wszPath1, L"vad-v") && wszFile[0]) {
        return MemMap_Read_VadExMap(ctx->pProcess, wszFile, pb, cb, pcbRead, cbOffset);

    }
    return nt;
}

/*
* List : function as specified by the module manager. The module manager will
* call into this callback function whenever a list directory shall occur from
* the given module.
* -- ctx
* -- pFileList
* -- return
*/
BOOL MemMap_List(_In_ PVMMDLL_PLUGIN_CONTEXT ctx, _Inout_ PHANDLE pFileList)
{
    DWORD iVad;
    LPWSTR wszFile;
    WCHAR wszPath1[MAX_PATH];
    PVMMOB_MAP_PTE pObPteMap = NULL;
    PVMMOB_MAP_VAD pObVadMap = NULL;
    if(!ctx->wszPath[0]) {
        // list page table memory map.
        if(VmmMap_GetPte(ctx->pProcess, &pObPteMap, FALSE)) {
            VMMDLL_VfsList_AddFile(pFileList, L"pte.txt", pObPteMap->cMap * (ctxVmm->f32 ? MEMMAP_PTE_LINELENGTH_X86 : MEMMAP_PTE_LINELENGTH_X64), NULL);
            Ob_DECREF_NULL(&pObPteMap);
        }
        // list vad & and extended vad map directory
        VMMDLL_VfsList_AddDirectory(pFileList, L"vad-v", NULL);
        if(VmmMap_GetVad(ctx->pProcess, &pObVadMap, VMM_VADMAP_TP_CORE)) {
            VMMDLL_VfsList_AddFile(pFileList, L"vad.txt", pObVadMap->cMap * (ctxVmm->f32 ? MEMMAP_VAD_LINELENGTH_X86 : MEMMAP_VAD_LINELENGTH_X64), NULL);
            Ob_DECREF_NULL(&pObVadMap);
        }
        return TRUE;
    }
    wszFile = Util_PathSplit2_ExWCHAR(ctx->wszPath, wszPath1, _countof(wszPath1));
    if(!_wcsicmp(wszPath1, L"vad-v") && !wszFile[0]) {
        if(VmmMap_GetVad(ctx->pProcess, &pObVadMap, VMM_VADMAP_TP_FULL)) {
            VMMDLL_VfsList_AddFile(pFileList, L"_vad-v.txt", pObVadMap->cPage * MEMMAP_VADEX_LINELENGTH, NULL);
            for(iVad = 0; iVad < pObVadMap->cMap; iVad++) {
                swprintf_s(
                    wszPath1,
                    _countof(wszPath1) - 1,
                    ctxVmm->f32 ? L"0x%08llx%s%s.txt" : L"0x%016llx%s%s.txt",
                    pObVadMap->pMap[iVad].vaStart,
                    pObVadMap->pMap[iVad].cwszText ? L"-" : L"",
                    pObVadMap->pMap[iVad].cwszText ? Util_PathSplitLastW(pObVadMap->pMap[iVad].wszText) : L""
                );
                VMMDLL_VfsList_AddFile(pFileList, wszPath1, pObVadMap->pMap[iVad].cVadExPages * MEMMAP_VADEX_LINELENGTH, NULL);
            }
            Ob_DECREF_NULL(&pObVadMap);
        }
    }
    return TRUE;
}

/*
* Initialization function. The module manager shall call into this function
* when the module shall be initialized. If the module wish to initialize it
* shall call the supplied pfnPluginManager_Register function.
* NB! the module does not have to register itself - for example if the target
* operating system or architecture is unsupported.
* -- pPluginRegInfo
*/
VOID M_MemMap_Initialize(_Inout_ PVMMDLL_PLUGIN_REGINFO pRI)
{
    if((pRI->magic != VMMDLL_PLUGIN_REGINFO_MAGIC) || (pRI->wVersion != VMMDLL_PLUGIN_REGINFO_VERSION)) { return; }
    if(!((pRI->tpMemoryModel == VMM_MEMORYMODEL_X64) || (pRI->tpMemoryModel == VMM_MEMORYMODEL_X86) || (pRI->tpMemoryModel == VMM_MEMORYMODEL_X86PAE))) { return; }
    wcscpy_s(pRI->reg_info.wszPathName, 128, L"\\memmap");              // module name
    pRI->reg_info.fRootModule = FALSE;                                  // module shows in root directory
    pRI->reg_info.fProcessModule = TRUE;                                // module shows in process directory
    pRI->reg_fn.pfnList = MemMap_List;                                  // List function supported
    pRI->reg_fn.pfnRead = MemMap_Read;                                  // Read function supported
    pRI->pfnPluginManager_Register(pRI);
}
