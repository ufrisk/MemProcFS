// m_memmap.c : implementation of the memmap built-in module.
//
// (c) Ulf Frisk, 2019-2020
// Author: Ulf Frisk, pcileech@frizk.net
//
#include "pluginmanager.h"
#include "util.h"
#include "vmm.h"
#include "vmmdll.h"

#define MEMMAP_PTE_LINELENGTH_X86       109ULL
#define MEMMAP_PTE_LINELENGTH_X64       128ULL
#define MEMMAP_VAD_LINELENGTH_X86       137ULL
#define MEMMAP_VAD_LINELENGTH_X64       161ULL

VOID MemMap_Read_VadMap_Protection(_In_ PVMM_MAP_VADENTRY pVad, _Out_writes_(6) LPSTR sz)
{
    BYTE vh = (BYTE)pVad->Protection >> 3;
    BYTE vl = (BYTE)pVad->Protection & 7;
    sz[0] = pVad->fPrivateMemory ? 'p' : '-';                                    // PRIVATE MEMORY
    sz[1] = (vh & 2) ? ((vh & 1) ? 'm' : 'g') : ((vh & 1) ? 'n' : '-');         // -/NO_CACHE/GUARD/WRITECOMBINE
    sz[2] = ((vl == 1) || (vl == 3) || (vl == 4) || (vl == 6)) ? 'r' : '-';     // COPY ON WRITE
    sz[3] = (vl & 4) ? 'w' : '-';                                               // WRITE
    sz[4] = (vl & 2) ? 'x' : '-';                                               // EXECUTE
    sz[5] = ((vl == 5) || (vl == 7)) ? 'c' : '-';                               // COPY ON WRITE
    if(sz[1] != '-' && sz[2] == '-' && sz[3] == '-' && sz[4] == '-' && sz[5] == '-') { sz[1] = '-'; }
}

LPSTR MemMap_Read_VadMap_Type(_In_ PVMM_MAP_VADENTRY pVad)
{
    if(pVad->fImage) {
        return "Image";
    } else if(pVad->fFile) {
        return "File ";
    } else if(pVad->fHeap) {
        return "Heap ";
    } else if(pVad->fStack) {
        return "Stack";
    } else if(pVad->fTeb) {
        return "Teb  ";
    } else if(pVad->fPageFile) {
        return "Pf   ";
    } else {
        return "     ";
    }
}

_Success_(return == 0)
NTSTATUS MemMap_Read_VadMap(_In_ PVMM_PROCESS pProcess, _In_ PVMMOB_MAP_VAD pVadMap, _Out_ PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset)
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
        MemMap_Read_VadMap_Protection(pVad, szProtection);
        if(ctxVmm->f32) {
            o += Util_snprintf_ln(
                sz + o,
                cbMax - o,
                cbLINELENGTH,
                "%04x%7i %08x %8x %8x %i %08x-%08x %s %s %-64S\n",
                (DWORD)i,
                pProcess->dwPID,
                (DWORD)pVad->vaVad,
                (DWORD)((pVad->vaEnd - pVad->vaStart + 1) >> 12),
                pVad->CommitCharge,
                pVad->MemCommit ? 1 : 0,
                (DWORD)pVad->vaStart,
                (DWORD)pVad->vaEnd,
                MemMap_Read_VadMap_Type(pVad),
                szProtection,
                pVad->wszText + pVad->cwszText - min(64, pVad->cwszText)
            );
        } else {
            o += Util_snprintf_ln(
                sz + o,
                cbMax - o,
                cbLINELENGTH,
                "%04x%7i %016llx %8x %8x %i %016llx-%016llx %s %s %-64S\n",
                (DWORD)i,
                pProcess->dwPID,
                pVad->vaVad,
                (DWORD)((pVad->vaEnd - pVad->vaStart + 1) >> 12),
                pVad->CommitCharge,
                pVad->MemCommit ? 1 : 0,
                pVad->vaStart,
                pVad->vaEnd,
                MemMap_Read_VadMap_Type(pVad),
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
NTSTATUS MemMap_Read_PteMap(_In_ PVMM_PROCESS pProcess, _In_ PVMMOB_MAP_PTE pPteMap, _Out_ PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset)
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
            o += Util_snprintf_ln(
                sz + o,
                cbMax - o,
                cbLINELENGTH,
                "%04x%7i %8x %08x-%08x %sr%s%s %-64S\n",
                (DWORD)i,
                pProcess->dwPID,
                (DWORD)pPte->cPages,
                (DWORD)pPte->vaBase,
                (DWORD)(pPte->vaBase + (pPte->cPages << 12) - 1),
                pPte->fPage & VMM_MEMMAP_PAGE_NS ? "-" : "s",
                pPte->fPage & VMM_MEMMAP_PAGE_W ? "w" : "-",
                pPte->fPage & VMM_MEMMAP_PAGE_NX ? "-" : "x",
                pPte->wszText + pPte->cwszText - min(64, pPte->cwszText)
            );
        } else {
            o += Util_snprintf_ln(
                sz + o,
                cbMax - o,
                cbLINELENGTH,
                "%04x%7i %8x %016llx-%016llx %sr%s%s%s%-64S\n",
                (DWORD)i,
                pProcess->dwPID,
                (DWORD)pPte->cPages,
                pPte->vaBase,
                pPte->vaBase + (pPte->cPages << 12) - 1,
                pPte->fPage & VMM_MEMMAP_PAGE_NS ? "-" : "s",
                pPte->fPage & VMM_MEMMAP_PAGE_W ? "w" : "-",
                pPte->fPage & VMM_MEMMAP_PAGE_NX ? "-" : "x",
                pPte->cwszText ? (pPte->fWoW64 ? " 32 " : "    ") : "    ",
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
NTSTATUS MemMap_Read(_In_ PVMMDLL_PLUGIN_CONTEXT ctx, _Out_ PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset)
{
    NTSTATUS nt = VMMDLL_STATUS_FILE_INVALID;
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
        if(VmmMap_GetVad(ctx->pProcess, &pObMemMapVad, TRUE)) {
            nt = MemMap_Read_VadMap(ctx->pProcess, pObMemMapVad, pb, cb, pcbRead, cbOffset);
            Ob_DECREF(pObMemMapVad);
        }
        return nt;
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
    PVMMOB_MAP_PTE pObMemMapPte = NULL;
    PVMMOB_MAP_VAD pObMemMapVad = NULL;
    // list page table memory map.
    if(VmmMap_GetPte(ctx->pProcess, &pObMemMapPte, FALSE)) {
        VMMDLL_VfsList_AddFile(pFileList, L"pte.txt", pObMemMapPte->cMap * (ctxVmm->f32 ? MEMMAP_PTE_LINELENGTH_X86 : MEMMAP_PTE_LINELENGTH_X64), NULL);
        Ob_DECREF_NULL(&pObMemMapPte);
    }
    // list vad memory map.
    if(VmmMap_GetVad(ctx->pProcess, &pObMemMapVad, FALSE)) {
        VMMDLL_VfsList_AddFile(pFileList, L"vad.txt", pObMemMapVad->cMap * (ctxVmm->f32 ? MEMMAP_VAD_LINELENGTH_X86 : MEMMAP_VAD_LINELENGTH_X64), NULL);
        Ob_DECREF_NULL(&pObMemMapVad);
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
