// m_proc_heap.c : implementation of the heaps built-in module.
//
// (c) Ulf Frisk, 2022-2025
// Author: Ulf Frisk, pcileech@frizk.net
//

#include "modules.h"

LPCSTR szMHEAP_README =
"Information about the heap process module                                    \n" \
"=========================================                                    \n" \
"The heap process module tries to parse user-mode heaps and display results.  \n" \
"Some heap parsing is dependant on debug symbols. Parsing may be degraded if  \n" \
"symbols are missing. The heap module is work in progress.                    \n" \
"NT heap parsing is supported on Vista and above.                             \n" \
"Segment heap parsing is supported on Windows 10 1709 and above.              \n" \
"---                                                                          \n" \
"Documentation: https://github.com/ufrisk/MemProcFS/wiki/FS_Proc_Heap         \n";

#define MHEAP_HEAP_LINELENGTH       42ULL
#define MHEAP_HEAP_LINEHEADER       "   #    PID Heap          Address Type"

#define MHEAP_SEGMENT_LINELENGTH    45ULL
#define MHEAP_SEGMENT_LINEHEADER    "   #    PID Heap          Address Type"

#define MHEAP_ALLOC_LINELENGTH      50ULL
#define MHEAP_ALLOC_LINEHEADER      "   #    PID Heap          Address     Size Type"

#define MHEAP_ALLOCV_LINELENGTH     120ULL
#define MHEAP_ALLOCV_LINEHEADER     "   #    PID Heap          Address     Size Type     HexAscii16"

#define MHEAP_ALLOC_PER_DIR_MAX     0x1000

typedef struct tdMHEAP_CTX {
    BOOL fVerbose;
    DWORD dwHeapId;
    PVMM_PROCESS pProcess;
} MHEAP_CTX, *PMHEAP_CTX;

VOID MHeap_HeapReadLineCB(_In_ VMM_HANDLE H, _In_ PMHEAP_CTX ctx, _In_ DWORD cbLineLength, _In_ DWORD ie, _In_ PVMM_MAP_HEAPENTRY pe, _Out_writes_(cbLineLength + 1) LPSTR szu8)
{
    Util_usnprintf_ln(szu8, cbLineLength,
        "%04x%7i %4i %016llx %s%s",
        ie,
        ctx->pProcess->dwPID,
        pe->iHeap,
        pe->va,
        VMM_HEAP_TP_STR[pe->tp],
        (!H->vmm.f32 && pe->f32) ? " (32)" : ""
    );
}

VOID MHeap_SegmentReadLineCB(_In_ VMM_HANDLE H, _In_ PMHEAP_CTX ctx, _In_ DWORD cbLineLength, _In_ DWORD ie, _In_ PVMM_MAP_HEAP_SEGMENTENTRY pe, _Out_writes_(cbLineLength + 1) LPSTR szu8)
{
    Util_usnprintf_ln(szu8, cbLineLength,
        "%04x%7i %4i %016llx %s",
        ie,
        ctx->pProcess->dwPID,
        pe->iHeap,
        pe->va,
        VMM_HEAP_SEGMENT_TP_STR[pe->tp]
    );
}

VOID MHeap_AllocReadLineCB(_In_ VMM_HANDLE H, _In_ PMHEAP_CTX ctx, _In_ DWORD cbLineLength, _In_ DWORD ie, _In_ PVMM_MAP_HEAPALLOCENTRY pe, _Out_writes_(cbLineLength + 1) LPSTR szu8)
{
    BYTE pb16[16] = { 0 };
    CHAR szHex[80] = { 0 };
    DWORD cbHex;
    if(ctx->fVerbose) {
        cbHex = sizeof(szHex);
        VmmRead(H, ctx->pProcess, pe->va, pb16, min(16, pe->cb));
        Util_FillHexAscii(pb16, 16, 0, szHex, &cbHex);
    }
    Util_usnprintf_ln(szu8, cbLineLength,
        "%04x%7i %4i %016llx %8x %-8s %s",
        ie,
        ctx->pProcess->dwPID,
        ctx->dwHeapId,
        pe->va,
        pe->cb,
        VMM_HEAPALLOC_TP_STR[pe->tp],
        szHex + 8
    );
}

_Success_(return)
BOOL MHeap_GetAllocPath(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_CONTEXT ctxP, _Out_ PVMMOB_MAP_HEAPALLOC *ppObHeapAllocMap, _Out_ LPSTR *pszPath)
{
    DWORD dwId = (DWORD)Util_GetNumericA(ctxP->uszPath);
    if(!dwId && (ctxP->uszPath[0] != '0')) return FALSE;
    *pszPath = (LPSTR)CharUtil_PathSplitNext(ctxP->uszPath);
    return VmmMap_GetHeapAlloc(H, ctxP->pProcess, dwId, ppObHeapAllocMap);
}

/*
* Write : function as specified by the module manager. The module manager will
* call into this callback function whenever a write shall occur from a "file".
* -- H
* -- ctxP
* -- pb
* -- cb
* -- pcbWrite
* -- cbOffset
* -- return
*/
NTSTATUS MHeap_Write(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_CONTEXT ctxP, _In_reads_(cb) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbWrite, _In_ QWORD cbOffset)
{
    QWORD va;
    LPCSTR uszPath;
    PVMM_MAP_HEAPALLOCENTRY peA;
    PVMMOB_MAP_HEAPALLOC pObHeapAllocMap = NULL;
    *pcbWrite = 0;
    if(!MHeap_GetAllocPath(H, ctxP, &pObHeapAllocMap, (LPSTR*)&uszPath)) { goto finish; }
    if(CharUtil_StrEndsWith(uszPath, ".mem", FALSE)) {
        uszPath = CharUtil_PathSplitLast(uszPath);
        va = Util_GetNumericA(uszPath);
        if(va && (peA = VmmMap_GetHeapAllocEntry(H, pObHeapAllocMap, va))) {
            VmmWriteAsFile(H, ctxP->pProcess, peA->va, peA->cb, pb, cb, pcbWrite, cbOffset);
        }
        goto finish;
    }
finish:
    return VMM_STATUS_SUCCESS;
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
NTSTATUS MHeap_Read(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_CONTEXT ctxP, _Out_writes_to_(cb, *pcbRead) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset)
{
    NTSTATUS nt = VMMDLL_STATUS_FILE_INVALID;
    PVMMOB_MAP_HEAP pObHeapMap = NULL;
    PVMMOB_MAP_HEAPALLOC pObHeapAllocMap = NULL;
    PVMM_MAP_HEAPALLOCENTRY peA;
    MHEAP_CTX ctx = { 0 };
    LPCSTR uszPath;
    QWORD va;
    if(!VmmMap_GetHeap(H, ctxP->pProcess, &pObHeapMap)) { return VMMDLL_STATUS_FILE_INVALID; }
    ctx.pProcess = (PVMM_PROCESS)ctxP->pProcess;
    // module root - heap info files
    if(!_stricmp(ctxP->uszPath, "readme.txt")) {
        return Util_VfsReadFile_FromStrA(szMHEAP_README, pb, cb, pcbRead, cbOffset);
    }
    if(!_stricmp(ctxP->uszPath, "heaps.txt")) {
        nt = Util_VfsLineFixed_Read(
            H, (UTIL_VFSLINEFIXED_PFN_CB)MHeap_HeapReadLineCB, &ctx, MHEAP_HEAP_LINELENGTH, MHEAP_HEAP_LINEHEADER,
            pObHeapMap->pMap, pObHeapMap->cMap, sizeof(VMM_MAP_HEAPENTRY),
            pb, cb, pcbRead, cbOffset
        );
        goto finish;
    }
    if(!_stricmp(ctxP->uszPath, "segments.txt")) {
        nt = Util_VfsLineFixed_Read(
            H, (UTIL_VFSLINEFIXED_PFN_CB)MHeap_SegmentReadLineCB, &ctx, MHEAP_SEGMENT_LINELENGTH, MHEAP_SEGMENT_LINEHEADER,
            pObHeapMap->pSegments, pObHeapMap->cSegments, sizeof(VMM_MAP_HEAP_SEGMENTENTRY),
            pb, cb, pcbRead, cbOffset
        );
        goto finish;
    }
    // specific heap
    if(!MHeap_GetAllocPath(H, ctxP, &pObHeapAllocMap, (LPSTR*)&uszPath)) { goto finish; }
    if(!_stricmp(uszPath, "allocations.txt")) {
        nt = Util_VfsLineFixed_Read(
            H, (UTIL_VFSLINEFIXED_PFN_CB)MHeap_AllocReadLineCB, &ctx, MHEAP_ALLOC_LINELENGTH, MHEAP_ALLOC_LINEHEADER,
            pObHeapAllocMap->pMap, pObHeapAllocMap->cMap, sizeof(VMM_MAP_HEAPALLOCENTRY),
            pb, cb, pcbRead, cbOffset
        );
        goto finish;
    }
    if(!_stricmp(uszPath, "allocations-v.txt")) {
        ctx.fVerbose = TRUE;
        nt = Util_VfsLineFixed_Read(
            H, (UTIL_VFSLINEFIXED_PFN_CB)MHeap_AllocReadLineCB, &ctx, MHEAP_ALLOCV_LINELENGTH, MHEAP_ALLOCV_LINEHEADER,
            pObHeapAllocMap->pMap, pObHeapAllocMap->cMap, sizeof(VMM_MAP_HEAPALLOCENTRY),
            pb, cb, pcbRead, cbOffset
        );
        goto finish;
    }
    if(CharUtil_StrEndsWith(uszPath, ".mem", FALSE)) {
        uszPath = CharUtil_PathSplitLast(uszPath);
        va = Util_GetNumericA(uszPath);
        if(va && (peA = VmmMap_GetHeapAllocEntry(H, pObHeapAllocMap, va))) {
            nt = Util_VfsReadFile_FromMEM(H, ctxP->pProcess, va, peA->cb, 0, pb, cb, pcbRead, cbOffset);
        }
        goto finish;
    }
finish:
    Ob_DECREF(pObHeapMap);
    return nt;
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
BOOL MHeap_List(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_CONTEXT ctxP, _Inout_ PHANDLE pFileList)
{
    PVMMOB_MAP_HEAP pObHeapMap = NULL;
    PVMMOB_MAP_HEAPALLOC pObHeapAllocMap = NULL;
    PVMM_MAP_HEAPENTRY peH;
    PVMM_MAP_HEAPALLOCENTRY peA;
    CHAR szBuffer[32];
    LPSTR uszPath;
    DWORD i, iBase;
    LPSTR szFORMATMEM = H->vmm.f32 ? "0x%08llx.mem" : "0x%012llx.mem";
    if(!VmmMap_GetHeap(H, ctxP->pProcess, &pObHeapMap)) { goto finish; }
    // module root - list heap map
    if(!ctxP->uszPath[0]) {
        for(i = 0; i < pObHeapMap->cMap; i++) {
            peH = pObHeapMap->pMap + i;
            _snprintf_s(szBuffer, _countof(szBuffer), _TRUNCATE, "%i", peH->iHeap);
            VMMDLL_VfsList_AddDirectory(pFileList, szBuffer, NULL);
        }
        VMMDLL_VfsList_AddFile(pFileList, "readme.txt", strlen(szMHEAP_README), NULL);
        VMMDLL_VfsList_AddFile(pFileList, "heaps.txt", UTIL_VFSLINEFIXED_LINECOUNT(H, pObHeapMap->cMap) * MHEAP_HEAP_LINELENGTH, NULL);
        VMMDLL_VfsList_AddFile(pFileList, "segments.txt", UTIL_VFSLINEFIXED_LINECOUNT(H, pObHeapMap->cSegments) * MHEAP_SEGMENT_LINELENGTH, NULL);
        goto finish;
    }
    // specific heap
    if(!MHeap_GetAllocPath(H, ctxP, &pObHeapAllocMap, &uszPath)) { goto finish; }
    if(!uszPath[0]) {
        for(i = 0; i < pObHeapAllocMap->cMap; i += MHEAP_ALLOC_PER_DIR_MAX) {
            _snprintf_s(szBuffer, _countof(szBuffer), _TRUNCATE, "0x%x", i);
            VMMDLL_VfsList_AddDirectory(pFileList, szBuffer, NULL);
        }
        VMMDLL_VfsList_AddFile(pFileList, "allocations.txt", UTIL_VFSLINEFIXED_LINECOUNT(H, pObHeapAllocMap->cMap) * MHEAP_ALLOC_LINELENGTH, NULL);
        VMMDLL_VfsList_AddFile(pFileList, "allocations-v.txt", UTIL_VFSLINEFIXED_LINECOUNT(H, pObHeapAllocMap->cMap) * MHEAP_ALLOCV_LINELENGTH, NULL);
        goto finish;
    }
    iBase = (DWORD)Util_GetNumericA(uszPath);
    if(!iBase && (uszPath[0] != '0')) { goto finish; }
    if(CharUtil_PathSplitNext(uszPath)[0]) { goto finish; }
    for(i = iBase; ((i < iBase + MHEAP_ALLOC_PER_DIR_MAX) && (i < pObHeapAllocMap->cMap)); i++) {
        peA = pObHeapAllocMap->pMap + i;
        _snprintf_s(szBuffer, _countof(szBuffer), _TRUNCATE, szFORMATMEM, peA->va);
        VMMDLL_VfsList_AddFile(pFileList, szBuffer, peA->cb, NULL);
    }
finish:
    Ob_DECREF_NULL(&pObHeapMap);
    Ob_DECREF_NULL(&pObHeapAllocMap);
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
VOID M_ProcHeap_Initialize(_In_ VMM_HANDLE H, _Inout_ PVMMDLL_PLUGIN_REGINFO pRI)
{
    if((pRI->magic != VMMDLL_PLUGIN_REGINFO_MAGIC) || (pRI->wVersion != VMMDLL_PLUGIN_REGINFO_VERSION)) { return; }
    if(!((pRI->tpSystem == VMM_SYSTEM_WINDOWS_64) || (pRI->tpSystem == VMM_SYSTEM_WINDOWS_32))) { return; }
    strcpy_s(pRI->reg_info.uszPathName, 128, "\\heaps");                // module name
    pRI->reg_info.fRootModule = FALSE;                                  // module shows in root directory
    pRI->reg_info.fProcessModule = TRUE;                                // module shows in process directory
    pRI->reg_fn.pfnList = MHeap_List;                                   // List function supported
    pRI->reg_fn.pfnRead = MHeap_Read;                                   // Read function supported
    pRI->reg_fn.pfnWrite = MHeap_Write;                                 // Write function supported
    pRI->pfnPluginManager_Register(H, pRI);
}
