// mm_x64_page_win.c : implementation related to the x64 windows paging subsystem
//                     (including paged out virtual/compressed virtual memory).
//
// (c) Ulf Frisk, 2019
// Author: Ulf Frisk, pcileech@frizk.net
//
#include "mm_x64_page_win.h"
#include "pe.h"
#include "statistics.h"
#include "util.h"

//-----------------------------------------------------------------------------
// CUSTOM GENERAL FUNCTIONS BELOW:
//-----------------------------------------------------------------------------

/*
* Read memory with option VMM_FLAG_NOPAGED to avoid circular reads back into
* the paging subsystem. Otherwise identical to the VmmRead function.
*/
_Success_(return)
BOOL MmX64PageWin_VmmRead(_In_opt_ PVMM_PROCESS pProcess, _In_ QWORD qwA, _Out_ PBYTE pb, _In_ DWORD cb)
{
    DWORD cbRead;
    VmmReadEx(pProcess, qwA, pb, cb, &cbRead, VMM_FLAG_NOPAGING);
    return (cbRead == cb);
}

//-----------------------------------------------------------------------------
// BTREE FUNCTIONALITY BELOW:
//-----------------------------------------------------------------------------

typedef struct td_BTREE_LEAF_NODE {
    DWORD k;
    DWORD v;
} _BTREE_LEAF_NODE;

typedef struct td_BTREE_LEAF {
    WORD cEntries;
    BYTE  cLevel;
    BYTE  fLeaf;
    QWORD vaLeftChild;
    _BTREE_LEAF_NODE Entries[];
} _BTREE_LEAF, *P_BTREE_LEAF;

typedef struct td_BTREE_NODE {
    DWORD k;
    QWORD vaLeaf;
} _BTREE_NODE;

typedef struct td_BTREE {
    WORD cEntries;
    BYTE  cLevel;
    BYTE  fLeaf;
    QWORD vaLeftChild;
    _BTREE_NODE Entries[];
} _BTREE, *P_BTREE;

_Success_(return)
BOOL MmX64PageWin_BTreeSearch_Leaf(_In_ PVMM_PROCESS pSystemProcess, _In_ QWORD vaLeaf, _In_ DWORD dwKey, _Out_ PDWORD pdwValue)
{
    BOOL f, fSearchPreFail = FALSE;
    DWORD i, dwSearchStep, dwSearchIndex = 1, dwSearchCount = 0;
    BYTE pbBuffer[0x1000];
    P_BTREE_LEAF pT = (P_BTREE_LEAF)pbBuffer;
    // 1: read tree leaf page
    f = VMM_KADDR64_PAGE(vaLeaf) &&
        MmX64PageWin_VmmRead(pSystemProcess, vaLeaf, pbBuffer, 0x1000) &&
        pT->fLeaf &&
        pT->cEntries &&
        (pT->cEntries <= 0x1ff);
    if(!f) { return FALSE; }
    // 2: search tree for leaf
    for(i = 1; (i < 12) && ((pT->cEntries - 1) >> i); i++);
    dwSearchIndex = dwSearchStep = min(1 << (i - 1), pT->cEntries);
    while(TRUE) {
        dwSearchCount++;
        dwSearchStep = dwSearchStep >> 1;
        if(pT->Entries[dwSearchIndex].k == dwKey) {
            *pdwValue = pT->Entries[dwSearchIndex].v;
            return TRUE;
        }
        if(dwSearchStep == 0) {
            if(fSearchPreFail) {
                return FALSE;
            }
            fSearchPreFail = TRUE;
            dwSearchStep = 1;
        }
        if(pT->Entries[dwSearchIndex].k < dwKey) {
            if(dwSearchIndex + dwSearchStep < pT->cEntries) {
                dwSearchIndex += dwSearchStep;
            }
        } else {
            if(dwSearchStep <= dwSearchIndex) {
                dwSearchIndex -= dwSearchStep;
            }
        }
    }
}

_Success_(return)
BOOL MmX64PageWin_BTreeSearch(_In_ PVMM_PROCESS pSystemProcess, _In_ QWORD vaTreeRoot, _In_ DWORD dwKey, _Out_ PDWORD pdwValue)
{
    BOOL f, fSearchPreFail = FALSE;
    DWORD i, dwSearchStep, dwSearchIndex = 1, dwSearchCount = 0;
    QWORD vaEntryLeaf = 0;
    BYTE pbBuffer[0x1000];
    P_BTREE pT = (P_BTREE)pbBuffer;
    // 1: read tree root
    f = VMM_KADDR64_PAGE(vaTreeRoot) &&
        MmX64PageWin_VmmRead(pSystemProcess, vaTreeRoot, pbBuffer, 0x1000) &&
        !pT->fLeaf &&
        pT->cEntries &&
        (pT->cEntries <= 0xff);
    if(!f) { return FALSE; }
    // 2: search tree for leaf
    for(i = 1; (i < 12) && ((pT->cEntries - 1) >> i); i++);
    dwSearchIndex = dwSearchStep = min(1 << (i - 1), pT->cEntries);
    while(TRUE) {
        dwSearchCount++;
        dwSearchStep = dwSearchStep >> 1;
        if((dwSearchStep == 0) && !fSearchPreFail) {
            fSearchPreFail = TRUE;
            dwSearchStep = 1;
        }
        if((dwSearchStep == 0) || ((pT->Entries[dwSearchIndex].k <= dwKey) && ((dwSearchIndex + 1 == pT->cEntries) || (pT->Entries[dwSearchIndex + 1].k > dwKey)))) {
            if((dwSearchIndex == 0) && (pT->Entries[0].k > dwKey)) {
                vaEntryLeaf = pT->vaLeftChild;
            } else {
                vaEntryLeaf = pT->Entries[dwSearchIndex].vaLeaf;
            }
            return MmX64PageWin_BTreeSearch_Leaf(pSystemProcess, vaEntryLeaf, dwKey, pdwValue);
        } else if(pT->Entries[dwSearchIndex].k < dwKey) {
            if(dwSearchIndex + dwSearchStep < pT->cEntries) {
                dwSearchIndex += dwSearchStep;
            }
        } else {
            if(dwSearchStep <= dwSearchIndex) {
                dwSearchIndex -= dwSearchStep;
            }
        }
    }
}

//-----------------------------------------------------------------------------
// INITIALIZATION FUNCTIONALITY BELOW:
//-----------------------------------------------------------------------------

/*
* Fuzz offsets in _SMKM_STORE / _ST_STORE / _ST_DATA_MGR
* NB! this function does not do any real fuzzing it rather queries the OS build
* number / version to determine correct offsets.
*/
VOID MmX64PageWin_MemCompress_Fuzz()
{
    PVMMWIN_MEMCOMPRESS_OFFSET po = &ctxVmm->kernel.MemCompress.O;
    po->SMKM_STORE.PagesTree = 0x50 + 0x0;                  // static = ok
    po->SMKM_STORE.ChunkMetaData = 0x50 + 0xC0;             // static = ok
    po->SMKM_STORE.SmkmStore = 0x50 + 0x320;                // static = ok
    po->SMKM_STORE.RegionSizeMask = 0x50 + 0x328;           // static = ok
    po->SMKM_STORE.RegionIndexMask = 0x50 + 0x32C;          // static = ok
    po->SMKM_STORE.CompressionAlgorithm = 0x50 + 0x3E0;     // 1709+
    po->SMKM_STORE.CompressedRegionPtrArray = 0x1848;       // 1709+
    po->SMKM_STORE.OwnerProcess = 0x19A8;                   // 1709+
    if(ctxVmm->kernel.dwVersionBuild == 15063) {            // 1703
        po->SMKM_STORE.CompressionAlgorithm = 0x50 + 0x3D0;
        po->SMKM_STORE.CompressedRegionPtrArray = 0x1828;
        po->SMKM_STORE.OwnerProcess = 0x1988;
    }
    if(ctxVmm->kernel.dwVersionBuild == 14393) {            // 1607
        po->SMKM_STORE.CompressionAlgorithm = 0x50 + 0x3D0;
        po->SMKM_STORE.CompressedRegionPtrArray = 0x17A8;
        po->SMKM_STORE.OwnerProcess = 0x1918;
    }
    po->_Size = po->SMKM_STORE.OwnerProcess + 8;
    po->_fProcessedTry = TRUE;
    po->_fValid = TRUE;
}

/*
* Retrieve the page file number of the virtual store. This will be '2' on a
* standard system, but if paging are configured in a non-standard way this
* number may differ.
* Walk ntoskrnl.exe!.data section for candidate pointers to nt!_MMPAGING_FILE
* which have pool header: 'Mm  '. The page file number and the virtual store
* flag is contained at same bits in all known versions with MemCompression
* as per below:
* dt nt!_MMPAGING_FILE
*  +0x0cc PageFileNumber   : Pos 0, 4 Bits
*  +0x0cc VirtualStorePagefile : Pos 6, 1 Bit
* If this function fails it will automatically fallback to the default number
* of 2.
*/
VOID MmX64PageWin_MemCompress_InitializeVirtualStorePageFileNumber()
{
    BOOL f;
    BYTE pbMm[0x100] = { 0 };
    QWORD j, va = 0;
    DWORD i, cb, cbRead;
    PBYTE pb = NULL;
    PVMM_PROCESS pObSystemProcess = NULL;
    IMAGE_SECTION_HEADER oSectionHeader;
    POB_VSET pObSet = NULL;
    ctxVmm->kernel.MemCompress.dwPageFileNumber = 2;
    // 1: Locate candicate pointers to 'nt!_MMPAGING_FILE' candidates in ntoskrnl.exe!.data section
    if(!(pObSystemProcess = VmmProcessGet(4))) { goto finish; }
    if(!(pObSet = ObVSet_New())) { goto finish; }
    if(!PE_SectionGetFromName(pObSystemProcess, ctxVmm->kernel.vaBase, ".data", &oSectionHeader)) {
        vmmprintfv_fn("CANNOT READ ntoskrnl.exe .data SECTION from PE header.\n");
        goto finish;
    }
    if(oSectionHeader.Misc.VirtualSize > 0x00100000) { goto finish; }
    cb = oSectionHeader.Misc.VirtualSize;
    if(!(pb = LocalAlloc(0, cb))) { goto finish; }
    if(!VmmRead(pObSystemProcess, ctxVmm->kernel.vaBase + oSectionHeader.VirtualAddress, pb, cb)) {
        vmmprintfv_fn("CANNOT READ ntoskrnl.exe .data SECTION.\n");
        goto finish;
    }
    for(i = 0; i < cb - 0x90; i += 8) {
        f = (*(PDWORD)(pb + i + 0x004) == 1) &&
            *(PDWORD)(pb + i + 0x000) &&
            (*(PDWORD)(pb + i + 0x000) < 16) &&
            VMM_KADDR64_16(*(PQWORD)(pb + i + 0x008)) &&
            VMM_KADDR64_16(*(PQWORD)(pb + i + 0x010)) &&
            ((*(PQWORD)(pb + i + 0x008) >> 32) == (*(PQWORD)(pb + i + 0x010) >> 32));
        if(f) {
            for(j = 0; j < *(PDWORD)(pb + i + 0x000); j++) {
                va = *(PQWORD)(pb + i + 0x008 + j * 8);
                if(VMM_KADDR64_16(va)) {
                    ObVSet_Push(pObSet, va);
                }
            }
        }
    }
    // 2: Verify nt!dt _MMPAGING_FILE by looking at pool header and VirtualStorePagefile bit
    VmmCachePrefetchPages(pObSystemProcess, pObSet);
    while((va = ObVSet_Pop(pObSet))) {
        VmmReadEx(pObSystemProcess, va - 0x10, pbMm, 0x100, &cbRead, VMM_FLAG_FORCECACHE_READ);
        if((*(PDWORD)(pbMm + 4) == '  mM') && (*(PBYTE)(pbMm + 0x10 + 0xcc) & 0x40)) {
            ctxVmm->kernel.MemCompress.dwPageFileNumber = (*(PBYTE)(pbMm + 0x10 + 0xcc) & 0x0f);
            goto finish;
        }
    }
    vmmprintfv_fn("WARN! did not find virtual store number - fallback to default.\n");
finish:
    LocalFree(pb);
    Ob_DECREF(pObSystemProcess);
    Ob_DECREF(pObSet);
}

/*
* Locate SmGlobals in 1st page of ntoskrnl.exe!CACHEALI section by looking for
* pointers to SMKM_STORE_METADATA (pool hdr: 'SmSa').
*     SMGLOBALS (_SMKM_STORE_MGR)+000 = Smkm Metadata   (_SMKM sSmkm)
*         _SMKM: PTR[32] to _SMKM_STORE_METADATA: (pool hdr smSa)
*             _SMKM_STORE_METADATA: sizeof(_SMKM_STORE_METADATA) = 0x28
*                 +000 = PTR to SMKM_STORE
*                 +018 = PTR to EPROCESS
*     SMGLOBALS (_SMKM_STORE_MGR)+1C0 = KeyToStoreTree (B_TREE sGlobalTree)
* -- pSystemProcess
*/
VOID MmX64PageWin_MemCompress_InitializeLocateSMGLOBALS()
{
    BOOL f;
    BYTE pbPage[0x1000] = { 0 };
    DWORD i, dwSmsaPoolHdr = 0, cbRead;
    QWORD vaSmGlobals, vaSmsa, vaKeyToStoreTree;
    IMAGE_SECTION_HEADER oSectionHeader;
    PVMM_PROCESS pObSystemProcess = NULL;
    POB_VSET pObSet = NULL;
    EnterCriticalSection(&ctxVmm->MasterLock);
    if(ctxVmm->kernel.MemCompress.fInitialized || (ctxVmm->kernel.dwVersionBuild < 14393)) { goto finish; }
    // 1: Locate SmGlobals candidates in ntoskrnl.exe!CACHEALI section
    if(!(pObSystemProcess = VmmProcessGet(4))) { goto finish; }
    if(!(pObSet = ObVSet_New())) { goto finish; }
    if(!PE_SectionGetFromName(pObSystemProcess, ctxVmm->kernel.vaBase, "CACHEALI", &oSectionHeader)) {
        vmmprintfv_fn("CANNOT READ ntoskrnl.exe CACHEALI SECTION from PE header.\n");
        goto finish;
    }
    if(!VmmRead(pObSystemProcess, ctxVmm->kernel.vaBase + oSectionHeader.VirtualAddress, pbPage, 0x1000)) {
        vmmprintfv_fn("CANNOT READ ntoskrnl.exe CACHEALI SECTION.\n");
        goto finish;
    }
    for(i = 0; i < 0x1000; i += 8) {
        vaSmGlobals = ctxVmm->kernel.vaBase + oSectionHeader.VirtualAddress + i;
        vaSmsa = *(PQWORD)(pbPage + i);
        vaKeyToStoreTree = *(PQWORD)(pbPage + i + 0x1c0);
        f = VMM_KADDR64_PAGE(vaKeyToStoreTree) &&
            VMM_KADDR64_16(vaSmsa) &&
            (vaSmsa > 0xffff8fff'ffffffff);
        if(f) {
            ObVSet_Push(pObSet, vaSmGlobals);
            ObVSet_Push(pObSet, vaKeyToStoreTree);
            ObVSet_Push(pObSet, vaSmsa);
        }
    }
    // 2: Verify SMGLOBALS / _SMKM_STORE_METADATA (pool hdr: 'smSa')
    VmmCachePrefetchPages(pObSystemProcess, pObSet);
    while(ObVSet_Size(pObSet)) {
        vaSmsa = ObVSet_Pop(pObSet);
        vaKeyToStoreTree = ObVSet_Pop(pObSet);
        vaSmGlobals = ObVSet_Pop(pObSet);
        VmmReadEx(pObSystemProcess, vaSmsa - 12, (PBYTE)&dwSmsaPoolHdr, sizeof(DWORD), &cbRead, VMM_FLAG_FORCECACHE_READ);
        if(dwSmsaPoolHdr == 'aSms') {
            MmX64PageWin_MemCompress_Fuzz();
            ctxVmm->kernel.MemCompress.fValid = TRUE;
            ctxVmm->kernel.MemCompress.vaSmGlobals = vaSmGlobals;
            ctxVmm->kernel.MemCompress.vaKeyToStoreTree = vaKeyToStoreTree;
            MmX64PageWin_MemCompress_InitializeVirtualStorePageFileNumber();
            vmmprintfv("Windows 10 Memory Compression Initialize #1 - SmGlobals located at: %16llx Pf: %i \n", ctxVmm->kernel.MemCompress.vaSmGlobals, ctxVmm->kernel.MemCompress.dwPageFileNumber);
            break;
        }
    }
finish:
    LeaveCriticalSection(&ctxVmm->MasterLock);
    ctxVmm->kernel.MemCompress.fInitialized = TRUE;
    Ob_DECREF(pObSystemProcess);
    Ob_DECREF(pObSet);
}

//-----------------------------------------------------------------------------
// COMPRESSED STORE FUNCTIONALITY BELOW:
//-----------------------------------------------------------------------------

#define COMPRESS_ALGORITHM_INVALID      0
#define COMPRESS_ALGORITHM_NULL         1
#define COMPRESS_ALGORITHM_MSZIP        2
#define COMPRESS_ALGORITHM_XPRESS       3
#define COMPRESS_ALGORITHM_XPRESS_HUFF  4
#define COMPRESS_ALGORITHM_LZMS         5
#define COMPRESS_ALGORITHM_MAX          6
#define COMPRESS_RAW             (1 << 29)

typedef struct tdMMX64WINPAGED_CONTEXT {
    PVMM_PROCESS pProcess;
    PVMM_PROCESS pSystemProcess;
    PVMM_PROCESS pProcessMemCompress;
    // per page items
    struct {
        QWORD va;
        QWORD PTE;
        DWORD dwPageKey;
        DWORD iSmkm;                        // index into 32x32 array in SmGlobals/SMKM_STORE_METADATA
        QWORD vaSmkmStore;
        QWORD vaEPROCESS;
        QWORD vaOwnerEPROCESS;
        BYTE pbSmkm[0x2000];
        DWORD dwRegionKey;
        QWORD vaPageRecord;
        QWORD vaRegion;
        DWORD cbRegionOffset;
        DWORD cbCompressedData;
        BYTE pbCompressedData[0x1000];
    } e;
} MMX64WINPAGED_CONTEXT, *PMMX64WINPAGED_CONTEXT;

#define PAGE_FILE_NUMBER_FROM_PTE(pte)      ((pte >> (((ctxVmm->kernel.dwVersionBuild >= 17134) ? 12 : 1))) & 0x0f)
#define PAGE_FILE_OFFSET_FROM_PTE(pte)      ((pte >> 32) & ((!(pte & 0x10) && (ctxVmm->kernel.dwVersionBuild >= 17134)) ? 0xffffdfff : 0xffffffff))
#define PAGE_KEY_COMPRESSED_FROM_PTE(pte)   (DWORD)(((PAGE_FILE_NUMBER_FROM_PTE(pte) << 0x1c) | PAGE_FILE_OFFSET_FROM_PTE(pte)))

typedef struct td_SMKM_STORE_METADATA {
    QWORD vaSmkmStore;
    QWORD Reserved1[2];
    QWORD vaEPROCESS;
    QWORD Reserved2;
} _SMKM_STORE_METADATA;

typedef struct td_SMHP_CHUNK_METADATA {
    QWORD avaChunkPtr[32];
    QWORD Reserved1;
    DWORD dwBitValue;
    DWORD dwPageRecordsPerChunkMask;
    DWORD dwPageRecordSize;
    DWORD Reserved2;
    DWORD dwChunkPageHeaderSize;
} _SMHP_CHUNK_METADATA, *P_SMHP_CHUNK_METADATA;

typedef struct td_ST_PAGE_RECORD {
    DWORD Key;
    DWORD CompressedSize;
    DWORD NextKey;
} _ST_PAGE_RECORD, *P_ST_PAGE_RECORD;

BOOL MmX64PageWin_MemCompress_LogError(_In_ PMMX64WINPAGED_CONTEXT ctx, _In_ LPSTR sz)
{
    vmmprintfvv(
        "MmX64PageWin: FAIL: %s\n" \
        "  va= %016llx ep= %016llx pgk=%08x ism=%04x vas=%016llx \n" \
        "  pte=%016llx oep=%016llx rgk=%08x pid=%04x \n" \
        "  pgr=%016llx rgn=%016llx rgo=%08x cbc=%04x rga=%016llx\n",
        sz,
        ctx->e.va, ctx->e.vaEPROCESS, ctx->e.dwPageKey, ctx->e.iSmkm, ctx->e.vaSmkmStore,
        ctx->e.PTE, ctx->e.vaOwnerEPROCESS, ctx->e.dwRegionKey, ctx->pProcess->dwPID,
        ctx->e.vaPageRecord, ctx->e.vaRegion, ctx->e.cbRegionOffset, ctx->e.cbCompressedData, (ctx->e.vaRegion + ctx->e.cbRegionOffset)
    );
    return FALSE;
}

/*
* Retrieve the index of the 32x32 array in SmGlobals/SMKM_STORE_METADATA which
* points to the SmkmStore. The index is retrieved from the KeyToStoreTree BTree
* pointed by SmGlobals/SMKM_STORE_METADATA.
* -- ctx
* -- pwSmkmStoreIndex
* -- return
*/
_Success_(return)
BOOL MmX64PageWin_MemCompress1_SmkmStoreIndex(_In_ PMMX64WINPAGED_CONTEXT ctx)
{
    DWORD v;
    if(!MmX64PageWin_BTreeSearch(ctx->pSystemProcess, ctxVmm->kernel.MemCompress.vaKeyToStoreTree, ctx->e.dwPageKey, &v)) { return MmX64PageWin_MemCompress_LogError(ctx, "#11 BTreeSearch"); }
    if(v & 0x01000000) { return MmX64PageWin_MemCompress_LogError(ctx, "#12 InvalidValue"); }
    ctx->e.iSmkm = 0x3ff & v;
    return TRUE;
}

/*
* Retrieve the virtual address to the SmkmStore and the EPROCESS of the process
* by walking the 32x32 array in SmGlobals.
* -- ctx
* -- return
*/
_Success_(return)
BOOL MmX64PageWin_MemCompress2_SmkmStoreMetadata(_In_ PMMX64WINPAGED_CONTEXT ctx)
{
    QWORD va;
    _SMKM_STORE_METADATA MetaData;
    // 1: 1st level fetch virtual address to 2nd level of 32x32 array
    if(!MmX64PageWin_VmmRead(ctx->pSystemProcess, ctxVmm->kernel.MemCompress.vaSmGlobals + (ctx->e.iSmkm >> 5) * sizeof(QWORD), (PBYTE)&va, sizeof(QWORD))) { return MmX64PageWin_MemCompress_LogError(ctx, "#21 Read"); }
    if(!VMM_KADDR64_16(va)) { return MmX64PageWin_MemCompress_LogError(ctx, "#22 NoKADDR"); }
    // 2: 2nd fetch values (_SMKM_STORE_METADATA) from 2nd level of 32x32 array.
    if(!MmX64PageWin_VmmRead(ctx->pSystemProcess, va + (ctx->e.iSmkm & 0x1f) * sizeof(_SMKM_STORE_METADATA), (PBYTE)&MetaData, sizeof(_SMKM_STORE_METADATA))) { return MmX64PageWin_MemCompress_LogError(ctx, "#23 Read"); }
    if(MetaData.vaEPROCESS && !VMM_KADDR64_16(MetaData.vaEPROCESS)) { return MmX64PageWin_MemCompress_LogError(ctx, "#24 NoKADDR"); }
    if(!VMM_KADDR64_PAGE(MetaData.vaSmkmStore)) { return MmX64PageWin_MemCompress_LogError(ctx, "#25 NoKADDR"); }
    ctx->e.vaSmkmStore = MetaData.vaSmkmStore;
    ctx->e.vaEPROCESS = MetaData.vaEPROCESS;
    return TRUE;
}

/*
* Retrieve the SmkmStore and the PageRecord.
* -- ctx
* -- return
*/
_Success_(return)
BOOL MmX64PageWin_MemCompress3_SmkmStoreAndPageRecord(_In_ PMMX64WINPAGED_CONTEXT ctx)
{
    QWORD vaPageRecordArray;
    DWORD i, dwEncodedMetadata, iChunkPtr = 0, iChunkArray, dwPoolHdr = 0;
    P_SMHP_CHUNK_METADATA pc;
    PVMMWIN_MEMCOMPRESS_OFFSET po = &ctxVmm->kernel.MemCompress.O;
    // 1: Load SmkmStore
    if(!MmX64PageWin_VmmRead(ctx->pSystemProcess, ctx->e.vaSmkmStore, ctx->e.pbSmkm, sizeof(ctx->e.pbSmkm))) {
        return MmX64PageWin_MemCompress_LogError(ctx, "#31 ReadSmkmStore");
    }
    // 2: Validate
    if(!VMM_KADDR64_16(*(PQWORD)(ctx->e.pbSmkm + po->SMKM_STORE.PagesTree))) {
        return MmX64PageWin_MemCompress_LogError(ctx, "#32 PagesTreePtrNoKADDR");
    }
    if(COMPRESS_ALGORITHM_XPRESS != *(PWORD)(ctx->e.pbSmkm + po->SMKM_STORE.CompressionAlgorithm)) {
        return MmX64PageWin_MemCompress_LogError(ctx, "#33 InvalidCompressionAlgorithm");
    }
    // 3: Get region key
    if(!MmX64PageWin_BTreeSearch(ctx->pSystemProcess, *(PQWORD)(ctx->e.pbSmkm + po->SMKM_STORE.PagesTree), ctx->e.dwPageKey, &ctx->e.dwRegionKey)) {
        return MmX64PageWin_MemCompress_LogError(ctx, "#34 RegionKeyBTreeSearch");
    }
    // 4: Get page record and calculate:
    //    - chunk "encoded metadata"
    //    - index into chunk metadata array (= highest non-zero bit position of encoded_metadata)
    //    - index into chunk array (pointed to by chunk metadata array)
    pc = (P_SMHP_CHUNK_METADATA)(ctx->e.pbSmkm + po->SMKM_STORE.ChunkMetaData);
    dwEncodedMetadata = ctx->e.dwRegionKey >> (pc->dwBitValue & 0xff);
    for(i = 0; i < 32; i++) {
        if(!(dwEncodedMetadata >> i)) { break; }
        iChunkPtr = i;
    }
    iChunkArray = (1 << iChunkPtr) ^ dwEncodedMetadata;
    // 5: Validate and fetch page record address
    if(iChunkArray > 0x400) {
        return MmX64PageWin_MemCompress_LogError(ctx, "#35 ChunkArrayTooLarge");
    }
    if(!VMM_KADDR64_16(pc->avaChunkPtr[iChunkPtr])) {
        return MmX64PageWin_MemCompress_LogError(ctx, "#36 ChunkPtrNoKADDR");
    }
    if(!MmX64PageWin_VmmRead(ctx->pSystemProcess, pc->avaChunkPtr[iChunkPtr] - 12, (PBYTE)&dwPoolHdr, 4) || (dwPoolHdr != 'ABms')) {
        return MmX64PageWin_MemCompress_LogError(ctx, "#37 ChunkBadPoolHdr");
    }
    if(!MmX64PageWin_VmmRead(ctx->pSystemProcess, pc->avaChunkPtr[iChunkPtr] + 0x10ULL * iChunkArray, (PBYTE)&vaPageRecordArray, 8) || !VMM_KADDR64_PAGE(vaPageRecordArray)) {
        return MmX64PageWin_MemCompress_LogError(ctx, "#38 PageRecordArray");
    }
    ctx->e.vaPageRecord = vaPageRecordArray + pc->dwChunkPageHeaderSize + ((QWORD)pc->dwPageRecordSize * (ctx->e.dwRegionKey & pc->dwPageRecordsPerChunkMask));
    // 6: Get owner EPROCESS
    ctx->e.vaOwnerEPROCESS = *(PQWORD)(ctx->e.pbSmkm + po->SMKM_STORE.OwnerProcess);
    if(ctx->e.vaOwnerEPROCESS != ctxVmm->kernel.MemCompress.vaEPROCESS) {
        return MmX64PageWin_MemCompress_LogError(ctx, "#39 OwnerEPROCESS");
    }
    return TRUE;
}

/*
* Retrieve the region address / data containing the compressed process.
* -- ctx
* -- return
*/
_Success_(return)
BOOL MmX64PageWin_MemCompress4_CompressedRegionData(_In_ PMMX64WINPAGED_CONTEXT ctx)
{
    QWORD vaRegionPtr;
    DWORD dwRegionIndexMask, dwRegionIndex;
    _ST_PAGE_RECORD PageRecord;
    PVMMWIN_MEMCOMPRESS_OFFSET po = &ctxVmm->kernel.MemCompress.O;
    // 1: Read page record
    if(!MmX64PageWin_VmmRead(ctx->pSystemProcess, ctx->e.vaPageRecord, (PBYTE)&PageRecord, sizeof(PageRecord))) {
        return MmX64PageWin_MemCompress_LogError(ctx, "#41 ReadPageRecord");
    }
    if(PageRecord.Key == 0xffffffff) {
        return MmX64PageWin_MemCompress_LogError(ctx, "#42 InvalidPageRecord");
    }
    ctx->e.cbCompressedData = (PageRecord.CompressedSize == 0x1000) ? 0x1000 : PageRecord.CompressedSize & 0xfff;
    // 2: Get pointer to region
    dwRegionIndexMask = *(PDWORD)(ctx->e.pbSmkm + po->SMKM_STORE.RegionIndexMask) & 0xff;
    dwRegionIndex = PageRecord.Key >> dwRegionIndexMask;
    vaRegionPtr = *(PQWORD)(ctx->e.pbSmkm + po->SMKM_STORE.CompressedRegionPtrArray) + dwRegionIndex * sizeof(QWORD);
    // 3: Get region and offset
    if(!MmX64PageWin_VmmRead(ctx->pSystemProcess, vaRegionPtr, (PBYTE)&ctx->e.vaRegion, sizeof(QWORD))) {
        return MmX64PageWin_MemCompress_LogError(ctx, "#42 ReadRegionVA");
    }
    if(!ctx->e.vaRegion || (ctx->e.vaRegion & 0xffff8000'0000ffff)) {
        return MmX64PageWin_MemCompress_LogError(ctx, "#42 InvalidRegionVA");
    }
    ctx->e.cbRegionOffset = (PageRecord.Key & *(PDWORD)(ctx->e.pbSmkm + po->SMKM_STORE.RegionSizeMask)) << 4;
    return TRUE;
}

/*
* Decompress a compressed page
* -- ctx
* -- pbDecompressedPage
* -- return
*/
_Success_(return)
BOOL MmX64PageWin_MemCompress5_DecompressPage(_In_ PMMX64WINPAGED_CONTEXT ctx, _Out_writes_(4096) PBYTE pbDecompressedPage)
{
    DWORD cbDecompressed;
    // 1: Read compressed data
    if(!MmX64PageWin_VmmRead(ctx->pProcessMemCompress, ctx->e.vaRegion + ctx->e.cbRegionOffset, ctx->e.pbCompressedData, ctx->e.cbCompressedData)) {
        MmX64PageWin_MemCompress_LogError(ctx, "#51 Read");
        return FALSE;
    }
    // 2: Decompress data
    if(ctx->e.cbCompressedData == 0x1000) {
        memcpy(pbDecompressedPage, ctx->e.pbCompressedData, 0x1000);
    } else {
        if((VMM_STATUS_SUCCESS != ctxVmm->fn.RtlDecompressBuffer(COMPRESS_ALGORITHM_XPRESS, pbDecompressedPage, 0x1000, ctx->e.pbCompressedData, ctx->e.cbCompressedData, &cbDecompressed)) || (cbDecompressed != 0x1000)) {
            return MmX64PageWin_MemCompress_LogError(ctx, "#52 Decompress");
        }
    }
    return TRUE;
}

/*
* Decompress a page.
* -- pProcess
* -- pMEM
*/
VOID MmX64PageWin_MemCompress(_In_ PVMM_PROCESS pProcess, PMEM_IO_SCATTER_HEADER pMEM)
{
    BOOL f;
    PMMX64WINPAGED_CONTEXT ctx = NULL;
    PVMM_PROCESS pObSystemProcess = NULL, pObMemCompressProcess = NULL;
    QWORD tm = Statistics_CallStart();
    if(!(ctx = LocalAlloc(LMEM_ZEROINIT, sizeof(MMX64WINPAGED_CONTEXT)))) { return; }
    if(pMEM->pvReserved1) {
        ctx->e.va = ((PMEM_IO_SCATTER_HEADER)pMEM->pvReserved1)->qwA;
    }
    ctx->e.PTE = pMEM->qwA;
    ctx->e.dwPageKey = PAGE_KEY_COMPRESSED_FROM_PTE(ctx->e.PTE);
    f = (ctx->pProcess = pProcess) &&
        (ctx->pSystemProcess = pObSystemProcess = VmmProcessGet(4)) &&
        (ctx->pProcessMemCompress = pObMemCompressProcess = VmmProcessGet(ctxVmm->kernel.MemCompress.dwPid)) &&
        MmX64PageWin_MemCompress1_SmkmStoreIndex(ctx) &&
        MmX64PageWin_MemCompress2_SmkmStoreMetadata(ctx) &&
        MmX64PageWin_MemCompress3_SmkmStoreAndPageRecord(ctx) &&
        MmX64PageWin_MemCompress4_CompressedRegionData(ctx) &&
        MmX64PageWin_MemCompress5_DecompressPage(ctx, pMEM->pb);
    if(f) {
        pMEM->cb = 0x1000;
    }
    LocalFree(ctx);
    Ob_DECREF(pObSystemProcess);
    Ob_DECREF(pObMemCompressProcess);
    Statistics_CallEnd(STATISTICS_ID_VMM_PagedCompressedMemory, tm);
}

VOID MmX64PageWin_ReadScatterPaged(_In_ PVMM_PROCESS pProcess, _Inout_ PPMEM_IO_SCATTER_HEADER ppMEMsPaged, _In_ DWORD cpMEMsPaged)
{
    DWORD iPG;
    QWORD pte;
    PMEM_IO_SCATTER_HEADER pMEM;
    for(iPG = 0; iPG < cpMEMsPaged; iPG++) {
        pMEM = ppMEMsPaged[iPG];
        pte = pMEM->qwA;
        // no processing of physical, cached, pre-failed or non-paged entries
        if((pte & 0x01) || (pMEM->cb == 0x1000) || (QWORD)pMEM->pvReserved2) {
            continue;
        }
        // demand zero virtual memory
        if(!PAGE_FILE_NUMBER_FROM_PTE(pte) && !PAGE_FILE_OFFSET_FROM_PTE(pte)) {
            pMEM->cb = 0x1000;
            ZeroMemory(pMEM->pb, 0x1000);
            InterlockedIncrement64(&ctxVmm->stat.cPageReadSuccessDemandZero);
            continue;
        }
        // potentially compressed virtual memory
        if(ctxVmm->kernel.MemCompress.dwPageFileNumber == PAGE_FILE_NUMBER_FROM_PTE(pte)) {
            if(!ctxVmm->kernel.MemCompress.fValid && !ctxVmm->kernel.MemCompress.fInitialized) {
                MmX64PageWin_MemCompress_InitializeLocateSMGLOBALS();
            }
            if(ctxVmm->kernel.MemCompress.fValid) {
                MmX64PageWin_MemCompress(pProcess, pMEM);
                if(pMEM->cb == 0x1000) {
                    InterlockedIncrement64(&ctxVmm->stat.cPageReadSuccessCompressed);
                } else {
                    ObVSet_Push(ctxVmm->Cache.PAGING_FAILED, pte);
                    InterlockedIncrement64(&ctxVmm->stat.cPageReadFailedCompressed);
                }
                continue;
            }
        }
        InterlockedIncrement64(&ctxVmm->stat.cPageReadFailed);
    }
}
