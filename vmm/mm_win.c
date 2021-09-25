// mm_win.c : implementation of functionality related to the windows paging subsystem.
//
// (c) Ulf Frisk, 2019-2021
// Author: Ulf Frisk, pcileech@frizk.net
//
#include "vmm.h"
#include "mm.h"
#include "pdb.h"
#include "pe.h"
#include "statistics.h"
#include "util.h"

#define MM_LOOP_PROTECT_ADD(flags)                  ((flags & ~0x00ff0000) | ((((flags >> 16) & 0xff) + 1) << 16))
#define MM_LOOP_PROTECT_MAX(flags)                  (((flags >> 16) & 0xff) > 4)

#define PTE_SWIZZLE_BIT                             0x10        // nt!_MMPTE_SOFTWARE.SwizzleBit
#define PTE_SWIZZLE_MASK                            (((PMMWIN_CONTEXT)ctxVmm->pMmContext)->MemCompress.dwInvalidPteMask)

#define MMWINX86_PTE_IS_HARDWARE(pte)               (pte & 0x01)
#define MMWINX86_PTE_TRANSITION(pte)                (((pte & 0x0c01) == 0x0800) ? ((pte & 0xfffff000) | 0x005) : 0)
#define MMWINX86_PTE_PROTOTYPE(pte)                 (((pte & 0x00000407) == 0x00000400) ? (0x80000000 | ((pte >> 1) & 0x7ffffc00) | ((pte << 1) & 0x3ff)) : 0)
#define MMWINX86_PTE_PAGE_FILE_NUMBER(pte)          ((pte >> 1) & 0x0f)
#define MMWINX86_PTE_PAGE_FILE_OFFSET(pte)          (pte >> 12)

#define MMWINX86PAE_PTE_IS_HARDWARE(pte)            (pte & 0x01)
#define MMWINX86PAE_PTE_TRANSITION(pte)             (((pte & 0x0c01) == 0x0800) ? ((pte & 0x0000003ffffff000) | 0x005) : 0)
#define MMWINX86PAE_PTE_PROTOTYPE(pte)              (((pte & 0x8000000700000401) == 0x8000000000000400) ? (pte >> 32) : 0)
#define MMWINX86PAE_PTE_PAGE_FILE_NUMBER(pte)       ((pte >> (((ctxVmm->kernel.dwVersionBuild >= 17134) ? 12 : 1))) & 0x0f)
#define MMWINX86PAE_PTE_PAGE_FILE_OFFSET(pte)       ((pte >> 32) ^ (!(pte & PTE_SWIZZLE_BIT) ? PTE_SWIZZLE_MASK : 0))
#define MMWINX86PAE_PTE_PAGE_KEY_COMPRESSED(pte)    (DWORD)(((MMWINX86PAE_PTE_PAGE_FILE_NUMBER(pte) << 0x1c) | MMWINX86PAE_PTE_PAGE_FILE_OFFSET(pte)))

#define MMWINX64_PTE_IS_HARDWARE(pte)               (pte & 0x01)
#define MMWINX64_PTE_TRANSITION(pte)                (((pte & 0x0c01) == 0x0800) ? ((pte & 0xffffdffffffff000) | 0x005) : 0)
#define MMWINX64_PTE_PROTOTYPE(pte)                 (((pte & 0x8000000000070401) == 0x8000000000000400) ? ((pte >> 16) | 0xffff000000000000) : 0)
#define MMWINX64_PTE_PAGE_FILE_NUMBER(pte)          ((pte >> (((ctxVmm->kernel.dwVersionBuild >= 17134) ? 12 : 1))) & 0x0f)
#define MMWINX64_PTE_PAGE_FILE_OFFSET(pte)          ((pte >> 32) ^ (!(pte & PTE_SWIZZLE_BIT) ? PTE_SWIZZLE_MASK : 0))
#define MMWINX64_PTE_PAGE_KEY_COMPRESSED(pte)       (DWORD)(((MMWINX64_PTE_PAGE_FILE_NUMBER(pte) << 0x1c) | MMWINX64_PTE_PAGE_FILE_OFFSET(pte)))

typedef struct tdMMWIN_MEMCOMPRESS_OFFSET {
    BOOL _fValid;
    BOOL _fProcessedTry;
    WORD _Size;
    struct {
        WORD PagesTree;
        WORD SmkmStore;
        WORD ChunkMetaData;
        WORD RegionSizeMask;
        WORD RegionIndexMask;
        WORD CompressionAlgorithm;
        WORD CompressedRegionPtrArray;
        WORD OwnerProcess;
    } SMKM_STORE;
} MMWIN_MEMCOMPRESS_OFFSET, *PMMWIN_MEMCOMPRESS_OFFSET;

typedef struct tdMMWIN_MEMCOMPRESS_CONTEXT {
    QWORD vaEPROCESS;
    DWORD dwPid;
    DWORD dwPageFileNumber;
    DWORD dwInvalidPteMask;     // top 32-bits of nt!MiState->Hardware.InvalidPteMask
    BOOL fValid;
    BOOL fInitialized;
    QWORD vaSmGlobals;
    QWORD vaKeyToStoreTree;
    MMWIN_MEMCOMPRESS_OFFSET O;
} MMWIN_MEMCOMPRESS_CONTEXT, *PMMWIN_MEMCOMPRESS_CONTEXT;

typedef struct tdMMWIN_CONTEXT {
    CRITICAL_SECTION Lock;
    FILE *pPageFile[10];
    MMWIN_MEMCOMPRESS_CONTEXT MemCompress;
} MMWIN_CONTEXT, *PMMWIN_CONTEXT;

//-----------------------------------------------------------------------------
// BTREE FUNCTIONALITY BELOW:
//-----------------------------------------------------------------------------

typedef struct td_BTREE_LEAF_ENTRY {
    DWORD k;
    DWORD v;
} _BTREE_LEAF_ENTRY;

typedef struct td_BTREE_NODE_ENTRY32 {
    DWORD k;
    DWORD vaLeaf;
} _BTREE_NODE_ENTRY32;

typedef struct td_BTREE_NODE_ENTRY64 {
    DWORD k;
    DWORD _Filler;
    QWORD vaLeaf;
} _BTREE_NODE_ENTRY64;

typedef struct td_BTREE32 {
    WORD cEntries;
    BYTE  cLevel;
    BYTE  fLeaf;
    DWORD vaLeftChild;
    union {
        _BTREE_LEAF_ENTRY LeafEntries[0];
        _BTREE_NODE_ENTRY32 NodeEntries[0];
    };
} _BTREE32, *P_BTREE32;

typedef struct td_BTREE64 {
    WORD cEntries;
    BYTE  cLevel;
    BYTE  fLeaf;
    DWORD _Filler;
    QWORD vaLeftChild;
    union {
        _BTREE_LEAF_ENTRY LeafEntries[0];
        _BTREE_NODE_ENTRY64 NodeEntries[0];
    };
} _BTREE64, *P_BTREE64;

_Success_(return)
BOOL MmWin_BTree32_Search(_In_ PVMM_PROCESS pProcess, _In_ QWORD vaTree, _In_ DWORD dwKey, _Out_ PDWORD pdwValue, _In_ QWORD fVmmRead);

_Success_(return)
BOOL MmWin_BTree64_Search(_In_ PVMM_PROCESS pProcess, _In_ QWORD vaTree, _In_ DWORD dwKey, _Out_ PDWORD pdwValue, _In_ QWORD fVmmRead);

_Success_(return)
BOOL MmWin_BTree32_SearchLeaf(_In_ PVMM_PROCESS pSystemProcess, _In_ P_BTREE32 pT, _In_ DWORD dwKey, _Out_ PDWORD pdwValue, _In_ QWORD fVmmRead)
{
    BOOL fSearchPreFail = FALSE;
    DWORD i, dwSearchStep, dwSearchIndex = 1, dwSearchCount = 0;
    // 2: search tree for leaf
    for(i = 1; (i < 12) && ((pT->cEntries - 1) >> i); i++);
    dwSearchIndex = dwSearchStep = min(1 << (i - 1), pT->cEntries);
    while(TRUE) {
        dwSearchCount++;
        dwSearchStep = dwSearchStep >> 1;
        if(pT->LeafEntries[dwSearchIndex].k == dwKey) {
            *pdwValue = pT->LeafEntries[dwSearchIndex].v;
            return TRUE;
        }
        if(dwSearchStep == 0) {
            if(fSearchPreFail) {
                return FALSE;
            }
            fSearchPreFail = TRUE;
            dwSearchStep = 1;
        }
        if(pT->LeafEntries[dwSearchIndex].k < dwKey) {
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
BOOL MmWin_BTree64_SearchLeaf(_In_ PVMM_PROCESS pSystemProcess, _In_ P_BTREE64 pT, _In_ DWORD dwKey, _Out_ PDWORD pdwValue, _In_ QWORD fVmmRead)
{
    BOOL fSearchPreFail = FALSE;
    DWORD i, dwSearchStep, dwSearchIndex = 1;
    // 2: search tree for leaf
    for(i = 1; (i < 12) && ((pT->cEntries - 1) >> i); i++);
    dwSearchIndex = dwSearchStep = min(1 << (i - 1), pT->cEntries);
    while(TRUE) {
        dwSearchStep = dwSearchStep >> 1;
        if(pT->LeafEntries[dwSearchIndex].k == dwKey) {
            *pdwValue = pT->LeafEntries[dwSearchIndex].v;
            return TRUE;
        }
        if(dwSearchStep == 0) {
            if(fSearchPreFail) {
                return FALSE;
            }
            fSearchPreFail = TRUE;
            dwSearchStep = 1;
        }
        if(pT->LeafEntries[dwSearchIndex].k < dwKey) {
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
BOOL MmWin_BTree32_SearchNode(_In_ PVMM_PROCESS pSystemProcess, _In_ P_BTREE32 pT, _In_ DWORD dwKey, _Out_ PDWORD pdwValue, _In_ QWORD fVmmRead)
{
    BOOL fSearchPreFail = FALSE;
    DWORD i, dwSearchStep, dwSearchIndex = 1;
    QWORD vaSubTree = 0;
    // 2: search tree for entry
    for(i = 1; (i < 12) && ((pT->cEntries - 1) >> i); i++);
    dwSearchIndex = dwSearchStep = min(1 << (i - 1), pT->cEntries - 1);
    while(TRUE) {
        dwSearchStep = dwSearchStep >> 1;
        if((dwSearchStep == 0) && !fSearchPreFail) {
            fSearchPreFail = TRUE;
            dwSearchStep = 1;
        }
        if((dwSearchStep == 0) || ((pT->NodeEntries[dwSearchIndex].k <= dwKey) && ((dwSearchIndex + 1 == pT->cEntries) || (pT->NodeEntries[dwSearchIndex + 1].k > dwKey)))) {
            if((dwSearchIndex == 0) && (pT->NodeEntries[0].k > dwKey)) {
                vaSubTree = pT->vaLeftChild;
            } else {
                vaSubTree = pT->NodeEntries[dwSearchIndex].vaLeaf;
            }
            return MmWin_BTree32_Search(pSystemProcess, vaSubTree, dwKey, pdwValue, MM_LOOP_PROTECT_ADD(fVmmRead));
        } else if(pT->NodeEntries[dwSearchIndex].k < dwKey) {
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
BOOL MmWin_BTree64_SearchNode(_In_ PVMM_PROCESS pSystemProcess, _In_ P_BTREE64 pT, _In_ DWORD dwKey, _Out_ PDWORD pdwValue, _In_ QWORD fVmmRead)
{
    BOOL fSearchPreFail = FALSE;
    DWORD i, dwSearchStep, dwSearchIndex = 1, dwSearchCount = 0;
    QWORD vaSubTree = 0;
    // 2: search tree for entry
    for(i = 1; (i < 12) && ((pT->cEntries - 1) >> i); i++);
    dwSearchIndex = dwSearchStep = min(1 << (i - 1), pT->cEntries - 1);
    while(TRUE) {
        dwSearchCount++;
        dwSearchStep = dwSearchStep >> 1;
        if((dwSearchStep == 0) && !fSearchPreFail) {
            fSearchPreFail = TRUE;
            dwSearchStep = 1;
        }
        if((dwSearchStep == 0) || ((pT->NodeEntries[dwSearchIndex].k <= dwKey) && ((dwSearchIndex + 1 == pT->cEntries) || (pT->NodeEntries[dwSearchIndex + 1].k > dwKey)))) {
            if((dwSearchIndex == 0) && (pT->NodeEntries[0].k > dwKey)) {
                vaSubTree = pT->vaLeftChild;
            } else {
                vaSubTree = pT->NodeEntries[dwSearchIndex].vaLeaf;
            }
            return MmWin_BTree64_Search(pSystemProcess, vaSubTree, dwKey, pdwValue, MM_LOOP_PROTECT_ADD(fVmmRead));
        } else if(pT->NodeEntries[dwSearchIndex].k < dwKey) {
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
BOOL MmWin_BTree32_Search(_In_ PVMM_PROCESS pProcess, _In_ QWORD vaTree, _In_ DWORD dwKey, _Out_ PDWORD pdwValue, _In_ QWORD fVmmRead)
{
    BOOL f;
    BYTE pbBuffer[0x1000];
    P_BTREE32 pT = (P_BTREE32)pbBuffer;
    // 1: read tree
    f = !MM_LOOP_PROTECT_MAX(fVmmRead) &&
        VMM_KADDR32_PAGE(vaTree) &&
        VmmRead2(pProcess, vaTree, pbBuffer, 0x1000, fVmmRead) &&
        pT->cEntries;
    if(!f) { return FALSE; }
    if(pT->fLeaf) {
        // Leaf
        if(pT->cEntries > 0x1ff) { return FALSE; }
        return MmWin_BTree32_SearchLeaf(pProcess, pT, dwKey, pdwValue, fVmmRead);
    } else {
        // Node
        if(pT->cEntries > 0x1ff) { return FALSE; }
        return MmWin_BTree32_SearchNode(pProcess, pT, dwKey, pdwValue, fVmmRead);
    }
}

_Success_(return)
BOOL MmWin_BTree64_Search(_In_ PVMM_PROCESS pProcess, _In_ QWORD vaTree, _In_ DWORD dwKey, _Out_ PDWORD pdwValue, _In_ QWORD fVmmRead)
{
    BOOL f;
    BYTE pbBuffer[0x1000];
    P_BTREE64 pT = (P_BTREE64)pbBuffer;
    // 1: read tree
    f = !MM_LOOP_PROTECT_MAX(fVmmRead) &&
        VMM_KADDR64_PAGE(vaTree) &&
        VmmRead2(pProcess, vaTree, pbBuffer, 0x1000, fVmmRead) &&
        pT->cEntries;
    if(!f) { return FALSE; }
    if(pT->fLeaf) {
        // Leaf
        if(pT->cEntries > 0x1ff) { return FALSE; }
        return MmWin_BTree64_SearchLeaf(pProcess, pT, dwKey, pdwValue, fVmmRead);
    } else {
        // Node
        if(pT->cEntries > 0xff) { return FALSE; }
        return MmWin_BTree64_SearchNode(pProcess, pT, dwKey, pdwValue, fVmmRead);
    }
}

_Success_(return)
BOOL MmWin_BTree_Search(_In_ PVMM_PROCESS pProcess, _In_ QWORD vaTree, _In_ DWORD dwKey, _Out_ PDWORD pdwValue, _In_ QWORD fVmmRead)
{
    return ctxVmm->f32 ? MmWin_BTree32_Search(pProcess, vaTree, dwKey, pdwValue, fVmmRead) : MmWin_BTree64_Search(pProcess, vaTree, dwKey, pdwValue, fVmmRead);
}


//-----------------------------------------------------------------------------
// MEMCOMPRESSION INITIALIZATION FUNCTIONALITY BELOW:
//-----------------------------------------------------------------------------

/*
* Initialize offsets in _SMKM_STORE / _ST_STORE / _ST_DATA_MGR
*/
VOID MmWin_MemCompress_InitializeOffsets32()
{
    PMMWIN_MEMCOMPRESS_OFFSET po = &((PMMWIN_CONTEXT)ctxVmm->pMmContext)->MemCompress.O;
    po->SMKM_STORE.PagesTree = 0x38 + 0x0;                  // static = ok
    po->SMKM_STORE.ChunkMetaData = 0x38 + 0x6C;             // static = ok
    po->SMKM_STORE.SmkmStore = 0x38 + 0x1C0;                // static = ok
    po->SMKM_STORE.RegionSizeMask = 0x38 + 0x1C4;           // static = ok
    po->SMKM_STORE.RegionIndexMask = 0x38 + 0x1C8;          // static = ok
    po->SMKM_STORE.CompressionAlgorithm = 0x38 + 0x224;     // 1709+
    po->SMKM_STORE.CompressedRegionPtrArray = 0x1184;       // 1709+
    po->SMKM_STORE.OwnerProcess = 0x125c;                   // 2004+
    if(ctxVmm->kernel.dwVersionBuild <= 18363) {            // 1709-1909
        po->SMKM_STORE.OwnerProcess = 0x1254;
    }
    if(ctxVmm->kernel.dwVersionBuild == 15063) {            // 1703
        po->SMKM_STORE.CompressionAlgorithm = 0x38 + 0x220;
        po->SMKM_STORE.CompressedRegionPtrArray = 0x1174;
        po->SMKM_STORE.OwnerProcess = 0x1244;
    }
    if(ctxVmm->kernel.dwVersionBuild == 14393) {            // 1607
        po->SMKM_STORE.CompressionAlgorithm = 0x38 + 0x220;
        po->SMKM_STORE.CompressedRegionPtrArray = 0x1124;
        po->SMKM_STORE.OwnerProcess = 0x1204;
    }
    po->_Size = po->SMKM_STORE.OwnerProcess + 8;
    po->_fProcessedTry = TRUE;
    po->_fValid = TRUE;
}

VOID MmWin_MemCompress_InitializeOffsets64()
{
    PMMWIN_MEMCOMPRESS_OFFSET po = &((PMMWIN_CONTEXT)ctxVmm->pMmContext)->MemCompress.O;
    po->SMKM_STORE.PagesTree = 0x50 + 0x0;                  // static = ok
    po->SMKM_STORE.ChunkMetaData = 0x50 + 0xC0;             // static = ok
    po->SMKM_STORE.SmkmStore = 0x50 + 0x320;                // static = ok
    po->SMKM_STORE.RegionSizeMask = 0x50 + 0x328;           // static = ok
    po->SMKM_STORE.RegionIndexMask = 0x50 + 0x32C;          // static = ok
    po->SMKM_STORE.CompressionAlgorithm = 0x50 + 0x3E0;     // 1709+
    po->SMKM_STORE.CompressedRegionPtrArray = 0x1848;       // 1709+
    po->SMKM_STORE.OwnerProcess = 0x19B8;                   // 2004+
    if(ctxVmm->kernel.dwVersionBuild <= 18363) {            // 1709-1909
        po->SMKM_STORE.OwnerProcess = 0x19A8;
    }
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
* Older version of InitializeVirtualStorePageFileNumber() which has no reliance
* on debug symbols.
* NB! THIS DOES NOT WORK ON MORE RECENT WINDOWS VERSION (SERVER2022/WIN11).
*/
VOID MmWin_MemCompress_InitializeVirtualStorePageFileNumber_Old(_Inout_ PMMWIN_CONTEXT ctx, _In_ PVMM_PROCESS pSystemProcess)
{
    BOOL f;
    BYTE pbMm[0x100] = { 0 };
    QWORD j, va = 0;
    DWORD i, cb, cbRead, oPoolHdr, oPfNum;
    PBYTE pb = NULL;
    IMAGE_SECTION_HEADER oSectionHeader;
    POB_SET pObSet = NULL;
    ctx->MemCompress.dwPageFileNumber = 2;
    // 1: SetUp and locate nt!MiSystemPartition/nt!.data
    if(!(pObSet = ObSet_New())) { goto finish; }
    if(!PE_SectionGetFromName(pSystemProcess, ctxVmm->kernel.vaBase, ".data", &oSectionHeader)) {
        vmmprintfv_fn("CANNOT READ ntoskrnl.exe .data SECTION from PE header.\n");
        goto finish;
    }
    if(oSectionHeader.Misc.VirtualSize > 0x00100000) { goto finish; }
    va = ctxVmm->kernel.vaBase + oSectionHeader.VirtualAddress;
    cb = oSectionHeader.Misc.VirtualSize;
    if(!(pb = LocalAlloc(0, cb))) { goto finish; }
    if(!VmmRead(pSystemProcess, va, pb, cb)) {
        vmmprintfv_fn("CANNOT READ ntoskrnl.exe .data SECTION.\n");
        goto finish;
    }
    if(ctxVmm->f32) {
        // 32-bit
        // 2: Search for candidate pointers
        for(i = 0; i < cb - 0x90; i += 4) {
            f = (*(PDWORD)(pb + i + 0x004) == 1) &&
                *(PDWORD)(pb + i + 0x000) &&
                (*(PDWORD)(pb + i + 0x000) < 16) &&
                VMM_KADDR32_8(*(PDWORD)(pb + i + 0x008)) &&
                VMM_KADDR32_8(*(PDWORD)(pb + i + 0x00c));
            if(f) {
                for(j = 0; j < *(PDWORD)(pb + i + 0x000); j++) {
                    va = *(PDWORD)(pb + i + 0x008 + j * 4);
                    if(VMM_KADDR32_8(va)) {
                        ObSet_Push(pObSet, va);
                    }
                }
            }
        }
        oPoolHdr = 12;
        oPfNum = 0x74;
    } else {
        // 64-bit
        // 2: Search for candidate pointers
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
                        ObSet_Push(pObSet, va);
                    }
                }
            }
        }
        oPoolHdr = 4;
        oPfNum = 0xcc;
    }
    // 3: Verify nt!dt _MMPAGING_FILE by looking at pool header and VirtualStorePagefile bit
    VmmCachePrefetchPages(pSystemProcess, pObSet, 0);
    while((va = ObSet_Pop(pObSet))) {
        VmmReadEx(pSystemProcess, va - 0x10, pbMm, 0x100, &cbRead, VMM_FLAG_FORCECACHE_READ);
        if((*(PDWORD)(pbMm + oPoolHdr) == '  mM') && (*(PBYTE)(pbMm + 0x10 + oPfNum) & 0x40)) {
            ctx->MemCompress.dwPageFileNumber = (*(PBYTE)(pbMm + 0x10 + oPfNum) & 0x0f);
            goto finish;
        }
    }
    vmmprintfv_fn("WARN! did not find virtual store number - fallback to default.\n");
finish:
    LocalFree(pb);
    Ob_DECREF(pObSet);
}

/*
* Retrieve the page file number of the virtual store. This will be '2' on a
* standard system, but if paging are configured in a non-standard way this
* number may differ.
* ---
* nt!MiSystemPartition(dt:_MI_PARTITION).Vp(dt:_MI_VISIBLE_PARTITION).
* .PagingFile[0-15](dt:PTR:_MMPAGING_FILE)
* ---
* The page file number and the virtual store flag is contained at same bits
* in all known versions with MemCompression as per below (for 64-bit):
* dt nt!_MMPAGING_FILE
*  +0x0cc PageFileNumber   : Pos 0, 4 Bits
*  +0x0cc VirtualStorePagefile : Pos 6, 1 Bit
* If this function fails it will automatically fallback to default number 2.
*/
VOID MmWin_MemCompress_InitializeVirtualStorePageFileNumber()
{
    BOOL f;
    PVMM_PROCESS pObSystemProcess = NULL;
    QWORD qw, va, vaMiState, iPfNum;
    DWORD oMiStateHardware, oMiStateHardwareInvalidPteMask;
    PMMWIN_CONTEXT ctx = (PMMWIN_CONTEXT)ctxVmm->pMmContext;
    DWORD oVp, oPagingFile, oPageFileNumber;
    POB_SET pObSet = NULL;
    BYTE pb[16 * sizeof(QWORD)], bFlags;
    // 1: Prepare
    if(!(pObSet = ObSet_New())) { goto finish; }
    if(!(pObSystemProcess = VmmProcessGet(4))) { goto finish; }
    // 2: Set InvalidPteMask
    if(ctxVmm->kernel.dwVersionBuild >= 15063) {
        f = PDB_GetSymbolAddress(PDB_HANDLE_KERNEL, "MiState", &vaMiState) &&
            PDB_GetTypeChildOffset(PDB_HANDLE_KERNEL, "_MI_SYSTEM_INFORMATION", "Hardware", &oMiStateHardware) &&
            PDB_GetTypeChildOffset(PDB_HANDLE_KERNEL, "_MI_HARDWARE_STATE", "InvalidPteMask", &oMiStateHardwareInvalidPteMask) &&
            VmmRead(pObSystemProcess, vaMiState + oMiStateHardware + oMiStateHardwareInvalidPteMask, (PBYTE)&qw, 8);
        ctx->MemCompress.dwInvalidPteMask = f ? (qw >> 32) : 0x00002000;     // if fail: [0x00002000 = most common on Intel]
    }
    // 3: fetch virtual store # via pdb symbols
    f = PDB_GetSymbolAddress(PDB_HANDLE_KERNEL, "MiSystemPartition", &va) &&
        PDB_GetTypeChildOffset(PDB_HANDLE_KERNEL, "_MI_PARTITION", "Vp", &oVp) &&
        PDB_GetTypeChildOffset(PDB_HANDLE_KERNEL, "_MI_VISIBLE_PARTITION", "PagingFile", &oPagingFile) &&
        PDB_GetTypeChildOffset(PDB_HANDLE_KERNEL, "_MMPAGING_FILE", "PageFileNumber", &oPageFileNumber) &&
        VmmRead(pObSystemProcess, va + oVp + oPagingFile, pb, 16 * sizeof(QWORD));
    if(!f) { goto fail; }
    for(iPfNum = 0; iPfNum < 16; iPfNum++) {
        va = ctxVmm->f32 ? *(PDWORD)(pb + iPfNum * 4) : *(PQWORD)(pb + iPfNum * 8);
        if(VMM_KADDR_8_16(va)) {
            ObSet_Push(pObSet, va + oPageFileNumber);
        }
    }
    VmmCachePrefetchPages(pObSystemProcess, pObSet, 0);
    while((va = ObSet_Pop(pObSet))) {
        if(VmmRead2(pObSystemProcess, va, &bFlags, 1, VMM_FLAG_FORCECACHE_READ)) {
            if(bFlags & 0x40) {
                ctx->MemCompress.dwPageFileNumber = bFlags & 0x0f;
                goto finish;
            }
        }
    }
fail:
    MmWin_MemCompress_InitializeVirtualStorePageFileNumber_Old(ctx, pObSystemProcess);
finish:
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
VOID MmWin_MemCompress_Initialize_NoPdb64()
{
    BOOL f, f32 = ctxVmm->f32;
    BYTE pbPage[0x1000] = { 0 };
    DWORD i, dwSmsaPoolHdr = 0, cbRead;
    QWORD vaSmGlobals, vaSmsa, vaKeyToStoreTree;
    IMAGE_SECTION_HEADER oSectionHeader;
    PVMM_PROCESS pObSystemProcess = NULL;
    POB_SET pObSet = NULL;
    PMMWIN_CONTEXT ctx = (PMMWIN_CONTEXT)ctxVmm->pMmContext;
    EnterCriticalSection(&ctxVmm->LockMaster);
    if(ctx->MemCompress.fInitialized || (ctxVmm->kernel.dwVersionBuild < 14393)) { goto finish; }
    // 1: Locate SmGlobals candidates in ntoskrnl.exe!CACHEALI section
    if(!(pObSystemProcess = VmmProcessGet(4))) { goto finish; }
    if(!(pObSet = ObSet_New())) { goto finish; }
    if(!PE_SectionGetFromName(pObSystemProcess, ctxVmm->kernel.vaBase, "CACHEALI", &oSectionHeader)) {
        vmmprintfv_fn("CANNOT READ ntoskrnl.exe CACHEALI SECTION from PE header.\n");
        goto finish;
    }
    if(!VmmRead(pObSystemProcess, ctxVmm->kernel.vaBase + oSectionHeader.VirtualAddress, pbPage, 0x1000)) {
        vmmprintfv_fn("CANNOT READ ntoskrnl.exe CACHEALI SECTION.\n");
        goto finish;
    }
    // 2: Verify SMGLOBALS / _SMKM_STORE_METADATA (pool hdr: 'smSa')
    for(i = 0; i < 0x1000 - 0x1c0 - sizeof(QWORD); i += 8) {
        vaSmGlobals = ctxVmm->kernel.vaBase + oSectionHeader.VirtualAddress + i;
        vaSmsa = *(PQWORD)(pbPage + i);
        vaKeyToStoreTree = *(PQWORD)(pbPage + i + 0x1c0);
        f = VMM_KADDR64_PAGE(vaKeyToStoreTree) &&
            VMM_KADDR64_16(vaSmsa);
        if(f) {
            ObSet_Push(pObSet, vaSmGlobals);
            ObSet_Push(pObSet, vaKeyToStoreTree);
            ObSet_Push(pObSet, vaSmsa);
        }
    }
    // 2: Verify SMGLOBALS / _SMKM_STORE_METADATA (pool hdr: 'smSa')
    VmmCachePrefetchPages(pObSystemProcess, pObSet, 0);
    while(ObSet_Size(pObSet)) {
        vaSmsa = ObSet_Pop(pObSet);
        vaKeyToStoreTree = ObSet_Pop(pObSet);
        vaSmGlobals = ObSet_Pop(pObSet);
        VmmReadEx(pObSystemProcess, vaSmsa - 12, (PBYTE)&dwSmsaPoolHdr, sizeof(DWORD), &cbRead, VMM_FLAG_FORCECACHE_READ);
        if(dwSmsaPoolHdr == 'aSms') {
            MmWin_MemCompress_InitializeOffsets64();
            ctx->MemCompress.fValid = TRUE;
            ctx->MemCompress.vaSmGlobals = vaSmGlobals;
            ctx->MemCompress.vaKeyToStoreTree = vaKeyToStoreTree;
            vmmprintfv("Windows 10 Memory Compression Initialize #1 - SmGlobals located at: %16llx Pf: %i \n", ctx->MemCompress.vaSmGlobals, ctx->MemCompress.dwPageFileNumber);
            break;
        }
    }
finish:
    LeaveCriticalSection(&ctxVmm->LockMaster);
    ctx->MemCompress.fInitialized = TRUE;
    Ob_DECREF(pObSystemProcess);
    Ob_DECREF(pObSet);
}

VOID MmWin_MemCompress_Initialize()
{
    DWORD vaKeyToStoreTree32;
    QWORD vaKeyToStoreTree64;
    PVMM_PROCESS pObSystemProcess = NULL, pObProcess = NULL;
    PMMWIN_CONTEXT ctx = (PMMWIN_CONTEXT)ctxVmm->pMmContext;
    if(ctxVmm->kernel.dwVersionMajor < 10) { goto fail; }
    MmWin_MemCompress_InitializeVirtualStorePageFileNumber();
    // Retrieve MemCompression process PID and vaEPROCESS
    while((pObProcess = VmmProcessGetNext(pObProcess, 0))) {
        if((pObProcess->dwPPID == 4) && !memcmp("MemCompression", pObProcess->szName, 15)) {
            ctx->MemCompress.dwPid = pObProcess->dwPID;
            ctx->MemCompress.vaEPROCESS = pObProcess->win.EPROCESS.va;
        }
    }
    // Retrieve SmGlobals address
    if(!PDB_GetSymbolAddress(PDB_HANDLE_KERNEL, "SmGlobals", &ctx->MemCompress.vaSmGlobals)) {
        if(ctxVmm->tpMemoryModel == VMM_MEMORYMODEL_X64) {
            MmWin_MemCompress_Initialize_NoPdb64();
        }
        goto fail;
    }
    if(!(pObSystemProcess = VmmProcessGet(4))) { goto fail; }
    if(ctxVmm->f32) {
        MmWin_MemCompress_InitializeOffsets32();
        if(!VmmRead(pObSystemProcess, ctx->MemCompress.vaSmGlobals + 0x0f4, (PBYTE)&vaKeyToStoreTree32, sizeof(DWORD))) { goto fail; }
        if(!VMM_KADDR32_PAGE(vaKeyToStoreTree32)) { goto fail; }
        ctx->MemCompress.vaKeyToStoreTree = vaKeyToStoreTree32;
    } else {
        MmWin_MemCompress_InitializeOffsets64();
        if(!VmmRead(pObSystemProcess, ctx->MemCompress.vaSmGlobals + 0x1c0, (PBYTE)&vaKeyToStoreTree64, sizeof(QWORD))) { goto fail; }
        if(!VMM_KADDR64_PAGE(vaKeyToStoreTree64)) { goto fail; }
        ctx->MemCompress.vaKeyToStoreTree = vaKeyToStoreTree64;
    }
    ctx->MemCompress.fValid = TRUE;
fail:
    Ob_DECREF(pObSystemProcess);
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
#define COMPRESS_RAW                    (1 << 29)

typedef struct tdMMWINX64_COMPRESS_CONTEXT {
    QWORD fVmmRead;
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
} MMWINX64_COMPRESS_CONTEXT, *PMMWINX64_COMPRESS_CONTEXT;

typedef struct td_SMKM_STORE_METADATA32 {
    DWORD vaSmkmStore;
    DWORD Reserved1[2];
    DWORD vaEPROCESS;
    DWORD Reserved2;
} _SMKM_STORE_METADATA32;

typedef struct td_SMKM_STORE_METADATA64 {
    QWORD vaSmkmStore;
    QWORD Reserved1[2];
    QWORD vaEPROCESS;
    QWORD Reserved2;
} _SMKM_STORE_METADATA64;

typedef struct td_SMHP_CHUNK_METADATA32 {
    DWORD avaChunkPtr[32];
    QWORD Reserved1;
    DWORD dwBitValue;
    DWORD dwPageRecordsPerChunkMask;
    DWORD dwPageRecordSize;
    DWORD Reserved2;
    DWORD dwChunkPageHeaderSize;
} _SMHP_CHUNK_METADATA32, *P_SMHP_CHUNK_METADATA32;

typedef struct td_SMHP_CHUNK_METADATA64 {
    QWORD avaChunkPtr[32];
    QWORD Reserved1;
    DWORD dwBitValue;
    DWORD dwPageRecordsPerChunkMask;
    DWORD dwPageRecordSize;
    DWORD Reserved2;
    DWORD dwChunkPageHeaderSize;
} _SMHP_CHUNK_METADATA64, *P_SMHP_CHUNK_METADATA64;

typedef struct td_ST_PAGE_RECORD {
    DWORD Key;
    DWORD CompressedSize;
    DWORD NextKey;
} _ST_PAGE_RECORD, *P_ST_PAGE_RECORD;

BOOL MmWin_MemCompress_LogError(_In_ PMMWINX64_COMPRESS_CONTEXT ctx, _In_ LPSTR sz)
{
    vmmprintfvv(
        "MmWin_CompressedPage: FAIL: %s\n" \
        "  va= %016llx ep= %016llx pgk=%08x ism=%04x vas=%016llx \n" \
        "  pte=%016llx oep=%016llx rgk=%08x pid=%04x vat=%016llx \n" \
        "  pgr=%016llx rgn=%016llx rgo=%08x cbc=%04x rga=%016llx\n",
        sz,
        ctx->e.va, ctx->e.vaEPROCESS, ctx->e.dwPageKey, ctx->e.iSmkm, ctx->e.vaSmkmStore,
        ctx->e.PTE, ctx->e.vaOwnerEPROCESS, ctx->e.dwRegionKey, ctx->pProcess->dwPID, ((PMMWIN_CONTEXT)ctxVmm->pMmContext)->MemCompress.vaKeyToStoreTree,
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
BOOL MmWin_MemCompress1_SmkmStoreIndex(_In_ PMMWINX64_COMPRESS_CONTEXT ctx)
{
    DWORD v;
    if(!MmWin_BTree_Search(ctx->pSystemProcess, ((PMMWIN_CONTEXT)ctxVmm->pMmContext)->MemCompress.vaKeyToStoreTree, ctx->e.dwPageKey, &v, ctx->fVmmRead)) {
        return MmWin_MemCompress_LogError(ctx, "#11 BTreeSearch");
    }
    if(v & 0x01000000) { return MmWin_MemCompress_LogError(ctx, "#12 InvalidValue"); }
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
BOOL MmWin_MemCompress2_SmkmStoreMetadata32(_In_ PMMWINX64_COMPRESS_CONTEXT ctx)
{
    DWORD va;
    _SMKM_STORE_METADATA32 MetaData;
    // 1: 1st level fetch virtual address to 2nd level of 32x32 array
    if(!VmmRead2(ctx->pSystemProcess, ((PMMWIN_CONTEXT)ctxVmm->pMmContext)->MemCompress.vaSmGlobals + (ctx->e.iSmkm >> 5) * sizeof(DWORD), (PBYTE)&va, sizeof(DWORD), ctx->fVmmRead)) { return MmWin_MemCompress_LogError(ctx, "#21 Read"); }
    if(!VMM_KADDR32_8(va)) { return MmWin_MemCompress_LogError(ctx, "#22 NoKADDR"); }
    // 2: 2nd fetch values (_SMKM_STORE_METADATA) from 2nd level of 32x32 array.
    if(!VmmRead2(ctx->pSystemProcess, va + (ctx->e.iSmkm & 0x1f) * sizeof(_SMKM_STORE_METADATA32), (PBYTE)&MetaData, sizeof(_SMKM_STORE_METADATA32), ctx->fVmmRead)) { return MmWin_MemCompress_LogError(ctx, "#23 Read"); }
    if(MetaData.vaEPROCESS && !VMM_KADDR32_8(MetaData.vaEPROCESS)) { return MmWin_MemCompress_LogError(ctx, "#24 NoKADDR"); }
    if(!VMM_KADDR32_PAGE(MetaData.vaSmkmStore)) { return MmWin_MemCompress_LogError(ctx, "#25 NoKADDR"); }
    ctx->e.vaSmkmStore = MetaData.vaSmkmStore;
    ctx->e.vaEPROCESS = MetaData.vaEPROCESS;
    return TRUE;
}

_Success_(return)
BOOL MmWin_MemCompress2_SmkmStoreMetadata64(_In_ PMMWINX64_COMPRESS_CONTEXT ctx)
{
    QWORD va;
    _SMKM_STORE_METADATA64 MetaData;
    // 1: 1st level fetch virtual address to 2nd level of 32x32 array
    if(!VmmRead2(ctx->pSystemProcess, ((PMMWIN_CONTEXT)ctxVmm->pMmContext)->MemCompress.vaSmGlobals + (ctx->e.iSmkm >> 5) * sizeof(QWORD), (PBYTE)&va, sizeof(QWORD), ctx->fVmmRead)) { return MmWin_MemCompress_LogError(ctx, "#21 Read"); }
    if(!VMM_KADDR64_16(va)) { return MmWin_MemCompress_LogError(ctx, "#22 NoKADDR"); }
    // 2: 2nd fetch values (_SMKM_STORE_METADATA) from 2nd level of 32x32 array.
    if(!VmmRead2(ctx->pSystemProcess, va + (ctx->e.iSmkm & 0x1f) * sizeof(_SMKM_STORE_METADATA64), (PBYTE)&MetaData, sizeof(_SMKM_STORE_METADATA64), ctx->fVmmRead)) { return MmWin_MemCompress_LogError(ctx, "#23 Read"); }
    if(MetaData.vaEPROCESS && !VMM_KADDR64_16(MetaData.vaEPROCESS)) { return MmWin_MemCompress_LogError(ctx, "#24 NoKADDR"); }
    if(!VMM_KADDR64_PAGE(MetaData.vaSmkmStore)) { return MmWin_MemCompress_LogError(ctx, "#25 NoKADDR"); }
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
BOOL MmWin_MemCompress3_SmkmStoreAndPageRecord32(_In_ PMMWINX64_COMPRESS_CONTEXT ctx)
{
    DWORD vaPageRecordArray;
    DWORD i, dwEncodedMetadata, iChunkPtr = 0, iChunkArray, dwPoolHdr = 0;
    P_SMHP_CHUNK_METADATA32 pc;
    PMMWIN_MEMCOMPRESS_OFFSET po = &((PMMWIN_CONTEXT)ctxVmm->pMmContext)->MemCompress.O;
    // 1: Load SmkmStore
    if(!VmmRead2(ctx->pSystemProcess, ctx->e.vaSmkmStore, ctx->e.pbSmkm, sizeof(ctx->e.pbSmkm), ctx->fVmmRead)) {
        return MmWin_MemCompress_LogError(ctx, "#31 ReadSmkmStore");
    }
    // 2: Validate
    if(!VMM_KADDR32_8(*(PDWORD)(ctx->e.pbSmkm + po->SMKM_STORE.PagesTree))) {
        return MmWin_MemCompress_LogError(ctx, "#32 PagesTreePtrNoKADDR");
    }
    if(COMPRESS_ALGORITHM_XPRESS != *(PWORD)(ctx->e.pbSmkm + po->SMKM_STORE.CompressionAlgorithm)) {
        return MmWin_MemCompress_LogError(ctx, "#33 InvalidCompressionAlgorithm");
    }
    // 3: Get region key
    if(!MmWin_BTree_Search(ctx->pSystemProcess, *(PDWORD)(ctx->e.pbSmkm + po->SMKM_STORE.PagesTree), ctx->e.dwPageKey, &ctx->e.dwRegionKey, ctx->fVmmRead)) {
        return MmWin_MemCompress_LogError(ctx, "#34 RegionKeyBTreeSearch");
    }
    // 4: Get page record and calculate:
    //    - chunk "encoded metadata"
    //    - index into chunk metadata array (= highest non-zero bit position of encoded_metadata)
    //    - index into chunk array (pointed to by chunk metadata array)
    pc = (P_SMHP_CHUNK_METADATA32)(ctx->e.pbSmkm + po->SMKM_STORE.ChunkMetaData);
    dwEncodedMetadata = ctx->e.dwRegionKey >> (pc->dwBitValue & 0xff);
    for(i = 0; i < 32; i++) {
        if(!(dwEncodedMetadata >> i)) { break; }
        iChunkPtr = i;
    }
    iChunkArray = (1 << iChunkPtr) ^ dwEncodedMetadata;
    // 5: Validate and fetch page record address
    if(iChunkArray > 0x400) {
        return MmWin_MemCompress_LogError(ctx, "#35 ChunkArrayTooLarge");
    }
    if(!VMM_KADDR32_8(pc->avaChunkPtr[iChunkPtr])) {
        return MmWin_MemCompress_LogError(ctx, "#36 ChunkPtrNoKADDR");
    }
    if(pc->avaChunkPtr[iChunkPtr] & 0xfff) {
        if(!VmmRead2(ctx->pSystemProcess, pc->avaChunkPtr[iChunkPtr] - 4, (PBYTE)&dwPoolHdr, 4, ctx->fVmmRead) || (dwPoolHdr != 'ABms')) {
            return MmWin_MemCompress_LogError(ctx, "#37 ChunkBadPoolHdr");
        }
    }
    if(!VmmRead2(ctx->pSystemProcess, pc->avaChunkPtr[iChunkPtr] + 0x0cULL * iChunkArray, (PBYTE)&vaPageRecordArray, sizeof(DWORD), ctx->fVmmRead) || !VMM_KADDR32_PAGE(vaPageRecordArray)) {
        return MmWin_MemCompress_LogError(ctx, "#38 PageRecordArray");
    }
    ctx->e.vaPageRecord = (DWORD)((QWORD)vaPageRecordArray + pc->dwChunkPageHeaderSize + ((QWORD)pc->dwPageRecordSize * (ctx->e.dwRegionKey & pc->dwPageRecordsPerChunkMask)));
    // 6: Get owner EPROCESS
    ctx->e.vaOwnerEPROCESS = *(PDWORD)(ctx->e.pbSmkm + po->SMKM_STORE.OwnerProcess);
    if(ctx->e.vaOwnerEPROCESS != ((PMMWIN_CONTEXT)ctxVmm->pMmContext)->MemCompress.vaEPROCESS) {
        return MmWin_MemCompress_LogError(ctx, "#39 OwnerEPROCESS");
    }
    return TRUE;
}

/*
* Retrieve the SmkmStore and the PageRecord.
* -- ctx
* -- return
*/
_Success_(return)
BOOL MmWin_MemCompress3_SmkmStoreAndPageRecord64(_In_ PMMWINX64_COMPRESS_CONTEXT ctx)
{
    QWORD vaPageRecordArray;
    DWORD i, dwEncodedMetadata, iChunkPtr = 0, iChunkArray, dwPoolHdr = 0;
    P_SMHP_CHUNK_METADATA64 pc;
    PMMWIN_MEMCOMPRESS_OFFSET po = &((PMMWIN_CONTEXT)ctxVmm->pMmContext)->MemCompress.O;
    // 1: Load SmkmStore
    if(!VmmRead2(ctx->pSystemProcess, ctx->e.vaSmkmStore, ctx->e.pbSmkm, sizeof(ctx->e.pbSmkm), ctx->fVmmRead)) {
        return MmWin_MemCompress_LogError(ctx, "#31 ReadSmkmStore");
    }
    // 2: Validate
    if(!VMM_KADDR64_16(*(PQWORD)(ctx->e.pbSmkm + po->SMKM_STORE.PagesTree))) {
        return MmWin_MemCompress_LogError(ctx, "#32 PagesTreePtrNoKADDR");
    }
    if(COMPRESS_ALGORITHM_XPRESS != *(PWORD)(ctx->e.pbSmkm + po->SMKM_STORE.CompressionAlgorithm)) {
        return MmWin_MemCompress_LogError(ctx, "#33 InvalidCompressionAlgorithm");
    }
    // 3: Get region key
    if(!MmWin_BTree_Search(ctx->pSystemProcess, *(PQWORD)(ctx->e.pbSmkm + po->SMKM_STORE.PagesTree), ctx->e.dwPageKey, &ctx->e.dwRegionKey, ctx->fVmmRead)) {
        return MmWin_MemCompress_LogError(ctx, "#34 RegionKeyBTreeSearch");
    }
    // 4: Get page record and calculate:
    //    - chunk "encoded metadata"
    //    - index into chunk metadata array (= highest non-zero bit position of encoded_metadata)
    //    - index into chunk array (pointed to by chunk metadata array)
    pc = (P_SMHP_CHUNK_METADATA64)(ctx->e.pbSmkm + po->SMKM_STORE.ChunkMetaData);
    dwEncodedMetadata = ctx->e.dwRegionKey >> (pc->dwBitValue & 0xff);
    for(i = 0; i < 32; i++) {
        if(!(dwEncodedMetadata >> i)) { break; }
        iChunkPtr = i;
    }
    iChunkArray = (1 << iChunkPtr) ^ dwEncodedMetadata;
    // 5: Validate and fetch page record address
    if(iChunkArray > 0x400) {
        return MmWin_MemCompress_LogError(ctx, "#35 ChunkArrayTooLarge");
    }
    if(!VMM_KADDR64_16(pc->avaChunkPtr[iChunkPtr])) {
        return MmWin_MemCompress_LogError(ctx, "#36 ChunkPtrNoKADDR");
    }
    if(pc->avaChunkPtr[iChunkPtr] & 0xfff) {
        if(!VmmRead2(ctx->pSystemProcess, pc->avaChunkPtr[iChunkPtr] - 12, (PBYTE)&dwPoolHdr, 4, ctx->fVmmRead) || (dwPoolHdr != 'ABms')) {
            return MmWin_MemCompress_LogError(ctx, "#37 ChunkBadPoolHdr");
        }
    }
    if(!VmmRead2(ctx->pSystemProcess, pc->avaChunkPtr[iChunkPtr] + 0x10ULL * iChunkArray, (PBYTE)&vaPageRecordArray, sizeof(QWORD), ctx->fVmmRead) || !VMM_KADDR64_PAGE(vaPageRecordArray)) {
        return MmWin_MemCompress_LogError(ctx, "#38 PageRecordArray");
    }
    ctx->e.vaPageRecord = (QWORD)(vaPageRecordArray + pc->dwChunkPageHeaderSize + ((QWORD)pc->dwPageRecordSize * (ctx->e.dwRegionKey & pc->dwPageRecordsPerChunkMask)));
    // 6: Get owner EPROCESS
    ctx->e.vaOwnerEPROCESS = *(PQWORD)(ctx->e.pbSmkm + po->SMKM_STORE.OwnerProcess);
    if(ctx->e.vaOwnerEPROCESS != ((PMMWIN_CONTEXT)ctxVmm->pMmContext)->MemCompress.vaEPROCESS) {
        return MmWin_MemCompress_LogError(ctx, "#39 OwnerEPROCESS");
    }
    return TRUE;
}

/*
* Retrieve the region address / data containing the compressed process.
* -- ctx
* -- return
*/
_Success_(return)
BOOL MmWin_MemCompress4_CompressedRegionData(_In_ PMMWINX64_COMPRESS_CONTEXT ctx)
{
    QWORD vaRegionPtr = 0;
    DWORD dwRegionIndexMask, dwRegionIndex;
    _ST_PAGE_RECORD PageRecord;
    PMMWIN_MEMCOMPRESS_OFFSET po = &((PMMWIN_CONTEXT)ctxVmm->pMmContext)->MemCompress.O;
    // 1: Read page record
    if(!VmmRead2(ctx->pSystemProcess, ctx->e.vaPageRecord, (PBYTE)&PageRecord, sizeof(PageRecord), ctx->fVmmRead)) {
        return MmWin_MemCompress_LogError(ctx, "#41 ReadPageRecord");
    }
    if(PageRecord.Key == 0xffffffff) {
        // TODO: implement support
        return MmWin_MemCompress_LogError(ctx, "#42 InvalidPageRecord");
    }
    ctx->e.cbCompressedData = (PageRecord.CompressedSize == 0x1000) ? 0x1000 : PageRecord.CompressedSize & 0xfff;
    if(ctxVmm->f32) {
        // 2: Get pointer to region (32-bit)
        dwRegionIndexMask = *(PDWORD)(ctx->e.pbSmkm + po->SMKM_STORE.RegionIndexMask) & 0xff;
        dwRegionIndex = PageRecord.Key >> dwRegionIndexMask;
        vaRegionPtr = *(PDWORD)(ctx->e.pbSmkm + po->SMKM_STORE.CompressedRegionPtrArray) + dwRegionIndex * sizeof(DWORD);
        // 3: Get region and offset (32-bit)
        if(!VmmRead2(ctx->pSystemProcess, vaRegionPtr, (PBYTE)&ctx->e.vaRegion, sizeof(DWORD), ctx->fVmmRead)) {
            return MmWin_MemCompress_LogError(ctx, "#43 ReadRegionVA");
        }
        if(!ctx->e.vaRegion || (ctx->e.vaRegion & 0x8000ffff)) {
            return MmWin_MemCompress_LogError(ctx, "#44 InvalidRegionVA");
        }
    } else {
        // 2: Get pointer to region (64-bit)
        dwRegionIndexMask = *(PDWORD)(ctx->e.pbSmkm + po->SMKM_STORE.RegionIndexMask) & 0xff;
        dwRegionIndex = PageRecord.Key >> dwRegionIndexMask;
        vaRegionPtr = *(PQWORD)(ctx->e.pbSmkm + po->SMKM_STORE.CompressedRegionPtrArray) + dwRegionIndex * sizeof(QWORD);
        // 3: Get region and offset (64-bit)
        if(!VmmRead2(ctx->pSystemProcess, vaRegionPtr, (PBYTE)&ctx->e.vaRegion, sizeof(QWORD), ctx->fVmmRead)) {
            return MmWin_MemCompress_LogError(ctx, "#45 ReadRegionVA");
        }
        if(!ctx->e.vaRegion || (ctx->e.vaRegion & 0xffff80000000ffff)) {
            return MmWin_MemCompress_LogError(ctx, "#46 InvalidRegionVA");
        }
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
BOOL MmWin_MemCompress5_DecompressPage(_In_ PMMWINX64_COMPRESS_CONTEXT ctx, _Out_writes_(4096) PBYTE pbDecompressedPage)
{
    DWORD cbDecompressed = 0;
    NTSTATUS nt = VMM_STATUS_UNSUCCESSFUL;
    // 1: Read compressed data
    if(!VmmRead2(ctx->pProcessMemCompress, ctx->e.vaRegion + ctx->e.cbRegionOffset, ctx->e.pbCompressedData, ctx->e.cbCompressedData, ctx->fVmmRead)) {
        MmWin_MemCompress_LogError(ctx, "#51 Read");
        return FALSE;
    }
    // 2: Decompress data
    if(ctx->e.cbCompressedData == 0x1000) {
        memcpy(pbDecompressedPage, ctx->e.pbCompressedData, 0x1000);
    } else {
        if(ctxVmm->fn.RtlDecompressBufferOpt) {
            nt = ctxVmm->fn.RtlDecompressBufferOpt(COMPRESS_ALGORITHM_XPRESS, pbDecompressedPage, 0x1000, ctx->e.pbCompressedData, ctx->e.cbCompressedData, &cbDecompressed);
        }
        if((nt != VMM_STATUS_SUCCESS) || (cbDecompressed != 0x1000)) {
            MmWin_MemCompress_LogError(ctx, "#52 Decompress");
            return FALSE;
        }
    }
    return TRUE;
}

/*
* Decompress a page.
* -- pProcess
* -- va
* -- pte
* -- pbPage
* -- fVmmRead = flags to VmmRead function calls.
* -- return
*/
_Success_(return)
BOOL MmWin_MemCompress(_In_ PVMM_PROCESS pProcess, _In_opt_ QWORD va, _In_ QWORD pte, _Out_writes_(4096) PBYTE pbPage, _In_ QWORD fVmmRead)
{
    BOOL fResult = FALSE;
    PMMWINX64_COMPRESS_CONTEXT ctx = NULL;
    PVMM_PROCESS pObSystemProcess = NULL, pObMemCompressProcess = NULL;
    QWORD tm = Statistics_CallStart();
    if(!(ctx = LocalAlloc(LMEM_ZEROINIT, sizeof(MMWINX64_COMPRESS_CONTEXT)))) { goto fail; }
    ctx->fVmmRead = fVmmRead;
    ctx->e.va = va;
    ctx->e.PTE = pte;
    if(ctxVmm->f32) {
        // 32-bit system
        ctx->e.dwPageKey = MMWINX86PAE_PTE_PAGE_KEY_COMPRESSED(pte);
        fResult =
            (ctx->pProcess = pProcess) &&
            (ctx->pSystemProcess = pObSystemProcess = VmmProcessGet(4)) &&
            (ctx->pProcessMemCompress = pObMemCompressProcess = VmmProcessGet(((PMMWIN_CONTEXT)ctxVmm->pMmContext)->MemCompress.dwPid)) &&
            MmWin_MemCompress1_SmkmStoreIndex(ctx) &&
            MmWin_MemCompress2_SmkmStoreMetadata32(ctx) &&
            MmWin_MemCompress3_SmkmStoreAndPageRecord32(ctx) &&
            MmWin_MemCompress4_CompressedRegionData(ctx) &&
            MmWin_MemCompress5_DecompressPage(ctx, pbPage);
    } else {
        // 64-bit system
        ctx->e.dwPageKey = MMWINX64_PTE_PAGE_KEY_COMPRESSED(pte);
        fResult =
            (ctx->pProcess = pProcess) &&
            (ctx->pSystemProcess = pObSystemProcess = VmmProcessGet(4)) &&
            (ctx->pProcessMemCompress = pObMemCompressProcess = VmmProcessGet(((PMMWIN_CONTEXT)ctxVmm->pMmContext)->MemCompress.dwPid)) &&
            MmWin_MemCompress1_SmkmStoreIndex(ctx) &&
            MmWin_MemCompress2_SmkmStoreMetadata64(ctx) &&
            MmWin_MemCompress3_SmkmStoreAndPageRecord64(ctx) &&
            MmWin_MemCompress4_CompressedRegionData(ctx) &&
            MmWin_MemCompress5_DecompressPage(ctx, pbPage);
    }
fail:
    LocalFree(ctx);
    Ob_DECREF(pObSystemProcess);
    Ob_DECREF(pObMemCompressProcess);
    Statistics_CallEnd(STATISTICS_ID_VMM_PagedCompressedMemory, tm);
    return fResult;
}


//-----------------------------------------------------------------------------
// PAGE FILE FUNCTIONALITY BELOW:
//-----------------------------------------------------------------------------

_Success_(return)
BOOL MmWin_PfReadFile(_In_ DWORD dwPfNumber, _In_ DWORD dwPfOffset, _Out_writes_(4096) PBYTE pbPage)
{
    PMMWIN_CONTEXT ctx = (PMMWIN_CONTEXT)ctxVmm->pMmContext;
    DWORD cb = 0;
    if(!ctx || !ctx->pPageFile[dwPfNumber]) { return FALSE; }
    EnterCriticalSection(&ctx->Lock);
    if(!_fseeki64(ctx->pPageFile[dwPfNumber], (QWORD)dwPfOffset << 12, SEEK_SET)) {
        cb = (DWORD)fread(pbPage, 1, 0x1000, ctx->pPageFile[dwPfNumber]);
    }
    LeaveCriticalSection(&ctx->Lock);
    return cb == 0x1000;
}

_Success_(return)
BOOL MmWin_PfRead(_In_ PVMM_PROCESS pProcess, _In_opt_ QWORD va, _In_ QWORD pte, _In_ QWORD fVmmRead, _In_ DWORD dwPfNumber, _In_ DWORD dwPfOffset, _Out_writes_(4096) PBYTE pbPage)
{
    BOOL fResult;
    PVMMOB_CACHE_MEM pObCacheEntry;
    // cached page?
    if((pObCacheEntry = VmmCacheGet(VMM_CACHE_TAG_PAGING, pte))) {
        memcpy(pbPage, pObCacheEntry->pb, 0x1000);
        Ob_DECREF(pObCacheEntry);
        InterlockedIncrement64(&ctxVmm->stat.page.cCacheHit);
        return TRUE;
    }
    // cached failed page?
    if(ObSet_Exists(ctxVmm->Cache.PAGING_FAILED, pte)) {
        InterlockedIncrement64(&ctxVmm->stat.page.cFailCacheHit);
        return FALSE;
    }
    // check flags: NoPagingIo, ForceCache and santity checks.
    if(fVmmRead & (VMM_FLAG_NOPAGING_IO | VMM_FLAG_FORCECACHE_READ)) { return FALSE; }
    if(!ctxVmm->pMmContext || (dwPfNumber >= 10)) { return FALSE; }
    // dispatch to page file or compressed virtual store
    if(((PMMWIN_CONTEXT)ctxVmm->pMmContext)->MemCompress.fValid && (dwPfNumber == ((PMMWIN_CONTEXT)ctxVmm->pMmContext)->MemCompress.dwPageFileNumber)) {
        fResult = MmWin_MemCompress(pProcess, va, pte, pbPage, fVmmRead);
        if(fResult) {
            InterlockedIncrement64(&ctxVmm->stat.page.cCompressed);
        } else {
            InterlockedIncrement64(&ctxVmm->stat.page.cFailCompressed);
        }
    } else {
        fResult = MmWin_PfReadFile(dwPfNumber, dwPfOffset, pbPage);
        if(fResult) {
            InterlockedIncrement64(&ctxVmm->stat.page.cPageFile);
        } else {
            InterlockedIncrement64(&ctxVmm->stat.page.cFailPageFile);
        }
    }
    // update cache
    if(fResult) {
        if((pObCacheEntry = VmmCacheReserve(VMM_CACHE_TAG_PAGING))) {
            pObCacheEntry->h.f = TRUE;
            pObCacheEntry->h.qwA = pte;
            memcpy(pObCacheEntry->pb, pbPage, 0x1000);
            VmmCacheReserveReturn(pObCacheEntry);
        }
        return TRUE;
    }
    ObSet_Push(ctxVmm->Cache.PAGING_FAILED, pte);
    return FALSE;
}


//-----------------------------------------------------------------------------
// X86 VIRTUAL MEMORY BELOW:
//-----------------------------------------------------------------------------

/*
* Fetch PTE from a prototype PTE. The returned PTE may be zero = fail, hardware or software PTE.
* -- pte
* -- fVmmRead = flags to VmmRead function calls.
* -- return
*/
DWORD MmWinX86_Prototype(_In_ DWORD pte, _In_ QWORD fVmmRead)
{
    PVMM_PROCESS pObSystemProcess;
    DWORD cbRead, dwPtePage = 0;
    if(!(pObSystemProcess = VmmProcessGet(4))) { goto fail; }
    VmmReadEx(pObSystemProcess, MMWINX86_PTE_PROTOTYPE(pte), (PBYTE)&dwPtePage, 4, &cbRead, fVmmRead);
    if(cbRead != 4) { goto fail; }
    if((MMWINX86_PTE_IS_HARDWARE(dwPtePage) && (dwPtePage >= ctxMain->dev.paMax)) || MMWINX86_PTE_PROTOTYPE(dwPtePage)) {
        dwPtePage = 0;
    }
fail:
    Ob_DECREF(pObSystemProcess);
    return dwPtePage;
}

/*
* Read a 'paged' page from virtual memory.
* -- pProcess
* -- va
* -- pte
* -- pbPage
* -- ppa
* -- ptp
* -- return
*/
_Success_(return)
BOOL MmWinX86_ReadPaged(_In_ PVMM_PROCESS pProcess, _In_opt_ DWORD va, _In_ DWORD pte, _Out_writes_opt_(4096) PBYTE pbPage, _Out_ PQWORD ppa, _Inout_opt_ PVMM_PTE_TP ptp, _In_ QWORD flags)
{
    BOOL f;
    DWORD dwPfNumber, dwPfOffset;
    *ppa = 0;
    if(MMWINX86_PTE_IS_HARDWARE(pte)) {
        if(ptp && !*ptp) { *ptp = VMM_PTE_TP_HARDWARE; }
        *ppa = pte & 0xfffff000;
        return FALSE;
    }
    if(MM_LOOP_PROTECT_MAX(flags)) { goto fail; }
    flags = MM_LOOP_PROTECT_ADD(flags);
    // prototype page [ nt!_MMPTE_PROTOTYPE ]
    if(!(flags & VMM_FLAG_NOPAGING_IO) && MMWINX86_PTE_PROTOTYPE(pte)) {
        if(ptp && !*ptp) { *ptp = VMM_PTE_TP_PROTOTYPE; }
        InterlockedIncrement64(&ctxVmm->stat.page.cPrototype);
        pte = MmWinX86_Prototype(pte, flags);
        if(MMWINX86_PTE_IS_HARDWARE(pte)) {
            *ppa = pte & 0xfffff000;
            return FALSE;
        }
        // prototype pte points to software pte -> use it as new pte and continue
    }
    // transition page [ nt!_MMPTE_TRANSITION ]
    if(MMWINX86_PTE_TRANSITION(pte)) {
        if(ptp && !*ptp) { *ptp = VMM_PTE_TP_TRANSITION; }
        pte = MMWINX86_PTE_TRANSITION(pte);
        if((pte & 0xfffff000) < ctxMain->dev.paMax) {
            *ppa = pte & 0xfffff000;
            InterlockedIncrement64(&ctxVmm->stat.page.cTransition);
        }
        return FALSE;
    }
    dwPfNumber = MMWINX86_PTE_PAGE_FILE_NUMBER(pte);
    dwPfOffset = MMWINX86_PTE_PAGE_FILE_OFFSET(pte);
    // Potentially VAD-backed virtual memory
    if(va && !VMM_KADDR32(va) && !(flags & VMM_FLAG_NOVAD) && (!pte || (dwPfOffset == 0x000fffff))) {
        pte = (DWORD)MmVad_PrototypePte(pProcess, va, &f, flags);
        if(!pte) {
            if(f) { InterlockedIncrement64(&ctxVmm->stat.page.cFailVAD); }
            return FALSE;
        }
        if(ptp && !*ptp) { *ptp = VMM_PTE_TP_PROTOTYPE; }
        InterlockedIncrement64(&ctxVmm->stat.page.cVAD);
        if(MMWINX86_PTE_IS_HARDWARE(pte)) {
            *ppa = pte & 0xfffff000;
            return FALSE;
        }
        return MmWinX86_ReadPaged(pProcess, va, pte, pbPage, ppa, NULL, flags | VMM_FLAG_NOVAD);
    }
    if(!pte) { return FALSE; }
    // demand zero virtual memory [ nt!_MMPTE_SOFTWARE ]
    if(!dwPfNumber && !dwPfOffset) {
        if(ptp && !*ptp) { *ptp = VMM_PTE_TP_DEMANDZERO; }
        if(pbPage) {
            ZeroMemory(pbPage, 0x1000);
            InterlockedIncrement64(&ctxVmm->stat.page.cDemandZero);
            return TRUE;
        }
        return FALSE;
    }
    // retrive from page file or compressed store
    if(ptp && !*ptp) {
        *ptp = (((PMMWIN_CONTEXT)ctxVmm->pMmContext)->MemCompress.fValid && (dwPfNumber == ((PMMWIN_CONTEXT)ctxVmm->pMmContext)->MemCompress.dwPageFileNumber)) ?
            VMM_PTE_TP_COMPRESSED : VMM_PTE_TP_PAGEFILE;
    }
    return pbPage ? MmWin_PfRead(pProcess, va, pte, flags, dwPfNumber, dwPfOffset, pbPage) : FALSE;
fail:
    InterlockedIncrement64(&ctxVmm->stat.page.cFail);
    return FALSE;
}


//-----------------------------------------------------------------------------
// X86PAE VIRTUAL MEMORY BELOW:
//-----------------------------------------------------------------------------

/*
* Fetch PTE from a prototype PTE. The returned PTE may be zero = fail, hardware or software PTE.
* -- pte
* -- fVmmRead = flags to VmmRead function calls.
* -- return
*/
QWORD MmWinX86PAE_Prototype(_In_ QWORD pte, _In_ QWORD fVmmRead)
{
    DWORD cbRead;
    QWORD qwPtePage = 0;
    PVMM_PROCESS pObSystemProcess;
    if(!(pObSystemProcess = VmmProcessGet(4))) { goto fail; }
    VmmReadEx(pObSystemProcess, MMWINX86PAE_PTE_PROTOTYPE(pte), (PBYTE)&qwPtePage, 8, &cbRead, fVmmRead);
    if(cbRead != 8) { goto fail; }
    if((MMWINX86PAE_PTE_IS_HARDWARE(qwPtePage) && ((qwPtePage & 0x0000003ffffff000) >= ctxMain->dev.paMax)) || MMWINX86PAE_PTE_PROTOTYPE(qwPtePage)) {
        qwPtePage = 0;
    }
fail:
    Ob_DECREF(pObSystemProcess);
    return qwPtePage;
}

/*
* Read a 'paged' page from virtual memory.
* -- pProcess
* -- va
* -- pte
* -- pbPage
* -- ppa
* -- ptp
* -- return
*/
_Success_(return)
BOOL MmWinX86PAE_ReadPaged(_In_ PVMM_PROCESS pProcess, _In_opt_ DWORD va, _In_ QWORD pte, _Out_writes_opt_(4096) PBYTE pbPage, _Out_ PQWORD ppa, _Inout_opt_ PVMM_PTE_TP ptp, _In_ QWORD flags)
{
    BOOL f;
    DWORD dwPfNumber, dwPfOffset;
    *ppa = 0;
    if(MMWINX86PAE_PTE_IS_HARDWARE(pte)) {
        if(ptp && !*ptp) { *ptp = VMM_PTE_TP_HARDWARE; }
        *ppa = pte & 0x0000003ffffff000;
        return FALSE;
    }
    if(MM_LOOP_PROTECT_MAX(flags)) { goto fail; }
    flags = MM_LOOP_PROTECT_ADD(flags);
    // prototype page [ nt!_MMPTE_PROTOTYPE ]
    if(!(flags & VMM_FLAG_NOPAGING_IO) && MMWINX86PAE_PTE_PROTOTYPE(pte)) {
        if(ptp && !*ptp) { *ptp = VMM_PTE_TP_PROTOTYPE; }
        InterlockedIncrement64(&ctxVmm->stat.page.cPrototype);
        pte = MmWinX86PAE_Prototype(pte, flags);
        if(MMWINX86PAE_PTE_IS_HARDWARE(pte)) {
            *ppa = pte & 0x0000003ffffff000;
            return FALSE;
        }
        // prototype pte points to software pte -> use it as new pte and continue
    }
    // transition page [ nt!_MMPTE_TRANSITION ]
    if(MMWINX86PAE_PTE_TRANSITION(pte)) {
        if(ptp && !*ptp) { *ptp = VMM_PTE_TP_TRANSITION; }
        pte = MMWINX86PAE_PTE_TRANSITION(pte);
        if((pte & 0x0000003ffffff000) < ctxMain->dev.paMax) {
            *ppa = pte & 0x0000003ffffff000;
            InterlockedIncrement64(&ctxVmm->stat.page.cTransition);
        }
        return FALSE;
    }
    dwPfNumber = MMWINX86PAE_PTE_PAGE_FILE_NUMBER(pte);
    dwPfOffset = MMWINX86PAE_PTE_PAGE_FILE_OFFSET(pte);
    // Potentially VAD-backed virtual memory
    if(va && !VMM_KADDR32(va) && !(flags & VMM_FLAG_NOVAD) && (!pte || (dwPfOffset == 0xffffffff))) {
        pte = MmVad_PrototypePte(pProcess, va, &f, flags);
        if(!pte) {
            if(f) { InterlockedIncrement64(&ctxVmm->stat.page.cFailVAD); }
            return FALSE;
        }
        if(ptp && !*ptp) { *ptp = VMM_PTE_TP_PROTOTYPE; }
        InterlockedIncrement64(&ctxVmm->stat.page.cVAD);
        if(MMWINX86PAE_PTE_IS_HARDWARE(pte)) {
            *ppa = pte & 0x0000003ffffff000;
            return FALSE;
        }
        return MmWinX86PAE_ReadPaged(pProcess, va, pte, pbPage, ppa, NULL, flags | VMM_FLAG_NOVAD);
    }
    if(!pte) { return FALSE; }
    // demand zero virtual memory [ nt!_MMPTE_SOFTWARE ]
    if(!dwPfNumber && !dwPfOffset) {
        if(ptp && !*ptp) { *ptp = VMM_PTE_TP_DEMANDZERO; }
        if(pbPage) {
            ZeroMemory(pbPage, 0x1000);
            InterlockedIncrement64(&ctxVmm->stat.page.cDemandZero);
            return TRUE;
        }
        return FALSE;
    }
    // retrive from page file or compressed store
    if(ptp && !*ptp) {
        *ptp = (((PMMWIN_CONTEXT)ctxVmm->pMmContext)->MemCompress.fValid && (dwPfNumber == ((PMMWIN_CONTEXT)ctxVmm->pMmContext)->MemCompress.dwPageFileNumber)) ?
            VMM_PTE_TP_COMPRESSED : VMM_PTE_TP_PAGEFILE;
    }
    return  pbPage ? MmWin_PfRead(pProcess, va, pte, flags, dwPfNumber, dwPfOffset, pbPage) : FALSE;
fail:
    InterlockedIncrement64(&ctxVmm->stat.page.cFail);
    return FALSE;
}


//-----------------------------------------------------------------------------
// X64 VIRTUAL MEMORY BELOW:
//-----------------------------------------------------------------------------

/*
* Fetch PTE from a prototype PTE. The returned PTE may be zero = fail, hardware or software PTE.
* -- pte
* -- fVmmRead = flags to VmmRead function calls.
* -- return
*/
QWORD MmWinX64_Prototype(_In_ QWORD pte, _In_ QWORD fVmmRead)
{
    DWORD cbRead;
    QWORD qwPtePage = 0;
    PVMM_PROCESS pObSystemProcess;
    if(!(pObSystemProcess = VmmProcessGet(4))) { goto fail; }
    VmmReadEx(pObSystemProcess, MMWINX64_PTE_PROTOTYPE(pte), (PBYTE)&qwPtePage, 8, &cbRead, fVmmRead);
    if(cbRead != 8) { goto fail; }
    if((MMWINX64_PTE_IS_HARDWARE(qwPtePage) && ((qwPtePage & 0x0000fffffffff000) >= ctxMain->dev.paMax)) || MMWINX64_PTE_PROTOTYPE(qwPtePage)) {
        qwPtePage = 0;
    }
fail:
    Ob_DECREF(pObSystemProcess);
    return qwPtePage;
}

/*
* Read a 'paged' page from virtual memory.
* -- pProcess
* -- va
* -- pte
* -- pbPage
* -- ppa
* -- ptp
* -- flags
* -- return
*/
_Success_(return)
BOOL MmWinX64_ReadPaged(_In_ PVMM_PROCESS pProcess, _In_opt_ QWORD va, _In_ QWORD pte, _Out_writes_opt_(4096) PBYTE pbPage, _Out_ PQWORD ppa, _Inout_opt_ PVMM_PTE_TP ptp, _In_ QWORD flags)
{
    BOOL f;
    DWORD dwPfNumber, dwPfOffset;
    *ppa = 0;
    if(MMWINX64_PTE_IS_HARDWARE(pte)) {
        if(ptp && !*ptp) { *ptp = VMM_PTE_TP_HARDWARE; }
        *ppa = pte & 0x0000fffffffff000;
        return FALSE;
    }
    if(MM_LOOP_PROTECT_MAX(flags)) { goto fail; }
    flags = MM_LOOP_PROTECT_ADD(flags);
    // prototype page
    if(!(flags & VMM_FLAG_NOPAGING_IO) && MMWINX64_PTE_PROTOTYPE(pte)) {
        if(ptp && !*ptp) { *ptp = VMM_PTE_TP_PROTOTYPE; }
        InterlockedIncrement64(&ctxVmm->stat.page.cPrototype);
        pte = MmWinX64_Prototype(pte, flags);
        if(MMWINX64_PTE_IS_HARDWARE(pte)) {
            *ppa = pte & 0x0000fffffffff000;
            return FALSE;
        }
        // prototype pte points to software pte -> use it as new pte and continue
    }
    // transition page
    if(MMWINX64_PTE_TRANSITION(pte)) {
        if(ptp && !*ptp) { *ptp = VMM_PTE_TP_TRANSITION; }
        pte = MMWINX64_PTE_TRANSITION(pte);
        if((pte & 0x0000fffffffff000) < ctxMain->dev.paMax) {
            *ppa = pte & 0x0000fffffffff000;
            InterlockedIncrement64(&ctxVmm->stat.page.cTransition);
        }
        return FALSE;
    }
    dwPfNumber = MMWINX64_PTE_PAGE_FILE_NUMBER(pte);
    dwPfOffset = MMWINX64_PTE_PAGE_FILE_OFFSET(pte);
    // Potentially VAD-backed virtual memory
    if(va && !VMM_KADDR64(va) && !(flags & VMM_FLAG_NOVAD) && (!pte || (dwPfOffset == 0xffffffff))) {
        pte = MmVad_PrototypePte(pProcess, va, &f, flags);
        if(!pte) {
            if(f) { InterlockedIncrement64(&ctxVmm->stat.page.cFailVAD); }
            return FALSE;
        }
        if(ptp && !*ptp) { *ptp = VMM_PTE_TP_PROTOTYPE; }
        InterlockedIncrement64(&ctxVmm->stat.page.cVAD);
        if(MMWINX64_PTE_IS_HARDWARE(pte)) {
            *ppa = pte & 0x0000fffffffff000;
            return FALSE;
        }
        return MmWinX64_ReadPaged(pProcess, va, pte, pbPage, ppa, NULL, flags | VMM_FLAG_NOVAD);
    }
    if(!pte) { return FALSE; }
    // demand zero virtual memory [ nt!_MMPTE_SOFTWARE ]
    if(!dwPfNumber && !dwPfOffset) {
        if(ptp && !*ptp) { *ptp = VMM_PTE_TP_DEMANDZERO; }
        if(pbPage) {
            ZeroMemory(pbPage, 0x1000);
            InterlockedIncrement64(&ctxVmm->stat.page.cDemandZero);
            return TRUE;
        }
        return FALSE;
    }
    // retrive from page file or compressed store
    if(ptp && !*ptp) {
        *ptp = (((PMMWIN_CONTEXT)ctxVmm->pMmContext)->MemCompress.fValid && (dwPfNumber == ((PMMWIN_CONTEXT)ctxVmm->pMmContext)->MemCompress.dwPageFileNumber)) ?
            VMM_PTE_TP_COMPRESSED : VMM_PTE_TP_PAGEFILE;
    }
    return pbPage ? MmWin_PfRead(pProcess, va, pte, flags, dwPfNumber, dwPfOffset, pbPage) : FALSE;
fail:
    InterlockedIncrement64(&ctxVmm->stat.page.cFail);
    return FALSE;
}


//-----------------------------------------------------------------------------
// INITIALIZATION FUNCTIONALITY BELOW:
//-----------------------------------------------------------------------------

VOID MmWin_PagingClose()
{
    PMMWIN_CONTEXT ctx = (PMMWIN_CONTEXT)ctxVmm->pMmContext;
    DWORD i;
    if(ctx) {
        ctxVmm->pMmContext = NULL;
        for(i = 0; i < 10; i++) {
            if(ctx->pPageFile[i]) {
                fclose(ctx->pPageFile[i]);
            }
        }
        LocalFree(ctx);
    }
}

VOID MmWin_PagingInitialize(_In_ BOOL fModeFull)
{
    PMMWIN_CONTEXT ctx = (PMMWIN_CONTEXT)ctxVmm->pMmContext;
    DWORD i;
    // 1: Initialize Paging
    switch(ctxVmm->tpMemoryModel) {
        case VMM_MEMORYMODEL_X64:
            ctxVmm->fnMemoryModel.pfnPagedRead = MmWinX64_ReadPaged;
            break;
        case VMM_MEMORYMODEL_X86PAE:
            ctxVmm->fnMemoryModel.pfnPagedRead = (BOOL(*)(PVMM_PROCESS, QWORD, QWORD, PBYTE, PQWORD, PVMM_PTE_TP, QWORD))MmWinX86PAE_ReadPaged;
            break;
        case VMM_MEMORYMODEL_X86:
            ctxVmm->fnMemoryModel.pfnPagedRead = (BOOL(*)(PVMM_PROCESS, QWORD, QWORD, PBYTE, PQWORD, PVMM_PTE_TP, QWORD))MmWinX86_ReadPaged;
            break;
        default:
            return;
    }
    // 2: Initialize Page Files (if any)
    if(!ctx) {
        ctx = LocalAlloc(LMEM_ZEROINIT, sizeof(MMWIN_CONTEXT));
        if(!ctx) { return; }
        InitializeCriticalSection(&ctx->Lock);
        for(i = 0; i < 10; i++) {
            if(ctxMain->cfg.szPageFile[i][0]) {
                if(fopen_s(&ctx->pPageFile[i], ctxMain->cfg.szPageFile[i], "rb")) {
                    vmmprintfv("WARNING: CANNOT OPEN PAGE FILE #%i '%s'\n", i, ctxMain->cfg.szPageFile[i]);
                } else {
                    vmmprintfvv("Successfully opened page file #%i '%s'\n", i, ctxMain->cfg.szPageFile[i]);
                }
            }
        }
        ctxVmm->pMmContext = ctx;
    }
    if(!fModeFull) { return; }
    // 3: Initialize Memory DeCompression
    MmWin_MemCompress_Initialize();
}
