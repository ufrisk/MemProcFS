// mm_vad.c : implementation of Windows VAD (virtual address descriptor) functionality.
//
// (c) Ulf Frisk, 2019-2024
// Author: Ulf Frisk, pcileech@frizk.net
//

#include "mm.h"
#include "../util.h"

#define MMVAD_POOLTAG_VAD               'Vad '
#define MMVAD_POOLTAG_VADF              'VadF'
#define MMVAD_POOLTAG_VADS              'VadS'
#define MMVAD_POOLTAG_VADL              'Vadl'
#define MMVAD_POOLTAG_VADM              'Vadm'

#define MMVAD_PTESIZE                   ((H->vmm.tpMemoryModel == VMM_MEMORYMODEL_X86) ? 4 : 8)
#define MMVAD_MAXVADS_THRESHOLD         0x20000
#define MMVAD_SLOWQUERY_THRESHOLD_MS    1000

// ----------------------------------------------------------------------------
// DEFINES OF VAD STRUCTS FOR DIFFRENT WINDOWS VERSIONS
// Define the VADs here statically rather than parse offsets it from PDBs
// to keep the VAD functionality fast and independent of PDBs.
// ----------------------------------------------------------------------------

typedef enum _tdMMVAD_TYPE {
    VadNone                 = 0,
    VadDevicePhysicalMemory = 1,
    VadImageMap             = 2,
    VadAwe                  = 3,
    VadWriteWatch           = 4,
    VadLargePages           = 5,
    VadRotatePhysical       = 6,
    VadLargePageSection     = 7
} _MMVAD_TYPE;

// WinXP 32-bit
typedef struct _tdMMVAD32_XP {
    DWORD _Dummy1;
    DWORD PoolTag;
    // _MMVAD_SHORT
    DWORD StartingVpn;
    DWORD EndingVpn;
    DWORD Parent;
    DWORD LeftChild;
    DWORD RightChild;
    union {
        struct {
            DWORD CommitCharge      : 19;   // Pos 0
            DWORD PhysicalMapping   : 1;    // Pos 19
            DWORD ImageMap          : 1;    // Pos 20
            DWORD UserPhysicalPages : 1;    // Pos 21
            DWORD NoChange          : 1;    // Pos 22
            DWORD WriteWatch        : 1;    // Pos 23
            DWORD Protection        : 5;    // Pos 24
            DWORD LargePages        : 1;    // Pos 29
            DWORD MemCommit         : 1;    // Pos 30
            DWORD PrivateMemory     : 1;    // Pos 31
        };
        DWORD u;
    };
    // _MMVAD
    DWORD ControlArea;
    DWORD FirstPrototypePte;
    DWORD LastContiguousPte;
    union {
        struct {
            DWORD FileOffset        : 24;   // Pos 0
            DWORD SecNoChange       : 1;    // Pos 24
            DWORD OneSecured        : 1;    // Pos 25
            DWORD MultipleSecured   : 1;    // Pos 26
            DWORD ReadOnly          : 1;    // Pos 27
            DWORD LongVad           : 1;    // Pos 28
            DWORD ExtendableFile    : 1;    // Pos 29
            DWORD Inherit           : 1;    // Pos 30
            DWORD CopyOnWrite       : 1;    // Pos 31
        };
        DWORD u2;
    };
} _MMVAD32_XP;

// Vista/7 32-bit
typedef struct _tdMMVAD32_7 {
    DWORD _Dummy1;
    DWORD PoolTag;
    // _MMVAD_SHORT
    DWORD u1;
    DWORD LeftChild;
    DWORD RightChild;
    DWORD StartingVpn;
    DWORD EndingVpn;
    union {
        struct {
            DWORD CommitCharge      : 19;   // Pos 0
            DWORD NoChange          : 1;    // Pos 51
            DWORD VadType           : 3;    // Pos 52
            DWORD MemCommit         : 1;    // Pos 55
            DWORD Protection        : 5;    // Pos 56
            DWORD _Spare1           : 2;    // Pos 61
            DWORD PrivateMemory     : 1;    // Pos 63
        };
        DWORD u;
    };
    DWORD PushLock;
    DWORD u5;
    // _MMVAD
    union {
        struct {
            DWORD FileOffset        : 24;   // Pos 0
            DWORD SecNoChange       : 1;    // Pos 24
            DWORD OneSecured        : 1;    // Pos 25
            DWORD MultipleSecured   : 1;    // Pos 26
            DWORD _Spare2           : 1;    // Pos 27
            DWORD LongVad           : 1;    // Pos 28
            DWORD ExtendableFile    : 1;    // Pos 29
            DWORD Inherit           : 1;    // Pos 30
            DWORD CopyOnWrite       : 1;    // Pos 31
        };
        DWORD u2;
    };
    DWORD Subsection;
    DWORD FirstPrototypePte;
    DWORD LastContiguousPte;
    DWORD ViewLinks[2];
    DWORD VadsProcess;
} _MMVAD32_7;

// Vista/7 64-bit
typedef struct _tdMMVAD64_7 {
    DWORD _Dummy1;
    DWORD PoolTag;
    QWORD _Dummy2;
    // _MMVAD_SHORT
    QWORD u1;
    QWORD LeftChild;
    QWORD RightChild;
    QWORD StartingVpn;
    QWORD EndingVpn;
    union {
        struct {
            QWORD CommitCharge      : 51;   // Pos 0
            QWORD NoChange          : 1;    // Pos 51
            QWORD VadType           : 3;    // Pos 52
            QWORD MemCommit         : 1;    // Pos 55
            QWORD Protection        : 5;    // Pos 56
            QWORD _Spare1           : 2;    // Pos 61
            QWORD PrivateMemory     : 1;    // Pos 63
        };
        QWORD u;
    };
    QWORD PushLock;
    QWORD u5;
    // _MMVAD
    union {
        struct {
            DWORD FileOffset        : 24;   // Pos 0
            DWORD SecNoChange       : 1;    // Pos 24
            DWORD OneSecured        : 1;    // Pos 25
            DWORD MultipleSecured   : 1;    // Pos 26
            DWORD _Spare2           : 1;    // Pos 27
            DWORD LongVad           : 1;    // Pos 28
            DWORD ExtendableFile    : 1;    // Pos 29
            DWORD Inherit           : 1;    // Pos 30
            DWORD CopyOnWrite       : 1;    // Pos 31
        };
        QWORD u2;
    };
    QWORD Subsection;
    QWORD FirstPrototypePte;
    QWORD LastContiguousPte;
    QWORD ViewLinks[2];
    QWORD VadsProcess;
} _MMVAD64_7;

// Win8.0 32-bit
typedef struct _tdMMVAD32_80 {
    DWORD PoolTag;
    QWORD _Dummy2;
    // _MMVAD_SHORT
    DWORD __u1;
    DWORD LeftChild;
    DWORD RightChild;
    DWORD StartingVpn;
    DWORD EndingVpn;
    DWORD PushLock;
    union {
        struct {
            DWORD VadType           : 3;    // Pos 0
            DWORD Protection        : 5;    // Pos 3
            DWORD PreferredNode     : 6;    // Pos 8
            DWORD NoChange          : 1;    // Pos 14
            DWORD PrivateMemory     : 1;    // Pos 15
            DWORD Teb               : 1;    // Pos 16
            DWORD PrivateFixup      : 1;    // Pos 17
            DWORD _Spare1           : 13;   // Pos 18
            DWORD DeleteInProgress  : 1;    // Pos 31
        };
        DWORD u;
    };
    union {
        struct {
            DWORD CommitCharge      : 31;   // Pos 0
            DWORD MemCommit         : 1;    // Pos 31
        };
        DWORD u1;
    };
    DWORD EventList;
    DWORD ReferenceCount;
    // _MMVAD
    union {
        struct {
            DWORD FileOffset        : 24;   // Pos 0
            DWORD Large             : 1;    // Pos 24
            DWORD TrimBehind        : 1;    // Pos 25
            DWORD Inherit           : 1;    // Pos 26
            DWORD CopyOnWrite       : 1;    // Pos 27
            DWORD NoValidationNeeded : 1;   // Pos 28
            DWORD _Spare2           : 3;    // Pos 29
        };
        DWORD u2;
    };
    DWORD Subsection;
    DWORD FirstPrototypePte;
    DWORD LastContiguousPte;
    DWORD ViewLinks[2];
    DWORD VadsProcess;
    DWORD u4;
} _MMVAD32_80;

// Win8.0 64-bit
typedef struct _tdMMVAD64_80 {
    DWORD _Dummy1;
    DWORD PoolTag;
    QWORD _Dummy2;
    // _MMVAD_SHORT
    QWORD __u1;
    QWORD LeftChild;
    QWORD RightChild;
    DWORD StartingVpn;
    DWORD EndingVpn;
    QWORD PushLock;
    union {
        struct {
            DWORD VadType           : 3;    // Pos 0
            DWORD Protection        : 5;    // Pos 3
            DWORD PreferredNode     : 6;    // Pos 8
            DWORD NoChange          : 1;    // Pos 14
            DWORD PrivateMemory     : 1;    // Pos 15
            DWORD Teb               : 1;    // Pos 16
            DWORD PrivateFixup      : 1;    // Pos 17
            DWORD _Spare1           : 13;   // Pos 18
            DWORD DeleteInProgress  : 1;    // Pos 31
        };
        DWORD u;
    };
    union {
        struct {
            DWORD CommitCharge      : 31;   // Pos 0
            DWORD MemCommit         : 1;    // Pos 31
        };
        DWORD u1;
    };
    QWORD EventList;
    DWORD ReferenceCount;
    DWORD _Filler;
    // _MMVAD
    union {
        struct {
            DWORD FileOffset        : 24;   // Pos 0
            DWORD Large             : 1;    // Pos 24
            DWORD TrimBehind        : 1;    // Pos 25
            DWORD Inherit           : 1;    // Pos 26
            DWORD CopyOnWrite       : 1;    // Pos 27
            DWORD NoValidationNeeded : 1;   // Pos 28
            DWORD _Spare2           : 3;    // Pos 29
        };
        QWORD u2;
    };
    QWORD Subsection;
    QWORD FirstPrototypePte;
    QWORD LastContiguousPte;
    QWORD ViewLinks[2];
    QWORD VadsProcess;
    QWORD u4;
} _MMVAD64_80;

// Win8.1/10 32-bit
typedef struct _tdMMVAD32_10 {
    DWORD _Dummy1;
    DWORD PoolTag;
    // _MMVAD_SHORT
    DWORD Children[2];
    DWORD ParentValue;
    DWORD StartingVpn;
    DWORD EndingVpn;
    DWORD ReferenceCount;
    DWORD PushLock;
    DWORD u;    // no struct - bit order varies too much in Win10
    union {
        struct {
            DWORD CommitCharge      : 31;   // Pos 0
            DWORD MemCommit         : 1;    // Pos 31
        };
        DWORD u1;
    };
    DWORD EventList;
    // _MMVAD
    union {
        struct {
            DWORD FileOffset        : 24;   // Pos 0
            DWORD Large             : 1;    // Pos 24
            DWORD TrimBehind        : 1;    // Pos 25
            DWORD Inherit           : 1;    // Pos 26
            DWORD CopyOnWrite       : 1;    // Pos 27
            DWORD NoValidationNeeded : 1;   // Pos 28
            DWORD _Spare2           : 3;    // Pos 29
        };
        DWORD u2;
    };
    DWORD Subsection;
    DWORD FirstPrototypePte;
    DWORD LastContiguousPte;
    DWORD ViewLinks[2];
    DWORD VadsProcess;
    DWORD u4;
    DWORD FileObject;
} _MMVAD32_10;

// Win8.1/10 64-bit
typedef struct _tdMMVAD64_10 {
    DWORD _Dummy1;
    DWORD PoolTag;
    QWORD _Dummy2;
    // _MMVAD_SHORT
    QWORD Children[2];
    QWORD ParentValue;
    DWORD StartingVpn;
    DWORD EndingVpn;
    BYTE StartingVpnHigh;
    BYTE EndingVpnHigh;
    BYTE CommitChargeHigh;
    BYTE SpareNT64VadUChar;
    DWORD _Filler1;
    QWORD PushLock;
    DWORD u;    // no struct - bit order varies too much in Win10
    union {
        struct {
            DWORD CommitCharge      : 31;   // Pos 0
            DWORD MemCommit         : 1;    // Pos 31
        };
        DWORD u1;
    };
    QWORD EventList;
    // _MMVAD
    union {
        struct {
            DWORD FileOffset        : 24;   // Pos 0
            DWORD Large             : 1;    // Pos 24
            DWORD TrimBehind        : 1;    // Pos 25
            DWORD Inherit           : 1;    // Pos 26
            DWORD CopyOnWrite       : 1;    // Pos 27
            DWORD NoValidationNeeded : 1;   // Pos 28
            DWORD _Spare2           : 3;    // Pos 29
        };
        QWORD u2;
    };
    QWORD Subsection;
    QWORD FirstPrototypePte;
    QWORD LastContiguousPte;
    QWORD ViewLinks[2];
    QWORD VadsProcess;
    QWORD u4;
    QWORD FileObject;
} _MMVAD64_10;

/*
* Object manager callback function for object cleanup tasks.
*/
VOID MmVad_MemMapVad_CloseObCallback(_In_ PVOID pVmmOb)
{
    PVMMOB_MAP_VAD pOb = (PVMMOB_MAP_VAD)pVmmOb;
    LocalFree(pOb->pbMultiText);
}



// ----------------------------------------------------------------------------
// PTE MAP UTILITY / HELPER FUNCTIONS BELOW:
// ----------------------------------------------------------------------------

typedef struct tdMMVAD_PTEENTRY_FIND_CONTEXT {
    QWORD vaBase;
    QWORD vaEnd;
} MMVAD_PTEENTRY_FIND_CONTEXT, *PMMVAD_PTEENTRY_FIND_CONTEXT;

int MmVad_PteEntryFind_CmpFind(_In_ QWORD qwFind, _In_ QWORD qwEntry)
{
    PMMVAD_PTEENTRY_FIND_CONTEXT ctxFind = (PMMVAD_PTEENTRY_FIND_CONTEXT)qwFind;
    PVMM_MAP_PTEENTRY pEntry = (PVMM_MAP_PTEENTRY)qwEntry;
    if(pEntry->vaBase > ctxFind->vaEnd) { return -1; }
    if(pEntry->vaBase + (pEntry->cPages << 12) - 1 < ctxFind->vaBase) { return 1; }
    return 0;
}

/*
* Retrieve the lowest PTE entry index mathing a PTE memory region from a PTE map.
*/
_Success_(return)
BOOL MmVad_PteEntryFind(_In_ PVMMOB_MAP_PTE pPteMap, _In_ QWORD vaBase, _In_ QWORD vaEnd, _Out_ PDWORD piPteEntry)
{
    DWORD iMap = 0;
    MMVAD_PTEENTRY_FIND_CONTEXT ctx = { vaBase, vaEnd };
    if(!Util_qfind_ex((QWORD)&ctx, pPteMap->cMap, pPteMap->pMap, sizeof(VMM_MAP_PTEENTRY), (UTIL_QFIND_CMP_PFN)MmVad_PteEntryFind_CmpFind, &iMap)) { return FALSE; }
    while(iMap && (pPteMap->pMap[iMap - 1].vaBase + (pPteMap->pMap[iMap - 1].cPages << 12) - 1 > vaBase)) {
        iMap--;
    }
    *piPteEntry = iMap;
    return TRUE;
}

/*
* Retrive number of "valid" pte entries in memory region.
*/
_Success_(return != 0)
DWORD MmVad_PteEntryFind_RegionPageCount(_In_ PVMMOB_MAP_PTE pPteMap, _In_ QWORD vaBase, _In_ QWORD vaEnd)
{
    PVMM_MAP_PTEENTRY pe;
    QWORD iPteBase, iPteEnd;
    DWORD cPages = 0, iPteEntry = 0;
    if(!MmVad_PteEntryFind(pPteMap, vaBase, vaEnd, &iPteEntry)) { return 0; }
    while((iPteEntry < pPteMap->cMap)) {
        pe = pPteMap->pMap + iPteEntry;
        if(pe->vaBase > vaEnd) { break; }
        iPteBase = max(vaBase, pe->vaBase) >> 12;
        iPteEnd = min((vaEnd + 1) >> 12, (pe->vaBase >> 12) + pe->cPages);
        cPages += (DWORD)(iPteEnd - iPteBase);
        iPteEntry++;
    }
    return cPages;
}



// ----------------------------------------------------------------------------
// IMPLEMENTATION OF VAD PARSING FUNCTIONALITY FOR DIFFERENT WINDOWS VERSIONS:
// ----------------------------------------------------------------------------

/*
* Comparator / Sorting function for qsort of VMM_VADMAP_ENTRIES.
* -- v1
* -- v2
* -- return
*/
int MmVad_CmpVadEntry(const void *v1, const void *v2)
{
    return
        (*(PQWORD)v1 < *(PQWORD)v2) ? -1 :
        (*(PQWORD)v1 > * (PQWORD)v2) ? 1 : 0;
}

BOOL MmVad_Spider_PoolTagAny(_In_ DWORD dwPoolTag, _In_ DWORD cPoolTag, ...)
{
    va_list argp;
    dwPoolTag = _byteswap_ulong(dwPoolTag);
    va_start(argp, cPoolTag);
    while(cPoolTag) {
        if(dwPoolTag == va_arg(argp, DWORD)) {
            va_end(argp);
            return TRUE;
        }
        cPoolTag--;
    }
    va_end(argp);
    return FALSE;
}

PVMM_MAP_VADENTRY MmVad_Spider_MMVAD32_XP(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pSystemProcess, _In_ QWORD va, _In_ PVMMOB_MAP_VAD pmVad, _In_ POB_SET psAll, _In_ POB_SET psTry1, _In_opt_ POB_SET psTry2, _In_ QWORD fVmmRead, _In_ DWORD dwReserved)
{
    _MMVAD32_XP v = { 0 };
    PVMM_MAP_VADENTRY e;
    if(!VmmRead2(H, pSystemProcess, va, (PBYTE)&v, sizeof(_MMVAD32_XP), fVmmRead | VMM_FLAG_FORCECACHE_READ)) {
        ObSet_Push(psTry2, va);
        return NULL;
    }
    if((v.EndingVpn < v.StartingVpn) || !MmVad_Spider_PoolTagAny(v.PoolTag, 5, MMVAD_POOLTAG_VADS, MMVAD_POOLTAG_VAD, MMVAD_POOLTAG_VADL, MMVAD_POOLTAG_VADM, MMVAD_POOLTAG_VADF)) {
        return NULL;
    }
    // short vad
    e = &pmVad->pMap[pmVad->cMap++];
    if(VMM_KADDR32_8(v.LeftChild) && ObSet_Push(psAll, v.LeftChild - 8)) {
        ObSet_Push(psTry1, v.LeftChild - 8);
    }
    if(VMM_KADDR32_8(v.RightChild) && ObSet_Push(psAll, v.RightChild - 8)) {
        ObSet_Push(psTry1, v.RightChild - 8);
    }
    e->vaStart = (QWORD)v.StartingVpn << 12;
    e->vaEnd = ((QWORD)v.EndingVpn << 12) | 0xfff;
    e->CommitCharge = v.CommitCharge;
    e->MemCommit = v.MemCommit;
    e->VadType = 0;
    e->Protection = v.Protection;
    e->fPrivateMemory = v.PrivateMemory;
    if(VMM_POOLTAG(v.PoolTag, MMVAD_POOLTAG_VADL)) { e->VadType = VadLargePages; }
    // full vad
    if(v.PoolTag == MMVAD_POOLTAG_VADS) { return e; }
    e->vaSubsection = v.ControlArea + H->vmm.offset.FILE._CONTROL_AREA.cb;
    if(VMM_KADDR32_4(v.FirstPrototypePte)) {
        e->vaPrototypePte = v.FirstPrototypePte;
        e->cbPrototypePte = (DWORD)(v.LastContiguousPte - v.FirstPrototypePte + MMVAD_PTESIZE);
    }
    return e;
}

PVMM_MAP_VADENTRY MmVad_Spider_MMVAD32_7(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pSystemProcess, _In_ QWORD va, _In_ PVMMOB_MAP_VAD pmVad, _In_ POB_SET psAll, _In_ POB_SET psTry1, _In_opt_ POB_SET psTry2, _In_ QWORD fVmmRead, _In_ DWORD dwReserved)
{
    _MMVAD32_7 v = { 0 };
    PVMM_MAP_VADENTRY e;
    if(!VmmRead2(H, pSystemProcess, va, (PBYTE)&v, sizeof(_MMVAD32_7), fVmmRead | VMM_FLAG_FORCECACHE_READ)) {
        ObSet_Push(psTry2, va);
        return NULL;
    }
    if((v.EndingVpn < v.StartingVpn) || !MmVad_Spider_PoolTagAny(v.PoolTag, 5, MMVAD_POOLTAG_VADS, MMVAD_POOLTAG_VAD, MMVAD_POOLTAG_VADL, MMVAD_POOLTAG_VADM, MMVAD_POOLTAG_VADF)) {
        return NULL;
    }
    // short vad
    e = &pmVad->pMap[pmVad->cMap++];
    if(VMM_KADDR32_8(v.LeftChild) && ObSet_Push(psAll, v.LeftChild - 8)) {
        ObSet_Push(psTry1, v.LeftChild - 8);
    }
    if(VMM_KADDR32_8(v.RightChild) && ObSet_Push(psAll, v.RightChild - 8)) {
        ObSet_Push(psTry1, v.RightChild - 8);
    }
    e->vaStart = (QWORD)v.StartingVpn << 12;
    e->vaEnd = ((QWORD)v.EndingVpn << 12) | 0xfff;
    e->CommitCharge = v.CommitCharge;
    e->MemCommit = v.MemCommit;
    e->VadType = v.VadType;
    e->Protection = v.Protection;
    e->fPrivateMemory = v.PrivateMemory;
    // full vad
    if(v.PoolTag == MMVAD_POOLTAG_VADS) { return e; }
    e->vaSubsection = v.Subsection;
    if(VMM_KADDR32_4(v.FirstPrototypePte)) {
        e->vaPrototypePte = v.FirstPrototypePte;
        e->cbPrototypePte = (DWORD)(v.LastContiguousPte - v.FirstPrototypePte + MMVAD_PTESIZE);
    }
    return e;
}

PVMM_MAP_VADENTRY MmVad_Spider_MMVAD64_7(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pSystemProcess, _In_ QWORD va, _In_ PVMMOB_MAP_VAD pmVad, _In_ POB_SET psAll, _In_ POB_SET psTry1, _In_opt_ POB_SET psTry2, _In_ QWORD fVmmRead, _In_ DWORD dwReserved)
{
    _MMVAD64_7 v = { 0 };
    PVMM_MAP_VADENTRY e;
    if(!VmmRead2(H, pSystemProcess, va, (PBYTE)&v, sizeof(_MMVAD64_7), fVmmRead | VMM_FLAG_FORCECACHE_READ)) {
        ObSet_Push(psTry2, va);
        return NULL;
    }
    if((v.EndingVpn < v.StartingVpn) || !MmVad_Spider_PoolTagAny(v.PoolTag, 5, MMVAD_POOLTAG_VADS, MMVAD_POOLTAG_VAD, MMVAD_POOLTAG_VADL, MMVAD_POOLTAG_VADM, MMVAD_POOLTAG_VADF)) {
        return NULL;
    }
    // short vad
    e = &pmVad->pMap[pmVad->cMap++];
    if(VMM_KADDR64_16(v.LeftChild) && ObSet_Push(psAll, v.LeftChild - 0x10)) {
        ObSet_Push(psTry1, v.LeftChild - 0x10);
    }
    if(VMM_KADDR64_16(v.RightChild) && ObSet_Push(psAll, v.RightChild - 0x10)) {
        ObSet_Push(psTry1, v.RightChild - 0x10);
    }
    e->vaStart = (QWORD)v.StartingVpn << 12;
    e->vaEnd = ((QWORD)v.EndingVpn << 12) | 0xfff;
    e->CommitCharge = (DWORD)v.CommitCharge;
    e->MemCommit = (DWORD)v.MemCommit;
    e->VadType = (DWORD)v.VadType;
    e->Protection = (DWORD)v.Protection;
    e->fPrivateMemory = (DWORD)v.PrivateMemory;
    // full vad
    if(v.PoolTag == MMVAD_POOLTAG_VADS) { return e; }
    e->vaSubsection = v.Subsection;
    if(VMM_KADDR64_8(v.FirstPrototypePte)) {
        e->vaPrototypePte = v.FirstPrototypePte;
        e->cbPrototypePte = (DWORD)(v.LastContiguousPte - v.FirstPrototypePte + 8);
    }
    return e;
}

PVMM_MAP_VADENTRY MmVad_Spider_MMVAD32_80(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pSystemProcess, _In_ QWORD va, _In_ PVMMOB_MAP_VAD pmVad, _In_ POB_SET psAll, _In_ POB_SET psTry1, _In_opt_ POB_SET psTry2, _In_ QWORD fVmmRead, _In_ DWORD dwReserved)
{
    _MMVAD32_80 v = { 0 };
    PVMM_MAP_VADENTRY e;
    if(!VmmRead2(H, pSystemProcess, va, (PBYTE)&v, sizeof(_MMVAD32_80), fVmmRead | VMM_FLAG_FORCECACHE_READ)) {
        ObSet_Push(psTry2, va);
        return NULL;
    }
    if((v.EndingVpn < v.StartingVpn) || !MmVad_Spider_PoolTagAny(v.PoolTag, 5, MMVAD_POOLTAG_VADS, MMVAD_POOLTAG_VAD, MMVAD_POOLTAG_VADL, MMVAD_POOLTAG_VADM, MMVAD_POOLTAG_VADF)) {
        return NULL;
    }
    // short vad
    e = &pmVad->pMap[pmVad->cMap++];
    if(VMM_KADDR64_16(v.LeftChild) && ObSet_Push(psAll, v.LeftChild - 8)) {
        ObSet_Push(psTry1, v.LeftChild - 8);
    }
    if(VMM_KADDR64_16(v.RightChild) && ObSet_Push(psAll, v.RightChild - 8)) {
        ObSet_Push(psTry1, v.RightChild - 8);
    }
    e->vaStart = (QWORD)v.StartingVpn << 12;
    e->vaEnd = ((QWORD)v.EndingVpn << 12) | 0xfff;
    e->CommitCharge = (DWORD)v.CommitCharge;
    e->MemCommit = (DWORD)v.MemCommit;
    e->VadType = (DWORD)v.VadType;
    e->Protection = (DWORD)v.Protection;
    e->fPrivateMemory = (DWORD)v.PrivateMemory;
    // full vad
    if(v.PoolTag == MMVAD_POOLTAG_VADS) { return e; }
    e->flags[2] = v.u2;
    e->vaSubsection = v.Subsection;
    if(VMM_KADDR32_8(v.FirstPrototypePte)) {
        e->vaPrototypePte = v.FirstPrototypePte;
        e->cbPrototypePte = (DWORD)(v.LastContiguousPte - v.FirstPrototypePte + 8);
    }
    return e;
}

PVMM_MAP_VADENTRY MmVad_Spider_MMVAD64_80(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pSystemProcess, _In_ QWORD va, _In_ PVMMOB_MAP_VAD pmVad, _In_ POB_SET psAll, _In_ POB_SET psTry1, _In_opt_ POB_SET psTry2, _In_ QWORD fVmmRead, _In_ DWORD dwReserved)
{
    _MMVAD64_80 v = { 0 };
    PVMM_MAP_VADENTRY e;
    if(!VmmRead2(H, pSystemProcess, va, (PBYTE)&v, sizeof(_MMVAD64_80), fVmmRead | VMM_FLAG_FORCECACHE_READ)) {
        ObSet_Push(psTry2, va);
        return NULL;
    }
    if((v.EndingVpn < v.StartingVpn) || !MmVad_Spider_PoolTagAny(v.PoolTag, 5, MMVAD_POOLTAG_VADS, MMVAD_POOLTAG_VAD, MMVAD_POOLTAG_VADL, MMVAD_POOLTAG_VADM, MMVAD_POOLTAG_VADF)) {
        return NULL;
    }
    // short vad
    e = &pmVad->pMap[pmVad->cMap++];
    if(VMM_KADDR64_16(v.LeftChild) && ObSet_Push(psAll, v.LeftChild - 0x10)) {
        ObSet_Push(psTry1, v.LeftChild - 0x10);
    }
    if(VMM_KADDR64_16(v.RightChild) && ObSet_Push(psAll, v.RightChild - 0x10)) {
        ObSet_Push(psTry1, v.RightChild - 0x10);
    }
    e->vaStart = (QWORD)v.StartingVpn << 12;
    e->vaEnd = ((QWORD)v.EndingVpn << 12) | 0xfff;
    e->CommitCharge = v.CommitCharge;
    e->MemCommit = v.MemCommit;
    e->VadType = v.VadType;
    e->Protection = v.Protection;
    e->fPrivateMemory = v.PrivateMemory;
    // full vad
    if(v.PoolTag == MMVAD_POOLTAG_VADS) { return e; }
    e->flags[2] = (DWORD)v.u2;
    e->vaSubsection = v.Subsection;
    if(VMM_KADDR64_8(v.FirstPrototypePte)) {
        e->vaPrototypePte = v.FirstPrototypePte;
        e->cbPrototypePte = (DWORD)(v.LastContiguousPte - v.FirstPrototypePte);
    }
    return e;
}

PVMM_MAP_VADENTRY MmVad_Spider_MMVAD32_10(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pSystemProcess, _In_ QWORD va, _In_ PVMMOB_MAP_VAD pmVad, _In_ POB_SET psAll, _In_ POB_SET psTry1, _In_opt_ POB_SET psTry2, _In_ QWORD fVmmRead, _In_ DWORD dwFlagsBitMask)
{
    _MMVAD32_10 v = { 0 };
    PVMM_MAP_VADENTRY e;
    if(!VmmRead2(H, pSystemProcess, va, (PBYTE)&v, sizeof(_MMVAD32_10), fVmmRead | VMM_FLAG_FORCECACHE_READ)) {
        ObSet_Push(psTry2, va);
        return NULL;
    }
    if((v.EndingVpn < v.StartingVpn) || !MmVad_Spider_PoolTagAny(v.PoolTag, 5, MMVAD_POOLTAG_VADS, MMVAD_POOLTAG_VAD, MMVAD_POOLTAG_VADL, MMVAD_POOLTAG_VADM, MMVAD_POOLTAG_VADF)) {
        return NULL;
    }
    // short vad
    e = &pmVad->pMap[pmVad->cMap++];
    if(VMM_KADDR32_8(v.Children[0]) && ObSet_Push(psAll, v.Children[0] - 8)) {
        ObSet_Push(psTry1, v.Children[0] - 8);
    }
    if(VMM_KADDR32_8(v.Children[1]) && ObSet_Push(psAll, v.Children[1] - 8)) {
        ObSet_Push(psTry1, v.Children[1] - 8);
    }
    e->vaStart = (QWORD)v.StartingVpn << 12;
    e->vaEnd = ((QWORD)v.EndingVpn << 12) | 0xfff;
    e->CommitCharge = v.CommitCharge;
    e->MemCommit = v.MemCommit;
    e->VadType = 0x07 & (v.u >> (dwFlagsBitMask & 0xff));
    e->Protection = 0x1f & (v.u >> ((dwFlagsBitMask >> 8) & 0xff));
    e->fPrivateMemory = 0x01 & (v.u >> ((dwFlagsBitMask >> 16) & 0xff));
    // full vad
    if(v.PoolTag == MMVAD_POOLTAG_VADS) { return e; }
    e->flags[2] = v.u2;
    e->vaSubsection = v.Subsection;
    if(VMM_KADDR32_4(v.FirstPrototypePte)) {
        e->vaPrototypePte = v.FirstPrototypePte;
        e->cbPrototypePte = (DWORD)(v.LastContiguousPte - v.FirstPrototypePte);
    }
    return e;
}

PVMM_MAP_VADENTRY MmVad_Spider_MMVAD64_10(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pSystemProcess, _In_ QWORD va, _In_ PVMMOB_MAP_VAD pmVad, _In_ POB_SET psAll, _In_ POB_SET psTry1, _In_opt_ POB_SET psTry2, _In_ QWORD fVmmRead, _In_ DWORD dwFlagsBitMask)
{
    _MMVAD64_10 v = { 0 };
    PVMM_MAP_VADENTRY e;
    if(!VmmRead2(H, pSystemProcess, va, (PBYTE)&v, sizeof(_MMVAD64_10), fVmmRead | VMM_FLAG_FORCECACHE_READ)) {
        ObSet_Push(psTry2, va);
        return NULL;
    }
    if((v.EndingVpnHigh < v.StartingVpnHigh) || (v.EndingVpn < v.StartingVpn) || !MmVad_Spider_PoolTagAny(v.PoolTag, 5, MMVAD_POOLTAG_VADS, MMVAD_POOLTAG_VAD, MMVAD_POOLTAG_VADL, MMVAD_POOLTAG_VADM, MMVAD_POOLTAG_VADF)) {
        return NULL;
    }
    // short vad
    e = &pmVad->pMap[pmVad->cMap++];
    if(VMM_KADDR64_16(v.Children[0]) && ObSet_Push(psAll, v.Children[0] - 0x10)) {
        ObSet_Push(psTry1, v.Children[0] - 0x10);
    }
    if(VMM_KADDR64_16(v.Children[1]) && ObSet_Push(psAll, v.Children[1] - 0x10)) {
        ObSet_Push(psTry1, v.Children[1] - 0x10);
    }
    e->vaStart = ((QWORD)v.StartingVpnHigh << (32 + 12)) | ((QWORD)v.StartingVpn << 12);
    e->vaEnd = ((QWORD)v.EndingVpnHigh << (32 + 12)) | ((QWORD)v.EndingVpn << 12) | 0xfff;
    e->CommitCharge = (DWORD)v.CommitCharge;
    e->MemCommit = (DWORD)v.MemCommit;
    e->VadType = 0x07 & (v.u >> (dwFlagsBitMask & 0xff));
    e->Protection = 0x1f & (v.u >> ((dwFlagsBitMask >> 8) & 0xff));
    e->fPrivateMemory = 0x01 & (v.u >> ((dwFlagsBitMask >> 16) & 0xff));
    // full vad
    if(v.PoolTag == MMVAD_POOLTAG_VADS) { return e; }
    e->flags[2] = (DWORD)v.u2;
    e->vaSubsection = v.Subsection;
    if(VMM_KADDR64_8(v.FirstPrototypePte)) {
        e->vaPrototypePte = v.FirstPrototypePte;
        e->cbPrototypePte = (DWORD)(v.LastContiguousPte - v.FirstPrototypePte + 8);
    }
    return e;
}

VOID MmVad_Spider_DoWork(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pSystemProcess, _In_ PVMM_PROCESS pProcess, _In_ QWORD fVmmRead)
{
    BOOL f, f32 = H->vmm.f32;
    DWORD dwVersionBuild = H->vmm.kernel.dwVersionBuild;
    QWORD i, va, fVmmReadSpider;
    DWORD cMax, cVads, dwFlagsBitMask = 0;
    PVMM_MAP_VADENTRY eVad;
    PVMMOB_MAP_VAD pmObVad = NULL, pmObVadTemp;
    POB_SET psObAll = NULL, psObTry1 = NULL, psObTry2 = NULL, psObPrefetch = NULL;
    PVMM_MAP_VADENTRY(*pfnMmVad_Spider)(VMM_HANDLE, PVMM_PROCESS, QWORD, PVMMOB_MAP_VAD, POB_SET, POB_SET, POB_SET, QWORD, DWORD);
    if(!(H->vmm.tpSystem == VMM_SYSTEM_WINDOWS_64 || H->vmm.tpSystem == VMM_SYSTEM_WINDOWS_32)) { goto fail; }
    // 1: retrieve # of VAD entries and sanity check.
    if(dwVersionBuild >= 9600) {
        // Win8.1 and later -> fetch # of RtlBalancedNode from EPROCESS.
        cVads = (DWORD)VMM_EPROCESS_PTR(f32, pProcess, H->vmm.offset.EPROCESS.VadRoot + (f32 ? 8 : 0x10));
    } else if(dwVersionBuild >= 6000) {
        // WinVista::Win8.0 -> fetch # of AvlNode from EPROCESS.
        i = (dwVersionBuild < 9200) ? (f32 ? 0x14 : 0x28) : (f32 ? 0x1c : 0x18);
        cVads = ((DWORD)VMM_EPROCESS_PTR(f32, pProcess, H->vmm.offset.EPROCESS.VadRoot + i) >> 8);
    } else {
        // WinXP
        cVads = (DWORD)VMM_EPROCESS_DWORD(pProcess, 0x240);
    }
    if(cVads > MMVAD_MAXVADS_THRESHOLD) {
        VmmLog(H, MID_VMM, LOGLEVEL_VERBOSE, "BAD #VAD VALUE- PID: %i #VAD: %x", pProcess->dwPID, cVads);
        cVads = MMVAD_MAXVADS_THRESHOLD;
    }
    // 2: allocate and retrieve objects required for processing
    if(!(pmObVad = Ob_AllocEx(H, OB_TAG_MAP_VAD, LMEM_ZEROINIT, sizeof(VMMOB_MAP_VAD) + cVads * sizeof(VMM_MAP_VADENTRY), MmVad_MemMapVad_CloseObCallback, NULL))) { goto fail; }
    if((cVads == 0) && (pProcess->dwPID != 4)) {    // No VADs
        VmmLog(H, MID_VMM, LOGLEVEL_VERBOSE, "NO VAD FOR PROCESS - PID: %i STATE: %i NAME: %s", pProcess->dwPID, pProcess->dwState, pProcess->szName);
        pProcess->Map.pObVad = Ob_INCREF(pmObVad);
        goto fail;
    }
    cMax = cVads;
    if(!(psObAll = ObSet_New(H))) { goto fail; }
    if(!(psObTry1 = ObSet_New(H))) { goto fail; }
    if(!(psObTry2 = ObSet_New(H))) { goto fail; }
    // 3: retrieve initial VAD node entry
    f = ((dwVersionBuild >= 6000) && (dwVersionBuild < 9600));    // AvlTree (Vista::Win8.0
    for(i = (f ? 1 : 0); i < (f ? 4 : 1); i++) {
        va = VMM_EPROCESS_PTR(f32, pProcess, H->vmm.offset.EPROCESS.VadRoot + i * (f32 ? 4 : 8));
        if(f32 && !VMM_KADDR32_8(va)) { continue; }
        if(!f32 && !VMM_KADDR64_16(va)) { continue; }
        va -= f32 ? 8 : 0x10;
        ObSet_Push(psObAll, va);
        ObSet_Push(psObTry2, va);
    }
    if(!ObSet_Size(psObTry2)) { goto fail; }
    if(dwVersionBuild >= 9600) {
        // Win8.1 and later
        pfnMmVad_Spider = f32 ? MmVad_Spider_MMVAD32_10 : MmVad_Spider_MMVAD64_10;
        if(dwVersionBuild >= 20348) {    // bitmask offset for empty:PrivateMemory:Protection:VadType
            dwFlagsBitMask = 0x00150704;
        } else if(dwVersionBuild >= 18362) {
            dwFlagsBitMask = 0x00140704;
        } else if(dwVersionBuild >= 17134) {
            dwFlagsBitMask = 0x000e0300;
        } else {
            dwFlagsBitMask = 0x000f0300;
        }
    } else if(dwVersionBuild >= 9200) {
        // Win8.0
        pfnMmVad_Spider = f32 ? MmVad_Spider_MMVAD32_80 : MmVad_Spider_MMVAD64_80;
    } else if(dwVersionBuild >= 6000) {
        // WinVista :: Win7
        pfnMmVad_Spider = f32 ? MmVad_Spider_MMVAD32_7 : MmVad_Spider_MMVAD64_7;
    } else {
        // WinXP
        pfnMmVad_Spider = MmVad_Spider_MMVAD32_XP;
    }
    // 4: cache: prefetch previous addresses
    if((psObPrefetch = ObContainer_GetOb(pProcess->pObPersistent->pObCMapVadPrefetch))) {
        VmmCachePrefetchPages3(H, pSystemProcess, psObPrefetch, sizeof(_MMVAD64_10), fVmmRead);
        Ob_DECREF_NULL(&psObPrefetch);
    }
    // 5: Spider VAD tree in an efficient way (minimize non-cached reads).
    //    NB! Read flags are altered to temporarily disregard no-cache flag.
    //        It's done to avoid extreme amounts of reads on larger VAD trees.
    fVmmReadSpider = fVmmRead;
    if(fVmmReadSpider & VMM_FLAG_NOCACHE) {
        fVmmReadSpider = (fVmmReadSpider & ~VMM_FLAG_NOCACHE);
    }
    while((pmObVad->cMap < cMax) && (ObSet_Size(psObTry1) || ObSet_Size(psObTry2))) {
        // fetch vad entries 2nd attempt
        VmmCachePrefetchPages3(H, pSystemProcess, psObTry2, sizeof(_MMVAD64_10), fVmmReadSpider);
        while((pmObVad->cMap < cMax) && (va = ObSet_Pop(psObTry2))) {
            if((eVad = pfnMmVad_Spider(H, pSystemProcess, va, pmObVad, psObAll, psObTry1, NULL, fVmmReadSpider, dwFlagsBitMask))) {
                if(eVad->CommitCharge > ((eVad->vaEnd + 1 - eVad->vaStart) >> 12)) { eVad->CommitCharge = 0; }
                eVad->vaVad = va + (f32 ? 8 : 0x10);
                eVad->cbuText = 1;
                eVad->uszText = "";
                if(eVad->cbPrototypePte > 0x01000000) { eVad->cbPrototypePte = MMVAD_PTESIZE * (DWORD)((0x1000 + eVad->vaEnd - eVad->vaStart) >> 12); }
            }
        }
        // fetch vad entries 1st attempt
        while((pmObVad->cMap < cMax) && (ObSet_Size(psObTry2) < (VMM_CACHE_REGION_MEMS_PHYS >> 1)) && (va = ObSet_Pop(psObTry1))) {
            if((eVad = pfnMmVad_Spider(H, pSystemProcess, va, pmObVad, psObAll, psObTry1, psObTry2, fVmmReadSpider, dwFlagsBitMask))) {
                if(eVad->CommitCharge > ((eVad->vaEnd + 1 - eVad->vaStart) >> 12)) { eVad->CommitCharge = 0; }
                eVad->vaVad = va + (f32 ? 8 : 0x10);
                eVad->cbuText = 1;
                eVad->uszText = "";
                if(eVad->cbPrototypePte > 0x01000000) { eVad->cbPrototypePte = MMVAD_PTESIZE * (DWORD)((0x1000 + eVad->vaEnd - eVad->vaStart) >> 12); }
            }
        }
    }
    // 6: sort result
    if(pmObVad->cMap > 1) {
        qsort(pmObVad->pMap, pmObVad->cMap, sizeof(VMM_MAP_VADENTRY), MmVad_CmpVadEntry);
    }
    // 7: cache: update
    ObContainer_SetOb(pProcess->pObPersistent->pObCMapVadPrefetch, psObAll);
    // 8: shrink oversized result object (if sufficiently too large)
    if(pmObVad->cMap + 0x10 < cMax) {
        pmObVadTemp = pmObVad;
        if(!(pmObVad = Ob_AllocEx(H, OB_TAG_MAP_VAD, 0, sizeof(VMMOB_MAP_VAD) + pmObVadTemp->cMap * sizeof(VMM_MAP_VADENTRY), MmVad_MemMapVad_CloseObCallback, NULL))) { goto fail; }
        memcpy(((POB_DATA)pmObVad)->pb, ((POB_DATA)pmObVadTemp)->pb, pmObVad->ObHdr.cbData);
        Ob_DECREF_NULL(&pmObVadTemp);
    }
    pProcess->Map.pObVad = Ob_INCREF(pmObVad);
fail:
    Ob_DECREF(pmObVad);
    Ob_DECREF(psObAll);
    Ob_DECREF(psObTry1);
    Ob_DECREF(psObTry2);
}

/*
* Maps a _SECTION object onto the VAD map. (This is only valid for Windows 10+).
* The MMVAD.SubSection points to the subsection which is always trailing the _CONTROL_AREA.
* The _SECTION object from the handles map is used to find the same _CONTROL_AREA.
* -- H
* -- pSystemProcess
* -- pProcess
* -- pVadMap
* -- psm
* -- fVmmRead
*/
VOID MmVad_ExtendedInfoFetch_FillSectionNames(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pSystemProcess, _In_ PVMM_PROCESS pProcess, _In_ PVMMOB_MAP_VAD pVadMap, _In_ POB_STRMAP psm, _In_ QWORD fVmmRead)
{
    DWORD i, iType, cType;
    QWORD vaControlArea;
    POB_MAP pmObControlArea2Object = NULL;
    PVMMOB_MAP_OBJECT pObObjectMap = NULL;
    PVMM_MAP_OBJECTENTRY peObject;
    PVMM_MAP_VADENTRY peVad;
    // 1: fetch object map and set up control area to object map:
    if(!(pmObControlArea2Object = ObMap_New(H, OB_MAP_FLAGS_OBJECT_VOID))) { goto fail; }
    if(!(VmmMap_GetObject(H, &pObObjectMap))) { goto fail; }
    iType = pObObjectMap->iTypeSortBase[H->vmm.ObjectTypeTable.tpSection];
    cType = pObObjectMap->cType[H->vmm.ObjectTypeTable.tpSection] + iType;
    for(i = iType; i < cType; i++) {
        peObject = &pObObjectMap->pMap[pObObjectMap->piTypeSort[i]];
        if(peObject->ExtInfo.va) {
            ObMap_Push(pmObControlArea2Object, peObject->ExtInfo.va, peObject);
        }
    }
    // 2: fill in the VAD map with the SECTION object names:
    for(i = 0; i < pVadMap->cMap; i++) {
        peVad = pVadMap->pMap + i;
        if(peVad->fPageFile && peVad->vaSubsection) {
            vaControlArea = pVadMap->pMap[i].vaSubsection - H->vmm.offset.FILE._CONTROL_AREA.cb;
            if((peObject = ObMap_GetByKey(pmObControlArea2Object, vaControlArea))) {
                ObStrMap_PushUU_snprintf_s(psm, &peVad->uszText, &peVad->cbuText, "SECTION-%llx %s", peObject->va, peObject->uszName);
            }
        }
    }
fail:
    Ob_DECREF(pmObControlArea2Object);
    Ob_DECREF(pObObjectMap);
}

/*
* Fetch extended information such as file and image names into the buffer
* pProcess->pObMemMapVad->wszText which will be allocated by the function
* and must be free'd upon cleanup of pObMemMapVad.
* NB! MUST BE CALLED IN THREAD-SAFE WAY AND MUST NOT HAVE A PREVIOUS BUFFER!
* -- H
* -- pSystemProcess
* -- pProcess
* -- tp = VMM_VADMAP_TP_*
* -- fVmmRead
*/
VOID MmVad_ExtendedInfoFetch(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pSystemProcess, _In_ PVMM_PROCESS pProcess, _In_ VMM_VADMAP_TP tp, _In_ QWORD fVmmRead)
{
    BOOL f, fSharedCacheMap = FALSE, f32 = H->vmm.f32;
    DWORD dwVersionBuild = H->vmm.kernel.dwVersionBuild;
    WORD oControlArea_FilePointer;
    DWORD cMax, cVads = 0;
    BYTE pbBuffer[0x60];
    PQWORD pva = NULL;
    QWORD i, j, va;
    PVMM_MAP_VADENTRY peVad, *ppeVads;
    PVMMOB_MAP_VAD pVadMap = NULL;
    PVMMOB_MAP_PTE pObPteMap = NULL;
    PVMMOB_MAP_HEAP pObHeapMap = NULL;
    PVMMOB_MAP_THREAD pObThreadMap = NULL;
    POB_STRMAP psmOb = NULL;
    pVadMap = pProcess->Map.pObVad;
    if(tp == VMM_VADMAP_TP_FULL) {
        if(!(psmOb = ObStrMap_New(H, 0))) { goto cleanup; }
    }
    // count max potential vads and allocate.
    {
        for(i = 0, cMax = pVadMap->cMap; i < cMax; i++) {
            va = pVadMap->pMap[i].vaSubsection;
            if(VMM_KADDR_4_8(f32, va)) {
                cVads++;
            }
        }
        if(!cVads || !(pva = LocalAlloc(LMEM_ZEROINIT, (SIZE_T)cVads * 0x18))) { goto cleanup; }
        ppeVads = (PVMM_MAP_VADENTRY*)(pva + (SIZE_T)cVads * 2);
    }
    // get subsection addresses from vad.
    {
        for(i = 0, j = 0, cMax = pVadMap->cMap; (i < cMax) && (j < cVads); i++) {
            va = pVadMap->pMap[i].vaSubsection;
            if(VMM_KADDR_4_8(f32, va)) {
                ppeVads[j] = pVadMap->pMap + i;
                pva[j++] = va;
            }
        }
    }
    // fetch subsection -> pointer to control area (1st address ptr in subsection)
    if((dwVersionBuild >= 6000)) {   // Not WinXP (ControlArea already in map subsection field).
        VmmCachePrefetchPages4(H, pSystemProcess, cVads, pva, 8, fVmmRead);
        for(i = 0, va = 0; i < cVads; i++) {
            f = pva[i] &&
                VmmRead2(H, pSystemProcess, pva[i], (PBYTE)&va, f32 ? 4 : 8, fVmmRead | VMM_FLAG_FORCECACHE_READ) &&
                VMM_KADDR_8_16(f32, va);
            pva[i] = f ? (va - 0x10) : 0;
        }
    }
    // fetch _CONTROL_AREA -> pointer to _FILE_OBJECT
    {
        VmmCachePrefetchPages4(H, pSystemProcess, cVads, pva, 0x50, fVmmRead);
        oControlArea_FilePointer = f32 ?
            ((dwVersionBuild <= 7601) ? 0x24 : 0x20) :   // 32-bit win7sp1- or win8.0+
            ((dwVersionBuild <= 6000) ? 0x30 : 0x40);    // 64-bit vistasp0- or vistasp1+
        for(i = 0; i < cVads; i++) {
            // pointer to _FILE_OBJECT
            f = pva[i] &&
                VmmRead2(H, pSystemProcess, pva[i], pbBuffer, sizeof(pbBuffer), fVmmRead | VMM_FLAG_FORCECACHE_READ) &&
                (VMM_POOLTAG_PREPENDED(f32, pbBuffer, 0x10, 'MmCa') || VMM_POOLTAG_PREPENDED(f32, pbBuffer, 0x10, 'MmCi')) &&
                (va = VMM_PTR_OFFSET_EX_FAST_REF(f32, pbBuffer + 0x10, oControlArea_FilePointer)) &&
                VMM_KADDR_8_16(f32, va);
            if(pva[i] && !f && VMM_POOLTAG_PREPENDED(f32, pbBuffer, 0x10, 'MmCa')) { ppeVads[i]->fPageFile = 1; }
            if(f && VMM_POOLTAG_PREPENDED(f32, pbBuffer, 0x10, 'MmCa')) {
                ppeVads[i]->fFile = 1;
                ppeVads[i]->vaFileObject = va;
            }
            if(f && VMM_POOLTAG_PREPENDED(f32, pbBuffer, 0x10, 'MmCi')) {
                ppeVads[i]->fImage = 1;
                ppeVads[i]->vaFileObject = va;
            }
            if(f && (tp == VMM_VADMAP_TP_FULL)) {
                // _FILE_OBJECT.FileName [_UNICODE_STRING]
                ObStrMap_Push_UnicodeObject(psmOb, f32, va + (f32 ? O32_FILE_OBJECT_FileName : O64_FILE_OBJECT_FileName), &ppeVads[i]->uszText, &ppeVads[i]->cbuText);
            }
        }
    }
    // [ page count set ]
    if(!pVadMap->cPage && VmmMap_GetPte(H, pProcess, &pObPteMap, FALSE)) {
        for(i = 0, cMax = pVadMap->cMap; i < cMax; i++) {
            peVad = &pVadMap->pMap[i];
            peVad->cVadExPagesBase = pVadMap->cPage;
            if(peVad->fFile || peVad->fImage) {
                peVad->cVadExPages = (DWORD)((peVad->vaEnd - peVad->vaStart + 1) >> 12);
            } else {
                peVad->cVadExPages = MmVad_PteEntryFind_RegionPageCount(pObPteMap, peVad->vaStart, peVad->vaEnd);
            }
            pVadMap->cPage += peVad->cVadExPages;
        }
    }
    // [ terminate if partial ]
    if(tp == VMM_VADMAP_TP_PARTIAL) {
        pVadMap->tp = tp;
        goto cleanup;
    }
    // [ heap map parse ]
    if(VmmMap_GetHeap(H, pProcess, &pObHeapMap)) {
        for(i = 0; i < pObHeapMap->cSegments; i++) {
            if((peVad = VmmMap_GetVadEntry(H, pVadMap, pObHeapMap->pSegments[i].va))) {
                peVad->fHeap = 1;
                peVad->HeapNum = pObHeapMap->pSegments[i].iHeap;
                if(peVad->cbuText < 2) {
                    ObStrMap_PushUU_snprintf_s(psmOb, &peVad->uszText, &peVad->cbuText, "HEAP-%02X [%s]", peVad->HeapNum, VMM_HEAP_SEGMENT_TP_STR[pObHeapMap->pSegments[i].tp]);
                }
            }
        }
    }
    // [ thread map parse ]
    if(VmmMap_GetThread(H, pProcess, &pObThreadMap)) {
        for(i = 0; i < pObThreadMap->cMap; i++) {
            if((peVad = VmmMap_GetVadEntry(H, pVadMap, pObThreadMap->pMap[i].vaTeb))) {
                peVad->fTeb = TRUE;
                if(peVad->cbuText < 2) {
                    ObStrMap_PushUU_snprintf_s(psmOb, &peVad->uszText, &peVad->cbuText, "TEB-%04X", (WORD)min(0xffff, pObThreadMap->pMap[i].dwTID));
                }
            }
            if((peVad = VmmMap_GetVadEntry(H, pVadMap, pObThreadMap->pMap[i].vaStackLimitUser))) {
                peVad->fStack = TRUE;
                if(peVad->cbuText < 2) {
                    ObStrMap_PushUU_snprintf_s(psmOb, &peVad->uszText, &peVad->cbuText, "STACK-%04X", (WORD)min(0xffff, pObThreadMap->pMap[i].dwTID));
                }
            }
        }
    }
    // [ object _SECTION names ]
    if((tp == VMM_VADMAP_TP_FULL) && (H->vmm.kernel.dwVersionBuild >= 10240)) {
        MmVad_ExtendedInfoFetch_FillSectionNames(H, pSystemProcess, pProcess, pVadMap, psmOb, fVmmRead);
    }
    // cleanup
    pVadMap->tp = tp;
cleanup:
    ObStrMap_FinalizeAllocU_DECREF_NULL(&psmOb, &pVadMap->pbMultiText, &pVadMap->cbMultiText);
    Ob_DECREF(pObThreadMap);
    Ob_DECREF(pObHeapMap);
    Ob_DECREF(pObPteMap);
    LocalFree(pva);
}

_Success_(return)
BOOL MmVad_PrototypePteArray_FetchNew_PoolHdrVerify(_In_ PBYTE pb, _In_ DWORD cbDataOffsetPoolHdr)
{
    DWORD o;
    if(cbDataOffsetPoolHdr < 0x10) {
        return !cbDataOffsetPoolHdr || ('tSmM' == *(PDWORD)pb);
    }
    for(o = 0; o < cbDataOffsetPoolHdr; o += 4) {
        if('tSmM' == *(PDWORD)(pb + o)) { return TRUE; }    // check for MmSt pool header in various locations
    }
    return FALSE;
}

/*
* Fetch an array of prototype pte's into the cache.
* -- pSystemProcess
* -- pVad
* -- fVmmRead
*/
VOID MmVad_PrototypePteArray_FetchNew(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pSystemProcess, _In_ PVMM_MAP_VADENTRY pVad, _In_ QWORD fVmmRead)
{
    PBYTE pbData;
    POB_DATA e = NULL;
    DWORD cbData, cbDataOffsetPoolHdr = 0;
    cbData = pVad->cbPrototypePte;
    // 1: santity check size
    if(cbData > 0x00010000) {   // most probably an error, file > 32MB
        cbData = MMVAD_PTESIZE * (DWORD)((0x1000 + pVad->vaEnd - pVad->vaStart) >> 12);
        if(cbData > 0x00010000) { return; }
    }
    // 2: pool header offset (if any)
    if(pVad->vaPrototypePte & 0xfff) {
        if(H->vmm.kernel.dwVersionBuild >= 9200) {             // WIN8.0 and later
            cbDataOffsetPoolHdr = H->vmm.f32 ? 0x04 : 0x0c;
        } else {
            // WinXP to Win7 - pool header seems to be varying between these zero and these offsets, check for them all...
            cbDataOffsetPoolHdr = H->vmm.f32 ? 0x34 : 0x5c;
            if((pVad->vaStart & 0xfff) < cbDataOffsetPoolHdr) { cbDataOffsetPoolHdr = 0; }
        }
        cbData += cbDataOffsetPoolHdr;
    }
    // 3: fetch prototype page table entries
    if(!(pbData = LocalAlloc(0, cbData))) { return; }
    if(VmmRead2(H, pSystemProcess, pVad->vaPrototypePte - cbDataOffsetPoolHdr, pbData, cbData, fVmmRead)) {
        if(MmVad_PrototypePteArray_FetchNew_PoolHdrVerify(pbData, cbDataOffsetPoolHdr)) {
            if((e = Ob_AllocEx(H, OB_TAG_VAD_MEM, 0, sizeof(OB) + cbData - cbDataOffsetPoolHdr, NULL, NULL))) {
                memcpy(e->pb, pbData + cbDataOffsetPoolHdr, cbData - cbDataOffsetPoolHdr);
            }
        }
    }
    if(!e) {
        e = Ob_AllocEx(H, OB_TAG_VAD_MEM, 0, sizeof(OB), NULL, NULL);
    }
    if(e) {
        ObMap_Push(H->vmm.Cache.pmPrototypePte, pVad->vaPrototypePte, e);
        Ob_DECREF(e);
    }
    LocalFree(pbData);
}

/*
* Retrieve an object manager object containing the prototype pte's. THe object
* will be retrieved from cache if possible, otherwise a read will be attempted
* provided that the fVmmRead flags allows for it.
* CALLER DECREF: return
* -- pVad
* -- fVmmRead
* -- return
*/
POB_DATA MmVad_PrototypePteArray_Get(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess, _In_ PVMM_MAP_VADENTRY pVad, _In_ QWORD fVmmRead)
{
    QWORD i, va;
    POB_DATA e = NULL;
    POB_SET psObPrefetch = NULL;
    PVMM_PROCESS pObSystemProcess = NULL;
    PVMMOB_MAP_VAD pVadMap;
    if(!pVad->vaPrototypePte || !pVad->cbPrototypePte) { return NULL; }
    if((e = ObMap_GetByKey(H->vmm.Cache.pmPrototypePte, pVad->vaPrototypePte))) { return e; }
    EnterCriticalSection(&pProcess->LockUpdate);
    if((e = ObMap_GetByKey(H->vmm.Cache.pmPrototypePte, pVad->vaPrototypePte))) {
        LeaveCriticalSection(&pProcess->LockUpdate);
        return e;
    }
    if((pObSystemProcess = VmmProcessGet(H, 4))) {
        if(!pProcess->Map.pObVad->fSpiderPrototypePte && pVad->cbPrototypePte < 0x1000 && (psObPrefetch = ObSet_New(H))) {
            pVadMap = pProcess->Map.pObVad;
            // spider all prototype pte's less than 0x1000 in size into the cache
            pVadMap->fSpiderPrototypePte = TRUE;
            for(i = 0; i < pVadMap->cMap; i++) {
                va = pVadMap->pMap[i].vaPrototypePte;
                if(va && (pVadMap->pMap[i].cbPrototypePte < 0x1000) && !ObMap_ExistsKey(H->vmm.Cache.pmPrototypePte, va)) {
                    ObSet_Push(psObPrefetch, va);
                }
            }
            VmmCachePrefetchPages3(H, pObSystemProcess, psObPrefetch, 0x1000, fVmmRead);
            for(i = 0; i < pVadMap->cMap; i++) {
                va = pVadMap->pMap[i].vaPrototypePte;
                if(va && (pVadMap->pMap[i].cbPrototypePte < 0x1000) && !ObMap_ExistsKey(H->vmm.Cache.pmPrototypePte, va)) {
                    MmVad_PrototypePteArray_FetchNew(H, pObSystemProcess, pVadMap->pMap + i, fVmmRead | VMM_FLAG_FORCECACHE_READ);
                }
            }
            Ob_DECREF(psObPrefetch);
        } else {
            // fetch single vad prototypte pte array into the cache
            MmVad_PrototypePteArray_FetchNew(H, pObSystemProcess, pVad, fVmmRead);
        }
        Ob_DECREF(pObSystemProcess);
    }
    LeaveCriticalSection(&pProcess->LockUpdate);
    return ObMap_GetByKey(H->vmm.Cache.pmPrototypePte, pVad->vaPrototypePte);
}



// ----------------------------------------------------------------------------
// IMPLEMENTATION OF VAD RELATED GENERAL FUNCTIONALITY BELOW:
// ----------------------------------------------------------------------------

/*
* Try to read a prototype page table entry (PTE).
* -- H
* -- pProcess
* -- va
* -- pfInRange
* -- fVmmRead = VMM_FLAG_* flags.
* -- return = prototype pte or zero on fail.
*/
QWORD MmVad_PrototypePte(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess, _In_ QWORD va, _Out_opt_ PBOOL pfInRange, _In_ QWORD fVmmRead)
{
    QWORD iPrototypePte, qwPrototypePte = 0;
    POB_DATA pObPteArray = NULL;
    PVMM_MAP_VADENTRY pVad = NULL;
    if(MmVad_MapInitialize(H, pProcess, VMM_VADMAP_TP_CORE, fVmmRead) && (pVad = VmmMap_GetVadEntry(H, pProcess->Map.pObVad, va)) && (pObPteArray = MmVad_PrototypePteArray_Get(H, pProcess, pVad, fVmmRead))) {
        iPrototypePte = (va - pVad->vaStart) >> 12;
        if(H->vmm.tpMemoryModel == VMM_MEMORYMODEL_X86) {
            if(pObPteArray->ObHdr.cbData > (iPrototypePte * 4)) {
                qwPrototypePte = pObPteArray->pdw[iPrototypePte];
            }
        } else {
            if(pObPteArray->ObHdr.cbData > (iPrototypePte * 8)) {
                qwPrototypePte = pObPteArray->pqw[iPrototypePte];
            }
        }
        Ob_DECREF(pObPteArray);
    }
    if(pfInRange) { *pfInRange = pVad ? TRUE : FALSE; }
    return qwPrototypePte;
}

_Success_(return)
BOOL MmVad_MapInitialize_Core(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess, _In_ QWORD fVmmRead)
{
    QWORD tmStart, tmEnd;
    PVMM_PROCESS pObSystemProcess;
    if(pProcess->Map.pObVad) { return TRUE; }
    tmStart = GetTickCount64();
    EnterCriticalSection(&pProcess->LockUpdate);
    if(!pProcess->Map.pObVad && (pObSystemProcess = VmmProcessGet(H, 4))) {
        if(pProcess->dwState != 1) {    // vads does not exist on terminated processes
            MmVad_Spider_DoWork(H, pObSystemProcess, pProcess, (fVmmRead & ~VMM_FLAG_FORCECACHE_READ) | VMM_FLAG_NOVAD);
        }
        if(!pProcess->Map.pObVad) {
            pProcess->Map.pObVad = Ob_AllocEx(H, OB_TAG_MAP_VAD, LMEM_ZEROINIT, sizeof(VMMOB_MAP_VAD), MmVad_MemMapVad_CloseObCallback, NULL);
        }
        Ob_DECREF(pObSystemProcess);
    }
    LeaveCriticalSection(&pProcess->LockUpdate);
    tmEnd = GetTickCount64();
    if(tmEnd - tmStart > MMVAD_SLOWQUERY_THRESHOLD_MS) {
        VmmLog(H, MID_VMM, LOGLEVEL_4_VERBOSE, "VAD: SLOW QUERY (CORE) PID: %i #VAD: %x TIME: %llums", pProcess->dwPID, (pProcess->Map.pObVad ? pProcess->Map.pObVad->cMap : 0), (tmEnd - tmStart));
    }
    return pProcess->Map.pObVad ? TRUE : FALSE;
}

_Success_(return)
BOOL MmVad_MapInitialize_ExtendedInfo(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess, _In_ VMM_VADMAP_TP tp, _In_ QWORD fVmmRead)
{
    QWORD tmStart, tmEnd;
    PVMM_PROCESS pObSystemProcess;
    if(!pProcess->Map.pObVad) { return FALSE; }
    if(tp <= pProcess->Map.pObVad->tp) { return TRUE; }
    tmStart = GetTickCount64();
    EnterCriticalSection(&pProcess->LockUpdate);
    if((pProcess->Map.pObVad->tp < tp) && (pObSystemProcess = VmmProcessGet(H, 4))) {
        MmVad_ExtendedInfoFetch(H, pObSystemProcess, pProcess, tp, fVmmRead | VMM_FLAG_NOVAD);
        Ob_DECREF(pObSystemProcess);
    }
    LeaveCriticalSection(&pProcess->LockUpdate);
    tmEnd = GetTickCount64();
    if(tmEnd - tmStart > MMVAD_SLOWQUERY_THRESHOLD_MS) {
        VmmLog(H, MID_VMM, LOGLEVEL_4_VERBOSE, "VAD: SLOW QUERY (EXT) PID: %i #VAD: %x TIME: %llums", pProcess->dwPID, (pProcess->Map.pObVad ? pProcess->Map.pObVad->cMap : 0), (tmEnd - tmStart));
    }
    return (pProcess->Map.pObVad->tp >= tp);
}

/*
* Initialize / Ensure that a VAD map is initialized for the specific process.
* -- H
* -- pProcess
* -- tp = VMM_VADMAP_TP_*
* -- fVmmRead = VMM_FLAGS_* flags.
* -- return
*/
_Success_(return)
BOOL MmVad_MapInitialize(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess, _In_ VMM_VADMAP_TP tp, _In_ QWORD fVmmRead)
{
    if(pProcess->Map.pObVad && (tp <= pProcess->Map.pObVad->tp)) { return TRUE; }
    VmmTlbSpider(H, pProcess);
    return MmVad_MapInitialize_Core(H, pProcess, fVmmRead) && ((tp == VMM_VADMAP_TP_CORE) || MmVad_MapInitialize_ExtendedInfo(H, pProcess, tp, fVmmRead));
}

/*
* Interprete VAD protection flags into string p[mgn]rwxc.
* -- pVad
* -- sz = buffer to receive written characters - not null terminated!
*/
VOID MmVad_StrProtectionFlags(_In_ PVMM_MAP_VADENTRY pVad, _Out_writes_(6) LPSTR sz)
{
    BYTE vh = (BYTE)pVad->Protection >> 3;
    BYTE vl = (BYTE)pVad->Protection & 7;
    sz[0] = pVad->fPrivateMemory ? 'p' : '-';                                   // PRIVATE MEMORY
    sz[1] = (vh & 2) ? ((vh & 1) ? 'm' : 'g') : ((vh & 1) ? 'n' : '-');         // -/NO_CACHE/GUARD/WRITECOMBINE
    sz[2] = ((vl == 1) || (vl == 3) || (vl == 4) || (vl == 6)) ? 'r' : '-';     // COPY ON WRITE
    sz[3] = (vl & 4) ? 'w' : '-';                                               // WRITE
    sz[4] = (vl & 2) ? 'x' : '-';                                               // EXECUTE
    sz[5] = ((vl == 5) || (vl == 7)) ? 'c' : '-';                               // COPY ON WRITE
    if(sz[1] != '-' && sz[2] == '-' && sz[3] == '-' && sz[4] == '-' && sz[5] == '-') { sz[1] = '-'; }
}

/*
* Retrieve the type of the VAD entry as an ansi string.
* The string must _not_ be free'd.
* -- pVad
* -- return
*/
LPCSTR MmVad_StrType(_In_ PVMM_MAP_VADENTRY pVad)
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

/*
* Retrieve the page type as a character.
* -- tp
* -- return
*/
CHAR MmVadEx_StrType(_In_ VMM_PTE_TP tp)
{
    switch(tp) {
        case VMM_PTE_TP_HARDWARE:   return 'A';
        case VMM_PTE_TP_TRANSITION: return 'T';
        case VMM_PTE_TP_PROTOTYPE:  return 'P';
        case VMM_PTE_TP_DEMANDZERO: return 'Z';
        case VMM_PTE_TP_COMPRESSED: return 'C';
        case VMM_PTE_TP_PAGEFILE:   return 'F';
        default:                    return '-';
    }
}



//-----------------------------------------------------------------------------
// EXTENDED VAD MAP BELOW:
//-----------------------------------------------------------------------------

VOID MmVadEx_EntryPrefill(
    _In_ VMM_HANDLE H,
    _In_ PVMM_PROCESS pProcess,
    _In_ PVMMOB_MAP_PTE pPteMap,
    _In_ PVMM_MAP_VADENTRY peVad,
    _In_ DWORD cVadEx,      // # peVadEx 
    _In_ DWORD oVadEx,      // start offset in # entries from vad base
    _Inout_count_(cVadEx) PVMM_MAP_VADEXENTRY peVadEx
) {
    BOOL fX86 = (H->vmm.tpMemoryModel == VMM_MEMORYMODEL_X86);
    DWORD cPteFwd, iePte = 0, iPteCurrent = 0;
    QWORD va, iVad, iVadEx;
    PVMM_MAP_VADEXENTRY pe;
    PVMM_MAP_PTEENTRY pePte = NULL;
    POB_DATA pObProtoPteArray = NULL;
    if(!peVad->fPrivateMemory && peVad->vaPrototypePte && peVad->cbPrototypePte) {
        pObProtoPteArray = MmVad_PrototypePteArray_Get(H, pProcess, peVad, 0);
    }
    if(peVad->fFile || peVad->fImage) {
        // FILE or IMAGE VAD
        for(iVadEx = 0; iVadEx < cVadEx; iVadEx++) {
            pe = peVadEx + iVadEx;
            iVad = oVadEx + iVadEx;
            pe->va = peVad->vaStart + (iVad << 12);
            if(pObProtoPteArray && (pObProtoPteArray->ObHdr.cbData > (iVad * (fX86 ? 4 : 8)))) {
                pe->proto.pte = fX86 ? pObProtoPteArray->pqw[iVad] : pObProtoPteArray->pqw[iVad];
            }
        }
    } else {
        // NO FILE|IMAGE VAD -> skip non-backed VAs -> populate VAs from page tables
        if(MmVad_PteEntryFind(pPteMap, peVad->vaStart, peVad->vaEnd, &iePte)) {
            // 1: adjust initial offset
            pePte = pPteMap->pMap + iePte;
            iPteCurrent = (DWORD)((max(peVad->vaStart, pePte->vaBase) - pePte->vaBase) >> 12);
            while(oVadEx && pePte) {
                cPteFwd = (DWORD)min(oVadEx, pePte->cPages - iPteCurrent);
                iPteCurrent += cPteFwd;
                oVadEx -= cPteFwd;
                // forward pte map entry if required
                if(iPteCurrent == pePte->cPages) {
                    iPteCurrent = 0;
                    iePte++;
                    pePte = (iePte < pPteMap->cMap) ? pPteMap->pMap + iePte : NULL;
                }
            }
            // 2: populate vadex entries with virtual addresses
            for(iVadEx = 0; iVadEx < cVadEx; iVadEx++) {
                pe = peVadEx + iVadEx;
                // forward pte map entry if required
                if(pePte && (iPteCurrent == pePte->cPages)) {
                    iPteCurrent = 0;
                    iePte++;
                    pePte = (iePte < pPteMap->cMap) ? pPteMap->pMap + iePte : NULL;
                }
                // map pte va -> vadex va (and prototype pte if suitable)
                if(pePte && ((va = pePte->vaBase + ((QWORD)iPteCurrent << 12)) < peVad->vaEnd)) {
                    iVad = (va - peVad->vaStart) >> 12;
                    if(pObProtoPteArray && (pObProtoPteArray->ObHdr.cbData > (iVad * (fX86 ? 4 : 8)))) {
                        pe->proto.pte = fX86 ? pObProtoPteArray->pqw[iVad] : pObProtoPteArray->pqw[iVad];
                    }
                    pe->va = va;
                    iPteCurrent++;
                } else {
                    pe->va = peVad->vaEnd & ~0xfff;
                }
            }
        }
    }
    // set VAD and prototype physical address
    for(iVadEx = 0; iVadEx < cVadEx; iVadEx++) {
        pe = peVadEx + iVadEx;
        pe->peVad = peVad;
        if(pe->proto.pte) {
            H->vmm.fnMemoryModel.pfnPagedRead(H, pProcess, pe->va, pe->proto.pte, NULL, &pe->proto.pa, &pe->proto.tp, VMM_FLAG_NOVAD);
        }
    }
    // cleanup
    Ob_DECREF(pObProtoPteArray);
}

/*
* Object manager callback function for object cleanup tasks.
*/
VOID MmVadEx_CloseObCallback(_In_ PVOID pVmmOb)
{
    PVMMOB_MAP_VADEX pOb = (PVMMOB_MAP_VADEX)pVmmOb;
    Ob_DECREF(pOb->pVadMap);
}

int MmVadEx_VadEntryFind_CmpFind(_In_ QWORD iPage, _In_ QWORD qwEntry)
{
    PVMM_MAP_VADENTRY pEntry = (PVMM_MAP_VADENTRY)qwEntry;
    if((QWORD)pEntry->cVadExPagesBase + pEntry->cVadExPages - 1 < iPage) { return 1; }
    if(pEntry->cVadExPagesBase > iPage) { return -1; }
    if(0 == pEntry->cVadExPages) { return 1; }
    return 0;
}

/*
* Initialize / Retrieve an extended VAD map with info about individual pages in
* the ranges pecified by the iPage and cPage variables.
* CALLER DECREF: return
* -- H
* -- pProcess
* -- tpVmmVadMap = VMM_VADMAP_TP_*
* -- iPage = index of range start in vad map.
* -- cPage = number of pages, starting at iPage.
* -- return
*/
_Success_(return != NULL)
PVMMOB_MAP_VADEX MmVadEx_MapInitialize(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess, _In_ VMM_VADMAP_TP tpVmmVadMap, _In_ DWORD iPage, _In_ DWORD cPage)
{
    DWORD iVadEx = 0, iPageCurrent, cPageCurrent;
    POB_DATA pObProtoPteArray = NULL;
    PVMM_MAP_VADENTRY peVad = NULL;
    PVMM_MAP_VADEXENTRY pex;
    PVMMOB_MAP_PTE pObPte = NULL;
    PVMMOB_MAP_VAD pObVad = NULL;
    PVMMOB_MAP_VADEX pObVadEx = NULL;
    // 1: fetch vad map and perform santity checks
    if(!VmmMap_GetPte(H, pProcess, &pObPte, FALSE)) { goto fail; }
    if(!VmmMap_GetVad(H, pProcess, &pObVad, min(VMM_VADMAP_TP_PARTIAL, tpVmmVadMap))) { goto fail; }
    cPage = min(cPage, pObVad->cPage - iPage);
    // 2: alloc extended vad map
    pObVadEx = Ob_AllocEx(H, OB_TAG_MAP_VADEX, LMEM_ZEROINIT, sizeof(VMMOB_MAP_VADEX) + cPage * sizeof(VMM_MAP_VADEXENTRY), MmVadEx_CloseObCallback, NULL);
    if(!pObVadEx) { goto fail; }
    pObVadEx->pVadMap = Ob_INCREF(pObVad);
    pObVadEx->cMap = cPage;
    // 3: fill extended vad map entries with va and peVad
    iPageCurrent = iPage;
    while(iPageCurrent < iPage + cPage) {
        peVad = Util_qfind((QWORD)iPageCurrent, pObVad->cMap, pObVad->pMap, sizeof(VMM_MAP_VADENTRY), MmVadEx_VadEntryFind_CmpFind);
        if(!peVad) { goto fail; }
        cPageCurrent = min(iPage + cPage - iPageCurrent, peVad->cVadExPagesBase + peVad->cVadExPages - iPageCurrent);
        MmVadEx_EntryPrefill(H, pProcess, pObPte, peVad, cPageCurrent, iPageCurrent - peVad->cVadExPagesBase, pObVadEx->pMap + iPageCurrent - iPage);
        iPageCurrent += cPageCurrent;
    }
    // 4: fill page table information with hardware mappings
    iVadEx = 0;
    while(iVadEx < pObVadEx->cMap) {
        if(pObVadEx->pMap[iVadEx].va) {
            H->vmm.fnMemoryModel.pfnVirt2PhysVadEx(H, pProcess->paDTB, pObVadEx, -1, &iVadEx);
        } else {
            iVadEx++;
        }
    }
    // 5: fill page table information with software mappings
    for(iVadEx = 0; iVadEx < pObVadEx->cMap; iVadEx++) {
        pex = pObVadEx->pMap + iVadEx;
        if(pex->tp == VMM_PTE_TP_NA) {
            if(pex->pte && (pex->iPML == 1)) {
                H->vmm.fnMemoryModel.pfnPagedRead(H, pProcess, pex->va, pex->pte, NULL, &pex->pa, &pex->tp, VMM_FLAG_NOVAD);
            }
            if(!pex->pte || (pex->iPML != 1) || (pex->tp == VMM_PTE_TP_PROTOTYPE)) {
                pex->tp = VMM_PTE_TP_PROTOTYPE;
                pex->pa = pex->proto.pa;
            }
        }
    }
    Ob_INCREF(pObVadEx);
fail:
    Ob_DECREF(pObPte);
    Ob_DECREF(pObVad);
    return Ob_DECREF(pObVadEx);
}
