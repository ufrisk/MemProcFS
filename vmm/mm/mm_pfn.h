// mm_pfn.h : definitions related to the pfn (page frame number) database and
//            related physical memory functionality.
//
// (c) Ulf Frisk, 2020-2025
// Author: Ulf Frisk, pcileech@frizk.net
//
#ifndef __MM_PFN_H__
#define __MM_PFN_H__
#include "../vmm.h"

static LPCSTR MMPFN_TYPE_TEXT[] = { "Zero", "Free", "Standby", "Modifiy", "ModNoWr", "Bad", "Active", "Transit" };
static LPCSTR MMPFN_TYPEEXTENDED_TEXT[] = { "-", "Unused", "ProcPriv", "PageTable", "LargePage", "DriverLock", "Shareable", "File" };

typedef enum tdMMPFN_TYPE {
    MmPfnTypeZero = 0,
    MmPfnTypeFree = 1,
    MmPfnTypeStandby = 2,
    MmPfnTypeModified = 3,
    MmPfnTypeModifiedNoWrite = 4,
    MmPfnTypeBad = 5,
    MmPfnTypeActive = 6,
    MmPfnTypeTransition = 7
} MMPFN_TYPE;

typedef enum tdMMPFN_TYPEEXTENDED {
    MmPfnExType_Unknown = 0,
    MmPfnExType_Unused = 1,
    MmPfnExType_ProcessPrivate = 2,
    MmPfnExType_PageTable = 3,
    MmPfnExType_LargePage = 4,
    MmPfnExType_DriverLocked = 5,
    MmPfnExType_Shareable = 6,
    MmPfnExType_File = 7,
} MMPFN_TYPEEXTENDED;

typedef struct tdMMPFN_MAP_ENTRY {
    DWORD dwPfn;
    MMPFN_TYPEEXTENDED tpExtended;
    struct {        // Only valid if active non-prototype PFN
        union {
            DWORD dwPid;
            DWORD dwPfnPte[5];  // PFN of paging levels 1-4 (x64)
        };
        QWORD va;               // valid if non-zero
    } AddressInfo;
    QWORD vaPte;
    QWORD OriginalPte;
    union {
        DWORD _u3;
        struct {
            WORD ReferenceCount;
            // MMPFNENTRY
            BYTE PageLocation       : 3;    // Pos 0
            BYTE WriteInProgress    : 1;    // Pos 3
            BYTE Modified           : 1;    // Pos 4
            BYTE ReadInProgress     : 1;    // Pos 5
            BYTE CacheAttribute     : 2;    // Pos 6
            BYTE Priority           : 3;    // Pos 0
            BYTE Rom_OnProtectedStandby : 1; // Pos 3
            BYTE InPageError        : 1;    // Pos 4
            BYTE KernelStack_SystemChargedPage : 1; // Pos 5
            BYTE RemovalRequested   : 1;    // Pos 6
            BYTE ParityError        : 1;    // Pos 7
        };
    };
    union {
        QWORD _u4;
        struct {
            DWORD PteFrame;
            DWORD PteFrameHigh      : 4;    // Pos 32
            DWORD _Reserved         : 21;   // Pos 36
            DWORD PrototypePte      : 1;    // Pos 57
            DWORD PageColor         : 6;    // Pos 58
        };
    };
    DWORD _FutureUse[6];
} MMPFN_MAP_ENTRY, *PMMPFN_MAP_ENTRY;

typedef struct tdMMPFNOB_MAP {
    OB ObHdr;
    DWORD cMap;                     // # map entries.
    MMPFN_MAP_ENTRY pMap[];         // map entries.
} MMPFNOB_MAP, *PMMPFNOB_MAP;

/*
* Close / Shutdown the PFN subsystem. This function should never be called when
* there may be an active thread in the PFN subsystem. This function should only
* be called on shutdown.
* -- H
*/
VOID MmPfn_Close(_In_ VMM_HANDLE H);

/*
* Refresh the PFN (page frame number) subsystem.
* This should be performed after each process list refresh.
* -- H
*/
VOID MmPfn_Refresh(_In_ VMM_HANDLE H);

/*
* Retrieve information about a sequential number of PFNs.
* CALLER DECREF: pObPfnMap
* -- H
* -- dwPfnStart = starting PFN. PFN = physical address / 0x1000.
* -- cPfn
* -- ppObPfnMap
* -- fExtended = extended information such as process id's.
* -- return
*/
_Success_(return)
BOOL MmPfn_Map_GetPfn(_In_ VMM_HANDLE H, _In_ DWORD dwPfnStart, _In_ DWORD cPfn, _Out_ PMMPFNOB_MAP *ppObPfnMap, _In_ BOOL fExtended);

/*
* Retrieve information about scattered PFNs. The PFNs are returned in order of
* in which they are stored in the psPfn set.
* NB! POB_SET does not support ZERO, for PFN zero use 0x8000000000000000.
* CALLER DECREF: pObPfnMap
* -- H
* -- psPfn = Set of PFNs. PFN = physical address / 0x1000.
* -- cPfn
* -- ppObPfnMap
* -- fExtended = extended information such as process id's.
* -- return
*/
_Success_(return)
BOOL MmPfn_Map_GetPfnScatter(_In_ VMM_HANDLE H, _In_ POB_SET psPfn, _Out_ PMMPFNOB_MAP *ppObPfnMap, _In_ BOOL fExtended);

/*
* Retrieve the system PTEs aka DTB PFNs in a fairly optimized way.
* -- H
* -- ppObPfnMap
* -- fExtended = extended information such as process id's.
* -- ppcProgress = optional progress counter to be updated continuously within function.
* -- return
*/
_Success_(return)
BOOL MmPfn_Map_GetPfnSystem(_In_ VMM_HANDLE H, _Out_ PMMPFNOB_MAP *ppObPfnMap, _In_ BOOL fExtended, _Out_opt_ PDWORD ppcProgress);

#endif /* __MM_PFN_H__ */
