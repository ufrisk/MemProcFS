// vmm.h : definitions related to virtual memory management support.
//
// (c) Ulf Frisk, 2018-2019
// Author: Ulf Frisk, pcileech@frizk.net
//
#ifndef __VMM_H__
#define __VMM_H__
#include <windows.h>
#include <stdio.h>
#include "leechcore.h"

typedef unsigned __int64                QWORD, *PQWORD;
#define VMM_MULTITHREAD_ENABLE
#define VMMOB_DEBUG

// ----------------------------------------------------------------------------
// VMM configuration constants and struct definitions below:
// ----------------------------------------------------------------------------

#define VMM_STATUS_SUCCESS                      ((NTSTATUS)0x00000000L)
#define VMM_STATUS_UNSUCCESSFUL                 ((NTSTATUS)0xC0000001L)
#define VMM_STATUS_END_OF_FILE                  ((NTSTATUS)0xC0000011L)
#define VMM_STATUS_FILE_INVALID                 ((NTSTATUS)0xC0000098L)
#define VMM_STATUS_FILE_SYSTEM_LIMITATION       ((NTSTATUS)0xC0000427L)

#define VMM_PROCESSTABLE_ENTRIES_MAX            0x4000
#define VMM_PROCESS_OS_ALLOC_PTR_MAX            0x4    // max number of operating system specific pointers that must be free'd
#define VMM_MEMMAP_ENTRIES_MAX                  0x4000

#define VMM_MEMMAP_PAGE_W                       0x0000000000000002
#define VMM_MEMMAP_PAGE_NS                      0x0000000000000004
#define VMM_MEMMAP_PAGE_NX                      0x8000000000000000
#define VMM_MEMMAP_PAGE_MASK                    0x8000000000000006

#define VMM_MEMMAP_FLAG_MODULES                 0x0001
#define VMM_MEMMAP_FLAG_SCAN                    0x0002
#define VMM_MEMMAP_FLAG_ALL                     (VMM_MEMMAP_FLAG_MODULES | VMM_MEMMAP_FLAG_SCAN)

#define VMM_CACHE_TABLESIZE                     0x4011  // (not even # to prevent clogging at specific table 'hash' buckets)
#define VMM_CACHE_TLB_ENTRIES                   0x4000  // -> 64MB of cached data
#define VMM_CACHE_PHYS_ENTRIES                  0x4000  // -> 64MB of cached data

#define VMM_FLAG_NOCACHE                        0x0001  // do not use the data cache (force reading from memory acquisition device)
#define VMM_FLAG_ZEROPAD_ON_FAIL                0x0002  // zero pad failed physical memory reads and report success if read within range of physical memory.
#define VMM_FLAG_PROCESS_SHOW_TERMINATED        0x0004  // show terminated processes in the process list (if they can be found).
#define VMM_FLAG_FORCECACHE_READ                0x0008  // force use of cache - fail non-cached pages - only valid for reads, invalid with VMM_FLAG_NOCACHE/VMM_FLAG_ZEROPAD_ON_FAIL.

#define PAGE_SIZE                               0x1000

static const LPSTR VMM_MEMORYMODEL_TOSTRING[4] = { "N/A", "X86", "X86PAE", "X64" };

typedef enum tdVMM_MEMORYMODEL_TP {
    VMM_MEMORYMODEL_NA      = 0,
    VMM_MEMORYMODEL_X86     = 1,
    VMM_MEMORYMODEL_X86PAE  = 2,
    VMM_MEMORYMODEL_X64     = 3
} VMM_MEMORYMODEL_TP;

typedef enum tdVMM_SYSTEM_TP {
    VMM_SYSTEM_UNKNOWN_X64  = 1,
    VMM_SYSTEM_WINDOWS_X64  = 2,
    VMM_SYSTEM_UNKNOWN_X86  = 3,
    VMM_SYSTEM_WINDOWS_X86  = 4
} VMM_SYSTEM_TP;

typedef struct tdVMM_MEMMAP_ENTRY {
    QWORD AddrBase;
    QWORD cPages;
    QWORD fPage;
    BOOL  fWoW64;
    CHAR  szTag[32];
} VMM_MEMMAP_ENTRY, *PVMM_MEMMAP_ENTRY;

typedef struct tdVMM_MODULEMAP_ENTRY {
    QWORD BaseAddress;
    QWORD EntryPoint;
    DWORD SizeOfImage;
    BOOL  fWoW64;
    CHAR  szName[32];
    // # of entries in EAT / IAT (lazy loaded due to performance reasons)
    BOOL  fLoadedEAT;
    DWORD cbDisplayBufferEAT;
    BOOL  fLoadedIAT;
    DWORD cbDisplayBufferIAT;
    DWORD cbDisplayBufferSections;
    DWORD cbFileSizeRaw;
} VMM_MODULEMAP_ENTRY, *PVMM_MODULEMAP_ENTRY;

typedef struct tdVMMOB {
    BYTE Reserved[0x1c];
    DWORD cbData;
} VMMOB, *PVMMOB;

typedef struct tdVMMOBCONTAINER {
    CRITICAL_SECTION Lock;
    PVMMOB pVmmOb;
} VMMOBCONTAINER, *PVMMOBCONTAINER;

typedef struct tdVMMDATALIST {
    DWORD iNext;
    QWORD Value;
} VMMDATALIST, *PVMMDATALIST;

typedef struct tdVMMOB_DATA {
    BYTE Reserved[0x1c];
    DWORD cbData;
    union {
        BYTE pbData[];
        DWORD pdwData[];
        QWORD pqwData[];
        VMMDATALIST pList[];
    };
} VMMOB_DATA, *PVMMOB_PDATA;

typedef struct tdVMMOB_DATASET {
    VMMOB ObHdr;
    BOOL fUnique;
    DWORD c;
    DWORD cMax;
    DWORD iListStart;
    PVMMOB_PDATA pObData;
} VMMOB_DATASET, *PVMMOB_DATASET;

typedef struct tdVMMOB_MEMMAP {
    BYTE Reserved[0x1c];
    DWORD cbData;
    BOOL fValid;                // map is valid (did not fail initialization)
    BOOL fTagModules;           // map contains tags from modules.
    BOOL fTagScan;              // map contains tags from scan.
    DWORD cMap;                 // # map entries.
    DWORD cbDisplay;            // byte count of display map (even if not existing yet).
    PVMMOB_PDATA pObDisplay;    // human readable memory map.
    VMM_MEMMAP_ENTRY pMap[];    // map entries
} VMMOB_MEMMAP, *PVMMOB_MEMMAP;

typedef struct tdVMMOB_MODULEMAP {
    BYTE Reserved[0x1c];
    DWORD cbData;
    BOOL fValid;                // map is valid (did not fail initialization).
    DWORD cMap;                 // # map entries.
    DWORD cbDisplay;            // size of 'text' module map.
    PBYTE pbDisplay;            // 'text' module map stored in-object after pMap).
    VMM_MODULEMAP_ENTRY pMap[]; // map entries
} VMMOB_MODULEMAP, *PVMMOB_MODULEMAP;

// 'static' process information that should be kept even in the ase of a total
// process refresh. Only use for information that may never change or things
// that may not affect analysis (like cache preload addresses that only may
// speed things up - but not change analysis result). May also be used by
// internal plugins to store persistent information in various plugin-internal
// thread safe ways. Use with extreme care!
typedef struct tdVMMOB_PROCESS_PERSISTENT {
    VMMOB ObHdr;
    VMMOBCONTAINER ObCLdrModulesCachePrefetch32;
    VMMOBCONTAINER ObCLdrModulesCachePrefetch64;
    struct {
        QWORD vaVirt2Phys;
    } Plugin;
} VMMOB_PROCESS_PERSISTENT, *PVMMOB_PROCESS_PERSISTENT;

typedef struct tdVMM_PROCESS {
    VMMOB ObHdr;
    CRITICAL_SECTION LockUpdate;
    DWORD dwPID;
    DWORD dwState;          // state of process, 0 = running
    QWORD paDTB;
    QWORD paDTB_UserOpt;
    CHAR szName[16];
    BOOL fUserOnly;
    BOOL fTlbSpiderDone;
    BOOL fFileCacheDisabled;
    PVMMOB_MEMMAP pObMemMap;
    PVMMOB_MODULEMAP pObModuleMap;
    PVMMOB_PROCESS_PERSISTENT pObProcessPersistent;     // Always exists
    union {
        struct {
            QWORD vaEPROCESS;
            QWORD vaPEB;
            DWORD vaPEB32;      // WoW64 only
            QWORD vaENTRY;
            BOOL fWow64;
        } win;
    } os;
    struct {
        VMMOBCONTAINER ObCLdrModulesDisplayCache;
        VMMOBCONTAINER ObCPeDumpDirCache;
    } Plugin;
} VMM_PROCESS, *PVMM_PROCESS;

#define VMM_CACHE2_REGIONS      17
#define VMM_CACHE2_BUCKETS      2039
#define VMM_CACHE2_MAX_ENTRIES  0x8000

#define VMM_CACHE_TAG_PHYS      'Ph'
#define VMM_CACHE_TAG_TLB       'Tb'

typedef struct tdVMMOB_MEM {
    BYTE Reserved[0x1c];
    DWORD cbData;
    SLIST_ENTRY SListTotal;
    SLIST_ENTRY SListEmpty;
    struct tdVMMOB_MEM *FLink;
    struct tdVMMOB_MEM *BLink;
    struct tdVMMOB_MEM *AgeFLink;
    struct tdVMMOB_MEM *AgeBLink;
    MEM_IO_SCATTER_HEADER h;
    union {
        BYTE pb[0x1000];
        DWORD pdw[0x400];
        QWORD pqw[0x200];
    };
} VMMOB_MEM, *PVMMOB_MEM, **PPVMMOB_MEM;

typedef struct tdVMM_CACHE_TABLE {
    SLIST_HEADER ListHeadEmpty;
    SLIST_HEADER ListHeadTotal;
    DWORD cEmpty;
    DWORD cTotal;
    BOOL fActive;
    WORD tag;
    WORD iReclaimLast;
    struct {
        DWORD c;
        DWORD dwFuture;
        CRITICAL_SECTION Lock;
        PVMMOB_MEM AgeFLink;
        PVMMOB_MEM AgeBLink;
        PVMMOB_MEM B[VMM_CACHE2_BUCKETS];
    } R[VMM_CACHE2_REGIONS];
} VMM_CACHE_TABLE, *PVMM_CACHE_TABLE;

typedef struct tdVMM_VIRT2PHYS_INFORMATION {
    VMM_MEMORYMODEL_TP tpMemoryModel;
    QWORD va;
    QWORD pas[5];   // physical addresses of pagetable[PML]/page[0]
    QWORD PTEs[5];  // PTEs[PML]
    WORD  iPTEs[5]; // Index of PTE in page table
} VMM_VIRT2PHYS_INFORMATION, *PVMM_VIRT2PHYS_INFORMATION;

typedef struct tdVMM_MEMORYMODEL_FUNCTIONS {
    VOID(*pfnClose)();
    BOOL(*pfnVirt2Phys)(_In_ QWORD paDTB, _In_ BOOL fUserOnly, _In_ BYTE iPML, _In_ QWORD va, _Out_ PQWORD ppa);
    VOID(*pfnVirt2PhysGetInformation)(_Inout_ PVMM_PROCESS pProcess, _Inout_ PVMM_VIRT2PHYS_INFORMATION pVirt2PhysInfo);
    VOID(*pfnMapInitialize)(_In_ PVMM_PROCESS pProcess);
    VOID(*pfnMapTag)(_In_ PVMM_PROCESS pProcess, _In_ QWORD vaBase, _In_ QWORD vaLimit, _In_opt_ LPSTR szTag, _In_opt_ LPWSTR wszTag, _In_ BOOL fWoW64, _In_ BOOL fOverwrite);
    BOOL(*pfnMapGetEntries)(_In_ PVMM_PROCESS pProcess, _In_ DWORD flags, _Out_ PVMMOB_MEMMAP *ppObMemMap);
    BOOL(*pfnMapGetDisplay)(_In_ PVMM_PROCESS pProcess, _In_ DWORD flags, _Out_ PVMMOB_PDATA *ppObDisplay);
    VOID(*pfnTlbSpider)(_In_ PVMM_PROCESS pProcess);
    BOOL(*pfnTlbPageTableVerify)(_Inout_ PBYTE pb, _In_ QWORD pa, _In_ BOOL fSelfRefReq);
} VMM_MEMORYMODEL_FUNCTIONS;

// ----------------------------------------------------------------------------
// VMM general constants and struct definitions below: 
// ----------------------------------------------------------------------------

typedef struct tdVmmConfig {
    CHAR szMountPoint[1];
    CHAR szPythonPath[MAX_PATH];
    QWORD paCR3;
    // flags below
    BOOL fCommandIdentify;
    BOOL fVerboseDll;
    BOOL fVerbose;
    BOOL fVerboseExtra;
    BOOL fVerboseExtraTlp;
    BOOL fDisableBackgroundRefresh;
    BOOL fDisableLeechCoreClose;    // when device 'existing'
} VMMCONFIG, *PVMMCONFIG;

typedef struct tdVMM_STATISTICS {
    QWORD cPhysCacheHit;
    QWORD cPhysReadSuccess;
    QWORD cPhysReadFail;
    QWORD cPhysWrite;
    QWORD cTlbCacheHit;
    QWORD cTlbReadSuccess;
    QWORD cTlbReadFail;
    QWORD cRefreshPhys;
    QWORD cRefreshTlb;
    QWORD cRefreshProcessPartial;
    QWORD cRefreshProcessFull;
} VMM_STATISTICS, *PVMM_STATISTICS;

typedef struct tdVMM_WIN_EPROCESS_OFFSET {
    BOOL fValid;
    WORD cbMaxOffset;
    WORD State;
    WORD DTB;
    WORD Name;
    WORD PID;
    WORD FLink;
    WORD BLink;
    WORD PEB;
    WORD DTB_User;
} VMM_WIN_EPROCESS_OFFSET, *PVMM_WIN_EPROCESS_OFFSET;

typedef struct tdVMM_KERNELINFO {
    QWORD paDTB;
    QWORD vaBase;
    QWORD cbSize;
    // optional non-required values below
    VMM_WIN_EPROCESS_OFFSET OffsetEPROCESS;
    QWORD vaEntry;
    QWORD vaPsLoadedModuleList;
    QWORD vaKDBG;
    DWORD dwPidMemCompression;
} VMM_KERNELINFO;

typedef NTSTATUS VMMFN_RtlDecompressBuffer(
    USHORT CompressionFormat,
    PUCHAR UncompressedBuffer,
    ULONG  UncompressedBufferSize,
    PUCHAR CompressedBuffer,
    ULONG  CompressedBufferSize,
    PULONG FinalUncompressedSize
);

typedef struct tdVMM_DYNAMIC_LOAD_FUNCTIONS {
    // functions below may be loaded on startup
    // NB! null checks are required before use!
    VMMFN_RtlDecompressBuffer *RtlDecompressBuffer;     // ntdll.dll!RtlDecompressBuffer
} VMM_DYNAMIC_LOAD_FUNCTIONS;

typedef struct tdVMM_CONTEXT {
    CRITICAL_SECTION MasterLock;
    VMMOBCONTAINER PROC;        // contains VMM_PROCESS_TABLE
    VMM_MEMORYMODEL_FUNCTIONS fnMemoryModel;
    VMM_MEMORYMODEL_TP tpMemoryModel;
    BOOL f32;
    VMM_SYSTEM_TP tpSystem;
    DWORD flags;    // VMM_FLAG_*
    struct {
        BOOL fEnabled;
        HANDLE hThread;
        DWORD cMs_TickPeriod;
        DWORD cTick_Phys;
        DWORD cTick_TLB;
        DWORD cTick_ProcPartial;
        DWORD cTick_ProcTotal;
    } ThreadProcCache;
    VMM_STATISTICS stat;
    VMM_KERNELINFO kernel;
    VMM_DYNAMIC_LOAD_FUNCTIONS fn;
    PVOID pVmmVfsModuleList;
    VMMOBCONTAINER ObCEPROCESSCachePrefetch;
    VMM_CACHE_TABLE PHYS;
    VMM_CACHE_TABLE TLB;
} VMM_CONTEXT, *PVMM_CONTEXT;

typedef struct tdVMM_MAIN_CONTEXT {
    VMMCONFIG cfg;
    LEECHCORE_CONFIG dev;
    PVOID pvStatistics;
} VMM_MAIN_CONTEXT, *PVMM_MAIN_CONTEXT;

// ----------------------------------------------------------------------------
// VMM global variables below:
// ----------------------------------------------------------------------------

PVMM_CONTEXT ctxVmm;
PVMM_MAIN_CONTEXT ctxMain;

#define vmmprintf(format, ...)          { if(ctxMain->cfg.fVerboseDll)       { printf(format, ##__VA_ARGS__); } }
#define vmmprintfv(format, ...)         { if(ctxMain->cfg.fVerbose)          { printf(format, ##__VA_ARGS__); } }
#define vmmprintfvv(format, ...)        { if(ctxMain->cfg.fVerboseExtra)     { printf(format, ##__VA_ARGS__); } }
#define vmmprintfvvv(format, ...)       { if(ctxMain->cfg.fVerboseExtraTlp)  { printf(format, ##__VA_ARGS__); } }
#define vmmprintf_fn(format, ...)       vmmprintf("%s: "format, __func__, ##__VA_ARGS__);
#define vmmprintfv_fn(format, ...)      vmmprintfv("%s: "format, __func__, ##__VA_ARGS__);
#define vmmprintfvv_fn(format, ...)     vmmprintfvv("%s: "format, __func__, ##__VA_ARGS__);
#define vmmprintfvvv_fn(format, ...)    vmmprintfvvv("%s: "format, __func__, ##__VA_ARGS__);

// ----------------------------------------------------------------------------
// CACHE AND TLB FUNCTIONALITY BELOW:
// ----------------------------------------------------------------------------

/*
* Retrieve an item from the cache.
* CALLER DECREF: return
* -- wTblTag
* -- qwA
* -- return
*/
PVMMOB_MEM VmmCacheGet(_In_ WORD wTblTag, _In_ QWORD qwA);

/*
* Retrieve a page table (0x1000 bytes) via the TLB cache.
* CALLER DECREF: return
* -- pa
* -- fCacheOnly = if set do not make a request to underlying device if not in cache.
* -- return
*/
PVMMOB_MEM VmmTlbGetPageTable(_In_ QWORD pa, _In_ BOOL fCacheOnly);

/*
* Check if an address page exists in the indicated cache.
* -- wTblTag
* -- qwA
* -- return
*/
BOOL VmmCacheExists(_In_ WORD wTblTag, _In_ QWORD qwA);

/*
* Check out an empty memory cache item from the cache. NB! once the item is
* filled (successfully or unsuccessfully) it must be returned to the cache with
* VmmCacheReserveReturn and must _NOT_ otherwise be DEFREF'ed.
* CALLER DECREF SPECIAL: return
* -- wTblTag
* -- return
*/
PVMMOB_MEM VmmCacheReserve(_In_ WORD wTblTag);

/*
* Return an entry retrieved with VmmCacheReserve to the cache.
* NB! no other items may be returned with this function!
* FUNCTION DECREF SPECIAL: pOb
* -- pOb
*/
VOID VmmCacheReserveReturn(_In_opt_ PVMMOB_MEM pOb);

// ----------------------------------------------------------------------------
// VMM object manager function definitions below:
// ----------------------------------------------------------------------------

/*
* Allocate a new vmm object manager memory object.
* -- tag = tag identifying the type of object.
* -- uFlags = flags as given by LocalAlloc.
* -- uBytes = bytes of object (excluding object header).
* -- pfnRef_0 = optional callback for cleanup o be called before object is destroyed.
*               (if object contains objects which references should be decremented
                 before destruction of this 'parent' object).
* -- pfnRef_1 = optional callback for when object reach refcount = 1 at DECREF.
* -- return = allocated object on success, with refcount = 1, - NULL on fail.
*/
PVOID VmmOb_Alloc(_In_ WORD tag, _In_ UINT uFlags, _In_ SIZE_T uBytes, _In_opt_ VOID(*pfnRef_0)(_In_ PVOID pVmmOb), _In_opt_ VOID(*pfnRef_1)(_In_ PVOID pVmmOb));

/*
* Increase the reference count of a vmm object by one.
* -- pVmmOb
* -- return
*/
PVOID VmmOb_INCREF(PVOID pVmmOb);

/*
* Decrease the reference count of a vmm object by one.
* NB! Do not use object after DECREF - other threads might have also DECREF'ed
* the object at same time making it to be free'd - making the memory invalid.
*/
VOID VmmOb_DECREF(PVOID pVmmOb);

/*
* Retrieve an enclosed VmmOb from the given pVmmObContainer. Reference count
* of the retrieved VmmOb must be decremented by caller after use is completed!
*/
PVOID VmmObContainer_GetOb(_In_ PVMMOBCONTAINER pVmmObContainer);

/*
* Set or Replace a VmmOb in the pVmmObContainer.
*/
VOID VmmObContainer_SetOb(_In_ PVMMOBCONTAINER pVmmObContainer, _In_opt_ PVOID pVmmOb);

/*
* Allocate a VmmObDataSet and optionally set it to only contain unique items.
* CALLER_DECREF: return
* -- fUnique = set will only contain unique values.
* -- return
*/
PVMMOB_DATASET VmmObDataSet_Alloc(_In_ BOOL fUnique);

/*
* Insert a value into a VmmObDataSet.
* This function is not meant to be called in a multi-threaded context.
* -- pDataSet
* -- v
* -- return = insertion was successful.
*/
BOOL VmmObDataSet_Put(_In_ PVMMOB_DATASET pDataSet, _In_ QWORD v);


// ----------------------------------------------------------------------------
// VMM function definitions below:
// ----------------------------------------------------------------------------

#ifdef VMM_MULTITHREAD_ENABLE

#define VmmLockAcquire()    // no need to acquire lock if multithreaded access is ok
#define VmmLockRelease()    // no need to acquire lock if multithreaded access is ok

#else /* VMM_MULTITHREAD_ENABLE */

/*
* Acquire the VMM master lock. Required if interoperating with the VMM from a
* function that has not already acquired the lock. Lock must be relased in a
* fairly short amount of time in order for the VMM to continue working.
* !!! MUST NEVER BE ACQUIRED FOR LENGTHY AMOUNT OF TIMES !!!
*/
inline VOID VmmLockAcquire()
{
    EnterCriticalSection(&ctxVmm->MasterLock);
}

/*
* Release VMM master lock that has previously been acquired by VmmLockAcquire.
*/
inline VOID VmmLockRelease()
{
    LeaveCriticalSection(&ctxVmm->MasterLock);
}

#endif /* VMM_MULTITHREAD_ENABLE */

/*
* Write a virtually contigious arbitrary amount of memory.
* -- pProcess
* -- qwVA
* -- pb
* -- cb
* -- return = TRUE on success, FALSE on partial or zero write.
*/
BOOL VmmWrite(_In_opt_ PVMM_PROCESS pProcess, _In_ QWORD qwVA, _In_ PBYTE pb, _In_ DWORD cb);

/*
* Write physical memory and clear any VMM caches that may contain data.
* -- pa
* -- pb
* -- cb
* -- return
*/
BOOL VmmWritePhysical(_In_ QWORD pa, _In_ PBYTE pb, _In_ DWORD cb);

/*
* Read a virtually contigious arbitrary amount of memory containing cch number of
* unicode characters and convert them into ansi characters. If the default char
* is used (no translation) the flag fDefaultChar will be set.
* -- pProcess
* -- qwVA
* -- sz
* -- cch
* -- fDefaultChar = default char used in translation.
* -- return
*/
_Success_(return)
BOOL VmmReadString_Unicode2Ansi(_In_ PVMM_PROCESS pProcess, _In_ QWORD qwVA, _Out_writes_(cch) LPSTR sz, _In_ DWORD cch, _Out_opt_ PBOOL pfDefaultChar);

/*
* Read a contigious arbitrary amount of memory, virtual or physical.
* Virtual memory is read if a process is specified in pProcess parameter.
* Physical memory is read if NULL is specified in pProcess parameter.
* -- pProcess
* -- qwVA = NULL=='physical memory read', PTR=='virtual memory read'
* -- pb
* -- cb
* -- return
*/
BOOL VmmRead(_In_opt_ PVMM_PROCESS pProcess, _In_ QWORD qwA, _Out_ PBYTE pb, _In_ DWORD cb);

/*
* Read a contigious arbitrary amount of memory, physical or virtual, and report
* the number of bytes read in pcbRead.
* Virtual memory is read if a process is specified in pProcess.
* Physical memory is read if NULL is specified in pProcess.
* -- pProcess = NULL=='physical memory read', PTR=='virtual memory read'
* -- qwA
* -- pb
* -- cb
* -- pcbRead
* -- flags = flags as in VMM_FLAG_*
*/
VOID VmmReadEx(_In_opt_ PVMM_PROCESS pProcess, _In_ QWORD qwA, _Out_ PBYTE pb, _In_ DWORD cb, _Out_opt_ PDWORD pcbReadOpt, _In_ QWORD flags);

/*
* Read a single 4096-byte page of memory, virtual or physical.
* Virtual memory is read if a process is specified in pProcess.
* Physical memory is read if NULL is specified in pProcess.
* -- pProcess = NULL=='physical memory read', PTR=='virtual memory read'
* -- qwA
* -- pbPage
* -- return
*/
BOOL VmmReadPage(_In_opt_ PVMM_PROCESS pProcess, _In_ QWORD qwA, _Inout_bytecount_(4096) PBYTE pbPage);

/*
* Scatter read virtual memory. Non contiguous 4096-byte pages.
* -- pProcess
* -- ppMEMsVirt
* -- cpMEMsVirt
* -- flags = flags as in VMM_FLAG_*, [VMM_FLAG_NOCACHE for supression of data (not tlb) caching]
*/
VOID VmmReadScatterVirtual(_In_ PVMM_PROCESS pProcess, _Inout_ PPMEM_IO_SCATTER_HEADER ppMEMsVirt, _In_ DWORD cpMEMsVirt, _In_ QWORD flags);

/*
* Scatter read physical memory. Non contiguous 4096-byte pages.
* -- ppMEMsPhys
* -- cpMEMsPhys
* -- flags = flags as in VMM_FLAG_*, [VMM_FLAG_NOCACHE for supression of caching]
*/
VOID VmmReadScatterPhysical(_Inout_ PPMEM_IO_SCATTER_HEADER ppMEMsPhys, _In_ DWORD cpMEMsPhys, _In_ QWORD flags);

/*
* Read a single 4096-byte page of physical memory.
* -- qwPA
* -- pbPage
* -- return
*/
BOOL VmmReadPhysicalPage(_In_ QWORD qwPA, _Inout_bytecount_(4096) PBYTE pbPage);

/*
* Translate a virtual address to a physical address by walking the page tables.
* -- paDTB
* -- fUserOnly
* -- va
* -- ppa
* -- return
*/
_Success_(return)
inline BOOL VmmVirt2PhysEx(_In_ QWORD paDTB, _In_ BOOL fUserOnly, _In_ QWORD va, _Out_ PQWORD ppa)
{
    if(ctxVmm->tpMemoryModel == VMM_MEMORYMODEL_NA) { return FALSE; }
    return ctxVmm->fnMemoryModel.pfnVirt2Phys(paDTB, fUserOnly, -1, va, ppa);
}

/*
* Translate a virtual address to a physical address by walking the page tables.
* -- pProcess
* -- va
* -- ppa
* -- return
*/
_Success_(return)
inline BOOL VmmVirt2Phys(_In_ PVMM_PROCESS pProcess, _In_ QWORD va, _Out_ PQWORD ppa)
{
    if(ctxVmm->tpMemoryModel == VMM_MEMORYMODEL_NA) { return FALSE; }
    return ctxVmm->fnMemoryModel.pfnVirt2Phys(pProcess->paDTB, pProcess->fUserOnly, -1, va, ppa);
}

/*
* Spider the TLB (page table cache) to load all page table pages into the cache.
* This is done to speed up various subsequent virtual memory accesses.
* NB! pages may fall out of the cache if it's in heavy use or doe to timing.
* -- pProcess
*/
inline VOID VmmTlbSpider(_In_ PVMM_PROCESS pProcess)
{
    if(ctxVmm->tpMemoryModel == VMM_MEMORYMODEL_NA) { return; }
    ctxVmm->fnMemoryModel.pfnTlbSpider(pProcess);
}

/*
* Try verify that a supplied page table in pb is valid by analyzing it.
* -- pb = 0x1000 bytes containing the page table page.
* -- pa = physical address if the page table page.
* -- fSelfRefReq = is a self referential entry required to be in the map? (PML4 for Windows).
*/
inline BOOL VmmTlbPageTableVerify(_Inout_ PBYTE pb, _In_ QWORD pa, _In_ BOOL fSelfRefReq)
{
    if(ctxVmm->tpMemoryModel == VMM_MEMORYMODEL_NA) { return FALSE; }
    return ctxVmm->fnMemoryModel.pfnTlbPageTableVerify(pb, pa, fSelfRefReq);
}

/*
* Retrieve information of the virtual2physical address translation for the
* supplied process. The Virtual address must be supplied in pVirt2PhysInfo upon
* entry.
* -- pProcess
* -- pVirt2PhysInfo
*/
inline VOID VmmVirt2PhysGetInformation(_Inout_ PVMM_PROCESS pProcess, _Inout_ PVMM_VIRT2PHYS_INFORMATION pVirt2PhysInfo)
{
    if(ctxVmm->tpMemoryModel == VMM_MEMORYMODEL_NA) { return; }
    ctxVmm->fnMemoryModel.pfnVirt2PhysGetInformation(pProcess, pVirt2PhysInfo);
}

/*
* Map a tag into the sorted memory map in O(log2) operations. Supply only one
* of szTag or wszTag. Tags are usually module/dll name.
* -- pProcess
* -- vaBase
* -- vaLimit = limit == vaBase + size (== top address in range +1)
* -- szTag
* -- wszTag
* -- fWoW64
* -- fOverwrite
*/
inline VOID VmmMemMapTag(_In_ PVMM_PROCESS pProcess, _In_ QWORD vaBase, _In_ QWORD vaLimit, _In_opt_ LPSTR szTag, _In_opt_ LPWSTR wszTag, _In_opt_ BOOL fWoW64, _In_ BOOL fOverwrite)
{
    if(ctxVmm->tpMemoryModel == VMM_MEMORYMODEL_NA) { return; }
    ctxVmm->fnMemoryModel.pfnMapTag(pProcess, vaBase, vaLimit, szTag, wszTag, fWoW64, fOverwrite);
}

/*
* Retrieve the memory map.
* CALLER DECREF: ppObMemMap
* -- pProcess
* -- flags
* -- ppObMemMap
* -- return
*/
_Success_(return)
inline BOOL VmmMemMapGetEntries(_In_ PVMM_PROCESS pProcess, _In_ DWORD flags, _Out_ PVMMOB_MEMMAP *ppObMemMap)
{
    if(ctxVmm->tpMemoryModel == VMM_MEMORYMODEL_NA) { return FALSE; }
    return ctxVmm->fnMemoryModel.pfnMapGetEntries(pProcess, flags, ppObMemMap);
}

/*
* Retrieve a human-readable memory map as text in buffer.
* CALLER DECREF: ppObDisplay
* -- pProcess
* -- flags = flags as specified by VMM_MAP_FLAGS*
* -- ppObDisplay
* -- return
*/
_Success_(return)
inline BOOL VmmMemMapGetDisplay(_In_ PVMM_PROCESS pProcess, _In_ DWORD flags, _Out_ PVMMOB_PDATA *ppObDisplay)
{
    if(ctxVmm->tpMemoryModel == VMM_MEMORYMODEL_NA) { return FALSE; }
    return ctxVmm->fnMemoryModel.pfnMapGetDisplay(pProcess, flags, ppObDisplay);
}

/*
* Retrieve an existing process given a process id (PID).
* CALLER DECREF: return
* -- dwPID
* -- return = a process struct, or NULL if not found.
*/
PVMM_PROCESS VmmProcessGet(_In_ DWORD dwPID);

/*
* Retrieve the next process given a process. This may be useful when iterating
* over a process list. NB! Listing of next item may fail prematurely if the
* previous process is terminated while having a reference to it.
* FUNCTION DECREF: pProcess
* CALLER DECREF: return
* -- pProcess = a process struct, or NULL if first.
     NB! function DECREF's  pProcess and must not be used after call!
* -- return = a process struct, or NULL if not found.
*/
PVMM_PROCESS VmmProcessGetNext(_In_opt_ PVMM_PROCESS pProcess);

/*
* Create a new process object. New process object are created in a separate
* data structure and won't become visible to the "Process" functions until
* after the VmmProcessCreateFinish have been called.
* CALLER DECREF: return
* -- fTotalRefresh = create a completely new entry - i.e. do not copy any form
*                    of data from the old entry such as module and memory maps.
* -- dwPID
* -- dwState
* -- paDTB
* -- paDTB_UserOpt
* -- szName
* -- fUserOnly = user mode process (hide supervisor pages from view)
*/
PVMM_PROCESS VmmProcessCreateEntry(_In_ BOOL fTotalRefresh, _In_ DWORD dwPID, _In_ DWORD dwState, _In_ QWORD paDTB, _In_ QWORD paDTB_UserOpt, _In_ CHAR szName[16], _In_ BOOL fUserOnly);

/*
* Activate the pending, not yet active, processes added by VmmProcessCreateEntry.
* This will also clear any previous processes.
*/
VOID VmmProcessCreateFinish();

/*
* List the PIDs and put them into the supplied table.
* -- pPIDs = user allocated DWORD array to receive result, or NULL.
* -- pcPIDs = ptr to number of DWORDs in pPIDs on entry - number of PIDs in system on exit.
*/
VOID VmmProcessListPIDs(_Out_writes_opt_(*pcPIDs) PDWORD pPIDs, _Inout_ PSIZE_T pcPIDs);

/* 
* Clear the specified cache from all entries.
* -- wTblTag
*/
VOID VmmCacheClear(_In_ WORD wTblTag);

/*
* Invalidate cache entries belonging to a specific physical address.
* -- pa
*/
VOID VmmCacheInvalidate(_In_ QWORD pa);

/*
* Prefetch a set of addresses contained in pObPrefetchAddresses into the cache.
* This is useful when reading data from somewhat known addresses over higher
* latency connections.
* -- pProcess
* -- pObPrefetchAddresses
*/
VOID VmmCachePrefetchPages(_In_opt_ PVMM_PROCESS pProcess, _In_opt_ PVMMOB_DATASET pObPrefetchAddresses);

/*
* Initialize the memory model specified and discard any previous memory models
* that may be in action.
* -- tp
*/
VOID VmmInitializeMemoryModel(_In_ VMM_MEMORYMODEL_TP tp);

/*
* Initialize a new VMM context. This must always be done before calling any
* other VMM functions. An alternative way to do this is to call the function:
* VmmProcInitialize.
* -- return
*/
BOOL VmmInitialize();

/*
* Close and clean up the VMM context inside the PCILeech context, if existing.
*/
VOID VmmClose();

#endif /* __VMM_H__ */
