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
#include "ob.h"

typedef unsigned __int64                QWORD, *PQWORD;

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
#define VMM_FLAG_NOPAGING                       0x0010  // do not try to retrieve memory from paged out memory from pagefile/compressed (even if possible).

#define PAGE_SIZE                               0x1000

#define VMM_KADDR32_8(va)                       ((va & 0xf0000007) == 0x80000000)
#define VMM_KADDR64(va)                         ((va & 0xffff8000'00000000) == 0xffff8000'00000000)
#define VMM_KADDR64_8(va)                       ((va & 0xffff8000'00000007) == 0xffff8000'00000000)
#define VMM_KADDR64_16(va)                      ((va & 0xffff8000'0000000f) == 0xffff8000'00000000)
#define VMM_KADDR64_PAGE(va)                    ((va & 0xffff8000'00000fff) == 0xffff8000'00000000)

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
    QWORD BaseDllName_Buffer;
    WORD  BaseDllName_Length;
} VMM_MODULEMAP_ENTRY, *PVMM_MODULEMAP_ENTRY;

typedef struct tdVMMDATALIST {
    DWORD iNext;
    QWORD Value;
} VMMDATALIST, *PVMMDATALIST;

typedef struct tdVMMOB_DATA {
    OB ObHdr;
    union {
        BYTE pbData[];
        DWORD pdwData[];
        QWORD pqwData[];
        VMMDATALIST pList[];
    };
} VMMOB_DATA, *PVMMOB_DATA;

typedef struct tdVMMOB_MEMMAP {
    OB ObHdr;
    BOOL fValid;                // map is valid (did not fail initialization)
    BOOL fTagModules;           // map contains tags from modules.
    BOOL fTagScan;              // map contains tags from scan.
    DWORD cMap;                 // # map entries.
    DWORD cbDisplay;            // byte count of display map (even if not existing yet).
    PVMMOB_DATA pObDisplay;    // human readable memory map.
    VMM_MEMMAP_ENTRY pMap[];    // map entries
} VMMOB_MEMMAP, *PVMMOB_MEMMAP;

typedef struct tdVMMOB_MODULEMAP {
    OB ObHdr;
    BOOL fValid;                // map is valid (did not fail initialization).
    DWORD cMap;                 // # map entries.
    DWORD cbDisplay;            // size of 'text' module map.
    PBYTE pbDisplay;            // 'text' module map stored in-object after pMap).
    VMM_MODULEMAP_ENTRY pMap[]; // map entries
} VMMOB_MODULEMAP, *PVMMOB_MODULEMAP;

typedef struct tdVMMWIN_USER_PROCESS_PARAMETERS {
    BOOL fProcessed;
    DWORD cchImagePathName;
    DWORD cchCommandLine;
    LPSTR szImagePathName;
    LPSTR szCommandLine;
} VMMWIN_USER_PROCESS_PARAMETERS, *PVMMWIN_USER_PROCESS_PARAMETERS;

#define VMM_PHYS2VIRT_INFORMATION_MAX_PROCESS_RESULT    4
#define VMM_PHYS2VIRT_MAX_AGE_MS                        2000

typedef struct tdVMMOB_PHYS2VIRT_INFORMATION {
    OB ObHdr;
    QWORD paTarget;
    DWORD cvaList;
    DWORD dwPID;
    QWORD pvaList[VMM_PHYS2VIRT_INFORMATION_MAX_PROCESS_RESULT];
} VMMOB_PHYS2VIRT_INFORMATION, *PVMMOB_PHYS2VIRT_INFORMATION;

// 'static' process information that should be kept even in the ase of a total
// process refresh. Only use for information that may never change or things
// that may not affect analysis (like cache preload addresses that only may
// speed things up - but not change analysis result). May also be used by
// internal plugins to store persistent information in various plugin-internal
// thread safe ways. Use with extreme care!
typedef struct tdVMMOB_PROCESS_PERSISTENT {
    OB ObHdr;
    BOOL fIsPostProcessingComplete;
    POB_CONTAINER pObCLdrModulesCachePrefetch32;
    POB_CONTAINER pObCLdrModulesCachePrefetch64;
    VMMWIN_USER_PROCESS_PARAMETERS UserProcessParams;
    // kernel path and long name (from EPROCESS.SeAuditProcessCreationInfo)
    WORD cchNameLong;
    WORD cchPathKernel;
    LPSTR szNameLong;
    CHAR szPathKernel[128];
    // plugin functionality below:
    struct {
        QWORD vaVirt2Phys;
        QWORD paPhys2Virt;
    } Plugin;
} VMMOB_PROCESS_PERSISTENT, *PVMMOB_PROCESS_PERSISTENT;

typedef struct tdVMM_PROCESS {
    OB ObHdr;
    CRITICAL_SECTION LockUpdate;
    DWORD dwPID;
    DWORD dwPPID;
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
    struct {
        QWORD vaPEB;
        DWORD vaPEB32;      // WoW64 only
        QWORD vaENTRY;
        BOOL fWow64;
        QWORD vaSeAuditProcessCreationInfo;
        struct {
            QWORD va;
            DWORD cb;
            BYTE pb[0x800];
        } EPROCESS;
    } win;
    struct {
        POB_CONTAINER pObCLdrModulesDisplayCache;
        POB_CONTAINER pObCPeDumpDirCache;
        POB_CONTAINER pObCPhys2Virt;
    } Plugin;
} VMM_PROCESS, *PVMM_PROCESS;

typedef struct tdVMMOB_PROCESS_TABLE {
    OB ObHdr;
    SIZE_T c;                       // Total # of processes in table
    SIZE_T cActive;                 // # of active processes (state = 0) in table
    WORD _iFLink;
    WORD _iFLinkM[VMM_PROCESSTABLE_ENTRIES_MAX];
    PVMM_PROCESS _M[VMM_PROCESSTABLE_ENTRIES_MAX];
    POB_CONTAINER pObCNewPROC;      // contains VMM_PROCESS_TABLE
} VMMOB_PROCESS_TABLE, *PVMMOB_PROCESS_TABLE;

#define VMM_CACHE2_REGIONS      17
#define VMM_CACHE2_BUCKETS      2039
#define VMM_CACHE2_MAX_ENTRIES  0x8000

#define VMM_CACHE_TAG_PHYS      'Ph'
#define VMM_CACHE_TAG_PAGING    'Pg'
#define VMM_CACHE_TAG_TLB       'Tb'

typedef struct tdVMMOB_MEM {
    OB Ob;
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
    VOID(*pfnPhys2VirtGetInformation)(_In_ PVMM_PROCESS pProcess, _Inout_ PVMMOB_PHYS2VIRT_INFORMATION pP2V);
    VOID(*pfnMapInitialize)(_In_ PVMM_PROCESS pProcess);
    VOID(*pfnMapTag)(_In_ PVMM_PROCESS pProcess, _In_ QWORD vaBase, _In_ QWORD vaLimit, _In_opt_ LPSTR szTag, _In_opt_ LPWSTR wszTag, _In_ BOOL fWoW64, _In_ BOOL fOverwrite);
    BOOL(*pfnMapGetEntries)(_In_ PVMM_PROCESS pProcess, _In_ DWORD flags, _Out_ PVMMOB_MEMMAP *ppObMemMap);
    BOOL(*pfnMapGetDisplay)(_In_ PVMM_PROCESS pProcess, _In_ DWORD flags, _Out_ PVMMOB_DATA *ppObDisplay);
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
    BOOL fVerboseDll;
    BOOL fVerbose;
    BOOL fVerboseExtra;
    BOOL fVerboseExtraTlp;
    BOOL fDisableBackgroundRefresh;
    BOOL fDisableLeechCoreClose;    // when device 'existing'
    BOOL fDisableSymbolServerOnStartup;
} VMMCONFIG, *PVMMCONFIG;

typedef struct tdVMM_STATISTICS {
    QWORD cPhysCacheHit;
    QWORD cPhysReadSuccess;
    QWORD cPhysReadFail;
    QWORD cPhysWrite;
    QWORD cPhysRefreshCache;
    QWORD cPageReadSuccessCacheHit;
    QWORD cPageReadSuccessCompressed;
    QWORD cPageReadSuccessDemandZero;
    QWORD cPageReadFailedCacheHit;
    QWORD cPageReadFailedCompressed;
    QWORD cPageReadFailed;
    QWORD cPageRefreshCache;
    QWORD cTlbCacheHit;
    QWORD cTlbReadSuccess;
    QWORD cTlbReadFail;
    QWORD cTlbRefreshCache;
    QWORD cProcessRefreshPartial;
    QWORD cProcessRefreshFull;
} VMM_STATISTICS, *PVMM_STATISTICS;

typedef struct tdVMM_WIN_EPROCESS_OFFSET {
    BOOL fValid;
    WORD cbMaxOffset;
    WORD State;
    WORD DTB;
    WORD Name;
    WORD PID;
    WORD PPID;
    WORD FLink;
    WORD BLink;
    WORD PEB;
    WORD DTB_User;
    WORD SeAuditProcessCreationInfo;
    struct {
        // values may not exist - indicated by zero offset
        BOOL fFailInitialize;
        WORD CreateTime;
        WORD ExitTime;
    } opt;
} VMM_WIN_EPROCESS_OFFSET, *PVMM_WIN_EPROCESS_OFFSET;

typedef struct tdVMMWIN_REGISTRY_CONTEXT    *PVMMWIN_REGISTRY_CONTEXT;
typedef QWORD                               VMMWIN_PDB_HANDLE;

typedef struct tdVMMWIN_TCPIP_OFFSET_TcpE {
    BOOL _fValid;
    BOOL _fProcessedTry;
    WORD _Size;
    WORD INET_AF;
    WORD INET_AF_AF;
    WORD INET_Addr;
    WORD FLink;
    WORD State;
    WORD PortSrc;
    WORD PortDst;
    WORD EProcess;
    WORD Time;
} VMMWIN_TCPIP_OFFSET_TcpE, *PVMMWIN_TCPIP_OFFSET_TcpE;

typedef struct tdVMMWIN_TCPIP_CONTEXT {
    CRITICAL_SECTION LockUpdate;
    BOOL fInitialized;
    QWORD vaPartitionTable;
    VMMWIN_TCPIP_OFFSET_TcpE OTcpE;
} VMMWIN_TCPIP_CONTEXT, *PVMMWIN_TCPIP_CONTEXT;

typedef struct tdVMMWIN_MEMCOMPRESS_OFFSET {
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
} VMMWIN_MEMCOMPRESS_OFFSET, *PVMMWIN_MEMCOMPRESS_OFFSET;

typedef struct tdVMMWIN_MEMCOMPRESS_CONTEXT {
    QWORD vaEPROCESS;
    DWORD dwPid;
    DWORD dwPageFileNumber;
    BOOL fValid;
    BOOL fInitialized;
    QWORD vaSmGlobals;
    QWORD vaKeyToStoreTree;
    VMMWIN_MEMCOMPRESS_OFFSET O;
} VMMWIN_MEMCOMPRESS_CONTEXT, *PVMMWIN_MEMCOMPRESS_CONTEXT;

typedef struct tdVMMWIN_OPTIONAL_KERNEL_CONTEXT {
    BOOL fInitialized;
    DWORD cCPUs;
    QWORD vaPfnDatabase;
    QWORD vaPsLoadedModuleListExp;
    struct {
        QWORD va;
        // encrypted kdbg info below (x64 win8+)
        QWORD vaKdpDataBlockEncoded;
        QWORD qwKiWaitAlways;
        QWORD qwKiWaitNever;
    } KDBG;
} VMMWIN_OPTIONAL_KERNEL_CONTEXT, *PVMMWIN_OPTIONAL_KERNEL_CONTEXT;

typedef struct tdVMM_KERNELINFO {
    QWORD paDTB;
    QWORD vaBase;
    QWORD cbSize;
    // Windows-only related values below:
    QWORD vaEntry;
    DWORD dwPidRegistry;
    DWORD dwVersionMajor;
    DWORD dwVersionMinor;
    DWORD dwVersionBuild;
    QWORD vaPsLoadedModuleListPtr;
    VMM_WIN_EPROCESS_OFFSET OffsetEPROCESS;
    VMMWIN_MEMCOMPRESS_CONTEXT MemCompress;
    VMMWIN_OPTIONAL_KERNEL_CONTEXT opt;
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
    HMODULE hModuleVmm;             // do not call FreeLibrary on hModuleVmm
    CRITICAL_SECTION MasterLock;
    POB_CONTAINER pObCPROC;         // contains VMM_PROCESS_TABLE
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
        DWORD cTick_Registry;
    } ThreadProcCache;
    VMM_STATISTICS stat;
    VMM_KERNELINFO kernel;
    POB pObVfsDumpContext;
    PVOID pPdbContext;
    PVMMWIN_REGISTRY_CONTEXT pRegistry;
    VMMWIN_TCPIP_CONTEXT TcpIp;
    QWORD paPluginPhys2VirtRoot;
    VMM_DYNAMIC_LOAD_FUNCTIONS fn;
    PVOID pVmmVfsModuleList;
    POB_CONTAINER pObCCachePrefetchEPROCESS;
    POB_CONTAINER pObCCachePrefetchRegistry;
    // page caches
    struct {
        VMM_CACHE_TABLE PHYS;
        VMM_CACHE_TABLE TLB;
        VMM_CACHE_TABLE PAGING;
        POB_VSET PAGING_FAILED;
    } Cache;
    // thread worker count
    struct {
        BOOL fEnabled;
        DWORD c;
    } ThreadWorkers;
} VMM_CONTEXT, *PVMM_CONTEXT;

typedef struct tdVMM_MAIN_CONTEXT {
    VMMCONFIG cfg;
    LEECHCORE_CONFIG dev;
    struct {
        BOOL fInitialized;
        BOOL fEnable;
        BOOL fServerEnable;
        CHAR szLocal[MAX_PATH];
        CHAR szServer[MAX_PATH];
        CHAR szSymbolPath[MAX_PATH];
    } pdb;
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
// VMM function definitions below:
// ----------------------------------------------------------------------------

/*
* Write a virtually contigious arbitrary amount of memory.
* -- pProcess
* -- qwA
* -- pb
* -- cb
* -- return = TRUE on success, FALSE on partial or zero write.
*/
BOOL VmmWrite(_In_opt_ PVMM_PROCESS pProcess, _In_ QWORD qwA, _In_reads_(cb) PBYTE pb, _In_ DWORD cb);

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

/*
* Read a Windows _UNICODE_STRING from an address into a buffer as an ascii-string.
* Conversion from unicode characters to ascii-characters are done automatically
* and some characters may be replaced with default characters.
* -- pProcess
* -- f32 = _UNICODE_STRING is 32-bit _UNICODE_STRING or 64-bit _UNICODE_STRING.
* -- flags =  = flags as in VMM_FLAG_*
* -- vaUS
* -- sz
* -- cch
* -- pcch = number of characters read (excluding null terminator)
* -- pfDefaultChar
* -- return
*/
_Success_(return)
BOOL VmmRead_U2A(_In_ PVMM_PROCESS pProcess, _In_ BOOL f32, _In_ QWORD flags, _In_ QWORD vaUS, _Out_writes_opt_(cch) LPSTR sz, _In_ DWORD cch, _Out_opt_ PDWORD pcch, _Out_opt_ PBOOL pfDefaultChar);

/*
* Read a Windows _UNICODE_STRING from an address into a newly allocated ascii-string.
* Conversion from unicode characters to ascii-characters are done automatically
* and some characters may be replaced with default characters.
* CALLER LocalFree: psz
* -- pProcess
* -- f32 = _UNICODE_STRING is 32-bit _UNICODE_STRING or 64-bit _UNICODE_STRING.
* -- flags =  = flags as in VMM_FLAG_*
* -- vaUS
* -- psz = pointer to receive function-allocated string. Caller is responsible for LocalFree.
* -- pcch = number of characters read (excluding null terminator)
* -- pfDefaultChar
* -- return
*/
_Success_(return)
BOOL VmmRead_U2A_Alloc(_In_ PVMM_PROCESS pProcess, _In_ BOOL f32, _In_ QWORD flags, _In_ QWORD vaUS, _Out_ LPSTR *psz, _Out_ PDWORD pcch, _Out_opt_ PBOOL pfDefaultChar);

/*
* Read a Windows _UNICODE_STRING buffer from an address into a buffer as an ascii-string.
* Conversion from unicode characters to ascii-characters are done automatically
* and some characters may be replaced with default characters.
* -- pProcess
* -- flags = flags as in VMM_FLAG_*
* -- vaStr
* -- cbStr
* -- sz
* -- cch
* -- pcch = number of characters read (excluding null terminator)
* -- pfDefaultChar
* -- return
*/
_Success_(return)
BOOL VmmRead_U2A_RawStr(_In_ PVMM_PROCESS pProcess, _In_ QWORD flags, _In_ QWORD vaStr, _In_ WORD cbStr, _Out_writes_(cch) LPSTR sz, _In_ DWORD cch, _Out_opt_ PDWORD pcch, _Out_opt_ PBOOL pfDefaultChar);

/*
* Read a contigious arbitrary amount of memory, virtual or physical.
* Virtual memory is read if a process is specified in pProcess parameter.
* Physical memory is read if NULL is specified in pProcess parameter.
* -- pProcess
* -- qwA
* -- pb
* -- cb
* -- return
*/
_Success_(return)
BOOL VmmRead(_In_opt_ PVMM_PROCESS pProcess, _In_ QWORD qwA, _Out_writes_(cb) PBYTE pb, _In_ DWORD cb);

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
VOID VmmReadEx(_In_opt_ PVMM_PROCESS pProcess, _In_ QWORD qwA, _Out_writes_(cb) PBYTE pb, _In_ DWORD cb, _Out_opt_ PDWORD pcbReadOpt, _In_ QWORD flags);

/*
* Read a single 4096-byte page of memory, virtual or physical.
* Virtual memory is read if a process is specified in pProcess.
* Physical memory is read if NULL is specified in pProcess.
* -- pProcess = NULL=='physical memory read', PTR=='virtual memory read'
* -- qwA
* -- pbPage
* -- return
*/
_Success_(return)
BOOL VmmReadPage(_In_opt_ PVMM_PROCESS pProcess, _In_ QWORD qwA, _Inout_bytecount_(4096) PBYTE pbPage);

/*
* Scatter read virtual memory. Non contiguous 4096-byte pages.
* -- pProcess
* -- ppMEMsVirt
* -- cpMEMsVirt
* -- flags = flags as in VMM_FLAG_*, [VMM_FLAG_NOCACHE for supression of data (not tlb) caching]
*/
VOID VmmReadScatterVirtual(_In_ PVMM_PROCESS pProcess, _Inout_updates_(cpMEMsVirt) PPMEM_IO_SCATTER_HEADER ppMEMsVirt, _In_ DWORD cpMEMsVirt, _In_ QWORD flags);

/*
* Scatter read physical memory. Non contiguous 4096-byte pages.
* -- ppMEMsPhys
* -- cpMEMsPhys
* -- flags = flags as in VMM_FLAG_*, [VMM_FLAG_NOCACHE for supression of caching]
*/
VOID VmmReadScatterPhysical(_Inout_ PPMEM_IO_SCATTER_HEADER ppMEMsPhys, _In_ DWORD cpMEMsPhys, _In_ QWORD flags);

/*
* Translate a virtual address to a physical address by walking the page tables.
* The successfully translated Physical Address (PA) is returned in ppa.
* Upon fail the PTE will be returned in ppa (if possible) - which may be used
* to further lookup virtual memory in case of PageFile or Win10 MemCompression.
* -- paDTB
* -- fUserOnly
* -- va
* -- ppa
* -- return
*/
_Success_(return)
inline BOOL VmmVirt2PhysEx(_In_ QWORD paDTB, _In_ BOOL fUserOnly, _In_ QWORD va, _Out_ PQWORD ppa)
{
    *ppa = 0;
    if(ctxVmm->tpMemoryModel == VMM_MEMORYMODEL_NA) { return FALSE; }
    return ctxVmm->fnMemoryModel.pfnVirt2Phys(paDTB, fUserOnly, -1, va, ppa);
}

/*
* Translate a virtual address to a physical address by walking the page tables.
* The successfully translated Physical Address (PA) is returned in ppa.
* Upon fail the PTE will be returned in ppa (if possible) - which may be used
* to further lookup virtual memory in case of PageFile or Win10 MemCompression.
* -- pProcess
* -- va
* -- ppa
* -- return
*/
_Success_(return)
inline BOOL VmmVirt2Phys(_In_ PVMM_PROCESS pProcess, _In_ QWORD va, _Out_ PQWORD ppa)
{
    *ppa = 0;
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
* Prefetch a set of physical addresses contained in pTlbPrefetch into the TLB cache.
* NB! pTlbPrefetch must not be updated/altered during the function call.
* -- pTlbPrefetch = the page table addresses to prefetch (on entry) and empty set on exit.
*/
VOID VmmTlbPrefetch(_In_ POB_VSET pTlbPrefetch);

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
* Retrieve information of the physical2virtual address translation for the
* supplied process. This function may take time on larger address spaces -
* such as the kernel adderss space due to extensive page walking. If a new
* address is to be used please supply it in paTarget. If paTarget == 0 then
* a previously stored address will be used.
* It's not possible to use this function to retrieve multiple targeted
* addresses in parallell.
* -- CALLER DECREF: return
* -- pProcess
* -- paTarget = targeted physical address (or 0 if use previously saved).
* -- return
*/
PVMMOB_PHYS2VIRT_INFORMATION VmmPhys2VirtGetInformation(_In_ PVMM_PROCESS pProcess, _In_ QWORD paTarget);

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
inline BOOL VmmMemMapGetDisplay(_In_ PVMM_PROCESS pProcess, _In_ DWORD flags, _Out_ PVMMOB_DATA *ppObDisplay)
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
* Retrieve the next process given a process and a process table. This may be
* useful when iterating over a process list. NB! Listing of next item may fail
* prematurely if the previous process is terminated while having a reference
* to it.
* FUNCTION DECREF: pProcess
* CALLER DECREF: return
* -- pt
* -- pProcess = a process struct, or NULL if first.
*    NB! function DECREF's  pProcess and must not be used after call!
* -- flags = 0 (recommended) or VMM_FLAG_PROCESS_SHOW_TERMINATED (_only_ if default setting in ctxVmm->flags should be overridden)
* -- return = a process struct, or NULL if not found.
*/
PVMM_PROCESS VmmProcessGetNextEx(_In_opt_ PVMMOB_PROCESS_TABLE pt, _In_opt_ PVMM_PROCESS pProcess, _In_ QWORD flags);

/*
* Retrieve the next process given a process. This may be useful when iterating
* over a process list. NB! Listing of next item may fail prematurely if the
* previous process is terminated while having a reference to it.
* FUNCTION DECREF: pProcess
* CALLER DECREF: return
* -- pProcess = a process struct, or NULL if first.
*    NB! function DECREF's  pProcess and must not be used after call!
* -- flags = 0 (recommended) or VMM_FLAG_PROCESS_SHOW_TERMINATED (_only_ if default setting in ctxVmm->flags should be overridden)
* -- return = a process struct, or NULL if not found.
*/
inline PVMM_PROCESS VmmProcessGetNext(_In_opt_ PVMM_PROCESS pProcess, _In_ QWORD flags)
{
    return VmmProcessGetNextEx(NULL, pProcess, flags);
}

/*
* Create a new process object. New process object are created in a separate
* data structure and won't become visible to the "Process" functions until
* after the VmmProcessCreateFinish have been called.
* CALLER DECREF: return
* -- fTotalRefresh = create a completely new entry - i.e. do not copy any form
*                    of data from the old entry such as module and memory maps.
* -- dwPID
* -- dwPPID = parent PID (if any)
* -- dwState
* -- paDTB
* -- paDTB_UserOpt
* -- szName
* -- fUserOnly = user mode process (hide supervisor pages from view)
* -- pbEPROCESS
* -- cbEPROCESS
* -- return
*/
PVMM_PROCESS VmmProcessCreateEntry(_In_ BOOL fTotalRefresh, _In_ DWORD dwPID, _In_ DWORD dwPPID, _In_ DWORD dwState, _In_ QWORD paDTB, _In_ QWORD paDTB_UserOpt, _In_ CHAR szName[16], _In_ BOOL fUserOnly, _In_reads_opt_(cbEPROCESS) PBYTE pbEPROCESS, _In_ DWORD cbEPROCESS);

/*
* Query process for its creation time.
* -- pProcess
* -- return = time as FILETIME or 0 on error.
*/
inline QWORD VmmProcess_GetCreateTimeOpt(_In_opt_ PVMM_PROCESS pProcess)
{
    return (pProcess && ctxVmm->kernel.OffsetEPROCESS.opt.CreateTime) ? *(PQWORD)(pProcess->win.EPROCESS.pb + ctxVmm->kernel.OffsetEPROCESS.opt.CreateTime) : 0;
}

/*
* Query process for its exit time.
* -- pProcess
* -- return = time as FILETIME or 0 on error.
*/
inline QWORD VmmProcess_GetExitTimeOpt(_In_opt_ PVMM_PROCESS pProcess)
{
    return (pProcess && ctxVmm->kernel.OffsetEPROCESS.opt.ExitTime) ? *(PQWORD)(pProcess->win.EPROCESS.pb + ctxVmm->kernel.OffsetEPROCESS.opt.ExitTime) : 0;
}

/*
* Activate the pending, not yet active, processes added by VmmProcessCreateEntry.
* This will also clear any previous processes.
*/
VOID VmmProcessCreateFinish();

/*
* List the PIDs and put them into the supplied table.
* -- pPIDs = user allocated DWORD array to receive result, or NULL.
* -- pcPIDs = ptr to number of DWORDs in pPIDs on entry - number of PIDs in system on exit.
* -- flags = 0 (recommended) or VMM_FLAG_PROCESS_SHOW_TERMINATED (_only_ if default setting in ctxVmm->flags should be overridden)
*/
VOID VmmProcessListPIDs(_Out_writes_opt_(*pcPIDs) PDWORD pPIDs, _Inout_ PSIZE_T pcPIDs, _In_ QWORD flags);

/*
* Perform multi-threaded parallel processing of processes in the process table.
* This is useful when slow I/O should take place on multiple or all processes
* simultaneously.
* First an optional criteria callback function (pfnCriteria) is executed to
* check which of the processes that should be processed. The absence of the
* critera function means all processes - including terminated processes.
* The selected processes are forwarded to the callback function pfnAction in
* parallel on multiple threads.
* NB! Manipulation of ctx in pfnAction callback function must be thread-safe!
* NB! For fast actions VmmProcessGetNext in single-threaded mode is recommended
*     over the use of this function!
* -- ctx = optional context forwarded to callback functions pfnCriteria / pfnAction.
* -- dwThreadLoadFactor = number of processed queued on each thread, or 0 for auto-select.
* -- pfnCriteria = optional callback function selecting which processes to process.
* -- pfnAction = processing function to be called in multi-threaded context.
*/
VOID VmmProcessActionForeachParallel(
    _In_opt_ PVOID ctx,
    _In_opt_ DWORD dwThreadLoadFactor,
    _In_opt_ BOOL(*pfnCriteria)(_In_ PVMM_PROCESS pProcess, _In_opt_ PVOID ctx),
    _In_ VOID(*pfnAction)(_In_ PVMM_PROCESS pProcess, _In_opt_ PVOID ctx)
);

/*
* Commonly used criteria - only process active processes instead of all processes
* (which may include terminated processes as well).
* -- pProcess
* -- ctx
* -- return
*/
BOOL VmmProcessActionForeachParallel_CriteriaActiveOnly(_In_ PVMM_PROCESS pProcess, _In_opt_ PVOID ctx);

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
* Prefetch a set of addresses contained in pPrefetchPages into the cache. This
* is useful when reading data from somewhat known addresses over higher latency
* connections.
* NB! pPrefetchPages must not be updated/altered during the function call.
* -- pProcess
* -- pPrefetchPages
*/
VOID VmmCachePrefetchPages(_In_opt_ PVMM_PROCESS pProcess, _In_opt_ POB_VSET pPrefetchPages);

/*
* Prefetch a set of addresses. This is useful when reading data from somewhat
* known addresses over higher latency connections.
* -- pProcess
* -- cAddresses
* -- ... = varargs of total cAddresses of addresses of type QWORD.
*/
VOID VmmCachePrefetchPages2(_In_opt_ PVMM_PROCESS pProcess, _In_ DWORD cAddresses, ...);

/*
* Prefetch a set of addresses contained in pPrefetchPagesNonPageAligned into
* the cache by first converting them to page aligned pages. This is used when
* reading data from somewhat known addresses over higher latency connections.
* NB! pPrefetchPagesNonPageAligned must not be altered during the function call.
* -- pProcess
* -- pPrefetchPagesNonPageAligned
* -- cb
*/
VOID VmmCachePrefetchPages3(_In_opt_ PVMM_PROCESS pProcess, _In_opt_ POB_VSET pPrefetchPagesNonPageAligned, _In_ DWORD cb);

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
