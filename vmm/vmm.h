// vmm.h : definitions related to virtual memory management support.
//
// (c) Ulf Frisk, 2018-2021
// Author: Ulf Frisk, pcileech@frizk.net
//
#ifndef __VMM_H__
#define __VMM_H__
#include "oscompatibility.h"
#include "leechcore.h"
#include "ob/ob.h"

#ifndef STRINGIZE2
#define STRINGIZE2(s) #s
#define STRINGIZE(s) STRINGIZE2(s)
#endif /* STRINGIZE2 */



// ----------------------------------------------------------------------------
// VMM configuration constants and struct definitions below:
// ----------------------------------------------------------------------------

#define VMM_STATUS_SUCCESS                      STATUS_SUCCESS
#define VMM_STATUS_UNSUCCESSFUL                 STATUS_UNSUCCESSFUL
#define VMM_STATUS_END_OF_FILE                  STATUS_END_OF_FILE
#define VMM_STATUS_FILE_INVALID                 STATUS_FILE_INVALID
#define VMM_STATUS_FILE_SYSTEM_LIMITATION       STATUS_FILE_SYSTEM_LIMITATION

#define VMM_PROCESSTABLE_ENTRIES_MAX            0x4000
#define VMM_PROCESS_OS_ALLOC_PTR_MAX            0x4    // max number of operating system specific pointers that must be free'd
#define VMM_MEMMAP_ENTRIES_MAX                  0x4000

#define VMM_MEMMAP_PAGE_W                       0x0000000000000002
#define VMM_MEMMAP_PAGE_NS                      0x0000000000000004
#define VMM_MEMMAP_PAGE_NX                      0x8000000000000000
#define VMM_MEMMAP_PAGE_MASK                    0x8000000000000006

#define VMM_MEMMAP_FLAG_MODULES                 0x0001
#define VMM_MEMMAP_FLAG_SCAN_PE                 0x0002
#define VMM_MEMMAP_FLAG_ALL                     (VMM_MEMMAP_FLAG_MODULES | VMM_MEMMAP_FLAG_SCAN_PE)

#define VMM_CACHE_TABLESIZE                     0x4011  // (not even # to prevent clogging at specific table 'hash' buckets)
#define VMM_CACHE_TLB_ENTRIES                   0x4000  // -> 64MB of cached data
#define VMM_CACHE_PHYS_ENTRIES                  0x4000  // -> 64MB of cached data

#define VMM_WORK_THREADPOOL_NUM_THREADS         0x20

#define VMM_FLAG_NOCACHE                        0x00000001  // do not use the data cache (force reading from memory acquisition device).
#define VMM_FLAG_ZEROPAD_ON_FAIL                0x00000002  // zero pad failed physical memory reads and report success if read within range of physical memory.
#define VMM_FLAG_PROCESS_SHOW_TERMINATED        0x00000004  // show terminated processes in the process list (if they can be found).
#define VMM_FLAG_FORCECACHE_READ                0x00000008  // force use of cache - fail non-cached pages - only valid for reads, invalid with VMM_FLAG_NOCACHE/VMM_FLAG_ZEROPAD_ON_FAIL.
#define VMM_FLAG_NOPAGING                       0x00000010  // do not try to retrieve memory from paged out memory (even if possible).
#define VMM_FLAG_NOPAGING_IO                    0x00000020  // do not try to retrieve memory from paged out memory if read would incur additional I/O (even if possible).
#define VMM_FLAG_PROCESS_TOKEN                  0x00000040  // try initialize process token
#define VMM_FLAG_ALTADDR_VA_PTE                 0x00000080  // alternative address mode - MEM_IO_SCATTER_HEADER.qwA contains PTE instead of VA when calling VmmRead* functions.
#define VMM_FLAG_NOCACHEPUT                     0x00000100  // do not write back to the data cache upon successful read from memory acquisition device.
#define VMM_FLAG_CACHE_RECENT_ONLY              0x00000200  // only fetch from the most recent active cache region when reading.
#define VMM_FLAG_PAGING_LOOP_PROTECT_BITS       0x00ff0000  // placeholder bits for paging loop protect counter.
#define VMM_FLAG_NOVAD                          0x01000000  // do not try to retrieve memory from backing VAD even if otherwise possible.

#define VMM_POOLTAG(v, tag)                     (v == _byteswap_ulong(tag))
#define VMM_POOLTAG_SHORT(v, tag)               ((v & 0x00ffffff) == (_byteswap_ulong(tag) & 0x00ffffff))
#define VMM_POOLTAG_PREPENDED(pb, o, tag)       (VMM_POOLTAG(*(PDWORD)(pb + o - (ctxVmm->f32 ? 4 : 12)), tag))
#define VMM_PTR_OFFSET(f32, pb, o)              ((f32) ? *(PDWORD)((o) + (PBYTE)(pb)) : *(PQWORD)((o) + (PBYTE)(pb)))
#define VMM_PTR_OFFSET_DUAL(f32, pb, o32, o64)  ((f32) ? *(PDWORD)((o32) + (PBYTE)(pb)) : *(PQWORD)((o64) + (PBYTE)(pb)))
#define VMM_PTR_OFFSET_EX_FAST_REF(f32, pb, o)  ((f32) ? (~0x7 & *(PDWORD)((o) + (PBYTE)(pb))) : (~0xfULL & *(PQWORD)((o) + (PBYTE)(pb))))
#define VMM_PTR_EX_FAST_REF(f32, v)             (((f32) ? ~0x7 : ~0xfULL) & v)

#define VMM_KADDR32(va)                         (((va) & 0x80000000) == 0x80000000)
#define VMM_KADDR32_4(va)                       (((va) & 0x80000003) == 0x80000000)
#define VMM_KADDR32_8(va)                       (((va) & 0x80000007) == 0x80000000)
#define VMM_KADDR32_PAGE(va)                    (((va) & 0x80000fff) == 0x80000000)
#define VMM_UADDR32(va)                         ((va) && (((va) & 0x80000000) == 0))
#define VMM_UADDR32_4(va)                       ((va) && (((va) & 0x80000003) == 0))
#define VMM_UADDR32_8(va)                       ((va) && (((va) & 0x80000007) == 0))
#define VMM_UADDR32_PAGE(va)                    ((va) && (((va) & 0x80000fff) == 0))
#define VMM_KADDR64(va)                         (((va) & 0xffff800000000000) == 0xffff800000000000)
#define VMM_KADDR64_8(va)                       (((va) & 0xffff800000000007) == 0xffff800000000000)
#define VMM_KADDR64_16(va)                      (((va) & 0xffff80000000000f) == 0xffff800000000000)
#define VMM_KADDR64_PAGE(va)                    (((va) & 0xffff800000000fff) == 0xffff800000000000)
#define VMM_UADDR64(va)                         ((va) && (((va) & 0xffff800000000000) == 0))
#define VMM_UADDR64_8(va)                       ((va) && (((va) & 0xffff800000000007) == 0))
#define VMM_UADDR64_16(va)                      ((va) && (((va) & 0xffff80000000000f) == 0))
#define VMM_UADDR64_PAGE(va)                    ((va) && (((va) & 0xffff800000000fff) == 0))
#define VMM_KADDR(va)                           (ctxVmm->f32 ? VMM_KADDR32(va) : VMM_KADDR64(va))
#define VMM_KADDR_4_8(va)                       (ctxVmm->f32 ? VMM_KADDR32_4(va) : VMM_KADDR64_8(va))
#define VMM_KADDR_8_16(va)                      (ctxVmm->f32 ? VMM_KADDR32_8(va) : VMM_KADDR64_16(va))
#define VMM_KADDR_PAGE(va)                      (ctxVmm->f32 ? VMM_KADDR32_PAGE(va) : VMM_KADDR64_PAGE(va))
#define VMM_UADDR(va)                           (ctxVmm->f32 ? VMM_UADDR32(va) : VMM_UADDR64(va))
#define VMM_UADDR_4_8(va)                       (ctxVmm->f32 ? VMM_UADDR32_4(va) : VMM_UADDR64_8(va))
#define VMM_UADDR_8_16(va)                      (ctxVmm->f32 ? VMM_UADDR32_8(va) : VMM_UADDR64_16(va))
#define VMM_UADDR_PAGE(va)                      (ctxVmm->f32 ? VMM_UADDR32_PAGE(va) : VMM_UADDR64_PAGE(va))

#define VMM_PID_PROCESS_CLONE_WITH_KERNELMEMORY 0x80000000      // Combine with PID to create a shallowly cloned process with fUserOnly = FALSE

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

typedef enum tdVMM_PTE_TP {
    VMM_PTE_TP_NA = 0,
    VMM_PTE_TP_HARDWARE = 1,
    VMM_PTE_TP_TRANSITION = 2,
    VMM_PTE_TP_PROTOTYPE = 3,
    VMM_PTE_TP_DEMANDZERO = 4,
    VMM_PTE_TP_COMPRESSED = 5,
    VMM_PTE_TP_PAGEFILE = 6,
} VMM_PTE_TP, *PVMM_PTE_TP;

// OBJECT TYPE table exists on Win7+ It's initialized on first use and it will
// exist throughout the lifetime of vmm context. Call function:
// VmmWin_ObjectTypeGet() to retrieve the type for a specific object type.
// OBJECT TYPE description table is dependant on PDB symbol functionality.
typedef struct tdVMMWIN_OBJECT_TYPE {
    DWORD cb;       // optional type size
    DWORD cbu;
    DWORD iType;
    LPSTR usz;
    LPSTR szType;   // optional type name
} VMMWIN_OBJECT_TYPE, *PVMMWIN_OBJECT_TYPE;

typedef struct tdVMMWIN_OBJECT_TYPE_TABLE {
    BOOL fInitialized;
    BOOL fInitializedFailed;
    BYTE bObjectHeaderCookie;
    DWORD cbMultiText;
    LPSTR pbMultiText;
    DWORD c;
    VMMWIN_OBJECT_TYPE h[256];
    union {
        BYTE _tpAll[0];
        struct {
            BYTE tpAlpcPort;
            BYTE tpDevice;
            BYTE tpDirectory;
            BYTE tpDriver;
            BYTE tpEvent;
            BYTE tpFile;
            BYTE tpJob;
            BYTE tpKey;
            BYTE tpMutant;
            BYTE tpProcess;
            BYTE tpSection;
            BYTE tpSemaphore;
            BYTE tpSession;
            BYTE tpSymbolicLink;
            BYTE tpThread;
            BYTE tpTimer;
            BYTE tpToken;
            BYTE tpType;
        };
    };
} VMMWIN_OBJECT_TYPE_TABLE, *PVMMWIN_OBJECT_TYPE_TABLE;



// ----------------------------------------------------------------------------
// VMM MAP object/struct definitions below:
// ----------------------------------------------------------------------------

typedef struct tdVMM_MAP_PTEENTRY {
    QWORD vaBase;
    QWORD cPages;
    QWORD fPage;
    BOOL  fWoW64;
    DWORD cbuText;
    LPSTR uszText;
    DWORD _Reserved1;
    DWORD cSoftware;    // # software (non active) PTEs in region
} VMM_MAP_PTEENTRY, *PVMM_MAP_PTEENTRY;

typedef enum tdVMM_VADMAP_TP {
    VMM_VADMAP_TP_CORE      = 0,    // core vad map
    VMM_VADMAP_TP_PARTIAL   = 1,    // core + additional info, such as fImage
    VMM_VADMAP_TP_FULL      = 2,    // full vad map
} VMM_VADMAP_TP;

typedef struct tdVMM_MAP_VADENTRY {
    QWORD vaStart;
    QWORD vaEnd;
    QWORD vaVad;
    union {
        struct {
            // DWORD 0
            DWORD VadType           : 3;   // Pos 0
            DWORD Protection        : 5;   // Pos 3
            DWORD fImage            : 1;   // Pos 8
            DWORD fFile             : 1;   // Pos 9
            DWORD fPageFile         : 1;   // Pos 10
            DWORD fPrivateMemory    : 1;   // Pos 11
            DWORD fTeb              : 1;   // Pos 12
            DWORD fStack            : 1;   // Pos 13
            DWORD fSpare            : 10;  // Pos 14
            DWORD HeapNum           : 7;   // Pos 24
            DWORD fHeap             : 1;   // Pos 31
            // DWORD 1
            DWORD CommitCharge      : 31;   // Pos 0
            DWORD MemCommit         : 1;    // Pos 31
            // DWORD 2
            DWORD FileOffset        : 24;   // Pos 0
            DWORD Large             : 1;    // Pos 24
            DWORD TrimBehind        : 1;    // Pos 25
            DWORD Inherit           : 1;    // Pos 26
            DWORD CopyOnWrite       : 1;    // Pos 27
            DWORD NoValidationNeeded : 1;   // Pos 28
            DWORD _Spare2           : 3;    // Pos 29
        };
        DWORD flags[3];
    };
    DWORD cbPrototypePte;
    QWORD vaPrototypePte;
    QWORD vaSubsection;
    LPSTR uszText;                  // Optional UTF-8 string pointed into VMMOB_MAP_VAD.pbMultiText
    DWORD cbuText;                  // byte count of uszText including terminating null
    DWORD _Reserved1;
    QWORD vaFileObject;             // only valid if fFile/fImage _and_ after wszText is initialized
    DWORD cVadExPages;              // number of "valid" VadEx pages in this VAD; require fExtendedText
    DWORD cVadExPagesBase;          // number of "valid" VadEx pages in "previous" VADs
    QWORD _Reserved2;
} VMM_MAP_VADENTRY, *PVMM_MAP_VADENTRY;

typedef struct tdVMM_MAP_VADEXENTRY {
    VMM_PTE_TP tp;
    DWORD iPML;
    QWORD va;
    QWORD pa;
    QWORD pte;
    struct {
        DWORD _Reserved1;
        VMM_PTE_TP tp;
        QWORD pa;
        QWORD pte;
    } proto;
    PVMM_MAP_VADENTRY peVad;
} VMM_MAP_VADEXENTRY, *PVMM_MAP_VADEXENTRY;

typedef enum tdVMM_MODULE_TP {
    VMM_MODULE_TP_NORMAL = 0,
    VMM_MODULE_TP_DATA = 1,
    VMM_MODULE_TP_NOTLINKED = 2,
    VMM_MODULE_TP_INJECTED = 3,
} VMM_MODULE_TP;

typedef struct tdVMM_MAP_MODULEENTRY {
    QWORD vaBase;
    QWORD vaEntry;
    DWORD cbImageSize;
    BOOL  fWoW64;
    LPSTR uszText;                  // UTF-8 LPSTR to name pointed into VMMOB_MAP_MODULE.pbMultiText
    DWORD cbuText;                  // byte count including terminating null
    DWORD cbuFullName;              // byte count including terminating null
    LPSTR uszFullName;              // UTF-8 LPSTR path+name pointed into VMM_MAP_MODULE.pbMultiText
    VMM_MODULE_TP tp;
    DWORD cbFileSizeRaw;
    DWORD cSection;
    DWORD cEAT;
    DWORD cIAT;
    DWORD _Reserved2;
    QWORD _Reserved1;
    QWORD _Reserved3;
} VMM_MAP_MODULEENTRY, *PVMM_MAP_MODULEENTRY;

typedef struct tdVMM_MAP_UNLOADEDMODULEENTRY {
    QWORD vaBase;
    DWORD cbImageSize;
    BOOL  fWoW64;
    LPSTR uszText;                  // UTF-8 LPSTR name pointed into VMMOB_MAP_UNLOADEDMODULE.pbMultiText
    DWORD cbuText;                  // byte count (including null terminator) or uszText
    DWORD dwCheckSum;               // user-mode only
    DWORD dwTimeDateStamp;          // user-mode only
    DWORD _Reserved1;
    QWORD ftUnload;                 // kernel-mode only
} VMM_MAP_UNLOADEDMODULEENTRY, *PVMM_MAP_UNLOADEDMODULEENTRY;

typedef struct tdVMM_MAP_EATENTRY {
    QWORD vaFunction;
    DWORD dwOrdinal;
    DWORD oFunctionsArray;          // PIMAGE_EXPORT_DIRECTORY->AddressOfFunctions[oFunctionsArray]
    DWORD oNamesArray;              // PIMAGE_EXPORT_DIRECTORY->AddressOfNames[oNamesArray]
    DWORD cbuFunction;              // byte count of uszFunction (including terminating null)
    LPSTR uszFunction;              // UTF-8 string
} VMM_MAP_EATENTRY, *PVMM_MAP_EATENTRY;

typedef struct tdVMM_MAP_IATENTRY {
    QWORD vaFunction;
    LPSTR uszFunction;
    DWORD cbuFunction;
    DWORD cbuModule;
    LPSTR uszModule;
    struct {
        BOOL f32;
        WORD wHint;
        WORD _Reserved1;
        DWORD rvaFirstThunk;
        DWORD rvaOriginalFirstThunk;
        DWORD rvaNameModule;
        DWORD rvaNameFunction;
    } Thunk;
} VMM_MAP_IATENTRY, *PVMM_MAP_IATENTRY;

typedef struct tdVMM_MAP_HEAPENTRY {
    QWORD vaHeapSegment;
    union {
        struct {
            DWORD cPages;
            DWORD cPagesUnCommitted : 24;
            DWORD HeapId : 7;
            DWORD fPrimary : 1;
        };
        QWORD qwHeapData;
    };
} VMM_MAP_HEAPENTRY, *PVMM_MAP_HEAPENTRY;

typedef struct tdVMM_MAP_THREADENTRY {
    DWORD dwTID;
    DWORD dwPID;
    DWORD dwExitStatus;
    UCHAR bState;
    UCHAR bRunning;
    UCHAR bPriority;
    UCHAR bBasePriority;
    QWORD vaETHREAD;
    QWORD vaTeb;
    QWORD ftCreateTime;
    QWORD ftExitTime;
    QWORD vaStartAddress;
    QWORD vaStackBaseUser;          // value from _NT_TIB / _TEB
    QWORD vaStackLimitUser;         // value from _NT_TIB / _TEB
    QWORD vaStackBaseKernel;
    QWORD vaStackLimitKernel;
    QWORD vaTrapFrame;
    QWORD vaRIP;                    // RIP register (if user mode)
    QWORD vaRSP;                    // RSP register (if user mode)
    QWORD qwAffinity;
    DWORD dwUserTime;
    DWORD dwKernelTime;
    UCHAR bSuspendCount;
    UCHAR _FutureUse1[3];
    DWORD _FutureUse2[15];
} VMM_MAP_THREADENTRY, *PVMM_MAP_THREADENTRY;

typedef enum tdVMM_MAP_HANDLEENTRY_TP_INFOEX {
    HANDLEENTRY_TP_INFO_NONE = 0,
    HANDLEENTRY_TP_INFO_ERROR = 1,
    HANDLEENTRY_TP_INFO_PRE_1 = 2,
    HANDLEENTRY_TP_INFO_PRE_2 = 3,
    HANDLEENTRY_TP_INFO_FILE = 4,
} VMM_MAP_HANDLEENTRY_TP_INFOEX;

// VMM_MAP_HANDLEENTRY - MUST BE 96 BYTES IN SIZE DUE TO DEPENCENDY TO VMMDLL
typedef struct tdVMM_MAP_HANDLEENTRY {
    QWORD vaObject;
    DWORD dwHandle;
    DWORD dwGrantedAccess : 24;
    DWORD iType : 8;
    QWORD qwHandleCount;
    QWORD qwPointerCount;
    QWORD vaObjectCreateInfo;
    QWORD vaSecurityDescriptor;
    LPSTR uszText;                  // optional LPSTR pointed into VMMOB_MAP_HANDLE.pbMultiText
    DWORD cbuText;                  // byte count of uszText (including terminating null).
    DWORD dwPID;
    DWORD dwPoolTag;
    // diff between vmm/vmmdll below:
    VMM_MAP_HANDLEENTRY_TP_INFOEX tpInfoEx;
    union {
        struct {
            DWORD cb;
        } _InfoFile;
        struct {
            QWORD qw2;
            DWORD dw2;
            DWORD dw;
            QWORD qw;
        } _Reserved;
    };
} VMM_MAP_HANDLEENTRY, *PVMM_MAP_HANDLEENTRY;

typedef struct tdVMM_MAP_OBJECTENTRY {
    QWORD va;
    DWORD id;
    DWORD cChild;
    DWORD dwHash;
    PVMMWIN_OBJECT_TYPE pType;
    struct tdVMM_MAP_OBJECTENTRY *pParent;
    struct tdVMM_MAP_OBJECTENTRY *pChild;
    struct tdVMM_MAP_OBJECTENTRY *pNextByParent;
    DWORD cbuName;
    LPSTR uszName;
    // type dependent extra fields
    struct {
        LPSTR usz;
        QWORD ft;
    } ExtInfo;
    PVOID _Reserved;
} VMM_MAP_OBJECTENTRY, *PVMM_MAP_OBJECTENTRY;

typedef struct tdVMM_MAP_KDRIVERENTRY {
    QWORD va;
    DWORD dwHash;
    DWORD _Reserved;
    QWORD vaStart;
    QWORD cbDriverSize;
    QWORD vaDeviceObject;
    LPSTR uszName;
    LPSTR uszPath;
    LPSTR uszServiceKeyName;
    QWORD MajorFunction[28];
} VMM_MAP_KDRIVERENTRY, *PVMM_MAP_KDRIVERENTRY;

typedef struct tdVMM_MAP_NETENTRY {
    DWORD dwPID;
    DWORD dwState;
    WORD _FutureUse3[3];
    WORD AF;                        // address family (IPv4/IPv6)
    struct {
        BOOL fValid;
        WORD _Reserved;
        WORD port;
        BYTE pbAddr[16];            // ipv4 = 1st 4 bytes, ipv6 = all bytes
        LPSTR uszText;
    } Src;
    struct {
        BOOL fValid;
        WORD _Reserved;
        WORD port;
        BYTE pbAddr[16];            // ipv4 = 1st 4 bytes, ipv6 = all bytes
        LPSTR uszText;
    } Dst;
    QWORD vaObj;
    QWORD ftTime;
    DWORD dwPoolTag;
    DWORD cbuText;                  // byte count of uszText (including null terminator)
    LPSTR uszText;                  // UTF-8 LPSTR pointed into VMMOB_MAP_NET.pbMultiText
    QWORD _Reserved1;
    QWORD _Reserved2;
} VMM_MAP_NETENTRY, *PVMM_MAP_NETENTRY;

typedef struct tdVMM_MAP_PHYSMEMENTRY {
    QWORD pa;
    QWORD cb;
} VMM_MAP_PHYSMEMENTRY, *PVMM_MAP_PHYSMEMENTRY;

typedef struct tdVMM_MAP_USERENTRY {
    PSID pSID;
    DWORD cbSID;
    LPSTR szSID;
    DWORD dwHashSID;
    DWORD cbuText;                  // byte count of uszText including terminating null
    LPSTR uszText;                  // UTF-8 STR pointed into VMMOB_MAP_USER.pbMultiText
    QWORD vaRegHive;
} VMM_MAP_USERENTRY, *PVMM_MAP_USERENTRY;

typedef struct tdVMM_MAP_SERVICEENTRY {
    QWORD vaObj;
    DWORD dwOrdinal;
    DWORD dwStartType;
    SERVICE_STATUS ServiceStatus;
    LPSTR uszServiceName;
    LPSTR uszDisplayName;
    LPSTR uszPath;
    LPSTR uszUserTp;
    LPSTR uszUserAcct;
    LPSTR uszImagePath;
    DWORD dwPID;
    DWORD _FutureUse;
    QWORD _Reserved;
} VMM_MAP_SERVICEENTRY, *PVMM_MAP_SERVICEENTRY;

typedef enum tdVMM_EVIL_TP {            // EVIL types - sorted by "evilness"
    VMM_EVIL_TP_PE_NA           = 0,    // _NA
    VMM_EVIL_TP_PE_INJECTED     = 1,    // MODULE
    VMM_EVIL_TP_PROC_NOLINK     = 2,    // _NA
    VMM_EVIL_TP_PEB_MASQUERADE  = 3,    // _NA
    VMM_EVIL_TP_PEB_BAD_LDR     = 4,    // _NA
    VMM_EVIL_TP_PE_NOTLINKED    = 5,    // MODULE
    VMM_EVIL_TP_VAD_PATCHED_PE  = 6,    // VADEX
    VMM_EVIL_TP_VAD_PRIVATE_RWX = 7,    // VADEX
    VMM_EVIL_TP_VAD_NOIMAGE_RWX = 8,    // VADEX
    VMM_EVIL_TP_VAD_PRIVATE_RX  = 9,    // VADEX
    VMM_EVIL_TP_VAD_NOIMAGE_RX  = 10,   // VADEX
} VMM_EVIL_TP;

static LPCSTR VMM_EVIL_TP_STRING[] = {
    "UNKNOWN    ",
    "PE_INJECT  ",
    "PROC_NOLINK",
    "PEB_MASQ   ",
    "PEB_BAD_LDR",
    "PE_NOLINK  ",
    "PE_PATCHED ",
    "PRIVATE_RWX",
    "NOIMAGE_RWX",
    "PRIVATE_RX ",
    "NOIMAGE_RX "
};

typedef struct tdVMM_MAP_EVILENTRY {
    VMM_EVIL_TP tp;
    DWORD dwPID;
    DWORD fEvilAllSuppress;
    DWORD oVadEx;   // from VAD base
    QWORD vaVad;
    QWORD va;
    struct {
        QWORD pa;
        QWORD paProto;
        WORD wPatchOffset;
        WORD wPatchByteCount;
    } VAD_PATCHED_PE;
} VMM_MAP_EVILENTRY, *PVMM_MAP_EVILENTRY;

typedef struct tdVMMOB_MAP_PTE {
    OB ObHdr;
    PBYTE pbMultiText;              // NULL or multi-str pointed into by VMM_MAP_PTEENTRY.uszText
    DWORD cbMultiText;
    BOOL fTagScan;                  // map contains tags from modules and scan.
    DWORD cMap;                     // # map entries.
    VMM_MAP_PTEENTRY pMap[];        // map entries.
} VMMOB_MAP_PTE, *PVMMOB_MAP_PTE;

typedef struct tdVMMOB_MAP_VAD {
    OB ObHdr;
    BOOL fSpiderPrototypePte;
    VMM_VADMAP_TP tp;
    DWORD cPage;                    // # pages in vad map.
    PBYTE pbMultiText;              // UTF-8 multi-string pointed into by VMM_MAP_VADENTRY.wszText
    DWORD cbMultiText;
    DWORD cMap;                     // # map entries.
    VMM_MAP_VADENTRY pMap[];        // map entries.
} VMMOB_MAP_VAD, *PVMMOB_MAP_VAD;

typedef struct tdVMMOB_MAP_VADEX {
    OB ObHdr;
    PVMMOB_MAP_VAD pVadMap;
    DWORD cMap;                     // # map entries.
    VMM_MAP_VADEXENTRY pMap[];      // map entries.
} VMMOB_MAP_VADEX, *PVMMOB_MAP_VADEX;

typedef struct tdVMMOB_MAP_MODULE {
    OB ObHdr;
    PQWORD pHashTableLookup;
    PBYTE pbMultiText;             //  UTF-8 multi-string into by VMM_MAP_MODULEENTRY.usz*
    DWORD cbMultiText;
    DWORD cMap;                     // # map entries.
    VMM_MAP_MODULEENTRY pMap[];     // map entries.
} VMMOB_MAP_MODULE, *PVMMOB_MAP_MODULE;

typedef struct tdVMMOB_MAP_UNLOADEDMODULE {
    OB ObHdr;
    PBYTE pbMultiText;
    DWORD cbMultiText;
    DWORD cMap;
    VMM_MAP_UNLOADEDMODULEENTRY pMap[];
} VMMOB_MAP_UNLOADEDMODULE, *PVMMOB_MAP_UNLOADEDMODULE;

typedef struct tdVMMOB_MAP_EAT {
    OB ObHdr;
    PQWORD pHashTableLookup;
    QWORD vaModuleBase;
    QWORD vaAddressOfFunctions;
    QWORD vaAddressOfNames;
    DWORD cNumberOfFunctions;
    DWORD cNumberOfNames;
    DWORD dwOrdinalBase;
    DWORD cbMultiText;
    PBYTE pbMultiText;              // UTF-8 multi-string pointed into by VMM_MAP_IATENTRY.uszFunction
    DWORD _Reserved1;
    DWORD cMap;                     // # map entries.
    VMM_MAP_EATENTRY pMap[];        // map entries.
} VMMOB_MAP_EAT, *PVMMOB_MAP_EAT;

typedef struct tdVMMOB_MAP_IAT {
    OB ObHdr;
    QWORD vaModuleBase;
    PBYTE pbMultiText;              // UTF-8 multi-string pointed into by VMM_MAP_IATENTRY.usz*
    DWORD cbMultiText;
    DWORD cMap;                     // # map entries.
    VMM_MAP_IATENTRY pMap[];        // map entries.
} VMMOB_MAP_IAT, *PVMMOB_MAP_IAT;

typedef struct tdVMMOB_MAP_HEAP {
    OB ObHdr;
    DWORD cMap;                      // # map entries.
    VMM_MAP_HEAPENTRY pMap[];        // map entries.
} VMMOB_MAP_HEAP, *PVMMOB_MAP_HEAP;

typedef struct tdVMMOB_MAP_THREAD {
    OB ObHdr;
    DWORD cMap;                      // # map entries.
    VMM_MAP_THREADENTRY pMap[];      // map entries.
} VMMOB_MAP_THREAD, *PVMMOB_MAP_THREAD;

typedef struct tdVMMOB_MAP_HANDLE {
    OB ObHdr;
    PBYTE pbMultiText;              // UTF-8 multi-string.
    DWORD cbMultiText;
    BOOL fInfoExFile;
    DWORD cMap;                     // # map entries.
    VMM_MAP_HANDLEENTRY pMap[];     // map entries.
} VMMOB_MAP_HANDLE, *PVMMOB_MAP_HANDLE;

typedef struct tdVMMOB_MAP_OBJECT {
    OB ObHdr;
    DWORD cType[256];
    DWORD iTypeSortBase[256];
    PDWORD piTypeSort;              // ptr to array of per-type sorted indexes into pMap
    PBYTE pbMultiText;              // UTF-8 multi-string.
    DWORD cbMultiText;
    DWORD cMap;                     // # map entries.
    VMM_MAP_OBJECTENTRY pMap[];     // map entries.
} VMMOB_MAP_OBJECT, *PVMMOB_MAP_OBJECT;

typedef struct tdVMMOB_MAP_KDRIVER {
    OB ObHdr;
    PBYTE pbMultiText;              // UTF-8 multi-string pointed into by VMM_MAP_KDRIVERENTRY.usz*
    DWORD cbMultiText;
    DWORD cMap;                     // # map entries.
    VMM_MAP_KDRIVERENTRY pMap[];    // map entries.
} VMMOB_MAP_KDRIVER, *PVMMOB_MAP_KDRIVER;

typedef struct tdVMMOB_MAP_NET {
    OB ObHdr;
    PBYTE pbMultiText;              // UTF-8 multi-string pointed into by VMM_MAP_NETENTRY.uszText
    DWORD cbMultiText;
    DWORD cMap;                     // # map entries.
    VMM_MAP_NETENTRY pMap[];        // map entries.
} VMMOB_MAP_NET, *PVMMOB_MAP_NET;

typedef struct tdVMMOB_MAP_PHYSMEM {
    OB ObHdr;
    DWORD cMap;                     // # map entries.
    VMM_MAP_PHYSMEMENTRY pMap[];    // map entries.
} VMMOB_MAP_PHYSMEM, *PVMMOB_MAP_PHYSMEM;

typedef struct tdVMMOB_MAP_USER {
    OB ObHdr;
    PBYTE pbMultiText;              // multi-str pointed into by VMM_MAP_USERENTRY.uszText
    DWORD cbMultiText;
    DWORD cMap;                     // # map entries.
    VMM_MAP_USERENTRY pMap[];       // map entries.
} VMMOB_MAP_USER, *PVMMOB_MAP_USER;

typedef struct tdVMMOB_MAP_SERVICE {
    OB ObHdr;
    PBYTE pbMultiText;              // multi-str pointed into by VMM_MAP_SERVICEENTRY.usz*
    DWORD cbMultiText;
    DWORD cMap;                     // # map entries.
    VMM_MAP_SERVICEENTRY pMap[];    // map entries.
} VMMOB_MAP_SERVICE, *PVMMOB_MAP_SERVICE;

typedef struct tdVMMOB_MAP_EVIL {
    OB ObHdr;
    QWORD tcCreateTime;             // create timestamp [internally used only]
    DWORD cMap;                     // # map entries.
    VMM_MAP_EVILENTRY pMap[];       // map entries.
} VMMOB_MAP_EVIL, *PVMMOB_MAP_EVIL;



// ----------------------------------------------------------------------------
// VMM process object/struct related definitions below:
// ----------------------------------------------------------------------------

typedef struct tdVMMWIN_USER_PROCESS_PARAMETERS {
    BOOL fProcessed;
    DWORD cbuImagePathName;
    DWORD cbuCommandLine;
    LPSTR uszImagePathName;         // UTF8 version of wszImagePathName
    LPSTR uszCommandLine;           // UTF8 version of wszCommandLine
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
    POB_CONTAINER pObCMapVadPrefetch;
    POB_CONTAINER pObCLdrModulesPrefetch32;
    POB_CONTAINER pObCLdrModulesPrefetch64;
    POB_CONTAINER pObCLdrModulesInjected;
    POB_CONTAINER pObCMapThreadPrefetch;
    VMMWIN_USER_PROCESS_PARAMETERS UserProcessParams;
    // kernel path and long name (from EPROCESS.SeAuditProcessCreationInfo)
    WORD cuszNameLong;
    WORD cuszPathKernel;
    LPSTR uszNameLong;
    LPSTR uszPathKernel;
    // plugin functionality below:
    struct {
        QWORD vaVirt2Phys;
        QWORD paPhys2Virt;
    } Plugin;
} VMMOB_PROCESS_PERSISTENT, *PVMMOB_PROCESS_PERSISTENT;

typedef struct tdVMM_PROCESS {
    OB ObHdr;
    CRITICAL_SECTION LockUpdate;
    CRITICAL_SECTION LockPlugin;    // Lock used by internal plugins
    DWORD dwPID;
    DWORD dwPPID;
    DWORD dwState;                  // state of process, 0 = running
    QWORD paDTB;
    QWORD paDTB_UserOpt;
    CHAR szName[16];
    BOOL fUserOnly;
    BOOL fTlbSpiderDone;
    struct {
        // NB! Map objects are _NEVER_ to be accessed directly from the
        //     process object itself! They may be deallocated on the fly!
        //     Only use VmmMap_* functions to retrieve objects!
        PVMMOB_MAP_PTE pObPte;
        PVMMOB_MAP_VAD pObVad;
        PVMMOB_MAP_MODULE pObModule;
        PVMMOB_MAP_UNLOADEDMODULE pObUnloadedModule;
        PVMMOB_MAP_HEAP pObHeap;
        PVMMOB_MAP_THREAD pObThread;
        PVMMOB_MAP_HANDLE pObHandle;
        PVMMOB_MAP_EVIL pObEvil;
        // separate locks from main process lock to avoid deadlocks
        // but also for increased parallelization for slow tasks.
        CRITICAL_SECTION LockUpdateThreadExtendedInfo;
        CRITICAL_SECTION LockUpdateMapEvil;
    } Map;
    PVMMOB_PROCESS_PERSISTENT pObPersistent;     // Always exists
    struct {
        QWORD vaPEB;
        DWORD vaPEB32;      // WoW64 only
        BOOL fWow64;
        struct {
            QWORD va;
            BOOL fNoLink;
            DWORD cb;
            BYTE pb[0xa00];
        } EPROCESS;
        struct {
            BOOL fInitialized;
            BOOL fSID;
            DWORD dwHashSID;
            DWORD dwSessionId;
            QWORD va;
            QWORD qwLUID;
            LPSTR szSID;
            union {
                SID SID;
                BYTE pbSID[SECURITY_MAX_SID_SIZE];
            };
        } TOKEN;
    } win;
    struct {
        POB_CONTAINER pObCLdrModulesDisplayCache;
        POB_CONTAINER pObCPeDumpDirCache;
        POB_CONTAINER pObCPhys2Virt;
    } Plugin;
    struct tdVMM_PROCESS *pObProcessCloneParent;    // only set in cloned processes
} VMM_PROCESS, *PVMM_PROCESS;

#define PVMM_PROCESS_SYSTEM         ((PVMM_PROCESS)-4)      // SYSTEM PROCESS (PID 4) - ONLY VALID WITH VmmRead*/VmmWrite*/VmmCachePrefetch* functions!

typedef struct tdVMMOB_PROCESS_TABLE {
    OB ObHdr;
    SIZE_T c;                       // Total # of processes in table
    SIZE_T cActive;                 // # of active processes (state = 0) in table
    WORD _iFLink;
    WORD _iFLinkM[VMM_PROCESSTABLE_ENTRIES_MAX];
    PVMM_PROCESS _M[VMM_PROCESSTABLE_ENTRIES_MAX];
    POB_CONTAINER pObCNewPROC;      // contains VMM_PROCESS_TABLE
} VMMOB_PROCESS_TABLE, *PVMMOB_PROCESS_TABLE;

#define VMM_CACHE_REGIONS       3
#define VMM_CACHE_REGION_MEMS   0x5000
#define VMM_CACHE_BUCKETS       0x5000

#define VMM_CACHE_TAG_PHYS      'CaPh'
#define VMM_CACHE_TAG_PAGING    'CaPg'
#define VMM_CACHE_TAG_TLB       'CaTb'

typedef struct tdVMMOB_CACHE_MEM {
    OB Ob;
    // internal cache table values below:
    DWORD iR;
    DWORD iB;
    SLIST_ENTRY SListEmpty;
    SLIST_ENTRY SListInUse;
    SLIST_ENTRY SListTotal;
    struct tdVMMOB_CACHE_MEM *FLink;
    struct tdVMMOB_CACHE_MEM *BLink;
    // "user" modifiable values below:
    MEM_SCATTER h;
    union {
        BYTE pb[0x1000];
        DWORD pdw[0x400];
        QWORD pqw[0x200];
    };
} VMMOB_CACHE_MEM, *PVMMOB_CACHE_MEM, **PPVMMOB_CACHE_MEM;

typedef struct tdVMM_CACHE_REGION {
    SRWLOCK LockSRW;
    SLIST_HEADER ListHeadEmpty;
    SLIST_HEADER ListHeadInUse;
    SLIST_HEADER ListHeadTotal;
    PVMMOB_CACHE_MEM B[VMM_CACHE_BUCKETS];
} VMM_CACHE_REGION, *PVMM_CACHE_REGION;

typedef struct tdVMM_CACHE_TABLE {
    BOOL fActive;
    DWORD tag;
    DWORD iR;
    BOOL fAllActiveRegions;
    CRITICAL_SECTION Lock;
    VMM_CACHE_REGION R[VMM_CACHE_REGIONS];
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
    VOID(*pfnVirt2PhysVadEx)(_In_ QWORD paPT, _Inout_ PVMMOB_MAP_VADEX pVadEx, _In_ BYTE iPML, _Inout_ PDWORD piVadEx);
    VOID(*pfnVirt2PhysGetInformation)(_Inout_ PVMM_PROCESS pProcess, _Inout_ PVMM_VIRT2PHYS_INFORMATION pVirt2PhysInfo);
    VOID(*pfnPhys2VirtGetInformation)(_In_ PVMM_PROCESS pProcess, _Inout_ PVMMOB_PHYS2VIRT_INFORMATION pP2V);
    BOOL(*pfnPteMapInitialize)(_In_ PVMM_PROCESS pProcess);
    VOID(*pfnTlbSpider)(_In_ PVMM_PROCESS pProcess);
    BOOL(*pfnTlbPageTableVerify)(_Inout_ PBYTE pb, _In_ QWORD pa, _In_ BOOL fSelfRefReq);
    BOOL(*pfnPagedRead)(_In_ PVMM_PROCESS pProcess, _In_opt_ QWORD va, _In_ QWORD pte, _Out_writes_opt_(4096) PBYTE pbPage, _Out_ PQWORD ppa, _Inout_opt_ PVMM_PTE_TP ptp, _In_ QWORD flags);
} VMM_MEMORYMODEL_FUNCTIONS;

#define VMM_EPROCESS_DWORD(pProcess, offset)    (*(PDWORD)(pProcess->win.EPROCESS.pb + offset))
#define VMM_EPROCESS_QWORD(pProcess, offset)    (*(PQWORD)(pProcess->win.EPROCESS.pb + offset))
#define VMM_EPROCESS_PTR(pProcess, offset)      (ctxVmm->f32 ? VMM_EPROCESS_DWORD(pProcess, offset) : VMM_EPROCESS_QWORD(pProcess, offset))



// ----------------------------------------------------------------------------
// VMM general constants and struct definitions below: 
// ----------------------------------------------------------------------------

typedef struct tdVmmConfig {
    CHAR szMountPoint[1];
    QWORD paCR3;
    DWORD tpForensicMode;                 // command line forensic mode
    // flags below
    BOOL fVerboseDll;
    BOOL fVerbose;
    BOOL fVerboseExtra;
    BOOL fVerboseExtraTlp;
    BOOL fDisableBackgroundRefresh;
    BOOL fDisableSymbolServerOnStartup;
    BOOL fDisablePython;
    BOOL fWaitInitialize;
    BOOL fUserInteract;
    BOOL fFileInfoHeader;
    // strings below
    CHAR szPythonPath[MAX_PATH];
    CHAR szPageFile[10][MAX_PATH];
    CHAR szMemMap[MAX_PATH];
    CHAR szMemMapStr[2048];
} VMMCONFIG, *PVMMCONFIG;

typedef struct tdVMM_STATISTICS {
    QWORD cPhysCacheHit;
    QWORD cPhysReadSuccess;
    QWORD cPhysReadFail;
    QWORD cPhysWrite;
    QWORD cPhysRefreshCache;
    struct {
        QWORD cPrototype;
        QWORD cTransition;
        QWORD cDemandZero;
        QWORD cVAD;
        QWORD cPageFile;
        QWORD cCacheHit;
        QWORD cCompressed;
        QWORD cFailCacheHit;
        QWORD cFailVAD;
        QWORD cFailPageFile;
        QWORD cFailCompressed;
        QWORD cFail;
    } page;
    QWORD cPageRefreshCache;
    QWORD cTlbCacheHit;
    QWORD cTlbReadSuccess;
    QWORD cTlbReadFail;
    QWORD cTlbRefreshCache;
    QWORD cProcessRefreshPartial;
    QWORD cProcessRefreshFull;
} VMM_STATISTICS, *PVMM_STATISTICS;

typedef struct tdVMM_OFFSET_EPROCESS {
    BOOL fValid;
    BOOL f64VistaOr7;
    WORD cbMaxOffset;
    WORD State;
    WORD DTB;
    WORD DTB_User;
    WORD Name;
    WORD PID;
    WORD PPID;
    WORD FLink;
    WORD BLink;
    WORD PEB;
    WORD SeAuditProcessCreationInfo;
    WORD VadRoot;
    WORD ObjectTable;
    WORD Wow64Process;  // only valid for 64-bit windows
    struct {
        // values may not exist - indicated by zero offset
        WORD CreateTime;
        WORD ExitTime;
        WORD Token;
        WORD TOKEN_TokenId;
        WORD TOKEN_SessionId;
        WORD TOKEN_UserAndGroups;
        WORD KernelTime;
        WORD UserTime;
    } opt;
} VMM_OFFSET_EPROCESS, *PVMM_OFFSET_EPROCESS;

typedef struct tdVMM_OFFSET_ETHREAD {
    WORD oThreadListHeadKP;
    // _KTHREAD offsets
    WORD oStackBase;
    WORD oStackLimit;
    WORD oState;
    WORD oSuspendCount;
    WORD oRunningOpt;
    WORD oPriority;
    WORD oBasePriority;
    WORD oTeb;
    WORD oTrapFrame;
    WORD oKernelTime;
    WORD oUserTime;
    WORD oAffinity;
    WORD oProcessOpt;
    // _ETHREAD offsets
    WORD oCreateTime;
    WORD oExitTime;
    WORD oExitStatus;
    WORD oStartAddress;
    WORD oThreadListEntry;
    WORD oCid;
    WORD oMax;
    // other
    WORD oTebStackBase;
    WORD oTebStackLimit;
    WORD oTrapRip;
    WORD oTrapRsp;
} VMM_OFFSET_ETHREAD, *PVMM_OFFSET_ETHREAD;

typedef struct tdVMM_OFFSET_FILE {
    BOOL fValid;
    struct {
        WORD cb;
        WORD oDeviceObject;
        WORD oSectionObjectPointer;
        WORD oFileName;
        WORD oFileNameBuffer;
    } _FILE_OBJECT;
    struct {
        WORD cb;
        WORD oDataSectionObject;
        WORD oSharedCacheMap;
        WORD oImageSectionObject;
    } _SECTION_OBJECT_POINTERS;
    struct {
        WORD cb;
        WORD oBaseAddress;
        WORD oSharedCacheMap;
    } _VACB;
    struct {
        WORD cb;
        WORD oFileSize;
        WORD oSectionSize;
        WORD oValidDataLength;
        WORD oInitialVacbs;
        WORD oVacbs;
        WORD oFileObjectFastRef;
    } _SHARED_CACHE_MAP;
    struct {
        WORD cb;
        WORD oSegment;
        WORD oFilePointer;
    } _CONTROL_AREA;
    struct {
        WORD cb;
        WORD oControlArea;
        WORD oSizeOfSegment;
        WORD oPrototypePte;
    } _SEGMENT;
    struct {
        WORD cb;
        WORD oControlArea;
        WORD oSubsectionBase;
        WORD oNextSubsection;
        WORD oStartingSector;
        WORD oNumberOfFullSectors;
        WORD oPtesInSubsection;
    } _SUBSECTION;
} VMM_OFFSET_FILE, *PVMM_OFFSET_FILE;

typedef struct tdVMM_OFFSET {
    VMM_OFFSET_EPROCESS EPROCESS;
    VMM_OFFSET_ETHREAD ETHREAD;
    VMM_OFFSET_FILE FILE;
    struct { WORD cb; } _OBJECT_HEADER_CREATOR_INFO;
    struct { WORD cb; } _OBJECT_HEADER_NAME_INFO;
    struct { WORD cb; } _OBJECT_HEADER_HANDLE_INFO;
    struct { WORD cb; } _OBJECT_HEADER_QUOTA_INFO;
    struct { WORD cb; } _OBJECT_HEADER_PROCESS_INFO;
    struct { WORD cb; } _OBJECT_HEADER_AUDIT_INFO;
    struct { WORD cb; } _POOL_HEADER;
} VMM_OFFSET, *PVMM_OFFSET;

typedef struct tdVMMWINOBJ_CONTEXT          *PVMMWINOBJ_CONTEXT;
typedef struct tdVMMWIN_REGISTRY_CONTEXT    *PVMMWIN_REGISTRY_CONTEXT;

typedef struct tdVMMWIN_OPTIONAL_KERNEL_CONTEXT {
    BOOL fInitialized;
    DWORD cCPUs;
    QWORD vaPfnDatabase;
    QWORD vaPsLoadedModuleListExp;
    QWORD vaMmUnloadedDrivers;
    QWORD vaMmLastUnloadedDriver;
    QWORD vaIopInvalidDeviceRequest;
    struct {
        QWORD va;
        // encrypted kdbg info below (x64 win8+)
        QWORD vaKdpDataBlockEncoded;
        QWORD qwKiWaitAlways;
        QWORD qwKiWaitNever;
    } KDBG;
    QWORD ftBootTime;
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
    VMMFN_RtlDecompressBuffer *RtlDecompressBufferOpt;     // ntdll.dll!RtlDecompressBuffer
} VMM_DYNAMIC_LOAD_FUNCTIONS;

typedef struct tdVMM_CONTEXT {
    HMODULE hModuleVmmOpt;          // only on _WIN32 builds! :: do not call FreeLibrary on hModuleVmm
    CRITICAL_SECTION LockMaster;
    CRITICAL_SECTION LockPlugin;
    POB_CONTAINER pObCPROC;         // contains VMM_PROCESS_TABLE
    VMM_MEMORYMODEL_FUNCTIONS fnMemoryModel;
    VMM_MEMORYMODEL_TP tpMemoryModel;
    BOOL f32;
    BOOL fThreadMapEnabled;         // Thread Map subsystem is enabled / available
    VMM_SYSTEM_TP tpSystem;
    DWORD flags;                    // VMM_FLAG_*
    DWORD dwSystemUniqueId;
    CHAR szSystemUniqueTag[15];
    struct {
        BOOL fEnabled;
        DWORD cMs_TickPeriod;
        DWORD cTick_MEM;
        DWORD cTick_TLB;
        DWORD cTick_Fast;
        DWORD cTick_Medium;
        DWORD cTick_Slow;
    } ThreadProcCache;
    QWORD tcRefreshMEM;
    QWORD tcRefreshTLB;
    QWORD tcRefreshFast;
    QWORD tcRefreshMedium;
    QWORD tcRefreshSlow;
    VMM_STATISTICS stat;
    VMM_KERNELINFO kernel;
    VMM_OFFSET offset;
    POB pObVfsDumpContext;
    POB pObPfnContext;
    POB pObPdbContext;
    PVOID pMmContext;
    PVOID pNetContext;
    struct {
        BYTE cProgressPercent;
    } EvilContext;
    struct {
        DWORD vaNtdll32;
        QWORD vaNtdll64;
    } ContextUnloadedModule;
    PVMMWINOBJ_CONTEXT pObjects;
    PVMMWIN_REGISTRY_CONTEXT pRegistry;
    QWORD paPluginPhys2VirtRoot;
    VMM_DYNAMIC_LOAD_FUNCTIONS fn;
    struct {
        PVOID FLinkAll;
        PVOID FLinkNotify;
        PVOID FLinkForensic;
        PVOID Root;
        PVOID Proc;
        struct {
            DWORD cEvent;
            HANDLE hEvent[MAXIMUM_WAIT_OBJECTS];
        } fc;
    } PluginManager;
    CRITICAL_SECTION LockUpdateMap;     // lock for global maps - such as MapUser
    CRITICAL_SECTION LockUpdateModule;  // lock for internal modules
    struct {                            // lightweight SRW locks
        SRWLOCK WinObjDisplay;
    } LockSRW;
    POB_CONTAINER pObCMapPhysMem;
    POB_CONTAINER pObCMapEvil;
    POB_CONTAINER pObCMapUser;
    POB_CONTAINER pObCMapNet;
    POB_CONTAINER pObCMapObject;
    POB_CONTAINER pObCMapKDriver;
    POB_CONTAINER pObCMapService;
    POB_CONTAINER pObCInfoDB;
    POB_CONTAINER pObCCachePrefetchEPROCESS;
    POB_CONTAINER pObCCachePrefetchRegistry;
    POB_CACHEMAP pObCacheMapEAT;
    POB_CACHEMAP pObCacheMapIAT;
    POB_CACHEMAP pObCacheMapWinObjDisplay;
    // page caches
    struct {
        VMM_CACHE_TABLE PHYS;
        VMM_CACHE_TABLE TLB;
        VMM_CACHE_TABLE PAGING;
        POB_SET PAGING_FAILED;
        POB_MAP pmPrototypePte;     // map with mm_vad.c managed data
    } Cache;
    // worker threads
    struct {
        BOOL fEnabled;
        POB_SET psThreadAll;
        POB_SET psThreadAvail;
        POB_SET psUnit;
    } Work;
    WCHAR _EmptyWCHAR;
    VMMWIN_OBJECT_TYPE_TABLE ObjectTypeTable;
} VMM_CONTEXT, *PVMM_CONTEXT;

typedef struct tdVMM_MAIN_CONTEXT {
    VMMCONFIG cfg;
    HANDLE hLC;
    LC_CONFIG dev;
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

extern PVMM_CONTEXT ctxVmm;
extern PVMM_MAIN_CONTEXT ctxMain;

#define vmmprintf(format, ...)          { if(ctxMain->cfg.fVerboseDll)       { printf(format, ##__VA_ARGS__); } }
#define vmmprintfv(format, ...)         { if(ctxMain->cfg.fVerbose)          { printf(format, ##__VA_ARGS__); } }
#define vmmprintfvv(format, ...)        { if(ctxMain->cfg.fVerboseExtra)     { printf(format, ##__VA_ARGS__); } }
#define vmmprintfvvv(format, ...)       { if(ctxMain->cfg.fVerboseExtraTlp)  { printf(format, ##__VA_ARGS__); } }
#define vmmprintf_fn(format, ...)       vmmprintf("%s: "format, __func__, ##__VA_ARGS__);
#define vmmprintfv_fn(format, ...)      vmmprintfv("%s: "format, __func__, ##__VA_ARGS__);
#define vmmprintfvv_fn(format, ...)     vmmprintfvv("%s: "format, __func__, ##__VA_ARGS__);
#define vmmprintfvvv_fn(format, ...)    vmmprintfvvv("%s: "format, __func__, ##__VA_ARGS__);

#define vmmwprintf(format, ...)          { if(ctxMain->cfg.fVerboseDll)       { wprintf(format, ##__VA_ARGS__); } }
#define vmmwprintfv(format, ...)         { if(ctxMain->cfg.fVerbose)          { wprintf(format, ##__VA_ARGS__); } }
#define vmmwprintfvv(format, ...)        { if(ctxMain->cfg.fVerboseExtra)     { wprintf(format, ##__VA_ARGS__); } }
#define vmmwprintfvvv(format, ...)       { if(ctxMain->cfg.fVerboseExtraTlp)  { wprintf(format, ##__VA_ARGS__); } }
#define vmmwprintf_fn(format, ...)       vmmwprintf(L"%S: "format, __func__, ##__VA_ARGS__);
#define vmmwprintfv_fn(format, ...)      vmmwprintfv(L"%S: "format, __func__, ##__VA_ARGS__);
#define vmmwprintfvv_fn(format, ...)     vmmwprintfvv(L"%S: "format, __func__, ##__VA_ARGS__);
#define vmmwprintfvvv_fn(format, ...)    vmmwprintfvvv(L"%S: "format, __func__, ##__VA_ARGS__);

// ----------------------------------------------------------------------------
// INITIALIZE/CLOSE FUNCTIONALITY BELOW:
// ----------------------------------------------------------------------------

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



// ----------------------------------------------------------------------------
// CACHE AND TLB FUNCTIONALITY BELOW:
// ----------------------------------------------------------------------------

/*
* Retrieve an item from the cache.
* CALLER DECREF: return
* -- dwTblTag
* -- qwA
* -- return
*/
PVMMOB_CACHE_MEM VmmCacheGet(_In_ DWORD dwTblTag, _In_ QWORD qwA);

/*
* Retrieve a page table (0x1000 bytes) via the TLB cache.
* CALLER DECREF: return
* -- pa
* -- fCacheOnly = if set do not make a request to underlying device if not in cache.
* -- return
*/
PVMMOB_CACHE_MEM VmmTlbGetPageTable(_In_ QWORD pa, _In_ BOOL fCacheOnly);

/*
* Check if an address page exists in the indicated cache.
* -- dwTblTag
* -- qwA
* -- return
*/
BOOL VmmCacheExists(_In_ DWORD dwTblTag, _In_ QWORD qwA);

/*
* Check out an empty memory cache item from the cache. NB! once the item is
* filled (successfully or unsuccessfully) it must be returned to the cache with
* VmmCacheReserveReturn and must _NOT_ otherwise be DEFREF'ed.
* CALLER DECREF SPECIAL: return
* -- dwTblTag
* -- return
*/
PVMMOB_CACHE_MEM VmmCacheReserve(_In_ DWORD wTblTag);

/*
* Return an entry retrieved with VmmCacheReserve to the cache.
* NB! no other items may be returned with this function!
* FUNCTION DECREF SPECIAL: pOb
* -- pOb
*/
VOID VmmCacheReserveReturn(_In_opt_ PVMMOB_CACHE_MEM pOb);



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
* Identical functionality as provided by 'VmmRead' - but with flags parameter.
* Read a contigious arbitrary amount of memory, virtual or physical.
* Virtual memory is read if a process is specified in pProcess parameter.
* Physical memory is read if NULL is specified in pProcess parameter.
* -- pProcess
* -- qwA
* -- pb
* -- cb
* -- flags = flags as in VMM_FLAG_*
* -- return
*/
_Success_(return)
BOOL VmmRead2(_In_opt_ PVMM_PROCESS pProcess, _In_ QWORD qwA, _Out_writes_(cb) PBYTE pb, _In_ DWORD cb, _In_ QWORD flags);

/*
* Read memory and allocate the required buffer. Two additional null bytes are
* also allocated on the returned buffer in case WCHAR-string data is read.
* CALLER LocalFree: ppb
* -- pProcess
* -- qwA
* -- ppb = function allocated buffer - caller is responsible for LocalFree!
* -- cb
* -- flags = flags as in VMM_FLAG_*
* -- return =
*/
_Success_(return)
BOOL VmmReadAlloc(_In_opt_ PVMM_PROCESS pProcess, _In_ QWORD qwA, _Out_ PBYTE *ppb, _In_ DWORD cb, _In_ QWORD flags);

/*
* Read a Windows _UNICODE_STRING from into the function allocated buffer pwsz.
* The allocated buffer is guaranteed to be NULL-terminated.
* CALLER LocalFree: pwsz
* -- pProcess
* -- f32 = 32/64-bit _UNICODE_STRING.
* -- flags =  = flags as in VMM_FLAG_*
* -- vaUS
* -- cchMax = max number of chars, or 0 for unlimited.
* -- pwsz = function allocated buffer - caller is responsible for LocalFree!
* -- pcch = number of characters read (excluding null terminator)
* -- return
*/
_Success_(return)
BOOL VmmReadAllocUnicodeString(_In_ PVMM_PROCESS pProcess, _In_ BOOL f32, _In_ QWORD flags, _In_ QWORD vaUS, _In_ DWORD cchMax, _Out_opt_ LPWSTR *pwsz, _Out_opt_ PDWORD pcch);

/*
* Combines VmmRead2() and CharUtil_WtoU().
* CALLER LOCALFREE (if *pusz != pbBuffer): *pjsz
* -- pProcess
* -- qwA
* -- cb = max number of bytes to read.
* -- flagsRead
* -- pbBuffer = optional buffer to place the result in.
* -- cbBuffer
* -- pusz = if set to null: function calculate length only and return TRUE.
            result utf-8 string, either as (*pusz == pbBuffer) or LocalAlloc'ed
*           buffer that caller is responsible for free.
* -- pcbu = byte length (including terminating null) of utf-8 string.
* -- flags = CHARUTIL_FLAG_NONE, CHARUTIL_FLAG_ALLOC or CHARUTIL_FLAG_TRUNCATE
* -- return
*/
_Success_(return)
BOOL VmmReadWtoU(
    _In_opt_ PVMM_PROCESS pProcess,
    _In_ QWORD qwA,
    _In_ DWORD cb,
    _In_ QWORD flagsRead,
    _Maybenull_ _Writable_bytes_(cbBuffer) PBYTE pbBuffer,
    _In_ DWORD cbBuffer,
    _Out_opt_ LPSTR *pusz,
    _Out_opt_ PDWORD pcbu,
    _In_ DWORD flagsChar
);

/*
* Read a contigious arbitrary amount of memory, physical or virtual, and report
* the number of bytes read in pcbRead.
* Virtual memory is read if a process is specified in pProcess.
* Physical memory is read if NULL is specified in pProcess.
* -- pProcess = NULL=='physical memory read', PTR=='virtual memory read'
* -- qwA
* -- pb
* -- cb
* -- pcbReadOpt
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
BOOL VmmReadPage(_In_opt_ PVMM_PROCESS pProcess, _In_ QWORD qwA, _Out_writes_(4096) PBYTE pbPage);

/*
* Scatter read virtual memory. Non contiguous 4096-byte pages.
* -- pProcess
* -- ppMEMsVirt
* -- cpMEMsVirt
* -- flags = flags as in VMM_FLAG_*, [VMM_FLAG_NOCACHE for supression of data (not tlb) caching]
*/
VOID VmmReadScatterVirtual(_In_ PVMM_PROCESS pProcess, _Inout_updates_(cpMEMsVirt) PPMEM_SCATTER ppMEMsVirt, _In_ DWORD cpMEMsVirt, _In_ QWORD flags);

/*
* Scatter read physical memory. Non contiguous 4096-byte pages.
* -- ppMEMsPhys
* -- cpMEMsPhys
* -- flags = flags as in VMM_FLAG_*, [VMM_FLAG_NOCACHE for supression of caching]
*/
VOID VmmReadScatterPhysical(_Inout_ PPMEM_SCATTER ppMEMsPhys, _In_ DWORD cpMEMsPhys, _In_ QWORD flags);

/*
* Read a memory segment as a file. This function is mainly a helper function
* for various file system functionality.
* -- pProcess = NULL=='physical memory read', PTR=='virtual memory read'
* -- qwMemoryAddress
* -- cbMemorySize
* -- pb
* -- cb
* -- pcbRead
* -- cbOffset
* -- return = NTSTATUS value
*/
NTSTATUS VmmReadAsFile(_In_opt_ PVMM_PROCESS pProcess, _In_ QWORD qwMemoryAddress, _In_ QWORD cbMemorySize, _Out_writes_(cb) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset);

/*
* Write to a memory segment as a file. This function is mainly a helper
* function for virtual file system functionality.
* -- pProcess = NULL=='physical memory read', PTR=='virtual memory read'
* -- qwMemoryAddress
* -- cbMemorySize
* -- pb
* -- cb
* -- pcbWrite
* -- cbOffset
* -- return = NTSTATUS value
*/
NTSTATUS VmmWriteAsFile(_In_opt_ PVMM_PROCESS pProcess, _In_ QWORD qwMemoryAddress, _In_ QWORD cbMemorySize, _In_reads_(cb) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbWrite, _In_ QWORD cbOffset);

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
BOOL VmmVirt2PhysEx(_In_ QWORD paDTB, _In_ BOOL fUserOnly, _In_ QWORD va, _Out_ PQWORD ppa);

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
BOOL VmmVirt2Phys(_In_opt_ PVMM_PROCESS pProcess, _In_ QWORD va, _Out_ PQWORD ppa);

/*
* Spider the TLB (page table cache) to load all page table pages into the cache.
* This is done to speed up various subsequent virtual memory accesses.
* NB! pages may fall out of the cache if it's in heavy use or doe to timing.
* -- pProcess
*/
VOID VmmTlbSpider(_In_ PVMM_PROCESS pProcess);

/*
* Try verify that a supplied page table in pb is valid by analyzing it.
* -- pb = 0x1000 bytes containing the page table page.
* -- pa = physical address if the page table page.
* -- fSelfRefReq = is a self referential entry required to be in the map? (PML4 for Windows).
*/
BOOL VmmTlbPageTableVerify(_Inout_ PBYTE pb, _In_ QWORD pa, _In_ BOOL fSelfRefReq);

/*
* Prefetch a set of physical addresses contained in pTlbPrefetch into the TLB cache.
* NB! pTlbPrefetch must not be updated/altered during the function call.
* -- pTlbPrefetch = the page table addresses to prefetch (on entry) and empty set on exit.
*/
VOID VmmTlbPrefetch(_In_ POB_SET pTlbPrefetch);

/*
* Retrieve information of the virtual2physical address translation for the
* supplied process. The Virtual address must be supplied in pVirt2PhysInfo upon
* entry.
* -- pProcess
* -- pVirt2PhysInfo
*/
VOID VmmVirt2PhysGetInformation(_Inout_ PVMM_PROCESS pProcess, _Inout_ PVMM_VIRT2PHYS_INFORMATION pVirt2PhysInfo);

/*
* Retrieve information of the physical2virtual address translation for the
* supplied process. This function may take time on larger address spaces -
* such as the kernel adderss space due to extensive page walking. If a new
* address is to be used please supply it in paTarget. If paTarget == 0 then
* a previously stored address will be used.
* It's not possible to use this function to retrieve multiple targeted
* addresses in parallell.
* CALLER DECREF: return
* -- pProcess
* -- paTarget = targeted physical address (or 0 if use previously saved).
* -- return
*/
PVMMOB_PHYS2VIRT_INFORMATION VmmPhys2VirtGetInformation(_In_ PVMM_PROCESS pProcess, _In_ QWORD paTarget);



// ----------------------------------------------------------------------------
// VMM process related function definitions below:
// ----------------------------------------------------------------------------

/*
* Retrieve a process for a given PID and optional PVMMOB_PROCESS_TABLE.
* CALLER DECREF: return
* -- pt
* -- dwPID
* -- flags = 0 (recommended) or VMM_FLAG_PROCESS_TOKEN.
* -- return
*/
PVMM_PROCESS VmmProcessGetEx(_In_opt_ PVMMOB_PROCESS_TABLE pt, _In_ DWORD dwPID, _In_ QWORD flags);

/*
* Retrieve a process for a given PID.
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
* -- flags = 0 (recommended) or VMM_FLAG_PROCESS_[TOKEN|SHOW_TERMINATED].
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
* -- flags = 0 (recommended) or VMM_FLAG_PROCESS_[TOKEN|SHOW_TERMINATED]
* -- return = a process struct, or NULL if not found.
*/
PVMM_PROCESS VmmProcessGetNext(_In_opt_ PVMM_PROCESS pProcess, _In_ QWORD flags);

/*
* Clone an original process entry creating a shallow clone. The user of this
* shallow clone may use it to set the fUserOnly flag to FALSE on an otherwise
* user-mode process to be able to access the whole kernel space for a standard
* user-mode process.
* NB! USE WITH EXTREME CARE - MAY CRASH VMM IF USED MORE GENERALLY!
* CALLER DECREF: return
* -- pProcess
* -- return
*/
PVMM_PROCESS VmmProcessClone(_In_ PVMM_PROCESS pProcess);

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
QWORD VmmProcess_GetCreateTimeOpt(_In_opt_ PVMM_PROCESS pProcess);

/*
* Query process for its exit time.
* -- pProcess
* -- return = time as FILETIME or 0 on error.
*/
QWORD VmmProcess_GetExitTimeOpt(_In_opt_ PVMM_PROCESS pProcess);

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
* Schedule an asynchronous work item onto a worker thread.
* NB! longer running functions must monitor ctxVmm->Work.fEnabled and exit
*     immediately if required!
* -- pfn
* -- ctx = optional context to provide to the pfn function.
* -- hEventFinish = optional event with will be set upon work completion.
*/
VOID VmmWork(_In_ LPTHREAD_START_ROUTINE pfn, _In_opt_ PVOID ctx, _In_opt_ HANDLE hEventFinish);

/*
* Schedule up to 64 asynchronous work items onto worker threads.
* Function will wait for all work items to complete before returning.
* NB! longer running functions must monitor ctxVmm->Work.fEnabled and exit
*     immediately if required!
* -- ctx = optional context to provide to the pfn functions.
* -- cWork = number of work LPTHREAD_START_ROUTINE following in varargs.
* -- ... = vararg of cWork LPTHREAD_START_ROUTINE work items.
*/
VOID VmmWorkWaitMultiple(_In_opt_ PVOID ctx, _In_ DWORD cWork, ...);

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
* -- ctxAction = optional context forwarded to callback functions pfnCriteria / pfnAction.
* -- pfnCriteria = optional callback function selecting which processes to process.
* -- pfnAction = processing function to be called in multi-threaded context.
*/
VOID VmmProcessActionForeachParallel(
    _In_opt_ PVOID ctxAction,
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
BOOL VmmProcessActionForeachParallel_CriteriaActiveUserOnly(_In_ PVMM_PROCESS pProcess, _In_opt_ PVOID ctx);

/*
* Clear the oldest region of all InUse entries and make it the new active region.
* -- wTblTag
*/
VOID VmmCacheClearPartial(_In_ DWORD dwTblTag);

/*
* Clear the specified cache from all entries.
* -- dwTblTag
*/
VOID VmmCacheClear(_In_ DWORD dwTblTag);

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
* -- flags
*/
VOID VmmCachePrefetchPages(_In_opt_ PVMM_PROCESS pProcess, _In_opt_ POB_SET pPrefetchPages, _In_ QWORD flags);

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
* -- flags
*/
VOID VmmCachePrefetchPages3(_In_opt_ PVMM_PROCESS pProcess, _In_opt_ POB_SET pPrefetchPagesNonPageAligned, _In_ DWORD cb, _In_ QWORD flags);

/*
* Prefetch an array of optionally non-page aligned addresses. This is useful
* when reading data from somewhat known addresses over higher latency connections.
* -- pProcess
* -- cAddresses
* -- pqwAddresses = array of addresses to fetch
* -- cb
* -- flags
*/
VOID VmmCachePrefetchPages4(_In_opt_ PVMM_PROCESS pProcess, _In_ DWORD cAddresses, _In_ PQWORD pqwAddresses, _In_ DWORD cb, _In_ QWORD flags);

/*
* Prefetch memory of optionally non-page aligned addresses which are derived
* from pmPrefetchObjects by the pfnFilter filter function.
* -- pProcess
* -- pmPrefetch = map of objects.
* -- cb
* -- flags
* -- pfnFilter = filter as required by ObMap_FilterSet function.
* -- return = at least one object is found to be prefetched into cache.
*/
BOOL VmmCachePrefetchPages5(_In_opt_ PVMM_PROCESS pProcess, _In_opt_ POB_MAP pmPrefetchObjects, _In_ DWORD cb, _In_ QWORD flags, _In_ VOID(*pfnFilter)(_In_ QWORD k, _In_ PVOID v, _Inout_ POB_SET ps));

/*
* Initialize the memory model specified and discard any previous memory models
* that may be in action.
* -- tp
*/
VOID VmmInitializeMemoryModel(_In_ VMM_MEMORYMODEL_TP tp);



// ----------------------------------------------------------------------------
// MAP FUNCTIONALITY BELOW:
// ----------------------------------------------------------------------------

/*
* Retrieve the PTE hardware page table memory map.
* CALLER DECREF: ppObPteMap
* -- pProcess
* -- ppObPteMap
* -- fExtendedText
* -- return
*/
_Success_(return)
BOOL VmmMap_GetPte(_In_ PVMM_PROCESS pProcess, _Out_ PVMMOB_MAP_PTE *ppObPteMap, _In_ BOOL fExtendedText);

/*
* Retrieve the VAD memory map.
* CALLER DECREF: ppObVadMap
* -- pProcess
* -- ppObVadMap
* -- tpVmmVadMap = VMM_VADMAP_TP_*
* -- return
*/
_Success_(return)
BOOL VmmMap_GetVad(_In_ PVMM_PROCESS pProcess, _Out_ PVMMOB_MAP_VAD *ppObVadMap, _In_ VMM_VADMAP_TP tpVmmVadMap);

/*
* Retrieve a single PVMM_MAP_VADENTRY for a given VadMap and address inside it.
* -- pVadMap
* -- va
* -- return = PTR to VADENTRY or NULL on fail. Must not be used out of pVadMap scope.
*/
PVMM_MAP_VADENTRY VmmMap_GetVadEntry(_In_opt_ PVMMOB_MAP_VAD pVadMap, _In_ QWORD va);

/*
* Retrieve the VAD extended memory map by range specified by iPage and cPage.
* CALLER DECREF: ppObVadExMap
* -- pProcess
* -- ppObVadExMap
* -- tpVmmVadMap = VMM_VADMAP_TP_*
* -- iPage = index of range start in vad map.
* -- cPage = number of pages, starting at iPage.
* -- return
*/
_Success_(return)
BOOL VmmMap_GetVadEx(_In_ PVMM_PROCESS pProcess, _Out_ PVMMOB_MAP_VADEX *ppObVadExMap, _In_ VMM_VADMAP_TP tpVmmVadMap, _In_ DWORD iPage, _In_ DWORD cPage);

/*
* Retrieve the process module map.
* CALLER DECREF: ppObModuleMap
* -- pProcess
* -- ppObModuleMap
* -- return
*/
_Success_(return)
BOOL VmmMap_GetModule(_In_ PVMM_PROCESS pProcess, _Out_ PVMMOB_MAP_MODULE *ppObModuleMap);

/*
* Retrieve a single VMM_MAP_MODULEENTRY for a given ModuleMap and module name inside it.
* -- pModuleMap
* -- uszModuleName
* -- return = PTR to VMM_MAP_MODULEENTRY or NULL on fail. Must not be used out of pModuleMap scope.
*/
PVMM_MAP_MODULEENTRY VmmMap_GetModuleEntry(_In_ PVMMOB_MAP_MODULE pModuleMap, _In_ LPSTR uszModuleName);

/*
* Retrieve a single VMM_MAP_MODULEENTRY for a given process and module name.
* CALLER DECREF: ppObModuleMap
* -- pProcessOpt
* -- dwPidOpt
* -- uszModuleName
* -- ppObModuleMap
* -- pModuleEntry
* -- return
*/
_Success_(return)
BOOL VmmMap_GetModuleEntryEx(_In_opt_ PVMM_PROCESS pProcessOpt, _In_opt_ DWORD dwPidOpt, _In_ LPSTR uszModuleName, _Out_ PVMMOB_MAP_MODULE *ppObModuleMap, _Out_ PVMM_MAP_MODULEENTRY *pModuleEntry);

/*
* Retrieve the process unloaded module map.
* CALLER DECREF: ppObUnloadedModuleMap
* -- pProcess
* -- ppObUnloadedModuleMap
* -- return
*/
_Success_(return)
BOOL VmmMap_GetUnloadedModule(_In_ PVMM_PROCESS pProcess, _Out_ PVMMOB_MAP_UNLOADEDMODULE *ppObUnloadedModuleMap);

/*
* Retrieve the process module export address table (EAT) map.
* CALLER DECREF: ppObEatMap
* -- pProcess
* -- pModule
* -- ppObEatMap
* -- return
*/
_Success_(return)
BOOL VmmMap_GetEAT(_In_ PVMM_PROCESS pProcess, _In_ PVMM_MAP_MODULEENTRY pModuleEntry, _Out_ PVMMOB_MAP_EAT *ppObEatMap);

/*
* Retrieve the export entry index in pEatMap->pMap by function name.
* -- pEatMap
* -- uszFunctionName
* -- pdwEntryIndex = pointer to receive the pEatMap->pMap index.
* -- return
*/
_Success_(return)
BOOL VmmMap_GetEATEntryIndexU(_In_ PVMMOB_MAP_EAT pEatMap, _In_ LPSTR uszFunctionName, _Out_ PDWORD pdwEntryIndex);

/*
* Retrieve the process module import address table (IAT) map.
* CALLER DECREF: ppObIatMap
* -- pProcess
* -- pModule
* -- ppObIatMap
* -- return
*/
_Success_(return)
BOOL VmmMap_GetIAT(_In_ PVMM_PROCESS pProcess, _In_ PVMM_MAP_MODULEENTRY pModuleEntry, _Out_ PVMMOB_MAP_IAT *ppObIatMap);

/*
* Retrieve the heap map.
* CALLER DECREF: ppObHeapMap
* -- pProcess
* -- ppObHeapMap
* -- return
*/
_Success_(return)
BOOL VmmMap_GetHeap(_In_ PVMM_PROCESS pProcess, _Out_ PVMMOB_MAP_HEAP *ppObHeapMap);

/*
* Retrieve the thread map.
* CALLER DECREF: ppObThreadMap
* -- pProcess
* -- ppObThreadMap
* -- return
*/
_Success_(return)
BOOL VmmMap_GetThread(_In_ PVMM_PROCESS pProcess, _Out_ PVMMOB_MAP_THREAD *ppObThreadMap);

/*
* Retrieve a single PVMM_MAP_THREADENTRY for a given ThreadMap and ThreadID.
* -- pThreadMap
* -- dwTID
* -- return = PTR to VMM_MAP_THREADENTRY or NULL on fail. Must not be used out of pThreadMap scope.
*/
PVMM_MAP_THREADENTRY VmmMap_GetThreadEntry(_In_ PVMMOB_MAP_THREAD pThreadMap, _In_ DWORD dwTID);

/*
* Retrieve the HANDLE map
* CALLER DECREF: ppObHandleMap
* -- pProcess
* -- ppObHandleMap
* -- fExtendedText
* -- return
*/
_Success_(return)
BOOL VmmMap_GetHandle(_In_ PVMM_PROCESS pProcess, _Out_ PVMMOB_MAP_HANDLE *ppObHandleMap, _In_ BOOL fExtendedText);

/*
* Retrieve the EVIL map
* CALLER DECREF: ppObEvilMap
* -- pProcess = retrieve for specific process, or if NULL for all processes.
* -- ppObEvilMap
* -- return
*/
_Success_(return)
BOOL VmmMap_GetEvil(_In_opt_ PVMM_PROCESS pProcess, _Out_ PVMMOB_MAP_EVIL *ppObEvilMap);

/*
* Retrieve the OBJECT MANAGER map
* CALLER DECREF: ppObObjectMap
* -- ppObObjectMap
* -- return
*/
_Success_(return)
BOOL VmmMap_GetObject(_Out_ PVMMOB_MAP_OBJECT *ppObObjectMap);

/*
* Retrieve the KERNEL DRIVER map
* CALLER DECREF: ppObKDriverMap
* -- ppObKDriverMap
* -- return
*/
_Success_(return)
BOOL VmmMap_GetKDriver(_Out_ PVMMOB_MAP_KDRIVER *ppObKDriverMap);

/*
* Retrieve the NETWORK CONNECTION map
* CALLER DECREF: ppObNetMap
* -- ppObNetMap
* -- return
*/
_Success_(return)
BOOL VmmMap_GetNet(_Out_ PVMMOB_MAP_NET *ppObNetMap);

/*
* Retrieve the Physical Memory Map.
* CALLER DECREF: ppObPhysMem
* -- ppObPhysMem
* -- return
*/
_Success_(return)
BOOL VmmMap_GetPhysMem(_Out_ PVMMOB_MAP_PHYSMEM *ppObPhysMem);

/*
* Retrieve the USER map
* CALLER DECREF: ppObUserMap
* -- ppObUserMap
* -- return
*/
_Success_(return)
BOOL VmmMap_GetUser(_Out_ PVMMOB_MAP_USER *ppObUserMap);

/*
* Retrieve the SERVICES map
* CALLER DECREF: ppObServiceMap
* -- ppObServiceMap
* -- return
*/
_Success_(return)
BOOL VmmMap_GetService(_Out_ PVMMOB_MAP_SERVICE *ppObServiceMap);

#endif /* __VMM_H__ */
