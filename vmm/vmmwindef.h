// vmmwindef.h : windows-related defines not in the standard header files.
//
// Author: Ulf Frisk, pcileech@frizk.net
//
#ifndef __VMMWINDEF_H__
#define __VMMWINDEF_H__
#include "oscompatibility.h"

#define O32_FILE_OBJECT_DeviceObject                    0x004
#define O64_FILE_OBJECT_DeviceObject                    0x008
#define O32_FILE_OBJECT_SectionObjectPointer            0x014
#define O64_FILE_OBJECT_SectionObjectPointer            0x028
#define O32_FILE_OBJECT_PrivateCacheMap                 0x018
#define O64_FILE_OBJECT_PrivateCacheMap                 0x030
#define O32_FILE_OBJECT_FileName                        0x030
#define O64_FILE_OBJECT_FileName                        0x058

#define O32_SECTION_OBJECT_POINTERS_DataSectionObject   0x000
#define O64_SECTION_OBJECT_POINTERS_DataSectionObject   0x000
#define O32_SECTION_OBJECT_POINTERS_SharedCacheMap      0x004
#define O64_SECTION_OBJECT_POINTERS_SharedCacheMap      0x008
#define O32_SECTION_OBJECT_POINTERS_ImageSectionObject  0x008
#define O64_SECTION_OBJECT_POINTERS_ImageSectionObject  0x010

#define O32_SEGMENT_SizeOfSegment                       0x010
#define O64_SEGMENT_SizeOfSegment                       0x018

#define O_SHARED_CACHE_MAP_FileSize                     0x008
#define O_CONTROL_AREA_Segment                          0x000

typedef struct _UNICODE_STRING32 {
    USHORT Length;
    USHORT MaximumLength;
    DWORD  Buffer;
} UNICODE_STRING32, *PUNICODE_STRING32;

typedef struct _UNICODE_STRING64 {
    USHORT Length;
    USHORT MaximumLength;
    DWORD  _Filler;
    QWORD  Buffer;
} UNICODE_STRING64, *PUNICODE_STRING64;

typedef struct _OBJECT_HEADER32 {
    DWORD PointerCount;
    union {
        DWORD HandleCount;
        DWORD NextToFree;
    };
    DWORD Lock;
    BYTE TypeIndex;
    BYTE TraceFlags;
    BYTE InfoMask;
    BYTE Flags;
    union {
        DWORD ObjectCreateInfo;
        DWORD QuotaBlockCharged;
    };
    DWORD SecurityDescriptor;
} OBJECT_HEADER32, *POBJECT_HEADER32;

typedef struct _OBJECT_HEADER64 {
    QWORD PointerCount;
    union {
        QWORD HandleCount;
        QWORD NextToFree;
    };
    QWORD Lock;
    BYTE TypeIndex;
    BYTE TraceFlags;
    BYTE InfoMask;
    BYTE Flags;
    DWORD _Filler;
    union {
        QWORD ObjectCreateInfo;
        QWORD QuotaBlockCharged;
    };
    QWORD SecurityDescriptor;
} OBJECT_HEADER64, *POBJECT_HEADER64;

typedef struct _OBJECT_HEADER_NAME_INFO32 {
    DWORD Directory;
    UNICODE_STRING32 Name;
    DWORD ReferenceCount;
} OBJECT_HEADER_NAME_INFO32, *POBJECT_HEADER_NAME_INFO32;

typedef struct _OBJECT_HEADER_NAME_INFO64 {
    QWORD Directory;
    UNICODE_STRING64 Name;
    DWORD ReferenceCount;
} OBJECT_HEADER_NAME_INFO64, *POBJECT_HEADER_NAME_INFO64;

typedef struct _DRIVER_EXTENSION32 {
    DWORD DriverObject;
    DWORD AddDevice;
    DWORD Count;
    UNICODE_STRING32 ServiceKeyName;
} DRIVER_EXTENSION32, *PDRIVER_EXTENSION32;

typedef struct _DRIVER_EXTENSION64 {
    QWORD DriverObject;
    QWORD AddDevice;
    DWORD Count;
    DWORD _Pad1;
    UNICODE_STRING64 ServiceKeyName;
} DRIVER_EXTENSION64, *PDRIVER_EXTENSION64;

typedef struct _DRIVER_OBJECT32 {
    WORD  Type;
    WORD  Size;
    DWORD DeviceObject;
    DWORD Flags;
    DWORD DriverStart;
    DWORD DriverSize;
    DWORD DriverSection;
    DWORD DriverExtension;
    UNICODE_STRING32 DriverName;
    DWORD HardwareDatabase;
    DWORD FastIoDispatch;
    DWORD DriverInit;
    DWORD DriverStartIo;
    DWORD DriverUnload;
    DWORD MajorFunction[28];
} DRIVER_OBJECT32, *PDRIVER_OBJECT32;

typedef struct _DRIVER_OBJECT64 {
    WORD  Type;
    WORD  Size;
    DWORD _Pad1;
    QWORD DeviceObject;
    DWORD Flags;
    DWORD _Pad2;
    QWORD DriverStart;
    QWORD DriverSize;
    QWORD DriverSection;
    QWORD DriverExtension;
    UNICODE_STRING64 DriverName;
    QWORD HardwareDatabase;
    QWORD FastIoDispatch;
    QWORD DriverInit;
    QWORD DriverStartIo;
    QWORD DriverUnload;
    QWORD MajorFunction[28];
} DRIVER_OBJECT64, *PDRIVER_OBJECT64;

typedef struct _DEVICE_OBJECT32 {
    WORD  Type;
    WORD  Size;
    DWORD ReferenceCount;
    DWORD DriverObject;
    DWORD NextDevice;
    DWORD AttachedDevice;
    DWORD CurrentIrp;
    DWORD Timer;
    DWORD Flags;
    DWORD Characteristics;
    DWORD Vpb;
    DWORD DeviceExtension;
    DWORD DeviceType;
    CHAR  StackSize;
    BYTE  _Filler1[3];
    BYTE  _Opaque[0x84];
} DEVICE_OBJECT32, *PDEVICE_OBJECT32;

typedef struct _DEVICE_OBJECT64 {
    WORD  Type;
    WORD  Size;
    DWORD ReferenceCount;
    QWORD DriverObject;
    QWORD NextDevice;
    QWORD AttachedDevice;
    QWORD CurrentIrp;
    QWORD Timer;
    DWORD Flags;
    DWORD Characteristics;
    QWORD Vpb;
    QWORD DeviceExtension;
    DWORD DeviceType;
    CHAR  StackSize;
    BYTE  _Filler1[3];
    BYTE  _Opaque[0xf8];
} DEVICE_OBJECT64, *PDEVICE_OBJECT64;

typedef struct _VPB32 {
    SHORT Type;
    SHORT Size;
    USHORT Flags;
    USHORT VolumeLabelLength;
    DWORD DeviceObject;
    DWORD RealDevice;
    DWORD SerialNumer;
    DWORD ReferenceCount;
    WORD VolumeLabel[32];
} VPB32, *PVPB32;

typedef struct _VPB64 {
    SHORT Type;
    SHORT Size;
    USHORT Flags;
    USHORT VolumeLabelLength;
    QWORD DeviceObject;
    QWORD RealDevice;
    DWORD SerialNumer;
    DWORD ReferenceCount;
    WORD VolumeLabel[32];
} VPB64, *PVPB64;

typedef struct tdCPU_CONTEXT32_FLOATING_SAVE_AREA {
    DWORD ControlWord;          // +000
    DWORD StatusWord;           // +004
    DWORD TagWord;              // +008
    DWORD ErrorOffset;          // +00c
    DWORD ErrorSelector;        // +010
    DWORD DataOffset;           // +014
    DWORD DataSelector;         // +018
    UCHAR RegisterArea[80];     // +01c
    DWORD Spare0;               // +06c
} CPU_CONTEXT32_FLOATING_SAVE_AREA, *PCPU_CONTEXT32_FLOATING_SAVE_AREA;

typedef struct tdCPU_CONTEXT32 {
    DWORD ContextFlags;         // +000
    DWORD Dr0;                  // +004
    DWORD Dr1;                  // +008
    DWORD Dr2;                  // +00c
    DWORD Dr3;                  // +010
    DWORD Dr6;                  // +014
    DWORD Dr7;                  // +018
    CPU_CONTEXT32_FLOATING_SAVE_AREA _FLOATING_SAVE_AREA;  // +01c
    DWORD SegGs;                // +08c
    DWORD SegFs;                // +090
    DWORD SegEs;                // +094
    DWORD SegDs;                // +098
    DWORD Edi;                  // +09c
    DWORD Esi;                  // +0a0
    DWORD Ebx;                  // +0a4
    DWORD Edx;                  // +0a8
    DWORD Ecx;                  // +0ac
    DWORD Eax;                  // +0b0
    DWORD Ebp;                  // +0b4
    DWORD Eip;                  // +0b8
    DWORD SegCs;                // +0bc
    DWORD EFlags;               // +0c0
    DWORD Esp;                  // +0c4
    DWORD SegSs;                // +0c8
    UCHAR ExtendedRegisters[512];   // +0cc
} CPU_CONTEXT32, *PCPU_CONTEXT32;

typedef struct tdCPU_KTRAP_FRAME32 {
    DWORD DbgEbp;               // +000
    DWORD DbgEip;               // +004
    DWORD DbgArgMark;           // +008
    SHORT TempSegCs;            // +00c
    UCHAR Logging;              // +00e
    UCHAR FrameType;            // +00f
    DWORD TempEsp;              // +010
    DWORD Dr0;                  // +014
    DWORD Dr1;                  // +018
    DWORD Dr2;                  // +01c
    DWORD Dr3;                  // +020
    DWORD Dr6;                  // +024
    DWORD Dr7;                  // +028
    DWORD SegGs;                // +02c
    DWORD SegEs;                // +030
    DWORD SegDs;                // +034
    DWORD Edx;                  // +038
    DWORD Ecx;                  // +03c
    DWORD Eax;                  // +040
    UCHAR PreviousPreviousMode; // +044
    UCHAR EntropyQueueDpc;      // +045
    UCHAR NmiMsrIbrs;           // +046
    UCHAR PreviousIrql;         // +047
    DWORD MxCsr;                // +048
    DWORD ExceptionList;        // +04c
    DWORD SegFs;                // +050
    DWORD Edi;                  // +054
    DWORD Esi;                  // +058
    DWORD Ebx;                  // +05c
    DWORD Ebp;                  // +060
    DWORD ErrCode;              // +064
    DWORD Eip;                  // +068
    DWORD SegCs;                // +06c
    DWORD EFlags;               // +070
    DWORD HardwareEsp;          // +074
    DWORD HardwareSegSs;        // +078
    DWORD V86Es;                // +07c
    DWORD V86Ds;                // +080
    DWORD V86Fs;                // +084
    DWORD V86Gs;                // +088
} CPU_KTRAP_FRAME32, *PCPU_KTRAP_FRAME32;

typedef struct tdCPU_CONTEXT64_XSAVE_FORMAT {
    WORD    ControlWord;
    WORD    StatusWord;
    BYTE    TagWord;
    BYTE    Reserved1;
    WORD    ErrorOpcode;
    DWORD   ErrorOffset;
    WORD    ErrorSelector;
    WORD    Reserved2;
    DWORD   DataOffset;
    WORD    DataSelector;
    WORD    Reserved3;
    DWORD   MxCsr;
    DWORD   MxCsr_Mask;
    M128A   FloatRegisters[8];
    M128A   XmmRegisters[16];
    BYTE    Reserved4[96];
} CPU_CONTEXT64_XSAVE_FORMAT, *PCPU_CONTEXT64_XSAVE_FORMAT;

typedef struct tdCPU_CONTEXT64 {
    DWORD64 P1Home;
    DWORD64 P2Home;
    DWORD64 P3Home;
    DWORD64 P4Home;
    DWORD64 P5Home;
    DWORD64 P6Home;
    DWORD   ContextFlags;
    DWORD   MxCsr;
    WORD    SegCs;
    WORD    SegDs;
    WORD    SegEs;
    WORD    SegFs;
    WORD    SegGs;
    WORD    SegSs;
    DWORD   EFlags;
    DWORD64 Dr0;
    DWORD64 Dr1;
    DWORD64 Dr2;
    DWORD64 Dr3;
    DWORD64 Dr6;
    DWORD64 Dr7;
    DWORD64 Rax;
    DWORD64 Rcx;
    DWORD64 Rdx;
    DWORD64 Rbx;
    DWORD64 Rsp;
    DWORD64 Rbp;
    DWORD64 Rsi;
    DWORD64 Rdi;
    DWORD64 R8;
    DWORD64 R9;
    DWORD64 R10;
    DWORD64 R11;
    DWORD64 R12;
    DWORD64 R13;
    DWORD64 R14;
    DWORD64 R15;
    DWORD64 Rip;
    union {
        CPU_CONTEXT64_XSAVE_FORMAT FltSave;
        struct {
            M128A Header[2];
            M128A Legacy[8];
            M128A Xmm0;
            M128A Xmm1;
            M128A Xmm2;
            M128A Xmm3;
            M128A Xmm4;
            M128A Xmm5;
            M128A Xmm6;
            M128A Xmm7;
            M128A Xmm8;
            M128A Xmm9;
            M128A Xmm10;
            M128A Xmm11;
            M128A Xmm12;
            M128A Xmm13;
            M128A Xmm14;
            M128A Xmm15;
        };
    };
    M128A   VectorRegister[26];
    DWORD64 VectorControl;
    DWORD64 DebugControl;
    DWORD64 LastBranchToRip;
    DWORD64 LastBranchFromRip;
    DWORD64 LastExceptionToRip;
    DWORD64 LastExceptionFromRip;
} CPU_CONTEXT64, *PCPU_CONTEXT64;

typedef struct tdCPU_KTRAP_FRAME64 {
    DWORD64 P1Home;             // +000
    DWORD64 P2Home;             // +008
    DWORD64 P3Home;             // +010
    DWORD64 P4Home;             // +018
    DWORD64 P5;                 // +020
    UCHAR   PreviousMode;       // +028
    UCHAR   PreviousIrql;       // +029
    UCHAR   FaultIndicator;     // +02a
    UCHAR   ExceptionActive;    // +02b
    DWORD   MxCsr;              // +02c
    DWORD64 Rax;                // +030
    DWORD64 Rcx;                // +038
    DWORD64 Rdx;                // +040
    DWORD64 R8;                 // +048
    DWORD64 R9;                 // +050
    DWORD64 R10;                // +058
    DWORD64 R11;                // +060
    union {                     // +068
        DWORD64 GsBase;
        DWORD64 GsSwap;
    };
    M128A   Xmm0;               // +070
    M128A   Xmm1;               // +080
    M128A   Xmm2;               // +090
    M128A   Xmm3;               // +0a0
    M128A   Xmm4;               // +0b0
    M128A   Xmm5;               // +0c0
    union {                     // +0d0
        DWORD64 FaultAddress;
        DWORD64 ContextRecord;
    };
    DWORD64 Dr0;                // +0d8
    DWORD64 Dr1;                // +0e0
    DWORD64 Dr2;                // +0e8
    DWORD64 Dr3;                // +0f0
    DWORD64 Dr6;                // +0f8
    DWORD64 Dr7;                // +100
    DWORD64 DebugControl;       // +108
    DWORD64 LastBranchToRip;    // +110
    DWORD64 LastBranchFromRip;  // +118
    DWORD64 LastExceptionToRip; // +120
    DWORD64 LastExceptionFromRip; // +128
    WORD    SegDs;              // +130
    WORD    SegEs;              // +132
    WORD    SegFs;              // +134
    WORD    SegGs;              // +136
    DWORD64 TrapFrame;          // +138
    DWORD64 Rbx;                // +140
    DWORD64 Rdi;                // +148
    DWORD64 Rsi;                // +150
    DWORD64 Rbp;                // +158
    union {                     // +160
        DWORD64 ErrorCode;
        DWORD64 ExceptionFrame;
        DWORD64 TimeStampKlog;
    };
    DWORD64 Rip;                // +168
    WORD    SegCs;              // +170
    UCHAR   Fill0;              // +172
    UCHAR   Logging;            // +173
    WORD    Fill1;              // +174
    DWORD   EFlags;             // +178
    DWORD   Fill2;              // +17c
    DWORD64 Rsp;                // +180
    WORD    SegSs;              // +188
    WORD    Fill3;              // +18a
    DWORD   Fill4;              // +18c
} CPU_KTRAP_FRAME64, *PCPU_KTRAP_FRAME64;

#define RTL_UNLOAD_EVENT_TRACE_NUMBER 64

typedef struct _RTL_UNLOAD_EVENT_TRACE32 {
    DWORD BaseAddress;
    DWORD SizeOfImage;
    DWORD Sequence;
    DWORD TimeDateStamp;
    DWORD CheckSum;
    WCHAR ImageName[32];
} RTL_UNLOAD_EVENT_TRACE32, *PRTL_UNLOAD_EVENT_TRACE32;

typedef struct _RTL_UNLOAD_EVENT_TRACE64 {
    QWORD BaseAddress;
    QWORD SizeOfImage;
    DWORD Sequence;
    DWORD TimeDateStamp;
    DWORD CheckSum;
    WCHAR ImageName[32];
} RTL_UNLOAD_EVENT_TRACE64, *PRTL_UNLOAD_EVENT_TRACE64;

#define MM_UNLOADED_DRIVER_MAX      50

typedef struct tdMM_UNLOADED_DRIVER32
{
    UNICODE_STRING32    Name;
    DWORD               ModuleStart;
    DWORD               ModuleEnd;
    QWORD               UnloadTime;
} MM_UNLOADED_DRIVER32, *PMM_UNLOADED_DRIVER32;

typedef struct tdMM_UNLOADED_DRIVER64
{
    UNICODE_STRING64    Name;
    QWORD               ModuleStart;
    QWORD               ModuleEnd;
    QWORD               UnloadTime;
} MM_UNLOADED_DRIVER64, *PMM_UNLOADED_DRIVER64;

typedef union tdSEP_TOKEN_PRIVILEGES_TYPE {
    QWORD qwValue;
    struct {
        QWORD fNA1 : 1;
        QWORD fNA2 : 1;
        QWORD fSeCreateTokenPrivilege : 1;
        QWORD fSeAssignPrimaryTokenPrivilege : 1;
        QWORD fSeLockMemoryPrivilege : 1;
        QWORD fSeIncreafSeQuotaPrivilege : 1;
        QWORD fSeMachineAccountPrivilege : 1;
        QWORD fSeTcbPrivilege : 1;
        QWORD fSefSecurityPrivilege : 1;
        QWORD fSeTakeOwnershipPrivilege : 1;
        QWORD fSeLoadDriverPrivilege : 1;
        QWORD fSeSystemProfilePrivilege : 1;
        QWORD fSeSystemtimePrivilege : 1;
        QWORD fSeProfileSingleProcessPrivilege : 1;
        QWORD fSeIncreafSeBafSePriorityPrivilege : 1;
        QWORD fSeCreatePagefilePrivilege : 1;
        QWORD fSeCreatePermanentPrivilege : 1;
        QWORD fSeBackupPrivilege : 1;
        QWORD fSeRestorePrivilege : 1;
        QWORD fSeShutdownPrivilege : 1;
        QWORD fSeDebugPrivilege : 1;
        QWORD fSeAuditPrivilege : 1;
        QWORD fSeSystemEnvironmentPrivilege : 1;
        QWORD fSeChangeNotifyPrivilege : 1;
        QWORD fSeRemoteShutdownPrivilege : 1;
        QWORD fSeUndockPrivilege : 1;
        QWORD fSeSyncAgentPrivilege : 1;
        QWORD fSeEnableDelegationPrivilege : 1;
        QWORD fSeManageVolumePrivilege : 1;
        QWORD fSeImpersonatePrivilege : 1;
        QWORD fSeCreateGlobalPrivilege : 1;
        QWORD fSeTrustedCredManAccessPrivilege : 1;
        QWORD fSeRelabelPrivilege : 1;
        QWORD fSeIncreafSeWorkingfSetPrivilege : 1;
        QWORD fSeTimeZonePrivilege : 1;
        QWORD fSeCreateSymbolicLinkPrivilege : 1;
        QWORD fSeDelegatefSessionUfSerImpersonatePrivilege : 1;
    };
} SEP_TOKEN_PRIVILEGES_TYPE;

static LPCSTR SEP_TOKEN_PRIVILEGES_TYPE_STR[] = {
    "",
    "",
    "SeCreateTokenPrivilege",                       // SE_CREATE_TOKEN_NAME
    "SeAssignPrimaryTokenPrivilege",                // SE_ASSIGNPRIMARYTOKEN_NAME
    "SeLockMemoryPrivilege",                        // SE_LOCK_MEMORY_NAME
    "SeIncreaseQuotaPrivilege",                     // SE_INCREASE_QUOTA_NAME
    "SeMachineAccountPrivilege",                    // SE_MACHINE_ACCOUNT_NAME
    "SeTcbPrivilege",                               // SE_TCB_NAME
    "SeSecurityPrivilege",                          // SE_SECURITY_NAME
    "SeTakeOwnershipPrivilege",                     // SE_TAKE_OWNERSHIP_NAME
    "SeLoadDriverPrivilege",                        // SE_LOAD_DRIVER_NAME
    "SeSystemProfilePrivilege",                     // SE_SYSTEM_PROFILE_NAME
    "SeSystemtimePrivilege",                        // SE_SYSTEMTIME_NAME
    "SeProfileSingleProcessPrivilege",              // SE_PROF_SINGLE_PROCESS_NAME
    "SeIncreaseBasePriorityPrivilege",              // SE_INC_BASE_PRIORITY_NAME
    "SeCreatePagefilePrivilege",                    // SE_CREATE_PAGEFILE_NAME
    "SeCreatePermanentPrivilege",                   // SE_CREATE_PERMANENT_NAME
    "SeBackupPrivilege",                            // SE_BACKUP_NAME
    "SeRestorePrivilege",                           // SE_RESTORE_NAME
    "SeShutdownPrivilege",                          // SE_SHUTDOWN_NAME
    "SeDebugPrivilege",                             // SE_DEBUG_NAME
    "SeAuditPrivilege",                             // SE_AUDIT_NAME
    "SeSystemEnvironmentPrivilege",                 // SE_SYSTEM_ENVIRONMENT_NAME
    "SeChangeNotifyPrivilege",                      // SE_CHANGE_NOTIFY_NAME
    "SeRemoteShutdownPrivilege",                    // SE_REMOTE_SHUTDOWN_NAME
    "SeUndockPrivilege",                            // SE_UNDOCK_NAME
    "SeSyncAgentPrivilege",                         // SE_SYNC_AGENT_NAME
    "SeEnableDelegationPrivilege",                  // SE_ENABLE_DELEGATION_NAME
    "SeManageVolumePrivilege",                      // SE_MANAGE_VOLUME_NAME
    "SeImpersonatePrivilege",                       // SE_IMPERSONATE_NAME
    "SeCreateGlobalPrivilege",                      // SE_CREATE_GLOBAL_NAME
    "SeTrustedCredManAccessPrivilege",              // SE_TRUSTED_CREDMAN_ACCESS_NAME
    "SeRelabelPrivilege",                           // SE_RELABEL_NAME
    "SeIncreaseWorkingSetPrivilege",                // SE_INC_WORKING_SET_NAME
    "SeTimeZonePrivilege",                          // SE_TIME_ZONE_NAME
    "SeCreateSymbolicLinkPrivilege",                // SE_CREATE_SYMBOLIC_LINK_NAME
    "SeDelegateSessionUserImpersonatePrivilege"     // SE_DELEGATE_SESSION_USER_IMPERSONATE_NAME
};

typedef struct tdSEP_TOKEN_PRIVILEGES {
    SEP_TOKEN_PRIVILEGES_TYPE Present;
    SEP_TOKEN_PRIVILEGES_TYPE Enabled;
    SEP_TOKEN_PRIVILEGES_TYPE EnabledByDefault;
} SEP_TOKEN_PRIVILEGES, *PSEP_TOKEN_PRIVILEGES;

#define _PHYSICAL_MEMORY_MAX_RUNS   0x20

typedef struct {
    DWORD BasePage;
    DWORD PageCount;
} _PHYSICAL_MEMORY_RUN32;

typedef struct {
    DWORD NumberOfRuns;
    DWORD NumberOfPages;
    _PHYSICAL_MEMORY_RUN32 Run[_PHYSICAL_MEMORY_MAX_RUNS];
} _PHYSICAL_MEMORY_DESCRIPTOR32, *_PPHYSICAL_MEMORY_DESCRIPTOR32;

typedef struct {
    QWORD BasePage;
    QWORD PageCount;
} _PHYSICAL_MEMORY_RUN64;

typedef struct {
    DWORD NumberOfRuns;
    DWORD Reserved1;
    DWORD NumberOfPages;
    DWORD Reserved2;
    _PHYSICAL_MEMORY_RUN64 Run[_PHYSICAL_MEMORY_MAX_RUNS];
} _PHYSICAL_MEMORY_DESCRIPTOR64, *_PPHYSICAL_MEMORY_DESCRIPTOR64;

typedef struct {
    DWORD PreviousSize : 9;
    DWORD PoolIndex    : 7;
    DWORD BlockSize    : 9;
    DWORD PoolType     : 7;
    DWORD PoolTag;
} _POOL_HEADER32, *_PPOOL_HEADER32;

typedef struct {
    DWORD PreviousSize : 8;
    DWORD PoolIndex : 8;
    DWORD BlockSize : 8;
    DWORD PoolType : 8;
    DWORD PoolTag;
    QWORD ProcessBilled;
} _POOL_HEADER64, *_PPOOL_HEADER64;

static LPCSTR _KTHREAD_STATE_STR[] = {
    "Init",
    "Ready",
    "Running",
    "Standby",
    "Term",
    "Waiting",
    "Transit",
    "DeffRdy",
    "GateWt"
};

static LPCSTR _KWAIT_REASON_STR[] = {
   "Executive",
   "FreePage",
   "PageIn",
   "PoolAllocation",
   "DelayExecution",
   "Suspended",
   "UserRequest",
   "WrExecutive",
   "WrFreePage",
   "WrPageIn",
   "WrPoolAllocation",
   "WrDelayExecution",
   "WrSuspended",
   "WrUserRequest",
   "WrSpare0",
   "WrQueue",
   "WrLpcReceive",
   "WrLpcReply",
   "WrVirtualMemory",
   "WrPageOut",
   "WrRendezvous",
   "WrKeyedEvent",
   "WrTerminated",
   "WrProcessInSwap",
   "WrCpuRateControl",
   "WrCalloutStack",
   "WrKernel",
   "WrResource",
   "WrPushLock",
   "WrMutex",
   "WrQuantumEnd",
   "WrDispatchInt",
   "WrPreempted",
   "WrYieldExecution",
   "WrFastMutex",
   "WrGuardedMutex",
   "WrRundown",
   "WrAlertByThreadId",
   "WrDeferredPreempt",
   "WrPhysicalFault"
};

// more extensive definition of the Windows LDR_DATA_TABLE_ENTRY struct.
typedef struct _LDR_MODULE64 {
    LIST_ENTRY64        InLoadOrderModuleList;
    LIST_ENTRY64        InMemoryOrderModuleList;
    LIST_ENTRY64        InInitializationOrderModuleList;
    QWORD               BaseAddress;
    QWORD               EntryPoint;
    ULONG               SizeOfImage;
    ULONG               _Filler1;
    UNICODE_STRING64    FullDllName;
    UNICODE_STRING64    BaseDllName;
    ULONG               Flags;
    SHORT               LoadCount;
    SHORT               TlsIndex;
    LIST_ENTRY64        HashTableEntry;
    ULONG               TimeDateStamp;
    ULONG               _Filler2;
} LDR_MODULE64, *PLDR_MODULE64;

typedef struct _LDR_MODULE32 {
    LIST_ENTRY32        InLoadOrderModuleList;
    LIST_ENTRY32        InMemoryOrderModuleList;
    LIST_ENTRY32        InInitializationOrderModuleList;
    DWORD               BaseAddress;
    DWORD               EntryPoint;
    ULONG               SizeOfImage;
    UNICODE_STRING32    FullDllName;
    UNICODE_STRING32    BaseDllName;
    ULONG               Flags;
    SHORT               LoadCount;
    SHORT               TlsIndex;
    LIST_ENTRY32        HashTableEntry;
    ULONG               TimeDateStamp;
} LDR_MODULE32, *PLDR_MODULE32;

typedef struct _PEB_LDR_DATA32 {
    BYTE Reserved1[8];
    DWORD Reserved2;
    LIST_ENTRY32 InLoadOrderModuleList;
    LIST_ENTRY32 InMemoryOrderModuleList;
    LIST_ENTRY32 InInitializationOrderModuleList;
} PEB_LDR_DATA32, *PPEB_LDR_DATA32;

typedef struct _PEB_LDR_DATA64 {
    BYTE Reserved1[8];
    QWORD Reserved2;
    LIST_ENTRY64 InLoadOrderModuleList;
    LIST_ENTRY64 InMemoryOrderModuleList;
    LIST_ENTRY64 InInitializationOrderModuleList;
} PEB_LDR_DATA64, *PPEB_LDR_DATA64;

typedef struct _PEB32 {
    BYTE Reserved1[2];
    BYTE BeingDebugged;
    BYTE Reserved2[1];
    DWORD Mutant;
    DWORD ImageBaseAddress;
    DWORD Ldr;
    DWORD ProcessParameters;
    DWORD SubSystemData;
    DWORD ProcessHeap;
    DWORD Unknown1[27];
    DWORD NumberOfHeaps;
    DWORD MaximumNumberOfHeaps;
    DWORD ProcessHeaps;
    // ...
} PEB32, *PPEB32;

typedef struct _PEB64 {
    BYTE Reserved1[2];
    BYTE BeingDebugged;
    BYTE Reserved2[1];
    DWORD _Filler;
    QWORD Mutant;
    QWORD ImageBaseAddress;
    QWORD Ldr;
    QWORD ProcessParameters;
    QWORD SubSystemData;
    QWORD ProcessHeap;
    QWORD Unknown1[22];
    DWORD NumberOfHeaps;
    DWORD MaximumNumberOfHeaps;
    QWORD ProcessHeaps;
    // ...
} PEB64, *PPEB64;

typedef struct _RTL_BALANCED_NODE64 {
    union {
        QWORD Children[2];
        struct { 
            QWORD Left;
            QWORD Right;
        };
    };
    union {
        UCHAR Red : 1;
        UCHAR Balance : 2;
        QWORD ParentValue;
    };
} RTL_BALANCED_NODE64, *PRTL_BALANCED_NODE64;

static LPCSTR FILE_DEVICE_STR[] = {
    "---",
    "FILE_DEVICE_BEEP",
    "FILE_DEVICE_CD_ROM",
    "FILE_DEVICE_CD_ROM_FILE_SYSTEM",
    "FILE_DEVICE_CONTROLLER",
    "FILE_DEVICE_DATALINK",
    "FILE_DEVICE_DFS",
    "FILE_DEVICE_DISK",
    "FILE_DEVICE_DISK_FILE_SYSTEM",
    "FILE_DEVICE_FILE_SYSTEM",
    "FILE_DEVICE_INPORT_PORT",
    "FILE_DEVICE_KEYBOARD",
    "FILE_DEVICE_MAILSLOT",
    "FILE_DEVICE_MIDI_IN",
    "FILE_DEVICE_MIDI_OUT",
    "FILE_DEVICE_MOUSE",
    "FILE_DEVICE_MULTI_UNC_PROVIDER",
    "FILE_DEVICE_NAMED_PIPE",
    "FILE_DEVICE_NETWORK",
    "FILE_DEVICE_NETWORK_BROWSER",
    "FILE_DEVICE_NETWORK_FILE_SYSTEM",
    "FILE_DEVICE_NULL",
    "FILE_DEVICE_PARALLEL_PORT",
    "FILE_DEVICE_PHYSICAL_NETCARD",
    "FILE_DEVICE_PRINTER",
    "FILE_DEVICE_SCANNER",
    "FILE_DEVICE_SERIAL_MOUSE_PORT",
    "FILE_DEVICE_SERIAL_PORT",
    "FILE_DEVICE_SCREEN",
    "FILE_DEVICE_SOUND",
    "FILE_DEVICE_STREAMS",
    "FILE_DEVICE_TAPE",
    "FILE_DEVICE_TAPE_FILE_SYSTEM",
    "FILE_DEVICE_TRANSPORT",
    "FILE_DEVICE_UNKNOWN",
    "FILE_DEVICE_VIDEO",
    "FILE_DEVICE_VIRTUAL_DISK",
    "FILE_DEVICE_WAVE_IN",
    "FILE_DEVICE_WAVE_OUT",
    "FILE_DEVICE_8042_PORT",
    "FILE_DEVICE_NETWORK_REDIRECTOR",
    "FILE_DEVICE_BATTERY",
    "FILE_DEVICE_BUS_EXTENDER",
    "FILE_DEVICE_MODEM",
    "FILE_DEVICE_VDM",
    "FILE_DEVICE_MASS_STORAGE",
    "FILE_DEVICE_SMB",
    "FILE_DEVICE_KS",
    "FILE_DEVICE_CHANGER",
    "FILE_DEVICE_SMARTCARD",
    "FILE_DEVICE_ACPI",
    "FILE_DEVICE_DVD",
    "FILE_DEVICE_FULLSCREEN_VIDEO",
    "FILE_DEVICE_DFS_FILE_SYSTEM",
    "FILE_DEVICE_DFS_VOLUME",
    "FILE_DEVICE_SERENUM",
    "FILE_DEVICE_TERMSRV",
    "FILE_DEVICE_KSEC",
    "FILE_DEVICE_FIPS",
    "FILE_DEVICE_INFINIBAND",
    "FILE_DEVICE_VMBUS",
    "FILE_DEVICE_CRYPT_PROVIDER",
    "FILE_DEVICE_WPD",
    "FILE_DEVICE_BLUETOOTH",
    "FILE_DEVICE_MT_COMPOSITE",
    "FILE_DEVICE_MT_TRANSPORT",
    "FILE_DEVICE_BIOMETRIC",
    "FILE_DEVICE_PMI",
    "FILE_DEVICE_EHSTOR",
    "FILE_DEVICE_DEVAPI",
    "FILE_DEVICE_GPIO",
    "FILE_DEVICE_USBEX",
    "FILE_DEVICE_CONSOLE",
    "FILE_DEVICE_NFP",
    "FILE_DEVICE_SYSENV",
    "FILE_DEVICE_VIRTUAL_BLOCK",
    "FILE_DEVICE_POINT_OF_SERVICE",
    "FILE_DEVICE_STORAGE_REPLICATION",
    "FILE_DEVICE_TRUST_ENV",
    "FILE_DEVICE_UCM",
    "FILE_DEVICE_UCMTCPCI",
    "FILE_DEVICE_PERSISTENT_MEMORY",
    "FILE_DEVICE_NVDIMM",
    "FILE_DEVICE_HOLOGRAPHIC",
    "FILE_DEVICE_SDFXHCI",
    "FILE_DEVICE_UCMUCSI",
    "FILE_DEVICE_PRM",
    "FILE_DEVICE_EVENT_COLLECTOR",
    "FILE_DEVICE_USB4",
    "FILE_DEVICE_SOUNDWIRE"
};

static LPCSTR SE_SIGNING_LEVEL_STR[] = {
    "UNCHECKED",
    "UNSIGNED",
    "ENTERPRISE",
    "DEVELOPER",
    "AUTHENTICODE",
    "CUSTOM_2",
    "STORE",
    "ANTIMALWARE",
    "MICROSOFT",
    "CUSTOM_4",
    "CUSTOM_5",
    "DYNAMIC_CODEGEN",
    "WINDOWS",
    "CUSTOM_7",
    "WINDOWS_TCB",
    "CUSTOM_6",
};

#endif /* __VMMWINDEF_H__ */
