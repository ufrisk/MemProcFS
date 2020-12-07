// vmmwindef.h : windows-related defines not in the standard header files.
//
// Author: Ulf Frisk, pcileech@frizk.net
//
#ifndef __VMMWINDEF_H__
#define __VMMWINDEF_H__
#include <windows.h>

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
    DWORD  Filler;
    QWORD  Buffer;
} UNICODE_STRING64, *PUNICODE_STRING64;

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

#endif /* __VMMWINDEF_H__ */
