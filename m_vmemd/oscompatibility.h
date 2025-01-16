// oscompatibility.h : VMM Windows/Linux compatibility layer.
//
// (c) Ulf Frisk, 2021-2025
// Author: Ulf Frisk, pcileech@frizk.net
//
#ifndef __OSCOMPATIBILITY_H__
#define __OSCOMPATIBILITY_H__
#include <leechcore.h>
#include "vmmdll.h"

#ifdef _WIN32

#include <Windows.h>
#include <stdio.h>
#define STATUS_SUCCESS                      ((NTSTATUS)0x00000000L)
#define STATUS_UNSUCCESSFUL                 ((NTSTATUS)0xC0000001L)
#define STATUS_END_OF_FILE                  ((NTSTATUS)0xC0000011L)
#define STATUS_FILE_INVALID                 ((NTSTATUS)0xC0000098L)
#define STATUS_FILE_SYSTEM_LIMITATION       ((NTSTATUS)0xC0000427L)
typedef unsigned __int64                    QWORD, *PQWORD;

#endif /* _WIN32 */
#if defined(LINUX) || defined(MACOS)
#define _FILE_OFFSET_BITS 64
#include <ctype.h>
#include <dirent.h>
#include <dlfcn.h>
#include <errno.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <time.h>
#include <unistd.h>
#include <sys/types.h>

#define LC_LIBRARY_FILETYPE                 ".so"

typedef void                                VOID, *PVOID, *LPVOID;
typedef void                                *HANDLE, **PHANDLE, *HMODULE, *FARPROC;
typedef uint32_t                            BOOL, *PBOOL;
typedef uint8_t                             BYTE, *PBYTE, *LPBYTE;
typedef uint8_t                             UCHAR, *PUCHAR;
typedef char                                CHAR, *PCHAR, *PSTR, *LPSTR;
typedef const char                          *LPCSTR;
typedef int16_t                             SHORT, *PSHORT;
typedef int32_t                             LONG;
typedef int64_t                             LONGLONG;
typedef uint16_t                            WORD, *PWORD, USHORT, *PUSHORT;
typedef uint16_t                            WCHAR, *PWCHAR, *LPWSTR;
typedef const uint16_t                      *LPCWSTR;
typedef uint32_t                            UINT, DWORD, *PDWORD, *LPDWORD, NTSTATUS, ULONG, *PULONG, ULONG32;
typedef long long unsigned int              QWORD, *PQWORD, ULONG64, *PULONG64, ULONG_PTR;
typedef uint64_t                            DWORD64, *PDWORD64, LARGE_INTEGER, *PLARGE_INTEGER, ULONGLONG, FILETIME, *PFILETIME;
typedef size_t                              SIZE_T, *PSIZE_T;
typedef struct _M128A                       { ULONGLONG Low; LONGLONG High; } M128A, *PM128A;
typedef void                                *OVERLAPPED, *LPOVERLAPPED;
typedef struct tdEXCEPTION_RECORD32         { CHAR sz[80]; } EXCEPTION_RECORD32;
typedef struct tdEXCEPTION_RECORD64         { CHAR sz[152]; } EXCEPTION_RECORD64;
typedef struct tdSID                        { BYTE pb[12]; } SID, *PSID;
typedef DWORD(*PTHREAD_START_ROUTINE)(PVOID);
typedef DWORD(*LPTHREAD_START_ROUTINE)(PVOID);
typedef int(*_CoreCrtNonSecureSearchSortCompareFunction)(void const *, void const *);
#define WINAPI
#define errno_t                             int
#define CONST                               const
#define TRUE                                1
#define FALSE                               0
#define MAX_PATH                            260
#define LMEM_ZEROINIT                       0x0040
#define INVALID_HANDLE_VALUE                ((HANDLE)-1)
#define STD_INPUT_HANDLE                    ((DWORD)-10)
#define STD_OUTPUT_HANDLE                   ((DWORD)-11)
#define GENERIC_WRITE                       (0x40000000L)
#define GENERIC_READ                        (0x80000000L)
#define FILE_SHARE_READ                     (0x00000001L)
#define CREATE_NEW                          (0x00000001L)
#define OPEN_EXISTING                       (0x00000003L)
#define FILE_ATTRIBUTE_NORMAL               (0x00000080L)
#define STILL_ACTIVE                        (0x00000103L)
#define CRYPT_STRING_HEX_ANY                (0x00000008L)
#define CRYPT_STRING_HEXASCIIADDR           (0x00000008L)
#define STILL_ACTIVE                        (0x00000103L)
#define INVALID_FILE_SIZE                   (0xffffffffL)
#define _TRUNCATE                           ((SIZE_T)-1LL)
#define HEAP_ZERO_MEMORY                    0x00000008  
#define CONSOLE_SCREEN_BUFFER_INFO          PVOID    // TODO: remove this dummy
#define SOCKET                              int
#define INVALID_SOCKET	                    -1
#define SOCKET_ERROR	                    -1
#define WSAEWOULDBLOCK                      10035L
#define WAIT_OBJECT_0                       (0x00000000UL)
#define INFINITE                            (0xFFFFFFFFUL)
#define MAXIMUM_WAIT_OBJECTS                64
#define SID_MAX_SUB_AUTHORITIES             (15)
#define SECURITY_MAX_SID_SIZE               (sizeof(SID) - sizeof(DWORD) + (SID_MAX_SUB_AUTHORITIES * sizeof(DWORD)))
#define CP_ACP                              0
#define CP_UTF8                             65001
#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES    16
#define STATUS_SUCCESS                      ((NTSTATUS)0x00000000L)
#define STATUS_UNSUCCESSFUL                 ((NTSTATUS)0xC0000001L)
#define STATUS_END_OF_FILE                  ((NTSTATUS)0xC0000011L)
#define STATUS_FILE_INVALID                 ((NTSTATUS)0xC0000098L)
#define STATUS_FILE_SYSTEM_LIMITATION       ((NTSTATUS)0xC0000427L)

//-----------------------------------------------------------------------------
// SAL DEFINES BELOW:
//-----------------------------------------------------------------------------
#define _In_
#define _In_z_
#define _Out_
#define _Inout_
#define _Inout_opt_
#define _In_opt_
#define _In_opt_z_
#define _Out_opt_
#define _Check_return_opt_
#define _Frees_ptr_opt_
#define _Post_ptr_invalid_
#define _Printf_format_string_
#define _In_reads_(x)
#define _In_reads_opt_(x)
#define _Out_writes_(x)
#define __bcount(x)
#define _Inout_bytecount_(x)
#define _Inout_count_(x)
#define _Inout_updates_(x)
#define _Inout_updates_opt_(x)
#define _Inout_updates_bytes_(x)
#define _Out_writes_bytes_(x)
#define _Out_writes_bytes_opt_(x)
#define _Out_writes_opt_(x)
#define _Out_writes_to_(x,y)
#define _Out_writes_z_(x)
#define _Maybenull_
#define _Success_(x)
#define _When_(x,y)
#define _Writable_bytes_(x)

#define UNREFERENCED_PARAMETER(x)

#define __declspec(dllexport)
#define max(a, b)                           (((a) > (b)) ? (a) : (b))
#define min(a, b)                           (((a) < (b)) ? (a) : (b))
#define _byteswap_ushort(v)                 (__builtin_bswap16(v))
#define _byteswap_ulong(v)                  (__builtin_bswap32(v))
#define _byteswap_uint64(v)                 (__builtin_bswap64(v))
#ifndef _rotr
#define _rotr(v,c)                          ((((DWORD)v) >> ((DWORD)c) | (DWORD)((DWORD)v) << (32 - (DWORD)c)))
#endif /* _rotr */
#define _rotr16(v,c)                        ((((WORD)v) >> ((WORD)c) | (WORD)((WORD)v) << (16 - (WORD)c)))
#define _rotr64(v,c)                        ((((QWORD)v) >> ((QWORD)c) | (QWORD)((QWORD)v) << (64 - (QWORD)c)))
#define _rotl64(v,c)                        ((QWORD)(((QWORD)v) << ((QWORD)c)) | (((QWORD)v) >> (64 - (QWORD)c)))
#define _countof(_Array)                    (sizeof(_Array) / sizeof(_Array[0]))
#define sprintf_s(s, maxcount, ...)         (snprintf(s, maxcount, __VA_ARGS__))
#define strnlen_s(s, maxcount)              (strnlen(s, maxcount))
#define strcpy_s(dst, len, src)             (strncpy(dst, src, len))
#define strncpy_s(dst, len, src, srclen)    (strncpy(dst, src, min((size_t)(max(1, len)) - 1, (size_t)(srclen))))
#define strncat_s(dst, dstlen, src, srclen) (strncat(dst, src, min((((strlen(dst) + 1 >= (size_t)(dstlen)) || ((size_t)(dstlen) == 0)) ? 0 : ((size_t)(dstlen) - strlen(dst) - 1)), (size_t)(srclen))))
#define strcat_s(dst, dstlen, src)          (strncat_s(dst, dstlen, src, _TRUNCATE))
#define _vsnprintf_s(dst, len, cnt, fmt, a) (vsnprintf(dst, min((size_t)(len), (size_t)(cnt)), fmt, a))
#define _stricmp(s1, s2)                    (strcasecmp(s1, s2))
#define _strnicmp(s1, s2, maxcount)         (strncasecmp(s1, s2, maxcount))
#define strtok_s(s, d, c)                   (strtok_r(s, d, c))
#define _snprintf_s(s,l,c,...)              (snprintf(s,min((size_t)(l), (size_t)(c)),__VA_ARGS__))
#define sscanf_s(s, f, ...)                 (sscanf(s, f, __VA_ARGS__))
#define SwitchToThread()                    (sched_yield())
#define ExitThread(dwExitCode)              (pthread_exit(dwExitCode))
#define ExitProcess(c)                      (exit(c ? EXIT_SUCCESS : EXIT_FAILURE))
#define Sleep(dwMilliseconds)               (usleep(1000*dwMilliseconds))
#define _fsopen(szFile, szMode, dwAttr)     fopen(szFile, szMode)
#define fopen_s(ppFile, szFile, szAttr)     ((*ppFile = fopen(szFile, szAttr)) ? 0 : 1)
#define ZeroMemory(pb, cb)                  (memset(pb, 0, cb))
#define _ftelli64(f)                        (ftello(f))
#define _fseeki64(f, o, w)                  (fseeko(f, o, w))
#define _chsize_s(fd, cb)                   (ftruncate64(fd, cb))
#define _fileno(f)                          (fileno(f))
#define InterlockedAdd64(p, v)              (__sync_add_and_fetch(p, v))
#define InterlockedIncrement64(p)           (__sync_add_and_fetch(p, 1))
#define InterlockedIncrement(p)             (__sync_add_and_fetch_4(p, 1))
#define InterlockedDecrement(p)             (__sync_sub_and_fetch_4(p, 1))
#define GetCurrentProcess()					((HANDLE)-1)
#define InetNtopA                           inet_ntop
#define closesocket(s)                      close(s)
#define FreeLibrary(h)
#define GetModuleHandleA(s)		            NULL
#define HeapAlloc(hHeap, dwFlags, dwBytes)  malloc(dwBytes)

HMODULE LoadLibraryA(LPSTR lpFileName);
FARPROC GetProcAddress(HMODULE hModule, LPSTR lpProcName);

// CRITICAL SECTION
#ifndef _LINUX_DEF_CRITICAL_SECTION
#define _LINUX_DEF_CRITICAL_SECTION
typedef struct tdCRITICAL_SECTION {
    pthread_mutex_t mutex;
    pthread_mutexattr_t mta;
} CRITICAL_SECTION, *LPCRITICAL_SECTION;
#endif /* _LINUX_DEF_CRITICAL_SECTION */
BOOL InitializeCriticalSectionAndSpinCount(LPCRITICAL_SECTION lpCriticalSection, DWORD dwSpinCount);
VOID InitializeCriticalSection(LPCRITICAL_SECTION lpCriticalSection);
VOID DeleteCriticalSection(LPCRITICAL_SECTION lpCriticalSection);
VOID EnterCriticalSection(LPCRITICAL_SECTION lpCriticalSection);
VOID LeaveCriticalSection(LPCRITICAL_SECTION lpCriticalSection);

typedef struct _SYSTEMTIME {
    WORD wYear;
    WORD wMonth;
    WORD wDayOfWeek;
    WORD wDay;
    WORD wHour;
    WORD wMinute;
    WORD wSecond;
    WORD wMilliseconds;
} SYSTEMTIME, *PSYSTEMTIME, *LPSYSTEMTIME;

typedef struct _WIN32_FIND_DATAA {
    CHAR __cExtension[5];
    CHAR cFileName[MAX_PATH];
} WIN32_FIND_DATAA, *PWIN32_FIND_DATAA, *LPWIN32_FIND_DATAA;

HANDLE FindFirstFileA(LPSTR lpFileName, LPWIN32_FIND_DATAA lpFindFileData);
BOOL FindNextFileA(HANDLE hFindFile, LPWIN32_FIND_DATAA lpFindFileData);
HANDLE LocalAlloc(DWORD uFlags, SIZE_T uBytes);
VOID LocalFree(HANDLE hMem);
QWORD GetTickCount64();
BOOL QueryPerformanceFrequency(_Out_ LARGE_INTEGER *lpFrequency);
BOOL QueryPerformanceCounter(_Out_ LARGE_INTEGER *lpPerformanceCount);
VOID GetLocalTime(LPSYSTEMTIME lpSystemTime);
DWORD InterlockedAdd(DWORD *Addend, DWORD Value);
BOOL GetExitCodeThread(_In_ HANDLE hThread, _Out_ LPDWORD lpExitCode);
BOOL FileTimeToSystemTime(_In_ PFILETIME lpFileTime, _Out_ PSYSTEMTIME lpSystemTime);
VOID GetSystemTimeAsFileTime(PFILETIME lpSystemTimeAsFileTime);
errno_t tmpnam_s(char *_Buffer, ssize_t _Size);

HANDLE CreateThread(
    PVOID    lpThreadAttributes,
    SIZE_T    dwStackSize,
    PVOID    lpStartAddress,
    PVOID    lpParameter,
    DWORD    dwCreationFlags,
    PDWORD    lpThreadId
);

BOOL CloseHandle(_In_ HANDLE hObject);
BOOL ResetEvent(_In_ HANDLE hEventIngestPhys);
BOOL SetEvent(_In_ HANDLE hEventIngestPhys);
HANDLE CreateEvent(_In_opt_ PVOID lpEventAttributes, _In_ BOOL bManualReset, _In_ BOOL bInitialState, _In_opt_ PVOID lpName);
DWORD WaitForMultipleObjects(_In_ DWORD nCount, HANDLE *lpHandles, _In_ BOOL bWaitAll, _In_ DWORD dwMilliseconds);
DWORD WaitForSingleObject(_In_ HANDLE hHandle, _In_ DWORD dwMilliseconds);

// for some unexplainable reasons the gcc on -O2 will optimize out functionality
// and destroy the proper workings on some functions due to an unexplainable
// reason disable optimization on a function level resolves the issues ...
#define LINUX_NO_OPTIMIZE __attribute__((optimize("O0")))

#define CONTAINING_RECORD(address, type, field) ((type *)( \
                                                  (PCHAR)(address) - \
                                                  (ULONG_PTR)(&((type *)0)->field)))

typedef struct _IMAGE_DEBUG_DIRECTORY {
    DWORD   Characteristics;
    DWORD   TimeDateStamp;
    WORD    MajorVersion;
    WORD    MinorVersion;
    DWORD   Type;
    DWORD   SizeOfData;
    DWORD   AddressOfRawData;
    DWORD   PointerToRawData;
} IMAGE_DEBUG_DIRECTORY, *PIMAGE_DEBUG_DIRECTORY;

#define IMAGE_DIRECTORY_ENTRY_EXPORT          0
#define IMAGE_DIRECTORY_ENTRY_IMPORT          1
#define IMAGE_DIRECTORY_ENTRY_RESOURCE        2
#define IMAGE_DIRECTORY_ENTRY_EXCEPTION       3
#define IMAGE_DIRECTORY_ENTRY_SECURITY        4
#define IMAGE_DIRECTORY_ENTRY_BASERELOC       5
#define IMAGE_DIRECTORY_ENTRY_DEBUG           6
#define IMAGE_DIRECTORY_ENTRY_ARCHITECTURE    7
#define IMAGE_DIRECTORY_ENTRY_GLOBALPTR       8
#define IMAGE_DIRECTORY_ENTRY_TLS             9
#define IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG    10
#define IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT   11
#define IMAGE_DIRECTORY_ENTRY_IAT            12
#define IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT   13
#define IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR 14

#define IMAGE_DOS_SIGNATURE                 0x5A4D
#define IMAGE_NT_SIGNATURE                  0x00004550 
#define IMAGE_NT_OPTIONAL_HDR32_MAGIC      0x10b
#define IMAGE_NT_OPTIONAL_HDR64_MAGIC      0x20b
#define IMAGE_DEBUG_TYPE_CODEVIEW             2

typedef struct _IMAGE_DOS_HEADER {
    WORD   e_magic;
    WORD   e_cblp;
    WORD   e_cp;
    WORD   e_crlc;
    WORD   e_cparhdr;
    WORD   e_minalloc;
    WORD   e_maxalloc;
    WORD   e_ss;
    WORD   e_sp;
    WORD   e_csum;
    WORD   e_ip;
    WORD   e_cs;
    WORD   e_lfarlc;
    WORD   e_ovno;
    WORD   e_res[4];
    WORD   e_oemid;
    WORD   e_oeminfo;
    WORD   e_res2[10];
    LONG   e_lfanew;
} IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;

typedef struct _IMAGE_FILE_HEADER {
    WORD    Machine;
    WORD    NumberOfSections;
    DWORD   TimeDateStamp;
    DWORD   PointerToSymbolTable;
    DWORD   NumberOfSymbols;
    WORD    SizeOfOptionalHeader;
    WORD    Characteristics;
} IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;

typedef struct _IMAGE_OPTIONAL_HEADER {
    WORD    Magic;
    BYTE    MajorLinkerVersion;
    BYTE    MinorLinkerVersion;
    DWORD   SizeOfCode;
    DWORD   SizeOfInitializedData;
    DWORD   SizeOfUninitializedData;
    DWORD   AddressOfEntryPoint;
    DWORD   BaseOfCode;
    DWORD   BaseOfData;
    DWORD   ImageBase;
    DWORD   SectionAlignment;
    DWORD   FileAlignment;
    WORD    MajorOperatingSystemVersion;
    WORD    MinorOperatingSystemVersion;
    WORD    MajorImageVersion;
    WORD    MinorImageVersion;
    WORD    MajorSubsystemVersion;
    WORD    MinorSubsystemVersion;
    DWORD   Win32VersionValue;
    DWORD   SizeOfImage;
    DWORD   SizeOfHeaders;
    DWORD   CheckSum;
    WORD    Subsystem;
    WORD    DllCharacteristics;
    DWORD   SizeOfStackReserve;
    DWORD   SizeOfStackCommit;
    DWORD   SizeOfHeapReserve;
    DWORD   SizeOfHeapCommit;
    DWORD   LoaderFlags;
    DWORD   NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER32, *PIMAGE_OPTIONAL_HEADER32;

typedef struct _IMAGE_OPTIONAL_HEADER64 {
    WORD        Magic;
    BYTE        MajorLinkerVersion;
    BYTE        MinorLinkerVersion;
    DWORD       SizeOfCode;
    DWORD       SizeOfInitializedData;
    DWORD       SizeOfUninitializedData;
    DWORD       AddressOfEntryPoint;
    DWORD       BaseOfCode;
    ULONGLONG   ImageBase;
    DWORD       SectionAlignment;
    DWORD       FileAlignment;
    WORD        MajorOperatingSystemVersion;
    WORD        MinorOperatingSystemVersion;
    WORD        MajorImageVersion;
    WORD        MinorImageVersion;
    WORD        MajorSubsystemVersion;
    WORD        MinorSubsystemVersion;
    DWORD       Win32VersionValue;
    DWORD       SizeOfImage;
    DWORD       SizeOfHeaders;
    DWORD       CheckSum;
    WORD        Subsystem;
    WORD        DllCharacteristics;
    ULONGLONG   SizeOfStackReserve;
    ULONGLONG   SizeOfStackCommit;
    ULONGLONG   SizeOfHeapReserve;
    ULONGLONG   SizeOfHeapCommit;
    DWORD       LoaderFlags;
    DWORD       NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER64, *PIMAGE_OPTIONAL_HEADER64;

typedef struct _IMAGE_NT_HEADERS64 {
    DWORD Signature;
    IMAGE_FILE_HEADER FileHeader;
    IMAGE_OPTIONAL_HEADER64 OptionalHeader;
} IMAGE_NT_HEADERS, IMAGE_NT_HEADERS64, *PIMAGE_NT_HEADERS, *PIMAGE_NT_HEADERS64;

typedef struct _IMAGE_NT_HEADERS {
    DWORD Signature;
    IMAGE_FILE_HEADER FileHeader;
    IMAGE_OPTIONAL_HEADER32 OptionalHeader;
} IMAGE_NT_HEADERS32, *PIMAGE_NT_HEADERS32;

typedef struct _IMAGE_EXPORT_DIRECTORY {
    DWORD   Characteristics;
    DWORD   TimeDateStamp;
    WORD    MajorVersion;
    WORD    MinorVersion;
    DWORD   Name;
    DWORD   Base;
    DWORD   NumberOfFunctions;
    DWORD   NumberOfNames;
    DWORD   AddressOfFunctions;
    DWORD   AddressOfNames;
    DWORD   AddressOfNameOrdinals;
} IMAGE_EXPORT_DIRECTORY, *PIMAGE_EXPORT_DIRECTORY;

typedef struct _IMAGE_IMPORT_DESCRIPTOR {
    union {
        DWORD   Characteristics;
        DWORD   OriginalFirstThunk;
    };
    DWORD   TimeDateStamp;
    DWORD   ForwarderChain;
    DWORD   Name;
    DWORD   FirstThunk;
} IMAGE_IMPORT_DESCRIPTOR, *PIMAGE_IMPORT_DESCRIPTOR;

#define REG_NONE                    ( 0ul )
#define REG_SZ                      ( 1ul )
#define REG_EXPAND_SZ               ( 2ul )
#define REG_BINARY                  ( 3ul )
#define REG_DWORD                   ( 4ul )
#define REG_DWORD_LITTLE_ENDIAN     ( 4ul )
#define REG_DWORD_BIG_ENDIAN        ( 5ul )
#define REG_LINK                    ( 6ul )
#define REG_MULTI_SZ                ( 7ul )
#define REG_RESOURCE_LIST           ( 8ul )
#define REG_FULL_RESOURCE_DESCRIPTOR ( 9ul )
#define REG_RESOURCE_REQUIREMENTS_LIST ( 10ul )
#define REG_QWORD                   ( 11ul )
#define REG_QWORD_LITTLE_ENDIAN     ( 11ul )

typedef enum _SID_NAME_USE {
    SidTypeUser = 1,
    SidTypeGroup,
    SidTypeDomain,
    SidTypeAlias,
    SidTypeWellKnownGroup,
    SidTypeDeletedAccount,
    SidTypeInvalid,
    SidTypeUnknown,
    SidTypeComputer,
    SidTypeLabel,
    SidTypeLogonSession
} SID_NAME_USE, *PSID_NAME_USE;

typedef struct _LIST_ENTRY {
    struct _LIST_ENTRY *Flink;
    struct _LIST_ENTRY *Blink;
} LIST_ENTRY, *PLIST_ENTRY;

typedef struct LIST_ENTRY32 {
    DWORD Flink;
    DWORD Blink;
} LIST_ENTRY32;
typedef LIST_ENTRY32 *PLIST_ENTRY32;

typedef struct LIST_ENTRY64 {
    ULONGLONG Flink;
    ULONGLONG Blink;
} LIST_ENTRY64;
typedef LIST_ENTRY64 *PLIST_ENTRY64;

#endif /* LINUX || MACOS */

#endif /* __OSCOMPATIBILITY_H__ */
