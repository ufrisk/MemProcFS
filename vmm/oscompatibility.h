// oscompatibility.h : VMM Windows/Linux compatibility layer.
//
// (c) Ulf Frisk, 2021-2024
// Author: Ulf Frisk, pcileech@frizk.net
//
#ifndef __OSCOMPATIBILITY_H__
#define __OSCOMPATIBILITY_H__
#include <leechcore.h>
#include "vmmdll.h"

#ifdef _WIN32

#include <Windows.h>
#include <stdio.h>
#define VMM_LIBRARY_FILETYPE                ".dll"
#define STATUS_SUCCESS                      ((NTSTATUS)0x00000000L)
#define STATUS_UNSUCCESSFUL                 ((NTSTATUS)0xC0000001L)
#define STATUS_END_OF_FILE                  ((NTSTATUS)0xC0000011L)
#define STATUS_FILE_INVALID                 ((NTSTATUS)0xC0000098L)
#define STATUS_FILE_SYSTEM_LIMITATION       ((NTSTATUS)0xC0000427L)
typedef unsigned __int64                    QWORD, *PQWORD;
_Ret_maybenull_ HMODULE WINAPI LoadLibraryU(_In_ LPCSTR lpLibFileName);
int LZ4_decompress_safe(const char *src, char *dst, int compressedSize, int dstCapacity);

#ifdef _WIN64
#define VMM_64BIT
#else /* _WIN64 */
#define VMM_32BIT
#endif /* _WIN64 */

#ifdef _M_ARM64
#define __lzcnt(v)                          (_CountLeadingZeros(v))
#endif /* _M_ARM64 */

#endif /* _WIN32 */
#ifdef LINUX
#define _FILE_OFFSET_BITS 64

#if __SIZEOF_POINTER__ == 8
#define VMM_64BIT
#else /* __SIZEOF_POINTER__ */
#define VMM_32BIT
#endif /* __SIZEOF_POINTER__ */

#include <byteswap.h>
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
#include <sys/eventfd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <lz4.h>
#undef  AF_INET6
#define AF_INET6 23

#define VMM_LIBRARY_FILETYPE                ".so"

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
#define __forceinline                       inline __attribute__((always_inline))
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
#define COMPRESSION_FORMAT_XPRESS           (0x0003)   
#define COMPRESSION_FORMAT_XPRESS_HUFF      (0x0004)

//-----------------------------------------------------------------------------
// SAL DEFINES BELOW:
//-----------------------------------------------------------------------------
#define _Check_return_opt_
#define _Frees_ptr_opt_
#define _In_
#define _In_bytecount_(x)
#define _In_count_(x)
#define _In_opt_
#define _In_opt_z_
#define _In_reads_(x)
#define _In_reads_opt_(x)
#define _In_z_
#define _Inout_
#define _Inout_bytecount_(x)
#define _Inout_count_(x)
#define _Inout_opt_
#define _Inout_updates_(x)
#define _Inout_updates_bytes_(x)
#define _Inout_updates_opt_(x)
#define _Maybenull_
#define _Out_
#define _Out_opt_
#define _Out_writes_(x)
#define _Out_writes_bytes_(x)
#define _Out_writes_bytes_opt_(x)
#define _Out_writes_opt_(x)
#define _Out_writes_to_(x,y)
#define _Out_writes_to_opt_(x,y)
#define _Out_writes_z_(x)
#define _Outptr_
#define _Post_ptr_invalid_
#define _Printf_format_string_
#define _Ret_maybenull_
#define _Success_(x)
#define _When_(x,y)
#define _Writable_bytes_(x)
#define __bcount(x)

#define UNREFERENCED_PARAMETER(x)

#define max(a, b)                           (((a) > (b)) ? (a) : (b))
#define min(a, b)                           (((a) < (b)) ? (a) : (b))
#define _byteswap_ushort(v)                 (bswap_16(v))
#define _byteswap_ulong(v)                  (bswap_32(v))
#define _byteswap_uint64(v)                 (bswap_64(v))
#ifndef _rotr
#define _rotr(v,c)                          ((((DWORD)v) >> ((DWORD)c) | (DWORD)((DWORD)v) << (32 - (DWORD)c)))
#endif /* _rotr */
#define _rotr16(v,c)                        ((((WORD)v) >> ((WORD)c) | (WORD)((WORD)v) << (16 - (WORD)c)))
#define _rotr64(v,c)                        ((((QWORD)v) >> ((QWORD)c) | (QWORD)((QWORD)v) << (64 - (QWORD)c)))
#define _rotl64(v,c)                        ((QWORD)(((QWORD)v) << ((QWORD)c)) | (((QWORD)v) >> (64 - (QWORD)c)))
#define __lzcnt(v)                          (__builtin_clz(v))
#define _countof(_Array)                    (sizeof(_Array) / sizeof(_Array[0]))
#define sprintf_s(s, maxcount, ...)         (snprintf(s, maxcount, __VA_ARGS__))
#define strnlen_s(s, maxcount)              (strnlen(s, maxcount))
#define strcpy_s(dst, len, src)             (strncpy(dst, src, len))
#define strncat_s(dst, dstlen, src, srclen) (strncat(dst, src, min((((strlen(dst) + 1 >= (size_t)(dstlen)) || ((size_t)(dstlen) == 0)) ? 0 : ((size_t)(dstlen) - strlen(dst) - 1)), (size_t)(srclen))))
#define strcat_s(dst, dstlen, src)          (strncat_s(dst, dstlen, src, _TRUNCATE))
#define _vsnprintf_s(dst, len, cnt, fmt, a) (vsnprintf(dst, min((size_t)(len), (size_t)(cnt)), fmt, a))
#define _stricmp(s1, s2)                    (strcasecmp(s1, s2))
#define _strnicmp(s1, s2, maxcount)         (strncasecmp(s1, s2, maxcount))
#define strtok_s(s, d, c)                   (strtok_r(s, d, c))
#define _snprintf_s(s,l,c,...)              (snprintf(s,min((size_t)(l), (size_t)(c)),__VA_ARGS__))
#define sscanf_s(s, f, ...)                 (sscanf(s, f, __VA_ARGS__))
#define StrStrIA(s, f)                      (strcasestr(s, f))
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
#define InterlockedAdd64(p, v)              (__sync_add_and_fetch_8(p, v))
#define InterlockedIncrement64(p)           (__sync_add_and_fetch_8(p, 1))
#define InterlockedIncrement(p)             (__sync_add_and_fetch_4(p, 1))
#define InterlockedDecrement(p)             (__sync_sub_and_fetch_4(p, 1))
#define GetCurrentProcess()					((HANDLE)-1)
#define InetNtopA(af,a,pb,cb)               inet_ntop(((af)==23?10:(af)),a,pb,cb)
#define closesocket(s)                      close(s)
#define HeapAlloc(hHeap, dwFlags, dwBytes)  malloc(dwBytes)

_Ret_maybenull_ HMODULE WINAPI LoadLibraryU(_In_ LPCSTR lpLibFileName);
BOOL FreeLibrary(_In_ HMODULE hLibModule);
FARPROC GetProcAddress(_In_opt_ HMODULE hModule, _In_ LPSTR lpProcName);

// SID
_Success_(return) BOOL IsValidSid(_In_opt_ PSID pSID);
_Success_(return) BOOL ConvertSidToStringSidA(_In_opt_ PSID pSID, _Outptr_ LPSTR *pszSid);
_Success_(return) BOOL ConvertStringSidToSidA(_In_opt_ LPSTR szSID, _Outptr_ PSID *ppSID);
#define LookupAccountSidA(lpSystemName, Sid, Name, cchName, ReferencedDomainName, cchReferencedDomainName, peUse)       (FALSE)

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
DWORD GetModuleFileNameA(_In_opt_ HMODULE hModule, _Out_ LPSTR lpFilename, _In_ DWORD nSize);
HMODULE GetModuleHandleA(_In_opt_ LPCSTR lpModuleName);
QWORD GetTickCount64();
BOOL QueryPerformanceFrequency(_Out_ LARGE_INTEGER *lpFrequency);
BOOL QueryPerformanceCounter(_Out_ LARGE_INTEGER *lpPerformanceCount);
VOID GetLocalTime(LPSYSTEMTIME lpSystemTime);
DWORD InterlockedAdd(DWORD *Addend, DWORD Value);
BOOL GetExitCodeThread(_In_ HANDLE hThread, _Out_ LPDWORD lpExitCode);
BOOL FileTimeToSystemTime(_In_ PFILETIME lpFileTime, _Out_ PSYSTEMTIME lpSystemTime);
BOOL SystemTimeToFileTime(_In_ PSYSTEMTIME lpSystemTime, _Out_ PFILETIME lpFileTime);
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
int strncpy_s(char *dst, size_t dst_size, const char *src, size_t count);
int _vscprintf(_In_z_ _Printf_format_string_ char const *const _Format, va_list _ArgList);

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

typedef struct _IMAGE_RESOURCE_DIRECTORY {
    DWORD   Characteristics;
    DWORD   TimeDateStamp;
    WORD    MajorVersion;
    WORD    MinorVersion;
    WORD    NumberOfNamedEntries;
    WORD    NumberOfIdEntries;
} IMAGE_RESOURCE_DIRECTORY, *PIMAGE_RESOURCE_DIRECTORY;

typedef struct _IMAGE_RESOURCE_DIRECTORY_ENTRY {
    union {
        struct {
            DWORD NameOffset : 31;
            DWORD NameIsString : 1;
        };
        DWORD   Name;
        WORD    Id;
    };
    union {
        DWORD   OffsetToData;
        struct {
            DWORD   OffsetToDirectory : 31;
            DWORD   DataIsDirectory : 1;
        };
    };
} IMAGE_RESOURCE_DIRECTORY_ENTRY, *PIMAGE_RESOURCE_DIRECTORY_ENTRY;

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








#define IMAGE_SCN_LNK_NRELOC_OVFL            0x01000000
#define IMAGE_SCN_MEM_DISCARDABLE            0x02000000
#define IMAGE_SCN_MEM_NOT_CACHED             0x04000000
#define IMAGE_SCN_MEM_NOT_PAGED              0x08000000
#define IMAGE_SCN_MEM_SHARED                 0x10000000
#define IMAGE_SCN_MEM_EXECUTE                0x20000000
#define IMAGE_SCN_MEM_READ                   0x40000000
#define IMAGE_SCN_MEM_WRITE                  0x80000000

#define SERVICE_KERNEL_DRIVER          0x00000001
#define SERVICE_FILE_SYSTEM_DRIVER     0x00000002
#define SERVICE_ADAPTER                0x00000004
#define SERVICE_RECOGNIZER_DRIVER      0x00000008
#define SERVICE_DRIVER                 (SERVICE_KERNEL_DRIVER | \
                                        SERVICE_FILE_SYSTEM_DRIVER | \
                                        SERVICE_RECOGNIZER_DRIVER)
#define SERVICE_WIN32_OWN_PROCESS      0x00000010
#define SERVICE_WIN32_SHARE_PROCESS    0x00000020
#define SERVICE_WIN32                  (SERVICE_WIN32_OWN_PROCESS | \
                                        SERVICE_WIN32_SHARE_PROCESS)
#define SERVICE_USER_SERVICE           0x00000040
#define SERVICE_USERSERVICE_INSTANCE   0x00000080
#define SERVICE_USER_SHARE_PROCESS     (SERVICE_USER_SERVICE | \
                                        SERVICE_WIN32_SHARE_PROCESS)
#define SERVICE_USER_OWN_PROCESS       (SERVICE_USER_SERVICE | \
                                        SERVICE_WIN32_OWN_PROCESS)
#define SERVICE_INTERACTIVE_PROCESS    0x00000100
#define SERVICE_PKG_SERVICE            0x00000200
#define SERVICE_TYPE_ALL               (SERVICE_WIN32  | \
                                        SERVICE_ADAPTER | \
                                        SERVICE_DRIVER  | \
                                        SERVICE_INTERACTIVE_PROCESS | \
                                        SERVICE_USER_SERVICE | \
                                        SERVICE_USERSERVICE_INSTANCE | \
                                        SERVICE_PKG_SERVICE)










// SRWLOCK
typedef struct tdSRWLOCK {
    uint32_t xchg;
    int c;
} SRWLOCK, *PSRWLOCK;
VOID InitializeSRWLock(PSRWLOCK SRWLock);
VOID AcquireSRWLockExclusive(_Inout_ PSRWLOCK SRWLock);
VOID ReleaseSRWLockExclusive(_Inout_ PSRWLOCK SRWLock);
#define AcquireSRWLockShared    AcquireSRWLockExclusive
#define ReleaseSRWLockShared    ReleaseSRWLockExclusive
#define SRWLOCK_INIT            { 0 }







typedef struct _SLIST_ENTRY {
    struct _SLIST_ENTRY *Next;
} SLIST_ENTRY, *PSLIST_ENTRY;

typedef struct _SLIST_HEADER {
    PSLIST_ENTRY Next;
    SRWLOCK LockSRW;
    USHORT c;
} SLIST_HEADER, *PSLIST_HEADER;

VOID InitializeSListHead(PSLIST_HEADER ListHead);
USHORT QueryDepthSList(PSLIST_HEADER ListHead);
PSLIST_ENTRY InterlockedPopEntrySList(_Inout_ PSLIST_HEADER ListHead);
PSLIST_ENTRY InterlockedPushEntrySList(_Inout_ PSLIST_HEADER ListHead, _Inout_ PSLIST_ENTRY ListEntry);

#endif /* LINUX */



#endif /* __OSCOMPATIBILITY_H__ */
