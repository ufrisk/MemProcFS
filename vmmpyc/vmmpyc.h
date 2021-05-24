// vmmpyc.h : definitions related to the MemProcFS/VMM Python API
//
// (c) Ulf Frisk, 2021
// Author: Ulf Frisk, pcileech@frizk.net
//
#ifndef __VMMPYC_H__
#define __VMMPYC_H__

#define PY_SSIZE_T_CLEAN
#define Py_LIMITED_API 0x03060000
#ifdef _DEBUG
#undef _DEBUG
#include <Python.h>
#include <structmember.h>
#define _DEBUG
#else
#include <Python.h>
#include <structmember.h>
#endif
#include <leechcore.h>
#include <vmmdll.h>
#undef EXPORTED_FUNCTION

#ifdef _WIN32
#define EXPORTED_FUNCTION                   __declspec(dllexport)
#endif /* _WIN32 */
#ifdef LINUX

#include <netinet/in.h>

#define EXPORTED_FUNCTION                   __attribute__((visibility("default")))
typedef uint32_t                            BOOL, *PBOOL;
typedef char                                CHAR, *PCHAR, *PSTR, *LPSTR;
typedef uint64_t                            LARGE_INTEGER, *PLARGE_INTEGER, ULONGLONG, FILETIME, *PFILETIME;

#define TRUE                                1
#define FALSE                               0
#define _TRUNCATE                           ((SIZE_T)-1LL)
#define LMEM_ZEROINIT                       0x0040

#define _In_
#define _Success_(x)

#define REG_NONE                            ( 0ul )
#define REG_SZ                              ( 1ul )
#define REG_EXPAND_SZ                       ( 2ul )
#define REG_BINARY                          ( 3ul )
#define REG_DWORD                           ( 4ul )
#define REG_DWORD_LITTLE_ENDIAN             ( 4ul )
#define REG_DWORD_BIG_ENDIAN                ( 5ul )
#define REG_LINK                            ( 6ul )
#define REG_MULTI_SZ                        ( 7ul )
#define REG_RESOURCE_LIST                   ( 8ul )
#define REG_FULL_RESOURCE_DESCRIPTOR        ( 9ul )
#define REG_RESOURCE_REQUIREMENTS_LIST      ( 10ul )
#define REG_QWORD                           ( 11ul )
#define REG_QWORD_LITTLE_ENDIAN             ( 11ul )

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

#define max(a, b)                           (((a) > (b)) ? (a) : (b))
#define min(a, b)                           (((a) < (b)) ? (a) : (b))
#define _countof(_Array)                    (sizeof(_Array) / sizeof(_Array[0]))
#define ZeroMemory(pb, cb)                  (memset(pb, 0, cb))
#define strcpy_s(dst, len, src)             (strncpy(dst, src, len))
#define strncpy_s(dst, len, src, srclen)    (strncpy(dst, src, min((QWORD)(max(1, len)) - 1, (QWORD)(srclen))))
#define sprintf_s(s, maxcount, ...)         (snprintf(s, maxcount, __VA_ARGS__))
#define _snprintf_s(s,l,c,...)              (snprintf(s,min((QWORD)(l), (QWORD)(c)),__VA_ARGS__))

// linux functions defined in oscompatibility.c
HANDLE LocalAlloc(DWORD uFlags, SIZE_T uBytes);
VOID LocalFree(HANDLE hMem);
BOOL FileTimeToSystemTime(_In_ PFILETIME lpFileTime, _Out_ PSYSTEMTIME lpSystemTime);

#endif /* LINUX */

extern PyObject *g_pPyType_Vmm;
extern PyObject *g_pPyType_Pdb;
extern PyObject *g_pPyType_Vfs;
extern PyObject *g_pPyType_Maps;
extern PyObject *g_pPyType_Kernel;
extern PyObject *g_pPyType_Module;
extern PyObject *g_pPyType_Process;
extern PyObject *g_pPyType_ProcessMaps;

typedef struct tdPyObj_Vmm {
    PyObject_HEAD
    BOOL fValid;
    BOOL fVmmCoreOpenType;      // original open = TRUE, existing open = FALSE
    PyObject *pyObjVfs;
    PyObject *pyObjKernel;
    PyObject *pyObjMemory;
} PyObj_Vmm;

typedef struct tdPyObj_Pdb {
    PyObject_HEAD
    BOOL fValid;
    CHAR szModule[MAX_PATH];
} PyObj_Pdb;

typedef struct tdPyObj_Vfs {
    PyObject_HEAD
    BOOL fValid;
} PyObj_Vfs;

typedef struct tdPyObj_Maps {
    PyObject_HEAD
    BOOL fValid;
} PyObj_Maps;

typedef struct tdPyObj_PhysicalMemory {
    PyObject_HEAD
    BOOL fValid;
} PyObj_PhysicalMemory;

typedef struct tdPyObj_Module {
    PyObject_HEAD
    BOOL fValid;
    DWORD dwPID;
    VMMDLL_MAP_MODULEENTRY ModuleEntry;
    CHAR uszText[64];
    CHAR uszFullName[128];
} PyObj_Module;

typedef struct tdPyObj_ModuleMaps {
    PyObject_HEAD
    BOOL fValid;
    DWORD dwPID;
    CHAR uszModule[64];
} PyObj_ModuleMaps;

typedef struct tdPyObj_Kernel {
    PyObject_HEAD
    BOOL fValid;
    PyObject *pyObjPdb;
    PyObject *pyObjProcess;
} PyObj_Kernel;

typedef struct tdPyObj_Process {
    PyObject_HEAD
    BOOL fValid;
    DWORD dwPID;
    BOOL fValidInfo;
    VMMDLL_PROCESS_INFORMATION Info;
} PyObj_Process;

typedef struct tdPyObj_ProcessMaps {
    PyObject_HEAD
    BOOL fValid;
    DWORD dwPID;
} PyObj_ProcessMaps;

typedef struct tdPyObj_VirtualMemory {
    PyObject_HEAD
    BOOL fValid;
    DWORD dwPID;
} PyObj_VirtualMemory;

typedef struct tdPyObj_RegHive {
    PyObject_HEAD
    BOOL fValid;
    VMMDLL_REGISTRY_HIVE_INFORMATION Info;
} PyObj_RegHive;

typedef struct tdPyObj_RegMemory {
    PyObject_HEAD
    BOOL fValid;
    QWORD vaCMHive;
} PyObj_RegMemory;

typedef struct tdPyObj_RegKey {
    PyObject_HEAD
    BOOL fValid;
    PyObject *pyName;   // unicode object
    CHAR uszPath[2 * MAX_PATH];
    QWORD ftLastWrite;
} PyObj_RegKey;

typedef struct tdPyObj_RegValue {
    PyObject_HEAD
    BOOL fValid;
    PyObject *pyName;   // unicode object
    CHAR uszPath[2 * MAX_PATH];
    BOOL fValue;
    BOOL fValueData;
    DWORD tp;
    DWORD cb;
    union {
        DWORD dw;
        QWORD qw;
        BYTE pb[0x40];
    } Value;
} PyObj_RegValue;

typedef struct tdPyObj_VmmPycPlugin {
    PyObject_HEAD
} PyObj_VmmPycPlugin;

int PyDict_SetItemDWORD_DECREF(PyObject *dp, DWORD key, PyObject *item);
int PyDict_SetItemString_DECREF(PyObject *dp, const char *key, PyObject *item);
int PyDict_SetItemUnicode_DECREF(PyObject *dp, PyObject *key_nodecref, PyObject *item);
int PyList_Append_DECREF(PyObject *dp, PyObject *item);

VOID Util_FileTime2String(_In_ QWORD ft, _Out_writes_(24) LPSTR szTime);

/*
* Return the sub-string after the last '\' character in the wsz NULL terminated
* string. If no '\' is found original wsz string is returned. The returned data
* must not be free'd and is only valid as long as the wsz parameter is valid.
* -- usz
* -- return
*/
LPSTR Util_PathSplitLastU(_In_ LPSTR usz);

/*
* Split the string usz into two at the last (back)slash which is removed.
* Ex: usz: XXX/YYY/ZZZ/AAA -> uszPath: XXX/YYY/ZZZ + return: AAA
* -- usz = utf-8 or ascii string.
* -- uszPath = buffer to receive result.
* -- cbuPath = byte length of uszPath buffer
* -- return
*/
LPSTR Util_PathSplitLastEx(_In_ LPSTR usz, _Out_writes_(cbuPath) LPSTR uszPath, _In_ DWORD cbuPath);

/*
* Initialize Python Type objects.
* -- pModule
* -- return
*/
_Success_(return) BOOL VmmPycVmm_InitializeType(PyObject *pModule);
_Success_(return) BOOL VmmPycPdb_InitializeType(PyObject *pModule);
_Success_(return) BOOL VmmPycVfs_InitializeType(PyObject *pModule);
_Success_(return) BOOL VmmPycMaps_InitializeType(PyObject *pModule);
_Success_(return) BOOL VmmPycKernel_InitializeType(PyObject *pModule);
_Success_(return) BOOL VmmPycModule_InitializeType(PyObject *pModule);
_Success_(return) BOOL VmmPycModuleMaps_InitializeType(PyObject *pModule);
_Success_(return) BOOL VmmPycProcess_InitializeType(PyObject *pModule);
_Success_(return) BOOL VmmPycProcessMaps_InitializeType(PyObject *pModule);
_Success_(return) BOOL VmmPycRegHive_InitializeType(PyObject *pModule);
_Success_(return) BOOL VmmPycRegKey_InitializeType(PyObject *pModule);
_Success_(return) BOOL VmmPycRegValue_InitializeType(PyObject *pModule);
_Success_(return) BOOL VmmPycPlugin_InitializeType(PyObject *pModule);
_Success_(return) BOOL VmmPycPhysicalMemory_InitializeType(PyObject *pModule);
_Success_(return) BOOL VmmPycVirtualMemory_InitializeType(PyObject *pModule);
_Success_(return) BOOL VmmPycRegMemory_InitializeType(PyObject *pModule);

PyObj_Pdb* VmmPycPdb_InitializeInternal1(_In_ DWORD dwPID, _In_ QWORD vaModuleBase);
PyObj_Pdb* VmmPycPdb_InitializeInternal2(_In_ LPSTR szModule);
PyObj_Vfs* VmmPycVfs_InitializeInternal();
PyObj_Maps* VmmPycMaps_InitializeInternal();
PyObj_PhysicalMemory* VmmPycPhysicalMemory_InitializeInternal();
PyObj_Kernel* VmmPycKernel_InitializeInternal();
PyObj_Process* VmmPycProcess_InitializeInternal(_In_ DWORD dwPID, _In_ BOOL fVerify);
PyObj_ProcessMaps* VmmPycProcessMaps_InitializeInternal(_In_ DWORD dwPID);
PyObj_VirtualMemory* VmmPycVirtualMemory_InitializeInternal(_In_ DWORD dwPID);
PyObj_Module* VmmPycModule_InitializeInternal(_In_ DWORD dwPID, _In_ PVMMDLL_MAP_MODULEENTRY pe);
PyObj_ModuleMaps* VmmPycModuleMaps_InitializeInternal(_In_ DWORD dwPID, _In_ LPSTR uszModule);
PyObj_RegHive* VmmPycRegHive_InitializeInternal(_In_ PVMMDLL_REGISTRY_HIVE_INFORMATION pInfo);
PyObj_RegMemory* VmmPycRegMemory_InitializeInternal(_In_ QWORD vaCMHive);
PyObj_RegKey* VmmPycRegKey_InitializeInternal(_In_ LPSTR uszFullPathKey, _In_ BOOL fVerify);
PyObj_RegValue* VmmPycRegValue_InitializeInternal(_In_ LPSTR uszFullPathKeyValue, _In_ BOOL fVerify);

PyObject* VmmPyc_MemReadScatter(_In_ DWORD dwPID, _In_ LPSTR szFN, PyObject *args);
PyObject* VmmPyc_MemRead(_In_ DWORD dwPID, _In_ LPSTR szFN, PyObject *args);
PyObject* VmmPyc_MemWrite(_In_ DWORD dwPID, _In_ LPSTR szFN, PyObject *args);

#endif /* __VMMPYC_H__ */
