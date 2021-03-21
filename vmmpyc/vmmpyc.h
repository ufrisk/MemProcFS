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
#include <ws2tcpip.h>
#include <Windows.h>
#include <vmmdll.h>

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
    WCHAR wszText[32];
    WCHAR wszFullName[64];
} PyObj_Module;

typedef struct tdPyObj_ModuleMaps {
    PyObject_HEAD
    BOOL fValid;
    DWORD dwPID;
    WCHAR wszModule[32];
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
    WCHAR wszPath[MAX_PATH];
    QWORD ftLastWrite;
} PyObj_RegKey;

typedef struct tdPyObj_RegValue {
    PyObject_HEAD
    BOOL fValid;
    PyObject *pyName;   // unicode object
    WCHAR wszPath[MAX_PATH];
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

inline int PyDict_SetItemDWORD_DECREF(PyObject *dp, DWORD key, PyObject *item)
{
    PyObject *pyObjectKey = PyLong_FromUnsignedLong(key);
    int i = PyDict_SetItem(dp, pyObjectKey, item);
    Py_XDECREF(pyObjectKey);
    Py_XDECREF(item);
    return i;
}

inline int PyDict_SetItemString_DECREF(PyObject *dp, const char *key, PyObject *item)
{
    int i = PyDict_SetItemString(dp, key, item);
    Py_XDECREF(item);
    return i;
}

inline int PyDict_SetItemUnicode_DECREF(PyObject *dp, PyObject *key_nodecref, PyObject *item)
{
    int i = PyDict_SetItem(dp, key_nodecref, item);
    Py_XDECREF(item);
    return i;
}

inline int PyList_Append_DECREF(PyObject *dp, PyObject *item)
{
    int i = PyList_Append(dp, item);
    Py_XDECREF(item);
    return i;
}

VOID Util_FileTime2String(_In_ QWORD ft, _Out_writes_(24) LPSTR szTime);

/*
* Return the sub-string after the last '\' character in the wsz NULL terminated
* string. If no '\' is found original wsz string is returned. The returned data
* must not be free'd and is only valid as long as the wsz parameter is valid.
* -- sz/wsz
* -- return
*/
LPWSTR Util_PathSplitLastW(_In_ LPWSTR wsz);

/*
* Split the string wsz into two at the last backslash which is removed. Ex:
* wsz: XXX\\YYY\\ZZZ\\AAA -> wszPath: XXX\\YYY\\ZZZ + return: AAA
* -- wsz
* -- wszPath
* -- return = NULL if no split is found.
*/
LPWSTR Util_PathFileSplitW(_In_ LPWSTR wsz, _Out_writes_(MAX_PATH) LPWSTR wszPath);

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
PyObj_ModuleMaps* VmmPycModuleMaps_InitializeInternal(_In_ DWORD dwPID, _In_ LPWSTR wszModule);
PyObj_RegHive* VmmPycRegHive_InitializeInternal(_In_ PVMMDLL_REGISTRY_HIVE_INFORMATION pInfo);
PyObj_RegMemory* VmmPycRegMemory_InitializeInternal(_In_ QWORD vaCMHive);
PyObj_RegKey* VmmPycRegKey_InitializeInternal(_In_ LPWSTR wszFullPathKey, _In_ BOOL fVerify);
PyObj_RegValue* VmmPycRegValue_InitializeInternal(_In_ LPWSTR wszFullPathKeyValue, _In_ BOOL fVerify);

PyObject* VmmPyc_MemReadScatter(_In_ DWORD dwPID, _In_ LPSTR szFN, PyObject *args);
PyObject* VmmPyc_MemRead(_In_ DWORD dwPID, _In_ LPSTR szFN, PyObject *args);
PyObject* VmmPyc_MemWrite(_In_ DWORD dwPID, _In_ LPSTR szFN, PyObject *args);

#endif /* __VMMPYC_H__ */
