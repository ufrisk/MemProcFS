// vmmpyc.c : implementation MemProcFS/VMM Python API
//
// (c) Ulf Frisk, 2018-2019
// Author: Ulf Frisk, pcileech@frizk.net
//
#define Py_LIMITED_API 0x03060000
#ifdef _DEBUG
#undef _DEBUG
#include <python.h>
#define _DEBUG
#else
#include <python.h>
#endif
#include <Windows.h>
#include "vmmdll.h"

//-----------------------------------------------------------------------------
// INITIALIZATION FUNCTIONALITY BELOW:
// Choose one way of initialzing the VMM / Memory Process File System.
//-----------------------------------------------------------------------------

// [STR] -> None
static PyObject*
VMMPYC_Initialize(PyObject *self, PyObject *args)
{
    PyObject *pyList, *pyString, **pyBytesDstArgs;
    BOOL result;
    DWORD i, cDstArgs;
    LPSTR *pszDstArgs;
    if(!PyArg_ParseTuple(args, "O!", &PyList_Type, &pyList)) { return NULL; } // borrowed reference
    cDstArgs = (DWORD)PyList_Size(pyList);
    if(cDstArgs == 0) { 
        Py_DECREF(pyList);
        return PyErr_Format(PyExc_RuntimeError, "VMMPYC_Initialize: Required argument list is empty.");
    }
    // allocate & initialize buffer+basic
    pszDstArgs = (LPSTR*)LocalAlloc(LMEM_ZEROINIT, sizeof(LPSTR) * cDstArgs);
    pyBytesDstArgs = (PyObject**)LocalAlloc(LMEM_ZEROINIT, sizeof(PyObject*) * cDstArgs);
    if(!pszDstArgs || !pyBytesDstArgs) {
        Py_DECREF(pyList);
        return PyErr_NoMemory();
    }
    // iterate over # entries and build argument list
    for(i = 0; i < cDstArgs; i++) {
        pyString = PyList_GetItem(pyList, i);   // borrowed reference
        if(!PyUnicode_Check(pyString)) { 
            Py_DECREF(pyList);
            return PyErr_Format(PyExc_RuntimeError, "VMMPYC_Initialize: Argument list contains non string item.");
        }
        pyBytesDstArgs[i] = PyUnicode_AsEncodedString(pyString, NULL, NULL);
        pszDstArgs[i] = pyBytesDstArgs[i] ? PyBytes_AsString(pyBytesDstArgs[i]) : "";

    }
    Py_DECREF(pyList);
    result = VMMDLL_Initialize(cDstArgs, pszDstArgs);
    for(i = 0; i < cDstArgs; i++) {
        Py_XDECREF(pyBytesDstArgs[i]);
    }
    if(!result) { return PyErr_Format(PyExc_RuntimeError, "VMMPYC_Initialize: Initialization of VMM failed."); }
    return Py_BuildValue("s", NULL);    // None returned on success.
}

// () -> None
static PyObject*
VMMPYC_Close(PyObject *self, PyObject *args)
{
    Py_BEGIN_ALLOW_THREADS;
    VMMDLL_Close();
    Py_END_ALLOW_THREADS;
    return Py_BuildValue("s", NULL);    // None returned on success.
}

// (DWORD) -> None
static PyObject*
VMMPYC_Refresh(PyObject *self, PyObject *args)
{
    BOOL result;
    DWORD dwReserved = 0;
    if(!PyArg_ParseTuple(args, "k", &dwReserved)) { return NULL; }
    Py_BEGIN_ALLOW_THREADS;
    result = VMMDLL_Refresh(dwReserved);
    Py_END_ALLOW_THREADS;
    if(!result) { return PyErr_Format(PyExc_RuntimeError, "VMMPYC_Refresh: Refresh failed."); }
    return Py_BuildValue("s", NULL);    // None returned on success.
}



//-----------------------------------------------------------------------------
// CONFIGURATION SETTINGS BELOW:
// Configure the memory process file system or the underlying memory
// acquisition devices.
//-----------------------------------------------------------------------------

// (ULONG64) -> ULONG64
static PyObject*
VMMPYC_ConfigGet(PyObject *self, PyObject *args)
{
    BOOL result;
    ULONG64 fOption, qwValue = 0;
    if(!PyArg_ParseTuple(args, "K", &fOption)) { return NULL; }
    Py_BEGIN_ALLOW_THREADS;
    result = VMMDLL_ConfigGet(fOption, &qwValue);
    Py_END_ALLOW_THREADS;
    if(!result) { return PyErr_Format(PyExc_RuntimeError, "VMMPYC_ConfigGet: Unable to retrieve config value for setting."); }
    return PyLong_FromUnsignedLongLong(qwValue);
}

// (ULONG64, ULONG64) -> None
static PyObject*
VMMPYC_ConfigSet(PyObject *self, PyObject *args)
{
    BOOL result;
    ULONG64 fOption, qwValue = 0;
    if(!PyArg_ParseTuple(args, "KK", &fOption, &qwValue)) { return NULL; }
    Py_BEGIN_ALLOW_THREADS;
    result = VMMDLL_ConfigSet(fOption, qwValue);
    Py_END_ALLOW_THREADS;
    if(!result) { return PyErr_Format(PyExc_RuntimeError, "VMMPYC_ConfigSet: Unable to set config value for setting."); }
    return Py_BuildValue("s", NULL);    // None returned on success.
}



//-----------------------------------------------------------------------------
// VMMPYC C-PYTHON FUNCTIONS BELOW:
//-----------------------------------------------------------------------------

// (DWORD, [STR], (DWORD)) -> [{...}]
static PyObject*
VMMPYC_MemReadScatter(PyObject *self, PyObject *args)
{
    PyObject *pyListSrc, *pyListItemSrc, *pyListDst, *pyDict;
    BOOL result;
    DWORD dwPID, cMEMs, flags = 0;
    ULONG64 i, qwA;
    PMEM_IO_SCATTER_HEADER pMEM, pMEMs;
    PPMEM_IO_SCATTER_HEADER ppMEMs;
    PBYTE pb, pbDataBuffer;
    if(!PyArg_ParseTuple(args, "kO!|k", &dwPID, &PyList_Type, &pyListSrc, &flags)) { return NULL; } // borrowed reference
    cMEMs = (DWORD)PyList_Size(pyListSrc);
    if(cMEMs == 0) { 
        Py_DECREF(pyListSrc);
        return PyList_New(0);
    }
    // allocate & initialize buffer+basic
    pb = LocalAlloc(0, cMEMs * (sizeof(PMEM_IO_SCATTER_HEADER) + sizeof(MEM_IO_SCATTER_HEADER) + 0x1000));
    if(!pb) {
        Py_DECREF(pyListSrc);
        return PyErr_NoMemory();
    }
    ppMEMs = (PPMEM_IO_SCATTER_HEADER)pb;
    pMEMs = (PMEM_IO_SCATTER_HEADER)(pb + cMEMs * sizeof(PMEM_IO_SCATTER_HEADER));
    pbDataBuffer = pb + cMEMs * (sizeof(PMEM_IO_SCATTER_HEADER) + sizeof(MEM_IO_SCATTER_HEADER));
    ZeroMemory(pb, pbDataBuffer - pb);
    // iterate over # entries and build scatter data structure
    for(i = 0; i < cMEMs; i++) {
        pMEM = pMEMs + i;
        pyListItemSrc = PyList_GetItem(pyListSrc, i); // borrowed reference
        if(!pyListItemSrc || !PyLong_Check(pyListItemSrc)) {
            Py_DECREF(pyListSrc);
            LocalFree(pb);
            return PyErr_Format(PyExc_RuntimeError, "VMMPYC_MemReadScatter: Argument list contains non numeric item.");
        }
        qwA = PyLong_AsUnsignedLongLong(pyListItemSrc);
        if(qwA == (ULONG64)-1) {
            Py_DECREF(pyListSrc);
            LocalFree(pb);
            return PyErr_Format(PyExc_RuntimeError, "VMMPYC_MemReadScatter: Argument list contains out-of-range numeric item.");
        }
        pMEM->cbMax = 0x1000;
        pMEM->pb = pbDataBuffer + (i << 12);
        pMEM->qwA = qwA;
        ppMEMs[i] = pMEM;
    }
    Py_DECREF(pyListSrc);
    // call c-dll for vmm
    Py_BEGIN_ALLOW_THREADS;
    result = VMMDLL_MemReadScatter(dwPID, ppMEMs, cMEMs, flags);
    Py_END_ALLOW_THREADS;
    if(!result) {
        LocalFree(pb);
        return PyErr_Format(PyExc_RuntimeError, "VMMPYC_MemReadScatter: Failed.");
    }
    if(!(pyListDst = PyList_New(0))) {
        LocalFree(pb);
        return PyErr_NoMemory();
    }
    for(i = 0; i < cMEMs; i++) {
        pMEM = pMEMs + i;
        if((pyDict = PyDict_New())) {
            PyDict_SetItemString(pyDict, "addr", PyLong_FromUnsignedLongLong(pMEM->qwA));
            PyDict_SetItemString(pyDict, ((dwPID == -1) ? "pa" : "va"), PyLong_FromUnsignedLongLong(pMEM->qwA));
            PyDict_SetItemString(pyDict, "data", PyBytes_FromStringAndSize(pMEM->pb, 0x1000));
            PyDict_SetItemString(pyDict, "size", PyLong_FromUnsignedLong(pMEM->cb));
            PyList_Append(pyListDst, pyDict);
        }
    }
    LocalFree(pb);
    return pyListDst;
}

// (DWORD, ULONG64, DWORD, (ULONG64)) -> PBYTE
static PyObject*
VMMPYC_MemRead(PyObject *self, PyObject *args)
{
    PyObject *pyBytes;
    BOOL result;
    DWORD dwPID, cb, cbRead = 0;
    ULONG64 qwA, flags = 0;
    PBYTE pb;
    if(!PyArg_ParseTuple(args, "kKk|K", &dwPID, &qwA, &cb, &flags)) { return NULL; }
    if(cb > 0x01000000) { return PyErr_Format(PyExc_RuntimeError, "VMMPYC_MemRead: Read larger than maxium supported (0x01000000) bytes requested."); }
    pb = LocalAlloc(0, cb);
    if(!pb) { return PyErr_NoMemory(); }
    Py_BEGIN_ALLOW_THREADS;
    result = VMMDLL_MemReadEx(dwPID, qwA, pb, cb, &cbRead, flags);
    Py_END_ALLOW_THREADS;
    if(!result) { 
        LocalFree(pb);
        return PyErr_Format(PyExc_RuntimeError, "VMMPYC_MemRead: Failed.");
    }
    pyBytes = PyBytes_FromStringAndSize(pb, cbRead);
    LocalFree(pb);
    return pyBytes;
}

// (DWORD, ULONG64, PBYTE) -> None
static PyObject*
VMMPYC_MemWrite(PyObject *self, PyObject *args)
{
    BOOL result;
    DWORD dwPID;
    ULONG64 va;
    PBYTE pb, pbPy;
    DWORD cb;
    if(!PyArg_ParseTuple(args, "kKy#", &dwPID, &va, &pbPy, &cb)) { return NULL; }
    if(cb == 0) {
        return Py_BuildValue("s", NULL);    // zero-byte write is always successful.
    }
    pb = LocalAlloc(0, cb);
    if(!pb) {
        return PyErr_NoMemory();
    }
    memcpy(pb, pbPy, cb);
    Py_BEGIN_ALLOW_THREADS;
    result = VMMDLL_MemWrite(dwPID, va, pb, (DWORD)cb);
    LocalFree(pb);
    Py_END_ALLOW_THREADS;
    if(!result) { return PyErr_Format(PyExc_RuntimeError, "VMMPYC_MemWrite: Failed."); }
    return Py_BuildValue("s", NULL);    // None returned on success.
}

// (DWORD, ULONG64) -> ULONG64
static PyObject*
VMMPYC_MemVirt2Phys(PyObject *self, PyObject *args)
{
    BOOL result;
    DWORD dwPID;
    ULONG64 va, pa;
    if(!PyArg_ParseTuple(args, "kK", &dwPID, &va)) { return NULL; }
    Py_BEGIN_ALLOW_THREADS;
    result = VMMDLL_MemVirt2Phys(dwPID, va, &pa);
    Py_END_ALLOW_THREADS;
    if(!result) { return PyErr_Format(PyExc_RuntimeError, "VMMPYC_MemVirt2Phys: Failed."); }
    return PyLong_FromUnsignedLongLong(pa);
}

// (DWORD, (BOOL)) -> [{...}]
static PyObject*
VMMPYC_ProcessGetMemoryMap(PyObject *self, PyObject *args)
{
    PyObject *pyList, *pyDict;
    BOOL result, fIdentifyModules;
    DWORD dwPID, i;
    ULONG64 cMemMapEntries = 0;
    PVMMDLL_MEMMAP_ENTRY pe, pMemMapEntries = NULL;
    CHAR sz[5];
    if(!PyArg_ParseTuple(args, "k|p", &dwPID, &fIdentifyModules)) { return NULL; }
    if(!(pyList = PyList_New(0))) { return PyErr_NoMemory(); }
    Py_BEGIN_ALLOW_THREADS;
    result =
        VMMDLL_ProcessGetMemoryMap(dwPID, NULL, &cMemMapEntries, fIdentifyModules) &&
        cMemMapEntries &&
        (pMemMapEntries = LocalAlloc(0, cMemMapEntries * sizeof(VMMDLL_MEMMAP_ENTRY))) &&
        VMMDLL_ProcessGetMemoryMap(dwPID, pMemMapEntries, &cMemMapEntries, fIdentifyModules);
    Py_END_ALLOW_THREADS;
    if(!result) { 
        Py_DECREF(pyList);
        LocalFree(pMemMapEntries);
        return PyErr_Format(PyExc_RuntimeError, "VMMPYC_ProcessGetMemoryMap: Failed.");
    }
    for(i = 0; i < cMemMapEntries; i++) {
        if((pyDict = PyDict_New())) {
            pe = pMemMapEntries + i;
            PyDict_SetItemString(pyDict, "va", PyLong_FromUnsignedLongLong(pe->AddrBase));
            PyDict_SetItemString(pyDict, "size", PyLong_FromUnsignedLongLong(pe->cPages << 12));
            PyDict_SetItemString(pyDict, "pages", PyLong_FromUnsignedLongLong(pe->cPages));
            PyDict_SetItemString(pyDict, "wow64", PyBool_FromLong((long)pe->fWoW64));
            PyDict_SetItemString(pyDict, "tag", PyUnicode_FromFormat("%s", pe->szTag));
            PyDict_SetItemString(pyDict, "flags-pte", PyLong_FromUnsignedLongLong(pe->fPage));
            sz[0] = (pe->fPage & VMMDLL_MEMMAP_FLAG_PAGE_NS) ? '-' : 's';
            sz[1] = 'r';
            sz[2] = (pe->fPage & VMMDLL_MEMMAP_FLAG_PAGE_W) ? 'w' : '-';
            sz[3] = (pe->fPage & VMMDLL_MEMMAP_FLAG_PAGE_NX) ? '-' : 'x';
            sz[4] = 0;
            PyDict_SetItemString(pyDict, "flags", PyUnicode_FromFormat("%s", sz));
            PyList_Append(pyList, pyDict);
        }
    }
    LocalFree(pMemMapEntries);
    return pyList;
}

// (DWORD, ULONG64, (DWORD)) -> {}
static PyObject*
VMMPYC_ProcessGetMemoryMapEntry(PyObject *self, PyObject *args)
{
    PyObject *pyDict;
    BOOL result, fIdentifyModules;
    DWORD dwPID;
    ULONG64 va;
    VMMDLL_MEMMAP_ENTRY e;
    CHAR sz[5];
    if(!PyArg_ParseTuple(args, "kK|p", &dwPID, &va, &fIdentifyModules)) { return NULL; }
    if(!(pyDict = PyDict_New())) { return PyErr_NoMemory(); }
    Py_BEGIN_ALLOW_THREADS;
    result = VMMDLL_ProcessGetMemoryMapEntry(dwPID, &e, va, fIdentifyModules);
    Py_END_ALLOW_THREADS;
    if(!result) { 
        Py_DECREF(pyDict);
        return PyErr_Format(PyExc_RuntimeError, "VMMDLL_ProcessGetMemoryMapEntry: Failed.");
    }
    PyDict_SetItemString(pyDict, "va", PyLong_FromUnsignedLongLong(e.AddrBase));
    PyDict_SetItemString(pyDict, "size", PyLong_FromUnsignedLongLong(e.cPages << 12));
    PyDict_SetItemString(pyDict, "pages", PyLong_FromUnsignedLongLong(e.cPages));
    PyDict_SetItemString(pyDict, "wow64", PyBool_FromLong((long)e.fWoW64));
    PyDict_SetItemString(pyDict, "tag", PyUnicode_FromFormat("%s", e.szTag));
    PyDict_SetItemString(pyDict, "flags-pte", PyLong_FromUnsignedLongLong(e.fPage));
    sz[0] = (e.fPage & VMMDLL_MEMMAP_FLAG_PAGE_NS) ? '-' : 's';
    sz[1] = 'r';
    sz[2] = (e.fPage & VMMDLL_MEMMAP_FLAG_PAGE_W) ? 'w' : '-';
    sz[3] = (e.fPage & VMMDLL_MEMMAP_FLAG_PAGE_NX) ? '-' : 'x';
    sz[4] = 0;
    PyDict_SetItemString(pyDict, "flags", PyUnicode_FromFormat("%s", sz));
    return pyDict;
}

// (DWORD) -> [{...}]
static PyObject*
VMMPYC_ProcessGetModuleMap(PyObject *self, PyObject *args)
{
    PyObject *pyList, *pyDict;
    BOOL result;
    DWORD dwPID;
    ULONG64 i, cModuleEntries = 0;
    PVMMDLL_MODULEMAP_ENTRY pe, pModuleEntries = NULL;
    if(!PyArg_ParseTuple(args, "k", &dwPID)) { return NULL; }
    if(!(pyList = PyList_New(0))) { return PyErr_NoMemory(); }
    Py_BEGIN_ALLOW_THREADS;
    result =
        VMMDLL_ProcessGetModuleMap(dwPID, NULL, &cModuleEntries) &&
        cModuleEntries &&
        (pModuleEntries = LocalAlloc(0, cModuleEntries * sizeof(VMMDLL_MODULEMAP_ENTRY))) &&
        VMMDLL_ProcessGetModuleMap(dwPID, pModuleEntries, &cModuleEntries);
    Py_END_ALLOW_THREADS;
    if(!result) {
        Py_DECREF(pyList);
        LocalFree(pModuleEntries);
        return PyErr_Format(PyExc_RuntimeError, "VMMPYC_ProcessGetModuleMap: Failed.");
    }
    for(i = 0; i < cModuleEntries; i++) {
        if((pyDict = PyDict_New())) {
            pe = pModuleEntries + i;
            PyDict_SetItemString(pyDict, "va", PyLong_FromUnsignedLongLong(pe->BaseAddress));
            PyDict_SetItemString(pyDict, "va-entry", PyLong_FromUnsignedLongLong(pe->EntryPoint));
            PyDict_SetItemString(pyDict, "size", PyLong_FromUnsignedLong(pe->SizeOfImage));
            PyDict_SetItemString(pyDict, "wow64", PyBool_FromLong((long)pe->fWoW64));
            PyDict_SetItemString(pyDict, "name", PyUnicode_FromFormat("%s", pe->szName));
            PyList_Append(pyList, pyDict);
        }
    }
    LocalFree(pModuleEntries);
    return pyList;
}

// (DWORD, STR) -> {...}
static PyObject*
VMMPYC_ProcessGetModuleFromName(PyObject *self, PyObject *args)
{
    PyObject *pyDict;
    BOOL result;
    DWORD dwPID;
    LPSTR szModuleName;
    VMMDLL_MODULEMAP_ENTRY e;
    if(!PyArg_ParseTuple(args, "ks", &dwPID, &szModuleName)) { return NULL; }
    if(!(pyDict = PyDict_New())) { return PyErr_NoMemory(); }
    Py_BEGIN_ALLOW_THREADS;
    ZeroMemory(&e, sizeof(VMMDLL_MODULEMAP_ENTRY));
    result = VMMDLL_ProcessGetModuleFromName(dwPID, szModuleName, &e);
    Py_END_ALLOW_THREADS;
    if(!result) { 
        Py_DECREF(pyDict);
        return PyErr_Format(PyExc_RuntimeError, "VMMPYC_ProcessGetModuleFromName: Failed.");
    }
    PyDict_SetItemString(pyDict, "va", PyLong_FromUnsignedLongLong(e.BaseAddress));
    PyDict_SetItemString(pyDict, "va-entry", PyLong_FromUnsignedLongLong(e.EntryPoint));
    PyDict_SetItemString(pyDict, "wow64", PyBool_FromLong((long)e.fWoW64));
    PyDict_SetItemString(pyDict, "size", PyLong_FromUnsignedLong(e.SizeOfImage));
    PyDict_SetItemString(pyDict, "name", PyUnicode_FromFormat("%s", e.szName));
    return pyDict;
}

// (STR) -> DWORD
static PyObject*
VMMPYC_PidGetFromName(PyObject *self, PyObject *args)
{
    BOOL result;
    DWORD dwPID;
    LPSTR szProcessName;
    if(!PyArg_ParseTuple(args, "s", &szProcessName)) { return NULL; }
    Py_BEGIN_ALLOW_THREADS;
    result = VMMDLL_PidGetFromName(szProcessName, &dwPID);
    Py_END_ALLOW_THREADS;
    if(!result) { return PyErr_Format(PyExc_RuntimeError, "VMMPYC_PidGetFromName: Failed."); }
    return PyLong_FromLong(dwPID);
}

// () -> [DWORD]
static PyObject*
VMMPYC_PidList(PyObject *self, PyObject *args)
{
    PyObject *pyList;
    BOOL result;
    ULONG64 cPIDs = 0;
    DWORD i, *pPIDs = NULL;
    if(!(pyList = PyList_New(0))) { return PyErr_NoMemory(); }
    Py_BEGIN_ALLOW_THREADS;
    result =
        VMMDLL_PidList(NULL, &cPIDs) &&
        (pPIDs = LocalAlloc(LMEM_ZEROINIT, cPIDs * sizeof(DWORD))) &&
        VMMDLL_PidList(pPIDs, &cPIDs);
    Py_END_ALLOW_THREADS;
    if(!result) {
        Py_DECREF(pyList);
        LocalFree(pPIDs);
        return PyErr_Format(PyExc_RuntimeError, "VMMPYC_PidList: Failed.");
    }
    for(i = 0; i < cPIDs; i++) {
        PyList_Append(pyList, PyLong_FromUnsignedLong(pPIDs[i]));
    }
    LocalFree(pPIDs);
    return pyList;
}

// (DWORD) -> {...}
static PyObject*
VMMPYC_ProcessGetInformation(PyObject *self, PyObject *args)
{
    PyObject *pyDict;
    BOOL result;
    DWORD dwPID;
    VMMDLL_PROCESS_INFORMATION info;
    SIZE_T cbInfo = sizeof(VMMDLL_PROCESS_INFORMATION);
    if(!PyArg_ParseTuple(args, "k", &dwPID)) { return NULL; }
    if(!(pyDict = PyDict_New())) { return PyErr_NoMemory(); }
    Py_BEGIN_ALLOW_THREADS;
    ZeroMemory(&info, sizeof(VMMDLL_PROCESS_INFORMATION));
    info.magic = VMMDLL_PROCESS_INFORMATION_MAGIC;
    info.wVersion = VMMDLL_PROCESS_INFORMATION_VERSION;
    result = VMMDLL_ProcessGetInformation(dwPID, &info, &cbInfo);
    Py_END_ALLOW_THREADS;
    if(!result) {
        Py_DECREF(pyDict);
        return PyErr_Format(PyExc_RuntimeError, "VMMPYC_ProcessGetInformation: Failed.");
    }
    PyDict_SetItemString(pyDict, "pid", PyLong_FromUnsignedLong(info.dwPID));
    PyDict_SetItemString(pyDict, "pa-dtb", PyLong_FromUnsignedLongLong(info.paDTB));
    PyDict_SetItemString(pyDict, "pa-dtb-user", PyLong_FromUnsignedLongLong(info.paDTB_UserOpt));
    PyDict_SetItemString(pyDict, "state", PyLong_FromUnsignedLong(info.dwState));
    PyDict_SetItemString(pyDict, "tp-memorymodel", PyLong_FromUnsignedLong(info.tpMemoryModel));
    PyDict_SetItemString(pyDict, "tp-system", PyLong_FromUnsignedLong(info.tpSystem));
    PyDict_SetItemString(pyDict, "usermode", PyBool_FromLong(info.fUserOnly));
    PyDict_SetItemString(pyDict, "name", PyUnicode_FromFormat("%s", info.szName));
    switch(info.tpSystem) {
        case VMMDLL_SYSTEM_WINDOWS_X64:
            PyDict_SetItemString(pyDict, "wow64", PyBool_FromLong((long)info.os.win.fWow64));
            PyDict_SetItemString(pyDict, "va-entry", PyLong_FromUnsignedLongLong(info.os.win.vaENTRY));
            PyDict_SetItemString(pyDict, "va-eprocess", PyLong_FromUnsignedLongLong(info.os.win.vaEPROCESS));
            PyDict_SetItemString(pyDict, "va-peb", PyLong_FromUnsignedLongLong(info.os.win.vaPEB));
            PyDict_SetItemString(pyDict, "va-peb32", PyLong_FromUnsignedLongLong(info.os.win.vaPEB32));
            break;
        case VMMDLL_SYSTEM_WINDOWS_X86:
            PyDict_SetItemString(pyDict, "va-entry", PyLong_FromUnsignedLongLong(info.os.win.vaENTRY));
            PyDict_SetItemString(pyDict, "va-eprocess", PyLong_FromUnsignedLongLong(info.os.win.vaEPROCESS));
            PyDict_SetItemString(pyDict, "va-peb", PyLong_FromUnsignedLongLong(info.os.win.vaPEB));
            break;
    }
    return pyDict;
}

// (DWORD, STR) -> [{...}]
static PyObject*
VMMPYC_ProcessGetDirectories(PyObject *self, PyObject *args)
{
    PyObject *pyList, *pyDict;
    BOOL result;
    DWORD i, dwPID, cDirectories;
    PIMAGE_DATA_DIRECTORY pe, pDirectories = NULL;
    LPSTR szModule;
    LPCSTR DIRECTORIES[16] = { "EXPORT", "IMPORT", "RESOURCE", "EXCEPTION", "SECURITY", "BASERELOC", "DEBUG", "ARCHITECTURE", "GLOBALPTR", "TLS", "LOAD_CONFIG", "BOUND_IMPORT", "IAT", "DELAY_IMPORT", "COM_DESCRIPTOR", "RESERVED" };
    if(!PyArg_ParseTuple(args, "ks", &dwPID, &szModule)) { return NULL; }
    if(!(pyList = PyList_New(0))) { return PyErr_NoMemory(); }
    Py_BEGIN_ALLOW_THREADS;
    result =
        (pDirectories = LocalAlloc(0, 16 * sizeof(IMAGE_DATA_DIRECTORY))) &&
        VMMDLL_ProcessGetDirectories(dwPID, szModule, pDirectories, 16, &cDirectories);
    Py_END_ALLOW_THREADS;
    if(!result) {
        Py_DECREF(pyList);
        LocalFree(pDirectories);
        return PyErr_Format(PyExc_RuntimeError, "VMMPYC_ProcessGetDirectories: Failed.");
    }
    for(i = 0; i < 16; i++) {
        if((pyDict = PyDict_New())) {
            pe = pDirectories + i;
            PyDict_SetItemString(pyDict, "i", PyLong_FromUnsignedLong(i));
            PyDict_SetItemString(pyDict, "size", PyLong_FromUnsignedLong(pe->Size));
            PyDict_SetItemString(pyDict, "offset", PyLong_FromUnsignedLong(pe->VirtualAddress));
            PyDict_SetItemString(pyDict, "name", PyUnicode_FromFormat("%s", DIRECTORIES[i]));
            PyList_Append(pyList, pyDict);
        }
    }
    LocalFree(pDirectories);
    return pyList;
}

// (DWORD, STR) -> [{...}]
static PyObject*
VMMPYC_ProcessGetSections(PyObject *self, PyObject *args)
{
    PyObject *pyList, *pyDict;
    BOOL result;
    DWORD i, dwPID, cSections;
    PIMAGE_SECTION_HEADER pe, pSections = NULL;
    LPSTR szModule;
    CHAR szName[9];
    szName[8] = 0;
    if(!PyArg_ParseTuple(args, "ks", &dwPID, &szModule)) { return NULL; }
    if(!(pyList = PyList_New(0))) { return PyErr_NoMemory(); }
    Py_BEGIN_ALLOW_THREADS;
    result =
        VMMDLL_ProcessGetSections(dwPID, szModule, NULL, 0, &cSections) &&
        cSections &&
        (pSections = LocalAlloc(0, cSections * sizeof(IMAGE_SECTION_HEADER))) &&
        VMMDLL_ProcessGetSections(dwPID, szModule, pSections, cSections, &cSections);
    Py_END_ALLOW_THREADS;
    if(!result) {
        Py_DECREF(pyList);
        LocalFree(pSections);
        return PyErr_Format(PyExc_RuntimeError, "VMMPYC_ProcessGetSections: Failed.");
    }
    for(i = 0; i < cSections; i++) {
        if((pyDict = PyDict_New())) {
            pe = pSections + i;
            PyDict_SetItemString(pyDict, "i", PyLong_FromUnsignedLong(i));
            PyDict_SetItemString(pyDict, "Characteristics", PyLong_FromUnsignedLong(pe->Characteristics));
            PyDict_SetItemString(pyDict, "misc-PhysicalAddress", PyLong_FromUnsignedLong(pe->Misc.PhysicalAddress));
            PyDict_SetItemString(pyDict, "misc-VirtualSize", PyLong_FromUnsignedLong(pe->Misc.VirtualSize));
            *(PULONG64)szName = *(PULONG64)pe->Name;
            PyDict_SetItemString(pyDict, "Name", PyUnicode_FromFormat("%s", szName));
            PyDict_SetItemString(pyDict, "NumberOfLinenumbers", PyLong_FromUnsignedLong(pe->NumberOfLinenumbers));
            PyDict_SetItemString(pyDict, "NumberOfRelocations", PyLong_FromUnsignedLong(pe->NumberOfRelocations));
            PyDict_SetItemString(pyDict, "PointerToLinenumbers", PyLong_FromUnsignedLong(pe->PointerToLinenumbers));
            PyDict_SetItemString(pyDict, "PointerToRawData", PyLong_FromUnsignedLong(pe->PointerToRawData));
            PyDict_SetItemString(pyDict, "PointerToRelocations", PyLong_FromUnsignedLong(pe->PointerToRelocations));
            PyDict_SetItemString(pyDict, "SizeOfRawData", PyLong_FromUnsignedLong(pe->SizeOfRawData));
            PyDict_SetItemString(pyDict, "VirtualAddress", PyLong_FromUnsignedLong(pe->VirtualAddress));
            PyList_Append(pyList, pyDict);
        }
    }
    LocalFree(pSections);
    return pyList;
}

// (DWORD, STR) -> [{...}]
static PyObject*
VMMPYC_ProcessGetEAT(PyObject *self, PyObject *args)
{
    PyObject *pyList, *pyDict;
    BOOL result;
    DWORD i, dwPID, cEATs;
    PVMMDLL_EAT_ENTRY pe, pEATs = NULL;
    LPSTR szModule;
    if(!PyArg_ParseTuple(args, "ks", &dwPID, &szModule)) { return NULL; }
    if(!(pyList = PyList_New(0))) { return PyErr_NoMemory(); }
    Py_BEGIN_ALLOW_THREADS;
    result =
        VMMDLL_ProcessGetEAT(dwPID, szModule, NULL, 0, &cEATs) &&
        cEATs &&
        (pEATs = LocalAlloc(0, cEATs * sizeof(VMMDLL_EAT_ENTRY))) &&
        VMMDLL_ProcessGetEAT(dwPID, szModule, pEATs, cEATs, &cEATs);
    Py_END_ALLOW_THREADS;
    if(!result) {
        Py_DECREF(pyList);
        LocalFree(pEATs);
        return PyErr_Format(PyExc_RuntimeError, "VMMPYC_ProcessGetEAT: Failed.");
    }
    for(i = 0; i < cEATs; i++) {
        if((pyDict = PyDict_New())) {
            pe = pEATs + i;
            PyDict_SetItemString(pyDict, "i", PyLong_FromUnsignedLong(i));
            PyDict_SetItemString(pyDict, "va", PyLong_FromUnsignedLongLong(pe->vaFunction));
            PyDict_SetItemString(pyDict, "offset", PyLong_FromUnsignedLong(pe->vaFunctionOffset));
            PyDict_SetItemString(pyDict, "fn", PyUnicode_FromFormat("%s", pe->szFunction));
            PyList_Append(pyList, pyDict);
        }
    }
    LocalFree(pEATs);
    return pyList;
}

// (DWORD, STR) -> [{...}]
static PyObject*
VMMPYC_ProcessGetIAT(PyObject *self, PyObject *args)
{
    PyObject *pyList, *pyDict;
    BOOL result;
    DWORD i, dwPID, cIATs;
    PVMMDLL_IAT_ENTRY pe, pIATs = NULL;
    LPSTR szModule;
    if(!PyArg_ParseTuple(args, "ks", &dwPID, &szModule)) { return NULL; }
    if(!(pyList = PyList_New(0))) { return PyErr_NoMemory(); }
    Py_BEGIN_ALLOW_THREADS;
    result =
        VMMDLL_ProcessGetIAT(dwPID, szModule, NULL, 0, &cIATs) &&
        cIATs &&
        (pIATs = LocalAlloc(0, cIATs * sizeof(VMMDLL_IAT_ENTRY))) &&
        VMMDLL_ProcessGetIAT(dwPID, szModule, pIATs, cIATs, &cIATs);
    Py_END_ALLOW_THREADS;
    if(!result) {
        Py_DECREF(pyList);
        LocalFree(pIATs);
        return PyErr_Format(PyExc_RuntimeError, "VMMPYC_ProcessGetIAT: Failed.");
    }
    for(i = 0; i < cIATs; i++) {
        if((pyDict = PyDict_New())) {
            pe = pIATs + i;
            PyDict_SetItemString(pyDict, "i", PyLong_FromUnsignedLong(i));
            PyDict_SetItemString(pyDict, "va", PyLong_FromUnsignedLongLong(pe->vaFunction));
            PyDict_SetItemString(pyDict, "fn", PyUnicode_FromFormat("%s", pe->szFunction));
            PyDict_SetItemString(pyDict, "dll", PyUnicode_FromFormat("%s", pe->szModule));
            PyList_Append(pyList, pyDict);
        }
    }
    LocalFree(pIATs);
    return pyList;
}

// (PBYTE, (DWORD)) -> STR
static PyObject*
VMMPYC_UtilFillHexAscii(PyObject *self, PyObject *args)
{
    PyObject *pyString;
    DWORD cb, cbInitialOffset = 0, csz = 0;
    PBYTE pb, pbPy;
    LPSTR sz = NULL;
    BOOL result;
    if(!PyArg_ParseTuple(args, "y#|k", &pbPy, &cb, &cbInitialOffset)) { return NULL; }
    if(cb == 0) {
        return PyUnicode_FromFormat("%s", "");
    }
    pb = LocalAlloc(0, cb);
    if(!pb) {
        return PyErr_NoMemory();
    }
    memcpy(pb, pbPy, cb);
    Py_BEGIN_ALLOW_THREADS;
    result =
        VMMDLL_UtilFillHexAscii(pb, cb, cbInitialOffset, NULL, &csz) &&
        csz &&
        (sz = (LPSTR)LocalAlloc(0, csz)) &&
        VMMDLL_UtilFillHexAscii(pb, cb, cbInitialOffset, sz, &csz);
    LocalFree(pb);
    Py_END_ALLOW_THREADS;
    if(!result || !sz) {
        LocalFree(sz);
        return PyErr_Format(PyExc_RuntimeError, "VMMPYC_UtilFillHexAscii: Failed.");
    }
    pyString = PyUnicode_FromFormat("%s", sz);
    LocalFree(sz);
    return pyString;
}

// (STR, DWORD, (ULONG64)) -> PBYTE
static PyObject*
VMMPYC_VfsRead(PyObject *self, PyObject *args)
{
    PyObject *pyBytes;
    NTSTATUS nt;
    DWORD i, cb, cbRead = 0;
    ULONG64 cbOffset = 0;
    PBYTE pb;
    LPSTR szFileName;
    WCHAR wszFileName[MAX_PATH];
    if(!PyArg_ParseTuple(args, "sk|K", &szFileName, &cb, &cbOffset)) { return NULL; }
    if(cb > 0x01000000) { return PyErr_Format(PyExc_RuntimeError, "VMMPYC_VfsRead: Read larger than maxium supported (0x01000000) bytes requested."); }
    {   // char* -> wchar*
        for(i = 0; i < MAX_PATH - 1; i++) {
            wszFileName[i] = szFileName[i];
            if(0 == szFileName[i]) { break; }
        }
        wszFileName[MAX_PATH - 1] = 0;
    }
    pb = LocalAlloc(0, cb);
    if(!pb) { return PyErr_NoMemory(); }
    Py_BEGIN_ALLOW_THREADS;
    nt = VMMDLL_VfsRead(wszFileName, pb, cb, &cbRead, cbOffset);
    Py_END_ALLOW_THREADS;
    if(nt != VMMDLL_STATUS_SUCCESS) {
        LocalFree(pb);
        return PyErr_Format(PyExc_RuntimeError, "VMMPYC_VfsRead: Failed.");
    }
    pyBytes = PyBytes_FromStringAndSize(pb, cbRead);
    LocalFree(pb);
    return pyBytes;
}

// (STR, PBYTE, (ULONG64)) -> None
static PyObject*
VMMPYC_VfsWrite(PyObject *self, PyObject *args)
{
    BOOL result;
    DWORD i, cb, cbWritten;
    ULONG64 cbOffset;
    PBYTE pb, pbPy;
    LPSTR szFileName;
    WCHAR wszFileName[MAX_PATH];
    if(!PyArg_ParseTuple(args, "sy#|K", &szFileName, &pbPy, &cb, &cbOffset)) { return NULL; }
    if(cb == 0) {
        return Py_BuildValue("s", NULL);    // zero-byte write is always successful.
    }
    {   // char* -> wchar*
        for(i = 0; i < MAX_PATH - 1; i++) {
            wszFileName[i] = szFileName[i];
            if(0 == szFileName[i]) { break; }
        }
        wszFileName[MAX_PATH - 1] = 0;
    }
    pb = LocalAlloc(0, cb);
    if(!pb) {
        return PyErr_NoMemory();
    }
    memcpy(pb, pbPy, cb);
    Py_BEGIN_ALLOW_THREADS;
    result = (VMMDLL_STATUS_SUCCESS == VMMDLL_VfsWrite(wszFileName, pb, cb, &cbWritten, cbOffset));
    LocalFree(pb);
    Py_END_ALLOW_THREADS;
    if(!result) { return PyErr_Format(PyExc_RuntimeError, "VMMPYC_VfsWrite: Failed."); }
    return Py_BuildValue("s", NULL);    // None returned on success.
}

// (DWORD, STR, STR) -> ULONG64
static PyObject*
VMMPYC_ProcessGetProcAddress(PyObject *self, PyObject *args)
{
    ULONG64 va;
    DWORD dwPID;
    LPSTR szModuleName, szProcName;
    if(!PyArg_ParseTuple(args, "kss", &dwPID, &szModuleName, &szProcName)) { return NULL; }
    Py_BEGIN_ALLOW_THREADS;
    va = VMMDLL_ProcessGetProcAddress(dwPID, szModuleName, szProcName);
    Py_END_ALLOW_THREADS;
    return va ?
        PyLong_FromUnsignedLongLong(va) :
        PyErr_Format(PyExc_RuntimeError, "VMMPYC_ProcessGetProcAddress: Failed.");
}

// (DWORD, STR) -> ULONG64
static PyObject*
VMMPYC_ProcessGetModuleBase(PyObject *self, PyObject *args)
{
    ULONG64 va;
    DWORD dwPID;
    LPSTR szModuleName;
    if(!PyArg_ParseTuple(args, "ks", &dwPID, &szModuleName)) { return NULL; }
    Py_BEGIN_ALLOW_THREADS;
    va = VMMDLL_ProcessGetModuleBase(dwPID, szModuleName);
    Py_END_ALLOW_THREADS;
    return va ?
        PyLong_FromUnsignedLongLong(va) :
        PyErr_Format(PyExc_RuntimeError, "VMMPYC_ProcessGetModuleBase: Failed.");
}

// (DWORD, STR, STR) -> {...}
static PyObject*
VMMPYC_WinGetThunkInfoEAT(PyObject *self, PyObject *args)
{
    PyObject *pyDict;
    BOOL result;
    DWORD dwPID;
    VMMDLL_WIN_THUNKINFO_EAT oThunkInfoEAT = { 0 };
    LPSTR szModuleName, szExportFunctionName;
    if(!PyArg_ParseTuple(args, "kss", &dwPID, &szModuleName, &szExportFunctionName)) { return NULL; }
    Py_BEGIN_ALLOW_THREADS;
    result = VMMDLL_WinGetThunkInfoEAT(dwPID, szModuleName, szExportFunctionName, &oThunkInfoEAT);
    Py_END_ALLOW_THREADS;
    if(!result || !oThunkInfoEAT.fValid) {
        return PyErr_Format(PyExc_RuntimeError, "VMMPYC_WinGetThunkInfoEAT: Failed.");
    }
    pyDict = PyDict_New();
    if(pyDict) {
        PyDict_SetItemString(pyDict, "vaFunction", PyLong_FromUnsignedLongLong(oThunkInfoEAT.vaFunction));
        PyDict_SetItemString(pyDict, "valueThunk", PyLong_FromUnsignedLong(oThunkInfoEAT.valueThunk));
        PyDict_SetItemString(pyDict, "vaNameFunction", PyLong_FromUnsignedLongLong(oThunkInfoEAT.vaNameFunction));
        PyDict_SetItemString(pyDict, "vaThunk", PyLong_FromUnsignedLongLong(oThunkInfoEAT.vaThunk));
    }
    return pyDict;
}

// (DWORD, STR, STR, STR) -> {...}
static PyObject*
VMMPYC_WinGetThunkInfoIAT(PyObject *self, PyObject *args)
{
    PyObject *pyDict;
    BOOL result;
    DWORD dwPID;
    VMMDLL_WIN_THUNKINFO_IAT oThunkInfoIAT = { 0 };
    LPSTR szModuleName, szImportModuleName, szImportFunctionName;
    if(!PyArg_ParseTuple(args, "ksss", &dwPID, &szModuleName, &szImportModuleName, &szImportFunctionName)) { return NULL; }
    Py_BEGIN_ALLOW_THREADS;
    result = VMMDLL_WinGetThunkInfoIAT(dwPID, szModuleName, szImportModuleName, szImportFunctionName, &oThunkInfoIAT);
    Py_END_ALLOW_THREADS;
    if(!result || !oThunkInfoIAT.fValid) {
        return PyErr_Format(PyExc_RuntimeError, "VMMPYC_WinGetThunkInfoEAT: Failed.");
    }
    pyDict = PyDict_New();
    if(pyDict) {
        PyDict_SetItemString(pyDict, "32", PyBool_FromLong(oThunkInfoIAT.f32 ? 1 : 0));
        PyDict_SetItemString(pyDict, "vaFunction", PyLong_FromUnsignedLongLong(oThunkInfoIAT.vaFunction));
        PyDict_SetItemString(pyDict, "vaNameFunction", PyLong_FromUnsignedLongLong(oThunkInfoIAT.vaNameFunction));
        PyDict_SetItemString(pyDict, "vaNameModule", PyLong_FromUnsignedLongLong(oThunkInfoIAT.vaNameModule));
        PyDict_SetItemString(pyDict, "vaThunk", PyLong_FromUnsignedLongLong(oThunkInfoIAT.vaThunk));
    }
    return pyDict;
}

// (ULONG64, DWORD) -> {b: PBYTE, c: DWORD}
static PyObject*
VMMPYC_WinMemCompression_DecompressPage(PyObject *self, PyObject *args)
{
    PyObject *pyDict;
    BOOL result;
    DWORD cb, cbCompressed;
    ULONG64 va;
    BYTE pbDecompressed[0x1000] = { 0 };
    if(!PyArg_ParseTuple(args, "Kk", &va, &cb)) { return NULL; }
    Py_BEGIN_ALLOW_THREADS;
    result = VMMDLL_WinMemCompression_DecompressPage(va, cb, pbDecompressed, &cbCompressed);
    Py_END_ALLOW_THREADS;
    if(!result) {
        return PyErr_Format(PyExc_RuntimeError, "VMMPYC_WinMemCompression_DecompressPage: Failed.");
    }
    pyDict = PyDict_New();
    if(pyDict) {
        PyDict_SetItemString(pyDict, "c", PyLong_FromUnsignedLong(cbCompressed));
        PyDict_SetItemString(pyDict, "b", PyBytes_FromStringAndSize(pbDecompressed, 0x1000));
    }
    return pyDict;
}



typedef struct tdVMMPYC_VFSLIST {
    struct tdVMMPYC_VFSLIST *FLink;
    CHAR szName[MAX_PATH];
    BOOL fIsDir;
    ULONG64 qwSize;
} VMMPYC_VFSLIST, *PVMMPYC_VFSLIST;


VOID VMMPYC_VfsList_AddInternal(_Inout_ HANDLE h, _In_ LPSTR szName, _In_ ULONG64 size, _In_ BOOL fIsDirectory)
{
    PVMMPYC_VFSLIST *ppE = (PVMMPYC_VFSLIST*)h;
    PVMMPYC_VFSLIST pE;
    if((pE = LocalAlloc(0, sizeof(VMMPYC_VFSLIST)))) {
        strncpy_s(pE->szName, MAX_PATH - 1, szName, _TRUNCATE);
        pE->fIsDir = fIsDirectory;
        pE->qwSize = size;
        pE->FLink = *ppE;
        *ppE = pE;
    }
}

VOID VMMPYC_VfsList_AddFile(_Inout_ HANDLE h, _In_ LPSTR szName, _In_ ULONG64 size, _In_ PVOID pvReserved)
{
    VMMPYC_VfsList_AddInternal(h, szName, size, FALSE);
}

VOID VMMPYC_VfsList_AddDirectory(_Inout_ HANDLE h, _In_ LPSTR szName, _In_ PVOID pvReserved)
{
    VMMPYC_VfsList_AddInternal(h, szName, 0, TRUE);
}


// (STR) -> {{...}}
static PyObject*
VMMPYC_VfsList(PyObject *self, PyObject *args)
{
    PyObject *pyDict, *PyDict_Attr;
    BOOL result;
    DWORD i;
    LPSTR szPath;
    WCHAR wszPath[MAX_PATH];
    VMMDLL_VFS_FILELIST hFileList;
    PVMMPYC_VFSLIST pE = NULL, pE_Next;
    if(!PyArg_ParseTuple(args, "s", &szPath)) { return NULL; }
    if(!(pyDict = PyDict_New())) { return PyErr_NoMemory(); }
    Py_BEGIN_ALLOW_THREADS;
    {   // char* -> wchar*
        for(i = 0; i < MAX_PATH - 1; i++) {
            wszPath[i] = szPath[i];
            if(0 == szPath[i]) { break; }
        }
        wszPath[MAX_PATH - 1] = 0;
    }
    hFileList.h = &pE;
    hFileList.pfnAddFile = VMMPYC_VfsList_AddFile;
    hFileList.pfnAddDirectory = VMMPYC_VfsList_AddDirectory;
    result = VMMDLL_VfsList(wszPath, &hFileList);
    pE = *(PVMMPYC_VFSLIST*)hFileList.h;
    Py_END_ALLOW_THREADS;
    while(pE) {
        if((PyDict_Attr = PyDict_New())) {
            PyDict_SetItemString(PyDict_Attr, "f_isdir", PyBool_FromLong(pE->fIsDir ? 1 : 0));
            PyDict_SetItemString(PyDict_Attr, "size", PyLong_FromUnsignedLongLong(pE->qwSize));
            PyDict_SetItemString(pyDict, pE->szName, PyDict_Attr);
        }
        pE_Next = pE->FLink;
        LocalFree(pE);
        pE = pE_Next;
    }
    if(!result) {
        Py_DECREF(pyDict);
        return PyErr_Format(PyExc_RuntimeError, "VMMPYC_VfsList: Failed.");
    }
    return pyDict;
}

//-----------------------------------------------------------------------------
// PY2C common functionality below:
//-----------------------------------------------------------------------------

static PyMethodDef VMMPYC_EmbMethods[] = {
    {"VMMPYC_Initialize", VMMPYC_Initialize, METH_VARARGS, "Initialize the VMM"},
    {"VMMPYC_Close", VMMPYC_Close, METH_VARARGS, "Try close the VMM"},
    {"VMMPYC_Refresh", VMMPYC_Refresh, METH_VARARGS, "Force refresh the VMM (process listings and caches)."},
    {"VMMPYC_ConfigGet", VMMPYC_ConfigGet, METH_VARARGS, "Get a device specific option value."},
    {"VMMPYC_ConfigSet", VMMPYC_ConfigSet, METH_VARARGS, "Set a device specific option value."},
    {"VMMPYC_MemReadScatter", VMMPYC_MemReadScatter, METH_VARARGS, "Read multiple 4kB page sized and aligned chunks of memory given as an address list."},
    {"VMMPYC_MemRead", VMMPYC_MemRead, METH_VARARGS, "Read memory."},
    {"VMMPYC_MemWrite", VMMPYC_MemWrite, METH_VARARGS, "Write memory."},
    {"VMMPYC_MemVirt2Phys", VMMPYC_MemVirt2Phys, METH_VARARGS, "Translate a virtual address into a physical address."},
    {"VMMPYC_PidGetFromName", VMMPYC_PidGetFromName, METH_VARARGS, "Locate a process by name and return the PID."},
    {"VMMPYC_PidList", VMMPYC_PidList, METH_VARARGS, "List all process PIDs."},
    {"VMMPYC_ProcessGetMemoryMap", VMMPYC_ProcessGetMemoryMap, METH_VARARGS, "Retrieve the memory map for a given process."},
    {"VMMPYC_ProcessGetMemoryMapEntry", VMMPYC_ProcessGetMemoryMapEntry, METH_VARARGS, "Retrieve a single memory map entry for a given process and virtual address."},
    {"VMMPYC_ProcessGetModuleMap", VMMPYC_ProcessGetModuleMap, METH_VARARGS, "Retrieve the module map for a given process."},
    {"VMMPYC_ProcessGetModuleFromName", VMMPYC_ProcessGetModuleFromName, METH_VARARGS, "Locate a module by name and return its information."},
    {"VMMPYC_ProcessGetInformation", VMMPYC_ProcessGetInformation, METH_VARARGS, "Retrieve process information for a specific process."},
    {"VMMPYC_ProcessGetDirectories", VMMPYC_ProcessGetDirectories, METH_VARARGS, "Retrieve the data directories for a specific process and module."},
    {"VMMPYC_ProcessGetSections", VMMPYC_ProcessGetSections, METH_VARARGS, "Retrieve the sections for a specific process and module."},
    {"VMMPYC_ProcessGetEAT", VMMPYC_ProcessGetEAT, METH_VARARGS, "Retrieve the export address table (EAT) for a specific process and module."},
    {"VMMPYC_ProcessGetIAT", VMMPYC_ProcessGetIAT, METH_VARARGS, "Retrieve the import address table (IAT) for a specific process and module."},
    {"VMMPYC_ProcessGetProcAddress", VMMPYC_ProcessGetProcAddress, METH_VARARGS, "Retrieve the proc address of a given module!function."},
    {"VMMPYC_ProcessGetModuleBase", VMMPYC_ProcessGetModuleBase, METH_VARARGS, "Retrieve the module base address given a module."},
    {"VMMPYC_WinGetThunkInfoEAT", VMMPYC_WinGetThunkInfoEAT, METH_VARARGS, "Retrieve information about the export address table (EAT) thunk. (useful for patching)."},
    {"VMMPYC_WinGetThunkInfoIAT", VMMPYC_WinGetThunkInfoIAT, METH_VARARGS, "Retrieve information about the import address table (IAT) thunk. (useful for patching)."},
    {"VMMPYC_VfsRead", VMMPYC_VfsRead, METH_VARARGS, "Read from a file in the virtual file system."},
    {"VMMPYC_VfsWrite", VMMPYC_VfsWrite, METH_VARARGS, "Write to a file in the virtual file system."},
    {"VMMPYC_VfsList", VMMPYC_VfsList, METH_VARARGS, "List files and folder for a specific directory in the Virutal File System."},
    {"VMMPYC_WinMemCompression_DecompressPage", VMMPYC_WinMemCompression_DecompressPage, METH_VARARGS, "Decompress compressed memory in the MemCompression process (if any)."},
    {"VMMPYC_UtilFillHexAscii", VMMPYC_UtilFillHexAscii, METH_VARARGS, "Convert a bytes object into a human readable 'memory dump' style type of string."},
    {NULL, NULL, 0, NULL}
};

static PyModuleDef VMMPYC_EmbModule = {
    PyModuleDef_HEAD_INIT, "vmmpyc", NULL, -1, VMMPYC_EmbMethods,
    NULL, NULL, NULL, NULL
};

__declspec(dllexport)
PyObject* PyInit_vmmpyc(void)
{
    return PyModule_Create(&VMMPYC_EmbModule);
}
