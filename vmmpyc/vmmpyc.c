// vmmpyc.c : implementation MemProcFS/VMM Python API
//
// (c) Ulf Frisk, 2018-2021
// Author: Ulf Frisk, pcileech@frizk.net
//
#include "vmmpyc.h"

//-----------------------------------------------------------------------------
// GENERAL READ/WRITE FUNCTIONS USED BY BASE VMM (PHYSICAL) AND PROCESS (VIRTUAL)
//-----------------------------------------------------------------------------

// ([DWORD], (DWORD)) -> [{...}]
PyObject* VmmPyc_MemReadScatter(_In_ DWORD dwPID, _In_ LPSTR szFN, PyObject *args)
{
    PyObject *pyListSrc, *pyListItemSrc, *pyListDst, *pyDict;
    BOOL result;
    DWORD cMEMs, flags = 0;
    ULONG64 i;
    PMEM_SCATTER pMEM;
    PPMEM_SCATTER ppMEMs = NULL;
    if(!PyArg_ParseTuple(args, "O!|k", &PyList_Type, &pyListSrc, &flags)) { // borrowed reference
        return PyErr_Format(PyExc_RuntimeError, "%s: Illegal argument.", szFN);
    }
    cMEMs = (DWORD)PyList_Size(pyListSrc);
    // allocate
    if((cMEMs == 0) || !LcAllocScatter1(cMEMs, &ppMEMs)) {
        return PyList_New(0);
    }
    // iterate over # entries and build scatter data structure
    for(i = 0; i < cMEMs; i++) {
        pMEM = ppMEMs[i];
        pyListItemSrc = PyList_GetItem(pyListSrc, i); // borrowed reference
        if(!pyListItemSrc || !PyLong_Check(pyListItemSrc)) {
            LcMemFree(ppMEMs);
            return PyErr_Format(PyExc_RuntimeError, "%s: Argument list contains non numeric item.", szFN);
        }
        pMEM->qwA = PyLong_AsUnsignedLongLong(pyListItemSrc);
    }
    // call c-dll for vmm
    Py_BEGIN_ALLOW_THREADS;
    result = VMMDLL_MemReadScatter(dwPID, ppMEMs, cMEMs, flags);
    Py_END_ALLOW_THREADS;
    if(!result) {
        LcMemFree(ppMEMs);
        return PyErr_Format(PyExc_RuntimeError, "%s: Failed.", szFN);
    }
    if(!(pyListDst = PyList_New(0))) {
        LcMemFree(ppMEMs);
        return PyErr_NoMemory();
    }
    for(i = 0; i < cMEMs; i++) {
        pMEM = ppMEMs[i];
        if((pyDict = PyDict_New())) {
            PyDict_SetItemString_DECREF(pyDict, "addr", PyLong_FromUnsignedLongLong(pMEM->qwA));
            PyDict_SetItemString_DECREF(pyDict, ((dwPID == 0xffffffff) ? "pa" : "va"), PyLong_FromUnsignedLongLong(pMEM->qwA));
            PyDict_SetItemString_DECREF(pyDict, "data", PyBytes_FromStringAndSize((const char *)pMEM->pb, 0x1000));
            PyDict_SetItemString_DECREF(pyDict, "size", PyLong_FromUnsignedLong(pMEM->cb));
            PyList_Append_DECREF(pyListDst, pyDict);
        }
    }
    LcMemFree(ppMEMs);
    return pyListDst;
}

// (ULONG64, DWORD, (ULONG64)) -> PBYTE
PyObject* VmmPyc_MemRead(_In_ DWORD dwPID, _In_ LPSTR szFN, PyObject *args)
{
    PyObject *pyBytes;
    BOOL result;
    PBYTE pb;
    DWORD cb, cbRead = 0;
    ULONG64 qwA, flags = 0;
    if(!PyArg_ParseTuple(args, "Kk|K",  &qwA, &cb, &flags)) {
        return PyErr_Format(PyExc_RuntimeError, "%s: Illegal argument.", szFN);
    }
    pb = LocalAlloc(0, cb);
    if(!pb) { return PyErr_NoMemory(); }
    Py_BEGIN_ALLOW_THREADS;
    result = VMMDLL_MemReadEx(dwPID, qwA, pb, cb, &cbRead, flags);
    Py_END_ALLOW_THREADS;
    if(!result) {
        LocalFree(pb);
        return PyErr_Format(PyExc_RuntimeError, "%s: Failed.", szFN);
    }
    pyBytes = PyBytes_FromStringAndSize((const char *)pb, cbRead);
    LocalFree(pb);
    return pyBytes;
}

// (ULONG64, PBYTE) -> None
PyObject* VmmPyc_MemWrite(_In_ DWORD dwPID, _In_ LPSTR szFN, PyObject *args)
{
    BOOL result;
    ULONG64 va;
    DWORD cb;
    PBYTE pb;
    if(!PyArg_ParseTuple(args, "Ky#", &dwPID, &va, &pb, &cb)) {
        return PyErr_Format(PyExc_RuntimeError, "%s: Illegal argument.", szFN);
    }
    if(cb == 0) {
        return Py_BuildValue("s", NULL);    // zero-byte write is always successful.
    }
    Py_BEGIN_ALLOW_THREADS;
    result = VMMDLL_MemWrite(dwPID, va, pb, (DWORD)cb);
    Py_END_ALLOW_THREADS;
    if(!result) { return PyErr_Format(PyExc_RuntimeError, "%s: Failed.", szFN); }
    return Py_BuildValue("s", NULL);    // None returned on success.
}



//-----------------------------------------------------------------------------
// PY2C common functionality below:
//-----------------------------------------------------------------------------

static PyMethodDef VMMPYC_EmbMethods[] = {
    {NULL, NULL, 0, NULL}
};

static PyModuleDef VMMPYC_EmbModule = {
    PyModuleDef_HEAD_INIT, "vmmpyc", NULL, -1, VMMPYC_EmbMethods,
    NULL, NULL, NULL, NULL
};

EXPORTED_FUNCTION
PyObject* PyInit_vmmpyc(void)
{
    DWORD i;
    PyObject *pPyModule;
    BOOL(*pfnTYPE_INITIALIZERS[])(PyObject*) = {
#ifdef _WIN32
        VmmPycPlugin_InitializeType,
#endif /* _WIN32 */
        VmmPycPhysicalMemory_InitializeType,
        VmmPycVirtualMemory_InitializeType, VmmPycRegMemory_InitializeType,
        VmmPycRegHive_InitializeType, VmmPycRegKey_InitializeType, VmmPycRegValue_InitializeType,
        VmmPycProcess_InitializeType, VmmPycProcessMaps_InitializeType,
        VmmPycModule_InitializeType, VmmPycModuleMaps_InitializeType,
        VmmPycKernel_InitializeType, VmmPycMaps_InitializeType,
        VmmPycPdb_InitializeType, VmmPycVfs_InitializeType, VmmPycVmm_InitializeType
    };
    // initialize 'vmmpyc' core module:
    pPyModule = PyModule_Create(&VMMPYC_EmbModule);
    if(!pPyModule) { return NULL; }
    // initialize types:
    for(i = 0; i < sizeof(pfnTYPE_INITIALIZERS) / sizeof(PVOID); i++) {
        if(!pfnTYPE_INITIALIZERS[i](pPyModule)) {
            Py_DECREF(pPyModule);
            return NULL;
        }
    }
    return pPyModule;
}
