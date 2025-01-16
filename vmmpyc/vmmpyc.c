// vmmpyc.c : implementation MemProcFS/VMM Python API
//
// (c) Ulf Frisk, 2018-2025
// Author: Ulf Frisk, pcileech@frizk.net
//
#include "vmmpyc.h"

//-----------------------------------------------------------------------------
// GENERAL READ/WRITE FUNCTIONS USED BY BASE VMM (PHYSICAL) AND PROCESS (VIRTUAL)
//-----------------------------------------------------------------------------

// ([DWORD], (DWORD)) -> [{...}]
PyObject* VmmPyc_MemReadScatter(_In_ VMM_HANDLE H, _In_ DWORD dwPID, _In_ LPSTR szFN, PyObject *args)
{
    PyObject *pyListSrc, *pyListItemSrc, *pyListDst, *pyDict;
    BOOL result;
    DWORD i, cMEMs, flags = 0;
    PMEM_SCATTER pMEM;
    PPMEM_SCATTER ppMEMs = NULL;
    if(!PyArg_ParseTuple(args, "O!|I", &PyList_Type, &pyListSrc, &flags)) { // borrowed reference
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
    result = VMMDLL_MemReadScatter(H, dwPID, ppMEMs, cMEMs, flags);
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

PyObject* VmmPyc_MemRead_Multi(_In_ VMM_HANDLE H, _In_ DWORD dwPID, _In_ LPSTR szFN, PyObject *args)
{
    BOOL fResult = FALSE;
    QWORD flags = 0;
    PyObject *pyListSrc, *pyListItemSrc, *pyLongAddress, *pyLongSize, *pyListResult, *pyBytes;
    DWORD cItem, iItem, cbMax = 0, cbRead;
    struct MultiInfo {
        QWORD qwA;
        DWORD cb;
    };
    struct MultiInfo *pMultiInfo = NULL, *pInfo;
    VMMDLL_SCATTER_HANDLE hS = NULL;
    PBYTE pb = NULL;
    if(!PyArg_ParseTuple(args, "O!|K", &PyList_Type, &pyListSrc, &flags)) {     // borrowed reference
        return PyErr_Format(PyExc_RuntimeError, "%s: Illegal argument.", szFN);
    }
    cItem = (DWORD)PyList_Size(pyListSrc);
    pMultiInfo = LocalAlloc(LMEM_ZEROINIT, cItem * sizeof(struct MultiInfo));
    hS = VMMDLL_Scatter_Initialize(H, dwPID, (DWORD)flags);
    pyListResult = PyList_New(0);
    if(!pMultiInfo || !hS || !pyListResult) { goto fail; }
    for(iItem = 0; iItem < cItem; iItem++) {
        pInfo = pMultiInfo + iItem;
        pyListItemSrc = PyList_GetItem(pyListSrc, iItem);           // borrowed reference
        if(!pyListItemSrc || !PyList_Check(pyListItemSrc)) { goto fail; }
        pyLongAddress = PyList_GetItem(pyListItemSrc, 0);           // borrowed reference
        pyLongSize = PyList_GetItem(pyListItemSrc, 1);              // borrowed reference
        if(!pyLongAddress || !pyLongSize || !PyLong_Check(pyLongAddress) || !PyLong_Check(pyLongSize)) { goto fail; }
        pInfo->qwA = PyLong_AsUnsignedLongLong(pyLongAddress);
        pInfo->cb = PyLong_AsUnsignedLong(pyLongSize);
        if((pInfo->qwA == (DWORD)-1) || (pInfo->cb == (DWORD)-1)) { goto fail; }
        cbMax = max(cbMax, pInfo->cb);
        VMMDLL_Scatter_Prepare(hS, pInfo->qwA, pInfo->cb);
    }
    VMMDLL_Scatter_ExecuteRead(hS);
    pb = LocalAlloc(0, cbMax);
    if(!pb) { goto fail; }
    for(iItem = 0; iItem < cItem; iItem++) {
        pInfo = pMultiInfo + iItem;
        if(VMMDLL_Scatter_Read(hS, pInfo->qwA, pInfo->cb, pb, &cbRead) && (pInfo->cb == cbRead) && (pyBytes = PyBytes_FromStringAndSize((const char*)pb, cbRead))) {
            PyList_Append_DECREF(pyListResult, pyBytes);
        } else {
            PyList_Append(pyListResult, Py_None);
        }
    }
    fResult = TRUE;
fail:
    LocalFree(pb);
    LocalFree(pMultiInfo);
    VMMDLL_Scatter_CloseHandle(hS);
    if(!fResult) {
        Py_XDECREF(pyListResult);
        PyErr_Format(PyExc_RuntimeError, "%s: Failed.", szFN);
    }
    return fResult ? pyListResult : PyErr_Format(PyExc_RuntimeError, "%s: Failed.", szFN);
}

// (ULONG64, DWORD, (ULONG64)) -> PBYTE
// ([[ULONG64, DWORD], ..], (ULONG64)) -> [PBYTE, ..]
PyObject* VmmPyc_MemRead(_In_ VMM_HANDLE H, _In_ DWORD dwPID, _In_ LPSTR szFN, PyObject *args)
{
    PyObject *pyBytes;
    BOOL result;
    PBYTE pb;
    DWORD cb, cbRead = 0;
    ULONG64 qwA, flags = 0;
    if(!PyArg_ParseTuple(args, "KI|K", &qwA, &cb, &flags)) {
        // try multi-read:
        PyErr_Clear();
        return VmmPyc_MemRead_Multi(H, dwPID, szFN, args);
    }
    pb = LocalAlloc(0, cb);
    if(!pb) { return PyErr_NoMemory(); }
    Py_BEGIN_ALLOW_THREADS;
    result = VMMDLL_MemReadEx(H, dwPID, qwA, pb, cb, &cbRead, flags);
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
PyObject* VmmPyc_MemWrite(_In_ VMM_HANDLE H, _In_ DWORD dwPID, _In_ LPSTR szFN, PyObject *args)
{
    BOOL result;
    ULONG64 va;
    SIZE_T cb;
    PBYTE pb;
    if(!PyArg_ParseTuple(args, "Ky#", &va, &pb, &cb)) {
        return PyErr_Format(PyExc_RuntimeError, "%s: Illegal argument.", szFN);
    }
    if(cb == 0) {
        Py_INCREF(Py_None); return Py_None; // zero-byte write is always successful.
    }
    Py_BEGIN_ALLOW_THREADS;
    result = VMMDLL_MemWrite(H, dwPID, va, pb, (DWORD)cb);
    Py_END_ALLOW_THREADS;
    if(!result) { return PyErr_Format(PyExc_RuntimeError, "%s: Failed.", szFN); }
    Py_INCREF(Py_None); return Py_None;     // None returned on success.
}

DWORD VmmPyc_MemReadType_TypeCheck(_In_ PyObject* pyUnicodeTp, _Out_ PDWORD pcbTp)
{
    PyObject *pyBytes;
    union {
        DWORD dw;
        BYTE b4[4];
    } tp = { 0 };
    SIZE_T cch;
    char *sz;
    if((pyBytes = PyUnicode_AsUTF8String(pyUnicodeTp))) {
        PyBytes_AsStringAndSize(pyBytes, &sz, &cch);
        tp.b4[3] = (cch > 0) ? sz[0] : ' ';
        tp.b4[2] = (cch > 1) ? sz[1] : ' ';
        tp.b4[1] = (cch > 2) ? sz[2] : ' ';
        tp.b4[0] = (cch > 3) ? sz[3] : ' ';
        Py_DECREF(pyBytes);
    }
    switch(tp.dw) {
        case 'i8  ':
        case 'u8  ':
            *pcbTp = 1;
            return tp.dw;
        case 'i16 ':
        case 'u16 ':
            *pcbTp = 2;
            return tp.dw;
        case 'f32 ':
        case 'i32 ':
        case 'u32 ':
            *pcbTp = 4;
            return tp.dw;
        case 'f64 ':
        case 'i64 ':
        case 'u64 ':
            *pcbTp = 8;
            return tp.dw;
        default:
            *pcbTp = 0;
            return tp.dw;
    }
}

PyObject* VmmPyc_MemReadType_TypeGet(_In_ DWORD tp, _In_ PBYTE pb, _In_ DWORD cbRead)
{
    BYTE pbZERO[8] = { 0 };
    switch(tp) {
        case 'i8  ':
            return PyLong_FromLong(*(BYTE*)((cbRead >= 1) ? pb : pbZERO)); break;
        case 'u8  ':
            return PyLong_FromUnsignedLong(*(BYTE*)((cbRead >= 1) ? pb : pbZERO)); break;
        case 'i16 ':
            return PyLong_FromLong(*(WORD*)((cbRead >= 2) ? pb : pbZERO)); break;
        case 'u16 ':
            return PyLong_FromUnsignedLong(*(WORD*)((cbRead >= 2) ? pb : pbZERO)); break;
        case 'f32 ':
            return PyFloat_FromDouble(*(float*)((cbRead >= 4) ? pb : pbZERO)); break;
        case 'i32 ':
            return PyLong_FromLong(*(DWORD*)((cbRead >= 4) ? pb : pbZERO)); break;
        case 'u32 ':
            return PyLong_FromUnsignedLong(*(DWORD*)((cbRead >= 4) ? pb : pbZERO)); break;
        case 'f64 ':
            return PyFloat_FromDouble(*(double*)((cbRead >= 8) ? pb : pbZERO)); break;
        case 'i64 ':
            return PyLong_FromLongLong(*(QWORD*)((cbRead >= 8) ? pb : pbZERO)); break;
        case 'u64 ':
            return PyLong_FromUnsignedLongLong(*(QWORD*)((cbRead >= 8) ? pb : pbZERO)); break;
        default:
            Py_INCREF(Py_None);
            return Py_None;
    }
}

// ([[ULONG64, STR], ..]) -> [T1, T2, ..]
PyObject* VmmPyc_MemReadType(_In_ VMM_HANDLE H, _In_ DWORD dwPID, _In_ LPSTR szFN, PyObject *args)
{
    PyObject *pyListItemSrc, *pyListResult = NULL, *pyLongAddress, *pyUnicodeTP;
    DWORD iItem, cItem;
    ULONG64 qwA, vaPrevious = (ULONG64)-1, flags = 0;
    BYTE pb8[8] = { 0 }, pbZERO[8] = { 0 }, *pbTP;
    DWORD tp, cbTP, cbRead;
    PyObject *pyObjArg0, *pyObjArg1 = NULL;
    struct MultiInfo {
        QWORD qwA;
        DWORD tp;
        DWORD cb;
        DWORD cbRead;
        BYTE pb[8];
    };
    VMMDLL_SCATTER_HANDLE hS = NULL;
    struct MultiInfo *pMultiInfo = NULL, *pInfo;
    if(!PyArg_ParseTuple(args, "O|OK", &pyObjArg0, &pyObjArg1, &flags)) {           // borrowed reference
        return PyErr_Format(PyExc_RuntimeError, "%s: Illegal argument.", szFN);
    }
    // Single type read on the format: (ULONG64, STR | ULONG64), Example: 0x1000, 'u32 '
    if(PyLong_Check(pyObjArg0)) {
        if(!pyObjArg1 || !PyUnicode_Check(pyObjArg1)) {
            return PyErr_Format(PyExc_RuntimeError, "%s: Illegal argument.", szFN);
        }
        tp = VmmPyc_MemReadType_TypeCheck(pyObjArg1, &cbTP);
        qwA = PyLong_AsUnsignedLongLong(pyObjArg0);
        pbTP = pbZERO;
        if(cbTP) {
            Py_BEGIN_ALLOW_THREADS;
            VMMDLL_MemReadEx(H, dwPID, qwA, pb8, cbTP, &cbRead, flags | VMMDLL_FLAG_NO_PREDICTIVE_READ);
            if(cbTP == cbRead) {
                pbTP = pb8;
            }
            Py_END_ALLOW_THREADS;
        }
        return VmmPyc_MemReadType_TypeGet(tp, pbTP, cbRead);
    }
    // List read on the format: ([[ULONG64, STR], ..] | ULONG64), Example: [[0x1000, 'u32 '], [0x2000, 'u32 ']]
    // verify and read python object data:
    if(!PyList_Check(pyObjArg0)) {
        return PyErr_Format(PyExc_RuntimeError, "%s: Illegal argument.", szFN);
    }
    if(pyObjArg1) {
        if(!PyLong_Check(pyObjArg1)) {
            return PyErr_Format(PyExc_RuntimeError, "%s: Illegal argument.", szFN);
        }
        flags = PyLong_AsUnsignedLongLong(pyObjArg1);
    }
    cItem = (DWORD)PyList_Size(pyObjArg0);
    pMultiInfo = LocalAlloc(LMEM_ZEROINIT, cItem * sizeof(struct MultiInfo));
    if(!pMultiInfo) { goto fail; }
    hS = VMMDLL_Scatter_Initialize(H, dwPID, (DWORD)flags | VMMDLL_FLAG_NO_PREDICTIVE_READ);
    for(iItem = 0; iItem < cItem; iItem++) {
        pInfo = pMultiInfo + iItem;
        pyListItemSrc = PyList_GetItem(pyObjArg0, iItem);           // borrowed reference
        if(!pyListItemSrc || !PyList_Check(pyListItemSrc)) { goto fail; }
        pyLongAddress = PyList_GetItem(pyListItemSrc, 0);           // borrowed reference
        pyUnicodeTP = PyList_GetItem(pyListItemSrc, 1);             // borrowed reference
        if(!pyLongAddress || !pyUnicodeTP || !PyLong_Check(pyLongAddress) || !PyUnicode_Check(pyUnicodeTP)) { goto fail; }
        pInfo->tp = VmmPyc_MemReadType_TypeCheck(pyUnicodeTP, &pInfo->cb);
        pInfo->qwA = PyLong_AsUnsignedLongLong(pyLongAddress);
        if(pInfo->cb) {
            VMMDLL_Scatter_PrepareEx(hS, pInfo->qwA, pInfo->cb, pInfo->pb, &pInfo->cbRead);
        }
    }
    // native read data:
    Py_BEGIN_ALLOW_THREADS;
    VMMDLL_Scatter_Execute(hS);
    Py_END_ALLOW_THREADS;
    // python allocate and return results:
    pyListResult = PyList_New(0);
    if(!pyListResult) { goto fail; }
    for(iItem = 0; iItem < cItem; iItem++) {
        pInfo = pMultiInfo + iItem;
        PyList_Append_DECREF(pyListResult, VmmPyc_MemReadType_TypeGet(pInfo->tp, pInfo->pb, pInfo->cbRead));
    }
    VMMDLL_Scatter_CloseHandle(hS);
    LocalFree(pMultiInfo);
    return pyListResult;
fail:
    VMMDLL_Scatter_CloseHandle(hS);
    LocalFree(pMultiInfo);
    Py_XDECREF(pyListResult);
    return PyErr_Format(PyExc_RuntimeError, "%s: Internal error.", szFN);
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
        VmmPycPlugin_InitializeType,
        VmmPycPhysicalMemory_InitializeType, VmmPycScatterMemory_InitializeType,
        VmmPycVirtualMemory_InitializeType, VmmPycRegMemory_InitializeType,
        VmmPycRegHive_InitializeType, VmmPycRegKey_InitializeType, VmmPycRegValue_InitializeType,
        VmmPycProcess_InitializeType, VmmPycProcessMaps_InitializeType,
        VmmPycModule_InitializeType, VmmPycModuleMaps_InitializeType,
        VmmPycKernel_InitializeType, VmmPycMaps_InitializeType,
        VmmPycPdb_InitializeType, VmmPycVfs_InitializeType, VmmPycVmm_InitializeType,
        VmmPycSearch_InitializeType, VmmPycYara_InitializeType,
        VmmPycVirtualMachine_InitializeType
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
