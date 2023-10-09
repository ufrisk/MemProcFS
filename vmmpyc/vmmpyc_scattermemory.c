// vmmpyc_scattermemory.c : implementation of easy-to-use read of scatter memory for vmmpyc.
// 
// vmmpyc_scattermemory is a wrapper around the VMMDLL_Scatter_* easy-to-use
// read scatter memory functionality. vmmpyc_scattermemory should be used to
// simplify reading multiple memory regions in one single efficient call to
// the underlying hardware/software. This will greatly speed up latency-bound
// memory regions.
// 
// vmmpyc_scattermemory supports read/write of:
//  - virtual memory.
//  - physical memory.
//  - vm guest physical memory.
//
// (c) Ulf Frisk, 2022-2023
// Author: Ulf Frisk, pcileech@frizk.net
//
#include "vmmpyc.h"

PyObject *g_pPyType_ScatterMemory = NULL;

// (ULONG64, DWORD) -> None
// [[ULONG64, DWORD], ..] -> None
// NB! GIL not released due to high-performance native calls.
static PyObject*
VmmPycScatterMemory_prepare(PyObj_ScatterMemory *self, PyObject *args)
{
    PyObject *pyList, *pyListItem, *pyA, *pyCB;
    BOOL result;
    DWORD c, i, cb;
    ULONG64 qwA;
    SIZE_T cArgs;
    if(!self->fValid) { return PyErr_Format(PyExc_RuntimeError, "VmmScatterMemory.prepare(): Not initialized."); }
    cArgs = PyTuple_Size(args);
    // single prepare:
    if((cArgs == 2) && PyArg_ParseTuple(args, "Kk", &qwA, &cb)) {
        result = VMMDLL_Scatter_Prepare(self->hScatter, qwA, cb);
        if(!result) { return PyErr_Format(PyExc_RuntimeError, "VmmScatterMemory.prepare(): Failed."); }
        Py_INCREF(Py_None); return Py_None;                 // None returned on success.        
    }
    // multi prepare:
    if((cArgs == 1) && PyArg_ParseTuple(args, "O!", &PyList_Type, &pyList)) {
        c = (DWORD)PyList_Size(pyList);
        for(i = 0; i < c; i++) {
            pyListItem = PyList_GetItem(pyList, i);         // borrowed reference
            if(!pyListItem || !PyList_Check(pyListItem) || (2 != PyList_Size(pyListItem))) { goto fail; }
            pyA = PyList_GetItem(pyListItem, 0);            // borrowed reference
            pyCB = PyList_GetItem(pyListItem, 1);           // borrowed reference
            if(!pyA || !pyCB || !PyLong_Check(pyA) || !PyLong_Check(pyCB)) { goto fail; }
            qwA = PyLong_AsUnsignedLongLong(pyA);
            cb = PyLong_AsUnsignedLong(pyCB);
            result = VMMDLL_Scatter_Prepare(self->hScatter, qwA, cb);
            if(!result) { return PyErr_Format(PyExc_RuntimeError, "VmmScatterMemory.prepare(): Failed."); }
        }
        Py_INCREF(Py_None); return Py_None;                 // None returned on success. 
    }
fail:
    return PyErr_Format(PyExc_RuntimeError, "VmmScatterMemory.prepare(): Illegal argument.");
}

// () -> None
static PyObject*
VmmPycScatterMemory_execute(PyObj_ScatterMemory *self, PyObject *args)
{
    BOOL result;
    if(!self->fValid) { return PyErr_Format(PyExc_RuntimeError, "VmmScatterMemory.execute(): Not initialized."); }
    Py_BEGIN_ALLOW_THREADS;
    result = VMMDLL_Scatter_ExecuteRead(self->hScatter);
    Py_END_ALLOW_THREADS;
    if(!result) { return PyErr_Format(PyExc_RuntimeError, "VmmScatterMemory.execute(): Failed."); }
    Py_INCREF(Py_None); return Py_None;                     // None returned on success. 
}

// (ULONG64, DWORD) -> PBYTE
// [[ULONG64, DWORD], ..] -> [PBYTE, ..]
// NB! GIL not released due to high-performance native calls.
static PyObject*
VmmPycScatterMemory_read(PyObj_ScatterMemory *self, PyObject *args)
{
    PyObject *pyBytes, *pyList, *pyListItem, *pyA, *pyCB, *pyListResult;
    BOOL result;
    PBYTE pb;
    DWORD c, i, cb, cbRead = 0;
    ULONG64 qwA;
    SIZE_T cArgs;
    if(!self->fValid) { return PyErr_Format(PyExc_RuntimeError, "VmmScatterMemory.read(): Not initialized."); }
    cArgs = PyTuple_Size(args);
    // single read:
    if((cArgs == 2) && PyArg_ParseTuple(args, "Kk", &qwA, &cb)) {
        pb = LocalAlloc(0, cb);
        if(!pb) { return PyErr_NoMemory(); }
        result = VMMDLL_Scatter_Read(self->hScatter, qwA, cb, pb, &cbRead);
        if(result) {
            pyBytes = PyBytes_FromStringAndSize((const char*)pb, cbRead);
            LocalFree(pb);
            return pyBytes;
        } else {
            LocalFree(pb);
            return PyErr_Format(PyExc_RuntimeError, "VmmScatterMemory.read(): Failed.");
        }
    }
    // multi read:
    if((cArgs == 1) && PyArg_ParseTuple(args, "O!", &PyList_Type, &pyList)) {
        pyListResult = PyList_New(0);
        if(!pyListResult) { return PyErr_NoMemory(); }
        c = (DWORD)PyList_Size(pyList);
        for(i = 0; i < c; i++) {
            pyListItem = PyList_GetItem(pyList, i);         // borrowed reference
            if(!pyListItem || !PyList_Check(pyListItem) || (2 != PyList_Size(pyListItem))) { goto fail; }
            pyA = PyList_GetItem(pyListItem, 0);            // borrowed reference
            pyCB = PyList_GetItem(pyListItem, 1);           // borrowed reference
            if(!pyA || !pyCB || !PyLong_Check(pyA) || !PyLong_Check(pyCB)) { goto fail; }
            qwA = PyLong_AsUnsignedLongLong(pyA);
            cb = PyLong_AsUnsignedLong(pyCB);
            pb = LocalAlloc(0, cb);
            if(!pb) { return PyErr_NoMemory(); }
            result = VMMDLL_Scatter_Read(self->hScatter, qwA, cb, pb, &cbRead);
            if(result) {
                pyBytes = PyBytes_FromStringAndSize((const char*)pb, cbRead);
                PyList_Append_DECREF(pyListResult, pyBytes);
            } else {
                PyList_Append(pyListResult, Py_None);
            }
            LocalFree(pb);
        }
        return pyListResult;
    }
fail:
    return PyErr_Format(PyExc_RuntimeError, "VmmScatterMemory.read(): Illegal argument.");
}

// (ULONG64, STR) -> T
// ([[ULONG64, STR], ..]) -> [T1, T2, ..]
// NB! GIL not released due to high-performance native calls.
static PyObject*
VmmPycScatterMemory_read_type(PyObj_ScatterMemory *self, PyObject *args)
{
    PyObject *pyListSrc, *pyListItemSrc, *pyListResult = NULL, *pyLongAddress, *pyUnicodeTP;
    DWORD iItem, cItem;
    ULONG64 qwA, flags = 0;
    BYTE pb8[8], pbZERO[8] = { 0 }, *pbTP;
    DWORD tp, cbTP, cbRead;
    BOOL result;
    SIZE_T cArgs;
    if(!self->fValid) { return PyErr_Format(PyExc_RuntimeError, "VmmScatterMemory.read(): Not initialized."); }
    cArgs = PyTuple_Size(args);
    // Single type read on the format: (ULONG64, STR) -> T, Example: 0x1000, 'u32'
    if((cArgs == 2) && PyArg_ParseTuple(args, "KO!", &qwA, &PyUnicode_Type, &pyUnicodeTP)) {
        tp = VmmPyc_MemReadType_TypeCheck(pyUnicodeTP, &cbTP);
        pbTP = pbZERO;
        if(cbTP) {
            result = VMMDLL_Scatter_Read(self->hScatter, qwA, cbTP, pb8, &cbRead);
            if(result && (cbTP == cbRead)) {
                pbTP = pb8;
            }
        }
        return VmmPyc_MemReadType_TypeGet(tp, pbTP);
    }
    // Multi read on the format: ([[ULONG64, STR], ..]) -> [T, ..], Example: [[0x1000, 'u32'], [0x2000, 'u32']]
    if((cArgs == 1) && PyArg_ParseTuple(args, "O!", &PyList_Type, &pyListSrc)) {
        cItem = (DWORD)PyList_Size(pyListSrc);
        pyListResult = PyList_New(0);
        if(!pyListResult) { return PyErr_NoMemory(); }
        for(iItem = 0; iItem < cItem; iItem++) {
            pyListItemSrc = PyList_GetItem(pyListSrc, iItem);           // borrowed reference
            if(!pyListItemSrc || !PyList_Check(pyListItemSrc)) { goto fail; }
            pyLongAddress = PyList_GetItem(pyListItemSrc, 0);           // borrowed reference
            pyUnicodeTP = PyList_GetItem(pyListItemSrc, 1);             // borrowed reference
            if(!pyLongAddress || !pyUnicodeTP || !PyLong_Check(pyLongAddress) || !PyUnicode_Check(pyUnicodeTP)) { goto fail; }
            qwA = PyLong_AsUnsignedLongLong(pyLongAddress);
            tp = VmmPyc_MemReadType_TypeCheck(pyUnicodeTP, &cbTP);
            pbTP = pbZERO;
            if(cbTP) {
                result = VMMDLL_Scatter_Read(self->hScatter, qwA, cbTP, pb8, &cbRead);
                if(result && (cbTP == cbRead)) {
                    pbTP = pb8;
                }
            }
            PyList_Append_DECREF(pyListResult, VmmPyc_MemReadType_TypeGet(tp, pbTP));
        }
        return pyListResult;
    }
fail:
    return PyErr_Format(PyExc_RuntimeError, "VmmScatterMemory.read_type(): Illegal argument.");
}

// ((DWORD, DWORD)) -> None
// NB! GIL not released due to high-performance native calls.
static PyObject*
VmmPycScatterMemory_clear(PyObj_ScatterMemory *self, PyObject *args)
{
    BOOL result;
    DWORD dwPID, dwReadFlags;
    if(!self->fValid) { return PyErr_Format(PyExc_RuntimeError, "VmmScatterMemory.clear(): Not initialized."); }
    dwPID = self->dwPID;
    dwReadFlags = self->dwReadFlags;
    if(!PyArg_ParseTuple(args, "|kk", &dwPID, &dwReadFlags)) {
        return PyErr_Format(PyExc_RuntimeError, "VmmScatterMemory.clear(): Illegal argument.");
    }
    result = VMMDLL_Scatter_Clear(self->hScatter, dwPID, dwReadFlags);
    if(!result) { return PyErr_Format(PyExc_RuntimeError, "VmmScatterMemory.clear(): Failed."); }
    self->dwPID = dwPID;
    self->dwReadFlags = dwReadFlags;
    Py_INCREF(Py_None); return Py_None;                 // None returned on success.
}

// () -> None
// NB! GIL not released due to high-performance native calls.
static PyObject*
VmmPycScatterMemory_close(PyObj_ScatterMemory *self, PyObject *args)
{
    if(!self->fValid) { return PyErr_Format(PyExc_RuntimeError, "VmmScatterMemory.close(): Not initialized."); }
    self->fValid = FALSE;
    VMMDLL_Scatter_CloseHandle(self->hScatter);
    self->hScatter = NULL;
    Py_INCREF(Py_None); return Py_None;                 // None returned on success. 
}

//-----------------------------------------------------------------------------
// VmmPycScatterMemory INITIALIZATION AND CORE FUNCTIONALITY BELOW:
//-----------------------------------------------------------------------------

PyObj_ScatterMemory*
VmmPycScatterMemory_InitializeInternal(_In_ PyObj_Vmm *pyVMM, _In_opt_ VMMVM_HANDLE hVM, _In_opt_ DWORD dwPID, _In_ DWORD dwReadFlags)
{
    PyObj_ScatterMemory *pyObj;
    if(!(pyObj = PyObject_New(PyObj_ScatterMemory, (PyTypeObject*)g_pPyType_ScatterMemory))) { return NULL; }
    Py_INCREF(pyVMM); pyObj->pyVMM = pyVMM;
    pyObj->fValid = TRUE;
    pyObj->hVM = hVM;
    pyObj->dwPID = dwPID;
    pyObj->dwReadFlags = dwReadFlags;
    if(hVM) {
        pyObj->hScatter = VMMDLL_VmScatterInitialize(pyVMM->hVMM, hVM);
    } else {
        pyObj->hScatter = VMMDLL_Scatter_Initialize(pyVMM->hVMM, dwPID, dwReadFlags);
    }
    if(!pyObj->hScatter) {
        Py_DECREF(pyObj);
        return NULL;
    }
    return pyObj;
}

static PyObject*
VmmPycScatterMemory_repr(PyObj_ScatterMemory *self)
{
    if(!self->fValid) {
        return PyUnicode_FromFormat("VmmScatterMemory:NotValid");
    } else if(self->dwPID != (DWORD)-1) {
        return PyUnicode_FromFormat("VmmScatterMemory:Virtual:%i", self->dwPID);
    } else {
        return PyUnicode_FromFormat("VmmScatterMemory:Physical");
    }
}

static int
VmmPycScatterMemory_init(PyObj_ScatterMemory *self, PyObject *args, PyObject *kwds)
{
    PyErr_SetString(PyExc_TypeError, "VmmScatterMemory.init(): Not allowed.");
    return -1;
}

static void
VmmPycScatterMemory_dealloc(PyObj_ScatterMemory *self)
{
    self->fValid = FALSE;
    VMMDLL_Scatter_CloseHandle(self->hScatter);
    Py_XDECREF(self->pyVMM);
    PyObject_Del(self);
}

_Success_(return)
BOOL VmmPycScatterMemory_InitializeType(PyObject *pModule)
{
    static PyMethodDef PyMethods[] = {
        {"prepare",     (PyCFunction)VmmPycScatterMemory_prepare,   METH_VARARGS, "Prepare a memory region to be read in a subsequent execute() call."},
        {"execute",     (PyCFunction)VmmPycScatterMemory_execute,   METH_VARARGS, "Read prepared memory regions into the ScatterMemory object.."},
        {"read",        (PyCFunction)VmmPycScatterMemory_read,      METH_VARARGS, "Read resulting scatter memory (after execute() has been called."},
        {"read_type",   (PyCFunction)VmmPycScatterMemory_read_type, METH_VARARGS, "Read user-defined type(s)."},
        {"clear",       (PyCFunction)VmmPycScatterMemory_clear,     METH_VARARGS, "Clear the scatter memory object and release some internal resources."},
        {"close",       (PyCFunction)VmmPycScatterMemory_close,     METH_VARARGS, "Manually Close the scatter object and deallocate all native memory."},
        {NULL, NULL, 0, NULL}
    };
    static PyMemberDef PyMembers[] = {
        {"pid",   T_ULONG, offsetof(PyObj_ScatterMemory, dwPID),       READONLY, "PID"},
        {"flags", T_ULONG, offsetof(PyObj_ScatterMemory, dwReadFlags), READONLY, "Read Flags: combination of one or multiple memprocfs.FLAGS_*."},
        {NULL}
    };
    static PyGetSetDef PyGetSet[] = {
        {NULL}
    };
    static PyType_Slot PyTypeSlot[] = {
        {Py_tp_init, VmmPycScatterMemory_init},
        {Py_tp_dealloc, VmmPycScatterMemory_dealloc},
        {Py_tp_repr, VmmPycScatterMemory_repr},
        {Py_tp_methods, PyMethods},
        {Py_tp_members, PyMembers},
        {Py_tp_getset, PyGetSet},
        {0, 0}
    };
    static PyType_Spec PyTypeSpec = {
        .name = "vmmpyc.VmmScatterMemory",
        .basicsize = sizeof(PyObj_ScatterMemory),
        .itemsize = 0,
        .flags = Py_TPFLAGS_DEFAULT,
        .slots = PyTypeSlot,
    };
    if((g_pPyType_ScatterMemory = PyType_FromSpec(&PyTypeSpec))) {
        if(PyModule_AddObject(pModule, "VmmScatterMemory", g_pPyType_ScatterMemory) < 0) {
            Py_DECREF(g_pPyType_ScatterMemory);
            g_pPyType_ScatterMemory = NULL;
        }
    }
    return g_pPyType_ScatterMemory ? TRUE : FALSE;
}
