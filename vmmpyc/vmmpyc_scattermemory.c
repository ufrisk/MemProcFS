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
static PyObject*
VmmPycScatterMemory_prepare(PyObj_ScatterMemory *self, PyObject *args)
{
    BOOL result;
    DWORD cb;
    ULONG64 qwA;
    if(!self->fValid) { return PyErr_Format(PyExc_RuntimeError, "VmmScatterMemory.prepare(): Not initialized."); }
    if(!PyArg_ParseTuple(args, "Kk", &qwA, &cb)) {
        return PyErr_Format(PyExc_RuntimeError, "VmmScatterMemory.prepare(): Illegal argument.");
    }
    Py_BEGIN_ALLOW_THREADS;
    result = VMMDLL_Scatter_Prepare(self->hScatter, qwA, cb);
    Py_END_ALLOW_THREADS;
    if(!result) { return PyErr_Format(PyExc_RuntimeError, "VmmScatterMemory.prepare(): Failed."); }
    return Py_BuildValue("s", NULL);        // None returned on success.
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
    return Py_BuildValue("s", NULL);        // None returned on success.
}

// (ULONG64, DWORD) -> PBYTE
static PyObject*
VmmPycScatterMemory_read(PyObj_ScatterMemory *self, PyObject *args)
{
    PyObject *pyBytes;
    BOOL result;
    PBYTE pb;
    DWORD cb, cbRead = 0;
    ULONG64 qwA;
    if(!self->fValid) { return PyErr_Format(PyExc_RuntimeError, "VmmScatterMemory.read(): Not initialized."); }
    if(!PyArg_ParseTuple(args, "Kk", &qwA, &cb)) {
        return PyErr_Format(PyExc_RuntimeError, "VmmScatterMemory.read(): Illegal argument.");
    }
    pb = LocalAlloc(0, cb);
    if(!pb) { return PyErr_NoMemory(); }
    Py_BEGIN_ALLOW_THREADS;
    result = VMMDLL_Scatter_Read(self->hScatter, qwA, cb, pb, &cbRead);
    Py_END_ALLOW_THREADS;
    if(!result) {
        LocalFree(pb);
        return PyErr_Format(PyExc_RuntimeError, "VmmScatterMemory.read(): Failed.");
    }
    pyBytes = PyBytes_FromStringAndSize((const char *)pb, cbRead);
    LocalFree(pb);
    return pyBytes;
}

// ([[ULONG64, STR], ..]) -> [T1, T2, ..]
static PyObject*
VmmPycScatterMemory_read_type(PyObj_ScatterMemory *self, PyObject *args)
{
    PyObject *pyListItemSrc, *pyListResult = NULL, *pyLongAddress, *pyUnicodeTP;
    DWORD iItem, cItem;
    ULONG64 qwA, flags = 0;
    BYTE pb8[8], pbZERO[8] = { 0 }, *pbTP;
    DWORD tp, cbTP, cbRead;
    PyObject *pyObjArg0, *pyObjArg1 = NULL;
    struct MultiInfo {
        QWORD qwA;
        DWORD tp;
        DWORD cb;
        BYTE pb[8];
    };
    struct MultiInfo *pMultiInfo = NULL, *pInfo;
    BOOL result;
    if(!PyArg_ParseTuple(args, "O|OK", &pyObjArg0, &pyObjArg1, &flags)) {           // borrowed reference
        return PyErr_Format(PyExc_RuntimeError, "VmmScatterMemory.read_type(): Illegal argument.");
    }
    // Single type read on the format: (ULONG64, STR | ULONG64), Example: 0x1000, 'u32 '
    if(PyLong_Check(pyObjArg0)) {
        if(!pyObjArg1 || !PyUnicode_Check(pyObjArg1)) {
            return PyErr_Format(PyExc_RuntimeError, "VmmScatterMemory.read_type(): Illegal argument.");
        }
        tp = VmmPyc_MemReadType_TypeCheck(pyObjArg1, &cbTP);
        qwA = PyLong_AsUnsignedLongLong(pyObjArg0);
        pbTP = pbZERO;
        if(cbTP) {
            Py_BEGIN_ALLOW_THREADS;
            result = VMMDLL_Scatter_Read(self->hScatter, qwA, cbTP, pb8, &cbRead);
            if(result && (cbTP == cbRead)) {
                pbTP = pb8;
            }
            Py_END_ALLOW_THREADS;
        }
        return VmmPyc_MemReadType_TypeGet(tp, pbTP);
    }
    // List read on the format: ([[ULONG64, STR], ..] | ULONG64), Example: [[0x1000, 'u32 '], [0x2000, 'u32 ']]
    // verify and read python object data:
    if(!PyList_Check(pyObjArg0)) {
        return PyErr_Format(PyExc_RuntimeError, "VmmScatterMemory.read_type(): Illegal argument.");
    }
    if(pyObjArg1) {
        if(!PyLong_Check(pyObjArg1)) {
            return PyErr_Format(PyExc_RuntimeError, "VmmScatterMemory.read_type(): Illegal argument.");
        }
        flags = PyLong_AsUnsignedLongLong(pyObjArg1);
    }
    cItem = (DWORD)PyList_Size(pyObjArg0);
    pMultiInfo = LocalAlloc(LMEM_ZEROINIT, cItem * sizeof(struct MultiInfo));
    if(!pMultiInfo) { goto fail; }
    for(iItem = 0; iItem < cItem; iItem++) {
        pInfo = pMultiInfo + iItem;
        pyListItemSrc = PyList_GetItem(pyObjArg0, iItem);           // borrowed reference
        if(!pyListItemSrc || !PyList_Check(pyListItemSrc)) { goto fail; }
        pyLongAddress = PyList_GetItem(pyListItemSrc, 0);           // borrowed reference
        pyUnicodeTP = PyList_GetItem(pyListItemSrc, 1);             // borrowed reference
        if(!pyLongAddress || !pyUnicodeTP || !PyLong_Check(pyLongAddress) || !PyUnicode_Check(pyUnicodeTP)) { goto fail; }
        pInfo->tp = VmmPyc_MemReadType_TypeCheck(pyUnicodeTP, &pInfo->cb);
        pInfo->qwA = PyLong_AsUnsignedLongLong(pyLongAddress);
    }
    // native read data:
    Py_BEGIN_ALLOW_THREADS;
    for(iItem = 0; iItem < cItem; iItem++) {
        pInfo = pMultiInfo + iItem;
        if(pInfo->cb && VMMDLL_Scatter_Read(self->hScatter, pInfo->qwA, pInfo->cb, pb8, &cbRead) && (pInfo->cb == cbRead)) {
            memcpy(pInfo->pb, pb8, pInfo->cb);
        }
    }
    Py_END_ALLOW_THREADS;
    // python allocate and return results:
    pyListResult = PyList_New(0);
    if(!pyListResult) { goto fail; }
    for(iItem = 0; iItem < cItem; iItem++) {
        pInfo = pMultiInfo + iItem;
        PyList_Append_DECREF(pyListResult, VmmPyc_MemReadType_TypeGet(pInfo->tp, pInfo->pb));
    }
    LocalFree(pMultiInfo);
    return pyListResult;
fail:
    LocalFree(pMultiInfo);
    Py_XDECREF(pyListResult);
    return PyErr_Format(PyExc_RuntimeError, "VmmScatterMemory.read_type(): Internal error.");
}

// ((DWORD, DWORD)) -> None
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
    Py_BEGIN_ALLOW_THREADS;
    result = VMMDLL_Scatter_Clear(self->hScatter, dwPID, dwReadFlags);
    Py_END_ALLOW_THREADS;
    if(!result) { return PyErr_Format(PyExc_RuntimeError, "VmmScatterMemory.clear(): Failed."); }
    self->dwPID = dwPID;
    self->dwReadFlags = dwReadFlags;
    return Py_BuildValue("s", NULL);        // None returned on success.
}

// () -> None
static PyObject*
VmmPycScatterMemory_close(PyObj_ScatterMemory *self, PyObject *args)
{
    if(!self->fValid) { return PyErr_Format(PyExc_RuntimeError, "VmmScatterMemory.close(): Not initialized."); }
    self->fValid = FALSE;
    Py_BEGIN_ALLOW_THREADS;
    VMMDLL_Scatter_CloseHandle(self->hScatter);
    Py_END_ALLOW_THREADS;
    self->hScatter = NULL;
    return Py_BuildValue("s", NULL);        // None returned on success.
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
