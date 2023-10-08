// vmmpyc_virtualmemory.c : implementation of process virtual memory for vmmpyc.
//
// (c) Ulf Frisk, 2021-2023
// Author: Ulf Frisk, pcileech@frizk.net
//
#include "vmmpyc.h"

PyObject *g_pPyType_VirtualMemory = NULL;

// ([DWORD], (DWORD)) -> [{...}]
static PyObject*
VmmPycVirtualMemory_read(PyObj_VirtualMemory *self, PyObject *args)
{
    if(!self->fValid) { return PyErr_Format(PyExc_RuntimeError, "VirtualMemory.read(): Not initialized."); }
    return VmmPyc_MemRead(self->pyVMM->hVMM, self->dwPID, "VirtualMemory.read()", args);
}

// (ULONG64, DWORD, (ULONG64)) -> [{...}]
static PyObject*
VmmPycVirtualMemory_read_scatter(PyObj_VirtualMemory *self, PyObject *args)
{
    if(!self->fValid) { return PyErr_Format(PyExc_RuntimeError, "VirtualMemory.read_scatter(): Not initialized."); }
    return VmmPyc_MemReadScatter(self->pyVMM->hVMM, self->dwPID, "VirtualMemory.read_scatter()", args);
}

// ([[ULONG64, STR], ..]) -> [T1, T2, ..]
static PyObject*
VmmPycVirtualMemory_read_type(PyObj_VirtualMemory *self, PyObject *args)
{
    if(!self->fValid) { return PyErr_Format(PyExc_RuntimeError, "VirtualMemory.read_type(): Not initialized."); }
    return VmmPyc_MemReadType(self->pyVMM->hVMM, self->dwPID, "VirtualMemory.read_type()", args);
}

// (ULONG64, PBYTE) -> None
static PyObject*
VmmPycVirtualMemory_write(PyObj_VirtualMemory *self, PyObject *args)
{
    if(!self->fValid) { return PyErr_Format(PyExc_RuntimeError, "VirtualMemory.write(): Not initialized."); }
    return VmmPyc_MemWrite(self->pyVMM->hVMM, self->dwPID, "VirtualMemory.write()", args);
}

// (ULONG64) -> ULONG64
static PyObject*
VmmPycVirtualMemory_virt2phys(PyObj_VirtualMemory *self, PyObject *args)
{
    BOOL result;
    ULONG64 va, pa;
    if(!self->fValid) { return PyErr_Format(PyExc_RuntimeError, "VirtualMemory.virt2phys(): Not initialized."); }
    if(!PyArg_ParseTuple(args, "K", &va)) {
        return PyErr_Format(PyExc_RuntimeError, "VirtualMemory.virt2phys(): Illegal argument.");
    }
    Py_BEGIN_ALLOW_THREADS;
    result = VMMDLL_MemVirt2Phys(self->pyVMM->hVMM, self->dwPID, va, &pa);
    Py_END_ALLOW_THREADS;
    if(!result) { return PyErr_Format(PyExc_RuntimeError, "VirtualMemory.virt2phys(): Failed."); }
    return PyLong_FromUnsignedLongLong(pa);
}

// ((DWORD)) -> PyObj_ScatterMemory
static PyObject*
VmmPycVirtualMemory_scatter_initialize(PyObj_VirtualMemory *self, PyObject *args)
{
    DWORD dwReadFlags = 0;
    if(!self->fValid) { return PyErr_Format(PyExc_RuntimeError, "VirtualMemory.scatter_initialize(): Not initialized."); }
    if(!PyArg_ParseTuple(args, "|k", &dwReadFlags)) { // borrowed reference
        return PyErr_Format(PyExc_RuntimeError, "VirtualMemory.scatter_initialize(): Illegal argument.");
    }
    return (PyObject*)VmmPycScatterMemory_InitializeInternal(self->pyVMM, NULL, self->dwPID, dwReadFlags);
}

//-----------------------------------------------------------------------------
// VmmPycVirtualMemory INITIALIZATION AND CORE FUNCTIONALITY BELOW:
//-----------------------------------------------------------------------------

PyObj_VirtualMemory*
VmmPycVirtualMemory_InitializeInternal(_In_ PyObj_Vmm *pyVMM, _In_ DWORD dwPID)
{
    PyObj_VirtualMemory *pyObj;
    if(!(pyObj = PyObject_New(PyObj_VirtualMemory, (PyTypeObject*)g_pPyType_VirtualMemory))) { return NULL; }
    Py_INCREF(pyVMM); pyObj->pyVMM = pyVMM;
    pyObj->fValid = TRUE;
    pyObj->dwPID = dwPID;
    return pyObj;
}

static PyObject*
VmmPycVirtualMemory_repr(PyObj_VirtualMemory *self)
{
    return self->fValid ?
        PyUnicode_FromFormat("VirtualMemory:%i", self->dwPID) :
        PyUnicode_FromFormat("VirtualMemory:NotValid");
}

static int
VmmPycVirtualMemory_init(PyObj_VirtualMemory *self, PyObject *args, PyObject *kwds)
{
    PyErr_SetString(PyExc_TypeError, "VirtualMemory.init(): Not allowed.");
    return -1;
}

static void
VmmPycVirtualMemory_dealloc(PyObj_VirtualMemory *self)
{
    self->fValid = FALSE;
    Py_XDECREF(self->pyVMM);
    PyObject_Del(self);
}

_Success_(return)
BOOL VmmPycVirtualMemory_InitializeType(PyObject *pModule)
{
    static PyMethodDef PyMethods[] = {
        {"virt2phys", (PyCFunction)VmmPycVirtualMemory_virt2phys, METH_VARARGS, "Translate virtual address to physical address."},
        {"read", (PyCFunction)VmmPycVirtualMemory_read, METH_VARARGS, "Read contigious virtual memory."},
        {"read_scatter", (PyCFunction)VmmPycVirtualMemory_read_scatter, METH_VARARGS, "Read scatter virtual 4kB memory pages."},
        {"read_type", (PyCFunction)VmmPycVirtualMemory_read_type, METH_VARARGS, "Read user-defined type(s)."},
        {"write", (PyCFunction)VmmPycVirtualMemory_write, METH_VARARGS, "Write contigious virtual memory."},
        {"scatter_initialize", (PyCFunction)VmmPycVirtualMemory_scatter_initialize, METH_VARARGS, "Initialize a Scatter memory object used for efficient reads."},
        {NULL, NULL, 0, NULL}
    };
    static PyMemberDef PyMembers[] = {
        {"pid", T_ULONG, offsetof(PyObj_VirtualMemory, dwPID), READONLY, "PID"},
        {NULL}
    };
    static PyGetSetDef PyGetSet[] = {
        {NULL}
    };
    static PyType_Slot PyTypeSlot[] = {
        {Py_tp_init, VmmPycVirtualMemory_init},
        {Py_tp_dealloc, VmmPycVirtualMemory_dealloc},
        {Py_tp_repr, VmmPycVirtualMemory_repr},
        {Py_tp_methods, PyMethods},
        {Py_tp_members, PyMembers},
        {Py_tp_getset, PyGetSet},
        {0, 0}
    };
    static PyType_Spec PyTypeSpec = {
        .name = "vmmpyc.VmmVirtualMemory",
        .basicsize = sizeof(PyObj_VirtualMemory),
        .itemsize = 0,
        .flags = Py_TPFLAGS_DEFAULT,
        .slots = PyTypeSlot,
    };
    if((g_pPyType_VirtualMemory = PyType_FromSpec(&PyTypeSpec))) {
        if(PyModule_AddObject(pModule, "VmmVirtualMemory", g_pPyType_VirtualMemory) < 0) {
            Py_DECREF(g_pPyType_VirtualMemory);
            g_pPyType_VirtualMemory = NULL;
        }
    }
    return g_pPyType_VirtualMemory ? TRUE : FALSE;
}
