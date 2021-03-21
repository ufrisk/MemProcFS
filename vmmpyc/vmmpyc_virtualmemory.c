// vmmpyc_virtualmemory.c : implementation of process virtual memory for vmmpyc.
//
// (c) Ulf Frisk, 2021
// Author: Ulf Frisk, pcileech@frizk.net
//
#include "vmmpyc.h"

PyObject *g_pPyType_VirtualMemory = NULL;

// ([DWORD], (DWORD)) -> [{...}]
static PyObject*
VmmPycVirtualMemory_read(PyObj_VirtualMemory *self, PyObject *args)
{
    if(!self->fValid) { return PyErr_Format(PyExc_RuntimeError, "VirtualMemory.read(): Not initialized."); }
    return VmmPyc_MemRead(self->dwPID, "VirtualMemory.read()", args);
}

// (ULONG64, DWORD, (ULONG64)) -> PBYTE
static PyObject*
VmmPycVirtualMemory_read_scatter(PyObj_VirtualMemory *self, PyObject *args)
{
    if(!self->fValid) { return PyErr_Format(PyExc_RuntimeError, "VirtualMemory.read_scatter(): Not initialized."); }
    return VmmPyc_MemReadScatter(self->dwPID, "VirtualMemory.read_scatter()", args);
}

// (ULONG64, PBYTE) -> None
static PyObject*
VmmPycVirtualMemory_write(PyObj_VirtualMemory *self, PyObject *args)
{
    if(!self->fValid) { return PyErr_Format(PyExc_RuntimeError, "VirtualMemory.write(): Not initialized."); }
    return VmmPyc_MemWrite(self->dwPID, "VirtualMemory.write()", args);
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
    result = VMMDLL_MemVirt2Phys(self->dwPID, va, &pa);
    Py_END_ALLOW_THREADS;
    if(!result) { return PyErr_Format(PyExc_RuntimeError, "VirtualMemory.virt2phys(): Failed."); }
    return PyLong_FromUnsignedLongLong(pa);
}

//-----------------------------------------------------------------------------
// VmmPycVirtualMemory INITIALIZATION AND CORE FUNCTIONALITY BELOW:
//-----------------------------------------------------------------------------

PyObj_VirtualMemory*
VmmPycVirtualMemory_InitializeInternal(_In_ DWORD dwPID)
{
    PyObj_VirtualMemory *pyObj;
    if(!(pyObj = PyObject_New(PyObj_VirtualMemory, (PyTypeObject*)g_pPyType_VirtualMemory))) { return NULL; }
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
}

_Success_(return)
BOOL VmmPycVirtualMemory_InitializeType(PyObject *pModule)
{
    static PyMethodDef PyMethods[] = {
        {"virt2phys", (PyCFunction)VmmPycVirtualMemory_virt2phys, METH_VARARGS, "Translate virtual address to physical address."},
        {"read", (PyCFunction)VmmPycVirtualMemory_read, METH_VARARGS, "Read contigious virtual memory."},
        {"read_scatter", (PyCFunction)VmmPycVirtualMemory_read_scatter, METH_VARARGS, "Read scatter virtual 4kB memory pages."},
        {"write", (PyCFunction)VmmPycVirtualMemory_write, METH_VARARGS, "Write contigious virtual memory."},
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
