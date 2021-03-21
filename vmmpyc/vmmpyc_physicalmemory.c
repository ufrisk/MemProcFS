// vmmpyc_physicalmemory.c : implementation or physical memory.
//
// (c) Ulf Frisk, 2021
// Author: Ulf Frisk, pcileech@frizk.net
//
#include "vmmpyc.h"

PyObject *g_pPyType_PhysicalMemory = NULL;

// ([DWORD], (DWORD)) -> [{...}]
static PyObject *
VmmPycPhysicalMemory_read(PyObj_PhysicalMemory *self, PyObject *args)
{
    if(!self->fValid) { return PyErr_Format(PyExc_RuntimeError, "PhysicalMemory.read(): Not initialized."); }
    return VmmPyc_MemRead((DWORD)-1, "PhysicalMemory.read()", args);
}

// (ULONG64, DWORD, (ULONG64)) -> PBYTE
static PyObject *
VmmPycPhysicalMemory_read_scatter(PyObj_PhysicalMemory *self, PyObject *args)
{
    if(!self->fValid) { return PyErr_Format(PyExc_RuntimeError, "PhysicalMemory.read_scatter(): Not initialized."); }
    return VmmPyc_MemReadScatter((DWORD)-1, "PhysicalMemory.read_scatter()", args);
}

// (ULONG64, PBYTE) -> None
static PyObject *
VmmPycPhysicalMemory_write(PyObj_PhysicalMemory *self, PyObject *args)
{
    if(!self->fValid) { return PyErr_Format(PyExc_RuntimeError, "PhysicalMemory.write(): Not initialized."); }
    return VmmPyc_MemWrite((DWORD)-1, "PhysicalMemory.write()", args);
}

//-----------------------------------------------------------------------------
// VmmPycPhysicalMemory INITIALIZATION AND CORE FUNCTIONALITY BELOW:
//-----------------------------------------------------------------------------

PyObj_PhysicalMemory*
VmmPycPhysicalMemory_InitializeInternal()
{
    PyObj_PhysicalMemory *pyObj;
    if(!(pyObj = PyObject_New(PyObj_PhysicalMemory, (PyTypeObject *)g_pPyType_PhysicalMemory))) { return NULL; }
    pyObj->fValid = TRUE;
    return pyObj;
}

static PyObject*
VmmPycPhysicalMemory_repr(PyObj_PhysicalMemory *self)
{
    return PyUnicode_FromFormat(self->fValid ? "PhysicalMemory" : "PhysicalMemory:NotValid");
}

static int
VmmPycPhysicalMemory_init(PyObj_PhysicalMemory *self, PyObject *args, PyObject *kwds)
{
    PyErr_SetString(PyExc_TypeError, "PhysicalMemory.init(): Not allowed.");
    return -1;
}

static void
VmmPycPhysicalMemory_dealloc(PyObj_PhysicalMemory *self)
{
    self->fValid = FALSE;
}

_Success_(return)
BOOL VmmPycPhysicalMemory_InitializeType(PyObject * pModule)
{
    static PyMethodDef PyMethods[] = {
        {"read", (PyCFunction)VmmPycPhysicalMemory_read, METH_VARARGS, "Read contigious physical memory."},
        {"read_scatter", (PyCFunction)VmmPycPhysicalMemory_read_scatter, METH_VARARGS, "Read scatter physical 4kB memory pages."},
        {"write", (PyCFunction)VmmPycPhysicalMemory_write, METH_VARARGS, "Write contigious physical memory."},
        {NULL, NULL, 0, NULL}
    };
    static PyMemberDef PyMembers[] = {
        {NULL}
    };
    static PyGetSetDef PyGetSet[] = {
        {NULL}
    };
    static PyType_Slot PyTypeSlot[] = {
        {Py_tp_init, VmmPycPhysicalMemory_init},
        {Py_tp_dealloc, VmmPycPhysicalMemory_dealloc},
        {Py_tp_repr, VmmPycPhysicalMemory_repr},
        {Py_tp_methods, PyMethods},
        {Py_tp_members, PyMembers},
        {Py_tp_getset, PyGetSet},
        {0, 0}
    };
    static PyType_Spec PyTypeSpec = {
        .name = "vmmpyc.VmmPhysicalMemory",
        .basicsize = sizeof(PyObj_PhysicalMemory),
        .itemsize = 0,
        .flags = Py_TPFLAGS_DEFAULT,
        .slots = PyTypeSlot,
    };
    if((g_pPyType_PhysicalMemory = PyType_FromSpec(&PyTypeSpec))) {
        if(PyModule_AddObject(pModule, "VmmPhysicalMemory", g_pPyType_PhysicalMemory) < 0) {
            Py_DECREF(g_pPyType_PhysicalMemory);
            g_pPyType_PhysicalMemory = NULL;
        }
    }
    return g_pPyType_PhysicalMemory ? TRUE : FALSE;
}
