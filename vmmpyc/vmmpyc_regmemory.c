// vmmpyc_regmemory.c : implementation of process registry hive memory for vmmpyc.
//
// (c) Ulf Frisk, 2021
// Author: Ulf Frisk, pcileech@frizk.net
//
#include "vmmpyc.h"

PyObject *g_pPyType_RegMemory = NULL;

// (DWORD, DWORD, (ULONG64)) -> PBYTE
static PyObject *
VmmPycRegMemory_read(PyObj_RegMemory *self, PyObject *args)
{
    PyObject *pyBytes;
    BOOL result;
    PBYTE pb;
    DWORD ra, cb, cbRead = 0;
    ULONG64 flags = 0;
    if(!self->fValid) { return PyErr_Format(PyExc_RuntimeError, "RegMemory.read(): Not initialized."); }
    if(!PyArg_ParseTuple(args, "kk|K", &ra, &cb, &flags)) {
        return PyErr_Format(PyExc_RuntimeError, "RegMemory.read(): Illegal argument.");
    }
    if(cb > 0x01000000) { return PyErr_Format(PyExc_RuntimeError, "RegMemory.read(): Read larger than maximum supported (0x01000000) bytes requested."); }
    pb = LocalAlloc(0, cb);
    if(!pb) { return PyErr_NoMemory(); }
    Py_BEGIN_ALLOW_THREADS;
    result = VMMDLL_WinReg_HiveReadEx(self->vaCMHive, ra, pb, cb, &cbRead, flags);
    Py_END_ALLOW_THREADS;
    if(!result) {
        LocalFree(pb);
        return PyErr_Format(PyExc_RuntimeError, "RegMemory.read(): Failed.");
    }
    pyBytes = PyBytes_FromStringAndSize((const char *)pb, cbRead);
    LocalFree(pb);
    return pyBytes;
}

// (DWORD, PBYTE) -> None
static PyObject *
VmmPycRegMemory_write(PyObj_RegMemory *self, PyObject *args)
{
    BOOL result;
    PBYTE pb;
    DWORD cb, ra;
    if(!self->fValid) { return PyErr_Format(PyExc_RuntimeError, "RegMemory.write(): Not initialized."); }
    if(!PyArg_ParseTuple(args, "ky#", &ra, &pb, &cb)) {
        return PyErr_Format(PyExc_RuntimeError, "RegMemory.write(): Illegal argument.");
    }
    if(cb == 0) {
        return Py_BuildValue("s", NULL);    // zero-byte write is always successful.
    }
    Py_BEGIN_ALLOW_THREADS;
    result = VMMDLL_WinReg_HiveWrite(self->vaCMHive, ra, pb, (DWORD)cb);
    Py_END_ALLOW_THREADS;
    if(!result) { return PyErr_Format(PyExc_RuntimeError, "RegMemory.write(): Failed."); }
    return Py_BuildValue("s", NULL);        // None returned on success.
}

//-----------------------------------------------------------------------------
// VmmPycRegMemory INITIALIZATION AND CORE FUNCTIONALITY BELOW:
//-----------------------------------------------------------------------------

PyObj_RegMemory*
VmmPycRegMemory_InitializeInternal(_In_ QWORD vaCMHive)
{
    PyObj_RegMemory *pyObj;
    if(!(pyObj = PyObject_New(PyObj_RegMemory, (PyTypeObject*)g_pPyType_RegMemory))) { return NULL; }
    pyObj->fValid = TRUE;
    pyObj->vaCMHive = vaCMHive;
    return pyObj;
}

static PyObject*
VmmPycRegMemory_repr(PyObj_RegMemory *self)
{
    return self->fValid ?
        PyUnicode_FromFormat("RegMemory:%llx", self->vaCMHive) :
        PyUnicode_FromFormat("RegMemory:NotValid");
}

static int
VmmPycRegMemory_init(PyObj_RegMemory *self, PyObject *args, PyObject *kwds)
{
    PyErr_SetString(PyExc_TypeError, "RegMemory.init(): Not allowed.");
    return -1;
}

static void
VmmPycRegMemory_dealloc(PyObj_RegMemory *self)
{
    self->fValid = FALSE;
}

_Success_(return)
BOOL VmmPycRegMemory_InitializeType(PyObject * pModule)
{
    static PyMethodDef PyMethods[] = {
        {"read", (PyCFunction)VmmPycRegMemory_read, METH_VARARGS, "Read from raw registry hive."},
        {"write", (PyCFunction)VmmPycRegMemory_write, METH_VARARGS, "Write to raw registry hive."},
        {NULL, NULL, 0, NULL}
    };
    static PyMemberDef PyMembers[] = {
        {"addr", T_ULONG, offsetof(PyObj_RegMemory, vaCMHive), READONLY, "Hive virtual address."},
        {NULL}
    };
    static PyGetSetDef PyGetSet[] = {
        {NULL}
    };
    static PyType_Slot PyTypeSlot[] = {
        {Py_tp_init, VmmPycRegMemory_init},
        {Py_tp_dealloc, VmmPycRegMemory_dealloc},
        {Py_tp_repr, VmmPycRegMemory_repr},
        {Py_tp_methods, PyMethods},
        {Py_tp_members, PyMembers},
        {Py_tp_getset, PyGetSet},
        {0, 0}
    };
    static PyType_Spec PyTypeSpec = {
        .name = "vmmpyc.VmmRegMemory",
        .basicsize = sizeof(PyObj_RegMemory),
        .itemsize = 0,
        .flags = Py_TPFLAGS_DEFAULT,
        .slots = PyTypeSlot,
    };
    if((g_pPyType_RegMemory = PyType_FromSpec(&PyTypeSpec))) {
        if(PyModule_AddObject(pModule, "VmmRegMemory", g_pPyType_RegMemory) < 0) {
            Py_DECREF(g_pPyType_RegMemory);
            g_pPyType_RegMemory = NULL;
        }
    }
    return g_pPyType_RegMemory ? TRUE : FALSE;
}
