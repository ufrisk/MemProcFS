// vmmpyc_pdb.c : implementation of debug symbol (pbd) functionality for vmmpyc.
//
// (c) Ulf Frisk, 2021-2023
// Author: Ulf Frisk, pcileech@frizk.net
//
#include "vmmpyc.h"

PyObject *g_pPyType_Pdb = NULL;

// (DWORD) -> {}
static PyObject*
VmmPycPdb_symbol_name(PyObj_Pdb *self, PyObject *args)
{
    PyObject *pyDict;
    BOOL result;
    CHAR szSymbolName[MAX_PATH];
    DWORD dwSymbolDisplacement;
    QWORD cbSymbolAddressOrOffset;
    if(!self->fValid) { return PyErr_Format(PyExc_RuntimeError, "Pdb.symbol_name(): Not initialized."); }
    if(!PyArg_ParseTuple(args, "K", &cbSymbolAddressOrOffset)) {
        return PyErr_Format(PyExc_RuntimeError, "Pdb.symbol_name(): Illegal argument.");
    }
    Py_BEGIN_ALLOW_THREADS;
    result = VMMDLL_PdbSymbolName(self->pyVMM->hVMM, self->szModule, cbSymbolAddressOrOffset, szSymbolName, &dwSymbolDisplacement);
    Py_END_ALLOW_THREADS;
    if(!result) {
        return PyErr_Format(PyExc_RuntimeError, "Pdb.symbol_name(): Failed.");
    }
    if((pyDict = PyDict_New())) {
        PyDict_SetItemString_DECREF(pyDict, "symbol", PyUnicode_FromFormat("%s", szSymbolName));
        PyDict_SetItemString_DECREF(pyDict, "displacement", PyLong_FromUnsignedLong(dwSymbolDisplacement));
    }
    return pyDict;
}

// (STR) -> ULONG64
static PyObject*
VmmPycPdb_symbol_address(PyObj_Pdb *self, PyObject *args)
{
    BOOL result;
    ULONG64 vaSymbol;
    LPSTR uszTypeName = NULL;
    if(!self->fValid) { return PyErr_Format(PyExc_RuntimeError, "Pdb.symbol_address(): Not initialized."); }
    if(!PyArg_ParseTuple(args, "s", &uszTypeName) || !uszTypeName) {
        return PyErr_Format(PyExc_RuntimeError, "Pdb.symbol_address(): Illegal argument.");
    }
    Py_BEGIN_ALLOW_THREADS;
    result = VMMDLL_PdbSymbolAddress(self->pyVMM->hVMM, self->szModule, uszTypeName, &vaSymbol);
    Py_END_ALLOW_THREADS;
    if(!result) {
        return PyErr_Format(PyExc_RuntimeError, "Pdb.symbol_address(): Failed.");
    }
    return PyLong_FromUnsignedLongLong(vaSymbol);
}

// (STR) -> ULONG
static PyObject*
VmmPycPdb_type_size(PyObj_Pdb *self, PyObject *args)
{
    BOOL result;
    DWORD dwSize;
    LPSTR uszTypeName = NULL;
    if(!self->fValid) { return PyErr_Format(PyExc_RuntimeError, "Pdb.type_size(): Not initialized."); }
    if(!PyArg_ParseTuple(args, "s", &uszTypeName) || !uszTypeName) {
        return PyErr_Format(PyExc_RuntimeError, "Pdb.type_size(): Illegal argument.");
    }
    Py_BEGIN_ALLOW_THREADS;
    result = VMMDLL_PdbTypeSize(self->pyVMM->hVMM, self->szModule, uszTypeName, &dwSize);
    Py_END_ALLOW_THREADS;
    if(!result) {
        return PyErr_Format(PyExc_RuntimeError, "Pdb.type_size(): Failed.");
    }
    return PyLong_FromUnsignedLong(dwSize);
}

// (STR, WSTR) -> ULONG
static PyObject*
VmmPycPdb_type_child_offset(PyObj_Pdb *self, PyObject *args)
{
    BOOL result;
    DWORD dwChildOffset;
    LPSTR uszTypeName = NULL;
    LPSTR uszTypeChildName = NULL;
    if(!self->fValid) { return PyErr_Format(PyExc_RuntimeError, "Pdb.type_child_offset(): Not initialized."); }
    if(!PyArg_ParseTuple(args, "ss", &uszTypeName, &uszTypeChildName) || !uszTypeName || !uszTypeChildName) {
        return PyErr_Format(PyExc_RuntimeError, "Pdb.type_child_offset(): Illegal argument.");
    }
    Py_BEGIN_ALLOW_THREADS;
    result = VMMDLL_PdbTypeChildOffset(self->pyVMM->hVMM, self->szModule, uszTypeName, uszTypeChildName, &dwChildOffset);
    Py_END_ALLOW_THREADS;
    if(!result) {
        return PyErr_Format(PyExc_RuntimeError, "Pdb.type_child_offset(): Failed.");
    }
    return PyLong_FromUnsignedLong(dwChildOffset);
}

//-----------------------------------------------------------------------------
// VmmPycPdb INITIALIZATION AND CORE FUNCTIONALITY BELOW:
//-----------------------------------------------------------------------------

PyObj_Pdb*
VmmPycPdb_InitializeInternal2(_In_ PyObj_Vmm *pyVMM, _In_ LPSTR szModule)
{
    PyObj_Pdb *pyObjPdb;
    if(!(pyObjPdb = PyObject_New(PyObj_Pdb, (PyTypeObject*)g_pPyType_Pdb))) { return NULL; }
    strncpy_s(pyObjPdb->szModule, MAX_PATH, szModule, _TRUNCATE);
    Py_INCREF(pyVMM); pyObjPdb->pyVMM = pyVMM;
    pyObjPdb->fValid = TRUE;
    return pyObjPdb;
}

PyObj_Pdb*
VmmPycPdb_InitializeInternal1(_In_ PyObj_Vmm *pyVMM, _In_ DWORD dwPID, _In_ QWORD vaModuleBase)
{
    BOOL result;
    CHAR szModule[MAX_PATH];
    Py_BEGIN_ALLOW_THREADS;
    result = VMMDLL_PdbLoad(pyVMM->hVMM, dwPID, vaModuleBase, szModule);
    Py_END_ALLOW_THREADS;
    if(!result) { return NULL; }
    return VmmPycPdb_InitializeInternal2(pyVMM, szModule);
}

static PyObject*
VmmPycPdb_repr(PyObj_Pdb *self)
{
    if(!self->fValid) { return PyUnicode_FromFormat("Pdb:NotValid"); }
    return PyUnicode_FromFormat("Pdb:%s", self->szModule);
}

static int
VmmPycPdb_init(PyObj_Pdb *self, PyObject *args, PyObject *kwds)
{
    PyErr_SetString(PyExc_TypeError, "Pdb.init(): Not allowed.");
    return -1;
}

static void
VmmPycPdb_dealloc(PyObj_Pdb *self)
{
    self->fValid = FALSE;
    Py_XDECREF(self->pyVMM);
    PyObject_Del(self);
}

_Success_(return)
BOOL VmmPycPdb_InitializeType(PyObject *pModule)
{
    static PyMethodDef PyMethods[] = {
        {"symbol_name", (PyCFunction)VmmPycPdb_symbol_name, METH_VARARGS, "symbol offset to symbol name"},
        {"symbol_address", (PyCFunction)VmmPycPdb_symbol_address, METH_VARARGS, "symbol name to address"},
        {"type_size", (PyCFunction)VmmPycPdb_type_size, METH_VARARGS, "type name to size"},
        {"type_child_offset", (PyCFunction)VmmPycPdb_type_child_offset, METH_VARARGS, "type name and type-child to offset"},
        {NULL, NULL, 0, NULL}
    };
    static PyMemberDef PyMembers[] = {
        {"module", T_STRING_INPLACE, offsetof(PyObj_Pdb, szModule), READONLY, "module"},
        {NULL}
    };
    static PyGetSetDef PyGetSet[] = {
        {NULL}
    };
    static PyType_Slot PyTypeSlot[] = {
        {Py_tp_init, VmmPycPdb_init},
        {Py_tp_dealloc, VmmPycPdb_dealloc},
        {Py_tp_repr, VmmPycPdb_repr},
        {Py_tp_methods, PyMethods},
        {Py_tp_members, PyMembers},
        {Py_tp_getset, PyGetSet},
        {0, 0}
    };
    static PyType_Spec PyTypeSpec = {
        .name = "vmmpyc.VmmPdb",
        .basicsize = sizeof(PyObj_Pdb),
        .itemsize = 0,
        .flags = Py_TPFLAGS_DEFAULT,
        .slots = PyTypeSlot,
    };
    if((g_pPyType_Pdb = PyType_FromSpec(&PyTypeSpec))) {
        if(PyModule_AddObject(pModule, "VmmPdb", g_pPyType_Pdb) < 0) {
            Py_DECREF(g_pPyType_Pdb);
            g_pPyType_Pdb = NULL;
        }
    }
    return g_pPyType_Pdb ? TRUE : FALSE;
}
