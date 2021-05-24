// vmmpyc_module.c : implementation of the modules functionality for vmmpyc.
//
// (c) Ulf Frisk, 2021
// Author: Ulf Frisk, pcileech@frizk.net
//
#include "vmmpyc.h"

PyObject *g_pPyType_Module = NULL;

// (STR) -> ULONG64
static PyObject*
VmmPycModule_procaddress(PyObj_Module *self, PyObject *args)
{
    ULONG64 va;
    LPSTR uszProcName = NULL;
    if(!self->fValid) { return PyErr_Format(PyExc_RuntimeError, "Module.procaddress(): Not initialized."); }
    if(!PyArg_ParseTuple(args, "s", &uszProcName) || !uszProcName) {
        return PyErr_Format(PyExc_RuntimeError, "Module.procaddress(): Illegal argument.");
    }
    Py_BEGIN_ALLOW_THREADS;
    va = VMMDLL_ProcessGetProcAddressU(self->dwPID, self->ModuleEntry.uszText, uszProcName);
    Py_END_ALLOW_THREADS;
    return va ?
        PyLong_FromUnsignedLongLong(va) :
        PyErr_Format(PyExc_RuntimeError, "Module.procaddress(): Failed.");
}

// -> MyObj_Pdb
static PyObject*
VmmPycModule_pdb(PyObj_Module *self, void *closure)
{
    PyObject *pyObjPdb;
    if(!self->fValid) { return PyErr_Format(PyExc_RuntimeError, "Module.pdb: Not initialized."); }
    pyObjPdb = (PyObject *)VmmPycPdb_InitializeInternal1(self->dwPID, self->ModuleEntry.vaBase);
    return pyObjPdb ? pyObjPdb : PyErr_Format(PyExc_RuntimeError, "Module.pdb: Not initialized.");
}

// -> *PyObj_ModuleMaps
static PyObject*
VmmPycModule_maps(PyObj_Module *self, void *closure)
{
    if(!self->fValid) { return PyErr_Format(PyExc_RuntimeError, "Module.maps: Not initialized."); }
    return (PyObject*)VmmPycModuleMaps_InitializeInternal(self->dwPID, self->ModuleEntry.uszText);
}

// -> PyObj_Process
static PyObject*
VmmPycModule_process(PyObj_Module *self, void *closure)
{
    if(!self->fValid) { return PyErr_Format(PyExc_RuntimeError, "Module.process: Not initialized."); }
    return (PyObject*)VmmPycProcess_InitializeInternal(self->dwPID, FALSE);
}

// -> STR
static PyObject*
VmmPycModule_name(PyObj_Module *self, void *closure)
{
    if(!self->fValid) { return PyErr_Format(PyExc_RuntimeError, "Module.name: Not initialized."); }
    return PyUnicode_FromString(self->ModuleEntry.uszText);
}

// -> STR
static PyObject*
VmmPycModule_fullname(PyObj_Module *self, void *closure)
{
    if(!self->fValid) { return PyErr_Format(PyExc_RuntimeError, "Module.fullname: Not initialized."); }
    return PyUnicode_FromString(self->ModuleEntry.uszFullName);
}

//-----------------------------------------------------------------------------
// VmmPycModule INITIALIZATION AND CORE FUNCTIONALITY BELOW:
//-----------------------------------------------------------------------------

PyObj_Module*
VmmPycModule_InitializeInternal(_In_ DWORD dwPID, _In_ PVMMDLL_MAP_MODULEENTRY pe)
{
    PyObj_Module *pyM;
    if(!(pyM = PyObject_New(PyObj_Module, (PyTypeObject*)g_pPyType_Module))) { return NULL; }
    pyM->fValid = TRUE;
    pyM->dwPID = dwPID;
    memcpy(&pyM->ModuleEntry, pe, sizeof(VMMDLL_MAP_MODULEENTRY));
    strncpy_s(pyM->uszText, _countof(pyM->uszText), pe->uszText, _TRUNCATE);
    strncpy_s(pyM->uszFullName, _countof(pyM->uszFullName), pe->uszFullName, _TRUNCATE);
    pyM->ModuleEntry.uszText = pyM->uszText;
    pyM->ModuleEntry.uszFullName = pyM->uszFullName;
    return pyM;
}

static PyObject*
VmmPycModule_repr(PyObj_Module *self)
{
    PyObject *pyStr, *pyModuleName;
    if(!self->fValid) { return PyUnicode_FromFormat("Module:NotValid"); }
    pyModuleName = PyUnicode_FromString(self->ModuleEntry.uszText);
    pyStr = PyUnicode_FromFormat("Module:%i:%U", self->dwPID, pyModuleName);
    Py_XDECREF(pyModuleName);
    return pyStr;
}

static int
VmmPycModule_init(PyObj_Module *self, PyObject *args, PyObject *kwds)
{
    PyErr_SetString(PyExc_TypeError, "Module.init(): Not allowed.");
    return -1;
}

static void
VmmPycModule_dealloc(PyObj_Module *self)
{
    self->fValid = FALSE;
}

_Success_(return)
BOOL VmmPycModule_InitializeType(PyObject *pModule)
{
    static PyMethodDef PyMethods[] = {
        {"procaddress", (PyCFunction)VmmPycModule_procaddress, METH_VARARGS, "Retrieve the address of a given exported function."},
        {NULL, NULL, 0, NULL}
    };
    static PyMemberDef PyMembers[] = {
        {"base", T_ULONGLONG, offsetof(PyObj_Module, ModuleEntry.vaBase), READONLY, "Module base address."},
        {"entry", T_ULONGLONG, offsetof(PyObj_Module, ModuleEntry.vaEntry), READONLY, "Module entry point address."},
        {"image_size", T_ULONG, offsetof(PyObj_Module, ModuleEntry.cbImageSize), READONLY, "Module image size (in memory)."},
        {"file_size", T_ULONG, offsetof(PyObj_Module, ModuleEntry.cbFileSizeRaw), READONLY, "Module file size (on disk)."},
        {"is_wow64", T_BOOL, offsetof(PyObj_Module, ModuleEntry.fWoW64), READONLY, "Module is Wow64 (32-bit module on 64-bit Windows)."},
        {"count_section", T_ULONG, offsetof(PyObj_Module, ModuleEntry.cSection), READONLY, "Number of sections in module PE header."},
        {"count_eat", T_ULONG, offsetof(PyObj_Module, ModuleEntry.cEAT), READONLY, "Number of exported functions."},
        {"count_iat", T_ULONG, offsetof(PyObj_Module, ModuleEntry.cIAT), READONLY, "Number of imported functions."},
        {NULL}
    };
    static PyGetSetDef PyGetSet[] = {
        {"process", (getter)VmmPycModule_process, (setter)NULL, "Process.", NULL},
        {"name", (getter)VmmPycModule_name, (setter)NULL, "Module name.", NULL},
        {"fullname", (getter)VmmPycModule_fullname, (setter)NULL, "Module full name.", NULL},
        {"maps", (getter)VmmPycModule_maps, (setter)NULL, "Info maps.", NULL},
        {"pdb", (getter)VmmPycModule_pdb, (setter)NULL, "PDB symbols.", NULL},
        {NULL}
    };
    static PyType_Slot PyTypeSlot[] = {
        {Py_tp_init, VmmPycModule_init},
        {Py_tp_dealloc, VmmPycModule_dealloc},
        {Py_tp_repr, VmmPycModule_repr},
        {Py_tp_methods, PyMethods},
        {Py_tp_members, PyMembers},
        {Py_tp_getset, PyGetSet},
        {0, 0}
    };
    static PyType_Spec PyTypeSpec = {
        .name = "vmmpyc.VmmModule",
        .basicsize = sizeof(PyObj_Module),
        .itemsize = 0,
        .flags = Py_TPFLAGS_DEFAULT,
        .slots = PyTypeSlot,
    };
    if((g_pPyType_Module = PyType_FromSpec(&PyTypeSpec))) {
        if(PyModule_AddObject(pModule, "VmmModule", g_pPyType_Module) < 0) {
            Py_DECREF(g_pPyType_Module);
            g_pPyType_Module = NULL;
        }
    }
    return g_pPyType_Module ? TRUE : FALSE;
}
