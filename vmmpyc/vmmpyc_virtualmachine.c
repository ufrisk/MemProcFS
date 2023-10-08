// vmmpyc_virtualmachine.c : implementation of virtual machine functionality vmmpyc.
//
// (c) Ulf Frisk, 2022-2023
// Author: Ulf Frisk, pcileech@frizk.net
//
#include "vmmpyc.h"

PyObject *g_pPyType_VirtualMachine = NULL;

// (ULONG64, DWORD) -> PBYTE
PyObject *VmmPycVirtualMachine_read(PyObj_VirtualMachine *self, PyObject *args)
{
    PyObject *pyBytes;
    BOOL result;
    PBYTE pb;
    DWORD cb;
    ULONG64 qwGPA;
    if(!self->fValid) { return PyErr_Format(PyExc_RuntimeError, "VirtualMachine.read(): Not initialized."); }
    if(!self->eVM.fActive) { return PyErr_Format(PyExc_RuntimeError, "VirtualMachine.read(): Not allowed inactive VM."); }
    if(!PyArg_ParseTuple(args, "Kk", &qwGPA, &cb)) {
        return PyErr_Format(PyExc_RuntimeError, "VirtualMachine.read(): Illegal argument.");
    }
    pb = LocalAlloc(0, cb);
    if(!pb) { return PyErr_NoMemory(); }
    Py_BEGIN_ALLOW_THREADS;
    result = VMMDLL_VmMemRead(self->pyVMM->hVMM, self->eVM.hVM, qwGPA, pb, cb);
    Py_END_ALLOW_THREADS;
    if(!result) {
        LocalFree(pb);
        return PyErr_Format(PyExc_RuntimeError, "VirtualMachine.read(): Failed.");
    }
    pyBytes = PyBytes_FromStringAndSize((const char *)pb, cb);
    LocalFree(pb);
    return pyBytes;
}

// (ULONG64, PBYTE) -> None
PyObject *VmmPycVirtualMachine_write(PyObj_VirtualMachine *self, PyObject *args)
{
    BOOL result;
    ULONG64 qwGPA;
    DWORD cb;
    PBYTE pb;
    if(!self->fValid) { return PyErr_Format(PyExc_RuntimeError, "VirtualMachine.write(): Not initialized."); }
    if(!self->eVM.fActive) { return PyErr_Format(PyExc_RuntimeError, "VirtualMachine.write(): Not allowed inactive VM."); }
    if(!PyArg_ParseTuple(args, "Ky#", &qwGPA, &pb, &cb)) {
        return PyErr_Format(PyExc_RuntimeError, "%VirtualMachine.write(): Illegal argument.");
    }
    if(cb == 0) {
        return Py_BuildValue("s", NULL);    // zero-byte write is always successful.
    }
    Py_BEGIN_ALLOW_THREADS;
    result = VMMDLL_VmMemWrite(self->pyVMM->hVMM, self->eVM.hVM, qwGPA, pb, cb);
    Py_END_ALLOW_THREADS;
    if(!result) { return PyErr_Format(PyExc_RuntimeError, "%VirtualMachine.write(): Failed."); }
    return Py_BuildValue("s", NULL);        // None returned on success.
}

// () -> PyObj_ScatterMemory
static PyObject*
VmmPycVirtualMachine_scatter_initialize(PyObj_VirtualMachine *self, PyObject *args)
{
    if(!self->fValid) { return PyErr_Format(PyExc_RuntimeError, "VirtualMachine.scatter_initialize(): Not initialized."); }
    if(!self->eVM.fActive) { return PyErr_Format(PyExc_RuntimeError, "VirtualMachine.Vmm(): Not allowed inactive VM."); }
    return (PyObject*)VmmPycScatterMemory_InitializeInternal(self->pyVMM, self->eVM.hVM, 0, 0);
}

// () -> PyObj_Vmm
static PyObject*
VmmPycVirtualMachine_Vmm(PyObj_VirtualMachine *self, PyObject *args)
{
    VMM_HANDLE hVMM = NULL;
    if(!self->fValid) { return PyErr_Format(PyExc_RuntimeError, "VirtualMachine.Vmm(): Not initialized."); }
    if(!self->eVM.fActive) { return PyErr_Format(PyExc_RuntimeError, "VirtualMachine.Vmm(): Not allowed inactive VM."); }
    if(self->eVM.fPhysicalOnly) { return PyErr_Format(PyExc_RuntimeError, "VirtualMachine.Vmm(): Not allowed on physical memory only VM."); }
    Py_BEGIN_ALLOW_THREADS;
    hVMM = VMMDLL_VmGetVmmHandle(self->pyVMM->hVMM, self->eVM.hVM);
    Py_END_ALLOW_THREADS;
    if(!hVMM) { return PyErr_Format(PyExc_RuntimeError, "VirtualMachine.Vmm(): Initialization of VMM failed."); }
    return (PyObject*)VmmPycVmm_InitializeInternal2(self->pyVMM, hVMM);
}

// -> BOOL
static PyObject*
VmmPycVirtualMachine_is_active(PyObj_VirtualMachine *self, void *closure)
{
    if(!self->fValid) { return PyErr_Format(PyExc_RuntimeError, "VirtualMachine.is_active: Not initialized."); }
    return PyBool_FromLong((long)self->eVM.fActive);
}

// -> BOOL
static PyObject*
VmmPycVirtualMachine_is_physical(PyObj_VirtualMachine *self, void *closure)
{
    if(!self->fValid) { return PyErr_Format(PyExc_RuntimeError, "VirtualMachine.is_physical: Not initialized."); }
    return PyBool_FromLong((long)self->eVM.fPhysicalOnly);
}

// -> BOOL
static PyObject*
VmmPycVirtualMachine_is_readonly(PyObj_VirtualMachine *self, void *closure)
{
    if(!self->fValid) { return PyErr_Format(PyExc_RuntimeError, "VirtualMachine.readonly: Not initialized."); }
    return PyBool_FromLong((long)self->eVM.fReadOnly);
}

// -> QWORD
static PyObject*
VmmPycVirtualMachine_max_memory(PyObj_VirtualMachine *self, PyObject *args)
{
    if(!self->fValid) { return PyErr_Format(PyExc_RuntimeError, "VirtualMachine.max_memory: Not initialized."); }
    return PyLong_FromUnsignedLongLong(self->eVM.gpaMax);
}

// -> STR
static PyObject*
VmmPycVirtualMachine_name(PyObj_VirtualMachine *self, void *closure)
{
    if(!self->fValid) { return PyErr_Format(PyExc_RuntimeError, "VirtualMachine.name: Not initialized."); }
    Py_INCREF(self->pyName);
    return self->pyName;
}

// -> DWORD
static PyObject*
VmmPycVirtualMachine_os_build(PyObj_VirtualMachine *self, PyObject *args)
{
    if(!self->fValid) { return PyErr_Format(PyExc_RuntimeError, "VirtualMachine.os_build: Not initialized."); }
    return PyLong_FromUnsignedLong(self->eVM.dwVersionBuild);
}

// -> DWORD
static PyObject*
VmmPycVirtualMachine_type(PyObj_VirtualMachine *self, PyObject *args)
{
    if(!self->fValid) { return PyErr_Format(PyExc_RuntimeError, "VirtualMachine.type: Not initialized."); }
    return PyLong_FromUnsignedLong(self->eVM.tp);
}

//-----------------------------------------------------------------------------
// VmmPycVirtualMachine INITIALIZATION AND CORE FUNCTIONALITY BELOW:
//-----------------------------------------------------------------------------

PyObj_VirtualMachine*
VmmPycVirtualMachine_InitializeInternal(_In_ PyObj_Vmm *pyVMM, _In_ PVMMDLL_MAP_VMENTRY pVM)
{
    PyObj_VirtualMachine *pyObj;
    if(!(pyObj = PyObject_New(PyObj_VirtualMachine, (PyTypeObject*)g_pPyType_VirtualMachine))) { return NULL; }
    Py_INCREF(pyVMM); pyObj->pyVMM = pyVMM;
    pyObj->pyName = PyUnicode_FromString(pVM->uszName);
    memcpy(&pyObj->eVM, pVM, sizeof(VMMDLL_MAP_VMENTRY));
    pyObj->eVM.uszName = NULL;
    pyObj->fValid = TRUE;
    return pyObj;
}

static PyObject*
VmmPycVirtualMachine_repr(PyObj_VirtualMachine *self)
{
    return PyUnicode_FromFormat(self->fValid ? "VirtualMachine" : "VirtualMachine:NotValid");
}

static int
VmmPycVirtualMachine_init(PyObj_VirtualMachine *self, PyObject *args, PyObject *kwds)
{
    PyErr_SetString(PyExc_TypeError, "VirtualMachine.init(): Not allowed.");
    return -1;
}

static void
VmmPycVirtualMachine_dealloc(PyObj_VirtualMachine *self)
{
    self->fValid = FALSE;
    Py_XDECREF(self->pyName);
    Py_XDECREF(self->pyVMM);
    PyObject_Del(self);
}

_Success_(return)
BOOL VmmPycVirtualMachine_InitializeType(PyObject *pModule)
{
    static PyMethodDef PyMethods[] = {
        {"read", (PyCFunction)VmmPycVirtualMachine_read, METH_VARARGS, "Read virtual machone guest physical memory."},
        {"scatter_initialize", (PyCFunction)VmmPycVirtualMachine_scatter_initialize, METH_VARARGS, "Initialize a Scatter memory object used for efficient reads."},
        {"write", (PyCFunction)VmmPycVirtualMachine_write, METH_VARARGS, "Write virtual machone guest physical memory."},
        {"Vmm", (PyCFunction)VmmPycVirtualMachine_Vmm, METH_VARARGS, "Initialize a new Vmm object representing the virtual machine."},
        {NULL, NULL, 0, NULL}
    };
    static PyMemberDef PyMembers[] = {
        {NULL}
    };
    static PyGetSetDef PyGetSet[] = {
        {"is_active", (getter)VmmPycVirtualMachine_is_active, (setter)NULL, "Is VM active?", NULL},
        {"is_physical", (getter)VmmPycVirtualMachine_is_physical, (setter)NULL, "Is VM physical memory only?", NULL},
        {"is_readonly", (getter)VmmPycVirtualMachine_is_readonly, (setter)NULL, "Is VM read-only?", NULL},
        {"max_memory", (getter)VmmPycVirtualMachine_max_memory, (setter)NULL, "Retrieve the VM maximum guest physical address.", NULL},
        {"name", (getter)VmmPycVirtualMachine_name, (setter)NULL, "VM name.", NULL},
        {"os_build", (getter)VmmPycVirtualMachine_os_build, (setter)NULL, "Operating system build.", NULL},
        {"type", (getter)VmmPycVirtualMachine_type, (setter)NULL, "Virtual machine type (VMMDLL_VM_TP_*)", NULL},
        {NULL}
    };
    static PyType_Slot PyTypeSlot[] = {
        {Py_tp_init, VmmPycVirtualMachine_init},
        {Py_tp_dealloc, VmmPycVirtualMachine_dealloc},
        {Py_tp_repr, VmmPycVirtualMachine_repr},
        {Py_tp_methods, PyMethods},
        {Py_tp_members, PyMembers},
        {Py_tp_getset, PyGetSet},
        {0, 0}
    };
    static PyType_Spec PyTypeSpec = {
        .name = "vmmpyc.VmmVirtualMachine",
        .basicsize = sizeof(PyObj_VirtualMachine),
        .itemsize = 0,
        .flags = Py_TPFLAGS_DEFAULT,
        .slots = PyTypeSlot,
    };
    if((g_pPyType_VirtualMachine = PyType_FromSpec(&PyTypeSpec))) {
        if(PyModule_AddObject(pModule, "VmmVirtualMachine", g_pPyType_VirtualMachine) < 0) {
            Py_DECREF(g_pPyType_VirtualMachine);
            g_pPyType_VirtualMachine = NULL;
        }
    }
    return g_pPyType_VirtualMachine ? TRUE : FALSE;
}
