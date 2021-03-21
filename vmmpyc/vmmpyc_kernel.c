// vmmpyc_kernel.c : implementation of the kernel functionality for vmmpyc.
//
// (c) Ulf Frisk, 2021
// Author: Ulf Frisk, pcileech@frizk.net
//
#include "vmmpyc.h"

PyObject *g_pPyType_Kernel = NULL;

// -> *PyObj_Process
static PyObject*
VmmPycKernel_process(PyObj_Kernel *self, void *closure)
{
    if(!self->fValid) { return PyErr_Format(PyExc_RuntimeError, "Kernel.process: Not initialized."); }
    return (PyObject*)VmmPycProcess_InitializeInternal(4, FALSE);
}

//-----------------------------------------------------------------------------
// VmmPycKernel INITIALIZATION AND CORE FUNCTIONALITY BELOW:
//-----------------------------------------------------------------------------

PyObj_Kernel*
VmmPycKernel_InitializeInternal()
{
    PyObj_Kernel *pyObjKernel;
    if(!(pyObjKernel = PyObject_New(PyObj_Kernel, (PyTypeObject*)g_pPyType_Kernel))) { return NULL; }
    pyObjKernel->fValid = TRUE;
    pyObjKernel->pyObjProcess = (PyObject*)VmmPycProcess_InitializeInternal(4, FALSE);
    pyObjKernel->pyObjPdb = (PyObject*)VmmPycPdb_InitializeInternal2("nt");
    return pyObjKernel;
}

static PyObject*
VmmPycKernel_repr(PyObj_Kernel *self)
{
    return PyUnicode_FromFormat(self->fValid ? "Kernel" : "Kernel:NotValid");
}

static int
VmmPycKernel_init(PyObj_Kernel *self, PyObject *args, PyObject *kwds)
{
    PyErr_SetString(PyExc_TypeError, "Kernel.init(): Not allowed.");
    return -1;
}

static void
VmmPycKernel_dealloc(PyObj_Kernel *self)
{
    self->fValid = FALSE;
    Py_XDECREF(self->pyObjPdb); self->pyObjPdb = NULL;
    Py_XDECREF(self->pyObjProcess); self->pyObjProcess = NULL;
}

_Success_(return)
BOOL VmmPycKernel_InitializeType(PyObject *pModule)
{
    static PyMethodDef PyMethods[] = {
        {NULL, NULL, 0, NULL}
    };
    static PyMemberDef PyMembers[] = {
        {"pdb", T_OBJECT, offsetof(PyObj_Kernel, pyObjPdb), READONLY, "pdb symbols"},
        {NULL}
    };
    static PyGetSetDef PyGetSet[] = {
        {"process", (getter)VmmPycKernel_process, (setter)NULL, "system process", NULL},
        {NULL}
    };
    static PyType_Slot PyTypeSlot[] = {
        {Py_tp_init, VmmPycKernel_init},
        {Py_tp_dealloc, VmmPycKernel_dealloc},
        {Py_tp_repr, VmmPycKernel_repr},
        {Py_tp_methods, PyMethods},
        {Py_tp_members, PyMembers},
        {Py_tp_getset, PyGetSet},
        {0, 0}
    };
    static PyType_Spec PyTypeSpec = {
        .name = "vmmpyc.VmmKernel",
        .basicsize = sizeof(PyObj_Kernel),
        .itemsize = 0,
        .flags = Py_TPFLAGS_DEFAULT,
        .slots = PyTypeSlot,
    };
    if((g_pPyType_Kernel = PyType_FromSpec(&PyTypeSpec))) {
        if(PyModule_AddObject(pModule, "VmmKernel", g_pPyType_Kernel) < 0) {
            Py_DECREF(g_pPyType_Kernel);
            g_pPyType_Kernel = NULL;
        }
    }
    return g_pPyType_Kernel ? TRUE : FALSE;
}
