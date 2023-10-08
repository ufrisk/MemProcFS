// vmmpyc_reghive.c : implementation of registry hive functionality for vmmpyc.
//
// (c) Ulf Frisk, 2021-2023
// Author: Ulf Frisk, pcileech@frizk.net
//
#include "vmmpyc.h"

PyObject *g_pPyType_RegHive = NULL;

// -> ObjRegKey
static PyObject*
VmmPycRegHive_rootkey(PyObj_RegHive *self, PyObject *args)
{
    CHAR uszPathKey[MAX_PATH];
    if(!self->fValid) { return PyErr_Format(PyExc_RuntimeError, "RegHive.rootkey: Not initialized."); }
    _snprintf_s(uszPathKey, sizeof(uszPathKey), _TRUNCATE, "0x%016llx\\ROOT", self->Info.vaCMHIVE);
    return (PyObject*)VmmPycRegKey_InitializeInternal(self->pyVMM, uszPathKey, FALSE);
}

// -> ObjRegKey
static PyObject*
VmmPycRegHive_orphankey(PyObj_RegHive *self, PyObject *args)
{
    CHAR uszPathKey[MAX_PATH];
    if(!self->fValid) { return PyErr_Format(PyExc_RuntimeError, "RegHive.orphankey: Not initialized."); }
    _snprintf_s(uszPathKey, sizeof(uszPathKey), _TRUNCATE, "0x%016llx\\ORPHAN", self->Info.vaCMHIVE);
    return (PyObject*)VmmPycRegKey_InitializeInternal(self->pyVMM, uszPathKey, FALSE);
}

// -> *PyObj_RegMemory
static PyObject*
VmmPycRegHive_memory(PyObj_RegHive *self, void *closure)
{
    if(!self->fValid) { return PyErr_Format(PyExc_RuntimeError, "RegHive.memory: Not initialized."); }
    return (PyObject*)VmmPycRegMemory_InitializeInternal(self->pyVMM, self->Info.vaCMHIVE);
}

//-----------------------------------------------------------------------------
// VmmPycRegHive INITIALIZATION AND CORE FUNCTIONALITY BELOW:
//-----------------------------------------------------------------------------

PyObj_RegHive*
VmmPycRegHive_InitializeInternal(_In_ PyObj_Vmm *pyVMM, _In_ PVMMDLL_REGISTRY_HIVE_INFORMATION pInfo)
{
    PyObj_RegHive *pyObj;
    if(!(pyObj = PyObject_New(PyObj_RegHive, (PyTypeObject*)g_pPyType_RegHive))) { return NULL; }
    Py_INCREF(pyVMM); pyObj->pyVMM = pyVMM;
    pyObj->fValid = TRUE;
    memcpy(&pyObj->Info, pInfo, sizeof(VMMDLL_REGISTRY_HIVE_INFORMATION));
    return pyObj;
}

static PyObject*
VmmPycRegHive_repr(PyObj_RegHive *self)
{
    PyObject *pyStr, *pyName;
    if(!self->fValid) { return PyUnicode_FromFormat("RegHive:NotValid"); }
    pyName = PyUnicode_FromString(self->Info.uszNameShort);
    pyStr = PyUnicode_FromFormat("RegHive:%U", pyName);
    Py_XDECREF(pyName);
    return pyStr;
}

static int
VmmPycRegHive_init(PyObj_RegHive *self, PyObject *args, PyObject *kwds)
{
    PyErr_SetString(PyExc_TypeError, "RegHive.init(): Not allowed.");
    return -1;
}

static void
VmmPycRegHive_dealloc(PyObj_RegHive *self)
{
    self->fValid = FALSE;
    Py_XDECREF(self->pyVMM);
    PyObject_Del(self);
}

_Success_(return)
BOOL VmmPycRegHive_InitializeType(PyObject *pModule)
{
    static PyMethodDef PyMethods[] = {
        {NULL, NULL, 0, NULL}
    };
    static PyMemberDef PyMembers[] = {
        {"addr", T_ULONGLONG, offsetof(PyObj_RegHive, Info.vaCMHIVE), READONLY, "Virtual address of CMHIVE."},
        {"addr_baseblock", T_ULONGLONG, offsetof(PyObj_RegHive, Info.vaHBASE_BLOCK), READONLY, "Virtual address of HBASE_BLOCK."},
        {"size", T_ULONG, offsetof(PyObj_RegHive, Info.cbLength), READONLY, "Size of hive (static part)."},
        {"name", T_STRING_INPLACE, offsetof(PyObj_RegHive, Info.uszName), READONLY, "Hive name."},
        {"name_short", T_STRING_INPLACE, offsetof(PyObj_RegHive, Info.uszNameShort), READONLY, "Short name."},
        {"path", T_STRING_INPLACE, offsetof(PyObj_RegHive, Info.uszHiveRootPath), READONLY, "Hive path."},
        {NULL}
    };
    static PyGetSetDef PyGetSet[] = {
        {"rootkey", (getter)VmmPycRegHive_rootkey, (setter)NULL, "The hive root key.", NULL},
        {"orphankey", (getter)VmmPycRegHive_orphankey, (setter)NULL, "The hive orphan key.", NULL},
        {"memory", (getter)VmmPycRegHive_memory, (setter)NULL, "The hive memory.", NULL},
        {NULL}
    };
    static PyType_Slot PyTypeSlot[] = {
        {Py_tp_init, VmmPycRegHive_init},
        {Py_tp_dealloc, VmmPycRegHive_dealloc},
        {Py_tp_repr, VmmPycRegHive_repr},
        {Py_tp_methods, PyMethods},
        {Py_tp_members, PyMembers},
        {Py_tp_getset, PyGetSet},
        {0, 0}
    };
    static PyType_Spec PyTypeSpec = {
        .name = "vmmpyc.VmmRegHive",
        .basicsize = sizeof(PyObj_RegHive),
        .itemsize = 0,
        .flags = Py_TPFLAGS_DEFAULT,
        .slots = PyTypeSlot,
    };
    if((g_pPyType_RegHive = PyType_FromSpec(&PyTypeSpec))) {
        if(PyModule_AddObject(pModule, "VmmRegHive", g_pPyType_RegHive) < 0) {
            Py_DECREF(g_pPyType_RegHive);
            g_pPyType_RegHive = NULL;
        }
    }
    return g_pPyType_RegHive ? TRUE : FALSE;
}
