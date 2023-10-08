// vmmpyc_regkey.c : implementation of registry key functionality for vmmpyc.
//
// (c) Ulf Frisk, 2021-2023
// Author: Ulf Frisk, pcileech@frizk.net
//
#include "vmmpyc.h"

PyObject *g_pPyType_RegKey = NULL;

static BOOL VmmPycRegKey_EnsureLastWrite(PyObj_RegKey *self)
{
    DWORD cch = 0;
    BOOL result = FALSE;
    if(!self->ftLastWrite) {
        Py_BEGIN_ALLOW_THREADS;
        result = VMMDLL_WinReg_EnumKeyExU(self->pyVMM->hVMM, self->uszPath, -1, NULL, &cch, (PFILETIME)&self->ftLastWrite);
        Py_END_ALLOW_THREADS;
    }
    return result || self->ftLastWrite;
}

// -> QWORD
static PyObject*
VmmPycRegKey_time_int(PyObj_RegKey *self, PyObject *args)
{
    if(!self->fValid) { return PyErr_Format(PyExc_RuntimeError, "RegKey.time_int(): Not initialized."); }
    if(!VmmPycRegKey_EnsureLastWrite(self)) { return PyErr_Format(PyExc_RuntimeError, "RegKey.time_int(): Failed."); }
    return PyLong_FromUnsignedLongLong(self->ftLastWrite);
}

// -> STR
static PyObject*
VmmPycRegKey_time_str(PyObj_RegKey *self, PyObject *args)
{
    CHAR szTime[24];
    if(!self->fValid) { return PyErr_Format(PyExc_RuntimeError, "RegKey.time_str(): Not initialized."); }
    if(!VmmPycRegKey_EnsureLastWrite(self)) { return PyErr_Format(PyExc_RuntimeError, "RegKey.time_str(): Failed."); }
    Util_FileTime2String(self->ftLastWrite, szTime);
    return PyUnicode_FromFormat("%s", szTime);
}

// -> [ObjRegValue, ...]
static PyObject*
VmmPycRegKey_values(PyObj_RegKey *self, void *closure)
{
    BOOL fResult;
    DWORD cch, i = 0;
    PyObject *pyList;
    CHAR usz[2 * MAX_PATH];
    LPSTR uszValueName;
    if(!self->fValid) { return PyErr_Format(PyExc_RuntimeError, "RegKey.subkeys(): Not initialized."); }
    if(!(pyList = PyList_New(0))) { return PyErr_NoMemory(); }
    strcpy_s(usz, _countof(usz), self->uszPath);
    cch = (DWORD)strlen(usz);
    usz[cch] = '\\';
    uszValueName = usz + cch + 1;
    while(TRUE) {
        Py_BEGIN_ALLOW_THREADS;
        cch = MAX_PATH;
        fResult = VMMDLL_WinReg_EnumValueU(self->pyVMM->hVMM, self->uszPath, i++, uszValueName, &cch, NULL, NULL, NULL);
        Py_END_ALLOW_THREADS;
        if(!fResult) { break; }
        PyList_Append_DECREF(pyList, (PyObject*)VmmPycRegValue_InitializeInternal(self->pyVMM, usz, FALSE));
    }
    return pyList;
}

// -> {name1: ObjRegValue1, ...}
static PyObject*
VmmPycRegKey_values_dict(PyObj_RegKey *self, void *closure)
{
    BOOL fResult;
    DWORD cch, i = 0;
    PyObject *pyDict;
    PyObj_RegValue *pyObjValue;
    CHAR usz[2 * MAX_PATH];
    LPSTR uszValueName;
    if(!self->fValid) { return PyErr_Format(PyExc_RuntimeError, "RegKey.values_dict(): Not initialized."); }
    if(!(pyDict = PyDict_New())) { return PyErr_NoMemory(); }
    strcpy_s(usz, _countof(usz), self->uszPath);
    cch = (DWORD)strlen(usz);
    usz[cch] = '\\';
    uszValueName = usz + cch + 1;
    while(TRUE) {
        Py_BEGIN_ALLOW_THREADS;
        cch = MAX_PATH;
        fResult = VMMDLL_WinReg_EnumValueU(self->pyVMM->hVMM, self->uszPath, i++, uszValueName, &cch, NULL, NULL, NULL);
        Py_END_ALLOW_THREADS;
        if(!fResult) { break; }
        if((pyObjValue = VmmPycRegValue_InitializeInternal(self->pyVMM, usz, FALSE))) {
            PyDict_SetItemUnicode_DECREF(pyDict, pyObjValue->pyName, (PyObject*)pyObjValue);
        }
    }
    return pyDict;
}

// -> [ObjRegKey, ...]
static PyObject*
VmmPycRegKey_subkeys(PyObj_RegKey *self, void *closure)
{
    BOOL fResult;
    DWORD cch, i = 0;
    PyObject *pyList;
    CHAR usz[2*MAX_PATH];
    LPSTR uszKeyName;
    if(!self->fValid) { return PyErr_Format(PyExc_RuntimeError, "RegKey.subkeys(): Not initialized."); }
    if(!(pyList = PyList_New(0))) { return PyErr_NoMemory(); }
    strcpy_s(usz, _countof(usz), self->uszPath);
    cch = (DWORD)strlen(usz);
    usz[cch] = '\\';
    uszKeyName = usz + cch + 1;
    while(TRUE) {
        Py_BEGIN_ALLOW_THREADS;
        cch = MAX_PATH;
        fResult = VMMDLL_WinReg_EnumKeyExU(self->pyVMM->hVMM, self->uszPath, i++, uszKeyName, &cch, NULL);
        Py_END_ALLOW_THREADS;
        if(!fResult) { break; }
        PyList_Append_DECREF(pyList, (PyObject*)VmmPycRegKey_InitializeInternal(self->pyVMM, usz, FALSE));
    }
    return pyList;
}

// -> {name: ObjRegKey, ...}
static PyObject*
VmmPycRegKey_subkeys_dict(PyObj_RegKey *self, void *closure)
{   
    BOOL fResult;
    DWORD cch, i = 0;
    PyObject *pyDict;
    PyObj_RegKey *pyObjKey;
    CHAR usz[2*MAX_PATH];
    LPSTR uszKeyName;
    if(!self->fValid) { return PyErr_Format(PyExc_RuntimeError, "RegKey.subkeys_dict(): Not initialized."); }
    if(!(pyDict = PyDict_New())) { return PyErr_NoMemory(); }
    strcpy_s(usz, _countof(usz), self->uszPath);
    cch = (DWORD)strlen(usz);
    usz[cch] = '\\';
    uszKeyName = usz + cch + 1;
    while(TRUE) {
        Py_BEGIN_ALLOW_THREADS;
        cch = MAX_PATH;
        fResult = VMMDLL_WinReg_EnumKeyExU(self->pyVMM->hVMM, self->uszPath, i++, uszKeyName, &cch, NULL);
        Py_END_ALLOW_THREADS;
        if(!fResult) { break; }
        if((pyObjKey = VmmPycRegKey_InitializeInternal(self->pyVMM, usz, FALSE))) {
            PyDict_SetItemUnicode_DECREF(pyDict, pyObjKey->pyName, (PyObject*)pyObjKey);
        }
    }
    return pyDict;
}

// -> ObjRegKey
static PyObject*
VmmPycRegKey_parent(PyObj_RegKey *self, void *closure)
{
    CHAR uszParentPath[2 * MAX_PATH];
    if(!self->fValid) { return PyErr_Format(PyExc_RuntimeError, "RegKey.parent: Not initialized."); }
    if(!Util_PathSplitLastEx(self->uszPath, uszParentPath, sizeof(uszParentPath))) {
        return PyErr_Format(PyExc_RuntimeError, "RegKey.parent: No parent key.");
    }
    return (PyObject*)VmmPycRegKey_InitializeInternal(self->pyVMM, uszParentPath, FALSE);
}

// -> STR
static PyObject*
VmmPycRegKey_name(PyObj_RegKey *self, void *closure)
{
    if(!self->fValid) { return PyErr_Format(PyExc_RuntimeError, "RegKey.name: Not initialized."); }
    Py_INCREF(self->pyName);
    return self->pyName;
}

// -> STR
static PyObject*
VmmPycRegKey_path(PyObj_RegKey *self, void *closure)
{
    if(!self->fValid) { return PyErr_Format(PyExc_RuntimeError, "RegKey.path: Not initialized."); }
    return PyUnicode_FromString(self->uszPath);
}

//-----------------------------------------------------------------------------
// VmmPycRegKey INITIALIZATION AND CORE FUNCTIONALITY BELOW:
//-----------------------------------------------------------------------------

PyObj_RegKey*
VmmPycRegKey_InitializeInternal(_In_ PyObj_Vmm *pyVMM, _In_ LPSTR uszFullPathKey, _In_ BOOL fVerify)
{
    PyObj_RegKey *pyObj;
    if(!(pyObj = PyObject_New(PyObj_RegKey, (PyTypeObject*)g_pPyType_RegKey))) { return NULL; }    
    Py_INCREF(pyVMM); pyObj->pyVMM = pyVMM;
    pyObj->fValid = TRUE;
    pyObj->ftLastWrite = 0;    
    strncpy_s(pyObj->uszPath, _countof(pyObj->uszPath), uszFullPathKey, _TRUNCATE);
    pyObj->pyName = PyUnicode_FromString(Util_PathSplitLastU(pyObj->uszPath));
    if(fVerify && !VmmPycRegKey_EnsureLastWrite(pyObj)) {
        Py_DECREF(pyObj);
        return NULL;
    }
    return pyObj;
}

static PyObject*
VmmPycRegKey_repr(PyObj_RegKey *self)
{
    if(!self->fValid) { return PyUnicode_FromFormat("RegKey:NotValid"); }
    return PyUnicode_FromFormat("RegKey:%U", self->pyName);
}

static int
VmmPycRegKey_init(PyObj_RegKey *self, PyObject *args, PyObject *kwds)
{
    PyErr_SetString(PyExc_TypeError, "RegKey.init(): Not allowed.");
    return -1;
}

static void
VmmPycRegKey_dealloc(PyObj_RegKey *self)
{
    self->fValid = FALSE;
    Py_XDECREF(self->pyName);
    Py_XDECREF(self->pyVMM);
    PyObject_Del(self);
}

_Success_(return)
BOOL VmmPycRegKey_InitializeType(PyObject *pModule)
{
    static PyMethodDef PyMethods[] = {
        {"subkeys", (PyCFunction)VmmPycRegKey_subkeys, METH_VARARGS, "Retrieve sub-keys."},
        {"values", (PyCFunction)VmmPycRegKey_values, METH_VARARGS, "Retrieve key values."},
        {"subkeys_dict", (PyCFunction)VmmPycRegKey_subkeys_dict, METH_VARARGS, "Retrieve sub-keys as a dict on name as key."},
        {"values_dict", (PyCFunction)VmmPycRegKey_values_dict, METH_VARARGS, "Retrieve key values as a dict on name as key."},
        {NULL, NULL, 0, NULL}
    };
    static PyMemberDef PyMembers[] = {
        {NULL}
    };
    static PyGetSetDef PyGetSet[] = {
        {"name", (getter)VmmPycRegKey_name, (setter)NULL, "Key name.", NULL},
        {"path", (getter)VmmPycRegKey_path, (setter)NULL, "Key path.", NULL},
        {"parent", (getter)VmmPycRegKey_parent, (setter)NULL, "Parent key.", NULL},
        {"time_int", (getter)VmmPycRegKey_time_int, (setter)NULL, "LastWrite timestamp in numeric format.", NULL},
        {"time_str", (getter)VmmPycRegKey_time_str, (setter)NULL, "LastWrite timestamp as string.", NULL},
        {NULL}
    };
    static PyType_Slot PyTypeSlot[] = {
        {Py_tp_init, VmmPycRegKey_init},
        {Py_tp_dealloc, VmmPycRegKey_dealloc},
        {Py_tp_repr, VmmPycRegKey_repr},
        {Py_tp_methods, PyMethods},
        {Py_tp_members, PyMembers},
        {Py_tp_getset, PyGetSet},
        {0, 0}
    };
    static PyType_Spec PyTypeSpec = {
        .name = "vmmpyc.VmmRegKey",
        .basicsize = sizeof(PyObj_RegKey),
        .itemsize = 0,
        .flags = Py_TPFLAGS_DEFAULT,
        .slots = PyTypeSlot,
    };
    if((g_pPyType_RegKey = PyType_FromSpec(&PyTypeSpec))) {
        if(PyModule_AddObject(pModule, "VmmRegKey", g_pPyType_RegKey) < 0) {
            Py_DECREF(g_pPyType_RegKey);
            g_pPyType_RegKey = NULL;
        }
    }
    return g_pPyType_RegKey ? TRUE : FALSE;
}
