// vmmpyc_regvalue.c : implementation of registry value functionality for vmmpyc.
//
// (c) Ulf Frisk, 2021
// Author: Ulf Frisk, pcileech@frizk.net
//
#include "vmmpyc.h"

PyObject *g_pPyType_RegValue = NULL;

static BOOL VmmPycRegValue_EnsureValue(PyObj_RegValue *self)
{
    BOOL result;
    DWORD cb = sizeof(self->Value.pb);
    if(self->fValue) { return TRUE; }
    Py_BEGIN_ALLOW_THREADS;
    result = VMMDLL_WinReg_QueryValueExU(self->uszPath, &self->tp, self->Value.pb, &cb);
    Py_END_ALLOW_THREADS;
    if(result) {
        if(cb < sizeof(self->Value.pb)) {
            self->fValueData = TRUE;
            self->fValue = TRUE;
            self->cb = cb;
        } else {
            Py_BEGIN_ALLOW_THREADS;
            result = VMMDLL_WinReg_QueryValueExU(self->uszPath, &self->tp, NULL, &cb);
            Py_END_ALLOW_THREADS;
            self->fValueData = FALSE;
            self->fValue = result;
            self->cb = cb;
        }
    }
    return self->fValue;
}

// -> DWORD
static PyObject*
VmmPycRegValue_type(PyObj_RegValue *self, PyObject *args)
{
    if(!self->fValid) { return PyErr_Format(PyExc_RuntimeError, "RegValue.type(): Not initialized."); }
    if(!VmmPycRegValue_EnsureValue(self)) { return PyErr_Format(PyExc_RuntimeError, "RegValue.type(): Failed."); }
    return PyLong_FromUnsignedLong(self->tp);
}

// -> DWORD
static PyObject*
VmmPycRegValue_size(PyObj_RegValue *self, PyObject *args)
{
    if(!self->fValid) { return PyErr_Format(PyExc_RuntimeError, "RegValue.size(): Not initialized."); }
    if(!VmmPycRegValue_EnsureValue(self)) { return PyErr_Format(PyExc_RuntimeError, "RegValue.size(): Failed."); }
    return PyLong_FromUnsignedLong(self->cb);
}

// -> PBYTE
static PyObject*
VmmPycRegValue_value(PyObj_RegValue *self, PyObject *args)
{
    PyObject *pyBytes;
    BOOL result;
    DWORD cb;
    PBYTE pb;
    if(!self->fValid) { return PyErr_Format(PyExc_RuntimeError, "RegValue.value(): Not initialized."); }
    if(!VmmPycRegValue_EnsureValue(self)) { return PyErr_Format(PyExc_RuntimeError, "RegValue.value(): Failed."); }
    if(self->fValueData) {
        return PyBytes_FromStringAndSize((char *)self->Value.pb, self->cb);
    }
    cb = self->cb;
    if(!(pb = LocalAlloc(LMEM_ZEROINIT, cb))) { return PyErr_NoMemory(); }
    Py_BEGIN_ALLOW_THREADS;
    result = VMMDLL_WinReg_QueryValueExU(self->uszPath, NULL, pb, &cb);
    Py_END_ALLOW_THREADS;
    if(!result) {
        LocalFree(pb);
        return PyErr_Format(PyExc_RuntimeError, "RegValue.value(): Failed.");
    }
    pyBytes = PyBytes_FromStringAndSize((const char *)pb, cb);
    LocalFree(pb);
    return pyBytes;
}

// (BOOL) -> DWORD
static PyObject*
VmmPycRegValue_vdword(PyObj_RegValue *self, PyObject *args)
{
    BOOL fTypeCheck = TRUE;
    if(!self->fValid) { return PyErr_Format(PyExc_RuntimeError, "RegValue.vdword(): Not initialized."); }
    if(!VmmPycRegValue_EnsureValue(self)) { return PyErr_Format(PyExc_RuntimeError, "RegValue.vdword(): Failed."); }
    if(!PyArg_ParseTuple(args, "|p", &fTypeCheck)) {
        return PyErr_Format(PyExc_RuntimeError, "RegValue.vdword(): Illegal argument.");
    }
    if(self->cb != sizeof(DWORD) || (fTypeCheck && (self->tp != REG_DWORD) && (self->tp != REG_DWORD_BIG_ENDIAN))) {
        return PyErr_Format(PyExc_RuntimeError, "RegValue.vdword(): Invalid type.");
    }
    return PyLong_FromUnsignedLong(self->Value.dw);
}

// (BOOL) -> QWORD
static PyObject*
VmmPycRegValue_vqword(PyObj_RegValue *self, PyObject *args)
{
    BOOL fTypeCheck = TRUE;
    if(!self->fValid) { return PyErr_Format(PyExc_RuntimeError, "RegValue.v_qword(): Not initialized."); }
    if(!VmmPycRegValue_EnsureValue(self)) { return PyErr_Format(PyExc_RuntimeError, "RegValue.v_qword(): Failed."); }
    if(!PyArg_ParseTuple(args, "|p", &fTypeCheck)) {
        return PyErr_Format(PyExc_RuntimeError, "RegValue.v_qword(): Illegal argument.");
    }
    if(self->cb != sizeof(QWORD) || (fTypeCheck && (self->tp != REG_QWORD))) {
        return PyErr_Format(PyExc_RuntimeError, "RegValue.v_qword(): Invalid type.");
    }
    return PyLong_FromUnsignedLongLong(self->Value.qw);
}

// (BOOL) -> QWORD
static PyObject*
VmmPycRegValue_vtime(PyObj_RegValue *self, PyObject *args)
{
    CHAR szTime[24];
    BOOL fTypeCheck = TRUE;
    if(!self->fValid) { return PyErr_Format(PyExc_RuntimeError, "RegValue.vtime(): Not initialized."); }
    if(!VmmPycRegValue_EnsureValue(self)) { return PyErr_Format(PyExc_RuntimeError, "RegValue.vtime(): Failed."); }
    if(!PyArg_ParseTuple(args, "|p", &fTypeCheck)) {
        return PyErr_Format(PyExc_RuntimeError, "RegValue.vtime(): Illegal argument.");
    }
    if(self->cb != sizeof(QWORD) || (fTypeCheck && (self->tp != REG_QWORD))) {
        return PyErr_Format(PyExc_RuntimeError, "RegValue.vtime(): Invalid type.");
    }
    Util_FileTime2String(self->Value.qw, szTime);
    return PyUnicode_FromFormat("%s", szTime);
}

// (BOOL) -> STR
static PyObject*
VmmPycRegValue_InternalValueString(PyObj_RegValue *self, PyObject *args, _In_ LPSTR szFN, _In_ BOOL fW, _In_ BOOL fTypeCheck)
{
    PyObject *pyUnicode;
    BOOL result;
    DWORD cb, i;
    PBYTE pb;
    LPWSTR wsz;
    // 1: fetch
    if(!self->fValid) { return PyErr_Format(PyExc_RuntimeError, "%s: Not initialized.", szFN); }
    if(!VmmPycRegValue_EnsureValue(self)) { return PyErr_Format(PyExc_RuntimeError, "%s: Failed.", szFN); }
    if(!PyArg_ParseTuple(args, "|p", &fTypeCheck)) {
        return PyErr_Format(PyExc_RuntimeError, "%s: Illegal argument.", szFN);
    }
    if((fW && (self->cb & 1)) || (fTypeCheck && (self->tp != REG_SZ) && (self->tp != REG_EXPAND_SZ))) {
        return PyErr_Format(PyExc_RuntimeError, "%s: Invalid type.", szFN);
    }
    cb = self->cb;
    if(!(pb = LocalAlloc(LMEM_ZEROINIT, cb))) { return PyErr_NoMemory(); }
    if(self->fValueData) {
        memcpy(pb, self->Value.pb, cb);
    } else {
        Py_BEGIN_ALLOW_THREADS;
        result = VMMDLL_WinReg_QueryValueExU(self->uszPath, NULL, pb, &cb);
        Py_END_ALLOW_THREADS;
        if(!result) {
            LocalFree(pb);
            return PyErr_Format(PyExc_RuntimeError, "%s.value(): Failed.", szFN);
        }
    }
    // 2: null-find:
    if(!fW) {
        for(i = 0; i < cb; i++) {
            if(pb[i] == 0) {
                cb = i;
                break;
            }
        }
    } else {
        wsz = (LPWSTR)pb;
        for(i = 0; i < cb >> 1; i++) {
            if(wsz[i] == 0) {
                cb = i << 1;
                break;
            }
        }
    }
    // 3: create string:
    pyUnicode = PyUnicode_Decode((const char *)pb, cb, (fW ? "utf-16le" : "ascii"), NULL);
    LocalFree(pb);
    return pyUnicode ? pyUnicode : PyErr_Format(PyExc_RuntimeError, "%s(): Failed translation.", szFN);
}

// (BOOL) -> STR
static PyObject*
VmmPycRegValue_vstr(PyObj_RegValue *self, PyObject *args)
{
    return VmmPycRegValue_InternalValueString(self, args, "RegValue.vstr()", TRUE, TRUE);
}

// (BOOL) -> STR
static PyObject*
VmmPycRegValue_vascii(PyObj_RegValue *self, PyObject *args)
{
    return VmmPycRegValue_InternalValueString(self, args, "RegValue.vascii()", FALSE, FALSE);
}

// -> ObjRegKey
static PyObject*
VmmPycRegValue_parent(PyObj_RegValue *self, void *closure)
{
    CHAR uszParentPath[2 * MAX_PATH];
    if(!self->fValid) { return PyErr_Format(PyExc_RuntimeError, "RegValue.parent: Not initialized."); }
    if(!Util_PathSplitLastEx(self->uszPath, uszParentPath, sizeof(uszParentPath))) {
        return PyErr_Format(PyExc_RuntimeError, "RegValue.parent: No parent key.");
    }
    return (PyObject*)VmmPycRegKey_InitializeInternal(uszParentPath, FALSE);
}

// -> STR
static PyObject*
VmmPycRegValue_name(PyObj_RegValue *self, void *closure)
{
    if(!self->fValid) { return PyErr_Format(PyExc_RuntimeError, "RegValue.name: Not initialized."); }
    Py_INCREF(self->pyName);
    return self->pyName;
}

// -> STR
static PyObject*
VmmPycRegValue_path(PyObj_RegValue *self, void *closure)
{
    if(!self->fValid) { return PyErr_Format(PyExc_RuntimeError, "RegValue.path: Not initialized."); }
    return PyUnicode_FromString(self->uszPath);
}

//-----------------------------------------------------------------------------
// VmmPycRegValue INITIALIZATION AND CORE FUNCTIONALITY BELOW:
//-----------------------------------------------------------------------------

PyObj_RegValue*
VmmPycRegValue_InitializeInternal(_In_ LPSTR uszFullPathKeyValue, _In_ BOOL fVerify)
{
    DWORD cch = 0;
    PyObj_RegValue *pyObj;
    if(!(pyObj = PyObject_New(PyObj_RegValue, (PyTypeObject*)g_pPyType_RegValue))) { return NULL; }
    pyObj->fValid = TRUE;
    pyObj->fValue = FALSE;
    pyObj->fValueData = FALSE;
    strncpy_s(pyObj->uszPath, _countof(pyObj->uszPath), uszFullPathKeyValue, _TRUNCATE);
    pyObj->pyName = PyUnicode_FromString(Util_PathSplitLastU(pyObj->uszPath));
    if(fVerify && !VmmPycRegValue_EnsureValue(pyObj)) {
        Py_DECREF(pyObj);
        return NULL;
    }
    return pyObj;
}

static PyObject*
VmmPycRegValue_repr(PyObj_RegValue *self)
{
    if(!self->fValid) { return PyUnicode_FromFormat("RegValue:NotValid"); }
    return PyUnicode_FromFormat("RegValue:%U", self->pyName);
}

static int
VmmPycRegValue_init(PyObj_RegValue *self, PyObject *args, PyObject *kwds)
{
    PyErr_SetString(PyExc_TypeError, "RegValue.init(): Not allowed.");
    return -1;
}

static void
VmmPycRegValue_dealloc(PyObj_RegValue *self)
{
    self->fValid = FALSE;
    Py_XDECREF(self->pyName);
}

_Success_(return)
BOOL VmmPycRegValue_InitializeType(PyObject *pModule)
{
    static PyMethodDef PyMethods[] = {
        {"vdword", (PyCFunction)VmmPycRegValue_vdword, METH_VARARGS, "Value as DWORD."},
        {"vqword", (PyCFunction)VmmPycRegValue_vqword, METH_VARARGS, "Value as QWORD."},
        {"vtime", (PyCFunction)VmmPycRegValue_vtime, METH_VARARGS, "Value as FILETIME STRING."},
        {"vascii", (PyCFunction)VmmPycRegValue_vascii, METH_VARARGS, "Value as STRING."},
        {"vstr", (PyCFunction)VmmPycRegValue_vstr, METH_VARARGS, "Value as STRING."},
        {NULL, NULL, 0, NULL}
    };
    static PyMemberDef PyMembers[] = {
        {NULL}
    };
    static PyGetSetDef PyGetSet[] = {
        {"name", (getter)VmmPycRegValue_name, (setter)NULL, "Value name.", NULL},
        {"path", (getter)VmmPycRegValue_path, (setter)NULL, "Value path.", NULL},
        {"parent", (getter)VmmPycRegValue_parent, (setter)NULL, "Parent key.", NULL},
        {"size", (getter)VmmPycRegValue_size, (setter)NULL, "Value byte size.", NULL},
        {"type", (getter)VmmPycRegValue_type, (setter)NULL, "Value type.", NULL},
        {"value", (getter)VmmPycRegValue_value, (setter)NULL, "Value as bytes.", NULL},
        {NULL}
    };
    static PyType_Slot PyTypeSlot[] = {
        {Py_tp_init, VmmPycRegValue_init},
        {Py_tp_dealloc, VmmPycRegValue_dealloc},
        {Py_tp_repr, VmmPycRegValue_repr},
        {Py_tp_methods, PyMethods},
        {Py_tp_members, PyMembers},
        {Py_tp_getset, PyGetSet},
        {0, 0}
    };
    static PyType_Spec PyTypeSpec = {
        .name = "vmmpyc.VmmRegValue",
        .basicsize = sizeof(PyObj_RegValue),
        .itemsize = 0,
        .flags = Py_TPFLAGS_DEFAULT,
        .slots = PyTypeSlot,
    };
    if((g_pPyType_RegValue = PyType_FromSpec(&PyTypeSpec))) {
        if(PyModule_AddObject(pModule, "VmmRegValue", g_pPyType_RegValue) < 0) {
            Py_DECREF(g_pPyType_RegValue);
            g_pPyType_RegValue = NULL;
        }
    }
    return g_pPyType_RegValue ? TRUE : FALSE;
}
