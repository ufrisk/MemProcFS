// vmmpyc_vmm.c : implementation of core functionality for vmmpyc.
//
// (c) Ulf Frisk, 2021-2024
// Author: Ulf Frisk, pcileech@frizk.net
//
#include "vmmpyc.h"

PyObject *g_pPyType_Vmm = NULL;

// () -> [PyObj_Process*, ...]
static PyObject*
VmmPycVmm_process_list(PyObj_Vmm *self, PyObject *args)
{
    PyObject *pyList;
    BOOL result;
    SIZE_T cPIDs = 0;
    DWORD i, *pPIDs = NULL;
    if(!self->fValid) { return PyErr_Format(PyExc_RuntimeError, "Vmm.process_list(): Not initialized."); }
    if(!(pyList = PyList_New(0))) { return PyErr_NoMemory(); }
    Py_BEGIN_ALLOW_THREADS;
    result =
        VMMDLL_PidList(self->hVMM, NULL, &cPIDs) &&
        (pPIDs = LocalAlloc(LMEM_ZEROINIT, (SIZE_T)(cPIDs * sizeof(DWORD)))) &&
        VMMDLL_PidList(self->hVMM, pPIDs, &cPIDs);
    Py_END_ALLOW_THREADS;
    if(!result) {
        Py_DECREF(pyList);
        LocalFree(pPIDs);
        return PyErr_Format(PyExc_RuntimeError, "Vmm.process_list(): Failed.");
    }
    for(i = 0; i < cPIDs; i++) {
        PyList_Append_DECREF(pyList, (PyObject*)VmmPycProcess_InitializeInternal(self, pPIDs[i], FALSE));
    }
    LocalFree(pPIDs);
    return pyList;
}

// (STR _OR_ DWORD) -> PyObj_Process*
static PyObject*
VmmPycVmm_process(PyObj_Vmm *self, PyObject *args)
{
    PyObject *pyData = NULL, *pyObjProcess;
    BOOL result;
    DWORD dwPID;
    LPSTR szProcessName = NULL;
    if(!self->fValid) { return PyErr_Format(PyExc_RuntimeError, "Vmm.process(): Not initialized."); }
    if(PyArg_ParseTuple(args, "I", &dwPID)) {
        // argument: by-pid:
        pyObjProcess = (PyObject*)VmmPycProcess_InitializeInternal(self, dwPID, TRUE);
        if(!pyObjProcess) {
            return PyErr_Format(PyExc_RuntimeError, "Vmm.process(): No such process - %i.", dwPID);
        }
        return pyObjProcess;
    }
    PyErr_Clear();
    // argument: by-name:
    if(!PyArg_ParseTuple(args, "s", &szProcessName) || !szProcessName) {
        return PyErr_Format(PyExc_RuntimeError, "Vmm.process(): Illegal argument.");
    }
    Py_BEGIN_ALLOW_THREADS;
    result = VMMDLL_PidGetFromName(self->hVMM, szProcessName, &dwPID);
    Py_END_ALLOW_THREADS;
    if(!result) { return PyErr_Format(PyExc_RuntimeError, "Vmm.process(): Failed."); }
    return (PyObject*)VmmPycProcess_InitializeInternal(self, dwPID, FALSE);
}

// (PBYTE, (DWORD)) -> STR
static PyObject*
VmmPycVmm_hex(PyObj_Vmm *self, PyObject *args)
{
    PyObject *pyString;
    DWORD cbInitialOffset = 0, csz = 0;
    SIZE_T cb;
    PBYTE pb;
    LPSTR sz = NULL;
    BOOL result;
    if(!self->fValid) { return PyErr_Format(PyExc_RuntimeError, "Vmm.hex(): Not initialized."); }
    if(!PyArg_ParseTuple(args, "y#|I", &pb, &cb, &cbInitialOffset)) {
        return PyErr_Format(PyExc_RuntimeError, "Vmm.hex(): Illegal argument.");
    }
    if(cb == 0) {
        return PyUnicode_FromFormat("%s", "");
    }
    Py_BEGIN_ALLOW_THREADS;
    cb = min(0x01000000, cb);
    result =
        VMMDLL_UtilFillHexAscii(pb, (DWORD)cb, cbInitialOffset, NULL, &csz) &&
        csz &&
        (sz = (LPSTR)LocalAlloc(0, csz)) &&
        VMMDLL_UtilFillHexAscii(pb, (DWORD)cb, cbInitialOffset, sz, &csz);
    Py_END_ALLOW_THREADS;
    if(!result || !sz) {
        LocalFree(sz);
        return PyErr_Format(PyExc_RuntimeError, "Vmm.hex(): Failed.");
    }
    pyString = PyUnicode_FromFormat("%s", sz);
    LocalFree(sz);
    return pyString;
}

// (ULONG64) -> ULONG64
static PyObject*
VmmPycVmm_get_config(PyObj_Vmm *self, PyObject *args)
{
    BOOL result;
    ULONG64 fOption, qwValue = 0;
    if(!self->fValid) { return PyErr_Format(PyExc_RuntimeError, "Vmm.get_config(): Not initialized."); }
    if(!PyArg_ParseTuple(args, "K", &fOption)) {
        return PyErr_Format(PyExc_RuntimeError, "Vmm.get_config(): Illegal argument.");
    }
    Py_BEGIN_ALLOW_THREADS;
    result = VMMDLL_ConfigGet(self->hVMM, fOption, &qwValue);
    Py_END_ALLOW_THREADS;
    if(!result) { return PyErr_Format(PyExc_RuntimeError, "Vmm.get_config(): Unable to retrieve value for option."); }
    return PyLong_FromUnsignedLongLong(qwValue);
}

// (ULONG64, ULONG64) -> None
static PyObject*
VmmPycVmm_set_config(PyObj_Vmm *self, PyObject *args)
{
    BOOL result;
    ULONG64 fOption, qwValue = 0;
    if(!self->fValid) { return PyErr_Format(PyExc_RuntimeError, "Vmm.set_config(): Not initialized."); }
    if(!PyArg_ParseTuple(args, "KK", &fOption, &qwValue)) {
        return PyErr_Format(PyExc_RuntimeError, "Vmm.set_config(): Illegal argument.");
    }
    Py_BEGIN_ALLOW_THREADS;
    result = VMMDLL_ConfigSet(self->hVMM, fOption, qwValue);
    Py_END_ALLOW_THREADS;
    if(!result) { return PyErr_Format(PyExc_RuntimeError, "Vmm.set_config(): Unable to set value for option."); }
    return Py_BuildValue("s", NULL);    // None returned on success.
}

// () -> [PyObj_RegHive*, ...]
static PyObject*
VmmPycVmm_reg_hive_list(PyObj_Vmm *self, PyObject *args)
{
    PyObject *pyList, *pyHive;
    BOOL result;
    DWORD i, cHives;
    PVMMDLL_REGISTRY_HIVE_INFORMATION pHives = NULL;
    if(!self->fValid) { return PyErr_Format(PyExc_RuntimeError, "Vmm.reg_hive_list(): Not initialized."); }
    if(!(pyList = PyList_New(0))) { return PyErr_NoMemory(); }
    Py_BEGIN_ALLOW_THREADS;
    result =
        VMMDLL_WinReg_HiveList(self->hVMM, NULL, 0, &cHives) &&
        cHives &&
        (pHives = LocalAlloc(0, cHives * sizeof(VMMDLL_REGISTRY_HIVE_INFORMATION))) &&
        VMMDLL_WinReg_HiveList(self->hVMM, pHives, cHives, &cHives);
    Py_END_ALLOW_THREADS;
    if(!result) {
        Py_DECREF(pyList);
        LocalFree(pHives);
        return PyErr_Format(PyExc_RuntimeError, "Vmm.reg_hive_list(): Failed.");
    }
    for(i = 0; i < cHives; i++) {
        if((pyHive = (PyObject*)VmmPycRegHive_InitializeInternal(self, pHives + i))) {
            PyList_Append_DECREF(pyList, pyHive);
        }
    }
    LocalFree(pHives);
    return pyList;
}

// (STR) -> PyObj_RegKey*
static PyObject*
VmmPycVmm_reg_key(PyObj_Vmm *self, PyObject *args)
{
    PyObject *pyObj, *pyUnicodeName;
    LPSTR uszName = NULL;
    if(!self->fValid) { return PyErr_Format(PyExc_RuntimeError, "Vmm.reg_key(): Not initialized."); }
    if(!PyArg_ParseTuple(args, "s", &uszName) || !uszName) {
        return PyErr_Format(PyExc_RuntimeError, "Vmm.reg_key(): Illegal argument.");
    }
    pyObj = (PyObject*)VmmPycRegKey_InitializeInternal(self, uszName, TRUE);
    if(!pyObj && (pyUnicodeName = PyUnicode_FromString(uszName))) {
        pyObj = PyErr_Format(PyExc_RuntimeError, "Vmm.reg_key('%U'): Failed.", pyUnicodeName);
        Py_XDECREF(pyObj);
    }
    return pyObj;
}

// (STR) -> PyObj_RegKey*
static PyObject*
VmmPycVmm_reg_value(PyObj_Vmm *self, PyObject *args)
{
    PyObject *pyObj, *pyUnicodeName;
    LPSTR uszName = NULL;
    if(!self->fValid) { return PyErr_Format(PyExc_RuntimeError, "Vmm.reg_value(): Not initialized."); }
    if(!PyArg_ParseTuple(args, "s", &uszName) || !uszName) {
        return PyErr_Format(PyExc_RuntimeError, "Vmm.reg_value(): Illegal argument.");
    }
    pyObj = (PyObject *)VmmPycRegValue_InitializeInternal(self, uszName, TRUE);
    if(!pyObj && (pyUnicodeName = PyUnicode_FromString(uszName))) {
        pyObj = PyErr_Format(PyExc_RuntimeError, "Vmm.reg_value('%U'): Failed.", pyUnicodeName);
        Py_XDECREF(pyUnicodeName);
    }
    return pyObj;
}

// (|QWORD, QWORD, QWORD) -> PyObj_Search*
static PyObject*
VmmPycVmm_search(PyObj_Vmm *self, PyObject *args)
{
    PyObject *pyObj;
    LPSTR uszName = NULL;
    if(!self->fValid) { return PyErr_Format(PyExc_RuntimeError, "Vmm.search(): Not initialized."); }
    pyObj = (PyObject*)VmmPycSearch_InitializeInternal(self, -1, args);
    if(!pyObj) {
        return PyErr_Format(PyExc_RuntimeError, "Vmm.search(): Illegal argument.");
    }
    return pyObj;
}

// (PyList(STR), |QWORD, QWORD, DWORD, QWORD) ->PyObj_Yara*
static PyObject*
VmmPycVmm_search_yara(PyObj_Vmm *self, PyObject *args)
{
    PyObject *pyObj;
    LPSTR uszName = NULL;
    if(!self->fValid) { return PyErr_Format(PyExc_RuntimeError, "Vmm.search_yara(): Not initialized."); }
    pyObj = (PyObject*)VmmPycYara_InitializeInternal(self, -1, args);
    if(!pyObj) {
        return PyErr_Format(PyExc_RuntimeError, "Vmm.search_yara(): Illegal argument.");
    }
    return pyObj;
}

// -> *PyLong
static PyObject*
VmmPycVmm_bits(PyObj_Vmm *self, void *closure)
{
    DWORD dwBits;
    ULONG64 qwValue = 0;
    if(!self->fValid) { return PyErr_Format(PyExc_RuntimeError, "Vmm.f32: Not initialized."); }
    Py_BEGIN_ALLOW_THREADS;
    VMMDLL_ConfigGet(self->hVMM, VMMDLL_OPT_CORE_MEMORYMODEL, &qwValue);
    dwBits = ((qwValue == VMMDLL_MEMORYMODEL_X86) || (qwValue == VMMDLL_MEMORYMODEL_X86PAE)) ? 32 : 64;
    Py_END_ALLOW_THREADS;
    return PyLong_FromUnsignedLong(dwBits);
}

//-----------------------------------------------------------------------------
// VmmPycVmm INITIALIZATION AND CORE FUNCTIONALITY BELOW:
//-----------------------------------------------------------------------------

PyObj_Vmm*
VmmPycVmm_InitializeInternal2(_In_ PyObj_Vmm *pyVMM, _In_ VMM_HANDLE hVMM)
{
    PyObj_Vmm *pyObj;
    if(!(pyObj = PyObject_New(PyObj_Vmm, (PyTypeObject*)g_pPyType_Vmm))) { return NULL; }
    pyObj->hVMM = hVMM;
    pyObj->fVmmCoreOpenType = TRUE;
    pyObj->pyObjKernel = (PyObject*)VmmPycKernel_InitializeInternal(pyObj);
    pyObj->pyObjMaps = (PyObject*)VmmPycMaps_InitializeInternal(pyObj);
    pyObj->pyObjMemory = (PyObject*)VmmPycPhysicalMemory_InitializeInternal(pyObj);
    pyObj->pyObjVfs = (PyObject*)VmmPycVfs_InitializeInternal(pyObj);
    pyObj->fValid = TRUE;
    return pyObj;
}

static PyObject*
VmmPycVmm_repr(PyObj_Vmm *self)
{
    return PyUnicode_FromFormat(self->fValid ? "Vmm" : "Vmm:NotValid");
}

static int
VmmPycVmm_init(PyObj_Vmm *self, PyObject *args, PyObject *kwds)
{
    DWORD PARAM_OFFSET = 2;
    static char *kwlist[] = { "args", NULL };
    PyObject *pyListSrc = NULL, *pyString, **pyBytesDstArgs, *pyObjProcessTest;
    DWORD i, cDstArgs;
    LPCSTR *pszDstArgs;
    self->fVmmCoreOpenType = FALSE;
    if(!PyArg_ParseTupleAndKeywords(args, kwds, "|O!", kwlist, &PyList_Type, &pyListSrc)) {
        PyErr_SetString(PyExc_TypeError, "Vmm.init(): Illegal argument.");
        return -1;
    }
    if(pyListSrc) {     // INITIALIZE NEW VMM
        cDstArgs = PARAM_OFFSET + (DWORD)PyList_Size(pyListSrc);
        if(cDstArgs == PARAM_OFFSET) {
            PyErr_SetString(PyExc_TypeError, "Vmm.init(): Required argument list is empty.");
            return -1;
        }
        // allocate & initialize buffer+basic
        pszDstArgs = (LPCSTR*)LocalAlloc(LMEM_ZEROINIT, sizeof(LPSTR) * cDstArgs);
        pyBytesDstArgs = (PyObject**)LocalAlloc(LMEM_ZEROINIT, sizeof(PyObject*)*cDstArgs);
        if(!pszDstArgs || !pyBytesDstArgs) {
            PyErr_SetString(PyExc_TypeError, "Vmm.init(): Out of memory.");
            return -1;
        }
        // iterate over # entries and build argument list
        pszDstArgs[0] = "";
        pszDstArgs[1] = "-waitinitialize";
        for(i = PARAM_OFFSET; i < cDstArgs; i++) {
            pyString = PyList_GetItem(pyListSrc, i - PARAM_OFFSET);   // borrowed reference
            if(!PyUnicode_Check(pyString)) {
                PyErr_SetString(PyExc_TypeError, "Vmm.init(): Argument list contains non string item.");
                return -1;
            }
            pyBytesDstArgs[i] = PyUnicode_AsEncodedString(pyString, NULL, NULL);
            pszDstArgs[i] = pyBytesDstArgs[i] ? PyBytes_AsString(pyBytesDstArgs[i]) : "";
        }
        Py_BEGIN_ALLOW_THREADS;
        self->hVMM = VMMDLL_Initialize(cDstArgs, pszDstArgs);
        if(self->hVMM) {
            VMMDLL_InitializePlugins(self->hVMM);
        }
        Py_END_ALLOW_THREADS;
        for(i = PARAM_OFFSET; i < cDstArgs; i++) {
            Py_XDECREF(pyBytesDstArgs[i]);
        }
        if(!self->hVMM) {
            PyErr_SetString(PyExc_TypeError, "Vmm.init(): Initialization of vmm failed.");
            return -1;
        }
        self->fVmmCoreOpenType = TRUE;
    } else {    // INITIALIZE EXISTING VMM (CHECK IF EXISTING IS VALID)
        self->hVMM = g_PluginVMM;
        pyObjProcessTest = (PyObject*)VmmPycProcess_InitializeInternal(self, 4, TRUE);
        if(!pyObjProcessTest) {
            return -1;
        }
        Py_DECREF(pyObjProcessTest);
        if(g_PluginVMM_LoadedOnce) {
            return -1;
        }
        if(!g_PluginVMM) {
            return -1;
        }
        g_PluginVMM_LoadedOnce = TRUE;
    }
    // success - initialize type object and return!
    self->pyObjKernel = (PyObject*)VmmPycKernel_InitializeInternal(self);
    self->pyObjMaps = (PyObject*)VmmPycMaps_InitializeInternal(self);
    self->pyObjMemory = (PyObject*)VmmPycPhysicalMemory_InitializeInternal(self);
    self->pyObjVfs = (PyObject*)VmmPycVfs_InitializeInternal(self);
    self->fValid = TRUE;
    return 0;
}

static void
VmmPycVmm_dealloc(PyObj_Vmm *self)
{
    if(self->fValid) {
        self->fValid = FALSE;
        if(self->fVmmCoreOpenType) {
            Py_BEGIN_ALLOW_THREADS;
            VMMDLL_Close(self->hVMM);
            Py_END_ALLOW_THREADS;
        }
    }
    Py_XDECREF(self->pyObjKernel);
    Py_XDECREF(self->pyObjMaps);
    Py_XDECREF(self->pyObjMemory);
    Py_XDECREF(self->pyObjVfs);
}

// () -> None
static PyObject*
VmmPycVmm_close(PyObj_Vmm *self, PyObject *args)
{
    if(!self->fValid) { return PyErr_Format(PyExc_RuntimeError, "Vmm.close(): Not initialized."); }
    self->fValid = FALSE;
    if(self->fVmmCoreOpenType) {
        Py_BEGIN_ALLOW_THREADS;
        VMMDLL_Close(self->hVMM);
        Py_END_ALLOW_THREADS;
    }
    return Py_BuildValue("s", NULL);    // None returned on success.
}

_Success_(return)
BOOL VmmPycVmm_InitializeType(PyObject *pModule)
{
    static PyMethodDef PyMethods[] = {
        {"close", (PyCFunction)VmmPycVmm_close, METH_VARARGS, "Close the VMM."},
        {"get_config", (PyCFunction)VmmPycVmm_get_config, METH_VARARGS, "Get configuration value."},
        {"set_config", (PyCFunction)VmmPycVmm_set_config, METH_VARARGS, "Set configuration value."},
        {"process_list", (PyCFunction)VmmPycVmm_process_list, METH_VARARGS, "List processes."},
        {"process", (PyCFunction)VmmPycVmm_process, METH_VARARGS, "Retrieve process by name or PID."},
        {"reg_hive_list", (PyCFunction)VmmPycVmm_reg_hive_list, METH_VARARGS, "List registry hives."},
        {"reg_key", (PyCFunction)VmmPycVmm_reg_key, METH_VARARGS, "Retrieve registry key from full path."},
        {"reg_value", (PyCFunction)VmmPycVmm_reg_value, METH_VARARGS, "Retrieve registry value from full path."},
        {"search", (PyCFunction)VmmPycVmm_search, METH_VARARGS, "Perform a binary search."},
        {"search_yara", (PyCFunction)VmmPycVmm_search_yara, METH_VARARGS, "Perform a YARA search."},
        {"hex", (PyCFunction)VmmPycVmm_hex, METH_VARARGS, "Convert a bytes object into a human readable 'memory dump' style type of string."},
        {NULL, NULL, 0, NULL}
    };
    static PyMemberDef PyMembers[] = {
        {"kernel", T_OBJECT, offsetof(PyObj_Vmm, pyObjKernel), READONLY, "Kernel information."},
        {"maps", T_OBJECT, offsetof(PyObj_Vmm, pyObjMaps), READONLY, "Info maps."},
        {"memory", T_OBJECT, offsetof(PyObj_Vmm, pyObjMemory), READONLY, "Physical memory."},
        {"vfs", T_OBJECT, offsetof(PyObj_Vmm, pyObjVfs), READONLY, "Virtual file system."},
        {NULL}
    };
    static PyGetSetDef PyGetSet[] = {
        {"bits", (getter)VmmPycVmm_bits, (setter)NULL, "System bitness, returns either 32 or 64.", NULL},
        {NULL}
    };
    static PyType_Slot PyTypeSlot[] = {
        {Py_tp_init, VmmPycVmm_init},
        {Py_tp_dealloc, VmmPycVmm_dealloc},
        {Py_tp_repr, VmmPycVmm_repr},
        {Py_tp_methods, PyMethods},
        {Py_tp_members, PyMembers},
        {Py_tp_getset, PyGetSet},
        {0, 0}
    };
    static PyType_Spec PyTypeSpec = {
        .name = "vmmpyc.Vmm",
        .basicsize = sizeof(PyObj_Vmm),
        .itemsize = 0,
        .flags = Py_TPFLAGS_DEFAULT,
        .slots = PyTypeSlot,
    };
    if((g_pPyType_Vmm = PyType_FromSpec(&PyTypeSpec))) {
        if(PyModule_AddObject(pModule, "Vmm", g_pPyType_Vmm) < 0) {
            Py_DECREF(g_pPyType_Vmm);
            g_pPyType_Vmm = NULL;
        }
    }
    return g_pPyType_Vmm ? TRUE : FALSE;
}
