#include "vmmpyc.h"

PyObject *g_pPyType_Vmm = NULL;

// () -> [PyObj_Process*, ...]
static PyObject*
VmmPycVmm_process_list(PyObj_Vmm *self, PyObject *args)
{
    PyObject *pyList;
    BOOL result;
    ULONG64 cPIDs = 0;
    DWORD i, *pPIDs = NULL;
    if(!self->fValid) { return PyErr_Format(PyExc_RuntimeError, "Vmm.process_list(): Not initialized."); }
    if(!(pyList = PyList_New(0))) { return PyErr_NoMemory(); }
    Py_BEGIN_ALLOW_THREADS;
    result =
        VMMDLL_PidList(NULL, &cPIDs) &&
        (pPIDs = LocalAlloc(LMEM_ZEROINIT, cPIDs * sizeof(DWORD))) &&
        VMMDLL_PidList(pPIDs, &cPIDs);
    Py_END_ALLOW_THREADS;
    if(!result) {
        Py_DECREF(pyList);
        LocalFree(pPIDs);
        return PyErr_Format(PyExc_RuntimeError, "Vmm.process_list(): Failed.");
    }
    for(i = 0; i < cPIDs; i++) {
        PyList_Append_DECREF(pyList, (PyObject*)VmmPycProcess_InitializeInternal(pPIDs[i], FALSE));
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
    if(PyArg_ParseTuple(args, "k", &dwPID)) {
        // argument: by-pid:
        pyObjProcess = (PyObject*)VmmPycProcess_InitializeInternal(dwPID, TRUE);
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
    result = VMMDLL_PidGetFromName(szProcessName, &dwPID);
    Py_END_ALLOW_THREADS;
    if(!result) { return PyErr_Format(PyExc_RuntimeError, "Vmm.process(): Failed."); }
    return (PyObject*)VmmPycProcess_InitializeInternal(dwPID, FALSE);
}

// (PBYTE, (DWORD)) -> STR
static PyObject*
VmmPycVmm_hex(PyObj_Vmm *self, PyObject *args)
{
    PyObject *pyString;
    DWORD cbInitialOffset = 0, csz = 0;
    QWORD cb;
    PBYTE pb;
    LPSTR sz = NULL;
    BOOL result;
    if(!self->fValid) { return PyErr_Format(PyExc_RuntimeError, "Vmm.hex(): Not initialized."); }
    if(!PyArg_ParseTuple(args, "y#|k", &pb, &cb, &cbInitialOffset)) {
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

// -> None
static PyObject*
VmmPycVmm_initialize_plugins(PyObj_Vmm *self, PyObject *args)
{
    BOOL result;
    if(!self->fValid) { return PyErr_Format(PyExc_RuntimeError, "Vmm.initialize_plugins(): Not initialized."); }
    Py_BEGIN_ALLOW_THREADS;
    result = VMMDLL_InitializePlugins();
    Py_END_ALLOW_THREADS;
    if(!result) { return PyErr_Format(PyExc_RuntimeError, "Vmm.initialize_plugins(): Initialization of plugin subsystem failed."); }
    // success! initialize plugin-dependant members (vfs):
    if(!self->pyObjVfs) {
        self->pyObjVfs = (PyObject*)VmmPycVfs_InitializeInternal();
    }
    return Py_BuildValue("s", NULL);    // None returned on success.
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
    result = VMMDLL_ConfigGet(fOption, &qwValue);
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
    result = VMMDLL_ConfigSet(fOption, qwValue);
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
    VMMDLL_WinReg_HiveList(NULL, 0, &cHives);
    result =
        VMMDLL_WinReg_HiveList(NULL, 0, &cHives) &&
        cHives &&
        (pHives = LocalAlloc(0, cHives * sizeof(VMMDLL_REGISTRY_HIVE_INFORMATION))) &&
        VMMDLL_WinReg_HiveList(pHives, cHives, &cHives);
    Py_END_ALLOW_THREADS;
    if(!result) {
        Py_DECREF(pyList);
        LocalFree(pHives);
        return PyErr_Format(PyExc_RuntimeError, "Vmm.reg_hive_list(): Failed.");
    }
    for(i = 0; i < cHives; i++) {
        if((pyHive = (PyObject*)VmmPycRegHive_InitializeInternal(pHives + i))) {
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
    pyObj = (PyObject*)VmmPycRegKey_InitializeInternal(uszName, TRUE);
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
    pyObj = (PyObject *)VmmPycRegValue_InitializeInternal(uszName, TRUE);
    if(!pyObj && (pyUnicodeName = PyUnicode_FromString(uszName))) {
        pyObj = PyErr_Format(PyExc_RuntimeError, "Vmm.reg_value('%U'): Failed.", pyUnicodeName);
        Py_XDECREF(pyUnicodeName);
    }
    return pyObj;
}

// -> *PyObj_Maps
static PyObject*
VmmPycVmm_maps(PyObj_Vmm *self, void *closure)
{
    if(!self->fValid) { return PyErr_Format(PyExc_RuntimeError, "Vmm.maps: Not initialized."); }
    return (PyObject*)VmmPycMaps_InitializeInternal();
}

//-----------------------------------------------------------------------------
// VmmPycVmm INITIALIZATION AND CORE FUNCTIONALITY BELOW:
//-----------------------------------------------------------------------------

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
    BOOL result;
    DWORD i, cDstArgs;
    LPSTR *pszDstArgs;
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
        pszDstArgs = (LPSTR *)LocalAlloc(LMEM_ZEROINIT, sizeof(LPSTR) * cDstArgs);
        pyBytesDstArgs = (PyObject **)LocalAlloc(LMEM_ZEROINIT, sizeof(PyObject *) * cDstArgs);
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
        result = VMMDLL_Initialize(cDstArgs, pszDstArgs);
        if(result) {
            VMMDLL_InitializePlugins();
        }
        Py_END_ALLOW_THREADS;
        for(i = PARAM_OFFSET; i < cDstArgs; i++) {
            Py_XDECREF(pyBytesDstArgs[i]);
        }
        if(!result) {
            PyErr_SetString(PyExc_TypeError, "Vmm.init(): Initialization of vmm failed.");
            return -1;
        }
        self->fVmmCoreOpenType = TRUE;
        // initialize vfs:
        if(!self->pyObjVfs) {
            self->pyObjVfs = (PyObject *)VmmPycVfs_InitializeInternal();
        }
    } else {    // INITIALIZE EXISTING VMM (CHECK IF EXISTING IS VALID)
        pyObjProcessTest = (PyObject*)VmmPycProcess_InitializeInternal(4, TRUE);
        if(!pyObjProcessTest) {
            PyErr_SetString(PyExc_TypeError, "Vmm.init(): Initialization of existing vmm failed - please initialize with startup options.");
            return -1;
        }
        Py_DECREF(pyObjProcessTest);
    }
    // success - initialize type object and return!
    self->pyObjKernel = (PyObject*)VmmPycKernel_InitializeInternal();
    self->pyObjMemory = (PyObject*)VmmPycPhysicalMemory_InitializeInternal();
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
            VMMDLL_Close();
            Py_END_ALLOW_THREADS;
        }
    }
    Py_XDECREF(self->pyObjVfs); self->pyObjVfs = NULL;
    Py_XDECREF(self->pyObjKernel); self->pyObjKernel = NULL;
    Py_XDECREF(self->pyObjMemory); self->pyObjMemory = NULL;
}

// () -> None
static PyObject*
VmmPycVmm_close(PyObj_Vmm *self, PyObject *args)
{
    if(!self->fValid) { return PyErr_Format(PyExc_RuntimeError, "Vmm.close(): Not initialized."); }
    VmmPycVmm_dealloc(self);
    return Py_BuildValue("s", NULL);    // None returned on success.
}

_Success_(return)
BOOL VmmPycVmm_InitializeType(PyObject *pModule)
{
    static PyMethodDef PyMethods[] = {
        {"close", (PyCFunction)VmmPycVmm_close, METH_VARARGS, "Close the VMM."},
        {"initialize_plugins", (PyCFunction)VmmPycVmm_initialize_plugins, METH_VARARGS, "Initialize plugin sub-system."},
        {"get_config", (PyCFunction)VmmPycVmm_get_config, METH_VARARGS, "Get configuration value."},
        {"set_config", (PyCFunction)VmmPycVmm_set_config, METH_VARARGS, "Set configuration value."},
        {"process_list", (PyCFunction)VmmPycVmm_process_list, METH_VARARGS, "List processes."},
        {"process", (PyCFunction)VmmPycVmm_process, METH_VARARGS, "Retrieve process by name or PID."},
        {"reg_hive_list", (PyCFunction)VmmPycVmm_reg_hive_list, METH_VARARGS, "List registry hives."},
        {"reg_key", (PyCFunction)VmmPycVmm_reg_key, METH_VARARGS, "Retrieve registry key from full path."},
        {"reg_value", (PyCFunction)VmmPycVmm_reg_value, METH_VARARGS, "Retrieve registry value from full path."},
        {"hex", (PyCFunction)VmmPycVmm_hex, METH_VARARGS, "Convert a bytes object into a human readable 'memory dump' style type of string."},
        {NULL, NULL, 0, NULL}
    };
    static PyMemberDef PyMembers[] = {
        {"memory", T_OBJECT, offsetof(PyObj_Vmm, pyObjMemory), READONLY, "Physical memory."},
        {"kernel", T_OBJECT, offsetof(PyObj_Vmm, pyObjKernel), READONLY, "Kernel information."},
        {"vfs", T_OBJECT, offsetof(PyObj_Vmm, pyObjVfs), READONLY, "Virtual file system."},
        {NULL}
    };
    static PyGetSetDef PyGetSet[] = {
        {"maps", (getter)VmmPycVmm_maps, (setter)NULL, "Info maps.", NULL},
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
