// vmmpyc_process.c : implementation of process functionality for vmmpyc.
//
// (c) Ulf Frisk, 2021-2025
// Author: Ulf Frisk, pcileech@frizk.net
//
#include "vmmpyc.h"

PyObject *g_pPyType_Process = NULL;

// () -> STR
static PyObject*
VmmPycProcess_cmdline(PyObj_Process *self, PyObject *args)
{
    PyObject *pyUnicode;
    LPSTR sz;
    if(!self->fValid) { return PyErr_Format(PyExc_RuntimeError, "Process.cmdline(): Not initialized."); }
    Py_BEGIN_ALLOW_THREADS;
    sz = VMMDLL_ProcessGetInformationString(self->pyVMM->hVMM, self->dwPID, VMMDLL_PROCESS_INFORMATION_OPT_STRING_CMDLINE);
    Py_END_ALLOW_THREADS;
    if(!sz) { return PyErr_Format(PyExc_RuntimeError, "Process.cmdline(): Failed."); }
    pyUnicode = PyUnicode_DecodeUTF8(sz, strlen(sz), NULL);
    VMMDLL_MemFree(sz);
    return pyUnicode;
}

// () -> STR
static PyObject*
VmmPycProcess_pathuser(PyObj_Process *self, PyObject *args)
{
    PyObject *pyUnicode;
    LPSTR sz;
    if(!self->fValid) { return PyErr_Format(PyExc_RuntimeError, "Process.pathuser(): Not initialized."); }
    Py_BEGIN_ALLOW_THREADS;
    sz = VMMDLL_ProcessGetInformationString(self->pyVMM->hVMM, self->dwPID, VMMDLL_PROCESS_INFORMATION_OPT_STRING_PATH_USER_IMAGE);
    Py_END_ALLOW_THREADS;
    if(!sz) { return PyErr_Format(PyExc_RuntimeError, "Process.pathuser(): Failed."); }
    pyUnicode = PyUnicode_DecodeUTF8(sz, strlen(sz), NULL);
    VMMDLL_MemFree(sz);
    return pyUnicode;
}

// () -> STR
static PyObject*
VmmPycProcess_pathkernel(PyObj_Process *self, PyObject *args)
{
    PyObject *pyUnicode;
    LPSTR sz;
    if(!self->fValid) { return PyErr_Format(PyExc_RuntimeError, "Process.pathkernel(): Not initialized."); }
    Py_BEGIN_ALLOW_THREADS;
    sz = VMMDLL_ProcessGetInformationString(self->pyVMM->hVMM, self->dwPID, VMMDLL_PROCESS_INFORMATION_OPT_STRING_PATH_KERNEL);
    Py_END_ALLOW_THREADS;
    if(!sz) { return PyErr_Format(PyExc_RuntimeError, "Process.pathkernel(): Failed."); }
    pyUnicode = PyUnicode_DecodeUTF8(sz, strlen(sz), NULL);
    VMMDLL_MemFree(sz);
    return pyUnicode;
}

// () -> [PyObj_Module*, ...]
static PyObject*
VmmPycProcess_module_list(PyObj_Process *self, PyObject *args)
{
    PyObject *pyList, *pyObjModule;
    BOOL result;
    ULONG64 i;
    PVMMDLL_MAP_MODULE pModuleMap = NULL;
    if(!self->fValid) { return PyErr_Format(PyExc_RuntimeError, "Process.module_list(): Not initialized."); }
    if(!(pyList = PyList_New(0))) { return PyErr_NoMemory(); }
    Py_BEGIN_ALLOW_THREADS;
    result = VMMDLL_Map_GetModuleU(self->pyVMM->hVMM, self->dwPID, &pModuleMap, 0);
    Py_END_ALLOW_THREADS;
    if(!result || (pModuleMap->dwVersion != VMMDLL_MAP_MODULE_VERSION)) {
        Py_DECREF(pyList);
        VMMDLL_MemFree(pModuleMap);
        return PyErr_Format(PyExc_RuntimeError, "Process.module_list(): Failed.");
    }
    for(i = 0; i < pModuleMap->cMap; i++) {
        if((pyObjModule = (PyObject*)VmmPycModule_InitializeInternal(self->pyVMM, self->dwPID, pModuleMap->pMap + i))) {
            PyList_Append_DECREF(pyList, pyObjModule);
        }
    }
    VMMDLL_MemFree(pModuleMap);
    return pyList;
}

// (STR) -> PyObj_Module*
static PyObject*
VmmPycProcess_module(PyObj_Process *self, PyObject *args)
{
    PyObject *pyObjModule;
    BOOL result;
    LPSTR uszModuleName = NULL;
    PVMMDLL_MAP_MODULEENTRY pe = NULL;
    if(!self->fValid) { return PyErr_Format(PyExc_RuntimeError, "Process.module(): Not initialized."); }
    if(!PyArg_ParseTuple(args, "s", &uszModuleName) || !uszModuleName) {
        return PyErr_Format(PyExc_RuntimeError, "Process.module(): Illegal argument.");
    }
    Py_BEGIN_ALLOW_THREADS;
    result = VMMDLL_Map_GetModuleFromNameU(self->pyVMM->hVMM, self->dwPID, uszModuleName, &pe, 0);
    Py_END_ALLOW_THREADS;
    if(!result) {
        VMMDLL_MemFree(pe);
        return PyErr_Format(PyExc_RuntimeError, "Process.module(): Failed.");
    }
    pyObjModule = (PyObject*)VmmPycModule_InitializeInternal(self->pyVMM, self->dwPID, pe);
    VMMDLL_MemFree(pe);
    return pyObjModule ? pyObjModule : PyErr_Format(PyExc_RuntimeError, "Process.module(): Failed.");
}

// -> *PyObj_VirtualMemory
static PyObject*
VmmPycProcess_memory(PyObj_Process *self, void *closure)
{
    if(!self->fValid) { return PyErr_Format(PyExc_RuntimeError, "Process.memory: Not initialized."); }
    if(!self->pyObjMemoryOpt) { self->pyObjMemoryOpt = (PyObject*)VmmPycVirtualMemory_InitializeInternal(self->pyVMM, self->dwPID); }
    Py_XINCREF(self->pyObjMemoryOpt);
    return self->pyObjMemoryOpt;
}

// -> *PyObj_ProcessMaps
static PyObject*
VmmPycProcess_maps(PyObj_Process *self, void *closure)
{
    if(!self->fValid) { return PyErr_Format(PyExc_RuntimeError, "Process.maps: Not initialized."); }
    if(!self->pyObjMapsOpt) { self->pyObjMapsOpt = (PyObject*)VmmPycProcessMaps_InitializeInternal(self->pyVMM, self->dwPID); }
    Py_XINCREF(self->pyObjMapsOpt);
    return self->pyObjMapsOpt;
}

// (|QWORD, QWORD, QWORD) -> PyObj_Search*
static PyObject*
VmmPycProcess_search(PyObj_Process *self, PyObject *args)
{
    PyObject *pyObj;
    LPSTR uszName = NULL;
    if(!self->fValid) { return PyErr_Format(PyExc_RuntimeError, "Process.search(): Not initialized."); }
    pyObj = (PyObject*)VmmPycSearch_InitializeInternal(self->pyVMM, self->dwPID, args);
    if(!pyObj) {
        return PyErr_Format(PyExc_RuntimeError, "Process.search(): Illegal argument.");
    }
    return pyObj;
}

// (PyList(STR), |QWORD, QWORD, DWORD, QWORD) ->PyObj_Yara*
static PyObject*
VmmPycProcess_search_yara(PyObj_Process *self, PyObject *args)
{
    PyObject *pyObj;
    LPSTR uszName = NULL;
    if(!self->fValid) { return PyErr_Format(PyExc_RuntimeError, "Process.search_yara(): Not initialized."); }
    pyObj = (PyObject*)VmmPycYara_InitializeInternal(self->pyVMM, self->dwPID, args);
    if(!pyObj) {
        return PyErr_Format(PyExc_RuntimeError, "Process.search_yara(): Illegal argument.");
    }
    return pyObj;
}

//-----------------------------------------------------------------------------
// VmmPycProcess: INFO PROPERTIES BELOW:
//-----------------------------------------------------------------------------

// -> PyError on FAIL, NULL on success
static PyObject*
VmmPycProcess_EnsureInfo(_Inout_ PyObj_Process *self, _In_ LPSTR szFN)
{
    BOOL result;
    SIZE_T cbInfo = sizeof(VMMDLL_PROCESS_INFORMATION);
    if(!self->fValid) { return PyErr_Format(PyExc_RuntimeError, "Process.%s: Not initialized.", szFN); }
    if(self->fValidInfo) { return NULL; }
    Py_BEGIN_ALLOW_THREADS;
    ZeroMemory(&self->Info, sizeof(VMMDLL_PROCESS_INFORMATION));
    self->Info.magic = VMMDLL_PROCESS_INFORMATION_MAGIC;
    self->Info.wVersion = VMMDLL_PROCESS_INFORMATION_VERSION;
    result = VMMDLL_ProcessGetInformation(self->pyVMM->hVMM, self->dwPID, &self->Info, &cbInfo);
    Py_END_ALLOW_THREADS;
    if(!result) {
        return PyErr_Format(PyExc_RuntimeError, "Process.%s: Failed.", szFN);
    }
    self->fValidInfo = TRUE;
    return NULL;
}

// -> DWORD
static PyObject*
VmmPycProcess_pid(PyObj_Process *self, void *closure)
{
    PyObject *pyErr;
    if((pyErr = VmmPycProcess_EnsureInfo(self, "pid"))) { return pyErr; }
    return PyLong_FromUnsignedLong(self->Info.dwPID);
}

// -> DWORD
static PyObject*
VmmPycProcess_ppid(PyObj_Process *self, void *closure)
{
    PyObject *pyErr;
    if((pyErr = VmmPycProcess_EnsureInfo(self, "ppid"))) { return pyErr; }
    return PyLong_FromUnsignedLong(self->Info.dwPPID);
}

// -> QWORD
static PyObject*
VmmPycProcess_dtb(PyObj_Process *self, void *closure)
{
    PyObject *pyErr;
    if((pyErr = VmmPycProcess_EnsureInfo(self, "dtb"))) { return pyErr; }
    return PyLong_FromUnsignedLongLong(self->Info.paDTB);
}

// -> QWORD
static PyObject*
VmmPycProcess_dtb_user(PyObj_Process *self, void *closure)
{
    PyObject *pyErr;
    if((pyErr = VmmPycProcess_EnsureInfo(self, "dtb_user"))) { return pyErr; }
    return PyLong_FromUnsignedLongLong(self->Info.paDTB_UserOpt);
}

// -> DWORD
static PyObject*
VmmPycProcess_state(PyObj_Process *self, void *closure)
{
    PyObject *pyErr;
    if((pyErr = VmmPycProcess_EnsureInfo(self, "state"))) { return pyErr; }
    return PyLong_FromUnsignedLong(self->Info.dwState);
}

// -> QWORD
static PyObject*
VmmPycProcess_tp_memorymodel(PyObj_Process *self, void *closure)
{
    PyObject *pyErr;
    if((pyErr = VmmPycProcess_EnsureInfo(self, "tp_memorymodel"))) { return pyErr; }
    return PyLong_FromUnsignedLongLong(self->Info.tpMemoryModel);
}

// -> QWORD
static PyObject*
VmmPycProcess_tp_system(PyObj_Process *self, void *closure)
{
    PyObject *pyErr;
    if((pyErr = VmmPycProcess_EnsureInfo(self, "tp_system"))) { return pyErr; }
    return PyLong_FromUnsignedLongLong(self->Info.tpSystem);
}

// -> BOOL
static PyObject*
VmmPycProcess_is_usermode(PyObj_Process *self, void *closure)
{
    PyObject *pyErr;
    if((pyErr = VmmPycProcess_EnsureInfo(self, "is_usermode"))) { return pyErr; }
    return PyBool_FromLong(self->Info.fUserOnly);
}

// -> STR
static PyObject*
VmmPycProcess_name(PyObj_Process *self, void *closure)
{
    PyObject *pyErr;
    if((pyErr = VmmPycProcess_EnsureInfo(self, "name"))) { return pyErr; }
    return PyUnicode_FromFormat("%s", self->Info.szName);
}

// -> STR
static PyObject*
VmmPycProcess_fullname(PyObj_Process *self, void *closure)
{
    PyObject *pyErr;
    if((pyErr = VmmPycProcess_EnsureInfo(self, "fullname"))) { return pyErr; }
    return PyUnicode_FromFormat("%s", self->Info.szNameLong);
}

// -> BOOL
static PyObject*
VmmPycProcess_is_wow64(PyObj_Process *self, void *closure)
{
    PyObject *pyErr;
    if((pyErr = VmmPycProcess_EnsureInfo(self, "is_wow64"))) { return pyErr; }
    return PyBool_FromLong((long)self->Info.win.fWow64);
}

// -> QWORD
static PyObject*
VmmPycProcess_peb(PyObj_Process *self, void *closure)
{
    PyObject *pyErr;
    if((pyErr = VmmPycProcess_EnsureInfo(self, "peb"))) { return pyErr; }
    return PyLong_FromUnsignedLongLong(self->Info.win.vaPEB);
}

// -> DWORD
static PyObject*
VmmPycProcess_peb32(PyObj_Process *self, void *closure)
{
    PyObject *pyErr;
    if((pyErr = VmmPycProcess_EnsureInfo(self, "peb32"))) { return pyErr; }
    return PyLong_FromUnsignedLong(self->Info.win.vaPEB32);
}

// -> QWORD
static PyObject*
VmmPycProcess_eprocess(PyObj_Process *self, void *closure)
{
    PyObject *pyErr;
    if((pyErr = VmmPycProcess_EnsureInfo(self, "eprocess"))) { return pyErr; }
    return PyLong_FromUnsignedLongLong(self->Info.win.vaEPROCESS);
}

// -> QWORD
static PyObject*
VmmPycProcess_luid(PyObj_Process *self, void *closure)
{
    PyObject *pyErr;
    if((pyErr = VmmPycProcess_EnsureInfo(self, "luid"))) { return pyErr; }
    return PyLong_FromUnsignedLongLong(self->Info.win.qwLUID);
}

// -> DWORD
static PyObject*
VmmPycProcess_session(PyObj_Process *self, void *closure)
{
    PyObject *pyErr;
    if((pyErr = VmmPycProcess_EnsureInfo(self, "session"))) { return pyErr; }
    return PyLong_FromUnsignedLong(self->Info.win.dwSessionId);
}

// -> STR
static PyObject *
VmmPycProcess_sid(PyObj_Process *self, void *closure)
{
    PyObject *pyErr;
    if((pyErr = VmmPycProcess_EnsureInfo(self, "sid"))) { return pyErr; }
    return PyUnicode_FromFormat("%s", self->Info.win.szSID);
}

// -> DWORD
static PyObject*
VmmPycProcess_integrity(PyObj_Process *self, void *closure)
{
    PyObject *pyErr;
    if((pyErr = VmmPycProcess_EnsureInfo(self, "integrity"))) { return pyErr; }
    return PyLong_FromUnsignedLong(self->Info.win.IntegrityLevel);
}

//-----------------------------------------------------------------------------
// VmmPycProcess INITIALIZATION AND CORE FUNCTIONALITY BELOW:
//-----------------------------------------------------------------------------

PyObj_Process*
VmmPycProcess_InitializeInternal(_In_ PyObj_Vmm *pyVMM, _In_ DWORD dwPID, _In_ BOOL fVerify)
{
    PyObj_Process *pyObj;
    PVMMDLL_MAP_MODULE pModuleMap = NULL;
    BOOL fResult;
    if(fVerify) {
        Py_BEGIN_ALLOW_THREADS;
        fResult = VMMDLL_Map_GetModuleU(pyVMM->hVMM, dwPID, &pModuleMap, 0);
        Py_END_ALLOW_THREADS;
        if(!fResult) { return NULL; }
        VMMDLL_MemFree(pModuleMap);
    }
    if(!(pyObj = PyObject_New(PyObj_Process, (PyTypeObject*)g_pPyType_Process))) { return NULL; }
    Py_INCREF(pyVMM); pyObj->pyVMM = pyVMM;
    pyObj->fValid = TRUE;
    pyObj->dwPID = dwPID;
    pyObj->fValidInfo = FALSE;
    pyObj->pyObjMapsOpt = NULL;
    pyObj->pyObjMemoryOpt = NULL;
    return pyObj;
}

static PyObject*
VmmPycProcess_repr(PyObj_Process *self)
{
    return self->fValid ?
        PyUnicode_FromFormat("Process:%i", self->dwPID) :
        PyUnicode_FromFormat("Process:NotValid");
}

static int
VmmPycProcess_init(PyObj_Process *self, PyObject *args, PyObject *kwds)
{
    PyErr_SetString(PyExc_TypeError, "Process.init(): Not allowed.");
    return -1;
}

static void
VmmPycProcess_dealloc(PyObj_Process *self)
{
    self->fValid = FALSE;
    Py_XDECREF(self->pyObjMapsOpt);
    Py_XDECREF(self->pyObjMemoryOpt);
    Py_XDECREF(self->pyVMM);
    PyObject_Del(self);
}

_Success_(return)
BOOL VmmPycProcess_InitializeType(PyObject *pModule)
{
    static PyMethodDef PyMethods[] = {
        {"module_list", (PyCFunction)VmmPycProcess_module_list, METH_VARARGS, "Retrieve all loaded modules (dlls)."},
        {"module", (PyCFunction)VmmPycProcess_module, METH_VARARGS, "Retrieve a single module (dll) from its name."},
        {"search", (PyCFunction)VmmPycProcess_search, METH_VARARGS, "Perform a binary search."},
        {"search_yara", (PyCFunction)VmmPycProcess_search_yara, METH_VARARGS, "Perform a YARA search."},
        {NULL, NULL, 0, NULL}
    };
    static PyMemberDef PyMembers[] = {
        {NULL}
    };
    static PyGetSetDef PyGetSet[] = {
        {"pid", (getter)VmmPycProcess_pid, (setter)NULL, "pricess id (PID)", NULL},
        {"ppid", (getter)VmmPycProcess_ppid, (setter)NULL, "parent pid (PPID).", NULL},
        {"dtb", (getter)VmmPycProcess_dtb, (setter)NULL, "directory table base (DTB).", NULL},
        {"dtb_user", (getter)VmmPycProcess_dtb_user, (setter)NULL, "user directory table base (DTB).", NULL},
        {"state", (getter)VmmPycProcess_state, (setter)NULL, "proces state.", NULL},
        {"tp_memorymodel", (getter)VmmPycProcess_tp_memorymodel, (setter)NULL, "memory model type.", NULL},
        {"tp_system", (getter)VmmPycProcess_tp_system, (setter)NULL, "system type.", NULL},
        {"is_usermode", (getter)VmmPycProcess_is_usermode, (setter)NULL, "is user mode process.", NULL},
        {"name", (getter)VmmPycProcess_name, (setter)NULL, "short name.", NULL},
        {"fullname", (getter)VmmPycProcess_fullname, (setter)NULL, "full name.", NULL},
        {"is_wow64", (getter)VmmPycProcess_is_wow64, (setter)NULL, "32-bit process on 64-bit Windows.", NULL},
        {"peb", (getter)VmmPycProcess_peb, (setter)NULL, "process environment block (PEB).", NULL},
        {"peb32", (getter)VmmPycProcess_peb32, (setter)NULL, "32-bit PEB in 32-bit process on 64-bit Windows.", NULL},
        {"eprocess", (getter)VmmPycProcess_eprocess, (setter)NULL, "address of EPROCESS.", NULL},
        {"luid", (getter)VmmPycProcess_luid, (setter)NULL, "token LUID.", NULL},
        {"session", (getter)VmmPycProcess_session, (setter)NULL, "token session.", NULL},
        {"sid", (getter)VmmPycProcess_sid, (setter)NULL, "token SID.", NULL},
        {"integrity", (getter)VmmPycProcess_integrity, (setter)NULL, "integrity level.", NULL},
        {"cmdline", (getter)VmmPycProcess_cmdline, (setter)NULL, "command line.", NULL},
        {"pathkernel", (getter)VmmPycProcess_pathkernel, (setter)NULL, "kernel path.", NULL},
        {"pathuser", (getter)VmmPycProcess_pathuser, (setter)NULL, "user mode path.", NULL},
        {"memory", (getter)VmmPycProcess_memory, (setter)NULL, "virtual memory.", NULL},
        {"maps", (getter)VmmPycProcess_maps, (setter)NULL, "info maps.", NULL},
        {NULL}
    };
    static PyType_Slot PyTypeSlot[] = {
        {Py_tp_init, VmmPycProcess_init},
        {Py_tp_dealloc, VmmPycProcess_dealloc},
        {Py_tp_repr, VmmPycProcess_repr},
        {Py_tp_methods, PyMethods},
        {Py_tp_members, PyMembers},
        {Py_tp_getset, PyGetSet},
        {0, 0}
    };
    static PyType_Spec PyTypeSpec = {
        .name = "vmmpyc.VmmProcess",
        .basicsize = sizeof(PyObj_Process),
        .itemsize = 0,
        .flags = Py_TPFLAGS_DEFAULT,
        .slots = PyTypeSlot,
    };
    if((g_pPyType_Process = PyType_FromSpec(&PyTypeSpec))) {
        if(PyModule_AddObject(pModule, "VmmProcess", g_pPyType_Process) < 0) {
            Py_DECREF(g_pPyType_Process);
            g_pPyType_Process = NULL;
        }
    }
    return g_pPyType_Process ? TRUE : FALSE;
}
