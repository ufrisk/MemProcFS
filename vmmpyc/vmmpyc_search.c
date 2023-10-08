// vmmpyc_search.c : implementation of binary search for vmmpyc.
// 
// vmmpyc_search is a wrapper around the VMMDLL_MemSearch() API.
// It's possible to search physical or virtual memory in various flexible
// ways including a bitwise wildcard search.
// 
// If the search doesn't provide enough flexibility it's possible to search
// using YARA rules - see vmmpyc_yara.c.
//
// (c) Ulf Frisk, 2023
// Author: Ulf Frisk, pcileech@frizk.net
//
#include "vmmpyc.h"

PyObject *g_pPyType_Search = NULL;

// CALLBACK to receive a search result:
BOOL VmmPycSearch_SearchResultCB(_In_ PVMMDLL_MEM_SEARCH_CONTEXT ctxSearch, _In_ QWORD va, _In_ DWORD iSearch)
{
    PyGILState_STATE gstate;
    PyObject *pyListResult;
    PyObj_Search *self = (PyObj_Search*)ctxSearch->pvUserPtrOpt;
    gstate = PyGILState_Ensure();
    pyListResult = PyList_New(0);
    if(pyListResult) {
        PyList_Append_DECREF(pyListResult, PyLong_FromUnsignedLongLong(va));
        PyList_Append_DECREF(pyListResult, PyLong_FromUnsignedLong(iSearch));
        PyList_Append_DECREF(self->pyListResult, pyListResult);
        self->ctxSearch.cResult = (DWORD)PyList_Size(self->pyListResult);
    }
    PyGILState_Release(gstate);
    return self->ctxSearch.cResult < self->ctxSearch.cMaxResult;
}

// Search thread entry point // Internal helper function for VmmPycSearch_start:
DWORD WINAPI VmmPycSearch_start_ThreadProc(LPVOID lpThreadParameter)
{
    PyObj_Search *self = (PyObj_Search*)lpThreadParameter;
    self->fStarted = TRUE;
    self->fCompletedSuccess = VMMDLL_MemSearch(self->pyVMM->hVMM, self->dwPID, &self->ctxSearch, NULL, NULL);
    self->fCompleted = TRUE;
    return 1;
}

// () -> None
static PyObject*
VmmPycSearch_start(PyObj_Search *self, PyObject *args)
{
    HANDLE hThread;
    if(!self->fValid) { return PyErr_Format(PyExc_RuntimeError, "VmmSearch.start(): Not initialized."); }
    if(!self->ctxSearch.cSearch) { return PyErr_Format(PyExc_RuntimeError, "VmmSearch.start(): No search criteria."); }
    if(self->fStarted) { Py_BuildValue("s", NULL); }      // None returned on success.
    Py_BEGIN_ALLOW_THREADS;
    if(!self->fStarted) {
        self->fStarted = TRUE;
        hThread = CreateThread(NULL, 0, VmmPycSearch_start_ThreadProc, self, 0, NULL);
        if(hThread) {
            CloseHandle(hThread);
        } else {
            self->fCompleted = TRUE;
        }
    }
    Py_END_ALLOW_THREADS;
    return Py_BuildValue("s", NULL);        // None returned on success.
}

// Retrieve the search result (blocking):
// () -> [addr1, addr2, ..., addrN]
static PyObject*
VmmPycSearch_result(PyObj_Search *self, PyObject *args)
{
    if(!self->fValid) { return PyErr_Format(PyExc_RuntimeError, "VmmSearch.result(): Not initialized."); }
    if(!self->fStarted) {
        Py_XDECREF(VmmPycSearch_start(self, args));
    }
    if(!self->fStarted) { return PyErr_Format(PyExc_RuntimeError, "VmmSearch.result(): Not started."); }
    while(!self->fCompleted) {
        Py_BEGIN_ALLOW_THREADS;
        SwitchToThread();
        Py_END_ALLOW_THREADS;
    }
    Py_XINCREF(self->pyListResult);
    return self->pyListResult;
}

// Poll the search result (non-blocking):
// () -> [addr1, addr2, ..., addrN]
static PyObject*
VmmPycSearch_poll(PyObj_Search *self, PyObject *args)
{
    if(!self->fValid) { return PyErr_Format(PyExc_RuntimeError, "VmmSearch.poll(): Not initialized."); }
    if(!self->fStarted) { return PyErr_Format(PyExc_RuntimeError, "VmmSearch.poll(): Not started."); }
    Py_XINCREF(self->pyListResult);
    return self->pyListResult;
}

// () -> None
static PyObject*
VmmPycSearch_abort(PyObj_Search *self, PyObject *args)
{
    if(!self->fValid) { return PyErr_Format(PyExc_RuntimeError, "VmmSearch.abort(): Not initialized."); }
    if(self->fStarted && !self->fCompleted) {
        self->ctxSearch.fAbortRequested = TRUE;
    }
    return Py_BuildValue("s", NULL);        // None returned on success.
}

// (PBYTE, PBYTE, DWORD) -> DWORD
static PyObject*
VmmPycSearch_add_search(PyObj_Search *self, PyObject *args)
{
    PyObject *pyObject;
    PBYTE pbSearch = NULL, pbMask = NULL;
    Py_ssize_t cbSearch = 0, cbMask = 0;
    DWORD cbAlign = 1, iSearch = 0;
    if(!self->fValid) { return PyErr_Format(PyExc_RuntimeError, "VmmSearch.add_search(): Not initialized."); }
    if(self->fStarted) { return PyErr_Format(PyExc_RuntimeError, "VmmSearch.add_search(): Search already started."); }
    if(self->ctxSearch.cSearch >= VMMDLL_MEM_SEARCH_MAX) { return PyErr_Format(PyExc_RuntimeError, "VmmSearch.add_search(): Too many searches."); }
    if(!PyArg_ParseTuple(args, "|y#y#k", &pbSearch, &cbSearch, &pbMask, &cbMask, &cbAlign)) {
        PyErr_Clear();
        if(!PyArg_ParseTuple(args, "|y#Ok", &pbSearch, &cbSearch, &pyObject, &cbAlign)) {
            return PyErr_Format(PyExc_RuntimeError, "VmmSearch.add_search(): Illegal argument.");
        }
        if(pyObject != Py_None) {
            return PyErr_Format(PyExc_RuntimeError, "VmmSearch.add_search(): Illegal argument.");
        }
        cbMask = 0;
    }
    if((cbSearch == 0) || (cbSearch > VMMDLL_MEM_SEARCH_MAXLENGTH)) {
        return PyErr_Format(PyExc_RuntimeError, "VmmSearch.add_search(): Search term missing or above max length (%i bytes).", VMMDLL_MEM_SEARCH_MAXLENGTH);
    }
    if(cbMask > cbSearch) {
        return PyErr_Format(PyExc_RuntimeError, "VmmSearch.add_search(): Wildcard mask longer than search term. (%i > %i)", cbMask, cbSearch);
    }
    if(((cbAlign & (cbAlign - 1)) != 0) || (cbAlign > 0x1000)) {
        return PyErr_Format(PyExc_RuntimeError, "VmmSearch.add_search(): Alignment must be a power of 2 and <= 0x1000.");
    }
    iSearch = self->ctxSearch.cSearch;
    self->ctxSearch.cSearch++;
    self->ctxSearch.search[iSearch].cbAlign = cbAlign;
    self->ctxSearch.search[iSearch].cb = (DWORD)cbSearch;
    memcpy(self->ctxSearch.search[iSearch].pb, pbSearch, cbSearch);
    if(cbMask) {
        memcpy(self->ctxSearch.search[iSearch].pbSkipMask, pbMask, cbMask);
    }
    return PyLong_FromUnsignedLong(iSearch);
}

// -> QWORD
static PyObject*
VmmPycSearch_flags_get(PyObj_Search *self, void *closure)
{
    if(!self->fValid) { return PyErr_Format(PyExc_RuntimeError, "VmmSearch.flags: Not initialized."); }
    return (PyObject*)PyLong_FromUnsignedLongLong(self->ctxSearch.ReadFlags);
}

// QWORD ->
static int
VmmPycSearch_flags_set(PyObj_Search *self, PyObject *value, void *closure)
{
    if(!self->fValid) {
        PyErr_SetString(PyExc_TypeError, "VmmSearch.flags: Not initialized.");
        return -1;
    }
    if(!PyLong_Check(value)) {
        PyErr_SetString(PyExc_TypeError, "VmmSearch.flags: Invalid type.");
        return -1;
    }
    if(self->fStarted) {
        PyErr_SetString(PyExc_TypeError, "VmmSearch.flags: Already started.");
        return -1;
    }
    self->ctxSearch.ReadFlags = PyLong_AsUnsignedLongLong(value);
    return 0;
}

// -> QWORD
static PyObject*
VmmPycSearch_addr_min_get(PyObj_Search *self, void *closure)
{
    if(!self->fValid) { return PyErr_Format(PyExc_RuntimeError, "VmmSearch.addr_min: Not initialized."); }
    return (PyObject*)PyLong_FromUnsignedLongLong(self->ctxSearch.vaMin);
}

// QWORD ->
static int
VmmPycSearch_addr_min_set(PyObj_Search *self, PyObject *value, void *closure)
{
    if(!self->fValid) {
        PyErr_SetString(PyExc_TypeError, "VmmSearch.addr_min: Not initialized.");
        return -1;
    }
    if(!PyLong_Check(value)) {
        PyErr_SetString(PyExc_TypeError, "VmmSearch.addr_min: Invalid type.");
        return -1;
    }
    if(self->fStarted) {
        PyErr_SetString(PyExc_TypeError, "VmmSearch.addr_min: Already started.");
        return -1;
    }
    self->ctxSearch.vaMin = PyLong_AsUnsignedLongLong(value);
    return 0;
}

// -> QWORD
static PyObject*
VmmPycSearch_addr_max_get(PyObj_Search *self, void *closure)
{
    if(!self->fValid) { return PyErr_Format(PyExc_RuntimeError, "VmmSearch.addr_max: Not initialized."); }
    return (PyObject*)PyLong_FromUnsignedLongLong(self->ctxSearch.vaMax);
}

// QWORD ->
static int
VmmPycSearch_addr_max_set(PyObj_Search *self, PyObject *value, void *closure)
{
    if(!self->fValid) {
        PyErr_SetString(PyExc_TypeError, "VmmSearch.addr_max: Not initialized.");
        return -1;
    }
    if(!PyLong_Check(value)) {
        PyErr_SetString(PyExc_TypeError, "VmmSearch.addr_max: Invalid type.");
        return -1;
    }
    if(self->fStarted) {
        PyErr_SetString(PyExc_TypeError, "VmmSearch.addr_max: Already started.");
        return -1;
    }
    self->ctxSearch.vaMax = PyLong_AsUnsignedLongLong(value);
    return 0;
}

// -> DWORD
static PyObject*
VmmPycSearch_max_results_get(PyObj_Search *self, void *closure)
{
    if(!self->fValid) { return PyErr_Format(PyExc_RuntimeError, "VmmSearch.max_results: Not initialized."); }
    return (PyObject*)PyLong_FromUnsignedLong(self->ctxSearch.cMaxResult);
}

// DWORD ->
static int
VmmPycSearch_max_results_set(PyObj_Search *self, PyObject *value, void *closure)
{
    DWORD dw;
    if(!self->fValid) {
        PyErr_SetString(PyExc_TypeError, "VmmSearch.max_results: Not initialized.");
        return -1;
    }
    if(!PyLong_Check(value)) {
        PyErr_SetString(PyExc_TypeError, "VmmSearch.max_results: Invalid type.");
        return -1;
    }
    if(self->fStarted) {
        PyErr_SetString(PyExc_TypeError, "VmmSearch.max_results: Already started.");
        return -1;
    }
    dw = PyLong_AsUnsignedLong(value);
    if((dw == (DWORD)-1) || (dw == 0) || (dw > 0x10000)) {
        PyErr_SetString(PyExc_TypeError, "VmmSearch.max_results: Invalid number [max 65536(0x10000) allowed].");
        return -1;
    }
    self->ctxSearch.cMaxResult = dw;
    return 0;
}

//-----------------------------------------------------------------------------
// VmmPycSearch INITIALIZATION AND CORE FUNCTIONALITY BELOW:
//-----------------------------------------------------------------------------

// args: (_In_opt_ QWORD vaMin, _In_opt_ QWORD vaMax, _In_opt_ QWORD qwReadFlags)
PyObj_Search*
VmmPycSearch_InitializeInternal(_In_ PyObj_Vmm *pyVMM, _In_opt_ DWORD dwPID, _In_ PyObject *args)
{
    PyObj_Search *pyObj;
    QWORD vaMin = 0, vaMax = 0, qwReadFlags = 0;
    // parse optional arguments:
    if(!PyArg_ParseTuple(args, "|KKK", &vaMin, &vaMax, &qwReadFlags)) {
        return NULL;
    }
    vaMin = vaMin & 0xfffffffffffff000;
    vaMax = vaMax & 0xfffffffffffff000;
    if(vaMax && (vaMax <= vaMin)) { return NULL; }
    // general object init:
    if(!(pyObj = PyObject_New(PyObj_Search, (PyTypeObject*)g_pPyType_Search))) { return NULL; }
    Py_INCREF(pyVMM); pyObj->pyVMM = pyVMM;
    pyObj->dwPID = dwPID;
    pyObj->fStarted = FALSE;
    pyObj->fCompleted = FALSE;
    pyObj->fCompletedSuccess = FALSE;
    if(!(pyObj->pyListResult = PyList_New(0))) {
        Py_DECREF(pyObj);
        return NULL;
    }
    // search context init:
    memset(&pyObj->ctxSearch, 0, sizeof(VMMDLL_MEM_SEARCH_CONTEXT));
    pyObj->ctxSearch.dwVersion = VMMDLL_MEM_SEARCH_VERSION;
    pyObj->ctxSearch.vaMin = vaMin;
    pyObj->ctxSearch.vaMax = vaMax;
    pyObj->ctxSearch.cMaxResult = 0x10000;
    pyObj->ctxSearch.ReadFlags = qwReadFlags;
    pyObj->ctxSearch.pvUserPtrOpt = pyObj;
    pyObj->ctxSearch.pfnResultOptCB = VmmPycSearch_SearchResultCB;
    // finish & return:
    pyObj->fValid = TRUE;
    return pyObj;
}

static PyObject*
VmmPycSearch_repr(PyObj_Search *self)
{
    if(!self->fValid) {
        return PyUnicode_FromFormat("VmmSearch:NotValid");
    } else if(self->dwPID != (DWORD)-1) {
        return PyUnicode_FromFormat("VmmSearch:Virtual:%i", self->dwPID);
    } else {
        return PyUnicode_FromFormat("VmmSearch:Physical");
    }
}

static int
VmmPycSearch_init(PyObj_Search *self, PyObject *args, PyObject *kwds)
{
    PyErr_SetString(PyExc_TypeError, "VmmSearch.init(): Not allowed.");
    return -1;
}

static void
VmmPycSearch_dealloc(PyObj_Search *self)
{
    self->fValid = FALSE;
    if(self->fStarted && !self->fCompleted) {
        Py_BEGIN_ALLOW_THREADS;
        self->ctxSearch.fAbortRequested = TRUE;
        while(!self->fCompleted) {
            SwitchToThread();
        }
        Py_END_ALLOW_THREADS;
    }
    Py_XDECREF(self->pyListResult);
    Py_XDECREF(self->pyVMM);
    PyObject_Del(self);
}

_Success_(return)
BOOL VmmPycSearch_InitializeType(PyObject *pModule)
{
    static PyMethodDef PyMethods[] = {
        {"add_search", (PyCFunction)VmmPycSearch_add_search, METH_VARARGS, "Add a search term (with optional wildcard)."},
        {"start", (PyCFunction)VmmPycSearch_start, METH_VARARGS, "Start a search."},
        {"poll", (PyCFunction)VmmPycSearch_poll, METH_VARARGS, "Poll a search (retrieve search result non-blocking)."},
        {"result", (PyCFunction)VmmPycSearch_result, METH_VARARGS, "Result of a search (blocking, wait until search is finished)."},
        {"abort", (PyCFunction)VmmPycSearch_abort, METH_VARARGS, "Abort an ongoing search."},
        {NULL, NULL, 0, NULL}
    };
    static PyMemberDef PyMembers[] = {
        {"addr_current", T_ULONGLONG, offsetof(PyObj_Search, ctxSearch.vaCurrent), READONLY, "Current address searched."},
        {"bytes_searched", T_ULONGLONG, offsetof(PyObj_Search, ctxSearch.cbReadTotal), READONLY, "Number of bytes searched."},
        {"is_aborted", T_BOOL, offsetof(PyObj_Search, ctxSearch.fAbortRequested), READONLY, "Abort of search is requested."},
        {"is_completed", T_BOOL,offsetof(PyObj_Search, fCompleted), READONLY, "Search is completed (successfully or unsuccessfully)."},
        {"is_completed_success", T_BOOL, offsetof(PyObj_Search, fCompletedSuccess), READONLY, "Search is completed successfully."},
        {"is_started", T_BOOL, offsetof(PyObj_Search, fStarted), READONLY, "Search is started."},
        {"num_searches", T_ULONG, offsetof(PyObj_Search, ctxSearch.cSearch), READONLY, "Number of search terms."},
        {"pid", T_ULONG, offsetof(PyObj_Search, dwPID), READONLY, "PID."},
        {NULL}
    };
    static PyGetSetDef PyGetSet[] = {
        {"addr_max", (getter)VmmPycSearch_addr_max_get, (setter)VmmPycSearch_addr_max_set, "Max address to search.", NULL},
        {"addr_min", (getter)VmmPycSearch_addr_min_get, (setter)VmmPycSearch_addr_min_set, "Min address to search.", NULL},
        {"flags", (getter)VmmPycSearch_flags_get, (setter)VmmPycSearch_flags_set, "Read Flags.", NULL},
        {"max_results", (getter)VmmPycSearch_max_results_get, (setter)VmmPycSearch_max_results_set, "Max address to search.", NULL},
        {NULL}
    };
    static PyType_Slot PyTypeSlot[] = {
        {Py_tp_init, VmmPycSearch_init},
        {Py_tp_dealloc, VmmPycSearch_dealloc},
        {Py_tp_repr, VmmPycSearch_repr},
        {Py_tp_methods, PyMethods},
        {Py_tp_members, PyMembers},
        {Py_tp_getset, PyGetSet},
        {0, 0}
    };
    static PyType_Spec PyTypeSpec = {
        .name = "vmmpyc.VmmSearch",
        .basicsize = sizeof(PyObj_Search),
        .itemsize = 0,
        .flags = Py_TPFLAGS_DEFAULT,
        .slots = PyTypeSlot,
    };
    if((g_pPyType_Search = PyType_FromSpec(&PyTypeSpec))) {
        if(PyModule_AddObject(pModule, "VmmSearch", g_pPyType_Search) < 0) {
            Py_DECREF(g_pPyType_Search);
            g_pPyType_Search = NULL;
        }
    }
    return g_pPyType_Search ? TRUE : FALSE;
}
