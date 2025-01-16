// vmmpyc_yara.c : implementation of YARA search for vmmpyc.
// 
// vmmpyc_yara is a wrapper around the VMMDLL_YaraSearch() API.
// It's possible to search physical and virtual address space using YARA rules.
//
// (c) Ulf Frisk, 2023-2025
// Author: Ulf Frisk, pcileech@frizk.net
//
#include "vmmpyc.h"

PyObject *g_pPyType_Yara = NULL;

// CALLBACK to receive a search result:
BOOL VmmPycYara_SearchResultCB(_In_ PVOID pvContext, _In_ PVMMYARA_RULE_MATCH pRuleMatch, _In_reads_bytes_(cbBuffer) PBYTE pbBuffer, _In_ SIZE_T cbBuffer)
{
    DWORD i, j;
    PyGILState_STATE gstate;
    PyObject *pyDictResult, *pyListTags, *pyDictMeta, *pyDictMatch;
    PyObject *pyMatchString, *pyMatchList;
    PyObj_Yara *self = (PyObj_Yara*)pvContext;
    gstate = PyGILState_Ensure();
    pyDictResult = PyDict_New();
    if(pyDictResult) {
        PyDict_SetItemString_DECREF(pyDictResult, "id", PyUnicode_FromString(pRuleMatch->szRuleIdentifier));
        if((pyListTags = PyList_New(0))) {
            for(i = 0; i < pRuleMatch->cTags; i++) {
                PyList_Append_DECREF(pyListTags, PyUnicode_FromString(pRuleMatch->szTags[i]));
            }
            PyDict_SetItemString_DECREF(pyDictResult, "tags", pyListTags);
        }
        if((pyDictMeta = PyDict_New())) {
            for(i = 0; i < pRuleMatch->cMeta; i++) {
                PyDict_SetItemString_DECREF(pyDictMeta, pRuleMatch->Meta[i].szIdentifier, PyUnicode_FromString(pRuleMatch->Meta[i].szString));
            }
            PyDict_SetItemString_DECREF(pyDictResult, "meta", pyListTags);
        }
        if((pyDictMatch = PyDict_New())) {
            for(i = 0; i < pRuleMatch->cStrings; i++) {
                pyMatchString = PyUnicode_FromString(pRuleMatch->Strings[i].szString);
                if(!pyMatchString) {
                    pyMatchString = PyUnicode_FromFormat("_%i", i);
                }
                if(!pyMatchString) { break; }
                pyMatchList = PyList_New(0);
                if(!pyMatchList) { break; }
                for(j = 0; j < pRuleMatch->Strings[i].cMatch; j++) {
                    PyList_Append_DECREF(pyMatchList, PyLong_FromUnsignedLongLong(self->ctxYara.vaCurrent + pRuleMatch->Strings[i].cbMatchOffset[j]));
                }
                PyDict_SetItem(pyDictMatch, pyMatchString, pyMatchList);
                Py_XDECREF(pyMatchString);
                Py_XDECREF(pyMatchList);
            }
            PyDict_SetItemString_DECREF(pyDictResult, "matches", pyDictMatch);
        }
        PyList_Append_DECREF(self->pyListResult, pyDictResult);
    }
    PyGILState_Release(gstate);
    return TRUE;
}

// Search thread entry point // Internal helper function for VmmPycYara_start:
DWORD WINAPI VmmPycYara_start_ThreadProc(LPVOID lpThreadParameter)
{
    PyObj_Yara *self = (PyObj_Yara*)lpThreadParameter;
    self->fStarted = TRUE;
    self->fCompletedSuccess = VMMDLL_YaraSearch(self->pyVMM->hVMM, self->dwPID, &self->ctxYara, NULL, NULL);
    self->fCompleted = TRUE;
    return 1;
}

// () -> None
static PyObject*
VmmPycYara_start(PyObj_Yara *self, PyObject *args)
{
    HANDLE hThread;
    if(!self->fValid) { return PyErr_Format(PyExc_RuntimeError, "VmmYara.start(): Not initialized."); }
    if(self->fStarted) { Py_BuildValue("s", NULL); }      // None returned on success.
    Py_BEGIN_ALLOW_THREADS;
    if(!self->fStarted) {
        self->fStarted = TRUE;
        hThread = CreateThread(NULL, 0, VmmPycYara_start_ThreadProc, self, 0, NULL);
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
VmmPycYara_result(PyObj_Yara *self, PyObject *args)
{
    if(!self->fValid) { return PyErr_Format(PyExc_RuntimeError, "VmmYara.result(): Not initialized."); }
    if(!self->fStarted) {
        Py_XDECREF(VmmPycYara_start(self, args));
    }
    if(!self->fStarted) { return PyErr_Format(PyExc_RuntimeError, "VmmYara.result(): Not started."); }
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
VmmPycYara_poll(PyObj_Yara *self, PyObject *args)
{
    if(!self->fValid) { return PyErr_Format(PyExc_RuntimeError, "VmmYara.poll(): Not initialized."); }
    if(!self->fStarted) { return PyErr_Format(PyExc_RuntimeError, "VmmYara.poll(): Not started."); }
    Py_XINCREF(self->pyListResult);
    return self->pyListResult;
}

// () -> None
static PyObject*
VmmPycYara_abort(PyObj_Yara *self, PyObject *args)
{
    if(!self->fValid) { return PyErr_Format(PyExc_RuntimeError, "VmmYara.abort(): Not initialized."); }
    if(self->fStarted && !self->fCompleted) {
        self->ctxYara.fAbortRequested = TRUE;
    }
    return Py_BuildValue("s", NULL);        // None returned on success.
}

// -> QWORD
static PyObject*
VmmPycYara_flags_get(PyObj_Yara *self, void *closure)
{
    if(!self->fValid) { return PyErr_Format(PyExc_RuntimeError, "VmmYara.flags: Not initialized."); }
    return (PyObject*)PyLong_FromUnsignedLongLong(self->ctxYara.ReadFlags);
}

// QWORD ->
static int
VmmPycYara_flags_set(PyObj_Yara *self, PyObject *value, void *closure)
{
    if(!self->fValid) {
        PyErr_SetString(PyExc_TypeError, "VmmYara.flags: Not initialized.");
        return -1;
    }
    if(!PyLong_Check(value)) {
        PyErr_SetString(PyExc_TypeError, "VmmYara.flags: Invalid type.");
        return -1;
    }
    if(self->fStarted) {
        PyErr_SetString(PyExc_TypeError, "VmmYara.flags: Already started.");
        return -1;
    }
    self->ctxYara.ReadFlags = PyLong_AsUnsignedLongLong(value);
    return 0;
}

// -> QWORD
static PyObject*
VmmPycYara_addr_min_get(PyObj_Yara *self, void *closure)
{
    if(!self->fValid) { return PyErr_Format(PyExc_RuntimeError, "VmmYara.addr_min: Not initialized."); }
    return (PyObject*)PyLong_FromUnsignedLongLong(self->ctxYara.vaMin);
}

// QWORD ->
static int
VmmPycYara_addr_min_set(PyObj_Yara *self, PyObject *value, void *closure)
{
    QWORD qw;
    if(!self->fValid) {
        PyErr_SetString(PyExc_TypeError, "VmmYara.addr_min: Not initialized.");
        return -1;
    }
    if(!PyLong_Check(value)) {
        PyErr_SetString(PyExc_TypeError, "VmmYara.addr_min: Invalid type.");
        return -1;
    }
    if(self->fStarted) {
        PyErr_SetString(PyExc_TypeError, "VmmYara.addr_min: Already started.");
        return -1;
    }
    qw = PyLong_AsUnsignedLongLong(value);
    if(qw == (QWORD)-1) {
        PyErr_SetString(PyExc_TypeError, "VmmYara.addr_min: Invalid number.");
        return -1;
    }
    self->ctxYara.vaMin = qw;
    return 0;
}

// -> QWORD
static PyObject*
VmmPycYara_addr_max_get(PyObj_Yara *self, void *closure)
{
    if(!self->fValid) { return PyErr_Format(PyExc_RuntimeError, "VmmYara.addr_max: Not initialized."); }
    return (PyObject*)PyLong_FromUnsignedLongLong(self->ctxYara.vaMax);
}

// QWORD ->
static int
VmmPycYara_addr_max_set(PyObj_Yara *self, PyObject *value, void *closure)
{
    QWORD qw;
    if(!self->fValid) {
        PyErr_SetString(PyExc_TypeError, "VmmYara.addr_max: Not initialized.");
        return -1;
    }
    if(!PyLong_Check(value)) {
        PyErr_SetString(PyExc_TypeError, "VmmYara.addr_max: Invalid type.");
        return -1;
    }
    if(self->fStarted) {
        PyErr_SetString(PyExc_TypeError, "VmmYara.addr_max: Already started.");
        return -1;
    }
    qw = PyLong_AsUnsignedLongLong(value);
    if(qw == (QWORD)-1) {
        PyErr_SetString(PyExc_TypeError, "VmmYara.addr_max: Invalid number.");
        return -1;
    }
    self->ctxYara.vaMax = qw;
    return 0;
}

// -> DWORD
static PyObject*
VmmPycYara_max_results_get(PyObj_Yara *self, void *closure)
{
    if(!self->fValid) { return PyErr_Format(PyExc_RuntimeError, "VmmYara.max_results: Not initialized."); }
    return (PyObject*)PyLong_FromUnsignedLong(self->ctxYara.cMaxResult);
}

// DWORD ->
static int
VmmPycYara_max_results_set(PyObj_Yara *self, PyObject *value, void *closure)
{
    DWORD dw;
    if(!self->fValid) {
        PyErr_SetString(PyExc_TypeError, "VmmYara.max_results: Not initialized.");
        return -1;
    }
    if(!PyLong_Check(value)) {
        PyErr_SetString(PyExc_TypeError, "VmmYara.max_results: Invalid type.");
        return -1;
    }
    if(self->fStarted) {
        PyErr_SetString(PyExc_TypeError, "VmmYara.max_results: Already started.");
        return -1;
    }
    dw = PyLong_AsUnsignedLong(value);
    if((dw == (DWORD)-1) || (dw == 0) || (dw > 0x10000)) {
        PyErr_SetString(PyExc_TypeError, "VmmYara.max_results: Invalid number [max 65536(0x10000) allowed].");
        return -1;
    }
    self->ctxYara.cMaxResult = dw;
    return 0;
}

//-----------------------------------------------------------------------------
// VmmPycYara INITIALIZATION AND CORE FUNCTIONALITY BELOW:
//-----------------------------------------------------------------------------

#define VMMPYC_YARA_MAX_RULES 0x10000

// args: (_In_req_ PyList[YaraRules], _In_opt_ QWORD vaMin, _In_opt_ QWORD vaMax, _In_opt_ DWORD MaxResults,  _In_opt_ QWORD qwReadFlags)
PyObj_Yara*
VmmPycYara_InitializeInternal(_In_ PyObj_Vmm *pyVMM, _In_opt_ DWORD dwPID, _In_ PyObject *args)
{
    PyObj_Yara *pyObj;
    PyObject *pyListRules = NULL, *pyStringRule, *pyBytesUTF8;
    LPSTR szSingleRule;
    LPSTR *pszRules = NULL;
    DWORD i, cRules = 0, cMaxResults = 0x10000;
    SIZE_T cbRules = 0;
    QWORD vaMin = 0, vaMax = 0, qwReadFlags = 0;
    Py_ssize_t cListRules, size = 0;
    // parse arguments:
    if(PyArg_ParseTuple(args, "O!|KKIK", &PyList_Type, &pyListRules, &vaMin, &vaMax, &cMaxResults, &qwReadFlags)) {
        cListRules = PyList_Size(pyListRules);
        if((cListRules == 0) || (cListRules > VMMPYC_YARA_MAX_RULES)) {
            return NULL;
        }
        if((pszRules = LocalAlloc(0, cListRules * sizeof(LPSTR)))) {
            for(i = 0; i < cListRules; i++) {
                pyStringRule = PyList_GetItem(pyListRules, i);
                if(pyStringRule && PyUnicode_Check(pyStringRule) && (pyBytesUTF8 = PyUnicode_AsEncodedString(pyStringRule, "utf-8", "strict"))) {
                    if((szSingleRule = PyBytes_AsString(pyBytesUTF8)) && strlen(szSingleRule)) {
                        if((pszRules[cRules] = strdup(szSingleRule))) {
                            cRules += 1;
                        }
                    }
                    Py_DECREF(pyBytesUTF8);
                }
            }
        }
    } else if(PyArg_ParseTuple(args, "s|KKIK", &szSingleRule, &vaMin, &vaMax, &cMaxResults, &qwReadFlags)) {
        if(szSingleRule && strlen(szSingleRule) && (pszRules = LocalAlloc(0, sizeof(LPSTR)))) {
            if((pszRules[cRules] = strdup(szSingleRule))) {
                cRules += 1;
            }
        }
    }
    PyErr_Clear();
    if(cRules == 0) {
        LocalFree(pszRules);
        return NULL;
    }
    vaMin = vaMin & 0xfffffffffffff000;
    vaMax = vaMax & 0xfffffffffffff000;
    if(vaMax && (vaMax <= vaMin)) { return NULL; }
    // general object init:
    if(!(pyObj = PyObject_New(PyObj_Yara, (PyTypeObject*)g_pPyType_Yara))) { return NULL; }
    Py_INCREF(pyVMM); pyObj->pyVMM = pyVMM;
    pyObj->dwPID = dwPID;
    pyObj->fStarted = FALSE;
    pyObj->fCompleted = FALSE;
    pyObj->fCompletedSuccess = FALSE;
    pyObj->uszMultiRules = NULL;
    if(!(pyObj->pyListResult = PyList_New(0))) {
        Py_DECREF(pyObj);
        return NULL;
    }
    // search context init:
    memset(&pyObj->ctxYara, 0, sizeof(VMMDLL_YARA_CONFIG));
    pyObj->ctxYara.dwVersion = VMMDLL_YARA_CONFIG_VERSION;
    pyObj->ctxYara.vaMin = vaMin;
    pyObj->ctxYara.vaMax = vaMax;
    pyObj->ctxYara.ReadFlags = qwReadFlags;
    pyObj->ctxYara.cMaxResult = 0x10000;
    pyObj->ctxYara.cRules = cRules;
    pyObj->ctxYara.pszRules = pszRules;
    pyObj->ctxYara.pvUserPtrOpt = pyObj;
    pyObj->ctxYara.pfnScanMemoryCB = VmmPycYara_SearchResultCB;
    // finish & return:
    pyObj->fValid = TRUE;
    return pyObj;
}

static PyObject*
VmmPycYara_repr(PyObj_Yara *self)
{
    if(!self->fValid) {
        return PyUnicode_FromFormat("VmmYara:NotValid");
    } else if(self->dwPID != (DWORD)-1) {
        return PyUnicode_FromFormat("VmmYara:Virtual:%i", self->dwPID);
    } else {
        return PyUnicode_FromFormat("VmmYara:Physical");
    }
}

static int
VmmPycYara_init(PyObj_Yara *self, PyObject *args, PyObject *kwds)
{
    PyErr_SetString(PyExc_TypeError, "VmmYara.init(): Not allowed.");
    return -1;
}

static void
VmmPycYara_dealloc(PyObj_Yara *self)
{
    DWORD i;
    self->fValid = FALSE;
    if(self->fStarted && !self->fCompleted) {
        Py_BEGIN_ALLOW_THREADS;
        self->ctxYara.fAbortRequested = TRUE;
        while(!self->fCompleted) {
            SwitchToThread();
        }
        for(i = 0; i < self->ctxYara.cRules; i++) {
            free(self->ctxYara.pszRules[i]);
        }
        LocalFree(self->ctxYara.pszRules);
        Py_END_ALLOW_THREADS;
    }
    Py_XDECREF(self->pyListResult);
    Py_XDECREF(self->pyVMM); self->pyVMM = NULL;
    PyObject_Del(self);
}

_Success_(return)
BOOL VmmPycYara_InitializeType(PyObject *pModule)
{
    static PyMethodDef PyMethods[] = {
        {"start", (PyCFunction)VmmPycYara_start, METH_VARARGS, "Start a YARA search."},
        {"poll", (PyCFunction)VmmPycYara_poll, METH_VARARGS, "Poll a YARA search (retrieve search result non-blocking)."},
        {"result", (PyCFunction)VmmPycYara_result, METH_VARARGS, "Result of a YARA search (blocking, wait until search is finished)."},
        {"abort", (PyCFunction)VmmPycYara_abort, METH_VARARGS, "Abort an ongoing YARA search."},
        {NULL, NULL, 0, NULL}
    };
    static PyMemberDef PyMembers[] = {
        {"addr_current", T_ULONGLONG, offsetof(PyObj_Yara, ctxYara.vaCurrent), READONLY, "Current address searched."},
        {"bytes_searched", T_ULONGLONG, offsetof(PyObj_Yara, ctxYara.cbReadTotal), READONLY, "Number of bytes searched."},
        {"is_aborted", T_BOOL, offsetof(PyObj_Yara, ctxYara.fAbortRequested), READONLY, "Abort of search is requested."},
        {"is_completed", T_BOOL,offsetof(PyObj_Yara, fCompleted), READONLY, "Search is completed (successfully or unsuccessfully)."},
        {"is_completed_success", T_BOOL, offsetof(PyObj_Yara, fCompletedSuccess), READONLY, "Search is completed successfully."},
        {"is_started", T_BOOL, offsetof(PyObj_Yara, fStarted), READONLY, "Search is started."},
        {"pid", T_ULONG, offsetof(PyObj_Yara, dwPID), READONLY, "PID"},
        {NULL}
    };
    static PyGetSetDef PyGetSet[] = {
        {"addr_max", (getter)VmmPycYara_addr_max_get, (setter)VmmPycYara_addr_max_set, "Max address to search.", NULL},
        {"addr_min", (getter)VmmPycYara_addr_min_get, (setter)VmmPycYara_addr_min_set, "Min address to search.", NULL},
        {"flags", (getter)VmmPycYara_flags_get, (setter)VmmPycYara_flags_set, "Read Flags.", NULL},
        {"max_results", (getter)VmmPycYara_max_results_get, (setter)VmmPycYara_max_results_set, "Max number of results before search is completed.", NULL},
        {NULL}
    };
    static PyType_Slot PyTypeSlot[] = {
        {Py_tp_init, VmmPycYara_init},
        {Py_tp_dealloc, VmmPycYara_dealloc},
        {Py_tp_repr, VmmPycYara_repr},
        {Py_tp_methods, PyMethods},
        {Py_tp_members, PyMembers},
        {Py_tp_getset, PyGetSet},
        {0, 0}
    };
    static PyType_Spec PyTypeSpec = {
        .name = "vmmpyc.VmmYara",
        .basicsize = sizeof(PyObj_Yara),
        .itemsize = 0,
        .flags = Py_TPFLAGS_DEFAULT,
        .slots = PyTypeSlot,
    };
    if((g_pPyType_Yara = PyType_FromSpec(&PyTypeSpec))) {
        if(PyModule_AddObject(pModule, "VmmYara", g_pPyType_Yara) < 0) {
            Py_DECREF(g_pPyType_Yara);
            g_pPyType_Yara = NULL;
        }
    }
    return g_pPyType_Yara ? TRUE : FALSE;
}
