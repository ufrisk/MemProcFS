// vmmpyc_processmaps.c : implementation of process infomaps functionality for vmmpyc.
//
// (c) Ulf Frisk, 2021
// Author: Ulf Frisk, pcileech@frizk.net
//
#include "vmmpyc.h"

PyObject *g_pPyType_ProcessMaps = NULL;

// ((BOOL)) -> [{...}]
static PyObject*
VmmPycProcessMaps_pte(PyObj_ProcessMaps *self, PyObject *args)
{
    PyObject *pyList, *pyDict;
    BOOL result, fIdentifyModules;
    DWORD i, cbPteMap = 0;
    PVMMDLL_MAP_PTEENTRY pe;
    PVMMDLL_MAP_PTE pPteMap = NULL;
    CHAR sz[5];
    if(!self->fValid) { return PyErr_Format(PyExc_RuntimeError, "ProcessMaps.pte(): Not initialized."); }
    if(!PyArg_ParseTuple(args, "|p", &fIdentifyModules)) {
        return PyErr_Format(PyExc_RuntimeError, "ProcessMaps.pte(): Illegal argument.");
    }
    if(!(pyList = PyList_New(0))) { return PyErr_NoMemory(); }
    Py_BEGIN_ALLOW_THREADS;
    result =
        VMMDLL_Map_GetPteU(self->dwPID, NULL, &cbPteMap, fIdentifyModules) &&
        cbPteMap &&
        (pPteMap = LocalAlloc(0, cbPteMap)) &&
        VMMDLL_Map_GetPteU(self->dwPID, pPteMap, &cbPteMap, fIdentifyModules);
    Py_END_ALLOW_THREADS;
    if(!result || (pPteMap->dwVersion != VMMDLL_MAP_PTE_VERSION)) {
        Py_DECREF(pyList);
        LocalFree(pPteMap);
        return PyErr_Format(PyExc_RuntimeError, "ProcessMaps.pte(): Failed.");
    }
    for(i = 0; i < pPteMap->cMap; i++) {
        if((pyDict = PyDict_New())) {
            pe = pPteMap->pMap + i;
            PyDict_SetItemString_DECREF(pyDict, "va", PyLong_FromUnsignedLongLong(pe->vaBase));
            PyDict_SetItemString_DECREF(pyDict, "size", PyLong_FromUnsignedLongLong(pe->cPages << 12));
            PyDict_SetItemString_DECREF(pyDict, "pages", PyLong_FromUnsignedLongLong(pe->cPages));
            PyDict_SetItemString_DECREF(pyDict, "pages-sw", PyLong_FromUnsignedLong(pe->cSoftware));
            PyDict_SetItemString_DECREF(pyDict, "wow64", PyBool_FromLong((long)pe->fWoW64));
            PyDict_SetItemString_DECREF(pyDict, "tag", PyUnicode_FromString(pe->uszText));
            PyDict_SetItemString_DECREF(pyDict, "flags-pte", PyLong_FromUnsignedLongLong(pe->fPage));
            sz[0] = (pe->fPage & VMMDLL_MEMMAP_FLAG_PAGE_NS) ? '-' : 's';
            sz[1] = 'r';
            sz[2] = (pe->fPage & VMMDLL_MEMMAP_FLAG_PAGE_W) ? 'w' : '-';
            sz[3] = (pe->fPage & VMMDLL_MEMMAP_FLAG_PAGE_NX) ? '-' : 'x';
            sz[4] = 0;
            PyDict_SetItemString_DECREF(pyDict, "flags", PyUnicode_FromString(sz));
            PyList_Append_DECREF(pyList, pyDict);
        }
    }
    LocalFree(pPteMap);
    return pyList;
}

VOID VmmPycProcessMaps_vad_Protection(_In_ PVMMDLL_MAP_VADENTRY pVad, _Out_writes_(6) LPSTR sz)
{
    BYTE vh = (BYTE)pVad->Protection >> 3;
    BYTE vl = (BYTE)pVad->Protection & 7;
    sz[0] = pVad->fPrivateMemory ? 'p' : '-';                                   // PRIVATE MEMORY
    sz[1] = (vh & 2) ? ((vh & 1) ? 'm' : 'g') : ((vh & 1) ? 'n' : '-');         // -/NO_CACHE/GUARD/WRITECOMBINE
    sz[2] = ((vl == 1) || (vl == 3) || (vl == 4) || (vl == 6)) ? 'r' : '-';     // COPY ON WRITE
    sz[3] = (vl & 4) ? 'w' : '-';                                               // WRITE
    sz[4] = (vl & 2) ? 'x' : '-';                                               // EXECUTE
    sz[5] = ((vl == 5) || (vl == 7)) ? 'c' : '-';                               // COPY ON WRITE
    if(sz[1] != '-' && sz[2] == '-' && sz[3] == '-' && sz[4] == '-' && sz[5] == '-') { sz[1] = '-'; }
}

LPSTR VmmPycProcessMaps_vad_Type(_In_ PVMMDLL_MAP_VADENTRY pVad)
{
    if(pVad->fImage) {
        return "Image";
    } else if(pVad->fFile) {
        return "File ";
    } else if(pVad->fHeap) {
        return "Heap ";
    } else if(pVad->fStack) {
        return "Stack";
    } else if(pVad->fTeb) {
        return "Teb  ";
    } else if(pVad->fPageFile) {
        return "Pf   ";
    } else {
        return "     ";
    }
}

// ((BOOL)) -> [{...}]
static PyObject*
VmmPycProcessMaps_vad(PyObj_ProcessMaps *self, PyObject *args)
{
    PyObject *pyList, *pyDict;
    BOOL result, fIdentifyModules = FALSE;
    DWORD i, cbVadMap = 0;
    PVMMDLL_MAP_VADENTRY pe;
    PVMMDLL_MAP_VAD pVadMap = NULL;
    CHAR szVadProtection[7] = { 0 };
    if(!self->fValid) { return PyErr_Format(PyExc_RuntimeError, "ProcessMaps.vad(): Not initialized."); }
    if(!PyArg_ParseTuple(args, "|p", &fIdentifyModules)) {
        return PyErr_Format(PyExc_RuntimeError, "ProcessMaps.vad(): Illegal argument.");
    }
    if(!(pyList = PyList_New(0))) { return PyErr_NoMemory(); }
    Py_BEGIN_ALLOW_THREADS;
    result =
        VMMDLL_Map_GetVadU(self->dwPID, NULL, &cbVadMap, fIdentifyModules) &&
        cbVadMap &&
        (pVadMap = LocalAlloc(0, cbVadMap)) &&
        VMMDLL_Map_GetVadU(self->dwPID, pVadMap, &cbVadMap, fIdentifyModules);
    Py_END_ALLOW_THREADS;
    if(!result || (pVadMap->dwVersion != VMMDLL_MAP_VAD_VERSION)) {
        Py_DECREF(pyList);
        LocalFree(pVadMap);
        return PyErr_Format(PyExc_RuntimeError, "ProcessMaps.vad(): Failed.");
    }
    for(i = 0; i < pVadMap->cMap; i++) {
        if((pyDict = PyDict_New())) {
            pe = pVadMap->pMap + i;
            VmmPycProcessMaps_vad_Protection(pe, szVadProtection);
            PyDict_SetItemString_DECREF(pyDict, "start", PyLong_FromUnsignedLongLong(pe->vaStart));
            PyDict_SetItemString_DECREF(pyDict, "end", PyLong_FromUnsignedLongLong(pe->vaEnd));
            PyDict_SetItemString_DECREF(pyDict, "cvadex-pages", PyLong_FromUnsignedLong(pe->cVadExPages));
            PyDict_SetItemString_DECREF(pyDict, "cvadex-pages-base", PyLong_FromUnsignedLong(pe->cVadExPagesBase));
            PyDict_SetItemString_DECREF(pyDict, "subsection", PyLong_FromUnsignedLongLong(pe->vaSubsection));
            PyDict_SetItemString_DECREF(pyDict, "prototype", PyLong_FromUnsignedLongLong(pe->vaPrototypePte));
            PyDict_SetItemString_DECREF(pyDict, "prototype-len", PyLong_FromUnsignedLong(pe->cbPrototypePte));
            PyDict_SetItemString_DECREF(pyDict, "mem_commit", PyBool_FromLong((long)pe->MemCommit));
            PyDict_SetItemString_DECREF(pyDict, "commit_charge", PyLong_FromUnsignedLong(pe->CommitCharge));
            PyDict_SetItemString_DECREF(pyDict, "protection", PyUnicode_FromString(szVadProtection));
            PyDict_SetItemString_DECREF(pyDict, "type", PyUnicode_FromFormat("%s", VmmPycProcessMaps_vad_Type(pe)));
            PyDict_SetItemString_DECREF(pyDict, "tag", PyUnicode_FromString(pe->uszText));
            PyList_Append_DECREF(pyList, pyDict);
        }
    }
    LocalFree(pVadMap);
    return pyList;
}

CHAR VmmPycProcessMaps_vad_ex_Type(_In_ VMMDLL_PTE_TP tp)
{
    switch(tp) {
        case VMMDLL_PTE_TP_HARDWARE:   return 'A';
        case VMMDLL_PTE_TP_TRANSITION: return 'T';
        case VMMDLL_PTE_TP_PROTOTYPE:  return 'P';
        case VMMDLL_PTE_TP_DEMANDZERO: return 'Z';
        case VMMDLL_PTE_TP_COMPRESSED: return 'C';
        case VMMDLL_PTE_TP_PAGEFILE:   return 'F';
        default:                       return '-';
    }
}

// (DWORD, DWORD) -> [{...}]
static PyObject*
VmmPycProcessMaps_vad_ex(PyObj_ProcessMaps *self, PyObject *args)
{
    PyObject *pyList, *pyDict;
    BOOL result;
    DWORD oPage, cPage, i;
    DWORD cbVadExMap = 0;
    PVMMDLL_MAP_VADEXENTRY pe;
    PVMMDLL_MAP_VADEX pVadExMap = NULL;
    if(!self->fValid) { return PyErr_Format(PyExc_RuntimeError, "ProcessMaps.vad_ex(): Not initialized."); }
    if(!PyArg_ParseTuple(args, "kk", &oPage, &cPage)) {
        return PyErr_Format(PyExc_RuntimeError, "ProcessMaps.vad_ex(): Illegal argument.");
    }
    if(!(pyList = PyList_New(0))) { return PyErr_NoMemory(); }
    Py_BEGIN_ALLOW_THREADS;
    result =
        VMMDLL_Map_GetVadEx(self->dwPID, NULL, &cbVadExMap, oPage, cPage) &&
        cbVadExMap &&
        (pVadExMap = LocalAlloc(0, cbVadExMap)) &&
        VMMDLL_Map_GetVadEx(self->dwPID, pVadExMap, &cbVadExMap, oPage, cPage);
    Py_END_ALLOW_THREADS;
    if(!result || (pVadExMap->dwVersion != VMMDLL_MAP_VADEX_VERSION)) {
        Py_DECREF(pyList);
        LocalFree(pVadExMap);
        return PyErr_Format(PyExc_RuntimeError, "ProcessMaps.vad_ex(): Failed.");
    }
    for(i = 0; i < pVadExMap->cMap; i++) {
        if((pyDict = PyDict_New())) {
            pe = pVadExMap->pMap + i;
            PyDict_SetItemString_DECREF(pyDict, "tp", PyUnicode_FromFormat("%c", VmmPycProcessMaps_vad_ex_Type(pe->tp)));
            PyDict_SetItemString_DECREF(pyDict, "pml", PyLong_FromUnsignedLong(pe->iPML));
            PyDict_SetItemString_DECREF(pyDict, "va", PyLong_FromUnsignedLongLong(pe->va));
            PyDict_SetItemString_DECREF(pyDict, "pa", PyLong_FromUnsignedLongLong(pe->pa));
            PyDict_SetItemString_DECREF(pyDict, "pte", PyLong_FromUnsignedLongLong(pe->pte));
            PyDict_SetItemString_DECREF(pyDict, "vad-va", PyLong_FromUnsignedLongLong(pe->vaVadBase));
            PyDict_SetItemString_DECREF(pyDict, "proto-tp", PyUnicode_FromFormat("%c", VmmPycProcessMaps_vad_ex_Type(pe->proto.tp)));
            PyDict_SetItemString_DECREF(pyDict, "proto-pa", PyLong_FromUnsignedLongLong(pe->proto.pa));
            PyDict_SetItemString_DECREF(pyDict, "proto-pte", PyLong_FromUnsignedLongLong(pe->proto.pte));
            PyList_Append_DECREF(pyList, pyDict);
        }
    }
    LocalFree(pVadExMap);
    return pyList;
}

// () -> [{...}]
static PyObject*
VmmPycProcessMaps_unloaded_module(PyObj_ProcessMaps *self, PyObject *args)
{
    PyObject *pyList, *pyDict;
    BOOL result;
    DWORD cbUnloadedMap = 0;
    ULONG64 i;
    PVMMDLL_MAP_UNLOADEDMODULE pUnloadedMap = NULL;
    PVMMDLL_MAP_UNLOADEDMODULEENTRY pe;
    if(!self->fValid) { return PyErr_Format(PyExc_RuntimeError, "ProcessMaps.unloaded_module(): Not initialized."); }
    if(!(pyList = PyList_New(0))) { return PyErr_NoMemory(); }
    Py_BEGIN_ALLOW_THREADS;
    result =
        VMMDLL_Map_GetUnloadedModuleU(self->dwPID, NULL, &cbUnloadedMap) &&
        cbUnloadedMap &&
        (pUnloadedMap = LocalAlloc(0, cbUnloadedMap)) &&
        VMMDLL_Map_GetUnloadedModuleU(self->dwPID, pUnloadedMap, &cbUnloadedMap);
    Py_END_ALLOW_THREADS;
    if(!result || (pUnloadedMap->dwVersion != VMMDLL_MAP_UNLOADEDMODULE_VERSION)) {
        Py_DECREF(pyList);
        LocalFree(pUnloadedMap);
        return PyErr_Format(PyExc_RuntimeError, "ProcessMaps.unloaded_module(): Failed.");
    }
    for(i = 0; i < pUnloadedMap->cMap; i++) {
        if((pyDict = PyDict_New())) {
            pe = pUnloadedMap->pMap + i;
            PyDict_SetItemString_DECREF(pyDict, "va", PyLong_FromUnsignedLongLong(pe->vaBase));
            PyDict_SetItemString_DECREF(pyDict, "size", PyLong_FromUnsignedLong(pe->cbImageSize));
            PyDict_SetItemString_DECREF(pyDict, "wow64", PyBool_FromLong((long)pe->fWoW64));
            PyDict_SetItemString_DECREF(pyDict, "name", PyUnicode_FromString(pe->uszText));
            PyDict_SetItemString_DECREF(pyDict, "dwCheckSum", PyLong_FromUnsignedLong(pe->dwCheckSum));
            PyDict_SetItemString_DECREF(pyDict, "dwTimeDateStamp", PyLong_FromUnsignedLong(pe->dwTimeDateStamp));
            PyDict_SetItemString_DECREF(pyDict, "ft", PyLong_FromUnsignedLongLong(pe->ftUnload));
            PyList_Append_DECREF(pyList, pyDict);
        }
    }
    LocalFree(pUnloadedMap);
    return pyList;
}

// () -> [{...}]
static PyObject*
VmmPycProcessMaps_heap(PyObj_ProcessMaps *self, PyObject *args)
{
    PyObject *pyList, *pyDict;
    BOOL result;
    DWORD i, cbHeapMap = 0;
    PVMMDLL_MAP_HEAPENTRY pe;
    PVMMDLL_MAP_HEAP pHeapMap = NULL;
    if(!self->fValid) { return PyErr_Format(PyExc_RuntimeError, "ProcessMaps.heap(): Not initialized."); }
    if(!(pyList = PyList_New(0))) { return PyErr_NoMemory(); }
    Py_BEGIN_ALLOW_THREADS;
    result =
        VMMDLL_Map_GetHeap(self->dwPID, NULL, &cbHeapMap) &&
        cbHeapMap &&
        (pHeapMap = LocalAlloc(0, cbHeapMap)) &&
        VMMDLL_Map_GetHeap(self->dwPID, pHeapMap, &cbHeapMap);
    Py_END_ALLOW_THREADS;
    if(!result || (pHeapMap->dwVersion != VMMDLL_MAP_HEAP_VERSION)) {
        Py_DECREF(pyList);
        LocalFree(pHeapMap);
        return PyErr_Format(PyExc_RuntimeError, "ProcessMaps.heap(): Failed.");
    }
    for(i = 0; i < pHeapMap->cMap; i++) {
        if((pyDict = PyDict_New())) {
            pe = pHeapMap->pMap + i;
            PyDict_SetItemString_DECREF(pyDict, "va", PyLong_FromUnsignedLongLong(pe->vaHeapSegment));
            PyDict_SetItemString_DECREF(pyDict, "size", PyLong_FromUnsignedLong(pe->cPages << 12));
            PyDict_SetItemString_DECREF(pyDict, "size-uncommitted", PyLong_FromUnsignedLong(pe->cPagesUnCommitted << 12));
            PyDict_SetItemString_DECREF(pyDict, "id", PyLong_FromUnsignedLong(pe->HeapId));
            PyDict_SetItemString_DECREF(pyDict, "primary", PyBool_FromLong((long)pe->fPrimary));
            PyList_Append_DECREF(pyList, pyDict);
        }
    }
    LocalFree(pHeapMap);
    return pyList;
}

// () -> [{...}]
static PyObject*
VmmPycProcessMaps_thread(PyObj_ProcessMaps *self, PyObject *args)
{
    PyObject *pyList, *pyDict;
    BOOL result;
    DWORD i;
    DWORD cbThreadMap = 0;
    PVMMDLL_MAP_THREADENTRY pe;
    PVMMDLL_MAP_THREAD pThreadMap = NULL;
    if(!self->fValid) { return PyErr_Format(PyExc_RuntimeError, "ProcessMaps.thread(): Not initialized."); }
    CHAR szTimeUTC[MAX_PATH];
    if(!(pyList = PyList_New(0))) { return PyErr_NoMemory(); }
    Py_BEGIN_ALLOW_THREADS;
    result =
        VMMDLL_Map_GetThread(self->dwPID, NULL, &cbThreadMap) &&
        cbThreadMap &&
        (pThreadMap = LocalAlloc(0, cbThreadMap)) &&
        VMMDLL_Map_GetThread(self->dwPID, pThreadMap, &cbThreadMap);
    Py_END_ALLOW_THREADS;
    if(!result || (pThreadMap->dwVersion != VMMDLL_MAP_THREAD_VERSION)) {
        Py_DECREF(pyList);
        LocalFree(pThreadMap);
        return PyErr_Format(PyExc_RuntimeError, "ProcessMaps.thread(): Failed.");
    }
    for(i = 0; i < pThreadMap->cMap; i++) {
        if((pyDict = PyDict_New())) {
            pe = pThreadMap->pMap + i;
            PyDict_SetItemString_DECREF(pyDict, "tid", PyLong_FromUnsignedLong(pe->dwTID));
            PyDict_SetItemString_DECREF(pyDict, "pid", PyLong_FromUnsignedLong(pe->dwPID));
            PyDict_SetItemString_DECREF(pyDict, "exitstatus", PyLong_FromUnsignedLong(pe->dwExitStatus));
            PyDict_SetItemString_DECREF(pyDict, "state", PyLong_FromUnsignedLong(pe->bState));
            PyDict_SetItemString_DECREF(pyDict, "running", PyLong_FromUnsignedLong(pe->bRunning));
            PyDict_SetItemString_DECREF(pyDict, "priority", PyLong_FromUnsignedLong(pe->bPriority));
            PyDict_SetItemString_DECREF(pyDict, "basepriority", PyLong_FromUnsignedLong(pe->bBasePriority));
            PyDict_SetItemString_DECREF(pyDict, "va-ethread", PyLong_FromUnsignedLongLong(pe->vaETHREAD));
            PyDict_SetItemString_DECREF(pyDict, "va-teb", PyLong_FromUnsignedLongLong(pe->vaTeb));
            PyDict_SetItemString_DECREF(pyDict, "va-start", PyLong_FromUnsignedLongLong(pe->vaStartAddress));
            PyDict_SetItemString_DECREF(pyDict, "va-stackbase", PyLong_FromUnsignedLongLong(pe->vaStackBaseUser));
            PyDict_SetItemString_DECREF(pyDict, "va-stacklimit", PyLong_FromUnsignedLongLong(pe->vaStackLimitUser));
            PyDict_SetItemString_DECREF(pyDict, "va-stackbase-kernel", PyLong_FromUnsignedLongLong(pe->vaStackBaseKernel));
            PyDict_SetItemString_DECREF(pyDict, "va-stacklimit-kernel", PyLong_FromUnsignedLongLong(pe->vaStackLimitKernel));
            PyDict_SetItemString_DECREF(pyDict, "va-trapframe", PyLong_FromUnsignedLongLong(pe->vaTrapFrame));
            PyDict_SetItemString_DECREF(pyDict, "reg-rip", PyLong_FromUnsignedLongLong(pe->vaRIP));
            PyDict_SetItemString_DECREF(pyDict, "reg-rsp", PyLong_FromUnsignedLongLong(pe->vaRSP));
            PyDict_SetItemString_DECREF(pyDict, "time-create", PyLong_FromUnsignedLongLong(pe->ftCreateTime));
            PyDict_SetItemString_DECREF(pyDict, "time-exit", PyLong_FromUnsignedLongLong(pe->ftExitTime));
            Util_FileTime2String(pe->ftCreateTime, szTimeUTC);
            PyDict_SetItemString_DECREF(pyDict, "time-create-str", PyUnicode_FromFormat("%s", szTimeUTC));
            Util_FileTime2String(pe->ftExitTime, szTimeUTC);
            PyDict_SetItemString_DECREF(pyDict, "time-exit-str", PyUnicode_FromFormat("%s", szTimeUTC));
            PyList_Append_DECREF(pyList, pyDict);
        }
    }
    LocalFree(pThreadMap);
    return pyList;
}

// () -> [{...}]
static PyObject*
VmmPycProcessMaps_handle(PyObj_ProcessMaps *self, PyObject *args)
{
    PyObject *pyList, *pyDict;
    BOOL result;
    DWORD cbHandleMap = 0;
    ULONG64 i;
    PVMMDLL_MAP_HANDLE pHandleMap = NULL;
    PVMMDLL_MAP_HANDLEENTRY pe;
    if(!self->fValid) { return PyErr_Format(PyExc_RuntimeError, "ProcessMaps.handle(): Not initialized."); }
    if(!(pyList = PyList_New(0))) { return PyErr_NoMemory(); }
    Py_BEGIN_ALLOW_THREADS;
    result =
        VMMDLL_Map_GetHandleU(self->dwPID, NULL, &cbHandleMap) &&
        cbHandleMap &&
        (pHandleMap = LocalAlloc(0, cbHandleMap)) &&
        VMMDLL_Map_GetHandleU(self->dwPID, pHandleMap, &cbHandleMap);
    Py_END_ALLOW_THREADS;
    if(!result || (pHandleMap->dwVersion != VMMDLL_MAP_HANDLE_VERSION)) {
        Py_DECREF(pyList);
        LocalFree(pHandleMap);
        return PyErr_Format(PyExc_RuntimeError, "ProcessMaps.handle(): Failed.");
    }
    for(i = 0; i < pHandleMap->cMap; i++) {
        if((pyDict = PyDict_New())) {
            pe = pHandleMap->pMap + i;
            PyDict_SetItemString_DECREF(pyDict, "va-object", PyLong_FromUnsignedLongLong(pe->vaObject));
            PyDict_SetItemString_DECREF(pyDict, "handle", PyLong_FromUnsignedLong(pe->dwHandle));
            PyDict_SetItemString_DECREF(pyDict, "access", PyLong_FromUnsignedLong(pe->dwGrantedAccess));
            PyDict_SetItemString_DECREF(pyDict, "typeindex", PyLong_FromUnsignedLong(pe->iType));
            PyDict_SetItemString_DECREF(pyDict, "pid", PyLong_FromUnsignedLong(pe->dwPID));
            PyDict_SetItemString_DECREF(pyDict, "pooltag", PyLong_FromUnsignedLong(pe->dwPoolTag));
            PyDict_SetItemString_DECREF(pyDict, "chandle", PyLong_FromUnsignedLongLong(pe->qwHandleCount));
            PyDict_SetItemString_DECREF(pyDict, "cpointer", PyLong_FromUnsignedLongLong(pe->qwPointerCount));
            PyDict_SetItemString_DECREF(pyDict, "va-object-creatinfo", PyLong_FromUnsignedLongLong(pe->vaObjectCreateInfo));
            PyDict_SetItemString_DECREF(pyDict, "va-securitydescriptor", PyLong_FromUnsignedLongLong(pe->vaSecurityDescriptor));
            PyDict_SetItemString_DECREF(pyDict, "tag", PyUnicode_FromString(pe->uszText));
            PyDict_SetItemString_DECREF(pyDict, "type", PyUnicode_FromString(pe->uszType));
            PyList_Append_DECREF(pyList, pyDict);
        }
    }
    LocalFree(pHandleMap);
    return pyList;
}

//-----------------------------------------------------------------------------
// VmmPycProcessMaps INITIALIZATION AND CORE FUNCTIONALITY BELOW:
//-----------------------------------------------------------------------------

PyObj_ProcessMaps*
VmmPycProcessMaps_InitializeInternal(_In_ DWORD dwPID)
{
    PyObj_ProcessMaps *pyObj;
    if(!(pyObj = PyObject_New(PyObj_ProcessMaps, (PyTypeObject*)g_pPyType_ProcessMaps))) { return NULL; }
    pyObj->fValid = TRUE;
    pyObj->dwPID = dwPID;
    return pyObj;
}

static PyObject*
VmmPycProcessMaps_repr(PyObj_ProcessMaps *self)
{
    return self->fValid ?
        PyUnicode_FromFormat("ProcessMaps:%i", self->dwPID) :
        PyUnicode_FromFormat("ProcessMaps:NotValid");
}

static int
VmmPycProcessMaps_init(PyObj_ProcessMaps *self, PyObject *args, PyObject *kwds)
{
    PyErr_SetString(PyExc_TypeError, "ProcessMaps.init(): Not allowed.");
    return -1;
}

static void
VmmPycProcessMaps_dealloc(PyObj_ProcessMaps *self)
{
    self->fValid = FALSE;
}

_Success_(return)
BOOL VmmPycProcessMaps_InitializeType(PyObject *pModule)
{
    static PyMethodDef PyMethods[] = {
        {"pte", (PyCFunction)VmmPycProcessMaps_pte, METH_VARARGS, "Retrieve the PTE memory map."},
        {"vad", (PyCFunction)VmmPycProcessMaps_vad, METH_VARARGS, "Retrieve the VAD memory map."},
        {"vad_ex", (PyCFunction)VmmPycProcessMaps_vad_ex, METH_VARARGS, "Retrieve extended VAD map (with additional information about each page)."},
        {"unloaded_module", (PyCFunction)VmmPycProcessMaps_unloaded_module, METH_VARARGS, "Retrieve the unloaded modules."},
        {"heap", (PyCFunction)VmmPycProcessMaps_heap, METH_VARARGS, "Retrieve the heaps."},
        {"thread", (PyCFunction)VmmPycProcessMaps_thread, METH_VARARGS, "Retrieve the threads."},
        {"handle", (PyCFunction)VmmPycProcessMaps_handle, METH_VARARGS, "Retrieve the handles."},
        {NULL, NULL, 0, NULL}
    };
    static PyMemberDef PyMembers[] = {
        {"pid", T_ULONG, offsetof(PyObj_ProcessMaps, dwPID), READONLY, "PID"},
        {NULL}
    };
    static PyGetSetDef PyGetSet[] = {
        {NULL}
    };
    static PyType_Slot PyTypeSlot[] = {
        {Py_tp_init, VmmPycProcessMaps_init},
        {Py_tp_dealloc, VmmPycProcessMaps_dealloc},
        {Py_tp_repr, VmmPycProcessMaps_repr},
        {Py_tp_methods, PyMethods},
        {Py_tp_members, PyMembers},
        {Py_tp_getset, PyGetSet},
        {0, 0}
    };
    static PyType_Spec PyTypeSpec = {
        .name = "vmmpyc.VmmProcessMaps",
        .basicsize = sizeof(PyObj_ProcessMaps),
        .itemsize = 0,
        .flags = Py_TPFLAGS_DEFAULT,
        .slots = PyTypeSlot,
    };
    if((g_pPyType_ProcessMaps = PyType_FromSpec(&PyTypeSpec))) {
        if(PyModule_AddObject(pModule, "VmmProcessMaps", g_pPyType_ProcessMaps) < 0) {
            Py_DECREF(g_pPyType_ProcessMaps);
            g_pPyType_ProcessMaps = NULL;
        }
    }
    return g_pPyType_ProcessMaps ? TRUE : FALSE;
}
