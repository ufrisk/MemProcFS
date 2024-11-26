// vmmpyc_processmaps.c : implementation of process infomaps functionality for vmmpyc.
//
// (c) Ulf Frisk, 2021-2024
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
    DWORD i;
    PVMMDLL_MAP_PTEENTRY pe;
    PVMMDLL_MAP_PTE pPteMap = NULL;
    CHAR sz[5];
    if(!self->fValid) { return PyErr_Format(PyExc_RuntimeError, "ProcessMaps.pte(): Not initialized."); }
    if(!PyArg_ParseTuple(args, "|p", &fIdentifyModules)) {
        return PyErr_Format(PyExc_RuntimeError, "ProcessMaps.pte(): Illegal argument.");
    }
    if(!(pyList = PyList_New(0))) { return PyErr_NoMemory(); }
    Py_BEGIN_ALLOW_THREADS;
    result = VMMDLL_Map_GetPteU(self->pyVMM->hVMM, self->dwPID, fIdentifyModules, &pPteMap);
    Py_END_ALLOW_THREADS;
    if(!result || (pPteMap->dwVersion != VMMDLL_MAP_PTE_VERSION)) {
        Py_DECREF(pyList);
        VMMDLL_MemFree(pPteMap);
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
    VMMDLL_MemFree(pPteMap);
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
    DWORD i;
    PVMMDLL_MAP_VADENTRY pe;
    PVMMDLL_MAP_VAD pVadMap = NULL;
    CHAR szVadProtection[7] = { 0 };
    if(!self->fValid) { return PyErr_Format(PyExc_RuntimeError, "ProcessMaps.vad(): Not initialized."); }
    if(!PyArg_ParseTuple(args, "|p", &fIdentifyModules)) {
        return PyErr_Format(PyExc_RuntimeError, "ProcessMaps.vad(): Illegal argument.");
    }
    if(!(pyList = PyList_New(0))) { return PyErr_NoMemory(); }
    Py_BEGIN_ALLOW_THREADS;
    result = VMMDLL_Map_GetVadU(self->pyVMM->hVMM, self->dwPID, fIdentifyModules, &pVadMap);
    Py_END_ALLOW_THREADS;
    if(!result || (pVadMap->dwVersion != VMMDLL_MAP_VAD_VERSION)) {
        Py_DECREF(pyList);
        VMMDLL_MemFree(pVadMap);
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
    VMMDLL_MemFree(pVadMap);
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
    PVMMDLL_MAP_VADEXENTRY pe;
    PVMMDLL_MAP_VADEX pVadExMap = NULL;
    if(!self->fValid) { return PyErr_Format(PyExc_RuntimeError, "ProcessMaps.vad_ex(): Not initialized."); }
    if(!PyArg_ParseTuple(args, "II", &oPage, &cPage)) {
        return PyErr_Format(PyExc_RuntimeError, "ProcessMaps.vad_ex(): Illegal argument.");
    }
    if(!(pyList = PyList_New(0))) { return PyErr_NoMemory(); }
    Py_BEGIN_ALLOW_THREADS;
    result =
        VMMDLL_Map_GetVadEx(self->pyVMM->hVMM, self->dwPID, oPage, cPage, &pVadExMap);
    Py_END_ALLOW_THREADS;
    if(!result || (pVadExMap->dwVersion != VMMDLL_MAP_VADEX_VERSION)) {
        Py_DECREF(pyList);
        VMMDLL_MemFree(pVadExMap);
        return PyErr_Format(PyExc_RuntimeError, "ProcessMaps.vad_ex(): Failed.");
    }
    for(i = 0; i < pVadExMap->cMap; i++) {
        if((pyDict = PyDict_New())) {
            pe = pVadExMap->pMap + i;
            PyDict_SetItemString_DECREF(pyDict, "tp", PyUnicode_FromFormat("%c", VmmPycProcessMaps_vad_ex_Type(pe->tp)));
            PyDict_SetItemString_DECREF(pyDict, "pml", PyLong_FromUnsignedLong(pe->iPML));
            PyDict_SetItemString_DECREF(pyDict, "pteflags", PyLong_FromUnsignedLong(pe->pteFlags));
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
    VMMDLL_MemFree(pVadExMap);
    return pyList;
}

// () -> [{...}]
static PyObject*
VmmPycProcessMaps_unloaded_module(PyObj_ProcessMaps *self, PyObject *args)
{
    PyObject *pyList, *pyDict;
    BOOL result;
    ULONG64 i;
    PVMMDLL_MAP_UNLOADEDMODULE pUnloadedMap = NULL;
    PVMMDLL_MAP_UNLOADEDMODULEENTRY pe;
    if(!self->fValid) { return PyErr_Format(PyExc_RuntimeError, "ProcessMaps.unloaded_module(): Not initialized."); }
    if(!(pyList = PyList_New(0))) { return PyErr_NoMemory(); }
    Py_BEGIN_ALLOW_THREADS;
    result = VMMDLL_Map_GetUnloadedModuleU(self->pyVMM->hVMM, self->dwPID, &pUnloadedMap);
    Py_END_ALLOW_THREADS;
    if(!result || (pUnloadedMap->dwVersion != VMMDLL_MAP_UNLOADEDMODULE_VERSION)) {
        Py_DECREF(pyList);
        VMMDLL_MemFree(pUnloadedMap);
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
    VMMDLL_MemFree(pUnloadedMap);
    return pyList;
}

// () -> {'heap': {...}, 'segment': [...]}
static PyObject*
VmmPycProcessMaps_heap(PyObj_ProcessMaps *self, PyObject *args)
{
    PyObject *pyDictResult, *pyDictHeap, *pyListSegment, *pyDict;
    BOOL result;
    DWORD i;
    PVMMDLL_MAP_HEAPENTRY peH;
    PVMMDLL_MAP_HEAP_SEGMENTENTRY peS;
    PVMMDLL_MAP_HEAP pHeapMap = NULL;
    if(!self->fValid) { return PyErr_Format(PyExc_RuntimeError, "ProcessMaps.heap(): Not initialized."); }
    if(!(pyListSegment = PyList_New(0))) { return PyErr_NoMemory(); }
    if(!(pyDictHeap = PyDict_New())) { return PyErr_NoMemory(); }
    if(!(pyDictResult = PyDict_New())) { return PyErr_NoMemory(); }
    PyDict_SetItemString_DECREF(pyDictResult, "heap", pyDictHeap);
    PyDict_SetItemString_DECREF(pyDictResult, "segment", pyListSegment);
    Py_BEGIN_ALLOW_THREADS;
    result = VMMDLL_Map_GetHeap(self->pyVMM->hVMM, self->dwPID, &pHeapMap);
    Py_END_ALLOW_THREADS;
    if(!result || (pHeapMap->dwVersion != VMMDLL_MAP_HEAP_VERSION)) {
        Py_DECREF(pyDictResult);
        VMMDLL_MemFree(pHeapMap);
        return PyErr_Format(PyExc_RuntimeError, "ProcessMaps.heap(): Failed.");
    }
    for(i = 0; i < pHeapMap->cMap; i++) {
        if((pyDict = PyDict_New())) {
            peH = pHeapMap->pMap + i;
            PyDict_SetItemString_DECREF(pyDict, "va", PyLong_FromUnsignedLongLong(peH->va));
            PyDict_SetItemString_DECREF(pyDict, "tp", PyLong_FromUnsignedLong(peH->tp));
            PyDict_SetItemString_DECREF(pyDict, "heapid", PyLong_FromUnsignedLong(peH->iHeap));
            PyDict_SetItemDWORD_DECREF(pyDictHeap, peH->iHeap, pyDict);
        }
    }
    for(i = 0; i < pHeapMap->cSegments; i++) {
        if((pyDict = PyDict_New())) {
            peS = pHeapMap->pSegments + i;
            PyDict_SetItemString_DECREF(pyDict, "va", PyLong_FromUnsignedLongLong(peS->va));
            PyDict_SetItemString_DECREF(pyDict, "tp", PyLong_FromUnsignedLong(peS->tp));
            PyDict_SetItemString_DECREF(pyDict, "heapid", PyLong_FromUnsignedLong(peS->iHeap));
            PyDict_SetItemString_DECREF(pyDict, "size", PyLong_FromUnsignedLong(peS->cb));
            PyList_Append_DECREF(pyListSegment, pyDict);
        }
    }
    VMMDLL_MemFree(pHeapMap);
    return pyDictResult;
}

// (QWORD) -> [...]
static PyObject*
VmmPycProcessMaps_heapalloc(PyObj_ProcessMaps *self, PyObject *args)
{
    PyObject *pyListResult, *pyDict;
    BOOL result;
    DWORD i;
    QWORD vaHeap;
    PVMMDLL_MAP_HEAPALLOCENTRY peA;
    PVMMDLL_MAP_HEAPALLOC pHeapAllocMap = NULL;
    if(!self->fValid) { return PyErr_Format(PyExc_RuntimeError, "ProcessMaps.heapalloc(): Not initialized."); }
    if(!PyArg_ParseTuple(args, "K", &vaHeap)) {
        return PyErr_Format(PyExc_RuntimeError, "ProcessMaps.heapalloc(): Illegal argument.");
    }
    if(!(pyListResult = PyList_New(0))) { return PyErr_NoMemory(); }
    Py_BEGIN_ALLOW_THREADS;
    result = VMMDLL_Map_GetHeapAlloc(self->pyVMM->hVMM, self->dwPID, vaHeap, &pHeapAllocMap);
    Py_END_ALLOW_THREADS;
    if(!result || (pHeapAllocMap->dwVersion != VMMDLL_MAP_HEAPALLOC_VERSION)) {
        Py_DECREF(pyListResult);
        VMMDLL_MemFree(pHeapAllocMap);
        return PyErr_Format(PyExc_RuntimeError, "ProcessMaps.heapalloc(): Failed.");
    }
    for(i = 0; i < pHeapAllocMap->cMap; i++) {
        if((pyDict = PyDict_New())) {
            peA = pHeapAllocMap->pMap + i;
            PyDict_SetItemString_DECREF(pyDict, "va", PyLong_FromUnsignedLongLong(peA->va));
            PyDict_SetItemString_DECREF(pyDict, "tp", PyLong_FromUnsignedLong(peA->tp));
            PyDict_SetItemString_DECREF(pyDict, "size", PyLong_FromUnsignedLong(peA->cb));
            PyList_Append_DECREF(pyListResult, pyDict);
        }
    }
    VMMDLL_MemFree(pHeapAllocMap);
    return pyListResult;
}

// () -> [{...}]
static PyObject*
VmmPycProcessMaps_thread(PyObj_ProcessMaps *self, PyObject *args)
{
    PyObject *pyList, *pyDict;
    BOOL result;
    DWORD i;
    PVMMDLL_MAP_THREADENTRY pe;
    PVMMDLL_MAP_THREAD pThreadMap = NULL;
    if(!self->fValid) { return PyErr_Format(PyExc_RuntimeError, "ProcessMaps.thread(): Not initialized."); }
    CHAR szTimeUTC[MAX_PATH];
    if(!(pyList = PyList_New(0))) { return PyErr_NoMemory(); }
    Py_BEGIN_ALLOW_THREADS;
    result = VMMDLL_Map_GetThread(self->pyVMM->hVMM, self->dwPID, &pThreadMap);
    Py_END_ALLOW_THREADS;
    if(!result || (pThreadMap->dwVersion != VMMDLL_MAP_THREAD_VERSION)) {
        Py_DECREF(pyList);
        VMMDLL_MemFree(pThreadMap);
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
            PyDict_SetItemString_DECREF(pyDict, "waitreason", PyLong_FromUnsignedLong(pe->bWaitReason));
            PyDict_SetItemString_DECREF(pyDict, "va-ethread", PyLong_FromUnsignedLongLong(pe->vaETHREAD));
            PyDict_SetItemString_DECREF(pyDict, "va-teb", PyLong_FromUnsignedLongLong(pe->vaTeb));
            PyDict_SetItemString_DECREF(pyDict, "va-start", PyLong_FromUnsignedLongLong(pe->vaStartAddress));
            PyDict_SetItemString_DECREF(pyDict, "va-win32start", PyLong_FromUnsignedLongLong(pe->vaWin32StartAddress));
            PyDict_SetItemString_DECREF(pyDict, "va-stackbase", PyLong_FromUnsignedLongLong(pe->vaStackBaseUser));
            PyDict_SetItemString_DECREF(pyDict, "va-stacklimit", PyLong_FromUnsignedLongLong(pe->vaStackLimitUser));
            PyDict_SetItemString_DECREF(pyDict, "va-stackbase-kernel", PyLong_FromUnsignedLongLong(pe->vaStackBaseKernel));
            PyDict_SetItemString_DECREF(pyDict, "va-stacklimit-kernel", PyLong_FromUnsignedLongLong(pe->vaStackLimitKernel));
            PyDict_SetItemString_DECREF(pyDict, "va-trapframe", PyLong_FromUnsignedLongLong(pe->vaTrapFrame));
            PyDict_SetItemString_DECREF(pyDict, "va-impersonation-token", PyLong_FromUnsignedLongLong(pe->vaImpersonationToken));
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
    VMMDLL_MemFree(pThreadMap);
    return pyList;
}

// () -> [{...}]
static PyObject*
VmmPycProcessMaps_thread_callstack(PyObj_ProcessMaps *self, PyObject *args)
{
    PyObject *pyList, *pyDict;
    BOOL result;
    DWORD i, dwTID, dwFlags = 0;
    PVMMDLL_MAP_THREAD_CALLSTACKENTRY pe;
    PVMMDLL_MAP_THREAD_CALLSTACK pThreadCallstackMap = NULL;
    if(!self->fValid) { return PyErr_Format(PyExc_RuntimeError, "ProcessMaps.thread_callstack(): Not initialized."); }
    if(!PyArg_ParseTuple(args, "I|I", &dwTID, &dwFlags)) {
        return PyErr_Format(PyExc_RuntimeError, "ProcessMaps.thread_callstack(): Illegal argument.");
    }
    if(!(pyList = PyList_New(0))) { return PyErr_NoMemory(); }
    Py_BEGIN_ALLOW_THREADS;
    result = VMMDLL_Map_GetThread_CallstackU(self->pyVMM->hVMM, self->dwPID, dwTID, dwFlags, &pThreadCallstackMap);
    Py_END_ALLOW_THREADS;
    if(!result || (pThreadCallstackMap->dwVersion != VMMDLL_MAP_THREAD_CALLSTACK_VERSION)) {
        Py_DECREF(pyList);
        VMMDLL_MemFree(pThreadCallstackMap);
        return PyErr_Format(PyExc_RuntimeError, "ProcessMaps.thread_callstack(): Failed.");
    }
    for(i = 0; i < pThreadCallstackMap->cMap; i++) {
        if((pyDict = PyDict_New())) {
            pe = pThreadCallstackMap->pMap + i;
            PyDict_SetItemString_DECREF(pyDict, "pid", PyLong_FromUnsignedLong(self->dwPID));
            PyDict_SetItemString_DECREF(pyDict, "tid", PyLong_FromUnsignedLong(dwTID));
            PyDict_SetItemString_DECREF(pyDict, "i", PyLong_FromUnsignedLong(pe->i));
            PyDict_SetItemString_DECREF(pyDict, "va-retaddr", PyLong_FromUnsignedLongLong(pe->vaRetAddr));
            PyDict_SetItemString_DECREF(pyDict, "va-rsp", PyLong_FromUnsignedLongLong(pe->vaRSP));
            PyDict_SetItemString_DECREF(pyDict, "va-base-sp", PyLong_FromUnsignedLongLong(pe->vaBaseSP));
            PyDict_SetItemString_DECREF(pyDict, "displacement", PyLong_FromUnsignedLong(pe->cbDisplacement));
            PyDict_SetItemString_DECREF(pyDict, "type", PyUnicode_FromString(pe->uszModule));
            PyDict_SetItemString_DECREF(pyDict, "type", PyUnicode_FromString(pe->uszFunction));
            PyList_Append_DECREF(pyList, pyDict);
        }
    }
    VMMDLL_MemFree(pThreadCallstackMap);
    return pyList;
}

// () -> [{...}]
static PyObject*
VmmPycProcessMaps_handle(PyObj_ProcessMaps *self, PyObject *args)
{
    PyObject *pyList, *pyDict;
    BOOL result;
    ULONG64 i;
    PVMMDLL_MAP_HANDLE pHandleMap = NULL;
    PVMMDLL_MAP_HANDLEENTRY pe;
    if(!self->fValid) { return PyErr_Format(PyExc_RuntimeError, "ProcessMaps.handle(): Not initialized."); }
    if(!(pyList = PyList_New(0))) { return PyErr_NoMemory(); }
    Py_BEGIN_ALLOW_THREADS;
    result = VMMDLL_Map_GetHandleU(self->pyVMM->hVMM, self->dwPID, &pHandleMap);
    Py_END_ALLOW_THREADS;
    if(!result || (pHandleMap->dwVersion != VMMDLL_MAP_HANDLE_VERSION)) {
        Py_DECREF(pyList);
        VMMDLL_MemFree(pHandleMap);
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
    VMMDLL_MemFree(pHandleMap);
    return pyList;
}

//-----------------------------------------------------------------------------
// VmmPycProcessMaps INITIALIZATION AND CORE FUNCTIONALITY BELOW:
//-----------------------------------------------------------------------------

PyObj_ProcessMaps*
VmmPycProcessMaps_InitializeInternal(_In_ PyObj_Vmm *pyVMM, _In_ DWORD dwPID)
{
    PyObj_ProcessMaps *pyObj;
    if(!(pyObj = PyObject_New(PyObj_ProcessMaps, (PyTypeObject*)g_pPyType_ProcessMaps))) { return NULL; }
    Py_INCREF(pyVMM); pyObj->pyVMM = pyVMM;
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
    Py_XDECREF(self->pyVMM);
    PyObject_Del(self);
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
        {"heapalloc", (PyCFunction)VmmPycProcessMaps_heapalloc, METH_VARARGS, "Retrieve heap allocations for a specified heap."},
        {"thread", (PyCFunction)VmmPycProcessMaps_thread, METH_VARARGS, "Retrieve the threads."},
        {"thread_callstack", (PyCFunction)VmmPycProcessMaps_thread_callstack, METH_VARARGS, "Retrieve the callstack for a specific thread."},
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
