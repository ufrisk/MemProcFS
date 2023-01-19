// vmmpyc_maps.c : implementation of the global infomaps functionality for vmmpyc.
//
// (c) Ulf Frisk, 2021-2023
// Author: Ulf Frisk, pcileech@frizk.net
//
#ifdef _WIN32
#include <ws2tcpip.h>
#endif /* _WIN32 */
#include "vmmpyc.h"

PyObject *g_pPyType_Maps = NULL;

LPSTR VmmPycMaps_PoolTagHelper(_In_ DWORD dwTag, _In_reads_(5) LPSTR szBuffer)
{
    *(PDWORD)szBuffer = dwTag;
    if(szBuffer[0] < 32 || szBuffer[0] > 126) { szBuffer[0] = '?'; }
    if(szBuffer[1] < 32 || szBuffer[1] > 126) { szBuffer[1] = '?'; }
    if(szBuffer[2] < 32 || szBuffer[2] > 126) { szBuffer[2] = '?'; }
    if(szBuffer[3] < 32 || szBuffer[3] > 126) { szBuffer[3] = '?'; }
    szBuffer[4] = 0;
    return szBuffer;
}

// () -> {'va': {...}, 'tag': {...}}
static PyObject *
VmmPycMaps_pool(PyObj_Maps *self, PyObject *args)
{
    PyObject *pyDictResult, *pyDictResultVA, *pyDictResultTag, *pyDictTag, *pyDict;
    BOOL result;
    DWORD iTag, iTagEntry;
    PVMMDLL_MAP_POOLENTRY pe;
    PVMMDLL_MAP_POOLENTRYTAG pTag;
    PVMMDLL_MAP_POOL pPoolMap = NULL;
    CHAR szBuffer[5] = { 0 };
    if(!self->fValid) { return PyErr_Format(PyExc_RuntimeError, "Maps.pool(): Not initialized."); }
    if(!(pyDictResult = PyDict_New())) { return PyErr_NoMemory(); }
    if(!(pyDictResultVA = PyDict_New())) { return PyErr_NoMemory(); } PyDict_SetItemString_DECREF(pyDictResult, "va", pyDictResultVA);
    if(!(pyDictResultTag = PyDict_New())) { return PyErr_NoMemory(); } PyDict_SetItemString_DECREF(pyDictResult, "tag", pyDictResultTag);
    Py_BEGIN_ALLOW_THREADS;
    result = VMMDLL_Map_GetPool(self->pyVMM->hVMM, &pPoolMap, VMMDLL_POOLMAP_FLAG_ALL);
    Py_END_ALLOW_THREADS;
    if(!result || (pPoolMap->dwVersion != VMMDLL_MAP_POOL_VERSION)) {
        Py_DECREF(pyDictResult);
        VMMDLL_MemFree(pPoolMap);
        return PyErr_Format(PyExc_RuntimeError, "Maps.pool(): Failed.");
    }
    for(iTag = 0; iTag < pPoolMap->cTag; iTag++) {
        pTag = pPoolMap->pTag + iTag;
        if((pyDictTag = PyDict_New())) {
            for(iTagEntry = 0; iTagEntry < pTag->cEntry; iTagEntry++) {
                pe = pPoolMap->pMap + pPoolMap->piTag2Map[pTag->iTag2Map + iTagEntry];
                if((pyDict = PyDict_New())) {
                    PyDict_SetItemString_DECREF(pyDict, "va", PyLong_FromUnsignedLongLong(pe->va));
                    PyDict_SetItemString_DECREF(pyDict, "cb", PyLong_FromUnsignedLong(pe->cb));
                    PyDict_SetItemString_DECREF(pyDict, "alloc", PyBool_FromLong(pe->fAlloc));
                    PyDict_SetItemString_DECREF(pyDict, "tpPool", PyLong_FromUnsignedLong(pe->tpPool));
                    PyDict_SetItemString_DECREF(pyDict, "tpSS", PyLong_FromUnsignedLong(pe->tpSS));
                    PyDict_SetItemString_DECREF(pyDict, "dwTag", PyLong_FromUnsignedLong(pe->dwTag));
                    PyDict_SetItemString_DECREF(pyDict, "tag", PyUnicode_FromString(VmmPycMaps_PoolTagHelper(pe->dwTag, szBuffer)));
                    Py_IncRef(pyDict); PyDict_SetItemQWORD_DECREF(pyDictTag, pe->va, pyDict);
                    PyDict_SetItemQWORD_DECREF(pyDictResultVA, pe->va, pyDict);
                }
            }
            PyDict_SetItemUnicode_DECREF(pyDictResultTag, PyUnicode_FromString(VmmPycMaps_PoolTagHelper(pTag->dwTag, szBuffer)), pyDictTag);
        }
    }
    VMMDLL_MemFree(pPoolMap);
    return pyDictResult;
}

// () -> [{...}]
static PyObject*
VmmPycMaps_net(PyObj_Maps *self, PyObject *args)
{
    PyObject *pyList, *pyDictTcpE;
    BOOL result;
    DWORD i, dwIpVersion;
    PVMMDLL_MAP_NET pNetMap = NULL;
    PVMMDLL_MAP_NETENTRY pe;
    CHAR szTime[24];
    if(!self->fValid) { return PyErr_Format(PyExc_RuntimeError, "Maps.net(): Not initialized."); }
    if(!(pyList = PyList_New(0))) { return PyErr_NoMemory(); }
    Py_BEGIN_ALLOW_THREADS;
    result = VMMDLL_Map_GetNetU(self->pyVMM->hVMM, &pNetMap);
    Py_END_ALLOW_THREADS;
    if(!result || (pNetMap->dwVersion != VMMDLL_MAP_NET_VERSION)) {
        Py_DECREF(pyList);
        VMMDLL_MemFree(pNetMap);
        return PyErr_Format(PyExc_RuntimeError, "Maps.net(): Failed.");
    }
    // add tcp endpoint entries to TcpE list
    for(i = 0; i < pNetMap->cMap; i++) {
        if((pyDictTcpE = PyDict_New())) {
            pe = pNetMap->pMap + i;
            dwIpVersion = (pe->AF == AF_INET) ? 4 : ((pe->AF == AF_INET6) ? 6 : 0);
            // get time
            Util_FileTime2String(pe->ftTime, szTime);
            PyDict_SetItemString_DECREF(pyDictTcpE, "ver", PyLong_FromUnsignedLong(dwIpVersion));
            PyDict_SetItemString_DECREF(pyDictTcpE, "pid", PyLong_FromUnsignedLong(pe->dwPID));
            PyDict_SetItemString_DECREF(pyDictTcpE, "pooltag", PyLong_FromUnsignedLong(pe->dwPoolTag));
            PyDict_SetItemString_DECREF(pyDictTcpE, "state", PyLong_FromUnsignedLong(pe->dwState));
            PyDict_SetItemString_DECREF(pyDictTcpE, "va", PyLong_FromUnsignedLongLong(pe->vaObj));
            PyDict_SetItemString_DECREF(pyDictTcpE, "time", PyLong_FromUnsignedLongLong(pe->ftTime));
            PyDict_SetItemString_DECREF(pyDictTcpE, "time-str", PyUnicode_FromFormat("%s", szTime));
            PyDict_SetItemString_DECREF(pyDictTcpE, "src-ip", PyUnicode_FromString(pe->Src.uszText));
            PyDict_SetItemString_DECREF(pyDictTcpE, "src-port", PyLong_FromUnsignedLong(pe->Src.port));
            PyDict_SetItemString_DECREF(pyDictTcpE, "dst-ip", PyUnicode_FromString(pe->Src.uszText));
            PyDict_SetItemString_DECREF(pyDictTcpE, "dst-port", PyLong_FromUnsignedLong(pe->Dst.port));
            PyList_Append_DECREF(pyList, pyDictTcpE);
        }
    }
    VMMDLL_MemFree(pNetMap);
    return pyList;
}

// () -> [[QWORD, QWORD], ...]
static PyObject*
VmmPycMaps_memmap(PyObj_Maps *self, PyObject *args)
{
    PyObject *pyList, *pyList_MemRange;
    BOOL result;
    ULONG64 i;
    PVMMDLL_MAP_PHYSMEM pPhysMemMap = NULL;
    PVMMDLL_MAP_PHYSMEMENTRY pe;
    if(!self->fValid) { return PyErr_Format(PyExc_RuntimeError, "Maps.memmap(): Not initialized."); }
    if(!(pyList = PyList_New(0))) { return PyErr_NoMemory(); }
    Py_BEGIN_ALLOW_THREADS;
    result = VMMDLL_Map_GetPhysMem(self->pyVMM->hVMM, &pPhysMemMap);
    Py_END_ALLOW_THREADS;
    if(!result || (pPhysMemMap->dwVersion != VMMDLL_MAP_PHYSMEM_VERSION)) {
        Py_DECREF(pyList);
        VMMDLL_MemFree(pPhysMemMap);
        return PyErr_Format(PyExc_RuntimeError, "Maps.memmap(): Failed.");
    }
    for(i = 0; i < pPhysMemMap->cMap; i++) {
        if((pyList_MemRange = PyList_New(0))) {
            pe = pPhysMemMap->pMap + i;
            PyList_Append_DECREF(pyList_MemRange, PyLong_FromUnsignedLongLong(pe->pa));
            PyList_Append_DECREF(pyList_MemRange, PyLong_FromUnsignedLongLong(pe->cb));
            PyList_Append_DECREF(pyList, pyList_MemRange);
        }
    }
    VMMDLL_MemFree(pPhysMemMap);
    return pyList;
}

// ([DWORD]) -> {...}
static PyObject*
VmmPycMaps_pfn(PyObj_Maps *self, PyObject *args)
{
    PyObject *pyListSrc, *pyListItemSrc, *pyDictDst, *pyDictItem;
    BOOL result;
    DWORD cPfns = 0, *pPfns = NULL;
    DWORD i, dwPfn, cbPfnMap = 0;
    PVMMDLL_MAP_PFN pPfnMap = NULL;
    PVMMDLL_MAP_PFNENTRY pe;
    if(!self->fValid) { return PyErr_Format(PyExc_RuntimeError, "Maps.pfn(): Not initialized."); }
    if(!PyArg_ParseTuple(args, "O!", &PyList_Type, &pyListSrc)) { return NULL; }    // borrowed reference
    cPfns = (DWORD)PyList_Size(pyListSrc);
    if(cPfns == 0) {
        return PyDict_New();
    }
    pPfns = LocalAlloc(0, cPfns * sizeof(DWORD));
    if(!pPfns) {
        return PyErr_NoMemory();
    }
    for(i = 0; i < cPfns; i++) {
        pyListItemSrc = PyList_GetItem(pyListSrc, i);   // borrowed reference
        if(!pyListItemSrc || !PyLong_Check(pyListItemSrc) || (0xffffffff == (dwPfn = PyLong_AsUnsignedLong(pyListItemSrc)))) {
            LocalFree(pPfns);
            return PyErr_Format(PyExc_RuntimeError, "Maps.pfn(): Argument list contains non numeric item or PFN exceeding 0xffffffff.");
        }
        pPfns[i] = dwPfn;
    }
    // call c-dll for vmm
    Py_BEGIN_ALLOW_THREADS;
    result =
        VMMDLL_Map_GetPfn(self->pyVMM->hVMM, pPfns, cPfns, NULL, &cbPfnMap) &&
        (pPfnMap = LocalAlloc(0, cbPfnMap)) &&
        VMMDLL_Map_GetPfn(self->pyVMM->hVMM, pPfns, cPfns, pPfnMap, &cbPfnMap);
    Py_END_ALLOW_THREADS;
    if(!result || (pPfnMap->dwVersion != VMMDLL_MAP_PFN_VERSION)) {
        LocalFree(pPfnMap);
        return PyErr_Format(PyExc_RuntimeError, "Maps.pfn(): Failed.");
    }
    if(!(pyDictDst = PyDict_New())) {
        LocalFree(pPfnMap);
        return PyErr_NoMemory();
    }
    for(i = 0; i < pPfnMap->cMap; i++) {
        pe = pPfnMap->pMap + i;
        if((pyDictItem = PyDict_New())) {
            PyDict_SetItemString_DECREF(pyDictItem, "pfn", PyLong_FromUnsignedLong(pe->dwPfn));
            PyDict_SetItemString_DECREF(pyDictItem, "pid", PyLong_FromUnsignedLong(pe->AddressInfo.dwPid));
            PyDict_SetItemString_DECREF(pyDictItem, "va", PyLong_FromUnsignedLongLong(pe->AddressInfo.va));
            PyDict_SetItemString_DECREF(pyDictItem, "va-pte", PyLong_FromUnsignedLongLong(pe->vaPte));
            PyDict_SetItemString_DECREF(pyDictItem, "tp", PyUnicode_FromFormat("%s", VMMDLL_PFN_TYPE_TEXT[pe->PageLocation]));
            PyDict_SetItemString_DECREF(pyDictItem, "tpex", PyUnicode_FromFormat("%s", VMMDLL_PFN_TYPEEXTENDED_TEXT[pe->tpExtended]));
            PyDict_SetItemDWORD_DECREF(pyDictDst, pe->dwPfn, pyDictItem);
        }
    }
    LocalFree(pPfnMap);
    return pyDictDst;
}

// () -> [{...}]
static PyObject*
VmmPycMaps_user(PyObj_Maps *self, PyObject *args)
{
    PyObject *pyList, *pyDict;
    BOOL result;
    ULONG64 i;
    PVMMDLL_MAP_USER pUserMap = NULL;
    PVMMDLL_MAP_USERENTRY pe;
    if(!self->fValid) { return PyErr_Format(PyExc_RuntimeError, "Maps.user(): Not initialized."); }
    if(!(pyList = PyList_New(0))) { return PyErr_NoMemory(); }
    Py_BEGIN_ALLOW_THREADS;
    result = VMMDLL_Map_GetUsersU(self->pyVMM->hVMM, &pUserMap);
    Py_END_ALLOW_THREADS;
    if(!result || (pUserMap->dwVersion != VMMDLL_MAP_USER_VERSION)) {
        Py_DECREF(pyList);
        VMMDLL_MemFree(pUserMap);;
        return PyErr_Format(PyExc_RuntimeError, "Maps.user(): Failed.");
    }
    for(i = 0; i < pUserMap->cMap; i++) {
        if((pyDict = PyDict_New())) {
            pe = pUserMap->pMap + i;
            PyDict_SetItemString_DECREF(pyDict, "va-reghive", PyLong_FromUnsignedLongLong(pe->vaRegHive));
            PyDict_SetItemString_DECREF(pyDict, "sid", PyUnicode_FromString(pe->uszSID));
            PyDict_SetItemString_DECREF(pyDict, "name", PyUnicode_FromString(pe->uszText));
            PyList_Append_DECREF(pyList, pyDict);
        }
    }
    VMMDLL_MemFree(pUserMap);
    return pyList;
}

// () -> {1: {...}, ...}
static PyObject*
VmmPycMaps_service(PyObj_Maps *self, PyObject *args)
{
    PyObject *pyDictResult, *pyDict;
    BOOL result;
    ULONG64 i;
    PVMMDLL_MAP_SERVICE pServiceMap = NULL;
    PVMMDLL_MAP_SERVICEENTRY pe;
    if(!self->fValid) { return PyErr_Format(PyExc_RuntimeError, "Maps.service(): Not initialized."); }
    if(!(pyDictResult = PyDict_New())) { return PyErr_NoMemory(); }
    Py_BEGIN_ALLOW_THREADS;
    result = VMMDLL_Map_GetServicesU(self->pyVMM->hVMM, &pServiceMap);
    Py_END_ALLOW_THREADS;
    if(!result || (pServiceMap->dwVersion != VMMDLL_MAP_SERVICE_VERSION)) {
        Py_DECREF(pyDictResult);
        VMMDLL_MemFree(pServiceMap);
        return PyErr_Format(PyExc_RuntimeError, "Maps.service(): Failed.");
    }
    for(i = 0; i < pServiceMap->cMap; i++) {
        if((pyDict = PyDict_New())) {
            pe = pServiceMap->pMap + i;
            PyDict_SetItemString_DECREF(pyDict, "ordinal", PyLong_FromUnsignedLong(pe->dwOrdinal));
            PyDict_SetItemString_DECREF(pyDict, "va-obj", PyLong_FromUnsignedLongLong(pe->vaObj));
            PyDict_SetItemString_DECREF(pyDict, "pid", PyLong_FromUnsignedLong(pe->dwPID));
            PyDict_SetItemString_DECREF(pyDict, "dwStartType", PyLong_FromUnsignedLong(pe->dwStartType));
            PyDict_SetItemString_DECREF(pyDict, "dwServiceType", PyLong_FromUnsignedLong(pe->ServiceStatus.dwServiceType));
            PyDict_SetItemString_DECREF(pyDict, "dwCurrentState", PyLong_FromUnsignedLong(pe->ServiceStatus.dwCurrentState));
            PyDict_SetItemString_DECREF(pyDict, "dwControlsAccepted", PyLong_FromUnsignedLong(pe->ServiceStatus.dwControlsAccepted));
            PyDict_SetItemString_DECREF(pyDict, "dwWin32ExitCode", PyLong_FromUnsignedLong(pe->ServiceStatus.dwWin32ExitCode));
            PyDict_SetItemString_DECREF(pyDict, "dwServiceSpecificExitCode", PyLong_FromUnsignedLong(pe->ServiceStatus.dwServiceSpecificExitCode));
            PyDict_SetItemString_DECREF(pyDict, "dwCheckPoint", PyLong_FromUnsignedLong(pe->ServiceStatus.dwCheckPoint));
            PyDict_SetItemString_DECREF(pyDict, "dwWaitHint", PyLong_FromUnsignedLong(pe->ServiceStatus.dwWaitHint));
            PyDict_SetItemString_DECREF(pyDict, "name", PyUnicode_FromString(pe->uszServiceName));
            PyDict_SetItemString_DECREF(pyDict, "name-display", PyUnicode_FromString(pe->uszDisplayName));
            PyDict_SetItemString_DECREF(pyDict, "path", PyUnicode_FromString(pe->uszPath));
            PyDict_SetItemString_DECREF(pyDict, "user-tp", PyUnicode_FromString(pe->uszUserTp));
            PyDict_SetItemString_DECREF(pyDict, "user-acct", PyUnicode_FromString(pe->uszUserAcct));
            PyDict_SetItemString_DECREF(pyDict, "path-image", PyUnicode_FromString(pe->uszImagePath));
            PyDict_SetItemDWORD_DECREF(pyDictResult, pe->dwOrdinal, pyDict);
        }
    }
    VMMDLL_MemFree(pServiceMap);
    return pyDictResult;
}

// () -> [VmmPycVirtualMachine, ...]
static PyObject*
VmmPycMaps_virtualmachines(PyObj_Maps *self, PyObject *args)
{
    PyObject *pyList;
    BOOL result;
    ULONG64 i;
    PVMMDLL_MAP_VM pVmMemMap = NULL;
    PyObj_VirtualMachine *pyVirtualMachine;
    if(!self->fValid) { return PyErr_Format(PyExc_RuntimeError, "Maps.virtualmachines(): Not initialized."); }
    if(!(pyList = PyList_New(0))) { return PyErr_NoMemory(); }
    Py_BEGIN_ALLOW_THREADS;
    result = VMMDLL_Map_GetVMU(self->pyVMM->hVMM, &pVmMemMap);
    Py_END_ALLOW_THREADS;
    if(!result || (pVmMemMap->dwVersion != VMMDLL_MAP_VM_VERSION)) {
        Py_DECREF(pyList);
        VMMDLL_MemFree(pVmMemMap);
        return PyErr_Format(PyExc_RuntimeError, "Maps.virtualmachines(): Failed.");
    }
    for(i = 0; i < pVmMemMap->cMap; i++) {
        pyVirtualMachine = VmmPycVirtualMachine_InitializeInternal(self->pyVMM, pVmMemMap->pMap + i);
        PyList_Append_DECREF(pyList, (PyObject*)pyVirtualMachine);
    }
    VMMDLL_MemFree(pVmMemMap);
    return pyList;
}

//-----------------------------------------------------------------------------
// VmmPycMaps INITIALIZATION AND CORE FUNCTIONALITY BELOW:
//-----------------------------------------------------------------------------

PyObj_Maps*
VmmPycMaps_InitializeInternal(_In_ PyObj_Vmm *pyVMM)
{
    PyObj_Maps *pyObj;
    if(!(pyObj = PyObject_New(PyObj_Maps, (PyTypeObject*)g_pPyType_Maps))) { return NULL; }
    Py_INCREF(pyVMM); pyObj->pyVMM = pyVMM;
    pyObj->fValid = TRUE;
    return pyObj;
}

static PyObject*
VmmPycMaps_repr(PyObj_Maps *self)
{
    return PyUnicode_FromFormat(self->fValid ? "Maps" : "Maps:NotValid");
}

static int
VmmPycMaps_init(PyObj_Maps *self, PyObject *args, PyObject *kwds)
{
    PyErr_SetString(PyExc_TypeError, "Maps.init(): Not allowed.");
    return -1;
}

static void
VmmPycMaps_dealloc(PyObj_Maps *self)
{
    self->fValid = FALSE;
}

_Success_(return)
BOOL VmmPycMaps_InitializeType(PyObject *pModule)
{
    static PyMethodDef PyMethods[] = {
        {"memmap", (PyCFunction)VmmPycMaps_memmap, METH_VARARGS, "Retrieve the physical memory map."},
        {"net", (PyCFunction)VmmPycMaps_net, METH_VARARGS, "Retrieve the etwork connection map."},
        {"pfn", (PyCFunction)VmmPycMaps_pfn, METH_VARARGS, "Retrieve page frame number (PFN) information for select page frame numbers."},
        {"pool", (PyCFunction)VmmPycMaps_pool, METH_VARARGS, "Retrieve kernel pool allocations."},
        {"service", (PyCFunction)VmmPycMaps_service, METH_VARARGS, "Retrieve services from the service control manager (SCM)."},
        {"user", (PyCFunction)VmmPycMaps_user, METH_VARARGS, "Retrieve the non-well known users."},
        {"virtualmachines", (PyCFunction)VmmPycMaps_virtualmachines, METH_VARARGS, "Retrieve virtual machines."},
        {NULL, NULL, 0, NULL}
    };
    static PyMemberDef PyMembers[] = {
        {NULL}
    };
    static PyGetSetDef PyGetSet[] = {
        {NULL}
    };
    static PyType_Slot PyTypeSlot[] = {
        {Py_tp_init, VmmPycMaps_init},
        {Py_tp_dealloc, VmmPycMaps_dealloc},
        {Py_tp_repr, VmmPycMaps_repr},
        {Py_tp_methods, PyMethods},
        {Py_tp_members, PyMembers},
        {Py_tp_getset, PyGetSet},
        {0, 0}
    };
    static PyType_Spec PyTypeSpec = {
        .name = "vmmpyc.VmmMaps",
        .basicsize = sizeof(PyObj_Maps),
        .itemsize = 0,
        .flags = Py_TPFLAGS_DEFAULT,
        .slots = PyTypeSlot,
    };
    if((g_pPyType_Maps = PyType_FromSpec(&PyTypeSpec))) {
        if(PyModule_AddObject(pModule, "VmmMaps", g_pPyType_Maps) < 0) {
            Py_DECREF(g_pPyType_Maps);
            g_pPyType_Maps = NULL;
        }
    }
    return g_pPyType_Maps ? TRUE : FALSE;
}
