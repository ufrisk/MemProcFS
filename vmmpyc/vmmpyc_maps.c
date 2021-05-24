// vmmpyc_maps.c : implementation of the global infomaps functionality for vmmpyc.
//
// (c) Ulf Frisk, 2021
// Author: Ulf Frisk, pcileech@frizk.net
//
#ifdef _WIN32
#include <ws2tcpip.h>
#endif /* _WIN32 */
#include "vmmpyc.h"

PyObject *g_pPyType_Maps = NULL;

// () -> [{...}]
static PyObject*
VmmPycMaps_net(PyObj_Maps *self, PyObject *args)
{
    PyObject *pyList, *pyDictTcpE;
    BOOL result;
    DWORD i, dwIpVersion, cbNetMap = 0;
    PVMMDLL_MAP_NET pNetMap = NULL;
    PVMMDLL_MAP_NETENTRY pe;
    CHAR szTime[24];
    if(!self->fValid) { return PyErr_Format(PyExc_RuntimeError, "Maps.net(): Not initialized."); }
    if(!(pyList = PyList_New(0))) { return PyErr_NoMemory(); }
    Py_BEGIN_ALLOW_THREADS;
    result =
        VMMDLL_Map_GetNetU(NULL, &cbNetMap) &&
        cbNetMap &&
        (pNetMap = LocalAlloc(0, cbNetMap)) &&
        VMMDLL_Map_GetNetU(pNetMap, &cbNetMap);
    Py_END_ALLOW_THREADS;
    if(!result || (pNetMap->dwVersion != VMMDLL_MAP_NET_VERSION)) {
        Py_DECREF(pyList);
        LocalFree(pNetMap);
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
    DWORD cbPhysMemMap = 0;
    ULONG64 i;
    PVMMDLL_MAP_PHYSMEM pPhysMemMap = NULL;
    PVMMDLL_MAP_PHYSMEMENTRY pe;
    if(!self->fValid) { return PyErr_Format(PyExc_RuntimeError, "Maps.memmap(): Not initialized."); }
    if(!(pyList = PyList_New(0))) { return PyErr_NoMemory(); }
    Py_BEGIN_ALLOW_THREADS;
    result =
        VMMDLL_Map_GetPhysMem(NULL, &cbPhysMemMap) &&
        cbPhysMemMap &&
        (pPhysMemMap = LocalAlloc(0, cbPhysMemMap)) &&
        VMMDLL_Map_GetPhysMem(pPhysMemMap, &cbPhysMemMap);
    Py_END_ALLOW_THREADS;
    if(!result || (pPhysMemMap->dwVersion != VMMDLL_MAP_PHYSMEM_VERSION)) {
        Py_DECREF(pyList);
        LocalFree(pPhysMemMap);
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
    LocalFree(pPhysMemMap);
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
        VMMDLL_Map_GetPfn(pPfns, cPfns, NULL, &cbPfnMap) &&
        (pPfnMap = LocalAlloc(0, cbPfnMap)) &&
        VMMDLL_Map_GetPfn(pPfns, cPfns, pPfnMap, &cbPfnMap);
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
    DWORD cbUserMap = 0;
    ULONG64 i;
    PVMMDLL_MAP_USER pUserMap = NULL;
    PVMMDLL_MAP_USERENTRY pe;
    if(!self->fValid) { return PyErr_Format(PyExc_RuntimeError, "Maps.user(): Not initialized."); }
    if(!(pyList = PyList_New(0))) { return PyErr_NoMemory(); }
    Py_BEGIN_ALLOW_THREADS;
    result =
        VMMDLL_Map_GetUsersU(NULL, &cbUserMap) &&
        cbUserMap &&
        (pUserMap = LocalAlloc(0, cbUserMap)) &&
        VMMDLL_Map_GetUsersU(pUserMap, &cbUserMap);
    Py_END_ALLOW_THREADS;
    if(!result || (pUserMap->dwVersion != VMMDLL_MAP_USER_VERSION)) {
        Py_DECREF(pyList);
        LocalFree(pUserMap);
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
    LocalFree(pUserMap);
    return pyList;
}

// () -> {1: {...}, ...}
static PyObject*
VmmPycMaps_service(PyObj_Maps *self, PyObject *args)
{
    PyObject *pyDictResult, *pyDict;
    BOOL result;
    DWORD cbServiceMap = 0;
    ULONG64 i;
    PVMMDLL_MAP_SERVICE pServiceMap = NULL;
    PVMMDLL_MAP_SERVICEENTRY pe;
    if(!self->fValid) { return PyErr_Format(PyExc_RuntimeError, "Maps.service(): Not initialized."); }
    if(!(pyDictResult = PyDict_New())) { return PyErr_NoMemory(); }
    Py_BEGIN_ALLOW_THREADS;
    result =
        VMMDLL_Map_GetServicesU(NULL, &cbServiceMap) &&
        cbServiceMap &&
        (pServiceMap = LocalAlloc(0, cbServiceMap)) &&
        VMMDLL_Map_GetServicesU(pServiceMap, &cbServiceMap);
    Py_END_ALLOW_THREADS;
    if(!result || (pServiceMap->dwVersion != VMMDLL_MAP_SERVICE_VERSION)) {
        Py_DECREF(pyDictResult);
        LocalFree(pServiceMap);
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
    LocalFree(pServiceMap);
    return pyDictResult;
}

//-----------------------------------------------------------------------------
// VmmPycMaps INITIALIZATION AND CORE FUNCTIONALITY BELOW:
//-----------------------------------------------------------------------------

PyObj_Maps*
VmmPycMaps_InitializeInternal()
{
    PyObj_Maps *pyObj;
    if(!(pyObj = PyObject_New(PyObj_Maps, (PyTypeObject*)g_pPyType_Maps))) { return NULL; }
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
        {"net", (PyCFunction)VmmPycMaps_net, METH_VARARGS, "Retrieve the etwork connection map."},
        {"memmap", (PyCFunction)VmmPycMaps_memmap, METH_VARARGS, "Retrieve the physical memory map."},
        {"user", (PyCFunction)VmmPycMaps_user, METH_VARARGS, "Retrieve the non-well known users."},
        {"service", (PyCFunction)VmmPycMaps_service, METH_VARARGS, "Retrieve services from the service control manager (SCM)."},
        {"pfn", (PyCFunction)VmmPycMaps_pfn, METH_VARARGS, "Retrieve page frame number (PFN) information for select page frame numbers."},
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
