// vmmpyc_modulemaps.c : implementation of the modules infomap functionality for vmmpyc.
//
// (c) Ulf Frisk, 2021
// Author: Ulf Frisk, pcileech@frizk.net
//
#include "vmmpyc.h"

PyObject *g_pPyType_ModuleMaps = NULL;

// -> [{...}]
static PyObject*
VmmPycModuleMaps_directories(PyObj_ModuleMaps *self, PyObject *args)
{
    PyObject *pyList, *pyDict;
    BOOL result;
    DWORD i, cDirectories;
    PIMAGE_DATA_DIRECTORY pe, pDirectories = NULL;
    LPCSTR DIRECTORIES[16] = { "EXPORT", "IMPORT", "RESOURCE", "EXCEPTION", "SECURITY", "BASERELOC", "DEBUG", "ARCHITECTURE", "GLOBALPTR", "TLS", "LOAD_CONFIG", "BOUND_IMPORT", "IAT", "DELAY_IMPORT", "COM_DESCRIPTOR", "RESERVED" };
    if(!self->fValid) { return PyErr_Format(PyExc_RuntimeError, "ModuleMaps.directories(): Not initialized."); }
    if(!(pyList = PyList_New(0))) { return PyErr_NoMemory(); }
    Py_BEGIN_ALLOW_THREADS;
    result =
        (pDirectories = LocalAlloc(0, 16 * sizeof(IMAGE_DATA_DIRECTORY))) &&
        VMMDLL_ProcessGetDirectoriesU(self->dwPID, self->uszModule, pDirectories, 16, &cDirectories);
    Py_END_ALLOW_THREADS;
    if(!result) {
        Py_DECREF(pyList);
        LocalFree(pDirectories);
        return PyErr_Format(PyExc_RuntimeError, "ModuleMaps.directories(): Failed.");
    }
    for(i = 0; i < 16; i++) {
        if((pyDict = PyDict_New())) {
            pe = pDirectories + i;
            PyDict_SetItemString_DECREF(pyDict, "i", PyLong_FromUnsignedLong(i));
            PyDict_SetItemString_DECREF(pyDict, "size", PyLong_FromUnsignedLong(pe->Size));
            PyDict_SetItemString_DECREF(pyDict, "offset", PyLong_FromUnsignedLong(pe->VirtualAddress));
            PyDict_SetItemString_DECREF(pyDict, "name", PyUnicode_FromFormat("%s", DIRECTORIES[i]));
            PyList_Append_DECREF(pyList, pyDict);
        }
    }
    LocalFree(pDirectories);
    return pyList;
}

// -> [{...}]
static PyObject*
VmmPycModuleMaps_sections(PyObj_ModuleMaps *self, PyObject *args)
{
    PyObject *pyList, *pyDict;
    BOOL result;
    DWORD i, cSections;
    PIMAGE_SECTION_HEADER pe, pSections = NULL;
    CHAR szName[9];
    if(!self->fValid) { return PyErr_Format(PyExc_RuntimeError, "ModuleMaps.sections(): Not initialized."); }
    szName[8] = 0;
    if(!(pyList = PyList_New(0))) { return PyErr_NoMemory(); }
    Py_BEGIN_ALLOW_THREADS;
    result =
        VMMDLL_ProcessGetSectionsU(self->dwPID, self->uszModule, NULL, 0, &cSections) &&
        cSections &&
        (pSections = LocalAlloc(0, cSections * sizeof(IMAGE_SECTION_HEADER))) &&
        VMMDLL_ProcessGetSectionsU(self->dwPID, self->uszModule, pSections, cSections, &cSections);
    Py_END_ALLOW_THREADS;
    if(!result) {
        Py_DECREF(pyList);
        LocalFree(pSections);
        return PyErr_Format(PyExc_RuntimeError, "ModuleMaps.sections(): Failed.");
    }
    for(i = 0; i < cSections; i++) {
        if((pyDict = PyDict_New())) {
            pe = pSections + i;
            PyDict_SetItemString_DECREF(pyDict, "i", PyLong_FromUnsignedLong(i));
            PyDict_SetItemString_DECREF(pyDict, "Characteristics", PyLong_FromUnsignedLong(pe->Characteristics));
            PyDict_SetItemString_DECREF(pyDict, "misc-PhysicalAddress", PyLong_FromUnsignedLong(pe->Misc.PhysicalAddress));
            PyDict_SetItemString_DECREF(pyDict, "misc-VirtualSize", PyLong_FromUnsignedLong(pe->Misc.VirtualSize));
            *(PULONG64)szName = *(PULONG64)pe->Name;
            PyDict_SetItemString_DECREF(pyDict, "Name", PyUnicode_FromFormat("%s", szName));
            PyDict_SetItemString_DECREF(pyDict, "NumberOfLinenumbers", PyLong_FromUnsignedLong(pe->NumberOfLinenumbers));
            PyDict_SetItemString_DECREF(pyDict, "NumberOfRelocations", PyLong_FromUnsignedLong(pe->NumberOfRelocations));
            PyDict_SetItemString_DECREF(pyDict, "PointerToLinenumbers", PyLong_FromUnsignedLong(pe->PointerToLinenumbers));
            PyDict_SetItemString_DECREF(pyDict, "PointerToRawData", PyLong_FromUnsignedLong(pe->PointerToRawData));
            PyDict_SetItemString_DECREF(pyDict, "PointerToRelocations", PyLong_FromUnsignedLong(pe->PointerToRelocations));
            PyDict_SetItemString_DECREF(pyDict, "SizeOfRawData", PyLong_FromUnsignedLong(pe->SizeOfRawData));
            PyDict_SetItemString_DECREF(pyDict, "VirtualAddress", PyLong_FromUnsignedLong(pe->VirtualAddress));
            PyList_Append_DECREF(pyList, pyDict);
        }
    }
    LocalFree(pSections);
    return pyList;
}

// -> {..., 'e': [{...}]}
static PyObject*
VmmPycModuleMaps_eat(PyObj_ModuleMaps *self, PyObject *args)
{
    PyObject *pyDictTop, *pyList, *pyDict;
    BOOL result;
    DWORD i, cbEatMap = 0;
    PVMMDLL_MAP_EATENTRY pe;
    PVMMDLL_MAP_EAT pEatMap = NULL;
    if(!self->fValid) { return PyErr_Format(PyExc_RuntimeError, "ModuleMaps.eat(): Not initialized."); }
    if(!(pyDictTop = PyDict_New())) { return PyErr_NoMemory(); }
    if(!(pyList = PyList_New(0))) { return PyErr_NoMemory(); }
    Py_BEGIN_ALLOW_THREADS;
    result =
        VMMDLL_Map_GetEATU(self->dwPID, self->uszModule, NULL, &cbEatMap) &&
        (pEatMap = LocalAlloc(0, cbEatMap)) &&
        VMMDLL_Map_GetEATU(self->dwPID, self->uszModule, pEatMap, &cbEatMap) &&
        (pEatMap->dwVersion == VMMDLL_MAP_EAT_VERSION);
    Py_END_ALLOW_THREADS;
    if(!result) {
        Py_DECREF(pyList);
        LocalFree(pEatMap);
        return PyErr_Format(PyExc_RuntimeError, "ModuleMaps.eat(): Failed.");
    }
    for(i = 0; i < pEatMap->cMap; i++) {
        if((pyDict = PyDict_New())) {
            pe = pEatMap->pMap + i;
            PyDict_SetItemString_DECREF(pyDict, "i", PyLong_FromUnsignedLong(i));
            PyDict_SetItemString_DECREF(pyDict, "ord", PyLong_FromUnsignedLong(pe->dwOrdinal));
            PyDict_SetItemString_DECREF(pyDict, "oafn", PyLong_FromUnsignedLong(pe->oFunctionsArray));
            PyDict_SetItemString_DECREF(pyDict, "oanm", PyLong_FromUnsignedLong(pe->oNamesArray));
            PyDict_SetItemString_DECREF(pyDict, "ofn", PyLong_FromUnsignedLong((DWORD)(pe->vaFunction - pEatMap->vaModuleBase)));
            PyDict_SetItemString_DECREF(pyDict, "va", PyLong_FromUnsignedLongLong(pe->vaFunction));
            PyDict_SetItemString_DECREF(pyDict, "fn", PyUnicode_FromString(pe->uszFunction));
            PyList_Append_DECREF(pyList, pyDict);
        }
    }
    PyDict_SetItemString_DECREF(pyDictTop, "va-module", PyLong_FromUnsignedLongLong(pEatMap->vaModuleBase));
    PyDict_SetItemString_DECREF(pyDictTop, "va-afn", PyLong_FromUnsignedLongLong(pEatMap->vaAddressOfFunctions));
    PyDict_SetItemString_DECREF(pyDictTop, "va-anm", PyLong_FromUnsignedLongLong(pEatMap->vaAddressOfNames));
    PyDict_SetItemString_DECREF(pyDictTop, "ord-base", PyLong_FromUnsignedLong(pEatMap->dwOrdinalBase));
    PyDict_SetItemString_DECREF(pyDictTop, "c-afn", PyLong_FromUnsignedLong(pEatMap->cNumberOfFunctions));
    PyDict_SetItemString_DECREF(pyDictTop, "c-anm", PyLong_FromUnsignedLong(pEatMap->cNumberOfNames));
    PyDict_SetItemString_DECREF(pyDictTop, "e", pyList);
    LocalFree(pEatMap);
    return pyDictTop;
}

// -> [{...}]
static PyObject *
VmmPycModuleMaps_iat(PyObj_ModuleMaps *self, PyObject *args)
{
    PyObject *pyList, *pyDict;
    BOOL result;
    DWORD i, cbIatMap = 0;
    PVMMDLL_MAP_IATENTRY pe;
    PVMMDLL_MAP_IAT pIatMap = NULL;
    if(!self->fValid) { return PyErr_Format(PyExc_RuntimeError, "ModuleMaps.iat(): Not initialized."); }
    if(!(pyList = PyList_New(0))) { return PyErr_NoMemory(); }
    Py_BEGIN_ALLOW_THREADS;
    result =
        VMMDLL_Map_GetIATU(self->dwPID, self->uszModule, NULL, &cbIatMap) &&
        (pIatMap = LocalAlloc(0, cbIatMap)) &&
        VMMDLL_Map_GetIATU(self->dwPID, self->uszModule, pIatMap, &cbIatMap) &&
        (pIatMap->dwVersion == VMMDLL_MAP_IAT_VERSION);
    Py_END_ALLOW_THREADS;
    if(!result) {
        Py_DECREF(pyList);
        LocalFree(pIatMap);
        return PyErr_Format(PyExc_RuntimeError, "ModuleMaps.iat(): Failed.");
    }
    for(i = 0; i < pIatMap->cMap; i++) {
        if((pyDict = PyDict_New())) {
            pe = pIatMap->pMap + i;
            PyDict_SetItemString_DECREF(pyDict, "i", PyLong_FromUnsignedLong(i));
            PyDict_SetItemString_DECREF(pyDict, "va-fn", PyLong_FromUnsignedLongLong(pe->vaFunction));
            PyDict_SetItemString_DECREF(pyDict, "va-mod", PyLong_FromUnsignedLongLong(pIatMap->vaModuleBase));
            PyDict_SetItemString_DECREF(pyDict, "fn", PyUnicode_FromString(pe->uszFunction));
            PyDict_SetItemString_DECREF(pyDict, "dll", PyUnicode_FromString(pe->uszModule));
            PyDict_SetItemString_DECREF(pyDict, "32", PyBool_FromLong(pe->Thunk.f32));
            PyDict_SetItemString_DECREF(pyDict, "hint", PyLong_FromUnsignedLong(pe->Thunk.wHint));
            PyDict_SetItemString_DECREF(pyDict, "rvaFirstThunk", PyLong_FromUnsignedLong(pe->Thunk.rvaFirstThunk));
            PyDict_SetItemString_DECREF(pyDict, "rvaOriginalFirstThunk", PyLong_FromUnsignedLong(pe->Thunk.rvaOriginalFirstThunk));
            PyDict_SetItemString_DECREF(pyDict, "rvaNameModule", PyLong_FromUnsignedLong(pe->Thunk.rvaNameModule));
            PyDict_SetItemString_DECREF(pyDict, "rvaNameFunction", PyLong_FromUnsignedLong(pe->Thunk.rvaNameFunction));
            PyList_Append_DECREF(pyList, pyDict);
        }
    }
    LocalFree(pIatMap);
    return pyList;
}

//-----------------------------------------------------------------------------
// VmmPycModuleMaps INITIALIZATION AND CORE FUNCTIONALITY BELOW:
//-----------------------------------------------------------------------------

PyObj_ModuleMaps*
VmmPycModuleMaps_InitializeInternal(_In_ DWORD dwPID, _In_ LPSTR uszModule)
{
    PyObj_ModuleMaps *pyObjModuleMaps;
    if(!(pyObjModuleMaps = PyObject_New(PyObj_ModuleMaps, (PyTypeObject*)g_pPyType_ModuleMaps))) { return NULL; }
    pyObjModuleMaps->fValid = TRUE;
    pyObjModuleMaps->dwPID = dwPID;
    strncpy_s(pyObjModuleMaps->uszModule, _countof(pyObjModuleMaps->uszModule), uszModule, _TRUNCATE);
    return pyObjModuleMaps;
}

static PyObject*
VmmPycModuleMaps_repr(PyObj_ModuleMaps *self)
{
    PyObject *pyStr, *pyModuleName;
    if(!self->fValid) { return PyUnicode_FromFormat("ModuleMaps:NotValid"); }
    pyModuleName = PyUnicode_FromString(self->uszModule);
    pyStr = PyUnicode_FromFormat("ModuleMaps:%i:%U", self->dwPID, pyModuleName);
    Py_XDECREF(pyModuleName);
    return pyStr;
}

static int
VmmPycModuleMaps_init(PyObj_ModuleMaps *self, PyObject *args, PyObject *kwds)
{
    PyErr_SetString(PyExc_TypeError, "VmmModuleMaps.init(): Not allowed.");
    return -1;
}

static void
VmmPycModuleMaps_dealloc(PyObj_ModuleMaps *self)
{
    self->fValid = FALSE;
}

_Success_(return)
BOOL VmmPycModuleMaps_InitializeType(PyObject *pModule)
{
    static PyMethodDef PyMethods[] = {
        {"directories", (PyCFunction)VmmPycModuleMaps_directories, METH_VARARGS, "Retrieve the data directories."},
        {"sections", (PyCFunction)VmmPycModuleMaps_sections, METH_VARARGS, "Retrieve the sections."},
        {"eat", (PyCFunction)VmmPycModuleMaps_eat, METH_VARARGS, "Retrieve the export address table (EAT)."},
        {"iat", (PyCFunction)VmmPycModuleMaps_iat, METH_VARARGS, "Retrieve the import address table (IAT)."},
        {NULL, NULL, 0, NULL}
    };
    static PyMemberDef PyMembers[] = {
        {"pid", T_ULONG, offsetof(PyObj_ModuleMaps, dwPID), READONLY, "PID"},
        {NULL}
    };
    static PyGetSetDef PyGetSet[] = {
        {NULL}
    };
    static PyType_Slot PyTypeSlot[] = {
        {Py_tp_init, VmmPycModuleMaps_init},
        {Py_tp_dealloc, VmmPycModuleMaps_dealloc},
        {Py_tp_repr, VmmPycModuleMaps_repr},
        {Py_tp_methods, PyMethods},
        {Py_tp_members, PyMembers},
        {Py_tp_getset, PyGetSet},
        {0, 0}
    };
    static PyType_Spec PyTypeSpec = {
        .name = "vmmpyc.VmmModuleMaps",
        .basicsize = sizeof(PyObj_ModuleMaps),
        .itemsize = 0,
        .flags = Py_TPFLAGS_DEFAULT,
        .slots = PyTypeSlot,
    };
    if((g_pPyType_ModuleMaps = PyType_FromSpec(&PyTypeSpec))) {
        if(PyModule_AddObject(pModule, "VmmModuleMaps", g_pPyType_ModuleMaps) < 0) {
            Py_DECREF(g_pPyType_ModuleMaps);
            g_pPyType_ModuleMaps = NULL;
        }
    }
    return g_pPyType_ModuleMaps ? TRUE : FALSE;
}
