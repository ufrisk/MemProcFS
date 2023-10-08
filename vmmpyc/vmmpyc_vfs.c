// vmmpyc_vfs.c : implementation of virtual file system (vfs) functionality for vmmpyc.
//
// (c) Ulf Frisk, 2021-2023
// Author: Ulf Frisk, pcileech@frizk.net
//
#include "vmmpyc.h"

PyObject *g_pPyType_Vfs = NULL;

typedef struct tdVMMPYCVFS_LIST {
    struct tdVMMPYCVFS_LIST *FLink;
    CHAR uszName[3 * MAX_PATH];
    BOOL fIsDir;
    ULONG64 qwSize;
} VMMPYCVFS_LIST, *PVMMPYCVFS_LIST;

LPSTR Util_ReplaceSlashAlloc(_In_opt_ LPSTR usz)
{
    DWORD i = 0, cbu = (usz ? (DWORD)strlen(usz) : 0) + 1;
    LPSTR uszDst = LocalAlloc(LMEM_ZEROINIT, cbu);
    if(usz && uszDst) {
        memcpy(uszDst, usz, cbu);
        while(uszDst[i]) {
            if(uszDst[i] == '/') { uszDst[i] = '\\'; }
            i++;
        }
    }
    return uszDst;
}

VOID VmmPycVfs_list_AddInternal(_Inout_ HANDLE h, _In_ LPSTR uszName, _In_ ULONG64 size, _In_ BOOL fIsDirectory)
{
    DWORD i = 0;
    PVMMPYCVFS_LIST pE;
    PVMMPYCVFS_LIST *ppE = (PVMMPYCVFS_LIST*)h;
    if((pE = LocalAlloc(0, sizeof(VMMPYCVFS_LIST)))) {
        while(i < sizeof(pE->uszName) && uszName && uszName[i]) {
            pE->uszName[i] = uszName[i];
            i++;
        }
        pE->uszName[min(i, sizeof(pE->uszName) - 1)] = 0;
        pE->fIsDir = fIsDirectory;
        pE->qwSize = size;
        pE->FLink = *ppE;
        *ppE = pE;
    }
}

VOID VmmPycVfs_list_AddFile(_Inout_ HANDLE h, _In_ LPSTR uszName, _In_ ULONG64 size, _In_opt_ PVMMDLL_VFS_FILELIST_EXINFO pExInfo)
{
    VmmPycVfs_list_AddInternal(h, uszName, size, FALSE);
}

VOID VmmPycVfs_list_AddDirectory(_Inout_ HANDLE h, _In_ LPSTR uszName, _In_opt_ PVMMDLL_VFS_FILELIST_EXINFO pExInfo)
{
    VmmPycVfs_list_AddInternal(h, uszName, 0, TRUE);
}

// (STR) -> {{...}}
static PyObject*
VmmPycVfs_list(PyObj_Vfs *self, PyObject *args)
{
    PyObject *pyDict, *PyDict_Attr;
    PyObject *pyKeyName;
    BOOL result;
    LPSTR uszPathPython = NULL, uszPath;
    VMMDLL_VFS_FILELIST2 hFileList;
    PVMMPYCVFS_LIST pE = NULL, pE_Next;
    if(!self->fValid) { return PyErr_Format(PyExc_RuntimeError, "Vfs.list(): Not initialized."); }
    if(!PyArg_ParseTuple(args, "s", &uszPathPython)) {
        return PyErr_Format(PyExc_RuntimeError, "Vfs.list(): Illegal argument.");
    }
    if(!(pyDict = PyDict_New())) { return PyErr_NoMemory(); }
    Py_BEGIN_ALLOW_THREADS;
    hFileList.h = &pE;
    hFileList.pfnAddFile = VmmPycVfs_list_AddFile;
    hFileList.pfnAddDirectory = VmmPycVfs_list_AddDirectory;
    hFileList.dwVersion = VMMDLL_VFS_FILELIST_VERSION;
    uszPath = Util_ReplaceSlashAlloc(uszPathPython);
    result = uszPath && VMMDLL_VfsListU(self->pyVMM->hVMM, uszPath, &hFileList);
    LocalFree(uszPath);
    pE = *(PVMMPYCVFS_LIST*)hFileList.h;
    Py_END_ALLOW_THREADS;
    while(pE) {
        if((PyDict_Attr = PyDict_New())) {
            pyKeyName = PyUnicode_FromString(pE->uszName);
            PyDict_SetItemString_DECREF(PyDict_Attr, "f_isdir", PyBool_FromLong(pE->fIsDir ? 1 : 0));
            PyDict_SetItemString_DECREF(PyDict_Attr, "size", PyLong_FromUnsignedLongLong(pE->qwSize));
            PyDict_SetItemString(PyDict_Attr, "name", pyKeyName);
            PyDict_SetItem(pyDict, pyKeyName, PyDict_Attr);
            Py_DECREF(PyDict_Attr);
            Py_DECREF(pyKeyName);
        }
        pE_Next = pE->FLink;
        LocalFree(pE);
        pE = pE_Next;
    }
    if(!result) {
        Py_DECREF(pyDict);
        PyErr_Format(PyExc_RuntimeError, "Vfs.list(): Failed.");
    }
    return pyDict;
}

// (STR, DWORD, (ULONG64)) -> PBYTE
static PyObject*
VmmPycVfs_read(PyObj_Vfs *self, PyObject *args)
{
    PyObject *pyBytes;
    NTSTATUS nt;
    DWORD cb = 0x00100000, cbRead = 0;
    ULONG64 cbOffset = 0;
    PBYTE pb;
    LPSTR uszPathPython = NULL, uszPath;
    if(!self->fValid) { return PyErr_Format(PyExc_RuntimeError, "Vfs.read(): Not initialized."); }
    if(!PyArg_ParseTuple(args, "s|kK", &uszPathPython, &cb, &cbOffset)) {
        return PyErr_Format(PyExc_RuntimeError, "Vfs.read(): Illegal argument.");
    }
    if(cb > 0x10000000) {
        return PyErr_Format(PyExc_RuntimeError, "Vfs.read(): Read exceeds maximum allowed (128MB).");
    }
    if(!(pb = LocalAlloc(0, cb))) { return PyErr_NoMemory(); }
    Py_BEGIN_ALLOW_THREADS;
    uszPath = Util_ReplaceSlashAlloc(uszPathPython);
    nt = VMMDLL_VfsReadU(self->pyVMM->hVMM, uszPath, pb, cb, &cbRead, cbOffset);
    LocalFree(uszPath);
    Py_END_ALLOW_THREADS;
    if(nt != VMMDLL_STATUS_SUCCESS) {
        LocalFree(pb);
        return PyErr_Format(PyExc_RuntimeError, "Vfs.read(): Failed.");
    }
    pyBytes = PyBytes_FromStringAndSize((const char*)pb, cbRead);
    LocalFree(pb);
    return pyBytes;
}

// (STR, PBYTE, (ULONG64)) -> None
static PyObject*
VmmPycVfs_write(PyObj_Vfs *self, PyObject *args)
{
    BOOL result;
    QWORD cb;
    DWORD cbWritten;
    ULONG64 cbOffset;
    PBYTE pb;
    LPSTR uszPathPython = NULL, uszPath;
    if(!self->fValid) { return PyErr_Format(PyExc_RuntimeError, "Vfs.write(): Not initialized."); }
    if(!PyArg_ParseTuple(args, "sy#|K", &uszPathPython, &pb, &cb, &cbOffset)) {
        return PyErr_Format(PyExc_RuntimeError, "Vfs.write(): Illegal argument.");
    }  
    if(cb == 0) {
        return Py_BuildValue("s", NULL);    // zero-byte write is always successful.
    }
    if(cb > 0x10000000) {
        return PyErr_Format(PyExc_RuntimeError, "Vfs.write(): Write exceeds maximum allowed (128MB).");
    }
    Py_BEGIN_ALLOW_THREADS;
    uszPath = Util_ReplaceSlashAlloc(uszPathPython);
    result = uszPath && (VMMDLL_STATUS_SUCCESS == VMMDLL_VfsWriteU(self->pyVMM->hVMM, uszPath, pb, (DWORD)cb, &cbWritten, cbOffset));
    LocalFree(uszPath);
    Py_END_ALLOW_THREADS;
    if(!result) {
        return PyErr_Format(PyExc_RuntimeError, "Vfs.write(): Failed.");
    }
    return Py_BuildValue("s", NULL);    // None returned on success.
}

//-----------------------------------------------------------------------------
// VmmPycVfs INITIALIZATION AND CORE FUNCTIONALITY BELOW:
//-----------------------------------------------------------------------------

PyObj_Vfs*
VmmPycVfs_InitializeInternal(_In_ PyObj_Vmm *pyVMM)
{
    PyObj_Vfs *pyObj;
    if(!(pyObj = PyObject_New(PyObj_Vfs, (PyTypeObject *)g_pPyType_Vfs))) { return NULL; }
    Py_INCREF(pyVMM); pyObj->pyVMM = pyVMM;
    pyObj->fValid = TRUE;
    return pyObj;
}

static PyObject*
VmmPycVfs_repr(PyObj_Vfs *self)
{
    return PyUnicode_FromFormat(self->fValid ? "Vfs" : "Vfs:NotValid");
}

static int
VmmPycVfs_init(PyObj_Vfs *self, PyObject *args, PyObject *kwds)
{
    PyErr_SetString(PyExc_TypeError, "Vfs.init(): Not allowed.");
    return -1;
}

static void
VmmPycVfs_dealloc(PyObj_Vfs *self)
{
    self->fValid = FALSE;
    Py_XDECREF(self->pyVMM);
    PyObject_Del(self);
}

_Success_(return)
BOOL VmmPycVfs_InitializeType(PyObject *pModule)
{
    static PyMethodDef PyMethods[] = {
        {"list", (PyCFunction)VmmPycVfs_list, METH_VARARGS, "List directory contents in virtual file system"},
        {"read", (PyCFunction)VmmPycVfs_read, METH_VARARGS, "Read file contents in virtual file system"},
        {"write", (PyCFunction)VmmPycVfs_write, METH_VARARGS, "Write file contents in virtual file system"},
        {NULL, NULL, 0, NULL}
    };
    static PyMemberDef PyMembers[] = {
        {NULL}
    };
    static PyGetSetDef PyGetSet[] = {
        {NULL}
    };
    static PyType_Slot PyTypeSlot[] = {
        {Py_tp_init, VmmPycVfs_init},
        {Py_tp_dealloc, VmmPycVfs_dealloc},
        {Py_tp_repr, VmmPycVfs_repr},
        {Py_tp_methods, PyMethods},
        {Py_tp_members, PyMembers},
        {Py_tp_getset, PyGetSet},
        {0, 0}
    };
    static PyType_Spec PyTypeSpec = {
        .name = "vmmpyc.VmmVfs",
        .basicsize = sizeof(PyObj_Vfs),
        .itemsize = 0,
        .flags = Py_TPFLAGS_DEFAULT,
        .slots = PyTypeSlot,
    };
    if((g_pPyType_Vfs = PyType_FromSpec(&PyTypeSpec))) {
        if(PyModule_AddObject(pModule, "VmmVfs", g_pPyType_Vfs) < 0) {
            Py_DECREF(g_pPyType_Vfs);
            g_pPyType_Vfs = NULL;
        }
    }
    return g_pPyType_Vfs ? TRUE : FALSE;
}
