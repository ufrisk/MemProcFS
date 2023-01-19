// vmmpycplugin.c : implementation of the python wrapper native MemProcFS plugin.
// NB! this is a special plugin since it's not residing in the plugin directory.
//
// (c) Ulf Frisk, 2018-2023
// Author: Ulf Frisk, pcileech@frizk.net
//
#include "vmmpyc.h"

//-----------------------------------------------------------------------------
// OS COMPATIBILITY LAYER BELOW:
//-----------------------------------------------------------------------------

#ifdef _WIN32

#undef EXPORTED_FUNCTION
#define EXPORTED_FUNCTION                   __declspec(dllexport)
#pragma warning( disable : 4996)

#endif /* _WIN32 */
#ifdef LINUX

#undef EXPORTED_FUNCTION
#define EXPORTED_FUNCTION                   __attribute__((visibility("default")))
typedef VOID *LPVOID;
#define __try                                if(TRUE)
#define __catch(X)                          if(FALSE)
#define __except(X)                         if(FALSE)
#define __declspec(X)
#define strncat_s(dst, dstlen, src, srclen) (strncat(dst, src, min((((strlen(dst) + 1 >= (size_t)(dstlen)) || ((size_t)(dstlen) == 0)) ? 0 : ((size_t)(dstlen) - strlen(dst) - 1)), (size_t)(srclen))))
#define strcat_s(dst, dstlen, src)          (strncat_s(dst, dstlen, src, _TRUNCATE))

#endif /* LINUX */



//-----------------------------------------------------------------------------
// GLOBAL VARIABLES BELOW:
//-----------------------------------------------------------------------------

static BOOL g_fPythonStandalone = FALSE;
PyObject *g_pPyType_VmmPycPlugin = NULL;

VMM_HANDLE g_PluginVMM = NULL;
BOOL g_PluginVMM_LoadedOnce = FALSE;



//-----------------------------------------------------------------------------
// PY2C PYTHON CALLBACK FUNCTIONALITY BELOW:
//-----------------------------------------------------------------------------

typedef struct tdPY2C_CONTEXT {
    BOOL fPrintf;
    BOOL fVerbose;
    BOOL fVerboseExtra;
    BOOL fVerboseExtraTlp;
    BOOL fInitialized;
    PyObject *fnList;
    PyObject *fnRead;
    PyObject *fnWrite;
    PyObject *fnNotify;
    PyObject *fnClose;
    PyObject *fnExec;
} PY2C_CONTEXT, *PPY2C_CONTEXT;

PPY2C_CONTEXT ctxPY2C = NULL;

static PyObject*
PY2C_CallbackRegister(PyObject *self, PyObject *args)
{
    if(ctxPY2C && !ctxPY2C->fInitialized) {
        Py_XDECREF(ctxPY2C->fnList);
        Py_XDECREF(ctxPY2C->fnRead);
        Py_XDECREF(ctxPY2C->fnWrite);
        Py_XDECREF(ctxPY2C->fnNotify);
        Py_XDECREF(ctxPY2C->fnClose);
        Py_XDECREF(ctxPY2C->fnExec);
        if(!PyArg_ParseTuple(args, "OOOOOO", &ctxPY2C->fnList, &ctxPY2C->fnRead, &ctxPY2C->fnWrite, &ctxPY2C->fnNotify, &ctxPY2C->fnClose, &ctxPY2C->fnExec)) { return NULL; }
        Py_XINCREF(ctxPY2C->fnList);
        Py_XINCREF(ctxPY2C->fnRead);
        Py_XINCREF(ctxPY2C->fnWrite);
        Py_XINCREF(ctxPY2C->fnNotify);
        Py_XINCREF(ctxPY2C->fnClose);
        Py_XINCREF(ctxPY2C->fnExec);
        ctxPY2C->fInitialized = TRUE;
    }
    return Py_BuildValue("s", NULL);    // None returned on success.
}

_Success_(return)
BOOL PY2C_Util_TranslatePathDelimiterU(_Out_writes_(3 * MAX_PATH) LPSTR dst, LPSTR src)
{
    DWORD i;
    for(i = 0; i < 3 * MAX_PATH; i++) {
        dst[i] = (src[i] == '\\') ? '/' : src[i];
        if(src[i] == 0) { return TRUE; }
    }
    return FALSE;
}

BOOL PY2C_Callback_List(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_CONTEXT ctxP, _Inout_ PHANDLE pFileList)
{
    BOOL result = FALSE;
    PyObject *args = NULL, *pyList = NULL, *pyDict, *pyPid = NULL, *pyPath = NULL, *pyBytes_Name;
    PyObject *pyDict_Name, *pyDict_Size, *pyDict_IsDir;
    LPSTR uszName;
    PyGILState_STATE gstate;
    SIZE_T i, cList;
    CHAR uszPathBuffer[3 * MAX_PATH];
    if(!ctxPY2C->fInitialized) { return FALSE; }
    if(!PY2C_Util_TranslatePathDelimiterU(uszPathBuffer, ctxP->uszPath)) { return FALSE; }
    gstate = PyGILState_Ensure();
    if(!(pyPath = PyUnicode_FromString(uszPathBuffer))) { goto pyfail; }
    pyPid = (ctxP->dwPID == 0xffffffff) ? NULL : PyLong_FromUnsignedLong(ctxP->dwPID);
    args = Py_BuildValue("OO", (pyPid ? pyPid : Py_None), pyPath);
    if(!args) { goto pyfail; }
    pyList = PyObject_CallObject(ctxPY2C->fnList, args);
    if(!pyList || !PyList_Check(pyList)) { goto pyfail; }
    cList = PyList_Size(pyList);
    for(i = 0; i < cList; i++) {
        pyDict = PyList_GetItem(pyList, i); // borrowed reference
        if(!PyDict_Check(pyDict)) { continue; }
        pyDict_Name = PyDict_GetItemString(pyDict, "name");         // borrowed reference
        pyDict_Size = PyDict_GetItemString(pyDict, "size");         // borrowed reference
        pyDict_IsDir = PyDict_GetItemString(pyDict, "f_isdir");     // borrowed reference
        if(!pyDict_Name || !PyUnicode_Check(pyDict_Name) || !pyDict_IsDir || !PyBool_Check(pyDict_IsDir)) { continue; }
        pyBytes_Name = PyUnicode_AsEncodedString(pyDict_Name, NULL, NULL);
        if(pyBytes_Name && (uszName = PyBytes_AsString(pyBytes_Name))) {
            if(pyDict_IsDir == Py_True) {
                VMMDLL_VfsList_AddDirectory(pFileList, uszName, NULL);
            } else {
                if(!pyDict_Size || !PyLong_Check(pyDict_Size)) { continue; }
                VMMDLL_VfsList_AddFile(pFileList, uszName, PyLong_AsUnsignedLongLong(pyDict_Size), NULL);
            }
            Py_DECREF(pyBytes_Name);
        }
    }
    result = TRUE;
    // fall through to cleanup
pyfail:
    Py_XDECREF(args);
    Py_XDECREF(pyPid);
    Py_XDECREF(pyList);
    Py_XDECREF(pyPath);
    PyGILState_Release(gstate);
    return result;
}

NTSTATUS PY2C_Callback_Read(
    _In_ VMM_HANDLE H,
    _In_ PVMMDLL_PLUGIN_CONTEXT ctxP,
    _Out_writes_to_(cb, *pcbRead) PBYTE pb,
    _In_ DWORD cb,
    _Out_ PDWORD pcbRead,
    _In_ ULONG64 cbOffset
) {
    NTSTATUS nt = VMMDLL_STATUS_FILE_INVALID;
    PyObject *args = NULL, *pyBytes = NULL, *pyPid = NULL, *pyPath = NULL;
    PyGILState_STATE gstate;
    CHAR uszPathBuffer[3 * MAX_PATH];
    if(!ctxPY2C->fInitialized) { return VMMDLL_STATUS_FILE_INVALID; }
    if(!PY2C_Util_TranslatePathDelimiterU(uszPathBuffer, ctxP->uszPath)) { return VMMDLL_STATUS_FILE_INVALID; }
    gstate = PyGILState_Ensure();
    if(!(pyPath = PyUnicode_FromString(uszPathBuffer))) { goto pyfail; }
    pyPid = (ctxP->dwPID == 0xffffffff) ? NULL : PyLong_FromUnsignedLong(ctxP->dwPID);
    args = Py_BuildValue("OOkK",
        pyPid ? pyPid : Py_None,
        pyPath,
        cb,
        cbOffset);
    if(!args) { goto pyfail; }
    pyBytes = PyObject_CallObject(ctxPY2C->fnRead, args);
    if(!pyBytes || !PyBytes_Check(pyBytes)) { goto pyfail; }
    *pcbRead = min(cb, (DWORD)PyBytes_Size(pyBytes));
    if(*pcbRead) {
        memcpy(pb, PyBytes_AsString(pyBytes), *pcbRead);
    }
    nt = *pcbRead ? VMMDLL_STATUS_SUCCESS : VMMDLL_STATUS_END_OF_FILE;
    // fall through to cleanup
pyfail:
    Py_XDECREF(args);
    Py_XDECREF(pyPid);
    Py_XDECREF(pyBytes);
    Py_XDECREF(pyPath);
    PyGILState_Release(gstate);
    return nt;
}

NTSTATUS PY2C_Callback_Write(
    _In_ VMM_HANDLE H,
    _In_ PVMMDLL_PLUGIN_CONTEXT ctxP,
    _In_reads_(cb) PBYTE pb,
    _In_ DWORD cb,
    _Out_ PDWORD pcbWrite,
    _In_ ULONG64 cbOffset
) {
    NTSTATUS nt = VMMDLL_STATUS_FILE_INVALID;
    PyObject *args = NULL, *pyLong = NULL, *pyPid = NULL, *pyPath = NULL;
    PyGILState_STATE gstate;
    CHAR uszPathBuffer[3 * MAX_PATH];
    *pcbWrite = 0;
    if(!ctxPY2C->fInitialized) { return VMMDLL_STATUS_FILE_INVALID; }
    if(!PY2C_Util_TranslatePathDelimiterU(uszPathBuffer, ctxP->uszPath)) { return VMMDLL_STATUS_FILE_INVALID; }
    gstate = PyGILState_Ensure();
    if(!(pyPath = PyUnicode_FromString(uszPathBuffer))) { goto pyfail; }
    pyPid = (ctxP->dwPID == 0xffffffff) ? NULL : PyLong_FromUnsignedLong(ctxP->dwPID);
    args = Py_BuildValue("OOy#K",
        pyPid ? pyPid : Py_None,
        pyPath,
        pb,
        cb,
        cbOffset);
    if(!args) { goto pyfail; }
    pyLong = PyObject_CallObject(ctxPY2C->fnWrite, args);
    if(!pyLong || !PyLong_Check(pyLong)) { goto pyfail; }
    nt = PyLong_AsUnsignedLong(pyLong);
    if(!nt) { *pcbWrite = cb; }
    // fall through to cleanup
pyfail:
    Py_XDECREF(args);
    Py_XDECREF(pyPid);
    Py_XDECREF(pyLong);
    Py_XDECREF(pyPath);
    PyGILState_Release(gstate);
    return nt;
}

VOID PY2C_Callback_Notify(
    _In_ VMM_HANDLE H,
    _In_ PVMMDLL_PLUGIN_CONTEXT ctxP,
    _In_ DWORD fEvent,
    _In_opt_ PVOID pvEvent,
    _In_opt_ DWORD cbEvent
) {
    PyObject *args, *pyResult = NULL;
    PyGILState_STATE gstate;
    if(!ctxPY2C->fInitialized) { return; }
    gstate = PyGILState_Ensure();
    args = Py_BuildValue("ky#", fEvent, (char *)pvEvent, cbEvent);
    if(!args) { goto pyfail; }
    pyResult = PyObject_CallObject(ctxPY2C->fnNotify, args);
    Py_DECREF(args);
    // fall through to cleanup
pyfail:
    if(pyResult) { Py_DECREF(pyResult); }
    PyGILState_Release(gstate);
}

BOOL PY2C_Callback_Close()
{
    PyObject *pyResult = NULL;
    PyGILState_STATE gstate;
    if(!ctxPY2C->fInitialized) { return FALSE; }
    gstate = PyGILState_Ensure();
    pyResult = PyObject_CallObject(ctxPY2C->fnClose, NULL);
    if(pyResult) { Py_DECREF(pyResult); }
    PyGILState_Release(gstate);
    return TRUE;
}

/*
* Execute python code and retrieve its result. This is not a normal Python API
* function and should only be called from within vmm.dll
* -- CALLER LocalFree: *puszResultOfExec
* -- H
* -- uszPythonCodeToExec
* -- puszResultOfExec
* -- return
*/
EXPORTED_FUNCTION
BOOL PY2C_Exec(_In_ VMM_HANDLE H, _In_ LPSTR uszPythonCodeToExec, _Out_ LPSTR *puszResultOfExec)
{
    BOOL result = FALSE;
    PyGILState_STATE gstate;
    PyObject *args = NULL, *pyStrResultOfExec = NULL, *pyBytesResultOfExec = NULL;
    LPSTR uszResultOfExec = NULL;
    SIZE_T cuszResultOfExec;
    if(!uszPythonCodeToExec || !puszResultOfExec) { return FALSE; }
    *puszResultOfExec = NULL;
    if(!ctxPY2C->fInitialized) { return FALSE; }
    gstate = PyGILState_Ensure();
    args = Py_BuildValue("sk", uszPythonCodeToExec, 0);
    if(!args) { goto pyfail; }
    pyStrResultOfExec = PyObject_CallObject(ctxPY2C->fnExec, args);
    if(!pyStrResultOfExec || !PyUnicode_Check(pyStrResultOfExec)) { goto pyfail; }
    pyBytesResultOfExec = PyUnicode_AsUTF8String(pyStrResultOfExec);
    if(!pyBytesResultOfExec || !PyBytes_Check(pyBytesResultOfExec)) { goto pyfail; }
    PyBytes_AsStringAndSize(pyBytesResultOfExec, &uszResultOfExec, &cuszResultOfExec);
    if(!uszResultOfExec) { goto pyfail; }
    *puszResultOfExec = LocalAlloc(0, cuszResultOfExec + 1);
    if(!*puszResultOfExec) { goto  pyfail; }
    memcpy(*puszResultOfExec, uszResultOfExec, cuszResultOfExec);
    (*puszResultOfExec)[cuszResultOfExec] = 0;
    result = TRUE;
    // fall through to cleanup
pyfail:
    Py_XDECREF(args);
    Py_XDECREF(pyBytesResultOfExec);
    Py_XDECREF(pyStrResultOfExec);
    PyGILState_Release(gstate);
    return result;
}



//-----------------------------------------------------------------------------
// PY2C common functionality below:
//-----------------------------------------------------------------------------

_Success_(return)
BOOL VmmPycPlugin_InitializeType(PyObject *pModule)
{
    static PyMethodDef PyMethods[] = {
        {"VMMPYCC_CallbackRegister", PY2C_CallbackRegister, METH_VARARGS, "Register callback functions: List, Read, Write, Close"},
        {NULL, NULL, 0, NULL}
    };
    static PyType_Slot PyTypeSlot[] = {
        {Py_tp_methods, PyMethods},
        {0, 0}
    };
    static PyType_Spec PyTypeSpec = {
        .name = "vmmpyc.VmmPycPlugin",
        .basicsize = sizeof(PyObj_VmmPycPlugin),
        .itemsize = 0,
        .flags = Py_TPFLAGS_DEFAULT,
        .slots = PyTypeSlot,
    };
    if((g_pPyType_VmmPycPlugin = PyType_FromSpec(&PyTypeSpec))) {
        if(PyModule_AddObject(pModule, "VmmPycPlugin", g_pPyType_VmmPycPlugin) < 0) {
            Py_DECREF(g_pPyType_VmmPycPlugin);
            g_pPyType_VmmPycPlugin = NULL;
        }
    }
    return g_pPyType_VmmPycPlugin ? TRUE : FALSE;
}



//-----------------------------------------------------------------------------
// CORE NATIVE MODULE FUNCTIONALITY BELOW:
//-----------------------------------------------------------------------------

/*
* Set the verbosity level of the Python C - plugin.
* Also set the verbosity level of the Python plugin manager (if already loaded).
*/
VOID VmmPyPlugin_UpdateVerbosity()
{
    ULONG64 f;
    VMMDLL_ConfigGet(g_PluginVMM, VMMDLL_OPT_CORE_PRINTF_ENABLE, &f); ctxPY2C->fPrintf = f ? TRUE : FALSE;
    if(ctxPY2C->fPrintf) {
        VMMDLL_ConfigGet(g_PluginVMM, VMMDLL_OPT_CORE_VERBOSE, &f); ctxPY2C->fVerbose = f ? TRUE : FALSE;
        VMMDLL_ConfigGet(g_PluginVMM, VMMDLL_OPT_CORE_VERBOSE_EXTRA, &f); ctxPY2C->fVerboseExtra = f ? TRUE : FALSE;
        VMMDLL_ConfigGet(g_PluginVMM, VMMDLL_OPT_CORE_VERBOSE_EXTRA_TLP, &f); ctxPY2C->fVerboseExtraTlp = f ? TRUE : FALSE;
    } else {
        ctxPY2C->fVerbose = FALSE;
        ctxPY2C->fVerboseExtra = FALSE;
        ctxPY2C->fVerboseExtraTlp = FALSE;
    }
}

#ifdef _WIN32

VOID Util_GetPathDllW(_Out_writes_(MAX_PATH) PWCHAR wszPath, _In_opt_ HMODULE hModule)
{
    SIZE_T i;
    GetModuleFileNameW(hModule, wszPath, MAX_PATH - 4);
    for(i = wcslen(wszPath) - 1; i > 0; i--) {
        if(wszPath[i] == L'/' || wszPath[i] == L'\\') {
            wszPath[i + 1] = L'\0';
            return;
        }
    }
}

VOID VmmPyPlugin_PythonInitialize_LibPath(_Out_writes_(MAX_PATH) LPWSTR wszPythonLib)
{
    WCHAR wsz[] = { 0, 0 };
    wcscpy_s(wszPythonLib, MAX_PATH, L"python3");
    wsz[0] = (WCHAR)Py_GetVersion()[2];
    wcscat_s(wszPythonLib, MAX_PATH, wsz);
    if(wsz[0] == '1') {
        wsz[0] = (WCHAR)Py_GetVersion()[3];
        wcscat_s(wszPythonLib, MAX_PATH, wsz);
    }
    wcscat_s(wszPythonLib, MAX_PATH, L".zip");
}

#define PYTHON_PATH_MAX             8*MAX_PATH
#define PYTHON_PATH_DELIMITER       L";"
BOOL VmmPyPlugin_PythonInitializeEmbedded(_In_ VMM_HANDLE H, _In_ HMODULE hDllPython, _In_ HMODULE hDllModule)
{
    PyObject *pyName = NULL, *pyModule = NULL;
    WCHAR wszPythonLib[MAX_PATH], wszPathBaseExe[MAX_PATH], wszPathBaseModule[MAX_PATH], wszPathBasePython[MAX_PATH], wszPathPython[PYTHON_PATH_MAX];
    // 0: fixup python zip version
    VmmPyPlugin_PythonInitialize_LibPath(wszPythonLib);
    // 1: Allocate context (if required) and fetch verbosity settings
    if(!ctxPY2C && !(ctxPY2C = LocalAlloc(LMEM_ZEROINIT, sizeof(PY2C_CONTEXT)))) {
        return FALSE;
    }
    VmmPyPlugin_UpdateVerbosity();
    // 2: Construct Python Path
    Util_GetPathDllW(wszPathBaseExe, NULL);
    Util_GetPathDllW(wszPathBaseModule, hDllModule);
    Util_GetPathDllW(wszPathBasePython, hDllPython);
    // 2.1: python base directory (where python dll is located)
    wcscpy_s(wszPathPython, PYTHON_PATH_MAX, wszPathBasePython);
    // 2.2: python zip
    wcscat_s(wszPathPython, PYTHON_PATH_MAX, PYTHON_PATH_DELIMITER);
    wcscat_s(wszPathPython, PYTHON_PATH_MAX, wszPathBasePython);
    wcscat_s(wszPathPython, PYTHON_PATH_MAX, wszPythonLib);
    // 2.3:  python dlls
    wcscat_s(wszPathPython, PYTHON_PATH_MAX, PYTHON_PATH_DELIMITER);
    wcscat_s(wszPathPython, PYTHON_PATH_MAX, wszPathBasePython);
    wcscat_s(wszPathPython, PYTHON_PATH_MAX, L"DLLs\\");
    // 2.4:  python lib
    wcscat_s(wszPathPython, PYTHON_PATH_MAX, PYTHON_PATH_DELIMITER);
    wcscat_s(wszPathPython, PYTHON_PATH_MAX, wszPathBasePython);
    wcscat_s(wszPathPython, PYTHON_PATH_MAX, L"Lib\\");
    // 2.5:  python lib\site-packages (python pip)
    wcscat_s(wszPathPython, PYTHON_PATH_MAX, PYTHON_PATH_DELIMITER);
    wcscat_s(wszPathPython, PYTHON_PATH_MAX, wszPathBasePython);
    wcscat_s(wszPathPython, PYTHON_PATH_MAX, L"Lib\\site-packages\\");
    // 2.6: .exe location of this process
    wcscat_s(wszPathPython, PYTHON_PATH_MAX, PYTHON_PATH_DELIMITER);
    wcscat_s(wszPathPython, PYTHON_PATH_MAX, wszPathBaseExe);
    // 2.7: module location location (vmmpyc.pyd)
    if(wcscmp(wszPathBaseExe, wszPathBaseModule)) {
        wcscat_s(wszPathPython, PYTHON_PATH_MAX, PYTHON_PATH_DELIMITER);
        wcscat_s(wszPathPython, PYTHON_PATH_MAX, wszPathBaseModule);
    }
    // 2.8: pylib relative to this process
    wcscat_s(wszPathPython, PYTHON_PATH_MAX, PYTHON_PATH_DELIMITER);
    wcscat_s(wszPathPython, PYTHON_PATH_MAX, wszPathBaseExe);
    wcscat_s(wszPathPython, PYTHON_PATH_MAX, L"pylib\\");
    // 3: Initialize (Embedded) Python.
    __try {
        Py_SetProgramName(L"VmmPyPluginManager");
        Py_SetPath(wszPathPython);
        VMMDLL_Log(H, VMMDLL_MID_PYTHON, VMMDLL_LOGLEVEL_DEBUG, "PythonPath: %S", wszPathPython);
        Py_Initialize();
        PyEval_InitThreads();
        // 4: Import VmmPyPlugin library/file to start the python part of the plugin manager.
        pyName = PyUnicode_DecodeFSDefault("vmmpyplugin");
        if(!pyName) { goto fail; }
        pyModule = PyImport_Import(pyName);
        if(!pyModule) { goto fail; }
        // 5: Cleanups
        Py_DECREF(pyName);
        Py_DECREF(pyModule);
        PyEval_SaveThread();
        return TRUE;
    } __except(EXCEPTION_EXECUTE_HANDLER) { ; }
fail:
    __try {
        if(pyName) { Py_DECREF(pyName); }
        if(pyModule) { Py_DECREF(pyModule); }
        Py_FinalizeEx();
    } __except(EXCEPTION_EXECUTE_HANDLER) { ; }
    return FALSE;
}

#endif /* _WIN32 */
#ifdef LINUX

VOID Util_GetPathDllA(_Out_writes_(MAX_PATH) LPSTR szPath, _In_opt_ HMODULE hModule)
{
    SIZE_T i;
    GetModuleFileNameA(hModule, szPath, MAX_PATH - 4);
    for(i = strlen(szPath) - 1; i > 0; i--) {
        if(szPath[i] == '/' || szPath[i] == '\\') {
            szPath[i + 1] = '\0';
            return;
        }
    }
}

#define PYTHON_IMPORT_PRE       "import sys\nsys.path.append(\""
#define PYTHON_IMPORT_POST      "\")"
BOOL VmmPyPlugin_PythonInitializeEmbedded(_In_ VMM_HANDLE H, _In_ HMODULE hDllPython, _In_ HMODULE hDllModule)
{
    DWORD i;
    PyObject *pyName = NULL, *pyModule = NULL;
    CHAR szPathBaseExe[MAX_PATH] = { 0 }, szImportBase[MAX_PATH] = { 0 } , szImportLibs[MAX_PATH] = { 0 };
    // 1: Allocate context (if required) and fetch verbosity settings
    if(!ctxPY2C && !(ctxPY2C = LocalAlloc(LMEM_ZEROINIT, sizeof(PY2C_CONTEXT)))) {
        return FALSE;
    }
    VmmPyPlugin_UpdateVerbosity();
    // 2: Construct Python Path
    Util_GetPathDllA(szPathBaseExe, NULL);
    // 2.1: .exe location of this process    
    strcat_s(szImportBase, MAX_PATH, PYTHON_IMPORT_PRE);
    strcat_s(szImportBase, MAX_PATH, szPathBaseExe);
    strcat_s(szImportBase, MAX_PATH, PYTHON_IMPORT_POST);
    // 2.2: plugins relative to this process
    strcat_s(szImportLibs, MAX_PATH, PYTHON_IMPORT_PRE);
    strcat_s(szImportLibs, MAX_PATH, szPathBaseExe);
    strcat_s(szImportLibs, MAX_PATH, "pylib/");
    strcat_s(szImportLibs, MAX_PATH, PYTHON_IMPORT_POST);
    // 3: Initialize (Embedded) Python.
    Py_SetProgramName(L"VmmPyPluginManager");   
    Py_Initialize();
    PyEval_InitThreads();
    PyRun_SimpleString(szImportBase);
    PyRun_SimpleString(szImportLibs);
    // 4: Import VmmPyPlugin library/file to start the python part of the plugin manager.
    pyName = PyUnicode_DecodeFSDefault("vmmpyplugin");
    if(!pyName) { goto fail; }
    pyModule = PyImport_Import(pyName);
    if(!pyModule) { goto fail; }
    // 5: Cleanups
    Py_DECREF(pyName);
    Py_DECREF(pyModule);
    PyEval_SaveThread();
    return TRUE;
fail:
    if(pyName) { Py_DECREF(pyName); }
    if(pyModule) { Py_DECREF(pyModule); }
    Py_FinalizeEx();
    return FALSE;
}

#endif /* LINUX */

BOOL VmmPyPlugin_PythonInitializeStandalone()
{
    PyGILState_STATE gstate = PyGILState_LOCKED;
    PyObject *pyName1 = NULL, *pyName2 = NULL, *pyModule = NULL;
    // 1: Allocate context (if required) and fetch verbosity settings
    if(!ctxPY2C && !(ctxPY2C = LocalAlloc(LMEM_ZEROINIT, sizeof(PY2C_CONTEXT)))) {
        return FALSE;
    }
    VmmPyPlugin_UpdateVerbosity();
    // 2: Initialize (Standalone) Python.
    __try {
        gstate = PyGILState_Ensure();
        pyName1 = PyUnicode_DecodeFSDefault("vmmpyplugin");
        pyName2 = PyUnicode_DecodeFSDefault("memprocfs.vmmpyplugin");
        if(!pyName1 || !pyName2) { goto fail; }
        if(!(pyModule = PyImport_Import(pyName2))) {
            PyErr_Clear();
            pyModule = PyImport_Import(pyName1);
        }
        if(!pyModule) { goto fail; }
        PyGILState_Release(gstate);
        return TRUE;
    } __except(EXCEPTION_EXECUTE_HANDLER) { ; }
fail:
    __try {
        if(pyName1) { Py_DECREF(pyName1); }
        if(pyName2) { Py_DECREF(pyName2); }
        if(pyModule) { Py_DECREF(pyModule); }
        if(gstate == PyGILState_UNLOCKED) {
            PyErr_Clear();
            PyGILState_Release(gstate);
        }
    } __except(EXCEPTION_EXECUTE_HANDLER) { }
    return FALSE;
}

BOOL VmmPyPlugin_PythonInitialize(_In_ VMM_HANDLE H, _In_ HMODULE hDllPython, _In_ HMODULE hDllModule, _In_ BOOL fPythonStandalone)
{
    BOOL f;
    if(g_PluginVMM) { return FALSE; }
    g_PluginVMM = H;
    g_fPythonStandalone = fPythonStandalone;
    f = fPythonStandalone ?
        VmmPyPlugin_PythonInitializeStandalone() :
        VmmPyPlugin_PythonInitializeEmbedded(H, hDllPython, hDllModule);
    if(!f) { g_PluginVMM = NULL; }
    return f;
}

VOID PYTHON_Close(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_CONTEXT ctx)
{
    __try {
        PY2C_Callback_Close();
    } __except(EXCEPTION_EXECUTE_HANDLER) { ; }
    if(!g_fPythonStandalone) {
        __try {
            PyGILState_Ensure();
            Py_FinalizeEx();
        } __except(EXCEPTION_EXECUTE_HANDLER) { ; }
    }
    g_PluginVMM = NULL;
}

/*
* Initialization function for the python native plugin.
* It's important that the function is exported in the DLL and that it is
* declared exactly as below. The plugin manager will call into this function
* after the DLL is loaded. The DLL then must fill the appropriate information
* into the supplied struct and call the pfnPluginManager_Register function to
* register itself with the plugin manager.
* -- H
* -- pRegInfo
*/
EXPORTED_FUNCTION
VOID InitializeVmmPlugin(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_REGINFO pRegInfo)
{
    if(g_PluginVMM) { return; }
    if((pRegInfo->magic != VMMDLL_PLUGIN_REGINFO_MAGIC) || (pRegInfo->wVersion != VMMDLL_PLUGIN_REGINFO_VERSION)) { return; }
    if(VmmPyPlugin_PythonInitialize(H, pRegInfo->python.hReservedDllPython3X, pRegInfo->hDLL, pRegInfo->python.fPythonStandalone)) {
        strcpy_s(pRegInfo->reg_info.uszPathName, 128, "py");    // module name - 'py'.
        pRegInfo->reg_info.fRootModule = TRUE;                  // module shows in root directory.
        pRegInfo->reg_info.fProcessModule = TRUE;               // module shows in process directory.
        pRegInfo->reg_fn.pfnList = PY2C_Callback_List;          // List function supported.
        pRegInfo->reg_fn.pfnRead = PY2C_Callback_Read;          // Read function supported.
        pRegInfo->reg_fn.pfnWrite = PY2C_Callback_Write;        // Write function supported.
        pRegInfo->reg_fn.pfnNotify = PY2C_Callback_Notify;      // Notify function supported.
        pRegInfo->reg_fn.pfnClose = PYTHON_Close;               // Close module handle.
        pRegInfo->pfnPluginManager_Register(H, pRegInfo);       // Register with the plugin maanger.
    }
}
