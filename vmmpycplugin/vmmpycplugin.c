// vmmpycplugin.c : implementation related to the python wrapper native plugin
// for the memory process file system. NB! this is a special plugin since it's
// not residing in the plugin directory.
//
// (c) Ulf Frisk, 2018-2019
// Author: Ulf Frisk, pcileech@frizk.net
//
#define Py_LIMITED_API 0x03060000
#ifdef _DEBUG
#undef _DEBUG
#include <python.h>
#define _DEBUG
#else
#include <python.h>
#endif
#include <Windows.h>
#include <stdio.h>
#include "vmmdll.h"


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
} PY2C_CONTEXT, *PPY2C_CONTEXT;

PPY2C_CONTEXT ctxPY2C = NULL;

static PyObject*
PY2C_CallbackRegister(PyObject *self, PyObject *args)
{
    if(!ctxPY2C->fInitialized) {
        Py_XDECREF(ctxPY2C->fnList);
        Py_XDECREF(ctxPY2C->fnRead);
        Py_XDECREF(ctxPY2C->fnWrite);
		Py_XDECREF(ctxPY2C->fnNotify);
        Py_XDECREF(ctxPY2C->fnClose);
        if(!PyArg_ParseTuple(args, "OOOOO", &ctxPY2C->fnList, &ctxPY2C->fnRead, &ctxPY2C->fnWrite, &ctxPY2C->fnNotify, &ctxPY2C->fnClose)) { return NULL; }
        Py_XINCREF(ctxPY2C->fnList);
        Py_XINCREF(ctxPY2C->fnRead);
        Py_XINCREF(ctxPY2C->fnWrite);
		Py_XINCREF(ctxPY2C->fnNotify);
        Py_XINCREF(ctxPY2C->fnClose);
        ctxPY2C->fInitialized = TRUE;
    }
    return Py_BuildValue("s", NULL);    // None returned on success.
}

BOOL PY2C_Util_TranslatePathDelimiter(_Out_writes_(MAX_PATH) PCHAR dst, LPSTR src)
{
    DWORD i;
    for(i = 0; i < MAX_PATH; i++) {
        dst[i] = (src[i] == '\\') ? '/' : src[i];
        if(src[i] == 0) { return TRUE; }
    }
    return FALSE;
}

BOOL PY2C_Callback_List(_In_ PVMMDLL_PLUGIN_CONTEXT ctx, _Inout_ PHANDLE pFileList)
{
    BOOL result = FALSE;
    PyObject *args, *pyList = NULL, *pyDict, *pyPid;
    PyObject *pyDict_Name, *pyDict_Size, *pyDict_IsDir;
    PyObject *pyDict_Name_Bytes;
    PyGILState_STATE gstate;
    SIZE_T i, cList;
    CHAR szPathBuffer[MAX_PATH];
    if(!ctxPY2C->fInitialized) { return FALSE; }
    if(!PY2C_Util_TranslatePathDelimiter(szPathBuffer, ctx->szPath)) { return FALSE; }
    gstate = PyGILState_Ensure();
    // pyPid is "consumed" by Py_BuildValue and does not need to be Py_DECREF'ed.
    if(ctx->dwPID == (DWORD)-1) {
        Py_INCREF(Py_None);
        pyPid = Py_None;
    } else {
        pyPid = PyLong_FromUnsignedLong(ctx->dwPID);
    }
    args = Py_BuildValue("Ns", pyPid, szPathBuffer);
    if(!args) { goto fail; }
    pyList = PyObject_CallObject(ctxPY2C->fnList, args);
    Py_DECREF(args);
    if(!pyList || !PyList_Check(pyList)) { goto fail; }
    cList = PyList_Size(pyList);
    for(i = 0; i < cList; i++) {
        pyDict = PyList_GetItem(pyList, i); // borrowed reference
        if(!PyDict_Check(pyDict)) { continue; }
        pyDict_Name = PyDict_GetItemString(pyDict, "name");
        pyDict_Size = PyDict_GetItemString(pyDict, "size");
        pyDict_IsDir = PyDict_GetItemString(pyDict, "f_isdir");
        if(!pyDict_Name || !PyUnicode_Check(pyDict_Name) || !pyDict_IsDir || !PyBool_Check(pyDict_IsDir)) { continue; }
        pyDict_Name_Bytes = PyUnicode_AsEncodedString(pyDict_Name, NULL, NULL);
        if(pyDict_Name_Bytes) {
            if(pyDict_IsDir == Py_True) {
                VMMDLL_VfsList_AddDirectory(pFileList, PyBytes_AsString(pyDict_Name_Bytes));
            } else {
                if(!pyDict_Size || !PyLong_Check(pyDict_Size)) { continue; }
                VMMDLL_VfsList_AddFile(pFileList, PyBytes_AsString(pyDict_Name_Bytes), PyLong_AsUnsignedLongLong(pyDict_Size));
            }
            Py_DECREF(pyDict_Name_Bytes);
        }
    }
    result = TRUE;
    // fall through to cleanup
fail:
    if(pyList) { Py_DECREF(pyList); }
    PyGILState_Release(gstate);
    return result;
}

NTSTATUS PY2C_Callback_Read(_In_ PVMMDLL_PLUGIN_CONTEXT ctx, _Out_ LPVOID pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ ULONG64 cbOffset)
{
    NTSTATUS nt = VMMDLL_STATUS_FILE_INVALID;
    PyObject *args, *pyBytes = NULL, *pyPid;
    PyGILState_STATE gstate;
    CHAR szPathBuffer[MAX_PATH];
    if(!ctxPY2C->fInitialized) { return FALSE; }
    if(!PY2C_Util_TranslatePathDelimiter(szPathBuffer, ctx->szPath)) { return FALSE; }
    gstate = PyGILState_Ensure();
    // pyPid is "consumed" by Py_BuildValue and does not need to be Py_DECREF'ed.
    if(ctx->dwPID == (DWORD)-1) {
        Py_INCREF(Py_None);
        pyPid = Py_None;
    } else {
        pyPid = PyLong_FromUnsignedLong(ctx->dwPID);
    }
    args = Py_BuildValue("NskK",
        pyPid,
        szPathBuffer,
        cb,
        cbOffset);
    if(!args) { goto fail; }
    pyBytes = PyObject_CallObject(ctxPY2C->fnRead, args);
    Py_DECREF(args);
    if(!pyBytes || !PyBytes_Check(pyBytes)) { goto fail; }
    *pcbRead = min(cb, (DWORD)PyBytes_Size(pyBytes));
    if(*pcbRead) {
        memcpy(pb, PyBytes_AsString(pyBytes), *pcbRead);
    }
    nt = *pcbRead ? VMMDLL_STATUS_SUCCESS : VMMDLL_STATUS_END_OF_FILE;
    // fall through to cleanup
fail:
    if(pyBytes) { Py_DECREF(pyBytes); }
    PyGILState_Release(gstate);
    return nt;
}

NTSTATUS PY2C_Callback_Write(_In_ PVMMDLL_PLUGIN_CONTEXT ctx, _In_ LPVOID pb, _In_ DWORD cb, _Out_ PDWORD pcbWrite, _In_ ULONG64 cbOffset)
{
    NTSTATUS nt = VMMDLL_STATUS_FILE_INVALID;
    PyObject *args, *pyLong = NULL, *pyPid;
    PyGILState_STATE gstate;
    CHAR szPathBuffer[MAX_PATH];
    *pcbWrite = 0;
    if(!ctxPY2C->fInitialized) { return VMMDLL_STATUS_FILE_INVALID; }
    if(!PY2C_Util_TranslatePathDelimiter(szPathBuffer, ctx->szPath)) { return VMMDLL_STATUS_FILE_INVALID; }
    gstate = PyGILState_Ensure();
    // pyPid is "consumed" by Py_BuildValue and does not need to be Py_DECREF'ed.
    if(ctx->dwPID == (DWORD)-1) {
        Py_INCREF(Py_None);
        pyPid = Py_None;
    } else {
        pyPid = PyLong_FromUnsignedLong(ctx->dwPID);
    }
    args = Py_BuildValue("Nsy#K",
        pyPid,
        szPathBuffer,
        pb,
        cb,
        cbOffset);
    if(!args) { goto fail; }
    pyLong = PyObject_CallObject(ctxPY2C->fnWrite, args);
    Py_DECREF(args);
    if(!pyLong || !PyLong_Check(pyLong)) { goto fail; }
    nt = PyLong_AsUnsignedLong(pyLong);
    if(!nt) { *pcbWrite = cb; }
    // fall through to cleanup
fail:
    if(pyLong) { Py_DECREF(pyLong); }
    PyGILState_Release(gstate);
    return nt;
}

VOID PY2C_Callback_Notify(_In_ DWORD fEvent, _In_opt_ PVOID pvEvent, _In_opt_ DWORD cbEvent)
{
    PyObject *args, *pyResult = NULL;
    PyGILState_STATE gstate;
    if(!ctxPY2C->fInitialized) { return; }
    gstate = PyGILState_Ensure();
    args = Py_BuildValue("ky#", fEvent, (char*)pvEvent, cbEvent);
    if(!args) { goto fail; }
    pyResult = PyObject_CallObject(ctxPY2C->fnNotify, args);
    Py_DECREF(args);
    // fall through to cleanup
fail:
    if(pyResult) { Py_DECREF(pyResult); }
    PyGILState_Release(gstate);
}

BOOL PY2C_Callback_Close()
{
    NTSTATUS nt = VMMDLL_STATUS_FILE_INVALID;
    PyObject *args, *pyResult = NULL;
    PyGILState_STATE gstate;
    if(!ctxPY2C->fInitialized) { return FALSE; }
    gstate = PyGILState_Ensure();
    args = Py_BuildValue("");
    if(!args) { goto fail; }
    pyResult = PyObject_CallObject(ctxPY2C->fnClose, args);
    Py_DECREF(args);
    // fall through to cleanup
fail:
    if(pyResult) { Py_DECREF(pyResult); }
    PyGILState_Release(gstate);
    return nt;
}

//-----------------------------------------------------------------------------
// PY2C common functionality below:
//-----------------------------------------------------------------------------

static PyMethodDef VMMPYCC_EmbMethods[] = {
    {"VMMPYCC_CallbackRegister", PY2C_CallbackRegister, METH_VARARGS, "Register callback functions: List, Read, Write, Close"},
    {NULL, NULL, 0, NULL}
};

static PyModuleDef VMMPYCC_EmbModule = {
    PyModuleDef_HEAD_INIT, "vmmpycc", NULL, -1, VMMPYCC_EmbMethods,
    NULL, NULL, NULL, NULL
};

static PyObject* VMMPYCC_PyInit(void)
{
    return PyModule_Create(&VMMPYCC_EmbModule);
}

void PY2C_InitializeModuleVMMPYCC()
{
    PyImport_AppendInittab("vmmpycc", &VMMPYCC_PyInit);
}


//-----------------------------------------------------------------------------
// CORE NATIVE MODULE FUNCTIONALITY BELOW:
//-----------------------------------------------------------------------------

VOID Util_GetPathDll(_Out_writes_(MAX_PATH) PWCHAR wszPath, _In_opt_ HMODULE hModule)
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

/*
* Set the verbosity level of the Python C - plugin.
* Also set the verbosity level of the Python plugin manager (if already loaded).
*/
VOID VmmPyPlugin_UpdateVerbosity()
{
	ULONG64 f;
	VMMDLL_ConfigGet(VMMDLL_OPT_CORE_PRINTF_ENABLE, &f); ctxPY2C->fPrintf = f ? TRUE : FALSE;
	if(ctxPY2C->fPrintf) {
		VMMDLL_ConfigGet(VMMDLL_OPT_CORE_VERBOSE, &f); ctxPY2C->fVerbose = f ? TRUE : FALSE;
		VMMDLL_ConfigGet(VMMDLL_OPT_CORE_VERBOSE_EXTRA, &f); ctxPY2C->fVerboseExtra = f ? TRUE : FALSE;
		VMMDLL_ConfigGet(VMMDLL_OPT_CORE_VERBOSE_EXTRA_TLP, &f); ctxPY2C->fVerboseExtraTlp = f ? TRUE : FALSE;
	} else {
		ctxPY2C->fVerbose = FALSE;
		ctxPY2C->fVerboseExtra = FALSE;
		ctxPY2C->fVerboseExtraTlp = FALSE;
	}
}

#define PYTHON_PATH_MAX             7*MAX_PATH
#define PYTHON_PATH_DELIMITER       L";"
BOOL VmmPyPlugin_PythonInitialize(_In_ HMODULE hDllPython)
{
    PyObject *pName = NULL, *pModule = NULL;
    WCHAR wszPathBaseExe[MAX_PATH], wszPathBasePython[MAX_PATH], wszPathPython[PYTHON_PATH_MAX];
    WCHAR wszPythonLib[] = { L'p', L'y', L't', L'h', L'o', L'n', L'3', L'6', L'.', L'z', L'i', L'p', 0 };
    // 0: fixup python zip version
    wszPythonLib[6] = (WCHAR)Py_GetVersion()[0];
    wszPythonLib[7] = (WCHAR)Py_GetVersion()[2];
    // 1: Allocate context (if required) and fetch verbosity settings
    if(!ctxPY2C && !(ctxPY2C = LocalAlloc(LMEM_ZEROINIT, sizeof(PY2C_CONTEXT)))) {
        return FALSE;
    }
	VmmPyPlugin_UpdateVerbosity();
    // 2: Construct Python Path
    Util_GetPathDll(wszPathBaseExe, NULL);
    Util_GetPathDll(wszPathBasePython, hDllPython);
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
    // 2.7: pylib relative to this process
    wcscat_s(wszPathPython, PYTHON_PATH_MAX, PYTHON_PATH_DELIMITER);
    wcscat_s(wszPathPython, PYTHON_PATH_MAX, wszPathBaseExe);
    wcscat_s(wszPathPython, PYTHON_PATH_MAX, L"pylib\\");
    // 3: Initialize (Embedded) Python.
    Py_SetProgramName(L"VmmPyPluginManager");
    Py_SetPath(wszPathPython);
    if(ctxPY2C->fVerboseExtra) {
        wprintf(L"VmmPyPluginManager: Python Path: %s\n", wszPathPython);
    }
    PY2C_InitializeModuleVMMPYCC();
    Py_Initialize();
    PyEval_InitThreads();
    // 4: Import VmmPyPlugin library/file to start the python part of the plugin manager.
    pName = PyUnicode_DecodeFSDefault("vmmpyplugin");
    if(!pName) { goto fail; }
    pModule = PyImport_Import(pName);
    if(!pModule) { goto fail; }
    // 5: Cleanups
    Py_DECREF(pName);
    Py_DECREF(pModule);
    PyEval_ReleaseLock();
    return TRUE;
fail:
    if(pName) { Py_DECREF(pName); }
    if(pModule) { Py_DECREF(pModule); }
    Py_FinalizeEx();
    return FALSE;
}

VOID PYTHON_Close()
{
    PY2C_Callback_Close();
    Py_FinalizeEx();
}

/*
* Initialization function for the vmemd native plugin module.
* It's important that the function is exported in the DLL and that it is
* declared exactly as below. The plugin manager will call into this function
* after the DLL is loaded. The DLL then must fill the appropriate information
* into the supplied struct and call the pfnPluginManager_Register function to
* register itself with the plugin manager.
* -- pRegInfo
*/
__declspec(dllexport)
VOID InitializeVmmPlugin(_In_ PVMMDLL_PLUGIN_REGINFO pRegInfo)
{
    if((pRegInfo->magic != VMMDLL_PLUGIN_REGINFO_MAGIC) || (pRegInfo->wVersion != VMMDLL_PLUGIN_REGINFO_VERSION)) { return; }
    if(VmmPyPlugin_PythonInitialize(pRegInfo->hReservedDllPython3X)) {
        strcpy_s(pRegInfo->reg_info.szModuleName, 32, "py");    // module name - 'py'.
        pRegInfo->reg_info.fRootModule = TRUE;                  // module shows in root directory.
        pRegInfo->reg_info.fProcessModule = TRUE;               // module shows in process directory.
        pRegInfo->reg_fn.pfnList = PY2C_Callback_List;          // List function supported.
        pRegInfo->reg_fn.pfnRead = PY2C_Callback_Read;          // Read function supported.
        pRegInfo->reg_fn.pfnWrite = PY2C_Callback_Write;        // Write function supported.
        pRegInfo->reg_fn.pfnNotify = PY2C_Callback_Notify;      // Notify function supported.
        pRegInfo->reg_fn.pfnClose = PYTHON_Close;               // Close module handle.
        pRegInfo->pfnPluginManager_Register(pRegInfo);          // Register with the plugin maanger.
    }
}
