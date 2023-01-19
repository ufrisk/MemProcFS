// vmmpyc_util.c : various utility functions used.
//
// (c) Ulf Frisk, 2021-2023
// Author: Ulf Frisk, pcileech@frizk.net
//
#include "vmmpyc.h"

VOID Util_FileTime2String(_In_ QWORD ft, _Out_writes_(24) LPSTR szTime)
{
    SYSTEMTIME SystemTime;
    if(!ft || (ft > 0x0200000000000000)) {
        strcpy_s(szTime, 24, "                    ***");
        return;
    }
    FileTimeToSystemTime((PFILETIME)&ft, &SystemTime);
    sprintf_s(
        szTime,
        24,
        "%04i-%02i-%02i %02i:%02i:%02i UTC",
        SystemTime.wYear,
        SystemTime.wMonth,
        SystemTime.wDay,
        SystemTime.wHour,
        SystemTime.wMinute,
        SystemTime.wSecond
    );
}

LPSTR Util_PathSplitLastU(_In_ LPSTR usz)
{
    LPSTR uszResult = usz;
    CHAR ch;
    DWORD i = 0;
    while(TRUE) {
        ch = usz[i++];
        if(ch == '\0') {
            return uszResult;
        }
        if(ch == '\\') {
            uszResult = usz + i;
        }
    }
}

/*
* Split the string usz into two at the last (back)slash which is removed.
* Ex: usz: XXX/YYY/ZZZ/AAA -> uszPath: XXX/YYY/ZZZ + return: AAA
* -- usz = utf-8 or ascii string.
* -- uszPath = buffer to receive result.
* -- cbuPath = byte length of uszPath buffer
* -- return
*/
LPSTR Util_PathSplitLastEx(_In_ LPSTR usz, _Out_writes_(cbuPath) LPSTR uszPath, _In_ DWORD cbuPath)
{
    DWORD i, iSlash = -1;
    CHAR ch = -1;
    if(!cbuPath) { return NULL; }
    for(i = 0; ch && i < cbuPath; i++) {
        ch = usz[i];
        uszPath[i] = ch;
        if((ch == '\\') || (ch == '/')) {
            iSlash = i;
        }
    }
    uszPath[cbuPath - 1] = 0;
    if(iSlash == 0xffffffff) { return NULL; }
    uszPath[iSlash] = 0;
    return uszPath + iSlash + 1;
}

int PyDict_SetItemDWORD_DECREF(PyObject *dp, DWORD key, PyObject *item)
{
    PyObject *pyObjectKey = PyLong_FromUnsignedLong(key);
    int i = PyDict_SetItem(dp, pyObjectKey, item);
    Py_XDECREF(pyObjectKey);
    Py_XDECREF(item);
    return i;
}

int PyDict_SetItemQWORD_DECREF(PyObject *dp, QWORD key, PyObject *item)
{
    PyObject *pyObjectKey = PyLong_FromUnsignedLongLong(key);
    int i = PyDict_SetItem(dp, pyObjectKey, item);
    Py_XDECREF(pyObjectKey);
    Py_XDECREF(item);
    return i;
}

int PyDict_SetItemString_DECREF(PyObject *dp, const char *key, PyObject *item)
{
    int i = PyDict_SetItemString(dp, key, item);
    Py_XDECREF(item);
    return i;
}

int PyDict_SetItemUnicode_DECREF(PyObject *dp, PyObject *key_nodecref, PyObject *item)
{
    int i = PyDict_SetItem(dp, key_nodecref, item);
    Py_XDECREF(item);
    return i;
}

int PyList_Append_DECREF(PyObject *dp, PyObject *item)
{
    int i = PyList_Append(dp, item);
    Py_XDECREF(item);
    return i;
}
