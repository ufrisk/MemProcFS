// oscompatibility.c : VMM Windows/Linux compatibility layer.
//
// (c) Ulf Frisk, 2021-2023
// Author: Ulf Frisk, pcileech@frizk.net
//
#ifdef LINUX

#include "vmmpyc.h"
#include <link.h>
#include <dlfcn.h>

// ----------------------------------------------------------------------------
// LocalAlloc/LocalFree BELOW:
// ----------------------------------------------------------------------------

HANDLE LocalAlloc(DWORD uFlags, SIZE_T uBytes)
{
    HANDLE h = malloc(uBytes);
    if(h && (uFlags & LMEM_ZEROINIT)) {
        memset(h, 0, uBytes);
    }
    return h;
}

VOID LocalFree(HANDLE hMem)
{
    free(hMem);
}



// ----------------------------------------------------------------------------
// OTHER FUNCTIONALITY BELOW:
// ----------------------------------------------------------------------------

BOOL FileTimeToSystemTime(_In_ PFILETIME lpFileTime, _Out_ PSYSTEMTIME pSystemTime)
{
    time_t tm = 0;
    struct tm t = { 0 };
    if(*lpFileTime >= 116444736000000000ULL) {
        tm = (*lpFileTime - 116444736000000000ULL) / 10000000ULL;
    }
    gmtime_r(&tm, &t);
    pSystemTime->wYear = 1900 + t.tm_year;
    pSystemTime->wMonth = 1 + t.tm_mon;
    pSystemTime->wDayOfWeek = t.tm_wday;
    pSystemTime->wDay = t.tm_mday;
    pSystemTime->wHour = t.tm_hour;
    pSystemTime->wMinute = t.tm_min;
    pSystemTime->wSecond = t.tm_sec;
    pSystemTime->wMilliseconds = (*lpFileTime / 10000) % 1000;
    return TRUE;
}

DWORD GetModuleFileNameA(_In_opt_ HMODULE hModule, _Out_ LPSTR lpFilename, _In_ DWORD nSize)
{
    struct link_map *lm = NULL;
    if(hModule) {
        dlinfo(hModule, RTLD_DI_LINKMAP, &lm);
        if(lm) {
            strncpy(lpFilename, lm->l_name, nSize);
            lpFilename[nSize - 1] = 0;
            return strlen(lpFilename);
        }
    }
    return readlink("/proc/self/exe", lpFilename, nSize);
}



// ----------------------------------------------------------------------------
// GENERAL HANDLES BELOW:
// ----------------------------------------------------------------------------

#define OSCOMPATIBILITY_HANDLE_INTERNAL         0x35d91cca
#define OSCOMPATIBILITY_HANDLE_TYPE_THREAD      2
#define OSCOMPATIBILITY_HANDLE_TYPE_EVENT       3

typedef struct tdHANDLE_INTERNAL {
    DWORD magic;
    DWORD type;
} HANDLE_INTERNAL, *PHANDLE_INTERNAL;

typedef struct tdHANDLE_INTERNAL_THREAD {
    DWORD magic;
    DWORD type;
    pthread_t thread;
} HANDLE_INTERNAL_THREAD, *PHANDLE_INTERNAL_THREAD;

BOOL CloseHandle(_In_ HANDLE hObject)
{
    PHANDLE_INTERNAL hi = (PHANDLE_INTERNAL)hObject;
    if(hi->magic != OSCOMPATIBILITY_HANDLE_INTERNAL) { return FALSE; }
    switch(hi->type) {
        case OSCOMPATIBILITY_HANDLE_TYPE_THREAD:
            pthread_join(((PHANDLE_INTERNAL_THREAD)hi)->thread, NULL);
            break;
        default:
            break;
    }
    LocalFree(hi);
    return TRUE;
}



// ----------------------------------------------------------------------------
// THREAD FUNCTIONALITY:
// ----------------------------------------------------------------------------

HANDLE CreateThread(
    PVOID     lpThreadAttributes,
    SIZE_T    dwStackSize,
    PVOID     lpStartAddress,
    PVOID     lpParameter,
    DWORD     dwCreationFlags,
    PDWORD    lpThreadId
) {
    PHANDLE_INTERNAL_THREAD ph;
    pthread_t thread;
    int status;
    status = pthread_create(&thread, NULL, lpStartAddress, lpParameter);
    if(status) { return NULL; }
    ph = malloc(sizeof(HANDLE_INTERNAL_THREAD));
    if(!ph) { return NULL; }
    ph->magic = OSCOMPATIBILITY_HANDLE_INTERNAL;
    ph->type = OSCOMPATIBILITY_HANDLE_TYPE_THREAD;
    ph->thread = thread;
    return (HANDLE)ph;
}

#endif /* LINUX */
