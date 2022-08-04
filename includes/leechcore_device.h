// leechcore_device.h : external header file to be used by LeechCore plug-in
//                      modules implemented as separate libraries.
//
// A LeechCore device plugin module must be placed alongside leechcore.[dll|so]
// and follow the naming convention leechcore_device_xxxx.[dll|so] where xxxx
// is the name of the device.
//
// The DLL load function must not initialize the device itself or do anything
// special that may take time to perform - since the plugin module will always
// be loaded even if not used.
//
// The plugin module must implement and export the open function:
// BOOL LcPluginCreate(_In_ PLC_CONTEXT ctx);
// The LcPluginCreate() function will be called whenever a new instance of the
// device may be created/opened - if only one instance may be open at the same
// time this should be handled by the plugin module itself.
//
// (c) Ulf Frisk, 2020-2022
// Author: Ulf Frisk, pcileech@frizk.net
//
// Header Version: 2.5
//

#ifndef __LEECHCORE_DEVICE_H__
#define __LEECHCORE_DEVICE_H__
#include <stdio.h>
#include "leechcore.h"

#ifdef LINUX
#include <string.h>
#include <pthread.h>
#ifndef _LINUX_DEF_CRITICAL_SECTION
#define _LINUX_DEF_CRITICAL_SECTION
typedef struct tdCRITICAL_SECTION {
    pthread_mutex_t mutex;
    pthread_mutexattr_t mta;
} CRITICAL_SECTION, *LPCRITICAL_SECTION;
#endif /* _LINUX_DEF_CRITICAL_SECTION */
#endif /* LINUX */

#define LC_CONTEXT_VERSION                  0xc0e10004
#define LC_DEVICE_PARAMETER_MAX_ENTRIES     0x10

typedef struct tdLC_DEVICE_PARAMETER_ENTRY {
    CHAR szName[MAX_PATH];
    CHAR szValue[MAX_PATH];
    QWORD qwValue;
} LC_DEVICE_PARAMETER_ENTRY, *PLC_DEVICE_PARAMETER_ENTRY;

typedef struct tdLC_CONTEXT LC_CONTEXT, *PLC_CONTEXT;

typedef struct tdLC_READ_CONTIGIOUS_CONTEXT {
    PLC_CONTEXT ctxLC;
    HANDLE hEventWakeup;
    HANDLE hEventFinish;
    HANDLE hThread;
    DWORD iRL;
    DWORD cMEMs;
    PPMEM_SCATTER ppMEMs;
    QWORD paBase;
    DWORD cbRead;
    DWORD cb;
    BYTE pb[0];
} LC_READ_CONTIGIOUS_CONTEXT, *PLC_READ_CONTIGIOUS_CONTEXT;

#define LC_PRINTF_ENABLE            0
#define LC_PRINTF_V                 1
#define LC_PRINTF_VV                2
#define LC_PRINTF_VVV               3

typedef struct tdLC_CONTEXT {
    DWORD version;                  // LC_CONTEXT_VERSION
    DWORD dwHandleCount;
    HANDLE FLink;
    union {
        CRITICAL_SECTION Lock;
        BYTE _PadLinux[48];
    };
    QWORD cReadScatterMEM;
    LC_STATISTICS CallStat;
    HANDLE hDeviceModule;
    BOOL(*pfnCreate)(_Inout_ PLC_CONTEXT ctxLC, _Out_opt_ PPLC_CONFIG_ERRORINFO ppLcCreateErrorInfo);
    // Config for use by devices below:
    LC_CONFIG Config;
    DWORD cDeviceParameter;
    LC_DEVICE_PARAMETER_ENTRY pDeviceParameter[LC_DEVICE_PARAMETER_MAX_ENTRIES];
    BOOL fWritable;         // deprecated - do not use!
    BOOL fPrintf[4];
    HANDLE hDevice;
    BOOL fMultiThread;
    VOID(*pfnReadScatter)(_In_ PLC_CONTEXT ctxLC, _In_ DWORD cpMEMs, _Inout_ PPMEM_SCATTER ppMEMs);
    VOID(*pfnReadContigious)(_Inout_ PLC_READ_CONTIGIOUS_CONTEXT ctxReadContigious);
    VOID(*pfnWriteScatter)(_In_ PLC_CONTEXT ctxLC, _In_ DWORD cpMEMs, _Inout_ PPMEM_SCATTER ppMEMs);
    BOOL(*pfnWriteContigious)(_In_ PLC_CONTEXT ctxLC, _In_ QWORD pa, _In_ DWORD cb, _In_reads_(cb) PBYTE pb);
    BOOL(*pfnGetOption)(_In_ PLC_CONTEXT ctxLC, _In_ QWORD fOption, _Out_ PQWORD pqwValue);
    BOOL(*pfnSetOption)(_In_ PLC_CONTEXT ctxLC, _In_ QWORD fOption, _In_ QWORD qwValue);
    BOOL(*pfnCommand)(_In_ PLC_CONTEXT ctxLC, _In_ QWORD fOption, _In_ DWORD cbDataIn, _In_reads_opt_(cbDataIn) PBYTE pbDataIn, _Out_opt_ PBYTE *ppbDataOut, _Out_opt_ PDWORD pcbDataOut);
    VOID(*pfnClose)(_Inout_ PLC_CONTEXT ctxLC);
    struct {
        DWORD cThread;
        DWORD cbChunkSize;
        BOOL fLoadBalance;
    } ReadContigious;
    // Internal ReadContigious functionality:
    struct {
        BOOL fActive;
        HANDLE hEventFinish[8];
        PLC_READ_CONTIGIOUS_CONTEXT ctx[8];
    } RC;
    // MemMap functionality:
    DWORD cMemMap;
    DWORD cMemMapMax;
    PLC_MEMMAP_ENTRY pMemMap;
    // Remote functionality:
    struct {
        BOOL fCompress;
        DWORD dwRpcClientId;
    } Rpc;
} LC_CONTEXT, *PLC_CONTEXT;

/*
* Retrieve a device parameter by its name (if exists).
* -- ctxLc
* -- szName
* -- return
*/
EXPORTED_FUNCTION PLC_DEVICE_PARAMETER_ENTRY LcDeviceParameterGet(_In_ PLC_CONTEXT ctxLC, _In_ LPSTR szName);

/*
* Retrieve the numeric value of a device parameter (if exists).
* -- ctxLc
* -- szName
* -- return = the numeric value of the device parameter - 0 on fail.
*/
EXPORTED_FUNCTION QWORD LcDeviceParameterGetNumeric(_In_ PLC_CONTEXT ctxLC, _In_ LPSTR szName);

#define lcprintf(ctxLC, _Format, ...)        { if(ctxLC->fPrintf[0]) { ctxLC->Config.pfn_printf_opt ? ctxLC->Config.pfn_printf_opt(_Format, ##__VA_ARGS__) : printf(_Format, ##__VA_ARGS__); } }
#define lcprintfv(ctxLC, _Format, ...)       { if(ctxLC->fPrintf[1]) { lcprintf(ctxLC, _Format, ##__VA_ARGS__); } }
#define lcprintfvv(ctxLC, _Format, ...)      { if(ctxLC->fPrintf[2]) { lcprintf(ctxLC, _Format, ##__VA_ARGS__); } }
#define lcprintfvvv(ctxLC, _Format, ...)     { if(ctxLC->fPrintf[3]) { lcprintf(ctxLC, _Format, ##__VA_ARGS__); } }
#define lcprintf_fn(ctxLC, _Format, ...)     { if(ctxLC->fPrintf[0]) { lcprintf(ctxLC, "%s: "_Format, __func__, ##__VA_ARGS__); } }
#define lcprintfv_fn(ctxLC, _Format, ...)    { if(ctxLC->fPrintf[1]) { lcprintf(ctxLC, "%s: "_Format, __func__, ##__VA_ARGS__); } }
#define lcprintfvv_fn(ctxLC, _Format, ...)   { if(ctxLC->fPrintf[2]) { lcprintf(ctxLC, "%s: "_Format, __func__, ##__VA_ARGS__); } }
#define lcprintfvvv_fn(ctxLC, _Format, ...)  { if(ctxLC->fPrintf[3]) { lcprintf(ctxLC, "%s: "_Format, __func__, ##__VA_ARGS__); } }

/*
* Check whether the memory map is initialized or not.
* -- ctxLC
* -- return
*/
EXPORTED_FUNCTION BOOL LcMemMap_IsInitialized(_In_ PLC_CONTEXT ctxLC);

/*
* Add a memory range to the memory map.
* -- ctxLC
* -- pa
* -- cb
* -- paRemap = remap offset within file (if relevant).
* -- return
*/
_Success_(return)
EXPORTED_FUNCTION BOOL LcMemMap_AddRange(_In_ PLC_CONTEXT ctxLC, _In_ QWORD pa, _In_ QWORD cb, _In_opt_ QWORD paRemap);

/*
* Get the max physical address from the memory map.
* -- ctxLC
* -- return
*/
_Success_(return != 0)
EXPORTED_FUNCTION QWORD LcMemMap_GetMaxAddress(_In_ PLC_CONTEXT ctxLC);

#endif /* __LEECHCORE_DEVICE_H__ */
