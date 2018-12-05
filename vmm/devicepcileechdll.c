// devicepcileechdll.c : implementation related to PCILeech DLL memory acquisition device.
//
// (c) Ulf Frisk, 2018
// Author: Ulf Frisk, pcileech@frizk.net
//
#include "devicepcileechdll.h"
#include "pcileech_dll.h"
#include "vmm.h"

typedef struct tdDEVICE_CONTEXT_PCILEECH_DLL {
    HMODULE hPCILeechDll;

    LPSTR(*PCILeech_GetVersion)();
    BOOL(*PCILeech_InitializeInternalReserved)(_In_ DWORD argc, _In_ char* argv[]);
    BOOL(*PCILeech_Close)();
    BOOL(*PCIleech_DeviceConfigGet)(_In_ ULONG64 fOption, _Out_ PULONG64 pqwValue);
    BOOL(*PCILeech_DeviceConfigSet)(_In_ ULONG64 fOption, _In_ ULONG64 qwValue);
    BOOL(*PCILeech_DeviceWriteMEM)(_In_ ULONG64 qwAddr, _In_ PBYTE pb, _In_ DWORD cb);
    DWORD(*PCILeech_DeviceReadScatterMEM)(_Inout_ PPMEM_IO_SCATTER_HEADER ppMEMs, _In_ DWORD cpMEMs);

} DEVICE_CONTEXT_PCILEECH_DLL, *PDEVICE_CONTEXT_PCILEECH_DLL;

BOOL DevicePCILeechDll_WriteMEM(_In_ QWORD qwAddr, _In_ PBYTE pb, _In_ DWORD cb)
{
    PDEVICE_CONTEXT_PCILEECH_DLL ctxDll = (PDEVICE_CONTEXT_PCILEECH_DLL)ctxMain->dev.hDevice;
    if(!ctxDll) { return FALSE; }
    return ctxDll->PCILeech_DeviceWriteMEM(qwAddr, pb, cb);
}

VOID DevicePCILeechDll_ReadScatterMEM(_Inout_ PPMEM_IO_SCATTER_HEADER ppMEMs, _In_ DWORD cpMEMs, _Out_opt_ PDWORD pcMEMsRead)
{
    DWORD cMEMsRead;
    PDEVICE_CONTEXT_PCILEECH_DLL ctxDll = (PDEVICE_CONTEXT_PCILEECH_DLL)ctxMain->dev.hDevice;
    if(!ctxDll) { 
        if(pcMEMsRead) { *pcMEMsRead = 0; }
        return;
    }
    cMEMsRead = ctxDll->PCILeech_DeviceReadScatterMEM(ppMEMs, cpMEMs);
    if(pcMEMsRead) {
        *pcMEMsRead = cMEMsRead;
    }
}

BOOL DevicePCILeechDll_GetOption(_In_ QWORD fOption, _Out_ PQWORD pqwValue)
{
    PDEVICE_CONTEXT_PCILEECH_DLL ctxDll = (PDEVICE_CONTEXT_PCILEECH_DLL)ctxMain->dev.hDevice;
    if(!ctxDll) { *pqwValue = 0; return FALSE; }
    return ctxDll->PCIleech_DeviceConfigGet(fOption, pqwValue);
}

BOOL DevicePCILeechDll_SetOption(_In_ QWORD fOption, _In_ QWORD qwValue)
{
    PDEVICE_CONTEXT_PCILEECH_DLL ctxDll = (PDEVICE_CONTEXT_PCILEECH_DLL)ctxMain->dev.hDevice;
    if(!ctxDll) { return FALSE; }
    return ctxDll->PCILeech_DeviceConfigSet(fOption, qwValue);
}

VOID DevicePCILeechDll_Close()
{
    PDEVICE_CONTEXT_PCILEECH_DLL ctxDll = (PDEVICE_CONTEXT_PCILEECH_DLL)ctxMain->dev.hDevice;
    if(!ctxDll) { return; }
    ctxDll->PCILeech_Close();
    FreeLibrary(ctxDll->hPCILeechDll);
    LocalFree(ctxDll);
    ZeroMemory(&ctxMain->dev, sizeof(ctxMain->dev));
}

BOOL DevicePCILeechDll_Open()
{
    BOOL result;
    DWORD cDllParams = 0;
    LPSTR szDllVersion, szDllParams[0x10];
    PDEVICE_CONTEXT_PCILEECH_DLL ctxDll;
    ctxDll = (PDEVICE_CONTEXT_PCILEECH_DLL)LocalAlloc(LMEM_ZEROINIT, sizeof(DEVICE_CONTEXT_PCILEECH_DLL));
    if(!ctxDll) { return FALSE; }
    // Load PCILeech DLL
    ctxDll->hPCILeechDll = LoadLibraryA("pcileech.dll");
    if(!ctxDll->hPCILeechDll) {
        vmmprintf("DEVICE: ERROR: Failed loading pcileech.dll - not found!\n");
        goto fail;
    }
    // Retrieve version number
    ctxDll->PCILeech_GetVersion = (LPSTR(*)())GetProcAddress(ctxDll->hPCILeechDll, "PCILeech_GetVersion");
    if(!ctxDll->PCILeech_GetVersion) {
        vmmprintf("DEVICE: ERROR: Failed loading pcileech.dll - version number inaccessible!\n");
        goto fail;
    }
    szDllVersion = ctxDll->PCILeech_GetVersion();
    if(strncmp(szDllVersion, "3.", 2)) {    // major version = 3 required (exactly)
        vmmprintf("DEVICE: ERROR: Failed loading pcileech.dll - version number (major) mismatch!\n");
        vmmprintf("          Please ensure most recent version of memprocfs.exe and pcileech.dll\n");
        goto fail;
    }
    if(atoi(szDllVersion + 2) < 6) {       // minor version = 6 required (at minimum)
        vmmprintf("DEVICE: ERROR: Failed loading pcileech.dll - version number (minor) mismatch!\n");
        vmmprintf("          Please ensure most recent version of memprocfs.exe and pcileech.dll\n");
        goto fail;
    }
    // Load required functions
    ctxDll->PCILeech_InitializeInternalReserved = (BOOL(*)(DWORD,char**))GetProcAddress(ctxDll->hPCILeechDll, "PCILeech_InitializeInternalReserved");
    ctxDll->PCILeech_Close = (BOOL(*)())GetProcAddress(ctxDll->hPCILeechDll, "PCILeech_Close");
    ctxDll->PCIleech_DeviceConfigGet = (BOOL(*)(ULONG64, PULONG64))GetProcAddress(ctxDll->hPCILeechDll, "PCIleech_DeviceConfigGet");
    ctxDll->PCILeech_DeviceConfigSet = (BOOL(*)(ULONG64, ULONG64))GetProcAddress(ctxDll->hPCILeechDll, "PCILeech_DeviceConfigSet");
    ctxDll->PCILeech_DeviceWriteMEM = (BOOL(*)(ULONG64, PBYTE, DWORD))GetProcAddress(ctxDll->hPCILeechDll, "PCILeech_DeviceWriteMEM");
    ctxDll->PCILeech_DeviceReadScatterMEM = (DWORD(*)(PPMEM_IO_SCATTER_HEADER, DWORD))GetProcAddress(ctxDll->hPCILeechDll, "PCILeech_DeviceReadScatterMEM");
    if(!(ctxDll->PCILeech_InitializeInternalReserved && ctxDll->PCILeech_Close && ctxDll->PCIleech_DeviceConfigGet &&
        ctxDll->PCILeech_DeviceConfigSet && ctxDll->PCILeech_DeviceWriteMEM && ctxDll->PCILeech_DeviceReadScatterMEM))
    {
        vmmprintf("DEVICE: ERROR: Failed loading pcileech.dll - missing function(s)!\n");
        goto fail;
    }
    // Initialize DLL: 1 - enable dll printf
    ctxDll->PCILeech_DeviceConfigSet(PCILEECH_DEVICE_CORE_PRINTF_ENABLE, ctxMain->cfg.fVerboseDll ? 1 : 0);
    // Initialize DLL: 2 - initialize context
    szDllParams[cDllParams++] = "";
    szDllParams[cDllParams++] = "dll_library_use";
    if(ctxMain->cfg.fVerbose) { szDllParams[cDllParams++] = "-v"; }
    if(ctxMain->cfg.fVerboseExtra) { szDllParams[cDllParams++] = "-vv"; }
    if(ctxMain->cfg.fVerboseExtraTlp) { szDllParams[cDllParams++] = "-vvv"; }
    szDllParams[cDllParams++] = "-device";
    szDllParams[cDllParams++] = ctxMain->cfg.szDevTpOrFileName;
    if(!ctxDll->PCILeech_InitializeInternalReserved(cDllParams, szDllParams)) {
        vmmprintf("DEVICE: ERROR: Failed initializing pcileech.dll!PCILeech_InitializeInternalReserved\n");
        goto fail;
    }
    // Initialize DLL: 3 - get max address and io size
    result = ctxDll->PCIleech_DeviceConfigGet(PCILEECH_DEVICE_CORE_MAX_NATIVE_ADDRESS, &ctxMain->dev.paAddrMaxNative);
    if(!result || (ctxMain->dev.paAddrMaxNative <= 0x00100000)) {
        vmmprintf("DEVICE: ERROR: Failed initializing pcileech.dll - max physical memory too low - %016llx\n", ctxMain->dev.paAddrMaxNative);
        goto fail;
    }
    result = ctxDll->PCIleech_DeviceConfigGet(PCILEECH_DEVICE_CORE_MAX_NATIVE_IOSIZE, &ctxMain->dev.qwMaxSizeMemIo);
    if(!result || (ctxMain->dev.qwMaxSizeMemIo < 0x1000)) {
        vmmprintf("DEVICE: ERROR: Failed initializing pcileech.dll - max iosize too low - %016llx\n", ctxMain->dev.qwMaxSizeMemIo);
        goto fail;
    }
    // set callback functions and fix up config
    ctxMain->dev.hDevice = (HANDLE)ctxDll;
    ctxMain->dev.tp = VMM_DEVICE_PCILEECH_DLL;
    ctxMain->dev.pfnClose = DevicePCILeechDll_Close;
    ctxMain->dev.pfnGetOption = DevicePCILeechDll_GetOption;
    ctxMain->dev.pfnSetOption = DevicePCILeechDll_SetOption;
    ctxMain->dev.pfnWriteMEM = DevicePCILeechDll_WriteMEM;
    ctxMain->dev.pfnReadScatterMEM = DevicePCILeechDll_ReadScatterMEM;
    vmmprintfv("DEVICE: Successfully opened pcileech.dll\n");
    return TRUE;
fail:
    if(ctxDll->hPCILeechDll) { FreeLibrary(ctxDll->hPCILeechDll); }
    LocalFree(ctxDll);
    ZeroMemory(&ctxMain->dev, sizeof(ctxMain->dev));
    return FALSE;
}
