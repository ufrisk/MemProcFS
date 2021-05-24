// memprocfs.h : implementation of core functionality for the Memory Process File System
// This is just a thin loader for the virtual memory manager dll which contains the logic.
//
// (c) Ulf Frisk, 2018-2021
// Author: Ulf Frisk, pcileech@frizk.net
//
#include <Windows.h>
#include <stdio.h>
#include <vmmdll.h>
#include "vfs.h"

CHAR g_VfsMountPoint = 'M';

/*
* Retrieve the mount point from the command line arguments. If no '-mount'
* command line argument is given the default mount point will be: M:
* -- argc
* -- argv
* -- return = the mount point as a drive letter.
*/
CHAR GetMountPoint(_In_ DWORD argc, _In_ char* argv[])
{
    CHAR chMountMount = 'M';
    DWORD i = 1;
    for(i = 0; i < argc - 1; i++) {
        if(0 == strcmp(argv[i], "-mount")) {
            chMountMount = argv[i + 1][0];
            break;
        }
    }
    if((chMountMount > 'A' && chMountMount < 'Z') || (chMountMount > 'a' && chMountMount < 'z')) {
        return chMountMount;
    }
    return 'M';
}

/*
* Call the VMMDLL_Close() function in a separate newly create thread.
* This will allow the main thread to exit even if the VMMDLL_Close()
* function should happen to get stuck.
* -- pv
*/
VOID MemProcFsCtrlHandler_TryShutdownThread(PVOID pv)
{
    HMODULE hModuleVmm;
    BOOL(*VMMDLL_Close)();
    __try {
        VfsDokan_Close(g_VfsMountPoint);
        VfsList_Close();
    } __except(EXCEPTION_EXECUTE_HANDLER) { ; }
    __try {
        hModuleVmm = GetModuleHandleA("vmm.dll");
        if(hModuleVmm) {
            VMMDLL_Close = (BOOL(*)())GetProcAddress(hModuleVmm, "VMMDLL_Close");
            if(VMMDLL_Close) {
                VMMDLL_Close();
            }
        }
    } __except(EXCEPTION_EXECUTE_HANDLER) { ; }
}

/*
* SetConsoleCtrlHandler for the MemProcFS - clean up whenever CTRL+C is pressed.
* If this is not here MemProcFS might not exit otherwise if there are lingering
* threads most notably in the Python plugin functionality.
* -- fdwCtrlType
* -- return
*/
BOOL WINAPI MemProcFsCtrlHandler(DWORD fdwCtrlType)
{
	HANDLE hThread;
    if (fdwCtrlType == CTRL_C_EVENT) {
        printf("CTRL+C detected - shutting down ...\n");
        hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)MemProcFsCtrlHandler_TryShutdownThread, NULL, 0, NULL);
		if(hThread) { WaitForSingleObject(hThread, INFINITE); }
        TerminateProcess(GetCurrentProcess(), 1);
        Sleep(1000);
        ExitProcess(1);
        return TRUE;
    }
    return FALSE;
}

/*
* Main entry point of the memory process file system. The main function will
* load and initialize VMM.DLL then initialize the VMM.DLL plugin manager and
* then hand over control to vfs.c!VfsInitializeAndMount which will start the
* dokany virtual file system and mount it at the correct mount point.
* All 'interesting' functionality will take part in VMM.DLL - the memprocfs
* executable should be considered as a thin wrapper around VMM.DLL.
* -- argc
* -- argv
* -- return
*/
int main(_In_ int argc, _In_ char* argv[])
{
    // MAIN FUNCTION PROPER BELOW:
    BOOL result;
    HMODULE hVMM;
    VMMDLL_FUNCTIONS VmmDll;
    int i;
    LPSTR *szArgs = NULL;
    LoadLibraryA("leechcore.dll");
    hVMM = LoadLibraryA("vmm.dll");
    if(!hVMM) {
        printf("MemProcFS: Error loading vmm.dll - ensure vmm.dll resides in the memprocfs.exe application directory!\n");
        return 1;
    }
    VmmDll.Initialize = (BOOL(*)(DWORD, LPSTR*))GetProcAddress(hVMM, "VMMDLL_Initialize");
    VmmDll.InitializePlugins = (BOOL(*)())GetProcAddress(hVMM, "VMMDLL_InitializePlugins");
    VmmDll.ConfigGet = (BOOL(*)(ULONG64, PULONG64))GetProcAddress(hVMM, "VMMDLL_ConfigGet");
    VmmDll.ConfigSet = (BOOL(*)(ULONG64, ULONG64))GetProcAddress(hVMM, "VMMDLL_ConfigSet");
    VmmDll.VfsList = (BOOL(*)(LPCWSTR, PVMMDLL_VFS_FILELIST2))GetProcAddress(hVMM, "VMMDLL_VfsListW");
    VmmDll.VfsRead = (DWORD(*)(LPCWSTR, LPVOID, DWORD, PDWORD, ULONG64))GetProcAddress(hVMM, "VMMDLL_VfsReadW");
    VmmDll.VfsWrite = (DWORD(*)(LPCWSTR, LPVOID, DWORD, PDWORD, ULONG64))GetProcAddress(hVMM, "VMMDLL_VfsWriteW");
    if(!VmmDll.Initialize || !VmmDll.ConfigGet || !VmmDll.VfsList || !VmmDll.VfsRead || !VmmDll.VfsWrite || !VmmDll.InitializePlugins) {
        printf("MemProcFS: Error loading vmm.dll - invalid version of vmm.dll found!\n");
        return 1;
    }
    if(!(szArgs = LocalAlloc(LMEM_ZEROINIT, (argc + 1ULL) * sizeof(LPSTR)))) {
        printf("MemProcFS: Out of memory!\n");
        return 1;
    }
    for(i = 1; i < argc; i++) {
        szArgs[i] = argv[i];
    }
    szArgs[0] = "-printf";
    if(argc > 2) {
        szArgs[argc++] = "-userinteract";
    }
    result = VmmDll.Initialize(argc, szArgs);
    if(!result) {
        // any error message will already be shown by the InitializeReserved function.
        return 1;
    }
    VmmDll.ConfigSet(VMMDLL_OPT_CONFIG_STATISTICS_FUNCTIONCALL, 1);
    result = VmmDll.InitializePlugins();
    if(!result) {
        printf("MemProcFS: Error file system plugins in vmm.dll!\n");
        return 1;
    }
    VfsList_Initialize(hVMM, 500, 128);
    SetConsoleCtrlHandler(MemProcFsCtrlHandler, TRUE);
    g_VfsMountPoint = GetMountPoint(argc, argv);
    VfsDokan_InitializeAndMount(g_VfsMountPoint, &VmmDll);
    CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)MemProcFsCtrlHandler_TryShutdownThread, NULL, 0, NULL);
    Sleep(250);
    TerminateProcess(GetCurrentProcess(), 1);
    Sleep(500);
    ExitProcess(1);
    return 0;
}
