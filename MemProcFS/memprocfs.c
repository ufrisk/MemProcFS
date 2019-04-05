// memprocfs.h : implementation of core functionality for the Memory Process File System
// This is just a thin loader for the virtual memory manager dll which contains the logic.
//
// (c) Ulf Frisk, 2018
// Author: Ulf Frisk, pcileech@frizk.net
//
#include <Windows.h>
#include <stdio.h>
#include "vmmdll.h"
#include "vfs.h"

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
		hModuleVmm = GetModuleHandleA("vmm.dll");
		if(hModuleVmm) {
			VMMDLL_Close = (BOOL(*)())GetProcAddress(hModuleVmm, "VMMDLL_Close");
			if(VMMDLL_Close) {
				VMMDLL_Close();
			}
		}
	}
	__except(EXCEPTION_EXECUTE_HANDLER) { ; }
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
	if (fdwCtrlType == CTRL_C_EVENT) {
		printf("CTRL+C detected - shutting down ...\n");
		CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)MemProcFsCtrlHandler_TryShutdownThread, NULL, 0, NULL);
		Sleep(500);
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
    LoadLibraryA("leechcore.dll");
    hVMM = LoadLibraryExA("vmm.dll", NULL, LOAD_LIBRARY_SEARCH_APPLICATION_DIR);
    if(!hVMM) {
        printf("MemProcFS: Error loading vmm.dll - ensure vmm.dll resides in the memprocfs.exe application directory!\n");
        return 1;
    }
    VmmDll.Initialize = (BOOL(*)(DWORD, LPSTR*))GetProcAddress(hVMM, "VMMDLL_Initialize");
    VmmDll.ConfigGet = (BOOL(*)(ULONG64, PULONG64))GetProcAddress(hVMM, "VMMDLL_ConfigGet");
    VmmDll.ConfigSet = (BOOL(*)(ULONG64, ULONG64))GetProcAddress(hVMM, "VMMDLL_ConfigSet");
    VmmDll.VfsList = (BOOL(*)(LPCWSTR, PVMMDLL_VFS_FILELIST))GetProcAddress(hVMM, "VMMDLL_VfsList");
    VmmDll.VfsRead = (DWORD(*)(LPCWSTR, LPVOID, DWORD, PDWORD, ULONG64))GetProcAddress(hVMM, "VMMDLL_VfsRead");
    VmmDll.VfsWrite = (DWORD(*)(LPCWSTR, LPVOID, DWORD, PDWORD, ULONG64))GetProcAddress(hVMM, "VMMDLL_VfsWrite");
    VmmDll.VfsInitializePlugins = (BOOL(*)())GetProcAddress(hVMM, "VMMDLL_VfsInitializePlugins");
    if(!VmmDll.Initialize || !VmmDll.ConfigGet || !VmmDll.VfsList || !VmmDll.VfsRead || !VmmDll.VfsWrite || !VmmDll.VfsInitializePlugins) {
        printf("MemProcFS: Error loading vmm.dll - invalid version of vmm.dll found!\n");
        return 1;
    }
    argv[0] = "-printf";
    result = VmmDll.Initialize(argc, argv);
    if(!result) {
        // any error message will already be shown by the InitializeReserved function.
        return 1;
    }
    VmmDll.ConfigSet(VMMDLL_OPT_CONFIG_STATISTICS_FUNCTIONCALL, 1);
    result = VmmDll.VfsInitializePlugins();
    if(!result) {
        printf("MemProcFS: Error file system plugins in vmm.dll!\n");
        return 1;
    }
	SetConsoleCtrlHandler(MemProcFsCtrlHandler, TRUE);
    VfsInitializeAndMount(GetMountPoint(argc, argv), &VmmDll);
    ExitProcess(0);
    return 0;
}
