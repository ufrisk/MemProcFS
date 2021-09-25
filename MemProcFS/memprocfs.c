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
DWORD WINAPI MemProcFsCtrlHandler_TryShutdownThread(PVOID pv)
{
    __try {
        VfsDokan_Close(g_VfsMountPoint);
        VfsList_Close();
    } __except(EXCEPTION_EXECUTE_HANDLER) { ; }
    __try {
        if(g_hLC_RemoteFS) {
            LcClose(g_hLC_RemoteFS);
            g_hLC_RemoteFS = NULL;
        } else {
            VMMDLL_Close();
        }
    } __except(EXCEPTION_EXECUTE_HANDLER) { ; }
    return 1;
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
        hThread = CreateThread(NULL, 0, MemProcFsCtrlHandler_TryShutdownThread, NULL, 0, NULL);
		if(hThread) { WaitForSingleObject(hThread, INFINITE); }
        TerminateProcess(GetCurrentProcess(), 1);
        Sleep(1000);
        ExitProcess(1);
        return TRUE;
    }
    return FALSE;
}

/*
* Initialize a remote instance of VMM.DLL instead of loading it into the
* process as is the default and preferred way.
* -- argc
* -- argv
* -- return
*/
_Success_(return)
BOOL MemProcFS_InitializeRemoteFS(_In_ int argc, _In_ char *argv[])
{
    int i;
    LC_CONFIG Dev = { 0 };
    // connect to remote system using LeechCore
    Dev.dwVersion = LC_CONFIG_VERSION;
    if(argc == 0) { return FALSE; }
    for(i = 0; i < argc - 1; i++) {
        if(!_stricmp("-device", argv[i])) {
            strncpy_s(Dev.szDevice, MAX_PATH, argv[i + 1], _TRUNCATE);
        }
        if(!_stricmp("-remote", argv[i])) {
            strncpy_s(Dev.szRemote, MAX_PATH, argv[i + 1], _TRUNCATE);
        }
    }
    if(!Dev.szDevice[0]) {
        printf("MemProcFS: missing required option: -device\n");
        return FALSE;
    }
    if(!Dev.szRemote[0]) {
        printf("MemProcFS: missing required option: -remote\n");
        return FALSE;
    }
    if(!(g_hLC_RemoteFS = LcCreate(&Dev))) {
        printf("MemProcFS: Failed to connect to the remote system.\n  Device: %s\n  Remote: %s\n", Dev.szDevice, Dev.szRemote);
        return FALSE;
    }
    // perform set operation (this will trigger a load of remote memory analysis)
    if(!MemProcFS_ConfigSet(VMMDLL_OPT_CONFIG_STATISTICS_FUNCTIONCALL, 1)) {
        printf("MemProcFS: Failed to initialize remote memory analysis.\n  Device: %s\n  Remote: %s\n", Dev.szDevice, Dev.szRemote);
        return FALSE;
    }
    return TRUE;
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
    BOOL result, fRemoteFS = FALSE;
    int i;
    HANDLE hLC_RemoteFS = 0;
    LPSTR *szArgs = NULL;
    LC_CMD_AGENT_VFS_REQ Req = { 0 };
    g_hLC_RemoteFS = 0;
    LoadLibraryA("leechcore.dll");
    if(!(szArgs = LocalAlloc(LMEM_ZEROINIT, (argc + 1ULL) * sizeof(LPSTR)))) {
        printf("MemProcFS: Out of memory!\n");
        return 1;
    }
    for(i = 1; i < argc; i++) {
        szArgs[i] = argv[i];
        if(!_stricmp(argv[i], "-remotefs")) { fRemoteFS = TRUE; }
    }
    if(fRemoteFS) {
        if(!MemProcFS_InitializeRemoteFS(argc, argv)) {
            // error message already given by MemProcFS_InitializeRemoteFS()
            return 1;
        }
    } else {
        szArgs[0] = "-printf";
        if(argc > 2) {
            szArgs[argc++] = "-userinteract";
        }
        result = VMMDLL_Initialize(argc, szArgs);
        if(!result) {
            // any error message will already be shown by the InitializeReserved function.
            return 1;
        }
        VMMDLL_ConfigSet(VMMDLL_OPT_CONFIG_STATISTICS_FUNCTIONCALL, 1);
        result = VMMDLL_InitializePlugins();
        if(!result) {
            printf("MemProcFS: Error file system plugins in vmm.dll!\n");
            return 1;
        }
    }
    VfsList_Initialize(500, 128);
    SetConsoleCtrlHandler(MemProcFsCtrlHandler, TRUE);
    g_VfsMountPoint = GetMountPoint(argc, argv);
    VfsDokan_InitializeAndMount(g_VfsMountPoint);
    if(g_hLC_RemoteFS) {
        LcClose(g_hLC_RemoteFS);
        g_hLC_RemoteFS = NULL;
    }
    CreateThread(NULL, 0, MemProcFsCtrlHandler_TryShutdownThread, NULL, 0, NULL);
    Sleep(250);
    TerminateProcess(GetCurrentProcess(), 1);
    Sleep(500);
    ExitProcess(1);
    return 0;
}
