// memprocfs.h : implementation of core functionality for the Memory Process File System
// This is just a thin loader for the virtual memory manager .so which contains the logic.
//
// (c) Ulf Frisk, 2021
// Author: Ulf Frisk, pcileech@frizk.net
//
#include <vmmdll.h>
#include "vfs.h"
#include "version.h"

/*
* Retrieve the mount point of the FUSE file system given in the -mount parameter.
* -- argc
* -- argv
* -- pszMountPoint
*/
VOID GetMountPoint(_In_ DWORD argc, _In_ char *argv[], _Out_ LPSTR *pszMountPoint)
{
    char *argv2[3];
    DWORD i = 0;
    *pszMountPoint = NULL;
    while(i < argc) {
        if(0 == _stricmp(argv[i], "-mount")) {
            *pszMountPoint = argv[i + 1];
            i += 2;
            continue;
        } else {
            i++;
            continue;
        }
    }
}

VOID VfsDokan_InitializeAndMount_DisplayInfo(LPSTR uszMountPoint)
{
    ULONG64 qwVersionVmmMajor = 0, qwVersionVmmMinor = 0, qwVersionVmmRevision = 0;
    ULONG64 qwVersionWinMajor = 0, qwVersionWinMinor = 0, qwVersionWinBuild = 0;
    ULONG64 qwUniqueSystemId = 0, iMemoryModel;
    // get vmm.dll versions
    VMMDLL_ConfigGet(VMMDLL_OPT_CONFIG_VMM_VERSION_MAJOR, &qwVersionVmmMajor);
    VMMDLL_ConfigGet(VMMDLL_OPT_CONFIG_VMM_VERSION_MINOR, &qwVersionVmmMinor);
    VMMDLL_ConfigGet(VMMDLL_OPT_CONFIG_VMM_VERSION_REVISION, &qwVersionVmmRevision);
    // get operating system versions
    VMMDLL_ConfigGet(VMMDLL_OPT_CORE_MEMORYMODEL, &iMemoryModel);
    VMMDLL_ConfigGet(VMMDLL_OPT_WIN_VERSION_MAJOR, &qwVersionWinMajor);
    VMMDLL_ConfigGet(VMMDLL_OPT_WIN_VERSION_MINOR, &qwVersionWinMinor);
    VMMDLL_ConfigGet(VMMDLL_OPT_WIN_VERSION_BUILD, &qwVersionWinBuild);
    VMMDLL_ConfigGet(VMMDLL_OPT_WIN_SYSTEM_UNIQUE_ID, &qwUniqueSystemId);
    printf("\n" \
        "=============== MemProcFS - THE MEMORY PROCESS FILE SYSTEM ===============\n" \
        " - Author:           Ulf Frisk - pcileech@frizk.net                     \n" \
        " - Info:             https://github.com/ufrisk/MemProcFS                \n" \
        " - License:          GNU Affero General Public License v3.0             \n" \
        "   -------------------------------------------------------------------- \n" \
        "   MemProcFS is free open source software. If you find it useful please \n" \
        "   become a sponsor at: https://github.com/sponsors/ufrisk Thank You :) \n" \
        "   -------------------------------------------------------------------- \n" \
        " - Version:          %i.%i.%i (%s)\n" \
        " - Mount Point:      %s           \n" \
        " - Tag:              %i_%x        \n",
        (DWORD)qwVersionVmmMajor, (DWORD)qwVersionVmmMinor, (DWORD)qwVersionVmmRevision, VER_OSARCH,
        uszMountPoint, (DWORD)qwVersionWinBuild, (DWORD)qwUniqueSystemId);
    if(qwVersionWinMajor && (iMemoryModel < (sizeof(VMMDLL_MEMORYMODEL_TOSTRING) / sizeof(LPSTR)))) {
        printf(" - Operating System: Windows %i.%i.%i (%s)\n",
            (DWORD)qwVersionWinMajor, (DWORD)qwVersionWinMinor, (DWORD)qwVersionWinBuild, VMMDLL_MEMORYMODEL_TOSTRING[iMemoryModel]);
    } else {
        printf(" - Operating System: Unknown\n");
    }
    printf("==========================================================================\n\n");
}

/*
* Main entry point of the memory process file system. The main function will
* load and initialize VMM.DLL then initialize the VMM.DLL plugin manager and
* then hand over control to vfsfuse!vfs_initialize_and_mount_displayinfo which
* will start the FUSE virtual file system and mount it at the correct mount point.
* All 'interesting' functionality will take part in VMM.so - the memprocfs
* executable should be considered as a thin wrapper around VMM.so.
* -- argc
* -- argv
* -- return
*/
int main(_In_ int argc, _In_ char* argv[])
{
    // MAIN FUNCTION PROPER BELOW:
    int i;
    BOOL result;
    LPSTR szMountPoint = NULL, *szArgs = NULL;
    GetMountPoint(argc, argv, &szMountPoint);
    if(!szMountPoint || (szMountPoint[0] != '/')) {
        printf("MemProcFS: no mount point specified - specify with: ./memprocfs -mount /dir/to/mount\n");
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
    VfsList_Initialize(500, 128);
    VfsDokan_InitializeAndMount_DisplayInfo(szMountPoint);
    // hand over control to FUSE.
    LPSTR szArgListFuse[] = { "", szMountPoint, "-f" };
    return vfs_initialize_and_mount_displayinfo(3, szArgListFuse);
}
