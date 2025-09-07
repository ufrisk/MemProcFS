// memprocfs_fuse.c : implementation of core functionality for MemProcFS
// This is just a thin loader for the virtual memory manager .so which contains the logic.
//
// (c) Ulf Frisk, 2021-2025
// Author: Ulf Frisk, pcileech@frizk.net
//
#if defined(LINUX) || defined(MACOS)
#include <vmmdll.h>
#include "charutil.h"
#include "vfslist.h"
#include "version.h"
#define FUSE_USE_VERSION 30
#include <fuse.h>
#include <signal.h>

typedef struct tdFUSE_INFO {
    struct fuse* pfuse;
    char* szMountPoint;
    struct fuse_chan *pchan;
} FUSE_INFO;

FUSE_INFO g_FuseInfo = { 0 };

VMM_HANDLE g_hVMM = NULL;

//-----------------------------------------------------------------------------
// FUSE FILE SYSTEM FUNCTIONALITY BELOW:
//-----------------------------------------------------------------------------

#define FILETIME_TO_UNIX(ft)        (time_t)((ft) / 10000000ULL - 11644473600ULL)
#ifdef LINUX
#define VER_OSARCH                  "Linux"
#endif /* LINUX */
#ifdef MACOS
#define VER_OSARCH                  "macOS"
#endif /* MACOS */

static int vfs_getattr(const char *uszPathFull, struct stat *st)
{
    CHAR uszPath[3 * MAX_PATH];
    LPSTR uszFile;
    BOOL result, fIsDirectoryExisting;
    VFS_ENTRY e;
    // set common values:
    st->st_uid = getuid();
    st->st_gid = getgid();
    // matches: root directory
    if(!strcmp(uszPathFull, "/")) {
        st->st_ctime = time(NULL);
        st->st_mtime = time(NULL);
        st->st_atime = time(NULL);
        st->st_mode = S_IFDIR | 0755;
        st->st_nlink = 2;
        return 0;
    }
    // matches vfs file/directory:
    uszFile = CharUtil_PathSplitLastEx((LPSTR)uszPathFull, uszPath, sizeof(uszPath));
    result = VfsList_GetSingle((uszPath[0] ? uszPath : "/"), uszFile, &e, &fIsDirectoryExisting);
    if(result) {
        st->st_ctime = FILETIME_TO_UNIX(e.ftCreationTime);
        st->st_mtime = FILETIME_TO_UNIX(e.ftLastWriteTime);
        st->st_atime = FILETIME_TO_UNIX(e.ftLastAccessTime);
        if(e.fDirectory) {
            st->st_mode = S_IFDIR | 0755;
            st->st_nlink = 2;
        } else {
            st->st_mode = S_IFREG | 0644;
            st->st_nlink = 1;
            st->st_size = e.cbFileSize;
        }
    }
    return 0;
}

typedef struct td_readdir_cb_ctx {
    void *buffer;
    fuse_fill_dir_t filler;
} readdir_cb_ctx, *preaddir_cb_ctx;

static void vfs_readdir_cb(_In_ PVFS_ENTRY pVfsEntry, _In_opt_ preaddir_cb_ctx ctx)
{
    ctx->filler(ctx->buffer, pVfsEntry->uszName, NULL, 0);
}

static int vfs_readdir(const char *uszPath, void *buffer, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fi)
{
    readdir_cb_ctx ctx;
    ctx.buffer = buffer;
    ctx.filler = filler;
    filler(buffer, ".", NULL, 0);
    filler(buffer, "..", NULL, 0);
    VfsList_ListDirectory((LPSTR)uszPath, &ctx, (void(*)(PVFS_ENTRY, PVOID))vfs_readdir_cb);
    return 0;
}

static int vfs_read(const char *uszPath, char *buffer, size_t size, off_t offset, struct fuse_file_info *fi)
{
    NTSTATUS nt;
    DWORD i = 0, readlength = 0;
    CHAR c = 0, uszPathCopy[3 * MAX_PATH] = { 0 };
    // 1: replace forward slash with backward slash
    strncpy_s(uszPathCopy, sizeof(uszPathCopy), uszPath, _TRUNCATE);
    while((c = uszPathCopy[i++])) {
        if(c == '/') { uszPathCopy[i - 1] = '\\'; }
    }
    // 2: read
    nt = VMMDLL_VfsReadU(g_hVMM, (LPSTR)uszPathCopy, (PBYTE)buffer, size, &readlength, offset);
    return ((nt == VMMDLL_STATUS_SUCCESS) || (nt == VMMDLL_STATUS_END_OF_FILE)) ? (int)readlength : 0;
}

static int vfs_truncate(const char *path, off_t size)
{
    // dummy function - required and called before vfs_write().
    return 0;
}

static int vfs_write(const char *uszPath, const char *buffer, size_t size, off_t offset, struct fuse_file_info *fi)
{
    NTSTATUS nt;
    DWORD i = 0, writelength = 0;
    CHAR c = 0, uszPathCopy[3 * MAX_PATH] = { 0 };
    // 1: replace forward slash with backward slash
    strncpy_s(uszPathCopy, sizeof(uszPathCopy), uszPath, _TRUNCATE);
    while((c = uszPathCopy[i++])) {
        if(c == '/') { uszPathCopy[i - 1] = '\\'; }
    }
    // 2: write
    nt = VMMDLL_VfsWriteU(g_hVMM, (LPSTR)uszPathCopy, (PBYTE)buffer, size, &writelength, offset);
    return ((nt == VMMDLL_STATUS_SUCCESS) || (nt == VMMDLL_STATUS_END_OF_FILE)) ? (int)size : 0;
}

static struct fuse_operations vfs_operations = {
    .readdir = vfs_readdir,
    .getattr = vfs_getattr,
    .read = vfs_read,
    .write = vfs_write,
    .truncate = vfs_truncate,
};

int vfs_initialize_and_mount_displayinfo(char *szMountPoint)
{
#ifdef LINUX
    struct fuse_args fargs = { 0 };
#endif /* LINUX */
#ifdef MACOS
    int argc = 5;
    char* argv[] = {"memprocfs", "-o", "local,volname=MemProcFS", "-o", "volicon=memprocfs.icns"};
    struct fuse_args fargs = FUSE_ARGS_INIT(argc, argv);
#endif /* MACOS */
    g_FuseInfo.szMountPoint = szMountPoint;
    g_FuseInfo.pchan = fuse_mount(g_FuseInfo.szMountPoint, &fargs);
    if(!g_FuseInfo.pchan) { return -ENOENT; };
    g_FuseInfo.pfuse = fuse_new(g_FuseInfo.pchan, &fargs, &vfs_operations, sizeof(vfs_operations), NULL);
    if(!g_FuseInfo.pfuse) { return -ENOENT; };
    return fuse_loop(g_FuseInfo.pfuse);
}



//-----------------------------------------------------------------------------
// LOCAL/REMOTE WRAPPER FUNCTIONS BELOW:
//-----------------------------------------------------------------------------

/*
* WRAPPER FUNCTION AROUND LOCAL/REMOTE VMMDLL_VfsListU
* List a directory of files in MemProcFS. Directories and files will be listed
* by callbacks into functions supplied in the pFileList parameter.
* If information of an individual file is needed it's neccessary to list all
* files in its directory.
* -- uszPath
* -- pFileList
* -- return
*/
_Success_(return) BOOL MemProcFS_VfsListU(_In_ LPSTR uszPath, _Inout_ PVMMDLL_VFS_FILELIST2 pFileList)
{
    return VMMDLL_VfsListU(g_hVMM, uszPath, pFileList);
}



//-----------------------------------------------------------------------------
// GENERAL INITIALIZATION FUNCTIONALITY BELOW:
//-----------------------------------------------------------------------------

/*
* SetConsoleCtrlHandler for the MemProcFS - clean up whenever CTRL+C is pressed.
* If this is not here MemProcFS might not exit otherwise if there are lingering
* threads most notably in the Python plugin functionality.
* -- s
* -- return
*/
void signal_handler_execute(int signo)
{
    if(signo == SIGINT) {
        printf("CTRL+C detected - shutting down ...\n");
        VMMDLL_CloseAll();
        fuse_unmount(g_FuseInfo.szMountPoint, g_FuseInfo.pchan);
        fuse_exit(g_FuseInfo.pfuse);
    } 
}

/*
* Retrieve the mount point of the FUSE file system given in the -mount parameter.
* -- argc
* -- argv
* -- pszMountPoint
* -- pfPythonExec
*/
VOID GetMountPoint(_In_ DWORD argc, _In_ char *argv[], _Out_ LPSTR *pszMountPoint, _Out_ PBOOL pfPythonExec)
{
    char *argv2[3];
    DWORD i = 0;
    *pszMountPoint = NULL;
    while(i < argc) {
        if(0 == _stricmp(argv[i], "-mount")) {
            *pszMountPoint = argv[i + 1];
            i += 2;
            continue;
        }
        if(0 == strcmp(argv[i], "-pythonexec")) {
            *pfPythonExec = TRUE;
            i += 2;
            continue;
        }
        i++;
    }
}

#ifdef VMM_PROFILE_FULL
#include "ex/memprocfs_ex.h"
#else /* VMM_PROFILE_FULL */
#define MEMPROCFS_IS_OPENSOURCE 1
#define MEMPROCFS_SPLASH \
    "==============================  MemProcFS  ==============================\n" \
    " - Author:           Ulf Frisk - pcileech@frizk.net                      \n" \
    " - Info:             https://github.com/ufrisk/MemProcFS                 \n" \
    " - Discord:          https://discord.gg/pcileech                         \n" \
    " - License:          GNU Affero General Public License v3.0              \n" \
    " - Licensed To:      %s\n"                                                   \
    "   --------------------------------------------------------------------- \n" \
    "   MemProcFS is free open source software. If you find it useful please  \n" \
    "   become a sponsor at: https://github.com/sponsors/ufrisk Thank You :)  \n" \
    "   --------------------------------------------------------------------- \n"
#endif /* VMM_PROFILE_FULL */

VOID Vfs_InitializeAndMount_DisplayInfo(_In_ LPSTR uszMountPoint)
{
    ULONG64 qwVersionVmmMajor = 0, qwVersionVmmMinor = 0, qwVersionVmmRevision = 0;
    ULONG64 qwVersionWinMajor = 0, qwVersionWinMinor = 0, qwVersionWinBuild = 0;
    ULONG64 qwUniqueSystemId = 0, iMemoryModel;
    LPSTR uszLicensedTo = NULL;
    BOOL fGPL;
    // get vmm.dll versions
    VMMDLL_ConfigGet(g_hVMM, VMMDLL_OPT_CONFIG_VMM_VERSION_MAJOR, &qwVersionVmmMajor);
    VMMDLL_ConfigGet(g_hVMM, VMMDLL_OPT_CONFIG_VMM_VERSION_MINOR, &qwVersionVmmMinor);
    VMMDLL_ConfigGet(g_hVMM, VMMDLL_OPT_CONFIG_VMM_VERSION_REVISION, &qwVersionVmmRevision);
    // get operating system versions
    VMMDLL_ConfigGet(g_hVMM, VMMDLL_OPT_CORE_MEMORYMODEL, &iMemoryModel);
    VMMDLL_ConfigGet(g_hVMM, VMMDLL_OPT_WIN_VERSION_MAJOR, &qwVersionWinMajor);
    VMMDLL_ConfigGet(g_hVMM, VMMDLL_OPT_WIN_VERSION_MINOR, &qwVersionWinMinor);
    VMMDLL_ConfigGet(g_hVMM, VMMDLL_OPT_WIN_VERSION_BUILD, &qwVersionWinBuild);
    VMMDLL_ConfigGet(g_hVMM, VMMDLL_OPT_WIN_SYSTEM_UNIQUE_ID, &qwUniqueSystemId);
    uszLicensedTo = VMMDLL_LicensedTo();
    if(!uszLicensedTo) {
        printf("[CRITICAL] A valid license could not be found. Terminating.\n");
        exit(1);
        return;
    }
    fGPL = strstr(uszLicensedTo, "General Public License") != NULL;
    if((MEMPROCFS_IS_OPENSOURCE && !fGPL) || (!MEMPROCFS_IS_OPENSOURCE && fGPL)) {
        printf("[CRITICAL] License mis-match. Terminating.\n");
        exit(1);
        return;
    }
    printf("\n"MEMPROCFS_SPLASH \
        " - Version:          %i.%i.%i (%s)\n" \
        " - Mount Point:      %s           \n" \
        " - Tag:              %i_%x        \n",
        uszLicensedTo,
        (DWORD)qwVersionVmmMajor, (DWORD)qwVersionVmmMinor, (DWORD)qwVersionVmmRevision, VER_OSARCH,
        uszMountPoint, (DWORD)qwVersionWinBuild, (DWORD)qwUniqueSystemId);
    if(qwVersionWinMajor && (iMemoryModel < (sizeof(VMMDLL_MEMORYMODEL_TOSTRING) / sizeof(LPSTR)))) {
        printf(" - Operating System: Windows %i.%i.%i (%s)\n",
            (DWORD)qwVersionWinMajor, (DWORD)qwVersionWinMinor, (DWORD)qwVersionWinBuild, VMMDLL_MEMORYMODEL_TOSTRING[iMemoryModel]);
    } else {
        printf(" - Operating System: Unknown\n");
    }
    printf("==========================================================================\n\n");
    VMMDLL_MemFree(uszLicensedTo);
}

/*
* Main entry point of MemProcFS. The main function will load and initialize
* 'vmm.so' then initialize the 'vmm.so' plugin manager and then hand over
* control to vfsfuse!vfs_initialize_and_mount_displayinfo which will start
* the FUSE virtual file system and mount it at the correct mount point.
* All 'interesting' functionality will take part in vmm.so - the memprocfs
* executable should be considered as a thin wrapper around VMM.so.
* -- argc
* -- argv
* -- return
*/
int main(_In_ int argc, _In_ char* argv[])
{
    // MAIN FUNCTION PROPER BELOW:
    int i;
    BOOL fPythonExec;
    LPCSTR *szArgs = NULL;
    LPSTR szMountPoint = NULL;
    GetMountPoint(argc, argv, &szMountPoint, &fPythonExec);
    if((argc > 2) && (!szMountPoint || !szMountPoint[0])) {
        if(!fPythonExec || szMountPoint) {
            printf("MemProcFS: no mount point specified - specify with: ./memprocfs -mount /dir/to/mount\n");
            return 1;
        }
    }
    if(!(szArgs = LocalAlloc(LMEM_ZEROINIT, (argc + 1ULL) * sizeof(LPSTR)))) {
        printf("MemProcFS: Out of memory!\n");
        return 1;
    }
    for(i = 1; i < argc; i++) {
        szArgs[i] = argv[i];
    }
    szArgs[0] = "-printf";
    // catch CTRL+C
    signal(SIGINT, signal_handler_execute);
    // Initialize MemProcFS
    g_hVMM = VMMDLL_Initialize(argc, szArgs);
    if(!g_hVMM) {
        // any error message will already be shown by the InitializeReserved function.
        return 1;
    }
    if(fPythonExec && !szMountPoint) {
        VMMDLL_CloseAll();
        return 0;
    }
    VMMDLL_ConfigSet(g_hVMM, VMMDLL_OPT_CONFIG_STATISTICS_FUNCTIONCALL, 1);
    if(!VMMDLL_InitializePlugins(g_hVMM)) {
        printf("MemProcFS: Error file system plugins in vmm.dll!\n");
        return 1;
    }
    VfsList_Initialize(MemProcFS_VfsListU, 500, 128, FALSE);
    Vfs_InitializeAndMount_DisplayInfo(szMountPoint);
    // catch CTRL+C
    signal(SIGINT, signal_handler_execute);
    // hand over control to FUSE.
    return vfs_initialize_and_mount_displayinfo(szMountPoint);
}

#endif /* LINUX || MACOS */
