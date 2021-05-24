#define FUSE_USE_VERSION 30

#include <fuse.h>
#include "vfs.h"
#include "charutil.h"

#define FILETIME_TO_UNIX(ft)        (time_t)((ft) / 10000000ULL - 11644473600ULL)

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
    nt = VMMDLL_VfsReadU((LPSTR)uszPathCopy, (PBYTE)buffer, size, &readlength, offset);
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
    nt = VMMDLL_VfsWriteU((LPSTR)uszPathCopy, (PBYTE)buffer, size, &writelength, offset);
    return ((nt == VMMDLL_STATUS_SUCCESS) || (nt == VMMDLL_STATUS_END_OF_FILE)) ? (int)size : 0;
}

static struct fuse_operations vfs_operations = {
    .readdir = vfs_readdir,
    .getattr = vfs_getattr,
    .read = vfs_read,
    .write = vfs_write,
    .truncate = vfs_truncate,
};

int vfs_initialize_and_mount_displayinfo(int argc, char *argv[])
{
    return fuse_main(argc, argv, &vfs_operations, NULL);
}
