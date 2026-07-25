/*
 * sqlite_vfs_memprocfs.c
 *
 * Read-only SQLite VFS for opening a SQLite main database and its WAL from
 * caller-owned memory buffers. Designed to be compiled directly into a program
 * that already embeds the SQLite amalgamation.
 *
 * Public API:
 *
 *   int MemProcFS_SqliteVfsRegister(void);
 *
 *   int MemProcFS_SqliteVfsOpen(
 *       const unsigned char *pbDatabase,
 *       sqlite3_int64 cbDatabase,
 *       const unsigned char *pbWal,
 *       sqlite3_int64 cbWal,
 *       sqlite3 **ppDatabase);
 *
 *   int MemProcFS_SqliteVfsClose(sqlite3 *pDatabase);
 *
 *   int MemProcFS_SqliteVfsPrepareReadOnly(
 *       sqlite3 *pDatabase,
 *       const char *zSql,
 *       sqlite3_stmt **ppStatement);
 *
 *   int MemProcFS_SqliteVfsResetProgress(sqlite3 *pDatabase);
 *
 *   int MemProcFS_SqliteVfsSetProgressLimit(
 *       sqlite3 *pDatabase,
 *       sqlite3_uint64 cVmOperations);
 *
 * The input buffers are borrowed, not copied. They must remain valid and
 * unchanged until MemProcFS_SqliteVfsClose() (or sqlite3_close()) succeeds.
 *
 * WAL support uses SQLite's single-client, exclusive-locking mode. Therefore
 * the sqlite3_io_methods object intentionally has iVersion == 1 and does not
 * implement xShmMap/xShmLock. MemProcFS_SqliteVfsOpen() sets
 * PRAGMA locking_mode=EXCLUSIVE before the first schema access.
 *
 * This implementation exposes only the main database and optional WAL as
 * memory-backed files. It fails closed for every other filename and never
 * delegates file access or dynamic-library loading to the host VFS. SQLite
 * temporary storage is forced into memory.
 *
 * The connection is hardened for attacker-controlled database bytes: trusted
 * schema is disabled; triggers and views are disabled; defensive and query-only
 * modes are enabled; ATTACH, PRAGMA, writes, virtual tables and extension loading
 * are blocked; limits and a progress budget constrain resource consumption.
 *
 * Compile this file together with sqlite3.c and include the matching sqlite3.h.
 * Do not build SQLite with SQLITE_OMIT_WAL.
 */

#include "sqlite3.h"

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#ifndef MEMPROCFS_SQLITE_VFS_NAME
#define MEMPROCFS_SQLITE_VFS_NAME "memprocfs-buffer-vfs"
#endif

#define MPFS_NAME_PREFIX "memprocfs-buffer-"
#define MPFS_NAME_HEX_CHARS 16
#define MPFS_NAME_SUFFIX_DB ".db"
#define MPFS_SYNTHETIC_NAME_MAX 64
#define MPFS_OPEN_NAME_MAX 96

#ifndef MEMPROCFS_SQLITE_PROGRESS_VM_OPS
#define MEMPROCFS_SQLITE_PROGRESS_VM_OPS 100000000ULL
#endif

#ifndef MEMPROCFS_SQLITE_PROGRESS_GRANULARITY
#define MEMPROCFS_SQLITE_PROGRESS_GRANULARITY 1000
#endif

#ifndef MEMPROCFS_SQLITE_LIMIT_LENGTH
#define MEMPROCFS_SQLITE_LIMIT_LENGTH (64 * 1024 * 1024)
#endif

#ifndef MEMPROCFS_SQLITE_LIMIT_SQL_LENGTH
#define MEMPROCFS_SQLITE_LIMIT_SQL_LENGTH (1024 * 1024)
#endif

#ifndef MEMPROCFS_SQLITE_LIMIT_COLUMN
#define MEMPROCFS_SQLITE_LIMIT_COLUMN 256
#endif

#ifndef MEMPROCFS_SQLITE_LIMIT_EXPR_DEPTH
#define MEMPROCFS_SQLITE_LIMIT_EXPR_DEPTH 100
#endif

#ifndef MEMPROCFS_SQLITE_LIMIT_COMPOUND_SELECT
#define MEMPROCFS_SQLITE_LIMIT_COMPOUND_SELECT 16
#endif

#ifndef MEMPROCFS_SQLITE_LIMIT_VDBE_OP
#define MEMPROCFS_SQLITE_LIMIT_VDBE_OP 250000
#endif

#ifndef MEMPROCFS_SQLITE_LIMIT_FUNCTION_ARG
#define MEMPROCFS_SQLITE_LIMIT_FUNCTION_ARG 64
#endif

#ifndef MEMPROCFS_SQLITE_LIMIT_VARIABLE_NUMBER
#define MEMPROCFS_SQLITE_LIMIT_VARIABLE_NUMBER 1024
#endif

#ifndef MEMPROCFS_SQLITE_LIMIT_LIKE_PATTERN_LENGTH
#define MEMPROCFS_SQLITE_LIMIT_LIKE_PATTERN_LENGTH 4096
#endif

#ifndef MEMPROCFS_SQLITE_CACHE_KIB
#define MEMPROCFS_SQLITE_CACHE_KIB 16384
#endif

/* Forward declarations for the public API. */
int MemProcFS_SqliteVfsRegister(void);
int MemProcFS_SqliteVfsOpen(
    const unsigned char *pbDatabase,
    sqlite3_int64 cbDatabase,
    const unsigned char *pbWal,
    sqlite3_int64 cbWal,
    sqlite3 **ppDatabase);
int MemProcFS_SqliteVfsClose(sqlite3 *pDatabase);
int MemProcFS_SqliteVfsPrepareReadOnly(
    sqlite3 *pDatabase,
    const char *zSql,
    sqlite3_stmt **ppStatement);
int MemProcFS_SqliteVfsResetProgress(sqlite3 *pDatabase);
int MemProcFS_SqliteVfsSetProgressLimit(
    sqlite3 *pDatabase,
    sqlite3_uint64 cVmOperations);

typedef enum MPFS_FILE_KIND {
    MPFS_FILE_NONE = 0,
    MPFS_FILE_MAIN_DB,
    MPFS_FILE_WAL,
    MPFS_FILE_SHM,
    MPFS_FILE_JOURNAL
} MPFS_FILE_KIND;

typedef struct MPFS_MEMORY_DB MPFS_MEMORY_DB;

struct MPFS_MEMORY_DB {
    MPFS_MEMORY_DB *pNext;
    sqlite3_uint64 id;

    const unsigned char *pbDatabase;
    sqlite3_int64 cbDatabase;
    const unsigned char *pbWal;
    sqlite3_int64 cbWal;

    sqlite3 *pConnection;
    sqlite3_uint64 cProgressLimit;
    sqlite3_uint64 cProgressUsed;

    int nRef;
    int isRegistered;
};

typedef struct MPFS_MEMORY_FILE {
    sqlite3_file base;
    MPFS_MEMORY_DB *pDb;
    MPFS_FILE_KIND kind;
    int lockLevel;
} MPFS_MEMORY_FILE;

static sqlite3_vfs g_MpfsVfs;
static sqlite3_vfs *g_pParentVfs = NULL;
static sqlite3_mutex *g_pRegistryMutex = NULL;
static MPFS_MEMORY_DB *g_pRegistry = NULL;
static sqlite3_uint64 g_NextId = 1;

static int MpfsIoClose(sqlite3_file *pFile);
static int MpfsIoRead(sqlite3_file *pFile, void *pBuffer, int cbRead, sqlite3_int64 offset);
static int MpfsIoWrite(sqlite3_file *pFile, const void *pBuffer, int cbWrite, sqlite3_int64 offset);
static int MpfsIoTruncate(sqlite3_file *pFile, sqlite3_int64 size);
static int MpfsIoSync(sqlite3_file *pFile, int flags);
static int MpfsIoFileSize(sqlite3_file *pFile, sqlite3_int64 *pSize);
static int MpfsIoLock(sqlite3_file *pFile, int lockLevel);
static int MpfsIoUnlock(sqlite3_file *pFile, int lockLevel);
static int MpfsIoCheckReservedLock(sqlite3_file *pFile, int *pResult);
static int MpfsIoFileControl(sqlite3_file *pFile, int op, void *pArg);
static int MpfsIoSectorSize(sqlite3_file *pFile);
static int MpfsIoDeviceCharacteristics(sqlite3_file *pFile);

/* iVersion == 1 is intentional; exclusive WAL mode then uses a heap wal-index. */
static const sqlite3_io_methods g_MpfsIoMethods = {
    1,
    MpfsIoClose,
    MpfsIoRead,
    MpfsIoWrite,
    MpfsIoTruncate,
    MpfsIoSync,
    MpfsIoFileSize,
    MpfsIoLock,
    MpfsIoUnlock,
    MpfsIoCheckReservedLock,
    MpfsIoFileControl,
    MpfsIoSectorSize,
    MpfsIoDeviceCharacteristics,
    NULL, /* xShmMap */
    NULL, /* xShmLock */
    NULL, /* xShmBarrier */
    NULL, /* xShmUnmap */
    NULL, /* xFetch */
    NULL  /* xUnfetch */
};

static void MpfsRegistryLock(void)
{
    sqlite3_mutex_enter(g_pRegistryMutex);
}

static void MpfsRegistryUnlock(void)
{
    sqlite3_mutex_leave(g_pRegistryMutex);
}

static void MpfsContextRefLocked(MPFS_MEMORY_DB *pDb)
{
    ++pDb->nRef;
}

static void MpfsContextFree(MPFS_MEMORY_DB *pDb)
{
    sqlite3_free(pDb);
}

static void MpfsContextUnref(MPFS_MEMORY_DB *pDb)
{
    int freeNow = 0;

    if (pDb == NULL) {
        return;
    }

    MpfsRegistryLock();
    if (--pDb->nRef == 0) {
        freeNow = 1;
    }
    MpfsRegistryUnlock();

    if (freeNow) {
        MpfsContextFree(pDb);
    }
}

static int MpfsContextRegister(MPFS_MEMORY_DB *pDb)
{
    MpfsRegistryLock();

    pDb->id = g_NextId++;
    if (pDb->id == 0) {
        pDb->id = g_NextId++;
    }

    pDb->pNext = g_pRegistry;
    g_pRegistry = pDb;
    pDb->isRegistered = 1;
    MpfsContextRefLocked(pDb); /* Registry reference. */

    MpfsRegistryUnlock();
    return SQLITE_OK;
}

static void MpfsContextUnregister(MPFS_MEMORY_DB *pDb)
{
    MPFS_MEMORY_DB **ppCurrent;
    int dropRegistryRef = 0;

    if (pDb == NULL) {
        return;
    }

    MpfsRegistryLock();

    if (pDb->isRegistered) {
        ppCurrent = &g_pRegistry;
        while (*ppCurrent != NULL && *ppCurrent != pDb) {
            ppCurrent = &(*ppCurrent)->pNext;
        }
        if (*ppCurrent == pDb) {
            *ppCurrent = pDb->pNext;
        }
        pDb->pNext = NULL;
        pDb->isRegistered = 0;
        dropRegistryRef = 1;
    }

    MpfsRegistryUnlock();

    if (dropRegistryRef) {
        MpfsContextUnref(pDb);
    }
}

static MPFS_MEMORY_DB *MpfsContextFindAndRef(sqlite3_uint64 id)
{
    MPFS_MEMORY_DB *pDb;

    MpfsRegistryLock();
    for (pDb = g_pRegistry; pDb != NULL; pDb = pDb->pNext) {
        if (pDb->id == id && pDb->isRegistered) {
            MpfsContextRefLocked(pDb);
            break;
        }
    }
    MpfsRegistryUnlock();

    return pDb;
}

static MPFS_MEMORY_DB *MpfsContextFindByConnectionAndRef(sqlite3 *pConnection)
{
    MPFS_MEMORY_DB *pDb;

    if (pConnection == NULL) {
        return NULL;
    }

    MpfsRegistryLock();
    for (pDb = g_pRegistry; pDb != NULL; pDb = pDb->pNext) {
        if (pDb->pConnection == pConnection && pDb->isRegistered) {
            MpfsContextRefLocked(pDb);
            break;
        }
    }
    MpfsRegistryUnlock();

    return pDb;
}

static void MpfsContextSetConnection(
    MPFS_MEMORY_DB *pDb,
    sqlite3 *pConnection)
{
    if (pDb == NULL) {
        return;
    }

    MpfsRegistryLock();
    pDb->pConnection = pConnection;
    MpfsRegistryUnlock();
}

static const char *MpfsBaseName(const char *zName)
{
    const char *zBase = zName;
    const char *p;

    if (zName == NULL) {
        return NULL;
    }

    for (p = zName; *p != '\0'; ++p) {
        if (*p == '/' || *p == '\\') {
            zBase = p + 1;
        }
    }
    return zBase;
}

static int MpfsHexValue(char ch)
{
    if (ch >= '0' && ch <= '9') {
        return ch - '0';
    }
    if (ch >= 'a' && ch <= 'f') {
        return ch - 'a' + 10;
    }
    if (ch >= 'A' && ch <= 'F') {
        return ch - 'A' + 10;
    }
    return -1;
}

static int MpfsParseSyntheticName(
    const char *zName,
    sqlite3_uint64 *pId,
    MPFS_FILE_KIND *pKind)
{
    const char *z;
    sqlite3_uint64 id = 0;
    size_t i;
    int v;

    if (pId != NULL) {
        *pId = 0;
    }
    if (pKind != NULL) {
        *pKind = MPFS_FILE_NONE;
    }

    z = MpfsBaseName(zName);
    if (z == NULL || strncmp(z, MPFS_NAME_PREFIX, sizeof(MPFS_NAME_PREFIX) - 1) != 0) {
        return 0;
    }
    z += sizeof(MPFS_NAME_PREFIX) - 1;

    for (i = 0; i < MPFS_NAME_HEX_CHARS; ++i) {
        v = MpfsHexValue(z[i]);
        if (v < 0) {
            return 0;
        }
        id = (id << 4) | (sqlite3_uint64)v;
    }
    z += MPFS_NAME_HEX_CHARS;

    if (strcmp(z, ".db") == 0) {
        if (pKind != NULL) {
            *pKind = MPFS_FILE_MAIN_DB;
        }
    } else if (strcmp(z, ".db-wal") == 0) {
        if (pKind != NULL) {
            *pKind = MPFS_FILE_WAL;
        }
    } else if (strcmp(z, ".db-shm") == 0) {
        if (pKind != NULL) {
            *pKind = MPFS_FILE_SHM;
        }
    } else if (strcmp(z, ".db-journal") == 0) {
        if (pKind != NULL) {
            *pKind = MPFS_FILE_JOURNAL;
        }
    } else {
        return 0;
    }

    if (pId != NULL) {
        *pId = id;
    }
    return 1;
}

static void MpfsFormatSyntheticName(char *zBuffer, size_t cchBuffer, sqlite3_uint64 id)
{
#if defined(_MSC_VER)
    (void)_snprintf_s(
        zBuffer,
        cchBuffer,
        _TRUNCATE,
        MPFS_NAME_PREFIX "%016llx" MPFS_NAME_SUFFIX_DB,
        (unsigned long long)id);
#else
    (void)snprintf(
        zBuffer,
        cchBuffer,
        MPFS_NAME_PREFIX "%016llx" MPFS_NAME_SUFFIX_DB,
        (unsigned long long)id);
#endif
}


static int MpfsDbConfigBoolean(sqlite3 *pDatabase, int option, int value)
{
    int actualValue = 0;
    return sqlite3_db_config(pDatabase, option, value, &actualValue);
}

static int MpfsFunctionIsDenied(const char *zFunction)
{
    static const char *const azDenied[] = {
        "edit",
        "exec",
        "fts3_tokenizer",
        "load_extension",
        "readfile",
        "shell",
        "system",
        "writefile"
    };
    size_t i;

    if (zFunction == NULL) {
        return 1;
    }

    for (i = 0; i < sizeof(azDenied) / sizeof(azDenied[0]); ++i) {
        if (sqlite3_stricmp(zFunction, azDenied[i]) == 0) {
            return 1;
        }
    }
    return 0;
}

static int MpfsAuthorizer(
    void *pUser,
    int action,
    const char *zArg1,
    const char *zArg2,
    const char *zDatabase,
    const char *zTriggerOrView)
{
    (void)pUser;
    (void)zArg1;

    /* Never allow SQL reached indirectly through a trigger or view. */
    if (zTriggerOrView != NULL) {
        return SQLITE_DENY;
    }

    switch (action) {
        case SQLITE_SELECT:
            return SQLITE_OK;

        case SQLITE_READ:
            return (zDatabase == NULL ||
                    sqlite3_stricmp(zDatabase, "main") == 0)
                       ? SQLITE_OK
                       : SQLITE_DENY;

        case SQLITE_FUNCTION:
            return MpfsFunctionIsDenied(zArg2) ? SQLITE_DENY : SQLITE_OK;

        default:
            /* Denies writes, PRAGMA, ATTACH/DETACH, transactions and DDL. */
            return SQLITE_DENY;
    }
}

static int MpfsProgressHandler(void *pUser)
{
    MPFS_MEMORY_DB *pDb = (MPFS_MEMORY_DB *)pUser;
    sqlite3_uint64 increment =
        (sqlite3_uint64)MEMPROCFS_SQLITE_PROGRESS_GRANULARITY;

    if (pDb == NULL || pDb->cProgressLimit == 0) {
        return 0;
    }

    if (increment == 0) {
        increment = 1;
    }

    if (pDb->cProgressUsed > UINT64_MAX - increment) {
        return 1;
    }

    pDb->cProgressUsed += increment;
    return pDb->cProgressUsed >= pDb->cProgressLimit;
}

static void MpfsApplyLimits(sqlite3 *pDatabase)
{
    (void)sqlite3_limit(
        pDatabase,
        SQLITE_LIMIT_LENGTH,
        MEMPROCFS_SQLITE_LIMIT_LENGTH);
    (void)sqlite3_limit(
        pDatabase,
        SQLITE_LIMIT_SQL_LENGTH,
        MEMPROCFS_SQLITE_LIMIT_SQL_LENGTH);
    (void)sqlite3_limit(
        pDatabase,
        SQLITE_LIMIT_COLUMN,
        MEMPROCFS_SQLITE_LIMIT_COLUMN);
    (void)sqlite3_limit(
        pDatabase,
        SQLITE_LIMIT_EXPR_DEPTH,
        MEMPROCFS_SQLITE_LIMIT_EXPR_DEPTH);
    (void)sqlite3_limit(
        pDatabase,
        SQLITE_LIMIT_COMPOUND_SELECT,
        MEMPROCFS_SQLITE_LIMIT_COMPOUND_SELECT);
#ifdef SQLITE_LIMIT_VDBE_OP
    (void)sqlite3_limit(
        pDatabase,
        SQLITE_LIMIT_VDBE_OP,
        MEMPROCFS_SQLITE_LIMIT_VDBE_OP);
#endif
    (void)sqlite3_limit(
        pDatabase,
        SQLITE_LIMIT_FUNCTION_ARG,
        MEMPROCFS_SQLITE_LIMIT_FUNCTION_ARG);
    (void)sqlite3_limit(
        pDatabase,
        SQLITE_LIMIT_ATTACHED,
        0);
    (void)sqlite3_limit(
        pDatabase,
        SQLITE_LIMIT_LIKE_PATTERN_LENGTH,
        MEMPROCFS_SQLITE_LIMIT_LIKE_PATTERN_LENGTH);
    (void)sqlite3_limit(
        pDatabase,
        SQLITE_LIMIT_VARIABLE_NUMBER,
        MEMPROCFS_SQLITE_LIMIT_VARIABLE_NUMBER);
    (void)sqlite3_limit(
        pDatabase,
        SQLITE_LIMIT_TRIGGER_DEPTH,
        0);
#ifdef SQLITE_LIMIT_WORKER_THREADS
    (void)sqlite3_limit(
        pDatabase,
        SQLITE_LIMIT_WORKER_THREADS,
        0);
#endif
}

static int MpfsApplyHardening(
    sqlite3 *pDatabase,
    MPFS_MEMORY_DB *pContext)
{
    char *zPragmas = NULL;
    int rc;

    if (pDatabase == NULL || pContext == NULL) {
        return SQLITE_MISUSE;
    }

#ifdef SQLITE_DBCONFIG_TRUSTED_SCHEMA
    rc = MpfsDbConfigBoolean(
        pDatabase,
        SQLITE_DBCONFIG_TRUSTED_SCHEMA,
        0);
    if (rc != SQLITE_OK) {
        return rc;
    }
#endif

#ifdef SQLITE_DBCONFIG_ENABLE_TRIGGER
    rc = MpfsDbConfigBoolean(
        pDatabase,
        SQLITE_DBCONFIG_ENABLE_TRIGGER,
        0);
    if (rc != SQLITE_OK) {
        return rc;
    }
#endif

#ifdef SQLITE_DBCONFIG_ENABLE_VIEW
    rc = MpfsDbConfigBoolean(
        pDatabase,
        SQLITE_DBCONFIG_ENABLE_VIEW,
        0);
    if (rc != SQLITE_OK) {
        return rc;
    }
#endif

#ifdef SQLITE_DBCONFIG_DEFENSIVE
    rc = MpfsDbConfigBoolean(
        pDatabase,
        SQLITE_DBCONFIG_DEFENSIVE,
        1);
    if (rc != SQLITE_OK) {
        return rc;
    }
#endif

#ifdef SQLITE_DBCONFIG_WRITABLE_SCHEMA
    rc = MpfsDbConfigBoolean(
        pDatabase,
        SQLITE_DBCONFIG_WRITABLE_SCHEMA,
        0);
    if (rc != SQLITE_OK) {
        return rc;
    }
#endif

#ifdef SQLITE_DBCONFIG_ENABLE_LOAD_EXTENSION
    rc = MpfsDbConfigBoolean(
        pDatabase,
        SQLITE_DBCONFIG_ENABLE_LOAD_EXTENSION,
        0);
    if (rc != SQLITE_OK) {
        return rc;
    }
#endif

#ifdef SQLITE_DBCONFIG_DQS_DML
    rc = MpfsDbConfigBoolean(pDatabase, SQLITE_DBCONFIG_DQS_DML, 0);
    if (rc != SQLITE_OK) {
        return rc;
    }
#endif

#ifdef SQLITE_DBCONFIG_DQS_DDL
    rc = MpfsDbConfigBoolean(pDatabase, SQLITE_DBCONFIG_DQS_DDL, 0);
    if (rc != SQLITE_OK) {
        return rc;
    }
#endif

#ifdef SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE
    rc = MpfsDbConfigBoolean(
        pDatabase,
        SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE,
        1);
    if (rc != SQLITE_OK) {
        return rc;
    }
#endif

#ifdef SQLITE_DBCONFIG_ENABLE_ATTACH_CREATE
    rc = MpfsDbConfigBoolean(
        pDatabase,
        SQLITE_DBCONFIG_ENABLE_ATTACH_CREATE,
        0);
    if (rc != SQLITE_OK) {
        return rc;
    }
#endif

#ifdef SQLITE_DBCONFIG_ENABLE_ATTACH_WRITE
    rc = MpfsDbConfigBoolean(
        pDatabase,
        SQLITE_DBCONFIG_ENABLE_ATTACH_WRITE,
        0);
    if (rc != SQLITE_OK) {
        return rc;
    }
#endif

#ifdef SQLITE_DBCONFIG_ENABLE_FTS3_TOKENIZER
    rc = MpfsDbConfigBoolean(
        pDatabase,
        SQLITE_DBCONFIG_ENABLE_FTS3_TOKENIZER,
        0);
    if (rc != SQLITE_OK) {
        return rc;
    }
#endif

#ifdef SQLITE_DBCONFIG_ENABLE_FKEY
    rc = MpfsDbConfigBoolean(
        pDatabase,
        SQLITE_DBCONFIG_ENABLE_FKEY,
        0);
    if (rc != SQLITE_OK) {
        return rc;
    }
#endif

#ifdef SQLITE_DBCONFIG_ENABLE_COMMENTS
    rc = MpfsDbConfigBoolean(
        pDatabase,
        SQLITE_DBCONFIG_ENABLE_COMMENTS,
        0);
    if (rc != SQLITE_OK) {
        return rc;
    }
#endif

#if !defined(SQLITE_OMIT_LOAD_EXTENSION)
    rc = sqlite3_enable_load_extension(pDatabase, 0);
    if (rc != SQLITE_OK) {
        return rc;
    }
#endif

    MpfsApplyLimits(pDatabase);

    rc = sqlite3_busy_timeout(pDatabase, 0);
    if (rc != SQLITE_OK) {
        return rc;
    }

    zPragmas = sqlite3_mprintf(
        "PRAGMA locking_mode=EXCLUSIVE;"
        "PRAGMA query_only=ON;"
        "PRAGMA temp_store=MEMORY;"
        "PRAGMA cell_size_check=ON;"
        "PRAGMA mmap_size=0;"
        "PRAGMA automatic_index=OFF;"
        "PRAGMA cache_spill=OFF;"
        "PRAGMA foreign_keys=OFF;"
        "PRAGMA recursive_triggers=OFF;"
        "PRAGMA cache_size=-%d;",
        MEMPROCFS_SQLITE_CACHE_KIB);
    if (zPragmas == NULL) {
        return SQLITE_NOMEM;
    }

    rc = sqlite3_exec(pDatabase, zPragmas, NULL, NULL, NULL);
    sqlite3_free(zPragmas);
    if (rc != SQLITE_OK) {
        return rc;
    }

    rc = sqlite3_set_authorizer(pDatabase, MpfsAuthorizer, pContext);
    if (rc != SQLITE_OK) {
        return rc;
    }

    pContext->cProgressUsed = 0;
    sqlite3_progress_handler(
        pDatabase,
        (MEMPROCFS_SQLITE_PROGRESS_GRANULARITY > 0)
            ? MEMPROCFS_SQLITE_PROGRESS_GRANULARITY
            : 1,
        MpfsProgressHandler,
        pContext);

    return SQLITE_OK;
}

static int MpfsSqlTailIsEmpty(const char *zTail)
{
    if (zTail == NULL) {
        return 1;
    }

    while (*zTail == ' ' ||
           *zTail == '\t' ||
           *zTail == '\r' ||
           *zTail == '\n' ||
           *zTail == '\f' ||
           *zTail == '\v') {
        ++zTail;
    }
    return *zTail == '\0';
}

static int MpfsGetBuffer(
    MPFS_MEMORY_FILE *pFile,
    const unsigned char **ppBuffer,
    sqlite3_int64 *pSize)
{
    if (pFile == NULL || pFile->pDb == NULL || ppBuffer == NULL || pSize == NULL) {
        return SQLITE_IOERR_READ;
    }

    switch (pFile->kind) {
        case MPFS_FILE_MAIN_DB:
            *ppBuffer = pFile->pDb->pbDatabase;
            *pSize = pFile->pDb->cbDatabase;
            return SQLITE_OK;

        case MPFS_FILE_WAL:
            *ppBuffer = pFile->pDb->pbWal;
            *pSize = pFile->pDb->cbWal;
            return SQLITE_OK;

        default:
            *ppBuffer = NULL;
            *pSize = 0;
            return SQLITE_IOERR_READ;
    }
}

static int MpfsIoClose(sqlite3_file *pSqliteFile)
{
    MPFS_MEMORY_FILE *pFile = (MPFS_MEMORY_FILE *)pSqliteFile;
    MPFS_MEMORY_DB *pDb = pFile->pDb;
    MPFS_FILE_KIND kind = pFile->kind;

    pFile->base.pMethods = NULL;
    pFile->pDb = NULL;
    pFile->kind = MPFS_FILE_NONE;
    pFile->lockLevel = SQLITE_LOCK_NONE;

    /* Once the main DB file closes, no new WAL opens should occur. */
    if (kind == MPFS_FILE_MAIN_DB) {
        MpfsContextUnregister(pDb);
    }
    MpfsContextUnref(pDb); /* File reference. */

    return SQLITE_OK;
}

static int MpfsIoRead(
    sqlite3_file *pSqliteFile,
    void *pBuffer,
    int cbRead,
    sqlite3_int64 offset)
{
    MPFS_MEMORY_FILE *pFile = (MPFS_MEMORY_FILE *)pSqliteFile;
    const unsigned char *pbFile = NULL;
    sqlite3_int64 cbFile = 0;
    sqlite3_int64 cbAvailable;
    int rc;

    if (pBuffer == NULL || cbRead < 0 || offset < 0) {
        return SQLITE_IOERR_READ;
    }

    rc = MpfsGetBuffer(pFile, &pbFile, &cbFile);
    if (rc != SQLITE_OK || pbFile == NULL || cbFile < 0) {
        memset(pBuffer, 0, (size_t)cbRead);
        return SQLITE_IOERR_READ;
    }

    if (offset >= cbFile) {
        memset(pBuffer, 0, (size_t)cbRead);
        return SQLITE_IOERR_SHORT_READ;
    }

    cbAvailable = cbFile - offset;
    if (cbAvailable >= (sqlite3_int64)cbRead) {
        memcpy(pBuffer, pbFile + (size_t)offset, (size_t)cbRead);
        return SQLITE_OK;
    }

    memcpy(pBuffer, pbFile + (size_t)offset, (size_t)cbAvailable);
    memset((unsigned char *)pBuffer + (size_t)cbAvailable,
           0,
           (size_t)((sqlite3_int64)cbRead - cbAvailable));
    return SQLITE_IOERR_SHORT_READ;
}

static int MpfsIoWrite(
    sqlite3_file *pFile,
    const void *pBuffer,
    int cbWrite,
    sqlite3_int64 offset)
{
    (void)pFile;
    (void)pBuffer;
    (void)cbWrite;
    (void)offset;
    return SQLITE_READONLY;
}

static int MpfsIoTruncate(sqlite3_file *pFile, sqlite3_int64 size)
{
    (void)pFile;
    (void)size;
    return SQLITE_READONLY;
}

static int MpfsIoSync(sqlite3_file *pFile, int flags)
{
    (void)pFile;
    (void)flags;
    return SQLITE_OK;
}

static int MpfsIoFileSize(sqlite3_file *pSqliteFile, sqlite3_int64 *pSize)
{
    MPFS_MEMORY_FILE *pFile = (MPFS_MEMORY_FILE *)pSqliteFile;
    const unsigned char *pbFile = NULL;
    sqlite3_int64 cbFile = 0;
    int rc;

    if (pSize == NULL) {
        return SQLITE_IOERR_FSTAT;
    }

    rc = MpfsGetBuffer(pFile, &pbFile, &cbFile);
    if (rc != SQLITE_OK || pbFile == NULL) {
        *pSize = 0;
        return SQLITE_IOERR_FSTAT;
    }

    *pSize = cbFile;
    return SQLITE_OK;
}

static int MpfsIoLock(sqlite3_file *pSqliteFile, int lockLevel)
{
    MPFS_MEMORY_FILE *pFile = (MPFS_MEMORY_FILE *)pSqliteFile;

    if (lockLevel > pFile->lockLevel) {
        pFile->lockLevel = lockLevel;
    }
    return SQLITE_OK;
}

static int MpfsIoUnlock(sqlite3_file *pSqliteFile, int lockLevel)
{
    MPFS_MEMORY_FILE *pFile = (MPFS_MEMORY_FILE *)pSqliteFile;
    pFile->lockLevel = lockLevel;
    return SQLITE_OK;
}

static int MpfsIoCheckReservedLock(sqlite3_file *pSqliteFile, int *pResult)
{
    MPFS_MEMORY_FILE *pFile = (MPFS_MEMORY_FILE *)pSqliteFile;

    if (pResult == NULL) {
        return SQLITE_IOERR_CHECKRESERVEDLOCK;
    }

    *pResult = (pFile->lockLevel >= SQLITE_LOCK_RESERVED) ? 1 : 0;
    return SQLITE_OK;
}

static int MpfsIoFileControl(sqlite3_file *pSqliteFile, int op, void *pArg)
{
    MPFS_MEMORY_FILE *pFile = (MPFS_MEMORY_FILE *)pSqliteFile;

    switch (op) {
        case SQLITE_FCNTL_LOCKSTATE:
            if (pArg != NULL) {
                *(int *)pArg = pFile->lockLevel;
                return SQLITE_OK;
            }
            return SQLITE_NOTFOUND;

#ifdef SQLITE_FCNTL_VFSNAME
        case SQLITE_FCNTL_VFSNAME:
            if (pArg != NULL) {
                *(char **)pArg = sqlite3_mprintf("%s", MEMPROCFS_SQLITE_VFS_NAME);
                return (*(char **)pArg != NULL) ? SQLITE_OK : SQLITE_NOMEM;
            }
            return SQLITE_NOTFOUND;
#endif

        default:
            return SQLITE_NOTFOUND;
    }
}

static int MpfsIoSectorSize(sqlite3_file *pFile)
{
    (void)pFile;
    return 4096;
}

static int MpfsIoDeviceCharacteristics(sqlite3_file *pFile)
{
    (void)pFile;
    return 0;
}

static int MpfsVfsOpen(
    sqlite3_vfs *pVfs,
    sqlite3_filename zName,
    sqlite3_file *pSqliteFile,
    int flags,
    int *pOutFlags)
{
    sqlite3_uint64 id = 0;
    MPFS_FILE_KIND kind = MPFS_FILE_NONE;
    MPFS_MEMORY_DB *pDb = NULL;
    MPFS_MEMORY_FILE *pFile;

    (void)pVfs;

    if (!MpfsParseSyntheticName(zName, &id, &kind)) {
        return SQLITE_CANTOPEN;
    }

    if (kind != MPFS_FILE_MAIN_DB && kind != MPFS_FILE_WAL) {
        return SQLITE_CANTOPEN;
    }

    pDb = MpfsContextFindAndRef(id);
    if (pDb == NULL) {
        return SQLITE_CANTOPEN;
    }

    if (kind == MPFS_FILE_MAIN_DB) {
        if (pDb->pbDatabase == NULL || pDb->cbDatabase <= 0) {
            MpfsContextUnref(pDb);
            return SQLITE_CANTOPEN;
        }
    } else {
        if (pDb->pbWal == NULL || pDb->cbWal < 32) {
            MpfsContextUnref(pDb);
            return SQLITE_CANTOPEN;
        }
    }

    pFile = (MPFS_MEMORY_FILE *)pSqliteFile;
    memset(pFile, 0, sizeof(*pFile));
    pFile->base.pMethods = &g_MpfsIoMethods;
    pFile->pDb = pDb;
    pFile->kind = kind;
    pFile->lockLevel = SQLITE_LOCK_NONE;

    if (pOutFlags != NULL) {
        *pOutFlags = (flags & ~(SQLITE_OPEN_READWRITE |
                               SQLITE_OPEN_CREATE |
                               SQLITE_OPEN_DELETEONCLOSE)) |
                     SQLITE_OPEN_READONLY;
    }

    return SQLITE_OK;
}

static int MpfsVfsDelete(sqlite3_vfs *pVfs, const char *zName, int syncDir)
{
    (void)pVfs;
    (void)zName;
    (void)syncDir;
    return SQLITE_IOERR_DELETE;
}

static int MpfsVfsAccess(
    sqlite3_vfs *pVfs,
    const char *zName,
    int flags,
    int *pResult)
{
    sqlite3_uint64 id = 0;
    MPFS_FILE_KIND kind = MPFS_FILE_NONE;
    MPFS_MEMORY_DB *pDb;
    int exists = 0;

    (void)pVfs;

    if (pResult == NULL) {
        return SQLITE_IOERR_ACCESS;
    }
    *pResult = 0;

    if (!MpfsParseSyntheticName(zName, &id, &kind)) {
        *pResult = 0;
        return SQLITE_OK;
    }

    pDb = MpfsContextFindAndRef(id);
    if (pDb != NULL) {
        if (kind == MPFS_FILE_MAIN_DB) {
            exists = (pDb->pbDatabase != NULL && pDb->cbDatabase > 0);
        } else if (kind == MPFS_FILE_WAL) {
            exists = (pDb->pbWal != NULL && pDb->cbWal >= 32);
        } else {
            exists = 0;
        }
        MpfsContextUnref(pDb);
    }

    switch (flags) {
        case SQLITE_ACCESS_EXISTS:
        case SQLITE_ACCESS_READ:
            *pResult = exists;
            break;

        case SQLITE_ACCESS_READWRITE:
            *pResult = 0;
            break;

        default:
            *pResult = exists;
            break;
    }

    return SQLITE_OK;
}

static int MpfsVfsFullPathname(
    sqlite3_vfs *pVfs,
    const char *zName,
    int cchOut,
    char *zOut)
{
    sqlite3_uint64 id;
    MPFS_FILE_KIND kind;
    size_t cchName;

    (void)pVfs;

    if (zName == NULL || zOut == NULL || cchOut <= 0) {
        return SQLITE_CANTOPEN;
    }

    if (!MpfsParseSyntheticName(zName, &id, &kind)) {
        return SQLITE_CANTOPEN;
    }

    (void)id;
    (void)kind;
    cchName = strlen(zName);
    if (cchName + 1 > (size_t)cchOut) {
        return SQLITE_CANTOPEN;
    }
    memcpy(zOut, zName, cchName + 1);
    return SQLITE_OK;
}

static void *MpfsVfsDlOpen(sqlite3_vfs *pVfs, const char *zFilename)
{
    (void)pVfs;
    (void)zFilename;
    return NULL;
}

static void MpfsVfsDlError(sqlite3_vfs *pVfs, int nByte, char *zErrMsg)
{
    static const char zMessage[] = "extension loading disabled";
    size_t cchCopy;

    (void)pVfs;
    if (zErrMsg == NULL || nByte <= 0) {
        return;
    }

    cchCopy = sizeof(zMessage) - 1;
    if (cchCopy >= (size_t)nByte) {
        cchCopy = (size_t)nByte - 1;
    }
    memcpy(zErrMsg, zMessage, cchCopy);
    zErrMsg[cchCopy] = '\0';
}

static void (*MpfsVfsDlSym(
    sqlite3_vfs *pVfs,
    void *pHandle,
    const char *zSymbol))(void)
{
    (void)pVfs;
    (void)pHandle;
    (void)zSymbol;
    return NULL;
}

static void MpfsVfsDlClose(sqlite3_vfs *pVfs, void *pHandle)
{
    (void)pVfs;
    (void)pHandle;
}

static int MpfsVfsRandomness(sqlite3_vfs *pVfs, int nByte, char *zOut)
{
    sqlite3_vfs *pParent = (sqlite3_vfs *)pVfs->pAppData;
    if (pParent != NULL && pParent->xRandomness != NULL) {
        return pParent->xRandomness(pParent, nByte, zOut);
    }
    if (zOut != NULL && nByte > 0) {
        memset(zOut, 0, (size_t)nByte);
    }
    return 0;
}

static int MpfsVfsSleep(sqlite3_vfs *pVfs, int microseconds)
{
    sqlite3_vfs *pParent = (sqlite3_vfs *)pVfs->pAppData;
    return (pParent != NULL && pParent->xSleep != NULL)
               ? pParent->xSleep(pParent, microseconds)
               : microseconds;
}

static int MpfsVfsCurrentTime(sqlite3_vfs *pVfs, double *pTime)
{
    sqlite3_vfs *pParent = (sqlite3_vfs *)pVfs->pAppData;
    return (pParent != NULL && pParent->xCurrentTime != NULL)
               ? pParent->xCurrentTime(pParent, pTime)
               : SQLITE_ERROR;
}

static int MpfsVfsGetLastError(sqlite3_vfs *pVfs, int nByte, char *zErrMsg)
{
    sqlite3_vfs *pParent = (sqlite3_vfs *)pVfs->pAppData;
    if (pParent != NULL && pParent->xGetLastError != NULL) {
        return pParent->xGetLastError(pParent, nByte, zErrMsg);
    }
    if (zErrMsg != NULL && nByte > 0) {
        zErrMsg[0] = '\0';
    }
    return 0;
}

int MemProcFS_SqliteVfsRegister(void)
{
    sqlite3_vfs *pExisting;
    int rc;

    rc = sqlite3_initialize();
    if (rc != SQLITE_OK) {
        return rc;
    }

    /* SQLITE_MUTEX_STATIC_VFS3 is reserved for application VFS use. */
    if (g_pRegistryMutex == NULL) {
        g_pRegistryMutex = sqlite3_mutex_alloc(SQLITE_MUTEX_STATIC_VFS3);
    }

    MpfsRegistryLock();

    pExisting = sqlite3_vfs_find(MEMPROCFS_SQLITE_VFS_NAME);
    if (pExisting != NULL) {
        rc = (pExisting == &g_MpfsVfs) ? SQLITE_OK : SQLITE_MISUSE;
        MpfsRegistryUnlock();
        return rc;
    }

    g_pParentVfs = sqlite3_vfs_find(NULL);
    if (g_pParentVfs == NULL) {
        MpfsRegistryUnlock();
        return SQLITE_NOTFOUND;
    }

    memset(&g_MpfsVfs, 0, sizeof(g_MpfsVfs));
    g_MpfsVfs.iVersion = 1;
    g_MpfsVfs.szOsFile = (int)sizeof(MPFS_MEMORY_FILE);
    g_MpfsVfs.mxPathname = MPFS_SYNTHETIC_NAME_MAX;
    g_MpfsVfs.zName = MEMPROCFS_SQLITE_VFS_NAME;
    g_MpfsVfs.pAppData = g_pParentVfs;
    g_MpfsVfs.xOpen = MpfsVfsOpen;
    g_MpfsVfs.xDelete = MpfsVfsDelete;
    g_MpfsVfs.xAccess = MpfsVfsAccess;
    g_MpfsVfs.xFullPathname = MpfsVfsFullPathname;
    g_MpfsVfs.xDlOpen = MpfsVfsDlOpen;
    g_MpfsVfs.xDlError = MpfsVfsDlError;
    g_MpfsVfs.xDlSym = MpfsVfsDlSym;
    g_MpfsVfs.xDlClose = MpfsVfsDlClose;
    g_MpfsVfs.xRandomness = MpfsVfsRandomness;
    g_MpfsVfs.xSleep = MpfsVfsSleep;
    g_MpfsVfs.xCurrentTime = MpfsVfsCurrentTime;
    g_MpfsVfs.xGetLastError = MpfsVfsGetLastError;

    rc = sqlite3_vfs_register(&g_MpfsVfs, 0);
    MpfsRegistryUnlock();
    return rc;
}

int MemProcFS_SqliteVfsOpen(
    const unsigned char *pbDatabase,
    sqlite3_int64 cbDatabase,
    const unsigned char *pbWal,
    sqlite3_int64 cbWal,
    sqlite3 **ppDatabase)
{
    MPFS_MEMORY_DB *pContext = NULL;
    sqlite3 *pDb = NULL;
    char szName[MPFS_SYNTHETIC_NAME_MAX];
    char szOpenName[MPFS_OPEN_NAME_MAX];
    const char *zOpenName;
    int openFlags;
    int rc;

    if (ppDatabase == NULL) {
        return SQLITE_MISUSE;
    }
    *ppDatabase = NULL;

    if (cbDatabase < 0 || cbWal < 0) {
        return SQLITE_MISUSE;
    }
    if (pbDatabase == NULL || cbDatabase < 100) {
        return SQLITE_NOTADB;
    }
    if ((sqlite3_uint64)cbDatabase > (sqlite3_uint64)SIZE_MAX ||
        (sqlite3_uint64)cbWal > (sqlite3_uint64)SIZE_MAX) {
        return SQLITE_TOOBIG;
    }
    if (pbWal == NULL) {
        cbWal = 0;
    }

    rc = MemProcFS_SqliteVfsRegister();
    if (rc != SQLITE_OK) {
        return rc;
    }

    pContext = (MPFS_MEMORY_DB *)sqlite3_malloc64(sizeof(*pContext));
    if (pContext == NULL) {
        return SQLITE_NOMEM;
    }
    memset(pContext, 0, sizeof(*pContext));
    pContext->pbDatabase = pbDatabase;
    pContext->cbDatabase = cbDatabase;
    pContext->pbWal = pbWal;
    pContext->cbWal = cbWal;
    pContext->cProgressLimit =
        (sqlite3_uint64)MEMPROCFS_SQLITE_PROGRESS_VM_OPS;
    pContext->cProgressUsed = 0;
    pContext->nRef = 1; /* Local reference held by this function. */

    rc = MpfsContextRegister(pContext);
    if (rc != SQLITE_OK) {
        MpfsContextUnref(pContext);
        return rc;
    }

    MpfsFormatSyntheticName(szName, sizeof(szName), pContext->id);

    zOpenName = szName;
    openFlags = SQLITE_OPEN_READONLY | SQLITE_OPEN_PRIVATECACHE;

    /*
     * A fully checkpointed database can retain WAL-mode header bytes even when
     * no WAL exists. immutable=1 permits that frozen main-only image to open.
     * Do not use immutable when a WAL buffer is present: SQLite must inspect it.
     */
    if (pbWal == NULL || cbWal < 32) {
#if defined(_MSC_VER)
        (void)_snprintf_s(
            szOpenName,
            sizeof(szOpenName),
            _TRUNCATE,
            "file:%s?immutable=1",
            szName);
#else
        (void)snprintf(
            szOpenName,
            sizeof(szOpenName),
            "file:%s?immutable=1",
            szName);
#endif
        zOpenName = szOpenName;
        openFlags |= SQLITE_OPEN_URI;
    }

    rc = sqlite3_open_v2(
        zOpenName,
        &pDb,
        openFlags,
        MEMPROCFS_SQLITE_VFS_NAME);
    if (rc != SQLITE_OK) {
        if (pDb != NULL) {
            sqlite3_close(pDb);
            pDb = NULL;
        }
        MpfsContextUnregister(pContext);
        MpfsContextUnref(pContext); /* Local reference. */
        return rc;
    }

    sqlite3_extended_result_codes(pDb, 1);
    MpfsContextSetConnection(pContext, pDb);

    /*
     * Apply all connection hardening before the first schema/table read.
     * locking_mode=EXCLUSIVE must also precede the first WAL access because
     * this VFS intentionally provides io_methods version 1 without xShmMap.
     */
    rc = MpfsApplyHardening(pDb, pContext);
    if (rc != SQLITE_OK) {
        (void)sqlite3_close(pDb);
        MpfsContextUnregister(pContext);
        MpfsContextUnref(pContext); /* Local reference. */
        return rc;
    }

    MpfsContextUnref(pContext); /* Drop local reference; registry/file own it. */
    *ppDatabase = pDb;
    return SQLITE_OK;
}

int MemProcFS_SqliteVfsPrepareReadOnly(
    sqlite3 *pDatabase,
    const char *zSql,
    sqlite3_stmt **ppStatement)
{
    MPFS_MEMORY_DB *pContext;
    sqlite3_stmt *pStatement = NULL;
    const char *zTail = NULL;
    unsigned int prepareFlags = 0;
    sqlite3_mutex *pMutex;
    int rc;

    if (pDatabase == NULL || zSql == NULL || ppStatement == NULL) {
        return SQLITE_MISUSE;
    }
    *ppStatement = NULL;

    pContext = MpfsContextFindByConnectionAndRef(pDatabase);
    if (pContext == NULL) {
        return SQLITE_MISUSE;
    }

    pMutex = sqlite3_db_mutex(pDatabase);
    sqlite3_mutex_enter(pMutex);
    pContext->cProgressUsed = 0;
    sqlite3_mutex_leave(pMutex);

#ifdef SQLITE_PREPARE_NO_VTAB
    prepareFlags |= SQLITE_PREPARE_NO_VTAB;
#else
    MpfsContextUnref(pContext);
    return SQLITE_NOTFOUND;
#endif

    rc = sqlite3_prepare_v3(
        pDatabase,
        zSql,
        -1,
        prepareFlags,
        &pStatement,
        &zTail);
    if (rc != SQLITE_OK) {
        MpfsContextUnref(pContext);
        return rc;
    }

    if (pStatement == NULL || !MpfsSqlTailIsEmpty(zTail)) {
        sqlite3_finalize(pStatement);
        MpfsContextUnref(pContext);
        return SQLITE_MISUSE;
    }

    if (!sqlite3_stmt_readonly(pStatement)) {
        sqlite3_finalize(pStatement);
        MpfsContextUnref(pContext);
        return SQLITE_READONLY;
    }

    MpfsContextUnref(pContext);
    *ppStatement = pStatement;
    return SQLITE_OK;
}

int MemProcFS_SqliteVfsResetProgress(sqlite3 *pDatabase)
{
    MPFS_MEMORY_DB *pContext;
    sqlite3_mutex *pMutex;

    if (pDatabase == NULL) {
        return SQLITE_MISUSE;
    }

    pContext = MpfsContextFindByConnectionAndRef(pDatabase);
    if (pContext == NULL) {
        return SQLITE_MISUSE;
    }

    pMutex = sqlite3_db_mutex(pDatabase);
    sqlite3_mutex_enter(pMutex);
    pContext->cProgressUsed = 0;
    sqlite3_mutex_leave(pMutex);

    MpfsContextUnref(pContext);
    return SQLITE_OK;
}

int MemProcFS_SqliteVfsSetProgressLimit(
    sqlite3 *pDatabase,
    sqlite3_uint64 cVmOperations)
{
    MPFS_MEMORY_DB *pContext;
    sqlite3_mutex *pMutex;

    if (pDatabase == NULL) {
        return SQLITE_MISUSE;
    }

    pContext = MpfsContextFindByConnectionAndRef(pDatabase);
    if (pContext == NULL) {
        return SQLITE_MISUSE;
    }

    pMutex = sqlite3_db_mutex(pDatabase);
    sqlite3_mutex_enter(pMutex);
    pContext->cProgressLimit = cVmOperations;
    pContext->cProgressUsed = 0;
    sqlite3_mutex_leave(pMutex);

    MpfsContextUnref(pContext);
    return SQLITE_OK;
}

int MemProcFS_SqliteVfsClose(sqlite3 *pDatabase)
{
    MPFS_MEMORY_DB *pContext;
    int rc;

    if (pDatabase == NULL) {
        return SQLITE_OK;
    }

    /* Hold the callback context alive throughout sqlite3_close(). */
    pContext = MpfsContextFindByConnectionAndRef(pDatabase);
    rc = sqlite3_close(pDatabase);
    MpfsContextUnref(pContext);
    return rc;
}
