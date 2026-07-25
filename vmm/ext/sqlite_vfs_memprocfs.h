/*
 * sqlite_vfs_memprocfs.h
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

/* Forward declarations for the public API. */
int MemProcFS_SqliteVfsRegister(void);
int MemProcFS_SqliteVfsOpen(const unsigned char *pbDatabase, sqlite3_int64 cbDatabase, const unsigned char *pbWal, sqlite3_int64 cbWal, sqlite3 **ppDatabase);
int MemProcFS_SqliteVfsClose(sqlite3 *pDatabase);
int MemProcFS_SqliteVfsPrepareReadOnly(sqlite3 *pDatabase, const char *zSql, sqlite3_stmt **ppStatement);
int MemProcFS_SqliteVfsResetProgress(sqlite3 *pDatabase);
int MemProcFS_SqliteVfsSetProgressLimit(sqlite3 *pDatabase, sqlite3_uint64 cVmOperations);
