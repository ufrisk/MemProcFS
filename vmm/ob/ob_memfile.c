// ob_memfile.c : implementation of object manager memory file functionality.
//
// The memfile is a growing memory backed file that may be read and appended.
// The memfile will be automatically (de)compressed when it's required for
// optimal performance. This object is typically implementing a generated
// output file - such as some forensic JSON data output.
//
// The memfile (ObMemFile) is thread safe.
// The ObMemFile is an object manager object and must be DECREF'ed when required.
//
// (c) Ulf Frisk, 2021
// Author: Ulf Frisk, pcileech@frizk.net
//
#include "ob.h"

#define OB_MEMFILE_ENTRIES_DIRECTORY    0x200
#define OB_MEMFILE_ENTRIES_TABLE        0x200
#define OB_MEMFILE_BUFSIZE              0x00010000
#define OB_MEMFILE_MAXSIZE              (OB_MEMFILE_ENTRIES_DIRECTORY*OB_MEMFILE_ENTRIES_TABLE*OB_MEMFILE_BUFSIZE)      // 16GB

#define OB_MEMFILE_INDEX_DIRECTORY(cb)  (((cb) >> 25) & 0x1ff)
#define OB_MEMFILE_INDEX_TABLE(cb)      (((cb) >> 16) & 0x1ff)

#define OB_MEMFILE_IS_VALID(p)          (p && (p->ObHdr._magic == OB_HEADER_MAGIC) && (p->ObHdr._tag == OB_TAG_CORE_MEMFILE))

#define NTSTATUS_SUCCESS                ((NTSTATUS)0x00000000L)
#define NTSTATUS_END_OF_FILE            ((NTSTATUS)0xC0000011L)
#define NTSTATUS_FILE_INVALID           ((NTSTATUS)0xC0000098L)

typedef struct tdOB_MEMFILE {
    OB ObHdr;
    SRWLOCK LockSRW;
    QWORD cb;
    POB_COMPRESSED* Directory[OB_MEMFILE_ENTRIES_DIRECTORY];
    POB_COMPRESSED Table0[OB_MEMFILE_ENTRIES_TABLE];
    BYTE pbBuffer[OB_MEMFILE_BUFSIZE];
} OB_MEMFILE, *POB_MEMFILE;

#define OB_MEMFILE_CALL_SYNCHRONIZED_IMPLEMENTATION_WRITE(pmf, RetTp, RetValFail, fn) { \
    if(!OB_MEMFILE_IS_VALID(pmf)) { return RetValFail; }                                \
    RetTp retVal;                                                                       \
    AcquireSRWLockExclusive(&pmf->LockSRW);                                             \
    retVal = fn;                                                                        \
    ReleaseSRWLockExclusive(&pmf->LockSRW);                                             \
    return retVal;                                                                      \
}

#define OB_MEMFILE_CALL_SYNCHRONIZED_IMPLEMENTATION_READ(pmf, RetTp, RetValFail, fn) {  \
    if(!OB_MEMFILE_IS_VALID(pmf)) { return RetValFail; }                                \
    RetTp retVal;                                                                       \
    AcquireSRWLockShared(&pmf->LockSRW);                                                \
    retVal = fn;                                                                        \
    ReleaseSRWLockShared(&pmf->LockSRW);                                                \
    return retVal;                                                                      \
}

/*
* Ob_DECREF / LocalFree all objects in the ObMemFile (if required).
* -- pmf
*/
VOID _ObMemFile_ObCloseCallback(_In_ POB_MEMFILE pmf)
{
    QWORD i, o, oMax;
    oMax = pmf->cb & ~(OB_MEMFILE_BUFSIZE - 1);
    for(o = 0; o < oMax; o += OB_MEMFILE_BUFSIZE) {
        Ob_DECREF(pmf->Directory[OB_MEMFILE_INDEX_DIRECTORY(o)][OB_MEMFILE_INDEX_TABLE(o)]);
    }
    for(i = 1; i < OB_MEMFILE_ENTRIES_DIRECTORY && pmf->Directory[i]; i++) {
        LocalFree(pmf->Directory[i]);
    }
}

_Success_(return == 0)
NTSTATUS _ObMemFile_ReadFile(_In_ POB_MEMFILE pmf, _Out_writes_to_(cb, *pcbRead) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset)
{
    POB_DATA pObData = NULL;
    QWORD iDirectory, iTable, cbBufferStart, oBuffer, cbCopy;
    if(cbOffset >= pmf->cb) { return NTSTATUS_END_OF_FILE; }
    *pcbRead = cb = (DWORD)min(cb, pmf->cb - cbOffset);
    cbBufferStart = pmf->cb & ~(OB_MEMFILE_BUFSIZE - 1);
    while(cb) {
        if(cbOffset >= cbBufferStart) {
            oBuffer = cbOffset - cbBufferStart;
            memcpy(pb, pmf->pbBuffer + oBuffer, cb);
            break;
        }
        oBuffer = cbOffset & (OB_MEMFILE_BUFSIZE - 1);
        cbCopy = min(cb, OB_MEMFILE_BUFSIZE - oBuffer);
        iDirectory = OB_MEMFILE_INDEX_DIRECTORY(cbOffset);
        iTable = OB_MEMFILE_INDEX_TABLE(cbOffset);
        pObData = ObCompressed_GetData(pmf->Directory[iDirectory][iTable]);
        if(!pObData || (pObData->ObHdr.cbData != OB_MEMFILE_BUFSIZE)) {
            *pcbRead = 0;
            Ob_DECREF_NULL(&pObData);
            return NTSTATUS_FILE_INVALID;
        }
        memcpy(pb, pObData->pb + oBuffer, (SIZE_T)cbCopy);
        Ob_DECREF_NULL(&pObData);
        pb += cbCopy;
        cb -= (DWORD)cbCopy;
        cbOffset += cbCopy;
    }
    return *pcbRead ? NTSTATUS_SUCCESS : NTSTATUS_END_OF_FILE;
}

/*
* Read data 'as file' from the ObMemFile.
* -- pmf
* -- pb
* -- cb
* -- pcbRad
* -- cbOffset
* -- return
*/
_Success_(return == 0)
NTSTATUS ObMemFile_ReadFile(_In_opt_ POB_MEMFILE pmf, _Out_writes_to_(cb, *pcbRead) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset)
{
    *pcbRead = 0;
    OB_MEMFILE_CALL_SYNCHRONIZED_IMPLEMENTATION_READ(pmf, NTSTATUS, NTSTATUS_FILE_INVALID, _ObMemFile_ReadFile(pmf, pb, cb, pcbRead, cbOffset));
}

_Success_(return)
BOOL _ObMemFile_Compress(_In_ POB_MEMFILE pmf)
{
    QWORD iDirectory, iTable;
    iDirectory = OB_MEMFILE_INDEX_DIRECTORY(pmf->cb - 1);
    iTable = OB_MEMFILE_INDEX_TABLE(pmf->cb - 1);
    if(!pmf->Directory[iDirectory]) {
        pmf->Directory[iDirectory] = LocalAlloc(LMEM_ZEROINIT, OB_MEMFILE_ENTRIES_TABLE * sizeof(POB_COMPRESSED));
        if(!pmf->Directory[iDirectory]) { goto fail; }
    }
    pmf->Directory[iDirectory][iTable] = ObCompressed_NewFromByte(pmf->pbBuffer, OB_MEMFILE_BUFSIZE);
    if(!pmf->Directory[iDirectory][iTable]) { goto fail; }
    return TRUE;
fail:
    // unable to allocate: catastropic failure!
    // -> overwrite already allocated buffer.
    pmf->cb -= OB_MEMFILE_BUFSIZE;
    return FALSE;
}

_Success_(return)
BOOL _ObMemFile_Append(_In_ POB_MEMFILE pmf, _In_reads_(cbData) PBYTE pbData, _In_ QWORD cbData)
{
    QWORD oBuffer, cbCopy;
    if(!cbData) { return TRUE; }
    while(cbData) {
        // fill as many bytes as possible to buffer
        oBuffer = pmf->cb % OB_MEMFILE_BUFSIZE;
        cbCopy = min(cbData, OB_MEMFILE_BUFSIZE - oBuffer);
        memcpy(pmf->pbBuffer + oBuffer, pbData, (SIZE_T)cbCopy);
        pbData += cbCopy;
        cbData -= cbCopy;
        pmf->cb += cbCopy;
        // if buffer is full -> compress!
        if(0 == (pmf->cb % OB_MEMFILE_BUFSIZE)) {
            if(!_ObMemFile_Compress(pmf)) { return FALSE; }
        }
    }
    return TRUE;
}

/*
* Append binary data to the ObMemFile.
* -- pmf
* -- pb
* -- cb
* -- return
*/
_Success_(return)
BOOL ObMemFile_Append(_In_opt_ POB_MEMFILE pmf, _In_reads_(cb) PBYTE pb, _In_ QWORD cb)
{
    OB_MEMFILE_CALL_SYNCHRONIZED_IMPLEMENTATION_WRITE(pmf, BOOL, FALSE, _ObMemFile_Append(pmf, pb, cb));
}

/*
* Append a string (ansi or utf-8) to the ObMemFile.
* -- pmf
* -- sz
* -- return
*/
_Success_(return)
BOOL ObMemFile_AppendString(_In_opt_ POB_MEMFILE pmf, _In_opt_z_ LPSTR sz)
{
    if(!sz) { return TRUE; }
    return ObMemFile_Append(pmf, (PBYTE)sz, strlen(sz));
}

/*
* Retrieve byte count of the ObMemFile.
* -- pmf
* -- return
*/
QWORD ObMemFile_Size(_In_opt_ POB_MEMFILE pmf)
{
    OB_MEMFILE_CALL_SYNCHRONIZED_IMPLEMENTATION_READ(pmf, QWORD, 0, pmf->cb);
}

/*
* Create a new empty memory file.
* CALLER DECREF: return
* -- return
*/
_Success_(return != NULL)
POB_MEMFILE ObMemFile_New()
{
    POB_MEMFILE pObMemFile = Ob_Alloc(OB_TAG_CORE_MEMFILE, LMEM_ZEROINIT, sizeof(OB_MEMFILE), (OB_CLEANUP_CB)_ObMemFile_ObCloseCallback, NULL);
    if(pObMemFile) {
        pObMemFile->Directory[0] = pObMemFile->Table0;
    }
    return pObMemFile;
}
