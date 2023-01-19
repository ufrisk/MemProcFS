// vmmwinobj.h : declarations of functionality related to windows object manager.
//
// (c) Ulf Frisk, 2021-2023
// Author: Ulf Frisk, pcileech@frizk.net
//

#ifndef __VMMWINOBJ_H__
#define __VMMWINOBJ_H__
#include "vmm.h"

#define VMMWINOBJ_FILE_OBJECT_SUBSECTION_MAX    0x20

typedef enum {
    VMMWINOBJ_TYPE_NONE = 0,
    VMMWINOBJ_TYPE_FILE = 1,
} VMMWINOBJ_TYPE;

typedef struct tdOB_VMMWINOBJ_OBJECT {
    OB ObHdr;
    QWORD va;
    VMMWINOBJ_TYPE tp;
    DWORD _FutureUse;
} OB_VMMWINOBJ_OBJECT, *POB_VMMWINOBJ_OBJECT;

typedef struct tVMMWINOBJ_FILE_SUBSECTION {
    QWORD vaSubsectionBase;         // PTR _MMPTE
    DWORD dwStartingSector;         // Sector = 512bytes
    DWORD dwNumberOfFullSectors;
    DWORD dwPtesInSubsection;
} VMMWINOBJ_FILE_SUBSECTION, *PVMMWINOBJ_FILE_SUBSECTION;

typedef struct tdOB_VMMWINOBJ_FILE {
    OB ObHdr;
    QWORD va;
    VMMWINOBJ_TYPE tp;
    DWORD _FutureUse;
    QWORD vaSectionObjectPointers;
    QWORD _Reserved2;
    QWORD cb;
    BOOL fData;
    BOOL fCache;
    BOOL fImage;
    DWORD dwNameHash;
    LPSTR uszPath;
    LPSTR uszName;
    QWORD vaControlArea;
    struct {
        BOOL fValid;
        QWORD va;
        QWORD cbFileSize;
        QWORD cbFileSizeValid;
        QWORD cbSectionSize;
        QWORD vaVacbs;
    } _SHARED_CACHE_MAP;
    struct {
        BOOL fValid;
        QWORD va;
        QWORD cbSizeOfSegment;
        QWORD vaPrototypePte;
    } _SEGMENT;
    DWORD _Reserved1;
    DWORD cSUBSECTION;
    PVMMWINOBJ_FILE_SUBSECTION pSUBSECTION;
} OB_VMMWINOBJ_FILE, *POB_VMMWINOBJ_FILE;

/*
* Initialize the Object sub-system. This should ideally be done on Vmm Init().
* -- H
*/
VOID VmmWinObj_Initialize(_In_ VMM_HANDLE H);

/*
* Create an object manager map and assign to the global vmm context upon success.
* CALLER DECREF: return
* -- H
* -- return
*/
PVMMOB_MAP_OBJECT VmmWinObjMgr_Initialize(_In_ VMM_HANDLE H);

/*
* Refresh the Object sub-system.
* -- H
*/
VOID VmmWinObj_Refresh(_In_ VMM_HANDLE H);

/*
* Cleanup the Object sub-system. This should ideally be done on Vmm Close().
* -- H
*/
VOID VmmWinObj_Close(_In_ VMM_HANDLE H);

/*
* Retrieve an object from the object cache.
* CALLER DECREF: return
* -- H
* -- va = virtual address of the object to retrieve.
* -- return = the object, NULL if not found in cache.
*/
POB_VMMWINOBJ_OBJECT VmmWinObj_Get(_In_ VMM_HANDLE H, _In_ QWORD va);

/*
* Retrieve all _FILE_OBJECT related to a process.
* CALLER DECREF: *ppmObFiles
* -- H
* -- pProcess
* -- ppmObFiles
* -- fHandles = TRUE = files from handles, FALSE = files from VADs
* -- return
*/
_Success_(return)
BOOL VmmWinObjFile_GetByProcess(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess, _Out_ POB_MAP *ppmObFiles, _In_ BOOL fHandles);

/*
* Read a contigious amount of file data and report the number of bytes read.
* -- H
* -- pFile
* -- cbOffset
* -- pb
* -- cb
* -- fVmmRead = flags as in VMM_FLAG_*
* -- return = the number of bytes read.
*/
_Success_(return != 0)
DWORD VmmWinObjFile_Read(_In_ VMM_HANDLE H, _In_ POB_VMMWINOBJ_FILE pFile, _In_ QWORD cbOffset, _Out_writes_(cb) PBYTE pb, _In_ DWORD cb, _In_ QWORD fVmmRead);

/*
* Create an kernel device map and assign to the global vmm context upon success.
* CALLER DECREF: return
* -- H
* -- return
*/
PVMMOB_MAP_KDEVICE VmmWinObjKDev_Initialize(_In_ VMM_HANDLE H);

/*
* Create an kernel driver map and assign to the global vmm context upon success.
* CALLER DECREF: return
* -- H
* -- return
*/
PVMMOB_MAP_KDRIVER VmmWinObjKDrv_Initialize(_In_ VMM_HANDLE H);

/*
* Vfs Read: helper function to read object files in an object information dir.
* -- H
* -- uszPathFile
* -- iTypeIndex = the object type index in the ObjectTypeTable
* -- vaObject
* -- pb
* -- cb
* -- pcbRead
* -- cbOffset
* -- return
*/
NTSTATUS VmmWinObjDisplay_VfsRead(_In_ VMM_HANDLE H, _In_ LPSTR uszPathFile, _In_opt_ DWORD iTypeIndex, _In_ QWORD vaObject, _Out_writes_to_(cb, *pcbRead) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset);

/*
* Vfs List: helper function to list object files in an object information dir.
* -- H
* -- iTypeIndex = the object type index in the ObjectTypeTable
* -- vaObject
* -- pFileList
*/
VOID VmmWinObjDisplay_VfsList(_In_ VMM_HANDLE H, _In_opt_ DWORD iTypeIndex, _In_ QWORD vaObject, _Inout_ PHANDLE pFileList);

#endif /* __VMMWINOBJ_H__ */
