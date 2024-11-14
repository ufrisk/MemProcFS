// vmmwinobj.h : declarations of functionality related to windows object manager.
//
// (c) Ulf Frisk, 2021-2024
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
    DWORD dwStartingSector;         // Sector = 4096(data), 512(image, usually)
    DWORD dwNumberOfFullSectors;
    DWORD dwPtesInSubsection;
} VMMWINOBJ_FILE_SUBSECTION, *PVMMWINOBJ_FILE_SUBSECTION;

typedef struct tdOB_VMMWINOBJ_SHARED_CACHE_MAP {
    OB ObHdr;
    QWORD va;
    QWORD vaVacbs;
    QWORD cbFileSize;
    QWORD cbFileSizeValid;
    QWORD cbSectionSize;
} OB_VMMWINOBJ_SHARED_CACHE_MAP, *POB_VMMWINOBJ_SHARED_CACHE_MAP;

typedef struct tdOB_VMMWINOBJ_CONTROL_AREA {
    OB ObHdr;
    QWORD va;
    struct {
        QWORD va;
        QWORD cbSizeOfSegment;
        DWORD cbSizeOfImage;
        BYTE bImageSigningLevel;        // SE_SIGNING_LEVEL_*
        BYTE bImageSigningType;         // SE_IMAGE_SIGNATURE_TYPE
        QWORD vaPrototypePte;
    } _SEGMENT;
    WORD cbSectorSize;
    DWORD cSUBSECTION;
    VMMWINOBJ_FILE_SUBSECTION pSUBSECTION[];
} OB_VMMWINOBJ_CONTROL_AREA, *POB_VMMWINOBJ_CONTROL_AREA;

typedef DWORD VMMWINOBJ_FILE_TP;

#define VMMWINOBJ_FILE_TP_DEFAULT   0
#define VMMWINOBJ_FILE_TP_DATA      1
#define VMMWINOBJ_FILE_TP_CACHE     2
#define VMMWINOBJ_FILE_TP_IMAGE     4
#define VMMWINOBJ_FILE_TP_ALL       (VMMWINOBJ_FILE_TP_DATA | VMMWINOBJ_FILE_TP_CACHE | VMMWINOBJ_FILE_TP_IMAGE)

typedef struct tdOB_VMMWINOBJ_FILE {
    // OB_VMMWINOBJ_OBJECT common fields:
    OB ObHdr;
    QWORD va;
    VMMWINOBJ_TYPE tp;
    DWORD _FutureUse;
    // fields:
    QWORD cb;           // File size for VMMWINOBJ_FILE_TP_ALL
    LPSTR uszPath;
    LPSTR uszName;
    DWORD fDuplicate;   // Shares the same path & section object pointers as another object.
    // new SECTION_OBJECT_POINTERS:
    QWORD vaSectionObjectPointers;
    POB_VMMWINOBJ_CONTROL_AREA pData;
    POB_VMMWINOBJ_SHARED_CACHE_MAP pCache;
    POB_VMMWINOBJ_CONTROL_AREA pImage;
    // reserved init:
    DWORD _Reserved1;
    QWORD _Reserved2;
    QWORD _Reserved3;
    QWORD _Reserved4;
} OB_VMMWINOBJ_FILE, *POB_VMMWINOBJ_FILE;

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
* Retrieve a process associated (open handle) with the object virtual address.
* NB! Object may have multiple processes associated, only the first is returned.
* If no process is found NULL is returned.
* CALLER DECREF: return
* -- H
* -- vaObject
* -- return = process associated with the file object (if any).
*/
_Success_(return != NULL)
PVMM_PROCESS VmmWinObj_GetProcessAssociated(_In_ VMM_HANDLE H, _In_ QWORD vaObject);

/*
* Retrieve a file object by its virtual address.
* CALLER DECREF: return
* -- H
* -- va = virtual address of the object to retrieve.
* -- return = the object, NULL if not found in cache.
*/
_Success_(return != NULL)
POB_VMMWINOBJ_FILE VmmWinObjFile_GetByVa(_In_ VMM_HANDLE H, _In_ QWORD va);

/*
* Retrieve all _FILE_OBJECT that can be recovered with data from the system.
* Function return a map of POB_VMMWINOBJ_FILE / POB_VMMWINOBJ_OBJECT.
* NB! this may take a long time to complete on first run.
* CALLER DECREF: *ppmObFiles
* -- H
* -- ppmObFiles
* -- return
*/
_Success_(return)
BOOL VmmWinObjFile_GetAll(_In_ VMM_HANDLE H, _Out_ POB_MAP *ppmObFiles);

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
* Retrieve the file size of a _FILE_OBJECT.
* The file size may differ depending on which types of the file object is being
* read, i.e. _DATA, _IMAGE or _CACHE.
* -- H
* -- pFile
* -- tp = VMMWINOBJ_FILE_TP_*
* -- return = the file size.
*/
QWORD VmmWinObjFile_Size(_In_ VMM_HANDLE H, _In_ POB_VMMWINOBJ_FILE pFile, _In_ VMMWINOBJ_FILE_TP tp);

/*
* Read a contigious amount of file data and report the number of bytes read.
* -- H
* -- pFile
* -- cbOffset
* -- pb
* -- cb
* -- fVmmRead = flags as in VMM_FLAG_*
* -- tp = VMMWINOBJ_FILE_TP_*
* -- return = the number of bytes read.
*/
_Success_(return != 0)
DWORD VmmWinObjFile_Read(_In_ VMM_HANDLE H, _In_ POB_VMMWINOBJ_FILE pFile, _In_ QWORD cbOffset, _Out_writes_(cb) PBYTE pb, _In_ DWORD cb, _In_ QWORD fVmmRead, _In_ VMMWINOBJ_FILE_TP tp);

/*
* Read a contigious amount of file data and report the number of bytes read.
* -- H
* -- vaFileObject
* -- cbOffset
* -- pb
* -- cb
* -- fVmmRead = flags as in VMM_FLAG_*
* -- tp = VMMWINOBJ_FILE_TP_*
* -- return = the number of bytes read.
*/
_Success_(return != 0)
DWORD VmmWinObjFile_ReadFromObjectAddress(_In_ VMM_HANDLE H, _In_ QWORD vaFileObject, _In_ QWORD cbOffset, _Out_writes_(cb) PBYTE pb, _In_ DWORD cb, _In_ QWORD fVmmRead, _In_ VMMWINOBJ_FILE_TP tp);

/*
* Translate a file offset into a physical address.
* -- H
* -- pFile
* -- cbOffset
* -- ppa
* -- return
*/
_Success_(return)
BOOL VmmWinObjFile_GetPA(_In_ VMM_HANDLE H, _In_ POB_VMMWINOBJ_FILE pFile, _In_ QWORD cbOffset, _Out_ PQWORD ppa);

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
NTSTATUS VmmWinObjDisplay_VfsRead(_In_ VMM_HANDLE H, _In_ LPCSTR uszPathFile, _In_opt_ DWORD iTypeIndex, _In_ QWORD vaObject, _Out_writes_to_(cb, *pcbRead) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset);

/*
* Vfs List: helper function to list object files in an object information dir.
* -- H
* -- iTypeIndex = the object type index in the ObjectTypeTable
* -- vaObject
* -- pFileList
*/
VOID VmmWinObjDisplay_VfsList(_In_ VMM_HANDLE H, _In_opt_ DWORD iTypeIndex, _In_ QWORD vaObject, _Inout_ PHANDLE pFileList);

#endif /* __VMMWINOBJ_H__ */
