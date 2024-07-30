// vmmwinobj.c : implementation related to Windows Objects.
//
// (c) Ulf Frisk, 2020-2024
// Author: Ulf Frisk, pcileech@frizk.net
//

#include "vmm.h"
#include "vmmwin.h"
#include "vmmwindef.h"
#include "vmmwinobj.h"
#include "pdb.h"
#include "charutil.h"
#include "util.h"

#define VMMWINOBJ_WORKITEM_FILEPROCSCAN_VAD         0x0000000100000000
#define VMMWINOBJ_WORKITEM_FILEPROCSCAN_HANDLE      0x0000000200000000

typedef struct tdOB_VMMWINOBJ_CONTEXT {
    OB ObHdr;
    BOOL fAll;
    CRITICAL_SECTION LockUpdate;
    POB_SET psError;                // key = va
    POB_MAP pmByObj;                // key = va
    POB_MAP pmByWorkitem;           // key = [VMMWINOBJ_WORKITEM_ | dwPID]
    POB_COUNTER pcVaToPid;          // key = va, value = PID
} OB_VMMWINOBJ_CONTEXT, *POB_VMMWINOBJ_CONTEXT;

//-----------------------------------------------------------------------------
// OBJECT INITIALIZATION/REFRESH/RETRIEVE FUNCTIONALITY BELOW:
//-----------------------------------------------------------------------------

VOID VmmWinObj_Context_CleanupCB(POB_VMMWINOBJ_CONTEXT pOb)
{
    DeleteCriticalSection(&pOb->LockUpdate);
    Ob_DECREF(pOb->psError);
    Ob_DECREF(pOb->pmByObj);
    Ob_DECREF(pOb->pmByWorkitem);
    Ob_DECREF(pOb->pcVaToPid);
}

/*
* Retrieve the OB_VMMWINOBJ_CONTEXT.
* CALLER DECREF: return
* -- H
* -- return
*/
_Success_(return != NULL)
POB_VMMWINOBJ_CONTEXT VmmWinObj_GetContext(_In_ VMM_HANDLE H)
{
    static SRWLOCK LockSRW = SRWLOCK_INIT;
    POB_VMMWINOBJ_CONTEXT pObCtx = NULL;
    if((pObCtx = ObContainer_GetOb(H->vmm.pObCWinObj))) { return pObCtx; }
    AcquireSRWLockExclusive(&LockSRW);
    if((pObCtx = ObContainer_GetOb(H->vmm.pObCWinObj))) {
        ReleaseSRWLockExclusive(&LockSRW);
        return pObCtx;
    }
    pObCtx = Ob_AllocEx(H, OB_TAG_OBJ_CTX, LMEM_ZEROINIT, sizeof(OB_VMMWINOBJ_CONTEXT), (OB_CLEANUP_CB)VmmWinObj_Context_CleanupCB, NULL);
    if(!pObCtx) { goto fail; }
    InitializeCriticalSection(&pObCtx->LockUpdate);
    if(!(pObCtx->psError = ObSet_New(H))) { goto fail; }
    if(!(pObCtx->pmByObj = ObMap_New(H, OB_MAP_FLAGS_OBJECT_OB))) { goto fail; }
    if(!(pObCtx->pmByWorkitem = ObMap_New(H, OB_MAP_FLAGS_OBJECT_OB))) { goto fail; }
    ObContainer_SetOb(H->vmm.pObCWinObj, pObCtx);
    ReleaseSRWLockExclusive(&LockSRW);
    return pObCtx;
fail:
    Ob_DECREF(pObCtx);
    ReleaseSRWLockExclusive(&LockSRW);
    return NULL;
}

/*
* Refresh the Object sub-system.
* -- H
*/
VOID VmmWinObj_Refresh(_In_ VMM_HANDLE H)
{
    ObContainer_SetOb(H->vmm.pObCWinObj, NULL);
    ObContainer_SetOb(H->vmm.pObCMapObjMgr, NULL);
    ObContainer_SetOb(H->vmm.pObCMapKDriver, NULL);
}

/*
* Retrieve an object from the object cache.
* CALLER DECREF: return
* -- H
* -- ctx
* -- tp = the type of object to retrieve.
* -- va = virtual address of the object to retrieve.
* -- return = the object, NULL if not found in cache.
*/
POB_VMMWINOBJ_OBJECT VmmWinObj_CacheGet(_In_ VMM_HANDLE H, _In_ POB_VMMWINOBJ_CONTEXT ctx, _In_ VMMWINOBJ_TYPE tp, _In_ QWORD va)
{
    POB_VMMWINOBJ_OBJECT pOb = ObMap_GetByKey(ctx->pmByObj, va);
    if(pOb) {
        if(pOb->tp == tp) { return pOb; }
        Ob_DECREF(pOb);
    }
    return NULL;
}



// ----------------------------------------------------------------------------
// _FILE_OBJECT INITIALIZATION AND RETRIEVAL:
// Initialization functionality takes one or more addresses to _FILE_OBJECT and
// initializes, in a #calls efficient way, multiple OB_VMMWINOBJ_FILE.
// The kernel objects have the relationship as per below:
// _FILE_OBJECT
//   _UNICODE_STRING
//   _SECTION_OBJECT_POINTERS
//     _SHARED_CACHE_MAP
//     _CONTROL_AREA
//       _SUBSECTION(s) [follows _CONTROL_AREA]
//       _SEGMENT
// ----------------------------------------------------------------------------

VOID VmmWinObj_ObObjFile_CleanupCB(POB_VMMWINOBJ_FILE pOb)
{
    Ob_DECREF(pOb->pSectionObjectPointers);
    LocalFree(pOb->uszPath);
}

VOID VmmWinObj_ObSectObjPtrs_CleanupCB(POB_VMMWINOBJ_SECTION_OBJECT_POINTERS pOb)
{
    LocalFree(pOb->pSUBSECTION);
}

/*
* Filter function for VmmWinObjFile_Initialize_SharedCacheMap.
*/
VOID VmmWinObjFile_Initialize_SharedCacheMap_Filter(_In_opt_ PVOID ctx, _In_ POB_SET ps, _In_ QWORD k, _In_ POB_VMMWINOBJ_SECTION_OBJECT_POINTERS v)
{
    if(v->_SHARED_CACHE_MAP.va) {
        ObSet_Push(ps, v->_SHARED_CACHE_MAP.va - 0x10);
    }
}

/*
* Fetch _SHARED_CACHE_MAP data into the OB_VMMWINOBJ_FILE contained by the pm map
* in a efficient way.
* -- H
* -- pSystemProcess
* -- pm
*/
VOID VmmWinObjFile_Initialize_SharedCacheMap(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pSystemProcess, _In_ POB_MAP pmSectObjPtrs)
{
    BOOL f, f32 = H->vmm.f32;
    BYTE pb[0x300];
    POB_VMMWINOBJ_SECTION_OBJECT_POINTERS peObPtr = NULL;
    PVMM_OFFSET_FILE po = &H->vmm.offset.FILE;
    // 1: Prefetch valid _SHARED_CACHE_MAP into cache.
    if(!VmmCachePrefetchPages5(H, pSystemProcess, pmSectObjPtrs, 0x10 + po->_SHARED_CACHE_MAP.cb, 0, (OB_MAP_FILTERSET_PFN_CB)VmmWinObjFile_Initialize_SharedCacheMap_Filter)) { return; }
    // 2: process _SHARED_CACHE_MAP
    while((peObPtr = ObMap_GetNext(pmSectObjPtrs, peObPtr))) {
        f = peObPtr->_SHARED_CACHE_MAP.va &&
            VmmRead2(H, pSystemProcess, peObPtr->_SHARED_CACHE_MAP.va - 0x10, pb, po->_SHARED_CACHE_MAP.cb, VMM_FLAG_FORCECACHE_READ) &&
            VMM_POOLTAG_PREPENDED(f32, pb, 0x10, 'CcSc') &&
            (peObPtr->_SHARED_CACHE_MAP.vaVacbs = VMM_PTR_OFFSET(f32, pb + 0x10, po->_SHARED_CACHE_MAP.oVacbs)) &&
            VMM_KADDR_4_8(f32, peObPtr->_SHARED_CACHE_MAP.vaVacbs) &&
            (peObPtr->_SHARED_CACHE_MAP.cbFileSize = *(PQWORD)(pb + 0x10 + po->_SHARED_CACHE_MAP.oFileSize)) &&
            (peObPtr->_SHARED_CACHE_MAP.cbSectionSize = *(PQWORD)(pb + 0x10 + po->_SHARED_CACHE_MAP.oSectionSize));
        peObPtr->_SHARED_CACHE_MAP.fValid = f;
        peObPtr->_SHARED_CACHE_MAP.cbFileSizeValid = *(PQWORD)(pb + 0x10 + po->_SHARED_CACHE_MAP.oValidDataLength);
        if(peObPtr->_SHARED_CACHE_MAP.fValid && ((peObPtr->cb == 0) || (peObPtr->_SHARED_CACHE_MAP.cbFileSize < peObPtr->cb))) {
            peObPtr->cb = peObPtr->_SHARED_CACHE_MAP.cbFileSize;
        }
    }
}

/*
* Walk subsections to gather information about this file object. _SUBSECTION
* entries are usually stacked in an array-like pattern immediately after the
* _CONTROL_AREA object. This makes them very likely to be in the memory cache,
* hence need for performance enhancing caching functionality
* -- H
* -- pSystemProcess
* -- pf
*/
BOOL VmmWinObjFile_Initialize_ControlArea_Subsection(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pSystemProcess, _In_ POB_VMMWINOBJ_SECTION_OBJECT_POINTERS pf)
{
    QWORD va;
    BOOL f = TRUE, fSoft, f32 = H->vmm.f32;
    BYTE pb[0x80] = { 0 };
    DWORD i = 0, dwStartingSectorNext = 0;
    VMMWINOBJ_FILE_SUBSECTION ps[VMMWINOBJ_FILE_OBJECT_SUBSECTION_MAX];
    PVMM_OFFSET_FILE po = &H->vmm.offset.FILE;
    // 1: Fetch # _SUBSECTION
    va = pf->vaControlArea + po->_CONTROL_AREA.cb;
    while(f && (i < VMMWINOBJ_FILE_OBJECT_SUBSECTION_MAX) && VMM_KADDR_4_8(f32, va) && VmmRead2(H, pSystemProcess, va, pb, po->_SUBSECTION.cb, VMM_FLAG_FORCECACHE_READ)) {
        ps[i].dwStartingSector = *(PDWORD)(pb + po->_SUBSECTION.oStartingSector);
        ps[i].dwNumberOfFullSectors = *(PDWORD)(pb + po->_SUBSECTION.oNumberOfFullSectors);
        f = (pf->vaControlArea == VMM_PTR_OFFSET(f32, pb, po->_SUBSECTION.oControlArea)) &&
            (ps[i].vaSubsectionBase = VMM_PTR_OFFSET(f32, pb, po->_SUBSECTION.oSubsectionBase)) && VMM_KADDR_4_8(f32, ps[i].vaSubsectionBase) &&
            (ps[i].dwPtesInSubsection = *(PDWORD)(pb + po->_SUBSECTION.oPtesInSubsection));
        fSoft = f &&
            (dwStartingSectorNext <= ps[i].dwStartingSector) &&
            (dwStartingSectorNext = ps[i].dwStartingSector + max(1, ps[i].dwNumberOfFullSectors));
        if(fSoft) { i++; }
        va = VMM_PTR_OFFSET(f32, pb, po->_SUBSECTION.oNextSubsection);
    }
    // 2: fill valid _SUBSECTION(s) info into 'pf'.
    if(i) {
        if(!(pf->pSUBSECTION = LocalAlloc(0, i * sizeof(VMMWINOBJ_FILE_SUBSECTION)))) { return TRUE; }
        memcpy(pf->pSUBSECTION, &ps, i * sizeof(VMMWINOBJ_FILE_SUBSECTION));
        pf->cSUBSECTION = i;
        pf->cb = pf->fImage ? (512ULL * dwStartingSectorNext) : pf->cb;
    }
    return TRUE;
}

/*
* Filter function for VmmWinObjFile_Initialize_ControlArea.
*/
VOID VmmWinObjFile_Initialize_ControlArea_FilterSegment(_In_opt_ PVOID ctx, _In_ POB_SET ps, _In_ QWORD k, _In_ POB_VMMWINOBJ_SECTION_OBJECT_POINTERS v)
{
    ObSet_Push(ps, v->_SEGMENT.va);
}

/*
* Filter function for VmmWinObjFile_Initialize_ControlArea.
*/
VOID VmmWinObjFile_Initialize_ControlArea_Filter(_In_opt_ PVOID ctx, _In_ POB_SET ps, _In_ QWORD k, _In_ POB_VMMWINOBJ_SECTION_OBJECT_POINTERS v)
{
    ObSet_Push(ps, v->vaControlArea);
}

/*
* Fetch _CONTROL_AREA data into the OB_VMMWINOBJ_FILE contained by the pm map
* in a efficient way.
* -- H
* -- pSystemProcess
* -- pmSectObjPtrs
*/
VOID VmmWinObjFile_Initialize_ControlArea(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pSystemProcess, _In_ POB_MAP pmSectObjPtrs)
{
    BOOL f, f32 = H->vmm.f32;
    BYTE pb[0x100];
    POB_VMMWINOBJ_SECTION_OBJECT_POINTERS peObPtr = NULL;
    PVMM_OFFSET_FILE po = &H->vmm.offset.FILE;
    // 1: Prefetch valid _CONTROL_AREA and following _SUBSECTION into cache.
    if(!VmmCachePrefetchPages5(H, pSystemProcess, pmSectObjPtrs, 0x1000, 0, (OB_MAP_FILTERSET_PFN_CB)VmmWinObjFile_Initialize_ControlArea_Filter)) { return; }
    // 2: get _SEGMENT pointer and sub-process _SUBSECTION(s)
    while((peObPtr = ObMap_GetNext(pmSectObjPtrs, peObPtr))) {
        f = peObPtr->vaControlArea &&
            VmmRead2(H, pSystemProcess, peObPtr->vaControlArea, pb, po->_CONTROL_AREA.cb, VMM_FLAG_FORCECACHE_READ) &&
            VMM_KADDR(f32, VMM_PTR_OFFSET(f32, pb, po->_CONTROL_AREA.oFilePointer)) &&
            (peObPtr->_SEGMENT.va = VMM_PTR_OFFSET(f32, pb, po->_CONTROL_AREA.oSegment)) && VMM_KADDR_4_8(f32, peObPtr->_SEGMENT.va);
        if(f) {
            VmmWinObjFile_Initialize_ControlArea_Subsection(H, pSystemProcess, peObPtr);
        }
    }
    // 3: Prefetch valid _SEGMENT into cache.
    if(!VmmCachePrefetchPages5(H, pSystemProcess, pmSectObjPtrs, po->_SEGMENT.cb, 0, (OB_MAP_FILTERSET_PFN_CB)VmmWinObjFile_Initialize_ControlArea_FilterSegment)) { return; }
    // 4: get _SEGMENT data
    while((peObPtr = ObMap_GetNext(pmSectObjPtrs, peObPtr))) {
        if(peObPtr->_SEGMENT.va && VmmRead2(H, pSystemProcess, peObPtr->_SEGMENT.va, pb, po->_SEGMENT.cb, VMM_FLAG_FORCECACHE_READ) && (peObPtr->vaControlArea == VMM_PTR_OFFSET(f32, pb, po->_SEGMENT.oControlArea))) {
            peObPtr->_SEGMENT.cbSizeOfSegment = *(PQWORD)(pb + po->_SEGMENT.oSizeOfSegment);
            peObPtr->_SEGMENT.vaPrototypePte = *(PQWORD)(pb + po->_SEGMENT.oPrototypePte);
            peObPtr->_SEGMENT.fValid = TRUE;
            peObPtr->cb = min(peObPtr->_SEGMENT.cbSizeOfSegment, (peObPtr->cb ? peObPtr->cb : (QWORD)-1));
        }
    }
}

/*
* Filter function for VmmWinObjFile_Initialize_FileObjects.
*/
VOID VmmWinObjFile_Initialize_FileObjects_Name_FilterCB(_In_opt_ PVOID ctx, _In_ POB_SET ps, _In_ QWORD k, _In_ POB_VMMWINOBJ_FILE v)
{
    ObSet_Push(ps, v->_Reserved2);
}

VOID VmmWinObjFile_Initialize_FileObjects_SectionObjectPointers_FilterSetCB(_In_opt_ PVOID ctx, _In_ POB_SET ps, _In_ QWORD k, _In_ POB_VMMWINOBJ_FILE v)
{
    ObSet_Push(ps, v->_Reserved3);
}

VOID VmmWinObjFile_Initialize_SectionObjectPointers(_In_ VMM_HANDLE H, _In_ POB_VMMWINOBJ_CONTEXT ctx, _In_ PVMM_PROCESS pSystemProcess, _Inout_ POB_SET psvaSectionObjectPointers)
{
    BOOL f, f32 = H->vmm.f32;
    BYTE pb[0x100];
    QWORD va, vaPtr;
    DWORD dwIndex = 0;
    PVMM_OFFSET_FILE po = &H->vmm.offset.FILE;
    POB_MAP pmObSectionObjectPointers = NULL;
    POB_VMMWINOBJ_SECTION_OBJECT_POINTERS peObPtr;
    // 1: filter out already initialized _SECTION_OBJECT_POINTERS
    while((va = ObSet_GetNextByIndex(psvaSectionObjectPointers, &dwIndex))) {
        if(ObMap_ExistsKey(ctx->pmByObj, va) || ObSet_Exists(ctx->psError, va)) {
            ObSet_Remove(psvaSectionObjectPointers, va);
        }
    }
    if(!ObSet_Size(psvaSectionObjectPointers)) { goto fail; }
    // 2: fetch section object pointers:
    if(!(pmObSectionObjectPointers = ObMap_New(H, OB_MAP_FLAGS_OBJECT_OB))) { goto fail; }
    VmmCachePrefetchPages3(H, pSystemProcess, psvaSectionObjectPointers, po->_SECTION_OBJECT_POINTERS.cb, 0);
    while((vaPtr = ObSet_Pop(psvaSectionObjectPointers))) {
        if(!VmmRead2(H, pSystemProcess, vaPtr, pb, po->_SECTION_OBJECT_POINTERS.cb, VMM_FLAG_FORCECACHE_READ)) {
            ObSet_Push(ctx->psError, vaPtr);
            continue;
        }
        if(!(peObPtr = Ob_AllocEx(H, OB_TAG_OBJ_FILE, LMEM_ZEROINIT, sizeof(OB_VMMWINOBJ_SECTION_OBJECT_POINTERS), (OB_CLEANUP_CB)VmmWinObj_ObSectObjPtrs_CleanupCB, NULL))) { goto fail; }
        peObPtr->va = vaPtr;
        peObPtr->tp = VMMWINOBJ_TYPE_SECTION_OBJECT_POINTERS;
        if((va = VMM_PTR_OFFSET(f32, pb, po->_SECTION_OBJECT_POINTERS.oDataSectionObject)) && VMM_KADDR_8_16(f32, va)) {
            peObPtr->fData = TRUE;
            peObPtr->vaControlArea = va;
        }
        if((va = VMM_PTR_OFFSET(f32, pb, po->_SECTION_OBJECT_POINTERS.oImageSectionObject)) && VMM_KADDR_8_16(f32, va)) {
            peObPtr->fImage = TRUE;
            peObPtr->vaControlArea = va;
        }
        if((va = VMM_PTR_OFFSET(f32, pb, po->_SECTION_OBJECT_POINTERS.oSharedCacheMap)) && VMM_KADDR_8_16(f32, va)) {
            peObPtr->fCache = TRUE;
            peObPtr->_SHARED_CACHE_MAP.va = va;
        }
        ObMap_Push(pmObSectionObjectPointers, peObPtr->va, peObPtr);
        Ob_DECREF(peObPtr);
    }
    if(!ObMap_Size(pmObSectionObjectPointers)) { goto fail; }
    // 3: fetch sub-objects
    VmmWinObjFile_Initialize_ControlArea(H, pSystemProcess, pmObSectionObjectPointers);
    VmmWinObjFile_Initialize_SharedCacheMap(H, pSystemProcess, pmObSectionObjectPointers);
    // 4: verify correctness and push to global map
    while((peObPtr = ObMap_Pop(pmObSectionObjectPointers))) {
        f = (peObPtr->fData || peObPtr->fImage || peObPtr->fCache) &&
            !(peObPtr->fCache && !peObPtr->_SHARED_CACHE_MAP.fValid) &&
            !(peObPtr->fData && (!peObPtr->_SEGMENT.fValid || !peObPtr->cSUBSECTION)) &&
            !(peObPtr->fImage && !peObPtr->cSUBSECTION);
        if(f) {
            ObMap_Push(ctx->pmByObj, peObPtr->va, peObPtr);
        } else {
            ObSet_Push(ctx->psError, peObPtr->va);
        }
        Ob_DECREF(peObPtr);
    }
fail:
    Ob_DECREF(pmObSectionObjectPointers);
}

/*
* Initialize new file objects.
* -- H
* -- ctx
* -- pSystemProcess
* -- psvaFiles = set of virtual addresses to _FILE_OBJECTs to initialize.
* -- pmFilesResult = reults map, new valid objects are added to this map.
*/
VOID VmmWinObjFile_Initialize_FileObjects(_In_ VMM_HANDLE H, _In_ POB_VMMWINOBJ_CONTEXT ctx, _In_ PVMM_PROCESS pSystemProcess, _Inout_ POB_SET psvaFiles, _Inout_ POB_MAP pmFilesResult)
{
    BOOL f, f32 = H->vmm.f32;
    QWORD va = 0;
    BYTE pb[0x100];
    DWORD cbPath, dwIndex = 0;
    QWORD vaSectionObjectPointers, vaFileNameBuffer;
    POB_MAP pmObFiles = NULL;
    POB_SET psvaObSectionObjectPointers = NULL;
    POB_VMMWINOBJ_FILE peObFile = NULL;
    WCHAR wszNameBuffer[MAX_PATH + 1] = { 0 };
    PVMM_OFFSET_FILE po = &H->vmm.offset.FILE;
    // 1: add already existing objects to result map
    while((va = ObSet_GetNextByIndex(psvaFiles, &dwIndex))) {
        if((peObFile = (POB_VMMWINOBJ_FILE)VmmWinObj_CacheGet(H, ctx, VMMWINOBJ_TYPE_FILE, va))) {
            ObMap_Push(pmFilesResult, va, peObFile);
            ObSet_Remove(psvaFiles, va);
            Ob_DECREF(peObFile);
        }
        if(ObSet_Exists(ctx->psError, va)) {
            ObSet_Remove(psvaFiles, va);
        }
    }
    if(!ObSet_Size(psvaFiles)) {
        return;
    }
    //
    if(!(pmObFiles = ObMap_New(H, OB_MAP_FLAGS_OBJECT_OB))) { return; }
    // 1: prefetch _FILE_OBJECT
    VmmCachePrefetchPages3(H, pSystemProcess, psvaFiles, po->_FILE_OBJECT.cb, 0);
    // 2: set up initial FileObjects
    while((va = ObSet_Pop(psvaFiles))) {
        f = VmmRead2(H, pSystemProcess, va, pb, po->_FILE_OBJECT.cb, VMM_FLAG_FORCECACHE_READ) &&
            (cbPath = *(PWORD)(pb + po->_FILE_OBJECT.oFileName)) && !(cbPath & 1) &&
            (vaFileNameBuffer = VMM_PTR_OFFSET(f32, pb, po->_FILE_OBJECT.oFileNameBuffer)) &&
            (vaSectionObjectPointers = VMM_PTR_OFFSET(f32, pb, po->_FILE_OBJECT.oSectionObjectPointer)) &&
            VMM_KADDR(f32, vaFileNameBuffer) && VMM_KADDR_4_8(f32, vaSectionObjectPointers) &&
            (peObFile = Ob_AllocEx(H, OB_TAG_OBJ_FILE, LMEM_ZEROINIT, sizeof(OB_VMMWINOBJ_FILE), (OB_CLEANUP_CB)VmmWinObj_ObObjFile_CleanupCB, NULL));
        if(f) {
            peObFile->tp = VMMWINOBJ_TYPE_FILE;
            peObFile->va = va;
            peObFile->_Reserved1 = cbPath;
            peObFile->_Reserved2 = vaFileNameBuffer;
            peObFile->_Reserved3 = vaSectionObjectPointers;
            ObMap_Push(pmObFiles, va, peObFile);
            Ob_DECREF_NULL(&peObFile);
        } else {
            ObSet_Push(ctx->psError, va);
        }
    }
    // 3: fetch path and name of _FILE_OBJECT:
    VmmCachePrefetchPages5(H, pSystemProcess, pmObFiles, MAX_PATH * 2, 0, (OB_MAP_FILTERSET_PFN_CB)VmmWinObjFile_Initialize_FileObjects_Name_FilterCB);
    while((peObFile = ObMap_GetNext(pmObFiles, peObFile))) {
        // _UNICODE_STRING
        cbPath = peObFile->_Reserved1; peObFile->_Reserved1 = 0;
        vaFileNameBuffer = peObFile->_Reserved2; peObFile->_Reserved2 = 0;
        if(cbPath > MAX_PATH * 2) {
            vaFileNameBuffer += cbPath - MAX_PATH * 2;
            cbPath = MAX_PATH * 2;
        }
        if(!VmmReadWtoU(H, pSystemProcess, vaFileNameBuffer, cbPath, VMM_FLAG_FORCECACHE_READ, NULL, 0, &peObFile->uszPath, NULL, CHARUTIL_FLAG_ALLOC)) {
            if(!(peObFile->uszPath = (LPSTR)LocalAlloc(LMEM_ZEROINIT, 1))) { continue; }
        }
        peObFile->uszName = (LPSTR)CharUtil_PathSplitLast(peObFile->uszPath);
    }
    // 4: fetch _SECTION_OBJECT_POINTERS:
    psvaObSectionObjectPointers = ObMap_FilterSet(pmObFiles, NULL, (OB_MAP_FILTERSET_PFN_CB)VmmWinObjFile_Initialize_FileObjects_SectionObjectPointers_FilterSetCB);
    VmmWinObjFile_Initialize_SectionObjectPointers(H, ctx, pSystemProcess, psvaObSectionObjectPointers);
    // 5: finish - finish up section object pointers and move valid to result map and invalid to error set.
    peObFile = NULL;
    while((peObFile = ObMap_Pop(pmObFiles))) {
        peObFile->pSectionObjectPointers = (POB_VMMWINOBJ_SECTION_OBJECT_POINTERS)VmmWinObj_CacheGet(H, ctx, VMMWINOBJ_TYPE_SECTION_OBJECT_POINTERS, peObFile->_Reserved3);
        if(peObFile->pSectionObjectPointers) {
            peObFile->cb = peObFile->pSectionObjectPointers->cb;
            ObMap_Push(pmFilesResult, peObFile->va, peObFile);
            ObMap_Push(ctx->pmByObj, peObFile->va, peObFile);
        } else {
            ObSet_Push(ctx->psError, peObFile->va);
        }
        Ob_DECREF(peObFile);
    }
    Ob_DECREF(psvaObSectionObjectPointers);
    Ob_DECREF(pmObFiles);
}

/*
* Retrieve addresses of potential _FILE_OBJECTs belonging to a process either
* by retrieving from Handles or Vads.
*/
VOID VmmWinObjFile_GetProcessAddressCandidates(_In_ VMM_HANDLE H, _In_ POB_VMMWINOBJ_CONTEXT ctx, _In_ PVMM_PROCESS pProcess, _In_ POB_SET psvaFiles, _In_ BOOL fHandles, _In_ BOOL fIncludeCachedFiles)
{
    QWORD va;
    DWORD i, iMax;
    PVMMOB_MAP_VAD pmObVad = NULL;
    PVMMOB_MAP_HANDLE pmObHandle = NULL;
    if(fHandles) {
        // handle map -> file objects
        if(VmmMap_GetHandle(H, pProcess, &pmObHandle, TRUE)) {
            for(i = 0, iMax = pmObHandle->cMap; i < iMax; i++) {
                if((pmObHandle->pMap[i].dwPoolTag & 0x00ffffff) == 'liF') {
                    va = pmObHandle->pMap[i].vaObject;
                    if(fIncludeCachedFiles || !(ObMap_ExistsKey(ctx->pmByObj, va) || ObSet_Exists(ctx->psError, va))) {
                        ObSet_Push(psvaFiles, va);
                    }
                }
            }
            Ob_DECREF_NULL(&pmObHandle);
        }
    } else {
        // vad map -> file objects
        if(VmmMap_GetVad(H, pProcess, &pmObVad, VMM_VADMAP_TP_PARTIAL)) {
            for(i = 0, iMax = pmObVad->cMap; i < iMax; i++) {
                va = pmObVad->pMap[i].vaFileObject;
                if(va) {
                    if(fIncludeCachedFiles || !(ObMap_ExistsKey(ctx->pmByObj, va) || ObSet_Exists(ctx->psError, va))) {
                        ObSet_Push(psvaFiles, va);
                    }
                }
            }
            Ob_DECREF_NULL(&pmObVad);
        }
    }
}

/*
* Retrieve and initialize all _FILE_OBJECTs belonging to the process either
* by retrieving from Handles or Vads.
* -- H
* -- ctx
* -- pProcess
* -- pmObFiles
* -- fHandles = TRUE = files from handles, FALSE = files from VADs
*/
VOID VmmWinObjFile_GetByProcess_DoWork(_In_ VMM_HANDLE H, _In_ POB_VMMWINOBJ_CONTEXT ctx, _In_ PVMM_PROCESS pProcess, _In_ POB_MAP pmObFiles, _In_ BOOL fHandles)
{
    POB_SET psvaObFiles = NULL;
    PVMM_PROCESS pObSystemProcess = NULL;
    if(!(psvaObFiles = ObSet_New(H))) { return; }
    VmmWinObjFile_GetProcessAddressCandidates(H, ctx, pProcess, psvaObFiles, fHandles, TRUE);
    // Fetch and initialize file objects
    if((pObSystemProcess = VmmProcessGet(H, 4))) {
        VmmWinObjFile_Initialize_FileObjects(H, ctx, pObSystemProcess, psvaObFiles, pmObFiles);
    }
    Ob_DECREF(psvaObFiles);
    Ob_DECREF(pObSystemProcess);
}

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
BOOL VmmWinObjFile_GetByProcess(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess, _Out_ POB_MAP *ppmObFiles, _In_ BOOL fHandles)
{
    DWORD i, iMax;
    POB_MAP pmObFiles = NULL;
    POB_SET psObKeyData = NULL;
    POB_DATA pObData = NULL;
    POB_VMMWINOBJ_FILE pObFile = NULL;
    POB_VMMWINOBJ_CONTEXT ctxOb = NULL;
    if(!H->vmm.offset.FILE.fValid || !(ctxOb = VmmWinObj_GetContext(H)) || !(pmObFiles = ObMap_New(H, OB_MAP_FLAGS_OBJECT_OB))) {
        Ob_DECREF(ctxOb);
        return FALSE;
    }
    EnterCriticalSection(&ctxOb->LockUpdate);
    // 1: try fetch from already completed process workitem cache
    if((pObData = ObMap_GetByKey(ctxOb->pmByWorkitem, (fHandles ? VMMWINOBJ_WORKITEM_FILEPROCSCAN_HANDLE : VMMWINOBJ_WORKITEM_FILEPROCSCAN_VAD) | pProcess->dwPID))) {
        for(i = 0, iMax = pObData->ObHdr.cbData / sizeof(QWORD); i < iMax; i++) {
            if((pObFile = (POB_VMMWINOBJ_FILE)VmmWinObj_CacheGet(H, ctxOb, VMMWINOBJ_TYPE_FILE, pObData->pqw[i]))) {
                ObMap_Push(pmObFiles, pObFile->va, pObFile);
            }
        }
        Ob_DECREF_NULL(&pObData);
        goto success;
    }
    // 2: try fetch from process handles, and put result in process workitem cache
    VmmWinObjFile_GetByProcess_DoWork(H, ctxOb, pProcess, pmObFiles, fHandles);
    if((psObKeyData = ObMap_FilterSet(pmObFiles, NULL, ObMap_FilterSet_FilterAllKey))) {
        if((pObData = ObSet_GetAll(psObKeyData))) {
            ObMap_Push(ctxOb->pmByWorkitem, (fHandles ? VMMWINOBJ_WORKITEM_FILEPROCSCAN_HANDLE : VMMWINOBJ_WORKITEM_FILEPROCSCAN_VAD) | pProcess->dwPID, pObData);
            Ob_DECREF_NULL(&pObData);
        }
        Ob_DECREF_NULL(&psObKeyData);
    }
success:
    LeaveCriticalSection(&ctxOb->LockUpdate);
    *ppmObFiles = pmObFiles;
    Ob_DECREF(ctxOb);
    return TRUE;
}

/*
* Retrieve a file object by its virtual address.
* CALLER DECREF: return
* -- H
* -- va = virtual address of the object to retrieve.
* -- return = the object, NULL if not found in cache.
*/
_Success_(return != NULL)
POB_VMMWINOBJ_FILE VmmWinObjFile_GetByVa(_In_ VMM_HANDLE H, _In_ QWORD va)
{
    POB_VMMWINOBJ_FILE pObFile = NULL;
    POB_VMMWINOBJ_CONTEXT ctxOb = NULL;
    PVMM_PROCESS pObSystemProcess = NULL;
    POB_SET psvaObFiles = NULL;
    POB_MAP pmObFiles = NULL;
    if(!(ctxOb = VmmWinObj_GetContext(H))) { goto finish; }
    if((pObFile = (POB_VMMWINOBJ_FILE)VmmWinObj_CacheGet(H, ctxOb, VMMWINOBJ_TYPE_FILE, va))) { goto finish; }
    EnterCriticalSection(&ctxOb->LockUpdate);
    if((pObFile = (POB_VMMWINOBJ_FILE)VmmWinObj_CacheGet(H, ctxOb, VMMWINOBJ_TYPE_FILE, va))) { goto finish_lock; }
    if(!(pObSystemProcess = VmmProcessGet(H, 4))) { goto finish_lock; }
    if(!(psvaObFiles = ObSet_New(H))) { goto finish_lock; }
    if(!(pmObFiles = ObMap_New(H, OB_MAP_FLAGS_OBJECT_OB))) { goto finish_lock; }
    ObSet_Push(psvaObFiles, va);
    VmmWinObjFile_Initialize_FileObjects(H, ctxOb, pObSystemProcess, psvaObFiles, pmObFiles);
    pObFile = ObMap_Pop(pmObFiles);
finish_lock:
    LeaveCriticalSection(&ctxOb->LockUpdate);
    Ob_DECREF(pObSystemProcess);
    Ob_DECREF(psvaObFiles);
    Ob_DECREF(pmObFiles);
finish:
    Ob_DECREF(ctxOb);
    return pObFile;
}

#define VMMWINOBJFILE_GETALL_MAX_CANDIDATES         0x400

/*
* Helper function for VmmWinObjFile_GetAll / VmmWinObjFile_GetAll_DoWork:
* Try to fetch all _FILE_OBJECT with redable contents into the main cache.
*/
VOID VmmWinObjFile_GetAll_DoWork_Pool(_In_ VMM_HANDLE H, _In_ POB_VMMWINOBJ_CONTEXT ctx, _In_ PVMM_PROCESS pSystemProcess, _In_ POB_SET psvaPoolCandidates, _Inout_ POB_MAP pmFilesResult)
{
    QWORD va;
    BYTE pb[0x100];
    POB_SET psvaFileObjects = NULL;
    DWORD o, oStep, dwFileNeedle;
    oStep = H->vmm.f32 ? 0x08 : 0x10;
    dwFileNeedle = (H->vmm.offset.FILE._FILE_OBJECT.cb << 16) | 0x0005;
    if(0 == ObSet_Size(psvaPoolCandidates)) { return; }
    if(!(psvaFileObjects = ObSet_New(H))) { return; }
    VmmCachePrefetchPages3(H, pSystemProcess, psvaPoolCandidates, sizeof(pb), 0);
    while((va = ObSet_Pop(psvaPoolCandidates))) {
        if(VmmRead2(H, pSystemProcess, va, pb, sizeof(pb), VMM_FLAG_FORCECACHE_READ)) {
            for(o = 0; o < sizeof(pb); o += oStep) {
                if(dwFileNeedle == *(PDWORD)(pb + o)) {
                    ObSet_Push(psvaFileObjects, va + o);
                    break;
                }
            }
        }
    }
    VmmWinObjFile_Initialize_FileObjects(H, ctx, pSystemProcess, psvaFileObjects, pmFilesResult);
    Ob_DECREF(psvaFileObjects);
}

/*
* Work function for VmmWinObjFile_GetAll - fetch all _FILE_OBJECT with possibly
* readable contents into the main cache.
* -- H
* -- ctx
* -- pSystemProcess
*/
VOID VmmWinObjFile_GetAll_DoWork(_In_ VMM_HANDLE H, _In_ POB_VMMWINOBJ_CONTEXT ctx)
{
    DWORD i;
    POB_MAP pmObFiles = NULL;
    POB_SET psvaObFiles = NULL;
    PVMMOB_MAP_POOL pObPoolMap = NULL;
    PVMM_MAP_POOLENTRY pePool;
    PVMM_MAP_POOLENTRYTAG pePoolTag;
    PVMM_PROCESS pObSystemProcess = NULL, pObProcess = NULL;
    DWORD cbFile = H->vmm.offset.FILE._FILE_OBJECT.cb;
    if(!(psvaObFiles = ObSet_New(H))) { goto fail; }
    if(!(pmObFiles = ObMap_New(H, OB_MAP_FLAGS_OBJECT_OB))) { goto fail; }
    if(!(pObSystemProcess = VmmProcessGet(H, 4))) { goto fail; }
    // fetch candicates from pool into cache:
    if(VmmMap_GetPool(H, &pObPoolMap, TRUE) && VmmMap_GetPoolTag(H, pObPoolMap, 'File', &pePoolTag)) {
        for(i = 0; i < pePoolTag->cEntry; i++) {
            pePool = pObPoolMap->pMap + pObPoolMap->piTag2Map[pePoolTag->iTag2Map + i];
            if((pePool->cb < cbFile) || (pePool->cb > cbFile + 0x100)) { continue; }
            ObSet_Push(psvaObFiles, pePool->va);
            if(ObSet_Size(psvaObFiles) >= VMMWINOBJFILE_GETALL_MAX_CANDIDATES) {
                VmmWinObjFile_GetAll_DoWork_Pool(H, ctx, pObSystemProcess, psvaObFiles, pmObFiles);
            }
        }
        VmmWinObjFile_GetAll_DoWork_Pool(H, ctx, pObSystemProcess, psvaObFiles, pmObFiles);
    }
    // fetch candidates from process handles & vads into cache:
    while((pObProcess = VmmProcessGetNext(H, pObProcess, 0))) {
        VmmWinObjFile_GetProcessAddressCandidates(H, ctx, pObProcess, psvaObFiles, TRUE, FALSE);
        VmmWinObjFile_GetProcessAddressCandidates(H, ctx, pObProcess, psvaObFiles, FALSE, FALSE);
        if(ObSet_Size(psvaObFiles) >= VMMWINOBJFILE_GETALL_MAX_CANDIDATES) {
            VmmWinObjFile_Initialize_FileObjects(H, ctx, pObSystemProcess, psvaObFiles, pmObFiles);
        }
    }
    VmmWinObjFile_Initialize_FileObjects(H, ctx, pObSystemProcess, psvaObFiles, pmObFiles);
fail:
    Ob_DECREF(pObSystemProcess);
    Ob_DECREF(psvaObFiles);
    Ob_DECREF(pmObFiles);
    Ob_DECREF(pObPoolMap);
}

/*
* Filter function for VmmWinObjFile_GetAll.
* -- pmDst
* -- va
* -- pObject
*/
VOID VmmWinObjFile_GetAll_FilterFile(_In_ POB_MAP pmDst, _In_ QWORD va, _In_ POB_VMMWINOBJ_OBJECT pObject)
{
    if(pObject->tp == VMMWINOBJ_TYPE_FILE) {
        ObMap_Push(pmDst, va, pObject);
    }
}

/*
* Retrieve all _FILE_OBJECT that can be recovered with data from the system.
* NB! this may take a long time to complete on first run.
* CALLER DECREF: *ppmObFiles
* -- H
* -- ppmObFiles
* -- return
*/
_Success_(return)
BOOL VmmWinObjFile_GetAll(_In_ VMM_HANDLE H, _Out_ POB_MAP *ppmObFiles)
{
    POB_VMMWINOBJ_CONTEXT ctxOb = NULL;
    *ppmObFiles = NULL;
    if(!(ctxOb = VmmWinObj_GetContext(H))) { goto finish; }
    if(ctxOb->fAll) { goto finish; }
    EnterCriticalSection(&ctxOb->LockUpdate);
    if(ctxOb->fAll) {
        LeaveCriticalSection(&ctxOb->LockUpdate);
        goto finish;
    }
    VmmWinObjFile_GetAll_DoWork(H, ctxOb);
    ctxOb->fAll = TRUE;
    LeaveCriticalSection(&ctxOb->LockUpdate);
finish:
    if(ctxOb && (*ppmObFiles = ObMap_New(H, OB_MAP_FLAGS_OBJECT_OB))) {
        ObMap_Filter(ctxOb->pmByObj, *ppmObFiles, (OB_MAP_FILTER_PFN_CB)VmmWinObjFile_GetAll_FilterFile);
    }
    Ob_DECREF(ctxOb);
    return *ppmObFiles != NULL;
}



// ----------------------------------------------------------------------------
// _OBJECT TO PROCESS MAPPING:
// ----------------------------------------------------------------------------

/*
* Single-threaded worker function creating the object va -> pid mapping
* by walking all process handle tables/maps.
* -- H
* -- ctx
*/
VOID VmmWinObj_GetProcessAssociated_DoWork(_In_ VMM_HANDLE H, _In_ POB_VMMWINOBJ_CONTEXT ctx)
{
    DWORD i, dwPID;
    POB_VMMWINOBJ_FILE pObFile = NULL;
    POB_MAP pmObFile = NULL;
    POB_COUNTER pcVaToPid = NULL;
    PVMM_PROCESS pObProcess = NULL;
    PVMMOB_MAP_HANDLE pObHandleMap = NULL;
    if(ctx->pcVaToPid || H->fAbort) { return; }
    if(!(pcVaToPid = ObCounter_New(H, 0))) { return; }
    // 1: add process object handles to map:
    while((pObProcess = VmmProcessGetNext(H, pObProcess, 0))) {
        if(VmmMap_GetHandle(H, pObProcess, &pObHandleMap, FALSE)) {
            for(i = 0; i < pObHandleMap->cMap; i++) {
                ObCounter_Set(pcVaToPid, pObHandleMap->pMap[i].vaObject, pObProcess->dwPID);
            }
            Ob_DECREF_NULL(&pObHandleMap);
        }
    }
    // 2: add file object section object pointers to map.
    //    (only if there is a process mapping to be found).
    //    also missing file objects to map.
    if(VmmWinObjFile_GetAll(H, &pmObFile)) {
        while((pObFile = ObMap_GetNext(pmObFile, pObFile))) {
            dwPID = (DWORD)ObCounter_Get(pcVaToPid, pObFile->va);
            if(dwPID && pObFile->pSectionObjectPointers) {
                ObCounter_Set(pcVaToPid, pObFile->pSectionObjectPointers->va, dwPID);
            }
        }
        while((pObFile = ObMap_GetNext(pmObFile, pObFile))) {
            if(!ObCounter_Exists(pcVaToPid, pObFile->va) && pObFile->pSectionObjectPointers) {
                dwPID = (DWORD)ObCounter_Get(pcVaToPid, pObFile->pSectionObjectPointers->va);
                if(dwPID) {
                    ObCounter_Set(pcVaToPid, pObFile->va, dwPID);
                }
            }
        }
    }
    Ob_DECREF(pmObFile);
    ctx->pcVaToPid = pcVaToPid;
}

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
PVMM_PROCESS VmmWinObj_GetProcessAssociated(_In_ VMM_HANDLE H, _In_ QWORD vaObject)
{
    DWORD dwPID = 0;
    POB_VMMWINOBJ_CONTEXT ctxOb = NULL;
    if(!(ctxOb = VmmWinObj_GetContext(H))) { return NULL; }
    // create new va->pid mapping if not already created:
    if(!ctxOb->pcVaToPid) {
        EnterCriticalSection(&ctxOb->LockUpdate);
        VmmWinObj_GetProcessAssociated_DoWork(H, ctxOb);
        LeaveCriticalSection(&ctxOb->LockUpdate);
    }
    // finish up and return process (if found):
    dwPID = (DWORD)ObCounter_Get(ctxOb->pcVaToPid, vaObject);
    Ob_DECREF(ctxOb);
    return dwPID ? VmmProcessGet(H, dwPID) : NULL;
}



// ----------------------------------------------------------------------------
// _FILE_OBJECT READ:
// ----------------------------------------------------------------------------

/*
* Helper function to retrieve a Page Table Entry (PTE). Retrieval is done in a
* fairly performance intensive (non-cached) way, but it's assumed this function
* won't be heavily called.
* -- H
* -- pSystemProcess
* -- vaPteBase
* -- iPte
* -- fVmmRead = VMM_FLAGS_* flags.
* -- return = the PTE or 0 on fail.
*/
QWORD VmmWinObjFile_ReadSubsectionAndSharedCache_GetPteSubsection(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pSystemProcess, _In_ QWORD vaPteBase, _In_ QWORD iPte, _In_ QWORD fVmmRead)
{
    QWORD pte = 0;
    DWORD cbPte = H->vmm.tpMemoryModel == VMMDLL_MEMORYMODEL_X86 ? 4 : 8;
    VmmReadEx(H, pSystemProcess, vaPteBase + iPte * cbPte, (PBYTE)&pte, cbPte, NULL, fVmmRead);
    return pte;
}

/*
* Helper function to retrieve the virtual address of a _SHARED_CACHE_MAP entry.
* Retrieval is done in a performance intensive (non-cached) way, but it's
* assumed this function won't be heavily called.
* -- H
* -- pSystemProcess
* -- pFile
* -- iPte
* -- fVmmRead
* -- return = the virtual address or 0 on fail.
*/
QWORD VmmWinObjFile_ReadSubsectionAndSharedCache_GetVaSharedCache(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pSystemProcess, _In_ POB_VMMWINOBJ_FILE pFile, _In_ QWORD iPte, _In_ QWORD fVmmRead)
{
    BOOL f, f32 = H->vmm.f32;
    BYTE pbVacb[0x40];
    QWORD va, iVacb, vaVacbs, vaVacb;
    PVMM_OFFSET_FILE po = &H->vmm.offset.FILE;
    iVacb = (iPte << 12) / pFile->pSectionObjectPointers->_SHARED_CACHE_MAP.cbSectionSize;
    vaVacbs = pFile->pSectionObjectPointers->_SHARED_CACHE_MAP.vaVacbs + iVacb * (f32 ? 4 : 8);
    f = VmmRead2(H, pSystemProcess, vaVacbs, pbVacb, 8, fVmmRead) &&
        (vaVacb = VMM_PTR_OFFSET(f32, pbVacb, 0)) &&
        VMM_KADDR_4_8(f32, vaVacb) &&
        VmmRead2(H, pSystemProcess, vaVacb, pbVacb, po->_VACB.cb, fVmmRead) &&
        (pFile->pSectionObjectPointers->_SHARED_CACHE_MAP.va == VMM_PTR_OFFSET(f32, pbVacb, po->_VACB.oSharedCacheMap)) &&
        (va = VMM_PTR_OFFSET(f32, pbVacb, po->_VACB.oBaseAddress));
    return f ? (va + (iPte << 12)) : 0;
}

/*
* Read data from a single _FILE_OBJECT _SUBSECTION and/or a _SHARED_CACHE_MAP.
* Function is very similar to the VmmReadEx() function. Reading is not yet
* optimized, but the assumption is the function won't be called frequently so
* any inefficencies should only have a minor performance impact.
* -- H
* -- pSystemProcess
* -- pFile
* -- iSubsection
* -- cbOffset
* -- pb
* -- cb
* -- pcbReadOpt
* -- fVmmRead = VMM_FLAGS_* flags.
* -- fSharedCache = pFile contains a _SHARED_CACHE_MAP that should be read.
*/
VOID VmmWinObjFile_ReadSubsectionAndSharedCache(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pSystemProcess, _In_ POB_VMMWINOBJ_FILE pFile, _In_ DWORD iSubsection, _In_ QWORD cbOffset, _Out_writes_(cb) PBYTE pb, _In_ DWORD cb, _Out_opt_ PDWORD pcbReadOpt, _In_ QWORD fVmmRead, _In_ BOOL fSharedCache)
{
    BOOL fReadSubsection = FALSE, fReadSharedCacheMap = FALSE;
    DWORD cbP, cMEMs, cbRead = 0;
    PBYTE pbBuffer;
    PMEM_SCATTER pMEMs, *ppMEMs;
    QWORD i, oA, iPte;
    if(pcbReadOpt) { *pcbReadOpt = 0; }
    if(!cb) { return; }
    cMEMs = (DWORD)(((cbOffset & 0xfff) + cb + 0xfff) >> 12);
    pbBuffer = (PBYTE)LocalAlloc(LMEM_ZEROINIT, 0x2000 + cMEMs * (sizeof(MEM_SCATTER) + sizeof(PMEM_SCATTER)));
    if(!pbBuffer) {
        ZeroMemory(pb, cb);
        return;
    }
    pMEMs = (PMEM_SCATTER)(pbBuffer + 0x2000);
    ppMEMs = (PPMEM_SCATTER)(pbBuffer + 0x2000 + cMEMs * sizeof(MEM_SCATTER));
    oA = cbOffset & 0xfff;
    // prepare "middle" pages
    for(i = 0; i < cMEMs; i++) {
        ppMEMs[i] = &pMEMs[i];
        pMEMs[i].version = MEM_SCATTER_VERSION;
        pMEMs[i].qwA = 0;
        pMEMs[i].f = FALSE;
        pMEMs[i].cb = 0x1000;
        pMEMs[i].pb = pb - oA + (i << 12);
    }
    // fixup "first/last" pages
    pMEMs[0].pb = pbBuffer;
    if(cMEMs > 1) {
        pMEMs[cMEMs - 1].pb = pbBuffer + 0x1000;
    }
    // Read from _SHARED_CACHE_MAP
    if(fSharedCache) {
        for(i = 0; i < cMEMs; i++) {
            iPte = i + ((cbOffset - oA) >> 12);
            pMEMs[i].qwA = VmmWinObjFile_ReadSubsectionAndSharedCache_GetVaSharedCache(H, pSystemProcess, pFile, iPte, fVmmRead);
            if(pMEMs[i].qwA) {
                fReadSharedCacheMap = TRUE;
            }
        }
        if(fReadSharedCacheMap) {
            VmmReadScatterVirtual(H, pSystemProcess, ppMEMs, cMEMs, fVmmRead);
        }
    }
    // Read from _SUBSECTION
    if(pFile->pSectionObjectPointers->cSUBSECTION && (iSubsection < pFile->pSectionObjectPointers->cSUBSECTION)) {
        for(i = 0; i < cMEMs; i++) {
            if(pMEMs[i].f) { continue; }
            iPte = i + ((cbOffset - oA) >> 12);
            pMEMs[i].qwA = (iPte < pFile->pSectionObjectPointers->pSUBSECTION[iSubsection].dwPtesInSubsection) ? VmmWinObjFile_ReadSubsectionAndSharedCache_GetPteSubsection(H, pSystemProcess, pFile->pSectionObjectPointers->pSUBSECTION[iSubsection].vaSubsectionBase, iPte, fVmmRead) : 0;
            fReadSubsection = TRUE;
        }
        if(fReadSubsection) {
            VmmReadScatterVirtual(H, pSystemProcess, ppMEMs, cMEMs, fVmmRead | VMM_FLAG_ALTADDR_VA_PTE);
        }
    }
    // Handle Result
    for(i = 0; i < cMEMs; i++) {
        if(pMEMs[i].f) {
            cbRead += 0x1000;
        } else {
            ZeroMemory(pMEMs[i].pb, 0x1000);
        }
    }
    cbRead -= pMEMs[0].f ? 0x1000 : 0;                             // adjust byte count for first page (if needed)
    cbRead -= ((cMEMs > 1) && pMEMs[cMEMs - 1].f) ? 0x1000 : 0;    // adjust byte count for last page (if needed)
    // Handle first page
    cbP = (DWORD)min(cb, 0x1000 - oA);
    if(pMEMs[0].f) {
        memcpy(pb, pMEMs[0].pb + oA, cbP);
        cbRead += cbP;
    } else {
        ZeroMemory(pb, cbP);
    }
    // Handle last page
    if(cMEMs > 1) {
        cbP = (((cbOffset + cb) & 0xfff) ? ((cbOffset + cb) & 0xfff) : 0x1000);
        if(pMEMs[cMEMs - 1].f) {
            memcpy(pb + ((QWORD)cMEMs << 12) - oA - 0x1000, pMEMs[cMEMs - 1].pb, cbP);
            cbRead += cbP;
        } else {
            ZeroMemory(pb + ((QWORD)cMEMs << 12) - oA - 0x1000, cbP);
        }
    }
    if(pcbReadOpt) { *pcbReadOpt = cbRead; }
    LocalFree(pbBuffer);
}

/*
* Read an image _FILE_OBJECT. i.e. a PE-file with multiple sections. Reading is
* performed by reading the necessary underlying _SUBSECTIONs.
* -- H
* -- pSystemProcess
* -- pFile
* -- cbOffset
* -- pb
* -- cb
* -- fVmmRead
* -- return
*/
_Success_(return != 0)
DWORD VmmWinObjFile_ReadImage(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pSystemProcess, _In_ POB_VMMWINOBJ_FILE pFile, _In_ QWORD cbOffset, _Out_writes_(cb) PBYTE pb, _In_ DWORD cb, _In_ QWORD fVmmRead)
{
    DWORD cbRead, cbReadTotal = 0;
    DWORD iSubsection;
    DWORD cbSubsection, cbSubsectionBase, cbSubsectionEnd;
    DWORD cbSubsectionOffset, cbReadBufferOffset, cbAdjusted;
    ZeroMemory(pb, cb);
    for(iSubsection = 0; iSubsection < pFile->pSectionObjectPointers->cSUBSECTION; iSubsection++) {
        cbSubsection = 512 * pFile->pSectionObjectPointers->pSUBSECTION[iSubsection].dwNumberOfFullSectors;
        cbSubsectionBase = 512 * pFile->pSectionObjectPointers->pSUBSECTION[iSubsection].dwStartingSector;
        cbSubsectionEnd = cbSubsectionBase + cbSubsection;
        if(cbSubsectionEnd < cbOffset) { continue; }
        if(cbSubsectionBase >= cbOffset + cb) { break; }
        cbSubsectionOffset = (DWORD)max(cbSubsectionBase, cbOffset) - cbSubsectionBase;
        cbReadBufferOffset = (DWORD)(cbSubsectionBase + cbSubsectionOffset - cbOffset);
        cbAdjusted = min(cb - cbReadBufferOffset, cbSubsection - cbSubsectionOffset);
        cbRead = 0;
        VmmWinObjFile_ReadSubsectionAndSharedCache(
            H,
            pSystemProcess,
            pFile,
            iSubsection,
            cbSubsectionOffset,
            pb + cbReadBufferOffset,
            cbAdjusted,
            &cbRead,
            fVmmRead,
            FALSE
        );
        cbReadTotal += cbRead;
    }
    return cbReadTotal;
}

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
DWORD VmmWinObjFile_Read(_In_ VMM_HANDLE H, _In_ POB_VMMWINOBJ_FILE pFile, _In_ QWORD cbOffset, _Out_writes_(cb) PBYTE pb, _In_ DWORD cb, _In_ QWORD fVmmRead)
{
    DWORD cbRead = 0;
    PVMM_PROCESS pObSystemProcess = NULL;
    ZeroMemory(pb, cb);
    if(cbOffset + cb > pFile->pSectionObjectPointers->cb) {
        if((cbOffset >= pFile->pSectionObjectPointers->cb) || (pFile->pSectionObjectPointers->cb - cbOffset > 0xffffffff)) {
            return 0;
        }
        cb = (DWORD)(pFile->pSectionObjectPointers->cb - cbOffset);
    }
    if(!(pObSystemProcess = VmmProcessGet(H, 4))) { return 0; }
    if(pFile->pSectionObjectPointers->fImage) {
        cbRead = VmmWinObjFile_ReadImage(H, pObSystemProcess, pFile, cbOffset, pb, cb, fVmmRead | VMM_FLAG_ZEROPAD_ON_FAIL);
        goto finish;
    }
    if(pFile->pSectionObjectPointers->fCache && pFile->pSectionObjectPointers->_SHARED_CACHE_MAP.fValid) {
        VmmWinObjFile_ReadSubsectionAndSharedCache(H, pObSystemProcess, pFile, 0, cbOffset, pb, cb, &cbRead, fVmmRead | VMM_FLAG_ZEROPAD_ON_FAIL, TRUE);
        goto finish;
    }
    if(pFile->pSectionObjectPointers->fData && (pFile->pSectionObjectPointers->cSUBSECTION == 1)) {
        VmmWinObjFile_ReadSubsectionAndSharedCache(H, pObSystemProcess, pFile, 0, cbOffset, pb, cb, &cbRead, fVmmRead | VMM_FLAG_ZEROPAD_ON_FAIL, FALSE);
        goto finish;
    }
finish:
    Ob_DECREF(pObSystemProcess);
    return cb;
}

/*
* Read a contigious amount of file data and report the number of bytes read.
* -- H
* -- vaFileObject
* -- cbOffset
* -- pb
* -- cb
* -- fVmmRead = flags as in VMM_FLAG_*
* -- return = the number of bytes read.
*/
_Success_(return != 0)
DWORD VmmWinObjFile_ReadFromObjectAddress(_In_ VMM_HANDLE H, _In_ QWORD vaFileObject, _In_ QWORD cbOffset, _Out_writes_(cb) PBYTE pb, _In_ DWORD cb, _In_ QWORD fVmmRead)
{
    DWORD cbRead = 0;
    POB_VMMWINOBJ_FILE pObFile;
    if((pObFile = VmmWinObjFile_GetByVa(H, vaFileObject))) {
        cbRead = VmmWinObjFile_Read(H, pObFile, cbOffset, pb, cb, fVmmRead);
        Ob_DECREF(pObFile);
    }
    return cbRead;
}

/*
* Translate a file offset into a physical address.
* -- H
* -- pSystemProcess
* -- pFile
* -- iSubsection
* -- cbOffset
* -- ppa
* -- fSharedCache = pFile contains a _SHARED_CACHE_MAP that should be read.
* -- return
*/
_Success_(return)
BOOL VmmWinObjFile_GetPA_FromSubsectionAndSharedCache(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pSystemProcess, _In_ POB_VMMWINOBJ_FILE pFile, _In_ DWORD iSubsection, _In_ QWORD cbOffset, _Out_ PQWORD ppa, _In_ BOOL fSharedCache)
{
    QWORD pa = 0, va = 0, pte = 0, iPte = cbOffset >> 12;
    // Read from _SHARED_CACHE_MAP
    if(fSharedCache) {
        va = VmmWinObjFile_ReadSubsectionAndSharedCache_GetVaSharedCache(H, pSystemProcess, pFile, iPte, 0);
        if(!VmmVirt2Phys(H, pSystemProcess, va, &pa) && pa) {
            pte = pa; pa = 0;
            H->vmm.fnMemoryModel.pfnPagedRead(H, pSystemProcess, 0, pte, NULL, &pa, NULL, 0);
        }
    }
    // Read from _SUBSECTION
    if(pFile->pSectionObjectPointers->cSUBSECTION && (iSubsection < pFile->pSectionObjectPointers->cSUBSECTION) && !pa && H->vmm.fnMemoryModel.pfnPagedRead) {
        pte = (iPte < pFile->pSectionObjectPointers->pSUBSECTION[iSubsection].dwPtesInSubsection) ? VmmWinObjFile_ReadSubsectionAndSharedCache_GetPteSubsection(H, pSystemProcess, pFile->pSectionObjectPointers->pSUBSECTION[iSubsection].vaSubsectionBase, iPte, 0) : 0;
        H->vmm.fnMemoryModel.pfnPagedRead(H, pSystemProcess, 0, pte, NULL, &pa, NULL, 0);
    }
    *ppa = pa;
    return pa ? TRUE : FALSE;
}

/*
* Translate a file offset into a physical address in an image _FILE_OBJECT.
* -- H
* -- pSystemProcess
* -- pFile
* -- cbOffset
* -- pb
* -- ppa
* -- return
*/
_Success_(return)
BOOL VmmWinObjFile_GetPA_FromImage(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pSystemProcess, _In_ POB_VMMWINOBJ_FILE pFile, _In_ QWORD cbOffset, _Out_ PQWORD ppa)
{
    DWORD iSubsection;
    DWORD cbSubsection, cbSubsectionBase, cbSubsectionEnd;
    DWORD cbSubsectionOffset;
    for(iSubsection = 0; iSubsection < pFile->pSectionObjectPointers->cSUBSECTION; iSubsection++) {
        cbSubsection = 512 * pFile->pSectionObjectPointers->pSUBSECTION[iSubsection].dwNumberOfFullSectors;
        cbSubsectionBase = 512 * pFile->pSectionObjectPointers->pSUBSECTION[iSubsection].dwStartingSector;
        cbSubsectionEnd = cbSubsectionBase + cbSubsection;
        if(cbSubsectionEnd < cbOffset) { continue; }
        if(cbSubsectionBase >= cbOffset) { return FALSE; }
        cbSubsectionOffset = (DWORD)max(cbSubsectionBase, cbOffset) - cbSubsectionBase;
        return VmmWinObjFile_GetPA_FromSubsectionAndSharedCache(H, pSystemProcess, pFile, iSubsection, cbSubsectionOffset, ppa, FALSE);
    }
    return FALSE;
}

/*
* Translate a file offset into a physical address.
* -- H
* -- pFile
* -- cbOffset
* -- ppa
* -- return
*/
_Success_(return)
BOOL VmmWinObjFile_GetPA(_In_ VMM_HANDLE H, _In_ POB_VMMWINOBJ_FILE pFile, _In_ QWORD cbOffset, _Out_ PQWORD ppa)
{
    BOOL fResult = FALSE;
    PVMM_PROCESS pObSystemProcess = NULL;
    if(cbOffset > pFile->pSectionObjectPointers->cb) { goto finish; }
    if(!(pObSystemProcess = VmmProcessGet(H, 4))) { goto finish; }
    if(pFile->pSectionObjectPointers->fImage) {
        fResult = VmmWinObjFile_GetPA_FromImage(H, pObSystemProcess, pFile, cbOffset, ppa);
        goto finish;
    }
    if(pFile->pSectionObjectPointers->fCache && pFile->pSectionObjectPointers->_SHARED_CACHE_MAP.fValid) {
        fResult = VmmWinObjFile_GetPA_FromSubsectionAndSharedCache(H, pObSystemProcess, pFile, 0, cbOffset, ppa, TRUE);
        goto finish;
    }
    if(pFile->pSectionObjectPointers->fData && (pFile->pSectionObjectPointers->cSUBSECTION == 1)) {
        fResult = VmmWinObjFile_GetPA_FromSubsectionAndSharedCache(H, pObSystemProcess, pFile, 0, cbOffset, ppa, FALSE);
        goto finish;
    }

finish:
    Ob_DECREF(pObSystemProcess);
    return fResult;
}



//-----------------------------------------------------------------------------
// WINDOWS OBJECT MANAGER: INTERNAL SETUP FUNCTIONALITY BELOW:
//-----------------------------------------------------------------------------

typedef struct tdVMM_WINOBJ_SETUP_OBJECT {
    QWORD va;
    struct tdVMM_WINOBJ_SETUP_OBJECT *pParent;
    PVMM_MAP_OBJECTENTRY pParentMapEntry;
    DWORD iType;
    DWORD iLevel;
    DWORD dwId;
    DWORD dwIdDir;
    DWORD cchName;
    QWORD vaName;
    struct {
        WORD cchName;
        QWORD vaName;
        QWORD ft;
        QWORD va;       // type dependent virtual address: (SECTION: vaControlArea)
    } ExtInfo;
} VMM_WINOBJ_SETUP_OBJECT, *PVMM_WINOBJ_SETUP_OBJECT, **PPVMM_WINOBJ_SETUP_OBJECT;

typedef struct tdVMM_WINOBJ_SETUP_CONTEXT {
    PVMM_PROCESS pSystemProcess;
    POB_SET psObj[2];
    POB_SET psDirEntry[2];
    POB_SET psObjectAll;
    POB_SET psObjectDir;
    POB_SET psvaAllObj;
    POB_SET psvaPrefetch;
} VMM_WINOBJ_SETUP_CONTEXT, *PVMM_WINOBJ_SETUP_CONTEXT;

/*
* Process a single object in the initial setup phase.
*/
VOID VmmWinObjMgr_Initialize_ProcessObject(_In_ VMM_HANDLE H, _Inout_ PVMM_WINOBJ_SETUP_CONTEXT ctxInit, _In_reads_(0x70) PBYTE pb, _In_ PVMM_WINOBJ_SETUP_OBJECT pe)
{
    QWORD va;
    DWORD vaDir32[37];
    QWORD vaDir64[37];
    POBJECT_HEADER32 pHdr32;
    POBJECT_HEADER64 pHdr64;
    POBJECT_HEADER_NAME_INFO32 pName32;
    POBJECT_HEADER_NAME_INFO64 pName64;
    PUNICODE_STRING32 pus32;
    PUNICODE_STRING64 pus64;
    PVMM_WINOBJ_SETUP_OBJECT peNext;
    BYTE i, iTp;
    if(!ObSet_Push(ctxInit->psvaAllObj, pe->va)) { goto fail; }     // loop/duplicate protect
    if(H->vmm.f32) {
        pHdr32 = (POBJECT_HEADER32)(pb + 0x20);
        if(pHdr32->SecurityDescriptor && !VMM_KADDR32(pHdr32->SecurityDescriptor)) { goto fail; }
        iTp = VmmWin_ObjectTypeGetIndexFromEncoded(H, pe->va - 0x18, pHdr32->TypeIndex);
        if(iTp < 2 || iTp >= H->vmm.ObjectTypeTable.c) { goto fail; }
        if(!(pHdr32->InfoMask & 2)) { goto fail; }
        pName32 = (POBJECT_HEADER_NAME_INFO32)(pb + (pHdr32->InfoMask & 1 ? 0 : 0x10));
        if((pName32->Name.Length & 1) || pName32->Name.Length > 0x200) { goto fail; }
        if(!VMM_KADDR32(pName32->Name.Buffer)) { goto fail; }
        if(pName32->Directory) {
            if(!pe->pParent) { goto fail; }
            if(pe->pParent->va != pName32->Directory) { goto fail; }
        } else {
            if(pe->pParent) { goto fail; }
        }
        pe->iType = iTp;
        pe->vaName = pName32->Name.Buffer;
        pe->cchName = pName32->Name.Length >> 1;
        if((iTp == 3) && VmmRead(H, ctxInit->pSystemProcess, pe->va, (PBYTE)vaDir32, 37 * sizeof(DWORD))) {
            // OBJECT_TYPE == DIRECTORY
            ObSet_Push(ctxInit->psObjectDir, (QWORD)pe);
            for(i = 0; i < 37; i++) {
                if(VMM_KADDR32_4(vaDir32[i]) && (peNext = LocalAlloc(LMEM_ZEROINIT, sizeof(VMM_WINOBJ_SETUP_OBJECT)))) {
                    peNext->va = vaDir32[i];
                    peNext->pParent = pe;
                    ObSet_Push(ctxInit->psDirEntry[0], (QWORD)peNext);
                }
            }
        }
    } else {
        pHdr64 = (POBJECT_HEADER64)(pb + 0x40);
        if(pHdr64->SecurityDescriptor && !VMM_KADDR64(pHdr64->SecurityDescriptor)) { goto fail; }
        iTp = VmmWin_ObjectTypeGetIndexFromEncoded(H, pe->va - 0x30, pHdr64->TypeIndex);
        if(iTp < 2 || iTp >= H->vmm.ObjectTypeTable.c) { goto fail; }
        if(!(pHdr64->InfoMask & 2)) { goto fail; }
        pName64 = (POBJECT_HEADER_NAME_INFO64)(pb + (pHdr64->InfoMask & 1 ? 0 : 0x20));
        if((pName64->Name.Length & 1) || pName64->Name.Length > 0x200) { goto fail; }
        if(!VMM_KADDR64(pName64->Name.Buffer)) { goto fail; }
        if(pName64->Directory) {
            if(!pe->pParent) { goto fail; }
            if(pe->pParent->va != pName64->Directory) { goto fail; }
        } else {
            if(pe->pParent) { goto fail; }
        }
        pe->iType = iTp;
        pe->vaName = pName64->Name.Buffer;
        pe->cchName = pName64->Name.Length >> 1;
        if((iTp == 3) && VmmRead(H, ctxInit->pSystemProcess, pe->va, (PBYTE)vaDir64, 37 * sizeof(QWORD))) {
            // OBJECT_TYPE == DIRECTORY
            ObSet_Push(ctxInit->psObjectDir, (QWORD)pe);
            for(i = 0; i < 37; i++) {
                if(VMM_KADDR64_8(vaDir64[i]) && (peNext = LocalAlloc(LMEM_ZEROINIT, sizeof(VMM_WINOBJ_SETUP_OBJECT)))) {
                    peNext->va = vaDir64[i];
                    peNext->pParent = pe;
                    ObSet_Push(ctxInit->psDirEntry[0], (QWORD)peNext);
                }
            }
        }
    }
    // OBJECT_TYPE == _OBJECT_SYMBOLIC_LINK --> EXTENDED INFO
    if((iTp == H->vmm.ObjectTypeTable.tpSymbolicLink) && VmmRead(H, ctxInit->pSystemProcess, pe->va, pb, 0x18)) {
        pe->ExtInfo.ft = *(PQWORD)pb;
        if(H->vmm.f32) {
            pus32 = (PUNICODE_STRING32)(pb + 8);
            if(!(pus32->Length & 1) && (pus32->Length < 0x200) && VMM_KADDR32(pus32->Buffer)) {
                pe->ExtInfo.cchName = pus32->Length >> 1;
                pe->ExtInfo.vaName = pus32->Buffer;
            }
        } else {
            pus64 = (PUNICODE_STRING64)(pb + 8);
            if(!(pus64->Length & 1) && (pus64->Length < 0x200) && VMM_KADDR64(pus64->Buffer)) {
                pe->ExtInfo.cchName = pus64->Length >> 1;
                pe->ExtInfo.vaName = pus64->Buffer;
            }
        }
    }
    // OBJECT_TYPE == _OBJECT_SECTION --> EXTENDED INFO
    if((iTp == H->vmm.ObjectTypeTable.tpSection)) {
        if(VmmRead(H, ctxInit->pSystemProcess, pe->va, pb, 0x30)) {
            if(H->vmm.f32) {
                if((va = *(PDWORD)(pb + 0x14)) && VMM_KADDR32_8(va)) {
                    pe->ExtInfo.va = va;
                }
            } else {
                if((va = *(PQWORD)(pb + 0x28)) && VMM_KADDR64_16(va)) {
                    pe->ExtInfo.va = va;
                }
            }
        }
    }
    pe->iLevel = pe->pParent ? pe->pParent->iLevel + 1 : 0;
    ObSet_Push(ctxInit->psObjectAll, (QWORD)pe);
    return;
fail:
    LocalFree(pe);
}

/*
* Process a single _OBJECT_DIRECTORY_ENTRY in the initial setup phase.
*/
VOID VmmWinObjMgr_Initialize_ProcessDirectoryObjectEntry(_In_ VMM_HANDLE H, _Inout_ PVMM_WINOBJ_SETUP_CONTEXT ctxInit, _In_reads_(0x10) PBYTE pb, _In_ PVMM_WINOBJ_SETUP_OBJECT pe)
{
    QWORD vaNext, vaObject;
    PVMM_WINOBJ_SETUP_OBJECT peNext;
    if(H->vmm.f32) {
        vaNext = *(PDWORD)pb;           // _OBJECT_DIRECTORY_ENTRY.ChainLink
        vaObject = *(PDWORD)(pb + 4);   // _OBJECT_DIRECTORY_ENTRY.Object
        if(!VMM_KADDR32_4(vaObject) || (vaNext && !VMM_KADDR32_4(vaNext))) { goto fail; }
    } else {
        vaNext = *(PQWORD)pb;           // _OBJECT_DIRECTORY_ENTRY.ChainLink
        vaObject = *(PQWORD)(pb + 8);   // _OBJECT_DIRECTORY_ENTRY.Object
        if(!VMM_KADDR64_8(vaObject) || (vaNext && !VMM_KADDR64_8(vaNext))) { goto fail; }
    }
    if(!ObSet_Push(ctxInit->psvaAllObj, pe->va | 1)) { goto fail; }     // loop/duplicate protect
    pe->va = vaObject;
    ObSet_Push(ctxInit->psObj[0], (QWORD)pe);
    if(vaNext && (peNext = LocalAlloc(LMEM_ZEROINIT, sizeof(VMM_WINOBJ_SETUP_OBJECT)))) {
        peNext->va = vaNext;
        peNext->pParent = pe->pParent;
        ObSet_Push(ctxInit->psDirEntry[0], (QWORD)peNext);
    }
    return;
fail:
    LocalFree(pe);
}

VOID VmmWinObjMgr_Initialize_ObjectNameExtInfo(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pSystemProcess, _Inout_ POB_STRMAP pStrMap, _Inout_ PVMM_MAP_OBJECTENTRY pe, _In_ PVMM_WINOBJ_SETUP_OBJECT pes)
{
    pe->ExtInfo.ft = pes->ExtInfo.ft;
    pe->ExtInfo.va = pes->ExtInfo.va;
    if(pes->ExtInfo.vaName) {
        ObStrMap_Push_UnicodeBuffer(pStrMap, min(0x200, pes->ExtInfo.cchName << 1), pes->ExtInfo.vaName, &pe->ExtInfo.usz, NULL);
    } else {
        ObStrMap_PushPtrWU(pStrMap, NULL, &pe->ExtInfo.usz, NULL);
    }
}

/*
* Fetch object name for a single object
*/
_Success_(return)
BOOL VmmWinObjMgr_Initialize_ObjectName(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pSystemProcess, _Inout_ POB_STRMAP pStrMap, _Inout_ PVMM_MAP_OBJECTENTRY pe, _In_ PVMM_WINOBJ_SETUP_OBJECT pes, _In_ BOOL fForce)
{
    WCHAR wsz[0x201];
    if(pes->cchName == (DWORD)-1) { return TRUE; }
    if(pes->vaName && VmmRead2(H, pSystemProcess, pes->vaName, (PBYTE)wsz, min(0x400, pes->cchName << 1), VMM_FLAG_FORCECACHE_READ)) {
        wsz[min(0x200, pes->cchName)] = 0;
        ObStrMap_PushPtrWU(pStrMap, wsz, &pe->uszName, &pe->cbuName);
        pes->cchName = -1;
        return TRUE;
    }
    if(!pes->vaName || fForce) {
        ObStrMap_PushUU_snprintf_s(pStrMap, &pe->uszName, &pe->cbuName, "$OBJECT-%llX", pe->va);
        pes->cchName = -1;
        return TRUE;
    }
    return FALSE;
}

/*
* Lookup and set object names and other string data.
*/
_Success_(return)
BOOL VmmWinObjMgr_Initialize_ObMapLookupStr(_In_ VMM_HANDLE H, _Inout_ PVMMOB_MAP_OBJECT pMap, _Inout_ PVMM_WINOBJ_SETUP_CONTEXT ctxInit)
{
    DWORD i;
    PVMM_WINOBJ_SETUP_OBJECT pes;
    PVMM_MAP_OBJECTENTRY pe;
    POB_STRMAP pObStrMap = NULL;
    if(!(pObStrMap = ObStrMap_New(H, OB_STRMAP_FLAGS_CASE_SENSITIVE))) { return FALSE; }
    ObSet_Clear(ctxInit->psvaPrefetch);
    for(i = 0; i < pMap->cMap; i++) {
        pe = pMap->pMap + i;
        pes = (PVMM_WINOBJ_SETUP_OBJECT)pe->_Reserved;
        if(!VmmWinObjMgr_Initialize_ObjectName(H, ctxInit->pSystemProcess, pObStrMap, pe, pes, FALSE)) {
            ObSet_Push_PageAlign(ctxInit->psvaPrefetch, pes->vaName, pes->cchName << 1);
        }
        VmmWinObjMgr_Initialize_ObjectNameExtInfo(H, ctxInit->pSystemProcess, pObStrMap, pe, pes);
    }
    if(ObSet_Size(ctxInit->psvaPrefetch)) {
        VmmCachePrefetchPages(H, ctxInit->pSystemProcess, ctxInit->psvaPrefetch, 0);
        for(i = 0; i < pMap->cMap; i++) {
            pe = pMap->pMap + i;
            pes = (PVMM_WINOBJ_SETUP_OBJECT)pe->_Reserved;
            VmmWinObjMgr_Initialize_ObjectName(H, ctxInit->pSystemProcess, pObStrMap, pe, pes, TRUE);
        }
    }
    if(!ObStrMap_FinalizeAllocU_DECREF_NULL(&pObStrMap, &pMap->pbMultiText, &pMap->cbMultiText)) { return FALSE; }
    if(pMap->cMap) { pMap->pMap[0].dwHash = CharUtil_HashNameFsU("ROOT", 0); }
    for(i = 1; i < pMap->cMap; i++) {
        pe = pMap->pMap + i;
        pe->dwHash = CharUtil_HashNameFsU(pe->uszName, 0);
    }
    return TRUE;
}

int VmmWinObjMgr_Initialize_ObMapAlloc_qsort_all(const void *pqw1, const void *pqw2)
{
    PVMM_WINOBJ_SETUP_OBJECT p1 = *(PPVMM_WINOBJ_SETUP_OBJECT)pqw1;
    PVMM_WINOBJ_SETUP_OBJECT p2 = *(PPVMM_WINOBJ_SETUP_OBJECT)pqw2;
    if(!p1->pParent) { return -1; }
    if(!p2->pParent) { return 1; }
    int i = (int)(p1->pParent->dwIdDir - p2->pParent->dwIdDir);
    return i ? i : (int)(p1->va - p2->va);
}

int VmmWinObjMgr_Initialize_ObMapAlloc_qsort_dir(const void *pqw1, const void *pqw2)
{
    PVMM_WINOBJ_SETUP_OBJECT p1 = *(PPVMM_WINOBJ_SETUP_OBJECT)pqw1;
    PVMM_WINOBJ_SETUP_OBJECT p2 = *(PPVMM_WINOBJ_SETUP_OBJECT)pqw2;
    int i = (int)(p1->iLevel - p2->iLevel);
    return i ? i : (int)(p1->va - p2->va);
}

VOID VmmWinObjMgr_CallbackCleanup_ObObjectMap(PVMMOB_MAP_OBJECT pOb)
{
    LocalFree(pOb->pbMultiText);
}

/*
* Allocate an object manager map, fill it with initial (non string) data and return it.
* CALLER DECREF: return
* -- H
* -- ctxInit
* -- return
*/
_Success_(return != NULL)
PVMMOB_MAP_OBJECT VmmWinObjMgr_Initialize_ObMapAlloc(_In_ VMM_HANDLE H, _Inout_ PVMM_WINOBJ_SETUP_CONTEXT ctxInit)
{
    DWORD i, cDir, cAll, cType[256] = { 0 }, iTypeSort;
    PVMMOB_MAP_OBJECT pObMap = NULL;
    POB_DATA pObData = NULL;
    PVMM_MAP_OBJECTENTRY pe;
    PVMM_WINOBJ_SETUP_OBJECT pes;
    if(0 == (cAll = ObSet_Size(ctxInit->psObjectAll))) { return NULL; }
    if(0 == (cDir = ObSet_Size(ctxInit->psObjectDir))) { return NULL; }
    // 1: sort directories by level & va
    if(!(pObData = ObSet_GetAll(ctxInit->psObjectDir))) { return NULL; }
    qsort(pObData->pqw, cDir, sizeof(QWORD), VmmWinObjMgr_Initialize_ObMapAlloc_qsort_dir);
    for(i = 0; i < cDir; i++) {
        ((PVMM_WINOBJ_SETUP_OBJECT)pObData->pqw[i])->dwIdDir = i;
    }
    Ob_DECREF_NULL(&pObData);
    // 2: sort all entries by parent-id & va
    if(!(pObData = ObSet_GetAll(ctxInit->psObjectAll))) { return NULL; }
    qsort(pObData->pqw, cAll, sizeof(QWORD), VmmWinObjMgr_Initialize_ObMapAlloc_qsort_all);
    for(i = 0; i < cAll; i++) {
        pes = (PVMM_WINOBJ_SETUP_OBJECT)pObData->pqw[i];
        cType[pes->iType]++;
        pes->dwId = i;
    }
    Ob_DECREF_NULL(&pObData);
    // 3: alloc
    pObMap = Ob_AllocEx(H, OB_TAG_MAP_OBJECT, LMEM_ZEROINIT, sizeof(VMMOB_MAP_OBJECT) + cAll * (sizeof(VMM_MAP_OBJECTENTRY) + sizeof(DWORD)), (OB_CLEANUP_CB)VmmWinObjMgr_CallbackCleanup_ObObjectMap, NULL);
    if(!pObMap) { return NULL; }
    pObMap->cMap = cAll;
    pObMap->piTypeSort = (PDWORD)((QWORD)pObMap + sizeof(VMMOB_MAP_OBJECT) + cAll * sizeof(VMM_MAP_OBJECTENTRY));
    for(i = 1; i < H->vmm.ObjectTypeTable.c; i++) {
        pObMap->iTypeSortBase[i] = pObMap->iTypeSortBase[i-1] + cType[i-1];
    }
    // 4: populate
    while((pes = (PVMM_WINOBJ_SETUP_OBJECT)ObSet_Pop(ctxInit->psObjectAll))) {
        pe = pObMap->pMap + pes->dwId;
        pe->va = pes->va;
        pe->id = pes->dwId;
        pe->pType = H->vmm.ObjectTypeTable.h + pes->iType;
        iTypeSort = pObMap->iTypeSortBase[pes->iType] + pObMap->cType[pes->iType]++;
        pObMap->piTypeSort[iTypeSort] = pe->id;
        if(pes->pParent) {
            pe->pParent = pObMap->pMap + pes->pParent->dwId;
            pe->pParent->cChild++;
            pe->pNextByParent = pe->pParent->pChild;
            pe->pParent->pChild = pe;
        }
        pe->_Reserved = pes;
    }
    return pObMap;
}

/*
* Create an object manager map, in a single threaded context, and return it upon success.
* CALLER DECREF: return
* -- H
* -- return
*/
_Success_(return != NULL)
PVMMOB_MAP_OBJECT VmmWinObjMgr_Initialize_DoWork(_In_ VMM_HANDLE H)
{
    BOOL fResult = FALSE;
    DWORD c, i, cbHdr = H->vmm.f32 ? 0x38 : 0x70;
    QWORD vaRootDirectoryObject = 0;
    PVMM_WINOBJ_SETUP_OBJECT pes;
    VMM_WINOBJ_SETUP_CONTEXT ctxInit = { 0 };
    BYTE pb[0x70];
    PVMMOB_MAP_OBJECT pObObjectMap = NULL;
    QWORD qwScatterPre = 0, qwScatterPost = 0;
    BOOL fLog = VmmLogIsActive(H, MID_OBJECT, LOGLEVEL_6_TRACE);
    // statistics init
    if(fLog) {
        VmmLog(H, MID_OBJECT, LOGLEVEL_6_TRACE, "INIT OBJECTMAP START:");
        LcGetOption(H->hLC, LC_OPT_CORE_STATISTICS_CALL_COUNT | LC_STATISTICS_ID_READSCATTER, &qwScatterPre);
    }
    // 1: INIT
    if(!VmmWin_ObjectTypeGet(H, 3)) { goto fail; }     // ensure type table initialization
    if(!(ctxInit.pSystemProcess = VmmProcessGet(H, 4))) { goto fail; }
    if(!PDB_GetSymbolPTR(H, PDB_HANDLE_KERNEL, "ObpRootDirectoryObject", ctxInit.pSystemProcess, &vaRootDirectoryObject)) { goto fail; }
    if(!VMM_KADDR_8_16(H->vmm.f32, vaRootDirectoryObject)) { goto fail; }
    for(i = 0; i < 2; i++) {
        if(!(ctxInit.psObj[i] = ObSet_New(H))) { goto fail; }
        if(!(ctxInit.psDirEntry[i] = ObSet_New(H))) { goto fail; }
    }
    if(!(ctxInit.psObjectAll = ObSet_New(H))) { goto fail; }
    if(!(ctxInit.psObjectDir = ObSet_New(H))) { goto fail; }
    if(!(ctxInit.psvaAllObj = ObSet_New(H))) { goto fail; }
    if(!(ctxInit.psvaPrefetch = ObSet_New(H))) { goto fail; }
    if(!(pes = LocalAlloc(LMEM_ZEROINIT, sizeof(VMM_WINOBJ_SETUP_OBJECT)))) { goto fail; }
    pes->va = vaRootDirectoryObject;
    ObSet_Push(ctxInit.psObj[0], (QWORD)pes);
    // 2: FETCH objects in an efficient way minimizing number of physical device accesses.
    while(ObSet_Size(ctxInit.psObj[0]) || ObSet_Size(ctxInit.psDirEntry[0])) {
        while(ObSet_Size(ctxInit.psObj[0]) || ObSet_Size(ctxInit.psDirEntry[0])) {
            while((pes = (PVMM_WINOBJ_SETUP_OBJECT)ObSet_Pop(ctxInit.psObj[0]))) {
                if(VmmRead2(H, ctxInit.pSystemProcess, pes->va - cbHdr, pb, cbHdr, VMM_FLAG_FORCECACHE_READ)) {
                    VmmWinObjMgr_Initialize_ProcessObject(H, &ctxInit, pb, pes);
                } else {
                    ObSet_Push(ctxInit.psObj[1], (QWORD)pes);
                }
            }
            while((pes = (PVMM_WINOBJ_SETUP_OBJECT)ObSet_Pop(ctxInit.psDirEntry[0]))) {
                if(VmmRead2(H, ctxInit.pSystemProcess, pes->va, pb, 0x18, VMM_FLAG_FORCECACHE_READ)) {
                    VmmWinObjMgr_Initialize_ProcessDirectoryObjectEntry(H, &ctxInit, pb, pes);
                } else {
                    ObSet_Push(ctxInit.psDirEntry[1], (QWORD)pes);
                }
            }
        }
        // OBJECT 2nd ATTEMPT:
        if((c = ObSet_Size(ctxInit.psObj[1]))) {
            ObSet_Clear(ctxInit.psvaPrefetch);
            for(i = 0; i < c; i++) {
                ObSet_Push_PageAlign(ctxInit.psvaPrefetch, ((PVMM_WINOBJ_SETUP_OBJECT)ObSet_Get(ctxInit.psObj[1], i))->va - cbHdr, cbHdr);
            }
            VmmCachePrefetchPages(H, ctxInit.pSystemProcess, ctxInit.psvaPrefetch, 0);
            while((pes = (PVMM_WINOBJ_SETUP_OBJECT)ObSet_Pop(ctxInit.psObj[1]))) {
                if(VmmRead2(H, ctxInit.pSystemProcess, pes->va - cbHdr, pb, cbHdr, VMM_FLAG_FORCECACHE_READ)) {
                    VmmWinObjMgr_Initialize_ProcessObject(H, &ctxInit, pb, pes);
                } else {
                    LocalFree(pes);
                }
            }
        }
        // DIR ENTRY 2nd ATTEMPT:
        if((c = ObSet_Size(ctxInit.psDirEntry[1]))) {
            ObSet_Clear(ctxInit.psvaPrefetch);
            for(i = 0; i < c; i++) {
                ObSet_Push_PageAlign(ctxInit.psvaPrefetch, ((PVMM_WINOBJ_SETUP_OBJECT)ObSet_Get(ctxInit.psDirEntry[1], i))->va, 0x18);
            }
            VmmCachePrefetchPages(H, ctxInit.pSystemProcess, ctxInit.psvaPrefetch, 0);
            while((pes = (PVMM_WINOBJ_SETUP_OBJECT)ObSet_Pop(ctxInit.psDirEntry[1]))) {
                if(VmmRead2(H, ctxInit.pSystemProcess, pes->va, pb, 0x18, VMM_FLAG_FORCECACHE_READ)) {
                    VmmWinObjMgr_Initialize_ProcessDirectoryObjectEntry(H, &ctxInit, pb, pes);
                } else {
                    LocalFree(pes);
                }
            }

        }
    }
    // 3: ALLOC ObMap and populate with initial data
    if(!(pObObjectMap = VmmWinObjMgr_Initialize_ObMapAlloc(H, &ctxInit))) { goto fail; }
    // 4: STRING LOOKUP:
    if(!VmmWinObjMgr_Initialize_ObMapLookupStr(H, pObObjectMap, &ctxInit)) { goto fail; }
    Ob_INCREF(pObObjectMap);
fail:
    if(fLog) {
        LcGetOption(H->hLC, LC_OPT_CORE_STATISTICS_CALL_COUNT | LC_STATISTICS_ID_READSCATTER, &qwScatterPost);
        VmmLog(H, MID_OBJECT, LOGLEVEL_6_TRACE, "INIT OBJECTMAP END:   count=%i scatter=%lli", (pObObjectMap ? pObObjectMap->cMap : 0), qwScatterPost - qwScatterPre);
    }
    for(i = 0; i < 2; i++) {
        Ob_DECREF(ctxInit.psObj[i]);
        Ob_DECREF(ctxInit.psDirEntry[i]);
    }
    Ob_DECREF(ctxInit.psObjectAll);
    Ob_DECREF(ctxInit.psObjectDir);
    Ob_DECREF(ctxInit.psvaAllObj);
    Ob_DECREF(ctxInit.psvaPrefetch);
    Ob_DECREF(ctxInit.pSystemProcess);
    if(pObObjectMap) {
        for(i = 0; i < pObObjectMap->cMap; i++) {
            LocalFree(pObObjectMap->pMap[i]._Reserved);
            pObObjectMap->pMap[i]._Reserved = 0;
        }
    }
    return Ob_DECREF(pObObjectMap);
}



//-----------------------------------------------------------------------------
// WINDOWS OBJECT MANAGER: EXPORTED FUNCTIONALITY BELOW:
//-----------------------------------------------------------------------------

/*
* Create an object manager map and assign to the global vmm context upon success.
* CALLER DECREF: return
* -- H
* -- return
*/
PVMMOB_MAP_OBJECT VmmWinObjMgr_Initialize(_In_ VMM_HANDLE H)
{
    PVMMOB_MAP_OBJECT pObObject = NULL;
    if((pObObject = ObContainer_GetOb(H->vmm.pObCMapObjMgr))) { return pObObject; }
    EnterCriticalSection(&H->vmm.LockUpdateMap);
    if((pObObject = ObContainer_GetOb(H->vmm.pObCMapObjMgr))) {
        LeaveCriticalSection(&H->vmm.LockUpdateMap);
        return pObObject;
    }
    if(!(pObObject = VmmWinObjMgr_Initialize_DoWork(H))) {
        pObObject = Ob_AllocEx(H, OB_TAG_MAP_OBJECT, LMEM_ZEROINIT, sizeof(VMMOB_MAP_OBJECT), NULL, NULL);
    }
    ObContainer_SetOb(H->vmm.pObCMapObjMgr, pObObject);
    LeaveCriticalSection(&H->vmm.LockUpdateMap);
    return pObObject;
}



//-----------------------------------------------------------------------------
// WINDOWS OBJECT MANAGER: KERNEL DRIVER FUNCTIONALITY BELOW:
//-----------------------------------------------------------------------------

/*
* Cleanup function to be called when reference count reaches zero.
*/
VOID VmmWinObjKDrv_ObCloseCallback(_In_ PVMMOB_MAP_KDRIVER pObKDriver)
{
    LocalFree(pObKDriver->pbMultiText);
}

/*
* qsort compare function for sorting kernel drivers.
*/
int VmmWinObjKDrv_Initialize_DoWork_CmpSort(_In_ PVMM_MAP_KDRIVERENTRY a, _In_ PVMM_MAP_KDRIVERENTRY b)
{
    if(a->vaStart == b->vaStart) {
        return (a->va < b->va) ? -1 : 1;
    }
    return (a->vaStart < b->vaStart) ? -1 : 1;
}

/*
* Worker function to initialize a new kernel driver map.
* CALLER DECREF: return
* -- H
* -- return
*/
PVMMOB_MAP_KDRIVER VmmWinObjKDrv_Initialize_DoWork(_In_ VMM_HANDLE H)
{
    BOOL f32 = H->vmm.f32;
    DWORD i, j, cDriver = 0, iObMapDriverBase;
    PVMM_PROCESS pObSystemProcess = NULL;
    PVMMOB_MAP_KDRIVER pObDriverMap = NULL;
    PVMMOB_MAP_OBJECT pObObjMap = NULL;
    PVMM_MAP_OBJECTENTRY peObj;
    PVMM_MAP_KDRIVERENTRY pe;
    POB_SET psObPrefetch = NULL;
    POB_STRMAP psmObText = NULL;
    BYTE pbBuffer[sizeof(DRIVER_OBJECT64)];
    PDRIVER_OBJECT32 pD32 = (PDRIVER_OBJECT32)pbBuffer;
    PDRIVER_OBJECT64 pD64 = (PDRIVER_OBJECT64)pbBuffer;
    QWORD qwScatterPre = 0, qwScatterPost = 0;
    BOOL fLog = VmmLogIsActive(H, MID_OBJECT, LOGLEVEL_6_TRACE);
    // statistics init
    if(fLog) {
        VmmLog(H, MID_OBJECT, LOGLEVEL_6_TRACE, "INIT KDRIVERMAP START:");
        LcGetOption(H->hLC, LC_OPT_CORE_STATISTICS_CALL_COUNT | LC_STATISTICS_ID_READSCATTER, &qwScatterPre);
    }
    // 1: pre-init
    if(!(pObSystemProcess = VmmProcessGet(H, 4))) { goto fail; }
    if(!(psObPrefetch = ObSet_New(H))) { goto fail; }
    if(!(psmObText = ObStrMap_New(H, OB_STRMAP_FLAGS_CASE_SENSITIVE))) { goto fail; }
    if(!VmmMap_GetObject(H, &pObObjMap)) { goto fail; }
    // 2: alloc object
    cDriver = pObObjMap->cType[H->vmm.ObjectTypeTable.tpDriver];
    pObDriverMap = Ob_AllocEx(H, OB_TAG_MAP_KDRIVER, LMEM_ZEROINIT, sizeof(VMMOB_MAP_KDRIVER) + cDriver * sizeof(VMM_MAP_KDRIVERENTRY), (OB_CLEANUP_CB)VmmWinObjKDrv_ObCloseCallback, NULL);
    if(!pObDriverMap) { goto fail; }
    pObDriverMap->cMap = cDriver;
    // 3: get initial data from object map and prefetch
    iObMapDriverBase = pObObjMap->iTypeSortBase[H->vmm.ObjectTypeTable.tpDriver];
    for(i = 0; i < cDriver; i++) {
        pe = pObDriverMap->pMap + i;
        peObj = pObObjMap->pMap + pObObjMap->piTypeSort[iObMapDriverBase + i];
        ObSet_Push_PageAlign(psObPrefetch, peObj->va, sizeof(DRIVER_OBJECT64));
        ObStrMap_PushPtrUU(psmObText, peObj->uszName, &pe->uszName, NULL);
        pe->va = peObj->va;
        pe->dwHash = peObj->dwHash;
    }
    VmmCachePrefetchPages(H, pObSystemProcess, psObPrefetch, 0);
    ObSet_Clear(psObPrefetch);
    // 4: fetch driver objects and populate
    for(i = 0; i < cDriver; i++) {
        pe = pObDriverMap->pMap + i;
        if(!VmmRead2(H, pObSystemProcess, pe->va, pbBuffer, (f32 ? sizeof(DRIVER_OBJECT32) : sizeof(DRIVER_OBJECT64)), VMM_FLAG_FORCECACHE_READ)) { continue; }
        if(f32) {
            if(VMM_KADDR32(pD32->DriverStart) && (pD32->DriverSize < 0x10000000)) {
                pe->vaStart = pD32->DriverStart;
                pe->cbDriverSize = pD32->DriverSize;
            }
            pe->vaDeviceObject = VMM_KADDR32_8(pD32->DeviceObject) ? pD32->DeviceObject : 0;
            for(j = 0; j < 28; j++) {
                pe->MajorFunction[j] = pD32->MajorFunction[j];
            }
            ObStrMap_Push_UnicodeObject(psmObText, TRUE, (QWORD)pD32->DriverExtension + 0x0c, &pe->uszServiceKeyName, NULL);
            ObStrMap_Push_UnicodeBuffer(psmObText, pD32->DriverName.Length, pD32->DriverName.Buffer, &pe->uszPath, NULL);
        } else {
            if(VMM_KADDR64(pD64->DriverStart) && (pD64->DriverSize < 0x10000000)) {
                pe->vaStart = pD64->DriverStart;
                pe->cbDriverSize = pD64->DriverSize;
            }
            pe->vaDeviceObject = VMM_KADDR64_16(pD64->DeviceObject) ? pD64->DeviceObject : 0;
            for(j = 0; j < 28; j++) {
                pe->MajorFunction[j] = pD64->MajorFunction[j];
            }
            ObStrMap_Push_UnicodeObject(psmObText, FALSE, pD64->DriverExtension + 0x18, &pe->uszServiceKeyName, NULL);
            ObStrMap_Push_UnicodeBuffer(psmObText, pD64->DriverName.Length, pD64->DriverName.Buffer, &pe->uszPath, NULL);
        }
    }
    if(!ObStrMap_FinalizeAllocU_DECREF_NULL(&psmObText, &pObDriverMap->pbMultiText, &pObDriverMap->cbMultiText)) { goto fail; }
    for(i = 0; i < cDriver; i++) {
        pe = pObDriverMap->pMap + i;
        if(!pe->uszName) { pe->uszName = (LPSTR)pObDriverMap->pbMultiText; }
        if(!pe->uszPath) { pe->uszPath = (LPSTR)pObDriverMap->pbMultiText; }
        if(!pe->uszServiceKeyName) { pe->uszServiceKeyName = (PBYTE)pObDriverMap->pbMultiText; }
    }
    qsort(pObDriverMap->pMap, pObDriverMap->cMap, sizeof(VMM_MAP_KDRIVERENTRY), (int(*)(void const *, void const *))VmmWinObjKDrv_Initialize_DoWork_CmpSort);
    Ob_INCREF(pObDriverMap);
fail:
    if(fLog) {
        LcGetOption(H->hLC, LC_OPT_CORE_STATISTICS_CALL_COUNT | LC_STATISTICS_ID_READSCATTER, &qwScatterPost);
        VmmLog(H, MID_OBJECT, LOGLEVEL_6_TRACE, "INIT KDRIVERMAP END:   count=%i scatter=%lli", (pObDriverMap ? pObDriverMap->cMap : 0), qwScatterPost - qwScatterPre);
    }
    Ob_DECREF(pObSystemProcess);
    Ob_DECREF(psObPrefetch);
    Ob_DECREF(psmObText);
    Ob_DECREF(pObObjMap);
    return Ob_DECREF(pObDriverMap);
}

/*
* Create an kernel driver map and assign to the global vmm context upon success.
* CALLER DECREF: return
* -- H
* -- return
*/
PVMMOB_MAP_KDRIVER VmmWinObjKDrv_Initialize(_In_ VMM_HANDLE H)
{
    PVMMOB_MAP_KDRIVER pObKDriver = NULL;
    if((pObKDriver = ObContainer_GetOb(H->vmm.pObCMapKDriver))) { return pObKDriver; }
    EnterCriticalSection(&H->vmm.LockUpdateMap);
    if((pObKDriver = ObContainer_GetOb(H->vmm.pObCMapKDriver))) {
        LeaveCriticalSection(&H->vmm.LockUpdateMap);
        return pObKDriver;
    }
    if(!(pObKDriver = VmmWinObjKDrv_Initialize_DoWork(H))) {
        pObKDriver = Ob_AllocEx(H, OB_TAG_MAP_KDRIVER, LMEM_ZEROINIT, sizeof(VMMOB_MAP_KDRIVER), NULL, NULL);
    }
    ObContainer_SetOb(H->vmm.pObCMapKDriver, pObKDriver);
    LeaveCriticalSection(&H->vmm.LockUpdateMap);
    return pObKDriver;
}



//-----------------------------------------------------------------------------
// WINDOWS OBJECT MANAGER: KERNEL DEVICE FUNCTIONALITY BELOW:
//-----------------------------------------------------------------------------

typedef struct tdVMMWINDEV_INIT_CONTEXT {
    PVMM_PROCESS pSystemProcess;
    PVMMOB_MAP_OBJECT pObjectMap;
    PVMMOB_MAP_KDRIVER pDriverMap;
    POB_STRMAP psmDevice;
    POB_MAP pmDevice;
} VMMWINDEV_INIT_CONTEXT, *PVMMWINDEV_INIT_CONTEXT;

/*
* Add a new device to the device initialization context. If the device already
* is added this function will fail.
*/
_Success_(return)
BOOL VmmWinObjKDev_Initialize_X_AddDevice(
    _In_ VMM_HANDLE H,
    _In_ PVMMWINDEV_INIT_CONTEXT ctx,
    _In_ QWORD va,
    _In_opt_ PVMM_MAP_KDRIVERENTRY peDriver,
    _In_opt_ PVMM_MAP_OBJECTENTRY peObject
) {
    PVMM_MAP_KDEVICEENTRY pe;
    if(!ObMap_ExistsKey(ctx->pmDevice, va) && (pe = LocalAlloc(LMEM_ZEROINIT, sizeof(VMM_MAP_KDEVICEENTRY)))) {
        pe->va = va;
        pe->pDriver = peDriver;
        pe->pObject = peObject;
        if(ObMap_Push(ctx->pmDevice, pe->va, pe)) {
            return TRUE;
        }
        LocalFree(pe);
    }
    return FALSE;
}

/*
* Fetch and add initial device object data from driver and object maps.
*/
VOID VmmWinObjKDev_Initialize_1_CreateFromDriverAndObject(_In_ VMM_HANDLE H, _In_ PVMMWINDEV_INIT_CONTEXT ctx)
{
    DWORD i, cObjDev, iObjDevBase;
    PVMM_MAP_KDEVICEENTRY pe;
    PVMM_MAP_OBJECTENTRY peObject;
    PVMM_MAP_KDRIVERENTRY peDriver;
    // 1: add devices from driver map
    for(i = 0; i < ctx->pDriverMap->cMap; i++) {
        peDriver = ctx->pDriverMap->pMap + i;
        if(peDriver->vaDeviceObject) {
            VmmWinObjKDev_Initialize_X_AddDevice(H, ctx, peDriver->vaDeviceObject, peDriver, NULL);
        }
    }
    // 2: add/update devices from object map
    cObjDev = ctx->pObjectMap->cType[H->vmm.ObjectTypeTable.tpDevice];
    iObjDevBase = ctx->pObjectMap->iTypeSortBase[H->vmm.ObjectTypeTable.tpDevice];
    for(i = 0; i < cObjDev; i++) {
        peObject = ctx->pObjectMap->pMap + ctx->pObjectMap->piTypeSort[iObjDevBase + i];
        if((pe = ObMap_GetByKey(ctx->pmDevice, peObject->va))) {
            pe->pObject = peObject;
        } else {
            VmmWinObjKDev_Initialize_X_AddDevice(H, ctx, peObject->va, NULL, peObject);
        }
    }
}

/*
* Fetch device object data from memory (and also add new devices found).
*/
VOID VmmWinObjKDev_Initialize_2_FetchAndCreate(_In_ VMM_HANDLE H, _In_ PVMMWINDEV_INIT_CONTEXT ctx)
{
    QWORD va;
    LPSTR szDeviceType;
    BYTE pbDevice[sizeof(DEVICE_OBJECT64)];
    PDEVICE_OBJECT32 po32 = (PDEVICE_OBJECT32)pbDevice;
    PDEVICE_OBJECT64 po64 = (PDEVICE_OBJECT64)pbDevice;
    PVMM_MAP_KDEVICEENTRY pe;
    POB_SET psPrefetch1 = NULL, psPrefetch2 = NULL, psTMP;
    DWORD cbDevice = H->vmm.f32 ? sizeof(DEVICE_OBJECT32) : sizeof(DEVICE_OBJECT64);
    if(!(psPrefetch1 = ObSet_New(H))) { goto fail; }
    if(!(psPrefetch2 = ObMap_FilterSet(ctx->pmDevice, NULL, ObMap_FilterSet_FilterAllKey))) { goto fail; }
    while(ObSet_Size(psPrefetch2)) {
        psTMP = psPrefetch2; psPrefetch2 = psPrefetch1; psPrefetch1 = psTMP;    // swap address/prefetch sets
        VmmCachePrefetchPages3(H, ctx->pSystemProcess, psPrefetch1, cbDevice, 0);
        while((va = ObSet_Pop(psPrefetch1))) {
            if(!(pe = ObMap_GetByKey(ctx->pmDevice, va))) { goto fail_entry; }
            if(!VmmRead2(H, ctx->pSystemProcess, va, pbDevice, cbDevice, VMM_FLAG_FORCECACHE_READ)) { goto fail_entry; }
            if(H->vmm.f32) {
                if(po32->Type != 3) { goto fail_entry; }
                if(po32->Size < sizeof(DEVICE_OBJECT32)) { goto fail_entry; }
                if(!pe->pDriver) {
                    pe->pDriver = VmmMap_GetKDriverEntry(H, ctx->pDriverMap, po32->DriverObject);
                }
                if(!pe->pDriver) { goto fail_entry; }
                if(po32->DriverObject != pe->pDriver->va) { goto fail_entry; }
                pe->dwDeviceType = po32->DeviceType;
                if(VMM_KADDR32_8(po32->NextDevice)) {
                    if(VmmWinObjKDev_Initialize_X_AddDevice(H, ctx, po32->NextDevice, pe->pDriver, NULL)) {
                        ObSet_Push(psPrefetch2, po32->NextDevice);
                    }
                }
                if(VMM_KADDR32_8(po32->AttachedDevice)) {
                    pe->vaAttachedDevice = po32->AttachedDevice;
                    if(VmmWinObjKDev_Initialize_X_AddDevice(H, ctx, po32->AttachedDevice, NULL, NULL)) {
                        ObSet_Push(psPrefetch2, po32->AttachedDevice);
                    }
                }
                if(VMM_KADDR32_8(po32->Vpb)) {
                    pe->_Reserved_vaVpb = po32->Vpb;
                }
            } else {
                if(po64->Type != 3) { goto fail_entry; }
                if(po64->Size < sizeof(DEVICE_OBJECT64)) { goto fail_entry; }
                if(!pe->pDriver) {
                    pe->pDriver = VmmMap_GetKDriverEntry(H, ctx->pDriverMap, po64->DriverObject);
                }
                if(!pe->pDriver) { goto fail_entry; }
                if(po64->DriverObject != pe->pDriver->va) { goto fail_entry; }
                pe->dwDeviceType = po64->DeviceType;
                if(VMM_KADDR64_16(po64->NextDevice)) {
                    if(VmmWinObjKDev_Initialize_X_AddDevice(H, ctx, po64->NextDevice, pe->pDriver, NULL)) {
                        ObSet_Push(psPrefetch2, po64->NextDevice);
                    }
                }
                if(VMM_KADDR64_16(po64->AttachedDevice)) {
                    pe->vaAttachedDevice = po64->AttachedDevice;
                    if(VmmWinObjKDev_Initialize_X_AddDevice(H, ctx, po64->AttachedDevice, NULL, NULL)) {
                        ObSet_Push(psPrefetch2, po64->AttachedDevice);
                    }
                }
                if(VMM_KADDR64_16(po64->Vpb)) {
                    pe->_Reserved_vaVpb = po64->Vpb;
                }
            }
            // add device type string:
            szDeviceType = (pe->dwDeviceType < sizeof(FILE_DEVICE_STR) / sizeof(LPSTR)) ? (LPSTR)FILE_DEVICE_STR[pe->dwDeviceType] : "---";
            ObStrMap_PushPtrAU(ctx->psmDevice, szDeviceType, &pe->szDeviceType, NULL);
            continue;
fail_entry:
            ObMap_RemoveByKey(ctx->pmDevice, va);
            VmmLog(H, MID_OBJECT, LOGLEVEL_4_VERBOSE, "_DEVICE_OBJECT FAIL: va=%llx", va);
        }
    }
fail:
    Ob_DECREF(psPrefetch1);
    Ob_DECREF(psPrefetch2);
}

VOID VmmWinObjKDev_Initialize_3_AttachAndSort_FilterSet(_In_ QWORD k, _In_ PVOID v, _Inout_ POB_SET ps)
{
    if(!((PVMM_MAP_KDEVICEENTRY)v)->_Reserved_vaTopDevice) {
        ObSet_Push(ps, k);
    }
}

int VmmWinObjKDev_Initialize_3_AttachAndSort_CmpSort(_In_ POB_MAP_ENTRY e1, _In_ POB_MAP_ENTRY e2)
{
    PVMM_MAP_KDEVICEENTRY pe1 = (PVMM_MAP_KDEVICEENTRY)e1->v;
    PVMM_MAP_KDEVICEENTRY pe2 = (PVMM_MAP_KDEVICEENTRY)e2->v;
    QWORD v1 = pe1->_Reserved_vaTopDevice + pe1->iDepth;
    QWORD v2 = pe2->_Reserved_vaTopDevice + pe2->iDepth;
    if(v1 < v2) { return -1; }
    if(v1 > v2) { return 1; }
    return 0;
}

/*
* Attach device objects to eachother (if possible) and sort the resulting map.
*/
VOID VmmWinObjKDev_Initialize_3_AttachAndSort(_In_ VMM_HANDLE H, _In_ PVMMWINDEV_INIT_CONTEXT ctx)
{
    QWORD va;
    DWORD cLoopProtectMaxDepth = 32;
    POB_SET ps1 = NULL, ps2 = NULL, psTMP;
    PVMM_MAP_KDEVICEENTRY pe = NULL, peAttach;
    // 1: init:
    if(!(ps1 = ObSet_New(H))) { goto fail; }
    if(!(ps2 = ObSet_New(H))) { goto fail; }
    // 2: mark top devices & get remaining (non-top) devices:
    while((pe = ObMap_GetNext(ctx->pmDevice, pe))) {
        if(pe->vaAttachedDevice) {
            ObSet_Push(ps1, pe->va);
        } else {
            pe->_Reserved_vaTopDevice = pe->va;
        }
    }
    // 3: drain remaining devices iteratively:
    while(ObSet_Size(ps1) && --cLoopProtectMaxDepth) {
        while((va = ObSet_Pop(ps1))) {
            if(!(pe = ObMap_GetByKey(ctx->pmDevice, va))) {
                continue;
            }
            if(!(peAttach = ObMap_GetByKey(ctx->pmDevice, pe->vaAttachedDevice))) {
                continue;
            }
            if(peAttach->_Reserved_vaTopDevice) {
                pe->_Reserved_vaTopDevice = peAttach->_Reserved_vaTopDevice;
                pe->iDepth = peAttach->iDepth + 1;
            } else {
                ObSet_Push(ps2, va);
            }
        }
        psTMP = ps1; ps1 = ps2; ps2 = psTMP;
    }
    // 4: sort
    ObMap_SortEntryIndex(ctx->pmDevice, VmmWinObjKDev_Initialize_3_AttachAndSort_CmpSort);
fail:
    Ob_DECREF(ps1);
    Ob_DECREF(ps2);
}

VOID VmmWinObjKDev_Initialize_4_FetchVpb_FilterSet(_In_opt_ PVOID ctx, _In_ POB_SET ps, _In_ QWORD k, _In_ PVMM_MAP_KDEVICEENTRY v)
{
    if(v->_Reserved_vaVpb) {
        ObSet_Push(ps, v->_Reserved_vaVpb);
    }
}

/*
* Fetch and process any volume parameter blocks (VPBs) for additional info.
*/
VOID VmmWinObjKDev_Initialize_4_FetchVpb(_In_ VMM_HANDLE H, _In_ PVMMWINDEV_INIT_CONTEXT ctx)
{
    POB_SET psPrefetch = NULL;
    BYTE pbVpb[sizeof(VPB64)];
    PVPB32 po32 = (PVPB32)pbVpb;
    PVPB64 po64 = (PVPB64)pbVpb;
    DWORD cbVpb = H->vmm.f32 ? sizeof(VPB32) : sizeof(VPB64);
    PVMM_MAP_KDEVICEENTRY pe = NULL;
    LPWSTR wszVolumeInfo;
    QWORD vaVpb;
    WORD wZERO = 0;
    // 1: prefetch vpb
    if((psPrefetch = ObMap_FilterSet(ctx->pmDevice, NULL, (OB_MAP_FILTERSET_PFN_CB)VmmWinObjKDev_Initialize_4_FetchVpb_FilterSet))) {
        VmmCachePrefetchPages3(H, ctx->pSystemProcess, psPrefetch, cbVpb, 0);
        Ob_DECREF_NULL(&psPrefetch);
    }
    // 2: iterate all object and fetch vpb if required.
    while((pe = ObMap_GetNext(ctx->pmDevice, pe))) {
        vaVpb = pe->_Reserved_vaVpb;
        pe->vaFileSystemDevice = 0;
        pe->uszVolumeInfo = NULL;
        wszVolumeInfo = (LPWSTR)&wZERO;
        if(VmmRead2(H, ctx->pSystemProcess, vaVpb, pbVpb, cbVpb, VMM_FLAG_FORCECACHE_READ)) {
            if(H->vmm.f32) {
                if((po32->RealDevice == pe->va) && VMM_KADDR32_8(po32->DeviceObject)) {
                    pe->vaFileSystemDevice = po32->DeviceObject;
                    po32->VolumeLabel[31] = 0;
                    wszVolumeInfo = po32->VolumeLabel;
                }
            } else {
                if((po64->RealDevice == pe->va) && VMM_KADDR64_16(po64->DeviceObject)) {
                    pe->vaFileSystemDevice = po64->DeviceObject;
                    po64->VolumeLabel[31] = 0;
                    wszVolumeInfo = po64->VolumeLabel;
                }
            }
        }
        ObStrMap_PushPtrWU(ctx->psmDevice, wszVolumeInfo, &pe->uszVolumeInfo, NULL);
    }
}

VOID VmmWinObjKDev_CallbackCleanup_ObMapKDevice(PVMMOB_MAP_KDEVICE pOb)
{
    Ob_DECREF(pOb->pMapDriver);
    Ob_DECREF(pOb->pMapObject);
    LocalFree(pOb->pbMultiText);
}

/*
* Create the PVMMOB_MAP_KDEVICE map from device initialization data.
* CALLER DECREF: return
* -- H
* -- ctx
* -- return
*/
_Success_(return != NULL)
PVMMOB_MAP_KDEVICE VmmWinObjKDev_Initialize_5_CreateMap(_In_ VMM_HANDLE H, _In_ PVMMWINDEV_INIT_CONTEXT ctx)
{
    DWORD i, cDevice;
    PVMMOB_MAP_KDEVICE pObMap = NULL;
    PVMM_MAP_KDEVICEENTRY peSrc, peDst;
    cDevice = ObMap_Size(ctx->pmDevice);
    pObMap = Ob_AllocEx(
        H,
        OB_TAG_MAP_KDEVICE,
        LMEM_ZEROINIT,
        sizeof(VMMOB_MAP_KDEVICE) + cDevice * sizeof(VMM_MAP_KDEVICEENTRY),
        (OB_CLEANUP_CB)VmmWinObjKDev_CallbackCleanup_ObMapKDevice,
        NULL);
    if(!pObMap) { return NULL; }
    if(!ObStrMap_FinalizeAllocU_DECREF_NULL(&ctx->psmDevice, &pObMap->pbMultiText, &pObMap->cbMultiText)) {
        Ob_DECREF(pObMap);
        return NULL;
    }
    pObMap->pMapDriver = Ob_INCREF(ctx->pDriverMap);
    pObMap->pMapObject = Ob_INCREF(ctx->pObjectMap);
    pObMap->cMap = cDevice;
    for(i = 0; i < cDevice; i++) {
        peDst = pObMap->pMap + i;
        peSrc = ObMap_GetByIndex(ctx->pmDevice, i);
        memcpy(peDst, peSrc, sizeof(VMM_MAP_KDEVICEENTRY));
    }
    return pObMap;
}

/*
* Worker function to initialize a new kernel device map.
* CALLER DECREF: return
* -- H
* -- return
*/
PVMMOB_MAP_KDEVICE VmmWinObjKDev_Initialize_DoWork(_In_ VMM_HANDLE H)
{
    BOOL f32 = H->vmm.f32;
    VMMWINDEV_INIT_CONTEXT ctx = { 0 };
    PVMMOB_MAP_KDEVICE pObDeviceMap = NULL;
    QWORD qwScatterPre = 0, qwScatterPost = 0;
    BOOL fLog = VmmLogIsActive(H, MID_OBJECT, LOGLEVEL_6_TRACE);
    // statistics init
    if(fLog) {
        VmmLog(H, MID_OBJECT, LOGLEVEL_6_TRACE, "INIT KDEVICEMAP START:");
        LcGetOption(H->hLC, LC_OPT_CORE_STATISTICS_CALL_COUNT | LC_STATISTICS_ID_READSCATTER, &qwScatterPre);
    }
    // init context
    if(!(ctx.pSystemProcess = VmmProcessGet(H, 4))) { goto fail; }
    if(!VmmMap_GetObject(H, &ctx.pObjectMap)) { goto fail; }
    if(!VmmMap_GetKDriver(H, &ctx.pDriverMap)) { goto fail; }
    if(!(ctx.pmDevice = ObMap_New(H, OB_MAP_FLAGS_OBJECT_LOCALFREE))) { goto fail; }
    if(!(ctx.psmDevice = ObStrMap_New(H, OB_STRMAP_FLAGS_CASE_SENSITIVE))) { goto fail; }
    // create, fetch, attach, sort and create map
    VmmWinObjKDev_Initialize_1_CreateFromDriverAndObject(H, &ctx);
    VmmWinObjKDev_Initialize_2_FetchAndCreate(H, &ctx);
    VmmWinObjKDev_Initialize_3_AttachAndSort(H, &ctx);
    VmmWinObjKDev_Initialize_4_FetchVpb(H, &ctx);
    pObDeviceMap = VmmWinObjKDev_Initialize_5_CreateMap(H, &ctx);
fail:
    if(fLog) {
        LcGetOption(H->hLC, LC_OPT_CORE_STATISTICS_CALL_COUNT | LC_STATISTICS_ID_READSCATTER, &qwScatterPost);
        VmmLog(H, MID_OBJECT, LOGLEVEL_6_TRACE, "INIT KDEVICEMAP END:   count=%i scatter=%lli", (pObDeviceMap ? pObDeviceMap->cMap : 0), qwScatterPost - qwScatterPre);
    }
    Ob_DECREF(ctx.pmDevice);
    Ob_DECREF(ctx.psmDevice);
    Ob_DECREF(ctx.pObjectMap);
    Ob_DECREF(ctx.pDriverMap);
    Ob_DECREF(ctx.pSystemProcess);
    return pObDeviceMap;
}

/*
* Create an kernel device map and assign to the global vmm context upon success.
* CALLER DECREF: return
* -- H
* -- return
*/
PVMMOB_MAP_KDEVICE VmmWinObjKDev_Initialize(_In_ VMM_HANDLE H)
{
    PVMMOB_MAP_KDEVICE pObKDevice = NULL;
    if((pObKDevice = ObContainer_GetOb(H->vmm.pObCMapKDevice))) { return pObKDevice; }
    EnterCriticalSection(&H->vmm.LockUpdateMap);
    if((pObKDevice = ObContainer_GetOb(H->vmm.pObCMapKDevice))) {
        LeaveCriticalSection(&H->vmm.LockUpdateMap);
        return pObKDevice;
    }
    if(!(pObKDevice = VmmWinObjKDev_Initialize_DoWork(H))) {
        pObKDevice = Ob_AllocEx(H, OB_TAG_MAP_KDEVICE, LMEM_ZEROINIT, sizeof(VMMOB_MAP_KDEVICE), NULL, NULL);
    }
    ObContainer_SetOb(H->vmm.pObCMapKDevice, pObKDevice);
    LeaveCriticalSection(&H->vmm.LockUpdateMap);
    return pObKDevice;
}



//-----------------------------------------------------------------------------
// WINDOWS OBJECT MANAGER: OBJECT DISPLAY FUNCTIONALITY BELOW:
//-----------------------------------------------------------------------------

#define VMMWINOBJDISPLAY_DEFAULT_OBJECT_MEMSIZE     0x400

typedef struct tdOB_OBJECT_DISPLAY {
    OB ObHdr;
    QWORD va;
    DWORD cbType;
    DWORD cbObj;                // -1 = failed fetch
    DWORD cbHdr;                // -1 = failed fetch
    POB_COMPRESSED pdcObj;
    POB_COMPRESSED pdcHdr;
} OB_OBJECT_DISPLAY, *POB_OBJECT_DISPLAY;

/*
* Windows Object Display cleanup function to be called when reference count reaches zero.
* -- pObCompressed
*/
VOID _VmmWinObjDisplay_ObCloseCallback(_In_ POB_OBJECT_DISPLAY pObObjectDisplay)
{
    Ob_DECREF(pObObjectDisplay->pdcObj);
    Ob_DECREF(pObObjectDisplay->pdcHdr);
}

/*
* Retrieve a display object representing object information normally displayed
* in a object-subdirectory to a '$_INFO' directory.
* CALLER DECREF: *ppObjectDisplay
* -- H
* -- szTypeName
* -- vaObject
* -- fDataObj
* -- fDataHdr
* -- ppObjectDisplay = ptr to receive POB_OBJECT_DISPLAY on success.
* -- return
*/
_Success_(return)
BOOL VmmWinObjDisplay_Get(_In_ VMM_HANDLE H, _In_ LPSTR szTypeName, _In_ QWORD vaObject, _In_ BOOL fDataObj, _In_ BOOL fDataHdr, _Out_ POB_OBJECT_DISPLAY *ppObObjectDisplay)
{
    LPSTR szData = NULL;
    BOOL fResult = FALSE;
    POB_OBJECT_DISPLAY pOb = NULL;
    AcquireSRWLockExclusive(&H->vmm.LockSRW.WinObjDisplay);
    // 1: fetch existing object from cache
    if(!H->vmm.pObCacheMapWinObjDisplay) {
        if(!(H->vmm.pObCacheMapWinObjDisplay = ObCacheMap_New(H, 0x10000, NULL, OB_CACHEMAP_FLAGS_OBJECT_OB))) { goto fail; }
    }
    if(!(pOb = ObCacheMap_GetByKey(H->vmm.pObCacheMapWinObjDisplay, vaObject))) {
        if(!(pOb = Ob_AllocEx(H, OB_TAG_OBJ_DISPLAY, LMEM_ZEROINIT, sizeof(OB_OBJECT_DISPLAY), (OB_CLEANUP_CB)_VmmWinObjDisplay_ObCloseCallback, NULL))) { goto fail; }
        pOb->va = vaObject;
        ObCacheMap_Push(H->vmm.pObCacheMapWinObjDisplay, vaObject, pOb, 0);
    }
    if((pOb->cbObj == (DWORD)-1) || (pOb->cbHdr == (DWORD)-1)) { goto fail; }
    // 2: fetch object data (if required)
    if(!pOb->cbObj || (fDataObj && !pOb->pdcObj)) {
        if(!PDB_DisplayTypeNt(H, szTypeName, 1, vaObject, TRUE, FALSE, (fDataObj ? &szData : NULL), &pOb->cbObj, &pOb->cbType)) { goto fail; }
        if(szData) {
            pOb->pdcObj = ObCompressed_NewFromByte(H, H->vmm.pObCacheMapObCompressedShared, szData, pOb->cbObj);
            LocalFree(szData); szData = NULL;
            if(!pOb->pdcObj) { goto fail; }
        }
    }
    // 2: fetch header data (if required)
    if(!pOb->cbHdr || (fDataHdr && !pOb->pdcHdr)) {
        if(!PDB_DisplayTypeNt(H, szTypeName, 1, vaObject, TRUE, TRUE, (fDataHdr ? &szData : NULL), &pOb->cbHdr, NULL)) { goto fail; }
        if(szData) {
            pOb->pdcHdr = ObCompressed_NewFromByte(H, H->vmm.pObCacheMapObCompressedShared, szData, pOb->cbHdr);
            LocalFree(szData); szData = NULL;
            if(!pOb->pdcHdr) { goto fail; }
        }
    }
    *ppObObjectDisplay = pOb;
    ReleaseSRWLockExclusive(&H->vmm.LockSRW.WinObjDisplay);
    return TRUE;
fail:
    if(pOb) {
        pOb->cbObj = -1;
        pOb->cbHdr = -1;
    }
    Ob_DECREF(pOb);
    ReleaseSRWLockExclusive(&H->vmm.LockSRW.WinObjDisplay);
    return FALSE;
}

/*
* Vfs Read: helper function to read object files in an object information dir.
* -- H
* -- wszPathFile
* -- iTypeIndex = the object type index in the ObjectTypeTable
* -- vaObject
* -- pb
* -- cb
* -- pcbRead
* -- cbOffset
* -- return
*/
NTSTATUS VmmWinObjDisplay_VfsRead(_In_ VMM_HANDLE H, _In_ LPCSTR uszPathFile, _In_opt_ DWORD iTypeIndex, _In_ QWORD vaObject, _Out_writes_to_(cb, *pcbRead) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset)
{
    NTSTATUS nt = VMMDLL_STATUS_FILE_INVALID;
    POB_OBJECT_DISPLAY pObObjDisp = NULL;
    PVMMWIN_OBJECT_TYPE ptp = NULL;
    if(CharUtil_StrEndsWith(uszPathFile, "obj-address.txt", TRUE)) {
        if(H->vmm.f32) {
            return Util_VfsReadFile_FromDWORD((DWORD)vaObject, pb, cb, pcbRead, cbOffset, FALSE);
        } else {
            return Util_VfsReadFile_FromQWORD(vaObject, pb, cb, pcbRead, cbOffset, FALSE);
        }
    }
    ptp = VmmWin_ObjectTypeGet(H, (BYTE)iTypeIndex);
    if(ptp && CharUtil_StrEndsWith(uszPathFile, "obj-type.txt", TRUE)) {
        return Util_VfsReadFile_FromPBYTE(ptp->usz, strlen(ptp->usz), pb, cb, pcbRead, cbOffset);
    }
    if(CharUtil_StrEndsWith(uszPathFile, "obj-data.mem", TRUE)) {
        if(ptp && ptp->szType && VmmWinObjDisplay_Get(H, ptp->szType, vaObject, FALSE, FALSE, &pObObjDisp)) {
            nt = Util_VfsReadFile_FromMEM(H, PVMM_PROCESS_SYSTEM, pObObjDisp->va, pObObjDisp->cbType, VMM_FLAG_ZEROPAD_ON_FAIL, pb, cb, pcbRead, cbOffset);
            Ob_DECREF(pObObjDisp);
            return nt;
        }
        return Util_VfsReadFile_FromMEM(H, PVMM_PROCESS_SYSTEM, vaObject, VMMWINOBJDISPLAY_DEFAULT_OBJECT_MEMSIZE, VMM_FLAG_ZEROPAD_ON_FAIL, pb, cb, pcbRead, cbOffset);
    }
    if(CharUtil_StrEndsWith(uszPathFile, "obj-data.txt", TRUE) && ptp && ptp->szType && VmmWinObjDisplay_Get(H, ptp->szType, vaObject, TRUE, FALSE, &pObObjDisp)) {
        nt = Util_VfsReadFile_FromObCompressedStrA(pObObjDisp->pdcObj, pb, cb, pcbRead, cbOffset);
        Ob_DECREF(pObObjDisp);
        return nt;
    }
    if(CharUtil_StrEndsWith(uszPathFile, "obj-header.txt", TRUE) && ptp && ptp->szType && VmmWinObjDisplay_Get(H, ptp->szType, vaObject, FALSE, TRUE, &pObObjDisp)) {
        nt = Util_VfsReadFile_FromObCompressedStrA(pObObjDisp->pdcHdr, pb, cb, pcbRead, cbOffset);
        Ob_DECREF(pObObjDisp);
        return nt;
    }
    return nt;
}


/*
* Vfs List: helper function to list object files in an object information dir.
* -- H
* -- iTypeIndex = the object type index in the ObjectTypeTable
* -- vaObject
* -- pFileList
*/
VOID VmmWinObjDisplay_VfsList(_In_ VMM_HANDLE H, _In_opt_ DWORD iTypeIndex, _In_ QWORD vaObject, _Inout_ PHANDLE pFileList)
{
    PVMMWIN_OBJECT_TYPE ptp = NULL;
    POB_OBJECT_DISPLAY pObObjDisp = NULL;
    ptp = VmmWin_ObjectTypeGet(H, (BYTE)iTypeIndex);
    if(ptp && ptp->szType && VmmWinObjDisplay_Get(H, ptp->szType, vaObject, FALSE, FALSE, &pObObjDisp)) {
        VMMDLL_VfsList_AddFile(pFileList, "obj-header.txt", pObObjDisp->cbHdr - 1, NULL);
        VMMDLL_VfsList_AddFile(pFileList, "obj-data.txt", pObObjDisp->cbObj - 1, NULL);
        VMMDLL_VfsList_AddFile(pFileList, "obj-data.mem", pObObjDisp->cbType, NULL);
    } else {
        VMMDLL_VfsList_AddFile(pFileList, "obj-data.mem", VMMWINOBJDISPLAY_DEFAULT_OBJECT_MEMSIZE, NULL);
    }
    if(ptp) {
        VMMDLL_VfsList_AddFile(pFileList, "obj-type.txt", strlen(ptp->usz), NULL);
    }
    VMMDLL_VfsList_AddFile(pFileList, "obj-address.txt", H->vmm.f32 ? 8 : 16, NULL);
    Ob_DECREF(pObObjDisp);
}
