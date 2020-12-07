// vmmwinobj.c : implementation of functionality related to Windows objects.
//
// (c) Ulf Frisk, 2020
// Author: Ulf Frisk, pcileech@frizk.net
//

#include "vmmwinobj.h"
#include "vmmwindef.h"
#include "vmm.h"
#include "util.h"

#define VMMWINOBJ_WORKITEM_FILEPROCSCAN_VAD         0x0000000100000000
#define VMMWINOBJ_WORKITEM_FILEPROCSCAN_HANDLE      0x0000000200000000

typedef struct tdVMMWINOBJ_CONTEXT {
    CRITICAL_SECTION LockUpdate;
    POB_SET psError;
    POB_MAP pmByObj;
    POB_MAP pmByWorkitem;
} VMMWINOBJ_CONTEXT, *PVMMWINOBJ_CONTEXT;

//-----------------------------------------------------------------------------
// EXPORTED INITIALIZATION/REFRESH/CLOSE FUNCTIONALITY BELOW:
//-----------------------------------------------------------------------------

VOID VmmWinObj_Initialize()
{
    PVMMWINOBJ_CONTEXT ctx;
    if(!(ctx = LocalAlloc(LMEM_ZEROINIT, sizeof(VMMWINOBJ_CONTEXT)))) { goto fail; }
    if(!(ctx->psError = ObSet_New())) { goto fail; }
    if(!(ctx->pmByObj = ObMap_New(OB_MAP_FLAGS_OBJECT_OB))) { goto fail; }
    if(!(ctx->pmByWorkitem = ObMap_New(OB_MAP_FLAGS_OBJECT_OB))) { goto fail; }
    InitializeCriticalSection(&ctx->LockUpdate);
    ctxVmm->pObjects = ctx;
    return;
fail:
    if(ctx) {
        Ob_DECREF(ctx->psError);
        Ob_DECREF(ctx->pmByObj);
        Ob_DECREF(ctx->pmByWorkitem);
        LocalFree(ctx);
    }
}

VOID VmmWinObj_Close()
{
    PVMMWINOBJ_CONTEXT ctx = ctxVmm->pObjects;
    if(ctx) {
        ctxVmm->pObjects = NULL;
        Ob_DECREF(ctx->psError);
        Ob_DECREF(ctx->pmByObj);
        Ob_DECREF(ctx->pmByWorkitem);
        LocalFree(ctx);
    }
}

VOID VmmWinObj_Refresh()
{
    PVMMWINOBJ_CONTEXT ctx = ctxVmm->pObjects;
    if(ctx) {
        EnterCriticalSection(&ctx->LockUpdate);
        ObSet_Clear(ctx->psError);
        ObMap_Clear(ctx->pmByObj);
        ObMap_Clear(ctx->pmByWorkitem);
        LeaveCriticalSection(&ctx->LockUpdate);
    }
}



// ----------------------------------------------------------------------------
// GENERAL OBJECT FUNCTIONALITY:
// ----------------------------------------------------------------------------

/*
* Retrieve an object from the object cache.
* CALLER DECREF: return
* -- va = virtual address of the object to retrieve.
* -- return = the object, NULL if not found in cache.
*/
POB_VMMWINOBJ_OBJECT VmmWinObj_Get(_In_ QWORD va)
{
    PVMMWINOBJ_CONTEXT ctx = ctxVmm->pObjects;
    return ObMap_GetByKey(ctx->pmByObj, va);
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

VOID VmmWinObj_CallbackCleanup_ObObjFile(POB_VMMWINOBJ_FILE pOb)
{
    LocalFree(pOb->wszPath);
    LocalFree(pOb->pSUBSECTION);
}

/*
* Filter function for VmmWinObjFile_Initialize_SharedCacheMap.
*/
VOID VmmWinObjFile_Initialize_SharedCacheMap_Filter(_In_ QWORD k, _In_ POB_VMMWINOBJ_FILE v, _Inout_ POB_SET ps)
{
    if(v->_SHARED_CACHE_MAP.va) {
        ObSet_Push(ps, v->_SHARED_CACHE_MAP.va - 0x10);
    }
}

/*
* Fetch _SHARED_CACHE_MAP data into the OB_VMMWINOBJ_FILE contained by the pm map
* in a efficient way.
* -- pSystemProcess
* -- pm
*/
VOID VmmWinObjFile_Initialize_SharedCacheMap(_In_ PVMM_PROCESS pSystemProcess, _In_ POB_MAP pmFiles)
{
    BOOL f, f32 = ctxVmm->f32;
    BYTE pb[0x300];
    POB_VMMWINOBJ_FILE peObFile = NULL;
    PVMM_OFFSET_FILE po = &ctxVmm->offset.FILE;
    // 1: Prefetch valid _SHARED_CACHE_MAP into cache.
    if(!VmmCachePrefetchPages5(pSystemProcess, pmFiles, 0x10 + po->_SHARED_CACHE_MAP.cb, 0, VmmWinObjFile_Initialize_SharedCacheMap_Filter)) { return; }
    // 2: process _SHARED_CACHE_MAP
    while((peObFile = ObMap_GetNext(pmFiles, peObFile))) {
        f = peObFile->_SHARED_CACHE_MAP.va &&
            VmmRead2(pSystemProcess, peObFile->_SHARED_CACHE_MAP.va - 0x10, pb, po->_SHARED_CACHE_MAP.cb, VMM_FLAG_FORCECACHE_READ) &&
            VMM_POOLTAG_PREPENDED(pb, 0x10, 'CcSc') &&
            (peObFile->_SHARED_CACHE_MAP.vaVacbs = VMM_PTR_OFFSET(f32, pb + 0x10, po->_SHARED_CACHE_MAP.oVacbs)) &&
            VMM_KADDR_4_8(peObFile->_SHARED_CACHE_MAP.vaVacbs) &&
            (peObFile->_SHARED_CACHE_MAP.cbFileSize = *(PQWORD)(pb + 0x10 + po->_SHARED_CACHE_MAP.oFileSize)) &&
            (peObFile->_SHARED_CACHE_MAP.cbSectionSize = *(PQWORD)(pb + 0x10 + po->_SHARED_CACHE_MAP.oSectionSize));
        peObFile->_SHARED_CACHE_MAP.fValid = f;
        peObFile->_SHARED_CACHE_MAP.cbFileSizeValid = *(PQWORD)(pb + 0x10 + po->_SHARED_CACHE_MAP.oValidDataLength);
        if(peObFile->_SHARED_CACHE_MAP.fValid && ((peObFile->cb == 0) || (peObFile->_SHARED_CACHE_MAP.cbFileSize < peObFile->cb))) {
            peObFile->cb = peObFile->_SHARED_CACHE_MAP.cbFileSize;
        }
    }
}

/*
* Walk subsections to gather information about this file object. _SUBSECTION
* entries are usually stacked in an array-like pattern immediately after the
* _CONTROL_AREA object. This makes them very likely to be in the memory cache,
* hence need for performance enhancing caching functionality
* -- pSystemProcess
* -- pf
*/
BOOL VmmWinObjFile_Initialize_ControlArea_Subsection(_In_ PVMM_PROCESS pSystemProcess, _In_ POB_VMMWINOBJ_FILE pf)
{
    QWORD va;
    BOOL f = TRUE, fSoft;
    BYTE pb[0x80] = { 0 };
    DWORD i = 0, dwStartingSectorNext = 0;
    VMMWINOBJ_FILE_SUBSECTION ps[VMMWINOBJ_FILE_OBJECT_SUBSECTION_MAX];
    PVMM_OFFSET_FILE po = &ctxVmm->offset.FILE;
    // 1: Fetch # _SUBSECTION
    va = pf->vaControlArea + po->_CONTROL_AREA.cb;
    while(f && (i < VMMWINOBJ_FILE_OBJECT_SUBSECTION_MAX) && VMM_KADDR_4_8(va) && VmmRead2(pSystemProcess, va, pb, po->_SUBSECTION.cb, VMM_FLAG_FORCECACHE_READ)) {
        ps[i].dwStartingSector = *(PDWORD)(pb + po->_SUBSECTION.oStartingSector);
        ps[i].dwNumberOfFullSectors = *(PDWORD)(pb + po->_SUBSECTION.oNumberOfFullSectors);
        f = (pf->vaControlArea == VMM_PTR_OFFSET(ctxVmm->f32, pb, po->_SUBSECTION.oControlArea)) &&
            (ps[i].vaSubsectionBase = VMM_PTR_OFFSET(ctxVmm->f32, pb, po->_SUBSECTION.oSubsectionBase)) && VMM_KADDR_4_8(ps[i].vaSubsectionBase) &&
            (ps[i].dwPtesInSubsection = *(PDWORD)(pb + po->_SUBSECTION.oPtesInSubsection));
        fSoft = f &&
            (dwStartingSectorNext <= ps[i].dwStartingSector) &&
            (dwStartingSectorNext = ps[i].dwStartingSector + max(1, ps[i].dwNumberOfFullSectors)) &&
            ++i;
        va = VMM_PTR_OFFSET(ctxVmm->f32, pb, po->_SUBSECTION.oNextSubsection);
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
VOID VmmWinObjFile_Initialize_ControlArea_FilterSegment(_In_ QWORD k, _In_ POB_VMMWINOBJ_FILE v, _Inout_ POB_SET ps)
{
    ObSet_Push(ps, v->_SEGMENT.va);
}

/*
* Filter function for VmmWinObjFile_Initialize_ControlArea.
*/
VOID VmmWinObjFile_Initialize_ControlArea_Filter(_In_ QWORD k, _In_ POB_VMMWINOBJ_FILE v, _Inout_ POB_SET ps)
{
    ObSet_Push(ps, v->vaControlArea);
}

/*
* Fetch _CONTROL_AREA data into the OB_VMMWINOBJ_FILE contained by the pm map
* in a efficient way.
* -- pSystemProcess
* -- pm
*/
VOID VmmWinObjFile_Initialize_ControlArea(_In_ PVMM_PROCESS pSystemProcess, _In_ POB_MAP pmFiles)
{
    BOOL f, f32 = ctxVmm->f32;
    BYTE pb[0x100];
    POB_VMMWINOBJ_FILE peObFile = NULL;
    PVMM_OFFSET_FILE po = &ctxVmm->offset.FILE;
    // 1: Prefetch valid _CONTROL_AREA and following _SUBSECTION into cache.
    if(!VmmCachePrefetchPages5(pSystemProcess, pmFiles, 0x1000, 0, VmmWinObjFile_Initialize_ControlArea_Filter)) { return; }
    // 2: get _SEGMENT pointer and sub-process _SUBSECTION(s)
    while((peObFile = ObMap_GetNext(pmFiles, peObFile))) {
        f = peObFile->vaControlArea &&
            VmmRead2(pSystemProcess, peObFile->vaControlArea, pb, po->_CONTROL_AREA.cb, VMM_FLAG_FORCECACHE_READ) &&
            VMM_KADDR(VMM_PTR_OFFSET(f32, pb, po->_CONTROL_AREA.oFilePointer)) &&
            (peObFile->_SEGMENT.va = VMM_PTR_OFFSET(f32, pb, po->_CONTROL_AREA.oSegment)) && VMM_KADDR_4_8(peObFile->_SEGMENT.va) &&
            VmmWinObjFile_Initialize_ControlArea_Subsection(pSystemProcess, peObFile);
    }
    // 3: Prefetch valid _SEGMENT into cache.
    if(!VmmCachePrefetchPages5(pSystemProcess, pmFiles, po->_SEGMENT.cb, 0, VmmWinObjFile_Initialize_ControlArea_FilterSegment)) { return; }
    // 4: get _SEGMENT data
    while((peObFile = ObMap_GetNext(pmFiles, peObFile))) {
        if(peObFile->_SEGMENT.va && VmmRead2(pSystemProcess, peObFile->_SEGMENT.va, pb, po->_SEGMENT.cb, VMM_FLAG_FORCECACHE_READ) && (peObFile->vaControlArea == VMM_PTR_OFFSET(f32, pb, po->_SEGMENT.oControlArea))) {
            peObFile->_SEGMENT.cbSizeOfSegment = *(PQWORD)(pb + po->_SEGMENT.oSizeOfSegment);
            peObFile->_SEGMENT.vaPrototypePte = *(PQWORD)(pb + po->_SEGMENT.oPrototypePte);
            peObFile->_SEGMENT.fValid = TRUE;
            peObFile->cb = min(peObFile->_SEGMENT.cbSizeOfSegment, (peObFile->cb ? peObFile->cb : (QWORD)-1));
        }
    }
}

/*
* Filter function for VmmWinObjFile_Initialize_FileObjects.
*/
VOID VmmWinObjFile_Initialize_FileObject_Filter(_In_ QWORD k, _In_ POB_VMMWINOBJ_FILE v, _Inout_ POB_SET ps)
{
    ObSet_Push(ps, v->_Reserved2);
    ObSet_Push(ps, v->vaSectionObjectPointers);
}

/*
* Filter function for VmmWinObjFile_Initialize_FileObjects.
*/
BOOL VmmWinObjFile_Initialize_FileObject_FilterRemove(_In_ QWORD k, _In_ POB_VMMWINOBJ_FILE v)
{
    BOOL f =
        !v->dwNameHash ||
        (!v->fData && !v->fImage && !v->fCache) ||
        (v->fCache && !v->_SHARED_CACHE_MAP.fValid) ||
        (v->fData && (!v->_SEGMENT.fValid || !v->cSUBSECTION)) ||
        (v->fImage && !v->cSUBSECTION);
    if(f) {
        ObSet_Push(ctxVmm->pObjects->psError, v->va);
    }
    return f;
}

/*
* Initialize new file objects.
* -- pSystemProcess
* -- psvaFiles = set of virtual addresses to _FILE_OBJECTs to initialize.
* -- pmFilesResult = reults map, new valid objects are added to this map.
*/
VOID VmmWinObjFile_Initialize_FileObjects(_In_ PVMM_PROCESS pSystemProcess, _Inout_ POB_SET psvaFiles, _Inout_ POB_MAP pmFilesResult)
{
    BOOL f, f32 = ctxVmm->f32;
    QWORD va;
    DWORD cbPath;
    QWORD vaSectionObjectPointers, vaFileNameBuffer;
    BYTE pb[0x100];
    POB_MAP pmObFiles = NULL;
    POB_VMMWINOBJ_FILE peObFile = NULL;
    WCHAR wszNameBuffer[MAX_PATH + 1] = { 0 };
    PVMMWINOBJ_CONTEXT ctx = ctxVmm->pObjects;
    PVMM_OFFSET_FILE po = &ctxVmm->offset.FILE;
    if(!(pmObFiles = ObMap_New(OB_MAP_FLAGS_OBJECT_OB))) { return; }
    // 1: prefetch _FILE_OBJECT
    VmmCachePrefetchPages3(pSystemProcess, psvaFiles, po->_FILE_OBJECT.cb, 0);
    // 2: set up initial FileObjects
    while((va = ObSet_Pop(psvaFiles))) {
        f = VmmRead2(pSystemProcess, va, pb, po->_FILE_OBJECT.cb, VMM_FLAG_FORCECACHE_READ) &&
            (cbPath = *(PWORD)(pb + po->_FILE_OBJECT.oFileName)) && !(cbPath & 1) &&
            (vaFileNameBuffer = VMM_PTR_OFFSET(f32, pb, po->_FILE_OBJECT.oFileNameBuffer)) &&
            (vaSectionObjectPointers = VMM_PTR_OFFSET(f32, pb, po->_FILE_OBJECT.oSectionObjectPointer)) &&
            VMM_KADDR(vaFileNameBuffer) && VMM_KADDR_4_8(vaSectionObjectPointers) &&
            (peObFile = Ob_Alloc(OB_TAG_OBJ_FILE, LMEM_ZEROINIT, sizeof(OB_VMMWINOBJ_FILE), VmmWinObj_CallbackCleanup_ObObjFile, NULL));
        if(f) {
            peObFile->tp = VMMWINOBJ_TYPE_FILE;
            peObFile->va = va;
            peObFile->vaSectionObjectPointers = vaSectionObjectPointers;
            peObFile->_Reserved1 = cbPath;
            peObFile->_Reserved2 = vaFileNameBuffer;
            ObMap_Push(pmObFiles, va, peObFile);
            Ob_DECREF_NULL(&peObFile);
        } else {
            ObSet_Push(ctx->psError, va);
        }
    }
    // 3: prefetch _UNICODE_STRING and _SECTION_OBJECT_POINTERS
    if(!VmmCachePrefetchPages5(pSystemProcess, pmObFiles, MAX_PATH * 2, 0, VmmWinObjFile_Initialize_FileObject_Filter)) { goto finish; }
    // 4: fill _UNICODE_STRING and _SECTION_OBJECT_POINTERS
    while((peObFile = ObMap_GetNext(pmObFiles, peObFile))) {
        // _UNICODE_STRING
        cbPath = peObFile->_Reserved1;
        vaFileNameBuffer = peObFile->_Reserved2;
        if(cbPath > MAX_PATH * 2) {
            vaFileNameBuffer += cbPath - MAX_PATH * 2;
            cbPath = MAX_PATH * 2;
        }
        if(!VmmReadAlloc(pSystemProcess, vaFileNameBuffer, (PBYTE*)&peObFile->wszPath, cbPath, VMM_FLAG_FORCECACHE_READ)) { continue; }
        peObFile->wszName = Util_PathSplitLastW(peObFile->wszPath);
        peObFile->dwNameHash = Util_HashStringUpperW(peObFile->wszName);
        // _SECTION_OBJECT_POINTERS
        if(!VmmRead2(pSystemProcess, peObFile->vaSectionObjectPointers, pb, po->_SECTION_OBJECT_POINTERS.cb, VMM_FLAG_FORCECACHE_READ)) { continue; }
        if((va = VMM_PTR_OFFSET(f32, pb, po->_SECTION_OBJECT_POINTERS.oDataSectionObject)) && VMM_KADDR_8_16(va)) {
            peObFile->fData = TRUE;
            peObFile->vaControlArea = va;
        }
        if((va = VMM_PTR_OFFSET(f32, pb, po->_SECTION_OBJECT_POINTERS.oImageSectionObject)) && VMM_KADDR_8_16(va)) {
            peObFile->fImage = TRUE;
            peObFile->vaControlArea = va;
        }
        if((va = VMM_PTR_OFFSET(f32, pb, po->_SECTION_OBJECT_POINTERS.oSharedCacheMap)) && VMM_KADDR_8_16(va)) {
            peObFile->fCache = TRUE;
            peObFile->_SHARED_CACHE_MAP.va = va;
        }
    }
    // 5: fetch sub-objects
    VmmWinObjFile_Initialize_ControlArea(pSystemProcess, pmObFiles);
    VmmWinObjFile_Initialize_SharedCacheMap(pSystemProcess, pmObFiles);
    // 6: finish - move valid to result map and invalid to error set.
finish:
    ObMap_RemoveByFilter(pmObFiles, VmmWinObjFile_Initialize_FileObject_FilterRemove);
    while((peObFile = ObMap_GetNext(pmObFiles, peObFile))) {
        ObMap_Push(pmFilesResult, peObFile->va, peObFile);
        ObMap_Push(ctx->pmByObj, peObFile->va, peObFile);
    }
}

/*
* Helper function for VmmWinObjFile_GetByProcess_DoWork
*/
VOID VmmWinObjFile_GetByProcess_DoWork_AddInitial(_In_ QWORD va, _In_ POB_MAP pmObFiles, _In_ POB_SET psvaObFiles, _In_ PVMMWINOBJ_CONTEXT ctx)
{
    POB_VMMWINOBJ_FILE pObF;
    if((pObF = ObMap_GetByKey(ctx->pmByObj, va))) {
        ObMap_Push(pmObFiles, va, pObF);
        Ob_DECREF(pObF);
    } else if(!ObSet_Exists(ctx->psError, va)) {
        ObSet_Push(psvaObFiles, va);
    }
}

/*
* Retrieve and initialize all _FILE_OBJECTs belonging to the process either
* by retrieving from Handles or Vads.
* -- pProcess
* -- pmObFiles
* -- fHandles = TRUE = files from handles, FALSE = files from VADs
*/
VOID VmmWinObjFile_GetByProcess_DoWork(_In_ PVMM_PROCESS pProcess, _In_ POB_MAP pmObFiles, _In_ BOOL fHandles)
{
    DWORD i, iMax;
    POB_SET psvaObFiles = NULL;
    PVMMOB_MAP_VAD pmObVad = NULL;
    PVMMOB_MAP_HANDLE pmObHandle = NULL;
    PVMMWINOBJ_CONTEXT ctx = ctxVmm->pObjects;
    PVMM_PROCESS pObSystemProcess;
    if(!(psvaObFiles = ObSet_New())) { return; }
    if(fHandles) {
        // handle map -> file objects
        if(VmmMap_GetHandle(pProcess, &pmObHandle, TRUE)) {
            for(i = 0, iMax = pmObHandle->cMap; i < iMax; i++) {
                if((pmObHandle->pMap[i].dwPoolTag & 0x00ffffff) == 'liF') {
                    VmmWinObjFile_GetByProcess_DoWork_AddInitial(pmObHandle->pMap[i].vaObject, pmObFiles, psvaObFiles, ctx);
                }
            }
            Ob_DECREF_NULL(&pmObHandle);
        }
    } else {
        // vad map -> file objects
        if(VmmMap_GetVad(pProcess, &pmObVad, VMM_VADMAP_TP_PARTIAL)) {
            for(i = 0, iMax = pmObVad->cMap; i < iMax; i++) {
                if(pmObVad->pMap[i].vaFileObject) {
                    VmmWinObjFile_GetByProcess_DoWork_AddInitial(pmObVad->pMap[i].vaFileObject, pmObFiles, psvaObFiles, ctx);
                }
            }
            Ob_DECREF_NULL(&pmObVad);
        }
    }
    // Fetch and initialize new file objects
    if(ObSet_Size(psvaObFiles)) {
        if((pObSystemProcess = VmmProcessGet(4))) {
            VmmWinObjFile_Initialize_FileObjects(pObSystemProcess, psvaObFiles, pmObFiles);
            Ob_DECREF(pObSystemProcess);
        }
    }
    Ob_DECREF(psvaObFiles);
}

/*
* Retrieve all _FILE_OBJECT related to a process.
* CALLER DECREF: ppmObFiles
* -- pProcess
* -- ppmObFiles
* -- fHandles = TRUE = files from handles, FALSE = files from VADs
* -- return
*/
_Success_(return)
BOOL VmmWinObjFile_GetByProcess(_In_ PVMM_PROCESS pProcess, _Out_ POB_MAP *ppmObFiles, _In_ BOOL fHandles)
{
    DWORD i, iMax;
    POB_MAP pmObFiles = NULL;
    POB_SET psObKeyData = NULL;
    POB_DATA pObData = NULL;
    POB_VMMWINOBJ_FILE pObFile = NULL;
    PVMMWINOBJ_CONTEXT ctx = ctxVmm->pObjects;
    if(!ctx || !ctxVmm->offset.FILE.fValid || !(pmObFiles = ObMap_New(OB_MAP_FLAGS_OBJECT_OB))) { return FALSE; }
    EnterCriticalSection(&ctx->LockUpdate);
    // 1: try fetch from already completed process workitem cache
    if((pObData = ObMap_GetByKey(ctx->pmByWorkitem, (fHandles ? VMMWINOBJ_WORKITEM_FILEPROCSCAN_HANDLE : VMMWINOBJ_WORKITEM_FILEPROCSCAN_VAD) | pProcess->dwPID))) {
        for(i = 0, iMax = pObData->ObHdr.cbData / sizeof(QWORD); i < iMax; i++) {
            if((pObFile = ObMap_GetByKey(ctx->pmByObj, pObData->pqw[i]))) {
                if(pObFile->tp == VMMWINOBJ_TYPE_FILE) {
                    ObMap_Push(pmObFiles, pObFile->va, pObFile);
                }
                Ob_DECREF_NULL(&pObFile);
            }
        }
        Ob_DECREF_NULL(&pObData);
        goto success;
    }
    // 2: try fetch from process handles, and put result in process workitem cache
    VmmWinObjFile_GetByProcess_DoWork(pProcess, pmObFiles, fHandles);
    if((psObKeyData = ObMap_FilterSet(pmObFiles, ObMap_FilterSet_FilterAllKey))) {
        if((pObData = ObSet_GetAll(psObKeyData))) {
            ObMap_Push(ctx->pmByWorkitem, (fHandles ? VMMWINOBJ_WORKITEM_FILEPROCSCAN_HANDLE : VMMWINOBJ_WORKITEM_FILEPROCSCAN_VAD) | pProcess->dwPID, pObData);
            Ob_DECREF_NULL(&pObData);
        }
        Ob_DECREF_NULL(&psObKeyData);
    }
success:
    *ppmObFiles = pmObFiles;
    LeaveCriticalSection(&ctx->LockUpdate);
    return TRUE;
}



// ----------------------------------------------------------------------------
// _FILE_OBJECT READ:
// ----------------------------------------------------------------------------

/*
* Helper function to retrieve a Page Table Entry (PTE). Retrieval is done in a
* fairly performance intensive (non-cached) way, but it's assumed this function
* won't be heavily called.
* -- pSystemProcess
* -- vaPteBase
* -- iPte
* -- fVmmRead = VMM_FLAGS_* flags.
* -- return = the PTE or 0 on fail.
*/
QWORD VmmWinObjFile_ReadSubsectionAndSharedCache_GetPteSubsection(_In_ PVMM_PROCESS pSystemProcess, _In_ QWORD vaPteBase, _In_ QWORD iPte, _In_ QWORD fVmmRead)
{
    QWORD pte = 0;
    DWORD cbPte = ctxVmm->tpMemoryModel == VMMDLL_MEMORYMODEL_X86 ? 4 : 8;
    VmmReadEx(pSystemProcess, vaPteBase + iPte * cbPte, (PBYTE)&pte, cbPte, NULL, fVmmRead);
    return pte;
}

/*
* Helper function to retrieve the virtual address of a _SHARED_CACHE_MAP entry.
* Retrieval is done in a performance intensive (non-cached) way, but it's
* assumed this function won't be heavily called.
* -- pSystemProcess
* -- pFile
* -- iPte
* -- fVmmRead
* -- return = the virtual address or 0 on fail.
*/
QWORD VmmWinObjFile_ReadSubsectionAndSharedCache_GetVaSharedCache(_In_ PVMM_PROCESS pSystemProcess, _In_ POB_VMMWINOBJ_FILE pFile, _In_ QWORD iPte, _In_ QWORD fVmmRead)
{
    BOOL f;
    BYTE pbVacb[0x40];
    QWORD va, iVacb, vaVacbs, vaVacb;
    PVMM_OFFSET_FILE po = &ctxVmm->offset.FILE;
    iVacb = (iPte << 12) / pFile->_SHARED_CACHE_MAP.cbSectionSize;
    vaVacbs = pFile->_SHARED_CACHE_MAP.vaVacbs + iVacb * (ctxVmm->f32 ? 4 : 8);
    f = VmmRead2(pSystemProcess, vaVacbs, pbVacb, 8, fVmmRead) &&
        (vaVacb = VMM_PTR_OFFSET(ctxVmm->f32, pbVacb, 0)) &&
        VMM_KADDR_4_8(vaVacb) &&
        VmmRead2(pSystemProcess, vaVacb, pbVacb, po->_VACB.cb, fVmmRead) &&
        (pFile->_SHARED_CACHE_MAP.va == VMM_PTR_OFFSET(ctxVmm->f32, pbVacb, po->_VACB.oSharedCacheMap)) &&
        (va = VMM_PTR_OFFSET(ctxVmm->f32, pbVacb, po->_VACB.oBaseAddress));
    return f ? (va + (iPte << 12)) : 0;
}

/*
* Read data from a single _FILE_OBJECT _SUBSECTION and/or a _SHARED_CACHE_MAP.
* Function is very similar to the VmmReadEx() function. Reading is not yet
* optimized, but the assumption is the function won't be called frequently so
* any inefficencies should only have a minor performance impact.
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
VOID VmmWinObjFile_ReadSubsectionAndSharedCache(_In_ PVMM_PROCESS pSystemProcess, _In_ POB_VMMWINOBJ_FILE pFile, _In_ DWORD iSubsection, _In_ QWORD cbOffset, _Out_writes_(cb) PBYTE pb, _In_ DWORD cb, _Out_opt_ PDWORD pcbReadOpt, _In_ QWORD fVmmRead, _In_ BOOL fSharedCache)
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
            pMEMs[i].qwA = VmmWinObjFile_ReadSubsectionAndSharedCache_GetVaSharedCache(pSystemProcess, pFile, iPte, fVmmRead);
            if(pMEMs[i].qwA) {
                fReadSharedCacheMap = TRUE;
            }
        }
        if(fReadSharedCacheMap) {
            VmmReadScatterVirtual(pSystemProcess, ppMEMs, cMEMs, fVmmRead);
        }
    }
    // Read from _SUBSECTION
    if(pFile->cSUBSECTION && (iSubsection < pFile->cSUBSECTION)) {
        for(i = 0; i < cMEMs; i++) {
            if(pMEMs[i].f) { continue; }
            iPte = i + ((cbOffset - oA) >> 12);
            pMEMs[i].qwA = (iPte < pFile->pSUBSECTION[iSubsection].dwPtesInSubsection) ? VmmWinObjFile_ReadSubsectionAndSharedCache_GetPteSubsection(pSystemProcess, pFile->pSUBSECTION[iSubsection].vaSubsectionBase, iPte, fVmmRead) : 0;
            fReadSubsection = TRUE;
        }
        if(fReadSubsection) {
            VmmReadScatterVirtual(pSystemProcess, ppMEMs, cMEMs, fVmmRead | VMM_FLAG_ALTADDR_VA_PTE);
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
* -- pSystemProcess
* -- pFile
* -- cbOffset
* -- pb
* -- cb
* -- fVmmRead
* -- return
*/
_Success_(return != 0)
DWORD VmmWinObjFile_ReadImage(_In_ PVMM_PROCESS pSystemProcess, _In_ POB_VMMWINOBJ_FILE pFile, _In_ QWORD cbOffset, _Out_writes_(cb) PBYTE pb, _In_ DWORD cb, _In_ QWORD fVmmRead)
{
    DWORD cbRead, cbReadTotal = 0;
    DWORD iSubsection;
    DWORD cbSubsection, cbSubsectionBase, cbSubsectionEnd;
    DWORD cbSubsectionOffset, cbReadBufferOffset, cbAdjusted;
    ZeroMemory(pb, cb);
    for(iSubsection = 0; iSubsection < pFile->cSUBSECTION; iSubsection++) {
        cbSubsection = 512 * pFile->pSUBSECTION[iSubsection].dwNumberOfFullSectors;
        cbSubsectionBase = 512 * pFile->pSUBSECTION[iSubsection].dwStartingSector;
        cbSubsectionEnd = cbSubsectionBase + cbSubsection;
        if(cbSubsectionEnd < cbOffset) { continue; }
        if(cbSubsectionBase >= cbOffset + cb) { break; }
        cbSubsectionOffset = (DWORD)max(cbSubsectionBase, cbOffset) - cbSubsectionBase;
        cbReadBufferOffset = (DWORD)(cbSubsectionBase + cbSubsectionOffset - cbOffset);
        cbAdjusted = min(cb - cbReadBufferOffset, cbSubsection - cbSubsectionOffset);
        cbRead = 0;
        VmmWinObjFile_ReadSubsectionAndSharedCache(
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
* -- pFile
* -- cbOffset
* -- pb
* -- cb
* -- fVmmRead = flags as in VMM_FLAG_*
* -- return = the number of bytes read.
*/
_Success_(return != 0)
DWORD VmmWinObjFile_Read(_In_ POB_VMMWINOBJ_FILE pFile, _In_ QWORD cbOffset, _Out_writes_(cb) PBYTE pb, _In_ DWORD cb, _In_ QWORD fVmmRead)
{
    DWORD cbRead = 0;
    PVMM_PROCESS pObSystemProcess = NULL;
    ZeroMemory(pb, cb);
    if(cbOffset + cb > pFile->cb) {
        if((cbOffset >= pFile->cb) || (pFile->cb - cbOffset > 0xffffffff)) {
            return 0;
        }
        cb = (DWORD)(pFile->cb - cbOffset);
    }
    if(!(pObSystemProcess = VmmProcessGet(4))) { return 0; }
    if(pFile->fImage) {
        cbRead = VmmWinObjFile_ReadImage(pObSystemProcess, pFile, cbOffset, pb, cb, fVmmRead | VMM_FLAG_ZEROPAD_ON_FAIL);
        goto finish;
    }
    if(pFile->fCache && pFile->_SHARED_CACHE_MAP.fValid) {
        VmmWinObjFile_ReadSubsectionAndSharedCache(pObSystemProcess, pFile, 0, cbOffset, pb, cb, &cbRead, fVmmRead | VMM_FLAG_ZEROPAD_ON_FAIL, TRUE);
        goto finish;
    }
    if(pFile->fData && (pFile->cSUBSECTION == 1)) {
        VmmWinObjFile_ReadSubsectionAndSharedCache(pObSystemProcess, pFile, 0, cbOffset, pb, cb, &cbRead, fVmmRead | VMM_FLAG_ZEROPAD_ON_FAIL, FALSE);
        goto finish;
    }
finish:
    Ob_DECREF(pObSystemProcess);
    return cb;
}
