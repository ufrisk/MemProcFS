// vmmwinobj.c : implementation related to Windows Objects.
//
// (c) Ulf Frisk, 2020-2021
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
        ObCacheMap_Clear(ctxVmm->pObCacheMapWinObjDisplay);
        LeaveCriticalSection(&ctx->LockUpdate);
    }
    ObContainer_SetOb(ctxVmm->pObCMapObject, NULL);
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
    LocalFree(pOb->uszPath);
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
    if(!VmmCachePrefetchPages5(pSystemProcess, pmFiles, 0x10 + po->_SHARED_CACHE_MAP.cb, 0, (VOID(*)(QWORD, PVOID, POB_SET))VmmWinObjFile_Initialize_SharedCacheMap_Filter)) { return; }
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
    if(!VmmCachePrefetchPages5(pSystemProcess, pmFiles, 0x1000, 0, (VOID(*)(QWORD, PVOID, POB_SET))VmmWinObjFile_Initialize_ControlArea_Filter)) { return; }
    // 2: get _SEGMENT pointer and sub-process _SUBSECTION(s)
    while((peObFile = ObMap_GetNext(pmFiles, peObFile))) {
        f = peObFile->vaControlArea &&
            VmmRead2(pSystemProcess, peObFile->vaControlArea, pb, po->_CONTROL_AREA.cb, VMM_FLAG_FORCECACHE_READ) &&
            VMM_KADDR(VMM_PTR_OFFSET(f32, pb, po->_CONTROL_AREA.oFilePointer)) &&
            (peObFile->_SEGMENT.va = VMM_PTR_OFFSET(f32, pb, po->_CONTROL_AREA.oSegment)) && VMM_KADDR_4_8(peObFile->_SEGMENT.va) &&
            VmmWinObjFile_Initialize_ControlArea_Subsection(pSystemProcess, peObFile);
    }
    // 3: Prefetch valid _SEGMENT into cache.
    if(!VmmCachePrefetchPages5(pSystemProcess, pmFiles, po->_SEGMENT.cb, 0, (VOID(*)(QWORD, PVOID, POB_SET))VmmWinObjFile_Initialize_ControlArea_FilterSegment)) { return; }
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
            (peObFile = Ob_Alloc(OB_TAG_OBJ_FILE, LMEM_ZEROINIT, sizeof(OB_VMMWINOBJ_FILE), (OB_CLEANUP_CB)VmmWinObj_CallbackCleanup_ObObjFile, NULL));
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
    if(!VmmCachePrefetchPages5(pSystemProcess, pmObFiles, MAX_PATH * 2, 0, (VOID(*)(QWORD, PVOID, POB_SET))VmmWinObjFile_Initialize_FileObject_Filter)) { goto finish; }
    // 4: fill _UNICODE_STRING and _SECTION_OBJECT_POINTERS
    while((peObFile = ObMap_GetNext(pmObFiles, peObFile))) {
        // _UNICODE_STRING
        cbPath = peObFile->_Reserved1;
        vaFileNameBuffer = peObFile->_Reserved2;
        if(cbPath > MAX_PATH * 2) {
            vaFileNameBuffer += cbPath - MAX_PATH * 2;
            cbPath = MAX_PATH * 2;
        }
        if(!VmmReadWtoU(pSystemProcess, vaFileNameBuffer, cbPath, VMM_FLAG_FORCECACHE_READ, NULL, 0, &peObFile->uszPath, NULL, CHARUTIL_FLAG_ALLOC)) {
            if(!(peObFile->uszPath = (LPSTR)LocalAlloc(LMEM_ZEROINIT, 1))) { continue; }
        }
        peObFile->uszName = CharUtil_PathSplitLast(peObFile->uszPath);
        peObFile->dwNameHash = CharUtil_HashNameFsU(peObFile->uszName, 0);
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
    ObMap_RemoveByFilter(pmObFiles, (BOOL(*)(QWORD, PVOID))VmmWinObjFile_Initialize_FileObject_FilterRemove);
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
        VmmWinObjFile_Initialize_FileObjects(PVMM_PROCESS_SYSTEM, psvaObFiles, pmObFiles);
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
BOOL VmmWinObjFile_GetByProcess(_In_ PVMM_PROCESS pProcess, _Out_ POB_MAP * ppmObFiles, _In_ BOOL fHandles)
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
        DWORD cchName;
        QWORD vaName;
        QWORD ft;
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
VOID VmmWinObjMgr_Initialize_ProcessObject(_Inout_ PVMM_WINOBJ_SETUP_CONTEXT ctxInit, _In_reads_(0x70) PBYTE pb, _In_ PVMM_WINOBJ_SETUP_OBJECT pe)
{
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
    if(ctxVmm->f32) {
        pHdr32 = (POBJECT_HEADER32)(pb + 0x20);
        if(pHdr32->SecurityDescriptor && !VMM_KADDR32(pHdr32->SecurityDescriptor)) { goto fail; }
        iTp = VmmWin_ObjectTypeGetIndexFromEncoded(pe->va - 0x18, pHdr32->TypeIndex);
        if(iTp < 2 || iTp >= ctxVmm->ObjectTypeTable.c) { goto fail; }
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
        if((iTp == 3) && VmmRead(ctxInit->pSystemProcess, pe->va, (PBYTE)vaDir32, 37 * sizeof(DWORD))) {
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
        iTp = VmmWin_ObjectTypeGetIndexFromEncoded(pe->va - 0x30, pHdr64->TypeIndex);
        if(iTp < 2 || iTp >= ctxVmm->ObjectTypeTable.c) { goto fail; }
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
        if((iTp == 3) && VmmRead(ctxInit->pSystemProcess, pe->va, (PBYTE)vaDir64, 37 * sizeof(QWORD))) {
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
    if((iTp == ctxVmm->ObjectTypeTable.tpSymbolicLink) && VmmRead(ctxInit->pSystemProcess, pe->va, pb, 0x18)) {
        pe->ExtInfo.ft = *(PQWORD)pb;
        if(ctxVmm->f32) {
            pus32 = (PUNICODE_STRING32)(pb + 8);
            if(!(pus32->Length & 1) && (pus32->Length < 0x200) && VMM_KADDR32(pus32->Buffer)) {
                pe->ExtInfo.cchName = pus32->Length;
                pe->ExtInfo.vaName = pus32->Buffer;
            }
        } else {
            pus64 = (PUNICODE_STRING64)(pb + 8);
            if(!(pus64->Length & 1) && (pus64->Length < 0x200) && VMM_KADDR64(pus64->Buffer)) {
                pe->ExtInfo.cchName = pus64->Length;
                pe->ExtInfo.vaName = pus64->Buffer;
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
VOID VmmWinObjMgr_Initialize_ProcessDirectoryObjectEntry(_Inout_ PVMM_WINOBJ_SETUP_CONTEXT ctxInit, _In_reads_(0x10) PBYTE pb, _In_ PVMM_WINOBJ_SETUP_OBJECT pe)
{
    QWORD vaNext, vaObject;
    PVMM_WINOBJ_SETUP_OBJECT peNext;
    if(ctxVmm->f32) {
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

_Success_(return)
BOOL VmmWinObjMgr_Initialize_ObjectNameExtInfo(_In_ PVMM_PROCESS pSystemProcess, _Inout_ POB_STRMAP pStrMap, _Inout_ PVMM_MAP_OBJECTENTRY pe, _In_ PVMM_WINOBJ_SETUP_OBJECT pes, _In_ BOOL fForce)
{
    WCHAR wsz[0x201];
    if(pes->ExtInfo.cchName == -1) { return TRUE; }
    pe->ExtInfo.ft = pes->ExtInfo.ft;
    if(pes->ExtInfo.vaName && VmmRead2(pSystemProcess, pes->ExtInfo.vaName, (PBYTE)wsz, min(0x400, pes->ExtInfo.cchName << 1), VMM_FLAG_FORCECACHE_READ)) {
        wsz[min(0x200, pes->ExtInfo.cchName)] = 0;
        ObStrMap_PushPtrWU(pStrMap, wsz, &pe->ExtInfo.usz, NULL);
        pes->ExtInfo.cchName = -1;
        return TRUE;
    }
    if(!pes->ExtInfo.vaName || fForce) {
        ObStrMap_PushPtrWU(pStrMap, NULL, &pe->ExtInfo.usz, NULL);
        pes->ExtInfo.cchName = -1;
        return TRUE;
    }
    return FALSE;
}

/*
* Fetch object name for a single object
*/
_Success_(return)
BOOL VmmWinObjMgr_Initialize_ObjectName(_In_ PVMM_PROCESS pSystemProcess, _Inout_ POB_STRMAP pStrMap, _Inout_ PVMM_MAP_OBJECTENTRY pe, _In_ PVMM_WINOBJ_SETUP_OBJECT pes, _In_ BOOL fForce)
{
    WCHAR wsz[0x201];
    if(pes->cchName == -1) { return TRUE; }
    if(pes->vaName && VmmRead2(pSystemProcess, pes->vaName, (PBYTE)wsz, min(0x400, pes->cchName << 1), VMM_FLAG_FORCECACHE_READ)) {
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
BOOL VmmWinObjMgr_Initialize_ObMapLookupStr(_Inout_ PVMMOB_MAP_OBJECT pMap, _Inout_ PVMM_WINOBJ_SETUP_CONTEXT ctxInit)
{
    DWORD i;
    PVMM_WINOBJ_SETUP_OBJECT pes;
    PVMM_MAP_OBJECTENTRY pe;
    POB_STRMAP pObStrMap = NULL;
    if(!(pObStrMap = ObStrMap_New(OB_STRMAP_FLAGS_CASE_SENSITIVE))) { return FALSE; }
    ObSet_Clear(ctxInit->psvaPrefetch);
    for(i = 0; i < pMap->cMap; i++) {
        pe = pMap->pMap + i;
        pes = (PVMM_WINOBJ_SETUP_OBJECT)pe->_Reserved;
        if(!VmmWinObjMgr_Initialize_ObjectName(ctxInit->pSystemProcess, pObStrMap, pe, pes, FALSE)) {
            ObSet_Push_PageAlign(ctxInit->psvaPrefetch, pes->vaName, pes->cchName << 1);
        }
        if(!VmmWinObjMgr_Initialize_ObjectNameExtInfo(ctxInit->pSystemProcess, pObStrMap, pe, pes, FALSE)) {
            ObSet_Push_PageAlign(ctxInit->psvaPrefetch, pes->ExtInfo.vaName, pes->ExtInfo.cchName << 1);
        }
    }
    if(ObSet_Size(ctxInit->psvaPrefetch)) {
        VmmCachePrefetchPages(ctxInit->pSystemProcess, ctxInit->psvaPrefetch, 0);
        for(i = 0; i < pMap->cMap; i++) {
            pe = pMap->pMap + i;
            pes = (PVMM_WINOBJ_SETUP_OBJECT)pe->_Reserved;
            VmmWinObjMgr_Initialize_ObjectName(ctxInit->pSystemProcess, pObStrMap, pe, pes, TRUE);
            VmmWinObjMgr_Initialize_ObjectNameExtInfo(ctxInit->pSystemProcess, pObStrMap, pe, pes, TRUE);
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
* -- return
*/
_Success_(return != NULL)
PVMMOB_MAP_OBJECT VmmWinObjMgr_Initialize_ObMapAlloc(_Inout_ PVMM_WINOBJ_SETUP_CONTEXT ctxInit)
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
    pObMap = Ob_Alloc(OB_TAG_MAP_OBJECT, LMEM_ZEROINIT, sizeof(VMMOB_MAP_OBJECT) + cAll * (sizeof(VMM_MAP_OBJECTENTRY) + sizeof(DWORD)), (OB_CLEANUP_CB)VmmWinObjMgr_CallbackCleanup_ObObjectMap, NULL);
    if(!pObMap) { return NULL; }
    pObMap->cMap = cAll;
    pObMap->piTypeSort = (PDWORD)((QWORD)pObMap + sizeof(VMMOB_MAP_OBJECT) + cAll * sizeof(VMM_MAP_OBJECTENTRY));
    for(i = 1; i < ctxVmm->ObjectTypeTable.c; i++) {
        pObMap->iTypeSortBase[i] = pObMap->iTypeSortBase[i-1] + cType[i-1];
    }
    // 4: populate
    while((pes = (PVMM_WINOBJ_SETUP_OBJECT)ObSet_Pop(ctxInit->psObjectAll))) {
        pe = pObMap->pMap + pes->dwId;
        pe->va = pes->va;
        pe->id = pes->dwId;
        pe->pType = ctxVmm->ObjectTypeTable.h + pes->iType;
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
* -- return
*/
_Success_(return != NULL)
PVMMOB_MAP_OBJECT VmmWinObjMgr_Initialize_DoWork()
{
    BOOL fResult = FALSE;
    DWORD c, i, cbHdr = ctxVmm->f32 ? 0x38 : 0x70;
    QWORD vaRootDirectoryObject = 0;
    PVMM_WINOBJ_SETUP_OBJECT pes;
    VMM_WINOBJ_SETUP_CONTEXT ctxInit = { 0 };
    BYTE pb[0x70];
    PVMMOB_MAP_OBJECT pObObjectMap = NULL;
    // 1: INIT
    if(!VmmWin_ObjectTypeGet(3)) { goto fail; }     // ensure type table initialization
    if(!(ctxInit.pSystemProcess = VmmProcessGet(4))) { goto fail; }
    if(!PDB_GetSymbolPTR(PDB_HANDLE_KERNEL, "ObpRootDirectoryObject", ctxInit.pSystemProcess, &vaRootDirectoryObject)) { goto fail; }
    if(!VMM_KADDR_8_16(vaRootDirectoryObject)) { goto fail; }
    for(i = 0; i < 2; i++) {
        if(!(ctxInit.psObj[i] = ObSet_New())) { goto fail; }
        if(!(ctxInit.psDirEntry[i] = ObSet_New())) { goto fail; }
    }
    if(!(ctxInit.psObjectAll = ObSet_New())) { goto fail; }
    if(!(ctxInit.psObjectDir = ObSet_New())) { goto fail; }
    if(!(ctxInit.psvaAllObj = ObSet_New())) { goto fail; }
    if(!(ctxInit.psvaPrefetch = ObSet_New())) { goto fail; }
    if(!(pes = LocalAlloc(LMEM_ZEROINIT, sizeof(VMM_WINOBJ_SETUP_OBJECT)))) { goto fail; }
    pes->va = vaRootDirectoryObject;
    ObSet_Push(ctxInit.psObj[0], (QWORD)pes);
    // 2: FETCH objects in an efficient way minimizing number of physical device accesses.
    while(ObSet_Size(ctxInit.psObj[0]) || ObSet_Size(ctxInit.psDirEntry[0])) {
        while(ObSet_Size(ctxInit.psObj[0]) || ObSet_Size(ctxInit.psDirEntry[0])) {
            while((pes = (PVMM_WINOBJ_SETUP_OBJECT)ObSet_Pop(ctxInit.psObj[0]))) {
                if(VmmRead2(ctxInit.pSystemProcess, pes->va - cbHdr, pb, cbHdr, VMM_FLAG_FORCECACHE_READ)) {
                    VmmWinObjMgr_Initialize_ProcessObject(&ctxInit, pb, pes);
                } else {
                    ObSet_Push(ctxInit.psObj[1], (QWORD)pes);
                }
            }
            while((pes = (PVMM_WINOBJ_SETUP_OBJECT)ObSet_Pop(ctxInit.psDirEntry[0]))) {
                if(VmmRead2(ctxInit.pSystemProcess, pes->va, pb, 0x18, VMM_FLAG_FORCECACHE_READ)) {
                    VmmWinObjMgr_Initialize_ProcessDirectoryObjectEntry(&ctxInit, pb, pes);
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
            VmmCachePrefetchPages(ctxInit.pSystemProcess, ctxInit.psvaPrefetch, 0);
            while((pes = (PVMM_WINOBJ_SETUP_OBJECT)ObSet_Pop(ctxInit.psObj[1]))) {
                if(VmmRead2(ctxInit.pSystemProcess, pes->va - cbHdr, pb, cbHdr, VMM_FLAG_FORCECACHE_READ)) {
                    VmmWinObjMgr_Initialize_ProcessObject(&ctxInit, pb, pes);
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
            VmmCachePrefetchPages(ctxInit.pSystemProcess, ctxInit.psvaPrefetch, 0);
            while((pes = (PVMM_WINOBJ_SETUP_OBJECT)ObSet_Pop(ctxInit.psDirEntry[1]))) {
                if(VmmRead2(ctxInit.pSystemProcess, pes->va, pb, 0x18, VMM_FLAG_FORCECACHE_READ)) {
                    VmmWinObjMgr_Initialize_ProcessDirectoryObjectEntry(&ctxInit, pb, pes);
                } else {
                    LocalFree(pes);
                }
            }

        }
    }
    // 3: ALLOC ObMap and populate with initial data
    if(!(pObObjectMap = VmmWinObjMgr_Initialize_ObMapAlloc(&ctxInit))) { goto fail; }
    // 4: STRING LOOKUP:
    if(!VmmWinObjMgr_Initialize_ObMapLookupStr(pObObjectMap, &ctxInit)) { goto fail; }
    Ob_INCREF(pObObjectMap);
fail:
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
* -- return
*/
PVMMOB_MAP_OBJECT VmmWinObjMgr_Initialize()
{
    PVMMOB_MAP_OBJECT pObObject = NULL;
    if((pObObject = ObContainer_GetOb(ctxVmm->pObCMapObject))) { return pObObject; }
    EnterCriticalSection(&ctxVmm->LockUpdateMap);
    if((pObObject = ObContainer_GetOb(ctxVmm->pObCMapObject))) {
        LeaveCriticalSection(&ctxVmm->LockUpdateMap);
        return pObObject;
    }
    if(!(pObObject = VmmWinObjMgr_Initialize_DoWork())) {
        pObObject = Ob_Alloc(OB_TAG_MAP_OBJECT, LMEM_ZEROINIT, sizeof(VMMOB_MAP_OBJECT), NULL, NULL);
    }
    ObContainer_SetOb(ctxVmm->pObCMapObject, pObObject);
    LeaveCriticalSection(&ctxVmm->LockUpdateMap);
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
* -- return
*/
PVMMOB_MAP_KDRIVER VmmWinObjKDrv_Initialize_DoWork()
{
    BOOL f32 = ctxVmm->f32;
    DWORD i, j, cDriver, iObMapDriverBase;
    PVMM_PROCESS pObSystemProcess = NULL;
    PVMMOB_MAP_KDRIVER pObMap = NULL;
    PVMMOB_MAP_OBJECT pObObjMap = NULL;
    PVMM_MAP_OBJECTENTRY peObj;
    PVMM_MAP_KDRIVERENTRY pe;
    POB_SET psObPrefetch = NULL;
    POB_STRMAP psmObText = NULL;
    BYTE pbBuffer[sizeof(DRIVER_OBJECT64)];
    PDRIVER_OBJECT32 pD32 = (PDRIVER_OBJECT32)pbBuffer;
    PDRIVER_OBJECT64 pD64 = (PDRIVER_OBJECT64)pbBuffer;
    // 1: pre-init
    if(!(pObSystemProcess = VmmProcessGet(4))) { goto fail; }
    if(!(psObPrefetch = ObSet_New())) { goto fail; }
    if(!(psmObText = ObStrMap_New(OB_STRMAP_FLAGS_CASE_SENSITIVE))) { goto fail; }
    if(!VmmMap_GetObject(&pObObjMap)) { goto fail; }
    // 2: alloc object
    cDriver = pObObjMap->cType[ctxVmm->ObjectTypeTable.tpDriver];
    pObMap = Ob_Alloc(OB_TAG_MAP_KDRIVER, LMEM_ZEROINIT, sizeof(VMMOB_MAP_KDRIVER) + cDriver * sizeof(VMM_MAP_KDRIVERENTRY), (OB_CLEANUP_CB)VmmWinObjKDrv_ObCloseCallback, NULL);
    if(!pObMap) { goto fail; }
    pObMap->cMap = cDriver;
    // 3: get initial data from object map and prefetch
    iObMapDriverBase = pObObjMap->iTypeSortBase[ctxVmm->ObjectTypeTable.tpDriver];
    for(i = 0; i < cDriver; i++) {
        pe = pObMap->pMap + i;
        peObj = pObObjMap->pMap + pObObjMap->piTypeSort[iObMapDriverBase + i];
        ObSet_Push_PageAlign(psObPrefetch, peObj->va, sizeof(DRIVER_OBJECT64));
        ObStrMap_PushPtrUU(psmObText, peObj->uszName, &pe->uszName, NULL);
        pe->va = peObj->va;
        pe->dwHash = peObj->dwHash;
    }
    VmmCachePrefetchPages(pObSystemProcess, psObPrefetch, 0);
    ObSet_Clear(psObPrefetch);
    // 4: fetch driver objects and populate
    for(i = 0; i < cDriver; i++) {
        pe = pObMap->pMap + i;
        if(!VmmRead2(pObSystemProcess, pe->va, pbBuffer, (f32 ? sizeof(DRIVER_OBJECT32) : sizeof(DRIVER_OBJECT64)), VMM_FLAG_FORCECACHE_READ)) { continue; }
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
            pe->vaDeviceObject = VMM_KADDR32_8(pD64->DeviceObject) ? pD64->DeviceObject : 0;
            for(j = 0; j < 28; j++) {
                pe->MajorFunction[j] = pD64->MajorFunction[j];
            }
            ObStrMap_Push_UnicodeObject(psmObText, FALSE, pD64->DriverExtension + 0x18, &pe->uszServiceKeyName, NULL);
            ObStrMap_Push_UnicodeBuffer(psmObText, pD64->DriverName.Length, pD64->DriverName.Buffer, &pe->uszPath, NULL);
        }
    }
    if(!ObStrMap_FinalizeAllocU_DECREF_NULL(&psmObText, &pObMap->pbMultiText, &pObMap->cbMultiText)) { goto fail; }
    for(i = 0; i < cDriver; i++) {
        pe = pObMap->pMap + i;
        if(!pe->uszName) { pe->uszName = (LPSTR)pObMap->pbMultiText; }
        if(!pe->uszPath) { pe->uszPath = (LPSTR)pObMap->pbMultiText; }
        if(!pe->uszServiceKeyName) { pe->uszServiceKeyName = (PBYTE)pObMap->pbMultiText; }
    }
    qsort(pObMap->pMap, pObMap->cMap, sizeof(VMM_MAP_KDRIVERENTRY), (int(*)(void const *, void const *))VmmWinObjKDrv_Initialize_DoWork_CmpSort);
    Ob_INCREF(pObMap);
fail:
    Ob_DECREF(pObSystemProcess);
    Ob_DECREF(psObPrefetch);
    Ob_DECREF(psmObText);
    Ob_DECREF(pObObjMap);
    return Ob_DECREF(pObMap);
}

/*
* Create an kernel driver map and assign to the global vmm context upon success.
* CALLER DECREF: return
* -- return
*/
PVMMOB_MAP_KDRIVER VmmWinObjKDrv_Initialize()
{
    PVMMOB_MAP_KDRIVER pObKDriver = NULL;
    if((pObKDriver = ObContainer_GetOb(ctxVmm->pObCMapKDriver))) { return pObKDriver; }
    EnterCriticalSection(&ctxVmm->LockUpdateMap);
    if((pObKDriver = ObContainer_GetOb(ctxVmm->pObCMapKDriver))) {
        LeaveCriticalSection(&ctxVmm->LockUpdateMap);
        return pObKDriver;
    }
    if(!(pObKDriver = VmmWinObjKDrv_Initialize_DoWork())) {
        pObKDriver = Ob_Alloc(OB_TAG_MAP_KDRIVER, LMEM_ZEROINIT, sizeof(VMMOB_MAP_KDRIVER), NULL, NULL);
    }
    ObContainer_SetOb(ctxVmm->pObCMapKDriver, pObKDriver);
    LeaveCriticalSection(&ctxVmm->LockUpdateMap);
    return pObKDriver;
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
* -- szTypeName
* -- vaObject
* -- fDataObj
* -- fDataHdr
* -- ppObjectDisplay = ptr to receive POB_OBJECT_DISPLAY on success.
* -- return
*/
_Success_(return)
BOOL VmmWinObjDisplay_Get(_In_ LPSTR szTypeName, _In_ QWORD vaObject, _In_ BOOL fDataObj, _In_ BOOL fDataHdr, _Out_ POB_OBJECT_DISPLAY *ppObObjectDisplay)
{
    LPSTR szData = NULL;
    BOOL fResult = FALSE;
    POB_OBJECT_DISPLAY pOb = NULL;
    AcquireSRWLockExclusive(&ctxVmm->LockSRW.WinObjDisplay);
    // 1: fetch existing object from cache
    if(!ctxVmm->pObCacheMapWinObjDisplay) {
        if(!(ctxVmm->pObCacheMapWinObjDisplay = ObCacheMap_New(0x10000, NULL, OB_CACHEMAP_FLAGS_OBJECT_OB))) { goto fail; }
    }
    if(!(pOb = ObCacheMap_GetByKey(ctxVmm->pObCacheMapWinObjDisplay, vaObject))) {
        if(!(pOb = Ob_Alloc(OB_TAG_OBJ_DISPLAY, LMEM_ZEROINIT, sizeof(OB_OBJECT_DISPLAY), (OB_CLEANUP_CB)_VmmWinObjDisplay_ObCloseCallback, NULL))) { goto fail; }
        pOb->va = vaObject;
        ObCacheMap_Push(ctxVmm->pObCacheMapWinObjDisplay, vaObject, pOb, 0);
    }
    if((pOb->cbObj == -1) || (pOb->cbHdr == -1)) { goto fail; }
    // 2: fetch object data (if required)
    if(!pOb->cbObj || (fDataObj && !pOb->pdcObj)) {
        if(!PDB_DisplayTypeNt(szTypeName, 1, vaObject, TRUE, FALSE, (fDataObj ? &szData : NULL), &pOb->cbObj, &pOb->cbType)) { goto fail; }
        if(szData) {
            pOb->pdcObj = ObCompressed_NewFromByte(szData, pOb->cbObj);
            LocalFree(szData); szData = NULL;
            if(!pOb->pdcObj) { goto fail; }
        }
    }
    // 2: fetch header data (if required)
    if(!pOb->cbHdr || (fDataHdr && !pOb->pdcHdr)) {
        if(!PDB_DisplayTypeNt(szTypeName, 1, vaObject, TRUE, TRUE, (fDataHdr ? &szData : NULL), &pOb->cbHdr, NULL)) { goto fail; }
        if(szData) {
            pOb->pdcHdr = ObCompressed_NewFromByte(szData, pOb->cbHdr);
            LocalFree(szData); szData = NULL;
            if(!pOb->pdcHdr) { goto fail; }
        }
    }
    *ppObObjectDisplay = pOb;
    ReleaseSRWLockExclusive(&ctxVmm->LockSRW.WinObjDisplay);
    return TRUE;
fail:
    if(pOb) {
        pOb->cbObj = -1;
        pOb->cbHdr = -1;
    }
    Ob_DECREF(pOb);
    ReleaseSRWLockExclusive(&ctxVmm->LockSRW.WinObjDisplay);
    return FALSE;
}

/*
* Vfs Read: helper function to read object files in an object information dir.
* -- wszPathFile
* -- iTypeIndex = the object type index in the ObjectTypeTable
* -- vaObject
* -- pb
* -- cb
* -- pcbRead
* -- cbOffset
* -- return
*/
NTSTATUS VmmWinObjDisplay_VfsRead(_In_ LPSTR uszPathFile, _In_opt_ DWORD iTypeIndex, _In_ QWORD vaObject, _Out_writes_to_(cb, *pcbRead) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset)
{
    NTSTATUS nt = VMMDLL_STATUS_FILE_INVALID;
    POB_OBJECT_DISPLAY pObObjDisp = NULL;
    PVMMWIN_OBJECT_TYPE ptp = NULL;
    if(CharUtil_StrEndsWith(uszPathFile, "obj-address.txt", TRUE)) {
        if(ctxVmm->f32) {
            return Util_VfsReadFile_FromDWORD((DWORD)vaObject, pb, cb, pcbRead, cbOffset, FALSE);
        } else {
            return Util_VfsReadFile_FromQWORD(vaObject, pb, cb, pcbRead, cbOffset, FALSE);
        }
    }
    ptp = VmmWin_ObjectTypeGet((BYTE)iTypeIndex);
    if(ptp && CharUtil_StrEndsWith(uszPathFile, "obj-type.txt", TRUE)) {
        return Util_VfsReadFile_FromPBYTE(ptp->usz, strlen(ptp->usz), pb, cb, pcbRead, cbOffset);
    }
    if(CharUtil_StrEndsWith(uszPathFile, "obj-data.mem", TRUE)) {
        if(ptp && ptp->szType && VmmWinObjDisplay_Get(ptp->szType, vaObject, FALSE, FALSE, &pObObjDisp)) {
            nt = Util_VfsReadFile_FromMEM(PVMM_PROCESS_SYSTEM, pObObjDisp->va, pObObjDisp->cbType, VMM_FLAG_ZEROPAD_ON_FAIL, pb, cb, pcbRead, cbOffset);
            Ob_DECREF(pObObjDisp);
            return nt;
        }
        return Util_VfsReadFile_FromMEM(PVMM_PROCESS_SYSTEM, vaObject, VMMWINOBJDISPLAY_DEFAULT_OBJECT_MEMSIZE, VMM_FLAG_ZEROPAD_ON_FAIL, pb, cb, pcbRead, cbOffset);
    }
    if(CharUtil_StrEndsWith(uszPathFile, "obj-data.txt", TRUE) && ptp && ptp->szType && VmmWinObjDisplay_Get(ptp->szType, vaObject, TRUE, FALSE, &pObObjDisp)) {
        nt = Util_VfsReadFile_FromObCompressedStrA(pObObjDisp->pdcObj, pb, cb, pcbRead, cbOffset);
        Ob_DECREF(pObObjDisp);
        return nt;
    }
    if(CharUtil_StrEndsWith(uszPathFile, "obj-header.txt", TRUE) && ptp && ptp->szType && VmmWinObjDisplay_Get(ptp->szType, vaObject, FALSE, TRUE, &pObObjDisp)) {
        nt = Util_VfsReadFile_FromObCompressedStrA(pObObjDisp->pdcHdr, pb, cb, pcbRead, cbOffset);
        Ob_DECREF(pObObjDisp);
        return nt;
    }
    return nt;
}


/*
* Vfs List: helper function to list object files in an object information dir.
* -- iTypeIndex = the object type index in the ObjectTypeTable
* -- vaObject
* -- pFileList
*/
VOID VmmWinObjDisplay_VfsList(_In_opt_ DWORD iTypeIndex, _In_ QWORD vaObject, _Inout_ PHANDLE pFileList)
{
    PVMMWIN_OBJECT_TYPE ptp = NULL;
    POB_OBJECT_DISPLAY pObObjDisp = NULL;
    ptp = VmmWin_ObjectTypeGet((BYTE)iTypeIndex);
    if(ptp && ptp->szType && VmmWinObjDisplay_Get(ptp->szType, vaObject, FALSE, FALSE, &pObObjDisp)) {
        VMMDLL_VfsList_AddFile(pFileList, "obj-header.txt", pObObjDisp->cbHdr - 1, NULL);
        VMMDLL_VfsList_AddFile(pFileList, "obj-data.txt", pObObjDisp->cbObj - 1, NULL);
        VMMDLL_VfsList_AddFile(pFileList, "obj-data.mem", pObObjDisp->cbType, NULL);
    } else {
        VMMDLL_VfsList_AddFile(pFileList, "obj-data.mem", VMMWINOBJDISPLAY_DEFAULT_OBJECT_MEMSIZE, NULL);
    }
    if(ptp) {
        VMMDLL_VfsList_AddFile(pFileList, "obj-type.txt", strlen(ptp->usz), NULL);
    }
    VMMDLL_VfsList_AddFile(pFileList, "obj-address.txt", ctxVmm->f32 ? 8 : 16, NULL);
    Ob_DECREF(pObObjDisp);
}
