// ob_strmap.c : implementation of "string map" initialization functionality.
//
// The strmap is created and populated with strings (ascii and wide-char)
// in an optimal way removing duplicates. Upon finalization the string map
// results in a multi-string and an update of string references will happen.
//
// References to the strings will only be valid after a successful call to
// finalize_DECREF_NULL().
//
// The strmap is only meant to be an interim object to be used for creation
// of multi-string values and should not be kept as a long-lived object.
//
// The ObStrMap is an object manager object and must be DECREF'ed when required.
//
// (c) Ulf Frisk, 2020-2021
// Author: Ulf Frisk, pcileech@frizk.net
//
#include "ob.h"
#include "../vmm.h"
#include "../vmmwindef.h"
#include <stdio.h>
#include <stdarg.h>

#define OB_STRMAP_SUBENTRY_SIZE         0x10
#define OB_STRMAP_IS_VALID(p)           (p && (p->ObHdr._magic == OB_HEADER_MAGIC) && (p->ObHdr._tag == OB_TAG_CORE_STRMAP))

typedef struct tdOB_STRMAP_UNICODEENTRY {
    struct tdOB_STRMAP_UNICODEENTRY *FLink;
    QWORD va;
    LPWSTR *pwsz;
    DWORD *pcch;
    union {
        BOOL f32;
        WORD cb;
    };
} OB_STRMAP_UNICODEENTRY, *POB_STRMAP_UNICODEENTRY;

typedef struct tdOB_STRMAP_PTRENTRY {
    LPWSTR *pwsz;
    DWORD *pcch;
} OB_STRMAP_PTRENTRY, *POB_STRMAP_PTRENTRY;

typedef struct tdOB_STRMAP_SUBENTRY {
    struct tdOB_STRMAP_SUBENTRY *FLink;
    OB_STRMAP_PTRENTRY e[OB_STRMAP_SUBENTRY_SIZE];
} OB_STRMAP_SUBENTRY, *POB_STRMAP_SUBENTRY;

typedef struct tdOB_STRMAP_ENTRY {
    POB_STRMAP_SUBENTRY FLink;
    DWORD cch;  // incl. terminating NULL.
    OB_STRMAP_PTRENTRY e1;
    WCHAR wsz[0];
} OB_STRMAP_ENTRY, *POB_STRMAP_ENTRY;


typedef struct tdOB_STRMAP {
    OB ObHdr;
    SRWLOCK LockSRW;
    BOOL fStrAssignTemporary;   // assign "temporary" strings to output location at push.
    BOOL fCaseInsensitive;
    DWORD cch;                  // incl. terminating NULL.
    POB_MAP pm;
    POB_STRMAP_UNICODEENTRY pUnicodeObjectListHead;
    POB_STRMAP_UNICODEENTRY pUnicodeBufferListHead;
} OB_STRMAP, *POB_STRMAP;

#define OB_STRMAP_CALL_SYNCHRONIZED_IMPLEMENTATION_WRITE(psm, RetTp, RetValFail, fn) {  \
    if(!OB_STRMAP_IS_VALID(psm)) { return RetValFail; }                                 \
    RetTp retVal;                                                                       \
    AcquireSRWLockExclusive(&psm->LockSRW);                                             \
    retVal = fn;                                                                        \
    ReleaseSRWLockExclusive(&psm->LockSRW);                                             \
    return retVal;                                                                      \
}

QWORD _StrMap_HashStringA(_In_ LPCSTR sz, _In_ BOOL fUpper)
{
    CHAR c;
    QWORD i = 0, qwHash = 0;
    if(!sz) { return 0; }
    while(TRUE) {
        c = sz[i++];
        if(!c) { return qwHash; }
        if(fUpper && c >= 'a' && c <= 'z') {
            c += 'A' - 'a';
        }
        qwHash = ((qwHash >> 13) | (qwHash << 51)) + c;
    }
}

QWORD _StrMap_HashStringW(_In_ LPCWSTR wsz, _In_ BOOL fUpper)
{
    WCHAR c;
    QWORD i = 0, qwHash = 0;
    if(!wsz) { return 0; }
    while(TRUE) {
        c = wsz[i++];
        if(!c) { return qwHash; }
        if(fUpper && c >= 'a' && c <= 'z') {
            c += 'A' - 'a';
        }
        qwHash = ((qwHash >> 13) | (qwHash << 51)) + c;
    }
}

_Success_(return)
BOOL _ObStrMap_Push(_In_ POB_STRMAP psm, _In_opt_ LPSTR sz, _In_opt_ LPWSTR wsz, _Out_opt_ LPWSTR *pwszDst, _Out_opt_ PDWORD pcchDst)
{
    BOOL fW = FALSE;
    DWORD i, cch;
    QWORD qwHash = 0;
    POB_STRMAP_ENTRY pStrEntry = NULL;
    POB_STRMAP_SUBENTRY pStrSubEntry = NULL;
    if(!pwszDst && !pcchDst) { return TRUE; }
    if(pwszDst) { *pwszDst = NULL; }
    if(pcchDst) { *pcchDst = 0; }
    if(wsz) {
        fW = TRUE;
        qwHash = _StrMap_HashStringW(wsz, psm->fCaseInsensitive);
    } else if(sz) {
        qwHash = _StrMap_HashStringA(sz, psm->fCaseInsensitive);
    }
    qwHash = max(1, qwHash);
    pStrEntry = ObMap_GetByKey(psm->pm, qwHash);
    if(pStrEntry) {
        // existing string entry
        if(!pStrEntry->FLink) {
            if(!(pStrEntry->FLink = LocalAlloc(LMEM_ZEROINIT, sizeof(OB_STRMAP_SUBENTRY)))) { return FALSE; }
        }
        pStrSubEntry = pStrEntry->FLink;
        while(pStrSubEntry->FLink) {
            pStrSubEntry = pStrSubEntry->FLink;
        }
        if(pStrSubEntry->e[OB_STRMAP_SUBENTRY_SIZE - 1].pwsz || pStrSubEntry->e[OB_STRMAP_SUBENTRY_SIZE - 1].pcch) {
            if(!(pStrSubEntry->FLink = LocalAlloc(LMEM_ZEROINIT, sizeof(OB_STRMAP_SUBENTRY)))) { return FALSE; }
            pStrSubEntry = pStrSubEntry->FLink;
        }
        for(i = 0; i < OB_STRMAP_SUBENTRY_SIZE; i++) {
            if(!pStrSubEntry->e[i].pwsz && !pStrSubEntry->e[i].pcch) {
                pStrSubEntry->e[i].pwsz = pwszDst;
                pStrSubEntry->e[i].pcch = pcchDst;
                break;
            }
        }
    } else {
        // new string entry
        if(!sz && !wsz) { return FALSE; }  // should never happen!
        cch = (DWORD)(fW ? wcslen(wsz) : strlen(sz)) + 1;
        if((psm->cch > 0x40000000) || (cch > 0x00100000)) { return FALSE; }
        if(!(pStrEntry = LocalAlloc(0, sizeof(OB_STRMAP_ENTRY) + cch * sizeof(WCHAR)))) { return FALSE; }
        psm->cch += cch;
        pStrEntry->FLink = NULL;
        pStrEntry->cch = cch;
        pStrEntry->e1.pwsz = pwszDst;
        pStrEntry->e1.pcch = pcchDst;
        if(fW) {
            memcpy(pStrEntry->wsz, wsz, (QWORD)cch << 1);
        } else {
            for(i = 0; i < cch; i++) {
                pStrEntry->wsz[i] = sz[i];
            }
        }
        ObMap_Push(psm->pm, qwHash, pStrEntry);
    }
    if(psm->fStrAssignTemporary && pwszDst) {
        *pwszDst = pStrEntry->wsz;
    }
    return TRUE;
}

/*
* Push / Insert into the ObStrMap.
* -- psm
* -- sz
* -- pwszDst
* -- pcchDst
* -- return = TRUE on insertion, FALSE otherwise.
*/
_Success_(return)
BOOL ObStrMap_PushA(_In_opt_ POB_STRMAP psm, _In_opt_ LPSTR sz, _Out_opt_ LPWSTR *pwszDst, _Out_opt_ PDWORD pcchDst)
{
    OB_STRMAP_CALL_SYNCHRONIZED_IMPLEMENTATION_WRITE(psm, BOOL, FALSE, _ObStrMap_Push(psm, sz, NULL, pwszDst, pcchDst))
}

/*
* Push / Insert into the ObStrMap.
* -- psm
* -- wsz
* -- pwszDst
* -- pcchDst
* -- return = TRUE on insertion, FALSE otherwise.
*/
_Success_(return)
BOOL ObStrMap_Push(_In_opt_ POB_STRMAP psm, _In_opt_ LPWSTR wsz, _Out_opt_ LPWSTR *pwszDst, _Out_opt_ PDWORD pcchDst)
{
    OB_STRMAP_CALL_SYNCHRONIZED_IMPLEMENTATION_WRITE(psm, BOOL, FALSE, _ObStrMap_Push(psm, NULL, wsz, pwszDst, pcchDst))
}

_Success_(return)
BOOL _ObStrMap_Push_UnicodeObject(_In_ POB_STRMAP psm, _In_ BOOL f32, _In_ QWORD vaUnicodeObject, _Out_opt_ LPWSTR *pwszDst, _Out_opt_ PDWORD pcchDst)
{
    POB_STRMAP_UNICODEENTRY pUnicodeEntry;
    if(!pwszDst && !pcchDst) { return TRUE; }
    if(psm->fStrAssignTemporary) { return FALSE; }
    if((f32 && !VMM_KADDR32_4(vaUnicodeObject)) || (!f32 && !VMM_KADDR64_8(vaUnicodeObject))) {
        _ObStrMap_Push(psm, NULL, NULL, pwszDst, pcchDst);
        return TRUE;
    }
    if(pwszDst) { *pwszDst = NULL; }
    if(pcchDst) { *pcchDst = 0; }
    if(!(pUnicodeEntry = LocalAlloc(LMEM_ZEROINIT, sizeof(OB_STRMAP_UNICODEENTRY)))) { return FALSE; }
    pUnicodeEntry->f32 = f32;
    pUnicodeEntry->va = vaUnicodeObject;
    pUnicodeEntry->pwsz = pwszDst;
    pUnicodeEntry->pcch = pcchDst;
    pUnicodeEntry->FLink = psm->pUnicodeObjectListHead;
    psm->pUnicodeObjectListHead = pUnicodeEntry;
    return TRUE;
}

_Success_(return)
BOOL _ObStrMap_Push_UnicodeBuffer(_In_ POB_STRMAP psm, _In_ WORD cbUnicodeBuffer, _In_ QWORD vaUnicodeBuffer, _Out_opt_ LPWSTR *pwszDst, _Out_opt_ PDWORD pcchDst)
{
    POB_STRMAP_UNICODEENTRY pUnicodeEntry;
    if(!pwszDst && !pcchDst) { return TRUE; }
    if(psm->fStrAssignTemporary) { return FALSE; }
    if((cbUnicodeBuffer & 1) || (vaUnicodeBuffer & 1)) {
        _ObStrMap_Push(psm, NULL, NULL, pwszDst, pcchDst);
        return TRUE;
    }
    cbUnicodeBuffer = min(cbUnicodeBuffer, MAX_PATH * 2);
    if(pwszDst) { *pwszDst = NULL; }
    if(pcchDst) { *pcchDst = 0; }
    if(!(pUnicodeEntry = LocalAlloc(LMEM_ZEROINIT, sizeof(OB_STRMAP_UNICODEENTRY)))) { return FALSE; }
    pUnicodeEntry->cb = cbUnicodeBuffer;
    pUnicodeEntry->va = vaUnicodeBuffer;
    pUnicodeEntry->pwsz = pwszDst;
    pUnicodeEntry->pcch = pcchDst;
    pUnicodeEntry->FLink = psm->pUnicodeBufferListHead;
    psm->pUnicodeBufferListHead = pUnicodeEntry;
    return TRUE;
}

/*
* Push a UNICODE_OBJECT Pointer for delayed resolve at finalize stage.
* NB! Incompatible with: OB_STRMAP_FLAGS_STR_ASSIGN_TEMPORARY create flag.
* -- psm
* -- f32 = 32-bit/64-bit unicode object.
* -- vaUnicodeObject
* -- pwszDst
* -- pcchDst
* -- return = TRUE on initial validation success (NB! no guarantee for success).
*/
_Success_(return)
BOOL ObStrMap_Push_UnicodeObject(_In_opt_ POB_STRMAP psm, _In_ BOOL f32, _In_ QWORD vaUnicodeObject, _Out_opt_ LPWSTR *pwszDst, _Out_opt_ PDWORD pcchDst)
{
    OB_STRMAP_CALL_SYNCHRONIZED_IMPLEMENTATION_WRITE(psm, BOOL, FALSE, _ObStrMap_Push_UnicodeObject(psm, f32, vaUnicodeObject, pwszDst, pcchDst))
}

/*
* Push a UNICODE_OBJECT Buffer for delayed resolve at finalize stage.
* NB! Incompatible with: OB_STRMAP_FLAGS_STR_ASSIGN_TEMPORARY create flag.
* -- psm
* -- cbUnicodeBuffer.
* -- vaUnicodeBuffer
* -- pwszDst
* -- pcchDst
* -- return = TRUE on initial validation success (NB! no guarantee for success).
*/
_Success_(return)
BOOL ObStrMap_Push_UnicodeBuffer(_In_opt_ POB_STRMAP psm, _In_ WORD cbUnicodeBuffer, _In_ QWORD vaUnicodeBuffer, _Out_opt_ LPWSTR *pwszDst, _Out_opt_ PDWORD pcchDst)
{
    OB_STRMAP_CALL_SYNCHRONIZED_IMPLEMENTATION_WRITE(psm, BOOL, FALSE, _ObStrMap_Push_UnicodeBuffer(psm, cbUnicodeBuffer, vaUnicodeBuffer, pwszDst, pcchDst))
}

/*
* Push / Insert max 2048 characters into ObStrMap using a swprintf_s syntax.
* -- psm
* -- pwszDst
* -- pcchDst
* -- wszFormat
* -- ...
* -- return = TRUE on insertion, FALSE otherwise.
*/
_Success_(return)
BOOL ObStrMap_Push_swprintf_s(_In_opt_ POB_STRMAP psm, _Out_opt_ LPWSTR *pwszDst, _Out_opt_ PDWORD pcchDst, _In_z_ _Printf_format_string_ wchar_t const *const wszFormat, ...)
{
    int cch;
    va_list arglist;
    WCHAR wszBuffer[2048];
    va_start(arglist, wszFormat);
    cch = _vsnwprintf_s(wszBuffer, 2048, _TRUNCATE, wszFormat, arglist);
    va_end(arglist);
    if(cch < 0) { return FALSE; }
    return ObStrMap_Push(psm, wszBuffer, pwszDst, pcchDst);
}

/*
* Object StrMap object manager cleanup function to be called when reference
* count reaches zero.
* -- psm
*/
VOID _ObStrMap_ObCloseCallback(_In_ POB_STRMAP psm)
{
    POB_STRMAP_ENTRY pe;
    POB_STRMAP_UNICODEENTRY pu;
    POB_STRMAP_SUBENTRY pse, pseNext;
    while((pe = ObMap_Pop(psm->pm))) {
        pse = pe->FLink;
        while(pse) {
            pseNext = pse->FLink;
            LocalFree(pse);
            pse = pseNext;
        }
        LocalFree(pe);
    }
    while((pu = psm->pUnicodeBufferListHead)) {
        psm->pUnicodeBufferListHead = pu->FLink;
        LocalFree(pu);
    }
    while((pu = psm->pUnicodeObjectListHead)) {
        psm->pUnicodeObjectListHead = pu->FLink;
        LocalFree(pu);
    }
    Ob_DECREF(psm->pm);
}

VOID _ObStrMap_FinalizeDoWork_UnicodeResolve(_In_ POB_STRMAP psm)
{
    BOOL f;
    WCHAR wsz[MAX_PATH + 1];
    POB_STRMAP_UNICODEENTRY pu;
    POB_SET psObPrefetch = NULL;
    PVMM_PROCESS pObSystemProcess = NULL;
    BYTE pbBuffer[sizeof(UNICODE_STRING64)];
    if(!psm->pUnicodeObjectListHead && !psm->pUnicodeBufferListHead) { return; }
    if(!(psObPrefetch = ObSet_New())) { return; }
    if(!(pObSystemProcess = VmmProcessGet(4))) { goto fail; }
    // resolve unicode object pointers:
    if(psm->pUnicodeObjectListHead) {
        pu = psm->pUnicodeObjectListHead;
        while(pu) {
            ObSet_Push_PageAlign(psObPrefetch, pu->va, pu->f32 ? sizeof(UNICODE_STRING32) : sizeof(UNICODE_STRING64));
            pu = pu->FLink;
        }
        VmmCachePrefetchPages(pObSystemProcess, psObPrefetch, 0);
        pu = psm->pUnicodeObjectListHead;
        while(pu) {
            if(VmmRead2(pObSystemProcess, pu->va, pbBuffer, pu->f32 ? sizeof(UNICODE_STRING32) : sizeof(UNICODE_STRING64), VMM_FLAG_FORCECACHE_READ)) {
                f = pu->f32 ?
                    _ObStrMap_Push_UnicodeBuffer(psm, ((PUNICODE_STRING32)pbBuffer)->Length, ((PUNICODE_STRING32)pbBuffer)->Buffer, pu->pwsz, pu->pcch) :
                    _ObStrMap_Push_UnicodeBuffer(psm, ((PUNICODE_STRING64)pbBuffer)->Length, ((PUNICODE_STRING64)pbBuffer)->Buffer, pu->pwsz, pu->pcch);
                if(!f) {
                    _ObStrMap_Push(psm, NULL, NULL, pu->pwsz, pu->pcch);
                }
            }
            pu = pu->FLink;
        }
        ObSet_Clear(psObPrefetch);
    }
    // resolve unicode object buffers:
    if(psm->pUnicodeBufferListHead) {
        pu = psm->pUnicodeBufferListHead;
        while(pu) {
            ObSet_Push_PageAlign(psObPrefetch, pu->va, pu->cb);
            pu = pu->FLink;
        }
        VmmCachePrefetchPages(pObSystemProcess, psObPrefetch, 0);
        pu = psm->pUnicodeBufferListHead;
        while(pu) {
            wsz[0] = 0;
            if(VmmRead2(pObSystemProcess, pu->va, (PBYTE)wsz, pu->cb, VMM_FLAG_FORCECACHE_READ)) {
                wsz[pu->cb >> 1] = 0;
            }
            _ObStrMap_Push(psm, NULL, wsz, pu->pwsz, pu->pcch);
            pu = pu->FLink;
        }
    }
fail:
    Ob_DECREF(pObSystemProcess);
    Ob_DECREF(psObPrefetch);
}

_Success_(return)
BOOL _ObStrMap_FinalizeDoWork(_In_ POB_STRMAP psm, _Out_ LPWSTR *pwszMultiStr, _Out_ PDWORD pcbMultiStr)
{
    DWORD i, j, cMax, o = 1;
    LPWSTR wsz, wszMultiStr;
    POB_STRMAP_ENTRY pe;
    POB_STRMAP_SUBENTRY pse, pseNext;
    _ObStrMap_FinalizeDoWork_UnicodeResolve(psm);
    if(!(wszMultiStr = LocalAlloc(0, psm->cch * sizeof(WCHAR)))) { return FALSE; }
    wszMultiStr[0] = 0;
    for(i = 0, cMax = ObMap_Size(psm->pm); i < cMax; i++) {
        // 1: fetch entry and assign to multi-string.
        pe = ObMap_GetByIndex(psm->pm, i);
        if(pe->cch == 1) {
            wsz = wszMultiStr;
        } else {
            wsz = wszMultiStr + o;
            o += pe->cch;
        }
        memcpy(wsz, pe->wsz, (QWORD)pe->cch << 1);
        // 2: assign ptr to value0
        if(pe->e1.pcch) {
            *(pe->e1.pcch) = pe->cch - 1;
        }
        if(pe->e1.pwsz) {
            *(pe->e1.pwsz) = wsz;
        }
        // 3: assign ptr to other values
        pse = pe->FLink;
        while(pse) {
            pseNext = pse->FLink;
            for(j = 0; j < OB_STRMAP_SUBENTRY_SIZE; j++) {
                if(pse->e[j].pcch) {
                    *(pse->e[j].pcch) = pe->cch - 1;
                }
                if(pse->e[j].pwsz) {
                    *(pse->e[j].pwsz) = wsz;
                }
            }
            pse = pseNext;
        }
    }
    *pwszMultiStr = wszMultiStr;
    *pcbMultiStr = o * sizeof(WCHAR);
    return TRUE;
}

_Success_(return)
BOOL _ObStrMap_Finalize(_In_ POB_STRMAP psm, _Out_ LPWSTR *pwszMultiStr, _Out_ PDWORD pcbMultiStr)
{
    OB_STRMAP_CALL_SYNCHRONIZED_IMPLEMENTATION_WRITE(psm, BOOL, FALSE, _ObStrMap_FinalizeDoWork(psm, pwszMultiStr, pcbMultiStr))
}

/*
* Finalize the ObStrMap. Create and assign the MultiStr and assign each
* previously added string reference to a pointer location within the MultiStr.
* ---
* Also decrease the reference count of the object. If the reference count
* reaches zero the object will be cleaned up.
* Also set the incoming pointer to NULL.
* CALLER LOCALFREE: *pwszMultiStr
* -- ppObStrMap
* -- pwszMultiStr
* -- pcbMultiStr
* -- return
*/
_Success_(return)
BOOL ObStrMap_Finalize_DECREF_NULL(_In_opt_ PVOID *ppsm, _Out_ LPWSTR *pwszMultiStr, _Out_ PDWORD pcbMultiStr)
{
    BOOL f = FALSE;
    f = ppsm && _ObStrMap_Finalize(*ppsm, pwszMultiStr, pcbMultiStr);
    Ob_DECREF_NULL(ppsm);
    return f;
}

/*
* Create a new strmap. A strmap (ObStrMap) provides an easy way to add new
* strings to a multi-string in an efficient way. The ObStrMap is not meant
* to be a long-term object - it's supposed to be finalized and decommissioned
* by calling ObStrMap_Finalize_DECREF_NULL().
* The ObStrMap is an object manager object and must be DECREF'ed when required.
* CALLER DECREF: return
* -- flags
* -- return
*/
POB_STRMAP ObStrMap_New(_In_ QWORD flags)
{
    POB_STRMAP pObStrMap = NULL;
    POB_STRMAP_ENTRY pStrEntry = NULL;
    if(!(pObStrMap = Ob_Alloc(OB_TAG_CORE_STRMAP, LMEM_ZEROINIT, sizeof(OB_STRMAP), _ObStrMap_ObCloseCallback, NULL))) { goto fail; }
    if(!(pStrEntry = LocalAlloc(LMEM_ZEROINIT, sizeof(OB_STRMAP_ENTRY) + 2))) { goto fail; }
    if(!(pObStrMap->pm = ObMap_New(0))) { goto fail; }
    pObStrMap->fCaseInsensitive = (flags & OB_STRMAP_FLAGS_CASE_INSENSITIVE) ? TRUE : FALSE;
    pObStrMap->fStrAssignTemporary = (flags & OB_STRMAP_FLAGS_STR_ASSIGN_TEMPORARY) ? TRUE : FALSE;
    pObStrMap->cch = 1;
    pStrEntry->cch = 1;
    ObMap_Push(pObStrMap->pm, 1, pStrEntry);
    return pObStrMap;
fail:
    LocalFree(pStrEntry);
    Ob_DECREF(pObStrMap);
    return FALSE;
}
