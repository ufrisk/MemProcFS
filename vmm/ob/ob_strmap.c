// ob_strmap.c : implementation of string map initialization functionality.
//
// The strmap is created and populated with strings (utf-8, ascii and wide-char)
// in an optimal way removing duplicates. Upon finalization the string map
// results in a multi-string and an update of string references will happen.
//
// References to the strings will only be valid after a successful call to
// FinalizeAlloc_DECREF_NULL() or FinalizeBuffer()
//
// The strmap is only meant to be an interim object to be used for creation
// of multi-string values and should not be kept as a long-lived object.
//
// The ObStrMap is an object manager object and must be DECREF'ed when required.
//
// (c) Ulf Frisk, 2021
// Author: Ulf Frisk, pcileech@frizk.net
//
#include "ob.h"
#include "../vmm.h"
#include "../charutil.h"
#include "../vmmwindef.h"
#include <stdio.h>
#include <stdarg.h>

#define OB_STRMAP_SUBENTRY_SIZE         0x10
#define OB_STRUMAP_IS_VALID(p)           (p && (p->ObHdr._magic == OB_HEADER_MAGIC) && (p->ObHdr._tag == OB_TAG_CORE_STRMAP))

typedef struct tdOB_STRMAP_PTRENTRY {
    LPSTR *pusz;
    LPWSTR *pwsz;
    DWORD *pcbu;
    DWORD *pcbw;
} OB_STRMAP_PTRENTRY, *POB_STRMAP_PTRENTRY;

typedef struct tdOB_STRMAP_UNICODEENTRY {
    struct tdOB_STRMAP_UNICODEENTRY *FLink;
    QWORD va;
    OB_STRMAP_PTRENTRY p;
    union {
        BOOL f32;
        WORD cb;
    };
} OB_STRMAP_UNICODEENTRY, *POB_STRMAP_UNICODEENTRY;

typedef struct tdOB_STRMAP_SUBENTRY {
    struct tdOB_STRMAP_SUBENTRY *FLink;
    OB_STRMAP_PTRENTRY e[OB_STRMAP_SUBENTRY_SIZE];
} OB_STRMAP_SUBENTRY, *POB_STRMAP_SUBENTRY;

typedef struct tdOB_STRMAP_ENTRY {
    OB_STRMAP_SUBENTRY SubEntry;
    DWORD cbu;                  // incl. terminating NULL.
    DWORD cbw;                  // incl. terminating NULL.
    CHAR usz[0];
} OB_STRMAP_ENTRY, *POB_STRMAP_ENTRY;

typedef struct tdOB_STRMAP {
    OB ObHdr;
    SRWLOCK LockSRW;
    BOOL fFinalized;
    BOOL fCaseInsensitive;
    BOOL fStrAssignTemporary;   // assign "temporary" strings to output location at push.
    BOOL fStrAssignOffset;      // assign offset (in bytes) instead of pointer at finalize.
    DWORD cbu;                  // incl. terminating NULL.
    DWORD cbw;                  // incl. terminating NULL.
    POB_MAP pm;
    POB_STRMAP_UNICODEENTRY pUnicodeObjectListHead;
    POB_STRMAP_UNICODEENTRY pUnicodeBufferListHead;
} OB_STRMAP, *POB_STRMAP;

#define OB_STRUMAP_CALL_SYNCHRONIZED_IMPLEMENTATION_WRITE(psm, RetTp, RetValFail, fn) { \
    if(!OB_STRUMAP_IS_VALID(psm)) { return RetValFail; }                                \
    RetTp retVal;                                                                       \
    AcquireSRWLockExclusive(&psm->LockSRW);                                             \
    retVal = fn;                                                                        \
    ReleaseSRWLockExclusive(&psm->LockSRW);                                             \
    return retVal;                                                                      \
}

_Success_(return != NULL)
POB_STRMAP_ENTRY _ObStrMap_PushStr(_In_ POB_STRMAP psm, _In_opt_ LPSTR usz, _In_opt_ LPSTR sz, _In_opt_ LPWSTR wsz)
{
    BOOL f;
    DWORD cbu = 0;
    QWORD qwHash = 0;
    POB_STRMAP_ENTRY pStrEntry = NULL;
    if(usz) {
        qwHash = CharUtil_Hash64U(usz, psm->fCaseInsensitive);
    } else if(wsz) {
        qwHash = CharUtil_Hash64W(wsz, psm->fCaseInsensitive);
    } else if(sz) {
        qwHash = CharUtil_Hash64A(sz, psm->fCaseInsensitive);
    }
    // 1: existing string entry:
    qwHash = max(1, qwHash);
    pStrEntry = ObMap_GetByKey(psm->pm, qwHash);
    if(pStrEntry) { return pStrEntry; }
    // 2: new string entry:
    if(psm->fFinalized) { return NULL; }
    if(usz) {
        CharUtil_UtoU(usz, -1, NULL, 0, NULL, &cbu, 0);
    } else if(wsz) {
        CharUtil_WtoU(wsz, -1, NULL, 0, NULL, &cbu, 0);
    } else {
        CharUtil_AtoU(sz, -1, NULL, 0, NULL, &cbu, 0);
    }
    if((psm->cbu > 0x40000000) || !cbu || (cbu > 0x00100000)) { return NULL; }
    if(!(pStrEntry = LocalAlloc(LMEM_ZEROINIT, sizeof(OB_STRMAP_ENTRY) + cbu))) { return NULL; }
    psm->cbu += cbu;
    pStrEntry->cbu = cbu;
    if(usz) {
        f = CharUtil_UtoU(usz, -1, pStrEntry->usz, cbu, NULL, NULL, CHARUTIL_FLAG_TRUNCATE | CHARUTIL_FLAG_STR_BUFONLY);
    } else if(wsz) {
        f = CharUtil_WtoU(wsz, -1, pStrEntry->usz, cbu, NULL, NULL, CHARUTIL_FLAG_TRUNCATE | CHARUTIL_FLAG_STR_BUFONLY);
    } else {
        f = CharUtil_AtoU(sz, -1, pStrEntry->usz, cbu, NULL, NULL, CHARUTIL_FLAG_TRUNCATE | CHARUTIL_FLAG_STR_BUFONLY);
    }
    if(f) {
        ObMap_Push(psm->pm, qwHash, pStrEntry);
    } else {
        LocalFree(pStrEntry);
        pStrEntry = NULL;
    }
    return pStrEntry;
}

_Success_(return)
BOOL _ObStrMap_PushPtr(_In_ POB_STRMAP psm, _In_opt_ LPSTR usz, _In_opt_ LPSTR sz, _In_opt_ LPWSTR wsz, _Out_opt_ LPSTR *puszDst, _Out_opt_ PDWORD pcbuDst, _Out_opt_ LPWSTR *pwszDst, _Out_opt_ PDWORD pcbwDst)
{
    DWORD i;
    POB_STRMAP_ENTRY pe;
    POB_STRMAP_SUBENTRY pSubEntry;
    pe = _ObStrMap_PushStr(psm, usz, sz, wsz);
    if(!pe) {
        pe = _ObStrMap_PushStr(psm, NULL, NULL, NULL);
        if(!pe) { return FALSE; }
    }
    pSubEntry = &pe->SubEntry;
    // existing string entry
    while(pSubEntry->FLink) {
        pSubEntry = pSubEntry->FLink;
    }
    for(i = 0; i < OB_STRMAP_SUBENTRY_SIZE; i++) {
        if(puszDst || pcbuDst) {
            if(!pSubEntry->e[i].pusz && !pSubEntry->e[i].pcbu) {
                pSubEntry->e[i].pusz = puszDst;
                pSubEntry->e[i].pcbu = pcbuDst;
                break;
            }
        }
        if(pwszDst || pcbwDst) {
            if(!pSubEntry->e[i].pwsz && !pSubEntry->e[i].pcbw) {
                pSubEntry->e[i].pwsz = pwszDst;
                pSubEntry->e[i].pcbw = pcbwDst;
                break;
            }
        }
    }
    if(i == OB_STRMAP_SUBENTRY_SIZE - 1) {
        pSubEntry->FLink = LocalAlloc(LMEM_ZEROINIT, sizeof(OB_STRMAP_SUBENTRY));
    }
    if(puszDst) { *puszDst = psm->fStrAssignTemporary ? pe->usz : NULL; }
    if(pcbuDst) { *pcbuDst = psm->fStrAssignTemporary ? pe->cbu : 0; }
    if(pwszDst) { *pwszDst = NULL; }
    if(pcbwDst) { *pcbwDst = 0; }
    return TRUE;
}

_Success_(return)
BOOL _ObStrMap_Push(_In_ POB_STRMAP psm, _In_opt_ LPSTR usz, _In_opt_ LPSTR sz, _In_opt_ LPWSTR wsz)
{
    return _ObStrMap_PushStr(psm, usz, sz, wsz) ? TRUE : FALSE;
}

/*
* Push / Insert into the ObStrMap.
* -- psm
* -- usz
* -- return = TRUE on insertion, FALSE otherwise.
*/
_Success_(return)
BOOL ObStrMap_PushU(_In_opt_ POB_STRMAP psm, _In_opt_ LPSTR usz)
{
    OB_STRUMAP_CALL_SYNCHRONIZED_IMPLEMENTATION_WRITE(psm, BOOL, FALSE, _ObStrMap_Push(psm, usz, NULL, NULL))
}

/*
* Push / Insert into the ObStrMap.
* -- psm
* -- sz
* -- return = TRUE on insertion, FALSE otherwise.
*/
_Success_(return)
BOOL ObStrMap_PushA(_In_opt_ POB_STRMAP psm, _In_opt_ LPSTR sz)
{
    OB_STRUMAP_CALL_SYNCHRONIZED_IMPLEMENTATION_WRITE(psm, BOOL, FALSE, _ObStrMap_Push(psm, NULL, sz, NULL))
}

/*
* Push / Insert into the ObStrMap.
* -- psm
* -- wsz
* -- return = TRUE on insertion, FALSE otherwise.
*/
_Success_(return)
BOOL ObStrMap_PushW(_In_opt_ POB_STRMAP psm, _In_opt_ LPWSTR wsz)
{
    OB_STRUMAP_CALL_SYNCHRONIZED_IMPLEMENTATION_WRITE(psm, BOOL, FALSE, _ObStrMap_Push(psm, NULL, NULL, wsz))
}

/*
* Push / Insert into the ObStrMap.
* -- psm
* -- usz
* -- puszDst
* -- pcbuDst
* -- return = TRUE on insertion, FALSE otherwise.
*/
_Success_(return)
BOOL ObStrMap_PushPtrUU(_In_opt_ POB_STRMAP psm, _In_opt_ LPSTR usz, _Out_opt_ LPSTR *puszDst, _Out_opt_ PDWORD pcbuDst)
{
    OB_STRUMAP_CALL_SYNCHRONIZED_IMPLEMENTATION_WRITE(psm, BOOL, FALSE, _ObStrMap_PushPtr(psm, usz, NULL, NULL, puszDst, pcbuDst, NULL, NULL))
}

/*
* Push / Insert into the ObStrMap.
* -- psm
* -- sz
* -- puszDst
* -- pcbuDst
* -- return = TRUE on insertion, FALSE otherwise.
*/
_Success_(return)
BOOL ObStrMap_PushPtrAU(_In_opt_ POB_STRMAP psm, _In_opt_ LPSTR sz, _Out_opt_ LPSTR *puszDst, _Out_opt_ PDWORD pcbuDst)
{
    OB_STRUMAP_CALL_SYNCHRONIZED_IMPLEMENTATION_WRITE(psm, BOOL, FALSE, _ObStrMap_PushPtr(psm, NULL, sz, NULL, puszDst, pcbuDst, NULL, NULL))
}

/*
* Push / Insert into the ObStrMap.
* -- psm
* -- wsz
* -- puszDst
* -- pcbuDst
* -- return = TRUE on insertion, FALSE otherwise.
*/
_Success_(return)
BOOL ObStrMap_PushPtrWU(_In_opt_ POB_STRMAP psm, _In_opt_ LPWSTR wsz, _Out_opt_ LPSTR *puszDst, _Out_opt_ PDWORD pcbuDst)
{
    OB_STRUMAP_CALL_SYNCHRONIZED_IMPLEMENTATION_WRITE(psm, BOOL, FALSE, _ObStrMap_PushPtr(psm, NULL, NULL, wsz, puszDst, pcbuDst, NULL, NULL))
}

/*
* Push / Insert into the ObStrMap.
* -- psm
* -- usz
* -- pwszDst
* -- pcbwDst
* -- return = TRUE on insertion, FALSE otherwise.
*/
_Success_(return)
BOOL ObStrMap_PushPtrUW(_In_opt_ POB_STRMAP psm, _In_opt_ LPSTR usz, _Out_opt_ LPWSTR *pwszDst, _Out_opt_ PDWORD pcbwDst)
{
    OB_STRUMAP_CALL_SYNCHRONIZED_IMPLEMENTATION_WRITE(psm, BOOL, FALSE, _ObStrMap_PushPtr(psm, usz, NULL, NULL, NULL, NULL, pwszDst, pcbwDst))
}

/*
* Push / Insert into the ObStrMap. Result pointer is dependant on fWideChar flag.
* -- psm
* -- usz
* -- puszDst = ptr to utf-8 _OR_ wide string depending on fWideChar
* -- pcbuDst = # bytes required to hold *puszDst
* -- fWideChar
* -- return = TRUE on insertion, FALSE otherwise.
*/
_Success_(return)
BOOL ObStrMap_PushPtrUXUW(_In_opt_ POB_STRMAP psm, _In_opt_ LPSTR usz, _Out_opt_ LPSTR *puszDst, _Out_opt_ PDWORD pcbuDst, BOOL fWideChar)
{
    if(fWideChar) {
        OB_STRUMAP_CALL_SYNCHRONIZED_IMPLEMENTATION_WRITE(psm, BOOL, FALSE, _ObStrMap_PushPtr(psm, usz, NULL, NULL, NULL, NULL, (LPWSTR*)puszDst, pcbuDst))
    } else {
        OB_STRUMAP_CALL_SYNCHRONIZED_IMPLEMENTATION_WRITE(psm, BOOL, FALSE, _ObStrMap_PushPtr(psm, usz, NULL, NULL, puszDst, pcbuDst, NULL, NULL))
    }
}

/*
* Push / Insert into the ObStrMap.
* -- psm
* -- wsz
* -- pwszDst
* -- pcbwDst
* -- return = TRUE on insertion, FALSE otherwise.
*/
_Success_(return)
BOOL ObStrMap_PushPtrWW(_In_opt_ POB_STRMAP psm, _In_opt_ LPWSTR wsz, _Out_opt_ LPWSTR *pwszDst, _Out_opt_ PDWORD pcbwDst)
{
    OB_STRUMAP_CALL_SYNCHRONIZED_IMPLEMENTATION_WRITE(psm, BOOL, FALSE, _ObStrMap_PushPtr(psm, NULL, NULL, wsz, NULL, NULL, pwszDst, pcbwDst))
}

_Success_(return)
BOOL _ObStrMap_Push_UnicodeObject(_In_ POB_STRMAP psm, _In_ BOOL f32, _In_ QWORD vaUnicodeObject, _Out_opt_ LPSTR *puszDst, _Out_opt_ PDWORD pcbuDst)
{
    POB_STRMAP_UNICODEENTRY pUnicodeEntry;
    if(psm->fFinalized) { return FALSE; }
    if(!puszDst && !pcbuDst) { return TRUE; }
    if(psm->fStrAssignTemporary) { return FALSE; }
    if((f32 && !VMM_KADDR32_4(vaUnicodeObject)) || (!f32 && !VMM_KADDR64_8(vaUnicodeObject))) {
        _ObStrMap_PushPtr(psm, NULL, NULL, NULL, puszDst, pcbuDst, NULL, NULL);
        return TRUE;
    }
    if(puszDst) { *puszDst = NULL; }
    if(pcbuDst) { *pcbuDst = 0; }
    if(!(pUnicodeEntry = LocalAlloc(LMEM_ZEROINIT, sizeof(OB_STRMAP_UNICODEENTRY)))) { return FALSE; }
    pUnicodeEntry->f32 = f32;
    pUnicodeEntry->va = vaUnicodeObject;
    pUnicodeEntry->p.pusz = puszDst;
    pUnicodeEntry->p.pcbu = pcbuDst;
    pUnicodeEntry->FLink = psm->pUnicodeObjectListHead;
    psm->pUnicodeObjectListHead = pUnicodeEntry;
    return TRUE;
}

_Success_(return)
BOOL _ObStrMap_Push_UnicodeBuffer(_In_ POB_STRMAP psm, _In_ WORD cbUnicodeBuffer, _In_ QWORD vaUnicodeBuffer, _Out_opt_ LPSTR *puszDst, _Out_opt_ PDWORD pcbuDst)
{
    POB_STRMAP_UNICODEENTRY pUnicodeEntry;
    if(psm->fFinalized) { return FALSE; }
    if(!puszDst && !pcbuDst) { return TRUE; }
    if(psm->fStrAssignTemporary) { return FALSE; }
    if((cbUnicodeBuffer & 1) || (vaUnicodeBuffer & 1)) {
        _ObStrMap_PushPtr(psm, NULL, NULL, NULL, puszDst, pcbuDst, NULL, NULL);
        return TRUE;
    }
    cbUnicodeBuffer = min(cbUnicodeBuffer, MAX_PATH * 2);
    if(puszDst) { *puszDst = NULL; }
    if(pcbuDst) { *pcbuDst = 0; }
    if(!(pUnicodeEntry = LocalAlloc(LMEM_ZEROINIT, sizeof(OB_STRMAP_UNICODEENTRY)))) { return FALSE; }
    pUnicodeEntry->cb = cbUnicodeBuffer;
    pUnicodeEntry->va = vaUnicodeBuffer;
    pUnicodeEntry->p.pusz = puszDst;
    pUnicodeEntry->p.pcbu = pcbuDst;
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
* -- puszDst
* -- pcbuDst
* -- return = TRUE on validation success (NB! no guarantee for final success).
*/
_Success_(return)
BOOL ObStrMap_Push_UnicodeObject(_In_opt_ POB_STRMAP psm, _In_ BOOL f32, _In_ QWORD vaUnicodeObject, _Out_opt_ LPSTR *puszDst, _Out_opt_ PDWORD pcbuDst)
{
    OB_STRUMAP_CALL_SYNCHRONIZED_IMPLEMENTATION_WRITE(psm, BOOL, FALSE, _ObStrMap_Push_UnicodeObject(psm, f32, vaUnicodeObject, puszDst, pcbuDst))
}

/*
* Push a UNICODE_OBJECT Buffer for delayed resolve at finalize stage.
* NB! Incompatible with: OB_STRMAP_FLAGS_STR_ASSIGN_TEMPORARY create flag.
* -- psm
* -- cbUnicodeBuffer.
* -- vaUnicodeBuffer
* -- puszDst
* -- pcbuDst
* -- return = TRUE on validation success (NB! no guarantee for final success).
*/
_Success_(return)
BOOL ObStrMap_Push_UnicodeBuffer(_In_opt_ POB_STRMAP psm, _In_ WORD cbUnicodeBuffer, _In_ QWORD vaUnicodeBuffer, _Out_opt_ LPSTR *puszDst, _Out_opt_ PDWORD pcbuDst)
{
    OB_STRUMAP_CALL_SYNCHRONIZED_IMPLEMENTATION_WRITE(psm, BOOL, FALSE, _ObStrMap_Push_UnicodeBuffer(psm, cbUnicodeBuffer, vaUnicodeBuffer, puszDst, pcbuDst))
}

/*
* Push / Insert max 2048 char-bytes into ObStrMap using a snprintf_s syntax.
* All szFormat and all string-arguments are assumed to be utf-8 encoded.
* -- psm
* -- puszDst
* -- pcbuDst
* -- uszFormat
* -- ...
* -- return = TRUE on insertion, FALSE otherwise.
*/
_Success_(return)
BOOL ObStrMap_PushUU_snprintf_s(_In_opt_ POB_STRMAP psm, _Out_opt_ LPSTR *puszDst, _Out_opt_ PDWORD pcbuDst, _In_z_ _Printf_format_string_ char const *const uszFormat, ...)
{
    int cch;
    va_list arglist;
    CHAR uszBuffer[2048];
    va_start(arglist, uszFormat);
    cch = _vsnprintf_s(uszBuffer, 2048, _TRUNCATE, uszFormat, arglist);
    va_end(arglist);
    if(cch < 0) { return FALSE; }
    return ObStrMap_PushPtrUU(psm, uszBuffer, puszDst, pcbuDst);
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
        pse = pe->SubEntry.FLink;
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
    USHORT wsz[MAX_PATH + 1];
    POB_STRMAP_UNICODEENTRY pu;
    POB_SET psObPrefetch = NULL;
    PVMM_PROCESS pObSystemProcess = NULL;
    BYTE pbBuffer[sizeof(UNICODE_STRING64)];
    if(psm->fFinalized) { return; }
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
                    _ObStrMap_Push_UnicodeBuffer(psm, ((PUNICODE_STRING32)pbBuffer)->Length, ((PUNICODE_STRING32)pbBuffer)->Buffer, pu->p.pusz, pu->p.pcbu) :
                    _ObStrMap_Push_UnicodeBuffer(psm, ((PUNICODE_STRING64)pbBuffer)->Length, ((PUNICODE_STRING64)pbBuffer)->Buffer, pu->p.pusz, pu->p.pcbu);
                if(!f) {
                    _ObStrMap_PushPtr(psm, NULL, NULL, NULL, pu->p.pusz, pu->p.pcbu, NULL, NULL);
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
            _ObStrMap_PushPtr(psm, NULL, NULL, (LPWSTR)wsz, pu->p.pusz, pu->p.pcbu, NULL, NULL);
            pu = pu->FLink;
        }
    }
fail:
    Ob_DECREF(pObSystemProcess);
    Ob_DECREF(psObPrefetch);
}

DWORD _ObStrMap_Finalize_ByteCount(_In_ POB_STRMAP psm, _In_ BOOL fWideChar)
{
    DWORD i, cMax;
    POB_STRMAP_ENTRY pe;
    if(!psm->fFinalized) {
        _ObStrMap_FinalizeDoWork_UnicodeResolve(psm);
        psm->fFinalized = TRUE;
    }
    if(fWideChar) {
        if(!psm->cbw) {
            for(i = 0, cMax = ObMap_Size(psm->pm); i < cMax; i++) {
                pe = ObMap_GetByIndex(psm->pm, i);
                CharUtil_UtoW(pe->usz, -1, NULL, 0, NULL, &pe->cbw, 0);
                psm->cbw += pe->cbw;
            }
        }
        return psm->cbw;
    }
    return psm->cbu;
}

_Success_(return)
BOOL _ObStrMap_Finalize_FillBuffer(_In_ POB_STRMAP psm, _In_ DWORD cbMultiStr, _Out_writes_bytes_opt_(cbMultiStr) PBYTE pbMultiStr, _Out_ PDWORD pcbMultiStr, _In_ BOOL fWideChar)
{
    DWORD i, j, cMax, o = 0, cb;
    LPWSTR wsz;
    LPSTR usz;
    POB_STRMAP_ENTRY pe;
    POB_STRMAP_SUBENTRY pse;
    BOOL fOffset = psm->fStrAssignOffset;
    cb = _ObStrMap_Finalize_ByteCount(psm, fWideChar);
    *pcbMultiStr = cb;
    if(!pbMultiStr) { return TRUE; }           // size request
    if(cb > cbMultiStr) { return FALSE; }
    if(fWideChar) {
        for(i = 0, cMax = ObMap_Size(psm->pm); i < cMax; i++) {
            // 1: fetch entry and assign to multi-string.
            pe = ObMap_GetByIndex(psm->pm, i);
            CharUtil_UtoW(pe->usz, -1, pbMultiStr + o, cbMultiStr - o, &wsz, NULL, 0);
            o += pe->cbw;
            // 2: assign ptrs
            pse = &pe->SubEntry;
            while(pse) {
                for(j = 0; j < OB_STRMAP_SUBENTRY_SIZE; j++) {
                    if(pse->e[j].pwsz) { *(pse->e[j].pwsz) = fOffset ? ((LPWSTR)((QWORD)wsz - (QWORD)pbMultiStr)) : wsz; }
                    if(pse->e[j].pcbw) { *(pse->e[j].pcbw) = pe->cbw; }
                }
                pse = pse->FLink;
            }
        }
    } else {
        for(i = 0, cMax = ObMap_Size(psm->pm); i < cMax; i++) {
            // 1: fetch entry and assign to multi-string.
            pe = ObMap_GetByIndex(psm->pm, i);
            usz = pbMultiStr + o;
            memcpy(usz, pe->usz, pe->cbu);
            o += pe->cbu;
            // 2: assign ptrs
            pse = &pe->SubEntry;
            while(pse) {
                for(j = 0; j < OB_STRMAP_SUBENTRY_SIZE; j++) {
                    if(pse->e[j].pusz) { *(pse->e[j].pusz) = fOffset ? ((LPSTR)((QWORD)usz - (QWORD)pbMultiStr)) : usz; }
                    if(pse->e[j].pcbu) { *(pse->e[j].pcbu) = pe->cbu; }
                }
                pse = pse->FLink;
            }
        }
    }
    return TRUE;
}

_Success_(return)
BOOL _ObStrMap_FinalizeAlloc_DoWork(_In_ POB_STRMAP psm, _Out_ PBYTE *ppbMultiStr, _Out_ PDWORD pcbMultiStr, _In_ BOOL fWideChar)
{
    BOOL f;
    DWORD cb = 0;
    PBYTE pb = NULL;
    f = _ObStrMap_Finalize_FillBuffer(psm, 0, NULL, &cb, fWideChar) &&
        (pb = LocalAlloc(0, cb)) &&
        _ObStrMap_Finalize_FillBuffer(psm, cb, pb, &cb, fWideChar);
    *ppbMultiStr = f ? pb : NULL;
    *pcbMultiStr = f ? cb : 0;
    return f;
}

_Success_(return)
BOOL _ObStrMap_FinalizeAlloc(_In_opt_ POB_STRMAP psm, _Out_ PBYTE *ppbMultiStr, _Out_ PDWORD pcbMultiStr, _In_ BOOL fWideChar)
{
    OB_STRUMAP_CALL_SYNCHRONIZED_IMPLEMENTATION_WRITE(psm, BOOL, FALSE, _ObStrMap_FinalizeAlloc_DoWork(psm, ppbMultiStr, pcbMultiStr, fWideChar))
}

/*
* Finalize the ObStrMap. Create and assign the MultiStr and assign each
* previously added string reference to a pointer location within the MultiStr.
* ---
* Also decrease the reference count of the object. If the reference count
* reaches zero the object will be cleaned up.
* Also set the incoming pointer to NULL.
* CALLER LOCALFREE: *ppbMultiStr
* -- ppObStrMap
* -- ppbMultiStr
* -- pcbMultiStr
* -- return
*/
_Success_(return)
BOOL ObStrMap_FinalizeAllocU_DECREF_NULL(_In_opt_ POB_STRMAP *ppObStrMap, _Out_ PBYTE *ppbMultiStr, _Out_ PDWORD pcbMultiStr)
{
    BOOL f = ppObStrMap && _ObStrMap_FinalizeAlloc(*ppObStrMap, ppbMultiStr, pcbMultiStr, FALSE);
    Ob_DECREF_NULL(ppObStrMap);
    return f;
}

/*
* Finalize the ObStrMap. Create and assign the MultiStr and assign each
* previously added string reference to a pointer location within the MultiStr.
* ---
* Also decrease the reference count of the object. If the reference count
* reaches zero the object will be cleaned up.
* Also set the incoming pointer to NULL.
* CALLER LOCALFREE: *ppbMultiStr
* -- ppObStrMap
* -- ppbMultiStr
* -- pcbMultiStr
* -- return
*/
_Success_(return)
BOOL ObStrMap_FinalizeAllocW_DECREF_NULL(_In_opt_ POB_STRMAP *ppObStrMap, _Out_ PBYTE *ppbMultiStr, _Out_ PDWORD pcbMultiStr)
{
    BOOL f = ppObStrMap && _ObStrMap_FinalizeAlloc(*ppObStrMap, ppbMultiStr, pcbMultiStr, TRUE);
    Ob_DECREF_NULL(ppObStrMap);
    return f;
}

/*
* Finalize the ObStrMap. Write the MultiStr into the supplied buffer and assign
* previously added string reference to a pointer location within the MultiStr.
* -- psm
* -- cbuMultiStr
* -- pbMultiStr = NULL for size query
* -- pcbMultiStr
* -- return
*/
_Success_(return)
BOOL ObStrMap_FinalizeBufferU(_In_opt_ POB_STRMAP psm, _In_ DWORD cbMultiStr, _Out_writes_bytes_opt_(cbMultiStr) PBYTE pbMultiStr, _Out_ PDWORD pcbMultiStr)
{
    OB_STRUMAP_CALL_SYNCHRONIZED_IMPLEMENTATION_WRITE(psm, BOOL, FALSE, _ObStrMap_Finalize_FillBuffer(psm, cbMultiStr, pbMultiStr, pcbMultiStr, FALSE))
}

/*
* Finalize the ObStrMap. Write the MultiStr into the supplied buffer and assign
* previously added string reference to a pointer location within the MultiStr.
* -- psm
* -- cbMultiStr
* -- pbMultiStr = NULL for size query
* -- pcbMultiStr
* -- return
*/
_Success_(return)
BOOL ObStrMap_FinalizeBufferW(_In_opt_ POB_STRMAP psm, _In_ DWORD cbMultiStr, _Out_writes_bytes_opt_(cbMultiStr) PBYTE pbMultiStr, _Out_ PDWORD pcbMultiStr)
{
    OB_STRUMAP_CALL_SYNCHRONIZED_IMPLEMENTATION_WRITE(psm, BOOL, FALSE, _ObStrMap_Finalize_FillBuffer(psm, cbMultiStr, pbMultiStr, pcbMultiStr, TRUE))
}

/*
* Finalize the ObStrMap as either UTF-8 or Wide. Write the MultiStr into the
* supplied buffer and assign previously added string reference to a pointer
* location within the MultiStr.
* -- psm
* -- cbMultiStr
* -- pbMultiStr = NULL for size query
* -- pcbMultiStr
* -- fWideChar
* -- return
*/
_Success_(return)
BOOL ObStrMap_FinalizeBufferXUW(_In_opt_ POB_STRMAP psm, _In_ DWORD cbMultiStr, _Out_writes_bytes_opt_(cbMultiStr) PBYTE pbMultiStr, _Out_ PDWORD pcbMultiStr, _In_ BOOL fWideChar)
{
    OB_STRUMAP_CALL_SYNCHRONIZED_IMPLEMENTATION_WRITE(psm, BOOL, FALSE, _ObStrMap_Finalize_FillBuffer(psm, cbMultiStr, pbMultiStr, pcbMultiStr, fWideChar))
}

/*
* Create a new strmap. A strmap (ObStrMap) provides an easy way to add new
* strings to a multi-string in an efficient way. The ObStrMap is not meant
* to be a long-term object - it's supposed to be finalized and possibly
* decommissioned by calling any of the ObStrMap_Finalize*() functions.
* The ObStrMap is an object manager object and must be DECREF'ed when required.
* CALLER DECREF: return
* -- flags
* -- return
*/
_Success_(return != NULL)
POB_STRMAP ObStrMap_New(_In_ QWORD flags)
{
    POB_STRMAP pObStrMap = NULL;
    POB_STRMAP_ENTRY pStrEntry = NULL;
    if((flags & OB_STRMAP_FLAGS_STR_ASSIGN_TEMPORARY) && (flags & OB_STRMAP_FLAGS_STR_ASSIGN_OFFSET)) { goto fail; }
    if(!(pObStrMap = Ob_Alloc(OB_TAG_CORE_STRMAP, LMEM_ZEROINIT, sizeof(OB_STRMAP), (OB_CLEANUP_CB)_ObStrMap_ObCloseCallback, NULL))) { goto fail; }
    if(!(pStrEntry = LocalAlloc(LMEM_ZEROINIT, sizeof(OB_STRMAP_ENTRY) + 1))) { goto fail; }        // "" entry
    if(!(pObStrMap->pm = ObMap_New(0))) { goto fail; }
    pObStrMap->fCaseInsensitive = (flags & OB_STRMAP_FLAGS_CASE_INSENSITIVE) ? TRUE : FALSE;
    pObStrMap->fStrAssignTemporary = (flags & OB_STRMAP_FLAGS_STR_ASSIGN_TEMPORARY) ? TRUE : FALSE;
    pObStrMap->fStrAssignOffset = (flags & OB_STRMAP_FLAGS_STR_ASSIGN_OFFSET) ? TRUE : FALSE;
    pObStrMap->cbu = 1;
    pStrEntry->cbu = 1;
    ObMap_Push(pObStrMap->pm, 1, pStrEntry);
    return pObStrMap;
fail:
    LocalFree(pStrEntry);
    Ob_DECREF(pObStrMap);
    return NULL;
}
