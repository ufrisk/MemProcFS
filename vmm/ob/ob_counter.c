// ob_counter.c : implementation of object manager counter functionality.
//
// The counter (ObCounter) is thread safe and implement efficient counting of
// an unknown amount of keys to be counted.
// The ObCounter is an object manager object and must be DECREF'ed when required.
//
// (c) Ulf Frisk, 2021-2025
// Author: Ulf Frisk, pcileech@frizk.net
//
#include "ob.h"

#define OB_COUNTER_ENTRIES_DIRECTORY    0x100
#define OB_COUNTER_ENTRIES_TABLE        0x200
#define OB_COUNTER_ENTRIES_STORE        0x100
#define OB_COUNTER_IS_VALID(p)          (p && (p->ObHdr._magic2 == OB_HEADER_MAGIC) && (p->ObHdr._magic1 == OB_HEADER_MAGIC) && (p->ObHdr._tag == OB_TAG_CORE_COUNTER))
#define OB_COUNTER_TABLE_MAX_CAPACITY   OB_COUNTER_ENTRIES_DIRECTORY * OB_COUNTER_ENTRIES_TABLE * OB_COUNTER_ENTRIES_STORE
#define OB_COUNTER_HASH_FUNCTION(v)     (13 * (v + _rotr16((WORD)v, 9) + _rotr((DWORD)v, 17) + _rotr64(v, 31)))

#define OB_COUNTER_INDEX_DIRECTORY(i)   ((i >> 17) & (OB_COUNTER_ENTRIES_DIRECTORY - 1))
#define OB_COUNTER_INDEX_TABLE(i)       ((i >> 8) & (OB_COUNTER_ENTRIES_TABLE - 1))
#define OB_COUNTER_INDEX_STORE(i)       (i & (OB_COUNTER_ENTRIES_STORE - 1))

#define OB_COUNTER_MAGIC_ZERO           0xfefff00dc00ffeee

typedef struct tdOB_COUNTER {
    OB ObHdr;
    SRWLOCK LockSRW;
    DWORD c;
    DWORD cHashMax;
    DWORD cHashGrowThreshold;
    BOOL fLargeMode;
    BOOL fZeroCount;
    BOOL fNegativeCount;
    PDWORD pHashMapKey;
    union {
        PPOB_COUNTER_ENTRY Directory[OB_COUNTER_ENTRIES_DIRECTORY];
        struct {
            PPOB_COUNTER_ENTRY _SmallDirectory[1];
            DWORD _SmallHashMap[0x200];
        };
    };
    POB_COUNTER_ENTRY _SmallTable[1];
    OB_COUNTER_ENTRY Store00[OB_COUNTER_ENTRIES_STORE];
} OB_COUNTER, *POB_COUNTER;

#define OB_COUNTER_CALL_SYNCHRONIZED_IMPLEMENTATION_WRITE(pm, RetTp, RetValFail, fn) {  \
    if(!OB_COUNTER_IS_VALID(pm)) { return RetValFail; }                                 \
    RetTp retVal;                                                                       \
    AcquireSRWLockExclusive(&pm->LockSRW);                                              \
    retVal = fn;                                                                        \
    ReleaseSRWLockExclusive(&pm->LockSRW);                                              \
    return retVal;                                                                      \
}

#define OB_COUNTER_CALL_SYNCHRONIZED_IMPLEMENTATION_READ(pm, RetTp, RetValFail, fn) {   \
    if(!OB_COUNTER_IS_VALID(pm)) { return RetValFail; }                                 \
    RetTp retVal;                                                                       \
    AcquireSRWLockShared(&pm->LockSRW);                                                 \
    retVal = fn;                                                                        \
    ReleaseSRWLockShared(&pm->LockSRW);                                                 \
    return retVal;                                                                      \
}

/*
* Object Counter object manager cleanup function to be called when reference
* count reaches zero.
* -- pObCounter
*/
VOID _ObCounter_ObCloseCallback(_In_ POB_COUNTER pObCounter)
{
    DWORD iDirectory, iTable;
    if(pObCounter->fLargeMode) {
        for(iDirectory = 0; iDirectory < OB_COUNTER_ENTRIES_DIRECTORY; iDirectory++) {
            if(!pObCounter->Directory[iDirectory]) { break; }
            for(iTable = 0; iTable < OB_COUNTER_ENTRIES_TABLE; iTable++) {
                if(!pObCounter->Directory[iDirectory][iTable]) { break; }
                if(iDirectory || iTable) {
                    LocalFree(pObCounter->Directory[iDirectory][iTable]);
                }
            }
            LocalFree(pObCounter->Directory[iDirectory]);
        }
        LocalFree(pObCounter->pHashMapKey);
    }
}

POB_COUNTER_ENTRY _ObCounter_GetFromIndex(_In_ POB_COUNTER pm, _In_ DWORD iEntry)
{
    if(!iEntry || (iEntry >= pm->c)) { return NULL; }
    return &pm->Directory[OB_COUNTER_INDEX_DIRECTORY(iEntry)][OB_COUNTER_INDEX_TABLE(iEntry)][OB_COUNTER_INDEX_STORE(iEntry)];
}

QWORD _ObCounter_GetFromEntryIndex(_In_ POB_COUNTER pm, _In_ DWORD iEntry)
{
    POB_COUNTER_ENTRY pe = _ObCounter_GetFromIndex(pm, iEntry);
    return pe ? pe->k : 0;
}

VOID _ObCounter_SetHashIndex(_In_ POB_COUNTER pm, _In_ DWORD iHash, _In_ DWORD iEntry)
{
    pm->pHashMapKey[iHash] = iEntry;
}

VOID _ObCounter_InsertHash(_In_ POB_COUNTER pm, _In_ DWORD iEntry)
{
    QWORD qwValueToHash;
    DWORD iHash, dwHashMask = pm->cHashMax - 1;
    qwValueToHash = _ObCounter_GetFromEntryIndex(pm, iEntry);
    iHash = OB_COUNTER_HASH_FUNCTION(qwValueToHash) & dwHashMask;
    while(pm->pHashMapKey[iHash]) {
        iHash = (iHash + 1) & dwHashMask;
    }
    _ObCounter_SetHashIndex(pm, iHash, iEntry);
}

VOID _ObCounter_RemoveHash(_In_ POB_COUNTER pm, _In_ QWORD k, _In_ DWORD iEntry)
{
    DWORD iHash, dwHashMask = pm->cHashMax - 1;
    DWORD iNextHash, iNextEntry, iNextHashPreferred;
    QWORD qwNextEntry;
    // search for hash index and clear
    iHash = OB_COUNTER_HASH_FUNCTION(k) & dwHashMask;
    while(TRUE) {
        if(iEntry == pm->pHashMapKey[iHash]) { break; }
        iHash = (iHash + 1) & dwHashMask;
    }
    _ObCounter_SetHashIndex(pm, iHash, 0);
    // re-hash any entries following (value)
    iNextHash = iHash;
    while(TRUE) {
        iNextHash = (iNextHash + 1) & dwHashMask;
        iNextEntry = pm->pHashMapKey[iNextHash];
        if(0 == iNextEntry) { return; }
        qwNextEntry = _ObCounter_GetFromEntryIndex(pm, iNextEntry);
        iNextHashPreferred = OB_COUNTER_HASH_FUNCTION(qwNextEntry) & dwHashMask;
        if(iNextHash == iNextHashPreferred) { continue; }
        _ObCounter_SetHashIndex(pm, iNextHash, 0);
        _ObCounter_InsertHash(pm, iNextEntry);
    }
}

_Success_(return)
BOOL _ObCounter_GetEntryIndexFromKeyOrValue(_In_ POB_COUNTER pm, _In_ QWORD k, _Out_opt_ PDWORD piEntry)
{
    DWORD iEntry;
    DWORD dwHashMask = pm->cHashMax - 1;
    DWORD iHash = OB_COUNTER_HASH_FUNCTION(k) & dwHashMask;
    // scan hash table to find entry
    while(TRUE) {
        iEntry = pm->pHashMapKey[iHash];
        if(0 == iEntry) { return FALSE; }
        if(k == _ObCounter_GetFromEntryIndex(pm, iEntry)) {
            if(piEntry) { *piEntry = iEntry; }
            return TRUE;
        }
        iHash = (iHash + 1) & dwHashMask;
    }
}

/*
* Get entry and entry index from key
* -- ppe
* -- return = entry index [0 on fail]
*/
_Success_(return != 0)
DWORD _ObCounter_GetEntryFromKey(_In_ POB_COUNTER pm, _In_ QWORD k, _Out_ PPOB_COUNTER_ENTRY ppe)
{
    DWORD iEntry;
    POB_COUNTER_ENTRY pe;
    DWORD dwHashMask = pm->cHashMax - 1;
    DWORD iHash = OB_COUNTER_HASH_FUNCTION(k) & dwHashMask;
    // scan hash table to find entry
    while(TRUE) {
        iEntry = pm->pHashMapKey[iHash];
        if(0 == iEntry) { return 0; }
        pe = &pm->Directory[OB_COUNTER_INDEX_DIRECTORY(iEntry)][OB_COUNTER_INDEX_TABLE(iEntry)][OB_COUNTER_INDEX_STORE(iEntry)];
        if(k == pe->k) {
            *ppe = pe;
            return iEntry;
        }
        iHash = (iHash + 1) & dwHashMask;
    }
}

VOID _ObCounter_Remove(_In_ POB_COUNTER pm, _In_ DWORD iEntry)
{
    QWORD qwRemoveKey;
    POB_COUNTER_ENTRY pRemoveEntry, pLastEntry;
    if(!(pRemoveEntry = _ObCounter_GetFromIndex(pm, iEntry))) { return; }
    qwRemoveKey = pRemoveEntry->k;
    _ObCounter_RemoveHash(pm, qwRemoveKey, iEntry);
    if(iEntry < pm->c - 1) {
        // not last item removed -> move last item into empty bucket
        pLastEntry = _ObCounter_GetFromIndex(pm, pm->c - 1);
        _ObCounter_RemoveHash(pm, pLastEntry->k, pm->c - 1);
        pRemoveEntry->k = pLastEntry->k;
        pRemoveEntry->v = pLastEntry->v;
        _ObCounter_InsertHash(pm, iEntry);
    }
    pm->c--;
}

/*
* Clear the ObCounter by removing all counts and keys.
* NB! underlying allocated memory will remain unchanged.
* -- pm
* -- return = clear was successful - always true.
*/
_Success_(return)
BOOL ObCounter_Clear(_In_opt_ POB_COUNTER pc)
{
    if(!OB_COUNTER_IS_VALID(pc) || (pc->c <= 1)) { return TRUE; }
    AcquireSRWLockExclusive(&pc->LockSRW);
    if(pc->c <= 1) {
        ReleaseSRWLockExclusive(&pc->LockSRW);
        return TRUE;
    }
    ZeroMemory(pc->pHashMapKey, 4ULL * pc->cHashMax);
    pc->c = 1;  // item zero is reserved - hence the initialization of count to 1
    ReleaseSRWLockExclusive(&pc->LockSRW);
    return TRUE;
}



//-----------------------------------------------------------------------------
// READ ONLY FUNCTIONALITY BELOW:
// ObCounter_Size, ObCounter_CountAll, ObCounter_Exists, ObCounter_Get,
// ObCounter_GetAll, ObCounter_GetAllSortedByKey, ObCounter_GetAllSortedByCount
//-----------------------------------------------------------------------------

BOOL _ObCounter_Exists(_In_ POB_COUNTER pc, _In_ QWORD k)
{
    POB_COUNTER_ENTRY pe;
    return _ObCounter_GetEntryFromKey(pc, k, &pe) ? TRUE : FALSE;
}

QWORD _ObCounter_Get(_In_ POB_COUNTER pc, _In_ QWORD k)
{
    POB_COUNTER_ENTRY pe;
    return _ObCounter_GetEntryFromKey(pc, k, &pe) ? pe->v : 0;
}

QWORD _ObCounter_CountAll(_In_ POB_COUNTER pc)
{
    QWORD i, v = 0;
    for(i = 1; i < pc->c; i++) {
        v += pc->Directory[OB_COUNTER_INDEX_DIRECTORY(i)][OB_COUNTER_INDEX_TABLE(i)][OB_COUNTER_INDEX_STORE(i)].v;
    }
    return v;
}

_Success_(return)
BOOL _ObCounter_GetAll(_In_ POB_COUNTER pc, _In_ DWORD cEntries, _Out_writes_(cEntries) POB_COUNTER_ENTRY pEntries)
{
    DWORD i, iEntry;
    POB_COUNTER_ENTRY peDst, peSrc;
    if(cEntries != pc->c - 1) { return FALSE; }
    for(i = 0; i < cEntries; i++) {
        iEntry = i + 1;
        peDst = pEntries + i;
        peSrc = &pc->Directory[OB_COUNTER_INDEX_DIRECTORY(iEntry)][OB_COUNTER_INDEX_TABLE(iEntry)][OB_COUNTER_INDEX_STORE(iEntry)];
        memcpy(peDst, peSrc, sizeof(OB_COUNTER_ENTRY));
        if(peDst->k == OB_COUNTER_MAGIC_ZERO) { peDst->k = 0; }
    }
    return TRUE;
}

/*
* Retrieve the number of counted keys the ObCounter.
* -- pc
* -- return
*/
DWORD ObCounter_Size(_In_opt_ POB_COUNTER pc)
{
    OB_COUNTER_CALL_SYNCHRONIZED_IMPLEMENTATION_READ(pc, DWORD, 0, pc->c - 1)
}

/*
* Retrieve the total count of the ObCounter.
* NB! The resulting count may overflow on large counts!
* -- pc
* -- return
*/
QWORD ObCounter_CountAll(_In_opt_ POB_COUNTER pc)
{
    OB_COUNTER_CALL_SYNCHRONIZED_IMPLEMENTATION_READ(pc, QWORD, 0, _ObCounter_CountAll(pc))
}

/*
* Check if the counted key exists in the ObCounter.
* -- pc
* -- k
* -- return
*/
BOOL ObCounter_Exists(_In_opt_ POB_COUNTER pc, _In_ QWORD k)
{
    if(!k) { k = OB_COUNTER_MAGIC_ZERO; }
    OB_COUNTER_CALL_SYNCHRONIZED_IMPLEMENTATION_READ(pc, BOOL, FALSE, _ObCounter_Exists(pc, k))
}

/*
* Get the count of a specific key.
* -- pc
* -- k
* -- return = the counted value after the action, zero on fail.
*/
QWORD ObCounter_Get(_In_opt_ POB_COUNTER pc, _In_ QWORD k)
{
    if(!k) { k = OB_COUNTER_MAGIC_ZERO; }
    OB_COUNTER_CALL_SYNCHRONIZED_IMPLEMENTATION_READ(pc, QWORD, 0, _ObCounter_Get(pc, k))
}

/*
* Retrieve all counts in a table.
* -- pc
* -- cEntries
* -- pEntries
* -- return
*/
_Success_(return)
BOOL ObCounter_GetAll(_In_opt_ POB_COUNTER pc, _In_ DWORD cEntries, _Out_writes_opt_(cEntries) POB_COUNTER_ENTRY pEntries)
{
    if(!pEntries) { return FALSE; }
    OB_COUNTER_CALL_SYNCHRONIZED_IMPLEMENTATION_READ(pc, BOOL, FALSE, _ObCounter_GetAll(pc, cEntries, pEntries))
}

int _ObCounter_qsort_k(POB_COUNTER_ENTRY p1, POB_COUNTER_ENTRY p2)
{
    return (p1->k < p2->k) ? -1 : ((p1->k > p2->k) ? 1 : (int)(p1->v - p2->v));
}

int _ObCounter_qsort_v(POB_COUNTER_ENTRY p1, POB_COUNTER_ENTRY p2)
{
    return (p1->v < p2->v) ? -1 : ((p1->v > p2->v) ? 1 : (int)(p1->k - p2->k));
}

/*
* Retrieve all counts in a sorted table.
* -- pc
* -- cEntries
* -- pEntries
* -- return
*/
_Success_(return)
BOOL ObCounter_GetAllSortedByKey(_In_opt_ POB_COUNTER pc, _In_ DWORD cEntries, _Out_writes_opt_(cEntries) POB_COUNTER_ENTRY pEntries)
{
    if(!pEntries || !ObCounter_GetAll(pc, cEntries, pEntries)) { return FALSE; }
    qsort(pEntries, cEntries, sizeof(OB_COUNTER_ENTRY), (_CoreCrtNonSecureSearchSortCompareFunction)_ObCounter_qsort_k);
    return TRUE;
}

/*
* Retrieve all counts in a sorted table.
* -- pc
* -- cEntries
* -- pEntries
* -- return
*/
_Success_(return)
BOOL ObCounter_GetAllSortedByCount(_In_opt_ POB_COUNTER pc, _In_ DWORD cEntries, _Out_writes_opt_(cEntries) POB_COUNTER_ENTRY pEntries)
{
    if(!pEntries || !ObCounter_GetAll(pc, cEntries, pEntries)) { return FALSE; }
    qsort(pEntries, cEntries, sizeof(OB_COUNTER_ENTRY), (_CoreCrtNonSecureSearchSortCompareFunction)_ObCounter_qsort_v);
    return TRUE;
}



//-----------------------------------------------------------------------------
// UPDATE FUNCTIONALITY BELOW:
// ObCounter_Add, ObCounter_Sub, ObCounter_Inc, ObCounter_Dec, ObCounter_Del
//-----------------------------------------------------------------------------

_Success_(return) BOOL _ObCounter_Push(_In_ POB_COUNTER pm, _In_ QWORD k, _In_ QWORD v);

QWORD _ObCounter_Set(_In_ POB_COUNTER pc, _In_ QWORD k, _In_ QWORD v)
{
    DWORD iEntry;
    POB_COUNTER_ENTRY pe = NULL;
    iEntry = _ObCounter_GetEntryFromKey(pc, k, &pe);
    if(!pe && (v || pc->fZeroCount) && ((v <= 0x7fffffffffffffff) || pc->fNegativeCount)) {
        _ObCounter_Push(pc, k, v);
        iEntry = _ObCounter_GetEntryFromKey(pc, k, &pe);
    }
    if(!pe) { return 0; }
    if(!v && !pc->fZeroCount) {
        _ObCounter_Remove(pc, iEntry);
        return 0;
    }
    pe->v = v;
    return v;
}

QWORD _ObCounter_Add(_In_ POB_COUNTER pc, _In_ QWORD k, _In_ QWORD v)
{
    POB_COUNTER_ENTRY pe;
    if(_ObCounter_GetEntryFromKey(pc, k, &pe)) {
        v += pe->v;
        if((v || pc->fZeroCount) && ((v <= 0x7fffffffffffffff) || pc->fNegativeCount)) {
            pe->v = v;
            return v;
        }
    }
    return _ObCounter_Set(pc, k, v);
}

QWORD _ObCounter_Del(_In_ POB_COUNTER pc, _In_ QWORD k)
{
    QWORD v = 0;
    DWORD iEntry;
    POB_COUNTER_ENTRY pe;
    if((iEntry = _ObCounter_GetEntryFromKey(pc, k, &pe))) {
        v = pe->v;
        _ObCounter_Remove(pc, iEntry);
    }
    return v;
}


_Success_(return != 0)
QWORD _ObCounter_RetrieveAndRemoveByEntryIndex(_In_ POB_COUNTER pc, _In_ DWORD iEntry, _Out_opt_ PQWORD pKey)
{
    QWORD v;
    POB_COUNTER_ENTRY pe;
    if((pe = _ObCounter_GetFromIndex(pc, iEntry))) {
        v = pe->v;
        if(pKey) { *pKey = pe->k; }
        _ObCounter_Remove(pc, iEntry);
        return v;
    } else {
        if(pKey) { *pKey = 0; }
        return 0;
    }
}

/*
* Set the count of a specific key.
* -- pc
* -- k
* -- v
* -- return = the counted value after the action, zero on fail.
*/
QWORD ObCounter_Set(_In_opt_ POB_COUNTER pc, _In_ QWORD k, _In_ QWORD v)
{
    if(!k) { k = OB_COUNTER_MAGIC_ZERO; }
    OB_COUNTER_CALL_SYNCHRONIZED_IMPLEMENTATION_WRITE(pc, QWORD, 0, _ObCounter_Set(pc, k, v))
}

/*
* Add the count v of a specific key.
* -- pc
* -- k
* -- v
* -- return = the counted value after the action, zero on fail.
*/
QWORD ObCounter_Add(_In_opt_ POB_COUNTER pc, _In_ QWORD k, _In_ QWORD v)
{
    if(!k) { k = OB_COUNTER_MAGIC_ZERO; }
    OB_COUNTER_CALL_SYNCHRONIZED_IMPLEMENTATION_WRITE(pc, QWORD, 0, _ObCounter_Add(pc, k, v))
}

/*
* Remove a specific key.
* -- pc
* -- k
* -- return = the count of the removed key, zero in fail.
*/
QWORD ObCounter_Del(_In_opt_ POB_COUNTER pc, _In_ QWORD k)
{
    if(!k) { k = OB_COUNTER_MAGIC_ZERO; }
    OB_COUNTER_CALL_SYNCHRONIZED_IMPLEMENTATION_WRITE(pc, QWORD, 0, _ObCounter_Del(pc, k))
}

/*
* Increment the count of a specific key with 1.
* -- pc
* -- k
* -- return = the counted value after the action, zero on fail.
*/
QWORD ObCounter_Inc(_In_opt_ POB_COUNTER pc, _In_ QWORD k)
{
    return ObCounter_Add(pc, k, 1);
}

/*
* Decrement the count of a specific key with 1.
* -- pc
* -- k
* -- return = the counted value after the action, zero on fail.
*/
QWORD ObCounter_Dec(_In_opt_ POB_COUNTER pc, _In_ QWORD k)
{
    return ObCounter_Add(pc, k, (QWORD)-1);
}

/*
* Subtract the count v of a specific key.
* -- pc
* -- k
* -- v
* -- return = the counted value after the action, zero on fail.
*/
QWORD ObCounter_Sub(_In_opt_ POB_COUNTER pc, _In_ QWORD k, _In_ QWORD v)
{
    return ObCounter_Add(pc, k, (QWORD)(0-v));
}

/*
* Remove the "last" count.
* -- pc
* -- return = success: count, fail: 0.
*/
_Success_(return != 0)
QWORD ObCounter_Pop(_In_opt_ POB_COUNTER pc)
{
    OB_COUNTER_CALL_SYNCHRONIZED_IMPLEMENTATION_WRITE(pc, QWORD, 0, _ObCounter_RetrieveAndRemoveByEntryIndex(pc, pc->c - 1, NULL))
}

/*
* Remove the "last" count and return it and its key.
* -- pc
* -- pKey
* -- return = success: count, fail: 0.
*/
_Success_(return != 0)
QWORD ObCounter_PopWithKey(_In_opt_ POB_COUNTER pc, _Out_opt_ PQWORD pKey)
{
    OB_COUNTER_CALL_SYNCHRONIZED_IMPLEMENTATION_WRITE(pc, QWORD, 0, _ObCounter_RetrieveAndRemoveByEntryIndex(pc, pc->c - 1, pKey))
}



//-----------------------------------------------------------------------------
// CREATE / INSERT FUNCTIONALITY BELOW:
//-----------------------------------------------------------------------------

/*
* Grow the Tables for hash lookups by a factor of *2.
* -- pvs
* -- pm
*/
_Success_(return)
BOOL _ObCounter_Grow(_In_ POB_COUNTER pm)
{
    DWORD iEntry;
    PDWORD pdwNewAllocHashMap;
    if(!(pdwNewAllocHashMap = LocalAlloc(LMEM_ZEROINIT, 2 * sizeof(DWORD) * pm->cHashMax))) { return FALSE; }
    if(!pm->fLargeMode) {
        if(!(pm->Directory[0] = LocalAlloc(LMEM_ZEROINIT, sizeof(POB_COUNTER_ENTRY) * OB_COUNTER_ENTRIES_TABLE))) { return FALSE; }
        pm->Directory[0][0] = pm->Store00;
        ZeroMemory(pm->_SmallHashMap, sizeof(pm->_SmallHashMap));
        pm->pHashMapKey = NULL;
        pm->fLargeMode = TRUE;
    }
    pm->cHashMax *= 2;
    pm->cHashGrowThreshold *= 2;
    LocalFree(pm->pHashMapKey);
    pm->pHashMapKey = pdwNewAllocHashMap;
    for(iEntry = 1; iEntry < pm->c; iEntry++) {
        _ObCounter_InsertHash(pm, iEntry);
    }
    return TRUE;
}

_Success_(return)
BOOL _ObCounter_Push(_In_ POB_COUNTER pm, _In_ QWORD k, _In_ QWORD v)
{
    POB_COUNTER_ENTRY pe;
    DWORD iEntry = pm->c;
    if(iEntry == OB_COUNTER_ENTRIES_DIRECTORY * OB_COUNTER_ENTRIES_TABLE * OB_COUNTER_ENTRIES_STORE) { return FALSE; }
    if(iEntry == pm->cHashGrowThreshold) {
        if(!_ObCounter_Grow(pm)) {
            return FALSE;
        }
    }
    if(!pm->Directory[OB_COUNTER_INDEX_DIRECTORY(iEntry)]) {    // allocate "table" if required
        if(!(pm->Directory[OB_COUNTER_INDEX_DIRECTORY(iEntry)] = LocalAlloc(LMEM_ZEROINIT, sizeof(POB_COUNTER_ENTRY) * OB_COUNTER_ENTRIES_TABLE))) { return FALSE; }
    }
    if(!pm->Directory[OB_COUNTER_INDEX_DIRECTORY(iEntry)][OB_COUNTER_INDEX_TABLE(iEntry)]) {    // allocate "store" if required
        if(!(pm->Directory[OB_COUNTER_INDEX_DIRECTORY(iEntry)][OB_COUNTER_INDEX_TABLE(iEntry)] = LocalAlloc(LMEM_ZEROINIT, sizeof(OB_COUNTER_ENTRY) * OB_COUNTER_ENTRIES_STORE))) { return FALSE; }
    }
    pm->c++;
    pe = _ObCounter_GetFromIndex(pm, iEntry);
    pe->k = k;
    pe->v = v;
    _ObCounter_InsertHash(pm, iEntry);
    return TRUE;
}

/*
* Create a new counter. A counter (ObCounter) provides atomic counting operations.
* The ObCounter is an object manager object and must be DECREF'ed when required.
* CALLER DECREF: return
* -- H
* -- flags = defined by OB_COUNTER_FLAGS_*
* -- return
*/
POB_COUNTER ObCounter_New(_In_opt_ VMM_HANDLE H, _In_ QWORD flags)
{
    POB_COUNTER pObCounter;
    pObCounter = Ob_AllocEx(H, OB_TAG_CORE_COUNTER, LMEM_ZEROINIT, sizeof(OB_COUNTER), (OB_CLEANUP_CB)_ObCounter_ObCloseCallback, NULL);
    if(!pObCounter) { return NULL; }
    InitializeSRWLock(&pObCounter->LockSRW);
    pObCounter->c = 1;      // item zero is reserved - hence the initialization of count to 1
    pObCounter->fZeroCount = (flags & OB_COUNTER_FLAGS_SHOW_ZERO) ? FALSE : TRUE;
    pObCounter->fNegativeCount = (flags & OB_COUNTER_FLAGS_ALLOW_NEGATIVE) ? TRUE : FALSE;
    pObCounter->_SmallTable[0] = pObCounter->Store00;
    pObCounter->Directory[0] = pObCounter->_SmallTable;
    pObCounter->pHashMapKey = pObCounter->_SmallHashMap;
    pObCounter->cHashMax = 0x100;
    pObCounter->cHashGrowThreshold = 0xc0;
    return pObCounter;
}
