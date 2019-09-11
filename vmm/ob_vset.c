// ob_vset.c : implementation of object manager hashed value set functionality.
//
// The hashed value set (ObVSet) provides thread safe efficient access to a set
// which is containing _NON_ZERO_ values (64-bit unsigned integers). The ObVSet
// may hold a maximum capacity of 0x01000000 (~16M) entries - which are UNIQUE
// and _NON_ZERO_.
// The hashed value set (ObVSet) guarantees order amongst values unless the
// function ObVSet_Remove is called - in which order may change and on-going
// iterations of the set with ObVSet_Get/ObVSet_GetNext may fail.
// The ObVSet is an object manager object and must be DECREF'ed when required.
//
// (c) Ulf Frisk, 2019
// Author: Ulf Frisk, pcileech@frizk.net
//
#include "ob.h"

#define OB_VSET_ENTRIES_DIRECTORY      0x100
#define OB_VSET_ENTRIES_TABLE          0x80
#define OB_VSET_ENTRIES_STORE          0x200

typedef struct tdOB_VSET_TABLE_ENTRY {
    PQWORD pValues;                 // ptr to QWORD[0x200]
} OB_VSET_TABLE_ENTRY, *POB_VSET_TABLE_ENTRY;

typedef struct tdOB_VSET_TABLE_DIRECTORY_ENTRY {
    POB_VSET_TABLE_ENTRY pTable;    // ptr to OB_VSET_TABLE_ENTRY[0x20]
} OB_VSET_TABLE_DIRECTORY_ENTRY, *POB_VSET_TABLE_DIRECTORY_ENTRY;

typedef struct tdOB_VSET {
    OB ObHdr;
    SRWLOCK LockSRW;
    DWORD c;
    DWORD cHashMax;
    DWORD cHashGrowThreshold;
    BOOL fLargeMode;
    PDWORD pHashMapLarge;
    union {
        WORD pHashMapSmall[0x400];
        OB_VSET_TABLE_DIRECTORY_ENTRY pDirectory[OB_VSET_ENTRIES_DIRECTORY];
    };
    OB_VSET_TABLE_ENTRY pTable0[OB_VSET_ENTRIES_TABLE];
    QWORD pStore00[OB_VSET_ENTRIES_STORE];
} OB_VSET, *POB_VSET;

#define OB_VSET_IS_VALID(p)         (p && (p->ObHdr._magic == OB_HEADER_MAGIC) && (p->ObHdr._tag == OB_TAG_CORE_VSET))
#define TABLE_MAX_CAPACITY          VSET_ENTRIES_DIRECTORY * VSET_ENTRIES_TABLE * VSET_ENTRIES_STORE
#define HASH_FUNCTION(v)            (13 * (v + _rotr16((WORD)v, 13) + _rotr((DWORD)v, 17) + _rotr64(v, 23)))

#define OB_VSET_CALL_SYNCHRONIZED_IMPLEMENTATION_WRITE(pvs, RetTp, RetValFail, fn) {    \
    if(!OB_VSET_IS_VALID(pvs)) { return RetValFail; }                                   \
    RetTp retVal;                                                                       \
    AcquireSRWLockExclusive(&pvs->LockSRW);                                             \
    retVal = fn;                                                                        \
    ReleaseSRWLockExclusive(&pvs->LockSRW);                                             \
    return retVal;                                                                      \
}

#define OB_VSET_CALL_SYNCHRONIZED_IMPLEMENTATION_READ(pvs, RetTp, RetValFail, fn) {     \
    if(!OB_VSET_IS_VALID(pvs)) { return RetValFail; }                                   \
    RetTp retVal;                                                                       \
    AcquireSRWLockShared(&pvs->LockSRW);                                                \
    retVal = fn;                                                                        \
    ReleaseSRWLockShared(&pvs->LockSRW);                                                \
    return retVal;                                                                      \
}

/*
* Object Container object manager cleanup function to be called when reference
* count reaches zero.
* -- pObVSet
*/
VOID _ObVSet_ObCloseCallback(_In_ POB_VSET pObVSet)
{
    DWORD iDirectory, iTable;
    if(pObVSet->fLargeMode) {
        for(iDirectory = 0; iDirectory < OB_VSET_ENTRIES_DIRECTORY; iDirectory++) {
            if(!pObVSet->pDirectory[iDirectory].pTable) { break; }
            for(iTable = 0; iTable < OB_VSET_ENTRIES_TABLE; iTable++) {
                if(!pObVSet->pDirectory[iDirectory].pTable[iTable].pValues) { break; }
                if(iDirectory || iTable) {
                    LocalFree(pObVSet->pDirectory[iDirectory].pTable[iTable].pValues);
                }
            }
            if(iDirectory) {
                LocalFree(pObVSet->pDirectory[iDirectory].pTable);
            }
        }
        LocalFree(pObVSet->pHashMapLarge);
    } else {
        for(iTable = 1; iTable < OB_VSET_ENTRIES_TABLE; iTable++) {
            if(!pObVSet->pTable0[iTable].pValues) { break; }
            LocalFree(pObVSet->pTable0[iTable].pValues);
        }
    }
}

/*
* Create a new hashed value set. A hashed value set (ObVSet) provides atomic
* ways to store unique 64-bit (or smaller) numbers as a set.
* The ObVSet is an object manager object and must be DECREF'ed when required.
* CALLER DECREF: return
* -- return
*/
POB_VSET ObVSet_New()
{
    POB_VSET pObVSet = Ob_Alloc(OB_TAG_CORE_VSET, LMEM_ZEROINIT, sizeof(OB_VSET), _ObVSet_ObCloseCallback, NULL);
    if(!pObVSet) { return NULL; }
    InitializeSRWLock(&pObVSet->LockSRW);
    pObVSet->c = 1;     // item zero is reserved - hence the initialization of count to 1
    pObVSet->cHashMax = 0x400;
    pObVSet->cHashGrowThreshold = 0x300;
    pObVSet->pTable0[0].pValues = pObVSet->pStore00;
    return pObVSet;
}

inline QWORD _ObVSet_GetValueFromIndex(_In_ POB_VSET pvs, _In_ DWORD iValue)
{
    WORD iDirectory = (iValue >> 14) & (OB_VSET_ENTRIES_DIRECTORY - 1);
    WORD iTable = (iValue >> 9) & (OB_VSET_ENTRIES_TABLE - 1);
    WORD iValueStore = iValue & (OB_VSET_ENTRIES_STORE - 1);
    if(!iValue || (iValue >= pvs->c)) { return 0; }
    return pvs->fLargeMode ?
        pvs->pDirectory[iDirectory].pTable[iTable].pValues[iValueStore] :
        pvs->pTable0[iTable].pValues[iValueStore];
}

inline VOID _ObVSet_SetValueFromIndex(_In_ POB_VSET pvs, _In_ DWORD iValue, _In_ QWORD qwValue)
{
    WORD iDirectory = (iValue >> 14) & (OB_VSET_ENTRIES_DIRECTORY - 1);
    WORD iTable = (iValue >> 9) & (OB_VSET_ENTRIES_TABLE - 1);
    WORD iValueStore = iValue & (OB_VSET_ENTRIES_STORE - 1);
    if(pvs->fLargeMode) {
        pvs->pDirectory[iDirectory].pTable[iTable].pValues[iValueStore] = qwValue;
    } else {
        pvs->pTable0[iTable].pValues[iValueStore] = qwValue;
    }
}

inline DWORD _ObVSet_GetIndexFromHash(_In_ POB_VSET pvs, _In_ DWORD iHash)
{
    return pvs->fLargeMode ? pvs->pHashMapLarge[iHash] : pvs->pHashMapSmall[iHash];
}

inline VOID _ObVSet_SetHashIndex(_In_ POB_VSET pvs, _In_ DWORD iHash, _In_ DWORD iValue)
{
    if(pvs->fLargeMode) {
        pvs->pHashMapLarge[iHash] = iValue;
    } else {
        pvs->pHashMapSmall[iHash] = (WORD)iValue;
    }
}

VOID _ObVSet_InsertHash(_In_ POB_VSET pvs, _In_ DWORD iValue)
{
    DWORD iHash;
    DWORD dwHashMask = pvs->cHashMax - 1;
    QWORD qwValueToHash = _ObVSet_GetValueFromIndex(pvs, iValue);
    if(!qwValueToHash) { return; }
    iHash = HASH_FUNCTION(qwValueToHash) & dwHashMask;
    while(_ObVSet_GetIndexFromHash(pvs, iHash)) {
        iHash = (iHash + 1) & dwHashMask;
    }
    _ObVSet_SetHashIndex(pvs, iHash, iValue);
}

VOID _ObVSet_RemoveHash(_In_ POB_VSET pvs, _In_ DWORD iHash)
{
    DWORD dwHashMask = pvs->cHashMax - 1;
    DWORD iNextHash, iNextEntry, iNextHashPreferred;
    // clear existing hash entry
    _ObVSet_SetHashIndex(pvs, iHash, 0);
    // re-hash any entries following
    iNextHash = iHash;
    while(TRUE) {
        iNextHash = (iNextHash + 1) & dwHashMask;
        iNextEntry = _ObVSet_GetIndexFromHash(pvs, iNextHash);
        if(0 == iNextEntry) { return; }
        iNextHashPreferred = HASH_FUNCTION(_ObVSet_GetValueFromIndex(pvs, iNextEntry)) & dwHashMask;
        if(iNextHash == iNextHashPreferred) { return; }
        if(pvs->fLargeMode) {
            pvs->pHashMapLarge[iNextHash] = 0;
        } else {
            pvs->pHashMapSmall[iNextHash] = 0;
        }
        _ObVSet_InsertHash(pvs, iNextEntry);
    }
}

_Success_(return)
BOOL _ObVSet_GetIndexFromValue(_In_ POB_VSET pvs, _In_ QWORD v, _Out_opt_ PDWORD pdwIndexValue, _Out_opt_ PDWORD pdwIndexHash)
{
    DWORD dwIndex;
    DWORD dwHashMask = pvs->cHashMax - 1;
    DWORD dwHash = HASH_FUNCTION(v) & dwHashMask;
    // scan hash table to find entry
    while(TRUE) {
        dwIndex = _ObVSet_GetIndexFromHash(pvs, dwHash);
        if(0 == dwIndex) { return FALSE; }
        if(v == _ObVSet_GetValueFromIndex(pvs, dwIndex)) { 
            if(pdwIndexValue) { *pdwIndexValue = dwIndex; }
            if(pdwIndexHash) { *pdwIndexHash = dwHash; }
            return TRUE;
        }
        dwHash = (dwHash + 1) & dwHashMask;
    }
}

inline BOOL _ObVSet_Exists(_In_ POB_VSET pvs, _In_ QWORD value)
{
    return _ObVSet_GetIndexFromValue(pvs, value, NULL, NULL);
}

/*
* Check if a value already exists in the ObVSet.
* -- pvs
* -- value
* -- return
*/
BOOL ObVSet_Exists(_In_opt_ POB_VSET pvs, _In_ QWORD value)
{
    OB_VSET_CALL_SYNCHRONIZED_IMPLEMENTATION_READ(pvs, BOOL, FALSE, _ObVSet_Exists(pvs, value))
}

/*
* Retrieve a value given a value index (which is less than the amount of items
* in the Set).
* NB! Correctness of the Get/GetNext functionality is _NOT- guaranteed if the
* ObVSet_Remove function is called while iterating over the ObVSet - items may
* be skipped or iterated over multiple times!
* -- pvs
* -- index
* -- return
*/
QWORD ObVSet_Get(_In_opt_ POB_VSET pvs, _In_ DWORD index)
{
    OB_VSET_CALL_SYNCHRONIZED_IMPLEMENTATION_READ(pvs, QWORD, 0, _ObVSet_GetValueFromIndex(pvs, index + 1))  // (+1 == account/adjust for index 0 (reserved))
}

QWORD _ObVSet_GetNext(_In_ POB_VSET pvs, _In_ QWORD value)
{
    DWORD iValue;
    if(value == 0) {
        return _ObVSet_GetValueFromIndex(pvs, 1);   // (+1 == account/adjust for index 0 (reserved))
    }
    if(!_ObVSet_GetIndexFromValue(pvs, value, &iValue, NULL)) { return 0; }
    return _ObVSet_GetValueFromIndex(pvs, iValue + 1);
}

/*
* Retrieve the next value given a value. The start value and end value are the
* ZERO value (which is a special reserved non-valid value).
* NB! Correctness of the Get/GetNext functionality is _NOT_ guaranteed if the
* ObVSet_Remove function is called while iterating over the ObVSet - items may
* be skipped or iterated over multiple times!
* -- pvs
* -- value
* -- return
*/
QWORD ObVSet_GetNext(_In_opt_ POB_VSET pvs, _In_ QWORD value)
{
    OB_VSET_CALL_SYNCHRONIZED_IMPLEMENTATION_READ(pvs, QWORD, 0, _ObVSet_GetNext(pvs, value))
}

BOOL _ObVSet_Remove(_In_ POB_VSET pvs, _In_ QWORD value)
{
    QWORD qwLastValue;
    DWORD iRemoveValue, iRemoveHash;
    DWORD iLastValue, iLastHash;
    DWORD dwHashMask = pvs->cHashMax - 1;
    if(value == 0) { return FALSE; }
    qwLastValue = _ObVSet_GetValueFromIndex(pvs, pvs->c - 1);
    if(qwLastValue == 0) { return FALSE; }
    if(!_ObVSet_GetIndexFromValue(pvs, qwLastValue, &iLastValue, &iLastHash)) { return FALSE; }
    if(!_ObVSet_GetIndexFromValue(pvs, value, &iRemoveValue, &iRemoveHash)) { return FALSE; }
    _ObVSet_SetValueFromIndex(pvs, iLastValue, 0);
    _ObVSet_RemoveHash(pvs, iLastHash);
    pvs->c--;
    if(iLastValue != iRemoveValue) {    // overwrite value to remove with last value if required.
        _ObVSet_RemoveHash(pvs, iRemoveHash);
        _ObVSet_SetValueFromIndex(pvs, iRemoveValue, qwLastValue);
        _ObVSet_InsertHash(pvs, iRemoveValue);
    }
    return TRUE;
}

/*
* Remove an existing value from the OBVSet.
* NB! must not be called simultaneously while iterating with ObVSet_Get/ObVSet_GetNext.
* -- pvs
* -- value
* -- return = removal was successful (i.e. the value was found and removed).
*/
BOOL ObVSet_Remove(_In_opt_ POB_VSET pvs, _In_ QWORD value)
{
    OB_VSET_CALL_SYNCHRONIZED_IMPLEMENTATION_WRITE(pvs, BOOL, FALSE, _ObVSet_Remove(pvs, value))
}

/*
* Clear the ObVSet by removing all values.
* NB! underlying allocated memory will remain unchanged.
* -- pvs
*/
VOID ObVSet_Clear(_In_opt_ POB_VSET pvs)
{
    if(!OB_VSET_IS_VALID(pvs) || (pvs->c <= 1)) { return; }
    AcquireSRWLockExclusive(&pvs->LockSRW);
    if(pvs->c <= 1) {
        ReleaseSRWLockExclusive(&pvs->LockSRW);
        return;
    }
    if(pvs->fLargeMode) {
        ZeroMemory(pvs->pHashMapLarge, pvs->cHashMax * sizeof(DWORD));
    } else {
        ZeroMemory(pvs->pHashMapSmall, sizeof(pvs->pHashMapSmall));
    }
    pvs->c = 1;     // item zero is reserved - hence the initialization of count to 1
    ReleaseSRWLockExclusive(&pvs->LockSRW);
}

QWORD _ObVSet_Pop(_In_ POB_VSET pvs)
{
    QWORD qwLastValue;
    DWORD iLastValue, iLastHash;
    qwLastValue = _ObVSet_GetValueFromIndex(pvs, pvs->c - 1);
    if(qwLastValue == 0) { return 0; }
    if(!_ObVSet_GetIndexFromValue(pvs, qwLastValue, &iLastValue, &iLastHash)) { return 0; }
    _ObVSet_SetValueFromIndex(pvs, iLastValue, 0);
    _ObVSet_RemoveHash(pvs, iLastHash);
    pvs->c--;
    return qwLastValue;
}

/*
* Remove the "last" value in a way that is safe for concurrent iterations of
* values in the set.
* -- pvs
* -- return = success: value, fail: 0.
*
*/
QWORD ObVSet_Pop(_In_opt_ POB_VSET pvs)
{
    OB_VSET_CALL_SYNCHRONIZED_IMPLEMENTATION_WRITE(pvs, QWORD, 0, _ObVSet_Pop(pvs))
}

/*
* Grow the Table for hash lookups by a factor of *2.
* -- pvs
* -- return
*/
_Success_(return)
BOOL _ObVSet_Grow(_In_ POB_VSET pvs)
{
    DWORD iValue;
    PDWORD pdwNewAllocHashMap;
    if(!(pdwNewAllocHashMap = LocalAlloc(LMEM_ZEROINIT, 2 * sizeof(DWORD) * pvs->cHashMax))) { return FALSE; }
    if(!pvs->fLargeMode) {
        ZeroMemory(pvs->pDirectory, OB_VSET_ENTRIES_DIRECTORY * sizeof(OB_VSET_TABLE_DIRECTORY_ENTRY));
        pvs->pDirectory[0].pTable = pvs->pTable0;
        pvs->fLargeMode = TRUE;
    }
    pvs->cHashMax *= 2;
    pvs->cHashGrowThreshold *= 2;
    LocalFree(pvs->pHashMapLarge);
    pvs->pHashMapLarge = pdwNewAllocHashMap;
    for(iValue = 1; iValue < pvs->c; iValue++) {
        _ObVSet_InsertHash(pvs, iValue);
    }
    return TRUE;
}

_Success_(return)
BOOL _ObVSet_Push(_In_ POB_VSET pvs, _In_ QWORD value)
{
    POB_VSET_TABLE_ENTRY pTable = NULL;
    DWORD iValue = pvs->c;
    WORD iDirectory = (iValue >> 14) & (OB_VSET_ENTRIES_DIRECTORY - 1);
    WORD iTable = (iValue >> 9) & (OB_VSET_ENTRIES_TABLE - 1);
    WORD iValueStore = iValue & (OB_VSET_ENTRIES_STORE - 1);
    if((value == 0) || _ObVSet_Exists(pvs, value)) { return FALSE; }
    if(iValue == OB_VSET_ENTRIES_DIRECTORY * OB_VSET_ENTRIES_TABLE * OB_VSET_ENTRIES_STORE) { return FALSE; }
    if(iValue == pvs->cHashGrowThreshold) {
        if(!_ObVSet_Grow(pvs)) {
            return FALSE;
        }
    }
    if(iDirectory && !pvs->pDirectory[iDirectory].pTable) { // Ensure Table Exists
        pvs->pDirectory[iDirectory].pTable = LocalAlloc(LMEM_ZEROINIT, OB_VSET_ENTRIES_TABLE * sizeof(OB_VSET_TABLE_ENTRY));
        if(!pvs->pDirectory[iDirectory].pTable) { return FALSE; }
    }
    pTable = iDirectory ? pvs->pDirectory[iDirectory].pTable : pvs->pTable0;
    if(!pTable[iTable].pValues) {   // Ensure Store Exists
        pTable[iTable].pValues = LocalAlloc(0, OB_VSET_ENTRIES_STORE * sizeof(OB_VSET_TABLE_ENTRY));
        if(!pTable[iTable].pValues) { return FALSE; }
    }
    pvs->c++;
    _ObVSet_SetValueFromIndex(pvs, iValue, value);
    _ObVSet_InsertHash(pvs, iValue);
    return TRUE;
}

/*
* Push / Insert a non-zero value into the ObVSet.
* -- pvs
* -- value
* -- return = TRUE on insertion, FALSE otherwise - i.e. if value already
*             exists or if the max capacity of the set is reached.
*/
_Success_(return)
BOOL ObVSet_Push(_In_opt_ POB_VSET pvs, _In_ QWORD value)
{
    OB_VSET_CALL_SYNCHRONIZED_IMPLEMENTATION_WRITE(pvs, BOOL, FALSE, _ObVSet_Push(pvs, value))
}

/*
* Insert a value representing an address into the ObVSet. If the length of the
* data read from the start of the address a traverses page boundries all the
* pages are inserted into the set.
* -- pvs
* -- a
* -- cb
*/
VOID ObVSet_Push_PageAlign(_In_opt_ POB_VSET pvs, _In_ QWORD a, _In_ DWORD cb)
{
    QWORD qwA;
    if(!OB_VSET_IS_VALID(pvs)) { return; }
    qwA = a & ~0xfff;
    while(qwA < a + cb) {
        ObVSet_Push(pvs, qwA);
        qwA += 0x1000;
    }
}

/*
* Retrieve the number of items in the given ObVSet.
* -- pvs
* -- return
*/
DWORD ObVSet_Size(_In_opt_ POB_VSET pvs)
{
    OB_VSET_CALL_SYNCHRONIZED_IMPLEMENTATION_READ(pvs, DWORD, 0, pvs->c - 1)
}
