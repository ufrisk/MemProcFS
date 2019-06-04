// ob.h : definitions related to the object manager and object manager collections.
//
// (c) Ulf Frisk, 2018-2019
// Author: Ulf Frisk, pcileech@frizk.net
//
#ifndef __OB_H__
#define __OB_H__
#include <windows.h>

typedef unsigned __int64                QWORD, *PQWORD;
#define OB_DEBUG
#define OB_HEADER_MAGIC                 0x0c0efefe

// ----------------------------------------------------------------------------
// OBJECT MANAGER CORE FUNCTIONALITY BELOW:
//
// The object manager is a minimal non-threaded way of allocating objects with
// reference counts. When reference count reach zero the object is deallocated
// automatically.
//
// All Ob functions are thread-safe and performs only minimum locking.
//
// A thread calls Ob_Alloc to allocate an object of a specific length. The
// object initially have reference count 1. Reference counts may be increased
// by calling Ob_INCREF and decreased by calling Ob_DECREF. If the refcount
// reach one or zero in a call to Ob_DECREF optional callbacks may be made
// (specified at Ob_Alloc time). Callbacks may be useful for cleanup tasks
// - such as decreasing reference count of sub-objects contained in the object
// that is to be deallocated.
// ----------------------------------------------------------------------------

typedef struct tdOB_RESERVED_HEADER {
    DWORD magic;                        // magic value - OB_HEADER_MAGIC
    WORD count;                         // reference count
    WORD tag;                           // tag - 2 chars, no null terminator
    VOID(*pfnRef_0)(_In_ PVOID pOb);    // callback - object specific cleanup before free
    VOID(*pfnRef_1)(_In_ PVOID pOb);    // callback - when object reach refcount 1 (not initial)
} OB_RESERVED_HEADER;

typedef struct tdOB {
    OB_RESERVED_HEADER Reserved;
    DWORD cbData;
} OB, *POB;

/*
* Allocate a new object manager memory object.
* -- tag = tag identifying the type of object.
* -- uFlags = flags as given by LocalAlloc.
* -- uBytes = bytes of object (excluding object header).
* -- pfnRef_0 = optional callback for cleanup o be called before object is destroyed.
*               (if object contains objects which references should be decremented
                 before destruction of this 'parent' object).
* -- pfnRef_1 = optional callback for when object reach refcount = 1 at DECREF.
* -- return = allocated object on success, with refcount = 1, - NULL on fail.
*/
PVOID Ob_Alloc(_In_ WORD tag, _In_ UINT uFlags, _In_ SIZE_T uBytes, _In_opt_ VOID(*pfnRef_0)(_In_ PVOID pOb), _In_opt_ VOID(*pfnRef_1)(_In_ PVOID pOb));

/*
* Increase the reference count of a object by one.
* -- pOb
* -- return
*/
PVOID Ob_INCREF(PVOID pOb);

/*
* Decrease the reference count of an object manager object by one.
* NB! Do not use object after DECREF - other threads might have also DECREF'ed
* the object at same time making it to be free'd - making the memory invalid.
* -- pOb
*/
VOID Ob_DECREF(PVOID pOb);

/*
* Decrease the reference count of a object manager object. If the reference
* count reaches zero the object will be cleaned up.
* Also set the incoming pointer to NULL.
* -- ppOb
*/
inline VOID Ob_DECREF_NULL(PVOID *ppOb)
{
    if(ppOb) {
        Ob_DECREF(*ppOb);
        *ppOb = NULL;
    }
}



// ----------------------------------------------------------------------------
// OBJECT CONTAINER FUNCTIONALITY BELOW:
//
// A container provides atomic access to a single Ob object. This is useful
// if a Ob object is to frequently be replaced by a new object in an atomic
// way. An example of this is the process list object containing the process
// information. The container holds a reference count to the object that is
// contained. The object container itself is an object manager object and
// must be DECREF'ed when required.
// ----------------------------------------------------------------------------

typedef struct tdOB_CONTAINER {
    OB ObHdr;
    CRITICAL_SECTION Lock;
    POB pOb;
} OB_CONTAINER, *POB_CONTAINER;

/*
* Create a new object container object with an optional contained object.
* An object container provides atomic access to its contained object in a
* multithreaded environment. The object container is in itself an object
* manager object and must be DECREF'ed by the caller when use is complete.
* CALLER DECREF: return
* -- pOb = optional contained object.
* -- return
*/
POB_CONTAINER ObContainer_New(_In_opt_ PVOID pOb);

/*
* Retrieve an enclosed object from the given pObContainer.
* CALLER DECREF: return
* -- pObContainer
* -- return
*/
PVOID ObContainer_GetOb(_In_ POB_CONTAINER pObContainer);

/*
* Set or Replace an object in the object container.
* -- pObContainer
* -- pOb
*/
VOID ObContainer_SetOb(_In_ POB_CONTAINER pObContainer, _In_opt_ PVOID pOb);



// ----------------------------------------------------------------------------
// HASHED VALUE SET FUNCTIONALITY BELOW:
//
// The hashed value set (ObVSet) provides thread safe efficient access to a set
// which is containing _NON_ZERO_ values (64-bit unsigned integers). The ObVSet
// may hold a maximum capacity of 0x01000000 (~16M) entries - which are UNIQUE
// and _NON_ZERO_.
// The hashed value set (ObVSet) guarantees order amongst values unless the
// function ObVSet_Remove is called - in which order may change and on-going
// iterations of the set with ObVSet_Get/ObVSet_GetNext may fail.
// The ObVSet is an object manager object and must be DECREF'ed when required.
// ----------------------------------------------------------------------------

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

/*
* Create a new hashed value set. A hashed value set (ObVSet) provides atomic
* ways to store unique 64-bit (or smaller) numbers as a set.
* The ObVSet is an object manager object and must be DECREF'ed when required.
* CALLER DECREF: return
* -- return
*/
POB_VSET ObVSet_New();

/*
* Retrieve the number of items in the given ObVSet.
* -- pvs
* -- return
*/
DWORD ObVSet_Size(_In_opt_ POB_VSET pvs);

/*
* Check if a value already exists in the ObVSet.
* -- pvs
* -- value
* -- return
*/
BOOL ObVSet_Exists(_In_opt_ POB_VSET pvs, _In_ QWORD value);

/*
* Put / Insert a non-zero value into the ObVSet.
* -- pvs
* -- value
* -- return = TRUE on insertion, FALSE otherwise - i.e. if value already
*             exists or if the max capacity of the set is reached.
*/
_Success_(return)
BOOL ObVSet_Put(_In_opt_ POB_VSET pvs, _In_ QWORD value);

/*
* Insert a value representing an address into the ObVSet. If the length of the
* data read from the start of the address a traverses page boundries all the
* pages are inserted into the set.
* -- pvs
* -- a
* -- cb
*/
VOID ObVSet_Put_PageAlign(_In_opt_ POB_VSET pvs, _In_ QWORD a, _In_ DWORD cb);

/*
* Remove an existing value from the OBVSet.
* NB! must not be called simultaneously while iterating with ObVSet_Get/ObVSet_GetNext.
* -- pvs
* -- value
* -- return = removal was successful (i.e. the value was found and removed).
*/
BOOL ObVSet_Remove(_In_opt_ POB_VSET pvs, _In_ QWORD value);

/*
* Remove the "last" value in a way that is safe for concurrent iterations of
* values in the set.
* -- pvs
* -- return = success: value, fail: 0.
*/
QWORD ObVSet_Pop(_In_opt_ POB_VSET pvs);

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
QWORD ObVSet_GetNext(_In_opt_ POB_VSET pvs, _In_ QWORD value);

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
QWORD ObVSet_Get(_In_opt_ POB_VSET pvs, _In_ DWORD index);

#endif /* __OB_H__ */
