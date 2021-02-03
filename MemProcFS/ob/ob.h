// ob.h : definitions related to the object manager and object manager collections.
//
// (c) Ulf Frisk, 2018-2021
// Author: Ulf Frisk, pcileech@frizk.net
//
#ifndef __OB_H__
#define __OB_H__
#include <windows.h>

typedef unsigned __int64                QWORD, *PQWORD;
#define OB_DEBUG
#define OB_HEADER_MAGIC                 0x0c0efefe

#define OB_TAG_CORE_CONTAINER           'ObCo'
#define OB_TAG_CORE_COMPRESSED          'ObCp'
#define OB_TAG_CORE_DATA                'ObDa'
#define OB_TAG_CORE_SET                 'ObSe'
#define OB_TAG_CORE_MAP                 'ObMa'
#define OB_TAG_CORE_CACHEMAP            'ObMc'
#define OB_TAG_CORE_STRMAP              'ObMs'

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

typedef struct tdOB {
    // internal object manager functionality below: (= do not use unless absolutely necessary)
    DWORD _magic;                        // magic value - OB_HEADER_MAGIC
    union {
        DWORD _tag;                      // tag - 2 chars, no null terminator
        CHAR _tagCh[4];
    };
    VOID(*_pfnRef_0)(_In_ PVOID pOb);    // callback - object specific cleanup before free
    VOID(*_pfnRef_1)(_In_ PVOID pOb);    // callback - when object reach refcount 1 (not initial)
    DWORD _count;                        // reference count
    // external object manager functionality below: (= ok to use)
    DWORD cbData;
} OB, *POB;

/*
* Allocate a new object manager memory object.
* -- tag = tag identifying the type of object.
* -- uFlags = flags as given by LocalAlloc.
* -- uBytes = bytes of object (_including_ object headers).
* -- pfnRef_0 = optional callback for cleanup o be called before object is destroyed.
*               (if object contains objects which references should be decremented
                 before destruction of this 'parent' object).
* -- pfnRef_1 = optional callback for when object reach refcount = 1 at DECREF.
* -- return = allocated object on success, with refcount = 1, - NULL on fail.
*/
PVOID Ob_Alloc(_In_ DWORD tag, _In_ UINT uFlags, _In_ SIZE_T uBytes, _In_opt_ VOID(*pfnRef_0)(_In_ PVOID pOb), _In_opt_ VOID(*pfnRef_1)(_In_ PVOID pOb));

/*
* Increase the reference count of a object by one.
* -- pOb
* -- return
*/
PVOID Ob_INCREF(_In_opt_ PVOID pOb);

/*
* Decrease the reference count of an object manager object by one.
* NB! Do not use object after DECREF - other threads might have also DECREF'ed
* the object at same time making it to be free'd - making the memory invalid.
* -- pOb
* -- return = pObIn if pObIn is valid and refcount > 0 after decref.
*/
PVOID Ob_DECREF(_In_opt_ PVOID pOb);

/*
* Decrease the reference count of a object manager object. If the reference
* count reaches zero the object will be cleaned up.
* Also set the incoming pointer to NULL.
* -- ppOb
*/
inline VOID Ob_DECREF_NULL(_In_opt_ PVOID *ppOb)
{
    if(ppOb) {
        Ob_DECREF(*ppOb);
        *ppOb = NULL;
    }
}

/*
* Checks if pObIn is a valid object manager object with the specified tag.
* -- pObIn
* -- tag
* -- return
*/
BOOL Ob_VALID_TAG(_In_ PVOID pObIn, _In_ DWORD tag);



// ----------------------------------------------------------------------------
// OBJECT MANAGER COMMON/GENERIC OBJECTS BELOW:
//
// ----------------------------------------------------------------------------

typedef struct tdOB_DATA {
    OB ObHdr;
    union {
        BYTE pb[];
        CHAR sz[];
        DWORD pdw[];
        QWORD pqw[];
    };
} OB_DATA, *POB_DATA;

/*
* Create a new object manager data object in which the ObHdr->cbData is equal
* to the number of bytes in the data buffer supplied to this function.
* May also be created with Ob_Alloc with size: sizeof(OB_HDR) + length of data.
* CALLER DECREF: return
* -- pb
* -- cb
* -- return
*/
_Success_(return != NULL)
POB_DATA ObData_New(_In_ PBYTE pb, _In_ DWORD cb);



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
* Create a new object container object without an initial contained object.
* An object container provides atomic access to its contained object in a
* multithreaded environment. The object container is in itself an object
* manager object and must be DECREF'ed by the caller when use is complete.
* CALLER DECREF: return
* -- return
*/
POB_CONTAINER ObContainer_New();

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

/*
* Check if the object container is valid and contains an object.
* -- pObContainer
* -- return
*/
BOOL ObContainer_Exists(_In_opt_ POB_CONTAINER pObContainer);



// ----------------------------------------------------------------------------
// HASHED VALUE SET FUNCTIONALITY BELOW:
//
// The hashed value set (ObSet) provides thread safe efficient access to a set
// which is containing _NON_ZERO_ values (64-bit unsigned integers). The ObSet
// may hold a maximum capacity of 0x01000000 (~16M) entries - which are UNIQUE
// and _NON_ZERO_.
// The hashed value set (ObSet) guarantees order amongst values unless the
// function ObSet_Remove is called - in which order may change and on-going
// iterations of the set with ObSet_Get/ObSet_GetNext may fail.
// The ObSet is an object manager object and must be DECREF'ed when required.
// ----------------------------------------------------------------------------

typedef struct tdOB_SET *POB_SET;

/*
* Create a new hashed value set. A hashed value set (ObSet) provides atomic
* ways to store unique 64-bit (or smaller) numbers as a set.
* The ObSet is an object manager object and must be DECREF'ed when required.
* CALLER DECREF: return
* -- return
*/
POB_SET ObSet_New();

/*
* Retrieve the number of items in the given ObSet.
* -- pvs
* -- return
*/
DWORD ObSet_Size(_In_opt_ POB_SET pvs);

/*
* Check if a value already exists in the ObSet.
* -- pvs
* -- value
* -- return
*/
BOOL ObSet_Exists(_In_opt_ POB_SET pvs, _In_ QWORD value);

/*
* Push / Insert a non-zero value into the ObSet.
* -- pvs
* -- value
* -- return = TRUE on insertion, FALSE otherwise - i.e. if value already
*             exists or if the max capacity of the set is reached.
*/
_Success_(return)
BOOL ObSet_Push(_In_opt_ POB_SET pvs, _In_ QWORD value);

/*
* Push/Merge/Insert all values from the ObSet pvsSrc into the ObSet pvs.
* The source set is kept intact.
* -- pvs
* -- pvsSrc
* -- return = TRUE on success, FALSE otherwise.
*/
_Success_(return)
BOOL ObSet_PushSet(_In_opt_ POB_SET pvs, _In_opt_ POB_SET pvsSrc);

/*
* Push/Merge/Insert all QWORD values from the ObData pDataSrc into the ObSet pvs.
* The source data is kept intact.
* -- pvs
* -- pDataSrc
* -- return = TRUE on success, FALSE otherwise.
*/
_Success_(return)
BOOL ObSet_PushData(_In_opt_ POB_SET pvs, _In_opt_ POB_DATA pDataSrc);

/*
* Insert a value representing an address into the ObSet. If the length of the
* data read from the start of the address a traverses page boundries all the
* pages are inserted into the set.
* -- pvs
* -- a
* -- cb
*/
VOID ObSet_Push_PageAlign(_In_opt_ POB_SET pvs, _In_ QWORD a, _In_ DWORD cb);

/*
* Remove an existing value from the ObSet.
* NB! must not be called simultaneously while iterating with ObSet_Get/ObSet_GetNext.
* -- pvs
* -- value
* -- return = removal was successful (i.e. the value was found and removed).
*/
BOOL ObSet_Remove(_In_opt_ POB_SET pvs, _In_ QWORD value);

/*
* Clear the ObSet by removing all values.
* NB! underlying allocated memory will remain unchanged.
* -- pvs
*/
VOID ObSet_Clear(_In_opt_ POB_SET pvs);

/*
* Save the contents of an ObSet to a disk file.
* The resulting disk file may be read with ObSet_FileLoad().
* -- pvs
* -- wszFileName = save file to create.
* -- return
*/
_Success_(return)
BOOL ObSet_FileSave(_In_opt_ POB_SET pvs, _In_ LPWSTR wszFileName);

/*
* Load the contents of an ObSet disk file into the supplied set.
* -- pvs
* -- wszFileName = file previously saved by ObSet_FileSave().
* -- return
*/
_Success_(return)
BOOL ObSet_FileLoad(_In_opt_ POB_SET pvs, _In_ LPWSTR wszFileName);

/*
* Remove the "last" value in a way that is safe for concurrent iterations of
* values in the set.
* -- pvs
* -- return = success: value, fail: 0.
*/
QWORD ObSet_Pop(_In_opt_ POB_SET pvs);

/*
* Retrieve the next value given a value. The start value and end value are the
* ZERO value (which is a special reserved non-valid value).
* NB! Correctness of the Get/GetNext functionality is _NOT_ guaranteed if the
* ObSet_Remove function is called while iterating over the ObSet - items may
* be skipped or iterated over multiple times!
* -- pvs
* -- value
* -- return
*/
QWORD ObSet_GetNext(_In_opt_ POB_SET pvs, _In_ QWORD value);

/*
* Retrieve a value given a value index (which is less than the amount of items
* in the Set).
* NB! Correctness of the Get/GetNext functionality is _NOT- guaranteed if the
* ObSet_Remove function is called while iterating over the ObSet - items may
* be skipped or iterated over multiple times!
* -- pvs
* -- index
* -- return
*/
QWORD ObSet_Get(_In_opt_ POB_SET pvs, _In_ DWORD index);

/*
* Retrieve all values in the Set as a POB_DATA object containing the values
* in a QWORD table.
* -- CALLER DECREF: return
* -- pvs
* -- return
*/
POB_DATA ObSet_GetAll(_In_opt_ POB_SET pvs);



// ----------------------------------------------------------------------------
// MAP FUNCTIONALITY BELOW:
//
// The map is a key-value map that may, as an option, contain object manager
// objects in its value field. They key may be user-defined, generated by a
// function or absent. The ObMap may hold a maximum capacity of 0x02000000
// (~32M) entries which are UNIQUE and non-NULL.
//
// The map (ObMap) is thread safe and implement efficient access to the data
// via internal hashing functionality.
// The map (ObMap) guarantees order amongst values unless the ObMap_Remove*
// functions are called - in which order may change and on-going iterations
// of the set with ObMap_Get/ObMap_GetNext may fail.
// The ObMap is an object manager object and must be DECREF'ed when required.
// ----------------------------------------------------------------------------

typedef struct tdOB_MAP *POB_MAP;

#define OB_MAP_FLAGS_OBJECT_VOID        0x00
#define OB_MAP_FLAGS_OBJECT_OB          0x01
#define OB_MAP_FLAGS_OBJECT_LOCALFREE   0x02
#define OB_MAP_FLAGS_NOKEY              0x04

/*
* Create a new map. A map (ObMap) provides atomic map operations and ways
* to optionally map key values to values, pointers or object manager objects.
* The ObSet is an object manager object and must be DECREF'ed when required.
* CALLER DECREF: return
* -- flags = defined by OB_MAP_FLAGS_*
* -- return
*/
POB_MAP ObMap_New(_In_ QWORD flags);

/*
* Retrieve the number of objects in the ObMap.
* -- pm
* -- return
*/
DWORD ObMap_Size(_In_opt_ POB_MAP pm);

/*
* Check if an object exists in the ObMap.
* -- pm
* -- qwKey/pvObject
* -- return
*/
BOOL ObMap_Exists(_In_opt_ POB_MAP pm, _In_ PVOID pvObject);

/*
* Check if a key exists in the ObMap.
* -- pm
* -- qwKey/pvObject
* -- return
*/
BOOL ObMap_ExistsKey(_In_opt_ POB_MAP pm, _In_ QWORD qwKey);

/*
* Push / Insert into the ObMap.
* If pvObject is OB the map performs Ob_INCREF on its own reference.
* -- pm
* -- qwKey
* -- pvObject
* -- return = TRUE on insertion, FALSE otherwise - i.e. if the key or object
*             already exists or if the max capacity of the map is reached.
*/
_Success_(return)
BOOL ObMap_Push(_In_opt_ POB_MAP pm, _In_ QWORD qwKey, _In_ PVOID pvObject);

/*
* Push / Insert into the ObMap by making a shallow copy of the object.
* NB! only valid for OB_MAP_FLAGS_OBJECT_LOCALFREE initialized maps.
* -- pm
* -- qwKey
* -- pvObject
* -- cbObject
* -- return = TRUE on insertion, FALSE otherwise - i.e. if the key or object
*             already exists or if the max capacity of the map is reached.
*/
_Success_(return)
BOOL ObMap_PushCopy(_In_opt_ POB_MAP pm, _In_ QWORD qwKey, _In_ PVOID pvObject, _In_ SIZE_T cbObject);

/*
* Remove the "last" object.
* CALLER DECREF(if OB): return
* -- pm
* -- return = success: object, fail: NULL.
*/
_Success_(return != NULL)
PVOID ObMap_Pop(_In_opt_ POB_MAP pm);

/*
* Remove the "last" object and return it and its key.
* CALLER DECREF(if OB): return
* -- pm
* -- pKey
* -- return = success: object, fail: NULL.
*/
_Success_(return != NULL)
PVOID ObMap_PopWithKey(_In_opt_ POB_MAP pm, _Out_ PQWORD pKey);

/*
* Remove an object from the ObMap.
* NB! must not be called simultaneously while iterating with ObMap_GetByIndex/ObMap_GetNext.
* CALLER DECREF(if OB): return
* -- pm
* -- value
* -- return = success: object, fail: NULL.
*/
PVOID ObMap_Remove(_In_opt_ POB_MAP pm, _In_ PVOID pvObject);

/*
* Remove an object from the ObMap by using its key.
* NB! must not be called simultaneously while iterating with ObMap_GetByIndex/ObMap_GetNext.
* CALLER DECREF(if OB): return
* -- pm
* -- qwKey
* -- return = success: object, fail: NULL.
*/
PVOID ObMap_RemoveByKey(_In_opt_ POB_MAP pm, _In_ QWORD qwKey);

/*
* Clear the ObMap by removing all objects and their keys.
* NB! underlying allocated memory will remain unchanged.
* -- pm
* -- return = clear was successful - always true.
*/
_Success_(return)
BOOL ObMap_Clear(_In_opt_ POB_MAP pm);

/*
* Peek the "last" object.
* CALLER DECREF(if OB): return
* -- pm
* -- return = success: object, fail: NULL.
*/
PVOID ObMap_Peek(_In_opt_ POB_MAP pm);

/*
* Peek the key of the "last" object.
* -- pm
* -- return = the key, otherwise 0.
*/
QWORD ObMap_PeekKey(_In_opt_ POB_MAP pm);

/*
* Retrieve the next object given an object. Start and end objects are NULL.
* NB! Correctness of the Get/GetNext functionality is _NOT_ guaranteed if the
* ObMap_Remove* functions are called while iterating over the ObMap - items may
* be skipped or iterated over multiple times!
* FUNCTION DECREF(if OB): pvObject
* CALLER DECREF(if OB): return
* -- pm
* -- pvObject
* -- return
*/
PVOID ObMap_GetNext(_In_opt_ POB_MAP pm, _In_opt_ PVOID pvObject);

/*
* Retrieve the next object given a key. To start iterating supply NULL in the
* pvObject parameter (this overrides qwKey). When no more objects are found
* NULL will be returned. This function may ideally be used when object maps
* may be refreshed between function calls. Key may be more stable than object.
* NB! Correctness of the Get/GetNext functionality is _NOT_ guaranteed if the
* ObMap_Remove* functions are called while iterating over the ObMap - items may
* be skipped or iterated over multiple times!
* FUNCTION DECREF(if OB): pvObject
* CALLER DECREF(if OB): return
* -- pm
* -- qwKey
* -- pvObject
* -- return
*/
PVOID ObMap_GetNextByKey(_In_opt_ POB_MAP pm, _In_ QWORD qwKey, _In_opt_ PVOID pvObject);

/*
* Retrieve a value given a key.
* CALLER DECREF(if OB): return
* -- pm
* -- qwKey
* -- return
*/
PVOID ObMap_GetByKey(_In_opt_ POB_MAP pm, _In_ QWORD qwKey);

/*
* Retrieve an object given an index (which is less than the amount of items
* in the ObMap).
* NB! Correctness of the Get/GetNext functionality is _NOT- guaranteed if the
* ObMap_Remove* functions are called while iterating over the ObSet - items
* may be skipped or iterated over multiple times!
* CALLER DECREF(if OB): return
* -- pm
* -- index
* -- return
*/
PVOID ObMap_GetByIndex(_In_opt_ POB_MAP pm, _In_ DWORD index);

/*
* Retrieve the key for an existing object in the ObMap.
* -- pm
* -- pvObject
* -- return
*/
_Success_(return != 0)
QWORD ObMap_GetKey(_In_opt_ POB_MAP pm, _In_ PVOID pvObject);

/*
* Common filter function related to ObMap_FilterSet.
*/
VOID ObMap_FilterSet_FilterAllKey(_In_ QWORD k, _In_ PVOID v, _Inout_ POB_SET ps);

/*
* Filter map objects into a generic context by using a user-supplied filter function.
* -- pm
* -- ctx = optional context to pass on to the filter function.
* -- pfnFilter
* -- return
*/
_Success_(return)
BOOL ObMap_Filter(_In_opt_ POB_MAP pm, _Inout_opt_ PVOID ctx, _In_opt_ VOID(*pfnFilter)(_In_ QWORD k, _In_ PVOID v, _Inout_opt_ PVOID ctx));

/*
* Filter map objects into a POB_SET by using a user-supplied filter function.
* CALLER DECREF: return
* -- pm
* -- pfnFilter
* -- return = POB_SET consisting of values gathered by the pfnFilter function.
*/
_Success_(return != NULL)
POB_SET ObMap_FilterSet(_In_opt_ POB_MAP pm, _In_opt_ VOID(*pfnFilter)(_In_ QWORD k, _In_ PVOID v, _Inout_ POB_SET ps));

/*
* Remove map objects using a user-supplied filter function.
* -- pm
* -- pfnFilter = decision making function: [pfnFilter(k,v)->TRUE(remove)|FALSE(keep)]
* -- return = number of entries removed.
*/
DWORD ObMap_RemoveByFilter(_In_opt_ POB_MAP pm, _In_opt_ BOOL(*pfnFilter)(_In_ QWORD k, _In_ PVOID v));



// ----------------------------------------------------------------------------
// CACHE MAP FUNCTIONALITY BELOW:
//
// The map (ObCacheMap) implements an efficient caching of objects stored in
// an internal hash map. The cached object are retrieved and cleared according
// to rules implemented by callback functions.
//
// If the max number of map entries are reached the least recently accessed
// entry will be removed if required to make room for a new entry.
//
// The map (ObCacheMap) is thread safe.
// The ObCacheMap is an object manager object and must be DECREF'ed when required.
// ----------------------------------------------------------------------------

typedef struct tdOB_CACHEMAP *POB_CACHEMAP;

#define OB_CACHEMAP_FLAGS_OBJECT_VOID        0x00
#define OB_CACHEMAP_FLAGS_OBJECT_OB          0x01
#define OB_CACHEMAP_FLAGS_OBJECT_LOCALFREE   0x02

/*
* Create a new cached map. A cached map (ObCacheMap) provides atomic map
* operations on cached objects.
* The ObCacheMap is an object manager object and must be DECREF'ed when required.
* CALLER DECREF: return
* -- cMaxEntries = max entries in the cache, if more entries are added the
*       least recently accessed item will be removed from the cache map.
* -- pfnValidEntry = validation callback function (if any).
* -- flags = defined by OB_CACHEMAP_FLAGS_*
* -- return
*/
POB_CACHEMAP ObCacheMap_New(
    _In_ DWORD cMaxEntries,
    _In_opt_ BOOL(*pfnValidEntry)(_Inout_ PQWORD qwContext, _In_ QWORD qwKey, _In_ PVOID pvObject),
    _In_ QWORD flags
);

/*
* Clear the ObCacheMap by removing all objects and their keys.
* -- pcm
* -- return = clear was successful - always true.
*/
_Success_(return)
BOOL ObCacheMap_Clear(_In_opt_ POB_CACHEMAP pcm);

/*
* Check if a key exists in the ObCacheMap.
* -- pcm
* -- qwKey/pvObject
* -- return
*/
BOOL ObCacheMap_ExistsKey(_In_opt_ POB_CACHEMAP pcm, _In_ QWORD qwKey);

/*
* Push / Insert into the ObCacheMap. If an object with the same key already
* exists it's removed from the cache map before the new object is inserted.
* If pvObject is OB the map performs Ob_INCREF on its own reference.
* -- pcm
* -- qwKey
* -- pvObject
* -- qwContextInitial = initial context (passed on to pfnValidEntry callback).
* -- return = TRUE on insertion, FALSE otherwise - i.e. if the key or object
*             already exists or if the max capacity of the map is reached.
*/
_Success_(return)
BOOL ObCacheMap_Push(_In_opt_ POB_CACHEMAP pcm, _In_ QWORD qwKey, _In_ PVOID pvObject, _In_ QWORD qwContextInitial);

/*
* Retrieve the number of objects in the ObCacheMap.
* -- pcm
* -- return
*/
DWORD ObCacheMap_Size(_In_opt_ POB_CACHEMAP pcm);

/*
* Retrieve a value given a key.
* CALLER DECREF(if OB): return
* -- pcm
* -- qwKey
* -- return
*/
PVOID ObCacheMap_GetByKey(_In_opt_ POB_CACHEMAP pcm, _In_ QWORD qwKey);

/*
* Remove an object from the ObCacheMap by using its key.
* NB! Object is removed and returned even if valid critera is not matched.
* CALLER DECREF(if OB): return
* -- pcm
* -- qwKey
* -- return = success: object, fail: NULL.
*/
PVOID ObCacheMap_RemoveByKey(_In_opt_ POB_CACHEMAP pcm, _In_ QWORD qwKey);


// ----------------------------------------------------------------------------
// STRMAP FUNCTIONALITY BELOW:
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
// ----------------------------------------------------------------------------

typedef struct tdOB_STRMAP *POB_STRMAP;

// Strings in OB_STRMAP are considered to be CASE SENSITIVE.
#define OB_STRMAP_FLAGS_CASE_SENSITIVE          0x00

// Strings in OB_STRMAP are considered to be CASE INSENSITIVE. The case is
// preserved for 1st unique entry added; subsequent entries will use 1st entry.
#define OB_STRMAP_FLAGS_CASE_INSENSITIVE        0x01

// Assign temporary string values to destinations at time of push.
// NB! values will become invalid after OB_STRMAP DECREF/FINALIZE!
#define OB_STRMAP_FLAGS_STR_ASSIGN_TEMPORARY    0x02

/*
* Create a new strmap. A strmap (ObStrMap) provides an easy way to add new
* strings to a multi-string in an efficient way. The ObStrMap is not meant
* to be a long-term object - it's supposed to be finalized and decommissioned
* by calling ObStrMap_Finalize_DECREF_NULL().
* The ObStrMap is an object manager object and must be DECREF'ed when required.
* CALLER DECREF: return
* -- flags = defined by OB_STRMAP_FLAGS_*
* -- return
*/
POB_STRMAP ObStrMap_New(_In_ QWORD flags);

/*
* Push / Insert into the ObStrMap.
* -- psm
* -- sz
* -- pwszDst
* -- pcchDst
* -- return = TRUE on insertion, FALSE otherwise.
*/
_Success_(return)
BOOL ObStrMap_PushA(_In_opt_ POB_STRMAP psm, _In_opt_ LPSTR sz, _Out_opt_ LPWSTR *pwszDst, _Out_opt_ PDWORD pcchDst);

/*
* Push / Insert into the ObStrMap.
* -- psm
* -- wsz
* -- pwszDst
* -- pcchDst
* -- return = TRUE on insertion, FALSE otherwise.
*/
_Success_(return)
BOOL ObStrMap_Push(_In_opt_ POB_STRMAP psm, _In_opt_ LPWSTR wsz, _Out_opt_ LPWSTR *pwszDst, _Out_opt_ PDWORD pcchDst);

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
BOOL ObStrMap_Push_swprintf_s(_In_opt_ POB_STRMAP psm, _Out_opt_ LPWSTR *pwszDst, _Out_opt_ PDWORD pcchDst, _In_z_ _Printf_format_string_ wchar_t const *const wszFormat, ...);

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
BOOL ObStrMap_Push_UnicodeObject(_In_opt_ POB_STRMAP psm, _In_ BOOL f32, _In_ QWORD vaUnicodeObject, _Out_opt_ LPWSTR *pwszDst, _Out_opt_ PDWORD pcchDst);

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
BOOL ObStrMap_Push_UnicodeBuffer(_In_opt_ POB_STRMAP psm, _In_ WORD cbUnicodeBuffer, _In_ QWORD vaUnicodeBuffer, _Out_opt_ LPWSTR *pwszDst, _Out_opt_ PDWORD pcchDst);

/*
* Finalize the ObStrMap. Create and assign the MultiStr and assign each
* previously added string reference to a pointer location within the MultiStr.
* ---
* Also decrease the reference count of the object. If the reference count
* reaches zero the object will be cleaned up.
* Also set the incoming pointer to NULL.
* CALLER LOCALFREE: *pwszMultiStr
* -- ppsm
* -- pwszMultiStr
* -- pcbMultiStr
* -- return
*/
_Success_(return)
BOOL ObStrMap_Finalize_DECREF_NULL(_In_opt_ PVOID *ppsm, _Out_ LPWSTR *pwszMultiStr, _Out_ PDWORD pcbMultiStr);



// ----------------------------------------------------------------------------
// COMPRESSED DATA OBJECT FUNCTIONALITY BELOW:
//
// ----------------------------------------------------------------------------

typedef struct tdOB_COMPRESSED *POB_COMPRESSED;

/*
* Create a new compressed buffer object from a byte buffer.
* CALLER DECREF: return
* -- pcm
* -- pb
* -- cb
* -- return
*/
_Success_(return != NULL)
POB_COMPRESSED ObCompressed_NewFromByte(_In_reads_(cb) PBYTE pb, _In_ DWORD cb);

/*
* Create a new compressed buffer object from a zero terminated string.
* CALLER DECREF: return
* -- pcm
* -- sz
* -- return
*/
_Success_(return != NULL)
POB_COMPRESSED ObCompress_NewFromStrA(_In_ LPSTR sz);

/*
* Retrieve the uncompressed size of the compressed data object.
* -- pdc
* -- return
*/
DWORD ObCompress_Size(_In_opt_ POB_COMPRESSED pdc);

/*
* Retrieve uncompressed from a compressed data object.
* CALLER DECREF: return
* -- pdc
* -- return
*/
_Success_(return != NULL)
POB_DATA ObCompressed_GetData(_In_opt_ POB_COMPRESSED pdc);

#endif /* __OB_H__ */
