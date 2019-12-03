// ob_core.c : implementation of object manager core functionality.
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
//
// (c) Ulf Frisk, 2018-2019
// Author: Ulf Frisk, pcileech@frizk.net
//
#include "ob.h"
#include <stdio.h>

#define obprintf_fn(format, ...)        printf("%s: "format, __func__, ##__VA_ARGS__);
#define OB_DEBUG_FOOTER_SIZE            0x20
#define OB_DEBUG_FOOTER_MAGIC           0x001122334455667788

/*
* Allocate a new object manager memory object.
* -- tag = tag of the object to be allocated.
* -- uFlags = flags as given by LocalAlloc.
* -- uBytes = bytes of object (_including_ object headers).
* -- pfnRef_0 = optional callback for cleanup o be called before object is destroyed.
*               (if object has references that should be decremented before destruction).
* -- pfnRef_1 = optional callback for when object reach refcount = 1 (excl. initial).
* -- return = allocated object on success, with refcount = 1, - NULL on fail.
*/
PVOID Ob_Alloc(_In_ DWORD tag, _In_ UINT uFlags, _In_ SIZE_T uBytes, _In_opt_ VOID(*pfnRef_0)(_In_ PVOID pOb), _In_opt_ VOID(*pfnRef_1)(_In_ PVOID pOb))
{
    POB pOb;
    if((uBytes > 0x40000000) || (uBytes < sizeof(OB))) { return NULL; }
    pOb = (POB)LocalAlloc(uFlags, uBytes + OB_DEBUG_FOOTER_SIZE);
    if(!pOb) { return NULL; }
    pOb->_magic = OB_HEADER_MAGIC;
    pOb->_count = 1;
    pOb->_tag = tag;
    pOb->_pfnRef_0 = pfnRef_0;
    pOb->_pfnRef_1 = pfnRef_1;
    pOb->cbData = (DWORD)uBytes - sizeof(OB);
#ifdef OB_DEBUG
    DWORD i, cb = sizeof(OB) + pOb->cbData;
    PBYTE pb = (PBYTE)pOb;
    for(i = 0; i < OB_DEBUG_FOOTER_SIZE; i += 8) {
        *(PQWORD)(pb + cb + i) = OB_DEBUG_FOOTER_MAGIC;
    }
#endif /* OB_DEBUG */
    return pOb;
}

/*
* Increase the reference count of a object manager object.
* -- pOb
* -- return
*/
PVOID Ob_INCREF(_In_opt_ PVOID pObIn)
{
    POB pOb = (POB)pObIn;
    if(pOb) {
        if(pOb->_magic == OB_HEADER_MAGIC) {
            InterlockedIncrement(&pOb->_count);
            return (POB)pOb;
        } else {
            obprintf_fn("ObCORE: CRITICAL: INCREF OF NON OBJECT MANAGER OBJECT!\n")
        }
    }
    return NULL;
}

/*
* Decrease the reference count of a object manager object. If the reference
* count reaches zero the object will be cleaned up.
* -- pObIn
*/
VOID Ob_DECREF(_In_opt_ PVOID pObIn)
{
    POB pOb = (POB)pObIn;
    DWORD c;
    if(pOb) {
        if(pOb->_magic == OB_HEADER_MAGIC) {
            c = InterlockedDecrement(&pOb->_count);
#ifdef OB_DEBUG
            DWORD i, cb = sizeof(OB) + pOb->cbData;
            PBYTE pb = (PBYTE)pOb;
            for(i = 0; i < OB_DEBUG_FOOTER_SIZE; i += 8) {
                if(*(PQWORD)(pb + cb + i) != OB_DEBUG_FOOTER_MAGIC) {
                    obprintf_fn("ObCORE: CRITICAL: FOOTER OVERWRITTEN - MEMORY CORRUPTION? REFCNT: %i TAG: %02X\n", c, pOb->_tag)
                }
            }
#endif /* OB_DEBUG */
            if(c == 0) {
                if(pOb->_pfnRef_0) { pOb->_pfnRef_0(pOb); }
                pOb->_magic = 0;
                LocalFree(pOb);
            } else if((c == 1) && pOb->_pfnRef_1) {
                pOb->_pfnRef_1(pOb);
            }
        } else {
            obprintf_fn("ObCORE: CRITICAL: DECREF OF NON OBJECT MANAGER OBJECT!\n")
        }
    }
}

/*
* Checks if pObIn is a valid object manager object with the specified tag.
* -- pObIn
* -- tag
* -- return
*/
BOOL Ob_VALID_TAG(_In_ PVOID pObIn, _In_ DWORD tag)
{
    POB pOb = (POB)pObIn;
    return pOb && (pOb->_magic == OB_HEADER_MAGIC) && (pOb->_tag = tag);
}
