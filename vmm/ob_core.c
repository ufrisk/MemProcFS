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

// Internal object manager use only - same size as opaque OB struct.
typedef struct tdOB_HEADER {
    DWORD magic;                        // magic value - OB_HEADER_MAGIC
    WORD count;                         // reference count
    WORD tag;                           // tag - 2 chars, no null terminator
    VOID(*pfnRef_0)(_In_ PVOID pOb);    // callback - object specific cleanup before free
    VOID(*pfnRef_1)(_In_ PVOID pOb);    // callback - when object reach refcount 1 (not initial)
    DWORD cbData;
    BYTE pbData[];
} OB_HEADER, *POB_HEADER;

/*
* Allocate a new object manager memory object.
* -- tag = tag of the object to be allocated.
* -- uFlags = flags as given by LocalAlloc.
* -- uBytes = bytes of object (excluding object headers).
* -- pfnRef_0 = optional callback for cleanup o be called before object is destroyed.
*               (if object has references that should be decremented before destruction).
* -- pfnRef_1 = optional callback for when object reach refcount = 1 (excl. initial).
* -- return = allocated object on success, with refcount = 1, - NULL on fail.
*/
PVOID Ob_Alloc(_In_ WORD tag, _In_ UINT uFlags, _In_ SIZE_T uBytes, _In_opt_ VOID(*pfnRef_0)(_In_ PVOID pOb), _In_opt_ VOID(*pfnRef_1)(_In_ PVOID pOb))
{
    POB_HEADER pOb;
    if(uBytes > 0x40000000) { return NULL; }
    pOb = (POB_HEADER)LocalAlloc(uFlags, uBytes + sizeof(OB_HEADER) + OB_DEBUG_FOOTER_SIZE);
    if(!pOb) { return NULL; }
    pOb->magic = OB_HEADER_MAGIC;
    pOb->count = 1;
    pOb->tag = tag;
    pOb->pfnRef_0 = pfnRef_0;
    pOb->pfnRef_1 = pfnRef_1;
    pOb->cbData = (DWORD)uBytes;
#ifdef OB_DEBUG
    DWORD i, cb = sizeof(OB_HEADER) + pOb->cbData;
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
PVOID Ob_INCREF(PVOID pObIn)
{
    POB_HEADER pOb = (POB_HEADER)pObIn;
    if(pOb) {
        if(pOb->magic == OB_HEADER_MAGIC) {
            InterlockedIncrement16(&pOb->count);
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
VOID Ob_DECREF(PVOID pObIn)
{
    POB_HEADER pOb = (POB_HEADER)pObIn;
    WORD c;
    if(pOb) {
        if(pOb->magic == OB_HEADER_MAGIC) {
            c = InterlockedDecrement16(&pOb->count);
#ifdef OB_DEBUG
            DWORD i, cb = sizeof(OB_HEADER) + pOb->cbData;
            PBYTE pb = (PBYTE)pOb;
            for(i = 0; i < OB_DEBUG_FOOTER_SIZE; i += 8) {
                if(*(PQWORD)(pb + cb + i) != OB_DEBUG_FOOTER_MAGIC) {
                    obprintf_fn("ObCORE: CRITICAL: FOOTER OVERWRITTEN - MEMORY CORRUPTION? REFCNT: %i TAG: %02X\n", c, pOb->tag)
                }
            }
#endif /* OB_DEBUG */
            if(c == 0) {
                if(pOb->pfnRef_0) { pOb->pfnRef_0(pOb); }
                pOb->magic = 0;
                LocalFree(pOb);
            } else if((c == 1) && pOb->pfnRef_1) {
                pOb->pfnRef_1(pOb);
            }
        } else {
            obprintf_fn("ObCORE: CRITICAL: DECREF OF NON OBJECT MANAGER OBJECT!\n")
        }
    }
}
