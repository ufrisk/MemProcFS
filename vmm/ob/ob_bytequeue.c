// ob_bytequeue.c : implementation of object manager byte queue.
//
// The byte queue contains a fixed number of bytes as buffer. The queue size
// is defined at queue creation and cannot be changed.
// 
// Bytes in the form of packets [pb, cb, tag] is pushed on the queue as long
// as there is available space.
// 
// Bytes may be popped from the queue. This will also free up space for more
// bytes to be pushed on the queue.
// 
// The bytes queue is FIFO and will always pop the oldest bytes first.
// 
// The ObByteQueue is an object manager object and must be DECREF'ed when required.
//
// (c) Ulf Frisk, 2019-2024
// Author: Ulf Frisk, pcileech@frizk.net
//
#include "ob.h"

#define OB_BYTEQUEUE_IS_VALID(p)    (p && (p->ObHdr._magic2 == OB_HEADER_MAGIC) && (p->ObHdr._magic1 == OB_HEADER_MAGIC) && (p->ObHdr._tag == OB_TAG_CORE_BYTEQUEUE))

typedef struct tdOB_BYTEQUEUE {
    OB ObHdr;
    SRWLOCK LockSRW;
    DWORD cPackets;
    DWORD cboHead;
    DWORD cboTail;
    DWORD cb;
    BYTE pb[0];
} OB_BYTEQUEUE, *POB_BYTEQUEUE;

typedef struct tdBYTEQUEUE_PACKET {
    QWORD qwTag;
    DWORD cboNext;
    DWORD cb;
    BYTE pb[0];
} BYTEQUEUE_PACKET, *PBYTEQUEUE_PACKET;

#define OB_BYTEQUEUE_CALL_SYNCHRONIZED_IMPLEMENTATION_WRITE(pm, RetTp, RetValFail, fn) {    \
    if(!OB_BYTEQUEUE_IS_VALID(pm)) { return RetValFail; }                                   \
    RetTp retVal;                                                                           \
    AcquireSRWLockExclusive(&pm->LockSRW);                                                  \
    retVal = fn;                                                                            \
    ReleaseSRWLockExclusive(&pm->LockSRW);                                                  \
    return retVal;                                                                          \
}

#define OB_BYTEQUEUE_CALL_SYNCHRONIZED_IMPLEMENTATION_READ(pm, RetTp, RetValFail, fn) {     \
    if(!OB_BYTEQUEUE_IS_VALID(pm)) { return RetValFail; }                                   \
    RetTp retVal;                                                                           \
    AcquireSRWLockShared(&pm->LockSRW);                                                     \
    retVal = fn;                                                                            \
    ReleaseSRWLockShared(&pm->LockSRW);                                                     \
    return retVal;                                                                          \
}



//-----------------------------------------------------------------------------
// IMPLEMENTATION BELOW:
//-----------------------------------------------------------------------------

_Success_(return)
BOOL _ObByteQueue_Peek(_In_ POB_BYTEQUEUE pq, _Out_opt_ QWORD *pqwTag, _In_ SIZE_T cb, _Out_ PBYTE pb, _Out_ SIZE_T *pcbRead)
{
    PBYTEQUEUE_PACKET p = (PBYTEQUEUE_PACKET)(pq->pb + pq->cboHead);
    if(!pq->cPackets) {
        *pcbRead = 0;
        return FALSE;
    }
    *pcbRead = p->cb;
    if(p->cb < cb) {
        return FALSE;
    }
    if(pqwTag) {
        *pqwTag = p->qwTag;
    }
    memcpy(pb, p->pb, p->cb);
    return TRUE;
}

_Success_(return)
BOOL _ObByteQueue_Pop(_In_ POB_BYTEQUEUE pq, _Out_opt_ QWORD *pqwTag, _In_ SIZE_T cb, _Out_ PBYTE pb, _Out_ SIZE_T *pcbRead)
{
    PBYTEQUEUE_PACKET p = (PBYTEQUEUE_PACKET)(pq->pb + pq->cboHead);
    if(!pq->cPackets) {
        *pcbRead = 0;
        return FALSE;
    }
    *pcbRead = p->cb;
    if(p->cb > cb) {
        return FALSE;
    }
    if(pqwTag) {
        *pqwTag = p->qwTag;
    }
    memcpy(pb, p->pb, p->cb);
    pq->cPackets--;
    if(!pq->cPackets) {
        pq->cboHead = 0;
        pq->cboTail = 0;
    } else {
        pq->cboHead = p->cboNext;
    }
    return TRUE;
}

_Success_(return)
BOOL _ObByteQueue_Push(_In_ POB_BYTEQUEUE pq, _In_opt_ QWORD qwTag, _In_ SIZE_T cb, _In_reads_bytes_(cb) PBYTE pb)
{
    PBYTEQUEUE_PACKET p;
    SIZE_T cboEoQ, cbEoQ, cbPkt = sizeof(BYTEQUEUE_PACKET) + cb;
    if(pq->cb < cbPkt) {
        return FALSE;
    }
    if(!pq->cPackets) {
        // 1st packet to be inserted at start-of-queue.
        p = (PBYTEQUEUE_PACKET)pq->pb;
    } else {
        // Nth packet to be inserted at end-of-queue.
        p = (PBYTEQUEUE_PACKET)(pq->pb + pq->cboTail);
        cboEoQ = pq->cboTail + sizeof(BYTEQUEUE_PACKET) + p->cb;
        cbEoQ = ((pq->cboHead < cboEoQ) ? pq->cb : pq->cboHead) - cboEoQ;
        if(cbEoQ >= cbPkt) {
            // Insert packet at next position in the circular buffer.
            p->cboNext = (DWORD)cboEoQ;
            p = (PBYTEQUEUE_PACKET)(pq->pb + p->cboNext);
        } else if((pq->cboTail > pq->cboHead) && (pq->cboHead >= cbPkt)) {
            // Insert packet at start of the circular buffer.
            p->cboNext = 0;
            p = (PBYTEQUEUE_PACKET)(pq->pb + p->cboNext);
        } else {
            // Not enough space.
            return FALSE;
        }
    }
    p->qwTag = qwTag;
    p->cb = (DWORD)cb;
    p->cboNext = 0;
    memcpy(p->pb, pb, cb);
    pq->cPackets++;
    pq->cboTail = (DWORD)((SIZE_T)p - (SIZE_T)pq->pb);
    return TRUE;
}

/*
* Retrieve the number of packets (not bytes) in the byte queue.
* -- pq
* -- return
*/
DWORD ObByteQueue_Size(_In_opt_ POB_BYTEQUEUE pq)
{
    OB_BYTEQUEUE_CALL_SYNCHRONIZED_IMPLEMENTATION_READ(pq, DWORD, 0, pq->cPackets)
}

/*
* Peek data from the byte queue. The data is copied into the user-supplied buffer.
* If the buffer is insufficient the function will return FALSE and the required
* size will be returned in pcbRead.
* -- pq
* -- pqwTag
* -- cb
* -- pb
* -- pcbRead
* -- return = TRUE if there was data to peek, FALSE otherwise.
*/
_Success_(return)
BOOL ObByteQueue_Peek(_In_opt_ POB_BYTEQUEUE pq, _Out_opt_ QWORD *pqwTag, _In_ SIZE_T cb, _Out_ PBYTE pb, _Out_ SIZE_T *pcbRead)
{
    OB_BYTEQUEUE_CALL_SYNCHRONIZED_IMPLEMENTATION_READ(pq, BOOL, FALSE, _ObByteQueue_Peek(pq, pqwTag, cb, pb, pcbRead))
}

/*
* Pop data from the byte queue. The data is copied into the user-supplied buffer.
* If the buffer is insufficient the function will return FALSE and the required
* size will be returned in pcbRead.
* -- pq
* -- pqwTag
* -- cb
* -- pb
* -- pcbRead
* -- return = TRUE if there was data to pop, FALSE otherwise.
*/
_Success_(return)
BOOL ObByteQueue_Pop(_In_opt_ POB_BYTEQUEUE pq, _Out_opt_ QWORD *pqwTag, _In_ SIZE_T cb, _Out_ PBYTE pb, _Out_ SIZE_T *pcbRead)
{
    OB_BYTEQUEUE_CALL_SYNCHRONIZED_IMPLEMENTATION_WRITE(pq, BOOL, FALSE, _ObByteQueue_Pop(pq, pqwTag, cb, pb, pcbRead))
}

/*
* Push / Insert into the ObByteQueue. The data is copied into the queue.
* -- pq
* -- qwTag
* -- cb
* -- pb
* -- return = TRUE on insertion, FALSE otherwise - i.e. if the byte queue
*             is insufficient to hold the byte data.
*/
_Success_(return)
BOOL ObByteQueue_Push(_In_opt_ POB_BYTEQUEUE pq, _In_opt_ QWORD qwTag, _In_ SIZE_T cb, _In_reads_bytes_(cb) PBYTE pb)
{
    OB_BYTEQUEUE_CALL_SYNCHRONIZED_IMPLEMENTATION_WRITE(pq, BOOL, FALSE, _ObByteQueue_Push(pq, qwTag, cb, pb))
}

/*
* Create a new byte queue. A byte queue (ObByteQueue) provides atomic queuing
* operations for pushing/popping bytes as packets on a FIFO queue.
* The ObByteQueue is an object manager object and must be DECREF'ed when required.
* CALLER DECREF: return
* -- H
* -- cbQueueSize = the queue size in bytes. Must be larger than 4096 bytes.
* -- return
*/
POB_BYTEQUEUE ObByteQueue_New(_In_opt_ VMM_HANDLE H, _In_ DWORD cbQueueSize)
{
    POB_BYTEQUEUE pObQ;
    if(cbQueueSize < 0x1000) { return NULL; }
    pObQ = Ob_AllocEx(H, OB_TAG_CORE_BYTEQUEUE, LMEM_ZEROINIT, sizeof(POB_BYTEQUEUE) + cbQueueSize, NULL, NULL);
    if(!pObQ) { return NULL; }
    InitializeSRWLock(&pObQ->LockSRW);
    pObQ->cb = cbQueueSize;
    return pObQ;
}
