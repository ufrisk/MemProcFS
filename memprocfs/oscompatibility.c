// oscompatibility.c : VMM Windows/Linux compatibility layer.
//
// (c) Ulf Frisk, 2021-2025
// Author: Ulf Frisk, pcileech@frizk.net
//
#if defined(LINUX) || defined(MACOS)
#include "oscompatibility.h"
#include <stdatomic.h>

// ----------------------------------------------------------------------------
// LocalAlloc/LocalFree BELOW:
// ----------------------------------------------------------------------------

HANDLE LocalAlloc(DWORD uFlags, SIZE_T uBytes)
{
    HANDLE h = malloc(uBytes);
    if(h && (uFlags & LMEM_ZEROINIT)) {
        memset(h, 0, uBytes);
    }
    return h;
}

VOID LocalFree(HANDLE hMem)
{
    free(hMem);
}



// ----------------------------------------------------------------------------
// CRITICAL_SECTION functionality below:
// ----------------------------------------------------------------------------

VOID InitializeCriticalSection(LPCRITICAL_SECTION lpCriticalSection)
{
    memset(lpCriticalSection, 0, sizeof(CRITICAL_SECTION));
    pthread_mutexattr_init(&lpCriticalSection->mta);
    pthread_mutexattr_settype(&lpCriticalSection->mta, PTHREAD_MUTEX_RECURSIVE);
    pthread_mutex_init(&lpCriticalSection->mutex, &lpCriticalSection->mta);
}

BOOL InitializeCriticalSectionAndSpinCount(LPCRITICAL_SECTION lpCriticalSection, DWORD dwSpinCount)
{
    InitializeCriticalSection(lpCriticalSection);
    return TRUE;
}

VOID DeleteCriticalSection(LPCRITICAL_SECTION lpCriticalSection)
{
    pthread_mutex_destroy(&lpCriticalSection->mutex);
    memset(lpCriticalSection, 0, sizeof(CRITICAL_SECTION));
}

VOID EnterCriticalSection(LPCRITICAL_SECTION lpCriticalSection)
{
    pthread_mutex_lock(&lpCriticalSection->mutex);
}

VOID LeaveCriticalSection(LPCRITICAL_SECTION lpCriticalSection)
{
    pthread_mutex_unlock(&lpCriticalSection->mutex);
}



// ----------------------------------------------------------------------------
// GENERAL STUFF BELOW:
// ----------------------------------------------------------------------------

#ifndef CLOCK_MONOTONIC_COARSE
#define CLOCK_MONOTONIC_COARSE CLOCK_MONOTONIC
#endif /* CLOCK_MONOTONIC_COARSE */

QWORD GetTickCount64()
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC_COARSE, &ts);
    return ts.tv_sec * 1000 + ts.tv_nsec / (1000 * 1000);
}

#endif /* LINUX || MACOS */



// ----------------------------------------------------------------------------
// SRWLock functionality below:
// ----------------------------------------------------------------------------

#ifdef LINUX

#include <sys/syscall.h>
#include <linux/futex.h>

static int futex(uint32_t *uaddr, int futex_op, uint32_t val, const struct timespec *timeout, uint32_t *uaddr2, uint32_t val3)
{
    return syscall(SYS_futex, uaddr, futex_op, val, timeout, uaddr2, val3);
}

VOID InitializeSRWLock(PSRWLOCK pSRWLock)
{
    ZeroMemory(pSRWLock, sizeof(SRWLOCK));
}

BOOL AcquireSRWLockExclusive_Try(_Inout_ PSRWLOCK pSRWLock)
{
    DWORD dwZero = 0;
    __sync_fetch_and_add_4(&pSRWLock->c, 1);
    if(atomic_compare_exchange_strong((atomic_uint *)&pSRWLock->xchg, &dwZero, 1)) {
        return TRUE;
    }
    __sync_sub_and_fetch_4(&pSRWLock->c, 1);
    return FALSE;
}

VOID AcquireSRWLockExclusive(_Inout_ PSRWLOCK pSRWLock)
{
    DWORD dwZero;
    __sync_fetch_and_add_4(&pSRWLock->c, 1);
    while(TRUE) {
        dwZero = 0;
        if(atomic_compare_exchange_strong((atomic_uint *)&pSRWLock->xchg, &dwZero, 1)) {
            return;
        }
        futex(&pSRWLock->xchg, FUTEX_WAIT, 1, NULL, NULL, 0);
    }
}

_Success_(return)
BOOL AcquireSRWLockExclusive_Timeout(_Inout_ PSRWLOCK pSRWLock, _In_ DWORD dwMilliseconds)
{
    DWORD dwZero;
    struct timespec ts;
    __sync_fetch_and_add_4(&pSRWLock->c, 1);
    while(TRUE) {
        dwZero = 0;
        if(atomic_compare_exchange_strong((atomic_uint *)&pSRWLock->xchg, &dwZero, 1)) {
            return TRUE;
        }
        if((dwMilliseconds != 0) && (dwMilliseconds != 0xffffffff)) {
            ts.tv_sec = dwMilliseconds / 1000;
            ts.tv_nsec = (dwMilliseconds % 1000) * 1000 * 1000;
            if((-1 == futex(&pSRWLock->xchg, FUTEX_WAIT, 1, &ts, NULL, 0)) && (errno != EAGAIN)) {
                __sync_sub_and_fetch_4(&pSRWLock->c, 1);
                return FALSE;
            }
        } else {
            if((-1 == futex(&pSRWLock->xchg, FUTEX_WAIT, 1, NULL, NULL, 0)) && (errno != EAGAIN)) {
                __sync_sub_and_fetch_4(&pSRWLock->c, 1);
                return FALSE;
            }
        }
    }
}

VOID ReleaseSRWLockExclusive(_Inout_ PSRWLOCK pSRWLock)
{
    DWORD dwOne = 1;
    if(atomic_compare_exchange_strong((atomic_uint *)&pSRWLock->xchg, &dwOne, 0)) {
        if(__sync_sub_and_fetch_4(&pSRWLock->c, 1)) {
            futex(&pSRWLock->xchg, FUTEX_WAKE, 1, NULL, NULL, 0);
        }
    }
}

#endif /* LINUX */

#ifdef MACOS

VOID InitializeSRWLock(PSRWLOCK pSRWLock)
{
    if(!pSRWLock->valid) {
        pSRWLock->sem = dispatch_semaphore_create(1);
    }
}

BOOL AcquireSRWLockExclusive_Try(_Inout_ PSRWLOCK pSRWLock)
{
    if(!pSRWLock->valid) { InitializeSRWLock(pSRWLock); }
    return (0 == dispatch_semaphore_wait(pSRWLock->sem, DISPATCH_TIME_NOW));
}

VOID AcquireSRWLockExclusive(_Inout_ PSRWLOCK pSRWLock)
{
    if(!pSRWLock->valid) { InitializeSRWLock(pSRWLock); }
    dispatch_semaphore_wait(pSRWLock->sem, DISPATCH_TIME_FOREVER);
}

_Success_(return)
BOOL AcquireSRWLockExclusive_Timeout(_Inout_ PSRWLOCK pSRWLock, _In_ DWORD dwMilliseconds)
{
    if(!pSRWLock->valid) { InitializeSRWLock(pSRWLock); }
    dispatch_time_t timeout = dispatch_time(DISPATCH_TIME_NOW, dwMilliseconds * NSEC_PER_MSEC);
    return (0 == dispatch_semaphore_wait(pSRWLock->sem, timeout));
}

VOID ReleaseSRWLockExclusive(_Inout_ PSRWLOCK pSRWLock)
{
    if(pSRWLock->valid) {
        dispatch_semaphore_signal(pSRWLock->sem);
    }
}

#endif /* MACOS */
