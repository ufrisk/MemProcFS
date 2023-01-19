// oscompatibility.c : VMM Windows/Linux compatibility layer.
//
// (c) Ulf Frisk, 2021-2023
// Author: Ulf Frisk, pcileech@frizk.net
//
#ifdef LINUX
#include "oscompatibility.h"
#include <stdatomic.h>
#include <sys/syscall.h>
#include <linux/futex.h>

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
// SRWLock functionality below:
// ----------------------------------------------------------------------------

static int futex(uint32_t *uaddr, int futex_op, uint32_t val, const struct timespec *timeout, uint32_t *uaddr2, uint32_t val3)
{
    return syscall(SYS_futex, uaddr, futex_op, val, timeout, uaddr2, val3);
}

VOID InitializeSRWLock(PSRWLOCK SRWLock)
{
    ZeroMemory(SRWLock, sizeof(SRWLOCK));
}

BOOL AcquireSRWLockExclusive_Try(_Inout_ PSRWLOCK SRWLock)
{
    DWORD dwZero = 0;
    __sync_fetch_and_add_4(&SRWLock->c, 1);
    if(atomic_compare_exchange_strong(&SRWLock->xchg, &dwZero, 1)) {
        return TRUE;
    }
    __sync_sub_and_fetch_4(&SRWLock->c, 1);
    return FALSE;
}

VOID AcquireSRWLockExclusive(_Inout_ PSRWLOCK SRWLock)
{
    DWORD dwZero;
    __sync_fetch_and_add_4(&SRWLock->c, 1);
    while(TRUE) {
        dwZero = 0;
        if(atomic_compare_exchange_strong(&SRWLock->xchg, &dwZero, 1)) {
            return;
        }
        futex(&SRWLock->xchg, FUTEX_WAIT, 1, NULL, NULL, 0);
    }
}

_Success_(return)
BOOL AcquireSRWLockExclusive_Timeout(_Inout_ PSRWLOCK SRWLock, _In_ DWORD dwMilliseconds)
{
    DWORD dwZero;
    struct timespec ts;
    __sync_fetch_and_add_4(&SRWLock->c, 1);
    while(TRUE) {
        dwZero = 0;
        if(atomic_compare_exchange_strong(&SRWLock->xchg, &dwZero, 1)) {
            return TRUE;
        }
        if((dwMilliseconds != 0) && (dwMilliseconds != 0xffffffff)) {
            ts.tv_sec = dwMilliseconds / 1000;
            ts.tv_nsec = (dwMilliseconds % 1000) * 1000 * 1000;
            if((-1 == futex(&SRWLock->xchg, FUTEX_WAIT, 1, &ts, NULL, 0)) && (errno != EAGAIN)) {
                __sync_sub_and_fetch_4(&SRWLock->c, 1);
                return FALSE;
            }
        } else {
            if((-1 == futex(&SRWLock->xchg, FUTEX_WAIT, 1, NULL, NULL, 0)) && (errno != EAGAIN)) {
                __sync_sub_and_fetch_4(&SRWLock->c, 1);
                return FALSE;
            }
        }
    }
}

VOID ReleaseSRWLockExclusive(_Inout_ PSRWLOCK SRWLock)
{
    DWORD dwOne = 1;
    if(atomic_compare_exchange_strong(&SRWLock->xchg, &dwOne, 0)) {
        if(__sync_sub_and_fetch_4(&SRWLock->c, 1)) {
            futex(&SRWLock->xchg, FUTEX_WAKE, 1, NULL, NULL, 0);
        }
    }
}



// ----------------------------------------------------------------------------
// GENERAL STUFF BELOW:
// ----------------------------------------------------------------------------

QWORD GetTickCount64()
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC_COARSE, &ts);
    return ts.tv_sec * 1000 + ts.tv_nsec / (1000 * 1000);
}

#endif /* LINUX */