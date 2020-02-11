// m_threadinfo.c : implementation of the thread info built-in module.
//
// (c) Ulf Frisk, 2019-2020
// Author: Ulf Frisk, pcileech@frizk.net
//
#include "pluginmanager.h"
#include "util.h"
#include "vmm.h"
#include "vmmdll.h"

#define THREADINFO_LINELENGTH       186ULL
#define THREADINFO_INFOFILE_LENGTH  582ULL

_Success_(return == 0)
NTSTATUS ThreadInfo_Read_ThreadInfo(_In_ PVMM_MAP_THREADENTRY pThreadEntry, _Out_ PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset)
{
    DWORD o;
    CHAR sz[THREADINFO_INFOFILE_LENGTH + 1];
    CHAR szTimeCreate[32] = { 0 }, szTimeExit[32] = { 0 };
    Util_FileTime2String((PFILETIME)&pThreadEntry->ftCreateTime, szTimeCreate);
    Util_FileTime2String((PFILETIME)&pThreadEntry->ftExitTime, szTimeExit);
    o = snprintf(
        sz,
        THREADINFO_INFOFILE_LENGTH + 1,
        "PID:          %21i\n" \
        "TID:          %21i\n" \
        "ExitStatus:   %21x\n" \
        "State:        %21x\n" \
        "Running:      %21x\n" \
        "Priority:     %21x\n" \
        "BasePriority: %21x\n" \
        "ETHREAD:      %21llx\n" \
        "TEB:          %21llx\n" \
        "StartAddress:      %16llx\n" \
        "UserStackBase:     %16llx\n" \
        "UserStackLimit:    %16llx\n" \
        "KernelStackBase:   %16llx\n" \
        "KernelStackLimit:  %16llx\n" \
        "CreateTime: %-26s\n" \
        "ExitTime:   %-26s\n",
        pThreadEntry->dwPID,
        pThreadEntry->dwTID,
        pThreadEntry->dwExitStatus,
        pThreadEntry->bState,
        pThreadEntry->bRunning,
        pThreadEntry->bPriority,
        pThreadEntry->bBasePriority,
        pThreadEntry->vaETHREAD,
        pThreadEntry->vaTeb,
        pThreadEntry->vaStartAddress,
        pThreadEntry->vaStackBaseUser,
        pThreadEntry->vaStackLimitUser,
        pThreadEntry->vaStackBaseKernel,
        pThreadEntry->vaStackLimitKernel,
        szTimeCreate,
        szTimeExit
    );
    return Util_VfsReadFile_FromPBYTE(sz, THREADINFO_INFOFILE_LENGTH, pb, cb, pcbRead, cbOffset);
}

_Success_(return == 0)
NTSTATUS ThreadInfo_Read_ThreadMap(_In_ PVMMOB_MAP_THREAD pThreadMap, _Out_ PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset)
{
    NTSTATUS nt;
    LPSTR sz;
    QWORD i, o = 0, cbMax, cStart, cEnd, cbLINELENGTH;
    PVMM_MAP_THREADENTRY pT;
    CHAR szTimeCreate[MAX_PATH] = { 0 }, szTimeExit[MAX_PATH] = { 0 };
    cbLINELENGTH = THREADINFO_LINELENGTH;
    cStart = (DWORD)(cbOffset / cbLINELENGTH);
    cEnd = (DWORD)min(pThreadMap->cMap - 1, (cb + cbOffset + cbLINELENGTH - 1) / cbLINELENGTH);
    cbMax = 1 + (1 + cEnd - cStart) * cbLINELENGTH;
    if(!pThreadMap->cMap || (cStart > pThreadMap->cMap)) { return VMMDLL_STATUS_END_OF_FILE; }
    if(!(sz = LocalAlloc(LMEM_ZEROINIT, cbMax))) { return VMMDLL_STATUS_FILE_INVALID; }
    for(i = cStart; i <= cEnd; i++) {
        pT = pThreadMap->pMap + i;
        Util_FileTime2String((PFILETIME)&pT->ftCreateTime, szTimeCreate);
        Util_FileTime2String((PFILETIME)&pT->ftExitTime, szTimeExit);
        o += snprintf(
            sz + o,
            cbMax - o,
            "%04x%7i%8i %16llx %2x %2x %2x %2x %8x %16llx -- %16llx : %16llx > %16llx [%s :: %s]\n",
            (DWORD)i,
            pT->dwPID,
            pT->dwTID,
            pT->vaETHREAD,
            pT->bState,
            pT->bRunning,
            pT->bBasePriority,
            pT->bPriority,
            pT->dwExitStatus,
            pT->vaStartAddress,
            pT->vaTeb,
            pT->vaStackBaseUser,
            pT->vaStackLimitUser,
            szTimeCreate,
            szTimeExit
        );
    }
    nt = Util_VfsReadFile_FromPBYTE(sz, cbMax - 1, pb, cb, pcbRead, cbOffset - cStart * cbLINELENGTH);
    LocalFree(sz);
    return nt;
}

/*
* Read : function as specified by the module manager. The module manager will
* call into this callback function whenever a read shall occur from a "file".
* -- ctx
* -- pb
* -- cb
* -- pcbRead
* -- cbOffset
* -- return
*/
_Success_(return == 0)
NTSTATUS ThreadInfo_Read(_In_ PVMMDLL_PLUGIN_CONTEXT ctx, _Out_ PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset)
{
    NTSTATUS nt = VMMDLL_STATUS_FILE_INVALID;
    PVMMOB_MAP_THREAD pObThreadMap = NULL;
    PVMM_PROCESS pObSystemProcess = NULL;
    WCHAR wszThreadName[16 + 1];
    LPWSTR wszSubPath;
    DWORD dwTID;
    PVMM_MAP_THREADENTRY pe;
    if(!VmmMap_GetThread(ctx->pProcess, &pObThreadMap)) { return VMMDLL_STATUS_FILE_INVALID; }
    // module root - thread info file
    if(!_wcsicmp(ctx->wszPath, L"threads.txt")) {
        nt = ThreadInfo_Read_ThreadMap(pObThreadMap, pb, cb, pcbRead, cbOffset);
        goto finish;
    }
    // individual thread file
    wszSubPath = Util_PathSplit2_ExWCHAR(ctx->wszPath, wszThreadName, _countof(wszThreadName));
    if(wszSubPath && (dwTID = (DWORD)Util_GetNumericW(ctx->wszPath)) && (pe = VmmMap_GetThreadEntry(pObThreadMap, dwTID))) {
        if(!_wcsicmp(wszSubPath, L"info.txt")) {
            nt = ThreadInfo_Read_ThreadInfo(pe, pb, cb, pcbRead, cbOffset);
            goto finish;
        }
        // individual thread files backed by user-mode memory below:
        if(!_wcsicmp(wszSubPath, L"teb")) {
            nt = VmmReadAsFile((PVMM_PROCESS)ctx->pProcess, pe->vaTeb, 0x1000, pb, cb, pcbRead, cbOffset);
            goto finish;
        }
        if(!_wcsicmp(wszSubPath, L"stack")) {
            nt = VmmReadAsFile((PVMM_PROCESS)ctx->pProcess, pe->vaStackLimitUser, pe->vaStackBaseUser - pe->vaStackLimitUser, pb, cb, pcbRead, cbOffset);
            goto finish;
        }
        // individual thread files backed by kernel memory below:
        if(!(pObSystemProcess = VmmProcessGet(4))) { goto finish; }
        if(!_wcsicmp(wszSubPath, L"ethread")) {
            nt = VmmReadAsFile(pObSystemProcess, pe->vaETHREAD, ctxVmm->offset.ETHREAD.oMax, pb, cb, pcbRead, cbOffset);
            goto finish;
        }
        if(!_wcsicmp(wszSubPath, L"kstack")) {
            nt = VmmReadAsFile(pObSystemProcess, pe->vaStackLimitKernel, pe->vaStackBaseKernel - pe->vaStackLimitKernel, pb, cb, pcbRead, cbOffset);
            goto finish;
        }
    }
finish:
    Ob_DECREF(pObSystemProcess);
    Ob_DECREF(pObThreadMap);
    return nt;
}

/*
* Write : function as specified by the module manager. The module manager will
* call into this callback function whenever a write shall occur from a "file".
* -- ctx
* -- pb
* -- cb
* -- pcbWrite
* -- cbOffset
* -- return
*/
NTSTATUS ThreadInfo_Write(_In_ PVMMDLL_PLUGIN_CONTEXT ctx, _In_ PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbWrite, _In_ QWORD cbOffset)
{
    NTSTATUS nt = VMMDLL_STATUS_FILE_INVALID;
    PVMMOB_MAP_THREAD pObThreadMap = NULL;
    PVMM_PROCESS pObSystemProcess = NULL;
    WCHAR wszThreadName[16 + 1];
    LPWSTR wszSubPath;
    DWORD dwTID;
    PVMM_MAP_THREADENTRY pe;
    if(!VmmMap_GetThread(ctx->pProcess, &pObThreadMap)) { return VMMDLL_STATUS_FILE_INVALID; }
    // individual thread file
    wszSubPath = Util_PathSplit2_ExWCHAR(ctx->wszPath, wszThreadName, _countof(wszThreadName));
    if(wszSubPath && (dwTID = (DWORD)Util_GetNumericW(ctx->wszPath)) && (pe = VmmMap_GetThreadEntry(pObThreadMap, dwTID))) {
        // individual thread files backed by user-mode memory below:
        if(!_wcsicmp(wszSubPath, L"teb")) {
            nt = VmmWriteAsFile((PVMM_PROCESS)ctx->pProcess, pe->vaTeb, 0x1000, pb, cb, pcbWrite, cbOffset);
            goto finish;
        }
        if(!_wcsicmp(wszSubPath, L"stack")) {
            nt = VmmWriteAsFile((PVMM_PROCESS)ctx->pProcess, pe->vaStackLimitUser, pe->vaStackBaseUser - pe->vaStackLimitUser, pb, cb, pcbWrite, cbOffset);
            goto finish;
        }
        // individual thread files backed by kernel memory below:
        if(!(pObSystemProcess = VmmProcessGet(4))) { goto finish; }
        if(!_wcsicmp(wszSubPath, L"ethread")) {
            nt = VmmWriteAsFile(pObSystemProcess, pe->vaETHREAD, ctxVmm->offset.ETHREAD.oMax, pb, cb, pcbWrite, cbOffset);
            goto finish;
        }
        if(!_wcsicmp(wszSubPath, L"kstack")) {
            nt = VmmWriteAsFile(pObSystemProcess, pe->vaStackLimitKernel, pe->vaStackBaseKernel - pe->vaStackLimitKernel, pb, cb, pcbWrite, cbOffset);
            goto finish;
        }
    }
finish:
    Ob_DECREF(pObSystemProcess);
    Ob_DECREF(pObThreadMap);
    return nt;
}

/*
* Set file timestamp into the ExInfo struct.
* -- pThreadEntry
* -- pExInfo
*/
VOID ThreadInfo_List_TimeStampFile(_In_ PVMM_MAP_THREADENTRY pThreadEntry, _Out_ PVMMDLL_VFS_FILELIST_EXINFO pExInfo)
{
    pExInfo->dwVersion = VMMDLL_VFS_FILELIST_EXINFO_VERSION;
    pExInfo->qwCreationTime = pThreadEntry->ftCreateTime;
    pExInfo->qwLastWriteTime = pThreadEntry->ftExitTime;
    if(!pExInfo->qwLastWriteTime) {
        pExInfo->qwLastWriteTime = pExInfo->qwCreationTime;
    }
}

/*
* List : function as specified by the module manager. The module manager will
* call into this callback function whenever a list directory shall occur from
* the given module.
* -- ctx
* -- pFileList
* -- return
*/
BOOL ThreadInfo_List(_In_ PVMMDLL_PLUGIN_CONTEXT ctx, _Inout_ PHANDLE pFileList)
{
    DWORD i, dwTID, cbStack;
    WCHAR wszBuffer[32] = { 0 };
    PVMMOB_MAP_THREAD pObThreadMap = NULL;
    PVMM_MAP_THREADENTRY pe;
    VMMDLL_VFS_FILELIST_EXINFO ExInfo = { 0 };
    if(!VmmMap_GetThread(ctx->pProcess, &pObThreadMap)) { goto fail; }
    // module root - list thread map
    if(!ctx->wszPath[0]) {
        for(i = 0; i < pObThreadMap->cMap; i++) {
            pe = pObThreadMap->pMap + i;
            ThreadInfo_List_TimeStampFile(pe, &ExInfo);
            _snwprintf_s(wszBuffer, _countof(wszBuffer), 32, L"%i", pe->dwTID);
            VMMDLL_VfsList_AddDirectory(pFileList, wszBuffer, &ExInfo);
        }
        VMMDLL_VfsList_AddFile(pFileList, L"threads.txt", pObThreadMap->cMap * THREADINFO_LINELENGTH, NULL);
        Ob_DECREF_NULL(&pObThreadMap);
        return TRUE;
    }
    // specific thread
    if(!(dwTID = (DWORD)Util_GetNumericW(ctx->wszPath))) { goto fail; }
    if(!(pe = VmmMap_GetThreadEntry(pObThreadMap, dwTID))) { goto fail; }
    ThreadInfo_List_TimeStampFile(pe, &ExInfo);
    VMMDLL_VfsList_AddFile(pFileList, L"info.txt", THREADINFO_INFOFILE_LENGTH, &ExInfo);
    VMMDLL_VfsList_AddFile(pFileList, L"ethread", ctxVmm->offset.ETHREAD.oMax, &ExInfo);
    if(pe->vaTeb) {
        VMMDLL_VfsList_AddFile(pFileList, L"teb", 0x1000, &ExInfo);
    }
    if(pe->vaStackBaseUser && pe->vaStackLimitUser && (pe->vaStackLimitUser < pe->vaStackBaseUser)) {
        cbStack = (DWORD)(pe->vaStackBaseUser - pe->vaStackLimitUser);
        VMMDLL_VfsList_AddFile(pFileList, L"stack", cbStack, &ExInfo);
    }
    if(pe->vaStackBaseKernel && pe->vaStackLimitKernel && (pe->vaStackLimitKernel < pe->vaStackBaseKernel)) {
        cbStack = (DWORD)(pe->vaStackBaseKernel - pe->vaStackLimitKernel);
        VMMDLL_VfsList_AddFile(pFileList, L"kstack", cbStack, &ExInfo);
    }
fail:
    Ob_DECREF_NULL(&pObThreadMap);
    return TRUE;
}

/*
* Initialization function. The module manager shall call into this function
* when the module shall be initialized. If the module wish to initialize it
* shall call the supplied pfnPluginManager_Register function.
* NB! the module does not have to register itself - for example if the target
* operating system or architecture is unsupported.
* -- pPluginRegInfo
*/
VOID M_ThreadInfo_Initialize(_Inout_ PVMMDLL_PLUGIN_REGINFO pRI)
{
    if((pRI->magic != VMMDLL_PLUGIN_REGINFO_MAGIC) || (pRI->wVersion != VMMDLL_PLUGIN_REGINFO_VERSION)) { return; }
    if(!((pRI->tpSystem == VMM_SYSTEM_WINDOWS_X64) || (pRI->tpSystem == VMM_SYSTEM_WINDOWS_X86))) { return; }
    wcscpy_s(pRI->reg_info.wszPathName, 128, L"\\threads");             // module name
    pRI->reg_info.fRootModule = FALSE;                                  // module shows in root directory
    pRI->reg_info.fProcessModule = TRUE;                                // module shows in process directory
    pRI->reg_fn.pfnList = ThreadInfo_List;                              // List function supported
    pRI->reg_fn.pfnRead = ThreadInfo_Read;                              // Read function supported
    pRI->reg_fn.pfnWrite = ThreadInfo_Write;                            // Write function supported
    pRI->pfnPluginManager_Register(pRI);
}
