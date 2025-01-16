// vmmdll_remote.c : implementation of remote library functionality:
//     proxying calls to a remote VMMDLL instance hosted by a LeechAgent.
//
// (c) Ulf Frisk, 2023-2025
// Author: Ulf Frisk, pcileech@frizk.net
//

#include "vmmdll_remote.h"
#include "charutil.h"

#define VMMDLL_REMOTE_MAGIC                             0xf3dc0fefea1e6666
#define VMMDLL_VFS_INITIALIZEBLOB_VERSION               0xfaaf0001
#define VMMDLL_VFS_INITIALIZEBLOB_MAX_ARGC              64
#define VMMDLL_VFS_CONSOLE_RSP_VERSION                  0xf00f0001

typedef struct tdVMMDLL_VFS_CONSOLE_RSP {
    // core:
    DWORD dwVersion;                        // VMMDLL_VFS_KEEPALIVE_RSP_VERSION
    DWORD cbStruct;
    // stdout/stderr:
    union { LPSTR szStdOut; QWORD qwStdOut; };
    union { LPSTR szStdErr; QWORD qwStdErr; };
    BYTE pbBuffer[0];
} VMMDLL_VFS_CONSOLE_RSP, *PVMMDLL_VFS_CONSOLE_RSP;

typedef struct tdVMMDLL_REMOTE_HANDLE {
    // core:
    QWORD magic;
    BOOL fAbort;
    DWORD dwHandleCount;
    DWORD cThreadExternal;
    DWORD cThreadInternal;
    // options:
    BOOL fVerboseDll;
    BOOL fVerbose;
    BOOL fVerboseExtra;
    BOOL fVerboseExtraTlp;
    BOOL fUserInteract;
    // leechcore & config
    HANDLE hLC;
    LC_CONFIG dev;
} *VMMDLL_REMOTE_HANDLE;

/*
* Remote initialization struct (shared between vmmdll_remote.c and leechagent_procchild.c).
*/
typedef struct tdVMMDLL_VFS_INITIALIZEBLOB {
    DWORD dwVersion;                        // VMMDLL_VFS_INITIALIZEBLOB_VERSION
    DWORD cbStruct;
    QWORD _FutureUse1[16];
    DWORD _FutureUse2;
    DWORD argc;
    union {
        LPSTR sz;
        QWORD qw;
    } argv[0];
} VMMDLL_VFS_INITIALIZEBLOB, *PVMMDLL_VFS_INITIALIZEBLOB;

/*
* printf a message to the console if allowed (i.e. not suppressed in a dll context).
* NB! VmmLog* functions are preferred if possible!
*/
#define VmmDllRemote_printf(HR, format, ...)          { if(HR->fVerboseDll)       { printf(format, ##__VA_ARGS__); } }

//-----------------------------------------------------------------------------
// INITIALIZATION AND CLOSE FUNCTIONALITY BELOW:
// 
// Initialize and Close functionality is put behind a single shared global lock.
// This functionality is similar to functionality in vmmdll_core.c.
//-----------------------------------------------------------------------------

// globals below:
#define VMMDLL_REMOTE_HANDLE_MAX_COUNT          64
static BOOL g_VMMDLL_REMOTE_INITIALIZED         = FALSE;
static CRITICAL_SECTION g_VMMDLL_REMOTE_LOCK    = { 0 };
static DWORD g_VMMDLL_REMOTE_HANDLE_COUNT       = 0;
static VMMDLL_REMOTE_HANDLE g_VMMDLL_REMOTE_HANDLES[VMMDLL_REMOTE_HANDLE_MAX_COUNT] = { 0 };

VOID VmmDllRemote_CloseHandle(_In_opt_ _Post_ptr_invalid_ VMM_HANDLE H, _In_ BOOL fForceCloseAll);

/*
* Initialize the global variables g_VMMDLL_REMOTE_*.
* This function should only be called from DllMain.
* NB! it's ok to leak the initialized globals since the leak will be minor only.
*/
VOID VmmDllRemote_InitializeGlobals()
{
    if(!g_VMMDLL_REMOTE_INITIALIZED) {
        g_VMMDLL_REMOTE_INITIALIZED = TRUE;
        InitializeCriticalSection(&g_VMMDLL_REMOTE_LOCK);
    }
}

/*
* Verify that the supplied handle is valid and also check it out.
* This must be called by each external access which requires a VMM_HANDLE.
* Each successful VmmDllRemote_HandleReserveExternal() call must be matched by
* a matched call to VmmDllRemote_HandleReturnExternal() after completion.
* -- H
* -- return
*/
_Success_(return != NULL)
VMMDLL_REMOTE_HANDLE VmmDllRemote_HandleReserveExternal(_In_opt_ VMM_HANDLE H)
{
    DWORD i = 0;
    VMMDLL_REMOTE_HANDLE HR = (VMMDLL_REMOTE_HANDLE)((SIZE_T)H & ~1);
    if(!H || ((SIZE_T)H < 0x10000)) { return NULL; }
    EnterCriticalSection(&g_VMMDLL_REMOTE_LOCK);
    for(i = 0; i < g_VMMDLL_REMOTE_HANDLE_COUNT; i++) {
        if(g_VMMDLL_REMOTE_HANDLES[i] == HR) {
            if((HR->magic == VMMDLL_REMOTE_MAGIC) && !HR->fAbort) {
                InterlockedIncrement(&HR->cThreadExternal);
                LeaveCriticalSection(&g_VMMDLL_REMOTE_LOCK);
                return HR;
            }
        }
    }
    LeaveCriticalSection(&g_VMMDLL_REMOTE_LOCK);
    return NULL;
}

/*
* Return a handle successfully reserved with a previous call to the function:
* VmmDllRemote_HandleReserveExternal()
* -- H
*/
VOID VmmDllRemote_HandleReturnExternal(_In_opt_ VMMDLL_REMOTE_HANDLE HR)
{
    if(HR) {
        InterlockedDecrement(&HR->cThreadExternal);
    }
}

/*
* Remove a handle from the external handle array.
* NB! Function is to be called behind exclusive lock g_VMMDLL_REMOTE_LOCK.
* -- H
*/
VOID VmmDllRemote_HandleRemove(_In_ VMMDLL_REMOTE_HANDLE HR)
{
    DWORD i;
    if(HR && (HR->magic == VMMDLL_REMOTE_MAGIC)) {
        for(i = 0; i < g_VMMDLL_REMOTE_HANDLE_COUNT; i++) {
            if(g_VMMDLL_REMOTE_HANDLES[i] == HR) {
                g_VMMDLL_REMOTE_HANDLE_COUNT--;
                if(i < g_VMMDLL_REMOTE_HANDLE_COUNT) {
                    g_VMMDLL_REMOTE_HANDLES[i] = g_VMMDLL_REMOTE_HANDLES[g_VMMDLL_REMOTE_HANDLE_COUNT];
                    g_VMMDLL_REMOTE_HANDLES[g_VMMDLL_REMOTE_HANDLE_COUNT] = NULL;
                } else {
                    g_VMMDLL_REMOTE_HANDLES[i] = NULL;
                }
                break;
            }
        }
    }
}

/*
* Add a new handle to the external handle array.
* NB! Function is to be called behind exclusive lock g_VMMDLL_CORE_LOCK.
* -- H
*/
_Success_(return)
BOOL VmmDllRemote_HandleAdd(_In_ VMMDLL_REMOTE_HANDLE HR)
{
    if(g_VMMDLL_REMOTE_HANDLE_COUNT < VMMDLL_REMOTE_HANDLE_MAX_COUNT) {
        g_VMMDLL_REMOTE_HANDLES[g_VMMDLL_REMOTE_HANDLE_COUNT] = HR;
        g_VMMDLL_REMOTE_HANDLE_COUNT++;
        return TRUE;
    }
    return FALSE;
}

/*
* Close a VMM_HANDLE / VMM_REMOTE_HANDLE and clean up everything!
* The VMM_HANDLE / VMM_REMOTE_HANDLE will not be valid after this function has
* been called. Function call may take some time since it's relying on backend
* calls to finish.
* The strategy is:
*   (1) disable external calls (set magic and abort flag)
*   (2) wait for worker threads to exit (done on abort) when completed no
*       threads except this one should access the handle.
* -- H = a VMMDLL_REMOTE_HANDLE fully or partially initialized
* -- fForceCloseAll = TRUE: disregard handle count. FALSE: adhere to handle count.
*/
VOID VmmDllRemote_CloseHandle(_In_opt_ _Post_ptr_invalid_ VMM_HANDLE H, _In_ BOOL fForceCloseAll)
{
    BOOL fCloseHandle = FALSE;
    VMMDLL_REMOTE_HANDLE HR = NULL;
    // Verify & decrement handle count.
    // If handle count > 0 (after decrement) return.
    // If handle count == 0 -> close and clean-up.
    // (this is done with help of HandleReserveExternal//HandleReturnExternal logic).
    if(!H) { return; }
    EnterCriticalSection(&g_VMMDLL_REMOTE_LOCK);
    if(!(HR = VmmDllRemote_HandleReserveExternal(H))) {
        LeaveCriticalSection(&g_VMMDLL_REMOTE_LOCK);
        return;
    }
    InterlockedDecrement(&HR->dwHandleCount);
    if(fForceCloseAll || (0 == HR->dwHandleCount)) {
        fCloseHandle = TRUE;
        HR->dwHandleCount = 0;
        // Remove handle from external allow-list.
        // This will stop external API calls using the handle.
        // This will also stop additional close calls using the handle.
        VmmDllRemote_HandleRemove(HR);
    }
    VmmDllRemote_HandleReturnExternal(HR);
    LeaveCriticalSection(&g_VMMDLL_REMOTE_LOCK);
    // Return if handle should not be closed - i.e. if handle count is > 0.
    if(!fCloseHandle) { return; }
    // Set the abort flag. This will cause internal threading shutdown.
    HR->fAbort = TRUE;
    HR->magic = 0;
    // Wait for multi-threading to shut down.
    while(HR->cThreadExternal) {
        SwitchToThread();
    }
    while(HR->cThreadInternal) {
        SwitchToThread();
    }
    // Close leechcore
    LcClose(HR->hLC);
    LocalFree(HR);
}

/*
* Close all remote VMM_REMOTE_HANDLE and clean up everything!
* No remote VMM_REMOTE_HANDLE will be valid after this function has been called.
*/
VOID VmmDllRemote_CloseAll()
{
    VMMDLL_REMOTE_HANDLE HR;
    while(TRUE) {
        EnterCriticalSection(&g_VMMDLL_REMOTE_LOCK);
        HR = g_VMMDLL_REMOTE_HANDLES[0];
        LeaveCriticalSection(&g_VMMDLL_REMOTE_LOCK);
        if(!HR) { return; }
        VmmDllRemote_CloseHandle((VMM_HANDLE)HR, TRUE);
    }
}

/*
* Close a remote VMM_HANDLE and clean up everything!
* The remote VMM_HANDLE will not be valid after this function has been called.
* -- H
*/
VOID VmmDllRemote_Close(_In_opt_ _Post_ptr_invalid_ VMM_HANDLE H)
{
    VmmDllRemote_CloseHandle(H, FALSE);
}

/*
* Remote VMMDLL_ConfigGet().
*/
_Success_(return)
BOOL VmmDllRemote_ConfigGet(_In_ VMM_HANDLE H, _In_ ULONG64 fOption, _Out_ PULONG64 pqwValue)
{
    BOOL fResult;
    LC_CMD_AGENT_VFS_REQ Req = { 0 };
    PLC_CMD_AGENT_VFS_RSP pRsp = NULL;
    VMMDLL_REMOTE_HANDLE HR = NULL;
    DWORD cbRsp;
    *pqwValue = 0;
    if(!(HR = VmmDllRemote_HandleReserveExternal(H))) { return FALSE; }
    // Remote MemProcFS below:
    Req.dwVersion = LC_CMD_AGENT_VFS_REQ_VERSION;
    Req.fOption = fOption;
    fResult = LcCommand(HR->hLC, LC_CMD_AGENT_VFS_OPT_GET, sizeof(LC_CMD_AGENT_VFS_REQ), (PBYTE)&Req, (PBYTE*)&pRsp, &cbRsp);
    fResult = fResult && (cbRsp >= sizeof(LC_CMD_AGENT_VFS_RSP)) && (pRsp->dwVersion == LC_CMD_AGENT_VFS_RSP_VERSION);
    if(fResult) {
        if((fResult = (pRsp->cb == sizeof(QWORD)))) {
            *pqwValue = *(PQWORD)pRsp->pb;
        }
        LocalFree(pRsp);
    }
    VmmDllRemote_HandleReturnExternal(HR);
    return fResult;
}

/*
* Remote VMMDLL_ConfigSet().
*/
_Success_(return)
BOOL VmmDllRemote_ConfigSet(_In_ VMM_HANDLE H, _In_ ULONG64 fOption, _In_ ULONG64 qwValue)
{
    BOOL fResult = FALSE;
    PLC_CMD_AGENT_VFS_REQ pReq = NULL;
    VMMDLL_REMOTE_HANDLE HR = NULL;
    if(!(HR = VmmDllRemote_HandleReserveExternal(H))) { return FALSE; }
    // Remote MemProcFS below:
    if(!(pReq = LocalAlloc(LMEM_ZEROINIT, sizeof(LC_CMD_AGENT_VFS_REQ) + sizeof(QWORD)))) { goto fail; }
    pReq->dwVersion = LC_CMD_AGENT_VFS_REQ_VERSION;
    pReq->fOption = fOption;
    pReq->cb = sizeof(QWORD);
    *(PQWORD)pReq->pb = 1ULL;
    fResult = LcCommand(HR->hLC, LC_CMD_AGENT_VFS_OPT_SET, sizeof(LC_CMD_AGENT_VFS_REQ) + sizeof(QWORD), (PBYTE)pReq, NULL, NULL);
fail:
    VmmDllRemote_HandleReturnExternal(HR);
    LocalFree(pReq);
    return fResult;
}

/*
* Remote VMMDLL_VfsListU().
*/
_Success_(return)
BOOL VmmDllRemote_VfsListU(_In_ VMM_HANDLE H, _In_ LPCSTR uszPath, _Inout_ PVMMDLL_VFS_FILELIST2 pFileList)
{
    DWORD i;
    LC_CMD_AGENT_VFS_REQ Req;
    PLC_CMD_AGENT_VFS_RSP pRsp = NULL;
    PVMMDLL_VFS_FILELISTBLOB pVfsList;
    PVMMDLL_VFS_FILELISTBLOB_ENTRY pe;
    VMMDLL_REMOTE_HANDLE HR = NULL;
    DWORD cbRsp;
    if(!(HR = VmmDllRemote_HandleReserveExternal(H))) { return FALSE; }
    // Remote MemProcFS below:
    ZeroMemory(&Req, sizeof(LC_CMD_AGENT_VFS_REQ));
    Req.dwVersion = LC_CMD_AGENT_VFS_REQ_VERSION;
    if(!CharUtil_UtoU(uszPath, -1, Req.uszPathFile, sizeof(Req.uszPathFile), NULL, NULL, CHARUTIL_FLAG_STR_BUFONLY)) { goto fail; }
    if(!LcCommand(HR->hLC, LC_CMD_AGENT_VFS_LIST, sizeof(LC_CMD_AGENT_VFS_REQ), (PBYTE)&Req, (PBYTE*)&pRsp, &cbRsp) || !pRsp) { goto fail; }
    if((cbRsp < sizeof(LC_CMD_AGENT_VFS_RSP)) || (pRsp->dwVersion != LC_CMD_AGENT_VFS_RSP_VERSION) || (cbRsp < sizeof(LC_CMD_AGENT_VFS_RSP) + pRsp->cb)) { goto fail; }
    pVfsList = (PVMMDLL_VFS_FILELISTBLOB)pRsp->pb;      // sanity/security checks on remote data are performed in leechcore
    pVfsList->uszMultiText = (LPSTR)pVfsList + (QWORD)pVfsList->uszMultiText;
    for(i = 0; i < pVfsList->cFileEntry; i++) {
        pe = pVfsList->FileEntry + i;
        if(pe->cbFileSize == (QWORD)-1) {
            pFileList->pfnAddDirectory(pFileList->h, pVfsList->uszMultiText + pe->ouszName, (PVMMDLL_VFS_FILELIST_EXINFO)&pe->ExInfo);
        } else {
            pFileList->pfnAddFile(pFileList->h, pVfsList->uszMultiText + pe->ouszName, pe->cbFileSize, (PVMMDLL_VFS_FILELIST_EXINFO)&pe->ExInfo);
        }
    }
fail:
    VmmDllRemote_HandleReturnExternal(HR);
    LocalFree(pRsp);
    return TRUE;
}

/*
* Remote VMMDLL_VfsReadU().
*/
NTSTATUS VmmDllRemote_VfsReadU(_In_ VMM_HANDLE H, _In_ LPCSTR uszFileName, _Out_writes_to_(cb, *pcbRead) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ ULONG64 cbOffset)
{
    NTSTATUS nt = VMMDLL_STATUS_FILE_INVALID;
    LC_CMD_AGENT_VFS_REQ Req;
    PLC_CMD_AGENT_VFS_RSP pRsp = NULL;
    VMMDLL_REMOTE_HANDLE HR = NULL;
    DWORD cbRsp;
    if(!(HR = VmmDllRemote_HandleReserveExternal(H))) { return VMMDLL_STATUS_FILE_INVALID; }
    // Remote MemProcFS below:
    ZeroMemory(&Req, sizeof(LC_CMD_AGENT_VFS_REQ));
    Req.dwVersion = LC_CMD_AGENT_VFS_REQ_VERSION;
    Req.qwOffset = cbOffset;
    Req.dwLength = cb;
    if(!CharUtil_UtoU(uszFileName, -1, Req.uszPathFile, sizeof(Req.uszPathFile), NULL, NULL, CHARUTIL_FLAG_STR_BUFONLY)) { goto fail; }
    if(!LcCommand(HR->hLC, LC_CMD_AGENT_VFS_READ, sizeof(LC_CMD_AGENT_VFS_REQ), (PBYTE)&Req, (PBYTE*)&pRsp, &cbRsp) || !pRsp) { goto fail; }
    if((cbRsp < sizeof(LC_CMD_AGENT_VFS_RSP)) || (pRsp->dwVersion != LC_CMD_AGENT_VFS_RSP_VERSION) || (cbRsp < sizeof(LC_CMD_AGENT_VFS_RSP) + pRsp->cb)) { goto fail; }
    nt = pRsp->dwStatus;
    *pcbRead = min(cb, pRsp->cb);
    memcpy(pb, pRsp->pb, *pcbRead);
fail:
    VmmDllRemote_HandleReturnExternal(HR);
    LocalFree(pRsp);
    return nt;
}

/*
* Remote VMMDLL_VfsWriteU().
*/
NTSTATUS VmmDllRemote_VfsWriteU(_In_ VMM_HANDLE H, _In_ LPCSTR uszFileName, _In_reads_(cb) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbWrite, _In_ ULONG64 cbOffset)
{
    NTSTATUS nt = VMMDLL_STATUS_FILE_INVALID;
    PLC_CMD_AGENT_VFS_REQ pReq = NULL;
    PLC_CMD_AGENT_VFS_RSP pRsp = NULL;
    VMMDLL_REMOTE_HANDLE HR = NULL;
    DWORD cbRsp;
    if(!(HR = VmmDllRemote_HandleReserveExternal(H))) { return VMMDLL_STATUS_FILE_INVALID; }
    // Remote MemProcFS below:
    *pcbWrite = 0;
    if(!(pReq = LocalAlloc(0, sizeof(LC_CMD_AGENT_VFS_REQ) + cb))) { goto fail; }
    ZeroMemory(pReq, sizeof(LC_CMD_AGENT_VFS_REQ));
    pReq->dwVersion = LC_CMD_AGENT_VFS_REQ_VERSION;
    pReq->qwOffset = cbOffset;
    pReq->dwLength = cb;
    pReq->cb = cb;
    memcpy(pReq->pb, pb, cb);
    if(!CharUtil_UtoU(uszFileName, -1, pReq->uszPathFile, sizeof(pReq->uszPathFile), NULL, NULL, CHARUTIL_FLAG_STR_BUFONLY)) { goto fail; }
    if(!LcCommand(HR->hLC, LC_CMD_AGENT_VFS_WRITE, sizeof(LC_CMD_AGENT_VFS_REQ) + cb, (PBYTE)pReq, (PBYTE*)&pRsp, &cbRsp) || !pRsp) { goto fail; }
    if((cbRsp < sizeof(LC_CMD_AGENT_VFS_RSP)) || (pRsp->dwVersion != LC_CMD_AGENT_VFS_RSP_VERSION)) { goto fail; }
    nt = pRsp->dwStatus;
    *pcbWrite = min(cb, pRsp->cbReadWrite);
fail:
    VmmDllRemote_HandleReturnExternal(HR);
    LocalFree(pReq);
    LocalFree(pRsp);
    return nt;
}

/*
* Keepalive function / retrieval of remote console data (if any).
*/
_Success_(return)
BOOL VmmDllRemote_KeepAlive_GetRemoteConsole(_In_ VMMDLL_REMOTE_HANDLE HR)
{
    BOOL fResult = FALSE;
    DWORD cbRsp = 0;
    PVMMDLL_VFS_CONSOLE_RSP pRsp = NULL;
    fResult = LcCommand(HR->hLC, LC_CMD_AGENT_VFS_CONSOLE, 0, NULL, (PBYTE*)&pRsp, &cbRsp);
    if(!fResult || (cbRsp < sizeof(VMMDLL_VFS_CONSOLE_RSP))) { goto fail; }
    if((pRsp->dwVersion != VMMDLL_VFS_CONSOLE_RSP_VERSION) || (pRsp->cbStruct < sizeof(VMMDLL_VFS_CONSOLE_RSP) + 1)) { goto fail; }
    ((PBYTE)pRsp)[pRsp->cbStruct - 1] = 0;
    if(pRsp->szStdOut) {
        if(pRsp->qwStdOut >= pRsp->cbStruct) { goto fail; }
        pRsp->szStdOut = (PBYTE)pRsp + pRsp->qwStdOut;
        VmmDllRemote_printf(HR, "%s", pRsp->szStdOut);
    }
    if(pRsp->szStdErr) {
        if(pRsp->qwStdErr >= pRsp->cbStruct) { goto fail; }
        pRsp->szStdErr = (PBYTE)pRsp + pRsp->qwStdErr;
        VmmDllRemote_printf(HR, "%s", pRsp->szStdErr);
    }
    fResult = TRUE;
fail:
    LocalFree(pRsp);
    return fResult;
}

/*
* Keepalive function for the remote MemProcFS instance so it's not auto-terminated.
*/
DWORD WINAPI VmmDllRemote_KeepAlive_ThreadProc(_In_ VMMDLL_REMOTE_HANDLE HR)
{
    QWORD tc = 0;
    while(!HR->fAbort) {
        if(tc + 10000 < GetTickCount64()) {     // 10s keepalive / ping / console update:
            tc = GetTickCount64();
            if(!VmmDllRemote_KeepAlive_GetRemoteConsole(HR)) {
                VmmDllRemote_printf(HR, "MemProcFS: Remote keepalive/ping failed - exiting.\n");
                InterlockedDecrement(&HR->cThreadInternal);
                VmmDllRemote_Close((VMM_HANDLE)HR);
                return 2;
            }
        }
        Sleep(50);
    }
    InterlockedDecrement(&HR->cThreadInternal);
    return 1;
}

/*
* Initialize command line config settings into the VMMDLL_REMOTE_HANDLE and
* the VMMDLL_VFS_INITIALIZEBLOB passed to the remote agent.
* CALLER LocalFree: *ppVfsInitBlob
* -- HR = a cleared fresh VMMDLL_REMOTE_HANDLE not yet fully initialized.
* -- argc
* -- argv
* -- ppVfsInitBlob
* -- return
*/
_Success_(return)
BOOL VmmDllRemote_InitializeConfig(_In_ VMMDLL_REMOTE_HANDLE HR, _In_ DWORD argc, _In_ const char *argv[], _Out_ PVMMDLL_VFS_INITIALIZEBLOB *ppVfsInitBlob)
{
    DWORD i, oMultiStr;
    POB_STRMAP psmOb = NULL;
    PVMMDLL_VFS_INITIALIZEBLOB pBlob = NULL;
    if(!(psmOb = ObStrMap_New(NULL, OB_STRMAP_FLAGS_CASE_SENSITIVE))) { goto fail; }
    if(!(pBlob = (PVMMDLL_VFS_INITIALIZEBLOB)LocalAlloc(LMEM_ZEROINIT, 0x2000))) { goto fail; }
    pBlob->dwVersion = VMMDLL_VFS_INITIALIZEBLOB_VERSION;
    pBlob->cbStruct = 0x2000;
    // parse command line arguments:
    for(i = 0; i < argc; i++) {
        // params not forwarded to remote agent:
        if(!_stricmp("-device", argv[i]) && (i + 1 < argc)) {
            strncpy_s(HR->dev.szDevice, MAX_PATH, argv[i + 1], _TRUNCATE);
            i++;
            continue;
        }
        if(!_stricmp("-remote", argv[i]) && (i + 1 < argc)) {
            strncpy_s(HR->dev.szRemote, MAX_PATH, argv[i + 1], _TRUNCATE);
            i++;
            continue;
        }
        if(!_stricmp("-remotefs", argv[i])) {
            continue;
        }
        if(!_stricmp("-userinteract", argv[i])) {
            HR->fUserInteract = TRUE;
            continue;
        }
        // params forwarded to remote agent:
        if(!_stricmp("-printf", argv[i])) {
            HR->fVerboseDll = TRUE;
        }
        if(!_stricmp("-v", argv[i])) {
            HR->fVerbose = TRUE;
        }
        if(!_stricmp("-vv", argv[i])) {
            HR->fVerboseExtra = TRUE;
        }
        if(!_stricmp("-vvv", argv[i])) {
            HR->fVerboseExtraTlp = TRUE;
        }
        // push ptr to blob:
        if(pBlob->argc >= VMMDLL_VFS_INITIALIZEBLOB_MAX_ARGC) {
            goto fail;
        }
        ObStrMap_PushPtrUU(psmOb, argv[i], &pBlob->argv[pBlob->argc].sz, NULL);
        pBlob->argc++;
    }
    // finalize blob:
    oMultiStr = sizeof(VMMDLL_VFS_INITIALIZEBLOB) + pBlob->argc * sizeof(LPSTR);
    if(!ObStrMap_FinalizeBufferU(psmOb, 0x2000 - oMultiStr, (PBYTE)pBlob + oMultiStr, &pBlob->cbStruct)) { goto fail; }
    pBlob->cbStruct += oMultiStr;
    for(i = 0; i < pBlob->argc; i++) {
        if(pBlob->argv[i].sz) {
            pBlob->argv[i].sz = (LPSTR)((PBYTE)pBlob->argv[i].sz - (SIZE_T)pBlob);
        }
    }
    Ob_DECREF(psmOb);
    *ppVfsInitBlob = pBlob;
    return TRUE;
fail:
    Ob_DECREF(psmOb);
    LocalFree(pBlob);
    return FALSE;
}

#ifdef _WIN32

/*
* Request user input. This is done upon a request from LeechCore. User input is
* only requested in interactive user contexts.
* -- HR = partially initialized VMM_REMOTE_HANDLE.
* -- argc
* -- argv
* -- return
*/
_Success_(return != NULL)
VMM_HANDLE VmmDllRemote_InitializeRequestUserInput(_In_ _Post_ptr_invalid_ VMMDLL_REMOTE_HANDLE HR, _In_ DWORD argc, _In_ LPSTR argv[])
{
    LPSTR szProto;
    DWORD i, cbRead = 0;
    CHAR szInput[33] = { 0 };
    CHAR szDevice[MAX_PATH] = { 0 };
    HANDLE hStdIn = GetStdHandle(STD_INPUT_HANDLE);     // must not be closed.
    // 1: read input
    VmmDllRemote_printf(HR, "\n?> ");
    ReadConsoleA(hStdIn, szInput, 32, &cbRead, NULL);
    for(i = 0; i < _countof(szInput); i++) {
        if((szInput[i] == '\r') || (szInput[i] == '\n')) { szInput[i] = 0; }
    }
    cbRead = (DWORD)strlen(szInput);
    if(!cbRead) { return NULL; }
    // 2: clear "userinput" option and update "device" option
    for(i = 0; i < argc; i++) {
        if(0 == _stricmp(argv[i], "-userinteract")) {
            argv[i] = "";
        }
        if((i + 1 < argc) && ((0 == _stricmp(argv[i], "-device")) || (0 == strcmp(argv[i], "-z")))) {
            szProto = strstr(argv[i + 1], "://");
            snprintf(
                szDevice,
                MAX_PATH - 1,
                "%s%s%sid=%s",
                argv[i + 1],
                szProto ? "" : "://",
                szProto && szProto[3] ? "," : "",
                szInput);
            argv[i + 1] = szDevice;
        }
    }
    // 3: try re-initialize with new user input.
    //    (and close earlier partially initialized handle).
    VmmDllRemote_CloseHandle((VMM_HANDLE)HR, FALSE);
    return VmmDllRemote_Initialize(argc, argv, NULL);
}

#endif /* _WIN32 */

/*
* Initialize a remote MemProcFS from user parameters. Upon success a VMM_HANDLE is returned.
* -- argc
* -- argv
* -- ppLcErrorInfo
* -- return
*/
_Success_(return != NULL)
VMM_HANDLE VmmDllRemote_Initialize(_In_ DWORD argc, _In_ LPCSTR argv[], _Out_opt_ PPLC_CONFIG_ERRORINFO ppLcErrorInfo)
{
    // TODO: IMPLEMENT PROPER ->
    //   - command line passing to remote agent.
    //   - error handling with ppLcErrorInfo.
    //   - proper init check.
    HANDLE hThread = NULL;
    VMMDLL_REMOTE_HANDLE HR = NULL;
    PVMMDLL_VFS_INITIALIZEBLOB pVfsInitBlob = NULL;
    DWORD cbLcErrorInfo = 0;
    PLC_CONFIG_ERRORINFO pLcErrorInfo = NULL;
    LPSTR uszUserText;
    BYTE pbBuffer[3 * MAX_PATH];
    if(ppLcErrorInfo) { *ppLcErrorInfo = NULL; }
    // 1: allocate VMM_REMOTE_HANDLE object and initialize command line
    //    configuration.
    if(!(HR = LocalAlloc(LMEM_ZEROINIT, sizeof(struct tdVMMDLL_REMOTE_HANDLE)))) { goto fail_prelock; }
    HR->magic = VMMDLL_REMOTE_MAGIC;
    HR->dwHandleCount = 1;
    // 2: initialize config:
    if(!VmmDllRemote_InitializeConfig(HR, argc, argv, &pVfsInitBlob)) {
        VmmDllRemote_printf(HR, "MemProcFS: Unable to parse remote command line.\n");
        goto fail_prelock;
    }
    if(!HR->dev.szDevice[0]) {
        VmmDllRemote_printf(HR, "MemProcFS: Missing required option: -device.\n");
        goto fail_prelock;
    }
    if(!HR->dev.szRemote[0]) {
        VmmDllRemote_printf(HR, "MemProcFS: Missing required option: -remote.\n");
        goto fail_prelock;
    }
    HR->dev.dwVersion = LC_CONFIG_VERSION;
    HR->dev.dwPrintfVerbosity |= HR->fVerboseDll ? LC_CONFIG_PRINTF_ENABLED : 0;
    HR->dev.dwPrintfVerbosity |= HR->fVerbose ? LC_CONFIG_PRINTF_V : 0;
    HR->dev.dwPrintfVerbosity |= HR->fVerboseExtra ? LC_CONFIG_PRINTF_VV : 0;
    HR->dev.dwPrintfVerbosity |= HR->fVerboseExtraTlp ? LC_CONFIG_PRINTF_VVV : 0;
    // 3: Acquire global shared lock (for remainder of initialization).
    EnterCriticalSection(&g_VMMDLL_REMOTE_LOCK);
    // 4: upon success add handle to external allow-list.
    if(!VmmDllRemote_HandleAdd(HR)) {
        VmmDllRemote_printf(HR, "MemProcFS: Failed to add handle to external allow-list (max %i concurrent tasks allowed).\n", g_VMMDLL_REMOTE_HANDLE_COUNT);
        goto fail;
    }
    // 5: Initialize remote LeechCore:
    if(!(HR->hLC = LcCreateEx(&HR->dev, &pLcErrorInfo))) {
#ifdef _WIN32
        if(pLcErrorInfo && (pLcErrorInfo->dwVersion == LC_CONFIG_ERRORINFO_VERSION)) {
            if(pLcErrorInfo->cwszUserText && CharUtil_WtoU(pLcErrorInfo->wszUserText, -1, pbBuffer, sizeof(pbBuffer), &uszUserText, NULL, 0)) {
                VmmDllRemote_printf(HR, "MESSAGE FROM MEMORY ACQUISITION DEVICE:\n=======================================\n%s\n", uszUserText);
            }
            if(HR->fUserInteract && pLcErrorInfo->fUserInputRequest) {
                LcMemFree(pLcErrorInfo);
                LeaveCriticalSection(&g_VMMDLL_REMOTE_LOCK);
                // the request user input function will force a re-initialization upon
                // success and free/discard the earlier partially initialized handle.
                return VmmDllRemote_InitializeRequestUserInput(HR, argc, argv);
            }
        }
#endif /* _WIN32 */
        VmmDllRemote_printf(HR, "MemProcFS: Failed to connect to the remote system (LeechCore).\n  Device: %s\n  Remote: %s\n", HR->dev.szDevice, HR->dev.szRemote);
        goto fail;
    }
    // 6: Initialize remote MemProcFS:
    if(!LcCommand(HR->hLC, LC_CMD_AGENT_VFS_INITIALIZE, pVfsInitBlob->cbStruct, (PBYTE)pVfsInitBlob, NULL, NULL)) {
        VmmDllRemote_printf(HR, "MemProcFS: Failed to connect to the remote system (MemProcFS).\n  Device: %s\n  Remote: %s\n", HR->dev.szDevice, HR->dev.szRemote);
        goto fail;
    }
    // 7: Set up background keep-alive thread:
    InterlockedIncrement(&HR->cThreadInternal);
    hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)VmmDllRemote_KeepAlive_ThreadProc, (LPVOID)HR, 0, NULL);
    if(hThread) { CloseHandle(hThread); }
    // 8: finish and return handle (as a "fake" VMM_HANDLE).
    LeaveCriticalSection(&g_VMMDLL_REMOTE_LOCK);
    LocalFree(pVfsInitBlob);
    return (VMM_HANDLE)((SIZE_T)HR | 1);
fail:
    if(ppLcErrorInfo) {
        *ppLcErrorInfo = pLcErrorInfo;
    } else {
        LcMemFree(pLcErrorInfo);
    }
    LeaveCriticalSection(&g_VMMDLL_REMOTE_LOCK);
    VmmDllRemote_CloseHandle((VMM_HANDLE)HR, FALSE);
    LocalFree(pVfsInitBlob);
    return NULL;
fail_prelock:
    LocalFree(pVfsInitBlob);
    LocalFree(HR);
    return NULL;
}
