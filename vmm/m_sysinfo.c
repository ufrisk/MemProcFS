// m_sysinfo.c : implementation related to the SysInfo built-in module.
//
// The SysInfo module is responsible for displaying various informational files
// at the path /sysinfo/
//
// Functionality includes:
//   ProcTree - process tree listing showing parent processes - files:
//              "proctree"
//              "proctree-v"
//   Version -  operating system version information - files:
//              "version"
//              "version-major"
//              "version-minor"
//              "version-build"
//
// (c) Ulf Frisk, 2019
// Author: Ulf Frisk, pcileech@frizk.net
//
#include <ws2tcpip.h>
#include "m_sysinfo.h"
#include "vmm.h"
#include "vmmwin.h"
#include "vmmwintcpip.h"
#include "util.h"

LPCSTR szMSYSINFO_NET_README =
    "Information about the sysinfo net module                                     \n" \
    "========================================                                     \n" \
    "The sysinfo net module tries to enumerate and list active TCP connections in \n" \
    "Windows 7 and later (x64 only).  It currently does not support listening TCP \n" \
    "ports or UDP ports. This functionality is planned for the future. Also, it's \n" \
    "not supporting 32-bit or Windows Vista/XP (future support less likely).      \n" \
    "For more information please visit: https://github.com/ufrisk/MemProcFS/wiki  \n";

// ----------------------------------------------------------------------------
// ProcTree functionality below:
// The proctree.txt file is re-generated for each read. This is not efficient,
// but the file is not read often so it should be OK.
// ----------------------------------------------------------------------------

#define MSYSINFO_PROCTREE_LINE_LENGTH_BASE              45
#define MSYSINFO_PROCTREE_LINE_LENGTH_HEADER_VERBOSE    64

const LPSTR szMSYSINFO_WHITELIST_WINDOWS_PATHS_AND_BINARIES[] = {
    "\\Windows\\System32\\",
    "\\Windows\\SystemApps\\",
    "\\Windows\\SysWOW64\\",
    "\\Windows\\explorer.exe",
    "\\Windows Defender\\MsMpEng.exe",
    "\\Windows Defender\\NisSrv.exe",
    "\\Microsoft\\OneDrive\\OneDrive.exe",
    "\\WINDOWS\\system32\\"
};

typedef struct tdMSYSINFO_PROCTREE_ENTRY {
    DWORD dwPPID;
    DWORD dwPID;
    BYTE iLevel;
    BOOL fProcessed;
    PVMM_PROCESS pObProcess;
} MSYSINFO_PROCTREE_ENTRY, *PMSYSINFO_PROCTREE_ENTRY;

BOOL MSysInfo_ProcTree_ExistsUnprocessed(PMSYSINFO_PROCTREE_ENTRY pPidList, DWORD cPidList, DWORD dwPID)
{
    DWORD i;
    for(i = 0; i < cPidList; i++) {
        if(pPidList[i].dwPID == dwPID) {
            return !pPidList[i].fProcessed;
        }
    }
    return FALSE;
}

DWORD MSysInfo_ProcTree_ProcessItems(_In_ PMSYSINFO_PROCTREE_ENTRY pProcessEntry, _In_ PMSYSINFO_PROCTREE_ENTRY pList, _In_ DWORD cList, _In_ PBYTE pb, _In_ DWORD cb, _In_ BYTE iLevel, _In_ BOOL fVerbose)
{
    LPCSTR szINDENT[] = { "-", "--", "---", "----", "-----", "------", "-------", "--------", "--------+" };
    DWORD i, o = 0;
    BOOL fWinNativeProc, fStateTerminated;
    if((cb > 0x01000000) || (cb < 0x00040000)) {
        vmmprintf_fn("WARNING: BUFFER MAY BE TOO SMALL - SHOULD NOT HAPPEN! %i\n", cb);
        return 0;
    }
    fStateTerminated = (pProcessEntry->pObProcess->dwState != 0);
    fWinNativeProc = (pProcessEntry->dwPID == 4) || (pProcessEntry->dwPPID == 4);
    for(i = 0; !fWinNativeProc && (i < (sizeof(szMSYSINFO_WHITELIST_WINDOWS_PATHS_AND_BINARIES) / sizeof(LPSTR))); i++) {
        fWinNativeProc = (NULL != strstr(pProcessEntry->pObProcess->pObProcessPersistent->szPathKernel, szMSYSINFO_WHITELIST_WINDOWS_PATHS_AND_BINARIES[i]));
    }
    o = snprintf(
            pb,
            cb,
            "%s %-15s%*s%6i %6i   %c%c %s\n",
            szINDENT[min(8, iLevel)],
            pProcessEntry->pObProcess->szName,
            8 - min(7, iLevel),
            "",
            pProcessEntry->dwPID,
            pProcessEntry->dwPPID,
            fStateTerminated ? 'T' : ' ',
            fWinNativeProc ? ' ' : '*',
            fVerbose ? pProcessEntry->pObProcess->pObProcessPersistent->szPathKernel : ""
        );
    if(fVerbose) {
        if(pProcessEntry->pObProcess->pObProcessPersistent->UserProcessParams.szImagePathName) {
            o += snprintf(pb + o, cb - o, "%44s%-*s\n", "", 
                pProcessEntry->pObProcess->pObProcessPersistent->UserProcessParams.cchImagePathName, 
                pProcessEntry->pObProcess->pObProcessPersistent->UserProcessParams.szImagePathName);
        }
        if(pProcessEntry->pObProcess->pObProcessPersistent->UserProcessParams.szCommandLine) {
            o += snprintf(pb + o, cb - o, "%44s%-*s\n", "", 
                pProcessEntry->pObProcess->pObProcessPersistent->UserProcessParams.cchCommandLine,
                pProcessEntry->pObProcess->pObProcessPersistent->UserProcessParams.szCommandLine);
        }
        o += snprintf(pb + o, cb - o, "\n");
    }
    pProcessEntry->iLevel = iLevel;
    pProcessEntry->fProcessed = TRUE;
    // 2: fetch and process sub-items (child processes)
    for(i = 0; i < cList; i++) {
        if(pList[i].fProcessed) { continue; }
        if(pList[i].dwPPID == pProcessEntry->dwPID) {
            o += MSysInfo_ProcTree_ProcessItems(pList + i, pList, cList, pb + o, cb - o, iLevel + 1, fVerbose);
        }
    }
    return o;
}

int MSysInfo_ProcTree_CmpSort(PMSYSINFO_PROCTREE_ENTRY a, PMSYSINFO_PROCTREE_ENTRY b)
{
    if(a->dwPPID - b->dwPPID) {
        return a->dwPID - b->dwPID;
    }
    return a->dwPPID - b->dwPPID;
}

_Success_(return)
BOOL MSysInfo_ProcTree(_In_ BOOL fVerbose, _Out_ PBYTE *ppb, _Out_ PDWORD pcb)
{
    BOOL fResult = FALSE;
    PVMM_PROCESS pObProcess = NULL;
    PMSYSINFO_PROCTREE_ENTRY pPidEntry, pPidList = NULL;
    DWORD iPidList = 0, i;
    SIZE_T cPidList = 0;
    PBYTE pb;
    DWORD cb = 0x00100000, o = 0;   // 1MB should be enough to hold any process list ...
    // 1: retrieve process information into "pid list"
    VmmProcessListPIDs(NULL, &cPidList, VMM_FLAG_PROCESS_SHOW_TERMINATED);
    if(!cPidList) { return FALSE; }
    if(!(pPidList = LocalAlloc(LMEM_ZEROINIT, cPidList * sizeof(MSYSINFO_PROCTREE_ENTRY)))) { return FALSE; }
    while((iPidList < cPidList) && (pObProcess = VmmProcessGetNext(pObProcess, VMM_FLAG_PROCESS_SHOW_TERMINATED))) {
        pPidEntry = pPidList + iPidList++;
        pPidEntry->dwPID = pObProcess->dwPID;
        pPidEntry->dwPPID = pObProcess->dwPPID;
        pPidEntry->pObProcess = (PVMM_PROCESS)Ob_INCREF(pObProcess);    // INCREF process object and assign to array
    }
    Ob_DECREF_NULL(&pObProcess);
    pb = LocalAlloc(0, cb);
    if(pb) {
        // 3: iterate over top level items - processes with no parent
        qsort(pPidList, cPidList, sizeof(MSYSINFO_PROCTREE_ENTRY), (int(*)(const void *, const void *))MSysInfo_ProcTree_CmpSort);
        o = snprintf(pb, cb, fVerbose ?
            "  Process                   Pid Parent Flag Path / Command Line\n---------------------------------------------------------------\n" :
            "  Process                   Pid Parent Flag \n--------------------------------------------\n");
        // 3.1 process items
        for(i = 0; i < cPidList; i++) {
            pPidEntry = pPidList + i;
            if(pPidEntry->fProcessed) { continue; }
            if(MSysInfo_ProcTree_ExistsUnprocessed(pPidList, (DWORD)cPidList, pPidEntry->dwPPID)) { continue; }
            o += MSysInfo_ProcTree_ProcessItems(pPidEntry, pPidList, (DWORD)cPidList, pb + o, cb - o, 0, fVerbose);
        }
        // 3.2 process remaining items (in case of PPID-loop which ideally should not happen)
        //     the remaining items are processed without regards for order.
        for(i = 0; i < cPidList; i++) {
            pPidEntry = pPidList + i;
            if(pPidEntry->fProcessed) { continue; }
            o += MSysInfo_ProcTree_ProcessItems(pPidEntry, pPidList, (DWORD)cPidList, pb + o, cb - o, 0, fVerbose);
        }
        // 4: finish!
        *ppb = pb;
        *pcb = o;
        fResult = TRUE;
    }
    for(i = 0; i < cPidList; i++) {
        Ob_DECREF(pPidList[i].pObProcess);  // DECREF array assigned process object.
    }
    LocalFree(pPidList);
    return fResult;
}

NTSTATUS MSysInfo_Read_ProcTree(_In_ LPSTR szPath, _Out_ PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset)
{
    NTSTATUS nt;
    DWORD cbFile = 0;
    PBYTE pbFile = NULL;
    if(!strcmp(szPath, "tree")) {
        MSysInfo_ProcTree(FALSE, &pbFile, &cbFile);
        nt = Util_VfsReadFile_FromPBYTE(pbFile, cbFile, pb, cb, pcbRead, cbOffset);
        LocalFree(pbFile);
        return nt;
    }
    if(!strcmp(szPath, "tree-v")) {
        MSysInfo_ProcTree(TRUE, &pbFile, &cbFile);
        nt = Util_VfsReadFile_FromPBYTE(pbFile, cbFile, pb, cb, pcbRead, cbOffset);
        LocalFree(pbFile);
        return nt;
    }
    return VMMDLL_STATUS_FILE_INVALID;
}

VOID MSysInfo_List_ProcTree_ProcessUserParams_CallbackAction(_In_ PVMM_PROCESS pProcess, _In_ PDWORD pcTotalBytes)
{
    PVMMWIN_USER_PROCESS_PARAMETERS pu = VmmWin_UserProcessParameters_Get(pProcess);
    DWORD c = MSYSINFO_PROCTREE_LINE_LENGTH_BASE + pProcess->pObProcessPersistent->cchPathKernel + 1;
    if(pu->szImagePathName) {
        c += MSYSINFO_PROCTREE_LINE_LENGTH_BASE + pu->cchImagePathName;
    }
    if(pu->szCommandLine) {
        c += MSYSINFO_PROCTREE_LINE_LENGTH_BASE + pu->cchCommandLine;
    }
    InterlockedAdd(pcTotalBytes, c);
}

BOOL MSysInfo_List_ProcTree(_Inout_ PHANDLE pFileList)
{
    SIZE_T cProcess = 0;
    DWORD cbProcTree = 0;
    VmmProcessListPIDs(NULL, &cProcess, VMM_FLAG_PROCESS_SHOW_TERMINATED);
    if(cProcess) {
        cbProcTree = (DWORD)(cProcess + 2) * MSYSINFO_PROCTREE_LINE_LENGTH_BASE;
        VMMDLL_VfsList_AddFile(pFileList, "tree", cbProcTree);
        cbProcTree = MSYSINFO_PROCTREE_LINE_LENGTH_HEADER_VERBOSE * 2;
        VmmProcessActionForeachParallel(&cbProcTree, 5, NULL, MSysInfo_List_ProcTree_ProcessUserParams_CallbackAction);
        VMMDLL_VfsList_AddFile(pFileList, "tree-v", cbProcTree);
    }
    return TRUE;
}

// ----------------------------------------------------------------------------
// Net functionality below:
// Show information related to TCP/IP connectivity in the analyzed system.
// ----------------------------------------------------------------------------

#define MSYSINFO_NET_CACHE_MAXAGE   500      // ms

typedef struct tdMSYSINFO_OB_NET_CONTEXT {
    OB hdr;
    QWORD qwCreateTimeTickCount64;
    DWORD cbFile;
    PBYTE pbFile;
    DWORD cbFileVerbose;
    PBYTE pbFileVerbose;
} MSYSINFO_OB_NET_CONTEXT, *PMSYSINFO_OB_NET_CONTEXT;

PMSYSINFO_OB_NET_CONTEXT gp_MSYSINFO_OB_NETCONTEXT = NULL;

VOID MSysInfo_ObNetContext_CallbackRefCount1(PMSYSINFO_OB_NET_CONTEXT pOb)
{
    LocalFree(pOb->pbFile);
    LocalFree(pOb->pbFileVerbose);
}

/*
* Format network connection into into human readable text.
*/
_Success_(return)
BOOL MSysInfo_GetNetContext_ToString(_In_ PVMMWIN_TCPIP_ENTRY pTcpE, _In_ DWORD cTcpE, _Out_ PBYTE* ppbFileN, _Out_ PDWORD pcbFileN, _Out_ PBYTE* ppbFileV, _Out_ PDWORD pcbFileV)
{
    BOOL fResult = FALSE;
    PVMMWIN_TCPIP_ENTRY pE;
    DWORD i, oN = 0, oV = 0, dwIpVersion;
    DWORD cbN = 0x00100000, cbV = 0x00100000;
    PBYTE pbN = NULL, pbV = NULL;
    PVMM_PROCESS pObProcess = NULL;
    DWORD cchSrc, cchDst;
    CHAR sz[64], szSrc[64], szDst[64], szTime[MAX_PATH];
    if(!(pbN = LocalAlloc(0, cbN))) { goto fail; }
    if(!(pbV = LocalAlloc(0, cbV))) { goto fail; }

    for(i = 0; i < cTcpE; i++) {
        pE = pTcpE + i;
        pObProcess = VmmProcessGet(pE->dwPID);
        dwIpVersion = (pE->AF.wAF == AF_INET) ? 4 : ((pE->AF.wAF == AF_INET6) ? 6 : 0);
        // format src addr
        if(pE->Src.fValid) {
            sz[0] = 0;
            InetNtopA(pE->AF.wAF, pE->Src.pbA, sz, sizeof(sz));
        } else {
            strcpy_s(sz, sizeof(sz), "***");
        }
        cchSrc = snprintf(szSrc, sizeof(szSrc), ((dwIpVersion == 6) ? "[%s]:%i" : "%s:%i"), sz, pE->Src.wPort);
        // format dst addr
        if(pE->Dst.fValid) {
            sz[0] = 0;
            InetNtopA(pE->AF.wAF, pE->Dst.pbA, sz, sizeof(sz));
        } else {
            strcpy_s(sz, sizeof(sz), "***");
        }
        cchDst = snprintf(szDst, sizeof(szDst), ((dwIpVersion == 6) ? "[%s]:%i" : "%s:%i"), sz, pE->Dst.wPort);
        // get time
        Util_FileTime2String((PFILETIME)&pE->qwTime, szTime);
        // print normal
        oN += snprintf(
            pbN + oN,
            (QWORD)cbN + oN,
            "TCPv%i  %-*s  %-*s  %-11s %6i  %s\n",
            dwIpVersion,
            max(28, cchSrc),
            szSrc,
            max(28, cchDst),
            szDst,
            pE->szState,
            pE->dwPID,
            (pObProcess ? pObProcess->szName : "***")
        );
        // print verbose
        oV += snprintf(
            pbV + oV,
            (QWORD)cbV + oV,
            "TCPv%i  %-*s  %-*s  %-11s  %s %6i  %-15s %s\n",
            dwIpVersion,
            max(28, cchSrc),
            szSrc,
            max(28, cchDst),
            szDst,
            pE->szState,
            szTime,
            pE->dwPID,
            (pObProcess ? pObProcess->szName : "***"),
            (pObProcess ? pObProcess->pObProcessPersistent->szPathKernel : "***")
        );
        Ob_DECREF_NULL(&pObProcess);
    }
    // move result into properly sized buffers
    if(!(*ppbFileN = LocalAlloc(0, oN))) { goto fail; }
    if(!(*ppbFileV = LocalAlloc(0, oV))) { goto fail; }
    memcpy(*ppbFileN, pbN, oN);
    memcpy(*ppbFileV, pbV, oV);
    *pcbFileN = oN;
    *pcbFileV = oV;
    fResult = TRUE;
fail:
    LocalFree(pbN);
    LocalFree(pbV);
    return fResult;
}

/*
* Retrieve a net context containing the processed data as an object manager object.
* CALLER DECREF: return
* -- return
*/
PMSYSINFO_OB_NET_CONTEXT MSysInfo_GetNetContext()
{
    DWORD cTcpE;
    PVMMWIN_TCPIP_ENTRY pTcpE = NULL;
    PMSYSINFO_OB_NET_CONTEXT pObCtx;
    EnterCriticalSection(&ctxVmm->TcpIp.LockUpdate);
    // 1: check if cached version is ok
    pObCtx = gp_MSYSINFO_OB_NETCONTEXT;
    if(pObCtx && (pObCtx->qwCreateTimeTickCount64 + MSYSINFO_NET_CACHE_MAXAGE > GetTickCount64())) {
        Ob_INCREF(pObCtx);
        goto finish;
    }
    // 2: replace with new version
    if(!VmmWinTcpIp_TcpE_Get(&pTcpE, &cTcpE)) { goto finish; }
    Ob_DECREF_NULL(&gp_MSYSINFO_OB_NETCONTEXT);
    pObCtx = gp_MSYSINFO_OB_NETCONTEXT = Ob_Alloc('IP', LMEM_ZEROINIT, sizeof(MSYSINFO_OB_NET_CONTEXT), MSysInfo_ObNetContext_CallbackRefCount1, NULL);
    if(!pObCtx) { goto finish; }    // alloc failed - should not happen -> finish and return NULL
    MSysInfo_GetNetContext_ToString(pTcpE, cTcpE, &pObCtx->pbFile, &pObCtx->cbFile, &pObCtx->pbFileVerbose, &pObCtx->cbFileVerbose);
    pObCtx->qwCreateTimeTickCount64 = GetTickCount64();
    Ob_INCREF(pObCtx);
finish:
    LeaveCriticalSection(&ctxVmm->TcpIp.LockUpdate);
    LocalFree(pTcpE);
    return pObCtx;
}

NTSTATUS MSysInfo_Read_Net(_In_ LPSTR szPath, _Out_ PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset)
{
    NTSTATUS nt = VMMDLL_STATUS_FILE_INVALID;
    PMSYSINFO_OB_NET_CONTEXT pObNetCtx;
    if(!strcmp(szPath, "readme")) {
        return Util_VfsReadFile_FromPBYTE((PBYTE)szMSYSINFO_NET_README, strlen(szMSYSINFO_NET_README), pb, cb, pcbRead, cbOffset);
    }
    if((pObNetCtx = MSysInfo_GetNetContext())) {
        if(!strcmp(szPath, "netstat")) {
            nt = Util_VfsReadFile_FromPBYTE(pObNetCtx->pbFile, pObNetCtx->cbFile, pb, cb, pcbRead, cbOffset);
        }
        if(!strcmp(szPath, "netstat-v")) {
            nt = Util_VfsReadFile_FromPBYTE(pObNetCtx->pbFileVerbose, pObNetCtx->cbFileVerbose, pb, cb, pcbRead, cbOffset);
        }
        Ob_DECREF(pObNetCtx);
    }
    return nt;
}

BOOL MSysInfo_List_Net(_Inout_ PHANDLE pFileList)
{
    PMSYSINFO_OB_NET_CONTEXT pObNetCtx;
    VMMDLL_VfsList_AddFile(pFileList, "readme", strlen(szMSYSINFO_NET_README));
    if((pObNetCtx = MSysInfo_GetNetContext())) {
        VMMDLL_VfsList_AddFile(pFileList, "netstat", pObNetCtx->cbFile);
        VMMDLL_VfsList_AddFile(pFileList, "netstat-v", pObNetCtx->cbFileVerbose);
        Ob_DECREF(pObNetCtx);
    }
    return TRUE;
}

// ----------------------------------------------------------------------------
// GENERAL FUNCTIONALITY BELOW:
// ----------------------------------------------------------------------------

NTSTATUS MSysInfo_Read(_In_ PVMMDLL_PLUGIN_CONTEXT ctx, _Out_ PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset)
{
    DWORD cbBuffer;
    BYTE pbBuffer[MAX_PATH];
    LPSTR szPath1, szPath2;
    // version.txt
    if(!strcmp(ctx->szPath, "version")) {
        cbBuffer = snprintf(pbBuffer, 32, "%i.%i.%i", ctxVmm->kernel.dwVersionMajor, ctxVmm->kernel.dwVersionMinor, ctxVmm->kernel.dwVersionBuild);
        return Util_VfsReadFile_FromPBYTE(pbBuffer, cbBuffer, pb, cb, pcbRead, cbOffset);
    }
    if(!strcmp(ctx->szPath, "version-major")) {
        return Util_VfsReadFile_FromNumber(ctxVmm->kernel.dwVersionMajor, pb, cb, pcbRead, cbOffset);
    }
    if(!strcmp(ctx->szPath, "version-minor")) {
        return Util_VfsReadFile_FromNumber(ctxVmm->kernel.dwVersionMinor, pb, cb, pcbRead, cbOffset);
    }
    if(!strcmp(ctx->szPath, "version-build")) {
        return Util_VfsReadFile_FromNumber(ctxVmm->kernel.dwVersionBuild, pb, cb, pcbRead, cbOffset);
    }
    // proc
    Util_PathSplit2(ctx->szPath, pbBuffer, &szPath1, &szPath2);
    if(!strcmp(szPath1, "proc")) {
        return MSysInfo_Read_ProcTree(szPath2, pb, cb, pcbRead, cbOffset);
    }
    if(!strcmp(szPath1, "net")) {
        return MSysInfo_Read_Net(szPath2, pb, cb, pcbRead, cbOffset);
    }
    return VMMDLL_STATUS_FILE_INVALID;
}

BOOL MSysInfo_List(_In_ PVMMDLL_PLUGIN_CONTEXT ctx, _Inout_ PHANDLE pFileList)
{
    DWORD cchMajor, cchMinor, cchBuild;
    if(!strcmp("proc", ctx->szPath)) {
        return MSysInfo_List_ProcTree(pFileList);
    } else if(!strcmp("net", ctx->szPath)) {
        return MSysInfo_List_Net(pFileList);
    }
    else if(ctx->szPath[0]) {
        return FALSE;
    }
    VMMDLL_VfsList_AddDirectory(pFileList, "net");
    VMMDLL_VfsList_AddDirectory(pFileList, "proc");
    // version.txt
    cchMajor = Util_GetNumDigits(ctxVmm->kernel.dwVersionMajor);
    cchMinor = Util_GetNumDigits(ctxVmm->kernel.dwVersionMinor);
    cchBuild = Util_GetNumDigits(ctxVmm->kernel.dwVersionBuild);
    VMMDLL_VfsList_AddFile(pFileList, "version", 2ULL + cchMajor + cchMinor + cchBuild);
    VMMDLL_VfsList_AddFile(pFileList, "version-major", cchMajor);
    VMMDLL_VfsList_AddFile(pFileList, "version-minor", cchMinor);
    VMMDLL_VfsList_AddFile(pFileList, "version-build", cchBuild);
    return TRUE;
}

VOID MSysInfo_Close()
{
    Ob_DECREF_NULL(&gp_MSYSINFO_OB_NETCONTEXT);
}

VOID M_SysInfo_Initialize(_Inout_ PVMMDLL_PLUGIN_REGINFO pRI)
{
    if((pRI->magic != VMMDLL_PLUGIN_REGINFO_MAGIC) || (pRI->wVersion != VMMDLL_PLUGIN_REGINFO_VERSION)) { return; }
    if((pRI->tpSystem != VMM_SYSTEM_WINDOWS_X64) && (pRI->tpSystem != VMM_SYSTEM_WINDOWS_X86)) { return; }
    strcpy_s(pRI->reg_info.szModuleName, 32, "sysinfo");    // module name
    pRI->reg_info.fRootModule = TRUE;                       // module shows in root directory
    pRI->reg_fn.pfnList = MSysInfo_List;                    // List function supported
    pRI->reg_fn.pfnRead = MSysInfo_Read;                    // Read function supported
    pRI->reg_fn.pfnClose = MSysInfo_Close;                  // Close function supported
    pRI->pfnPluginManager_Register(pRI);
}
