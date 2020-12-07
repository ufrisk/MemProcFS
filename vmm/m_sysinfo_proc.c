// m_sysinfo_proc.c : implementation related to the SysInfo/Proc built-in module.
//
// The SysInfo/Proc module is responsible for displaying the process list
// as a tree structure together with various nice to have information at
// the path '/sysinfo/proc/'
//
// (c) Ulf Frisk, 2020
// Author: Ulf Frisk, pcileech@frizk.net
//
#include <ws2tcpip.h>
#include "vmm.h"
#include "vmmwin.h"
#include "util.h"

// ----------------------------------------------------------------------------
// ProcTree functionality below:
// NB! The proctree text files are re-generated for each read. This is not
// efficient, but the file is not read often so it should be OK.
// ----------------------------------------------------------------------------

#define MSYSINFOPROC_TREE_LINE_LENGTH_BASE              63
#define MSYSINFOPROC_TREE_LINE_LENGTH_HEADER_VERBOSE    82

const LPSTR szMSYSINFOPROC_WHITELIST_WINDOWS_PATHS_AND_BINARIES[] = {
    "\\Windows\\System32\\",
    "\\Windows\\SystemApps\\",
    "\\Windows\\SysWOW64\\",
    "\\Windows\\explorer.exe",
    "\\Windows Defender\\MsMpEng.exe",
    "\\Windows Defender\\NisSrv.exe",
    "\\Microsoft\\OneDrive\\OneDrive.exe",
    "\\WINDOWS\\system32\\"
};

typedef struct tdMSYSINFOPROC_TREE_ENTRY {
    DWORD dwPPID;
    DWORD dwPID;
    BYTE iLevel;
    BOOL fProcessed;
    PVMM_PROCESS pObProcess;
} MSYSINFOPROC_TREE_ENTRY, *PMSYSINFOPROC_TREE_ENTRY;

BOOL MSysInfoProc_Tree_ExistsUnprocessed(PMSYSINFOPROC_TREE_ENTRY pPidList, DWORD cPidList, DWORD dwPID)
{
    DWORD i;
    for(i = 0; i < cPidList; i++) {
        if(pPidList[i].dwPID == dwPID) {
            return !pPidList[i].fProcessed;
        }
    }
    return FALSE;
}

VOID MSysInfoProc_Tree_ProcessItems_GetUserName(_In_ PVMM_PROCESS pProcess, _Out_writes_(17) LPSTR szUserName, _Out_ PBOOL fAccountUser)
{
    BOOL f, fWellKnownAccount;
    DWORD cwszName;
    WCHAR wszUserName[MAX_PATH];
    f = pProcess->win.TOKEN.fSID &&
        VmmWinUser_GetNameW(&pProcess->win.TOKEN.SID, wszUserName, MAX_PATH, &cwszName, &fWellKnownAccount) &&
        snprintf(szUserName, 17, "%S", wszUserName);
    szUserName[f ? 16 : 0] = 0;
    *fAccountUser = f && !fWellKnownAccount;
}

DWORD MSysInfoProc_Tree_ProcessItems(_In_ PMSYSINFOPROC_TREE_ENTRY pProcessEntry, _In_ PMSYSINFOPROC_TREE_ENTRY pList, _In_ DWORD cList, _In_ PBYTE pb, _In_ DWORD cb, _In_ BYTE iLevel, _In_ BOOL fVerbose)
{
    LPCSTR szINDENT[] = { "-", "--", "---", "----", "-----", "------", "-------", "--------", "--------+" };
    CHAR szUserName[17];
    DWORD i, o = 0;
    BOOL fWinNativeProc, fStateTerminated, fAccountUser = FALSE;
    if((cb > 0x01000000) || (cb < 0x00040000)) {
        vmmprintf_fn("WARNING: BUFFER MAY BE TOO SMALL - SHOULD NOT HAPPEN! %i\n", cb);
        return 0;
    }
    fStateTerminated = (pProcessEntry->pObProcess->dwState != 0);
    fWinNativeProc = (pProcessEntry->dwPID == 4) || (pProcessEntry->dwPPID == 4);
    for(i = 0; !fWinNativeProc && (i < (sizeof(szMSYSINFOPROC_WHITELIST_WINDOWS_PATHS_AND_BINARIES) / sizeof(LPSTR))); i++) {
        fWinNativeProc = (NULL != strstr(pProcessEntry->pObProcess->pObPersistent->uszPathKernel, szMSYSINFOPROC_WHITELIST_WINDOWS_PATHS_AND_BINARIES[i]));
    }
    MSysInfoProc_Tree_ProcessItems_GetUserName(pProcessEntry->pObProcess, szUserName, &fAccountUser);
    o = snprintf(
        pb,
        cb,
        "%s %-15s%*s%6i %6i %s%c%c%c %-16s %s\n",
        szINDENT[min(8, iLevel)],
        pProcessEntry->pObProcess->szName,
        8 - min(7, iLevel),
        "",
        pProcessEntry->dwPID,
        pProcessEntry->dwPPID,
        pProcessEntry->pObProcess->win.fWow64 ? "32" : "  ",
        fStateTerminated ? 'T' : ' ',
        fAccountUser ? 'U' : ' ',
        fWinNativeProc ? ' ' : '*',
        szUserName,
        fVerbose ? pProcessEntry->pObProcess->pObPersistent->uszPathKernel : ""
    );
    if(fVerbose) {
        if(pProcessEntry->pObProcess->pObPersistent->UserProcessParams.uszImagePathName) {
            o += snprintf(pb + o, cb - o, "%61s%-*s\n", "",
                pProcessEntry->pObProcess->pObPersistent->UserProcessParams.cuszImagePathName,
                pProcessEntry->pObProcess->pObPersistent->UserProcessParams.uszImagePathName);
        }
        if(pProcessEntry->pObProcess->pObPersistent->UserProcessParams.uszCommandLine) {
            o += snprintf(pb + o, cb - o, "%61s%-*s\n", "",
                pProcessEntry->pObProcess->pObPersistent->UserProcessParams.cuszCommandLine,
                pProcessEntry->pObProcess->pObPersistent->UserProcessParams.uszCommandLine);
        }
        o += snprintf(pb + o, cb - o, "\n");
    }
    pProcessEntry->iLevel = iLevel;
    pProcessEntry->fProcessed = TRUE;
    // 2: fetch and process sub-items (child processes)
    for(i = 0; i < cList; i++) {
        if(pList[i].fProcessed) { continue; }
        if(pList[i].dwPPID == pProcessEntry->dwPID) {
            o += MSysInfoProc_Tree_ProcessItems(pList + i, pList, cList, pb + o, cb - o, iLevel + 1, fVerbose);
        }
    }
    return o;
}

int MSysInfoProc_Tree_CmpSort(PMSYSINFOPROC_TREE_ENTRY a, PMSYSINFOPROC_TREE_ENTRY b)
{
    if(a->dwPPID - b->dwPPID) {
        return a->dwPID - b->dwPID;
    }
    return a->dwPPID - b->dwPPID;
}

_Success_(return)
BOOL MSysInfoProc_Tree(_In_ BOOL fVerbose, _Out_ PBYTE * ppb, _Out_ PDWORD pcb)
{
    BOOL fResult = FALSE;
    PVMM_PROCESS pObProcess = NULL;
    PMSYSINFOPROC_TREE_ENTRY pPidEntry, pPidList = NULL;
    DWORD iPidList = 0, i;
    SIZE_T cPidList = 0;
    PBYTE pb;
    DWORD cb = 0x00100000, o = 0;   // 1MB should be enough to hold any process list ...
    // 1: retrieve process information into "pid list"
    VmmProcessListPIDs(NULL, &cPidList, VMM_FLAG_PROCESS_SHOW_TERMINATED);
    if(!cPidList) { return FALSE; }
    if(!(pPidList = LocalAlloc(LMEM_ZEROINIT, cPidList * sizeof(MSYSINFOPROC_TREE_ENTRY)))) { return FALSE; }
    while((iPidList < cPidList) && (pObProcess = VmmProcessGetNext(pObProcess, VMM_FLAG_PROCESS_SHOW_TERMINATED | VMM_FLAG_PROCESS_TOKEN))) {
        pPidEntry = pPidList + iPidList++;
        pPidEntry->dwPID = pObProcess->dwPID;
        pPidEntry->dwPPID = pObProcess->dwPPID;
        pPidEntry->pObProcess = (PVMM_PROCESS)Ob_INCREF(pObProcess);    // INCREF process object and assign to array
    }
    Ob_DECREF_NULL(&pObProcess);
    pb = LocalAlloc(0, cb);
    if(pb) {
        // 3: iterate over top level items - processes with no parent
        qsort(pPidList, cPidList, sizeof(MSYSINFOPROC_TREE_ENTRY), (int(*)(const void *, const void *))MSysInfoProc_Tree_CmpSort);
        o = snprintf(pb, cb, fVerbose ?
            "  Process                   Pid Parent  Flag User             Path / Command Line\n---------------------------------------------------------------------------------\n" :
            "  Process                   Pid Parent  Flag User             \n--------------------------------------------------------------\n");
        // 3.1 process items
        for(i = 0; i < cPidList; i++) {
            pPidEntry = pPidList + i;
            if(pPidEntry->fProcessed) { continue; }
            if(MSysInfoProc_Tree_ExistsUnprocessed(pPidList, (DWORD)cPidList, pPidEntry->dwPPID)) { continue; }
            o += MSysInfoProc_Tree_ProcessItems(pPidEntry, pPidList, (DWORD)cPidList, pb + o, cb - o, 0, fVerbose);
        }
        // 3.2 process remaining items (in case of PPID-loop which ideally should not happen)
        //     the remaining items are processed without regards for order.
        for(i = 0; i < cPidList; i++) {
            pPidEntry = pPidList + i;
            if(pPidEntry->fProcessed) { continue; }
            o += MSysInfoProc_Tree_ProcessItems(pPidEntry, pPidList, (DWORD)cPidList, pb + o, cb - o, 0, fVerbose);
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

VOID MSysInfoProc_ListTree_ProcessUserParams_CallbackAction(_In_ PVMM_PROCESS pProcess, _In_ PDWORD pcTotalBytes)
{
    PVMMWIN_USER_PROCESS_PARAMETERS pu = VmmWin_UserProcessParameters_Get(pProcess);
    DWORD c = MSYSINFOPROC_TREE_LINE_LENGTH_BASE + pProcess->pObPersistent->cuszPathKernel + 1;
    if(pu->uszImagePathName) {
        c += MSYSINFOPROC_TREE_LINE_LENGTH_BASE + pu->cuszImagePathName;
    }
    if(pu->uszCommandLine) {
        c += MSYSINFOPROC_TREE_LINE_LENGTH_BASE + pu->cuszCommandLine;
    }
    InterlockedAdd(pcTotalBytes, c);
}

NTSTATUS MSysInfoProc_Read(_In_ PVMMDLL_PLUGIN_CONTEXT ctx, _Out_writes_to_(cb, *pcbRead) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset)
{
    NTSTATUS nt;
    DWORD cbFile = 0;
    PBYTE pbFile = NULL;
    if(!wcscmp(ctx->wszPath, L"proc.txt")) {
        MSysInfoProc_Tree(FALSE, &pbFile, &cbFile);
        nt = Util_VfsReadFile_FromPBYTE(pbFile, cbFile, pb, cb, pcbRead, cbOffset);
        LocalFree(pbFile);
        return nt;
    }
    if(!wcscmp(ctx->wszPath, L"proc-v.txt")) {
        MSysInfoProc_Tree(TRUE, &pbFile, &cbFile);
        nt = Util_VfsReadFile_FromPBYTE(pbFile, cbFile, pb, cb, pcbRead, cbOffset);
        LocalFree(pbFile);
        return nt;
    }
    return VMMDLL_STATUS_FILE_INVALID;
}

BOOL MSysInfoProc_List(_In_ PVMMDLL_PLUGIN_CONTEXT ctx, _Inout_ PHANDLE pFileList)
{
    SIZE_T cProcess = 0;
    DWORD cbProcTree = 0;
    if(ctx->wszPath[0]) { return FALSE; }
    VmmProcessListPIDs(NULL, &cProcess, VMM_FLAG_PROCESS_SHOW_TERMINATED);
    if(cProcess) {
        cbProcTree = (DWORD)(cProcess + 2) * MSYSINFOPROC_TREE_LINE_LENGTH_BASE;
        VMMDLL_VfsList_AddFile(pFileList, L"proc.txt", cbProcTree, NULL);
        cbProcTree = MSYSINFOPROC_TREE_LINE_LENGTH_HEADER_VERBOSE * 2;
        VmmProcessActionForeachParallel(&cbProcTree, NULL, MSysInfoProc_ListTree_ProcessUserParams_CallbackAction);
        VMMDLL_VfsList_AddFile(pFileList, L"proc-v.txt", cbProcTree, NULL);
    }
    return TRUE;
}

VOID M_SysInfoProc_Initialize(_Inout_ PVMMDLL_PLUGIN_REGINFO pRI)
{
    if((pRI->magic != VMMDLL_PLUGIN_REGINFO_MAGIC) || (pRI->wVersion != VMMDLL_PLUGIN_REGINFO_VERSION)) { return; }
    if((pRI->tpSystem != VMM_SYSTEM_WINDOWS_X64) && (pRI->tpSystem != VMM_SYSTEM_WINDOWS_X86)) { return; }
    wcscpy_s(pRI->reg_info.wszPathName, 128, L"\\sysinfo\\proc");   // module name
    pRI->reg_info.fRootModule = TRUE;                               // module shows in root directory
    pRI->reg_fn.pfnList = MSysInfoProc_List;                        // List function supported
    pRI->reg_fn.pfnRead = MSysInfoProc_Read;                        // Read function supported
    pRI->pfnPluginManager_Register(pRI);
}
