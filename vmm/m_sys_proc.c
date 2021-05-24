// m_sys_proc.c : implementation related to the Sys/Proc built-in module.
//
// The '/sys/proc' module is responsible for displaying the process list
// as a tree structure together with various nice to have information at
// the path '/sys/proc/'
//
// (c) Ulf Frisk, 2020-2021
// Author: Ulf Frisk, pcileech@frizk.net
//
#include "vmm.h"
#include "vmmwin.h"
#include "charutil.h"
#include "util.h"

// ----------------------------------------------------------------------------
// ProcTree functionality below:
// NB! The proctree text files are re-generated for each read. This is not
// efficient, but the file is not read often so it should be OK.
// ----------------------------------------------------------------------------

#define MSYSPROC_TREE_LINE_LENGTH                   112
#define MSYSPROC_TREE_LINE_LENGTH_VERBOSE_BASE      64
#define MSYSPROC_TREE_LINE_LENGTH_VERBOSE_HEADER    85

const LPSTR szMSYSPROC_WHITELIST_WINDOWS_PATHS_AND_BINARIES[] = {
    "\\Windows\\System32\\",
    "\\Windows\\SystemApps\\",
    "\\Windows\\SysWOW64\\",
    "\\Windows\\explorer.exe",
    "\\Windows Defender\\MsMpEng.exe",
    "\\Windows Defender\\NisSrv.exe",
    "\\Microsoft\\OneDrive\\OneDrive.exe",
    "\\WINDOWS\\system32\\"
};

typedef struct tdMSYSPROC_TREE_ENTRY {
    DWORD dwPPID;
    DWORD dwPID;
    BYTE iLevel;
    BOOL fProcessed;
    PVMM_PROCESS pObProcess;
} MSYSPROC_TREE_ENTRY, *PMSYSPROC_TREE_ENTRY;

BOOL MSysProc_Tree_ExistsUnprocessed(PMSYSPROC_TREE_ENTRY pPidList, DWORD cPidList, DWORD dwPID)
{
    DWORD i;
    for(i = 0; i < cPidList; i++) {
        if(pPidList[i].dwPID == dwPID) {
            return !pPidList[i].fProcessed;
        }
    }
    return FALSE;
}

VOID MSysProc_Tree_ProcessItems_GetUserName(_In_ PVMM_PROCESS pProcess, _Out_writes_(17) LPSTR uszUserName, _Out_ PBOOL fAccountUser)
{
    BOOL f, fWellKnownAccount = FALSE;
    uszUserName[0] = 0;
    f = pProcess->win.TOKEN.fSID &&
        VmmWinUser_GetName(&pProcess->win.TOKEN.SID, uszUserName, 17, &fWellKnownAccount);
    *fAccountUser = f && !fWellKnownAccount;
}

DWORD MSysProc_Tree_ProcessItems(_In_ PMSYSPROC_TREE_ENTRY pProcessEntry, _In_ PMSYSPROC_TREE_ENTRY pList, _In_ DWORD cList, _In_ PBYTE pb, _In_ DWORD cb, _In_ BYTE iLevel, _In_ BOOL fVerbose)
{
    LPCSTR szINDENT[] = { "-", "--", "---", "----", "-----", "------", "-------", "--------", "--------+" };
    CHAR szUserName[17], szTimeCRE[24], szTimeEXIT[24];
    DWORD i, o = 0;
    BOOL fWinNativeProc, fStateTerminated, fAccountUser = FALSE;
    PVMMWIN_USER_PROCESS_PARAMETERS pu;
    if((cb > 0x01000000) || (cb < 0x00040000)) {
        vmmprintf_fn("WARNING: BUFFER MAY BE TOO SMALL - SHOULD NOT HAPPEN! %i\n", cb);
        return 0;
    }
    fStateTerminated = (pProcessEntry->pObProcess->dwState != 0);
    fWinNativeProc = (pProcessEntry->dwPID == 4) || (pProcessEntry->dwPPID == 4);
    for(i = 0; !fWinNativeProc && (i < (sizeof(szMSYSPROC_WHITELIST_WINDOWS_PATHS_AND_BINARIES) / sizeof(LPSTR))); i++) {
        fWinNativeProc = (NULL != strstr(pProcessEntry->pObProcess->pObPersistent->uszPathKernel, szMSYSPROC_WHITELIST_WINDOWS_PATHS_AND_BINARIES[i]));
    }
    MSysProc_Tree_ProcessItems_GetUserName(pProcessEntry->pObProcess, szUserName, &fAccountUser);
    Util_FileTime2String(VmmProcess_GetCreateTimeOpt(pProcessEntry->pObProcess), szTimeCRE);
    Util_FileTime2String(VmmProcess_GetExitTimeOpt(pProcessEntry->pObProcess), szTimeEXIT);
    if(!fVerbose) {
        // normal non-verbose file: 'proc.txt'
        o = snprintf(
            pb,
            cb,
            "%s %-15s%*s%6i %6i %s%c%c%c%c %-16s %s  %s\n",
            szINDENT[min(8, iLevel)],
            pProcessEntry->pObProcess->szName,
            8 - min(7, iLevel),
            "",
            pProcessEntry->dwPID,
            pProcessEntry->dwPPID,
            pProcessEntry->pObProcess->win.fWow64 ? "32" : "  ",
            pProcessEntry->pObProcess->win.EPROCESS.fNoLink ? 'E' : ' ',
            fStateTerminated ? 'T' : ' ',
            fAccountUser ? 'U' : ' ',
            fWinNativeProc ? ' ' : '*',
            szUserName,
            szTimeCRE,
            szTimeEXIT
        );
    } else {
        // verbose file: 'proc-v.txt'
        o = snprintf(
            pb,
            cb,
            "%s %-15s%*s%6i %6i %s%c%c%c%c %-16s %s\n",
            szINDENT[min(8, iLevel)],
            pProcessEntry->pObProcess->szName,
            8 - min(7, iLevel),
            "",
            pProcessEntry->dwPID,
            pProcessEntry->dwPPID,
            pProcessEntry->pObProcess->win.fWow64 ? "32" : "  ",
            pProcessEntry->pObProcess->win.EPROCESS.fNoLink ? 'E' : ' ',
            fStateTerminated ? 'T' : ' ',
            fAccountUser ? 'U' : ' ',
            fWinNativeProc ? ' ' : '*',
            szUserName,
            pProcessEntry->pObProcess->pObPersistent->uszPathKernel
        );
        pu = VmmWin_UserProcessParameters_Get(pProcessEntry->pObProcess);
        if(pu->cbuImagePathName > 1) {
            o += snprintf(pb + o, cb - o, "%63s%s\n", "", pu->uszImagePathName);
        }
        if(pu->cbuCommandLine > 1) {
            o += snprintf(pb + o, cb - o, "%63s%s\n", "", pu->uszCommandLine);
        }
        if(szTimeCRE[0] != ' ') {
            o += snprintf(pb + o, cb - o, "%63s%s -> %s\n", "", szTimeCRE, szTimeEXIT);
        }
        o += snprintf(pb + o, cb - o, "\n");
    }
    pProcessEntry->iLevel = iLevel;
    pProcessEntry->fProcessed = TRUE;
    // 2: fetch and process sub-items (child processes)
    for(i = 0; i < cList; i++) {
        if(pList[i].fProcessed) { continue; }
        if(pList[i].dwPPID == pProcessEntry->dwPID) {
            o += MSysProc_Tree_ProcessItems(pList + i, pList, cList, pb + o, cb - o, iLevel + 1, fVerbose);
        }
    }
    return o;
}

int MSysProc_Tree_CmpSort(PMSYSPROC_TREE_ENTRY a, PMSYSPROC_TREE_ENTRY b)
{
    if(a->dwPPID - b->dwPPID) {
        return a->dwPID - b->dwPID;
    }
    return a->dwPPID - b->dwPPID;
}

_Success_(return)
BOOL MSysProc_Tree(_In_ BOOL fVerbose, _Out_ PBYTE * ppb, _Out_ PDWORD pcb)
{
    BOOL fResult = FALSE;
    PVMM_PROCESS pObProcess = NULL;
    PMSYSPROC_TREE_ENTRY pPidEntry, pPidList = NULL;
    DWORD iPidList = 0, i;
    SIZE_T cPidList = 0;
    PBYTE pb;
    DWORD cb = 0x00100000, o = 0;   // 1MB should be enough to hold any process list ...
    // 1: retrieve process information into "pid list"
    VmmProcessListPIDs(NULL, &cPidList, VMM_FLAG_PROCESS_SHOW_TERMINATED);
    if(!cPidList) { return FALSE; }
    if(!(pPidList = LocalAlloc(LMEM_ZEROINIT, cPidList * sizeof(MSYSPROC_TREE_ENTRY)))) { return FALSE; }
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
        qsort(pPidList, cPidList, sizeof(MSYSPROC_TREE_ENTRY), (int(*)(const void *, const void *))MSysProc_Tree_CmpSort);
        o = snprintf(pb, cb, fVerbose ?
            "  Process                   Pid Parent   Flag User             Path / Command / Time\n------------------------------------------------------------------------------------\n" :
            "  Process                   Pid Parent   Flag User             Create Time              Exit Time              \n---------------------------------------------------------------------------------------------------------------\n");
        // 3.1 process items
        for(i = 0; i < cPidList; i++) {
            pPidEntry = pPidList + i;
            if(pPidEntry->fProcessed) { continue; }
            if(MSysProc_Tree_ExistsUnprocessed(pPidList, (DWORD)cPidList, pPidEntry->dwPPID)) { continue; }
            o += MSysProc_Tree_ProcessItems(pPidEntry, pPidList, (DWORD)cPidList, pb + o, cb - o, 0, fVerbose);
        }
        // 3.2 process remaining items (in case of PPID-loop which ideally should not happen)
        //     the remaining items are processed without regards for order.
        for(i = 0; i < cPidList; i++) {
            pPidEntry = pPidList + i;
            if(pPidEntry->fProcessed) { continue; }
            o += MSysProc_Tree_ProcessItems(pPidEntry, pPidList, (DWORD)cPidList, pb + o, cb - o, 0, fVerbose);
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

VOID MSysProc_ListTree_ProcessUserParams_CallbackAction(_In_ PVMM_PROCESS pProcess, _In_ PVOID ctx)
{
    PDWORD pcTotalBytes = (PDWORD)ctx;
    PVMMWIN_USER_PROCESS_PARAMETERS pu = VmmWin_UserProcessParameters_Get(pProcess);
    DWORD c = MSYSPROC_TREE_LINE_LENGTH_VERBOSE_BASE + pProcess->pObPersistent->cuszPathKernel + 1;
    if(pu->cbuImagePathName > 1) {
        c += MSYSPROC_TREE_LINE_LENGTH_VERBOSE_BASE + pu->cbuImagePathName - 1;
    }
    if(pu->cbuCommandLine > 1) {
        c += MSYSPROC_TREE_LINE_LENGTH_VERBOSE_BASE + pu->cbuCommandLine - 1;
    }
    if(VmmProcess_GetCreateTimeOpt(pProcess)) {
        c += MSYSPROC_TREE_LINE_LENGTH_VERBOSE_BASE + 23 + 4 + 23;
    }
    InterlockedAdd(pcTotalBytes, c);
}

NTSTATUS MSysProc_Read(_In_ PVMMDLL_PLUGIN_CONTEXT ctx, _Out_writes_to_(cb, *pcbRead) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset)
{
    NTSTATUS nt;
    DWORD cbFile = 0;
    PBYTE pbFile = NULL;
    if(!_stricmp(ctx->uszPath, "proc.txt")) {
        MSysProc_Tree(FALSE, &pbFile, &cbFile);
        nt = Util_VfsReadFile_FromPBYTE(pbFile, cbFile, pb, cb, pcbRead, cbOffset);
        LocalFree(pbFile);
        return nt;
    }
    if(!_stricmp(ctx->uszPath, "proc-v.txt")) {
        MSysProc_Tree(TRUE, &pbFile, &cbFile);
        nt = Util_VfsReadFile_FromPBYTE(pbFile, cbFile, pb, cb, pcbRead, cbOffset);
        LocalFree(pbFile);
        return nt;
    }
    return VMMDLL_STATUS_FILE_INVALID;
}

BOOL MSysProc_List(_In_ PVMMDLL_PLUGIN_CONTEXT ctx, _Inout_ PHANDLE pFileList)
{
    SIZE_T cProcess = 0;
    DWORD cbProcTree = 0;
    if(ctx->uszPath[0]) { return FALSE; }
    VmmProcessListPIDs(NULL, &cProcess, VMM_FLAG_PROCESS_SHOW_TERMINATED);
    if(cProcess) {
        cbProcTree = (DWORD)(cProcess + 2) * MSYSPROC_TREE_LINE_LENGTH;
        VMMDLL_VfsList_AddFile(pFileList, "proc.txt", cbProcTree, NULL);
        cbProcTree = MSYSPROC_TREE_LINE_LENGTH_VERBOSE_HEADER * 2;
        VmmProcessActionForeachParallel(&cbProcTree, NULL, MSysProc_ListTree_ProcessUserParams_CallbackAction);
        VMMDLL_VfsList_AddFile(pFileList, "proc-v.txt", cbProcTree, NULL);
    }
    return TRUE;
}

VOID M_SysProc_Initialize(_Inout_ PVMMDLL_PLUGIN_REGINFO pRI)
{
    if((pRI->magic != VMMDLL_PLUGIN_REGINFO_MAGIC) || (pRI->wVersion != VMMDLL_PLUGIN_REGINFO_VERSION)) { return; }
    if((pRI->tpSystem != VMM_SYSTEM_WINDOWS_X64) && (pRI->tpSystem != VMM_SYSTEM_WINDOWS_X86)) { return; }
    strcpy_s(pRI->reg_info.uszPathName, 128, "\\sys\\proc");    // module name
    pRI->reg_info.fRootModule = TRUE;                           // module shows in root directory
    pRI->reg_fn.pfnList = MSysProc_List;                        // List function supported
    pRI->reg_fn.pfnRead = MSysProc_Read;                        // Read function supported
    pRI->pfnPluginManager_Register(pRI);
}
