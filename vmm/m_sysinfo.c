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
#include "m_sysinfo.h"
#include "vmm.h"
#include "vmmwin.h"
#include "util.h"

// ----------------------------------------------------------------------------
// ProcTree functionality below:
// The proctree.txt file is re-generated for each read. This is not efficient,
// but the file is not read often so it should be OK.
// ----------------------------------------------------------------------------

#define MSYSINFO_PROCTREE_LINE_LENGTH_BASE              45
#define MSYSINFO_PROCTREE_LINE_LENGTH_HEADER_VERBOSE    64

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
    LPCSTR szINDENT[] = { "-", "--", "---", "----", "-----", "------", "-------", "------+" };
    DWORD i, o = 0;
    BOOL fWinNativeProc, fStateTerminated;
    if((cb > 0x01000000) || (cb < 0x00040000)) {
        vmmprintf_fn("WARNING: BUFFER MAY BE TOO SMALL - SHOULD NOT HAPPEN! %i\n", cb);
        return 0;
    }
    fStateTerminated = (pProcessEntry->pObProcess->dwState != 0);
    fWinNativeProc =
        (pProcessEntry->dwPID == 4) || (pProcessEntry->dwPPID == 4) ||
        strstr(pProcessEntry->pObProcess->pObProcessPersistent->szPathKernel, "\\Windows\\System32\\")  ||
        strstr(pProcessEntry->pObProcess->pObProcessPersistent->szPathKernel, "\\Windows\\SystemApps\\")  ||
        strstr(pProcessEntry->pObProcess->pObProcessPersistent->szPathKernel, "\\Windows\\explorer.exe") ||
        strstr(pProcessEntry->pObProcess->pObProcessPersistent->szPathKernel, "\\Windows Defender\\MsMpEng.exe") ||
        strstr(pProcessEntry->pObProcess->pObProcessPersistent->szPathKernel, "\\Windows Defender\\NisSrv.exe") ||
        strstr(pProcessEntry->pObProcess->pObProcessPersistent->szPathKernel, "\\Microsoft\\OneDrive\\OneDrive.exe") ||
        strstr(pProcessEntry->pObProcess->pObProcessPersistent->szPathKernel, "\\WINDOWS\\system32\\");
    o = snprintf(
            pb,
            cb,
            " %s %-15s%*s%6i %6i   %c%c %s\n",
            szINDENT[min(7, iLevel)],
            pProcessEntry->pObProcess->szName,
            7 - min(7, iLevel),
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
            "   Process                  Pid Parent Flag Path / Command Line\n---------------------------------------------------------------\n" :
            "   Process                  Pid Parent Flag \n--------------------------------------------\n");
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

// ----------------------------------------------------------------------------
// GENERAL FUNCTIONALITY BELOW:
// ----------------------------------------------------------------------------

NTSTATUS MSysInfo_Read(_In_ PVMMDLL_PLUGIN_CONTEXT ctx, _Out_ PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset)
{
    NTSTATUS nt;
    BYTE pbBuffer[64];
    DWORD cbBuffer;
    PBYTE pbFile = NULL;
    DWORD cbFile = 0;
    // proclist.txt
    if(!strcmp(ctx->szPath, "proctree")) {
        MSysInfo_ProcTree(FALSE, &pbFile, &cbFile);
        nt = Util_VfsReadFile_FromPBYTE(pbFile, cbFile, pb, cb, pcbRead, cbOffset);
        LocalFree(pbFile);
        return nt;
    }
    if(!strcmp(ctx->szPath, "proctree-v")) {
        MSysInfo_ProcTree(TRUE, &pbFile, &cbFile);
        nt = Util_VfsReadFile_FromPBYTE(pbFile, cbFile, pb, cb, pcbRead, cbOffset);
        LocalFree(pbFile);
        return nt;
    }
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
    return VMMDLL_STATUS_FILE_INVALID;
}

VOID MSysInfo_List_ProcessUserParams_CallbackAction(_In_ PVMM_PROCESS pProcess, _In_ PDWORD pcTotalBytes)
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

BOOL MSysInfo_List(_In_ PVMMDLL_PLUGIN_CONTEXT ctx, _Inout_ PHANDLE pFileList)
{
    SIZE_T cProcess = 0;
    DWORD cchMajor, cchMinor, cchBuild;
    DWORD cbProcTree = 0;
    if(ctx->szPath[0]) { return FALSE; }
    // proclist.txt
    VmmProcessListPIDs(NULL, &cProcess, VMM_FLAG_PROCESS_SHOW_TERMINATED);
    if(cProcess) {
        cbProcTree = (DWORD)(cProcess + 2) * MSYSINFO_PROCTREE_LINE_LENGTH_BASE;
        VMMDLL_VfsList_AddFile(pFileList, "proctree", cbProcTree);
        cbProcTree = MSYSINFO_PROCTREE_LINE_LENGTH_HEADER_VERBOSE * 2;
        VmmProcessActionForeachParallel(&cbProcTree, 5, NULL, MSysInfo_List_ProcessUserParams_CallbackAction);
        VMMDLL_VfsList_AddFile(pFileList, "proctree-v", cbProcTree);
    }
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

VOID M_SysInfo_Initialize(_Inout_ PVMMDLL_PLUGIN_REGINFO pRI)
{
    if((pRI->magic != VMMDLL_PLUGIN_REGINFO_MAGIC) || (pRI->wVersion != VMMDLL_PLUGIN_REGINFO_VERSION)) { return; }
    if((pRI->tpSystem != VMM_SYSTEM_WINDOWS_X64) && (pRI->tpSystem != VMM_SYSTEM_WINDOWS_X86)) { return; }
    strcpy_s(pRI->reg_info.szModuleName, 32, "sysinfo");    // module name
    pRI->reg_info.fRootModule = TRUE;                       // module shows in root directory
    pRI->reg_fn.pfnList = MSysInfo_List;                    // List function supported
    pRI->reg_fn.pfnRead = MSysInfo_Read;                    // Read function supported
    pRI->pfnPluginManager_Register(pRI);
}
