// m_phys2virt.c : implementation of the phys2virt built-in module.
//
// (c) Ulf Frisk, 2019-2021
// Author: Ulf Frisk, pcileech@frizk.net
//
#include "pluginmanager.h"
#include "util.h"
#include "vmm.h"

LPCSTR szMPHYS2VIRT_README =
    "Information about the phys2virt module                                       \n" \
    "======================================                                       \n" \
    "Write a physical address (in hex) to the file 'phys'.  Writing will trigger a\n" \
    "scan of process page tables for corresponding virtual addresses.   Up to four\n" \
    "virtual addresses which map to physical address will be presented in the file\n" \
    "'virt' (per process).                                                        \n" \
    "The phys2virt module may take time to execute  - especially if using the root\n" \
    "module (scan all process page tables) instead of individual processes.       \n" \
    "For more information please visit: https://github.com/ufrisk/MemProcFS/wiki  \n";

typedef struct tdM_PHYS2VIRT_MULTIENTRY {
    DWORD dwPID;
    QWORD va;
} M_PHYS2VIRT_MULTIENTRY, *PM_PHYS2VIRT_MULTIENTRY;

typedef struct tdM_PHYS2VIRT_MULTIENTRY_CONTEXT {
    QWORD pa;
    DWORD c;
    DWORD cMax;
    M_PHYS2VIRT_MULTIENTRY e[0];
} M_PHYS2VIRT_MULTIENTRY_CONTEXT, *PM_PHYS2VIRT_MULTIENTRY_CONTEXT;

VOID Phys2Virt_GetUpdateAll_CallbackAction(_In_ PVMM_PROCESS pProcess, _In_opt_ PVOID ctxIn)
{
    PM_PHYS2VIRT_MULTIENTRY_CONTEXT ctx = (PM_PHYS2VIRT_MULTIENTRY_CONTEXT)ctxIn;
    DWORD i, j;
    PVMMOB_PHYS2VIRT_INFORMATION pObPhys2Virt = NULL;
    if(!ctx) { return; }
    pObPhys2Virt = VmmPhys2VirtGetInformation(pProcess, ctx->pa);
    if(!pObPhys2Virt) { return; }
    for(j = 0; j < pObPhys2Virt->cvaList; j++) {
        if(pObPhys2Virt->pvaList[j]) {
            i = InterlockedIncrement(&ctx->c);
            if(i < ctx->cMax) {
                ctx->e[i].dwPID = pProcess->dwPID;
                ctx->e[i].va = pObPhys2Virt->pvaList[j];
            }
        }
    }
    Ob_DECREF(pObPhys2Virt);
}

/*
* CALLER LocalFree: ppMultiEntry
*/
_Success_(return)
BOOL Phys2Virt_GetUpdateAll(_Out_opt_ PM_PHYS2VIRT_MULTIENTRY_CONTEXT *ppMultiEntry, _Out_opt_ PDWORD pcMultiEntry)
{
    PM_PHYS2VIRT_MULTIENTRY_CONTEXT ctx = NULL;
    SIZE_T cPIDs = 0;
    VmmProcessListPIDs(NULL, &cPIDs, 0);
    ctx = LocalAlloc(LMEM_ZEROINIT, sizeof(M_PHYS2VIRT_MULTIENTRY_CONTEXT) + cPIDs * 4 * sizeof(M_PHYS2VIRT_MULTIENTRY));
    if(!ctx) { return FALSE; }
    ctx->pa = ctxVmm->paPluginPhys2VirtRoot;
    ctx->cMax = (DWORD)cPIDs * 4;
    VmmProcessActionForeachParallel(ctx, VmmProcessActionForeachParallel_CriteriaActiveOnly, Phys2Virt_GetUpdateAll_CallbackAction);
    ctx->c = min(ctx->c, ctx->cMax - 1);
    if(pcMultiEntry) { *pcMultiEntry = ctx->c; }
    if(ppMultiEntry) {
        *ppMultiEntry = ctx;
    } else {
        LocalFree(ctx);
    }
    return TRUE;
}

/*
* qsort compare function for sorting the resulting Phys2Virt virtual addresses and PIDs
* after a scan of all process virtual address spaces from the root module.
*/
int Phys2Virt_ReadVirtRoot_CmpSort(PM_PHYS2VIRT_MULTIENTRY a, PM_PHYS2VIRT_MULTIENTRY b)
{
    if(a->dwPID == b->dwPID) {
        return (a->va > b->va) ? 1 : -1;
    }
    return a->dwPID - b->dwPID;
}

NTSTATUS Phys2Virt_ReadVirtRoot(_Out_ PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset)
{
    NTSTATUS nt = VMMDLL_STATUS_FILE_INVALID;
    DWORD i, cbBuffer = 0, cbBufferMax;
    PBYTE pbBuffer = NULL;
    PM_PHYS2VIRT_MULTIENTRY_CONTEXT ctx = NULL;
    if(Phys2Virt_GetUpdateAll(&ctx, NULL)) {
        cbBufferMax = 24 * ctx->c + 0x10;
        pbBuffer = LocalAlloc(0, cbBufferMax);
        if(pbBuffer) {
            if(ctx->c > 1) {
                qsort(ctx->e + 1, ctx->c - 1, sizeof(M_PHYS2VIRT_MULTIENTRY), (_CoreCrtNonSecureSearchSortCompareFunction)Phys2Virt_ReadVirtRoot_CmpSort);
            }
            for(i = 1; i <= ctx->c; i++) {
                cbBuffer += snprintf(
                    pbBuffer + cbBuffer,
                    cbBufferMax - cbBuffer,
                    ctxVmm->f32 ? "%6i %08llx\n" : "%6i %016llx\n",
                    ctx->e[i].dwPID,
                    ctx->e[i].va
                );
            }
            nt = Util_VfsReadFile_FromPBYTE(pbBuffer, cbBuffer, pb, cb, pcbRead, cbOffset);
        }
    }
    LocalFree(ctx);
    LocalFree(pbBuffer);
    return nt;
}

/*
* Read the virtual address file with up to PHYS2VIRT_MAX_NUMBER_ADDRESS entries.
* -- pProcess
* -- pb
* -- cb
* -- pcbRead
* -- cbOffset
* -- return
*/
NTSTATUS Phys2Virt_ReadVirtProcess(_In_ PVMM_PROCESS pProcess, _Out_ PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset)
{
    DWORD i;
    DWORD cbBuffer = 0, cbBufferMax = 0x10 + VMM_PHYS2VIRT_INFORMATION_MAX_PROCESS_RESULT * 17;
    BYTE pbBuffer[0x10 + VMM_PHYS2VIRT_INFORMATION_MAX_PROCESS_RESULT * 17] = { 0 };
    PVMMOB_PHYS2VIRT_INFORMATION pObPhys2Virt = NULL;
    // 1: retrieve / start update of PVMMOB_PHYS2VIRT_INFORMATION in a thread-safe way.
    pObPhys2Virt = VmmPhys2VirtGetInformation(pProcess, 0);
    // 2: show result
    if(pObPhys2Virt) {
        for(i = 0; i < pObPhys2Virt->cvaList; i++) {
            cbBuffer += snprintf(
                pbBuffer + cbBuffer,
                cbBufferMax - cbBuffer,
                ctxVmm->f32 ? "%08llx\n" : "%016llx\n",
                pObPhys2Virt->pvaList[i]
            );
        }
    }
    Ob_DECREF_NULL(&pObPhys2Virt);
    return Util_VfsReadFile_FromPBYTE(pbBuffer, cbBuffer, pb, cb, pcbRead, cbOffset);
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
NTSTATUS Phys2Virt_Read(_In_ PVMMDLL_PLUGIN_CONTEXT ctx, _Out_writes_to_(cb, *pcbRead) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset)
{
    NTSTATUS nt;
    PVMMOB_PHYS2VIRT_INFORMATION pObPhys2Virt = NULL;
    PVMM_PROCESS pProcess = (PVMM_PROCESS)ctx->pProcess;
    if(!_stricmp(ctx->uszPath, "readme.txt")) {
        return Util_VfsReadFile_FromPBYTE((PBYTE)szMPHYS2VIRT_README, strlen(szMPHYS2VIRT_README), pb, cb, pcbRead, cbOffset);
    }
    if(pProcess) {
        if(!_stricmp(ctx->uszPath, "phys.txt")) {
            pObPhys2Virt = VmmPhys2VirtGetInformation(pProcess, 0);
            nt = Util_VfsReadFile_FromQWORD((pObPhys2Virt ? pObPhys2Virt->paTarget : 0), pb, cb, pcbRead, cbOffset, FALSE);
            Ob_DECREF_NULL(&pObPhys2Virt);
            return nt;
        }
        if(!_stricmp(ctx->uszPath, "virt.txt")) {
            return Phys2Virt_ReadVirtProcess(pProcess, pb, cb, pcbRead, cbOffset);
        }
    } else {
        if(!_stricmp(ctx->uszPath, "phys.txt")) {
            return Util_VfsReadFile_FromQWORD(ctxVmm->paPluginPhys2VirtRoot, pb, cb, pcbRead, cbOffset, FALSE);
        }
        if(!_stricmp(ctx->uszPath, "virt.txt")) {
            return Phys2Virt_ReadVirtRoot(pb, cb, pcbRead, cbOffset);
        }
    }
    return VMMDLL_STATUS_FILE_INVALID;
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
NTSTATUS Phys2Virt_Write(_In_ PVMMDLL_PLUGIN_CONTEXT ctx, _In_reads_(cb) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbWrite, _In_ QWORD cbOffset)
{
    BYTE pbBuffer[17];
    PVMM_PROCESS pProcess = (PVMM_PROCESS)ctx->pProcess;
    *pcbWrite = 0;
    if(!_stricmp(ctx->uszPath, "phys.txt")) {
        if(cbOffset < 16) {
            *pcbWrite = cb;
            memcpy(pbBuffer, "0000000000000000", 16);
            cb = (DWORD)min(16 - cbOffset, cb);
            memcpy(pbBuffer + cbOffset, pb, cb);
            pbBuffer[16] = 0;
            if(pProcess) {
                Ob_DECREF(VmmPhys2VirtGetInformation(pProcess, strtoull(pbBuffer, NULL, 16)));
            } else {
                ctxVmm->paPluginPhys2VirtRoot = strtoull(pbBuffer, NULL, 16);
                Phys2Virt_GetUpdateAll(NULL, NULL);
            }
        }
        return *pcbWrite ? VMMDLL_STATUS_SUCCESS : VMMDLL_STATUS_END_OF_FILE;
    }
    return VMMDLL_STATUS_FILE_INVALID;  // only 'phys' file is writable
}

/*
* List : function as specified by the module manager. The module manager will
* call into this callback function whenever a list directory shall occur from
* the given module.
* -- ctx
* -- pFileList
* -- return
*/
BOOL Phys2Virt_List(_In_ PVMMDLL_PLUGIN_CONTEXT ctx, _Inout_ PHANDLE pFileList)
{
    DWORD c = 0, cb;
    PVMMOB_PHYS2VIRT_INFORMATION pObPhys2Virt = NULL;
    PVMM_PROCESS pProcess = (PVMM_PROCESS)ctx->pProcess;
    if(ctx->uszPath[0]) { return FALSE; }
    if(pProcess) {
        // process context
        pObPhys2Virt = VmmPhys2VirtGetInformation(pProcess, 0);
        cb = !pObPhys2Virt ? 0 : pObPhys2Virt->cvaList * (1 + (ctxVmm->f32 ? 8 : 16));
        Ob_DECREF(pObPhys2Virt);
    } else {
        // root context
        Phys2Virt_GetUpdateAll(NULL, &c);
        cb = c * (8 + (ctxVmm->f32 ? 8 : 16));
    }
    VMMDLL_VfsList_AddFile(pFileList, "readme.txt", strlen(szMPHYS2VIRT_README), NULL);
    VMMDLL_VfsList_AddFile(pFileList, "phys.txt", 16, NULL);
    VMMDLL_VfsList_AddFile(pFileList, "virt.txt", cb, NULL);
    return TRUE;
}

/*
* Initialization function. The module manager shall call into this function
* when the module shall be initialized. If the module wish to initialize it
* shall call the supplied pfnPluginManager_Register function.
* NB! the module does not have to register itself - for example if the target
* operating system or architecture is unsupported.
* -- pRI
*/
VOID M_Phys2Virt_Initialize(_Inout_ PVMMDLL_PLUGIN_REGINFO pRI)
{
    if((pRI->magic != VMMDLL_PLUGIN_REGINFO_MAGIC) || (pRI->wVersion != VMMDLL_PLUGIN_REGINFO_VERSION)) { return; }
    if(!((pRI->tpMemoryModel == VMM_MEMORYMODEL_X64) || (pRI->tpMemoryModel == VMM_MEMORYMODEL_X86) || (pRI->tpMemoryModel == VMM_MEMORYMODEL_X86PAE))) { return; }
    pRI->reg_fn.pfnList = Phys2Virt_List;                                // List function supported
    pRI->reg_fn.pfnRead = Phys2Virt_Read;                                // Read function supported
    pRI->reg_fn.pfnWrite = Phys2Virt_Write;                              // Write function supported
    // register process plugin
    strcpy_s(pRI->reg_info.uszPathName, 128, "\\phys2virt");
    pRI->reg_info.fRootModule = FALSE;
    pRI->reg_info.fProcessModule = TRUE;
    pRI->pfnPluginManager_Register(pRI);
    // register root plugin
    strcpy_s(pRI->reg_info.uszPathName, 128, "\\misc\\phys2virt");
    pRI->reg_info.fRootModule = TRUE;
    pRI->reg_info.fProcessModule = FALSE;
    pRI->pfnPluginManager_Register(pRI);
}
