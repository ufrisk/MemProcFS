// m_virt2phys.c : implementation of the virt2phys built-in module.
//
// (c) Ulf Frisk, 2018-2021
// Author: Ulf Frisk, pcileech@frizk.net
//
#include "pluginmanager.h"
#include "util.h"
#include "vmm.h"

LPCSTR szMVIRT2PHYS_README =
    "Information about the virt2phys module                                       \n" \
    "======================================                                       \n" \
    "Write a virtual address (in hex) to the file 'virt'. If the virtual address  \n" \
    "is valid the other files in the directory will be populated as per below:    \n" \
    "- virt - the virtual address                                   [read-write]  \n" \
    "- map  - page map with info about paging structures            [read-only]   \n" \
    "- pt_* - 4kB pages with binary data containing page tables     [read-write]  \n" \
    "- page - the 4kB aligned virtual memory addressed by virt      [read-write]  \n" \
    "For more information please visit : https://github.com/ufrisk/MemProcFS/wiki \n";

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
NTSTATUS Virt2Phys_Read(_In_ PVMMDLL_PLUGIN_CONTEXT ctx, _Out_writes_to_(cb, *pcbRead) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset)
{
    BYTE iPML = 0;
    DWORD cbBuffer;
    PBYTE pbSourceData;
    BYTE pbBuffer[0x1000];
    PVMMOB_CACHE_MEM pObPT = NULL;
    PVMM_PROCESS pProcess = (PVMM_PROCESS)ctx->pProcess;
    VMM_VIRT2PHYS_INFORMATION Virt2PhysInfo = { 0 };
    Virt2PhysInfo.va = pProcess->pObPersistent->Plugin.vaVirt2Phys;
    VmmVirt2PhysGetInformation(pProcess, &Virt2PhysInfo);
    if(!_stricmp(ctx->uszPath, "readme.txt")) {
        return Util_VfsReadFile_FromPBYTE((PBYTE)szMVIRT2PHYS_README, strlen(szMVIRT2PHYS_README), pb, cb, pcbRead, cbOffset);
    }
    if(!_stricmp(ctx->uszPath, "virt.txt")) {
        switch(ctxVmm->tpMemoryModel) {
            case VMM_MEMORYMODEL_X64:
                return Util_VfsReadFile_FromQWORD(Virt2PhysInfo.va, pb, cb, pcbRead, cbOffset, FALSE);
            case VMM_MEMORYMODEL_X86:
            case VMM_MEMORYMODEL_X86PAE:
                return Util_VfsReadFile_FromDWORD((DWORD)Virt2PhysInfo.va, pb, cb, pcbRead, cbOffset, FALSE);
            default:
                return VMMDLL_STATUS_FILE_INVALID;
        }
    }
    if(!_stricmp(ctx->uszPath, "phys.txt")) {
        return Util_VfsReadFile_FromQWORD(Virt2PhysInfo.pas[0], pb, cb, pcbRead, cbOffset, FALSE);
    }
    if(!_stricmp(ctx->uszPath, "map.txt")) {
        switch(ctxVmm->tpMemoryModel) {
            case VMM_MEMORYMODEL_X64:
                cbBuffer = snprintf(
                    (LPSTR)pbBuffer,
                    0x1000,
                    "PML4 %016llx +%03x %016llx\n" \
                    "PDPT %016llx +%03x %016llx\n" \
                    "PD   %016llx +%03x %016llx\n" \
                    "PT   %016llx +%03x %016llx\n" \
                    "PAGE %016llx\n",
                    Virt2PhysInfo.pas[4], Virt2PhysInfo.iPTEs[4] << 3, Virt2PhysInfo.PTEs[4],
                    Virt2PhysInfo.pas[3], Virt2PhysInfo.iPTEs[3] << 3, Virt2PhysInfo.PTEs[3],
                    Virt2PhysInfo.pas[2], Virt2PhysInfo.iPTEs[2] << 3, Virt2PhysInfo.PTEs[2],
                    Virt2PhysInfo.pas[1], Virt2PhysInfo.iPTEs[1] << 3, Virt2PhysInfo.PTEs[1],
                    Virt2PhysInfo.pas[0]
                );
                break;
            case VMM_MEMORYMODEL_X86PAE:
                cbBuffer = snprintf(
                    (LPSTR)pbBuffer,
                    0x1000,
                    "PDPT %016llx +%03x %016llx\n" \
                    "PD   %016llx +%03x %016llx\n" \
                    "PT   %016llx +%03x %016llx\n" \
                    "PAGE %016llx\n",
                    Virt2PhysInfo.pas[3], Virt2PhysInfo.iPTEs[3] << 3, Virt2PhysInfo.PTEs[3],
                    Virt2PhysInfo.pas[2], Virt2PhysInfo.iPTEs[2] << 3, Virt2PhysInfo.PTEs[2],
                    Virt2PhysInfo.pas[1], Virt2PhysInfo.iPTEs[1] << 3, Virt2PhysInfo.PTEs[1],
                    Virt2PhysInfo.pas[0]
                );
                break;
            case VMM_MEMORYMODEL_X86:
                cbBuffer = snprintf(
                    (LPSTR)pbBuffer,
                    0x1000,
                    "PD   %016llx +%03x %08x\n" \
                    "PT   %016llx +%03x %08x\n" \
                    "PAGE %016llx\n",
                    Virt2PhysInfo.pas[2], Virt2PhysInfo.iPTEs[2] << 2, (DWORD)Virt2PhysInfo.PTEs[2],
                    Virt2PhysInfo.pas[1], Virt2PhysInfo.iPTEs[1] << 2, (DWORD)Virt2PhysInfo.PTEs[1],
                    Virt2PhysInfo.pas[0]
                );
                break;
            default:
                return VMMDLL_STATUS_FILE_INVALID;
        }
        return Util_VfsReadFile_FromPBYTE(pbBuffer, cbBuffer, pb, cb, pcbRead, cbOffset);
    }
    // "page table" or data page
    if(!_stricmp(ctx->uszPath, "pt_pml4.mem")) { iPML = 4; }
    if(!_stricmp(ctx->uszPath, "pt_pdpt.mem")) { iPML = 3; }
    if(!_stricmp(ctx->uszPath, "pt_pd.mem")) { iPML = 2; }
    if(!_stricmp(ctx->uszPath, "pt_pt.mem")) { iPML = 1; }
    if((ctxVmm->tpMemoryModel == VMM_MEMORYMODEL_X86) && (iPML > 2)) { return VMMDLL_STATUS_FILE_INVALID; }
    if((ctxVmm->tpMemoryModel == VMM_MEMORYMODEL_X86PAE) && (iPML > 3)) { return VMMDLL_STATUS_FILE_INVALID; }
    ZeroMemory(pbBuffer, 0x1000);
    pbSourceData = pbBuffer;
    if(iPML && (Virt2PhysInfo.pas[iPML] & ~0xfff)) {
        pObPT = VmmTlbGetPageTable(Virt2PhysInfo.pas[iPML] & ~0xfff, FALSE);
        if(pObPT) {
            memcpy(pbSourceData, pObPT->pb, 0x1000);
            Ob_DECREF(pObPT);
            pObPT = NULL;
        }
    }
    if(!_stricmp(ctx->uszPath, "page.mem") && (Virt2PhysInfo.pas[0] & ~0xfff)) {
        VmmReadPage(NULL, Virt2PhysInfo.pas[0] & ~0xfff, pbBuffer);
    }
    if(iPML || !_stricmp(ctx->uszPath, "page.mem")) {
        return Util_VfsReadFile_FromPBYTE(pbSourceData, 0x1000, pb, cb, pcbRead, cbOffset);
    }
    return VMMDLL_STATUS_FILE_INVALID;
}

/*
* Write to the "virt" virtual file - update stored persistent address.
* -- ctx
* -- pb
* -- cb
* -- pcbWrite
* -- cbOffset
* -- return
*/
NTSTATUS Virt2Phys_WriteVA(_In_ PVMMDLL_PLUGIN_CONTEXT ctx, _In_reads_(cb) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbWrite, _In_ QWORD cbOffset)
{
    PVMM_PROCESS pProcess = (PVMM_PROCESS)ctx->pProcess;
    CHAR szBuffer[17];
    VMM_MEMORYMODEL_TP tp = ctxVmm->tpMemoryModel;
    if((tp == VMM_MEMORYMODEL_X64) && (cbOffset < 16)) {
        *pcbWrite = cb;
        snprintf(szBuffer, 17, "%016llx", pProcess->pObPersistent->Plugin.vaVirt2Phys);
        cb = (DWORD)min(16 - cbOffset, cb);
        memcpy(szBuffer + cbOffset, pb, cb);
        szBuffer[16] = 0;
        pProcess->pObPersistent->Plugin.vaVirt2Phys = strtoull(szBuffer, NULL, 16);
    } else if ((tp == VMM_MEMORYMODEL_X86) || (tp == VMM_MEMORYMODEL_X86PAE)) {
        *pcbWrite = cb;
        snprintf(szBuffer, 9, "%08x", (DWORD)pProcess->pObPersistent->Plugin.vaVirt2Phys);
        cb = (DWORD)min(8 - cbOffset, cb);
        memcpy(szBuffer + cbOffset, pb, cb);
        szBuffer[8] = 0;
        pProcess->pObPersistent->Plugin.vaVirt2Phys = strtoul(szBuffer, NULL, 16);
    } else {
        *pcbWrite = 0;
    }
    return VMMDLL_STATUS_SUCCESS;
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
NTSTATUS Virt2Phys_Write(_In_ PVMMDLL_PLUGIN_CONTEXT ctx, _In_reads_(cb) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbWrite, _In_ QWORD cbOffset)
{
    DWORD i;
    PVMM_PROCESS pProcess = (PVMM_PROCESS)ctx->pProcess;
    VMM_VIRT2PHYS_INFORMATION Virt2PhysInfo = { 0 };
    if(!_stricmp(ctx->uszPath, "virt.txt")) {
        return Virt2Phys_WriteVA(ctx, pb, cb, pcbWrite, cbOffset);
    }
    Virt2PhysInfo.va = pProcess->pObPersistent->Plugin.vaVirt2Phys;
    VmmVirt2PhysGetInformation(pProcess, &Virt2PhysInfo);
    i = 0xff;
    if(!_stricmp(ctx->uszPath, "pt_pml4.mem")) { i = 4; }
    if(!_stricmp(ctx->uszPath, "pt_pdpt.mem")) { i = 3; }
    if(!_stricmp(ctx->uszPath, "pt_pd.mem")) { i = 2; }
    if(!_stricmp(ctx->uszPath, "pt_pt.mem")) { i = 1; }
    if(!_stricmp(ctx->uszPath, "page.mem")) { i = 0; }
    if(i > 4) { return VMMDLL_STATUS_FILE_INVALID; }
    if(Virt2PhysInfo.pas[i] < 0x1000) { return VMMDLL_STATUS_FILE_INVALID; }
    if(cbOffset > 0x1000) { return VMMDLL_STATUS_END_OF_FILE; }
    *pcbWrite = (DWORD)min(cb, 0x1000 - cbOffset);
    VmmWrite(NULL, Virt2PhysInfo.pas[i] + cbOffset, pb, *pcbWrite);
    return *pcbWrite ? VMMDLL_STATUS_SUCCESS : VMMDLL_STATUS_END_OF_FILE;
}

/*
* List : function as specified by the module manager. The module manager will
* call into this callback function whenever a list directory shall occur from
* the given module.
* -- ctx
* -- pFileList
* -- return
*/
BOOL Virt2Phys_List(_In_ PVMMDLL_PLUGIN_CONTEXT ctx, _Inout_ PHANDLE pFileList)
{
    if(ctx->uszPath[0]) {
        // only list in module root directory.
        // not root directory == error for this module.
        return FALSE;
    }
    switch(ctxVmm->tpMemoryModel) {
        case VMM_MEMORYMODEL_X64:
            VMMDLL_VfsList_AddFile(pFileList, "virt.txt", 16, NULL);
            VMMDLL_VfsList_AddFile(pFileList, "phys.txt", 16, NULL);
            VMMDLL_VfsList_AddFile(pFileList, "map.txt", 198, NULL);
            VMMDLL_VfsList_AddFile(pFileList, "pt_pml4.mem", 0x1000, NULL);
            VMMDLL_VfsList_AddFile(pFileList, "pt_pdpt.mem", 0x1000, NULL);
            VMMDLL_VfsList_AddFile(pFileList, "pt_pd.mem", 0x1000, NULL);
            VMMDLL_VfsList_AddFile(pFileList, "pt_pt.mem", 0x1000, NULL);
            VMMDLL_VfsList_AddFile(pFileList, "page.mem", 0x1000, NULL);
            break;
        case VMM_MEMORYMODEL_X86PAE:
            VMMDLL_VfsList_AddFile(pFileList, "virt.txt", 8, NULL);
            VMMDLL_VfsList_AddFile(pFileList, "phys.txt", 16, NULL);
            VMMDLL_VfsList_AddFile(pFileList, "map.txt", 154, NULL);
            VMMDLL_VfsList_AddFile(pFileList, "pt_pdpt.mem", 0x1000, NULL);
            VMMDLL_VfsList_AddFile(pFileList, "pt_pd.mem", 0x1000, NULL);
            VMMDLL_VfsList_AddFile(pFileList, "pt_pt.mem", 0x1000, NULL);
            VMMDLL_VfsList_AddFile(pFileList, "page.mem", 0x1000, NULL);
            break;
        case VMM_MEMORYMODEL_X86:
            VMMDLL_VfsList_AddFile(pFileList, "virt.txt", 8, NULL);
            VMMDLL_VfsList_AddFile(pFileList, "phys.txt", 16, NULL);
            VMMDLL_VfsList_AddFile(pFileList, "map.txt", 94, NULL);
            VMMDLL_VfsList_AddFile(pFileList, "pt_pd.mem", 0x1000, NULL);
            VMMDLL_VfsList_AddFile(pFileList, "pt_pt.mem", 0x1000, NULL);
            VMMDLL_VfsList_AddFile(pFileList, "page.mem", 0x1000, NULL);
            break;
        default:
            return FALSE;
    }
    VMMDLL_VfsList_AddFile(pFileList, "readme.txt", strlen(szMVIRT2PHYS_README), NULL);
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
VOID M_Virt2Phys_Initialize(_Inout_ PVMMDLL_PLUGIN_REGINFO pRI)
{
    if((pRI->magic != VMMDLL_PLUGIN_REGINFO_MAGIC) || (pRI->wVersion != VMMDLL_PLUGIN_REGINFO_VERSION)) { return; }
    if(!((pRI->tpMemoryModel == VMM_MEMORYMODEL_X64) || (pRI->tpMemoryModel == VMM_MEMORYMODEL_X86) || (pRI->tpMemoryModel == VMM_MEMORYMODEL_X86PAE))) { return; }
    strcpy_s(pRI->reg_info.uszPathName, 128, "\\virt2phys");             // module name
    pRI->reg_info.fProcessModule = TRUE;                                 // module shows in process directory
    pRI->reg_fn.pfnList = Virt2Phys_List;                                // List function supported
    pRI->reg_fn.pfnRead = Virt2Phys_Read;                                // Read function supported
    pRI->reg_fn.pfnWrite = Virt2Phys_Write;                              // Write function supported
    pRI->pfnPluginManager_Register(pRI);
}
