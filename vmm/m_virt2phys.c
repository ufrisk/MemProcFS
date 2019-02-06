// m_virt2phys.c : implementation of the virt2phys built-in module.
//
// (c) Ulf Frisk, 2018-2019
// Author: Ulf Frisk, pcileech@frizk.net
//
#include "m_virt2phys.h"
#include "pluginmanager.h"
#include "util.h"
#include "vmm.h"
#include "vmmvfs.h"

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
NTSTATUS Virt2Phys_Read(_In_ PVMMDLL_PLUGIN_CONTEXT ctx, _Out_ LPVOID pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset)
{
    BYTE iPML = 0;
    DWORD cbBuffer;
    PBYTE pbSourceData;
    BYTE pbBuffer[0x1000];
    PVMMOB_MEM pObPT = NULL;
    PVMM_PROCESS pProcess = (PVMM_PROCESS)ctx->pProcess;
    VMM_VIRT2PHYS_INFORMATION Virt2PhysInfo = { 0 };
    Virt2PhysInfo.va = pProcess->pObProcessPersistent->Plugin.vaVirt2Phys;
    VmmVirt2PhysGetInformation(pProcess, &Virt2PhysInfo);
    if(!_stricmp(ctx->szPath, "virt")) {
        switch(ctxVmm->tpMemoryModel) {
            case VMM_MEMORYMODEL_X64:
                return Util_VfsReadFile_FromQWORD(Virt2PhysInfo.va, pb, cb, pcbRead, cbOffset, FALSE);
                break;
            case VMM_MEMORYMODEL_X86:
            case VMM_MEMORYMODEL_X86PAE:
                return Util_VfsReadFile_FromDWORD((DWORD)Virt2PhysInfo.va, pb, cb, pcbRead, cbOffset, FALSE);
                break;
        }
    }
    if(!_stricmp(ctx->szPath, "phys")) {
        return Util_VfsReadFile_FromQWORD(Virt2PhysInfo.pas[0], pb, cb, pcbRead, cbOffset, FALSE);
    }
    if(!_stricmp(ctx->szPath, "map")) {
        switch(ctxVmm->tpMemoryModel) {
            case VMM_MEMORYMODEL_X64:
                cbBuffer = snprintf(
                    pbBuffer,
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
                    pbBuffer,
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
                    pbBuffer,
                    0x1000,
                    "PD   %016llx +%03x %08x\n" \
                    "PT   %016llx +%03x %08x\n" \
                    "PAGE %016llx\n",
                    Virt2PhysInfo.pas[2], Virt2PhysInfo.iPTEs[2] << 2, (DWORD)Virt2PhysInfo.PTEs[2],
                    Virt2PhysInfo.pas[1], Virt2PhysInfo.iPTEs[1] << 2, (DWORD)Virt2PhysInfo.PTEs[1],
                    Virt2PhysInfo.pas[0]
                );
                break;
        }
        return Util_VfsReadFile_FromPBYTE(pbBuffer, cbBuffer, pb, cb, pcbRead, cbOffset);
    }
    // "page table" or data page
    if(!_stricmp(ctx->szPath, "pt_pml4")) { iPML = 4; }
    if(!_stricmp(ctx->szPath, "pt_pdpt")) { iPML = 3; }
    if(!_stricmp(ctx->szPath, "pt_pd")) { iPML = 2; }
    if(!_stricmp(ctx->szPath, "pt_pt")) { iPML = 1; }
    if((ctxVmm->tpMemoryModel == VMM_MEMORYMODEL_X86) && (iPML > 2)) { return VMMDLL_STATUS_FILE_INVALID; }
    if((ctxVmm->tpMemoryModel == VMM_MEMORYMODEL_X86PAE) && (iPML > 3)) { return VMMDLL_STATUS_FILE_INVALID; }
    ZeroMemory(pbBuffer, 0x1000);
    pbSourceData = pbBuffer;
    if(iPML && (Virt2PhysInfo.pas[iPML] & ~0xfff)) {
        pObPT = VmmTlbGetPageTable(Virt2PhysInfo.pas[iPML] & ~0xfff, FALSE);
        if(pObPT) {
            memcpy(pbSourceData, pObPT->pb, 0x1000);
            VmmOb_DECREF(pObPT);
            pObPT = NULL;
        }
    }
    if(!_stricmp(ctx->szPath, "page") && (Virt2PhysInfo.pas[0] & ~0xfff)) {
        VmmReadPhysicalPage(Virt2PhysInfo.pas[0] & ~0xfff, pbBuffer);
    }
    if(iPML || !_stricmp(ctx->szPath, "page")) {
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
NTSTATUS Virt2Phys_WriteVA(_In_ PVMMDLL_PLUGIN_CONTEXT ctx, _In_ LPVOID pb, _In_ DWORD cb, _Out_ PDWORD pcbWrite, _In_ QWORD cbOffset)
{
    PVMM_PROCESS pProcess = (PVMM_PROCESS)ctx->pProcess;
    BYTE pbBuffer[17];
    VMM_MEMORYMODEL_TP tp = ctxVmm->tpMemoryModel;
    if((tp == VMM_MEMORYMODEL_X64) && (cbOffset < 16)) {
        *pcbWrite = cb;
        snprintf(pbBuffer, 17, "%016llx", pProcess->pObProcessPersistent->Plugin.vaVirt2Phys);
        cb = (DWORD)min(16 - cbOffset, cb);
        memcpy(pbBuffer + cbOffset, pb, cb);
        pbBuffer[16] = 0;
        pProcess->pObProcessPersistent->Plugin.vaVirt2Phys = strtoull(pbBuffer, NULL, 16);
    } else if ((tp == VMM_MEMORYMODEL_X86) || (tp == VMM_MEMORYMODEL_X86PAE)) {
        *pcbWrite = cb;
        snprintf(pbBuffer, 9, "%08x", (DWORD)pProcess->pObProcessPersistent->Plugin.vaVirt2Phys);
        cb = (DWORD)min(8 - cbOffset, cb);
        memcpy(pbBuffer + cbOffset, pb, cb);
        pbBuffer[8] = 0;
        pProcess->pObProcessPersistent->Plugin.vaVirt2Phys = strtoul(pbBuffer, NULL, 16);
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
NTSTATUS Virt2Phys_Write(_In_ PVMMDLL_PLUGIN_CONTEXT ctx, _In_ LPVOID pb, _In_ DWORD cb, _Out_ PDWORD pcbWrite, _In_ QWORD cbOffset)
{
    DWORD i;
    PVMM_PROCESS pProcess = (PVMM_PROCESS)ctx->pProcess;
    VMM_VIRT2PHYS_INFORMATION Virt2PhysInfo = { 0 };
    if(!_stricmp(ctx->szPath, "virt")) {
        return Virt2Phys_WriteVA(ctx, pb, cb, pcbWrite, cbOffset);
    }
    Virt2PhysInfo.va = pProcess->pObProcessPersistent->Plugin.vaVirt2Phys;
    VmmVirt2PhysGetInformation(pProcess, &Virt2PhysInfo);
    i = 0xff;
    if(!_stricmp(ctx->szPath, "pt_pml4")) { i = 4; }
    if(!_stricmp(ctx->szPath, "pt_pdpt")) { i = 3; }
    if(!_stricmp(ctx->szPath, "pt_pd")) { i = 2; }
    if(!_stricmp(ctx->szPath, "pt_pt")) { i = 1; }
    if(!_stricmp(ctx->szPath, "page")) { i = 0; }
    if(i > 4) { return VMMDLL_STATUS_FILE_INVALID; }
    if(Virt2PhysInfo.pas[i] < 0x1000) { return VMMDLL_STATUS_FILE_INVALID; }
    if(cbOffset > 0x1000) { return VMMDLL_STATUS_END_OF_FILE; }
    *pcbWrite = (DWORD)min(cb, 0x1000 - cbOffset);
    VmmWritePhysical(Virt2PhysInfo.pas[i] + cbOffset, pb, *pcbWrite);
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
    if(ctx->szPath[0]) {
        // only list in module root directory.
        // not root directory == error for this module.
        return FALSE;
    }
    switch(ctxVmm->tpMemoryModel) {
        case VMM_MEMORYMODEL_X64:
            VMMDLL_VfsList_AddFile(pFileList, "virt", 16);
            VMMDLL_VfsList_AddFile(pFileList, "phys", 16);
            VMMDLL_VfsList_AddFile(pFileList, "map", 198);
            VMMDLL_VfsList_AddFile(pFileList, "pt_pml4", 0x1000);
            VMMDLL_VfsList_AddFile(pFileList, "pt_pdpt", 0x1000);
            VMMDLL_VfsList_AddFile(pFileList, "pt_pd", 0x1000);
            VMMDLL_VfsList_AddFile(pFileList, "pt_pt", 0x1000);
            VMMDLL_VfsList_AddFile(pFileList, "page", 0x1000);
            break;
        case VMM_MEMORYMODEL_X86PAE:
            VMMDLL_VfsList_AddFile(pFileList, "virt", 8);
            VMMDLL_VfsList_AddFile(pFileList, "phys", 16);
            VMMDLL_VfsList_AddFile(pFileList, "map", 154);
            VMMDLL_VfsList_AddFile(pFileList, "pt_pdpt", 0x1000);
            VMMDLL_VfsList_AddFile(pFileList, "pt_pd", 0x1000);
            VMMDLL_VfsList_AddFile(pFileList, "pt_pt", 0x1000);
            VMMDLL_VfsList_AddFile(pFileList, "page", 0x1000);
            break;
        case VMM_MEMORYMODEL_X86:
            VMMDLL_VfsList_AddFile(pFileList, "virt", 8);
            VMMDLL_VfsList_AddFile(pFileList, "phys", 16);
            VMMDLL_VfsList_AddFile(pFileList, "map", 94);
            VMMDLL_VfsList_AddFile(pFileList, "pt_pd", 0x1000);
            VMMDLL_VfsList_AddFile(pFileList, "pt_pt", 0x1000);
            VMMDLL_VfsList_AddFile(pFileList, "page", 0x1000);
            break;
    }
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
    strcpy_s(pRI->reg_info.szModuleName, 32, "virt2phys");               // module name
    pRI->reg_info.fProcessModule = TRUE;                                 // module shows in process directory
    pRI->reg_fn.pfnList = Virt2Phys_List;                                // List function supported
    pRI->reg_fn.pfnRead = Virt2Phys_Read;                                // Read function supported
    pRI->reg_fn.pfnWrite = Virt2Phys_Write;                              // Write function supported
    pRI->pfnPluginManager_Register(pRI);
}
