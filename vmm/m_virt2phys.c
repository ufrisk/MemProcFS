// m_virt2phys.c : implementation of the virt2phys built-in module.
//
// (c) Ulf Frisk, 2018
// Author: Ulf Frisk, pcileech@frizk.net
//
#include "m_virt2phys.h"
#include "pluginmanager.h"
#include "util.h"
#include "vmm.h"
#include "vmmvfs.h"

/*
* Virt2Phys_GetContext is an internal function which retrieves (or allocates)
* a pointer to a VMM_VIRT2PHYS_INFORMATION structure. If it does not exist and
* no "Dummy" is supplied a new VMM_VIRT2PHYS_INFORMATION is allocated & stored
* in the handle pointed by phProcessPrivate. This may later be free'd when the
* module manager calls the Virt2Phys_CloseHandleProcess function.
* -- phProcessPrivate
* -- pDummy
* -- return
*/
PVMM_VIRT2PHYS_INFORMATION Virt2Phys_GetContext(_Inout_opt_ PHANDLE phProcessPrivate, _Inout_opt_ PVMM_VIRT2PHYS_INFORMATION pDummy)
{
    if(*phProcessPrivate) {
        return (PVMM_VIRT2PHYS_INFORMATION)*phProcessPrivate;
    }
    if(pDummy) {
        ZeroMemory(pDummy, sizeof(VMM_VIRT2PHYS_INFORMATION));
        return pDummy;
    }
    *phProcessPrivate = (HANDLE)LocalAlloc(LMEM_ZEROINIT, sizeof(VMM_VIRT2PHYS_INFORMATION));
    return (PVMM_VIRT2PHYS_INFORMATION)*phProcessPrivate;
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
NTSTATUS Virt2Phys_Read(_In_ PVMMDLL_PLUGIN_CONTEXT ctx, _Out_ LPVOID pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset)
{
    BYTE iPML = 0;
    DWORD cbBuffer;
    PBYTE pbSourceData;
    BYTE pbBuffer[0x1000];
    VMM_VIRT2PHYS_INFORMATION Virt2PhysInfo_Dummy, *pVirt2PhysInfo;
    pVirt2PhysInfo = Virt2Phys_GetContext(ctx->phProcessPrivate, &Virt2PhysInfo_Dummy);
    if(!_stricmp(ctx->szPath, "virt")) {
        return Util_VfsReadFile_FromQWORD(pVirt2PhysInfo->va, pb, cb, pcbRead, cbOffset, FALSE);
    }
    if(!_stricmp(ctx->szPath, "phys")) {
        return Util_VfsReadFile_FromQWORD(pVirt2PhysInfo->x64.pas[0], pb, cb, pcbRead, cbOffset, FALSE);
    }
    if(!_stricmp(ctx->szPath, "map")) {
        cbBuffer = snprintf(
            pbBuffer,
            0x1000,
            "PML4 %016llx +%03x %016llx\n" \
            "PDPT %016llx +%03x %016llx\n" \
            "PD   %016llx +%03x %016llx\n" \
            "PT   %016llx +%03x %016llx\n" \
            "PAGE %016llx\n",
            pVirt2PhysInfo->x64.pas[4], pVirt2PhysInfo->x64.iPTEs[4] << 3, pVirt2PhysInfo->x64.PTEs[4],
            pVirt2PhysInfo->x64.pas[3], pVirt2PhysInfo->x64.iPTEs[3] << 3, pVirt2PhysInfo->x64.PTEs[3],
            pVirt2PhysInfo->x64.pas[2], pVirt2PhysInfo->x64.iPTEs[2] << 3, pVirt2PhysInfo->x64.PTEs[2],
            pVirt2PhysInfo->x64.pas[1], pVirt2PhysInfo->x64.iPTEs[1] << 3, pVirt2PhysInfo->x64.PTEs[1],
            pVirt2PhysInfo->x64.pas[0]
        );
        return Util_VfsReadFile_FromPBYTE(pbBuffer, cbBuffer, pb, cb, pcbRead, cbOffset);
    }
    // "page table" or data page
    if(!_stricmp(ctx->szPath, "pt_pml4")) { iPML = 4; }
    if(!_stricmp(ctx->szPath, "pt_pdpt")) { iPML = 3; }
    if(!_stricmp(ctx->szPath, "pt_pd")) { iPML = 2; }
    if(!_stricmp(ctx->szPath, "pt_pt")) { iPML = 1; }
    ZeroMemory(pbBuffer, 0x1000);
    pbSourceData = pbBuffer;
    if(iPML && (pVirt2PhysInfo->x64.pas[iPML] & ~0xfff)) {
        pbSourceData = VmmTlbGetPageTable(pVirt2PhysInfo->x64.pas[iPML] & ~0xfff, FALSE);
    }
    if(!_stricmp(ctx->szPath, "page") && (pVirt2PhysInfo->x64.pas[0] & ~0xfff)) {
        VmmReadPhysicalPage(pVirt2PhysInfo->x64.pas[0] & ~0xfff, pbBuffer);
    }
    if(iPML || !_stricmp(ctx->szPath, "page")) {
        return Util_VfsReadFile_FromPBYTE(pbSourceData, 0x1000, pb, cb, pcbRead, cbOffset);
    }
    return VMMDLL_STATUS_FILE_INVALID;
}

/*
* Write to the "virt" virtual file - a new virtual address is written. Triggers
* an update of the cached virtual to physical translation information.
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
    PVMM_VIRT2PHYS_INFORMATION pVirt2PhysInfo;
    if(cbOffset < 16) {
        pVirt2PhysInfo = Virt2Phys_GetContext(ctx->phProcessPrivate, NULL);
        *pcbWrite = cb;
        snprintf(pbBuffer, 17, "%016llx", pVirt2PhysInfo->va);
        cb = (DWORD)min(16 - cbOffset, cb);
        memcpy(pbBuffer + cbOffset, pb, cb);
        pbBuffer[16] = 0;
        pVirt2PhysInfo->va = strtoull(pbBuffer, NULL, 16);
        VmmVirt2PhysGetInformation(pProcess, pVirt2PhysInfo);
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
    VMM_VIRT2PHYS_INFORMATION Virt2PhysInfo_Dummy, *pVirt2PhysInfo;
    if(!_stricmp(ctx->szPath, "virt")) {
        return Virt2Phys_WriteVA(ctx, pb, cb, pcbWrite, cbOffset);
    }
    pVirt2PhysInfo = Virt2Phys_GetContext(ctx->phProcessPrivate, &Virt2PhysInfo_Dummy);
    i = 0xff;
    if(!_stricmp(ctx->szPath, "pt_pml4")) { i = 4; }
    if(!_stricmp(ctx->szPath, "pt_pdpt")) { i = 3; }
    if(!_stricmp(ctx->szPath, "pt_pd")) { i = 2; }
    if(!_stricmp(ctx->szPath, "pt_pt")) { i = 1; }
    if(!_stricmp(ctx->szPath, "page")) { i = 0; }
    if(i > 4) { return VMMDLL_STATUS_FILE_INVALID; }
    if(pVirt2PhysInfo->x64.pas[i] < 0x1000) { return VMMDLL_STATUS_FILE_INVALID; }
    if(cbOffset > 0x1000) { return VMMDLL_STATUS_END_OF_FILE; }
    *pcbWrite = (DWORD)min(cb, 0x1000 - cbOffset);
    VmmWritePhysical(pVirt2PhysInfo->x64.pas[i] + cbOffset, pb, *pcbWrite);
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
    VMMDLL_VfsList_AddFile(pFileList, "virt", 16);
    VMMDLL_VfsList_AddFile(pFileList, "phys", 16);
    VMMDLL_VfsList_AddFile(pFileList, "map", 198);
    VMMDLL_VfsList_AddFile(pFileList, "page", 0x1000);
    VMMDLL_VfsList_AddFile(pFileList, "pt_pml4", 0x1000);
    VMMDLL_VfsList_AddFile(pFileList, "pt_pdpt", 0x1000);
    VMMDLL_VfsList_AddFile(pFileList, "pt_pd", 0x1000);
    VMMDLL_VfsList_AddFile(pFileList, "pt_pt", 0x1000);
    return TRUE;
}

/*
* CloseHandleProcess : function as specified by the module manager. The module
* manager will call into this callback function whenever a process specific
* handle shall be closed. Please note that only the memory pointed to by the
* parameter phProcessPrivate shall be free'd.
* -- ctx
* -- phModulePrivate
* -- phProcessPrivate = memory to be free'd.
*/
VOID Virt2Phys_CloseHandleProcess(_In_opt_ PHANDLE phModulePrivate, _Inout_ PHANDLE phProcessPrivate)
{
    LocalFree(*phProcessPrivate);
}

/*
* Initialization function. The module manager shall call into this function
* when the module shall be initialized. If the module wish to initialize it
* shall call the supplied pfnPluginManager_Register function.
* NB! the module does not have to register itself - for example if the target
* operating system or architecture is unsupported.
* -- pPluginRegInfo
*/
VOID M_Virt2Phys_Initialize(_Inout_ PVMMDLL_PLUGIN_REGINFO pPluginRegInfo)
{
    if(0 == (pPluginRegInfo->fTargetSystem & (VMM_TARGET_UNKNOWN_X64 | VMM_TARGET_WINDOWS_X64))) { return; }
    strcpy_s(pPluginRegInfo->reg_info.szModuleName, 32, "virt2phys");               // module name
    pPluginRegInfo->reg_info.fProcessModule = TRUE;                                 // module shows in process directory
    pPluginRegInfo->reg_fn.pfnList = Virt2Phys_List;                                // List function supported
    pPluginRegInfo->reg_fn.pfnRead = Virt2Phys_Read;                                // Read function supported
    pPluginRegInfo->reg_fn.pfnWrite = Virt2Phys_Write;                              // Write function supported
    pPluginRegInfo->reg_fn.pfnCloseHandleProcess = Virt2Phys_CloseHandleProcess;    // Close process module private handle supported
    pPluginRegInfo->pfnPluginManager_Register(pPluginRegInfo);
}
