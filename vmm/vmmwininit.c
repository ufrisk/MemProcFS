// vmmwininit.c : implementation of detection mechanisms for Windows operating
//                systems. Contains functions for detecting DTB and Memory Model
//                as well as the Windows kernel base and core functionality.
//
// (c) Ulf Frisk, 2018
// Author: Ulf Frisk, pcileech@frizk.net
//

#include "vmm.h"
#include "vmmwin.h"
#include "device.h"
#include "pe.h"
#include "util.h"

/*
* Scan a page table hierarchy between virtual addresses between vaMin and vaMax
* for the first occurence of large 2MB pages. This is usually 'ntoskrnl.exe' if
* the OS is Windows. 'ntoskrnl.exe' is loaded between the virtual addresses:
* 0xFFFFF80000000000-0xFFFFF803FFFFFFFF
* -- paTable = set to: physical address of PML4
* -- vaBase = set to 0
* -- vaMin = 0xFFFFF80000000000 (if windows kernel)
* -- vaMax = 0xFFFFF803FFFFFFFF (if windows kernel)
* -- cPML = set to 4
* -- pvaBase
* -- pcbSize
*/
VOID VmmWinInit_FindNtosScan64_LargePageWalk(_In_ QWORD paTable, _In_ QWORD vaBase, _In_ QWORD vaMin, _In_ QWORD vaMax, _In_ BYTE iPML, _Inout_ PQWORD pvaBase, _Inout_ PQWORD pcbSize)
{
    const QWORD PML_REGION_SIZE[5] = { 0, 12, 21, 30, 39 };
    QWORD i, pte, *ptes, vaCurrent, vaSizeRegion;
    ptes = (PQWORD)VmmTlbGetPageTable(paTable, FALSE);
    if(!ptes) { return; }
    if(iPML == 4) {
        *pvaBase = 0;
        *pcbSize = 0;
        if(!VmmTlbPageTableVerify((PBYTE)ptes, paTable, TRUE)) { return; }
        vaBase = 0;
    }
    for(i = 0; i < 512; i++) {
        // address in range
        vaSizeRegion = 1ULL << PML_REGION_SIZE[iPML];
        vaCurrent = vaBase + (i << PML_REGION_SIZE[iPML]);
        vaCurrent |= (vaCurrent & 0x0000800000000000) ? 0xffff000000000000 : 0; // sign extend
        if(*pvaBase && (vaCurrent > (*pvaBase + *pcbSize))) { return; }
        if(vaCurrent < vaMin) { continue; }
        if(vaCurrent > vaMax) { return; }
        // check PTEs
        pte = ptes[i];
        if(!(pte & 0x01)) { continue; }     // NOT VALID
        if(iPML == 2) {
            if(!(pte & 0x80)) { continue; }
            if(!*pvaBase) { *pvaBase = vaCurrent; }
            *pcbSize += 0x200000;
            continue;
        } else {
            if(pte & 0x80) { continue; }    // PS = 1
            VmmWinInit_FindNtosScan64_LargePageWalk(pte & 0x0000fffffffff000, vaCurrent, vaMin, vaMax, iPML - 1, pvaBase, pcbSize);
        }
    }
}

/*
* Sometimes the PageDirectoryBase (PML4) is known, but the kernel location may
* be unknown. This functions walks the page table in the area in which ntoskrnl
* is loaded (0xFFFFF80000000000-0xFFFFF803FFFFFFFF) looking for 2MB large pages
* If an area in 2MB pages are found it is scanned for the ntoskrnl.exe base.
* -- pSystemProcess
* -- return = virtual address of ntoskrnl.exe base if successful, otherwise 0.
*/
QWORD VmmWinInit_FindNtosScan64(PVMM_PROCESS pSystemProcess)
{
    PBYTE pb;
    QWORD p, o, vaCurrentMin, vaBase, cbSize;
    CHAR szModuleName[MAX_PATH] = { 0 };
    vaCurrentMin = 0xFFFFF80000000000;
    while(TRUE) {
        vaBase = 0;
        cbSize = 0;
        VmmWinInit_FindNtosScan64_LargePageWalk(pSystemProcess->paDTB, 0, vaCurrentMin, 0xFFFFF803FFFFFFFF, 4, &vaBase, &cbSize);
        if(!vaBase) { return 0; }
        vaCurrentMin = vaBase + cbSize;
        if(cbSize >= 0x01000000) { continue; }  // too big
        if(cbSize <= 0x00400000) { continue; }  // too small
        // try locate ntoskrnl.exe base inside suggested area
        if(!(pb = (PBYTE)LocalAlloc(0, cbSize))) { return 0; }
        VmmReadEx(pSystemProcess, vaBase, pb, (DWORD)cbSize, NULL, 0);
        for(p = 0; p < cbSize; p += 0x1000) {
            // check for (1) MZ header, (2) POOLCODE section, (3) ntoskrnl.exe module name
            if(*(PWORD)(pb + p) != 0x5a4d) { continue; } // MZ header
            for(o = 0; o < 0x1000; o += 8) {
                if(*(PQWORD)(pb + p + o) == 0x45444F434C4F4F50) { // POOLCODE
                    PE_GetModuleNameEx(pSystemProcess, vaBase + p, FALSE, pb + p, szModuleName, NULL);
                    if(!_stricmp(szModuleName, "ntoskrnl.exe")) {
                        LocalFree(pb);
                        return vaBase + p;
                    }
                }
            }
        }
        LocalFree(pb);
    }
    return 0;
}

/*
* Locate the virtual base address of 'ntoskrnl.exe' given any address inside
* the kernel. Localization will be done by a scan-back method. A maximum of
* 32MB will be scanned back.
* -- pSystemProcess
* -- return = virtual address of ntoskrnl.exe base if successful, otherwise 0
*/
QWORD VmmWinInit_FindNtosScanHint64(_In_ PVMM_PROCESS pSystemProcess)
{
    PBYTE pb;
    QWORD vaBase, o, p, vaNtosBase = 0;
    DWORD cbRead;
    QWORD vaHint = ctxVmm->kernel.vaEntry;
    CHAR szModuleName[MAX_PATH] = { 0 };
    pb = LocalAlloc(0, 0x00200000);
    if(!pb) { goto cleanup; }
    // Scan back in 2MB chunks a time, (ntoskrnl.exe is loaded in 2MB pages).
    for(vaBase = vaHint & ~0x1fffff; vaBase + 0x02000000 > vaHint; vaBase -= 0x200000) {
        VmmReadEx(pSystemProcess, vaBase, pb, 0x200000, &cbRead, 0);
        // only fail here if all virtual memory in read fails. reason is that kernel is
        // properly mapped in memory (with NX MZ header in separate page) with empty
        // space before next valid kernel pages when running Virtualization Based Security.
        if(!cbRead) { goto cleanup; }
        for(p = 0; p < 0x200000; p += 0x1000) {
            // check for (1) MZ header, (2) POOLCODE section, (3) ntoskrnl.exe module name
            if(*(PWORD)(pb + p) != 0x5a4d) { continue; } // MZ header
            for(o = 0; o < 0x1000; o += 8) {
                if(*(PQWORD)(pb + p + o) == 0x45444F434C4F4F50) { // POOLCODE
                    PE_GetModuleNameEx(pSystemProcess, vaBase + p, FALSE, pb + p, szModuleName, NULL);
                    if(!_stricmp(szModuleName, "ntoskrnl.exe")) {
                        LocalFree(pb);
                        return vaBase + p;
                    }
                }
            }
        }
    }
cleanup:
    LocalFree(pb);
    return vaNtosBase;
}

/*
* scans the relatively limited memory space 0x80000000-0x83ffffff for the base
* of 'ntoskrnl.exe'. NB! this is a very non-optimized way of doing things and
* should be improved upon to increase startup performance - but 64MB is not a
* huge amount of memory and it's only scanned at startup ...
* -- pSystemProcess
* -- return = virtual address of ntoskrnl.exe base if successful, otherwise 0.
*/
DWORD VmmWinInit_FindNtosScan32(_In_ PVMM_PROCESS pSystemProcess)
{
    DWORD o, p;
    PBYTE pb;
    CHAR szModuleName[MAX_PATH] = { 0 };
    if(!(pb = LocalAlloc(LMEM_ZEROINIT, 0x04000000))) { return 0; }
    for(p = 0; p < 0x04000000; p += 0x1000) {
        // read 8MB chunks when required.
        if(0 == p % 0x00800000) {
            VmmReadEx(pSystemProcess, 0x80000000ULL + p, pb + p, 0x00800000, NULL, 0);
        }
        // check for (1) MZ header, (2) POOLCODE section, (3) ntoskrnl.exe module name
        if(*(PWORD)(pb + p) != 0x5a4d) { continue; } // MZ header
        for(o = 0; o < 0x1000; o += 8) {
            if(*(PQWORD)(pb + p + o) == 0x45444F434C4F4F50) { // POOLCODE
                PE_GetModuleNameEx(pSystemProcess, 0x80000000ULL + p, FALSE, pb + p, szModuleName, NULL);
                if(!_stricmp(szModuleName, "ntoskrnl.exe")) {
                    LocalFree(pb);
                    return 0x80000000 + p;
                }
            }
        }
    }
    LocalFree(pb);
    return 0;
}

/*
* Scan for the 'ntoskrnl.exe' by using the DTB and memory model information
* from the ctxVmm.
* -- ppSystemProcess = ptr to receive pSystemProcess upon success.
* -- return
*/
BOOL VmmWinInit_FindNtosScan(_Out_ PVMM_PROCESS *ppSystemProcess)
{
    QWORD vaKernelBase = 0, cbKernelSize;
    PVMM_PROCESS pSystemProcess;
    *ppSystemProcess = NULL;
    // 1: Pre-initialize System PID (required by VMM)
    pSystemProcess = VmmProcessCreateEntry(4, 0, ctxVmm->kernel.paDTB, 0, "System", FALSE, TRUE);
    if(!pSystemProcess) { return FALSE; }
    VmmProcessCreateFinish();
    // 2: Spider DTB to speed things up.
    VmmTlbSpider(ctxVmm->kernel.paDTB, FALSE);
    // 3: Find the base of 'ntoskrnl.exe'
    if(VMM_MEMORYMODEL_X64 == ctxVmm->tpMemoryModel) {
        if(ctxVmm->kernel.vaEntry) {
            vaKernelBase = VmmWinInit_FindNtosScanHint64(pSystemProcess);
        }
        if(!vaKernelBase) {
            vaKernelBase = VmmWinInit_FindNtosScan64(pSystemProcess);
        }
    } else {
        vaKernelBase = VmmWinInit_FindNtosScan32(pSystemProcess);
    }
    if(!vaKernelBase) { return FALSE; }
    cbKernelSize = PE_GetSize(pSystemProcess, vaKernelBase);
    if(!cbKernelSize) { return FALSE; }
    *ppSystemProcess = pSystemProcess;
    ctxVmm->kernel.vaBase = vaKernelBase;
    ctxVmm->kernel.cbSize = cbKernelSize;
    return TRUE;
}

/*
* Check if a page looks like the Windows Kernel x86 Directory Table Base (DTB)
* in the 32-bit mode -  i.e. the PD of the System process.
* 1: self-referential entry exists at offset 0xC00
* 2: PDE[0] is a user-mode PDE pointing to a PT.
* 3: a minimum number of supervisor-mode PDEs must exist.
*/
_Success_(return)
BOOL VmmWinInit_DTB_FindValidate_X86(_In_ QWORD pa, _In_reads_(0x1000) PBYTE pbPage)
{
    DWORD c, i;
    if((*(PDWORD)(pbPage + 0xc00) & 0xfffff003) != pa + 0x03) { return FALSE; } // self-referential entry exists
    if(*pbPage != 0x67) { return FALSE; }  // user-mode page table exists at 1st PTE (index 0)
    for(c = 0, i = 0x800; i < 0x1000; i += 4) { // minimum number of supervisor entries above 0x800
        if((*(pbPage + i) == 0x63) || (*(pbPage + i) == 0xe3)) { c++; }
        if(c > 16) { return TRUE; }
    }
    return FALSE;
}

/*
* Check if a page looks like the Windows Kernel x86 Directory Table Base (DTB)
* in the 32-bit PAE memory mode - i.e. the PDPT of the System process.
* Also please note that this may not be the actual PDPT used by the kernel -
* it may very well rather be the PDPT probably set up by WinLoad and then the
* 'System' process uses another. But it works for auto-detect!
* 1: (4) valid PDPT entries with consecutive physical addresses of the PDPT.
* 2: all zeroes for the rest of the page.
*/
_Success_(return)
BOOL VmmWinInit_DTB_FindValidate_X86PAE(_In_ QWORD pa, _In_reads_(0x1000) PBYTE pbPage)
{
    for(QWORD i = 0; i < 0x1000; i += 8) {
        if((i < 0x20) && ((*(PQWORD)(pbPage + i) != pa + (i << 9) + 0x1001))) {
            return FALSE;
        } else if((i >= 0x20) && *(PQWORD)(pbPage + i)) {
            return FALSE;
        }
    }
    return TRUE;
}

_Success_(return)
BOOL VmmWinInit_DTB_FindValidate_X64(_In_ QWORD pa, _In_reads_(0x1000) PBYTE pbPage)
{
    DWORD c, i;
    BOOL fSelfRef = FALSE;
    QWORD pte, paMax;
    paMax = ctxMain->cfg.paAddrMax;
    // check for user-mode page table with PDPT below max physical address and not NX.
    pte = *(PQWORD)pbPage;
    if(((pte & 0x8000000000000087) != 0x07) || ((pte & 0x0000fffffffff000) > paMax)) { return FALSE; }
    for(c = 0, i = 0x800; i < 0x1000; i += 8) { // minimum number of supervisor entries above 0x800
        pte = *(PQWORD)(pbPage + i);
        // check for user-mode page table with PDPT below max physical address and not NX.
        if(((pte & 0x8000ff0000000087) == 0x03) && ((pte & 0x0000fffffffff000) > paMax)) { c++; }
        // check for self-referential entry
        if((*(PQWORD)(pbPage + i) & 0x8000fffffffff083) == pa + 0x03) { fSelfRef = TRUE; }
    }
    return fSelfRef && (c >= 6);
}

/*
* Find and validate the low stub (loaded <1MB if exists). The low stub almost
* always exists on real hardware. It may be missing on virtual machines though.
* Upon success both the PML4 and 'ntoskrnl.exe' KernelEntry point are located.
* The PML4 is stored as the ctxVmm->kernel.paDTB and the KernelEntry is stored
* as ctxVmm->kernel.vaHintOpt
*/
BOOL VmmWinInit_DTB_FindValidate_X64_LowStub(_In_ PBYTE pbLowStub1M)
{
    DWORD o = 0;
    while(o < 0x100000) {
        o += 0x1000;
        if(0x00000001000600E9 != (0xffffffffffff00ff & *(PQWORD)(pbLowStub1M + o + 0x000))) { continue; } // START BYTES
        if(0xfffff80000000000 != (0xfffff80000000003 & *(PQWORD)(pbLowStub1M + o + 0x070))) { continue; } // KERNEL ENTRY
        if(0xffffff0000000fff & *(PQWORD)(pbLowStub1M + o + 0x0a0)) { continue; }                         // PML4
        ctxVmm->kernel.vaEntry = *(PQWORD)(pbLowStub1M + o + 0x070);
        ctxVmm->kernel.paDTB = *(PQWORD)(pbLowStub1M + o + 0x0a0);
        return TRUE;
    }
    return FALSE;
}

/*
* Tries to locate the Directory Table Base and the Memory Model by using various
* detection and scanning functions. Upon success memory model and kernel DTB is
* returned in the ctxVmm context.
-- return
*/
_Success_(return)
BOOL VmmWinInit_DTB_FindValidate()
{
    DWORD pa;
    QWORD paDTB = 0;
    PBYTE pb16M;
    if(!(pb16M = LocalAlloc(LMEM_ZEROINIT, 0x01000000))) { return FALSE; }
    // 1: try locate DTB via X64 low stub in lower 1MB
    DeviceReadMEMEx(0, pb16M, 0x00100000, NULL);
    if(VmmWinInit_DTB_FindValidate_X64_LowStub(pb16M)) {
        VmmInitializeMemoryModel(VMM_MEMORYMODEL_X64);
        paDTB = ctxVmm->kernel.paDTB;
    }
    // 2: try locate DTB by scanning in lower 16MB
    // X64
    if(!paDTB) {
        for(pa = 0; pa < 0x01000000; pa += 0x1000) {
            if(pa == 0x00100000) {
                DeviceReadMEMEx(0x00100000, pb16M + 0x00100000, 0x00f00000, NULL);
            }
            if(VmmWinInit_DTB_FindValidate_X64(pa, pb16M + pa)) {
                VmmInitializeMemoryModel(VMM_MEMORYMODEL_X64);
                paDTB = pa;
                break;
            }
        }
    }
    // X86-PAE
    if(!paDTB) {
        for(pa = 0; pa < 0x01000000; pa += 0x1000) {
            if(VmmWinInit_DTB_FindValidate_X86PAE(pa, pb16M + pa)) {
                VmmInitializeMemoryModel(VMM_MEMORYMODEL_X86PAE);
                paDTB = pa;
                break;
            }
        }
    }
    // X86
    if(!paDTB) {
        for(pa = 0; pa < 0x01000000; pa += 0x1000) {
            if(VmmWinInit_DTB_FindValidate_X86(pa, pb16M + pa)) {
                VmmInitializeMemoryModel(VMM_MEMORYMODEL_X86);
                paDTB = pa;
                break;
            }
        }
    }
    LocalFree(pb16M);
    if(!paDTB) { return FALSE; }
    ctxVmm->kernel.paDTB = paDTB;
    return TRUE;
}

/*
* Validate a DTB supplied by the user. The memory model will be detected and
* the result will be stored in the ctxVmm context upon success.
* -- paDTB
* -- return
*/
BOOL VmmWinInit_DTB_Validate(QWORD paDTB)
{
    BYTE pb[0x1000];
    DeviceReadMEMEx(0, pb, 0x1000, NULL);
    if(VmmWinInit_DTB_FindValidate_X64(paDTB, pb)) {
        VmmInitializeMemoryModel(VMM_MEMORYMODEL_X64);
        ctxVmm->kernel.paDTB = paDTB;
        return TRUE;
    }
    if(VmmWinInit_DTB_FindValidate_X86PAE(paDTB, pb)) {
        VmmInitializeMemoryModel(VMM_MEMORYMODEL_X86PAE);
        ctxVmm->kernel.paDTB = paDTB;
        return TRUE;
    }
    if(VmmWinInit_DTB_FindValidate_X86(paDTB, pb)) {
        VmmInitializeMemoryModel(VMM_MEMORYMODEL_X86);
        ctxVmm->kernel.paDTB = paDTB;
        return TRUE;
    }
    return FALSE;
}

BOOL VmmWinInit_FindPsLoadedModuleListKDBG(_In_ PVMM_PROCESS pSystemProcess)
{
    PBYTE pbData = NULL, pbKDBG;
    IMAGE_SECTION_HEADER SectionHeader;
    DWORD o;
    QWORD va;
    // 1: Try locate 'PsLoadedModuleList' by exported kernel symbol. If this is
    //    possible it's most probably Windows 10 and KDBG will be encrypted so
    //    no need to continue looking for it.
    ctxVmm->kernel.vaPsLoadedModuleList = PE_GetProcAddress(pSystemProcess, ctxVmm->kernel.vaBase, "PsLoadedModuleList");
    if(ctxVmm->kernel.vaPsLoadedModuleList) { return TRUE; }
    // 2: Try locate 'KDBG' by looking in 'ntoskrnl.exe' '.text' section. This
    //    is the normal way of finding it on 64-bit Windows below Windows 10.
    //    This also works on 32-bit Windows versions - so use this method for
    //    simplicity rather than using a separate 32-bit method.
    if(!ctxVmm->kernel.vaKDBG) {
        if(!PE_SectionGetFromName(pSystemProcess, ctxVmm->kernel.vaBase, ".data", &SectionHeader)) { goto fail; }
        if((SectionHeader.Misc.VirtualSize > 0x00100000) || (SectionHeader.VirtualAddress > 0x01000000)) { goto fail; }
        if(!(pbData = LocalAlloc(LMEM_ZEROINIT, SectionHeader.Misc.VirtualSize))) { goto fail; }
        VmmReadEx(pSystemProcess, ctxVmm->kernel.vaBase + SectionHeader.VirtualAddress, pbData, SectionHeader.Misc.VirtualSize, NULL, 0);
        for(o = 16; o <= SectionHeader.Misc.VirtualSize - 0x290; o += 4) {
            if(*(PDWORD)(pbData + o) == 0x4742444b) { // KDBG tag
                pbKDBG = pbData + o - 16;
                if(ctxVmm->kernel.vaBase != *(PQWORD)(pbKDBG + 0x18)) { continue; }
                // fetch PsLoadedModuleList
                va = *(PQWORD)(pbKDBG + 0x48);
                if((va < ctxVmm->kernel.vaBase) || (va > ctxVmm->kernel.vaBase + ctxVmm->kernel.cbSize)) { goto fail; }
                if(!VmmRead(pSystemProcess, va, (PBYTE)&ctxVmm->kernel.vaPsLoadedModuleList, ctxVmm->f32 ? 4 : 8)) { goto fail; }
                // finish!
                ctxVmm->kernel.vaKDBG = ctxVmm->kernel.vaBase + SectionHeader.VirtualAddress + o - 16;
                LocalFree(pbData);
                return TRUE;
            }
        }
    }
fail:
    LocalFree(pbData);
    return FALSE;
}

/*
* Try initialize the VMM from scratch with new WINDOWS support.
* -- paDTBOpt
* -- return
*/
BOOL VmmWinInit_TryInitialize(_In_opt_ QWORD paDTBOpt)
{
    PVMM_PROCESS pSystemProcess = NULL;
    QWORD vaPsInitialSystemProcess, vaSystemEPROCESS;
    // Fetch Directory Base (DTB (PML4)) and initialize Memory Model.
    if(paDTBOpt) {
        if(!VmmWinInit_DTB_Validate(paDTBOpt)) {
            vmmprintfv("VmmWinInit_TryInitialize: Initialization Failed. Unable to verify user-supplied DTB. #1\n");
            goto fail;
        }
    } else {
        if(!VmmWinInit_DTB_FindValidate()) {
            vmmprintfv("VmmWinInit_TryInitialize: Initialization Failed. Unable to locate valid DTB. #2\n");
            goto fail;
        }
    }
    vmmprintfvv("VmmWinInit_TryInitialize: INFO: DTB  located at: %016llx. MemoryModel: %s\n", ctxVmm->kernel.paDTB, VMM_MEMORYMODEL_TOSTRING[ctxVmm->tpMemoryModel]);
    // Fetch 'ntoskrnl.exe' base address
    if(!VmmWinInit_FindNtosScan(&pSystemProcess)) {
        vmmprintfv("VmmWinInit_TryInitialize: Initialization Failed. Unable to locate ntoskrnl.exe. #3\n");
        goto fail;
    }
    vmmprintfvv("VmmWinInit_TryInitialize: INFO: NTOS located at: %016llx.\n", ctxVmm->kernel.vaBase);
    // Locate System EPROCESS
    vaPsInitialSystemProcess = PE_GetProcAddress(pSystemProcess, ctxVmm->kernel.vaBase, "PsInitialSystemProcess");
    if(!VmmRead(pSystemProcess, vaPsInitialSystemProcess, (PBYTE)&vaSystemEPROCESS, 8)) {
        vmmprintfv("VmmWinInit_TryInitialize: Initialization Failed. Unable to locate EPROCESS. #4\n");
        goto fail;
    }
    if((VMM_MEMORYMODEL_X86 == ctxVmm->tpMemoryModel) || (VMM_MEMORYMODEL_X86PAE == ctxVmm->tpMemoryModel)) {
        vaSystemEPROCESS &= 0xffffffff;
    }
    pSystemProcess->os.win.vaEPROCESS = vaSystemEPROCESS;
    vmmprintfvv("VmmWinInit_TryInitialize: INFO: PsInitialSystemProcess located at %016llx.\n", vaPsInitialSystemProcess);
    vmmprintfvv("VmmWinInit_TryInitialize: INFO: EPROCESS located at %016llx.\n", vaSystemEPROCESS);
    // Enumerate processes
    if(!VmmWin_EnumerateEPROCESS(pSystemProcess)) {
        vmmprintfv("VmmWinInit: Initialization Failed. Unable to walk EPROCESS. #5\n");
        goto fail;
    }
    ctxVmm->tpSystem = (VMM_MEMORYMODEL_X64 == ctxVmm->tpMemoryModel) ? VMM_SYSTEM_WINDOWS_X64 : VMM_SYSTEM_WINDOWS_X86;
    // Optionally fetch PsLoadedModuleList / KDBG
    VmmWinInit_FindPsLoadedModuleListKDBG(pSystemProcess);
    return TRUE;
fail:
    VmmInitializeMemoryModel(VMM_MEMORYMODEL_NA); // clean memory model
    ZeroMemory(&ctxVmm->kernel, sizeof(VMM_KERNELINFO));
    return FALSE;
}
