// vmmwininit.c : implementation of detection mechanisms for Windows operating
//                systems. Contains functions for detecting DTB and Memory Model
//                as well as the Windows kernel base and core functionality.
//
// (c) Ulf Frisk, 2018-2020
// Author: Ulf Frisk, pcileech@frizk.net
//

#include "vmm.h"
#include "mm.h"
#include "mm_pfn.h"
#include "pe.h"
#include "pdb.h"
#include "util.h"
#include "vmmwin.h"
#include "vmmwinobj.h"
#include "vmmwinreg.h"

/*
* Try initialize threading - this is dependent on available PDB symbols.
*/
VOID VmmWinInit_TryInitializeThreading()
{
    BOOL f;
    DWORD cbEThread = 0;
    PVMM_OFFSET_ETHREAD pti = &ctxVmm->offset.ETHREAD;
    f = PDB_GetTypeChildOffsetShort(PDB_HANDLE_KERNEL, "_EPROCESS", L"ThreadListHead", &pti->oThreadListHeadKP) &&
        PDB_GetTypeChildOffsetShort(PDB_HANDLE_KERNEL, "_KTHREAD", L"StackBase", &pti->oStackBase) &&
        PDB_GetTypeChildOffsetShort(PDB_HANDLE_KERNEL, "_KTHREAD", L"StackLimit", &pti->oStackLimit) &&
        PDB_GetTypeChildOffsetShort(PDB_HANDLE_KERNEL, "_KTHREAD", L"State", &pti->oState) &&
        PDB_GetTypeChildOffsetShort(PDB_HANDLE_KERNEL, "_KTHREAD", L"SuspendCount", &pti->oSuspendCount) &&
        PDB_GetTypeChildOffsetShort(PDB_HANDLE_KERNEL, "_KTHREAD", L"Priority", &pti->oPriority) &&
        PDB_GetTypeChildOffsetShort(PDB_HANDLE_KERNEL, "_KTHREAD", L"BasePriority", &pti->oBasePriority) &&
        PDB_GetTypeChildOffsetShort(PDB_HANDLE_KERNEL, "_KTHREAD", L"Teb", &pti->oTeb) &&
        PDB_GetTypeChildOffsetShort(PDB_HANDLE_KERNEL, "_KTHREAD", L"TrapFrame", &pti->oTrapFrame) &&
        PDB_GetTypeChildOffsetShort(PDB_HANDLE_KERNEL, "_KTHREAD", L"KernelTime", &pti->oKernelTime) &&
        PDB_GetTypeChildOffsetShort(PDB_HANDLE_KERNEL, "_KTHREAD", L"UserTime", &pti->oUserTime) &&
        PDB_GetTypeChildOffsetShort(PDB_HANDLE_KERNEL, "_KTHREAD", L"Affinity", &pti->oAffinity) &&
        PDB_GetTypeChildOffsetShort(PDB_HANDLE_KERNEL, "_ETHREAD", L"CreateTime", &pti->oCreateTime) &&
        PDB_GetTypeChildOffsetShort(PDB_HANDLE_KERNEL, "_ETHREAD", L"ExitTime", &pti->oExitTime) &&
        PDB_GetTypeChildOffsetShort(PDB_HANDLE_KERNEL, "_ETHREAD", L"ExitStatus", &pti->oExitStatus) &&
        PDB_GetTypeChildOffsetShort(PDB_HANDLE_KERNEL, "_ETHREAD", L"StartAddress", &pti->oStartAddress) &&
        PDB_GetTypeChildOffsetShort(PDB_HANDLE_KERNEL, "_ETHREAD", L"ThreadListEntry", &pti->oThreadListEntry) &&
        PDB_GetTypeChildOffsetShort(PDB_HANDLE_KERNEL, "_ETHREAD", L"Cid", &pti->oCid) &&
        PDB_GetTypeSize(PDB_HANDLE_KERNEL, "_ETHREAD", &cbEThread) &&
        (PDB_GetTypeChildOffsetShort(PDB_HANDLE_KERNEL, "_KTRAP_FRAME", L"Rip", &pti->oTrapRip) || PDB_GetTypeChildOffsetShort(PDB_HANDLE_KERNEL, "_KTRAP_FRAME", L"Eip", &pti->oTrapRip)) &&
        (PDB_GetTypeChildOffsetShort(PDB_HANDLE_KERNEL, "_KTRAP_FRAME", L"Rsp", &pti->oTrapRsp) || PDB_GetTypeChildOffsetShort(PDB_HANDLE_KERNEL, "_KTRAP_FRAME", L"HardwareEsp", &pti->oTrapRsp));
    PDB_GetTypeChildOffsetShort(PDB_HANDLE_KERNEL, "_KTHREAD", L"Process", &pti->oProcessOpt);   // optional - does not exist in xp.
    PDB_GetTypeChildOffsetShort(PDB_HANDLE_KERNEL, "_KTHREAD", L"Running", &pti->oRunningOpt);   // optional - does not exist in vista/xp.
    pti->oMax = (WORD)(cbEThread + 8);
    pti->oTebStackBase = ctxVmm->f32 ? 0x004 : 0x008;
    pti->oTebStackLimit = ctxVmm->f32 ? 0x008 : 0x010;
    ctxVmm->fThreadMapEnabled = f;
}

/*
* Try initialize not yet initialized values in the optional windows kernel
* context ctxVmm->kernel.opt
* This function should be run once the system is fully up and running.
* This is a best-effort function, uninitialized values will remain zero.
*/
VOID VmmWinInit_TryInitializeKernelOptionalValues()
{
    BOOL f;
    PVMM_PROCESS pObSystemProcess = NULL;
    POB_REGISTRY_HIVE pObHive = NULL;
    POB_REGISTRY_KEY pObKey = NULL;
    POB_MAP pmObSubkeys = NULL;
    DWORD oKdpDataBlockEncoded, dwKDBG, dwo;
    BYTE bKdpDataBlockEncoded;
    PVMM_OFFSET_FILE pof;
    if(ctxVmm->kernel.opt.fInitialized) { return; }
    if(!(pObSystemProcess = VmmProcessGet(4))) { return; }
    // Optional EPROCESS and _TOKEN offsets
    if(!ctxVmm->offset.EPROCESS.opt.Token) {
        // EPROCESS / KPROCESS
        if(PDB_GetTypeChildOffset(PDB_HANDLE_KERNEL, "_EPROCESS", L"Token", &dwo) && (dwo < sizeof(((PVMM_PROCESS)0)->win.EPROCESS.cb) - 8)) {
            ctxVmm->offset.EPROCESS.opt.Token = (WORD)dwo;
        }
        if(PDB_GetTypeChildOffset(PDB_HANDLE_KERNEL, "_EPROCESS", L"CreateTime", &dwo) && (dwo < sizeof(((PVMM_PROCESS)0)->win.EPROCESS.cb) - 8)) {
            ctxVmm->offset.EPROCESS.opt.CreateTime = (WORD)dwo;
        }
        if(PDB_GetTypeChildOffset(PDB_HANDLE_KERNEL, "_EPROCESS", L"ExitTime", &dwo) && (dwo < sizeof(((PVMM_PROCESS)0)->win.EPROCESS.cb) - 8)) {
            ctxVmm->offset.EPROCESS.opt.ExitTime = (WORD)dwo;
        }
        if(PDB_GetTypeChildOffset(PDB_HANDLE_KERNEL, "_KPROCESS", L"KernelTime", &dwo) && (dwo < sizeof(((PVMM_PROCESS)0)->win.EPROCESS.cb) - 8)) {
            ctxVmm->offset.EPROCESS.opt.KernelTime = (WORD)dwo;
        }
        if(PDB_GetTypeChildOffset(PDB_HANDLE_KERNEL, "_KPROCESS", L"UserTime", &dwo) && (dwo < sizeof(((PVMM_PROCESS)0)->win.EPROCESS.cb) - 8)) {
            ctxVmm->offset.EPROCESS.opt.UserTime = (WORD)dwo;
        }
        // TOKEN
        PDB_GetTypeChildOffsetShort(PDB_HANDLE_KERNEL, "_TOKEN", L"UserAndGroups", &ctxVmm->offset.EPROCESS.opt.TOKEN_UserAndGroups);
        PDB_GetTypeChildOffsetShort(PDB_HANDLE_KERNEL, "_TOKEN", L"SessionId", &ctxVmm->offset.EPROCESS.opt.TOKEN_SessionId);
        PDB_GetTypeChildOffsetShort(PDB_HANDLE_KERNEL, "_TOKEN", L"TokenId", &ctxVmm->offset.EPROCESS.opt.TOKEN_TokenId);
    }
    // Optional _FILE_OBJECT related offsets
    if(!ctxVmm->offset.FILE.fValid) {
        pof = &ctxVmm->offset.FILE;
        // _FILE_OBJECT
        PDB_GetTypeSizeShort(PDB_HANDLE_KERNEL, "_FILE_OBJECT", &pof->_FILE_OBJECT.cb);
        PDB_GetTypeChildOffsetShort(PDB_HANDLE_KERNEL, "_FILE_OBJECT", L"DeviceObject", &pof->_FILE_OBJECT.oDeviceObject);
        PDB_GetTypeChildOffsetShort(PDB_HANDLE_KERNEL, "_FILE_OBJECT", L"SectionObjectPointer", &pof->_FILE_OBJECT.oSectionObjectPointer);
        PDB_GetTypeChildOffsetShort(PDB_HANDLE_KERNEL, "_FILE_OBJECT", L"FileName", &pof->_FILE_OBJECT.oFileName);
        pof->_FILE_OBJECT.oFileNameBuffer       = pof->_FILE_OBJECT.oFileName + (ctxVmm->f32 ? 4 : 8);
        // _SECTION_OBJECT_POINTERS
        PDB_GetTypeSizeShort(PDB_HANDLE_KERNEL, "_SECTION_OBJECT_POINTERS", &pof->_SECTION_OBJECT_POINTERS.cb);
        PDB_GetTypeChildOffsetShort(PDB_HANDLE_KERNEL, "_SECTION_OBJECT_POINTERS", L"DataSectionObject", &pof->_SECTION_OBJECT_POINTERS.oDataSectionObject);
        PDB_GetTypeChildOffsetShort(PDB_HANDLE_KERNEL, "_SECTION_OBJECT_POINTERS", L"SharedCacheMap", &pof->_SECTION_OBJECT_POINTERS.oSharedCacheMap);
        PDB_GetTypeChildOffsetShort(PDB_HANDLE_KERNEL, "_SECTION_OBJECT_POINTERS", L"ImageSectionObject", &pof->_SECTION_OBJECT_POINTERS.oImageSectionObject);
        // _VACB
        PDB_GetTypeSizeShort(PDB_HANDLE_KERNEL, "_VACB", &pof->_VACB.cb);
        PDB_GetTypeChildOffsetShort(PDB_HANDLE_KERNEL, "_VACB", L"BaseAddress", &pof->_VACB.oBaseAddress);
        PDB_GetTypeChildOffsetShort(PDB_HANDLE_KERNEL, "_VACB", L"SharedCacheMap", &pof->_VACB.oSharedCacheMap);
        // _SHARED_CACHE_MAP
        PDB_GetTypeSizeShort(PDB_HANDLE_KERNEL, "_SHARED_CACHE_MAP", &pof->_SHARED_CACHE_MAP.cb);
        PDB_GetTypeChildOffsetShort(PDB_HANDLE_KERNEL, "_SHARED_CACHE_MAP", L"FileSize", &pof->_SHARED_CACHE_MAP.oFileSize);
        PDB_GetTypeChildOffsetShort(PDB_HANDLE_KERNEL, "_SHARED_CACHE_MAP", L"SectionSize", &pof->_SHARED_CACHE_MAP.oSectionSize);
        PDB_GetTypeChildOffsetShort(PDB_HANDLE_KERNEL, "_SHARED_CACHE_MAP", L"ValidDataLength", &pof->_SHARED_CACHE_MAP.oValidDataLength);
        PDB_GetTypeChildOffsetShort(PDB_HANDLE_KERNEL, "_SHARED_CACHE_MAP", L"InitialVacbs", &pof->_SHARED_CACHE_MAP.oInitialVacbs);
        PDB_GetTypeChildOffsetShort(PDB_HANDLE_KERNEL, "_SHARED_CACHE_MAP", L"Vacbs", &pof->_SHARED_CACHE_MAP.oVacbs);
        PDB_GetTypeChildOffsetShort(PDB_HANDLE_KERNEL, "_SHARED_CACHE_MAP", L"FileObjectFastRef", &pof->_SHARED_CACHE_MAP.oFileObjectFastRef);
        // _CONTROL_AREA
        PDB_GetTypeSizeShort(PDB_HANDLE_KERNEL, "_CONTROL_AREA", &pof->_CONTROL_AREA.cb);
        PDB_GetTypeChildOffsetShort(PDB_HANDLE_KERNEL, "_CONTROL_AREA", L"Segment", &pof->_CONTROL_AREA.oSegment);
        PDB_GetTypeChildOffsetShort(PDB_HANDLE_KERNEL, "_CONTROL_AREA", L"FilePointer", &pof->_CONTROL_AREA.oFilePointer);
        // _SEGMENT
        PDB_GetTypeSizeShort(PDB_HANDLE_KERNEL, "_SEGMENT", &pof->_SEGMENT.cb);
        PDB_GetTypeChildOffsetShort(PDB_HANDLE_KERNEL, "_SEGMENT", L"ControlArea", &pof->_SEGMENT.oControlArea);
        PDB_GetTypeChildOffsetShort(PDB_HANDLE_KERNEL, "_SEGMENT", L"SizeOfSegment", &pof->_SEGMENT.oSizeOfSegment);
        PDB_GetTypeChildOffsetShort(PDB_HANDLE_KERNEL, "_SEGMENT", L"PrototypePte", &pof->_SEGMENT.oPrototypePte);
        // _SUBSECTION
        PDB_GetTypeSizeShort(PDB_HANDLE_KERNEL, "_SUBSECTION", &pof->_SUBSECTION.cb);
        PDB_GetTypeChildOffsetShort(PDB_HANDLE_KERNEL, "_SUBSECTION", L"ControlArea", &pof->_SUBSECTION.oControlArea);
        PDB_GetTypeChildOffsetShort(PDB_HANDLE_KERNEL, "_SUBSECTION", L"NextSubsection", &pof->_SUBSECTION.oNextSubsection);
        PDB_GetTypeChildOffsetShort(PDB_HANDLE_KERNEL, "_SUBSECTION", L"NumberOfFullSectors", &pof->_SUBSECTION.oNumberOfFullSectors);
        PDB_GetTypeChildOffsetShort(PDB_HANDLE_KERNEL, "_SUBSECTION", L"PtesInSubsection", &pof->_SUBSECTION.oPtesInSubsection);
        PDB_GetTypeChildOffsetShort(PDB_HANDLE_KERNEL, "_SUBSECTION", L"StartingSector", &pof->_SUBSECTION.oStartingSector);
        PDB_GetTypeChildOffsetShort(PDB_HANDLE_KERNEL, "_SUBSECTION", L"SubsectionBase", &pof->_SUBSECTION.oSubsectionBase);
        pof->fValid = pof->_SUBSECTION.cb ? TRUE : FALSE;
    }
    // cpu count
    if(!ctxVmm->kernel.opt.cCPUs) {
        PDB_GetSymbolDWORD(PDB_HANDLE_KERNEL, "KiTotalCpuSetCount", pObSystemProcess, &ctxVmm->kernel.opt.cCPUs);
        if(ctxVmm->kernel.opt.cCPUs > 128) { ctxVmm->kernel.opt.cCPUs = 0; }
    }
    if(!ctxVmm->kernel.opt.cCPUs && VmmWinReg_KeyHiveGetByFullPath(L"HKLM\\HARDWARE\\DESCRIPTION\\System\\CentralProcessor", &pObHive, &pObKey)) {
        pmObSubkeys = VmmWinReg_KeyList(pObHive, pObKey);
        ctxVmm->kernel.opt.cCPUs = ObMap_Size(pmObSubkeys);
    }
    // pfn database & pfn subsystem initialize
    if(!ctxVmm->kernel.opt.vaPfnDatabase) {
        PDB_GetSymbolPTR(PDB_HANDLE_KERNEL, "MmPfnDatabase", pObSystemProcess, &ctxVmm->kernel.opt.vaPfnDatabase);
    }
    MmPfn_Initialize(pObSystemProcess);
    // PsLoadedModuleListExp
    if(!ctxVmm->kernel.opt.vaPsLoadedModuleListExp) {
        PDB_GetSymbolAddress(PDB_HANDLE_KERNEL, "PsLoadedModuleList", &ctxVmm->kernel.opt.vaPsLoadedModuleListExp);
    }
    // MmUnloadedDrivers / MmLastUnloadedDriver
    if(!ctxVmm->kernel.opt.vaMmUnloadedDrivers || !ctxVmm->kernel.opt.vaMmLastUnloadedDriver) {
        PDB_GetSymbolAddress(PDB_HANDLE_KERNEL, "MmUnloadedDrivers", &ctxVmm->kernel.opt.vaMmUnloadedDrivers);
        PDB_GetSymbolAddress(PDB_HANDLE_KERNEL, "MmLastUnloadedDriver", &ctxVmm->kernel.opt.vaMmLastUnloadedDriver);
    }
    // KdDebuggerDataBlock (KDBG)
    if(!ctxVmm->kernel.opt.KDBG.va && PDB_GetSymbolAddress(PDB_HANDLE_KERNEL, "KdDebuggerDataBlock", &ctxVmm->kernel.opt.KDBG.va)) {
        f = !ctxVmm->f32 &&
            VmmRead(pObSystemProcess, ctxVmm->kernel.opt.KDBG.va + 0x10, (PBYTE)&dwKDBG, sizeof(DWORD)) && (dwKDBG != 0x4742444b) &&
            PDB_GetSymbolOffset(PDB_HANDLE_KERNEL, "KdpDataBlockEncoded", &oKdpDataBlockEncoded) &&
            PDB_GetSymbolPBYTE(PDB_HANDLE_KERNEL, "KdpDataBlockEncoded", pObSystemProcess, &bKdpDataBlockEncoded, 1) &&
            (bKdpDataBlockEncoded == 1);
        if(f) {
            ctxVmm->kernel.opt.KDBG.vaKdpDataBlockEncoded = ctxVmm->kernel.vaBase + oKdpDataBlockEncoded;
            PDB_GetSymbolQWORD(PDB_HANDLE_KERNEL, "KiWaitAlways", pObSystemProcess, &ctxVmm->kernel.opt.KDBG.qwKiWaitAlways);
            PDB_GetSymbolQWORD(PDB_HANDLE_KERNEL, "KiWaitNever", pObSystemProcess, &ctxVmm->kernel.opt.KDBG.qwKiWaitNever);
        }
    }
    // Cleanup
    Ob_DECREF(pObKey);
    Ob_DECREF(pObHive);
    Ob_DECREF(pmObSubkeys);
    Ob_DECREF(pObSystemProcess);
    ctxVmm->kernel.opt.fInitialized = TRUE;
}

/*
* Helper/Worker function for VmmWinInit_FindNtosScan64_SmallPageWalk().
* -- paTable = set to: physical address of PML4
* -- vaBase = set to 0
* -- vaMin = 0xFFFFF80000000000 (if windows kernel)
* -- vaMax = 0xFFFFF803FFFFFFFF (if windows kernel)
* -- iPML = set to 4
* -- psvaKernelCandidates
*/
VOID VmmWinInit_FindNtosScan64_SmallPageWalk_DoWork(_In_ QWORD paTable, _In_ QWORD vaBase, _In_ QWORD vaMin, _In_ QWORD vaMax, _In_ BYTE iPML, _In_ POB_SET psvaKernelCandidates)
{
    const QWORD PML_REGION_SIZE[5] = { 0, 12, 21, 30, 39 };
    QWORD i, j, pte, vaCurrent, vaSizeRegion;
    PVMMOB_CACHE_MEM pObPTEs = NULL;
    BOOL f;
    pObPTEs = VmmTlbGetPageTable(paTable, FALSE);
    if(!pObPTEs) { return; }
    if(iPML == 4) {
        if(!VmmTlbPageTableVerify(pObPTEs->pb, paTable, TRUE)) { goto finish; }
        vaBase = 0;
    }
    for(i = 0; i < 512; i++) {
        // address in range
        vaSizeRegion = 1ULL << PML_REGION_SIZE[iPML];
        vaCurrent = vaBase + (i << PML_REGION_SIZE[iPML]);
        vaCurrent |= (vaCurrent & 0x0000800000000000) ? 0xffff000000000000 : 0; // sign extend
        if(vaCurrent < vaMin) { continue; }
        if(vaCurrent > vaMax) { goto finish; }
        // check PTEs
        pte = pObPTEs->pqw[i];
        if(!(pte & 0x01)) { continue; }                     // NOT VALID
        if(iPML == 1) {
            if(i && pObPTEs->pqw[i - 1]) { continue; }      // PAGE i-1 NOT EMPTY -> NOT VALID
            if((pte & 0x80000000'0000000f) != 0x80000000'00000003) { continue; } // PAGE i+0 IS ACTIVE-WRITE-SUPERVISOR-NOEXECUTE
            for(j = i + 1, f = TRUE; f && (j < min(i + 32, 512)); j++) {
                f = ((pObPTEs->pqw[j] & 0x80000000'0000000f) == 0x01);   // PAGE i+0 IS ACTIVE-SUPERVISOR-NOEXECUTE
            }
            if(f) {
                ObSet_Push(psvaKernelCandidates, vaCurrent);
            }
        }
        if(pte & 0x80) { continue; }                        // PS (large page) -> NOT VALID
        VmmWinInit_FindNtosScan64_SmallPageWalk_DoWork(pte & 0x0000fffffffff000, vaCurrent, vaMin, vaMax, iPML - 1, psvaKernelCandidates);
    }
finish:
    Ob_DECREF(pObPTEs);
}

/*
* Scan a page table hierarchy between virtual addresses between vaMin and vaMax
* for the ntoskrnl.exe windows kernel. Kernel is assumed, by this algoritm, to:
* - be located in 4kB page betwen vaMin and vaMax
* - page #-1 be NULL PTE
* - page #0 be read/write
* - page #1-#32 be read/execute
* - page starts with MZ and contains POOLCODE
* -- pSystemProcess
* -- vaMin = 0xFFFFF80000000000
* -- vaMax = 0xFFFFF803FFFFFFFF
* -- pvaBase
* -- pcbSize
*/
VOID VmmWinInit_FindNtosScan64_SmallPageWalk(_In_ PVMM_PROCESS pSystemProcess, _In_ QWORD vaMin, _In_ QWORD vaMax, _Inout_ PQWORD pvaBase, _Inout_ PQWORD pcbSize)
{
    QWORD o, va;
    BYTE pb[4096];
    POB_SET psObKernelVa = NULL;
    if(!(psObKernelVa = ObSet_New())) { return; }
    VmmWinInit_FindNtosScan64_SmallPageWalk_DoWork(pSystemProcess->paDTB, 0, vaMin, vaMax, 4, psObKernelVa);
    VmmCachePrefetchPages(pSystemProcess, psObKernelVa, 0);
    while((va = ObSet_Pop(psObKernelVa))) {
        if(VmmReadPage(pSystemProcess, va, pb)) {
            if(pb[0] != 'M' || pb[1] != 'Z') { continue; }
            for(o = 0; o < 0x1000; o += 8) {
                if(*(PQWORD)(pb + o) == 0x45444F434C4F4F50) { // POOLCODE
                    *pvaBase = va;
                    *pcbSize = 0x00800000;  // DUMMY
                    Ob_DECREF(psObKernelVa);
                    return;
                }
            }
        }
    }
    Ob_DECREF(psObKernelVa);
}

/*
* Scan a page table hierarchy between virtual addresses between vaMin and vaMax
* for the first occurence of large 2MB pages. This is usually 'ntoskrnl.exe' if
* the OS is Windows. 'ntoskrnl.exe'.
* -- paTable = set to: physical address of PML4
* -- vaBase = set to 0
* -- vaMin = 0xFFFFF80000000000 (if windows kernel)
* -- vaMax = 0xFFFFF803FFFFFFFF (if windows kernel)
* -- iPML = set to 4
* -- pvaBase
* -- pcbSize
*/
VOID VmmWinInit_FindNtosScan64_LargePageWalk(_In_ QWORD paTable, _In_ QWORD vaBase, _In_ QWORD vaMin, _In_ QWORD vaMax, _In_ BYTE iPML, _Inout_ PQWORD pvaBase, _Inout_ PQWORD pcbSize)
{
    const QWORD PML_REGION_SIZE[5] = { 0, 12, 21, 30, 39 };
    QWORD i, pte, vaCurrent, vaSizeRegion;
    PVMMOB_CACHE_MEM pObPTEs = NULL;
    pObPTEs = VmmTlbGetPageTable(paTable, FALSE);
    if(!pObPTEs) { return; }
    if(iPML == 4) {
        *pvaBase = 0;
        *pcbSize = 0;
        if(!VmmTlbPageTableVerify(pObPTEs->pb, paTable, TRUE)) { goto finish; }
        vaBase = 0;
    }
    for(i = 0; i < 512; i++) {
        // address in range
        vaSizeRegion = 1ULL << PML_REGION_SIZE[iPML];
        vaCurrent = vaBase + (i << PML_REGION_SIZE[iPML]);
        vaCurrent |= (vaCurrent & 0x0000800000000000) ? 0xffff000000000000 : 0; // sign extend
        if(*pvaBase && (vaCurrent > (*pvaBase + *pcbSize))) { goto finish; }
        if(vaCurrent < vaMin) { continue; }
        if(vaCurrent > vaMax) { goto finish; }
        // check PTEs
        pte = pObPTEs->pqw[i];
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
finish:
    Ob_DECREF(pObPTEs);
}

/*
* Sometimes the PageDirectoryBase (PML4) is known, but the kernel location may
* be unknown. This functions walks the page table in the area in which ntoskrnl
* is loaded looking for 2MB large pages. If an area in 2MB pages are found it
* is scanned for the ntoskrnl.exe base.
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
        VmmWinInit_FindNtosScan64_LargePageWalk(pSystemProcess->paDTB, 0, vaCurrentMin, 0xFFFFF807FFFFFFFF, 4, &vaBase, &cbSize);
        if(!vaBase) {
            VmmWinInit_FindNtosScan64_SmallPageWalk(pSystemProcess, vaCurrentMin, 0xFFFFF807FFFFFFFF, &vaBase, &cbSize);
        }
        if(!vaBase) { return 0; }
        vaCurrentMin = vaBase + cbSize;
        if(cbSize >= 0x01800000) { continue; }  // too big
        if(cbSize <= 0x00400000) { continue; }  // too small
        // try locate ntoskrnl.exe base inside suggested area
        if(!(pb = (PBYTE)LocalAlloc(0, cbSize))) { return 0; }
        VmmReadEx(pSystemProcess, vaBase, pb, (DWORD)cbSize, NULL, 0);
        for(p = 0; p < cbSize; p += 0x1000) {
            // check for (1) MZ header, (2) POOLCODE section, (3) ntoskrnl.exe module name
            if(*(PWORD)(pb + p) != 0x5a4d) { continue; } // MZ header
            for(o = 0; o < 0x1000; o += 8) {
                if(*(PQWORD)(pb + p + o) == 0x45444F434C4F4F50) { // POOLCODE
                    PE_GetModuleNameEx(pSystemProcess, vaBase + p, FALSE, pb + p, szModuleName, _countof(szModuleName), NULL);
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
QWORD VmmWinInit_FindNtosScanHint64(_In_ PVMM_PROCESS pSystemProcess, _In_ QWORD vaHint)
{
    PBYTE pb;
    QWORD vaBase, o, p, vaNtosTry = 0;
    DWORD cbRead;
    CHAR szModuleName[MAX_PATH] = { 0 };
    PIMAGE_DOS_HEADER pDosHeader;
    PIMAGE_NT_HEADERS pNtHeader;
    pb = LocalAlloc(0, 0x00200000);
    if(!pb) { goto cleanup; }
    // Scan back in 2MB chunks a time, (ntoskrnl.exe is loaded in 2MB pages except in low memory situations).
    for(vaBase = vaHint & ~0x1fffff; vaBase + 0x02000000 > vaHint; vaBase -= 0x200000) {
        VmmReadEx(pSystemProcess, vaBase, pb, 0x200000, &cbRead, 0);
        // Only fail here if all virtual memory in read fails. reason is that kernel is
        // properly mapped in memory (with NX MZ header in separate page) with empty
        // space before next valid kernel pages when running Virtualization Based Security.
        // Memory pages may be paged out of small pages are used in low-mem situations.
        if(!cbRead) { goto cleanup; }
        for(p = 0; p < 0x200000; p += 0x1000) {
            // check for (1) MZ+NT header, (2) POOLCODE section, (3) ntoskrnl.exe module name (if possible to read)
            pDosHeader = (PIMAGE_DOS_HEADER)(pb + p);                       // DOS header
            if(pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) { continue; }    // DOS header signature (MZ)
            if(pDosHeader->e_lfanew > 0x800) { continue; }
            pNtHeader = (PIMAGE_NT_HEADERS)(pb + p + pDosHeader->e_lfanew); // NT header
            if(pNtHeader->Signature != IMAGE_NT_SIGNATURE) { continue; }    // NT header signature
            for(o = 0; o < 0x1000; o += 8) {
                if(*(PQWORD)(pb + p + o) == 0x45444F434C4F4F50) {           // POOLCODE
                    if(!PE_GetModuleNameEx(pSystemProcess, vaBase + p, FALSE, pb + p, szModuleName, _countof(szModuleName), NULL)) {
                        vaNtosTry = vaBase + p;
                        continue;
                    }
                    if(_stricmp(szModuleName, "ntoskrnl.exe")) {            // not ntoskrnl.exe
                        continue;
                    }
                    LocalFree(pb);
                    return vaBase + p;
                }
            }
        }
    }
cleanup:
    LocalFree(pb);
    return vaNtosTry;       // on fail try return NtosTry derived from MZ + POOLCODE only
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
    DWORD o, p, vaNtosTry = 0;
    PBYTE pb;
    CHAR szModuleName[MAX_PATH] = { 0 };
    PIMAGE_DOS_HEADER pDosHeader;
    PIMAGE_NT_HEADERS pNtHeader;
    if(!(pb = LocalAlloc(LMEM_ZEROINIT, 0x04000000))) { return 0; }
    for(p = 0; p < 0x04000000; p += 0x1000) {
        // read 8MB chunks when required.
        if(0 == p % 0x00800000) {
            VmmReadEx(pSystemProcess, 0x80000000ULL + p, pb + p, 0x00800000, NULL, 0);
        }
        // check for (1) MZ+NT header, (2) POOLCODE section, (3) ntoskrnl.exe module name (if possible to read)
        pDosHeader = (PIMAGE_DOS_HEADER)(pb + p);                       // DOS header
        if(pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) { continue; }    // DOS header signature (MZ)
        if(pDosHeader->e_lfanew > 0x800) { continue; }
        pNtHeader = (PIMAGE_NT_HEADERS)(pb + p + pDosHeader->e_lfanew); // NT header
        if(pNtHeader->Signature != IMAGE_NT_SIGNATURE) { continue; }    // NT header signature
        for(o = 0; o < 0x800; o += 8) {
            if(*(PQWORD)(pb + p + o) == 0x45444F434C4F4F50) {           // POOLCODE
                if(!PE_GetModuleNameEx(pSystemProcess, 0x80000000ULL + p, FALSE, pb + p, szModuleName, _countof(szModuleName), NULL)) {
                    vaNtosTry = 0x80000000 + p;
                    continue;
                }
                if(_stricmp(szModuleName, "ntoskrnl.exe")) {            // not ntoskrnl.exe
                    continue;
                }
                LocalFree(pb);
                return 0x80000000 + p;
            }
        }
    }
    LocalFree(pb);
    return vaNtosTry;      // on fail try return NtosTry derived from MZ + POOLCODE only.
}

/*
* Scan for the 'ntoskrnl.exe' by using the DTB and memory model information
* from the ctxVmm. Return the system process (if found).
* CALLER DECREF: return
* -- return = system process - NB! CALLER must DECREF!
*/
PVMM_PROCESS VmmWinInit_FindNtosScan()
{
    QWORD vaKernelBase = 0, cbKernelSize, vaKernelHint;
    PVMM_PROCESS pObSystemProcess = NULL;
    // 1: Pre-initialize System PID (required by VMM)
    pObSystemProcess = VmmProcessCreateEntry(TRUE, 4, 0, 0, ctxVmm->kernel.paDTB, 0, "System         ", FALSE, NULL, 0);
    if(!pObSystemProcess) { return NULL; }
    VmmProcessCreateFinish();
    // 2: Spider DTB to speed things up.
    VmmTlbSpider(pObSystemProcess);
    // 3: Find the base of 'ntoskrnl.exe'
    if(VMM_MEMORYMODEL_X64 == ctxVmm->tpMemoryModel) {
        LcGetOption(ctxMain->hLC, LC_OPT_MEMORYINFO_OS_KERNELBASE, &vaKernelBase);
        if(!vaKernelBase) {
            vaKernelHint = ctxVmm->kernel.vaEntry;
            if(!vaKernelHint) { LcGetOption(ctxMain->hLC, LC_OPT_MEMORYINFO_OS_KERNELHINT, &vaKernelHint); }
            if(!vaKernelHint) { LcGetOption(ctxMain->hLC, LC_OPT_MEMORYINFO_OS_PsActiveProcessHead, &vaKernelHint); }
            if(!vaKernelHint) { LcGetOption(ctxMain->hLC, LC_OPT_MEMORYINFO_OS_PsLoadedModuleList, &vaKernelHint); }
            if(vaKernelHint) {
                vaKernelBase = VmmWinInit_FindNtosScanHint64(pObSystemProcess, vaKernelHint);
            }
        }
        if(!vaKernelBase) {
            vaKernelBase = VmmWinInit_FindNtosScan64(pObSystemProcess);
        }
    } else {
        vaKernelBase = VmmWinInit_FindNtosScan32(pObSystemProcess);
    }
    if(!vaKernelBase) { goto fail; }
    cbKernelSize = PE_GetSize(pObSystemProcess, vaKernelBase);
    ctxVmm->kernel.vaBase = vaKernelBase;
    ctxVmm->kernel.cbSize = cbKernelSize;
    return pObSystemProcess;
fail:
    Ob_DECREF(pObSystemProcess);
    return NULL;
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
    QWORD *ptes, paMax;
    BOOL fSelfRef = FALSE;
    ptes = (PQWORD)pbPage;
    paMax = ctxMain->dev.paMax;
    // check for user-mode page table with PDPT below max physical address and not NX.
    if((ptes[0] & 1) && ((ptes[0] & 0x0000fffffffff000) > paMax)) { return FALSE; }
    for(c = 0, i = 256; i < 512; i++) { // minimum number of supervisor entries above 0x800
        // check for user-mode page table with PDPT below max physical address and not NX.
        if(((ptes[i] & 0x8000000000000087) == 0x03) && ((ptes[i] & 0x0000fffffffff000) < paMax)) { c++; }
        // check for self-referential entry
        if((ptes[i] & 0x0000fffffffff083) == pa + 0x03) { fSelfRef = TRUE; }
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
    // 1: try locate DTB via X64 low stub in lower 1MB -
    //    avoiding normally reserved memory at a0000-fffff.
    LcRead(ctxMain->hLC, 0x1000, 0x9f000, pb16M + 0x1000);
    if(VmmWinInit_DTB_FindValidate_X64_LowStub(pb16M)) {
        VmmInitializeMemoryModel(VMM_MEMORYMODEL_X64);
        paDTB = ctxVmm->kernel.paDTB;
    }
    // 2: try locate DTB by scanning in lower 16MB
    // X64
    if(!paDTB) {
        for(pa = 0; pa < 0x01000000; pa += 0x1000) {
            if(pa == 0x00100000) {
                LcRead(ctxMain->hLC, 0x00100000, 0x00f00000, pb16M + 0x00100000);
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
    paDTB = paDTB & ~0xfff;
    if(!LcRead(ctxMain->hLC, paDTB, 0x1000, pb)) { return FALSE; }
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
    DWORD o, va32 = 0;
    QWORD va, va64 = 0;
    // 1: Try locate 'PsLoadedModuleList' by querying the microsoft crash dump
    //    file used. This will fail if another memory acqusition device is used.
    if(LcGetOption(ctxMain->hLC, LC_OPT_MEMORYINFO_OS_PsLoadedModuleList, &va) && va) {
        LcGetOption(ctxMain->hLC, LC_OPT_MEMORYINFO_OS_PFN, &ctxVmm->kernel.opt.vaPfnDatabase);
        LcGetOption(ctxMain->hLC, LC_OPT_MEMORYINFO_OS_KdDebuggerDataBlock, &ctxVmm->kernel.opt.KDBG.va);
        if(ctxVmm->f32 && VmmRead(pSystemProcess, va, (PBYTE)&va32, 4) && (va32 > 0x80000000)) {
            ctxVmm->kernel.opt.vaPsLoadedModuleListExp = va;
            ctxVmm->kernel.vaPsLoadedModuleListPtr = va32;
            return TRUE;
        }
        if(!ctxVmm->f32 && VmmRead(pSystemProcess, va, (PBYTE)&va64, 8) && (va64 > 0xffff800000000000)) {
            ctxVmm->kernel.opt.vaPsLoadedModuleListExp = va;
            ctxVmm->kernel.vaPsLoadedModuleListPtr = va64;
            return TRUE;
        }
    }
    //    (optionally) Locate the PFN database:
    //    The PFN database is static on before Windows 10 x64 1607/14393.
    if(!ctxVmm->f32 && (ctxVmm->kernel.dwVersionBuild < 14393)) {
        ctxVmm->kernel.opt.vaPfnDatabase = 0xfffffa80'00000000;
    }
    // 2: Try locate 'PsLoadedModuleList' by exported kernel symbol. If this is
    //    possible _and_ the system is 64-bit it's most probably Windows 10 and
    //    KDBG will be encrypted so no need to continue looking for it.
    ctxVmm->kernel.vaPsLoadedModuleListPtr = PE_GetProcAddress(pSystemProcess, ctxVmm->kernel.vaBase, "PsLoadedModuleList");
    if(ctxVmm->kernel.vaPsLoadedModuleListPtr && !ctxVmm->f32) {
        ctxVmm->kernel.opt.vaPsLoadedModuleListExp = ctxVmm->kernel.vaPsLoadedModuleListPtr;
        return TRUE;
    }
    // 3: Try locate 'KDBG' by looking in 'ntoskrnl.exe' '.text' section. This
    //    is the normal way of finding it on 64-bit Windows below Windows 10.
    //    This also works on 32-bit Windows versions - so use this method for
    //    simplicity rather than using a separate 32-bit method.
    if(!ctxVmm->kernel.opt.KDBG.va && (ctxVmm->f32 || ctxVmm->kernel.dwVersionMajor < 10)) {
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
                if(!VmmRead(pSystemProcess, va, (PBYTE)&ctxVmm->kernel.vaPsLoadedModuleListPtr, ctxVmm->f32 ? 4 : 8)) { goto fail; }
                ctxVmm->kernel.opt.vaPsLoadedModuleListExp = va;
                // finish!
                ctxVmm->kernel.opt.KDBG.va = ctxVmm->kernel.vaBase + SectionHeader.VirtualAddress + o - 16;
                LocalFree(pbData);
                return TRUE;
            }
        }
    }
    // 4: Try locate by querying the PDB for symbols. At this point the PDB
    //    subsystem may not be fully initialized yet so wait for it to init.
    PDB_Initialize_WaitComplete();
    if(PDB_GetSymbolPTR(PDB_HANDLE_KERNEL, "PsLoadedModuleList", pSystemProcess, &ctxVmm->kernel.vaPsLoadedModuleListPtr)) {
        PDB_GetSymbolAddress(PDB_HANDLE_KERNEL, "PsLoadedModuleList", &ctxVmm->kernel.opt.vaPsLoadedModuleListExp);
        return TRUE;
    }
fail:
    LocalFree(pbData);
    return (0 != ctxVmm->kernel.vaPsLoadedModuleListPtr);
}

/*
* Retrieve the operating system versioning information by looking at values in
* the PEB of the process 'smss.exe'.
* -- pProcessSMSS
* -- return
*/
VOID VmmWinInit_VersionNumber(_In_ PVMM_PROCESS pProcessSMSS)
{
    BOOL fRead;
    BYTE pbPEB[0x130];
    PVMM_PROCESS pObProcess = NULL;
    fRead = VmmRead(pProcessSMSS, pProcessSMSS->win.vaPEB, pbPEB, 0x130);
    if(!fRead) { // failed (paging?) - try to read from crss.exe / lsass.exe / winlogon.exe
        while((pObProcess = VmmProcessGetNext(pObProcess, 0))) {
            if(!strcmp("crss.exe", pObProcess->szName) || !strcmp("lsass.exe", pObProcess->szName) || !strcmp("winlogon.exe", pObProcess->szName)) {
                if((fRead = VmmRead(pObProcess, pObProcess->win.vaPEB, pbPEB, 0x130))) { break; }
            }
        }
        Ob_DECREF_NULL(&pObProcess);
    }
    if(fRead) {
        if(ctxVmm->f32) {
            ctxVmm->kernel.dwVersionMajor = *(PDWORD)(pbPEB + 0x0a4);
            ctxVmm->kernel.dwVersionMinor = *(PDWORD)(pbPEB + 0x0a8);
            ctxVmm->kernel.dwVersionBuild = *(PWORD)(pbPEB + 0x0ac);
        } else {
            ctxVmm->kernel.dwVersionMajor = *(PDWORD)(pbPEB + 0x118);
            ctxVmm->kernel.dwVersionMinor = *(PDWORD)(pbPEB + 0x11c);
            ctxVmm->kernel.dwVersionBuild = *(PWORD)(pbPEB + 0x120);
        }
    }
}

/*
* Helper fucntion to VmmWinInit_TryInitialize. Tries to locate the EPROCESS of
* the SYSTEM process and return it.
* -- pSystemProcess
* -- return
*/
QWORD VmmWinInit_FindSystemEPROCESS(_In_ PVMM_PROCESS pSystemProcess)
{
    BOOL f32 = ctxVmm->f32;
    IMAGE_SECTION_HEADER SectionHeader;
    BYTE pbALMOSTRO[0x80], pbSYSTEM[0x300];
    QWORD i, vaPsInitialSystemProcess, vaSystemEPROCESS;
    // 1: try locate System EPROCESS by PsInitialSystemProcess exported symbol (works on all win versions)
    vaPsInitialSystemProcess = PE_GetProcAddress(pSystemProcess, ctxVmm->kernel.vaBase, "PsInitialSystemProcess");
    if(VmmRead(pSystemProcess, vaPsInitialSystemProcess, (PBYTE)& vaSystemEPROCESS, 8)) {
        if((VMM_MEMORYMODEL_X86 == ctxVmm->tpMemoryModel) || (VMM_MEMORYMODEL_X86PAE == ctxVmm->tpMemoryModel)) {
            vaSystemEPROCESS &= 0xffffffff;
        }
        pSystemProcess->win.EPROCESS.va = vaSystemEPROCESS;
        vmmprintfvv_fn("INFO: PsInitialSystemProcess located at %016llx.\n", vaPsInitialSystemProcess);
        goto success;
    }
    // 2: fail - paging? try to retrive using PDB subsystem - this may take some time to initialize
    //           and download symbols - but it's better than failing totally ...
    PDB_Initialize(NULL, FALSE);
    PDB_GetSymbolPTR(PDB_HANDLE_KERNEL, "PsInitialSystemProcess", pSystemProcess, &vaSystemEPROCESS);
    if(vaSystemEPROCESS) { goto success; }
    // 3: fail - paging? (or not windows) - this should ideally not happen - but it happens rarely...
    //    try scan beginning of ALMOSTRO section for pointers and validate (working on pre-win10 only)
    if(!PE_SectionGetFromName(pSystemProcess, ctxVmm->kernel.vaBase, "ALMOSTRO", &SectionHeader)) { return 0; }
    if(!VmmRead(pSystemProcess, ctxVmm->kernel.vaBase + SectionHeader.VirtualAddress, pbALMOSTRO, sizeof(pbALMOSTRO))) { return 0; }
    for(i = 0; i < sizeof(pbALMOSTRO); i += f32 ? 4 : 8) {
        vaSystemEPROCESS = f32 ? *(PDWORD)(pbALMOSTRO + i) : *(PQWORD)(pbALMOSTRO + i);
        if(f32 ? VMM_KADDR32_8(vaSystemEPROCESS) : VMM_KADDR64_16(vaSystemEPROCESS)) {
            if(VmmRead(pSystemProcess, vaSystemEPROCESS, pbSYSTEM, sizeof(pbSYSTEM))) {
                if(f32 && ((*(PDWORD)(pbSYSTEM + 0x18) & ~0xf) == ctxVmm->kernel.paDTB)) { goto success; }      // 32-bit EPROCESS DTB at fixed offset
                if(!f32 && ((*(PQWORD)(pbSYSTEM + 0x28) & ~0xf) == ctxVmm->kernel.paDTB)) { goto success; }     // 64-bit EPROCESS DTB at fixed offset
            }
        }
    }
    return 0;
success:
    vmmprintfvv_fn("INFO: EPROCESS located at %016llx.\n", vaSystemEPROCESS);
    return vaSystemEPROCESS;
}

/*
* Async initialization of remaining actions in VmmWinInit_TryInitialize.
* -- lpParameter
* -- return
*/
DWORD VmmWinInit_TryInitialize_Async(LPVOID lpParameter)
{
    PDB_Initialize_WaitComplete();
    MmWin_PagingInitialize(TRUE);   // initialize full paging (memcompression)
    VmmWinInit_TryInitializeThreading();
    VmmWinInit_TryInitializeKernelOptionalValues();
    return 1;
}

/*
* Try initialize the VMM from scratch with new WINDOWS support.
* -- paDTBOpt
* -- return
*/
BOOL VmmWinInit_TryInitialize(_In_opt_ QWORD paDTBOpt)
{
    HANDLE hThreadInitializeAsync;
    PVMM_PROCESS pObSystemProcess = NULL, pObProcess = NULL;
    // Fetch Directory Base (DTB (PML4)) and initialize Memory Model.
    if(paDTBOpt) {
        if(!VmmWinInit_DTB_Validate(paDTBOpt)) {
            vmmprintfv("VmmWinInit_TryInitialize: Initialization Failed. Unable to verify user-supplied (0x%016llx) DTB. #1\n", paDTBOpt);
            goto fail;
        }
    } else if(LcGetOption(ctxMain->hLC, LC_OPT_MEMORYINFO_OS_DTB, &paDTBOpt)) {
        if(!VmmWinInit_DTB_Validate(paDTBOpt)) {
            vmmprintfv("VmmWinInit_TryInitialize: Warning: Unable to verify crash-dump supplied DTB. (0x%016llx) #1\n", paDTBOpt);
            goto fail;
        }
    } else if(!ctxVmm->kernel.paDTB) {
        if(!VmmWinInit_DTB_FindValidate()) {
            vmmprintfv("VmmWinInit_TryInitialize: Initialization Failed. Unable to locate valid DTB. #2\n");
            goto fail;
        }
    }
    vmmprintfvv_fn("INFO: DTB  located at: %016llx. MemoryModel: %s\n", ctxVmm->kernel.paDTB, VMM_MEMORYMODEL_TOSTRING[ctxVmm->tpMemoryModel]);
    // Fetch 'ntoskrnl.exe' base address
    if(!(pObSystemProcess = VmmWinInit_FindNtosScan())) {
        vmmprintfv("VmmWinInit_TryInitialize: Initialization Failed. Unable to locate ntoskrnl.exe. #3\n");
        goto fail;
    }
    vmmprintfvv_fn("INFO: NTOS located at: %016llx.\n", ctxVmm->kernel.vaBase);
    // Initialize Paging (Limited Mode)
    MmWin_PagingInitialize(FALSE);
    // Locate System EPROCESS
    pObSystemProcess->win.EPROCESS.va = VmmWinInit_FindSystemEPROCESS(pObSystemProcess);
    if(!pObSystemProcess->win.EPROCESS.va) {
        vmmprintfv_fn("Initialization Failed. Unable to locate EPROCESS. #4\n");
        goto fail;
    }
    // Enumerate processes
    if(!VmmWinProcess_Enumerate(pObSystemProcess, TRUE)) {
        vmmprintfv("VmmWinInit: Initialization Failed. Unable to walk EPROCESS. #5\n");
        goto fail;
    }
    ctxVmm->tpSystem = (VMM_MEMORYMODEL_X64 == ctxVmm->tpMemoryModel) ? VMM_SYSTEM_WINDOWS_X64 : VMM_SYSTEM_WINDOWS_X86;
    // Retrieve operating system version information from 'smss.exe' process
    // Optionally retrieve PID of Registry process
    while((pObProcess = VmmProcessGetNext(pObProcess, 0))) {
        if(pObProcess->dwPPID == 4) {
            if(!memcmp("Registry", pObProcess->szName, 9)) {
                ctxVmm->kernel.dwPidRegistry = pObProcess->dwPID;
            }
            if(!_stricmp("smss.exe", pObProcess->szName)) {
                VmmWinInit_VersionNumber(pObProcess);
            }
        }
    }
    // Initialization functionality:
    PDB_Initialize(NULL, TRUE);                                 // Async init of PDB subsystem.
    VmmWinInit_FindPsLoadedModuleListKDBG(pObSystemProcess);    // Find PsLoadedModuleList and possibly KDBG.
    VmmWinObj_Initialize();                                     // Windows Objects Manager.
    VmmWinReg_Initialize();                                     // Registry.
    // Async Initialization functionality:
    hThreadInitializeAsync = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)VmmWinInit_TryInitialize_Async, (LPVOID)NULL, 0, NULL);
    if(hThreadInitializeAsync) {
        if(ctxMain->cfg.fWaitInitialize) {
            WaitForSingleObject(hThreadInitializeAsync, INFINITE);
        }
        CloseHandle(hThreadInitializeAsync);
    }
    // return
    Ob_DECREF(pObSystemProcess);
    vmmprintf(
        "Initialized %i-bit Windows %i.%i.%i\n",
        (ctxVmm->f32 ? 32 : 64),
        ctxVmm->kernel.dwVersionMajor,
        ctxVmm->kernel.dwVersionMinor,
        ctxVmm->kernel.dwVersionBuild);
    return TRUE;
fail:
    VmmInitializeMemoryModel(VMM_MEMORYMODEL_NA); // clean memory model
    ZeroMemory(&ctxVmm->kernel, sizeof(VMM_KERNELINFO));
    Ob_DECREF(pObSystemProcess);
    return FALSE;
}
