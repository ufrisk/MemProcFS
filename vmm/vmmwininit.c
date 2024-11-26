// vmmwininit.c : implementation of detection mechanisms for Windows operating
//                systems. Contains functions for detecting DTB and Memory Model
//                as well as the Windows kernel base and core functionality.
//
// (c) Ulf Frisk, 2018-2024
// Author: Ulf Frisk, pcileech@frizk.net
//

#include "vmm.h"
#include "pe.h"
#include "pdb.h"
#include "util.h"
#include "vmmlog.h"
#include "vmmwin.h"
#include "vmmwinobj.h"
#include "vmmwinreg.h"
#include "infodb.h"
#include "mm/mm.h"
#include "charutil.h"

/*
* Try initialize threading - this is dependent on available PDB symbols.
* -- H
*/
VOID VmmWinInit_TryInitializeThreading(_In_ VMM_HANDLE H)
{
    BOOL f;
    DWORD cbEThread = 0;
    PVMM_OFFSET_ETHREAD pti = &H->vmm.offset.ETHREAD;
    f = PDB_GetTypeChildOffsetShort(H, PDB_HANDLE_KERNEL, "_EPROCESS", "ThreadListHead", &pti->oThreadListHeadKP) &&
        PDB_GetTypeChildOffsetShort(H, PDB_HANDLE_KERNEL, "_KTHREAD", "StackBase", &pti->oStackBase) &&
        PDB_GetTypeChildOffsetShort(H, PDB_HANDLE_KERNEL, "_KTHREAD", "StackLimit", &pti->oStackLimit) &&
        PDB_GetTypeChildOffsetShort(H, PDB_HANDLE_KERNEL, "_KTHREAD", "State", &pti->oState) &&
        PDB_GetTypeChildOffsetShort(H, PDB_HANDLE_KERNEL, "_KTHREAD", "SuspendCount", &pti->oSuspendCount) &&
        PDB_GetTypeChildOffsetShort(H, PDB_HANDLE_KERNEL, "_KTHREAD", "Priority", &pti->oPriority) &&
        PDB_GetTypeChildOffsetShort(H, PDB_HANDLE_KERNEL, "_KTHREAD", "BasePriority", &pti->oBasePriority) &&
        PDB_GetTypeChildOffsetShort(H, PDB_HANDLE_KERNEL, "_KTHREAD", "WaitReason", &pti->oWaitReason) &&
        PDB_GetTypeChildOffsetShort(H, PDB_HANDLE_KERNEL, "_KTHREAD", "Teb", &pti->oTeb) &&
        PDB_GetTypeChildOffsetShort(H, PDB_HANDLE_KERNEL, "_KTHREAD", "TrapFrame", &pti->oTrapFrame) &&
        PDB_GetTypeChildOffsetShort(H, PDB_HANDLE_KERNEL, "_KTHREAD", "KernelTime", &pti->oKernelTime) &&
        PDB_GetTypeChildOffsetShort(H, PDB_HANDLE_KERNEL, "_KTHREAD", "UserTime", &pti->oUserTime) &&
        PDB_GetTypeChildOffsetShort(H, PDB_HANDLE_KERNEL, "_KTHREAD", "Affinity", &pti->oAffinity) &&
        PDB_GetTypeChildOffsetShort(H, PDB_HANDLE_KERNEL, "_ETHREAD", "CreateTime", &pti->oCreateTime) &&
        PDB_GetTypeChildOffsetShort(H, PDB_HANDLE_KERNEL, "_ETHREAD", "ExitTime", &pti->oExitTime) &&
        PDB_GetTypeChildOffsetShort(H, PDB_HANDLE_KERNEL, "_ETHREAD", "ExitStatus", &pti->oExitStatus) &&
        PDB_GetTypeChildOffsetShort(H, PDB_HANDLE_KERNEL, "_ETHREAD", "StartAddress", &pti->oStartAddress) &&
        PDB_GetTypeChildOffsetShort(H, PDB_HANDLE_KERNEL, "_ETHREAD", "Win32StartAddress", &pti->oWin32StartAddress) &&
        PDB_GetTypeChildOffsetShort(H, PDB_HANDLE_KERNEL, "_ETHREAD", "ThreadListEntry", &pti->oThreadListEntry) &&
        PDB_GetTypeChildOffsetShort(H, PDB_HANDLE_KERNEL, "_ETHREAD", "Cid", &pti->oCid) &&
        PDB_GetTypeSize(H, PDB_HANDLE_KERNEL, "_ETHREAD", &cbEThread) &&
        (PDB_GetTypeChildOffsetShort(H, PDB_HANDLE_KERNEL, "_KTRAP_FRAME", "Rip", &pti->oTrapRip) || PDB_GetTypeChildOffsetShort(H, PDB_HANDLE_KERNEL, "_KTRAP_FRAME", "Eip", &pti->oTrapRip)) &&
        (PDB_GetTypeChildOffsetShort(H, PDB_HANDLE_KERNEL, "_KTRAP_FRAME", "Rsp", &pti->oTrapRsp) || PDB_GetTypeChildOffsetShort(H, PDB_HANDLE_KERNEL, "_KTRAP_FRAME", "HardwareEsp", &pti->oTrapRsp));
    PDB_GetTypeChildOffsetShort(H, PDB_HANDLE_KERNEL, "_KTHREAD", "Process", &pti->oProcessOpt);                // optional - does not exist in xp.
    PDB_GetTypeChildOffsetShort(H, PDB_HANDLE_KERNEL, "_KTHREAD", "Running", &pti->oRunningOpt);                // optional - does not exist in vista/xp.
    PDB_GetTypeChildOffsetShort(H, PDB_HANDLE_KERNEL, "_ETHREAD", "ClientSecurity", &pti->oClientSecurityOpt);  // optional - does not exist in xp.
    pti->oMax = (WORD)(cbEThread + 8);
    pti->oTebStackBase = H->vmm.f32 ? 0x004 : 0x008;
    pti->oTebStackLimit = H->vmm.f32 ? 0x008 : 0x010;
    H->vmm.fThreadMapEnabled = f;
}

/*
* Try initialize not yet initialized values in the optional windows kernel
* context H->vmm.kernel.opt
* This function should be run once the system is fully up and running.
* This is a best-effort function, uninitialized values will remain zero.
* -- H
*/
VOID VmmWinInit_TryInitializeKernelOptionalValues(_In_ VMM_HANDLE H)
{
    BOOL f;
    PVMM_PROCESS pObSystemProcess = NULL;
    POB_REGISTRY_HIVE pObHive = NULL;
    POB_REGISTRY_KEY pObKey = NULL;
    POB_MAP pmObSubkeys = NULL;
    DWORD oKdpDataBlockEncoded, dwKDBG, dwo;
    BYTE bKdpDataBlockEncoded;
    PVMM_OFFSET_FILE pof;
    if(H->vmm.kernel.opt.fInitialized) { return; }
    if(!(pObSystemProcess = VmmProcessGet(H, 4))) { return; }
    // Optional EPROCESS and _TOKEN offsets
    if(!H->vmm.offset.EPROCESS.opt.Token) {
        // EPROCESS / KPROCESS
        if(PDB_GetTypeChildOffset(H, PDB_HANDLE_KERNEL, "_EPROCESS", "Token", &dwo) && (dwo < pObSystemProcess->win.EPROCESS.cb - 8)) {
            H->vmm.offset.EPROCESS.opt.Token = (WORD)dwo;
        }
        if(PDB_GetTypeChildOffset(H, PDB_HANDLE_KERNEL, "_EPROCESS", "CreateTime", &dwo) && (dwo < pObSystemProcess->win.EPROCESS.cb - 8)) {
            H->vmm.offset.EPROCESS.opt.CreateTime = (WORD)dwo;
        }
        if(PDB_GetTypeChildOffset(H, PDB_HANDLE_KERNEL, "_EPROCESS", "ExitTime", &dwo) && (dwo < pObSystemProcess->win.EPROCESS.cb - 8)) {
            H->vmm.offset.EPROCESS.opt.ExitTime = (WORD)dwo;
        }
        if(PDB_GetTypeChildOffset(H, PDB_HANDLE_KERNEL, "_EPROCESS", "SectionBaseAddress", &dwo) && (dwo < pObSystemProcess->win.EPROCESS.cb - 8)) {
            H->vmm.offset.EPROCESS.opt.SectionBaseAddress = (WORD)dwo;
        }
        if(PDB_GetTypeChildOffset(H, PDB_HANDLE_KERNEL, "_KPROCESS", "KernelTime", &dwo) && (dwo < pObSystemProcess->win.EPROCESS.cb - 8)) {
            H->vmm.offset.EPROCESS.opt.KernelTime = (WORD)dwo;
        }
        if(PDB_GetTypeChildOffset(H, PDB_HANDLE_KERNEL, "_KPROCESS", "UserTime", &dwo) && (dwo < pObSystemProcess->win.EPROCESS.cb - 8)) {
            H->vmm.offset.EPROCESS.opt.UserTime = (WORD)dwo;
        }
        // TOKEN
        PDB_GetTypeSizeShort(H, PDB_HANDLE_KERNEL, "_TOKEN", &H->vmm.offset.EPROCESS.opt.TOKEN_cb);
        PDB_GetTypeChildOffsetShort(H, PDB_HANDLE_KERNEL, "_TOKEN", "IntegrityLevelIndex", &H->vmm.offset.EPROCESS.opt.TOKEN_IntegrityLevelIndex);
        PDB_GetTypeChildOffsetShort(H, PDB_HANDLE_KERNEL, "_TOKEN", "Privileges", &H->vmm.offset.EPROCESS.opt.TOKEN_Privileges);
        PDB_GetTypeChildOffsetShort(H, PDB_HANDLE_KERNEL, "_TOKEN", "SessionId", &H->vmm.offset.EPROCESS.opt.TOKEN_SessionId);
        PDB_GetTypeChildOffsetShort(H, PDB_HANDLE_KERNEL, "_TOKEN", "TokenId", &H->vmm.offset.EPROCESS.opt.TOKEN_TokenId);
        PDB_GetTypeChildOffsetShort(H, PDB_HANDLE_KERNEL, "_TOKEN", "UserAndGroups", &H->vmm.offset.EPROCESS.opt.TOKEN_UserAndGroups);
        PDB_GetTypeChildOffsetShort(H, PDB_HANDLE_KERNEL, "_TOKEN", "UserAndGroupCount", &H->vmm.offset.EPROCESS.opt.TOKEN_UserAndGroupCount);
    }
    // Optional _FILE_OBJECT related offsets
    if(!H->vmm.offset.FILE.fValid) {
        pof = &H->vmm.offset.FILE;
        // _FILE_OBJECT
        PDB_GetTypeSizeShort(H, PDB_HANDLE_KERNEL, "_FILE_OBJECT", &pof->_FILE_OBJECT.cb);
        PDB_GetTypeChildOffsetShort(H, PDB_HANDLE_KERNEL, "_FILE_OBJECT", "DeviceObject", &pof->_FILE_OBJECT.oDeviceObject);
        PDB_GetTypeChildOffsetShort(H, PDB_HANDLE_KERNEL, "_FILE_OBJECT", "FsContext", &pof->_FILE_OBJECT.oFsContext);
        PDB_GetTypeChildOffsetShort(H, PDB_HANDLE_KERNEL, "_FILE_OBJECT", "SectionObjectPointer", &pof->_FILE_OBJECT.oSectionObjectPointer);
        PDB_GetTypeChildOffsetShort(H, PDB_HANDLE_KERNEL, "_FILE_OBJECT", "FileName", &pof->_FILE_OBJECT.oFileName);
        pof->_FILE_OBJECT.oFileNameBuffer       = pof->_FILE_OBJECT.oFileName + (H->vmm.f32 ? 4 : 8);
        // _FSRTL_COMMON_FCB_HEADER
        PDB_GetTypeSizeShort(H, PDB_HANDLE_KERNEL, "_FSRTL_ADVANCED_FCB_HEADER", &pof->_FSRTL_COMMON_FCB_HEADER.cb);
        PDB_GetTypeChildOffsetShort(H, PDB_HANDLE_KERNEL, "_FSRTL_ADVANCED_FCB_HEADER", "Version", &pof->_FSRTL_COMMON_FCB_HEADER.oVersion);
        PDB_GetTypeChildOffsetShort(H, PDB_HANDLE_KERNEL, "_FSRTL_ADVANCED_FCB_HEADER", "Resource", &pof->_FSRTL_COMMON_FCB_HEADER.oResource);
        PDB_GetTypeChildOffsetShort(H, PDB_HANDLE_KERNEL, "_FSRTL_ADVANCED_FCB_HEADER", "AllocationSize", &pof->_FSRTL_COMMON_FCB_HEADER.oAllocationSize);
        PDB_GetTypeChildOffsetShort(H, PDB_HANDLE_KERNEL, "_FSRTL_ADVANCED_FCB_HEADER", "FileSize", &pof->_FSRTL_COMMON_FCB_HEADER.oFileSize);
        PDB_GetTypeChildOffsetShort(H, PDB_HANDLE_KERNEL, "_FSRTL_ADVANCED_FCB_HEADER", "ValidDataLength", &pof->_FSRTL_COMMON_FCB_HEADER.oValidDataLength);
        // _SECTION_OBJECT_POINTERS
        PDB_GetTypeSizeShort(H, PDB_HANDLE_KERNEL, "_SECTION_OBJECT_POINTERS", &pof->_SECTION_OBJECT_POINTERS.cb);
        PDB_GetTypeChildOffsetShort(H, PDB_HANDLE_KERNEL, "_SECTION_OBJECT_POINTERS", "DataSectionObject", &pof->_SECTION_OBJECT_POINTERS.oDataSectionObject);
        PDB_GetTypeChildOffsetShort(H, PDB_HANDLE_KERNEL, "_SECTION_OBJECT_POINTERS", "SharedCacheMap", &pof->_SECTION_OBJECT_POINTERS.oSharedCacheMap);
        PDB_GetTypeChildOffsetShort(H, PDB_HANDLE_KERNEL, "_SECTION_OBJECT_POINTERS", "ImageSectionObject", &pof->_SECTION_OBJECT_POINTERS.oImageSectionObject);
        // _VACB
        PDB_GetTypeSizeShort(H, PDB_HANDLE_KERNEL, "_VACB", &pof->_VACB.cb);
        PDB_GetTypeChildOffsetShort(H, PDB_HANDLE_KERNEL, "_VACB", "BaseAddress", &pof->_VACB.oBaseAddress);
        PDB_GetTypeChildOffsetShort(H, PDB_HANDLE_KERNEL, "_VACB", "SharedCacheMap", &pof->_VACB.oSharedCacheMap);
        // _SHARED_CACHE_MAP
        PDB_GetTypeSizeShort(H, PDB_HANDLE_KERNEL, "_SHARED_CACHE_MAP", &pof->_SHARED_CACHE_MAP.cb);
        PDB_GetTypeChildOffsetShort(H, PDB_HANDLE_KERNEL, "_SHARED_CACHE_MAP", "FileSize", &pof->_SHARED_CACHE_MAP.oFileSize);
        PDB_GetTypeChildOffsetShort(H, PDB_HANDLE_KERNEL, "_SHARED_CACHE_MAP", "SectionSize", &pof->_SHARED_CACHE_MAP.oSectionSize);
        PDB_GetTypeChildOffsetShort(H, PDB_HANDLE_KERNEL, "_SHARED_CACHE_MAP", "ValidDataLength", &pof->_SHARED_CACHE_MAP.oValidDataLength);
        PDB_GetTypeChildOffsetShort(H, PDB_HANDLE_KERNEL, "_SHARED_CACHE_MAP", "InitialVacbs", &pof->_SHARED_CACHE_MAP.oInitialVacbs);
        PDB_GetTypeChildOffsetShort(H, PDB_HANDLE_KERNEL, "_SHARED_CACHE_MAP", "Vacbs", &pof->_SHARED_CACHE_MAP.oVacbs);
        PDB_GetTypeChildOffsetShort(H, PDB_HANDLE_KERNEL, "_SHARED_CACHE_MAP", "FileObjectFastRef", &pof->_SHARED_CACHE_MAP.oFileObjectFastRef);
        // _CONTROL_AREA
        PDB_GetTypeSizeShort(H, PDB_HANDLE_KERNEL, "_CONTROL_AREA", &pof->_CONTROL_AREA.cb);
        PDB_GetTypeChildOffsetShort(H, PDB_HANDLE_KERNEL, "_CONTROL_AREA", "Segment", &pof->_CONTROL_AREA.oSegment);
        PDB_GetTypeChildOffsetShort(H, PDB_HANDLE_KERNEL, "_CONTROL_AREA", "FilePointer", &pof->_CONTROL_AREA.oFilePointer);
        // _SECTION_IMAGE_INFORMATION
        PDB_GetTypeSizeShort(H, PDB_HANDLE_KERNEL, "_SECTION_IMAGE_INFORMATION", &pof->_SECTION_IMAGE_INFORMATION.cb);
        PDB_GetTypeChildOffsetShort(H, PDB_HANDLE_KERNEL, "_SECTION_IMAGE_INFORMATION", "ImageFileSize", &pof->_SECTION_IMAGE_INFORMATION.oImageFileSize);
        // _SEGMENT
        PDB_GetTypeSizeShort(H, PDB_HANDLE_KERNEL, "_SEGMENT", &pof->_SEGMENT.cb);
        PDB_GetTypeChildOffsetShort(H, PDB_HANDLE_KERNEL, "_SEGMENT", "ControlArea", &pof->_SEGMENT.oControlArea);
        PDB_GetTypeChildOffsetShort(H, PDB_HANDLE_KERNEL, "_SEGMENT", "SegmentFlags", &pof->_SEGMENT.oSegmentFlags);
        PDB_GetTypeChildOffsetShort(H, PDB_HANDLE_KERNEL, "_SEGMENT", "SizeOfSegment", &pof->_SEGMENT.oSizeOfSegment);
        PDB_GetTypeChildOffsetShort(H, PDB_HANDLE_KERNEL, "_SEGMENT", "u2", &pof->_SEGMENT.oU2);
        PDB_GetTypeChildOffsetShort(H, PDB_HANDLE_KERNEL, "_SEGMENT", "PrototypePte", &pof->_SEGMENT.oPrototypePte);
        // _SUBSECTION
        PDB_GetTypeSizeShort(H, PDB_HANDLE_KERNEL, "_SUBSECTION", &pof->_SUBSECTION.cb);
        PDB_GetTypeChildOffsetShort(H, PDB_HANDLE_KERNEL, "_SUBSECTION", "ControlArea", &pof->_SUBSECTION.oControlArea);
        PDB_GetTypeChildOffsetShort(H, PDB_HANDLE_KERNEL, "_SUBSECTION", "NextSubsection", &pof->_SUBSECTION.oNextSubsection);
        PDB_GetTypeChildOffsetShort(H, PDB_HANDLE_KERNEL, "_SUBSECTION", "NumberOfFullSectors", &pof->_SUBSECTION.oNumberOfFullSectors);
        PDB_GetTypeChildOffsetShort(H, PDB_HANDLE_KERNEL, "_SUBSECTION", "PtesInSubsection", &pof->_SUBSECTION.oPtesInSubsection);
        PDB_GetTypeChildOffsetShort(H, PDB_HANDLE_KERNEL, "_SUBSECTION", "StartingSector", &pof->_SUBSECTION.oStartingSector);
        PDB_GetTypeChildOffsetShort(H, PDB_HANDLE_KERNEL, "_SUBSECTION", "SubsectionBase", &pof->_SUBSECTION.oSubsectionBase);
        pof->fValid = pof->_SUBSECTION.cb ? TRUE : FALSE;
    }
    // cpu count
    if(!H->vmm.kernel.opt.cCPUs) {
        PDB_GetSymbolDWORD(H, PDB_HANDLE_KERNEL, "KiTotalCpuSetCount", pObSystemProcess, &H->vmm.kernel.opt.cCPUs);
        if(H->vmm.kernel.opt.cCPUs > 128) { H->vmm.kernel.opt.cCPUs = 0; }
    }
    if(!H->vmm.kernel.opt.cCPUs && VmmWinReg_KeyHiveGetByFullPath(H, "HKLM\\HARDWARE\\DESCRIPTION\\System\\CentralProcessor", &pObHive, &pObKey)) {
        pmObSubkeys = VmmWinReg_KeyList(H, pObHive, pObKey);
        H->vmm.kernel.opt.cCPUs = ObMap_Size(pmObSubkeys);
    }
    // pfn database & pfn subsystem initialize
    if(!H->vmm.kernel.opt.vaPfnDatabase) {
        PDB_GetSymbolPTR(H, PDB_HANDLE_KERNEL, "MmPfnDatabase", pObSystemProcess, &H->vmm.kernel.opt.vaPfnDatabase);
    }
    // PsLoadedModuleListExp
    if(!H->vmm.kernel.opt.vaPsLoadedModuleListExp) {
        PDB_GetSymbolAddress(H, PDB_HANDLE_KERNEL, "PsLoadedModuleList", &H->vmm.kernel.opt.vaPsLoadedModuleListExp);
    }
    // MmUnloadedDrivers / MmLastUnloadedDriver
    if(!H->vmm.kernel.opt.vaMmUnloadedDrivers || !H->vmm.kernel.opt.vaMmLastUnloadedDriver) {
        PDB_GetSymbolAddress(H, PDB_HANDLE_KERNEL, "MmUnloadedDrivers", &H->vmm.kernel.opt.vaMmUnloadedDrivers);
        PDB_GetSymbolAddress(H, PDB_HANDLE_KERNEL, "MmLastUnloadedDriver", &H->vmm.kernel.opt.vaMmLastUnloadedDriver);
    }
    // KdDebuggerDataBlock (KDBG)
    if(!H->vmm.kernel.opt.KDBG.va && PDB_GetSymbolAddress(H, PDB_HANDLE_KERNEL, "KdDebuggerDataBlock", &H->vmm.kernel.opt.KDBG.va)) {
        f = !H->vmm.f32 &&
            VmmRead(H, pObSystemProcess, H->vmm.kernel.opt.KDBG.va + 0x10, (PBYTE)&dwKDBG, sizeof(DWORD)) && (dwKDBG != 0x4742444b) &&
            PDB_GetSymbolOffset(H, PDB_HANDLE_KERNEL, "KdpDataBlockEncoded", &oKdpDataBlockEncoded) &&
            PDB_GetSymbolPBYTE(H, PDB_HANDLE_KERNEL, "KdpDataBlockEncoded", pObSystemProcess, &bKdpDataBlockEncoded, 1) &&
            (bKdpDataBlockEncoded == 1);
        if(f) {
            H->vmm.kernel.opt.KDBG.vaKdpDataBlockEncoded = H->vmm.kernel.vaBase + oKdpDataBlockEncoded;
            PDB_GetSymbolQWORD(H, PDB_HANDLE_KERNEL, "KiWaitAlways", pObSystemProcess, &H->vmm.kernel.opt.KDBG.qwKiWaitAlways);
            PDB_GetSymbolQWORD(H, PDB_HANDLE_KERNEL, "KiWaitNever", pObSystemProcess, &H->vmm.kernel.opt.KDBG.qwKiWaitNever);
        }
    }
    // IopInvalidDeviceRequest
    if(!H->vmm.kernel.opt.vaIopInvalidDeviceRequest) {
        PDB_GetSymbolAddress(H, PDB_HANDLE_KERNEL, "IopInvalidDeviceRequest", &H->vmm.kernel.opt.vaIopInvalidDeviceRequest);
    }
    // _OBJECT_HEADER InfoMask headers:
    PDB_GetTypeSizeShort(H, PDB_HANDLE_KERNEL, "_OBJECT_HEADER_CREATOR_INFO", &H->vmm.offset._OBJECT_HEADER_CREATOR_INFO.cb);
    PDB_GetTypeSizeShort(H, PDB_HANDLE_KERNEL, "_OBJECT_HEADER_NAME_INFO",    &H->vmm.offset._OBJECT_HEADER_NAME_INFO.cb);
    PDB_GetTypeSizeShort(H, PDB_HANDLE_KERNEL, "_OBJECT_HEADER_HANDLE_INFO",  &H->vmm.offset._OBJECT_HEADER_HANDLE_INFO.cb);
    PDB_GetTypeSizeShort(H, PDB_HANDLE_KERNEL, "_OBJECT_HEADER_QUOTA_INFO",   &H->vmm.offset._OBJECT_HEADER_QUOTA_INFO.cb);
    PDB_GetTypeSizeShort(H, PDB_HANDLE_KERNEL, "_OBJECT_HEADER_PROCESS_INFO", &H->vmm.offset._OBJECT_HEADER_PROCESS_INFO.cb);
    PDB_GetTypeSizeShort(H, PDB_HANDLE_KERNEL, "_OBJECT_HEADER_AUDIT_INFO",   &H->vmm.offset._OBJECT_HEADER_AUDIT_INFO.cb);
    PDB_GetTypeSizeShort(H, PDB_HANDLE_KERNEL, "_POOL_HEADER",                &H->vmm.offset._POOL_HEADER.cb);
    // Other:
    PDB_GetSymbolQWORD(H, PDB_HANDLE_KERNEL, "KeBootTime", pObSystemProcess, &H->vmm.kernel.opt.ftBootTime);
    // Cleanup
    Ob_DECREF(pObKey);
    Ob_DECREF(pObHive);
    Ob_DECREF(pmObSubkeys);
    Ob_DECREF(pObSystemProcess);
    H->vmm.kernel.opt.fInitialized = TRUE;
}

/*
* Log heap offsets
*/
VOID VmmWinInit_InitializeOffsetStatic_Heap_Print(_In_ VMM_HANDLE H, _In_ BOOL f32, _In_ PVMM_OFFSET_HEAP po)
{
    if(!VmmLogIsActive(H, MID_OFFSET, LOGLEVEL_6_TRACE)) { return; }
    VmmLog(H, MID_OFFSET, LOGLEVEL_6_TRACE, "HEAP: %s(%s)", (po->fValid ? "SUCCESS" : "FAIL"), (f32 ? "32" : "64"));
    VmmLog(H, MID_OFFSET, LOGLEVEL_6_TRACE, "  _HEAP: Encoding: %03x VirtualAllocdBlocks: %03x FrontEndHeap: %03x FrontEndHeapType: %03x" ,
        po->nt.HEAP.Encoding, po->nt.HEAP.VirtualAllocdBlocks, po->nt.HEAP.FrontEndHeap, po->nt.HEAP.FrontEndHeapType);
    VmmLog(H, MID_OFFSET, LOGLEVEL_6_TRACE, "  _HEAP_SEGMENT: FirstEntry(%03x FirstEntry(%03x",
        po->nt.HEAP_SEGMENT.FirstEntry, po->nt.HEAP_SEGMENT.LastValidEntry);
    VmmLog(H, MID_OFFSET, LOGLEVEL_6_TRACE, "  _HEAP_USERDATA_HEADER: Signature: %03x EncodedOffsets: %03x BusyBitmap: %03x BitmapData: %03x",
        po->nt.HEAP_USERDATA_HEADER.Signature, po->nt.HEAP_USERDATA_HEADER.EncodedOffsets, po->nt.HEAP_USERDATA_HEADER.BusyBitmap, po->nt.HEAP_USERDATA_HEADER.BitmapData);
    VmmLog(H, MID_OFFSET, LOGLEVEL_6_TRACE, "  _SEGMENT_HEAP: LargeAllocMetadata: %03x LargeReservedPages: %03x SegContexts: %03x",
        po->seg.SEGMENT_HEAP.LargeAllocMetadata, po->seg.SEGMENT_HEAP.LargeReservedPages, po->seg.SEGMENT_HEAP.SegContexts);
    VmmLog(H, MID_OFFSET, LOGLEVEL_6_TRACE, "  _HEAP_SEG_CONTEXT: SegmentListHead: %03x UnitShift: %03x FirstDescriptorIndex: %03x",
        po->seg.HEAP_SEG_CONTEXT.SegmentListHead, po->seg.HEAP_SEG_CONTEXT.UnitShift, po->seg.HEAP_SEG_CONTEXT.FirstDescriptorIndex);
    VmmLog(H, MID_OFFSET, LOGLEVEL_6_TRACE, "  _HEAP_PAGE_RANGE_DESCRIPTOR: TreeSignature: %03x RangeFlags: %03x UnitSize: %03x",
        po->seg.HEAP_PAGE_RANGE_DESCRIPTOR.TreeSignature, po->seg.HEAP_PAGE_RANGE_DESCRIPTOR.RangeFlags, po->seg.HEAP_PAGE_RANGE_DESCRIPTOR.UnitSize);
    VmmLog(H, MID_OFFSET, LOGLEVEL_6_TRACE, "  _HEAP_LFH_SUBSEGMENT: BlockOffsets: %03x BlockBitmap: %03x",
        po->seg.HEAP_LFH_SUBSEGMENT.BlockOffsets, po->seg.HEAP_LFH_SUBSEGMENT.BlockBitmap);
    VmmLog(H, MID_OFFSET, LOGLEVEL_6_TRACE, "  _SEGMENT_HEAP %03x _HEAP_SEG_CONTEXT %03x _HEAP_PAGE_SEGMENT %03x _HEAP_PAGE_RANGE_DESCRIPTOR %03x _HEAP_VS_CHUNK_HEADER %03x ",
        po->seg.SEGMENT_HEAP.cb, po->seg.HEAP_SEG_CONTEXT.cb, po->seg.HEAP_PAGE_SEGMENT.cb, po->seg.HEAP_PAGE_RANGE_DESCRIPTOR.cb, po->seg.HEAP_VS_CHUNK_HEADER.cb);
}

/*
* Initialization of heap offsets statically based on build number.
* -- H
*/
VOID VmmWinInit_InitializeOffsetStatic_Heap(_In_ VMM_HANDLE H)
{
    DWORD i;
    BOOL f32;
    PDB_HANDLE hPDB;
    PVMM_OFFSET_HEAP po;
    for(i = 0; i < 2; i++) {
        if(H->vmm.f32) {
            if(i) { return; }
            f32 = TRUE;
            hPDB = PDB_HANDLE_NTDLL;
            po = &H->vmm.offset.HEAP32;
        } else {
            f32 = i ? FALSE : TRUE;
            hPDB = f32 ? PDB_HANDLE_NTDLL_WOW64 : PDB_HANDLE_NTDLL;
            po = f32 ? &H->vmm.offset.HEAP32 : &H->vmm.offset.HEAP64;
        }
        // NT HEAP:
        PDB_GetTypeChildOffsetShort(H, hPDB, "_HEAP", "Encoding", &po->nt.HEAP.Encoding);
        PDB_GetTypeChildOffsetShort(H, hPDB, "_HEAP", "VirtualAllocdBlocks", &po->nt.HEAP.VirtualAllocdBlocks);
        PDB_GetTypeChildOffsetShort(H, hPDB, "_HEAP", "FrontEndHeap", &po->nt.HEAP.FrontEndHeap);
        PDB_GetTypeChildOffsetShort(H, hPDB, "_HEAP", "FrontEndHeapType", &po->nt.HEAP.FrontEndHeapType);
        PDB_GetTypeChildOffsetShort(H, hPDB, "_HEAP_SEGMENT", "FirstEntry", &po->nt.HEAP_SEGMENT.FirstEntry);
        PDB_GetTypeChildOffsetShort(H, hPDB, "_HEAP_SEGMENT", "LastValidEntry", &po->nt.HEAP_SEGMENT.LastValidEntry);
        PDB_GetTypeChildOffsetShort(H, hPDB, "_HEAP_USERDATA_HEADER", "Signature", &po->nt.HEAP_USERDATA_HEADER.Signature);
        PDB_GetTypeChildOffsetShort(H, hPDB, "_HEAP_USERDATA_HEADER", "EncodedOffsets", &po->nt.HEAP_USERDATA_HEADER.EncodedOffsets);
        PDB_GetTypeChildOffsetShort(H, hPDB, "_HEAP_USERDATA_HEADER", "BusyBitmap", &po->nt.HEAP_USERDATA_HEADER.BusyBitmap);
        PDB_GetTypeChildOffsetShort(H, hPDB, "_HEAP_USERDATA_HEADER", "BitmapData", &po->nt.HEAP_USERDATA_HEADER.BitmapData);
        // SEGMENT HEAP:
        PDB_GetTypeChildOffsetShort(H, hPDB, "_SEGMENT_HEAP", "LargeAllocMetadata", &po->seg.SEGMENT_HEAP.LargeAllocMetadata);
        PDB_GetTypeChildOffsetShort(H, hPDB, "_SEGMENT_HEAP", "LargeReservedPages", &po->seg.SEGMENT_HEAP.LargeReservedPages);
        PDB_GetTypeChildOffsetShort(H, hPDB, "_SEGMENT_HEAP", "SegContexts", &po->seg.SEGMENT_HEAP.SegContexts);
        PDB_GetTypeChildOffsetShort(H, hPDB, "_HEAP_SEG_CONTEXT", "SegmentListHead", &po->seg.HEAP_SEG_CONTEXT.SegmentListHead);
        PDB_GetTypeChildOffsetShort(H, hPDB, "_HEAP_SEG_CONTEXT", "UnitShift", &po->seg.HEAP_SEG_CONTEXT.UnitShift);
        PDB_GetTypeChildOffsetShort(H, hPDB, "_HEAP_SEG_CONTEXT", "FirstDescriptorIndex", &po->seg.HEAP_SEG_CONTEXT.FirstDescriptorIndex);
        PDB_GetTypeChildOffsetShort(H, hPDB, "_HEAP_PAGE_RANGE_DESCRIPTOR", "TreeSignature", &po->seg.HEAP_PAGE_RANGE_DESCRIPTOR.TreeSignature);
        PDB_GetTypeChildOffsetShort(H, hPDB, "_HEAP_PAGE_RANGE_DESCRIPTOR", "RangeFlags", &po->seg.HEAP_PAGE_RANGE_DESCRIPTOR.RangeFlags);
        PDB_GetTypeChildOffsetShort(H, hPDB, "_HEAP_PAGE_RANGE_DESCRIPTOR", "UnitSize", &po->seg.HEAP_PAGE_RANGE_DESCRIPTOR.UnitSize);
        PDB_GetTypeChildOffsetShort(H, hPDB, "_HEAP_LFH_SUBSEGMENT", "BlockOffsets", &po->seg.HEAP_LFH_SUBSEGMENT.BlockOffsets);
        PDB_GetTypeChildOffsetShort(H, hPDB, "_HEAP_LFH_SUBSEGMENT", "BlockBitmap", &po->seg.HEAP_LFH_SUBSEGMENT.BlockBitmap);
        PDB_GetTypeSizeShort(H, hPDB, "_SEGMENT_HEAP", &po->seg.SEGMENT_HEAP.cb);
        PDB_GetTypeSizeShort(H, hPDB, "_HEAP_SEG_CONTEXT", &po->seg.HEAP_SEG_CONTEXT.cb);
        PDB_GetTypeSizeShort(H, hPDB, "_HEAP_PAGE_SEGMENT", &po->seg.HEAP_PAGE_SEGMENT.cb);
        PDB_GetTypeSizeShort(H, hPDB, "_HEAP_PAGE_RANGE_DESCRIPTOR", &po->seg.HEAP_PAGE_RANGE_DESCRIPTOR.cb);
        PDB_GetTypeSizeShort(H, hPDB, "_HEAP_VS_CHUNK_HEADER", &po->seg.HEAP_VS_CHUNK_HEADER.cb);
        po->seg.HEAP_PAGE_SEGMENT.qwSignatureStaticKey = ((H->vmm.kernel.dwVersionBuild < 26100) ? 0xa2e64eada2e64ead : 0);
        // VALIDITY CHECK AND LOG:
        po->fValid = po->nt.HEAP.VirtualAllocdBlocks || po->nt.HEAP.FrontEndHeap || po->seg.SEGMENT_HEAP.cb;
        VmmWinInit_InitializeOffsetStatic_Heap_Print(H, f32, po);
    }
}

// TODO: FIX THIS ARM64
/*
* Helper/Worker function for VmmWinInit_FindNtosScan64_SmallPageWalk().
* -- H
* -- paTable = set to: physical address of PML4
* -- va = set to 0
* -- vaMin = 0xFFFFF80000000000 (if windows kernel)
* -- vaMax = 0xFFFFF803FFFFFFFF (if windows kernel)
* -- iPML = set to 4
* -- psvaKernelCandidates
*/
VOID VmmWinInit_FindNtosScan64_SmallPageWalk_DoWork(_In_ VMM_HANDLE H, _In_ QWORD paTable, _In_ QWORD vaBase, _In_ QWORD vaMin, _In_ QWORD vaMax, _In_ BYTE iPML, _In_ POB_SET psvaKernelCandidates)
{
    static const QWORD PML_REGION_SIZE[5] = { 0, 12, 21, 30, 39 };
    QWORD i, j, pte, vaCurrent;
    PVMMOB_CACHE_MEM pObPTEs = NULL;
    BOOL f;
    if(iPML == 0) { return; }
    pObPTEs = VmmTlbGetPageTable(H, paTable, FALSE);
    if(!pObPTEs) { return; }
    if(iPML == 4) {
        if(!VmmTlbPageTableVerify(H, pObPTEs->pb, paTable, TRUE)) { goto finish; }
        vaBase = 0;
    }
    if(H->vmm.tpMemoryModel == VMMDLL_MEMORYMODEL_X64) {
        for(i = 0; i < 512; i++) {
            // address in range
            vaCurrent = vaBase + (i << PML_REGION_SIZE[iPML]);
            vaCurrent |= (vaCurrent & 0x0000800000000000) ? 0xffff000000000000 : 0; // sign extend
            if(vaCurrent < vaMin) { continue; }
            if(vaCurrent > vaMax) { goto finish; }
            // check PTEs
            pte = pObPTEs->pqw[i];
            if(!(pte & 0x01)) { continue; }                     // NOT VALID
            if(iPML == 1) {
                if(i && pObPTEs->pqw[i - 1]) { continue; }      // PAGE i-1 NOT EMPTY -> NOT VALID
                if((pte & 0x800000000000000f) != 0x8000000000000003) { continue; } // PAGE i+0 IS ACTIVE-WRITE-SUPERVISOR-NOEXECUTE
                for(j = i + 2, f = TRUE; f && (j < min(i + 32, 512)); j++) {
                    f = ((pObPTEs->pqw[j] & 0x0f) == 0x01);   // PAGE i+1 IS ACTIVE-SUPERVISOR
                }
                if(f) {
                    ObSet_Push(psvaKernelCandidates, vaCurrent);
                }
            }
            if(pte & 0x80) { continue; }                        // PS (large page) -> NOT VALID
            VmmWinInit_FindNtosScan64_SmallPageWalk_DoWork(H, pte & 0x0000fffffffff000, vaCurrent, vaMin, vaMax, iPML - 1, psvaKernelCandidates);
        }
    } else if(H->vmm.tpMemoryModel == VMMDLL_MEMORYMODEL_ARM64) {
        for(i = 0; i < 512; i++) {
            // address in range
            vaCurrent = vaBase + (i << PML_REGION_SIZE[iPML]);
            vaCurrent |= (vaCurrent & 0x0000800000000000) ? 0xffff000000000000 : 0; // sign extend
            if(vaCurrent < vaMin) { continue; }
            if(vaCurrent > vaMax) { goto finish; }
            // check PTEs
            pte = pObPTEs->pqw[i];
            if((pte & 0x00E0000000000003) != 0x0060000000000003) { continue; }    // VALID, NOT_LARGE_PAGE, NO-EXECUTE(USER), NO-EXECUTE(PRIVILEGED), NO-WRITE
            if(iPML == 1) {
                if(i && pObPTEs->pqw[i - 1]) { continue; }      // PAGE i-1 NOT EMPTY -> NOT VALID
                for(j = i + 2, f = TRUE; f && (j < min(i + 32, 512)); j++) {
                    f = ((pObPTEs->pqw[j] & 0x03) == 0x03);   // PAGE i+1 IS VALID, NOT_LARGE_PAGE
                }
                if(f) {
                    ObSet_Push(psvaKernelCandidates, vaCurrent);
                }
            }
            if(pte & 0x80) { continue; }                        // PS (large page) -> NOT VALID
            VmmWinInit_FindNtosScan64_SmallPageWalk_DoWork(H, pte & 0x0000fffffffff000, vaCurrent, vaMin, vaMax, iPML - 1, psvaKernelCandidates);
        }
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
* -- H
* -- pSystemProcess
* -- vaMin = 0xFFFFF80000000000
* -- vaMax = 0xFFFFF803FFFFFFFF
* -- pvaBase
* -- pcbSize
*/
VOID VmmWinInit_FindNtosScan64_SmallPageWalk(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pSystemProcess, _In_ QWORD vaMin, _In_ QWORD vaMax, _Inout_ PQWORD pvaBase, _Inout_ PQWORD pcbSize)
{
    QWORD o, va;
    BYTE pb[4096];
    POB_SET psObKernelVa = NULL;
    if(!(psObKernelVa = ObSet_New(H))) { return; }
    VmmWinInit_FindNtosScan64_SmallPageWalk_DoWork(H, pSystemProcess->paDTB, 0, vaMin, vaMax, 4, psObKernelVa);
    VmmCachePrefetchPages(H, pSystemProcess, psObKernelVa, 0);
    while((va = ObSet_Pop(psObKernelVa))) {
        if(VmmReadPage(H, pSystemProcess, va, pb)) {
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
* -- H
* -- paTable = set to: physical address of PML4
* -- va = set to 0
* -- vaMin = 0xFFFFF80000000000 (if windows kernel)
* -- vaMax = 0xFFFFF803FFFFFFFF (if windows kernel)
* -- iPML = set to 4
* -- pvaBase
* -- pcbSize
*/
VOID VmmWinInit_FindNtosScan64_LargePageWalk(_In_ VMM_HANDLE H, _In_ QWORD paTable, _In_ QWORD vaBase, _In_ QWORD vaMin, _In_ QWORD vaMax, _In_ BYTE iPML, _Inout_ PQWORD pvaBase, _Inout_ PQWORD pcbSize)
{
    const QWORD PML_REGION_SIZE[5] = { 0, 12, 21, 30, 39 };
    QWORD i, pte, vaCurrent;
    PVMMOB_CACHE_MEM pObPTEs = NULL;
    if(iPML == 1) { return; }
    pObPTEs = VmmTlbGetPageTable(H, paTable, FALSE);
    if(!pObPTEs) { return; }
    if(iPML == 4) {
        *pvaBase = 0;
        *pcbSize = 0;
        if(!VmmTlbPageTableVerify(H, pObPTEs->pb, paTable, TRUE)) { goto finish; }
        vaBase = 0;
    }
    if(H->vmm.tpMemoryModel == VMM_MEMORYMODEL_X64) {
        for(i = 0; i < 512; i++) {
            // address in range
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
                VmmWinInit_FindNtosScan64_LargePageWalk(H, pte & 0x0000fffffffff000, vaCurrent, vaMin, vaMax, iPML - 1, pvaBase, pcbSize);
            }
        }
    }
    if(H->vmm.tpMemoryModel == VMM_MEMORYMODEL_ARM64) {
        for(i = 0; i < 512; i++) {
            // address in range
            vaCurrent = vaBase + (i << PML_REGION_SIZE[iPML]);
            vaCurrent |= (vaCurrent & 0x0000800000000000) ? 0xffff000000000000 : 0; // sign extend
            if(*pvaBase && (vaCurrent > (*pvaBase + *pcbSize))) { goto finish; }
            if(vaCurrent < vaMin) { continue; }
            if(vaCurrent > vaMax) { goto finish; }
            // check PTEs
            pte = pObPTEs->pqw[i];
            if(!(pte & 0x01)) { continue; }     // NOT VALID
            if(iPML == 2) {
                if(pte & 0x02) { continue; }
                if(!*pvaBase) { *pvaBase = vaCurrent; }
                *pcbSize += 0x200000;
                continue;
            } else {
                if(!(pte & 0x02)) { continue; }
                VmmWinInit_FindNtosScan64_LargePageWalk(H, pte & 0x0003fffffffff000, vaCurrent, vaMin, vaMax, iPML - 1, pvaBase, pcbSize);
            }
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
* -- H
* -- pSystemProcess
* -- return = virtual address of ntoskrnl.exe base if successful, otherwise 0.
*/
QWORD VmmWinInit_FindNtosScan64(_In_ VMM_HANDLE H, PVMM_PROCESS pSystemProcess)
{
    PBYTE pb;
    QWORD p, o, vaCurrentMin, vaBase, cbSize;
    CHAR szModuleName[MAX_PATH] = { 0 };
    vaCurrentMin = 0xFFFFF80000000000;
    while(TRUE) {
        vaBase = 0;
        cbSize = 0;
        VmmWinInit_FindNtosScan64_LargePageWalk(H, pSystemProcess->paDTB, 0, vaCurrentMin, 0xFFFFF807FFFFFFFF, 4, &vaBase, &cbSize);
        if(!vaBase) {
            VmmWinInit_FindNtosScan64_SmallPageWalk(H, pSystemProcess, vaCurrentMin, 0xFFFFF807FFFFFFFF, &vaBase, &cbSize);
        }
        if(!vaBase) { return 0; }
        vaCurrentMin = vaBase + cbSize;
        if(cbSize >= 0x01800000) { continue; }  // too big
        if(cbSize <= 0x00400000) { continue; }  // too small
        // try locate ntoskrnl.exe base inside suggested area
        if(!(pb = (PBYTE)LocalAlloc(0, (DWORD)cbSize))) { return 0; }
        VmmReadEx(H, pSystemProcess, vaBase, pb, (DWORD)cbSize, NULL, 0);
        // Scan for ntoskrnl.exe - pass #1:
        for(p = 0; p < cbSize; p += 0x1000) {
            // check for (1) MZ header, (2) POOLCODE section, (3) ntoskrnl.exe module name
            if(*(PWORD)(pb + p) != 0x5a4d) { continue; } // MZ header
            for(o = 0; o < 0x1000; o += 8) {
                if(*(PQWORD)(pb + p + o) == 0x45444F434C4F4F50) { // POOLCODE
                    PE_GetModuleNameEx(H, pSystemProcess, vaBase + p, FALSE, pb + p, szModuleName, _countof(szModuleName), NULL);
                    //if(!_stricmp(szModuleName, "ntoskrnl.exe")) {
                        LocalFree(pb);
                        return vaBase + p;
                    //}
                }
            }
        }
        // Scan for ntoskrnl.exe - pass #2: (more relaxed in case if not found in pass #1)
        for(p = 0; p < cbSize; p += 0x1000) {
            // check for (1) MZ header, (2) POOLCODE section:
            if(*(PWORD)(pb + p) != 0x5a4d) { continue; } // MZ header
            for(o = 0; o < 0x1000; o += 8) {
                if(*(PQWORD)(pb + p + o) == 0x45444F434C4F4F50) { // POOLCODE
                    LocalFree(pb);
                    return vaBase + p;
                }
            }
        }
        // Not found:
        LocalFree(pb);
    }
    return 0;
}

/*
* Locate the virtual base address of 'ntoskrnl.exe' given any address inside
* the kernel. Localization will be done by a scan-back method. A maximum of
* 32MB will be scanned back.
* -- H
* -- pSystemProcess
* -- return = virtual address of ntoskrnl.exe base if successful, otherwise 0
*/
QWORD VmmWinInit_FindNtosScanHint64(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pSystemProcess, _In_ QWORD vaHint)
{
    PBYTE pb;
    QWORD vaBase, o, p, vaNtosTry = 0;
    DWORD cbRead;
    CHAR szModuleName[MAX_PATH] = { 0 };
    PIMAGE_DOS_HEADER pDosHeader;
    PIMAGE_NT_HEADERS64 pNtHeader;
    pb = LocalAlloc(0, 0x00200000);
    if(!pb) { goto cleanup; }
    // Scan back in 2MB chunks a time, (ntoskrnl.exe is loaded in 2MB pages except in low memory situations).
    for(vaBase = vaHint & ~0x1fffff; vaBase + 0x02000000 > vaHint; vaBase -= 0x200000) {
        VmmReadEx(H, pSystemProcess, vaBase, pb, 0x200000, &cbRead, 0);
        // Only fail here if all virtual memory in read fails. reason is that kernel is
        // properly mapped in memory (with NX MZ header in separate page) with empty
        // space before next valid kernel pages when running Virtualization Based Security.
        // Memory pages may be paged out of small pages are used in low-mem situations.
        if(!cbRead) { goto cleanup; }
        for(p = 0; p < 0x200000; p += 0x1000) {
            // check for (1) MZ+NT header, (2) POOLCODE section, (3) ntoskrnl.exe module name (if possible to read)
            pDosHeader = (PIMAGE_DOS_HEADER)(pb + p);                       // DOS header
            if(pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) { continue; }    // DOS header signature (MZ)
            if((pDosHeader->e_lfanew < 0) || (pDosHeader->e_lfanew > 0x800)) { continue; }
            pNtHeader = (PIMAGE_NT_HEADERS64)(pb + p + pDosHeader->e_lfanew); // NT header
            if(pNtHeader->Signature != IMAGE_NT_SIGNATURE) { continue; }    // NT header signature
            for(o = 0; o < 0x1000; o += 8) {
                if(*(PQWORD)(pb + p + o) == 0x45444F434C4F4F50) {           // POOLCODE
                    if(!PE_GetModuleNameEx(H, pSystemProcess, vaBase + p, FALSE, pb + p, szModuleName, _countof(szModuleName), NULL)) {
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
* scans the relatively limited memory space 0x80000000-0x847fffff for the base
* of 'ntoskrnl.exe'. NB! this is a very non-optimized way of doing things and
* should be improved upon to increase startup performance - but 72MB is not a
* huge amount of memory and it's only scanned at startup ...
* -- H
* -- pSystemProcess
* -- return = virtual address of ntoskrnl.exe base if successful, otherwise 0.
*/
DWORD VmmWinInit_FindNtosScan32(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pSystemProcess)
{
    DWORD vaBase, ova;
    DWORD o, vaNtosTry = 0;
    PBYTE pb;
    CHAR szModuleName[MAX_PATH] = { 0 };
    PIMAGE_DOS_HEADER pDosHeader;
    PIMAGE_NT_HEADERS pNtHeader;
    if(!(pb = LocalAlloc(LMEM_ZEROINIT, 0x00800000))) { return 0; }
    for(vaBase = 0x80000000; vaBase < 0x88000000; vaBase += 0x1000) {
        ova = vaBase % 0x00800000;
        if(ova == 0) {
            VmmReadEx(H, pSystemProcess, vaBase, pb, 0x00800000, NULL, 0);
        }
        // check for (1) MZ+NT header, (2) POOLCODE section, (3) ntoskrnl.exe module name (if possible to read)
        pDosHeader = (PIMAGE_DOS_HEADER)(pb + ova);                         // DOS header
        if(pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) { continue; }        // DOS header signature (MZ)
        if((pDosHeader->e_lfanew < 0) || (pDosHeader->e_lfanew > 0x800)) { continue; }
        pNtHeader = (PIMAGE_NT_HEADERS)(pb + ova + pDosHeader->e_lfanew);   // NT header
        if(pNtHeader->Signature != IMAGE_NT_SIGNATURE) { continue; }        // NT header signature
        for(o = 0; o < 0x800; o += 8) {
            if(*(PQWORD)(pb + ova + o) == 0x45444F434C4F4F50) {             // POOLCODE
                if(!PE_GetModuleNameEx(H, pSystemProcess, (QWORD)vaBase + ova, FALSE, pb + ova, szModuleName, _countof(szModuleName), NULL)) {
                    vaNtosTry = vaBase;
                    continue;
                }
                if(_stricmp(szModuleName, "ntoskrnl.exe")) {                // not ntoskrnl.exe
                    continue;
                }
                LocalFree(pb);
                return vaBase;
            }
        }
    }
    LocalFree(pb);
    return vaNtosTry;      // on fail try return NtosTry derived from MZ + POOLCODE only.
}

/*
* Scan for the 'ntoskrnl.exe' by using the DTB and memory model information
* from the vmm handle. Return the system process (if found).
* CALLER DECREF: return
* -- H
* -- return = system process - NB! CALLER must DECREF!
*/
PVMM_PROCESS VmmWinInit_FindNtosScan(_In_ VMM_HANDLE H)
{
    QWORD vaKernelBase = 0, cbKernelSize, vaKernelHint;
    PVMM_PROCESS pObSystemProcess = NULL;
    // 1: Pre-initialize System PID (required by VMM)
    pObSystemProcess = VmmProcessCreateEntry(H, TRUE, 4, 0, 0, H->vmm.kernel.paDTB, 0, "System         ", FALSE, NULL, 0);
    if(!pObSystemProcess) { return NULL; }
    VmmProcessCreateFinish(H);
    // 2: Spider DTB to speed things up.
    VmmTlbSpider(H, pObSystemProcess);
    // 3: Find the base of 'ntoskrnl.exe'
    if((VMM_MEMORYMODEL_X64 == H->vmm.tpMemoryModel) || (VMM_MEMORYMODEL_ARM64 == H->vmm.tpMemoryModel)) {
        LcGetOption(H->hLC, LC_OPT_MEMORYINFO_OS_KERNELBASE, &vaKernelBase);
        if(!vaKernelBase) {
            vaKernelHint = H->vmm.kernel.vaEntry;
            if(!vaKernelHint) { LcGetOption(H->hLC, LC_OPT_MEMORYINFO_OS_KERNELHINT, &vaKernelHint); }
            if(!vaKernelHint) { LcGetOption(H->hLC, LC_OPT_MEMORYINFO_OS_PsActiveProcessHead, &vaKernelHint); }
            if(!vaKernelHint) { LcGetOption(H->hLC, LC_OPT_MEMORYINFO_OS_PsLoadedModuleList, &vaKernelHint); }
            if(vaKernelHint) {
                vaKernelBase = VmmWinInit_FindNtosScanHint64(H, pObSystemProcess, vaKernelHint);
            }
        }
        if(!vaKernelBase) {
            vaKernelBase = VmmWinInit_FindNtosScan64(H, pObSystemProcess);
        }
    } else {
        vaKernelBase = VmmWinInit_FindNtosScan32(H, pObSystemProcess);
    }
    if(!vaKernelBase) { goto fail; }
    cbKernelSize = PE_GetSize(H, pObSystemProcess, vaKernelBase);
    H->vmm.kernel.vaBase = vaKernelBase;
    H->vmm.kernel.cbSize = cbKernelSize;
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
BOOL VmmWinInit_DTB_FindValidate_X64(_In_ VMM_HANDLE H, _In_ QWORD pa, _In_reads_(0x1000) PBYTE pbPage)
{
    DWORD cKernelValid = 0, i;
    DWORD cUserZero = 0, cKernelZero = 0;
    QWORD *ptes, paMax;
    BOOL fSelfRef = FALSE;
    ptes = (PQWORD)pbPage;
    paMax = H->dev.paMax;
    // check for user-mode page table with PDPT below max physical address and not NX.
    if((ptes[0] & 1) && ((ptes[0] & 0x0000fffffffff000) > paMax)) { return FALSE; }
    for(i = 0; i < 256; i++) {      // user-mode
        if(ptes[i] == 0) { cUserZero++; }
    }
    for(i = 256; i < 512; i++) {    // kernel mode: minimum number of supervisor entries above 0x800
        if(ptes[i] == 0) { cKernelZero++; }
        // check for user-mode page table with PDPT below max physical address and not NX.
        if(((ptes[i] & 0x8000000000000087) == 0x03) && ((ptes[i] & 0x0000fffffffff000) < paMax)) { cKernelValid++; }
        // check for self-referential entry
        if((ptes[i] & 0x0000fffffffff083) == pa + 0x03) {
            fSelfRef = TRUE;
        }
    }
    return fSelfRef && (cKernelValid >= 6) && (cUserZero > 0x40) && (cKernelZero > 0x40);
}

_Success_(return)
BOOL VmmWinInit_DTB_FindValidate_ARM64(_In_ VMM_HANDLE H, _In_ QWORD pa, _In_reads_(0x1000) PBYTE pbPage)
{
    DWORD cKernelValid = 0, i;
    DWORD cUserZero = 0, cKernelZero = 0;
    QWORD *ptes, paMax;
    BOOL fSelfRef = FALSE;
    ptes = (PQWORD)pbPage;
    paMax = H->dev.paMax;
    // check for user-mode page table entries:
    if((0x0060000000000003 != (ptes[0] & 0x0060000000000073)) || ((ptes[0] & 0x0003fffffffff000) > paMax)) { return FALSE; }
    for(i = 0; i < 256; i++) {      // user-mode
        if(ptes[i] == 0) { cUserZero++; }
    }
    for(i = 256; i < 512; i++) {    // kernel mode: minimum number of entries above 0x800
        if(ptes[i] == 0) { cKernelZero++; }
        // check for kernel-mode page table with PP below max physical address
        if(((ptes[i] & 0x0060000000000071) == 0x0060000000000001) && ((ptes[i] & 0x0003fffffffff000) < paMax)) { cKernelValid++; }
        // check for self-referential entry
        if((ptes[i] & 0x0063fffffffff073) == pa + 0x0060000000000003) {
            fSelfRef = TRUE;
        }
    }
    return fSelfRef && (cKernelValid >= 6) && (cUserZero > 0x40) && (cKernelZero > 0x40);
}

/*
* Find and validate the low stub (loaded <1MB if exists). The low stub almost
* always exists on real hardware. It may be missing on virtual machines though.
* Upon success both the PML4 and 'ntoskrnl.exe' KernelEntry point are located.
* The PML4 is stored as the H->vmm.kernel.paDTB and the KernelEntry is stored
* as H->vmm.kernel.vaHintOpt
*/
BOOL VmmWinInit_DTB_FindValidate_X64_LowStub(_In_ VMM_HANDLE H, _In_ PBYTE pbLowStub1M)
{
    DWORD o = 0;
    while(o < 0x100000) {
        o += 0x1000;
        if(0x00000001000600E9 != (0xffffffffffff00ff & *(PQWORD)(pbLowStub1M + o + 0x000))) { continue; } // START BYTES
        if(0xfffff80000000000 != (0xfffff80000000003 & *(PQWORD)(pbLowStub1M + o + 0x070))) { continue; } // KERNEL ENTRY
        if(0xffffff0000000fff & *(PQWORD)(pbLowStub1M + o + 0x0a0)) { continue; }                         // PML4
        H->vmm.kernel.vaEntry = *(PQWORD)(pbLowStub1M + o + 0x070);
        H->vmm.kernel.paDTB = *(PQWORD)(pbLowStub1M + o + 0x0a0);
        return TRUE;
    }
    return FALSE;
}

/*
* Tries to locate the Directory Table Base and the Memory Model by using various
* detection and scanning functions. Upon success memory model and kernel DTB is
* returned in the vmm handle.
* -- H
* -- return
*/
_Success_(return)
BOOL VmmWinInit_DTB_FindValidate(_In_ VMM_HANDLE H)
{
    DWORD pa;
    QWORD paDTB = 0, pa16M;
    PBYTE pb16M;
    if(!(pb16M = LocalAlloc(LMEM_ZEROINIT, 0x01000000))) { return FALSE; }
    // 1: try locate DTB via X64 low stub in lower 1MB -
    //    avoiding normally reserved memory at a0000-fffff.
    LcRead(H->hLC, 0x1000, 0x9f000, pb16M + 0x1000);
    if(((H->cfg.tpMemoryModel == VMM_MEMORYMODEL_NA) || (H->cfg.tpMemoryModel == VMM_MEMORYMODEL_X64)) && VmmWinInit_DTB_FindValidate_X64_LowStub(H, pb16M)) {
        VmmInitializeMemoryModel(H, VMM_MEMORYMODEL_X64);
        paDTB = H->vmm.kernel.paDTB;
        goto finish;
    }
    // 2: try locate DTB by scanning in lower 16MB
    // X64
    if(!paDTB && ((H->cfg.tpMemoryModel == VMM_MEMORYMODEL_NA) || (H->cfg.tpMemoryModel == VMM_MEMORYMODEL_X64))) {
        for(pa = 0; pa < 0x01000000; pa += 0x1000) {
            if(pa == 0x00100000) {
                LcRead(H->hLC, 0x00100000, 0x00f00000, pb16M + 0x00100000);
            }
            if(VmmWinInit_DTB_FindValidate_X64(H, pa, pb16M + pa)) {
                VmmInitializeMemoryModel(H, VMM_MEMORYMODEL_X64);
                paDTB = pa;
                goto finish;
            }
        }
    }
    // X86-PAE
    if(!paDTB && ((H->cfg.tpMemoryModel == VMM_MEMORYMODEL_NA) || (H->cfg.tpMemoryModel == VMM_MEMORYMODEL_X86PAE))) {
        for(pa = 0; pa < 0x01000000; pa += 0x1000) {
            if(VmmWinInit_DTB_FindValidate_X86PAE(pa, pb16M + pa)) {
                VmmInitializeMemoryModel(H, VMM_MEMORYMODEL_X86PAE);
                paDTB = pa;
                goto finish;
            }
        }
    }
    // X86
    if(!paDTB && ((H->cfg.tpMemoryModel == VMM_MEMORYMODEL_NA) || (H->cfg.tpMemoryModel == VMM_MEMORYMODEL_X86))) {
        for(pa = 0; pa < 0x01000000; pa += 0x1000) {
            if(VmmWinInit_DTB_FindValidate_X86(pa, pb16M + pa)) {
                VmmInitializeMemoryModel(H, VMM_MEMORYMODEL_X86);
                paDTB = pa;
                goto finish;
            }
        }
    }
    // 3: if ARM64, try locate DTB by scanning up to top of image (slow)
    if(!paDTB && (H->cfg.tpMemoryModel == VMM_MEMORYMODEL_ARM64)) {
        VmmLog(H, MID_CORE, LOGLEVEL_WARNING, "Scanning ARM64 image for DirectoryTableBase (DTB)...");
        VmmLog(H, MID_CORE, LOGLEVEL_WARNING, "  This may take time, use .DMP memory dumps instead of .RAW for ARM64 if possible.");
        for(pa16M = 0; pa16M < H->dev.paMax; pa16M += 0x01000000) {
            if(LcRead(H->hLC, pa16M, 0x01000000, pb16M)) {
                for(pa = 0; pa < 0x01000000; pa += 0x1000) {
                    if(VmmWinInit_DTB_FindValidate_ARM64(H, pa16M + pa, pb16M + pa)) {
                        VmmLog(H, MID_CORE, LOGLEVEL_WARNING, "  DTB located. For faster start-up specify: -dtb 0x%llx", pa16M + pa);
                        VmmInitializeMemoryModel(H, VMM_MEMORYMODEL_ARM64);
                        paDTB = pa16M + pa;
                        goto finish;
                    }
                }
            }
        }
        VmmLog(H, MID_CORE, LOGLEVEL_WARNING, "  Failed locating DTB.");
    }
finish:
    LocalFree(pb16M);
    if(!paDTB) { return FALSE; }
    H->vmm.kernel.paDTB = paDTB;
    return TRUE;
}

/*
* Validate a DTB supplied by the user. The memory model will be detected and
* the result will be stored in the vmm handle upon success.
* -- H
* -- paDTB
* -- return
*/
BOOL VmmWinInit_DTB_Validate(_In_ VMM_HANDLE H, _In_ QWORD paDTB)
{
    BYTE pb[0x1000];
    paDTB = paDTB & ~0xfff;
    if(!LcRead(H->hLC, paDTB, 0x1000, pb)) { return FALSE; }
    if(((H->cfg.tpMemoryModel == VMM_MEMORYMODEL_NA) || (H->cfg.tpMemoryModel == VMM_MEMORYMODEL_X64)) && VmmWinInit_DTB_FindValidate_X64(H, paDTB, pb)) {
        VmmInitializeMemoryModel(H, VMM_MEMORYMODEL_X64);
        H->vmm.kernel.paDTB = paDTB;
        return TRUE;
    }
    if(((H->cfg.tpMemoryModel == VMM_MEMORYMODEL_NA) || (H->cfg.tpMemoryModel == VMM_MEMORYMODEL_ARM64)) && VmmWinInit_DTB_FindValidate_ARM64(H, paDTB, pb)) {
        VmmInitializeMemoryModel(H, VMM_MEMORYMODEL_ARM64);
        H->vmm.kernel.paDTB = paDTB;
        return TRUE;
    }
    if(((H->cfg.tpMemoryModel == VMM_MEMORYMODEL_NA) || (H->cfg.tpMemoryModel == VMM_MEMORYMODEL_X86PAE)) && VmmWinInit_DTB_FindValidate_X86PAE(paDTB, pb)) {
        VmmInitializeMemoryModel(H, VMM_MEMORYMODEL_X86PAE);
        H->vmm.kernel.paDTB = paDTB;
        return TRUE;
    }
    if(((H->cfg.tpMemoryModel == VMM_MEMORYMODEL_NA) || (H->cfg.tpMemoryModel == VMM_MEMORYMODEL_X86)) && VmmWinInit_DTB_FindValidate_X86(paDTB, pb)) {
        VmmInitializeMemoryModel(H, VMM_MEMORYMODEL_X86);
        H->vmm.kernel.paDTB = paDTB;
        return TRUE;
    }
    return FALSE;
}

BOOL VmmWinInit_FindPsLoadedModuleListKDBG(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pSystemProcess)
{
    PBYTE pbData = NULL, pbKDBG;
    IMAGE_SECTION_HEADER SectionHeader;
    DWORD o, va32 = 0;
    QWORD va, va64 = 0;
    // 1: Try locate 'PsLoadedModuleList' by querying the microsoft crash dump
    //    file used. This will fail if another memory acqusition device is used.
    if(LcGetOption(H->hLC, LC_OPT_MEMORYINFO_OS_PsLoadedModuleList, &va) && va) {
        LcGetOption(H->hLC, LC_OPT_MEMORYINFO_OS_PFN, &H->vmm.kernel.opt.vaPfnDatabase);
        LcGetOption(H->hLC, LC_OPT_MEMORYINFO_OS_KdDebuggerDataBlock, &H->vmm.kernel.opt.KDBG.va);
        if(H->vmm.f32 && VmmRead(H, pSystemProcess, va, (PBYTE)&va32, 4) && (va32 > 0x80000000)) {
            H->vmm.kernel.opt.vaPsLoadedModuleListExp = va;
            H->vmm.kernel.vaPsLoadedModuleListPtr = va32;
            return TRUE;
        }
        if(!H->vmm.f32 && VmmRead(H, pSystemProcess, va, (PBYTE)&va64, 8) && (va64 > 0xffff800000000000)) {
            H->vmm.kernel.opt.vaPsLoadedModuleListExp = va;
            H->vmm.kernel.vaPsLoadedModuleListPtr = va64;
            return TRUE;
        }
    }
    //    (optionally) Locate the PFN database:
    //    The PFN database is static on before Windows 10 x64 1607/14393.
    if(!H->vmm.f32 && (H->vmm.kernel.dwVersionBuild < 14393)) {
        H->vmm.kernel.opt.vaPfnDatabase = 0xfffffa8000000000;
    }
    // 2: Try locate 'PsLoadedModuleList' by exported kernel symbol. If this is
    //    possible _and_ the system is 64-bit it's most probably Windows 10 and
    //    KDBG will be encrypted so no need to continue looking for it.
    H->vmm.kernel.vaPsLoadedModuleListPtr = PE_GetProcAddress(H, pSystemProcess, H->vmm.kernel.vaBase, "PsLoadedModuleList");
    if(H->vmm.kernel.vaPsLoadedModuleListPtr && !H->vmm.f32) {
        H->vmm.kernel.opt.vaPsLoadedModuleListExp = H->vmm.kernel.vaPsLoadedModuleListPtr;
        return TRUE;
    }
    // 3: Try locate 'KDBG' by looking in 'ntoskrnl.exe' '.text' section. This
    //    is the normal way of finding it on 64-bit Windows below Windows 10.
    //    This also works on 32-bit Windows versions - so use this method for
    //    simplicity rather than using a separate 32-bit method.
    if(!H->vmm.kernel.opt.KDBG.va && (H->vmm.f32 || H->vmm.kernel.dwVersionMajor < 10)) {
        if(!PE_SectionGetFromName(H, pSystemProcess, H->vmm.kernel.vaBase, ".data", &SectionHeader)) { goto fail; }
        if((SectionHeader.Misc.VirtualSize > 0x00100000) || (SectionHeader.VirtualAddress > 0x01000000)) { goto fail; }
        if(!(pbData = LocalAlloc(LMEM_ZEROINIT, SectionHeader.Misc.VirtualSize))) { goto fail; }
        VmmReadEx(H, pSystemProcess, H->vmm.kernel.vaBase + SectionHeader.VirtualAddress, pbData, SectionHeader.Misc.VirtualSize, NULL, 0);
        for(o = 16; o <= SectionHeader.Misc.VirtualSize - 0x290; o += 4) {
            if(*(PDWORD)(pbData + o) == 0x4742444b) { // KDBG tag
                pbKDBG = pbData + o - 16;
                if(H->vmm.kernel.vaBase != *(PQWORD)(pbKDBG + 0x18)) { continue; }
                // fetch PsLoadedModuleList
                va = *(PQWORD)(pbKDBG + 0x48);
                if((va < H->vmm.kernel.vaBase) || (va > H->vmm.kernel.vaBase + H->vmm.kernel.cbSize)) { goto fail; }
                if(!VmmRead(H, pSystemProcess, va, (PBYTE)&H->vmm.kernel.vaPsLoadedModuleListPtr, H->vmm.f32 ? 4 : 8)) { goto fail; }
                H->vmm.kernel.opt.vaPsLoadedModuleListExp = va;
                // finish!
                H->vmm.kernel.opt.KDBG.va = H->vmm.kernel.vaBase + SectionHeader.VirtualAddress + o - 16;
                LocalFree(pbData);
                return TRUE;
            }
        }
    }
    // 4: Try locate by querying the PDB for symbols. At this point the PDB
    //    subsystem may not be fully initialized yet so wait for it to init.
    PDB_Initialize_WaitComplete(H);
    if(PDB_GetSymbolPTR(H, PDB_HANDLE_KERNEL, "PsLoadedModuleList", pSystemProcess, &H->vmm.kernel.vaPsLoadedModuleListPtr)) {
        PDB_GetSymbolAddress(H, PDB_HANDLE_KERNEL, "PsLoadedModuleList", &H->vmm.kernel.opt.vaPsLoadedModuleListExp);
        return TRUE;
    }
fail:
    LocalFree(pbData);
    return (0 != H->vmm.kernel.vaPsLoadedModuleListPtr);
}

/*
* Retrieve the operating system versioning information by looking at the PEB.
* -- H
* -- pProcess
* -- return
*/
_Success_(return)
BOOL VmmWinInit_VersionNumberFromProcess(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess)
{
    BYTE pbPEB[0x130];
    if(VmmRead(H, pProcess, pProcess->win.vaPEB, pbPEB, 0x130)) {
        if(H->vmm.f32) {
            H->vmm.kernel.dwVersionMajor = *(PDWORD)(pbPEB + 0x0a4);
            H->vmm.kernel.dwVersionMinor = *(PDWORD)(pbPEB + 0x0a8);
            H->vmm.kernel.dwVersionBuild = *(PWORD)(pbPEB + 0x0ac);
        } else {
            H->vmm.kernel.dwVersionMajor = *(PDWORD)(pbPEB + 0x118);
            H->vmm.kernel.dwVersionMinor = *(PDWORD)(pbPEB + 0x11c);
            H->vmm.kernel.dwVersionBuild = *(PWORD)(pbPEB + 0x120);
        }
        if((H->vmm.kernel.dwVersionMajor < 5) || (H->vmm.kernel.dwVersionMajor > 11)) { return FALSE; }
        if((H->vmm.kernel.dwVersionBuild < 2600) || (H->vmm.kernel.dwVersionBuild > 30000)) { return FALSE; }
        return TRUE;
    }
    return FALSE;
}

/*
* Retrieve the operating system versioning information by looking at values in
* the PEB of the process 'smss.exe'.
* -- H
* -- pSystemProcess
* -- pProcessSMSS
* -- return
*/
_Success_(return)
BOOL VmmWinInit_VersionNumber(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pSystemProcess, _In_ PVMM_PROCESS pProcessSMSS)
{
    QWORD vaBuildNumber;
    PVMM_PROCESS pObProcess = NULL;
    // 1: From PEB SMSS:
    if(VmmWinInit_VersionNumberFromProcess(H, pProcessSMSS)) { return TRUE; }
    // 2: From Kernel:
    vaBuildNumber = PE_GetProcAddress(H, pSystemProcess, H->vmm.kernel.vaBase, "NtBuildNumber");
    if(VMM_KADDR_DUAL(H->vmm.f32, vaBuildNumber) && VmmRead(H, pSystemProcess, vaBuildNumber, (PBYTE)&H->vmm.kernel.dwVersionBuild, sizeof(DWORD))) {
        H->vmm.kernel.dwVersionBuild = (WORD)H->vmm.kernel.dwVersionBuild;
        if((H->vmm.kernel.dwVersionBuild < 2600) || (H->vmm.kernel.dwVersionBuild > 30000)) { return FALSE; }
        if(H->vmm.kernel.dwVersionBuild) {
            if(H->vmm.kernel.dwVersionBuild >= 10240) {         // 10 (incl. win11)
                H->vmm.kernel.dwVersionMajor = 10;
                H->vmm.kernel.dwVersionMinor = 0;
            } else if(H->vmm.kernel.dwVersionBuild >= 9100) {   // 8
                H->vmm.kernel.dwVersionMajor = 6;
                H->vmm.kernel.dwVersionMinor = 3;
            } else if(H->vmm.kernel.dwVersionBuild >= 7600) {   // 7
                H->vmm.kernel.dwVersionMajor = 6;
                H->vmm.kernel.dwVersionMinor = 1;
            } else if(H->vmm.kernel.dwVersionBuild >= 6000) {   // VISTA
                H->vmm.kernel.dwVersionMajor = 6;
                H->vmm.kernel.dwVersionMinor = 0;
            } else {                                            // XP
                H->vmm.kernel.dwVersionMajor = 5;
                H->vmm.kernel.dwVersionMinor = 1;
            }
        }
        return TRUE;
    }
    // 3: From PEB crss.exe / lsass.exe / winlogon.exe:
    while((pObProcess = VmmProcessGetNext(H, pObProcess, 0))) {
        if(!strcmp("crss.exe", pObProcess->szName) || !strcmp("lsass.exe", pObProcess->szName) || !strcmp("winlogon.exe", pObProcess->szName)) {
            if(VmmWinInit_VersionNumberFromProcess(H, pObProcess)) {
                Ob_DECREF(pObProcess);
                return TRUE;
            }
        }
    }
    return FALSE;
}

/*
* Helper fucntion to VmmWinInit_TryInitialize. Tries to locate the EPROCESS of
* the SYSTEM process and return it.
* -- H
* -- pSystemProcess
* -- return
*/
QWORD VmmWinInit_FindSystemEPROCESS(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pSystemProcess)
{
    BOOL f32 = H->vmm.f32;
    IMAGE_SECTION_HEADER SectionHeader;
    BYTE pbALMOSTRO[0x80], pbSYSTEM[0x300];
    QWORD i, vaPsInitialSystemProcess, vaSystemEPROCESS;
    // 1: try locate System EPROCESS by PsInitialSystemProcess exported symbol (works on all win versions)
    vaPsInitialSystemProcess = PE_GetProcAddress(H, pSystemProcess, H->vmm.kernel.vaBase, "PsInitialSystemProcess");
    if(VmmRead(H, pSystemProcess, vaPsInitialSystemProcess, (PBYTE)&vaSystemEPROCESS, 8)) {
        if((VMM_MEMORYMODEL_X86 == H->vmm.tpMemoryModel) || (VMM_MEMORYMODEL_X86PAE == H->vmm.tpMemoryModel)) {
            vaSystemEPROCESS &= 0xffffffff;
        }
        pSystemProcess->win.EPROCESS.va = vaSystemEPROCESS;
        VmmLog(H, MID_CORE, LOGLEVEL_DEBUG, "PsInitialSystemProcess located at %016llx", vaPsInitialSystemProcess);
        goto success;
    }
    // 2: fail - paging? try to retrive using PDB subsystem - this may take some time to initialize
    //           and download symbols - but it's better than failing totally ...
    InfoDB_Initialize(H);
    PDB_Initialize(H, NULL, FALSE);
    PDB_GetSymbolPTR(H, PDB_HANDLE_KERNEL, "PsInitialSystemProcess", pSystemProcess, &vaSystemEPROCESS);
    if(vaSystemEPROCESS) { goto success; }
    // 3: fail - paging? (or not windows) - this should ideally not happen - but it happens rarely...
    //    try scan beginning of ALMOSTRO section for pointers and validate (working on pre-win10 only)
    if(!PE_SectionGetFromName(H, pSystemProcess, H->vmm.kernel.vaBase, "ALMOSTRO", &SectionHeader)) { return 0; }
    if(!VmmRead(H, pSystemProcess, H->vmm.kernel.vaBase + SectionHeader.VirtualAddress, pbALMOSTRO, sizeof(pbALMOSTRO))) { return 0; }
    for(i = 0; i < sizeof(pbALMOSTRO); i += f32 ? 4 : 8) {
        vaSystemEPROCESS = f32 ? *(PDWORD)(pbALMOSTRO + i) : *(PQWORD)(pbALMOSTRO + i);
        if(f32 ? VMM_KADDR32_8(vaSystemEPROCESS) : VMM_KADDR64_16(vaSystemEPROCESS)) {
            if(VmmRead(H, pSystemProcess, vaSystemEPROCESS, pbSYSTEM, sizeof(pbSYSTEM))) {
                if(f32 && ((*(PDWORD)(pbSYSTEM + 0x18) & ~0xf) == H->vmm.kernel.paDTB)) { goto success; }      // 32-bit EPROCESS DTB at fixed offset
                if(!f32 && ((*(PQWORD)(pbSYSTEM + 0x28) & ~0xf) == H->vmm.kernel.paDTB)) { goto success; }     // 64-bit EPROCESS DTB at fixed offset
            }
        }
    }
    return 0;
success:
    VmmLog(H, MID_CORE, LOGLEVEL_DEBUG, "EPROCESS located at %016llx", vaSystemEPROCESS);
    return vaSystemEPROCESS;
}

typedef struct tdVMMWININITOB_PARTIAL_TERMINATED_PROCESS {
    DWORD dwPID;
    DWORD dwPPID;
    QWORD ftCreate;
    QWORD ftExit;
    CHAR szShortName[16];
    CHAR szLongName[MAX_PATH];
} VMMWININITOB_PARTIAL_TERMINATED_PROCESS, *PVMMWININITOB_PARTIAL_TERMINATED_PROCESS;

/*
* Parse a single line of SgrmBroker.exe json log data for terminated processes
* and add it to the result map.
* -- H
* -- szJson
* -- pmResult
*/
VOID VmmWinInit_FindAddTerminatedProcesses_ParseSgrmJsonLine(_In_ VMM_HANDLE H, _In_ LPSTR szJson, _In_ POB_MAP pmResult)
{
    QWORD ftCreate = 0, ftExit = 0;
    DWORD dwPID = 0, dwPPID = 0;
    LPSTR sz, uszImageName = NULL;
    VMMWININITOB_PARTIAL_TERMINATED_PROCESS sTProc = { 0 };
    PVMMWININITOB_PARTIAL_TERMINATED_PROCESS pTProc = NULL;
    if((sz = strstr(szJson, "\"ProcessID\":"))) {
        dwPID = (DWORD)Util_GetNumericA(sz + 12);
    }
    if((sz = strstr(szJson, "\"ParentProcessID\":"))) {
        dwPPID = (DWORD)Util_GetNumericA(sz + 18);
    }
    if((sz = strstr(szJson, "\"CreateTime\":\""))) {
        ftCreate = Util_TimeIso8601ToFileTime(sz + 14);
        if((ftCreate < 0x0100000000000000) || (ftCreate > 0x0200000000000000)) { ftCreate = 0; }
    }
    if((sz = strstr(szJson, "\"ExitTime\":\""))) {
        ftExit = Util_TimeIso8601ToFileTime(sz + 12);
        if((ftExit < 0x0100000000000000) || (ftExit > 0x0200000000000000)) { ftCreate = 0; }
    }
    if((sz = strstr(szJson, "\"ImageName\":\""))) {
        sz += 13;
        uszImageName = sz;
        while(sz[0] && (sz[0] != '"')) { sz++; }
        sz[0] = 0;
    }
    if(!dwPID || (dwPID & 3) || (dwPPID & 3) || !ftCreate || !uszImageName) { return; }
    pTProc = ObMap_GetByKey(pmResult, dwPID);
    if(!pTProc) { pTProc = &sTProc; }
    pTProc->dwPID = dwPID;
    if(dwPPID) { pTProc->dwPPID = dwPPID; }
    if(ftCreate) { pTProc->ftCreate = ftCreate; }
    if(ftExit) { pTProc->ftExit = ftExit; }
    if(uszImageName) {
        if(strlen(uszImageName) < 15) {
            strncpy_s(pTProc->szShortName, sizeof(pTProc->szShortName), uszImageName, _TRUNCATE);
        } else {
            if(!CharUtil_UtoU(uszImageName, -1, pTProc->szLongName, sizeof(pTProc->szLongName), NULL, NULL, CHARUTIL_FLAG_STR_BUFONLY | CHARUTIL_FLAG_TRUNCATE)) { return; }
        }
    }
    if(pTProc == &sTProc) {
        ObMap_PushCopy(pmResult, dwPID, pTProc, sizeof(VMMWININITOB_PARTIAL_TERMINATED_PROCESS));
    }
}

/*
* Find and add terminated processes in alternative ways. This can be a somewhat
* heavy operation and is only done in forensic mode on non-volatile memory.
* Currently supported methods are:
*   - SgrmBroker.exe (heap scanning for json log strings).
* -- H
*/
VOID VmmWinInit_FindAddTerminatedProcesses(_In_ VMM_HANDLE H)
{
    DWORD i, cb, oS, oE, cbE, dwPID;
    BOOL fParentIsServices, fNewTProc = FALSE;
    PVMM_PROCESS pObProcess, pObProcessSgrm = NULL;
    PVMMOB_MAP_HEAP pObHeapMap = NULL;
    PVMM_MAP_HEAP_SEGMENTENTRY pSeg;
    PBYTE pb = NULL;
    POB_MAP pmObTProcMap = NULL;
    PVMMWININITOB_PARTIAL_TERMINATED_PROCESS pTProc = NULL;
    if(!H->cfg.tpForensicMode) { return; }
    if((H->vmm.kernel.dwVersionBuild < 19041) || (H->vmm.kernel.dwVersionBuild > 22631)) { return; }
    // locate SgrmBroker.exe process:
    while((pObProcessSgrm = VmmProcessGetNext(H, pObProcessSgrm, 0))) {
        if(CharUtil_StrEquals(pObProcessSgrm->szName, "SgrmBroker.exe", FALSE)) {
            pObProcess = VmmProcessGet(H, pObProcessSgrm->dwPPID);
            fParentIsServices = pObProcess && CharUtil_StrEquals(pObProcess->szName, "services.exe", FALSE);
            Ob_DECREF_NULL(&pObProcess);
            if(fParentIsServices) {
                break;
            }
        }
    }
    if(!pObProcessSgrm) { goto fail; }
    // retrieve heap map:
    if(!VmmMap_GetHeap(H, pObProcessSgrm, &pObHeapMap) || !pObHeapMap->cSegments) { goto fail; }
    if(!(pmObTProcMap = ObMap_New(H, OB_MAP_FLAGS_OBJECT_LOCALFREE))) { goto fail; }
    if(!(pb = LocalAlloc(LMEM_ZEROINIT, 0x01000000))) { goto fail; }
    // scan heap segments for json strings of terminated process candidates:
    for(i = 0; i < pObHeapMap->cSegments; i++) {
        pSeg = &pObHeapMap->pSegments[i];
        if(pSeg->cb > 0x01000000) { continue; }
        if(pSeg->tp != VMM_HEAP_SEGMENT_TP_NT_SEGMENT) { continue; }
        VmmReadEx(H, pObProcessSgrm, pSeg->va, pb, pSeg->cb, NULL, VMM_FLAG_ZEROPAD_ON_FAIL);
        cb = pSeg->cb;
        // scan heap segment buffer:
        for(oS = 0x10; oS < cb - 0x40; oS++) {
            if(pb[oS] != '{') { continue; }
            if(0x7365636f7250227b != *(PQWORD)(pb + oS)) { continue; }  // {"Proces
            if(!CharUtil_StrStartsWith(pb + oS, "{\"ProcessID\":", FALSE)) { continue; }
            cbE = min(cb, oS + 0x1000);
            for(oE = oS; oE < cbE; oE++) {
                if(pb[oE] < 0x20) { oS = oE; break; }
                if((pb[oE] == '}') && (pb[oE - 1] == '"')) {
                    pb[oE + 1] = 0;
                    dwPID = (DWORD)Util_GetNumericA(pb + oS + 13);
                    if(dwPID && !(pObProcess = VmmProcessGet(H, dwPID))) {
                        // candidate found:
                        VmmWinInit_FindAddTerminatedProcesses_ParseSgrmJsonLine(H, pb + oS, pmObTProcMap);
                    }
                    Ob_DECREF_NULL(&pObProcess);
                    oS = oE; break;
                }
            }
        }
    }
    // add terminated processes to the process map:
    EnterCriticalSection(&H->vmm.LockMaster);
    while((pTProc = ObMap_Pop(pmObTProcMap))) {
        if(VmmProcessCreateTerminatedFakeEntry(H, pTProc->dwPID, pTProc->dwPPID, pTProc->ftCreate, pTProc->ftExit, pTProc->szShortName, pTProc->szLongName)) {
            VmmLog(H, MID_CORE, LOGLEVEL_6_TRACE, "Terminated process added: %5i - %s", pTProc->dwPID, pTProc->szShortName);
            fNewTProc = TRUE;
        }
        LocalFree(pTProc);
    }
    if(fNewTProc) {
        VmmProcessCreateFinish(H);
    }
    LeaveCriticalSection(&H->vmm.LockMaster);
fail:
    Ob_DECREF(pObHeapMap);
    Ob_DECREF(pObProcessSgrm);
    Ob_DECREF(pmObTProcMap);
    LocalFree(pb);
}

/*
* Async initialization of remaining actions in VmmWinInit_TryInitialize.
* -- H
* -- qwNotUsed
* -- return
*/
VOID VmmWinInit_TryInitialize_Async(_In_ VMM_HANDLE H, _In_ QWORD qwNotUsed)
{
    POB_SET psObNoLinkEPROCESS = NULL;
    PVMM_PROCESS pObSystemProcess = NULL;
    PVMMOB_MAP_VM pObVmMap = NULL;
    PDB_Initialize_WaitComplete(H);
    MmWin_PagingInitialize(H, TRUE);   // initialize full paging (memcompression)
    VmmWinInit_TryInitializeThreading(H);
    VmmWinInit_InitializeOffsetStatic_Heap(H);
    VmmWinInit_TryInitializeKernelOptionalValues(H);
    // locate no-link processes and retired processes (no longer in eprocess list) [only in non-volatile memory due to performance].
    if(!H->dev.fVolatile) {
        if((psObNoLinkEPROCESS = VmmWinProcess_Enumerate_FindNoLinkProcesses(H))) {
            if((pObSystemProcess = VmmProcessGet(H, 4))) {
                VmmWinProcess_Enumerate(H, pObSystemProcess, FALSE, psObNoLinkEPROCESS);
            }
            Ob_DECREF(psObNoLinkEPROCESS);
            Ob_DECREF(pObSystemProcess);
        }
        if(H->cfg.tpForensicMode) {
            VmmWinInit_FindAddTerminatedProcesses(H);
        }
    }
    // vm parse (if enabled)
    VmmMap_GetVM(H, &pObVmMap);
    Ob_DECREF(pObVmMap);
}

/*
* Initialize the "system unique tag" - i.e. an unique system-dependent id.
* -- H
*/
VOID VmmWinInit_TryInitialize_SystemUniqueTag(_In_ VMM_HANDLE H)
{
    BYTE pbSHA256[32] = { 0 };
    PVMM_PROCESS pObSystemProcess = NULL;
    if((pObSystemProcess = VmmProcessGet(H, 4))) {
        Util_HashSHA256(pObSystemProcess->win.EPROCESS.pb, pObSystemProcess->win.EPROCESS.cb, pbSHA256);
        H->vmm.dwSystemUniqueId = *(PDWORD)pbSHA256;
        snprintf(H->vmm.szSystemUniqueTag, _countof(H->vmm.szSystemUniqueTag), "%i_%x", H->vmm.kernel.dwVersionBuild, H->vmm.dwSystemUniqueId);
    }
    Ob_DECREF(pObSystemProcess);
}

/*
* Initialize memory map auto - i.e. retrieve it from the kernel (or fallback registry) and load it into LeechCore.
* -- H
* -- return
*/
_Success_(return)
BOOL VmmWinInit_TryInitialize_MemMapAuto(_In_ VMM_HANDLE H)
{
    BOOL fResult = FALSE;
    DWORD i, cbMemMap = 0;
    LPSTR szMemMap = NULL;
    PVMMOB_MAP_PHYSMEM pObMap = NULL;
    if(!VmmMap_GetPhysMem(H, &pObMap) || !pObMap->cMap) { goto fail; }
    if(!(szMemMap = LocalAlloc(LMEM_ZEROINIT, 0x00100000))) { goto fail; }
    for(i = 0; i < pObMap->cMap; i++) {
        cbMemMap += snprintf(szMemMap + cbMemMap, 0x00100000 - cbMemMap - 1, "%016llx %016llx\n", pObMap->pMap[i].pa, pObMap->pMap[i].pa + pObMap->pMap[i].cb - 1);
    }
    fResult =
        LcCommand(H->hLC, LC_CMD_MEMMAP_SET, cbMemMap, (PBYTE)szMemMap, NULL, NULL) &&
        LcGetOption(H->hLC, LC_OPT_CORE_ADDR_MAX, &H->dev.paMax);
fail:
    ObContainer_SetOb(H->vmm.pObCMapPhysMem, NULL);
    LocalFree(szMemMap);
    Ob_DECREF(pObMap);
    return fResult;
}

/*
* Try initialize the VMM from scratch with new WINDOWS support.
* -- H
* -- paDTBOpt
* -- return
*/
BOOL VmmWinInit_TryInitialize(_In_ VMM_HANDLE H, _In_opt_ QWORD paDTBOpt)
{
    PVMM_PROCESS pObSystemProcess = NULL, pObProcess = NULL;
    // Fetch Directory Base (DTB (PML4)) and initialize Memory Model.
    QWORD qwMemoryModelOpt;
    if((H->cfg.tpMemoryModel == VMM_MEMORYMODEL_NA) && LcGetOption(H->hLC, LC_OPT_MEMORYINFO_ARCH, &qwMemoryModelOpt)) {
        H->cfg.tpMemoryModel = (VMM_MEMORYMODEL_TP)qwMemoryModelOpt;
    }
    if(paDTBOpt && !VmmWinInit_DTB_Validate(H, paDTBOpt)) {
        VmmLog(H, MID_CORE, LOGLEVEL_CRITICAL, "Initialization Failed. Unable to verify user-supplied (0x%016llx) DTB. #1", paDTBOpt);
        goto fail;
    }
    if(!H->vmm.kernel.paDTB && LcGetOption(H->hLC, LC_OPT_MEMORYINFO_OS_DTB, &paDTBOpt)) {
        if(!VmmWinInit_DTB_Validate(H, paDTBOpt)) {
            VmmLog(H, MID_CORE, LOGLEVEL_WARNING, "Unable to verify crash-dump supplied DTB. (0x%016llx) #1", paDTBOpt);
        }
    }
    if(!H->vmm.kernel.paDTB && !VmmWinInit_DTB_FindValidate(H)) {
        VmmLog(H, MID_CORE, LOGLEVEL_CRITICAL, "Initialization Failed. Unable to locate valid DTB. #2");
        goto fail;
    }
    VmmLog(H, MID_CORE, LOGLEVEL_DEBUG, "DTB  located at: %016llx. MemoryModel: %s", H->vmm.kernel.paDTB, VMM_MEMORYMODEL_TOSTRING[H->vmm.tpMemoryModel]);
    // Fetch 'ntoskrnl.exe' base address
    if(H->fAbort) { goto fail; }
    if(!(pObSystemProcess = VmmWinInit_FindNtosScan(H))) {
        VmmLog(H, MID_CORE, LOGLEVEL_CRITICAL, "Initialization Failed. Unable to locate ntoskrnl.exe. #3");
        goto fail;
    }
    VmmLog(H, MID_CORE, LOGLEVEL_DEBUG, "NTOS located at: %016llx", H->vmm.kernel.vaBase);
    // -memmap auto: Try to initialize the memory map early to minimize the risk of
    // an out-of-range memory read. This may slow down the initialization. 1st try.
    if(H->cfg.fMemMapAuto) {
        InfoDB_Initialize(H);
        PDB_Initialize(H, NULL, FALSE);
        H->cfg.fMemMapAuto = !VmmWinInit_TryInitialize_MemMapAuto(H);
    }
    // Initialize Paging (Limited Mode)
    MmWin_PagingInitialize(H, FALSE);
    // Locate System EPROCESS
    if(H->fAbort) { goto fail; }
    pObSystemProcess->win.EPROCESS.va = VmmWinInit_FindSystemEPROCESS(H, pObSystemProcess);
    if(!pObSystemProcess->win.EPROCESS.va) {
        VmmLog(H, MID_CORE, LOGLEVEL_CRITICAL, "Initialization Failed. Unable to locate EPROCESS. #4");
        goto fail;
    }
    // Enumerate processes
    if(H->fAbort) { goto fail; }
    if(!VmmWinProcess_Enumerate(H, pObSystemProcess, TRUE, NULL)) {
        VmmLog(H, MID_CORE, LOGLEVEL_CRITICAL, "Initialization Failed. Unable to walk EPROCESS. #5");
        goto fail;
    }
    if((H->vmm.tpMemoryModel == VMM_MEMORYMODEL_X64) || (H->vmm.tpMemoryModel == VMM_MEMORYMODEL_ARM64)) {
        H->vmm.tpSystem = VMM_SYSTEM_WINDOWS_64;
    } else {
        H->vmm.tpSystem = VMM_SYSTEM_WINDOWS_32;
    }
    // Switch to proper system process and update kernel dtb:
    Ob_DECREF_NULL(&pObSystemProcess);
    if(!(pObSystemProcess = VmmProcessGet(H, 4))) {
        VmmLog(H, MID_CORE, LOGLEVEL_CRITICAL, "Initialization Failed. Unable to load system process. #6");
        goto fail;
    }
    H->vmm.kernel.paDTB = pObSystemProcess->paDTB;
    // Retrieve operating system version information from 'smss.exe' process
    // Optionally retrieve PID of Registry process
    while((pObProcess = VmmProcessGetNext(H, pObProcess, 0))) {
        if(pObProcess->dwPPID == 4) {
            if(!memcmp("Registry", pObProcess->szName, 9)) {
                H->vmm.kernel.dwPidRegistry = pObProcess->dwPID;
            }
            if(!_stricmp("smss.exe", pObProcess->szName)) {
                VmmWinInit_VersionNumber(H, pObSystemProcess, pObProcess);
            }
        }
    }
    if((H->vmm.kernel.dwVersionBuild < 2600) || (H->vmm.kernel.dwVersionBuild > 30000)) {
        VmmLog(H, MID_CORE, LOGLEVEL_WARNING, "Initialization Partially Failed. Unsupported build number: %i", H->vmm.kernel.dwVersionBuild);
    }
    // Initialization functionality:
    if(H->fAbort) { goto fail; }
    InfoDB_Initialize(H);
    PDB_Initialize(H, NULL, !H->cfg.fWaitInitialize);           // Init of PDB subsystem (async/sync).
    VmmWinInit_FindPsLoadedModuleListKDBG(H, pObSystemProcess); // Find PsLoadedModuleList and possibly KDBG.
    VmmWinReg_Initialize(H);                                    // Registry.
    VmmWinInit_TryInitialize_SystemUniqueTag(H);
    // Async Initialization functionality:
    if(H->fAbort) { goto fail; }
    if(H->cfg.fWaitInitialize) {
        VmmWinInit_TryInitialize_Async(H, 0);                   // synchronous initialization
    } else {
        VmmWork_Value(H, VmmWinInit_TryInitialize_Async, 0, 0, VMMWORK_FLAG_PRIO_NORMAL); // async initialization
    }
    // -memmap auto: 2nd try (if not already initialized)
    if(H->cfg.fMemMapAuto && !VmmWinInit_TryInitialize_MemMapAuto(H)) {
        VmmLog(H, MID_CORE, LOGLEVEL_CRITICAL, "Failed to load initial memory map from: 'auto'.\n");
        goto fail;
    }
    // clean up, print version (unless python execute parameter is set) and return!
    Ob_DECREF(pObSystemProcess);
    if(!H->cfg.szPythonExecuteFile[0]) {
        vmmprintf(H,
            "Initialized %i-bit Windows %i.%i.%i\n",
            (H->vmm.f32 ? 32 : 64),
            H->vmm.kernel.dwVersionMajor,
            H->vmm.kernel.dwVersionMinor,
            H->vmm.kernel.dwVersionBuild);
    }
    return TRUE;
fail:
    VmmInitializeMemoryModel(H, VMM_MEMORYMODEL_NA); // clean memory model
    ZeroMemory(&H->vmm.kernel, sizeof(VMM_KERNELINFO));
    Ob_DECREF(pObSystemProcess);
    return FALSE;
}
