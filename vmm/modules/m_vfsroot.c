// m_vfsroot.c : implementation of virtual file system root - not including
//               sub-modules and the special /name/ and /pid/ folders.
//               In practice this is the implementation of the root files:
//               'memory.dmp' and 'memory.pmem' only.
//
// (c) Ulf Frisk, 2020-2025
// Author: Ulf Frisk, pcileech@frizk.net
//

#include "modules.h"
#include "../sysquery.h"
#include "../version.h"
#include "../vmmwin.h"
#include "../vmmwininit.h"

#define KDBG64_KiProcessorBlock     0x218
#define KDBG64_ContextKPRCB         0x338
#define KDBG64_OffsetPrcbNumber     0x2be

typedef struct tdVMMVFS_DUMP_CONTEXT_OVERLAY {
    QWORD pa;
    DWORD cb;
    PBYTE pb;
} VMMVFS_DUMP_CONTEXT_OVERLAY, *PVMMVFS_DUMP_CONTEXT_OVERLAY;

typedef struct tdOB_VMMVFS_DUMP_CONTEXT {
    OB ObHdr;
    BOOL fInitialized;
    CRITICAL_SECTION Lock;
    DWORD cbHdr;
    union {
        BYTE pb[0x2000];
    } Hdr;
    struct {
        BOOL fEncrypted;
        QWORD pa;
        QWORD paKdpDataBlockEncoded;
        DWORD cb;
        BYTE pb[0x800];
        BYTE pbKdbDataBlockEncoded[1];
    } KDBG;
    struct {
        QWORD pa;
        DWORD cb;
        BYTE pb[0x10];
    } KiInitialPCR_Context;
    VMMVFS_DUMP_CONTEXT_OVERLAY OVERLAY[3];
} OB_VMMVFS_DUMP_CONTEXT, *POB_VMMVFS_DUMP_CONTEXT;

/*
* Optionally ensure Prcb[0].Context (nt!_CONTEXT) segment registers are
* set to non-zero. This is required by WinDbg. Lets fake these values.
* -- pSystemProcess
* -- ctx
*/
VOID MVfsRoot_EnsureProcessorContext0(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pSystemProcess, _In_ POB_VMMVFS_DUMP_CONTEXT ctx)
{
    BOOL f;
    QWORD va, vaContextKPRCB;
    if(H->vmm.f32) { return; }
    f = (va = *(PQWORD)(ctx->KDBG.pb + KDBG64_KiProcessorBlock)) &&
        VMM_KADDR64_16(va) &&
        VmmRead(H, pSystemProcess, va, (PBYTE)&va, sizeof(QWORD)) &&
        VMM_KADDR64_16(va) &&
        (va = va + *(PWORD)(ctx->KDBG.pb + KDBG64_ContextKPRCB)) &&
        VmmRead(H, pSystemProcess, va, (PBYTE)&vaContextKPRCB, sizeof(QWORD)) &&
        VMM_KADDR64_16(vaContextKPRCB);
    if(f) {
        if(VmmVirt2Phys(H, pSystemProcess, vaContextKPRCB + 0x038, &ctx->KiInitialPCR_Context.pa)) {
            ctx->KiInitialPCR_Context.cb = 0x10;
            *(PWORD)(ctx->KiInitialPCR_Context.pb + 0x00) = 0x10;   // SegCs
            *(PWORD)(ctx->KiInitialPCR_Context.pb + 0x02) = 0x2b;   // SegDs
            *(PWORD)(ctx->KiInitialPCR_Context.pb + 0x04) = 0x2b;   // SegEs
            *(PWORD)(ctx->KiInitialPCR_Context.pb + 0x06) = 0x53;   // SegFs
            *(PWORD)(ctx->KiInitialPCR_Context.pb + 0x08) = 0x2b;   // SegGs
            *(PWORD)(ctx->KiInitialPCR_Context.pb + 0x0a) = 0x00;   // SegSs
        }
        // set physical memory overlay struct for processor context
        ctx->OVERLAY[2].pa = ctx->KiInitialPCR_Context.pa;
        ctx->OVERLAY[2].cb = ctx->KiInitialPCR_Context.cb;
        ctx->OVERLAY[2].pb = ctx->KiInitialPCR_Context.pb;
    }
}

VOID MVfsRoot_KdbgDecryptRun(_In_ VMM_HANDLE H, _Inout_ PQWORD pqw)
{
    QWORD v = *pqw ^ H->vmm.kernel.opt.KDBG.qwKiWaitNever;
    v = _rotl64(v, (UCHAR)H->vmm.kernel.opt.KDBG.qwKiWaitNever);
    v = v ^ H->vmm.kernel.opt.KDBG.vaKdpDataBlockEncoded;
    v = _byteswap_uint64(v);
    *pqw = v ^ H->vmm.kernel.opt.KDBG.qwKiWaitAlways;
}

/*
* Load KDBG (KDebuggerDataBlock) and optionally (if required) decrypt it.
* Decryption most often needs to be done on x64 Win8+.
* -- H
* -- pSystemProcess
* -- ctx
*/
VOID MVfsRoot_KdbgLoadAndDecrypt(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pSystemProcess, _In_ POB_VMMVFS_DUMP_CONTEXT ctx)
{
    DWORD i;
    union {
        QWORD qw;
        struct {
            DWORD magic;
            DWORD cb;
        };
    } hdr;
    if(H->vmm.f32 || !H->vmm.kernel.opt.KDBG.va) { return; }
    if(!VmmVirt2Phys(H, pSystemProcess, H->vmm.kernel.opt.KDBG.va, &ctx->KDBG.pa)) { return; }
    if(!VmmRead(H, pSystemProcess, H->vmm.kernel.opt.KDBG.va + 0x10, (PBYTE)&hdr.qw, sizeof(QWORD))) { return; }
    if(hdr.magic == 0x4742444b) {
        // load decrypted and return
        if((hdr.cb > sizeof(ctx->KDBG.pb)) || !VmmRead(H, pSystemProcess, H->vmm.kernel.opt.KDBG.va, ctx->KDBG.pb, hdr.cb)) { return; }
        if(!VmmVirt2Phys(H, pSystemProcess, H->vmm.kernel.opt.KDBG.va, &ctx->KDBG.pa)) { return; }
        ctx->KDBG.cb = hdr.cb;
        ctx->KDBG.fEncrypted = FALSE;
        return;
    }
    // encrypted - try decrypt
    if(!H->vmm.kernel.opt.KDBG.vaKdpDataBlockEncoded || !H->vmm.kernel.opt.KDBG.qwKiWaitAlways || !H->vmm.kernel.opt.KDBG.qwKiWaitNever) { return; }
    if(!VmmVirt2Phys(H, pSystemProcess, H->vmm.kernel.opt.KDBG.vaKdpDataBlockEncoded, &ctx->KDBG.paKdpDataBlockEncoded)) { return; }
    MVfsRoot_KdbgDecryptRun(H, &hdr.qw);
    if((hdr.magic != 0x4742444b) || (hdr.cb > sizeof(ctx->KDBG.pb)) || (hdr.cb & 0x07)) { return; }
    if(!VmmRead(H, pSystemProcess, H->vmm.kernel.opt.KDBG.va, ctx->KDBG.pb, hdr.cb)) { return; }
    for(i = 0; i < hdr.cb; i += 8) {
        MVfsRoot_KdbgDecryptRun(H, (PQWORD)(ctx->KDBG.pb + i));
    }
    ctx->KDBG.cb = hdr.cb;
    // set physical memory overlay struct for decrypted KDBG
    ctx->OVERLAY[0].pa = ctx->KDBG.pa;
    ctx->OVERLAY[0].cb = ctx->KDBG.cb;
    ctx->OVERLAY[0].pb = ctx->KDBG.pb;
    ctx->OVERLAY[1].pa = ctx->KDBG.paKdpDataBlockEncoded;
    ctx->OVERLAY[1].cb = 1;
    ctx->OVERLAY[1].pb = ctx->KDBG.pbKdbDataBlockEncoded;
    ctx->KDBG.fEncrypted = TRUE;
}

VOID MVfsRoot_InitializeDumpContext_SetMemory(_In_ VMM_HANDLE H, _In_ POB_VMMVFS_DUMP_CONTEXT ctx)
{
    _PPHYSICAL_MEMORY_DESCRIPTOR32 pMd32 = (_PPHYSICAL_MEMORY_DESCRIPTOR32)(ctx->Hdr.pb + 0x064);
    _PPHYSICAL_MEMORY_DESCRIPTOR64 pMd64 = (_PPHYSICAL_MEMORY_DESCRIPTOR64)(ctx->Hdr.pb + 0x088);
    if(H->vmm.f32) {
        pMd32->NumberOfRuns = 1;
        pMd32->NumberOfPages = (DWORD)(H->dev.paMax / 0x1000);
        pMd32->Run[0].BasePage = 0;
        pMd32->Run[0].PageCount = (DWORD)(H->dev.paMax / 0x1000);
    } else {
        pMd64->Reserved1 = 0;
        pMd64->Reserved2 = 0;
        pMd64->NumberOfRuns = 1;
        pMd64->NumberOfPages = (DWORD)(H->dev.paMax / 0x1000);
        pMd64->Run[0].BasePage = 0;
        pMd64->Run[0].PageCount = H->dev.paMax / 0x1000;
    }
}

VOID MVfsRoot_InitializeDumpContext64(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pSystemProcess, _In_ POB_VMMVFS_DUMP_CONTEXT ctx)
{
    PBYTE pb = ctx->Hdr.pb;
    QWORD ftMin, ftMax;
    ftMin = H->vmm.kernel.opt.ftBootTime;
    ftMax = SysQuery_TimeCurrent(H);
    *(PDWORD)(pb + 0x000) = 0x45474150;                         // Signature #1
    *(PDWORD)(pb + 0x004) = 0x34365544;                         // Signature #2
    *(PDWORD)(pb + 0x008) = 0x0000000F;                         // DumpVersion
    *(PDWORD)(pb + 0x00c) = H->vmm.kernel.dwVersionBuild;       // BuildNo
    *(PQWORD)(pb + 0x010) = H->vmm.kernel.paDTB;
    *(PQWORD)(pb + 0x018) = H->vmm.kernel.opt.vaPfnDatabase;
    *(PQWORD)(pb + 0x020) = H->vmm.kernel.opt.vaPsLoadedModuleListExp;
    *(PQWORD)(pb + 0x028) = pSystemProcess->win.EPROCESS.va;
    *(PDWORD)(pb + 0x030) = (H->vmm.tpMemoryModel == VMMDLL_MEMORYMODEL_X64) ? 0x8664 : 0xAA64;     // MachineImageType = AMD64 / ARM64
    *(PDWORD)(pb + 0x034) = max(1, H->vmm.kernel.opt.cCPUs);
    *(PDWORD)(pb + 0x038) = 0xDEADDEAD;                         // BugCheckCode
    *(PQWORD)(pb + 0x040) = 1;                                  // BugCheck1
    *(PQWORD)(pb + 0x048) = 2;                                  // BugCheck2
    *(PQWORD)(pb + 0x050) = 3;                                  // BugCheck3
    *(PQWORD)(pb + 0x058) = 4;                                  // BugCheck4
    *(PQWORD)(pb + 0x080) = H->vmm.kernel.opt.KDBG.va;          // KDBG
    MVfsRoot_InitializeDumpContext_SetMemory(H, ctx);
    ZeroMemory(pb + 0x348, 3000);                               // ContextRecord
    *(PWORD)(pb + 0x348 + 0x038) = 0x10;                        // SegCs
    *(PWORD)(pb + 0x348 + 0x03a) = 0x2b;                        // SegDs
    *(PWORD)(pb + 0x348 + 0x03c) = 0x2b;                        // SegEs
    *(PWORD)(pb + 0x348 + 0x03e) = 0x53;                        // SegFs
    *(PWORD)(pb + 0x348 + 0x040) = 0x2b;                        // SegGs
    *(PWORD)(pb + 0x348 + 0x042) = 0x00;                        // SegSs
    *(PQWORD)(pb + 0x348 + 0x098) = H->vmm.kernel.vaBase;       // Rsp
    ZeroMemory(pb + 0xf00, 152);                                // ExceptionRecord
    ZeroMemory(pb + 0xfb0, 128);                                // Comment
    snprintf(
        pb + 0xfb0,
        128,
        "Dump file generated by MemProcFS v%i.%i.%i-%i - https://github.com/ufrisk/MemProcFS",
        VERSION_MAJOR,
        VERSION_MINOR,
        VERSION_REVISION,
        VERSION_BUILD);
    *(PDWORD)(pb + 0xf98) = 1;
    *(PQWORD)(pb + 0xfa0) = 0x2000 + H->dev.paMax;
    *(PQWORD)(pb + 0xfa8) = ftMax;
    *(PQWORD)(pb + 0x1030) = ftMax - ftMin;
    *(PDWORD)(pb + 0x1038) = 0;
    *(PDWORD)(pb + 0x103c) = 0;
    *(PDWORD)(pb + 0x1040) = 1;
    *(PDWORD)(pb + 0x1044) = 0;
    ctx->fInitialized = TRUE;
}

VOID MVfsRoot_InitializeDumpContext32(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pSystemProcess, POB_VMMVFS_DUMP_CONTEXT ctx)
{
    PBYTE pb = ctx->Hdr.pb;
    //PDUMP_HEADER32 pd = &ctx->Hdr._32;
    QWORD ftMin, ftMax;
    ftMin = H->vmm.kernel.opt.ftBootTime;
    ftMax = SysQuery_TimeCurrent(H);
    *(PDWORD)(pb + 0x000) = 0x45474150;                         // Signature #1
    *(PDWORD)(pb + 0x004) = 0x504d5544;                         // Signature #2
    *(PDWORD)(pb + 0x008) = 0x0000000F;                         // DumpVersion
    *(PDWORD)(pb + 0x00c) = H->vmm.kernel.dwVersionBuild;      // BuildNo
    *(PDWORD)(pb + 0x010) = (DWORD)H->vmm.kernel.paDTB;
    *(PDWORD)(pb + 0x014) = (DWORD)H->vmm.kernel.opt.vaPfnDatabase;
    *(PDWORD)(pb + 0x018) = (DWORD)H->vmm.kernel.opt.vaPsLoadedModuleListExp;
    *(PDWORD)(pb + 0x01c) = (DWORD)pSystemProcess->win.EPROCESS.va;
    *(PDWORD)(pb + 0x020) = 0x014c;                             // MachineImageType = I386
    *(PDWORD)(pb + 0x024) = max(1, H->vmm.kernel.opt.cCPUs);
    *(PDWORD)(pb + 0x028) = 0xDEADDEAD;                         // BugCheckCode
    *(PDWORD)(pb + 0x02c) = 1;                                  // BugCheck1
    *(PDWORD)(pb + 0x030) = 2;                                  // BugCheck2
    *(PDWORD)(pb + 0x034) = 3;                                  // BugCheck3
    *(PDWORD)(pb + 0x038) = 4;                                  // BugCheck4
    *(PBYTE)(pb + 0x05c) = (H->vmm.tpMemoryModel == VMM_MEMORYMODEL_X86PAE) ? 1 : 0;   // PAE or NOT.
    *(PDWORD)(pb + 0x060) = (DWORD)H->vmm.kernel.opt.KDBG.va;  // KDBG
    MVfsRoot_InitializeDumpContext_SetMemory(H, ctx);
    ZeroMemory(pb + 0x320, 1200);                               // ContextRecord
    ZeroMemory(pb + 0x7d0, 80);                                 // ExceptionRecord
    ZeroMemory(pb + 0x820, 128);                                // Comment
    snprintf(
        pb + 0x820,
        128,
        "Dump file generated by MemProcFS v%i.%i.%i-%i - https://github.com/ufrisk/MemProcFS",
        VERSION_MAJOR,
        VERSION_MINOR,
        VERSION_REVISION,
        VERSION_BUILD);
    *(PDWORD)(pb + 0xf88) = 1;
    *(PQWORD)(pb + 0xfa0) = 0x2000 + H->dev.paMax;
    *(PQWORD)(pb + 0xfc0) = ftMax;
    *(PQWORD)(pb + 0xfb8) = ftMax - ftMin;
    *(PDWORD)(pb + 0xf8c) = 0;
    *(PDWORD)(pb + 0xf90) = 0;
    *(PDWORD)(pb + 0xf94) = 1;
    *(PDWORD)(pb + 0xf98) = 0;
    ctx->fInitialized = TRUE;
}

VOID MVfsRoot_InitializeDumpContext(_In_ VMM_HANDLE H, POB_VMMVFS_DUMP_CONTEXT ctx)
{
    PVMM_PROCESS pObSystemProcess = NULL;
    DWORD cbDumpHeader;
    PBYTE pbDumpHeader;
    // 1: Try to initialize from underlying crash dump file header (if possible)
    //    The crash dump header is simply copied verbatim - except mem regions.
    //    Crash dump headers are always assumed to be correct and the dump files
    //    are assumed to have a decrypted KDBG block.
    ctx->cbHdr = H->vmm.f32 ? 0x1000 : 0x2000;
    if(LcCommand(H->hLC, LC_CMD_FILE_DUMPHEADER_GET, 0, NULL, &pbDumpHeader, &cbDumpHeader)) {
        if(cbDumpHeader == ctx->cbHdr) {
            memcpy(ctx->Hdr.pb, pbDumpHeader, ctx->cbHdr);
            LocalFree(pbDumpHeader);
            MVfsRoot_InitializeDumpContext_SetMemory(H, ctx);
            ctx->fInitialized = TRUE;
            return;
        }
        LocalFree(pbDumpHeader);
    }
    // 2: Load optional required values in a best-effort way and decrypt KDBG
    //    if necessary and possible.
    if(!(pObSystemProcess = VmmProcessGet(H, 4))) { return; }
    VmmWinInit_TryInitializeKernelOptionalValues(H);
    MVfsRoot_KdbgLoadAndDecrypt(H, pObSystemProcess, ctx);
    MVfsRoot_EnsureProcessorContext0(H, pObSystemProcess, ctx);
    // 3: Initialize dump headers
    memset(ctx->Hdr.pb, 'X', ctx->cbHdr);
    if(H->vmm.f32) {
        MVfsRoot_InitializeDumpContext32(H, pObSystemProcess, ctx);
    } else {
        MVfsRoot_InitializeDumpContext64(H, pObSystemProcess, ctx);
    }
    Ob_DECREF(pObSystemProcess);
}

VOID MVfsRoot_CallbackCleanup_ObVmmVfsDumpContext(POB_VMMVFS_DUMP_CONTEXT pOb)
{
    DeleteCriticalSection(&pOb->Lock);
}

/*
* Retrieve the module context object.
* CALLER DECREF: return
* -- H
* -- return
*/
POB_VMMVFS_DUMP_CONTEXT MVfsRoot_GetDumpContext(_In_ VMM_HANDLE H)
{
    POB_VMMVFS_DUMP_CONTEXT ctx;
    // 1: fetch context or create initial context if required
    if(!(ctx = (POB_VMMVFS_DUMP_CONTEXT)Ob_INCREF(H->vmm.pObVfsDumpContext))) {
        EnterCriticalSection(&H->vmm.LockMaster);
        if(!(ctx = (POB_VMMVFS_DUMP_CONTEXT)Ob_INCREF(H->vmm.pObVfsDumpContext))) {
            ctx = (POB_VMMVFS_DUMP_CONTEXT)Ob_AllocEx(H, OB_TAG_VMMVFS_DUMPCONTEXT, LMEM_ZEROINIT, sizeof(OB_VMMVFS_DUMP_CONTEXT), NULL, NULL);
            if(ctx) {
                InitializeCriticalSection(&ctx->Lock);
                H->vmm.pObVfsDumpContext = Ob_INCREF(ctx);
            }
        }
        LeaveCriticalSection(&H->vmm.LockMaster);
    }
    // 2: initialize context (if required)
    if(ctx && !ctx->fInitialized) {
        EnterCriticalSection(&ctx->Lock);
        if(!ctx->fInitialized) {
            MVfsRoot_InitializeDumpContext(H, ctx);
        }
        LeaveCriticalSection(&ctx->Lock);
    }
    return ctx;
}

/*
* Read from memory dump files in the virtual file system root.
* -- H
* -- ctxP
* -- pb
* -- cb
* -- pcbRead
* -- cbOffset
* -- return
*/
NTSTATUS MVfsRoot_Read(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_CONTEXT ctxP, _Out_writes_to_(cb, *pcbRead) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset)
{
    NTSTATUS nt = VMM_STATUS_FILE_INVALID;
    POB_VMMVFS_DUMP_CONTEXT pObDumpCtx = NULL;
    PVMMVFS_DUMP_CONTEXT_OVERLAY po;
    DWORD io, cbHead = 0, cbReadMem = 0;
    DWORD cbOverlayOffset, cbOverlay;
    QWORD cbOverlayAdjust;
    if(!_stricmp(ctxP->uszPath, "memory.pmem")) {
        VmmReadEx(H, NULL, cbOffset, pb, cb, pcbRead, VMM_FLAG_ZEROPAD_ON_FAIL);
        return VMM_STATUS_SUCCESS;
    }
    if(!_stricmp(ctxP->uszPath, "memory.dmp")) {
        if((H->vmm.tpSystem != VMM_SYSTEM_WINDOWS_64) && (H->vmm.tpSystem != VMM_SYSTEM_WINDOWS_32)) { goto finish; }
        if(!(pObDumpCtx = MVfsRoot_GetDumpContext(H))) { goto finish; }
        // read dump header
        if(cbOffset < pObDumpCtx->cbHdr) {
            cbHead = min(cb, pObDumpCtx->cbHdr - (DWORD)cbOffset);
            memcpy(pb, pObDumpCtx->Hdr.pb + cbOffset, cbHead);
            pb += cbHead;
            cb -= cbHead;
            cbOffset += cbHead;
        }
        if(cb == 0) {
            if(pcbRead) { *pcbRead = cbHead; }
            nt = VMM_STATUS_SUCCESS;
            goto finish;
        }
        cbOffset -= pObDumpCtx->cbHdr;
        // read memory
        VmmReadEx(H, NULL, cbOffset, pb, cb, &cbReadMem, VMM_FLAG_ZEROPAD_ON_FAIL);
        if(pcbRead) { *pcbRead = cbHead + cbReadMem; }
        // overlay decrypted KDBG, KdpDataBlockEncoded (if encrypted) and ProcessorContext0
        for(io = 0; io < sizeof(pObDumpCtx->OVERLAY) / sizeof(VMMVFS_DUMP_CONTEXT_OVERLAY); io++) {
            po = pObDumpCtx->OVERLAY + io;
            if(!po->cb) { continue; }
            if((cbOffset <= po->pa + po->cb) && (cbOffset + cb > po->pa)) {
                if(po->pa <= cbOffset) {
                    cbOverlayAdjust = 0;
                    cbOverlayOffset = (DWORD)(cbOffset - po->pa);
                    cbOverlay = min(po->cb - cbOverlayOffset, cb);
                } else {
                    cbOverlayAdjust = po->pa - cbOffset;
                    cbOverlayOffset = 0;
                    cbOverlay = (DWORD)min(po->cb, cb - cbOverlayAdjust);
                }
                memcpy(pb + cbOverlayAdjust, po->pb + cbOverlayOffset, cbOverlay);
            }
        }
        nt = VMM_STATUS_SUCCESS;
    }
finish:
    Ob_DECREF(pObDumpCtx);
    return nt;
}

/*
* Write to memory dump files in the virtual file system root. This requires a
* write-capable backend device/driver. Also the crash dump header in microsoft
* crash dumps aren't writable. This write function does not account for any
* overlayed memory - such as decrypted KDBG.
* -- H
* -- ctxP
* -- pb
* -- cb
* -- pcbWrite
* -- cbOffset
* -- return
*/
NTSTATUS MVfsRoot_Write(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_CONTEXT ctxP, _In_reads_(cb) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbWrite, _In_ QWORD cbOffset)
{
    BOOL fResult;
    DWORD cbHeaderSize;
    if(!_stricmp(ctxP->uszPath, "memory.pmem")) {
        *pcbWrite = cb;
        fResult = VmmWrite(H, NULL, cbOffset, pb, cb);
        return fResult ? VMM_STATUS_SUCCESS : VMM_STATUS_FILE_SYSTEM_LIMITATION;
    }
    if(!_stricmp(ctxP->uszPath, "memory.dmp")) {
        if((H->vmm.tpSystem != VMM_SYSTEM_WINDOWS_64) && (H->vmm.tpSystem != VMM_SYSTEM_WINDOWS_32)) { return VMM_STATUS_FILE_INVALID; }
        *pcbWrite = cb;
        cbHeaderSize = H->vmm.f32 ? 0x1000 : 0x2000;
        if(cbOffset + cb <= cbHeaderSize) {
            return VMM_STATUS_SUCCESS;
        }
        if(cbOffset < cbHeaderSize) {
            pb += (DWORD)(cbHeaderSize - cbOffset);
            cb -= (DWORD)(cbHeaderSize - cbOffset);
            cbOffset = cbHeaderSize;
        }
        fResult = VmmWrite(H, NULL, cbOffset, pb, cb);
        return fResult ? VMM_STATUS_SUCCESS : VMM_STATUS_FILE_SYSTEM_LIMITATION;
    }
    return VMM_STATUS_FILE_INVALID;
}

/*
* List : function as specified by the module manager. The module manager will
* call into this callback function whenever a list directory shall occur from
* the given module.
* -- ctx
* -- pFileList
* -- return
*/
BOOL MVfsRoot_List(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_CONTEXT ctxP, _Inout_ PHANDLE pFileList)
{
    if(!ctxP->uszPath[0]) {
        VMMDLL_VfsList_AddFile(pFileList, "memory.pmem", H->dev.paMax, NULL);
        if((H->vmm.tpSystem == VMM_SYSTEM_WINDOWS_64) || (H->vmm.tpSystem == VMM_SYSTEM_WINDOWS_32)) {
            VMMDLL_VfsList_AddFile(pFileList, "memory.dmp", H->dev.paMax + (H->vmm.f32 ? 0x1000 : 0x2000), NULL);
        }
        if(H->vmm.tpSystem != VMM_SYSTEM_UNKNOWN_PHYSICAL) {
            VMMDLL_VfsList_AddDirectory(pFileList, "name", NULL);
            VMMDLL_VfsList_AddDirectory(pFileList, "pid", NULL);
        }
    }
    return TRUE;
}

/*
* Initialization function. The module manager shall call into this function
* when the module shall be initialized. If the module wish to initialize it
* shall call the supplied pfnPluginManager_Register function.
* NB! the module does not have to register itself - for example if the target
* operating system or architecture is unsupported.
* -- H
* -- pRI
*/
VOID M_VfsRoot_Initialize(_In_ VMM_HANDLE H, _Inout_ PVMMDLL_PLUGIN_REGINFO pRI)
{
    strcpy_s(pRI->reg_info.uszPathName, 128, "\\");                      // module name
    pRI->reg_info.fRootModule = TRUE;                                    // root module
    pRI->reg_fn.pfnList = MVfsRoot_List;                                 // List function supported
    pRI->reg_fn.pfnRead = MVfsRoot_Read;                                 // Read function supported
    if(H->dev.fWritable) {
        pRI->reg_fn.pfnWrite = MVfsRoot_Write;                           // Write function supported
    }
    pRI->pfnPluginManager_Register(H, pRI);
}
