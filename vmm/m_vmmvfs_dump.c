// m_vmmvfs_dump.h : implementation of vmmvfs memory dump file functionality
//                   which shows the raw memory dump microsoft crash dump files
//                   in the virtual file system root.
// NB! this is not a normal plugin.
//
// (c) Ulf Frisk, 2019
// Author: Ulf Frisk, pcileech@frizk.net
//
#include "m_phys2virt.h"
#include "pluginmanager.h"
#include "pe.h"
#include "sysquery.h"
#include "version.h"
#include "vmm.h"
#include "vmmwininit.h"

#define KDBG64_KiProcessorBlock     0x218
#define KDBG64_ContextKPRCB         0x338
#define KDBG64_OffsetPrcbNumber     0x2be

#define DUMP_SIGNATURE              0x45474150
#define DUMP_VALID_DUMP             0x504d5544
#define DUMP_VALID_DUMP64           0x34365544
#define DUMP_MAJOR_VERSION          0x0000000F
#define DUMP_TYPE_FULL              1
#define _PHYSICAL_MEMORY_MAX_RUNS   0x20

typedef struct {
    QWORD BasePage;
    QWORD PageCount;
} _PHYSICAL_MEMORY_RUN64;

typedef struct {
    QWORD NumberOfRuns;
    QWORD NumberOfPages;
    _PHYSICAL_MEMORY_RUN64 Run[_PHYSICAL_MEMORY_MAX_RUNS];
} _PHYSICAL_MEMORY_DESCRIPTOR64;

typedef struct {
    DWORD BasePage;
    DWORD PageCount;
} _PHYSICAL_MEMORY_RUN32;

typedef struct {
    DWORD NumberOfRuns;
    DWORD NumberOfPages;
    _PHYSICAL_MEMORY_RUN32 Run[_PHYSICAL_MEMORY_MAX_RUNS];
} _PHYSICAL_MEMORY_DESCRIPTOR32;

typedef struct tdDUMP_HEADER32 {
    ULONG Signature;                    // 0x0000
    ULONG ValidDump;                    // 0x0004
    ULONG MajorVersion;                 // 0x0008
    ULONG MinorVersion;					// 0x000c
    ULONG DirectoryTableBase;			// 0x0010
    ULONG PfnDataBase;                  // 0x0014
    ULONG PsLoadedModuleList;           // 0x0018
    ULONG PsActiveProcessHead;          // 0x001c
    ULONG MachineImageType;             // 0x0020
    ULONG NumberProcessors;             // 0x0024
    ULONG BugCheckCode;                 // 0x0028
    ULONG BugCheckParameter1;           // 0x002c
    ULONG BugCheckParameter2;           // 0x0030
    ULONG BugCheckParameter3;           // 0x0034
    ULONG BugCheckParameter4;           // 0x0038
    CHAR VersionUser[32];               // 0x003c
    CHAR PaeEnabled;                    // 0x005c
    CHAR KdSecondaryVersion;            // 0x005d
    CHAR spare[2];                      // 0x005e
    ULONG KdDebuggerDataBlock;          // 0x0060
    union {                             // 0x0064
        _PHYSICAL_MEMORY_DESCRIPTOR32 PhysicalMemoryBlock;
        UCHAR PhysicalMemoryBlockBuffer[700];
    };
    UCHAR ContextRecord[1200];          // 0x0320
    EXCEPTION_RECORD32 ExceptionRecord; // 0x07d0
    CHAR Comment[128];                  // 0x0820
    UCHAR reserved0[1768];              // 0x08a0
    ULONG DumpType;                     // 0x0f88
    ULONG MiniDumpFields;               // 0x0f8c
    ULONG SecondaryDataState;           // 0x0f90
    ULONG ProductType;                  // 0x0f94
    ULONG SuiteMask;                    // 0x0f98
    UCHAR reserved1[4];                 // 0x0f9c
    ULONG64 RequiredDumpSpace;          // 0x0fa0
    UCHAR reserved2[16];                // 0x0fa8
    ULONG64 SystemUpTime;               // 0x0fb8
    ULONG64 SystemTime;                 // 0x0fc0
    UCHAR reserved3[56];                // 0x0fc8
} DUMP_HEADER32, *PDUMP_HEADER32;

typedef struct tdDUMP_HEADER64 {
    ULONG Signature;					// 0x0000
    ULONG ValidDump;					// 0x0004
    ULONG MajorVersion;					// 0x0008
    ULONG MinorVersion;					// 0x000c
    ULONG64 DirectoryTableBase;			// 0x0010
    ULONG64 PfnDataBase;				// 0x0018
    ULONG64 PsLoadedModuleList;			// 0x0020
    ULONG64 PsActiveProcessHead;		// 0x0028
    ULONG MachineImageType;				// 0x0030
    ULONG NumberProcessors;				// 0x0034
    ULONG BugCheckCode;					// 0x0038
    ULONG64 BugCheckParameter1;			// 0x0040
    ULONG64 BugCheckParameter2;			// 0x0048
    ULONG64 BugCheckParameter3;			// 0x0050
    ULONG64 BugCheckParameter4;			// 0x0058
    CHAR VersionUser[32];				// 0x0060
    ULONG64 KdDebuggerDataBlock;		// 0x0080
    union {								// 0x0088
        _PHYSICAL_MEMORY_DESCRIPTOR64 PhysicalMemoryBlock;
        UCHAR PhysicalMemoryBlockBuffer[700];
    };
    UCHAR ContextRecord[3000];			// 0x0348
    EXCEPTION_RECORD64 ExceptionRecord;	// 0x0F00
    ULONG DumpType;						// 0x0F98
    ULONG64 RequiredDumpSpace;	        // 0x0FA0
    ULONG64 SystemTime;				    // 0x0FA8 
    CHAR Comment[0x80];					// 0x0FB0 May not be present.
    ULONG64 SystemUpTime;				// 0x1030
    ULONG MiniDumpFields;				// 0x1038
    ULONG SecondaryDataState;			// 0x103c
    ULONG ProductType;					// 0x1040
    ULONG SuiteMask;					// 0x1044
    ULONG WriterStatus;					// 0x1048
    UCHAR Unused1;						// 0x104c
    UCHAR KdSecondaryVersion;			// 0x104d Present only for W2K3 SP1 and better
    UCHAR Unused[2];					// 0x104e
    UCHAR _reserved0[4016];				// 0x1050
} DUMP_HEADER64, *PDUMP_HEADER64;

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
        DUMP_HEADER64 _64;
        DUMP_HEADER32 _32;
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
VOID MVmmVfsDump_EnsureProcessorContext0(_In_ PVMM_PROCESS pSystemProcess, _In_ POB_VMMVFS_DUMP_CONTEXT ctx)
{
    BOOL f;
    QWORD va, vaContextKPRCB;
    if(!ctxVmm->f32) {
        f = (va = *(PQWORD)(ctx->KDBG.pb + KDBG64_KiProcessorBlock)) &&
            VMM_KADDR64_16(va) &&
            VmmRead(pSystemProcess, va, (PBYTE)&va, sizeof(QWORD)) &&
            VMM_KADDR64_16(va) &&
            (va = va + *(PWORD)(ctx->KDBG.pb + KDBG64_ContextKPRCB)) &&
            VmmRead(pSystemProcess, va, (PBYTE)&vaContextKPRCB, sizeof(QWORD)) &&
            VMM_KADDR64_16(vaContextKPRCB);
        if(f) {
            if(VmmVirt2Phys(pSystemProcess, vaContextKPRCB + 0x038, &ctx->KiInitialPCR_Context.pa)) {
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
}

VOID MVmmVfsDump_KdbgDecryptRun(_Inout_ PQWORD pqw)
{
    QWORD v = *pqw ^ ctxVmm->kernel.opt.KDBG.qwKiWaitNever;
    v = _rotl64(v, (UCHAR)ctxVmm->kernel.opt.KDBG.qwKiWaitNever);
    v = v ^ ctxVmm->kernel.opt.KDBG.vaKdpDataBlockEncoded;
    v = _byteswap_uint64(v);
    *pqw = v ^ ctxVmm->kernel.opt.KDBG.qwKiWaitAlways;
}

/*
* Load KDBG (KDebuggerDataBlock) and optionally (if required) decrypt it.
* Decryption most often needs to be done on x64 Win8+.
* -- pSystemProcess
* -- ctx
*/
VOID MVmmVfsDump_KdbgLoadAndDecrypt(_In_ PVMM_PROCESS pSystemProcess, _In_ POB_VMMVFS_DUMP_CONTEXT ctx)
{
    DWORD i;
    union {
        QWORD qw;
        struct {
            DWORD magic;
            DWORD cb;
        };
    } hdr;
    if(ctxVmm->f32 || !ctxVmm->kernel.opt.KDBG.va) { return; }
    if(!VmmVirt2Phys(pSystemProcess, ctxVmm->kernel.opt.KDBG.va, &ctx->KDBG.pa)) { return; }
    if(!VmmRead(pSystemProcess, ctxVmm->kernel.opt.KDBG.va + 0x10, (PBYTE)&hdr.qw, sizeof(QWORD))) { return; }
    if(hdr.magic == 0x4742444b) {
        // load decrypted and return
        if((hdr.cb > sizeof(ctx->KDBG.pb)) || !VmmRead(pSystemProcess, ctxVmm->kernel.opt.KDBG.va, ctx->KDBG.pb, hdr.cb)) { return; }
        if(!VmmVirt2Phys(pSystemProcess, ctxVmm->kernel.opt.KDBG.va, &ctx->KDBG.pa)) { return; }
        ctx->KDBG.cb = hdr.cb;
        ctx->KDBG.fEncrypted = FALSE;
        return;
    }
    // encrypted - try decrypt
    if(!ctxVmm->kernel.opt.KDBG.vaKdpDataBlockEncoded || !ctxVmm->kernel.opt.KDBG.qwKiWaitAlways || !ctxVmm->kernel.opt.KDBG.qwKiWaitNever) { return; }
    if(!VmmVirt2Phys(pSystemProcess, ctxVmm->kernel.opt.KDBG.vaKdpDataBlockEncoded, &ctx->KDBG.paKdpDataBlockEncoded)) { return; }
    MVmmVfsDump_KdbgDecryptRun(&hdr.qw);
    if((hdr.magic != 0x4742444b) || (hdr.cb > sizeof(ctx->KDBG.pb)) || (hdr.cb & 0x07)) { return; }
    if(!VmmRead(pSystemProcess, ctxVmm->kernel.opt.KDBG.va, ctx->KDBG.pb, hdr.cb)) { return; }
    for(i = 0; i < hdr.cb; i += 8) {
        MVmmVfsDump_KdbgDecryptRun((PQWORD)(ctx->KDBG.pb + i));
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

VOID MVmmVfsDump_InitializeDumpContext_SetMemory(_In_ POB_VMMVFS_DUMP_CONTEXT ctx)
{
    if(ctxVmm->f32) {
        ctx->Hdr._32.PhysicalMemoryBlock.NumberOfRuns = 1;
        ctx->Hdr._32.PhysicalMemoryBlock.NumberOfPages = (DWORD)(ctxMain->dev.paMax / 0x1000);
        ctx->Hdr._32.PhysicalMemoryBlock.Run[0].BasePage = 0;
        ctx->Hdr._32.PhysicalMemoryBlock.Run[0].PageCount = (DWORD)(ctxMain->dev.paMax / 0x1000);
    } else {
        ctx->Hdr._64.PhysicalMemoryBlock.NumberOfRuns = 1;
        ctx->Hdr._64.PhysicalMemoryBlock.NumberOfPages = (DWORD)(ctxMain->dev.paMax / 0x1000);
        ctx->Hdr._64.PhysicalMemoryBlock.Run[0].BasePage = 0;
        ctx->Hdr._64.PhysicalMemoryBlock.Run[0].PageCount = ctxMain->dev.paMax / 0x1000;
    }
}

VOID MVmmVfsDump_InitializeDumpContext64(_In_ PVMM_PROCESS pSystemProcess, _In_ POB_VMMVFS_DUMP_CONTEXT ctx)
{
    PDUMP_HEADER64 pd = &ctx->Hdr._64;
    QWORD ftMin = 0, ftMax = 0;
    SysQuery_TimeProcessMinMax(&ftMin, &ftMax);
    pd->Signature = DUMP_SIGNATURE;
    pd->ValidDump = DUMP_VALID_DUMP64;
    pd->MajorVersion = DUMP_MAJOR_VERSION;
    pd->MinorVersion = ctxVmm->kernel.dwVersionBuild;
    pd->DirectoryTableBase = ctxVmm->kernel.paDTB;
    pd->PfnDataBase = ctxVmm->kernel.opt.vaPfnDatabase;
    pd->PsLoadedModuleList = ctxVmm->kernel.opt.vaPsLoadedModuleListExp;
    pd->PsActiveProcessHead = pSystemProcess->win.EPROCESS.va;
    pd->MachineImageType = IMAGE_FILE_MACHINE_AMD64;
    pd->NumberProcessors = ctxVmm->kernel.opt.cCPUs;
    pd->BugCheckCode = 0xDEADDEAD;
    pd->BugCheckParameter1 = 1;
    pd->BugCheckParameter2 = 2;
    pd->BugCheckParameter3 = 3;
    pd->BugCheckParameter4 = 4;
    pd->KdDebuggerDataBlock = ctxVmm->kernel.opt.KDBG.va;
    MVmmVfsDump_InitializeDumpContext_SetMemory(ctx);
    ZeroMemory(pd->ContextRecord, sizeof(pd->ContextRecord));
    *(PWORD)(pd->ContextRecord + 0x038) = 0x10;                     // SegCs
    *(PWORD)(pd->ContextRecord + 0x03a) = 0x2b;                     // SegDs
    *(PWORD)(pd->ContextRecord + 0x03c) = 0x2b;                     // SegEs
    *(PWORD)(pd->ContextRecord + 0x03e) = 0x53;                     // SegFs
    *(PWORD)(pd->ContextRecord + 0x040) = 0x2b;                     // SegGs
    *(PWORD)(pd->ContextRecord + 0x042) = 0x00;                     // SegSs
    *(PQWORD)(pd->ContextRecord + 0x098) = ctxVmm->kernel.vaBase;   // Rsp
    ZeroMemory(&pd->ExceptionRecord, sizeof(pd->ExceptionRecord));
    pd->DumpType = DUMP_TYPE_FULL;
    pd->RequiredDumpSpace = 0x2000 + ctxMain->dev.paMax;
    pd->SystemTime = ftMax;
    ZeroMemory(pd->Comment, sizeof(pd->Comment));
    snprintf(
        pd->Comment,
        sizeof(pd->Comment),
        "Dump file generated by MemProcFS v%i.%i.%i-%i - The Memory Process File System - https://github.com/ufrisk/MemProcFS",
        VERSION_MAJOR,
        VERSION_MINOR,
        VERSION_REVISION,
        VERSION_BUILD);
    pd->SystemUpTime = ftMax - ftMin;
    pd->MiniDumpFields = 0;
    pd->SecondaryDataState = 0;
    pd->ProductType = 1;
    pd->SuiteMask = 0;
    ctx->fInitialized = TRUE;
}

VOID MVmmVfsDump_InitializeDumpContext32(PVMM_PROCESS pSystemProcess, POB_VMMVFS_DUMP_CONTEXT ctx)
{
    PDUMP_HEADER32 pd = &ctx->Hdr._32;
    QWORD ftMin = 0, ftMax = 0;
    SysQuery_TimeProcessMinMax(&ftMin, &ftMax);
    pd->Signature = DUMP_SIGNATURE;
    pd->ValidDump = DUMP_VALID_DUMP;
    pd->MajorVersion = DUMP_MAJOR_VERSION;
    pd->MinorVersion = ctxVmm->kernel.dwVersionBuild;
    pd->DirectoryTableBase = (DWORD)ctxVmm->kernel.paDTB;
    pd->PfnDataBase = (DWORD)ctxVmm->kernel.opt.vaPfnDatabase;
    pd->PsLoadedModuleList = (DWORD)ctxVmm->kernel.opt.vaPsLoadedModuleListExp;
    pd->PsActiveProcessHead = (DWORD)pSystemProcess->win.EPROCESS.va;
    pd->MachineImageType = IMAGE_FILE_MACHINE_I386;
    pd->NumberProcessors = ctxVmm->kernel.opt.cCPUs;
    pd->BugCheckCode = 0xDEADDEAD;
    pd->BugCheckParameter1 = 1;
    pd->BugCheckParameter2 = 2;
    pd->BugCheckParameter3 = 3;
    pd->BugCheckParameter4 = 4;
    pd->PaeEnabled = (ctxVmm->tpMemoryModel == VMM_MEMORYMODEL_X86PAE) ? 1 : 0;
    pd->KdDebuggerDataBlock = (DWORD)ctxVmm->kernel.opt.KDBG.va;
    MVmmVfsDump_InitializeDumpContext_SetMemory(ctx);
    ZeroMemory(pd->ContextRecord, sizeof(pd->ContextRecord));
    ZeroMemory(&pd->ExceptionRecord, sizeof(pd->ExceptionRecord));
    pd->DumpType = DUMP_TYPE_FULL;
    pd->RequiredDumpSpace = 0x1000 + ctxMain->dev.paMax;
    pd->SystemTime = ftMax;
    ZeroMemory(pd->Comment, sizeof(pd->Comment));
    snprintf(
        pd->Comment,
        sizeof(pd->Comment),
        "Dump file generated by MemProcFS v%i.%i.%i-%i - The Memory Process File System - https://github.com/ufrisk/MemProcFS",
        VERSION_MAJOR,
        VERSION_MINOR,
        VERSION_REVISION,
        VERSION_BUILD);
    pd->SystemUpTime = ftMax - ftMin;
    pd->MiniDumpFields = 0;
    pd->SecondaryDataState = 0;
    pd->ProductType = 1;
    pd->SuiteMask = 0;
    ctx->fInitialized = TRUE;
}

VOID MVmmVfsDump_InitializeDumpContext(POB_VMMVFS_DUMP_CONTEXT ctx)
{
    PVMM_PROCESS pObSystemProcess = NULL;
    // 1: Try to initialize from underlying crash dump file header (if possible)
    //    The crash dump header is simply copied verbatim - except mem regions.
    //    Crash dump headers are always assumed to be correct and the dump files
    //    are assumed to have a decrypted KDBG block.
    ctx->cbHdr = ctxVmm->f32 ? 0x1000 : 0x2000;
    if(LeechCore_CommandData(LEECHCORE_COMMANDDATA_FILE_DUMPHEADER_GET, NULL, 0, ctx->Hdr.pb, ctx->cbHdr, NULL)) {
        MVmmVfsDump_InitializeDumpContext_SetMemory(ctx);
        ctx->fInitialized = TRUE;
        return;
    }
    // 2: Load optional required values in a best-effort way and decrypt KDBG
    //    if necessary and possible.
    if(!(pObSystemProcess = VmmProcessGet(4))) { return; }
    VmmWinInit_TryInitializeKernelOptionalValues();
    MVmmVfsDump_KdbgLoadAndDecrypt(pObSystemProcess, ctx);
    MVmmVfsDump_EnsureProcessorContext0(pObSystemProcess, ctx);
    // 3: Initialize dump headers
    memset(ctx->Hdr.pb, 'X', ctx->cbHdr);
    if(ctxVmm->f32) {
        MVmmVfsDump_InitializeDumpContext32(pObSystemProcess, ctx);
    } else {
        MVmmVfsDump_InitializeDumpContext64(pObSystemProcess, ctx);
    }
    Ob_DECREF(pObSystemProcess);
}

VOID MVmmVfsDump_CallbackCleanup_ObVmmVfsDumpContext(POB_VMMVFS_DUMP_CONTEXT pOb)
{
    DeleteCriticalSection(&pOb->Lock);
}

/*
* Retrieve the module context object.
* CALLER DECREF: return
* -- return
*/
POB_VMMVFS_DUMP_CONTEXT MVmmVfsDump_GetDumpContext()
{
    POB_VMMVFS_DUMP_CONTEXT ctx;
    // 1: fetch context or create initial context if required
    if(!(ctx = (POB_VMMVFS_DUMP_CONTEXT)Ob_INCREF(ctxVmm->pObVfsDumpContext))) {
        EnterCriticalSection(&ctxVmm->MasterLock);
        if(!(ctx = (POB_VMMVFS_DUMP_CONTEXT)Ob_INCREF(ctxVmm->pObVfsDumpContext))) {
            ctx = (POB_VMMVFS_DUMP_CONTEXT)Ob_Alloc(OB_TAG_VMMVFS_DUMPCONTEXT, LMEM_ZEROINIT, sizeof(OB_VMMVFS_DUMP_CONTEXT), NULL, NULL);
            if(ctx) {
                InitializeCriticalSection(&ctx->Lock);
                ctxVmm->pObVfsDumpContext = Ob_INCREF(ctx);
            }
        }
        LeaveCriticalSection(&ctxVmm->MasterLock);
    }
    // 2: initialize context (if required)
    if(ctx && !ctx->fInitialized) {
        EnterCriticalSection(&ctx->Lock);
        if(!ctx->fInitialized) {
            MVmmVfsDump_InitializeDumpContext(ctx);
        }
        LeaveCriticalSection(&ctx->Lock);
    }
    return ctx;
}

/*
* Read from memory dump files in the virtual file system root.
* -- wcsFileName
* -- pb
* -- cb
* -- pcbRead
* -- cbOffset
* -- return
*/
NTSTATUS MVmmVfsDump_Read(_In_ LPCWSTR wcsFileName, _Out_writes_(cb) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset)
{
    NTSTATUS nt = VMM_STATUS_FILE_INVALID;
    POB_VMMVFS_DUMP_CONTEXT ctx = NULL;
    PVMMVFS_DUMP_CONTEXT_OVERLAY po;
    DWORD io, cbHead = 0, cbReadMem = 0;
    DWORD cbOverlayOffset, cbOverlay;
    QWORD cbOverlayAdjust;
    if(!_wcsicmp(wcsFileName, L"\\memory.pmem")) {
        VmmReadEx(NULL, cbOffset, pb, cb, pcbRead, VMM_FLAG_ZEROPAD_ON_FAIL);
        return VMM_STATUS_SUCCESS;
    }
    if(!_wcsicmp(wcsFileName, L"\\memory.dmp")) {
        if(!(ctx = MVmmVfsDump_GetDumpContext())) { goto finish; }
        // read dump header
        if(cbOffset < ctx->cbHdr) {
            cbHead = min(cb, ctx->cbHdr - (DWORD)cbOffset);
            memcpy(pb, ctx->Hdr.pb + cbOffset, cbHead);
            pb += cbHead;
            cb -= cbHead;
            cbOffset += cbHead;
        }
        if(cb == 0) {
            if(pcbRead) { *pcbRead = cbHead; }
            nt = VMM_STATUS_SUCCESS;
            goto finish;
        }
        cbOffset -= ctx->cbHdr;
        // read memory
        VmmReadEx(NULL, cbOffset, pb, cb, &cbReadMem, VMM_FLAG_ZEROPAD_ON_FAIL);
        if(pcbRead) { *pcbRead = cbHead + cbReadMem; }
        // overlay decrypted KDBG, KdpDataBlockEncoded (if encrypted) and ProcessorContext0
        for(io = 0; io < sizeof(ctx->OVERLAY) / sizeof(VMMVFS_DUMP_CONTEXT_OVERLAY); io++) {
            po = ctx->OVERLAY + io;
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
    Ob_DECREF(ctx);
    return nt;
}

/*
* Write to memory dump files in the virtual file system root. This requires a
* write-capable backend device/driver. Also the crash dump header in microsoft
* crash dumps aren't writable. This write function does not account for any
* overlayed memory - such as decrypted KDBG.
* -- wcsFileName
* -- pb
* -- cb
* -- pcbWrite
* -- cbOffset
* -- return
*/
NTSTATUS MVmmVfsDump_Write(_In_ LPCWSTR wcsFileName, _In_reads_(cb) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbWrite, _In_ QWORD cbOffset)
{
    BOOL fResult;
    DWORD cbHeaderSize;
    if(!_wcsicmp(wcsFileName, L"\\memory.pmem")) {
        *pcbWrite = cb;
        fResult = VmmWrite(NULL, cbOffset, pb, cb);
        return fResult ? VMM_STATUS_SUCCESS : VMM_STATUS_FILE_SYSTEM_LIMITATION;
    }
    if(!_wcsicmp(wcsFileName, L"\\memory.dmp")) {
        *pcbWrite = cb;
        cbHeaderSize = ctxVmm->f32 ? 0x1000 : 0x2000;
        if(cbOffset + cb <= cbHeaderSize) {
            return VMM_STATUS_SUCCESS;
        }
        if(cbOffset < cbHeaderSize) {
            pb += (DWORD)(cbHeaderSize - cbOffset);
            cb -= (DWORD)(cbHeaderSize - cbOffset);
            cbOffset = cbHeaderSize;
        }
        fResult = VmmWrite(NULL, cbOffset, pb, cb);
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
VOID MVmmVfsDump_List(_Inout_ PHANDLE pFileList)
{
    VMMDLL_VfsList_AddFile(pFileList, "memory.pmem", ctxMain->dev.paMax);
    if(ctxVmm->kernel.dwVersionBuild >= 7600) {
        // Memory dump files compatible with WinDbg are supported on Win7 and later.
        VMMDLL_VfsList_AddFile(pFileList, "memory.dmp", ctxMain->dev.paMax + (ctxVmm->f32 ? 0x1000 : 0x2000));
    }
}
