// m_minidump.c : implementation of the minidump built-in module.
//
// (c) Ulf Frisk, 2020
// Author: Ulf Frisk, pcileech@frizk.net
//
#include "pluginmanager.h"
#include "pe.h"
#include "util.h"
#include "vmm.h"
#include "vmmdll.h"
#include "vmmwin.h"
#include "vmmwindef.h"
#include "vmmwinreg.h"
#include "version.h"
#include <DbgHelp.h>

#define M_MINIDUMP_DYNAMIC_DUMP_MAX_AGE_MS      30*1000

POB_MAP g_pmOb_MMINIDUMP_CONTEXT = NULL;

LPCSTR szMMINIDUMP_README =
"Information about the minidump module                                        \n" \
"=====================================                                        \n" \
"The minidump module generates a minidump.dmp .dmp file for processes.        \n" \
" Prerequisites:                                                              \n" \
"  - symbols from Microsoft symbol server must be downloaded and active.      \n" \
"  - process must be an active user-mode (non-kernel) process.                \n";

typedef struct tdOB_M_MINIDUMP_CONTEXT {
    OB ObHdr;
    DWORD cb;
    PBYTE pb;
    QWORD cbMemory;
    QWORD qwTimeUpdate;
    QWORD qwLastAccessTickCount64;
    struct {
        DWORD cb;
        DWORD rva;
        PMINIDUMP_HEADER p;
    } Head;
    struct {
        DWORD cb;
        DWORD rva;
        PMINIDUMP_DIRECTORY p;
    } Directory;
    struct {
        DWORD cb;
        DWORD rva;
        PMINIDUMP_THREAD_LIST p;
    } ThreadList;
    struct {
        DWORD cb;
        DWORD rva;
        PMINIDUMP_THREAD_INFO_LIST p1;
        PMINIDUMP_THREAD_INFO p2;
    } ThreadInfoList;
    struct {
        DWORD cb;
        DWORD rva;
        PMINIDUMP_MODULE_LIST p;
    } ModuleList;
    struct {
        DWORD cb;
        DWORD rva;
        PMINIDUMP_UNLOADED_MODULE_LIST p1;
        PMINIDUMP_UNLOADED_MODULE p2;
    } UnloadedModuleList;
    struct {
        DWORD cb;
        DWORD rva;
        PMINIDUMP_MEMORY64_LIST p;
    } MemoryList;
    struct {
        DWORD cb;
        DWORD rva;
        PMINIDUMP_MEMORY_INFO_LIST p1;
        PMINIDUMP_MEMORY_INFO p2;
    } MemoryInfoList;
    struct {
        DWORD cb;
        DWORD rva;
        PMINIDUMP_SYSTEM_INFO p;
    } SystemInfo;
    struct {
        DWORD cb;
        DWORD rva;
        PMINIDUMP_MISC_INFO_3 p;
    } MiscInfoStream;
    struct {
        DWORD cb;
        DWORD rva;
        PMINIDUMP_HANDLE_DATA_STREAM p;
    } HandleDataStream;
} OB_M_MINIDUMP_CONTEXT, *POB_M_MINIDUMP_CONTEXT;

#define MINIDUMP_BUFFER_INITIAL         0x01000000

// https://docs.microsoft.com/en-us/dotnet/api/system.diagnostics.process.priorityclass?view=netframework-4.8
UCHAR M_MiniDump_Initialize_GetThreadPriorityClass(PVMM_MAP_THREADENTRY peT)
{
    if(peT->bBasePriority == 4) { return 64; }
    if(peT->bBasePriority == 13) { return 128; }
    if(peT->bBasePriority == 24) { return (UCHAR)256; }
    return 32;
}

DWORD M_MiniDump_Initialize_AddBinary(_Inout_ POB_M_MINIDUMP_CONTEXT ctx, _In_ PBYTE pb, _In_ DWORD cb)
{
    ctx->cb = (ctx->cb + 3) & ~3;       // DWORD ALIGN START
    if((ctx->cb >> 23) || (cb >> 23)) { return 0; }
    memcpy(ctx->pb + ctx->cb, pb, cb);
    ctx->cb += cb;
    return ctx->cb - cb;
}

DWORD M_MiniDump_Initialize_AddText(_Inout_ POB_M_MINIDUMP_CONTEXT ctx, _In_ LPWSTR wszText)
{
    DWORD rva, cb;
    rva = ctx->cb;
    cb = (DWORD)(2 * wcslen(wszText));
    if((ctx->cb >> 23) || (cb >> 23)) { return 0; }
    *(PDWORD)(ctx->pb + ctx->cb) = cb;  // SET SIZE
    memcpy(ctx->pb + ctx->cb + 4, (PBYTE)wszText, cb);
    ctx->cb += 4 + cb + 2;
    return rva;
}

VOID M_MiniDump_Initialize_ThreadList_CpuContext32(_In_ PVMM_PROCESS pSystemProcess, _Inout_ POB_M_MINIDUMP_CONTEXT mdCtx, _In_ PVMM_MAP_THREADENTRY peT, _Inout_ PMINIDUMP_THREAD pmdT)
{
    CPU_CONTEXT32 ctx = { 0 };
    CPU_KTRAP_FRAME32 trap = { 0 };
    VmmReadEx(pSystemProcess, peT->vaTrapFrame, (PBYTE)&trap, sizeof(CPU_KTRAP_FRAME32), NULL, VMM_FLAG_ZEROPAD_ON_FAIL);
    ctx.Dr0 = trap.Dr0;
    ctx.Dr1 = trap.Dr1;
    ctx.Dr2 = trap.Dr2;
    ctx.Dr3 = trap.Dr3;
    ctx.Dr6 = trap.Dr6;
    ctx.Dr7 = trap.Dr7;
    ctx.SegGs = trap.SegGs;
    ctx.SegEs = trap.SegEs;
    ctx.SegDs = trap.SegDs;
    ctx.Edx = trap.Edx;
    ctx.Ecx = trap.Ecx;
    ctx.Eax = trap.Eax;
    ctx.SegFs = trap.SegFs;
    ctx.Edi = trap.Edi;
    ctx.Esi = trap.Esi;
    ctx.Ebx = trap.Ebx;
    ctx.Ebp = trap.Ebp;
    ctx.Eip = trap.Eip;
    ctx.SegCs = trap.SegCs;
    ctx.EFlags = trap.EFlags;
    ctx.Esp = trap.HardwareEsp;
    ctx.SegSs = trap.HardwareSegSs;
    pmdT->ThreadContext.DataSize = sizeof(CPU_CONTEXT32);
    pmdT->ThreadContext.Rva = M_MiniDump_Initialize_AddBinary(mdCtx, (PBYTE)&ctx, sizeof(CPU_CONTEXT32));
}

VOID M_MiniDump_Initialize_ThreadList_CpuContext64(_In_ PVMM_PROCESS pSystemProcess, _Inout_ POB_M_MINIDUMP_CONTEXT mdCtx, _In_ PVMM_MAP_THREADENTRY peT, _Inout_ PMINIDUMP_THREAD pmdT)
{
    CPU_CONTEXT64 ctx = { 0 };
    CPU_KTRAP_FRAME64 trap = { 0 };
    VmmReadEx(pSystemProcess, peT->vaTrapFrame, (PBYTE)&trap, sizeof(CPU_KTRAP_FRAME64), NULL, VMM_FLAG_ZEROPAD_ON_FAIL);
    ctx.P1Home = trap.P1Home;
    ctx.P2Home = trap.P2Home;
    ctx.P3Home = trap.P3Home;
    ctx.P4Home = trap.P4Home;
    ctx.P5Home = trap.P5;
    ctx.MxCsr = trap.MxCsr;
    ctx.SegCs = trap.SegCs;
    ctx.SegDs = trap.SegDs;
    ctx.SegEs = trap.SegEs;
    ctx.SegFs = trap.SegFs;
    ctx.SegGs = trap.SegGs;
    ctx.SegSs = trap.SegSs;
    ctx.EFlags = trap.EFlags;
    ctx.Dr0 = trap.Dr0;
    ctx.Dr1 = trap.Dr1;
    ctx.Dr2 = trap.Dr2;
    ctx.Dr3 = trap.Dr3;
    ctx.Dr6 = trap.Dr6;
    ctx.Dr7 = trap.Dr7;
    ctx.Rax = trap.Rax;
    ctx.Rcx = trap.Rcx;
    ctx.Rdx = trap.Rdx;
    ctx.Rbx = trap.Rbx;
    ctx.Rsp = trap.Rsp;
    ctx.Rbp = trap.Rbp;
    ctx.Rsi = trap.Rsi;
    ctx.Rdi = trap.Rdi;
    ctx.R8 = trap.R8;
    ctx.R9 = trap.R9;
    ctx.R10 = trap.R10;
    ctx.R11 = trap.R11;
    ctx.Rip = trap.Rip;
    ctx.Xmm0 = trap.Xmm0;
    ctx.Xmm1 = trap.Xmm1;
    ctx.Xmm2 = trap.Xmm2;
    ctx.Xmm3 = trap.Xmm3;
    ctx.Xmm4 = trap.Xmm4;
    ctx.Xmm5 = trap.Xmm5;
    pmdT->ThreadContext.DataSize = sizeof(CPU_CONTEXT64);
    pmdT->ThreadContext.Rva = M_MiniDump_Initialize_AddBinary(mdCtx, (PBYTE)&ctx, sizeof(CPU_CONTEXT64));
}

VOID M_MiniDump_CallbackCleanup_ObMiniDumpContext(POB_M_MINIDUMP_CONTEXT pOb)
{
    LocalFree(pOb->pb);
}

/*
* Create a new minidump context for the given process.
* CALLER DECREF: return
* -- pProcess
* -- return
*/
POB_M_MINIDUMP_CONTEXT M_MiniDump_Initialize_Internal(_In_ PVMM_PROCESS pProcess)
{
    BOOL f, f32 = ctxVmm->f32;
    DWORD i, j, iPte, iVad, iMR, dwCpuMhz, cThreadActive = 0;
    QWORD qw;
    PVMM_PROCESS pObSystemProcess = NULL;
    POB_M_MINIDUMP_CONTEXT ctx = NULL;
    PMINIDUMP_THREAD pmdT;
    PMINIDUMP_THREAD_INFO pmdTI;
    PVMMOB_MAP_THREAD pObThreadMap = NULL;
    PVMM_MAP_THREADENTRY peT;
    PMINIDUMP_MODULE pmdM;
    PVMMOB_MAP_MODULE pObModuleMap = NULL;
    PMINIDUMP_UNLOADED_MODULE pmdU;
    PVMM_MAP_UNLOADEDMODULEENTRY peU;
    PVMMOB_MAP_UNLOADEDMODULE pObUnloadedModuleMap = NULL;
    PVMM_MAP_MODULEENTRY peM;
    POB_SET psObPrefetch = NULL;
    PE_CODEVIEW_INFO CodeViewInfo;
    PVMMOB_MAP_PTE pObPteMap = NULL;
    PVMMOB_MAP_VAD pObVadMap = NULL;
    PVMM_MAP_PTEENTRY peP;
    PVMM_MAP_VADENTRY peV;
    PMINIDUMP_MEMORY_DESCRIPTOR64 pmdMR;
    PMINIDUMP_MEMORY_INFO pmdMI, pmdMIprev;
    WCHAR wszComment[0x80];
    // initialization
    if(!(psObPrefetch = ObSet_New())) { goto fail; }
    if(!(pObSystemProcess = VmmProcessGet(4))) { goto fail; }
    if(!VmmMap_GetPte(pProcess, &pObPteMap, FALSE) || !pObPteMap->cMap || (pObPteMap->cMap > 0x4000)) { goto fail; }
    if(!VmmMap_GetVad(pProcess, &pObVadMap, VMM_VADMAP_TP_FULL) || !pObVadMap->cMap || (pObVadMap->cMap > 0x1000)) { goto fail; }
    if(!VmmMap_GetThread(pProcess, &pObThreadMap) || !pObThreadMap->cMap || (pObThreadMap->cMap > 0x4000)) { goto fail; }
    if(!VmmMap_GetModule(pProcess, &pObModuleMap) || !pObModuleMap->cMap || (pObModuleMap->cMap > 0x4000)) { goto fail; }
    if(!VmmMap_GetUnloadedModule(pProcess, &pObUnloadedModuleMap)) { goto fail; }
    if(!(ctx = Ob_Alloc(OB_TAG_MOD_MINIDUMP_CTX, LMEM_ZEROINIT, sizeof(OB_M_MINIDUMP_CONTEXT), M_MiniDump_CallbackCleanup_ObMiniDumpContext, NULL))) { goto fail; }
    if(!(ctx->pb = LocalAlloc(LMEM_ZEROINIT, MINIDUMP_BUFFER_INITIAL))) { goto fail; }
    _snwprintf_s(
        wszComment,
        _countof(wszComment),
        _countof(wszComment),
        L"[ Dump file generated by MemProcFS v%i.%i.%i-%i - The Memory Process File System - https://github.com/ufrisk/MemProcFS ]",
        VERSION_MAJOR,
        VERSION_MINOR,
        VERSION_REVISION,
        VERSION_BUILD);
    for(i = 0; i < pObThreadMap->cMap; i++) {   // avoid finished threads
        if(!pObThreadMap->pMap[i].ftExitTime) {
            cThreadActive++;
        }
    }

    // allocate: MINIDUMP_HEADER
    ctx->Head.cb = sizeof(MINIDUMP_HEADER);
    ctx->Head.rva = ctx->cb;
    ctx->Head.p = (PMINIDUMP_HEADER)(ctx->pb + ctx->Head.rva);
    ctx->cb += ctx->Head.cb;

    // allocate: MINIDUMP_DIRECTORY
    ctx->Directory.cb = 11 * sizeof(MINIDUMP_DIRECTORY);
    ctx->Directory.rva = ctx->cb;
    ctx->Directory.p = (PMINIDUMP_DIRECTORY)(ctx->pb + ctx->Directory.rva);
    ctx->cb += ctx->Directory.cb;

    // allocate: MINIDUMP_SYSTEM_INFO
    ctx->SystemInfo.cb = sizeof(MINIDUMP_SYSTEM_INFO);
    ctx->SystemInfo.rva = ctx->cb;
    ctx->SystemInfo.p = (PMINIDUMP_SYSTEM_INFO)(ctx->pb + ctx->SystemInfo.rva);
    ctx->cb += ctx->SystemInfo.cb;

    // allocate: MINIDUMP_MISC_INFO_3
    ctx->MiscInfoStream.cb = sizeof(MINIDUMP_MISC_INFO_3);
    ctx->MiscInfoStream.rva = ctx->cb;
    ctx->MiscInfoStream.p = (PMINIDUMP_MISC_INFO_3)(ctx->pb + ctx->MiscInfoStream.rva);
    ctx->cb += ctx->MiscInfoStream.cb;

    // allocate: MINIDUMP_THREAD_LIST
    ctx->ThreadList.cb = sizeof(MINIDUMP_THREAD_LIST) + cThreadActive * sizeof(MINIDUMP_THREAD);
    ctx->ThreadList.rva = ctx->cb;
    ctx->ThreadList.p = (PMINIDUMP_THREAD_LIST)(ctx->pb + ctx->ThreadList.rva);
    ctx->cb += ctx->ThreadList.cb;

    // allocate: MINIDUMP_THREAD_INFO_LIST
    ctx->ThreadInfoList.cb = sizeof(MINIDUMP_THREAD_INFO_LIST) + cThreadActive * sizeof(MINIDUMP_THREAD_INFO);
    ctx->ThreadInfoList.rva = ctx->cb;
    ctx->ThreadInfoList.p1 = (PMINIDUMP_THREAD_INFO_LIST)(ctx->pb + ctx->ThreadInfoList.rva);
    ctx->ThreadInfoList.p2 = (PMINIDUMP_THREAD_INFO)((QWORD)ctx->ThreadInfoList.p1 + sizeof(MINIDUMP_THREAD_INFO_LIST));
    ctx->cb += ctx->ThreadInfoList.cb;

    // allocate: MINIDUMP_MODULE_LIST
    ctx->ModuleList.cb = sizeof(MINIDUMP_MODULE_LIST) + pObModuleMap->cMap * sizeof(MINIDUMP_MODULE);
    ctx->ModuleList.rva = ctx->cb;
    ctx->ModuleList.p = (PMINIDUMP_MODULE_LIST)(ctx->pb + ctx->ModuleList.rva);
    ctx->cb += ctx->ModuleList.cb;

    // allocate: MINIDUMP_UNLOADED_MODULE_LIST
    ctx->UnloadedModuleList.cb = sizeof(MINIDUMP_UNLOADED_MODULE_LIST) + pObUnloadedModuleMap->cMap * sizeof(MINIDUMP_UNLOADED_MODULE);
    ctx->UnloadedModuleList.rva = ctx->cb;
    ctx->UnloadedModuleList.p1 = (PMINIDUMP_UNLOADED_MODULE_LIST)(ctx->pb + ctx->UnloadedModuleList.rva);
    ctx->UnloadedModuleList.p2 = (PMINIDUMP_UNLOADED_MODULE)((QWORD)ctx->UnloadedModuleList.p1 + sizeof(MINIDUMP_UNLOADED_MODULE_LIST));
    ctx->cb += ctx->UnloadedModuleList.cb;

    // populate: MINIDUMP_MISC_INFO_3
    {
        ctx->MiscInfoStream.p->SizeOfInfo = sizeof(MINIDUMP_MISC_INFO_3);
        ctx->MiscInfoStream.p->Flags1 = MINIDUMP_MISC1_PROCESS_ID | MINIDUMP_MISC1_PROCESS_TIMES;
        ctx->MiscInfoStream.p->ProcessId = pProcess->dwPID;
        ctx->MiscInfoStream.p->ProcessCreateTime = (DWORD)((*(PQWORD)(pProcess->win.EPROCESS.pb + ctxVmm->offset.EPROCESS.opt.CreateTime) - 11644473600000 * 10000) / 10000000);
        ctx->MiscInfoStream.p->ProcessUserTime = *(PDWORD)(pProcess->win.EPROCESS.pb + ctxVmm->offset.EPROCESS.opt.UserTime);
        ctx->MiscInfoStream.p->ProcessKernelTime = *(PDWORD)(pProcess->win.EPROCESS.pb + ctxVmm->offset.EPROCESS.opt.KernelTime);
        if(VmmWinReg_ValueQuery2(L"HKLM\\HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0\\~MHz", NULL, (PBYTE)&dwCpuMhz, sizeof(DWORD), NULL)) {
            ctx->MiscInfoStream.p->Flags1 = ctx->MiscInfoStream.p->Flags1 | MINIDUMP_MISC1_PROCESSOR_POWER_INFO;
            ctx->MiscInfoStream.p->ProcessorMaxMhz = dwCpuMhz;
            ctx->MiscInfoStream.p->ProcessorCurrentMhz = dwCpuMhz;
            ctx->MiscInfoStream.p->ProcessorMhzLimit = dwCpuMhz;
            ctx->MiscInfoStream.p->ProcessorMaxIdleState = 2;       // DUMMY VALUE
            ctx->MiscInfoStream.p->ProcessorCurrentIdleState = 2;   // DUMMY VALUE
        }
        // TODO: ADD TIMEZONE INFO AND OTHER MISC INFO
    }

    // populate: MINIDUMP_SYSTEM_INFO
    {
        ctx->SystemInfo.p->ProcessorArchitecture = (f32 ? PROCESSOR_ARCHITECTURE_INTEL : PROCESSOR_ARCHITECTURE_AMD64);
        ctx->SystemInfo.p->ProcessorLevel = 0;
        ctx->SystemInfo.p->ProcessorRevision = 0x31;
        ctx->SystemInfo.p->NumberOfProcessors = (UCHAR)ctxVmm->kernel.opt.cCPUs;
        ctx->SystemInfo.p->ProductType = VER_NT_WORKSTATION;
        ctx->SystemInfo.p->MajorVersion = ctxVmm->kernel.dwVersionMajor;
        ctx->SystemInfo.p->MinorVersion = ctxVmm->kernel.dwVersionMinor;
        ctx->SystemInfo.p->BuildNumber = ctxVmm->kernel.dwVersionBuild;
        ctx->SystemInfo.p->PlatformId = VER_PLATFORM_WIN32_NT;
        ctx->SystemInfo.p->CSDVersionRva = M_MiniDump_Initialize_AddText(ctx, wszComment);
        ctx->SystemInfo.p->SuiteMask = 0;
        //ctx->SystemInfo.p->Cpu ...    // TODO:
    }

    // populate: MINIDUMP_MODULE_LIST #1 - CORE
    {
        WCHAR wszDEBUG[MAX_PATH] = { 0 };

        ctx->ModuleList.p->NumberOfModules = pObModuleMap->cMap;
        for(i = 0; i < pObModuleMap->cMap; i++) {
            peM = &pObModuleMap->pMap[i];
            pmdM = &ctx->ModuleList.p->Modules[i];
            pmdM->BaseOfImage = peM->vaBase;
            pmdM->SizeOfImage = peM->cbImageSize;
            PE_GetTimeDateStampCheckSum(pProcess, peM->vaBase, &pmdM->TimeDateStamp, &pmdM->CheckSum);
            pmdM->ModuleNameRva = M_MiniDump_Initialize_AddText(ctx, peM->wszFullName);
            //pmdM->VersionInfo. ...    // TODO:
            //pmdM->CvRecord            // ADDED LATER
            pmdM->MiscRecord.DataSize = 0;
            pmdM->MiscRecord.Rva = 0;
        }
    }

    // populate: MINIDUMP_UNLOADED_MODULE_LIST
    {
        ctx->ThreadInfoList.p1->SizeOfHeader = sizeof(MINIDUMP_UNLOADED_MODULE_LIST);
        ctx->ThreadInfoList.p1->SizeOfEntry = sizeof(MINIDUMP_UNLOADED_MODULE);
        ctx->ThreadInfoList.p1->NumberOfEntries = pObUnloadedModuleMap->cMap;
        for(i = 0; i < pObUnloadedModuleMap->cMap; i++) {
            peU = &pObUnloadedModuleMap->pMap[i];
            pmdU = &ctx->UnloadedModuleList.p2[i];
            pmdU->BaseOfImage = peU->vaBase;
            pmdU->CheckSum = peU->dwCheckSum;
            pmdU->SizeOfImage = peU->cbImageSize;
            pmdU->TimeDateStamp = peU->dwTimeDateStamp;
            pmdU->ModuleNameRva = M_MiniDump_Initialize_AddText(ctx, peU->wszText);
        }
    }

    // populate: MINIDUMP_THREAD_INFO_LIST
    {
        ctx->ThreadInfoList.p1->SizeOfHeader = sizeof(MINIDUMP_THREAD_INFO_LIST);
        ctx->ThreadInfoList.p1->SizeOfEntry = sizeof(MINIDUMP_THREAD_INFO);
        ctx->ThreadInfoList.p1->NumberOfEntries = cThreadActive;
        for(i = 0, j = 0; i < pObThreadMap->cMap; i++) {
            if((peT = &pObThreadMap->pMap[i])->ftExitTime) { continue; }
            pmdTI = &ctx->ThreadInfoList.p2[j++];
            pmdTI->ThreadId = peT->dwTID;
            pmdTI->DumpFlags = (peT->ftExitTime ? MINIDUMP_THREAD_INFO_EXITED_THREAD : 0);
            pmdTI->DumpError = S_OK;
            pmdTI->ExitStatus = peT->dwExitStatus;
            pmdTI->CreateTime = peT->ftCreateTime;
            pmdTI->ExitTime = peT->ftExitTime;
            pmdTI->KernelTime = peT->dwKernelTime;
            pmdTI->UserTime = peT->dwUserTime;
            pmdTI->StartAddress = peT->vaStartAddress;
            pmdTI->Affinity = peT->qwAffinity;
        }
    }

    // populate: MINIDUMP_THREAD_LIST
    {
        ctx->ThreadList.p->NumberOfThreads = cThreadActive;
        for(i = 0, j = 0; i < pObThreadMap->cMap; i++) {
            if((peT = &pObThreadMap->pMap[i])->ftExitTime) { continue; }
            pmdT = &ctx->ThreadList.p->Threads[j++];
            pmdT->ThreadId = peT->dwTID;
            pmdT->SuspendCount = peT->bSuspendCount;
            pmdT->PriorityClass = M_MiniDump_Initialize_GetThreadPriorityClass(peT);
            pmdT->Priority = peT->bPriority;
            if(!peT->ftExitTime) {
                pmdT->Teb = peT->vaTeb;
                if((peT->vaStackBaseUser > peT->vaRSP) && (peT->vaStackLimitUser < peT->vaRSP)) {
                    pmdT->Stack.StartOfMemoryRange = peT->vaRSP;
                    pmdT->Stack.Memory.DataSize = (DWORD)(peT->vaStackBaseUser - peT->vaRSP);
                    ObSet_Push(psObPrefetch, peT->vaTrapFrame);
                }
            }
        }
        VmmCachePrefetchPages3(pObSystemProcess, psObPrefetch, sizeof(CPU_KTRAP_FRAME64), 0);
        ObSet_Clear(psObPrefetch);
        for(i = 0, j = 0; i < pObThreadMap->cMap; i++) {
            if((peT = &pObThreadMap->pMap[i])->ftExitTime) { continue; }
            pmdT = &ctx->ThreadList.p->Threads[j++];
            if(pmdT->Stack.StartOfMemoryRange) {
                if(f32) {
                    M_MiniDump_Initialize_ThreadList_CpuContext32(pObSystemProcess, ctx, peT, pmdT);
                } else {
                    M_MiniDump_Initialize_ThreadList_CpuContext64(pObSystemProcess, ctx, peT, pmdT);
                }
            }
        }
    }

    // populate: MINIDUMP_MODULE_LIST #2 - CODEVIEW PDB DEBUG INFO
    {
        for(i = 0; i < ctx->ModuleList.p->NumberOfModules; i++) {
            pmdM = &ctx->ModuleList.p->Modules[i];
            if(PE_GetCodeViewInfo(pProcess, pmdM->BaseOfImage, NULL, &CodeViewInfo)) {
                pmdM->CvRecord.DataSize = CodeViewInfo.SizeCodeView;
                pmdM->CvRecord.Rva = M_MiniDump_Initialize_AddBinary(ctx, (PBYTE)&CodeViewInfo.CodeView, CodeViewInfo.SizeCodeView);
            }
        }
    }

    // populate: MINIDUMP_UNLOADED_MODULE_LIST
    {
        ctx->UnloadedModuleList.p1->SizeOfHeader = sizeof(MINIDUMP_UNLOADED_MODULE_LIST);
        ctx->UnloadedModuleList.p1->SizeOfEntry = sizeof(MINIDUMP_UNLOADED_MODULE);
        ctx->UnloadedModuleList.p1->NumberOfEntries = 0;
    }

    // allocate: MINIDUMP_HANDLE_DATA_STREAM
    {
        ctx->HandleDataStream.cb = sizeof(MINIDUMP_HANDLE_DATA_STREAM);
        ctx->HandleDataStream.rva = ctx->cb;
        ctx->HandleDataStream.p = (PMINIDUMP_HANDLE_DATA_STREAM)(ctx->pb + ctx->HandleDataStream.rva);
        ctx->cb += ctx->HandleDataStream.cb;
    }

    // allocate: MINIDUMP_MEMORY_INFO_LIST
    {
        ctx->MemoryInfoList.cb = sizeof(MINIDUMP_MEMORY_INFO_LIST) + pObPteMap->cMap * sizeof(MINIDUMP_MEMORY_INFO);
        ctx->MemoryInfoList.rva = ctx->cb;
        ctx->MemoryInfoList.p1 = (PMINIDUMP_MEMORY_INFO_LIST)(ctx->pb + ctx->MemoryInfoList.rva);
        ctx->MemoryInfoList.p2 = (PMINIDUMP_MEMORY_INFO)((QWORD)ctx->MemoryInfoList.p1 + sizeof(MINIDUMP_MEMORY_INFO_LIST));
        ctx->cb += ctx->MemoryInfoList.cb;
    }

    // prefill: MINIDUMP_MEMORY64_LIST
    {
        ctx->MemoryList.cb = sizeof(MINIDUMP_MEMORY64_LIST) + pObPteMap->cMap * sizeof(MINIDUMP_MEMORY_DESCRIPTOR64);
        ctx->MemoryList.rva = ctx->cb;
        ctx->MemoryList.p = (PMINIDUMP_MEMORY64_LIST)(ctx->pb + ctx->MemoryList.rva);
        ctx->cb += ctx->MemoryList.cb;
    }

    // populate: MINIDUMP_HANDLE_DATA_STREAM
    // handle data stream is populated empty, creating a minidump in
    // taskmgr.exe seems to be doing this and it works ...
    {
        ctx->HandleDataStream.p->SizeOfHeader = sizeof(MINIDUMP_HANDLE_DATA_STREAM);
        ctx->HandleDataStream.p->SizeOfDescriptor = sizeof(MINIDUMP_HANDLE_DESCRIPTOR_2);
        ctx->HandleDataStream.p->NumberOfDescriptors = 0;
    }

    // populate: MINIDUMP_MEMORY64_LIST & MINIDUMP_MEMORY_INFO_LIST
    {
        //ctx->MemoryList.p->BaseRva =      // ADDED LATER
        ctx->MemoryList.p->NumberOfMemoryRanges = pObPteMap->cMap;
        ctx->MemoryInfoList.p1->SizeOfHeader = sizeof(MINIDUMP_MEMORY_INFO_LIST);
        ctx->MemoryInfoList.p1->SizeOfEntry = sizeof(MINIDUMP_MEMORY_INFO);
        ctx->MemoryInfoList.p1->NumberOfEntries = pObPteMap->cMap;
        for(iPte = 0, iVad = 0, iMR = 0; iPte < pObPteMap->cMap; iPte++, iMR++) {
            pmdMR = &ctx->MemoryList.p->MemoryRanges[iMR];
            pmdMI = &ctx->MemoryInfoList.p2[iMR];
            peP = &pObPteMap->pMap[iPte];
            // get matching vad entry
            while(TRUE) {
                peV = &pObVadMap->pMap[iVad];
                if(peV->vaEnd < peP->vaBase) {
                    if(iVad < pObPteMap->cMap - 1) {
                        iVad++;
                        continue;
                    }
                    peV = NULL;
                    break;
                }
                if((peP->vaBase + (peP->cPages << 12) - 1) > peV->vaEnd) { peV = NULL; }
                break;
            }
            // set initial range
            pmdMR->StartOfMemoryRange = peP->vaBase;
            pmdMR->DataSize = peP->cPages << 12;
            // adjust range (in case of non mapped pte's in vad image)
            if(peV && peV->fImage) {
                f = i && (pmdMR->StartOfMemoryRange > peV->vaStart) &&
                    (pmdMR->StartOfMemoryRange > ctx->MemoryList.p->MemoryRanges[iMR - 1].StartOfMemoryRange + ctx->MemoryList.p->MemoryRanges[iMR - 1].DataSize);
                if(f) {
                    // adjust downwards
                    qw = pmdMR->StartOfMemoryRange - max(peV->vaStart, ctx->MemoryList.p->MemoryRanges[iMR - 1].StartOfMemoryRange + ctx->MemoryList.p->MemoryRanges[iMR - 1].DataSize);
                    pmdMR->StartOfMemoryRange -= qw;
                    pmdMR->DataSize += qw;
                }
                f = (iPte < pObPteMap->cMap - 1) && 
                    (iMR < ctx->MemoryList.p->NumberOfMemoryRanges - 1) &&
                    (pmdMR->StartOfMemoryRange + pmdMR->DataSize < peV->vaEnd) &&
                    (peV->vaEnd < pObPteMap->pMap[iPte + 1].vaBase);
                if(f) {
                    // adjust upwards
                    qw = min(0x00400000, peV->vaEnd + 1 - (pmdMR->StartOfMemoryRange + pmdMR->DataSize));
                    pmdMR->DataSize += qw;
                }
            }
            pmdMI->BaseAddress = pmdMR->StartOfMemoryRange;
            pmdMI->AllocationBase = pmdMR->StartOfMemoryRange;
            pmdMI->AllocationProtect = (peP->fPage & VMM_MEMMAP_PAGE_NX) ? ((peP->fPage & VMM_MEMMAP_PAGE_W) ? PAGE_READWRITE : PAGE_READONLY) : ((peP->fPage & VMM_MEMMAP_PAGE_W) ? PAGE_EXECUTE_READWRITE : PAGE_EXECUTE_READ);
            pmdMI->RegionSize = pmdMR->DataSize;
            pmdMI->State = MEM_COMMIT;
            pmdMI->Protect = pmdMI->AllocationProtect;
            pmdMI->Type = (peV && peV->fImage) ? MEM_IMAGE : ((peV && peV->fFile) ? MEM_MAPPED : MEM_PRIVATE);
            ctx->cbMemory += pmdMR->DataSize;
            // merge with previous range if possible
            if(peV && peV->fImage && iMR) {
                pmdMIprev = &ctx->MemoryInfoList.p2[iMR - 1];
                if((pmdMI->AllocationProtect == pmdMIprev->AllocationProtect) && (pmdMI->BaseAddress == pmdMIprev->BaseAddress + pmdMIprev->RegionSize) && (pmdMI->Type == pmdMIprev->Type)){
                    pmdMIprev->RegionSize += pmdMI->RegionSize;
                    ctx->MemoryInfoList.p1->NumberOfEntries--;
                    ctx->MemoryList.p->MemoryRanges[iMR - 1].DataSize += pmdMR->DataSize;
                    ctx->MemoryList.p->NumberOfMemoryRanges--;
                    iMR--;

                    ctx->MemoryList.cb -= sizeof(MINIDUMP_MEMORY_DESCRIPTOR64);
                    ctx->MemoryInfoList.cb -= sizeof(MINIDUMP_MEMORY_INFO);
                }
            }
        }
    }

    // populate: MINIDUMP_DIRECTORY
    {
        i = 0;
        ctx->Directory.p[i].StreamType = ThreadListStream;
        ctx->Directory.p[i].Location.DataSize = ctx->ThreadList.cb;
        ctx->Directory.p[i].Location.Rva = ctx->ThreadList.rva;
        i++;
        ctx->Directory.p[i].StreamType = ThreadInfoListStream;
        ctx->Directory.p[i].Location.DataSize = ctx->ThreadInfoList.cb;
        ctx->Directory.p[i].Location.Rva = ctx->ThreadInfoList.rva;
        i++;
        ctx->Directory.p[i].StreamType = ModuleListStream;
        ctx->Directory.p[i].Location.DataSize = ctx->ModuleList.cb;
        ctx->Directory.p[i].Location.Rva = ctx->ModuleList.rva;
        i++;
        ctx->Directory.p[i].StreamType = UnloadedModuleListStream;
        ctx->Directory.p[i].Location.DataSize = ctx->UnloadedModuleList.cb;
        ctx->Directory.p[i].Location.Rva = ctx->UnloadedModuleList.rva;
        i++;
        ctx->Directory.p[i].StreamType = Memory64ListStream;
        ctx->Directory.p[i].Location.DataSize = ctx->MemoryList.cb;
        ctx->Directory.p[i].Location.Rva = ctx->MemoryList.rva;
        i++;
        ctx->Directory.p[i].StreamType = MemoryInfoListStream;
        ctx->Directory.p[i].Location.DataSize = ctx->MemoryInfoList.cb;
        ctx->Directory.p[i].Location.Rva = ctx->MemoryInfoList.rva;
        i++;
        ctx->Directory.p[i].StreamType = SystemInfoStream;
        ctx->Directory.p[i].Location.DataSize = ctx->SystemInfo.cb;
        ctx->Directory.p[i].Location.Rva = ctx->SystemInfo.rva;
        i++;
        ctx->Directory.p[i].StreamType = MiscInfoStream;
        ctx->Directory.p[i].Location.DataSize = ctx->MiscInfoStream.cb;
        ctx->Directory.p[i].Location.Rva = ctx->MiscInfoStream.rva;
        i++;
        ctx->Directory.p[i].StreamType = HandleDataStream;
        ctx->Directory.p[i].Location.DataSize = ctx->HandleDataStream.cb;
        ctx->Directory.p[i].Location.Rva = ctx->HandleDataStream.rva;
        i++;
    }

    // populate: MINIDUMP_HEADER
    {
        ctx->Head.p->Signature = 'PMDM';
        ctx->Head.p->Version = 0x64B1A793;
        ctx->Head.p->NumberOfStreams = ctx->Directory.cb / sizeof(MINIDUMP_DIRECTORY);
        ctx->Head.p->StreamDirectoryRva = ctx->Directory.rva;
        ctx->Head.p->CheckSum = 0;
        ctx->Head.p->TimeDateStamp = ctx->MiscInfoStream.p->ProcessCreateTime;
        ctx->Head.p->Flags = MiniDumpWithFullMemory | MiniDumpWithHandleData | MiniDumpWithUnloadedModules | MiniDumpWithFullMemoryInfo | MiniDumpWithThreadInfo;
    }

    // adjust backing buffer size and set BaseRVA for memory regions
    ctx->cb = (ctx->cb + 0xfff) & ~0xfff;
    ctx->MemoryList.p->BaseRva = ctx->cb;
    if(ctx->pb != LocalReAlloc(ctx->pb, ctx->cb, LMEM_FIXED)) { goto fail; }

    // set update time (used for file time stamp)
    ctx->qwLastAccessTickCount64 = GetTickCount64();
    if(ctxMain->dev.fVolatile || !(ctx->qwTimeUpdate = VmmProcess_GetCreateTimeOpt(pProcess))) {
        GetSystemTimeAsFileTime((LPFILETIME)&ctx->qwTimeUpdate);
    }

    // finish
    Ob_INCREF(ctx);
fail:
    Ob_DECREF(pObSystemProcess);
    Ob_DECREF(pObPteMap);
    Ob_DECREF(pObVadMap);
    Ob_DECREF(psObPrefetch);
    Ob_DECREF(pObThreadMap);
    Ob_DECREF(pObModuleMap);
    Ob_DECREF(pObUnloadedModuleMap);
    return Ob_DECREF(ctx);
}

/*
* Retrieve minidump context for the given process.
* CALLER DECREF: return
* -- pProcess
* -- return
*/
POB_M_MINIDUMP_CONTEXT M_MiniDump_GetContext(_In_ PVMM_PROCESS pProcess)
{
    POB_M_MINIDUMP_CONTEXT pObCtx = NULL;
    QWORD qwKey = (QWORD)pProcess->dwPID;
    if(!pProcess->fUserOnly) { return NULL; }
    if((pObCtx = ObMap_GetByKey(g_pmOb_MMINIDUMP_CONTEXT, qwKey))) {
        if(!ctxMain->dev.fVolatile || pObCtx->qwLastAccessTickCount64 + M_MINIDUMP_DYNAMIC_DUMP_MAX_AGE_MS > GetTickCount64()) {
            goto finish;
        }
        // ctx is aged out
        ObMap_RemoveByKey(g_pmOb_MMINIDUMP_CONTEXT, qwKey);
        Ob_DECREF_NULL(&pObCtx);
    }
    EnterCriticalSection(&pProcess->LockPlugin);
    if(!(pObCtx = ObMap_GetByKey(g_pmOb_MMINIDUMP_CONTEXT, qwKey))) {
        if((pObCtx = M_MiniDump_Initialize_Internal(pProcess))) {
            ObMap_Push(g_pmOb_MMINIDUMP_CONTEXT, qwKey, pObCtx);
        }
    }
    LeaveCriticalSection(&pProcess->LockPlugin);
finish:
    if(pObCtx) {
        pObCtx->qwLastAccessTickCount64 = GetTickCount64();
    }
    return pObCtx;
}

_Success_(return == STATUS_SUCCESS)
NTSTATUS M_MiniDump_ReadMiniDump(_In_ PVMM_PROCESS pProcess, _Out_writes_to_(cb, *pcbRead) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset)
{
    DWORD i, cbHead = 0, cbReadMem = 0, dwIntraSize;
    QWORD cbBase = 0, cbIntraOffset;
    PMINIDUMP_MEMORY_DESCRIPTOR64 pmd;
    POB_M_MINIDUMP_CONTEXT pObMiniDump = NULL;
    if(!(pObMiniDump = M_MiniDump_GetContext(pProcess))) { return VMMDLL_STATUS_FILE_INVALID; }
    // read minidmump header
    if(cbOffset < pObMiniDump->cb) {
        cbHead = min(cb, pObMiniDump->cb - (DWORD)cbOffset);
        memcpy(pb, pObMiniDump->pb + cbOffset, cbHead);
        pb += cbHead;
        cb -= cbHead;
        cbOffset += cbHead;
    }
    if(cb == 0) { goto finish; }
    cbOffset -= pObMiniDump->cb;
    // read memory
    for(i = 0; i < pObMiniDump->MemoryList.p->NumberOfMemoryRanges; i++) {
        pmd = &pObMiniDump->MemoryList.p->MemoryRanges[i];
        if(i) {
            cbBase += pObMiniDump->MemoryList.p->MemoryRanges[i - 1].DataSize;
        }
        if(cbBase + pmd->DataSize <= cbOffset) { continue; }
        if(cbBase >= cbOffset + cbReadMem + cb) { break; }
        cbIntraOffset = (cbBase < cbOffset) ? cbOffset - cbBase : 0;
        dwIntraSize = (DWORD)min(cb, pmd->DataSize - cbIntraOffset);
        VmmReadEx(pProcess, pmd->StartOfMemoryRange + cbIntraOffset, pb, dwIntraSize, NULL, VMM_FLAG_ZEROPAD_ON_FAIL);
        cbReadMem += dwIntraSize;
        pb += dwIntraSize;
        cb -= dwIntraSize;
        if(cb == 0) { break; }
    }
finish:
    if(pcbRead) { *pcbRead = cbHead + cbReadMem; }
    Ob_DECREF(pObMiniDump);
    return VMM_STATUS_SUCCESS;
}

_Success_(return == STATUS_SUCCESS)
NTSTATUS M_MiniDump_Read(_In_ PVMMDLL_PLUGIN_CONTEXT ctx, _Out_ PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset)
{
    if(!wcscmp(ctx->wszPath, L"readme.txt")) {
        return Util_VfsReadFile_FromPBYTE((PBYTE)szMMINIDUMP_README, strlen(szMMINIDUMP_README), pb, cb, pcbRead, cbOffset);
    }
    if(!wcscmp(ctx->wszPath, L"minidump.dmp")) {
        return M_MiniDump_ReadMiniDump(ctx->pProcess, pb, cb, pcbRead, cbOffset);
    }
    return VMMDLL_STATUS_FILE_INVALID;
}

BOOL M_MiniDump_List(_In_ PVMMDLL_PLUGIN_CONTEXT ctx, _Inout_ PHANDLE pFileList)
{
    VMMDLL_VFS_FILELIST_EXINFO ExInfo = { 0 };
    POB_M_MINIDUMP_CONTEXT pObMiniDump = NULL;
    if(ctx->wszPath[0]) { return FALSE; }
    VMMDLL_VfsList_AddFile(pFileList, L"readme.txt", strlen(szMMINIDUMP_README), NULL);
    if((pObMiniDump = M_MiniDump_GetContext(ctx->pProcess))) {
        ExInfo.dwVersion = VMMDLL_VFS_FILELIST_EXINFO_VERSION;
        ExInfo.qwCreationTime = ExInfo.qwLastAccessTime = ExInfo.qwLastWriteTime = pObMiniDump->qwTimeUpdate;
        VMMDLL_VfsList_AddFile(pFileList, L"minidump.dmp", pObMiniDump->cb + pObMiniDump->cbMemory, &ExInfo);
        Ob_DECREF_NULL(&pObMiniDump);
    }
    return TRUE;
}

VOID M_MiniDump_Close()
{
    Ob_DECREF_NULL(&g_pmOb_MMINIDUMP_CONTEXT);
}

/*
* Initialization function. The module manager shall call into this function
* when the module shall be initialized. If the module wish to initialize it
* shall call the supplied pfnPluginManager_Register function.
* NB! the module does not have to register itself - for example if the target
* operating system or architecture is unsupported.
* -- pPluginRegInfo
*/
VOID M_MiniDump_Initialize(_Inout_ PVMMDLL_PLUGIN_REGINFO pRI)
{
    if((pRI->magic != VMMDLL_PLUGIN_REGINFO_MAGIC) || (pRI->wVersion != VMMDLL_PLUGIN_REGINFO_VERSION)) { return; }
    if(!((pRI->tpSystem == VMM_SYSTEM_WINDOWS_X64) || (pRI->tpSystem == VMM_SYSTEM_WINDOWS_X86))) { return; }
    if(!(g_pmOb_MMINIDUMP_CONTEXT = ObMap_New(OB_MAP_FLAGS_OBJECT_OB))) { return; }
    wcscpy_s(pRI->reg_info.wszPathName, 128, L"\\minidump");              // module name
    pRI->reg_info.fRootModule = FALSE;                                    // module shows in root directory
    pRI->reg_info.fProcessModule = TRUE;                                  // module shows in process directory
    pRI->reg_fn.pfnList = M_MiniDump_List;                                // List function supported
    pRI->reg_fn.pfnRead = M_MiniDump_Read;                                // Read function supported
    pRI->reg_fn.pfnClose = M_MiniDump_Close;                              // Close function supported
    pRI->pfnPluginManager_Register(pRI);
}
