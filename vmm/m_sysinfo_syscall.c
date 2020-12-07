// m_sysinfo_syscall.c : implementation related to the SysInfo/Syscall built-in module.
//
// The SysInfo/Syscall module is responsible for displaying the Windows syscall table
// a.k.a. the System Service Dispatch Table.
//
// (c) Ulf Frisk, 2020
// Author: Ulf Frisk, pcileech@frizk.net
//
#include "pluginmanager.h"
#include "vmm.h"
#include "pdb.h"
#include "util.h"

PVOID g_MSYSCALL_CONTEXT = NULL;

typedef struct tdKSERVICE_DESCRIPTOR_TABLE32 {
    DWORD ServiceTableBase;
    DWORD ServiceCounterTableBase;
    DWORD NumberOfServices;
    DWORD ParamTableBase;
} KSERVICE_DESCRIPTOR_TABLE32, *PKSERVICE_DESCRIPTOR_TABLE32;

typedef struct tdKSERVICE_DESCRIPTOR_TABLE64 {
    QWORD ServiceTableBase;
    QWORD ServiceCounterTableBase;
    QWORD NumberOfServices;
    QWORD ParamTableBase;
} KSERVICE_DESCRIPTOR_TABLE64, *PKSERVICE_DESCRIPTOR_TABLE64;

typedef struct tdMSYSCALL_CONTEXT {
    BOOL fInit;
    QWORD vaKeServiceDescriptorTableShadow;
    union {
        BYTE pbServiceDescriptorTable[1];
        KSERVICE_DESCRIPTOR_TABLE32 ServiceDescriptorTable32[2];
        KSERVICE_DESCRIPTOR_TABLE64 ServiceDescriptorTable64[2];
    };
    DWORD cb[2];
    PBYTE pb[2];
} MSYSCALL_CONTEXT, *PMSYSCALL_CONTEXT;

/*
* Retrieve fake csrss.exe process with nothing but DTB and paging set to kernel.
* Reason is that win32k driver is not mapped into ordinary kernel address space.
* Win32k is only mapped into user mode processes and csrss.exe always exist on
* a system so pick this process and create a new fake/dummy process object with
* paging set to kernel to access Win32k
* CALLER DECREF: return
* -- return
*/
PVMM_PROCESS MSyscall_GetProcessCsrssFake()
{
    PVMM_PROCESS pObProcess = NULL, pObProcessClone = NULL;
    while((pObProcess = VmmProcessGetNext(pObProcess, 0))) {
        if(pObProcess->fUserOnly && !strcmp(pObProcess->szName, "csrss.exe") && (pObProcessClone = VmmProcessClone(pObProcess))) {
            pObProcessClone->fUserOnly = FALSE;
            Ob_DECREF(pObProcess);
            return pObProcessClone;
        }
    }
    return NULL;
}

VOID MSyscall_Initialize_BuildText(PMSYSCALL_CONTEXT ctx, PVMM_PROCESS pProcess, DWORD iTable, PDB_HANDLE hPDB, QWORD vaBase)
{
    BOOL f, f32 = ctxVmm->f32;
    DWORD i, c, dwSymbolDisplacement, oBuffer = 0, cbBuffer;
    PBYTE pbBuffer;
    QWORD va, vaServiceTableBase;
    PDWORD pdwTable = NULL;
    CHAR szSymbolName[MAX_PATH];
    c = f32 ? ctx->ServiceDescriptorTable32[iTable].NumberOfServices : (DWORD)ctx->ServiceDescriptorTable64[iTable].NumberOfServices;
    vaServiceTableBase = f32 ? ctx->ServiceDescriptorTable32[iTable].ServiceTableBase : ctx->ServiceDescriptorTable64[iTable].ServiceTableBase;
    if(!(pdwTable = LocalAlloc(0, c * sizeof(DWORD)))) { goto fail; }
    if(!VmmRead(pProcess, vaServiceTableBase, (PBYTE)pdwTable, c * sizeof(DWORD))) { goto fail; }
    cbBuffer = c * (64 + MAX_PATH);
    if(!(pbBuffer = LocalAlloc(0, cbBuffer))) { goto fail; }
    for(i = 0; i < c; i++) {
        va = 0;
        f = pdwTable[i] &&
            (va = f32 ? pdwTable[i] : vaServiceTableBase + (((LONG)pdwTable[i]) >> 4)) &&
            PDB_GetSymbolFromOffset(hPDB, (DWORD)(va - vaBase), szSymbolName, &dwSymbolDisplacement) &&
            (dwSymbolDisplacement == 0);
        oBuffer += f ?
            snprintf(pbBuffer + oBuffer, cbBuffer - oBuffer, "%04x %08x +%06x %llx %s %s\n", (i + 0x1000 * iTable), pdwTable[i], (DWORD)(va - vaBase), va, (iTable ? "win32k" : "nt    "), szSymbolName) :
            snprintf(pbBuffer + oBuffer, cbBuffer - oBuffer, "%04x %08x +%06x %*llx %s %s\n", (i + 0x1000 * iTable), pdwTable[i], 0, (f32 ? 8 : 16), va, (iTable ? "win32k" : "nt    "), "---");
    }
    ctx->pb[iTable] = LocalReAlloc(pbBuffer, oBuffer, 0);
    ctx->cb[iTable] = oBuffer;
fail:
    LocalFree(pdwTable);
}

VOID MSyscall_Initialize(PMSYSCALL_CONTEXT ctx)
{
    BOOL f, f32 = ctxVmm->f32;
    DWORD i, cbRead;
    PDB_HANDLE hPdbWin32k;
    PVMM_MAP_MODULEENTRY peModuleWin32k;
    PVMMOB_MAP_MODULE pObModuleMap = NULL;
    PE_CODEVIEW_INFO CVInfoWin32k = { 0 };
    PVMM_PROCESS pObProcessFakeCsrss = NULL, pObSystemProcess = NULL;
    if(!(pObSystemProcess = VmmProcessGet(4))) { goto fail; }
    // retrieve nt!KeServiceDescriptorTableShadow
    if(!PDB_GetSymbolAddress(PDB_HANDLE_KERNEL, "KeServiceDescriptorTableShadow", &ctx->vaKeServiceDescriptorTableShadow)) { goto fail; }
    if(!VMM_KADDR_8_16(ctx->vaKeServiceDescriptorTableShadow)) { goto fail; }
    cbRead = 2 * (f32 ? sizeof(KSERVICE_DESCRIPTOR_TABLE32) : sizeof(KSERVICE_DESCRIPTOR_TABLE64));
    if(!VmmRead(pObSystemProcess, ctx->vaKeServiceDescriptorTableShadow, ctx->pbServiceDescriptorTable, cbRead)) { goto fail; }
    // validate nt!KeServiceDescriptorTableShadow
    for(i = 0; i < 2; i++) {
        if(f32) {
            f = VMM_KADDR32_4(ctx->ServiceDescriptorTable32[i].ServiceTableBase) &&
                (ctx->ServiceDescriptorTable32[i].ServiceCounterTableBase == 0) &&
                (ctx->ServiceDescriptorTable32[i].NumberOfServices < 0x800) &&
                VMM_KADDR32(ctx->ServiceDescriptorTable32[i].ParamTableBase) &&
                (ctx->ServiceDescriptorTable32[i].ServiceTableBase < ctx->ServiceDescriptorTable32[i].ParamTableBase);
            if(!f) { return; }
        } else {
            f = VMM_KADDR64_8(ctx->ServiceDescriptorTable64[i].ServiceTableBase) &&
                (ctx->ServiceDescriptorTable64[i].ServiceCounterTableBase == 0) &&
                (ctx->ServiceDescriptorTable64[i].NumberOfServices < 0x800) &&
                VMM_KADDR64(ctx->ServiceDescriptorTable64[i].ParamTableBase) &&
                (ctx->ServiceDescriptorTable64[i].ServiceTableBase < ctx->ServiceDescriptorTable64[i].ParamTableBase);
            if(!f) { return; }
        }
    }
    // fetch win32k infos
    if(!(pObProcessFakeCsrss = MSyscall_GetProcessCsrssFake())) { goto fail_win32k; }
    if(!VmmMap_GetModuleEntryEx(pObSystemProcess, 0, L"win32k.sys", &pObModuleMap, &peModuleWin32k)) { goto fail_win32k; }
    //if(!PE_GetCodeViewInfo(pObProcessFakeCsrss, peModuleWin32k->vaBase, NULL, &CVInfoWin32k)) { goto fail_win32k; }
    //if(!(hPdbWin32k = PDB_AddModuleEntry(peModuleWin32k->vaBase, peModuleWin32k->cbImageSize, "win32k.sys", CVInfoWin32k.CodeView.PdbFileName, CVInfoWin32k.CodeView.Guid, CVInfoWin32k.CodeView.Age))) { goto fail_win32k; }
    if(!(hPdbWin32k = PDB_GetHandleFromModuleAddress(pObProcessFakeCsrss, peModuleWin32k->vaBase))) { goto fail_win32k; }
    // build text files in-memory (win32k)
    MSyscall_Initialize_BuildText(ctx, pObProcessFakeCsrss, 1, hPdbWin32k, peModuleWin32k->vaBase);
fail_win32k:
    // build text files in-memory (nt)
    MSyscall_Initialize_BuildText(ctx, pObSystemProcess, 0, PDB_HANDLE_KERNEL, ctxVmm->kernel.vaBase);
    ctx->fInit = TRUE;
fail:
    Ob_DECREF(pObModuleMap);
    Ob_DECREF(pObSystemProcess);
    Ob_DECREF(pObProcessFakeCsrss);
    g_MSYSCALL_CONTEXT = ctx;
}

PMSYSCALL_CONTEXT MSyscall_GetContext()
{
    PMSYSCALL_CONTEXT ctx;;
    if((ctx = (PMSYSCALL_CONTEXT)g_MSYSCALL_CONTEXT)) {
        return ctx->fInit ? ctx : NULL;
    }
    EnterCriticalSection(&ctxVmm->LockPlugin);
    if((ctx = (PMSYSCALL_CONTEXT)g_MSYSCALL_CONTEXT)) { goto finish; }
    if(!(ctx = LocalAlloc(LMEM_ZEROINIT, sizeof(MSYSCALL_CONTEXT)))) { goto finish; }
    PDB_Initialize_WaitComplete();
    MSyscall_Initialize(ctx);
finish:
    LeaveCriticalSection(&ctxVmm->LockPlugin);
    return (ctx && ctx->fInit) ? ctx : NULL;
}

NTSTATUS MSyscall_Read(_In_ PVMMDLL_PLUGIN_CONTEXT ctx, _Out_writes_to_(cb, *pcbRead) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset)
{
    PMSYSCALL_CONTEXT ctxSyscall;
    if((ctxSyscall = MSyscall_GetContext())) {
        if(!_wcsicmp(ctx->wszPath, L"syscall_nt.txt")) {
            return Util_VfsReadFile_FromPBYTE(ctxSyscall->pb[0], ctxSyscall->cb[0], pb, cb, pcbRead, cbOffset);
        }
        if(!_wcsicmp(ctx->wszPath, L"syscall_win32k.txt")) {
            return Util_VfsReadFile_FromPBYTE(ctxSyscall->pb[1], ctxSyscall->cb[1], pb, cb, pcbRead, cbOffset);
        }
    }
    return VMMDLL_STATUS_FILE_INVALID;
}

BOOL MSyscall_List(_In_ PVMMDLL_PLUGIN_CONTEXT ctx, _Inout_ PHANDLE pFileList)
{
    PMSYSCALL_CONTEXT ctxSyscall;
    if(ctx->wszPath[0]) { return FALSE; }
    if((ctxSyscall = MSyscall_GetContext())) {
        VMMDLL_VfsList_AddFile(pFileList, L"syscall_nt.txt", ctxSyscall->cb[0], NULL);
        VMMDLL_VfsList_AddFile(pFileList, L"syscall_win32k.txt", ctxSyscall->cb[1], NULL);
    }
    return TRUE;
}

VOID MSyscall_Close()
{
    PMSYSCALL_CONTEXT ctxSyscall;
    if((ctxSyscall = MSyscall_GetContext())) {
        g_MSYSCALL_CONTEXT = NULL;
        LocalFree(ctxSyscall->pb[0]);
        LocalFree(ctxSyscall->pb[1]);
        LocalFree(ctxSyscall);
    }
}

VOID M_SysInfoSyscall_Initialize(_Inout_ PVMMDLL_PLUGIN_REGINFO pRI)
{
    if((pRI->magic != VMMDLL_PLUGIN_REGINFO_MAGIC) || (pRI->wVersion != VMMDLL_PLUGIN_REGINFO_VERSION)) { return; }
    if((pRI->tpSystem != VMM_SYSTEM_WINDOWS_X64) && (pRI->tpSystem != VMM_SYSTEM_WINDOWS_X86)) { return; }
    wcscpy_s(pRI->reg_info.wszPathName, 128, L"\\sysinfo\\syscall");        // module name
    pRI->reg_info.fRootModule = TRUE;                                       // module shows in root directory
    pRI->reg_fn.pfnList = MSyscall_List;                                    // List function supported
    pRI->reg_fn.pfnRead = MSyscall_Read;                                    // Read function supported
    pRI->reg_fn.pfnClose = MSyscall_Close;                                  // Close function supported
    pRI->pfnPluginManager_Register(pRI);
}
