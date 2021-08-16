// m_sys_syscall.c : implementation related to the Sys/Syscall built-in module.
//
// The '/sys/syscall' module is responsible for displaying the Windows syscall table
// a.k.a. the System Service Dispatch Table (SSDT).
//
// (c) Ulf Frisk, 2020-2021
// Author: Ulf Frisk, pcileech@frizk.net
//
#include "pluginmanager.h"
#include "vmm.h"
#include "pdb.h"
#include "util.h"

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
    QWORD vaKeServiceDescriptorTable;
    QWORD vaKeServiceDescriptorTableShadow;
    union {
        BYTE pbServiceDescriptorTable[1];
        // [0] = TableNt, [1] = TableNtShadow, [2] = TableWin32kShadow
        KSERVICE_DESCRIPTOR_TABLE32 ServiceDescriptorTable32[3];
        KSERVICE_DESCRIPTOR_TABLE64 ServiceDescriptorTable64[3];
    };
    POB_COMPRESSED pCompressedData[3];
} MSYSCALL_CONTEXT, *PMSYSCALL_CONTEXT;

/*
* Retrieve csrss.exe process. It's a specially treated process with both
* user/kernel space mapped for win32k reasons.
* CALLER DECREF: return
* -- return
*/
PVMM_PROCESS MSyscall_GetProcessCsrss()
{
    PVMM_PROCESS pObProcess = NULL;
    while((pObProcess = VmmProcessGetNext(pObProcess, 0))) {
        if(!strcmp(pObProcess->szName, "csrss.exe")) {
            return pObProcess;
        }
    }
    return NULL;
}

VOID MSyscall_Initialize_BuildText(PMSYSCALL_CONTEXT ctxM, PVMM_PROCESS pProcess, DWORD iTable, PDB_HANDLE hPDB, QWORD vaBase)
{
    BOOL f, f32 = ctxVmm->f32;
    DWORD i, c, dwSymbolDisplacement, oBuffer = 0, cbBuffer;
    PBYTE pbBuffer = NULL;
    PDWORD pdwTable = NULL;
    QWORD va, vaServiceTableBase;
    CHAR szSymbolName[MAX_PATH];
    c = f32 ? ctxM->ServiceDescriptorTable32[iTable].NumberOfServices : (DWORD)ctxM->ServiceDescriptorTable64[iTable].NumberOfServices;
    vaServiceTableBase = f32 ? ctxM->ServiceDescriptorTable32[iTable].ServiceTableBase : ctxM->ServiceDescriptorTable64[iTable].ServiceTableBase;
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
            snprintf(pbBuffer + oBuffer, cbBuffer - oBuffer, "%04x %08x +%06x %llx %s %s\n", (i + 0x1000 * iTable), pdwTable[i], (DWORD)(va - vaBase), va, (iTable == 2 ? "win32k" : "nt    "), szSymbolName) :
            snprintf(pbBuffer + oBuffer, cbBuffer - oBuffer, "%04x %08x +%06x %*llx %s %s\n", (i + 0x1000 * iTable), pdwTable[i], 0, (f32 ? 8 : 16), va, (iTable == 2 ? "win32k" : "nt    "), "---");
    }
    ctxM->pCompressedData[iTable] = ObCompressed_NewFromByte(pbBuffer, oBuffer);
fail:
    LocalFree(pbBuffer);
    LocalFree(pdwTable);
}

VOID MSyscall_Initialize(PMSYSCALL_CONTEXT ctxM)
{
    BOOL f, f32 = ctxVmm->f32;
    DWORD i, cbRead;
    PDB_HANDLE hPdbWin32k;
    PVMM_MAP_MODULEENTRY peModuleWin32k;
    PVMMOB_MAP_MODULE pObModuleMap = NULL;
    PE_CODEVIEW_INFO CVInfoWin32k = { 0 };
    PVMM_PROCESS pObProcessCsrss = NULL, pObSystemProcess = NULL;
    if(!(pObSystemProcess = VmmProcessGet(4))) { goto fail; }
    // retrieve nt!KeServiceDescriptorTable & nt!KeServiceDescriptorTableShadow
    if(!PDB_GetSymbolAddress(PDB_HANDLE_KERNEL, "KeServiceDescriptorTable", &ctxM->vaKeServiceDescriptorTable)) { goto fail; }
    if(!PDB_GetSymbolAddress(PDB_HANDLE_KERNEL, "KeServiceDescriptorTableShadow", &ctxM->vaKeServiceDescriptorTableShadow)) { goto fail; }
    if(!VMM_KADDR_8_16(ctxM->vaKeServiceDescriptorTable)) { goto fail; }
    if(!VMM_KADDR_8_16(ctxM->vaKeServiceDescriptorTableShadow)) { goto fail; }
    cbRead = (f32 ? sizeof(KSERVICE_DESCRIPTOR_TABLE32) : sizeof(KSERVICE_DESCRIPTOR_TABLE64));
    if(!VmmRead(pObSystemProcess, ctxM->vaKeServiceDescriptorTable, ctxM->pbServiceDescriptorTable, cbRead)) { goto fail; }                     // Table
    if(!VmmRead(pObSystemProcess, ctxM->vaKeServiceDescriptorTableShadow, ctxM->pbServiceDescriptorTable + cbRead, 2 * cbRead)) { goto fail; }  // TableShadow
    // validate nt!KeServiceDescriptorTable / nt!KeServiceDescriptorTableShadow
    for(i = 0; i < 3; i++) {
        if(f32) {
            f = VMM_KADDR32_4(ctxM->ServiceDescriptorTable32[i].ServiceTableBase) &&
                (ctxM->ServiceDescriptorTable32[i].ServiceCounterTableBase == 0) &&
                (ctxM->ServiceDescriptorTable32[i].NumberOfServices < 0x800) &&
                VMM_KADDR32(ctxM->ServiceDescriptorTable32[i].ParamTableBase) &&
                (ctxM->ServiceDescriptorTable32[i].ServiceTableBase < ctxM->ServiceDescriptorTable32[i].ParamTableBase);
            if(!f) { return; }
        } else {
            f = VMM_KADDR64_8(ctxM->ServiceDescriptorTable64[i].ServiceTableBase) &&
                (ctxM->ServiceDescriptorTable64[i].ServiceCounterTableBase == 0) &&
                (ctxM->ServiceDescriptorTable64[i].NumberOfServices < 0x800) &&
                VMM_KADDR64(ctxM->ServiceDescriptorTable64[i].ParamTableBase) &&
                (ctxM->ServiceDescriptorTable64[i].ServiceTableBase < ctxM->ServiceDescriptorTable64[i].ParamTableBase);
            if(!f) { return; }
        }
    }
    // fetch win32k infos
    if(!(pObProcessCsrss = MSyscall_GetProcessCsrss())) { goto fail_win32k; }
    if(!VmmMap_GetModuleEntryEx(pObSystemProcess, 0, "win32k.sys", &pObModuleMap, &peModuleWin32k)) { goto fail_win32k; }
    if(!(hPdbWin32k = PDB_GetHandleFromModuleAddress(pObProcessCsrss, peModuleWin32k->vaBase))) { goto fail_win32k; }
    // build text files in-memory (win32k)
    MSyscall_Initialize_BuildText(ctxM, pObProcessCsrss, 2, hPdbWin32k, peModuleWin32k->vaBase);
fail_win32k:
    // build text files in-memory (nt)
    MSyscall_Initialize_BuildText(ctxM, pObSystemProcess, 0, PDB_HANDLE_KERNEL, ctxVmm->kernel.vaBase);
    MSyscall_Initialize_BuildText(ctxM, pObSystemProcess, 1, PDB_HANDLE_KERNEL, ctxVmm->kernel.vaBase);
fail:
    Ob_DECREF(pObModuleMap);
    Ob_DECREF(pObSystemProcess);
    Ob_DECREF(pObProcessCsrss);
    ctxM->fInit = TRUE;
}

PMSYSCALL_CONTEXT MSyscall_GetContext(_In_ PVMMDLL_PLUGIN_CONTEXT ctxP)
{
    PMSYSCALL_CONTEXT ctxM = (PMSYSCALL_CONTEXT)ctxP->ctxM;
    if(ctxM->fInit) { return ctxM; }
    EnterCriticalSection(&ctxVmm->LockPlugin);
    if(ctxM->fInit) { goto finish; }
    PDB_Initialize_WaitComplete();
    MSyscall_Initialize(ctxM);
finish:
    LeaveCriticalSection(&ctxVmm->LockPlugin);
    return ctxM;
}

NTSTATUS MSyscall_Read(_In_ PVMMDLL_PLUGIN_CONTEXT ctxP, _Out_writes_to_(cb, *pcbRead) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset)
{
    PMSYSCALL_CONTEXT ctxM = MSyscall_GetContext(ctxP);
    if(!_stricmp(ctxP->uszPath, "syscall_nt.txt")) {
        return Util_VfsReadFile_FromObCompressed(ctxM->pCompressedData[0], pb, cb, pcbRead, cbOffset);
    }
    if(!_stricmp(ctxP->uszPath, "syscall_nt_shadow.txt")) {
        return Util_VfsReadFile_FromObCompressed(ctxM->pCompressedData[1], pb, cb, pcbRead, cbOffset);
    }
    if(!_stricmp(ctxP->uszPath, "syscall_win32k.txt")) {
        return Util_VfsReadFile_FromObCompressed(ctxM->pCompressedData[2], pb, cb, pcbRead, cbOffset);
    }
    return VMMDLL_STATUS_FILE_INVALID;
}

BOOL MSyscall_List(_In_ PVMMDLL_PLUGIN_CONTEXT ctxP, _Inout_ PHANDLE pFileList)
{
    PMSYSCALL_CONTEXT ctxM = MSyscall_GetContext(ctxP);
    if(ctxP->uszPath[0]) { return FALSE; }
    VMMDLL_VfsList_AddFile(pFileList, "syscall_nt.txt", ObCompress_Size(ctxM->pCompressedData[0]), NULL);
    VMMDLL_VfsList_AddFile(pFileList, "syscall_nt_shadow.txt", ObCompress_Size(ctxM->pCompressedData[1]), NULL);
    VMMDLL_VfsList_AddFile(pFileList, "syscall_win32k.txt", ObCompress_Size(ctxM->pCompressedData[2]), NULL);
    return TRUE;
}

VOID MSyscall_Close(_In_ PVMMDLL_PLUGIN_CONTEXT ctxP)
{
    PMSYSCALL_CONTEXT ctxM = (PMSYSCALL_CONTEXT)ctxP->ctxM;
    Ob_DECREF(ctxM->pCompressedData[0]);
    Ob_DECREF(ctxM->pCompressedData[1]);
    Ob_DECREF(ctxM->pCompressedData[2]);
    LocalFree(ctxM);
}

VOID M_SysSyscall_Initialize(_Inout_ PVMMDLL_PLUGIN_REGINFO pRI)
{
    if((pRI->magic != VMMDLL_PLUGIN_REGINFO_MAGIC) || (pRI->wVersion != VMMDLL_PLUGIN_REGINFO_VERSION)) { return; }
    if((pRI->tpSystem != VMM_SYSTEM_WINDOWS_X64) && (pRI->tpSystem != VMM_SYSTEM_WINDOWS_X86)) { return; }
    if(!(pRI->reg_info.ctxM = LocalAlloc(LMEM_ZEROINIT, sizeof(MSYSCALL_CONTEXT)))) { return; }     // internal module context
    strcpy_s(pRI->reg_info.uszPathName, 128, "\\sys\\syscall");     // module name
    pRI->reg_info.fRootModule = TRUE;                               // module shows in root directory
    pRI->reg_fn.pfnList = MSyscall_List;                            // List function supported
    pRI->reg_fn.pfnRead = MSyscall_Read;                            // Read function supported
    pRI->reg_fn.pfnClose = MSyscall_Close;                          // Close function supported
    pRI->pfnPluginManager_Register(pRI);
}
