// m_evil_apc1.c : evil detectors for potentially evil APCs.
//
// Additional information:
//  - https://repnz.github.io/posts/apc/user-apc
//  - https://repnz.github.io/posts/apc/kernel-user-apc-api
//  - https://github.com/kyleavery/AceLdr (Sleeping Beacon)
//
// Contributed under BSD 0-Clause License (0BSD)
// Author: the`janitor
//

#include "modules.h"
#include "../mm/mm.h"
#include "../vmmlog.h"
#include "../vmmwin.h"
#include "../sysquery.h"

typedef struct tdMEVIL_APC1_CONTEXT {
    WORD oApcState;
    WORD oApcListHead;
    WORD oApcListEntry;
    WORD oApcNormalRoutine;
    WORD oApcNormalContext;
    WORD oApcSystemArgument1; 
    WORD oApcSystemArgument2;
    DWORD cbApc;
    DWORD cbListEntry;
    PVMM_PROCESS pObSystemProcess;
} MEVIL_APC1_CONTEXT, *PMEVIL_APC1_CONTEXT;

//-----------------------------------------------------------------------------
// APC:
//-----------------------------------------------------------------------------

VOID GetSymbolFromAddress(_In_ VMM_HANDLE H, PVMM_PROCESS pProcess, QWORD qwA, _Out_writes_(MAX_PATH) LPSTR szSymbolName)
{
    PVMMOB_MAP_MODULE pObModuleMap = NULL;
    PVMM_MAP_MODULEENTRY pModuleEntry = NULL;
    PDB_HANDLE hPDB;
    DWORD dwSymbolDisplacement = 0;
    
    strcpy_s(szSymbolName, 10, "-");
    if(VmmMap_GetModule(H, pProcess, 0, &pObModuleMap) && pObModuleMap) {
        pModuleEntry = VmmMap_GetModuleEntryEx2(H, pObModuleMap, qwA);
        if(pModuleEntry) {
            if((hPDB = PDB_GetHandleFromModuleAddress(H, pProcess, pModuleEntry->vaBase))) {
                CHAR Temp[MAX_PATH] = { 0 };
                if(PDB_GetSymbolFromOffset(H, hPDB, (DWORD)(qwA - pModuleEntry->vaBase), Temp, &dwSymbolDisplacement)) {
                    _snprintf_s(szSymbolName, MAX_PATH, _TRUNCATE, "%s+%x", Temp, dwSymbolDisplacement);
                }
            }
        }
    }
    Ob_DECREF(pObModuleMap);
}

VOID ProcessThreadAPCs(_In_ VMM_HANDLE H, PMEVIL_APC1_CONTEXT ctx, PVMM_PROCESS pProcess, PVMM_MAP_THREADENTRY pThreadEntry)
{
    BOOL f;
    QWORD vaApcListHead = 0;
    QWORD vaApcListHead_UserFLink = 0;
    QWORD vaCurrentFLink = 0;
    QWORD vaApc = 0;
    QWORD vaApcNormalRoutine = 0;
    QWORD vaApcNormalContext = 0;
    QWORD vaApcSystemArgument1 = 0;
    QWORD vaApcSystemArgument2 = 0;
    CHAR szApcNormalRoutine[MAX_PATH] = { 0 };
    CHAR szApcNormalContext[MAX_PATH] = { 0 };
    CHAR szApcSystemArgument1[MAX_PATH] = { 0 };
    CHAR szApcSystemArgument2[MAX_PATH] = { 0 };

    vaApcListHead = pThreadEntry->vaETHREAD + ctx->oApcState + ctx->oApcListHead;
    
    // user-mode APCs
    vaApcListHead_UserFLink = vaApcListHead + ctx->cbListEntry;
    vaCurrentFLink = vaApcListHead_UserFLink;

    while(vaCurrentFLink != 0 && VmmRead(H, ctx->pObSystemProcess, vaCurrentFLink, (PBYTE)&vaCurrentFLink, H->vmm.f32 ? 4 : 8))
    {
        if(H->fAbort) { break; }
        if(vaCurrentFLink == vaApcListHead_UserFLink) { break; }

        vaApc = vaCurrentFLink - ctx->oApcListEntry;

        vaApcNormalRoutine = 0;
        vaApcNormalContext = 0;
        vaApcSystemArgument1 = 0;
        vaApcSystemArgument2 = 0;

        f = VmmRead(H, ctx->pObSystemProcess, vaApc + ctx->oApcNormalRoutine, (PBYTE)&vaApcNormalRoutine, H->vmm.f32 ? 4 : 8) &&
            VmmRead(H, ctx->pObSystemProcess, vaApc + ctx->oApcNormalContext, (PBYTE)&vaApcNormalContext, H->vmm.f32 ? 4 : 8) &&
            VmmRead(H, ctx->pObSystemProcess, vaApc + ctx->oApcSystemArgument1, (PBYTE)&vaApcSystemArgument1, H->vmm.f32 ? 4 : 8) &&
            VmmRead(H, ctx->pObSystemProcess, vaApc + ctx->oApcSystemArgument2, (PBYTE)&vaApcSystemArgument2, H->vmm.f32 ? 4 : 8);

        if(!f) { break; }

        GetSymbolFromAddress(H, pProcess, vaApcNormalRoutine, szApcNormalRoutine);
        GetSymbolFromAddress(H, pProcess, vaApcNormalContext, szApcNormalContext);
        GetSymbolFromAddress(H, pProcess, vaApcSystemArgument1, szApcSystemArgument1);
        GetSymbolFromAddress(H, pProcess, vaApcSystemArgument2, szApcSystemArgument2);

        FcEvilAdd(H, EVIL_UM_APC, pProcess, vaApcNormalRoutine, "%s %016llx %s %016llx %s %016llx %s TID:%i", 
            szApcNormalRoutine, vaApcNormalContext, szApcNormalContext, vaApcSystemArgument1, 
            szApcSystemArgument1, vaApcSystemArgument2, szApcSystemArgument2, pThreadEntry->dwTID);
    }
}

//-----------------------------------------------------------------------------
// COMMON:
//-----------------------------------------------------------------------------

VOID MEvilAPC1_DoWork(_In_ VMM_HANDLE H, _In_ VMMDLL_MODULE_ID MID, _In_opt_ PVOID ctxfc)
{
    BOOL f;
    DWORD i;
    PVMM_MAP_THREADENTRY pThreadEntry;
    PVMM_PROCESS pObProcess = NULL;
    PVMMOB_MAP_THREAD pObThreadMap = NULL;
    MEVIL_APC1_CONTEXT ctx = { 0 };
    // initialize:
    if(!(ctx.pObSystemProcess = VmmProcessGet(H, 4))) { goto fail; }
    f = PDB_GetTypeChildOffsetShort(H, PDB_HANDLE_KERNEL, "_KTHREAD", "ApcState", &ctx.oApcState) &&
        PDB_GetTypeChildOffsetShort(H, PDB_HANDLE_KERNEL, "_KAPC_STATE", "ApcListHead", &ctx.oApcListHead) &&
        PDB_GetTypeChildOffsetShort(H, PDB_HANDLE_KERNEL, "_KAPC", "ApcListEntry", &ctx.oApcListEntry) &&
        PDB_GetTypeChildOffsetShort(H, PDB_HANDLE_KERNEL, "_KAPC", "NormalRoutine", &ctx.oApcNormalRoutine) &&
        PDB_GetTypeChildOffsetShort(H, PDB_HANDLE_KERNEL, "_KAPC", "NormalContext", &ctx.oApcNormalContext) &&
        PDB_GetTypeChildOffsetShort(H, PDB_HANDLE_KERNEL, "_KAPC", "SystemArgument1", &ctx.oApcSystemArgument1) &&
        PDB_GetTypeChildOffsetShort(H, PDB_HANDLE_KERNEL, "_KAPC", "SystemArgument2", &ctx.oApcSystemArgument2) &&
        PDB_GetTypeSize(H, PDB_HANDLE_KERNEL, "_KAPC", &ctx.cbApc) &&
        PDB_GetTypeSize(H, PDB_HANDLE_KERNEL, "_LIST_ENTRY", &ctx.cbListEntry);
    if(!f) { goto fail; }
    // iterate over user-mode processes:
    while((pObProcess = VmmProcessGetNext(H, pObProcess, 0))) {
        if(VmmProcess_IsKernelOnly(pObProcess)) { continue; }
        if(H->fAbort) { goto fail; }
        if(VmmMap_GetThread(H, pObProcess, &pObThreadMap)) {
            for(i = 0; i < pObThreadMap->cMap; i++) {
                if(H->fAbort) { goto fail; }
                pThreadEntry = pObThreadMap->pMap + i;
                ProcessThreadAPCs(H, &ctx, pObProcess, pThreadEntry);
            }
        }
        Ob_DECREF_NULL(&pObThreadMap);
    }
    VmmLog(H, MID, LOGLEVEL_6_TRACE, "COMPLETED FINDEVIL SCAN");
fail:
    Ob_DECREF(ctx.pObSystemProcess);
    Ob_DECREF(pObThreadMap);
    Ob_DECREF(pObProcess);
}

VOID M_Evil_APC1(_In_ VMM_HANDLE H, _Inout_ PVMMDLL_PLUGIN_REGINFO pRI)
{
    if((pRI->magic != VMMDLL_PLUGIN_REGINFO_MAGIC) || (pRI->wVersion != VMMDLL_PLUGIN_REGINFO_VERSION)) { return; }
    if(pRI->sysinfo.f32 || (pRI->sysinfo.dwVersionBuild < 9600)) { return; }    // only support 64-bit Win8.1+ for now
    // register findevil plugin:
    strcpy_s(pRI->reg_info.uszPathName, 128, "\\findevil\\EvAPC1");
    pRI->reg_info.fRootModule = TRUE;
    pRI->reg_info.fRootModuleHidden = TRUE;
    pRI->reg_fnfc.pfnFindEvil = MEvilAPC1_DoWork;
    pRI->pfnPluginManager_Register(H, pRI);
}
