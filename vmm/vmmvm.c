// vmmvm.c : implementation related to virtual machine parsing functionality.
//
// Currently Full Hyper-V machines is supported.
// Support for Hyper-V containers, sandboxes may be implemented in the future.
// Support for other virtualization layers (VMWare, VirtualBox) may or may not
// be implemented in the future as well.
//
//  
// The Hyper-V implementation is largely based from the most excellent blog
// entry by @gerhart_x (twitter.com/gerhart_x). Blog Entry:
// http://hvinternals.blogspot.com/2019/09/hyper-v-memory-internals-guest-os-memory-access.html
// 
// Please also check out LiveCloudKd at: https://github.com/gerhart01/LiveCloudKd
// 
//
// (c) Ulf Frisk, 2022
// Author: Ulf Frisk, pcileech@frizk.net
//

#include "vmm.h"
#include "vmmvm.h"
#include "vmmdll_core.h"
#include "charutil.h"
#include "util.h"
#include "infodb.h"

typedef struct tdVMMVM_VMHVTRANSLATE_GPAR {
    QWORD GpaPfnBase;
    QWORD GpaPfnTop;
    QWORD vaGPAR;           // address of gpar
    QWORD vaMB;             // address of memory block
    QWORD vaGPAA;           // address of gpa->pa translation array
} VMMVM_VMHVTRANSLATE_GPAR, *PVMMVM_VMHVTRANSLATE_GPAR;

typedef struct tdVMMVMOB_VMHVTRANSLATE_CONTEXT {
    OB ObHdr;
    QWORD vaGparArray;
    DWORD cGparAll;
    DWORD cGparValid;
    VMMVM_VMHVTRANSLATE_GPAR pGpar[0];
} VMMVMOB_VMHVTRANSLATE_CONTEXT, *PVMMVMOB_VMHVTRANSLATE_CONTEXT;

#define VMMVM_TRANSLATE_MEM_MAX         24

typedef struct tdVMMOB_VM_CONTEXT {
    OB ObHdr;
    QWORD va;
    SRWLOCK LockSRW;
    BOOL fActive;
    BOOL fReadOnly;
    BOOL fMarkShutdown;
    BOOL fPhysicalOnly;
    DWORD dwPartitionID;
    QWORD vaGparHandle;
    QWORD gpaMax;
    VMM_VM_TP tp;
    DWORD dwParentVmmMountID;   // VMM mount id/index in parent VMM.
    VMM_SYSTEM_TP tpSystem;     // VM OS system type.
    DWORD dwVersionBuild;       // VM OS version build.
    // hVMM VMM_HANDLE array does not carry "refcount". Entries may be invalid
    // and should only be used with VMMDLL_* functions which will do checks.
    VMM_HANDLE hVMM;
    PVMMVMOB_VMHVTRANSLATE_CONTEXT pTranslate;
    CHAR uszName[MAX_PATH];
} VMMOB_VM_CONTEXT, *PVMMOB_VM_CONTEXT;

typedef struct tdVMM_VM_OFFSET {
    struct {
        DWORD cb;
        DWORD Signature;
        DWORD Type;
        DWORD Name;
        DWORD Id;
        DWORD HndGpar;
    } prtn;
    struct {
        DWORD cb;
        DWORD Signature;
        DWORD GpaPfnBase;
        DWORD GpaPfnTop;
        DWORD MB;
    } gpar;
    struct {
        DWORD cb;
        DWORD Signature;
        DWORD HndPrtn;
        DWORD GPAA;
    } mb;
} VMM_VM_OFFSET, *PVMM_VM_OFFSET;

typedef struct tdVMMOB_VMGLOBAL_CONTEXT {
    OB ObHdr;
    SRWLOCK LockSRW;
    POB_MAP pVmMap;
    POB_SET psPrefetch;
    VMM_VM_OFFSET offset;
    struct {
        // only valid during init!
        PVMM_PROCESS pSystemProcess;
        PVMMOB_MAP_POOL pBigPoolMap;
    } init;
} VMMOB_VMGLOBAL_CONTEXT, *PVMMOB_VMGLOBAL_CONTEXT;

typedef struct tdVID_GPAR_HANDLE64 {
    QWORD vaPartition;
    QWORD vaGparArray;
    DWORD _Filler;
    DWORD cGpar;
    DWORD cGpar_Pre16299;
} VID_GPAR_HANDLE64, *PVID_GPAR_HANDLE64;

/*
* Cleanup a VM map.
*/
VOID VmmVm_CallbackCleanup_ObVmMap(PVMMOB_MAP_VM pOb)
{
    LocalFree(pOb->pbMultiText);
}

/*
* Cleanup a VM context.
* This also unmounts the VM child VMM from any parent VMM if needed.
*/
VOID VmmVm_CallbackCleanup_ObVmContext(PVMMOB_VM_CONTEXT pVM)
{
    VMMDLL_Close(pVM->hVMM);
    Ob_DECREF(pVM->pTranslate);
}

/*
* Cleanup the global VM context.
*/
VOID VmmVm_CallbackCleanup_ObVmGlobalContext(PVMMOB_VMGLOBAL_CONTEXT pOb)
{
    Ob_DECREF(pOb->pVmMap);
    Ob_DECREF(pOb->psPrefetch);
    Ob_DECREF(pOb->init.pBigPoolMap);
}



//-----------------------------------------------------------------------------
// VM MODULE INTERNAL INITIALIZATION & REFRESH FUNCTIONALITY BELOW:
//-----------------------------------------------------------------------------

/*
* Create a new memory translation map for pVM.
* This should be done on both VM initialization and VM refresh.
* REQUIRE: LOCK_SHARED(pVMG->LockSRW)
* REQUIRE: LOCK_EXCLUSIVE(pVM->LockSRW)
* -- H
* -- pVMG
* -- pVM
* -- return = the max translatable memory address.
*/
_Success_(return != 0)
QWORD VmmVm_DoWork_NewHvMemTranslate(_In_ VMM_HANDLE H, _In_ PVMMOB_VMGLOBAL_CONTEXT pVMG, _In_ PVMMOB_VM_CONTEXT pVM)
{
    PVMM_VM_OFFSET po = &pVMG->offset;
    BYTE pb[0x400];
    QWORD gpaMax = 0;
    PQWORD pvaGparArray = NULL;
    PVMMVMOB_VMHVTRANSLATE_CONTEXT ctxObT = NULL;
    PVMMVM_VMHVTRANSLATE_GPAR peT = NULL;
    VID_GPAR_HANDLE64 GparHandle;
    PVMM_MAP_POOLENTRY pePool;
    DWORD i, cbGPAA_Entry = (H->vmm.kernel.dwVersionBuild <= 10586) ? 8 : 16;
    if(sizeof(pb) < max(po->gpar.cb, po->mb.cb)) { goto fail; }
    // 1: On refresh - prefetch as much as possible!
    if(pVM->fActive && pVM->pTranslate) {
        ObSet_Clear(pVMG->psPrefetch);
        ObSet_Push_PageAlign(pVMG->psPrefetch, pVM->vaGparHandle, sizeof(VID_GPAR_HANDLE64));
        ObSet_Push_PageAlign(pVMG->psPrefetch, pVM->pTranslate->vaGparArray, pVM->pTranslate->cGparAll * sizeof(QWORD));
        for(i = 0; i < pVM->pTranslate->cGparAll; i++) {
            if(pVM->pTranslate->pGpar[i].vaGPAR) {
                ObSet_Push_PageAlign(pVMG->psPrefetch, pVM->pTranslate->pGpar[i].vaGPAR, po->gpar.cb);
            }
            if(pVM->pTranslate->pGpar[i].vaMB) {
                ObSet_Push_PageAlign(pVMG->psPrefetch, pVM->pTranslate->pGpar[i].vaMB, po->mb.cb);
            }
        }
        VmmCachePrefetchPages(H, pVMG->init.pSystemProcess, pVMG->psPrefetch, 0);
    }
    // 2: Fetch GPAR handle:
    if(!VmmRead(H, pVMG->init.pSystemProcess, pVM->vaGparHandle, (PBYTE)&GparHandle, sizeof(VID_GPAR_HANDLE64))) { goto fail; }
    if(H->vmm.kernel.dwVersionBuild <= 16299) {
        GparHandle.cGpar = GparHandle.cGpar_Pre16299;
    } else {
        if(GparHandle.vaPartition != pVM->va) {
            VmmLog(H, MID_VM, LOGLEVEL_6_TRACE, "FAIL: HvMemTranslate: Bad handle. [VM=%llx]", pVM->va);
            goto fail;
        }
    }
    if(!VMM_KADDR64_16(GparHandle.vaGparArray)) {
        VmmLog(H, MID_VM, LOGLEVEL_6_TRACE, "FAIL: HvMemTranslate: Bad GPAR array address. [VM=%llx]", pVM->va);
        goto fail;
    }
    if(!GparHandle.cGpar || (GparHandle.cGpar > 0x800)) {
        VmmLog(H, MID_VM, LOGLEVEL_6_TRACE, "FAIL: HvMemTranslate: Too many GPARs (%i). [VM=%llx]", GparHandle.cGpar, pVM->va);
        goto fail;
    }
    // 3: Fetch GPAR array:
    if(!VmmReadAlloc(H, pVMG->init.pSystemProcess, GparHandle.vaGparArray, (PBYTE*)&pvaGparArray, GparHandle.cGpar * sizeof(QWORD), 0)) {
        VmmLog(H, MID_VM, LOGLEVEL_6_TRACE, "FAIL: HvMemTranslate: Bad GPAR array. [VM=%llx]", pVM->va);
        goto fail;
    }
    ObSet_Clear(pVMG->psPrefetch);
    for(i = 0; i < GparHandle.cGpar; i++) {
        if(!VMM_KADDR64_16(pvaGparArray[i])) { goto fail; }
        ObSet_Push_PageAlign(pVMG->psPrefetch, pvaGparArray[i], pVMG->offset.gpar.cb);
    }
    // 4: Allocate GPAR internal object
    if(!(ctxObT = Ob_AllocEx(H, OB_TAG_VM_CONTEXT, LMEM_ZEROINIT, sizeof(VMMVMOB_VMHVTRANSLATE_CONTEXT) + GparHandle.cGpar * sizeof(VMMVMOB_VMHVTRANSLATE_CONTEXT), NULL, NULL))) { goto fail; }
    ctxObT->vaGparArray = GparHandle.vaGparArray;
    ctxObT->cGparAll = GparHandle.cGpar;
    // 5: Fetch GPARs:
    VmmCachePrefetchPages(H, pVMG->init.pSystemProcess, pVMG->psPrefetch, 0);
    ObSet_Clear(pVMG->psPrefetch);
    for(i = 0; i < ctxObT->cGparAll; i++) {
        peT = ctxObT->pGpar + i;
        peT->vaGPAR = pvaGparArray[i];
        if(!VmmRead2(H, pVMG->init.pSystemProcess, pvaGparArray[i], pb, po->gpar.cb, VMM_FLAG_FORCECACHE_READ)) { continue; }
        if('rapG' != *(PDWORD)(pb + po->gpar.Signature)) {  // Signature: 'Gpar'
            VmmLog(H, MID_VM, LOGLEVEL_6_TRACE, "[%02X] FAIL: HvMemTranslate: Bad Signature. [GPAR=%llx]", pVM->dwPartitionID, peT->vaGPAR);
            goto fail;
        }
        peT->GpaPfnBase = *(PQWORD)(pb + po->gpar.GpaPfnBase);
        peT->GpaPfnTop = *(PQWORD)(pb + po->gpar.GpaPfnTop);
        if(peT->GpaPfnBase > peT->GpaPfnTop) { continue; }
        if(peT->GpaPfnTop < 0x100) { continue; }
        if((peT->GpaPfnBase < 0x100000) && (peT->GpaPfnBase >= 0xf0000)) { continue; }
        if(peT->GpaPfnBase == 0xfff800) { continue; }
        peT->vaMB = *(PQWORD)(pb + po->gpar.MB);
        if(!VMM_KADDR64_16(peT->vaMB)) { peT->vaMB = 0; continue; }
        ObSet_Push_PageAlign(pVMG->psPrefetch, peT->vaMB, pVMG->offset.mb.cb);
    }
    // 6: Fetch MemoryBlock for valid GPARs
    VmmCachePrefetchPages(H, pVMG->init.pSystemProcess, pVMG->psPrefetch, 0);
    for(i = 0; i < ctxObT->cGparAll; i++) {
        peT = ctxObT->pGpar + i;
        if(!peT->vaMB) { continue; }
        if(!VmmRead2(H, pVMG->init.pSystemProcess, peT->vaMB, pb, po->mb.cb, VMM_FLAG_FORCECACHE_READ)) { continue; }
        if('  bM' != *(PDWORD)(pb + po->mb.Signature)) { continue; }     // Signature: 'Mb  '
        if(pVM->va != *(PQWORD)(pb + po->mb.HndPrtn)) { continue; }
        peT->vaGPAA = *(PQWORD)(pb + po->mb.GPAA);
        if(!VmmMap_GetPoolEntry(H, pVMG->init.pBigPoolMap, peT->vaGPAA, &pePool)) {
            // DEBUG / TODO: is it a valid assumption vaGPAA is in big pool table?
            VmmLog(H, MID_VM, LOGLEVEL_6_TRACE, "[%02X] WARN: HvMemTranslate: GPAA not in BigPoolTable. [GPAR=%llx,MB=%llx,GPAA=%llx]", pVM->dwPartitionID, peT->vaGPAR, peT->vaMB, peT->vaGPAA);
            continue;
        }
        if((pePool->cb / cbGPAA_Entry) < (peT->GpaPfnTop + 1 - peT->GpaPfnBase)) {
            VmmLog(H, MID_VM, LOGLEVEL_6_TRACE, "[%02X] FAIL: HvMemTranslate: cbGPAA too small. [GPAR=%llx,MB=%llx,GPAA=%llx]", pVM->dwPartitionID, peT->vaGPAR, peT->vaMB, peT->vaGPAA);
            continue;
        }
        // check previous valid GPAR is at PFN below current.
        if(ctxObT->cGparValid && (ctxObT->pGpar[ctxObT->cGparValid - 1].GpaPfnTop > peT->GpaPfnBase)) {
            VmmLog(H, MID_VM, LOGLEVEL_6_TRACE, "[%02X] FAIL: HvMemTranslate: GPAR RANGE NOT INCREASING. [GPAR=%llx(%llx),GPAR_PREV=%llx(%llx)]",
                pVM->dwPartitionID,
                peT->vaGPAR, ctxObT->pGpar[ctxObT->cGparValid - 1].GpaPfnTop,
                peT->vaGPAA, ctxObT->pGpar[ctxObT->cGparValid - 1].GpaPfnBase
            );
            goto fail;
        }
        // move valid GPAR to front by switching entries (if required) and increase valid count.
        if(ctxObT->cGparValid != i) {
            memcpy(pb, peT, sizeof(VMMVM_VMHVTRANSLATE_GPAR));
            memcpy(peT, ctxObT->pGpar + ctxObT->cGparValid, sizeof(VMMVM_VMHVTRANSLATE_GPAR));
            memcpy(ctxObT->pGpar + ctxObT->cGparValid, pb, sizeof(VMMVM_VMHVTRANSLATE_GPAR));
        }
        ctxObT->cGparValid++;
        if(!pVM->fActive) {
            VmmLog(H, MID_VM, LOGLEVEL_6_TRACE, "[%02X] MEMORY RANGE: [%10llx->%10llx] GPAR=%llx", pVM->dwPartitionID, (peT->GpaPfnBase << 12), ((peT->GpaPfnTop << 12) + 0xfff), peT->vaGPAR);
        }
    }
    if(!ctxObT->cGparValid) { goto fail; }
    // 7: update/assign to pVM context:
    Ob_DECREF_NULL(&pVM->pTranslate);
    pVM->pTranslate = Ob_INCREF(ctxObT);
    gpaMax = (ctxObT->pGpar[ctxObT->cGparValid - 1].GpaPfnTop << 12) + 0xfff;
fail:
    LocalFree(pvaGparArray);
    Ob_DECREF(ctxObT);
    return gpaMax;
}

/*
* Create VM map and push it to global vmm container (H->vmm.pObCMapVM).
*/
VOID VmmVm_DoWork_5_CreateMap(_In_ VMM_HANDLE H, _In_ PVMMOB_VMGLOBAL_CONTEXT pVMG)
{
    DWORD iMap, cMap;
    PVMM_MAP_VMENTRY peDst;
    PVMMOB_VM_CONTEXT peObSrc;
    PVMMOB_MAP_VM pObMap = NULL;
    POB_STRMAP psmOb = NULL;
    cMap = ObMap_Size(pVMG->pVmMap);
    if(!(psmOb = ObStrMap_New(H, OB_STRMAP_FLAGS_CASE_SENSITIVE))) { goto fail; }
    if(!(pObMap = Ob_AllocEx(H, OB_TAG_MAP_VM, LMEM_ZEROINIT, sizeof(VMMOB_MAP_VM) + cMap * sizeof(VMM_MAP_VMENTRY), (OB_CLEANUP_CB)VmmVm_CallbackCleanup_ObVmMap, NULL))) { goto fail; }
    pObMap->cMap = cMap;
    for(iMap = 0; iMap < cMap; iMap++) {
        peObSrc = ObMap_GetByIndex(pVMG->pVmMap, iMap);
        peDst = pObMap->pMap + iMap;
        peDst->hVM = (VMMVM_HANDLE)peObSrc->va;
        peDst->tp = peObSrc->tp;
        peDst->fActive = peObSrc->fActive;
        peDst->fReadOnly = peObSrc->fReadOnly;
        peDst->fPhysicalOnly = peObSrc->fPhysicalOnly;
        peDst->dwPartitionID = peObSrc->dwPartitionID;
        peDst->dwParentVmmMountID = peObSrc->dwParentVmmMountID;
        peDst->gpaMax = peObSrc->gpaMax;
        ObStrMap_PushPtrUU(psmOb, peObSrc->uszName, &peDst->uszName, NULL);
        peDst->tpSystem = peObSrc->tpSystem;
        peDst->dwVersionBuild = peObSrc->dwVersionBuild;
        Ob_DECREF(peObSrc);
    }
    if(!ObStrMap_FinalizeAllocU_DECREF_NULL(&psmOb, &pObMap->pbMultiText, &pObMap->cbMultiText)) { goto fail; }
    ObContainer_SetOb(H->vmm.pObCMapVM, pObMap);
fail:
    Ob_DECREF(pObMap);
    Ob_DECREF(psmOb);
}

/*
* Initialize an analysis task for a VM and also mount it into the file system if possible.
* This is done in a separate thread to avoid some potential deadlock issues.
* -- H
* -- pVM = VM handle to create analysis task for.
*/
VOID VmmVm_DoWork_4_NewVM_StartupVmm(_In_ VMM_HANDLE H, _In_ PVMMOB_VM_CONTEXT pVM)
{
    VMM_HANDLE hVMM = NULL;
    LPSTR szOsType = "Windows";
    CHAR szLcDevice[128], szGpaMax[32], szParentVmm[32];
    DWORD cArg = 0;
    LPSTR szArg[32];
    // 1: Sanity check & create init parameters:
    if(H->fAbort || !pVM->fActive || pVM->hVMM) { return; }
    // 2: Common arguments:
    _snprintf_s(szLcDevice, _countof(szLcDevice), _TRUNCATE, "vmm://hvmm=0x%016llx,hvm=0x%016llx", (QWORD)H, pVM->va);
    _snprintf_s(szGpaMax, _countof(szGpaMax), _TRUNCATE, "0x%016llx", pVM->gpaMax);
    _snprintf_s(szParentVmm, _countof(szParentVmm), _TRUNCATE, "0x%016llx", (QWORD)H);
    szArg[cArg++] = "";
    szArg[cArg++] = "-device";
    szArg[cArg++] = szLcDevice;
    szArg[cArg++] = "-max";
    szArg[cArg++] = szGpaMax;
    szArg[cArg++] = "-_internal_vmm_parent";
    szArg[cArg++] = szParentVmm;
    szArg[cArg++] = "-disable-python";
    if(!pVM->fPhysicalOnly && H->cfg.fVMNested) {
        szArg[cArg++] = "-vm-nested";
    }
    // 3: Try init Windows VM:
    if(!pVM->fPhysicalOnly) {
        if(H->cfg.tpForensicMode) {
            szArg[cArg++] = "-forensic";
            szArg[cArg++] = "1";
        }
        if(H->cfg.fWaitInitialize) {
            szArg[cArg++] = "-waitinitialize";
        }
        hVMM = VMMDLL_Initialize(cArg, szArg);
        if(!hVMM) {
            // Windows VM initialization failed!
            // Try init physical memory only VM in recursive call.
            pVM->fPhysicalOnly = TRUE;
            VmmVm_DoWork_4_NewVM_StartupVmm(H, pVM);
            return;
        }
    }
    // 4: Try init physical memory only VM:
    if(pVM->fPhysicalOnly) {
        szOsType = "Physical";
        szArg[cArg++] = "-_internal_physical_memory_only";
        hVMM = VMMDLL_Initialize(cArg, szArg);
    }
    // 5: Initialize plugins:
    if(hVMM && !H->fAbort) {
        VMMDLL_InitializePlugins(hVMM);
    }
    // 6: Finish and log result:
    pVM->hVMM = hVMM;
    if(pVM->hVMM && VmmDllCore_HandleReserveExternal(pVM->hVMM)) {
        pVM->dwParentVmmMountID = pVM->hVMM->childvmm.dwParentIndex;
        pVM->tpSystem = pVM->hVMM->vmm.tpSystem;
        pVM->dwVersionBuild = pVM->hVMM->vmm.kernel.dwVersionBuild;
        if(pVM->hVMM) {
            VmmLog(H, MID_VM, LOGLEVEL_3_INFO, "[%02X] VMM INITIALIZED: MOUNT=/vm/%i TYPE='%s(%s)' NAME='%s'", pVM->dwPartitionID, pVM->hVMM->childvmm.dwParentIndex, VMM_VM_TP_STRING[pVM->tp], szOsType, pVM->uszName);
        } else {
            VmmLog(H, MID_VM, LOGLEVEL_4_VERBOSE, "[%02X] VMM INITIALIZATION FAILED", pVM->dwPartitionID);
        }
        VmmDllCore_HandleReturnExternal(pVM->hVMM);
    }
}

/*
* Create a new VM entry and try to start it.
*/
VOID VmmVm_DoWork_4_NewVM(_In_ VMM_HANDLE H, _In_ PVMMOB_VMGLOBAL_CONTEXT pVMG, _In_ QWORD vaPrtn)
{
    PVMM_VM_OFFSET po = &pVMG->offset;
    PBYTE pbPrtn = NULL;
    DWORD dwPrtnTp, dwPrtnID;
    QWORD vaPrtnGparHandle;
    PVMMOB_VM_CONTEXT ctx = NULL;
    // 1: verify and allocate initial VM context:
    if(!VmmReadAlloc(H, pVMG->init.pSystemProcess, vaPrtn, &pbPrtn, po->prtn.cb, VMM_FLAG_NOCACHE)) { goto fail; }
    if('ntrP' != *(PDWORD)(pbPrtn + po->prtn.Signature)) { goto fail; }     // Signature: 'Prtn'
    if(!(dwPrtnID = *(PDWORD)(pbPrtn + po->prtn.Id))) { goto fail; }
    if(!VMM_KADDR64_16((vaPrtnGparHandle = *(PQWORD)(pbPrtn + po->prtn.HndGpar)))) { goto fail; }
    if(!(ctx = Ob_AllocEx(H, OB_TAG_VM_CONTEXT, LMEM_ZEROINIT, sizeof(VMMOB_VM_CONTEXT), (OB_CLEANUP_CB)VmmVm_CallbackCleanup_ObVmContext, NULL))) { goto fail; }
    ctx->fReadOnly = !H->dev.fWritable;
    ctx->fPhysicalOnly = H->cfg.fVMPhysicalOnly;
    if(!CharUtil_WtoU((LPWSTR)(pbPrtn + po->prtn.Name), 512, ctx->uszName, sizeof(ctx->uszName), NULL, NULL, CHARUTIL_FLAG_STR_BUFONLY | CHARUTIL_FLAG_TRUNCATE)) {
        Ob_DECREF_NULL(&ctx);
        goto fail;
    }
    dwPrtnTp = *(PDWORD)(pbPrtn + po->prtn.Type);
    if(((dwPrtnTp >> 16) != 0x0200)) {
        Ob_DECREF_NULL(&ctx);
        goto fail;
    }
    ctx->va = vaPrtn;
    ctx->tp = VMM_VM_TP_HV;
    ctx->dwPartitionID = dwPrtnID;
    ctx->vaGparHandle = vaPrtnGparHandle;
    VmmLog(H, MID_VM, LOGLEVEL_6_TRACE, "[%02X] NEW VM LOCATED: va=%llx tp=%08x/%i/'%s' name='%s'", ctx->dwPartitionID, vaPrtn, dwPrtnTp, ctx->tp, VMM_VM_TP_STRING[ctx->tp], ctx->uszName);
    // 2: Fetch memory translation info:
    ctx->gpaMax = VmmVm_DoWork_NewHvMemTranslate(H, pVMG, ctx);
    if(!ctx->gpaMax || !ctx->pTranslate) { goto fail; }
    // 3: Assign VM and try to start up child VMM.
    ctx->fActive = TRUE;
    if(!ObMap_Push(pVMG->pVmMap, ctx->va, ctx)) {
        Ob_DECREF(ObMap_RemoveByKey(pVMG->pVmMap, ctx->va));
        if(!ObMap_Push(pVMG->pVmMap, ctx->va, ctx)) {
            ctx->fActive = FALSE;
            goto fail;
        }
    }
    VmmVm_DoWork_4_NewVM_StartupVmm(H, ctx);
    VmmLog(H, MID_VM, LOGLEVEL_6_TRACE, "[%02X] NEW VM INITIALIZATION: SUCCESSFUL", ctx->dwPartitionID);
    // fall-through to cleanup:
fail:
    if(!ctx) {
        VmmLog(H, MID_VM, LOGLEVEL_6_TRACE, "[--] NEW VM INITIALIZATION: FAILED: Parse VM at: %llx", vaPrtn);
    } else if(!ctx->fActive) {
        VmmLog(H, MID_VM, LOGLEVEL_6_TRACE, "[%02X] NEW VM INITIALIZATION: FAILED", ctx->dwPartitionID);
        ObMap_Push(pVMG->pVmMap, ctx->va, ctx);
    }
    LocalFree(pbPrtn);
    Ob_DECREF(ctx);
}

/*
* Scan for VM candidates (i.e. matching pool entry critiera) and which are not
* already active. If a candidate is found try to start it!
*/
VOID VmmVm_DoWork_4_NewVMs(_In_ VMM_HANDLE H, _In_ PVMMOB_VMGLOBAL_CONTEXT pVMG)
{
    PVMMOB_VM_CONTEXT pVM = NULL;
    DWORD iPoolEntry, iTagPoolEntry;
    PVMM_MAP_POOLENTRYTAG pePoolTag;
    PVMM_MAP_POOLENTRY pePool;
    // Fetch 'VdDr' big pool entries. Some of these may contain Hyper-V partitions.
    if(VmmMap_GetPoolTag(H, pVMG->init.pBigPoolMap, 'VdDr', &pePoolTag)) {
        for(iTagPoolEntry = 0; iTagPoolEntry < pePoolTag->cEntry; iTagPoolEntry++) {
            iPoolEntry = pVMG->init.pBigPoolMap->piTag2Map[pePoolTag->iTag2Map + iTagPoolEntry];
            pePool = pVMG->init.pBigPoolMap->pMap + iPoolEntry;
            if(pePool->cb == pVMG->offset.prtn.cb) {
                pVM = ObMap_GetByKey(pVMG->pVmMap, pePool->va);
                if(!pVM || !pVM->fActive) {
                    VmmVm_DoWork_4_NewVM(H, pVMG, pePool->va);
                }
            }
        }
    }
}

/*
* Shut down analysis of no longer existing VMs
*/
VOID VmmVm_DoWork_3_Shutdown(_In_ VMM_HANDLE H, _In_ PVMMOB_VMGLOBAL_CONTEXT pVMG)
{
    VMM_HANDLE hVMM;
    PVMMOB_VM_CONTEXT pVM = NULL;
    while((pVM = ObMap_GetNext(pVMG->pVmMap, pVM))) {
        if(pVM->fActive && pVM->fMarkShutdown) {
            AcquireSRWLockExclusive(&pVM->LockSRW);
            pVM->fActive = FALSE;
            pVM->fMarkShutdown = FALSE;
            VmmLog(H, MID_VM, LOGLEVEL_4_VERBOSE, "[%02X] SHUTDOWN VM: %s", pVM->dwPartitionID, pVM->uszName);
            if((hVMM = pVM->hVMM)) {
                pVM->hVMM = NULL;
                VMMDLL_Close(hVMM);
            }
            ReleaseSRWLockExclusive(&pVM->LockSRW);
        }
    }
}

/*
* Refresh a single active VM - on fail mark for shutdown!
* REQUIRE: LOCK_SHARED(pVMG->LockSRW)
* REQUIRE: LOCK_EXCLUSIVE(pVM->LockSRW)
*/
VOID VmmVm_DoWork_2_RefreshVMs_SingleVM(_In_ VMM_HANDLE H, _In_ PVMMOB_VMGLOBAL_CONTEXT pVMG, _In_ PVMMOB_VM_CONTEXT pVM)
{
    PVMM_VM_OFFSET po = &pVMG->offset;
    PBYTE pbPrtn = NULL;
    DWORD dwPrtnTp;
    // 1: Fetch partition object and do initial checking:
    if(!VmmReadAlloc(H, pVMG->init.pSystemProcess, pVM->va, &pbPrtn, po->prtn.cb, 0)) { goto fail; }
    if('ntrP' != *(PDWORD)(pbPrtn + po->prtn.Signature)) { goto fail; }     // Signature: 'Prtn'
    if(pVM->dwPartitionID != *(PDWORD)(pbPrtn + po->prtn.Id)) { goto fail; }
    if(pVM->vaGparHandle != *(PQWORD)(pbPrtn + po->prtn.HndGpar)) { goto fail; }
    dwPrtnTp = *(PDWORD)(pbPrtn + po->prtn.Type);
    if(((dwPrtnTp >> 16) != 0x0200)) { goto fail; }
    // 2: Refresh memory translations:
    pVM->gpaMax = VmmVm_DoWork_NewHvMemTranslate(H, pVMG, pVM);
    if(!pVM->gpaMax || !pVM->pTranslate) { goto fail; }
    LocalFree(pbPrtn);
    return;
fail:
    LocalFree(pbPrtn);
    pVM->fMarkShutdown = TRUE;
}

/*
* Refresh VMs. This is important in a live memory scenario.
* A fail to refresh will mark the VM for shutdown.
*/
VOID VmmVm_DoWork_2_RefreshVMs(_In_ VMM_HANDLE H, _In_ PVMMOB_VMGLOBAL_CONTEXT pVMG)
{
    PVMMOB_VM_CONTEXT pVM = NULL;
    while((pVM = ObMap_GetNext(pVMG->pVmMap, pVM))) {
        if(pVM->fActive) {
            AcquireSRWLockExclusive(&pVM->LockSRW);
            VmmVm_DoWork_2_RefreshVMs_SingleVM(H, pVMG, pVM);
            ReleaseSRWLockExclusive(&pVM->LockSRW);
        }
    }
}

/*
* Retrieve offsets from static info db.
*/
_Success_(return)
BOOL VmmVm_DoWork_1_AllocGlobalContext_GetOffsets(_In_ VMM_HANDLE H, _In_ PVMM_VM_OFFSET po)
{
    return 
        InfoDB_TypeSize_Static(H, "hv", "_PRTN", &po->prtn.cb) &&
        InfoDB_TypeSize_Static(H, "hv", "_GPAR", &po->gpar.cb) &&
        InfoDB_TypeSize_Static(H, "hv", "_MB", &po->mb.cb) &&
        InfoDB_TypeChildOffset_Static(H, "hv", "_PRTN", "Signature", &po->prtn.Signature) &&
        InfoDB_TypeChildOffset_Static(H, "hv", "_PRTN", "Type", &po->prtn.Type) &&
        InfoDB_TypeChildOffset_Static(H, "hv", "_PRTN", "Name", &po->prtn.Name) &&
        InfoDB_TypeChildOffset_Static(H, "hv", "_PRTN", "Id", &po->prtn.Id) &&
        InfoDB_TypeChildOffset_Static(H, "hv", "_PRTN", "HndGpar", &po->prtn.HndGpar) &&
        InfoDB_TypeChildOffset_Static(H, "hv", "_GPAR", "Signature", &po->gpar.Signature) &&
        InfoDB_TypeChildOffset_Static(H, "hv", "_GPAR", "GpaPfnBase", &po->gpar.GpaPfnBase) &&
        InfoDB_TypeChildOffset_Static(H, "hv", "_GPAR", "GpaPfnTop", &po->gpar.GpaPfnTop) &&
        InfoDB_TypeChildOffset_Static(H, "hv", "_GPAR", "MB", &po->gpar.MB) &&
        InfoDB_TypeChildOffset_Static(H, "hv", "_MB", "Signature", &po->mb.Signature) &&
        InfoDB_TypeChildOffset_Static(H, "hv", "_MB", "HndPrtn", &po->mb.HndPrtn) &&
        InfoDB_TypeChildOffset_Static(H, "hv", "_MB", "GPAA", &po->mb.GPAA);
}

/*
* Allocate global VM context and apply it to vmm.
* (This should only take place at first run).
*/
VOID VmmVm_DoWork_1_AllocGlobalContext(_In_ VMM_HANDLE H)
{
    PVMMOB_VMGLOBAL_CONTEXT pObVMG = NULL;
    EnterCriticalSection(&H->vmm.LockUpdateMap);
    if(H->vmm.pObVmGlobalContext) { goto fail; }
    if(!(pObVMG = Ob_AllocEx(H, OB_TAG_VM_GLOBAL, LMEM_ZEROINIT, sizeof(VMMOB_VMGLOBAL_CONTEXT), (OB_CLEANUP_CB)VmmVm_CallbackCleanup_ObVmGlobalContext, NULL))) { goto fail; }
    if(!VmmVm_DoWork_1_AllocGlobalContext_GetOffsets(H, &pObVMG->offset)) { goto fail; }
    if(!(pObVMG->pVmMap = ObMap_New(H, OB_MAP_FLAGS_OBJECT_OB))) { goto fail; }
    if(!(pObVMG->psPrefetch = ObSet_New(H))) { goto fail; }
    H->vmm.pObVmGlobalContext = Ob_INCREF(pObVMG);
fail:
    Ob_DECREF(pObVMG);
    LeaveCriticalSection(&H->vmm.LockUpdateMap);
}

/*
* Initialization / Refresh of virtual machines. Initialization should happen in
* synchronous mode whilst refreshes should happen in a background async thread.
* -- H
* -- qwNotUsed
*/
VOID VmmVm_DoWork_ThreadProc(_In_ VMM_HANDLE H, _In_ QWORD qwNotUsed)
{
    PVMMOB_VMGLOBAL_CONTEXT pVMG = NULL;
    // 1: Get global VM context and acquire its lock and init "init" objects.
    if(H->fAbort) { return; }
    if(!(pVMG = H->vmm.pObVmGlobalContext)) {
        VmmVm_DoWork_1_AllocGlobalContext(H);
        if(!(pVMG = H->vmm.pObVmGlobalContext)) {
            return;
        }
    }
    AcquireSRWLockExclusive(&pVMG->LockSRW);
    if(!(pVMG->init.pSystemProcess = VmmProcessGet(H, 4))) { goto fail; }
    if(!VmmMap_GetPool(H, &pVMG->init.pBigPoolMap, FALSE)) { goto fail; }
    // 2-X: Perform other actions.
    VmmVm_DoWork_2_RefreshVMs(H, pVMG);
    VmmVm_DoWork_3_Shutdown(H, pVMG);
    VmmVm_DoWork_4_NewVMs(H, pVMG);
    VmmVm_DoWork_5_CreateMap(H, pVMG);
    // TODO: if non-volatile memory -> create blacklist memory map to block
    //       various memory analysis tasks on child VM memory.
fail:
    Ob_DECREF_NULL(&pVMG->init.pBigPoolMap);
    Ob_DECREF_NULL(&pVMG->init.pSystemProcess);
    ReleaseSRWLockExclusive(&pVMG->LockSRW);
}



//-----------------------------------------------------------------------------
// VM MODULE GENERAL FUNCTIONALITY BELOW:
//-----------------------------------------------------------------------------

/*
* Retrieve the VM context for the HVM handle if possible.
* CALLER DECREF: return
* -- H
* -- HVM
* -- return
*/
_Success_(return != NULL)
PVMMOB_VM_CONTEXT VmmVm_GetVmContext(_In_ VMM_HANDLE H, _In_ VMMVM_HANDLE HVM)
{
    PVMMOB_VM_CONTEXT pObVM;
    if(!H->vmm.pObVmGlobalContext) { return NULL; }
    pObVM = ObMap_GetByKey(H->vmm.pObVmGlobalContext->pVmMap, (QWORD)HVM);
    if(pObVM && pObVM->fActive) {
        return pObVM;
    }
    Ob_DECREF(pObVM);
    return NULL;
}

int VmmVm_TranslateGPA2PA_HVFULL_CmpFind(_In_ QWORD gpa, _In_ QWORD qwEntry)
{
    PVMMVM_VMHVTRANSLATE_GPAR pGPAR = (PVMMVM_VMHVTRANSLATE_GPAR)qwEntry;
    if(pGPAR->GpaPfnTop <= gpa) { return 1; }
    if(pGPAR->GpaPfnBase > gpa) { return -1; }
    return 0;
}

/*
* Translate MEMs in parallel using the full Hyper-V VM technique.
* -- H
* -- pVM
* -- ppMEMsGPA
* -- cpMEMsGPA
* -- ppMEMs_Translate = MEMs used for translation - length of at least cpMEMsGPA.
*/
VOID VmmVm_TranslateGPA2PA_HVFULL(_In_ VMM_HANDLE H, _In_ PVMMOB_VM_CONTEXT pVM, _Inout_ PPMEM_SCATTER ppMEMsGPA, _In_ DWORD cpMEMsGPA, _In_ PPMEM_SCATTER ppMEMs_Translate)
{
    // TODO: INCREASE EFFICIENCY! IN MOST CASES ONLY 1-2 PMEM_SCATTER IS REQUIRED!!!!
    BOOL fValid;
    QWORD oTranslate, vaTranslateBase, vaTranslateBaseLast = (QWORD)-1;
    QWORD iMEM = 0, iMEM_Translate = 0, oMEM_Translate;
    PMEM_SCATTER pMEM, pMEM_Translate;
    PVMMVM_VMHVTRANSLATE_GPAR pGpar;
    DWORD dwRecordSizeBits = (H->vmm.kernel.dwVersionBuild <= 10586) ? 3 : 4;
    // 1: Walk each MEM and PUSH qwA, iTranslate, oTranslate to MEM stack.
    for(iMEM = 0; iMEM < cpMEMsGPA; iMEM++) {
        fValid = FALSE;
        pMEM = ppMEMsGPA[iMEM];
        MEM_SCATTER_STACK_PUSH(pMEM, pMEM->qwA);
        if(MEM_SCATTER_ADDR_ISVALID(pMEM)) {
            if((pGpar = Util_qfind(pMEM->qwA >> 12, pVM->pTranslate->cGparValid, pVM->pTranslate->pGpar, sizeof(VMMVM_VMHVTRANSLATE_GPAR), VmmVm_TranslateGPA2PA_HVFULL_CmpFind))) {
                vaTranslateBase = pGpar->vaGPAA;
                oTranslate = (((pMEM->qwA >> 12) - pGpar->GpaPfnBase) << dwRecordSizeBits); // Offset in bytes inside GPA array. A record is 16 bytes per page.
                if(vaTranslateBase & 0xfff) {
                    oTranslate += vaTranslateBase & 0xfff;
                    vaTranslateBase = vaTranslateBase & ~0xfff;
                }
                vaTranslateBase += oTranslate & ~0xfff;
                oTranslate = oTranslate & 0xfff;
                fValid = TRUE;
            }
        }
        if(fValid) {
            if(iMEM_Translate && (vaTranslateBase == vaTranslateBaseLast)) {
                iMEM_Translate--;
            }
            pMEM_Translate = ppMEMs_Translate[iMEM_Translate];
            pMEM_Translate->f = FALSE;
            pMEM_Translate->qwA = vaTranslateBase;
            MEM_SCATTER_STACK_PUSH(pMEM, iMEM_Translate);       // index reference to pMEM_Translate.
            MEM_SCATTER_STACK_PUSH(pMEM, oTranslate);           // byte offset in pMEM_Translate page.
            vaTranslateBaseLast = vaTranslateBase;
            iMEM_Translate++;
        } else {
            MEM_SCATTER_STACK_PUSH(pMEM, (QWORD)-1);
            MEM_SCATTER_STACK_PUSH(pMEM, (QWORD)-1);
        }
    }
    // 2: Fetch translation MEMs:
    VmmReadScatterVirtual(H, PVMM_PROCESS_SYSTEM, ppMEMs_Translate, (DWORD)iMEM_Translate, 0);
    // 3: Update MEMs with translated PAs:
    for(iMEM = 0; iMEM < cpMEMsGPA; iMEM++) {
        pMEM = ppMEMsGPA[iMEM];
        oMEM_Translate = MEM_SCATTER_STACK_POP(pMEM);
        iMEM_Translate = MEM_SCATTER_STACK_POP(pMEM);
        if((iMEM_Translate >= VMMVM_TRANSLATE_MEM_MAX) || (oMEM_Translate > 0xFF8)) {
            pMEM->qwA = MEM_SCATTER_ADDR_INVALID;
            continue;
        }
        pMEM_Translate = ppMEMs_Translate[iMEM_Translate];
        if(pMEM_Translate->f) {
            pMEM->qwA = *(PQWORD)(pMEM_Translate->pb + oMEM_Translate) << 12;
        } else {
            pMEM->qwA = MEM_SCATTER_ADDR_INVALID;
        }
    }
}

/*
* Translate multiple virtual machine (VM) guest physical addresses (GPAs) to physical addresses (PAs).
* Upon success the translated address will be in 'qwA' field. Old 'qwA' will be pushed on MEM stack.
* -- hVMM
* -- pVM
* -- ppMEMsGPA
* -- cpMEMsGPA
* -- return = success/fail.
*/
_Success_(return)
BOOL VmmVm_TranslateGPA2PA(_In_ VMM_HANDLE H, _In_ PVMMOB_VM_CONTEXT pVM, _Inout_ PPMEM_SCATTER ppMEMsGPA, _In_ DWORD cpMEMsGPA)
{
    PMEM_SCATTER pMEM;
    BOOL fValid = FALSE;
    DWORD iMEM, cMEMsTranslate;
    PPMEM_SCATTER ppMEMs_Translate;
    // 1: Initial validity check:
    //    - at least one (1) pMEM with valid address to translate
    //    - all pMEMs have sufficient remaining stack depth
    for(iMEM = 0; iMEM < cpMEMsGPA; iMEM++) {
        pMEM = ppMEMsGPA[iMEM];
        if(pMEM->iStack > MEM_SCATTER_STACK_SIZE - 4) {
            return FALSE;
        }
        if(pMEM->qwA & 0xfff) {
            pMEM->qwA = MEM_SCATTER_ADDR_INVALID;
        }
        fValid = fValid || MEM_SCATTER_ADDR_ISVALID(pMEM);
    }
    if(!fValid) { return FALSE; }
    // 2: Translate GPA to PA:
    if(pVM->tp == VMM_VM_TP_HV) {
        cMEMsTranslate = min(cpMEMsGPA, VMMVM_TRANSLATE_MEM_MAX);
        if(!LcAllocScatter1(cMEMsTranslate, &ppMEMs_Translate)) { return FALSE; }
        while(cpMEMsGPA) {
            cMEMsTranslate = min(cpMEMsGPA, VMMVM_TRANSLATE_MEM_MAX);
            VmmVm_TranslateGPA2PA_HVFULL(H, pVM, ppMEMsGPA, cMEMsTranslate, ppMEMs_Translate);
            ppMEMsGPA += cMEMsTranslate;
            cpMEMsGPA -= cMEMsTranslate;
        }
        LcMemFree(ppMEMs_Translate);
        return TRUE;
    }
    // 3: fail on unsupported virtual machine type.
    return FALSE;
}

/*
* Translate a virtual machine (VM) guest physical address (GPA) to a physical address (PA).
* -- hVMM
* -- pVM
* -- qwGPA
* -- pqwPA
* -- return = success/fail.
*/
_Success_(return)
BOOL VmmVm_GPA2PA_DoWork(_In_ VMM_HANDLE H, _In_ PVMMOB_VM_CONTEXT pVM, _In_ ULONG64 qwGPA, _Out_ PULONG64 pqwPA)
{
    BOOL f = FALSE;
    MEM_SCATTER MEM = { 0 };
    PMEM_SCATTER pMEM = &MEM;
    // create a dummy MEM and translate it with VmmVm_TranslateGPA2PA()
    // which also properly verifies the validity of the HVM handle.
    MEM.qwA = qwGPA;
    f = VmmVm_TranslateGPA2PA(H, pVM, &pMEM, 1);
    *pqwPA = MEM.qwA;
    return f;
}

/*
* Scatter read guest physical address (GPA) memory. Non contiguous 4096-byte pages.
* -- H
* -- pVM
* -- ppMEMsGPA
* -- cpMEMsVirt
*/
VOID VmmVm_ReadScatterGPA_DoWork(_In_ VMM_HANDLE H, _In_ PVMMOB_VM_CONTEXT pVM, _Inout_ PPMEM_SCATTER ppMEMsGPA, _In_ DWORD cpMEMsGPA)
{
    DWORD iMEM;
    PMEM_SCATTER pMEM;
    if(pVM->tp == VMM_VM_TP_HV) {
        // 1: Full Hyper-V VMs: call VmmVm_TranslateGPA2PA() to translate GPAs to PAs:
        if(!VmmVm_TranslateGPA2PA(H, pVM, ppMEMsGPA, cpMEMsGPA)) { return; }
        // 2: Call LeechCore directly to retrieve the data. This may be done since
        //    caching is assumed to be handled by upstream layers so avoid calling
        //    VmmReadScatterPhysical() to double cache things.
        LcReadScatter(H->hLC, cpMEMsGPA, ppMEMsGPA);
        // 3: Restore "stack" of pMEMs set by VmmVm_TranslateGPA2PA().
        //    Also update statistics.
        for(iMEM = 0; iMEM < cpMEMsGPA; iMEM++) {
            pMEM = ppMEMsGPA[iMEM];
            if(pMEM->f) {
                InterlockedIncrement64(&H->vmm.stat.cGpaReadSuccess);
            } else {
                InterlockedIncrement64(&H->vmm.stat.cGpaReadFail);
            }
            pMEM->qwA = MEM_SCATTER_STACK_POP(pMEM);
        }
        return;
    }
    // TODO: support additional VM types.
}

/*
* Scatter write guest physical address (GPA) memory. Non contiguous 4096-byte pages.
* -- H
* -- pVM
* -- ppMEMsGPA
* -- cpMEMsVirt
*/
VOID VmmVm_WriteScatterGPA_DoWork(_In_ VMM_HANDLE H, _In_ PVMMOB_VM_CONTEXT pVM, _Inout_ PPMEM_SCATTER ppMEMsGPA, _In_ DWORD cpMEMsGPA)
{
    DWORD iMEM;
    PMEM_SCATTER pMEM;
    if(pVM->fReadOnly) { return; }
    if(pVM->tp == VMM_VM_TP_HV) {
        // 1: Full Hyper-V VMs: call VmmVm_TranslateGPA2PA() to translate GPAs to PAs:
        if(!VmmVm_TranslateGPA2PA(H, pVM, ppMEMsGPA, cpMEMsGPA)) { return; }
        // 2: Call LeechCore directly to retrieve the data. This may be done since
        //    caching is assumed to be handled by upstream layers so avoid calling
        //    VmmWriteScatterPhysical() to double cache things.
        LcWriteScatter(H->hLC, cpMEMsGPA, ppMEMsGPA);
        // 3: Restore "stack" of pMEMs set by VmmVm_TranslateGPA2PA()
        //    Also update statistics.
        InterlockedAdd64(&H->vmm.stat.cGpaWrite, cpMEMsGPA);
        for(iMEM = 0; iMEM < cpMEMsGPA; iMEM++) {
            pMEM = ppMEMsGPA[iMEM];
            if(MEM_SCATTER_ADDR_ISVALID(pMEM)) {
                VmmCacheInvalidate(H, pMEM->qwA);
            }
            pMEM->qwA = MEM_SCATTER_STACK_POP(pMEM);
        }
        return;
    }
    // TODO: support additional VM types.
}



// ----------------------------------------------------------------------------
// MODULE EXTERNAL FUNCTIONS BELOW:
// ----------------------------------------------------------------------------

/*
* Cleanup the VM sub-system. This should ideally be done on Vmm Close().
* -- H
*/
VOID VmmVm_Close(_In_ VMM_HANDLE H)
{
    Ob_DECREF_NULL(&H->vmm.pObVmGlobalContext);
}

/*
* Refresh the VM sub-system.
* VM refresh should be called after pool map refresh.
* -- H
*/
VOID VmmVm_Refresh(_In_ VMM_HANDLE H)
{
    if(H->cfg.fVM) {
        VmmWork_Value(H, VmmVm_DoWork_ThreadProc, 0, 0, VMMWORK_FLAG_PRIO_NORMAL);  // refresh async
    }
}

/*
* Translate a virtual machine (VM) guest physical address (GPA) to a physical address (PA).
* -- hVMM
* -- HVM
* -- qwGPA
* -- pqwPA
* -- return = success/fail.
*/
_Success_(return)
BOOL VmmVm_GPA2PA(_In_ VMM_HANDLE H, _In_ VMMVM_HANDLE HVM, _In_ ULONG64 qwGPA, _Out_ PULONG64 pqwPA)
{
    BOOL f = FALSE;
    PVMMOB_VM_CONTEXT pObVM = NULL;
    if(!H->fAbort && (pObVM = VmmVm_GetVmContext(H, HVM))) {
        AcquireSRWLockShared(&pObVM->LockSRW);
        if(pObVM->fActive) {
            f = VmmVm_GPA2PA_DoWork(H, pObVM, qwGPA, pqwPA);
        }
        ReleaseSRWLockShared(&pObVM->LockSRW);
        Ob_DECREF(pObVM);
    }
    return f;
}

/*
* Scatter read guest physical address (GPA) memory. Non contiguous 4096-byte pages.
* -- H
* -- HVM
* -- ppMEMsGPA
* -- cpMEMsGPA
*/
VOID VmmVm_ReadScatterGPA(_In_ VMM_HANDLE H, _In_ VMMVM_HANDLE HVM, _Inout_ PPMEM_SCATTER ppMEMsGPA, _In_ DWORD cpMEMsGPA)
{
    PVMMOB_VM_CONTEXT pObVM = NULL;
    if(!H->fAbort && (pObVM = VmmVm_GetVmContext(H, HVM))) {
        AcquireSRWLockShared(&pObVM->LockSRW);
        if(pObVM->fActive) {
            VmmVm_ReadScatterGPA_DoWork(H, pObVM, ppMEMsGPA, cpMEMsGPA);
        }
        ReleaseSRWLockShared(&pObVM->LockSRW);
        Ob_DECREF(pObVM);
    }
}

/*
* Scatter write guest physical address (GPA) memory. Non contiguous 4096-byte pages.
* -- H
* -- HVM
* -- ppMEMsGPA
* -- cpMEMsGPA
*/
VOID VmmVm_WriteScatterGPA(_In_ VMM_HANDLE H, _In_ VMMVM_HANDLE HVM, _Inout_ PPMEM_SCATTER ppMEMsGPA, _In_ DWORD cpMEMsGPA)
{
    PVMMOB_VM_CONTEXT pObVM = NULL;
    if(!H->fAbort && (pObVM = VmmVm_GetVmContext(H, HVM))) {
        AcquireSRWLockShared(&pObVM->LockSRW);
        if(pObVM->fActive) {
            VmmVm_WriteScatterGPA_DoWork(H, pObVM, ppMEMsGPA, cpMEMsGPA);
        }
        ReleaseSRWLockShared(&pObVM->LockSRW);
        Ob_DECREF(pObVM);
    }
}

/*
* Read guest physical address (GPA) memory.
* -- H
* -- HVM
* -- pb
* -- cb
* -- pcbReadOpt
*/
VOID VmmVm_Read(_In_ VMM_HANDLE H, _In_ VMMVM_HANDLE HVM, _In_ QWORD qwA, _Out_writes_(cb) PBYTE pb, _In_ DWORD cb, _Out_opt_ PDWORD pcbReadOpt)
{
    DWORD cbP, cMEMs, cbRead = 0;
    PBYTE pbBuffer;
    PMEM_SCATTER pMEMs, *ppMEMs;
    QWORD i, oA;
    if(pcbReadOpt) { *pcbReadOpt = 0; }
    if(!cb) { return; }
    cMEMs = (DWORD)(((qwA & 0xfff) + cb + 0xfff) >> 12);
    pbBuffer = (PBYTE)LocalAlloc(LMEM_ZEROINIT, 0x2000 + cMEMs * (sizeof(MEM_SCATTER) + sizeof(PMEM_SCATTER)));
    if(!pbBuffer) {
        ZeroMemory(pb, cb);
        return;
    }
    pMEMs = (PMEM_SCATTER)(pbBuffer + 0x2000);
    ppMEMs = (PPMEM_SCATTER)(pbBuffer + 0x2000 + cMEMs * sizeof(MEM_SCATTER));
    oA = qwA & 0xfff;
    // prepare "middle" pages
    for(i = 0; i < cMEMs; i++) {
        ppMEMs[i] = &pMEMs[i];
        pMEMs[i].version = MEM_SCATTER_VERSION;
        pMEMs[i].qwA = qwA - oA + (i << 12);
        pMEMs[i].cb = 0x1000;
        pMEMs[i].pb = pb - oA + (i << 12);
    }
    // fixup "first/last" pages
    pMEMs[0].pb = pbBuffer;
    if(cMEMs > 1) {
        pMEMs[cMEMs - 1].pb = pbBuffer + 0x1000;
    }
    // Read VMMVM_SCATTER and handle result
    VmmVm_ReadScatterGPA(H, HVM, ppMEMs, cMEMs);
    for(i = 0; i < cMEMs; i++) {
        if(pMEMs[i].f) {
            cbRead += 0x1000;
        } else {
            ZeroMemory(pMEMs[i].pb, 0x1000);
        }
    }
    cbRead -= pMEMs[0].f ? 0x1000 : 0;                             // adjust byte count for first page (if needed)
    cbRead -= ((cMEMs > 1) && pMEMs[cMEMs - 1].f) ? 0x1000 : 0;    // adjust byte count for last page (if needed)
    // Handle first page
    cbP = (DWORD)min(cb, 0x1000 - oA);
    if(pMEMs[0].f) {
        memcpy(pb, pMEMs[0].pb + oA, cbP);
        cbRead += cbP;
    } else {
        ZeroMemory(pb, cbP);
    }
    // Handle last page
    if(cMEMs > 1) {
        cbP = (((qwA + cb) & 0xfff) ? ((qwA + cb) & 0xfff) : 0x1000);
        if(pMEMs[cMEMs - 1].f) {
            memcpy(pb + ((QWORD)cMEMs << 12) - oA - 0x1000, pMEMs[cMEMs - 1].pb, cbP);
            cbRead += cbP;
        } else {
            ZeroMemory(pb + ((QWORD)cMEMs << 12) - oA - 0x1000, cbP);
        }
    }
    if(pcbReadOpt) { *pcbReadOpt = cbRead; }
    LocalFree(pbBuffer);
}

/*
* Write guest physical address (GPA) memory.
* -- H
* -- HVM
* -- pb
* -- cb
* -- pcbWrite
*/
VOID VmmVm_Write(_In_ VMM_HANDLE H, _In_ VMMVM_HANDLE HVM, _In_ QWORD qwA, _In_ PBYTE pb, _In_ DWORD cb, _Out_opt_ PDWORD pcbWrite)
{
    DWORD i = 0, oA = 0, cbWrite = 0, cbP, cMEMs;
    PBYTE pbBuffer;
    PMEM_SCATTER pMEM, pMEMs, *ppMEMs;
    if(pcbWrite) { *pcbWrite = 0; }
    // allocate
    cMEMs = (DWORD)(((qwA & 0xfff) + cb + 0xfff) >> 12);
    if(!(pbBuffer = (PBYTE)LocalAlloc(LMEM_ZEROINIT, cMEMs * (sizeof(MEM_SCATTER) + sizeof(PMEM_SCATTER))))) { return; }
    pMEMs = (PMEM_SCATTER)pbBuffer;
    ppMEMs = (PPMEM_SCATTER)(pbBuffer + cMEMs * sizeof(MEM_SCATTER));
    // prepare pages
    while(oA < cb) {
        cbP = 0x1000 - ((qwA + oA) & 0xfff);
        cbP = min(cbP, cb - oA);
        ppMEMs[i] = pMEM = pMEMs + i; i++;
        pMEM->version = MEM_SCATTER_VERSION;
        pMEM->qwA = qwA + oA;
        pMEM->cb = cbP;
        pMEM->pb = pb + oA;
        oA += cbP;
    }
    // write VMMVM_SCATTER and count result
    VmmVm_WriteScatterGPA(H, HVM, ppMEMs, cMEMs);
    if(pcbWrite) {
        for(i = 0; i < cMEMs; i++) {
            if(pMEMs[i].f) {
                cbWrite += pMEMs[i].cb;
            }
        }
        *pcbWrite = cbWrite;
    }
    LocalFree(pbBuffer);
}

/*
* Retrieve the VMM_HANDLE handle for a VMMVM_HANDLE.
* Also increase the VMM_HANDLE refcount.
* This is not allowed on physical memory only VMs.
* NB! The returned VMM_HANDLE is not "reserved".
* NB! The returned VMM_HANDLE must be closed by VMMDLL_Close().
* -- H
* -- HVM
* -- return
*/
_Success_(return != NULL)
VMM_HANDLE VmmVm_RetrieveNewVmmHandle(_In_ VMM_HANDLE H, _In_ VMMVM_HANDLE HVM)
{
    VMM_HANDLE hVMMVM = NULL;
    PVMMOB_VM_CONTEXT pObVM = NULL;
    if(!H->fAbort && (pObVM = VmmVm_GetVmContext(H, HVM))) {
        AcquireSRWLockShared(&pObVM->LockSRW);
        if(pObVM->fActive && !pObVM->fPhysicalOnly) {
            hVMMVM = VmmDllCore_HandleDuplicate(pObVM->hVMM);
        }
        ReleaseSRWLockShared(&pObVM->LockSRW);
        Ob_DECREF(pObVM);
    }
    return hVMMVM;
}

/*
* Create a VM map and assign it to the global context upon success.
* CALLER DECREF: return
* -- H
* -- return
*/
PVMMOB_MAP_VM VmmVm_Initialize(_In_ VMM_HANDLE H)
{
    PVMMOB_MAP_VM pObVM = NULL;
    if(!H->cfg.fVM) { return NULL; }
    if((pObVM = ObContainer_GetOb(H->vmm.pObCMapVM))) { return pObVM; }
    EnterCriticalSection(&H->vmm.LockUpdateMap);
    if((pObVM = ObContainer_GetOb(H->vmm.pObCMapVM))) {
        LeaveCriticalSection(&H->vmm.LockUpdateMap);
        return pObVM;
    }
    if(H->cfg.fVM) {
        // first time init is synchronous - refreshes will be async.
        VmmVm_DoWork_ThreadProc(H, 0);
    }
    if(!(pObVM = ObContainer_GetOb(H->vmm.pObCMapVM))) {
        pObVM = Ob_AllocEx(H, OB_TAG_VM_GLOBAL, LMEM_ZEROINIT, sizeof(VMMOB_MAP_VM), NULL, NULL);
        ObContainer_SetOb(H->vmm.pObCMapVM, pObVM);
    }
    LeaveCriticalSection(&H->vmm.LockUpdateMap);
    return pObVM;
}
