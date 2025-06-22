// m_misc_bitlocker.c : implementation of the bitlocker key recovery built-in module.
//
// (c) Ulf Frisk, 2022-2025
// Author: Ulf Frisk, pcileech@frizk.net
//

#include "modules.h"

LPSTR szMBDE_README =
"Bitlocker plugin for MemProcFS:                                             \n" \
"===============================                                             \n" \
"                                                                            \n" \
"The BitLocker plugin tries to recover BitLocker key material from memory.   \n" \
"                                                                            \n" \
"The MemProcFS BitLocker plugin is to some degree inspired by the excellent  \n" \
"Volatility plugin at: https://github.com/breppo/Volatility-BitLocker        \n" \
"                                                                            \n" \
"To mount a bitlocker drive please use Linux dislocker. You may mount with   \n" \
"the recovered key material in the .fvek file by:                            \n" \
"dislocker -k <recovered_key>.fvek /path/to/disk /path/to/dislocker          \n" \
"mount /path/to/dislocker/dislocker-file /path/to/mount                      \n" \
"                                                                            \n" \
"The plugin works best analyzing Windows 7 and Windows 10/11 targets.        \n" \
"Windows 8 support is more error prone - but will most often work.           \n" \
"---                                                                         \n" \
"Documentation: https://github.com/ufrisk/MemProcFS/wiki/FS_BitLocker        \n";

typedef struct tdMBDE_KEY {
    QWORD va;
    BOOL fWin8Merge;
    DWORD cbKey;
    union {
        BYTE pbDislocker[66];
        struct {
            BYTE dwMode;
            BYTE dw80;
            BYTE pbKey1[32];
            BYTE pbKey2[32];
        };
        struct {
            BYTE _Reserved1;
            BYTE _Reserved2;
            BYTE pbKey12[64];
        };
    };
    BYTE pbBuffer[32];
    CHAR szNameFVEK[32];
    CHAR szNameBIN[32];
    CHAR szNameTXT[32];
    CHAR szTXT[0x100];
    DWORD cbBlob;
    BYTE pbBlob[0];
} MBDE_KEY, *PMBDE_KEY;

typedef struct tdMBDE_CONTEXT {
    PVMMDLL_PLUGIN_CONTEXT ctxP;
    PVMMOB_MAP_POOL pPoolMap;
    POB_MAP pmBDE;
    BOOL fWin8;
} MBDE_CONTEXT, *PMBDE_CONTEXT;

typedef struct tdMBDE_OFFSET {
    DWORD o0;
    DWORD o1;
    DWORD o2;
    DWORD o3;
} MBDE_OFFSET, *PMBDE_OFFSET;

static BYTE pbMBDE_ZERO32[32] = { 0 };

#define MBDE_MODE_AES128_DIFFUSER       0
#define MBDE_MODE_AES256_DIFFUSER       1
#define MBDE_MODE_AES128                2
#define MBDE_MODE_AES256                3
#define MBDE_MODE_AES256_XTS            4
#define MBDE_MODE_AES128_XTS            5

static LPCSTR szMBDE_MODE_STR[] = {
    "AES 128-bit with Diffuser",
    "AES 256-bit with Diffuser",
    "AES 128-bit",
    "AES 256-bit",
    "AES-XTS 256-bit",
    "AES-XTS 128-bit"
};



// ----------------------------------------------------------------------------
// BITLOCKER KEY RETRIEVAL / ANALYSIS BELOW:
// ----------------------------------------------------------------------------

/*
* Update a key with display information.
* -- ctxBDE
* -- pk
*/
VOID MBDE_ContextKeyUpdate(_In_ PMBDE_CONTEXT ctxBDE, _In_ PMBDE_KEY pk)
{
    DWORD o, i = 0;
    CHAR szKey1[129], szKey2[129];
    pk->dw80 = 0x80;
    snprintf(pk->szNameFVEK, _countof(pk->szNameFVEK), "%llx.fvek", pk->va);
    snprintf(pk->szNameBIN, _countof(pk->szNameBIN), "%llx.bin", pk->va);
    snprintf(pk->szNameTXT, _countof(pk->szNameTXT), "%llx.txt", pk->va);
    for(i = 0; i < 64; i++) {
        snprintf(szKey1 + i * 2ULL, 3, "%02x", pk->pbKey12[i]);
    }
    for(i = 0; i < 32; i++) {
        snprintf(szKey2 + i * 2ULL, 3, "%02x", pk->pbKey2[i]);
    }
    o = snprintf(pk->szTXT, _countof(pk->szTXT),
        "Address: 0x%llx\nCipher:  %s\nKey:     %.*s\n",
        pk->va,
        szMBDE_MODE_STR[pk->dwMode],
        2 * pk->cbKey, szKey1
    );
    if((pk->dwMode == MBDE_MODE_AES128_DIFFUSER) || (pk->dwMode == MBDE_MODE_AES256_DIFFUSER) || ctxBDE->fWin8) {
        snprintf(pk->szTXT + o, _countof(pk->szTXT) - o, "Tweak:   %.*s\n", 2 * pk->cbKey, szKey2);
    }
}

/*
* Add a key context. This is usually a recovered bitlocker AES key.
* In case of Win8 it may be a partial key if elephant diffuser is used.
* -- H
* -- ctxBDE
* -- peKey
* -- pbKeyBlob
*/
VOID MBDE_ContextKeyAdd(_In_ VMM_HANDLE H, _In_ PMBDE_CONTEXT ctxBDE, _In_ PMBDE_KEY peKey, _In_ PBYTE pbKeyBlob)
{
    PMBDE_KEY pk;
    if(!(pk = LocalAlloc(0, sizeof(MBDE_KEY) + peKey->cbBlob))) { return; }
    if(!ObMap_Push(ctxBDE->pmBDE, peKey->va, pk)) {
        LocalFree(pk);
        return;
    }
    memcpy(pk, peKey, sizeof(MBDE_KEY));
    memcpy(pk->pbBlob, pbKeyBlob, peKey->cbBlob);
    MBDE_ContextKeyUpdate(ctxBDE, pk);
    VmmLog(H, ctxBDE->ctxP->MID, LOGLEVEL_TRACE, "Key located at %llx", pk->va);
}

/*
* Merge any Win8 diffuser keys. In Win8 and early win10 keys are split between
* two different key blobs. There is a pointer which ties keys together. Merge
* these key blobs into two different versions - one correct and one fail.
* -- ctxBDE
*/
VOID MBDE_Win8_PostProcess(_In_ VMM_HANDLE H, _In_ PMBDE_CONTEXT ctxBDE)
{
    PMBDE_KEY pKey1 = NULL, pKey2;
    QWORD va1 = 0, va2 = 0;
    while((pKey1 = ObMap_GetNext(ctxBDE->pmBDE, pKey1))) {
        va1 = VMM_PTR_OFFSET_DUAL(H->vmm.f32, pKey1->pbBlob, 0x10, 8);
        pKey2 = NULL;
        while((pKey2 = ObMap_GetNext(ctxBDE->pmBDE, pKey2))) {
            va2 = VMM_PTR_OFFSET_DUAL(H->vmm.f32, pKey2->pbBlob, 0x10, 8);
            if((pKey1 == pKey2) || (va1 != va2) || pKey1->fWin8Merge || pKey2->fWin8Merge) { continue; }
            // pointer match - merge keys in two different ways!
            if(pKey1->dwMode == MBDE_MODE_AES128) { pKey1->dwMode = MBDE_MODE_AES128_DIFFUSER; }
            if(pKey1->dwMode == MBDE_MODE_AES256) { pKey1->dwMode = MBDE_MODE_AES256_DIFFUSER; }
            if(pKey2->dwMode == MBDE_MODE_AES128) { pKey2->dwMode = MBDE_MODE_AES128_DIFFUSER; }
            if(pKey2->dwMode == MBDE_MODE_AES256) { pKey2->dwMode = MBDE_MODE_AES256_DIFFUSER; }
            memcpy(pKey1->pbKey2, pKey2->pbKey1, 32);
            memcpy(pKey2->pbKey2, pKey1->pbKey1, 32);
            MBDE_ContextKeyUpdate(ctxBDE, pKey1);
            MBDE_ContextKeyUpdate(ctxBDE, pKey2);
            pKey1->fWin8Merge = TRUE;
            pKey2->fWin8Merge = TRUE;
            VmmLog(H, ctxBDE->ctxP->MID, LOGLEVEL_TRACE, "Keys updated at %llx %llx", pKey1->va, pKey2->va);
            return;
        }
    }
}

/*
* Parse a Win10 14393+ bitlocker key.
* -- H
* -- ctxBDE
* -- pe
* -- pb
*/
VOID MBDE_Win10(_In_ VMM_HANDLE H, _In_ PMBDE_CONTEXT ctxBDE, _In_ PVMM_MAP_POOLENTRY pe, _In_ PBYTE pb)
{
    MBDE_KEY e = { 0 };
    MBDE_OFFSET o = { 0 };
    DWORD i, dw, cbKey, dwMode;
    BOOL fWin8 = (H->vmm.kernel.dwVersionBuild < 14393);
    if(pe->cb > 0x1000) { return; }
    if(H->vmm.f32) {
        // 32-bit
        if(pe->cb < (fWin8 ? 0x268UL : 0x400UL)) { return; }
        if(H->vmm.kernel.dwVersionBuild <= 17134) {
            o.o0 = 0x50; o.o1 = 0x54; o.o2 = 0x78; o.o3 = 0x98;
        } else {
            o.o0 = 0x54; o.o1 = 0x58; o.o2 = 0x7c; o.o3 = 0x9c;
        }
    } else {
        // 64-bit
        if(pe->cb < (fWin8 ? 0x290UL : 0x4c0UL)) { return; }
        o.o0 = 0x54; o.o1 = 0x58; o.o2 = 0x7c; o.o3 = 0x9c;
    }
    e.va = pe->va;
    e.cbBlob = pe->cb;
    for(i = 0; i < pe->cb - 0x80; i += 4) {
        if((*(PDWORD)(pb + i + 0x00) == 'UUUR') && (*(PDWORD)(pb + i + 0x20) == 'MSSK')) {
            if(!memcmp(e.pbKey1, pb + i + o.o1, 16)) { continue; }  // key already processed - continue!
            // length/signature:
            dw = *(PDWORD)(pb + i + o.o0);
            if((dw != 0x10) && (dw != 0x20) && (dw != 0x40)) {
                VmmLog(H, ctxBDE->ctxP->MID, LOGLEVEL_TRACE, "Failed candidate at %llx (signature)", pe->va);
                return;
            }
            // mode & length:
            dwMode = 0;
            if(!memcmp(pb + i + o.o1, pb + i + o.o2, 16)) {
                if(!memcmp(pb + i + o.o1, pb + i + o.o2, 32)) {
                    cbKey = 0x20;
                    dwMode = MBDE_MODE_AES256;
                } else {
                    cbKey = 0x10;
                    dwMode = MBDE_MODE_AES128;
                }
            }
            if(!memcmp(pb + i + o.o1, pb + i + o.o3, 16)) {
                if(!memcmp(pb + i + o.o1, pb + i + o.o3, 32)) {
                    cbKey = 0x40;
                    dwMode = MBDE_MODE_AES256_XTS;
                } else {
                    cbKey = 0x20;
                    dwMode = MBDE_MODE_AES128_XTS;
                }
            }
            if(!dwMode || (e.dwMode && (e.dwMode != dwMode))) {
                VmmLog(H, ctxBDE->ctxP->MID, LOGLEVEL_TRACE, "Failed candidate at %llx (mode #1)", pe->va);
                return;
            }
            e.cbKey = cbKey;
            e.dwMode = (BYTE)dwMode;
            // key:
            if(memcmp(e.pbKey1, pbMBDE_ZERO32, 32)) {
                // pre-existing key - this is a tweak key (diffuser)
                if((e.dwMode == MBDE_MODE_AES128_XTS) || (e.dwMode == MBDE_MODE_AES256_XTS)) {
                    VmmLog(H, ctxBDE->ctxP->MID, LOGLEVEL_TRACE, "Failed candidate at %llx (mode #2)", pe->va);
                    return;
                }
                e.dwMode = (e.cbKey == 16) ? MBDE_MODE_AES128_DIFFUSER : MBDE_MODE_AES256_DIFFUSER;
                memcpy(e.pbKey2, pb + i + o.o1, e.cbKey);
                break;
            } else {
                memcpy(e.pbKey12, pb + i + o.o1, e.cbKey);
            }
        }
    }
    // finish:
    if(!memcmp(e.pbKey1, pbMBDE_ZERO32, 32)) {
        VmmLog(H, ctxBDE->ctxP->MID, LOGLEVEL_TRACE, "Failed candidate at %llx (no key found)", pe->va);
        return;
    }
    MBDE_ContextKeyAdd(H, ctxBDE, &e, pb);
}

/*
* Parse a Win7 bitlocker key.
* -- H
* -- ctxBDE
* -- pe
* -- pb
*/
VOID MBDE_Win7(_In_ VMM_HANDLE H, _In_ PMBDE_CONTEXT ctxBDE, _In_ PVMM_MAP_POOLENTRY pe, _In_ PBYTE pb)
{
    MBDE_KEY e = { 0 };
    MBDE_OFFSET o = { 0 };
    // 1: initialize static offsets
    if(H->vmm.f32) {
        if(pe->cb == 0x1f0) { o.o0 = 0x10; o.o1 = 0x18; o.o2 = 0; }
        if(pe->cb == 0x3c8) { o.o0 = 0x10; o.o1 = 0x18; o.o2 = 0x1f0; }
    } else {
        if(pe->cb == 0x200) { o.o0 = 0x1c; o.o1 = 0x20; o.o2 = 0; }
        if(pe->cb == 0x3e0) { o.o0 = 0x1c; o.o1 = 0x20; o.o2 = 0x200; }
    }
    if(!o.o0) {
        VmmLog(H, ctxBDE->ctxP->MID, LOGLEVEL_TRACE, "Failed candidate at %llx [%i] (length)", pe->va, pe->cb);
        return;
    }
    // 2: parse mode & key
    if((pb[o.o0] > 0x03) || (pb[o.o0 + 1] != 0x80)) {
        VmmLog(H, ctxBDE->ctxP->MID, LOGLEVEL_TRACE, "Failed candidate at %llx (mode)", pe->va);
        return;
    }
    e.va = pe->va;
    e.cbBlob = pe->cb;
    e.dwMode = pb[o.o0];
    e.cbKey = ((e.dwMode == 0x00) || (e.dwMode == 0x02)) ? 16 : 32;
    memcpy(e.pbKey1, pb + o.o1, e.cbKey);
    if((e.dwMode == MBDE_MODE_AES128_DIFFUSER) || (e.dwMode == MBDE_MODE_AES256_DIFFUSER)) {
        memcpy(e.pbKey2, pb + o.o2, e.cbKey);
    }
    MBDE_ContextKeyAdd(H, ctxBDE, &e, pb);
}

/*
* Pool scanner function - locates bitlocker pool tags and send them onwards
* for analysis in os-dependent pfnCB callback function.
* -- H
* -- ctxBDE
* -- dwPoolTag
* -- pfnCB
*/
VOID MBDE_PoolScan(_In_ VMM_HANDLE H, _In_ PMBDE_CONTEXT ctxBDE, _In_ DWORD dwPoolTag, _In_ VOID(*pfnCB)(VMM_HANDLE H, PMBDE_CONTEXT, PVMM_MAP_POOLENTRY, PBYTE))
{
    DWORD i, j;
    BYTE pb[4096];
    PVMM_MAP_POOLENTRY pe;
    PVMM_MAP_POOLENTRYTAG pTag;
    for(i = 0; i < ctxBDE->pPoolMap->cTag; i++) {
        pTag = ctxBDE->pPoolMap->pTag + i;
        if(pTag->dwTag == dwPoolTag) {
            for(j = 0; j < pTag->cEntry; j++) {
                pe = ctxBDE->pPoolMap->pMap + ctxBDE->pPoolMap->piTag2Map[pTag->iTag2Map + j];
                if((pe->cb < sizeof(pb)) && VmmRead(H, PVMM_PROCESS_SYSTEM, pe->va, pb, pe->cb)) {
                    pfnCB(H, ctxBDE, pe, pb);
                }
            }
            return;
        }
    }
}

/*
* Build a new context with results.
* CALLER DECREF: return
* -- H
* -- ctxP
* -- return
*/
POB_MAP MBDE_ContextFetch_DoWork(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_CONTEXT ctxP)
{
    MBDE_CONTEXT ctxBDE = { 0 };
    DWORD dwBuild = H->vmm.kernel.dwVersionBuild;
    VmmLog(H, ctxP->MID, LOGLEVEL_TRACE, "Initialization started");
    // 1: context init
    ctxBDE.ctxP = ctxP;
    ctxBDE.pmBDE = ObMap_New(H, OB_MAP_FLAGS_OBJECT_LOCALFREE);
    VmmMap_GetPool(H, &ctxBDE.pPoolMap, TRUE);
    if(!ctxBDE.pmBDE || !ctxBDE.pPoolMap) {
        VmmLog(H, ctxP->MID, LOGLEVEL_VERBOSE, "Initialization failed: POOL/OOM");
        goto fail;
    }
    // 2: dispatch
    if(dwBuild >= 14393) {
        MBDE_PoolScan(H, &ctxBDE, 'enoN', MBDE_Win10);
    } else if(dwBuild >= 9200) {
        ctxBDE.fWin8 = TRUE;
        MBDE_PoolScan(H, &ctxBDE, 'bgnC', MBDE_Win10);
        MBDE_Win8_PostProcess(H, &ctxBDE);
    } else if(dwBuild >= 7600) {
        MBDE_PoolScan(H, &ctxBDE, 'cEVF', MBDE_Win7);
    }
    VmmLog(H, ctxP->MID, LOGLEVEL_TRACE, "Initialization completed");
fail:
    Ob_DECREF(ctxBDE.pPoolMap);
    return ctxBDE.pmBDE;
}

/*
* Fetch, and if required, build a new context with results.
* CALLER DECREF: return
* -- H
* -- ctxP
* -- return
*/
POB_MAP MBDE_ContextFetch(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_CONTEXT ctxP)
{
    POB_MAP pmObBDE = ObContainer_GetOb((POB_CONTAINER)ctxP->ctxM);
    if(!pmObBDE) {
        EnterCriticalSection(&H->vmm.LockPlugin);
        pmObBDE = ObContainer_GetOb((POB_CONTAINER)ctxP->ctxM);
        if(!pmObBDE) {
            pmObBDE = MBDE_ContextFetch_DoWork(H, ctxP);
            ObContainer_SetOb((POB_CONTAINER)ctxP->ctxM, pmObBDE);
        }
        LeaveCriticalSection(&H->vmm.LockPlugin);
    }
    return pmObBDE;
}



// ----------------------------------------------------------------------------
// PLUGIN ACCESS FUNCTIONALITY BELOW:
// ----------------------------------------------------------------------------

VOID MBDE_FcLogJSON(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_CONTEXT ctxP, _In_ VOID(*pfnLogJSON)(_In_ VMM_HANDLE H, _In_ PVMMDLL_FORENSIC_JSONDATA pData))
{
    DWORD i, cKey = 0;
    PMBDE_KEY pKey = NULL;
    POB_MAP pmObBDE = NULL;
    CHAR szDislocker[MAX_PATH];
    PVMMDLL_FORENSIC_JSONDATA pd = NULL;
    if(ctxP->pProcess) { return; }
    if(!(pmObBDE = MBDE_ContextFetch(H, ctxP))) { goto fail; }
    if(!(pd = LocalAlloc(LMEM_ZEROINIT, sizeof(VMMDLL_FORENSIC_JSONDATA)))) { goto fail; }
    pd->dwVersion = VMMDLL_FORENSIC_JSONDATA_VERSION;
    pd->szjType = "bitlocker";
    while((pKey = ObMap_GetNext(pmObBDE, pKey))) {
        for(i = 0; i < sizeof(pKey->pbDislocker); i++) {
            snprintf(szDislocker + i * 2ULL, 3, "%02x", pKey->pbDislocker[i]);
        }
        pd->i = cKey++;
        pd->vaObj = pKey->va;
        pd->usz[0] = szMBDE_MODE_STR[pKey->dwMode];
        pd->usz[1] = szDislocker;
        pfnLogJSON(H, pd);
    }
fail:
    Ob_DECREF(pmObBDE);
    LocalFree(pd);
}

NTSTATUS MBDE_ReadInternal(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_CONTEXT ctxP, _In_ POB_MAP pmObBDE, _Out_ LPVOID pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ ULONG64 cbOffset)
{
    PMBDE_KEY pKey = NULL;
    if(0 == _stricmp("readme.txt", ctxP->uszPath)) {
        return VMMDLL_UtilVfsReadFile_FromPBYTE(szMBDE_README, strlen(szMBDE_README), pb, cb, pcbRead, cbOffset);
    }
    while((pKey = ObMap_GetNext(pmObBDE, pKey))) {
        if(0 == _stricmp(pKey->szNameBIN, ctxP->uszPath)) {
            return VMMDLL_UtilVfsReadFile_FromPBYTE(pKey->pbBlob, pKey->cbBlob, pb, cb, pcbRead, cbOffset);
        }
        if(0 == _stricmp(pKey->szNameTXT, ctxP->uszPath)) {
            return VMMDLL_UtilVfsReadFile_FromPBYTE(pKey->szTXT, strlen(pKey->szTXT), pb, cb, pcbRead, cbOffset);
        }
        if(0 == _stricmp(pKey->szNameFVEK, ctxP->uszPath)) {
            return VMMDLL_UtilVfsReadFile_FromPBYTE(pKey->pbDislocker, sizeof(pKey->pbDislocker), pb, cb, pcbRead, cbOffset);
        }
    }
    return VMMDLL_STATUS_FILE_INVALID;
}

NTSTATUS MBDE_Read(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_CONTEXT ctxP, _Out_writes_to_(cb, *pcbRead) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ ULONG64 cbOffset)
{
    NTSTATUS nt = VMMDLL_STATUS_FILE_INVALID;
    POB_MAP pmObBDE = MBDE_ContextFetch(H, ctxP);
    *pcbRead = 0;
    if(pmObBDE) {
        nt = MBDE_ReadInternal(H, ctxP, pmObBDE, pb, cb, pcbRead, cbOffset);
    }
    Ob_DECREF(pmObBDE);
    return nt;
}

BOOL MBDE_List(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_CONTEXT ctxP, _Inout_ PHANDLE pFileList)
{
    PMBDE_KEY pKey = NULL;
    POB_MAP pmObBDE = MBDE_ContextFetch(H, ctxP);
    if(!ctxP->uszPath[0]) {
        VMMDLL_VfsList_AddFile(pFileList, "readme.txt", strlen(szMBDE_README), NULL);
        while((pKey = ObMap_GetNext(pmObBDE, pKey))) {
            VMMDLL_VfsList_AddFile(pFileList, pKey->szNameTXT, strlen(pKey->szTXT), NULL);
            VMMDLL_VfsList_AddFile(pFileList, pKey->szNameFVEK, 66, NULL);
            VMMDLL_VfsList_AddFile(pFileList, pKey->szNameBIN, pKey->cbBlob, NULL);
        }
    }
    Ob_DECREF(pmObBDE);
    return TRUE;
}

VOID MBDE_Notify(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_CONTEXT ctxP, _In_ DWORD fEvent, _In_opt_ PVOID pvEvent, _In_opt_ DWORD cbEvent)
{
    if(fEvent == VMMDLL_PLUGIN_NOTIFY_REFRESH_SLOW) {
        ObContainer_SetOb((POB_CONTAINER)ctxP->ctxM, NULL);
    }
}

VOID MBDE_Close(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_CONTEXT ctxP)
{
    Ob_DECREF((POB_CONTAINER)ctxP->ctxM);
}

VOID M_BDE_Initialize(_In_ VMM_HANDLE H, _Inout_ PVMMDLL_PLUGIN_REGINFO pRI)
{
    if((pRI->magic != VMMDLL_PLUGIN_REGINFO_MAGIC) || (pRI->wVersion != VMMDLL_PLUGIN_REGINFO_VERSION)) { return; }
    // the bitlocker plugin is only supported on: 64-bit Windows or 32-bit Windows 10 14393 or later.
    if((pRI->tpSystem != VMMDLL_SYSTEM_WINDOWS_32) && (pRI->tpSystem != VMMDLL_SYSTEM_WINDOWS_64)) { return; }
    if(pRI->sysinfo.dwVersionBuild < 7600) { return; }              // WIN7+ are supported
    if(!(pRI->reg_info.ctxM = (PVMMDLL_PLUGIN_INTERNAL_CONTEXT)ObContainer_New())) { return; }
    strcpy_s(pRI->reg_info.uszPathName, 128, "\\misc\\bitlocker");  // module name - 'bitlocker'.
    pRI->reg_info.fRootModule = TRUE;                               // module shows in root.
    pRI->reg_fn.pfnList = MBDE_List;                                // List function supported.
    pRI->reg_fn.pfnRead = MBDE_Read;                                // Read function supported.
    pRI->reg_fn.pfnNotify = MBDE_Notify;                            // Notify function supported.
    pRI->reg_fn.pfnClose = MBDE_Close;                              // Close function supported.
    pRI->reg_fnfc.pfnLogJSON = MBDE_FcLogJSON;                      // JSON log function supported
    pRI->pfnPluginManager_Register(H, pRI);                            // Register with the plugin manager
}
