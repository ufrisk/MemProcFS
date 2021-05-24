// m_sys_driver.c : implementation related to the sys/drivers built-in module.
//
// The 'sys/drivers' module lists various aspects of drivers from the windows
// kernel object manager.
//
// (c) Ulf Frisk, 2021
// Author: Ulf Frisk, pcileech@frizk.net
//
#include "vmm.h"
#include "charutil.h"
#include "util.h"
#include "pluginmanager.h"
#include "vmmwinobj.h"
#include "vmmwindef.h"

#define MSYSDRIVER_DRV_LINELENGTH                  128ULL
#define MSYSDRIVER_IRP_LINELENGTH                  88ULL
#define MSYSDRIVER_DRV_LINEHEADER     "   #   Object Address Driver               Size Drv Range: Start-End              Service Key      Driver Name"
#define MSYSDRIVER_IRP_LINEHEADER     "   # Driver            # IRP_MJ_*                          Address Target Module"

#define MSYSDRIVER_IRP_STR (LPCSTR[]){ \
    "CREATE",                   \
    "CREATE_NAMED_PIPE",        \
    "CLOSE",                    \
    "READ",                     \
    "WRITE",                    \
    "QUERY_INFORMATION",        \
    "SET_INFORMATION",          \
    "QUERY_EA",                 \
    "SET_EA",                   \
    "FLUSH_BUFFERS",            \
    "QUERY_VOLUME_INFORMATION", \
    "SET_VOLUME_INFORMATION",   \
    "DIRECTORY_CONTROL",        \
    "FILE_SYSTEM_CONTROL",      \
    "DEVICE_CONTROL",           \
    "INTERNAL_DEVICE_CONTROL",  \
    "SHUTDOWN",                 \
    "LOCK_CONTROL",             \
    "CLEANUP",                  \
    "CREATE_MAILSLOT",          \
    "QUERY_SECURITY",           \
    "SET_SECURITY",             \
    "POWER",                    \
    "SYSTEM_CONTROL",           \
    "DEVICE_CHANGE",            \
    "QUERY_QUOTA",              \
    "SET_QUOTA",                \
    "PNP" }

typedef struct tdMSYSDRIVER_IRP_CONTEXT {
    PVMMOB_MAP_PTE pPteMap;
    PVMMOB_MAP_KDRIVER pDrvMap;
} MSYSDRIVER_IRP_CONTEXT, *PMSYSDRIVER_IRP_CONTEXT;

/*
* Comparison function to efficiently locate a single PTE given address and map.
*/
int MSysDriver_PteCmpFind(_In_ PVOID va, _In_ PVMM_MAP_PTEENTRY pe)
{
    if((QWORD)va < pe->vaBase) { return -1; }
    if((QWORD)va > pe->vaBase + (pe->cPages << 12) - 1) { return 1; }
    return 0;
}

/*
* Line callback function to print a single driver/irp line.
*/
VOID MSysDriver_IrpReadLine_Callback(_In_ PMSYSDRIVER_IRP_CONTEXT ctx, _In_ DWORD cbLineLength, _In_ DWORD ie, _In_ PVOID pv, _Out_writes_(cbLineLength + 1) LPSTR usz)
{
    PVMM_MAP_PTEENTRY pePte;
    PVMM_MAP_KDRIVERENTRY pe;
    QWORD vaIrp;
    DWORD iDrv, iIrp;
    LPSTR uszTxt = "?";
    iDrv = ie / 28;
    iIrp = ie % 28;
    pe = ctx->pDrvMap->pMap + iDrv;
    vaIrp = pe->MajorFunction[iIrp];
    if(vaIrp == ctxVmm->kernel.opt.vaIopInvalidDeviceRequest) {
        uszTxt = "---";
    } else if((vaIrp >= pe->vaStart) && (vaIrp < pe->vaStart + pe->cbDriverSize)) {
        uszTxt = pe->uszName;
    } else if((pePte = Util_qfind((PVOID)vaIrp, ctx->pPteMap->cMap, ctx->pPteMap->pMap, sizeof(VMM_MAP_PTEENTRY), (UTIL_QFIND_CMP_PFN)MSysDriver_PteCmpFind))) {
        uszTxt = pePte->uszText;
    }
    Util_usnprintf_ln(usz, cbLineLength,
        "%04x %-16.16s %2i %-24.24s %16llx %s",
        ie,
        pe->uszName,
        iIrp,
        MSYSDRIVER_IRP_STR[iIrp],
        vaIrp,
        uszTxt
    );
}

VOID MSysDriver_DrvReadLine_Callback(_Inout_opt_ PVOID ctx, _In_ DWORD cbLineLength, _In_ DWORD ie, _In_ PVMM_MAP_KDRIVERENTRY pe, _Out_writes_(cbLineLength + 1) LPSTR usz)
{
    Util_usnprintf_ln(usz, cbLineLength,
        "%04x %16llx %-16.16s %8llx %16llx-%16llx %-16.16s %s",
        ie,
        pe->va,
        pe->uszName,
        pe->cbDriverSize,
        pe->vaStart,
        pe->cbDriverSize ? (pe->vaStart + pe->cbDriverSize - 1) : pe->vaStart,
        pe->uszServiceKeyName,
        pe->uszPath
    );
}

_Success_(return)
BOOL MSysDriver_EntryFromPath(_In_ LPSTR uszPath, _In_ PVMMOB_MAP_KDRIVER pDrvMap, _Out_ PVMM_MAP_KDRIVERENTRY *ppDrvMapEntry, _Out_opt_ LPSTR *puszPath)
{
    DWORD i, dwHash;
    CHAR usz[MAX_PATH];
    if(_strnicmp(uszPath, "by-name\\", 8)) { return FALSE; }
    CharUtil_PathSplitFirst(uszPath + 8, usz, sizeof(usz));
    dwHash = CharUtil_HashNameFsU(usz, 0);
    for(i = 0; i < pDrvMap->cMap; i++) {
        if(dwHash == pDrvMap->pMap[i].dwHash) {
            if(puszPath) { *puszPath = uszPath + 8; }
            *ppDrvMapEntry = pDrvMap->pMap + i;
            return TRUE;
        }
    }
    return FALSE;
}

NTSTATUS MSysDriver_Read(_In_ PVMMDLL_PLUGIN_CONTEXT ctx, _Out_writes_to_(cb, *pcbRead) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset)
{
    NTSTATUS nt = VMMDLL_STATUS_FILE_INVALID;
    PVMM_MAP_KDRIVERENTRY pe;
    PVMMOB_MAP_PTE pObPteMap = NULL;
    PVMMOB_MAP_KDRIVER pObDrvMap = NULL;
    PVMM_PROCESS pObSystemProcess = NULL;
    MSYSDRIVER_IRP_CONTEXT IrpCtx = { 0 };
    if(!VmmMap_GetKDriver(&pObDrvMap)) { goto cleanup; }
    if(!_stricmp(ctx->uszPath, "drivers.txt")) {
        nt = Util_VfsLineFixed_Read(
            (UTIL_VFSLINEFIXED_PFN_CB)MSysDriver_DrvReadLine_Callback, NULL, MSYSDRIVER_DRV_LINELENGTH, MSYSDRIVER_DRV_LINEHEADER,
            pObDrvMap->pMap, pObDrvMap->cMap, sizeof(VMM_MAP_KDRIVERENTRY),
            pb, cb, pcbRead, cbOffset
        );
        goto cleanup;
    }
    if(!_stricmp(ctx->uszPath, "driver_irp.txt")) {
        if(!(pObSystemProcess = VmmProcessGet(4))) { goto cleanup; }
        if(!VmmMap_GetPte(pObSystemProcess, &pObPteMap, TRUE)) { goto cleanup; }
        IrpCtx.pDrvMap = pObDrvMap;
        IrpCtx.pPteMap = pObPteMap;
        nt = Util_VfsLineFixed_Read(
            (UTIL_VFSLINEFIXED_PFN_CB)MSysDriver_IrpReadLine_Callback, &IrpCtx, MSYSDRIVER_IRP_LINELENGTH, MSYSDRIVER_IRP_LINEHEADER,
            pObDrvMap->pMap, pObDrvMap->cMap * 28ULL, 0,
            pb, cb, pcbRead, cbOffset
        );
        goto cleanup;
    }
    if(!_strnicmp("by-name\\", ctx->uszPath, 8)) {
        if(MSysDriver_EntryFromPath(ctx->uszPath, pObDrvMap, &pe, NULL)) {
            nt = VmmWinObjDisplay_VfsRead(ctx->uszPath, ctxVmm->ObjectTypeTable.tpDriver, pe->va, pb, cb, pcbRead, cbOffset);
            goto cleanup;
        }
    }
cleanup:
    Ob_DECREF(pObDrvMap);
    Ob_DECREF(pObPteMap);
    Ob_DECREF(pObSystemProcess);
    return nt;
}

BOOL MSysDriver_List(_In_ PVMMDLL_PLUGIN_CONTEXT ctx, _Inout_ PHANDLE pFileList)
{
    DWORD i;
    LPSTR uszPath;
    PVMM_MAP_KDRIVERENTRY pe;
    PVMMOB_MAP_KDRIVER pObDrvMap = NULL;
    if(!VmmMap_GetKDriver(&pObDrvMap)) { goto finish; }
    if(!ctx->uszPath[0]) {
        VMMDLL_VfsList_AddDirectory(pFileList, "by-name", NULL);
        VMMDLL_VfsList_AddFile(pFileList, "drivers.txt", UTIL_VFSLINEFIXED_LINECOUNT(pObDrvMap->cMap) * MSYSDRIVER_DRV_LINELENGTH, NULL);
        VMMDLL_VfsList_AddFile(pFileList, "driver_irp.txt", UTIL_VFSLINEFIXED_LINECOUNT(pObDrvMap->cMap * 28ULL) * MSYSDRIVER_IRP_LINELENGTH, NULL);
        goto finish;
    }
    if(!_stricmp(ctx->uszPath, "by-name")) {
        for(i = 0; i < pObDrvMap->cMap; i++) {
            VMMDLL_VfsList_AddDirectory(pFileList, pObDrvMap->pMap[i].uszName, NULL);
        }
        goto finish;
    }
    if(MSysDriver_EntryFromPath(ctx->uszPath, pObDrvMap, &pe, &uszPath) && uszPath[0]) {
        VmmWinObjDisplay_VfsList(ctxVmm->ObjectTypeTable.tpDriver, pe->va, pFileList);
        goto finish;
    }
finish:
    Ob_DECREF(pObDrvMap);
    return TRUE;
}

VOID MSysDriver_FcLogJSON(_In_ PVMMDLL_PLUGIN_CONTEXT ctxP, _In_ VOID(*pfnLogJSON)(_In_ PVMMDLL_PLUGIN_FORENSIC_JSONDATA pData))
{
    PVMMDLL_PLUGIN_FORENSIC_JSONDATA pd;
    PVMMOB_MAP_KDRIVER pObDrvMap = NULL;
    PVMM_MAP_KDRIVERENTRY pe;
    DWORD i;
    CHAR usz[MAX_PATH];
    if(ctxP->pProcess || !(pd = LocalAlloc(LMEM_ZEROINIT, sizeof(VMMDLL_PLUGIN_FORENSIC_JSONDATA)))) { return; }
    pd->dwVersion = VMMDLL_PLUGIN_FORENSIC_JSONDATA_VERSION;
    pd->szjType = "driver";
    if(VmmMap_GetKDriver(&pObDrvMap)) {
        for(i = 0; i < pObDrvMap->cMap; i++) {
            pe = pObDrvMap->pMap + i;
            pd->i = i;
            pd->vaObj = pe->va;
            pd->qwNum[0] = pe->cbDriverSize;
            pd->va[0] = pe->vaStart;
            pd->va[1] = pe->cbDriverSize ? (pe->vaStart + pe->cbDriverSize - 1) : pe->vaStart;
            pd->usz[0] = pe->uszName;
            snprintf(usz, sizeof(usz), "svc:[%s] path:[%s]", pe->uszServiceKeyName, pe->uszPath);
            pd->usz[1] = usz;
            pfnLogJSON(pd);
        }
    }
    Ob_DECREF(pObDrvMap);
    LocalFree(pd);
}

VOID M_SysDriver_Initialize(_Inout_ PVMMDLL_PLUGIN_REGINFO pRI)
{
    if((pRI->magic != VMMDLL_PLUGIN_REGINFO_MAGIC) || (pRI->wVersion != VMMDLL_PLUGIN_REGINFO_VERSION)) { return; }
    if((pRI->tpSystem != VMM_SYSTEM_WINDOWS_X64) && (pRI->tpSystem != VMM_SYSTEM_WINDOWS_X86)) { return; }
    if(pRI->sysinfo.dwVersionBuild < 7600) { return; }              // WIN7+ required
    strcpy_s(pRI->reg_info.uszPathName, 128, "\\sys\\drivers");     // module name
    pRI->reg_info.fRootModule = TRUE;                               // module shows in root directory
    pRI->reg_fn.pfnList = MSysDriver_List;                          // List function supported
    pRI->reg_fn.pfnRead = MSysDriver_Read;                          // Read function supported
    pRI->reg_fnfc.pfnLogJSON = MSysDriver_FcLogJSON;                // JSON log function supported
    pRI->pfnPluginManager_Register(pRI);
}
