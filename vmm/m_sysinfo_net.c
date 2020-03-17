// m_sysinfo_net.c : implementation related to the SysInfo/Net built-in module.
//
// The SysInfo/Net module is responsible for displaying networking information
// in a 'netstat' like way at the path '/sysinfo/net/'
//
// (c) Ulf Frisk, 2020
// Author: Ulf Frisk, pcileech@frizk.net
//
#include <ws2tcpip.h>
#include "vmm.h"
#include "vmmwin.h"
#include "vmmwintcpip.h"
#include "util.h"

LPCSTR szMSYSINFONET_README =
"Information about the sysinfo net module                                     \n" \
"========================================                                     \n" \
"The sysinfo net module tries to enumerate and list active TCP connections in \n" \
"Windows 7 and later (x64 only).  It currently does not support listening TCP \n" \
"ports or UDP ports. This functionality is planned for the future. Also, it's \n" \
"not supporting 32-bit or Windows Vista/XP (future support less likely).      \n" \
"For more information please visit: https://github.com/ufrisk/MemProcFS/wiki  \n";

// ----------------------------------------------------------------------------
// Net functionality below:
// Show information related to TCP/IP connectivity in the analyzed system.
// ----------------------------------------------------------------------------

#define MSYSINFONET_CACHE_MAXAGE   500      // ms

typedef struct tdMSYSINFONET_OB_CONTEXT {
    OB ObHdr;
    QWORD qwCreateTimeTickCount64;
    DWORD cbFile;
    PBYTE pbFile;
    DWORD cbFileVerbose;
    PBYTE pbFileVerbose;
} MSYSINFONET_OB_CONTEXT, *PMSYSINFONET_OB_CONTEXT;

PMSYSINFONET_OB_CONTEXT gp_MSYSINFO_OB_NETCONTEXT = NULL;

VOID MSysInfoNet_ObContext_CallbackRefCount1(PMSYSINFONET_OB_CONTEXT pOb)
{
    LocalFree(pOb->pbFile);
    LocalFree(pOb->pbFileVerbose);
}

/*
* Format network connection into into human readable text.
*/
_Success_(return)
BOOL MSysInfoNet_GetContext_ToString(_In_ PVMMWIN_TCPIP_ENTRY pTcpE, _In_ DWORD cTcpE, _Out_ PBYTE *ppbFileN, _Out_ PDWORD pcbFileN, _Out_ PBYTE *ppbFileV, _Out_ PDWORD pcbFileV)
{
    BOOL fResult = FALSE;
    PVMMWIN_TCPIP_ENTRY pE;
    DWORD i, oN = 0, oV = 0, dwIpVersion;
    DWORD cbN = 0x00100000, cbV = 0x00100000;
    PBYTE pbN = NULL, pbV = NULL;
    PVMM_PROCESS pObProcess = NULL;
    DWORD cchSrc, cchDst;
    CHAR sz[64], szSrc[64], szDst[64], szTime[MAX_PATH];
    if(!(pbN = LocalAlloc(0, cbN))) { goto fail; }
    if(!(pbV = LocalAlloc(0, cbV))) { goto fail; }

    for(i = 0; i < cTcpE; i++) {
        pE = pTcpE + i;
        pObProcess = VmmProcessGet(pE->dwPID);
        dwIpVersion = (pE->AF.wAF == AF_INET) ? 4 : ((pE->AF.wAF == AF_INET6) ? 6 : 0);
        // format src addr
        if(pE->Src.fValid) {
            sz[0] = 0;
            InetNtopA(pE->AF.wAF, pE->Src.pbA, sz, sizeof(sz));
        } else {
            strcpy_s(sz, sizeof(sz), "***");
        }
        cchSrc = snprintf(szSrc, sizeof(szSrc), ((dwIpVersion == 6) ? "[%s]:%i" : "%s:%i"), sz, pE->Src.wPort);
        // format dst addr
        if(pE->Dst.fValid) {
            sz[0] = 0;
            InetNtopA(pE->AF.wAF, pE->Dst.pbA, sz, sizeof(sz));
        } else {
            strcpy_s(sz, sizeof(sz), "***");
        }
        cchDst = snprintf(szDst, sizeof(szDst), ((dwIpVersion == 6) ? "[%s]:%i" : "%s:%i"), sz, pE->Dst.wPort);
        // get time
        Util_FileTime2String((PFILETIME)&pE->qwTime, szTime);
        // print normal
        oN += snprintf(
            pbN + oN,
            (QWORD)cbN + oN,
            "TCPv%i  %-*s  %-*s  %-11s %6i  %s\n",
            dwIpVersion,
            max(28, cchSrc),
            szSrc,
            max(28, cchDst),
            szDst,
            pE->szState,
            pE->dwPID,
            (pObProcess ? pObProcess->szName : "***")
        );
        // print verbose
        oV += snprintf(
            pbV + oV,
            (QWORD)cbV + oV,
            "TCPv%i  %-*s  %-*s  %-11s  %s %6i  %-15s %S\n",
            dwIpVersion,
            max(28, cchSrc),
            szSrc,
            max(28, cchDst),
            szDst,
            pE->szState,
            szTime,
            pE->dwPID,
            (pObProcess ? pObProcess->szName : "***"),
            (pObProcess ? pObProcess->pObPersistent->wszPathKernel : L"***")
        );
        Ob_DECREF_NULL(&pObProcess);
    }
    // move result into properly sized buffers
    if(!(*ppbFileN = LocalAlloc(0, oN))) { goto fail; }
    if(!(*ppbFileV = LocalAlloc(0, oV))) { goto fail; }
    memcpy(*ppbFileN, pbN, oN);
    memcpy(*ppbFileV, pbV, oV);
    *pcbFileN = oN;
    *pcbFileV = oV;
    fResult = TRUE;
fail:
    LocalFree(pbN);
    LocalFree(pbV);
    return fResult;
}

/*
* Retrieve a net context containing the processed data as an object manager object.
* CALLER DECREF: return
* -- return
*/
PMSYSINFONET_OB_CONTEXT MSysInfoNet_GetContext()
{
    DWORD cTcpE;
    PVMMWIN_TCPIP_ENTRY pTcpE = NULL;
    PMSYSINFONET_OB_CONTEXT pObCtx;
    EnterCriticalSection(&ctxVmm->TcpIp.LockUpdate);
    // 1: check if cached version is ok
    pObCtx = gp_MSYSINFO_OB_NETCONTEXT;
    if(pObCtx && (pObCtx->qwCreateTimeTickCount64 + MSYSINFONET_CACHE_MAXAGE > GetTickCount64())) {
        Ob_INCREF(pObCtx);
        goto finish;
    }
    // 2: replace with new version
    if(!VmmWinTcpIp_TcpE_Get(&pTcpE, &cTcpE)) { goto finish; }
    Ob_DECREF_NULL(&gp_MSYSINFO_OB_NETCONTEXT);
    pObCtx = gp_MSYSINFO_OB_NETCONTEXT = Ob_Alloc('IP__', LMEM_ZEROINIT, sizeof(MSYSINFONET_OB_CONTEXT), MSysInfoNet_ObContext_CallbackRefCount1, NULL);
    if(!pObCtx) { goto finish; }    // alloc failed - should not happen -> finish and return NULL
    MSysInfoNet_GetContext_ToString(pTcpE, cTcpE, &pObCtx->pbFile, &pObCtx->cbFile, &pObCtx->pbFileVerbose, &pObCtx->cbFileVerbose);
    pObCtx->qwCreateTimeTickCount64 = GetTickCount64();
    Ob_INCREF(pObCtx);
finish:
    LeaveCriticalSection(&ctxVmm->TcpIp.LockUpdate);
    LocalFree(pTcpE);
    return pObCtx;
}

NTSTATUS MSysInfoNet_Read(_In_ PVMMDLL_PLUGIN_CONTEXT ctx, _Out_ PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset)
{
    NTSTATUS nt = VMMDLL_STATUS_FILE_INVALID;
    PMSYSINFONET_OB_CONTEXT pObNetCtx;
    if(!wcscmp(ctx->wszPath, L"readme.txt")) {
        return Util_VfsReadFile_FromPBYTE((PBYTE)szMSYSINFONET_README, strlen(szMSYSINFONET_README), pb, cb, pcbRead, cbOffset);
    }
    if((pObNetCtx = MSysInfoNet_GetContext())) {
        if(!wcscmp(ctx->wszPath, L"netstat.txt")) {
            nt = Util_VfsReadFile_FromPBYTE(pObNetCtx->pbFile, pObNetCtx->cbFile, pb, cb, pcbRead, cbOffset);
        }
        if(!wcscmp(ctx->wszPath, L"netstat-v.txt")) {
            nt = Util_VfsReadFile_FromPBYTE(pObNetCtx->pbFileVerbose, pObNetCtx->cbFileVerbose, pb, cb, pcbRead, cbOffset);
        }
        Ob_DECREF(pObNetCtx);
    }
    return nt;
}

BOOL MSysInfoNet_List(_In_ PVMMDLL_PLUGIN_CONTEXT ctx, _Inout_ PHANDLE pFileList)
{
    PMSYSINFONET_OB_CONTEXT pObNetCtx;
    if(ctx->wszPath[0]) { return FALSE; }
    VMMDLL_VfsList_AddFile(pFileList, L"readme.txt", strlen(szMSYSINFONET_README), NULL);
    if((pObNetCtx = MSysInfoNet_GetContext())) {
        VMMDLL_VfsList_AddFile(pFileList, L"netstat.txt", pObNetCtx->cbFile, NULL);
        VMMDLL_VfsList_AddFile(pFileList, L"netstat-v.txt", pObNetCtx->cbFileVerbose, NULL);
        Ob_DECREF(pObNetCtx);
    }
    return TRUE;
}

VOID MSysInfoNet_Close()
{
    Ob_DECREF_NULL(&gp_MSYSINFO_OB_NETCONTEXT);
}

VOID M_SysInfoNet_Initialize(_Inout_ PVMMDLL_PLUGIN_REGINFO pRI)
{
    if((pRI->magic != VMMDLL_PLUGIN_REGINFO_MAGIC) || (pRI->wVersion != VMMDLL_PLUGIN_REGINFO_VERSION)) { return; }
    if((pRI->tpSystem != VMM_SYSTEM_WINDOWS_X64) && (pRI->tpSystem != VMM_SYSTEM_WINDOWS_X86)) { return; }
    wcscpy_s(pRI->reg_info.wszPathName, 128, L"\\sysinfo\\net");    // module name
    pRI->reg_info.fRootModule = TRUE;                               // module shows in root directory
    pRI->reg_fn.pfnList = MSysInfoNet_List;                         // List function supported
    pRI->reg_fn.pfnRead = MSysInfoNet_Read;                         // Read function supported
    pRI->reg_fn.pfnClose = MSysInfoNet_Close;                       // Close function supported
    pRI->pfnPluginManager_Register(pRI);
}
