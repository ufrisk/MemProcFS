// m_winreg.c : implementation related to the WinReg built-in module.
//
// (c) Ulf Frisk, 2019
// Author: Ulf Frisk, pcileech@frizk.net
//
#include "m_winreg.h"
#include "vmm.h"
#include "vmmwinreg.h"
#include "util.h"

_Success_(return)
BOOL MWinReg_Read_HiveFile(PVMMOB_REGISTRY_HIVE pHive, _Out_ PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset)
{
    DWORD cbReadBaseBlock;
    BYTE pbBaseBlock[0x1000] = { 0 };
    PVMM_PROCESS pObSystemProcess = NULL;
    *pcbRead = 0;
    if(!cb || (cbOffset >= pHive->cbLength + 0x1000ULL)) { return FALSE; }
    if(cbOffset + cb > pHive->cbLength + 0x1000ULL) {
        cb = (DWORD)(pHive->cbLength + 0x1000 - cbOffset);
    }
    *pcbRead = cb;
    // Read base block / regf (first 0x1000 bytes).
    if(cbOffset < 0x1000) {
        cbReadBaseBlock = (DWORD)min(cb, 0x1000 - cbOffset);
        if((pObSystemProcess = VmmProcessGet(4))) {
            VmmReadEx(pObSystemProcess, pHive->vaHBASE_BLOCK, pbBaseBlock, 0x1000, NULL, VMM_FLAG_ZEROPAD_ON_FAIL);
        }
        Ob_DECREF_NULL(&pObSystemProcess);
        memcpy(pb, pbBaseBlock + cbOffset, cbReadBaseBlock);
        cbOffset += cbReadBaseBlock;
        pb += cbReadBaseBlock;
        cb -= cbReadBaseBlock;
    }
    // read hive memory space
    if((cbOffset >= 0x1000) && cb) {
        VmmWinReg_HiveReadEx(pHive, (DWORD)(cbOffset - 0x1000), pb, cb, NULL, VMM_FLAG_ZEROPAD_ON_FAIL);
    }
    return TRUE;
}

_Success_(return)
BOOL MWinReg_Write_HiveFile(PVMMOB_REGISTRY_HIVE pHive, _In_ PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbWrite, _In_ QWORD cbOffset)
{
    DWORD cbWriteBaseBlock;
    PVMM_PROCESS pObSystemProcess = NULL;
    *pcbWrite = 0;
    if(!cb || (cbOffset >= pHive->cbLength + 0x1000ULL)) { return FALSE; }
    if(cbOffset + cb > pHive->cbLength + 0x1000ULL) {
        cb = (DWORD)(pHive->cbLength + 0x1000 - cbOffset);
    }
    *pcbWrite = cb;
    // Write base block / regf (first 0x1000 bytes).
    if(cbOffset < 0x1000) {
        cbWriteBaseBlock = (DWORD)min(cb, 0x1000 - cbOffset);
        if((pObSystemProcess = VmmProcessGet(4))) {
            VmmWrite(pObSystemProcess, (pHive->vaHBASE_BLOCK + (cbOffset & 0xfff)), pb, cbWriteBaseBlock);
        }
        Ob_DECREF_NULL(&pObSystemProcess);
        cbOffset += cbWriteBaseBlock;
        pb += cbWriteBaseBlock;
        cb -= cbWriteBaseBlock;
    }
    // write hive memory space
    if((cbOffset >= 0x1000) && cb) {
        VmmWinReg_HiveWrite(pHive, (DWORD)(cbOffset - 0x1000), pb, cb);
    }
    return TRUE;
}

NTSTATUS MWinReg_Read(_In_ PVMMDLL_PLUGIN_CONTEXT ctx, _Out_ PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset)
{
    PVMMOB_REGISTRY_HIVE pObHive = NULL;
    CHAR _szBuf[MAX_PATH] = { 0 };
    LPSTR szTopPath, szSubPath;
    Util_PathSplit2(ctx->szPath, _szBuf, &szTopPath, &szSubPath);
    if(!strcmp(szTopPath, "hive_files")) {
        pObHive = VmmWinReg_HiveGetByAddress(Util_GetNumeric(szSubPath));
        if(!pObHive) { return VMMDLL_STATUS_FILE_INVALID; }
        MWinReg_Read_HiveFile(pObHive, pb, cb, pcbRead, cbOffset);
        Ob_DECREF(pObHive);
        return VMMDLL_STATUS_SUCCESS;
    }
    return VMMDLL_STATUS_FILE_INVALID;
}

NTSTATUS MWinReg_Write(_In_ PVMMDLL_PLUGIN_CONTEXT ctx, _In_ PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbWrite, _In_ QWORD cbOffset)
{
    PVMMOB_REGISTRY_HIVE pObHive = NULL;
    CHAR _szBuf[MAX_PATH] = { 0 };
    LPSTR szTopPath, szSubPath;
    Util_PathSplit2(ctx->szPath, _szBuf, &szTopPath, &szSubPath);
    if(!strcmp(szTopPath, "hive_files")) {
        pObHive = VmmWinReg_HiveGetByAddress(Util_GetNumeric(szSubPath));
        if(!pObHive) { return VMMDLL_STATUS_FILE_INVALID; }
        MWinReg_Write_HiveFile(pObHive, pb, cb, pcbWrite, cbOffset);
        Ob_DECREF(pObHive);
        return VMMDLL_STATUS_SUCCESS;
    }
    return VMMDLL_STATUS_FILE_INVALID;
}

BOOL MWinReg_List(_In_ PVMMDLL_PLUGIN_CONTEXT ctx, _Inout_ PHANDLE pFileList)
{
    PVMMOB_REGISTRY_HIVE pObHive = NULL;
    if(!ctx->szPath[0]) {
        VMMDLL_VfsList_AddDirectory(pFileList, "hive_files");
        return TRUE;
    }
    if(!strcmp(ctx->szPath, "hive_files")) {
        while((pObHive = VmmWinReg_HiveGetNext(pObHive))) {
            VMMDLL_VfsList_AddFile(pFileList, pObHive->szName, pObHive->cbLength + 0x1000ULL);
        }
        return TRUE;
    }
    return FALSE;
}

VOID M_WinReg_Initialize(_Inout_ PVMMDLL_PLUGIN_REGINFO pRI)
{
    if((pRI->magic != VMMDLL_PLUGIN_REGINFO_MAGIC) || (pRI->wVersion != VMMDLL_PLUGIN_REGINFO_VERSION)) { return; }
    if((pRI->tpSystem != VMM_SYSTEM_WINDOWS_X64) && (pRI->tpSystem != VMM_SYSTEM_WINDOWS_X86)) { return; }
    strcpy_s(pRI->reg_info.szModuleName, 32, "registry");   // module name
    pRI->reg_info.fRootModule = TRUE;                       // module shows in root directory
    pRI->reg_fn.pfnList = MWinReg_List;                     // List function supported
    pRI->reg_fn.pfnRead = MWinReg_Read;                     // Read function supported
    pRI->reg_fn.pfnWrite = MWinReg_Write;                   // Write function supported
    pRI->pfnPluginManager_Register(pRI);
}
