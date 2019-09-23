// m_winreg.c : implementation related to the WinReg built-in module.
//
// (c) Ulf Frisk, 2019
// Author: Ulf Frisk, pcileech@frizk.net
//
#include "m_winreg.h"
#include "vmm.h"
#include "vmmwinreg.h"
#include "util.h"

#define KEY_META_BUFFER_SIZE            0xA000

_Success_(return)
BOOL MWinReg_Read_HiveFile(POB_REGISTRY_HIVE pHive, _Out_writes_(*pcbRead) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset)
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
BOOL MWinReg_Write_HiveFile(POB_REGISTRY_HIVE pHive, _In_ PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbWrite, _In_ QWORD cbOffset)
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

/*
* Helper function for MWinReg_Read_KeyValue to calculate the size of hexascii (binary) meta-data
*/
DWORD MWinReg_Read_KeyValue_GetHexAscii(_In_ LPSTR szKeyName, _In_ PBYTE pbData, _In_ DWORD cbData, _Out_writes_(KEY_META_BUFFER_SIZE) LPSTR szMeta)
{
    DWORD i, cszMeta = snprintf(szMeta, KEY_META_BUFFER_SIZE, "%s\n", szKeyName);
    if(cbData) {
        i = KEY_META_BUFFER_SIZE - cszMeta;
        if(Util_FillHexAscii(pbData, min(KEY_META_BUFFER_SIZE / 5, cbData), 0, szMeta + cszMeta, &i)) {
            cszMeta += i;
        }
    }
    return cszMeta;
}

DWORD MWinReg_Read_KeyValue_GetAscii(_In_ LPSTR szKeyName, _In_ LPWSTR wszData, _In_ DWORD cbData, _Out_writes_(KEY_META_BUFFER_SIZE) LPSTR szMeta)
{
    WCHAR c;
    DWORD o, cszMeta;
    strncpy_s(szMeta, KEY_META_BUFFER_SIZE, szKeyName, _TRUNCATE);
    cszMeta = (DWORD)strlen(szKeyName);
    szMeta[cszMeta++] = '\n';
    if(cbData > 2) {
        for(o = 0; (o < (cbData >> 1) - 1) && (cszMeta < KEY_META_BUFFER_SIZE - 2); o++) {
            c = wszData[o];
            c = (c < 128 && c != '\n') ? UTIL_PRINTASCII[c] : ((c < 256) ? c : '.');
            szMeta[cszMeta++] = (CHAR)c;
        }
        szMeta[cszMeta++] = '\n';
    }
    szMeta[cszMeta] = 0;
    return cszMeta;
}

NTSTATUS MWinReg_Read_KeyValue(_In_ LPWSTR wszPathFull, _Out_ PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset)
{
    NTSTATUS nt = VMMDLL_STATUS_FILE_INVALID;
    POB_REGISTRY_HIVE pObHive = NULL;
    WCHAR wszSubPath[MAX_PATH];
    DWORD i, cwszSubPath, dwType, cszMeta;
    DWORD cbData;
    PBYTE pbData = NULL;
    LPSTR szMeta = NULL;
    if(!VmmWinReg_PathHiveGetByFullPath(wszPathFull, &pObHive, wszSubPath)) { goto finish; }
    cwszSubPath = (DWORD)wcslen(wszSubPath);
    if((cwszSubPath < 5) || wcscmp(wszSubPath + cwszSubPath - 4, L".txt")) {
        // raw registry value - i.e not metadata
        nt = VmmWinReg_ValueQuery1(pObHive, wszSubPath, NULL, pb, cb, pcbRead, cbOffset) ? VMMDLL_STATUS_SUCCESS : VMMDLL_STATUS_END_OF_FILE;
        goto finish;
    }
    // metadata file below:
    wszSubPath[cwszSubPath - 4] = 0;
    // allocate buffers and read value
    if(!(szMeta = (LPSTR)LocalAlloc(0, KEY_META_BUFFER_SIZE))) { goto finish; }
    if(!(pbData = LocalAlloc(LMEM_ZEROINIT, KEY_META_BUFFER_SIZE))) { goto finish; }
    VmmWinReg_ValueQuery1(pObHive, wszSubPath, &dwType, pbData, KEY_META_BUFFER_SIZE, &cbData, 0) || VmmWinReg_ValueQuery1(pObHive, wszSubPath, &dwType, NULL, 0, &cbData, 0);
    // process read data
    switch(dwType) {
        case REG_NONE:
            cszMeta = snprintf(szMeta, KEY_META_BUFFER_SIZE, "REG_NONE\n");
            break;
        case REG_SZ:
            cszMeta = MWinReg_Read_KeyValue_GetAscii("REG_SZ", (LPWSTR)pbData, cbData, szMeta);
            break;
        case REG_EXPAND_SZ:
            cszMeta = MWinReg_Read_KeyValue_GetAscii("REG_EXPAND_SZ", (LPWSTR)pbData, cbData, szMeta);
            break;
        case REG_BINARY:
            cszMeta = MWinReg_Read_KeyValue_GetHexAscii("REG_BINARY", pbData, cbData, szMeta);
            break;
        case REG_DWORD:
            cszMeta = snprintf(szMeta, KEY_META_BUFFER_SIZE, "REG_DWORD\n%08x\n", *(PDWORD)pbData);
            break;
        case REG_DWORD_BIG_ENDIAN:
            cszMeta = snprintf(szMeta, KEY_META_BUFFER_SIZE, "REG_DWORD_BIG_ENDIAN\n%2x%2x%2x%2x\n", pbData[0], pbData[1], pbData[2], pbData[3]);
            break;
        case REG_LINK:
            cszMeta = MWinReg_Read_KeyValue_GetAscii("REG_LINK", (LPWSTR)pbData, cbData, szMeta);
            break;
        case REG_MULTI_SZ:
            for(i = 0; (cbData >= 6) && (i < cbData - 4); i += 2) { // replace NULL WCHAR between strings with newline
                if(!*(LPWSTR)(pbData + i)) {
                    *(LPWSTR)(pbData + i) = '\n';
                }
            }
            cszMeta = MWinReg_Read_KeyValue_GetAscii("REG_MULTI_SZ", (LPWSTR)pbData, (cbData < 2 ? 0 : cbData - 2), szMeta);
            break;
        case REG_RESOURCE_LIST:
            cszMeta = MWinReg_Read_KeyValue_GetHexAscii("REG_RESOURCE_LIST", pbData, cbData, szMeta);
            break;
        case REG_FULL_RESOURCE_DESCRIPTOR:
            cszMeta = MWinReg_Read_KeyValue_GetHexAscii("REG_FULL_RESOURCE_DESCRIPTOR", pbData, cbData, szMeta);
            break;
        case REG_RESOURCE_REQUIREMENTS_LIST:
            cszMeta = MWinReg_Read_KeyValue_GetHexAscii("REG_RESOURCE_REQUIREMENTS_LIST", pbData, cbData, szMeta);
            break;
        case REG_QWORD:
            cszMeta = snprintf(szMeta, KEY_META_BUFFER_SIZE, "REG_QWORD\n%016llx\n", *(PQWORD)pbData);
            break;
        default:
            cszMeta = MWinReg_Read_KeyValue_GetHexAscii("REG_UNKNOWN", pbData, cbData, szMeta);
            break;
    }
    Util_VfsReadFile_FromPBYTE(szMeta, cszMeta, pb, cb, pcbRead, cbOffset);
    nt = VMMDLL_STATUS_SUCCESS;
finish:
    Ob_DECREF(pObHive);
    LocalFree(szMeta);
    LocalFree(pbData);
    return nt;
}

NTSTATUS MWinReg_Read(_In_ PVMMDLL_PLUGIN_CONTEXT ctx, _Out_ PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset)
{
    BOOL fResult;
    POB_REGISTRY_HIVE pObHive = NULL;
    WCHAR wszTopPath[64];
    LPWSTR wszSubPath;
    *pcbRead = 0;
    wszSubPath = Util_PathSplit2_ExWCHAR(ctx->wszPath, wszTopPath, _countof(wszTopPath));
    if(!wcscmp(wszTopPath, L"hive_files")) {
        pObHive = VmmWinReg_HiveGetByAddress(Util_GetNumericW(wszSubPath));
        if(!pObHive) { return VMMDLL_STATUS_FILE_INVALID; }
        fResult = MWinReg_Read_HiveFile(pObHive, pb, cb, pcbRead, cbOffset);
        Ob_DECREF(pObHive);
        return fResult ? VMMDLL_STATUS_SUCCESS : VMMDLL_STATUS_END_OF_FILE;
    }
    if(!wcscmp(wszTopPath, L"by-hive") || !wcscmp(wszTopPath, L"HKLM")) {
        return MWinReg_Read_KeyValue(ctx->wszPath, pb, cb, pcbRead, cbOffset);
    }
    return VMMDLL_STATUS_FILE_INVALID;
}

NTSTATUS MWinReg_Write(_In_ PVMMDLL_PLUGIN_CONTEXT ctx, _In_ PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbWrite, _In_ QWORD cbOffset)
{
    POB_REGISTRY_HIVE pObHive = NULL;
    WCHAR wszTopPath[64];
    LPWSTR wszSubPath;
    wszSubPath = Util_PathSplit2_ExWCHAR(ctx->wszPath, wszTopPath, _countof(wszTopPath));
    if(!wcscmp(wszTopPath, L"hive_files")) {
        pObHive = VmmWinReg_HiveGetByAddress(Util_GetNumericW(wszSubPath));
        if(!pObHive) { return VMMDLL_STATUS_FILE_INVALID; }
        MWinReg_Write_HiveFile(pObHive, pb, cb, pcbWrite, cbOffset);
        Ob_DECREF(pObHive);
        return VMMDLL_STATUS_SUCCESS;
    }
    return VMMDLL_STATUS_FILE_INVALID;
}

DWORD MWinReg_List_MWinReg_List_KeyAndValueMetaSize(_In_ PVMM_REGISTRY_VALUE_INFO pValueInfo)
{
    DWORD cbHexAscii = 0, cbsz = min(KEY_META_BUFFER_SIZE - 0x20, pValueInfo->cbData >> 1);
    switch(pValueInfo->dwType) {
        case REG_NONE:
            return sizeof("REG_NONE");
        case REG_SZ:
            return sizeof("REG_SZ") + cbsz;
        case REG_EXPAND_SZ:
            return sizeof("REG_EXPAND_SZ") + cbsz;
        case REG_BINARY:
            Util_FillHexAscii(NULL, min(KEY_META_BUFFER_SIZE / 5, pValueInfo->cbData), 0, NULL, &cbHexAscii);
            return sizeof("REG_BINARY") + cbHexAscii - 1;
        case REG_DWORD:
            return sizeof("REG_DWORD") + 8 + 1;
        case REG_DWORD_BIG_ENDIAN:
            return sizeof("REG_DWORD_BIG_ENDIAN") + 8 + 1;
        case REG_LINK:
            return sizeof("REG_LINK") + cbsz;
        case REG_MULTI_SZ:
            return sizeof("REG_MULTI_SZ") + cbsz - 1;
        case REG_RESOURCE_LIST:
            Util_FillHexAscii(NULL, min(KEY_META_BUFFER_SIZE / 5, pValueInfo->cbData), 0, NULL, &cbHexAscii);
            return sizeof("REG_RESOURCE_LIST") + cbHexAscii - 1;
        case REG_FULL_RESOURCE_DESCRIPTOR:
            Util_FillHexAscii(NULL, min(KEY_META_BUFFER_SIZE / 5, pValueInfo->cbData), 0, NULL, &cbHexAscii);
            return sizeof("REG_FULL_RESOURCE_DESCRIPTOR") + cbHexAscii - 1;
        case REG_RESOURCE_REQUIREMENTS_LIST:
            Util_FillHexAscii(NULL, min(KEY_META_BUFFER_SIZE / 5, pValueInfo->cbData), 0, NULL, &cbHexAscii);
            return sizeof("REG_RESOURCE_REQUIREMENTS_LIST") + cbHexAscii - 1;
        case REG_QWORD:
            return sizeof("REG_QWORD") + 16 + 1;
        default:
            Util_FillHexAscii(NULL, min(KEY_META_BUFFER_SIZE / 5, pValueInfo->cbData), 0, NULL, &cbHexAscii);
            return sizeof("REG_UNKNOWN") + cbHexAscii - 1;
    }
}

VOID MWinReg_List_KeyAndValue(_Inout_ PHANDLE pFileList, _In_ POB_REGISTRY_HIVE pHive, _In_ LPWSTR wszPath)
{
    WCHAR wszNameMeta[MAX_PATH];
    POB_MAP pmObSubkeys, pmObValues = NULL;
    POB_REGISTRY_KEY pObKey = NULL, pObSubkey = NULL;
    POB_REGISTRY_VALUE pObValue = NULL;
    VMM_REGISTRY_KEY_INFO KeyInfo;
    VMM_REGISTRY_VALUE_INFO ValueInfo;
    VMMDLL_VFS_FILELIST_EXINFO FileExInfo = { 0 };
    FileExInfo.dwVersion = VMMDLL_VFS_FILELIST_EXINFO_VERSION;
    if(wszPath[0] && !(pObKey = VmmWinReg_KeyGetByPathW(pHive, wszPath))) { return; }
    // list sub-keys
    if((pmObSubkeys = VmmWinReg_KeyList(pHive, pObKey))) {
        while((pObSubkey = ObMap_GetNext(pmObSubkeys, pObSubkey))) {
            VmmWinReg_KeyInfo(pHive, pObSubkey, &KeyInfo);
            FileExInfo.fCompressed = !KeyInfo.fActive;
            FileExInfo.qwLastWriteTime = KeyInfo.ftLastWrite;
            VMMDLL_VfsList_AddDirectoryEx(pFileList, NULL, KeyInfo.wszName, &FileExInfo);
        }
    }
    // list values
    if(pObKey && (pmObValues = VmmWinReg_KeyValueList(pHive, pObKey))) {
        VmmWinReg_KeyInfo(pHive, pObKey, &KeyInfo);
        FileExInfo.fCompressed = !KeyInfo.fActive;
        FileExInfo.qwLastWriteTime = KeyInfo.ftLastWrite;
        while((pObValue = ObMap_GetNext(pmObValues, pObValue))) {
            VmmWinReg_ValueInfo(pHive, pObValue, &ValueInfo);
            VMMDLL_VfsList_AddFileEx(pFileList, NULL, ValueInfo.wszName, ValueInfo.cbData, &FileExInfo);
            wcsncpy_s(wszNameMeta, MAX_PATH, ValueInfo.wszName, _TRUNCATE);
            wcsncat_s(wszNameMeta, MAX_PATH, L".txt", _TRUNCATE);
            VMMDLL_VfsList_AddFileEx(pFileList, NULL, wszNameMeta, MWinReg_List_MWinReg_List_KeyAndValueMetaSize(&ValueInfo), &FileExInfo);
        }
    }
    Ob_DECREF(pmObSubkeys);
    Ob_DECREF(pmObValues);
    Ob_DECREF(pObKey);
}

BOOL MWinReg_List(_In_ PVMMDLL_PLUGIN_CONTEXT ctx, _Inout_ PHANDLE pFileList)
{
    CHAR szNameHive[148];
    WCHAR wszPathHive[MAX_PATH];
    POB_REGISTRY_HIVE pObHive = NULL;
    VMMDLL_VFS_FILELIST_EXINFO FileExInfo = { 0 };
    if(!ctx->wszPath[0]) {
        VMMDLL_VfsList_AddDirectory(pFileList, "hive_files");
        VMMDLL_VfsList_AddDirectory(pFileList, "by-hive");
        VMMDLL_VfsList_AddDirectory(pFileList, "HKLM");
        return TRUE;
    }
    if(!wcscmp(ctx->wszPath, L"hive_files")) {
        while((pObHive = VmmWinReg_HiveGetNext(pObHive))) {
            strncpy_s(szNameHive, sizeof(szNameHive), pObHive->szName, _TRUNCATE);
            strncat_s(szNameHive, sizeof(szNameHive), ".reghive", _TRUNCATE);
            VMMDLL_VfsList_AddFile(pFileList, szNameHive, pObHive->cbLength + 0x1000ULL);
        }
        return TRUE;
    }
    if(!wcsncmp(ctx->wszPath, L"by-hive", 7)) {
        // list hives
        if(!wcscmp(ctx->wszPath, L"by-hive")) {
            while((pObHive = VmmWinReg_HiveGetNext(pObHive))) {
                VMMDLL_VfsList_AddDirectory(pFileList, pObHive->szName);
            }
            return TRUE;
        }
        // list hive contents
        if(VmmWinReg_PathHiveGetByFullPath(ctx->wszPath, &pObHive, wszPathHive)) {
            MWinReg_List_KeyAndValue(pFileList, pObHive, wszPathHive);
            Ob_DECREF_NULL(&pObHive);
            return TRUE;
        }
        return FALSE;
    }
    if(!wcsncmp(ctx->wszPath, L"HKLM", 4)) {
        if(!wcsncmp(ctx->wszPath, L"HKLM\\ORPHAN", 11)) {
            FileExInfo.fCompressed = TRUE;
        }
        if(!wcscmp(ctx->wszPath, L"HKLM") || !wcscmp(ctx->wszPath, L"HKLM\\ORPHAN")) {
            VMMDLL_VfsList_AddDirectoryEx(pFileList, "BCD", NULL, &FileExInfo);
            VMMDLL_VfsList_AddDirectoryEx(pFileList, "HARDWARE", NULL, &FileExInfo);
            VMMDLL_VfsList_AddDirectoryEx(pFileList, "SAM", NULL, &FileExInfo);
            VMMDLL_VfsList_AddDirectoryEx(pFileList, "SECURITY", NULL, &FileExInfo);
            VMMDLL_VfsList_AddDirectoryEx(pFileList, "SOFTWARE", NULL, &FileExInfo);
            VMMDLL_VfsList_AddDirectoryEx(pFileList, "SYSTEM", NULL, &FileExInfo);
            if(!wcscmp(ctx->wszPath, L"HKLM")) {
                FileExInfo.fCompressed = TRUE;
                VMMDLL_VfsList_AddDirectoryEx(pFileList, "ORPHAN", NULL, &FileExInfo);
            }
            return TRUE;
        }
        // list hive contents
        if(VmmWinReg_PathHiveGetByFullPath(ctx->wszPath, &pObHive, wszPathHive)) {
            MWinReg_List_KeyAndValue(pFileList, pObHive, wszPathHive);
            Ob_DECREF_NULL(&pObHive);
            return TRUE;
        }
        return FALSE;
    }
    return FALSE;
}

VOID M_WinReg_Initialize(_Inout_ PVMMDLL_PLUGIN_REGINFO pRI)
{
    if((pRI->magic != VMMDLL_PLUGIN_REGINFO_MAGIC) || (pRI->wVersion != VMMDLL_PLUGIN_REGINFO_VERSION)) { return; }
    if((pRI->tpSystem != VMM_SYSTEM_WINDOWS_X64) && (pRI->tpSystem != VMM_SYSTEM_WINDOWS_X86)) { return; }
    wcscpy_s(pRI->reg_info.wszModuleName, 32, L"registry");     // module name
    pRI->reg_info.fRootModule = TRUE;                           // module shows in root directory
    pRI->reg_fn.pfnList = MWinReg_List;                         // List function supported
    pRI->reg_fn.pfnRead = MWinReg_Read;                         // Read function supported
    pRI->reg_fn.pfnWrite = MWinReg_Write;                       // Write function supported
    pRI->pfnPluginManager_Register(pRI);
}
