// m_winreg.c : implementation related to the WinReg built-in module.
//
// (c) Ulf Frisk, 2019-2025
// Author: Ulf Frisk, pcileech@frizk.net
//

#include "modules.h"
#include "../vmmwinreg.h"

#define KEY_INFO_META_SIZE              59ULL
#define KEY_META_BUFFER_SIZE            0xA000

_Success_(return)
BOOL MWinReg_Read_HiveFile(_In_ VMM_HANDLE H, POB_REGISTRY_HIVE pHive, _Out_writes_(*pcbRead) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset)
{
    DWORD cbReadBaseBlock;
    BYTE pbBaseBlock[0x1000] = { 0 };
    *pcbRead = 0;
    if(!cb || (cbOffset >= pHive->cbLength + 0x1000ULL)) { return FALSE; }
    if(cbOffset + cb > pHive->cbLength + 0x1000ULL) {
        cb = (DWORD)(pHive->cbLength + 0x1000 - cbOffset);
    }
    *pcbRead = cb;
    // Read base block / regf (first 0x1000 bytes).
    if(cbOffset < 0x1000) {
        cbReadBaseBlock = (DWORD)min(cb, 0x1000 - cbOffset);
        VmmReadEx(H, PVMM_PROCESS_SYSTEM, pHive->vaHBASE_BLOCK, pbBaseBlock, 0x1000, NULL, VMM_FLAG_ZEROPAD_ON_FAIL);
        memcpy(pb, pbBaseBlock + cbOffset, cbReadBaseBlock);
        cbOffset += cbReadBaseBlock;
        pb += cbReadBaseBlock;
        cb -= cbReadBaseBlock;
    }
    // read hive memory space
    if((cbOffset >= 0x1000) && cb) {
        VmmWinReg_HiveReadEx(H, pHive, (DWORD)(cbOffset - 0x1000), pb, cb, NULL, VMM_FLAG_ZEROPAD_ON_FAIL);
    }
    return TRUE;
}

_Success_(return)
BOOL MWinReg_Read_HiveMemory(_In_ VMM_HANDLE H, POB_REGISTRY_HIVE pHive, _Out_writes_(*pcbRead) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset)
{
    if(cbOffset >= 0x100000000) {
        *pcbRead = 0;
        return FALSE;
    }
    *pcbRead = cb = (DWORD)min(cb, 0x100000000 - cbOffset);
    VmmWinReg_HiveReadEx(H, pHive, (DWORD)cbOffset, pb, cb, NULL, VMM_FLAG_ZEROPAD_ON_FAIL);
    return TRUE;
}

VOID MWinReg_Write_HiveFile(_In_ VMM_HANDLE H, POB_REGISTRY_HIVE pHive, _In_reads_(cb) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbWrite, _In_ QWORD cbOffset)
{
    DWORD cbWriteBaseBlock;
    *pcbWrite = 0;
    if(!cb || (cbOffset >= pHive->cbLength + 0x1000ULL)) { return; }
    if(cbOffset + cb > pHive->cbLength + 0x1000ULL) {
        cb = (DWORD)(pHive->cbLength + 0x1000 - cbOffset);
    }
    *pcbWrite = cb;
    // Write base block / regf (first 0x1000 bytes).
    if(cbOffset < 0x1000) {
        cbWriteBaseBlock = (DWORD)min(cb, 0x1000 - cbOffset);
        VmmWrite(H, PVMM_PROCESS_SYSTEM, (pHive->vaHBASE_BLOCK + (cbOffset & 0xfff)), pb, cbWriteBaseBlock);
        cbOffset += cbWriteBaseBlock;
        pb += cbWriteBaseBlock;
        cb -= cbWriteBaseBlock;
    }
    // write hive memory space
    if((cbOffset >= 0x1000) && cb) {
        VmmWinReg_HiveWrite(H, pHive, (DWORD)(cbOffset - 0x1000), pb, cb);
    }
}

VOID MWinReg_Write_HiveMemory(_In_ VMM_HANDLE H, POB_REGISTRY_HIVE pHive, _In_reads_(cb) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbWrite, _In_ QWORD cbOffset)
{
    if(cbOffset >= 0x100000000) {
        *pcbWrite = 0;
        return;
    }
    cb = (DWORD)min(cb, 0x100000000 - cbOffset);
    VmmWinReg_HiveWrite(H, pHive, (DWORD)cbOffset, pb, cb);
    *pcbWrite = cb;
}

/*
* Helper function for MWinReg_Read_KeyValue to calculate the size of hexascii (binary) meta-data
*/
DWORD MWinReg_Read_KeyValue_GetHexAscii(_In_ VMM_HANDLE H, _In_ LPSTR szKeyName, _In_ PBYTE pbData, _In_ DWORD cbData, _Out_writes_(KEY_META_BUFFER_SIZE) LPSTR szMeta)
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

DWORD MWinReg_Read_KeyValue_GetAscii(_In_ VMM_HANDLE H, _In_ LPSTR szKeyName, _In_ LPWSTR wszData, _In_ DWORD cbData, _Out_writes_(KEY_META_BUFFER_SIZE) LPSTR szMeta)
{
    WCHAR c;
    DWORD o, cszMeta;
    strncpy_s(szMeta, KEY_META_BUFFER_SIZE, szKeyName, _TRUNCATE);
    cszMeta = (DWORD)strlen(szKeyName);
    szMeta[cszMeta++] = '\n';
    if(cbData > 2) {
        for(o = 0; (o < (cbData >> 1) - 1) && (cszMeta < KEY_META_BUFFER_SIZE - 2); o++) {
            c = wszData[o];
            c = (c < 128 && c != '\n') ? UTIL_PRINTASCII[c] : ((c < 256) ? c : ' ');
            szMeta[cszMeta++] = (CHAR)c;
        }
        szMeta[cszMeta++] = '\n';
    }
    szMeta[cszMeta] = 0;
    return cszMeta;
}

NTSTATUS MWinReg_Read_KeyInfo(_In_ VMM_HANDLE H, POB_REGISTRY_HIVE pHive, _In_ LPSTR uszKeyPath, _In_ BOOL fMeta, _Out_writes_to_(cb, *pcbRead) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset)
{
    NTSTATUS nt = VMMDLL_STATUS_FILE_INVALID;
    VMM_REGISTRY_KEY_INFO KeyInfo = { 0 };
    POB_REGISTRY_KEY pObKey = NULL;
    PBYTE pbKey = NULL;
    DWORD cbKey;
    CHAR szTime[24];
    if(!(pObKey = VmmWinReg_KeyGetByPath(H, pHive, uszKeyPath))) { goto fail; }
    VmmWinReg_KeyInfo(pHive, pObKey, &KeyInfo);
    if(fMeta) {
        cbKey = KEY_INFO_META_SIZE + KeyInfo.cbuName;
        if(!(pbKey = LocalAlloc(LMEM_ZEROINIT, (SIZE_T)cbKey + 1))) { goto fail; }
        Util_FileTime2String(KeyInfo.ftLastWrite, szTime);
        snprintf((LPSTR)pbKey, (SIZE_T)cbKey + 1, "%016llx:%08x\nREG_KEY\n%s\n%s\n", pHive->vaCMHIVE, KeyInfo.raKeyCell, KeyInfo.uszName, szTime);
        nt = Util_VfsReadFile_FromPBYTE(pbKey, cbKey, pb, cb, pcbRead, cbOffset);
    } else {
        cbKey = KeyInfo.cbKeyCell;
        if(!(pbKey = LocalAlloc(LMEM_ZEROINIT, cbKey))) { goto fail; }
        VmmWinReg_HiveReadEx(H, pHive, KeyInfo.raKeyCell, pbKey, cbKey, NULL, VMM_FLAG_ZEROPAD_ON_FAIL);
        nt = Util_VfsReadFile_FromPBYTE(pbKey, cbKey, pb, cb, pcbRead, cbOffset);
    }
fail:
    Ob_DECREF(pObKey);
    LocalFree(pbKey);
    return nt;
}

NTSTATUS MWinReg_Read_KeyValue(_In_ VMM_HANDLE H, _In_ LPSTR uszPathFull, _Out_writes_to_(cb, *pcbRead) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset)
{
    NTSTATUS nt = VMMDLL_STATUS_FILE_INVALID;
    POB_REGISTRY_HIVE pObHive = NULL;
    CHAR uszSubPath[MAX_PATH];
    DWORD i, cuszSubPath, dwType = REG_NONE, cszMeta;
    DWORD cbData, raValue = 0;
    PBYTE pbData = NULL;
    LPSTR szMeta = NULL;
    if(!VmmWinReg_PathHiveGetByFullPath(H, uszPathFull, &pObHive, uszSubPath)) { goto finish; }
    cuszSubPath = (DWORD)strlen(uszSubPath);
    // key info file
    if(CharUtil_StrEndsWith(uszSubPath, "\\(_Key_)", TRUE)) {
        uszSubPath[cuszSubPath - 8] = 0;
        nt = MWinReg_Read_KeyInfo(H, pObHive, uszSubPath, FALSE, pb, cb, pcbRead, cbOffset);
        goto finish;
    }
    if(CharUtil_StrEndsWith(uszSubPath, "\\(_Key_).txt", TRUE)) {
        uszSubPath[cuszSubPath - 12] = 0;
        nt = MWinReg_Read_KeyInfo(H, pObHive, uszSubPath, TRUE, pb, cb, pcbRead, cbOffset);
        goto finish;
    }
    // raw registry value - i.e not metadata
    if((cuszSubPath < 5) || strcmp(uszSubPath + cuszSubPath - 4, ".txt")) {
        nt = VmmWinReg_ValueQuery1(H, pObHive, uszSubPath, NULL, NULL, pb, cb, pcbRead, cbOffset) ? VMMDLL_STATUS_SUCCESS : VMMDLL_STATUS_END_OF_FILE;
        goto finish;
    }
    // metadata file below:
    uszSubPath[cuszSubPath - 4] = 0;
    // allocate buffers and read value
    if(!(szMeta = (LPSTR)LocalAlloc(0, 27 + KEY_META_BUFFER_SIZE))) { goto finish; }
    if(!(pbData = LocalAlloc(LMEM_ZEROINIT, 2 * KEY_META_BUFFER_SIZE))) { goto finish; }
    if(!VmmWinReg_ValueQuery1(H, pObHive, uszSubPath, &dwType, &raValue, pbData, 2 * KEY_META_BUFFER_SIZE, &cbData, 0)) {
        VmmWinReg_ValueQuery1(H, pObHive, uszSubPath, &dwType, &raValue, NULL, 0, &cbData, 0);
    }
    cbData = min(cbData, 2 * KEY_META_BUFFER_SIZE);
    // write address header and temporarily move szMeta start forward 26 bytes
    snprintf(szMeta, 27, "%016llx:%08x\n", pObHive->vaCMHIVE, raValue);
    szMeta += 26;
    // process read data
    switch(dwType) {
        case REG_NONE:
            cszMeta = snprintf(szMeta, KEY_META_BUFFER_SIZE, "REG_NONE\n");
            break;
        case REG_SZ:
            cszMeta = MWinReg_Read_KeyValue_GetAscii(H, "REG_SZ", (LPWSTR)pbData, cbData, szMeta);
            break;
        case REG_EXPAND_SZ:
            cszMeta = MWinReg_Read_KeyValue_GetAscii(H, "REG_EXPAND_SZ", (LPWSTR)pbData, cbData, szMeta);
            break;
        case REG_BINARY:
            cszMeta = MWinReg_Read_KeyValue_GetHexAscii(H, "REG_BINARY", pbData, cbData, szMeta);
            break;
        case REG_DWORD:
            cszMeta = snprintf(szMeta, KEY_META_BUFFER_SIZE, "REG_DWORD\n%08x\n", *(PDWORD)pbData);
            break;
        case REG_DWORD_BIG_ENDIAN:
            cszMeta = snprintf(szMeta, KEY_META_BUFFER_SIZE, "REG_DWORD_BIG_ENDIAN\n%2x%2x%2x%2x\n", pbData[0], pbData[1], pbData[2], pbData[3]);
            break;
        case REG_LINK:
            cszMeta = MWinReg_Read_KeyValue_GetAscii(H, "REG_LINK", (LPWSTR)pbData, cbData + 2, szMeta);
            break;
        case REG_MULTI_SZ:
            for(i = 0; (cbData >= 6) && (i < cbData - 4); i += 2) { // replace NULL WCHAR between strings with newline
                if(!*(LPWSTR)(pbData + i)) {
                    *(LPWSTR)(pbData + i) = '\n';
                }
            }
            cszMeta = MWinReg_Read_KeyValue_GetAscii(H, "REG_MULTI_SZ", (LPWSTR)pbData, (cbData < 2 ? 0 : cbData - 2), szMeta);
            break;
        case REG_RESOURCE_LIST:
            cszMeta = MWinReg_Read_KeyValue_GetHexAscii(H, "REG_RESOURCE_LIST", pbData, cbData, szMeta);
            break;
        case REG_FULL_RESOURCE_DESCRIPTOR:
            cszMeta = MWinReg_Read_KeyValue_GetHexAscii(H, "REG_FULL_RESOURCE_DESCRIPTOR", pbData, cbData, szMeta);
            break;
        case REG_RESOURCE_REQUIREMENTS_LIST:
            cszMeta = MWinReg_Read_KeyValue_GetHexAscii(H, "REG_RESOURCE_REQUIREMENTS_LIST", pbData, cbData, szMeta);
            break;
        case REG_QWORD:
            cszMeta = snprintf(szMeta, KEY_META_BUFFER_SIZE, "REG_QWORD\n%016llx\n", *(PQWORD)pbData);
            break;
        default:
            cszMeta = MWinReg_Read_KeyValue_GetHexAscii(H, "REG_UNKNOWN", pbData, cbData, szMeta);
            break;
    }
    // move back address header
    szMeta -= 26;
    cszMeta += 26;
    // return data
    nt = Util_VfsReadFile_FromPBYTE((PBYTE)szMeta, cszMeta, pb, cb, pcbRead, cbOffset);
finish:
    Ob_DECREF(pObHive);
    LocalFree(szMeta);
    LocalFree(pbData);
    return nt;
}

NTSTATUS MWinReg_Read(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_CONTEXT ctxP, _Out_writes_to_(cb, *pcbRead) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset)
{
    BOOL fResult;
    POB_REGISTRY_HIVE pObHive = NULL;
    CHAR uszTopPath[64];
    LPCSTR uszSubPath;
    *pcbRead = 0;
    uszSubPath = CharUtil_PathSplitFirst(ctxP->uszPath, uszTopPath, sizeof(uszTopPath));
    if(!_stricmp(uszTopPath, "hive_files")) {
        pObHive = VmmWinReg_HiveGetByAddress(H, Util_GetNumericA(uszSubPath));
        if(!pObHive) { return VMMDLL_STATUS_FILE_INVALID; }
        fResult = MWinReg_Read_HiveFile(H, pObHive, pb, cb, pcbRead, cbOffset);
        Ob_DECREF(pObHive);
        return fResult ? VMMDLL_STATUS_SUCCESS : VMMDLL_STATUS_END_OF_FILE;
    }
    if(!_stricmp(uszTopPath, "hive_memory")) {
        pObHive = VmmWinReg_HiveGetByAddress(H, Util_GetNumericA(uszSubPath));
        if(!pObHive) { return VMMDLL_STATUS_FILE_INVALID; }
        fResult = MWinReg_Read_HiveMemory(H, pObHive, pb, cb, pcbRead, cbOffset);
        Ob_DECREF(pObHive);
        return fResult ? VMMDLL_STATUS_SUCCESS : VMMDLL_STATUS_END_OF_FILE;
    }
    if(!_stricmp(uszTopPath, "by-hive") || !_stricmp(uszTopPath, "HKLM") || !_stricmp(uszTopPath, "HKU")) {
        return MWinReg_Read_KeyValue(H, ctxP->uszPath, pb, cb, pcbRead, cbOffset);
    }
    return VMMDLL_STATUS_FILE_INVALID;
}

NTSTATUS MWinReg_Write(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_CONTEXT ctxP, _In_reads_(cb) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbWrite, _In_ QWORD cbOffset)
{
    POB_REGISTRY_HIVE pObHive = NULL;
    CHAR uszTopPath[64];
    LPCSTR uszSubPath;
    uszSubPath = CharUtil_PathSplitFirst(ctxP->uszPath, uszTopPath, sizeof(uszTopPath));
    if(!_stricmp(uszTopPath, "hive_files")) {
        pObHive = VmmWinReg_HiveGetByAddress(H, Util_GetNumericA(uszSubPath));
        if(!pObHive) { return VMMDLL_STATUS_FILE_INVALID; }
        MWinReg_Write_HiveFile(H, pObHive, pb, cb, pcbWrite, cbOffset);
        Ob_DECREF(pObHive);
        return VMMDLL_STATUS_SUCCESS;
    }
    if(!_stricmp(uszTopPath, "hive_memory")) {
        pObHive = VmmWinReg_HiveGetByAddress(H, Util_GetNumericA(uszSubPath));
        if(!pObHive) { return VMMDLL_STATUS_FILE_INVALID; }
        MWinReg_Write_HiveMemory(H, pObHive, pb, cb, pcbWrite, cbOffset);
        Ob_DECREF(pObHive);
        return VMMDLL_STATUS_SUCCESS;
    }
    return VMMDLL_STATUS_FILE_INVALID;
}

DWORD MWinReg_List_MWinReg_List_KeyAndValueMetaSize(_In_ PVMM_REGISTRY_VALUE_INFO pValueInfo)
{
    DWORD cbHexAscii = 0, cbsz = min(KEY_META_BUFFER_SIZE - 0x40, pValueInfo->cbData >> 1);
    switch(pValueInfo->dwType) {
        case REG_NONE:
            return 26 + sizeof("REG_NONE");
        case REG_SZ:
            return 26 + sizeof("REG_SZ") + cbsz;
        case REG_EXPAND_SZ:
            return 26 + sizeof("REG_EXPAND_SZ") + cbsz;
        case REG_BINARY:
            Util_FillHexAscii(NULL, min(KEY_META_BUFFER_SIZE / 5, pValueInfo->cbData), 0, NULL, &cbHexAscii);
            return 26 + sizeof("REG_BINARY") + cbHexAscii - 1;
        case REG_DWORD:
            return 26 + sizeof("REG_DWORD") + 8 + 1;
        case REG_DWORD_BIG_ENDIAN:
            return 26 + sizeof("REG_DWORD_BIG_ENDIAN") + 8 + 1;
        case REG_LINK:
            return 26 + sizeof("REG_LINK") + cbsz;
        case REG_MULTI_SZ:
            return 26 + sizeof("REG_MULTI_SZ") + cbsz - 1;
        case REG_RESOURCE_LIST:
            Util_FillHexAscii(NULL, min(KEY_META_BUFFER_SIZE / 5, pValueInfo->cbData), 0, NULL, &cbHexAscii);
            return 26 + sizeof("REG_RESOURCE_LIST") + cbHexAscii - 1;
        case REG_FULL_RESOURCE_DESCRIPTOR:
            Util_FillHexAscii(NULL, min(KEY_META_BUFFER_SIZE / 5, pValueInfo->cbData), 0, NULL, &cbHexAscii);
            return 26 + sizeof("REG_FULL_RESOURCE_DESCRIPTOR") + cbHexAscii - 1;
        case REG_RESOURCE_REQUIREMENTS_LIST:
            Util_FillHexAscii(NULL, min(KEY_META_BUFFER_SIZE / 5, pValueInfo->cbData), 0, NULL, &cbHexAscii);
            return 26 + sizeof("REG_RESOURCE_REQUIREMENTS_LIST") + cbHexAscii - 1;
        case REG_QWORD:
            return 26 + sizeof("REG_QWORD") + 16 + 1;
        default:
            Util_FillHexAscii(NULL, min(KEY_META_BUFFER_SIZE / 5, pValueInfo->cbData), 0, NULL, &cbHexAscii);
            return 26 + sizeof("REG_UNKNOWN") + cbHexAscii - 1;
    }
}

VOID MWinReg_List_KeyAndValue(_In_ VMM_HANDLE H, _Inout_ PHANDLE pFileList, _In_ POB_REGISTRY_HIVE pHive, _In_ LPSTR uszPath)
{
    CHAR uszNameMeta[MAX_PATH];
    POB_MAP pmObSubkeys, pmObValues = NULL;
    POB_REGISTRY_KEY pObKey = NULL, pObSubkey = NULL;
    POB_REGISTRY_VALUE pObValue = NULL;
    VMM_REGISTRY_KEY_INFO KeyInfo;
    VMM_REGISTRY_VALUE_INFO ValueInfo;
    VMMDLL_VFS_FILELIST_EXINFO FileExInfo = { 0 };
    FileExInfo.dwVersion = VMMDLL_VFS_FILELIST_EXINFO_VERSION;
    if(uszPath[0] && !(pObKey = VmmWinReg_KeyGetByPath(H, pHive, uszPath))) { return; }
    // list key info
    if(pObKey && _stricmp(uszPath, "ORPHAN\\") && _stricmp(uszPath, "ORPHAN")) {
        VmmWinReg_KeyInfo(pHive, pObKey, &KeyInfo);
        FileExInfo.fCompressed = !KeyInfo.fActive;
        FileExInfo.qwLastWriteTime = KeyInfo.ftLastWrite;
        VMMDLL_VfsList_AddFile(pFileList, "(_Key_)", KeyInfo.cbKeyCell, &FileExInfo);
        VMMDLL_VfsList_AddFile(pFileList, "(_Key_).txt", KEY_INFO_META_SIZE + KeyInfo.cbuName, &FileExInfo);
    }
    // list sub-keys
    if((pmObSubkeys = VmmWinReg_KeyList(H, pHive, pObKey))) {
        while((pObSubkey = ObMap_GetNext(pmObSubkeys, pObSubkey))) {
            VmmWinReg_KeyInfo(pHive, pObSubkey, &KeyInfo);
            FileExInfo.fCompressed = !KeyInfo.fActive;
            FileExInfo.qwLastWriteTime = KeyInfo.ftLastWrite;
            VMMDLL_VfsList_AddDirectory(pFileList, KeyInfo.uszName, &FileExInfo);
        }
    }
    // list values
    if(pObKey && (pmObValues = VmmWinReg_KeyValueList(H, pHive, pObKey))) {
        VmmWinReg_KeyInfo(pHive, pObKey, &KeyInfo);
        FileExInfo.fCompressed = !KeyInfo.fActive;
        FileExInfo.qwLastWriteTime = KeyInfo.ftLastWrite;
        while((pObValue = ObMap_GetNext(pmObValues, pObValue))) {
            VmmWinReg_ValueInfo(pHive, pObValue, &ValueInfo);
            VMMDLL_VfsList_AddFile(pFileList, ValueInfo.uszName, ValueInfo.cbData, &FileExInfo);
            strncpy_s(uszNameMeta, MAX_PATH, ValueInfo.uszName, _TRUNCATE);
            strncat_s(uszNameMeta, MAX_PATH, ".txt", _TRUNCATE);
            VMMDLL_VfsList_AddFile(pFileList, uszNameMeta, MWinReg_List_MWinReg_List_KeyAndValueMetaSize(&ValueInfo), &FileExInfo);
        }
    }
    Ob_DECREF(pmObSubkeys);
    Ob_DECREF(pmObValues);
    Ob_DECREF(pObKey);
}

BOOL MWinReg_List(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_CONTEXT ctx, _Inout_ PHANDLE pFileList)
{
    DWORD i;
    CHAR uszNameHive[MAX_PATH];
    CHAR uszPathHive[MAX_PATH];
    PVMMOB_MAP_USER pObUserMap = NULL;
    POB_REGISTRY_HIVE pObHive = NULL;
    VMMDLL_VFS_FILELIST_EXINFO FileExInfo = { 0 };
    LPSTR uszPath = ctx->uszPath;
    if(!uszPath[0]) {
        VMMDLL_VfsList_AddDirectory(pFileList, "hive_files", NULL);
        VMMDLL_VfsList_AddDirectory(pFileList, "hive_memory", NULL);
        VMMDLL_VfsList_AddDirectory(pFileList, "by-hive", NULL);
        VMMDLL_VfsList_AddDirectory(pFileList, "HKLM", NULL);
        VMMDLL_VfsList_AddDirectory(pFileList, "HKU", NULL);
        return TRUE;
    }
    if(!_stricmp(uszPath, "hive_files")) {
        while((pObHive = VmmWinReg_HiveGetNext(H, pObHive))) {
            _snprintf_s(uszNameHive, _countof(uszNameHive), _TRUNCATE, "%s.reghive", pObHive->uszName);
            VMMDLL_VfsList_AddFile(pFileList, uszNameHive, pObHive->cbLength + 0x1000ULL, NULL);
        }
        return TRUE;
    }
    if(!_stricmp(uszPath, "hive_memory")) {
        while((pObHive = VmmWinReg_HiveGetNext(H, pObHive))) {
            _snprintf_s(uszNameHive, _countof(uszNameHive), _TRUNCATE, "%s.hivemem", pObHive->uszName);
            VMMDLL_VfsList_AddFile(pFileList, uszNameHive, 0x100000000, NULL);
        }
        return TRUE;
    }
    if(!_strnicmp(uszPath, "by-hive", 7)) {
        // list hives
        if(!_stricmp(uszPath, "by-hive")) {
            while((pObHive = VmmWinReg_HiveGetNext(H, pObHive))) {
                _snprintf_s(uszNameHive, _countof(uszNameHive), _TRUNCATE, "%s", pObHive->uszName);
                VMMDLL_VfsList_AddDirectory(pFileList, uszNameHive, NULL);
            }
            return TRUE;
        }
        // list hive contents
        if(VmmWinReg_PathHiveGetByFullPath(H, uszPath, &pObHive, uszPathHive)) {
            MWinReg_List_KeyAndValue(H, pFileList, pObHive, uszPathHive);
            Ob_DECREF_NULL(&pObHive);
            return TRUE;
        }
        return FALSE;
    }
    if(!_strnicmp(uszPath, "HKLM", 4)) {
        if(!strncmp(uszPath, "HKLM\\ORPHAN", 11)) {
            FileExInfo.fCompressed = TRUE;
        }
        if(!_stricmp(uszPath, "HKLM") || !_stricmp(uszPath, "HKLM\\ORPHAN")) {
            VMMDLL_VfsList_AddDirectory(pFileList, "BCD",  &FileExInfo);
            VMMDLL_VfsList_AddDirectory(pFileList, "HARDWARE",  &FileExInfo);
            VMMDLL_VfsList_AddDirectory(pFileList, "SAM",  &FileExInfo);
            VMMDLL_VfsList_AddDirectory(pFileList, "SECURITY",  &FileExInfo);
            VMMDLL_VfsList_AddDirectory(pFileList, "SOFTWARE",  &FileExInfo);
            VMMDLL_VfsList_AddDirectory(pFileList, "SYSTEM",  &FileExInfo);
            if(!_stricmp(uszPath, "HKLM")) {
                FileExInfo.fCompressed = TRUE;
                VMMDLL_VfsList_AddDirectory(pFileList, "ORPHAN",  &FileExInfo);
            }
            return TRUE;
        }
        // list hive contents
        if(VmmWinReg_PathHiveGetByFullPath(H, uszPath, &pObHive, uszPathHive)) {
            MWinReg_List_KeyAndValue(H, pFileList, pObHive, uszPathHive);
            Ob_DECREF_NULL(&pObHive);
            return TRUE;
        }
        return FALSE;
    }
    if(!_strnicmp(uszPath, "HKU", 3)) {
        if(!strncmp(uszPath, "HKU\\ORPHAN", 10)) {
            FileExInfo.fCompressed = TRUE;
        }
        if(!_stricmp(uszPath, "HKU") || !_stricmp(uszPath, "HKU\\ORPHAN")) {
            if(VmmMap_GetUser(H, &pObUserMap)) {
                for(i = 0; i < pObUserMap->cMap; i++) {
                    if(pObUserMap->pMap[i].vaRegHive) {
                        VMMDLL_VfsList_AddDirectory(pFileList, pObUserMap->pMap[i].uszText, &FileExInfo);
                    }
                }
                Ob_DECREF_NULL(&pObUserMap);
                VMMDLL_VfsList_AddDirectory(pFileList, "LocalSystem", &FileExInfo);
                VMMDLL_VfsList_AddDirectory(pFileList, "LocalService", &FileExInfo);
                VMMDLL_VfsList_AddDirectory(pFileList, "NetworkService", &FileExInfo);
            }
            if(!_stricmp(uszPath, "HKU")) {
                FileExInfo.fCompressed = TRUE;
                VMMDLL_VfsList_AddDirectory(pFileList, "ORPHAN", &FileExInfo);
            }
            return TRUE;
        }
        // list hive contents
        if(VmmWinReg_PathHiveGetByFullPath(H, uszPath, &pObHive, uszPathHive)) {
            MWinReg_List_KeyAndValue(H, pFileList, pObHive, uszPathHive);
            Ob_DECREF_NULL(&pObHive);
            return TRUE;
        }
        return FALSE;
    }
    return FALSE;
}

VOID M_WinReg_Initialize(_In_ VMM_HANDLE H, _Inout_ PVMMDLL_PLUGIN_REGINFO pRI)
{
    if((pRI->magic != VMMDLL_PLUGIN_REGINFO_MAGIC) || (pRI->wVersion != VMMDLL_PLUGIN_REGINFO_VERSION)) { return; }
    if((pRI->tpSystem != VMM_SYSTEM_WINDOWS_64) && (pRI->tpSystem != VMM_SYSTEM_WINDOWS_32)) { return; }
    strcpy_s(pRI->reg_info.uszPathName, 128, "\\registry");     // module name
    pRI->reg_info.fRootModule = TRUE;                           // module shows in root directory
    pRI->reg_fn.pfnList = MWinReg_List;                         // List function supported
    pRI->reg_fn.pfnRead = MWinReg_Read;                         // Read function supported
    pRI->reg_fn.pfnWrite = MWinReg_Write;                       // Write function supported
    pRI->pfnPluginManager_Register(H, pRI);
}
