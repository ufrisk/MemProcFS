// m_sys_cert.c : implementation related to the Sys/Certificates built-in module.
//
// The 'sys/certificates' module is responsible for displaying cryptographic
// certificates from the certificate stores in the virtual file system.
//
// (c) Ulf Frisk, 2020-2025
// Author: Ulf Frisk, pcileech@frizk.net
//

#include "modules.h"
#include "../infodb.h"
#include "../vmmwinreg.h"

#define MSYSCERT_LINE_LENGTH              228ULL

typedef struct tdMSYSCERT_OB_ENTRY {
    OB ObHdr;
    QWORD qwIdMapKey;
    QWORD vaHive;
    DWORD oRegBlob;
    DWORD oRegCellValue;
    DWORD cbCert;
    DWORD dwHashUserSID;
    LPSTR uszStore;
    LPSTR uszIdHash;
    LPSTR uszIssuerCN;
    LPSTR uszSubjectCN;
} MSYSCERT_OB_ENTRY, *PMSYSCERT_OB_ENTRY;

VOID MSysCert_CallbackCleanup(PMSYSCERT_OB_ENTRY pOb)
{
    LocalFree(pOb->uszStore);
    LocalFree(pOb->uszIdHash);
    LocalFree(pOb->uszIssuerCN);
    LocalFree(pOb->uszSubjectCN);
}

VOID MSysCert_GetContext_UserAddSingleCert(_In_ VMM_HANDLE H, _In_ POB_REGISTRY_HIVE pHive, _In_ POB_REGISTRY_KEY pkStore, _In_ POB_REGISTRY_KEY pkCert, _In_opt_ PVMM_MAP_USERENTRY pUser, _Inout_ POB_MAP pmCtx)
{
    DWORD o, cb, cch;
    BYTE pb[0x1800];
    WCHAR wszBuffer[MAX_PATH + 1] = { 0 };
    PCCERT_CONTEXT pCertContext = NULL;
    POB_REGISTRY_VALUE pObValue = NULL;
    PMSYSCERT_OB_ENTRY pObResult = NULL;
    VMM_REGISTRY_VALUE_INFO ValueInfo = { 0 };
    VMM_REGISTRY_KEY_INFO KeyCertInfo = { 0 };
    VMM_REGISTRY_KEY_INFO KeyStoreInfo = { 0 };
    if(!(pObValue = VmmWinReg_KeyValueGetByName(H, pHive, pkCert, "Blob"))) {
        goto fail;
    }
    if(!VmmWinReg_ValueQuery4(H, pHive, pObValue, NULL, pb, sizeof(pb), &cb) || (cb < 0x20)) {
        goto fail;
    }
    VmmWinReg_KeyInfo(pHive, pkCert, &KeyCertInfo);
    VmmWinReg_KeyInfo(pHive, pkStore, &KeyStoreInfo);
    VmmWinReg_ValueInfo(pHive, pObValue, &ValueInfo);
    if(strlen(KeyCertInfo.uszName) != 40) {
        goto fail;
    }
    // locate certificate part in registry blob
    // https://blog.nviso.eu/2019/08/28/extracting-certificates-from-the-windows-registry/
    for(o = 0; o < cb - 0x20; o++) {
        if(*(PQWORD)(pb + o) == 0x0000000100000020) {
            cb = min(cb - o - 8 - 4, *(PDWORD)(pb + o + 8));
            o += 12;
            break;
        }
    }
    if(!(pCertContext = CertCreateCertificateContext(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, pb + o, cb + 10))) {
        goto fail;
    }
    if(!(pObResult = Ob_AllocEx(H, OB_TAG_MOD_CERTIFICATES, LMEM_ZEROINIT, sizeof(MSYSCERT_OB_ENTRY), MSysCert_CallbackCleanup, NULL))) {
        goto fail;
    }
    // Subject CN
    wszBuffer[0] = 0;
    cch = CertGetNameStringW(pCertContext, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, NULL, 0);
    CertGetNameStringW(pCertContext, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, wszBuffer, min(cch, MAX_PATH));
    if(!CharUtil_WtoU(wszBuffer, min(cch, 64), NULL, 0, &pObResult->uszSubjectCN, NULL, CHARUTIL_FLAG_ALLOC)) { goto fail; }
    // Issuer CN
    wszBuffer[0] = 0;
    cch = CertGetNameStringW(pCertContext, CERT_NAME_SIMPLE_DISPLAY_TYPE, CERT_NAME_ISSUER_FLAG, NULL, NULL, 0);
    CertGetNameStringW(pCertContext, CERT_NAME_SIMPLE_DISPLAY_TYPE, CERT_NAME_ISSUER_FLAG, NULL, wszBuffer, min(cch, MAX_PATH));
    if(!CharUtil_WtoU(wszBuffer, min(cch, 64), NULL, 0, &pObResult->uszIssuerCN, NULL, CHARUTIL_FLAG_ALLOC)) { goto fail; }
    // hash and store
    if(!(pObResult->uszIdHash = Util_StrDupA(KeyCertInfo.uszName))) { goto fail; }
    if(!(pObResult->uszStore = Util_StrDupA(KeyStoreInfo.uszName))) { goto fail; }
    if(strlen(pObResult->uszStore) > 32) { pObResult->uszStore[32] = 0; }
    // other values and finish
    pObResult->qwIdMapKey = strtoull(pObResult->uszIdHash + 24, NULL, 16);
    pObResult->vaHive = pHive->vaCMHIVE;
    pObResult->oRegBlob = o;
    pObResult->oRegCellValue = ValueInfo.raValueCell;
    pObResult->cbCert = cb;
    pObResult->dwHashUserSID = pUser ? pUser->dwHashSID : 0;
    ObMap_Push(pmCtx, pObResult->qwIdMapKey, pObResult);
fail:
    if(pCertContext) { CertFreeCertificateContext(pCertContext); }
    Ob_DECREF(pObResult);
    Ob_DECREF(pObValue);
}

VOID MSysCert_GetContext_UserAddCerts(_In_ VMM_HANDLE H, _In_ POB_REGISTRY_HIVE pHive, _In_ POB_REGISTRY_KEY pKeySystemCertificates, _In_opt_ PVMM_MAP_USERENTRY pUserEntry, _Inout_ POB_MAP pmCtx)
{
    POB_REGISTRY_KEY pkObCertStore = NULL, pkObCertStoreCerts = NULL, pkObCert = NULL;
    POB_MAP pmkObCertStores = NULL, pmObCerts = NULL;
    if(!(pmkObCertStores = VmmWinReg_KeyList(H, pHive, pKeySystemCertificates))) { return; }
    while((pkObCertStore = ObMap_GetNext(pmkObCertStores, pkObCertStore))) {
        if((pkObCertStoreCerts = VmmWinReg_KeyGetByChildName(H, pHive, pkObCertStore, "Certificates"))) {
            if((pmObCerts = VmmWinReg_KeyList(H, pHive, pkObCertStoreCerts))) {
                while((pkObCert = ObMap_GetNext(pmObCerts, pkObCert))) {
                    MSysCert_GetContext_UserAddSingleCert(H, pHive, pkObCertStore, pkObCert, pUserEntry, pmCtx);
                }
                Ob_DECREF_NULL(&pmObCerts);
            }
            Ob_DECREF_NULL(&pkObCertStoreCerts);
        }
    }
    Ob_DECREF_NULL(&pmkObCertStores);
}

/*
* Retrieve the context map containing information about the certificates.
* CALLER DECREF: return
* -- return
*/
_Success_(return != NULL)
POB_MAP MSysCert_GetContext(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_CONTEXT ctxP)
{
    LPSTR uszCertStoresUSER[] = { "ROOT\\Software\\Microsoft\\SystemCertificates", "ROOT\\Software\\Policies\\Microsoft\\SystemCertificates" };
    LPSTR uszCertStoresSYSTEM[] = { "HKLM\\SOFTWARE\\Microsoft\\SystemCertificates", "HKLM\\SOFTWARE\\Policies\\Microsoft\\SystemCertificates" };
    DWORD iMap, i;
    POB_MAP pObCtx = NULL;
    PVMMOB_MAP_USER pObUserMap = NULL;
    POB_REGISTRY_KEY pObKey = NULL;
    POB_REGISTRY_HIVE pObHive = NULL;
    POB_CONTAINER ctxM = (POB_CONTAINER)ctxP->ctxM;
    if((pObCtx = ObContainer_GetOb(ctxM))) { return pObCtx; }
    EnterCriticalSection(&H->vmm.LockUpdateModule);
    if((pObCtx = ObContainer_GetOb(ctxM))) { goto finish; }
    if(!(pObCtx = ObMap_New(H, OB_MAP_FLAGS_OBJECT_OB))) { goto finish; }
    // Retrieve system (local machine) certificates:
    for(i = 0; i < sizeof(uszCertStoresSYSTEM) / sizeof(LPSTR); i++) {
        if(VmmWinReg_KeyHiveGetByFullPath(H, uszCertStoresSYSTEM[i], &pObHive, &pObKey)) {
            MSysCert_GetContext_UserAddCerts(H, pObHive, pObKey, NULL, pObCtx);
            Ob_DECREF_NULL(&pObKey);
            Ob_DECREF_NULL(&pObHive);
        }
    }
    // Retrieve user certificates:
    if(VmmMap_GetUser(H, &pObUserMap)) {
        for(iMap = 0; iMap < pObUserMap->cMap; iMap++) {
            if((pObHive = VmmWinReg_HiveGetByAddress(H, pObUserMap->pMap[iMap].vaRegHive))) {
                for(i = 0; i < sizeof(uszCertStoresUSER) / sizeof(LPSTR); i++) {
                    if((pObKey = VmmWinReg_KeyGetByPath(H, pObHive, uszCertStoresUSER[i]))) {
                        MSysCert_GetContext_UserAddCerts(H, pObHive, pObKey, pObUserMap->pMap + iMap, pObCtx);
                        Ob_DECREF_NULL(&pObKey);
                    }
                }
                Ob_DECREF_NULL(&pObHive);
            }
        }
        Ob_DECREF_NULL(&pObUserMap);
    }
    ObContainer_SetOb(ctxM, pObCtx);
finish:
    LeaveCriticalSection(&H->vmm.LockUpdateModule);
    return pObCtx;
}

NTSTATUS MSysCert_Read_Cert(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_CONTEXT ctxP, _Out_writes_to_(cb, *pcbRead) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset)
{
    NTSTATUS nt = VMMDLL_STATUS_FILE_INVALID;
    BYTE pbCertBuffer[0x1800];
    DWORD cbCertBuffer;
    QWORD cch, qwIdMapKey;
    POB_MAP pmOb = NULL;
    PMSYSCERT_OB_ENTRY pObEntry = NULL;
    POB_REGISTRY_HIVE pObHive = NULL;
    POB_REGISTRY_VALUE pObValue = NULL;
    VMM_REGISTRY_VALUE_INFO ValueInfo = { 0 };
    if(!(cch = strlen(ctxP->uszPath)) || (cch < 20)) { goto fail; }
    if(_stricmp(ctxP->uszPath + cch - 4, ".cer")) { goto fail; }
    if(!(qwIdMapKey = strtoull(ctxP->uszPath + cch - 20, NULL, 16))) { goto fail; }
    if(!(pmOb = MSysCert_GetContext(H, ctxP))) { goto fail; }
    if(!(pObEntry = ObMap_GetByKey(pmOb, qwIdMapKey))) { goto fail; }
    if(!(pObHive = VmmWinReg_HiveGetByAddress(H, pObEntry->vaHive))) { goto fail; }
    if(!(pObValue = VmmWinReg_KeyValueGetByOffset(H, pObHive, pObEntry->oRegCellValue))) { goto fail; }
    if(!VmmWinReg_ValueQuery4(H, pObHive, pObValue, NULL, pbCertBuffer, sizeof(pbCertBuffer), &cbCertBuffer)) { goto fail; }
    if(cb < pObEntry->oRegBlob) { goto fail; }
    cbCertBuffer = min(pObEntry->cbCert, cbCertBuffer - pObEntry->oRegBlob);
    nt = Util_VfsReadFile_FromPBYTE(pbCertBuffer + pObEntry->oRegBlob, cbCertBuffer, pb, cb, pcbRead, cbOffset);
fail:
    Ob_DECREF(pmOb);
    Ob_DECREF(pObEntry);
    Ob_DECREF(pObValue);
    Ob_DECREF(pObHive);
    return nt;
}

VOID MSysCert_Read_InfoFile_GetUserName(_In_ VMM_HANDLE H, _In_ PVMMOB_MAP_USER pUserMap, _In_ DWORD dwHashSid, _Out_writes_(17) LPSTR uszUserName)
{
    DWORD i;
    if(0 == dwHashSid) {
        snprintf(uszUserName, 17, "LocalMachine");
        return;
    }
    for(i = 0; i < pUserMap->cMap; i++) {
        if(pUserMap->pMap[i].dwHashSID == dwHashSid) {
            CharUtil_UtoU(pUserMap->pMap[i].uszText, -1, (PBYTE)uszUserName, 17, NULL, NULL, CHARUTIL_FLAG_TRUNCATE | CHARUTIL_FLAG_STR_BUFONLY);
            return;
        }
    }
    uszUserName[0] = 0;
}

NTSTATUS MSysCert_Read_InfoFile2(_In_ VMM_HANDLE H, _In_ POB_MAP pmCertificates, _In_ PVMMOB_MAP_USER pUserMap, _Out_writes_to_(cb, *pcbRead) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset)
{
    NTSTATUS nt = VMMDLL_STATUS_FILE_INVALID;
    LPSTR sz;
    BOOL fWellKnown;
    CHAR szUserName[17];
    QWORD i, o = 0, cCertificates, cbMax, cStart, cEnd, cbLINELENGTH;
    PMSYSCERT_OB_ENTRY peOb = NULL;
    cbLINELENGTH = MSYSCERT_LINE_LENGTH;
    cCertificates = ObMap_Size(pmCertificates);
    cStart = (DWORD)(cbOffset / cbLINELENGTH);
    cEnd = (DWORD)min(cCertificates - 1, (cb + cbOffset + cbLINELENGTH - 1) / cbLINELENGTH);
    cbMax = 1 + (1 + cEnd - cStart) * cbLINELENGTH;
    if(!cCertificates || (cStart > cCertificates)) { return VMMDLL_STATUS_END_OF_FILE; }
    if(!(sz = LocalAlloc(LMEM_ZEROINIT, (SIZE_T)cbMax))) { return VMMDLL_STATUS_FILE_INVALID; }
    for(i = cStart; i <= cEnd; i++) {
        peOb = ObMap_GetByIndex(pmCertificates, (DWORD)i);
        fWellKnown = InfoDB_CertIsWellKnown(H, peOb->qwIdMapKey);
        MSysCert_Read_InfoFile_GetUserName(H, pUserMap, peOb->dwHashUserSID, szUserName);
        o += Util_usnprintf_ln(
            sz + o,
            cbLINELENGTH,
            "%04x %-16s %-32s %-64s %-64s%c %s",
            (DWORD)i,
            szUserName,
            peOb->uszStore,
            peOb->uszSubjectCN,
            peOb->uszIssuerCN,
            (fWellKnown ? ' ' : '*'),
            peOb->uszIdHash
        );
        Ob_DECREF_NULL(&peOb);
    }
    nt = Util_VfsReadFile_FromPBYTE(sz, cbMax - 1, pb, cb, pcbRead, cbOffset - cStart * cbLINELENGTH);
    LocalFree(sz);
    return nt;
}

NTSTATUS MSysCert_Read_InfoFile(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_CONTEXT ctxP, _Out_writes_to_(cb, *pcbRead) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset)
{
    NTSTATUS nt = VMMDLL_STATUS_FILE_INVALID;
    POB_MAP pmObCtx = NULL;
    PVMMOB_MAP_USER pObUserMap = NULL;
    if(!VmmMap_GetUser(H, &pObUserMap)) { goto fail; }
    if(!(pmObCtx = MSysCert_GetContext(H, ctxP))) { goto fail; }
    nt = MSysCert_Read_InfoFile2(H, pmObCtx, pObUserMap, pb, cb, pcbRead, cbOffset);
fail:
    Ob_DECREF(pmObCtx);
    Ob_DECREF(pObUserMap);
    return nt;
}


NTSTATUS MSysCert_Read(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_CONTEXT ctxP, _Out_writes_to_(cb, *pcbRead) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset)
{
    return _stricmp(ctxP->uszPath, "certificates.txt") ? MSysCert_Read_Cert(H, ctxP, pb, cb, pcbRead, cbOffset) : MSysCert_Read_InfoFile(H, ctxP, pb, cb, pcbRead, cbOffset);
}

BOOL MSysCert_List(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_CONTEXT ctxP, _Inout_ PHANDLE pFileList)
{
    DWORD i, dwHashUserSID = 0;
    CHAR usz[MAX_PATH];
    POB_MAP pmObCtx = NULL;
    PVMMOB_MAP_USER pObUserMap = NULL;
    PMSYSCERT_OB_ENTRY pObEntry = NULL;
    if(!VmmMap_GetUser(H, &pObUserMap)) { goto fail; }
    if(!(pmObCtx = MSysCert_GetContext(H, ctxP))) { goto fail; }
    if(!ctxP->uszPath[0]) {
        // ROOT
        VMMDLL_VfsList_AddFile(pFileList, "certificates.txt", ObMap_Size(pmObCtx) * MSYSCERT_LINE_LENGTH, NULL);
        VMMDLL_VfsList_AddDirectory(pFileList, "LocalMachine", NULL);
        for(i = 0; i < pObUserMap->cMap; i++) {
            VMMDLL_VfsList_AddDirectory(pFileList, pObUserMap->pMap[i].uszText, NULL);
        }
    } else {
        // USER DIR
        if(_stricmp(ctxP->uszPath, "LocalMachine")) {
            for(i = 0; i < pObUserMap->cMap; i++) {
                if(_stricmp(ctxP->uszPath, pObUserMap->pMap[i].uszText)) {
                    dwHashUserSID = pObUserMap->pMap[i].dwHashSID;
                    break;
                }
            }
            if(dwHashUserSID == 0) { goto fail; }
        }
        while((pObEntry = ObMap_GetNext(pmObCtx, pObEntry))) {
            if(pObEntry->dwHashUserSID != dwHashUserSID) { continue; }
            _snprintf_s(usz, MAX_PATH, MAX_PATH, "%s-%s-%s.cer", pObEntry->uszStore, pObEntry->uszSubjectCN, pObEntry->uszIdHash);
            usz[MAX_PATH - 1] = 0;
            VMMDLL_VfsList_AddFile(pFileList, usz, pObEntry->cbCert, NULL);
        }
    }
fail:
    Ob_DECREF(pObUserMap);
    Ob_DECREF(pmObCtx);
    return TRUE;
}

VOID MSysCert_FcLogJSON(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_CONTEXT ctxP, _In_ VOID(*pfnLogJSON)(_In_ VMM_HANDLE H, _In_ PVMMDLL_FORENSIC_JSONDATA pData))
{
    PVMMDLL_FORENSIC_JSONDATA pd;
    POB_MAP pmObCerts = NULL;
    PMSYSCERT_OB_ENTRY peOb = NULL;
    DWORD i, iMax;
    CHAR usz[MAX_PATH];
    if(ctxP->pProcess || !(pd = LocalAlloc(LMEM_ZEROINIT, sizeof(VMMDLL_FORENSIC_JSONDATA)))) { return; }
    pd->dwVersion = VMMDLL_FORENSIC_JSONDATA_VERSION;
    pd->szjType = "certificate";
    if((pmObCerts = MSysCert_GetContext(H, ctxP))) {
        for(i = 0, iMax = ObMap_Size(pmObCerts); i < iMax; i++) {
            if((peOb = ObMap_GetByIndex(pmObCerts, (DWORD)i))) {
                snprintf(usz, _countof(usz), "store:[%s] thumbprint:[%s] issuer:[%s]", peOb->uszStore, peOb->uszIdHash, peOb->uszIssuerCN);
                pd->i = i;
                pd->usz[0] = peOb->uszSubjectCN;
                pd->usz[1] = usz;
                pfnLogJSON(H, pd);
                Ob_DECREF_NULL(&peOb);
            }
        }
    }
    Ob_DECREF(pmObCerts);
    LocalFree(pd);
}

VOID MSysCert_Notify(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_CONTEXT ctxP, _In_ DWORD fEvent, _In_opt_ PVOID pvEvent, _In_opt_ DWORD cbEvent)
{
    POB_CONTAINER ctxM = (POB_CONTAINER)ctxP->ctxM;
    if(fEvent == VMMDLL_PLUGIN_NOTIFY_REFRESH_SLOW) {
        ObContainer_SetOb(ctxM, NULL);
    }
}

VOID MSysCert_Close(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_CONTEXT ctxP)
{
    Ob_DECREF((POB_CONTAINER)ctxP->ctxM);
}

VOID M_SysCert_Initialize(_In_ VMM_HANDLE H, _Inout_ PVMMDLL_PLUGIN_REGINFO pRI)
{
    if((pRI->magic != VMMDLL_PLUGIN_REGINFO_MAGIC) || (pRI->wVersion != VMMDLL_PLUGIN_REGINFO_VERSION)) { return; }
    if((pRI->tpSystem != VMM_SYSTEM_WINDOWS_64) && (pRI->tpSystem != VMM_SYSTEM_WINDOWS_32)) { return; }
    if(!(pRI->reg_info.ctxM = (PVMMDLL_PLUGIN_INTERNAL_CONTEXT)ObContainer_New())) { return; }      // Initialize context container
    strcpy_s(pRI->reg_info.uszPathName, 128, "\\sys\\certificates");    // module name
    pRI->reg_info.fRootModule = TRUE;                                   // module shows in root directory
    pRI->reg_fn.pfnList = MSysCert_List;                                // List function supported
    pRI->reg_fn.pfnRead = MSysCert_Read;                                // Read function supported
    pRI->reg_fn.pfnClose = MSysCert_Close;                              // Close function supported
    pRI->reg_fn.pfnNotify = MSysCert_Notify;                            // Notify function supported
    pRI->reg_fnfc.pfnLogJSON = MSysCert_FcLogJSON;                      // JSON log function supported
    pRI->pfnPluginManager_Register(H, pRI);
}
