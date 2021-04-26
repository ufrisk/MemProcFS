// m_sys_cert.c : implementation related to the Sys/Certificates built-in module.
//
// The 'sys/certificates' module is responsible for displaying cryptographic
// certificates from the certificate stores in the virtual file system.
//
// (c) Ulf Frisk, 2020-2021
// Author: Ulf Frisk, pcileech@frizk.net
//
#include "vmm.h"
#include "util.h"
#include "vmmwin.h"
#include "vmmwinreg.h"

// a _SORTED_ collection of the last 64-bits of some well known (benign) certificate thumbprints:
QWORD gqw_MSYS_CERTWELLKNOWN[] = {    
    0x009C0E2236494FAA, 0x03A72CA340A05BD5, 0x0878D0403AA20264, 0x0926DF5B856976AD, 0x0CC1D057F0369B46, 0x0CDE9523E7260C6D, 0x0E8BC0CA4F25FD6F, 0x107BF4187486EFCC,
    0x10E180E882B385CC, 0x118C687ECBA3F4D8, 0x1281AD9FEEDD4E4C, 0x13CDFE13C20F934E, 0x14A89C99FA3B5247, 0x14C3D0E3370EB58A, 0x171E30148030C072, 0x1AB3BD3CBAA15BFC,
    0x1BDE3A09E8F8770F, 0x1D1141BF883866B1, 0x22D8C687A4EB0085, 0x23108DC28192E2BB, 0x23ADF445084ED656, 0x244141B92511B279, 0x246B1EE0EC41BA22, 0x280B04C27F902712,
    0x2BE1BBC53E6174E2, 0x2C78DB2852CAE474, 0x300183382500ABF9, 0x33E70D3FFE9871AF, 0x34EC7C8F6C77721E, 0x381242105F1B78F5, 0x383569D8E4EFB961, 0x38B82E74F89A830A,
    0x3BF751735E9BD358, 0x3CDD78D31EF5A8DA, 0x3E1974AF94AF59D4, 0x3EF4F318A5624A9E, 0x40C576755DCC1FDF, 0x40C6DD2FB19C5436, 0x42914468726138DD, 0x4375038E8DF8DDC0,
    0x4423589005B2571D, 0x44C9FEB3F33EFA9A, 0x456F4F78DCFAD6D4, 0x474724C055FDE8B6, 0x47B440CAD90A1945, 0x483B6A749F6178C6, 0x48AD815CF51E801A, 0x49F6A22BF28ABB6B,
    0x4B57E8B7D8F1FCA6, 0x4BDFB5A899B24D43, 0x4D37EA6A4463768A, 0x4DF5E45B68851868, 0x4E8960984B2905B6, 0x505A672C438D4E9C, 0x51223DB5103405CB, 0x519243C13142EBC3,
    0x53063C5BE6FC620C, 0x53B5BECD78375931, 0x5608E60A05D3CBF3, 0x560FDBEA2AC23EF1, 0x56167F62F532E547, 0x56BE3D9B6744A5E5, 0x58FBF12ABA298F7A, 0x593E7D44D934FF11,
    0x596C87934D5F2AB4, 0x5AACE6A5D1C4454C, 0x62FB376ED6096F24, 0x64D2A3A3F5D88B8C, 0x67F209B843BE15B3, 0x6982A400A4D9224E, 0x6A66B8F6E41FF157, 0x6CB95508461EAB2F,
    0x6E4A0D18EBCE4CFA, 0x6F7F586A285B2D5B, 0x732638CA6AD77C13, 0x76B8178FA215F344, 0x7C72E4ACDA12F7E7, 0x7CB854FC317E1539, 0x7E6E504D43AB10B5, 0x7F7537E165EA574B,
    0x7F9D62139786633A, 0x8468CB88EEDDEEA8, 0x8485EA3014C0BCFE, 0x84ED05F1DCE5370C, 0x85843524BBFAB727, 0x861A754976C8DD25, 0x873B0FA77BB70D54, 0x87FDE2A065FD89D4,
    0x8B3338E89398EE18, 0x8C503726A81E2B93, 0x8CE86A81109FE48E, 0x8DFF0F2445184AEB, 0x8E7E0AAFB7033B90, 0x90B70F4002D1D6E9, 0x93D0795F0FAE155F, 0x95C65B3A44534274,
    0x98DF70F8F091BC52, 0x9DD391BC65A68964, 0xA024204BF286A8F6, 0xA1D4862F951D3D5D, 0xA2593A19A70F069E, 0xA2D1B12FAC830338, 0xA349A7F9962A8212, 0xA6F7A79DD298EEE7,
    0xA79F45C254FDE68B, 0xA85D3E2D58476A0F, 0xA8F60D2E1C52EAC6, 0xA974BF2AE1DFE7E1, 0xAC1D81D8385E2D46, 0xAE957B9E04741E85, 0xAF37E7FE20A8B419, 0xB0C500BEE1D0C256,
    0xB488278CDD9597DD, 0xB656D3BF8257846F, 0xB6CCA0081B67EC9D, 0xB74110B4F2E49A27, 0xBB0D4631B4BEF8BA, 0xBC076201008976C9, 0xBC5E4600E3BEF9D7, 0xBC8B975023D07C50,
    0xBD6A02FC7ABD9B52, 0xBF031D88A6510E9E, 0xC0697C740733031C, 0xC17044ACFEF755BB, 0xC292A3635BD123D3, 0xC2AB466C4264F956, 0xC7B1E3CEA4DC3DC6, 0xCA556AF3ECAA35FB,
    0xCCC3372D2748381E, 0xCD14680A4F60142A, 0xCD17CE99DAB04CDD, 0xCDCD0E72AC8D48D5, 0xCF794431367EF474, 0xCFE9B43668086CCE, 0xD0082B372FEF9A54, 0xD070A1D8DA442829,
    0xD203CB8BF5A82766, 0xD31D11D9A3805421, 0xD44DF5D4674952F9, 0xD54215222E95E71F, 0xD61330FD8CDE37BF, 0xD77770028F20EEE4, 0xDC0302DEF37AEBBE, 0xDDDE38E4B7242EFE,
    0xDE7B0BB0D3298224, 0xDF22E34BCBEF3352, 0xE28D57A0199A3F44, 0xE2F897BBCD7A8CB4, 0xE5483EAAD6BA32D9, 0xE5AAE30384024B9C, 0xE6D38F1A61C7DC25, 0xE7BDC29B2FAAA060,
    0xE8BE56CEBC288CF3, 0xE919EA675C94D217, 0xECE9608477AF556F, 0xF2150152A41D829C, 0xF357A20C4A9F115E, 0xF388CAD3A699585D, 0xF64C2D0555B7E073, 0xF7E992F31190F010,
    0xF8A9ED3D038E2EA8, 0xF8C775C34CCD17B6, 0xFA589B3073951DCB, 0xFA6CDC21D92E8099, 0xFABCB418C68D31C5, 0xFB665DAA2C0E225C, 0xFD277F6A9FB4FAC1, 0xFD42BA3F43886AEF,
    0xFE06D1CC8D4F82A4, 0xFE2F9DF5B7D18A41
};

#define MSYSCERT_LINE_LENGTH              228ULL

typedef struct tdMSYSCERT_OB_ENTRY {
    OB ObHdr;
    QWORD qwIdMapKey;
    QWORD vaHive;
    DWORD oRegBlob;
    DWORD oRegCellValue;
    DWORD cbCert;
    DWORD dwHashUserSID;
    LPWSTR wszStore;
    LPWSTR wszIdHash;
    LPWSTR wszIssuerCN;
    LPWSTR wszSubjectCN;
} MSYSCERT_OB_ENTRY, *PMSYSCERT_OB_ENTRY;

VOID MSysCert_CallbackCleanup(PMSYSCERT_OB_ENTRY pOb)
{
    LocalFree(pOb->wszStore);
    LocalFree(pOb->wszIdHash);
    LocalFree(pOb->wszIssuerCN);
    LocalFree(pOb->wszSubjectCN);
}

VOID MSysCert_GetContext_UserAddSingleCert(_In_ POB_REGISTRY_HIVE pHive, _In_ POB_REGISTRY_KEY pkStore, _In_ POB_REGISTRY_KEY pkCert, _In_opt_ PVMM_MAP_USERENTRY pUser, _Inout_ POB_MAP pmCtx)
{
    DWORD o, cb, cch;
    BYTE pb[0x1800];
    PCCERT_CONTEXT pCertContext = NULL;
    POB_REGISTRY_VALUE pObValue = NULL;
    PMSYSCERT_OB_ENTRY pObResult = NULL;
    VMM_REGISTRY_VALUE_INFO ValueInfo = { 0 };
    VMM_REGISTRY_KEY_INFO KeyCertInfo = { 0 };
    VMM_REGISTRY_KEY_INFO KeyStoreInfo = { 0 };
    if(!(pObValue = VmmWinReg_KeyValueGetByName(pHive, pkCert, L"Blob"))) {
        goto fail;
    }
    if(!VmmWinReg_ValueQuery4(pHive, pObValue, NULL, pb, sizeof(pb), &cb) || (cb < 0x20)) {
        goto fail;
    }
    VmmWinReg_KeyInfo(pHive, pkCert, &KeyCertInfo);
    VmmWinReg_KeyInfo(pHive, pkStore, &KeyStoreInfo);
    VmmWinReg_ValueInfo(pHive, pObValue, &ValueInfo);
    if(wcslen(KeyCertInfo.wszName) != 40) {
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
    if(!(pObResult = Ob_Alloc('Pcer', LMEM_ZEROINIT, sizeof(MSYSCERT_OB_ENTRY), MSysCert_CallbackCleanup, NULL))) {
        goto fail;
    }
    // Subject CN
    cch = CertGetNameStringW(pCertContext, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, NULL, 0);
    if(!(pObResult->wszSubjectCN = LocalAlloc(LMEM_ZEROINIT, max(2, 2 * cch)))) { goto fail; }
    CertGetNameStringW(pCertContext, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, pObResult->wszSubjectCN, cch);
    if(cch > 64) { pObResult->wszSubjectCN[64] = 0; }   // max 64 characters length
    // Issuer CN
    cch = CertGetNameStringW(pCertContext, CERT_NAME_SIMPLE_DISPLAY_TYPE, CERT_NAME_ISSUER_FLAG, NULL, NULL, 0);
    if(!(pObResult->wszIssuerCN = LocalAlloc(LMEM_ZEROINIT, max(2, 2 * cch)))) {
        goto fail;
    }
    CertGetNameStringW(pCertContext, CERT_NAME_SIMPLE_DISPLAY_TYPE, CERT_NAME_ISSUER_FLAG, NULL, pObResult->wszIssuerCN, cch);
    if(cch > 64) { pObResult->wszIssuerCN[64] = 0; }    // max 64 characters length
    // hash and store
    if(!(pObResult->wszIdHash = Util_StrDupW(KeyCertInfo.wszName))) { goto fail; }
    if(!(pObResult->wszStore = Util_StrDupW(KeyStoreInfo.wszName))) { goto fail; }
    if(wcslen(pObResult->wszStore) > 32) { pObResult->wszStore[32] = 0; }
    // other values and finish
    pObResult->qwIdMapKey = wcstoull(pObResult->wszIdHash + 24, NULL, 16);
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

VOID MSysCert_GetContext_UserAddCerts(_In_ POB_REGISTRY_HIVE pHive, _In_ POB_REGISTRY_KEY pKeySystemCertificates, _In_opt_ PVMM_MAP_USERENTRY pUserEntry, _Inout_ POB_MAP pmCtx)
{
    POB_REGISTRY_KEY pkObCertStore = NULL, pkObCertStoreCerts = NULL, pkObCert = NULL;
    POB_MAP pmkObCertStores = NULL, pmObCerts = NULL;
    if(!(pmkObCertStores = VmmWinReg_KeyList(pHive, pKeySystemCertificates))) { return; }
    while((pkObCertStore = ObMap_GetNext(pmkObCertStores, pkObCertStore))) {
        pkObCertStoreCerts = VmmWinReg_KeyGetByChildName(pHive, pkObCertStore, L"Certificates");
        if(!pkObCertStoreCerts) { continue; }
        if((pmObCerts = VmmWinReg_KeyList(pHive, pkObCertStoreCerts))) {
            while((pkObCert = ObMap_GetNext(pmObCerts, pkObCert))) {
                MSysCert_GetContext_UserAddSingleCert(pHive, pkObCertStore, pkObCert, pUserEntry, pmCtx);
            }
            Ob_DECREF_NULL(&pmObCerts);
        }
        Ob_DECREF_NULL(&pkObCertStoreCerts);
    }
    Ob_DECREF_NULL(&pmkObCertStores);
}

/*
* Retrieve the context map containing information about the certificates.
* CALLER DECREF: return
* -- return
*/
_Success_(return != NULL)
POB_MAP MSysCert_GetContext(_In_ PVMMDLL_PLUGIN_CONTEXT ctxP)
{
    LPWSTR wszCertStoresUSER[] = { L"ROOT\\Software\\Microsoft\\SystemCertificates", L"ROOT\\Software\\Policies\\Microsoft\\SystemCertificates" };
    LPWSTR wszCertStoresSYSTEM[] = { L"HKLM\\SOFTWARE\\Microsoft\\SystemCertificates", L"HKLM\\SOFTWARE\\Policies\\Microsoft\\SystemCertificates" };
    DWORD i;
    POB_MAP pObCtx = NULL;
    PVMMOB_MAP_USER pObUserMap = NULL;
    POB_REGISTRY_KEY pObKey = NULL;
    POB_REGISTRY_HIVE pObHive = NULL;
    POB_CONTAINER ctxM = (POB_CONTAINER)ctxP->ctxM;
    if((pObCtx = ObContainer_GetOb(ctxM))) { return pObCtx; }
    EnterCriticalSection(&ctxVmm->LockUpdateModule);
    if((pObCtx = ObContainer_GetOb(ctxM))) { goto finish; }
    if(!(pObCtx = ObMap_New(OB_MAP_FLAGS_OBJECT_OB))) { goto finish; }
    // Retrieve system (local machine) certificates:
    for(i = 0; i < sizeof(wszCertStoresSYSTEM) / sizeof(LPWSTR); i++) {
        if(VmmWinReg_KeyHiveGetByFullPath(wszCertStoresSYSTEM[i], &pObHive, &pObKey)) {
            MSysCert_GetContext_UserAddCerts(pObHive, pObKey, NULL, pObCtx);
            Ob_DECREF_NULL(&pObKey);
            Ob_DECREF_NULL(&pObHive);
        }
    }
    // Retrieve user certificates:
    if(VmmMap_GetUser(&pObUserMap)) {
        for(i = 0; i < pObUserMap->cMap; i++) {
            if((pObHive = VmmWinReg_HiveGetByAddress(pObUserMap->pMap[i].vaRegHive))) {
                for(i = 0; i < sizeof(wszCertStoresUSER) / sizeof(LPWSTR); i++) {
                    if((pObKey = VmmWinReg_KeyGetByPath(pObHive, wszCertStoresUSER[i]))) {
                        MSysCert_GetContext_UserAddCerts(pObHive, pObKey, pObUserMap->pMap + i, pObCtx);
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
    LeaveCriticalSection(&ctxVmm->LockUpdateModule);
    return pObCtx;
}

NTSTATUS MSysCert_Read_Cert(_In_ PVMMDLL_PLUGIN_CONTEXT ctxP, _Out_writes_to_(cb, *pcbRead) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset)
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
    if(!(cch = wcslen(ctxP->wszPath)) || (cch < 20)) { goto fail; }
    if(_wcsicmp(ctxP->wszPath + cch - 4, L".cer")) { goto fail; }
    if(!(qwIdMapKey = wcstoull(ctxP->wszPath + cch - 20, NULL, 16))) { goto fail; }
    if(!(pmOb = MSysCert_GetContext(ctxP))) { goto fail; }
    if(!(pObEntry = ObMap_GetByKey(pmOb, qwIdMapKey))) { goto fail; }
    if(!(pObHive = VmmWinReg_HiveGetByAddress(pObEntry->vaHive))) { goto fail; }
    if(!(pObValue = VmmWinReg_KeyValueGetByOffset(pObHive, pObEntry->oRegCellValue))) { goto fail; }
    if(!VmmWinReg_ValueQuery4(pObHive, pObValue, NULL, pbCertBuffer, sizeof(pbCertBuffer), &cbCertBuffer)) { goto fail; }
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

VOID MSysCert_Read_InfoFile_GetUserName(_In_ PVMMOB_MAP_USER pUserMap, _In_ DWORD dwHashSid, _Out_writes_(17) LPSTR szUserName)
{
    DWORD i;
    if(0 == dwHashSid) {
        snprintf(szUserName, 17, "LocalMachine");
        return;
    }
    for(i = 0; i < pUserMap->cMap; i++) {
        if(pUserMap->pMap[i].dwHashSID == dwHashSid) {
            snprintf(szUserName, 17, "%S", pUserMap->pMap[i].wszText);
            szUserName[16] = 0;
            return;
        }
    }
    szUserName[0] = 0;
}

NTSTATUS MSysCert_Read_InfoFile2(_In_ POB_MAP pmCertificates, _In_ PVMMOB_MAP_USER pUserMap, _Out_writes_to_(cb, *pcbRead) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset)
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
    if(!(sz = LocalAlloc(LMEM_ZEROINIT, cbMax))) { return VMMDLL_STATUS_FILE_INVALID; }
    for(i = cStart; i <= cEnd; i++) {
        peOb = ObMap_GetByIndex(pmCertificates, (DWORD)i);
        fWellKnown = 0 != Util_qfind((PVOID)peOb->qwIdMapKey, sizeof(gqw_MSYS_CERTWELLKNOWN) / sizeof(QWORD), gqw_MSYS_CERTWELLKNOWN, sizeof(QWORD), Util_qfind_CmpFindTableQWORD);
        MSysCert_Read_InfoFile_GetUserName(pUserMap, peOb->dwHashUserSID, szUserName);
        o += Util_snwprintf_u8ln(
            sz + o,
            cbLINELENGTH,
            L"%04x %-16S %-32s %-64s %-64s%c %s",
            (DWORD)i,
            szUserName,
            peOb->wszStore,
            peOb->wszSubjectCN,
            peOb->wszIssuerCN,
            (fWellKnown ? ' ' : '*'),
            peOb->wszIdHash
        );
    }
    nt = Util_VfsReadFile_FromPBYTE(sz, cbMax - 1, pb, cb, pcbRead, cbOffset - cStart * cbLINELENGTH);
    LocalFree(sz);
    return nt;
}

NTSTATUS MSysCert_Read_InfoFile(_In_ PVMMDLL_PLUGIN_CONTEXT ctxP, _Out_writes_to_(cb, *pcbRead) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset)
{
    NTSTATUS nt = VMMDLL_STATUS_FILE_INVALID;
    POB_MAP pmObCtx = NULL;
    PVMMOB_MAP_USER pObUserMap = NULL;
    if(!VmmMap_GetUser(&pObUserMap)) { goto fail; }
    if(!(pmObCtx = MSysCert_GetContext(ctxP))) { goto fail; }
    nt = MSysCert_Read_InfoFile2(pmObCtx, pObUserMap, pb, cb, pcbRead, cbOffset);
fail:
    Ob_DECREF(pmObCtx);
    Ob_DECREF(pObUserMap);
    return nt;
}


NTSTATUS MSysCert_Read(_In_ PVMMDLL_PLUGIN_CONTEXT ctxP, _Out_writes_to_(cb, *pcbRead) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset)
{
    return _wcsicmp(ctxP->wszPath, L"certificates.txt") ? MSysCert_Read_Cert(ctxP, pb, cb, pcbRead, cbOffset) : MSysCert_Read_InfoFile(ctxP, pb, cb, pcbRead, cbOffset);
}

BOOL MSysCert_List(_In_ PVMMDLL_PLUGIN_CONTEXT ctxP, _Inout_ PHANDLE pFileList)
{
    DWORD i, dwHashUserSID = 0;
    WCHAR wsz[MAX_PATH];
    POB_MAP pmObCtx = NULL;
    PVMMOB_MAP_USER pObUserMap = NULL;
    PMSYSCERT_OB_ENTRY pObEntry = NULL;
    if(!VmmMap_GetUser(&pObUserMap)) { goto fail; }
    if(!(pmObCtx = MSysCert_GetContext(ctxP))) { goto fail; }
    if(!ctxP->wszPath[0]) {
        // ROOT
        VMMDLL_VfsList_AddFile(pFileList, L"certificates.txt", ObMap_Size(pmObCtx) * MSYSCERT_LINE_LENGTH, NULL);
        VMMDLL_VfsList_AddDirectory(pFileList, L"LocalMachine", NULL);
        for(i = 0; i < pObUserMap->cMap; i++) {
            VMMDLL_VfsList_AddDirectory(pFileList, pObUserMap->pMap[i].wszText, NULL);
        }
    } else {
        // USER DIR
        if(_wcsicmp(ctxP->wszPath, L"LocalMachine")) {
            for(i = 0; i < pObUserMap->cMap; i++) {
                if(_wcsicmp(ctxP->wszPath, pObUserMap->pMap[i].wszText)) {
                    dwHashUserSID = pObUserMap->pMap[i].dwHashSID;
                    break;
                }
            }
            if(dwHashUserSID == 0) { goto fail; }
        }
        while((pObEntry = ObMap_GetNext(pmObCtx, pObEntry))) {
            if(pObEntry->dwHashUserSID != dwHashUserSID) { continue; }
            _snwprintf_s(wsz, MAX_PATH, MAX_PATH, L"%s-%s-%s.cer", pObEntry->wszStore, pObEntry->wszSubjectCN, pObEntry->wszIdHash);
            wsz[MAX_PATH - 1] = 0;
            VMMDLL_VfsList_AddFile(pFileList, wsz, pObEntry->cbCert, NULL);
        }
    }
fail:
    Ob_DECREF(pObUserMap);
    Ob_DECREF(pmObCtx);
    return TRUE;
}

VOID MSysCert_FcLogJSON(_In_ PVMMDLL_PLUGIN_CONTEXT ctxP, _In_ VOID(*pfnLogJSON)(_In_ PVMMDLL_PLUGIN_FORENSIC_JSONDATA pData))
{
    PVMMDLL_PLUGIN_FORENSIC_JSONDATA pd;
    POB_MAP pmObCerts = NULL;
    PMSYSCERT_OB_ENTRY peOb = NULL;
    DWORD i, iMax;
    CHAR szj[MAX_PATH];
    if(ctxP->pProcess || !(pd = LocalAlloc(LMEM_ZEROINIT, sizeof(VMMDLL_PLUGIN_FORENSIC_JSONDATA)))) { return; }
    pd->dwVersion = VMMDLL_PLUGIN_FORENSIC_JSONDATA_VERSION;
    pd->szjType = "certificate";
    if((pmObCerts = MSysCert_GetContext(ctxP))) {
        for(i = 0, iMax = ObMap_Size(pmObCerts); i < iMax; i++) {
            if((peOb = ObMap_GetByIndex(pmObCerts, (DWORD)i))) {
                Util_snwprintf_u8j(szj, _countof(szj), L"store:[%s] thumbprint:[%s] issuer:[%s]", peOb->wszStore, peOb->wszIdHash, peOb->wszIssuerCN);
                pd->i = i;
                pd->wsz[0] = peOb->wszSubjectCN;
                pd->szj[1] = szj;
                pfnLogJSON(pd);
                Ob_DECREF_NULL(&peOb);
            }
        }
    }
    Ob_DECREF(pmObCerts);
    LocalFree(pd);
}

VOID MSysCert_Notify(_In_ PVMMDLL_PLUGIN_CONTEXT ctxP, _In_ DWORD fEvent, _In_opt_ PVOID pvEvent, _In_opt_ DWORD cbEvent)
{
    POB_CONTAINER ctxM = (POB_CONTAINER)ctxP->ctxM;
    if(fEvent == VMMDLL_PLUGIN_NOTIFY_REFRESH_SLOW) {
        ObContainer_SetOb(ctxM, NULL);
    }
}

VOID MSysCert_Close(_In_ PVMMDLL_PLUGIN_CONTEXT ctxP)
{
    POB_CONTAINER ctxM = (POB_CONTAINER)ctxP->ctxM;
    Ob_DECREF(ctxM);
}

VOID M_SysCert_Initialize(_Inout_ PVMMDLL_PLUGIN_REGINFO pRI)
{
    if((pRI->magic != VMMDLL_PLUGIN_REGINFO_MAGIC) || (pRI->wVersion != VMMDLL_PLUGIN_REGINFO_VERSION)) { return; }
    if((pRI->tpSystem != VMM_SYSTEM_WINDOWS_X64) && (pRI->tpSystem != VMM_SYSTEM_WINDOWS_X86)) { return; }
    if(!(pRI->reg_info.ctxM = (PVMMDLL_PLUGIN_INTERNAL_CONTEXT)ObContainer_New())) { return; }      // Initialize context container
    wcscpy_s(pRI->reg_info.wszPathName, 128, L"\\sys\\certificates");   // module name
    pRI->reg_info.fRootModule = TRUE;                                   // module shows in root directory
    pRI->reg_fn.pfnList = MSysCert_List;                                // List function supported
    pRI->reg_fn.pfnRead = MSysCert_Read;                                // Read function supported
    pRI->reg_fn.pfnClose = MSysCert_Close;                              // Close function supported
    pRI->reg_fn.pfnNotify = MSysCert_Notify;                            // Notify function supported
    pRI->reg_fnfc.pfnLogJSON = MSysCert_FcLogJSON;                      // JSON log function supported
    pRI->pfnPluginManager_Register(pRI);
}
