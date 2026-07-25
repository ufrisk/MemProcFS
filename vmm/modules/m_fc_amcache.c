// m_fc_amcache.c : AmCache forensic module.
//
// Modern-schema implementation for application, file, shortcut, driver
// and device inventory with identifier-based correlation.
//
// REQUIRE: FORENSIC SUB-SYSTEM INIT.
//
// This parser intentionally treats AmCache entries as inventory/presence
// artifacts. It does not label a file as executed merely because it has an
// InventoryApplicationFile entry.
//
// (c) Ulf Frisk, 2026
// Author: Ulf Frisk, pcileech@frizk.net
//
#include "modules.h"
#include "../vmmwinreg.h"

#define MFCAMCACHE_MAX_APPLICATIONS             0x00002000
#define MFCAMCACHE_MAX_FILES                    0x00004000
#define MFCAMCACHE_MAX_SHORTCUTS                0x00002000
#define MFCAMCACHE_MAX_DRIVER_BINARIES          0x00002000
#define MFCAMCACHE_MAX_DRIVER_PACKAGES          0x00001000
#define MFCAMCACHE_MAX_DEVICE_CONTAINERS        0x00001000
#define MFCAMCACHE_MAX_DEVICE_PNPS              0x00001000
#define MFCAMCACHE_MAX_VALUE_UTF8               0x00000200
#define MFCAMCACHE_MAX_VALUE_RAW                0x00000400
#define MFCAMCACHE_MAX_VALUES_PER_RECORD        0x00000100
#define MFCAMCACHE_MAX_LIST_ITEMS_PER_RECORD    0x00000100
#define MFCAMCACHE_INDEX_NONE                   0xffffffff
#define MFCAMCACHE_APPLICATION_NONE             MFCAMCACHE_INDEX_NONE

#define MFCAMCACHE_APP_FLAG_PROGRAMID_FROM_KEY  0x00000001
#define MFCAMCACHE_APP_FLAG_PROGRAMID_DUPLICATE 0x00000002

#define MFCAMCACHE_APP_LINELENGTH               400ULL
#define MFCAMCACHE_FILE_LINELENGTH              448ULL
#define MFCAMCACHE_SHORTCUT_LINELENGTH          448ULL
#define MFCAMCACHE_DRIVER_BINARY_LINELENGTH     512ULL
#define MFCAMCACHE_DRIVER_PACKAGE_LINELENGTH    448ULL
#define MFCAMCACHE_DEVICE_CONTAINER_LINELENGTH  448ULL
#define MFCAMCACHE_DEVICE_PNP_LINELENGTH        512ULL

#define MFCAMCACHE_APP_LINEHEADER               "   # #Files #Lnk Flag KeyLastWrite            ProgramId                                Name                                                             Publisher                                        Version              RootDirPath"
#define MFCAMCACHE_FILE_LINEHEADER              "    #  App M KeyLastWrite                    Size Name                                             Application                                      FileId                                   ProgramId                                Path"
#define MFCAMCACHE_SHORTCUT_LINEHEADER          "   #  App M KeyLastWrite            ShortcutProgramId                       ShortcutPath                                                     ShortcutTargetPath"
#define MFCAMCACHE_DRIVER_BINARY_LINEHEADER     "   #  Pkg #Dev KeyLastWrite            DriverName                                       Service                                          DriverPackageStrongName                         DriverId"
#define MFCAMCACHE_DRIVER_PACKAGE_LINEHEADER    "   # #Bin #Dev KeyLastWrite            Inf                                              Provider                                         Version                  Directory"
#define MFCAMCACHE_DEVICE_CONTAINER_LINEHEADER  "   # #Dev KeyLastWrite            FriendlyName                                                     Manufacturer                                     ModelName                                        Categories"
#define MFCAMCACHE_DEVICE_PNP_LINEHEADER        "   #  Ctr  Bin  Pkg KeyLastWrite            Description                                      Manufacturer                                     Service                                          DriverName                                       HWID"

static LPCSTR MFCAMCACHE_CSV_APPLICATIONS =
    "KeyLastWrite,Index,FileCount,ShortcutCount,ProgramId,ProgramInstanceId,Name,Publisher,Version,"
    "RootDirPath,RegistryKeyPath,UninstallString,InstallDate,InstallDateMsi,"
    "InstallDateFromLinkFile,Source,Type,PackageFullName,MsiProductCode,MsiPackageCode,"
    "ManifestPath,RegistrySubKey,ProgramIdFromKey,DuplicateProgramId\n";

static LPCSTR MFCAMCACHE_CSV_FILES =
    "KeyLastWrite,Index,ApplicationIndex,ApplicationMatched,FileId,ProgramId,"
    "LowerCaseLongPath,Name,Publisher,ProductName,ProductVersion,Version,"
    "BinFileVersion,BinProductVersion,BinaryType,Language,LinkDate,Description,"
    "OriginalFileName,Size,Usn,IsPeFile,IsOsComponent,RegistrySubKey\n";

static LPCSTR MFCAMCACHE_CSV_SHORTCUTS =
    "KeyLastWrite,Index,ApplicationIndex,ApplicationMatched,ShortcutProgramId,ShortcutPath,ShortcutTargetPath,RegistrySubKey\n";

static LPCSTR MFCAMCACHE_CSV_DRIVER_BINARIES =
    "KeyLastWrite,Index,DriverPackageIndex,DeviceCount,DriverId,DriverName,DriverCompany,"
    "DriverPackageStrongName,Service,Inf,Product,ProductVersion,DriverVersion,DriverLastWriteTime,"
    "DriverCheckSum,DriverTimeStamp,DriverType,ImageSize,WdfVersion,DriverInBox,DriverIsKernelMode,DriverSigned,"
    "COMPID,HWID,RegistrySubKey\n";

static LPCSTR MFCAMCACHE_CSV_DRIVER_PACKAGES =
    "KeyLastWrite,Index,DriverBinaryCount,DeviceCount,Class,ClassGuid,Date,Directory,"
    "Inf,Provider,Version,FlightIds,RecoveryIds,SubmissionId,HWIDs,SYSFILE,DriverInBox,RegistrySubKey\n";

static LPCSTR MFCAMCACHE_CSV_DEVICE_CONTAINERS =
    "KeyLastWrite,Index,DeviceCount,Categories,DiscoveryMethod,FriendlyName,Icon,Manufacturer,ModelId,ModelName,"
    "ModelNumber,PrimaryCategory,State,IsActive,IsConnected,IsMachineContainer,IsNetworked,IsPaired,RegistrySubKey\n";

static LPCSTR MFCAMCACHE_CSV_DEVICE_PNPS =
    "KeyLastWrite,Index,DeviceContainerIndex,DriverBinaryIndex,DriverPackageIndex,BusReportedDescription,Class,ClassGuid,"
    "COMPID,ContainerId,Description,DeviceState,DriverId,DriverName,DriverPackageStrongName,DriverVerDate,"
    "DriverVerVersion,Enumerator,HWID,Inf,InstallState,Manufacturer,MatchingID,Model,ParentId,ProblemCode,Provider,"
    "Service,STACKID,RegistrySubKey\n";

typedef struct tdVMM_MAP_AMCACHE_APPLICATION {
    DWORD dwIndex;
    DWORD dwFlags;
    DWORD cFiles;
    DWORD cShortcuts;
    QWORD ftKeyLastWrite;
    QWORD qwProgramIdHash;

    LPSTR uszRegistrySubKey;
    LPSTR uszProgramId;
    LPSTR uszProgramInstanceId;
    LPSTR uszName;
    LPSTR uszPublisher;
    LPSTR uszVersion;
    LPSTR uszRootDirPath;
    LPSTR uszRegistryKeyPath;
    LPSTR uszUninstallString;
    LPSTR uszInstallDate;
    LPSTR uszInstallDateMsi;
    LPSTR uszInstallDateFromLinkFile;
    LPSTR uszSource;
    LPSTR uszType;
    LPSTR uszPackageFullName;
    LPSTR uszMsiProductCode;
    LPSTR uszMsiPackageCode;
    LPSTR uszManifestPath;
    LPSTR uszBundleManifestPath;
    LPSTR uszLanguage;
    LPSTR uszOSVersionAtInstallTime;
    LPSTR uszManufacturer;
} VMM_MAP_AMCACHE_APPLICATION, *PVMM_MAP_AMCACHE_APPLICATION;

typedef struct tdVMM_MAP_AMCACHE_FILE {
    DWORD dwIndex;
    DWORD iApplication;
    QWORD ftKeyLastWrite;
    QWORD qwProgramIdHash;
    QWORD cbFile;
    QWORD usn;

    BOOL fIsPeFile;
    BOOL fIsOsComponent;

    LPSTR uszRegistrySubKey;
    LPSTR uszFileId;
    LPSTR uszProgramId;
    LPSTR uszLowerCaseLongPath;
    LPSTR uszName;
    LPSTR uszPublisher;
    LPSTR uszProductName;
    LPSTR uszProductVersion;
    LPSTR uszVersion;
    LPSTR uszBinFileVersion;
    LPSTR uszBinProductVersion;
    LPSTR uszBinaryType;
    LPSTR uszLanguage;
    LPSTR uszLinkDate;
    LPSTR uszLongPathHash;
    LPSTR uszDescription;
    LPSTR uszOriginalFileName;
} VMM_MAP_AMCACHE_FILE, *PVMM_MAP_AMCACHE_FILE;

typedef struct tdVMM_MAP_AMCACHE_SHORTCUT {
    DWORD dwIndex;
    DWORD iApplication;
    QWORD ftKeyLastWrite;
    LPSTR uszRegistrySubKey;
    LPSTR uszShortcutProgramId;
    LPSTR uszShortcutPath;
    LPSTR uszShortcutTargetPath;
} VMM_MAP_AMCACHE_SHORTCUT, *PVMM_MAP_AMCACHE_SHORTCUT;

typedef struct tdVMM_MAP_AMCACHE_DRIVER_BINARY {
    DWORD dwIndex;
    DWORD iDriverPackage;
    DWORD cDevices;
    QWORD ftKeyLastWrite;
    QWORD qwDriverCheckSum;
    QWORD qwDriverTimeStamp;
    QWORD cbImageSize;
    BOOL fDriverInBox;
    BOOL fDriverIsKernelMode;
    BOOL fDriverSigned;
    LPSTR uszRegistrySubKey;
    LPSTR uszDriverId;
    LPSTR uszDriverName;
    LPSTR uszDriverCompany;
    LPSTR uszDriverPackageStrongName;
    LPSTR uszService;
    LPSTR uszInf;
    LPSTR uszProduct;
    LPSTR uszProductVersion;
    LPSTR uszDriverVersion;
    LPSTR uszDriverLastWriteTime;
    LPSTR uszDriverType;
    LPSTR uszWdfVersion;
    LPSTR uszCOMPID;
    LPSTR uszHWID;
} VMM_MAP_AMCACHE_DRIVER_BINARY, *PVMM_MAP_AMCACHE_DRIVER_BINARY;

typedef struct tdVMM_MAP_AMCACHE_DRIVER_PACKAGE {
    DWORD dwIndex;
    DWORD cDriverBinaries;
    DWORD cDevices;
    QWORD ftKeyLastWrite;
    BOOL fDriverInBox;
    LPSTR uszRegistrySubKey;
    LPSTR uszClass;
    LPSTR uszClassGuid;
    LPSTR uszDate;
    LPSTR uszDirectory;
    LPSTR uszInf;
    LPSTR uszProvider;
    LPSTR uszVersion;
    LPSTR uszFlightIds;
    LPSTR uszRecoveryIds;
    LPSTR uszSubmissionId;
    LPSTR uszHWIDs;
    LPSTR uszSYSFILE;
} VMM_MAP_AMCACHE_DRIVER_PACKAGE, *PVMM_MAP_AMCACHE_DRIVER_PACKAGE;

typedef struct tdVMM_MAP_AMCACHE_DEVICE_CONTAINER {
    DWORD dwIndex;
    DWORD cDevices;
    QWORD ftKeyLastWrite;
    BOOL fIsActive;
    BOOL fIsConnected;
    BOOL fIsMachineContainer;
    BOOL fIsNetworked;
    BOOL fIsPaired;
    LPSTR uszRegistrySubKey;
    LPSTR uszCategories;
    LPSTR uszDiscoveryMethod;
    LPSTR uszFriendlyName;
    LPSTR uszIcon;
    LPSTR uszManufacturer;
    LPSTR uszModelId;
    LPSTR uszModelName;
    LPSTR uszModelNumber;
    LPSTR uszPrimaryCategory;
    LPSTR uszState;
} VMM_MAP_AMCACHE_DEVICE_CONTAINER, *PVMM_MAP_AMCACHE_DEVICE_CONTAINER;

typedef struct tdVMM_MAP_AMCACHE_DEVICE_PNP {
    DWORD dwIndex;
    DWORD iDeviceContainer;
    DWORD iDriverBinary;
    DWORD iDriverPackage;
    QWORD ftKeyLastWrite;
    LPSTR uszRegistrySubKey;
    LPSTR uszBusReportedDescription;
    LPSTR uszClass;
    LPSTR uszClassGuid;
    LPSTR uszCOMPID;
    LPSTR uszContainerId;
    LPSTR uszDescription;
    LPSTR uszDeviceState;
    LPSTR uszDriverId;
    LPSTR uszDriverName;
    LPSTR uszDriverPackageStrongName;
    LPSTR uszDriverVerDate;
    LPSTR uszDriverVerVersion;
    LPSTR uszEnumerator;
    LPSTR uszHWID;
    LPSTR uszInf;
    LPSTR uszInstallState;
    LPSTR uszManufacturer;
    LPSTR uszMatchingID;
    LPSTR uszModel;
    LPSTR uszParentId;
    LPSTR uszProblemCode;
    LPSTR uszProvider;
    LPSTR uszService;
    LPSTR uszSTACKID;
} VMM_MAP_AMCACHE_DEVICE_PNP, *PVMM_MAP_AMCACHE_DEVICE_PNP;

typedef struct tdVMMOB_MAP_AMCACHE {
    OB ObHdr;
    PBYTE pbMultiText;
    DWORD cbMultiText;
    PBYTE pbSummary;
    DWORD cbSummary;

    BOOL fHiveFound;
    BOOL fInventoryApplicationFound;
    BOOL fInventoryApplicationFileFound;
    BOOL fInventoryApplicationShortcutFound;
    BOOL fInventoryDriverBinaryFound;
    BOOL fInventoryDriverPackageFound;
    BOOL fInventoryDeviceContainerFound;
    BOOL fInventoryDevicePnpFound;
    BOOL fApplicationsTruncated;
    BOOL fFilesTruncated;
    BOOL fShortcutsTruncated;
    BOOL fDriverBinariesTruncated;
    BOOL fDriverPackagesTruncated;
    BOOL fDeviceContainersTruncated;
    BOOL fDevicePnpsTruncated;

    CHAR uszHiveName[128];
    CHAR uszHiveRootPath[MAX_PATH];

    DWORD cApplications;
    DWORD cFiles;
    DWORD cFilesAssociated;
    DWORD cFilesUnassociated;
    DWORD cShortcuts;
    DWORD cShortcutsAssociated;
    DWORD cDriverBinaries;
    DWORD cDriverPackages;
    DWORD cDeviceContainers;
    DWORD cDevicePnps;

    PVMM_MAP_AMCACHE_APPLICATION pApplications;
    PVMM_MAP_AMCACHE_FILE pFiles;
    PVMM_MAP_AMCACHE_SHORTCUT pShortcuts;
    PVMM_MAP_AMCACHE_DRIVER_BINARY pDriverBinaries;
    PVMM_MAP_AMCACHE_DRIVER_PACKAGE pDriverPackages;
    PVMM_MAP_AMCACHE_DEVICE_CONTAINER pDeviceContainers;
    PVMM_MAP_AMCACHE_DEVICE_PNP pDevicePnps;
} VMMOB_MAP_AMCACHE, *PVMMOB_MAP_AMCACHE;

typedef struct tdMFCAMCACHE_INIT_CONTEXT {
    POB_STRMAP psm;
    POB_MAP pmApplications;
    POB_MAP pmApplicationsByProgramId;
    POB_MAP pmFiles;
    POB_MAP pmShortcuts;
    POB_MAP pmDriverBinaries;
    POB_MAP pmDriverBinariesByService;
    POB_MAP pmDriverBinariesByDriverId;
    POB_MAP pmDriverPackages;
    POB_MAP pmDriverPackagesByStrongName;
    POB_MAP pmDriverPackagesByInf;
    POB_MAP pmDeviceContainers;
    POB_MAP pmDeviceContainersById;
    POB_MAP pmDevicePnps;

    BOOL fHiveFound;
    BOOL fInventoryApplicationFound;
    BOOL fInventoryApplicationFileFound;
    BOOL fInventoryApplicationShortcutFound;
    BOOL fInventoryDriverBinaryFound;
    BOOL fInventoryDriverPackageFound;
    BOOL fInventoryDeviceContainerFound;
    BOOL fInventoryDevicePnpFound;
    BOOL fApplicationsTruncated;
    BOOL fFilesTruncated;
    BOOL fShortcutsTruncated;
    BOOL fDriverBinariesTruncated;
    BOOL fDriverPackagesTruncated;
    BOOL fDeviceContainersTruncated;
    BOOL fDevicePnpsTruncated;

    CHAR uszHiveName[128];
    CHAR uszHiveRootPath[MAX_PATH];
} MFCAMCACHE_INIT_CONTEXT, *PMFCAMCACHE_INIT_CONTEXT;


//------------------------------------------------------------------------------
//  Helper functions:
//------------------------------------------------------------------------------
static VOID MFcAmcache_TrimAscii(_Inout_ LPSTR usz)
{
    LPSTR p;
    SIZE_T cch;
    if(!usz || !usz[0]) { return; }
    p = usz;
    while((*p == ' ') || (*p == '\t') || (*p == '\r') || (*p == '\n')) {
        p++;
    }
    if(p != usz) {
        memmove(usz, p, strlen(p) + 1);
    }
    cch = strlen(usz);
    while(cch && (
        (usz[cch - 1] == ' ') ||
        (usz[cch - 1] == '\t') ||
        (usz[cch - 1] == '\r') ||
        (usz[cch - 1] == '\n')
    )) {
        usz[--cch] = 0;
    }
}

/*
 * Case-insensitive 64-bit FNV-1a for ProgramId indexing.
 * Exact case-insensitive string comparison is still performed before accepting
 * a hash lookup, so a hash collision cannot produce an incorrect association.
 */
static QWORD MFcAmcache_Hash(_In_opt_ LPCSTR usz)
{
    BYTE ch;
    QWORD h = 1469598103934665603ULL;
    if(!usz || !usz[0]) { return 0; }
    while((ch = (BYTE)*usz++)) {
        if((ch >= 'A') && (ch <= 'Z')) {
            ch = (BYTE)(ch + ('a' - 'A'));
        }
        h ^= ch;
        h *= 1099511628211ULL;
    }
    return h ? h : 1;
}

static BOOL MFcAmcache_ReadString(_In_ VMM_HANDLE H, _In_ POB_REGISTRY_HIVE pHive, _In_ POB_REGISTRY_VALUE pValue, _Out_writes_(cbu) LPSTR usz, _In_ DWORD cbu)
{
    DWORD dwType = 0;
    if(!usz || !cbu) { return FALSE; }
    usz[0] = 0;
    if(!VmmWinReg_ValueQueryString4(H, pHive, pValue, &dwType, usz, cbu)) {
        return FALSE;
    }
    usz[cbu - 1] = 0;
    MFcAmcache_TrimAscii(usz);
    return usz[0] != 0;
}

static VOID MFcAmcache_PushString(_In_ VMM_HANDLE H, _In_ POB_REGISTRY_HIVE pHive, _In_ POB_REGISTRY_VALUE pValue, _In_ POB_STRMAP psm, _Out_opt_ LPSTR *ppusz)
{
    CHAR usz[MFCAMCACHE_MAX_VALUE_UTF8];
    if(ppusz) { *ppusz = ""; }
    if(MFcAmcache_ReadString(H, pHive, pValue, usz, sizeof(usz))) {
        ObStrMap_PushPtrUU(psm, usz, ppusz, NULL);
    }
}

static BOOL MFcAmcache_ReadQWORD(_In_ VMM_HANDLE H, _In_ POB_REGISTRY_HIVE pHive, _In_ POB_REGISTRY_VALUE pValue, _Out_ PQWORD pqw)
{
    BYTE pb[64] = { 0 };
    CHAR usz[64] = { 0 };
    DWORD cb = 0, dwType = 0;
    QWORD qw = 0;
    char *pszEnd = NULL;
    if(!pqw) { return FALSE; }
    *pqw = 0;
    if(!VmmWinReg_ValueQuery4(H, pHive, pValue, &dwType, pb, sizeof(pb), &cb)) { return FALSE; }
    if((dwType == REG_DWORD) && (cb >= sizeof(DWORD))) {
        *pqw = *(PDWORD)pb;
        return TRUE;
    }
    if((dwType == REG_QWORD) && (cb >= sizeof(QWORD))) {
        *pqw = *(PQWORD)pb;
        return TRUE;
    }
    /*
     * Some AmCache revisions have used fixed-width binary values. Accepting
     * 4/8-byte REG_BINARY here is useful and remains length-bounded.
     */
    if((dwType == REG_BINARY) && (cb == sizeof(DWORD))) {
        *pqw = *(PDWORD)pb;
        return TRUE;
    }
    if((dwType == REG_BINARY) && (cb == sizeof(QWORD))) {
        *pqw = *(PQWORD)pb;
        return TRUE;
    }
    if((dwType == REG_SZ) || (dwType == REG_EXPAND_SZ)) {
        if(!VmmWinReg_ValueQueryString4(H, pHive, pValue, NULL, usz, sizeof(usz))) {
            return FALSE;
        }
        MFcAmcache_TrimAscii(usz);
        if(!usz[0] || (usz[0] == '-')) { return FALSE; }
        errno = 0;
        qw = (QWORD)strtoull(usz, &pszEnd, ((usz[0] == '0') && ((usz[1] == 'x') || (usz[1] == 'X'))) ? 16 : 10);
        if((pszEnd == usz) || (errno == ERANGE)) { return FALSE; }
        while(*pszEnd == ' ' || *pszEnd == '\t') { pszEnd++; }
        if(*pszEnd) { return FALSE; }
        *pqw = qw;
        return TRUE;
    }
    return FALSE;
}

/*
* The name matches a known AmCache registry hive.
* -- pHive
* -- return
*/
static BOOL MFcAmcache_HiveNameMatch(_In_ POB_REGISTRY_HIVE pHive)
{
    if(!pHive) { return FALSE; }
    return
        CharUtil_StrEndsWith(pHive->uszHiveRootPath, "\\AppCompat\\Programs\\Amcache.hve", TRUE) ||
        CharUtil_StrEndsWith(pHive->uszHiveRootPath, "\\Amcache.hve", TRUE) ||
        CharUtil_StrEndsWith(pHive->uszName, "Amcache.hve", TRUE) ||
        CharUtil_StrEndsWith(pHive->uszNameShort, "Amcache.hve", TRUE);
}

/*
 * Locate Amcache.hve. The backing path/name is authoritative. A structural
 * fallback is retained for captures where the hive path strings are missing.
 * CALLER DECREF: return
 * -- H
 * -- return
 */
static POB_REGISTRY_HIVE MFcAmcache_LocateHive(_In_ VMM_HANDLE H)
{
    BOOL fCandidate;
    POB_REGISTRY_HIVE pHive = NULL;
    POB_REGISTRY_KEY pKeyApplication = NULL;
    POB_REGISTRY_KEY pKeyFile = NULL;
    while((pHive = VmmWinReg_HiveGetNext(H, pHive))) {
        if(MFcAmcache_HiveNameMatch(pHive)) {
            return pHive;
        }
    }
    while((pHive = VmmWinReg_HiveGetNext(H, pHive))) {
        pKeyApplication = VmmWinReg_KeyGetByPath(H, pHive, "Root\\InventoryApplication");
        pKeyFile = VmmWinReg_KeyGetByPath(H, pHive, "Root\\InventoryApplicationFile");
        fCandidate = pKeyApplication || pKeyFile;
        Ob_DECREF_NULL(&pKeyApplication);
        Ob_DECREF_NULL(&pKeyFile);
        if(fCandidate) {
            return pHive;
        }
    }
    return NULL;
}


//------------------------------------------------------------------------------
// InventoryApplication parsing:
//-----------------------------------------------------------------------------
static BOOL MFcAmcache_ParseApplicationValues(_In_ VMM_HANDLE H, _In_ POB_REGISTRY_HIVE pHive, _In_ POB_REGISTRY_KEY pKey, _In_ POB_STRMAP psm, _Inout_ PVMM_MAP_AMCACHE_APPLICATION pe)
{
    BOOL fProgramId = FALSE;
    DWORD i, iMax;
    CHAR uszProgramId[MFCAMCACHE_MAX_VALUE_UTF8];
    POB_MAP pmValues = NULL;
    POB_REGISTRY_VALUE pValue;
    VMM_REGISTRY_VALUE_INFO vi = { 0 };
    if(!(pmValues = VmmWinReg_KeyValueList(H, pHive, pKey))) { return FALSE; }
    iMax = min(ObMap_Size(pmValues), MFCAMCACHE_MAX_VALUES_PER_RECORD);
    for(i = 0; i < iMax; i++)
    {
        if(!(pValue = ObMap_GetByIndex(pmValues, i))) { continue; }
        ZeroMemory(&vi, sizeof(vi));
        VmmWinReg_ValueInfo(pHive, pValue, &vi);
        vi.uszName[_countof(vi.uszName) - 1] = 0;
        if(!vi.uszName[0]) { continue; }
        if(CharUtil_StrEquals(vi.uszName, "ProgramId", TRUE)) {
            if(MFcAmcache_ReadString(H, pHive, pValue, uszProgramId, sizeof(uszProgramId))) {
                fProgramId = ObStrMap_PushPtrUU(psm, uszProgramId, &pe->uszProgramId, NULL ) || fProgramId;
            }
        }
        else if(CharUtil_StrEquals(vi.uszName, "ProgramInstanceId", TRUE))     { MFcAmcache_PushString(H, pHive, pValue, psm, &pe->uszProgramInstanceId);          }
        else if(CharUtil_StrEquals(vi.uszName, "Name", TRUE))                  { MFcAmcache_PushString(H, pHive, pValue, psm, &pe->uszName);                       }
        else if(CharUtil_StrEquals(vi.uszName, "Publisher", TRUE))             { MFcAmcache_PushString(H, pHive, pValue, psm, &pe->uszPublisher);                  }
        else if(CharUtil_StrEquals(vi.uszName, "Version", TRUE))               { MFcAmcache_PushString(H, pHive, pValue, psm, &pe->uszVersion);                    }
        else if(CharUtil_StrEquals(vi.uszName, "RootDirPath", TRUE))           { MFcAmcache_PushString(H, pHive, pValue, psm, &pe->uszRootDirPath);                }
        else if(CharUtil_StrEquals(vi.uszName, "RegistryKeyPath", TRUE))       { MFcAmcache_PushString(H, pHive, pValue, psm, &pe->uszRegistryKeyPath);            }
        else if(CharUtil_StrEquals(vi.uszName, "UninstallString", TRUE))       { MFcAmcache_PushString(H, pHive, pValue, psm, &pe->uszUninstallString);            }
        else if(CharUtil_StrEquals(vi.uszName, "InstallDate", TRUE))           { MFcAmcache_PushString(H, pHive, pValue, psm, &pe->uszInstallDate);                }
        else if(CharUtil_StrEquals(vi.uszName, "InstallDateMsi", TRUE))        { MFcAmcache_PushString(H, pHive, pValue, psm, &pe->uszInstallDateMsi);             }
        else if(CharUtil_StrEquals(vi.uszName, "InstallDateFromLinkFile", TRUE)) { MFcAmcache_PushString(H, pHive, pValue, psm, &pe->uszInstallDateFromLinkFile);  }
        else if(CharUtil_StrEquals(vi.uszName, "Source", TRUE))                { MFcAmcache_PushString(H, pHive, pValue, psm, &pe->uszSource);                     }
        else if(CharUtil_StrEquals(vi.uszName, "Type", TRUE))                  { MFcAmcache_PushString(H, pHive, pValue, psm, &pe->uszType);                       }
        else if(CharUtil_StrEquals(vi.uszName, "PackageFullName", TRUE))       { MFcAmcache_PushString(H, pHive, pValue, psm, &pe->uszPackageFullName);            }
        else if(CharUtil_StrEquals(vi.uszName, "MsiProductCode", TRUE))        { MFcAmcache_PushString(H, pHive, pValue, psm, &pe->uszMsiProductCode);             }
        else if(CharUtil_StrEquals(vi.uszName, "MsiPackageCode", TRUE))        { MFcAmcache_PushString(H, pHive, pValue, psm, &pe->uszMsiPackageCode);             }
        else if(CharUtil_StrEquals(vi.uszName, "ManifestPath", TRUE))          { MFcAmcache_PushString(H, pHive, pValue, psm, &pe->uszManifestPath);               }
        else if(CharUtil_StrEquals(vi.uszName, "BundleManifestPath", TRUE))    { MFcAmcache_PushString(H, pHive, pValue, psm, &pe->uszBundleManifestPath);         }
        else if(CharUtil_StrEquals(vi.uszName, "Language", TRUE))              { MFcAmcache_PushString(H, pHive, pValue, psm, &pe->uszLanguage);                   }
        else if(CharUtil_StrEquals(vi.uszName, "OSVersionAtInstallTime", TRUE)){ MFcAmcache_PushString(H, pHive, pValue, psm, &pe->uszOSVersionAtInstallTime);     }
        else if(CharUtil_StrEquals(vi.uszName, "Manufacturer", TRUE))          { MFcAmcache_PushString(H, pHive, pValue, psm, &pe->uszManufacturer);               }
    }
    Ob_DECREF(pmValues);
    return fProgramId;
}

static VOID MFcAmcache_ParseApplications(_In_ VMM_HANDLE H, _In_ POB_REGISTRY_HIVE pHive, _Inout_ PMFCAMCACHE_INIT_CONTEXT ctx)
{
    BOOL fProgramIdValue;
    DWORD i, iMax;
    POB_REGISTRY_KEY pRoot = NULL;
    POB_REGISTRY_KEY pKey;
    POB_MAP pmKeys = NULL;
    PVMM_MAP_AMCACHE_APPLICATION pe = NULL;
    VMM_REGISTRY_KEY_INFO ki = { 0 };
    pRoot = VmmWinReg_KeyGetByPath(H, pHive, "\\ROOT\\Root\\InventoryApplication");
    if(!pRoot) { goto finish; }
    ctx->fInventoryApplicationFound = TRUE;
    pmKeys = VmmWinReg_KeyList(H, pHive, pRoot);
    if(!pmKeys) { goto finish; }
    if(ObMap_Size(pmKeys) > MFCAMCACHE_MAX_APPLICATIONS) {
        ctx->fApplicationsTruncated = TRUE;
    }
    iMax = min(ObMap_Size(pmKeys), MFCAMCACHE_MAX_APPLICATIONS);
    for(i = 0; i < iMax; i++) {
        pKey = ObMap_GetByIndex(pmKeys, i);
        if(!pKey) { continue; }
        if(!(pe = LocalAlloc(LMEM_ZEROINIT, sizeof(VMM_MAP_AMCACHE_APPLICATION)))) {
            ctx->fApplicationsTruncated = TRUE;
            break;
        }
        ZeroMemory(&ki, sizeof(ki));
        VmmWinReg_KeyInfo(pHive, pKey, &ki);
        ki.uszName[_countof(ki.uszName) - 1] = 0;
        pe->dwIndex = ObMap_Size(ctx->pmApplications);
        pe->ftKeyLastWrite = ki.ftLastWrite;
        if(!ObMap_Push(ctx->pmApplications, pe->dwIndex + 1, pe)) {
            LocalFree(pe);
            pe = NULL;
            ctx->fApplicationsTruncated = TRUE;
            break;
        }
        // push ptrs only after successful map insertion:
        if(ki.uszName[0]) {
            ObStrMap_PushPtrUU(ctx->psm, ki.uszName, &pe->uszRegistrySubKey, NULL);
        }
        fProgramIdValue = MFcAmcache_ParseApplicationValues(H, pHive, pKey, ctx->psm, pe);
        if(!fProgramIdValue && ki.uszName[0]) {
            ObStrMap_PushPtrUU(ctx->psm, ki.uszName, &pe->uszProgramId, NULL);
            pe->dwFlags |= MFCAMCACHE_APP_FLAG_PROGRAMID_FROM_KEY;
        }
        pe = NULL;
    }
finish:
    LocalFree(pe);
    Ob_DECREF(pmKeys);
    Ob_DECREF(pRoot);
}


//------------------------------------------------------------------------------
// InventoryApplicationFile parsing.
//------------------------------------------------------------------------------

static VOID MFcAmcache_ParseFileValues(_In_ VMM_HANDLE H, _In_ POB_REGISTRY_HIVE pHive, _In_ POB_REGISTRY_KEY pKey, _In_ POB_STRMAP psm, _Inout_ PVMM_MAP_AMCACHE_FILE pe)
{
    DWORD i, iMax;
    QWORD qw;
    POB_MAP pmValues = NULL;
    POB_REGISTRY_VALUE pValue;
    VMM_REGISTRY_VALUE_INFO vi = { 0 };
    if(!(pmValues = VmmWinReg_KeyValueList(H, pHive, pKey))) { return; }
    iMax = min(ObMap_Size(pmValues), MFCAMCACHE_MAX_VALUES_PER_RECORD);
    for(i = 0; i < iMax; i++) {
        if(!(pValue = ObMap_GetByIndex(pmValues, i))) { continue; }
        ZeroMemory(&vi, sizeof(vi));
        VmmWinReg_ValueInfo(pHive, pValue, &vi);
        vi.uszName[_countof(vi.uszName) - 1] = 0;
        if(!vi.uszName[0]) { continue; }
        if(CharUtil_StrEquals(vi.uszName, "Size", TRUE)) {
            if(MFcAmcache_ReadQWORD(H, pHive, pValue, &qw)) {
                pe->cbFile = qw;
            }
        } else if(CharUtil_StrEquals(vi.uszName, "Usn", TRUE)) {
            if(MFcAmcache_ReadQWORD(H, pHive, pValue, &qw)) {
                pe->usn = qw;
            }
        } else if(CharUtil_StrEquals(vi.uszName, "IsPeFile", TRUE)) {
            if(MFcAmcache_ReadQWORD(H, pHive, pValue, &qw)) {
                pe->fIsPeFile = qw ? TRUE : FALSE;
            }
        } else if(CharUtil_StrEquals(vi.uszName, "IsOsComponent", TRUE)) {
            if(MFcAmcache_ReadQWORD(H, pHive, pValue, &qw)) {
                pe->fIsOsComponent = qw ? TRUE : FALSE;
            }
        }
        else if(CharUtil_StrEquals(vi.uszName, "FileId", TRUE))            { MFcAmcache_PushString(H, pHive, pValue, psm, &pe->uszFileId);             }
        else if(CharUtil_StrEquals(vi.uszName, "ProgramId", TRUE))         { MFcAmcache_PushString(H, pHive, pValue, psm, &pe->uszProgramId);          }
        else if(CharUtil_StrEquals(vi.uszName, "LowerCaseLongPath", TRUE)) { MFcAmcache_PushString(H, pHive, pValue, psm, &pe->uszLowerCaseLongPath);  }
        else if(CharUtil_StrEquals(vi.uszName, "Name", TRUE))              { MFcAmcache_PushString(H, pHive, pValue, psm, &pe->uszName);               }
        else if(CharUtil_StrEquals(vi.uszName, "Publisher", TRUE))         { MFcAmcache_PushString(H, pHive, pValue, psm, &pe->uszPublisher);          }
        else if(CharUtil_StrEquals(vi.uszName, "ProductName", TRUE))       { MFcAmcache_PushString(H, pHive, pValue, psm, &pe->uszProductName);        }
        else if(CharUtil_StrEquals(vi.uszName, "ProductVersion", TRUE))    { MFcAmcache_PushString(H, pHive, pValue, psm, &pe->uszProductVersion);     }
        else if(CharUtil_StrEquals(vi.uszName, "Version", TRUE))           { MFcAmcache_PushString(H, pHive, pValue, psm, &pe->uszVersion);            }
        else if(CharUtil_StrEquals(vi.uszName, "BinFileVersion", TRUE))    { MFcAmcache_PushString(H, pHive, pValue, psm, &pe->uszBinFileVersion);     }
        else if(CharUtil_StrEquals(vi.uszName, "BinProductVersion", TRUE)) { MFcAmcache_PushString(H, pHive, pValue, psm, &pe->uszBinProductVersion);  }
        else if(CharUtil_StrEquals(vi.uszName, "BinaryType", TRUE))        { MFcAmcache_PushString(H, pHive, pValue, psm, &pe->uszBinaryType);         }
        else if(CharUtil_StrEquals(vi.uszName, "Language", TRUE))          { MFcAmcache_PushString(H, pHive, pValue, psm, &pe->uszLanguage);           }
        else if(CharUtil_StrEquals(vi.uszName, "LinkDate", TRUE))          { MFcAmcache_PushString(H, pHive, pValue, psm, &pe->uszLinkDate);           }
        else if(CharUtil_StrEquals(vi.uszName, "LongPathHash", TRUE))      { MFcAmcache_PushString(H, pHive, pValue, psm, &pe->uszLongPathHash);       }
        else if(CharUtil_StrEquals(vi.uszName, "Description", TRUE))       { MFcAmcache_PushString(H, pHive, pValue, psm, &pe->uszDescription);        }
        else if(CharUtil_StrEquals(vi.uszName, "OriginalFileName", TRUE))  { MFcAmcache_PushString(H, pHive, pValue, psm, &pe->uszOriginalFileName);   }
    }
    Ob_DECREF(pmValues);
}

static VOID MFcAmcache_ParseFiles(_In_ VMM_HANDLE H, _In_ POB_REGISTRY_HIVE pHive, _Inout_ PMFCAMCACHE_INIT_CONTEXT ctx)
{
    DWORD i, iMax;
    POB_REGISTRY_KEY pRoot = NULL;
    POB_REGISTRY_KEY pKey;
    POB_MAP pmKeys = NULL;
    PVMM_MAP_AMCACHE_FILE pe = NULL;
    VMM_REGISTRY_KEY_INFO ki = { 0 };
    pRoot = VmmWinReg_KeyGetByPath(H, pHive, "\\ROOT\\Root\\InventoryApplicationFile");
    if(!pRoot) { goto finish; }
    ctx->fInventoryApplicationFileFound = TRUE;
    pmKeys = VmmWinReg_KeyList(H, pHive, pRoot);
    if(!pmKeys) { goto finish; }
    iMax = min(ObMap_Size(pmKeys), MFCAMCACHE_MAX_FILES);
    ctx->fFilesTruncated = (iMax == MFCAMCACHE_MAX_FILES);
    for(i = 0; i < iMax; i++) {
        pKey = ObMap_GetByIndex(pmKeys, i);
        if(!pKey) { continue; }
        if(!(pe = LocalAlloc(LMEM_ZEROINIT, sizeof(VMM_MAP_AMCACHE_FILE)))) {
            ctx->fFilesTruncated = TRUE;
            break;
        }
        ZeroMemory(&ki, sizeof(ki));
        VmmWinReg_KeyInfo(pHive, pKey, &ki);
        ki.uszName[_countof(ki.uszName) - 1] = 0;
        pe->dwIndex = ObMap_Size(ctx->pmFiles);
        pe->iApplication = MFCAMCACHE_APPLICATION_NONE;
        pe->ftKeyLastWrite = ki.ftLastWrite;
        if(ObMap_Push(ctx->pmFiles, pe->dwIndex + 1, pe)) {
            MFcAmcache_ParseFileValues(H, pHive, pKey, ctx->psm, pe);
            ObStrMap_PushPtrUU(ctx->psm, ki.uszName, &pe->uszRegistrySubKey, NULL);
        } else {
            LocalFree(pe);
            ctx->fFilesTruncated = TRUE;
        }
        pe = NULL;
    }
finish:
    Ob_DECREF(pmKeys);
    Ob_DECREF(pRoot);
}

typedef VOID(*PFN_MFCAMCACHE_LIST_ITEM)(_Inout_ PVOID pvContext, _In_ LPCSTR uszItem);
typedef BOOL(*PFN_MFCAMCACHE_PARSE_KEY)(_In_ VMM_HANDLE H, _In_ POB_REGISTRY_HIVE pHive, _In_ POB_REGISTRY_KEY pKey, _In_ PVMM_REGISTRY_KEY_INFO pKeyInfo, _Inout_ PMFCAMCACHE_INIT_CONTEXT ctx);

/*
 * AmCache identifiers sometimes have a four-character hexadecimal algorithm
 * prefix. Match exact identifiers first and, only when both identifiers have
 * such a prefix, also permit comparison without it.
 */
static BOOL MFcAmcache_IsHex4Prefix(_In_opt_ LPCSTR usz)
{
    DWORD i;
    BYTE ch;
    if(!usz || strlen(usz) <= 4) { return FALSE; }
    for(i = 0; i < 4; i++) {
        ch = (BYTE)usz[i];
        if(!(((ch >= '0') && (ch <= '9')) || ((ch >= 'a') && (ch <= 'f')) || ((ch >= 'A') && (ch <= 'F')))) {
            return FALSE;
        }
    }
    return TRUE;
}

static BOOL MFcAmcache_IdEquals(_In_opt_ LPCSTR usz1, _In_opt_ LPCSTR usz2)
{
    SIZE_T cch1, cch2;
    BOOL fPrefix1, fPrefix2;
    if(!usz1 || !usz2 || !usz1[0] || !usz2[0]) { return FALSE; }
    if(!_stricmp(usz1, usz2)) { return TRUE; }
    cch1 = strlen(usz1);
    cch2 = strlen(usz2);
    fPrefix1 = MFcAmcache_IsHex4Prefix(usz1);
    fPrefix2 = MFcAmcache_IsHex4Prefix(usz2);
    if(fPrefix1 && fPrefix2 && !_stricmp(usz1 + 4, usz2 + 4)) { return TRUE; }
    if(fPrefix1 && (cch1 == cch2 + 4) && !_stricmp(usz1 + 4, usz2)) { return TRUE; }
    if(fPrefix2 && (cch2 == cch1 + 4) && !_stricmp(usz1, usz2 + 4)) { return TRUE; }
    return FALSE;
}

static LPCSTR MFcAmcache_PathBaseName(_In_opt_ LPCSTR usz)
{
    LPCSTR p1, p2;
    if(!usz) { return ""; }
    p1 = strrchr(usz, '\\');
    p2 = strrchr(usz, '/');
    if(p1 && p2) { return ((p1 > p2) ? p1 : p2) + 1; }
    if(p1) { return p1 + 1; }
    if(p2) { return p2 + 1; }
    return usz;
}

static BOOL MFcAmcache_ListDelimiter(_In_ CHAR ch)
{
    return (ch == '|') || (ch == ';') || (ch == ',') || (ch == '\r') || (ch == '\n');
}

static VOID MFcAmcache_ListEmit(
_Inout_updates_(cbuJoined) LPSTR uszJoined, _In_ DWORD cbuJoined, _Inout_ PDWORD pcItems, _Inout_ PDWORD pcbuJoined, _Inout_updates_(cbuItem) LPSTR uszItem, _In_ DWORD cbuItem, _In_opt_ PFN_MFCAMCACHE_LIST_ITEM pfnItem, _Inout_opt_ PVOID pvContext)
{
    DWORD cbu;
    uszItem[cbuItem - 1] = 0;
    MFcAmcache_TrimAscii(uszItem);
    if(!uszItem[0] || (*pcItems >= MFCAMCACHE_MAX_LIST_ITEMS_PER_RECORD)) { return; }
    cbu = (DWORD)strlen(uszItem);
    if(*pcbuJoined && (*pcbuJoined + 1 < cbuJoined)) {
        uszJoined[(*pcbuJoined)++] = '|';
        uszJoined[*pcbuJoined] = 0;
    }
    if(*pcbuJoined < cbuJoined - 1) {
        DWORD cbuCopy = min(cbu, cbuJoined - 1 - *pcbuJoined);
        memcpy(uszJoined + *pcbuJoined, uszItem, cbuCopy);
        *pcbuJoined += cbuCopy;
        uszJoined[*pcbuJoined] = 0;
    }
    (*pcItems)++;
    if(pfnItem && pvContext) { pfnItem(pvContext, uszItem); }
}

/*
 * Read a REG_MULTI_SZ or a delimiter-separated string. The normalized display
 * representation uses '|'. Each item may also be delivered to a callback.
 */
static DWORD MFcAmcache_ReadListString(_In_ VMM_HANDLE H, _In_ POB_REGISTRY_HIVE pHive, _In_ POB_REGISTRY_VALUE pValue, _In_ POB_STRMAP psm, _Out_opt_ LPSTR *ppusz, _In_opt_ PFN_MFCAMCACHE_LIST_ITEM pfnItem, _Inout_opt_ PVOID pvContext)
{
    DWORD cb = 0, dwType = 0, cItems = 0, cbuJoined = 0, i, cch, iStart;
    PBYTE pb = NULL;
    LPWSTR wsz;
    CHAR uszJoined[MFCAMCACHE_MAX_VALUE_UTF8] = { 0 };
    CHAR uszItem[MFCAMCACHE_MAX_VALUE_UTF8] = { 0 };
    if(ppusz) { *ppusz = ""; }
    if(!(pb = LocalAlloc(LMEM_ZEROINIT, MFCAMCACHE_MAX_VALUE_RAW))) { return 0; }
    if(!VmmWinReg_ValueQuery4(H, pHive, pValue, &dwType, pb, MFCAMCACHE_MAX_VALUE_RAW, &cb)) { goto finish; }
    if((dwType == REG_MULTI_SZ) && (cb >= sizeof(WCHAR))) {
        wsz = (LPWSTR)pb;
        cch = min(cb / sizeof(WCHAR), MFCAMCACHE_MAX_VALUE_RAW / sizeof(WCHAR));
        i = 0;
        while((i < cch) && wsz[i] && (cItems < MFCAMCACHE_MAX_LIST_ITEMS_PER_RECORD)) {
            iStart = i;
            while((i < cch) && wsz[i]) { i++; }
            if(i > iStart) {
                LPSTR uszConverted = uszItem;
                DWORD cbuConverted = 0;
                uszItem[0] = 0;
                if(CharUtil_WtoU(wsz + iStart, i - iStart, (PBYTE)uszItem, sizeof(uszItem), &uszConverted, &cbuConverted, CHARUTIL_FLAG_STR_BUFONLY | CHARUTIL_FLAG_TRUNCATE)) {
                    MFcAmcache_ListEmit(uszJoined, sizeof(uszJoined), &cItems, &cbuJoined, uszItem, sizeof(uszItem), pfnItem, pvContext);
                }
            }
            i++;
        }
    } else {
        if(MFcAmcache_ReadString(H, pHive, pValue, uszItem, sizeof(uszItem))) {
            BOOL fHasDelimiter = FALSE;
            CHAR uszToken[MFCAMCACHE_MAX_VALUE_UTF8] = { 0 };
            DWORD iToken = 0;
            for(i = 0; uszItem[i]; i++) {
                if(MFcAmcache_ListDelimiter(uszItem[i])) { fHasDelimiter = TRUE; break; }
            }
            if(!fHasDelimiter) {
                MFcAmcache_ListEmit(uszJoined, sizeof(uszJoined), &cItems, &cbuJoined, uszItem, sizeof(uszItem), pfnItem, pvContext);
            } else {
                for(i = 0;; i++) {
                    if(!uszItem[i] || MFcAmcache_ListDelimiter(uszItem[i])) {
                        uszToken[iToken] = 0;
                        MFcAmcache_ListEmit(uszJoined, sizeof(uszJoined), &cItems, &cbuJoined, uszToken, sizeof(uszToken), pfnItem, pvContext);
                        iToken = 0;
                        if(!uszItem[i]) { break; }
                    } else if(iToken < sizeof(uszToken) - 1) {
                        uszToken[iToken++] = uszItem[i];
                    }
                }
            }
        }
    }
    if(cItems && ppusz) {
        ObStrMap_PushPtrUU(psm, uszJoined, ppusz, NULL);
    }
finish:
    LocalFree(pb);
    return cItems;
}

static VOID MFcAmcache_ParseRootKeyList(_In_ VMM_HANDLE H, _In_ POB_REGISTRY_HIVE pHive, _Inout_ PMFCAMCACHE_INIT_CONTEXT ctx, _In_ LPCSTR uszPath, _In_ DWORD cMax, _Out_ PBOOL pfFound, _Out_ PBOOL pfTruncated, _In_ PFN_MFCAMCACHE_PARSE_KEY pfnParse)
{
    DWORD i, iMax;
    POB_REGISTRY_KEY pRoot = NULL, pKey;
    POB_MAP pmKeys = NULL;
    VMM_REGISTRY_KEY_INFO ki = { 0 };
    *pfFound = FALSE;
    *pfTruncated = FALSE;
    pRoot = VmmWinReg_KeyGetByPath(H, pHive, uszPath);
    if(!pRoot) { goto finish; }
    *pfFound = TRUE;
    pmKeys = VmmWinReg_KeyList(H, pHive, pRoot);
    if(!pmKeys) { goto finish; }
    if(ObMap_Size(pmKeys) > cMax) { *pfTruncated = TRUE; }
    iMax = min(ObMap_Size(pmKeys), cMax);
    for(i = 0; i < iMax; i++) {
        if(!(pKey = ObMap_GetByIndex(pmKeys, i))) { continue; }
        ZeroMemory(&ki, sizeof(ki));
        VmmWinReg_KeyInfo(pHive, pKey, &ki);
        ki.uszName[_countof(ki.uszName) - 1] = 0;
        if(!pfnParse(H, pHive, pKey, &ki, ctx)) {
            *pfTruncated = TRUE;
            break;
        }
    }
finish:
    Ob_DECREF(pmKeys);
    Ob_DECREF(pRoot);
}

//------------------------------------------------------------------------------
// Additional modern AmCache inventory parsing.
//------------------------------------------------------------------------------
static BOOL MFcAmcache_ParseShortcutKey(_In_ VMM_HANDLE H, _In_ POB_REGISTRY_HIVE pHive, _In_ POB_REGISTRY_KEY pKey, _In_ PVMM_REGISTRY_KEY_INFO pKeyInfo, _Inout_ PMFCAMCACHE_INIT_CONTEXT ctx)
{
    DWORD i, iMax;
    BOOL fAnyKnown = FALSE, fProgramId = FALSE;
    CHAR uszProgramId[MFCAMCACHE_MAX_VALUE_UTF8];
    POB_MAP pmValues = NULL;
    POB_REGISTRY_VALUE pValue;
    VMM_REGISTRY_VALUE_INFO vi = { 0 };
    PVMM_MAP_AMCACHE_SHORTCUT pe = LocalAlloc(LMEM_ZEROINIT, sizeof(VMM_MAP_AMCACHE_SHORTCUT));
    if(!pe) { return FALSE; }
    pe->dwIndex = ObMap_Size(ctx->pmShortcuts);
    pe->iApplication = MFCAMCACHE_INDEX_NONE;
    pe->ftKeyLastWrite = pKeyInfo->ftLastWrite;
    ObStrMap_PushPtrUU(ctx->psm, pKeyInfo->uszName, &pe->uszRegistrySubKey, NULL);
    if((pmValues = VmmWinReg_KeyValueList(H, pHive, pKey))) {
        iMax = min(ObMap_Size(pmValues), MFCAMCACHE_MAX_VALUES_PER_RECORD);
        for(i = 0; i < iMax; i++) {
            if(!(pValue = ObMap_GetByIndex(pmValues, i))) { continue; }
            ZeroMemory(&vi, sizeof(vi));
            VmmWinReg_ValueInfo(pHive, pValue, &vi);
            vi.uszName[_countof(vi.uszName) - 1] = 0;
            if(CharUtil_StrEquals(vi.uszName, "ShortcutProgramId", TRUE)) {
                if(MFcAmcache_ReadString(H, pHive, pValue, uszProgramId, sizeof(uszProgramId))) {
                    ObStrMap_PushPtrUU(ctx->psm, uszProgramId, &pe->uszShortcutProgramId, NULL);
                    fProgramId = TRUE;
                }
                fAnyKnown = TRUE;
            } else if(CharUtil_StrEquals(vi.uszName, "ShortcutPath", TRUE)) {
                MFcAmcache_PushString(H, pHive, pValue, ctx->psm, &pe->uszShortcutPath);
                fAnyKnown = TRUE;
            } else if(CharUtil_StrEquals(vi.uszName, "ShortcutTargetPath", TRUE) || CharUtil_StrEquals(vi.uszName, "TargetPath", TRUE)) {
                MFcAmcache_PushString(H, pHive, pValue, ctx->psm, &pe->uszShortcutTargetPath);
                fAnyKnown = TRUE;
            }
        }
        /* Older modern-schema variants expose only one unnamed/unknown value. */
        if(!fAnyKnown && ObMap_Size(pmValues)) {
            pValue = ObMap_GetByIndex(pmValues, 0);
            if(pValue) { MFcAmcache_PushString(H, pHive, pValue, ctx->psm, &pe->uszShortcutPath); }
        }
    }
    if(!fProgramId && pKeyInfo->uszName[0]) {
        /* Some revisions use the subkey name as the shortcut program identifier. */
        ObStrMap_PushPtrUU(ctx->psm, pKeyInfo->uszName, &pe->uszShortcutProgramId, NULL);
    }
    Ob_DECREF(pmValues);
    return ObMap_Push(ctx->pmShortcuts, pe->dwIndex + 1, pe);   // in case of failure, leak 'pe' due to possibly open str ptrs.
}

static VOID MFcAmcache_ParseShortcuts(_In_ VMM_HANDLE H, _In_ POB_REGISTRY_HIVE pHive, _Inout_ PMFCAMCACHE_INIT_CONTEXT ctx)
{
    MFcAmcache_ParseRootKeyList(H, pHive, ctx, "\\ROOT\\Root\\InventoryApplicationShortcut", MFCAMCACHE_MAX_SHORTCUTS, &ctx->fInventoryApplicationShortcutFound, &ctx->fShortcutsTruncated, MFcAmcache_ParseShortcutKey);
}

static BOOL MFcAmcache_ParseDriverBinaryKey(_In_ VMM_HANDLE H, _In_ POB_REGISTRY_HIVE pHive, _In_ POB_REGISTRY_KEY pKey, _In_ PVMM_REGISTRY_KEY_INFO pKeyInfo, _Inout_ PMFCAMCACHE_INIT_CONTEXT ctx)
{
    BOOL fDriverId = FALSE;
    DWORD i, iMax;
    QWORD qw = 0;
    CHAR uszDriverId[MFCAMCACHE_MAX_VALUE_UTF8];
    POB_MAP pmValues = NULL;
    POB_REGISTRY_VALUE pValue;
    VMM_REGISTRY_VALUE_INFO vi = { 0 };
    PVMM_MAP_AMCACHE_DRIVER_BINARY pe = LocalAlloc(LMEM_ZEROINIT, sizeof(VMM_MAP_AMCACHE_DRIVER_BINARY));
    if(!pe) { return FALSE; }
    pe->dwIndex = ObMap_Size(ctx->pmDriverBinaries);
    pe->iDriverPackage = MFCAMCACHE_INDEX_NONE;
    pe->ftKeyLastWrite = pKeyInfo->ftLastWrite;
    ObStrMap_PushPtrUU(ctx->psm, pKeyInfo->uszName, &pe->uszRegistrySubKey, NULL);
    if((pmValues = VmmWinReg_KeyValueList(H, pHive, pKey))) {
        iMax = min(ObMap_Size(pmValues), MFCAMCACHE_MAX_VALUES_PER_RECORD);
        for(i = 0; i < iMax; i++) {
            if(!(pValue = ObMap_GetByIndex(pmValues, i))) { continue; }
            ZeroMemory(&vi, sizeof(vi)); VmmWinReg_ValueInfo(pHive, pValue, &vi); vi.uszName[_countof(vi.uszName)-1] = 0;
            if(CharUtil_StrEquals(vi.uszName, "DriverCheckSum", TRUE)) { if(MFcAmcache_ReadQWORD(H,pHive,pValue,&qw)) pe->qwDriverCheckSum=qw; }
            else if(CharUtil_StrEquals(vi.uszName, "DriverTimeStamp", TRUE)) { if(MFcAmcache_ReadQWORD(H,pHive,pValue,&qw)) pe->qwDriverTimeStamp=qw; }
            else if(CharUtil_StrEquals(vi.uszName, "ImageSize", TRUE)) { if(MFcAmcache_ReadQWORD(H,pHive,pValue,&qw)) pe->cbImageSize=qw; }
            else if(CharUtil_StrEquals(vi.uszName, "DriverInBox", TRUE)) { if(MFcAmcache_ReadQWORD(H,pHive,pValue,&qw)) pe->fDriverInBox=qw?TRUE:FALSE; }
            else if(CharUtil_StrEquals(vi.uszName, "DriverIsKernelMode", TRUE)) { if(MFcAmcache_ReadQWORD(H,pHive,pValue,&qw)) pe->fDriverIsKernelMode=qw?TRUE:FALSE; }
            else if(CharUtil_StrEquals(vi.uszName, "DriverSigned", TRUE)) { if(MFcAmcache_ReadQWORD(H,pHive,pValue,&qw)) pe->fDriverSigned=qw?TRUE:FALSE; }
            else if(CharUtil_StrEquals(vi.uszName, "DriverName", TRUE)) { MFcAmcache_PushString(H,pHive,pValue,ctx->psm,&pe->uszDriverName); }
            else if(CharUtil_StrEquals(vi.uszName, "DriverCompany", TRUE)) { MFcAmcache_PushString(H,pHive,pValue,ctx->psm,&pe->uszDriverCompany); }
            else if(CharUtil_StrEquals(vi.uszName, "DriverPackageStrongName", TRUE)) { MFcAmcache_PushString(H,pHive,pValue,ctx->psm,&pe->uszDriverPackageStrongName); }
            else if(CharUtil_StrEquals(vi.uszName, "Service", TRUE)) { MFcAmcache_PushString(H,pHive,pValue,ctx->psm,&pe->uszService); }
            else if(CharUtil_StrEquals(vi.uszName, "Inf", TRUE)) { MFcAmcache_PushString(H,pHive,pValue,ctx->psm,&pe->uszInf); }
            else if(CharUtil_StrEquals(vi.uszName, "Product", TRUE)) { MFcAmcache_PushString(H,pHive,pValue,ctx->psm,&pe->uszProduct); }
            else if(CharUtil_StrEquals(vi.uszName, "ProductVersion", TRUE)) { MFcAmcache_PushString(H,pHive,pValue,ctx->psm,&pe->uszProductVersion); }
            else if(CharUtil_StrEquals(vi.uszName, "DriverVersion", TRUE)) { MFcAmcache_PushString(H,pHive,pValue,ctx->psm,&pe->uszDriverVersion); }
            else if(CharUtil_StrEquals(vi.uszName, "DriverLastWriteTime", TRUE)) { MFcAmcache_PushString(H,pHive,pValue,ctx->psm,&pe->uszDriverLastWriteTime); }
            else if(CharUtil_StrEquals(vi.uszName, "DriverType", TRUE)) { MFcAmcache_PushString(H,pHive,pValue,ctx->psm,&pe->uszDriverType); }
            else if(CharUtil_StrEquals(vi.uszName, "WdfVersion", TRUE)) { MFcAmcache_PushString(H,pHive,pValue,ctx->psm,&pe->uszWdfVersion); }
            else if(CharUtil_StrEquals(vi.uszName, "COMPID", TRUE)) { MFcAmcache_PushString(H,pHive,pValue,ctx->psm,&pe->uszCOMPID); }
            else if(CharUtil_StrEquals(vi.uszName, "HWID", TRUE)) { MFcAmcache_PushString(H,pHive,pValue,ctx->psm,&pe->uszHWID); }
            else if(CharUtil_StrEquals(vi.uszName, "DriverId", TRUE)) {
                fDriverId = MFcAmcache_ReadString(H, pHive, pValue, uszDriverId, sizeof(uszDriverId));
                if(fDriverId) {
                    ObStrMap_PushPtrUU(ctx->psm, uszDriverId, &pe->uszDriverId, NULL);
                }
            }
        }
    }
    if(!fDriverId && pKeyInfo->uszName[0]) {
        ObStrMap_PushPtrUU(ctx->psm, pKeyInfo->uszName, &pe->uszDriverId, NULL);
    }
    Ob_DECREF(pmValues);
    return ObMap_Push(ctx->pmDriverBinaries, pe->dwIndex + 1, pe);   // in case of failure, leak 'pe' due to possibly open str ptrs.
}

static VOID MFcAmcache_ParseDriverBinaries(_In_ VMM_HANDLE H, _In_ POB_REGISTRY_HIVE pHive, _Inout_ PMFCAMCACHE_INIT_CONTEXT ctx)
{
    MFcAmcache_ParseRootKeyList(H, pHive, ctx, "\\ROOT\\Root\\InventoryDriverBinary", MFCAMCACHE_MAX_DRIVER_BINARIES, &ctx->fInventoryDriverBinaryFound, &ctx->fDriverBinariesTruncated, MFcAmcache_ParseDriverBinaryKey);
}

static BOOL MFcAmcache_ParseDriverPackageKey(_In_ VMM_HANDLE H, _In_ POB_REGISTRY_HIVE pHive, _In_ POB_REGISTRY_KEY pKey, _In_ PVMM_REGISTRY_KEY_INFO pKeyInfo, _Inout_ PMFCAMCACHE_INIT_CONTEXT ctx)
{
    DWORD i, iMax;
    QWORD qw = 0;
    POB_MAP pmValues = NULL;
    POB_REGISTRY_VALUE pValue;
    VMM_REGISTRY_VALUE_INFO vi = { 0 };
    PVMM_MAP_AMCACHE_DRIVER_PACKAGE pe = LocalAlloc(LMEM_ZEROINIT, sizeof(VMM_MAP_AMCACHE_DRIVER_PACKAGE));
    if(!pe) { return FALSE; }
    pe->dwIndex = ObMap_Size(ctx->pmDriverPackages);
    pe->ftKeyLastWrite = pKeyInfo->ftLastWrite;
    ObStrMap_PushPtrUU(ctx->psm, pKeyInfo->uszName, &pe->uszRegistrySubKey, NULL);
    if((pmValues = VmmWinReg_KeyValueList(H, pHive, pKey))) {
        iMax = min(ObMap_Size(pmValues), MFCAMCACHE_MAX_VALUES_PER_RECORD);
        for(i = 0; i < iMax; i++) {
            if(!(pValue = ObMap_GetByIndex(pmValues, i))) { continue; }
            ZeroMemory(&vi, sizeof(vi)); VmmWinReg_ValueInfo(pHive,pValue,&vi); vi.uszName[_countof(vi.uszName)-1]=0;
            if(CharUtil_StrEquals(vi.uszName,"DriverInBox",TRUE)) { if(MFcAmcache_ReadQWORD(H,pHive,pValue,&qw)) pe->fDriverInBox=qw?TRUE:FALSE; }
            else if(CharUtil_StrEquals(vi.uszName,"Class",TRUE)) { MFcAmcache_PushString(H,pHive,pValue,ctx->psm,&pe->uszClass); }
            else if(CharUtil_StrEquals(vi.uszName,"ClassGuid",TRUE)) { MFcAmcache_PushString(H,pHive,pValue,ctx->psm,&pe->uszClassGuid); }
            else if(CharUtil_StrEquals(vi.uszName,"Date",TRUE)) { MFcAmcache_PushString(H,pHive,pValue,ctx->psm,&pe->uszDate); }
            else if(CharUtil_StrEquals(vi.uszName,"Directory",TRUE)) { MFcAmcache_PushString(H,pHive,pValue,ctx->psm,&pe->uszDirectory); }
            else if(CharUtil_StrEquals(vi.uszName,"Inf",TRUE)) { MFcAmcache_PushString(H,pHive,pValue,ctx->psm,&pe->uszInf); }
            else if(CharUtil_StrEquals(vi.uszName,"Provider",TRUE)) { MFcAmcache_PushString(H,pHive,pValue,ctx->psm,&pe->uszProvider); }
            else if(CharUtil_StrEquals(vi.uszName,"Version",TRUE)) { MFcAmcache_PushString(H,pHive,pValue,ctx->psm,&pe->uszVersion); }
            else if(CharUtil_StrEquals(vi.uszName,"FlightIds",TRUE)) { MFcAmcache_ReadListString(H,pHive,pValue,ctx->psm,&pe->uszFlightIds,NULL,NULL); }
            else if(CharUtil_StrEquals(vi.uszName,"RecoveryIds",TRUE)) { MFcAmcache_ReadListString(H,pHive,pValue,ctx->psm,&pe->uszRecoveryIds,NULL,NULL); }
            else if(CharUtil_StrEquals(vi.uszName,"SubmissionId",TRUE)) { MFcAmcache_PushString(H,pHive,pValue,ctx->psm,&pe->uszSubmissionId); }
            else if(CharUtil_StrEquals(vi.uszName,"HWIDs",TRUE) || CharUtil_StrEquals(vi.uszName,"Hwids",TRUE)) { MFcAmcache_ReadListString(H,pHive,pValue,ctx->psm,&pe->uszHWIDs,NULL,NULL); }
            else if(CharUtil_StrEquals(vi.uszName,"SYSFILE",TRUE)) { MFcAmcache_ReadListString(H,pHive,pValue,ctx->psm,&pe->uszSYSFILE,NULL,NULL); }
        }
    }
    Ob_DECREF(pmValues);
    return ObMap_Push(ctx->pmDriverPackages, pe->dwIndex + 1, pe);   // in case of failure, leak 'pe' due to possibly open str ptrs.
}

static VOID MFcAmcache_ParseDriverPackages(_In_ VMM_HANDLE H, _In_ POB_REGISTRY_HIVE pHive, _Inout_ PMFCAMCACHE_INIT_CONTEXT ctx)
{
    MFcAmcache_ParseRootKeyList(H, pHive, ctx, "\\ROOT\\Root\\InventoryDriverPackage", MFCAMCACHE_MAX_DRIVER_PACKAGES, &ctx->fInventoryDriverPackageFound, &ctx->fDriverPackagesTruncated, MFcAmcache_ParseDriverPackageKey);
}

static BOOL MFcAmcache_ParseDeviceContainerKey(_In_ VMM_HANDLE H, _In_ POB_REGISTRY_HIVE pHive, _In_ POB_REGISTRY_KEY pKey, _In_ PVMM_REGISTRY_KEY_INFO pKeyInfo, _Inout_ PMFCAMCACHE_INIT_CONTEXT ctx)
{
    DWORD i, iMax;
    QWORD qw = 0;
    POB_MAP pmValues = NULL;
    POB_REGISTRY_VALUE pValue;
    VMM_REGISTRY_VALUE_INFO vi = { 0 };
    PVMM_MAP_AMCACHE_DEVICE_CONTAINER pe;
    pe = LocalAlloc(LMEM_ZEROINIT, sizeof(VMM_MAP_AMCACHE_DEVICE_CONTAINER));
    if(!pe) { return FALSE; }
    pe->dwIndex=ObMap_Size(ctx->pmDeviceContainers); pe->ftKeyLastWrite=pKeyInfo->ftLastWrite;
    ObStrMap_PushPtrUU(ctx->psm,pKeyInfo->uszName,&pe->uszRegistrySubKey,NULL);
    if((pmValues = VmmWinReg_KeyValueList(H,pHive,pKey))) {
        iMax = min(ObMap_Size(pmValues), MFCAMCACHE_MAX_VALUES_PER_RECORD);
        for(i = 0; i < iMax; i++) {
            if(!(pValue = ObMap_GetByIndex(pmValues, i))) { continue; }
            ZeroMemory(&vi, sizeof(vi));
            VmmWinReg_ValueInfo(pHive, pValue, &vi);
            vi.uszName[_countof(vi.uszName) - 1] = 0;
            if(CharUtil_StrEquals(vi.uszName,"IsActive",TRUE)) { if(MFcAmcache_ReadQWORD(H,pHive,pValue,&qw)) pe->fIsActive=qw?TRUE:FALSE; }
            else if(CharUtil_StrEquals(vi.uszName,"IsConnected",TRUE)) { if(MFcAmcache_ReadQWORD(H,pHive,pValue,&qw)) pe->fIsConnected=qw?TRUE:FALSE; }
            else if(CharUtil_StrEquals(vi.uszName,"IsMachineContainer",TRUE)) { if(MFcAmcache_ReadQWORD(H,pHive,pValue,&qw)) pe->fIsMachineContainer=qw?TRUE:FALSE; }
            else if(CharUtil_StrEquals(vi.uszName,"IsNetworked",TRUE)) { if(MFcAmcache_ReadQWORD(H,pHive,pValue,&qw)) pe->fIsNetworked=qw?TRUE:FALSE; }
            else if(CharUtil_StrEquals(vi.uszName,"IsPaired",TRUE)) { if(MFcAmcache_ReadQWORD(H,pHive,pValue,&qw)) pe->fIsPaired=qw?TRUE:FALSE; }
            else if(CharUtil_StrEquals(vi.uszName,"Categories",TRUE)) { MFcAmcache_ReadListString(H,pHive,pValue,ctx->psm,&pe->uszCategories,NULL,NULL); }
            else if(CharUtil_StrEquals(vi.uszName,"DiscoveryMethod",TRUE)) { MFcAmcache_PushString(H,pHive,pValue,ctx->psm,&pe->uszDiscoveryMethod); }
            else if(CharUtil_StrEquals(vi.uszName,"FriendlyName",TRUE)) { MFcAmcache_PushString(H,pHive,pValue,ctx->psm,&pe->uszFriendlyName); }
            else if(CharUtil_StrEquals(vi.uszName,"Icon",TRUE)) { MFcAmcache_PushString(H,pHive,pValue,ctx->psm,&pe->uszIcon); }
            else if(CharUtil_StrEquals(vi.uszName,"Manufacturer",TRUE)) { MFcAmcache_PushString(H,pHive,pValue,ctx->psm,&pe->uszManufacturer); }
            else if(CharUtil_StrEquals(vi.uszName,"ModelId",TRUE)) { MFcAmcache_PushString(H,pHive,pValue,ctx->psm,&pe->uszModelId); }
            else if(CharUtil_StrEquals(vi.uszName,"ModelName",TRUE)) { MFcAmcache_PushString(H,pHive,pValue,ctx->psm,&pe->uszModelName); }
            else if(CharUtil_StrEquals(vi.uszName,"ModelNumber",TRUE)) { MFcAmcache_PushString(H,pHive,pValue,ctx->psm,&pe->uszModelNumber); }
            else if(CharUtil_StrEquals(vi.uszName,"PrimaryCategory",TRUE)) { MFcAmcache_PushString(H,pHive,pValue,ctx->psm,&pe->uszPrimaryCategory); }
            else if(CharUtil_StrEquals(vi.uszName,"State",TRUE)) { MFcAmcache_PushString(H,pHive,pValue,ctx->psm,&pe->uszState); }
        }
    }
    Ob_DECREF(pmValues);
    return ObMap_Push(ctx->pmDeviceContainers, pe->dwIndex + 1, pe);   // in case of failure, leak 'pe' due to possibly open str ptrs.
}

static VOID MFcAmcache_ParseDeviceContainers(_In_ VMM_HANDLE H, _In_ POB_REGISTRY_HIVE pHive, _Inout_ PMFCAMCACHE_INIT_CONTEXT ctx)
{
    MFcAmcache_ParseRootKeyList(H,pHive,ctx,"\\ROOT\\Root\\InventoryDeviceContainer",MFCAMCACHE_MAX_DEVICE_CONTAINERS,&ctx->fInventoryDeviceContainerFound,&ctx->fDeviceContainersTruncated,MFcAmcache_ParseDeviceContainerKey);
}

static BOOL MFcAmcache_ParseDevicePnpKey(_In_ VMM_HANDLE H, _In_ POB_REGISTRY_HIVE pHive, _In_ POB_REGISTRY_KEY pKey, _In_ PVMM_REGISTRY_KEY_INFO pKeyInfo, _Inout_ PMFCAMCACHE_INIT_CONTEXT ctx)
{
    DWORD i, iMax;
    POB_MAP pmValues = NULL;
    POB_REGISTRY_VALUE pValue;
    VMM_REGISTRY_VALUE_INFO vi = { 0 };
    PVMM_MAP_AMCACHE_DEVICE_PNP pe;
    pe = LocalAlloc(LMEM_ZEROINIT, sizeof(VMM_MAP_AMCACHE_DEVICE_PNP));
    if(!pe) { return FALSE; }
    pe->dwIndex = ObMap_Size(ctx->pmDevicePnps);
    pe->iDeviceContainer = MFCAMCACHE_INDEX_NONE;
    pe->iDriverBinary = MFCAMCACHE_INDEX_NONE;
    pe->iDriverPackage = MFCAMCACHE_INDEX_NONE;
    pe->ftKeyLastWrite = pKeyInfo->ftLastWrite;
    ObStrMap_PushPtrUU(ctx->psm, pKeyInfo->uszName, &pe->uszRegistrySubKey, NULL);
    if((pmValues=VmmWinReg_KeyValueList(H,pHive,pKey))) {
        iMax=min(ObMap_Size(pmValues),MFCAMCACHE_MAX_VALUES_PER_RECORD);
        for(i = 0; i < iMax; i++) {
            if(!(pValue = ObMap_GetByIndex(pmValues, i))) { continue; }
            ZeroMemory(&vi, sizeof(vi));
            VmmWinReg_ValueInfo(pHive, pValue, &vi);
            vi.uszName[_countof(vi.uszName) - 1] = 0;
            if(CharUtil_StrEquals(vi.uszName, "BusReportedDescription", TRUE)) { MFcAmcache_PushString(H, pHive, pValue, ctx->psm, &pe->uszBusReportedDescription); }
            else if(CharUtil_StrEquals(vi.uszName, "Class", TRUE)) { MFcAmcache_PushString(H, pHive, pValue, ctx->psm, &pe->uszClass); }
            else if(CharUtil_StrEquals(vi.uszName, "ClassGuid", TRUE)) { MFcAmcache_PushString(H, pHive, pValue, ctx->psm, &pe->uszClassGuid); }
            else if(CharUtil_StrEquals(vi.uszName, "COMPID", TRUE)) { MFcAmcache_ReadListString(H, pHive, pValue, ctx->psm, &pe->uszCOMPID, NULL, NULL); }
            else if(CharUtil_StrEquals(vi.uszName, "ContainerId", TRUE)) { MFcAmcache_PushString(H, pHive, pValue, ctx->psm, &pe->uszContainerId); }
            else if(CharUtil_StrEquals(vi.uszName, "Description", TRUE)) { MFcAmcache_PushString(H, pHive, pValue, ctx->psm, &pe->uszDescription); }
            else if(CharUtil_StrEquals(vi.uszName, "DeviceState", TRUE)) { MFcAmcache_PushString(H, pHive, pValue, ctx->psm, &pe->uszDeviceState); }
            else if(CharUtil_StrEquals(vi.uszName, "DriverId", TRUE)) { MFcAmcache_PushString(H, pHive, pValue, ctx->psm, &pe->uszDriverId); }
            else if(CharUtil_StrEquals(vi.uszName, "DriverName", TRUE)) { MFcAmcache_PushString(H, pHive, pValue, ctx->psm, &pe->uszDriverName); }
            else if(CharUtil_StrEquals(vi.uszName, "DriverPackageStrongName", TRUE)) { MFcAmcache_PushString(H, pHive, pValue, ctx->psm, &pe->uszDriverPackageStrongName); }
            else if(CharUtil_StrEquals(vi.uszName, "DriverVerDate", TRUE)) { MFcAmcache_PushString(H, pHive, pValue, ctx->psm, &pe->uszDriverVerDate); }
            else if(CharUtil_StrEquals(vi.uszName, "DriverVerVersion", TRUE)) { MFcAmcache_PushString(H, pHive, pValue, ctx->psm, &pe->uszDriverVerVersion); }
            else if(CharUtil_StrEquals(vi.uszName, "Enumerator", TRUE)) { MFcAmcache_PushString(H, pHive, pValue, ctx->psm, &pe->uszEnumerator); }
            else if(CharUtil_StrEquals(vi.uszName, "HWID", TRUE)) { MFcAmcache_ReadListString(H, pHive, pValue, ctx->psm, &pe->uszHWID, NULL, NULL); }
            else if(CharUtil_StrEquals(vi.uszName, "Inf", TRUE)) { MFcAmcache_PushString(H, pHive, pValue, ctx->psm, &pe->uszInf); }
            else if(CharUtil_StrEquals(vi.uszName, "InstallState", TRUE)) { MFcAmcache_PushString(H, pHive, pValue, ctx->psm, &pe->uszInstallState); }
            else if(CharUtil_StrEquals(vi.uszName, "Manufacturer", TRUE)) { MFcAmcache_PushString(H, pHive, pValue, ctx->psm, &pe->uszManufacturer); }
            else if(CharUtil_StrEquals(vi.uszName, "MatchingID", TRUE)) { MFcAmcache_PushString(H, pHive, pValue, ctx->psm, &pe->uszMatchingID); }
            else if(CharUtil_StrEquals(vi.uszName, "Model", TRUE)) { MFcAmcache_PushString(H, pHive, pValue, ctx->psm, &pe->uszModel); }
            else if(CharUtil_StrEquals(vi.uszName, "ParentId", TRUE)) { MFcAmcache_PushString(H, pHive, pValue, ctx->psm, &pe->uszParentId); }
            else if(CharUtil_StrEquals(vi.uszName, "ProblemCode", TRUE)) { MFcAmcache_PushString(H, pHive, pValue, ctx->psm, &pe->uszProblemCode); }
            else if(CharUtil_StrEquals(vi.uszName, "Provider", TRUE)) { MFcAmcache_PushString(H, pHive, pValue, ctx->psm, &pe->uszProvider); }
            else if(CharUtil_StrEquals(vi.uszName, "Service", TRUE)) { MFcAmcache_PushString(H, pHive, pValue, ctx->psm, &pe->uszService); }
            else if(CharUtil_StrEquals(vi.uszName, "STACKID", TRUE)) { MFcAmcache_ReadListString(H, pHive, pValue, ctx->psm, &pe->uszSTACKID, NULL, NULL); }
        }
    }
    Ob_DECREF(pmValues);
    return ObMap_Push(ctx->pmDevicePnps, pe->dwIndex + 1, pe);   // in case of failure, leak 'pe' due to possibly open str ptrs.
}

static VOID MFcAmcache_ParseDevicePnps(_In_ VMM_HANDLE H, _In_ POB_REGISTRY_HIVE pHive, _Inout_ PMFCAMCACHE_INIT_CONTEXT ctx)
{
    MFcAmcache_ParseRootKeyList(H, pHive, ctx, "\\ROOT\\Root\\InventoryDevicePnp", MFCAMCACHE_MAX_DEVICE_PNPS, &ctx->fInventoryDevicePnpFound, &ctx->fDevicePnpsTruncated, MFcAmcache_ParseDevicePnpKey);
}

static VOID MFcAmcache_MapPushFirst(_In_ POB_MAP pm, _In_opt_ LPCSTR usz, _In_ PVOID pv)
{
    if(pm && usz && usz[0]) {
        ObMap_Push(pm, MFcAmcache_Hash(usz), pv);
    }
}

static PVMM_MAP_AMCACHE_DRIVER_PACKAGE MFcAmcache_FindDriverPackage(_In_ PMFCAMCACHE_INIT_CONTEXT ctx, _In_opt_ LPCSTR uszStrongName, _In_opt_ LPCSTR uszInf)
{
    QWORD qwHash;
    PVMM_MAP_AMCACHE_DRIVER_PACKAGE pe;
    if(uszStrongName && uszStrongName[0]) {
        qwHash = MFcAmcache_Hash(uszStrongName);
        pe = ObMap_GetByKey(ctx->pmDriverPackagesByStrongName, qwHash);
        if(pe && (!_stricmp(VMM_STR_NONULL(pe->uszRegistrySubKey), uszStrongName) || !_stricmp(MFcAmcache_PathBaseName(pe->uszDirectory), uszStrongName))) { return pe; }
    }
    if(uszInf && uszInf[0]) {
        qwHash = MFcAmcache_Hash(MFcAmcache_PathBaseName(uszInf));
        pe = ObMap_GetByKey(ctx->pmDriverPackagesByInf, qwHash);
        if(pe && !_stricmp(MFcAmcache_PathBaseName(pe->uszInf), MFcAmcache_PathBaseName(uszInf))) { return pe; }
    }
    return NULL;
}

static VOID MFcAmcache_BuildIndexes(_In_ VMM_HANDLE H, _Inout_ PMFCAMCACHE_INIT_CONTEXT ctx)
{
    DWORD i;
    PVMM_MAP_AMCACHE_APPLICATION peApp, peFirst;
    PVMM_MAP_AMCACHE_DRIVER_BINARY peBinary;
    PVMM_MAP_AMCACHE_DRIVER_PACKAGE pePackage;
    PVMM_MAP_AMCACHE_DEVICE_CONTAINER peContainer;
    Ob_DECREF_NULL(&ctx->pmApplicationsByProgramId);
    Ob_DECREF_NULL(&ctx->pmDriverBinariesByService);
    Ob_DECREF_NULL(&ctx->pmDriverBinariesByDriverId);
    Ob_DECREF_NULL(&ctx->pmDriverPackagesByStrongName);
    Ob_DECREF_NULL(&ctx->pmDriverPackagesByInf);
    Ob_DECREF_NULL(&ctx->pmDeviceContainersById);
    ctx->pmApplicationsByProgramId = ObMap_New(H, OB_MAP_FLAGS_OBJECT_VOID);
    ctx->pmDriverBinariesByService = ObMap_New(H, OB_MAP_FLAGS_OBJECT_VOID);
    ctx->pmDriverBinariesByDriverId = ObMap_New(H, OB_MAP_FLAGS_OBJECT_VOID);
    ctx->pmDriverPackagesByStrongName = ObMap_New(H, OB_MAP_FLAGS_OBJECT_VOID);
    ctx->pmDriverPackagesByInf = ObMap_New(H, OB_MAP_FLAGS_OBJECT_VOID);
    ctx->pmDeviceContainersById = ObMap_New(H, OB_MAP_FLAGS_OBJECT_VOID);
    for(i = 0; i < ObMap_Size(ctx->pmApplications); i++) {
        peApp = ObMap_GetByIndex(ctx->pmApplications, i);
        if(!peApp) { continue; }
        peApp->cFiles = peApp->cShortcuts = 0;
        peApp->qwProgramIdHash = MFcAmcache_Hash(peApp->uszProgramId);
        if(peApp->qwProgramIdHash && ctx->pmApplicationsByProgramId) {
            peFirst = ObMap_GetByKey(ctx->pmApplicationsByProgramId, peApp->qwProgramIdHash);
            if(peFirst && MFcAmcache_IdEquals(peFirst->uszProgramId, peApp->uszProgramId)) {
                peFirst->dwFlags |= MFCAMCACHE_APP_FLAG_PROGRAMID_DUPLICATE;
                peApp->dwFlags |= MFCAMCACHE_APP_FLAG_PROGRAMID_DUPLICATE;
            } else if(!peFirst) {
                ObMap_Push(ctx->pmApplicationsByProgramId, peApp->qwProgramIdHash, peApp);
            }
        }
    }
    for(i = 0; i < ObMap_Size(ctx->pmDriverPackages); i++) {
        pePackage = ObMap_GetByIndex(ctx->pmDriverPackages, i);
        if(!pePackage) { continue; }
        pePackage->cDriverBinaries = pePackage->cDevices = 0;
        MFcAmcache_MapPushFirst(ctx->pmDriverPackagesByStrongName, pePackage->uszRegistrySubKey, pePackage);
        MFcAmcache_MapPushFirst(ctx->pmDriverPackagesByStrongName, MFcAmcache_PathBaseName(pePackage->uszDirectory), pePackage);
        MFcAmcache_MapPushFirst(ctx->pmDriverPackagesByInf, MFcAmcache_PathBaseName(pePackage->uszInf), pePackage);
    }
    for(i = 0; i < ObMap_Size(ctx->pmDriverBinaries); i++) {
        peBinary = ObMap_GetByIndex(ctx->pmDriverBinaries, i);
        if(!peBinary) { continue; }
        peBinary->cDevices = 0;
        MFcAmcache_MapPushFirst(ctx->pmDriverBinariesByService, peBinary->uszService, peBinary);
        MFcAmcache_MapPushFirst(ctx->pmDriverBinariesByDriverId, peBinary->uszDriverId, peBinary);
        MFcAmcache_MapPushFirst(ctx->pmDriverBinariesByDriverId, peBinary->uszRegistrySubKey, peBinary);
    }
    for(i = 0; i < ObMap_Size(ctx->pmDeviceContainers); i++) {
        peContainer = ObMap_GetByIndex(ctx->pmDeviceContainers, i);
        if(!peContainer) { continue; }
        peContainer->cDevices = 0;
        MFcAmcache_MapPushFirst(ctx->pmDeviceContainersById, peContainer->uszRegistrySubKey, peContainer);
    }
}

static VOID MFcAmcache_JoinAll(_In_ VMM_HANDLE H, _Inout_ PMFCAMCACHE_INIT_CONTEXT ctx, _Out_ PDWORD pcFilesAssociated, _Out_ PDWORD pcFilesUnassociated, _Out_ PDWORD pcShortcutsAssociated)
{
    DWORD i, iMax;
    PVMM_MAP_AMCACHE_APPLICATION peApp;
    PVMM_MAP_AMCACHE_FILE peFile;
    PVMM_MAP_AMCACHE_SHORTCUT peShortcut;
    PVMM_MAP_AMCACHE_DRIVER_BINARY peBinary;
    PVMM_MAP_AMCACHE_DRIVER_PACKAGE pePackage;
    PVMM_MAP_AMCACHE_DEVICE_CONTAINER peContainer;
    PVMM_MAP_AMCACHE_DEVICE_PNP peDevice;
    *pcFilesAssociated = *pcFilesUnassociated = *pcShortcutsAssociated = 0;
    MFcAmcache_BuildIndexes(H, ctx);
    iMax = ObMap_Size(ctx->pmFiles);
    for(i = 0; i < iMax; i++) {
        peFile = ObMap_GetByIndex(ctx->pmFiles, i);
        if(!peFile) { continue; }
        peFile->iApplication = MFCAMCACHE_INDEX_NONE;
        peFile->qwProgramIdHash = MFcAmcache_Hash(peFile->uszProgramId);
        peApp = ObMap_GetByKey(ctx->pmApplicationsByProgramId, peFile->qwProgramIdHash);
        if(peApp) { peFile->iApplication = peApp->dwIndex; peApp->cFiles++; (*pcFilesAssociated)++; } else { (*pcFilesUnassociated)++; }
    }
    iMax = ObMap_Size(ctx->pmShortcuts);
    for(i = 0; i < iMax; i++) {
        peShortcut = ObMap_GetByIndex(ctx->pmShortcuts, i);
        if(!peShortcut) { continue; }
        peShortcut->iApplication = MFCAMCACHE_INDEX_NONE;
        peApp = ObMap_GetByKey(ctx->pmApplicationsByProgramId, MFcAmcache_Hash(peShortcut->uszShortcutProgramId));
        if(peApp) { peShortcut->iApplication = peApp->dwIndex; peApp->cShortcuts++; (*pcShortcutsAssociated)++; }
    }
    iMax = ObMap_Size(ctx->pmDriverBinaries);
    for(i = 0; i < iMax; i++) {
        peBinary = ObMap_GetByIndex(ctx->pmDriverBinaries, i);
        if(!peBinary) { continue; }
        peBinary->iDriverPackage = MFCAMCACHE_INDEX_NONE;
        pePackage = MFcAmcache_FindDriverPackage(ctx, peBinary->uszDriverPackageStrongName, peBinary->uszInf);
        if(pePackage) { peBinary->iDriverPackage = pePackage->dwIndex; pePackage->cDriverBinaries++; }
    }
    iMax = ObMap_Size(ctx->pmDevicePnps);
    for(i = 0; i < iMax; i++) {
        peDevice = ObMap_GetByIndex(ctx->pmDevicePnps, i);
        if(!peDevice) { continue; }
        peDevice->iDeviceContainer = peDevice->iDriverBinary = peDevice->iDriverPackage = MFCAMCACHE_INDEX_NONE;
        peContainer = ObMap_GetByKey(ctx->pmDeviceContainersById, MFcAmcache_Hash(peDevice->uszContainerId));
        if(peContainer) { peDevice->iDeviceContainer = peContainer->dwIndex; peContainer->cDevices++; }
        peBinary = ObMap_GetByKey(ctx->pmDriverBinariesByDriverId, MFcAmcache_Hash(peDevice->uszDriverId));
        if(!peBinary) {
            peBinary = ObMap_GetByKey(ctx->pmDriverBinariesByService, MFcAmcache_Hash(peDevice->uszService));
        }
        if(peBinary) {
            peDevice->iDriverBinary = peBinary->dwIndex;
            peBinary->cDevices++;
        }
        pePackage = MFcAmcache_FindDriverPackage(ctx, peDevice->uszDriverPackageStrongName, peDevice->uszInf);
        if(!pePackage && peBinary && (peBinary->iDriverPackage != MFCAMCACHE_INDEX_NONE)) {
            pePackage = ObMap_GetByIndex(ctx->pmDriverPackages, peBinary->iDriverPackage);
        }
        if(pePackage) { peDevice->iDriverPackage = pePackage->dwIndex; pePackage->cDevices++; }
    }

}

VOID MFcAmcache_CloseObCallback(_In_ PVMMOB_MAP_AMCACHE pOb)
{
    LocalFree(pOb->pbMultiText);
    LocalFree(pOb->pbSummary);
}

static VOID MFcAmcache_InitializeSummary(_In_ PVMMOB_MAP_AMCACHE pObMap)
{
    LPSTR usz;
    int cch;
    if(!(usz = LocalAlloc(0, 0x00100000))) { return; }
    cch = _snprintf_s(
        usz,
        0x00100000,
        _TRUNCATE,
        "MemProcFS AmCache inventory parser:\n"
        "\n"
        "Hive found                         : %s\n"
        "Hive name                          : %s\n"
        "Hive path                          : %s\n"
        "InventoryApplication               : %s\n"
        "InventoryApplicationFile           : %s\n"
        "InventoryApplicationShortcut       : %s\n"
        "InventoryDriverBinary              : %s\n"
        "InventoryDriverPackage             : %s\n"
        "InventoryDeviceContainer           : %s\n"
        "InventoryDevicePnp                 : %s\n"
        "Applications                       : %u%s\n"
        "Files                              : %u%s\n"
        "Files associated by ProgramId      : %u\n"
        "Files unassociated                 : %u\n"
        "Shortcuts                          : %u%s\n"
        "Shortcuts associated by ProgramId  : %u\n"
        "Driver binaries                    : %u%s\n"
        "Driver packages                    : %u%s\n"
        "Device containers                  : %u%s\n"
        "PnP devices                        : %u%s\n"
        "\n"
        "Evidence note:\n"
        "  AmCache records establish application, file, driver or device inventory/presence.\n"
        "  They are not, by themselves, proof that a file was executed.\n"
        "\n"
        "Correlation note:\n"
        "  Application files and shortcuts are joined by ProgramId.\n"
        "  Drivers are correlated by service, DriverId, package strong name and INF.\n"
        "  PnP devices are correlated to containers, driver binaries and packages.\n",
        pObMap->fHiveFound ? "yes" : "no",
        pObMap->uszHiveName,
        pObMap->uszHiveRootPath,
        pObMap->fInventoryApplicationFound ? "yes" : "no",
        pObMap->fInventoryApplicationFileFound ? "yes" : "no",
        pObMap->fInventoryApplicationShortcutFound ? "yes" : "no",
        pObMap->fInventoryDriverBinaryFound ? "yes" : "no",
        pObMap->fInventoryDriverPackageFound ? "yes" : "no",
        pObMap->fInventoryDeviceContainerFound ? "yes" : "no",
        pObMap->fInventoryDevicePnpFound ? "yes" : "no",
        pObMap->cApplications, pObMap->fApplicationsTruncated ? " (truncated)" : "",
        pObMap->cFiles, pObMap->fFilesTruncated ? " (truncated)" : "",
        pObMap->cFilesAssociated,
        pObMap->cFilesUnassociated,
        pObMap->cShortcuts, pObMap->fShortcutsTruncated ? " (truncated)" : "",
        pObMap->cShortcutsAssociated,
        pObMap->cDriverBinaries, pObMap->fDriverBinariesTruncated ? " (truncated)" : "",
        pObMap->cDriverPackages, pObMap->fDriverPackagesTruncated ? " (truncated)" : "",
        pObMap->cDeviceContainers, pObMap->fDeviceContainersTruncated ? " (truncated)" : "",
        pObMap->cDevicePnps, pObMap->fDevicePnpsTruncated ? " (truncated)" : ""
    );
    if(cch < 0) { cch = 0; }
    pObMap->pbSummary = LocalAlloc(0, cch);
    if(pObMap->pbSummary) {
        memcpy(pObMap->pbSummary, usz, cch);
        pObMap->cbSummary = cch;
    }
    LocalFree(usz);
}

/*
 * Create a new AmCache map.
 * CALLER DECREF: return
 * -- H
 * -- return
 */
_Success_(return != NULL)
PVMMOB_MAP_AMCACHE MFcAmcache_Initialize(_In_ VMM_HANDLE H)
{
    DWORD i;
    DWORD cApplications, cFiles, cShortcuts;
    DWORD cDriverBinaries, cDriverPackages, cDeviceContainers, cDevicePnps;
    DWORD cFilesAssociated = 0, cFilesUnassociated = 0, cShortcutsAssociated = 0;
    QWORD cbMap64;
    PBYTE pbNext;
    POB_REGISTRY_HIVE pHive = NULL;
    PVMMOB_MAP_AMCACHE pObMap = NULL;
    PMFCAMCACHE_INIT_CONTEXT ctx = NULL;

    if(!(ctx = LocalAlloc(LMEM_ZEROINIT, sizeof(MFCAMCACHE_INIT_CONTEXT)))) { goto fail; }
    ctx->psm = ObStrMap_New(H, OB_STRMAP_FLAGS_CASE_SENSITIVE);
    ctx->pmApplications = ObMap_New(H, OB_MAP_FLAGS_OBJECT_LOCALFREE);
    ctx->pmFiles = ObMap_New(H, OB_MAP_FLAGS_OBJECT_LOCALFREE);
    ctx->pmShortcuts = ObMap_New(H, OB_MAP_FLAGS_OBJECT_LOCALFREE);
    ctx->pmDriverBinaries = ObMap_New(H, OB_MAP_FLAGS_OBJECT_LOCALFREE);
    ctx->pmDriverPackages = ObMap_New(H, OB_MAP_FLAGS_OBJECT_LOCALFREE);
    ctx->pmDeviceContainers = ObMap_New(H, OB_MAP_FLAGS_OBJECT_LOCALFREE);
    ctx->pmDevicePnps = ObMap_New(H, OB_MAP_FLAGS_OBJECT_LOCALFREE);
    if(!ctx->psm || !ctx->pmApplications || !ctx->pmFiles || !ctx->pmShortcuts) { goto fail; }
    if(!ctx->pmDriverBinaries || !ctx->pmDriverPackages || !ctx->pmDeviceContainers || !ctx->pmDevicePnps) { goto fail; }

    pHive = MFcAmcache_LocateHive(H);
    if(pHive) {
        ctx->fHiveFound = TRUE;
        strncpy_s(ctx->uszHiveName, sizeof(ctx->uszHiveName), pHive->uszName, _TRUNCATE);
        strncpy_s(ctx->uszHiveRootPath, sizeof(ctx->uszHiveRootPath), pHive->uszHiveRootPath, _TRUNCATE);
        MFcAmcache_ParseApplications(H, pHive, ctx);
        MFcAmcache_ParseFiles(H, pHive, ctx);
        MFcAmcache_ParseShortcuts(H, pHive, ctx);
        MFcAmcache_ParseDriverPackages(H, pHive, ctx);
        MFcAmcache_ParseDriverBinaries(H, pHive, ctx);
        MFcAmcache_ParseDeviceContainers(H, pHive, ctx);
        MFcAmcache_ParseDevicePnps(H, pHive, ctx);
    }

    cApplications = ObMap_Size(ctx->pmApplications);
    cFiles = ObMap_Size(ctx->pmFiles);
    cShortcuts = ObMap_Size(ctx->pmShortcuts);
    cDriverBinaries = ObMap_Size(ctx->pmDriverBinaries);
    cDriverPackages = ObMap_Size(ctx->pmDriverPackages);
    cDeviceContainers = ObMap_Size(ctx->pmDeviceContainers);
    cDevicePnps = ObMap_Size(ctx->pmDevicePnps);
    cbMap64 = sizeof(VMMOB_MAP_AMCACHE) +
        (QWORD)cApplications * sizeof(VMM_MAP_AMCACHE_APPLICATION) +
        (QWORD)cFiles * sizeof(VMM_MAP_AMCACHE_FILE) +
        (QWORD)cShortcuts * sizeof(VMM_MAP_AMCACHE_SHORTCUT) +
        (QWORD)cDriverBinaries * sizeof(VMM_MAP_AMCACHE_DRIVER_BINARY) +
        (QWORD)cDriverPackages * sizeof(VMM_MAP_AMCACHE_DRIVER_PACKAGE) +
        (QWORD)cDeviceContainers * sizeof(VMM_MAP_AMCACHE_DEVICE_CONTAINER) +
        (QWORD)cDevicePnps * sizeof(VMM_MAP_AMCACHE_DEVICE_PNP);
    if(cbMap64 > 0x7fffffffULL) { goto fail; }
    pObMap = Ob_AllocEx(H, OB_TAG_MAP_AMCACHE, LMEM_ZEROINIT, (SIZE_T)cbMap64, (OB_CLEANUP_CB)MFcAmcache_CloseObCallback, NULL);
    if(!pObMap) { goto fail; }
    pbNext = (PBYTE)pObMap + sizeof(VMMOB_MAP_AMCACHE);
    pObMap->pApplications = (PVMM_MAP_AMCACHE_APPLICATION)pbNext; pbNext += (SIZE_T)cApplications * sizeof(VMM_MAP_AMCACHE_APPLICATION);
    pObMap->pFiles = (PVMM_MAP_AMCACHE_FILE)pbNext; pbNext += (SIZE_T)cFiles * sizeof(VMM_MAP_AMCACHE_FILE);
    pObMap->pShortcuts = (PVMM_MAP_AMCACHE_SHORTCUT)pbNext; pbNext += (SIZE_T)cShortcuts * sizeof(VMM_MAP_AMCACHE_SHORTCUT);
    pObMap->pDriverBinaries = (PVMM_MAP_AMCACHE_DRIVER_BINARY)pbNext; pbNext += (SIZE_T)cDriverBinaries * sizeof(VMM_MAP_AMCACHE_DRIVER_BINARY);
    pObMap->pDriverPackages = (PVMM_MAP_AMCACHE_DRIVER_PACKAGE)pbNext; pbNext += (SIZE_T)cDriverPackages * sizeof(VMM_MAP_AMCACHE_DRIVER_PACKAGE);
    pObMap->pDeviceContainers = (PVMM_MAP_AMCACHE_DEVICE_CONTAINER)pbNext; pbNext += (SIZE_T)cDeviceContainers * sizeof(VMM_MAP_AMCACHE_DEVICE_CONTAINER);
    pObMap->pDevicePnps = (PVMM_MAP_AMCACHE_DEVICE_PNP)pbNext;

    if(!ObStrMap_FinalizeAllocU_DECREF_NULL(&ctx->psm, &pObMap->pbMultiText, &pObMap->cbMultiText)) { goto fail; }
    MFcAmcache_JoinAll(H, ctx, &cFilesAssociated, &cFilesUnassociated, &cShortcutsAssociated);

    pObMap->fHiveFound = ctx->fHiveFound;
    pObMap->fInventoryApplicationFound = ctx->fInventoryApplicationFound;
    pObMap->fInventoryApplicationFileFound = ctx->fInventoryApplicationFileFound;
    pObMap->fInventoryApplicationShortcutFound = ctx->fInventoryApplicationShortcutFound;
    pObMap->fInventoryDriverBinaryFound = ctx->fInventoryDriverBinaryFound;
    pObMap->fInventoryDriverPackageFound = ctx->fInventoryDriverPackageFound;
    pObMap->fInventoryDeviceContainerFound = ctx->fInventoryDeviceContainerFound;
    pObMap->fInventoryDevicePnpFound = ctx->fInventoryDevicePnpFound;
    pObMap->fApplicationsTruncated = ctx->fApplicationsTruncated;
    pObMap->fFilesTruncated = ctx->fFilesTruncated;
    pObMap->fShortcutsTruncated = ctx->fShortcutsTruncated;
    pObMap->fDriverBinariesTruncated = ctx->fDriverBinariesTruncated;
    pObMap->fDriverPackagesTruncated = ctx->fDriverPackagesTruncated;
    pObMap->fDeviceContainersTruncated = ctx->fDeviceContainersTruncated;
    pObMap->fDevicePnpsTruncated = ctx->fDevicePnpsTruncated;
    strncpy_s(pObMap->uszHiveName, sizeof(pObMap->uszHiveName), ctx->uszHiveName, _TRUNCATE);
    strncpy_s(pObMap->uszHiveRootPath, sizeof(pObMap->uszHiveRootPath), ctx->uszHiveRootPath, _TRUNCATE);
    pObMap->cApplications = cApplications;
    pObMap->cFiles = cFiles;
    pObMap->cFilesAssociated = cFilesAssociated;
    pObMap->cFilesUnassociated = cFilesUnassociated;
    pObMap->cShortcuts = cShortcuts;
    pObMap->cShortcutsAssociated = cShortcutsAssociated;
    pObMap->cDriverBinaries = cDriverBinaries;
    pObMap->cDriverPackages = cDriverPackages;
    pObMap->cDeviceContainers = cDeviceContainers;
    pObMap->cDevicePnps = cDevicePnps;

#define MFCAMCACHE_COPY_MAP(_map, _dst, _count, _type) \
    for(i = 0; i < (_count); i++) { PVOID _src = ObMap_GetByIndex((_map), i); if(_src) memcpy(&(_dst)[i], _src, sizeof(_type)); }
    MFCAMCACHE_COPY_MAP(ctx->pmApplications, pObMap->pApplications, cApplications, VMM_MAP_AMCACHE_APPLICATION);
    MFCAMCACHE_COPY_MAP(ctx->pmFiles, pObMap->pFiles, cFiles, VMM_MAP_AMCACHE_FILE);
    MFCAMCACHE_COPY_MAP(ctx->pmShortcuts, pObMap->pShortcuts, cShortcuts, VMM_MAP_AMCACHE_SHORTCUT);
    MFCAMCACHE_COPY_MAP(ctx->pmDriverBinaries, pObMap->pDriverBinaries, cDriverBinaries, VMM_MAP_AMCACHE_DRIVER_BINARY);
    MFCAMCACHE_COPY_MAP(ctx->pmDriverPackages, pObMap->pDriverPackages, cDriverPackages, VMM_MAP_AMCACHE_DRIVER_PACKAGE);
    MFCAMCACHE_COPY_MAP(ctx->pmDeviceContainers, pObMap->pDeviceContainers, cDeviceContainers, VMM_MAP_AMCACHE_DEVICE_CONTAINER);
    MFCAMCACHE_COPY_MAP(ctx->pmDevicePnps, pObMap->pDevicePnps, cDevicePnps, VMM_MAP_AMCACHE_DEVICE_PNP);
#undef MFCAMCACHE_COPY_MAP
    MFcAmcache_InitializeSummary(pObMap);
    Ob_INCREF(pObMap);
fail:
    Ob_DECREF(pHive);
    if(ctx) {
        Ob_DECREF(ctx->psm);
        Ob_DECREF(ctx->pmApplicationsByProgramId);
        Ob_DECREF(ctx->pmDriverBinariesByService);
        Ob_DECREF(ctx->pmDriverBinariesByDriverId);
        Ob_DECREF(ctx->pmDriverPackagesByStrongName);
        Ob_DECREF(ctx->pmDriverPackagesByInf);
        Ob_DECREF(ctx->pmDeviceContainersById);
        Ob_DECREF(ctx->pmDevicePnps);
        Ob_DECREF(ctx->pmDeviceContainers);
        Ob_DECREF(ctx->pmDriverPackages);
        Ob_DECREF(ctx->pmDriverBinaries);
        Ob_DECREF(ctx->pmShortcuts);
        Ob_DECREF(ctx->pmFiles);
        Ob_DECREF(ctx->pmApplications);
        LocalFree(ctx);
    }
    return Ob_DECREF(pObMap);
}

/*
* Retrieve the AmCache map.
* CALLER DECREF: return
* -- H
* -- ctxP
* -- return
*/
_Success_(return != NULL)
PVMMOB_MAP_AMCACHE MFcAmcache_GetMap(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_CONTEXT ctxP)
{
    static SRWLOCK LockSRW = SRWLOCK_INIT;
    POB_CONTAINER pContainer = (POB_CONTAINER)ctxP->ctxM;
    PVMMOB_MAP_AMCACHE pObMap = NULL;
    if((pObMap = ObContainer_GetOb(pContainer))) { return pObMap; }
    AcquireSRWLockExclusive(&LockSRW);
    pObMap = ObContainer_GetOb(pContainer);
    if(!pObMap) {
        pObMap = MFcAmcache_Initialize(H);
        if(!pObMap) { pObMap = Ob_AllocEx(H, OB_TAG_MAP_AMCACHE, LMEM_ZEROINIT, sizeof(VMMOB_MAP_AMCACHE), NULL, NULL); }
        ObContainer_SetOb(pContainer, pObMap);
    }
    ReleaseSRWLockExclusive(&LockSRW);
    return pObMap;
}

//------------------------------------------------------------------------------
// VFS functionality:
//------------------------------------------------------------------------------
static VOID MFcAmcache_IndexString(_Out_writes_(cbu) LPSTR usz, _In_ DWORD cbu, _In_ DWORD i)
{
    if(i == MFCAMCACHE_INDEX_NONE) { strcpy_s(usz, cbu, "----"); }
    else { _snprintf_s(usz, cbu, _TRUNCATE, "%04x", i); }
}

VOID MFcAmcache_ApplicationReadLine_CB(_In_ VMM_HANDLE H, _In_ PVOID pv, _In_ DWORD cbLineLength, _In_ DWORD ie, _In_ PVMM_MAP_AMCACHE_APPLICATION pe, _Out_writes_(cbLineLength + 1) LPSTR szu8)
{
    CHAR szTime[24], szFlags[5] = { '-', '-', ' ', ' ', 0 };
    if(pe->dwFlags & MFCAMCACHE_APP_FLAG_PROGRAMID_FROM_KEY) szFlags[0] = 'K';
    if(pe->dwFlags & MFCAMCACHE_APP_FLAG_PROGRAMID_DUPLICATE) szFlags[1] = 'D';
    Util_FileTime2String(pe->ftKeyLastWrite, szTime);
    Util_usnprintf_ln(szu8, cbLineLength,
        "%04x %6u %4u %s %s %-40.40s %-64.64s %-48.48s %-20.20s %s",
        ie,
        pe->cFiles,
        pe->cShortcuts,
        szFlags,
        szTime,
        VMM_STR_NONULL(pe->uszProgramId),
        VMM_STR_NONULL(pe->uszName),
        VMM_STR_NONULL(pe->uszPublisher),
        VMM_STR_NONULL(pe->uszVersion),
        VMM_STR_NONULL(pe->uszRootDirPath)
    );
}

VOID MFcAmcache_FileReadLine_CB(_In_ VMM_HANDLE H, _In_ PVMMOB_MAP_AMCACHE pObMap, _In_ DWORD cbLineLength, _In_ DWORD ie, _In_ PVMM_MAP_AMCACHE_FILE pe, _Out_writes_(cbLineLength + 1) LPSTR szu8)
{
    CHAR szTime[24], szApplicationIndex[8]; LPCSTR uszApplicationName = "";
    Util_FileTime2String(pe->ftKeyLastWrite, szTime); MFcAmcache_IndexString(szApplicationIndex, sizeof(szApplicationIndex), pe->iApplication);
    if(pe->iApplication < pObMap->cApplications) uszApplicationName = VMM_STR_NONULL(pObMap->pApplications[pe->iApplication].uszName);
    Util_usnprintf_ln(szu8, cbLineLength,
        "%05x %s %c %s %12llu %-48.48s %-48.48s %-40.40s %-40.40s %s",
        ie,
        szApplicationIndex,
        pe->iApplication != MFCAMCACHE_INDEX_NONE ? 'M' : '-',
        szTime,
        pe->cbFile,
        VMM_STR_NONULL(pe->uszName),
        uszApplicationName,
        VMM_STR_NONULL(pe->uszFileId),
        VMM_STR_NONULL(pe->uszProgramId),
        VMM_STR_NONULL(pe->uszLowerCaseLongPath)
    );
}

VOID MFcAmcache_ShortcutReadLine_CB(_In_ VMM_HANDLE H, _In_ PVOID pv, _In_ DWORD cbLineLength, _In_ DWORD ie, _In_ PVMM_MAP_AMCACHE_SHORTCUT pe, _Out_writes_(cbLineLength + 1) LPSTR szu8)
{
    CHAR szTime[24], szApp[8];
    Util_FileTime2String(pe->ftKeyLastWrite, szTime);
    MFcAmcache_IndexString(szApp,sizeof(szApp), pe->iApplication);
    Util_usnprintf_ln(szu8, cbLineLength,
        "%04x %s %c %s %-40.40s %-64.64s %s",
        ie,
        szApp,
        pe->iApplication!=MFCAMCACHE_INDEX_NONE?'M':'-',
        szTime,
        VMM_STR_NONULL(pe->uszShortcutProgramId),
        VMM_STR_NONULL(pe->uszShortcutPath),
        VMM_STR_NONULL(pe->uszShortcutTargetPath)
    );
}

VOID MFcAmcache_DriverBinaryReadLine_CB(_In_ VMM_HANDLE H, _In_ PVOID pv, _In_ DWORD cbLineLength, _In_ DWORD ie, _In_ PVMM_MAP_AMCACHE_DRIVER_BINARY pe, _Out_writes_(cbLineLength + 1) LPSTR szu8)
{
    CHAR szTime[24],szPkg[8];
    Util_FileTime2String(pe->ftKeyLastWrite,szTime);
    MFcAmcache_IndexString(szPkg,sizeof(szPkg),pe->iDriverPackage);
    Util_usnprintf_ln(szu8, cbLineLength,
        "%04x %s %4u %s %-48.48s %-48.48s %-48.48s %s",
        ie,
        szPkg,
        pe->cDevices,
        szTime,
        VMM_STR_NONULL(pe->uszDriverName),
        VMM_STR_NONULL(pe->uszService),
        VMM_STR_NONULL(pe->uszDriverPackageStrongName),
        VMM_STR_NONULL(pe->uszDriverId)
    );
}

VOID MFcAmcache_DriverPackageReadLine_CB(_In_ VMM_HANDLE H, _In_ PVOID pv, _In_ DWORD cbLineLength, _In_ DWORD ie, _In_ PVMM_MAP_AMCACHE_DRIVER_PACKAGE pe, _Out_writes_(cbLineLength + 1) LPSTR szu8)
{
    CHAR szTime[24];
    Util_FileTime2String(pe->ftKeyLastWrite,szTime);
    Util_usnprintf_ln(szu8, cbLineLength,
        "%04x %4u %4u %s %-48.48s %-48.48s %-24.24s %s",
        ie,
        pe->cDriverBinaries,
        pe->cDevices,
        szTime,
        VMM_STR_NONULL(pe->uszInf),
        VMM_STR_NONULL(pe->uszProvider),
        VMM_STR_NONULL(pe->uszVersion),
        VMM_STR_NONULL(pe->uszDirectory)
    );
}

VOID MFcAmcache_DeviceContainerReadLine_CB(_In_ VMM_HANDLE H, _In_ PVOID pv, _In_ DWORD cbLineLength, _In_ DWORD ie, _In_ PVMM_MAP_AMCACHE_DEVICE_CONTAINER pe, _Out_writes_(cbLineLength + 1) LPSTR szu8)
{
    CHAR szTime[24];
    Util_FileTime2String(pe->ftKeyLastWrite,szTime);
    Util_usnprintf_ln(szu8, cbLineLength,
        "%04x %4u %s %-64.64s %-48.48s %-48.48s %s",
        ie,
        pe->cDevices,
        szTime,
        VMM_STR_NONULL(pe->uszFriendlyName),
        VMM_STR_NONULL(pe->uszManufacturer),
        VMM_STR_NONULL(pe->uszModelName),
        VMM_STR_NONULL(pe->uszCategories)
    );
}

VOID MFcAmcache_DevicePnpReadLine_CB(_In_ VMM_HANDLE H, _In_ PVOID pv, _In_ DWORD cbLineLength, _In_ DWORD ie, _In_ PVMM_MAP_AMCACHE_DEVICE_PNP pe, _Out_writes_(cbLineLength + 1) LPSTR szu8)
{
    CHAR szTime[24],szCtr[8],szBin[8],szPkg[8];
    Util_FileTime2String(pe->ftKeyLastWrite,szTime);
    MFcAmcache_IndexString(szCtr,sizeof(szCtr),pe->iDeviceContainer);
    MFcAmcache_IndexString(szBin,sizeof(szBin),pe->iDriverBinary);
    MFcAmcache_IndexString(szPkg,sizeof(szPkg),pe->iDriverPackage);
    Util_usnprintf_ln(szu8, cbLineLength,
        "%04x %s %s %s %s %-48.48s %-48.48s %-48.48s %-48.48s %s",
        ie,
        szCtr,
        szBin,
        szPkg,
        szTime,
        VMM_STR_NONULL(pe->uszDescription),
        VMM_STR_NONULL(pe->uszManufacturer),
        VMM_STR_NONULL(pe->uszService),
        VMM_STR_NONULL(pe->uszDriverName),
        VMM_STR_NONULL(pe->uszHWID)
    );
}

NTSTATUS MFcAmcache_Read(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_CONTEXT ctxP, _Out_writes_to_(cb, *pcbRead) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset)
{
    NTSTATUS nt = VMMDLL_STATUS_FILE_INVALID;
    PVMMOB_MAP_AMCACHE pObMap = NULL;
    if(!(pObMap = MFcAmcache_GetMap(H, ctxP))) { goto finish; }
    if(CharUtil_StrEquals(ctxP->uszPath, "summary.txt", TRUE)) {
        nt = Util_VfsReadFile_FromPBYTE(pObMap->pbSummary, pObMap->cbSummary, pb, cb, pcbRead, cbOffset);
    } else if(CharUtil_StrEquals(ctxP->uszPath, "applications.txt", TRUE)) {
        nt = Util_VfsLineFixed_Read(H, (UTIL_VFSLINEFIXED_PFN_CB)MFcAmcache_ApplicationReadLine_CB, NULL, MFCAMCACHE_APP_LINELENGTH, MFCAMCACHE_APP_LINEHEADER, pObMap->pApplications, pObMap->cApplications, sizeof(VMM_MAP_AMCACHE_APPLICATION), pb, cb, pcbRead, cbOffset);
    } else if(CharUtil_StrEquals(ctxP->uszPath, "files.txt", TRUE)) {
        nt = Util_VfsLineFixed_Read(H, (UTIL_VFSLINEFIXED_PFN_CB)MFcAmcache_FileReadLine_CB, pObMap, MFCAMCACHE_FILE_LINELENGTH, MFCAMCACHE_FILE_LINEHEADER, pObMap->pFiles, pObMap->cFiles, sizeof(VMM_MAP_AMCACHE_FILE), pb, cb, pcbRead, cbOffset);
    } else if(CharUtil_StrEquals(ctxP->uszPath, "shortcuts.txt", TRUE)) {
        nt = Util_VfsLineFixed_Read(H, (UTIL_VFSLINEFIXED_PFN_CB)MFcAmcache_ShortcutReadLine_CB, NULL, MFCAMCACHE_SHORTCUT_LINELENGTH, MFCAMCACHE_SHORTCUT_LINEHEADER, pObMap->pShortcuts, pObMap->cShortcuts, sizeof(VMM_MAP_AMCACHE_SHORTCUT), pb, cb, pcbRead, cbOffset);
    } else if(CharUtil_StrEquals(ctxP->uszPath, "driver_binaries.txt", TRUE)) {
        nt = Util_VfsLineFixed_Read(H, (UTIL_VFSLINEFIXED_PFN_CB)MFcAmcache_DriverBinaryReadLine_CB, NULL, MFCAMCACHE_DRIVER_BINARY_LINELENGTH, MFCAMCACHE_DRIVER_BINARY_LINEHEADER, pObMap->pDriverBinaries, pObMap->cDriverBinaries, sizeof(VMM_MAP_AMCACHE_DRIVER_BINARY), pb, cb, pcbRead, cbOffset);
    } else if(CharUtil_StrEquals(ctxP->uszPath, "driver_packages.txt", TRUE)) {
        nt = Util_VfsLineFixed_Read(H, (UTIL_VFSLINEFIXED_PFN_CB)MFcAmcache_DriverPackageReadLine_CB, NULL, MFCAMCACHE_DRIVER_PACKAGE_LINELENGTH, MFCAMCACHE_DRIVER_PACKAGE_LINEHEADER, pObMap->pDriverPackages, pObMap->cDriverPackages, sizeof(VMM_MAP_AMCACHE_DRIVER_PACKAGE), pb, cb, pcbRead, cbOffset);
    } else if(CharUtil_StrEquals(ctxP->uszPath, "device_containers.txt", TRUE)) {
        nt = Util_VfsLineFixed_Read(H, (UTIL_VFSLINEFIXED_PFN_CB)MFcAmcache_DeviceContainerReadLine_CB, NULL, MFCAMCACHE_DEVICE_CONTAINER_LINELENGTH, MFCAMCACHE_DEVICE_CONTAINER_LINEHEADER, pObMap->pDeviceContainers, pObMap->cDeviceContainers, sizeof(VMM_MAP_AMCACHE_DEVICE_CONTAINER), pb, cb, pcbRead, cbOffset);
    } else if(CharUtil_StrEquals(ctxP->uszPath, "devices_pnp.txt", TRUE)) {
        nt = Util_VfsLineFixed_Read(H, (UTIL_VFSLINEFIXED_PFN_CB)MFcAmcache_DevicePnpReadLine_CB, NULL, MFCAMCACHE_DEVICE_PNP_LINELENGTH, MFCAMCACHE_DEVICE_PNP_LINEHEADER, pObMap->pDevicePnps, pObMap->cDevicePnps, sizeof(VMM_MAP_AMCACHE_DEVICE_PNP), pb, cb, pcbRead, cbOffset);
    }
finish:
    Ob_DECREF(pObMap);
    return nt;
}

BOOL MFcAmcache_List(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_CONTEXT ctxP, _Inout_ PHANDLE pFileList)
{
    PVMMOB_MAP_AMCACHE pObMap = MFcAmcache_GetMap(H, ctxP);
    if(!pObMap || ctxP->uszPath[0]) { Ob_DECREF(pObMap); return FALSE; }
    VMMDLL_VfsList_AddFile(pFileList, "summary.txt", pObMap->cbSummary, NULL);
    VMMDLL_VfsList_AddFile(pFileList, "applications.txt",      UTIL_VFSLINEFIXED_LINECOUNT(H, pObMap->cApplications)     * MFCAMCACHE_APP_LINELENGTH, NULL);
    VMMDLL_VfsList_AddFile(pFileList, "files.txt",             UTIL_VFSLINEFIXED_LINECOUNT(H, pObMap->cFiles)            * MFCAMCACHE_FILE_LINELENGTH, NULL);
    VMMDLL_VfsList_AddFile(pFileList, "shortcuts.txt",         UTIL_VFSLINEFIXED_LINECOUNT(H, pObMap->cShortcuts)        * MFCAMCACHE_SHORTCUT_LINELENGTH, NULL);
    VMMDLL_VfsList_AddFile(pFileList, "driver_binaries.txt",   UTIL_VFSLINEFIXED_LINECOUNT(H, pObMap->cDriverBinaries)   * MFCAMCACHE_DRIVER_BINARY_LINELENGTH, NULL);
    VMMDLL_VfsList_AddFile(pFileList, "driver_packages.txt",   UTIL_VFSLINEFIXED_LINECOUNT(H, pObMap->cDriverPackages)   * MFCAMCACHE_DRIVER_PACKAGE_LINELENGTH, NULL);
    VMMDLL_VfsList_AddFile(pFileList, "device_containers.txt", UTIL_VFSLINEFIXED_LINECOUNT(H, pObMap->cDeviceContainers) * MFCAMCACHE_DEVICE_CONTAINER_LINELENGTH, NULL);
    VMMDLL_VfsList_AddFile(pFileList, "devices_pnp.txt",       UTIL_VFSLINEFIXED_LINECOUNT(H, pObMap->cDevicePnps)       * MFCAMCACHE_DEVICE_PNP_LINELENGTH, NULL);
    Ob_DECREF(pObMap);
    return TRUE;
}

//------------------------------------------------------------------------------
// Forensic: JSON, CSV and Timeline.
//------------------------------------------------------------------------------
VOID MFcAmcache_FcLogJSON(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_CONTEXT ctxP, _In_ VOID(*pfnLogJSON)(_In_ VMM_HANDLE H, _In_ PVMMDLL_FORENSIC_JSONDATA pData))
{
    DWORD i;
    CHAR usz[4096];
    PVMMOB_MAP_AMCACHE pObMap = NULL;
    PVMMDLL_FORENSIC_JSONDATA pd = NULL;
    if(!(pObMap = MFcAmcache_GetMap(H, ctxP))) { goto finish; }
    if(!(pd = LocalAlloc(LMEM_ZEROINIT, sizeof(VMMDLL_FORENSIC_JSONDATA)))) { goto finish; }
#define MFCAMCACHE_JSON_INIT(_type) FC_JSONDATA_INIT_PIDTYPE(pd, 0, (_type))
#define MFCAMCACHE_JSON_LOG(_i,_name,_fmt,...) do { pd->i=(_i); pd->usz[0]=VMM_STR_NONULL((_name)); _snprintf_s(usz,sizeof(usz),_TRUNCATE,(_fmt),__VA_ARGS__); pd->usz[1]=usz; pfnLogJSON(H,pd); } while(0)
    MFCAMCACHE_JSON_INIT("amcache-application");
    for(i=0;i<pObMap->cApplications;i++) { PVMM_MAP_AMCACHE_APPLICATION pe=&pObMap->pApplications[i]; pd->qwNum[0]=pe->cFiles; pd->qwNum[1]=pe->cShortcuts; MFCAMCACHE_JSON_LOG(i,pe->uszName,"program_id:[%s] publisher:[%s] version:[%s] files:[%u] shortcuts:[%u] key_last_write:[%016llx]",VMM_STR_NONULL(pe->uszProgramId),VMM_STR_NONULL(pe->uszPublisher),VMM_STR_NONULL(pe->uszVersion),pe->cFiles,pe->cShortcuts,pe->ftKeyLastWrite); }
    MFCAMCACHE_JSON_INIT("amcache-file");
    for(i=0;i<pObMap->cFiles;i++) { PVMM_MAP_AMCACHE_FILE pe=&pObMap->pFiles[i]; pd->qwNum[0]=pe->cbFile; pd->qwNum[1]=pe->usn; MFCAMCACHE_JSON_LOG(i,pe->uszLowerCaseLongPath?pe->uszLowerCaseLongPath:pe->uszName,"file_id:[%s] program_id:[%s] application_index:[%u] inventory_presence:[true] execution_established:[false] key_last_write:[%016llx]",VMM_STR_NONULL(pe->uszFileId),VMM_STR_NONULL(pe->uszProgramId),pe->iApplication,pe->ftKeyLastWrite); }
    MFCAMCACHE_JSON_INIT("amcache-shortcut");
    for(i=0;i<pObMap->cShortcuts;i++) { PVMM_MAP_AMCACHE_SHORTCUT pe=&pObMap->pShortcuts[i]; MFCAMCACHE_JSON_LOG(i,pe->uszShortcutPath,"program_id:[%s] application_index:[%u] target:[%s] key_last_write:[%016llx]",VMM_STR_NONULL(pe->uszShortcutProgramId),pe->iApplication,VMM_STR_NONULL(pe->uszShortcutTargetPath),pe->ftKeyLastWrite); }
    MFCAMCACHE_JSON_INIT("amcache-driver-binary");
    for(i=0;i<pObMap->cDriverBinaries;i++) { PVMM_MAP_AMCACHE_DRIVER_BINARY pe=&pObMap->pDriverBinaries[i]; pd->qwNum[0]=pe->cbImageSize; MFCAMCACHE_JSON_LOG(i,pe->uszDriverName,"driver_id:[%s] service:[%s] package:[%s] driver_package_index:[%u] devices:[%u] signed:[%u] kernel_mode:[%u] key_last_write:[%016llx]",VMM_STR_NONULL(pe->uszDriverId),VMM_STR_NONULL(pe->uszService),VMM_STR_NONULL(pe->uszDriverPackageStrongName),pe->iDriverPackage,pe->cDevices,pe->fDriverSigned,pe->fDriverIsKernelMode,pe->ftKeyLastWrite); }
    MFCAMCACHE_JSON_INIT("amcache-driver-package");
    for(i=0;i<pObMap->cDriverPackages;i++) { PVMM_MAP_AMCACHE_DRIVER_PACKAGE pe=&pObMap->pDriverPackages[i]; MFCAMCACHE_JSON_LOG(i,pe->uszInf,"provider:[%s] version:[%s] directory:[%s] binaries:[%u] devices:[%u] key_last_write:[%016llx]",VMM_STR_NONULL(pe->uszProvider),VMM_STR_NONULL(pe->uszVersion),VMM_STR_NONULL(pe->uszDirectory),pe->cDriverBinaries,pe->cDevices,pe->ftKeyLastWrite); }
    MFCAMCACHE_JSON_INIT("amcache-device-container");
    for(i=0;i<pObMap->cDeviceContainers;i++) { PVMM_MAP_AMCACHE_DEVICE_CONTAINER pe=&pObMap->pDeviceContainers[i]; MFCAMCACHE_JSON_LOG(i,pe->uszFriendlyName,"container_id:[%s] manufacturer:[%s] model:[%s] categories:[%s] devices:[%u] connected:[%u] key_last_write:[%016llx]",VMM_STR_NONULL(pe->uszRegistrySubKey),VMM_STR_NONULL(pe->uszManufacturer),VMM_STR_NONULL(pe->uszModelName),VMM_STR_NONULL(pe->uszCategories),pe->cDevices,pe->fIsConnected,pe->ftKeyLastWrite); }
    MFCAMCACHE_JSON_INIT("amcache-device-pnp");
    for(i=0;i<pObMap->cDevicePnps;i++) { PVMM_MAP_AMCACHE_DEVICE_PNP pe=&pObMap->pDevicePnps[i]; MFCAMCACHE_JSON_LOG(i,pe->uszDescription,"container_index:[%u] driver_binary_index:[%u] driver_package_index:[%u] driver_id:[%s] service:[%s] hwid:[%s] key_last_write:[%016llx]",pe->iDeviceContainer,pe->iDriverBinary,pe->iDriverPackage,VMM_STR_NONULL(pe->uszDriverId),VMM_STR_NONULL(pe->uszService),VMM_STR_NONULL(pe->uszHWID),pe->ftKeyLastWrite); }
#undef MFCAMCACHE_JSON_LOG
#undef MFCAMCACHE_JSON_INIT
finish:
    LocalFree(pd);
    Ob_DECREF(pObMap);
}


VOID MFcAmcache_FcLogCSV(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_CONTEXT ctxP, _In_ VMMDLL_CSV_HANDLE hCSV)
{
    DWORD i;
    CHAR sz1[16], sz2[16], sz3[16];
    PVMMOB_MAP_AMCACHE pObMap = NULL;
    if(ctxP->pProcess || !ctxP->ctxM) { return; }
    if(!(pObMap = MFcAmcache_GetMap(H, ctxP))) { return; }
#define MFCAMCACHE_CSV_INDEX(_buf,_i) do { if((_i)==MFCAMCACHE_INDEX_NONE) (_buf)[0]=0; else _snprintf_s((_buf),sizeof(_buf),_TRUNCATE,"%u",(_i)); } while(0)
    for(i=0;i<pObMap->cApplications;i++) {
        PVMM_MAP_AMCACHE_APPLICATION pe=&pObMap->pApplications[i]; FcCsv_Reset(hCSV);
        FcFileAppend(H,"amcache_applications.csv","%s,%u,%u,%u,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%u,%u\n",
            FcCsv_FileTime(hCSV,pe->ftKeyLastWrite),pe->dwIndex,pe->cFiles,pe->cShortcuts,
            FcCsv_String(hCSV,pe->uszProgramId),FcCsv_String(hCSV,pe->uszProgramInstanceId),FcCsv_String(hCSV,pe->uszName),FcCsv_String(hCSV,pe->uszPublisher),FcCsv_String(hCSV,pe->uszVersion),
            FcCsv_String(hCSV,pe->uszRootDirPath),FcCsv_String(hCSV,pe->uszRegistryKeyPath),FcCsv_String(hCSV,pe->uszUninstallString),FcCsv_String(hCSV,pe->uszInstallDate),FcCsv_String(hCSV,pe->uszInstallDateMsi),
            FcCsv_String(hCSV,pe->uszInstallDateFromLinkFile),FcCsv_String(hCSV,pe->uszSource),FcCsv_String(hCSV,pe->uszType),FcCsv_String(hCSV,pe->uszPackageFullName),FcCsv_String(hCSV,pe->uszMsiProductCode),
            FcCsv_String(hCSV,pe->uszMsiPackageCode),FcCsv_String(hCSV,pe->uszManifestPath),FcCsv_String(hCSV,pe->uszRegistrySubKey),
            (pe->dwFlags&MFCAMCACHE_APP_FLAG_PROGRAMID_FROM_KEY)?1:0,(pe->dwFlags&MFCAMCACHE_APP_FLAG_PROGRAMID_DUPLICATE)?1:0);
    }
    for(i=0;i<pObMap->cFiles;i++) {
        PVMM_MAP_AMCACHE_FILE pe=&pObMap->pFiles[i]; FcCsv_Reset(hCSV); MFCAMCACHE_CSV_INDEX(sz1,pe->iApplication);
        FcFileAppend(H,"amcache_files.csv","%s,%u,%s,%u,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%llu,%llu,%u,%u,%s\n",
            FcCsv_FileTime(hCSV,pe->ftKeyLastWrite),pe->dwIndex,FcCsv_String(hCSV,sz1),pe->iApplication!=MFCAMCACHE_INDEX_NONE?1:0,
            FcCsv_String(hCSV,pe->uszFileId),FcCsv_String(hCSV,pe->uszProgramId),FcCsv_String(hCSV,pe->uszLowerCaseLongPath),FcCsv_String(hCSV,pe->uszName),FcCsv_String(hCSV,pe->uszPublisher),
            FcCsv_String(hCSV,pe->uszProductName),FcCsv_String(hCSV,pe->uszProductVersion),FcCsv_String(hCSV,pe->uszVersion),FcCsv_String(hCSV,pe->uszBinFileVersion),FcCsv_String(hCSV,pe->uszBinProductVersion),
            FcCsv_String(hCSV,pe->uszBinaryType),FcCsv_String(hCSV,pe->uszLanguage),FcCsv_String(hCSV,pe->uszLinkDate),FcCsv_String(hCSV,pe->uszDescription),FcCsv_String(hCSV,pe->uszOriginalFileName),
            pe->cbFile,pe->usn,pe->fIsPeFile?1:0,pe->fIsOsComponent?1:0,FcCsv_String(hCSV,pe->uszRegistrySubKey));
    }
    for(i=0;i<pObMap->cShortcuts;i++) {
        PVMM_MAP_AMCACHE_SHORTCUT pe=&pObMap->pShortcuts[i]; FcCsv_Reset(hCSV); MFCAMCACHE_CSV_INDEX(sz1,pe->iApplication);
        FcFileAppend(H,"amcache_shortcuts.csv","%s,%u,%s,%u,%s,%s,%s,%s\n",FcCsv_FileTime(hCSV,pe->ftKeyLastWrite),pe->dwIndex,FcCsv_String(hCSV,sz1),pe->iApplication!=MFCAMCACHE_INDEX_NONE?1:0,FcCsv_String(hCSV,pe->uszShortcutProgramId),FcCsv_String(hCSV,pe->uszShortcutPath),FcCsv_String(hCSV,pe->uszShortcutTargetPath),FcCsv_String(hCSV,pe->uszRegistrySubKey));
    }
    for(i=0;i<pObMap->cDriverBinaries;i++) {
        PVMM_MAP_AMCACHE_DRIVER_BINARY pe=&pObMap->pDriverBinaries[i]; FcCsv_Reset(hCSV); MFCAMCACHE_CSV_INDEX(sz1,pe->iDriverPackage);
        FcFileAppend(H,"amcache_driver_binaries.csv","%s,%u,%s,%u,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%llu,%llu,%s,%llu,%s,%u,%u,%u,%s,%s,%s\n",
            FcCsv_FileTime(hCSV,pe->ftKeyLastWrite),pe->dwIndex,FcCsv_String(hCSV,sz1),pe->cDevices,
            FcCsv_String(hCSV,pe->uszDriverId),FcCsv_String(hCSV,pe->uszDriverName),FcCsv_String(hCSV,pe->uszDriverCompany),FcCsv_String(hCSV,pe->uszDriverPackageStrongName),FcCsv_String(hCSV,pe->uszService),FcCsv_String(hCSV,pe->uszInf),
            FcCsv_String(hCSV,pe->uszProduct),FcCsv_String(hCSV,pe->uszProductVersion),FcCsv_String(hCSV,pe->uszDriverVersion),FcCsv_String(hCSV,pe->uszDriverLastWriteTime),pe->qwDriverCheckSum,pe->qwDriverTimeStamp,
            FcCsv_String(hCSV,pe->uszDriverType),pe->cbImageSize,FcCsv_String(hCSV,pe->uszWdfVersion),pe->fDriverInBox?1:0,pe->fDriverIsKernelMode?1:0,pe->fDriverSigned?1:0,FcCsv_String(hCSV,pe->uszCOMPID),FcCsv_String(hCSV,pe->uszHWID),FcCsv_String(hCSV,pe->uszRegistrySubKey));
    }
    for(i=0;i<pObMap->cDriverPackages;i++) {
        PVMM_MAP_AMCACHE_DRIVER_PACKAGE pe=&pObMap->pDriverPackages[i]; FcCsv_Reset(hCSV);
        FcFileAppend(H,"amcache_driver_packages.csv","%s,%u,%u,%u,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%u,%s\n",
            FcCsv_FileTime(hCSV,pe->ftKeyLastWrite),pe->dwIndex,pe->cDriverBinaries,pe->cDevices,FcCsv_String(hCSV,pe->uszClass),FcCsv_String(hCSV,pe->uszClassGuid),FcCsv_String(hCSV,pe->uszDate),FcCsv_String(hCSV,pe->uszDirectory),FcCsv_String(hCSV,pe->uszInf),FcCsv_String(hCSV,pe->uszProvider),FcCsv_String(hCSV,pe->uszVersion),FcCsv_String(hCSV,pe->uszFlightIds),FcCsv_String(hCSV,pe->uszRecoveryIds),FcCsv_String(hCSV,pe->uszSubmissionId),FcCsv_String(hCSV,pe->uszHWIDs),FcCsv_String(hCSV,pe->uszSYSFILE),pe->fDriverInBox?1:0,FcCsv_String(hCSV,pe->uszRegistrySubKey));
    }
    for(i=0;i<pObMap->cDeviceContainers;i++) {
        PVMM_MAP_AMCACHE_DEVICE_CONTAINER pe=&pObMap->pDeviceContainers[i]; FcCsv_Reset(hCSV);
        FcFileAppend(H,"amcache_device_containers.csv","%s,%u,%u,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%u,%u,%u,%u,%u,%s\n",
            FcCsv_FileTime(hCSV,pe->ftKeyLastWrite),pe->dwIndex,pe->cDevices,FcCsv_String(hCSV,pe->uszCategories),FcCsv_String(hCSV,pe->uszDiscoveryMethod),FcCsv_String(hCSV,pe->uszFriendlyName),FcCsv_String(hCSV,pe->uszIcon),FcCsv_String(hCSV,pe->uszManufacturer),FcCsv_String(hCSV,pe->uszModelId),FcCsv_String(hCSV,pe->uszModelName),FcCsv_String(hCSV,pe->uszModelNumber),FcCsv_String(hCSV,pe->uszPrimaryCategory),FcCsv_String(hCSV,pe->uszState),pe->fIsActive?1:0,pe->fIsConnected?1:0,pe->fIsMachineContainer?1:0,pe->fIsNetworked?1:0,pe->fIsPaired?1:0,FcCsv_String(hCSV,pe->uszRegistrySubKey));
    }
    for(i=0;i<pObMap->cDevicePnps;i++) {
        PVMM_MAP_AMCACHE_DEVICE_PNP pe=&pObMap->pDevicePnps[i]; FcCsv_Reset(hCSV); MFCAMCACHE_CSV_INDEX(sz1,pe->iDeviceContainer); MFCAMCACHE_CSV_INDEX(sz2,pe->iDriverBinary); MFCAMCACHE_CSV_INDEX(sz3,pe->iDriverPackage);
        FcFileAppend(H,"amcache_devices_pnp.csv","%s,%u,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n",
            FcCsv_FileTime(hCSV,pe->ftKeyLastWrite),pe->dwIndex,FcCsv_String(hCSV,sz1),FcCsv_String(hCSV,sz2),FcCsv_String(hCSV,sz3),FcCsv_String(hCSV,pe->uszBusReportedDescription),FcCsv_String(hCSV,pe->uszClass),FcCsv_String(hCSV,pe->uszClassGuid),FcCsv_String(hCSV,pe->uszCOMPID),FcCsv_String(hCSV,pe->uszContainerId),FcCsv_String(hCSV,pe->uszDescription),FcCsv_String(hCSV,pe->uszDeviceState),FcCsv_String(hCSV,pe->uszDriverId),FcCsv_String(hCSV,pe->uszDriverName),FcCsv_String(hCSV,pe->uszDriverPackageStrongName),FcCsv_String(hCSV,pe->uszDriverVerDate),FcCsv_String(hCSV,pe->uszDriverVerVersion),FcCsv_String(hCSV,pe->uszEnumerator),FcCsv_String(hCSV,pe->uszHWID),FcCsv_String(hCSV,pe->uszInf),FcCsv_String(hCSV,pe->uszInstallState),FcCsv_String(hCSV,pe->uszManufacturer),FcCsv_String(hCSV,pe->uszMatchingID),FcCsv_String(hCSV,pe->uszModel),FcCsv_String(hCSV,pe->uszParentId),FcCsv_String(hCSV,pe->uszProblemCode),FcCsv_String(hCSV,pe->uszProvider),FcCsv_String(hCSV,pe->uszService),FcCsv_String(hCSV,pe->uszSTACKID),FcCsv_String(hCSV,pe->uszRegistrySubKey));
    }
#undef MFCAMCACHE_CSV_INDEX
    Ob_DECREF(pObMap);
}

VOID MFcAmcache_FcTimeline(
    _In_ VMM_HANDLE H,
    _In_opt_ PVOID ctxfc,
    _In_ HANDLE hTimeline,
    _In_ VOID(*pfnAddEntry)(_In_ VMM_HANDLE H, _In_ HANDLE hTimeline, _In_ QWORD ft, _In_ DWORD dwAction, _In_ DWORD dwPID, _In_ DWORD dwData32, _In_ QWORD qwData64, _In_ LPCSTR uszText),
    _In_ VOID(*pfnEntryAddBySql)(_In_ VMM_HANDLE H, _In_ HANDLE hTimeline, _In_ DWORD cEntrySql, _In_ LPCSTR *pszEntrySql)
) {
    DWORD i;
    CHAR usz[2048];
    PVMMOB_MAP_AMCACHE p = (PVMMOB_MAP_AMCACHE)ctxfc;
    if(!p) return;
#define MFCAMCACHE_TIMELINE(_ft,_index,_data,_fmt,...) do { if((_ft)) { _snprintf_s(usz,sizeof(usz),_TRUNCATE,(_fmt),__VA_ARGS__); pfnAddEntry(H,hTimeline,(_ft),FC_TIMELINE_ACTION_MODIFY,0,(_index),(_data),usz); } } while(0)
    for(i=0;i<p->cApplications;i++)     { PVMM_MAP_AMCACHE_APPLICATION      e=&p->pApplications[i];     MFCAMCACHE_TIMELINE(e->ftKeyLastWrite,e->dwIndex,0,"AmCache application inventory record updated: %s [%s]",VMM_STR_NONULL(e->uszName),VMM_STR_NONULL(e->uszProgramId)); }
    for(i=0;i<p->cFiles;i++)            { PVMM_MAP_AMCACHE_FILE             e=&p->pFiles[i];            MFCAMCACHE_TIMELINE(e->ftKeyLastWrite,e->dwIndex,e->cbFile,"AmCache file inventory record updated: %s",e->uszLowerCaseLongPath?e->uszLowerCaseLongPath:VMM_STR_NONULL(e->uszName)); }
    for(i=0;i<p->cShortcuts;i++)        { PVMM_MAP_AMCACHE_SHORTCUT         e=&p->pShortcuts[i];        MFCAMCACHE_TIMELINE(e->ftKeyLastWrite,e->dwIndex,0,"AmCache shortcut inventory record updated: %s",VMM_STR_NONULL(e->uszShortcutPath)); }
    for(i=0;i<p->cDriverBinaries;i++)   { PVMM_MAP_AMCACHE_DRIVER_BINARY    e=&p->pDriverBinaries[i];   MFCAMCACHE_TIMELINE(e->ftKeyLastWrite,e->dwIndex,e->cbImageSize,"AmCache driver binary inventory record updated: %s [%s]",VMM_STR_NONULL(e->uszDriverName),VMM_STR_NONULL(e->uszService)); }
    for(i=0;i<p->cDriverPackages;i++)   { PVMM_MAP_AMCACHE_DRIVER_PACKAGE   e=&p->pDriverPackages[i];   MFCAMCACHE_TIMELINE(e->ftKeyLastWrite,e->dwIndex,0,"AmCache driver package inventory record updated: %s",VMM_STR_NONULL(e->uszInf)); }
    for(i=0;i<p->cDeviceContainers;i++) { PVMM_MAP_AMCACHE_DEVICE_CONTAINER e=&p->pDeviceContainers[i]; MFCAMCACHE_TIMELINE(e->ftKeyLastWrite,e->dwIndex,0,"AmCache device container inventory record updated: %s",VMM_STR_NONULL(e->uszFriendlyName)); }
    for(i=0;i<p->cDevicePnps;i++)       { PVMM_MAP_AMCACHE_DEVICE_PNP       e=&p->pDevicePnps[i];       MFCAMCACHE_TIMELINE(e->ftKeyLastWrite,e->dwIndex,0,"AmCache PnP device inventory record updated: %s",VMM_STR_NONULL(e->uszDescription)); }
#undef MFCAMCACHE_TIMELINE
}

VOID MFcAmcache_Close(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_CONTEXT ctxP)
{
    Ob_DECREF((POB_CONTAINER)ctxP->ctxM);
}

VOID MFcAmcache_Notify(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_CONTEXT ctxP, _In_ DWORD fEvent, _In_opt_ PVOID pvEvent, _In_opt_ DWORD cbEvent)
{
    PVMMOB_MAP_AMCACHE pObMap = NULL;
    if(fEvent != VMMDLL_PLUGIN_NOTIFY_FORENSIC_INIT_COMPLETE) { return; }
    pObMap = MFcAmcache_GetMap(H, ctxP);
    if(pObMap && pObMap->fHiveFound) {
        PluginManager_SetVisibility(H, TRUE, "\\forensic\\amcache", TRUE);
    }
    Ob_DECREF(pObMap);
}

VOID MFcAmcache_FcFinalize(_In_ VMM_HANDLE H, _In_opt_ PVOID ctxfc)
{
    Ob_DECREF(ctxfc);
}

PVOID MFcAmcache_FcInitialize(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_CONTEXT ctxP)
{
    FcFileAppend(H,"amcache_applications.csv",    MFCAMCACHE_CSV_APPLICATIONS);
    FcFileAppend(H,"amcache_files.csv",           MFCAMCACHE_CSV_FILES);
    FcFileAppend(H,"amcache_shortcuts.csv",       MFCAMCACHE_CSV_SHORTCUTS);
    FcFileAppend(H,"amcache_driver_binaries.csv", MFCAMCACHE_CSV_DRIVER_BINARIES);
    FcFileAppend(H,"amcache_driver_packages.csv", MFCAMCACHE_CSV_DRIVER_PACKAGES);
    FcFileAppend(H,"amcache_device_containers.csv", MFCAMCACHE_CSV_DEVICE_CONTAINERS);
    FcFileAppend(H,"amcache_devices_pnp.csv",     MFCAMCACHE_CSV_DEVICE_PNPS);
    return MFcAmcache_GetMap(H,ctxP);
}



//------------------------------------------------------------------------------
// Plugin Initialization:
//------------------------------------------------------------------------------
VOID M_FcAmcache_Initialize(_In_ VMM_HANDLE H, _Inout_ PVMMDLL_PLUGIN_REGINFO pRI)
{
    if((pRI->magic != VMMDLL_PLUGIN_REGINFO_MAGIC) || (pRI->wVersion != VMMDLL_PLUGIN_REGINFO_VERSION)) { return; }
    if((pRI->tpSystem != VMMDLL_SYSTEM_WINDOWS_64) && (pRI->tpSystem != VMMDLL_SYSTEM_WINDOWS_32)) { return; }
    // This implementation only handles the modern inventory schema, i.e. win10+
    if(pRI->sysinfo.dwVersionBuild < 10240) { return; }
    if(!(pRI->reg_info.ctxM = (PVMMDLL_PLUGIN_INTERNAL_CONTEXT)ObContainer_New())) { return; }
    strcpy_s(pRI->reg_info.uszPathName, 128, "\\forensic\\amcache");
    pRI->reg_info.fRootModule = TRUE;
    pRI->reg_info.fRootModuleHidden = TRUE;
    // functions supported:
    pRI->reg_fn.pfnList = MFcAmcache_List;
    pRI->reg_fn.pfnRead = MFcAmcache_Read;
    pRI->reg_fn.pfnNotify = MFcAmcache_Notify;
    pRI->reg_fn.pfnClose = MFcAmcache_Close;
    // forensic & timelining support:
    pRI->reg_fnfc.pfnLogJSON = MFcAmcache_FcLogJSON;
    pRI->reg_fnfc.pfnLogCSV = MFcAmcache_FcLogCSV;
    pRI->reg_fnfc.pfnInitialize = MFcAmcache_FcInitialize;
    pRI->reg_fnfc.pfnTimeline = MFcAmcache_FcTimeline;
    pRI->reg_fnfc.pfnFinalize = MFcAmcache_FcFinalize;
    memcpy(pRI->reg_info.sTimelineNameShort, "AMCA", 5);
    strncpy_s(pRI->reg_info.uszTimelineFile, 32, "timeline_amcache", _TRUNCATE);
    pRI->pfnPluginManager_Register(H, pRI);
}
