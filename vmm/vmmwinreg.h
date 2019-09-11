// vmmwinreg.h : declarations of functionality related to the Windows registry.
//
// (c) Ulf Frisk, 2019
// Author: Ulf Frisk, pcileech@frizk.net
//

#ifndef __VMMWINREG_H__
#define __VMMWINREG_H__
#include "vmm.h"

typedef struct tdOB_REGISTRY_HIVE {
    OB ObHdr;
    QWORD vaCMHIVE;
    QWORD vaHBASE_BLOCK;
    DWORD cbLength;
    CHAR szName[128];
    WCHAR wszNameShort[32 + 1];
    WCHAR wszHiveRootPath[MAX_PATH];
    QWORD _FutureReserved[0x10];
    QWORD vaHMAP_DIRECTORY;
    QWORD vaHMAP_TABLE_SmallDir;
    CRITICAL_SECTION LockUpdate;
    // snapshot functionality below - VmmWinReg_EnsureSnapshot() must be called before access!
    struct {
        BOOL fInitialized;
        POB_MAP pmKeyHash;      // object map for POB_REG_KEY keyed by hash
        POB_MAP pmKeyOffset;    // object map for POB_REG_KEY& keyed by offset
        DWORD cb;
        PBYTE pb;
    } Snapshot;
} OB_REGISTRY_HIVE, *POB_REGISTRY_HIVE;

typedef struct tdVMM_REGISTRY_KEY_INFO {
    BOOL fActive;
    QWORD ftLastWrite;
    DWORD cchName;
    WCHAR wszName[MAX_PATH];
} VMM_REGISTRY_KEY_INFO, *PVMM_REGISTRY_KEY_INFO;

typedef struct tdVMM_REGISTRY_VALUE_INFO {
    DWORD dwType;
    DWORD cbData;
    DWORD cchName;
    WCHAR wszName[MAX_PATH];
} VMM_REGISTRY_VALUE_INFO, *PVMM_REGISTRY_VALUE_INFO;

typedef struct tdOB_REGISTRY_KEY                *POB_REGISTRY_KEY;
typedef struct tdOB_REGISTRY_VALUE              *POB_REGISTRY_VALUE;

/*
* Initialize the Registry sub-system. This should ideally be done on Vmm Init().
*/
VOID VmmWinReg_Initialize();

/*
* Refresh the Registry sub-system.
*/
VOID VmmWinReg_Refresh();

/*
* Cleanup the Registry sub-system. This should ideally be done on Vmm Close().
*/
VOID VmmWinReg_Close();

/*
* Retrieve the next registry hive given a registry hive. This may be useful
* when iterating over registry hives.
* FUNCTION DECREF: pObRegistryHive
* CALLER DECREF: return
* -- pObRegistryHive = a registry hive struct, or NULL if first.
     NB! function DECREF's - pObRegistryHive and must not be used after call!
* -- return = a registry hive struct, or NULL if not found.
*/
POB_REGISTRY_HIVE VmmWinReg_HiveGetNext(_In_opt_ POB_REGISTRY_HIVE pObRegistryHive);

/*
* Retrieve the next registry hive given a hive address.
* CALLER DECREF: return
* -- vaCMHIVE
* -- return = a registry hive struct, or NULL if not found.
*/
POB_REGISTRY_HIVE VmmWinReg_HiveGetByAddress(_In_ QWORD vaCMHIVE);

/*
* Get the number of total registry hives.
* -- return
*/
DWORD VmmWinReg_HiveCount();

/*
* Read a contigious arbitrary amount of registry hive memory and report the
* number of bytes read in pcbRead.
* NB! Address space does not include regf registry hive file header!
* -- pRegistryHive
* -- ra
* -- pb
* -- cb
* -- pcbRead
* -- flags = flags as in VMM_FLAG_*
*/
VOID VmmWinReg_HiveReadEx(_In_ POB_REGISTRY_HIVE pRegistryHive, _In_ DWORD ra, _Out_writes_(cb) PBYTE pb, _In_ DWORD cb, _Out_opt_ PDWORD pcbReadOpt, _In_ QWORD flags);

/*
* Write a virtually contigious arbitrary amount of memory.
* NB! Address space does not include regf registry hive file header!
* -- pRegistryHive
* -- ra
* -- pb
* -- cb
* -- return = TRUE on success, FALSE on partial or zero write.
*/
_Success_(return)
BOOL VmmWinReg_HiveWrite(_In_ POB_REGISTRY_HIVE pRegistryHive, _In_ DWORD ra, _In_ PBYTE pb, _In_ DWORD cb);

/*
* Retrieve registry hive and key/value path from a "full" path starting with:
* '0x...', 'by-hive\0x...' or 'HKLM\'
* CALLER DECREF: *ppHive
* -- wszPathFull
* -- ppHive
* -- wszPathKeyValue
* -- return
*/
_Success_(return)
BOOL VmmWinRegKey_KeyValuePathFromPath(_In_ LPWSTR wszPathFull, _Out_ POB_REGISTRY_HIVE *ppHive, _Out_writes_(MAX_PATH) LPWSTR wszPathKeyValue);

/*
* Retrieve a registry key by its path. If no registry key is found then NULL
* will be returned.
* CALLER DECREF: return
* -- pHive
* -- wszPath
* -- return
*/
POB_REGISTRY_KEY VmmWinReg_KeyGetByPathW(_In_ POB_REGISTRY_HIVE pHive, _In_ LPWSTR wszPath);

/*
* Retrive registry sub-keys from the level directly below the given parent key.
* The resulting keys are returned in a no-key map (set). If no parent key is
* given the root keys are returned.
* CALLER DECREF: return
* -- pHive
* -- pKeyParent
* -- return = ObMap of POB_REGISTRY_KEY
*/
POB_MAP VmmWinReg_KeyList(_In_ POB_REGISTRY_HIVE pHive, _In_opt_ POB_REGISTRY_KEY pKeyParent);

/*
* Retrieve information about a registry key.
* -- pHive
* -- pKey
* -- pKeyInfo
*/
VOID VmmWinReg_KeyInfo(_In_ POB_REGISTRY_HIVE pHive, _In_ POB_REGISTRY_KEY pKey, _Out_ PVMM_REGISTRY_KEY_INFO pKeyInfo);

/*
* Retrive registry values given a key. The resulting values are returned in a
* no-key map (set). If no values are found the empty set or NULL are returned.
* CALLER DECREF: return
* -- pHive
* -- pKeyParent
* -- return = ObMap of POB_REGISTRY_VALUE
*/
POB_MAP VmmWinReg_KeyValueList(_In_ POB_REGISTRY_HIVE pHive, _In_ POB_REGISTRY_KEY pKeyParent);

/*
* Retrieve information about a registry key value.
* -- pHive
* -- pValue
* -- pValueInfo
*/
VOID VmmWinReg_ValueInfo(_In_ POB_REGISTRY_HIVE pHive, _In_ POB_REGISTRY_VALUE pValue, _Out_ PVMM_REGISTRY_VALUE_INFO pValueInfo);

/*
* Read a registry value - similar to WINAPI function 'RegQueryValueEx'.
* -- pHive
* -- wszPathKeyValue
* -- pdwType
* -- pb
* -- cb
* -- pcbRead
* -- cbOffset
* -- return
*/
_Success_(return)
BOOL VmmWinReg_ValueQuery1(_In_ POB_REGISTRY_HIVE pHive, _In_ LPWSTR wszPathKeyValue, _Out_opt_ PDWORD pdwType, _Out_writes_opt_(cb) PBYTE pb, _In_ DWORD cb, _Out_opt_ PDWORD pcbRead, _In_ QWORD cbOffset);

/*
* Read a registry value - similar to WINAPI function 'RegQueryValueEx'.
* -- wszFullPathKeyValue
* -- pdwType
* -- pbData
* -- cbData
* -- pcbData
* -- return
*/
_Success_(return)
BOOL VmmWinReg_ValueQuery2(_In_ LPWSTR wszFullPathKeyValue, _Out_opt_ PDWORD pdwType, _Out_writes_opt_(cbData) PBYTE pbData, _In_ DWORD cbData, _Out_opt_ PDWORD pcbData);

/*
* Read a registry value - similar to WINAPI function 'RegQueryValueEx'.
* -- pHive
* -- wszPathKeyValue
* -- pdwType
* -- pbData
* -- cbData
* -- pcbData
* -- return
*/
_Success_(return)
BOOL VmmWinReg_ValueQuery3(_In_ POB_REGISTRY_HIVE pHive, _In_ LPWSTR wszPathKeyValue, _Out_opt_ PDWORD pdwType, _Out_writes_opt_(cbData) PBYTE pbData, _In_ DWORD cbData, _Out_opt_ PDWORD pcbData);

/*
* Read a registry value - similar to WINAPI function 'RegQueryValueEx'.
* -- pHive
* -- pObKeyValue
* -- pdwType
* -- pbData
* -- cbData
* -- pcbData
* -- return
*/
_Success_(return)
BOOL VmmWinReg_ValueQuery4(_In_ POB_REGISTRY_HIVE pHive, _In_ POB_REGISTRY_VALUE pObKeyValue, _Out_opt_ PDWORD pdwType, _Out_writes_opt_(cbData) PBYTE pbData, _In_ DWORD cbData, _Out_opt_ PDWORD pcbData);

#endif /* __VMMWINREG_H__ */
