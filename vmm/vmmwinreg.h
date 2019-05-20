// vmmwinreg.h : declarations of functionality related to the Windows registry.
//
// (c) Ulf Frisk, 2019
// Author: Ulf Frisk, pcileech@frizk.net
//

#ifndef __VMMWINREG_H__
#define __VMMWINREG_H__
#include "vmm.h"

/*
* Retrieve the registry information object. If the registry sub-system is not
* yet initialized it will be initialized on the first call to this function.
* CALLER DECREF: return
* -- return = a registry information struct, or NULL if not found.
*/
PVMMOB_REGISTRY VmmWinReg_RegistryGet();

/*
* Set the refresh flag on the registry subsystem.
* The registry will be refreshed upon next access.
*/
VOID VmmWinReg_Refresh();

/*
* Retrieve the next registry hive given a registry hive. This may be useful
* when iterating over registry hives.
* FUNCTION DECREF: pObRegistryHive
* CALLER DECREF: return
* -- pObRegistryHive = a registry hive struct, or NULL if first.
     NB! function DECREF's - pObRegistryHive and must not be used after call!
* -- return = a registry hive struct, or NULL if not found.
*/
PVMMOB_REGISTRY_HIVE VmmWinReg_HiveGetNext(_In_opt_ PVMMOB_REGISTRY_HIVE pObRegistryHive);

/*
* Retrieve the next registry hive given a hive address.
* CALLER DECREF: return
* -- vaCMHIVE
* -- return = a registry hive struct, or NULL if not found.
*/
PVMMOB_REGISTRY_HIVE VmmWinReg_HiveGetByAddress(_In_ QWORD vaCMHIVE);

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
VOID VmmWinReg_HiveReadEx(_In_ PVMMOB_REGISTRY_HIVE pRegistryHive, _In_ DWORD ra, _Out_ PBYTE pb, _In_ DWORD cb, _Out_opt_ PDWORD pcbReadOpt, _In_ QWORD flags);

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
BOOL VmmWinReg_HiveWrite(_In_ PVMMOB_REGISTRY_HIVE pRegistryHive, _In_ DWORD ra, _In_ PBYTE pb, _In_ DWORD cb);

#endif /* __VMMWINREG_H__ */
