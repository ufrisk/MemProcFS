// pdb.h : definitions related to parsing of program databases (PDB) files used
//         for debug symbols and automatic retrieval from the Microsoft Symbol
//         Server. (Windows exclusive functionality).
//
// (c) Ulf Frisk, 2019-2023
// Author: Ulf Frisk, pcileech@frizk.net
//
#ifndef __PDB_H__
#define __PDB_H__
#include "vmm.h"
#include "pe.h"

typedef QWORD                               PDB_HANDLE;

#define PDB_HANDLE_KERNEL                   ((PDB_HANDLE)-1)
#define PDB_HANDLE_TCPIP                    ((PDB_HANDLE)-2)
#define PDB_HANDLE_NTDLL                    ((PDB_HANDLE)-3)
#define PDB_HANDLE_NTDLL_WOW64              ((PDB_HANDLE)-4)

/*
* Initialize the PDB sub-system. This should ideally be done on Vmm Init().
* -- H
* -- pPdbInfoOpt
* -- fInitializeKernelAsync
*/
VOID PDB_Initialize(_In_ VMM_HANDLE H, _In_opt_ PPE_CODEVIEW_INFO pPdbInfoOpt, _In_ BOOL fInitializeKernelAsync);

/*
* Wait for completion of initialization of the PDB sub-system.
* -- H
*/
VOID PDB_Initialize_WaitComplete(_In_ VMM_HANDLE H);

/*
* Cleanup the PDB sub-system. This should ideally be done on Vmm Close().
* -- H
*/
VOID PDB_Close(_In_ VMM_HANDLE H);

/*
* Update the PDB configuration. The PDB syb-system will be reloaded on
* configuration changes - which may cause a short interruption for any
* caller.
* -- H
*/
VOID PDB_ConfigChange(_In_ VMM_HANDLE H);

/*
* Retrieve a PDB handle given a process and module base address. If the handle
* is not found in the database an attempt to automatically add it is performed.
* NB! Only one PDB with the same base address may exist regardless of process.
* NB! The PDB for the added module won't be loaded until required.
* -- H
* -- pProcess
* -- vaModuleBase
* -- return = The PDB handle on success (no need to close handle); or zero on fail.
*/
PDB_HANDLE PDB_GetHandleFromModuleAddress(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess, _In_ QWORD vaModuleBase);

/*
* Retrieve a PDB handle from an already added module.
* NB! If multiple modules exists with the same name the 1st module to be added
*     is returned.
* -- H
* -- szModuleName
* -- return = The PDB handle on success (no need to close handle); or zero on fail.
*/
PDB_HANDLE PDB_GetHandleFromModuleName(_In_ VMM_HANDLE H, _In_ LPSTR szModuleName);

/*
* Ensure that the PDB_HANDLE have its symbols loaded into memory.
* -- H
* -- hPDB
* -- return
*/
_Success_(return)
BOOL PDB_LoadEnsure(_In_ VMM_HANDLE H, _In_opt_ PDB_HANDLE hPDB);

/*
* Return module information given a PDB handle.
* -- H
* -- hPDB
* -- szModuleName = buffer to receive module name upon success.
* -- pvaModuleBase
* -- pcbModuleSize
* -- return
*/
_Success_(return)
BOOL PDB_GetModuleInfo(_In_ VMM_HANDLE H, _In_opt_ PDB_HANDLE hPDB, _Out_writes_opt_(MAX_PATH) LPSTR szModuleName, _Out_opt_ PQWORD pvaModuleBase, _Out_opt_ PDWORD pcbModuleSize);



//-----------------------------------------------------------------------------
// SYMBOL FUNCTIONALITY BELOW:
// Symbol lookups come in two variants:
// (1) relies on the loaded base stored at load-time.
// (2) relies on a user-supplied base (for infodb lookups with magic handle).
//-----------------------------------------------------------------------------

/*
* Query the PDB for the offset of a symbol.
* -- H
* -- hPDB
* -- szSymbolName
* -- pdwSymbolOffset
* -- return
*/
_Success_(return)
BOOL PDB_GetSymbolOffset(_In_ VMM_HANDLE H, _In_opt_ PDB_HANDLE hPDB, _In_ LPSTR szSymbolName, _Out_ PDWORD pdwSymbolOffset);

/*
* Query the PDB for the offset of a symbol and return its virtual address.
* -- H
* -- hPDB
* -- szSymbolName
* -- pvaSymbolAddress
* -- return
*/
_Success_(return)
BOOL PDB_GetSymbolAddress(_In_ VMM_HANDLE H, _In_opt_ PDB_HANDLE hPDB, _In_ LPSTR szSymbolName, _Out_ PQWORD pvaSymbolAddress);

/*
* Query the PDB for the closest symbol name given an offset from the module
* base address.
* -- H
* -- hPDB
* -- dwSymbolOffset = the offset from the module base to query.
* -- szSymbolName = buffer to receive the name of the symbol.
* -- pdwSymbolDisplacement = displacement from the beginning of the symbol.
* -- return
*/
_Success_(return)
BOOL PDB_GetSymbolFromOffset(_In_ VMM_HANDLE H, _In_opt_ PDB_HANDLE hPDB, _In_ DWORD dwSymbolOffset, _Out_writes_opt_(MAX_PATH) LPSTR szSymbolName, _Out_opt_ PDWORD pdwSymbolDisplacement);

/*
* Read memory at the PDB acquired symbol offset.
* Functions PDB_GetSymbolQWORD and PDB_GetSymbolDWORD behave similarly.
* -- H
* -- hPDB
* -- szSymbolName
* -- pProcess
* -- pb
* -- cb
* -- return
*/
_Success_(return)
BOOL PDB_GetSymbolPBYTE(_In_ VMM_HANDLE H, _In_opt_ PDB_HANDLE hPDB, _In_ LPSTR szSymbolName, _In_ PVMM_PROCESS pProcess, _Out_writes_(cb) PBYTE pb, _In_ DWORD cb);

/*
* Read memory pointed to at the PDB acquired symbol offset.
* -- H
* -- hPDB
* -- szSymbolName
* -- pProcess
* -- pqw
* -- return
*/
_Success_(return)
BOOL PDB_GetSymbolQWORD(_In_ VMM_HANDLE H, _In_opt_ PDB_HANDLE hPDB, _In_ LPSTR szSymbolName, _In_ PVMM_PROCESS pProcess, _Out_ PQWORD pqw);

/*
* Read memory pointed to at the PDB acquired symbol offset.
* -- H
* -- hPDB
* -- szSymbolName
* -- pProcess
* -- pdw
* -- return
*/
_Success_(return)
BOOL PDB_GetSymbolDWORD(_In_ VMM_HANDLE H, _In_opt_ PDB_HANDLE hPDB, _In_ LPSTR szSymbolName, _In_ PVMM_PROCESS pProcess, _Out_ PDWORD pdw);

/*
* Read memory pointed to at the PDB acquired symbol offset.
* -- H
* -- hPDB
* -- szSymbolName
* -- pProcess
* -- pv = PDWORD on 32-bit and PQWORD on 64-bit _operating_system_ architecture.
* -- return
*/
_Success_(return)
BOOL PDB_GetSymbolPTR(_In_ VMM_HANDLE H, _In_opt_ PDB_HANDLE hPDB, _In_ LPSTR szSymbolName, _In_ PVMM_PROCESS pProcess, _Out_ PVOID pv);

/*
* Read memory at the PDB acquired symbol offset and virtual address base.
* -- H
* -- hPDB
* -- vaBase
* -- szSymbolName = wildcard symbol name
* -- pProcess
* -- pb
* -- cb
* -- return
*/
_Success_(return)
BOOL PDB_GetSymbolPBYTE2(_In_ VMM_HANDLE H, _In_opt_ PDB_HANDLE hPDB, _In_ QWORD vaBase, _In_ LPSTR szSymbolName, _In_ PVMM_PROCESS pProcess, _Out_writes_(cb) PBYTE pb, _In_ DWORD cb);

/*
* Read memory pointed to at the PDB acquired symbol offset and virtual address base.
* -- H
* -- hPDB
* -- vaBase
* -- szSymbolName
* -- pProcess
* -- pqw
* -- return
*/
_Success_(return)
BOOL PDB_GetSymbolQWORD2(_In_ VMM_HANDLE H, _In_opt_ PDB_HANDLE hPDB, _In_ QWORD vaBase, _In_ LPSTR szSymbolName, _In_ PVMM_PROCESS pProcess, _Out_ PQWORD pqw);

/*
* Read memory pointed to at the PDB acquired symbol offset and virtual address base.
* -- H
* -- hPDB
* -- vaBase
* -- szSymbolName
* -- pProcess
* -- pdw
* -- return
*/
_Success_(return)
BOOL PDB_GetSymbolDWORD2(_In_ VMM_HANDLE H, _In_opt_ PDB_HANDLE hPDB, _In_ QWORD vaBase, _In_ LPSTR szSymbolName, _In_ PVMM_PROCESS pProcess, _Out_ PDWORD pdw);

/*
* Read memory pointed to at the PDB acquired symbol offset and virtual address base.
* -- H
* -- hPDB
* -- vaBase
* -- szSymbolName
* -- pProcess
* -- pv = PDWORD on 32-bit and PQWORD on 64-bit _operating_system_ architecture.
* -- return
*/
_Success_(return)
BOOL PDB_GetSymbolPTR2(_In_ VMM_HANDLE H, _In_opt_ PDB_HANDLE hPDB, _In_ QWORD vaBase, _In_ LPSTR szSymbolName, _In_ PVMM_PROCESS pProcess, _Out_ PVOID pv);



//-----------------------------------------------------------------------------
// TYPE INFORMATION BELOW:
//-----------------------------------------------------------------------------

/*
* Query the PDB for the size of a type. If szTypeName contains wildcard '?*'
* characters and matches multiple types the size of the 1st type is returned.
* -- H
* -- hPDB
* -- szTypeName = wildcard type name
* -- pdwTypeSize / pwTypeSize
* -- return
*/
_Success_(return)
BOOL PDB_GetTypeSize(_In_ VMM_HANDLE H, _In_opt_ PDB_HANDLE hPDB, _In_ LPSTR szTypeName, _Out_ PDWORD pdwTypeSize);

_Success_(return)
BOOL PDB_GetTypeSizeShort(_In_ VMM_HANDLE H, _In_opt_ PDB_HANDLE hPDB, _In_ LPSTR szTypeName, _Out_ PWORD pwTypeSize);

/*
* Query the PDB for the offset of a child inside a type - often inside a struct.
* If szTypeName contains wildcard '?*' characters and matches multiple types the
* first type is queried for children. The child name must match exactly.
* -- H
* -- hPDB
* -- szTypeName = wildcard type name.
* -- uszTypeChildName = exact match of child name.
* -- pdwTypeOffset = offset relative to type base.
* -- return
*/
_Success_(return)
BOOL PDB_GetTypeChildOffset(_In_ VMM_HANDLE H, _In_opt_ PDB_HANDLE hPDB, _In_ LPSTR szTypeName, _In_ LPSTR uszTypeChildName, _Out_ PDWORD pdwTypeOffset);

_Success_(return)
BOOL PDB_GetTypeChildOffsetShort(_In_ VMM_HANDLE H, _In_opt_ PDB_HANDLE hPDB, _In_ LPSTR szTypeName, _In_ LPSTR uszTypeChildName, _Out_ PWORD pwTypeOffset);

/*
* Fetch the ntoskrnl.exe type information from the PDB symbols and return it in
* a human readable utf-8 string. Caller is responsible for LocalFree().
* Please also note that this function is single-threaded by an internal lock.
* CALLER LocalFree: *pszResult
* -- H
* -- szTypeName = the name of the type - only types within ntosknl.exe are allowed.
* -- cLevelMax = recurse into sub-types to cLevelMax.
* -- vaType = optional kernel address in SYSTEM process address space where to
*             load optional data from.
* -- fHexAscii = append object bytes as hexascii at the end of the string.
* -- fObjHeader = fetch object header instead of object.
* -- pszResult = optional ptr to receive the utf-8 string data
*                (function allocated - callee free)
* -- pcbResult = optional ptr to receive the byte length of the returned string
*                (including terminating null character).
* -- pcbType
* -- return
*/
_Success_(return)
BOOL PDB_DisplayTypeNt(
    _In_ VMM_HANDLE H,
    _In_ LPSTR szTypeName,
    _In_ BYTE cLevelMax,
    _In_opt_ QWORD vaType,
    _In_ BOOL fHexAscii,
    _In_ BOOL fObjHeader,
    _Out_opt_ LPSTR * pszResult,
    _Out_opt_ PDWORD pcbResult,
    _Out_opt_ PDWORD pcbType
);

#endif /* __PDB_H__ */
