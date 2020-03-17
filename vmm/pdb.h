// pdb.h : definitions related to parsing of program databases (PDB) files used
//         for debug symbols and automatic retrieval from the Microsoft Symbol
//         Server. (Windows exclusive functionality).
//
// (c) Ulf Frisk, 2019-2020
// Author: Ulf Frisk, pcileech@frizk.net
//
#ifndef __PDB_H__
#define __PDB_H__
#include "vmm.h"
#include "pe.h"

#define VMMWIN_PDB_HANDLE_KERNEL            ((QWORD)-1)

/*
* Initialize the PDB sub-system. This should ideally be done on Vmm Init().
* -- pPdbInfoOpt
* -- fInitializeKernelAsync
*/
VOID PDB_Initialize(_In_opt_ PIMAGE_DEBUG_TYPE_CODEVIEW_PDBINFO pPdbInfoOpt, _In_ BOOL fInitializeKernelAsync);

/*
* Wait for completion of initialization of the PDB sub-system.
*/
VOID PDB_Initialize_WaitComplete();

/*
* Cleanup the PDB sub-system. This should ideally be done on Vmm Close().
*/
VOID PDB_Close();

/*
* Update the PDB configuration. The PDB syb-system will be reloaded on
* configuration changes - which may cause a short interruption for any
* caller.
*/
VOID PDB_ConfigChange();

/*
* Add a module to the PDB database and return its handle. The PDB for the added
* module won't be loaded until required. If the module already exists in the
* PDB database the handle will also be returned.
* -- vaModuleBase
* -- szModuleName
* -- szPdbName
* -- pbPdbGUID
* -- dwPdbAge
* -- return
*/
VMMWIN_PDB_HANDLE PDB_AddModuleEntry(_In_ QWORD vaModuleBase, _In_ LPSTR szModuleName, _In_ LPSTR szPdbName, _In_reads_(16) PBYTE pbPdbGUID, _In_ DWORD dwPdbAge);

/*
* Retrieve a PDB handle from an already added module.
* NB! If multiple modules exists with the same name the 1st module to be added
*     is returned.
* -- szModuleName
* -- return
*/
VMMWIN_PDB_HANDLE PDB_GetHandleFromModuleName(_In_ LPSTR szModuleName);

/*
* Query the PDB for the offset of a symbol. If szSymbolName contains wildcard
* '?*' characters and matches multiple symbols the offset of the 1st symbol is
* returned.
* -- hPDB
* -- szSymbolName = wildcard symbol name
* -- pdwSymbolOffset
* -- return
*/
_Success_(return)
BOOL PDB_GetSymbolOffset(_In_opt_ VMMWIN_PDB_HANDLE hPDB, _In_ LPSTR szSymbolName, _Out_ PDWORD pdwSymbolOffset);

/*
* Query the PDB for the offset of a symbol and return its virtual address. If
* szSymbolName contains wildcard '?*' characters and matches multiple symbols
* the virtual address of the 1st symbol is returned.
* -- hPDB
* -- szSymbolName = wildcard symbol name
* -- pvaSymbolOffset
* -- return
*/
_Success_(return)
BOOL PDB_GetSymbolAddress(_In_opt_ VMMWIN_PDB_HANDLE hPDB, _In_ LPSTR szSymbolName, _Out_ PQWORD pvaSymbolOffset);

/*
* Read memory at the PDB acquired symbol offset. If szSymbolName contains
* wildcard '?*' characters and matches multiple symbols the offset of the
* 1st symbol is used to read the memory.
* Functions PDB_GetSymbolQWORD and PDB_GetSymbolDWORD behave similarly.
* -- hPDB
* -- szSymbolName = wildcard symbol name
* -- pProcess
* -- pb
* -- cb
* -- return
*/
_Success_(return)
BOOL PDB_GetSymbolPBYTE(_In_opt_ VMMWIN_PDB_HANDLE hPDB, _In_ LPSTR szSymbolName, _In_ PVMM_PROCESS pProcess, _Out_writes_(cb) PBYTE pb, _In_ DWORD cb);

/*
* Read memory pointed to at the PDB acquired symbol offset.
* -- hPDB
* -- szSymbolName
* -- pProcess
* -- pqw
* -- return
*/
_Success_(return)
inline BOOL PDB_GetSymbolQWORD(_In_opt_ VMMWIN_PDB_HANDLE hPDB, _In_ LPSTR szSymbolName, _In_ PVMM_PROCESS pProcess, _Out_ PQWORD pqw)
{
    return PDB_GetSymbolPBYTE(hPDB, szSymbolName, pProcess, (PBYTE)pqw, sizeof(QWORD));
}

/*
* Read memory pointed to at the PDB acquired symbol offset.
* -- hPDB
* -- szSymbolName
* -- pProcess
* -- pdw
* -- return
*/
_Success_(return)
inline BOOL PDB_GetSymbolDWORD(_In_opt_ VMMWIN_PDB_HANDLE hPDB, _In_ LPSTR szSymbolName, _In_ PVMM_PROCESS pProcess, _Out_ PDWORD pdw)
{
    return PDB_GetSymbolPBYTE(hPDB, szSymbolName, pProcess, (PBYTE)pdw, sizeof(DWORD));
}

/*
* Read memory pointed to at the PDB acquired symbol offset.
* -- hPDB
* -- szSymbolName
* -- pProcess
* -- pv = PDWORD on 32-bit and PQWORD on 64-bit _operating_system_ architecture.
* -- return
*/
_Success_(return)
inline BOOL PDB_GetSymbolPTR(_In_opt_ VMMWIN_PDB_HANDLE hPDB, _In_ LPSTR szSymbolName, _In_ PVMM_PROCESS pProcess, _Out_ PVOID pv)
{
    return PDB_GetSymbolPBYTE(hPDB, szSymbolName, pProcess, (PBYTE)pv, (ctxVmm->f32 ? sizeof(DWORD) : sizeof(QWORD)));
}

/*
* Query the PDB for the size of a type. If szTypeName contains wildcard '?*'
* characters and matches multiple types the size of the 1st type is returned.
* -- hPDB
* -- szTypeName = wildcard type name
* -- pdwTypeSize / pwTypeSize
* -- return
*/
_Success_(return)
BOOL PDB_GetTypeSize(_In_opt_ VMMWIN_PDB_HANDLE hPDB, _In_ LPSTR szTypeName, _Out_ PDWORD pdwTypeSize);

_Success_(return)
BOOL PDB_GetTypeSizeShort(_In_opt_ VMMWIN_PDB_HANDLE hPDB, _In_ LPSTR szTypeName, _Out_ PWORD pwTypeSize);

/*
* Query the PDB for the offset of a child inside a type - often inside a struct.
* If szTypeName contains wildcard '?*' characters and matches multiple types the
* first type is queried for children. The child name must match exactly.
* -- hPDB
* -- szTypeName = wildcard type name.
* -- wszTypeChildName = exact match of child name.
* -- pdwTypeOffset / pwTypeOffset = offset relative to type base.
* -- return
*/
_Success_(return)
BOOL PDB_GetTypeChildOffset(_In_opt_ VMMWIN_PDB_HANDLE hPDB, _In_ LPSTR szTypeName, _In_ LPWSTR wszTypeChildName, _Out_ PDWORD pdwTypeOffset);

_Success_(return)
BOOL PDB_GetTypeChildOffsetShort(_In_opt_ VMMWIN_PDB_HANDLE hPDB, _In_ LPSTR szTypeName, _In_ LPWSTR wszTypeChildName, _Out_ PWORD pwTypeOffset);

#endif /* __PDB_H__ */
