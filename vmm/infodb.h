// infodb.h : definitions related to the information read-only sqlite database.
//
// (c) Ulf Frisk, 2021
// Author: Ulf Frisk, pcileech@frizk.net
//
#ifndef __INFODB_H__
#define __INFODB_H__
#include "vmm.h"

/*
* Check if a certificate is well know against the database.
* -- qwThumbprintEndSHA1 = QWORD representation of the last 64 bits of the SHA-1 certificate thumbprint.
* -- return
*/
_Success_(return)
BOOL InfoDB_CertIsWellKnown(_In_ QWORD qwThumbprintEndSHA1);

/*
* Query the InfoDB for the offset of a symbol.
* Currently only szModule values of 'nt', 'ntoskrnl', 'tcpip' is supported.
* -- szModule
* -- szSymbolName
* -- pdwSymbolOffset
* -- return
*/
_Success_(return)
BOOL InfoDB_SymbolOffset(_In_ LPSTR szModule, _In_ LPSTR szSymbolName, _Out_ PDWORD pdwSymbolOffset);

/*
* Read memory pointed to at the symbol offset.
* -- szModule
* -- vaModuleBase
* -- szSymbolName
* -- pProcess
* -- pqw
* -- return
*/
_Success_(return)
BOOL InfoDB_GetSymbolQWORD(_In_ LPSTR szModule, _In_ QWORD vaModuleBase, _In_ LPSTR szSymbolName, _In_ PVMM_PROCESS pProcess, _Out_ PQWORD pqw);

/*
* Read memory pointed to at the symbol offset.
* -- szModule
* -- vaModuleBase
* -- szSymbolName
* -- pProcess
* -- pdw
* -- return
*/
_Success_(return)
BOOL InfoDB_SymbolDWORD(_In_ LPSTR szModule, _In_ QWORD vaModuleBase, _In_ LPSTR szSymbolName, _In_ PVMM_PROCESS pProcess, _Out_ PDWORD pdw);

/*
* Read memory pointed to at the symbol offset.
* -- szModule
* -- vaModuleBase
* -- szSymbolName
* -- pProcess
* -- pv = PDWORD on 32-bit and PQWORD on 64-bit _operating_system_ architecture.
* -- return
*/
_Success_(return)
BOOL InfoDB_SymbolPTR(_In_ LPSTR szModule, _In_ QWORD vaModuleBase, _In_ LPSTR szSymbolName, _In_ PVMM_PROCESS pProcess, _Out_ PVOID pv);

/*
* Query the InfoDB for the size of a type.
* Currently only szModule values of 'nt' or 'ntoskrnl' is supported.
* -- szModule
* -- szTypeName
* -- pdwTypeSize
* -- return
*/
_Success_(return)
BOOL InfoDB_TypeSize(_In_ LPSTR szModule, _In_ LPSTR szTypeName, _Out_ PDWORD pdwTypeSize);

/*
* Query the InfoDB for the offset of a child inside a type - often inside a struct.
* Currently only szModule values of 'nt' or 'ntoskrnl' is supported.
* -- szModule
* -- szTypeName
* -- uszTypeChildName
* -- pdwTypeOffset = offset relative to type base.
* -- return
*/
_Success_(return)
BOOL InfoDB_TypeChildOffset(_In_ LPSTR szModule, _In_ LPSTR szTypeName, _In_ LPSTR uszTypeChildName, _Out_ PDWORD pdwTypeOffset);

/*
* Return whether the InfoDB symbols are ok or not.
* -- pfNtos
* -- pfTcpIp
*/
VOID InfoDB_IsValidSymbols(_Out_opt_ PBOOL pfNtos, _Out_opt_ PBOOL pfTcpIp);

/*
* Return if the InfoDB have been successfully initialized.
* Will return fail on no-init or failure to init (missing info.db file).
* -- return;
*/
BOOL InfoDB_IsInitialized();

/*
* Initialize the InfoDB (if possible):
*/
VOID InfoDB_Initialize();

#endif /* __INFODB_H__ */
