// pdb.c : implementation related to parsing of program databases (PDB) files
//         used for debug symbols and automatic retrieval from the Microsoft
//         Symbol Server.
// 
//         Microsoft Symbol Server:
//         Parsing may take place by using the Microsoft debug libraries
//         'dbghelp.dll' and 'symsrv.dll' on Windows if these .dll files
//         exists alongside 'vmm.dll'. This is the default behavior.
// 
//         PDBCRust wrapper around Rust PDB crate:
//         Parsing may also take place using the pdbcrust wrapper library
//         which wraps the Rust PDB crate in a convenient c-library. This
//         is the fallback method on Windows and the primary method on Linux.
//         The file 'pdbcrust.[so|dll]' must exist alongside [vmm.so|dll]
//         for this to work.
// 
//         Fallback to INFODB:
//         A fallback of select functionality of cached symbols towards
//         the info.db sqlite database may also take place.
//
// (c) Ulf Frisk, 2019-2025
// Author: Ulf Frisk, pcileech@frizk.net
//
#include "pdb.h"
#include "pe.h"
#include "infodb.h"
#include "charutil.h"
#include "util.h"
#include "vmmwindef.h"
#include "vmmwininit.h"
#include "vmmuserconfig.h"
#include "ob/ob.h"
#include "ob/ob_tag.h"
#include <libpdbcrust.h>

VOID PDB_PrintError(_In_ VMM_HANDLE H, _In_ LPSTR szErrorMessage1, _In_opt_ LPSTR szErrorMessage2)
{
    BOOL fInfoDB_Ntos;
    DWORD dwTimeDateStamp = 0;
    PVMM_PROCESS pObSystemProcess;
    InfoDB_IsValidSymbols(H, &fInfoDB_Ntos, NULL);
    if(fInfoDB_Ntos) {
        VmmLog(H, MID_SYMBOL, LOGLEVEL_WARNING, "Functionality may be limited. Extended debug information disabled.");
        VmmLog(H, MID_SYMBOL, LOGLEVEL_WARNING, "Partial offline fallback symbols in use.");
        VmmLog(H, MID_SYMBOL, LOGLEVEL_WARNING, "For additional information use startup option: -loglevel symbol:4");
        if(szErrorMessage2) { VmmLog(H, MID_SYMBOL, LOGLEVEL_WARNING, "%s", szErrorMessage2); }
        VmmLog(H, MID_SYMBOL, LOGLEVEL_WARNING, "%s\n", szErrorMessage1);
        return;
    }
    if(InfoDB_IsInitialized(H)) {
        if((pObSystemProcess = VmmProcessGet(H, 4))) {
            PE_GetTimeDateStampCheckSum(H, pObSystemProcess, H->vmm.kernel.vaBase, &dwTimeDateStamp, NULL);
            Ob_DECREF_NULL(&pObSystemProcess);
        }
        VmmLog(H, MID_SYMBOL, LOGLEVEL_WARNING, "Functionality may be limited. Extended debug information disabled.");
        VmmLog(H, MID_SYMBOL, LOGLEVEL_WARNING, "Offline symbols unavailable - ID: %08X%X", dwTimeDateStamp, (DWORD)H->vmm.kernel.cbSize);
        if(szErrorMessage2) { VmmLog(H, MID_SYMBOL, LOGLEVEL_WARNING, "%s", szErrorMessage2); }
        VmmLog(H, MID_SYMBOL, LOGLEVEL_WARNING, "%s\n", szErrorMessage1);
    } else {
        VmmLog(H, MID_SYMBOL, LOGLEVEL_WARNING, "Functionality may be limited. Extended debug information disabled.");
        VmmLog(H, MID_SYMBOL, LOGLEVEL_WARNING, "Offline symbols unavailable - file 'info.db' not found.");
        if(szErrorMessage2) { VmmLog(H, MID_SYMBOL, LOGLEVEL_WARNING, "%s", szErrorMessage2); }
        VmmLog(H, MID_SYMBOL, LOGLEVEL_WARNING, "%s\n", szErrorMessage1);
    }
}

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
BOOL PDB_GetSymbolQWORD(_In_ VMM_HANDLE H, _In_opt_ PDB_HANDLE hPDB, _In_ LPCSTR szSymbolName, _In_ PVMM_PROCESS pProcess, _Out_ PQWORD pqw)
{
    return PDB_GetSymbolPBYTE(H, hPDB, szSymbolName, pProcess, (PBYTE)pqw, sizeof(QWORD));
}

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
BOOL PDB_GetSymbolDWORD(_In_ VMM_HANDLE H, _In_opt_ PDB_HANDLE hPDB, _In_ LPCSTR szSymbolName, _In_ PVMM_PROCESS pProcess, _Out_ PDWORD pdw)
{
    return PDB_GetSymbolPBYTE(H, hPDB, szSymbolName, pProcess, (PBYTE)pdw, sizeof(DWORD));
}

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
BOOL PDB_GetSymbolPTR(_In_ VMM_HANDLE H, _In_opt_ PDB_HANDLE hPDB, _In_ LPCSTR szSymbolName, _In_ PVMM_PROCESS pProcess, _Out_ PVOID pv)
{
    return PDB_GetSymbolPBYTE(H, hPDB, szSymbolName, pProcess, (PBYTE)pv, (H->vmm.f32 ? sizeof(DWORD) : sizeof(QWORD)));
}

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
BOOL PDB_GetSymbolPBYTE2(_In_ VMM_HANDLE H, _In_opt_ PDB_HANDLE hPDB, _In_ QWORD vaBase, _In_ LPCSTR szSymbolName, _In_ PVMM_PROCESS pProcess, _Out_writes_(cb) PBYTE pb, _In_ DWORD cb)
{
    DWORD dwSymbolOffset;
    if(!PDB_GetSymbolOffset(H, hPDB, szSymbolName, &dwSymbolOffset)) { return FALSE; }
    return VmmRead(H, pProcess, vaBase + dwSymbolOffset, pb, cb);
}

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
BOOL PDB_GetSymbolQWORD2(_In_ VMM_HANDLE H, _In_opt_ PDB_HANDLE hPDB, _In_ QWORD vaBase, _In_ LPCSTR szSymbolName, _In_ PVMM_PROCESS pProcess, _Out_ PQWORD pqw)
{
    return PDB_GetSymbolPBYTE2(H, hPDB, vaBase, szSymbolName, pProcess, (PBYTE)pqw, sizeof(QWORD));
}

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
BOOL PDB_GetSymbolDWORD2(_In_ VMM_HANDLE H, _In_opt_ PDB_HANDLE hPDB, _In_ QWORD vaBase, _In_ LPCSTR szSymbolName, _In_ PVMM_PROCESS pProcess, _Out_ PDWORD pdw)
{
    return PDB_GetSymbolPBYTE2(H, hPDB, vaBase, szSymbolName, pProcess, (PBYTE)pdw, sizeof(DWORD));
}

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
BOOL PDB_GetSymbolPTR2(_In_ VMM_HANDLE H, _In_opt_ PDB_HANDLE hPDB, _In_ QWORD vaBase, _In_ LPCSTR szSymbolName, _In_ PVMM_PROCESS pProcess, _Out_ PVOID pv)
{
    return PDB_GetSymbolPBYTE2(H, hPDB, vaBase, szSymbolName, pProcess, (PBYTE)pv, (H->vmm.f32 ? sizeof(DWORD) : sizeof(QWORD)));
}

/*
* Retrieve a module name given a magic hPDB. If no match is made NULL is returned.
* -- hPDB = magic PDB handle.
* -- return
*/
_Success_(return != NULL)
LPSTR PDB_ModuleNameFromHandleMagic(_In_ PDB_HANDLE hPDB)
{
    switch(hPDB) {
        case PDB_HANDLE_KERNEL:      return "nt";
        case PDB_HANDLE_TCPIP:       return "tcpip";
        case PDB_HANDLE_NTDLL:       return "ntdll";
        case PDB_HANDLE_NTDLL_WOW64: return "wntdll";
        default:                     return NULL;
    }
}

/*
* Wrapper for Query the InfoDB for the offset of a symbol.
* NB! Query must be done with magic PDB handle to succeed.
* -- H
* -- hPDB = magic PDB handle.
* -- szSymbolName
* -- pdwSymbolOffset
* -- return
*/
_Success_(return)
BOOL PDB_InfoDB_SymbolOffset(_In_ VMM_HANDLE H, _In_opt_ PDB_HANDLE hPDB, _In_ LPCSTR szSymbolName, _Out_ PDWORD pdwSymbolOffset)
{
    LPSTR szModule = PDB_ModuleNameFromHandleMagic(hPDB);
    if(!szModule) { return FALSE; }
    return InfoDB_SymbolOffset(H, szModule, szSymbolName, pdwSymbolOffset);
}

/*
* Wrapper for Query the InfoDB for the size of a type.
* NB! Query must be done with magic PDB handle to succeed.
* 
* -- hPDB = magic PDB handle.
* -- szTypeName
* -- pdwTypeSize
* -- fDynamic = dynamic(TRUE) or static(FALSE) type InfoDB lookup.
* -- return
*/
_Success_(return)
BOOL PDB_InfoDB_TypeSize(_In_ VMM_HANDLE H, _In_opt_ PDB_HANDLE hPDB, _In_ LPCSTR szTypeName, _Out_ PDWORD pdwTypeSize, _In_ BOOL fDynamic)
{
    LPSTR szModule = PDB_ModuleNameFromHandleMagic(hPDB);
    if(!szModule) { return FALSE; }
    if(fDynamic) {
        return InfoDB_TypeSize_Dynamic(H, szModule, szTypeName, pdwTypeSize);
    } else {
        return InfoDB_TypeSize_Static(H, szModule, szTypeName, pdwTypeSize);
    }
}

/*
* Wrapper for Query the InfoDB for the offset of a child inside a type - often inside a struct.
* NB! Query must be done with magic PDB handle to succeed.
* -- H
* -- hPDB = magic PDB handle.
* -- szTypeName
* -- uszTypeChildName
* -- pdwTypeOffset = offset relative to type base.
* -- fDynamic = dynamic(TRUE) or static(FALSE) type InfoDB lookup.
* -- return
*/
_Success_(return)
BOOL PDB_InfoDB_TypeChildOffset(_In_ VMM_HANDLE H, _In_opt_ PDB_HANDLE hPDB, _In_ LPCSTR szTypeName, _In_ LPCSTR uszTypeChildName, _Out_ PDWORD pdwTypeOffset, _In_ BOOL fDynamic)
{
    LPSTR szModule = PDB_ModuleNameFromHandleMagic(hPDB);
    if(!szModule) { return FALSE; }
    if(fDynamic) {
        return InfoDB_TypeChildOffset_Dynamic(H, szModule, szTypeName, uszTypeChildName, pdwTypeOffset);
    } else {
        return InfoDB_TypeChildOffset_Static(H, szModule, szTypeName, uszTypeChildName, pdwTypeOffset);
    }
}

#define VMMWIN_PDB_LOAD_ADDRESS_STEP    0x10000000
#define VMMWIN_PDB_LOAD_ADDRESS_BASE    0x0000511f00000000

QWORD g_PDB_qwLoadAddressNext = VMMWIN_PDB_LOAD_ADDRESS_BASE;

typedef struct tdPDB_ENTRY {
    OB ObHdr;
    QWORD qwHash;
    QWORD vaModuleBase;
    LPSTR szModuleName;
    LPSTR szName;
    BYTE pbGUID[16];
    DWORD dwAge;
    DWORD cbModuleSize;
    // load data below
    BOOL fLoadFailed;
    LPSTR szPath;
    QWORD qwLoadAddress;    // MSPDB fake load address or CRUST handle
    // CRUST cleanup function (since no access to pdb context exist at cleanup)
    void(*pfn_pdbcrust_close_opt)(_In_ size_t hnd);
} PDB_ENTRY, *PPDB_ENTRY;

#ifdef _WIN32
#include <io.h>
#define _NO_CVCONST_H
#include <dbghelp.h>

const LPSTR szMSPDB_PDB_FUNCTIONS[] = {
    "SymGetOptions",
    "SymSetOptions",
    "SymInitialize",
    "SymCleanup",
    "SymFindFileInPath",
    "SymLoadModuleEx",
    "SymUnloadModule64",
    "SymEnumSymbols",
    "SymEnumTypesByName",
    "SymGetTypeFromName",
    "SymGetTypeInfo",
    "SymGetTypeInfoEx",
    "SymFromAddr",
};

typedef struct tdMSPDB_PDB_FUNCTIONS {
    DWORD(WINAPI *SymGetOptions)(VOID);
    DWORD(WINAPI *SymSetOptions)(_In_ DWORD SymOptions);
    BOOL(WINAPI *SymInitialize)(_In_ HANDLE hProcess, _In_opt_ PCSTR UserSearchPath, _In_ BOOL fInvadeProcess);
    BOOL(WINAPI *SymCleanup)(_In_ HANDLE hProcess);
    BOOL(WINAPI *SymFindFileInPath)(_In_ HANDLE hprocess, _In_opt_ PCSTR SearchPath, _In_ PCSTR FileName, _In_opt_ PVOID id, _In_ DWORD two, _In_ DWORD three, _In_ DWORD flags, _Out_writes_(MAX_PATH + 1) PSTR FoundFile, _In_opt_ PFINDFILEINPATHCALLBACK callback, _In_opt_ PVOID context);
    DWORD64(WINAPI *SymLoadModuleEx)(_In_ HANDLE hProcess, _In_opt_ HANDLE hFile, _In_opt_ PCSTR ImageName, _In_opt_ PCSTR ModuleName, _In_ DWORD64 BaseOfDll, _In_ DWORD DllSize, _In_opt_ PMODLOAD_DATA Data, _In_opt_ DWORD Flags);
    BOOL(WINAPI *SymUnloadModule64)(_In_ HANDLE hProcess, _In_ DWORD64 BaseOfDll);
    BOOL(WINAPI *SymEnumSymbols)(_In_ HANDLE hProcess, _In_ ULONG64 BaseOfDll, _In_opt_ PCSTR Mask, _In_ PSYM_ENUMERATESYMBOLS_CALLBACK EnumSymbolsCallback, _In_opt_ PVOID UserContext);
    BOOL(WINAPI *SymEnumTypesByName)(_In_ HANDLE hProcess, _In_ ULONG64 BaseOfDll, _In_opt_ PCSTR mask, _In_ PSYM_ENUMERATESYMBOLS_CALLBACK EnumSymbolsCallback, _In_opt_ PVOID UserContext);
    BOOL(WINAPI *SymGetTypeFromName)(_In_ HANDLE hProcess, _In_ ULONG64 BaseOfDll, _In_ PCSTR Name, _Inout_ PSYMBOL_INFO);
    BOOL(WINAPI *SymGetTypeInfo)(_In_ HANDLE hProcess, _In_ DWORD64 ModBase, _In_ ULONG TypeId, _In_ IMAGEHLP_SYMBOL_TYPE_INFO GetType, _Out_ PVOID pInfo);
    BOOL(WINAPI *SymGetTypeInfoEx)(_In_ HANDLE hProcess, _In_ DWORD64 ModBase, _Inout_ PIMAGEHLP_GET_TYPE_INFO_PARAMS Params);
    BOOL(WINAPI *SymFromAddr)(_In_ HANDLE hProcess, _In_ DWORD64 Address, _Out_ PDWORD64 Displacement, _Out_ PSYMBOL_INFO Symbol);
} MSPDB_PDB_FUNCTIONS, *PMSPDB_PDB_FUNCTIONS;

#endif /* _WIN32 */

const LPSTR szCRUST_PDB_FUNCTIONS[] = {
    "pdbcrust_pdb_download_ensure",
    "pdbcrust_open",
    "pdbcrust_close",
    "pdbcrust_symbol_offset",
    "pdbcrust_symbol_name_from_offset",
    "pdbcrust_type_size",
    "pdbcrust_type_child_offset",
};

typedef struct tdCRUST_PDB_FUNCTIONS {
    bool(*pdbcrust_pdb_download_ensure)(_In_ const char *szPdbBasePath, _In_ char *szPdbGuidAge, _In_ const char *szPdbName, _In_ bool fDownload, _In_ size_t cbFullPdbPath, _Out_writes_bytes_(cbFullPdbPath) char *szFullPdbPath);
    size_t(*pdbcrust_open)(_In_ const char *szFullPdbPath);
    void(*pdbcrust_close)(_In_ size_t hnd);
    unsigned int(*pdbcrust_symbol_offset)(_In_ size_t hnd, _In_ const char *szSymbol);
    bool(*pdbcrust_symbol_name_from_offset)(_In_ size_t hnd, _In_ unsigned int symbol_offset, _In_ size_t len_symbol_name, _Out_writes_bytes_(len_symbol_name) char *sz_symbol_name, _Out_ unsigned int *displacement);
    unsigned int(*pdbcrust_type_size)(_In_ size_t hnd, _In_ const char *szTypeName);
    bool(*pdbcrust_type_child_offset)(_In_ size_t hnd, _In_ const char *szTypeName, _In_ const char *szChildName, _In_ unsigned int *offset_type_child);
} CRUST_PDB_FUNCTIONS, *PCRUST_PDB_FUNCTIONS;

typedef struct tdOB_PDB_CONTEXT {
    OB ObHdr;
    BOOL fDisabled;
    CRITICAL_SECTION Lock;
    POB_MAP pmPdbByHash;
    POB_MAP pmPdbByModule;
    struct {
        BOOL fValid;
        HMODULE hModule;
        union {
            CRUST_PDB_FUNCTIONS pfn;
            PVOID vafn[sizeof(CRUST_PDB_FUNCTIONS) / sizeof(PVOID)];
        };
    } crust;
#ifdef _WIN32
    struct {
        BOOL fValid;
        HANDLE hSym;
        HMODULE hModuleSymSrv;
        HMODULE hModuleDbgHelp;
        union {
            MSPDB_PDB_FUNCTIONS pfn;
            PVOID vafn[sizeof(MSPDB_PDB_FUNCTIONS) / sizeof(PVOID)];
        };
    } mspdb;
#endif /* _WIN32 */
} OB_PDB_CONTEXT, *POB_PDB_CONTEXT;

typedef struct tdOB_PDB_INITIALIZE_KERNEL_PARAMETERS {
    OB ObHdr;
    PHANDLE phEventThreadStarted;
    BOOL fPdbInfo;
    PE_CODEVIEW_INFO PdbInfo;
} OB_PDB_INITIALIZE_KERNEL_PARAMETERS, *POB_PDB_INITIALIZE_KERNEL_PARAMETERS;

QWORD PDB_HashPdb(_In_ LPSTR szPdbName, _In_reads_(16) PBYTE pbPdbGUID, _In_ DWORD dwPdbAge)
{
    QWORD qwHash = 0;
    qwHash = CharUtil_Hash32A(szPdbName, TRUE);
    qwHash = dwPdbAge + ((qwHash >> 13) | (qwHash << 51));
    qwHash = *(PQWORD)pbPdbGUID + ((qwHash >> 13) | (qwHash << 51));
    qwHash = *(PQWORD)(pbPdbGUID + 8) + ((qwHash >> 13) | (qwHash << 51));
    return qwHash;
}

DWORD PDB_HashModuleName(_In_ LPCSTR uszModuleName)
{
    return CharUtil_HashNameFsU(uszModuleName, 0);
}

VOID PDB_CallbackCleanup_ObPdbEntry(PPDB_ENTRY pOb)
{
    if(pOb->pfn_pdbcrust_close_opt && ((pOb->qwLoadAddress & 0xffff) == 0)) {
        pOb->pfn_pdbcrust_close_opt((SIZE_T)pOb->qwLoadAddress);
    }
    LocalFree(pOb->szModuleName);
    LocalFree(pOb->szName);
    LocalFree(pOb->szPath);
}
/*
* Cleanup callback to clean up PDB context.
*/
VOID PDB_CallbackCleanup_ObPdbContext(POB_PDB_CONTEXT ctx)
{
    Ob_DECREF(ctx->pmPdbByHash);
    Ob_DECREF(ctx->pmPdbByModule);
    if(ctx->crust.hModule) { FreeLibrary(ctx->crust.hModule); }
#ifdef _WIN32
    if(ctx->mspdb.hSym) { ctx->mspdb.pfn.SymCleanup(ctx->mspdb.hSym); }
    if(ctx->mspdb.hModuleSymSrv) { FreeLibrary(ctx->mspdb.hModuleSymSrv); }
    if(ctx->mspdb.hModuleDbgHelp) { FreeLibrary(ctx->mspdb.hModuleDbgHelp); }
#endif /* _WIN32 */
    DeleteCriticalSection(&ctx->Lock);
}

/*
* Retrieve the current PDB context
* CALLER DECREF: return
* -- H
* -- return
*/
POB_PDB_CONTEXT PDB_GetContext(_In_ VMM_HANDLE H)
{
    return Ob_INCREF(H->vmm.pObPdbContext);
}

/*
* Add a module to the PDB database and return its handle.
* NB! The PDB for the added module won't be loaded until required.
* -- H
* -- vaModuleBase
* -- cbModuleSize = optional size of the module (required if using GetSymbolFromAddress functionality).
* -- szModuleName
* -- szPdbName
* -- pbPdbGUID
* -- dwPdbAge
* -- return = The PDB handle on success (no need to close handle); or zero on fail.
*/
PDB_HANDLE PDB_AddModuleEntry(_In_ VMM_HANDLE H, _In_ QWORD vaModuleBase, _In_opt_ DWORD cbModuleSize, _In_ LPSTR szModuleName, _In_ LPSTR szPdbName, _In_reads_(16) PBYTE pbPdbGUID, _In_ DWORD dwPdbAge)
{
    POB_PDB_CONTEXT ctxOb = PDB_GetContext(H);
    PPDB_ENTRY pObPdbEntry;
    QWORD qwPdbHash = 0;
    if(!ctxOb) { return 0; }
    qwPdbHash = PDB_HashPdb(szPdbName, pbPdbGUID, dwPdbAge);
    EnterCriticalSection(&ctxOb->Lock);
    if(!ObMap_ExistsKey(ctxOb->pmPdbByHash, qwPdbHash)) {
        pObPdbEntry = Ob_AllocEx(H, OB_TAG_PDB_ENTRY, LMEM_ZEROINIT, sizeof(PDB_ENTRY), (OB_CLEANUP_CB)PDB_CallbackCleanup_ObPdbEntry, NULL);
        if(!pObPdbEntry) { goto fail; }
        pObPdbEntry->dwAge = dwPdbAge;
        pObPdbEntry->qwHash = qwPdbHash;
        memcpy(pObPdbEntry->pbGUID, pbPdbGUID, 16);
        pObPdbEntry->szName = Util_StrDupA(szPdbName);
        pObPdbEntry->szModuleName = Util_StrDupA(szModuleName);
        pObPdbEntry->vaModuleBase = vaModuleBase;
        pObPdbEntry->cbModuleSize = cbModuleSize;
        ObMap_Push(ctxOb->pmPdbByHash, qwPdbHash, pObPdbEntry);
        ObMap_Push(ctxOb->pmPdbByModule, PDB_HashModuleName(szModuleName), pObPdbEntry);
        Ob_DECREF(pObPdbEntry);
    }
fail:
    LeaveCriticalSection(&ctxOb->Lock);
    Ob_DECREF(ctxOb);
    return qwPdbHash;
}

/*
* Retrieve a PDB handle given a process and module base address. If the handle
* is not found in the database an attempt to automatically add it is performed.
* NB! Only one PDB with the same base address may exist regardless of process.
* NB! The PDB for the added module won't be loaded until required.
* -- pProcess
* -- vaModuleBase
* -- return = The PDB handle on success (no need to close handle); or zero on fail.
*/
PDB_HANDLE PDB_GetHandleFromModuleAddress(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess, _In_ QWORD vaModuleBase)
{
    POB_PDB_CONTEXT ctxOb = PDB_GetContext(H);
    PPDB_ENTRY pObPdbEntry = 0;
    PE_CODEVIEW_INFO CodeViewInfo = { 0 };
    DWORD i, iMax;
    QWORD qwPdbHash, cbModuleSize;
    CHAR szModuleName[MAX_PATH], *szPdbText;
    if(!ctxOb) { return 0; }
    // find: module base address already in .pdb database.
    for(i = 0, iMax = ObMap_Size(ctxOb->pmPdbByHash); i < iMax; i++) {
        if((pObPdbEntry = ObMap_GetByIndex(ctxOb->pmPdbByHash, i))) {
            if(vaModuleBase == pObPdbEntry->vaModuleBase) {
                qwPdbHash = pObPdbEntry->qwHash;
                Ob_DECREF_NULL(&pObPdbEntry);
                Ob_DECREF_NULL(&ctxOb);
                return qwPdbHash;
            }
            Ob_DECREF_NULL(&pObPdbEntry);
        }
    }
    Ob_DECREF_NULL(&ctxOb);
    // retrieve codeview and add to .pdb database.
    if(!(cbModuleSize = PE_GetSize(H, pProcess, vaModuleBase)) || (cbModuleSize > 0x04000000)) { return 0; }
    if(!PE_GetCodeViewInfo(H, pProcess, vaModuleBase, NULL, &CodeViewInfo)) { return 0; }
    strcpy_s(szModuleName, MAX_PATH, CodeViewInfo.CodeView.PdbFileName);
    if((szPdbText = strstr(szModuleName, ".pdb"))) {
        szPdbText[0] = 0;
    }
    return PDB_AddModuleEntry(
        H,
        vaModuleBase,
        (DWORD)cbModuleSize,
        szModuleName,
        CodeViewInfo.CodeView.PdbFileName,
        CodeViewInfo.CodeView.Guid,
        CodeViewInfo.CodeView.Age
    );
}

/*
* Retrieve a PDB handle from an already added module.
* NB! If multiple modules exists with the same name the 1st module to be added
*     is returned.
* -- H
* -- szModuleName
* -- return = The PDB handle on success (no need to close handle); or zero on fail.
*/
PDB_HANDLE PDB_GetHandleFromModuleName(_In_ VMM_HANDLE H, _In_ LPCSTR szModuleName)
{
    POB_PDB_CONTEXT ctxOb = PDB_GetContext(H);
    PPDB_ENTRY pObPdbEntry = NULL;
    QWORD qwHashPdb = 0;
    DWORD dwHashModule;
    if(!ctxOb || ctxOb->fDisabled) { goto fail; }
    if(!szModuleName || !strcmp("nt", szModuleName)) {
        szModuleName = "ntoskrnl";
    }
    dwHashModule = PDB_HashModuleName(szModuleName);
    if(!(pObPdbEntry = ObMap_GetByKey(ctxOb->pmPdbByModule, dwHashModule))) { goto fail; }
    qwHashPdb = pObPdbEntry->fLoadFailed ? 0 : pObPdbEntry->qwHash;
fail:
    Ob_DECREF(pObPdbEntry);
    Ob_DECREF(ctxOb);
    return qwHashPdb;
}

/*
* Get a valid PDB handle given an ordinary or magic PDB handle.
* -- H
* -- hPDB = ordinary or magic PDB handle.
* -- return = ordinary PDB handle (or 0 on fail).
*/
PDB_HANDLE PDB_GetHandleFromHandleMagic(_In_ VMM_HANDLE H, _In_ PDB_HANDLE hPDB)
{
    LPSTR szModule = PDB_ModuleNameFromHandleMagic(hPDB);
    return szModule ? PDB_GetHandleFromModuleName(H, szModule) : hPDB;
}

/*
* Ensure that the PDB_ENTRY have its symbols loaded into memory.
* NB! this function must be called in a single-threaded context!
* -- H
* -- ctx
* -- pPdbEntry
* -- return
*/
_Success_(return)
BOOL PDB_LoadEnsureEx(_In_ VMM_HANDLE H, _In_ POB_PDB_CONTEXT ctx, _In_ PPDB_ENTRY pPdbEntry)
{
    BOOL fLoadResult = FALSE;
    QWORD qwLoadAddress;
    CHAR szPdbGuidAge[66];
    CHAR szPdbPath[MAX_PATH + 1];
    if(!ctx || pPdbEntry->fLoadFailed) { return FALSE; }
    if(pPdbEntry->qwLoadAddress) { return TRUE; }
#ifdef _WIN32
    if(ctx->mspdb.fValid) {
        fLoadResult = ctx->mspdb.pfn.SymFindFileInPath(ctx->mspdb.hSym, NULL, pPdbEntry->szName, pPdbEntry->pbGUID, pPdbEntry->dwAge, 0, SSRVOPT_GUIDPTR, szPdbPath, NULL, NULL);
    }
#endif /* _WIN32 */
    if(!fLoadResult) {
        _snprintf_s(szPdbGuidAge, _countof(szPdbGuidAge), _TRUNCATE, "%08X%04X%04X%02X%02X%02X%02X%02X%02X%02X%02X%i",
            *(PDWORD)(pPdbEntry->pbGUID + 0), *(PWORD)(pPdbEntry->pbGUID + 4), *(PWORD)(pPdbEntry->pbGUID + 6),
            pPdbEntry->pbGUID[8], pPdbEntry->pbGUID[9], pPdbEntry->pbGUID[10], pPdbEntry->pbGUID[11],
            pPdbEntry->pbGUID[12], pPdbEntry->pbGUID[13], pPdbEntry->pbGUID[14], pPdbEntry->pbGUID[15],
            pPdbEntry->dwAge
        );
        fLoadResult = ctx->crust.fValid && ctx->crust.pfn.pdbcrust_pdb_download_ensure(H->pdb.szLocal, szPdbGuidAge, pPdbEntry->szName, TRUE, sizeof(szPdbPath), szPdbPath);
    }
    if(!fLoadResult) {
        if(VmmLogIsActive(H, MID_SYMBOL, LOGLEVEL_4_VERBOSE)) {
            if(CharUtil_StrCmpAny(CharUtil_StrEquals, pPdbEntry->szName, FALSE, 8, "ntkrnlmp.pdb", "ntkrnlpa.pdb", "ntkrpamp.pdb", "ntmarta.pdb", "ntoskrnl.pdb", "tcpip.pdb", "ntdll.pdb", "wntdll.pdb")) {
                VmmLog(H, MID_SYMBOL, LOGLEVEL_4_VERBOSE, "Unable to download required debug symbols %s - manual download possible.", pPdbEntry->szName);
                VmmLog(H, MID_SYMBOL, LOGLEVEL_4_VERBOSE, "Download from:");
                VmmLog(H, MID_SYMBOL, LOGLEVEL_4_VERBOSE, "  https://msdl.microsoft.com/download/symbols/%s/%s/%s", pPdbEntry->szName, szPdbGuidAge, pPdbEntry->szName);
                VmmLog(H, MID_SYMBOL, LOGLEVEL_4_VERBOSE, "Download to:");
                VmmLog(H, MID_SYMBOL, LOGLEVEL_4_VERBOSE, "  %s\\%s\\%s\\%s", H->pdb.szLocal, pPdbEntry->szName, szPdbGuidAge, pPdbEntry->szName);
            }
        }
        goto fail;
    }
    pPdbEntry->szPath = Util_StrDupA(szPdbPath);
#ifdef _WIN32
    if(ctx->mspdb.fValid) {
        qwLoadAddress = InterlockedAdd64(&g_PDB_qwLoadAddressNext, VMMWIN_PDB_LOAD_ADDRESS_STEP);
        pPdbEntry->qwLoadAddress = ctx->mspdb.pfn.SymLoadModuleEx(ctx->mspdb.hSym, NULL, szPdbPath, NULL, qwLoadAddress, pPdbEntry->cbModuleSize, NULL, 0);
    }
#endif /* _WIN32 */
    if(ctx->crust.fValid) {
        pPdbEntry->qwLoadAddress = (QWORD)ctx->crust.pfn.pdbcrust_open(szPdbPath);
    }
    if(!pPdbEntry->szPath || !pPdbEntry->qwLoadAddress) { goto fail; }
    return TRUE;
fail:
    pPdbEntry->fLoadFailed = TRUE;
    return FALSE;
}

/*
* Ensure that the PDB_HANDLE have its symbols loaded into memory.
* -- H
* -- hPDB
* -- return
*/
_Success_(return)
BOOL PDB_LoadEnsure(_In_ VMM_HANDLE H, _In_opt_ PDB_HANDLE hPDB)
{
    POB_PDB_CONTEXT ctxOb = PDB_GetContext(H);
    PPDB_ENTRY pObPdbEntry = NULL;
    BOOL fResult = FALSE;
    if(!ctxOb || ctxOb->fDisabled) { goto fail; }
    if(!(hPDB = PDB_GetHandleFromHandleMagic(H, hPDB))) { goto fail; }
    if(!(pObPdbEntry = ObMap_GetByKey(ctxOb->pmPdbByHash, hPDB))) { goto fail; }
    EnterCriticalSection(&ctxOb->Lock);
    fResult = PDB_LoadEnsureEx(H, ctxOb, pObPdbEntry);
    LeaveCriticalSection(&ctxOb->Lock);
fail:
    Ob_DECREF(pObPdbEntry);
    Ob_DECREF(ctxOb);
    return fResult;
}

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
BOOL PDB_GetModuleInfo(_In_ VMM_HANDLE H, _In_opt_ PDB_HANDLE hPDB, _Out_writes_opt_(MAX_PATH) LPSTR szModuleName, _Out_opt_ PQWORD pvaModuleBase, _Out_opt_ PDWORD pcbModuleSize)
{
    POB_PDB_CONTEXT ctxOb = PDB_GetContext(H);
    PPDB_ENTRY pObPdbEntry = NULL;
    BOOL fResult = FALSE;
    if(!ctxOb || ctxOb->fDisabled) { goto fail; }
    if(!(hPDB = PDB_GetHandleFromHandleMagic(H, hPDB))) { goto fail; }
    if(!(pObPdbEntry = ObMap_GetByKey(ctxOb->pmPdbByHash, hPDB))) { goto fail; }
    if(szModuleName) {
        strncpy_s(szModuleName, MAX_PATH, pObPdbEntry->szModuleName, MAX_PATH - 1);
    }
    if(pvaModuleBase) {
        *pvaModuleBase = pObPdbEntry->vaModuleBase;
    }
    if(pcbModuleSize) {
        *pcbModuleSize = pObPdbEntry->cbModuleSize;
    }
    fResult = TRUE;
fail:
    Ob_DECREF(pObPdbEntry);
    Ob_DECREF(ctxOb);
    return fResult;
}

#ifdef _WIN32
/*
* Callback function for PDB_GetSymbolOffset() / SymEnumSymbols()
*/
BOOL PDB_GetSymbolOffset_Callback(_In_ PSYMBOL_INFO pSymInfo, _In_ ULONG SymbolSize, _In_ PDWORD pdwSymbolOffset)
{
    if(pSymInfo->Address - pSymInfo->ModBase < 0x10000000) {
        *pdwSymbolOffset = (DWORD)(pSymInfo->Address - pSymInfo->ModBase);
    }
    return FALSE;
}
#endif /* _WIN32 */

/*
* Query the PDB for the offset of a symbol.
* -- H
* -- hPDB
* -- szSymbolName
* -- pdwSymbolOffset
* -- return
*/
_Success_(return)
BOOL PDB_GetSymbolOffset(_In_ VMM_HANDLE H, _In_opt_ PDB_HANDLE hPDB, _In_ LPCSTR szSymbolName, _Out_ PDWORD pdwSymbolOffset)
{
    POB_PDB_CONTEXT ctxOb = PDB_GetContext(H);
    PPDB_ENTRY pObPdbEntry = NULL;
    *pdwSymbolOffset = 0;
    if(PDB_InfoDB_SymbolOffset(H, hPDB, szSymbolName, pdwSymbolOffset)) { Ob_DECREF(ctxOb); return TRUE; }
    if(!ctxOb || ctxOb->fDisabled) { goto fail; }
    if(!(hPDB = PDB_GetHandleFromHandleMagic(H, hPDB))) { goto fail; }
    if(!(pObPdbEntry = ObMap_GetByKey(ctxOb->pmPdbByHash, hPDB))) { goto fail; }
    EnterCriticalSection(&ctxOb->Lock);
    if(PDB_LoadEnsureEx(H, ctxOb, pObPdbEntry)) {
#ifdef _WIN32
        SYMBOL_INFO SymbolInfo = { 0 };
        if(ctxOb->mspdb.fValid) {
            if(!H->vmm.f32) {
                // 64-bit: use faster algo
                SymbolInfo.SizeOfStruct = sizeof(SYMBOL_INFO);
                if(ctxOb->mspdb.pfn.SymGetTypeFromName(ctxOb->mspdb.hSym, pObPdbEntry->qwLoadAddress, szSymbolName, &SymbolInfo)) {
                    *pdwSymbolOffset = (DWORD)(SymbolInfo.Address - SymbolInfo.ModBase);
                }
            }
            if(0 == *pdwSymbolOffset) {
                // 32-bit & 64-bit fallback: use slower algo since it's working ...
                ctxOb->mspdb.pfn.SymEnumSymbols(ctxOb->mspdb.hSym, pObPdbEntry->qwLoadAddress, szSymbolName, (PSYM_ENUMERATESYMBOLS_CALLBACK)PDB_GetSymbolOffset_Callback, pdwSymbolOffset);
            }
        }
#endif /* _WIN32 */
        if(ctxOb->crust.fValid) {
            *pdwSymbolOffset = (DWORD)ctxOb->crust.pfn.pdbcrust_symbol_offset((SIZE_T)pObPdbEntry->qwLoadAddress, szSymbolName);
        }
    }
    LeaveCriticalSection(&ctxOb->Lock);
fail:
    Ob_DECREF(pObPdbEntry);
    Ob_DECREF(ctxOb);
    return *pdwSymbolOffset ? TRUE : FALSE;
}

/*
* Query the PDB for the offset of a symbol and return its virtual address. If
* szSymbolName contains wildcard '?*' characters and matches multiple symbols
* the virtual address of the 1st symbol is returned.
* -- H
* -- hPDB
* -- szSymbolName = wildcard symbol name
* -- pvaSymbolAddress
* -- return
*/
_Success_(return)
BOOL PDB_GetSymbolAddress(_In_ VMM_HANDLE H, _In_opt_ PDB_HANDLE hPDB, _In_ LPCSTR szSymbolName, _Out_ PQWORD pvaSymbolAddress)
{
    POB_PDB_CONTEXT ctxOb = PDB_GetContext(H);
    PPDB_ENTRY pObPdbEntry = NULL;
    DWORD cbSymbolOffset;
    BOOL fResult = FALSE;
    if(!PDB_GetSymbolOffset(H, hPDB, szSymbolName, &cbSymbolOffset)) { goto fail; }
    if(hPDB == PDB_HANDLE_KERNEL) {
        *pvaSymbolAddress = H->vmm.kernel.vaBase + cbSymbolOffset;
    } else {
        if(!ctxOb || ctxOb->fDisabled) { goto fail; }
        if(!(hPDB = PDB_GetHandleFromHandleMagic(H, hPDB))) { goto fail; }
        if(!(pObPdbEntry = ObMap_GetByKey(ctxOb->pmPdbByHash, hPDB))) { goto fail; }
        *pvaSymbolAddress = pObPdbEntry->vaModuleBase + cbSymbolOffset;
    }
    fResult = TRUE;
fail:
    Ob_DECREF(pObPdbEntry);
    Ob_DECREF(ctxOb);
    return fResult;
}

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
BOOL PDB_GetSymbolFromOffset(_In_ VMM_HANDLE H, _In_opt_ PDB_HANDLE hPDB, _In_ DWORD dwSymbolOffset, _Out_writes_opt_(MAX_PATH) LPSTR szSymbolName, _Out_opt_ PDWORD pdwSymbolDisplacement)
{
    POB_PDB_CONTEXT ctxOb = PDB_GetContext(H);
    QWORD cch, qwDisplacement;
    PPDB_ENTRY pObPdbEntry = NULL;
    BOOL fResult = FALSE;
    if(!ctxOb || ctxOb->fDisabled) { goto fail; }
    if(!(hPDB = PDB_GetHandleFromHandleMagic(H, hPDB))) { goto fail; }
    if(!(pObPdbEntry = ObMap_GetByKey(ctxOb->pmPdbByHash, hPDB))) { goto fail; }
    EnterCriticalSection(&ctxOb->Lock);
    if(PDB_LoadEnsureEx(H, ctxOb, pObPdbEntry)) {
#ifdef _WIN32
        if(ctxOb->mspdb.fValid) {
            SYMBOL_INFO_PACKAGE SymbolInfo = { 0 };
            SymbolInfo.si.SizeOfStruct = sizeof(SYMBOL_INFO);
            SymbolInfo.si.MaxNameLen = MAX_SYM_NAME;
            if(ctxOb->mspdb.pfn.SymFromAddr(ctxOb->mspdb.hSym, pObPdbEntry->qwLoadAddress + dwSymbolOffset, &qwDisplacement, &SymbolInfo.si)) {
                if(szSymbolName) {
                    cch = min(MAX_PATH - 1, SymbolInfo.si.NameLen);
                    memcpy(szSymbolName, SymbolInfo.si.Name, (SIZE_T)cch);
                    szSymbolName[cch] = 0;
                }
                if(pdwSymbolDisplacement) {
                    *pdwSymbolDisplacement = (DWORD)qwDisplacement;
                }
                fResult = TRUE;
            }
        }
#endif /* _WIN32 */
        if(!fResult && ctxOb->crust.fValid) {
            fResult = ctxOb->crust.pfn.pdbcrust_symbol_name_from_offset((SIZE_T)pObPdbEntry->qwLoadAddress, dwSymbolOffset, MAX_PATH, szSymbolName, pdwSymbolDisplacement);
        }
    }
    LeaveCriticalSection(&ctxOb->Lock);
fail:
    Ob_DECREF(pObPdbEntry);
    Ob_DECREF(ctxOb);
    return fResult;
}

/*
* Read memory at the PDB acquired symbol offset. If szSymbolName contains
* wildcard '?*' characters and matches multiple symbols the offset of the
* 1st symbol is used to read the memory.
* -- H
* -- hPDB
* -- szSymbolName = wildcard symbol name
* -- pProcess
* -- pb
* -- cb
* -- return
*/
_Success_(return)
BOOL PDB_GetSymbolPBYTE(_In_ VMM_HANDLE H, _In_opt_ PDB_HANDLE hPDB, _In_ LPCSTR szSymbolName, _In_ PVMM_PROCESS pProcess, _Out_writes_(cb) PBYTE pb, _In_ DWORD cb)
{
    POB_PDB_CONTEXT ctxOb = PDB_GetContext(H);
    PPDB_ENTRY pObPdbEntry = NULL;
    DWORD dwSymbolOffset;
    QWORD va;
    BOOL fResult = FALSE;
    if(!PDB_GetSymbolOffset(H, hPDB, szSymbolName, &dwSymbolOffset)) { goto fail; }
    if(hPDB == PDB_HANDLE_KERNEL) {
        va = H->vmm.kernel.vaBase + dwSymbolOffset;
    } else {
        if(!ctxOb || ctxOb->fDisabled) { goto fail; }
        if(!(hPDB = PDB_GetHandleFromHandleMagic(H, hPDB))) { goto fail; }
        if(!(pObPdbEntry = ObMap_GetByKey(ctxOb->pmPdbByHash, hPDB))) { goto fail; }
        va = pObPdbEntry->vaModuleBase + dwSymbolOffset;
    }
    fResult = VmmRead(H, pProcess, va, pb, cb);
fail:
    Ob_DECREF(pObPdbEntry);
    Ob_DECREF(ctxOb);
    return fResult;
}

/*
* Query the PDB for the size of a type. If szTypeName contains wildcard '?*'
* characters and matches multiple types the size of the 1st type is returned.
* -- H
* -- hPDB
* -- szTypeName = wildcard type name
* -- pdwTypeSize
* -- return
*/
_Success_(return)
BOOL PDB_GetTypeSize_Internal(_In_ VMM_HANDLE H, _In_opt_ PDB_HANDLE hPDB, _In_ LPCSTR szTypeName, _Out_ PDWORD pdwTypeSize)
{
    POB_PDB_CONTEXT ctxOb = PDB_GetContext(H);
    PPDB_ENTRY pObPdbEntry = NULL;
    BOOL fResult = FALSE;
    if(!ctxOb || ctxOb->fDisabled) { goto fail; }
    if(!(hPDB = PDB_GetHandleFromHandleMagic(H, hPDB))) { goto fail; }
    if(!(pObPdbEntry = ObMap_GetByKey(ctxOb->pmPdbByHash, hPDB))) { goto fail; }
    EnterCriticalSection(&ctxOb->Lock);
    if(PDB_LoadEnsureEx(H, ctxOb, pObPdbEntry)) {
#ifdef _WIN32
        if(ctxOb->mspdb.fValid) {
            SYMBOL_INFO SymbolInfo = { 0 };
            SymbolInfo.SizeOfStruct = sizeof(SYMBOL_INFO);
            fResult = ctxOb->mspdb.pfn.SymGetTypeFromName(ctxOb->mspdb.hSym, pObPdbEntry->qwLoadAddress, szTypeName, &SymbolInfo) && SymbolInfo.Size;
            *pdwTypeSize = SymbolInfo.Size;
        }
#endif /* _WIN32 */
        if(!fResult && ctxOb->crust.fValid) {
            *pdwTypeSize = ctxOb->crust.pfn.pdbcrust_type_size((DWORD)pObPdbEntry->qwLoadAddress, szTypeName);
            fResult = *pdwTypeSize != 0;
        }
    }
    LeaveCriticalSection(&ctxOb->Lock);
fail:
    Ob_DECREF(pObPdbEntry);
    Ob_DECREF(ctxOb);
    return fResult;
}

/*
* Query the PDB for the size of a type. If szTypeName contains wildcard '?*'
* characters and matches multiple types the size of the 1st type is returned.
* -- H
* -- hPDB
* -- szTypeName = wildcard type name
* -- pdwTypeSize
* -- return
*/
_Success_(return)
BOOL PDB_GetTypeSize(_In_ VMM_HANDLE H, _In_opt_ PDB_HANDLE hPDB, _In_ LPCSTR szTypeName, _Out_ PDWORD pdwTypeSize)
{
    // lookup hierarchy (1): InfoDB dynamic (cached pdb), (2): Full PDB, (3): InfoDB static (build# based).
    return
        PDB_InfoDB_TypeSize(H, hPDB, szTypeName, pdwTypeSize, TRUE) ||
        PDB_GetTypeSize_Internal(H, hPDB, szTypeName, pdwTypeSize) ||
        PDB_InfoDB_TypeSize(H, hPDB, szTypeName, pdwTypeSize, FALSE);
}

_Success_(return)
BOOL PDB_GetTypeSizeShort(_In_ VMM_HANDLE H, _In_opt_ PDB_HANDLE hPDB, _In_ LPCSTR szTypeName, _Out_ PWORD pwTypeSize)
{
    DWORD dwTypeSize;
    if(!PDB_GetTypeSize(H, hPDB, szTypeName, &dwTypeSize) || (dwTypeSize > 0xffff)) { return FALSE; }
    if(pwTypeSize) { *pwTypeSize = (WORD)dwTypeSize; }
    return TRUE;
}

#ifdef _WIN32

/*
* Callback function for PDB_GetTypeChildOffset()
*/
BOOL WINAPI PDB_GetTypeChildOffset_MSPDB_Callback(_In_ PSYMBOL_INFO pSymInfo, _In_ ULONG SymbolSize, _In_ PDWORD pdwTypeId)
{
    *pdwTypeId = pSymInfo->Index;
    pSymInfo->Index;
    return FALSE;
}

_Success_(return)
BOOL PDB_GetTypeChildOffset_MSPDB_Internal(_In_ VMM_HANDLE H, _In_ POB_PDB_CONTEXT ctx, _In_ PPDB_ENTRY pPdbEntry, _In_ LPCSTR szTypeName, _In_ LPCSTR uszTypeChildName, _Out_ PDWORD pdwTypeOffset)
{
    BOOL fResult = FALSE;
    LPWSTR wszTypeChildSymName;
    LPSTR uszTypeChildSymName;
    BYTE pbBuffer[MAX_PATH];
    DWORD dwTypeId, cTypeChildren, iTypeChild;
    TI_FINDCHILDREN_PARAMS *pFindChildren = NULL;
    if(!ctx->mspdb.fValid) { goto fail; }
    if(!ctx->mspdb.pfn.SymEnumTypesByName(ctx->mspdb.hSym, pPdbEntry->qwLoadAddress, szTypeName, (PSYM_ENUMERATESYMBOLS_CALLBACK)PDB_GetTypeChildOffset_MSPDB_Callback, &dwTypeId) || !dwTypeId) { goto fail; }
    if(!ctx->mspdb.pfn.SymGetTypeInfo(ctx->mspdb.hSym, pPdbEntry->qwLoadAddress, dwTypeId, TI_GET_CHILDRENCOUNT, &cTypeChildren) || !cTypeChildren) { goto fail; }
    if(!(pFindChildren = LocalAlloc(LMEM_ZEROINIT, sizeof(TI_FINDCHILDREN_PARAMS) + cTypeChildren * sizeof(ULONG)))) { goto fail; }
    pFindChildren->Count = cTypeChildren;
    if(!ctx->mspdb.pfn.SymGetTypeInfo(ctx->mspdb.hSym, pPdbEntry->qwLoadAddress, dwTypeId, TI_FINDCHILDREN, pFindChildren)) { goto fail; }
    for(iTypeChild = 0; iTypeChild < cTypeChildren; iTypeChild++) {
        if(!ctx->mspdb.pfn.SymGetTypeInfo(ctx->mspdb.hSym, pPdbEntry->qwLoadAddress, pFindChildren->ChildId[iTypeChild], TI_GET_SYMNAME, &wszTypeChildSymName)) { continue; }
        if(CharUtil_WtoU(wszTypeChildSymName, -1, pbBuffer, sizeof(pbBuffer), &uszTypeChildSymName, NULL, 0) && !strcmp(uszTypeChildName, uszTypeChildSymName)) {
            if(ctx->mspdb.pfn.SymGetTypeInfo(ctx->mspdb.hSym, pPdbEntry->qwLoadAddress, pFindChildren->ChildId[iTypeChild], TI_GET_OFFSET, pdwTypeOffset)) {
                LocalFree(wszTypeChildSymName);
                fResult = TRUE;
                break;
            }
        }
        LocalFree(wszTypeChildSymName);
    }
fail:
    LocalFree(pFindChildren);
    return fResult;
}

#else

_Success_(return)
BOOL PDB_GetTypeChildOffset_MSPDB_Internal(_In_ VMM_HANDLE H, _In_ POB_PDB_CONTEXT ctx, _In_ PPDB_ENTRY pPdbEntry, _In_ LPCSTR szTypeName, _In_ LPCSTR uszTypeChildName, _Out_ PDWORD pdwTypeOffset)
{
    return FALSE;
}

#endif /* _WIN32 */

/*
* Query the PDB for the offset of a child inside a type - often inside a struct.
* -- H
* -- hPDB
* -- szTypeName = wildcard type name.
* -- uszTypeChildName = exact match of child name.
* -- pdwTypeOffset = offset relative to type base.
* -- return
*/
_Success_(return)
BOOL PDB_GetTypeChildOffset_Internal(_In_ VMM_HANDLE H, _In_opt_ PDB_HANDLE hPDB, _In_ LPCSTR szTypeName, _In_ LPCSTR uszTypeChildName, _Out_ PDWORD pdwTypeOffset)
{
    POB_PDB_CONTEXT ctxOb = PDB_GetContext(H);
    BOOL fResult = FALSE;
    PPDB_ENTRY pObPdbEntry = NULL;
    if(!ctxOb || ctxOb->fDisabled) { goto fail; }
    if(!(hPDB = PDB_GetHandleFromHandleMagic(H, hPDB))) { goto fail; }
    if(!(pObPdbEntry = ObMap_GetByKey(ctxOb->pmPdbByHash, hPDB))) { goto fail; }
    EnterCriticalSection(&ctxOb->Lock);
    if(!PDB_LoadEnsureEx(H, ctxOb, pObPdbEntry)) { goto fail_lock; }
    fResult = PDB_GetTypeChildOffset_MSPDB_Internal(H, ctxOb, pObPdbEntry, szTypeName, uszTypeChildName, pdwTypeOffset);
    if(!fResult && ctxOb->crust.fValid) {
        fResult = ctxOb->crust.pfn.pdbcrust_type_child_offset((DWORD)pObPdbEntry->qwLoadAddress, szTypeName, uszTypeChildName, pdwTypeOffset);
    }
fail_lock:
    LeaveCriticalSection(&ctxOb->Lock);
fail:
    Ob_DECREF(pObPdbEntry);
    Ob_DECREF(ctxOb);
    return fResult;
}

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
BOOL PDB_GetTypeChildOffset(_In_ VMM_HANDLE H, _In_opt_ PDB_HANDLE hPDB, _In_ LPCSTR szTypeName, _In_ LPCSTR uszTypeChildName, _Out_ PDWORD pdwTypeOffset)
{
    // lookup hierarchy (1): InfoDB dynamic (cached pdb), (2): Full PDB, (3): InfoDB static (build# based).
    return
        PDB_InfoDB_TypeChildOffset(H, hPDB, szTypeName, uszTypeChildName, pdwTypeOffset, TRUE) ||
        PDB_GetTypeChildOffset_Internal(H, hPDB, szTypeName, uszTypeChildName, pdwTypeOffset) ||
        PDB_InfoDB_TypeChildOffset(H, hPDB, szTypeName, uszTypeChildName, pdwTypeOffset, FALSE);
}

_Success_(return)
BOOL PDB_GetTypeChildOffsetShort(_In_ VMM_HANDLE H, _In_opt_ PDB_HANDLE hPDB, _In_ LPCSTR szTypeName, _In_ LPCSTR uszTypeChildName, _Out_ PWORD pwTypeOffset)
{
    DWORD dwTypeOffset;
    if(!PDB_GetTypeChildOffset(H, hPDB, szTypeName, uszTypeChildName, &dwTypeOffset) || (dwTypeOffset > 0xffff)) { return FALSE; }
    if(pwTypeOffset) { *pwTypeOffset = (WORD)dwTypeOffset; }
    return TRUE;
}



//-----------------------------------------------------------------------------
// INITIALIZATION/REFRESH/CLOSE FUNCTIONALITY BELOW:
//-----------------------------------------------------------------------------

/*
* Cleanup the PDB sub-system. This should ideally be done on Vmm Close().
*/
VOID PDB_Close(_In_ VMM_HANDLE H)
{
    Ob_DECREF_NULL(&H->vmm.pObPdbContext);
    H->pdb.fInitialized = FALSE;
}

/*
* 
*/
_Success_(return)
BOOL PDB_Initialize_Async_Kernel_ScanForPdbInfo(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pSystemProcess, _Out_ PPE_CODEVIEW_INFO pCodeViewInfo)
{
    PBYTE pb = NULL;
    DWORD i, cbRead;
    PPE_CODEVIEW pPdb;
    ZeroMemory(pCodeViewInfo, sizeof(PE_CODEVIEW_INFO));
    if(!H->vmm.kernel.vaBase) { return FALSE; }
    if(!(pb = LocalAlloc(0, 0x00800000))) { return FALSE; }
    VmmReadEx(H, pSystemProcess, H->vmm.kernel.vaBase, pb, 0x00800000, &cbRead, VMM_FLAG_ZEROPAD_ON_FAIL);
    // 1: search for pdb debug information adn extract offset of PsInitialSystemProcess
    for(i = 0; i < 0x00800000 - sizeof(PE_CODEVIEW); i += 4) {
        pPdb = (PPE_CODEVIEW)(pb + i);
        if(pPdb->Signature == 0x53445352) {
            if(pPdb->Age > 0x20) { continue; }
            if(memcmp("nt", pPdb->PdbFileName, 2)) { continue; }
            if(memcmp(".pdb", pPdb->PdbFileName + 8, 5)) { continue; }
            pCodeViewInfo->SizeCodeView = 4 + 16 + 4 + 12;
            pCodeViewInfo->CodeView.Signature = pPdb->Signature;
            memcpy(pCodeViewInfo->CodeView.Guid, pPdb->Guid, 16);
            pCodeViewInfo->CodeView.Age = pPdb->Age;
            memcpy(pCodeViewInfo->CodeView.PdbFileName, pPdb->PdbFileName, 12);
            LocalFree(pb);
            return TRUE;
        }
    }
    LocalFree(pb);
    return FALSE;
}

VOID PDB_Initialize_WaitComplete(_In_ VMM_HANDLE H)
{
    POB_PDB_CONTEXT ctxOb = PDB_GetContext(H);
    if(ctxOb && H->pdb.fEnable) {
        EnterCriticalSection(&ctxOb->Lock);
        LeaveCriticalSection(&ctxOb->Lock);
    }
    Ob_DECREF(ctxOb);
}

/*
* Asynchronous initialization of the PDB for the kernel. This is done async
* since it may take some time to load the PDB from the Microsoft Symbol server.
* Once this initializtion is successfully completed the fDisabled flag will be
* removed - allowing other threads to use the PDB subsystem.
* If the initialization fails it's assume the PDB system should be disabled.
* -- H
* -- pKernelParameters
*/
VOID PDB_Initialize_Async_Kernel_ThreadProc(_In_ VMM_HANDLE H, _In_ POB_PDB_INITIALIZE_KERNEL_PARAMETERS pKernelParameters)
{
    POB_PDB_CONTEXT ctxOb = PDB_GetContext(H);
    DWORD dwReturnStatus = 0;
    PVMM_PROCESS pObSystemProcess = NULL;
    PPDB_ENTRY pObKernelEntry = NULL;
    QWORD qwPdbHash;
    if(!ctxOb) { return; }
    EnterCriticalSection(&ctxOb->Lock);
    SetEvent(*pKernelParameters->phEventThreadStarted);
    if(!(pObSystemProcess = VmmProcessGet(H, 4))) { goto fail; }
    pKernelParameters->fPdbInfo = pKernelParameters->fPdbInfo ||
        PE_GetCodeViewInfo(H, pObSystemProcess, H->vmm.kernel.vaBase, NULL, &pKernelParameters->PdbInfo) ||
        PDB_Initialize_Async_Kernel_ScanForPdbInfo(H, pObSystemProcess, &pKernelParameters->PdbInfo);
    if(!pKernelParameters->fPdbInfo) {
        PDB_PrintError(H, "Reason: Unable to locate debugging information in kernel image.", NULL);
        goto fail;
    }
    qwPdbHash = PDB_AddModuleEntry(H, H->vmm.kernel.vaBase, (DWORD)H->vmm.kernel.cbSize, "ntoskrnl", pKernelParameters->PdbInfo.CodeView.PdbFileName, pKernelParameters->PdbInfo.CodeView.Guid, pKernelParameters->PdbInfo.CodeView.Age);
    pObKernelEntry = ObMap_GetByKey(ctxOb->pmPdbByHash, qwPdbHash);
    if(!pObKernelEntry) {
        PDB_PrintError(H, "Reason: Failed creating initial PDB entry.", NULL);
        goto fail;
    }
    if(!PDB_LoadEnsureEx(H, ctxOb, pObKernelEntry)) {
        PDB_PrintError(H, "Reason: Unable to download kernel symbols to cache from Symbol Server.", NULL);
        goto fail;
    }
    VmmLog(H, MID_SYMBOL, LOGLEVEL_DEBUG, "Initialization of debug symbol .pdb functionality completed");
    VmmLog(H, MID_SYMBOL, LOGLEVEL_DEBUG, "[ %s ]", H->pdb.szSymbolPath);
    ctxOb->fDisabled = FALSE;
    // fall-through to fail for cleanup
fail:
    LeaveCriticalSection(&ctxOb->Lock);
    Ob_DECREF(pObKernelEntry);
    Ob_DECREF(pObSystemProcess);
    Ob_DECREF(ctxOb);
}



//-----------------------------------------------------------------------------
// INITIALIZATION FUNCTIONALITY BELOW:
// Initialization may take place using either:
// - MSPDB: Microsoft debug libraries (Windows only).
// - PDBCRust: C-wrapper library for the rust PDB crate (Windows & Linux).
//-----------------------------------------------------------------------------

#ifdef _WIN32

VOID PDB_Initialize_InitialValues(_In_ VMM_HANDLE H)
{
    DWORD dwEnableSymbols, dwEnableSymbolServer;
    // 1: try load values from registry
    if(!H->pdb.fInitialized) {
        H->pdb.fEnable = 1;
        H->pdb.fServerEnable = !H->cfg.fDisableSymbolServerOnStartup;
    }
    H->pdb.szLocal[0] = 0;
    H->pdb.szServer[0] = 0;
    dwEnableSymbols = H->pdb.fEnable ? 1 : 0;
    dwEnableSymbolServer = H->pdb.fServerEnable ? 1 : 0;
    if(!VmmUserConfig_GetString("SymbolCache", sizeof(H->pdb.szLocal), H->pdb.szLocal)) { H->pdb.szLocal[0] = 0; }
    if(!VmmUserConfig_GetString("SymbolServer", sizeof(H->pdb.szServer), H->pdb.szServer)) { H->pdb.szServer[0] = 0; }
    if(H->pdb.fEnable) {
        VmmUserConfig_GetNumber("SymbolEnable", &dwEnableSymbols);
    }
    if(H->pdb.fServerEnable) {
        VmmUserConfig_GetNumber("SymbolServerEnable", &dwEnableSymbolServer);
    }
    // 2: set default values (if not already loaded from registry)
    if(!H->pdb.szLocal[0]) {
        Util_GetPathLib(H->pdb.szLocal);
        strncat_s(H->pdb.szLocal, _countof(H->pdb.szLocal), "Symbols", _TRUNCATE);
    }
    if(!H->pdb.szServer[0]) {
        strncpy_s(H->pdb.szServer, _countof(H->pdb.szServer), "https://msdl.microsoft.com/download/symbols", _TRUNCATE);
    }
    // 3: set final values
    H->pdb.fEnable = (dwEnableSymbols == 1);
    H->pdb.fServerEnable = (dwEnableSymbolServer == 1);
    strncpy_s(H->pdb.szSymbolPath, _countof(H->pdb.szSymbolPath), "srv*", _TRUNCATE);
    strncat_s(H->pdb.szSymbolPath, _countof(H->pdb.szSymbolPath), H->pdb.szLocal, _TRUNCATE);
    if(H->pdb.fServerEnable) {
        strncat_s(H->pdb.szSymbolPath, _countof(H->pdb.szSymbolPath), "*", _TRUNCATE);
        strncat_s(H->pdb.szSymbolPath, _countof(H->pdb.szSymbolPath), H->pdb.szServer, _TRUNCATE);
    }
    H->pdb.fInitialized = TRUE;
}

/*
* Update the PDB configuration. The PDB syb-system will be reloaded on
* configuration changes - which may cause a short interruption for any
* caller.
* -- H
*/
VOID PDB_ConfigChange(_In_ VMM_HANDLE H)
{
    CHAR szLocalPath[MAX_PATH] = { 0 };
    if(H->cfg.fDisableSymbols) {
        VmmLog(H, MID_SYMBOL, LOGLEVEL_INFO, "Debug symbols disabled by user");
        return;
    }
    // update new values in registry
    Util_GetPathLib(szLocalPath);
    if(strncmp(szLocalPath, H->pdb.szLocal, strlen(szLocalPath) - 1) && !_access_s(H->pdb.szLocal, 06)) {
        VmmUserConfig_SetString("SymbolCache", H->pdb.szLocal);
    } else {
        VmmUserConfig_Delete("SymbolCache");
    }
    if((!strncmp("http://", H->pdb.szServer, 7) || !strncmp("https://", H->pdb.szServer, 8)) && !strstr(H->pdb.szServer, "msdl.microsoft.com")) {
        VmmUserConfig_SetString("SymbolServer", H->pdb.szServer);
    } else {
        VmmUserConfig_Delete("SymbolServer");
    }
    // refresh values and reload!
    EnterCriticalSection(&H->vmm.LockMaster);
    PDB_Close(H);
    PDB_Initialize(H, NULL, FALSE);
    LeaveCriticalSection(&H->vmm.LockMaster);
}

#endif /* _WIN32 */
#if defined(LINUX) || defined(MACOS)

/*
* PDB config changes have no meaning on Linux.
*/
VOID PDB_ConfigChange(_In_ VMM_HANDLE H)
{
    return;
}

VOID PDB_Initialize_InitialValues(_In_ VMM_HANDLE H)
{
    if(!H->pdb.fInitialized) {
        H->pdb.fEnable = 1;
        H->pdb.fServerEnable = !H->cfg.fDisableSymbolServerOnStartup;
    }
    H->pdb.szLocal[0] = 0;
    H->pdb.szServer[0] = 0;
    // 1: set symbol path to Symbol directory related to 'vmm.so'/'vmm.dylib' folder.
    Util_GetPathDll(H->pdb.szLocal, H->vmm.hModuleVmmOpt);
    strncat_s(H->pdb.szLocal, _countof(H->pdb.szLocal), "Symbols", _TRUNCATE);
    // 2: if directory is not writable - then use /tmp
    if(access(H->pdb.szLocal, W_OK)) {
        strncpy_s(H->pdb.szLocal, _countof(H->pdb.szLocal), "/tmp", _TRUNCATE);
    }
    // 3: set final values:
    H->pdb.fEnable = H->pdb.fEnable ? 1 : 0;
    H->pdb.fServerEnable = H->pdb.fServerEnable ? 1 : 0;
}

#endif /* LINUX || MACOS */

/*
* Initialize the PDB sub-system. This should ideally be done on Vmm Init().
* -- H
* -- pPdbInfoOpt
* -- fInitializeKernelAsync
*/
VOID PDB_Initialize(_In_ VMM_HANDLE H, _In_opt_ PPE_CODEVIEW_INFO pPdbInfoOpt, _In_ BOOL fInitializeKernelAsync)
{
    HANDLE hEventThreadStarted = 0;
    POB_PDB_CONTEXT ctx = NULL;
    DWORD i, dwSymOptions;
    BOOL fValidMSPDB = FALSE;
    LPSTR szErrorMSPDB = NULL;
    CHAR szPathLib[MAX_PATH];
    POB_PDB_INITIALIZE_KERNEL_PARAMETERS pObKernelParameters = NULL;
    // 1: General sanity checks and pre-initialization.
    if(H->pdb.fInitialized) {
        return;
    }
    if(H->cfg.fDisableSymbols) {
        VmmLog(H, MID_SYMBOL, LOGLEVEL_INFO, "Debug symbols disabled by user");
        return;
    }
    PDB_Initialize_InitialValues(H);
    if(!H->pdb.fEnable) {
        return;
    }
    if(!(ctx = Ob_AllocEx(H, OB_TAG_PDB_CTX, LMEM_ZEROINIT, sizeof(OB_PDB_CONTEXT), (OB_CLEANUP_CB)PDB_CallbackCleanup_ObPdbContext, NULL))) { goto fail; }
    if(!(ctx->pmPdbByHash = ObMap_New(H, OB_MAP_FLAGS_OBJECT_OB))) { goto fail; }
    if(!(ctx->pmPdbByModule = ObMap_New(H, OB_MAP_FLAGS_OBJECT_OB))) { goto fail; }
#ifdef _WIN32
    // 2.1: Try initialize pdb subsystem using the microsoft dbghelp.dll/symsrv.dll files.
    //      this only possible to do on windows.
    //      If initialization fail the rust library will be tried as a fallback instead.
    CHAR szPathSymSrv[MAX_PATH], szPathDbgHelp[MAX_PATH];
    Util_GetPathLib(szPathSymSrv);
    Util_GetPathLib(szPathDbgHelp);
    strncat_s(szPathSymSrv, MAX_PATH, "symsrv.dll", _TRUNCATE);
    strncat_s(szPathDbgHelp, MAX_PATH, "dbghelp.dll", _TRUNCATE);
    ctx->mspdb.hModuleSymSrv = LoadLibraryU(szPathSymSrv);
    ctx->mspdb.hModuleDbgHelp = LoadLibraryU(szPathDbgHelp);
    if(!ctx->mspdb.hModuleSymSrv || !ctx->mspdb.hModuleDbgHelp) {
        szErrorMSPDB = "Reason: Could not load PDB required file - symsrv.dll/dbghelp.dll.";
        goto fail_mspdb;
    }
    for(i = 0; i < sizeof(MSPDB_PDB_FUNCTIONS) / sizeof(PVOID); i++) {
        ctx->mspdb.vafn[i] = GetProcAddress(ctx->mspdb.hModuleDbgHelp, szMSPDB_PDB_FUNCTIONS[i]);
        if(!ctx->mspdb.vafn[i]) {
            szErrorMSPDB = "Reason: Could not load functions from symsrv.dll/dbghelp.dll.";
            goto fail_mspdb;
        }
    }
    // 2.2: Initialize dbghelp.dll
    ctx->mspdb.hSym = (HANDLE)H;                      // fake handle - set this to H
    dwSymOptions = ctx->mspdb.pfn.SymGetOptions();
    dwSymOptions &= ~SYMOPT_DEFERRED_LOADS;
    dwSymOptions &= ~SYMOPT_LOAD_LINES;
    dwSymOptions |= SYMOPT_CASE_INSENSITIVE;
    dwSymOptions |= SYMOPT_IGNORE_NT_SYMPATH;
    dwSymOptions |= SYMOPT_UNDNAME;
    ctx->mspdb.pfn.SymSetOptions(dwSymOptions);
    if(!ctx->mspdb.pfn.SymInitialize(ctx->mspdb.hSym, H->pdb.szSymbolPath, FALSE)) {
        szErrorMSPDB = "Reason: Failed to initialize Symbol Handler / dbghelp.dll.";
        ctx->mspdb.hSym = NULL;
    }
    fValidMSPDB = TRUE;
fail_mspdb:
#endif /* _WIN32 */
    // 3: Try initialize pdb subsystem using the wrapper library pdbcrust around the rust pdb crate.
    //    This is only done if the MSPDB loading was not successful.
    if(!fValidMSPDB) {
        ZeroMemory(szPathLib, sizeof(szPathLib));
        Util_GetPathLib(szPathLib);
        strncat_s(szPathLib, MAX_PATH, "libpdbcrust"VMM_LIBRARY_FILETYPE, _TRUNCATE);
        ctx->crust.hModule = LoadLibraryU(szPathLib);
#ifndef _WIN32
        if(!ctx->crust.hModule) {
            ZeroMemory(szPathLib, sizeof(szPathLib));
            Util_GetPathLib(szPathLib);
            strncat_s(szPathLib, MAX_PATH, "libpdbcrust2"VMM_LIBRARY_FILETYPE, _TRUNCATE);
            ctx->crust.hModule = LoadLibraryU(szPathLib);
        }
#endif /* _WIN32 */
        if(!ctx->crust.hModule) {
            PDB_PrintError(H, "Reason: Could not load PDB required file - libpdbcrust"VMM_LIBRARY_FILETYPE".", szErrorMSPDB);
            goto fail;
        }
        for(i = 0; i < sizeof(CRUST_PDB_FUNCTIONS) / sizeof(PVOID); i++) {
            ctx->crust.vafn[i] = GetProcAddress(ctx->crust.hModule, szCRUST_PDB_FUNCTIONS[i]);
            if(!ctx->crust.vafn[i]) {
                PDB_PrintError(H, "Reason: Could not load functions from libpdbcrust"VMM_LIBRARY_FILETYPE".", szErrorMSPDB);
                goto fail;
            }
        }
        strncpy_s(H->pdb.szSymbolPath, _countof(H->pdb.szSymbolPath), H->pdb.szLocal, _TRUNCATE);
    }
    // 4: Success - finish up and load kernel .pdb async (to optimize startup time).
    //    PDB subsystem won't be fully initialized until before the kernel is loaded.
    if(!(hEventThreadStarted = CreateEvent(NULL, TRUE, FALSE, NULL))) { goto fail; }
    if(!(pObKernelParameters = Ob_AllocEx(H, OB_TAG_PDB_KERNEL_CONTEXT, LMEM_ZEROINIT, sizeof(OB_PDB_INITIALIZE_KERNEL_PARAMETERS), NULL, NULL))) { goto fail; }
    pObKernelParameters->phEventThreadStarted = &hEventThreadStarted;
    if(pPdbInfoOpt) {
        pObKernelParameters->fPdbInfo = TRUE;
        memcpy(&pObKernelParameters->PdbInfo, pPdbInfoOpt, sizeof(PE_CODEVIEW_INFO));
    }
    InitializeCriticalSection(&ctx->Lock);
    ctx->fDisabled = TRUE;
#ifdef _WIN32
    ctx->mspdb.fValid = fValidMSPDB;
#endif /* _WIN32 */
    ctx->crust.fValid = !fValidMSPDB;
    H->vmm.pObPdbContext = (POB)ctx;
    if(fInitializeKernelAsync) {
        VmmWork_Ob(H, (PVMM_WORK_START_ROUTINE_OB_PFN)PDB_Initialize_Async_Kernel_ThreadProc, (POB)pObKernelParameters, NULL, VMMWORK_FLAG_PRIO_NORMAL);
        WaitForSingleObject(hEventThreadStarted, 1000);  // wait for async thread initialize thread to start (and acquire PDB lock).
    } else {
        PDB_Initialize_Async_Kernel_ThreadProc(H, pObKernelParameters); // synchronous call
    }
    CloseHandle(hEventThreadStarted);
    Ob_DECREF(pObKernelParameters);
    VmmLog(H, MID_SYMBOL, LOGLEVEL_4_VERBOSE, "Initialized symbol subsystem (%s).", fValidMSPDB ? "Microsoft" : "Rust");
    return;
fail:
    if(hEventThreadStarted) { CloseHandle(hEventThreadStarted); }
    Ob_DECREF(pObKernelParameters);
    Ob_DECREF(ctx);
    H->pdb.fEnable = FALSE;
}



//-----------------------------------------------------------------------------
// DT - DISPLAY TYPE FUNCTIONALITY BELOW:
// The DisplayType functionality generates human readable type information for
// types in 'ntoskrnl.exe' only. The type information may optionally be decor-
// ated with values retrieved from memory.
//-----------------------------------------------------------------------------

#ifdef _WIN32

typedef struct tdPDB_DT_CONTEXT {
    HANDLE hSym;
    ULONG64 BaseOfDll;
    PMSPDB_PDB_FUNCTIONS pfn;
    LPSTR szu8;
    QWORD csz;
    QWORD cszMax;
    WCHAR wszln[MAX_PATH + 1];
    WCHAR wszBuffer[MAX_PATH + 1];
    BYTE iLevelMax;
} PDB_DT_CONTEXT, *PPDB_DT_CONTEXT;

typedef struct tdPDB_DT_INFO {
    LPWSTR wszName;
    LPWSTR wszTypeName;
    QWORD qwBitFieldLength;
    QWORD qwLength;
    DWORD dwTag;
    DWORD dwPtrTag;
    DWORD dwOffset;
    DWORD dwTypeIndex;
    DWORD dwBaseType;
    DWORD dwArrayCount;
    DWORD dwChildCount;
    DWORD dwPtrTypeIndex;
    DWORD dwArrayTypeIndex;
} PDB_DT_INFO, *PPDB_DT_INFO;

/*
* Retrieve the name of a type. I don't find this in a header so a lookup table it is...
*/
LPWSTR PDB_DisplayTypeNt_GetTypeName(_In_ PPDB_DT_INFO pDT, _In_ QWORD cbType)
{
    if(pDT->wszTypeName) { return pDT->wszTypeName; }
    switch(pDT->dwBaseType) {
        case 1: return L"void";
        case 2: return L"char";
        case 3: return L"wchar";
        case 8: return L"float";
        case 9: return L"bcd";
        case 10: return L"bool";
        case 25: return L"currency";
        case 26: return L"date";
        case 27: return L"variant";
        case 28: return L"complex";
        case 29: return L"bit";
        case 30: return L"BSTR";
        case 31: return L"HRESULT";
        case 6:
        case 13:
            switch(cbType) {
                case 1: return L"int8";
                case 2: return L"int16";
                case 4: return L"int32";
                case 8: return L"int64";
                default: return L"int??";
            }
        case 7:
        case 14:
            switch(cbType) {
                case 1: return L"byte";
                case 2: return L"word";
                case 4: return L"dword";
                case 8: return L"uint64";
                default: return L"uint??";
            }
        case -1: return L"function";
        case -2: return L"pointer";
        default: return L"???";
    }
}

/*
* Internal processing of a type - write result human readable data to a utf-8
* text buffer in the ctxDT context. This function makes multiple and possible
* also recursive lookups against dbghelp.dll.
*/
VOID PDB_DisplayTypeNt_DoWork(_In_ VMM_HANDLE H, _Inout_ PPDB_DT_CONTEXT ctxDT, _In_ BYTE iLevel, _In_ DWORD dwTypeIndex, _In_ DWORD dwChildCount, _In_ LPWSTR wszTypeName, _In_opt_ PBYTE pbMEM, _In_ DWORD cbMEM)
{
    static const IMAGEHLP_SYMBOL_TYPE_INFO _INFO1_ReqKinds[] = {
        TI_GET_SYMNAME,
        TI_GET_LENGTH,    // bit length in bit-fields
        TI_GET_OFFSET,
        TI_GET_TYPEID,
    };
    static const ULONG_PTR _INFO1_ReqOffsets[] = {
        offsetof(PDB_DT_INFO, wszName),
        offsetof(PDB_DT_INFO, qwBitFieldLength),
        offsetof(PDB_DT_INFO, dwOffset),
        offsetof(PDB_DT_INFO, dwTypeIndex),
    };
    static const ULONG _INFO1_ReqSizes[] = {
        sizeof(LPWSTR),
        sizeof(QWORD),
        sizeof(DWORD),
        sizeof(DWORD),
        sizeof(DWORD),
    };
    static const IMAGEHLP_SYMBOL_TYPE_INFO _INFO2_ReqKinds[] = {
        TI_GET_SYMNAME,
        TI_GET_LENGTH,
        TI_GET_SYMTAG,
        TI_GET_COUNT,
        TI_GET_CHILDRENCOUNT,
        TI_GET_TYPE,
        TI_GET_ARRAYINDEXTYPEID,
        TI_GET_BASETYPE,
    };
    static const ULONG_PTR _INFO2_ReqOffsets[] = {
        offsetof(PDB_DT_INFO, wszTypeName),
        offsetof(PDB_DT_INFO, qwLength),
        offsetof(PDB_DT_INFO, dwTag),
        offsetof(PDB_DT_INFO, dwArrayCount),
        offsetof(PDB_DT_INFO, dwChildCount),
        offsetof(PDB_DT_INFO, dwPtrTypeIndex),
        offsetof(PDB_DT_INFO, dwArrayTypeIndex),
        offsetof(PDB_DT_INFO, dwBaseType),
    };
    static const ULONG _INFO2_ReqSizes[] = {
        sizeof(LPWSTR),
        sizeof(QWORD),
        sizeof(DWORD),
        sizeof(DWORD),
        sizeof(DWORD),
        sizeof(DWORD),
        sizeof(DWORD),
        sizeof(DWORD),
    };
    IMAGEHLP_GET_TYPE_INFO_PARAMS IP1 = { 0 };
    IMAGEHLP_GET_TYPE_INFO_PARAMS IP2 = { 0 };
    PDWORD pdwTypeIndex = NULL;
    DWORD i, cInfo = dwChildCount;
    PPDB_DT_INFO pe, pInfo = NULL;
    WCHAR wszBuffer[0x20];
    LPWSTR wszName, wszFormat;
    SIZE_T oln;
    QWORD v, cbType, cbTypeLast = 0, qwBitBase = 0, cbData, vaData;
    if(!(pInfo = LocalAlloc(LMEM_ZEROINIT, cInfo * sizeof(PDB_DT_INFO)))) { goto fail; }
    // 1: fetch info about "children" into INFO struct array.
    IP1.SizeOfStruct = sizeof(IMAGEHLP_GET_TYPE_INFO_PARAMS);
    IP1.Flags = IMAGEHLP_GET_TYPE_INFO_CHILDREN;
    IP1.NumIds = 1;
    IP1.TypeIds = &dwTypeIndex;
    IP1.TagFilter = (1ULL << SymTagDimension) - 1;
    IP1.NumReqs = _countof(_INFO1_ReqKinds);
    IP1.ReqKinds = (IMAGEHLP_SYMBOL_TYPE_INFO *)_INFO1_ReqKinds;
    IP1.ReqOffsets = (PULONG_PTR)_INFO1_ReqOffsets;
    IP1.ReqSizes = (PULONG)_INFO1_ReqSizes;
    IP1.ReqStride = sizeof(PDB_DT_INFO);
    IP1.BufferSize = cInfo * sizeof(PDB_DT_INFO);
    IP1.Buffer = pInfo;
    if(!ctxDT->pfn->SymGetTypeInfoEx(ctxDT->hSym, ctxDT->BaseOfDll, &IP1)) { goto fail; }
    if(dwChildCount != IP1.EntriesFilled) { goto fail; }
    // 2: fetch info about the types of the children into INFO struct array.
    if(!(pdwTypeIndex = LocalAlloc(0, cInfo * sizeof(DWORD)))) { goto fail; }
    for(i = 0; i < cInfo; i++) {
        pdwTypeIndex[i] = pInfo[i].dwTypeIndex;
    }
    IP2.SizeOfStruct = sizeof(IMAGEHLP_GET_TYPE_INFO_PARAMS);
    IP2.Flags = 0;
    IP2.NumIds = cInfo;
    IP2.TypeIds = pdwTypeIndex;
    IP2.TagFilter = (1ULL << SymTagDimension) - 1;
    IP2.NumReqs = _countof(_INFO2_ReqKinds);
    IP2.ReqKinds = (IMAGEHLP_SYMBOL_TYPE_INFO*)_INFO2_ReqKinds;
    IP2.ReqOffsets = (PULONG_PTR)_INFO2_ReqOffsets;
    IP2.ReqSizes = (PULONG)_INFO2_ReqSizes;
    IP2.ReqStride = sizeof(PDB_DT_INFO);
    IP2.BufferSize = cInfo * sizeof(PDB_DT_INFO);
    IP2.Buffer = pInfo;
    if(!ctxDT->pfn->SymGetTypeInfoEx(ctxDT->hSym, ctxDT->BaseOfDll, &IP2)) { goto fail; }
    if(dwChildCount != IP1.EntriesFilled) { goto fail; }
    // 3: interpret result:
    for(i = 0; i < cInfo; i++) {
        pe = pInfo + i;
        oln = 0;
        cbType = pe->dwArrayCount ? (pe->qwLength / pe->dwArrayCount) : pe->qwLength;
        if(!pe->wszTypeName && pe->dwPtrTypeIndex && ((pe->dwTag == SymTagArrayType) || (pe->dwTag == SymTagPointerType))) {
            ctxDT->pfn->SymGetTypeInfo(ctxDT->hSym, ctxDT->BaseOfDll, pe->dwPtrTypeIndex, TI_GET_SYMNAME, &pe->wszTypeName);
        }
        if(qwBitBase) {
            if((cbTypeLast != cbType) || (qwBitBase >= (cbType << 3)) || ((cbType != 1) && (cbType != 2) && (cbType != 4) && (cbType != 8))) {
                qwBitBase = 0;
            }
        }
        // line: offset + name
        oln += _snwprintf_s(ctxDT->wszln + oln, MAX_PATH - oln, _TRUNCATE, L"%*s  +0x%03x %-*s : ", iLevel * 2, L"", pe->dwOffset, 24 - iLevel * 2, pe->wszName);
        // line: optional type array prefix
        if(pe->dwArrayCount) {
            oln += _snwprintf_s(ctxDT->wszln + oln, MAX_PATH - oln, _TRUNCATE, L"[%i] ", pe->dwArrayCount);
        }
        // line: optional type ptr prefix
        if(pe->dwPtrTypeIndex) {
            oln += _snwprintf_s(ctxDT->wszln + oln, MAX_PATH - oln, _TRUNCATE, L"Ptr: ");
            if(!pe->wszTypeName) {
                ctxDT->pfn->SymGetTypeInfo(ctxDT->hSym, ctxDT->BaseOfDll, pe->dwPtrTypeIndex, TI_GET_BASETYPE, &pe->dwBaseType);
                if(!pe->dwBaseType) {
                    ctxDT->pfn->SymGetTypeInfo(ctxDT->hSym, ctxDT->BaseOfDll, pe->dwPtrTypeIndex, TI_GET_SYMTAG, &pe->dwPtrTag);
                    if(pe->dwPtrTag == SymTagFunctionType) {
                        pe->dwBaseType = -1;    // fake base type - will resolve into 'function'
                    }
                    if(pe->dwPtrTag == SymTagPointerType) {
                        pe->dwBaseType = -2;    // fake base type - will resolve into 'pointer'
                    }
                }
            }
        }
        // special types #1:
        if((pe->dwTag == SymTagUDT) && pe->wszTypeName) {
            if(!wcscmp(L"_LARGE_INTEGER", pe->wszTypeName) || !_wcsnicmp(pe->wszTypeName, L"_EX_", 4) || !wcscmp(L"_KEVENT", pe->wszTypeName)) {
                pe->dwTag = SymTagBaseType;
            }
        }
        // type: complex or ordinary?
        if(pe->dwTag == SymTagUDT) {
            oln += _snwprintf_s(ctxDT->wszln + oln, MAX_PATH - oln, _TRUNCATE, L"%s", pe->wszTypeName);
            ctxDT->csz += _snprintf_s(ctxDT->szu8 + ctxDT->csz, (SIZE_T)(ctxDT->cszMax - ctxDT->csz), _TRUNCATE, "%S\n", ctxDT->wszln);   // commit line to result utf-8 result string
            oln = 0;
            if(pe->dwChildCount && (iLevel < ctxDT->iLevelMax) && (!pbMEM || (pe->dwOffset + pe->qwLength <= cbMEM))) {
                PDB_DisplayTypeNt_DoWork(H, ctxDT, iLevel + 1, pe->dwTypeIndex, pe->dwChildCount, pe->wszTypeName, (pbMEM ? pbMEM + pe->dwOffset : NULL), (pbMEM ? cbMEM - pe->dwOffset : 0));
            }
        } else {
            wszBuffer[0] = 0;
            if(pe->qwBitFieldLength) {
                _snwprintf_s(wszBuffer, _countof(wszBuffer), _TRUNCATE, L" bit[%lli:%lli]", qwBitBase, qwBitBase + pe->qwBitFieldLength - 1);
            }
            wszName = PDB_DisplayTypeNt_GetTypeName(pe, cbType);
            oln += _snwprintf_s(ctxDT->wszln + oln, MAX_PATH - oln, _TRUNCATE, L"%s%s", wszName, wszBuffer);
            // optional data:
            if(pbMEM && ((pe->dwTag == SymTagBaseType) || (pe->dwTag == SymTagPointerType)) && ((cbType == 1) || (cbType == 2) || (cbType == 4) || (cbType == 8))) {
                v = 0;
                memcpy((PBYTE)&v, pbMEM + pe->dwOffset, (SIZE_T)cbType);
                if(pe->qwBitFieldLength) {
                    v = v >> qwBitBase;
                    v = v & ((1ULL << pe->qwBitFieldLength) - 1);
                }
                if(v < 10) {
                    wszFormat = L"%*s : %llX";
                } else if(cbType == 1) {
                    wszFormat = L"%*s : 0x%02llX";
                } else if(cbType == 2) {
                    wszFormat = L"%*s : 0x%04llX";
                } else if(cbType == 4) {
                    wszFormat = L"%*s : 0x%08llX";
                } else {
                    wszFormat = L"%*s : 0x%016llX";
                }
                oln += _snwprintf_s(ctxDT->wszln + oln, MAX_PATH - oln, _TRUNCATE, wszFormat, max(0, (int)(60 - oln)), L"", v);
            }
            // _UNICODE_STRING special case:
            if(pbMEM && (dwChildCount == 3) && (i == 2) && wszTypeName && !wcscmp(L"_UNICODE_STRING", wszTypeName)) {
                cbData = *(PWORD)pbMEM;
                vaData = H->vmm.f32 ? *(PDWORD)(pbMEM + 4) : *(PQWORD)(pbMEM + 8);
                if(VMM_KADDR(H->vmm.f32, vaData) && cbData && !(cbData & 1) && (cbData < MAX_PATH * 2)) {
                    if(VmmRead(H, PVMM_PROCESS_SYSTEM, vaData, (PBYTE)ctxDT->wszBuffer, (DWORD)cbData)) {
                        ctxDT->wszBuffer[cbData >> 1] = 0;
                        oln += _snwprintf_s(ctxDT->wszln + oln, MAX_PATH - oln, _TRUNCATE, L" - %s", ctxDT->wszBuffer);
                    }
                }
            }
        }
        // commit line to result buffer:
        if(oln) {
            ctxDT->csz += _snprintf_s(ctxDT->szu8 + ctxDT->csz, (SIZE_T)(ctxDT->cszMax - ctxDT->csz), _TRUNCATE, "%S\n", ctxDT->wszln);   // commit line to result utf-8 result string
        }
        cbTypeLast = cbType;
        qwBitBase += pe->qwBitFieldLength;
    }
fail:
    LocalFree(pdwTypeIndex);
    if(pInfo) {
        for(i = 0; i < cInfo; i++) {
            pe = pInfo + i;
            LocalFree(pe->wszName);
            LocalFree(pe->wszTypeName);
        }
        LocalFree(pInfo);
    }
}

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
    _In_ LPCSTR szTypeName,
    _In_ BYTE cLevelMax,
    _In_opt_ QWORD vaType,
    _In_ BOOL fHexAscii,
    _In_ BOOL fObjHeader,
    _Out_opt_ LPSTR *pszResult,
    _Out_opt_ PDWORD pcbResult,
    _Out_opt_ PDWORD pcbType
) {
    POB_PDB_CONTEXT ctxOb = PDB_GetContext(H);
    BOOL fResult = FALSE;
    PDB_HANDLE hPDB;
    SYMBOL_INFO_PACKAGE SymbolInfoType = { 0 };
    PPDB_ENTRY pObPdbEntry = NULL;
    PDB_DT_CONTEXT ctxDT = { 0 };
    DWORD i, cTypeChildren, cbHexAscii, cbSubType;
    PBYTE pbMEM = NULL;
    LPSTR szFormat;
    LPSTR szSubType = NULL, szSubTypeResult, szu8Result = NULL;
    if(pszResult) { *pszResult = NULL; }
    if(pcbResult) { *pcbResult = 0; }
    if(pcbType) { *pcbType = 0; }
    if(!ctxOb || ctxOb->fDisabled || !ctxOb->mspdb.fValid) {
        Ob_DECREF(ctxOb);
        return FALSE;
    }
    hPDB = PDB_GetHandleFromModuleName(H, "ntoskrnl");
    if(!(pObPdbEntry = ObMap_GetByKey(ctxOb->pmPdbByHash, hPDB))) { return FALSE; }
    EnterCriticalSection(&ctxOb->Lock);
    if(!PDB_LoadEnsureEx(H, ctxOb, pObPdbEntry)) { goto fail; }
    // flag: object header -> type == _OBJECT_HEADER + adjust va type base.
    if(fObjHeader) { szTypeName = "_OBJECT_HEADER"; }
    if(fObjHeader && vaType) { vaType -= H->vmm.f32 ? sizeof(OBJECT_HEADER32) : sizeof(OBJECT_HEADER64); }
    // fetch type data:
    SymbolInfoType.si.SizeOfStruct = sizeof(SYMBOL_INFO);
    SymbolInfoType.si.MaxNameLen = MAX_SYM_NAME;
    if(!ctxOb->mspdb.pfn.SymGetTypeFromName(ctxOb->mspdb.hSym, pObPdbEntry->qwLoadAddress, szTypeName, &SymbolInfoType.si)) { goto fail; }
    if(SymbolInfoType.si.Tag != SymTagUDT) { goto fail; }   // only complex types - i.e. structs are allowed
    if(!ctxOb->mspdb.pfn.SymGetTypeInfo(ctxOb->mspdb.hSym, pObPdbEntry->qwLoadAddress, SymbolInfoType.si.TypeIndex, TI_GET_CHILDRENCOUNT, &cTypeChildren) || !cTypeChildren) { goto fail; }
    if(pcbType) { *pcbType = SymbolInfoType.si.Size; }
    // setup DisplayType context:
    ctxDT.hSym = ctxOb->mspdb.hSym;
    ctxDT.BaseOfDll = pObPdbEntry->qwLoadAddress;
    ctxDT.pfn = &ctxOb->mspdb.pfn;
    ctxDT.iLevelMax = cLevelMax;
    ctxDT.cszMax = 0x10000;
    ctxDT.szu8 = LocalAlloc(0, 0x10000);
    ctxDT.szu8[0] = 0;
    if(!ctxDT.szu8) { goto fail; }
    // fetch optional type memory (if possible):
    if(VMM_KADDR_4_8(H->vmm.f32, vaType) && (SymbolInfoType.si.Size >= 4) && (SymbolInfoType.si.Size < 0x2000)) {
        if((pbMEM = LocalAlloc(0, SymbolInfoType.si.Size))) {
            if(!VmmRead(H, PVMM_PROCESS_SYSTEM, vaType, pbMEM, SymbolInfoType.si.Size)) {
                pbMEM = LocalFree(pbMEM);
            }
        }
    }
    // call worker function:
    if(pbMEM) {
        szFormat = H->vmm.f32 ? "dt nt!%s  0x%08llX\n" : "dt nt!%s  0x%016llX\n";
        ctxDT.csz += snprintf(ctxDT.szu8 + ctxDT.csz, (SIZE_T)(ctxDT.cszMax - ctxDT.csz), szFormat, SymbolInfoType.si.Name, vaType);
    } else {
        ctxDT.csz += snprintf(ctxDT.szu8 + ctxDT.csz, (SIZE_T)(ctxDT.cszMax - ctxDT.csz), "dt nt!%s\n", SymbolInfoType.si.Name);
    }
    PDB_DisplayTypeNt_DoWork(H, &ctxDT, 0, SymbolInfoType.si.TypeIndex, cTypeChildren, NULL, pbMEM, (pbMEM ? SymbolInfoType.si.Size : 0));
    // append optional hexascii:
    if(fHexAscii && pbMEM && ctxDT.csz) {
        szFormat = H->vmm.f32 ? "\n---\n\ndb  0x%08llX  L%03X\n" : "\n---\n\ndb  0x%016llX  L%03X\n";
        ctxDT.csz += snprintf(ctxDT.szu8 + ctxDT.csz, (SIZE_T)(ctxDT.cszMax - ctxDT.csz), szFormat, vaType, SymbolInfoType.si.Size);
        cbHexAscii = (DWORD)(ctxDT.cszMax - ctxDT.csz);
        if(Util_FillHexAscii(pbMEM, min(0x2000, SymbolInfoType.si.Size), 0, ctxDT.szu8 + ctxDT.csz, &cbHexAscii)) {
            ctxDT.csz += cbHexAscii;
        }
    }
    // flag: object header: special processing:
    if(fObjHeader && pbMEM && H->vmm.offset._OBJECT_HEADER_CREATOR_INFO.cb) {
        for(i = 0; i < 9; i++) {
            if(((1 << i) & (H->vmm.f32 ? ((POBJECT_HEADER32)pbMEM)->InfoMask : ((POBJECT_HEADER64)pbMEM)->InfoMask)) || (i == 8)) {
                switch(i) {
                    case 0: szSubType = "_OBJECT_HEADER_CREATOR_INFO"; cbSubType = H->vmm.offset._OBJECT_HEADER_CREATOR_INFO.cb; break;        // 0x01
                    case 1: szSubType = "_OBJECT_HEADER_NAME_INFO";    cbSubType = H->vmm.offset._OBJECT_HEADER_NAME_INFO.cb;    break;        // 0x02
                    case 2: szSubType = "_OBJECT_HEADER_HANDLE_INFO";  cbSubType = H->vmm.offset._OBJECT_HEADER_HANDLE_INFO.cb;  break;        // 0x04
                    case 3: szSubType = "_OBJECT_HEADER_QUOTA_INFO";   cbSubType = H->vmm.offset._OBJECT_HEADER_QUOTA_INFO.cb;   break;        // 0x08
                    case 4: szSubType = "_OBJECT_HEADER_PROCESS_INFO"; cbSubType = H->vmm.offset._OBJECT_HEADER_PROCESS_INFO.cb; break;        // 0x10
                    case 6: szSubType = "_OBJECT_HEADER_AUDIT_INFO";   cbSubType = H->vmm.offset._OBJECT_HEADER_AUDIT_INFO.cb;   break;        // 0x40
                    case 8: szSubType = "_POOL_HEADER";                cbSubType = H->vmm.offset._POOL_HEADER.cb;                break;        // ---
                    default: szSubType = NULL; cbSubType = 0; break;
                }
                if(!cbSubType || !szSubType) { break; }
                vaType -= cbSubType;
                if(PDB_DisplayTypeNt(H, szSubType, 2, vaType, fHexAscii, FALSE, &szSubTypeResult, NULL, NULL)) {
                    ctxDT.csz += snprintf(ctxDT.szu8 + ctxDT.csz, (SIZE_T)(ctxDT.cszMax - ctxDT.csz), "\n======\n\n%s", szSubTypeResult);
                    LocalFree(szSubTypeResult);
                }
            }
        }
    }
    // set output
    if(pszResult) {
        if(!ctxDT.csz || !(*pszResult = LocalAlloc(0, (SIZE_T)(ctxDT.csz + 1)))) { goto fail; }
        memcpy(*pszResult, ctxDT.szu8, (SIZE_T)(ctxDT.csz + 1));
    }
    if(pcbResult) { *pcbResult = (DWORD)(ctxDT.csz + 1); }
    fResult = TRUE;
fail:
    LeaveCriticalSection(&ctxOb->Lock);
    Ob_DECREF(pObPdbEntry);
    LocalFree(ctxDT.szu8);
    LocalFree(pbMEM);
    Ob_DECREF(ctxOb);
    return fResult;
}

#endif /* _WIN32 */
#if defined(LINUX) || defined(MACOS)

_Success_(return)
BOOL PDB_DisplayTypeNt(
    _In_ VMM_HANDLE H,
    _In_ LPCSTR szTypeName,
    _In_ BYTE cLevelMax,
    _In_opt_ QWORD vaType,
    _In_ BOOL fHexAscii,
    _In_ BOOL fObjHeader,
    _Out_opt_ LPSTR *pszResult,
    _Out_opt_ PDWORD pcbResult,
    _Out_opt_ PDWORD pcbType
) {
    return FALSE;
}

#endif /* LINUX || MACOS */
