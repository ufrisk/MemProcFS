// pe.h : definitions related to parsing of portable executable (PE) images in
//        virtual address space. This may mostly (but not exclusively) be used
//        by Windows functionality.
//
// (c) Ulf Frisk, 2018-2024
// Author: Ulf Frisk, pcileech@frizk.net
//
#ifndef __PE_H__
#define __PE_H__
#include "vmm.h"

#define PE_MAX_SUPPORTED_SIZE           0x80000000      // >2GB not supported (may be error / corrupt indata)

static const LPCSTR  PE_DATA_DIRECTORIES[16]  = {  "EXPORT",  "IMPORT",  "RESOURCE",  "EXCEPTION",  "SECURITY",  "BASERELOC",  "DEBUG",  "ARCHITECTURE",  "GLOBALPTR",  "TLS",  "LOAD_CONFIG",  "BOUND_IMPORT",  "IAT",  "DELAY_IMPORT",  "COM_DESCRIPTOR",  "RESERVED" };

typedef struct tdPE_CODEVIEW {
    DWORD Signature;
    BYTE Guid[16];
    DWORD Age;
    CHAR PdbFileName[256 - 4 - 16 - 4];
} PE_CODEVIEW, *PPE_CODEVIEW;

typedef struct tdPE_CODEVIEW_INFO {
    DWORD SizeCodeView;
    PE_CODEVIEW CodeView;
    DWORD _Reserved;
} PE_CODEVIEW_INFO, *PPE_CODEVIEW_INFO;

typedef struct tdPE_THUNKINFO_IAT {
    BOOL fValid;
    BOOL f32;               // if TRUE fn is a 32-bit/4-byte entry, otherwise 64-bit/8-byte entry.
    ULONG64 vaThunk;        // address of import address table 'thunk'.
    ULONG64 vaFunction;     // value if import address table 'thunk' == address of imported function.
    ULONG64 vaNameModule;   // address of name string for imported module.
    ULONG64 vaNameFunction; // address of name string for imported function.
} PE_THUNKINFO_IAT, *PPE_THUNKINFO_IAT;

typedef struct tdPE_THUNKINFO_EAT {
    BOOL fValid;
    DWORD valueThunk;       // value of export address table 'thunk'.
    ULONG64 vaThunk;        // address of import address table 'thunk'.
    ULONG64 vaNameFunction; // address of name string for exported function.
    ULONG64 vaFunction;     // address of exported function (module base + value parameter).
} PE_THUNKINFO_EAT, *PPE_THUNKINFO_EAT;

/*
* Retrieve the size of the module given its base.
* -- H
* -- pProcess
* -- vaModuleBase = PE module base address.
* -- return = success: size of module. fail: 0.
*/
QWORD PE_GetSize(
    _In_ VMM_HANDLE H,
    _In_ PVMM_PROCESS pProcess,
    _In_opt_ QWORD vaModuleBase
);

/*
* Retrieve the TimeDateStamp and CheckSum from the PE header.
* -- H
* -- pProcess
* -- vaModuleBase = PE module base address.
* -- pdwTimeDateStamp
* -- pdwCheckSum
* -- return
*/
_Success_(return)
BOOL PE_GetTimeDateStampCheckSum(
    _In_ VMM_HANDLE H,
    _In_ PVMM_PROCESS pProcess,
    _In_opt_ QWORD vaModuleBase,
    _Out_opt_ PDWORD pdwTimeDateStamp,
    _Out_opt_ PDWORD pdwCheckSum
);

/*
* Lookup the virtual address of an exported function or symbol in the module supplied.
* Similar to Windows 'GetProcAddress'.
* -- H
* -- pProcess
* -- vaModuleBase = PE module base address.
* -- return = success: virtual address of function / symbol. fail: 0.
*/
QWORD PE_GetProcAddress(
    _In_ VMM_HANDLE H,
    _In_ PVMM_PROCESS pProcess,
    _In_ QWORD vaModuleBase,
    _In_ LPCSTR lpProcName
);

/*
* Lookup the virtual address of an exported function or symbol in the module supplied
* among with additional information returned in the pThunkInfoEAT struct.
* -- H
* -- pProcess
* -- vaModuleBase = PE module base address.
* -- szProcName
* -- pThunkInfoEAT
* -- return
*/
_Success_(return)
BOOL PE_GetThunkInfoEAT(
    _In_ VMM_HANDLE H,
    _In_ PVMM_PROCESS pProcess,
    _In_ QWORD vaModuleBase,
    _In_ LPCSTR szProcName,
    _Out_ PPE_THUNKINFO_EAT pThunkInfoEAT
);

/*
* Retrieve an import address table (IAT) entry for a specific function.
* This may be useful for IAT patching functionality.
* -- H
* -- pProcess
* -- vaModuleBase
* -- szImportModuleName
* -- szImportProcName
* -- pThunkInfoIAT
* -- return
*/
_Success_(return)
BOOL PE_GetThunkInfoIAT(
    _In_ VMM_HANDLE H,
    _In_ PVMM_PROCESS pProcess,
    _In_ QWORD vaModuleBase,
    _In_ LPCSTR szImportModuleName,
    _In_ LPCSTR szImportProcName,
    _Out_ PPE_THUNKINFO_IAT pThunkInfoIAT
);

/*
* Retrieve the module name and optionally the module size.
* -- H
* -- pProcess
* -- vaModuleBase
* -- fOnFailDummyName
* -- pbModuleHeaderOpt
* -- szModuleName
* -- cszModuleName
* -- pdwSize
* -- return
*/
_Success_(return)
BOOL PE_GetModuleNameEx(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess, _In_ QWORD vaModuleBase, _In_ BOOL fOnFailDummyName, _In_reads_opt_(0x1000) PBYTE pbModuleHeaderOpt, _Out_writes_(cszModuleName) PCHAR szModuleName, _In_ DWORD cszModuleName, _Out_opt_ PDWORD pdwSize);
_Success_(return)
BOOL PE_GetModuleName(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess, _In_ QWORD vaModuleBase, _Out_writes_(cszModuleName) PCHAR szModuleName, _In_ DWORD cszModuleName);

/*
* Retrieve the number of sections in the module given by either the module base
* virtual address or a pre-retrieved pbModuleHeader of size 0x1000.
* -- H
* -- pProcess
* -- vaModuleBase = PE module base address (unless pbModuleHeaderOpt is specified)
* -- pbModuleHeaderOpt = Optional buffer containing module header (MZ) page.
* -- return = success: number of sections. fail: 0.
*/
WORD PE_SectionGetNumberOfEx(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess, _In_opt_ QWORD vaModuleBase, _In_reads_opt_(0x1000) PBYTE pbModuleHeaderOpt);
WORD PE_SectionGetNumberOf(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess, _In_opt_ QWORD vaModuleBase);

/*
* Retrieve a single section header given its name.
* -- H
* -- pProcess
* -- vaModuleBase
* -- szSectionName
* -- pSection
* -- return
*/
_Success_(return)
BOOL PE_SectionGetFromName(
    _In_ VMM_HANDLE H,
    _In_ PVMM_PROCESS pProcess,
    _In_ QWORD vaModuleBase,
    _In_ LPCSTR szSectionName,
    _Out_ PIMAGE_SECTION_HEADER pSection
);

/*
* Retrieve a single section header given its address offset.
* -- H
* -- pProcess
* -- vaModuleBase
* -- cboAddress
* -- pSection
* -- return
*/
_Success_(return)
BOOL PE_SectionGetFromAddressOffset(
    _In_ VMM_HANDLE H,
    _In_ PVMM_PROCESS pProcess,
    _In_ QWORD vaModuleBase,
    _In_ DWORD cboAddress,
    _Out_ PIMAGE_SECTION_HEADER pSection
);

/*
* Retrieve all sections.
* -- H
* -- pProcess
* -- vaModuleBase
* -- cSections
* -- pSections
* -- return
*/
_Success_(return)
BOOL PE_SectionGetAll(
    _In_ VMM_HANDLE H,
    _In_ PVMM_PROCESS pProcess,
    _In_ QWORD vaModuleBase,
    _In_ DWORD cSections,
    _Out_writes_(cSections) PIMAGE_SECTION_HEADER pSections
);

/*
* Validate that the string provided in szForwardedFunction is a forwarded
* function on the format: module.function or module.#ordinal (as given by EAT).
* -- szForwardedFunction = forwarded function identifier as given by EAT.
* -- szModule = optional buffer to receive module name.
* -- cbModule = size of szModule buffer.
* -- pdwOrdinal = ptr to receive ordinal if parsed data is on ordinal format.
* -- return = function name or ordinal upon success. NULL on fail.
*/
_Success_(return != NULL)
LPSTR PE_EatForwardedFunctionNameValidate(
    _In_ LPCSTR szForwardedFunction,
    _Out_writes_opt_(cbModule) LPSTR szModule,
    _In_ DWORD cbModule,
    _Out_opt_ PDWORD pdwOrdinal
);

/*
* Retrieve the number of export address table (EAT) entries - i.e. the number
* of functions that the module is exporting.
* -- H
* -- pProcess
* -- vaModuleBase = PE module base address (unless pbModuleHeaderOpt is specified)
* -- pbModuleHaderOpt = Optional buffer containing module header (MZ) page.
* -- return = success: number of entries. fail: 0.
*/
DWORD PE_EatGetNumberOfEx(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess, _In_opt_ QWORD vaModuleBase, _In_reads_opt_(0x1000) PBYTE pbModuleHeaderOpt);
__forceinline DWORD PE_EatGetNumberOf(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess, _In_opt_ QWORD vaModuleBase)
{
    return PE_EatGetNumberOfEx(H, pProcess, vaModuleBase, NULL);
}

/*
* Retrieve the number of import address table (IAT) entries - i.e. the number
* of functions that the module is importing.
* -- H
* -- pProcess
* -- vaModuleBase = PE module base address (unless pbModuleHeaderOpt is specified)
* -- pbModuleHaderOpt = Optional buffer containing module header (MZ) page.
* -- return = success: number of entries. fail: 0.
*/
DWORD PE_IatGetNumberOfEx(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess, _In_opt_ QWORD vaModuleBase, _In_reads_opt_(0x1000) PBYTE pbModuleHeaderOpt);
__forceinline DWORD PE_IatGetNumberOf(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess, _In_opt_ QWORD vaModuleBase)
{
    return PE_IatGetNumberOfEx(H, pProcess, vaModuleBase, NULL);
}

/*
* Retrieve info about the PE directories.
* -- H
* -- pProcess
* -- vaModuleBase = PE module base address (unless pbModuleHeaderOpt is specified)
* -- pbModuleHeaderOpt = Optional buffer containing module header (MZ) page.
* -- pDirectories = buffer to receive the data of the 16 directories.
*/
_Success_(return)
BOOL PE_DirectoryGetAll(
    _In_ VMM_HANDLE H,
    _In_ PVMM_PROCESS pProcess,
    _In_opt_ QWORD vaModuleBase,
    _In_reads_opt_(0x1000) PBYTE pbModuleHeaderOpt,
    _Out_writes_(IMAGE_NUMBEROF_DIRECTORY_ENTRIES) PIMAGE_DATA_DIRECTORY pDirectories
);

/*
* Retrieve the offset of a PE directory - i.e. the VirtualAddress of the directory.
* -- H
* -- pProcess
* -- vaModuleBase = PE module base address (unless pbModuleHeaderOpt is specified)
* -- pbModuleHeaderOpt = Optional buffer containing module header (MZ) page.
* -- dwDataDirectory = Data directory as specified by IMAGE_DIRECTORY_ENTRY_*
* -- pcbSizeOfDirectory = size of data directory.
* -- return = the offset in bytes from PE base or 0 on fail.
*/
_Success_(return != 0)
DWORD PE_DirectoryGetOffset(
    _In_ VMM_HANDLE H,
    _In_ PVMM_PROCESS pProcess,
    _In_opt_ QWORD vaModuleBase,
    _In_reads_opt_(0x1000) PBYTE pbModuleHeaderOpt,
    _In_ DWORD dwDirectory,
    _Out_opt_ PDWORD pcbSizeOfDirectory
);

/*
* Retrieve PDB debugging information from a single module.
* -- H
* -- pProcess
* -- vaModulebase
* -- pbModuleHeaderOpt
* -- pCodeViewInfo
* -- return
*/
_Success_(return)
BOOL PE_GetCodeViewInfo(
    _In_ VMM_HANDLE H,
    _In_ PVMM_PROCESS pProcess,
    _In_opt_ QWORD vaModuleBase,
    _In_reads_opt_(0x1000) PBYTE pbModuleHeaderOpt,
    _Out_ PPE_CODEVIEW_INFO pCodeViewInfo
);

/*
* Retrieve the raw size of the 'file' estimation that is possible to rebuild
* using PE sections from memory.
* -- H
* -- pProcess
* -- vaModuleBase = PE module base address (unless pbModuleHeaderOpt is specified)
* -- pbModuleHaderOpt = Optional buffer containing module header (MZ) page.
* -- return = success: size of file. fail: 0.
*/
DWORD PE_FileRaw_Size(
    _In_ VMM_HANDLE H,
    _In_ PVMM_PROCESS pProcess,
    _In_opt_ QWORD vaModuleBase,
    _In_reads_opt_(0x1000) PBYTE pbModuleHeaderOpt
);

/*
* Read part of a, from memory, best-effort re-constructed PE file.
* -- H
* -- pProcess
* -- vaModuleBase = PE module base address.
* -- pb
* -- cb
* -- pcbRead
* -- cbOffset
* -- return
*/
_Success_(return)
BOOL PE_FileRaw_Read(
    _In_ VMM_HANDLE H,
    _In_ PVMM_PROCESS pProcess,
    _In_ QWORD vaModuleBase,
    _Out_ PBYTE pb,
    _In_ DWORD cb,
    _Out_ PDWORD pcbRead,
    _In_ DWORD cbOffset
);

/*
* Write to the underlying pages which supports this re-constructed PE file.
* This is normally not recommended and will be very dangerous since it is most
* likely to affect all instances - in all processes - of the PE file written to.
* -- H
* -- pProcess
* -- vaModuleBase = PE module base address.
* -- pb
* -- cb
* -- pcbWrite
* -- cbOffset
* -- return
*/
_Success_(return)
BOOL PE_FileRaw_Write(
    _In_ VMM_HANDLE H,
    _In_ PVMM_PROCESS pProcess,
    _In_ QWORD vaModuleBase,
    _In_reads_(cb) PBYTE pb,
    _In_ DWORD cb,
    _Out_ PDWORD pcbWrite,
    _In_ DWORD cbOffset
);

/*
* Retieve the VS_VERSION_INFO struct from a module.
* NULL entries may exist after 'psm' finalize even on success.
* -- H
* -- pProcess
* -- vaModuleBase
* -- psm
* -- pMEVI
* -- return
*/
_Success_(return)
BOOL PE_VsGetVersionInfo(
    _In_ VMM_HANDLE H,
    _In_ PVMM_PROCESS pProcess,
    _In_ QWORD vaModuleBase,
    _In_ POB_STRMAP psm,
    _In_ PVMM_MAP_MODULEENTRY_VERSIONINFO pMEVI
);

#endif /* __PE_H__ */
