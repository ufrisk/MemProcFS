// pe.h : definitions related to parsing of portable executable (PE) images in
//        virtual address space. This may mostly (but not exclusively) be used
//        by Windows functionality.
//
// (c) Ulf Frisk, 2018-2021
// Author: Ulf Frisk, pcileech@frizk.net
//
#ifndef __PE_H__
#define __PE_H__
#include "vmm.h"

#define CONTAINING_RECORD32(address, type, field) ((DWORD)( \
                                                  (DWORD)(QWORD)(address) - \
                                                  (DWORD)(QWORD)(&((type *)0)->field)))

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
* -- pProcess
* -- vaModuleBase = PE module base address.
* -- return = success: size of module. fail: 0.
*/
QWORD PE_GetSize(
    _In_ PVMM_PROCESS pProcess,
    _In_opt_ QWORD vaModuleBase
);

/*
* Retrieve the TimeDateStamp and CheckSum from the PE header.
* -- pProcess
* -- vaModuleBase = PE module base address.
* -- pdwTimeDateStamp
* -- pdwCheckSum
* -- return
*/
_Success_(return)
BOOL PE_GetTimeDateStampCheckSum(
    _In_ PVMM_PROCESS pProcess,
    _In_opt_ QWORD vaModuleBase,
    _Out_opt_ PDWORD pdwTimeDateStamp,
    _Out_opt_ PDWORD pdwCheckSum
);

/*
* Lookup the virtual address of an exported function or symbol in the module supplied.
* Similar to Windows 'GetProcAddress'.
* -- pProcess
* -- vaModuleBase = PE module base address.
* -- return = success: virtual address of function / symbol. fail: 0.
*/
QWORD PE_GetProcAddress(
    _In_ PVMM_PROCESS pProcess,
    _In_ QWORD vaModuleBase,
    _In_ LPSTR lpProcName
);

/*
* Lookup the virtual address of an exported function or symbol in the module supplied
* among with additional information returned in the pThunkInfoEAT struct.
* -- pProcess
* -- vaModuleBase = PE module base address.
* -- szProcName
* -- pThunkInfoEAT
* -- return
*/
_Success_(return)
BOOL PE_GetThunkInfoEAT(
    _In_ PVMM_PROCESS pProcess,
    _In_ QWORD vaModuleBase,
    _In_ LPSTR szProcName,
    _Out_ PPE_THUNKINFO_EAT pThunkInfoEAT
);

/*
* Retrieve an import address table (IAT) entry for a specific function.
* This may be useful for IAT patching functionality.
* -- pProcess
* -- vaModuleBase
* -- szImportModuleName
* -- szImportProcName
* -- pThunkInfoIAT
* -- return
*/
_Success_(return)
BOOL PE_GetThunkInfoIAT(
    _In_ PVMM_PROCESS pProcess,
    _In_ QWORD vaModuleBase,
    _In_ LPSTR szImportModuleName,
    _In_ LPSTR szImportProcName,
    _Out_ PPE_THUNKINFO_IAT pThunkInfoIAT
);

/*
* Retrieve the module name and optionally the module size.
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
BOOL PE_GetModuleNameEx(_In_ PVMM_PROCESS pProcess, _In_ QWORD vaModuleBase, _In_ BOOL fOnFailDummyName, _In_reads_opt_(0x1000) PBYTE pbModuleHeaderOpt, _Out_writes_(cszModuleName) PCHAR szModuleName, _In_ DWORD cszModuleName, _Out_opt_ PDWORD pdwSize);
_Success_(return)
BOOL PE_GetModuleName(_In_ PVMM_PROCESS pProcess, _In_ QWORD vaModuleBase, _Out_writes_(cszModuleName) PCHAR szModuleName, _In_ DWORD cszModuleName);

/*
* Retrieve the number of sections in the module given by either the module base
* virtual address or a pre-retrieved pbModuleHeader of size 0x1000.
* -- pProcess
* -- vaModuleBase = PE module base address (unless pbModuleHeaderOpt is specified)
* -- pbModuleHeaderOpt = Optional buffer containing module header (MZ) page.
* -- return = success: number of sections. fail: 0.
*/
WORD PE_SectionGetNumberOfEx(_In_ PVMM_PROCESS pProcess, _In_opt_ QWORD vaModuleBase, _In_reads_opt_(0x1000) PBYTE pbModuleHeaderOpt);
WORD PE_SectionGetNumberOf(_In_ PVMM_PROCESS pProcess, _In_opt_ QWORD vaModuleBase);

/*
* Retrieve a single section header given its name.
* -- pProcess
* -- vaModuleBase
* -- szSectionName
* -- pSection
* -- return
*/
_Success_(return)
BOOL PE_SectionGetFromName(
    _In_ PVMM_PROCESS pProcess,
    _In_ QWORD vaModuleBase,
    _In_ LPSTR szSectionName,
    _Out_ PIMAGE_SECTION_HEADER pSection
);

/*
* Retrieve all sections.
* -- pProcess
* -- vaModuleBase
* -- cSections
* -- pSections
* -- return
*/
_Success_(return)
BOOL PE_SectionGetAll(
    _In_ PVMM_PROCESS pProcess,
    _In_ QWORD vaModuleBase,
    _In_ DWORD cSections,
    _Out_writes_(cSections) PIMAGE_SECTION_HEADER pSections
);

/*
* Retrieve the number of export address table (EAT) entries - i.e. the number
* of functions that the module is exporting.
* -- pProcess
* -- vaModuleBase = PE module base address (unless pbModuleHeaderOpt is specified)
* -- pbModuleHaderOpt = Optional buffer containing module header (MZ) page.
* -- return = success: number of entries. fail: 0.
*/
DWORD PE_EatGetNumberOfEx(_In_ PVMM_PROCESS pProcess, _In_opt_ QWORD vaModuleBase, _In_reads_opt_(0x1000) PBYTE pbModuleHeaderOpt);
inline DWORD PE_EatGetNumberOf(_In_ PVMM_PROCESS pProcess, _In_opt_ QWORD vaModuleBase)
{
    return PE_EatGetNumberOfEx(pProcess, vaModuleBase, NULL);
}

/*
* Retrieve the number of import address table (IAT) entries - i.e. the number
* of functions that the module is importing.
* -- pProcess
* -- vaModuleBase = PE module base address (unless pbModuleHeaderOpt is specified)
* -- pbModuleHaderOpt = Optional buffer containing module header (MZ) page.
* -- return = success: number of entries. fail: 0.
*/
DWORD PE_IatGetNumberOfEx(_In_ PVMM_PROCESS pProcess, _In_opt_ QWORD vaModuleBase, _In_reads_opt_(0x1000) PBYTE pbModuleHeaderOpt);
inline DWORD PE_IatGetNumberOf(_In_ PVMM_PROCESS pProcess, _In_opt_ QWORD vaModuleBase)
{
    return PE_IatGetNumberOfEx(pProcess, vaModuleBase, NULL);
}

/*
* Retrieve info about the PE directories.
* -- pProcess
* -- vaModuleBase = PE module base address (unless pbModuleHeaderOpt is specified)
* -- pbModuleHeaderOpt = Optional buffer containing module header (MZ) page.
* -- pDirectories = buffer to receive the data of the 16 directories.
*/
_Success_(return)
BOOL PE_DirectoryGetAll(
    _In_ PVMM_PROCESS pProcess,
    _In_opt_ QWORD vaModuleBase,
    _In_reads_opt_(0x1000) PBYTE pbModuleHeaderOpt,
    _Out_writes_(IMAGE_NUMBEROF_DIRECTORY_ENTRIES) PIMAGE_DATA_DIRECTORY pDirectories
);

/*
* Retrieve the offset of a PE directory - i.e. the VirtualAddress of the directory.
* -- pProcess
* -- vaModuleBase = PE module base address (unless pbModuleHeaderOpt is specified)
* -- pbModuleHeaderOpt = Optional buffer containing module header (MZ) page.
* -- dwDataDirectory = Data directory as specified by IMAGE_DIRECTORY_ENTRY_*
* -- return = the offset in bytes from PE base or 0 on fail.
*/
DWORD PE_DirectoryGetOffset(
    _In_ PVMM_PROCESS pProcess,
    _In_opt_ QWORD vaModuleBase,
    _In_reads_opt_(0x1000) PBYTE pbModuleHeaderOpt,
    _In_ DWORD dwDirectory
);

/*
* Retrieve PDB debugging information from a single module.
* -- pProcess
* -- vaModulebase
* -- pbModuleHeaderOpt
* -- pCodeViewInfo
* -- return
*/
_Success_(return)
BOOL PE_GetCodeViewInfo(
    _In_ PVMM_PROCESS pProcess,
    _In_opt_ QWORD vaModuleBase,
    _In_reads_opt_(0x1000) PBYTE pbModuleHeaderOpt,
    _Out_ PPE_CODEVIEW_INFO pCodeViewInfo
);

/*
* Retrieve the raw size of the 'file' estimation that is possible to rebuild
* using PE sections from memory.
* -- pProcess
* -- vaModuleBase = PE module base address (unless pbModuleHeaderOpt is specified)
* -- pbModuleHaderOpt = Optional buffer containing module header (MZ) page.
* -- return = success: size of file. fail: 0.
*/
DWORD PE_FileRaw_Size(
    _In_ PVMM_PROCESS pProcess,
    _In_opt_ QWORD vaModuleBase,
    _In_reads_opt_(0x1000) PBYTE pbModuleHeaderOpt
);

/*
* Read part of a, from memory, best-effort re-constructed PE file.
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
    _In_ PVMM_PROCESS pProcess,
    _In_ QWORD vaModuleBase,
    _In_reads_(cb) PBYTE pb,
    _In_ DWORD cb,
    _Out_ PDWORD pcbWrite,
    _In_ DWORD cbOffset
);

#endif /* __PE_H__ */
