// pe.h : definitions related to parsing of portable executable (PE) images in
//        virtual address space. This may mostly (but not exclusively) be used
//        by Windows functionality.
//
// (c) Ulf Frisk, 2018
// Author: Ulf Frisk, pcileech@frizk.net
//
#ifndef __PE_H__
#define __PE_H__
#include "vmm.h"

static const LPCSTR PE_DATA_DIRECTORIES[16] = { "EXPORT", "IMPORT", "RESOURCE", "EXCEPTION", "SECURITY", "BASERELOC", "DEBUG", "ARCHITECTURE", "GLOBALPTR", "TLS", "LOAD_CONFIG", "BOUND_IMPORT", "IAT", "DELAY_IMPORT", "COM_DESCRIPTOR", "RESERVED" };

/*
* Retrieve the size of the module given its base.
* -- pProcess
* -- vaModuleBase = PE module base address.
* -- return = success: size of module. fail: 0.
*/
QWORD PE_GetSize(_In_ PVMM_PROCESS pProcess, _In_opt_ QWORD vaModuleBase);

/*
* Lookup the virtual address of an exported function or symbol in the module supplied.
* Similar to Windows 'GetProcAddress'.
* -- pProcess
* -- vaModuleBase = PE module base address.
* -- return = success: virtual address of function / symbol. fail: 0.
*/
QWORD PE_GetProcAddress(_In_ PVMM_PROCESS pProcess, _In_ QWORD vaModuleBase, _In_ LPSTR lpProcName);

/*
* Retrieve the module name and optionally the module size.
* -- pProcess
* -- vaModuleBase
* -- fOnFailDummyName
* -- pbModuleHeaderOpt
* -- szModuleName
* -- pdwSize
* -- return
*/
_Success_(return)
BOOL PE_GetModuleNameEx(_In_ PVMM_PROCESS pProcess, _In_ QWORD vaModuleBase, _In_ BOOL fOnFailDummyName, _In_reads_opt_(0x1000) PBYTE pbModuleHeaderOpt, _Out_writes_(MAX_PATH) PCHAR szModuleName, _Out_opt_ PDWORD pdwSize);
_Success_(return)
inline BOOL PE_GetModuleName(_In_ PVMM_PROCESS pProcess, _In_ QWORD vaModuleBase, _Out_writes_(MAX_PATH) PCHAR szModuleName)
{
    return PE_GetModuleNameEx(pProcess, vaModuleBase, FALSE, NULL, szModuleName, NULL);
}

/*
* Retrieve the number of sections in the module given by either the module base
* virtual address or a pre-retrieved pbModuleHeader of size 0x1000.
* -- pProcess
* -- vaModuleBase = PE module base address (unless pbModuleHeaderOpt is specified)
* -- pbModuleHeaderOpt = Optional buffer containing module header (MZ) page.
* -- return = success: number of sections. fail: 0.
*/
WORD PE_SectionGetNumberOfEx(_In_ PVMM_PROCESS pProcess, _In_opt_ QWORD vaModuleBase, _In_reads_opt_(0x1000) PBYTE pbModuleHeaderOpt);
inline WORD PE_SectionGetNumberOf(_In_ PVMM_PROCESS pProcess, _In_opt_ QWORD vaModuleBase)
{
    return PE_SectionGetNumberOfEx(pProcess, vaModuleBase, NULL);
}

/*
* Retrieve a single section header given its name.
* -- pProcess
* -- vaModuleBase
* -- szSectionName
* -- pSection
* -- return
*/
_Success_(return)
BOOL PE_SectionGetFromName(_In_ PVMM_PROCESS pProcess, _In_ QWORD vaModuleBase, _In_ LPSTR szSectionName, _Out_ PIMAGE_SECTION_HEADER pSection);

/*
* Retrieve the number of export address table (EAT) entries - i.e. the number
* of functions that the module is exporting.
* -- pProcess
* -- vaModuleBase = PE module base address (unless pbModuleHeaderOpt is specified)
* -- pbModuleHaderOpt = Optional buffer containing module header (MZ) page.
* -- return = success: number of entries. fail: 0.
*/
DWORD PE_EatGetNumberOfEx(_In_ PVMM_PROCESS pProcess, _In_ QWORD vaModuleBase, _In_reads_opt_(0x1000) PBYTE pbModuleHeaderOpt);
inline DWORD PE_EatGetNumberOf(_In_ PVMM_PROCESS pProcess, _In_ QWORD vaModuleBase)
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
DWORD PE_IatGetNumberOfEx(_In_ PVMM_PROCESS pProcess, _In_ QWORD vaModuleBase, _In_reads_opt_(0x1000) PBYTE pbModuleHeaderOpt);
inline DWORD PE_IatGetNumberOf(_In_ PVMM_PROCESS pProcess, _In_ QWORD vaModuleBase)
{
    return PE_IatGetNumberOfEx(pProcess, vaModuleBase, NULL);
}

#endif /* __PE_H__ */
