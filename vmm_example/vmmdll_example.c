// vmmdll_example.c - Memory Process File System / Virtual Memory Manager DLL API usage examples
//
// Note that this is not a complete list of the VMM API. For the complete list please consult the vmmdll.h header file.
//
// (c) Ulf Frisk, 2018
// Author: Ulf Frisk, pcileech@frizk.net
//

#include <Windows.h>
#include <stdio.h>
#include <conio.h>
#include "vmmdll.h"

#pragma comment(lib, "vmm")

// ----------------------------------------------------------------------------
// Initialize from type of device, FILE, FPGA or Total Meltdown (CVE-2018-1038).
// Ensure only one is active below at one single time!
// INITIALIZE_FROM_FILE contains file name to a raw memory dump.
// ----------------------------------------------------------------------------
#define _INITIALIZE_FROM_FILE    "c:\\temp\\win10.raw"
//#define _INITIALIZE_FROM_FPGA
//#define _INITIALIZE_FROM_TOTALMELTDOWN

// ----------------------------------------------------------------------------
// Utility functions below:
// ----------------------------------------------------------------------------

VOID ShowKeyPress()
{
    printf("PRESS ANY KEY TO CONTINUE ...\n");
    Sleep(250);
    _getch();
}

VOID PrintHexAscii(_In_ PBYTE pb, _In_ DWORD cb)
{
    DWORD szMax;
    LPSTR sz;
    VMMDLL_UtilFillHexAscii(pb, cb, 0, NULL, &szMax);
    if(!(sz = LocalAlloc(0, szMax))) { return; }
    VMMDLL_UtilFillHexAscii(pb, cb, 0, sz, &szMax);
    printf(sz);
    LocalFree(sz);
}

VOID CallbackList_AddFile(_Inout_ HANDLE h, _In_ LPSTR szName, _In_ ULONG64 cb, _In_ PVOID pvReserved)
{
    printf("         FILE: '%s'\tSize: %i\n", szName, (DWORD)cb);
}

VOID CallbackList_AddDirectory(_Inout_ HANDLE h, _In_ LPSTR szName, _In_ PVOID pvReserved)
{
    printf("         DIR:  '%s'\n", szName);
}

// ----------------------------------------------------------------------------
// Main entry point which contains various sample code how to use PCILeech DLL.
// Please walk though for different API usage examples. To select device ensure
// one device type only is uncommented in the #defines above.
// ----------------------------------------------------------------------------
int main(_In_ int argc, _In_ char* argv[])
{
    BOOL result;
    NTSTATUS nt;
    DWORD i, dwPID;
    DWORD dw = 0;
    QWORD va;
    BYTE pbPage1[0x1000], pbPage2[0x1000];

#ifdef _INITIALIZE_FROM_FILE
    // Initialize PCILeech DLL with a memory dump file.
    printf("------------------------------------------------------------\n");
    printf("#01: Initialize from file:                                  \n");
    ShowKeyPress();
    printf("CALL:    VMMDLL_InitializeFile\n");
    result = VMMDLL_Initialize(3, (LPSTR[]){ "", "-device", _INITIALIZE_FROM_FILE });
    if(result) {
        printf("SUCCESS: VMMDLL_InitializeFile\n");
    } else {
        printf("FAIL:    VMMDLL_InitializeFile\n");
        return 1;
    }
#endif /* _INITIALIZE_FROM_FILE */

#ifdef _INITIALIZE_FROM_TOTALMELTDOWN
    // Initialize VMM DLL from a linked PCILeech with the TotalMeltdown exploit.
    printf("------------------------------------------------------------\n");
    printf("#01: Initialize from TotalMeltdown:                         \n");
    ShowKeyPress();
    printf("CALL:    VMMDLL_Initialize\n");
    result = result = VMMDLL_Initialize(3, (LPSTR[]) { "", "-device", "totalmeltdown" });
    if(result) {
        printf("SUCCESS: VMMDLL_Initialize\n");
    } else {
        printf("FAIL:    VMMDLL_Initialize\n");
        return 1;
    }
#endif /* _INITIALIZE_FROM_TOTALMELTDOWN */

#ifdef _INITIALIZE_FROM_FPGA
    // Initialize VMM DLL from a linked PCILeech with a FPGA hardware device
    printf("------------------------------------------------------------\n");
    printf("#01: Initialize from FPGA:                                  \n");
    ShowKeyPress();
    printf("CALL:    VMMDLL_Initialize\n");
    result = VMMDLL_Initialize(3, (LPSTR[]) { "", "-device", "fpga" });
    if(result) {
        printf("SUCCESS: VMMDLL_Initialize\n");
    } else {
        printf("FAIL:    VMMDLL_Initialize\n");
        return 1;
    }
    // Retrieve the ID of the FPPA (SP605/PCIeScreamer/AC701 ...) and the bitstream version
    ULONG64 qwID, qwVersionMajor, qwVersionMinor;
    ShowKeyPress();
    printf("CALL:    VMMDLL_ConfigGet\n");
    result =
        VMMDLL_ConfigGet(VMMDLL_OPT_DEVICE_FPGA_FPGA_ID, &qwID) &&
        VMMDLL_ConfigGet(VMMDLL_OPT_DEVICE_FPGA_VERSION_MAJOR, &qwVersionMajor) &&
        VMMDLL_ConfigGet(VMMDLL_OPT_DEVICE_FPGA_VERSION_MINOR, &qwVersionMinor);
    if(result) {
        printf("SUCCESS: VMMDLL_ConfigGet\n");
        printf("         ID = %lli\n", qwID);
        printf("         VERSION = %lli.%lli\n", qwVersionMajor, qwVersionMinor);
    } else {
        printf("FAIL:    VMMDLL_ConfigGet\n");
        return 1;
    }
    // Retrieve the read delay value (in microseconds uS) that is used by the
    // FPGA to pause in every read. Sometimes it may be a good idea to adjust
    // this (and other related values) to lower versions if the FPGA device
    // still works stable without errors. Use PCIleech_DeviceConfigSet to set
    // values.
    ULONG64 qwReadDelay;
    ShowKeyPress();
    printf("CALL:    VMMDLL_ConfigGet\n");
    result = VMMDLL_ConfigGet(VMMDLL_OPT_DEVICE_FPGA_DELAY_READ, &qwReadDelay);
    if(result) {
        printf("SUCCESS: VMMDLL_ConfigGet\n");
        printf("         FPGA Read Delay in microseconds (uS) = %lli\n", qwReadDelay);
    } else {
        printf("FAIL:    VMMDLL_ConfigGet\n");
        return 1;
    }
#endif /* _INITIALIZE_FROM_FPGA */


    // Read physical memory at physical address 0x1000 and display the first
    // 0x100 bytes on-screen.
    printf("------------------------------------------------------------\n");
    printf("#02: Read from physical memory (0x1000 bytes @ 0x1000).     \n");
    ShowKeyPress();
    printf("CALL:    VMMDLL_MemRead\n");
    result = VMMDLL_MemRead(-1, 0x1000, pbPage1, 0x1000);
    if(result) {
        printf("SUCCESS: VMMDLL_MemRead\n");
        PrintHexAscii(pbPage1, 0x100);
    } else {
        printf("FAIL:    VMMDLL_MemRead\n");
        return 1;
    }


    // Retrieve PID of explorer.exe
    // NB! if multiple explorer.exe exists only one will be returned by this
    // specific function call. Please see .h file for additional information
    // about how to retrieve the complete list of PIDs in the system by using
    // the function PCILeech_VmmProcessListPIDs instead.
    printf("------------------------------------------------------------\n");
    printf("#03: Get PID from the first 'explorer.exe' process found.   \n");
    ShowKeyPress();
    printf("CALL:    VMMDLL_PidGetFromName\n");
    result = VMMDLL_PidGetFromName("explorer.exe", &dwPID);
    if(result) {
        printf("SUCCESS: VMMDLL_PidGetFromName\n");
        printf("         PID = %i\n", dwPID);
    } else {
        printf("FAIL:    VMMDLL_PidGetFromName\n");
        return 1;
    }


    // Retrieve additional process information such as: name of the process,
    // PML4 (PageDirectoryBase) PML4-USER (if exists) and Process State.
    printf("------------------------------------------------------------\n");
    printf("#04: Get Process Information from 'explorer.exe'.           \n");
    ShowKeyPress();
    VMMDLL_PROCESS_INFORMATION ProcessInformation;
    SIZE_T cbProcessInformation = sizeof(VMMDLL_PROCESS_INFORMATION);
    ZeroMemory(&ProcessInformation, sizeof(VMMDLL_PROCESS_INFORMATION));
    ProcessInformation.magic = VMMDLL_PROCESS_INFORMATION_MAGIC;
    ProcessInformation.wVersion = VMMDLL_PROCESS_INFORMATION_VERSION;
    printf("CALL:    VMMDLL_ProcessGetInformation\n");
    result = VMMDLL_ProcessGetInformation(dwPID, &ProcessInformation, &cbProcessInformation);
    if(result) {
        printf("SUCCESS: VMMDLL_ProcessGetInformation\n");
        printf("         Name = %s\n", ProcessInformation.szName);
        printf("         PageDirectoryBase = 0x%016llx\n", ProcessInformation.paDTB);
        printf("         PageDirectoryBaseUser = 0x%016llx\n", ProcessInformation.paDTB_UserOpt);
        printf("         ProcessState = 0x%08x\n", ProcessInformation.dwState);
    } else {
        printf("FAIL:    VMMDLL_ProcessGetInformation\n");
        return 1;
    }


    // Retrieve the memory map from the page table. This function also tries to
    // make additional parsing to identify modules and tag the memory map with
    // them. This is done by multiple methods internally and may sometimes be
    // more resilient against anti-reversing techniques that may be employed in
    // some processes.
    printf("------------------------------------------------------------\n");
    printf("#05: Get Memory Map of 'explorer.exe'.                      \n");
    ShowKeyPress();
    ULONG64 cMemMapEntries;
    PVMMDLL_MEMMAP_ENTRY pMemMapEntries;
    printf("CALL:    VMMDLL_ProcessGetMemoryMap #1\n");
    result = VMMDLL_ProcessGetMemoryMap(dwPID, NULL, &cMemMapEntries, TRUE);
    if(result) {
        printf("SUCCESS: VMMDLL_ProcessGetMemoryMap #1\n");
        printf("         Count = %lli\n", cMemMapEntries);
    } else {
        printf("FAIL:    VMMDLL_ProcessGetMemoryMap #1\n");
        return 1;
    }
    pMemMapEntries = (PVMMDLL_MEMMAP_ENTRY)LocalAlloc(0, cMemMapEntries * sizeof(VMMDLL_MEMMAP_ENTRY));
    if(!pMemMapEntries) {
        printf("FAIL:    OutOfMemory\n");
        return 1;
    }
    printf("CALL:    VMMDLL_ProcessGetMemoryMap #2\n");
    result = VMMDLL_ProcessGetMemoryMap(dwPID, pMemMapEntries, &cMemMapEntries, TRUE);
    if(result) {
        printf("SUCCESS: VMMDLL_ProcessGetMemoryMap #2\n");
        printf("         #      #PAGES ADRESS_RANGE                      SRWX\n");
        printf("         ====================================================\n");
        for(i = 0; i < cMemMapEntries; i++) {
            printf(
                "         %04x %8x %016llx-%016llx %sr%s%s%s%s\n",
                i,
                (DWORD)pMemMapEntries[i].cPages,
                pMemMapEntries[i].AddrBase,
                pMemMapEntries[i].AddrBase + (pMemMapEntries[i].cPages << 12) - 1,
                pMemMapEntries[i].fPage & VMMDLL_MEMMAP_FLAG_PAGE_NS ? "-" : "s",
                pMemMapEntries[i].fPage & VMMDLL_MEMMAP_FLAG_PAGE_W ? "w" : "-",
                pMemMapEntries[i].fPage & VMMDLL_MEMMAP_FLAG_PAGE_NX ? "-" : "x",
                pMemMapEntries[i].szTag[0] ? (pMemMapEntries[i].fWoW64 ? " 32 " : "    ") : "",
                pMemMapEntries[i].szTag
            );
        }
    } else {
        printf("FAIL:    VMMDLL_ProcessGetMemoryMap #2\n");
        return 1;
    }


    // Retrieve the list of loaded DLLs from the process. Please note that this
    // list is retrieved by parsing in-process memory structures such as the
    // process environment block (PEB) which may be partly destroyed in some
    // processes due to obfuscation and anti-reversing. If that is the case the
    // memory map may use alternative parsing techniques to list DLLs.
    printf("------------------------------------------------------------\n");
    printf("#06: Get Module Map of 'explorer.exe'.                      \n");
    ShowKeyPress();
    ULONG64 cModules;
    PVMMDLL_MODULEMAP_ENTRY pModules;
    printf("CALL:    VMMDLL_ProcessGetModuleMap #1\n");
    result = VMMDLL_ProcessGetModuleMap(dwPID, NULL, &cModules);
    if(result) {
        printf("SUCCESS: VMMDLL_ProcessGetModuleMap #1\n");
        printf("         Count = %lli\n", cModules);
    } else {
        printf("FAIL:    VMMDLL_ProcessGetModuleMap #1\n");
        return 1;
    }
    pModules = (PVMMDLL_MODULEMAP_ENTRY)LocalAlloc(0, cModules * sizeof(VMMDLL_MODULEMAP_ENTRY));
    if(!pModules) {
        printf("FAIL:    OutOfMemory\n");
        return 1;
    }
    printf("CALL:    VMMDLL_ProcessGetModuleMap #2\n");
    result = VMMDLL_ProcessGetModuleMap(dwPID, pModules, &cModules);
    if(result) {
        printf("SUCCESS: VMMDLL_ProcessGetModuleMap #2\n");
        printf("         MODULE_NAME                                 BASE             SIZE     ENTRY\n");
        printf("         ======================================================================================\n");
        for(i = 0; i < cModules; i++) {
            printf(
                "         %-40.40s %i %016llx %08x %016llx\n",
                pModules[i].szName,
                pModules[i].fWoW64 ? 32 : 64,
                pModules[i].BaseAddress,
                pModules[i].SizeOfImage,
                pModules[i].EntryPoint           
            );
        }
    } else {
        printf("FAIL:    VMMDLL_ProcessGetModuleMap #2\n");
        return 1;
    }


    // Retrieve the module of kernel32.dll by its name. Note it is also possible
    // to retrieve it by retrieving the complete module map (list) and iterate
    // over it. But if the name of the module is known this is more convenient.
    // This required that the PEB and LDR list in-process haven't been tampered
    // with ...
    printf("------------------------------------------------------------\n");
    printf("#07: Get by name 'kernel32.dll' in 'explorer.exe'.          \n");
    ShowKeyPress();
    VMMDLL_MODULEMAP_ENTRY ModuleEntry;
    printf("CALL:    VMMDLL_ProcessGetModuleFromName\n");
    result = VMMDLL_ProcessGetModuleFromName(dwPID, "kernel32.dll", &ModuleEntry);
    if(result) {
        printf("SUCCESS: VMMDLL_ProcessGetModuleFromName\n");
        printf("         MODULE_NAME                                 BASE             SIZE     ENTRY\n");
        printf("         ======================================================================================\n");
        printf(
            "         %-40.40s %i %016llx %08x %016llx\n",
            ModuleEntry.szName,
            ModuleEntry.fWoW64 ? 32 : 64,
            ModuleEntry.BaseAddress,
            ModuleEntry.SizeOfImage,
            ModuleEntry.EntryPoint
        );
    } else {
        printf("FAIL:    VMMDLL_ProcessGetModuleFromName\n");
        return 1;
    }


    // Retrieve the memory at the base of kernel32.dll previously fetched and
    // display the first 0x200 bytes of it. This read is fetched from the cache
    // by default (if possible). If reads should be forced from the DMA device
    // please specify the flag: VMM_FLAG_NOCACHE
    printf("------------------------------------------------------------\n");
    printf("#08: Read 0x200 bytes of 'kernel32.dll' in 'explorer.exe'.  \n");
    ShowKeyPress();
    DWORD cRead;
    printf("CALL:    VMMDLL_MemReadEx\n");
    result = VMMDLL_MemReadEx(dwPID, ModuleEntry.BaseAddress, pbPage2, 0x1000, &cRead, 0);                      // standard cached read
    //result = VMMDLL_MemReadEx(dwPID, ModuleEntry.BaseAddress, pbPage2, 0x1000, &cRead, VMMDLL_FLAG_NOCACHE);    // uncached read
    if(result) {
        printf("SUCCESS: VMMDLL_MemReadEx\n");
        PrintHexAscii(pbPage2, min(cRead, 0x200));
    } else {
        printf("FAIL:    VMMDLL_MemReadEx\n");
        return 1;
    }


    // List the sections from the module of kernel32.dll.
    printf("------------------------------------------------------------\n");
    printf("#09: List sections of 'kernel32.dll' in 'explorer.exe'.     \n");
    ShowKeyPress();
    DWORD cSections;
    PIMAGE_SECTION_HEADER pSectionHeaders;
    printf("CALL:    VMMDLL_ProcessGetSections #1\n");
    result = VMMDLL_ProcessGetSections(dwPID, "kernel32.dll", NULL, 0, &cSections);
    if(result) {
        printf("SUCCESS: VMMDLL_ProcessGetSections #1\n");
        printf("         Count = %lli\n", cModules);
    } else {
        printf("FAIL:    VMMDLL_ProcessGetSections #1\n");
        return 1;
    }
    pSectionHeaders = (PIMAGE_SECTION_HEADER)LocalAlloc(LMEM_ZEROINIT, cSections * sizeof(IMAGE_SECTION_HEADER));
    if(!pModules) {
        printf("FAIL:    OutOfMemory\n");
        return 1;
    }
    printf("CALL:    VMMDLL_ProcessGetSections #2\n");
    result = VMMDLL_ProcessGetSections(dwPID, "kernel32.dll", pSectionHeaders, cSections, &cSections);
    if(result) {
        printf("SUCCESS: VMMDLL_ProcessGetSections #2\n");
        printf("         #  NAME     OFFSET   SIZE     RWX\n");
        printf("         =================================\n");
        for(i = 0; i < cSections; i++) {
            printf(
                "         %02lx %-8.8s %08x %08x %c%c%c\n",
                i,
                pSectionHeaders[i].Name,
                pSectionHeaders[i].VirtualAddress,
                pSectionHeaders[i].Misc.VirtualSize,
                (pSectionHeaders[i].Characteristics & IMAGE_SCN_MEM_READ) ? 'r' : '-',
                (pSectionHeaders[i].Characteristics & IMAGE_SCN_MEM_WRITE) ? 'w' : '-',
                (pSectionHeaders[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) ? 'x' : '-'
            );
        }
    } else {
        printf("FAIL:    VMMDLL_ProcessGetSections #2\n");
        return 1;
    }


    // Retrieve and display the data directories of kernel32.dll. The number of
    // data directories in a PE is always 16 - so this can be used to simplify
    // calling the functionality somewhat.
    printf("------------------------------------------------------------\n");
    printf("#10: List directories of 'kernel32.dll' in 'explorer.exe'.  \n");
    ShowKeyPress();
    LPCSTR DIRECTORIES[16] = { "EXPORT", "IMPORT", "RESOURCE", "EXCEPTION", "SECURITY", "BASERELOC", "DEBUG", "ARCHITECTURE", "GLOBALPTR", "TLS", "LOAD_CONFIG", "BOUND_IMPORT", "IAT", "DELAY_IMPORT", "COM_DESCRIPTOR", "RESERVED" };
    DWORD cDirectories;
    IMAGE_DATA_DIRECTORY pDirectories[16];
    printf("CALL:    VMMDLL_ProcessGetDirectories\n");
    result = VMMDLL_ProcessGetDirectories(dwPID, "kernel32.dll", pDirectories, 16, &cDirectories);
    if(result) {
        printf("SUCCESS: PCIleech_VmmProcess_GetDirectories\n");
        printf("         #  NAME             OFFSET   SIZE\n");
        printf("         =====================================\n");
        for(i = 0; i < 16; i++) {
            printf(
                "         %02lx %-16.16s %08x %08x\n",
                i,
                DIRECTORIES[i],
                pDirectories[i].VirtualAddress,
                pDirectories[i].Size
            );
        }
    } else {
        printf("FAIL:    VMMDLL_ProcessGetDirectories\n");
        return 1;
    }


    // Retrieve the export address table (EAT) of kernel32.dll
    printf("------------------------------------------------------------\n");
    printf("#11: exports of 'kernel32.dll' in 'explorer.exe'.           \n");
    ShowKeyPress();
    DWORD cEATs;
    PVMMDLL_EAT_ENTRY pEATs;
    printf("CALL:    VMMDLL_ProcessGetEAT #1\n");
    result = VMMDLL_ProcessGetEAT(dwPID, "kernel32.dll", NULL, 0, &cEATs);
    if(result) {
        printf("SUCCESS: VMMDLL_ProcessGetEAT #1\n");
        printf("         Count = %i\n", cEATs);
    } else {
        printf("FAIL:    VMMDLL_ProcessGetEAT #1\n");
        return 1;
    }
    pEATs = (PVMMDLL_EAT_ENTRY)LocalAlloc(LMEM_ZEROINIT, cEATs * sizeof(VMMDLL_EAT_ENTRY));
    if(!pEATs) {
        printf("FAIL:    OutOfMemory\n");
        return 1;
    }
    printf("CALL:    VMMDLL_ProcessGetEAT #2\n");
    result = VMMDLL_ProcessGetEAT(dwPID, "kernel32.dll", pEATs, cEATs, &cEATs);
    if(result) {
        printf("SUCCESS: VMMDLL_ProcessGetEAT #2\n");
        printf("         #    OFFSET   NAME\n");
        printf("         =================================\n");
        for(i = 0; i < cEATs; i++) {
            printf(
                "         %04lx %08x %s\n",
                i,
                pEATs[i].vaFunctionOffset,
                pEATs[i].szFunction
            );
        }
    } else {
        printf("FAIL:    VMMDLL_ProcessGetEAT #2\n");
        return 1;
    }


    // Retrieve the import address table (IAT) of kernel32.dll
    printf("------------------------------------------------------------\n");
    printf("#12: imports of 'kernel32.dll' in 'explorer.exe'.           \n");
    ShowKeyPress();
    DWORD cIATs;
    PVMMDLL_IAT_ENTRY pIATs;
    printf("CALL:    VMMDLL_ProcessGetIAT #1\n");
    result = VMMDLL_ProcessGetIAT(dwPID, "kernel32.dll", NULL, 0, &cIATs);
    if(result) {
        printf("SUCCESS: VMMDLL_ProcessGetIAT #1\n");
        printf("         Count = %i\n", cIATs);
    } else {
        printf("FAIL:    VMMDLL_ProcessGetIAT #1\n");
        return 1;
    }
    pIATs = (PVMMDLL_IAT_ENTRY)LocalAlloc(LMEM_ZEROINIT, cIATs * sizeof(VMMDLL_IAT_ENTRY));
    if(!pIATs) {
        printf("FAIL:    OutOfMemory\n");
        return 1;
    }
    printf("CALL:    VMMDLL_ProcessGetIAT #2\n");
    result = VMMDLL_ProcessGetIAT(dwPID, "kernel32.dll", pIATs, cIATs, &cIATs);
    if(result) {
        printf("SUCCESS: VMMDLL_ProcessGetIAT #2\n");
        printf("         #    VIRTUAL_ADDRESS    MODULE!NAME\n");
        printf("         ===================================\n");
        for(i = 0; i < cIATs; i++) {
            printf(
                "         %04lx %016llx   %s!%s\n",
                i,
                pIATs[i].vaFunction,
                pIATs[i].szModule,
                pIATs[i].szFunction
            );
        }
    } else {
        printf("FAIL:    VMMDLL_ProcessGetIAT #2\n");
        return 1;
    }


    // The Memory Process File System exists virtually in the form of a virtual
    // file system even if it may not be mounted at a mount point or drive.
    // It is possible to call the functions 'List', 'Read' and 'Write' by using
    // the API.
    // Virtual File System: 'List'.
    printf("------------------------------------------------------------\n");
    printf("#13: call the file system 'List' function on the root dir.  \n");
    ShowKeyPress();
    VMMDLL_VFS_FILELIST VfsFileList;
    VfsFileList.h = 0; // your handle passed to the callback functions (not used in example).
    VfsFileList.pfnAddDirectory = CallbackList_AddDirectory;
    VfsFileList.pfnAddFile = CallbackList_AddFile;
    printf("CALL:    VMMDLL_VfsList\n");
    result = VMMDLL_VfsList(L"\\", &VfsFileList);
    if(result) {
        printf("SUCCESS: VMMDLL_VfsList\n");
    } else {
        printf("FAIL:    VMMDLL_VfsList\n");
        return 1;
    }


    // Virtual File System: 'Read' of 0x100 bytes from the offset 0x1000
    // in the physical memory by reading the /pmem physical memory file.
    printf("------------------------------------------------------------\n");
    printf("#14: call the file system 'Read' function on the pmem file. \n");
    ShowKeyPress();
    printf("CALL:    VMMDLL_VfsRead\n");
    nt = VMMDLL_VfsRead(L"\\pmem", pbPage1, 0x100, &i, 0x1000);
    if(nt == VMMDLL_STATUS_SUCCESS) {
        printf("SUCCESS: VMMDLL_VfsRead\n");
        PrintHexAscii(pbPage1, i);
    } else {
        printf("FAIL:    VMMDLL_VfsRead\n");
        return 1;
    }


    // Initialize plugin manager so that statistics may be read in the
    // following read call to the .status built-in module/plugin.
    printf("------------------------------------------------------------\n");
    printf("#15: initialize virtual file system plugins                 \n");
    printf("     (this is required for following read call)             \n");
    ShowKeyPress();
    printf("CALL:    VMMDLL_VfsInitializePlugins\n");
    result = VMMDLL_VfsInitializePlugins();
    if(result) {
        printf("SUCCESS: VMMDLL_VfsInitializePlugins\n");
    } else {
        printf("FAIL:    VMMDLL_VfsInitializePlugins\n");
        return 1;
    }


    // Virtual File System: 'Read' statistics from the .status module/plugin.
    printf("------------------------------------------------------------\n");
    printf("#16: call file system 'Read' on .status\\statistics         \n");
    ShowKeyPress();
    printf("CALL:    VMMDLL_VfsRead\n");
    nt = VMMDLL_VfsRead(L"\\.status\\statistics", pbPage1, 0x1000, &i, 0);
    if(nt == VMMDLL_STATUS_SUCCESS) {
        printf("SUCCESS: VMMDLL_VfsRead\n");
        printf("%s", (LPSTR)pbPage1);
    } else {
        printf("FAIL:    VMMDLL_VfsRead\n");
        return 1;
    }


    // Get base virtual address of ntoskrnl.exe
    printf("------------------------------------------------------------\n");
    printf("#17: get ntoskrnl.exe base virtual address                  \n");
    ShowKeyPress();
    printf("CALL:    VMMDLL_ProcessGetModuleBase\n");
    va = VMMDLL_ProcessGetModuleBase(4, "ntoskrnl.exe");
    if(va) {
        printf("SUCCESS: VMMDLL_ProcessGetModuleBase\n");
        printf("         %s = %016llx\n", "ntoskrnl.exe", va);
    } else {
        printf("FAIL:    VMMDLL_ProcessGetModuleBase\n");
        return 1;
    }


    // GetProcAddress from ntoskrnl.exe
    printf("------------------------------------------------------------\n");
    printf("#18: get proc address for ntoskrnl.exe!KeGetCurrentIrql     \n");
    ShowKeyPress();
    printf("CALL:    VMMDLL_ProcessGetProcAddress\n");
    va = VMMDLL_ProcessGetProcAddress(4, "ntoskrnl.exe", "KeGetCurrentIrql");
    if(va) {
        printf("SUCCESS: VMMDLL_ProcessGetProcAddress\n");
        printf("         %s!%s = %016llx\n", "ntoskrnl.exe", "KeGetCurrentIrql", va);
    } else {
        printf("FAIL:    VMMDLL_ProcessGetProcAddress\n");
        return 1;
    }


    // Get EAT Thunk from ntoskrnl.exe!KeGetCurrentIrql
    printf("------------------------------------------------------------\n");
    printf("#19: Address of EAT thunk for ntoskrnl.exe!KeGetCurrentIrql \n");
    ShowKeyPress();
    VMMDLL_WIN_THUNKINFO_EAT oThunkInfoEAT;
    ZeroMemory(&oThunkInfoEAT, sizeof(VMMDLL_WIN_THUNKINFO_EAT));
    printf("CALL:    VMMDLL_WinGetThunkInfoEAT\n");
    result = VMMDLL_WinGetThunkInfoEAT(4, "ntoskrnl.exe", "KeGetCurrentIrql", &oThunkInfoEAT);
    if(result) {
        printf("SUCCESS: VMMDLL_WinGetThunkInfoEAT\n");
        printf("         vaFunction:     %016llx\n", oThunkInfoEAT.vaFunction);
        printf("         vaThunk:        %016llx\n", oThunkInfoEAT.vaThunk);
        printf("         valueThunk:             %08x\n", oThunkInfoEAT.valueThunk);
        printf("         vaNameFunc:     %016llx\n", oThunkInfoEAT.vaNameFunction);
    } else {
        printf("FAIL:    VMMDLL_WinGetThunkInfoEAT\n");
        return 1;
    }


    // Get IAT Thunk ntoskrnl.exe -> hal.dll!HalSendNMI
    printf("------------------------------------------------------------\n");
    printf("#20: Address of IAT thunk for hal.dll!HalSendNMI in ntoskrnl\n");
    ShowKeyPress();
    VMMDLL_WIN_THUNKINFO_IAT oThunkInfoIAT;
    ZeroMemory(&oThunkInfoIAT, sizeof(VMMDLL_WIN_THUNKINFO_IAT));
    printf("CALL:    VMMDLL_WinGetThunkInfoIAT\n");
    result = VMMDLL_WinGetThunkInfoIAT(4, "ntoskrnl.Exe", "hal.Dll", "HalSendNMI", &oThunkInfoIAT);
    if(result) {
        printf("SUCCESS: VMMDLL_WinGetThunkInfoIAT\n");
        printf("         vaFunction:     %016llx\n", oThunkInfoIAT.vaFunction);
        printf("         vaThunk:        %016llx\n", oThunkInfoIAT.vaThunk);
        printf("         vaNameFunction: %016llx\n", oThunkInfoIAT.vaNameFunction);
        printf("         vaNameModule:   %016llx\n", oThunkInfoIAT.vaNameModule);
    }
    else {
        printf("FAIL:    VMMDLL_WinGetThunkInfoEAT\n");
        return 1;
    }



    // Finish everything and exit!
    printf("------------------------------------------------------------\n");
    printf("#99: FINISHED EXAMPLES!                                     \n");
    ShowKeyPress();
    printf("FINISHED TEST CASES - EXITING!\n");
    return 0;
}
