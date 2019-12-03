// vmmdll_example.c - MemProcFS C/C++ VMM API usage examples
//
// Note that this is not a complete list of the VMM API. For the complete list please consult the vmmdll.h header file.
//
// (c) Ulf Frisk, 2018-2019
// Author: Ulf Frisk, pcileech@frizk.net
//

#include <Windows.h>
#include <stdio.h>
#include <conio.h>
#include "leechcore.h"
#include "vmmdll.h"

#pragma comment(lib, "leechcore")
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
    LPSTR sz;
    DWORD szMax = 0;
    VMMDLL_UtilFillHexAscii(pb, cb, 0, NULL, &szMax);
    if(!(sz = LocalAlloc(0, szMax))) { return; }
    VMMDLL_UtilFillHexAscii(pb, cb, 0, sz, &szMax);
    printf(sz);
    LocalFree(sz);
}

VOID CallbackList_AddFile(_Inout_ HANDLE h, _In_opt_ LPSTR szName, _In_opt_ LPWSTR wszName, _In_ ULONG64 cb, _In_opt_ PVMMDLL_VFS_FILELIST_EXINFO pExInfo)
{
    if(szName) {
        printf("         FILE: '%s'\tSize: %lli\n", szName, cb);
    }
    if(wszName) {
        wprintf(L"         FILE: '%s'\tSize: %lli\n", wszName, cb);
    }
}

VOID CallbackList_AddDirectory(_Inout_ HANDLE h, _In_opt_ LPSTR szName, _In_opt_ LPWSTR wszName, _In_opt_ PVMMDLL_VFS_FILELIST_EXINFO pExInfo)
{
    if(szName) {
        printf("         DIR:  '%s'\n", szName);
    }
    if(wszName) {
        wprintf(L"         DIR:  '%s'\n", wszName);
    }
}

VOID VadMap_Protection(_In_ PVMMDLL_MAP_VADENTRY pVad, _Out_writes_(6) LPSTR sz)
{
    BYTE vh = (BYTE)pVad->Protection >> 3;
    BYTE vl = (BYTE)pVad->Protection & 7;
    sz[0] = pVad->fPrivateMemory ? 'p' : '-';                                    // PRIVATE MEMORY
    sz[1] = (vh & 2) ? ((vh & 1) ? 'm' : 'g') : ((vh & 1) ? 'n' : '-');         // -/NO_CACHE/GUARD/WRITECOMBINE
    sz[2] = ((vl == 1) || (vl == 3) || (vl == 4) || (vl == 6)) ? 'r' : '-';     // COPY ON WRITE
    sz[3] = (vl & 4) ? 'w' : '-';                                               // WRITE
    sz[4] = (vl & 2) ? 'x' : '-';                                               // EXECUTE
    sz[5] = ((vl == 5) || (vl == 7)) ? 'c' : '-';                               // COPY ON WRITE
    if(sz[1] != '-' && sz[2] == '-' && sz[3] == '-' && sz[4] == '-' && sz[5] == '-') { sz[1] = '-'; }
}

LPSTR VadMap_Type(_In_ PVMMDLL_MAP_VADENTRY pVad)
{
    if(pVad->fImage) {
        return "Image";
    } else if(pVad->fFile) {
        return "File ";
    } else if(pVad->fHeap) {
        return "Heap ";
    } else if(pVad->fStack) {
        return "Stack";
    } else if(pVad->fTeb) {
        return "Teb  ";
    } else if(pVad->fPageFile) {
        return "Pf   ";
    } else {
        return "     ";
    }
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
    result = VMMDLL_Initialize(3, (LPSTR[]) { "", "-device", _INITIALIZE_FROM_FILE });
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
        VMMDLL_ConfigGet(LEECHCORE_OPT_FPGA_FPGA_ID, &qwID) &&
        VMMDLL_ConfigGet(LEECHCORE_OPT_FPGA_VERSION_MAJOR, &qwVersionMajor) &&
        VMMDLL_ConfigGet(LEECHCORE_OPT_FPGA_VERSION_MINOR, &qwVersionMinor);
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
    result = VMMDLL_ConfigGet(LEECHCORE_OPT_FPGA_DELAY_READ, &qwReadDelay);
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


    // Write physical memory at physical address 0x1000 and display the first
    // 0x100 bytes on-screen - afterwards. Maybe result of write is in there?
    // (only if device is capable of writes and target system accepts writes)
    printf("------------------------------------------------------------\n");
    printf("#03: Try write to physical memory at address 0x1000.        \n");
    printf("     NB! Write capable device is required for success!      \n");
    printf("     (1) Read existing data from physical memory.           \n");
    printf("     (2) Try write to physical memory at 0x1000.            \n");
    printf("         Bytes written:  11112222333344445555666677778888   \n");
    printf("     (3) Read resulting data from physical memory.          \n");
    ShowKeyPress();
    printf("CALL:    VMMDLL_MemRead - BEFORE WRITE\n");
    result = VMMDLL_MemRead(-1, 0x1000, pbPage1, 0x1000);
    if(result) {
        printf("SUCCESS: VMMDLL_MemRead - BEFORE WRITE\n");
        PrintHexAscii(pbPage1, 0x100);
    } else {
        printf("FAIL:    VMMDLL_MemRead - BEFORE WRITE\n");
        return 1;
    }
    printf("CALL:    VMMDLL_MemWrite\n");
    DWORD cbWriteDataPhysical = 0x20;
    BYTE pbWriteDataPhysical[0x20] = {
        0x11, 0x11, 0x11, 0x11, 0x22, 0x22, 0x22, 0x22,
        0x33, 0x33, 0x33, 0x33, 0x44, 0x44, 0x44, 0x44,
        0x55, 0x55, 0x55, 0x55, 0x66, 0x66, 0x66, 0x66,
        0x77, 0x77, 0x77, 0x77, 0x88, 0x88, 0x88, 0x88,
    };
    VMMDLL_MemWrite(-1, 0x1000, pbWriteDataPhysical, cbWriteDataPhysical);
    printf("CALL:    VMMDLL_MemRead - AFTER WRITE\n");
    result = VMMDLL_MemRead(-1, 0x1000, pbPage1, 0x1000);
    if(result) {
        printf("SUCCESS: VMMDLL_MemRead - AFTER WRITE\n");
        PrintHexAscii(pbPage1, 0x100);
    } else {
        printf("FAIL:    VMMDLL_MemRead - AFTER WRITE\n");
        return 1;
    }


    // Retrieve PID of explorer.exe
    // NB! if multiple explorer.exe exists only one will be returned by this
    // specific function call. Please see .h file for additional information
    // about how to retrieve the complete list of PIDs in the system by using
    // the function PCILeech_VmmProcessListPIDs instead.
    printf("------------------------------------------------------------\n");
    printf("#04: Get PID from the first 'explorer.exe' process found.   \n");
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
    printf("#05: Get Process Information from 'explorer.exe'.           \n");
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
        printf("         PID = 0x%08x\n", ProcessInformation.dwPID);
        printf("         ParentPID = 0x%08x\n", ProcessInformation.dwPPID);
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
    printf("#06: Get PTE Memory Map of 'explorer.exe'.                  \n");
    ShowKeyPress();
    DWORD cbPteMap = 0;
    PVMMDLL_MAP_PTE pPteMap = NULL;
    PVMMDLL_MAP_PTEENTRY pPteMapEntry;
    printf("CALL:    VMMDLL_ProcessMap_GetPte #1\n");
    result = VMMDLL_ProcessMap_GetPte(dwPID, NULL, &cbPteMap, TRUE);
    if(result) {
        printf("SUCCESS: VMMDLL_ProcessMap_GetPte #1\n");
        printf("         ByteCount = %i\n", cbPteMap);
    } else {
        printf("FAIL:    VMMDLL_ProcessMap_GetPte #1\n");
        return 1;
    }
    pPteMap = (PVMMDLL_MAP_PTE)LocalAlloc(0, cbPteMap);
    if(!pPteMap) {
        printf("FAIL:    OutOfMemory\n");
        return 1;
    }
    printf("CALL:    VMMDLL_ProcessMap_GetPte #2\n");
    result = VMMDLL_ProcessMap_GetPte(dwPID, pPteMap, &cbPteMap, TRUE);
    if(result) {
        printf("SUCCESS: VMMDLL_ProcessMap_GetPte #2\n");
        printf("         #      #PAGES ADRESS_RANGE                      SRWX\n");
        printf("         ====================================================\n");
        for(i = 0; i < pPteMap->cMap; i++) {
            pPteMapEntry = &pPteMap->pMap[i];
            printf(
                "         %04x %8x %016llx-%016llx %sr%s%s%s%S\n",
                i,
                (DWORD)pPteMapEntry->cPages,
                pPteMapEntry->vaBase,
                pPteMapEntry->vaBase + (pPteMapEntry->cPages << 12) - 1,
                pPteMapEntry->fPage & VMMDLL_MEMMAP_FLAG_PAGE_NS ? "-" : "s",
                pPteMapEntry->fPage & VMMDLL_MEMMAP_FLAG_PAGE_W ? "w" : "-",
                pPteMapEntry->fPage & VMMDLL_MEMMAP_FLAG_PAGE_NX ? "-" : "x",
                pPteMapEntry->cwszText ? (pPteMapEntry->fWoW64 ? " 32 " : "    ") : "",
                pPteMapEntry->wszText
            );
        }
    } else {
        printf("FAIL:    VMMDLL_ProcessMap_GetPte #2\n");
        return 1;
    }
    LocalFree(pPteMap);
    pPteMap = NULL;


    // Retrieve the memory map from the virtual address descriptors (VAD). This
    // function also makes additional parsing to identify modules and tag the
    // memory map with them.
    printf("------------------------------------------------------------\n");
    printf("#07: Get VAD Memory Map of 'explorer.exe'.                  \n");
    ShowKeyPress();
    CHAR szVadProtection[7] = { 0 };
    DWORD cbVadMap = 0;
    PVMMDLL_MAP_VAD pVadMap = NULL;
    PVMMDLL_MAP_VADENTRY pVadMapEntry;
    printf("CALL:    VMMDLL_ProcessMap_GetVad #1\n");
    result = VMMDLL_ProcessMap_GetVad(dwPID, NULL, &cbVadMap, TRUE);
    if(result) {
        printf("SUCCESS: VMMDLL_ProcessMap_GetVad #1\n");
        printf("         ByteCount = %i\n", cbVadMap);
    } else {
        printf("FAIL:    VMMDLL_ProcessMap_GetVad #1\n");
        return 1;
    }
    pVadMap = (PVMMDLL_MAP_VAD)LocalAlloc(0, cbVadMap);
    if(!pVadMap) {
        printf("FAIL:    OutOfMemory\n");
        return 1;
    }
    printf("CALL:    VMMDLL_ProcessMap_GetVad #2\n");
    result = VMMDLL_ProcessMap_GetVad(dwPID, pVadMap, &cbVadMap, TRUE);
    if(result) {
        printf("SUCCESS: VMMDLL_ProcessMap_GetVad #2\n");
        printf("         #    ADRESS_RANGE                      KERNEL_ADDR        TYPE  PROT   INFO \n");
        printf("         ============================================================================\n");
        for(i = 0; i < pVadMap->cMap; i++) {
            pVadMapEntry = &pVadMap->pMap[i];
            VadMap_Protection(pVadMapEntry, szVadProtection);
            printf(
                "         %04x %016llx-%016llx [%016llx] %s %s %S\n",
                i,
                pVadMapEntry->vaStart,
                pVadMapEntry->vaEnd,
                pVadMapEntry->vaVad,
                VadMap_Type(pVadMapEntry),
                szVadProtection,
                pVadMapEntry->wszText
            );
        }
    } else {
        printf("FAIL:    VMMDLL_ProcessMap_GetVad #2\n");
        return 1;
    }
    LocalFree(pVadMap);
    pVadMap = NULL;


    // Retrieve the list of loaded DLLs from the process. Please note that this
    // list is retrieved by parsing in-process memory structures such as the
    // process environment block (PEB) which may be partly destroyed in some
    // processes due to obfuscation and anti-reversing. If that is the case the
    // memory map may use alternative parsing techniques to list DLLs.
    printf("------------------------------------------------------------\n");
    printf("#08: Get Module Map of 'explorer.exe'.                      \n");
    ShowKeyPress();
    DWORD cbModuleMap = 0;
    PVMMDLL_MAP_MODULE pModuleMap = NULL;
    printf("CALL:    VMMDLL_ProcessMap_GetModule #1\n");
    result = VMMDLL_ProcessMap_GetModule(dwPID, NULL, &cbModuleMap);
    if(result) {
        printf("SUCCESS: VMMDLL_ProcessMap_GetModule #1\n");
        printf("         ByteCount = %i\n", cbModuleMap);
    } else {
        printf("FAIL:    VMMDLL_ProcessMap_GetModule #1\n");
        return 1;
    }
    pModuleMap = (PVMMDLL_MAP_MODULE)LocalAlloc(0, cbModuleMap);
    if(!pModuleMap) {
        printf("FAIL:    OutOfMemory\n");
        return 1;
    }
    printf("CALL:    VMMDLL_ProcessMap_GetModule #2\n");
    result = VMMDLL_ProcessMap_GetModule(dwPID, pModuleMap, &cbModuleMap);
    if(result) {
        printf("SUCCESS: VMMDLL_ProcessMap_GetModule #2\n");
        printf("         MODULE_NAME                                 BASE             SIZE     ENTRY\n");
        printf("         ======================================================================================\n");
        for(i = 0; i < pModuleMap->cMap; i++) {
            printf(
                "         %-40.40S %i %016llx %08x %016llx\n",
                pModuleMap->pMap[i].wszText,
                pModuleMap->pMap[i].fWoW64 ? 32 : 64,
                pModuleMap->pMap[i].vaBase,
                pModuleMap->pMap[i].cbImageSize,
                pModuleMap->pMap[i].vaEntry
            );
        }
    } else {
        printf("FAIL:    VMMDLL_ProcessMap_GetModule #2\n");
        return 1;
    }
    LocalFree(pModuleMap);
    pModuleMap = NULL;


    // Retrieve the module of explorer.exe by its name. Note it is also possible
    // to retrieve it by retrieving the complete module map (list) and iterate
    // over it. But if the name of the module is known this is more convenient.
    // This required that the PEB and LDR list in-process haven't been tampered
    // with ...
    printf("------------------------------------------------------------\n");
    printf("#09: Get module by name 'explorer.exe' in 'explorer.exe'.   \n");
    ShowKeyPress();
    printf("CALL:    VMMDLL_ProcessMap_GetModuleFromName\n");
    VMMDLL_MAP_MODULEENTRY ModuleEntryExplorer;
    result = VMMDLL_ProcessMap_GetModuleFromName(dwPID, L"explorer.exe", &ModuleEntryExplorer);
    if(result) {
        printf("SUCCESS: VMMDLL_ProcessMap_GetModuleFromName\n");
        printf("         MODULE_NAME                                 BASE             SIZE     ENTRY\n");
        printf("         ======================================================================================\n");
        printf(
            "         %-40.40S %i %016llx %08x %016llx\n",
            L"explorer.exe",
            ModuleEntryExplorer.fWoW64 ? 32 : 64,
            ModuleEntryExplorer.vaBase,
            ModuleEntryExplorer.cbImageSize,
            ModuleEntryExplorer.vaEntry
        );
    } else {
        printf("FAIL:    VMMDLL_ProcessMap_GetModuleFromName\n");
        return 1;
    }


    // THREADS: Retrieve thread information about threads in the explorer.exe
    // process and display on the screen.
    printf("------------------------------------------------------------\n");
    printf("#10: Get Thread Information of 'explorer.exe'.              \n");
    ShowKeyPress();
    DWORD cbThreadMap = 0;
    PVMMDLL_MAP_THREAD pThreadMap = NULL;
    PVMMDLL_MAP_THREADENTRY pThreadMapEntry;
    printf("CALL:    VMMDLL_ProcessMap_GetThread #1\n");
    result = VMMDLL_ProcessMap_GetThread(dwPID, NULL, &cbThreadMap);
    if(result) {
        printf("SUCCESS: VMMDLL_ProcessMap_GetThread #1\n");
        printf("         ByteCount = %i\n", cbThreadMap);
    } else {
        printf("FAIL:    VMMDLL_ProcessMap_GetThread #1\n");
        return 1;
    }
    pThreadMap = (PVMMDLL_MAP_THREAD)LocalAlloc(0, cbThreadMap);
    if(!pThreadMap) {
        printf("FAIL:    OutOfMemory\n");
        return 1;
    }
    printf("CALL:    VMMDLL_ProcessMap_GetThread #2\n");
    result = VMMDLL_ProcessMap_GetThread(dwPID, pThreadMap, &cbThreadMap);
    if(result) {
        printf("SUCCESS: VMMDLL_ProcessMap_GetThread #2\n");
        printf("         #         TID      PID ADDR_TEB         ADDR_ETHREAD     ADDR_START       STACK\n");
        printf("         ===============================================================================\n");
        for(i = 0; i < pThreadMap->cMap; i++) {
            pThreadMapEntry = &pThreadMap->pMap[i];
            printf(
                "         %04x %8x %8x %016llx %016llx %016llx [%016llx->%016llx]\n",
                i,
                pThreadMapEntry->dwTID,
                pThreadMapEntry->dwPID,
                pThreadMapEntry->vaTeb,
                pThreadMapEntry->vaETHREAD,
                pThreadMapEntry->vaStartAddress,
                pThreadMapEntry->vaStackBaseUser,
                pThreadMapEntry->vaStackLimitUser
            );
        }
    } else {
        printf("FAIL:    VMMDLL_ProcessMap_GetThread #2\n");
        return 1;
    }
    LocalFree(pThreadMap);
    pThreadMap = NULL;


    // THREADS: Retrieve handle information about handles in the explorer.exe
    // process and display on the screen.
    printf("------------------------------------------------------------\n");
    printf("#11: Get Handle Information of 'explorer.exe'.              \n");
    ShowKeyPress();
    DWORD cbHandleMap = 0;
    PVMMDLL_MAP_HANDLE pHandleMap = NULL;
    PVMMDLL_MAP_HANDLEENTRY pHandleMapEntry;
    printf("CALL:    VMMDLL_ProcessMap_GetHandle #1\n");
    result = VMMDLL_ProcessMap_GetHandle(dwPID, NULL, &cbHandleMap);
    if(result) {
        printf("SUCCESS: VMMDLL_ProcessMap_GetHandle #1\n");
        printf("         ByteCount = %i\n", cbHandleMap);
    } else {
        printf("FAIL:    VMMDLL_ProcessMap_GetHandle #1\n");
        return 1;
    }
    pHandleMap = (PVMMDLL_MAP_HANDLE)LocalAlloc(0, cbHandleMap);
    if(!pHandleMap) {
        printf("FAIL:    OutOfMemory\n");
        return 1;
    }
    printf("CALL:    VMMDLL_ProcessMap_GetHandle #2\n");
    result = VMMDLL_ProcessMap_GetHandle(dwPID, pHandleMap, &cbHandleMap);
    if(result) {
        printf("SUCCESS: VMMDLL_ProcessMap_GetHandle #2\n");
        printf("         #         HANDLE   PID ADDR_OBJECT      ACCESS TYPE             DESCRIPTION\n");
        printf("         ===========================================================================\n");
        for(i = 0; i < pHandleMap->cMap; i++) {
            pHandleMapEntry = &pHandleMap->pMap[i];
            printf(
                "         %04x %8x %8x %016llx %6x %-16S %S\n",
                i,
                pHandleMapEntry->dwHandle,
                pHandleMapEntry->dwPID,
                pHandleMapEntry->vaObject,
                pHandleMapEntry->dwGrantedAccess,
                pHandleMapEntry->wszType,
                pHandleMapEntry->wszText
            );
        }
    } else {
        printf("FAIL:    VMMDLL_ProcessMap_GetHandle #2\n");
        return 1;
    }
    LocalFree(pHandleMap);
    pHandleMap = NULL;


    // Write virtual memory at PE header of Explorer.EXE and display the first
    // 0x80 bytes on-screen - afterwards. Maybe result of write is in there?
    // (only if device is capable of writes and target system accepts writes)
    printf("------------------------------------------------------------\n");
    printf("#12: Try write to virtual memory of Explorer.EXE PE header  \n");
    printf("     NB! Write capable device is required for success!      \n");
    printf("     (1) Read existing data from virtual memory.            \n");
    printf("     (2) Try write to virtual memory at PE header.          \n");
    printf("     (3) Read resulting data from virtual memory.           \n");
    ShowKeyPress();
    printf("CALL:    VMMDLL_MemRead - BEFORE WRITE\n");
    result = VMMDLL_MemRead(dwPID, ModuleEntryExplorer.vaBase, pbPage1, 0x1000);
    if(result) {
        printf("SUCCESS: VMMDLL_MemRead - BEFORE WRITE\n");
        PrintHexAscii(pbPage1, 0x80);
    } else {
        printf("FAIL:    VMMDLL_MemRead - BEFORE WRITE\n");
        return 1;
    }
    printf("CALL:    VMMDLL_MemWrite\n");
    DWORD cbWriteDataVirtual = 0x1c;
    BYTE pbWriteDataVirtual[0x1c] = {
        0x61, 0x6d, 0x20, 0x69, 0x73, 0x20, 0x6d, 0x6f,
        0x64, 0x69, 0x66, 0x69, 0x65, 0x64, 0x20, 0x62,
        0x79, 0x20, 0x4d, 0x65, 0x6d, 0x50, 0x72, 0x6f,
        0x63, 0x46, 0x53, 0x00,
    };
    VMMDLL_MemWrite(dwPID, ModuleEntryExplorer.vaBase + 0x58, pbWriteDataVirtual, cbWriteDataVirtual);
    printf("CALL:    VMMDLL_MemRead - AFTER WRITE\n");
    result = VMMDLL_MemRead(dwPID, ModuleEntryExplorer.vaBase, pbPage1, 0x1000);
    if(result) {
        printf("SUCCESS: VMMDLL_MemRead - AFTER WRITE\n");
        PrintHexAscii(pbPage1, 0x80);
    } else {
        printf("FAIL:    VMMDLL_MemRead - AFTER WRITE\n");
        return 1;
    }


    // Retrieve the module of kernel32.dll by its name. Note it is also possible
    // to retrieve it by retrieving the complete module map (list) and iterate
    // over it. But if the name of the module is known this is more convenient.
    // This required that the PEB and LDR list in-process haven't been tampered
    // with ...
    printf("------------------------------------------------------------\n");
    printf("#13: Get by name 'kernel32.dll' in 'explorer.exe'.          \n");
    ShowKeyPress();
    printf("CALL:    VMMDLL_ProcessMap_GetModuleFromName\n");
    VMMDLL_MAP_MODULEENTRY ModuleEntryKernel32;
    result = VMMDLL_ProcessMap_GetModuleFromName(dwPID, L"kernel32.dll", &ModuleEntryKernel32);
    if(result) {
        printf("SUCCESS: VMMDLL_ProcessMap_GetModuleFromName\n");
        printf("         MODULE_NAME                                 BASE             SIZE     ENTRY\n");
        printf("         ======================================================================================\n");
        printf(
            "         %-40.40S %i %016llx %08x %016llx\n",
            L"kernel32.dll",
            ModuleEntryKernel32.fWoW64 ? 32 : 64,
            ModuleEntryKernel32.vaBase,
            ModuleEntryKernel32.cbImageSize,
            ModuleEntryKernel32.vaEntry
        );
    } else {
        printf("FAIL:    VMMDLL_ProcessMap_GetModuleFromName\n");
        return 1;
    }


    // Retrieve the memory at the base of kernel32.dll previously fetched and
    // display the first 0x200 bytes of it. This read is fetched from the cache
    // by default (if possible). If reads should be forced from the DMA device
    // please specify the flag: VMM_FLAG_NOCACHE
    printf("------------------------------------------------------------\n");
    printf("#14: Read 0x200 bytes of 'kernel32.dll' in 'explorer.exe'.  \n");
    ShowKeyPress();
    DWORD cRead;
    printf("CALL:    VMMDLL_MemReadEx\n");
    result = VMMDLL_MemReadEx(dwPID, ModuleEntryKernel32.vaBase, pbPage2, 0x1000, &cRead, 0);                       // standard cached read
    //result = VMMDLL_MemReadEx(dwPID, ModuleEntryKernel32.vaBase, pbPage2, 0x1000, &cRead, VMMDLL_FLAG_NOCACHE);   // uncached read
    if(result) {
        printf("SUCCESS: VMMDLL_MemReadEx\n");
        PrintHexAscii(pbPage2, min(cRead, 0x200));
    } else {
        printf("FAIL:    VMMDLL_MemReadEx\n");
        return 1;
    }


    // List the sections from the module of kernel32.dll.
    printf("------------------------------------------------------------\n");
    printf("#15: List sections of 'kernel32.dll' in 'explorer.exe'.     \n");
    ShowKeyPress();
    printf("CALL:    VMMDLL_ProcessGetSections #1\n");
    DWORD cSections;
    PIMAGE_SECTION_HEADER pSectionHeaders;
    result = VMMDLL_ProcessGetSections(dwPID, L"kernel32.dll", NULL, 0, &cSections);
    if(result) {
        printf("SUCCESS: VMMDLL_ProcessGetSections #1\n");
        printf("         Count = %i\n", cSections);
    } else {
        printf("FAIL:    VMMDLL_ProcessGetSections #1\n");
        return 1;
    }
    pSectionHeaders = (PIMAGE_SECTION_HEADER)LocalAlloc(LMEM_ZEROINIT, cSections * sizeof(IMAGE_SECTION_HEADER));
    if(!pSectionHeaders) {
        printf("FAIL:    OutOfMemory\n");
        return 1;
    }
    printf("CALL:    VMMDLL_ProcessGetSections #2\n");
    result = VMMDLL_ProcessGetSections(dwPID, L"kernel32.dll", pSectionHeaders, cSections, &cSections);
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


    // Scatter Read memory from each of the sections of kernel32.dll in explorer.exe
    printf("------------------------------------------------------------\n");
    printf("#16: 0x20 bytes of each 'kernel32.dll' section.             \n");
    ShowKeyPress();
    PPMEM_IO_SCATTER_HEADER ppMEMs = NULL;
    // Allocate empty scatter entries and populate them with the virtual addresses of
    // the sections to read. If one wish to have a more efficient way of doing things
    // without lots of copying of memory it's possible to initialize the ppMEMs array
    // manually and set each individual MEM_IO_SCATTER_HEADER result byte buffer to
    // point into ones own pre-allocated data buffer.
    printf("CALL:    LeechCore_AllocScatterEmpty #1\n");
    if(LeechCore_AllocScatterEmpty(cSections, &ppMEMs)) {
        printf("SUCCESS: LeechCore_AllocScatterEmpty #1\n");
    } else {
        printf("FAIL:    LeechCore_AllocScatterEmpty #1\n");
        return 1;
    }
    for(i = 0; i < cSections; i++) {
        // populate the virtual address of each scatter entry with the address to read
        // (sections are assumed to be page-aligned in virtual memory.
        ppMEMs[i]->qwA = ModuleEntryKernel32.vaBase + pSectionHeaders[i].VirtualAddress;
    }
    // Scatter Read - read all scatter entries in one efficient go. In this
    // example the internal VMM cache is not to be used, and virtual memory
    // is not to be used. One can skip the flags to get default behaviour -
    // that is use cache and paging, and keep buffer byte data as-is on fail.
    printf("CALL:    VMMDLL_MemReadScatter #1\n");
    if(VMMDLL_MemReadScatter(dwPID, ppMEMs, cSections, VMMDLL_FLAG_NOCACHE | VMMDLL_FLAG_ZEROPAD_ON_FAIL | VMMDLL_FLAG_NOPAGING)) {
        printf("SUCCESS: VMMDLL_MemReadScatter #1\n");
    } else {
        printf("FAIL:    VMMDLL_MemReadScatter #1\n");
        return 1;
    }
    // print result
    for(i = 0; i < cSections; i++) {
        printf("--------------\n         %s\n", pSectionHeaders[i].Name);
        if(ppMEMs[i]->cb == 0x1000) {
            PrintHexAscii(ppMEMs[i]->pb, 0x40);
        } else {
            printf("[read failed]\n");
        }
    }
    // free previosly allocated ppMEMs;
    LeechCore_MemFree(ppMEMs);


    // Retrieve and display the data directories of kernel32.dll. The number of
    // data directories in a PE is always 16 - so this can be used to simplify
    // calling the functionality somewhat.
    printf("------------------------------------------------------------\n");
    printf("#17: List directories of 'kernel32.dll' in 'explorer.exe'.  \n");
    ShowKeyPress();
    LPCSTR DIRECTORIES[16] = { "EXPORT", "IMPORT", "RESOURCE", "EXCEPTION", "SECURITY", "BASERELOC", "DEBUG", "ARCHITECTURE", "GLOBALPTR", "TLS", "LOAD_CONFIG", "BOUND_IMPORT", "IAT", "DELAY_IMPORT", "COM_DESCRIPTOR", "RESERVED" };
    DWORD cDirectories;
    IMAGE_DATA_DIRECTORY pDirectories[16];
    printf("CALL:    VMMDLL_ProcessGetDirectories\n");
    result = VMMDLL_ProcessGetDirectories(dwPID, L"kernel32.dll", pDirectories, 16, &cDirectories);
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
    printf("#18: exports of 'kernel32.dll' in 'explorer.exe'.           \n");
    ShowKeyPress();
    DWORD cEATs;
    PVMMDLL_EAT_ENTRY pEATs;
    printf("CALL:    VMMDLL_ProcessGetEAT #1\n");
    result = VMMDLL_ProcessGetEAT(dwPID, L"kernel32.dll", NULL, 0, &cEATs);
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
    result = VMMDLL_ProcessGetEAT(dwPID, L"kernel32.dll", pEATs, cEATs, &cEATs);
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
    printf("#19: imports of 'kernel32.dll' in 'explorer.exe'.           \n");
    ShowKeyPress();
    DWORD cIATs;
    PVMMDLL_IAT_ENTRY pIATs;
    printf("CALL:    VMMDLL_ProcessGetIAT #1\n");
    result = VMMDLL_ProcessGetIAT(dwPID, L"kernel32.dll", NULL, 0, &cIATs);
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
    result = VMMDLL_ProcessGetIAT(dwPID, L"kernel32.dll", pIATs, cIATs, &cIATs);
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
    printf("#20: call the file system 'List' function on the root dir.  \n");
    ShowKeyPress();
    VMMDLL_VFS_FILELIST VfsFileList;
    VfsFileList.dwVersion = VMMDLL_VFS_FILELIST_VERSION;
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
    printf("#21: call the file system 'Read' function on the pmem file. \n");
    ShowKeyPress();
    printf("CALL:    VMMDLL_VfsRead\n");
    nt = VMMDLL_VfsRead(L"\\memory.pmem", pbPage1, 0x100, &i, 0x1000);
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
    printf("#22: initialize virtual file system plugins                 \n");
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
    printf("#23: call file system 'Read' on .status\\statistics         \n");
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
    printf("#24: get ntoskrnl.exe base virtual address                  \n");
    ShowKeyPress();
    printf("CALL:    VMMDLL_ProcessGetModuleBase\n");
    va = VMMDLL_ProcessGetModuleBase(4, L"ntoskrnl.exe");
    if(va) {
        printf("SUCCESS: VMMDLL_ProcessGetModuleBase\n");
        printf("         %s = %016llx\n", "ntoskrnl.exe", va);
    } else {
        printf("FAIL:    VMMDLL_ProcessGetModuleBase\n");
        return 1;
    }


    // GetProcAddress from ntoskrnl.exe
    printf("------------------------------------------------------------\n");
    printf("#25: get proc address for ntoskrnl.exe!KeGetCurrentIrql     \n");
    ShowKeyPress();
    printf("CALL:    VMMDLL_ProcessGetProcAddress\n");
    va = VMMDLL_ProcessGetProcAddress(4, L"ntoskrnl.exe", "KeGetCurrentIrql");
    if(va) {
        printf("SUCCESS: VMMDLL_ProcessGetProcAddress\n");
        printf("         %s!%s = %016llx\n", "ntoskrnl.exe", "KeGetCurrentIrql", va);
    } else {
        printf("FAIL:    VMMDLL_ProcessGetProcAddress\n");
        return 1;
    }


    // Get EAT Thunk from ntoskrnl.exe!KeGetCurrentIrql
    printf("------------------------------------------------------------\n");
    printf("#26: Address of EAT thunk for ntoskrnl.exe!KeGetCurrentIrql \n");
    ShowKeyPress();
    VMMDLL_WIN_THUNKINFO_EAT oThunkInfoEAT;
    ZeroMemory(&oThunkInfoEAT, sizeof(VMMDLL_WIN_THUNKINFO_EAT));
    printf("CALL:    VMMDLL_WinGetThunkInfoEAT\n");
    result = VMMDLL_WinGetThunkInfoEAT(4, L"ntoskrnl.exe", "KeGetCurrentIrql", &oThunkInfoEAT);
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
    printf("#27: Address of IAT thunk for hal.dll!HalSendNMI in ntoskrnl\n");
    ShowKeyPress();
    VMMDLL_WIN_THUNKINFO_IAT oThunkInfoIAT;
    ZeroMemory(&oThunkInfoIAT, sizeof(VMMDLL_WIN_THUNKINFO_IAT));
    printf("CALL:    VMMDLL_WinGetThunkInfoIAT\n");
    result = VMMDLL_WinGetThunkInfoIAT(4, L"ntoskrnl.Exe", "hal.Dll", "HalSendNMI", &oThunkInfoIAT);
    if(result) {
        printf("SUCCESS: VMMDLL_WinGetThunkInfoIAT\n");
        printf("         vaFunction:     %016llx\n", oThunkInfoIAT.vaFunction);
        printf("         vaThunk:        %016llx\n", oThunkInfoIAT.vaThunk);
        printf("         vaNameFunction: %016llx\n", oThunkInfoIAT.vaNameFunction);
        printf("         vaNameModule:   %016llx\n", oThunkInfoIAT.vaNameModule);
    } else {
        printf("FAIL:    VMMDLL_WinGetThunkInfoEAT\n");
        return 1;
    }


    // List Windows registry hives
    printf("------------------------------------------------------------\n");
    printf("#28: List Windows Registry Hives.                           \n");
    ShowKeyPress();
    DWORD cWinRegHives;
    PVMMDLL_REGISTRY_HIVE_INFORMATION pWinRegHives = NULL;
    printf("CALL:    VMMDLL_WinReg_HiveList\n");
    result = VMMDLL_WinReg_HiveList(NULL, 0, &cWinRegHives);
    if(!result || !cWinRegHives) {
        printf("FAIL:    VMMDLL_WinReg_HiveList #1 - Get # Hives.\n");
        return 1;
    }
    pWinRegHives = LocalAlloc(LMEM_ZEROINIT, cWinRegHives * sizeof(VMMDLL_REGISTRY_HIVE_INFORMATION));
    if(!pWinRegHives) {
        printf("FAIL:    OutOfMemory\n");
        return 1;
    }
    result = VMMDLL_WinReg_HiveList(pWinRegHives, cWinRegHives, &cWinRegHives);
    if(result && cWinRegHives) {
        printf("SUCCESS: VMMDLL_WinReg_HiveList\n");
        for(i = 0; i < cWinRegHives; i++) {
            printf("         %s\n", pWinRegHives[i].szName);
        }
    } else {
        printf("FAIL:    VMMDLL_WinReg_HiveList #2\n");
        return 1;
    }


    // Read 0x100 bytes from offset 0x1000 from the 1st located registry hive memory space
    printf("------------------------------------------------------------\n");
    printf("#29: Read 0x100 bytes from offset 0x1000 of registry hive   \n");
    ShowKeyPress();
    printf("CALL:    VMMDLL_WinReg_HiveReadEx\n");
    result = VMMDLL_WinReg_HiveReadEx(pWinRegHives[0].vaCMHIVE, 0x1000, pbPage1, 0x100, NULL, 0);
    if(result) {
        printf("SUCCESS: VMMDLL_WinReg_HiveReadEx\n");
        PrintHexAscii(pbPage1, 0x100);
    } else {
        printf("FAIL:    VMMDLL_WinReg_HiveReadEx\n");
        return 1;
    }



    // Finish everything and exit!
    printf("------------------------------------------------------------\n");
    printf("#99: FINISHED EXAMPLES!                                     \n");
    ShowKeyPress();
    printf("FINISHED TEST CASES - EXITING!\n");
    return 0;
}
