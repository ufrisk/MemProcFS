// vmmdll_example.c - MemProcFS C/C++ VMM API usage examples
//
// Note that this is not a complete list of the VMM API.
// For the complete list please consult the vmmdll.h header file.
// 
// Note about Windows/Linux differences:
// - Path to the file to be analyzed
// - Not all functionality is yet implemented on Linux - primarily debug symbol
//   and forensic functionality is missing. Future support is planned.
//   Please see the guide at https://github.com/ufrisk/MemProcFS/wiki for info.
// - Windows have access to both UTF-8 *U functions as well as Wide-Char *W
//   functions whilst linux in general should use UTF-8 functions only. This
//   example use UTF-8 functions throughout to have the best compatibility.
//
// (c) Ulf Frisk, 2018-2025
// Author: Ulf Frisk, pcileech@frizk.net
//

#ifdef _WIN32

#include <Windows.h>
#include <stdio.h>
#include <conio.h>
#include <leechcore.h>
#include <vmmdll.h>
#pragma comment(lib, "leechcore")
#pragma comment(lib, "vmm")

#endif /* _WIN32 */
#if defined(LINUX) || defined(MACOS)

#include <leechcore.h>
#include <vmmdll.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define TRUE                                1
#define FALSE                               0
#define LMEM_ZEROINIT                       0x0040
#define _getch()                            (getchar())
#define ZeroMemory(pb, cb)                  (memset(pb, 0, cb))
#define Sleep(dwMilliseconds)               (usleep(1000*dwMilliseconds))
#define min(a, b)                           (((a) < (b)) ? (a) : (b))
#define IMAGE_SCN_MEM_EXECUTE               0x20000000
#define IMAGE_SCN_MEM_READ                  0x40000000
#define IMAGE_SCN_MEM_WRITE                 0x80000000

HANDLE LocalAlloc(DWORD uFlags, SIZE_T uBytes)
{
    HANDLE h = malloc(uBytes);
    if(h && (uFlags & LMEM_ZEROINIT)) {
        memset(h, 0, uBytes);
    }
    return h;
}

VOID LocalFree(HANDLE hMem)
{
    free(hMem);
}

#endif /* LINUX || MACOS */

// ----------------------------------------------------------------------------
// Initialize from type of device, FILE or  FPGA.
// Ensure only one is active below at one single time!
// INITIALIZE_FROM_FILE contains file name to a raw memory dump.
// ----------------------------------------------------------------------------
#define _INITIALIZE_FROM_FILE    "Z:\\x64\\WIN10-X64-1909-18363-1.core"
//#define _INITIALIZE_FROM_FILE    "/mnt/c/Dumps/WIN7-x64-SP1-1.pmem"
//#define _INITIALIZE_FROM_FPGA

// ----------------------------------------------------------------------------
// Utility functions below:
// ----------------------------------------------------------------------------

VOID ShowKeyPress()
{
    printf("PRESS ANY KEY TO CONTINUE ...\n");
    Sleep(250);
    //_getch();
}

VOID PrintHexAscii(_In_ PBYTE pb, _In_ DWORD cb)
{
    LPSTR sz;
    DWORD szMax = 0;
    VMMDLL_UtilFillHexAscii(pb, cb, 0, NULL, &szMax);
    if(!(sz = LocalAlloc(0, szMax))) { return; }
    VMMDLL_UtilFillHexAscii(pb, cb, 0, sz, &szMax);
    printf("%s", sz);
    LocalFree(sz);
}

VOID CallbackList_AddFile(_Inout_ HANDLE h, _In_ LPCSTR uszName, _In_ ULONG64 cb, _In_opt_ PVMMDLL_VFS_FILELIST_EXINFO pExInfo)
{
    if(uszName) {
        printf("         FILE: '%s'\tSize: %lli\n", uszName, cb);
    }
}

VOID CallbackList_AddDirectory(_Inout_ HANDLE h, _In_ LPCSTR uszName, _In_opt_ PVMMDLL_VFS_FILELIST_EXINFO pExInfo)
{
    if(uszName) {
        printf("         DIR:  '%s'\n", uszName);
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
// Callback functions (YARA SEARCH) functionality below:
// ----------------------------------------------------------------------------

BOOL CallbackSearchYaraMatch(_In_ PVOID pvContext, _In_ PVMMYARA_RULE_MATCH pRuleMatch, _In_reads_bytes_(cbBuffer) PBYTE pbBuffer, _In_ SIZE_T cbBuffer)
{
    PVMMDLL_YARA_CONFIG ctx = (PVMMDLL_YARA_CONFIG)pvContext;                   // We pass the PVMMDLL_YARA_CONFIG into the user-set context pointer (ctx->pvUserPtrOpt)
                                                                                // This is done so we'll get the base address of the buffer being scanned.   
                                                                                // if one wish to use another user-context the field ctx->pvUserPtrOpt2 may be used.
    if(pRuleMatch->dwVersion != VMMYARA_RULE_MATCH_VERSION) { return FALSE; }
    if((pRuleMatch->cStrings > 0) && (pRuleMatch->Strings[0].cMatch > 0)) {     // ensure at least one string match exists - only print the address of the first occurence.
        printf("         rule: %s  address: %llx  string: %s\n", pRuleMatch->szRuleIdentifier, ctx->vaCurrent + pRuleMatch->Strings[0].cbMatchOffset[0], pRuleMatch->Strings[0].szString);
    }
    return TRUE;        // TRUE = continue search, FALSE = abort search
}

/*
* Optional filter callback. Tell whether a memory region should be scanned or not.
* User-mode applications predominantely use vad entries, whilst kernel use pte entries.
* -- ctx = Pointer to the VMMDLL_YARA_CONFIG structure.
* -- pePte = Pointer to the VMMDLL_MAP_PTEENTRY structure. NULL if not available.
* -- peVad = Pointer to the VMMDLL_MAP_VADENTRY structure. NULL if not available.
* -- return = TRUE to scan the memory region, FALSE to skip it.
*/
BOOL CallbackSearchYaraFilter(_In_ PVMMDLL_YARA_CONFIG ctx, _In_opt_ PVMMDLL_MAP_PTEENTRY pePte, _In_opt_ PVMMDLL_MAP_VADENTRY peVad)
{
    if(ctx->dwVersion != VMMDLL_YARA_CONFIG_VERSION) { return FALSE; }
    // only scan VAD-backed image memory regions since we're scanning for PE headers.
    // this may miss out on PE headers in other memory regions commonly used by malware.
    return   peVad && peVad->fImage;
}


// ----------------------------------------------------------------------------
// Callback functions (MEM CALLBACK) functionality below:
// ----------------------------------------------------------------------------

VOID CallbackMemCallback_PhysicalReadPost(_In_opt_ PVOID ctxUser, _In_ DWORD dwPID, _In_ DWORD cpMEMs, _In_ PPMEM_SCATTER ppMEMs)
{
    DWORD i;
    PMEM_SCATTER pMEM;
    for(i = 0; i < cpMEMs; i++) {
        pMEM = ppMEMs[i];
        if(pMEM->f && (pMEM->qwA == 0x1000) && (pMEM->cb >= 0x10)) {
            // Successful physical memory read at address 0x1000.
            // This is simplified since read may start mid-range if
            // non-page-aligned MEMs are used.
            memcpy(pMEM->pb, (PBYTE)"0123456789ABCDEF", 0x10);
        }
    }
}


// ----------------------------------------------------------------------------
// Main entry point which contains various sample code how to use MemProcFS DLL.
// Please walk though for different API usage examples. To select device ensure
// one device type only is uncommented in the #defines above.
// ---
// Since v5 MemProcFS supports memory analysis targets at the same time. The
// VMM_HANDLE (hVMM) which the initialization function return upon success is
// to be used in all subsequent API calls.
// ----------------------------------------------------------------------------
int main(_In_ int argc, _In_ char* argv[])
{
    VMM_HANDLE hVMM = NULL;
    BOOL result;
    NTSTATUS nt;
    DWORD i, j, cbRead, dwPID;
    DWORD dw = 0;
    QWORD va;
    BYTE pbPage1[0x1000], pbPage2[0x1000];
    CHAR usz[MAX_PATH];

#ifdef _INITIALIZE_FROM_FILE
    // Initialize PCILeech DLL with a memory dump file.
    printf("------------------------------------------------------------\n");
    printf("# Initialize from file:                                     \n");
    ShowKeyPress();
    printf("CALL:    VMMDLL_InitializeFile\n");
    hVMM = VMMDLL_Initialize(3, (LPCSTR[]) { "", "-device", _INITIALIZE_FROM_FILE });
    if(hVMM) {
        printf("SUCCESS: VMMDLL_InitializeFile\n");
    } else {
        printf("FAIL:    VMMDLL_InitializeFile\n");
        return 1;
    }
#endif /* _INITIALIZE_FROM_FILE */

#ifdef _INITIALIZE_FROM_FPGA
    // Initialize VMM DLL from a linked PCILeech with a FPGA hardware device
    printf("------------------------------------------------------------\n");
    printf("# Initialize from FPGA:                                     \n");
    ShowKeyPress();
    printf("CALL:    VMMDLL_Initialize\n");
    hVMM = VMMDLL_Initialize(3, (LPSTR[]) { "", "-device", "fpga" });
    if(hVMM) {
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
        VMMDLL_ConfigGet(hVMM, LC_OPT_FPGA_FPGA_ID, &qwID) &&
        VMMDLL_ConfigGet(hVMM, LC_OPT_FPGA_VERSION_MAJOR, &qwVersionMajor) &&
        VMMDLL_ConfigGet(hVMM, LC_OPT_FPGA_VERSION_MINOR, &qwVersionMinor);
    if(result) {
        printf("SUCCESS: VMMDLL_ConfigGet\n");
        printf("         ID = %lli\n", qwID);
        printf("         VERSION = %lli.%lli\n", qwVersionMajor, qwVersionMinor);
    } else {
        printf("FAIL:    VMMDLL_ConfigGet\n");
        return 1;
    }
    // Set PCIe config space status register flags auto-clear [master abort].
    // This requires bitstream version 4.7 or above. By default the flags are
    // reset evry ms. If timing are to be changed it's possible to write a new
    // timing value to PCILeech PCIe register at address: 0x054 (DWORD-value,
    // tickcount of multiples of 62.5MHz ticks).
    if((qwVersionMajor >= 4) && ((qwVersionMajor >= 5) || (qwVersionMinor >= 7)))
    {
        HANDLE hLC;
        LC_CONFIG LcConfig = {
            .dwVersion = LC_CONFIG_VERSION,
            .szDevice = "existing"
        };
        // fetch already existing leechcore handle.
        hLC = LcCreate(&LcConfig);
        if(hLC) {
            // enable auto-clear of status register [master abort].
            LcCommand(hLC, LC_CMD_FPGA_CFGREGPCIE_MARKWR | 0x002, 4, (BYTE[4]) { 0x10, 0x00, 0x10, 0x00 }, NULL, NULL);
            printf("SUCCESS: LcCommand: STATUS REGISTER AUTO-CLEAR\n");
            // close leechcore handle.
            LcClose(hLC);
        }
    }
#endif /* _INITIALIZE_FROM_FPGA */
       
    
    // Read physical memory at physical address 0x1000 and display the first
    // 0x100 bytes on-screen.
    printf("------------------------------------------------------------\n");
    printf("# Read from physical memory (0x1000 bytes @ 0x1000).        \n");
    ShowKeyPress();
    printf("CALL:    VMMDLL_MemRead\n");
    result = VMMDLL_MemRead(hVMM, -1, 0x1000, pbPage1, 0x1000);
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
    printf("# Try write to physical memory at address 0x1000.           \n");
    printf("     NB! Write capable device is required for success!      \n");
    printf("     (1) Read existing data from physical memory.           \n");
    printf("     (2) Try write to physical memory at 0x1000.            \n");
    printf("         Bytes written:  11112222333344445555666677778888   \n");
    printf("     (3) Read resulting data from physical memory.          \n");
    ShowKeyPress();
    printf("CALL:    VMMDLL_MemRead - BEFORE WRITE\n");
    result = VMMDLL_MemRead(hVMM, -1, 0x1000, pbPage1, 0x1000);
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
    VMMDLL_MemWrite(hVMM, -1, 0x1000, pbWriteDataPhysical, cbWriteDataPhysical);
    printf("CALL:    VMMDLL_MemRead - AFTER WRITE\n");
    result = VMMDLL_MemRead(hVMM, -1, 0x1000, pbPage1, 0x1000);
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
    printf("# Get PID from the first 'explorer.exe' process found.      \n");
    ShowKeyPress();
    printf("CALL:    VMMDLL_PidGetFromName\n");
    result = VMMDLL_PidGetFromName(hVMM, "explorer.exe", &dwPID);
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
    printf("# Get Process Information from 'explorer.exe'.              \n");
    ShowKeyPress();
    VMMDLL_PROCESS_INFORMATION ProcessInformation;
    SIZE_T cbProcessInformation = sizeof(VMMDLL_PROCESS_INFORMATION);
    ZeroMemory(&ProcessInformation, sizeof(VMMDLL_PROCESS_INFORMATION));
    ProcessInformation.magic = VMMDLL_PROCESS_INFORMATION_MAGIC;
    ProcessInformation.wVersion = VMMDLL_PROCESS_INFORMATION_VERSION;
    printf("CALL:    VMMDLL_ProcessGetInformation\n");
    result = VMMDLL_ProcessGetInformation(hVMM, dwPID, &ProcessInformation, &cbProcessInformation);
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


    // Retrieve process information such as: name of the process, PML4 (DTB),
    // PML4-USER (if exists) and Process State from _all_ processes.
    // Active processes will have ProcessState = 0.
    printf("------------------------------------------------------------\n");
    printf("# Get Process Information from ALL PROCESSES.               \n");
    ShowKeyPress();
    DWORD cProcessInformation = 0;
    PVMMDLL_PROCESS_INFORMATION pProcessInformationEntry, pProcessInformationAll = NULL;
    printf("CALL:    VMMDLL_ProcessGetInformationAll\n");
    result = VMMDLL_ProcessGetInformationAll(hVMM, &pProcessInformationAll, &cProcessInformation);
    if(result) {
        // print results upon success:
        printf("SUCCESS: VMMDLL_ProcessGetInformationAll\n");
        for(i = 0; i < cProcessInformation; i++) {
            pProcessInformationEntry = &pProcessInformationAll[i];
            printf("         --------------------------------------\n");
            printf("         Name =                  %s\n", pProcessInformationEntry->szName);
            printf("         LongName =              %s\n", pProcessInformationEntry->szNameLong);
            printf("         PageDirectoryBase =     0x%016llx\n", pProcessInformationEntry->paDTB);
            printf("         PageDirectoryBaseUser = 0x%016llx\n", pProcessInformationEntry->paDTB_UserOpt);
            printf("         ProcessState =          0x%08x\n", pProcessInformationEntry->dwState);
            printf("         PID =                   0x%08x\n", pProcessInformationEntry->dwPID);
            printf("         ParentPID =             0x%08x\n", pProcessInformationEntry->dwPPID);
        }
        // free function allocated memory:
        VMMDLL_MemFree(pProcessInformationAll);
    } else {
        printf("FAIL:    VMMDLL_ProcessGetInformationAll\n");
        return 1;
    }

    
    // Retrieve the memory map from the page table. This function also tries to
    // make additional parsing to identify modules and tag the memory map with
    // them. This is done by multiple methods internally and may sometimes be
    // more resilient against anti-reversing techniques that may be employed in
    // some processes.
    //
    // Note! VMMDLL_Map_GetPte() comes in two variants. The Wide-Char version
    //       VMMDLL_Map_GetPteW() is only available on Windows whilst the UTF-8
    //       VMMDLL_Map_GetPteU() version is available on Linux and Windows.
    printf("------------------------------------------------------------\n");
    printf("# Get PTE Memory Map of 'explorer.exe'.                     \n");
    ShowKeyPress();
    PVMMDLL_MAP_PTE pPteMap = NULL;
    PVMMDLL_MAP_PTEENTRY pPteMapEntry;
    printf("CALL:    VMMDLL_Map_GetPteU\n");
    result = VMMDLL_Map_GetPteU(hVMM, dwPID, TRUE, &pPteMap);
    if(!result) {
        printf("FAIL:    VMMDLL_Map_GetPteU\n");
        return 1;
    }
    if(pPteMap->dwVersion != VMMDLL_MAP_PTE_VERSION) {
        printf("FAIL:    VMMDLL_Map_GetPteU - BAD VERSION\n");
        VMMDLL_MemFree(pPteMap); pPteMap = NULL;
        return 1;
    }
    {
        printf("SUCCESS: VMMDLL_Map_GetPteU\n");
        printf("         #      #PAGES ADRESS_RANGE                      SRWX\n");
        printf("         ====================================================\n");
        for(i = 0; i < pPteMap->cMap; i++) {
            pPteMapEntry = &pPteMap->pMap[i];
            printf(
                "         %04x %8x %016llx-%016llx %sr%s%s%s%s\n",
                i,
                (DWORD)pPteMapEntry->cPages,
                pPteMapEntry->vaBase,
                pPteMapEntry->vaBase + (pPteMapEntry->cPages << 12) - 1,
                pPteMapEntry->fPage & VMMDLL_MEMMAP_FLAG_PAGE_NS ? "-" : "s",
                pPteMapEntry->fPage & VMMDLL_MEMMAP_FLAG_PAGE_W ? "w" : "-",
                pPteMapEntry->fPage & VMMDLL_MEMMAP_FLAG_PAGE_NX ? "-" : "x",
                pPteMapEntry->fWoW64 ? " 32 " : "    ",
                pPteMapEntry->uszText
            );
        }
        VMMDLL_MemFree(pPteMap); pPteMap = NULL;
    }


    // Retrieve the memory map from the virtual address descriptors (VAD). This
    // function also makes additional parsing to identify modules and tag the
    // memory map with them.
    printf("------------------------------------------------------------\n");
    printf("# Get VAD Memory Map of 'explorer.exe'.                     \n");
    ShowKeyPress();
    CHAR szVadProtection[7] = { 0 };
    PVMMDLL_MAP_VAD pVadMap = NULL;
    PVMMDLL_MAP_VADENTRY pVadMapEntry;
    printf("CALL:    VMMDLL_Map_GetVadU\n");
    result = VMMDLL_Map_GetVadU(hVMM, dwPID, TRUE, &pVadMap);
    if(!result) {
        printf("FAIL:    VMMDLL_Map_GetVadU\n");
        return 1;
    }
    if(pVadMap->dwVersion != VMMDLL_MAP_VAD_VERSION) {
        printf("FAIL:    VMMDLL_Map_GetVadU - BAD VERSION\n");
        VMMDLL_MemFree(pVadMap); pVadMap = NULL;
        return 1;
    }
    {
        printf("SUCCESS: VMMDLL_Map_GetVadU\n");
        printf("         #    ADRESS_RANGE                      KERNEL_ADDR        TYPE  PROT   INFO \n");
        printf("         ============================================================================\n");
        for(i = 0; i < pVadMap->cMap; i++) {
            pVadMapEntry = &pVadMap->pMap[i];
            VadMap_Protection(pVadMapEntry, szVadProtection);
            printf(
                "         %04x %016llx-%016llx [%016llx] %s %s %s\n",
                i,
                pVadMapEntry->vaStart,
                pVadMapEntry->vaEnd,
                pVadMapEntry->vaVad,
                VadMap_Type(pVadMapEntry),
                szVadProtection,
                pVadMapEntry->uszText
            );
        }
        VMMDLL_MemFree(pVadMap); pVadMap = NULL;
    }


    // Retrieve the list of loaded DLLs from the process. Please note that this
    // list is retrieved by parsing in-process memory structures such as the
    // process environment block (PEB) which may be partly destroyed in some
    // processes due to obfuscation and anti-reversing. If that is the case the
    // memory map may use alternative parsing techniques to list DLLs.
    printf("------------------------------------------------------------\n");
    printf("# Get Module Map of 'explorer.exe'.                         \n");
    ShowKeyPress();
    PVMMDLL_MAP_MODULE pModuleMap = NULL;
    printf("CALL:    VMMDLL_Map_GetModuleU\n");
    result = VMMDLL_Map_GetModuleU(hVMM, dwPID, &pModuleMap, 0);
    if(!result) {
        printf("FAIL:    VMMDLL_Map_GetModuleU #1\n");
        return 1;
    }
    if(pModuleMap->dwVersion != VMMDLL_MAP_MODULE_VERSION) {
        printf("FAIL:    VMMDLL_Map_GetModuleU - BAD VERSION\n");
        VMMDLL_MemFree(pModuleMap); pModuleMap = NULL;
        return 1;
    }
    {
        printf("SUCCESS: VMMDLL_Map_GetModuleU\n");
        printf("         MODULE_NAME                                 BASE             SIZE     ENTRY           PATH\n");
        printf("         ==========================================================================================\n");
        for(i = 0; i < pModuleMap->cMap; i++) {
            printf(
                "         %-40.40s %s %016llx %08x %016llx %s\n",
                pModuleMap->pMap[i].uszText,
                pModuleMap->pMap[i].fWoW64 ? "32" : "  ",
                pModuleMap->pMap[i].vaBase,
                pModuleMap->pMap[i].cbImageSize,
                pModuleMap->pMap[i].vaEntry,
                pModuleMap->pMap[i].uszFullName
            );
        }
        VMMDLL_MemFree(pModuleMap); pModuleMap = NULL;
    }


    // Retrieve the list of loaded DLLs from the process and also include debug
    // and versioning information. Extended information such as debug/versioning
    // information is not included by default (included with flags) and require
    // extra performance to fetch.
    printf("------------------------------------------------------------\n");
    printf("# Get Module Map with DEBUG & VERSION info of 'explorer.exe'.\n");
    ShowKeyPress();
    PVMMDLL_MAP_MODULE pModuleExMap = NULL;
    printf("CALL:    VMMDLL_Map_GetModuleU\n");
    result = VMMDLL_Map_GetModuleU(hVMM, dwPID, &pModuleExMap, VMMDLL_MODULE_FLAG_DEBUGINFO | VMMDLL_MODULE_FLAG_VERSIONINFO);
    if(!result) {
        printf("FAIL:    VMMDLL_Map_GetModuleU #1\n");
        return 1;
    }
    if(pModuleExMap->dwVersion != VMMDLL_MAP_MODULE_VERSION) {
        printf("FAIL:    VMMDLL_Map_GetModuleU - BAD VERSION\n");
        VMMDLL_MemFree(pModuleExMap); pModuleExMap = NULL;
        return 1;
    }
    {
        printf("SUCCESS: VMMDLL_Map_GetModuleU\n");
        printf("         MODULE_NAME                              PDB-PATH                         CompanyName                      FileDescription                  InternalName\n");
        printf("         ================================================================================================================================================================\n");
        for(i = 0; i < pModuleExMap->cMap; i++) {
            printf(
                "         %-40.40s %-32.32s %-32.32s %-32.32s %s\n",
                pModuleExMap->pMap[i].uszText,
                pModuleExMap->pMap[i].pExDebugInfo->uszPdbFilename,
                pModuleExMap->pMap[i].pExVersionInfo->uszCompanyName,
                pModuleExMap->pMap[i].pExVersionInfo->uszFileDescription,
                pModuleExMap->pMap[i].pExVersionInfo->uszInternalName
            );
        }
        VMMDLL_MemFree(pModuleExMap); pModuleExMap = NULL;
    }


    // Retrieve the list of unloaded DLLs from the process. Please note that
    // Windows only keeps references of the most recent 50-64 entries.
    printf("------------------------------------------------------------\n");
    printf("# Get Unloaded Module Map of 'explorer.exe'.                \n");
    ShowKeyPress();
    PVMMDLL_MAP_UNLOADEDMODULE pUnloadedMap = NULL;
    printf("CALL:    VMMDLL_Map_GetUnloadedModuleU\n");
    result = VMMDLL_Map_GetUnloadedModuleU(hVMM, dwPID, &pUnloadedMap);
    if(!result) {
        printf("FAIL:    VMMDLL_Map_GetUnloadedModuleU\n");
        return 1;
    }
    if(pUnloadedMap->dwVersion != VMMDLL_MAP_UNLOADEDMODULE_VERSION) {
        printf("FAIL:    VMMDLL_Map_GetUnloadedModuleU - BAD VERSION\n");
        VMMDLL_MemFree(pUnloadedMap); pUnloadedMap = NULL;
        return 1;
    }
    {
        printf("SUCCESS: VMMDLL_Map_GetUnloadedModuleU\n");
        printf("         MODULE_NAME                                 BASE             SIZE\n");
        printf("         =================================================================\n");
        for(i = 0; i < pUnloadedMap->cMap; i++) {
            printf(
                "         %-40.40s %s %016llx %08x\n",
                pUnloadedMap->pMap[i].uszText,
                pUnloadedMap->pMap[i].fWoW64 ? "32" : "  ",
                pUnloadedMap->pMap[i].vaBase,
                pUnloadedMap->pMap[i].cbImageSize
            );
        }
        VMMDLL_MemFree(pUnloadedMap); pUnloadedMap = NULL;
    }


    // Retrieve the module of explorer.exe by its name. Note it is also possible
    // to retrieve it by retrieving the complete module map (list) and iterate
    // over it. But if the name of the module is known this is more convenient.
    // This required that the PEB and LDR list in-process haven't been tampered
    // with ...
    printf("------------------------------------------------------------\n");
    printf("# Get module by name 'explorer.exe' in 'explorer.exe'.      \n");
    ShowKeyPress();
    printf("CALL:    VMMDLL_Map_GetModuleFromNameU\n");
    PVMMDLL_MAP_MODULEENTRY pModuleEntryExplorer;
    result = VMMDLL_Map_GetModuleFromNameU(hVMM, dwPID, "explorer.exe", &pModuleEntryExplorer, 0);
    if(result) {
        printf("SUCCESS: VMMDLL_Map_GetModuleFromNameU\n");
        printf("         MODULE_NAME                                 BASE             SIZE     ENTRY\n");
        printf("         ======================================================================================\n");
        printf(
            "         %-40.40s %i %016llx %08x %016llx\n",
            "explorer.exe",
            pModuleEntryExplorer->fWoW64 ? 32 : 64,
            pModuleEntryExplorer->vaBase,
            pModuleEntryExplorer->cbImageSize,
            pModuleEntryExplorer->vaEntry
        );
    } else {
        printf("FAIL:    VMMDLL_Map_GetModuleFromNameU\n");
        VMMDLL_MemFree(pModuleEntryExplorer); pModuleEntryExplorer = NULL;
        return 1;
    }


    // THREADS: Retrieve thread information about threads in the explorer.exe
    // process and display on the screen.
    printf("------------------------------------------------------------\n");
    printf("# Get Thread Information of 'explorer.exe'.                 \n");
    ShowKeyPress();
    PVMMDLL_MAP_THREAD pThreadMap = NULL;
    PVMMDLL_MAP_THREADENTRY pThreadMapEntry;
    printf("CALL:    VMMDLL_Map_GetThread\n");
    result = VMMDLL_Map_GetThread(hVMM, dwPID, &pThreadMap);
    if(!result) {
        printf("FAIL:    VMMDLL_Map_GetThread\n");
        return 1;
    }
    if(pThreadMap->dwVersion != VMMDLL_MAP_THREAD_VERSION) {
        printf("FAIL:    VMMDLL_Map_GetThread - BAD VERSION\n");
        VMMDLL_MemFree(pThreadMap); pThreadMap = NULL;
        return 1;
    }
    {
        printf("SUCCESS: VMMDLL_Map_GetThread\n");
        printf("         #         TID      PID ADDR_TEB         ADDR_ETHREAD     ADDR_START       INSTRUCTION_PTR  STACK[BASE:TOP]:PTR\n");
        printf("         ==============================================================================================================\n");
        for(i = 0; i < pThreadMap->cMap; i++) {
            pThreadMapEntry = &pThreadMap->pMap[i];
            printf(
                "         %04x %8x %8x %016llx %016llx %016llx [%016llx->%016llx]:%016llx %016llx\n",
                i,
                pThreadMapEntry->dwTID,
                pThreadMapEntry->dwPID,
                pThreadMapEntry->vaTeb,
                pThreadMapEntry->vaETHREAD,
                pThreadMapEntry->vaStartAddress,
                pThreadMapEntry->vaStackBaseUser,
                pThreadMapEntry->vaStackLimitUser,
                pThreadMapEntry->vaRSP,
                pThreadMapEntry->vaRIP
            );
        }
        VMMDLL_MemFree(pThreadMap); pThreadMap = NULL;
    }


    // THREAD CALLSTACK: Retrieve callstack information for the threads in the
    // 'smss.exe' process and display on the screen.
    DWORD dwPID_SMSS = 0;
    PVMMDLL_MAP_THREAD pThreadMap_SMSS = NULL;
    PVMMDLL_MAP_THREADENTRY pThreadMapEntry_SMSS;
    PVMMDLL_MAP_THREAD_CALLSTACK pThreadCallstack = NULL;
    PVMMDLL_MAP_THREAD_CALLSTACKENTRY pThreadCallstackEntry = NULL;
    printf("------------------------------------------------------------\n");
    printf("# Get Thread Callstack Information of 'smss.exe' threads.   \n");
    ShowKeyPress();
    VMMDLL_PidGetFromName(hVMM, "smss.exe", &dwPID_SMSS);
    VMMDLL_Map_GetThread(hVMM, dwPID_SMSS, &pThreadMap_SMSS);
    if(!dwPID_SMSS || !pThreadMap_SMSS) {
        printf("FAIL:    VMMDLL_PidGetFromName//VMMDLL_Map_GetThread\n");
        return 1;
    }
    for(i = 0; i < pThreadMap_SMSS->cMap; i++) {
        pThreadMapEntry_SMSS = &pThreadMap_SMSS->pMap[i];
        printf("CALL:    VMMDLL_Map_GetThread_CallstackU\n");
        result = VMMDLL_Map_GetThread_CallstackU(hVMM, dwPID_SMSS, pThreadMapEntry_SMSS->dwTID, 0, &pThreadCallstack);
        if(!result) {
            printf("FAIL:    VMMDLL_Map_GetThread_CallstackU\n");
            return 1;
        }
        printf("SUCCESS: VMMDLL_Map_GetThread_CallstackU\n");
        printf("%s", pThreadCallstack->uszText);
        printf("-------------\n");
        for(j = 0; j < pThreadCallstack->cMap; j++) {
            pThreadCallstackEntry = &pThreadCallstack->pMap[j];
            printf("%02x: %016llx %016llx :: %s!%s+%x\n", pThreadCallstackEntry->i, pThreadCallstackEntry->vaRSP, pThreadCallstackEntry->vaRetAddr, pThreadCallstackEntry->uszModule, pThreadCallstackEntry->uszFunction, pThreadCallstackEntry->cbDisplacement);
        }
        printf("------------------------------------------------------------\n");
        VMMDLL_MemFree(pThreadCallstack); pThreadCallstack = NULL;
    }
    VMMDLL_MemFree(pThreadMap_SMSS); pThreadMap_SMSS = NULL;


    // HANDLES: Retrieve handle information about handles in the explorer.exe
    // process and display on the screen.
    printf("------------------------------------------------------------\n");
    printf("# Get Handle Information of 'explorer.exe'.                 \n");
    ShowKeyPress();
    PVMMDLL_MAP_HANDLE pHandleMap = NULL;
    PVMMDLL_MAP_HANDLEENTRY pHandleMapEntry;
    printf("CALL:    VMMDLL_Map_GetHandleU\n");
    result = VMMDLL_Map_GetHandleU(hVMM, dwPID, &pHandleMap);
    if(!result) {
        printf("FAIL:    VMMDLL_Map_GetHandleU\n");
        return 1;
    }
    if(pHandleMap->dwVersion != VMMDLL_MAP_HANDLE_VERSION) {
        printf("FAIL:    VMMDLL_Map_GetHandleU - BAD VERSION\n");
        VMMDLL_MemFree(pHandleMap); pHandleMap = NULL;
        return 1;
    }
    {
        printf("SUCCESS: VMMDLL_Map_GetHandleU\n");
        printf("         #         HANDLE   PID ADDR_OBJECT      ACCESS TYPE             DESCRIPTION\n");
        printf("         ===========================================================================\n");
        for(i = 0; i < pHandleMap->cMap; i++) {
            pHandleMapEntry = &pHandleMap->pMap[i];
            printf(
                "         %04x %8x %8x %016llx %6x %-16s %s\n",
                i,
                pHandleMapEntry->dwHandle,
                pHandleMapEntry->dwPID,
                pHandleMapEntry->vaObject,
                pHandleMapEntry->dwGrantedAccess,
                pHandleMapEntry->uszType,
                pHandleMapEntry->uszText
            );
        }
        VMMDLL_MemFree(pHandleMap); pHandleMap = NULL;
    }


    // HEAPS: Retrieve heap information about handles in the explorer.exe
    // process and display on the screen.
    printf("------------------------------------------------------------\n");
    printf("# Get Heap Information of 'explorer.exe'.                 \n");
    ShowKeyPress();
    PVMMDLL_MAP_HEAP pHeapMap = NULL;
    PVMMDLL_MAP_HEAPENTRY pHeapMapEntry;
    printf("CALL:    VMMDLL_Map_GetHeap\n");
    result = VMMDLL_Map_GetHeap(hVMM, dwPID, &pHeapMap);
    if(!result) {
        printf("FAIL:    VMMDLL_Map_GetHeap\n");
        return 1;
    }
    if(pHeapMap->dwVersion != VMMDLL_MAP_HEAP_VERSION) {
        printf("FAIL:    VMMDLL_Map_GetHeap - BAD VERSION\n");
        VMMDLL_MemFree(pHeapMap); pHeapMap = NULL;
        return 1;
    }
    {
        printf("SUCCESS: VMMDLL_Map_GetHeap\n");
        printf("         #       PID ADDR_HEAP      HEAP#  TYPE\n");
        printf("         ======================================\n");
        for(i = 0; i < pHeapMap->cMap; i++) {
            pHeapMapEntry = &pHeapMap->pMap[i];
            printf(
                "         %04x%7i %016llx %3i %2i %s\n",
                pHeapMapEntry->iHeap,
                dwPID,
                pHeapMapEntry->va,
                pHeapMapEntry->dwHeapNum,
                pHeapMapEntry->tp,
                pHeapMapEntry->f32 ? "32" : ""
            );
        }
        VMMDLL_MemFree(pHeapMap); pHeapMap = NULL;
    }


    // BINARY SEARCH WITH WILDCARD BITMASK for process PE header signatures.
    // The search is performed at offset 0x0 in each 4096-byte memory page.
    // Only search virtual memory above 4GB. For more information see vmmdll.h.
    printf("------------------------------------------------------------\n");
    printf("# Binary Search for PE header signatures in 'explorer.exe'. \n");
    ShowKeyPress();
    // Initialize search context and add one search term. Up to 16 search terms
    // are possible to use at the same time for more efficient searches.
    // In addition to the listed configuration it's possible to use callback
    // functions for both which ranges should be scanned and for search results.
    // Also additional properties for max address and more exists.
    VMMDLL_MEM_SEARCH_CONTEXT_SEARCHENTRY SearchEntry3[3] = { 0 };      // an array which may hold up to 3 search terms (max).
    VMMDLL_MEM_SEARCH_CONTEXT ctxSearch = { 0 };
    ctxSearch.dwVersion = VMMDLL_MEM_SEARCH_VERSION;            // required struct version.
    ctxSearch.pSearch = SearchEntry3;                           // required pointer to search terms.
    if(ctxSearch.cSearch < 3) {
        ctxSearch.pSearch[ctxSearch.cSearch].cb = 4;            // required number of bytes to search, max 32.
        memcpy(ctxSearch.pSearch[ctxSearch.cSearch].pb,
            (BYTE[4]) {
            0x4d, 0x5a, 0x90, 0x00
        }, 4);           // required bytes to search for, max 32.
        memcpy(ctxSearch.pSearch[ctxSearch.cSearch].pbSkipMask,
            (BYTE[4]) {
            0x00, 0x00, 0xff, 0x00
        }, 4);           // optional bitwise wildcard mask, here the 3rd byte is completely optional.
        ctxSearch.pSearch[ctxSearch.cSearch].cbAlign = 0x1000;  // optional alignment, i.e. search every X bytes,
                                                                // here we search in beginning of pages only.
                                                                // other common values are 0/1 (default) - full search
                                                                // and 8 - search every 8 bytes for 64-bit pointers.
        ctxSearch.cSearch++;
    }
    ctxSearch.ReadFlags = VMMDLL_FLAG_NOCACHE;                  // optional read flags are possible to use.
    ctxSearch.vaMin = 0x100000000;                              // optional start searching at 4GB in virtual memory
    // perform the actual search:
    printf("CALL:    VMMDLL_MemSearch\n");
    DWORD cvaSearchResult = 0;
    PQWORD pvaSearchResult = NULL;
    result = VMMDLL_MemSearch(hVMM, dwPID, &ctxSearch, &pvaSearchResult, &cvaSearchResult);
    if(result) {
        printf("SUCCESS: VMMDLL_MemSearch\n");
        printf("         Number of search results: %u\n", cvaSearchResult);
        printf("       ");
        for(i = 0; i < cvaSearchResult; i++) {
            printf("  0x%016llx", pvaSearchResult[i]);
        }
        printf("\n");
        VMMDLL_MemFree(pvaSearchResult);     // free any function-allocated memory containing results.
    } else {
        printf("FAIL:    VMMDLL_MemSearch\n");
        VMMDLL_MemFree(pvaSearchResult);     // free any function-allocated memory containing results.
        return 1;
    }


    // YARA SEARCH for process PE header signatures.
    // NB! YARA SEARCH REQUIRES 'vmmyara.dll'/'vmmyara.so' to be present in the vmm directory.
    // The search is performed at offset 0x0in each scanned memory region (VAD or PTE).
    // Only search virtual memory above 4GB. For more information see vmmdll.h.
    // The search will return a maximum number of 32 results.
    printf("------------------------------------------------------------\n");
    printf("# YARA Search for PE header signatures in 'explorer.exe'.   \n");
    ShowKeyPress();
    VMMDLL_YARA_CONFIG ctxYara = { 0 };
    ctxYara.dwVersion = VMMDLL_YARA_CONFIG_VERSION;             // required struct version.
    // YARA rules: Yara rules may be in the form of any number of strings as
    // given in the below example.
    // Yara rules may also be given in the form of one (1) file (including path)
    // containing one or more YARA rules or index rules.
    LPSTR szYaraRule1 = " rule mz_header { strings: $mz = \"MZ\" condition: $mz at 0 } ";
    LPSTR szYaraRules[] = { szYaraRule1 };
    ctxYara.pszRules = szYaraRules;                             // required YARA rules array.
    ctxYara.cRules = 1;                                         // required number of YARA rules.
    ctxYara.pvUserPtrOpt = &ctxYara;                            // optional user pointer passed to callback functions
                                                                //          here ctxYara is passed since we need to read the base address of the memory region.
                                                                //          any other user-defined pointer may be set in ctxYara.pvUserPtrOpt2
    ctxYara.cMaxResult = 16;                                    // optional max number of results to return.
    ctxYara.ReadFlags = VMMDLL_FLAG_NOCACHE;                    // optional read flags are possible to use.
    ctxYara.vaMin = 0x100000000;                                // optional start searching at 4GB in virtual memory
    ctxYara.pfnFilterOptCB = CallbackSearchYaraFilter;          // optional callback function for filtering which memory ranges to scan.
    ctxYara.pfnScanMemoryCB = CallbackSearchYaraMatch;          // optional callback function for handling search results
    // perform the actual search:
    // Note that the the two last arguments works the same as in the VMMDLL_MemSearch() function.
    // These are not used in this example though since a callback is used instead (it's possible to use both or just one of them).
    printf("CALL:    VMMDLL_YaraSearch\n");
    result = VMMDLL_YaraSearch(hVMM, dwPID, &ctxYara, NULL, NULL);
    if(result) {
        printf("SUCCESS: VMMDLL_YaraSearch\n");
        printf("         Number of search results: %u\n", ctxYara.cResult);
    } else {
        printf("FAIL:    VMMDLL_YaraSearch\n");
        // YARA search will fail if 'vmmyara.dll'/'vmmyara.so' is not present in the vmm directory.
    }

    
    // Write virtual memory at PE header of Explorer.EXE and display the first
    // 0x80 bytes on-screen - afterwards. Maybe result of write is in there?
    // (only if device is capable of writes and target system accepts writes)
    printf("------------------------------------------------------------\n");
    printf("# Try write to virtual memory of Explorer.EXE PE header     \n");
    printf("     NB! Write capable device is required for success!      \n");
    printf("     (1) Read existing data from virtual memory.            \n");
    printf("     (2) Try write to virtual memory at PE header.          \n");
    printf("     (3) Read resulting data from virtual memory.           \n");
    ShowKeyPress();
    printf("CALL:    VMMDLL_MemRead - BEFORE WRITE\n");
    result = VMMDLL_MemRead(hVMM, dwPID, pModuleEntryExplorer->vaBase, pbPage1, 0x1000);
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
    VMMDLL_MemWrite(hVMM, dwPID, pModuleEntryExplorer->vaBase + 0x58, pbWriteDataVirtual, cbWriteDataVirtual);
    printf("CALL:    VMMDLL_MemRead - AFTER WRITE\n");
    result = VMMDLL_MemRead(hVMM, dwPID, pModuleEntryExplorer->vaBase, pbPage1, 0x1000);
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
    printf("# Get by name 'kernel32.dll' in 'explorer.exe'.             \n");
    ShowKeyPress();
    printf("CALL:    VMMDLL_Map_GetModuleFromNameU\n");
    PVMMDLL_MAP_MODULEENTRY pModuleEntryKernel32;
    result = VMMDLL_Map_GetModuleFromNameU(hVMM, dwPID, "kernel32.dll", &pModuleEntryKernel32, 0);
    if(result) {
        printf("SUCCESS: VMMDLL_Map_GetModuleFromNameU\n");
        printf("         MODULE_NAME                                 BASE             SIZE     ENTRY\n");
        printf("         ======================================================================================\n");
        printf(
            "         %-40.40s %i %016llx %08x %016llx\n",
            "kernel32.dll",
            pModuleEntryKernel32->fWoW64 ? 32 : 64,
            pModuleEntryKernel32->vaBase,
            pModuleEntryKernel32->cbImageSize,
            pModuleEntryKernel32->vaEntry
        );
    } else {
        printf("FAIL:    VMMDLL_Map_GetModuleFromNameU\n");
        VMMDLL_MemFree(pModuleEntryKernel32); pModuleEntryKernel32 = NULL;
        return 1;
    }

    
    // Retrieve the memory at the base of kernel32.dll previously fetched and
    // display the first 0x200 bytes of it. This read is fetched from the cache
    // by default (if possible). If reads should be forced from the DMA device
    // please specify the flag: VMM_FLAG_NOCACHE
    printf("------------------------------------------------------------\n");
    printf("# Read 0x200 bytes of 'kernel32.dll' in 'explorer.exe'.     \n");
    ShowKeyPress();
    DWORD cRead;
    printf("CALL:    VMMDLL_MemReadEx\n");
    result = VMMDLL_MemReadEx(hVMM, dwPID, pModuleEntryKernel32->vaBase, pbPage2, 0x1000, &cRead, 0);                       // standard cached read
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
    printf("# List sections of 'kernel32.dll' in 'explorer.exe'.        \n");
    ShowKeyPress();
    printf("CALL:    VMMDLL_ProcessGetSectionsU #1\n");
    DWORD cSections;
    PIMAGE_SECTION_HEADER pSectionHeaders;
    result = VMMDLL_ProcessGetSectionsU(hVMM, dwPID, "kernel32.dll", NULL, 0, &cSections);
    if(result) {
        printf("SUCCESS: VMMDLL_ProcessGetSectionsU #1\n");
        printf("         Count = %i\n", cSections);
    } else {
        printf("FAIL:    VMMDLL_ProcessGetSectionsU #1\n");
        return 1;
    }
    pSectionHeaders = (PIMAGE_SECTION_HEADER)LocalAlloc(LMEM_ZEROINIT, cSections * sizeof(IMAGE_SECTION_HEADER));
    if(!pSectionHeaders) {
        printf("FAIL:    OutOfMemory\n");
        return 1;
    }
    printf("CALL:    VMMDLL_ProcessGetSectionsU #2\n");
    result = VMMDLL_ProcessGetSectionsU(hVMM, dwPID, "kernel32.dll", pSectionHeaders, cSections, &cSections);
    if(result) {
        printf("SUCCESS: VMMDLL_ProcessGetSectionsU #2\n");
        printf("         #  NAME     OFFSET   SIZE     RWX\n");
        printf("         =================================\n");
        for(i = 0; i < cSections; i++) {
            printf(
                "         %02x %-8.8s %08x %08x %c%c%c\n",
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
        printf("FAIL:    VMMDLL_ProcessGetSectionsU #2\n");
        return 1;
    }


    // Scatter Read memory from each of the sections of kernel32.dll in explorer.exe
    printf("------------------------------------------------------------\n");
    printf("# 0x20 bytes of each 'kernel32.dll' section.                \n");
    ShowKeyPress();
    PPMEM_SCATTER ppMEMs = NULL;
    // Allocate empty scatter entries and populate them with the virtual addresses of
    // the sections to read. If one wish to have a more efficient way of doing things
    // without lots of copying of memory it's possible to initialize the ppMEMs array
    // manually and set each individual MEM_SCATTER result byte buffer to point into
    // own pre-allocated data buffer or use one of the other LcAllocScatterX() fns.
    printf("CALL:    LcAllocScatter1 #1\n");
    if(LcAllocScatter1(cSections, &ppMEMs)) {
        printf("SUCCESS: LcAllocScatter1 #1\n");
    } else {
        printf("FAIL:    LcAllocScatter1 #1\n");
        return 1;
    }
    for(i = 0; i < cSections; i++) {
        // populate the virtual address of each scatter entry with the address to read
        // (sections are assumed to be page-aligned in virtual memory.
        ppMEMs[i]->qwA = pModuleEntryKernel32->vaBase + pSectionHeaders[i].VirtualAddress;
    }
    // Scatter Read - read all scatter entries in one efficient go. In this
    // example the internal VMM cache is not to be used, and virtual memory
    // is not to be used. One can skip the flags to get default behaviour -
    // that is use cache and paging, and keep buffer byte data as-is on fail.
    printf("CALL:    VMMDLL_MemReadScatter #1\n");
    if(VMMDLL_MemReadScatter(hVMM, dwPID, ppMEMs, cSections, VMMDLL_FLAG_NOCACHE | VMMDLL_FLAG_ZEROPAD_ON_FAIL | VMMDLL_FLAG_NOPAGING)) {
        printf("SUCCESS: VMMDLL_MemReadScatter #1\n");
    } else {
        printf("FAIL:    VMMDLL_MemReadScatter #1\n");
        return 1;
    }
    // print result
    for(i = 0; i < cSections; i++) {
        printf("--------------\n         %s\n", pSectionHeaders[i].Name);
        if(ppMEMs[i]->f) {
            PrintHexAscii(ppMEMs[i]->pb, 0x40);
        } else {
            printf("[read failed]\n");
        }
    }
    // free previosly allocated ppMEMs;
    LcMemFree(ppMEMs);


    // Retrieve and display the data directories of kernel32.dll. The number of
    // data directories in a PE is always 16 - so this can be used to simplify
    // calling the functionality somewhat.
    printf("------------------------------------------------------------\n");
    printf("# List directories of 'kernel32.dll' in 'explorer.exe'.     \n");
    ShowKeyPress();
    LPCSTR DIRECTORIES[16] = { "EXPORT", "IMPORT", "RESOURCE", "EXCEPTION", "SECURITY", "BASERELOC", "DEBUG", "ARCHITECTURE", "GLOBALPTR", "TLS", "LOAD_CONFIG", "BOUND_IMPORT", "IAT", "DELAY_IMPORT", "COM_DESCRIPTOR", "RESERVED" };
    IMAGE_DATA_DIRECTORY pDirectories[16];
    printf("CALL:    VMMDLL_ProcessGetDirectoriesU\n");
    result = VMMDLL_ProcessGetDirectoriesU(hVMM, dwPID, "kernel32.dll", pDirectories);
    if(result) {
        printf("SUCCESS: PCIleech_VmmProcess_GetDirectories\n");
        printf("         #  NAME             OFFSET   SIZE\n");
        printf("         =====================================\n");
        for(i = 0; i < 16; i++) {
            printf(
                "         %02x %-16.16s %08x %08x\n",
                i,
                DIRECTORIES[i],
                pDirectories[i].VirtualAddress,
                pDirectories[i].Size
            );
        }
    } else {
        printf("FAIL:    VMMDLL_ProcessGetDirectoriesU\n");
        return 1;
    }
    

    // Retrieve the export address table (EAT) of kernel32.dll
    printf("------------------------------------------------------------\n");
    printf("# exports of 'kernel32.dll' in 'explorer.exe'.              \n");
    ShowKeyPress();
    PVMMDLL_MAP_EAT pEatMap = NULL;
    PVMMDLL_MAP_EATENTRY pEatMapEntry;
    printf("CALL:    VMMDLL_Map_GetEATU\n");
    result = VMMDLL_Map_GetEATU(hVMM, dwPID, "kernel32.dll", &pEatMap);
    if(!result) {
        printf("FAIL:    VMMDLL_Map_GetEATU\n");
        return 1;
    }
    if(pEatMap->dwVersion != VMMDLL_MAP_EAT_VERSION) {
        printf("FAIL:    VMMDLL_Map_GetEATU - BAD VERSION\n");
        VMMDLL_MemFree(pEatMap); pEatMap = NULL;
        return 1;
    }
    {
        printf("SUCCESS: VMMDLL_Map_GetEATU\n");
        printf("         #  ORDINAL  ADDRESS NAME      ->ForwardedFunction\n");
        printf("         =================================================\n");
        for(i = 0; i < pEatMap->cMap; i++) {
            pEatMapEntry = pEatMap->pMap + i;
            printf(
                "         %04x %4x %12llx %s  ->%s\n",
                i,
                pEatMapEntry->dwOrdinal,
                pEatMapEntry->vaFunction,
                pEatMapEntry->uszFunction,
                pEatMapEntry->uszForwardedFunction
            );
        }
        VMMDLL_MemFree(pEatMap); pEatMap = NULL;
    }


    // Retrieve the import address table (IAT) of kernel32.dll
    printf("------------------------------------------------------------\n");
    printf("# imports of 'kernel32.dll' in 'explorer.exe'.              \n");
    ShowKeyPress();
    DWORD cbIatMap = 0;
    PVMMDLL_MAP_IAT pIatMap = NULL;
    PVMMDLL_MAP_IATENTRY pIatMapEntry;
    printf("CALL:    VMMDLL_Map_GetIATU\n");
    result = VMMDLL_Map_GetIATU(hVMM, dwPID, "kernel32.dll", &pIatMap);
    if(!result) {
        printf("FAIL:    VMMDLL_Map_GetIATU\n");
        return 1;
    }
    if(pIatMap->dwVersion != VMMDLL_MAP_IAT_VERSION) {
        printf("FAIL:    VMMDLL_Map_GetIATU - BAD VERSION\n");
        VMMDLL_MemFree(pIatMap); pIatMap = NULL;
        return 1;
    }
    {
        printf("SUCCESS: VMMDLL_Map_GetIATU\n");
        printf("         #    VIRTUAL_ADDRESS    MODULE!NAME\n");
        printf("         ===================================\n");
        for(i = 0; i < pIatMap->cMap; i++) {
            pIatMapEntry = pIatMap->pMap + i;
            printf(
                "         %04x %016llx   %s!%s\n",
                i,
                pIatMapEntry->vaFunction,
                pIatMapEntry->uszModule,
                pIatMapEntry->uszFunction
            );
        }
        VMMDLL_MemFree(pIatMap); pIatMap = NULL;
    }


    // Initialize the plugin manager for the Vfs functionality to work.
    printf("------------------------------------------------------------\n");
    printf("# Initialize Plugin Manager functionality as is required    \n");
    printf("     by virtual file system (vfs) functionality.            \n");
    ShowKeyPress();
    printf("CALL:    VMMDLL_InitializePlugins\n");
    result = VMMDLL_InitializePlugins(hVMM);
    if(result) {
        printf("SUCCESS: VMMDLL_InitializePlugins\n");
    } else {
        printf("FAIL:    VMMDLL_InitializePlugins\n");
        return 1;
    }


    // The Memory Process File System exists virtually in the form of a virtual
    // file system even if it may not be mounted at a mount point or drive.
    // It is possible to call the functions 'List', 'Read' and 'Write' by using
    // the API.
    // Virtual File System: 'List'.
    printf("------------------------------------------------------------\n");
    printf("# Call the file system 'List' function on the root dir.     \n");
    ShowKeyPress();
    VMMDLL_VFS_FILELIST2 VfsFileList;
    VfsFileList.dwVersion = VMMDLL_VFS_FILELIST_VERSION;
    VfsFileList.h = 0; // your handle passed to the callback functions (not used in example).
    VfsFileList.pfnAddDirectory = CallbackList_AddDirectory;
    VfsFileList.pfnAddFile = CallbackList_AddFile;
    printf("CALL:    VMMDLL_VfsListU\n");
    result = VMMDLL_VfsListU(hVMM, "\\", &VfsFileList);
    if(result) {
        printf("SUCCESS: VMMDLL_VfsListU\n");
    } else {
        printf("FAIL:    VMMDLL_VfsListU\n");
        return 1;
    }


    // Virtual File System: 'Read' of 0x100 bytes from the offset 0x1000
    // in the physical memory by reading the /pmem physical memory file.
    printf("------------------------------------------------------------\n");
    printf("# Call the file system 'Read' function on memory.pmem.      \n");
    ShowKeyPress();
    printf("CALL:    VMMDLL_VfsReadU\n");
    nt = VMMDLL_VfsReadU(hVMM, "\\memory.pmem", pbPage1, 0x100, &i, 0x1000);
    if(nt == VMMDLL_STATUS_SUCCESS) {
        printf("SUCCESS: VMMDLL_VfsReadU\n");
        PrintHexAscii(pbPage1, i);
    } else {
        printf("FAIL:    VMMDLL_VfsReadU\n");
        return 1;
    }


    // Virtual File System: 'Read' statistics from the .status module/plugin.
    printf("------------------------------------------------------------\n");
    printf("# Call file system 'Read' on conf\\statistics.txt        \n");
    ShowKeyPress();
    printf("CALL:    VMMDLL_VfsReadU\n");
    ZeroMemory(pbPage1, 0x1000);
    nt = VMMDLL_VfsReadU(hVMM, "\\conf\\statistics.txt", pbPage1, 0xfff, &i, 0);
    if(nt == VMMDLL_STATUS_SUCCESS) {
        printf("SUCCESS: VMMDLL_VfsReadU\n");
        printf("%s", (LPSTR)pbPage1);
    } else {
        printf("FAIL:    VMMDLL_VfsReadU\n");
        return 1;
    }


    // Get base virtual address of ntoskrnl.exe
    printf("------------------------------------------------------------\n");
    printf("# Get ntoskrnl.exe base virtual address                     \n");
    ShowKeyPress();
    printf("CALL:    VMMDLL_ProcessGetModuleBaseU\n");
    va = VMMDLL_ProcessGetModuleBaseU(hVMM, 4, "ntoskrnl.exe");
    if(va) {
        printf("SUCCESS: VMMDLL_ProcessGetModuleBaseU\n");
        printf("         %s = %016llx\n", "ntoskrnl.exe", va);
    } else {
        printf("FAIL:    VMMDLL_ProcessGetModuleBaseU\n");
        return 1;
    }


    // GetProcAddress from ntoskrnl.exe
    printf("------------------------------------------------------------\n");
    printf("# Get proc address for ntoskrnl.exe!KeGetCurrentIrql        \n");
    ShowKeyPress();
    printf("CALL:    VMMDLL_ProcessGetProcAddressU\n");
    va = VMMDLL_ProcessGetProcAddressU(hVMM, 4, "ntoskrnl.exe", "KeGetCurrentIrql");
    if(va) {
        printf("SUCCESS: VMMDLL_ProcessGetProcAddressU\n");
        printf("         %s!%s = %016llx\n", "ntoskrnl.exe", "KeGetCurrentIrql", va);
    } else {
        printf("FAIL:    VMMDLL_ProcessGetProcAddressU\n");
        return 1;
    }


    // Get IAT Thunk ntoskrnl.exe -> hal.dll!HalSendNMI
    printf("------------------------------------------------------------\n");
    printf("# Address of IAT thunk for hal.dll!HalSendNMI in ntoskrnl   \n");
    ShowKeyPress();
    VMMDLL_WIN_THUNKINFO_IAT oThunkInfoIAT;
    ZeroMemory(&oThunkInfoIAT, sizeof(VMMDLL_WIN_THUNKINFO_IAT));
    printf("CALL:    VMMDLL_WinGetThunkInfoIATU\n");
    result = VMMDLL_WinGetThunkInfoIATU(hVMM, 4, "ntoskrnl.Exe", "hal.Dll", "HalSendNMI", &oThunkInfoIAT);
    if(result) {
        printf("SUCCESS: VMMDLL_WinGetThunkInfoIATU\n");
        printf("         vaFunction:     %016llx\n", oThunkInfoIAT.vaFunction);
        printf("         vaThunk:        %016llx\n", oThunkInfoIAT.vaThunk);
        printf("         vaNameFunction: %016llx\n", oThunkInfoIAT.vaNameFunction);
        printf("         vaNameModule:   %016llx\n", oThunkInfoIAT.vaNameModule);
    } else {
        printf("FAIL:    VMMDLL_WinGetThunkInfoIATU\n");
        return 1;
    }


    // List Windows registry hives
    printf("------------------------------------------------------------\n");
    printf("# List Windows Registry Hives.                              \n");
    ShowKeyPress();
    DWORD cWinRegHives;
    PVMMDLL_REGISTRY_HIVE_INFORMATION pWinRegHives = NULL;
    printf("CALL:    VMMDLL_WinReg_HiveList\n");
    result = VMMDLL_WinReg_HiveList(hVMM, NULL, 0, &cWinRegHives);
    if(!result || !cWinRegHives) {
        printf("FAIL:    VMMDLL_WinReg_HiveList #1 - Get # Hives.\n");
        return 1;
    }
    pWinRegHives = LocalAlloc(LMEM_ZEROINIT, cWinRegHives * sizeof(VMMDLL_REGISTRY_HIVE_INFORMATION));
    if(!pWinRegHives) {
        printf("FAIL:    OutOfMemory\n");
        return 1;
    }
    result = VMMDLL_WinReg_HiveList(hVMM, pWinRegHives, cWinRegHives, &cWinRegHives);
    if(result && cWinRegHives) {
        printf("SUCCESS: VMMDLL_WinReg_HiveList\n");
        for(i = 0; i < cWinRegHives; i++) {
            printf("         %s\n", pWinRegHives[i].uszName);
        }
    } else {
        printf("FAIL:    VMMDLL_WinReg_HiveList #2\n");
        return 1;
    }


    // Retrieve Physical Memory Map
    printf("------------------------------------------------------------\n");
    printf("# Retrieve Physical Memory Map                              \n");
    ShowKeyPress();
    PVMMDLL_MAP_PHYSMEM pPhysMemMap = NULL;
    printf("CALL:    VMMDLL_Map_GetPhysMem\n");
    result = VMMDLL_Map_GetPhysMem(hVMM, &pPhysMemMap);
    if(!result) {
        printf("FAIL:    VMMDLL_Map_GetPhysMem #1 - Get # Hives.\n");
        return 1;
    }
    if(pPhysMemMap->dwVersion != VMMDLL_MAP_PHYSMEM_VERSION) {
        printf("FAIL:    VMMDLL_Map_GetPhysMem - BAD VERSION\n");
        VMMDLL_MemFree(pPhysMemMap); pPhysMemMap = NULL;
        return 1;
    }
    {
        printf("SUCCESS: VMMDLL_Map_GetPhysMem\n");
        for(i = 0; i < pPhysMemMap->cMap; i++) {
            printf("%04i %12llx - %12llx\n", i, pPhysMemMap->pMap[i].pa, pPhysMemMap->pMap[i].pa + pPhysMemMap->pMap[i].cb - 1);
        }
        VMMDLL_MemFree(pPhysMemMap); pPhysMemMap = NULL;
    }


    // Read 0x100 bytes from offset 0x1000 from the 1st located registry hive memory space
    printf("------------------------------------------------------------\n");
    printf("# Read 0x100 bytes from offset 0x1000 of registry hive      \n");
    ShowKeyPress();
    printf("CALL:    VMMDLL_WinReg_HiveReadEx\n");
    result = VMMDLL_WinReg_HiveReadEx(hVMM, pWinRegHives[0].vaCMHIVE, 0x1000, pbPage1, 0x100, NULL, 0);
    if(result) {
        printf("SUCCESS: VMMDLL_WinReg_HiveReadEx\n");
        PrintHexAscii(pbPage1, 0x100);
    } else {
        printf("FAIL:    VMMDLL_WinReg_HiveReadEx\n");
        return 1;
    }


    // Retrieve Page Frame Number (PFN) information for pages located at
    // physical addresses 0x00001000, 0x00677000, 0x27000000, 0x18000000
    printf("------------------------------------------------------------\n");
    printf("# Retrieve PAGE FRAME NUMBERS (PFNs)                        \n");
    ShowKeyPress();
    DWORD cbPfnMap = 0, cPfns, dwPfns[] = { 1, 0x677, 0x27000, 0x18000 };
    PVMMDLL_MAP_PFN pPfnMap = NULL;
    PVMMDLL_MAP_PFNENTRY pPfnEntry;
    cPfns = sizeof(dwPfns) / sizeof(DWORD);
    printf("CALL:    VMMDLL_Map_GetPfn #1\n");
    result = VMMDLL_Map_GetPfn(hVMM, dwPfns, cPfns, NULL, &cbPfnMap);
    if(!result) {
        printf("FAIL:    VMMDLL_Map_GetPfn #1\n");
        return 1;
    }
    pPfnMap = LocalAlloc(LMEM_ZEROINIT, cbPfnMap);
    if(!pPfnMap) {
        printf("FAIL:    OutOfMemory\n");
        return 1;
    }
    result = VMMDLL_Map_GetPfn(hVMM, dwPfns, cPfns, pPfnMap, &cbPfnMap);
    if(!result) {
        printf("FAIL:    VMMDLL_Map_GetPfn #2\n");
        return 1;
    }
    if(pPfnMap->dwVersion != VMMDLL_MAP_PFN_VERSION) {
        printf("FAIL:    VMMDLL_Map_GetPfn - BAD VERSION\n");
        return 1;
    }
    {
        printf("SUCCESS: VMMDLL_Map_GetPfn\n");
        printf("#    PFN# TYPE       TYPEEX     VA\n");
        for(i = 0; i < pPfnMap->cMap; i++) {
            pPfnEntry = pPfnMap->pMap + i;
            printf(
                "%i%8i %-10s %-10s %16llx\n",
                i,
                pPfnEntry->dwPfn,
                VMMDLL_PFN_TYPE_TEXT[pPfnEntry->PageLocation],
                VMMDLL_PFN_TYPEEXTENDED_TEXT[pPfnEntry->tpExtended],
                pPfnEntry->vaPte
                );
        }
    }


    // Retrieve services from the service control manager (SCM) and display
    // select information about the services.
    printf("------------------------------------------------------------\n");
    printf("# Retrieve SERVICES                                         \n");
    ShowKeyPress();
    PVMMDLL_MAP_SERVICE pServiceMap = NULL;
    PVMMDLL_MAP_SERVICEENTRY pServiceEntry;
    printf("CALL:    VMMDLL_Map_GetServicesU\n");
    result = VMMDLL_Map_GetServicesU(hVMM, &pServiceMap);
    if(!result) {
        printf("FAIL:    VMMDLL_Map_GetServicesU #1\n");
        return 1;
    }
    if(pServiceMap->dwVersion != VMMDLL_MAP_SERVICE_VERSION) {
        printf("FAIL:    VMMDLL_Map_GetServicesU - BAD VERSION\n");
        VMMDLL_MemFree(pServiceMap); pServiceMap = NULL;
        return 1;
    }
    {
        printf("SUCCESS: VMMDLL_Map_GetServicesU\n");
        printf("#     PID  VA-OBJ   STATE NAME                       PATH [USER]\n");
        for(i = 0; i < pServiceMap->cMap; i++) {
            pServiceEntry = pServiceMap->pMap + i;
            printf(
                "%02i%7i %12llx %02i %-32s %s [%s]\n",
                pServiceEntry->dwOrdinal,
                pServiceEntry->dwPID,
                pServiceEntry->vaObj,
                pServiceEntry->ServiceStatus.dwCurrentState,
                pServiceEntry->uszServiceName,
                pServiceEntry->uszPath,
                pServiceEntry->uszUserAcct
            );
        }
        VMMDLL_MemFree(pServiceMap); pServiceMap = NULL;
    }


    // Retrieve Pool Tag Map
    printf("------------------------------------------------------------\n");
    printf("# Retrieve Pool Tag Map                                     \n");
    ShowKeyPress();
    DWORD iPoolTagEntry = 0, iPoolEntry = 0;
    PVMMDLL_MAP_POOL pPoolMap = NULL;
    PVMMDLL_MAP_POOLENTRY pPoolEntry;
    PVMMDLL_MAP_POOLENTRYTAG pPoolTag;
    printf("CALL:    VMMDLL_Map_GetPool\n");
    result = VMMDLL_Map_GetPool(hVMM, &pPoolMap, VMMDLL_POOLMAP_FLAG_ALL);
    if(!result) {
        printf("FAIL:    VMMDLL_Map_GetPool.\n");
        return 1;
    }
    if(pPoolMap->dwVersion != VMMDLL_MAP_POOL_VERSION) {
        printf("FAIL:    VMMDLL_Map_GetPool - BAD VERSION\n");
        VMMDLL_MemFree(pPoolMap); pPoolMap = NULL;
        return 1;
    }
    if(result) {
        // print all pool tag addresses consisting of TcpE - TCP Endpoint
        // NB! The retrieval of the pool tag consiting of the first TcpE
        // entry is very inefficient (scanning approach) for simplicity.
        // For better performance a BTREE approach in the by-tag sorted
        // tag table would be better.
        printf("Scanning for 'TcpE' tag...\n");
        for(iPoolTagEntry = 0; iPoolTagEntry < pPoolMap->cTag; iPoolTagEntry++) {
            if(pPoolMap->pTag[iPoolTagEntry].dwTag == 0x45706354) {     // 0x45706354 == EpcT (TcpE in reverse)
                pPoolTag = &pPoolMap->pTag[iPoolTagEntry];
                for(i = 0; i < pPoolTag->cEntry; i++) {
                    iPoolEntry = pPoolMap->piTag2Map[pPoolTag->iTag2Map + i];
                    pPoolEntry = &pPoolMap->pMap[iPoolEntry];
                    printf("Pool Entry TcpE va = %llx size = %4x\n", pPoolEntry->va, pPoolEntry->cb);
                }
                break;
            }
        }
        printf("SUCCESS: VMMDLL_Map_GetPool\n");
    }
    VMMDLL_MemFree(pPoolMap); pPoolMap = NULL;


    // Retrieve virtual machine information and read VM memory.
    // NB! MemProcFS must have been initialized with either of below options:
    //     -forensic [1-4] -vm -vm-basic -vm-nested
    printf("------------------------------------------------------------\n");
    printf("# Retrieve Virtual Machine Map                              \n");
    ShowKeyPress();
    DWORD iVirtualMachineEntry = 0;
    PVMMDLL_MAP_VM pVirtualMachineMap = NULL;
    PVMMDLL_MAP_VMENTRY pVirtualMachineEntry;
    printf("CALL:    VMMDLL_Map_GetVMU\n");
    result = VMMDLL_Map_GetVMU(hVMM, &pVirtualMachineMap);
    if(result) {
        // print all VM names:
        for(iVirtualMachineEntry = 0; iVirtualMachineEntry < pVirtualMachineMap->cMap; iVirtualMachineEntry++) {
            pVirtualMachineEntry = pVirtualMachineMap->pMap + iVirtualMachineEntry;
            printf("VM: %02i %02x %6i %s\n",
                iVirtualMachineEntry,
                pVirtualMachineEntry->dwPartitionID,
                pVirtualMachineEntry->dwVersionBuild,
                pVirtualMachineEntry->uszName
            );
        }
        VMMDLL_MemFree(pVirtualMachineMap); pVirtualMachineMap = NULL;
    } else {
        printf("FAIL:    VMMDLL_Map_GetVMU.\n");
    }


    // Read virtual memory from multiple locations in one efficient sweep
    // using the VMMDLL_Scatter_* API functions.
    printf("------------------------------------------------------------\n");
    printf("# Read Scatter from 3+1 addresses in one efficient go.      \n");
    ShowKeyPress();
    VMMDLL_SCATTER_HANDLE hS = NULL;
    QWORD vaNt, vaHal, vaCi, vaBeep;
    BYTE pbNt[0x400];
    DWORD cbNt = 0, cbCi = 0;
    vaNt = VMMDLL_ProcessGetModuleBaseU(hVMM, 4, "ntoskrnl.exe");
    vaHal = VMMDLL_ProcessGetModuleBaseU(hVMM, 4, "hal.dll");
    vaCi = VMMDLL_ProcessGetModuleBaseU(hVMM, 4, "CI.DLL");
    vaBeep = VMMDLL_ProcessGetModuleBaseU(hVMM, 4, "beep.sys");
    // EX.1: CREATE SCATTER HANDLE
    printf("CALL:    VMMDLL_Scatter_Initialize\n");
    hS = VMMDLL_Scatter_Initialize(hVMM, 4, VMMDLL_FLAG_NOCACHE | VMMDLL_FLAG_NOPAGING_IO);
    if(hS) {
        printf("SUCCESS: VMMDLL_Scatter_Initialize\n");
    } else {
        printf("FAIL:    VMMDLL_Scatter_Initialize\n");
        return 1;
    }
    // EX.2: PREPARE / REGISTER MEMORY RANGES TO READ
    printf("CALL:    VMMDLL_Scatter_Prepare\n");
    result = VMMDLL_Scatter_PrepareEx(hS, vaNt, 0x400, pbNt, &cbNt);
    printf("%s:    VMMDLL_Scatter_PrepareEx\n", (result ? "SUCCESS" : "FAIL"));
    result = VMMDLL_Scatter_Prepare(hS, vaHal, 0x400);
    printf("%s:    VMMDLL_Scatter_Prepare\n", (result ? "SUCCESS" : "FAIL"));
    result = VMMDLL_Scatter_Prepare(hS, vaCi, 0x2000);
    printf("%s:    VMMDLL_Scatter_Prepare\n", (result ? "SUCCESS" : "FAIL"));
    result = VMMDLL_Scatter_Prepare(hS, vaBeep + 0xff0, 0x3000);
    printf("%s:    VMMDLL_Scatter_Prepare\n", (result ? "SUCCESS" : "FAIL"));
    // EX.3: READ MEMORY FROM BACKEND IN AN EFFICIENT SWEEP
    printf("CALL:    VMMDLL_Scatter_ExecuteRead\n");
    result = VMMDLL_Scatter_ExecuteRead(hS);
    if(result) {
        printf("SUCCESS: VMMDLL_Scatter_ExecuteRead\n");
    } else {
        printf("FAIL:    VMMDLL_Scatter_ExecuteRead\n");
        return 1;
    }
    // EX.4: Nt which was provided as a buffer to VMMDLL_Scatter_PrepareEx call
    //       should now be populated!
    if(cbNt) {
        printf("NTOSKRNL.EXE HEADER READ VIA VMMDLL_Scatter_PrepareEx / VMMDLL_Scatter_ExecuteRead:\n");
        PrintHexAscii(pbNt, cbNt);
    }
    // EX.5: try read memory from other ranges as well.
    printf("CALL:    VMMDLL_Scatter_Read\n");
    result = VMMDLL_Scatter_Read(hS, vaCi, 0x400, pbPage1, &cbCi);
    if(result) {
        printf("SUCCESS: VMMDLL_Scatter_Read\n");
        PrintHexAscii(pbPage1, cbCi);
    } else {
        printf("FAIL:    VMMDLL_Scatter_Read\n");
    }
    // EX.5: Close and clean-up
    printf("CALL:    VMMDLL_Scatter_CloseHandle\n");
    VMMDLL_Scatter_CloseHandle(hS);
    hS = NULL;


    // Log a message using the MemProcFS logging system. This is most
    // used by C/C++ plugins which should use the module id (MID) which
    // is supplied in the PVMMDLL_PLUGIN_CONTEXT supplied to the functions.
    // ---
    // It's also possible for the main application to make use of logging
    // by supplying the pseudo module id VMMDLL_MID_MAIN
    // ---
    // NB! MemProcFS must be initialized with -printf flag or -loglevel 3
    //     for logging to display on-screen. it's also possible to enable
    //     printf logging by setting option
    printf("------------------------------------------------------------\n");
    printf("# Log a message using the MemProcFS logging system.         \n");
    ShowKeyPress();
    printf("CALL:    VMMDLL_ConfigSet - printf enable\n");
    VMMDLL_ConfigSet(hVMM, VMMDLL_OPT_CORE_PRINTF_ENABLE, 1);
    printf("SUCCESS: VMMDLL_ConfigSet - printf enable\n");
    printf("CALL:    VMMDLL_Log\n");
    VMMDLL_Log(
        hVMM,
        VMMDLL_MID_MAIN,
        VMMDLL_LOGLEVEL_WARNING,
        "%i fake warning message from %s!", 1, "vmmdll_example");
    printf("SUCCESS: VMMDLL_Log\n");


    // Read the file /misc/procinfo/dtb.txt containing the DTBs of processes
    // in the target system. This virtual file takes a short while to render
    // after first access.
    // To make use of the virtual file system it's necessary to enable the
    // MemProcFS plugins first. This API call is only required once.
    printf("------------------------------------------------------------\n");
    printf("# Access /misc/procinfo/dtb.txt                             \n");
    ShowKeyPress();
    VMMDLL_InitializePlugins(hVMM);
    printf("CALL:    VMMDLL_VfsRead\n");
    ZeroMemory(pbPage1, sizeof(pbPage1));
    BOOL fResultDTB = FALSE;
    while(TRUE) {
        nt = VMMDLL_VfsReadU(hVMM, "\\misc\\procinfo\\progress_percent.txt", pbPage1, 3, &cbRead, 0);
        if(nt == VMMDLL_STATUS_SUCCESS) {
            printf("SUCCESS: VMMDLL_VfsRead: %s\n", (LPSTR)pbPage1);
            if(!strcmp((LPSTR)pbPage1, "100")) {
                // success - progress is at 100% - read the file.
                PBYTE pb1M = LocalAlloc(LMEM_ZEROINIT, 0x00100000);
                if(pb1M) {
                    nt = VMMDLL_VfsReadU(hVMM, "\\misc\\procinfo\\dtb.txt", pb1M, 0x00100000, &cbRead, 0);
                    if(nt == VMMDLL_STATUS_SUCCESS) {
                        printf("SUCCESS: VMMDLL_VfsRead:\n%s\n", (LPSTR)pb1M);
                    } else {
                        printf("FAIL:    VMMDLL_VfsRead\n");
                        return 1;
                    }
                    LocalFree(pb1M); pb1M = NULL;
                }
                break;
            }
            Sleep(100);
        } else {
            printf("FAIL:    VMMDLL_VfsRead\n");
            return 1;
        }
    }


    // Use a Memory Callback function to alter the MemProcFS view of underlying
    // physical memory. This can be useful to implement alternative views of
    // memory and/or for debugging and logging purposes.
    // It's possible to register a callback function which will be called every
    // time a physical memory read or write is performed.
    // It also works for any process internal virtual memory read or write.
    // For this example to work we'll read uncached memory since a cache hit
    // would prevent the need for a 2nd physical memory read.
    {
        printf("------------------------------------------------------------\n");
        printf("# Demonstrate memory callback functionality:                \n");
        printf("     (1) Read existing data from physical memory at 0x1000  \n");
        printf("     (2) Register a callback function:                      \n");
        printf("     (3) Read existing data from physical memory at 0x1000  \n");
        printf("     (4) Unregister the callback function:                  \n");
        ShowKeyPress();
        printf("CALL:    VMMDLL_MemRead - BEFORE CALLBACK\n");
        result = VMMDLL_MemReadEx(hVMM, -1, 0x1000, pbPage1, 0x1000, NULL, VMMDLL_FLAG_NOCACHE);
        if(result) {
            printf("SUCCESS: VMMDLL_MemRead - BEFORE CALLBACK\n");
            PrintHexAscii(pbPage1, 0x80);
        } else {
            printf("FAIL:    VMMDLL_MemRead - BEFORE CALLBACK\n");
            return 1;
        }
        printf("CALL:    VMMDLL_MemCallback (Register)\n");
        VMMDLL_MemCallback(hVMM, VMMDLL_MEM_CALLBACK_READ_PHYSICAL_POST, NULL, CallbackMemCallback_PhysicalReadPost);
        printf("CALL:    VMMDLL_MemRead - AFTER CALLBACK\n");
        result = VMMDLL_MemReadEx(hVMM, -1, 0x1000, pbPage1, 0x1000, NULL, VMMDLL_FLAG_NOCACHE);
        if(result) {
            printf("SUCCESS: VMMDLL_MemRead - AFTER CALLBACK\n");
            PrintHexAscii(pbPage1, 0x80);
        } else {
            printf("FAIL:    VMMDLL_MemRead - AFTER CALLBACK\n");
            return 1;
        }
        printf("CALL:    VMMDLL_MemCallback (Unregister)\n");
        VMMDLL_MemCallback(hVMM, VMMDLL_MEM_CALLBACK_READ_PHYSICAL_POST, NULL, NULL);
    }




    // PDB/Symbol functionality: Get the module name of a loaded PDB file.
    printf("------------------------------------------------------------\n");
    printf("# PDB: Get the PDB file path of kernel32.dll                \n");
    ShowKeyPress();
    printf("CALL:    VMMDLL_Map_GetModuleFromNameU\n");
    PVMMDLL_MAP_MODULEENTRY pPdbModuleEntryNtdll;
    result = VMMDLL_Map_GetModuleFromNameU(hVMM, dwPID, "ntdll.dll", &pPdbModuleEntryNtdll, 0);
    if(!result) {
        printf("FAIL:    VMMDLL_Map_GetModuleFromNameU\n");
        return 1;
    }
    printf("CALL:    VMMDLL_PdbLoad\n");
    CHAR szPdbModuleName_NtDll[MAX_PATH] = { 0 };
    result = VMMDLL_PdbLoad(hVMM, dwPID, pPdbModuleEntryNtdll->vaBase, szPdbModuleName_NtDll);
    if(!result) {
        printf("FAIL:    VMMDLL_PdbLoad\n");
        return 1;
    }
    printf("SUCCESS: VMMDLL_PdbLoad [%s]\n", szPdbModuleName_NtDll);


    // PDB/Symbol functionality: Get the address of the symbol/function 'ntdll!LdrLoadDll'
    printf("------------------------------------------------------------\n");
    printf("# PDB: Get symbol address of ntdll.dll!LdrLoadDll    \n");
    ShowKeyPress();
    printf("CALL:    VMMDLL_PdbSymbolAddress\n");
    QWORD vaPdbSymbolAddress_LdrLoadDll = 0;
    result = VMMDLL_PdbSymbolAddress(hVMM, szPdbModuleName_NtDll, "LdrLoadDll", &vaPdbSymbolAddress_LdrLoadDll);
    if(!result) {
        printf("FAIL:    VMMDLL_PdbSymbolAddress\n");
        return 1;
    }
    printf("SUCCESS: VMMDLL_PdbSymbolAddress [%llx]\n", vaPdbSymbolAddress_LdrLoadDll);


    // PDB/Symbol functionality: Get the symbol (exactly/near) of the address of the function 'LdrLoadDll'
    printf("------------------------------------------------------------\n");
    printf("# PDB: Get symbol name exactly/near(+0) address             \n");
    ShowKeyPress();
    printf("CALL:    VMMDLL_PdbSymbolName\n");
    DWORD dwPdbSymbolDisplacement1 = 0;
    result = VMMDLL_PdbSymbolName(hVMM, szPdbModuleName_NtDll, vaPdbSymbolAddress_LdrLoadDll, usz, &dwPdbSymbolDisplacement1);
    if(!result) {
        printf("FAIL:    VMMDLL_PdbSymbolName\n");
        return 1;
    }
    printf("SUCCESS: VMMDLL_PdbSymbolName name:[%s] displacement:[%x]\n", usz, dwPdbSymbolDisplacement1);


    // PDB/Symbol functionality: Get the symbol (exactly/near) of the address of the function 'LdrLoadDll'
    printf("------------------------------------------------------------\n");
    printf("# PDB: Get symbol name near(+10) address                    \n");
    ShowKeyPress();
    printf("CALL:    VMMDLL_PdbSymbolName\n");
    DWORD dwPdbSymbolDisplacement2 = 0;
    result = VMMDLL_PdbSymbolName(hVMM, szPdbModuleName_NtDll, vaPdbSymbolAddress_LdrLoadDll + 0x10, usz, &dwPdbSymbolDisplacement2);
    if(!result) {
        printf("FAIL:    VMMDLL_PdbSymbolName\n");
        return 1;
    }
    printf("SUCCESS: VMMDLL_PdbSymbolName name:[%s] displacement:[%x]\n", usz, dwPdbSymbolDisplacement2);


    // PDB/Symbol functionality: Get type size of the kernel structure '_EPROCESS'
    // The kernel is a special 'module' which is loaded by the name of 'nt', i.e.
    // no previous call to 'VMMDLL_PdbLoad()' is required.
    printf("------------------------------------------------------------\n");
    printf("# PDB: Get type size of _EPROCESS                           \n");
    ShowKeyPress();
    printf("CALL:    VMMDLL_PdbTypeSize\n");
    DWORD dwPdbTypeSize = 0;
    result = VMMDLL_PdbTypeSize(hVMM, "nt", "_EPROCESS", &dwPdbTypeSize);
    if(!result) {
        printf("FAIL:    VMMDLL_PdbTypeSize\n");
        return 1;
    }
    printf("SUCCESS: VMMDLL_PdbTypeSize name:[_EPROCESS] type_size:[%x]\n", dwPdbTypeSize);


    // PDB/Symbol functionality: Get type offset of the _EPROCESS.Token child member.
    // The kernel is a special 'module' which is loaded by the name of 'nt', i.e.
    // no previous call to 'VMMDLL_PdbLoad()' is required.
    printf("------------------------------------------------------------\n");
    printf("# PDB: Get type child offset of _EPROCESS.Token              \n");
    ShowKeyPress();
    printf("CALL:    VMMDLL_PdbTypeChildOffset\n");
    DWORD dwPdbTypeChildOffset = 0;
    result = VMMDLL_PdbTypeChildOffset(hVMM, "nt", "_EPROCESS", "Token", &dwPdbTypeChildOffset);
    if(!result) {
        printf("FAIL:    VMMDLL_PdbTypeChildOffset\n");
        return 1;
    }
    printf("SUCCESS: VMMDLL_PdbTypeChildOffset name:[_EPROCESS.Token] child_offset:[%x]\n", dwPdbTypeChildOffset);




    // Close the VMM_HANDLE and clean up native resources.
    printf("------------------------------------------------------------\n");
    printf("# Close the VMM_HANDLE (hVMM) to clean up native resources. \n");
    ShowKeyPress();
    VMMDLL_MemFree(pModuleEntryKernel32); pModuleEntryKernel32 = NULL;
    VMMDLL_MemFree(pModuleEntryExplorer); pModuleEntryExplorer = NULL;
    printf("CALL:    VMMDLL_Close #1\n");
    VMMDLL_Close(hVMM);
    

    // Finish everything and exit!
    printf("------------------------------------------------------------\n");
    printf("# FINISHED EXAMPLES!                                        \n");
    ShowKeyPress();
    printf("FINISHED TEST CASES - EXITING!\n");
    return 0;
}
