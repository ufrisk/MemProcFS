// statistics.h : definitions of statistics related functionality.
//
// (c) Ulf Frisk, 2016-2021
// Author: Ulf Frisk, pcileech@frizk.net
//
#ifndef __STATISTICS_H__
#define __STATISTICS_H__
#include "vmm.h"

#define PAGE_STATISTICS_MEM_MAP_MAX_ENTRY    2048

typedef struct tdPageStatistics {
    QWORD qwAddr;
    QWORD cPageTotal;
    QWORD cPageSuccess;
    QWORD cPageFail;
    BOOL fKMD;
    LPSTR szAction;
    struct _InternalUseOnly {
        BOOL fUpdate;
        BOOL fThreadExit;
        BOOL fMemMap;
        BOOL fIsFirstPrintCompleted;
        HANDLE hThread;
        WORD wConsoleCursorPosition;
        QWORD qwTickCountStart;
        QWORD MemMapIdx;
        QWORD MemMapPrintIdx;
        struct {
            QWORD qwAddrBase;
            DWORD cPages;
        } MemMap[PAGE_STATISTICS_MEM_MAP_MAX_ENTRY];
    } i;
} PAGE_STATISTICS, *PPAGE_STATISTICS;

/*
* Initialize the page statistics. This will also start displaying the page statistics
* on the screen asynchronously. PageStatClose must be called to stop this.
* -- ps = ptr to NULL pPageStat PageStatInitialize will initialize. Must be free'd with PageStatClose.
* -- qwAddrBase = the base address that the statistics will be based upon.
* -- qwAddrMax = the maximum address.
* -- szAction = the text shown as action.
* -- fKMD = is KMD mode.
* -- fPageMap = display read memory map when PageStatClose is called.
* -- return
*/
_Success_(return)
BOOL PageStatInitialize(_Out_ PPAGE_STATISTICS *ppPageStat, _In_ QWORD qwAddrBase, _In_ QWORD qwAddrMax, _In_ LPSTR szAction, _In_ BOOL fKMD, _In_ BOOL fMemMap);

/*
* Do one last update of the on-screen page statistics, display the read memory map if
* previously set in PageStatInitialize and stop the on-screen updates.
* -- pPageStat = ptr to the PPAGE_STATISTICS struct to close and free.
*/
VOID PageStatClose(_In_opt_ PPAGE_STATISTICS *ppPageStat);

/*
* Update the page statistics with the current address and with successfully and failed
* pages. Should not be called before PageStatInitialize and not after PageStatClose.
* This function must be used if the memory map should be shown; otherwise it's possible
* to alter the PPAGE_STATISTICS struct members directly.
* -- pPageStat = pointer to page statistics struct.
* -- qwAddr = new address (after completed operation).
* -- cPageSuccessAdd = number of successfully read pages.
* -- cPageFailAdd = number of pages that failed.
*/
VOID PageStatUpdate(_In_opt_ PPAGE_STATISTICS pPageStat, _In_ QWORD qwAddr, _In_ QWORD cPageSuccessAdd, _In_ QWORD cPageFailAdd);

// NB! also update STATISTICS_ID_STR
#define STATISTICS_ID_INITIALIZE                                0x00
#define STATISTICS_ID_PluginManager_List                        0x01
#define STATISTICS_ID_PluginManager_Read                        0x02
#define STATISTICS_ID_PluginManager_Write                       0x03
#define STATISTICS_ID_PluginManager_Notify                      0x04
#define STATISTICS_ID_PluginManager_FcInitialize                0x05
#define STATISTICS_ID_PluginManager_FcFinalize                  0x06
#define STATISTICS_ID_PluginManager_FcTimeline                  0x07
#define STATISTICS_ID_PluginManager_FcLogJSON                   0x08
#define STATISTICS_ID_PluginManager_FcIngestPhysmem             0x09
#define STATISTICS_ID_PluginManager_FcIngestFinalize            0x0a
#define STATISTICS_ID_FORENSIC_FcInitialize                       0x0b
#define STATISTICS_ID_VMMDLL_VfsList                            0x0c
#define STATISTICS_ID_VMMDLL_VfsRead                            0x0d
#define STATISTICS_ID_VMMDLL_VfsWrite                           0x0e
#define STATISTICS_ID_VMMDLL_InitializePlugins                  0x0f
#define STATISTICS_ID_VMMDLL_MemReadEx                          0x10
#define STATISTICS_ID_VMMDLL_MemReadScatter                     0x11
#define STATISTICS_ID_VMMDLL_MemWrite                           0x12
#define STATISTICS_ID_VMMDLL_MemVirt2Phys                       0x13
#define STATISTICS_ID_VMMDLL_MemPrefetchPages                   0x14
#define STATISTICS_ID_VMMDLL_PidList                            0x15
#define STATISTICS_ID_VMMDLL_PidGetFromName                     0x16
#define STATISTICS_ID_VMMDLL_ProcessGetInformation              0x17
#define STATISTICS_ID_VMMDLL_ProcessGetInformationString        0x18
#define STATISTICS_ID_VMMDLL_Map_GetPte                         0x19
#define STATISTICS_ID_VMMDLL_Map_GetVad                         0x1a
#define STATISTICS_ID_VMMDLL_Map_GetVadEx                       0x1b
#define STATISTICS_ID_VMMDLL_Map_GetModule                      0x1c
#define STATISTICS_ID_VMMDLL_Map_GetModuleFromName              0x1d
#define STATISTICS_ID_VMMDLL_Map_GetUnloadedModule              0x1e
#define STATISTICS_ID_VMMDLL_Map_GetEAT                         0x1f
#define STATISTICS_ID_VMMDLL_Map_GetIAT                         0x20
#define STATISTICS_ID_VMMDLL_Map_GetHeap                        0x21
#define STATISTICS_ID_VMMDLL_Map_GetThread                      0x22
#define STATISTICS_ID_VMMDLL_Map_GetHandle                      0x23
#define STATISTICS_ID_VMMDLL_Map_GetPhysMem                     0x24
#define STATISTICS_ID_VMMDLL_Map_GetNet                         0x25
#define STATISTICS_ID_VMMDLL_Map_GetUsers                       0x26
#define STATISTICS_ID_VMMDLL_Map_GetServices                    0x27
#define STATISTICS_ID_VMMDLL_Map_GetPfn                         0x28
#define STATISTICS_ID_VMMDLL_ProcessGetDirectories              0x29
#define STATISTICS_ID_VMMDLL_ProcessGetSections                 0x2a
#define STATISTICS_ID_VMMDLL_ProcessGetProcAddress              0x2b
#define STATISTICS_ID_VMMDLL_ProcessGetModuleBase               0x2c
#define STATISTICS_ID_VMMDLL_WinGetThunkIAT                     0x2d
#define STATISTICS_ID_VMMDLL_WinMemCompression_DecompressPage   0x2e
#define STATISTICS_ID_VMMDLL_WinRegHive_List                    0x2f
#define STATISTICS_ID_VMMDLL_WinRegHive_ReadEx                  0x30
#define STATISTICS_ID_VMMDLL_WinRegHive_Write                   0x31
#define STATISTICS_ID_VMMDLL_WinReg_EnumKeyExW                  0x32
#define STATISTICS_ID_VMMDLL_WinReg_EnumValueW                  0x33
#define STATISTICS_ID_VMMDLL_WinReg_QueryValueEx               0x34
#define STATISTICS_ID_VMMDLL_UtilFillHexAscii                   0x35
#define STATISTICS_ID_VMMDLL_PdbLoad                            0x36
#define STATISTICS_ID_VMMDLL_PdbSymbolName                      0x37
#define STATISTICS_ID_VMMDLL_PdbSymbolAddress                   0x38
#define STATISTICS_ID_VMMDLL_PdbTypeSize                        0x39
#define STATISTICS_ID_VMMDLL_PdbTypeChildOffset                 0x3a
#define STATISTICS_ID_VMM_PagedCompressedMemory                 0x3b
#define STATISTICS_ID_MAX                                       0x3b
#define STATISTICS_ID_NOLOG                                     0xffffffff

static LPCSTR STATISTICS_ID_STR[] = {
    "INITIALIZE",
    "PluginManager_List",
    "PluginManager_Read",
    "PluginManager_Write",
    "PluginManager_Notify",
    "PluginManager_FcInitialize",
    "PluginManager_FcFinalize",
    "PluginManager_FcTimeline",
    "PluginManager_FcLogJSON",
    "PluginManager_IngestPhysmem",
    "PluginManager_IngestFinalize",
    "FORENSIC_FcInitialize",
    "VMMDLL_VfsList",
    "VMMDLL_VfsRead",
    "VMMDLL_VfsWrite",
    "VMMDLL_InitializePlugins",
    "VMMDLL_MemReadEx",
    "VMMDLL_MemReadScatter",
    "VMMDLL_MemWrite",
    "VMMDLL_MemVirt2Phys",
    "VMMDLL_MemPrefetchPages",
    "VMMDLL_PidList",
    "VMMDLL_PidGetFromName",
    "VMMDLL_ProcessGetInformation",
    "VMMDLL_ProcessGetInformationString",
    "VMMDLL_Map_GetPte",
    "VMMDLL_Map_GetVad",
    "VMMDLL_Map_GetVadEx",
    "VMMDLL_Map_GetModule",
    "VMMDLL_Map_GetModuleFromName",
    "VMMDLL_Map_GetUnloadedModule",
    "VMMDLL_Map_GetEAT",
    "VMMDLL_Map_GetIAT",
    "VMMDLL_Map_GetHeap",
    "VMMDLL_Map_GetThread",
    "VMMDLL_Map_GetHandle",
    "VMMDLL_Map_GetPhysMem",
    "VMMDLL_Map_GetNet",
    "VMMDLL_Map_GetUsers",
    "VMMDLL_Map_GetServices",
    "VMMDLL_Map_GetPfn",
    "VMMDLL_ProcessGetDirectories",
    "VMMDLL_ProcessGetSections",
    "VMMDLL_ProcessGetProcAddress",
    "VMMDLL_ProcessGetModuleBase",
    "VMMDLL_WinGetThunkIAT",
    "VMMDLL_WinMemCompression_DecompressPage",
    "VMMDLL_WinRegHive_List",
    "VMMDLL_WinRegHive_ReadEx",
    "VMMDLL_WinRegHive_Write",
    "VMMDLL_WinReg_EnumKeyExW",
    "VMMDLL_WinReg_EnumValueW",
    "VMMDLL_WinReg_QueryValueExW",
    "VMMDLL_UtilFillHexAscii",
    "VMMDLL_PdbLoad",
    "VMMDLL_PdbSymbolName",
    "VMMDLL_PdbSymbolAddress",
    "VMMDLL_PdbTypeSize",
    "VMMDLL_PdbTypeChildOffset",
    "VMM_PagedCompressedMemory",
};

VOID Statistics_CallSetEnabled(_In_ BOOL fEnabled);
BOOL Statistics_CallGetEnabled();
QWORD Statistics_CallStart();
QWORD Statistics_CallEnd(_In_ DWORD fId, QWORD tmCallStart);

/*
* Retrieve call statistics as a string buffer and size. If psz is not supplied
* only retrieve size.
* CALLER LocalFree: psz
* -- psz
* -- pcsz
* -- return
*/
_Success_(return)
BOOL Statistics_CallToString(_Out_opt_ LPSTR *psz, _Out_ PDWORD pcsz);

#endif /* __STATISTICS_H__ */
