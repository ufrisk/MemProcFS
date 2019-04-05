// statistics.h : definitions of statistics related functionality.
//
// (c) Ulf Frisk, 2016-2019
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

// NB! also update statistics.c!NAMES_VMM_STATISTICS_CALL
#define STATISTICS_ID_INITIALIZE                                0x00
#define STATISTICS_ID_VMMDLL_VfsList                            0x01
#define STATISTICS_ID_VMMDLL_VfsRead                            0x02
#define STATISTICS_ID_VMMDLL_VfsWrite                           0x03
#define STATISTICS_ID_VMMDLL_VfsInitializePlugins               0x04
#define STATISTICS_ID_VMMDLL_MemReadEx                          0x05
#define STATISTICS_ID_VMMDLL_MemReadScatter                     0x06
#define STATISTICS_ID_VMMDLL_MemWrite                           0x07
#define STATISTICS_ID_VMMDLL_MemVirt2Phys                       0x08
#define STATISTICS_ID_VMMDLL_MemPrefetchPages                   0x09
#define STATISTICS_ID_VMMDLL_PidList                            0x0a
#define STATISTICS_ID_VMMDLL_PidGetFromName                     0x0b
#define STATISTICS_ID_VMMDLL_ProcessGetInformation              0x0c
#define STATISTICS_ID_VMMDLL_ProcessGetMemoryMap                0x0d
#define STATISTICS_ID_VMMDLL_ProcessGetMemoryMapEntry           0x0e
#define STATISTICS_ID_VMMDLL_ProcessGetModuleMap                0x0f
#define STATISTICS_ID_VMMDLL_ProcessGetModuleFromName           0x10
#define STATISTICS_ID_VMMDLL_ProcessGetDirectories              0x11
#define STATISTICS_ID_VMMDLL_ProcessGetSections                 0x12
#define STATISTICS_ID_VMMDLL_ProcessGetEAT                      0x13
#define STATISTICS_ID_VMMDLL_ProcessGetIAT                      0x14
#define STATISTICS_ID_VMMDLL_ProcessGetProcAddress              0x15
#define STATISTICS_ID_VMMDLL_ProcessGetModuleBase               0x16
#define STATISTICS_ID_VMMDLL_WinGetThunkEAT                     0x17
#define STATISTICS_ID_VMMDLL_WinGetThunkIAT                     0x18
#define STATISTICS_ID_VMMDLL_WinMemCompression_DecompressPage   0x19
#define STATISTICS_ID_VMMDLL_Refresh                            0x1a
#define STATISTICS_ID_PluginManager_List                        0x1b
#define STATISTICS_ID_PluginManager_Read                        0xac
#define STATISTICS_ID_PluginManager_Write                       0x1d
#define STATISTICS_ID_PluginManager_Notify                      0x1e
#define STATISTICS_ID_MAX                                       0x1e
#define STATISTICS_ID_NOLOG                                     0xffffffff

VOID Statistics_CallSetEnabled(_In_ BOOL fEnabled);
BOOL Statistics_CallGetEnabled();
QWORD Statistics_CallStart();
VOID Statistics_CallEnd(_In_ DWORD fId, QWORD tmCallStart);
VOID Statistics_CallToString(_In_opt_ PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcb);

#endif /* __STATISTICS_H__ */
