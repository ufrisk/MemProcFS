// vmmwintcpip.c :  implementation of functionality related to the Windows networking.
//
// (c) Ulf Frisk, 2019
// Author: Ulf Frisk, pcileech@frizk.net
//

#include "vmmwintcpip.h"
#include "pe.h"
#include "vmmproc.h"
#include "vmmwin.h"
#include "util.h"

#define AF_INET6        23      // Ws2tcpip.h

typedef struct _RTL_DYNAMIC_HASH_TABLE {
    DWORD Flags;                // +000
    DWORD Shift;                // +004
    DWORD TableSize;            // +008
    DWORD Pivot;                // +00c
    DWORD DivisorMask;          // +010
    DWORD NumEntries;           // +014
    DWORD NonEmptyBuckets;      // +018
    DWORD NumEnumerators;       // +01c
    QWORD Directory;            // +020
} RTL_DYNAMIC_HASH_TABLE, *PRTL_DYNAMIC_HASH_TABLE;

// ----------------------------------------------------------------------------
// PARTITION TABLE LOCALIZATION FUNCTIONALITY BELOW:
// Locate the tcpip.sys!PartitionTable which contains references to hash maps
// which in turn contains entries to TCP ENDPOINTS (TcpE).
// The PartitionTable is located by scanning for potential pointers in the
// tcpip.sys .data section and then judging if it's the PartitionTable by
// looking at the contents of it.
// The PartitionTable is only localized once. It's assumed that the location
// in virtual memory won't change.
// ----------------------------------------------------------------------------

#define VMMWINTCPIP_PARTITIONTABLE_OFFSET20(pbPT, vaPT)     (*(PQWORD)pbPT && !*(PQWORD)(pbPT + 0x30) && ((vaPT + 0x20) == *(PQWORD)(pbPT + 0x20)) && ((vaPT + 0x20) == *(PQWORD)(pbPT + 0x28)))
#define VMMWINTCPIP_PARTITIONTABLE_OFFSET18(pbPT, vaPT)     (*(PQWORD)pbPT && !*(PQWORD)(pbPT + 0x28) && ((vaPT + 0x18) == *(PQWORD)(pbPT + 0x18)) && ((vaPT + 0x18) == *(PQWORD)(pbPT + 0x20)))
#define VMMWINTCPIP_PARTITIONTABLE_WIN10_1903(pbPT)         (VMM_KADDR64_16(*(PQWORD)(pbPT + 0x00)) && VMM_KADDR64_16(*(PQWORD)(pbPT + 0x08)) && VMM_KADDR64_16(*(PQWORD)(pbPT + 0x10)) && (*(PQWORD)(pbPT + 0x08) - *(PQWORD)(pbPT + 0x00) < 0x200) && (*(PQWORD)(pbPT + 0x10) - *(PQWORD)(pbPT + 0x08) < 0x200))

QWORD VmmWinTcpIp_GetPartitionTable64_PageAligned(_In_ PVMM_PROCESS pSystemProcess, _In_ PBYTE pbData, _In_ DWORD cbData)
{
    BOOL f;
    QWORD va;
    BYTE pb[0x38];
    POB_VSET pObSet = NULL;
    DWORD i, cbRead, dwPoolHdr;
    if(!(pObSet = ObVSet_New())) { goto fail; }
    // 1: fetch potential page-aligned candidates
    for(i = 0; i < cbData - 8; i += 8) {
        va = *(PQWORD)(pbData + i);
        if(VMM_KADDR64_PAGE(va)) {
            ObVSet_Push(pObSet, va);
        }
    }
    VmmCachePrefetchPages(pSystemProcess, pObSet);
    // 2: filter potential page-aligned candidates
    while((va = ObVSet_Pop(pObSet))) {
        VmmReadEx(pSystemProcess, va, pb, 0x38, &cbRead, VMM_FLAG_FORCECACHE_READ);
        if(cbRead != 0x38) { continue; }
        f = VMMWINTCPIP_PARTITIONTABLE_OFFSET20(pb, va) ||
            VMMWINTCPIP_PARTITIONTABLE_OFFSET18(pb, va) ||
            VMMWINTCPIP_PARTITIONTABLE_WIN10_1903(pb);
        f = f &&
            VMM_KADDR64_8(*(PQWORD)pb) &&
            VmmRead(pSystemProcess, *(PQWORD)pb - 0x0c, (PBYTE)&dwPoolHdr, 4) &&
            dwPoolHdr == 'THcT';    // TcHT pool header
        if(f) {
            Ob_DECREF(pObSet);
            return va;
        }
    }
fail:
    Ob_DECREF(pObSet);
    return 0;
}

QWORD VmmWinTcpIp_GetPartitionTable64_PoolHdr(_In_ PVMM_PROCESS pSystemProcess, _In_ PBYTE pbData, _In_ DWORD cbData)
{
    BOOL f;
    QWORD va;
    BYTE pb[0x48];
    POB_VSET pObSet = NULL;
    DWORD i, cbRead;
    if(!(pObSet = ObVSet_New())) { goto fail; }
    // 1: fetch potential candidates
    for(i = 0; i < cbData - 8; i += 8) {
        va = *(PQWORD)(pbData + i);
        if(VMM_KADDR64_16(va)) {
            ObVSet_Push(pObSet, va);
        }
    }
    VmmCachePrefetchPages3(pSystemProcess, pObSet, 0x48);
    // 2: filter potential candidates
    while((va = ObVSet_Pop(pObSet))) {
        VmmReadEx(pSystemProcess, va - 0x10, pb, 0x48, &cbRead, VMM_FLAG_FORCECACHE_READ);
        if((cbRead != 0x48) || (*(PDWORD)(pb + 0x04) != 'tPcT')) { continue; }  // TcPt pool header
        f = VMMWINTCPIP_PARTITIONTABLE_OFFSET20(pb + 0x10, va) ||
            VMMWINTCPIP_PARTITIONTABLE_OFFSET18(pb + 0x10, va) ||
            VMMWINTCPIP_PARTITIONTABLE_WIN10_1903(pb + 0x10);
        if(f) {
            Ob_DECREF(pObSet);
            return va;
        }
    }
fail:
    Ob_DECREF(pObSet);
    return 0;
}

/*
* Retrieve the address of the partition table and populate ctxVmm->TcpIp.vaPartitionTable
*/
VOID VmmWinTcpIp_GetPartitionTable64(_In_ PVMM_PROCESS pSystemProcess)
{
    DWORD cbData;
    PBYTE pbData = NULL;
    PVMMOB_MODULEMAP pObModuleMap = NULL;
    PVMM_MODULEMAP_ENTRY pModuleMapEntry;
    IMAGE_SECTION_HEADER oSectionHeader;
    if(ctxVmm->TcpIp.fInitialized) { return; }
    EnterCriticalSection(&ctxVmm->TcpIp.LockUpdate);
    if(ctxVmm->TcpIp.fInitialized) {
        LeaveCriticalSection(&ctxVmm->TcpIp.LockUpdate);
        return;
    }
    // 1: fetch tcpip.sys .data section - it contains a pointer to tcpip!PartitionTable [TcPt]
    if(!VmmProc_ModuleMapGetSingleEntry(pSystemProcess, L"tcpip.sys", &pObModuleMap, &pModuleMapEntry)) {
        vmmprintfv_fn("CANNOT LOCATE tcpip.sys.\n")
        goto fail;
    }
    if(!PE_SectionGetFromName(pSystemProcess, pModuleMapEntry->BaseAddress, ".data", &oSectionHeader)) {
        vmmprintfv_fn("CANNOT READ tcpip.sys .data PE SECTION.\n")
        goto fail;
    }
    cbData = oSectionHeader.Misc.VirtualSize;
    if(!cbData || cbData > 0x00100000) { goto fail; }
    if(!(pbData = LocalAlloc(0, cbData))) { goto fail; }
    if(!VmmRead(pSystemProcess, pModuleMapEntry->BaseAddress + oSectionHeader.VirtualAddress, pbData, cbData)) { goto fail; }
    // 2: Locate tcpip!PartitionTable - it can either be in a page-aligned full page or in a smaller allocation with pool header
    ctxVmm->TcpIp.vaPartitionTable = VmmWinTcpIp_GetPartitionTable64_PageAligned(pSystemProcess, pbData, cbData);
    if(!ctxVmm->TcpIp.vaPartitionTable) {
        ctxVmm->TcpIp.vaPartitionTable = VmmWinTcpIp_GetPartitionTable64_PoolHdr(pSystemProcess, pbData, cbData);
    }
fail:
    LeaveCriticalSection(&ctxVmm->TcpIp.LockUpdate);
    ctxVmm->TcpIp.fInitialized = TRUE;
    Ob_DECREF(pObModuleMap);
    LocalFree(pbData);
    if(!ctxVmm->TcpIp.vaPartitionTable) {
        vmmprintfv_fn("NET FUNCTIONALITY DISABLED.\n")
    }
}

// ----------------------------------------------------------------------------
// TCP ENDPOINT FUNCTIONALITY BELOW:
// ----------------------------------------------------------------------------

/*
* qsort compare function for sorting the TCP connection list
*/
int VmmWinTcpIp_TcpE_CmpSort(PVMMWIN_TCPIP_ENTRY a, PVMMWIN_TCPIP_ENTRY b)
{
    if(a->dwPID != b->dwPID) {
        return a->dwPID - b->dwPID;
    }
    if(memcmp(a->Src.pbA, b->Src.pbA, 16)) {
        return memcmp(a->Src.pbA, b->Src.pbA, 16);
    }
    if(memcmp(a->Dst.pbA, b->Dst.pbA, 16)) {
        return memcmp(a->Dst.pbA, b->Dst.pbA, 16);
    }
    return a->Src.wPort - b->Src.wPort;
}

/*
* Fuzz offsets in TcpE if required. Upon a successful fuzz values will be stored
* in the ctxVmm global context.
* -- pSystemProcess
* -- vaTcpE - virtual address of a TCP ENDPOINT entry (TcpE).
*/
VOID VmmWinTcpIp_TcpE_Fuzz(_In_ PVMM_PROCESS pSystemProcess, _In_ QWORD vaTcpE)
{
    BOOL f;
    QWORD o, va;
    DWORD dwPoolTagInNl, dwAfInet;
    BYTE pb[0x300];
    PVMM_PROCESS pObProcess = NULL;
    PVMMWIN_TCPIP_OFFSET_TcpE po = &ctxVmm->TcpIp.OTcpE;
    if(po->_fValid || po->_fProcessedTry) { goto fail; }
    po->_fProcessedTry = TRUE;
    if(!VmmRead(pSystemProcess, vaTcpE, pb, 0x300)) { goto fail; }
    // Search for EPROCESS value in TcpE struct
    while((pObProcess = VmmProcessGetNext(pObProcess, VMM_FLAG_PROCESS_SHOW_TERMINATED))) {
        for(o = 0x80; o < 0x300; o += 8) {
            va = *(PQWORD)(pb + o);
            if(!VMM_KADDR64_16(va)) { continue; }
            if(va == pObProcess->win.EPROCESS.va) {
                po->EProcess = (WORD)o;
                // INET_AF offset:
                f = VMM_KADDR64_16(*(PQWORD)(pb + 0x10)) &&
                    VmmRead(pSystemProcess, *(PQWORD)(pb + 0x10) - 0x0c, (PBYTE)&dwPoolTagInNl, 4) &&
                    (dwPoolTagInNl == 'lNnI');
                po->INET_AF = f ? 0x10 : 0x18;
                // INET_AF AF offset
                f = VmmRead(pSystemProcess, *(PQWORD)(pb + po->INET_AF) + 0x14, (PBYTE)&dwAfInet, 4) &&
                    ((dwAfInet == AF_INET) || (dwAfInet == AF_INET6));
                po->INET_AF_AF = f ? 0x14 : 0x18;
                // check for state offset
                po->State = (*(PDWORD)(pb + 0x6c) < 0x20) ? 0x6c : 0x68;
                // static or relative offsets
                po->INET_Addr = po->INET_AF + 0x08;
                po->FLink = 0x40;
                po->PortSrc = po->State + 0x04;
                po->PortDst = po->State + 0x06;
                po->Time = po->EProcess + 0x10;
                po->_Size = po->Time + 8;
                po->_fValid = TRUE;
                // print result
                if(ctxMain->cfg.fVerboseExtra) {
                    vmmprintfvv_fn("0x%016llx:\n", vaTcpE);
                    vmmprintfvv(
                        "  _Size %03X, InetAF  %03X, InetAFAF %03X, InetAddr %03X, FLink %03X\n",
                        po->_Size, po->INET_AF, po->INET_AF_AF, po->INET_Addr, po->FLink);
                    vmmprintfvv(
                        "  State %03X, SrcPort %03X, DstPort  %03X, EProcess %03X, Time  %03X\n",
                        po->State, po->PortSrc, po->PortDst, po->EProcess, po->Time);
                    Util_PrintHexAscii(pb, 0x300, 0);
                }
                Ob_DECREF(pObProcess);
                return;
            }
        }
    }
fail:
    Ob_DECREF(pObProcess);
}

/*
* Retrieve the virtual addresses of the TCP ENDPOINT structs in memory (TcpE).
* The virtual addresses will be put into the pObSet_TcpEndpoints set upon success.
* -- pSystemProcess
* -- pObSet_TcpEndpoints
* -- return
*/
_Success_(return)
BOOL VmmWinTcpIp_TcpE_GetAddressEPs(_In_ PVMM_PROCESS pSystemProcess, _Inout_ POB_VSET pObSet_TcpEndpoints)
{
    BOOL f, fResult = FALSE;
    QWORD va, va2, va3;
    DWORD i, o, oStartHT, oListPT = 0, cbRead, cbTcpHT;
    BYTE pb[0x810] = { 0 }, pbTcHT[0x400];
    PBYTE pbPartitionTable;
    POB_VSET pObTcHT = NULL, pObHTab = NULL, pObTcpE = NULL;
    PRTL_DYNAMIC_HASH_TABLE pTcpHT;
    if(!(pbPartitionTable = LocalAlloc(LMEM_ZEROINIT, 0x4000))) { goto fail; }
    if(!(pObTcHT = ObVSet_New())) { goto fail; }
    if(!(pObHTab = ObVSet_New())) { goto fail; }
    if(!(pObTcpE = ObVSet_New())) { goto fail; }
    // 1: load partition table
    if(!ctxVmm->TcpIp.fInitialized) {
        VmmWinTcpIp_GetPartitionTable64(pSystemProcess);
    }
    if(!ctxVmm->TcpIp.vaPartitionTable) { goto fail; }
    vmmprintfvv_fn("tcpip!PartitionTable located at: 0x%016llx\n", ctxVmm->TcpIp.vaPartitionTable)
    VmmReadEx(pSystemProcess, ctxVmm->TcpIp.vaPartitionTable, pbPartitionTable, 0x4000, NULL, 0);
    // 2: enumerate possible TcHT by walking tcpip.sys!PartitionTable
    oStartHT = (DWORD)(*(PQWORD)(pbPartitionTable + 0x10) - *(PQWORD)(pbPartitionTable + 0x00));
    cbTcpHT = 0x10 + oStartHT + 4 * sizeof(RTL_DYNAMIC_HASH_TABLE);
    if(cbTcpHT > sizeof(pbTcHT)) { goto fail; }
    oListPT = VMMWINTCPIP_PARTITIONTABLE_OFFSET20(pbPartitionTable, ctxVmm->TcpIp.vaPartitionTable) ? 0x20 : oListPT;
    oListPT = VMMWINTCPIP_PARTITIONTABLE_OFFSET18(pbPartitionTable, ctxVmm->TcpIp.vaPartitionTable) ? 0x18 : oListPT;
    if(oListPT) {
        for(o = 0; o < 0x1000 - oListPT - 8; o += 8) {
            f = *(PQWORD)(pbPartitionTable + o + 0x00) &&
                (*(PQWORD)(pbPartitionTable + o + 0x10) - *(PQWORD)(pbPartitionTable + o + 0x00) == oStartHT) &&
                ((ctxVmm->TcpIp.vaPartitionTable + o + oListPT) == *(PQWORD)(pbPartitionTable + o + oListPT)) &&
                ((ctxVmm->TcpIp.vaPartitionTable + o + oListPT) == *(PQWORD)(pbPartitionTable + o + oListPT + 8));
            if(!f) { continue; }
            ObVSet_Push(pObTcHT, *(PQWORD)(pbPartitionTable + o + 0x00) - 0x10);  // store address in set & adjust for prepended pool header
            o += 0x70;
        }
    }
    if(VMMWINTCPIP_PARTITIONTABLE_WIN10_1903(pbPartitionTable)) {
        for(o = 0; o < 0x4000 - 0xc0 && VMMWINTCPIP_PARTITIONTABLE_WIN10_1903(pbPartitionTable + o); o += 0xc0) {
            ObVSet_Push(pObTcHT, *(PQWORD)(pbPartitionTable + o + 0x00) - 0x10);  // store address in set & adjust for prepended pool header
        }
    }
    if(0 == ObVSet_Size(pObTcHT)) { goto fail; }
    VmmCachePrefetchPages3(pSystemProcess, pObTcHT, cbTcpHT);
    // 3: enumerate possible/interesting TCP hash tables - TcHT.
    while((va = ObVSet_Pop(pObTcHT))) {
        ZeroMemory(pbTcHT, cbTcpHT);
        VmmReadEx(pSystemProcess, va, pbTcHT, cbTcpHT, &cbRead, VMM_FLAG_FORCECACHE_READ);
        if((cbTcpHT != cbRead) || (*(PDWORD)(pbTcHT + 0x04) !=  'THcT')) { continue; }
        for(i = 0; i < 4; i++) {
            pTcpHT = (PRTL_DYNAMIC_HASH_TABLE)(pbTcHT + 0x10 + oStartHT) + i;
            if(!VMM_KADDR64_16(pTcpHT->Directory) || (pTcpHT->TableSize != 0x80) || (pTcpHT->DivisorMask != 0x7f)) { break; }
            if(!pTcpHT->NonEmptyBuckets) { continue; }
            ObVSet_Push(pObHTab, pTcpHT->Directory - 0x10);  // store address in set & account for prepended pool header
        }
    }
    if(0 == ObVSet_Size(pObHTab)) { goto fail; }
    VmmCachePrefetchPages3(pSystemProcess, pObHTab, 0x810);
    // 4: Enumerate TCP Endpoints 'TcpE' out of the potential 'HTab'
    while((va = ObVSet_Pop(pObHTab))) {
        VmmReadEx(pSystemProcess, va, pb, 0x810, &cbRead, VMM_FLAG_FORCECACHE_READ);
        if(0x810 != cbRead) { continue; }
        if((*(PDWORD)(pb + 0x04) != 'baTH') && (ctxVmm->kernel.dwVersionBuild != 10240)) {
            vmmprintfv_fn("UNEXPECTED POOL HDR: '%c%c%c%c' EXPECT: 'HTab' AT VA: 0x%016llx\n", pb[4], pb[5], pb[6], pb[7], va);
            continue;
        }
        for(o = 0x10; o < 0x800; o += 0x10) {
            va2 = *(PQWORD)(pb + o);
            if((va + o == va2) || !VMM_KADDR64_16(va2)) { continue; }
            ObVSet_Push(pObTcpE, va2 - 0x50);
            va3 = *(PQWORD)(pb + o + 8);
            if((va + o == va3) || (va2 == va3) || !VMM_KADDR64_16(va2)) { continue; }
            ObVSet_Push(pObTcpE, va3 - 0x50);
        }
    }
    if(0 == ObVSet_Size(pObTcpE)) { goto fail; }
    VmmCachePrefetchPages3(pSystemProcess, pObTcpE, 0x10);
    // 5: Verify and transfer to outgoing result set pObTcpE_Located
    while((va = ObVSet_Pop(pObTcpE))) {
        VmmReadEx(pSystemProcess, va, pb, 0x10, &cbRead, VMM_FLAG_FORCECACHE_READ);
        if(0x10 != cbRead) { continue; }
        if(*(PDWORD)(pb + 0x04) != 'EpcT') {
            vmmprintfv_fn("UNEXPECTED POOL HDR: '%c%c%c%c' EXPECT: 'TcpE' AT VA: 0x%016llx\n", pb[4], pb[5], pb[6], pb[7], va);
            continue;
        }
        ObVSet_Push(pObSet_TcpEndpoints, va + 0x10);
    }
    if(0 == ObVSet_Size(pObSet_TcpEndpoints)) { goto fail; }
    fResult = TRUE;
fail:
    Ob_DECREF(pObTcHT);
    Ob_DECREF(pObHTab);
    Ob_DECREF(pObTcpE);
    LocalFree(pbPartitionTable);
    return fResult;
}

/*
* Read the TCP ENDPOINTS in the set pSet_TcpE and fill the data into the sorted
* result array pTcpEs.
* -- pSystemProcess,
* -- pSet_TcpE = set of TcpE VAs to parse
* -- pTcpEs = buffer to receive result of sorted entries
* -- cTcpEs
* -- pcTcpEs
* -- return
*/
_Success_(return)
BOOL VmmWinTcpIp_TcpE_Enumerate(_In_ PVMM_PROCESS pSystemProcess, _In_ POB_VSET pSet_TcpE, _In_count_(cTcpEs) PVMMWIN_TCPIP_ENTRY pTcpEs, _In_ DWORD cTcpEs, _Out_ PDWORD pcTcpEs)
{
    BOOL f;
    QWORD va;
    DWORD cbRead, c = 0, i, j;
    BYTE pb[0x400] = { 0 };
    PVMMWIN_TCPIP_ENTRY pE;
    POB_VSET pObPrefetch = NULL;
    PVMM_PROCESS pObProcess = NULL;
    PVMMWIN_TCPIP_OFFSET_TcpE po = &ctxVmm->TcpIp.OTcpE;
    LPCSTR szSTATES[] = {
        "CLOSED",
        "LISTENING",
        "SYN_SENT",
        "SYN_RCVD",
        "ESTABLISHED",
        "FIN_WAIT_1",
        "FIN_WAIT_2",
        "CLOSE_WAIT",
        "CLOSING",
        "LAST_ACK",
        "TIME_WAIT"
    };
    if(cTcpEs < ObVSet_Size(pSet_TcpE)) { goto fail; }
    if(!(pObPrefetch = ObVSet_New())) { goto fail; }
    VmmCachePrefetchPages3(pSystemProcess, pSet_TcpE, po->_Size);
    // 1: retrieve general info from main struct (TcpE)
    while((va = ObVSet_Pop(pSet_TcpE))) {
        VmmReadEx(pSystemProcess, va, pb, po->_Size, &cbRead, VMM_FLAG_FORCECACHE_READ);
        if(po->_Size != cbRead) { continue; }
        pE = pTcpEs + c;
        pE->Dst.wPort = _byteswap_ushort(*(PWORD)(pb + po->PortDst));
        pE->Src.wPort = _byteswap_ushort(*(PWORD)(pb + po->PortSrc));
        pE->dwState = *(PDWORD)(pb + po->State);
        if(pE->dwState < sizeof(szSTATES) / sizeof(LPCSTR)) {
            strcpy_s(pE->szState, 12, szSTATES[pE->dwState]);
        }
        pE->vaTcpE = va;
        pE->qwTime = *(PQWORD)(pb + po->Time);
        pE->vaEPROCESS = *(PQWORD)(pb + po->EProcess);
        pE->_Reserved_vaINET_AF = *(PQWORD)(pb + po->INET_AF);
        pE->_Reserved_vaINET_Addr = *(PQWORD)(pb + po->INET_Addr);
        if(!VMM_KADDR64_8(pE->vaEPROCESS) || !VMM_KADDR64_8(pE->_Reserved_vaINET_AF) || !VMM_KADDR64_8(pE->_Reserved_vaINET_Addr)) { continue; }
        ObVSet_Push(pObPrefetch, pE->_Reserved_vaINET_AF - 0x10);
        ObVSet_Push(pObPrefetch, pE->_Reserved_vaINET_Addr);
        c++;
    }
    // 2: retrieve address family and ptr to address
    VmmCachePrefetchPages3(pSystemProcess, pObPrefetch, 0x30);
    Ob_DECREF_NULL(&pObPrefetch);
    if(!(pObPrefetch = ObVSet_New())) { goto fail; }
    for(i = 0; i < c; i++) {
        pE = pTcpEs + i;
        // 2.1 fetch INET_AF
        VmmReadEx(pSystemProcess, pE->_Reserved_vaINET_AF - 0x10, pb, 0x30, &cbRead, VMM_FLAG_FORCECACHE_READ);
        if(0x30 != cbRead) { continue; }
        if(*(PDWORD)(pb + 0x04) != 'lNnI') {
            vmmprintfv_fn("UNEXPECTED POOL HDR: '%c%c%c%c' EXPECT: 'InNl' AT VA: 0x%016llx\n", pb[4], pb[5], pb[6], pb[7], pE->_Reserved_vaINET_AF);
            continue;
        }
        pE->AF.wAF = *(PWORD)(pb + 0x10 + po->INET_AF_AF);
        if((pE->AF.wAF != AF_INET) && (pE->AF.wAF != AF_INET6)) {
            vmmprintfv_fn("UNEXPECTED INET_AF: %i EXPECT: %i or %i AT VA: 0x%016llx\n", pE->AF.wAF, AF_INET, AF_INET6, pE->_Reserved_vaINET_AF);
            continue;
        }
        pE->AF.fValid = TRUE;
        // 2.2 fetch ptrs to INET_ADDR SRC/DST and queue for prefetch
        VmmReadEx(pSystemProcess, pE->_Reserved_vaINET_Addr, pb, 0x18, &cbRead, VMM_FLAG_FORCECACHE_READ);
        if((0x18 != cbRead) || !VMM_KADDR64_8(*(PQWORD)(pb + 0x00)) || !VMM_KADDR64_8(*(PQWORD)(pb + 0x10))) { continue; }
        pE->_Reserved_vaINET_Src = *(PQWORD)(pb + 0x00);
        pE->_Reserved_vaINET_Dst = *(PQWORD)(pb + 0x10);
        ObVSet_Push(pObPrefetch, pE->_Reserved_vaINET_Src);
        ObVSet_Push(pObPrefetch, pE->_Reserved_vaINET_Dst);
    }
    // 3: retrieve src / dst addresses
    VmmCachePrefetchPages3(pSystemProcess, pObPrefetch, 0x18);
    for(i = 0; i < c; i++) {
        pE = pTcpEs + i;
        if(pE->AF.fValid) {
            if((pE->AF.wAF == AF_INET) || (pE->AF.wAF == AF_INET6)) {
                // 3.1 src address
                VmmReadEx(pSystemProcess, pE->_Reserved_vaINET_Src, pb, 0x18, &cbRead, VMM_FLAG_FORCECACHE_READ);
                f = (0x18 == cbRead) &&
                    VMM_KADDR64_8(*(PQWORD)(pb + 0x10)) &&
                    VmmRead(pSystemProcess, *(PQWORD)(pb + 0x10), pb, 0x08) &&
                    VMM_KADDR64_8(*(PQWORD)pb) &&
                    VmmRead(pSystemProcess, *(PQWORD)pb, pb, 0x20);
                if(f) {
                    memcpy(pE->Src.pbA, pb, (pE->AF.wAF == AF_INET) ? 4 : 16);
                    pE->Src.fValid = TRUE;
                }
                // 3.2 dst address
                VmmReadEx(pSystemProcess, pE->_Reserved_vaINET_Dst, pb, 0x20, &cbRead, VMM_FLAG_FORCECACHE_READ);
                if(0x20 == cbRead) {
                    memcpy(pE->Dst.pbA, pb, (pE->AF.wAF == AF_INET) ? 4 : 16);
                    pE->Dst.fValid = TRUE;
                }
            }
        }
        pE->_Reserved_fPidSearch = FALSE;
    }
    // 4: set process pids and sort list
    for(i = 0; i < c; i++) {
        pE = pTcpEs + i;
        if(pE->_Reserved_fPidSearch) { continue; }
        pE->_Reserved_fPidSearch = TRUE;
        while((pObProcess = VmmProcessGetNext(pObProcess, VMM_FLAG_PROCESS_SHOW_TERMINATED))) {
            if(pE->vaEPROCESS == pObProcess->win.EPROCESS.va) {
                for(j = i; j < c; j++) {
                    if(pTcpEs[j].vaEPROCESS == pObProcess->win.EPROCESS.va) {
                        pTcpEs[j].dwPID = pObProcess->dwPID;
                        pTcpEs[j]._Reserved_fPidSearch = TRUE;
                    }
                }
                break;
            }
        }
        Ob_DECREF_NULL(&pObProcess);
    }
    qsort(pTcpEs, c, sizeof(VMMWIN_TCPIP_ENTRY), (int(*)(const void*, const void*))VmmWinTcpIp_TcpE_CmpSort);
    *pcTcpEs = c;
    return TRUE;
fail:
    Ob_DECREF(pObPrefetch);
    return FALSE;
}

/*
* Retrieve a freshly parsed array of sorted active TCP connections.
* CALLER LocalFree: ppTcpE
* -- ppTcpE = ptr to receive function allocated buffer containing sorted active TCP connections. Caller responsible for LocalFree.
* -- pcTcpE = length of ppTcpE
* -- return
*/
_Success_(return)
BOOL VmmWinTcpIp_TcpE_Get(_Out_ PPVMMWIN_TCPIP_ENTRY ppTcpE, _Out_ PDWORD pcTcpE)
{
    DWORD cTcpEs;
    PVMMWIN_TCPIP_ENTRY pTcpEs = NULL;
    PVMM_PROCESS pObSystemProcess = NULL;
    POB_VSET pObTcpE = NULL;
    if(ctxVmm->f32) { goto fail; }
    if(!(pObTcpE = ObVSet_New())) { goto fail; }
    if(!(pObSystemProcess = VmmProcessGet(4))) { goto fail; }
    if(!VmmWinTcpIp_TcpE_GetAddressEPs(pObSystemProcess, pObTcpE)) { goto fail; }
    VmmWinTcpIp_TcpE_Fuzz(pObSystemProcess, ObVSet_Get(pObTcpE, 0));
    if(!ctxVmm->TcpIp.OTcpE._fValid) { goto fail; }
    cTcpEs = ObVSet_Size(pObTcpE);
    if(!(pTcpEs = LocalAlloc(LMEM_ZEROINIT, cTcpEs * sizeof(VMMWIN_TCPIP_ENTRY)))) { goto fail; }
    if(!VmmWinTcpIp_TcpE_Enumerate(pObSystemProcess, pObTcpE, pTcpEs, cTcpEs, &cTcpEs)) { goto fail; }
    *ppTcpE = pTcpEs;
    *pcTcpE = cTcpEs;
    Ob_DECREF(pObTcpE);
    Ob_DECREF(pObSystemProcess);
    return TRUE;
fail:
    LocalFree(pTcpEs);
    Ob_DECREF(pObTcpE);
    Ob_DECREF(pObSystemProcess);
    return FALSE;
}
