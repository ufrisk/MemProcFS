// vmmnet.c :  implementation of functionality related to the Windows networking.
//
// (c) Ulf Frisk, 2019-2021
// Author: Ulf Frisk, pcileech@frizk.net
//

#ifdef _WIN32
#include <ws2tcpip.h>
#endif /* _WIN32 */
#include "vmmnet.h"
#include "pe.h"
#include "pdb.h"
#include "infodb.h"
#include "util.h"

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

// INTERNAL TYPEDEF's BELOW:

typedef struct tdVMMNET_OFFSET_TcpE {
    BOOL _fValid;
    BOOL _fProcessedTry;
    WORD _Size;
    WORD INET_AF;
    WORD INET_AF_AF;
    WORD INET_Addr;
    WORD FLink;
    WORD State;
    WORD PortSrc;
    WORD PortDst;
    WORD EProcess;
    WORD Time;
} VMMNET_OFFSET_TcpE, *PVMMNET_OFFSET_TcpE;

typedef struct tdVMMNET_OFFSET_TcpL_UdpA {
    WORD _Size;
    WORD INET_AF;
    WORD INET_AF_AF;
    WORD SrcAddr;
    WORD SrcPort;
    WORD DstPort;
    WORD FLink;
    WORD EProcess;
    WORD Time;
} VMMNET_OFFSET_TcpL_UdpA, *PVMMNET_OFFSET_TcpL_UdpA;

typedef struct tdVMMNET_CONTEXT {
    QWORD vaModuleTcpip;
    DWORD cPartition;
    QWORD vaPartitionTable;
    VMMNET_OFFSET_TcpE oTcpE;
    VMMNET_OFFSET_TcpL_UdpA oTcpL;
    VMMNET_OFFSET_TcpL_UdpA oUdpA;
    QWORD vaTcpPortPool;
    QWORD vaUdpPortPool;
} VMMNET_CONTEXT, *PVMMNET_CONTEXT;

typedef struct tdVMMNET_ASYNC_CONTEXT {
    PVMMNET_CONTEXT ctx;
    POB_MAP pmNetEntries;
    PVMM_PROCESS pSystemProcess;
} VMMNET_ASYNC_CONTEXT, *PVMMNET_ASYNC_CONTEXT;

#define VMMNET_PARTITIONTABLE_OFFSET20(pbPT, vaPT)     (*(PQWORD)pbPT && !*(PQWORD)(pbPT + 0x30) && ((vaPT + 0x20) == *(PQWORD)(pbPT + 0x20)) && ((vaPT + 0x20) == *(PQWORD)(pbPT + 0x28)))
#define VMMNET_PARTITIONTABLE_OFFSET18(pbPT, vaPT)     (*(PQWORD)pbPT && !*(PQWORD)(pbPT + 0x28) && ((vaPT + 0x18) == *(PQWORD)(pbPT + 0x18)) && ((vaPT + 0x18) == *(PQWORD)(pbPT + 0x20)))
#define VMMNET_PARTITIONTABLE_WIN10_1903(pbPT)         (VMM_KADDR64_16(*(PQWORD)(pbPT + 0x00)) && VMM_KADDR64_16(*(PQWORD)(pbPT + 0x08)) && VMM_KADDR64_16(*(PQWORD)(pbPT + 0x10)) && (*(PQWORD)(pbPT + 0x08) - *(PQWORD)(pbPT + 0x00) < 0x200) && (*(PQWORD)(pbPT + 0x10) - *(PQWORD)(pbPT + 0x08) < 0x200))

// ----------------------------------------------------------------------------
// TCP ENDPOINT FUNCTIONALITY BELOW:
// ----------------------------------------------------------------------------

/*
* qsort compare function for sorting the TCP connection list
*/
int VmmNet_TcpE_CmpSort(PVMM_MAP_NETENTRY a, PVMM_MAP_NETENTRY b)
{
    if((a->dwPoolTag != b->dwPoolTag) && (a->dwPoolTag == 'UdpA' || b->dwPoolTag == 'UdpA')) {
        return (a->dwPoolTag == 'UdpA') ? 1 : -1;
    }
    if(a->dwPID != b->dwPID) {
        return a->dwPID - b->dwPID;
    }
    if(memcmp(a->Src.pbAddr, b->Src.pbAddr, 16)) {
        return memcmp(a->Src.pbAddr, b->Src.pbAddr, 16);
    }
    if(a->Src.port != b->Src.port) {
        return a->Src.port - b->Src.port;
    }
    if(a->AF != b->AF) {
        return a->AF - b->AF;
    }
    return memcmp(a->Dst.pbAddr, b->Dst.pbAddr, 16);
}

/*
* Fuzz offsets in TcpE if required. Upon a successful fuzz values will be stored
* in the ctxVmm global context.
* -- ctx
* -- pSystemProcess
* -- vaTcpE_UdpA - virtual address of a TCP ENDPOINT entry (TcpE).
*/
VOID VmmNet_TcpE_Fuzz(_In_ PVMMNET_CONTEXT ctx, _In_ PVMM_PROCESS pSystemProcess, _In_ QWORD vaTcpE)
{
    BOOL f;
    QWORD o, va;
    DWORD dwPoolTagInNl;
    BYTE pb[0x300];
    PVMM_PROCESS pObProcess = NULL;
    PVMMNET_OFFSET_TcpE po = &ctx->oTcpE;
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
                po->INET_AF_AF = (ctxVmm->kernel.dwVersionBuild < 9200) ? 0x14 : 0x18;  // VISTA-WIN7 or WIN8+
                // check for state offset
                po->State = (*(PDWORD)(pb + 0x6c) <= 13) ? 0x6c : 0x68;
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
                        "  _Size %03X, InetAF  %03X, InetAFAF %03X, InetAddr %03X, FLinkAll %03X\n",
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
* -- ctx
* -- pSystemProcess
* -- pObSet_TcpEndpoints
* -- return
*/
_Success_(return)
BOOL VmmNet_TcpE_GetAddressEPs(_In_ PVMMNET_CONTEXT ctx, _In_ PVMM_PROCESS pSystemProcess, _Inout_ POB_SET psvaOb_TcpEndpoints)
{
    BOOL f, fResult = FALSE;
    QWORD va, va2, va3;
    DWORD i, o, oStartHT, oListPT = 0, cbRead, cbTcpHT, dwPoolTag;
    BYTE pb[0x810] = { 0 };
    PBYTE pbPartitionTable = NULL, pbTcHT = NULL;
    POB_SET pObTcHT = NULL, pObHTab = NULL, pObTcpE = NULL;
    PRTL_DYNAMIC_HASH_TABLE pTcpHT;
    if(!(pObTcHT = ObSet_New())) { goto fail; }
    if(!(pObHTab = ObSet_New())) { goto fail; }
    if(!(pObTcpE = ObSet_New())) { goto fail; }
    if(!(pbPartitionTable = LocalAlloc(LMEM_ZEROINIT, 0x4000))) { goto fail; }
    // 1: enumerate possible TcHT by walking tcpip.sys!PartitionTable
    VmmReadEx(pSystemProcess, ctx->vaPartitionTable, pbPartitionTable, 0x4000, NULL, 0);
    oStartHT = (DWORD)(*(PQWORD)(pbPartitionTable + 0x10) - *(PQWORD)(pbPartitionTable + 0x00));
    cbTcpHT = 0x10 + oStartHT + ctx->cPartition * sizeof(RTL_DYNAMIC_HASH_TABLE);
    if(cbTcpHT > 0x10000) { goto fail; }
    if(!(pbTcHT = LocalAlloc(LMEM_ZEROINIT, cbTcpHT))) { goto fail; }
    oListPT = VMMNET_PARTITIONTABLE_OFFSET20(pbPartitionTable, ctx->vaPartitionTable) ? 0x20 : oListPT;
    oListPT = VMMNET_PARTITIONTABLE_OFFSET18(pbPartitionTable, ctx->vaPartitionTable) ? 0x18 : oListPT;
    if(oListPT) {
        for(o = 0; o < 0x1000 - oListPT - 8; o += 8) {
            f = *(PQWORD)(pbPartitionTable + o + 0x00) &&
                (*(PQWORD)(pbPartitionTable + o + 0x10) - *(PQWORD)(pbPartitionTable + o + 0x00) == oStartHT) &&
                ((ctx->vaPartitionTable + o + oListPT) == *(PQWORD)(pbPartitionTable + o + oListPT)) &&
                ((ctx->vaPartitionTable + o + oListPT) == *(PQWORD)(pbPartitionTable + o + oListPT + 8));
            if(!f) { continue; }
            ObSet_Push(pObTcHT, *(PQWORD)(pbPartitionTable + o + 0x00) - 0x10);  // store address in set & adjust for prepended pool header
            o += 0x70;
        }
    }
    if(VMMNET_PARTITIONTABLE_WIN10_1903(pbPartitionTable)) {
        for(o = 0; o < 0x4000 - 0xc0 && VMMNET_PARTITIONTABLE_WIN10_1903(pbPartitionTable + o); o += 0xc0) {
            ObSet_Push(pObTcHT, *(PQWORD)(pbPartitionTable + o + 0x00) - 0x10);  // store address in set & adjust for prepended pool header
        }
    }
    if(0 == ObSet_Size(pObTcHT)) { goto fail; }
    VmmCachePrefetchPages3(pSystemProcess, pObTcHT, cbTcpHT, 0);
    // 2: enumerate possible/interesting TCP hash tables - TcHT.
    while((va = ObSet_Pop(pObTcHT))) {
        ZeroMemory(pbTcHT, cbTcpHT);
        VmmReadEx(pSystemProcess, va, pbTcHT, cbTcpHT, &cbRead, VMM_FLAG_FORCECACHE_READ);
        if((cbTcpHT != cbRead) || (*(PDWORD)(pbTcHT + 0x04) !=  'THcT')) { continue; }
        for(i = 0; i < ctx->cPartition; i++) {
            pTcpHT = (PRTL_DYNAMIC_HASH_TABLE)(pbTcHT + 0x10 + oStartHT) + i;
            if(!VMM_KADDR64_16(pTcpHT->Directory) || (pTcpHT->TableSize != 0x80) || (pTcpHT->DivisorMask != 0x7f)) { break; }
            if(!pTcpHT->NonEmptyBuckets) { continue; }
            ObSet_Push(pObHTab, pTcpHT->Directory - 0x10);  // store address in set & account for prepended pool header
        }
    }
    if(0 == ObSet_Size(pObHTab)) { goto fail; }
    VmmCachePrefetchPages3(pSystemProcess, pObHTab, 0x810, 0);
    // 3: Enumerate TCP Endpoints 'TcpE' out of the potential 'HTab'
    while((va = ObSet_Pop(pObHTab))) {
        VmmReadEx(pSystemProcess, va, pb, 0x810, &cbRead, VMM_FLAG_FORCECACHE_READ);
        if(0x810 != cbRead) { continue; }
        if((*(PDWORD)(pb + 0x04) != 'baTH') && (ctxVmm->kernel.dwVersionBuild != 10240)) {
            vmmprintfv_fn("UNEXPECTED POOL HDR: '%c%c%c%c' EXPECT: 'HTab' AT VA: 0x%016llx\n", pb[4], pb[5], pb[6], pb[7], va);
            continue;
        }
        for(o = 0x10; o < 0x800; o += 0x10) {
            va2 = *(PQWORD)(pb + o);
            if((va + o == va2) || !VMM_KADDR64_16(va2)) { continue; }
            ObSet_Push(pObTcpE, va2 - 0x50);
            va3 = *(PQWORD)(pb + o + 8);
            if((va + o == va3) || (va2 == va3) || !VMM_KADDR64_16(va2)) { continue; }
            ObSet_Push(pObTcpE, va3 - 0x50);
        }
    }
    if(0 == ObSet_Size(pObTcpE)) { goto fail; }
    VmmCachePrefetchPages3(pSystemProcess, pObTcpE, 0x10, 0);
    // 4: Verify and transfer to outgoing result set pObTcpE_Located
    while((va = ObSet_Pop(pObTcpE))) {
        VmmReadEx(pSystemProcess, va, pb, 0x10, &cbRead, VMM_FLAG_FORCECACHE_READ);
        if(0x10 != cbRead) { continue; }
        dwPoolTag = *(PDWORD)(pb + 0x04);
        if(!VMM_POOLTAG(dwPoolTag, 'TcpE') && !VMM_POOLTAG(dwPoolTag, 'TTcb')) {
            vmmprintfv_fn("UNEXPECTED POOL HDR: '%c%c%c%c' EXPECT: 'TcpE/TTcb' AT VA: 0x%016llx\n", pb[4], pb[5], pb[6], pb[7], va);
            continue;
        }
        ObSet_Push(psvaOb_TcpEndpoints, va + 0x10);
    }
    if(0 == ObSet_Size(psvaOb_TcpEndpoints)) { goto fail; }
    fResult = TRUE;
fail:
    Ob_DECREF(pObTcHT);
    Ob_DECREF(pObHTab);
    Ob_DECREF(pObTcpE);
    LocalFree(pbPartitionTable);
    LocalFree(pbTcHT);
    return fResult;
}

_Success_(return)
BOOL VmmNet_TcpE_Enumerate(_In_ PVMMNET_CONTEXT ctx, _In_ PVMM_PROCESS pSystemProcess, _In_ POB_SET pSet_TcpE, _Inout_ POB_MAP pmTcpE)
{
    BOOL f;
    QWORD va, vaEPROCESS;
    DWORD cbRead, c = 0, i;
    BYTE pb[0x400] = { 0 };
    PVMM_MAP_NETENTRY pe;
    POB_SET pObPrefetch = NULL;
    PVMM_PROCESS pObProcess = NULL;
    PVMMNET_OFFSET_TcpE po = &ctx->oTcpE;
    QWORD vaINET_AF, vaINET_Addr, vaINET_Src, vaINET_Dst;
    if(!(pObPrefetch = ObSet_New())) { goto fail; }
    VmmCachePrefetchPages3(pSystemProcess, pSet_TcpE, po->_Size, 0);
    // 1: retrieve general info from main struct (TcpE)
    while((va = ObSet_Pop(pSet_TcpE))) {
        VmmReadEx(pSystemProcess, va, pb, po->_Size, &cbRead, VMM_FLAG_FORCECACHE_READ);
        if(po->_Size != cbRead) { continue; }
        if(!VMM_KADDR64_8(*(PQWORD)(pb + po->EProcess)) || !VMM_KADDR64_8(*(PQWORD)(pb + po->INET_AF)) || !VMM_KADDR64_8(*(PQWORD)(pb + po->INET_Addr))) { continue; }
        if(!(pe = LocalAlloc(LMEM_ZEROINIT, sizeof(VMM_MAP_NETENTRY)))) { continue; }
        pe->dwPoolTag = 'TcpE';
        pe->Dst.port = _byteswap_ushort(*(PWORD)(pb + po->PortDst));
        pe->Src.port = _byteswap_ushort(*(PWORD)(pb + po->PortSrc));
        pe->dwState = *(PWORD)(pb + po->State);
        pe->vaObj = va;
        pe->ftTime = *(PQWORD)(pb + po->Time);
        pe->_Reserved1 = *(PQWORD)(pb + po->INET_AF);       // vaINET_AF
        pe->_Reserved2 = *(PQWORD)(pb + po->INET_Addr);     // vaINET_Addr
        vaEPROCESS = *(PQWORD)(pb + po->EProcess);
        while((pObProcess = VmmProcessGetNext(pObProcess, VMM_FLAG_PROCESS_SHOW_TERMINATED))) {
            if(vaEPROCESS == pObProcess->win.EPROCESS.va) {
                pe->dwPID = pObProcess->dwPID;
                Ob_DECREF_NULL(&pObProcess);
                break;
            }
        }
        ObSet_Push(pObPrefetch, pe->_Reserved1 - 0x10);
        ObSet_Push(pObPrefetch, pe->_Reserved2);
        ObMap_Push(pmTcpE, va, pe);
    }
    // 2: retrieve address family and ptr to address
    VmmCachePrefetchPages3(pSystemProcess, pObPrefetch, 0x30, 0);
    Ob_DECREF_NULL(&pObPrefetch);
    if(!(pObPrefetch = ObSet_New())) { goto fail; }
    for(i = 0, c = ObMap_Size(pmTcpE); i < c; i++) {
        pe = ObMap_GetByIndex(pmTcpE, i);
        vaINET_AF = pe->_Reserved1;
        vaINET_Addr = pe->_Reserved2;
        pe->_Reserved1 = 0;
        pe->_Reserved2 = 0;
        // 2.1 fetch INET_AF
        VmmReadEx(pSystemProcess, vaINET_AF - 0x10, pb, 0x30, &cbRead, VMM_FLAG_FORCECACHE_READ);
        if(0x30 != cbRead) { continue; }
        if(*(PDWORD)(pb + 0x04) != 'lNnI') {
            vmmprintfv_fn("UNEXPECTED POOL HDR: '%c%c%c%c' EXPECT: 'InNl' AT VA: 0x%016llx\n", pb[4], pb[5], pb[6], pb[7], vaINET_AF);
            continue;
        }
        pe->AF = *(PWORD)(pb + 0x10 + po->INET_AF_AF);
        if((pe->AF != AF_INET) && (pe->AF != AF_INET6)) {
            vmmprintfv_fn("UNEXPECTED INET_AF: %i EXPECT: %i or %i AT VA: 0x%016llx\n", pe->AF, AF_INET, AF_INET6, vaINET_AF);
            continue;
        }
        // 2.2 fetch ptrs to INET_ADDR SRC/DST and queue for prefetch
        VmmReadEx(pSystemProcess, vaINET_Addr, pb, 0x18, &cbRead, VMM_FLAG_FORCECACHE_READ);
        if((0x18 != cbRead) || !VMM_KADDR64_8(*(PQWORD)(pb + 0x00)) || !VMM_KADDR64_8(*(PQWORD)(pb + 0x10))) { continue; }
        pe->_Reserved1 = *(PQWORD)(pb + 0x00);  // vaINET_Src
        pe->_Reserved2 = *(PQWORD)(pb + 0x10);  // vaINET_Dst
        ObSet_Push(pObPrefetch, pe->_Reserved1);
        ObSet_Push(pObPrefetch, pe->_Reserved2);
    }
    // 3: retrieve src / dst addresses
    VmmCachePrefetchPages3(pSystemProcess, pObPrefetch, 0x18, 0);
    Ob_DECREF_NULL(&pObPrefetch);
    for(i = 0, c = ObMap_Size(pmTcpE); i < c; i++) {
        pe = ObMap_GetByIndex(pmTcpE, i);
        vaINET_Src = pe->_Reserved1;
        vaINET_Dst = pe->_Reserved2;
        pe->_Reserved1 = 0;
        pe->_Reserved2 = 0;
        if((pe->AF == AF_INET) || (pe->AF == AF_INET6)) {
            // 3.1 src address
            VmmReadEx(pSystemProcess, vaINET_Src, pb, 0x18, &cbRead, VMM_FLAG_FORCECACHE_READ);
            f = (0x18 == cbRead) &&
                VMM_KADDR64_8(*(PQWORD)(pb + 0x10)) &&
                VmmRead(pSystemProcess, *(PQWORD)(pb + 0x10), pb, 0x08) &&
                VMM_KADDR64_8(*(PQWORD)pb) &&
                VmmRead(pSystemProcess, *(PQWORD)pb, pb, 0x20);
            if(f) {
                pe->Src.fValid = TRUE;
                memcpy(pe->Src.pbAddr, pb, (pe->AF == AF_INET) ? 4 : 16);
            }
            // 3.2 dst address
            VmmReadEx(pSystemProcess, vaINET_Dst, pb, 0x20, &cbRead, VMM_FLAG_FORCECACHE_READ);
            if(0x20 == cbRead) {
                pe->Dst.fValid = TRUE;
                memcpy(pe->Dst.pbAddr, pb, (pe->AF == AF_INET) ? 4 : 16);
            }
        }
    }
    return TRUE;
fail:
    Ob_DECREF(pObPrefetch);
    return FALSE;
}

/*
* Retrieve active TCP connections.
* NB! Function may be started asynchronously.
*/
DWORD VmmNet_TcpE_DoWork(PVOID lpThreadParameter)
{
    PVMMNET_ASYNC_CONTEXT actx = (PVMMNET_ASYNC_CONTEXT)lpThreadParameter;
    PVMMNET_CONTEXT ctx = actx->ctx;
    PVMM_PROCESS pSystemProcess = actx->pSystemProcess;
    POB_MAP pmNetEntries = actx->pmNetEntries;
    POB_SET pObTcpE = NULL;
    if(!(pObTcpE = ObSet_New())) { goto fail; }
    if(!VmmNet_TcpE_GetAddressEPs(ctx, pSystemProcess, pObTcpE)) { goto fail; }
    VmmNet_TcpE_Fuzz(ctx, pSystemProcess, ObSet_Get(pObTcpE, 0));
    if(!ctx->oTcpE._fValid) { goto fail; }
    if(!VmmNet_TcpE_Enumerate(ctx, pSystemProcess, pObTcpE, pmNetEntries)) { goto fail; }
fail:
    Ob_DECREF(pObTcpE);
    return 0;
}



// ----------------------------------------------------------------------------
// UDP ENDPOINT AND TCP LISTENER FUNCTIONALITY (VIA PORT POOL InPP) BELOW:
// ----------------------------------------------------------------------------

#define VMMNET_EP_OFFSET                0xC0
#define VMMNET_EP_SIZE                  0x380

/*
* Filter for TcpL / UdpA
*/
VOID VmmNet_InPP_FilterTcpLUdpA(_In_ QWORD k, _In_ PVOID v, _Inout_opt_ PVOID ctx)
{
    POB_MAP pm = ctx;
    if((((PVMM_MAP_NETENTRY)v)->dwPoolTag == 'TcpL') || (((PVMM_MAP_NETENTRY)v)->dwPoolTag == 'UdpA')) {
        ObMap_Push(pm, k, v);
    }
}

/*
* Perform post processing of already enumerated UdpA / TcpL entries in map
* pmNetEntriesPre. Upon completion valid entries will be transferred to map
* pmNetEntries.
* -- ctx
* -- pSystemProcess
* -- pmNetEntriesPre = map of partial not-yet completed entries.
* -- pmNetEntries = result map of completed net entries.
*/
VOID VmmNet_InPP_PostTcpLUdpA(_In_ PVMMNET_CONTEXT ctx, _In_ PVMM_PROCESS pSystemProcess, _Inout_ POB_MAP pmNetEntriesPre, _Inout_ POB_MAP pmNetEntries)
{
    DWORD o, cbRead;
    BYTE pb[0x30] = { 0 };
    POB_SET psObPrefetch = NULL;
    POB_MAP pmOb = NULL;
    QWORD vaINET_AF, vaLocal_Addr;
    PVMM_MAP_NETENTRY pe = NULL;
    if(!(pmOb = ObMap_New(0))) { goto fail; }
    if(!(psObPrefetch = ObSet_New())) { goto fail; }
    if(!ObMap_Filter(pmNetEntriesPre, pmOb, VmmNet_InPP_FilterTcpLUdpA)) { goto fail; }
    // 1: prefetch
    while((pe = ObMap_GetNext(pmOb, pe))) {
        if(pe->_Reserved1) { ObSet_Push(psObPrefetch, pe->_Reserved1 - 0x10); }
        if(pe->_Reserved2) { ObSet_Push(psObPrefetch, pe->_Reserved2); }
    }
    if(!ObSet_Size(psObPrefetch)) { goto fail; }
    // 2: retrieve address family and ptr to address
    VmmCachePrefetchPages3(pSystemProcess, psObPrefetch, 0x30, 0);
    ObSet_Clear(psObPrefetch);
    while((pe = ObMap_GetNext(pmOb, pe))) {
        vaINET_AF = pe->_Reserved1;
        vaLocal_Addr = pe->_Reserved2;
        pe->_Reserved1 = 0;
        pe->_Reserved2 = 0;
        // 2.1 fetch INET_AF
        VmmReadEx(pSystemProcess, vaINET_AF - 0x10, pb, 0x30, &cbRead, VMM_FLAG_FORCECACHE_READ);
        if(0x30 != cbRead) { continue; }
        if(*(PDWORD)(pb + 0x04) != 'lNnI') {
            vmmprintfv_fn("UNEXPECTED POOL HDR: '%c%c%c%c' EXPECT: 'InNl' AT VA: 0x%016llx\n", pb[4], pb[5], pb[6], pb[7], vaINET_AF);
            continue;
        }
        pe->AF = *(PWORD)(pb + 0x10 + ctx->oTcpL.INET_AF_AF);
        if((pe->AF != AF_INET) && (pe->AF != AF_INET6)) {
            vmmprintfv_fn("UNEXPECTED INET_AF: %i EXPECT: %i or %i AT VA: 0x%016llx\n", pe->AF, AF_INET, AF_INET6, vaINET_AF);
            continue;
        }
        // 2.2 fetch ptrs to INET_ADDR SRC and queue for prefetch
        if(vaLocal_Addr) {
            o = ((pe->dwPoolTag == 'UdpA') && ctxVmm->kernel.dwVersionBuild >= 10240) ? 0x18 : 0x10;        // UDP-Win10 special offset
            VmmReadEx(pSystemProcess, vaLocal_Addr, pb, 0x20, &cbRead, VMM_FLAG_FORCECACHE_READ);
            if((0x20 != cbRead) || !VMM_KADDR64_8(*(PQWORD)(pb + o))) { continue; }
            pe->_Reserved2 = *(PQWORD)(pb + o);  // vaSrc
            ObSet_Push(psObPrefetch, pe->_Reserved2);
        } else {
            pe->Src.fValid = TRUE;      // address 0.0.0.0
        }
    }
    // 3: retrieve addr ptr
    VmmCachePrefetchPages3(pSystemProcess, psObPrefetch, 8, 0);
    ObSet_Clear(psObPrefetch);
    while((pe = ObMap_GetNext(pmOb, pe))) {
        if(pe->_Reserved2) {
            vaLocal_Addr = pe->_Reserved2;
            pe->_Reserved2 = 0;
            VmmReadEx(pSystemProcess, vaLocal_Addr, pb, 8, &cbRead, VMM_FLAG_FORCECACHE_READ);
            if((8 != cbRead) || !VMM_KADDR64_8(*(PQWORD)(pb))) { continue; }
            pe->_Reserved2 = *(PQWORD)(pb);  // vaSrc
            ObSet_Push(psObPrefetch, pe->_Reserved2);
        }
    }
    // 4: retrieve addr
    VmmCachePrefetchPages3(pSystemProcess, psObPrefetch, 0x20, 0);
    while((pe = ObMap_GetNext(pmOb, pe))) {
        if(pe->_Reserved2) {
            o = ((pe->dwPoolTag == 'UdpA') && ctxVmm->kernel.dwVersionBuild >= 10240) ? 0x18 : 0;        // UDP-Win10 special offset
            if(VmmRead2(pSystemProcess, pe->_Reserved2 + o, pb, 16, VMM_FLAG_FORCECACHE_READ)) {
                pe->Src.fValid = TRUE;
                memcpy(pe->Src.pbAddr, pb, (pe->AF == AF_INET) ? 4 : 16);
            }
            pe->_Reserved2 = 0;
        }
        ObMap_Remove(pmNetEntriesPre, pe);
        ObMap_Push(pmNetEntries, pe->vaObj, pe);
    }
fail:
    Ob_DECREF(pmOb);
    Ob_DECREF(psObPrefetch);
}

/*
* Enumerate PortPool TcpE entries. Enumeration is currently limited and will at
* this moment only look at forward linked entries.
* TODO: IMPLEMENT InPP-TcpE SUPPORT:
*/
PVMM_MAP_NETENTRY VmmNet_InPP_TcpE(_In_ PVMMNET_CONTEXT ctx, _In_ PVMM_PROCESS pSystemProcess, _In_ QWORD vaTcpE, _In_reads_(cb) PBYTE pb, _In_ DWORD cb, _Inout_ POB_SET psEP_Next)
{
    QWORD vaNext = *(PQWORD)(pb + 0x70);
    if(VMM_KADDR64(vaNext)) {
        ObSet_Push(psEP_Next, (vaNext & ~7) - VMMNET_EP_OFFSET);
    }
    return NULL;
}

/*
* Enumerate PortPool UdpA / TcpL entries.
*/
PVMM_MAP_NETENTRY VmmNet_InPP_TcpL_UdpA(_In_ PVMMNET_CONTEXT ctx, _In_ PVMM_PROCESS pSystemProcess, _In_ DWORD dwPoolTag, PVMMNET_OFFSET_TcpL_UdpA po, _In_ QWORD vaTcpE_UdpA, _In_reads_(cb) PBYTE pb, _In_ DWORD cb, _Inout_ POB_SET psEP_Next)
{
    DWORD c = 0;
    QWORD ftTime, vaNext, vaEPROCESS;
    PVMM_MAP_NETENTRY pe;
    PVMM_PROCESS pObProcess = NULL;
    vaNext = *(PQWORD)(pb + po->FLink);
    if(VMM_KADDR64(vaNext)) {
        ObSet_Push(psEP_Next, (vaNext & ~7) - VMMNET_EP_OFFSET);
    }
    if(!VMM_KADDR64_8(*(PQWORD)(pb + po->INET_AF))) { return NULL; }
    if(!(pe = LocalAlloc(LMEM_ZEROINIT, sizeof(VMM_MAP_NETENTRY)))) { return NULL; }
    pe->dwPoolTag = dwPoolTag;
    pe->dwState = (dwPoolTag == 'TcpL') ? 1 : 13;
    pe->Src.port = _byteswap_ushort(*(PWORD)(pb + po->SrcPort));
    if(po->DstPort) {
        pe->Dst.port = _byteswap_ushort(*(PWORD)(pb + po->DstPort));
    }
    pe->vaObj = vaTcpE_UdpA;
    ftTime = *(PQWORD)(pb + po->Time);
    if(1 == (ftTime >> 56)) {
        pe->ftTime = ftTime;
    }
    pe->_Reserved1 = *(PQWORD)(pb + po->INET_AF);       // vaINET_AF
    if(VMM_KADDR64_8(*(PQWORD)(pb + po->SrcAddr))) {
        pe->_Reserved2 = *(PQWORD)(pb + po->SrcAddr); // vaLocalAddr
    }
    vaEPROCESS = *(PQWORD)(pb + po->EProcess);
    if(VMM_KADDR64_16(vaEPROCESS)) {
        while((pObProcess = VmmProcessGetNext(pObProcess, VMM_FLAG_PROCESS_SHOW_TERMINATED))) {
            if(vaEPROCESS == pObProcess->win.EPROCESS.va) {
                pe->dwPID = pObProcess->dwPID;
                Ob_DECREF_NULL(&pObProcess);
                break;
            }
        }
    }
    return pe;
}

/*
* Dispatch a PortPool entry to its enumeration function.
*/
VOID VmmNet_InPP_Dispatch(_In_ PVMMNET_CONTEXT ctx, _In_ PVMM_PROCESS pSystemProcess, _In_ DWORD tag, _In_ QWORD va, _In_reads_(cb) PBYTE pb, _In_ DWORD cb, _In_ DWORD oFLink, _Inout_ POB_SET psEP_Next, _Inout_ POB_MAP pmNetEntriesPre)
{
    PVMM_MAP_NETENTRY pe;
    PVMMNET_OFFSET_TcpL_UdpA po = &ctx->oTcpL;
    if(ObMap_ExistsKey(pmNetEntriesPre, va)) { return; }
    if(tag == 'TcpE') {
        // TODO: IMPLEMENT SUPPORT FOR InPP-TcpE
        VmmNet_InPP_TcpE(ctx, pSystemProcess, va, pb, cb, psEP_Next);
    }
    if(tag == 'TcpL') {
        if((pe = VmmNet_InPP_TcpL_UdpA(ctx, pSystemProcess, 'TcpL', &ctx->oTcpL, va, pb, cb, psEP_Next))) {
            ObMap_Push(pmNetEntriesPre, va, pe);
        }
    }
    if(tag == 'UdpA') {
        if((pe = VmmNet_InPP_TcpL_UdpA(ctx, pSystemProcess, 'UdpA', &ctx->oUdpA, va, pb, cb, psEP_Next))) {
            ObMap_Push(pmNetEntriesPre, va, pe);
        }
    }
}

/*
* Enumerate PortPool entries and put valid ones into the result map.
* NB! Function may be started asynchronously.
*/
DWORD VmmNet_InPP_DoWork(PVOID lpThreadParameter)
{
    PVMMNET_ASYNC_CONTEXT actx = (PVMMNET_ASYNC_CONTEXT)lpThreadParameter;
    PVMMNET_CONTEXT ctx = actx->ctx;
    PVMM_PROCESS pSystemProcess = actx->pSystemProcess;
    POB_MAP pmNetEntries = actx->pmNetEntries;
    DWORD cbInPPe, oInPPe, oInPA = 0, o, oFLink, tag;
    QWORD i, j, va;
    BYTE pb[0x2000], pb2[0x20];
    POB_SET psObPA = NULL, psObPreEP = NULL, psObEP = NULL, psObEP_Next = NULL, psObEP_SWAP;
    POB_MAP pmObNetEntriesPre = NULL;
    if(!(psObPA = ObSet_New())) { goto fail; }
    if(!(psObPreEP = ObSet_New())) { goto fail; }
    if(!(psObEP = ObSet_New())) { goto fail; }
    if(!(psObEP_Next = ObSet_New())) { goto fail; }
    if(!(pmObNetEntriesPre = ObMap_New(OB_MAP_FLAGS_OBJECT_LOCALFREE))) { goto fail; }
    // set offsets
    if(ctxVmm->kernel.dwVersionBuild <= 9200) {
        oInPPe = 0x08;
        cbInPPe = 0x10;
    } else if(ctxVmm->kernel.dwVersionBuild <= 18363) {
        oInPPe = 0x08;
        cbInPPe = 0x18;
    } else {
        oInPPe = 0x10;
        cbInPPe = 0x20;
    }
    // fetch InPA
    VmmCachePrefetchPages2(pSystemProcess, 2, ctx->vaTcpPortPool, ctx->vaUdpPortPool);
    for(i = 0; i < 2; i++) {
        if(!VmmRead2(pSystemProcess, i ? ctx->vaTcpPortPool : ctx->vaUdpPortPool, pb, 0x1000, VMM_FLAG_FORCECACHE_READ)) { continue; }
        // offet for ptrs into InPA starts at +0a0 + extra, each InPA is responsible for 256 ports.
        if(!oInPA) {
            for(o = 0x0a0; o < 0x100; o += 8) {
                va = *(PQWORD)(pb + o);
                if(VMM_KADDR64_16(va) && !VMM_KADDR64_PAGE(va) && VmmRead(pSystemProcess, va - 0x10, pb2, 0x20) && VMM_POOLTAG_PREPENDED(pb2, 0x10, 'InPA')) {
                    oInPA = o;
                    break;
                }
            }
            if(!oInPA) { goto fail; }
        }
        for(j = 0; j < 256; j++) {
            va = *(PQWORD)(pb + oInPA + j * 8);
            if(VMM_KADDR64_16(va)) {
                ObSet_Push(psObPA, va - 0x10);
            }
        }
    }
    if(!ObSet_Size(psObPA)) { goto fail; }
    // fetch InPA tables
    VmmCachePrefetchPages3(pSystemProcess, psObPA, 0x40, 0);
    while((va = ObSet_Pop(psObPA))) {
        if(VmmRead2(pSystemProcess, va, pb, 0x40, VMM_FLAG_FORCECACHE_READ) && VMM_POOLTAG_PREPENDED(pb, 0x10, 'InPA')) {
            va = *(PQWORD)(pb + 0x28);
            if(!VMM_KADDR64_PAGE(va)) {
                va = *(PQWORD)(pb + 0x30);
            }
            if(VMM_KADDR64_PAGE(va)) {
                ObSet_Push(psObPreEP, va);
            }
        }
    }
    if(!ObSet_Size(psObPreEP)) { goto fail; }
    // fetch initial addresses for endpoints / listeners.
    VmmCachePrefetchPages(pSystemProcess, psObPreEP, 0);
    while((va = ObSet_Pop(psObPreEP))) {
        VmmRead2(pSystemProcess, va, pb, 256 * cbInPPe, VMM_FLAG_FORCECACHE_READ | VMM_FLAG_ZEROPAD_ON_FAIL);
        for(i = 0; i < 256; i++) {    // TODO - 0-255
            va = *(PQWORD)(pb + i * cbInPPe + oInPPe) & ~7;
            if(VMM_KADDR64_8(va)) {
                ObSet_Push(psObEP, va - VMMNET_EP_OFFSET);
            }
        }
    }
    // fetch and process endpoints / listeners
    while(ObSet_Size(psObEP) || ObSet_Size(psObEP_Next)) {
        VmmCachePrefetchPages3(pSystemProcess, psObEP, VMMNET_EP_SIZE, 0);
        while((va = ObSet_Pop(psObEP))) {
            oFLink = VMMNET_EP_OFFSET;
            if(va & 8) {
                oFLink -= 8;
                va += 8;
            }
            VmmRead2(pSystemProcess, va, pb, VMMNET_EP_SIZE, VMM_FLAG_FORCECACHE_READ | VMM_FLAG_ZEROPAD_ON_FAIL);
            for(o = 0x10; o < 0x80; o += 0x10) {
                tag = 0;
                if(VMM_POOLTAG_PREPENDED(pb, o, 'TcpL')) { tag = 'TcpL'; }
                if(VMM_POOLTAG_PREPENDED(pb, o, 'TcpE')) { tag = 'TcpE'; }
                if(VMM_POOLTAG_PREPENDED(pb, o, 'UdpA')) { tag = 'UdpA'; }
                if(tag) {
                    VmmNet_InPP_Dispatch(ctx, pSystemProcess, tag, va + o, pb + o, VMMNET_EP_SIZE - 8 - o, oFLink - o, psObEP_Next, pmObNetEntriesPre);
                    break;
                }
            }
        }
        psObEP_SWAP = psObEP;
        psObEP = psObEP_Next;
        psObEP_Next = psObEP_SWAP;
    }
    // post processing of entries
    // TODO: add post processing of InPP-TcpE
    VmmNet_InPP_PostTcpLUdpA(ctx, pSystemProcess, pmObNetEntriesPre, pmNetEntries);
fail:
    Ob_DECREF(psObEP_Next);
    Ob_DECREF(psObEP);
    Ob_DECREF(psObPreEP);
    Ob_DECREF(psObPA);
    Ob_DECREF(pmObNetEntriesPre);
    return 0;
}



// ----------------------------------------------------------------------------
// INITIALIZATION / MAP CREATE FUNCTIONALITY BELOW:
// ----------------------------------------------------------------------------

VOID VmmNet_CallbackCleanup_ObMapNet(PVMMOB_MAP_NET pOb)
{
    LocalFree(pOb->pbMultiText);
}

/*
* Set static offsets for the 'TcpL' / 'UdpA' structs depending on OS version.
*/
VOID VmmNet_Initialize_Context_Fuzz_TcpL_UdpA(_In_ PVMMNET_CONTEXT ctx)
{
    PVMMNET_OFFSET_TcpL_UdpA po;
    DWORD dwBuild = ctxVmm->kernel.dwVersionBuild;
    // TcpL
    po = &ctx->oTcpL;
    if(dwBuild >= 10240) {
        // WIN10+
        po->INET_AF = 0x28;
        po->EProcess = 0x30;
        po->Time = 0x40;
        po->SrcAddr = 0x60;
        po->SrcPort = 0x72;
        po->FLink = 0x78;
    } else {
        // VISTA - WIN8.1
        po->INET_AF = 0x60;
        po->EProcess = 0x28;
        po->SrcAddr = 0x58;
        po->SrcPort = 0x6a;
        po->FLink = 0x70;
    }
    po->INET_AF_AF = (dwBuild < 9200) ? 0x14 : 0x18;  // VISTA-WIN7 or WIN8+
    po->_Size = po->FLink + 8;
    // UdpA
    po = &ctx->oUdpA;
    if(dwBuild >= 19041) {          // WIN10 / WIN11 / SERVER2022
        po->SrcAddr = 0xa8;
        po->SrcPort = 0xa0;
        po->DstPort = 0x110;
        po->FLink = 0x70;   // ??
    } else if(dwBuild >= 10240) {   // WIN10
        po->SrcAddr = 0x80;
        po->SrcPort = 0x78;
        po->FLink = 0x70;
    } else {                        // VISTA - WIN8.1
        po->SrcAddr = 0x60;
        po->SrcPort = 0x80;
        po->FLink = 0x88;
    }
    po->INET_AF = 0x20;
    po->EProcess = 0x28;
    po->Time = 0x58;
    po->INET_AF_AF = (dwBuild < 9200) ? 0x14 : 0x18;  // VISTA-WIN7 or WIN8+
    po->_Size = max(max(po->SrcAddr, po->SrcPort), max(po->DstPort, po->FLink)) + 8;
}

/*
* Helper function for VmmNet_Initialize_Context in order to locate the TCP/UDP
* port pool structures in memory on more recent Windows 10 systems.
* The port pool may be located by traversing pool allocations such as:
* tcpip!TcpCompartmentSet [InCS] -> [InCo] -> [TcCo/UdCo] -> [InPP large].
* -- pSystemProcess
* -- vaInCS
* -- dwTagTcpUdp
* -- return = address of TcpPortPool / UdpPortPool on success, zero on fail.
*/
QWORD VmmNet_Initialize_Context_PortPool(_In_ PVMM_PROCESS pSystemProcess, _In_ QWORD vaInCS, _In_ DWORD dwTagTcpUdp)
{
    BOOL f;
    BYTE pb[0x200];
    POB_SET psvaOb = NULL;
    QWORD o, va, vaTcCo = 0, vaInPP = 0;
    // 1: InCS struct
    if(!(psvaOb = ObSet_New())) { goto fail; }
    if(!VmmRead(pSystemProcess, vaInCS - 0x10, pb, 0x180)) { goto fail; }
    if(!VMM_POOLTAG_PREPENDED(pb, 0x10, 'InCS')) { goto fail; }
    for(o = 0x10; o < 0x180; o += 8) {
        va = *(PQWORD)(pb + o);
        if(VMM_KADDR64_16(va)) {
            ObSet_Push(psvaOb, va - 0x10);
        }
    }
    // 2: InCo struct
    VmmCachePrefetchPages3(pSystemProcess, psvaOb, 0x40, 0);
    while((va = ObSet_Pop(psvaOb))) {
        f = VmmRead2(pSystemProcess, va, pb, 0x40, VMM_FLAG_FORCECACHE_READ) &&
            VMM_POOLTAG_PREPENDED(pb, 0x10, 'InCo') &&
            (va = *(PQWORD)(pb + 0x30)) &&
            VMM_KADDR64_16(va);
        if(f) {
            vaTcCo = va;
            break;
        }
    }
    if(!vaTcCo) { goto fail; }
    // 3: TcCo/UdCo struct
    f = VmmRead(pSystemProcess, vaTcCo - 0x10, pb, 0x20) &&
        VMM_POOLTAG_PREPENDED(pb, 0x10, dwTagTcpUdp) &&
        (vaInPP = *(PQWORD)(pb + 0x10)) &&
        VMM_KADDR64_PAGE(vaInPP);
    if(!f) { vaInPP = 0; }
fail:
    Ob_DECREF(psvaOb);
    return vaInPP;
}

/*
* Initialize the network context containing various offsets and other
* required data to look up networking information.
* -- pSystemProcess
*/
VOID VmmNet_Initialize_Context(_In_ PVMM_PROCESS pSystemProcess)
{
    BOOL fResult = FALSE;
    QWORD va;
    PDB_HANDLE hPDB = 0;
    PVMMNET_CONTEXT ctx = NULL;
    PVMMOB_MAP_MODULE pObModuleMap = NULL;
    PVMM_MAP_MODULEENTRY peModuleTcpip;
    if(!(ctx = LocalAlloc(LMEM_ZEROINIT, sizeof(VMMNET_CONTEXT)))) { goto fail; }
    // 1: fetch tcpip.sys info
    if(!VmmMap_GetModuleEntryEx(pSystemProcess, 0, "tcpip.sys", &pObModuleMap, &peModuleTcpip)) { goto fail; }
    ctx->vaModuleTcpip = peModuleTcpip->vaBase;
    // 2: fetch optional pdb handle
    if((hPDB = PDB_GetHandleFromModuleAddress(pSystemProcess, ctx->vaModuleTcpip))) {
        PDB_LoadEnsure(hPDB);
    }
    // 4: retrieve pdb information
    if(hPDB) {
        PDB_GetSymbolPTR(hPDB, "PartitionTable", pSystemProcess, &ctx->vaPartitionTable);
        PDB_GetSymbolDWORD(hPDB, "PartitionCount", pSystemProcess, &ctx->cPartition);
    } else {
        InfoDB_SymbolPTR("tcpip", ctx->vaModuleTcpip, "PartitionTable", pSystemProcess, &ctx->vaPartitionTable);
        InfoDB_SymbolDWORD("tcpip", ctx->vaModuleTcpip, "PartitionCount", pSystemProcess, &ctx->cPartition);
    }
    if(!VMM_KADDR(ctx->vaPartitionTable) || !ctx->cPartition || (ctx->cPartition > 64)) { goto fail; }
    // 3: retrieve TcpPortPool / UdpPortPool
    if(ctxVmm->kernel.dwVersionBuild <= 10586) {
        if(hPDB) {
            PDB_GetSymbolPTR(hPDB, "TcpPortPool", pSystemProcess, &ctx->vaTcpPortPool);
            PDB_GetSymbolPTR(hPDB, "UdpPortPool", pSystemProcess, &ctx->vaUdpPortPool);
        } else {
            InfoDB_SymbolPTR("tcpip", ctx->vaModuleTcpip, "TcpPortPool", pSystemProcess, &ctx->vaTcpPortPool);
            InfoDB_SymbolPTR("tcpip", ctx->vaModuleTcpip, "UdpPortPool", pSystemProcess, &ctx->vaUdpPortPool);
        }
    } else {
        if(PDB_GetSymbolPTR(hPDB, "TcpCompartmentSet", pSystemProcess, &va) || InfoDB_SymbolPTR("tcpip", ctx->vaModuleTcpip, "TcpCompartmentSet", pSystemProcess, &va)) {
            ctx->vaTcpPortPool = VmmNet_Initialize_Context_PortPool(pSystemProcess, va, 'TcCo');
        }
        if(PDB_GetSymbolPTR(hPDB, "UdpCompartmentSet", pSystemProcess, &va) || InfoDB_SymbolPTR("tcpip", ctx->vaModuleTcpip, "UdpCompartmentSet", pSystemProcess, &va)) {
            ctx->vaUdpPortPool = VmmNet_Initialize_Context_PortPool(pSystemProcess, va, 'UdCo');
        }
    }
    // 4: set offsets
    VmmNet_Initialize_Context_Fuzz_TcpL_UdpA(ctx);
    vmmprintfvv_fn("NET INIT: \n\t PartitionTable: 0x%llx [%i] \n\t TcpPortPool:    0x%llx \n\t UdpPortPool:    0x%llx\n", ctx->vaPartitionTable, ctx->cPartition, ctx->vaTcpPortPool, ctx->vaUdpPortPool);
    fResult = TRUE;
fail:
    if(!fResult) {
        LocalFree(ctx);
        ctx = NULL;
    }
    Ob_DECREF(pObModuleMap);
    ctxVmm->pNetContext = ctx;
}

/*
* Retrieve a Map containing the network connections of the system if possible.
* CALLER DECREF: return
* -- pSystemProcess
* -- return
*/
PVMMOB_MAP_NET VmmNet_Initialize_DoWork(_In_ PVMM_PROCESS pSystemProcess)
{
    PVMMNET_CONTEXT ctx = (PVMMNET_CONTEXT)ctxVmm->pNetContext;
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
        "***",
        "***",
        "TIME_WAIT",
        "***"
    };
    DWORD i, cNetEntries;
    PVMMOB_MAP_NET pObNet = NULL;
    PVMM_MAP_NETENTRY pe, pNetEntry;
    DWORD dwIpVersion, cwszSrc, cwszDst;
    CHAR uszSrc[64], uszDst[64];
    CHAR uszBuffer[MAX_PATH];
    POB_MAP pmObNetEntries = NULL;
    VMMNET_ASYNC_CONTEXT actx;
    POB_STRMAP psmOb = NULL;
    // 1: fetch / initialize context
    if(ctxVmm->f32) { goto fail; }
    if(!ctx) {
        VmmNet_Initialize_Context(pSystemProcess);
        if(!(ctx = (PVMMNET_CONTEXT)ctxVmm->pNetContext)) { goto fail; }
    }
    if(!(pmObNetEntries = ObMap_New(OB_MAP_FLAGS_OBJECT_LOCALFREE))) { goto fail; }
    // enumeration may take some time - schedule work in parallel to speed things up.
    actx.ctx = ctx;
    actx.pmNetEntries = pmObNetEntries;
    actx.pSystemProcess = pSystemProcess;
    VmmWorkWaitMultiple(&actx, 2, VmmNet_TcpE_DoWork, VmmNet_InPP_DoWork);
    cNetEntries = ObMap_Size(pmObNetEntries);
    if(!(psmOb = ObStrMap_New(OB_STRMAP_FLAGS_STR_ASSIGN_TEMPORARY))) { goto fail; }
    if(!(pObNet = Ob_Alloc(OB_TAG_MAP_NET, LMEM_ZEROINIT, sizeof(VMMOB_MAP_NET) + cNetEntries * sizeof(VMM_MAP_NETENTRY), (OB_CLEANUP_CB)VmmNet_CallbackCleanup_ObMapNet, NULL))) { goto fail; }
    for(i = 0; i < cNetEntries; i++) {
        pe = pObNet->pMap + i;
        pNetEntry = ObMap_GetByIndex(pmObNetEntries, i);
        memcpy(pe, pNetEntry, sizeof(VMM_MAP_NETENTRY));
        // src
        if(pe->Src.fValid && InetNtopA(pe->AF, pe->Src.pbAddr, uszBuffer, sizeof(uszBuffer))) {
            ObStrMap_PushPtrUU(psmOb, uszBuffer, &pe->Src.uszText, NULL);
        } else {
            ObStrMap_PushPtrUU(psmOb, "***", &pe->Src.uszText, NULL);
        }
        // dst
        if(pe->Dst.fValid && InetNtopA(pe->AF, pe->Dst.pbAddr, uszBuffer, sizeof(uszBuffer))) {
            ObStrMap_PushPtrUU(psmOb, uszBuffer, &pe->Dst.uszText, NULL);
        } else {
            ObStrMap_PushPtrUU(psmOb, "***", &pe->Dst.uszText, NULL);
        }
        // wsz
        dwIpVersion = (pe->AF == AF_INET) ? 4 : ((pe->AF == AF_INET6) ? 6 : 0);
        cwszSrc = _snprintf_s(uszSrc, _countof(uszSrc), _TRUNCATE, ((dwIpVersion == 6) ? "[%s]:%i" : "%s:%i"), pe->Src.uszText, pe->Src.port);
        cwszDst = pe->Dst.fValid ?
            _snprintf_s(uszDst, _countof(uszDst), _TRUNCATE, ((dwIpVersion == 6) ? "[%s]:%i" : "%s:%i"), pe->Dst.uszText, pe->Dst.port) :
            _snprintf_s(uszDst, _countof(uszDst), _TRUNCATE, "***");
        _snprintf_s(
            uszBuffer,
            sizeof(uszBuffer),
            _TRUNCATE,
            "%sv%i  %-11s  %-*s  %-*s",
            ((pe->dwPoolTag == 'UdpA') ? "UDP" : "TCP"),
            dwIpVersion,
            szSTATES[pe->dwState],
            max(28, cwszSrc),
            uszSrc,
            max(28, cwszDst),
            uszDst
        );
        ObStrMap_PushPtrUU(psmOb, uszBuffer, &pe->uszText, &pe->cbuText);
        pObNet->cMap++;
    }
    ObStrMap_FinalizeAllocU_DECREF_NULL(&psmOb, &pObNet->pbMultiText, &pObNet->cbMultiText);
    qsort(pObNet->pMap, pObNet->cMap, sizeof(VMM_MAP_NETENTRY), (int(*)(void const*, void const*))VmmNet_TcpE_CmpSort);
    Ob_INCREF(pObNet);
fail:
    Ob_DECREF(psmOb);
    Ob_DECREF(pmObNetEntries);
    return Ob_DECREF(pObNet);
}

/*
* Create a network connection map and assign to the global context upon success.
* CALLER DECREF: return
* -- return
*/
PVMMOB_MAP_NET VmmNet_Initialize()
{
    PVMMOB_MAP_NET pObNet = NULL;
    PVMM_PROCESS pObSystemProcess = NULL;
    if((pObNet = ObContainer_GetOb(ctxVmm->pObCMapNet))) { return pObNet; }
    EnterCriticalSection(&ctxVmm->LockUpdateMap);
    if((pObNet = ObContainer_GetOb(ctxVmm->pObCMapNet))) {
        LeaveCriticalSection(&ctxVmm->LockUpdateMap);
        return pObNet;
    }
    if((pObSystemProcess = VmmProcessGet(4))) {
        pObNet = VmmNet_Initialize_DoWork(pObSystemProcess);
        Ob_DECREF_NULL(&pObSystemProcess);
    }
    if(!pObNet) {
        pObNet = Ob_Alloc(OB_TAG_MAP_NET, LMEM_ZEROINIT, sizeof(VMMOB_MAP_NET), NULL, NULL);
    }
    ObContainer_SetOb(ctxVmm->pObCMapNet, pObNet);
    LeaveCriticalSection(&ctxVmm->LockUpdateMap);
    return pObNet;
}

/*
* Close the networking functionality.
* NB! Close() should only be called on vmm exit. To clear internal state plesae
* use function: VmmNet_Refresh().
*/
VOID VmmNet_Close()
{
    EnterCriticalSection(&ctxVmm->LockMaster);
    LocalFree(ctxVmm->pNetContext);
    ctxVmm->pNetContext = NULL;
    LeaveCriticalSection(&ctxVmm->LockMaster);
}

/*
* Refresh the network connection map.
*/
VOID VmmNet_Refresh()
{
    ObContainer_SetOb(ctxVmm->pObCMapNet, NULL);
}
