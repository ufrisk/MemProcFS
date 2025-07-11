// m_sys_netdns.c : implementation related to the Sys/Net/Dns built-in module.
//
// The 'sys/net/dns' module is responsible for displaying network DNS information
// cached by the operating system.
//
// (c) Ulf Frisk, 2025
// Author: Ulf Frisk, pcileech@frizk.net
// 
// This module is built upon the reversing work of the DNS caching algorithm
// done by MattCore71.
//

#ifdef _WIN32
#include <ws2tcpip.h>
#endif /* _WIN32 */
#include "../oscompatibility.h"
#include "modules.h"

LPCSTR szMSYSNETDNS_README =
"Information about the sys net/dns module                                     \n" \
"========================================                                     \n" \
"The sys/net/dns module tries extract cached dns information from the system. \n" \
"---                                                                          \n" \
"NB! Extraction of DNS information which is not cached by the system,         \n" \
"    such as browser-internal DNS information (DoH), is not supported.        \n" \
"---                                                                          \n" \
"Documentation: https://github.com/ufrisk/MemProcFS/wiki/FS_SysInfo_Network   \n";

typedef struct tdVMM_MAP_NETDNSENTRY {
    QWORD va;
    DWORD dwTTL;
    DWORD dwFlags;
    LPSTR uszName;
    LPSTR uszType;
    LPSTR uszData;
} VMM_MAP_NETDNSENTRY, *PVMM_MAP_NETDNSENTRY;

typedef struct tdVMMOB_MAP_NETDNS {
    OB ObHdr;
    PBYTE pbMultiText;              // UTF-8 multi-string pointed into by VMM_MAP_VADENTRY.wszText
    DWORD cbMultiText;
    DWORD cMap;                     // # map entries.
    VMM_MAP_NETDNSENTRY pMap[];     // map entries.
} VMMOB_MAP_NETDNS, *PVMMOB_MAP_NETDNS;

#define MSYSNETDNS_LINELENGTH       200ULL
#define MSYSNETDNS_LINEHEADER       "   #      Address Type        TTL Name                                                             Data"
#define MSYSNETDNS_CSV              "Address,Type,Flags,TTL,Name,Data\n"



// ----------------------------------------------------------------------------
// NETDNS functionality below:
// (excl. module specific functionality).
// ----------------------------------------------------------------------------

#define VMMNETDNS_MAX_CHARLEN   2048
#define VMMNETDNS_MAX_ENTRIES   0x00010000  // 64k entries max.

typedef struct tdDNS_RECORD32 {
    DWORD vaFLink;
    DWORD vaName;
    USHORT wType;
    USHORT wDataLength;
    ULONG dwFlags;
    ULONG dwTTL;
    ULONG dwReserved;
    BYTE  pbData[16];   // IPv4, IPv6, or PTR data.
} DNS_RECORD32, *PDNS_RECORD32;

typedef struct tdDNS_RECORD64 {
    QWORD vaFLink;
    QWORD vaName;
    USHORT wType;
    USHORT wDataLength;
    ULONG dwFlags;
    ULONG dwTTL;
    ULONG dwReserved;
    BYTE  pbData[16];   // IPv4, IPv6, or PTR data.
} DNS_RECORD64, *PDNS_RECORD64;

static LPCSTR NETDNS_TYPE_STR[256] = {
    [0x01] = "A",
    [0x02] = "NS",
    [0x03] = "MD",
    [0x04] = "MF",
    [0x05] = "CNAME",
    [0x06] = "SOA",
    [0x07] = "MB",
    [0x08] = "MG",
    [0x09] = "MR",
    [0x0a] = "NULL",
    [0x0b] = "WKS",
    [0x0c] = "PTR",
    [0x0d] = "HINFO",
    [0x0e] = "MINFO",
    [0x0f] = "MX",
    [0x10] = "TEXT",
    [0x11] = "RP",
    [0x12] = "AFSDB",
    [0x13] = "X25",
    [0x14] = "ISDN",
    [0x15] = "RT",
    [0x16] = "NSAP",
    [0x17] = "NSAPPTR",
    [0x18] = "SIG",
    [0x19] = "KEY",
    [0x1a] = "PX",
    [0x1b] = "GPOS",
    [0x1c] = "AAAA",
    [0x1d] = "LOC",
    [0x1e] = "NXT",
    [0x1f] = "EID",
    [0x20] = "NIMLOC",
    [0x21] = "SRV",
    [0x22] = "ATMA",
    [0x23] = "NAPTR",
    [0x24] = "KX",
    [0x25] = "CERT",
    [0x26] = "A6",
    [0x27] = "DNAME",
    [0x28] = "SINK",
    [0x29] = "OPT",
    [0x64] = "UINFO",
    [0x65] = "UID",
    [0x66] = "GID",
    [0x67] = "UNSPEC",
    [0xf8] = "ADDRS",
    [0xf9] = "TKEY",
    [0xfa] = "TSIG",
    [0xfb] = "IXFR",
    [0xfc] = "AXFR",
    [0xfd] = "MAILB",
    [0xfe] = "MAILA",
    [0xff] = "ALL",
};

static BOOL NETDNS_TYPE_PTR[256] = {
    [0x02] = TRUE,
    [0x03] = TRUE,
    [0x04] = TRUE,
    [0x05] = TRUE,
    [0x07] = TRUE,
    [0x08] = TRUE,
    [0x09] = TRUE,
    [0x0c] = TRUE,
    [0x02] = TRUE,
    [0x02] = TRUE,
    [0x21] = TRUE,
    [0x27] = TRUE,
};

typedef struct tdVMMNETDNS_INIT_CONTEXT {
    VMM_MODULE_ID MID;
    PVMM_PROCESS pProcess;
    QWORD vaHashTable;
    QWORD vaHashTableTop;
    DWORD cHashTable;
    POB_SET psvaHashRecordAll;
    POB_SET psvaHashRecordNew;
    POB_SET psvaHashRecordNew2;
    POB_SET psvaDnsRecordAll;
    POB_SET psvaDnsRecordNew;
    POB_SET psvaDnsRecordNew2;
    POB_MAP pmDnsRecord;
    POB_STRMAP psmDnsText;
    PVMMOB_SCATTER hS;
    struct {
        WORD cb;
        WORD oFlink;
        WORD oBlink;
        WORD oDNS;
    } off_hashentry;
} VMMNETDNS_INIT_CONTEXT, *PVMMNETDNS_INIT_CONTEXT;

#define VMMNETDNS_IS_ADDR_HASHTABLE(ctx, va)        ((va) >= ((ctx)->vaHashTable) && ((va) < (ctx)->vaHashTableTop))

/*
* Verify that the process is a proper 'svchost.exe' process.
* -- H
* -- pProcess = process to verify.
* -- return
*/
static BOOL VmmNetDns_GetProcess_VerifySvchost(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess)
{
    BOOL f;
    PVMM_PROCESS pObProcessParent = NULL;
    f = CharUtil_StrEquals(pProcess->szName, "svchost.exe", FALSE) &&
        (pObProcessParent = VmmProcessGet(H, pProcess->dwPPID)) &&
        CharUtil_StrEquals(pObProcessParent->szName, "services.exe", FALSE);
    Ob_DECREF(pObProcessParent);
    return f;
}

/*
* Retrieve the 'svchost.exe' process that runs the DNS caching service.
* CALLER DECREF: return
* -- H
* -- return
*/
_Success_(return != NULL)
static PVMM_PROCESS VmmNetDns_GetProcess(_In_ VMM_HANDLE H)
{
    PVMM_PROCESS pObProcess = NULL;
    PVMMWIN_USER_PROCESS_PARAMETERS pu;
    PVMMOB_MAP_MODULE pObModuleMap = NULL;
    PVMM_MAP_MODULEENTRY peModule = NULL;
    // 1: try to find the 'svchost.exe' process that runs the DNS caching service
    // by checking the command line for '-s Dnscache' (faster method):
    while((pObProcess = VmmProcessGetNext(H, pObProcess, 0))) {
        if((*(PQWORD)pObProcess->szName != 0x2e74736f68637673) || !VmmNetDns_GetProcess_VerifySvchost(H, pObProcess)) { continue; }
        pu = VmmWin_UserProcessParameters_Get(H, pObProcess);
        if(pu && pu->uszCommandLine && strstr(pu->uszCommandLine, "-s Dnscache")) {
            return pObProcess;
        }
    }
    // 2: try to find the 'svchost.exe' process that runs the DNS caching service
    // by checking if the module 'dnsrslvr.dll' is loaded:
    while((pObProcess = VmmProcessGetNext(H, pObProcess, 0))) {
        if((*(PQWORD)pObProcess->szName != 0x2e74736f68637673) || !VmmNetDns_GetProcess_VerifySvchost(H, pObProcess)) { continue; }
        VmmMap_GetModuleEntryEx(H, pObProcess, 0, "dnsrslvr.dll", 0, &pObModuleMap, &peModule);
        Ob_DECREF_NULL(&pObModuleMap);
        if(peModule) {
            return pObProcess;
        }
    }
    return NULL;
}

/*
* Calculate the hash table top address based on the base address and size.
* -- H
* -- vaHashTableBase = base address of the hash table.
* -- cHashTable = size of the hash table.
* -- return = top address of the hash table.
*/
static QWORD VmmNetDns_LookupHashTable_HashTableTop(_In_ VMM_HANDLE H, _In_ QWORD vaHashTableBase, _In_ DWORD cHashTable)
{
    DWORD cbPtr;
    if(H->vmm.f32) {
        cbPtr = 4;
    } else if(H->vmm.kernel.dwVersionBuild <= 22000) {
        cbPtr = 8;
    } else {
        cbPtr = 16;
    }
    return vaHashTableBase + (cHashTable * cbPtr);
}

/*
* Retrieve the DNS hash table address and its size.
* -- H
* -- pProcess
* -- pvaHashTableBase = receives the hash table base address.
* -- pvaHashTableTop = receives the hash table top address.
* -- pcHashTable = receives the size of the hash table.
* -- fIsSymbolLookup = receives TRUE if the hash table was found using symbols, otherwise heuristic lookup.
* -- return
*/
_Success_(return)
static BOOL VmmNetDns_LookupHashTable(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess, _Out_ PQWORD pvaHashTableBase, _Out_ PQWORD pvaHashTableTop, _Out_ PDWORD pcHashTable, _Out_ PBOOL fSymbolLookup)
{
    BOOL fResult = FALSE;
    PVMMOB_MAP_MODULE pObModuleMap = NULL;
    PVMM_MAP_MODULEENTRY peModule = NULL;
    PVMMOB_MAP_HEAP pObHeapMap = NULL;
    PVMM_MAP_HEAPENTRY peHeap = NULL;
    DWORD i, c;
    PVMMOB_MAP_HEAPALLOC pObHeapAllocMap = NULL;
    PVMM_MAP_HEAPALLOCENTRY peAlloc, peAllocPrev = NULL;
    DWORD cbPTR = (H->vmm.f32 ? 4 : 8);
    DWORD cbMinSizeHashTable = ((H->vmm.kernel.dwVersionBuild <= 9600) ? 0x400 : 0x1000); // minimum size of the hash table allocation.
    PQWORD pvaT = NULL;
    *fSymbolLookup = FALSE;
    *pvaHashTableBase = 0;
    *pvaHashTableTop = 0;
    *pcHashTable = 0;
    // 1: try lookup DNS hash table using symbols:
    if(VmmMap_GetModuleEntryEx(H, pProcess, 0, "dnsrslvr.dll", 0, &pObModuleMap, &peModule)) {
        if(PDB_GetHandleFromModuleAddress(H, pProcess, peModule->vaBase)) {
            fResult =
                PDB_GetSymbolPTR(H, PDB_HANDLE_DNSRSLVR, "g_HashTable", pProcess, (PVOID)pvaHashTableBase) &&
                PDB_GetSymbolDWORD(H, PDB_HANDLE_DNSRSLVR, "g_HashTableSize", pProcess, pcHashTable);
        }
        Ob_DECREF_NULL(&pObModuleMap);
    }
    if(fResult) {
        *pvaHashTableTop = VmmNetDns_LookupHashTable_HashTableTop(H, *pvaHashTableBase, *pcHashTable);
        *fSymbolLookup = TRUE;
        return TRUE;
    }
    // 2: try lookup DNS hash table using heuristics:
    //    in XP->Win10 it's assumed the largest heap allocation in the topmost heap is the DNS hash table.
    //    in Win11+ any allocation larger than 0x7000 bytes is a candidate and is read and "verified".
    if(VmmMap_GetHeap(H, pProcess, &pObHeapMap) && pObHeapMap->cMap) {
        // 2.1 - locate the topmost heap:
        for(i = 0; i < pObHeapMap->cMap; i++) {
            if(!peHeap || (peHeap->dwHeapNum < pObHeapMap->pMap[i].dwHeapNum)) {
                peHeap = &pObHeapMap->pMap[i];
            }
        }
        if(peHeap && VmmMap_GetHeapAlloc(H, pProcess, peHeap->va, &pObHeapAllocMap)) {
            if(H->vmm.kernel.dwVersionBuild >= 22000) {
                // Win11+ heuristics: read any allocation larger than 0x7000 and integrity check it.
                for(i = 0; i < pObHeapAllocMap->cMap; i++) {
                    peAlloc = &pObHeapAllocMap->pMap[i];
                    if((peAlloc->cb < 0x7000) || (peAlloc->cb > 0x00100000) || (peAlloc->cb & 0xf)) { continue; }
                    if(VmmReadAlloc(H, pProcess, peAlloc->va, (PBYTE*)&pvaT, peAlloc->cb, 0)) {
                        fResult = TRUE;
                        c = (peAlloc->cb / 16) - 2; // number of entries in the hash table.
                        for(i = 0; i < c; i++) {
                            if(!VMM_UADDR64_8(pvaT[i])) {
                                fResult = FALSE;
                                break;
                            }
                        }
                        LocalFree(pvaT);
                        if(fResult) {
                            *pvaHashTableBase = peAlloc->va;
                            *pcHashTable = (peAlloc->cb / 16) - 2;
                            break;
                        }
                    }
                }
            } else {
                // XP->Win10 heuristics: try to find the DNS hash table in the heap allocations:
                for(i = 0; i < pObHeapAllocMap->cMap; i++) {
                    peAlloc = &pObHeapAllocMap->pMap[i];
                    if(peAlloc->cb < cbMinSizeHashTable) { continue; }
                    if(peAlloc->cb % cbPTR) { continue; }
                    if(!peAllocPrev || (peAllocPrev->cb < peAlloc->cb)) {
                        peAllocPrev = peAlloc;
                    }
                }
                if(peAllocPrev) {
                    fResult = TRUE;
                    *pvaHashTableBase = peAllocPrev->va;
                    *pcHashTable = (peAllocPrev->cb / (H->vmm.f32 ? 4 : 8)) - 4;
                }
            }
        }
    }
    Ob_DECREF(pObHeapMap);
    Ob_DECREF(pObHeapAllocMap);
    *pvaHashTableTop = VmmNetDns_LookupHashTable_HashTableTop(H, *pvaHashTableBase, *pcHashTable);
    return fResult;
}

/*
* Retrieve the hash table records and parse the DNS record pointers.
* -- H
* -- ctx = initialization context containing the hash table address and size.
* -- return
*/
_Success_(return)
static BOOL VmmNetDns_FetchParseHashRecord(_In_ VMM_HANDLE H, _In_ PVMMNETDNS_INIT_CONTEXT ctx)
{
    BOOL f32 = H->vmm.f32;
    DWORD cbPtr = (H->vmm.f32 ? 4 : 8);
    QWORD va, vaFLink, vaBLink, vaDNS;
    DWORD i, cLoopProtect = 0;
    BYTE pb[0x100] = { 0 };
    PBYTE pbHashTable = NULL;
    // 1: fetch the hash table and its ptrs:
    if(H->vmm.kernel.dwVersionBuild >= 22621) { cbPtr = 0x10; };
    if(!VmmReadAlloc(H, ctx->pProcess, ctx->vaHashTable, &pbHashTable, ctx->cHashTable * cbPtr, VMM_FLAG_ZEROPAD_ON_FAIL)) { return FALSE; }
    if(f32) {
        for(i = 0; i < ctx->cHashTable; i++) {
            va = ((PDWORD)pbHashTable)[i];
            if(VMM_UADDR32_8(va)) {
                ObSet_Push(ctx->psvaHashRecordNew, va);
            }
        }
    } else {
        if(H->vmm.kernel.dwVersionBuild >= 22621) {
            for(i = 0; i < 2 * ctx->cHashTable; i++) {
                va = ((PQWORD)pbHashTable)[i] - 8;
                if(VMM_UADDR64_16(va) && !VMMNETDNS_IS_ADDR_HASHTABLE(ctx, va)) {
                    ObSet_Push(ctx->psvaHashRecordNew, va);
                }
            }
        } else {
            for(i = 0; i < ctx->cHashTable; i++) {
                va = ((PQWORD)pbHashTable)[i];
                if(VMM_UADDR64_16(va) && !VMMNETDNS_IS_ADDR_HASHTABLE(ctx, va)) {
                    ObSet_Push(ctx->psvaHashRecordNew, va);
                }
            }
        }
    }
    LocalFree(pbHashTable);
    if(!ObSet_Size(ctx->psvaHashRecordNew)) { return FALSE; }
    // 2: fetch & parse hash records:
    while(ObSet_Size(ctx->psvaHashRecordNew) && (++cLoopProtect < 10)) {
        ObSet_PushSet(ctx->psvaHashRecordAll, ctx->psvaHashRecordNew);
        VmmScatter_Clear(ctx->hS);
        VmmScatter_Prepare3(ctx->hS, ctx->psvaHashRecordNew, ctx->off_hashentry.cb);
        VmmScatter_Execute(ctx->hS, ctx->pProcess);
        while((va = ObSet_Pop(ctx->psvaHashRecordNew))) {
            if(VmmScatter_Read(ctx->hS, va, ctx->off_hashentry.cb, pb, NULL)) {
                if(ctx->off_hashentry.oFlink) {
                    // _LIST_ENTRY
                    vaFLink = VMM_PTR_OFFSET(f32, pb, ctx->off_hashentry.oFlink) - ctx->off_hashentry.oFlink;
                    if(VMM_UADDR_8_16(f32, vaFLink) && !VMMNETDNS_IS_ADDR_HASHTABLE(ctx, vaFLink) && !ObSet_Exists(ctx->psvaHashRecordAll, vaFLink)) {
                        ObSet_Push(ctx->psvaHashRecordNew2, vaFLink);
                    }
                    vaBLink = VMM_PTR_OFFSET(f32, pb, ctx->off_hashentry.oBlink) - ctx->off_hashentry.oFlink;
                    if(VMM_UADDR_8_16(f32, vaBLink) && !VMMNETDNS_IS_ADDR_HASHTABLE(ctx, vaBLink) && !ObSet_Exists(ctx->psvaHashRecordAll, vaBLink)) {
                        ObSet_Push(ctx->psvaHashRecordNew2, vaBLink);
                    }
                }
                // DNS
                vaDNS = VMM_PTR_OFFSET(f32, pb, ctx->off_hashentry.oDNS);
                if(VMM_UADDR_8_16(f32, vaDNS)) {
                    ObSet_Push(ctx->psvaDnsRecordNew, vaDNS);
                }
            }
        }
        ObSet_PushSet(ctx->psvaHashRecordNew, ctx->psvaHashRecordNew2);
        ObSet_Clear(ctx->psvaHashRecordNew2);
    }
    return ObSet_Size(ctx->psvaDnsRecordNew) > 0;
}

/*
* Verify the DNS record & save it for later.
* -- H
* -- ctx = initialization context.
* -- va = virtual address of the DNS record.
* -- pDns64 = pointer to the DNS record (either 32 or 64 bit).
*/
static VOID VmmNetDns_FetchParseDnsRecord_Single(_In_ VMM_HANDLE H, _In_ PVMMNETDNS_INIT_CONTEXT ctx, _In_ QWORD va, _In_ PDNS_RECORD64 pDns64)
{
    DNS_RECORD64 oDNS3264;
    PDNS_RECORD64 pDNS = NULL;
    PDNS_RECORD32 pDNS32 = NULL;
    QWORD vaPtr = 0;
    BOOL f32 = H->vmm.f32;
    DWORD cbPTR = f32 ? 4 : 8;
    // 1: 32 to 64 bit conversions (if required):
    if(f32) {
        pDNS32 = (PDNS_RECORD32)pDns64;
        oDNS3264.vaFLink = pDNS32->vaFLink;
        oDNS3264.vaName = pDNS32->vaName;
        oDNS3264.wType = pDNS32->wType;
        oDNS3264.wDataLength = pDNS32->wDataLength;
        oDNS3264.dwFlags = pDNS32->dwFlags;
        oDNS3264.dwTTL = pDNS32->dwTTL;
        oDNS3264.dwReserved = pDNS32->dwReserved;
        memcpy(oDNS3264.pbData, pDNS32->pbData, 16);
        pDNS = &oDNS3264;
    } else {
        pDNS = pDns64;
    }
    // 2: Sanity checks:
    if(pDNS->vaFLink && !VMM_UADDR_8_16(f32, pDNS->vaFLink)) {
        VmmLog(H, ctx->MID, LOGLEVEL_6_TRACE, "FAIL: Invalid FLink PTR va:[%llx]", va);
        return;
    }
    if(!VMM_UADDR_8_16(f32, pDNS->vaName)) {
        VmmLog(H, ctx->MID, LOGLEVEL_6_TRACE, "FAIL: Invalid Name PTR va:[%llx] vaName:[%llx]", va, pDNS->vaName);
        return;
    }
    if((pDNS->wType > 255) || !NETDNS_TYPE_STR[pDNS->wType]) {
        VmmLog(H, ctx->MID, LOGLEVEL_6_TRACE, "FAIL: Invalid Type va:[%llx] tp:[%x]", va, pDNS->wType);
        return;
    }
    if(NETDNS_TYPE_PTR[pDNS->wType]) {   // PTR-record
        vaPtr = VMM_PTR_OFFSET(f32, pDNS->pbData, 0);
        if(!VMM_UADDR_4_8(f32, vaPtr) || (pDNS->wDataLength != cbPTR)) {
            VmmLog(H, ctx->MID, LOGLEVEL_6_TRACE, "FAIL: Invalid Data PTR va:[%llx]", va);
            return;
        }
    }
    // 3: Queue FLink PTR for later lookup:
    if(pDNS->vaFLink && VMM_UADDR_8_16(f32, pDNS->vaFLink) && !ObSet_Exists(ctx->psvaDnsRecordAll, pDNS->vaFLink)) {
        ObSet_Push(ctx->psvaDnsRecordNew2, pDNS->vaFLink);
    }
    // 4: Save the DNS record for later processing:
    ObMap_PushCopy(ctx->pmDnsRecord, va, pDNS, sizeof(DNS_RECORD64));
}

/*
* Retrieve the DNS records and do initial parsing of them.
* -- H
* -- ctx
* -- return
*/
_Success_(return)
static BOOL VmmNetDns_FetchParseDnsRecord(_In_ VMM_HANDLE H, _In_ PVMMNETDNS_INIT_CONTEXT ctx)
{
    QWORD va;
    DNS_RECORD64 oDNS;
    DWORD cLoopProtect = 0;
    // 1: fetch & parse hash records:
    while(ObSet_Size(ctx->psvaDnsRecordNew) && (++cLoopProtect < 10)) {
        ObSet_PushSet(ctx->psvaDnsRecordAll, ctx->psvaDnsRecordNew);
        VmmScatter_Clear(ctx->hS);
        VmmScatter_Prepare3(ctx->hS, ctx->psvaDnsRecordNew, sizeof(DNS_RECORD64));
        VmmScatter_Execute(ctx->hS, ctx->pProcess);
        while((va = ObSet_Pop(ctx->psvaDnsRecordNew))) {
            if(VmmScatter_Read(ctx->hS, va, sizeof(DNS_RECORD64), (PBYTE)&oDNS, NULL)) {
                VmmNetDns_FetchParseDnsRecord_Single(H, ctx, va, &oDNS);
            }
        }
        ObSet_PushSet(ctx->psvaDnsRecordNew, ctx->psvaDnsRecordNew2);
        ObSet_Clear(ctx->psvaDnsRecordNew2);
    }
    return ObMap_Size(ctx->pmDnsRecord) > 0;
}

/*
* Cleanup callback function for VMMOB_MAP_NETDNS.
* -- pOb
*/
static VOID VmmNetDns_CleanupCB(PVMMOB_MAP_NETDNS pOb)
{
    LocalFree(pOb->pbMultiText);
}

/*
* Sorting comparator for VMM_MAP_NETDNSENTRY.
* -- p1
* -- p2
* -- return
*/
static int VmmNetDns_qsort_NetDnsEntry(PVMM_MAP_NETDNSENTRY p1, PVMM_MAP_NETDNSENTRY p2)
{
    int i = strcmp(p1->uszName, p2->uszName);
    if(i) { return i; }  // sort by name first.
    return (p1->va < p2->va) ? -1 : ((p1->va > p2->va) ? 1 : 0);
}

/*
* Parse all DNS records and return a map object containing the parsed entries.
* CALLER DECREF: return
* -- H
* -- ctx = initialization context containing the DNS record addresses.
* -- return = map object containing the parsed DNS entries, or NULL on failure.
*/
_Success_(return != NULL)
static PVMMOB_MAP_NETDNS VmmNetDns_ParseDnsRecordAll(_In_ VMM_HANDLE H, _In_ PVMMNETDNS_INIT_CONTEXT ctx)
{
    PVMM_MAP_NETDNSENTRY pe;
    PVMMOB_MAP_NETDNS pObMap = NULL;
    PDNS_RECORD64 pDNS;
    QWORD va, vaPTR;
    DWORD i, cMap = 0;
    LPCSTR szType;
    CHAR szIP[128];
    BOOL f32 = H->vmm.f32;
    DWORD cbPTR = f32 ? 4 : 8;
    // 1: allocate the map object:
    cMap = ObMap_Size(ctx->pmDnsRecord);
    pObMap = (PVMMOB_MAP_NETDNS)Ob_AllocEx(H, OB_TAG_MAP_NETDNS, LMEM_ZEROINIT, sizeof(VMMOB_MAP_NETDNS) + cMap * sizeof(VMM_MAP_NETDNSENTRY), (OB_CLEANUP_CB)VmmNetDns_CleanupCB, NULL);
    if(!pObMap) { goto fail; }
    // 2: fill map with dns entries:
    pObMap->cMap = cMap;
    for(i = 0; i < cMap; i++) {
        pe = &pObMap->pMap[i];
        pDNS = (PDNS_RECORD64)ObMap_GetByIndex(ctx->pmDnsRecord, i);        // map localalloc copy - do not free here!
        va = ObMap_GetKey(ctx->pmDnsRecord, pDNS);                          // get the key (va) for the DNS record.
        // parse already verified DNS record:
        szType = NETDNS_TYPE_STR[pDNS->wType];
        if(pDNS->wType == 0x01) {         // A-record (IPv4)
            if((pDNS->wDataLength != 4) || !InetNtopA(AF_INET, pDNS->pbData, szIP, sizeof(szIP))) {
                szIP[0] = 0;
            }
            ObStrMap_PushPtrAU(ctx->psmDnsText, szIP, &pe->uszData, NULL);
        } else if(pDNS->wType == 0x1c) {    // AAAA-record (IPv6)
            if((pDNS->wDataLength != 16) || !InetNtopA(AF_INET6, pDNS->pbData, szIP, sizeof(szIP))) {
                szIP[0] = 0;
            }
            ObStrMap_PushPtrAU(ctx->psmDnsText, szIP, &pe->uszData, NULL);
        } else if(NETDNS_TYPE_PTR[pDNS->wType]) {   // PTR-record
            vaPTR = VMM_PTR_OFFSET(f32, pDNS->pbData, 0);
            if(!VMM_UADDR_4_8(f32, vaPTR) || (pDNS->wDataLength != cbPTR)) {
                VmmLog(H, ctx->MID, LOGLEVEL_6_TRACE, "FAIL: Invalid Data PTR va:[%llx]", va);
                return FALSE;
            }
            ObStrMap_Push_UnicodeBuffer(ctx->psmDnsText, VMMNETDNS_MAX_CHARLEN, vaPTR, &pe->uszData, NULL);
        } else {
            ObStrMap_PushPtrAU(ctx->psmDnsText, "", &pe->uszData, NULL);
        }
        // 4: Finalize: Name, Type, va, Flags, TTL:
        ObStrMap_Push_UnicodeBuffer(ctx->psmDnsText, VMMNETDNS_MAX_CHARLEN, pDNS->vaName, &pe->uszName, NULL);
        ObStrMap_PushPtrAU(ctx->psmDnsText, szType, &pe->uszType, NULL);
        pe->va = va;
        pe->dwFlags = pDNS->dwFlags;
        pe->dwTTL = pDNS->dwTTL;
        VmmLog(H, ctx->MID, LOGLEVEL_6_TRACE, "DNS_RECORD: va:[%llx] tp:[%s]", va, szType);
    }
    // 3: finalize and sort map:
    if(!cMap) { goto fail; }
    pObMap->cMap = cMap;
    if(!ObStrMap_FinalizeAllocU_DECREF_NULL(&ctx->psmDnsText, &pObMap->pbMultiText, &pObMap->cbMultiText)) { goto fail; }
    qsort(pObMap->pMap, pObMap->cMap, sizeof(VMM_MAP_NETDNSENTRY), (_CoreCrtNonSecureSearchSortCompareFunction)VmmNetDns_qsort_NetDnsEntry);   // sort by DNS name, then by address.
    Ob_INCREF(pObMap);
fail:
    return Ob_DECREF(pObMap);
}

/*
* Initialize the 'NetDnsMap' object.
* CALLER DECREF: return
* -- H
* -- ctxP = plugin context containing the module ID.
* -- return = map object containing the parsed DNS entries, or NULL on failure.
*/
_Success_(return != NULL)
static PVMMOB_MAP_NETDNS VmmNetDns_Initialize_DoWork(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_CONTEXT ctxP)
{
    BOOL fSymbolLookup;
    PVMMOB_MAP_NETDNS pObMap = NULL;
    PVMMNETDNS_INIT_CONTEXT ctx = NULL;
    VMMSTATISTICS_LOG Statistics = { 0 };
    VmmStatisticsLogStart(H, ctxP->MID, LOGLEVEL_6_TRACE, NULL, &Statistics, "INIT_DNS");
    if(!(ctx = (PVMMNETDNS_INIT_CONTEXT)LocalAlloc(LMEM_ZEROINIT, sizeof(VMMNETDNS_INIT_CONTEXT)))) { goto fail; }
    ctx->MID = ctxP->MID;
    if(!(ctx->pProcess = VmmNetDns_GetProcess(H))) { goto fail; }
    VmmLog(H, ctx->MID, LOGLEVEL_6_TRACE, "Caching service process PID:[%u]", ctx->pProcess->dwPID);
    if(!(ctx->psvaHashRecordAll = ObSet_New(H))) { goto fail; }
    if(!(ctx->psvaHashRecordNew = ObSet_New(H))) { goto fail; }
    if(!(ctx->psvaHashRecordNew2 = ObSet_New(H))) { goto fail; }
    if(!(ctx->psvaDnsRecordAll = ObSet_New(H))) { goto fail; }
    if(!(ctx->psvaDnsRecordNew = ObSet_New(H))) { goto fail; }
    if(!(ctx->psvaDnsRecordNew2 = ObSet_New(H))) { goto fail; }
    if(!(ctx->pmDnsRecord = ObMap_New(H, OB_MAP_FLAGS_OBJECT_LOCALFREE))) { goto fail; }
    if(!(ctx->psmDnsText = ObStrMap_New(H, OB_STRMAP_FLAGS_WITH_PROCESS_PID | ((QWORD)ctx->pProcess->dwPID << 32)))) { goto fail; }
    if(!(ctx->hS = VmmScatter_Initialize(H, VMM_FLAG_ZEROPAD_ON_FAIL))) { goto fail; }
    if(!VmmNetDns_LookupHashTable(H, ctx->pProcess, &ctx->vaHashTable, &ctx->vaHashTableTop, &ctx->cHashTable, &fSymbolLookup)) { goto fail; }
    VmmLog(H, ctx->MID, LOGLEVEL_6_TRACE, "Hash table va:[%llx] size:[%u] type:[%s]", ctx->vaHashTable, ctx->cHashTable, (fSymbolLookup ? "SYMBOL" : "HEURISTICS"));
    if(!VMM_UADDR_8_16(H->vmm.f32, ctx->vaHashTable) || !ctx->cHashTable || (ctx->cHashTable > VMMNETDNS_MAX_ENTRIES)) { goto fail; }
    PDB_GetTypeChildOffsetShort(H, PDB_HANDLE_DNSRSLVR, "_HASHRECORD", "DNS", &ctx->off_hashentry.oDNS);
    PDB_GetTypeChildOffsetShort(H, PDB_HANDLE_DNSRSLVR, "_HASHRECORD", "FLink", &ctx->off_hashentry.oFlink);
    ctx->off_hashentry.oBlink = ctx->off_hashentry.oFlink + (H->vmm.f32 ? 4 : 8);
    ctx->off_hashentry.cb = ctx->off_hashentry.oDNS + 8;
    if(!ctx->off_hashentry.oDNS || !ctx->off_hashentry.oFlink) {
        VmmLog(H, ctx->MID, LOGLEVEL_5_DEBUG, "FAIL: Unable to retrieve offsets for DNS hash record.");
        goto fail;
    }
    if(!VmmNetDns_FetchParseHashRecord(H, ctx)) {
        VmmLog(H, ctx->MID, LOGLEVEL_5_DEBUG, "FAIL: unable to parse hash records.");
        goto fail;
    }
    if(!VmmNetDns_FetchParseDnsRecord(H, ctx)) {
        VmmLog(H, ctx->MID, LOGLEVEL_5_DEBUG, "FAIL: unable to parse dns records.");
        goto fail;
    }
    if(!(pObMap = VmmNetDns_ParseDnsRecordAll(H, ctx))) {
        VmmLog(H, ctx->MID, LOGLEVEL_5_DEBUG, "FAIL: unable to parse DNS records.");
        goto fail;
    }
    // fall through to cleanup:
fail:
    // cleanup:
    if(ctx) {
        Ob_DECREF(ctx->pProcess);
        Ob_DECREF(ctx->psvaHashRecordAll);
        Ob_DECREF(ctx->psvaHashRecordNew);
        Ob_DECREF(ctx->psvaHashRecordNew2);
        Ob_DECREF(ctx->psvaDnsRecordAll);
        Ob_DECREF(ctx->psvaDnsRecordNew);
        Ob_DECREF(ctx->psvaDnsRecordNew2);
        Ob_DECREF(ctx->pmDnsRecord);
        Ob_DECREF(ctx->psmDnsText);
        Ob_DECREF(ctx->hS);
        LocalFree(ctx);
    }
    // finish:
    if(!pObMap) {
        pObMap = Ob_AllocEx(H, OB_TAG_MAP_NETDNS, LMEM_ZEROINIT, sizeof(VMMOB_MAP_NETDNS), NULL, NULL);
    }
    ObContainer_SetOb((POB_CONTAINER)ctxP->ctxM, pObMap);
    VmmStatisticsLogEnd(H, &Statistics, "INIT_DNS");
    return pObMap;
}

/*
* Fetch the 'NetDnsMap' object.
* CALLER DECREF: return
* -- ctxP
* -- return
*/
_Success_(return != NULL)
static PVMMOB_MAP_NETDNS VmmNetDns_GetMap(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_CONTEXT ctxP)
{
    PVMMOB_MAP_NETDNS pOb;
    if((pOb = ObContainer_GetOb((POB_CONTAINER)ctxP->ctxM))) { return pOb; }
    EnterCriticalSection(&H->vmm.LockPlugin);
    if(!(pOb = ObContainer_GetOb((POB_CONTAINER)ctxP->ctxM))) {
        pOb = VmmNetDns_Initialize_DoWork(H, ctxP);
    }
    LeaveCriticalSection(&H->vmm.LockPlugin);
    return pOb;
}



// ----------------------------------------------------------------------------
// MSysNetDns module functionality below:
// ----------------------------------------------------------------------------

/*
* Generate a single line in the dns.txt file.
*/
static VOID MSysNetDns_ReadLine_CB(_In_ VMM_HANDLE H, _In_ PVMMOB_MAP_NETDNS pDnsMap, _In_ DWORD cbLineLength, _In_ DWORD ie, _In_ PVOID pv, _Out_writes_(cbLineLength + 1) LPSTR szu8)
{
    PVMM_MAP_NETDNSENTRY pe = &pDnsMap->pMap[ie];
    Util_usnprintf_ln(szu8, cbLineLength,
        "%04x %012llx %-7.7s %7u %-64.64s %s",
        ie,
        pe->va,
        pe->uszType,
        pe->dwTTL,
        pe->uszName,
        pe->uszData
    );
}

static NTSTATUS MSysNetDns_Read(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_CONTEXT ctxP, _Out_writes_to_(cb, *pcbRead) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset)
{
    NTSTATUS nt = VMMDLL_STATUS_FILE_INVALID;
    PVMMOB_MAP_NETDNS pObDnsMap = NULL;
    if(!_stricmp(ctxP->uszPath, "readme.txt")) {
        return Util_VfsReadFile_FromStrA(szMSYSNETDNS_README, pb, cb, pcbRead, cbOffset);
    }
    if((pObDnsMap = VmmNetDns_GetMap(H, ctxP))) {
        if(!_stricmp(ctxP->uszPath, "dns.txt")) {
            nt = Util_VfsLineFixed_Read(
                H, (UTIL_VFSLINEFIXED_PFN_CB)MSysNetDns_ReadLine_CB, pObDnsMap, MSYSNETDNS_LINELENGTH, MSYSNETDNS_LINEHEADER,
                pObDnsMap->pMap, pObDnsMap->cMap, sizeof(VMMOB_MAP_NETDNS),
                pb, cb, pcbRead, cbOffset
            );
            goto finish;
        }
    }
finish:
    Ob_DECREF(pObDnsMap);
    return nt;
}

static BOOL MSysNetDns_List(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_CONTEXT ctxP, _Inout_ PHANDLE pFileList)
{
    PVMMOB_MAP_NETDNS pObDnsMap = NULL;
    if(ctxP->uszPath[0]) { return FALSE; }
    VMMDLL_VfsList_AddFile(pFileList, "readme.txt", strlen(szMSYSNETDNS_README), NULL);
    if((pObDnsMap = VmmNetDns_GetMap(H, ctxP))) {
        VMMDLL_VfsList_AddFile(pFileList, "dns.txt", UTIL_VFSLINEFIXED_LINECOUNT(H, pObDnsMap->cMap) * MSYSNETDNS_LINELENGTH, NULL);
        Ob_DECREF_NULL(&pObDnsMap);
    }
    return TRUE;
}

static VOID MSysNetDns_FcLogCSV(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_CONTEXT ctxP, _In_ VMMDLL_CSV_HANDLE hCSV)
{
    DWORD i;
    PVMM_MAP_NETDNSENTRY pe;
    PVMMOB_MAP_NETDNS pObDnsMap = NULL;
    if((ctxP->dwPID == 4) && (pObDnsMap = VmmNetDns_GetMap(H, ctxP))) {
        FcFileAppend(H, "netdns.csv", MSYSNETDNS_CSV);
        for(i = 0; i < pObDnsMap->cMap; i++) {
            pe = pObDnsMap->pMap + i;
            //"Address,Type,Flags,TTL,Name,Data"
            FcCsv_Reset(hCSV);
            FcFileAppend(H, "netdns.csv", "%llx,%s,0x%x,%u,%s,%s\n",
                pe->va,
                FcCsv_String(hCSV, pe->uszType),
                pe->dwFlags,
                pe->dwTTL,
                FcCsv_String(hCSV, pe->uszName),
                FcCsv_String(hCSV, pe->uszData)
            );
        }
    }
}

static VOID MSysNetDns_FcLogJSON(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_CONTEXT ctxP, _In_ VOID(*pfnLogJSON)(_In_ VMM_HANDLE H, _In_ PVMMDLL_FORENSIC_JSONDATA pData))
{
    PVMMDLL_FORENSIC_JSONDATA pd;
    PVMMOB_MAP_NETDNS pObDnsMap = NULL;
    PVMM_MAP_NETDNSENTRY pe;
    DWORD i;
    CHAR szu[MAX_PATH];
    if(ctxP->pProcess || !(pd = LocalAlloc(LMEM_ZEROINIT, sizeof(VMMDLL_FORENSIC_JSONDATA)))) { return; }
    pd->dwVersion = VMMDLL_FORENSIC_JSONDATA_VERSION;
    pd->szjType = "netdns";
    if((pObDnsMap = VmmNetDns_GetMap(H, ctxP))) {
        for(i = 0; i < pObDnsMap->cMap; i++) {
            pe = pObDnsMap->pMap + i;
            snprintf(szu, _countof(szu), "type:[%s] ttl:[%u] flags:[0x%x] data:[%s]",
                pe->uszType,
                pe->dwTTL,
                pe->dwFlags,
                pe->uszData);
            pd->i = i;
            pd->vaObj = pe->va;
            pd->usz[0] = pe->uszName;
            pd->usz[1] = szu;
            pfnLogJSON(H, pd);
        }
    }
    Ob_DECREF(pObDnsMap);
    LocalFree(pd);
}

static VOID MSysNetDns_Notify(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_CONTEXT ctxP, _In_ DWORD fEvent, _In_opt_ PVOID pvEvent, _In_opt_ DWORD cbEvent)
{
    if(fEvent == VMMDLL_PLUGIN_NOTIFY_REFRESH_SLOW) {
        ObContainer_SetOb((POB_CONTAINER)ctxP->ctxM, NULL);
    }
}

static VOID MSysNetDns_Close(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_CONTEXT ctxP)
{
    Ob_DECREF(ctxP->ctxM);
}

VOID M_SysNetDns_Initialize(_In_ VMM_HANDLE H, _Inout_ PVMMDLL_PLUGIN_REGINFO pRI)
{
    if((pRI->magic != VMMDLL_PLUGIN_REGINFO_MAGIC) || (pRI->wVersion != VMMDLL_PLUGIN_REGINFO_VERSION)) { return; }
    if((pRI->tpSystem != VMMDLL_SYSTEM_WINDOWS_64) && (pRI->tpSystem != VMMDLL_SYSTEM_WINDOWS_32)) { return; }
    strcpy_s(pRI->reg_info.uszPathName, 128, "\\sys\\net\\dns");// Module name
    pRI->reg_info.fRootModule = TRUE;                           // Module shows in root directory
    pRI->reg_info.ctxM = (PVMMDLL_PLUGIN_INTERNAL_CONTEXT)ObContainer_New();
    // functions supported:
    pRI->reg_fn.pfnList = MSysNetDns_List;                      // List function supported
    pRI->reg_fn.pfnRead = MSysNetDns_Read;                      // Read function supported
    pRI->reg_fn.pfnNotify = MSysNetDns_Notify;                  // Notify function supported
    pRI->reg_fn.pfnClose = MSysNetDns_Close;                    // Close function supported
    // csv/json support:
    pRI->reg_fnfc.pfnLogCSV = MSysNetDns_FcLogCSV;
    pRI->reg_fnfc.pfnLogJSON = MSysNetDns_FcLogJSON;
    pRI->pfnPluginManager_Register(H, pRI);
}
