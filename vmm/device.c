// device.c : implementation related to memory acquisition devices.
//
// (c) Ulf Frisk, 2018
// Author: Ulf Frisk, pcileech@frizk.net
//
#include "device.h"
#include "devicefile.h"
#include "devicepcileechdll.h"
#include "statistics.h"
#include "vmm.h"

VOID DeviceReadScatterMEM(_Inout_ PPMEM_IO_SCATTER_HEADER ppDMAs, _In_ DWORD cpDMAs, _Out_opt_ PDWORD pcpDMAsRead)
{
    QWORD tmStart = Statistics_CallStart();
    ctxMain->dev.pfnReadScatterMEM( ppDMAs, cpDMAs, pcpDMAsRead);
    Statistics_CallEnd(STATISTICS_ID_DeviceReadScatterMEM, tmStart);
}

BOOL DeviceWriteMEM(_In_ QWORD qwAddr, _In_ PBYTE pb, _In_ DWORD cb)
{
    BOOL result;
    QWORD tmStart = Statistics_CallStart();
    result = ctxMain->dev.pfnWriteMEM && ctxMain->dev.pfnWriteMEM(qwAddr, pb, cb);
    Statistics_CallEnd(STATISTICS_ID_DeviceWriteMEM, tmStart);
    return result;
}

VOID DeviceClose()
{
    if(ctxMain->dev.pfnClose) {
        ctxMain->dev.pfnClose();
    }
}

/*
* Auto-identifies the maximum address by starting to try to read memory at 4GB
* and then by moving upwards. Reads should be minimized - but if "bad" hardware
* this may still (in very rare occurances) freeze the target computer if DMA
* device is used. Should only be called whenever needed - i.e. when the native
* device does not report a valid value in combination with the absence of user
* defined max address.
*/
QWORD DeviceAutoIdentifyMaxAddress()
{
    DWORD i, cMEM;
    QWORD qwCurrentAddress = 0x100000000, qwChunkSize = 0x100000000;
    MEM_IO_SCATTER_HEADER pMEM[1], *ppMEM[1];
    BYTE pbDummy[0x1000];
    DWORD dwOFFSETS[] = { 0x0, 0x1000, 0x2000, 0x3000, 0x00010000, 0x00100000, 0x01000000, 0x10000000 };
    DWORD cOFFSETS = sizeof(dwOFFSETS) / sizeof(DWORD);
    // 1: set up
    ZeroMemory(pMEM, sizeof(MEM_IO_SCATTER_HEADER));
    pMEM->pb = pbDummy;
    pMEM->cbMax = 0x1000;
    *ppMEM = pMEM;
    // 2: loop until fail on smallest chunk size (0x1000)
    while(TRUE) {
        for(i = 0; i < cOFFSETS; i++) {
            pMEM->cb = 0;
            pMEM->qwA = qwCurrentAddress + qwChunkSize + dwOFFSETS[i];
            DeviceReadScatterMEM(ppMEM, 1, &cMEM);
            if(cMEM) {
                qwCurrentAddress += qwChunkSize;
                break;
            }
        }
        if(cMEM) { continue; }
        if(qwChunkSize == 0x1000) {
            return qwCurrentAddress + ((qwCurrentAddress == 0x100000000) ? 0 : 0xfff);
        }
        qwChunkSize >>= 1; // half chunk size
    }
}

BOOL DeviceOpen()
{
    BOOL result;
    if((0 == _stricmp("fpga", ctxMain->cfg.szDevTpOrFileName)) || (0 == _stricmp("totalmeltdown", ctxMain->cfg.szDevTpOrFileName))) {
        result = DevicePCILeechDll_Open(ctxMain);
    } else {
        result = DeviceFile_Open(ctxMain);
    }
    if(result) {
        if((ctxMain->cfg.paAddrMax == 0x0000ffffffffffff) && (ctxMain->dev.paAddrMaxNative == 0x0000ffffffffffff)) {
            // probe for max address - if needed and not already user supplied
            ctxMain->dev.paAddrMaxNative = DeviceAutoIdentifyMaxAddress(ctxMain);
        }
        ctxMain->cfg.paAddrMax = min(ctxMain->cfg.paAddrMax, ctxMain->dev.paAddrMaxNative);
    }
    return result;
}

BOOL DeviceGetOption(_In_ QWORD fOption, _Out_ PQWORD pqwValue)
{
    return ctxMain->dev.pfnGetOption && ctxMain->dev.pfnGetOption(fOption, pqwValue);
}

BOOL DeviceSetOption(_In_ QWORD fOption, _In_ QWORD qwValue)
{
    return ctxMain->dev.pfnSetOption && ctxMain->dev.pfnSetOption(fOption, qwValue);
}

DWORD DeviceReadMEMEx_DoWork_Scatter(_In_ QWORD qwAddr, _Out_ PBYTE pb, _In_ DWORD cb, _Inout_opt_ PPAGE_STATISTICS pPageStat)
{
    PBYTE pbBuffer;
    PMEM_IO_SCATTER_HEADER pDMAs, *ppDMAs;
    DWORD i, o, cDMAs, cDMAsRead;
    cDMAs = cb >> 12;
    pbBuffer = (PBYTE)LocalAlloc(LMEM_ZEROINIT, cDMAs * (sizeof(PMEM_IO_SCATTER_HEADER) + sizeof(MEM_IO_SCATTER_HEADER)));
    if(!pbBuffer) { return 0; }
    ppDMAs = (PMEM_IO_SCATTER_HEADER*)pbBuffer;
    pDMAs = (PMEM_IO_SCATTER_HEADER)(pbBuffer + cDMAs * sizeof(PMEM_IO_SCATTER_HEADER));
    for(i = 0, o = 0; i < cDMAs; i++, o += 0x1000) {
        ppDMAs[i] = pDMAs + i;
        pDMAs[i].qwA = qwAddr + o;
        pDMAs[i].cbMax = min(0x1000, cb - o);
        pDMAs[i].pb = pb + o;
    }
    DeviceReadScatterMEM(ppDMAs, cDMAs, &cDMAsRead);
    for(i = 0; i < cDMAs; i++) {
        if(pDMAs[i].cb == 0x1000) {
            PageStatUpdate(pPageStat, pDMAs[i].qwA + 0x1000, 1, 0);
        } else {
            PageStatUpdate(pPageStat, pDMAs[i].qwA + 0x1000, 0, 1);
            ZeroMemory(pDMAs[i].pb, 0x1000);
        }
    }
    LocalFree(pbBuffer);
    return cDMAsRead << 12;
}

DWORD DeviceReadMEMEx_DoWork(_In_ QWORD qwAddr, _Out_ PBYTE pb, _In_ DWORD cb, _Inout_opt_ PPAGE_STATISTICS pPageStat, _In_ DWORD cbMaxSizeIo)
{
    DWORD cbRd, cbRdOff;
    DWORD cbChunk, cChunkTotal, cChunkSuccess = 0;
    DWORD i, cbSuccess = 0;
    // calculate current chunk sizes
    cbChunk = ~0xfff & min(cb, cbMaxSizeIo);
    cbChunk = (cbChunk > 0x3000) ? cbChunk : 0x1000;
    cChunkTotal = (cb / cbChunk) + ((cb % cbChunk) ? 1 : 0);
    // try read memory
    memset(pb, 0, cb);
    for(i = 0; i < cChunkTotal; i++) {
        cbRdOff = i * cbChunk;
        cbRd = ((i == cChunkTotal - 1) && (cb % cbChunk)) ? (cb % cbChunk) : cbChunk; // (last chunk may be smaller)
        cbSuccess += DeviceReadMEMEx_DoWork_Scatter(qwAddr + cbRdOff, pb + cbRdOff, cbRd, pPageStat);
    }
    return cbSuccess;
}

DWORD DeviceReadMEMEx(_In_ QWORD qwAddr, _Out_ PBYTE pb, _In_ DWORD cb, _Inout_opt_ PPAGE_STATISTICS pPageStat)
{
    BYTE pbWorkaround[4096];
    DWORD cbDataRead;
    // read memory (with strange workaround for 1-page reads...)
    if(cb != 0x1000) {
        cbDataRead = DeviceReadMEMEx_DoWork(qwAddr, pb, cb, pPageStat, (DWORD)ctxMain->dev.qwMaxSizeMemIo);
    } else {
        // why is this working ??? if not here console is screwed up... (threading issue?)
        cbDataRead = DeviceReadMEMEx_DoWork(qwAddr, pbWorkaround, 0x1000, pPageStat, (DWORD)ctxMain->dev.qwMaxSizeMemIo);
        memcpy(pb, pbWorkaround, 0x1000);
    }
    return cbDataRead;
}
