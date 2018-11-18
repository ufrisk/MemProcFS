// devicefile.c : implementation related to file backed memory acquisition device.
//
// (c) Ulf Frisk, 2018
// Author: Ulf Frisk, pcileech@frizk.net
//
#include "devicefile.h"
#include "util.h"
#include "vmm.h"

typedef struct tdDEVICE_CONTEXT_FILE {
    FILE *pFile;
    QWORD cbFile;
    LPSTR szFileName;
} DEVICE_CONTEXT_FILE, *PDEVICE_CONTEXT_FILE;

VOID DeviceFile_ReadScatterMEM(_Inout_ PPMEM_IO_SCATTER_HEADER ppMEMs, _In_ DWORD cpMEMs, _Out_opt_ PDWORD pcMEMsRead)
{
    PDEVICE_CONTEXT_FILE ctxFile = (PDEVICE_CONTEXT_FILE)ctxMain->dev.hDevice;
    DWORD i, cbToRead, c = 0;
    PMEM_IO_SCATTER_HEADER pMEM;
    for(i = 0; i < cpMEMs; i++) {
        pMEM = ppMEMs[i];
        if(pMEM->qwA >= ctxFile->cbFile) { continue; }
        cbToRead = (DWORD)min(pMEM->cb, ctxFile->cbFile - pMEM->qwA);
        if(pMEM->qwA != _ftelli64(ctxFile->pFile)) {
            if(_fseeki64(ctxFile->pFile, pMEM->qwA, SEEK_SET)) { continue; }
        }
        pMEM->cb = (DWORD)fread(pMEM->pb, 1, pMEM->cbMax, ctxFile->pFile);
        if(ctxMain->cfg.fVerboseExtraTlp) {
            vmmprintf(
                "devicefile.c!DeviceFile_ReadScatterMEM: READ:\n" \
                "        file='%s'\n" \
                "        offset=%016llx req_len=%08x rsp_len=%08x\n", 
                ctxFile->szFileName, 
                pMEM->qwA, 
                pMEM->cbMax, 
                pMEM->cb
            );
            Util_PrintHexAscii(pMEM->pb, pMEM->cb, 0);
        }
        c += (ppMEMs[i]->cb >= ppMEMs[i]->cbMax) ? 1 : 0;
    }
    if(pcMEMsRead) {
        *pcMEMsRead = c;
    }
}

VOID DeviceFile_Close()
{
    PDEVICE_CONTEXT_FILE ctxFile = (PDEVICE_CONTEXT_FILE)ctxMain->dev.hDevice;
    if(!ctxFile) { return; }
    fclose(ctxFile->pFile);
    LocalFree(ctxFile);
    ctxMain->dev.hDevice = 0;
}

BOOL DeviceFile_Open()
{
    PDEVICE_CONTEXT_FILE ctxFile;
    ctxFile = (PDEVICE_CONTEXT_FILE)LocalAlloc(LMEM_ZEROINIT, sizeof(DEVICE_CONTEXT_FILE));
    if(!ctxFile) { return FALSE; }
    // open backing file
    if(fopen_s(&ctxFile->pFile, ctxMain->cfg.szDevTpOrFileName, "rb") || !ctxFile->pFile) { goto fail; }
    if(_fseeki64(ctxFile->pFile, 0, SEEK_END)) { goto fail; }       // seek to end of file
    ctxFile->cbFile = _ftelli64(ctxFile->pFile);                    // get current file pointer
    if(ctxFile->cbFile < 0x1000) { goto fail; }
    ctxFile->szFileName = ctxMain->cfg.szDevTpOrFileName;
    ctxMain->dev.hDevice = (HANDLE)ctxFile;
    // set callback functions and fix up config
    ctxMain->dev.tp = VMM_DEVICE_FILE;
    ctxMain->dev.qwMaxSizeMemIo = 0x00100000;          // 1MB
    ctxMain->dev.paAddrMaxNative = ctxFile->cbFile;
    ctxMain->dev.pfnClose = DeviceFile_Close;
    ctxMain->dev.pfnReadScatterMEM = DeviceFile_ReadScatterMEM;
    vmmprintfv("DEVICE: Successfully opened file: '%s'.\n", ctxMain->cfg.szDevTpOrFileName);
    return TRUE;
fail:
    if(ctxFile->pFile) { fclose(ctxFile->pFile); }
    LocalFree(ctxFile);
    printf("DEVICE: ERROR: Failed opening file: '%s'.\n", ctxMain->cfg.szDevTpOrFileName);
    return FALSE;
}
