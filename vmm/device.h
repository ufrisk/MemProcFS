// device.h : definitions related to memory acquisition devices.
//
// (c) Ulf Frisk, 2018
// Author: Ulf Frisk, pcileech@frizk.net
//
#ifndef __DEVICE_H__
#define __DEVICE_H__
#include "vmm.h"
#include "statistics.h"

/*
* Open a connection to the target device.
* -- result
*/
BOOL DeviceOpen();

/*
* Clean up various device related stuff and deallocate memory buffers.
*/
VOID DeviceClose();

/*
* Read memory in various non-contigious locations specified by the items in the
* phDMAs array. Result for each unit of work will be given individually. No upper
* limit of number of items to read, but no performance boost will be given if
* above hardware limit. Max size of each unit of work is one 4k page (4096 bytes).
* -- ppMEMs = array of scatter read headers.
* -- cpMEMs = count of ppDMAs.
* -- pcpMEMsRead = optional count of number of successfully read ppMEMs.
*/
VOID DeviceReadScatterMEM(_Inout_ PPMEM_IO_SCATTER_HEADER ppMEMs, _In_ DWORD cpMEMs, _Out_opt_ PDWORD pcpMEMsRead);

/*
* Try read memory in a fairly optimal way considering device limits. The number
* of total successfully read bytes is returned. Failed reads will be zeroed out
* in the returned memory.
* -- qwAddr
* -- pb
* -- cb
* -- pPageStat = optional page statistics
* -- return = the number of bytes successfully read.
*/
DWORD DeviceReadMEMEx(_In_ QWORD qwAddr, _Out_ PBYTE pb, _In_ DWORD cb, _Inout_opt_ PPAGE_STATISTICS pPageStat);

/*
* Write data to the target system using DMA.
* -- qwAddr
* -- pb
* -- cb
* -- return
*/
BOOL DeviceWriteMEM(_In_ QWORD qwAddr, _In_ PBYTE pb, _In_ DWORD cb);

/*
* Set a device specific option value. Please see individual device header files
* for a list of the possible device specific options.
* -- fOption
* -- pqwValue = pointer to QWORD to receive option value.
* -- return
*/
BOOL DeviceGetOption(_In_ QWORD fOption, _Out_ PQWORD pqwValue);

/*
* Set a device specific option value. Please see individual device header files
* for a list of the possible device specific options.
* -- fOption
* -- qwValue
* -- return
*/
BOOL DeviceSetOption(_In_ QWORD fOption, _In_ QWORD qwValue);

#endif /* __DEVICE_H__ */
