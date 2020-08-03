// vmmwinnet.h : declarations of functionality related to the Windows networking.
//
// (c) Ulf Frisk, 2019-2020
// Author: Ulf Frisk, pcileech@frizk.net
//

#ifndef __VMMWINNET_H__
#define __VMMWINNET_H__
#include "vmm.h"

typedef struct tdVMMWIN_TCPIP_ENTRY {   // SHARED WITH VMMDLL
    DWORD dwPID;
    DWORD dwState;
    CHAR szState[12];
    struct {    // address family (IPv4/IPv6)
        BOOL fValid;
        WORD wAF;
    } AF;
    struct {
        BOOL fValid;
        WORD wPort;
        BYTE pbA[16];   // ipv4 = 1st 4 bytes, ipv6 = all bytes
    } Src;
    struct {
        BOOL fValid;
        WORD wPort;
        BYTE pbA[16];   // ipv4 = 1st 4 bytes, ipv6 = all bytes
    } Dst;
    QWORD vaTcpE;
    QWORD qwTime;
    QWORD vaEPROCESS;
    // internal usage only below
    union {
        QWORD _Reserved_vaINET_Addr;
        QWORD _Reserved_vaINET_Src;
        BOOL _Reserved_fPidSearch;
    };
    union {
        QWORD _Reserved_vaINET_AF;
        QWORD _Reserved_vaINET_Dst;
    };
} VMMWIN_TCPIP_ENTRY, *PVMMWIN_TCPIP_ENTRY, **PPVMMWIN_TCPIP_ENTRY;

/*
* Retrieve a freshly parsed array of sorted active TCP connections.
* CALLER LocalFree: ppTcpE
* -- ppTcpE = ptr to receive function allocated buffer containing sorted active TCP connections. Caller responsible for LocalFree.
* -- pcTcpE = length of ppTcpE
* -- return
*/
_Success_(return)
BOOL VmmWinTcpIp_TcpE_Get(_Out_ PPVMMWIN_TCPIP_ENTRY ppTcpE, _Out_ PDWORD pcTcpE);

/*
* Create a network connection map and assign to the global context upon success.
* CALLER DECREF: return
* -- return
*/
PVMMOB_MAP_NET VmmWinNet_Initialize();

/*
* Refresh the network connection map.
*/
VOID VmmWinNet_Refresh();

#endif /* __VMMWINNET_H__ */
