#include <Windows.h>
#include <vmmdll.h>
#include "vfs.h"

//-----------------------------------------------------------------------------
// UTILITY FUNCTIONS BELOW:
//-----------------------------------------------------------------------------

VOID Util_SplitPathFile(_Out_writes_(MAX_PATH) PWCHAR wszPath, _Out_ LPWSTR *pwcsFile, _In_ LPCWSTR wcsFileName)
{
    DWORD i, iSplitFilePath = 0;
    wcsncpy_s(wszPath, MAX_PATH, wcsFileName, _TRUNCATE);
    for(i = 0; i < MAX_PATH; i++) {
        if(wszPath[i] == '\\') {
            iSplitFilePath = i;
        }
        if(wszPath[i] == 0) {
            break;
        }
    }
    wszPath[iSplitFilePath] = 0;
    *pwcsFile = wszPath + iSplitFilePath + 1;
}

LPWSTR Util_PathSplit2_ExWCHAR(_In_ LPWSTR wsz, _Out_writes_(cwsz1) LPWSTR wsz1, _In_ DWORD cwsz1)
{
    WCHAR wch;
    DWORD i = 0;
    while((wch = wsz[i]) && (wch != '\\') && (i < cwsz1 - 1)) {
        wsz1[i++] = wch;
    }
    wsz1[i] = 0;
    return wsz[i] ? &wsz[i + 1] : L"";
}

/*
* Hash a string in uppercase.
* -- wsz
* -- return
*/
DWORD Util_HashStringUpperW(_In_opt_ LPWSTR wsz)
{
    WCHAR c;
    DWORD i = 0, dwHash = 0;
    if(!wsz) { return 0; }
    while(TRUE) {
        c = wsz[i++];
        if(!c) { return dwHash; }
        if(c >= 'a' && c <= 'z') {
            c += 'A' - 'a';
        }
        dwHash = ((dwHash >> 13) | (dwHash << 19)) + c;
    }
}

/*
* Hash a path in uppercase.
* -- wszPath
* -- return
*/
QWORD Util_HashPathW(_In_ LPWSTR wszPath)
{
    DWORD dwHashName;
    QWORD qwHashTotal = 0;
    WCHAR wsz1[MAX_PATH];
    while(wszPath && wszPath[0]) {
        wszPath = Util_PathSplit2_ExWCHAR(wszPath, wsz1, _countof(wsz1));
        dwHashName = Util_HashStringUpperW(wsz1);
        qwHashTotal = dwHashName + ((qwHashTotal >> 13) | (qwHashTotal << 51));
    }
    return qwHashTotal;
}

/*
* Convert UTF-8 string into a Windows Wide-Char string.
* Function support usz == pbBuffer - usz will then become overwritten.
* CALLER LOCALFREE (if *pusz != pbBuffer): *pusz
* -- usz = the string to convert.
* -- cch = -1 for null-terminated string; or max number of chars (excl. null).
* -- pbBuffer = optional buffer to place the result in.
* -- cbBuffer
* -- pusz = if set to null: function calculate length only and return TRUE.
            result wide-string, either as (*pwsz == pbBuffer) or LocalAlloc'ed
*           buffer that caller is responsible for free.
* -- pcbu = byte length (including terminating null) of wide-char string.
* -- flags = CHARUTIL_FLAG_NONE, CHARUTIL_FLAG_ALLOC or CHARUTIL_FLAG_TRUNCATE
* -- return
*/
_Success_(return)
BOOL CharUtil_UtoW(_In_opt_ LPSTR usz, _In_ DWORD cch, _Maybenull_ _Writable_bytes_(cbBuffer) PBYTE pbBuffer, _In_ DWORD cbBuffer, _Out_opt_ LPWSTR *pwsz, _Out_opt_ PDWORD pcbw, _In_ DWORD flags)
{
    UCHAR c;
    LPWSTR wsz;
    DWORD i, j, n, cbu = 0, cbw = 0, ch;
    BOOL fTruncate = flags & CHARUTIL_FLAG_TRUNCATE;
    if(pcbw) { *pcbw = 0; }
    if(pwsz) { *pwsz = NULL; }
    if(!usz) { usz = ""; }
    if(cch > CHARUTIL_CONVERT_MAXSIZE) { cch = CHARUTIL_CONVERT_MAXSIZE; }
    // 1: utf-8 byte-length:
    cbBuffer = cbBuffer & ~1;       // multiple of 2-byte sizeof(WCHAR)
    if(fTruncate && (!cbBuffer || (flags & CHARUTIL_FLAG_ALLOC))) { goto fail; }
    while((c = usz[cbu]) && (cbu < cch)) {
        if(c & 0x80) {
            // utf-8 char:
            n = 0;
            if((c & 0xe0) == 0xc0) { n = 2; }
            if((c & 0xf0) == 0xe0) { n = 3; }
            if((c & 0xf8) == 0xf0) { n = 4; }
            if(!n || (cbu + n > cch)) { break; }
            if(fTruncate && (cbw + ((n == 4) ? 4 : 2) >= cbBuffer)) { break; }
            if((n > 1) && ((usz[cbu + 1] & 0xc0) != 0x80)) { goto fail; }   // invalid char-encoding
            if((n > 2) && ((usz[cbu + 2] & 0xc0) != 0x80)) { goto fail; }   // invalid char-encoding
            if((n > 3) && ((usz[cbu + 3] & 0xc0) != 0x80)) { goto fail; }   // invalid char-encoding
            cbw += (n == 4) ? 4 : 2;
            cbu += n;
        } else {
            if(fTruncate && (cbw + 2 >= cbBuffer)) { break; }
            cbw += 2;
            cbu += 1;
        }
    }
    cbu += 1;
    cbw += 2;
    if(pcbw) { *pcbw = cbw; }
    // 2: return on length-request or alloc-fail
    if(!pwsz) {
        if(!(flags & CHARUTIL_FLAG_STR_BUFONLY)) { return TRUE; }   // success: length request
        if(flags & CHARUTIL_FLAG_ALLOC) { return FALSE; }
    }
    if(!(flags & CHARUTIL_FLAG_ALLOC) && (!pbBuffer || (cbBuffer < cbw))) { goto fail; } // fail: insufficient buffer space
    wsz = (pbBuffer && (cbBuffer >= cbw)) ? pbBuffer : LocalAlloc(0, cbw);
    if(!wsz) { goto fail; }                                                 // fail: failed buffer space allocation
    // 3: Populate with wchar string. NB! algorithm works only on correctly
    //    formed UTF-8 - which has been verified in the count-step.
    i = cbu - 2; j = (cbw >> 1) - 1;
    wsz[j--] = 0;
    while(i < 0x7fffffff) {
        if(((c = usz[i--]) & 0xc0) == 0x80) {
            // 2-3-4 byte utf-8
            ch = c & 0x3f;
            if(((c = usz[i--]) & 0xc0) == 0x80) {
                // 3-4 byte utf-8
                ch += (c & 0x3f) << 6;
                if(((c = usz[i--]) & 0xc0) == 0x80) {
                    ch += (c & 0x3f) << 12;     // 4-byte utf-8
                    c = usz[i--];
                    ch += (c & 0x07) << 18;
                } else {
                    ch += (c & 0x0f) << 12;     // 3-byte utf-8
                }
            } else {
                ch += (c & 0x1f) << 6;          // 2-byte utf-8
            }
            if(ch >= 0x10000) {
                // surrogate pair:
                ch -= 0x10000;
                wsz[j--] = (ch & 0x3ff) + 0xdc00;
                wsz[j--] = (USHORT)((ch >> 10) + 0xd800);
            } else {
                wsz[j--] = (USHORT)ch;
            }
        } else {
            wsz[j--] = c;
        }
    }
    if(pwsz) { *pwsz = wsz; }
    return TRUE;
fail:
    if(!(flags ^ CHARUTIL_FLAG_TRUNCATE_ONFAIL_NULLSTR) && pbBuffer && (cbBuffer > 1)) {
        if(pwsz) { *pwsz = (LPWSTR)pbBuffer; }
        if(pcbw) { *pcbw = 2; }
        pbBuffer[0] = 0;
    }
    return FALSE;
}

_Success_(return)
BOOL CharUtil_WtoU(_In_opt_ LPWSTR wsz, _In_ DWORD cch, _Maybenull_ _Writable_bytes_(cbBuffer) PBYTE pbBuffer, _In_ DWORD cbBuffer, _Out_opt_ LPSTR *pusz, _Out_opt_ PDWORD pcbu, _In_ DWORD flags)
{
    USHORT c, cZERO = 0;
    LPSTR usz;
    PUSHORT pus;
    DWORD i, j, cbw = 0, cbu = 0, chSur;
    if(pcbu) { *pcbu = 0; }
    if(pusz) { *pusz = NULL; }
    pus = wsz ? (PUSHORT)wsz : &cZERO;
    if(cch > CHARUTIL_CONVERT_MAXSIZE) { cch = CHARUTIL_CONVERT_MAXSIZE; }
    // 1: ansi byte-length and if ansi-only
    if((flags & CHARUTIL_FLAG_TRUNCATE)) {
        if(!cbBuffer || (flags & CHARUTIL_FLAG_ALLOC)) { goto fail; }
        while((cbw < cch) && (c = pus[cbw])) {
            if(c > 0x7ff) {
                if(c >= 0xD800 && c <= 0xDFFF) {
                    // surrogate pair
                    if(cbw + cbu + 1 + 2 + 1 >= cbBuffer) { break; }
                    if(cbw + 1 >= cch) { break; }    // end of string
                    if(pus[cbw + 1] < 0xD800 || pus[cbw + 1] > 0xDFFF) { goto fail; }    // fail: invalid code point
                    cbu += 2;
                    cbw++;
                } else {
                    if(cbw + cbu + 1 + 2 >= cbBuffer) { break; }
                    cbu += 2;
                }
            } else if(c > 0x7f) {
                if(cbw + cbu + 1 + 1 >= cbBuffer) { break; }
                cbu++;
            } else {
                if(cbw + cbu + 1 >= cbBuffer) { break; }
            }
            cbw++;
        }
    } else {
        while((cbw < cch) && (c = pus[cbw])) {
            if(c > 0x7ff) {
                if(c >= 0xD800 && c <= 0xDFFF) {
                    // surrogate pair
                    if(cbw + 1 >= cch) { break; }    // end of string
                    if(pus[cbw + 1] < 0xD800 || pus[cbw + 1] > 0xDFFF) { goto fail; }    // fail: invalid code point
                    cbu += 2;
                    cbw++;
                } else {
                    cbu += 2;
                }
            } else if(c > 0x7f) {
                cbu++;
            }
            cbw++;
        }
    }
    cbw++;
    cbu += cbw;
    if(pcbu) { *pcbu = cbu; }
    // 2: return on length-request or alloc-fail
    if(!pusz) {
        if(!(flags & CHARUTIL_FLAG_STR_BUFONLY)) { return TRUE; }   // success: length request
        if(flags & CHARUTIL_FLAG_ALLOC) { return FALSE; }
    }
    if(!(flags & CHARUTIL_FLAG_ALLOC) && (!pbBuffer || (cbBuffer < cbu))) { goto fail; } // fail: insufficient buffer space
    usz = (pbBuffer && (cbBuffer >= cbu)) ? pbBuffer : LocalAlloc(0, cbu);
    if(!usz) { goto fail; }                                              // fail: failed buffer space allocation
    // 3: populate with utf-8 string
    i = cbw - 2; j = cbu - 2;
    while(i < 0x7fffffff) {
        c = pus[i--];
        if(c > 0x7ff) {
            if(c >= 0xD800 && c <= 0xDFFF) {
                // surrogate pair (previously validated in step 1)
                chSur = 0x10000 + (((pus[i--] - 0xD800) << 10) | ((c - 0xDC00) & 0x3ff));
                usz[j--] = 0x80 | (chSur & 0x3f);
                usz[j--] = 0x80 | ((chSur >> 6) & 0x3f);
                usz[j--] = 0x80 | ((chSur >> 12) & 0x3f);
                usz[j--] = 0xf0 | ((chSur >> 18) & 0x0f);
            } else {
                usz[j--] = 0x80 | (c & 0x3f);
                usz[j--] = 0x80 | ((c >> 6) & 0x3f);
                usz[j--] = 0xe0 | ((c >> 12) & 0x1f);
            }
        } else if(c > 0x7f) {
            usz[j--] = 0x80 | (c & 0x3f);
            usz[j--] = 0xc0 | ((c >> 6) & 0x3f);
        } else {
            usz[j--] = (CHAR)c;
        }
    }
    usz[cbu - 1] = 0;
    if(pusz) { *pusz = usz; }
    return TRUE;
fail:
    if(!(flags ^ CHARUTIL_FLAG_TRUNCATE_ONFAIL_NULLSTR) && pbBuffer && cbBuffer) {
        if(pusz) { *pusz = (LPSTR)pbBuffer; }
        if(pcbu) { *pcbu = 1; }
        pbBuffer[0] = 0;
    }
    return FALSE;
}



//-----------------------------------------------------------------------------
// WRAPPER FUNCTIONS BELOW:
//-----------------------------------------------------------------------------

/*
* WRAPPER FUNCTION AROUND LOCAL/REMOTE VMMDLL_VfsListW
* List a directory of files in MemProcFS. Directories and files will be listed
* by callbacks into functions supplied in the pFileList parameter.
* If information of an individual file is needed it's neccessary to list all
* files in its directory.
* -- wszPath
* -- pFileList
* -- return
*/
_Success_(return) BOOL MemProcFS_VfsListW(_In_ LPWSTR wszPath, _Inout_ PVMMDLL_VFS_FILELIST2 pFileList)
{
    DWORD i;
    LC_CMD_AGENT_VFS_REQ Req;
    PLC_CMD_AGENT_VFS_RSP pRsp = NULL;
    PVMMDLL_VFS_FILELISTBLOB pVfsList;
    PVMMDLL_VFS_FILELISTBLOB_ENTRY pe;
    if(!g_hLC_RemoteFS) {
        return VMMDLL_VfsListW(wszPath, pFileList);
    }
    ZeroMemory(&Req, sizeof(LC_CMD_AGENT_VFS_REQ));
    Req.dwVersion = LC_CMD_AGENT_VFS_REQ_VERSION;
    if(!CharUtil_WtoU(wszPath, -1, Req.uszPathFile, sizeof(Req.uszPathFile), NULL, NULL, CHARUTIL_FLAG_STR_BUFONLY)) { goto fail; }
    if(!LcCommand(g_hLC_RemoteFS, LC_CMD_AGENT_VFS_LIST, sizeof(LC_CMD_AGENT_VFS_REQ), (PBYTE)&Req, (PBYTE *)&pRsp, NULL) || !pRsp) { goto fail; }
    pVfsList = (PVMMDLL_VFS_FILELISTBLOB)pRsp->pb;      // sanity/security checks on remote deta done in leechcore
    pVfsList->uszMultiText = (LPSTR)pVfsList + (QWORD)pVfsList->uszMultiText;
    for(i = 0; i < pVfsList->cFileEntry; i++) {
        pe = pVfsList->FileEntry + i;
        if(pe->cbFileSize == (QWORD)-1) {
            pFileList->pfnAddDirectory(pFileList->h, pVfsList->uszMultiText + pe->ouszName, (PVMMDLL_VFS_FILELIST_EXINFO)&pe->ExInfo);
        } else {
            pFileList->pfnAddFile(pFileList->h, pVfsList->uszMultiText + pe->ouszName, pe->cbFileSize, (PVMMDLL_VFS_FILELIST_EXINFO)&pe->ExInfo);
        }
    }
fail:
    LocalFree(pRsp);
    return TRUE;
}

/*
* WRAPPER FUNCTION AROUND LOCAL/REMOTE VMMDLL_VfsReadW
* Read select parts of a file in MemProcFS.
* -- wszFileName
* -- pb
* -- cb
* -- pcbRead
* -- cbOffset
* -- return
*/
NTSTATUS MemProcFS_VfsReadW(_In_ LPWSTR wszFileName, _Out_writes_to_(cb, *pcbRead) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ ULONG64 cbOffset)
{
    NTSTATUS nt = VMMDLL_STATUS_FILE_INVALID;
    LC_CMD_AGENT_VFS_REQ Req;
    PLC_CMD_AGENT_VFS_RSP pRsp = NULL;
    if(!g_hLC_RemoteFS) {
        return VMMDLL_VfsReadW(wszFileName, pb, cb, pcbRead, cbOffset);
    }
    // Remote MemProcFS below:
    ZeroMemory(&Req, sizeof(LC_CMD_AGENT_VFS_REQ));
    Req.dwVersion = LC_CMD_AGENT_VFS_REQ_VERSION;
    Req.qwOffset = cbOffset;
    Req.dwLength = cb;
    if(!CharUtil_WtoU(wszFileName, -1, Req.uszPathFile, sizeof(Req.uszPathFile), NULL, NULL, CHARUTIL_FLAG_STR_BUFONLY)) { goto fail; }
    if(!LcCommand(g_hLC_RemoteFS, LC_CMD_AGENT_VFS_READ, sizeof(LC_CMD_AGENT_VFS_REQ), (PBYTE)&Req, (PBYTE *)&pRsp, NULL) || !pRsp) { goto fail; }
    nt = pRsp->dwStatus;
    *pcbRead = min(cb, pRsp->cb);
    memcpy(pb, pRsp->pb, *pcbRead);
fail:
    LocalFree(pRsp);
    return nt;
}

/*
* WRAPPER FUNCTION AROUND LOCAL/REMOTE VMMDLL_VfsWriteW
* Write select parts to a file in MemProcFS.
* -- wszFileName
* -- pb
* -- cb
* -- pcbWrite
* -- cbOffset
* -- return
*/
NTSTATUS MemProcFS_VfsWriteW(_In_ LPWSTR wszFileName, _In_reads_(cb) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbWrite, _In_ ULONG64 cbOffset)
{
    NTSTATUS nt = VMMDLL_STATUS_FILE_INVALID;
    PLC_CMD_AGENT_VFS_REQ pReq = NULL;
    PLC_CMD_AGENT_VFS_RSP pRsp = NULL;
    if(!g_hLC_RemoteFS) {
        return VMMDLL_VfsWriteW(wszFileName, pb, cb, pcbWrite, cbOffset);
    }
    // Remote MemProcFS below:
    *pcbWrite = 0;
    if(!(pReq = LocalAlloc(0, sizeof(LC_CMD_AGENT_VFS_REQ) + cb))) { goto fail; }
    ZeroMemory(pReq, sizeof(LC_CMD_AGENT_VFS_REQ));
    pReq->dwVersion = LC_CMD_AGENT_VFS_REQ_VERSION;
    pReq->qwOffset = cbOffset;
    pReq->dwLength = cb;
    pReq->cb = cb;
    memcpy(pReq->pb, pb, cb);
    if(!CharUtil_WtoU(wszFileName, -1, pReq->uszPathFile, sizeof(pReq->uszPathFile), NULL, NULL, CHARUTIL_FLAG_STR_BUFONLY)) { goto fail; }
    if(!LcCommand(g_hLC_RemoteFS, LC_CMD_AGENT_VFS_WRITE, sizeof(LC_CMD_AGENT_VFS_REQ) + cb, (PBYTE)pReq, (PBYTE *)&pRsp, NULL) || !pRsp) { goto fail; }
    nt = pRsp->dwStatus;
    *pcbWrite = min(cb, pRsp->cbReadWrite);
fail:
    LocalFree(pReq);
    LocalFree(pRsp);
    return nt;
}

/*
* WRAPPER FUNCTION AROUND LOCAL/REMOTE VMMDLL_ConfigGet
* Set a device specific option value. Please see defines VMMDLL_OPT_* for infor-
* mation about valid option values. Please note that option values may overlap
* between different device types with different meanings.
* -- fOption
* -- pqwValue = pointer to ULONG64 to receive option value.
* -- return = success/fail.
*/
_Success_(return)
BOOL MemProcFS_ConfigGet(_In_ ULONG64 fOption, _Out_ PULONG64 pqwValue)
{
    BOOL fResult;
    LC_CMD_AGENT_VFS_REQ Req = { 0 };
    PLC_CMD_AGENT_VFS_RSP pRsp = NULL;
    *pqwValue = 0;
    if(!g_hLC_RemoteFS) {
        return VMMDLL_ConfigGet(fOption, pqwValue);
    }
    // Remote MemProcFS below:
    Req.dwVersion = LC_CMD_AGENT_VFS_REQ_VERSION;
    Req.fOption = fOption;
    fResult = LcCommand(g_hLC_RemoteFS, LC_CMD_AGENT_VFS_OPT_GET, sizeof(LC_CMD_AGENT_VFS_REQ), (PBYTE)&Req, (PBYTE*)&pRsp, NULL);
    if(!fResult) { return FALSE; }
    if((fResult = (pRsp->cb == sizeof(QWORD)))) {
        *pqwValue = *(PQWORD)pRsp->pb;
    }
    LocalFree(pRsp);
    return fResult;
}

/*
* WRAPPER FUNCTION AROUND LOCAL/REMOTE VMMDLL_ConfigSet
* Set a device specific option value. Please see defines VMMDLL_OPT_* for infor-
* mation about valid option values. Please note that option values may overlap
* between different device types with different meanings.
* -- fOption
* -- qwValue
* -- return = success/fail.
*/
_Success_(return)
BOOL MemProcFS_ConfigSet(_In_ ULONG64 fOption, _In_ ULONG64 qwValue)
{
    BOOL fResult;
    PLC_CMD_AGENT_VFS_REQ pReq = NULL;
    if(!g_hLC_RemoteFS) {
        return VMMDLL_ConfigSet(fOption, qwValue);
    }
    // Remote MemProcFS below:
    if(!(pReq = LocalAlloc(LMEM_ZEROINIT, sizeof(LC_CMD_AGENT_VFS_REQ) + sizeof(QWORD)))) { return FALSE; }
    pReq->dwVersion = LC_CMD_AGENT_VFS_REQ_VERSION;
    pReq->fOption = fOption;
    pReq->cb = sizeof(QWORD);
    *(PQWORD)pReq->pb = 1ULL;
    fResult = LcCommand(g_hLC_RemoteFS, LC_CMD_AGENT_VFS_OPT_SET, sizeof(LC_CMD_AGENT_VFS_REQ) + sizeof(QWORD), (PBYTE)pReq, NULL, NULL);
    LocalFree(pReq);
    return fResult;
}
