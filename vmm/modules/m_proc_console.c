// m_proc_console.c : implementation of the console info built-in module.
//
// (c) Ulf Frisk, 2024-2025
// Author: Ulf Frisk, pcileech@frizk.net
//

#include "modules.h"
#include "../version.h"
#include "../vmmwinobj.h"
#include "../vmmwinreg.h"
#include "../charutil.h"

typedef struct tdOB_MCON_CONTEXT {
    OB ObHdr;
    BOOL fValid;
    DWORD cbText;       // Length in bytes of uszText (excl. NULL).
    LPSTR uszText;      // The console text.
} OB_MCON_CONTEXT, *POB_MCON_CONTEXT;

#define MCON_MAX_HEAP_ENTRIES 512

#define MCON_SCREEN_MAX_CHARS 0x00400000    // 4M
#define MCON_INIT_BUFFER_SIZE 0x00800000    // 8M

typedef struct tdMCON_INIT_CONTEXT {
    BOOL f32;
    BOOL fSuccess;
    DWORD dwBuild;
    VMM_MODULE_ID MID;
    PVMM_PROCESS pProcess;
    QWORD vaAllocation;
    DWORD cbAllocation;
    DWORD cbAllocationInitialOffset;
    DWORD cchBufferText;
    BYTE pbAllocation[MCON_INIT_BUFFER_SIZE];
    union {
        WCHAR wszBufferText[MCON_SCREEN_MAX_CHARS];
        BYTE pbBufferText[MCON_INIT_BUFFER_SIZE * 3];
    };
} MCON_INIT_CONTEXT, *PMCON_INIT_CONTEXT;

/*
* "Compact" a wide-char null-terminated buffer by removing all trailing spaces
* and excessive newlines (more than 3 newlines in a row + newlines at the end).
* -- wsz: The wide-char buffer to compress.
* -- return: the number of chars in the wise-char buffer (excl. NULL).
*/
DWORD MCON_Init_CompactConsoleBuffer(_Inout_ LPWSTR wsz)
{
    WCHAR ch;
    BOOL fSkipToNewLine = FALSE;
    DWORD iDst = 0, iSrc = 0, iNoSpace = 0;
    while(TRUE) {
        ch = wsz[iSrc++];
        if(0xff == ch) { ch = 0x20; }
        if(0xff == (ch >> 8)) { fSkipToNewLine = TRUE; }
        if(fSkipToNewLine && (ch != 0x0A) && (ch != 0)) { continue; }
        wsz[iDst] = ch;
        if(ch == 0) {
            while(iDst && wsz[iDst - 1] == 0x0A) { iDst--; }
            wsz[iDst] = 0;
            return iDst ? iDst - 1 : 0;
        }
        if((ch != 0x20) && (ch != 0x0A)) {
            iNoSpace = iDst;
        }
        if(ch == 0x0A) {
            iDst = iNoSpace + 1;
            if((iDst >= 3) && (wsz[iDst - 1] == 0x0A) && (wsz[iDst - 2] == 0x0A) && (wsz[iDst - 3] == 0x0A)) {
                iDst--;
            }
            wsz[iDst] = ch;
            iNoSpace = iDst;
            fSkipToNewLine = FALSE;
        }
        iDst++;
    }
}



// ----------------------------------------------------------------------------
// WINDOWS 11 26100+ CONSOLE PARSING:
// ---
// Windows 22 26100 (24H2) stores the console buffer in a single allocation.
// The buffer is stored as an array of row records. Each row record contains
// the text to be recovered inline. The record length may vary, but fuzzing
// of the record length is possible since the header format is known.
// ----------------------------------------------------------------------------

typedef struct tdMCON_WIN11_26100_ROW_RECORD_HEAD {
    QWORD vaText0;
    QWORD qwZero;
    QWORD vaText;
    QWORD qwUnk1;
    QWORD vaTextEnd;
    QWORD qwUnk2;
    QWORD vaUnk;
    QWORD qwUnk3[6];
    WORD wUnk1;
    WORD wContinueNext;
    DWORD dwUnk1;
} MCON_WIN11_26100_ROW_RECORD_HEAD, *PMCON_WIN11_26100_ROW_RECORD_HEAD;

_Success_(return)
BOOL MCON_Initialize_Win11_26100_ValidateRecord(_In_ PMCON_WIN11_26100_ROW_RECORD_HEAD pR, _In_ QWORD vaR, _In_ DWORD cbR)
{
    if(!VMM_UADDR64_8(pR->vaText) || !VMM_UADDR64_8(pR->vaText0) || !VMM_UADDR64_8(pR->vaTextEnd) || !VMM_UADDR64_8(pR->vaUnk) || (pR->qwZero != 0)) { return FALSE; }
    if((pR->vaText < vaR) || (pR->vaTextEnd < pR->vaText) || (pR->vaTextEnd >= vaR + cbR)) { return FALSE; }
    return TRUE;
}

/*
* Parse a Windows 11 26100/24H2 console window:
* In Win11 24H2 the console screen exists as an array of row records.
* But it's possible to fuzz it from the record header.
*/
VOID MCON_Initialize_Win11_26100(_In_ VMM_HANDLE H, _Inout_ PMCON_INIT_CONTEXT ctx)
{
    PBYTE pbRecordArray;
    QWORD vaRecordArray, vaR;
    DWORD cbR, iR, cR, cbText, cbTextTotal;
    PMCON_WIN11_26100_ROW_RECORD_HEAD pR;
    // set initial data:
    if((ctx->cbAllocation < 0x1000) || (ctx->cbAllocation >= MCON_INIT_BUFFER_SIZE)) { return; }
    VmmRead2(H, ctx->pProcess, ctx->vaAllocation, ctx->pbAllocation, ctx->cbAllocation, VMM_FLAG_ZEROPAD_ON_FAIL);
    pbRecordArray = ctx->pbAllocation;
    vaRecordArray = ctx->vaAllocation;
    // test initial record validity & fuzz record length:
    cbR = 0x1000;
    vaR = vaRecordArray;
    pR = (PMCON_WIN11_26100_ROW_RECORD_HEAD)pbRecordArray;
    if(!MCON_Initialize_Win11_26100_ValidateRecord(pR, vaR, cbR)) { return; }
    cbR = 0x100;
    while(TRUE) {
        vaR = vaRecordArray + cbR;
        pR = (PMCON_WIN11_26100_ROW_RECORD_HEAD)(pbRecordArray + cbR);
        if(MCON_Initialize_Win11_26100_ValidateRecord(pR, vaR, cbR)) {
            break;
        }
        if(cbR == 0xff0) { return; }
        cbR += 0x10;
    }
    cR = ctx->cbAllocation / cbR;
    // iterate over records:
    cbTextTotal = 0;
    for(iR = 0; iR < cR; iR++) {
        vaR = vaRecordArray + iR * cbR;
        pR = (PMCON_WIN11_26100_ROW_RECORD_HEAD)(pbRecordArray + iR * cbR);
        if(!MCON_Initialize_Win11_26100_ValidateRecord(pR, vaR, cbR)) { break; }
        cbText = (DWORD)(pR->vaTextEnd - pR->vaText);
        if(cbText > 0x1000) { break; }
        if(cbText) {
            memcpy(ctx->pbBufferText + cbTextTotal, (PBYTE)pR + (pR->vaText - vaR), cbText);
        }
        cbTextTotal += cbText;
        if(pR->wContinueNext) {
            // line continuations may be space-padded, assume spaces should be removed.
            while((cbTextTotal > 2) && (ctx->pbBufferText[cbTextTotal - 2] == 0x20) && (ctx->pbBufferText[cbTextTotal - 1] == 0x00)) { cbTextTotal -= 2; }
        } else {
            // add newline:
            ctx->pbBufferText[cbTextTotal++] = 0x0A;
            ctx->pbBufferText[cbTextTotal++] = 0x00;
        }
        if(cbTextTotal >= (MCON_SCREEN_MAX_CHARS / 2) - 0x2000) { break; }
    }
    ctx->pbBufferText[cbTextTotal++] = 0x00;
    ctx->pbBufferText[cbTextTotal++] = 0x00;
    ctx->cchBufferText = cbTextTotal >> 1;
}



// ----------------------------------------------------------------------------
// WINDOWS 10 17763 --> WINDOWS 11 22631 CONSOLE PARSING:
// ---
// The formats differ slightly, the Windows 11 format relies on a single
// allocation which may or may not have data in-line in the record. The
// Windows 10 format relies on a pointer array with external text, but
// the record format is similar so we can use the same parsing function.
// ----------------------------------------------------------------------------

typedef struct tdMCON_OFFSETS {
    WORD cb;
    WORD cbHeader;
    WORD oPartialLine;
    WORD oCountText;
    WORD oPtrSelf;
    WORD oPtrText;
    WORD oPtrScreenInfo;
} MCON_OFFSETS, *PMCON_OFFSETS;

/*
* Parse a Windows 10 / 11 console window built upon the 3-char wchar format.
* In Windows 11 everything is by default stored in one big buffer, but text
* references may be external as well.
* In Windows 10 things are stored in individual allocations with external
* text, but callers of this function should have prepared the buffer to
* contain records (array-wise) in the Windows 11 format.
*/
VOID MCON_Initialize_Win1011_RowRecordParse(_In_ VMM_HANDLE H, _In_ PMCON_OFFSETS off, _Inout_ PMCON_INIT_CONTEXT ctx)
{
    WCHAR ch;
    BOOL f32 = ctx->f32;
    BOOL f, fPartialLine = FALSE, fExternalText = FALSE;
    DWORD i, j, cb, cbo = 0, iRowRecord;
    QWORD va, vaCurrent, vaSelf, vaRowText, vaScreenInfo, vaScreenInfoThis;
    PBYTE pb, pbRowText;
    DWORD cchRowText, cchTextTotal = 0, cRowRecords = 0;
    PVMMOB_SCATTER hObScatter = NULL;
    // set initial data:
    va = ctx->vaAllocation;
    cb = ctx->cbAllocation;
    pb = ctx->pbAllocation;
    cbo = ctx->cbAllocationInitialOffset;
    ctx->cchBufferText = 0;
    // test record validity by verifying ptr to "screen info" main object.
    vaScreenInfo = VMM_PTR_OFFSET(f32, pb, cbo + off->oPtrScreenInfo);
    if(!VMM_UADDR_8_16(f32, vaScreenInfo) || (vaScreenInfo != VMM_PTR_OFFSET(f32, pb, cbo + off->oPtrScreenInfo + off->cb))) { return; }
    // validate and count row records:
    while(TRUE) {
        if(cbo + off->cb >= cb) { break; }
        vaCurrent = va + cbo;
        cchRowText = *(PWORD)(pb + cbo + off->oCountText);
        vaRowText = VMM_PTR_OFFSET(f32, pb, cbo + off->oPtrText);
        vaSelf = VMM_PTR_OFFSET(f32, pb, cbo + off->oPtrSelf);
        vaScreenInfoThis = VMM_PTR_OFFSET(f32, pb, cbo + off->oPtrScreenInfo);
        // sanity checks:
        if(!VMM_UADDR64(vaRowText)) { break; }
        if(vaCurrent != vaSelf) { break; }
        if(vaScreenInfo != vaScreenInfoThis) { break; }
        if(cchTextTotal + cchRowText >= MCON_SCREEN_MAX_CHARS + 2) { break; }
        // valid record:
        cRowRecords++;
        cchTextTotal += cchRowText + 1;
        fExternalText = fExternalText || (vaRowText < vaCurrent) || (vaRowText + cchRowText * 3 > vaCurrent + off->cb);
        cbo += off->cb;
    }
    if((cchTextTotal < 0x20) || (cRowRecords < 8)) { return; }
    if(fExternalText) {
        // read record-external text (if necessary):
        cchTextTotal = 0;
        hObScatter = VmmScatter_Initialize(H, VMM_FLAG_SCATTER_FORCE_PAGEREAD);
        if(!hObScatter) { return; }
        // prepare & execute scatter read:
        for(iRowRecord = 0; iRowRecord < cRowRecords; iRowRecord++) {
            cbo = ctx->cbAllocationInitialOffset + iRowRecord * off->cb;
            cchRowText = *(PWORD)(pb + cbo + off->oCountText);
            vaRowText = VMM_PTR_OFFSET(f32, pb, cbo + off->oPtrText);
            fPartialLine = *(PWORD)(pb + cbo + off->oPartialLine) ? TRUE : FALSE;
            f = VmmScatter_PrepareEx(hObScatter, vaRowText, cchRowText * 3, ctx->pbBufferText + cchTextTotal * 3, NULL);
            if(!f) {
                Ob_DECREF_NULL(&hObScatter);
                return;
            }
            cchTextTotal += cchRowText;
            if(!fPartialLine) {
                ctx->pbBufferText[cchTextTotal * 3] = 0x0A;
                ctx->pbBufferText[cchTextTotal * 3 + 1] = 0x00;
                ctx->pbBufferText[cchTextTotal * 3 + 2] = 0x00;
                cchTextTotal++;
            }
        }
        VmmScatter_Execute(hObScatter, ctx->pProcess);
        Ob_DECREF_NULL(&hObScatter);
        // parse individual 3-byte characters & finish up:
        pbRowText = ctx->pbBufferText;
        for(i = 0, j = 0; i < cchTextTotal; i++) {
            ch = *(PWCHAR)(pbRowText + j);
            ctx->wszBufferText[ctx->cchBufferText++] = ch;
            if(!ch) { break; }
            j += 3;
        }
        ctx->wszBufferText[ctx->cchBufferText] = 0;
        if(ctx->cchBufferText < 0x20) {
            ctx->cchBufferText = 0;
        }
        return;
    } else {
        // read record-internal text:
        for(iRowRecord = 0; iRowRecord < cRowRecords; iRowRecord++) {
            cbo = ctx->cbAllocationInitialOffset + iRowRecord * off->cb;
            cchRowText = *(PWORD)(pb + cbo + off->oCountText);
            vaRowText = VMM_PTR_OFFSET(f32, pb, cbo + off->oPtrText);
            fPartialLine = *(PWORD)(pb + cbo + off->oPartialLine) ? TRUE : FALSE;
            // parse individual 3-byte characters:
            pbRowText = pb + (vaRowText - va);
            for(i = 0, j = 0; i < cchRowText; i++) {
                ch = *(PWCHAR)(pbRowText + j);
                ctx->wszBufferText[ctx->cchBufferText++] = ch;
                if(!ch) { return; }
                j += 3;
            }
            if(!fPartialLine) {
                ctx->wszBufferText[ctx->cchBufferText++] = 0x0A;
            }
        }
        ctx->wszBufferText[ctx->cchBufferText] = 0;
        return;
    }
}

/*
* Windows 11 specific functionality.
* In Windows 11 the buffer does not usually start at the beginning of the
* buffer so we'll have to find the start of the buffer first.
*/
VOID MCON_Initialize_Win11_2(_In_ VMM_HANDLE H, _In_ PMCON_OFFSETS off, _Inout_ PMCON_INIT_CONTEXT ctx)
{
    QWORD vaScreenInfo = 0;
    DWORD cbo = 0;
    // skip forward:
    while((cbo + 0x1000 <= ctx->cbAllocation) && !memcmp(ctx->pbAllocation + cbo, H->ZERO_PAGE, 0x1000)) { cbo += 0x1000; }
    cbo += off->cbHeader;
    if(cbo + 0x1000 > ctx->cbAllocation) { return; }
    // test record validity by verifying ptr to "screen info" main object.
    vaScreenInfo = VMM_PTR_OFFSET(ctx->f32, ctx->pbAllocation, cbo + off->oPtrScreenInfo);
    if(!VMM_UADDR64_16(vaScreenInfo) || (vaScreenInfo != VMM_PTR_OFFSET(ctx->f32, ctx->pbAllocation, cbo + off->oPtrScreenInfo + off->cb))) { return; }
    // call main parsing function:
    ctx->cbAllocationInitialOffset = cbo;
    MCON_Initialize_Win1011_RowRecordParse(H, off, ctx);
}

/*
* Parse a Windows 11 console window.
* In Windows 11 everything is by default stored in one big buffer, but text
* references may be external as well. Windows 11 have two different sets of
* offsets so we need to try both. In reality this changed mid-build 22621.
*/
VOID MCON_Initialize_Win11(_In_ VMM_HANDLE H, _Inout_ PMCON_INIT_CONTEXT ctx)
{
    MCON_OFFSETS off = { 0 };
    // load buffer:
    if(ctx->cbAllocation >= MCON_INIT_BUFFER_SIZE) { return; }
    if(!VmmRead(H, ctx->pProcess, ctx->vaAllocation, ctx->pbAllocation, ctx->cbAllocation)) { return; }
    // try default offsets:
    off.cb = 0x1E0;
    off.cbHeader = 0x60;
    off.oPtrText = 0x00;
    off.oCountText = 0x08;
    off.oPtrSelf = 0x188;
    off.oPartialLine = 0x1D0;
    off.oPtrScreenInfo = 0x1D8;
    ctx->cchBufferText = 0;
    MCON_Initialize_Win11_2(H, &off, ctx);
    if((ctx->cchBufferText < 0x20) && (ctx->dwBuild >= 22621)) {
        // try alternate offsets:
        off.cb = 0x1D8;
        off.oPartialLine = 0x1C8;
        off.oPtrScreenInfo = 0x1D0;
        MCON_Initialize_Win11_2(H, &off, ctx);
    }
}

VOID MCON_Initialize_Win10(_In_ VMM_HANDLE H, _Inout_ PMCON_INIT_CONTEXT ctx)
{
    MCON_OFFSETS off = { 0 };
    BOOL f32 = ctx->f32;
    DWORD cbo;
    QWORD va, va2;
    DWORD cbA;
    PBYTE pbA = NULL;
    DWORD cbPtr = ctx->f32 ? 4 : 8;
    DWORD cbRcd = ctx->f32 ? 0x30 : 0x60;
    BYTE pbRcd[0x60] = { 0 };
    PVMMOB_SCATTER hObScatter = NULL;
    DWORD i, cboSrc = 0, cboDst = 0, cRowRecords = 0;
    QWORD vaScreenInfo = 0;
    BOOL fInitialVerify = FALSE;
    // init offsets:
    if(ctx->f32) {
        off.cb = 0x30;
        off.cbHeader = 0x10;
        off.oPtrText = 0x04;
        off.oCountText = 0x20;
        off.oPtrSelf = 0x10;
        off.oPartialLine = 0x00;
        off.oPtrScreenInfo = 0x2c;
    } else {
        off.cb = 0x60;
        off.cbHeader = 0x10;
        off.oPtrText = 0x08;
        off.oCountText = 0x40;
        off.oPtrSelf = 0x20;
        off.oPartialLine = 0x00;
        off.oPtrScreenInfo = 0x58;
    }
    // read allocation, which is the pointer array:
    cbA = ctx->cbAllocation;
    pbA = ctx->pbAllocation;
    if((cbA <= 0x00004000) || (cbA >= 0x00100000)) { return; }
    VmmRead2(H, ctx->pProcess, ctx->vaAllocation + off.cbHeader, pbA, cbA - off.cbHeader, VMM_FLAG_ZEROPAD_ON_FAIL);
    // try to verify allocation. start of array seems to be a bit fuzzy,
    // so we'll have to fuzz the correct start of the buffer first.
    for(cboSrc = 0; cboSrc < 8 * cbPtr; cboSrc += cbPtr) {
        va = VMM_PTR_OFFSET(f32, pbA, cboSrc);
        if(!VMM_UADDR_8_16(f32, va)) { continue; }
        if(!VmmRead(H, ctx->pProcess, va, pbRcd, cbRcd)) { continue; }
        if(va != VMM_PTR_OFFSET(ctx->f32, pbRcd, off.oPtrSelf)) { continue; }
        va2 = VMM_PTR_OFFSET(ctx->f32, pbRcd, off.oPtrScreenInfo);
        if(!VMM_UADDR_8_16(f32, va2)) { continue; }
        if(va2 == vaScreenInfo) {
            fInitialVerify = TRUE;
            break;
        }
        vaScreenInfo = va2;
    }
    if(!fInitialVerify) { return; }
    cboSrc -= cbPtr;
    // Walk the pointer array and scatter read the entries into the buffer.
    // It's not an issue to use the same buffer since the scatter read will
    // only overwrite the buffer when executed.
    hObScatter = VmmScatter_Initialize(H, VMMDLL_FLAG_ZEROPAD_ON_FAIL | VMM_FLAG_SCATTER_PREPAREEX_NOMEMZERO);
    if(!hObScatter) { return; }
    while(TRUE) {
        va = VMM_PTR_OFFSET(f32, pbA, cboSrc);
        if(!VMM_UADDR_8_16(f32, va)) { break; }
        VmmScatter_PrepareEx(hObScatter, va, off.cb, pbA + cboDst, NULL);
        cboSrc += cbPtr;
        cboDst += off.cb;
        cRowRecords++;
        if(cboDst > MCON_INIT_BUFFER_SIZE - 0x100) { break; }
    }
    ctx->cbAllocation = cboDst;
    VmmScatter_Execute(hObScatter, ctx->pProcess);
    Ob_DECREF_NULL(&hObScatter);
    // fix-up the self-ptr to support self-validation in row-record-parse:
    for(i = 0; i < cRowRecords; i++) {
        cbo = i * off.cb;
        if(f32) {
            *(PDWORD)(pbA + cbo + off.oPtrSelf) = (DWORD)(ctx->vaAllocation + cbo);
        } else {
            *(PQWORD)(pbA + cbo + off.oPtrSelf) = ctx->vaAllocation + cbo;
        }
    }
    // call main parsing function:
    MCON_Initialize_Win1011_RowRecordParse(H, &off, ctx);
}



// ----------------------------------------------------------------------------
// WINDOWS 7 7600 -> WINDOWS 10 17134 CONSOLE PARSING:
// ----------------------------------------------------------------------------

VOID MCON_Initialize_Win7(_In_ VMM_HANDLE H, _Inout_ PMCON_INIT_CONTEXT ctx)
{
    BOOL f, f32 = ctx->f32;
    DWORD cbA, cRcd, cboDst = 0;
    PBYTE pbA = NULL;
    DWORD iRcd;
    PBYTE pbRcd;
    PVMMOB_SCATTER hObScatter = NULL;
    QWORD vaRowText, va;
    DWORD cbRowText, cbTextTotal = 0;
    struct {
        DWORD cb;
        DWORD cbHeader;
        WORD oCountText;
        WORD oPtrText;
        WORD oPtr10;
        WORD oRcdId;
    } off = { 0 };
    // init offsets:
    if(f32) {
        off.cb = 0x1c;
        off.oPtrText = 0x08;
        if(ctx->dwBuild >= 10240) { off.cb = 0x24; off.oPtrText = 0x08; off.oPtr10 = 0x1c; off.oRcdId = 0x20; }
        if(ctx->dwBuild >= 14393) { off.cb = 0x20; off.oPtrText = 0x04; off.oPtr10 = 0x18; off.oRcdId = 0x1c; }
        if(ctx->dwBuild >= 15063) { off.cb = 0x1c; off.oPtrText = 0x04; off.oPtr10 = 0x14; off.oRcdId = 0x18; }
        if(ctx->dwBuild >= 17134) { off.cb = 0x20; off.oPtrText = 0x04; off.oPtr10 = 0x14; off.oRcdId = 0x1c; off.cbHeader = 0x04; }
    } else {
        off.cb = 0x28;
        off.oPtrText = 0x08;
        if(ctx->dwBuild >= 10240) { off.cb = 0x38; off.oPtr10 = 0x28; off.oRcdId = 0x30; }
        if(ctx->dwBuild >= 17134) { off.cb = 0x40; off.oPtr10 = 0x28; off.oRcdId = 0x38; off.cbHeader = 0x08; }
    }
    // read allocation, which is the pointer array:
    cbA = ctx->cbAllocation;
    pbA = ctx->pbAllocation;
    cRcd = (ctx->cbAllocation - off.cbHeader) / off.cb;
    if((cbA <= 0x00001000) || (cbA >= 0x00400000)) { return; }
    if(cbA != (cRcd * off.cb + off.cbHeader)) { return; }
    if(cRcd > 0x8000) { return; }
    if(!VmmRead(H, ctx->pProcess, ctx->vaAllocation + off.cbHeader, pbA, cbA - off.cbHeader)) { return;}
    // verify array allocation:
    for(iRcd = 0; iRcd < cRcd; iRcd++) {
        pbRcd = pbA + iRcd * off.cb;
        va = VMM_PTR_OFFSET(f32, pbRcd, off.oPtrText);
        if(!VMM_UADDR(f32, va) || (va & 1)) { return; }
        if(off.oPtr10) {
            va = VMM_PTR_OFFSET(f32, pbRcd, off.oPtr10);
            if(!VMM_UADDR(f32, va) || (va & 1)) { return; }
        }
        if(off.oRcdId && (iRcd != *(PDWORD)(pbRcd + off.oRcdId))) { return; }
        if(*(PWORD)(pbRcd + off.oCountText) >= 0x8000) { return; }
    }
    // Walk the pointer array and scatter read the entries into the text buffer.
    hObScatter = VmmScatter_Initialize(H, VMMDLL_FLAG_ZEROPAD_ON_FAIL | VMMDLL_FLAG_SCATTER_PREPAREEX_NOMEMZERO);
    if(!hObScatter) { return; }
    for(iRcd = 0; iRcd < cRcd; iRcd++) {
        pbRcd = pbA + iRcd * off.cb;
        cbRowText = (DWORD)(*(PWORD)(pbRcd + off.oCountText)) << 1;
        vaRowText = VMM_PTR_OFFSET(f32, pbRcd, off.oPtrText);
        if(((cbTextTotal + cbRowText) >> 1) >= MCON_SCREEN_MAX_CHARS + 2) { break; }
        if(cbRowText) {
            f = VmmScatter_PrepareEx(hObScatter, vaRowText, cbRowText, ctx->pbBufferText + cbTextTotal, NULL);
            if(!f) {
                Ob_DECREF(hObScatter);
                return;
            }
            cbTextTotal += cbRowText;
        }
        ctx->pbBufferText[cbTextTotal++] = 0x0A;
        ctx->pbBufferText[cbTextTotal++] = 0x00;
    }
    VmmScatter_Execute(hObScatter, ctx->pProcess);
    Ob_DECREF_NULL(&hObScatter);
    // finalize buffer:
    ctx->pbBufferText[cbTextTotal++] = 0x00;
    ctx->pbBufferText[cbTextTotal++] = 0x00;
    ctx->cchBufferText = cbTextTotal >> 1;
    if(ctx->cchBufferText < 0x20) {
        ctx->cchBufferText = 0;
    }
}



// ----------------------------------------------------------------------------
// MAIN INITIALIZATION FUNCTIONALITY:
// ----------------------------------------------------------------------------

VOID MCON_Initialize_CleanupCB(_In_ PVOID pOb)
{
    LocalFree(((POB_MCON_CONTEXT)pOb)->uszText);
}

/*
* Initialize a context for the given process.
* CALLER DECREF: return
*/
_Success_(return != NULL)
POB_MCON_CONTEXT MCON_Initialize(_In_ VMM_HANDLE H, _In_ VMM_MODULE_ID MID, _In_ PVMM_PROCESS pProcess)
{
    DWORD i, cb, cchBufferTextPre;
    POB_MCON_CONTEXT ctxUser = NULL;
    PMCON_INIT_CONTEXT ctxInit = NULL;
    PVMMOB_MAP_VAD pObVadMap = NULL;
    PVMM_MAP_VADENTRY peVad;
    PVMMOB_MAP_HEAPALLOC pObHeapAllocMap = NULL;
    PVMM_MAP_HEAPALLOCENTRY peHeapAlloc;
    VMMSTATISTICS_LOG Statistics = { 0 };
    // alloc:
    VmmStatisticsLogStart(H, MID, LOGLEVEL_6_TRACE, pProcess, &Statistics, "INIT_CONSOLE");
    if(!(ctxInit = LocalAlloc(LMEM_ZEROINIT, sizeof(MCON_INIT_CONTEXT)))) { goto fail; }
    if(!(ctxUser = Ob_AllocEx(H, 'MCON', LMEM_ZEROINIT, sizeof(OB_MCON_CONTEXT), MCON_Initialize_CleanupCB, NULL))) { goto fail; }
    ctxInit->f32 = H->vmm.f32 || pProcess->win.fWow64;
    ctxInit->MID = MID;
    ctxInit->pProcess = pProcess;
    ctxInit->dwBuild = H->vmm.kernel.dwVersionBuild;
    // find allocation and dispatch to os-dependent parsing function:
    if(ctxInit->dwBuild >= 22000) {
        // WIN11 21H2 - 23H2:
        // strategy is to find large vad allocations which are private, read, write and also "unmarked" as in unknown.
        if(!VmmMap_GetVad(H, pProcess, &pObVadMap, VMM_VADMAP_TP_FULL) || !pObVadMap->cMap) {
            VmmLog(H, MID, LOGLEVEL_5_DEBUG, "Fail: Unable to retrieve VAD map. PID:[%i]", pProcess->dwPID);
            goto fail;
        }
        for(i = 0; i < pObVadMap->cMap; i++) {
            peVad = pObVadMap->pMap + i;
            cb = (DWORD)(peVad->vaEnd - peVad->vaStart);
            if(!peVad->fPrivateMemory || peVad->uszText[0]) { continue; }
            if(peVad->fFile || peVad->fHeap || peVad->fImage || peVad->fPageFile || peVad->fStack || peVad->fTeb || peVad->vaFileObject) { continue; }
            if((cb < 0x50000) || (cb > MCON_INIT_BUFFER_SIZE)) { continue; }
            if((ctxInit->dwBuild < 26100) && (peVad->CommitCharge < 0x10)) { continue; }
            VmmLog(H, MID, LOGLEVEL_6_TRACE, "Info: Try parse candidate buffer. PID:[%i] va:[%llx]", pProcess->dwPID, peVad->vaStart);
            // try parse the potential console buffer:
            ctxInit->cchBufferText = 0;
            ctxInit->vaAllocation = peVad->vaStart;
            ctxInit->cbAllocation = (DWORD)(peVad->vaEnd - peVad->vaStart);
            if(ctxInit->dwBuild >= 26100) {
                MCON_Initialize_Win11_26100(H, ctxInit);
            } else {
                MCON_Initialize_Win11(H, ctxInit);
            }
            ctxInit->vaAllocation = peVad->vaStart;
            if(ctxInit->cchBufferText > 0x10) { break; }
        }
    } else {
        // WIN7 -> WIN10 1803:
        // WIN10 1809 -> WIN10 23H2:
        // strategy is to find large heap allocations.
        if(!VmmMap_GetHeapAlloc(H, pProcess, 0, &pObHeapAllocMap) || !pObHeapAllocMap->cMap) {
            VmmLog(H, MID, LOGLEVEL_5_DEBUG, "Fail: Unable to retrieve heap allocation map. PID:[%i]", pProcess->dwPID);
            goto fail;
        }
        for(i = 0; i < pObHeapAllocMap->cMap; i++) {
            peHeapAlloc = pObHeapAllocMap->pMap + i;
            if((peHeapAlloc->cb <= 0x1000) || (peHeapAlloc->cb >= 0x00100000) || !(peHeapAlloc->cb & 0xfff)) { continue; }
            VmmLog(H, MID, LOGLEVEL_6_TRACE, "Info: Try parse candidate buffer. PID:[%i] va:[%llx] size:[%x]", pProcess->dwPID, peHeapAlloc->va, peHeapAlloc->cb);
            // try parse the potential console buffer:
            ctxInit->vaAllocation = peHeapAlloc->va;
            ctxInit->cbAllocation = peHeapAlloc->cb;
            ctxInit->cchBufferText = 0;
            ctxInit->fSuccess = FALSE;
            if(ctxInit->dwBuild >= 17763) {
                MCON_Initialize_Win10(H, ctxInit);
            } else {
                MCON_Initialize_Win7(H, ctxInit);
            }
            ctxInit->vaAllocation = peHeapAlloc->va;
            if(ctxInit->cchBufferText > 0x10) { break; }
        }
    }
    // any recovered text buffer may have lots of space-padding and newlines.
    // compact the buffer to remove any unnecessary padding and newlines.
    if(ctxInit->cchBufferText > 0x10) {
        cchBufferTextPre = ctxInit->cchBufferText;
        ctxInit->cchBufferText = MCON_Init_CompactConsoleBuffer(ctxInit->wszBufferText);
        ctxInit->fSuccess = TRUE;
        VmmLog(H, MID, LOGLEVEL_6_TRACE, "Info: Parsed buffer. PID:[%i] va:[%llx] chars:[%x] chars-compressed:[%x] verdict:[%s]", pProcess->dwPID, ctxInit->vaAllocation, cchBufferTextPre, ctxInit->cchBufferText, ctxInit->fSuccess ? "success" : "fail");
    }
    // finalize context:
    // convert the wchar buffer to utf-8 and store in the context.
    if(ctxInit->fSuccess && CharUtil_WtoU(ctxInit->wszBufferText, ctxInit->cchBufferText, NULL, 0, &ctxUser->uszText, &ctxUser->cbText, CHARUTIL_FLAG_ALLOC | CHARUTIL_FLAG_BAD_UTF8CP_SOFTFAIL)) {
        ctxUser->fValid = TRUE;
        if(ctxUser->cbText) { ctxUser->cbText--; }
        VmmLog(H, MID, LOGLEVEL_6_TRACE, "Success: Parse console buffer. PID:[%i] va:[%llx] length:[%x]", pProcess->dwPID, ctxInit->vaAllocation, ctxUser->cbText);
    } else {
        VmmLog(H, MID, LOGLEVEL_6_TRACE, "Fail: Parse console buffer. PID:[%i]", pProcess->dwPID);
    }
fail:
    Ob_DECREF(pObHeapAllocMap);
    Ob_DECREF(pObVadMap);
    LocalFree(ctxInit);
    VmmStatisticsLogEnd(H, &Statistics, "INIT_CONSOLE");
    return ctxUser;
}

/*
* Retrieve the context for the given process.
* CALLER DECREF: return
*/
_Success_(return != NULL)
POB_MCON_CONTEXT MCON_GetContext(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_CONTEXT ctxP)
{
    POB_MCON_CONTEXT ctxOb = NULL;
    PVMM_PROCESS pProcess = ctxP->pProcess;
    if(!pProcess) { return NULL; }
    if(!(ctxOb = ObMap_GetByKey((POB_MAP)ctxP->ctxM, pProcess->dwPID))) {
        EnterCriticalSection(&H->vmm.LockPlugin);
        if(!(ctxOb = ObMap_GetByKey((POB_MAP)ctxP->ctxM, pProcess->dwPID))) {
            ctxOb = MCON_Initialize(H, ctxP->MID, pProcess);
            ObMap_Push((POB_MAP)ctxP->ctxM, pProcess->dwPID, ctxOb);
        }
        LeaveCriticalSection(&H->vmm.LockPlugin);
    }
    return ctxOb;
}



// ----------------------------------------------------------------------------
// MODULE BASE FUNCTIONALITY:
// ----------------------------------------------------------------------------

_Success_(return == STATUS_SUCCESS)
NTSTATUS M_ProcConsole_Read(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_CONTEXT ctxP, _Out_ PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset)
{
    NTSTATUS nt = VMMDLL_STATUS_FILE_INVALID;
    POB_MCON_CONTEXT ctxOb = MCON_GetContext(H, ctxP);
    if(CharUtil_StrEquals(ctxP->uszPath, "console.txt", TRUE) && ctxOb && ctxOb->fValid) {
        nt = Util_VfsReadFile_FromPBYTE(ctxOb->uszText, ctxOb->cbText, pb, cb, pcbRead, cbOffset);
    }
    Ob_DECREF(ctxOb);
    return nt;
}

BOOL M_ProcConsole_List(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_CONTEXT ctxP, _Inout_ PHANDLE pFileList)
{
    POB_MCON_CONTEXT ctxOb = MCON_GetContext(H, ctxP);
    if(!ctxP->uszPath[0] && ctxOb && ctxOb->fValid) {
        VMMDLL_VfsList_AddFile(pFileList, "console.txt", ctxOb->cbText, NULL);
    }
    Ob_DECREF(ctxOb);
    return TRUE;
}

VOID M_ProcConsole_Close(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_CONTEXT ctxP)
{
    Ob_DECREF(ctxP->ctxM);
}

VOID M_ProcConsole_Notify(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_CONTEXT ctxP, _In_ DWORD fEvent, _In_opt_ PVOID pvEvent, _In_opt_ DWORD cbEvent)
{
    if(fEvent == VMMDLL_PLUGIN_NOTIFY_REFRESH_SLOW) {
        ObMap_Clear((POB_MAP)ctxP->ctxM);
    }
}

BOOL M_ProcConsole_VisibleModule(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_CONTEXT ctxP)
{
    PVMM_PROCESS pProcess = ctxP->pProcess;
    return pProcess && (*(PQWORD)pProcess->szName == 0x2e74736f686e6f63) && ((*(PDWORD)(pProcess->szName + 8) == 0x0657865));   // "conhost." "exe\0"
}

/*
* Initialization function. The module manager shall call into this function
* when the module shall be initialized. If the module wish to initialize it
* shall call the supplied pfnPluginManager_Register function.
* NB! the module does not have to register itself - for example if the target
* operating system or architecture is unsupported.
* -- pRI
*/
VOID M_ProcConsole_Initialize(_In_ VMM_HANDLE H, _Inout_ PVMMDLL_PLUGIN_REGINFO pRI)
{
    if((pRI->magic != VMMDLL_PLUGIN_REGINFO_MAGIC) || (pRI->wVersion != VMMDLL_PLUGIN_REGINFO_VERSION)) { return; }
    if(pRI->sysinfo.dwVersionBuild < 7600) { return; }                      // WIN7 and later is supported.
    if(!(pRI->reg_info.ctxM = (PVMMDLL_PLUGIN_INTERNAL_CONTEXT)ObMap_New(H, OB_MAP_FLAGS_OBJECT_OB))) { return; }    // internal module context
    strcpy_s(pRI->reg_info.uszPathName, 128, "\\console");                  // module name
    pRI->reg_info.fRootModule = FALSE;                                      // module shows in root directory
    pRI->reg_info.fProcessModule = TRUE;                                    // module shows in process directory
    pRI->reg_fn.pfnVisibleModule = M_ProcConsole_VisibleModule;             // Visible module function supported
    pRI->reg_fn.pfnNotify = M_ProcConsole_Notify;                           // Notify function supported
    pRI->reg_fn.pfnList = M_ProcConsole_List;                               // List function supported
    pRI->reg_fn.pfnRead = M_ProcConsole_Read;                               // Read function supported
    pRI->reg_fn.pfnClose = M_ProcConsole_Close;                             // Close function supported
    pRI->pfnPluginManager_Register(H, pRI);
}
