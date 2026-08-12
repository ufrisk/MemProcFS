// m_proc_winterm.c : implementation of the Windows Terminal text buffer module.
//
// (c) Ulf Frisk, 2026
// Author: Ulf Frisk, pcileech@frizk.net
//
// Layouts are resolved from static offsets in info.db and validated against the
// captured memory before any text is exposed.
//

#include "modules.h"
#include "../infodb.h"

#define MWTR_MAX_TERMINALS                  64
#define MWTR_MAX_SEARCH_HITS                4096
#define MWTR_MAX_SEARCH_HEAP_SEGMENTS       0x00010000
#define MWTR_MAX_SEARCH_HEAP_VAD_BYTES      0x0000000040000000ULL
#define MWTR_MAX_SEARCH_HEAP_BYTES          0x0000000100000000ULL
#define MWTR_MAX_ROWS                       0x00008000
#define MWTR_MIN_COLUMNS                    1
#define MWTR_MAX_COLUMNS                    1000
#define MWTR_MAX_ROW_CHARS                  0x00010000
#define MWTR_MAX_SCREEN_CHARS               0x00800000
#define MWTR_MAX_CONTEXT_TEXT_BYTES         0x04000000

#define MWTR_TERMINAL_CB_MAX                0x1000
#define MWTR_TEXTBUFFER_CB_MAX              0x0400
#define MWTR_ROW_CB_MAX                     0x0400
#define MWTR_CONTROL_IMAGE_CB_MAX           0x02000000
#define MWTR_OFFSET_INVALID                 0xffffffff

#define MWTR_LEGACY_CELL_CB                     3
#define MWTR_LEGACY_CELL_ATTR_MASK              7
#define MWTR_LEGACY_CELL_ATTR_TRAILING          2
#define MWTR_LEGACY_CELL_ATTR_GLYPH_STORED      4

#define MWTR_TERMINALS_HEADER               "  #         TerminalVA   ActiveBufferVA     MainBufferVA      AltBufferVA   Rows   Cols FirstRow CursorX CursorY Bytes HeurCmd\n" \
                                            "------------------------------------------------------------------------------------------------------------------------------\n"

typedef enum tdMWTR_BUFFER_LAYOUT {
    MWTR_BUFFER_LAYOUT_LEGACY   = 1,
    MWTR_BUFFER_LAYOUT_SPAN     = 2,
    MWTR_BUFFER_LAYOUT_ARENA    = 3
} MWTR_BUFFER_LAYOUT;

typedef struct tdMWTR_LAYOUT {
    CHAR uszName[64];
    CHAR uszModule[64];
    DWORD dwVersionMajor;
    DWORD dwVersionMinor;
    MWTR_BUFFER_LAYOUT tpBuffer;
    BOOL fHasAltTextBuffer;
    DWORD cbTerminal;
    DWORD oTerminalFromSearch;
    DWORD rvaSearchVft;
    DWORD oMainTextBuffer;
    DWORD oAltTextBuffer;
    QWORD vaControl;
    DWORD cbControl;
    QWORD vaRdata;
    QWORD vaRdataEnd;
    QWORD vaText;
    QWORD vaTextEnd;
    struct {
        DWORD cb;
        DWORD cbCoord;
        DWORD oViewportLeft;
        DWORD oViewportTop;
        DWORD oViewportRight;
        DWORD oViewportBottom;
        DWORD oCharBuffer;
        DWORD oStorageBegin;
        DWORD oStorageEnd;
        DWORD oStorageCap;
        DWORD oBufferEnd;
        DWORD oWatermark;
        DWORD oRowStride;
        DWORD oCharsOffset;
        DWORD oOffsetsOffset;
        DWORD oWidth;
        DWORD oHeight;
        DWORD oFirstRow;
        DWORD oCursorParent;
        DWORD oCursorX;
        DWORD oCursorY;
        DWORD oActive;
    } TextBuffer;
    struct {
        DWORD cb;
        DWORD cbCoord;
        DWORD oCharsBuffer;
        DWORD oCharsHeap;
        DWORD oCharsPtr;
        DWORD oCharsCount;
        DWORD oCharsCapacity;
        DWORD oCharsInline;
        DWORD oOffsetsPtr;
        DWORD oOffsetsCount;
        DWORD oCharParent;
        DWORD oTextBufferParent;
        DWORD oId;
        DWORD oColumns;
        DWORD oRendition;
        DWORD oWrap;
        DWORD oDoubleByte;
    } Row;
} MWTR_LAYOUT, *PMWTR_LAYOUT;

typedef const MWTR_LAYOUT *PCMWTR_LAYOUT;

typedef struct tdMWTR_TEXTBUFFER_INFO {
    PMWTR_LAYOUT pLayout;
    QWORD vaTextBuffer;
    QWORD vaCharBuffer;
    QWORD vaRows;
    QWORD vaRowsEnd;
    QWORD vaCommitWatermark;
    DWORD cRows;
    DWORD cColumns;
    DWORD iFirstRow;
    DWORD xCursor;
    DWORD yCursor;
    DWORD cbRowStride;
    DWORD oRowChars;
    DWORD oRowOffsets;
    DWORD cCommittedRows;
} MWTR_TEXTBUFFER_INFO, *PMWTR_TEXTBUFFER_INFO;

typedef struct tdMWTR_DISCOVERED {
    QWORD vaTerminal;
    QWORD vaMainTextBuffer;
    QWORD vaAltTextBuffer;
    MWTR_TEXTBUFFER_INFO TextBuffer;
} MWTR_DISCOVERED, *PMWTR_DISCOVERED;

typedef struct tdMWTR_SEARCH_RESULT {
    VMM_HANDLE H;
    PVMM_PROCESS pProcess;
    PMWTR_LAYOUT pLayout;
    DWORD cHits;
    DWORD cTerminals;
    BOOL fLimit;
    QWORD cbTotalBytesSearched;
    MWTR_DISCOVERED Terminal[MWTR_MAX_TERMINALS];
} MWTR_SEARCH_RESULT, *PMWTR_SEARCH_RESULT;

typedef struct tdMWTR_ROW_PARSE {
    QWORD vaChars;
    QWORD cChars;
    QWORD vaOffsets;
    DWORD cReadable;
    DWORD oRaw;
    DWORD cch;
    DWORD cbReadOffset;
    DWORD cbReadChars;
    WORD wCchRaw;
    BYTE fWrap;
    BYTE fCommitted;
} MWTR_ROW_PARSE, *PMWTR_ROW_PARSE;

typedef struct tdMWTR_TERMINAL {
    QWORD vaTerminal;
    QWORD vaMainTextBuffer;
    QWORD vaAltTextBuffer;
    MWTR_TEXTBUFFER_INFO TextBuffer;
    POB_DATA pObText;
    POB_DATA pObCommandsHeuristic;
    DWORD cCommandsHeuristic;
} MWTR_TERMINAL, *PMWTR_TERMINAL;

typedef struct tdOB_MWTR_CONTEXT {
    OB ObHdr;
    BOOL fValid;
    DWORD cTerminals;
    MWTR_LAYOUT Layout;
    POB_MEMFILE pmfTerminal;
    POB_MEMFILE pmfTerminals;
    POB_MEMFILE pmfCommandsHeuristic;
    MWTR_TERMINAL Terminal[MWTR_MAX_TERMINALS];
} OB_MWTR_CONTEXT, *POB_MWTR_CONTEXT;



// ----------------------------------------------------------------------------
// SAFE UNALIGNED ACCESS HELPERS:
// ----------------------------------------------------------------------------
_Success_(return)
static BOOL MWTR_AddQWORD(_In_ QWORD a, _In_ QWORD b, _Out_ PQWORD pResult)
{
    if(a > (QWORD)-1 - b) { return FALSE; }
    *pResult = a + b;
    return TRUE;
}

LONG MWTR_GetSignedCoord(_In_reads_bytes_(cb) PBYTE pb, _In_ DWORD cb)
{
    return (cb == sizeof(SHORT)) ? (LONG)*(PSHORT)(pb) : *(PLONG)(pb);
}

DWORD MWTR_GetUnsignedCoord(_In_reads_bytes_(cb) PBYTE pb, _In_ DWORD cb)
{
    return (cb == sizeof(WORD)) ? *(PWORD)(pb) : *(PDWORD)(pb);
}

BOOL MWTR_OffsetInBounds(_In_ DWORD o, _In_ DWORD cbField, _In_ DWORD cbObject)
{
    return (o != MWTR_OFFSET_INVALID) && (o <= cbObject) && (cbField <= cbObject - o);
}

VOID MWTR_LayoutCopyModule(_In_ PCMWTR_LAYOUT pModule, _Out_ PMWTR_LAYOUT pLayout)
{
    ZeroMemory(pLayout, sizeof(*pLayout));
    strcpy_s(pLayout->uszModule, sizeof(pLayout->uszModule), pModule->uszModule);
    pLayout->dwVersionMajor = pModule->dwVersionMajor;
    pLayout->dwVersionMinor = pModule->dwVersionMinor;
    pLayout->vaControl = pModule->vaControl;
    pLayout->cbControl = pModule->cbControl;
    pLayout->vaRdata = pModule->vaRdata;
    pLayout->vaRdataEnd = pModule->vaRdataEnd;
    pLayout->vaText = pModule->vaText;
    pLayout->vaTextEnd = pModule->vaTextEnd;
    pLayout->cbTerminal = MWTR_TERMINAL_CB_MAX;
    pLayout->oMainTextBuffer = MWTR_OFFSET_INVALID;
    pLayout->oAltTextBuffer = MWTR_OFFSET_INVALID;
}

BOOL MWTR_OffsetsInBounds(_In_ DWORD cbObject, _In_reads_(cFields) PDWORD poFields, _In_reads_(cFields) PDWORD pcbFields, _In_ DWORD cFields)
{
    DWORD i;
    for(i = 0; i < cFields; i++) {
        if(!MWTR_OffsetInBounds(poFields[i], pcbFields[i], cbObject)) { return FALSE; }
    }
    return TRUE;
}

BOOL MWTR_LayoutSanity(_In_ PCMWTR_LAYOUT pLayout)
{
    DWORD cbCoord, ao[20], acb[20], c = 0;
    if(!pLayout || !pLayout->TextBuffer.cb || (pLayout->TextBuffer.cb > MWTR_TEXTBUFFER_CB_MAX) ||
       !pLayout->Row.cb || (pLayout->Row.cb > MWTR_ROW_CB_MAX) ||
       !pLayout->cbTerminal || (pLayout->cbTerminal > MWTR_TERMINAL_CB_MAX)) { return FALSE; }
    cbCoord = pLayout->TextBuffer.cbCoord;
    if(((cbCoord != 2) && (cbCoord != 4)) ||
       ((pLayout->Row.cbCoord != 2) && (pLayout->Row.cbCoord != 4))) { return FALSE; }
#define MWTR_SANITY_ADD(_o, _cb) do { ao[c] = (_o); acb[c++] = (_cb); } while(0)
    if(pLayout->tpBuffer == MWTR_BUFFER_LAYOUT_LEGACY) {
        MWTR_SANITY_ADD(pLayout->TextBuffer.oViewportLeft, cbCoord);
        MWTR_SANITY_ADD(pLayout->TextBuffer.oViewportTop, cbCoord);
        MWTR_SANITY_ADD(pLayout->TextBuffer.oViewportRight, cbCoord);
        MWTR_SANITY_ADD(pLayout->TextBuffer.oViewportBottom, cbCoord);
        MWTR_SANITY_ADD(pLayout->TextBuffer.oStorageBegin, 8);
        MWTR_SANITY_ADD(pLayout->TextBuffer.oStorageEnd, 8);
        MWTR_SANITY_ADD(pLayout->TextBuffer.oStorageCap, 8);
        MWTR_SANITY_ADD(pLayout->TextBuffer.oFirstRow, cbCoord);
        MWTR_SANITY_ADD(pLayout->TextBuffer.oCursorParent, 8);
        MWTR_SANITY_ADD(pLayout->TextBuffer.oCursorX, cbCoord);
        MWTR_SANITY_ADD(pLayout->TextBuffer.oCursorY, cbCoord);
        if(!MWTR_OffsetsInBounds(pLayout->TextBuffer.cb, ao, acb, c)) { return FALSE; }
        c = 0;
        MWTR_SANITY_ADD(pLayout->Row.oCharsPtr, 8);
        MWTR_SANITY_ADD(pLayout->Row.oCharsCount, 8);
        MWTR_SANITY_ADD(pLayout->Row.oCharsCapacity, 8);
        MWTR_SANITY_ADD(pLayout->Row.oCharsInline, 1);
        if(!MWTR_OffsetsInBounds(pLayout->Row.cb, ao, acb, c)) { return FALSE; }
        if((pLayout->Row.oCharParent != MWTR_OFFSET_INVALID) ||
           (pLayout->Row.oTextBufferParent != MWTR_OFFSET_INVALID) ||
           (pLayout->Row.oId != MWTR_OFFSET_INVALID) ||
           (pLayout->Row.oColumns != MWTR_OFFSET_INVALID) ||
           (pLayout->Row.oWrap != MWTR_OFFSET_INVALID) ||
           (pLayout->Row.oDoubleByte != MWTR_OFFSET_INVALID)) {
            c = 0;
            MWTR_SANITY_ADD(pLayout->Row.oCharParent, 8);
            MWTR_SANITY_ADD(pLayout->Row.oTextBufferParent, 8);
            MWTR_SANITY_ADD(pLayout->Row.oId, pLayout->Row.cbCoord);
            MWTR_SANITY_ADD(pLayout->Row.oColumns, pLayout->Row.cbCoord);
            MWTR_SANITY_ADD(pLayout->Row.oWrap, 1);
            MWTR_SANITY_ADD(pLayout->Row.oDoubleByte, 1);
            if(!MWTR_OffsetsInBounds(pLayout->Row.cb, ao, acb, c)) { return FALSE; }
        }
        return TRUE;
    }
    if(pLayout->tpBuffer == MWTR_BUFFER_LAYOUT_SPAN) {
        MWTR_SANITY_ADD(pLayout->TextBuffer.oCharBuffer, 8);
        MWTR_SANITY_ADD(pLayout->TextBuffer.oStorageBegin, 8);
        MWTR_SANITY_ADD(pLayout->TextBuffer.oStorageEnd, 8);
        MWTR_SANITY_ADD(pLayout->TextBuffer.oStorageCap, 8);
        MWTR_SANITY_ADD(pLayout->TextBuffer.oFirstRow, cbCoord);
        MWTR_SANITY_ADD(pLayout->TextBuffer.oCursorParent, 8);
        MWTR_SANITY_ADD(pLayout->TextBuffer.oCursorX, cbCoord);
        MWTR_SANITY_ADD(pLayout->TextBuffer.oCursorY, cbCoord);
        MWTR_SANITY_ADD(pLayout->TextBuffer.oViewportLeft, cbCoord);
        MWTR_SANITY_ADD(pLayout->TextBuffer.oViewportTop, cbCoord);
        MWTR_SANITY_ADD(pLayout->TextBuffer.oViewportRight, cbCoord);
        MWTR_SANITY_ADD(pLayout->TextBuffer.oViewportBottom, cbCoord);
        MWTR_SANITY_ADD(pLayout->TextBuffer.oActive, 1);
    } else if(pLayout->tpBuffer == MWTR_BUFFER_LAYOUT_ARENA) {
        MWTR_SANITY_ADD(pLayout->TextBuffer.oStorageBegin, 8);
        MWTR_SANITY_ADD(pLayout->TextBuffer.oBufferEnd, 8);
        MWTR_SANITY_ADD(pLayout->TextBuffer.oWatermark, 8);
        MWTR_SANITY_ADD(pLayout->TextBuffer.oRowStride, 8);
        MWTR_SANITY_ADD(pLayout->TextBuffer.oCharsOffset, 8);
        MWTR_SANITY_ADD(pLayout->TextBuffer.oOffsetsOffset, 8);
        MWTR_SANITY_ADD(pLayout->TextBuffer.oWidth, 2);
        MWTR_SANITY_ADD(pLayout->TextBuffer.oHeight, 2);
        MWTR_SANITY_ADD(pLayout->TextBuffer.oFirstRow, cbCoord);
        MWTR_SANITY_ADD(pLayout->TextBuffer.oCursorParent, 8);
        MWTR_SANITY_ADD(pLayout->TextBuffer.oCursorX, cbCoord);
        MWTR_SANITY_ADD(pLayout->TextBuffer.oCursorY, cbCoord);
        MWTR_SANITY_ADD(pLayout->TextBuffer.oActive, 1);
    } else {
        return FALSE;
    }
    if(!MWTR_OffsetsInBounds(pLayout->TextBuffer.cb, ao, acb, c)) { return FALSE; }
    c = 0;
    MWTR_SANITY_ADD(pLayout->Row.oCharsBuffer, 8);
    MWTR_SANITY_ADD(pLayout->Row.oCharsHeap, 8);
    MWTR_SANITY_ADD(pLayout->Row.oCharsPtr, 8);
    MWTR_SANITY_ADD(pLayout->Row.oCharsCount, 8);
    MWTR_SANITY_ADD(pLayout->Row.oOffsetsPtr, 8);
    MWTR_SANITY_ADD(pLayout->Row.oOffsetsCount, 8);
    MWTR_SANITY_ADD(pLayout->Row.oColumns, pLayout->Row.cbCoord);
    MWTR_SANITY_ADD(pLayout->Row.oWrap, 1);
    if(pLayout->tpBuffer == MWTR_BUFFER_LAYOUT_ARENA) {
        MWTR_SANITY_ADD(pLayout->Row.oRendition, 1);
        MWTR_SANITY_ADD(pLayout->Row.oDoubleByte, 1);
    }
#undef MWTR_SANITY_ADD
    return MWTR_OffsetsInBounds(pLayout->Row.cb, ao, acb, c);
}



// ----------------------------------------------------------------------------
// UNICODE SPAN-ROW/VECTOR TEXT BUFFER VALIDATION AND EXTRACTION:
// ----------------------------------------------------------------------------

_Success_(return)
static BOOL MWTR_ValidateRowSpan(_In_ PBYTE pbRow, _In_ PMWTR_TEXTBUFFER_INFO pInfo, _In_ DWORD iPhysicalRow, _Out_opt_ PMWTR_ROW_PARSE pParse)
{
    BYTE fWrap;
    WORD cColumns;
    QWORD vaExpectedChars, vaExpectedOffsets;
    QWORD vaCharsBuffer, vaCharsHeap, vaChars, cChars, vaOffsets, cOffsets;
    QWORD oBacking;
    PMWTR_LAYOUT pLayout = pInfo->pLayout;
    if(!pLayout || (pLayout->tpBuffer != MWTR_BUFFER_LAYOUT_SPAN) || (iPhysicalRow >= pInfo->cRows)) { return FALSE; }
    oBacking = (QWORD)iPhysicalRow * (4ULL * pInfo->cColumns + 2);
    if(!MWTR_AddQWORD(pInfo->vaCharBuffer, oBacking, &vaExpectedChars)) { return FALSE; }
    if(!MWTR_AddQWORD(vaExpectedChars, 2ULL * pInfo->cColumns, &vaExpectedOffsets)) { return FALSE; }
    vaCharsBuffer = *(PQWORD)(pbRow + pLayout->Row.oCharsBuffer);
    vaCharsHeap = *(PQWORD)(pbRow + pLayout->Row.oCharsHeap);
    vaChars = *(PQWORD)(pbRow + pLayout->Row.oCharsPtr);
    cChars = *(PQWORD)(pbRow + pLayout->Row.oCharsCount);
    vaOffsets = *(PQWORD)(pbRow + pLayout->Row.oOffsetsPtr);
    cOffsets = *(PQWORD)(pbRow + pLayout->Row.oOffsetsCount);
    cColumns = (WORD)MWTR_GetUnsignedCoord(pbRow + pLayout->Row.oColumns, pLayout->Row.cbCoord);
    fWrap = pbRow[pLayout->Row.oWrap];
    if(vaCharsBuffer != vaExpectedChars) { return FALSE; }
    if((vaOffsets != vaExpectedOffsets) || (cOffsets != (QWORD)pInfo->cColumns + 1)) { return FALSE; }
    if((cColumns != pInfo->cColumns) || (fWrap > 1)) { return FALSE; }
    if(!VMM_UADDR64(vaChars) || (vaChars & 1) || !VMM_UADDR64(vaOffsets) || (vaOffsets & 1)) { return FALSE; }
    if(!cChars || (cChars > MWTR_MAX_ROW_CHARS)) { return FALSE; }
    if((vaChars != vaCharsBuffer) && (!vaCharsHeap || (vaChars != vaCharsHeap))) { return FALSE; }
    if(pParse) {
        pParse->vaChars = vaChars;
        pParse->cChars = cChars;
        pParse->vaOffsets = vaOffsets;
        pParse->fWrap = fWrap;
    }
    return TRUE;
}

BOOL MWTR_ValidateTextBufferSpan(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess, _Inout_ PMWTR_LAYOUT pLayout, _In_ QWORD vaTextBuffer, _Out_ PMWTR_TEXTBUFFER_INFO pInfo)
{
    BYTE pb[MWTR_TEXTBUFFER_CB_MAX];
    BYTE pbRow[MWTR_ROW_CB_MAX];
    BYTE bActive;
    LONG iFirstRow, xCursor, yCursor, xLeft, yTop, xRight, yBottom;
    QWORD vaCharBuffer, vaRows, vaRowsEnd, vaRowsCap, cbRows, cRows64;
    DWORD cRows, cColumns;
    DWORD iSample[3], i;
    ZeroMemory(pInfo, sizeof(*pInfo));
    pInfo->pLayout = pLayout;
    if(!VMM_UADDR64_8(vaTextBuffer) || !MWTR_LayoutSanity(pLayout) || (pLayout->TextBuffer.cb > sizeof(pb)) ||
       !pLayout->TextBuffer.cb || !pLayout->Row.cb || (pLayout->Row.cb > sizeof(pbRow))) { return FALSE; }
    if(!VmmRead(H, pProcess, vaTextBuffer, pb, pLayout->TextBuffer.cb)) { return FALSE; }
    vaCharBuffer = *(PQWORD)(pb + pLayout->TextBuffer.oCharBuffer);
    vaRows = *(PQWORD)(pb + pLayout->TextBuffer.oStorageBegin);
    vaRowsEnd = *(PQWORD)(pb + pLayout->TextBuffer.oStorageEnd);
    vaRowsCap = *(PQWORD)(pb + pLayout->TextBuffer.oStorageCap);
    iFirstRow = MWTR_GetSignedCoord(pb + pLayout->TextBuffer.oFirstRow, pLayout->TextBuffer.cbCoord);
    xCursor = MWTR_GetSignedCoord(pb + pLayout->TextBuffer.oCursorX, pLayout->TextBuffer.cbCoord);
    yCursor = MWTR_GetSignedCoord(pb + pLayout->TextBuffer.oCursorY, pLayout->TextBuffer.cbCoord);
    xLeft = MWTR_GetSignedCoord(pb + pLayout->TextBuffer.oViewportLeft, pLayout->TextBuffer.cbCoord);
    yTop = MWTR_GetSignedCoord(pb + pLayout->TextBuffer.oViewportTop, pLayout->TextBuffer.cbCoord);
    xRight = MWTR_GetSignedCoord(pb + pLayout->TextBuffer.oViewportRight, pLayout->TextBuffer.cbCoord);
    yBottom = MWTR_GetSignedCoord(pb + pLayout->TextBuffer.oViewportBottom, pLayout->TextBuffer.cbCoord);
    bActive = pb[pLayout->TextBuffer.oActive];
    if(!VMM_UADDR64_8(vaCharBuffer) || !VMM_UADDR64_8(vaRows) || !VMM_UADDR64_8(vaRowsEnd) || !VMM_UADDR64_8(vaRowsCap)) { return FALSE; }
    if((vaRowsEnd < vaRows) || (vaRowsCap < vaRowsEnd)) { return FALSE; }
    cbRows = vaRowsEnd - vaRows;
    if(!cbRows || (cbRows % pLayout->Row.cb)) { return FALSE; }
    cRows64 = cbRows / pLayout->Row.cb;
    if(!cRows64 || (cRows64 > MWTR_MAX_ROWS)) { return FALSE; }
    if(((vaRowsCap - vaRows) % pLayout->Row.cb) || ((vaRowsCap - vaRows) / pLayout->Row.cb > MWTR_MAX_ROWS)) { return FALSE; }
    cRows = (DWORD)cRows64;
    if((xLeft != 0) || (yTop != 0) || (xRight < MWTR_MIN_COLUMNS - 1) || (xRight >= MWTR_MAX_COLUMNS)) { return FALSE; }
    if((yBottom < 0) || ((QWORD)yBottom + 1 != cRows64)) { return FALSE; }
    cColumns = (DWORD)xRight + 1;
    if((QWORD)cRows * cColumns > MWTR_MAX_SCREEN_CHARS) { return FALSE; }
    if((iFirstRow < 0) || ((DWORD)iFirstRow >= cRows)) { return FALSE; }
    if((xCursor < 0) || (xCursor > (LONG)cColumns) || (yCursor < 0) || ((DWORD)yCursor >= cRows)) { return FALSE; }
    if((*(PQWORD)(pb + pLayout->TextBuffer.oCursorParent) != vaTextBuffer) || (bActive > 1)) { return FALSE; }
    pInfo->vaTextBuffer = vaTextBuffer;
    pInfo->vaCharBuffer = vaCharBuffer;
    pInfo->vaRows = vaRows;
    pInfo->cRows = cRows;
    pInfo->cColumns = cColumns;
    pInfo->iFirstRow = (DWORD)iFirstRow;
    pInfo->xCursor = (DWORD)xCursor;
    pInfo->yCursor = (DWORD)yCursor;
    pInfo->cbRowStride = pLayout->Row.cb;
    // Validate rows at both ends of the vector and one adjacent row. This
    // verifies that _charBuffer is the contiguous backing allocation.
    iSample[0] = 0;
    iSample[1] = (cRows > 1) ? 1 : 0;
    iSample[2] = cRows - 1;
    for(i = 0; i < _countof(iSample); i++) {
        QWORD vaRow;
        if(!MWTR_AddQWORD(vaRows, (QWORD)iSample[i] * pLayout->Row.cb, &vaRow)) { return FALSE; }
        if(!VmmRead(H, pProcess, vaRow, pbRow, pLayout->Row.cb)) { return FALSE; }
        if(!MWTR_ValidateRowSpan(pbRow, pInfo, iSample[i], NULL)) { return FALSE; }
    }
    return TRUE;
}

/*
* Parse a validated TextBuffer. Rows are stored as a circular array. The
* logical order is (firstRow + y) % rowCount. Every logical row is considered;
* unused rows are removed by trimming the final blank/newline tail.
* CALLER DECREF: return
*/
POB_DATA MWTR_ParseTextBufferSpan(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess, _In_ PMWTR_TEXTBUFFER_INFO pInfo)
{
    BOOL f;
    DWORD i, iPhysical, cbRows, cchRawTotal = 0, cchOut = 0, cbuText = 0;
    DWORD cchRow, cchTrim, j;
    PBYTE pbRows = NULL;
    PMWTR_ROW_PARSE pRows = NULL, pR;
    PVMMOB_SCATTER hObScatter = NULL;
    LPWSTR wszRaw = NULL, wszOut = NULL;
    LPSTR uszText = NULL;
    POB_DATA pObText = NULL;
    QWORD cbRows64 = (QWORD)pInfo->cRows * pInfo->cbRowStride;
    QWORD cchOutMax;
    if((cbRows64 > 0xffffffff) || !cbRows64) { goto fail; }
    cbRows = (DWORD)cbRows64;
    if(!VmmReadAlloc(H, pProcess, pInfo->vaRows, &pbRows, cbRows, 0)) { goto fail; }
    if(!(pRows = LocalAlloc(LMEM_ZEROINIT, (SIZE_T)pInfo->cRows * sizeof(MWTR_ROW_PARSE)))) { goto fail; }
    // Phase 1: retrieve the terminal offset for each row. It gives the actual
    // UTF-16 storage length, including heap-backed grapheme/surrogate rows.
    if(!(hObScatter = VmmScatter_Initialize(H, VMM_FLAG_SCATTER_FORCE_PAGEREAD))) { goto fail; }
    for(i = 0; i < pInfo->cRows; i++) {
        iPhysical = (pInfo->iFirstRow + i) % pInfo->cRows;
        pR = pRows + i;
        if(!MWTR_ValidateRowSpan(pbRows + (SIZE_T)iPhysical * pInfo->cbRowStride, pInfo, iPhysical, pR)) { goto fail; }
        f = VmmScatter_PrepareEx(
            hObScatter,
            pR->vaOffsets + 2ULL * pInfo->cColumns,
            sizeof(WORD),
            (PBYTE)&pR->wCchRaw,
            &pR->cbReadOffset
        );
        if(!f) { goto fail; }
    }
    if(!VmmScatter_Execute(hObScatter, pProcess)) { goto fail; }
    Ob_DECREF_NULL(&hObScatter);
    for(i = 0; i < pInfo->cRows; i++) {
        pR = pRows + i;
        if(pR->cbReadOffset != sizeof(WORD)) { goto fail; }
        pR->cch = pR->wCchRaw & 0x7fff;
        if((pR->cch > pR->cChars) || (pR->cch > MWTR_MAX_ROW_CHARS)) { goto fail; }
        pR->oRaw = cchRawTotal;
        if(pR->cch > MWTR_MAX_SCREEN_CHARS - cchRawTotal) { goto fail; }
        cchRawTotal += pR->cch;
    }
    if(!(wszRaw = LocalAlloc(LMEM_ZEROINIT, ((SIZE_T)cchRawTotal + 1) * sizeof(WCHAR)))) { goto fail; }
    // Phase 2: retrieve the actual UTF-16 row text in one scatter operation.
    if(!(hObScatter = VmmScatter_Initialize(H, VMM_FLAG_SCATTER_FORCE_PAGEREAD))) { goto fail; }
    for(i = 0; i < pInfo->cRows; i++) {
        pR = pRows + i;
        if(!pR->cch) { continue; }
        f = VmmScatter_PrepareEx(
            hObScatter,
            pR->vaChars,
            pR->cch * sizeof(WCHAR),
            (PBYTE)(wszRaw + pR->oRaw),
            &pR->cbReadChars
        );
        if(!f) { goto fail; }
    }
    if(!VmmScatter_Execute(hObScatter, pProcess)) { goto fail; }
    Ob_DECREF_NULL(&hObScatter);
    for(i = 0; i < pInfo->cRows; i++) {
        pR = pRows + i;
        if(pR->cch && (pR->cbReadChars != pR->cch * sizeof(WCHAR))) { goto fail; }
    }
    cchOutMax = (QWORD)cchRawTotal + pInfo->cRows + 1;
    if(cchOutMax > MWTR_MAX_SCREEN_CHARS + MWTR_MAX_ROWS + 1) { goto fail; }
    if(!(wszOut = LocalAlloc(LMEM_ZEROINIT, (SIZE_T)cchOutMax * sizeof(WCHAR)))) { goto fail; }
    for(i = 0; i < pInfo->cRows; i++) {
        pR = pRows + i;
        cchRow = pR->cch;
        while(cchRow) {
            WCHAR ch = wszRaw[pR->oRaw + cchRow - 1];
            if((ch != 0) && (ch != 0x20)) { break; }
            cchRow--;
        }
        cchTrim = cchRow;
        for(j = 0; j < cchTrim; j++) {
            WCHAR ch = wszRaw[pR->oRaw + j];
            // Embedded NULs are empty terminal cells, not C string ends.
            wszOut[cchOut++] = ch ? ch : 0x20;
        }
        if(!pR->fWrap) {
            wszOut[cchOut++] = 0x0a;
        }
    }
    while(cchOut && (wszOut[cchOut - 1] == 0x0a)) { cchOut--; }
    wszOut[cchOut] = 0;
    if(!cchOut) {
        pObText = ObData_New(H, (PBYTE)"", 1);
        goto fail;
    }
    if(!CharUtil_WtoU(
        wszOut,
        cchOut,
        NULL,
        0,
        &uszText,
        &cbuText,
        CHARUTIL_FLAG_ALLOC | CHARUTIL_FLAG_BAD_UTF8CP_SOFTFAIL
    )) { goto fail; }
    if(!uszText || !cbuText || !(pObText = ObData_New(H, (PBYTE)uszText, cbuText))) { goto fail; }
fail:
    Ob_DECREF_NULL(&hObScatter);
    LocalFree(pbRows);
    LocalFree(pRows);
    LocalFree(wszRaw);
    LocalFree(wszOut);
    LocalFree(uszText);
    return pObText;
}

// ----------------------------------------------------------------------------
// PACKED CHARROW/VECTOR TEXT BUFFER VALIDATION AND EXTRACTION:
// ----------------------------------------------------------------------------

_Success_(return)
static BOOL MWTR_ValidateRowLegacy(_In_ PBYTE pbRow, _In_ QWORD vaRow, _In_ PMWTR_TEXTBUFFER_INFO pInfo, _In_ DWORD iPhysicalRow, _Out_opt_ PMWTR_ROW_PARSE pParse)
{
    BYTE fWrap, fDoubleByte;
    WORD cColumns;
    QWORD vaChars, cChars, cCapacity, vaInline;
    PMWTR_LAYOUT pLayout = pInfo->pLayout;
    if(!pLayout || (pLayout->tpBuffer != MWTR_BUFFER_LAYOUT_LEGACY) || (iPhysicalRow >= pInfo->cRows)) { return FALSE; }
    vaChars = *(PQWORD)(pbRow + pLayout->Row.oCharsPtr);
    cChars = *(PQWORD)(pbRow + pLayout->Row.oCharsCount);
    cCapacity = *(PQWORD)(pbRow + pLayout->Row.oCharsCapacity);
    cColumns = (WORD)MWTR_GetUnsignedCoord(pbRow + pLayout->Row.oColumns, pLayout->Row.cbCoord);
    fWrap = pbRow[pLayout->Row.oWrap];
    fDoubleByte = pbRow[pLayout->Row.oDoubleByte];
    if(!MWTR_AddQWORD(vaRow, pLayout->Row.oCharsInline, &vaInline)) { return FALSE; }
    if(!VMM_UADDR64(vaChars) || (cChars != pInfo->cColumns) || (cColumns != pInfo->cColumns)) { return FALSE; }
    if((cCapacity < cChars) || (cCapacity > MWTR_MAX_ROW_CHARS)) { return FALSE; }
    if((vaChars == vaInline) && (cCapacity != 122)) { return FALSE; }
    if((fWrap > 1) || (fDoubleByte > 1)) { return FALSE; }
    if(*(PQWORD)(pbRow + pLayout->Row.oCharParent) != vaRow) { return FALSE; }
    if(*(PQWORD)(pbRow + pLayout->Row.oTextBufferParent) != pInfo->vaTextBuffer) { return FALSE; }
    if(MWTR_GetSignedCoord(pbRow + pLayout->Row.oId, pLayout->Row.cbCoord) != (LONG)iPhysicalRow) { return FALSE; }
    if(pParse) {
        pParse->vaChars = vaChars;
        pParse->cChars = cChars;
        pParse->fWrap = fWrap;
    }
    return TRUE;
}

/*
* Fuzz the packed ROW tail from back-references and three independent rows.
* This covers the 16-bit and 32-bit coordinate variants without version/build
* tables and rejects the layout unless each required field is unique.
*/
BOOL MWTR_FuzzLegacyRowLayout(
    _In_ VMM_HANDLE H,
    _In_ PVMM_PROCESS pProcess,
    _Inout_ PMWTR_LAYOUT pLayout,
    _In_ PMWTR_TEXTBUFFER_INFO pInfo
)
{
    BYTE abRow[3][MWTR_ROW_CB_MAX];
    DWORD aiRow[3], cSample, i, j, o, cMatch;
    DWORD oCharParent = MWTR_OFFSET_INVALID, oTextParent = MWTR_OFFSET_INVALID, oTail = MWTR_OFFSET_INVALID;
    QWORD vaRow;
    if(!pLayout || !pInfo || !pLayout->Row.cb || (pLayout->Row.cb > MWTR_ROW_CB_MAX) || (pInfo->cRows < 2)) { return FALSE; }
    aiRow[0] = 0;
    aiRow[1] = 1;
    aiRow[2] = pInfo->cRows - 1;
    cSample = (aiRow[2] == aiRow[1]) ? 2 : 3;
    for(i = 0; i < cSample; i++) {
        if(!MWTR_AddQWORD(pInfo->vaRows, (QWORD)aiRow[i] * pLayout->Row.cb, &vaRow) ||
           !VmmRead(H, pProcess, vaRow, abRow[i], pLayout->Row.cb)) { return FALSE; }
    }
    cMatch = 0;
    for(o = 0; o + sizeof(QWORD) <= pLayout->Row.cb; o += sizeof(QWORD)) {
        for(i = 0; i < cSample; i++) {
            vaRow = pInfo->vaRows + (QWORD)aiRow[i] * pLayout->Row.cb;
            if(*(PQWORD)(abRow[i] + o) != vaRow) { break; }
        }
        if(i == cSample) { oCharParent = o; cMatch++; }
    }
    if(cMatch != 1) { return FALSE; }
    cMatch = 0;
    for(o = 0; o + sizeof(QWORD) <= pLayout->Row.cb; o += sizeof(QWORD)) {
        for(i = 0; i < cSample; i++) {
            if(*(PQWORD)(abRow[i] + o) != pInfo->vaTextBuffer) { break; }
        }
        if(i == cSample) { oTextParent = o; cMatch++; }
    }
    if(cMatch != 1) { return FALSE; }
    cMatch = 0;
    for(o = 0; o + 2 * pLayout->Row.cbCoord + 2 <= pLayout->Row.cb; o += pLayout->Row.cbCoord) {
        for(i = 0; i < cSample; i++) {
            j = o + 2 * pLayout->Row.cbCoord;
            if((MWTR_GetSignedCoord(abRow[i] + o, pLayout->Row.cbCoord) != (LONG)aiRow[i]) ||
               (MWTR_GetUnsignedCoord(abRow[i] + o + pLayout->Row.cbCoord, pLayout->Row.cbCoord) != pInfo->cColumns) ||
               (abRow[i][j] > 1) || (abRow[i][j + 1] > 1)) { break; }
        }
        if(i == cSample) { oTail = o; cMatch++; }
    }
    if(cMatch != 1) { return FALSE; }
    pLayout->Row.oCharParent = oCharParent;
    pLayout->Row.oTextBufferParent = oTextParent;
    pLayout->Row.oId = oTail;
    pLayout->Row.oColumns = oTail + pLayout->Row.cbCoord;
    pLayout->Row.oWrap = oTail + 2 * pLayout->Row.cbCoord;
    pLayout->Row.oDoubleByte = pLayout->Row.oWrap + 1;
    return TRUE;
}

BOOL MWTR_ValidateTextBufferLegacy(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess, _Inout_ PMWTR_LAYOUT pLayout, _In_ QWORD vaTextBuffer, _Out_ PMWTR_TEXTBUFFER_INFO pInfo)
{
    BYTE pb[MWTR_TEXTBUFFER_CB_MAX];
    BYTE pbRow[MWTR_ROW_CB_MAX];
    LONG iFirstRow, xCursor, yCursor, xLeft, yTop, xRight, yBottom;
    QWORD vaRows, vaRowsEnd, vaRowsCap, cbRows;
    DWORD cRows, cColumns, iSample[3], i;
    ZeroMemory(pInfo, sizeof(*pInfo));
    pInfo->pLayout = pLayout;
    if(!pLayout || (pLayout->tpBuffer != MWTR_BUFFER_LAYOUT_LEGACY) || !MWTR_LayoutSanity(pLayout) || !VMM_UADDR64_8(vaTextBuffer) ||
       !pLayout->TextBuffer.cb || (pLayout->TextBuffer.cb > sizeof(pb))) { return FALSE; }
    if(!VmmRead(H, pProcess, vaTextBuffer, pb, pLayout->TextBuffer.cb)) { return FALSE; }
    xLeft = MWTR_GetSignedCoord(pb + pLayout->TextBuffer.oViewportLeft, pLayout->TextBuffer.cbCoord);
    yTop = MWTR_GetSignedCoord(pb + pLayout->TextBuffer.oViewportTop, pLayout->TextBuffer.cbCoord);
    xRight = MWTR_GetSignedCoord(pb + pLayout->TextBuffer.oViewportRight, pLayout->TextBuffer.cbCoord);
    yBottom = MWTR_GetSignedCoord(pb + pLayout->TextBuffer.oViewportBottom, pLayout->TextBuffer.cbCoord);
    vaRows = *(PQWORD)(pb + pLayout->TextBuffer.oStorageBegin);
    vaRowsEnd = *(PQWORD)(pb + pLayout->TextBuffer.oStorageEnd);
    vaRowsCap = *(PQWORD)(pb + pLayout->TextBuffer.oStorageCap);
    xCursor = MWTR_GetSignedCoord(pb + pLayout->TextBuffer.oCursorX, pLayout->TextBuffer.cbCoord);
    yCursor = MWTR_GetSignedCoord(pb + pLayout->TextBuffer.oCursorY, pLayout->TextBuffer.cbCoord);
    iFirstRow = MWTR_GetSignedCoord(pb + pLayout->TextBuffer.oFirstRow, pLayout->TextBuffer.cbCoord);
    if(!VMM_UADDR64_8(vaRows) || !VMM_UADDR64_8(vaRowsEnd) || !VMM_UADDR64_8(vaRowsCap)) { return FALSE; }
    if((vaRowsEnd < vaRows) || (vaRowsCap < vaRowsEnd)) { return FALSE; }
    if((xLeft != 0) || (yTop != 0) || (xRight < MWTR_MIN_COLUMNS - 1) || (xRight >= MWTR_MAX_COLUMNS)) { return FALSE; }
    if((yBottom < 0) || ((QWORD)yBottom + 1 > MWTR_MAX_ROWS)) { return FALSE; }
    cRows = (DWORD)yBottom + 1;
    cbRows = vaRowsEnd - vaRows;
    if(!cbRows || (cbRows % cRows)) { return FALSE; }
    if((cbRows / cRows < 0x40) || (cbRows / cRows > MWTR_ROW_CB_MAX)) { return FALSE; }
    if(pLayout->Row.cb != cbRows / cRows) { return FALSE; }
    if(((vaRowsCap - vaRows) % pLayout->Row.cb) || ((vaRowsCap - vaRows) / pLayout->Row.cb > MWTR_MAX_ROWS)) { return FALSE; }
    cColumns = (DWORD)xRight + 1;
    if((iFirstRow < 0) || ((DWORD)iFirstRow >= cRows)) { return FALSE; }
    if((xCursor < 0) || ((DWORD)xCursor > cColumns) || (yCursor < 0) || ((DWORD)yCursor >= cRows)) { return FALSE; }
    if(*(PQWORD)(pb + pLayout->TextBuffer.oCursorParent) != vaTextBuffer) { return FALSE; }
    pInfo->vaTextBuffer = vaTextBuffer;
    pInfo->vaRows = vaRows;
    pInfo->cRows = cRows;
    pInfo->cColumns = cColumns;
    pInfo->iFirstRow = (DWORD)iFirstRow;
    pInfo->xCursor = (DWORD)xCursor;
    pInfo->yCursor = (DWORD)yCursor;
    pInfo->cbRowStride = pLayout->Row.cb;
    if((pLayout->Row.oCharParent == MWTR_OFFSET_INVALID) ||
       (pLayout->Row.oTextBufferParent == MWTR_OFFSET_INVALID) ||
       (pLayout->Row.oId == MWTR_OFFSET_INVALID) ||
       (pLayout->Row.oColumns == MWTR_OFFSET_INVALID) ||
       (pLayout->Row.oWrap == MWTR_OFFSET_INVALID) ||
       (pLayout->Row.oDoubleByte == MWTR_OFFSET_INVALID)) {
        if(!MWTR_FuzzLegacyRowLayout(H, pProcess, pLayout, pInfo)) { return FALSE; }
    }
    iSample[0] = 0;
    iSample[1] = (cRows > 1) ? 1 : 0;
    iSample[2] = cRows - 1;
    for(i = 0; i < _countof(iSample); i++) {
        QWORD vaRow;
        if(!MWTR_AddQWORD(vaRows, (QWORD)iSample[i] * pLayout->Row.cb, &vaRow)) { return FALSE; }
        if(!VmmRead(H, pProcess, vaRow, pbRow, pLayout->Row.cb)) { return FALSE; }
        if(!MWTR_ValidateRowLegacy(pbRow, vaRow, pInfo, iSample[i], NULL)) { return FALSE; }
    }
    return TRUE;
}

POB_DATA MWTR_ParseTextBufferLegacy(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess, _In_ PMWTR_TEXTBUFFER_INFO pInfo)
{
    BOOL f;
    DWORD i, j, iPhysical, cbRows, cbCells, cbCellsPerRow, cchOut = 0, cbuText = 0;
    DWORD cchRowBegin, cchRowEnd;
    QWORD cbRows64, cbCells64, cchOutMax;
    PBYTE pbRows = NULL, pbCells = NULL, pbCell;
    PMWTR_ROW_PARSE pRows = NULL, pR;
    PVMMOB_SCATTER hObScatter = NULL;
    LPWSTR wszOut = NULL;
    LPSTR uszText = NULL;
    POB_DATA pObText = NULL;
    cbRows64 = (QWORD)pInfo->cRows * pInfo->cbRowStride;
    cbCellsPerRow = pInfo->cColumns * MWTR_LEGACY_CELL_CB;
    cbCells64 = (QWORD)pInfo->cRows * cbCellsPerRow;
    cchOutMax = (QWORD)pInfo->cRows * pInfo->cColumns + pInfo->cRows + 1;
    if(!cbRows64 || (cbRows64 > 0xffffffff) || !cbCells64 || (cbCells64 > 3ULL * MWTR_MAX_SCREEN_CHARS)) { goto fail; }
    if(cchOutMax > MWTR_MAX_SCREEN_CHARS + MWTR_MAX_ROWS + 1) { goto fail; }
    cbRows = (DWORD)cbRows64;
    cbCells = (DWORD)cbCells64;
    if(!VmmReadAlloc(H, pProcess, pInfo->vaRows, &pbRows, cbRows, 0)) { goto fail; }
    if(!(pbCells = LocalAlloc(LMEM_ZEROINIT, cbCells))) { goto fail; }
    if(!(pRows = LocalAlloc(LMEM_ZEROINIT, (SIZE_T)pInfo->cRows * sizeof(MWTR_ROW_PARSE)))) { goto fail; }
    if(!(hObScatter = VmmScatter_Initialize(H, VMM_FLAG_SCATTER_FORCE_PAGEREAD))) { goto fail; }
    for(i = 0; i < pInfo->cRows; i++) {
        QWORD vaRow;
        iPhysical = (pInfo->iFirstRow + i) % pInfo->cRows;
        vaRow = pInfo->vaRows + (QWORD)iPhysical * pInfo->cbRowStride;
        pR = pRows + i;
        if(!MWTR_ValidateRowLegacy(pbRows + (SIZE_T)iPhysical * pInfo->cbRowStride, vaRow, pInfo, iPhysical, pR)) { goto fail; }
        pR->oRaw = i * cbCellsPerRow;
        f = VmmScatter_PrepareEx(hObScatter, pR->vaChars, cbCellsPerRow, pbCells + pR->oRaw, &pR->cbReadChars);
        if(!f) { goto fail; }
    }
    if(!VmmScatter_Execute(hObScatter, pProcess)) { goto fail; }
    Ob_DECREF_NULL(&hObScatter);
    if(!(wszOut = LocalAlloc(LMEM_ZEROINIT, (SIZE_T)cchOutMax * sizeof(WCHAR)))) { goto fail; }
    for(i = 0; i < pInfo->cRows; i++) {
        pR = pRows + i;
        if(pR->cbReadChars != cbCellsPerRow) { goto fail; }
        cchRowBegin = cchOut;
        for(j = 0; j < pInfo->cColumns; j++) {
            BYTE bAttr;
            WCHAR ch;
            pbCell = pbCells + pR->oRaw + (SIZE_T)j * MWTR_LEGACY_CELL_CB;
            bAttr = pbCell[2] & MWTR_LEGACY_CELL_ATTR_MASK;
            if((bAttr & 3) == 3) { goto fail; }
            // Multi-code-unit glyphs live in an MSVC unordered_map outside the
            // row. Refuse an inexact reconstruction until that map is decoded.
            if(bAttr & MWTR_LEGACY_CELL_ATTR_GLYPH_STORED) { goto fail; }
            if((bAttr & 3) == MWTR_LEGACY_CELL_ATTR_TRAILING) { continue; }
            ch = *(PWCHAR)(pbCell);
            wszOut[cchOut++] = ch;
        }
        cchRowEnd = cchOut;
        while((cchRowEnd > cchRowBegin) && (!wszOut[cchRowEnd - 1] || (wszOut[cchRowEnd - 1] == 0x20))) { cchRowEnd--; }
        cchOut = cchRowEnd;
        for(j = cchRowBegin; j < cchOut; j++) {
            if(!wszOut[j]) { wszOut[j] = 0x20; }
        }
        if(!pR->fWrap) { wszOut[cchOut++] = 0x0a; }
    }
    while(cchOut && (wszOut[cchOut - 1] == 0x0a)) { cchOut--; }
    wszOut[cchOut] = 0;
    if(!cchOut) {
        pObText = ObData_New(H, (PBYTE)"", 1);
        goto fail;
    }
    if(!CharUtil_WtoU(wszOut, cchOut, NULL, 0, &uszText, &cbuText, CHARUTIL_FLAG_ALLOC | CHARUTIL_FLAG_BAD_UTF8CP_SOFTFAIL)) { goto fail; }
    if(!uszText || !cbuText || !(pObText = ObData_New(H, (PBYTE)uszText, cbuText))) { goto fail; }
fail:
    Ob_DECREF_NULL(&hObScatter);
    LocalFree(pbRows);
    LocalFree(pbCells);
    LocalFree(pRows);
    LocalFree(wszOut);
    LocalFree(uszText);
    return pObText;
}

// ----------------------------------------------------------------------------
// RESERVED VIRTUAL-ARENA VALIDATION AND EXTRACTION:
// ----------------------------------------------------------------------------

static BOOL MWTR_ValidateOffsetsArena(_In_reads_(cReadable + 1) PWORD pwOffsets, _In_ DWORD cReadable, _In_ QWORD cChars, _Out_opt_ PDWORD pcch)
{
    DWORD i, oPrevious = 0, oCurrent;
    if(pcch) { *pcch = 0; }
    if((*(PWORD)((PBYTE)pwOffsets) & 0x7fff) != 0) { return FALSE; }
    for(i = 1; i <= cReadable; i++) {
        oCurrent = *(PWORD)((PBYTE)(pwOffsets + i)) & 0x7fff;
        if((oCurrent < oPrevious) || (oCurrent > cChars)) { return FALSE; }
        oPrevious = oCurrent;
    }
    if(pcch) { *pcch = oPrevious; }
    return TRUE;
}

_Success_(return)
static BOOL MWTR_ValidateRowArena(_In_ PBYTE pbRow, _In_ QWORD vaRow, _In_ PMWTR_TEXTBUFFER_INFO pInfo, _Out_opt_ PMWTR_ROW_PARSE pParse)
{
    BYTE bRendition, fWrap, fDoubleByte;
    WORD cColumns;
    DWORD cReadable;
    QWORD vaExpectedChars, vaExpectedOffsets;
    QWORD vaCharsBuffer, vaCharsHeap, vaChars, cChars, vaOffsets, cOffsets;
    PMWTR_LAYOUT pLayout = pInfo->pLayout;
    if(!pLayout || (pLayout->tpBuffer != MWTR_BUFFER_LAYOUT_ARENA)) { return FALSE; }
    if(!MWTR_AddQWORD(vaRow, pInfo->oRowChars, &vaExpectedChars) || !MWTR_AddQWORD(vaRow, pInfo->oRowOffsets, &vaExpectedOffsets)) { return FALSE; }
    vaCharsBuffer = *(PQWORD)(pbRow + pLayout->Row.oCharsBuffer);
    vaCharsHeap = *(PQWORD)(pbRow + pLayout->Row.oCharsHeap);
    vaChars = *(PQWORD)(pbRow + pLayout->Row.oCharsPtr);
    cChars = *(PQWORD)(pbRow + pLayout->Row.oCharsCount);
    vaOffsets = *(PQWORD)(pbRow + pLayout->Row.oOffsetsPtr);
    cOffsets = *(PQWORD)(pbRow + pLayout->Row.oOffsetsCount);
    cColumns = (WORD)MWTR_GetUnsignedCoord(pbRow + pLayout->Row.oColumns, pLayout->Row.cbCoord);
    bRendition = pbRow[pLayout->Row.oRendition];
    fWrap = pbRow[pLayout->Row.oWrap];
    fDoubleByte = pbRow[pLayout->Row.oDoubleByte];
    if((vaCharsBuffer != vaExpectedChars) || (vaOffsets != vaExpectedOffsets)) { return FALSE; }
    if((cOffsets != (QWORD)pInfo->cColumns + 1) || (cColumns != pInfo->cColumns)) { return FALSE; }
    if(!VMM_UADDR64(vaChars) || (vaChars & 1) || !VMM_UADDR64(vaOffsets) || (vaOffsets & 1)) { return FALSE; }
    if(!cChars || (cChars > MWTR_MAX_ROW_CHARS)) { return FALSE; }
    if((vaChars != vaCharsBuffer) && (!vaCharsHeap || (vaChars != vaCharsHeap))) { return FALSE; }
    if((bRendition > 3) || (fWrap > 1) || (fDoubleByte > 1)) { return FALSE; }
    if(!bRendition) {
        if(pInfo->cColumns < fDoubleByte) { return FALSE; }
        cReadable = pInfo->cColumns - fDoubleByte;
    } else {
        if(pInfo->cColumns < 2U * fDoubleByte) { return FALSE; }
        cReadable = (pInfo->cColumns - 2U * fDoubleByte) >> 1;
    }
    if(pParse) {
        pParse->vaChars = vaChars;
        pParse->cChars = cChars;
        pParse->vaOffsets = vaOffsets;
        pParse->cReadable = cReadable;
        pParse->fWrap = fWrap;
        pParse->fCommitted = TRUE;
    }
    return TRUE;
}

BOOL MWTR_ValidateTextBufferArena(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess, _Inout_ PMWTR_LAYOUT pLayout, _In_ QWORD vaTextBuffer, _Out_ PMWTR_TEXTBUFFER_INFO pInfo)
{
    DWORD cch;
    BYTE pb[MWTR_TEXTBUFFER_CB_MAX];
    BYTE pbRow[MWTR_ROW_CB_MAX];
    WORD wOffsets[MWTR_MAX_COLUMNS + 1];
    BYTE bActive;
    WORD cColumns, cRows;
    LONG iFirstRow, xCursor, yCursor;
    DWORD cbRowStride, oRowChars, oRowOffsets, cCommittedRows, cSamples = 0, i;
    DWORD iSample[2];
    QWORD vaRow, vaRows, vaRowsEnd, vaWatermark, cbRowStride64, oRowChars64, oRowOffsets64;
    QWORD cbSubBuffer, cbArena, vaExpectedEnd, cCommittedWithScratch;
    ZeroMemory(pInfo, sizeof(*pInfo));
    pInfo->pLayout = pLayout;
    if(!pLayout || (pLayout->tpBuffer != MWTR_BUFFER_LAYOUT_ARENA) || !MWTR_LayoutSanity(pLayout) || !VMM_UADDR64_8(vaTextBuffer) ||
       !pLayout->TextBuffer.cb || (pLayout->TextBuffer.cb > sizeof(pb)) || !pLayout->Row.cb ||
       (pLayout->Row.cb > sizeof(pbRow))) { return FALSE; }
    if(!VmmRead(H, pProcess, vaTextBuffer, pb, pLayout->TextBuffer.cb)) { return FALSE; }
    vaRows = *(PQWORD)(pb + pLayout->TextBuffer.oStorageBegin);
    vaRowsEnd = *(PQWORD)(pb + pLayout->TextBuffer.oBufferEnd);
    vaWatermark = *(PQWORD)(pb + pLayout->TextBuffer.oWatermark);
    cbRowStride64 = *(PQWORD)(pb + pLayout->TextBuffer.oRowStride);
    oRowChars64 = *(PQWORD)(pb + pLayout->TextBuffer.oCharsOffset);
    oRowOffsets64 = *(PQWORD)(pb + pLayout->TextBuffer.oOffsetsOffset);
    cColumns = *(PWORD)(pb + pLayout->TextBuffer.oWidth);
    cRows = *(PWORD)(pb + pLayout->TextBuffer.oHeight);
    iFirstRow = MWTR_GetSignedCoord(pb + pLayout->TextBuffer.oFirstRow, pLayout->TextBuffer.cbCoord);
    xCursor = MWTR_GetSignedCoord(pb + pLayout->TextBuffer.oCursorX, pLayout->TextBuffer.cbCoord);
    yCursor = MWTR_GetSignedCoord(pb + pLayout->TextBuffer.oCursorY, pLayout->TextBuffer.cbCoord);
    bActive = pb[pLayout->TextBuffer.oActive];
    if(!VMM_UADDR64_8(vaRows) || !VMM_UADDR64_8(vaRowsEnd) || !VMM_UADDR64_8(vaWatermark)) { return FALSE; }
    if(!cRows || (cRows > MWTR_MAX_ROWS) || (cColumns < MWTR_MIN_COLUMNS) || (cColumns > MWTR_MAX_COLUMNS)) { return FALSE; }
    if((QWORD)cRows * cColumns > MWTR_MAX_SCREEN_CHARS) { return FALSE; }
    if((cbRowStride64 > 0xffffffff) || (oRowChars64 > 0xffffffff) || (oRowOffsets64 > 0xffffffff)) { return FALSE; }
    cbRowStride = (DWORD)cbRowStride64;
    oRowChars = (DWORD)oRowChars64;
    oRowOffsets = (DWORD)oRowOffsets64;
    cbSubBuffer = (2ULL * cColumns + 16) & ~15ULL;
    if((oRowChars != pLayout->Row.cb) || (oRowOffsets != pLayout->Row.cb + cbSubBuffer) || (cbRowStride != pLayout->Row.cb + 2 * cbSubBuffer)) { return FALSE; }
    cbArena = ((QWORD)cRows + 1) * cbRowStride;
    if(!MWTR_AddQWORD(vaRows, cbArena, &vaExpectedEnd) || (vaRowsEnd != vaExpectedEnd)) { return FALSE; }
    if((vaWatermark < vaRows) || (vaWatermark > vaRowsEnd) || ((vaWatermark - vaRows) % cbRowStride)) { return FALSE; }
    cCommittedWithScratch = (vaWatermark - vaRows) / cbRowStride;
    if(cCommittedWithScratch > (QWORD)cRows + 1) { return FALSE; }
    cCommittedRows = cCommittedWithScratch ? (DWORD)cCommittedWithScratch - 1 : 0;
    if((iFirstRow < 0) || (iFirstRow >= cRows) || (xCursor < 0) || (xCursor > cColumns) || (yCursor < 0) || (yCursor >= cRows) || (bActive > 1)) { return FALSE; }
    if(*(PQWORD)(pb + pLayout->TextBuffer.oCursorParent) != vaTextBuffer) { return FALSE; }
    pInfo->vaTextBuffer = vaTextBuffer;
    pInfo->vaRows = vaRows;
    pInfo->vaRowsEnd = vaRowsEnd;
    pInfo->vaCommitWatermark = vaWatermark;
    pInfo->cRows = cRows;
    pInfo->cColumns = cColumns;
    pInfo->iFirstRow = (DWORD)iFirstRow;
    pInfo->xCursor = (DWORD)xCursor;
    pInfo->yCursor = (DWORD)yCursor;
    pInfo->cbRowStride = cbRowStride;
    pInfo->oRowChars = oRowChars;
    pInfo->oRowOffsets = oRowOffsets;
    pInfo->cCommittedRows = cCommittedRows;
    if(cCommittedRows) {
        iSample[cSamples++] = 0;
        if(cCommittedRows > 1) { iSample[cSamples++] = cCommittedRows - 1; }
    }
    for(i = 0; i < cSamples; i++) {
        vaRow = vaRows + ((QWORD)iSample[i] + 1) * cbRowStride;
        MWTR_ROW_PARSE Row = { 0 };
        if(!VmmRead(H, pProcess, vaRow, pbRow, pLayout->Row.cb) || !MWTR_ValidateRowArena(pbRow, vaRow, pInfo, &Row)) { return FALSE; }
        if(!VmmRead(H, pProcess, Row.vaOffsets, (PBYTE)wOffsets, (Row.cReadable + 1) * sizeof(WORD))) { return FALSE; }
        if(!MWTR_ValidateOffsetsArena(wOffsets, Row.cReadable, Row.cChars, &cch)) { return FALSE; }
    }
    return TRUE;
}

POB_DATA MWTR_ParseTextBufferArena(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess, _In_ PMWTR_TEXTBUFFER_INFO pInfo)
{
    BOOL f;
    WCHAR ch;
    DWORD i, j, iPhysical, cbHeaders, cbOffsetsPerRow, cbOffsets, cchRawTotal = 0, cchOut = 0, cbuText = 0;
    DWORD cch, cchRow, cchTrim;
    QWORD vaRow, cbHeaders64, cbOffsets64, cchOutMax;
    PBYTE pbHeaders = NULL, pbOffsets = NULL;
    PMWTR_ROW_PARSE pRows = NULL, pR;
    PVMMOB_SCATTER hObScatter = NULL;
    LPWSTR wszRaw = NULL, wszOut = NULL;
    LPSTR uszText = NULL;
    POB_DATA pObText = NULL;
    cbHeaders64 = (QWORD)pInfo->cRows * pInfo->oRowChars;
    cbOffsetsPerRow = (pInfo->cColumns + 1) * sizeof(WORD);
    cbOffsets64 = (QWORD)pInfo->cRows * cbOffsetsPerRow;
    if(!cbHeaders64 || (cbHeaders64 > 0xffffffff) || !cbOffsets64 || (cbOffsets64 > 0xffffffff)) { goto fail; }
    cbHeaders = (DWORD)cbHeaders64;
    cbOffsets = (DWORD)cbOffsets64;
    if(!(pbHeaders = LocalAlloc(LMEM_ZEROINIT, cbHeaders)) || !(pbOffsets = LocalAlloc(LMEM_ZEROINIT, cbOffsets))) { goto fail; }
    if(!(pRows = LocalAlloc(LMEM_ZEROINIT, (SIZE_T)pInfo->cRows * sizeof(MWTR_ROW_PARSE)))) { goto fail; }
    if(pInfo->cCommittedRows) {
        if(!(hObScatter = VmmScatter_Initialize(H, VMM_FLAG_SCATTER_FORCE_PAGEREAD))) { goto fail; }
        for(i = 0; i < pInfo->cRows; i++) {
            iPhysical = (pInfo->iFirstRow + i) % pInfo->cRows;
            if(iPhysical >= pInfo->cCommittedRows) { continue; }
            vaRow = pInfo->vaRows + ((QWORD)iPhysical + 1) * pInfo->cbRowStride;
            f = VmmScatter_PrepareEx(hObScatter, vaRow, pInfo->oRowChars, pbHeaders + (SIZE_T)i * pInfo->oRowChars, &pRows[i].cbReadChars);
            if(!f) { goto fail; }
        }
        if(!VmmScatter_Execute(hObScatter, pProcess)) { goto fail; }
        Ob_DECREF_NULL(&hObScatter);
        if(!(hObScatter = VmmScatter_Initialize(H, VMM_FLAG_SCATTER_FORCE_PAGEREAD))) { goto fail; }
        for(i = 0; i < pInfo->cRows; i++) {
            iPhysical = (pInfo->iFirstRow + i) % pInfo->cRows;
            pR = pRows + i;
            if(iPhysical >= pInfo->cCommittedRows) { continue; }
            if(pR->cbReadChars != pInfo->oRowChars) { goto fail; }
            vaRow = pInfo->vaRows + ((QWORD)iPhysical + 1) * pInfo->cbRowStride;
            if(!MWTR_ValidateRowArena(pbHeaders + (SIZE_T)i * pInfo->oRowChars, vaRow, pInfo, pR)) { goto fail; }
            f = VmmScatter_PrepareEx(hObScatter, pR->vaOffsets, cbOffsetsPerRow, pbOffsets + (SIZE_T)i * cbOffsetsPerRow, &pR->cbReadOffset);
            if(!f) { goto fail; }
        }
        if(!VmmScatter_Execute(hObScatter, pProcess)) { goto fail; }
        Ob_DECREF_NULL(&hObScatter);
    }
    for(i = 0; i < pInfo->cRows; i++) {
        cch = 0;
        pR = pRows + i;
        if(pR->fCommitted) {
            if(pR->cbReadOffset != cbOffsetsPerRow) { goto fail; }
            if(!MWTR_ValidateOffsetsArena((PWORD)(pbOffsets + (SIZE_T)i * cbOffsetsPerRow), pR->cReadable, pR->cChars, &cch)) { goto fail; }
        }
        pR->cch = cch;
        pR->oRaw = cchRawTotal;
        if(cch > MWTR_MAX_SCREEN_CHARS - cchRawTotal) { goto fail; }
        cchRawTotal += cch;
    }
    cchOutMax = (QWORD)cchRawTotal + pInfo->cRows + 1;
    if(cchOutMax > MWTR_MAX_SCREEN_CHARS + MWTR_MAX_ROWS + 1) { goto fail; }
    if(!(wszRaw = LocalAlloc(LMEM_ZEROINIT, ((SIZE_T)cchRawTotal + 1) * sizeof(WCHAR)))) { goto fail; }
    if(cchRawTotal) {
        if(!(hObScatter = VmmScatter_Initialize(H, VMM_FLAG_SCATTER_FORCE_PAGEREAD))) { goto fail; }
        for(i = 0; i < pInfo->cRows; i++) {
            pR = pRows + i;
            if(!pR->cch) { continue; }
            pR->cbReadChars = 0;
            f = VmmScatter_PrepareEx(hObScatter, pR->vaChars, pR->cch * sizeof(WCHAR), (PBYTE)(wszRaw + pR->oRaw), &pR->cbReadChars);
            if(!f) { goto fail; }
        }
        if(!VmmScatter_Execute(hObScatter, pProcess)) { goto fail; }
        Ob_DECREF_NULL(&hObScatter);
    }
    if(!(wszOut = LocalAlloc(LMEM_ZEROINIT, (SIZE_T)cchOutMax * sizeof(WCHAR)))) { goto fail; }
    for(i = 0; i < pInfo->cRows; i++) {
        pR = pRows + i;
        if(pR->cch && (pR->cbReadChars != pR->cch * sizeof(WCHAR))) { goto fail; }
        cchRow = pR->cch;
        while(cchRow) {
            ch = wszRaw[pR->oRaw + cchRow - 1];
            if(ch && (ch != 0x20)) { break; }
            cchRow--;
        }
        cchTrim = cchRow;
        for(j = 0; j < cchTrim; j++) {
            ch = wszRaw[pR->oRaw + j];
            wszOut[cchOut++] = ch ? ch : 0x20;
        }
        if(!pR->fWrap) { wszOut[cchOut++] = 0x0a; }
    }
    while(cchOut && (wszOut[cchOut - 1] == 0x0a)) { cchOut--; }
    wszOut[cchOut] = 0;
    if(!cchOut) {
        pObText = ObData_New(H, (PBYTE)"", 1);
        goto fail;
    }
    if(!CharUtil_WtoU(wszOut, cchOut, NULL, 0, &uszText, &cbuText, CHARUTIL_FLAG_ALLOC | CHARUTIL_FLAG_BAD_UTF8CP_SOFTFAIL)) { goto fail; }
    if(!uszText || !cbuText || !(pObText = ObData_New(H, (PBYTE)uszText, cbuText))) { goto fail; }
fail:
    Ob_DECREF_NULL(&hObScatter);
    LocalFree(pbHeaders);
    LocalFree(pbOffsets);
    LocalFree(pRows);
    LocalFree(wszRaw);
    LocalFree(wszOut);
    LocalFree(uszText);
    return pObText;
}

BOOL MWTR_ValidateTextBuffer(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess, _Inout_ PMWTR_LAYOUT pLayout, _In_ QWORD vaTextBuffer, _Out_ PMWTR_TEXTBUFFER_INFO pInfo)
{
    if(!pLayout) { return FALSE; }
    switch(pLayout->tpBuffer) {
        case MWTR_BUFFER_LAYOUT_LEGACY:
            return MWTR_ValidateTextBufferLegacy(H, pProcess, pLayout, vaTextBuffer, pInfo);
        case MWTR_BUFFER_LAYOUT_SPAN:
            return MWTR_ValidateTextBufferSpan(H, pProcess, pLayout, vaTextBuffer, pInfo);
        case MWTR_BUFFER_LAYOUT_ARENA:
            return MWTR_ValidateTextBufferArena(H, pProcess, pLayout, vaTextBuffer, pInfo);
        default:
            ZeroMemory(pInfo, sizeof(*pInfo));
            return FALSE;
    }
}

POB_DATA MWTR_ParseTextBuffer(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess, _In_ PMWTR_TEXTBUFFER_INFO pInfo)
{
    if(!pInfo || !pInfo->pLayout) { return NULL; }
    switch(pInfo->pLayout->tpBuffer) {
        case MWTR_BUFFER_LAYOUT_LEGACY:
            return MWTR_ParseTextBufferLegacy(H, pProcess, pInfo);
        case MWTR_BUFFER_LAYOUT_SPAN:
            return MWTR_ParseTextBufferSpan(H, pProcess, pInfo);
        case MWTR_BUFFER_LAYOUT_ARENA:
            return MWTR_ParseTextBufferArena(H, pProcess, pInfo);
        default:
            return NULL;
    }
}

/*
* Recover commands from recognizable default PowerShell and cmd.exe prompts.
* This is intentionally exposed as heuristic data: without OSC 133 / FinalTerm
* shell-integration marks Windows Terminal cannot distinguish input from output.
* CALLER DECREF: return
*/
POB_DATA MWTR_ParseCommandsHeuristic(_In_ VMM_HANDLE H, _In_ POB_DATA pObText, _Out_ PDWORD pcCommands)
{
    BOOL fPowerShell, fCmd;
    DWORD i = 0, iLine, iEnd, iPrompt, iCommand, iCommandEnd, cbText, cbOut = 0;
    PBYTE pbOut = NULL;
    POB_DATA pObCommands = NULL;
    *pcCommands = 0;
    if(!pObText || !pObText->ObHdr.cbData) { return NULL; }
    cbText = pObText->ObHdr.cbData - 1;
    if(!cbText || !(pbOut = LocalAlloc(0, (SIZE_T)cbText + 1))) { return NULL; }
    while(i < cbText) {
        iLine = i;
        while((i < cbText) && (pObText->pb[i] != 0x0a)) { i++; }
        iEnd = i;
        if((iEnd > iLine) && (pObText->pb[iEnd - 1] == 0x0d)) { iEnd--; }
        fPowerShell = (iEnd >= iLine + 4) && !memcmp(pObText->pb + iLine, "PS ", 3);
        fCmd = (iEnd >= iLine + 3) &&
            (((pObText->pb[iLine] >= 'A') && (pObText->pb[iLine] <= 'Z')) ||
             ((pObText->pb[iLine] >= 'a') && (pObText->pb[iLine] <= 'z'))) &&
            (pObText->pb[iLine + 1] == ':');
        if(fPowerShell || fCmd) {
            iPrompt = fPowerShell ? iLine + 3 : iLine + 2;
            while((iPrompt < iEnd) && (pObText->pb[iPrompt] != '>')) { iPrompt++; }
            if(iPrompt < iEnd) {
                iCommand = iPrompt + 1;
                while((iCommand < iEnd) && ((pObText->pb[iCommand] == ' ') || (pObText->pb[iCommand] == '\t'))) { iCommand++; }
                iCommandEnd = iEnd;
                while((iCommandEnd > iCommand) && ((pObText->pb[iCommandEnd - 1] == ' ') || (pObText->pb[iCommandEnd - 1] == '\t'))) { iCommandEnd--; }
                if(iCommandEnd > iCommand) {
                    if(cbOut) { pbOut[cbOut++] = 0x0a; }
                    memcpy(pbOut + cbOut, pObText->pb + iCommand, iCommandEnd - iCommand);
                    cbOut += iCommandEnd - iCommand;
                    (*pcCommands)++;
                }
            }
        }
        if(i < cbText) { i++; }
    }
    if(cbOut) {
        pbOut[cbOut++] = 0;
        pObCommands = ObData_New(H, pbOut, cbOut);
    }
    LocalFree(pbOut);
    return pObCommands;
}



// ----------------------------------------------------------------------------
// STATIC INFODB LAYOUT RESOLUTION:
// ----------------------------------------------------------------------------

VOID MWTR_ParseVersion(_In_opt_ LPCSTR uszVersion, _Out_ PDWORD pdwMajor, _Out_ PDWORD pdwMinor)
{
    LPSTR uszEnd = NULL;
    *pdwMajor = 0;
    *pdwMinor = 0;
    if(!uszVersion || !uszVersion[0]) { return; }
    *pdwMajor = strtoul(uszVersion, &uszEnd, 10);
    if(!uszEnd || (*uszEnd != '.')) { *pdwMajor = 0; return; }
    *pdwMinor = strtoul(uszEnd + 1, &uszEnd, 10);
}

BOOL MWTR_ControlModule(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess, _Out_ PMWTR_LAYOUT pLayout)
{
    static LPCSTR auszModule[] = { "Microsoft.Terminal.Control.dll", "TerminalControl.dll" };
    DWORD i;
    LPCSTR uszVersion;
    IMAGE_SECTION_HEADER SectionRdata = { 0 }, SectionText = { 0 };
    PVMMOB_MAP_MODULE pObModuleMap = NULL;
    PVMM_MAP_MODULEENTRY peModule = NULL;
    ZeroMemory(pLayout, sizeof(*pLayout));
    for(i = 0; i < _countof(auszModule); i++) {
        if(!VmmMap_GetModuleEntryEx(
            H,
            pProcess,
            0,
            auszModule[i],
            VMM_MODULE_FLAG_VERSIONINFO,
            &pObModuleMap,
            &peModule
        ) || !peModule || !VMM_UADDR64_8(peModule->vaBase) || !peModule->cbImageSize ||
           (peModule->cbImageSize > MWTR_CONTROL_IMAGE_CB_MAX)) {
            Ob_DECREF_NULL(&pObModuleMap);
            continue;
        }
        if(!PE_SectionGetFromName(H, pProcess, peModule->vaBase, ".rdata", &SectionRdata) ||
           !PE_SectionGetFromName(H, pProcess, peModule->vaBase, ".text", &SectionText) ||
           !SectionRdata.Misc.VirtualSize || !SectionText.Misc.VirtualSize ||
           (SectionRdata.VirtualAddress >= peModule->cbImageSize) ||
           (SectionText.VirtualAddress >= peModule->cbImageSize) ||
           (SectionRdata.Misc.VirtualSize > peModule->cbImageSize - SectionRdata.VirtualAddress) ||
           (SectionText.Misc.VirtualSize > peModule->cbImageSize - SectionText.VirtualAddress)) {
            Ob_DECREF_NULL(&pObModuleMap);
            continue;
        }
        strcpy_s(pLayout->uszModule, sizeof(pLayout->uszModule), auszModule[i]);
        pLayout->vaControl = peModule->vaBase;
        pLayout->cbControl = peModule->cbImageSize;
        pLayout->vaRdata = peModule->vaBase + SectionRdata.VirtualAddress;
        pLayout->vaRdataEnd = pLayout->vaRdata + SectionRdata.Misc.VirtualSize;
        pLayout->vaText = peModule->vaBase + SectionText.VirtualAddress;
        pLayout->vaTextEnd = pLayout->vaText + SectionText.Misc.VirtualSize;
        uszVersion = (peModule->pExVersionInfo && peModule->pExVersionInfo->uszFileVersion && peModule->pExVersionInfo->uszFileVersion[0]) ?
            peModule->pExVersionInfo->uszFileVersion :
            ((peModule->pExVersionInfo && peModule->pExVersionInfo->uszProductVersion) ? peModule->pExVersionInfo->uszProductVersion : NULL);
        MWTR_ParseVersion(uszVersion, &pLayout->dwVersionMajor, &pLayout->dwVersionMinor);
        pLayout->cbTerminal = MWTR_TERMINAL_CB_MAX;
        pLayout->oMainTextBuffer = MWTR_OFFSET_INVALID;
        pLayout->oAltTextBuffer = MWTR_OFFSET_INVALID;
        Ob_DECREF(pObModuleMap);
        return TRUE;
    }
    return FALSE;
}

/*
* Retrieve the Windows Terminal layout from the static info database.
*/
_Success_(return)
BOOL MWTR_InfoDBResolveLayout(_In_ VMM_HANDLE H, _In_ PCMWTR_LAYOUT pModule, _Out_ PMWTR_LAYOUT pLayout)
{
    DWORD dwBufferType, fHasAltTextBuffer;
#define MWTR_INFODB_OFFSET(_type, _child, _field) InfoDB_TypeChildOffset_Static(H, "wt", (_type), (_child), &(_field))
    MWTR_LayoutCopyModule(pModule, pLayout);
    if(!InfoDB_TypeSize_Static(H, "wt", "Terminal", &pLayout->cbTerminal) ||
       !InfoDB_TypeSize_Static(H, "wt", "TextBuffer", &pLayout->TextBuffer.cb) ||
       !InfoDB_TypeSize_Static(H, "wt", "ROW", &pLayout->Row.cb) ||
       !MWTR_INFODB_OFFSET("_LAYOUT", "BufferType", dwBufferType) ||
       !MWTR_INFODB_OFFSET("_LAYOUT", "TextBufferCoordSize", pLayout->TextBuffer.cbCoord) ||
       !MWTR_INFODB_OFFSET("_LAYOUT", "RowCoordSize", pLayout->Row.cbCoord) ||
       !MWTR_INFODB_OFFSET("_LAYOUT", "SearchVftRva", pLayout->rvaSearchVft) ||
       !MWTR_INFODB_OFFSET("_LAYOUT", "TerminalFromSearch", pLayout->oTerminalFromSearch) ||
       !MWTR_INFODB_OFFSET("_LAYOUT", "HasAltTextBuffer", fHasAltTextBuffer) ||
       !MWTR_INFODB_OFFSET("Terminal", "MainTextBuffer", pLayout->oMainTextBuffer) ||
       !MWTR_INFODB_OFFSET("TextBuffer", "FirstRow", pLayout->TextBuffer.oFirstRow) ||
       !MWTR_INFODB_OFFSET("TextBuffer", "CursorParent", pLayout->TextBuffer.oCursorParent) ||
       !MWTR_INFODB_OFFSET("TextBuffer", "CursorX", pLayout->TextBuffer.oCursorX) ||
       !MWTR_INFODB_OFFSET("TextBuffer", "CursorY", pLayout->TextBuffer.oCursorY)) { return FALSE; }
    if((dwBufferType < MWTR_BUFFER_LAYOUT_LEGACY) || (dwBufferType > MWTR_BUFFER_LAYOUT_ARENA) ||
       (fHasAltTextBuffer > 1)) { return FALSE; }
    pLayout->tpBuffer = (MWTR_BUFFER_LAYOUT)dwBufferType;
    pLayout->fHasAltTextBuffer = fHasAltTextBuffer;
    if(pLayout->fHasAltTextBuffer &&
       !MWTR_INFODB_OFFSET("Terminal", "AltTextBuffer", pLayout->oAltTextBuffer)) { return FALSE; }
    if(pLayout->tpBuffer == MWTR_BUFFER_LAYOUT_LEGACY) {
        if(!MWTR_INFODB_OFFSET("TextBuffer", "ViewportLeft", pLayout->TextBuffer.oViewportLeft) ||
           !MWTR_INFODB_OFFSET("TextBuffer", "ViewportTop", pLayout->TextBuffer.oViewportTop) ||
           !MWTR_INFODB_OFFSET("TextBuffer", "ViewportRight", pLayout->TextBuffer.oViewportRight) ||
           !MWTR_INFODB_OFFSET("TextBuffer", "ViewportBottom", pLayout->TextBuffer.oViewportBottom) ||
           !MWTR_INFODB_OFFSET("TextBuffer", "StorageBegin", pLayout->TextBuffer.oStorageBegin) ||
           !MWTR_INFODB_OFFSET("TextBuffer", "StorageEnd", pLayout->TextBuffer.oStorageEnd) ||
           !MWTR_INFODB_OFFSET("TextBuffer", "StorageCap", pLayout->TextBuffer.oStorageCap) ||
           !MWTR_INFODB_OFFSET("ROW", "CharsPtr", pLayout->Row.oCharsPtr) ||
           !MWTR_INFODB_OFFSET("ROW", "CharsCount", pLayout->Row.oCharsCount) ||
           !MWTR_INFODB_OFFSET("ROW", "CharsCapacity", pLayout->Row.oCharsCapacity) ||
           !MWTR_INFODB_OFFSET("ROW", "CharsInline", pLayout->Row.oCharsInline) ||
           !MWTR_INFODB_OFFSET("ROW", "CharParent", pLayout->Row.oCharParent) ||
           !MWTR_INFODB_OFFSET("ROW", "TextBufferParent", pLayout->Row.oTextBufferParent) ||
           !MWTR_INFODB_OFFSET("ROW", "Id", pLayout->Row.oId) ||
           !MWTR_INFODB_OFFSET("ROW", "Columns", pLayout->Row.oColumns) ||
           !MWTR_INFODB_OFFSET("ROW", "Wrap", pLayout->Row.oWrap) ||
           !MWTR_INFODB_OFFSET("ROW", "DoubleByte", pLayout->Row.oDoubleByte)) { return FALSE; }
    } else {
        if(!MWTR_INFODB_OFFSET("TextBuffer", "Active", pLayout->TextBuffer.oActive) ||
           !MWTR_INFODB_OFFSET("ROW", "CharsBuffer", pLayout->Row.oCharsBuffer) ||
           !MWTR_INFODB_OFFSET("ROW", "CharsHeap", pLayout->Row.oCharsHeap) ||
           !MWTR_INFODB_OFFSET("ROW", "CharsPtr", pLayout->Row.oCharsPtr) ||
           !MWTR_INFODB_OFFSET("ROW", "CharsCount", pLayout->Row.oCharsCount) ||
           !MWTR_INFODB_OFFSET("ROW", "OffsetsPtr", pLayout->Row.oOffsetsPtr) ||
           !MWTR_INFODB_OFFSET("ROW", "OffsetsCount", pLayout->Row.oOffsetsCount) ||
           !MWTR_INFODB_OFFSET("ROW", "Columns", pLayout->Row.oColumns) ||
           !MWTR_INFODB_OFFSET("ROW", "Wrap", pLayout->Row.oWrap)) { return FALSE; }
        if(pLayout->tpBuffer == MWTR_BUFFER_LAYOUT_SPAN) {
            if(!MWTR_INFODB_OFFSET("TextBuffer", "CharBuffer", pLayout->TextBuffer.oCharBuffer) ||
               !MWTR_INFODB_OFFSET("TextBuffer", "StorageBegin", pLayout->TextBuffer.oStorageBegin) ||
               !MWTR_INFODB_OFFSET("TextBuffer", "StorageEnd", pLayout->TextBuffer.oStorageEnd) ||
               !MWTR_INFODB_OFFSET("TextBuffer", "StorageCap", pLayout->TextBuffer.oStorageCap) ||
               !MWTR_INFODB_OFFSET("TextBuffer", "ViewportLeft", pLayout->TextBuffer.oViewportLeft) ||
               !MWTR_INFODB_OFFSET("TextBuffer", "ViewportTop", pLayout->TextBuffer.oViewportTop) ||
               !MWTR_INFODB_OFFSET("TextBuffer", "ViewportRight", pLayout->TextBuffer.oViewportRight) ||
               !MWTR_INFODB_OFFSET("TextBuffer", "ViewportBottom", pLayout->TextBuffer.oViewportBottom)) { return FALSE; }
        } else {
            if(!MWTR_INFODB_OFFSET("TextBuffer", "Buffer", pLayout->TextBuffer.oStorageBegin) ||
               !MWTR_INFODB_OFFSET("TextBuffer", "BufferEnd", pLayout->TextBuffer.oBufferEnd) ||
               !MWTR_INFODB_OFFSET("TextBuffer", "CommitWatermark", pLayout->TextBuffer.oWatermark) ||
               !MWTR_INFODB_OFFSET("TextBuffer", "BufferRowStride", pLayout->TextBuffer.oRowStride) ||
               !MWTR_INFODB_OFFSET("TextBuffer", "BufferOffsetChars", pLayout->TextBuffer.oCharsOffset) ||
               !MWTR_INFODB_OFFSET("TextBuffer", "BufferOffsetCharOffsets", pLayout->TextBuffer.oOffsetsOffset) ||
               !MWTR_INFODB_OFFSET("TextBuffer", "Width", pLayout->TextBuffer.oWidth) ||
               !MWTR_INFODB_OFFSET("TextBuffer", "Height", pLayout->TextBuffer.oHeight) ||
               !MWTR_INFODB_OFFSET("ROW", "Rendition", pLayout->Row.oRendition) ||
               !MWTR_INFODB_OFFSET("ROW", "DoubleByte", pLayout->Row.oDoubleByte)) { return FALSE; }
        }
    }
#undef MWTR_INFODB_OFFSET
    if(!pLayout->rvaSearchVft || (pLayout->rvaSearchVft >= pLayout->cbControl) || !MWTR_LayoutSanity(pLayout)) { return FALSE; }
    _snprintf_s(
        pLayout->uszName,
        sizeof(pLayout->uszName),
        _TRUNCATE,
        "%u.%u %s InfoDB",
        pLayout->dwVersionMajor,
        pLayout->dwVersionMinor,
        (pLayout->tpBuffer == MWTR_BUFFER_LAYOUT_LEGACY) ? "packed" :
        ((pLayout->tpBuffer == MWTR_BUFFER_LAYOUT_SPAN) ? "span-vector" : "arena")
    );
    return TRUE;
}

BOOL MWTR_IsVftPointer(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess, _In_ PCMWTR_LAYOUT pLayout, _In_ QWORD vaVft)
{
    QWORD vaFunction;
    if((pLayout->vaRdataEnd <= pLayout->vaRdata) ||
       (pLayout->vaRdataEnd - pLayout->vaRdata < sizeof(QWORD)) ||
       (pLayout->vaTextEnd <= pLayout->vaText) ||
       !VMM_UADDR64_8(vaVft) || (vaVft < pLayout->vaRdata) || (vaVft > pLayout->vaRdataEnd - sizeof(QWORD)) ||
       !VmmRead(H, pProcess, vaVft, (PBYTE)&vaFunction, sizeof(vaFunction))) { return FALSE; }
    return (vaFunction >= pLayout->vaText) && (vaFunction < pLayout->vaTextEnd);
}

BOOL MWTR_ValidateTerminal(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess, _Inout_ PMWTR_LAYOUT pLayout, _In_ QWORD vaSearchHit, _Out_ PMWTR_DISCOVERED pResult)
{
    BYTE pbTerminal[MWTR_TERMINAL_CB_MAX];
    QWORD vaTerminal, vaTextBuffer, vaAltTextBuffer, vaSearchVft, vaExpectedSearch;
    MWTR_LAYOUT Resolved;
    MWTR_TEXTBUFFER_INFO MainTextBuffer = { 0 }, AltTextBuffer = { 0 };
    ZeroMemory(pResult, sizeof(*pResult));
    if(!pLayout || !VMM_UADDR64_8(vaSearchHit) || !pLayout->rvaSearchVft || !pLayout->cbTerminal ||
       (pLayout->cbTerminal > sizeof(pbTerminal)) ||
       !MWTR_AddQWORD(vaSearchHit, pLayout->oTerminalFromSearch, &vaTerminal) || !VMM_UADDR64_8(vaTerminal)) { return FALSE; }
    if(!MWTR_AddQWORD(pLayout->vaControl, pLayout->rvaSearchVft, &vaExpectedSearch) ||
       !VmmRead(H, pProcess, vaSearchHit, (PBYTE)&vaSearchVft, sizeof(vaSearchVft)) ||
       (vaSearchVft != vaExpectedSearch) ||
       !VmmRead2(H, pProcess, vaTerminal, pbTerminal, pLayout->cbTerminal, VMM_FLAG_ZEROPAD_ON_FAIL) ||
       !MWTR_IsVftPointer(H, pProcess, pLayout, *(PQWORD)pbTerminal)) { return FALSE; }
    Resolved = *pLayout;
    if(!MWTR_OffsetInBounds(Resolved.oMainTextBuffer, sizeof(QWORD), Resolved.cbTerminal) || (Resolved.fHasAltTextBuffer && !MWTR_OffsetInBounds(Resolved.oAltTextBuffer, sizeof(QWORD), Resolved.cbTerminal))) { return FALSE; }
    vaTextBuffer = *(PQWORD)(pbTerminal + Resolved.oMainTextBuffer);
    vaAltTextBuffer = Resolved.fHasAltTextBuffer ? *(PQWORD)(pbTerminal + Resolved.oAltTextBuffer) : 0;
    if(!MWTR_ValidateTextBuffer(H, pProcess, &Resolved, vaTextBuffer, &MainTextBuffer)) { return FALSE; }
    if(vaAltTextBuffer && (!VMM_UADDR64_8(vaAltTextBuffer) || !MWTR_ValidateTextBuffer(H, pProcess, &Resolved, vaAltTextBuffer, &AltTextBuffer))) { return FALSE; }
    if(vaAltTextBuffer && (AltTextBuffer.vaTextBuffer != vaAltTextBuffer)) { return FALSE; }
    *pLayout = Resolved;
    MainTextBuffer.pLayout = pLayout;
    AltTextBuffer.pLayout = pLayout;
    pResult->TextBuffer = vaAltTextBuffer ? AltTextBuffer : MainTextBuffer;
    pResult->TextBuffer.pLayout = pLayout;
    pResult->vaTerminal = vaTerminal;
    pResult->vaMainTextBuffer = vaTextBuffer;
    pResult->vaAltTextBuffer = vaAltTextBuffer;
    return TRUE;
}

BOOL MWTR_SearchResultCB(_In_ PVMM_MEMORY_SEARCH_CONTEXT ctxs, _In_ QWORD va, _In_ DWORD iSearch)
{
    DWORD i;
    QWORD vaVft;
    MWTR_LAYOUT Candidate;
    MWTR_DISCOVERED Discovered = { 0 };
    PMWTR_SEARCH_RESULT pResult = (PMWTR_SEARCH_RESULT)ctxs->pvUserPtrOpt;
    UNREFERENCED_PARAMETER(iSearch);
    if(!pResult || !VmmRead(pResult->H, pResult->pProcess, va, (PBYTE)&vaVft, sizeof(vaVft))) { return TRUE; }
    if(!MWTR_IsVftPointer(pResult->H, pResult->pProcess, pResult->pLayout, vaVft)) { return TRUE; }
    if(++pResult->cHits > MWTR_MAX_SEARCH_HITS) {
        pResult->fLimit = TRUE;
        return FALSE;
    }
    Candidate = *pResult->pLayout;
    if(!MWTR_ValidateTerminal(pResult->H, pResult->pProcess, &Candidate, va, &Discovered)) { return TRUE; }
    *pResult->pLayout = Candidate;
    Discovered.TextBuffer.pLayout = pResult->pLayout;
    for(i = 0; i < pResult->cTerminals; i++) {
        if((pResult->Terminal[i].vaTerminal == Discovered.vaTerminal) ||
           (pResult->Terminal[i].TextBuffer.vaTextBuffer == Discovered.TextBuffer.vaTextBuffer)) { return TRUE; }
    }
    if(pResult->cTerminals >= MWTR_MAX_TERMINALS) {
        pResult->fLimit = TRUE;
        return FALSE;
    }
    pResult->Terminal[pResult->cTerminals++] = Discovered;
    return TRUE;
}

DWORD MWTR_BuildSearchEntries(_In_ PCMWTR_LAYOUT pLayout, _Out_ PVMM_MEMORY_SEARCH_CONTEXT_SEARCHENTRY pEntry)
{
    QWORD vaSearch;
    ZeroMemory(pEntry, sizeof(*pEntry));
    if(!pLayout->rvaSearchVft || !MWTR_AddQWORD(pLayout->vaControl, pLayout->rvaSearchVft, &vaSearch)) { return 0; }
    pEntry->cbAlign = 8;
    pEntry->cb = sizeof(QWORD);
    memcpy(pEntry->pb, &vaSearch, sizeof(vaSearch));
    return 1;
}

static BOOL MWTR_SearchVadFilterCB(_In_ PVMM_MEMORY_SEARCH_CONTEXT ctxs, _In_opt_ PVMM_MAP_PTEENTRY pePte, _In_opt_ PVMM_MAP_VADENTRY peVad)
{
    BOOL fResult;
    QWORD cbVad;
    PMWTR_SEARCH_RESULT pResult = (PMWTR_SEARCH_RESULT)ctxs->pvUserPtrOpt;
    if(!peVad || pResult->fLimit) { return FALSE; }
    if(peVad->fImage || peVad->fFile || peVad->fPageFile || peVad->fStack || peVad->fTeb) { return FALSE; }
    cbVad = peVad->vaEnd - peVad->vaStart + 1;
    if(!cbVad) { return FALSE; }
    if((cbVad > MWTR_MAX_SEARCH_HEAP_VAD_BYTES) || (cbVad + pResult->cbTotalBytesSearched > MWTR_MAX_SEARCH_HEAP_VAD_BYTES)) { 
        pResult->fLimit = TRUE;
        return FALSE;
    }
    fResult = peVad->fHeap;
    if(!fResult) {
        // Segment Heap backing VADs are not always tagged fHeap. Include otherwise
        // anonymous allocator VADs, but exclude mapped data, stacks and empty
        // reservations.
        fResult = (peVad->cVadExPages || peVad->CommitCharge) && !(peVad->Protection & 2) && !peVad->vaPrototypePte && !peVad->cbPrototypePte;
    }
    if(fResult) {
        pResult->cbTotalBytesSearched += cbVad;
    }
    return fResult;
}

_Success_(return)
BOOL MWTR_RunTerminalSearch(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess, _Inout_ PMWTR_LAYOUT pLayout, _Out_ PMWTR_SEARCH_RESULT pResult)
{
    BOOL fResult = FALSE;
    VMM_MEMORY_SEARCH_CONTEXT_SEARCHENTRY SearchEntry;
    VMM_MEMORY_SEARCH_CONTEXT Search = { 0 };
    DWORD cSearch = MWTR_BuildSearchEntries(pLayout, &SearchEntry);
    QWORD cbSearchTotal = 0;
    if(!cSearch) { return FALSE; }
    ZeroMemory(pResult, sizeof(*pResult));
    pResult->H = H;
    pResult->pProcess = pProcess;
    pResult->pLayout = pLayout;
    Search.cSearch = cSearch;
    Search.pSearch = &SearchEntry;
    Search.vaMin = 0;
    Search.vaMax = 0x0000800000000000;
    Search.fForceVAD = TRUE;
    Search.pvUserPtrOpt = pResult;
    Search.pfnResultOptCB = MWTR_SearchResultCB;
    Search.pfnFilterOptCB = MWTR_SearchVadFilterCB;
    fResult = VmmSearch(H, pProcess, &Search, NULL);
    return fResult || pResult->fLimit;
}

int MWTR_DiscoveredCompare(_In_ const void *p1, _In_ const void *p2)
{
    QWORD va1 = ((PMWTR_DISCOVERED)p1)->vaTerminal;
    QWORD va2 = ((PMWTR_DISCOVERED)p2)->vaTerminal;
    return (va1 < va2) ? -1 : ((va1 > va2) ? 1 : 0);
}

BOOL MWTR_SearchResultValidateFull(_In_ VMM_HANDLE H, _In_ PVMM_PROCESS pProcess, _Inout_ PMWTR_LAYOUT pLayout, _In_ PMWTR_SEARCH_RESULT pSearchResult)
{
    BOOL f;
    DWORD i;
    QWORD cbText = 0;
    for(i = 0; i < pSearchResult->cTerminals; i++) {
        MWTR_DISCOVERED DiscoveredAfter = { 0 };
        PMWTR_DISCOVERED pDiscovered = pSearchResult->Terminal + i;
        POB_DATA pObText;
        pDiscovered->TextBuffer.pLayout = pLayout;
        pObText = MWTR_ParseTextBuffer(H, pProcess, &pDiscovered->TextBuffer);
        if(!pObText || (pObText->ObHdr.cbData > MWTR_MAX_CONTEXT_TEXT_BYTES - cbText)) {
            Ob_DECREF(pObText);
            return FALSE;
        }
        cbText += pObText->ObHdr.cbData;
        Ob_DECREF(pObText);
        f = (pDiscovered->vaTerminal < pLayout->oTerminalFromSearch);
        f = f || !MWTR_ValidateTerminal(H, pProcess, pLayout, pDiscovered->vaTerminal - pLayout->oTerminalFromSearch, &DiscoveredAfter);
        f = f || memcmp(pDiscovered, &DiscoveredAfter, sizeof(DiscoveredAfter));
        if(f) { return FALSE; }
    }
    return TRUE;
}



// ----------------------------------------------------------------------------
// CONTEXT INITIALIZATION AND CACHING:
// ----------------------------------------------------------------------------

VOID MWTR_ContextCleanupCB(_In_ PVOID pOb)
{
    DWORD i;
    POB_MWTR_CONTEXT ctx = (POB_MWTR_CONTEXT)pOb;
    Ob_DECREF(ctx->pmfTerminal);
    Ob_DECREF(ctx->pmfTerminals);
    Ob_DECREF(ctx->pmfCommandsHeuristic);
    for(i = 0; i < ctx->cTerminals; i++) {
        Ob_DECREF(ctx->Terminal[i].pObText);
        Ob_DECREF(ctx->Terminal[i].pObCommandsHeuristic);
    }
}

/*
* Initialize a Windows Terminal context for one process.
* CALLER DECREF: return
*/
POB_MWTR_CONTEXT MWTR_Initialize(_In_ VMM_HANDLE H, _In_ VMM_MODULE_ID MID, _In_ PVMM_PROCESS pProcess)
{
    BOOL fSearch, fFull = FALSE;
    DWORD i, cDiscovered = 0;
    DWORD cbText, cbCommands;
    QWORD cbContextText = 0;
    PMWTR_TERMINAL pTerminal;
    POB_MWTR_CONTEXT ctxUser = NULL;
    MWTR_LAYOUT ModuleLayout = { 0 };
    MWTR_DISCOVERED Discovered[MWTR_MAX_TERMINALS] = { 0 };
    MWTR_SEARCH_RESULT SearchResult = { 0 };
    VMMSTATISTICS_LOG Statistics = { 0 };
    VmmStatisticsLogStart(H, MID, LOGLEVEL_6_TRACE, pProcess, &Statistics, "INIT_WINTERM");
    if(!(ctxUser = Ob_AllocEx(H, 'MWTR', LMEM_ZEROINIT, sizeof(OB_MWTR_CONTEXT), MWTR_ContextCleanupCB, NULL))) { goto fail; }
    if(!MWTR_ControlModule(H, pProcess, &ModuleLayout)) {
        VmmLog(H, MID, LOGLEVEL_6_TRACE, "Fail: Windows Terminal control DLL or required PE sections not found. PID:[%i]", pProcess->dwPID);
        goto fail;
    }
    if(!MWTR_InfoDBResolveLayout(H, &ModuleLayout, &ctxUser->Layout)) {
        VmmLog(H, MID, LOGLEVEL_5_DEBUG, "Fail: Windows Terminal InfoDB layout resolution failed. PID:[%i]", pProcess->dwPID);
        goto fail;
    }
    fSearch = MWTR_RunTerminalSearch(H, pProcess, &ctxUser->Layout, &SearchResult);
    if(fSearch && !SearchResult.fLimit && SearchResult.cTerminals) {
        fFull = MWTR_SearchResultValidateFull(H, pProcess, &ctxUser->Layout, &SearchResult);
    }
    VmmLog(
        H,
        MID,
        LOGLEVEL_6_TRACE,
        "Info: Windows Terminal InfoDB search result:%u full:%u limit:%u terminals:%u. PID:[%i]",
        fSearch,
        fFull,
        SearchResult.fLimit,
        SearchResult.cTerminals,
        pProcess->dwPID
    );
    if(!fSearch || SearchResult.fLimit || !SearchResult.cTerminals || !fFull) {
        VmmLog(H, MID, LOGLEVEL_5_DEBUG, "Fail: Windows Terminal InfoDB-derived layout did not validate. PID:[%i]", pProcess->dwPID);
        goto fail;
    }
    cDiscovered = SearchResult.cTerminals;
    VmmLog(H, MID, LOGLEVEL_5_DEBUG, "Info: Windows Terminal InfoDB layout resolved as %s. PID:[%i]", ctxUser->Layout.uszName, pProcess->dwPID);
    memcpy(Discovered, SearchResult.Terminal, (SIZE_T)cDiscovered * sizeof(MWTR_DISCOVERED));
    for(i = 0; i < cDiscovered; i++) { Discovered[i].TextBuffer.pLayout = &ctxUser->Layout; }
    qsort(Discovered, cDiscovered, sizeof(MWTR_DISCOVERED), MWTR_DiscoveredCompare);
    for(i = 0; i < cDiscovered; i++) {
        POB_DATA pObText = MWTR_ParseTextBuffer(H, pProcess, &Discovered[i].TextBuffer);
        POB_DATA pObTextVerify = NULL;
        MWTR_DISCOVERED DiscoveredAfter = { 0 };
        if(!pObText) { goto fail; }
        if(H->dev.fVolatile) {
            pObTextVerify = MWTR_ParseTextBuffer(H, pProcess, &Discovered[i].TextBuffer);
            if(!pObTextVerify || (pObTextVerify->ObHdr.cbData != pObText->ObHdr.cbData) ||
                memcmp(pObTextVerify->pb, pObText->pb, pObText->ObHdr.cbData)) {
                Ob_DECREF(pObTextVerify);
                Ob_DECREF(pObText);
                goto fail;
            }
            Ob_DECREF_NULL(&pObTextVerify);
        }
        // Reject a volatile snapshot if the circular buffer changed while it
        // was being extracted. A later slow refresh will retry the parse.
        if((Discovered[i].vaTerminal < ctxUser->Layout.oTerminalFromSearch) ||
            !MWTR_ValidateTerminal(H, pProcess, &ctxUser->Layout, Discovered[i].vaTerminal - ctxUser->Layout.oTerminalFromSearch, &DiscoveredAfter) ||
            memcmp(&Discovered[i], &DiscoveredAfter, sizeof(DiscoveredAfter))) {
            Ob_DECREF(pObText);
            goto fail;
        }
        if(pObText->ObHdr.cbData > MWTR_MAX_CONTEXT_TEXT_BYTES - cbContextText) {
            Ob_DECREF(pObText);
            goto fail;
        }
        cbContextText += pObText->ObHdr.cbData;
        pTerminal = ctxUser->Terminal + ctxUser->cTerminals++;
        pTerminal->vaTerminal = Discovered[i].vaTerminal;
        pTerminal->vaMainTextBuffer = Discovered[i].vaMainTextBuffer;
        pTerminal->vaAltTextBuffer = Discovered[i].vaAltTextBuffer;
        pTerminal->TextBuffer = Discovered[i].TextBuffer;
        pTerminal->pObText = pObText;
        pTerminal->pObCommandsHeuristic = MWTR_ParseCommandsHeuristic(H, pObText, &pTerminal->cCommandsHeuristic);
        if(pTerminal->pObCommandsHeuristic) {
            if(pTerminal->pObCommandsHeuristic->ObHdr.cbData > MWTR_MAX_CONTEXT_TEXT_BYTES - cbContextText) {
                Ob_DECREF_NULL(&pTerminal->pObCommandsHeuristic);
                pTerminal->cCommandsHeuristic = 0;
            } else {
                cbContextText += pTerminal->pObCommandsHeuristic->ObHdr.cbData;
            }
        }
        VmmLog(
            H,
            MID,
            LOGLEVEL_6_TRACE,
            "Info: parsed Windows Terminal %s buffer. PID:[%i] terminal:[%llx] textbuffer:[%llx] rows:[%i] cols:[%i] bytes:[%i]",
            ctxUser->Layout.uszName,
            pProcess->dwPID,
            pTerminal->vaTerminal,
            pTerminal->TextBuffer.vaTextBuffer,
            pTerminal->TextBuffer.cRows,
            pTerminal->TextBuffer.cColumns,
            VMM_DEC_IFNOZERO(pTerminal->pObText->ObHdr.cbData)
        );
    }
    if(!ctxUser->cTerminals) { goto fail; }
    if(!(ctxUser->pmfTerminal = ObMemFile_New(H, H->vmm.pObCacheMapObCompressedShared))) { goto fail; }
    if(!(ctxUser->pmfTerminals = ObMemFile_New(H, H->vmm.pObCacheMapObCompressedShared))) { goto fail; }
    if(!(ctxUser->pmfCommandsHeuristic = ObMemFile_New(H, H->vmm.pObCacheMapObCompressedShared))) { goto fail; }
    if(!ObMemFile_AppendString(ctxUser->pmfTerminals, MWTR_TERMINALS_HEADER)) { goto fail; }
    for(i = 0; i < ctxUser->cTerminals; i++) {
        pTerminal = ctxUser->Terminal + i;
        cbText = VMM_DEC_IFNOZERO(pTerminal->pObText->ObHdr.cbData);
        if(!ObMemFile_AppendStringEx(
            ctxUser->pmfTerminals,
            "%03i   %016llx %016llx %016llx %016llx %6i %6i %8i %7i %7i %i %8i\n",
            i,
            pTerminal->vaTerminal,
            pTerminal->TextBuffer.vaTextBuffer,
            pTerminal->vaMainTextBuffer,
            pTerminal->vaAltTextBuffer,
            pTerminal->TextBuffer.cRows,
            pTerminal->TextBuffer.cColumns,
            pTerminal->TextBuffer.iFirstRow,
            pTerminal->TextBuffer.xCursor,
            pTerminal->TextBuffer.yCursor,
            cbText,
            pTerminal->cCommandsHeuristic
        )) { goto fail; }
        if(ctxUser->cTerminals > 1) {
            if(!ObMemFile_AppendStringEx(ctxUser->pmfTerminal, "===== terminal-%03i.txt =====\n", i)) { goto fail; }
        }
        if(cbText && !ObMemFile_Append(ctxUser->pmfTerminal, pTerminal->pObText->pb, cbText)) { goto fail; }
        if((ctxUser->cTerminals > 1) && (i + 1 < ctxUser->cTerminals)) {
            if(!ObMemFile_AppendString(ctxUser->pmfTerminal, "\n\n")) { goto fail; }
        }
        if(pTerminal->pObCommandsHeuristic) {
            cbCommands = VMM_DEC_IFNOZERO(pTerminal->pObCommandsHeuristic->ObHdr.cbData);
            if(ObMemFile_Size(ctxUser->pmfCommandsHeuristic) && !ObMemFile_AppendString(ctxUser->pmfCommandsHeuristic, "\n")) { goto fail; }
            if(ctxUser->cTerminals > 1 && !ObMemFile_AppendStringEx(ctxUser->pmfCommandsHeuristic, "[terminal-%03i]\n", i)) { goto fail; }
            if(cbCommands && !ObMemFile_Append(ctxUser->pmfCommandsHeuristic, pTerminal->pObCommandsHeuristic->pb, cbCommands)) { goto fail; }
        }
    }
    ctxUser->fValid = TRUE;
fail:
    VmmStatisticsLogEnd(H, &Statistics, "INIT_WINTERM");
    return ctxUser;
}

/*
* Retrieve the (cached) context for one process.
* CALLER DECREF: return
*/
POB_MWTR_CONTEXT MWTR_GetContext(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_CONTEXT ctxP)
{
    POB_MWTR_CONTEXT ctxOb = NULL;
    PVMM_PROCESS pProcess = ctxP->pProcess;
    if(!pProcess) { return NULL; }
    if(!(ctxOb = ObMap_GetByKey((POB_MAP)ctxP->ctxM, pProcess->dwPID))) {
        EnterCriticalSection(&pProcess->LockPlugin);
        if(!(ctxOb = ObMap_GetByKey((POB_MAP)ctxP->ctxM, pProcess->dwPID))) {
            ctxOb = MWTR_Initialize(H, ctxP->MID, pProcess);
            ObMap_Push((POB_MAP)ctxP->ctxM, pProcess->dwPID, ctxOb);
        }
        LeaveCriticalSection(&pProcess->LockPlugin);
    }
    return ctxOb;
}



// ----------------------------------------------------------------------------
// MODULE BASE FUNCTIONALITY:
// ----------------------------------------------------------------------------

_Success_(return == STATUS_SUCCESS)
NTSTATUS MWTR_Read(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_CONTEXT ctxP, _Out_ PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset)
{
    DWORD i;
    CHAR uszName[32];
    NTSTATUS nt = VMMDLL_STATUS_FILE_INVALID;
    POB_MWTR_CONTEXT ctxOb = MWTR_GetContext(H, ctxP);
    if(!ctxOb || !ctxOb->fValid) { goto finish; }
    if(CharUtil_StrEquals(ctxP->uszPath, "terminal.txt", TRUE)) {
        nt = ObMemFile_ReadFile(ctxOb->pmfTerminal, pb, cb, pcbRead, cbOffset);
        goto finish;
    }
    if(CharUtil_StrEquals(ctxP->uszPath, "terminals.txt", TRUE)) {
        nt = ObMemFile_ReadFile(ctxOb->pmfTerminals, pb, cb, pcbRead, cbOffset);
        goto finish;
    }
    if(CharUtil_StrEquals(ctxP->uszPath, "commands-heuristic.txt", TRUE) && ObMemFile_Size(ctxOb->pmfCommandsHeuristic)) {
        nt = ObMemFile_ReadFile(ctxOb->pmfCommandsHeuristic, pb, cb, pcbRead, cbOffset);
        goto finish;
    }
    for(i = 0; i < ctxOb->cTerminals; i++) {
        _snprintf_s(uszName, _countof(uszName), _TRUNCATE, "terminal-%03u.txt", i);
        if(CharUtil_StrEquals(ctxP->uszPath, uszName, TRUE)) {
            nt = Util_VfsReadFile_FromPBYTE(ctxOb->Terminal[i].pObText->pb, VMM_DEC_IFNOZERO(ctxOb->Terminal[i].pObText->ObHdr.cbData), pb, cb, pcbRead, cbOffset);
            goto finish;
        }
    }
finish:
    Ob_DECREF(ctxOb);
    return nt;
}

BOOL MWTR_List(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_CONTEXT ctxP, _Inout_ PHANDLE pFileList)
{
    DWORD i, cbText;
    CHAR uszName[32];
    POB_MWTR_CONTEXT ctxOb = MWTR_GetContext(H, ctxP);
    if(!ctxP->uszPath[0] && ctxOb && ctxOb->fValid) {
        VMMDLL_VfsList_AddFile(pFileList, "terminal.txt", ObMemFile_Size(ctxOb->pmfTerminal), NULL);
        VMMDLL_VfsList_AddFile(pFileList, "terminals.txt", ObMemFile_Size(ctxOb->pmfTerminals), NULL);
        VMMDLL_VfsList_AddFile(pFileList, "commands-heuristic.txt", ObMemFile_Size(ctxOb->pmfCommandsHeuristic), NULL);
        for(i = 0; i < ctxOb->cTerminals; i++) {
            _snprintf_s(uszName, _countof(uszName), _TRUNCATE, "terminal-%03i.txt", i);
            cbText = VMM_DEC_IFNOZERO(ctxOb->Terminal[i].pObText->ObHdr.cbData);
            VMMDLL_VfsList_AddFile(pFileList, uszName, cbText, NULL);
        }
    }
    Ob_DECREF(ctxOb);
    return TRUE;
}

VOID MWTR_Close(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_CONTEXT ctxP)
{
    Ob_DECREF(ctxP->ctxM);
}

VOID MWTR_Notify(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_CONTEXT ctxP, _In_ DWORD fEvent, _In_opt_ PVOID pvEvent, _In_opt_ DWORD cbEvent)
{
    if(fEvent == VMMDLL_PLUGIN_NOTIFY_REFRESH_SLOW) {
        ObMap_Clear((POB_MAP)ctxP->ctxM);
    }
}

BOOL MWTR_VisibleModule(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_CONTEXT ctxP)
{
    PVMM_PROCESS pProcess = ctxP->pProcess;
    if(!pProcess) { return FALSE; }
    if(*(PQWORD)pProcess->szName != 0x5473776f646e6957) { return FALSE; }
    if(CharUtil_StrEquals(pProcess->szName, "WindowsTermina", TRUE)) { return TRUE; }
    return pProcess->pObPersistent && pProcess->pObPersistent->uszNameLong && CharUtil_StrEquals(pProcess->pObPersistent->uszNameLong, "WindowsTerminal.exe", TRUE);
}

/*
* Initialize the Windows Terminal process module.
*/
VOID M_ProcWinTerm_Initialize(_In_ VMM_HANDLE H, _Inout_ PVMMDLL_PLUGIN_REGINFO pRI)
{
    if((pRI->magic != VMMDLL_PLUGIN_REGINFO_MAGIC) || (pRI->wVersion != VMMDLL_PLUGIN_REGINFO_VERSION)) { return; }
    if((pRI->tpSystem != VMMDLL_SYSTEM_WINDOWS_64) || (pRI->tpMemoryModel != VMMDLL_MEMORYMODEL_X64)) { return; }
    if(!(pRI->reg_info.ctxM = (PVMMDLL_PLUGIN_INTERNAL_CONTEXT)ObMap_New(H, OB_MAP_FLAGS_OBJECT_OB))) { return; }
    if(H->vmm.kernel.dwVersionBuild < 22000) { return; }    // WT parsing supported on win11+
    strcpy_s(pRI->reg_info.uszPathName, 128, "\\winterm");
    pRI->reg_info.fRootModule = FALSE;
    pRI->reg_info.fProcessModule = TRUE;
    pRI->reg_fn.pfnVisibleModule = MWTR_VisibleModule;
    pRI->reg_fn.pfnNotify = MWTR_Notify;
    pRI->reg_fn.pfnList = MWTR_List;
    pRI->reg_fn.pfnRead = MWTR_Read;
    pRI->reg_fn.pfnClose = MWTR_Close;
    pRI->pfnPluginManager_Register(H, pRI);
}
