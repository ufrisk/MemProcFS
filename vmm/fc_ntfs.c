// fc_ntfs.c : implementation of functions related to ntfs file system forensics.
//
// NTFS MFT documenation: https://flatcap.org/linux-ntfs/ntfs/index.html
//
// (c) Ulf Frisk, 2020
// Author: Ulf Frisk, pcileech@frizk.net
//

#include "fc.h"
#include "vmm.h"
#include "vmmdll.h"
#include "mm_pfn.h"
#include "pluginmanager.h"
#include "util.h"

//-----------------------------------------------------------------------------
// NTFS MFT WINDOWS DEFINES AND TYPEDEFS BELOW:
//-----------------------------------------------------------------------------

typedef struct tdNTFS_REF {
    QWORD SegmentNumber : 48;
    QWORD SequenceNumber : 16;
} NTFS_REF, *PNTFS_REF;

typedef struct tdNTFS_FILE_RECORD {
    DWORD   Signature;                  // +000 : signature 'FILE'
    WORD    UpdateSequenceArrayOffset;  // +004 : (most common 0x30)
    WORD    UpdateSequenceArraySize;    // +006 : (most common 0x03)
    QWORD   LogFileSequenceNumber;      // +008
    WORD    SequenceNumber;             // +010
    WORD    HardLinkCount;              // +012
    WORD    FirstAttributeOffset;       // +014
    WORD    Flags;                      // +016 : 0x01 = inuse, 0x02 = directory
    DWORD   RealSize;                   // +018 : size on disk
    DWORD   AllocatedSize;              // +01c : size (QWORD aligned)
    NTFS_REF BaseFileRecordSegment;     // +020 : 0 if base record
    WORD    NextAttributeId;            // +028
    WORD    _Pad;                       // +02a
    DWORD   MftRecordNumber;            // +02c : mft record id
} NTFS_FILE_RECORD, *PNTFS_FILE_RECORD;

#define NTFS_ATTR_TYPE_STANDARD_INFORMATION     0x10
#define NTFS_ATTR_TYPE_ATTRIBUTE_LIST           0x20
#define NTFS_ATTR_TYPE_FILE_NAME                0x30
#define NTFS_ATTR_TYPE_OBJECT_ID                0x40
#define NTFS_ATTR_TYPE_SECURITY_DESCRIPTOR      0x50
#define NTFS_ATTR_TYPE_VOLUME_NAME              0x60
#define NTFS_ATTR_TYPE_VOLUME_INFORMATION       0x70
#define NTFS_ATTR_TYPE_DATA                     0x80
#define NTFS_ATTR_TYPE_INDEX_ROOT               0x90
#define NTFS_ATTR_TYPE_INDEX_ALLOCATION         0xA0
#define NTFS_ATTR_TYPE_BITMAP                   0xB0
#define NTFS_ATTR_TYPE_REPARSE_POINT            0xC0
#define NTFS_ATTR_TYPE_EA_INFORMATION           0xD0
#define NTFS_ATTR_TYPE_EA                       0xE0
#define NTFS_ATTR_TYPE_PROPERTY_SET             0xF0
#define NTFS_ATTR_TYPE_LOGGED_UTILITY_STREAM    0x100

typedef struct tdNTFS_ATTR {
    DWORD Type;                         // +000
    DWORD Length;                       // +004
    BYTE fNonResident;                  // +008
    BYTE NameLength;                    // +009
    WORD NameOffset;                    // +00a
    WORD Flags;                         // +00c
    WORD AttrId;                        // +00e
    DWORD AttrLength;                   // +010
    WORD AttrOffset;                    // +014
    BYTE fIndexed;                      // +016
    BYTE _Pad;                          // +017
} NTFS_ATTR, *PNTFS_ATTR;

#define NTFS_STDINFO_PERMISSION_READONLY        0x0001
#define NTFS_STDINFO_PERMISSION_HIDDEN          0x0002
#define NTFS_STDINFO_PERMISSION_SYSTEM          0x0004
#define NTFS_STDINFO_PERMISSION_ARCHIVE         0x0020
#define NTFS_STDINFO_PERMISSION_DEVICE          0x0040
#define NTFS_STDINFO_PERMISSION_TEMPORARY       0x0100
#define NTFS_STDINFO_PERMISSION_SPARSE          0x0200
#define NTFS_STDINFO_PERMISSION_REPARSE         0x0400
#define NTFS_STDINFO_PERMISSION_COMPRESSED      0x0800
#define NTFS_STDINFO_PERMISSION_OFFLINE         0x1000
#define NTFS_STDINFO_PERMISSION_NOINDEX         0x2000
#define NTFS_STDINFO_PERMISSION_ENCRYPTED       0x4000

typedef struct tdNTFS_STANDARD_INFORMATION {
    QWORD TimeCreate;                   // +000
    QWORD TimeAlter;                    // +008
    QWORD TimeModify;                   // +010
    QWORD TimeRead;                     // +018
    DWORD DosFilePermissions;           // +020
    DWORD MaxVersions;                  // +024
    DWORD Version;                      // +028
    DWORD ClassId;                      // +02c
    DWORD OwnerId;                      // +030
    DWORD SecurityId;                   // +034
    QWORD QuotaCharged;                 // +038
    QWORD UpdateSequenceNumber;         // +040
} NTFS_STANDARD_INFORMATION, *PNTFS_STANDARD_INFORMATION;

typedef struct tdNTFS_OBJECT_ID {
    BYTE ObjectId[16];                  // +000
    BYTE BirthVolumeId[16];             // +010
    BYTE BirthObjectId[16];             // +020
    BYTE DomainId[16];                  // +030
} NTFS_OBJECT_ID, *PNTFS_OBJECT_ID;

#define NTFS_FILENAME_NAMESPACE_POSIX           0x00
#define NTFS_FILENAME_NAMESPACE_WIN32           0x01
#define NTFS_FILENAME_NAMESPACE_DOS             0x02
#define NTFS_FILENAME_NAMESPACE_WIN32DOS        0x03

typedef struct tdNTFS_FILE_NAME {
    NTFS_REF ParentDirectory;           // +000
    QWORD TimeCreate;                   // +008
    QWORD TimeAlter;                    // +010
    QWORD TimeModify;                   // +018
    QWORD TimeRead;                     // +020
    QWORD SizeAllocated;                // +028
    QWORD SizeReal;                     // +030
    DWORD Flags;                        // +038
    DWORD _Reserved;                    // +03c
    BYTE NameLength;                    // +040
    BYTE NameSpace;                     // +041
    WCHAR Name[];                       // +042
} NTFS_FILE_NAME, *PNTFS_FILE_NAME;



//-----------------------------------------------------------------------------
// NTFS INTERNAL DEFINES AND TYPEDEFS BELOW:
//-----------------------------------------------------------------------------

typedef struct tdFCNTFS {
    QWORD pa;
    QWORD va;
    struct {
        QWORD qwLogFileSequenceNumber;  // LSN used for duplicate checks.
        DWORD dwIdFs;                   // file system id (idfs) [internal only] of this file system (in case of multiple)
        DWORD dwIdParent;               // id of parent directory
        struct tdFCNTFS* pNextAll;      // next entry within same idfs domain (all)
        struct tdFCNTFS* pNextFile;     // next entry within same idfs domain (file)
        struct tdFCNTFS* pNextDir;      // next entry within same idfs domain (directory)
    } Setup;
    struct tdFCNTFS *pParent;           // parent entry [not counted as reference]
    struct tdFCNTFS *pChild;            // 1st child entry [not counted as reference]
    struct tdFCNTFS *pSibling;          // sibling entry list [not counted as reference]
    BOOL fDir;
    QWORD ftCreate;
    QWORD ftModify;
    QWORD ftRead;
    QWORD cbFileSize;
    QWORD qwHashThis;  
    WORD wName_SeqNbr;                  // collision counter for wszName (in same directory)
    WORD wIdThis_SeqNbr;                // collision counter for dwIdThis
    DWORD dwIdThis;                     // ntfs id of this file/directory
    DWORD iMap;                         // index (after setup)
    WORD iDirDepth;                     // directory depth from GlobalRoot
    WORD cbFileSizeMftResident;
    WORD Flags;
    DWORD cszu8Name;
    QWORD cszu8NameSum;
    WCHAR wszName[0];
} FCNTFS, *PFCNTFS;

typedef struct tdFCNTFS_CONTEXT_COUNTER {
    DWORD cNeg;
    DWORD cPos;
} FCNTFS_CONTEXT_COUNTER, *PFCNTFS_CONTEXT_COUNTER;

typedef struct tdFCNTFS_CONTEXT_IDFS_LISTENTRY {
    DWORD dwIdFs;
    DWORD cAll;
    DWORD cDir;
    DWORD cFile;
    PFCNTFS pAll;
    PFCNTFS pDir;
    PFCNTFS pFile;
} FCNTFS_CONTEXT_IDFS_LISTENTRY, *PFCNTFS_CONTEXT_IDFS_LISTENTRY, **PPFCNTFS_CONTEXT_IDFS_LISTENTRY;

typedef struct tdFCNTFS_COUNTX {
    DWORD i;
    int c;
} FCNTFS_COUNTX, *PFCNTFS_COUNTX;

#define NTFS_LAST_VA_MAX    0x40

typedef struct tdFCNTFS_SETUP_CONTEXT {
    CRITICAL_SECTION LockUpdate;
    POB_MAP pmId;                               // map of: [MftRecordId+InternalSeqId]->[PFCNTFS]
    POB_MAP pmFs;                               // map of: [IdFs]->[PFCNTFS_CONTEXT_IDFS_LISTENTRY]
    DWORD iLastVa;
    DWORD dwLastIdFs;
    PFCNTFS pLast;
    PFCNTFS pLastVa[NTFS_LAST_VA_MAX];
    // below used in finalize:
    PPFCNTFS_CONTEXT_IDFS_LISTENTRY ppListsSorted;
    PFCNTFS_CONTEXT_COUNTER pListsCounter;
} FCNTFS_SETUP_CONTEXT, *PFCNTFS_SETUP_CONTEXT;



//-----------------------------------------------------------------------------
// NTFS MFT ANALYSIS / INITIALIZATION FUNCTIONALITY BELOW:
// The NTFS MFT analysis heavily builds upon the analysis of physical memory
// which is analyzed page-by-page as the forensic sub-system is doing its
// physical memory scan. The results of the NTFS MFT entries gathered during
// the physical memory scan phase is then analyzed and pieced together using
// a best-effort algorithm into somewhat valid file systems.
// NB! artifacts will be missing from memory and best-effort guesses will be
//     made. This may result in files/directories being missed or assembled
//     towards another file system. Manual analysis of the MFT entries are
//     recommended for more correct forensics.
// NB! the code below is somewhat messy and should be cleaned up; but it's
//     working at the moment and provides the functionality needed.
//-----------------------------------------------------------------------------

/*
* Close and clean up PFCNTFS_SETUP_CONTEXT.
* -- ctx
*/
VOID FcNtfs_SetupClose(_Frees_ptr_opt_ PFCNTFS_SETUP_CONTEXT ctx)
{
    // TODO: CHECK REMAINING REFERENCE COUNTS !!!
    if(ctx) {
        DeleteCriticalSection(&ctx->LockUpdate);
        Ob_DECREF(ctx->pmId);
        Ob_DECREF(ctx->pmFs);
        LocalFree(ctx->ppListsSorted);
        LocalFree(ctx->pListsCounter);
        LocalFree(ctx);
    }
}

/*
* Initialize a new empty PFCNTFS_SETUP_CONTEXT.
* -- return = the initialized context, or NULL on fail.
*/
PVOID FcNtfs_SetupInitialize()
{
    PFCNTFS_SETUP_CONTEXT ctx;
    if(!(ctx = LocalAlloc(LMEM_ZEROINIT, sizeof(FCNTFS_SETUP_CONTEXT)))) { goto fail; }
    InitializeCriticalSection(&ctx->LockUpdate);
    if(!(ctx->pmId = ObMap_New(OB_MAP_FLAGS_OBJECT_LOCALFREE))) { goto fail; }
    if(!(ctx->pmFs = ObMap_New(OB_MAP_FLAGS_OBJECT_LOCALFREE))) { goto fail; }
    return ctx;
fail:
    FcNtfs_SetupClose(ctx);
    return NULL;
}

/*
* Helper function to iterate over a map / key collision list.
* -- pm
* -- dwKey
* -- pNtfs
* -- return
*/
PFCNTFS FcNtfs_Setup_ObMap_GetNextByKey(_In_ POB_MAP pm, _In_ DWORD dwKey, _In_opt_ PFCNTFS pNtfs)
{
    QWORD qwKeyHi = pNtfs ? ((pNtfs->wIdThis_SeqNbr + 1ULL) << 32) : 0;
    return ObMap_GetByKey(pm, qwKeyHi | dwKey);
}

/*
* Helper function to add NTFS entry to a map / key collision list.
* -- pm
* -- pNtfs
*/
VOID FcNtfs_Setup_ObMap_Push(_In_ POB_MAP pm, _In_ PFCNTFS pNtfs)
{
    while(!ObMap_Push(pm, ((QWORD)pNtfs->wIdThis_SeqNbr << 32) + pNtfs->dwIdThis, pNtfs)) {
        pNtfs->wIdThis_SeqNbr++;
    }
}

/*
* Helper function to create an MFT entry internal object.
* -- ctx
* -- dwIdMftRecordNumber
* -- wszName
* -- cwszName
* -- fDir
* -- return
*/
PFCNTFS FcNtfs_SetupCreateEntry(_In_ PFCNTFS_SETUP_CONTEXT ctx, _In_ DWORD dwIdMftRecordNumber, _In_ LPWSTR wszName, _In_ QWORD cwszName, _In_ BOOL fDir)
{
    PFCNTFS pNtfs;
    if(!(pNtfs = LocalAlloc(LMEM_ZEROINIT, sizeof(FCNTFS) + ((cwszName + 1) << 1)))) { return NULL; }
    memcpy(pNtfs->wszName, wszName, cwszName << 1);
    pNtfs->dwIdThis = dwIdMftRecordNumber;
    pNtfs->fDir = fDir;
    pNtfs->Flags = fDir ? 0x03 : 0x00;
    FcNtfs_Setup_ObMap_Push(ctx->pmId, pNtfs);
    return pNtfs;
}

/*
* Try add a single MFT entry to the NTFS MFT dataset.
* -- ctx
* -- qwPhysicalAddress
* -- qwVirtualAddress
* -- pb
*/
VOID FcNtfs_SetupMftEntry(_In_ PFCNTFS_SETUP_CONTEXT ctx, _In_ QWORD qwPhysicalAddress, _In_opt_ QWORD qwVirtualAddress, _In_reads_(0x400) PBYTE pb)
{
    DWORD i, oA, dwIdFs, cbData = 0;
    PNTFS_FILE_RECORD pr;
    PNTFS_ATTR pa;
    PNTFS_FILE_NAME pfnC, pfn = NULL;
    PNTFS_STANDARD_INFORMATION psi = NULL;
    PFCNTFS pNtfs = NULL, pNtfs_IdColl = NULL;
    PFCNTFS_CONTEXT_IDFS_LISTENTRY pFsList;
    pr = (PNTFS_FILE_RECORD)pb;
    // Check MFT record number is within the correct location inside the page.
    if((((qwPhysicalAddress >> 10) & 0x3) != (0x3 & pr->MftRecordNumber)) || (pr->MftRecordNumber == 0)) { return; }
    // Extract attributes loop.
    oA = pr->FirstAttributeOffset;
    while((oA + sizeof(NTFS_ATTR) < 0x400)) {
        pa = (PNTFS_ATTR)(pb + oA);
        if((pa->Type == 0xffffffff) || (pa->Length < sizeof(NTFS_ATTR))) { break; }
        if(oA + pa->Length > 0x400) { break; }
        if(pa->Length < pa->AttrOffset + pa->AttrLength) { break; }
        if(pa->Type == NTFS_ATTR_TYPE_DATA) {
            cbData = pa->AttrLength;
        }
        if(pa->Type == NTFS_ATTR_TYPE_STANDARD_INFORMATION) {
            if(pa->AttrLength < sizeof(NTFS_STANDARD_INFORMATION)) { break; }
            psi = (PNTFS_STANDARD_INFORMATION)(pb + oA + pa->AttrOffset);
        }
        if(pa->Type == NTFS_ATTR_TYPE_FILE_NAME) {
            pfnC = (PNTFS_FILE_NAME)(pb + oA + pa->AttrOffset);
            if((pfnC->NameSpace != NTFS_FILENAME_NAMESPACE_DOS) && (pa->AttrLength >= 42 + pfnC->NameLength * sizeof(WCHAR))) {
                if(!pfn || (pfnC->SizeReal > pfn->SizeReal)) {
                    pfn = pfnC;
                }
            }
        }
        oA += pa->Length;
    }
    if(!psi || !pfn || (pfn->ParentDirectory.SegmentNumber > 0xffffffff)) { return; }
    // Duplicate check by MftRecordNumber and LogFileSequenceNumber [SINGLE THREADED SECTION].
    while((pNtfs_IdColl = FcNtfs_Setup_ObMap_GetNextByKey(ctx->pmId, pr->MftRecordNumber, pNtfs_IdColl))) {
        if(pNtfs_IdColl->Setup.qwLogFileSequenceNumber == pr->LogFileSequenceNumber) {
            return;
        }
    }
    // Create NTFS object and populate [SINGLE THREADED SECTION].
    if(!(pNtfs = FcNtfs_SetupCreateEntry(ctx, pr->MftRecordNumber, pfn->Name, pfn->NameLength, (pr->Flags & 0x02)))) {
        return;
    }
    pNtfs->pa = qwPhysicalAddress;
    pNtfs->va = qwVirtualAddress;
    pNtfs->Setup.qwLogFileSequenceNumber = pr->LogFileSequenceNumber;
    pNtfs->Setup.dwIdParent = (DWORD)pfn->ParentDirectory.SegmentNumber;
    pNtfs->cbFileSize = max(cbData, pfn->SizeReal);
    pNtfs->cbFileSizeMftResident = (WORD)cbData;
    pNtfs->ftCreate = psi->TimeCreate;
    pNtfs->ftModify = psi->TimeModify;
    pNtfs->ftRead = psi->TimeRead;
    pNtfs->Flags = pr->Flags;
    // Set idfs [internal file system id]
    dwIdFs = 0;
    if(ctx->pLast && ((ctx->pLast->pa >> 12) == (pNtfs->pa >> 12))) {
        // Physical address: same page as last item -> same idfs.
        dwIdFs = ctx->pLast->Setup.dwIdFs;
    }
    if(!dwIdFs && pNtfs->va) {
        // Virtual address: MFT record number distance corresponds with virtual address distance -> same idfs.
        // NB! virtual address is disabled by default by performance reasons so this section will never enter.
        for(i = 0; i < NTFS_LAST_VA_MAX; i++) {
            if(ctx->pLastVa[i] && ((DWORD)((ctx->pLastVa[i]->va >> 10) - (pNtfs->va >> 10)) == ctx->pLastVa[i]->dwIdThis - pNtfs->dwIdThis)) {
                dwIdFs = ctx->pLastVa[i]->Setup.dwIdFs;
                break;
            }
        }
        if(!dwIdFs) {
            ctx->iLastVa++;
            ctx->pLastVa[ctx->iLastVa % NTFS_LAST_VA_MAX] = pNtfs;
        }
    }
    if(!dwIdFs) {
        dwIdFs = ctx->dwLastIdFs++;
    }
    pNtfs->Setup.dwIdFs = dwIdFs;
    ctx->pLast = pNtfs;
    // Commit NTFS object to ctx [SINGLE THREADED SECTION].
    if(!(pFsList = ObMap_GetByKey(ctx->pmFs, dwIdFs))) {
        if(!(pFsList = LocalAlloc(LMEM_ZEROINIT, sizeof(FCNTFS_CONTEXT_IDFS_LISTENTRY)))) {
            ObMap_Remove(ctx->pmId, pNtfs);
            LocalFree(pNtfs);
            return;
        }
        pFsList->dwIdFs = pNtfs->Setup.dwIdFs;
        ObMap_Push(ctx->pmFs, dwIdFs, pFsList);
    }
    pNtfs->Setup.pNextAll = pFsList->pAll;
    pFsList->pAll = pNtfs;
    pFsList->cAll++;
    if(pNtfs->fDir) { // DIRECTORY
        pNtfs->Setup.pNextDir = pFsList->pDir;
        pFsList->pDir = pNtfs;
        pFsList->cDir++;
    } else {            // FILE
        pNtfs->Setup.pNextFile = pFsList->pFile;
        pFsList->pFile = pNtfs;
        pFsList->cFile++;
    }
    // Debug output:
    vmmwprintfvv_fn(
        L"   %04x %16llx %8lli : %c : %s \n",
        pNtfs->Setup.dwIdFs,
        pNtfs->pa,
        pNtfs->cbFileSize,
        (pNtfs->fDir ? 'D' : ' '),
        pNtfs->wszName
    );
}

/*
* Try add a physical memory page to the NTFS MFT dataset.
* -- ctx
* -- pa
* -- pbPage
*/
VOID FcNtfs_SetupMftPage(_In_ PFCNTFS_SETUP_CONTEXT ctx, _In_ QWORD pa, _In_reads_(0x1000) PBYTE pbPage)
{
    QWORD i, va = 0;
    PNTFS_FILE_RECORD pr;
    if(*(PDWORD)pbPage != 'ELIF') { return; }     // file signature
    // virtual address correlation is effective for reducing the number of file
    // system fragments and hence lowers the risk of incorrect mergers across
    // file systems if multiple file systems exists. But it's very resource
    // intensive to retrieve virtual address from physical address so skip this.
    /*
    PVMM_PROCESS pObSystemProcess = NULL;
    PVMMOB_PHYS2VIRT_INFORMATION pObPhys2Virt = NULL;
    if((pObSystemProcess = VmmProcessGet(4))) {
        if((pObPhys2Virt = VmmPhys2VirtGetInformation(pObSystemProcess, pa)) && pObPhys2Virt->cvaList) {
            va = pObPhys2Virt->pvaList[0];
        }
        Ob_DECREF_NULL(&pObPhys2Virt);
        Ob_DECREF_NULL(&pObSystemProcess);
    }
    */
    for(i = 0; i < 0x1000; i += 0x400) {
        pr = (PNTFS_FILE_RECORD)(pbPage + i);
        if(pr->Signature != 'ELIF') { continue; }
        if((pr->UpdateSequenceArrayOffset > 0x100) || (pr->UpdateSequenceArraySize > 0x100)) { continue; }
        if(pr->BaseFileRecordSegment.SegmentNumber) { continue; }
        if(pr->FirstAttributeOffset > 0x300) { continue; }
        FcNtfs_SetupMftEntry(ctx, pa + i, (va ? va + i : 0), pbPage + i);
    }
}

/*
* Filter incoming POB_FC_SCANPHYSMEM_CHUNK to retrieve potential MFT entry
* physical page addresses and their data in a map [pa -> pb].
* CALLER DECREF: return
* -- pc
* -- return = MAP or NULL if no candidate pages found.
*/
POB_MAP FcNtfs_SetupGetValidAddrMap(_In_ POB_FC_SCANPHYSMEM_CHUNK pc)
{
    BOOL fPfnValidForMft;
    DWORD i;
    POB_MAP pmObAddr;
    PMMPFN_MAP_ENTRY pePfn;
    if(!(pmObAddr = ObMap_New(0))) { return NULL; }
    for(i = 0; i < 0x1000; i++) {
        if((pc->ppMEMs[i]->qwA != (QWORD)-1) && pc->ppMEMs[i]->f && (pc->ppMEMs[i]->cb == 0x1000) && (*(PDWORD)pc->ppMEMs[i]->pb == 'ELIF')) {
            pePfn = (pc->pPfnMap && (i < pc->pPfnMap->cMap)) ? (pc->pPfnMap->pMap + i) : NULL;
            fPfnValidForMft =
                !pePfn || (pePfn->dwPfn != (pc->ppMEMs[i]->qwA >> 12)) ||
                (pePfn->PageLocation == MmPfnTypeStandby) ||
                (pePfn->PageLocation == MmPfnTypeModified) ||
                (pePfn->PageLocation == MmPfnTypeModifiedNoWrite) ||
                (pePfn->PageLocation == MmPfnTypeTransition) ||
                ((pePfn->PageLocation == MmPfnTypeActive) && (pePfn->Priority == 5));
            if(fPfnValidForMft) {
                ObMap_Push(pmObAddr, pc->ppMEMs[i]->qwA, pc->ppMEMs[i]->pb);
            }
        }
    }
    if(ObMap_Size(pmObAddr)) {
        return pmObAddr;
    }
    Ob_DECREF(pmObAddr);
    return NULL;
}

/*
* Analyze a POB_FC_SCANPHYSMEM_CHUNK 16MB memory chunk for MFT file candidates
* and add any found to the internal data sets. This function is meant to be
* called asynchronously by a worker thread (VmmWork). Function is thread-safe.
* -- pc
*/
VOID FcNtfs_Setup_ThreadProc(_In_ POB_FC_SCANPHYSMEM_CHUNK pc)
{
    QWORD pa;
    PBYTE pb;
    POB_MAP pmObAddr;
    PFCNTFS_SETUP_CONTEXT ctx = (PFCNTFS_SETUP_CONTEXT)pc->ctx_NTFS;
    EnterCriticalSection(&ctx->LockUpdate);
    if((pmObAddr = FcNtfs_SetupGetValidAddrMap(pc))) {
        while((pb = ObMap_PopWithKey(pmObAddr, &pa))) {
            FcNtfs_SetupMftPage(ctx, pa, pb);
        }
    }
    LeaveCriticalSection(&ctx->LockUpdate);
    Ob_DECREF(pmObAddr);
}

/*
* qsort comparator
*/
int FcNtfs_SetupFinalize_CmpFsListEntry(const void *v1, const void *v2)
{
    PFCNTFS_CONTEXT_IDFS_LISTENTRY p1 = *(PPFCNTFS_CONTEXT_IDFS_LISTENTRY)v1;
    PFCNTFS_CONTEXT_IDFS_LISTENTRY p2 = *(PPFCNTFS_CONTEXT_IDFS_LISTENTRY)v2;
    if(p1->cDir > p2->cDir) { return -1; }
    if(p1->cDir < p2->cDir) { return 1; }
    if(p1->cAll > p2->cAll) { return -1; }
    if(p1->cAll < p2->cAll) { return 1; }
    return 0;
}

int FcNtfs_SetupFinalize_CmpFsListEntryFinal(const void *v1, const void *v2)
{
    PFCNTFS_CONTEXT_IDFS_LISTENTRY p1 = *(PPFCNTFS_CONTEXT_IDFS_LISTENTRY)v1;
    PFCNTFS_CONTEXT_IDFS_LISTENTRY p2 = *(PPFCNTFS_CONTEXT_IDFS_LISTENTRY)v2;
    if(p1->cAll > p2->cAll) { return -1; }
    if(p1->cAll < p2->cAll) { return 1; }
    return 0;
}

/*
* "Compact" NTFS MFT entries within same file system domain (FsId) - that is
* put files/directories as child item on their parent-directory and remove
* them as "no-ref" items.
* -- ctx
* -- pList
*/
VOID FcNtfs_SetupFinalize_Compact(_In_ PFCNTFS_SETUP_CONTEXT ctx, _In_opt_ PFCNTFS_CONTEXT_IDFS_LISTENTRY pList)
{
    BOOL fCompact, fLoop;
    PFCNTFS pe, pePrev, peParent, peParent_LoopProtect;
    if(!pList || !pList->pDir) { return; }
    // 1: Compact Directory
    pe = pList->pDir;
    pePrev = NULL;
    while(pe) {
        peParent = NULL;
        fCompact = FALSE;
        while((peParent = FcNtfs_Setup_ObMap_GetNextByKey(ctx->pmId, pe->Setup.dwIdParent, peParent))) {
            if(peParent->fDir && (peParent->Setup.dwIdFs == pe->Setup.dwIdFs)) {
                // loop protect - do not compact directories if they turn into parent<->child loops
                // this is normally only the case with the root directory . but it may also happen
                // if some file system fragments are merged wrongly.
                fLoop = (pe->dwIdThis == pe->Setup.dwIdParent);
                peParent_LoopProtect = peParent;
                while(peParent_LoopProtect) {
                    if(pe == peParent_LoopProtect) {
                        fLoop = TRUE;
                        break;
                    }
                    peParent_LoopProtect = peParent_LoopProtect->pParent;
                }
                // consolidate directories (unless there is a loop).
                if(!fLoop) {
                    pe->pParent = peParent;
                    pe->pSibling = peParent->pChild;
                    peParent->pChild = pe;
                    if(pePrev) {
                        pePrev->Setup.pNextDir = pe->Setup.pNextDir;
                    } else {
                        pList->pDir = pe->Setup.pNextDir;
                    }
                    pe->Setup.pNextDir = NULL;
                    pList->cDir--;
                    fCompact = TRUE;
                    break;
                }
            }
        }
        if(fCompact) {
            pe = pePrev ? pePrev->Setup.pNextDir : pList->pDir;
        } else {
            pePrev = pe;
            pe = pe->Setup.pNextDir;
        }
    }
    // 1: Compact File
    pe = pList->pFile;
    pePrev = NULL;
    while(pe) {
        peParent = NULL;
        fCompact = FALSE;
        while((peParent = FcNtfs_Setup_ObMap_GetNextByKey(ctx->pmId, pe->Setup.dwIdParent, peParent))) {
            if(peParent->fDir && (peParent->Setup.dwIdFs == pe->Setup.dwIdFs)) {
                pe->pParent = peParent;
                pe->pSibling = peParent->pChild;
                peParent->pChild = pe;
                if(pePrev) {
                    pePrev->Setup.pNextFile = pe->Setup.pNextFile;
                } else {
                    pList->pFile = pe->Setup.pNextFile;
                }
                pe->Setup.pNextFile = NULL;
                pList->cFile--;
                fCompact = TRUE;
                break;
            }
        }
        if(fCompact) {
            pe = pePrev ? pePrev->Setup.pNextFile : pList->pFile;
        } else {
            pePrev = pe;
            pe = pe->Setup.pNextFile;
        }
    }
}

/*
* Merge two file system fragments into one.
* -- ctx
* -- pListDst
* -- pListSrc
*/
VOID FcNtfs_SetupFinalize_Merge(_In_ PFCNTFS_SETUP_CONTEXT ctx, _In_opt_ PFCNTFS_CONTEXT_IDFS_LISTENTRY pListDst, _In_opt_ PFCNTFS_CONTEXT_IDFS_LISTENTRY pListSrc)
{
    PFCNTFS pe;
    if(!pListDst || !pListSrc) { return; }
    if(pListDst == pListSrc) { return; }
    while((pe = pListSrc->pAll)) {
        pe->Setup.dwIdFs = pListDst->dwIdFs;
        pListSrc->pAll = pe->Setup.pNextAll;
        pe->Setup.pNextAll = pListDst->pAll;
        pListDst->pAll = pe;
        pListDst->cAll++;
        pListSrc->cAll--;
    }
    while((pe = pListSrc->pFile)) {
        pListSrc->pFile = pe->Setup.pNextFile;
        pe->Setup.pNextFile = pListDst->pFile;
        pListDst->pFile = pe;
        pListDst->cFile++;
        pListSrc->cFile--;
    }
    while((pe = pListSrc->pDir)) {
        pListSrc->pDir = pe->Setup.pNextDir;
        pe->Setup.pNextDir = pListDst->pDir;
        pListDst->pDir = pe;
        pListDst->cDir++;
        pListSrc->cDir--;
    }
}

/*
* Merge a file system fragments with only one single entry (optimization function).
* -- ctx
* -- pFs
*/
VOID FcNtfs_SetupFinalize_MergeSingleOnly(_In_ PFCNTFS_SETUP_CONTEXT ctx, _In_opt_ PFCNTFS_CONTEXT_IDFS_LISTENTRY pFs)
{
    PFCNTFS peParent;
    if(!pFs || (pFs->cAll != 1)) { return; }
    peParent = FcNtfs_Setup_ObMap_GetNextByKey(ctx->pmId, pFs->pAll->Setup.dwIdParent, NULL);
    if(!peParent || !peParent->fDir) { return; }
    FcNtfs_SetupFinalize_Merge(ctx, ObMap_GetByKey(ctx->pmFs, peParent->Setup.dwIdFs), pFs);
}

/*
* Count smaller file system fragments potential parents in a somewhat efficient manner.
* -- pc
* -- cc
* -- dwId
* -- fValid = TRUE if valid file system entry.
* -- return = the id with max # counts, -1 if none exists.
*/
DWORD FcNtfs_CountX(_Inout_updates_(cc) PFCNTFS_COUNTX pc, _In_ DWORD cc, _In_ DWORD dwId, _In_ BOOL fValid)
{
    int cMax = 0;
    DWORD i, dwIdMax = -1;
    BOOL fUpdated = FALSE;
    // check/update existing
    for(i = 0; i < cc && pc[i].i; i++) {
        if(pc[i].i == dwId) {
            fUpdated = TRUE;
            pc[i].c = fValid ? (pc[i].c + 1) : INT_MIN;
            if(pc[i].c > cMax) {
                cMax = pc[i].c;
                dwIdMax = pc[i].i;
            }
        }
    }
    // insert new
    if(!fUpdated && i < cc) {
        pc[i].i = dwId;
        pc[i].c = fValid ? 1 : INT_MIN;
        if(pc[i].c > cMax) {
            cMax = pc[i].c;
            dwIdMax = pc[i].i;
        }
    }
    return dwIdMax;
}

/*
* Alternative faster MergeFind algoritm for smaller file system fragments.
* -- ctx
* -- iListMerge
* -- return = the file system id most suitable to merge into (-1 if none).
*/
DWORD FcNtfs_SetupFinalize_MergeFind2(_In_ PFCNTFS_SETUP_CONTEXT ctx, _In_ DWORD iListMerge)
{
    PFCNTFS_CONTEXT_IDFS_LISTENTRY pFsList;
    PFCNTFS pe, peParent;
    DWORD cCount, dwIdFsMaxCount = -1;
    FCNTFS_COUNTX pCount[0x20] = { 0 };
    pFsList = ObMap_GetByKey(ctx->pmFs, iListMerge);
    if(!pFsList || !pFsList->pAll) { return -1; }
    cCount = min(0x20, pFsList->cDir + pFsList->cFile);
    pe = pFsList->pDir ? pFsList->pDir : pFsList->pFile;
    while(pe) {
        peParent = NULL;
        while((peParent = FcNtfs_Setup_ObMap_GetNextByKey(ctx->pmId, pe->Setup.dwIdParent, peParent))) {
            if(peParent->Setup.dwIdFs != pe->Setup.dwIdFs) {
                dwIdFsMaxCount = FcNtfs_CountX(pCount, cCount, peParent->Setup.dwIdFs, peParent->fDir);
            }
        }

        if(pe->fDir) {
            pe = pe->Setup.pNextDir ? pe->Setup.pNextDir : pFsList->pFile;
        } else {
            pe = pe->Setup.pNextFile;
        }
    }
    return dwIdFsMaxCount;
}

/*
* Find the ideal file system fragment to merge into.
* -- ctx
* -- iListMerge
* -- return = the file system id most suitable to merge into (-1 if none).
*/
DWORD FcNtfs_SetupFinalize_MergeFind(_In_ PFCNTFS_SETUP_CONTEXT ctx, _In_ DWORD iListMerge)
{
    PFCNTFS_CONTEXT_IDFS_LISTENTRY pFsList;
    PFCNTFS pe, peParent;
    DWORD i, iMerge;
    ZeroMemory(ctx->pListsCounter, ctx->dwLastIdFs * sizeof(FCNTFS_CONTEXT_COUNTER));
    pFsList = ObMap_GetByKey(ctx->pmFs, iListMerge);
    pe = pFsList ? pFsList->pAll : NULL;
    while(pe) {
        if(!pe->pParent) {
            peParent = NULL;
            while((peParent = FcNtfs_Setup_ObMap_GetNextByKey(ctx->pmId, pe->Setup.dwIdParent, peParent))) {
                if(peParent->Setup.dwIdFs != pe->Setup.dwIdFs) {
                    if(peParent->fDir) {
                        ctx->pListsCounter[peParent->Setup.dwIdFs].cPos++;
                    } else {
                        ctx->pListsCounter[peParent->Setup.dwIdFs].cNeg++;
                    }
                }
            }
        }
        pe = pe->Setup.pNextAll;
    }
    for(i = 0, iMerge = -1; i < ctx->dwLastIdFs; i++) {
        if(ctx->pListsCounter[i].cNeg || !ctx->pListsCounter[i].cPos) { continue; }
        if((iMerge == -1) || (ctx->pListsCounter[i].cPos > ctx->pListsCounter[iMerge].cPos)) {
            iMerge = i;
        }
    }
    return iMerge;
}

typedef struct tdFCNTFS_FINALIZE_CONTEXT {
    sqlite3 *hSql;
    sqlite3_stmt *st;
    sqlite3_stmt *st_str;
    QWORD cbUtf8Total;
    QWORD cbJsonTotal;
} FCNTFS_FINALIZE_CONTEXT, *PFCNTFS_FINALIZE_CONTEXT;

/*
* Add a file system entry to the database.
*/
VOID FcNtfs_SetupFinalize_DatabaseAdd(_In_ PFCNTFS_FINALIZE_CONTEXT ctx, _In_ PFCNTFS pe, _In_ LPWSTR wszPathName, _In_ DWORD owszName)
{
    QWORD id = pe->iMap;
    FCSQL_INSERTSTRTABLE SqlStrInsert = { 0 };
    if(!Fc_SqlInsertStr(ctx->st_str, wszPathName + 1, owszName - 1, &SqlStrInsert)) { return; }
    sqlite3_reset(ctx->st);
    sqlite3_bind_int64(ctx->st, 1, id);
    sqlite3_bind_int64(ctx->st, 2, pe->pParent ? pe->pParent->iMap : -1);
    sqlite3_bind_int64(ctx->st, 3, SqlStrInsert.id);
    sqlite3_bind_int64(ctx->st, 4, pe->qwHashThis);
    sqlite3_bind_int64(ctx->st, 5, pe->pParent ? pe->pParent->qwHashThis : -1);
    sqlite3_bind_int64(ctx->st, 6, pe->pa);
    sqlite3_bind_int64(ctx->st, 7, pe->dwIdThis);
    sqlite3_bind_int64(ctx->st, 8, pe->Flags);
    sqlite3_bind_int64(ctx->st, 9, pe->iDirDepth);
    sqlite3_bind_int64(ctx->st, 10, pe->cbFileSize);
    sqlite3_bind_int64(ctx->st, 11, pe->cbFileSizeMftResident);
    sqlite3_bind_int64(ctx->st, 12, pe->ftCreate);
    sqlite3_bind_int64(ctx->st, 13, pe->ftModify);
    sqlite3_bind_int64(ctx->st, 14, pe->ftRead);
    sqlite3_bind_int64(ctx->st, 15, pe->wName_SeqNbr);
    sqlite3_bind_int64(ctx->st, 16, ctx->cbUtf8Total + id * M_NTFS_INFO_LINELENGTH_UTF8);
    sqlite3_bind_int64(ctx->st, 17, ctx->cbJsonTotal + id * M_NTFS_INFO_LINELENGTH_JSON);
    sqlite3_step(ctx->st);
    ctx->cbUtf8Total += SqlStrInsert.cbu;
    ctx->cbJsonTotal += SqlStrInsert.cbj;
}

DWORD FcNtfs_SetupFinalize_SetupFinish(_In_ PFCNTFS_FINALIZE_CONTEXT ctx, _In_ POB_SET psHashPath, _In_ PFCNTFS peNtfs, _In_ DWORD iMap, _In_ BYTE iDirDepth, _In_reads_(2048) LPWSTR wszPath, _In_ DWORD cwszPath)
{
    DWORD dwHashName, cwszName;
    QWORD qwHashTotal;
    while(peNtfs) {
        // update/set path
        cwszName = (DWORD)wcslen(peNtfs->wszName);
        if(cwszPath + cwszName + 2 >= 2048) { break; }
        wszPath[cwszPath] = '\\';
        memcpy(&wszPath[cwszPath + 1], peNtfs->wszName, ((QWORD)cwszName << 1) + 2);
        // update/set path hash
        while(TRUE) {
            qwHashTotal = peNtfs->pParent ? peNtfs->pParent->qwHashThis : 0;
            dwHashName = Util_HashNameW_Registry(peNtfs->wszName, peNtfs->wName_SeqNbr);
            qwHashTotal = dwHashName + ((qwHashTotal >> 13) | (qwHashTotal << 51));
            if(!ObSet_Exists(psHashPath, qwHashTotal) || (peNtfs->wName_SeqNbr > 100)) { break; }
            peNtfs->wName_SeqNbr++;
        }
        ObSet_Push(psHashPath, qwHashTotal);
        peNtfs->qwHashThis = qwHashTotal;
        peNtfs->iDirDepth = iDirDepth;
        peNtfs->iMap = iMap++;
        FcNtfs_SetupFinalize_DatabaseAdd(ctx, peNtfs, wszPath, cwszPath + 1);
        iMap = FcNtfs_SetupFinalize_SetupFinish(ctx, psHashPath, peNtfs->pChild, iMap, iDirDepth + 1, wszPath, cwszPath + cwszName + 1);
        peNtfs = peNtfs->pSibling;
    }
    wszPath[cwszPath] = 0;
    return iMap;
}

VOID FcNtfs_SetupFinalize_AddToParent(_In_ PFCNTFS pNtfsParent, _In_ PFCNTFS pNtfs)
{
    pNtfs->pParent = pNtfsParent;
    pNtfs->pSibling = pNtfsParent->pChild;
    pNtfsParent->pChild = pNtfs;
}

VOID FcNtfs_SetupFinalize_MergeFinalTree(_In_ PFCNTFS_CONTEXT_IDFS_LISTENTRY pListSrc, _In_ PFCNTFS pNtfsFsRoot, _In_ PFCNTFS pNtfsFsOrphan, _In_ BOOL fFullFs)
{
    PFCNTFS pePrev, pe = pListSrc->pDir;
    while(pe) {
        if(fFullFs && (pe->dwIdThis == pe->Setup.dwIdParent)) {
            FcNtfs_SetupFinalize_AddToParent(pNtfsFsRoot, pe);
        } else {
            FcNtfs_SetupFinalize_AddToParent(pNtfsFsOrphan, pe);
        }
        pePrev = pe;
        pe = pe->Setup.pNextDir;
        pePrev->Setup.pNextDir = NULL;
    }
    pe = pListSrc->pFile;
    while(pe) {
        FcNtfs_SetupFinalize_AddToParent(pNtfsFsOrphan, pe);
        pePrev = pe;
        pe = pe->Setup.pNextFile;
        pePrev->Setup.pNextFile = NULL;
    }
    ZeroMemory(pListSrc, sizeof(FCNTFS_CONTEXT_IDFS_LISTENTRY));
}

/*
* Finalize the NTFS setup/initialization phase. Try to put re-assemble the NTFS
* MFT file fragments into some kind of usable file-system approximation using
* heuristics and save it to the forensic database.
* -- pvSetupContextNtfs
* -- fScanSuccess
*/
VOID FcNtfs_SetupFinalize(_In_opt_ PVOID pvSetupContextNtfs, _In_ BOOL fScanSuccess)
{
    PFCNTFS_SETUP_CONTEXT ctx = (PFCNTFS_SETUP_CONTEXT)pvSetupContextNtfs;
    DWORD i, iNtfsDummy = 0, iFileSystem = 0;
    PFCNTFS pNtfsGlobalRoot, pNtfsGlobalOrphan, pNtfsFsRoot, pNtfsFsOrphan;
    PFCNTFS_CONTEXT_IDFS_LISTENTRY pFsList, pFsListMerge;
    POB_SET psObHashPath = NULL;
    WCHAR wszBuffer1[MAX_PATH], wszBuffer2[MAX_PATH];
    WCHAR wszPath[2048] = { 0 };
    FCNTFS_FINALIZE_CONTEXT ctxFinal = { 0 };
    int rc;
    if(!ctx) { return; }
    if(!fScanSuccess) { goto fail; }
    // initialize general
    if(!(psObHashPath = ObSet_New())) { goto fail; }
    // initialize virtual root
    pNtfsGlobalRoot = FcNtfs_SetupCreateEntry(ctx, --iNtfsDummy, L"", 0, TRUE);
    pNtfsGlobalOrphan = FcNtfs_SetupCreateEntry(ctx, --iNtfsDummy, L"u0", 8, TRUE);
    FcNtfs_SetupFinalize_AddToParent(pNtfsGlobalRoot, pNtfsGlobalOrphan);
    // allocate arrays for counting and sorting
    if(!(ctx->pListsCounter = LocalAlloc(LMEM_ZEROINIT, ctx->dwLastIdFs * sizeof(FCNTFS_CONTEXT_COUNTER)))) { goto fail; }
    if(!(ctx->ppListsSorted = LocalAlloc(LMEM_ZEROINIT, ctx->dwLastIdFs * sizeof(PFCNTFS_CONTEXT_COUNTER)))) { goto fail; }
    // COMPACT INITIAL & MERGE SINGLE
    for(i = 0; i < ctx->dwLastIdFs; i++) {
        if((pFsList = ObMap_GetByKey(ctx->pmFs, i))) {
            FcNtfs_SetupFinalize_Compact(ctx, pFsList);
            FcNtfs_SetupFinalize_MergeSingleOnly(ctx, pFsList);     // merge single entry filesystem fragments (optimization)
        }
    }
    // MERGE UP TO 32-ENTRIES AND COMPACT (OPTIMIZATION STEP)
    for(i = 0; i < ctx->dwLastIdFs; i++) {
        if((pFsList = ObMap_GetByKey(ctx->pmFs, i)) && pFsList->cAll && (pFsList->cAll <= 32)) {
            FcNtfs_SetupFinalize_Merge(
                ctx,
                ObMap_GetByKey(ctx->pmFs, FcNtfs_SetupFinalize_MergeFind2(ctx, pFsList->pAll->Setup.dwIdFs)),
                pFsList
            );
        }
    }
    for(i = 0; i < ctx->dwLastIdFs; i++) {
        if((pFsList = ObMap_GetByKey(ctx->pmFs, i))) {
            FcNtfs_SetupFinalize_Compact(ctx, pFsList);
            ctx->ppListsSorted[i] = pFsList;
        }
    }
    qsort(ctx->ppListsSorted, ctx->dwLastIdFs, sizeof(PFCNTFS_CONTEXT_IDFS_LISTENTRY), FcNtfs_SetupFinalize_CmpFsListEntry);
    // COMPACT AND MERGE AS MUCH AS POSSIBLE
    for(i = 0; i < ctx->dwLastIdFs; i++) {
        pFsList = ctx->ppListsSorted[i];
        if(pFsList->cAll) {
            if((pFsListMerge = ObMap_GetByKey(ctx->pmFs, FcNtfs_SetupFinalize_MergeFind(ctx, pFsList->pAll->Setup.dwIdFs)))) {
                FcNtfs_SetupFinalize_Merge(ctx, pFsListMerge, pFsList);
                FcNtfs_SetupFinalize_Compact(ctx, pFsListMerge);
            }
        }
    }
    // ADD SMALLER FILE SYSTEM FRAGMENTS TO GLOBAL ORPHAN DIRECTORIES
    for(i = 0; i < ctx->dwLastIdFs; i++) {
        pFsList = ObMap_GetByKey(ctx->pmFs, i);
        if(pFsList && pFsList->cAll && (pFsList->cAll < 0x20)) {
            FcNtfs_SetupFinalize_MergeFinalTree(pFsList, pNtfsGlobalRoot, pNtfsGlobalOrphan, FALSE);
        }
    }
    // ADD LARGER FILE SYSTEM FRAGMENTS / COMPLETE FILE SYSTEMS
    qsort(ctx->ppListsSorted, ctx->dwLastIdFs, sizeof(PFCNTFS_CONTEXT_IDFS_LISTENTRY), FcNtfs_SetupFinalize_CmpFsListEntryFinal);
    for(i = 0; i < ctx->dwLastIdFs; i++) {
        pFsList = ctx->ppListsSorted[i];
        if(pFsList->cAll) {
            iFileSystem++;
            wsprintf(wszBuffer1, L"%i", iFileSystem);
            wsprintf(wszBuffer2, L"u%i", iFileSystem);
            pNtfsFsRoot = FcNtfs_SetupCreateEntry(ctx, --iNtfsDummy, wszBuffer1, (DWORD)wcslen(wszBuffer1), TRUE);
            pNtfsFsOrphan = FcNtfs_SetupCreateEntry(ctx, --iNtfsDummy, wszBuffer2, (DWORD)wcslen(wszBuffer2), TRUE);
            FcNtfs_SetupFinalize_MergeFinalTree(pFsList, pNtfsFsRoot, pNtfsFsOrphan, TRUE);
            if(pNtfsFsRoot->pChild) {
                FcNtfs_SetupFinalize_AddToParent(pNtfsGlobalRoot, pNtfsFsRoot);
            }
            if(pNtfsFsOrphan->pChild) {
                FcNtfs_SetupFinalize_AddToParent(pNtfsGlobalRoot, pNtfsFsOrphan);
            }
        }
    }
    // SETUP FINISH:
    if(!(ctxFinal.hSql = Fc_SqlReserve())) { goto fail; }
    rc = sqlite3_prepare_v2(ctxFinal.hSql, 
        "INSERT INTO ntfs " \
        "(id, id_parent, id_str, hash, hash_parent, addr_phys, inode, mft_flags, depth, size_file, size_fileres, time_create, time_modify, time_read, name_seq, oln_u, oln_j) " \
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);"
        , -1, &ctxFinal.st, NULL);
    if(rc != SQLITE_OK) { goto fail; }
    rc = sqlite3_prepare_v2(ctxFinal.hSql, "INSERT INTO str (id, osz, csz, cbu, cbj, sz) VALUES (?, ?, ?, ?, ?, ?);", -1, &ctxFinal.st_str, NULL);
    if(rc != SQLITE_OK) { goto fail; }
    sqlite3_exec(ctxFinal.hSql, "BEGIN TRANSACTION", NULL, NULL, NULL);
    DWORD DEBUG_NUM = FcNtfs_SetupFinalize_SetupFinish(&ctxFinal, psObHashPath, pNtfsGlobalRoot, 0, 0, wszPath, 0);
    sqlite3_exec(ctxFinal.hSql, "COMMIT TRANSACTION", NULL, NULL, NULL);
    // MARK AS FINISHED AND CLEAN UP:
    ctxFc->fEnableNtfs = TRUE;
fail:
    sqlite3_finalize(ctxFinal.st);
    sqlite3_finalize(ctxFinal.st_str);
    Fc_SqlReserveReturn(ctxFinal.hSql);
    Ob_DECREF(psObHashPath);
    FcNtfs_SetupClose(ctx);
}



//-----------------------------------------------------------------------------
// NTFS MFT DATA RETRIEVAL FUNCTIONALITY BELOW:
// In essence this is "just" a query interface towards the sqlite database
// with the exception of the relatively minor functionality to retrieve MFT
// resident file contents of very small files.
//-----------------------------------------------------------------------------

/*
* Retrieve the MFT resident data (i.e. read file contents that fit into the MFT).
* -- pNtfsEntry
* -- pbData
* -- cbData
* -- pcbDataRead
* -- return
*/
_Success_(return)
BOOL FcNtfs_GetMftResidentData(_In_ PFC_MAP_NTFSENTRY pNtfsEntry, _Out_writes_opt_(cbData) PBYTE pbData, _In_ DWORD cbData, _Out_opt_ PDWORD pcbDataRead)
{
    DWORD oA;
    PNTFS_ATTR pa;
    PNTFS_FILE_RECORD pr;
    BYTE pbMftEntry[0x400];
    if(!VmmRead(NULL, pNtfsEntry->pa, pbMftEntry, 0x400)) { return FALSE; }
    pr = (PNTFS_FILE_RECORD)pbMftEntry;
    // Check MFT record number is within the correct location inside the page.
    if((((pNtfsEntry->pa >> 10) & 0x3) != (0x3 & pr->MftRecordNumber)) || (pr->MftRecordNumber == 0)) { return FALSE; }
    // Extract attributes loop.
    oA = pr->FirstAttributeOffset;
    while((oA + sizeof(NTFS_ATTR) < 0x400)) {
        pa = (PNTFS_ATTR)(pbMftEntry + oA);
        if((pa->Type == 0xffffffff) || (pa->Length < sizeof(NTFS_ATTR))) { return FALSE; }
        if(pa->Type == NTFS_ATTR_TYPE_DATA) {
            if(pcbDataRead) {
                *pcbDataRead = pa->AttrLength;
            }
            if(cbData != pa->AttrLength) { return FALSE; }
            if(pbData) {
                memcpy(pbData, (pbMftEntry + oA + pa->AttrOffset), pa->AttrLength);
            }
            return TRUE;
        }
        oA += pa->Length;
    }
    return FALSE;
}

#define FCNTFS_SQL_SELECT_FIELDS " csz, osz, sz, id, id_parent, addr_phys, inode, mft_flags, depth, name_seq, time_create, time_modify, time_read, size_file, size_fileres, oln_u, oln_j "

_Success_(return)
BOOL FcNtfsMap_CreateInternal(_In_ LPSTR szSqlCount, _In_ LPSTR szSqlSelect, _In_ DWORD cQueryValues, _In_reads_(cQueryValues) PQWORD pqwQueryValues, _Out_ PFCOB_MAP_NTFS *ppObNtfsMap)
{
    int rc;
    QWORD pqwResult[2];
    DWORD i, cchMultiText, owszName;
    LPWSTR wszMultiText, wszEntryText;
    PFCOB_MAP_NTFS pObNtfsMap = NULL;
    PFC_MAP_NTFSENTRY pe;
    sqlite3 *hSql = NULL;
    sqlite3_stmt *hStmt = NULL;
    rc = Fc_SqlQueryN(szSqlCount, cQueryValues, pqwQueryValues, 2, pqwResult, NULL);
    if((rc != SQLITE_OK) || (pqwResult[0] > 0x00010000) || (pqwResult[1] > 0x01000000)) { goto fail; }
    cchMultiText = (DWORD)(1 + 2 * pqwResult[0] + pqwResult[1]);
    pObNtfsMap = Ob_Alloc('Mntf', LMEM_ZEROINIT, sizeof(FCOB_MAP_NTFS) + pqwResult[0] * sizeof(FC_MAP_NTFSENTRY) + cchMultiText * sizeof(WCHAR), NULL, NULL);
    if(!pObNtfsMap) { goto fail; }
    pObNtfsMap->wszMultiText = (LPWSTR)((PBYTE)pObNtfsMap + sizeof(FCOB_MAP_NTFS) + pqwResult[0] * sizeof(FC_MAP_NTFSENTRY));
    pObNtfsMap->cbMultiText = cchMultiText * sizeof(WCHAR);
    pObNtfsMap->cMap = (DWORD)pqwResult[0];
    cchMultiText--;
    wszMultiText = pObNtfsMap->wszMultiText + 1;
    if(!(hSql = Fc_SqlReserve())) { goto fail; }
    rc = sqlite3_prepare_v2(hSql, szSqlSelect, -1, &hStmt, 0);
    if(rc != SQLITE_OK) { goto fail; }
    for(i = 0; i < cQueryValues; i++) {
        sqlite3_bind_int64(hStmt, i + 1, pqwQueryValues[i]);
    }
    for(i = 0; i < pObNtfsMap->cMap; i++) {
        rc = sqlite3_step(hStmt);
        if(rc != SQLITE_ROW) { goto fail; }
        pe = pObNtfsMap->pMap + i;
        // populate text related data: path+name
        pe->cwszText = sqlite3_column_int(hStmt, 0);
        owszName = sqlite3_column_int(hStmt, 1);
        wszEntryText = (LPWSTR)sqlite3_column_text16(hStmt, 2);
        if(!wszEntryText || (pe->cwszText != wcslen(wszEntryText)) || (pe->cwszText > cchMultiText - 1) || (owszName > pe->cwszText)) { goto fail; }
        pe->wszText = wszMultiText;
        pe->wszTextName = wszMultiText + owszName;
        memcpy(wszMultiText, wszEntryText, pe->cwszText * sizeof(WCHAR));
        wszMultiText = wszMultiText + pe->cwszText + 1;
        cchMultiText += pe->cwszText + 1;
        // populate numeric data
        pe->qwId = sqlite3_column_int64(hStmt, 3);
        pe->qwIdParent = sqlite3_column_int64(hStmt, 4);
        pe->pa = sqlite3_column_int64(hStmt, 5);
        pe->dwMftId = sqlite3_column_int(hStmt, 6);
        pe->dwMftFlags = sqlite3_column_int(hStmt, 7);
        pe->fDir = (pe->dwMftFlags & 2) ? TRUE : FALSE;
        pe->dwDirDepth = sqlite3_column_int(hStmt, 8);
        pe->dwTextSeq = sqlite3_column_int(hStmt, 9);
        pe->ftCreate = sqlite3_column_int64(hStmt, 10);
        pe->ftModify = sqlite3_column_int64(hStmt, 11);
        pe->ftRead = sqlite3_column_int64(hStmt, 12);
        pe->qwFileSize = sqlite3_column_int64(hStmt, 13);
        pe->dwFileSizeResident = sqlite3_column_int(hStmt, 14);
        pe->cszuOffset = sqlite3_column_int64(hStmt, 15);
        pe->cszjOffset = sqlite3_column_int64(hStmt, 16);
    }
    Ob_INCREF(pObNtfsMap);
fail:
    sqlite3_finalize(hStmt);
    Fc_SqlReserveReturn(hSql);
    *ppObNtfsMap = Ob_DECREF(pObNtfsMap);
    return (*ppObNtfsMap != NULL);
}

/*
* Retrieve a FCOB_MAP_NTFS map object containing a specific entry given by its
* file system hash.
* -- qwHash
* -- ppObNtfsMap
* -- return
*/
_Success_(return)
BOOL FcNtfsMap_GetFromHash(_In_ QWORD qwHash, _Out_ PFCOB_MAP_NTFS *ppObNtfsMap)
{
    return FcNtfsMap_CreateInternal(
        "SELECT COUNT(*), SUM(csz) FROM v_ntfs WHERE hash = ?",
        "SELECT "FCNTFS_SQL_SELECT_FIELDS" FROM v_ntfs WHERE hash = ?",
        1,
        &qwHash,
        ppObNtfsMap
    );
}

/*
* Retrieve a FCOB_MAP_NTFS map object containing entries which have the same
* file system parent given by its parent hash.
* -- qwHashParent
* -- ppObNtfsMap
* -- return
*/
_Success_(return)
BOOL FcNtfsMap_GetFromHashParent(_In_ QWORD qwHashParent, _Out_ PFCOB_MAP_NTFS *ppObNtfsMap)
{
    return FcNtfsMap_CreateInternal(
        "SELECT COUNT(*), SUM(csz) FROM v_ntfs WHERE hash_parent = ?",
        "SELECT "FCNTFS_SQL_SELECT_FIELDS" FROM v_ntfs WHERE hash_parent = ?",
        1,
        &qwHashParent,
        ppObNtfsMap
    );
}

/*
* Retrieve a FCOB_MAP_NTFS map object containing entries within a range.
* -- qwId
* -- cId
* -- ppObNtfsMap
* -- return
*/
_Success_(return)
BOOL FcNtfsMap_GetFromIdRange(_In_ QWORD qwId, _In_ QWORD cId, _Out_ PFCOB_MAP_NTFS *ppObNtfsMap)
{
    QWORD v[] = { qwId, qwId + cId };
    return FcNtfsMap_CreateInternal(
        "SELECT COUNT(*), SUM(csz) FROM v_ntfs WHERE id >= ? AND id < ?",
        "SELECT "FCNTFS_SQL_SELECT_FIELDS" FROM v_ntfs WHERE id >= ? AND id < ? ORDER BY id",
        2,
        v,
        ppObNtfsMap
    );
}

/*
* Retieve the file size of the ntfs information file either in JSON or UTF8.
* -- pcRecords = number of entries/lines/records.
* -- pcbUTF8 = UTF8 text file size.
* -- pcbJSON = JSON file size.
* -- return
*/
_Success_(return)
BOOL FcNtfs_GetFileSize(_Out_opt_ PQWORD pcRecords, _Out_opt_ PQWORD pcbUTF8, _Out_opt_ PQWORD pcbJSON)
{
    QWORD pqwResult[3];
    // query below is convoluted but it's very fast ...
    if(SQLITE_OK != Fc_SqlQueryN("SELECT id, oln_u+cbu+"STRINGIZE(M_NTFS_INFO_LINELENGTH_UTF8)" AS cbu_tot, oln_j+cbj+"STRINGIZE(M_NTFS_INFO_LINELENGTH_JSON)" AS cbj_tot FROM v_ntfs WHERE id = (SELECT MAX(id) FROM v_ntfs)", 0, NULL, 3, pqwResult, NULL)) { return FALSE; }
    if(pcRecords) { *pcRecords = pqwResult[0]; }
    if(pcbUTF8) { *pcbUTF8 = pqwResult[1]; }
    if(pcbJSON) { *pcbJSON = pqwResult[1]; }
    return TRUE;
}

/*
* Retrieve the id associated within the position of the info file.
* -- qwFilePos
* -- fJSON
* -- pqwId
* -- return
*/
_Success_(return)
BOOL FcNtfs_GetIdFromPosition(_In_ QWORD qwFilePos, _In_ BOOL fJSON, _Out_ PQWORD pqwId)
{
    QWORD v[] = { max(2048, qwFilePos) - 2048, qwFilePos};
    return fJSON ?
        (SQLITE_OK == Fc_SqlQueryN("SELECT MAX(id) FROM ntfs WHERE oln_j >= ? AND oln_j <= ?", 2, v, 1, pqwId, NULL)) :
        (SQLITE_OK == Fc_SqlQueryN("SELECT MAX(id) FROM ntfs WHERE oln_u >= ? AND oln_u <= ?", 2, v, 1, pqwId, NULL));
}
