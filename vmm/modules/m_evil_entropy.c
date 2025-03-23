// m_evil_entropy.c : detect evil by entropy calculation.
//
// Detections:
//  - HIGH_ENTROPY: Detects high entropy in process memory.
// 
// Contributed under BSD 0-Clause License (0BSD) by MattCore71
// Modified by Ulf Frisk
// 
// (c) MattCore71, Ulf Frisk, 2025
// Author: Ulf Frisk, pcileech@frizk.net
//

#include "modules.h"
#include "../mm/mm.h"
#include "../pe.h"

#define _USE_MATH_DEFINES
#include <math.h>

#define MEVILENTROPY_THRESHOLD                  7.5
#define MEVILENTROPY_THRESHOLD_X                7.0
#define MEVILENTROPY_MAX_FINDINGS_PER_PROCESS   3
#define MEVILENTROPY_CHUNK_SIZE                 (4096 / 8)

static LPCSTR szMEVILENTROPY_SKIP_PROCESS[] = {
    "chrome.exe",
    "MicrosoftEdgeC",
    "MsMpEng",
    "smartscreen"
};

static LPCSTR szMEVILENTROPY_SKIP_IMAGE_SYSROOT[] = {
    "clrcompression.dll",
    "coml2.dll",
    "d3d10_1core.dll",
    "imageres.dll",
    "IPHLPAPI.DLL",
    "policymanager.dll",
    "propdefs.dll",
    "sdiageng.dll",
    "SLsvc.exe",
    "sppc.dll",
    "sppcext.dll",
    "version.dll",
    "wldp.dll",
    "wups.dll"
};

static LPCSTR szMEVILENTROPY_SKIP_IMAGE_COMMON[] = {
    "MSOINTL.DLL",
    "msointl30.dll"
};

typedef struct tdMEVILENTROPY_CONTEXT {
    POB_COUNTER pc;
} MEVILENTROPY_CONTEXT, *PMEVILENTROPY_CONTEXT;

typedef struct tdMEVILENTROPY_STRUCTUREINFO {
    BOOL fPE;
    BOOL fTableSection;
    struct {
        QWORD va;
        DWORD size;
    } Data;
} MEVILENTROPY_STRUCTUREINFO, *PMEVILENTROPY_STRUCTUREINFO;

/*
* Remove chunks in which a single byte is over-represented (90% of the chunk).
*/
_Success_(return > 0)
DWORD MEvilEntropy_CleanBuffer(_In_reads_bytes_(cbIn) PBYTE pbIn, _In_ DWORD cbIn, _Out_writes_bytes_opt_(cbOut) PBYTE pbOut, _In_ DWORD cbOut)
{
    PBYTE pbChunk;
    BOOL fDiscardChunk;
    DWORD i, j, cbChunk, idxWrite = 0;
    WORD freq[256], wFreqSkipThreshold;
    for(i = 0; i < cbIn; i += MEVILENTROPY_CHUNK_SIZE) {
        pbChunk = pbIn + i;
        cbChunk = (i + MEVILENTROPY_CHUNK_SIZE <= cbIn) ? MEVILENTROPY_CHUNK_SIZE : (cbIn - i);
        wFreqSkipThreshold = (WORD)(0.9 * cbChunk);
        ZeroMemory(freq, sizeof(freq));
        // all-zero chunk fast path:
        if(!pbChunk[0] && (cbChunk == MEVILENTROPY_CHUNK_SIZE)) {
            fDiscardChunk = TRUE;
            for(j = 0; j < cbChunk; j += 8) {
                if(*(PQWORD)(pbChunk + j)) {
                    fDiscardChunk = FALSE;
                    break;
                }
            }
            if(fDiscardChunk) {
                continue;
            }
        }
        // count frequency of each byte in the chunk:
        for(j = 0; j < cbChunk; j++) {
            freq[pbChunk[j]]++;
        }
        // chunk frequency calculation:
        fDiscardChunk = FALSE;
        for(j = 0; j < 256; j++) {
            if(freq[j] > wFreqSkipThreshold) {
                fDiscardChunk = TRUE;
                break;
            }
        }
        // copy non-discarded chunk to output buffer:
        if(!fDiscardChunk) {
            if(pbOut && (idxWrite + cbChunk <= cbOut)) {
                memcpy(pbOut + idxWrite, pbChunk, cbChunk);
            }
            idxWrite += cbChunk;
        }
    }
    return idxWrite;
}

/*
* Calculate entropy of a buffer.
* -- pb
* -- cb
* -- return = the calculated entropy.
*/
double MEvilEntropy_CalculateEntropy(_In_reads_bytes_(cb) PBYTE pb, _In_ DWORD cb)
{
    DWORD i;
    double p, entropy = 0.0;
    double freq[256] = { 0 };
    for(i = 0; i < cb; i++) {
        freq[pb[i]]++;
    }
    for(i = 0; i < 256; i++) {
        if(freq[i] > 0) {
            p = freq[i] / cb;
            entropy -= p * log2(p);
        }
    }
    return entropy;
}

/*
* Check the type of the VAD, searching for MZ header and the ".data" section.
*/
VOID MEvilEntropy_CheckType(_In_ VMM_HANDLE H, _In_ PVMMDLL_FORENSIC_INGEST_VIRTMEM pIngestVirtmem, _Out_ MEVILENTROPY_STRUCTUREINFO *infos)
{
    DWORD oPE;
    IMAGE_SECTION_HEADER oSection;
    ZeroMemory(infos, sizeof(MEVILENTROPY_STRUCTUREINFO));
    // 1: search for PE image, i.e. MZ header:
    for(oPE = 0; oPE < pIngestVirtmem->cb; oPE += 0x1000) {
        if((pIngestVirtmem->pb[oPE + 0] == 'M') && (pIngestVirtmem->pb[oPE + 1] == 'Z') && (pIngestVirtmem->pb[oPE + 3] == 0)) {
            infos->fPE = TRUE;
            // 2: search for ".data" section:
            if(PE_SectionGetFromName(H, pIngestVirtmem->pvProcess, pIngestVirtmem->va + oPE, ".data", &oSection) && (infos->Data.size >= MEVILENTROPY_CHUNK_SIZE)) {
                infos->fTableSection = TRUE;
                infos->Data.va = oPE + oSection.VirtualAddress;
                infos->Data.size = oSection.Misc.VirtualSize;
                return;
            }
            break;
        }
    }
}

/*
* Ingest virtual memory in a forensic run to detect high entropy.
*/
VOID MEvilEntropy_IngestVirtmem(_In_ VMM_HANDLE H, _In_opt_ PVOID ctxfc, _In_ PVMMDLL_FORENSIC_INGEST_VIRTMEM pIngestVirtmem)
{
    BOOL f = FALSE;
    DWORD i, cbVad, cbBuffer;
    PBYTE pbBuffer = NULL;
    LPCSTR szVadType;
    PVMM_MAP_VADENTRY peVad = NULL;
    PVMMOB_MAP_VAD pObVadMap = NULL;
    PMEVILENTROPY_CONTEXT ctx = (PMEVILENTROPY_CONTEXT)ctxfc;
    PVMM_PROCESS pProcess = (PVMM_PROCESS)pIngestVirtmem->pvProcess;
    double score = 0.0;
    MEVILENTROPY_STRUCTUREINFO infos = { 0 };
    CHAR szVadProtection[7] = { 0 };
    // 1: Verify process eligibility:
    if(!ctx || !pProcess || !pIngestVirtmem->fVad) { return; }
    if(VmmProcess_IsKernelOnly(pProcess)) { return; }
    for(i = 0; i < _countof(szMEVILENTROPY_SKIP_PROCESS); i++) {
        if(strstr(pProcess->szName, szMEVILENTROPY_SKIP_PROCESS[i])) { return; }
    }
    if(ObCounter_Get(ctx->pc, pProcess->dwPID) >= MEVILENTROPY_MAX_FINDINGS_PER_PROCESS) { return; }
    // 2: Get VAD and verify VAD eligibility:
    if(!VmmMap_GetVad(H, pProcess, &pObVadMap, VMM_VADMAP_TP_FULL)) { return; }
    if(!(peVad = VmmMap_GetVadEntry(H, pObVadMap, pIngestVirtmem->va))) { goto fail; }
    if(peVad->fFile || peVad->fPageFile || peVad->fStack || peVad->fHeap || peVad->fTeb) { goto fail; }
    if(strstr(peVad->uszText, "HEAP") || strstr(peVad->uszText, "SECTION") || strstr(peVad->uszText, "STACK") || strstr(peVad->uszText, "TEB") || strstr(peVad->uszText, "FILE")) { goto fail; }
    if(peVad->vaStart != pIngestVirtmem->va) { goto fail; }
    cbVad = (DWORD)(peVad->vaEnd + 1 - peVad->vaStart);
    if((cbVad < 0x1000) || (cbVad > pIngestVirtmem->cb)) { goto fail; }
    // 3: Check the type of the VAD and calculate entropy:
    MEvilEntropy_CheckType(H, pIngestVirtmem, &infos);
    // CASE: MZ with clean section table
    if(infos.fPE && infos.fTableSection) {
        // Only checking entropy in data section as the absolute majority of malware encrypt this section before .text which has an elevated technical cost.
        if(infos.Data.va + infos.Data.size > cbVad) { goto fail; }
        score = MEvilEntropy_CalculateEntropy(pIngestVirtmem->pb + infos.Data.va, infos.Data.size);
        f = TRUE;
    }
    //CASE: MZ but no section table parsable (for instance packer)
    else if(infos.fPE && !infos.fTableSection) {
        f = (cbBuffer = MEvilEntropy_CleanBuffer(pIngestVirtmem->pb + 0x400, cbVad - 0x400, NULL, 0)) &&
            (pbBuffer = LocalAlloc(0, cbBuffer)) &&
            (MEvilEntropy_CleanBuffer(pIngestVirtmem->pb + 0x400, cbVad - 0x400, pbBuffer, cbBuffer) > 0) &&
            (score = MEvilEntropy_CalculateEntropy(pbBuffer, cbBuffer));
        LocalFree(pbBuffer); pbBuffer = NULL;
    }
    // CASE: NOT PE with headers in clear text
    else if(!infos.fPE) {
        f = (cbBuffer = MEvilEntropy_CleanBuffer(pIngestVirtmem->pb, cbVad, NULL, 0)) &&
            (pbBuffer = LocalAlloc(0, cbBuffer)) &&
            (MEvilEntropy_CleanBuffer(pIngestVirtmem->pb, cbVad, pbBuffer, cbBuffer) > 0) &&
            (score = MEvilEntropy_CalculateEntropy(pbBuffer, cbBuffer));
        LocalFree(pbBuffer); pbBuffer = NULL;
    }
    // 4: Log to FindEvil in case of high entropy:
    // FALSE POSITIVE above 7.5 : SYSTEM, MSMPENG, chrome.exe, smartscreen on data segment which is probably encrypted
    // ALL BUT BETWEEN 7 AND 7.5 SHOWING ONLY PROCESS WITH X permission to reduce false positive
    // XOR encryption is above 7.5, AES above 7.9, .text is about 6, .data is about 3/4
    if(!f || (score <= MEVILENTROPY_THRESHOLD_X)) { goto fail; }
    MmVad_StrProtectionFlags(peVad, szVadProtection);
    if((score >= MEVILENTROPY_THRESHOLD) || (((score >= MEVILENTROPY_THRESHOLD_X) && strchr(szVadProtection, 'x')))) {
        // match, but skip known false positives (image):
        if(peVad->fImage) {
            if(0 == strncmp(peVad->uszText, "\\Windows\\System32\\", 18)) {
                for(i = 0; i < _countof(szMEVILENTROPY_SKIP_IMAGE_SYSROOT); i++) {
                    if(strstr(peVad->uszText, szMEVILENTROPY_SKIP_IMAGE_SYSROOT[i])) {
                        goto fail;
                    }
                }
            }
            for(i = 0; i < _countof(szMEVILENTROPY_SKIP_IMAGE_COMMON); i++) {
                if(strstr(peVad->uszText, szMEVILENTROPY_SKIP_IMAGE_COMMON[i])) {
                    goto fail;
                }
            }
        }
        // log match to FindEvil:
        szVadType = MmVad_StrType(peVad);
        FcEvilAdd(H, EVIL_HIGH_ENTROPY, pProcess, peVad->vaStart, "Entropy:[%.2f] %s %s %s", score, szVadType, szVadProtection, peVad->uszText);
        ObCounter_Add(ctx->pc, pProcess->dwPID, 1);
    }
fail:
    Ob_DECREF(pObVadMap);
}

VOID MEvilEntropy_CloseContext(_In_opt_ PMEVILENTROPY_CONTEXT ctxfc)
{
    if(!ctxfc) { return; }
    Ob_DECREF(ctxfc->pc);
    LocalFree(ctxfc);
}

PVOID MEvilEntropy_Initialize(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_CONTEXT ctxP)
{
    PMEVILENTROPY_CONTEXT ctxfc = NULL;
    if(!(ctxfc = LocalAlloc(LMEM_ZEROINIT, sizeof(MEVILENTROPY_CONTEXT)))) { goto fail; }
    if(!(ctxfc->pc = ObCounter_New(H, 0))) { goto fail; }
    return ctxfc;
fail:
    MEvilEntropy_CloseContext(ctxfc);
    return NULL;
}

VOID MEvilEntropy_FcIngestFinalize(_In_ VMM_HANDLE H, _In_opt_ PVOID ctxfc)
{
    MEvilEntropy_CloseContext(ctxfc);
}

VOID M_Evil_Entropy_Initialize(_In_ VMM_HANDLE H, _Inout_ PVMMDLL_PLUGIN_REGINFO pRI)
{
    if((pRI->magic != VMMDLL_PLUGIN_REGINFO_MAGIC) || (pRI->wVersion != VMMDLL_PLUGIN_REGINFO_VERSION)) { return; }
    strcpy_s(pRI->reg_info.uszPathName, 128, "\\forensic\\entropy");
    pRI->reg_info.fRootModule = TRUE;
    pRI->reg_info.fRootModuleHidden = TRUE;
    pRI->reg_fn.pfnList = NULL;
    pRI->reg_fn.pfnRead = NULL;
    pRI->reg_fn.pfnNotify = NULL;
    pRI->reg_fnfc.pfnInitialize = MEvilEntropy_Initialize;
    pRI->reg_fnfc.pfnIngestVirtmem = MEvilEntropy_IngestVirtmem;
    pRI->reg_fnfc.pfnIngestFinalize = MEvilEntropy_FcIngestFinalize;
    pRI->pfnPluginManager_Register(H, pRI);
}
