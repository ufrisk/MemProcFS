// m_vm.c : implementation of virtual machine sub virtual file system (vfs) functionality.
//
// (c) Ulf Frisk, 2022-2025
// Author: Ulf Frisk, pcileech@frizk.net
//

#include "modules.h"

#define MVM_LINELENGTH      133ULL
#define MVM_LINEHEADER      "   # VmMemPID Type         Flags   ObjectAddress       MaxGPA Name                                     OsType        OsBuild Mount"

VOID MVM_ReadLineCB(_In_ VMM_HANDLE H, _Inout_opt_ PVOID ctx, _In_ DWORD cbLineLength, _In_ DWORD ie, _In_ PVMM_MAP_VMENTRY pe, _Out_writes_(cbLineLength + 1) LPSTR usz)
{
    CHAR szMountID[16] = { 0 };
    if(pe->dwParentVmmMountID) {
        _snprintf_s(szMountID, _countof(szMountID), _TRUNCATE, "/vm/%i", pe->dwParentVmmMountID);
    }
    Util_usnprintf_ln(usz, cbLineLength,
        "%04x  %7i %-12s %c,%s %16llx %12llx %-40.40s %-15s %5i %s",
        ie,
        pe->dwVmMemPID,
        VMM_VM_TP_STRING[pe->tp],
        pe->fActive ? 'A' : 'T',
        pe->fActive ? (pe->fReadOnly ? "ro" : "rw") : "--",
        (QWORD)pe->hVM,
        pe->gpaMax,
        pe->uszName,
        VMM_SYSTEM_TP_STRING[pe->tpSystem],
        pe->dwVersionBuild,
        szMountID
    );
}

_Success_(return != NULL)
LPCSTR MVM_GetPathAndChild(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_CONTEXT ctxP, _Out_ VMM_HANDLE *phVmmChild)
{
    DWORD iChild;
    LPCSTR uszNewPath;
    CHAR uszChildIndex[32];
    uszNewPath = CharUtil_PathSplitFirst(ctxP->uszPath, uszChildIndex, _countof(uszChildIndex));
    iChild = strtoul(uszChildIndex, NULL, 10);
    if(iChild > 0) {
        AcquireSRWLockShared(&H->childvmm.LockSRW);
        if((iChild > 0) && (iChild <= H->childvmm.iMax)) {
            *phVmmChild = H->childvmm.h[iChild];
            ReleaseSRWLockShared(&H->childvmm.LockSRW);
            return uszNewPath;
        }
        ReleaseSRWLockShared(&H->childvmm.LockSRW);
    }
    return NULL;
}

NTSTATUS MVM_Write(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_CONTEXT ctxP, _In_reads_(cb) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbWrite, _In_ QWORD cbOffset)
{
    VMM_HANDLE hVmmChild = NULL;
    LPCSTR uszNewPath = MVM_GetPathAndChild(H, ctxP, &hVmmChild);
    if(uszNewPath && hVmmChild) {
        return VMMDLL_VfsWriteU(hVmmChild, uszNewPath, pb, cb, pcbWrite, cbOffset);
    }
    return VMMDLL_STATUS_FILE_INVALID;
}

NTSTATUS MVM_Read(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_CONTEXT ctxP, _Out_writes_to_(cb, *pcbRead) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset)
{
    NTSTATUS nt = VMMDLL_STATUS_FILE_INVALID;
    PVMMOB_MAP_VM pObVmMap = NULL;
    VMM_HANDLE hVmmChild = NULL;
    LPCSTR uszNewPath = NULL;
    if(CharUtil_StrEquals(ctxP->uszPath, "vm.txt", TRUE)) {
        // vm.txt
        if(VmmMap_GetVM(H, &pObVmMap)) {
            nt = Util_VfsLineFixed_Read(
                H, (UTIL_VFSLINEFIXED_PFN_CB)MVM_ReadLineCB, NULL, MVM_LINELENGTH, MVM_LINEHEADER,
                pObVmMap->pMap, pObVmMap->cMap, sizeof(VMM_MAP_VMENTRY),
                pb, cb, pcbRead, cbOffset
            );
            Ob_DECREF(pObVmMap);
        }
    } else {
        // child vm vfs:
        uszNewPath = MVM_GetPathAndChild(H, ctxP, &hVmmChild);
        if(uszNewPath && hVmmChild) {
            return VMMDLL_VfsReadU(hVmmChild, uszNewPath, pb, cb, pcbRead, cbOffset);
        }
    }
    return nt;
}

BOOL MVM_List(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_CONTEXT ctxP, _Inout_ PHANDLE pFileList)
{
    DWORD i;
    LPCSTR uszNewPath;
    VMM_HANDLE hVmmChild = NULL;
    CHAR uszBuffer[32];
    PVMMOB_MAP_VM pObVmMap = NULL;
    // display root directory:
    if(!ctxP->uszPath[0]) {
        AcquireSRWLockShared(&H->childvmm.LockSRW);
        for(i = 1; i <= H->childvmm.iMax; i++) {
            if(H->childvmm.h[i]) {
                _snprintf_s(uszBuffer, _countof(uszBuffer), _TRUNCATE, "%i", i);
                VMMDLL_VfsList_AddDirectory(pFileList, uszBuffer, NULL);
            }
        }
        ReleaseSRWLockShared(&H->childvmm.LockSRW);
        if(VmmMap_GetVM(H, &pObVmMap)) {
            VMMDLL_VfsList_AddFile(pFileList, "vm.txt", UTIL_VFSLINEFIXED_LINECOUNT(H, pObVmMap->cMap) * MVM_LINELENGTH, NULL);
            Ob_DECREF(pObVmMap);
        }
        return TRUE;
    }
    // display sub-directory:
    uszNewPath = MVM_GetPathAndChild(H, ctxP, &hVmmChild);
    if(uszNewPath && hVmmChild) {
        return VMMDLL_VfsListU(hVmmChild, uszNewPath, (PVMMDLL_VFS_FILELIST2)pFileList);
    }
    return TRUE;
}

VOID MVM_FcLogJSON(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_CONTEXT ctxP, _In_ VOID(*pfnLogJSON)(_In_ VMM_HANDLE H, _In_ PVMMDLL_FORENSIC_JSONDATA pData))
{
    PVMMDLL_FORENSIC_JSONDATA pd;
    PVMMOB_MAP_VM pObVmMap = NULL;
    PVMM_MAP_VMENTRY pe;
    DWORD i;
    CHAR usz[MAX_PATH];
    if(ctxP->pProcess || !(pd = LocalAlloc(LMEM_ZEROINIT, sizeof(VMMDLL_FORENSIC_JSONDATA)))) { return; }
    pd->dwVersion = VMMDLL_FORENSIC_JSONDATA_VERSION;
    pd->szjType = "virtualmachine";
    if(VmmMap_GetVM(H, &pObVmMap)) {
        for(i = 0; i < pObVmMap->cMap; i++) {
            pe = pObVmMap->pMap + i;
            pd->i = i;
            pd->vaObj = (QWORD)pe->hVM;
            pd->qwHex[0] = pe->dwPartitionID;
            pd->va[0] = pe->gpaMax;
            pd->usz[0] = pe->uszName;
            snprintf(usz, sizeof(usz), "active:[%s] type:[%s] build:[%i]",
                VMM_VM_TP_STRING[pe->tp],
                pe->fActive ? "TRUE": "FALSE",
                pe->dwVersionBuild
            );
            pd->usz[1] = usz;
            pfnLogJSON(H, pd);
        }
    }
    Ob_DECREF(pObVmMap);
    LocalFree(pd);
}

VOID MVM_FcLogCSV(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_CONTEXT ctxP, _In_ VMMDLL_CSV_HANDLE hCSV)
{
    DWORD i;
    PVMM_MAP_VMENTRY pe;
    PVMMOB_MAP_VM pObVmMap = NULL;
    if(!ctxP->pProcess) {
        FcFileAppend(H, "virtualmachines.csv", "Name,Type,MaxGPA,Build,SystemType,PartitionID,IsActive,IsReadonly,IsPhysicalOnly,VmmemPID,MountID\n");
        if(VmmMap_GetVM(H, &pObVmMap)) {
            for(i = 0; i < pObVmMap->cMap; i++) {
                pe = pObVmMap->pMap + i;
                //"Name,Type,MaxGPA,Build,SystemType,PartitionID,IsActive,IsReadonly,IsPhysicalOnly,VmmemPID,MountID"
                FcCsv_Reset(hCSV);
                FcFileAppend(H, "virtualmachines.csv", "%s,%s,%llx,%u,%s,%u,%s,%s,%s,%u,%u\n",
                    FcCsv_String(hCSV, pe->uszName),
                    FcCsv_String(hCSV, (LPSTR)VMM_VM_TP_STRING[pe->tp]),
                    pe->gpaMax,
                    pe->dwVersionBuild,
                    FcCsv_String(hCSV, (LPSTR)VMM_SYSTEM_TP_STRING[pe->tpSystem]),
                    pe->dwPartitionID,
                    pe->fActive ? "TRUE" : "FALSE",
                    pe->fReadOnly ? "TRUE" : "FALSE",
                    pe->fPhysicalOnly ? "TRUE" : "FALSE",
                    pe->dwVmMemPID,
                    pe->dwParentVmmMountID
                );
            }
        }
        Ob_DECREF(pObVmMap);
    }
}

VOID M_VM_Initialize(_In_ VMM_HANDLE H, _Inout_ PVMMDLL_PLUGIN_REGINFO pRI)
{
    if(!H->cfg.fVM) { return; }
    if((pRI->magic != VMMDLL_PLUGIN_REGINFO_MAGIC) || (pRI->wVersion != VMMDLL_PLUGIN_REGINFO_VERSION)) { return; }
    if((pRI->tpSystem != VMM_SYSTEM_WINDOWS_64) && (pRI->tpSystem != VMM_SYSTEM_WINDOWS_32)) { return; }
    strcpy_s(pRI->reg_info.uszPathName, 128, "\\vm");           // module name
    pRI->reg_info.fRootModule = TRUE;                           // module shows in root directory
    pRI->reg_fn.pfnList = MVM_List;                             // List function supported
    pRI->reg_fn.pfnRead = MVM_Read;                             // Read function supported
    pRI->reg_fn.pfnWrite = MVM_Write;                           // Write function supported
    pRI->reg_fnfc.pfnLogJSON = MVM_FcLogJSON;                   // JSON log function supported
    pRI->reg_fnfc.pfnLogCSV = MVM_FcLogCSV;                     // CSV log function supported
    pRI->pfnPluginManager_Register(H, pRI);
}
