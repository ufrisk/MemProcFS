// m_misc_view.c : view filtered file system under 'misc/view/txt' & 'misc/view/bin'
//
// (c) Ulf Frisk, 2022-2025
// Author: Ulf Frisk, pcileech@frizk.net
//

#include "modules.h"

// forward declarations of VFS implemented functionality in core VMMDLL.
BOOL VMMDLL_VfsList_Impl(_In_ VMM_HANDLE H, _In_ LPCSTR uszPath, _Inout_ PHANDLE pFileList);
NTSTATUS VMMDLL_VfsRead_Impl(_In_ VMM_HANDLE H, _In_ LPCSTR uszPath, _Out_writes_to_(cb, *pcbRead) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset);
NTSTATUS VMMDLL_VfsWrite_Impl(_In_ VMM_HANDLE H, _In_ LPCSTR uszPath, _In_reads_(cb) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbWrite, _In_ QWORD cbOffset);

LPSTR szMVIEW_EXCLUDE_DIRS_ROOT[] = {
    "forensic\\ntfs\\.-"
    "forensic\\ntfs\\_"
    "forensic\\ntfs\\ORPHAN"
    "misc\\phys2virt",
    "misc\\search",
    "misc\\view",
    "sys\\memory",
    "sys\\pool\\all\\by-tag",
    "sys\\pool\\big\\by-tag",
};

LPSTR szMVIEW_EXCLUDE_DIRS_PROC[] = {
    "heaps",
    "phys2virt",
    "search"
};

LPSTR szMVIEW_README =
"View plugin for MemProcFS:                                                  \n" \
"==========================                                                  \n" \
"                                                                            \n" \
"The view plugin show the file system in a text and binary view. The plugin  \n" \
"also adds additional filtering - such as file size (max 128MB) and the      \n" \
"exclusion of some known directories.                                        \n" \
"---                                                                         \n" \
"Documentation: https://github.com/ufrisk/MemProcFS/wiki/FS_View             \n";

typedef struct tdMVIEW_VFS_FILELIST3 {
    DWORD dwVersion;
    VOID(*pfnAddFile)     (_Inout_ HANDLE h, _In_ LPSTR uszName, _In_ ULONG64 cb, _In_opt_ PVMMDLL_VFS_FILELIST_EXINFO pExInfo);
    VOID(*pfnAddDirectory)(_Inout_ HANDLE h, _In_ LPSTR uszName, _In_opt_ PVMMDLL_VFS_FILELIST_EXINFO pExInfo);
    HANDLE hSelf;
    BOOL fTXT;
    BOOL fBIN;
    LPSTR szPath;
    QWORD cbMaxBin;
    PVMMDLL_VFS_FILELIST2 pFileList2;
} MVIEW_VFS_FILELIST3, *PMVIEW_VFS_FILELIST3;

NTSTATUS MView_Write(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_CONTEXT ctxP, _In_reads_(cb) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbWrite, _In_ QWORD cbOffset)
{
    if(CharUtil_StrStartsWith(ctxP->uszPath, "txt", TRUE) || CharUtil_StrStartsWith(ctxP->uszPath, "bin", TRUE)) {
        return VMMDLL_VfsWrite_Impl(H, ctxP->uszPath + 3, pb, cb, pcbWrite, cbOffset);
    }
    return VMMDLL_STATUS_FILE_INVALID;
}

NTSTATUS MView_Read(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_CONTEXT ctxP, _Out_writes_to_(cb, *pcbRead) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset)
{
    if(!_stricmp("readme.txt", ctxP->uszPath)) {
        return VMMDLL_UtilVfsReadFile_FromPBYTE(szMVIEW_README, strlen(szMVIEW_README), pb, cb, pcbRead, cbOffset);
    }
    if(CharUtil_StrStartsWith(ctxP->uszPath, "txt", TRUE) || CharUtil_StrStartsWith(ctxP->uszPath, "bin", TRUE)) {
        return VMMDLL_VfsRead_Impl(H, ctxP->uszPath + 3, pb, cb, pcbRead, cbOffset);
    }
    return VMMDLL_STATUS_FILE_INVALID;
}

/*
* Callback function to add a file during a list operation.
*/
VOID MView_AddFileCB(_Inout_ HANDLE h, _In_ LPSTR uszName, _In_ ULONG64 cb, _In_opt_ PVMMDLL_VFS_FILELIST_EXINFO pExInfo)
{
    PMVIEW_VFS_FILELIST3 p = (PMVIEW_VFS_FILELIST3)h;
    BOOL f = FALSE;
    if(p->fTXT) {
        f = CharUtil_StrEndsWith(uszName, ".txt", TRUE);
    }
    if(p->fBIN) {
        f = !CharUtil_StrEndsWith(uszName, ".txt", TRUE) && (cb <= p->cbMaxBin);
    }
    if(f) {
        p->pFileList2->pfnAddFile(p->pFileList2->h, uszName, cb, pExInfo);
    }
}

/*
* Callback function to add a directory during a list operation.
*/
VOID MView_AddDirectoryCB(_Inout_ HANDLE h, _In_ LPSTR uszName, _In_opt_ PVMMDLL_VFS_FILELIST_EXINFO pExInfo)
{
    PMVIEW_VFS_FILELIST3 p = (PMVIEW_VFS_FILELIST3)h;
    LPCSTR szProcPath;
    CHAR szPath[MAX_PATH];
    DWORD i;
    _snprintf_s(szPath, _countof(szPath), _TRUNCATE, "%s\\%s", p->szPath, uszName);
    if(CharUtil_StrStartsWith(szPath, "name", TRUE) || CharUtil_StrStartsWith(szPath, "pid", TRUE)) {
        // check for excluded per-process directories
        szProcPath = CharUtil_PathSplitNext(CharUtil_PathSplitNext(szPath));
        for(i = 0; i < sizeof(szMVIEW_EXCLUDE_DIRS_PROC) / sizeof(LPSTR); i++) {
            if(CharUtil_StrStartsWith(szProcPath, szMVIEW_EXCLUDE_DIRS_PROC[i], TRUE)) {
                return;
            }
        }
    } else {
        // check for excluded global directories
        for(i = 0; i < sizeof(szMVIEW_EXCLUDE_DIRS_ROOT) / sizeof(LPSTR); i++) {
            if(CharUtil_StrStartsWith(szPath, szMVIEW_EXCLUDE_DIRS_ROOT[i], TRUE)) {
                return;
            }
        }
    }
    // dispatch to nested original AddDirectory function.
    p->pFileList2->pfnAddDirectory(p->pFileList2->h, uszName, pExInfo);
}

BOOL MView_List(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_CONTEXT ctxP, _Inout_ PHANDLE pFileList)
{
    MVIEW_VFS_FILELIST3 FileList3 = { 0 };
    if(((PMVIEW_VFS_FILELIST3)pFileList)->hSelf == (HANDLE)pFileList) {
        // nested listings are not allowed!
        return TRUE;
    }
    if(!ctxP->uszPath[0]) {
        VMMDLL_VfsList_AddFile(pFileList, "readme.txt", strlen(szMVIEW_README), NULL);
        VMMDLL_VfsList_AddDirectory(pFileList, "txt", NULL);
        VMMDLL_VfsList_AddDirectory(pFileList, "bin", NULL);
        return TRUE;
    }
    FileList3.dwVersion = VMMDLL_VFS_FILELIST_VERSION;
    FileList3.pfnAddFile = MView_AddFileCB;
    FileList3.pfnAddDirectory = MView_AddDirectoryCB;
    FileList3.hSelf = (HANDLE)&FileList3;
    FileList3.pFileList2 = (PVMMDLL_VFS_FILELIST2)pFileList;
    if(CharUtil_StrStartsWith(ctxP->uszPath, "txt", TRUE)) {
        FileList3.fTXT = TRUE;
        FileList3.szPath = ctxP->uszPath + ((ctxP->uszPath[3] == '\\') ? 4 : 3);
        VMMDLL_VfsList_Impl(H, FileList3.szPath, (PHANDLE)&FileList3);
        return TRUE;
    }
    if(CharUtil_StrStartsWith(ctxP->uszPath, "bin", TRUE)) {
        FileList3.fBIN = TRUE;
        FileList3.cbMaxBin = 0x10000000;
        FileList3.szPath = ctxP->uszPath + ((ctxP->uszPath[3] == '\\') ? 4 : 3);
        VMMDLL_VfsList_Impl(H, FileList3.szPath, (PHANDLE)&FileList3);
        return TRUE;
    }
    return TRUE;
}

VOID M_MiscView_Initialize(_In_ VMM_HANDLE H, _Inout_ PVMMDLL_PLUGIN_REGINFO pRI)
{
    if((pRI->magic != VMMDLL_PLUGIN_REGINFO_MAGIC) || (pRI->wVersion != VMMDLL_PLUGIN_REGINFO_VERSION)) { return; }
    strcpy_s(pRI->reg_info.uszPathName, 128, "\\misc\\view");                   // module name
    pRI->reg_info.fRootModule = TRUE;                                           // module shows in root directory
    // functions supported:
    pRI->reg_fn.pfnList = MView_List;
    pRI->reg_fn.pfnRead = MView_Read;
    pRI->reg_fn.pfnWrite = MView_Write;
    pRI->pfnPluginManager_Register(H, pRI);
}
