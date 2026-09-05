// vmmloader.c : implementation related to transparent loading of vmm (Windows) or vmmlx (Linux) memory parsing engines.
//
// (c) Ulf Frisk, 2026
// Author: Ulf Frisk, pcileech@frizk.net
//
#define VMMLOADER_NO_REMAP
#include "vmmloader.h"
#include "oscompatibility.h"

typedef VMM_HANDLE(*PFN_VMMLX_INITIALIZE)(_In_ DWORD argc, _In_ LPCSTR argv[]);
typedef VOID(*PFN_VMMLX_CLOSEALL)();
typedef VOID(*PFN_VMMLX_MEMFREE)(_Frees_ptr_opt_ PVOID pvMem);
typedef BOOL(*PFN_VMMLX_CONFIGGET)(_In_ VMM_HANDLE hVMM, _In_ ULONG64 fOption, _Out_ PULONG64 pqwValue);
typedef BOOL(*PFN_VMMLX_CONFIGSET)(_In_ VMM_HANDLE hVMM, _In_ ULONG64 fOption, _In_ ULONG64 qwValue);
typedef BOOL(*PFN_VMMLX_INITIALIZEPLUGINS)(_In_ VMM_HANDLE hVMM);
typedef BOOL(*PFN_VMMLX_VFSLISTU)(_In_ VMM_HANDLE hVMM, _In_ LPCSTR uszPath, _Inout_ PVMMDLL_VFS_FILELIST2 pFileList);
typedef NTSTATUS(*PFN_VMMLX_VFSREADU)(_In_ VMM_HANDLE hVMM, _In_ LPCSTR uszFileName, _Out_writes_to_(cb, *pcbRead) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ ULONG64 cbOffset);
typedef NTSTATUS(*PFN_VMMLX_VFSWRITEU)(_In_ VMM_HANDLE hVMM, _In_ LPCSTR uszFileName, _In_reads_(cb) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbWrite, _In_ ULONG64 cbOffset);
typedef NTSTATUS(*PFN_VMMLX_VFSREADW)(_In_ VMM_HANDLE hVMM, _In_ LPCWSTR wszFileName, _Out_writes_to_(cb, *pcbRead) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ ULONG64 cbOffset);
typedef NTSTATUS(*PFN_VMMLX_VFSWRITEW)(_In_ VMM_HANDLE hVMM, _In_ LPCWSTR wszFileName, _In_reads_(cb) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbWrite, _In_ ULONG64 cbOffset);
typedef LPSTR(*PFN_VMMLX_LICENSEDTO)();

typedef struct tdVMMLX_LOADER_CONTEXT {
    HMODULE hModule;
    PFN_VMMLX_INITIALIZE pfnInitialize;
    PFN_VMMLX_CLOSEALL pfnCloseAll;
    PFN_VMMLX_MEMFREE pfnMemFree;
    PFN_VMMLX_CONFIGGET pfnConfigGet;
    PFN_VMMLX_CONFIGSET pfnConfigSet;
    PFN_VMMLX_INITIALIZEPLUGINS pfnInitializePlugins;
    PFN_VMMLX_VFSLISTU pfnVfsListU;
    PFN_VMMLX_VFSREADU pfnVfsReadU;
    PFN_VMMLX_VFSWRITEU pfnVfsWriteU;
    PFN_VMMLX_VFSREADW pfnVfsReadW;
    PFN_VMMLX_VFSWRITEW pfnVfsWriteW;
    PFN_VMMLX_LICENSEDTO pfnLicensedTo;
} VMMLX_LOADER_CONTEXT;

static VMMLX_LOADER_CONTEXT g_VmmlxLoader = { 0 };

static PVOID VmmlxLoader_GetSymbol(_In_ LPCSTR szSymbol)
{
#ifdef _WIN32
    return GetProcAddress(g_VmmlxLoader.hModule, szSymbol);
#else /* _WIN32 */
    return dlsym(g_VmmlxLoader.hModule, szSymbol);
#endif /* _WIN32 */
}

static VOID VmmlxLoader_CloseModule()
{
    if(!g_VmmlxLoader.hModule) {
        return;
    }
#ifdef _WIN32
    FreeLibrary(g_VmmlxLoader.hModule);
#else /* _WIN32 */
    dlclose(g_VmmlxLoader.hModule);
#endif /* _WIN32 */
    memset(&g_VmmlxLoader, 0, sizeof(g_VmmlxLoader));
}

#ifdef _WIN32
static HMODULE VmmlxLoader_LoadLocalModule()
{
    DWORD cchPath;
    LPWSTR wszSlash;
    WCHAR wszPath[MAX_PATH];
    cchPath = GetModuleFileNameW(NULL, wszPath, _countof(wszPath));
    if(!cchPath || (cchPath >= _countof(wszPath)) || !(wszSlash = wcsrchr(wszPath, L'\\'))) {
        return NULL;
    }
    if(0 != wcscpy_s(wszSlash + 1, _countof(wszPath) - (wszSlash + 1 - wszPath), L"vmmlx.dll")) {
        return NULL;
    }
    g_VmmlxLoader.hModule = LoadLibraryW(wszPath);
    return g_VmmlxLoader.hModule;
}
#elif defined(MACOS)
static HMODULE VmmlxLoader_LoadLocalModule()
{
    g_VmmlxLoader.hModule = dlopen("@executable_path/vmmlx.dylib", RTLD_NOW | RTLD_LOCAL);
    return g_VmmlxLoader.hModule;
}
#else /* LINUX */
static HMODULE VmmlxLoader_LoadLocalModule()
{
    LPSTR szSlash;
    ssize_t cchPath;
    CHAR szPath[4096];
    cchPath = readlink("/proc/self/exe", szPath, sizeof(szPath) - 1);
    if((cchPath <= 0) || ((SIZE_T)cchPath >= sizeof(szPath) - 1)) {
        return NULL;
    }
    szPath[cchPath] = 0;
    if(!(szSlash = strrchr(szPath, '/')) || ((SIZE_T)(szSlash + 1 - szPath) + sizeof("vmmlx.so") > sizeof(szPath))) {
        return NULL;
    }
    strcpy(szSlash + 1, "vmmlx.so");
    g_VmmlxLoader.hModule = dlopen(szPath, RTLD_NOW | RTLD_LOCAL);
    return g_VmmlxLoader.hModule;
}
#endif /* _WIN32 || MACOS || LINUX */

#define VMMLOADER_RESOLVE(fn, suffix)                                            \
    do {                                                                            \
        LPCSTR szSymbol = "VMMLX_" suffix;                                          \
        PVOID pSymbol = VmmlxLoader_GetSymbol(szSymbol);                            \
        if(!pSymbol || (sizeof(pSymbol) != sizeof(g_VmmlxLoader.fn))) {             \
            VmmlxLoader_CloseModule();                                              \
            return FALSE;                                                           \
        }                                                                           \
        memcpy(&g_VmmlxLoader.fn, &pSymbol, sizeof(g_VmmlxLoader.fn));              \
    } while(0)

_Success_(return)
BOOL VmmlxLoader_Initialize()
{
    if(g_VmmlxLoader.hModule) { return TRUE; }
    if(!VmmlxLoader_LoadLocalModule()) { return FALSE; }
    VMMLOADER_RESOLVE(pfnInitialize, "Initialize");
    VMMLOADER_RESOLVE(pfnCloseAll, "CloseAll");
    VMMLOADER_RESOLVE(pfnMemFree, "MemFree");
    VMMLOADER_RESOLVE(pfnConfigGet, "ConfigGet");
    VMMLOADER_RESOLVE(pfnConfigSet, "ConfigSet");
    VMMLOADER_RESOLVE(pfnInitializePlugins, "InitializePlugins");
    VMMLOADER_RESOLVE(pfnLicensedTo, "LicensedTo");
    VMMLOADER_RESOLVE(pfnVfsListU, "VfsListU");
    VMMLOADER_RESOLVE(pfnVfsReadU, "VfsReadU");
    VMMLOADER_RESOLVE(pfnVfsWriteU, "VfsWriteU");
#ifdef _WIN32
    VMMLOADER_RESOLVE(pfnVfsReadW, "VfsReadW");
    VMMLOADER_RESOLVE(pfnVfsWriteW, "VfsWriteW");
#endif /* _WIN32 */
    return TRUE;
}

VMM_HANDLE VmmlxLoader_VmmInitialize(_In_ DWORD argc, _In_ LPCSTR argv[])
{
    return g_VmmlxLoader.hModule ? g_VmmlxLoader.pfnInitialize(argc, argv) : VMMDLL_Initialize(argc, argv);
}

VOID VmmlxLoader_VmmCloseAll()
{
    if(g_VmmlxLoader.hModule) {
        g_VmmlxLoader.pfnCloseAll();
    } else {
        VMMDLL_CloseAll();
    }
}

VOID VmmlxLoader_VmmMemFree(_Frees_ptr_opt_ PVOID pvMem)
{
    if(g_VmmlxLoader.hModule) {
        g_VmmlxLoader.pfnMemFree(pvMem);
    } else {
        VMMDLL_MemFree(pvMem);
    }
}

BOOL VmmlxLoader_VmmConfigGet(_In_ VMM_HANDLE hVMM, _In_ ULONG64 fOption, _Out_ PULONG64 pqwValue)
{
    return g_VmmlxLoader.hModule ? g_VmmlxLoader.pfnConfigGet(hVMM, fOption, pqwValue) : VMMDLL_ConfigGet(hVMM, fOption, pqwValue);
}

BOOL VmmlxLoader_VmmConfigSet(_In_ VMM_HANDLE hVMM, _In_ ULONG64 fOption, _In_ ULONG64 qwValue)
{
    return g_VmmlxLoader.hModule ? g_VmmlxLoader.pfnConfigSet(hVMM, fOption, qwValue) : VMMDLL_ConfigSet(hVMM, fOption, qwValue);
}

BOOL VmmlxLoader_VmmInitializePlugins(_In_ VMM_HANDLE hVMM)
{
    return g_VmmlxLoader.hModule ? g_VmmlxLoader.pfnInitializePlugins(hVMM) : VMMDLL_InitializePlugins(hVMM);
}

LPSTR VmmlxLoader_VmmLicensedTo()
{
    return g_VmmlxLoader.hModule ? g_VmmlxLoader.pfnLicensedTo() : VMMDLL_LicensedTo();
}

BOOL VmmlxLoader_VmmVfsListU(_In_ VMM_HANDLE hVMM, _In_ LPCSTR uszPath, _Inout_ PVMMDLL_VFS_FILELIST2 pFileList)
{
    return g_VmmlxLoader.hModule ? g_VmmlxLoader.pfnVfsListU(hVMM, uszPath, pFileList) : VMMDLL_VfsListU(hVMM, uszPath, pFileList);
}

NTSTATUS VmmlxLoader_VmmVfsReadU(_In_ VMM_HANDLE hVMM, _In_ LPCSTR uszFileName, _Out_writes_to_(cb, *pcbRead) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ ULONG64 cbOffset)
{
    return g_VmmlxLoader.hModule ? g_VmmlxLoader.pfnVfsReadU(hVMM, uszFileName, pb, cb, pcbRead, cbOffset) : VMMDLL_VfsReadU(hVMM, uszFileName, pb, cb, pcbRead, cbOffset);
}

NTSTATUS VmmlxLoader_VmmVfsWriteU(_In_ VMM_HANDLE hVMM, _In_ LPCSTR uszFileName, _In_reads_(cb) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbWrite, _In_ ULONG64 cbOffset)
{
    return g_VmmlxLoader.hModule ? g_VmmlxLoader.pfnVfsWriteU(hVMM, uszFileName, pb, cb, pcbWrite, cbOffset) : VMMDLL_VfsWriteU(hVMM, uszFileName, pb, cb, pcbWrite, cbOffset);
}

#ifdef _WIN32
NTSTATUS VmmlxLoader_VmmVfsReadW(_In_ VMM_HANDLE hVMM, _In_ LPCWSTR wszFileName, _Out_writes_to_(cb, *pcbRead) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ ULONG64 cbOffset)
{
    return g_VmmlxLoader.hModule ? g_VmmlxLoader.pfnVfsReadW(hVMM, wszFileName, pb, cb, pcbRead, cbOffset) : VMMDLL_VfsReadW(hVMM, wszFileName, pb, cb, pcbRead, cbOffset);
}

NTSTATUS VmmlxLoader_VmmVfsWriteW(_In_ VMM_HANDLE hVMM, _In_ LPCWSTR wszFileName, _In_reads_(cb) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbWrite, _In_ ULONG64 cbOffset)
{
    return g_VmmlxLoader.hModule ? g_VmmlxLoader.pfnVfsWriteW(hVMM, wszFileName, pb, cb, pcbWrite, cbOffset) : VMMDLL_VfsWriteW(hVMM, wszFileName, pb, cb, pcbWrite, cbOffset);
}
#endif /* _WIN32 */
