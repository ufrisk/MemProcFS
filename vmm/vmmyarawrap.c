// vmmyarawrap.c : Internal wrapper API around the vmmyara.dll/so library.
// 
// The vmmyara library is dynamically loaded and this wrapper will perform a
// graceful fallback if the library is not available. The vmmyara library may
// be treated as a singleton shared amongst all instances of VMM.DLL/MemProcFS.
// 
// (c) Ulf Frisk, 2023-2025
// Author: Ulf Frisk, pcileech@frizk.net
//
#include "vmm.h"
#include "util.h"
#include <vmmyara.h>

typedef VMMYARA_ERROR(*pfnVmmYara_RulesLoadSourceCombined)(
    _In_ DWORD cszSourceCombinedRules,
    _In_reads_(cszSourceCombinedRules) LPSTR pszSourceCombinedRules[],
    _Out_ PVMMYARA_RULES *phVmmYaraRules
    );

typedef VMMYARA_ERROR(*pfnVmmYara_RulesLoadCompiled)(
    _In_ LPSTR szCompiledFileRules,
    _Out_ PVMMYARA_RULES *phVmmYaraRules
);

typedef VMMYARA_ERROR(*pfnVmmYara_RulesLoadSourceFile)(
    _In_ DWORD cszSourceFileRules,
    _In_reads_(cszSourceFileRules) LPSTR pszSourceFileRules[],
    _Out_ PVMMYARA_RULES *phVmmYaraRules
);

typedef VMMYARA_ERROR(*pfnVmmYara_RulesLoadSourceString)(
    _In_ DWORD cszSourceStringRules,
    _In_reads_(cszSourceStringRules) LPSTR pszSourceStringRules[],
    _Out_ PVMMYARA_RULES *phVmmYaraRules
);

typedef VMMYARA_ERROR(*pfnVmmYara_RulesDestroy)(
    _In_ PVMMYARA_RULES hVmmYaraRules
);

typedef VMMYARA_ERROR(*pfnVmmYara_ScanMemory)(
    _In_ PVMMYARA_RULES hVmmYaraRules,
    _In_reads_bytes_(cbBuffer) PBYTE pbBuffer,
    _In_ SIZE_T cbBuffer,
    _In_ int flags,
    _In_ VMMYARA_SCAN_MEMORY_CALLBACK pfnCallback,
    _In_ PVOID pvContext,
    _In_ int timeout
);

// globals - shared amongst all instances
BOOL g_VmmYaraInitialized = FALSE;
BOOL g_VmmYaraInitializeFail = FALSE;
HMODULE g_VmmYaraDLL = 0;
pfnVmmYara_RulesLoadCompiled gpfn_VmmYara_RulesLoadCompiled = NULL;
pfnVmmYara_RulesLoadSourceCombined gpfn_VmmYara_RulesLoadSourceCombined = NULL;
pfnVmmYara_RulesLoadSourceFile gpfn_VmmYara_RulesLoadSourceFile = NULL;
pfnVmmYara_RulesLoadSourceString gpfn_VmmYara_RulesLoadSourceString = NULL;
pfnVmmYara_RulesDestroy gpfn_VmmYara_RulesDestroy = NULL;
pfnVmmYara_ScanMemory gpfn_VmmYara_ScanMemory = NULL;

/*
* Initialize the yara functionality for all instances on the first call.
*/
VOID VmmYara_Initialize()
{
    CHAR szLibraryPath[MAX_PATH];
    if(g_VmmYaraInitialized || g_VmmYaraInitializeFail) { return; }
    ZeroMemory(szLibraryPath, sizeof(szLibraryPath));
    Util_GetPathLib(szLibraryPath);
    strcat_s(szLibraryPath, MAX_PATH, "vmmyara"VMM_LIBRARY_FILETYPE);
    g_VmmYaraDLL = LoadLibraryU(szLibraryPath);
#ifndef _WIN32
if(!g_VmmYaraDLL) {
        ZeroMemory(szLibraryPath, sizeof(szLibraryPath));
        Util_GetPathLib(szLibraryPath);
        strcat_s(szLibraryPath, MAX_PATH, "vmmyara2"VMM_LIBRARY_FILETYPE);
        g_VmmYaraDLL = LoadLibraryU(szLibraryPath);
    }
#endif /* _WIN32 */
    if(!g_VmmYaraDLL) { goto fail; }
    if(!(gpfn_VmmYara_RulesLoadCompiled = (pfnVmmYara_RulesLoadCompiled)GetProcAddress(g_VmmYaraDLL, "VmmYara_RulesLoadCompiled"))) { goto fail; }
    if(!(gpfn_VmmYara_RulesLoadSourceCombined = (pfnVmmYara_RulesLoadSourceString)GetProcAddress(g_VmmYaraDLL, "VmmYara_RulesLoadSourceCombined"))) { goto fail; }
    if(!(gpfn_VmmYara_RulesLoadSourceFile = (pfnVmmYara_RulesLoadSourceFile)GetProcAddress(g_VmmYaraDLL, "VmmYara_RulesLoadSourceFile"))) { goto fail; }
    if(!(gpfn_VmmYara_RulesLoadSourceString = (pfnVmmYara_RulesLoadSourceString)GetProcAddress(g_VmmYaraDLL, "VmmYara_RulesLoadSourceString"))) { goto fail; }
    if(!(gpfn_VmmYara_RulesDestroy = (pfnVmmYara_RulesDestroy)GetProcAddress(g_VmmYaraDLL, "VmmYara_RulesDestroy"))) { goto fail; }
    if(!(gpfn_VmmYara_ScanMemory = (pfnVmmYara_ScanMemory)GetProcAddress(g_VmmYaraDLL, "VmmYara_ScanMemory"))) { goto fail; }
    g_VmmYaraInitialized = TRUE;
    return;
fail:
    g_VmmYaraInitializeFail = TRUE;
    if(g_VmmYaraDLL) { FreeLibrary(g_VmmYaraDLL); }
    g_VmmYaraDLL = 0;
}

/*
* Load a compiled yara rule file.
* -- szCompiledFileRules = the file path of the compiled yara rule file to load.
* -- phVmmYaraRules = pointer to a PVMMYARA_RULES variable that will receive
*                    the handle to the loaded rule set on success.
* -- return = VMMYARA_ERROR_SUCCESS on success, otherwise a yara error.
*/
_Success_(return == VMMYARA_ERROR_SUCCESS)
VMMYARA_ERROR VmmYara_RulesLoadCompiled(
    _In_ LPSTR szCompiledFileRules,
    _Out_ PVMMYARA_RULES *phVmmYaraRules
) {
    VmmYara_Initialize();
    if(!g_VmmYaraInitialized) { return VMMYARA_ERROR_INVALID_FILE; }
    return gpfn_VmmYara_RulesLoadCompiled(szCompiledFileRules, phVmmYaraRules);
}

/*
* Load one or multiple yara rules from either memory or source files.
* -- cszSourceCombinedRules = the number of source files/strings to load.
* -- pszSourceCombinedRules = array of source file paths/strings to load.
* -- phVmmYaraRules = pointer to a PVMMYARA_RULES variable that will receive the
*                    handle to the loaded rule set on success.
* -- return = VMMYARA_ERROR_SUCCESS on success, otherwise a yara error.
*/
_Success_(return == VMMYARA_ERROR_SUCCESS)
VMMYARA_ERROR VmmYara_RulesLoadSourceCombined(
    _In_ DWORD cszSourceCombinedRules,
    _In_reads_(cszSourceCombinedRules) LPSTR pszSourceCombinedRules[],
    _Out_ PVMMYARA_RULES *phVmmYaraRules
) {
    VmmYara_Initialize();
    if(!g_VmmYaraInitialized) { return VMMYARA_ERROR_INVALID_FILE; }
    return gpfn_VmmYara_RulesLoadSourceCombined(cszSourceCombinedRules, pszSourceCombinedRules, phVmmYaraRules);
}

/*
* Load one or multiple yara rules from source files.
* -- cszSourceFileRules = the number of source files to load.
* -- pszSourceFileRules = array of source file paths to load.
* -- phVmmYaraRules = pointer to a PVMMYARA_RULES variable that will receive
*                    the handle to the loaded rule set on success.
* -- return = VMMYARA_ERROR_SUCCESS on success, otherwise a yara error.
*/
_Success_(return == VMMYARA_ERROR_SUCCESS)
VMMYARA_ERROR VmmYara_RulesLoadSourceFile(
    _In_ DWORD cszSourceFileRules,
    _In_reads_(cszSourceFileRules) LPSTR pszSourceFileRules[],
    _Out_ PVMMYARA_RULES *phVmmYaraRules
) {
    VmmYara_Initialize();
    if(!g_VmmYaraInitialized) { return VMMYARA_ERROR_INVALID_FILE; }
    return gpfn_VmmYara_RulesLoadSourceFile(cszSourceFileRules, pszSourceFileRules, phVmmYaraRules);
}

/*
* Load one or multiple yara rules from in-memory source strings.
* -- cszSourceStringRules = the number of source strings to load.
* -- pszSourceStringRules = array of source strings to load.
* -- phVmmYaraRules = pointer to a PVMMYARA_RULES variable that will receive
*                    the handle to the loaded rule set on success.
* -- return = VMMYARA_ERROR_SUCCESS on success, otherwise a yara error.
*/
_Success_(return == VMMYARA_ERROR_SUCCESS)
VMMYARA_ERROR VmmYara_RulesLoadSourceString(
    _In_ DWORD cszSourceStringRules,
    _In_reads_(cszSourceStringRules) LPSTR pszSourceStringRules[],
    _Out_ PVMMYARA_RULES *phVmmYaraRules
) {
    VmmYara_Initialize();
    if(!g_VmmYaraInitialized) { return VMMYARA_ERROR_INVALID_FILE; }
    return gpfn_VmmYara_RulesLoadSourceString(cszSourceStringRules, pszSourceStringRules, phVmmYaraRules);
}

/*
* Destroy a previously loaded rule set.
* -- hVmmYaraRules = the handle to the rule set to destroy.
* -- return = VMMYARA_ERROR_SUCCESS on success, otherwise a yara error.
*/
_Success_(return == VMMYARA_ERROR_SUCCESS)
VMMYARA_ERROR VmmYara_RulesDestroy(_In_ PVMMYARA_RULES hVmmYaraRules) {
    VmmYara_Initialize();
    if(!g_VmmYaraInitialized) { return VMMYARA_ERROR_INVALID_FILE; }
    return gpfn_VmmYara_RulesDestroy(hVmmYaraRules);
}

/*
* Scan a memory buffer for matches against the specified rule set.
* Upon a match the callback function will be called with the match information.
* -- hVmmYaraRules = the handle to the rule set to scan against.
* -- pbBuffer = the memory buffer to scan.
* -- cbBuffer = the size of the memory buffer to scan.
* -- flags = flags according to yr_rules_scan_mem() to use.
* -- pfnCallback = the callback function to call upon a match.
* -- pvContext = context to pass to the callback function.
* -- timeout = timeout in seconds according to yr_rules_scan_mem().
* -- return = VMMYARA_ERROR_SUCCESS on success, otherwise a yara error.
*/
_Success_(return == VMMYARA_ERROR_SUCCESS)
VMMYARA_ERROR VmmYara_ScanMemory(
    _In_ PVMMYARA_RULES hVmmYaraRules,
    _In_reads_bytes_(cbBuffer) PBYTE pbBuffer,
    _In_ SIZE_T cbBuffer,
    _In_ int flags,
    _In_ VMMYARA_SCAN_MEMORY_CALLBACK pfnCallback,
    _In_ PVOID pvContext,
    _In_ int timeout
) {
    VmmYara_Initialize();
    if(!g_VmmYaraInitialized) { return VMMYARA_ERROR_INVALID_FILE; }
    return gpfn_VmmYara_ScanMemory(hVmmYaraRules, pbBuffer, cbBuffer, flags, pfnCallback, pvContext, timeout);
}
