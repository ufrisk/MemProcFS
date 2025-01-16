// vmmuserconfig.c : get/set options in a persistent user configuration.
// 
// The user configuration is stored depending on operating system as follows:
// - Windows: HKCU\Software\UlfFrisk\MemProcFS
// - Linux: ~/.memprocfs
//
// (c) Ulf Frisk, 2023-2025
// Author: Ulf Frisk, pcileech@frizk.net
//
#include "vmmuserconfig.h"

#ifdef _WIN32
/*
* Delete a key from the user configuration.
*/
VOID VmmUserConfig_Delete(_In_ LPCSTR szKey)
{
    HKEY hKey = 0;
    if(ERROR_SUCCESS == RegOpenKeyExA(HKEY_CURRENT_USER, "Software\\UlfFrisk\\MemProcFS", 0, KEY_ALL_ACCESS, &hKey)) {
        RegDeleteValueA(hKey, szKey);
        RegCloseKey(hKey);
    }
}

/*
* Retrieve a string value from the user configuration.
* -- szKey
* -- cbValue
* -- szValue
* -- return
*/
_Success_(return)
BOOL VmmUserConfig_GetString(_In_ LPCSTR szKey, _In_ DWORD cbValue, _Out_writes_opt_(cbValue) LPSTR szValue)
{
    return ERROR_SUCCESS == RegGetValueA(HKEY_CURRENT_USER, "Software\\UlfFrisk\\MemProcFS", szKey, RRF_RT_REG_SZ, NULL, szValue, &cbValue);
}

/*
* Set a string value in the user configuration.
* -- szKey
* -- szValue
* -- return
*/
_Success_(return)
BOOL VmmUserConfig_SetString(_In_ LPCSTR szKey, _In_ LPCSTR szValue)
{
    HKEY hKey = 0;
    BOOL fResult = FALSE;
    if(ERROR_SUCCESS != RegOpenKeyExA(HKEY_CURRENT_USER, "Software\\UlfFrisk\\MemProcFS", 0, KEY_ALL_ACCESS, &hKey)) {
        RegCreateKeyA(HKEY_CURRENT_USER, "Software\\UlfFrisk\\MemProcFS", &hKey);
        RegCloseKey(hKey);
    }
    if(ERROR_SUCCESS == RegOpenKeyExA(HKEY_CURRENT_USER, "Software\\UlfFrisk\\MemProcFS", 0, KEY_ALL_ACCESS, &hKey)) {
        fResult = (ERROR_SUCCESS == RegSetValueExA(hKey, szKey, 0, REG_SZ, (PBYTE)szValue, (DWORD)strlen(szValue)));
        RegCloseKey(hKey);
    }
    return fResult;
}
#endif /* _WIN32 */

#if defined(LINUX) || defined(MACOS)

#include <pwd.h>

char *get_user_config_file_path()
{
    struct passwd *pw;
    const char *homedir;
    char *path;
    FILE *file;
    if(!(pw = getpwuid(getuid()))) { return NULL; }
    if(!(homedir = pw->pw_dir)) { return NULL; }
    if(!(path = malloc(strlen(homedir) + strlen("/.memprocfs") + 1))) { return NULL; }
    sprintf(path, "%s/.memprocfs", homedir);
    return path;
}

FILE* get_user_config_file_read()
{
    FILE *file = NULL;
    char *path = get_user_config_file_path();
    if(path) {
        file = fopen(path, "r");
        free(path);
    }
    return file;
}

FILE *get_user_config_file_write()
{
    FILE *file = NULL;
    char *path = get_user_config_file_path();
    if(path) {
        file = fopen(path, "w");
        free(path);
    }
    return file;
}


/*
* Delete a key from the user configuration.
*/
VOID VmmUserConfig_Delete(_In_ LPCSTR szKey)
{
    VmmUserConfig_SetString(szKey, NULL);
}

/*
* Retrieve a string value from the user configuration.
* -- szKey
* -- cbValue
* -- szValue
* -- return
*/
_Success_(return)
BOOL VmmUserConfig_GetString(_In_ LPCSTR szKey, _In_ DWORD cbValue, _Out_writes_opt_(cbValue) LPSTR szValue)
{
    char key[256], val[256];
    FILE *file = get_user_config_file_read();
    if(file) {
        while(fscanf(file, "%255[^=]=%255[^\n]%*c", key, val) == 2) {
            if(0 == strcmp(key, szKey)) {
                if(szValue) {
                    strncpy(szValue, val, min(cbValue, sizeof(val)));
                }
                fclose(file);
                return TRUE;
            }
        }
        fclose(file);
    }
    return FALSE;
}

/*
* Check if the user key/value equals the stored one.
* -- szKey
* -- szValue
* -- return
*/
_Success_(return)
BOOL VmmUserConfig_EqualsString(_In_ LPCSTR szKey, _In_ LPCSTR szValue)
{
    char key[256], val[256];
    FILE *file = get_user_config_file_read();
    if(file) {
        while(fscanf(file, "%255[^=]=%255[^\n]%*c", key, val) == 2) {
            if((0 == strcmp(key, szKey)) && (0 == strcmp(val, szValue))) {
                fclose(file);
                return TRUE;
            }
        }
        fclose(file);
    }
    return FALSE;
}

/*
* Set a string value in the user configuration.
* -- szKey
* -- szValue
* -- return
*/
_Success_(return)
BOOL VmmUserConfig_SetString(_In_ LPCSTR szKey, _In_ LPCSTR szValue)
{
    int o = 0;
    BOOL f_result = FALSE;
    char key[256], val[256];
    char *buf1M = NULL;
    FILE *file_write = NULL;
    FILE *file_read = NULL;
    if(VmmUserConfig_EqualsString(szKey, szValue)) { return TRUE; }
    if(!(buf1M = malloc(0x00100000))) { goto fail; }
    if((file_read = get_user_config_file_read())) {
        while(fscanf(file_read, "%255[^=]=%255[^\n]%*c", key, val) == 2) {
            if(strcmp(key, szKey)) {
                o += snprintf(buf1M + o, 0x00100000 - o, "%s=%s\n", key, val);
            }
            if(o >= 0x00100000 - 0x1000) { goto fail; } // 1MB - 4kB
        }
        fclose(file_read); file_read = NULL;
    }
    if(szValue) {
        o += snprintf(buf1M + o, 0x00100000 - o, "%s=%s\n", szKey, szValue);
    }
    if(o && (file_write = get_user_config_file_write())) {
        fwrite(buf1M, 1, o, file_write);
        f_result = TRUE;
    }
fail:
    free(buf1M);
    if(file_read) { fclose(file_read); }
    if(file_write) { fclose(file_write); }
    return f_result;
}
#endif /* LINUX || MACOS */

/*
* Check if a key exists in the user configuration.
* -- szKey
* -- return
*/
BOOL VmmUserConfig_Exists(_In_ LPCSTR szKey)
{
    return VmmUserConfig_GetString(szKey, 0, NULL);
}

/*
* Retrieve a number value from the user configuration.
* -- szKey
* -- pdwValue
* -- return
*/
_Success_(return)
BOOL VmmUserConfig_GetNumber(_In_ LPCSTR szKey, _Out_opt_ PDWORD pdwValue)
{
    CHAR sz[32];
    if(VmmUserConfig_GetString(szKey, sizeof(sz), sz)) {
        if(pdwValue) {
            *pdwValue = strtoul(sz, NULL, 0);
        }
        return TRUE;
    }
    return FALSE;
}

/*
* Set a number value in the user configuration.
* -- szKey
* -- dwValue
* -- return
*/
_Success_(return)
BOOL VmmUserConfig_SetNumber(_In_ LPCSTR szKey, _In_ DWORD dwValue)
{
    CHAR sz[32] = { 0 };
    _snprintf_s(sz, 32, _TRUNCATE, "%i", dwValue);
    return VmmUserConfig_SetString(szKey, sz);
}
