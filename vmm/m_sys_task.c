// m_sys_task.c : implementation related to the sys/tasks built-in module.
//
// The '/sys/tasks' module is responsible for displaying information about
// Windows scheduled tasks. The information is gathered in a somwhat robust
// way from the registry.
// 
// The scheduled tasks module is supported on Windows 8.0 and above.
//
// (c) Ulf Frisk, 2021
// Author: Ulf Frisk, pcileech@frizk.net
//
#include "vmm.h"
#include "vmmwinreg.h"
#include "util.h"
#include "fc.h"
#include "pluginmanager.h"

#define MSYSTASK_LINELENGTH      256ULL
#define MSYSTASK_LINEHEADER      L"   # Task GUID                              Task Name                                                                        Time (Most Recent)      User         Command Line :: Parameters"

#define TASKREGROOT             L"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\"
#define TASKREGROOT_LOCALHIVE   L"ROOT\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\"

#define VMM_MAP_TASKENTRY_TP_DIRECTORY      0x00
#define VMM_MAP_TASKENTRY_TP_TASK           0x01
#define VMM_MAP_TASKENTRY_TP_BOOT           0x02
#define VMM_MAP_TASKENTRY_TP_LOGON          0x04
#define VMM_MAP_TASKENTRY_TP_MAINTENANCE    0x08
#define VMM_MAP_TASKENTRY_TP_PLAIN          0x10

typedef struct tdVMM_MAP_TASKENTRY {
    DWORD tp;
    QWORD ftRegLastWrite;
    LPWSTR wszName;
    LPWSTR wszPath;
    QWORD qwHashParent;          // parent key hash (calculated on file system compatible hash)
    QWORD qwHashThis;            // this key hash (calculated on file system compatible hash)
    QWORD qwHashName;            // name dword hash (calculated on file system compatible hash)
    // valid scheduled task info below / no directory info:
    QWORD qwHashGUID;
    QWORD ftCreate;
    QWORD ftLastRun;
    QWORD ftLastCompleted;
    LPWSTR wszGUID;
    LPWSTR wszActionUser;
    LPWSTR wszActionCommand;
    LPWSTR wszActionParameters;
} VMM_MAP_TASKENTRY, *PVMM_MAP_TASKENTRY;

typedef struct tdVMMOB_MAP_TASK {
    OB ObHdr;
    PQWORD pqwByHashName;       // ptr to array of cMap items
    PQWORD pqwByHashGuid;       // ptr to array of cTask items
    PQWORD pqwByTaskName;       // ptr to array of cTask items
    DWORD cTask;
    DWORD _Reserved;
    LPWSTR wszMultiText;
    DWORD cbMultiText;
    DWORD cMap;                 // # map entries.
    VMM_MAP_TASKENTRY pMap[];   // map entries.
} VMMOB_MAP_TASK, *PVMMOB_MAP_TASK;

typedef struct tdVMM_TASK_SETUP_CONTEXT {
    POB_REGISTRY_HIVE pHive;
    POB_MAP pmAll;      // by path hash
    POB_MAP pmDir;      // by path hash
    POB_MAP pmTask;     // by guid hash
    POB_STRMAP psm;
} VMM_TASK_SETUP_CONTEXT, *PVMM_TASK_SETUP_CONTEXT;



//-----------------------------------------------------------------------------
// SCHEDULED TASKS - INFO GATHERING LAYER BELOW:
// Layer will create a 'map' structure.
//-----------------------------------------------------------------------------

BOOL VmmSysTask_Util_VerifyGUID(_In_reads_opt_(39) LPWSTR wszGUID)
{
    DWORD i;
    WCHAR ch;
    if(!wszGUID || wszGUID[0] != '{' || wszGUID[37] != '}' || wszGUID[38] != 0) { return FALSE; }
    for(i = 1; i < 37; i++) {
        ch = wszGUID[i];
        if((ch >= '0' && ch <= '9') || (ch >= 'A' && ch <= 'F') || (ch >= 'a' && ch <= 'f') || (ch == '-')) { continue; }
        return FALSE;
    }
    return TRUE;
}

QWORD VmmSysTask_Util_HashGUID(_In_reads_opt_(39) LPWSTR wszGUID)
{
    if(!wszGUID || !VmmSysTask_Util_VerifyGUID(wszGUID)) { return 0; }
    return Util_HashNameW_Registry(wszGUID, 0) + *(PQWORD)(wszGUID + 1);
}

/*
* Populate a task with information such as action and additional time stamps.
* The data is retrieved from the task 'TackCache\Tasks\{GUID}' key values.
*/
VOID VmmSysTask_Initialize_AddInfo(_In_ PVMM_TASK_SETUP_CONTEXT ctx, _In_ POB_REGISTRY_KEY pKey, _In_ PVMM_MAP_TASKENTRY pTask)
{
    DWORD dw, dwVer, cb, o;
    BYTE pb[0x800];
    WCHAR wsz[MAX_PATH + 1];
    // time stamps from 'DynamicInfo' value:
    ZeroMemory(pb, 0x24);
    if(VmmWinReg_ValueQuery5(ctx->pHive, pKey, L"DynamicInfo", NULL, pb, sizeof(pb), NULL)) {
        if(pb[0x0b] == 0x01) { pTask->ftCreate = *(PQWORD)(pb + 0x04); }
        if(pb[0x13] == 0x01) { pTask->ftLastRun = *(PQWORD)(pb + 0x0c); }
        if(pb[0x23] == 0x01) { pTask->ftLastCompleted = *(PQWORD)(pb + 0x1c); }
    }
    // user, command, parameters from 'Actions' value:
    if(VmmWinReg_ValueQuery5(ctx->pHive, pKey, L"Actions", NULL, pb, sizeof(pb), &cb)) {
        dwVer = *(PWORD)pb;
        if(!cb || (cb < 0x1c) || !dwVer || dwVer > 3) { return; }
        // [user]
        if(dwVer == 1) {
            // v1 does not contain 'user' so skip forward
            o = 8;
        } else {
            dw = *(PDWORD)(pb + 2); o = 6;
            if(!dw || (dw > MAX_PATH) || (dw & 1)) { return; }
            memcpy(wsz, pb + o, dw); o += dw + 6;
            wsz[dw >> 1] = 0;
            ObStrMap_Push(ctx->psm, wsz, &pTask->wszActionUser, NULL);
        }
        // [command]
        dw = *(PDWORD)(pb + o); o += 4;
        if((dw < MAX_PATH) && !(dw & 1)) {
            memcpy(wsz, pb + o, dw); o += dw;
            wsz[dw >> 1] = 0;
            ObStrMap_Push(ctx->psm, wsz, &pTask->wszActionCommand, NULL);
        } else {
            ObStrMap_Push(ctx->psm, L"Custom Handler", &pTask->wszActionCommand, NULL);
            o += 16 - 4;
        }
        // [parameters]
        dw = *(PDWORD)(pb + o); o += 4;
        if((o >= cb) || !dw || (dw > MAX_PATH) || (dw & 1) || (dw > cb - o)) { return; }
        memcpy(wsz, pb + o, dw);
        wsz[dw >> 1] = 0;
        ObStrMap_Push(ctx->psm, wsz, &pTask->wszActionParameters, NULL);
    }
}

VOID VmmSysTask_Initialize_AddTask_FullPath(_In_ PVMM_TASK_SETUP_CONTEXT ctx, _In_ PVMM_MAP_TASKENTRY pe, _Out_writes_(MAX_PATH) LPWSTR wszPath)
{
    PVMM_MAP_TASKENTRY pTaskParent;
    wszPath[0] = 0;
    if((pTaskParent = ObMap_GetByKey(ctx->pmAll, pe->qwHashParent))) {
        wcsncat_s(wszPath, MAX_PATH, pTaskParent->wszPath, _TRUNCATE);
    }
    wcsncat_s(wszPath, MAX_PATH, L"\\", _TRUNCATE);
    wcsncat_s(wszPath, MAX_PATH, pe->wszName, _TRUNCATE);
}

/*
* Create or retrieve a single task in the initialization phase.
*/
PVMM_MAP_TASKENTRY VmmSysTask_Initialize_AddTask(
    _In_ PVMM_TASK_SETUP_CONTEXT ctx,
    _In_ QWORD ftRegLastWrite,
    _In_ LPWSTR wszName,
    _In_opt_ LPWSTR wszGUID,
    _In_opt_ PVMM_MAP_TASKENTRY pParentTask
) {
    DWORD dwHashName;
    QWORD qwHashGUID, qwHashThis;
    PVMM_MAP_TASKENTRY pTask = NULL;
    WCHAR wszPath[MAX_PATH];
    // 1: find existing tasks
    if((qwHashGUID = VmmSysTask_Util_HashGUID(wszGUID))) {
        pTask = ObMap_GetByKey(ctx->pmTask, qwHashGUID);
    }
    if(!pTask) {
        qwHashThis = pParentTask ? pParentTask->qwHashThis : 0;
        dwHashName = Util_HashNameW_Registry(wszName, 0);
        qwHashThis = dwHashName + ((qwHashThis >> 13) | (qwHashThis << 51));
        pTask = ObMap_GetByKey(ctx->pmAll, qwHashThis);
    }
    if(pTask) {
        if(pTask->ftRegLastWrite < ftRegLastWrite) {
            pTask->ftRegLastWrite = ftRegLastWrite;
        }
        return pTask;
    }
    // 2: task not found - allocate new
    pTask = LocalAlloc(LMEM_ZEROINIT, sizeof(VMM_MAP_TASKENTRY));
    if(!pTask) { return NULL; }
    pTask->ftRegLastWrite = ftRegLastWrite;
    pTask->qwHashParent = pParentTask ? pParentTask->qwHashThis : 0;
    pTask->qwHashThis = qwHashThis;
    pTask->qwHashName = dwHashName;
    ObStrMap_Push(ctx->psm, wszName, &pTask->wszName, NULL);
    ObStrMap_Push(ctx->psm, (qwHashGUID ? wszGUID : NULL), &pTask->wszGUID, NULL);
    VmmSysTask_Initialize_AddTask_FullPath(ctx, pTask, wszPath);
    ObStrMap_Push(ctx->psm, wszPath, &pTask->wszPath, NULL);
    ObMap_Push(ctx->pmAll, qwHashThis, pTask);
    if(qwHashGUID) {
        pTask->qwHashGUID = qwHashGUID;
        pTask->tp = VMM_MAP_TASKENTRY_TP_TASK;
        ObMap_Push(ctx->pmTask, qwHashGUID, pTask);
    } else {
        pTask->tp = VMM_MAP_TASKENTRY_TP_DIRECTORY;
        ObMap_Push(ctx->pmDir, qwHashThis, pTask);
    }
    return pTask;
}

VOID VmmSysTask_Initialize_Tree(_In_ PVMM_TASK_SETUP_CONTEXT ctx, _In_ POB_REGISTRY_KEY pKey, _In_ BOOL fTopLevel, _In_opt_ PVMM_MAP_TASKENTRY pParentTask)
{
    WCHAR wszGUID[40] = { 0 };
    DWORD dwKeyValueTp;
    PVMM_MAP_TASKENTRY pTask = NULL;
    VMM_REGISTRY_KEY_INFO KeyInfo = { 0 };
    POB_REGISTRY_KEY pObSubKey;
    POB_MAP pmObKeyList = NULL;
    // 1: fetch current task entry/directory.
    if(!fTopLevel) {
        VmmWinReg_KeyInfo(ctx->pHive, pKey, &KeyInfo);
        VmmWinReg_ValueQuery5(ctx->pHive, pKey, L"Id", &dwKeyValueTp, (PBYTE)wszGUID, sizeof(wszGUID) - 2, NULL);
        pTask = VmmSysTask_Initialize_AddTask(ctx, KeyInfo.ftLastWrite, KeyInfo.wszName, wszGUID, pParentTask);
        if(!pTask) { return; }
    }
    // 2: iterate over sub-directories
    if((pmObKeyList = VmmWinReg_KeyList(ctx->pHive, pKey))) {
        while((pObSubKey = ObMap_Pop(pmObKeyList))) {
            VmmSysTask_Initialize_Tree(ctx, pObSubKey, FALSE, pTask);
            Ob_DECREF(pObSubKey);
        }
        Ob_DECREF_NULL(&pmObKeyList);
    }
}

/*
* Add new task by path - create dir entries if needed. This should ideally
* never be called since all tasks should be indexed in 'TaskCache\Tree' -
* but if data have been corrupted this adds to robustness by having a 2nd
* way to retrieve data.
*/
PVMM_MAP_TASKENTRY VmmSysTask_Initialize_GetTaskByPath(_In_ PVMM_TASK_SETUP_CONTEXT ctx, _In_ LPWSTR wszPath, _In_opt_ PVMM_REGISTRY_KEY_INFO pKeyInfo)
{
    QWORD qwHash;
    LPWSTR wszNewName;
    WCHAR wszNewPath[MAX_PATH];
    PVMM_MAP_TASKENTRY pTask, pTaskParent = NULL;
    if(!(qwHash = Util_HashPathW_Registry(wszPath))) { return NULL; }
    if((pTask = ObMap_GetByKey(ctx->pmAll, qwHash))) { return pTask; }
    // get level -1
    if(!(wszNewName = Util_PathFileSplitW(wszPath, wszNewPath))) { return NULL; }
    if((wszNewPath[0] != 0) && (wszNewPath[1] != 0)) {
        pTaskParent = VmmSysTask_Initialize_GetTaskByPath(ctx, wszNewPath, NULL);
        if(!pTaskParent) { return NULL; }
    }
    return VmmSysTask_Initialize_AddTask(ctx, (pKeyInfo ? pKeyInfo->ftLastWrite : 0), wszNewName, (pKeyInfo ? pKeyInfo->wszName : NULL), pTaskParent);
}

VOID VmmSysTask_Initialize_AddInfoOrType(_In_ PVMM_TASK_SETUP_CONTEXT ctx, _In_ LPWSTR wszKeyPath, _In_ DWORD dwTypeOpt)
{
    PVMM_MAP_TASKENTRY pTask;
    POB_MAP pmObKeyList = NULL;
    POB_REGISTRY_KEY pObSubKey, pObKey = NULL;
    VMM_REGISTRY_KEY_INFO KeyInfo = { 0 };
    WCHAR wszPath[MAX_PATH];
    if((pObKey = VmmWinReg_KeyGetByPath(ctx->pHive, wszKeyPath)) && (pmObKeyList = VmmWinReg_KeyList(ctx->pHive, pObKey))) {
        while((pObSubKey = ObMap_Pop(pmObKeyList))) {
            VmmWinReg_KeyInfo(ctx->pHive, pObSubKey, &KeyInfo);
            pTask = ObMap_GetByKey(ctx->pmTask, VmmSysTask_Util_HashGUID(KeyInfo.wszName));
            if(!pTask && !dwTypeOpt) {
                // code path should only be triggered on corrupt (due to paging or intentionally manipulated) task cache
                ZeroMemory(wszPath, MAX_PATH * sizeof(WCHAR));
                if(VmmWinReg_ValueQuery5(ctx->pHive, pObSubKey, L"Path", NULL, (PBYTE)wszPath, sizeof(wszPath) - 2, NULL)) {
                    pTask = VmmSysTask_Initialize_GetTaskByPath(ctx, wszPath, &KeyInfo);
                }
            }
            if(pTask) {
                if(dwTypeOpt) {
                    pTask->tp = pTask->tp | dwTypeOpt;
                } else {
                    VmmSysTask_Initialize_AddInfo(ctx, pObSubKey, pTask);
                }
            }
            Ob_DECREF(pObSubKey);
        }
    }
    Ob_DECREF_NULL(&pmObKeyList);
    Ob_DECREF(pObKey);
}

int VmmSysTask_Initialize_DoWork_qsort(PVMM_MAP_TASKENTRY p1, PVMM_MAP_TASKENTRY p2)
{
    return wcscmp(p1->wszPath, p2->wszPath);
}

VOID VmmSysTask_CallbackCleanup_ObObjectMap(PVMMOB_MAP_TASK pOb)
{
    LocalFree(pOb->wszMultiText);
}

VOID VmmSysTask_Initialize_DoWork(_In_ PVMMDLL_PLUGIN_CONTEXT ctxP)
{
    BOOL fResult = FALSE;
    QWORD cAll, cTask, cbData, cbo, i, iTask;
    PVMM_MAP_TASKENTRY pTask;
    PVMMOB_MAP_TASK pObMap = NULL;
    POB_REGISTRY_KEY pObKey = NULL;
    VMM_TASK_SETUP_CONTEXT ctxInit = { 0 };
    // 1: INIT:
    if(!(ctxInit.pmAll = ObMap_New(OB_MAP_FLAGS_OBJECT_LOCALFREE))) { goto fail; }
    if(!(ctxInit.pmDir = ObMap_New(OB_MAP_FLAGS_OBJECT_VOID))) { goto fail; }
    if(!(ctxInit.pmTask = ObMap_New(OB_MAP_FLAGS_OBJECT_VOID))) { goto fail; }
    if(!(ctxInit.psm = ObStrMap_New(OB_STRMAP_FLAGS_CASE_INSENSITIVE | OB_STRMAP_FLAGS_STR_ASSIGN_TEMPORARY))) { goto fail; }
    // 2: ITERATE OVER 'TaskCache\Tree':
    if(!VmmWinReg_KeyHiveGetByFullPath(TASKREGROOT L"Tree", &ctxInit.pHive, &pObKey)) { goto fail; }
    VmmSysTask_Initialize_Tree(&ctxInit, pObKey, TRUE, NULL);
    // 3: ADD TASK ADDITIONAL INFO:
    VmmSysTask_Initialize_AddInfoOrType(&ctxInit, TASKREGROOT_LOCALHIVE L"Tasks", 0);
    // 4: ADD TASK TYPE:
    VmmSysTask_Initialize_AddInfoOrType(&ctxInit, TASKREGROOT_LOCALHIVE L"Boot", VMM_MAP_TASKENTRY_TP_BOOT);
    VmmSysTask_Initialize_AddInfoOrType(&ctxInit, TASKREGROOT_LOCALHIVE L"Logon", VMM_MAP_TASKENTRY_TP_LOGON);
    VmmSysTask_Initialize_AddInfoOrType(&ctxInit, TASKREGROOT_LOCALHIVE L"Maintenance", VMM_MAP_TASKENTRY_TP_MAINTENANCE);
    VmmSysTask_Initialize_AddInfoOrType(&ctxInit, TASKREGROOT_LOCALHIVE L"Plain", VMM_MAP_TASKENTRY_TP_PLAIN);
    // 5: CREATE MAP / FINALIZE:
    cAll = ObMap_Size(ctxInit.pmAll);
    cTask = ObMap_Size(ctxInit.pmTask);
    if(cAll > 0xffff) { goto fail; }
    cbData = sizeof(VMMOB_MAP_TASK) + cAll * sizeof(VMM_MAP_TASKENTRY) + (cAll + cTask + cTask) * sizeof(QWORD);
    pObMap = Ob_Alloc(OB_TAG_MAP_TASK, LMEM_ZEROINIT, cbData, VmmSysTask_CallbackCleanup_ObObjectMap, NULL);
    if(!pObMap) { goto fail; }
    cbo = sizeof(VMMOB_MAP_TASK) + cAll * sizeof(VMM_MAP_TASKENTRY);
    pObMap->pqwByHashName = (PQWORD)((PBYTE)pObMap + cbo); cbo += cAll * sizeof(QWORD);
    pObMap->pqwByHashGuid = (PQWORD)((PBYTE)pObMap + cbo); cbo += cTask * sizeof(QWORD);
    pObMap->pqwByTaskName = (PQWORD)((PBYTE)pObMap + cbo); cbo += cTask * sizeof(QWORD);
    pObMap->cTask = (DWORD)cTask;
    pObMap->cMap = (DWORD)cAll;
    for(i = 0; i < pObMap->cMap; i++) {     // FIXUPS
        if(!(pTask = ObMap_GetByIndex(ctxInit.pmAll, (DWORD)i))) { goto fail; }
        if(!pTask->wszActionUser)       { ObStrMap_Push(ctxInit.psm, L"---", &pTask->wszActionUser, NULL); }
        if(!pTask->wszActionCommand)    { ObStrMap_Push(ctxInit.psm, L"---", &pTask->wszActionCommand, NULL); }
        if(!pTask->wszActionParameters) { ObStrMap_Push(ctxInit.psm, L"---", &pTask->wszActionParameters, NULL); }
    }
    ObStrMap_Finalize_DECREF_NULL(&ctxInit.psm, &pObMap->wszMultiText, &pObMap->cbMultiText);
    for(i = 0; i < pObMap->cMap; i++) {     // COPY TASKENTRY TO MAP
        if(!(pTask = ObMap_GetByIndex(ctxInit.pmAll, (DWORD)i))) { goto fail; }
        memcpy(pObMap->pMap + i, pTask, sizeof(VMM_MAP_TASKENTRY));
    }
    qsort(pObMap->pMap, cAll, sizeof(VMM_MAP_TASKENTRY), (_CoreCrtNonSecureSearchSortCompareFunction)VmmSysTask_Initialize_DoWork_qsort);
    // 6: CREATE / SORT HASH LOOKUP TABLES
    for(i = 0, iTask = 0; i < cAll; i++) {
        pTask = pObMap->pMap + i;
        pObMap->pqwByHashName[i] = (pTask->qwHashName << 16) | i;
        if(pTask->wszGUID[0] && (iTask < cTask)) {
            pObMap->pqwByHashGuid[iTask] = (pTask->qwHashGUID << 16) | i;
            pObMap->pqwByTaskName[iTask] = i;
            iTask++;
        }
    }
    qsort(pObMap->pqwByHashName, cAll, sizeof(QWORD), Util_qsort_QWORD);
    qsort(pObMap->pqwByHashGuid, cTask, sizeof(QWORD), Util_qsort_QWORD);
    // 7: FINISH
    ObContainer_SetOb((POB_CONTAINER)ctxP->ctxM, pObMap);
    fResult = TRUE;
fail:
    Ob_DECREF(pObMap);
    Ob_DECREF(pObKey);
    if(!fResult && (pObMap = Ob_Alloc(OB_TAG_MAP_TASK, LMEM_ZEROINIT, sizeof(VMMOB_MAP_TASK), NULL, NULL))) {
        ObContainer_SetOb((POB_CONTAINER)ctxP->ctxM, pObMap);
        Ob_DECREF(pObMap);
    }
    Ob_DECREF(ctxInit.pHive);
    Ob_DECREF(ctxInit.pmAll);
    Ob_DECREF(ctxInit.pmDir);
    Ob_DECREF(ctxInit.pmTask);
    Ob_DECREF(ctxInit.psm);
}

/*
* Fetch the 'TaskSchedulerMap' object.
* CALLER DECREF: return
* -- ctxP
* -- return
*/
PVMMOB_MAP_TASK VmmSysTask_GetTaskMap(_In_ PVMMDLL_PLUGIN_CONTEXT ctxP)
{
    PVMMOB_MAP_TASK pOb;
    if((pOb = ObContainer_GetOb((POB_CONTAINER)ctxP->ctxM))) { return pOb; }
    EnterCriticalSection(&ctxVmm->LockPlugin);
    VmmSysTask_Initialize_DoWork(ctxP);
    LeaveCriticalSection(&ctxVmm->LockPlugin);
    return ObContainer_GetOb((POB_CONTAINER)ctxP->ctxM);
}

int VmmSysTask_GetTaskByHash_qfind_CmpFindTableQWORD(_In_ QWORD qwKey, _In_ PQWORD pqwEntry)
{
    QWORD qwEntry = *pqwEntry >> 16;
    return (qwEntry > qwKey) ? -1 : ((qwEntry == qwKey) ? 0 : 1);
}

PVMM_MAP_TASKENTRY VmmSysTask_GetTaskByHash(_In_ PVMMOB_MAP_TASK pObTaskMap, _In_ PQWORD pqwHashTable, _In_ DWORD cHashTable, _In_ QWORD qwHash)
{
    PQWORD pqwHash;
    if(!qwHash) { return NULL; }
    pqwHash = Util_qfind((PVOID)(qwHash & 0x0000ffff'ffffffff), cHashTable, pqwHashTable, sizeof(QWORD), (int(*)(PVOID, PVOID))VmmSysTask_GetTaskByHash_qfind_CmpFindTableQWORD);
    if(!pqwHash) { return NULL; }
    return pObTaskMap->pMap + (*pqwHash & 0xffff);
}



//-----------------------------------------------------------------------------
// SCHEDULED TASKS - PRESENTATION LAYER BELOW:
//-----------------------------------------------------------------------------

/*
* Generate the file 'taskinfo.txt' in each individual task:
*/
DWORD MSysTask_InfoFromEntry(_In_ PVMM_MAP_TASKENTRY pe, _Out_writes_(cbszu8) LPSTR szu8, _In_ DWORD cbszu8)
{
    CHAR szTimeRegWR[24], szTimeCreate[24], szTimeLastRun[24], szTimeCompleted[24];
    Util_FileTime2String(pe->ftRegLastWrite, szTimeRegWR);
    Util_FileTime2String(pe->ftCreate, szTimeCreate);
    Util_FileTime2String(pe->ftLastRun, szTimeLastRun);
    Util_FileTime2String(pe->ftLastCompleted, szTimeCompleted);
    return (DWORD)Util_snwprintf_u8(szu8, cbszu8,
        L"Name:       %s\n" \
        L"Path:       %s\n" \
        L"User:       %s\n" \
        L"Command:    %s\n" \
        L"Parameters: %s\n" \
        L"GUID:       %s\n" \
        L"RegLastWr:  %S\n" \
        L"Create:     %S\n" \
        L"LastRun:    %S\n" \
        L"Completed:  %S\n",
        pe->wszName,
        pe->wszPath,
        pe->wszActionUser,
        pe->wszActionCommand,
        pe->wszActionParameters,
        pe->wszGUID,
        szTimeRegWR,
        szTimeCreate,
        szTimeLastRun,
        szTimeCompleted
    );
}

/*
* Read a 'single entry' file - the 'taskinfo.txt' a registry sub-folder file.
*/
NTSTATUS MSysTask_ReadSingleEntry(_In_ PVMMDLL_PLUGIN_CONTEXT ctxP, _Out_writes_to_(cb, *pcbRead) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset, _In_ PVMM_MAP_TASKENTRY pTask, _In_ LPWSTR wszPath)
{
    DWORD cbInfoFile;
    WCHAR wsz[MAX_PATH];
    CHAR szu8InfoFile[0x1000];
    if(!_wcsicmp(L"taskinfo.txt", wszPath)) {
        cbInfoFile = MSysTask_InfoFromEntry(pTask, szu8InfoFile, sizeof(szu8InfoFile));
        return Util_VfsReadFile_FromPBYTE((PBYTE)szu8InfoFile, cbInfoFile, pb, cb, pcbRead, cbOffset);
    }
    if(!_wcsnicmp(L"registry", wszPath, 8)) {
        _snwprintf_s(wsz, MAX_PATH, _TRUNCATE, L"registry\\HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tasks\\%s\\%s", pTask->wszGUID, wszPath + (wszPath[8] ? 9 : 8));
        return PluginManager_Read(NULL, wsz, pb, cb, pcbRead, cbOffset);
    }
    return VMMDLL_STATUS_FILE_INVALID;
}

/*
* Generate a single line in the tasks.txt file.
*/
VOID MSysTask_ReadLine_CB(_In_ PVMMOB_MAP_TASK pObTaskMap, _In_ DWORD cbLineLength, _In_ DWORD ie, _In_ PVOID pv, _Out_writes_(cbLineLength + 1) LPSTR szu8)
{
    PVMM_MAP_TASKENTRY pe = pObTaskMap->pMap + pObTaskMap->pqwByTaskName[ie];
    CHAR szTime[24];
    QWORD ftMax = max(max(pe->ftCreate, pe->ftLastCompleted), max(pe->ftLastRun, pe->ftRegLastWrite));
    Util_FileTime2String(ftMax, szTime);
    Util_snwprintf_u8ln(szu8, cbLineLength,
        L"%04x %38s %-80.80s %S %-12.12s %s :: %s",
        ie,
        pe->wszGUID,
        pe->wszPath,
        szTime,
        pe->wszActionUser,
        pe->wszActionCommand,
        pe->wszActionParameters
    );
}

NTSTATUS MSysTask_Read(_In_ PVMMDLL_PLUGIN_CONTEXT ctxP, _Out_writes_to_(cb, *pcbRead) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset)
{
    NTSTATUS nt = VMMDLL_STATUS_FILE_INVALID;
    PVMMOB_MAP_TASK pObTaskMap = NULL;
    WCHAR wsz[MAX_PATH];
    LPWSTR wszSubPath;
    QWORD qwHash;
    PVMM_MAP_TASKENTRY pe;
    if(!(pObTaskMap = VmmSysTask_GetTaskMap(ctxP))) { goto finish; }
    if(!_wcsicmp(ctxP->wszPath, L"tasks.txt")) {
        nt = Util_VfsLineFixed_Read(
            MSysTask_ReadLine_CB, pObTaskMap, MSYSTASK_LINELENGTH, MSYSTASK_LINEHEADER,
            pObTaskMap->pMap, pObTaskMap->cTask, sizeof(VMM_MAP_TASKENTRY),
            pb, cb, pcbRead, cbOffset
        );
        goto finish;
    }
    if(!_wcsnicmp(L"by-guid\\", ctxP->wszPath, 8) || !_wcsnicmp(L"by-name\\", ctxP->wszPath, 8)) {
        wszSubPath = Util_PathSplit2_ExWCHAR(ctxP->wszPath + 8, wsz, MAX_PATH);
        if(!_wcsnicmp(L"by-guid\\", ctxP->wszPath, 8)) {
            qwHash = VmmSysTask_Util_HashGUID(wsz);
            pe = VmmSysTask_GetTaskByHash(pObTaskMap, pObTaskMap->pqwByHashGuid, pObTaskMap->cTask, qwHash);
        } else {
            qwHash = Util_HashNameW_Registry(wsz, 0);
            pe = VmmSysTask_GetTaskByHash(pObTaskMap, pObTaskMap->pqwByHashName, pObTaskMap->cMap, qwHash);
        }
        nt = MSysTask_ReadSingleEntry(ctxP,pb, cb, pcbRead, cbOffset, pe, wszSubPath);
        goto finish;
    }
finish:
    Ob_DECREF(pObTaskMap);
    return nt;
}

/*
* List a single entry directory - i.e. the directory as such or the registry sub-directory.
*/
VOID MSysTask_ListSingleEntry(_In_ PVMMDLL_PLUGIN_CONTEXT ctxP, _Inout_ PHANDLE pFileList, _In_ PVMM_MAP_TASKENTRY pTask, _In_ LPWSTR wszPath)
{
    DWORD cbInfoFile;
    WCHAR wsz[MAX_PATH];
    CHAR szu8InfoFile[0x1000];
    if(!pTask) { return; }
    if(!wszPath[0]) {
        cbInfoFile = MSysTask_InfoFromEntry(pTask, szu8InfoFile, sizeof(szu8InfoFile));
        VMMDLL_VfsList_AddFile(pFileList, L"taskinfo.txt", cbInfoFile, NULL);
        VMMDLL_VfsList_AddDirectory(pFileList, L"registry", NULL);
        return;
    }
    if(!_wcsnicmp(L"registry", wszPath, 8)) {
        _snwprintf_s(wsz, MAX_PATH, _TRUNCATE, L"registry\\HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tasks\\%s\\%s", pTask->wszGUID, wszPath + (wszPath[8] ? 9 : 8));
        PluginManager_List(NULL, wsz, pFileList);
        return;
    }
}

BOOL MSysTask_List(_In_ PVMMDLL_PLUGIN_CONTEXT ctxP, _Inout_ PHANDLE pFileList)
{
    QWORD i, qwHash;
    WCHAR wsz[MAX_PATH];
    LPWSTR wszSubPath;
    PVMM_MAP_TASKENTRY pe;
    PVMMOB_MAP_TASK pObTaskMap = NULL;
    if(!(pObTaskMap = VmmSysTask_GetTaskMap(ctxP))) { goto finish; }
    if(!ctxP->wszPath[0]) {
        VMMDLL_VfsList_AddDirectory(pFileList, L"by-guid", NULL);
        VMMDLL_VfsList_AddDirectory(pFileList, L"by-name", NULL);
        VMMDLL_VfsList_AddFile(pFileList, L"tasks.txt", UTIL_VFSLINEFIXED_LINECOUNT(pObTaskMap->cTask) * MSYSTASK_LINELENGTH, NULL);
        goto finish;
    }
    if(!_wcsicmp(L"by-guid", ctxP->wszPath)) {
        for(i = 0; i < pObTaskMap->cTask; i++) {
            pe = pObTaskMap->pMap + (pObTaskMap->pqwByHashGuid[i] & 0xffff);
            VMMDLL_VfsList_AddDirectory(pFileList, pe->wszGUID, NULL);
        }
        goto finish;
    }
    if(!_wcsicmp(L"by-name", ctxP->wszPath)) {
        for(i = 0; i < pObTaskMap->cTask; i++) {
            pe = pObTaskMap->pMap + pObTaskMap->pqwByTaskName[i];
            VMMDLL_VfsList_AddDirectory(pFileList, pe->wszName, NULL);
        }
        goto finish;
    }
    if(!_wcsnicmp(L"by-guid\\", ctxP->wszPath, 8) || !_wcsnicmp(L"by-name\\", ctxP->wszPath, 8)) {
        wszSubPath = Util_PathSplit2_ExWCHAR(ctxP->wszPath + 8, wsz, MAX_PATH);
        if(!_wcsnicmp(L"by-guid\\", ctxP->wszPath, 8)) {
            qwHash = VmmSysTask_Util_HashGUID(wsz);
            pe = VmmSysTask_GetTaskByHash(pObTaskMap, pObTaskMap->pqwByHashGuid, pObTaskMap->cTask, qwHash);
        } else {
            qwHash = Util_HashNameW_Registry(wsz, 0);
            pe = VmmSysTask_GetTaskByHash(pObTaskMap, pObTaskMap->pqwByHashName, pObTaskMap->cMap, qwHash);
        }
        MSysTask_ListSingleEntry(ctxP, pFileList, pe, wszSubPath);
        goto finish;
    }
finish:
    Ob_DECREF(pObTaskMap);
    return TRUE;
}

/*
* Forensic Timeline: Retrieve ObTaskMap into ctxfc.
*/
PVOID MSysTask_FcInitialize(_In_ PVMMDLL_PLUGIN_CONTEXT ctxP)
{
    return VmmSysTask_GetTaskMap(ctxP);
}

/*
* Forensic Timeline: Populate timeline information:
*/
VOID MSysTask_FcTimeline(
    _In_opt_ PVOID ctxfc,
    _In_ HANDLE hTimeline,
    _In_ VOID(*pfnAddEntry)(_In_ HANDLE hTimeline, _In_ QWORD ft, _In_ DWORD dwAction, _In_ DWORD dwPID, _In_ DWORD dwData32, _In_ QWORD dwData64, _In_ LPWSTR wszText),
    _In_ VOID(*pfnEntryAddBySql)(_In_ HANDLE hTimeline, _In_ DWORD cEntrySql, _In_ LPSTR *pszEntrySql)
) {
    PVMMOB_MAP_TASK pObTaskMap = ctxfc;
    PVMM_MAP_TASKENTRY pe;
    WCHAR wsz[MAX_PATH];
    DWORD i;
    if(pObTaskMap) {
        for(i = 0; i < pObTaskMap->cTask; i++) {
            pe = pObTaskMap->pMap + pObTaskMap->pqwByTaskName[i];
            _snwprintf_s(wsz, MAX_PATH, _TRUNCATE, L"%s - [%s :: %s] (%s)", pe->wszName, pe->wszActionCommand, pe->wszActionParameters, pe->wszActionUser);
            if(pe->ftRegLastWrite) { pfnAddEntry(hTimeline, pe->ftRegLastWrite, FC_TIMELINE_ACTION_MODIFY, 0, 0, 0, wsz); }
            if(pe->ftCreate) { pfnAddEntry(hTimeline, pe->ftCreate, FC_TIMELINE_ACTION_CREATE, 0, 0, 0, wsz); }
            if(pe->ftLastRun) { pfnAddEntry(hTimeline, pe->ftLastRun, FC_TIMELINE_ACTION_READ, 0, 0, 0, wsz); }
            if(pe->ftLastCompleted) { pfnAddEntry(hTimeline, pe->ftLastCompleted, FC_TIMELINE_ACTION_DELETE, 0, 0, 0, wsz); }
        }
    }
}

/*
* Forensic JSON log:
*/
VOID MSysTask_FcLogJSON(_In_ PVMMDLL_PLUGIN_CONTEXT ctxP, _In_ VOID(*pfnLogJSON)(_In_ PVMMDLL_PLUGIN_FORENSIC_JSONDATA pData))
{
    PVMMDLL_PLUGIN_FORENSIC_JSONDATA pd;
    PVMMOB_MAP_TASK pObTaskMap = NULL;
    PVMM_MAP_TASKENTRY pe;
    DWORD i;
    CHAR szj[MAX_PATH];
    if(ctxP->pProcess || !(pd = LocalAlloc(LMEM_ZEROINIT, sizeof(VMMDLL_PLUGIN_FORENSIC_JSONDATA)))) { return; }
    pd->dwVersion = VMMDLL_PLUGIN_FORENSIC_JSONDATA_VERSION;
    pd->szjType = "shtask";
    if((pObTaskMap = VmmSysTask_GetTaskMap(ctxP))) {
        for(i = 0; i < pObTaskMap->cMap; i++) {
            pe = pObTaskMap->pMap + i;
            pd->i = i;
            Util_snwprintf_u8j(szj, _countof(szj), L"user:[%s] cmd:[%s] param:[%s]", pe->wszActionUser, pe->wszActionCommand, pe->wszActionParameters);
            pd->wsz[0] = pe->wszPath;
            pd->szj[1] = szj;
            pfnLogJSON(pd);
        }
    }
    Ob_DECREF(pObTaskMap);
    LocalFree(pd);
}

/*
* Forensic Timeline: Free ObTaskMap from FcInitialize().
*/
VOID MSysTask_FcFinalize(_In_opt_ PVOID ctxfc)
{
    Ob_DECREF(ctxfc);
}

VOID MSysTask_Notify(_In_ PVMMDLL_PLUGIN_CONTEXT ctxP, _In_ DWORD fEvent, _In_opt_ PVOID pvEvent, _In_opt_ DWORD cbEvent)
{
    if(fEvent == VMMDLL_PLUGIN_NOTIFY_REFRESH_SLOW) {
        ObContainer_SetOb((POB_CONTAINER)ctxP->ctxM, NULL);
    }
}

VOID MSysTask_Close(_In_ PVMMDLL_PLUGIN_CONTEXT ctxP)
{
    Ob_DECREF(ctxP->ctxM);
}

VOID M_SysTask_Initialize(_Inout_ PVMMDLL_PLUGIN_REGINFO pRI)
{
    if((pRI->magic != VMMDLL_PLUGIN_REGINFO_MAGIC) || (pRI->wVersion != VMMDLL_PLUGIN_REGINFO_VERSION)) { return; }
    if((pRI->tpSystem != VMM_SYSTEM_WINDOWS_X64) && (pRI->tpSystem != VMM_SYSTEM_WINDOWS_X86)) { return; }
    if(pRI->sysinfo.dwVersionBuild < 9200) { return; }                      // WIN8+ supported
    wcscpy_s(pRI->reg_info.wszPathName, 128, L"\\sys\\tasks");              // module name
    pRI->reg_info.fRootModule = TRUE;                                       // module shows in root directory
    pRI->reg_info.ctxM = (PVMMDLL_PLUGIN_INTERNAL_CONTEXT)ObContainer_New();
    // functions supported:
    pRI->reg_fn.pfnList = MSysTask_List;
    pRI->reg_fn.pfnRead = MSysTask_Read;
    pRI->reg_fn.pfnNotify = MSysTask_Notify;
    pRI->reg_fn.pfnClose = MSysTask_Close;
    pRI->reg_fnfc.pfnLogJSON = MSysTask_FcLogJSON;
    // timelining support:
    pRI->reg_fnfc.pfnInitialize = MSysTask_FcInitialize;
    pRI->reg_fnfc.pfnTimeline = MSysTask_FcTimeline;
    pRI->reg_fnfc.pfnFinalize = MSysTask_FcFinalize;
    memcpy(pRI->reg_info.sTimelineNameShort, "ShTask", 6);
    strncpy_s(pRI->reg_info.szTimelineFileUTF8, 32, "timeline_task.txt", _TRUNCATE);
    pRI->pfnPluginManager_Register(pRI);
}
