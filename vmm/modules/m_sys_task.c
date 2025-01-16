// m_sys_task.c : implementation related to the sys/tasks built-in module.
//
// The '/sys/tasks' module is responsible for displaying information about
// Windows scheduled tasks. The information is gathered in a somwhat robust
// way from the registry.
// 
// The scheduled tasks module is supported on Windows 8.0 and above.
//
// (c) Ulf Frisk, 2021-2025
// Author: Ulf Frisk, pcileech@frizk.net
//

#include "modules.h"
#include "../vmmwinreg.h"

static LPSTR MSYSTASK_CSV_TASKS = "GUID,TaskName,TaskPath,User,TimeMostRecent,CommandLine,Parameters,TimeReg,TimeCreate,TimeLastRun,TimeCompleted\n";

#define MSYSTASK_LINELENGTH      256ULL
#define MSYSTASK_LINEHEADER      "   # Task GUID                              Task Name                                                                        Time (Most Recent)      User         Command Line :: Parameters"

#define TASKREGROOT             "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\"
#define TASKREGROOT_LOCALHIVE   "ROOT\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\"

#define VMM_MAP_TASKENTRY_TP_DIRECTORY      0x00
#define VMM_MAP_TASKENTRY_TP_TASK           0x01
#define VMM_MAP_TASKENTRY_TP_BOOT           0x02
#define VMM_MAP_TASKENTRY_TP_LOGON          0x04
#define VMM_MAP_TASKENTRY_TP_MAINTENANCE    0x08
#define VMM_MAP_TASKENTRY_TP_PLAIN          0x10

typedef struct tdVMM_MAP_TASKENTRY {
    DWORD tp;
    QWORD ftRegLastWrite;
    LPSTR uszName;
    LPSTR uszNameFs;
    LPSTR uszPath;
    QWORD qwHashParent;          // parent key hash (calculated on file system compatible hash)
    QWORD qwHashThis;            // this key hash (calculated on file system compatible hash)
    QWORD qwHashName;            // name dword hash (calculated on file system compatible hash)
    // valid scheduled task info below / no directory info:
    QWORD qwHashGUID;
    QWORD ftCreate;
    QWORD ftLastRun;
    QWORD ftLastCompleted;
    LPSTR uszGUID;
    LPSTR uszActionUser;
    LPSTR uszActionCommand;
    LPSTR uszActionParameters;
} VMM_MAP_TASKENTRY, *PVMM_MAP_TASKENTRY;

typedef struct tdVMMOB_MAP_TASK {
    OB ObHdr;
    PQWORD pqwByHashName;       // ptr to array of cMap items
    PQWORD pqwByHashGuid;       // ptr to array of cTask items
    PQWORD pqwByTaskName;       // ptr to array of cTask items
    DWORD cTask;
    DWORD _Reserved;
    PBYTE pbMultiText;
    DWORD cbMultiText;
    DWORD cMap;                 // # map entries.
    VMM_MAP_TASKENTRY pMap[0];  // map entries.
} VMMOB_MAP_TASK, *PVMMOB_MAP_TASK;

typedef struct tdVMM_TASK_SETUP_CONTEXT {
    POB_REGISTRY_HIVE pHive;
    POB_MAP pmAll;      // by path hash
    POB_MAP pmDir;      // by path hash
    POB_MAP pmTask;     // by guid hash
    POB_SET psName;     // name hash duplicate check
    POB_STRMAP psm;
} VMM_TASK_SETUP_CONTEXT, *PVMM_TASK_SETUP_CONTEXT;



//-----------------------------------------------------------------------------
// SCHEDULED TASKS - INFO GATHERING LAYER BELOW:
// Layer will create a 'map' structure.
//-----------------------------------------------------------------------------

BOOL VmmSysTask_Util_VerifyGUID(_In_reads_opt_(39) LPSTR szGUID)
{
    DWORD i;
    CHAR ch;
    if(!szGUID || szGUID[0] != '{' || szGUID[37] != '}' || szGUID[38] != 0) { return FALSE; }
    for(i = 1; i < 37; i++) {
        ch = szGUID[i];
        if((ch >= '0' && ch <= '9') || (ch >= 'A' && ch <= 'F') || (ch >= 'a' && ch <= 'f') || (ch == '-')) { continue; }
        return FALSE;
    }
    return TRUE;
}

QWORD VmmSysTask_Util_HashGUID(_In_reads_opt_(39) LPSTR szGUID)
{
    if(!szGUID || !VmmSysTask_Util_VerifyGUID(szGUID)) { return 0; }
    return CharUtil_HashNameFsA(szGUID, 0) + *(PQWORD)(szGUID + 1);
}

/*
* Populate a task with information such as action and additional time stamps.
* The data is retrieved from the task 'TackCache\Tasks\{GUID}' key values.
*/
VOID VmmSysTask_Initialize_AddInfo(_In_ VMM_HANDLE H, _In_ PVMM_TASK_SETUP_CONTEXT ctx, _In_ POB_REGISTRY_KEY pKey, _In_ PVMM_MAP_TASKENTRY pTask)
{
    DWORD dw, dwVer, cb, o;
    BYTE pb[0x800];
    WCHAR wsz[MAX_PATH + 1];
    // time stamps from 'DynamicInfo' value:
    ZeroMemory(pb, 0x24);
    if(VmmWinReg_ValueQuery5(H, ctx->pHive, pKey, "DynamicInfo", NULL, pb, sizeof(pb), NULL)) {
        if(pb[0x0b] == 0x01) { pTask->ftCreate = *(PQWORD)(pb + 0x04); }
        if(pb[0x13] == 0x01) { pTask->ftLastRun = *(PQWORD)(pb + 0x0c); }
        if(pb[0x23] == 0x01) { pTask->ftLastCompleted = *(PQWORD)(pb + 0x1c); }
    }
    // user, command, parameters from 'Actions' value:
    if(VmmWinReg_ValueQuery5(H, ctx->pHive, pKey, "Actions", NULL, pb, sizeof(pb), &cb)) {
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
            ObStrMap_PushPtrWU(ctx->psm, wsz, &pTask->uszActionUser, NULL);
        }
        // [command]
        dw = *(PDWORD)(pb + o); o += 4;
        if((dw < MAX_PATH) && !(dw & 1)) {
            memcpy(wsz, pb + o, dw); o += dw;
            wsz[dw >> 1] = 0;
            ObStrMap_PushPtrWU(ctx->psm, wsz, &pTask->uszActionCommand, NULL);
        } else {
            ObStrMap_PushPtrUU(ctx->psm, "Custom Handler", &pTask->uszActionCommand, NULL);
            o += 16 - 4;
        }
        // [parameters]
        dw = *(PDWORD)(pb + o); o += 4;
        if((o >= cb) || !dw || (dw > MAX_PATH) || (dw & 1) || (dw > cb - o)) { return; }
        memcpy(wsz, pb + o, dw);
        wsz[dw >> 1] = 0;
        ObStrMap_PushPtrWU(ctx->psm, wsz, &pTask->uszActionParameters, NULL);
    }
}

VOID VmmSysTask_Initialize_AddTask_FullPath(_In_ PVMM_TASK_SETUP_CONTEXT ctx, _In_ PVMM_MAP_TASKENTRY pe, _Out_writes_(MAX_PATH) LPSTR uszPath)
{
    PVMM_MAP_TASKENTRY pTaskParent;
    uszPath[0] = 0;
    if((pTaskParent = ObMap_GetByKey(ctx->pmAll, pe->qwHashParent))) {
        strncat_s(uszPath, MAX_PATH, pTaskParent->uszPath, _TRUNCATE);
    }
    strncat_s(uszPath, MAX_PATH, "\\", _TRUNCATE);
    strncat_s(uszPath, MAX_PATH, pe->uszName, _TRUNCATE);
}

/*
* Create or retrieve a single task in the initialization phase.
*/
PVMM_MAP_TASKENTRY VmmSysTask_Initialize_AddTask(
    _In_ VMM_HANDLE H,
    _In_ PVMM_TASK_SETUP_CONTEXT ctx,
    _In_ QWORD ftRegLastWrite,
    _In_ LPSTR uszName,
    _In_opt_ LPSTR szGUID,
    _In_opt_ PVMM_MAP_TASKENTRY pParentTask
) {
    DWORD dwHashName, iNameFs = 0;
    QWORD qwHashGUID, qwHashThis;
    PVMM_MAP_TASKENTRY pTask = NULL;
    CHAR uszPath[MAX_PATH];
    CHAR uszNameFsBuffer[MAX_PATH];
    LPSTR uszNameFs = uszName;
    // 1: find existing tasks
    if((qwHashGUID = VmmSysTask_Util_HashGUID(szGUID))) {
        pTask = ObMap_GetByKey(ctx->pmTask, qwHashGUID);
    }
    if(!pTask) {
        qwHashThis = pParentTask ? pParentTask->qwHashThis : 0;
        dwHashName = CharUtil_HashNameFsU(uszName, 0);
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
    while(!ObSet_Push(ctx->psName, dwHashName)) {
        iNameFs++;
        qwHashThis = pParentTask ? pParentTask->qwHashThis : 0;
        dwHashName = CharUtil_HashNameFsU(uszName, iNameFs);
        qwHashThis = dwHashName + ((qwHashThis >> 13) | (qwHashThis << 51));
    }
    if(iNameFs) {
        _snprintf_s(uszNameFsBuffer, _countof(uszNameFsBuffer), _TRUNCATE, "%s-%i", uszName, iNameFs);
        uszNameFs = uszNameFsBuffer;
    }
    pTask = LocalAlloc(LMEM_ZEROINIT, sizeof(VMM_MAP_TASKENTRY));
    if(!pTask) { return NULL; }
    pTask->ftRegLastWrite = ftRegLastWrite;
    pTask->qwHashParent = pParentTask ? pParentTask->qwHashThis : 0;
    pTask->qwHashThis = qwHashThis;
    pTask->qwHashName = dwHashName;
    ObStrMap_PushPtrUU(ctx->psm, uszName, &pTask->uszName, NULL);
    ObStrMap_PushPtrUU(ctx->psm, uszNameFs, &pTask->uszNameFs, NULL);
    ObStrMap_PushPtrUU(ctx->psm, (qwHashGUID ? szGUID : NULL), &pTask->uszGUID, NULL);
    VmmSysTask_Initialize_AddTask_FullPath(ctx, pTask, uszPath);
    ObStrMap_PushPtrUU(ctx->psm, uszPath, &pTask->uszPath, NULL);
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

VOID VmmSysTask_Initialize_Tree(_In_ VMM_HANDLE H, _In_ PVMM_TASK_SETUP_CONTEXT ctx, _In_ POB_REGISTRY_KEY pKey, _In_ BOOL fTopLevel, _In_opt_ PVMM_MAP_TASKENTRY pParentTask)
{
    LPSTR uszGUID;
    BYTE pbBuffer[80], pbRegGUID[80];
    DWORD dwKeyValueTp;
    PVMM_MAP_TASKENTRY pTask = NULL;
    VMM_REGISTRY_KEY_INFO KeyInfo = { 0 };
    POB_REGISTRY_KEY pObSubKey;
    POB_MAP pmObKeyList = NULL;
    // 1: fetch current task entry/directory.
    if(!fTopLevel) {
        VmmWinReg_KeyInfo(ctx->pHive, pKey, &KeyInfo);
        if(!VmmWinReg_ValueQuery5(H, ctx->pHive, pKey, "Id", &dwKeyValueTp, pbRegGUID, sizeof(pbRegGUID) - 2, NULL)) { return; }
        if(!CharUtil_WtoU((LPWSTR)pbRegGUID, -1, pbBuffer, sizeof(pbBuffer), &uszGUID, NULL, 0)) { return; }
        if(!(pTask = VmmSysTask_Initialize_AddTask(H, ctx, KeyInfo.ftLastWrite, KeyInfo.uszName, uszGUID, pParentTask))) { return; }
    }
    // 2: iterate over sub-directories
    if((pmObKeyList = VmmWinReg_KeyList(H, ctx->pHive, pKey))) {
        while((pObSubKey = ObMap_Pop(pmObKeyList))) {
            VmmSysTask_Initialize_Tree(H, ctx, pObSubKey, FALSE, pTask);
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
PVMM_MAP_TASKENTRY VmmSysTask_Initialize_GetTaskByPath(_In_ VMM_HANDLE H, _In_ PVMM_TASK_SETUP_CONTEXT ctx, _In_ LPSTR uszPath, _In_opt_ PVMM_REGISTRY_KEY_INFO pKeyInfo)
{
    QWORD qwHash;
    LPSTR uszNewName;
    CHAR uszNewPath[MAX_PATH];
    PVMM_MAP_TASKENTRY pTask, pTaskParent = NULL;
    if(!(qwHash = CharUtil_HashPathFsU(uszPath))) { return NULL; }
    if((pTask = ObMap_GetByKey(ctx->pmAll, qwHash))) { return pTask; }
    // get level -1
    if(!(uszNewName = CharUtil_PathSplitLastEx(uszPath, uszNewPath, sizeof(uszNewPath)))) { return NULL; }
    if((uszNewPath[0] != 0) && (uszNewPath[1] != 0)) {
        pTaskParent = VmmSysTask_Initialize_GetTaskByPath(H, ctx, uszNewPath, NULL);
        if(!pTaskParent) { return NULL; }
    }
    return VmmSysTask_Initialize_AddTask(H, ctx, (pKeyInfo ? pKeyInfo->ftLastWrite : 0), uszNewName, (pKeyInfo ? pKeyInfo->uszName : NULL), pTaskParent);
}

VOID VmmSysTask_Initialize_AddInfoOrType(_In_ VMM_HANDLE H, _In_ PVMM_TASK_SETUP_CONTEXT ctx, _In_ LPSTR uszKeyPath, _In_ DWORD dwTypeOpt)
{
    PVMM_MAP_TASKENTRY pTask;
    POB_MAP pmObKeyList = NULL;
    POB_REGISTRY_KEY pObSubKey, pObKey = NULL;
    VMM_REGISTRY_KEY_INFO KeyInfo = { 0 };
    BYTE pbBufferPath[2 * MAX_PATH], pbBuffer[MAX_PATH];
    LPSTR uszPath;
    if((pObKey = VmmWinReg_KeyGetByPath(H, ctx->pHive, uszKeyPath)) && (pmObKeyList = VmmWinReg_KeyList(H, ctx->pHive, pObKey))) {
        while((pObSubKey = ObMap_Pop(pmObKeyList))) {
            VmmWinReg_KeyInfo(ctx->pHive, pObSubKey, &KeyInfo);
            pTask = ObMap_GetByKey(ctx->pmTask, VmmSysTask_Util_HashGUID(KeyInfo.uszName));
            if(!pTask && !dwTypeOpt) {
                // code path should only be triggered on corrupt (due to paging or intentionally manipulated) task cache
                ZeroMemory(pbBufferPath, sizeof(pbBufferPath));
                if(VmmWinReg_ValueQuery5(H, ctx->pHive, pObSubKey, "Path", NULL, pbBufferPath, sizeof(pbBufferPath) - 2, NULL)) {
                    if(CharUtil_WtoU((LPWSTR)pbBufferPath, -1, pbBuffer, sizeof(pbBuffer), &uszPath, NULL, CHARUTIL_FLAG_TRUNCATE)) {
                        pTask = VmmSysTask_Initialize_GetTaskByPath(H, ctx, uszPath, &KeyInfo);
                    }
                }
            }
            if(pTask) {
                if(dwTypeOpt) {
                    pTask->tp = pTask->tp | dwTypeOpt;
                } else {
                    VmmSysTask_Initialize_AddInfo(H, ctx, pObSubKey, pTask);
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
    return strcmp(p1->uszPath, p2->uszPath);
}

VOID VmmSysTask_CallbackCleanup_ObObjectMap(PVMMOB_MAP_TASK pOb)
{
    LocalFree(pOb->pbMultiText);
}

VOID VmmSysTask_Initialize_DoWork(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_CONTEXT ctxP)
{
    BOOL fResult = FALSE;
    DWORD cAll, cTask, cbData, cbo, i, iTask;
    PVMM_MAP_TASKENTRY pTask;
    PVMMOB_MAP_TASK pObMap = NULL;
    POB_REGISTRY_KEY pObKey = NULL;
    VMM_TASK_SETUP_CONTEXT ctxInit = { 0 };
    // 1: INIT:
    if(!(ctxInit.psName = ObSet_New(H))) { goto fail; }
    if(!(ctxInit.pmAll = ObMap_New(H, OB_MAP_FLAGS_OBJECT_LOCALFREE))) { goto fail; }
    if(!(ctxInit.pmDir = ObMap_New(H, OB_MAP_FLAGS_OBJECT_VOID))) { goto fail; }
    if(!(ctxInit.pmTask = ObMap_New(H, OB_MAP_FLAGS_OBJECT_VOID))) { goto fail; }
    if(!(ctxInit.psm = ObStrMap_New(H, OB_STRMAP_FLAGS_CASE_INSENSITIVE | OB_STRMAP_FLAGS_STR_ASSIGN_TEMPORARY))) { goto fail; }
    // 2: ITERATE OVER 'TaskCache\Tree':
    if(!VmmWinReg_KeyHiveGetByFullPath(H, TASKREGROOT "Tree", &ctxInit.pHive, &pObKey)) { goto fail; }
    VmmSysTask_Initialize_Tree(H, &ctxInit, pObKey, TRUE, NULL);
    // 3: ADD TASK ADDITIONAL INFO:
    VmmSysTask_Initialize_AddInfoOrType(H, &ctxInit, TASKREGROOT_LOCALHIVE "Tasks", 0);
    // 4: ADD TASK TYPE:
    VmmSysTask_Initialize_AddInfoOrType(H, &ctxInit, TASKREGROOT_LOCALHIVE "Boot", VMM_MAP_TASKENTRY_TP_BOOT);
    VmmSysTask_Initialize_AddInfoOrType(H, &ctxInit, TASKREGROOT_LOCALHIVE "Logon", VMM_MAP_TASKENTRY_TP_LOGON);
    VmmSysTask_Initialize_AddInfoOrType(H, &ctxInit, TASKREGROOT_LOCALHIVE "Maintenance", VMM_MAP_TASKENTRY_TP_MAINTENANCE);
    VmmSysTask_Initialize_AddInfoOrType(H, &ctxInit, TASKREGROOT_LOCALHIVE "Plain", VMM_MAP_TASKENTRY_TP_PLAIN);
    // 5: CREATE MAP / FINALIZE:
    cAll = ObMap_Size(ctxInit.pmAll);
    cTask = ObMap_Size(ctxInit.pmTask);
    if(cAll > 0xffff) { goto fail; }
    cbData = sizeof(VMMOB_MAP_TASK) + cAll * sizeof(VMM_MAP_TASKENTRY) + ((SIZE_T)cAll + cTask + cTask) * sizeof(QWORD);
    pObMap = Ob_AllocEx(H, OB_TAG_MAP_TASK, LMEM_ZEROINIT, cbData, (OB_CLEANUP_CB)VmmSysTask_CallbackCleanup_ObObjectMap, NULL);
    if(!pObMap) { goto fail; }
    cbo = sizeof(VMMOB_MAP_TASK) + cAll * sizeof(VMM_MAP_TASKENTRY);
    pObMap->pqwByHashName = (PQWORD)((PBYTE)pObMap + cbo); cbo += cAll * sizeof(QWORD);
    pObMap->pqwByHashGuid = (PQWORD)((PBYTE)pObMap + cbo); cbo += cTask * sizeof(QWORD);
    pObMap->pqwByTaskName = (PQWORD)((PBYTE)pObMap + cbo); cbo += cTask * sizeof(QWORD);
    pObMap->cTask = (DWORD)cTask;
    pObMap->cMap = (DWORD)cAll;
    for(i = 0; i < pObMap->cMap; i++) {     // FIXUPS
        if(!(pTask = ObMap_GetByIndex(ctxInit.pmAll, (DWORD)i))) { goto fail; }
        if(!pTask->uszActionUser)       { ObStrMap_PushPtrUU(ctxInit.psm, "---", &pTask->uszActionUser, NULL); }
        if(!pTask->uszActionCommand)    { ObStrMap_PushPtrUU(ctxInit.psm, "---", &pTask->uszActionCommand, NULL); }
        if(!pTask->uszActionParameters) { ObStrMap_PushPtrUU(ctxInit.psm, "---", &pTask->uszActionParameters, NULL); }
    }
    ObStrMap_FinalizeAllocU_DECREF_NULL(&ctxInit.psm, &pObMap->pbMultiText, &pObMap->cbMultiText);
    for(i = 0; i < pObMap->cMap; i++) {     // COPY TASKENTRY TO MAP
        if(!(pTask = ObMap_GetByIndex(ctxInit.pmAll, (DWORD)i))) { goto fail; }
        memcpy(pObMap->pMap + i, pTask, sizeof(VMM_MAP_TASKENTRY));
    }
    qsort(pObMap->pMap, cAll, sizeof(VMM_MAP_TASKENTRY), (_CoreCrtNonSecureSearchSortCompareFunction)VmmSysTask_Initialize_DoWork_qsort);
    // 6: CREATE / SORT HASH LOOKUP TABLES
    for(i = 0, iTask = 0; i < cAll; i++) {
        pTask = pObMap->pMap + i;
        pObMap->pqwByHashName[i] = (pTask->qwHashName << 16) | i;
        if(pTask->uszGUID[0] && (iTask < cTask)) {
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
    if(!fResult && (pObMap = Ob_AllocEx(H, OB_TAG_MAP_TASK, LMEM_ZEROINIT, sizeof(VMMOB_MAP_TASK), NULL, NULL))) {
        ObContainer_SetOb((POB_CONTAINER)ctxP->ctxM, pObMap);
        Ob_DECREF(pObMap);
    }
    Ob_DECREF(ctxInit.pHive);
    Ob_DECREF(ctxInit.pmAll);
    Ob_DECREF(ctxInit.pmDir);
    Ob_DECREF(ctxInit.pmTask);
    Ob_DECREF(ctxInit.psName);
    Ob_DECREF(ctxInit.psm);
}

/*
* Fetch the 'TaskSchedulerMap' object.
* CALLER DECREF: return
* -- ctxP
* -- return
*/
PVMMOB_MAP_TASK VmmSysTask_GetTaskMap(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_CONTEXT ctxP)
{
    PVMMOB_MAP_TASK pOb;
    if((pOb = ObContainer_GetOb((POB_CONTAINER)ctxP->ctxM))) { return pOb; }
    EnterCriticalSection(&H->vmm.LockPlugin);
    VmmSysTask_Initialize_DoWork(H, ctxP);
    LeaveCriticalSection(&H->vmm.LockPlugin);
    return ObContainer_GetOb((POB_CONTAINER)ctxP->ctxM);
}

int VmmSysTask_GetTaskByHash_qfind_CmpFindTableQWORD(_In_ QWORD qwKey, _In_ QWORD qwpqwEntry)
{
    PQWORD pqwEntry = (PQWORD)qwpqwEntry;
    QWORD qwEntry = *pqwEntry >> 16;
    return (qwEntry > qwKey) ? -1 : ((qwEntry == qwKey) ? 0 : 1);
}

PVMM_MAP_TASKENTRY VmmSysTask_GetTaskByHash(_In_ PVMMOB_MAP_TASK pObTaskMap, _In_ PQWORD pqwHashTable, _In_ DWORD cHashTable, _In_ QWORD qwHash)
{
    PQWORD pqwHash;
    if(!qwHash) { return NULL; }
    pqwHash = Util_qfind((qwHash & 0x0000ffffffffffff), cHashTable, pqwHashTable, sizeof(QWORD), VmmSysTask_GetTaskByHash_qfind_CmpFindTableQWORD);
    if(!pqwHash) { return NULL; }
    return pObTaskMap->pMap + (*pqwHash & 0xffff);
}



//-----------------------------------------------------------------------------
// SCHEDULED TASKS - PRESENTATION LAYER BELOW:
//-----------------------------------------------------------------------------

/*
* Generate the file 'taskinfo.txt' in each individual task:
*/
DWORD MSysTask_InfoFromEntry(_In_ VMM_HANDLE H, _In_ PVMM_MAP_TASKENTRY pe, _Out_writes_(cbu) LPSTR usz, _In_ DWORD cbu)
{
    CHAR szTimeRegWR[24], szTimeCreate[24], szTimeLastRun[24], szTimeCompleted[24];
    Util_FileTime2String(pe->ftRegLastWrite, szTimeRegWR);
    Util_FileTime2String(pe->ftCreate, szTimeCreate);
    Util_FileTime2String(pe->ftLastRun, szTimeLastRun);
    Util_FileTime2String(pe->ftLastCompleted, szTimeCompleted);
    return (DWORD)snprintf(usz, cbu,
        "Name:       %s\n" \
        "Path:       %s\n" \
        "User:       %s\n" \
        "Command:    %s\n" \
        "Parameters: %s\n" \
        "GUID:       %s\n" \
        "RegLastWr:  %s\n" \
        "Create:     %s\n" \
        "LastRun:    %s\n" \
        "Completed:  %s\n",
        pe->uszName,
        pe->uszPath,
        pe->uszActionUser,
        pe->uszActionCommand,
        pe->uszActionParameters,
        pe->uszGUID,
        szTimeRegWR,
        szTimeCreate,
        szTimeLastRun,
        szTimeCompleted
    );
}

/*
* Read a 'single entry' file - the 'taskinfo.txt' a registry sub-folder file.
*/
NTSTATUS MSysTask_ReadSingleEntry(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_CONTEXT ctxP, _Out_writes_to_(cb, *pcbRead) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset, _In_ PVMM_MAP_TASKENTRY pTask, _In_ LPCSTR uszPath)
{
    DWORD cbInfoFile;
    CHAR usz[MAX_PATH];
    CHAR szu8InfoFile[0x1000];
    if(!_stricmp("taskinfo.txt", uszPath)) {
        cbInfoFile = MSysTask_InfoFromEntry(H, pTask, szu8InfoFile, sizeof(szu8InfoFile));
        return Util_VfsReadFile_FromPBYTE((PBYTE)szu8InfoFile, cbInfoFile, pb, cb, pcbRead, cbOffset);
    }
    if(!_strnicmp("registry", uszPath, 8)) {
        _snprintf_s(usz, MAX_PATH, _TRUNCATE, "registry\\HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tasks\\%s\\%s", pTask->uszGUID, uszPath + (uszPath[8] ? 9 : 8));
        return PluginManager_Read(H, NULL, usz, pb, cb, pcbRead, cbOffset);
    }
    return VMMDLL_STATUS_FILE_INVALID;
}

/*
* Generate a single line in the tasks.txt file.
*/
VOID MSysTask_ReadLine_CB(_In_ VMM_HANDLE H, _In_ PVMMOB_MAP_TASK pObTaskMap, _In_ DWORD cbLineLength, _In_ DWORD ie, _In_ PVOID pv, _Out_writes_(cbLineLength + 1) LPSTR szu8)
{
    PVMM_MAP_TASKENTRY pe = pObTaskMap->pMap + pObTaskMap->pqwByTaskName[ie];
    CHAR szTime[24];
    QWORD ftMax = max(max(pe->ftCreate, pe->ftLastCompleted), max(pe->ftLastRun, pe->ftRegLastWrite));
    Util_FileTime2String(ftMax, szTime);
    Util_usnprintf_ln(szu8, cbLineLength,
        "%04x %38s %-80.80s %s %-12.12s %s :: %s",
        ie,
        pe->uszGUID,
        pe->uszPath,
        szTime,
        pe->uszActionUser,
        pe->uszActionCommand,
        pe->uszActionParameters
    );
}

NTSTATUS MSysTask_Read(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_CONTEXT ctxP, _Out_writes_to_(cb, *pcbRead) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset)
{
    NTSTATUS nt = VMMDLL_STATUS_FILE_INVALID;
    PVMMOB_MAP_TASK pObTaskMap = NULL;
    CHAR usz[MAX_PATH];
    LPCSTR uszSubPath;
    QWORD qwHash;
    PVMM_MAP_TASKENTRY pe;
    if(!(pObTaskMap = VmmSysTask_GetTaskMap(H, ctxP))) { goto finish; }
    if(!_stricmp(ctxP->uszPath, "tasks.txt")) {
        nt = Util_VfsLineFixed_Read(
            H, (UTIL_VFSLINEFIXED_PFN_CB)MSysTask_ReadLine_CB, pObTaskMap, MSYSTASK_LINELENGTH, MSYSTASK_LINEHEADER,
            pObTaskMap->pMap, pObTaskMap->cTask, sizeof(VMM_MAP_TASKENTRY),
            pb, cb, pcbRead, cbOffset
        );
        goto finish;
    }
    if(!_strnicmp("by-guid\\", ctxP->uszPath, 8) || !_strnicmp("by-name\\", ctxP->uszPath, 8)) {
        uszSubPath = CharUtil_PathSplitFirst(ctxP->uszPath + 8, usz, sizeof(usz));
        if(!_strnicmp("by-guid\\", ctxP->uszPath, 8)) {
            qwHash = VmmSysTask_Util_HashGUID(usz);
            pe = VmmSysTask_GetTaskByHash(pObTaskMap, pObTaskMap->pqwByHashGuid, pObTaskMap->cTask, qwHash);
        } else {
            qwHash = CharUtil_HashNameFsU(usz, 0);
            pe = VmmSysTask_GetTaskByHash(pObTaskMap, pObTaskMap->pqwByHashName, pObTaskMap->cMap, qwHash);
        }
        nt = MSysTask_ReadSingleEntry(H, ctxP, pb, cb, pcbRead, cbOffset, pe, uszSubPath);
        goto finish;
    }
finish:
    Ob_DECREF(pObTaskMap);
    return nt;
}

/*
* List a single entry directory - i.e. the directory as such or the registry sub-directory.
*/
VOID MSysTask_ListSingleEntry(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_CONTEXT ctxP, _Inout_ PHANDLE pFileList, _In_ PVMM_MAP_TASKENTRY pTask, _In_ LPCSTR uszPath)
{
    DWORD cbInfoFile;
    CHAR usz[MAX_PATH];
    CHAR szu8InfoFile[0x1000];
    if(!pTask) { return; }
    if(!uszPath[0]) {
        cbInfoFile = MSysTask_InfoFromEntry(H, pTask, szu8InfoFile, sizeof(szu8InfoFile));
        VMMDLL_VfsList_AddFile(pFileList, "taskinfo.txt", cbInfoFile, NULL);
        VMMDLL_VfsList_AddDirectory(pFileList, "registry", NULL);
        return;
    }
    if(!_strnicmp(uszPath, "registry", 8)) {
        _snprintf_s(usz, MAX_PATH, _TRUNCATE, "registry\\HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tasks\\%s\\%s", pTask->uszGUID, uszPath + (uszPath[8] ? 9 : 8));
        PluginManager_List(H, NULL, usz, pFileList);
        return;
    }
}

BOOL MSysTask_List(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_CONTEXT ctxP, _Inout_ PHANDLE pFileList)
{
    QWORD i, qwHash;
    CHAR usz[MAX_PATH];
    LPCSTR uszSubPath;
    PVMM_MAP_TASKENTRY pe;
    PVMMOB_MAP_TASK pObTaskMap = NULL;
    if(!(pObTaskMap = VmmSysTask_GetTaskMap(H, ctxP))) { goto finish; }
    if(!ctxP->uszPath[0]) {
        VMMDLL_VfsList_AddDirectory(pFileList, "by-guid", NULL);
        VMMDLL_VfsList_AddDirectory(pFileList, "by-name", NULL);
        VMMDLL_VfsList_AddFile(pFileList, "tasks.txt", UTIL_VFSLINEFIXED_LINECOUNT(H, pObTaskMap->cTask) * MSYSTASK_LINELENGTH, NULL);
        goto finish;
    }
    if(!_stricmp("by-guid", ctxP->uszPath)) {
        for(i = 0; i < pObTaskMap->cTask; i++) {
            pe = pObTaskMap->pMap + (pObTaskMap->pqwByHashGuid[i] & 0xffff);
            VMMDLL_VfsList_AddDirectory(pFileList, pe->uszGUID, NULL);
        }
        goto finish;
    }
    if(!_stricmp("by-name", ctxP->uszPath)) {
        for(i = 0; i < pObTaskMap->cTask; i++) {
            pe = pObTaskMap->pMap + pObTaskMap->pqwByTaskName[i];
            VMMDLL_VfsList_AddDirectory(pFileList, pe->uszNameFs, NULL);
        }
        goto finish;
    }
    if(!_strnicmp("by-guid\\", ctxP->uszPath, 8) || !_strnicmp("by-name\\", ctxP->uszPath, 8)) {
        uszSubPath = CharUtil_PathSplitFirst(ctxP->uszPath + 8, usz, sizeof(usz));
        if(!_strnicmp("by-guid\\", ctxP->uszPath, 8)) {
            qwHash = VmmSysTask_Util_HashGUID(usz);
            pe = VmmSysTask_GetTaskByHash(pObTaskMap, pObTaskMap->pqwByHashGuid, pObTaskMap->cTask, qwHash);
        } else {
            qwHash = CharUtil_HashNameFsU(usz, 0);
            pe = VmmSysTask_GetTaskByHash(pObTaskMap, pObTaskMap->pqwByHashName, pObTaskMap->cMap, qwHash);
        }
        MSysTask_ListSingleEntry(H, ctxP, pFileList, pe, uszSubPath);
        goto finish;
    }
finish:
    Ob_DECREF(pObTaskMap);
    return TRUE;
}

/*
* Forensic Timeline: Retrieve ObTaskMap into ctxfc.
*/
PVOID MSysTask_FcInitialize(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_CONTEXT ctxP)
{
    FcFileAppend(H, "tasks.csv", MSYSTASK_CSV_TASKS);
    return VmmSysTask_GetTaskMap(H, ctxP);
}

/*
* Forensic Timeline: Populate timeline information:
*/
VOID MSysTask_FcTimeline(
    _In_ VMM_HANDLE H,
    _In_opt_ PVOID ctxfc,
    _In_ HANDLE hTimeline,
    _In_ VOID(*pfnAddEntry)(_In_ VMM_HANDLE H, _In_ HANDLE hTimeline, _In_ QWORD ft, _In_ DWORD dwAction, _In_ DWORD dwPID, _In_ DWORD dwData32, _In_ QWORD dwData64, _In_ LPCSTR uszText),
    _In_ VOID(*pfnEntryAddBySql)(_In_ VMM_HANDLE H, _In_ HANDLE hTimeline, _In_ DWORD cEntrySql, _In_ LPCSTR *pszEntrySql)
) {
    PVMMOB_MAP_TASK pObTaskMap = ctxfc;
    PVMM_MAP_TASKENTRY pe;
    CHAR usz[MAX_PATH];
    DWORD i;
    if(pObTaskMap) {
        for(i = 0; i < pObTaskMap->cTask; i++) {
            pe = pObTaskMap->pMap + pObTaskMap->pqwByTaskName[i];
            _snprintf_s(usz, MAX_PATH, _TRUNCATE, "%s - [%s :: %s] (%s)", pe->uszName, pe->uszActionCommand, pe->uszActionParameters, pe->uszActionUser);
            if(pe->ftRegLastWrite) { pfnAddEntry(H, hTimeline, pe->ftRegLastWrite, FC_TIMELINE_ACTION_MODIFY, 0, 0, 0, usz); }
            if(pe->ftCreate) { pfnAddEntry(H, hTimeline, pe->ftCreate, FC_TIMELINE_ACTION_CREATE, 0, 0, 0, usz); }
            if(pe->ftLastRun) { pfnAddEntry(H, hTimeline, pe->ftLastRun, FC_TIMELINE_ACTION_READ, 0, 0, 0, usz); }
            if(pe->ftLastCompleted) { pfnAddEntry(H, hTimeline, pe->ftLastCompleted, FC_TIMELINE_ACTION_DELETE, 0, 0, 0, usz); }
        }
    }
}

/*
* Forensic JSON log:
*/
VOID MSysTask_FcLogJSON(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_CONTEXT ctxP, _In_ VOID(*pfnLogJSON)(_In_ VMM_HANDLE H, _In_ PVMMDLL_FORENSIC_JSONDATA pData))
{
    PVMMDLL_FORENSIC_JSONDATA pd;
    PVMMOB_MAP_TASK pObTaskMap = NULL;
    PVMM_MAP_TASKENTRY pe;
    DWORD i;
    CHAR uzj[MAX_PATH];
    if(ctxP->pProcess || !(pd = LocalAlloc(LMEM_ZEROINIT, sizeof(VMMDLL_FORENSIC_JSONDATA)))) { return; }
    pd->dwVersion = VMMDLL_FORENSIC_JSONDATA_VERSION;
    pd->szjType = "shtask";
    if((pObTaskMap = VmmSysTask_GetTaskMap(H, ctxP))) {
        for(i = 0; i < pObTaskMap->cMap; i++) {
            pe = pObTaskMap->pMap + i;
            pd->i = i;
            snprintf(uzj, _countof(uzj), "user:[%s] cmd:[%s] param:[%s]", pe->uszActionUser, pe->uszActionCommand, pe->uszActionParameters);
            pd->usz[0] = pe->uszPath;
            pd->usz[1] = uzj;
            pfnLogJSON(H, pd);
        }
    }
    Ob_DECREF(pObTaskMap);
    LocalFree(pd);
}

/*
* Forensic Timeline: Free ObTaskMap from FcInitialize().
*/
VOID MSysTask_FcFinalize(_In_ VMM_HANDLE H, _In_opt_ PVOID ctxfc)
{
    Ob_DECREF(ctxfc);
}

VOID MSysTask_FcLogCSV(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_CONTEXT ctxP, _In_ VMMDLL_CSV_HANDLE hCSV)
{
    DWORD i;
    QWORD ftRecent;
    CHAR vszTimeRecent[24], vszTimeRegWR[24], vszTimeCreate[24], vszTimeLastRun[24], vszTimeCompleted[24];
    PVMMOB_MAP_TASK pObTaskMap = NULL;
    PVMM_MAP_TASKENTRY pe;
    if((ctxP->dwPID == 4) && (pObTaskMap = VmmSysTask_GetTaskMap(H, ctxP))) {
        for(i = 0; i < pObTaskMap->cMap; i++) {
            pe = pObTaskMap->pMap + i;
            ftRecent = max(max(pe->ftCreate, pe->ftLastCompleted), max(pe->ftLastRun, pe->ftRegLastWrite));
            if(!ftRecent) { continue; }
            Util_FileTime2CSV(ftRecent, vszTimeRecent);
            Util_FileTime2CSV(pe->ftRegLastWrite, vszTimeRegWR);
            Util_FileTime2CSV(pe->ftCreate, vszTimeCreate);
            Util_FileTime2CSV(pe->ftLastRun, vszTimeLastRun);
            Util_FileTime2CSV(pe->ftLastCompleted, vszTimeCompleted);
            //"GUID,TaskName,TaskPath,User,TimeMostRecent,CommandLine,Parameters,TimeReg,TimeCreate,TimeLastRun,TimeCompleted"
            FcCsv_Reset(hCSV);
            FcFileAppend(H, "tasks.csv", "%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n",
                FcCsv_String(hCSV, pe->uszGUID),
                FcCsv_String(hCSV, pe->uszName),
                FcCsv_String(hCSV, pe->uszPath),
                FcCsv_String(hCSV, pe->uszActionUser),
                vszTimeRecent,
                FcCsv_String(hCSV, pe->uszActionCommand),
                FcCsv_String(hCSV, pe->uszActionParameters),
                vszTimeRegWR,
                vszTimeCreate,
                vszTimeLastRun,
                vszTimeCompleted
            );
        }
    }
}

VOID MSysTask_Notify(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_CONTEXT ctxP, _In_ DWORD fEvent, _In_opt_ PVOID pvEvent, _In_opt_ DWORD cbEvent)
{
    if(fEvent == VMMDLL_PLUGIN_NOTIFY_REFRESH_SLOW) {
        ObContainer_SetOb((POB_CONTAINER)ctxP->ctxM, NULL);
    }
}

VOID MSysTask_Close(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_CONTEXT ctxP)
{
    Ob_DECREF(ctxP->ctxM);
}

VOID M_SysTask_Initialize(_In_ VMM_HANDLE H, _Inout_ PVMMDLL_PLUGIN_REGINFO pRI)
{
    if((pRI->magic != VMMDLL_PLUGIN_REGINFO_MAGIC) || (pRI->wVersion != VMMDLL_PLUGIN_REGINFO_VERSION)) { return; }
    if((pRI->tpSystem != VMM_SYSTEM_WINDOWS_64) && (pRI->tpSystem != VMM_SYSTEM_WINDOWS_32)) { return; }
    if(pRI->sysinfo.dwVersionBuild < 9200) { return; }                      // WIN8+ supported
    strcpy_s(pRI->reg_info.uszPathName, 128, "\\sys\\tasks");               // module name
    pRI->reg_info.fRootModule = TRUE;                                       // module shows in root directory
    pRI->reg_info.ctxM = (PVMMDLL_PLUGIN_INTERNAL_CONTEXT)ObContainer_New();
    // functions supported:
    pRI->reg_fn.pfnList = MSysTask_List;
    pRI->reg_fn.pfnRead = MSysTask_Read;
    pRI->reg_fn.pfnNotify = MSysTask_Notify;
    pRI->reg_fn.pfnClose = MSysTask_Close;
    pRI->reg_fnfc.pfnLogJSON = MSysTask_FcLogJSON;
    // timelining & csv support:
    pRI->reg_fnfc.pfnInitialize = MSysTask_FcInitialize;
    pRI->reg_fnfc.pfnLogCSV = MSysTask_FcLogCSV;
    pRI->reg_fnfc.pfnTimeline = MSysTask_FcTimeline;
    pRI->reg_fnfc.pfnFinalize = MSysTask_FcFinalize;
    memcpy(pRI->reg_info.sTimelineNameShort, "ShTask", 6);
    strncpy_s(pRI->reg_info.uszTimelineFile, 32, "timeline_task", _TRUNCATE);
    pRI->pfnPluginManager_Register(H, pRI);
}
