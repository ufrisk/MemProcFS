#include <vmmwinthread.h>
#define _INITIALIZE_FROM_FILE    "file.raw"


int main(_In_ int argc, _In_ char* argv[])
{

    VMM_HANDLE hVMM = NULL;
    BOOL result;
    DWORD cRead;
    DWORD i, cbRead, dwPID;
    PVMMDLL_MAP_MODULE pModuleMap = NULL;
    PVMMDLL_MAP_THREAD pThreadMap = NULL;
    PVMMDLL_MAP_THREADENTRY pThreadMapEntry;

    printf("------------------------------------------------------------\n");
    printf("# Initialize from file:                                     \n");
    printf("CALL:    VMMDLL_InitializeFile\n");
    hVMM = VMMDLL_Initialize(3, (LPCSTR[]) { "", "-device", _INITIALIZE_FROM_FILE });
    if(hVMM) {
    } else {
        printf("FAIL:    VMMDLL_InitializeFile\n");
        return 1;
    }
    result = VMMDLL_PidGetFromName(hVMM, "explorer.exe", &dwPID);
    if(result) {
        printf("         PID = %i\n", dwPID);
    } else {
        printf("FAIL:    VMMDLL_PidGetFromName\n");
        return 1;
    }

    printf("CALL:    VMMDLL_Map_GetModuleU\n");
    result = VMMDLL_Map_GetModuleU(hVMM, dwPID, &pModuleMap, 0);
    if(!result) {
        printf("FAIL:    VMMDLL_Map_GetModuleU #1\n");
        return 1;
    }
    if(pModuleMap->dwVersion != VMMDLL_MAP_MODULE_VERSION) {
        printf("FAIL:    VMMDLL_Map_GetModuleU - BAD VERSION\n");
        VMMDLL_MemFree(pModuleMap); pModuleMap = NULL;
        return 1;
    }
    result = 0;
    result = VMMDLL_Map_GetThread(hVMM, dwPID, &pThreadMap);


    printf("------------------------------------------------------------\n");
    printf("# Get Thread Information of 'explorer.exe'.                 \n");
    printf("CALL:    VMMDLL_Map_GetThread\n");
    if(!result) {
        return 1;
    }
    if(pThreadMap->dwVersion != VMMDLL_MAP_THREAD_VERSION) {
        printf("FAIL:    VMMDLL_Map_GetThread - BAD VERSION\n");
        VMMDLL_MemFree(pThreadMap); pThreadMap = NULL;
        return 1;
    }


///MULTIPLE THREAD 

    DoublyLinkedList list; 
    init_list(&list);
    BOOL state=FALSE;
    for (int z=0;z<pThreadMap->cMap;z++){
        pThreadMapEntry = &pThreadMap->pMap[z];
        printf("Starting for thread %d, TID:%8x \n",z,pThreadMapEntry->dwTID);
        state = UnwindScanCallstack(dwPID,hVMM,pThreadMapEntry,&list);
        if(state == FALSE){
            continue;
        }
    }
    free_list(&list);
    

///SINGLE THREAD 
/*
BOOL state;
DoublyLinkedList list; 
init_list(&list);
pThreadMapEntry = &pThreadMap->pMap[16];
state = UnwindScanCallstack(pModuleMap,dwPID,hVMM,pThreadMapEntry,&list);
if(state == FALSE){
    return 1;
}
else{
    return 0;
}

free_list(&list);
*/


printf("------------------------------------------------------------\n");
VMMDLL_MemFree(pModuleMap); pModuleMap = NULL;
VMMDLL_MemFree(pThreadMap); pThreadMap = NULL;
VMMDLL_Close(hVMM);
    
return 0;


}
 BOOL UnwindFrame(_In_ DWORD dwPID,_In_ VMM_HANDLE hVMM, _In_ td_FRAME* psCurrentFrame,_In_ PVMMDLL_MAP_THREADENTRY pThreadMapEntry,_Out_ td_FRAME* pFrameOut){


    QWORD qwCurrentAddress;
    BOOL fResult=FALSE; 
    if(!psCurrentFrame){fResult=FALSE; goto end;}
    qwCurrentAddress = psCurrentFrame->RetAddr;
    BOOL bIsChained = FALSE;

    sModuleSection smsModuleInfo;
    QWORD qwCurrentRSP,qwVaPdata, qwUnwindAddress,qwBaseModule,qwRvaAddress,qwRetAddress = 0;
    DWORD dwResultFromAddress,result,cRead,dwPdataSize;
    size_t sCountFct;

    RUNTIME_FUNCTION* runtimeIter;
    BYTE pUnwindInfoRead[4];
    UNWIND_INFO* pUnwindStruct = NULL;
    BYTE* pbPages =NULL;

    dwResultFromAddress = getVADFromAddress(&qwCurrentAddress,dwPID,hVMM,&smsModuleInfo);
    
    //Unwinding from metadata is unavailable if not PE or if function fails, exiting
    if(dwResultFromAddress == 0 || dwResultFromAddress == 3){fResult=FALSE;goto end;}
    
    else if(dwResultFromAddress == 1 || dwResultFromAddress == 2){
        qwBaseModule = smsModuleInfo.base;
        dwPdataSize = smsModuleInfo.sizePdata;
        qwVaPdata = smsModuleInfo.vaPdata;
    }
    pbPages = (BYTE*)calloc(dwPdataSize,sizeof(BYTE));if(pbPages == NULL){fResult=FALSE;goto end;}
    runtimeIter = (RUNTIME_FUNCTION*) pbPages;

    //reading all the pdata section containing the RUNTIME_FUNCTION
    if(!VMMDLL_MemReadEx(hVMM, dwPID, qwBaseModule + qwVaPdata, pbPages, dwPdataSize, &cRead, 0)) {fResult=FALSE;goto end;}

    
    qwRvaAddress = qwCurrentAddress - qwBaseModule ;

    //Finding the number of functions in pdata section
    sCountFct = dwPdataSize / sizeof(RUNTIME_FUNCTION); 

    //printf("RVA is %016llx\n",qwRvaAddress);
    //Finding where the previous Return address is located among runtime functions and getting the unwindInfo structure address

    int dwMaxCountRuntime = 0;
    for (size_t dwIterRuntime = 0; dwIterRuntime < sCountFct; dwIterRuntime++) {
        if (qwRvaAddress >=  runtimeIter[dwIterRuntime].BeginAddress && qwRvaAddress < (runtimeIter[dwIterRuntime].EndAddress) && runtimeIter[dwIterRuntime].BeginAddress!=0)
        {   printf("Runtime structure %016llx   %016llx       %016llx\n : ",runtimeIter[dwIterRuntime].BeginAddress,runtimeIter[dwIterRuntime].EndAddress,runtimeIter[dwIterRuntime].UnwindInfo);
            qwUnwindAddress = runtimeIter[dwIterRuntime].UnwindInfo ;
            printf("le unwind info se trouve à l'adresse %016llx\n",qwBaseModule + qwUnwindAddress);
            
            //issue iffinding multiple runtime functions corresponding, exiting..
            if (dwMaxCountRuntime > 1){fResult=FALSE;goto end;}
            dwMaxCountRuntime++;
        }
    }
    if(qwUnwindAddress == 0){fResult=FALSE;goto end;}
    

    //Reading UNWIND INFO structure
    pUnwindStruct = (UNWIND_INFO*)pUnwindInfoRead;

    printf("Reading UNWIND_INFO\n");
    if(!VMMDLL_MemReadEx(hVMM, dwPID, qwBaseModule+qwUnwindAddress, pUnwindInfoRead, 4, &cRead, 0)) {fResult = FALSE;goto end;}

    //PrintHexAscii((PBYTE)pUnwindStruct, min(cRead, 4));

    printf("Version of UNWIND_INFO structure is %02x\n",pUnwindStruct->Version);
    printf("Flag is %02x\n",pUnwindStruct->Flags);

    //retreiving the number of slot for the current UNWIND_INFO
    DWORD dwNbslot=pUnwindStruct->CountOfCodes;

    //finding out if UNWIND INFO is not conventional, exiting if not.
    if((pUnwindStruct->Version != 0x01 && pUnwindStruct->Version != 0x02)|| (pUnwindStruct->Flags > 0x04)){fResult = FALSE;goto end;}

    // If the CountOfCodes is NULL and the baseSP is null we are at the beginning of the unwind process, therefore the returnAdress is on top of the stack, no need to restore anything
    else if(pUnwindStruct->CountOfCodes== 0x00 && psCurrentFrame->baseSP == 0 && (pUnwindStruct->Flags != 0x04)){
        //printf("No Prolog is present, it is a leaf function at the beginning\n");
        
        //We can get the return address of top by passing pThreadMapEntry->vaRSP
        if (!PopReturnAddress(&pThreadMapEntry->vaRSP,dwPID,hVMM,&qwRetAddress)){
            pFrameOut->RetAddr = 0;
            pFrameOut->RSP = pThreadMapEntry->vaRSP;
            fResult=FALSE; goto end;
        }
        printf("The return address is %016llx\n",qwRetAddress);
        pFrameOut->RetAddr = qwRetAddress;
        pFrameOut->RSP = pThreadMapEntry->vaRSP;
        pFrameOut->baseSP = pThreadMapEntry->vaRSP + 8;
        fResult=TRUE;goto end;
    }
    //if we find a leaf function without being at the beginning
    else if(pUnwindStruct->CountOfCodes == 0x00 && psCurrentFrame->baseSP != 0 && (pUnwindStruct->Flags != 0x04)){

        qwCurrentRSP = psCurrentFrame->baseSP;
        printf("No Prolog is present, it is a leaf function, the return address is on top of stack but we are not at the beginning\n");
        
        if (!PopReturnAddress(&qwCurrentRSP,dwPID,hVMM,&qwRetAddress)){fResult=FALSE;goto end;}

        printf("The return address is %016llx\n",qwRetAddress);
        pFrameOut->RetAddr = qwRetAddress;
        pFrameOut->baseSP = qwCurrentRSP + 8;
        pFrameOut->RSP = qwCurrentRSP;
        fResult=TRUE;goto end;
    }
    //we need to unwind each code to restore RSP and pop the return address
    else{
        printf("Normal function, Continuing..");
        td_RSP_UNWINDER* pInRSPOut =NULL;
        pInRSPOut = (td_RSP_UNWINDER*)calloc(1,sizeof(td_RSP_UNWINDER)); if(pInRSPOut ==NULL){fResult=FALSE;goto end;}

        printf("Address of pInRSPOut : %p\n", (void*)pInRSPOut);
        pInRSPOut->unwind_adress = qwBaseModule+qwUnwindAddress;
        pFrameOut->RSP = qwCurrentRSP;
        pInRSPOut-> RSP_in = psCurrentFrame->baseSP;
        if(!RspUnwinder(dwPID,hVMM,pInRSPOut)){fResult=FALSE;goto end;}
        
        printf("The new RSP is :%016llx ",pInRSPOut->RSP_out);
        qwCurrentRSP = pInRSPOut->RSP_out;
        free(pInRSPOut);pInRSPOut=NULL;

        printf("Getting the return address but before testing if UNWIND INFO is chained (flag 0x04)\n");

        if(pUnwindStruct->Flags == 0x04){
            QWORD qwRtimChainAddr;
            RUNTIME_FUNCTION* pRuntimeChained;
            BYTE pbReadRtime[sizeof(RUNTIME_FUNCTION)];
            QWORD qwUwdChainedAddr;
        chain:
            pRuntimeChained =NULL;
            bIsChained = FALSE;
            //RUNTIME struct for chained is after previous unwind structure + 4 + 2bytes for each UNWIND_CODES
            qwRtimChainAddr = qwBaseModule+qwUnwindAddress+4+2*dwNbslot;
            memset(pbReadRtime, 0, sizeof(RUNTIME_FUNCTION));
            pRuntimeChained = (RUNTIME_FUNCTION*) pbReadRtime; 
            printf("Reading RUNTIME_FUNCTIONS for chained steps\n");

            //we read RUNTIME_FUNCTION for chained steps
            if(!VMMDLL_MemReadEx(hVMM, dwPID, qwRtimChainAddr, pbReadRtime, sizeof(RUNTIME_FUNCTION), &cRead, 0)) {fResult=FALSE;goto end;}
            printf("the adress for chained RUNTIME address is  %016llx\n",qwRtimChainAddr);
           
            qwUwdChainedAddr = pRuntimeChained[0].UnwindInfo;
            if(qwUwdChainedAddr == 0){fResult=FALSE;goto end;}

            printf("UNWIND_INFO for chained structures is at %016llx\n",qwBaseModule + qwUwdChainedAddr);

            td_RSP_UNWINDER* pInRSPOutChained =NULL;
            pInRSPOutChained = (td_RSP_UNWINDER*)calloc(1,sizeof(td_RSP_UNWINDER));if(pInRSPOutChained ==NULL){fResult=FALSE;goto end;}

            //preparing second structure pInRSPOutChained for new call to RspUnwinder in order to resolve chain. 
            pInRSPOutChained->unwind_adress = qwBaseModule+qwUwdChainedAddr;
            pInRSPOutChained->RSP_in = qwCurrentRSP;

            if(!RspUnwinder(dwPID,hVMM,pInRSPOutChained)){fResult=FALSE;goto end;}

            printf("New RSP is %016llx ",pInRSPOutChained->RSP_out);

            //updating current RSP
            qwCurrentRSP = pInRSPOutChained->RSP_out;

            //if chained function was also chained, redoing chained step (goto chain)
            bIsChained = pInRSPOutChained->chained;
            if(bIsChained==TRUE){
                //updating current UnwindAddress before jumping
                qwUnwindAddress = qwUwdChainedAddr;
                dwNbslot = pInRSPOutChained->nb_slot_chained;
                free(pInRSPOutChained),pInRSPOutChained=NULL;goto chain;
            }
        }

        if (!PopReturnAddress(&qwCurrentRSP,dwPID,hVMM,&qwRetAddress)){fResult=FALSE;goto end;}

        printf("Decrementing RSP because popping out the return address\n");
        qwCurrentRSP = qwCurrentRSP + 8;
        
        printf("Final RSP :  %016llx\n",qwCurrentRSP);
        printf("Return Address :  %016llx\n",qwRetAddress);
        
        //preparing return argument structure
        pFrameOut->RetAddr = qwRetAddress;
        pFrameOut->baseSP = qwCurrentRSP;
        pFrameOut->RSP = psCurrentFrame->baseSP;
        fResult=TRUE;
    }
end :
    if(pbPages){free(pbPages);pbPages = NULL;}
    return fResult;
    
}

BOOL RspUnwinder(_In_ DWORD dwPID,_In_ VMM_HANDLE hVMM,_In_Out_ td_RSP_UNWINDER* pInRSPOut){
    BYTE pUnwindInfoRead[4];
    UNWIND_INFO* pUnwindStruct = NULL;
    pUnwindStruct = (UNWIND_INFO*)pUnwindInfoRead;
    DWORD cRead,dwUnwdIter;
    QWORD pReadUnwind = pInRSPOut->unwind_adress+4;
    QWORD qwCurrentRSP;
    BOOL fResult;
    USHORT FrameOffset;
    if (pInRSPOut ==NULL){fResult = FALSE;goto end;}
    qwCurrentRSP = pInRSPOut->RSP_in;


    printf("Reading UNWIND_INFO for unwind address passed in structure at %016llx\n",pInRSPOut->unwind_adress);
    if(!VMMDLL_MemReadEx(hVMM, dwPID, pInRSPOut->unwind_adress, pUnwindInfoRead, 4, &cRead, 0)) {fResult = FALSE;goto end;}

    DWORD dwNbslot=pUnwindStruct->CountOfCodes;
    //reading UNWIND CODES for dwNbslot 
    UNWIND_CODE* pUnwindCodes = (UNWIND_CODE*)calloc(dwNbslot,sizeof(UNWIND_CODE));if(pUnwindCodes==NULL){fResult = FALSE;goto end;}
    
    //detecting multiple chained function 
    if(pUnwindStruct->Flags == 0x04){
        pInRSPOut->chained = TRUE;
        pInRSPOut->nb_slot_chained = dwNbslot;
    }

    if(pUnwindStruct->CountOfCodes == 0x00){
        pInRSPOut->RSP_out = pInRSPOut->RSP_in;
        fResult = TRUE;goto end;
    }

    //PrintHexAscii((PBYTE)pUnwindStruct, min(cRead, 4));
    printf("Reading UNWIND_CODES in fct\n");
    if(!VMMDLL_MemReadEx(hVMM, dwPID, pReadUnwind, (PBYTE)pUnwindCodes, 2*dwNbslot, &cRead, 0)) {fResult = FALSE;goto end;}
    
    printf("Enumerating each UNWIND CODES\n");
    printf("RSP at begenning is :  %016llx\n",pInRSPOut->RSP_in);
        
    //for each slot, testing type of OpInfo 
    for (dwUnwdIter = 0; dwUnwdIter<dwNbslot;dwUnwdIter++){
        switch (pUnwindCodes[dwUnwdIter].UnwindOp)
        {
            //we pop a registry, the stack need to grow down
            case UWOP_PUSH_NONVOL:
                qwCurrentRSP = qwCurrentRSP + 8;
                printf("NEW RSP :  %016llx\n",qwCurrentRSP);
                break;
            //Restoring former stack allocation, (the number of bytes is given by new slot and carried by FrameOffset)
            case UWOP_ALLOC_LARGE:
                if(pUnwindCodes[dwUnwdIter].OpInfo == 0x00){
                    FRAME_OFFSET_SH* offset = (FRAME_OFFSET_SH *)&pUnwindCodes[dwUnwdIter+1];
                    FrameOffset = (offset->FrameOffset)*8;
                    printf("Frame offset is %02x\n",FrameOffset);
                    qwCurrentRSP = qwCurrentRSP + FrameOffset;
                    printf("NEW RSP :  %016llx\n",qwCurrentRSP);
                    dwUnwdIter++;
                    break;
                }
                else if(pUnwindCodes[dwUnwdIter].OpInfo == 0x01){
                    FRAME_OFFSET_L* offset_l = (FRAME_OFFSET_L *)&pUnwindCodes[dwUnwdIter+1];
                    FrameOffset = (offset_l->FrameOffset);
                    printf("Frame offset is %02x\n",FrameOffset);
                    qwCurrentRSP = qwCurrentRSP + FrameOffset;
                    printf("NEW RSP :  %016llx\n",qwCurrentRSP);
                    dwUnwdIter=dwUnwdIter+2;
                    break;
                }
                break;                
            case UWOP_ALLOC_SMALL:
                FrameOffset = (pUnwindCodes[dwUnwdIter].OpInfo)*8 +8;
                printf("Le frame offset est %d\n",FrameOffset);
                qwCurrentRSP = qwCurrentRSP + FrameOffset;
                printf("NEW RSP :  %016llx\n",qwCurrentRSP);
                break;

            //  RSP is left untouched 
            case UWOP_SET_FPREG:
                break;
            
            // the save is only made on stack space already allocated, RSP is left untouched but next slot is used for this register so we go over it
            case UWOP_SAVE_NONVOL:
                dwUnwdIter++;
                break;
            
            // the save is only made on stack already allocated, RSP is left untouched 
            case UWOP_SAVE_NONVOL_FAR:
                break;

            // the save is only made on stack already allocated, RSP is left untouched 
            case UWOP_SAVE_XMM128:
                break;

            // the save is only made on stack already allocated, RSP is left untouched 
            case UWOP_SAVE_XMM128_FAR:
                break;

            case UWOP_PUSH_MACHFRAME:
                if(pUnwindCodes[dwUnwdIter].OpInfo == 0x00){
                    qwCurrentRSP = qwCurrentRSP + 40;
                    printf("NEW RSP :  %016llx\n",qwCurrentRSP);
                    break;
                }
                else if(pUnwindCodes[dwUnwdIter].OpInfo == 0x01){
                    qwCurrentRSP = qwCurrentRSP + 48;
                    printf("NEW RSP :  %016llx\n",qwCurrentRSP);
                    break;
                }
                break;
                
            default:
                printf("Code Unknown\n");
                break;
        }
        pInRSPOut->RSP_out = qwCurrentRSP;
    }
    fResult = TRUE;
end : 
    if(pUnwindCodes){free(pUnwindCodes); pUnwindCodes = NULL;}
    return fResult;
}

BOOL UnwindScanCallstack(_In_ DWORD dwPID,_In_ VMM_HANDLE hVMM,_In_ PVMMDLL_MAP_THREADENTRY pThreadMapEntry,_In_ DoublyLinkedList* list){
    td_FRAME sFrameInit;
    td_FRAME* psCurrentFrame = NULL;
    DWORD dwIterDisplay,dwIterFrame;
    td_FRAME* psFullCallStack = NULL; 
    BOOL fResult,fResultScan,GlobalResult,fResult_display= FALSE;
    QWORD qwLimitKernel = 0x00007FFFFFFF0000;

    psFullCallStack = (td_FRAME*)calloc(100,sizeof(td_FRAME));if(psFullCallStack==NULL){GlobalResult =FALSE;goto end;}
    psCurrentFrame = (td_FRAME*)calloc(1,sizeof(td_FRAME));if(psCurrentFrame==NULL){GlobalResult =FALSE;goto end;}

    //checcking condition before starting to unwind
    if(!validateThreadBeforeUnwind(dwPID,hVMM,pThreadMapEntry)){GlobalResult = FALSE;goto end;}

    printf("RIP IS %016llx\n ",pThreadMapEntry->vaRIP);
    printf("Constructing first frame with RIP retreived from pThreadMapEntry\n");
    sFrameInit.RetAddr = pThreadMapEntry->vaRIP;
    //setting RSP as 0 as we are not unwinding kernel stack
    sFrameInit.RSP = 0;
    sFrameInit.baseSP = 0;
    psFullCallStack[0] = sFrameInit;
    
    for (dwIterFrame = 0; dwIterFrame<20 ; dwIterFrame++) {
        if(psFullCallStack[dwIterFrame].RetAddr > qwLimitKernel){
            printf("Adress is in Kernel space, unwinding not supported at the moment\n");
            break;
        }
        fResult = UnwindFrame(dwPID, hVMM, &psFullCallStack[dwIterFrame], pThreadMapEntry,psCurrentFrame);

        if(fResult == TRUE){
            psFullCallStack[dwIterFrame + 1] = *psCurrentFrame;
        }
        //if false we could not unwind, trying heuristic technique
        else if(fResult == FALSE){
           fResultScan = heuristicScanForFrame(pThreadMapEntry,dwPID,hVMM,&psFullCallStack[dwIterFrame],psCurrentFrame);
           if(fResultScan ==TRUE){
                psFullCallStack[dwIterFrame + 1] = *psCurrentFrame;
            }
            //both technique failed, stopping
            else{
                break;
            }
        }
    }
    //setting the last frame before display
    if(psFullCallStack[dwIterFrame].RetAddr != 0){
        dwIterFrame=dwIterFrame+1;
        psFullCallStack[dwIterFrame].RSP = psFullCallStack[dwIterFrame-1].baseSP;
        psFullCallStack[dwIterFrame].RetAddr = 0;
    }

    printf("Printing Call Stack\n");

    td_SYMBOL* ptdCurrentSym = NULL;
    printf("Index     SP   Return Address  CallSite\n");
    for (int dwIterDisplay = 0; dwIterDisplay <= dwIterFrame; dwIterDisplay++) {
        ptdCurrentSym = (td_SYMBOL*)calloc(100,sizeof(td_SYMBOL));

        if(ptdCurrentSym==NULL){GlobalResult =FALSE;goto end;}

        if (psFullCallStack[dwIterDisplay-1].RetAddr !=0)
            fResult_display = GetSymbolFromAddr(psFullCallStack[dwIterDisplay-1].RetAddr, dwPID, hVMM, list,ptdCurrentSym );
            //if no symbol was resolved, printing the raw address
    if (fResult_display) {
        if (ptdCurrentSym->name != NULL && psFullCallStack[dwIterDisplay-1].RetAddr !=0){
            printf("Index %d : SP %016llx, Return Address %016llx, Symbol %s+%x\n", dwIterDisplay, psFullCallStack[dwIterDisplay].RSP, psFullCallStack[dwIterDisplay].RetAddr, ptdCurrentSym->name,ptdCurrentSym->deplacement);
        } else {
            printf("Index %d : SP %016llx, Return Address %016llx\n", dwIterDisplay, psFullCallStack[dwIterDisplay].RSP, psFullCallStack[dwIterDisplay].RetAddr);
        }
    } else {
        printf("Index %d : SP %016llx, Return Address %016llx\n", dwIterDisplay, psFullCallStack[dwIterDisplay].RSP, psFullCallStack[dwIterDisplay].RetAddr);
    }
    if(ptdCurrentSym){free(ptdCurrentSym);ptdCurrentSym=NULL;}
    }
    
    GlobalResult=TRUE;

end : 
    if(psFullCallStack){free(psFullCallStack);psFullCallStack = NULL;}
    if(psCurrentFrame){free(psCurrentFrame);psCurrentFrame = NULL;}
    return GlobalResult;
}


BOOL PopReturnAddress(_In_ QWORD* qwAddres,_In_ DWORD dwPID,VMM_HANDLE hVMM,_Out_ QWORD* BufferCandidates){

    BYTE pbAddressRead[8];
    QWORD qwAddressCandidate;
    sModuleSection sModule;
    BOOL fResult=FALSE;
    DWORD cRead ;

    if(!VMMDLL_MemReadEx(hVMM, dwPID, *qwAddres, pbAddressRead, 8, &cRead, 0)) {
        return FALSE;
    }
    //popping the 8 first bytes
    memcpy(&qwAddressCandidate, pbAddressRead, sizeof(QWORD));


    if(getVADFromAddress(&qwAddressCandidate,dwPID,hVMM,&sModule)){
            BufferCandidates[0] = qwAddressCandidate;
            return TRUE;
    }
    else{
        return FALSE;
    }
}



BOOL heuristicScanForFrame(_In_ PVMMDLL_MAP_THREADENTRY pThreadMapEntry,_In_ DWORD dwPID,_In_ VMM_HANDLE hVMM,_In_ td_FRAME* psCurrentFrame,_Out_ td_FRAME* psReturnScanFrame ){
    
    td_FRAME sValidationTempFrame,psRegistryTempFrame;
    //Getting previous RSP adn ret address as input for ValidateCandidate
    psReturnScanFrame->RetAddr = psCurrentFrame->RetAddr;
    psReturnScanFrame->RSP = psCurrentFrame->baseSP;
    BYTE pbReadCanidate[8];
    QWORD qwAddressCandidate;
    sModuleSection sModule;
    DWORD dwLimit = 0;
    DWORD cRead = 0;
    QWORD qwCurrentRSP = psCurrentFrame->baseSP;
    DWORD dwCounterReg=0;

    psRegistryTempFrame.regIsPresent = FALSE;

    //reading 8 bytes by 8 bytes and decreasing RSP at the same time (which increase addresses)
    for(qwCurrentRSP = psCurrentFrame->baseSP;qwCurrentRSP != pThreadMapEntry->vaStackBaseUser && dwLimit<50;qwCurrentRSP = qwCurrentRSP+8){
        memset(pbReadCanidate, 0, sizeof(pbReadCanidate));
        if(!VMMDLL_MemReadEx(hVMM, dwPID, qwCurrentRSP, pbReadCanidate, 8, &cRead, 0)){return FALSE;}
        memcpy(&qwAddressCandidate, pbReadCanidate, sizeof(QWORD));
        if(getVADFromAddress(&qwAddressCandidate,dwPID,hVMM,&sModule)){
                if(ValidateCandidate(dwPID,hVMM,qwAddressCandidate,psReturnScanFrame,&sValidationTempFrame)){
                        //reserving call registry in case we do not find another candidate
                        if(sValidationTempFrame.regIsPresent == TRUE && dwCounterReg == 0){
                            printf("reserving for registry call\n");
                            psRegistryTempFrame.baseSP = qwCurrentRSP+8;
                            psRegistryTempFrame.RetAddr = sValidationTempFrame.RetAddr;
                            psRegistryTempFrame.regIsPresent = TRUE;
                            dwCounterReg = dwCounterReg+1;
                            continue;
                        }
                        //not a call by registry we found a candidate, we can update the structure and return
                        else{
                            psReturnScanFrame->baseSP = qwCurrentRSP+8;
                            psReturnScanFrame->RetAddr = sValidationTempFrame.RetAddr;
                            return TRUE;
                        }
                }
                else{
                    printf("%016llx is not a valid candidate\n",qwAddressCandidate);
                }  
            }
        dwLimit++;    
    }
    if(psRegistryTempFrame.regIsPresent == TRUE){
        printf("restoring candidate from call registry\n");
        //Updating return structure psReturnScanFrame with values
        psReturnScanFrame->baseSP = psRegistryTempFrame.baseSP;
        psReturnScanFrame->RetAddr  = psRegistryTempFrame.RetAddr ;
        return TRUE;
    }
    printf("No candidates were found\n");
    //we reached the end and did not find any candidate
    return FALSE;
}

//FF D0 : call rax
//FF D3 : call rbx
//FF 15 : call [RIP+x]
//E8 : call xxxxxx
//FF 90 : call[RAX+x]

BOOL ValidateCandidate(_In_ DWORD dwPID,_In_ VMM_HANDLE hVMM,_In_ QWORD qwAddressCandidate,_In_ td_FRAME* psCurrentFrame,_Out_ td_FRAME* sValidationTempFrame){
    BYTE pbOpcodesDirectRead[5];
    BYTE pbOpcodesIndirectRead[6];
    BYTE pbOffset[4];
    DWORD cRead = 0;
    sValidationTempFrame->regIsPresent = FALSE;
    BYTE dcall[1] = { 0xe8 };
    BYTE icall[1] = { 0xff };
    BYTE mripi[1] = { 0x15 };
    BYTE mraxi[1] = { 0x90 };
    BYTE raxi[1] = { 0xD0 };
    BYTE rbxi[1] = { 0xD3 };
    QWORD qwDirectCallAddress,qwIndirectCallAddress,qwIndirectStoredAddress;
    DWORD dwOffset;
    QWORD qwCurrentRIP = psCurrentFrame->RetAddr;
    sModuleSection sVADRip,sVADTargetCall;

    if(!VMMDLL_MemReadEx(hVMM, dwPID, qwAddressCandidate -5 , pbOpcodesDirectRead, 5, &cRead, 0)){
        return FALSE;
    }
    if(!VMMDLL_MemReadEx(hVMM, dwPID, qwAddressCandidate -6 , pbOpcodesIndirectRead, 6, &cRead, 0)){
        return FALSE;
    }
    //Finding zone for RIP
    if(!getVADFromAddress(&qwCurrentRIP,dwPID,hVMM,&sVADRip)){
        return FALSE;
    }
    else{
        printf("RIP is zone starting from %016llx\n", sVADRip.base);
    }

    //we check first if the call is direct
    if(memcmp(pbOpcodesDirectRead,dcall,1) == 0){
        printf("we have a call instruction at %016llx\n",qwAddressCandidate -5);
        //we retreive the offset for the call 
        memcpy(pbOffset,pbOpcodesDirectRead+1,4);
        PrintHexAscii(pbOffset, min(cRead, 4));
        memcpy(&dwOffset, pbOffset, 4);
        //we construct the address target for the call
        qwDirectCallAddress = qwAddressCandidate + dwOffset;
        printf("Target of the Direct call  is at %016llx\n:\n",qwDirectCallAddress);

        //we retreive the VAD for the target of the call and store it in sVADTargetCall
        if(!getVADFromAddress(&qwDirectCallAddress,dwPID,hVMM,&sVADTargetCall)){
            printf("could not find appropriate module for the direct adress\n");
            return FALSE;
        }
        else{
            //we check that the target for the direct call is in the same VAD as the previous return address i.e RIP
            if (sVADRip.base !=0 && (sVADRip.base == sVADTargetCall.base)) {
            printf("RIP is in same module than target of the direct jump\n");
            printf("RIP %016llx is in range with %016llx\n",sVADRip.base,sVADTargetCall.base);
            sValidationTempFrame->RetAddr = qwAddressCandidate;
            return TRUE;

            } else {
                return FALSE;
            }
        }
    }
    //checking if we have an indirect call opcode, first
    else if(memcmp(pbOpcodesIndirectRead,icall,1) == 0){
        printf("We have an indirect call instruction at %016llx\n",qwAddressCandidate -6);
        //FF 15 : call [RIP+x]
        if(memcmp(pbOpcodesIndirectRead+1,mripi,1) == 0){
            printf("The indirect offset is :\n");
            memcpy(pbOffset,pbOpcodesIndirectRead+2,4);
            memcpy(&dwOffset, pbOffset, 4);
            qwIndirectCallAddress = qwAddressCandidate + dwOffset;
            printf("The indirect address is %016llx\n:\n",qwIndirectCallAddress); 
            printf("Retreiving the adress stored at the indirect jump adress\n"); 

            if(!PopReturnAddress(&qwIndirectCallAddress,dwPID,hVMM,&qwIndirectStoredAddress)){
                return FALSE;
            }
            printf("True target address stored at localtion is %016llx\n:\n",qwIndirectStoredAddress);

            if(!getVADFromAddress(&qwIndirectStoredAddress,dwPID,hVMM,&sVADTargetCall)){
                printf("could not find apporpriate module for the direct adress\n");
                return FALSE;
            }
            else{
                if (sVADRip.base !=0 && (sVADRip.base == sVADTargetCall.base)) {
                printf("RIP is in same module than indirect jump\n");
                printf("found true return address, RIP %016llx is in range with %016llx\n",sVADRip.base,sVADTargetCall.base);
                sValidationTempFrame->RetAddr = qwAddressCandidate;
                return TRUE;

                } else {
                    printf("Not the same module\n");
                    return FALSE;
                }
            }
        }
        //Not able to check jump address but storing it in case we don't have anything else
        else if(memcmp(pbOpcodesIndirectRead+1,mraxi,1) == 0){
            printf("It is Indirect via memory RAX\n");
            sValidationTempFrame->regIsPresent = TRUE;
            sValidationTempFrame->RetAddr = qwAddressCandidate;
            return TRUE;
        }
        else if(memcmp(pbOpcodesIndirectRead+1,raxi,1) == 0){
            printf("It is indirect via  RAX\n");
            sValidationTempFrame->regIsPresent = TRUE;
            sValidationTempFrame->RetAddr = qwAddressCandidate;
            return TRUE;
        }
        else if(memcmp(pbOpcodesIndirectRead+1,rbxi,1) == 0){
            printf("It is indirect via  RBX\n");
            sValidationTempFrame->regIsPresent = TRUE;
            sValidationTempFrame->RetAddr = qwAddressCandidate;
            return TRUE;
        }
        else{
            return FALSE;
        }
    }
    else{
        printf("We have an unknown suite byte :0X%x\n",pbOpcodesIndirectRead[0]);
        return FALSE;
    }
}

BOOL validateThreadBeforeUnwind(_In_ DWORD dwPID,_In_ VMM_HANDLE hVMM,_In_ PVMMDLL_MAP_THREADENTRY pThreadMapEntry){
    
    QWORD qwCurrentRIP;
    if(pThreadMapEntry !=NULL){qwCurrentRIP = pThreadMapEntry->vaRIP;}
    sModuleSection sModule;
    printf("Verifying RSP and RIP\n");

    if (pThreadMapEntry->vaRSP > pThreadMapEntry->vaStackBaseUser || pThreadMapEntry->vaRSP < pThreadMapEntry->vaStackLimitUser ){
        printf("SP for thread is invalid\n");
        return FALSE;
    }
    if (!getVADFromAddress(&qwCurrentRIP,dwPID,hVMM,&sModule)){
        return FALSE;
    }
    else {
        return TRUE;
    }
}


// Issues with some modules PDB loading such as KERNELBASE, win32u and some others.. address are left without symbols for these. 
BOOL GetSymbolFromAddr(_In_ QWORD returnAddres, _In_ DWORD dwPID, _In_ VMM_HANDLE hVMM,_In_ DoublyLinkedList* pLinkedLIstPDBLoaded,_Out_ td_SYMBOL* ptdCurrentSym){
    CHAR szModuleName[MAX_PATH] = { 0 };
    sModuleSection sModule;
    DWORD dwPdbSymbolDisplacement1 = 0;
    CHAR pFunctionName[MAX_PATH] = { 0 };
    CHAR pTempBufferModule[MAX_PATH] = { 0 };
    CHAR pBufferModSym[MAX_PATH] = { 0 };
    if(!getVADFromAddress(&returnAddres,dwPID,hVMM,&sModule)){
        return FALSE;
    }
    strncpy(pTempBufferModule , sModule.name, sizeof(pTempBufferModule) - 1);
    pTempBufferModule[sizeof(pTempBufferModule) - 1] = '\0';
    remove_extension_generic(pTempBufferModule, ".dll");
    remove_extension_generic(pTempBufferModule, ".DLL");

    //if we dont have already loaded the PDB file for this module, we load it
    if(!find_module(pLinkedLIstPDBLoaded,pTempBufferModule)){
        printf("The DLL %s was not found in the linked list for already loaded module\n",pTempBufferModule);
        if(!VMMDLL_PdbLoad(hVMM,dwPID,(ULONG64)sModule.base,szModuleName)){
            return FALSE;
        }
        else{
            //Once the PDB is loaded, we add it on the list
            append(pLinkedLIstPDBLoaded,pTempBufferModule);
            if(!VMMDLL_PdbSymbolName(hVMM,szModuleName,returnAddres,pFunctionName,&dwPdbSymbolDisplacement1)){
                return FALSE;
            }
            else{
                snprintf(pBufferModSym, sizeof(pBufferModSym), "%s!%s", szModuleName, pFunctionName);
                strncpy(ptdCurrentSym->name , pBufferModSym, sizeof(pFunctionName) - 1);
                ptdCurrentSym->name[sizeof(pBufferModSym) - 1] = '\0';
                ptdCurrentSym->retaddress = returnAddres;
                ptdCurrentSym->deplacement = dwPdbSymbolDisplacement1;
                return TRUE;
            } 
            
        }
    }
    // PDB was already loaded, we can retreive the SymbolName directly
    else{
        if(!VMMDLL_PdbSymbolName(hVMM,pTempBufferModule,returnAddres,pFunctionName,&dwPdbSymbolDisplacement1)){
            return FALSE;
        }
        else{
            snprintf(pBufferModSym, sizeof(pBufferModSym), "%s!%s", pTempBufferModule, pFunctionName);
            strncpy(ptdCurrentSym->name , pBufferModSym, sizeof(pFunctionName) - 1);
            //preparing return structure
            ptdCurrentSym->name[sizeof(pBufferModSym) - 1] = '\0';
            ptdCurrentSym->retaddress = returnAddres;
            ptdCurrentSym->deplacement = dwPdbSymbolDisplacement1;
            return TRUE;
        } 
    }
}

DWORD getVADFromAddress( _In_ QWORD* pAddress, _In_ DWORD dwPID,_In_ VMM_HANDLE hVMM, _Out_ sModuleSection* pmodule2Return){

    DWORD i;
    LPSTR pModule = NULL;
    DWORD fResult = FALSE;
    LPSTR sectionText = ".text";
    LPSTR sectionPdata = ".pdata";
    sSection SSectionDetails;
    PVMMDLL_MAP_VAD pVadMap = NULL;
    PVMMDLL_MAP_VADENTRY pVadMapEntry;
    VMMDLL_MEM_SEARCH_CONTEXT_SEARCHENTRY SearchEntry3[3] = { 0 };
    VMMDLL_MEM_SEARCH_CONTEXT ctxSearch = { 0 };
    PVMMDLL_MAP_MODULE pModuleMap = NULL;
    DWORD cvaSearchResult = 0;
    PQWORD pvaSearchResult = NULL;
    CHAR szVadProtection[7] = { 0 };


    if(! VMMDLL_Map_GetModuleU(hVMM, dwPID, &pModuleMap, 0)) {fResult = 0;goto end;}
    if(pModuleMap->dwVersion != VMMDLL_MAP_MODULE_VERSION) {fResult = 0;goto end;}
    if (pAddress == NULL){fResult = 0;goto end;} 

    //use VMMDLL_Map_GetModuleU first
    for (i = 0; i < pModuleMap->cMap; i++) {
        if (*pAddress >= pModuleMap->pMap[i].vaBase && *pAddress < (pModuleMap->pMap[i].vaBase + pModuleMap->pMap[i].cbImageSize)) {

            pmodule2Return->base = pModuleMap->pMap[i].vaBase;
            pmodule2Return->name = pModuleMap->pMap[i].uszText;

            //get Text section info
            if(!GetSectionInfos(pModuleMap->pMap[i].vaBase,sectionText,dwPID,hVMM,&SSectionDetails)){fResult = 0;goto end;}

            else{
                pmodule2Return->vaText = SSectionDetails.va;
                pmodule2Return->sizeText = SSectionDetails.size;
            }
            //get Pdata section info
            memset(&SSectionDetails, 0, sizeof(sSection));

            if(!GetSectionInfos(pModuleMap->pMap[i].vaBase,sectionPdata,dwPID,hVMM,&SSectionDetails)){fResult = 0;goto end;}
            else{
                pmodule2Return->vaPdata = SSectionDetails.va;
                pmodule2Return->sizePdata = SSectionDetails.size;
            }
            fResult = 1;goto end;
        }
    }
    if(!VMMDLL_Map_GetVadU(hVMM, dwPID, TRUE, &pVadMap)){fResult = 0;goto end;}

    for(i = 0; i < pVadMap->cMap; i++) {
        memset(szVadProtection, 0, sizeof(szVadProtection));
        pVadMapEntry = &pVadMap->pMap[i];
        VadMap_Protection(pVadMapEntry, szVadProtection);
        if (*pAddress >= pVadMapEntry->vaStart && *pAddress < pVadMapEntry->vaEnd && strchr(szVadProtection, 'x') != NULL) {
            //we prepare structure for searching MZ in VAD
            ctxSearch.dwVersion = VMMDLL_MEM_SEARCH_VERSION;        
            ctxSearch.pSearch = SearchEntry3;
            if(ctxSearch.cSearch < 3) {
                ctxSearch.pSearch[ctxSearch.cSearch].cb = 4;           
                memcpy(ctxSearch.pSearch[ctxSearch.cSearch].pb,(BYTE[4]) {0x4d, 0x5a, 0x90, 0x00}, 4);  
                memcpy(ctxSearch.pSearch[ctxSearch.cSearch].pbSkipMask,(BYTE[4]) {0x00, 0x00, 0xff, 0x00}, 4);        
                ctxSearch.pSearch[ctxSearch.cSearch].cbAlign = 0x1000; 
                ctxSearch.cSearch++;
            }
            ctxSearch.ReadFlags = VMMDLL_FLAG_NOCACHE; 
            ctxSearch.vaMin = pVadMapEntry->vaStart;
            ctxSearch.vaMax = pVadMapEntry->vaEnd;

            //MZ header found in VAD
            if(VMMDLL_MemSearch(hVMM, dwPID, &ctxSearch, &pvaSearchResult, &cvaSearchResult)){
                printf("  0x%016llx\n", pvaSearchResult[0]);
                if(GetSectionInfos(pvaSearchResult[0],sectionText,dwPID,hVMM,&SSectionDetails)){
                    pmodule2Return->vaText = SSectionDetails.va;
                    pmodule2Return->sizeText = SSectionDetails.size;
                }
                else{fResult = 0;goto end;}

                if(GetSectionInfos(pvaSearchResult[0],sectionPdata,dwPID,hVMM,&SSectionDetails)){
                    printf("la va de la section %s est de 0x%02x\n",sectionPdata,SSectionDetails.va);
                    pmodule2Return->vaPdata = SSectionDetails.va;
                    pmodule2Return->sizePdata = SSectionDetails.size;
                }
                else{fResult = 0;goto end;}

            fResult = 2;
            pmodule2Return->base = pVadMapEntry->vaStart;
            pmodule2Return->size_vad = pVadMapEntry->vaEnd - pVadMapEntry->vaStart;
            goto end;
            }

            else if(strchr(szVadProtection, 'x') != NULL){
                printf("Did not find anything while searching the VADS for MZ header, the adress is not in PE, returning the VAD anyway...\n");
                pmodule2Return->base = pVadMapEntry->vaStart;
                pmodule2Return->size_vad = pVadMapEntry->vaEnd - pVadMapEntry->vaStart;
                fResult = 3;goto end;
            }
            else{fResult = 0;goto end;}
        }
    }
    fResult = 0;
    pmodule2Return->base = 0;
    pmodule2Return->size_vad = 0;

end:
    if(pVadMap){VMMDLL_MemFree(pVadMap); pVadMap = NULL;}
    if(pvaSearchResult){VMMDLL_MemFree(pvaSearchResult);pvaSearchResult=NULL;}
    if(pModuleMap){VMMDLL_MemFree(pModuleMap); pModuleMap = NULL;}
    return fResult;
}

BOOL GetSectionInfos(_In_ QWORD module, _In_ LPSTR pSectionName, _In_ DWORD dwPID, _In_ VMM_HANDLE hVMM, _Out_ sSection* pReturnSection) {
    DWORD cSections;
    PIMAGE_SECTION_HEADER pSectionHeaders;
    BYTE pSection[IMAGE_SIZEOF_SHORT_NAME];
    BOOL fResult = FALSE;
    DWORD cRead = 0;

    IMAGE_DOS_HEADER dos; 
    IMAGE_NT_HEADERS ntHeaders; 
    IMAGE_SECTION_HEADER sectionHeader[9];

    strncpy((LPSTR)pSection, pSectionName, IMAGE_SIZEOF_SHORT_NAME - 1);
    pSection[IMAGE_SIZEOF_SHORT_NAME - 1] = '\0';

    // Reading DOS header
    if (!VMMDLL_MemReadEx(hVMM, dwPID, module, (PBYTE)&dos, sizeof(IMAGE_DOS_HEADER), &cRead, 0)) {return FALSE;}

    if (dos.e_magic != IMAGE_DOS_SIGNATURE) {return FALSE;}

    // Offset retreival for NT headers
    QWORD ntHeadersAddress = module + dos.e_lfanew;

    // Reading NT headers
    if (!VMMDLL_MemReadEx(hVMM, dwPID, ntHeadersAddress, (PBYTE)&ntHeaders, sizeof(IMAGE_NT_HEADERS), &cRead, 0)) {return FALSE;}
    if (ntHeaders.Signature != IMAGE_NT_SIGNATURE) {return FALSE;}

    cSections = ntHeaders.FileHeader.NumberOfSections;
    QWORD sectionHeadersAddress = ntHeadersAddress + sizeof(IMAGE_NT_HEADERS);

    if (!VMMDLL_MemReadEx(hVMM, dwPID, (QWORD)sectionHeadersAddress, (PBYTE)&sectionHeader, cSections * sizeof(IMAGE_SECTION_HEADER), &cRead, 0)) {return FALSE;}

    for (DWORD i = 0; i < cSections; i++) {
        IMAGE_SECTION_HEADER* section = &sectionHeader[i];
        if (memcmp(section->Name,pSection,IMAGE_SIZEOF_SHORT_NAME) == 0){
            pReturnSection->va = section->VirtualAddress;
            pReturnSection->size = section->Misc.VirtualSize;
            return TRUE;
        }
    }
}

