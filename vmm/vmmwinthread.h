// CallStack unwinding features for threads in memory dumps
//
// Contributed under BSD 0-Clause License (0BSD)
// Author: MattCore71
//

#include <leechcore.h>
#include <vmmdll.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <libpdbcrust.h>
#include <ctype.h>
#include <../vmm/oscompatibility.h>
#define _In_
#define _Out_
#define _In_Out_ 


#define TRUE                                1
#define FALSE                               0
#define LMEM_ZEROINIT                       0x0040
#define _getch()                            (getchar())
#define ZeroMemory(pb, cb)                  (memset(pb, 0, cb))
#define Sleep(dwMilliseconds)               (usleep(1000*dwMilliseconds))
#define min(a, b)                           (((a) < (b)) ? (a) : (b))
#define IMAGE_SCN_MEM_EXECUTE               0x20000000
#define IMAGE_SCN_MEM_READ                  0x40000000
#define IMAGE_SCN_MEM_WRITE                 0x80000000



#define UWOP_PUSH_NONVOL 0x0   
#define UWOP_ALLOC_LARGE 0x01     
#define UWOP_ALLOC_SMALL 0x02    
#define UWOP_SET_FPREG 0x03     
#define UWOP_SAVE_NONVOL 0x04    
#define UWOP_SAVE_NONVOL_FAR 0x05
#define UWOP_SAVE_XMM128 0x08    
#define UWOP_SAVE_XMM128_FAR 0x09 
#define UWOP_PUSH_MACHFRAME 0x0a

#define  UNW_FLAG_NHANDLER  0x0
#define  UNW_FLAG_EHANDLER  0x1
#define  UNW_FLAG_UHANDLER 0x2
#define  UNW_FLAG_CHAININFO 0x4

typedef unsigned char UBYTE;
typedef unsigned short USHORT;

typedef struct Node {
    char* module_name;       
    struct Node* prev;        
    struct Node* next;       
} Node;


typedef struct {
    Node* head;  
    Node* tail;  
} DoublyLinkedList;


typedef struct _RUNTIME_FUNCTION {
  DWORD BeginAddress;
  DWORD EndAddress;
  DWORD UnwindInfo;
} RUNTIME_FUNCTION, *PRUNTIME_FUNCTION, _IMAGE_RUNTIME_FUNCTION_ENTRY, *_PIMAGE_RUNTIME_FUNCTION_ENTRY;



typedef struct td_SYMBOL {
    CHAR name[MAX_PATH];
    DWORD deplacement;
    QWORD retaddress;

}td_SYMBOL;


typedef struct sModuleSection {
    LPSTR name;
    QWORD base;
    DWORD size_vad;
    QWORD vaText;
    DWORD sizeText;
    QWORD vaPdata;
    DWORD sizePdata;
}sModuleSection;



typedef struct sSection {
    DWORD size;
    QWORD va;
}sSection;

typedef struct td_FRAME {
    BOOL regIsPresent;
    QWORD RetAddr;
    QWORD RSP;
    QWORD baseSP;
    BOOL end;
}td_FRAME;

typedef struct td_RSP_UNWINDER{
    QWORD unwind_adress;
    QWORD RSP_in;
    QWORD RSP_out;
    BOOL chained;
    DWORD nb_slot_chained;
}td_RSP_UNWINDER;

typedef struct _FRAME_OFFSET_SH {
    USHORT FrameOffset;
} FRAME_OFFSET_SH, *PFRAME_OFFSET_SH;

typedef struct _FRAME_OFFSET_L {
    DWORD FrameOffset;
} FRAME_OFFSET_L, *PFRAME_OFFSET_L;

typedef struct _UNWIND_INFO {
    UBYTE Version       : 3;
    UBYTE Flags         : 5;
    UBYTE SizeOfProlog;
    UBYTE CountOfCodes;
    UBYTE FrameRegister_offset;
} UNWIND_INFO, *PUNWIND_INFO;

typedef union _UNWIND_CODE {
    struct {
        UBYTE CodeOffset;
        UBYTE UnwindOp : 4;
        UBYTE OpInfo   : 4;
    };
} UNWIND_CODE, *PUNWIND_CODE;



HANDLE LocalAlloc(DWORD uFlags, SIZE_T uBytes)
{
    HANDLE h = malloc(uBytes);
    if(h && (uFlags & LMEM_ZEROINIT)) {
        memset(h, 0, uBytes);
    }
    return h;
}

VOID LocalFree(HANDLE hMem)
{
    free(hMem);
}

VOID PrintHexAscii(_In_ PBYTE pb, _In_ DWORD cb)
{
    LPSTR sz;
    DWORD szMax = 0;
    VMMDLL_UtilFillHexAscii(pb, cb, 0, NULL, &szMax);
    if(!(sz = LocalAlloc(0, szMax))) { return; }
    VMMDLL_UtilFillHexAscii(pb, cb, 0, sz, &szMax);
    printf("%s", sz);
    LocalFree(sz);
}


VOID VadMap_Protection(_In_ PVMMDLL_MAP_VADENTRY pVad, _Out_writes_(6) LPSTR sz)
{
    BYTE vh = (BYTE)pVad->Protection >> 3;
    BYTE vl = (BYTE)pVad->Protection & 7;
    sz[0] = pVad->fPrivateMemory ? 'p' : '-';                                    // PRIVATE MEMORY
    sz[1] = (vh & 2) ? ((vh & 1) ? 'm' : 'g') : ((vh & 1) ? 'n' : '-');         // -/NO_CACHE/GUARD/WRITECOMBINE
    sz[2] = ((vl == 1) || (vl == 3) || (vl == 4) || (vl == 6)) ? 'r' : '-';     // COPY ON WRITE
    sz[3] = (vl & 4) ? 'w' : '-';                                               // WRITE
    sz[4] = (vl & 2) ? 'x' : '-';                                               // EXECUTE
    sz[5] = ((vl == 5) || (vl == 7)) ? 'c' : '-';                               // COPY ON WRITE
    if(sz[1] != '-' && sz[2] == '-' && sz[3] == '-' && sz[4] == '-' && sz[5] == '-') { sz[1] = '-'; }
}

LPSTR VadMap_Type(_In_ PVMMDLL_MAP_VADENTRY pVad)
{
    if(pVad->fImage) {
        return "Image";
    } else if(pVad->fFile) {
        return "File ";
    } else if(pVad->fHeap) {
        return "Heap ";
    } else if(pVad->fStack) {
        return "Stack";
    } else if(pVad->fTeb) {
        return "Teb  ";
    } else if(pVad->fPageFile) {
        return "Pf   ";
    } else {
        return "     ";
    }
}


Node* find_module(DoublyLinkedList* list, const char* module_name) {
    Node* current = list->head;
    while (current != NULL) {
        if (strcmp(current->module_name, module_name) == 0) {
            return current;
        }
        current = current->next;
    }
    return NULL; 
}

void init_list(DoublyLinkedList* list) {
    list->head = NULL;
    list->tail = NULL;
}

Node* create_node(const char* module_name) {
    Node* new_node = (Node*)malloc(sizeof(Node));
    if (!new_node) {
        perror("Failed to allocate memory for node");
        exit(EXIT_FAILURE);
    }

    new_node->module_name = strdup(module_name);
    new_node->prev = NULL;
    new_node->next = NULL;
    return new_node;
}

void append(DoublyLinkedList* list, const char* module_name) {
    Node* new_node = create_node(module_name);

    if (list->tail) {
        list->tail->next = new_node;
        new_node->prev = list->tail;
        list->tail = new_node;
    } else {
        list->head = list->tail = new_node;
    }
}

void print_list(const DoublyLinkedList* list) {
    Node* current = list->head;
    while (current) {
        printf("Module: %s\n", current->module_name);
        current = current->next;
    }
}

void free_list(DoublyLinkedList* list) {
    Node* current = list->head;
    while (current) {
        Node* temp = current;
        current = current->next;
        free(temp->module_name); 
        free(temp);    
    }
    list->head = list->tail = NULL;
}

void remove_extension_generic(char* str, const char* ext) {
    size_t len = strlen(str);
    size_t ext_len = strlen(ext);

    if (len > ext_len && strcmp(str + len - ext_len, ext) == 0) {
        str[len - ext_len] = '\0';
    }
}



/*
* Unwind a frame by giving a current frame psCurrentFrame and returns the next frame pFrameOut. pThreadMapEntry is only usefull for first frame to be unwind
* -- dwPID
* -- hVMM
* -- psCurrentFrame
* -- pThreadMapEntry
* -- pFrameOut
*/
BOOL UnwindFrame(_In_ DWORD dwPID,_In_ VMM_HANDLE hVMM, _In_ td_FRAME* psCurrentFrame,_In_ PVMMDLL_MAP_THREADENTRY pThreadMapEntry,_Out_ td_FRAME* pFrameOut);

/*
* Retreive a callstack by testing unwinding on frames and using heuristic method in case it fails. A linked list initalialized is passed to ensure the tracability of PDB loaded. 
* -- dwPID
* -- hVMM
* -- pThreadMapEntry
* -- list
*/
BOOL UnwindScanCallstack(_In_ DWORD dwPID,_In_ VMM_HANDLE hVMM,_In_ PVMMDLL_MAP_THREADENTRY pThreadMapEntry,_In_ DoublyLinkedList* list);


/*
* Pop a return address retreived from an address given (generaly stack pointer)
* -- qwAddres
* -- dwPID
* -- hVMM
* -- BufferCandidates
*/
BOOL PopReturnAddress(_In_ QWORD* qwAddres,_In_ DWORD dwPID,_In_ VMM_HANDLE hVMM,_Out_ QWORD* BufferCandidates);



/*
* Validate an address candidate for return address retreived from the stack by analysing the flow of execution. it is fetching previous opcodes looking for direct and indirect call, then comparing the target of jump with previous RIP to validate
* -- dwPID
* -- hVMM
* -- qwAddressCandidate
* -- psCurrentFrame
* -- sValidationTempFrame
*/
BOOL ValidateCandidate(_In_ DWORD dwPID,_In_ VMM_HANDLE hVMM,_In_ QWORD qwAddressCandidate,_In_ td_FRAME* psCurrentFrame,_Out_ td_FRAME* sValidationTempFrame);

/*
* Fetch the next frame from the previous one by scanning and validating return address retreived on stack
* -- pThreadMapEntry
* -- dwPID
* -- hVMM
* -- psCurrentFrame
* -- psReturnScanFrame
*/

BOOL heuristicScanForFrame(PVMMDLL_MAP_THREADENTRY pThreadMapEntry,DWORD dwPID,VMM_HANDLE hVMM,td_FRAME* psCurrentFrame,_Out_ td_FRAME* psReturnScanFrame );


/*
* Validate entries parameters
* -- dwPID
* -- hVMM
* -- pThreadMapEntry
*/
BOOL validateThreadBeforeUnwind(_In_ DWORD dwPID,_In_ VMM_HANDLE hVMM,_In_ PVMMDLL_MAP_THREADENTRY pThreadMapEntry);


/*
* Given the previous RSP from the previous frame and the Unwind info address, unwind the frame to reconstruct the previous RSP
* -- dwPID
* -- hVMM
* -- pInRSPOut
*/
BOOL RspUnwinder(_In_ DWORD dwPID,_In_ VMM_HANDLE hVMM,_In_Out_ td_RSP_UNWINDER *pInRSPOut);


/*
* Get the symbol associated with the address
* -- pThreadMapEntry
* -- dwPID
* -- hVMM
* -- psCurrentFrame
* -- psReturnScanFrame
*/
BOOL GetSymbolFromAddr(_In_ QWORD returnAddres, _In_ DWORD dwPID, _In_ VMM_HANDLE hVMM,_In_ DoublyLinkedList* list,_Out_ td_SYMBOL* sym);



/*
* Get the module or VAD info (pdata and text section VA and size, base address of the VAD or module) from an address given.
* -- pAddress
* -- dwPID
* -- hVMM
* -- pmodule2Return
*/
DWORD getVADFromAddress( _In_ QWORD* pAddress, _In_ DWORD dwPID,_In_ VMM_HANDLE hVMM, _Out_ sModuleSection* pmodule2Return);


/*
* Retreived section VA and size given it's name
* -- module
* -- pSectionName
* -- dwPID
* -- hVMM
* -- pReturnSection
*/
BOOL GetSectionInfos(_In_ QWORD module,_In_ LPSTR pSectionName,_In_ DWORD dwPID,_In_ VMM_HANDLE hVMM,_Out_ sSection* pReturnSection);




// Functions for linkedList in order to optimize PDB use. 
void free_list(_In_ DoublyLinkedList* list);
void print_list(_In_ const DoublyLinkedList* list);
void append(_In_ DoublyLinkedList* list, _In_ const char* module_name) ;
Node* create_node(_In_ const char* module_name);
void init_list(_In_ DoublyLinkedList* list) ;
void remove_extension_generic(_In_ char* str, _In_ const char* ext);
Node* find_module(_In_ DoublyLinkedList* list, _In_ const char* module_name);



