// vmmwininit.h : declarations of detection mechanisms for Windows operating
//                systems. Contains functions for detecting DTB and Memory Model
//                as well as the Windows kernel base and core functionality.
//
// (c) Ulf Frisk, 2018-2023
// Author: Ulf Frisk, pcileech@frizk.net
//

#ifndef __VMMWININIT_H__
#define __VMMWININIT_H__
#include "vmm.h"

/*
* Try initialize not yet initialized values in the optional windows kernel
* context H->vmm.kernel.opt
* This function should be run once the system is fully up and running.
* This is a best-effort function, uninitialized values will remain zero.
* -- H
*/
VOID VmmWinInit_TryInitializeKernelOptionalValues(_In_ VMM_HANDLE H);

/*
* Try initialize the VMM from scratch with new WINDOWS support.
* -- H
* -- paDTB
* -- return
*/
_Success_(return)
BOOL VmmWinInit_TryInitialize(_In_ VMM_HANDLE H, _In_opt_ QWORD paDTB);

#endif /* __VMMWININIT_H__ */
