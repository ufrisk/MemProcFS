// vmmwininit.h : declarations of detection mechanisms for Windows operating
//                systems. Contains functions for detecting DTB and Memory Model
//                as well as the Windows kernel base and core functionality.
//
// (c) Ulf Frisk, 2018-2019
// Author: Ulf Frisk, pcileech@frizk.net
//

#ifndef __VMMWININIT_H__
#define __VMMWININIT_H__
#include "vmm.h"

/*
* Try initialize the VMM from scratch with new WINDOWS support.
* -- paDTB
* -- return
*/
_Success_(return)
BOOL VmmWinInit_TryInitialize(_In_opt_ QWORD paDTB);

#endif /* __VMMWININIT_H__ */
