// mm_x64.h : definitions related to the x64 / IA32e / long-mode paging / memory model.
//
// (c) Ulf Frisk, 2018-2019
// Author: Ulf Frisk, pcileech@frizk.net
//
#ifndef __MM_X64_H__
#define __MM_X64_H__
#include "vmm.h"

/*
* Initialize the X64 / IA32e / Long-Mode paging / memory model.
* If a previous memory model exists that memory model is first closed before 
* the new X64 memory model is initialized.
*/
VOID MmX64_Initialize();

#endif /* __MM_X64_H__ */
