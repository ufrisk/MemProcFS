// mm_x86.h : definitions related to the x86 32-bit protected mode memory model.
//
// (c) Ulf Frisk, 2018-2019
// Author: Ulf Frisk, pcileech@frizk.net
//
#ifndef __MM_X86_H__
#define __MM_X86_H__
#include "vmm.h"

/*
* Initialize the X86 32-bit protected mode memory model.
* If a previous memory model exists that memory model is first closed before
* the new X86 memory model is initialized.
*/
VOID MmX86_Initialize();

#endif /* __MM_X86_H__ */
