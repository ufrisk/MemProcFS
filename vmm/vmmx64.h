// vmmx64.h : definitions related to the x64 / IA32e / long-mode paging / memory model.
//
// (c) Ulf Frisk, 2018
// Author: Ulf Frisk, pcileech@frizk.net
//
#ifndef __VMMX64_H__
#define __VMMX64_H__
#include "vmm.h"

/*
* Initialize the X64 / IA32e / Long-Mode paging / memory model.
* If a previous memory model exists that memory model is first closed before 
* the new X64 memory model is initialized.
*/
VOID VmmX64_Initialize();

#endif /* __VMMX64_H__ */
