// modules.h : common includes used by modules.
//
// (c) Ulf Frisk, 2023-2025
// Author: Ulf Frisk, pcileech@frizk.net
//
#ifndef __MODULES_H__
#define __MODULES_H__

#include "../vmmdll.h"
#include "../vmm.h"

#include "../fc.h"
#include "../charutil.h"
#include "../pdb.h"
#include "../pe.h"
#include "../pluginmanager.h"
#include "../statistics.h"
#include "../util.h"
#include "../vmmlog.h"
#include "../vmmwin.h"
#include "../vmmwindef.h"



// EVIL TYPES: (max length = 15 chars):
static const VMMEVIL_TYPE EVIL_TIME_CHANGE  = { .Name = "TIME_CHANGE",  .Severity = 0x10000 };
static const VMMEVIL_TYPE EVIL_AV_DETECT    = { .Name = "AV_DETECT",    .Severity = 0xf000 };
static const VMMEVIL_TYPE EVIL_PE_INJECT    = { .Name = "PE_INJECT",    .Severity = 0xe000 };
static const VMMEVIL_TYPE EVIL_UM_APC       = { .Name = "UM_APC",       .Severity = 0xd800 };
static const VMMEVIL_TYPE EVIL_PROC_NOLINK  = { .Name = "PROC_NOLINK",  .Severity = 0xd000 };
static const VMMEVIL_TYPE EVIL_PROC_PARENT  = { .Name = "PROC_PARENT",  .Severity = 0xc000 };
static const VMMEVIL_TYPE EVIL_PROC_BAD_DTB = { .Name = "PROC_BAD_DTB", .Severity = 0xb000 };
static const VMMEVIL_TYPE EVIL_PROC_USER    = { .Name = "PROC_USER",    .Severity = 0xa000 };
static const VMMEVIL_TYPE EVIL_PROC_BASEADDR= { .Name = "PROC_BASEADDR",.Severity = 0x9C00 };
static const VMMEVIL_TYPE EVIL_PE_HDR_SPOOF = { .Name = "PE_HDR_SPOOF", .Severity = 0x9800 };
static const VMMEVIL_TYPE EVIL_HIGH_ENTROPY = { .Name = "HIGH_ENTROPY", .Severity = 0x9400 };
static const VMMEVIL_TYPE EVIL_PEB_MASQ     = { .Name = "PEB_MASQ",     .Severity = 0x9000 };
static const VMMEVIL_TYPE EVIL_DRIVER_PATH  = { .Name = "DRIVER_PATH",  .Severity = 0x8000 };
static const VMMEVIL_TYPE EVIL_PROC_DEBUG   = { .Name = "PROC_DEBUG",   .Severity = 0x7800 };
static const VMMEVIL_TYPE EVIL_THREAD       = { .Name = "THREAD",       .Severity = 0x7400 };
static const VMMEVIL_TYPE EVIL_PEB_BAD_LDR  = { .Name = "PEB_BAD_LDR",  .Severity = 0x7000 };
static const VMMEVIL_TYPE EVIL_PE_NOLINK    = { .Name = "PE_NOLINK",    .Severity = 0x6000 };
static const VMMEVIL_TYPE EVIL_PE_PATCHED   = { .Name = "PE_PATCHED",   .Severity = 0x5000 };
static const VMMEVIL_TYPE EVIL_PRIVATE_RWX  = { .Name = "PRIVATE_RWX",  .Severity = 0x4000 };
static const VMMEVIL_TYPE EVIL_NOIMAGE_RWX  = { .Name = "NOIMAGE_RWX",  .Severity = 0x3000 };
static const VMMEVIL_TYPE EVIL_PRIVATE_RX   = { .Name = "PRIVATE_RX",   .Severity = 0x2000 };
static const VMMEVIL_TYPE EVIL_NOIMAGE_RX   = { .Name = "NOIMAGE_RX",   .Severity = 0x1000 };

#endif /* __MODULES_H__ */
