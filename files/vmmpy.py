# vmmpy.py
#
# Provides a convenient python interface for the memory process file system
# virtual memory manager - vmm.dll / vmmpyc.pyc.
#
# Fast and convenient python access towards the native vmm.dll and in some
# cases linked pcileech.dll libraries. This wrapper also provides for code
# completion in some supported dev environments.
#
# https://github.com/ufrisk/
#
# (c) Ulf Frisk, 2018-2019
# Author: Ulf Frisk, pcileech@frizk.net
#
# Header Version: 2.4
#

from vmmpyc import *

#------------------------------------------------------------------------------
# VmmPy CONSTANTS BELOW:
# NB! Only some unrelated contants are put here. Constants more closely related
#     to functionality is put close to the functionality itself.
#------------------------------------------------------------------------------

# NTSTATUS values. (Used/Returned by Write file plugin callbacks).
VMMPY_STATUS_SUCCESS =                  0x00000000
VMMPY_STATUS_UNSUCCESSFUL =             0xC0000001
VMMPY_STATUS_END_OF_FILE =              0xC0000011
VMMPY_STATUS_FILE_INVALID =             0xC0000098

# SYSTEM values - used to determine if a plugin is supported or not for
# the current system that is being analyzed.
VMMPY_SYSTEM_UNKNOWN_X64 =              0x0001
VMMPY_SYSTEM_WINDOWS_X64 =              0x0002
VMMPY_SYSTEM_UNKNOWN_X86 =              0x0003
VMMPY_SYSTEM_WINDOWS_X86 =              0x0004

# MEMORYMODEL values - used to determine if a plugin is supported or not
# for a specific memory model.
VMMPY_MEMORYMODEL_NA =                  0x0000
VMMPY_MEMORYMODEL_X86 =                 0x0001
VMMPY_MEMORYMODEL_X86PAE =              0x0002
VMMPY_MEMORYMODEL_X64 =                 0x0003

# EVENT values - received by the notify callback function for specific events
# occuring in the native plugin manager / vmm / memory process file system.
VMMPY_PLUGIN_EVENT_VERBOSITYCHANGE =    0x01
VMMPY_PLUGIN_EVENT_TOTALREFRESH =       0x02

#------------------------------------------------------------------------------
# VmmPy INITIALIZATION FUNCTIONALITY BELOW:
#------------------------------------------------------------------------------

def VmmPy_Close():
    """Close an initialized instance of VMM.DLL and clean up all allocated resources including plugins, linked PCILeech.dll and other memory resources.

    Keyword arguments:
    N/A
    
    Example:
    VmmPy_Close()
    """
    VMMPYC_Close()



def VmmPy_Refresh():
    """Force refresh the internal state of the VMM.DLL - refreshing process listings and internal caches. NB! function may take a long time to execute!

    Keyword arguments:
    N/A
    
    Example:
    VmmPy_Refresh()
    """
    VMMPYC_Refresh(0)



def VmmPy_Initialize(args, is_printf = True, is_verbose = False, is_verbose_extra = False, is_verbose_tlp = False, page_table_base = 0):
    """Initialize VmmPy and the Virtual Memory Manager VMM.DLL with arguments as
       in the argument list args. Important is the -device option and optionally
       -remote option as closer described in the MemProcFS and LeechCore projects.

    Keyword arguments:
    file_name -- str: memory dump file to load.
    is_printf -- bool: console output from vmm.dll is enabled.
    is_verbose -- bool: verbose level.
    is_verbose_extra -- bool: extra verbose level.
    is_verbose_tlp -- bool: show FPGA TLPs or similar - super verbose!
    page_table_base -- int: optional page directory base of the OS kernel or a x64 process.
    
    Example:
    VmmPy_Initialize(['c:\\temp\\dump.raw'])
    VmmPy_Initialize(['-device', 'dumpit','-remote', 'rpc://insecure:remote.example.com'])
    """
    if page_table_base > 0:
        args.append("-cr3")
        args.append(str(page_table_base))
    if is_printf:
        args.append("-printf")
    if is_verbose:
        args.append("-v")
    if is_verbose_extra:
        args.append("-vv")
    if is_verbose_tlp:
        args.append("-vvv")
    VMMPYC_Initialize(args)



#------------------------------------------------------------------------------
# VmmPy CONFIGURATION FUNCTIONALITY BELOW:
#------------------------------------------------------------------------------

VMMPY_OPT_CORE_PRINTF_ENABLE                  = 0x80000001  # RW
VMMPY_OPT_CORE_VERBOSE                        = 0x80000002  # RW
VMMPY_OPT_CORE_VERBOSE_EXTRA                  = 0x80000003  # RW
VMMPY_OPT_CORE_VERBOSE_EXTRA_TLP              = 0x80000004  # RW
VMMPY_OPT_CORE_MAX_NATIVE_ADDRESS             = 0x80000005  # R
VMMPY_OPT_CORE_MAX_NATIVE_IOSIZE              = 0x80000006  # R
VMMPY_OPT_CORE_SYSTEM                         = 0x80000007  # R
VMMPY_OPT_CORE_MEMORYMODEL                    = 0x80000008  # R

VMMPY_OPT_CONFIG_IS_REFRESH_ENABLED           = 0x40000001  # R - 1/0
VMMPY_OPT_CONFIG_TICK_PERIOD                  = 0x40000002  # RW - base tick period in ms
VMMPY_OPT_CONFIG_READCACHE_TICKS              = 0x40000003  # RW - memory cache validity period (in ticks)
VMMPY_OPT_CONFIG_TLBCACHE_TICKS               = 0x40000004  # RW - page table (tlb) cache validity period (in ticks)
VMMPY_OPT_CONFIG_PROCCACHE_TICKS_PARTIAL      = 0x40000005  # RW - process refresh (partial) period (in ticks)
VMMPY_OPT_CONFIG_PROCCACHE_TICKS_TOTAL        = 0x40000006  # RW - process refresh (full) period (in ticks)
VMMPY_OPT_CONFIG_VMM_VERSION_MAJOR            = 0x40000007  # R
VMMPY_OPT_CONFIG_VMM_VERSION_MINOR            = 0x40000008  # R
VMMPY_OPT_CONFIG_VMM_VERSION_REVISION         = 0x40000009  # R
VMMPY_OPT_CONFIG_STATISTICS_FUNCTIONCALL      = 0x4000000A  # RW - enable function call statistics (.status/statistics_fncall file)


def VmmPy_ConfigGet(vmmpy_opt_id):
    """Retrieve a configuration setting given a VMMPY_OPT_* option.

    Keyword arguments:
    vmmpy_opt_id -- int: the configuration value to retrieve as defined by VMMPY_OPT_*.
    return -- int: configuration value. (Fail: -1).
    
    Example:
    VmmPy_ConfigGet(VMMPY_OPT_CORE_PRINTF_ENABLE) --> 1
    """
    return VMMPYC_ConfigGet(vmmpy_opt_id)



def VmmPy_ConfigSet(vmmpy_opt_id, value):
    """Set a configuration setting given a VMMPY_OPT_* option.

    Keyword arguments:
    vmmpy_opt_id -- int: the configuration value to retrieve as defined by VMMPY_OPT_*.
    value -- int: value to set.
    
    Example:
    VmmPy_ConfigSet(VMMPY_OPT_CORE_PRINTF_ENABLE, 0)
    """
    VMMPYC_ConfigSet(vmmpy_opt_id, value)



def VmmPy_GetVersion():
    """Retrieve the Version of the core functionality in the VMM.DLL.
  
    Example:
    VmmPy_GetVersion() -> 1.0.0
    """
    verMajor = VMMPYC_ConfigGet(VMMPY_OPT_CONFIG_VMM_VERSION_MAJOR)
    verMinor = VMMPYC_ConfigGet(VMMPY_OPT_CONFIG_VMM_VERSION_MINOR)
    verRevision = VMMPYC_ConfigGet(VMMPY_OPT_CONFIG_VMM_VERSION_REVISION)
    return str(verMajor) + '.' + str(verMinor) + '.' + str(verRevision)



#------------------------------------------------------------------------------
# VmmPy MEMORY ACCESS FUNCTIONALITY BELOW:
#------------------------------------------------------------------------------

VMMPY_FLAG_NOCACHE           = 0x0001      # do not use the data cache (force reading from memory acquisition device)
VMMPY_FLAG_ZEROPAD_ON_FAIL   = 0x0002      # zero pad failed physical memory reads and report success if read within range of physical memory.
VMMPY_FLAG_FORCECACHE_READ   = 0x0008      # force use of cache - fail non-cached pages - only valid for reads, invalid with VMM_FLAG_NOCACHE/VMM_FLAG_ZEROPAD_ON_FAIL.



def VmmPy_MemRead(pid, address, length, flags = 0):
    """Read memory given a pid, a (64-bit) address and length. Return result as bytes.

    Keyword arguments:
    pid -- int: the process identifier (pid) when reading process virtual memory. -1 when reading physical memory.
    address -- int: the address to read.
    length -- int: the number of bytes to read.
    flags -- int: optional flags as specified by VMMPY_FLAG* constants.
    return -- bytes: memory.
    
    Example:
    VmmPy_MemRead(-1, 0x1000, 4) --> b'\x00\x01\x02\x03'
    """
    return VMMPYC_MemRead(pid, address, length, flags)



def VmmPy_MemReadScatter(pid, address_list, flags = 0):
    """Read page (4kB) sized & aligned memory given a pid and a list of (64-bit) addresses. Return result in list of dict.

    Keyword arguments:
    pid -- int: the process identifier (pid) when reading process virtual memory. -1 when reading physical memory.
    address_list -- list: a list of page (4kB/0x1000) aligned addresses.
    flags -- int: optional flags as specified by VMMPY_FLAG* constants.
    return -- list: of dicts with the result.
    
    Example:
    VmmPy_MemReadScatter(-1, [0x1000]) --> [{'addr': 4096, 'pa': 4096, 'data': b'\x00\x01\x02\x03\x04 ... ', 'size': 4096}]
    """

    return VMMPYC_MemReadScatter(pid, address_list, flags)



def VmmPy_MemWrite(pid, address, bytes_data):
    """Write memory given a pid, a (64-bit) address and length. No return.

    Keyword arguments:
    pid -- int: the process identifier (pid) when reading process virtual memory. -1 when writing physical memory.
    address -- int: the address to write.
    bytes_data -- bytes: a bytes-like object.
    
    Example:
    VmmPy_MemWrite(0x666, 0x1000, b'\x00\x01\x02\x03')
    """
    VMMPYC_MemWrite(pid, address, bytes_data)



def VmmPy_MemVirt2Phys(pid, address):
    """Translate a virtual address (va) to a physical address given a pid and return the result.

    Keyword arguments:
    pid -- int: the process identifier (pid) when reading process virtual memory.
    va -- int: the virtual address (va) to translate
    return -- int: the physical address (pa).
    
    Example:
    VmmPy_MemVirt2Phys(0x666, 0x00007ff74d5da000) --> 0x000000004d5da000
    """
    return VMMPYC_MemVirt2Phys(pid, address)



#------------------------------------------------------------------------------
# VmmPy GENERAL PROCESS / MEMORY MAP FUNCTIONALITY BELOW:
#------------------------------------------------------------------------------

def VmmPy_PidList():
    """Retrieve all process identifiers (pids) in the system and return them as a list.

    Keyword arguments:
    return -- list: pids.
    
    Example:
    VmmPy_PidList() --> [4, 76, 324, 392, 576, 588, ...]
    """
    return sorted(VMMPYC_PidList())



def VmmPy_PidGetFromName(process_name):
    """Retrieve a pid from a process_name and return it.
    NB! if more processes do have the same name only one will be returned by
    this function. If important to find all then use VmmPy_PidList() instead.

    Keyword arguments:
    process_name -- str: name of a process to find.
    return -- int: pid number.
    
    Example:
    VmmPy_PidGetFromName() --> 4
    """
    return VMMPYC_PidGetFromName(process_name)



def VmmPy_ProcessGetMemoryMap(pid, is_identify_modules = False):
    """Retrieve the memory map for a specific pid.

    Keyword arguments:
    pid -- int: the process identifier (pid) when reading process virtual memory.
    is_identify_modules -- bool: (optional) identify module names (slow).
    return -- list: of dict of memory map entries.
    
    Example:
    VmmPy_ProcessGetMemoryMap(4) --> [{'va': 2147352576, 'size': 4096, 'pages': 1, 'wow64': False, 'tag': '', 'flags-pte': 9223372036854775812, 'flags': 'srwx'}, ...]
    """
    return VMMPYC_ProcessGetMemoryMap(pid, is_identify_modules)



def VmmPy_ProcessGetMemoryMapEntry(pid, va, is_identify_modules = False):
    """Retrieve a single memory map entry for a given pid and virtual address (va).

    Keyword arguments:
    pid -- int: the process identifier (pid) when reading process virtual memory.
    va -- int: a virtual address inside the entry to retrieve.
    is_identify_modules -- bool: (optional) identify module names (slow).
    return -- dict: of memory map entries.
    
    Example:
    VmmPy_ProcessGetMemoryMapEntry(4, 0x7ffe0000) --> {'va': 2147352576, 'size': 4096, 'pages': 1, 'wow64': False, 'name': '', 'flags-pte': 9223372036854775812, 'flags': 'srwx'}
    """
    return VMMPYC_ProcessGetMemoryMapEntry(pid, va, is_identify_modules)



def VmmPy_ProcessGetModuleMap(pid):
    """Retrieve the module map for a specific pid.

    Keyword arguments:
    pid -- int: the process identifier (pid) when reading process virtual memory.
    return -- list: of dict of module map information entries.
    
    Example:
    VmmPy_ProcessGetModuleMap(332) --> [{'va': 140718422491136, 'va-entry': 0, 'wow64': False, 'size': 1966080, 'name': 'ntdll.dll'}, ...]
    """
    return VMMPYC_ProcessGetModuleMap(pid)



def VmmPy_ProcessGetModuleFromName(pid, module_name):
    """Retrieve the module map for a specific pid and module name.

    Keyword arguments:
    pid -- int: the process identifier (pid) when reading process virtual memory.
    module_name -- bool: name of the module to retrieve.
    return -- dict: of module information.
    
    Example:
    VmmPy_ProcessGetModuleMap(332, "ntdll.dll") --> {'va': 140718422491136, 'va-entry': 0, 'wow64': False, 'size': 1966080, 'name': 'ntdll.dll'}
    """
    return VMMPYC_ProcessGetModuleFromName(pid, module_name)



def VmmPy_ProcessGetInformation(pid):
    """Retrieve process information for a specific pid and return as dict.

    Keyword arguments:
    pid -- int: the process identifier (pid) when reading process virtual memory.
    return -- dict: of process information.
    
    Example:
    VmmPy_ProcessGetInformation(332) --> {'pid': 8796, 'pa-dtb': 5798625280, 'pa-dtb-user': 6237978624, 'state': 0, 'tp-system': 2, 'usermode': True, 'name': 'cmd.exe', 'wow64': False, 'va-entry': 140700131683072, 'va-eprocess': 18446635809067693440, 'va-peb': 708313505792, 'va-peb32': 0}
    """
    return VMMPYC_ProcessGetInformation(pid)



def VmmPy_ProcessListInformation():
    """Retrieve process information for all pids and return as dict of dict.

    Keyword arguments:
    return -- dict: dict of process information with pid as key.
    
    Example:
    VmmPy_ProcessListInformation() --> {4: {...}, ..., 322: {'pid': 8796, 'pa-dtb': 5798625280, 'pa-dtb-user': 6237978624, 'state': 0, 'tp-system': 2, 'usermode': True, 'name': 'cmd.exe', 'wow64': False, 'va-entry': 140700131683072, 'va-eprocess': 18446635809067693440, 'va-peb': 708313505792, 'va-peb32': 0}
    """
    pids = VmmPy_PidList()
    result = {}
    for pid in pids:
        result[pid] = VMMPYC_ProcessGetInformation(pid)
    return result



#------------------------------------------------------------------------------
# VmmPy WINDOWS SPECIFIC PROCESS FUNCTIONALITY BELOW:
#------------------------------------------------------------------------------

def VmmPy_ProcessGetEAT(pid, module_name):
    """Retrieve the export address table (EAT) for a specific pid and module name and return as list of dict.

    Keyword arguments:
    pid -- int: the process identifier (pid) when reading process virtual memory.
    module_name -- str: name of the module to retrieve.
    return -- list: of dict of EAT information.
    
    Example:
    VmmPy_ProcessGetEAT(332, "ntdll.dll") --> [{'i': 0, 'va': 140718385196671, 'offset': 585343, 'fn': 'AcquireSRWLockExclusive'}, ... ]
    """
    return VMMPYC_ProcessGetEAT(pid, module_name)



def VmmPy_ProcessGetIAT(pid, module_name):
    """Retrieve the import address table (IAT) for a specific pid and module name and return as list of dict.

    Keyword arguments:
    pid -- int: the process identifier (pid) when reading process virtual memory.
    module_name -- str: name of the module to retrieve.
    return -- list: of dict of IAT information.
    
    Example:
    VmmPy_ProcessGetAT(332, "cmd.exe") --> [{'i': 0, 'va': 140718377374992, 'fn': 'setlocale', 'dll': 'msvcrt.dll'}, ... ]
    """
    return VMMPYC_ProcessGetIAT(pid, module_name)



def VmmPy_ProcessGetDirectories(pid, module_name):
    """Retrieve the data directories for a specific pid and module name and return as list of dict.

    Keyword arguments:
    pid -- int: the process identifier (pid) when reading process virtual memory.
    module_name -- str: name of the module to retrieve.
    return -- list: of dict of data direcories information.
    
    Example:
    VmmPy_ProcessGetDirectories(332, "cmd.exe") --> [{'i': 0, 'size': 0, 'offset': 0, 'name': 'EXPORT'},  ... ]
    """
    return VMMPYC_ProcessGetDirectories(pid, module_name)



def VmmPy_ProcessGetSections(pid, module_name):
    """Retrieve the sections for a specific pid and module name and return as list of dict.

    Keyword arguments:
    pid -- int: the process identifier (pid) when reading process virtual memory.
    module_name -- str: name of the module to retrieve.
    return -- list: of dict of section information.
    
    Example:
    VmmPy_ProcessGetSections(332, "cmd.exe") --> [{'i': 0, 'Characteristics': 1610612768, 'misc-PhysicalAddress': 183592, 'misc-VirtualSize': 183592, 'Name': '.text', 'NumberOfLinenumbers': 0, 'NumberOfRelocations': 0, 'PointerToLinenumbers': 0, 'PointerToRawData': 1024, 'PointerToRelocations': 0, 'SizeOfRawData': 183808, 'VirtualAddress': 4096},  ... ]
    """
    return VMMPYC_ProcessGetSections(pid, module_name)



#------------------------------------------------------------------------------
# VmmPy VFS (Virtual File System) FUNCTIONALITY BELOW:
#------------------------------------------------------------------------------
def VmmPy_VfsList(path):
    """Retrieve a Virtual File System directory listing a path and return it.

    Keyword arguments:
    path -- str: the directory path.
    return -- dict: of dict of file/directory names.
    
    Example:
    VmmPy_VfsList("/") --> {'pmem' : {'size': 247078670, 'f_isdir': False}, ...}
    """
    path = path.replace('/', '\\')
    return VMMPYC_VfsList(path)



def VmmPy_VfsRead(path_file, length, offset = 0):
    """Read a Virtual File System file.

    Keyword arguments:
    path_file -- str: the file path including the file name.
    length -- int: the amount of bytes to read.
    offset -- int: start reading from this offset.
    return -- bytes: the read data.
    
    Example:
    VmmPy_VfsRead("/pmem", 0x1000, 0x10000000) --> b'000032040234023400 ...'
    """
    path_file = path_file.replace('/', '\\')
    return VMMPYC_VfsRead(path_file, length, offset)



def VmmPy_VfsWrite(path_file, bytes_data, offset = 0):
    """Write to Virtual File System file.

    Keyword arguments:
    path_file -- str: the file path including the file name.
    bytes_data -- bytes: the data to write.
    offset -- int: start writing from this offset.
    
    Example:
    VmmPy_VfsWrite("/pmem", b'000000011122', 0x2000)
    """
    path_file = path_file.replace('/', '\\')
    VmmPy_VfsWrite(path_file, bytes_data, offset)


#------------------------------------------------------------------------------
# VmmPy WINDOWS ONLY FUNCTIONALITY BELOW:
#------------------------------------------------------------------------------

def VmmPy_WinGetThunkInfoEAT(pid, module_name, exported_function):
    """Retrieve information about a single export address table (EAT) entry. This may be useful for hooking.

    Keyword arguments:
    pid -- int: the process identifier (pid) when reading process virtual memory.
    module_name -- str: name of the module to retrieve.
    exported_function -- str: name of the exported function to retrieve.
    return -- dict: information about the EAT entry.

    Example:
    VmmPy_WinGetThunkInfoEAT(4, 'ntoskrnl.exe', 'KeGetCurrentIrql') --> {'vaFunction': 18446735288139539584, 'valueThunk': 1479808, 'vaNameFunction': 18446735288147899428, 'vaThunk': 18446735288147849312}
    """
    return VMMPYC_WinGetThunkInfoEAT(pid, module_name, exported_function)



def VmmPy_WinGetThunkInfoIAT(pid, module_name, imported_module_name, imported_module_function):
    """Retrieve information about a single import address table (IAT) entry. This may be useful for hooking.

    Keyword arguments:
    pid -- int: the process identifier (pid) when reading process virtual memory.
    module_name -- str: name of the module to retrieve.
    imported_module_name -- str: name of the imported module to retrieve.
    imported_module_function -- str: name of the imported function to retrieve.
    return -- dict: information about the IAT entry.

    Example:
    VmmPy_WinGetThunkInfoIAT(4, 'ntoskrnl.exe', 'hal.dll', 'HalSendNMI') --> {'32': False, 'vaFunction': 18446735288149190896, 'vaNameFunction': 18446735288143568050, 'vaNameModule': 18446735288143568362, 'vaThunk': 18446735288143561136}
    """
    return VMMPYC_WinGetThunkInfoIAT(pid, module_name, imported_module_name, imported_module_function)



def VmmPy_WinDecompressPage(va_compressed, len_compressed = 0):
    """Decompress a page stored in the MemCompression process in Windows 10.

    Keyword arguments:
    va_compressed -- int: the virtual address inside 'MemCompression' where the compressed buffer starts.
    len_compressed -- int: optional length of the compressed buffer (leave out for auto-detect).
    return -- dict: containing decompressed data and size of compressed buffer.

    Example:
    VmmPy_WinDecompressPage(0x00000210bfb40000) --> {'c': 456, 'b': b'...'}
    """
    return VMMPYC_WinMemCompression_DecompressPage(va_compressed, len_compressed)



#------------------------------------------------------------------------------
# VmmPy UTIL FUNCTIONALITY BELOW:
#------------------------------------------------------------------------------

def VmmPy_UtilFillHexAscii(data_bytes, cb_initial_offset = 0):
    """Fill a human readable hex ascii memory dump string given a bytes object.

    Keyword arguments:
    data_bytes -- bytes: binary data to convert.
    cb_initial_offset -- int: offset, must be max 0x1000 and multiple of 0x10.
    return -- str: human readable dump-data.
    """
    return VMMPYC_UtilFillHexAscii(data_bytes, cb_initial_offset)


