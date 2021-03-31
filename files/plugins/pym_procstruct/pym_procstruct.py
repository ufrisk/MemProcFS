# pym_procstruct.py
#
# Example python plugin module for the memory process file system. This module
# shows how it is possible to display files in the file system and implement
# Read and Write functionality for the files.
#
# The module displays binary and hexascii versions of EPROCESS and PEB in the
# 'py/procstruct' directory.
#
# https://github.com/ufrisk/
#
# (c) Ulf Frisk, 2018-2021
# Author: Ulf Frisk, pcileech@frizk.net
#

import memprocfs
from vmmpyplugin import *

procstruct_eprocess_size_bin = 0x880
procstruct_eprocess_size_hex = 0
procstruct_peb_size_bin = 0x1000
procstruct_peb_size_hex = 0
procstruct_cache_proc_wow64 = {}

def ReadEPROCESS_Binary(pid, file_path, file_name, file_attr, bytes_length, bytes_offset):
    #
    # Read binary data from the EPROCESS file that the List function put into
    # the VmmPyPlugin file list.
    #
    # Since this function was only put into the VmmPyPlugin file list for this
    # specific file no extra checks have to be made on pid (which could be none
    # if this plugin would have registered the file entry as a root file -
    # which it did not). Neither does the file_name need to be checked since
    # this is the only file that will call this read function.
    #
    # The plugin manager also checks that bytes_length and bytes_offset does
    # not exceed the file size that is registered in the plugin manager - if
    # it does they are automatically adjusted - so no need to check those for
    # validity either.
    #
    # Start by retriving the process object and then the eprocess attribute:
    va_eprocess = vmm.process(pid).eprocess
    # Read the amount of bytes from virtual memory with the specified offset.
    # Since EPROCESS resides in kernel memory (which is mapped into process
    # address space as supervisor only memory, but is filtered out by the
    # VMM) it is necessary to read it from the SYSTEM process - i.e. pid 4.
    memory_data = vmm.kernel.process.memory.read(va_eprocess + bytes_offset, bytes_length)
    # The read memory data should be of the correct size and correct offset,
    # and it's also already of the bytes data type - so just return it and
    # finish with the read!
    return memory_data



def ReadEPROCESS_Hexdump(pid, file_path, file_name, file_attr, bytes_length, bytes_offset):
    # Read the binary data required for the EPROCESS struct by calling the
    # function ReadEPROCESS_Binary which already does this very conveniently.
    memory_data = ReadEPROCESS_Binary(pid, file_path, file_name, file_attr, bytes_length, bytes_offset)
    # Translate the binary data into hexascii memory dump format by calling
    # the VmmPy_UtilFillHexAscii function.
    hexdump_string = vmm.hex(memory_data)
    # Convert from string into bytes using ascii encoding.
    hexdump_binary = bytes(hexdump_string, 'ascii')
    # return the data that should be read as a bytes object.
    return hexdump_binary[bytes_offset:bytes_length+bytes_offset]



def WriteEPROCESS_Binary(pid, file_path, file_name, file_attr, bytes_data, bytes_offset):
    # Write binary data to the EPROCESS struct in kernel memory.
    #
    # Since the List function only registered this function with one file which
    # is in a process directory we do not need to check pid, file_name and
    # bytes_offset since thise are all verified by the plugin manager.
    #
    # Start by retriving the process object and then the eprocess attribute:
    va_eprocess = vmm.process(pid).eprocess
    # Now all data which is required to make a write exists! Perform the write!
    vmm.kernel.process.write(va_eprocess+bytes_offset, bytes_data)
    return memprocfs.STATUS_SUCCESS



def ReadPEB_Binary(pid, file_path, file_name, file_attr, bytes_length, bytes_offset):
    #
    # Read binary data from the PEB page. This is a compact version of the
    # Read function. Please see ReadEPROCESS_Binary for a detailed description
    #
    process = vmm.process(pid)
    if '32' in file_name:
        va_peb = process.peb32
    else:
        va_peb = process.peb
    return process.memory.read(va_peb + bytes_offset, bytes_length)



def ReadPEB_Hexdump(pid, file_path, file_name, file_attr, bytes_length, bytes_offset):
    #
    # Read hexascii data from the PEB page. This is a compact version of the
    # Read function. Please see ReadEPROCESS_Hexdump for a detailed description
    #
    memory_data = ReadPEB_Binary(pid, file_path, file_name, file_attr, bytes_length, bytes_offset)
    hexdump_string = vmm.hex(memory_data)
    return bytes(hexdump_string, 'ascii')[bytes_offset:bytes_length+bytes_offset]



def WritePEB_Binary(pid, file_path, file_name, file_attr, bytes_data, bytes_offset):
    #
    # Write binary data to the PEB page. This is a compact version of the
    # Write function. Please see WritePEB_Binary for a detailed description
    #
    process = vmm.process(pid)
    if '32' in file_name:
        va_peb = process.peb32
    else:
        va_peb = process.peb
    process.write(va_peb+bytes_offset, bytes_data)
    return memprocfs.STATUS_SUCCESS



def IsProcessPeb6432(pid):
    #
    # Check if the pid is a regular process with a PEB at all or if it's a special
    # process like 'System' without a PEB. Also check whether a 32-bit PEB exists
    # or not (wow64 process).
    # Also employ a small caching functionality.
    #
    if pid in procstruct_cache_proc_wow64:
        return procstruct_cache_proc_wow64[pid]
    process = vmm.process(pid)
    if(process.state != 0):
        result = False, False
    else:
        result = process.peb > 0, process.peb32 > 0
    procstruct_cache_proc_wow64[pid] = result
    return result



def List(pid, path):
    #
    # List function - this module employs a dynamic list function - which makes
    # it responsible for providing directory listings of its contents in a
    # highly optimized way. It is very important that the List function is as
    # speedy as possible - to avoid locking up the file system.
    #
    # First check the directory to be listed. Only the module root directory is
    # allowed. If it's not the module root directory return None.
    if path != 'procstruct':
        return None
    # Populate the 'common' files which are always in the module directory
    # below. Both binary and hexdump/hexascii versions are populated.
    result = {
        'eprocess.bin': {'size': procstruct_eprocess_size_bin, 'read': ReadEPROCESS_Binary, 'write': WriteEPROCESS_Binary},
        'eprocess.txt': {'size': procstruct_eprocess_size_hex, 'read': ReadEPROCESS_Hexdump, 'write': None}
        }
    # Populate PEB (if it exists), it almost always do, but there may be
    # some special processes like 'System', 'Registry' and so on that only
    # exist in kernel space without a PEB...
    fPeb64, fPeb32 = IsProcessPeb6432(pid)
    if fPeb64:
        result['peb.bin'] = {'size': procstruct_peb_size_bin, 'read': ReadPEB_Binary, 'write': WritePEB_Binary}
        result['peb.txt'] = {'size': procstruct_peb_size_hex, 'read': ReadPEB_Hexdump, 'write': None}
    # Optionally populate 32-bit PEBs into the directory listings if a 32-bit
    # process is to be listed.
    if fPeb32:
        result['peb32.bin'] = {'size': procstruct_peb_size_bin, 'read': ReadPEB_Binary, 'write': WritePEB_Binary}
        result['peb32.txt'] = {'size': procstruct_peb_size_hex, 'read': ReadPEB_Hexdump, 'write': None}
    return result



def Close():
    # Nothing to clean up here for this plugin -> do nothing!
    pass



def Initialize(target_system, target_memorymodel):
    # Check that the operating system is 32-bit or 64-bit Windows. If it's not
    # then raise an exception to terminate loading of this module.
    if target_system != memprocfs.SYSTEM_WINDOWS_X64 and target_system != memprocfs.SYSTEM_WINDOWS_X86:
        raise RuntimeError("Only Windows is supported by the pym_procstruct module.")
    # Calculate the size of the 'eprocess_size_hex' global variable. This is
    # only done once - at module instantiation to speed up the list operation.
    global procstruct_eprocess_size_hex
    procstruct_eprocess_size_hex = len(vmm.hex(bytes(procstruct_eprocess_size_bin)))
    # Calculate the size of the 'PEB page'
    global procstruct_peb_size_hex
    procstruct_peb_size_hex = len(vmm.hex(bytes(procstruct_peb_size_bin)))
    # Register a directory with the VmmPyPlugin plugin manager. The directory
    # is a non-root (i.e. a process) directory and have a custom List function.
    VmmPyPlugin_FileRegisterDirectory(True, 'procstruct', List)
