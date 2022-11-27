# memprocfs_example.py
#
# Example showcase file displaying how it is possible to interface with
# MemProcFS from user created python programs.
#
# API reference: https://github.com/ufrisk/MemProcFS/wiki/API_Python
# 
# Requirement: Memory Dump file from Windows 7 x64 or later with a logged in
# user that have the process 'explorer.exe' running.
#
# To start example run:
#    from memprocfs_example import *
#    MemProcFS_Example(["-device", "<filename_of_windows_memory_dump_file>"])
# where <filename_of_windows_memory_dump_file> is the file name and path of a
# Windows dump file of a Windows operating system. You may also run the test
# cases against live FPGA memory with example run:
#    from memprocfs_example import *
#    MemProcFS_Example(["-device", "fpga", "-memmap", "auto")
#
#
#
# https://github.com/ufrisk/
#
# (c) Ulf Frisk, 2018-2022
# Author: Ulf Frisk, pcileech@frizk.net
#

import memprocfs
from io import BytesIO


# Examples:
#
# MemProcFS_Example(["-device", "c:\\dumps\\WIN7-X64-SP1-1.pmem"])
# MemProcFS_Example(["-device", "fpga", "-memmap", "auto"])

def MemProcFS_Example(args):
    print("--------------------------------------------------------------------")
    print("Welcome to the MemProcFS example showcase / test cases. This will   ")
    print("demo how it is possible to use MemProcFS to access memory dump files")
    print("in a convenient way. Please ensure that the MemProcFS requirements  ")
    print("about python version (64-bit Python Windows version 3.6 or later) is")
    print("met before starting ...                                             ")

    # INIITALIZE
    print("--------------------------------------------------------------------")
    print("Initialize MemProcFS with the dump file specified.                  ")
    input("Press Enter to continue...")
    print("CALL: memprocfs.Vmm()")
    vmm = memprocfs.Vmm(args)
    print("SUCCESS: memprocfs.Vmm(). Handle stored in object: 'vmm'")

    # GET CONFIG
    print("--------------------------------------------------------------------")
    print("Retrieve config value for: memprocfs.OPT_CORE_MAX_NATIVE_ADDRESS.   ")
    input("Press Enter to continue...")
    print("CALL: vmm.get_config()")
    result = vmm.get_config(memprocfs.OPT_CORE_MAX_NATIVE_ADDRESS)
    print("SUCCESS: vmm.get_config()")
    print(result)

    # SET CONFIG
    print("--------------------------------------------------------------------")
    print("Set configuration value for: memprocfs.OPT_CORE_PRINTF_ENABLE.      ")
    input("Press Enter to continue...")
    print("CALL: vmm.set_config()")
    vmm.set_config(memprocfs.OPT_CORE_PRINTF_ENABLE, 1)
    print("SUCCESS: vmm.set_config()")

    # MEM READ
    print("--------------------------------------------------------------------")
    print("Read 0x100 bytes of memory from the physical address 0x1000         ")
    input("Press Enter to continue...")
    print("CALL: vmm.memory.read()")
    result = vmm.memory.read(0x1000, 0x100)
    print("SUCCESS: vmm.memory.read()")
    print(result)

    # MEM READ + FillHexAscii
    print("--------------------------------------------------------------------")
    print("Read 0x100 bytes of memory from the physical address 0x1000         ")
    input("Press Enter to continue...")
    print("CALL: vmm.hex(vmm.memory.read())")
    result = vmm.hex(vmm.memory.read(0x1000, 0x100))
    print("SUCCESS: vmm.hex(vmm.memory.read())")
    print(result)

    # MEM READ SCATTER
    print("--------------------------------------------------------------------")
    print("Read 2 non-contigious (scatter) memory from the physical addresses: ")
    print("0x1000 and 0x3000.                                                  ")
    input("Press Enter to continue...")
    print("CALL: vmm.memory.read_scatter()")
    result = vmm.memory.read_scatter([0x1000, 0x3000])
    print("SUCCESS: vmm.memory.read_scatter()")
    print(result)

    # USER MAP
    print("--------------------------------------------------------------------")
    print("Get the USER map of logged on non well known users.                 ")
    input("Press Enter to continue...")
    print("CALL: vmm.maps.user()")
    result = vmm.maps.user()
    print("SUCCESS: vmm.maps.user()")
    print(result)

    # SERVICE MAP
    print("--------------------------------------------------------------------")
    print("Retrieve services from the service control manager (SCM).           ")
    input("Press Enter to continue...")
    print("CALL: vmm.maps.service()")
    result = vmm.maps.service()
    print("SUCCESS: vmm.maps.service()")
    print(result)

    # PROCESS
    print("--------------------------------------------------------------------")
    print("Retrieve the process object for 'explorer.exe'.                     ")
    input("Press Enter to continue...")
    print("CALL: vmm.process()")
    process_explorer = vmm.process("explorer.exe")
    print("SUCCESS: vmm.process(). Handle stored in object: 'process_explorer'")
    print(process_explorer)

    # PROCESS INFORMATION
    print("--------------------------------------------------------------------")
    print("Print some information about the explorer process.                  ")
    input("Press Enter to continue...")
    print("process full name:   " + process_explorer.fullname)
    print("process path kernel: " + process_explorer.pathkernel)
    print("process token SID:   " + process_explorer.sid)
    print("process parent PID:  " + str(process_explorer.ppid))

    # PROCESS ALL
    print("--------------------------------------------------------------------")
    print("List the process objects of the processes in the system.            ")
    input("Press Enter to continue...")
    print("CALL: vmm.process_list()")
    result = vmm.process_list()
    print("SUCCESS: vmm.process_list()")
    print(result)

    # PTE MEM MAP
    print("--------------------------------------------------------------------")
    print("Get the PTE memory map of 'explorer.exe' by walking the page table. ")
    input("Press Enter to continue...")
    print("CALL: process_explorer.maps.pte()")
    result = process_explorer.maps.pte(True)
    print("SUCCESS: process_explorer.maps.pte()")
    print(result)

    # VAD MEM MAP
    print("--------------------------------------------------------------------")
    print("Get the VAD memory map of 'explorer.exe'                            ")
    input("Press Enter to continue...")
    print("CALL: process_explorer.maps.pte()")
    result = process_explorer.maps.pte(True)
    print("SUCCESS: process_explorer.maps.pte()")
    print(result)

    # HEAP MAP
    print("--------------------------------------------------------------------")
    print("Get the HEAP map of 'explorer.exe'                                  ")
    input("Press Enter to continue...")
    print("CALL: process_explorer.maps.heap()")
    result = process_explorer.maps.heap()
    print("SUCCESS: process_explorer.maps.heap()")
    print(result)

    # THREAD MAP
    print("--------------------------------------------------------------------")
    print("Get the THREAD map of 'explorer.exe' by walking ETHREAD list        ")
    input("Press Enter to continue...")
    print("CALL: process_explorer.maps.thread()")
    result = process_explorer.maps.thread()
    print("SUCCESS: process_explorer.maps.thread()")
    print(result)

    # HANDLE MAP
    print("--------------------------------------------------------------------")
    print("Get the HANDLE map of 'explorer.exe'                                ")
    input("Press Enter to continue...")
    print("CALL: process_explorer.maps.handle()")
    result = process_explorer.maps.handle()
    print("SUCCESS: process_explorer.maps.handle()")
    print(result)

    # UNLOADED MODULE MAP
    print("--------------------------------------------------------------------")
    print("Get unloaded module information about the explorer.exe process.     ")
    input("Press Enter to continue...")
    print("CALL: process_explorer.maps.unloaded_module()")
    result = process_explorer.maps.unloaded_module()
    print("SUCCESS: process_explorer.maps.unloaded_module()")
    print(result)

    # MODULE INFORMATION
    print("--------------------------------------------------------------------")
    print("Get module 'explorer.exe' and 'kernel32.dll' in the process.        ")
    input("Press Enter to continue...")
    print("CALL: process_explorer.module()")
    module_explorer = process_explorer.module("explorer.exe")
    module_kernel32 = process_explorer.module("kernel32.dll")
    print("SUCCESS: process_explorer.module().                                 ")
    print("   Handles stored in object: 'module_explorer' and 'module_kernel32'")
    print(module_explorer)
    print(module_kernel32)

    # MEM VIRTUAL2PHYSICAL
    print("--------------------------------------------------------------------")
    print("Get physical address of the PE virtual address of 'explorer.exe'.   ")
    input("Press Enter to continue...")
    print("CALL: process_explorer.memory.virt2phys(()")
    result = process_explorer.memory.virt2phys(module_explorer.base)
    print("SUCCESS: process_explorer.memory.virt2phys(()")
    print(result)

    # MEM READ
    print("--------------------------------------------------------------------")
    print("Read 0x100 bytes of memory from 'explorer.exe' PE base.             ")
    input("Press Enter to continue...")
    print("CALL: process_explorer.memory.read()")
    result = vmm.hex(process_explorer.memory.read(module_explorer.base, 0x100))
    print("SUCCESS: process_explorer.memory.read()")
    print(result)

    # PE EAT
    print("--------------------------------------------------------------------")
    print("Get the Export Address Table given 'explorer.exe'/'kernel32.dll'    ")
    input("Press Enter to continue...")
    print("CALL: module_kernel32.maps.eat()")
    result = module_kernel32.maps.eat()
    print("SUCCESS: module_kernel32.maps.eat()")
    print(result)

    # PE IAT
    print("--------------------------------------------------------------------")
    print("Get the Import Address Table given 'explorer.exe'/'kernel32.dll'    ")
    input("Press Enter to continue...")
    print("CALL: module_kernel32.maps.iat()")
    result = module_kernel32.maps.iat()
    print("SUCCESS: module_kernel32.maps.iat()")
    print(result)

    # PE DATA DIRECTORIES
    print("--------------------------------------------------------------------")
    print("Get the PE Data Directories from 'explorer.exe'/'kernel32.dll'      ")
    input("Press Enter to continue...")
    print("CALL: module_kernel32.maps.directories()")
    result = module_kernel32.maps.directories()
    print("SUCCESS: module_kernel32.maps.directories()")
    print(result)

    # PE SECTIONS
    print("--------------------------------------------------------------------")
    print("Get the PE Data Directories from 'explorer.exe'/'kernel32.dll'      ")
    input("Press Enter to continue...")
    print("CALL: module_kernel32.maps.sections()")
    result = module_kernel32.maps.sections()
    print("SUCCESS: module_kernel32.maps.sections()")
    print(result)

    # LIST REGISTRY HIVES
    print("--------------------------------------------------------------------")
    print("List the registry hives                                             ")
    input("Press Enter to continue...")
    print("CALL: vmm.reg_hive_list()")
    reg_hives = vmm.reg_hive_list()
    print("SUCCESS: vmm.reg_hive_list(). Hive list stored as: 'reg_hives'")
    print(reg_hives)

    # READ REGISTRY RAW HIVE DATA
    print("--------------------------------------------------------------------")
    print("Read 0x100 bytes from registry hive memory space address 0x1000     ")
    input("Press Enter to continue...")
    if(len(reg_hives) > 0):
        print("CALL: reg_hives[0].memory.read(0x1000, 0x100)")
        result = vmm.hex( reg_hives[0].memory.read(0x1000, 0x100) )
        print("SUCCESS: reg_hives[0].memory.read(0x1000, 0x100)")
        print(result)
    else:
        print("FAIL: No registry hives read from vmm.hive_list()")

    # Retrieve PHYSICAL MEMORY MAP
    print("--------------------------------------------------------------------")
    print("Retrieve physical memory map                                        ")
    input("Press Enter to continue...")
    print("CALL: vmm.maps.memmap()")
    result = vmm.maps.memmap()
    print("SUCCESS: vmm.maps.memmap()")
    print(result)

    # Retrieve PFNs (page frame numbers).
    print("--------------------------------------------------------------------")
    print("Retrieve PFNs (page frame numbers)                                  ")
    input("Press Enter to continue...")
    print("CALL: vmm.maps.pfn([1, 0x123456, 0x58f4c])")
    result = vmm.maps.pfn([1, 0x123456, 0x58f4c])
    print("SUCCESS: vmm.maps.pfn([1, 0x123456, 0x58f4c])")
    print(result)

    # INITIALIZE PLUGIN MANAGER (REQUIRED BY VIRTUAL FILE SYSTEM - VFS)
    print("--------------------------------------------------------------------")
    print("Initialize plugin functionality - required by virtual file system   ")
    input("Press Enter to continue...")
    print("CALL: vmm.initialize_plugins()")
    vmm.initialize_plugins()
    print("SUCCESS: vmm.initialize_plugins()")

    # VFS LIST /
    # NB! vmm.initialize_plugins() must be called prior to vmm.vfs.list()
    print("--------------------------------------------------------------------")
    print("Retrieve the file list of the virtual file system from the root path")
    input("Press Enter to continue...")
    print("CALL: vmm.vfs.list()")
    result = vmm.vfs.list('/')
    print("SUCCESS: vmm.vfs.list()")
    print(result)

    # VFS LIST /name
    # NB! vmm.initialize_plugins() must be called prior to vmm.vfs.list()
    print("--------------------------------------------------------------------")
    print("Retrieve the file list of the virtual file system from the name path")
    input("Press Enter to continue...")
    print("CALL: vmm.vfs.list()")
    result = vmm.vfs.list('/name')
    print("SUCCESS: vmm.vfs.list()")
    print(result)

    # VFS READ
    # NB! vmm.initialize_plugins() must be called prior to vmm.vfs.read()
    print("--------------------------------------------------------------------")
    print("Read from a file in the virtual file system (/memory.pmem at offset 0x1000)")
    input("Press Enter to continue...")
    print("CALL: vmm.vfs.read()")
    result = vmm.hex(vmm.vfs.read('/memory.pmem', 0x100, 0x1000))
    print("SUCCESS: vmm.vfs.read()")
    print(result)

    # EXIT
    input("Press enter to exit (examples finished)...")
