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
# (c) Ulf Frisk, 2018-2023
# Author: Ulf Frisk, pcileech@frizk.net
#

import memprocfs
import time
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

    # MEM READ (MULTIPLE) + FillHexAscii
    print("--------------------------------------------------------------------")
    print("Read multiple chunks of physical memory at the same time using an   ")
    print("efficient 'scatter read'. Also disallow using the built-in cache.   ")
    print("2 chunks are read: 0x100 bytes from 0x1000, 0x80 bytes from 0x3000  ")
    input("Press Enter to continue...")
    print("CALL: vmm.hex(vmm.memory.read())")
    result = vmm.memory.read([[0x1000, 0x100], [0x3000, 0x80]], memprocfs.FLAG_NOCACHE)
    print("SUCCESS: vmm.hex(vmm.memory.read()[0])")
    print(vmm.hex(result[0]))
    print("SUCCESS: vmm.hex(vmm.memory.read()[1])")
    print(vmm.hex(result[1]))

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

    # MEM READ (MULTIPLE)
    print("--------------------------------------------------------------------")
    print("Read multiple chunks of virtual memory at the same time using an    ")
    print("efficient 'scatter read'. Also disallow using the built-in cache.   ")
    print("read chunks: 8 bytes at PE_BASE and 0x10 bytes at PE_BASE+0x3000.   ")
    input("Press Enter to continue...")
    print("CALL: vmm.hex(process_explorer.memory.read())")
    result = process_explorer.memory.read([[module_explorer.base, 8], [module_explorer.base+0x3000, 0x10]], memprocfs.FLAG_NOCACHE)
    print("SUCCESS: process_explorer.memory.read()")
    print(result)

    # MEM READ NATIVE TYPE (SINGLE)
    print("--------------------------------------------------------------------")
    print("Read a native type and return its corresponding Python type.        ")
    print("Supported types: i8, u8, i16, u16, f32, i32, u64, f64, i64, u64     ")
    input("Press Enter to continue...")
    print("CALL: vmm.hex(process_explorer.memory.read_type())")
    result = process_explorer.memory.read_type(module_explorer.base, 'u16')
    print("SUCCESS: process_explorer.memory.read_type()")
    print(result)

    # MEM READ NATIVE TYPE (MULTIPLE)
    print("--------------------------------------------------------------------")
    print("Read multiple native types and return corresponding Python types.   ")
    print("Supported types: i8, u8, i16, u16, f32, i32, u64, f64, i64, u64     ")
    input("Press Enter to continue...")
    print("CALL: vmm.hex(process_explorer.memory.read_type())")
    result = process_explorer.memory.read_type([[module_explorer.base, 'u16'], [module_explorer.base + 0x100, 'u64']], memprocfs.FLAG_NOCACHE)
    print("SUCCESS: process_explorer.memory.read_type()")
    print(result)

    # MEM READ NEW SCATTER
    print("--------------------------------------------------------------------")
    print("Read multiple memory regions at the same time using a scatter memory")
    print("approach as follows:                                                ")
    print("   1. Initialize the scatter object.                                ")
    print("   2. Prepare multiple ranges for reading.                          ")
    print("   3. Execute the read underlying read, performing io operations.   ")
    print("   4. Read the results from the scatter object.                     ")
    print("   5. Close the scatter object, alternatively clear it for re-use.  ")
    input("Press Enter to continue...")
    print("CALL: process_explorer.memory.read_scatter_initialize()")
    scatter = process_explorer.memory.scatter_initialize(memprocfs.FLAG_NOCACHE)
    print("CALL: scatter.prepare() - SINGLE")
    scatter.prepare(module_explorer.base, 0x100)
    print("CALL: scatter.prepare() - MULTIPLE")
    scatter.prepare([[module_explorer.base, 0x100], [module_explorer.base+0x1000, 0x100]])
    print("CALL: scatter.execute()")
    scatter.execute()
    print("CALL: scatter.read() - SINGLE")
    result = scatter.read(module_explorer.base, 0x10)
    print(result)
    print("CALL: scatter.read() - MULTIPLE")
    result = scatter.read([[module_explorer.base, 8], [module_explorer.base+0x1000, 0x10]])
    print(result)
    # NB! scatter.execute() may be called here to re-read the prepared regions.
    # NB! scatter.clear() may be called here to clear the scatter object for re-use.
    # NB! scatter.close() may be called here to close the scatter object, this is
    #     not required as the object will be cleaned up when it goes out of scope.

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

    # SEARCH PE HEADERS AT START-OF-PAGE (0x1000 aligned) IN VIRTUAL MEMORY USING BINARY SEARCH
    # NB! it's also possible to search physical memory and search multiple terms. See documentation.
    print("--------------------------------------------------------------------")
    print("Search, using binary search, for PE headers in process virtual memory.")
    input("Press Enter to continue...")
    search_binary = process_explorer.search(0, 0xffffffffffffffff, memprocfs.FLAG_NOCACHE)
    search_binary.add_search(b'PE',b'\x00\x00',0x1000)
    search_binary.start()
    while not search_binary.is_completed:
        print("current address: %x" % (search_binary.addr_current))
        print(search_binary.poll())
        time.sleep(0.1)
    print("SUCCESS: search results:")
    print("current address: %x" % (search_binary.addr_current))
    print(search_binary.result())

    # SEARCH PE HEADERS AT START-OF-PAGE (0x1000 aligned) IN VIRTUAL MEMORY USING YARA SEARCH
    # This demonstrates how it's possible to use in-memory YARA rules to search for PE headers.
    # It's using the blocking result() method, which will block until the search is completed.
    # It's also possible to use yara file rules by specifying the path. Also it's possible to
    # use the poll() pattern to poll an ongoing search (as demonstrated in the binary search example).
    print("--------------------------------------------------------------------")
    print("Search, using binary search, for PE headers in process virtual memory.")
    input("Press Enter to continue...")
    yara_rule_1 = " rule mz_header { strings: $mz = \"MZ\" condition: $mz at 0 } "
    search_yara = process_explorer.search_yara([yara_rule_1])
    print(search_yara.result())
    print("current address: %x" % (search_yara.addr_current))




    # EXIT
    input("Press enter to exit (examples finished)...")
