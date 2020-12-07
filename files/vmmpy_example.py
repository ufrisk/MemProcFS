# vmmpy_example.py
#
# Example showcase file displaying how it is possible to interface the Memory
# Process File System / Virtual Memory Manager - VMM.DLL / VmmPy / VmmPyC with
# user created python programs.
#
# Requirement: Memory Dump file from Windows 7 x64 or later with a logged in
# user that have the process 'explorer.exe' running.
#
# To start example run:
#    from vmmpy_example import *
#    VmmPy_Example(["-device", <filename_of_windows_memory_dump_file>"])
# where <filename_of_windows_memory_dump_file> is the file name and path of a
# Windows dump file of a Windows operating system. You may also run the test
# cases against live FPGA memory with example run:
#    from vmmpy_example import *
#    VmmPy_Example(["-device", "fpga", "-memmap", "auto")
#
#
#
# https://github.com/ufrisk/
#
# (c) Ulf Frisk, 2018-2020
# Author: Ulf Frisk, pcileech@frizk.net
#

from vmmpy import *
from io import BytesIO


# Examples:
#
# VmmPy_Example(["-device", "c:\\dumps\\WIN7-X64-SP1-1.pmem"])
# VmmPy_Example(["-device", "fpga", "-memmap", "auto"])

def VmmPy_Example(args):
    print("--------------------------------------------------------------------")
    print("Welcome to the VmmPy Example showcase / test cases. This will demo  ")
    print("how it is possible to use VmmPy to access memory dump files in a    ")
    print("convenient way. Please ensure that the VmmPy requirements about the ")
    print("python version (64-bit Python Windows version 3.6 or later) is met  ")
    print("before starting ...                                                 ")

    # INIITALIZE
    print("--------------------------------------------------------------------")
    print("Initialize VmmPy with the dump file specified.                      ")
    input("Press Enter to continue...")
    print("CALL: VmmPy_Initialize()")
    VmmPy_Initialize(args)
    print("SUCCESS: VmmPy_Initialize()")

    # GET CONFIG
    print("--------------------------------------------------------------------")
    print("Retrieve configuration value for: VMMPY_OPT_CORE_MAX_NATIVE_ADDRESS.")
    input("Press Enter to continue...")
    print("CALL: VmmPy_ConfigGet()")
    result = VmmPy_ConfigGet(VMMPY_OPT_CORE_MAX_NATIVE_ADDRESS)
    print("SUCCESS: VmmPy_ConfigGet()")
    print(result)

    # SET CONFIG
    print("--------------------------------------------------------------------")
    print("Set configuration value for: VMMPY_OPT_CORE_PRINTF_ENABLE.          ")
    input("Press Enter to continue...")
    print("CALL: VmmPy_ConfigSet()")
    VmmPy_ConfigSet(VMMPY_OPT_CORE_PRINTF_ENABLE, 1)
    print("SUCCESS: VmmPy_ConfigSet()")

    # MEM READ
    print("--------------------------------------------------------------------")
    print("Read 0x100 bytes of memory from the physical address 0x1000         ")
    input("Press Enter to continue...")
    print("CALL: VmmPy_MemRead()")
    result = VmmPy_MemRead(-1, 0x1000, 0x100)
    print("SUCCESS: VmmPy_MemRead()")
    print(result)

    # MEM READ + FillHexAscii
    print("--------------------------------------------------------------------")
    print("Read 0x100 bytes of memory from the physical address 0x1000         ")
    input("Press Enter to continue...")
    print("CALL: VMMPYC_UtilFillHexAscii(VmmPy_MemRead())")
    result = VmmPy_UtilFillHexAscii(VmmPy_MemRead(-1, 0x1000, 0x100))
    print("SUCCESS: VMMPYC_UtilFillHexAscii(VmmPy_MemRead())")
    print(result)

    # MEM READ SCATTER
    print("--------------------------------------------------------------------")
    print("Read 2 non-contigious (scatter) memory from the physical addresses: ")
    print("0x1000 and 0x3000.                                                  ")
    input("Press Enter to continue...")
    print("CALL: VmmPy_MemReadScatter()")
    result = VmmPy_MemReadScatter(-1, [0x1000, 0x3000])
    print("SUCCESS: VmmPy_MemReadScatter()")
    print(result)

    # PID
    print("--------------------------------------------------------------------")
    print("Retrieve the process identifier pid for the process 'explorer.exe'. ")
    input("Press Enter to continue...")
    print("CALL: VmmPy_PidGetFromName()")
    result = VmmPy_PidGetFromName("explorer.exe")
    print("SUCCESS: VmmPy_PidGetFromName()")
    print(result)
    pid = result

    # PIDs
    print("--------------------------------------------------------------------")
    print("List the process identifier pids of the processes in the system.    ")
    input("Press Enter to continue...")
    print("CALL: VmmPy_PidList()")
    result = VMMPYC_PidList()
    print("SUCCESS: VmmPy_PidList()")
    print(result)

    # PROCESS INFORMATION GET
    print("--------------------------------------------------------------------")
    print("Get the process information about the earlier explorer.exe process. ")
    input("Press Enter to continue...")
    print("CALL: VmmPy_ProcessGetInformation()")
    result = VmmPy_ProcessGetInformation(pid)
    print("SUCCESS: VmmPy_ProcessGetInformation()")
    print(result)

    # PROCESS INFORMATION LIST
    print("--------------------------------------------------------------------")
    print("Get the process information for all process in a dict by pid.       ")
    input("Press Enter to continue...")
    print("CALL: VmmPy_ProcessListInformation()")
    result = VmmPy_ProcessListInformation()
    print("SUCCESS: VmmPy_ProcessListInformation()")
    print(result)

    # PTE MEM MAP
    print("--------------------------------------------------------------------")
    print("Get the PTE memory map of 'explorer.exe' by walking the page table. ")
    input("Press Enter to continue...")
    print("CALL: VmmPy_ProcessGetPteMap()")
    result = VmmPy_ProcessGetPteMap(pid, True)
    print("SUCCESS: VmmPy_ProcessGetPteMap()")
    print(result)

    # VAD MEM MAP
    print("--------------------------------------------------------------------")
    print("Get the VAD memory map of 'explorer.exe' by looking at VADs         ")
    input("Press Enter to continue...")
    print("CALL: VmmPy_ProcessGetVadMap()")
    result = VmmPy_ProcessGetVadMap(pid, True)
    print("SUCCESS: VmmPy_ProcessGetVadMap()")
    print(result)

    # MODULE INFORMATION
    print("--------------------------------------------------------------------")
    print("Get module information about the explorer.exe module in the process.")
    input("Press Enter to continue...")
    print("CALL: VmmPy_ProcessGetModuleFromName()")
    result = VmmPy_ProcessGetModuleFromName(pid, "explorer.exe")
    print("SUCCESS: VmmPy_ProcessGetModuleFromName()")
    print(result)
    va = result['va']

    # UNLOADED MODULE MAP
    print("--------------------------------------------------------------------")
    print("Get unloaded module information about the explorer.exe process.     ")
    input("Press Enter to continue...")
    print("CALL: VmmPy_ProcessGetUnloadedModuleMap()")
    result = VmmPy_ProcessGetUnloadedModuleMap(pid)
    print("SUCCESS: VmmPy_ProcessGetUnloadedModuleMap()")
    print(result)

    # HEAP MAP
    print("--------------------------------------------------------------------")
    print("Get the HEAP map of 'explorer.exe'                                  ")
    input("Press Enter to continue...")
    print("CALL: VmmPy_ProcessGetHeapMap()")
    result = VmmPy_ProcessGetHeapMap(pid)
    print("SUCCESS: VmmPy_ProcessGetHeapMap()")
    print(result)

    # THREAD MAP
    print("--------------------------------------------------------------------")
    print("Get the THREAD map of 'explorer.exe' by walking ETHREAD list        ")
    input("Press Enter to continue...")
    print("CALL: VmmPy_ProcessGetThreadMap()")
    result = VmmPy_ProcessGetThreadMap(pid)
    print("SUCCESS: VmmPy_ProcessGetThreadMap()")
    print(result)

    # HANDLE MAP
    print("--------------------------------------------------------------------")
    print("Get the HANDLE map of 'explorer.exe'                                ")
    input("Press Enter to continue...")
    print("CALL: VmmPy_ProcessGetHandleMap()")
    result = VmmPy_ProcessGetHandleMap(pid)
    print("SUCCESS: VmmPy_ProcessGetHandleMap()")
    print(result)

    # USER MAP
    print("--------------------------------------------------------------------")
    print("Get the USER map of logged on non well known users.                 ")
    input("Press Enter to continue...")
    print("CALL: VmmPy_GetUsers()")
    result = VmmPy_GetUsers()
    print("SUCCESS: VmmPy_GetUsers()")
    print(result)

    # SERVICE MAP
    print("--------------------------------------------------------------------")
    print("Retrieve services from the service control manager (SCM).           ")
    input("Press Enter to continue...")
    print("CALL: VmmPy_MapGetServices()")
    result = VmmPy_MapGetServices()
    print("SUCCESS: VmmPy_MapGetServices()")
    print(result)

    # MEM VIRTUAL2PHYSICAL
    print("--------------------------------------------------------------------")
    print("Get physical address of the PE virtual address of 'explorer.exe'.   ")
    input("Press Enter to continue...")
    print("CALL: VmmPy_MemVirt2Phys()")
    result = VmmPy_MemVirt2Phys(pid, va)
    print("SUCCESS: VmmPy_MemVirt2Phys()")
    print(result)

    # MEM READ
    print("--------------------------------------------------------------------")
    print("Read 0x100 bytes of memory from 'explorer.exe' PE base.             ")
    input("Press Enter to continue...")
    print("CALL: VmmPy_MemRead()")
    result = VmmPy_UtilFillHexAscii(VmmPy_MemRead(pid, va, 0x100))
    print("SUCCESS: VmmPy_MemRead()")
    print(result)

    # PE EAT
    print("--------------------------------------------------------------------")
    print("Get the Export Address Table given 'explorer.exe'/'kernel32.dll'    ")
    input("Press Enter to continue...")
    print("CALL: VmmPy_ProcessGetEAT()")
    result = VmmPy_ProcessGetEAT(pid, "kernel32.dll")
    print("SUCCESS: VmmPy_ProcessGetEAT()")
    print(result)

    # PE IAT
    print("--------------------------------------------------------------------")
    print("Get the Import Address Table given 'explorer.exe'/'kernel32.dll'    ")
    input("Press Enter to continue...")
    print("CALL: VmmPy_ProcessGetIAT()")
    result = VmmPy_ProcessGetIAT(pid, "kernel32.dll")
    print("SUCCESS: VmmPy_ProcessGetIAT()")
    print(result)

    # PE DATA DIRECTORIES
    print("--------------------------------------------------------------------")
    print("Get the PE Data Directories from 'explorer.exe'/'kernel32.dll'      ")
    input("Press Enter to continue...")
    print("CALL: VmmPy_ProcessGetDirectories()")
    result = VmmPy_ProcessGetDirectories(pid, "kernel32.dll")
    print("SUCCESS: VmmPy_ProcessGetDirectories()")
    print(result)

    # PE SECTIONS
    print("--------------------------------------------------------------------")
    print("Get the PE Data Directories from 'explorer.exe'/'kernel32.dll'      ")
    input("Press Enter to continue...")
    print("CALL: VmmPy_ProcessGetSections()")
    result = VmmPy_ProcessGetSections(pid, "kernel32.dll")
    print("SUCCESS: VmmPy_ProcessGetSections()")
    print(result)

    # LIST REGISTRY HIVES
    print("--------------------------------------------------------------------")
    print("List the registry hives                                             ")
    input("Press Enter to continue...")
    print("CALL: VmmPy_WinReg_HiveList()")
    result = VmmPy_WinReg_HiveList()
    print("SUCCESS: VmmPy_WinReg_HiveList()")
    print(result)

    # READ REGISTRY RAW HIVE DATA
    print("--------------------------------------------------------------------")
    print("Read 0x100 bytes from registry hive memory space address 0x1000     ")
    input("Press Enter to continue...")
    if(len(result) > 0):
        print("CALL: VmmPy_WinReg_HiveRead(%s, 0x1000, 0x100)" % (result[0]['va_hive']))
        result = VmmPy_UtilFillHexAscii(VmmPy_WinReg_HiveRead(result[0]['va_hive'], 0x1000, 0x100))
        print("SUCCESS: VmmPy_WinReg_HiveRead()")
        print(result)
    else:
        print("FAIL: No registry hives read from VmmPy_WinReg_HiveList()")

    # Retrieve PHYSICAL MEMORY MAP
    print("--------------------------------------------------------------------")
    print("Retrieve physical memory map                                        ")
    input("Press Enter to continue...")
    print("CALL: VmmPy_MapGetPhysMem()")
    result = VmmPy_MapGetPhysMem()
    print("SUCCESS: VmmPy_MapGetPhysMem()")
    print(result)

    # Retrieve PFNs (page frame numbers).
    print("--------------------------------------------------------------------")
    print("Retrieve PFNs (page frame numbers)                                  ")
    input("Press Enter to continue...")
    print("CALL: VmmPy_MapGetPfns([1, 0x123456, 0x58f4c])")
    result = VmmPy_MapGetPfns([1, 0x123456, 0x58f4c])
    print("SUCCESS: VmmPy_MapGetPfns([1, 0x123456, 0x58f4c])")
    print(result)

    # INITIALIZE PLUGIN MANAGER (REQUIRED BY VFS)
    print("--------------------------------------------------------------------")
    print("Initialize plugin functionality - required by virtual file system   ")
    input("Press Enter to continue...")
    print("CALL: VmmPy_Initialize_Plugins()")
    VmmPy_Initialize_Plugins()
    print("SUCCESS: VmmPy_Initialize_Plugins()")

    # VFS LIST /
    # NB! VmmPy_Initialize_Plugins() must be called prior to VmmPy_VfsList()
    print("--------------------------------------------------------------------")
    print("Retrieve the file list of the virtual file system from the root path")
    input("Press Enter to continue...")
    print("CALL: VmmPy_VfsList()")
    result = VmmPy_VfsList('/')
    print("SUCCESS: VmmPy_VfsList()")
    print(result)

    # VFS LIST /name
    # NB! VmmPy_Initialize_Plugins() must be called prior to VmmPy_VfsList()
    print("--------------------------------------------------------------------")
    print("Retrieve the file list of the virtual file system from the name path")
    input("Press Enter to continue...")
    print("CALL: VmmPy_VfsList()")
    result = VmmPy_VfsList('/name')
    print("SUCCESS: VmmPy_VfsList()")
    print(result)

    # VFS READ
    # NB! VmmPy_Initialize_Plugins() must be called prior to VmmPy_VfsRead()
    print("--------------------------------------------------------------------")
    print("Read from a file in the virtual file system (/memory.pmem at offset 0x1000)")
    input("Press Enter to continue...")
    print("CALL: VmmPy_VfsRead()")
    result = VmmPy_UtilFillHexAscii(VmmPy_VfsRead('/memory.pmem', 0x100, 0x1000))
    print("SUCCESS: VmmPy_VfsRead()")
    print(result)

    # EXIT
    input("Press enter to exit (examples finished)...")
