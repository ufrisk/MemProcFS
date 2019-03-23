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
#    VmmPy_Example("<filename_of_windows_memory_dump_file>")
# where <filename_of_windows_memory_dump_file> is the file name and path of a
# Windows dump file of a 64-bit Windows operating system - Windows 7 or later.
#
# To start example how to conveniently parse the PE header structs by using
# the dissect.cstruct library and VmmPy please run the example:
#    from vmmpy_example import *
#    VmmPy_Example_ParsePE(<filename_of_windows_memory_dump_file>)
#
# https://github.com/ufrisk/
#
# (c) Ulf Frisk, 2018
# Author: Ulf Frisk, pcileech@frizk.net
#

from vmmpy import *
from io import BytesIO
from dissect import cstruct


# Examples:
#
# VmmPy_Example("c:\\temp\\win10.raw")
# VmmPy_Example_ParsePE("c:\\temp\\win10.raw")

def VmmPy_Example(dump_file_name):
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
    VmmPy_Initialize(["-device", dump_file_name])
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

    # MODULE INFORMATION
    print("--------------------------------------------------------------------")
    print("Get module information about the explorer.exe module in the process.")
    input("Press Enter to continue...")
    print("CALL: VmmPy_ProcessGetModuleFromName()")
    result = VmmPy_ProcessGetModuleFromName(pid, "explorer.exe")
    print("SUCCESS: VmmPy_ProcessGetModuleFromName()")
    print(result)
    va = result['va']

    # MEM MAP
    print("--------------------------------------------------------------------")
    print("Get the memory map of 'explorer.exe' by walking the page table.     ")
    input("Press Enter to continue...")
    print("CALL: VmmPy_ProcessGetMemoryMap()")
    result = VmmPy_ProcessGetMemoryMap(pid, True)
    print("SUCCESS: VmmPy_ProcessGetMemoryMap()")
    print(result)

    # MEM MAP ENTRY
    print("--------------------------------------------------------------------")
    print("Get the PE base of 'explorer.exe' in the 'explorer.exe' process.    ")
    input("Press Enter to continue...")
    print("CALL: VmmPy_ProcessGetMemoryMapEntry()")
    result = VmmPy_ProcessGetMemoryMapEntry(pid, va, True)
    print("SUCCESS: VmmPy_ProcessGetMemoryMapEntry()")
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

    # VFS LIST /
    print("--------------------------------------------------------------------")
    print("Retrieve the file list of the virtual file system from the root path")
    input("Press Enter to continue...")
    print("CALL: VmmPy_VfsList()")
    result = VmmPy_VfsList('/')
    print("SUCCESS: VmmPy_VfsList()")
    print(result)

    # VFS LIST /name
    print("--------------------------------------------------------------------")
    print("Retrieve the file list of the virtual file system from the name path")
    input("Press Enter to continue...")
    print("CALL: VmmPy_VfsList()")
    result = VmmPy_VfsList('/name')
    print("SUCCESS: VmmPy_VfsList()")
    print(result)

    # VFS READ
    print("--------------------------------------------------------------------")
    print("Read from a file in the virtual file system (/pmem at offset 0x1000)")
    input("Press Enter to continue...")
    print("CALL: VmmPy_VfsRead()")
    result = VmmPy_UtilFillHexAscii(VmmPy_VfsRead('/pmem', 0x100, 0x1000))
    print("SUCCESS: VmmPy_VfsRead()")
    print(result)



PE_STRUCT_DEFINITIONS = """
    #define IMAGE_NUMBEROF_DIRECTORY_ENTRIES 16
    #define IMAGE_SIZEOF_SHORT_NAME          8
    typedef struct _IMAGE_DOS_HEADER
    {
        WORD e_magic;
        WORD e_cblp;
        WORD e_cp;
        WORD e_crlc;
        WORD e_cparhdr;
        WORD e_minalloc;
        WORD e_maxalloc;
        WORD e_ss;
        WORD e_sp;
        WORD e_csum;
        WORD e_ip;
        WORD e_cs;
        WORD e_lfarlc;
        WORD e_ovno;
        WORD e_res[4];
        WORD e_oemid;
        WORD e_oeminfo;
        WORD e_res2[10];
        LONG e_lfanew;
    } IMAGE_DOS_HEADER;
    typedef struct _IMAGE_FILE_HEADER {
        WORD  Machine;
        WORD  NumberOfSections;
        DWORD TimeDateStamp;
        DWORD PointerToSymbolTable;
        DWORD NumberOfSymbols;
        WORD  SizeOfOptionalHeader;
        WORD  Characteristics;
    } IMAGE_FILE_HEADER;
    typedef struct _IMAGE_DATA_DIRECTORY {
        ULONG   VirtualAddress;
        ULONG   Size;
    } IMAGE_DATA_DIRECTORY;
    typedef struct _IMAGE_OPTIONAL_HEADER {
        WORD                 Magic;
        BYTE                 MajorLinkerVersion;
        BYTE                 MinorLinkerVersion;
        DWORD                SizeOfCode;
        DWORD                SizeOfInitializedData;
        DWORD                SizeOfUninitializedData;
        DWORD                AddressOfEntryPoint;
        DWORD                BaseOfCode;
        DWORD                BaseOfData;
        DWORD                ImageBase;
        DWORD                SectionAlignment;
        DWORD                FileAlignment;
        WORD                 MajorOperatingSystemVersion;
        WORD                 MinorOperatingSystemVersion;
        WORD                 MajorImageVersion;
        WORD                 MinorImageVersion;
        WORD                 MajorSubsystemVersion;
        WORD                 MinorSubsystemVersion;
        DWORD                Win32VersionValue;
        DWORD                SizeOfImage;
        DWORD                SizeOfHeaders;
        DWORD                CheckSum;
        WORD                 Subsystem;
        WORD                 DllCharacteristics;
        DWORD                SizeOfStackReserve;
        DWORD                SizeOfStackCommit;
        DWORD                SizeOfHeapReserve;
        DWORD                SizeOfHeapCommit;
        DWORD                LoaderFlags;
        DWORD                NumberOfRvaAndSizes;
        IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
    } IMAGE_OPTIONAL_HEADER;
    typedef struct _IMAGE_OPTIONAL_HEADER64 {
        WORD        Magic;
        BYTE        MajorLinkerVersion;
        BYTE        MinorLinkerVersion;
        DWORD       SizeOfCode;
        DWORD       SizeOfInitializedData;
        DWORD       SizeOfUninitializedData;
        DWORD       AddressOfEntryPoint;
        DWORD       BaseOfCode;
        ULONGLONG   ImageBase;
        DWORD       SectionAlignment;
        DWORD       FileAlignment;
        WORD        MajorOperatingSystemVersion;
        WORD        MinorOperatingSystemVersion;
        WORD        MajorImageVersion;
        WORD        MinorImageVersion;
        WORD        MajorSubsystemVersion;
        WORD        MinorSubsystemVersion;
        DWORD       Win32VersionValue;
        DWORD       SizeOfImage;
        DWORD       SizeOfHeaders;
        DWORD       CheckSum;
        WORD        Subsystem;
        WORD        DllCharacteristics;
        ULONGLONG   SizeOfStackReserve;
        ULONGLONG   SizeOfStackCommit;
        ULONGLONG   SizeOfHeapReserve;
        ULONGLONG   SizeOfHeapCommit;
        DWORD       LoaderFlags;
        DWORD       NumberOfRvaAndSizes;
        IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
    } IMAGE_OPTIONAL_HEADER64;
    typedef struct _IMAGE_SECTION_HEADER {
        char    Name[IMAGE_SIZEOF_SHORT_NAME];
        ULONG   VirtualSize;
        ULONG   VirtualAddress;
        ULONG   SizeOfRawData;
        ULONG   PointerToRawData;
        ULONG   PointerToRelocations;
        ULONG   PointerToLinenumbers;
        USHORT  NumberOfRelocations;
        USHORT  NumberOfLinenumbers;
        ULONG   Characteristics;
    } IMAGE_SECTION_HEADER;
"""



def VmmPy_Example_ParsePE(dump_file_name):
    # INIITALIZE
    print("--------------------------------------------------------------------")
    print("Initialize VmmPy with the dump file specified.                      ")
    input("Press Enter to continue...")
    print("CALL: VmmPy_InitializeFile()")
    VmmPy_InitializeFile(dump_file_name)
    print("SUCCESS: VmmPy_InitializeFile()")

    #
    # EXAMPLE BELOW USE THE FOX-IT DISSECT CSTRUCT PYTHON MODULE TO PARSE THE
    # THE PE HEADER OF 'ntdll.dll' in 'explorer.exe'
    #
    print("--------------------------------------------------------------------")
    print("Parse the PE header of 'explorer.exe'/'ntdll.dll' by using a VmmPy  ")
    print("custom version of the dissect.cstruct parsing library from fox-it.  ")
    print("dissect.cstruct: https://github.com/fox-it/dissect.cstruct          ")
    input("Press Enter to continue...")

    # Call VmmPy to retrieve the actual 0x1000 page containing the PE header.
    print("CALL: VmmPy*")
    mz_pid = VmmPy_PidGetFromName('explorer.exe')
    mz_va = VmmPy_ProcessGetModuleFromName(mz_pid, "ntdll.dll")['va']
    mz_bytes = VmmPy_MemRead(mz_pid, mz_va, 0x1000)
    print("SUCCESS: VmmPy*")

    # Create a stream for convenience
    mz_stream = BytesIO(mz_bytes)

    # Set up dissect.cstruct
    print("INITIALIZING dissect.cstruct and parsing PE header structures ...   ")
    pestruct = cstruct.cstruct()
    pestruct.load(PE_STRUCT_DEFINITIONS)

    # Load the MZ stream into dissect.struct. NB! loading mz_bytes will work as
    # well but will not be as convenient since the 'file pointer' won't move on
    # struct reads automatically...
    struct_mz = pestruct.IMAGE_DOS_HEADER(mz_stream)
    if struct_mz.e_magic != 0x5a4d:
        print("MZ HEADER DOES NOT MATCH - ABORTING")
        return
    print(struct_mz)
    print(cstruct.dumpstruct(struct_mz, None, 0, False, True))

    # Seek towards the PE signature / magic value and check that it is correct.
    mz_stream.seek(struct_mz.e_lfanew)
    signature = pestruct.uint32(mz_stream)
    if signature != 0x4550:
        print("PE HEADER DOES NOT MATCH")
        return

    # Parse and display the PE file_header struct.
    struct_file_header = pestruct.IMAGE_FILE_HEADER(mz_stream)
    print(struct_file_header)
    print(cstruct.dumpstruct(struct_file_header, None, 0, False, True))

    # Parse and display the PE struct_optional_header struct.
    struct_optional_header = pestruct.IMAGE_OPTIONAL_HEADER64(mz_stream) if struct_file_header.Machine == 0x8664 else pestruct.IMAGE_OPTIONAL_HEADER(mz_stream)
    print(struct_optional_header)
    print(cstruct.dumpstruct(struct_optional_header, None, 0, False, True))

    # Parse and display the PE sections.
    struct_sections = [pestruct.IMAGE_SECTION_HEADER(mz_stream) for _ in range(struct_file_header.NumberOfSections)]
    for struct_section in struct_sections:
        print(cstruct.dumpstruct(struct_section, None, 0, False, True))
