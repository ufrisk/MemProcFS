# sysinfo_helpers.py
#
# Helper functions to retrieve the file time and version information from a file.
# NB! there are cleaner and better ways to do this, but this works ...
#
# https://github.com/ufrisk/
#
# (c) Ulf Frisk, 2019
# Author: Ulf Frisk, pcileech@frizk.net
#

from io import BytesIO
from dissect import cstruct
from vmmpy import *

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
"""

def PEGetFileTime(pid, module):
    mz_va = VmmPy_ProcessGetModuleFromName(pid, module)['va']
    mz_bytes = VmmPy_MemRead(pid, mz_va, 0x1000)
    mz_stream = BytesIO(mz_bytes)
    # Set up dissect.cstruct
    pestruct = cstruct.cstruct()
    pestruct.load(PE_STRUCT_DEFINITIONS)
    # Parse MZ header
    struct_mz = pestruct.IMAGE_DOS_HEADER(mz_stream)
    if struct_mz.e_magic != 0x5a4d:
        return 0
    mz_stream.seek(struct_mz.e_lfanew)
    signature = pestruct.uint32(mz_stream)
    if signature != 0x4550:
        return 0
    # Parse the PE file_header struct.
    struct_file_header = pestruct.IMAGE_FILE_HEADER(mz_stream)
    return struct_file_header.TimeDateStamp

def PEGetVersionEx(pid, module):
    modinfo = VmmPy_ProcessGetModuleFromName(pid, module)
    moddir = VmmPy_ProcessGetDirectories(pid, module)[2]
    if moddir['size'] > 0x4000:
        raise Exception('.rsrc size')
    data = VmmPy_MemRead(pid, modinfo['va'] + moddir['offset'], moddir['size'])
    i = data.find(bytes('VS_VERSION_INFO', 'utf-16le'))
    if i == -1:
        raise Exception('.rsrc VS_VERSION_INFO')
    i = data.find(bytes('FileVersion', 'utf-16le'), i)
    if i == -1:
        raise Exception('.rsrc FileVersion')
    for s in str(data[i+22:i+200], 'utf-16le').split(chr(0)):
        if len(s) > 0:
            return s.split()[0]
    raise Exception('.rsrc FileVersion not found')

def PEGetVersion(pid, module):
    modules = ['kernel32.dll', 'msasn1.dll', 'bcrypt.dll']
    modules.insert(0, module)
	
    for mod in modules:
        try:
            return PEGetVersionEx(pid, mod)
        except:
            pass
    raise Exception('.rsrc FileVersion not found')
