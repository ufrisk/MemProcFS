# memprocfs.py
#
# Fast and convenient python access towards the native vmm.dll and in some
# cases linked pcileech.dll libraries.
#
# https://github.com/ufrisk/
# https://github.com/ufrisk/MemProcFS
# https://github.com/ufrisk/MemProcFS/wiki/API_Python
#
# (c) Ulf Frisk, 2021
# Author: Ulf Frisk, pcileech@frizk.net
#
# Header Version: 4.0
#

try:
    import leechcorepyc
except: pass

try:
    from .vmmpyc import Vmm
except:
    from vmmpyc import Vmm

try:
    try:
        from .vmmpyc import VmmPycPlugin
    except:
        from vmmpyc import VmmPycPlugin
except: pass



#------------------------------------------------------------------------------
# memprocfs.RegUtil:
#------------------------------------------------------------------------------

class RegUtil:
    """ RegUtil 'container' for helper functions related to registry.
    """

    def __init__(self, name, course):
        raise ValueError('Not Allowed!')

    @staticmethod
    def ft2str(ft_int):
        """Convert a Windows FileTime integer to string.

        Keyword arguments:
        -- ft_int = int: Windows FileTime value.
        -- return = str: 23 char time in format: '%Y-%m-%d %H:%M:%S UTC' / '2020-01-01 23:59:59 UTC'.
        """
        from datetime import datetime, timedelta
        if ft_int > 0x0100000000000000 and ft_int < 0x0200000000000000:
            ft_dt = datetime(1601,1,1) + timedelta(microseconds=ft_int/10)
            return ft_dt.strftime("%Y-%m-%d %H:%M:%S UTC")
        return '                    ***'


    @staticmethod
    def print_keyvalue(indent_int, key_str, value_str = '', line_length = 80, is_line_truncate = False, is_value_bracket = False):
        """Print a key-value pair on the screen with formatting.

        Keyword arguments:
        -- indent_int = int: indent in # spaces.
        -- key_str = str: key name.
        -- value_str = str: optional value string; default: ''.
        -- line_length = int: optional line length; default: 80.
        -- is_line_truncate = bool: optional truncate flag; default False.
        -- is_value_bracked = bool: optional put value str inside []; default False.
        """
        pad = max(0, line_length - 23 - indent_int)
        if is_value_bracket:
            value_str = '[' + value_str + ']'
        if is_line_truncate:
            key_str = key_str[0:line_length - 25 - indent_int]
            value_str = value_str[0:25]
        if value_str == '':
            pad = 0
        else:
            value_str = ' ' + value_str
        print('%*s%-*s%s' % (indent_int, '', pad, key_str, value_str))


    @staticmethod
    def print_filetime(indent_int, key_str, ft_int, line_length = 80, is_line_truncate = False, is_value_bracket = False):
        """Print a keyname/filetime pair on the screen with formatting.

        Keyword arguments:
        -- indent_int = int: indent in # spaces.
        -- key_str = str: key name.
        -- ft_int = int: time in Windows FILETIME format.
        -- line_length = int: optional line length; default: 80.
        -- is_line_truncate = bool: optional truncate flag; default False.
        -- is_value_bracked = bool: optional put value str inside []; default False.
        """
        ft_str = RegUtil.ft2str(ft_int)
        RegUtil.print_keyvalue(indent_int, key_str, ft_str, line_length, is_line_truncate, is_value_bracket)


    @staticmethod
    def read_utf16(vmm, reg_value_path, is_skip_typecheck = False):
        """Read a UTF-16 value from registry with exceptions suppressed.
        UTF-16 values are default for registry keys.

        Keyword arguments:
        -- vmm = Vmm: MemProcFS VMM object.
        -- reg_value_path = str: value path/name __OR__ bytes: raw value.
        -- is_skip_typecheck = bool: skip typecheck (REG_SZ, REG_EXPAND_SZ); default False.
        -- return = str: value on success, '' on fail.
        """
        try:
            if type(reg_value_path) is bytes:
                data_str = reg_value_path.decode('utf-16le')
                data_nul = data_str.index('\0')
                if data_nul == -1:
                    return data_str
                return data_str[0:data_nul]
            else:
                return vmm.reg_value(reg_value_path).vstr(not is_skip_typecheck)
        except: pass
        return ''


    @staticmethod
    def read_ascii(vmm, reg_value_path):
        """Read an ascii value from registry with exceptions suppressed.

        Keyword arguments:
        -- vmm = Vmm: MemProcFS VMM object.
        -- reg_value_path = str: value path/name __OR__ bytes: raw value.
        -- return = str: value on success, '' on fail.
        """
        try:
            if type(reg_value_path) is bytes:
                data_str = reg_value_path.decode('ascii')
                data_nul = data_str.index('\0')
                if data_nul == -1:
                    return data_str
                return data_str[0:data_nul]
            else:
                return vmm.reg_value(reg_value_path).vascii()
        except: pass
        return ''


    @staticmethod
    def read_qword(vmm, reg_value_path, is_skip_typecheck = False):
        """Read a 64-bit 'QWORD' value from registry with exceptions suppressed.

        Keyword arguments:
        -- vmm = Vmm: MemProcFS VMM object.
        -- reg_value_path = str: value path/name __OR__ bytes: raw value.
        -- is_skip_typecheck = bool: skip typecheck; default False.
        -- return = int: value on success, -1 on fail.
        """
        try:
            if type(reg_value_path) is bytes:
                if len(reg_value_path) == 8:
                    return int.from_bytes(reg_value_path, byteorder='little')
            else:
                return vmm.reg_value(reg_value_path).vqword(not is_skip_typecheck)
        except: pass
        return -1


    @staticmethod
    def read_dword(vmm, reg_value_path, is_skip_typecheck = False):
        """Read a 32-bit 'DWORD' value from registry with exceptions suppressed.

        Keyword arguments:
        -- vmm = Vmm: MemProcFS VMM object.
        -- reg_value_path = str: value path/name __OR__ bytes: raw value.
        -- is_skip_typecheck = bool: skip typecheck; default False.
        -- return = int: value on success, -1 on fail.
        """
        try:
            if type(reg_value_path) is bytes:
                if len(reg_value_path) == 4:
                    return int.from_bytes(reg_value_path, byteorder='little')
            else:
                return vmm.reg_value(reg_value_path).vdword(not is_skip_typecheck)
        except: pass
        return -1


    @staticmethod
    def mrulistex_expand(mrulistex_bytes):
        """Convert a MRUListEx reg value into a list.

        Keyword arguments:
        -- mrulistex_bytes = bytes: value of MRUListEx data.
        -- return = array: int of value MRUListEx values.
        """
        i = 0
        result = []
        if len(mrulistex_bytes) % 4 == 0:
            while i < len(mrulistex_bytes):
                v = int.from_bytes(mrulistex_bytes[i:i+4], byteorder='little')
                if v == 0xffffffff:
                    return result
                result.append(v)
                i = i + 4
        return []



#------------------------------------------------------------------------------
# CONSTANTS BELOW:
#------------------------------------------------------------------------------

# FLAG used to supress the default read cache in calls to VMM_MemReadEx()
# which will lead to the read being fetched from the target system always.
# Cached page tables (used for translating virtual2physical) are still used.
FLAG_NOCACHE                          = 0x0001 # do not use the data cache (force reading from memory acquisition device)
FLAG_ZEROPAD_ON_FAIL                  = 0x0002 # zero pad failed physical memory reads and report success if read within range of physical memory.
FLAG_FORCECACHE_READ                  = 0x0008 # force use of cache - fail non-cached pages - only valid for reads, invalid with VMM_FLAG_NOCACHE/VMM_FLAG_ZEROPAD_ON_FAIL.
FLAG_NOPAGING                         = 0x0010 # do not try to retrieve memory from paged out memory from pagefile/compressed (even if possible)
FLAG_NOPAGING_IO                      = 0x0020 # do not try to retrieve memory from paged out memory if read would incur additional I/O (even if possible).
FLAG_NOCACHEPUT                       = 0x0100 # do not write back to the data cache upon successful read from memory acquisition device.
FLAG_CACHE_RECENT_ONLY                = 0x0200 # only fetch from the most recent active cache region when reading.
FLAG_NO_PREDICTIVE_READ               = 0x0400 # do not perform additional predictive page reads (default on smaller requests).

# NTSTATUS values. (Used/Returned by Write file plugin callbacks).
STATUS_SUCCESS                        = 0x00000000
STATUS_UNSUCCESSFUL                   = 0xC0000001
STATUS_END_OF_FILE                    = 0xC0000011
STATUS_FILE_INVALID                   = 0xC0000098

# SYSTEM values - used to determine if a plugin is supported or not for
# the current system that is being analyzed.
SYSTEM_UNKNOWN_X64                    = 0x0001
SYSTEM_WINDOWS_X64                    = 0x0002
SYSTEM_UNKNOWN_X86                    = 0x0003
SYSTEM_WINDOWS_X86                    = 0x0004

# MEMORYMODEL values - used to determine if a plugin is supported or not
# for a specific memory model.
MEMORYMODEL_NA                        = 0x0000
MEMORYMODEL_X86                       = 0x0001
MEMORYMODEL_X86PAE                    = 0x0002
MEMORYMODEL_X64                       = 0x0003

# NOTIFY EVENT values - received by the notify callback function for specific
# events occuring in the native plugin manager / VMM / MemProcFS.
PLUGIN_NOTIFY_VERBOSITYCHANGE         = 0x01
PLUGIN_NOTIFY_REFRESH_FAST            = 0x05    # refresh fast event   - at partial process refresh.
PLUGIN_NOTIFY_REFRESH_MEDIUM          = 0x02    # refresh medium event - at full process refresh.
PLUGIN_NOTIFY_REFRESH_SLOW            = 0x04    # refresh slow event   - at registry refresh.
PLUGIN_NOTIFY_FORENSIC_INIT           = 0x01000100
PLUGIN_NOTIFY_FORENSIC_INIT_COMPLETE  = 0x01000200

# WINDOWS REGISTRY contants below:
WINREG_NONE                           = 0x00
WINREG_SZ                             = 0x01
WINREG_EXPAND_SZ                      = 0x02
WINREG_BINARY                         = 0x03
WINREG_DWORD                          = 0x04
WINREG_DWORD_BIG_ENDIAN               = 0x05
WINREG_LINK                           = 0x06
WINREG_MULTI_SZ                       = 0x07
WINREG_RESOURCE_LIST                  = 0x08
WINREG_FULL_RESOURCE_DESCRIPTOR       = 0x09
WINREG_RESOURCE_REQUIREMENTS_LIST     = 0x0A
WINREG_QWORD                          = 0x0B

PID_PROCESS_CLONE_WITH_KERNELMEMORY   = 0x80000000

#------------------------------------------------------------------------------
# VmmPy CONFIGURATION FUNCTIONALITY BELOW:
#------------------------------------------------------------------------------

OPT_CORE_PRINTF_ENABLE                = 0x4000000100000000  # RW
OPT_CORE_VERBOSE                      = 0x4000000200000000  # RW
OPT_CORE_VERBOSE_EXTRA                = 0x4000000300000000  # RW
OPT_CORE_VERBOSE_EXTRA_TLP            = 0x4000000400000000  # RW
OPT_CORE_MAX_NATIVE_ADDRESS           = 0x4000000800000000  # R

OPT_CORE_SYSTEM                       = 0x2000000100000000  # R
OPT_CORE_MEMORYMODEL                  = 0x2000000200000000  # R
OPT_CONFIG_IS_REFRESH_ENABLED         = 0x2000000300000000  # R - 1/0
OPT_CONFIG_TICK_PERIOD                = 0x2000000400000000  # RW - base tick period in ms
OPT_CONFIG_READCACHE_TICKS            = 0x2000000500000000  # RW - memory cache validity period (in ticks)
OPT_CONFIG_TLBCACHE_TICKS             = 0x2000000600000000  # RW - page table (tlb) cache validity period (in ticks)
OPT_CONFIG_PROCCACHE_TICKS_PARTIAL    = 0x2000000700000000  # RW - process refresh (partial) period (in ticks)
OPT_CONFIG_PROCCACHE_TICKS_TOTAL      = 0x2000000800000000  # RW - process refresh (full) period (in ticks)
OPT_CONFIG_VMM_VERSION_MAJOR          = 0x2000000900000000  # R
OPT_CONFIG_VMM_VERSION_MINOR          = 0x2000000A00000000  # R
OPT_CONFIG_VMM_VERSION_REVISION       = 0x2000000B00000000  # R
OPT_CONFIG_STATISTICS_FUNCTIONCALL    = 0x2000000C00000000  # RW - enable function call statistics (.status/statistics_fncall file)
OPT_CONFIG_IS_PAGING_ENABLED          = 0x2000000D00000000  # RW - 1/0

OPT_WIN_VERSION_MAJOR                 = 0x2000010100000000  # R
OPT_WIN_VERSION_MINOR                 = 0x2000010200000000  # R
OPT_WIN_VERSION_BUILD                 = 0x2000010300000000  # R

OPT_REFRESH_ALL                       = 0x2001ffff00000000  # W - refresh all caches
OPT_REFRESH_FREQ_FAST                 = 0x2001040000000000  # W - refresh fast frequency (including partial process listings)
OPT_REFRESH_FREQ_MEDIUM               = 0x2001000100000000  # W - refresh medium frequency (including full process listings)
OPT_REFRESH_FREQ_SLOW                 = 0x2001001000000000  # W - refresh slow frequency (including registry)
OPT_REFRESH_READ                      = 0x2001000200000000  # W - refresh physical read cache
OPT_REFRESH_TLB                       = 0x2001000400000000  # W - refresh page table (TLB) cache
OPT_REFRESH_PAGING                    = 0x2001000800000000  # W - refresh virtual memory 'paging' cache
OPT_REFRESH_USER                      = 0x2001002000000000  # W
OPT_REFRESH_PHYSMEMMAP                = 0x2001004000000000  # W
OPT_REFRESH_PFN                       = 0x2001008000000000  # W
OPT_REFRESH_OBJ                       = 0x2001010000000000  # W
OPT_REFRESH_NET                       = 0x2001020000000000  # W
