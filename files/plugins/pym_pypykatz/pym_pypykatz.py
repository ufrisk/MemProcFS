# pym_pypykatz.py
#
# Pypykatz plugin for MemProcFS
#
# https://github.com/skelsec/
#
# (c) Tamas Jos, 2019
# Author: Tamas Jos (@skelsec), info@skelsec.com
#

from vmmpy import *
from vmmpyplugin import *

install_info_text = """
INSTALLATION INFORMATION
========================
The Pypykatz plugin for MemProcFS provides 'mimikatz' like functionality for MemProcFS.

The plugin must be installed separately from the MemProcFS plugin respository.

The plugin is available for download from https://github.com/ufrisk/MemProcFS-Plugins

Installation is quick and easy - just copy the plugin files into the correct plugin directory!

Please see installation instructions at: https://github.com/ufrisk/MemProcFS-Plugins
"""
		
def ReadFile(pid, file_name, file_attr, bytes_length, bytes_offset):
    return install_info_text.encode()[bytes_offset:bytes_offset+bytes_length]

def Initialize(target_system, target_memorymodel):
    if target_system != VMMPY_SYSTEM_WINDOWS_X64 and target_system != VMMPY_SYSTEM_WINDOWS_X86:
        raise RuntimeError("Only Windows is supported by the pym_pypykatz module.")
    VmmPyPlugin_FileRegister(None, 'installation_info.txt', len(install_info_text), ReadFile)
