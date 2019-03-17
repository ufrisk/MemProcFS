from vmmpy import *
from vmmpyplugin import *

install_info_text = """
INSTALLATION INFORMATION
========================
The Pypykatz plugin for MemProcFS provides 'mimikatz' like functionality for MemProcFS.

The plugin is not part of MemProcFS and must be installed separately from the MemProcFS plugin respository.

AUTOMATIC DOWNLOAD AND INSTALLATION
===================================
To start automatic download and installation from https://github.com/ufrisk/MemProcFS-Plugins repository change something in this file and save it.

Any save of any changes to this file will trigger automatic installation of the plugin. Note! save from normal notepad doesn't work at the moment - Notepad++ or similar is recommended.

When installation is completed a message will appear in console window for MemProcFS. MemProcFS will have to be restarted for changes to take affect after a successful installation.

MANUAL INSTALLATION
===================
If the automatic installation fails it's quick and easy to install manually!

The plugin is available for download from https://github.com/ufrisk/MemProcFS-Plugins

Installation is quick and easy - just copy the plugin files into the correct plugin directory!

Please see installation instructions at: https://github.com/ufrisk/MemProcFS-Plugins
"""

def WriteFile(pid, file_name, file_attr, bytes_data, bytes_offset):
    try:
        import urllib.request
        path_src = 'https://raw.githubusercontent.com/ufrisk/MemProcFS-plugins/master/files/plugins/pym_pypykatz/'
        path_dst = '.\\plugins\\pym_pypykatz\\'
        files = ['pypyreader.py', 'sysinfo_helpers.py', '__init__.py', 'pym_pypykatz.py']
        for file in files:
            urllib.request.urlretrieve(path_src + file, path_dst + file)
        print('Additional dependencies: python pip install pypykatz may be required.')
        print('Auto-installation of pypykatz module is hopefully completed.')
        print('*** Restart MemProcFS for changes to take affect. ***')
    except Exception as e:
        print('Auto-installation of plugin failed. Please install manually.')
        print('Manual installation from https://github.com/ufrisk/MemProcFS-Plugins')
        print(str(e))

def ReadFile(pid, file_name, file_attr, bytes_length, bytes_offset):
    return install_info_text.encode()[bytes_offset:bytes_offset+bytes_length]

def Close():
    pass

def Initialize(target_system, target_memorymodel):
    if target_system != VMMPY_SYSTEM_WINDOWS_X64 and target_system != VMMPY_SYSTEM_WINDOWS_X86:
        raise RuntimeError("Only Windows is supported by the pym_pypykatz module.")
    VmmPyPlugin_FileRegister(None, 'secrets/installation_info.txt', len(install_info_text), ReadFile, WriteFile)
