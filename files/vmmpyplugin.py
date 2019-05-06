# VmmPyPlugin.py
#
# Provides plugin related functionality to the memory process file system and
# the virtual memory manager in VMM.DLL. Functionality mainly consists of DLL
# and Python callback functionality allowing for integration between the file
# system native code base and any python modules.
#
# The VmmPyPlugin is responsible for providing List, Read, Write and Close
# functionality towards the file system as well as loading any python modules
# from the plugin sub-directory matching './plugins/m_*.py'.
#
# General API callback functionality is provided by the vmmpy module that may
# be used in plugins, but also in ordinary stand-alone python for convenient
# and easy vmm integration.
#
# https://github.com/ufrisk/
#
# (c) Ulf Frisk, 2018
# Author: Ulf Frisk, pcileech@frizk.net
#
# Header Version: 2.4
#

from vmmpy import *
from vmmpycc import *

VmmPyPlugin_fPrint =    False   # print statements enable.
VmmPyPlugin_fPrintV =   False   # verbose print statements enable.
VmmPyPlugin_fPrintVV =  False   # extra verbose print statements enable.
VmmPyPlugin_fPrintVVV = False   # super verbose print statements enable.

#------------------------------------------------------------------------------
# VmmPy DIRECTORY LISTING AND CALLBACK FUNCTIONALITY BELOW:
#------------------------------------------------------------------------------

"""
Each file/directory is put as a dict inside the dict with the file/directory
name as the key. The dict is documented below. Please note that list and dirs
are a directory only attributes, while size, read, write are file only
attributes.
dict_file_directory['name'] = {
    # directory only attributes below:
    'list': <function: callback function called before accessing 'dirs'
             if None is returned 'dirs' will be accessed, otherwise
             return data will be treated and used instead of 'dirs'>
    'dirs': <dict: containing sub-directory entries with name as keys>
    # file only attributes below:
    'size': <integer number: file size (uint64)>
    'write': <function: write callback function>
    'read': <function: read callback function>
}

The dicts are: VmmPy_RootDirectoryRoot and VmmPy_RootDirectoryProcess.

Please note that the VmmPy_RootDirectoryProcess dict is shared amongst all
processes. If process independant file listings are required please use the
'list' function callback to generate dynamic directory listings per-process.

Please also note that even though the directory listings are shared amongst
all processes it's still possible to differentiate on file contents via the
'read' and 'write' callback functions.
"""



def VmmPyPlugin_InternalInitialize():
    """Internal Use Only! - initialization function.
    """
    if 'VmmPyPlugin_IsInitialized' in globals():
        return
    global VmmPyPlugin_IsInitialized
    global VmmPyPlugin_RootDirectoryRoot
    global VmmPyPlugin_RootDirectoryProcess
    global VmmPyPlugin_TargetSystem
    global VmmPyPlugin_TargetMemoryModel
    VmmPyPlugin_IsInitialized = True
    VmmPyPlugin_RootDirectoryRoot = {}
    VmmPyPlugin_RootDirectoryProcess = {}
    VmmPyPlugin_TargetSystem = VmmPy_ConfigGet(VMMPY_OPT_CORE_SYSTEM)
    VmmPyPlugin_TargetMemoryModel = VmmPy_ConfigGet(VMMPY_OPT_CORE_MEMORYMODEL)
    VmmPyPlugin_InternalSetVerbosity();
    VmmPyPlugin_InternalInitializePlugins()
    VMMPYCC_CallbackRegister(
        VmmPyPlugin_InternalCallback_List, 
        VmmPyPlugin_InternalCallback_Read, 
        VmmPyPlugin_InternalCallback_Write, 
        VmmPyPlugin_InternalCallback_Notify, 
        VmmPyPlugin_InternalCallback_Close)



def VmmPyPlugin_InternalInitializePlugins():
    """Internal Use Only! - initialization function - Load Plugins.
    """
    import os
    import glob
    import importlib
    global VmmPyPlugin_PluginModules
    path = os.path.dirname(__file__) + '/'
    plugin_files = glob.glob(path + 'plugins/pym_*/pym_*.py', recursive=True)
    plugin_names = set()
    for f in plugin_files:
        f_split = f.replace(path, '').replace('\\', '/').split('/')
        plugin_names.add(f_split[0] + '.' + f_split[1])
    VmmPyPlugin_PluginModules = []
    for e in plugin_names:
        try:
            module = importlib.import_module(e)
            module.Initialize(VmmPyPlugin_TargetSystem, VmmPyPlugin_TargetMemoryModel)
            VmmPyPlugin_PluginModules.append(module)
            if VmmPyPlugin_fPrintV:
                print("VmmPyPlugin: Loaded '" + e + "'")
        except Exception as e2:
            if VmmPyPlugin_fPrintV:
                print("VmmPyPlugin: Failed to load '" + e + "'")
                print("VmmPyPlugin_InternalInitializePlugins: Exception: " + str(e2))



def VmmPyPlugin_InternalCallback_List(pid, path):
    """Internal Use Only!
    For a given path return list of dicts containing info for each entry.

    Keyword arguments:
    pid -- int: the pid (or None/False if root).
    path -- str: the path to retrieve.
    return -- list of dict containing the information.
    """
    try:
        dir_entry = VmmPyPlugin_RootDirectoryRoot if (pid == None or pid == False) else VmmPyPlugin_RootDirectoryProcess
        path_items = list(filter(None, path.split('/')))
        for e in path_items:
            if not e in dir_entry:
                return []
            if not 'list' in dir_entry[e]:
                return []
            if dir_entry[e]['list'] != None:
                dir_entry = dir_entry[e]['list'](pid, path)
                break
            else:
                dir_entry = dir_entry[e]['dirs']
        if dir_entry == None:
            return []
        result = []
        for k,v in dir_entry.items():
            result.append({'name': k,
                           'size': v['size'] if 'size' in v else 0,
                           'f_isdir': True if 'dirs' in v else False
                           })
        return result
    except Exception as e:
        if VmmPyPlugin_fPrintV:
            print("VmmPyPlugin_InternalCallback_List: Exception: " + str(e))
        return []



def VmmPyPlugin_InternalCallback_Read(pid, path, bytes_length, bytes_offset):
    """Internal Use Only!
    Read bytes from a given path/file.

    Keyword arguments:
    pid -- int: process identifier (PID), None/False for root.
    path -- str: the path/file to read.
    bytes_length -- int: number of bytes to read.
    bytes_offset -- int: offset of bytes to read.
    return -- bytes: the data read.
    """
    try:
        file_name, file_attr = VmmPyPlugin_FileRetrieve(pid, path)
        if file_attr['read'] == None:
            return b''
        if bytes_offset >= file_attr['size']:
            return b''
        if bytes_length + bytes_offset > file_attr['size']:
            bytes_length = file_attr['size'] - bytes_offset
        return file_attr['read'](pid, file_name, file_attr, bytes_length, bytes_offset)
    except Exception as e:
        if VmmPyPlugin_fPrintV:
            print("VmmPyPlugin_InternalCallback_Read: Exception: " + str(e))
        return None


   
def VmmPyPlugin_InternalCallback_Write(pid, path, bytes_data, bytes_offset):
    """Internal Use Only!
    Write bytes to a given path/file.

    Keyword arguments:
    pid -- int: process identifier (PID), None/False for root.
    path -- str: the path/file to write.
    bytes_data -- bytes: the bytes to write.
    bytes_offset -- int: offset of bytes to write.
    return -- int: VMMPY_STATUS (NTSTATUS) value of the write operation.
    """
    try:
        file_name, file_attr = VmmPyPlugin_FileRetrieve(pid, path)
        bytes_length = len(bytes_data)
        if file_attr['write'] == None:
            return VMMPY_STATUS_END_OF_FILE
        if bytes_offset >= file_attr['size']:
            return VMMPY_STATUS_END_OF_FILE
        if bytes_length + bytes_offset > file_attr['size']:
            bytes_length = file_attr['size'] - bytes_offset
        return file_attr['write'](pid, file_name, file_attr, bytes_data, bytes_offset)
    except Exception as e:
        if VmmPyPlugin_fPrintV:
            print("VmmPyPlugin_InternalCallback_Write: Exception: " + str(e))
        return VMMPY_STATUS_FILE_INVALID



def VmmPyPlugin_InternalSetVerbosity():
    """Internal Use Only!
    Set verbosity level variables
    """
    try:
        global VmmPyPlugin_fPrint, VmmPyPlugin_fPrintV, VmmPyPlugin_fPrintVV, VmmPyPlugin_fPrintVVV
        VmmPyPlugin_fPrint = VmmPy_ConfigGet(VMMPY_OPT_CORE_PRINTF_ENABLE) > 0
        VmmPyPlugin_fPrintV = VmmPyPlugin_fPrint and VmmPy_ConfigGet(VMMPY_OPT_CORE_VERBOSE) > 0
        VmmPyPlugin_fPrintVV = VmmPyPlugin_fPrint and VmmPy_ConfigGet(VMMPY_OPT_CORE_VERBOSE_EXTRA) > 0
        VmmPyPlugin_fPrintVVV = VmmPyPlugin_fPrint and VmmPy_ConfigGet(VMMPY_OPT_CORE_VERBOSE_EXTRA_TLP) > 0
    except Exception as e:
        if VmmPyPlugin_fPrintV:
            print("VmmPyPlugin_InternalSetVerbosity: Exception: " + str(e))



def VmmPyPlugin_InternalCallback_Notify(fEvent, bytesData):
    """Internal Use Only!
    Receive notify events from the native plugin manager.

    Keyword arguments:
    fEvent -- int: the event id as given by VMMPY_PLUGIN_EVENT_*
    bytesData -- bytes: any bytes object (or None) related to the event.
    """
    if fEvent == VMMPY_PLUGIN_EVENT_VERBOSITYCHANGE:
        VmmPyPlugin_InternalSetVerbosity()
    for module in VmmPyPlugin_PluginModules:
        if hasattr(module, 'Notify'):
            module.Notify(fEvent, bytesData)



def VmmPyPlugin_InternalCallback_Close():
    """Internal Use Only!
    Callback when closing down python interpreter.
    """
    print("VmmPyPlugin_InternalCallback_Close")
    return 0



def VmmPyPlugin_FileRegister(pid, path, size, fn_read_callback, fn_write_callback = None, is_overwrite = False):
    """Register a file in the file listing database.
    NB! Required directories are automatically created if possible.

    Keyword arguments:
    pid -- int: process identifier (PID), None/False for root.
    path -- str: the path including the file name to register.
    size -- the file size.
    fn_read_callback = callback function for read operation.
    fn_write_callback = callback function for write operation.
    is_overwrite -- overwrise allowed?
    """
    dir_entry = VmmPyPlugin_RootDirectoryRoot if (pid == None or pid == False) else VmmPyPlugin_RootDirectoryProcess
    path_items = list(filter(None, path.split('/')))
    file = path_items.pop()
    for path_item in path_items:
        if not path_item in dir_entry:
            dir_entry[path_item] = {'list': None, 'dirs': {}}
        if dir_entry[path_item]['list'] != None:
            raise RuntimeError('VmmPyPlugin_FileRegister: cannot add file entry to sub-directory with dynamic listing.')
        dir_entry = dir_entry[path_item]['dirs']
    if not is_overwrite and file in dir_entry:
        raise RuntimeError('VmmPyPlugin_FileRegister: cannot overwrite existing file without is_overwrite flag set.')
    dir_entry[file] = {'size': size, 'read': fn_read_callback, 'write': fn_write_callback}



def VmmPyPlugin_FileRegisterDirectory(pid, path, fn_list_callback = None, is_overwrite = False):
    """Register a directory in the file listing database.
    NB! Required directories are automatically created if possible.

    Keyword arguments:
    pid -- int: process identifier (PID), None/False for root.
    path -- the path including the file name to register.
    fn_list_callback = callback function for dynamic directory listing.
    is_overwrite -- overwrise allowed?
    """
    dir_entry = VmmPyPlugin_RootDirectoryRoot if (pid == None or pid == False) else VmmPyPlugin_RootDirectoryProcess
    path_items = list(filter(None, path.split('/')))
    dir_to_reg = path_items.pop()
    for path_item in path_items:
        if not path_item in dir_entry:
            dir_entry[path_item] = {'list': None, 'dirs': {}}
        if dir_entry[path_item]['list'] != None:
            raise RuntimeError('VmmPyPlugin_FileRegisterDirectory: cannot add directory entry to sub-directory with dynamic listing.')
        dir_entry = dir_entry[path_item]['dirs']
    if not is_overwrite and dir_to_reg in dir_entry:
        raise RuntimeError('VmmPyPlugin_FileRegisterDirectory: cannot overwrite existing directory without is_overwrite flag set.')
    dir_entry[dir_to_reg] = {'list': fn_list_callback, 'dirs': {}}



def VmmPyPlugin_FileUnregister(pid, path):
    """Unregister a directory or file from the file listing database.

    Keyword arguments:
    pid -- int: process identifier (PID), None/False for root.
    path -- str: the path including the file name to register.
    """
    dir_entry = VmmPyPlugin_RootDirectoryRoot if (pid == None or pid == False) else VmmPyPlugin_RootDirectoryProcess
    path_items = list(filter(None, path.split('/')))
    entry = path_items.pop()
    for path_item in path_items:
        if not path_item in dir_entry:
            raise RuntimeError('VmmPyPlugin_FileUnregister: cannot remove non-existant directory/file.')
        dir_entry = dir_entry[path_item]['dirs']
    if not entry in dir_entry:
        raise RuntimeError('VmmPyPlugin_FileUnregister: cannot remove non-existant directory/file.')
    del dir_entry[entry]



def VmmPyPlugin_FileRetrieve(pid, path):
    """Retrieve a file from the file listing database.

    Keyword arguments:
    pid -- int: process identifier (PID), None/False for root.
    path -- str: the path including the file name to register.
    pid -- int: process identifier (optional) to be forwarded to any dynamic list functions.
    return -- tuple: <str name, dict values>.
    """
    dir_entry = VmmPyPlugin_RootDirectoryRoot if (pid == None or pid == False) else VmmPyPlugin_RootDirectoryProcess
    path_items = list(filter(None, path.split('/')))
    entry = path_items.pop()
    dir_path = '/'.join(path_items)
    for path_item in path_items:
        if not path_item in dir_entry:
            raise RuntimeError('VmmPyPlugin_FileRetrieve: not found.')
        if dir_entry[path_item]['list'] != None:
            dir_entry = dir_entry[path_item]['list'](pid, dir_path)
            break
        else:
            dir_entry = dir_entry[path_item]['dirs']
    if entry in dir_entry:
        return entry, dir_entry[entry]
    raise RuntimeError('VmmPyPlugin_FileRetrieve: not found.')



#------------------------------------------------------------------------------
# Initialize the VmmPyPlugin system and register it with the native code VMM.
#------------------------------------------------------------------------------

try:
    VmmPyPlugin_InternalInitialize()
except Exception as e:
    print(str(e))
