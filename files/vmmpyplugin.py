# VmmPyPlugin.py
#
# Provides plugin related functionality to the memory process file system and
# the virtual memory manager in VMM.DLL. Functionality mainly consists of DLL
# and Python callback functionality allowing for integration between the file
# system native code base and any python modules.
#
# The VmmPyPlugin is responsible for providing List, Read, Write and Close
# functionality towards the file system as well as loading any python modules
# from the plugin sub-directory matching './plugins/pym_*/*'.
#
# VmmPyPlugin also loads Light plugins: smaller, faster plugins which generate
# output by printing to stdout. Light plugins are run at first access and are
# refreshed at: PLUGIN_NOTIFY_REFRESH_SLOW intervals. Light plugins are
# ordinary .py files placed in the plugin directory. Light plugins are not
# possible to use in a per-process context.
# They are only suitable for fast small output have the file name format:
# 'pyp_root_<dirname>_<filename>.py' or 'pyp_root_<dirname>_<filename>.py'.
#
# General API callback functionality is provided by the vmmpy module that may
# be used in plugins, but also in ordinary stand-alone python for convenient
# and easy vmm integration.
#
# https://github.com/ufrisk/
#
# (c) Ulf Frisk, 2018-2023
# Author: Ulf Frisk, pcileech@frizk.net
#
# Header Version: 5.7
#

import memprocfs

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
    global vmm
    global VmmPyPlugin_IsInitialized
    global VmmPyPlugin_RootDirectoryRoot
    global VmmPyPlugin_RootDirectoryProcess
    global VmmPyPlugin_TargetSystem
    global VmmPyPlugin_TargetMemoryModel
    vmm = memprocfs.Vmm()
    VmmPyPlugin_IsInitialized = True
    VmmPyPlugin_RootDirectoryRoot = {}
    VmmPyPlugin_RootDirectoryProcess = {}
    VmmPyPlugin_TargetSystem = vmm.get_config(memprocfs.OPT_CORE_SYSTEM)
    VmmPyPlugin_TargetMemoryModel = vmm.get_config(memprocfs.OPT_CORE_MEMORYMODEL)
    VmmPyPlugin_InternalSetVerbosity();
    VmmPyPlugin_InternalInitializePlugins()
    VmmPyPluginLight_InternalInitializePlugins()
    memprocfs.VmmPycPlugin().VMMPYCC_CallbackRegister(
        VmmPyPlugin_InternalCallback_List, 
        VmmPyPlugin_InternalCallback_Read, 
        VmmPyPlugin_InternalCallback_Write, 
        VmmPyPlugin_InternalCallback_Notify, 
        VmmPyPlugin_InternalCallback_Close, 
        VmmPyPlugin_InternalCallback_Exec)



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
        file_path, file_name, file_attr = VmmPyPlugin_FileRetrieve(pid, path)
        if file_attr['read'] == None:
            return b''
        if bytes_offset >= file_attr['size']:
            return b''
        if bytes_length + bytes_offset > file_attr['size']:
            bytes_length = file_attr['size'] - bytes_offset
        return file_attr['read'](pid, file_path, file_name, file_attr, bytes_length, bytes_offset)
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
    return -- int: memprocfs.STATUS_* (NTSTATUS) value of the write operation.
    """
    try:
        file_path, file_name, file_attr = VmmPyPlugin_FileRetrieve(pid, path)
        bytes_length = len(bytes_data)
        if file_attr['write'] == None:
            return memprocfs.VSTATUS_END_OF_FILE
        if bytes_offset >= file_attr['size']:
            return memprocfs.STATUS_END_OF_FILE
        if bytes_length + bytes_offset > file_attr['size']:
            bytes_length = file_attr['size'] - bytes_offset
        return file_attr['write'](pid, file_path, file_name, file_attr, bytes_data, bytes_offset)
    except Exception as e:
        if VmmPyPlugin_fPrintV:
            print("VmmPyPlugin_InternalCallback_Write: Exception: " + str(e))
        return memprocfs.STATUS_FILE_INVALID



def VmmPyPlugin_InternalSetVerbosity():
    """Internal Use Only!
    Set verbosity level variables
    """
    try:
        global VmmPyPlugin_fPrint, VmmPyPlugin_fPrintV, VmmPyPlugin_fPrintVV, VmmPyPlugin_fPrintVVV
        VmmPyPlugin_fPrint = vmm.get_config(memprocfs.OPT_CORE_PRINTF_ENABLE) > 0
        VmmPyPlugin_fPrintV = VmmPyPlugin_fPrint and vmm.get_config(memprocfs.OPT_CORE_VERBOSE) > 0
        VmmPyPlugin_fPrintVV = VmmPyPlugin_fPrint and vmm.get_config(memprocfs.OPT_CORE_VERBOSE_EXTRA) > 0
        VmmPyPlugin_fPrintVVV = VmmPyPlugin_fPrint and vmm.get_config(memprocfs.OPT_CORE_VERBOSE_EXTRA_TLP) > 0
    except Exception as e:
        if VmmPyPlugin_fPrintV:
            print("VmmPyPlugin_InternalSetVerbosity: Exception: " + str(e))



def VmmPyPlugin_InternalCallback_Notify(fEvent, bytesData):
    """Internal Use Only!
    Receive notify events from the native plugin manager.

    Keyword arguments:
    fEvent -- int: the event id as given by memprocfs.PLUGIN_EVENT_*
    bytesData -- bytes: any bytes object (or None) related to the event.
    """
    if fEvent == memprocfs.PLUGIN_NOTIFY_VERBOSITYCHANGE:
        VmmPyPlugin_InternalSetVerbosity()
    for module in VmmPyPlugin_PluginModules:
        if hasattr(module, 'Notify'):
            module.Notify(fEvent, bytesData)
    if fEvent == memprocfs.PLUGIN_NOTIFY_REFRESH_SLOW:
        VmmPyPluginLight_InternalCallback_Refresh()



def VmmPyPlugin_InternalCallback_Exec(str_code, int_flags):
    """Internal Use Only!
    Execute python code.

    Keyword arguments:
    str_code -- string: python code to execute.
    int_flags -- int: flags (future use).
    return -- string: result of code execution.
    """
    import io
    from contextlib import redirect_stdout
    try:
        io_stdout = io.StringIO()
        with redirect_stdout(io_stdout):
            exec(str_code)
        data_str = io_stdout.getvalue()
    except Exception as e:
        data_str = ''
        if VmmPyPlugin_fPrintV:
            print("------\nVmmPyPlugin_InternalCallback_Exec: Exception: " + str(e) + "\n------")
    return data_str



def VmmPyPlugin_InternalCallback_Close():
    """Internal Use Only!
    Callback when closing down python interpreter.
    """
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
    fn_list_callback -- callback function for dynamic directory listing.
    is_overwrite -- overwrise allowed?
    """
    if '{by-user}' in path:
        # replace {by-user} with all user names and perform as many directory
        # registrations as there are users in the system. Use the function:
        # VmmPyPlugin_UserDirectoryStrip(path) to remove user-name from path.
        for user in vmm.maps.user():
            userpath = path.replace('{by-user}', 'by-user/' + user['name'].replace('\\', '_').replace('/', '_'))
            VmmPyPlugin_FileRegisterDirectory(pid, userpath, fn_list_callback, is_overwrite)
        return
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
    if '{by-user}' in path:
        # replace {by-user} with all user names and perform as many directory
        # registrations as there are users in the system. Use the function:
        # VmmPyPlugin_UserDirectoryStrip(path) to remove user-name from path.
        for user in vmm.maps.user():
            userpath = path.replace('{by-user}', 'by-user/' + user['name'].replace('\\', '_').replace('/', '_'))
            VmmPyPlugin_FileUnregister(pid, userpath)
        return
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
    return -- tuple: <str path, str name, dict values>.
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
        return dir_path, entry, dir_entry[entry]
    raise RuntimeError('VmmPyPlugin_FileRetrieve: not found.')



def VmmPyPlugin_UserDirectoryStrip(path):
    """Strip a valid username on the format '/by-user/username' from path and
    return the stripped string and the user-dict [as given by vmm.maps.user()]

    Keyword arguments:
    path -- the path with the potential system username
    return -- str: path-stripped, dict: user-info. Fail: dict is None.

    Example:
    VmmPyPlugin_UserDirectoryStrip('plugin/by-user/George/file.txt') -> 'plugin/file.txt', {'va-reghive': 18446663847596163072, 'sid': 'S-1-5-21-3317879871-105768242-2947499445-1001', 'name': 'George'}
    """
    if not 'by-user/' in path:
        return path, None
    for user in vmm.maps.user():
        name = 'by-user/' + user['name'].replace('\\', '_').replace('/', '_') + '/'
        if name in path:
            return path.replace(name, ''), user
    return path, None



#------------------------------------------------------------------------------
# VmmPy LIGHT PLUGIN FUNCTIONALITY BELOW:
#------------------------------------------------------------------------------



def VmmPyPluginLight_InternalInitializePlugins():
    """Internal Use Only! - initialization function - Load Light Plugins.
    """
    import os
    import glob
    import threading
    global VmmPyPluginLight_registry
    VmmPyPluginLight_registry = {}
    path = os.path.dirname(__file__) + os.sep + 'plugins' + os.sep
    plugin_files = glob.glob(path + 'pyp_*.py')
    for plugin_file in plugin_files:
        df = plugin_file[plugin_file.index('pyp_')+4:-3].split('_') # [0]=ignore; [1]=root/user; [2]=dir; [3]=file
        if len(df) != 4 or len(df[2]) == 0 or len(df[3]) == 0 or (df[1] != 'root' and df[1] != 'user'):
            print(df)
            continue
        if df[1] == 'root':
            df[2] = df[2].replace('$', '/')
        else:
            df[2] = '$' + df[2].replace('$', '/')
        df[3] = df[3].replace('$', '_') + '.txt'
        if df[2] not in VmmPyPluginLight_registry:
            VmmPyPluginLight_registry[df[2]] = {'$list': None, '$lock': threading.Lock()}
        VmmPyPluginLight_registry[df[2]][df[3]] = {'file': df[3], 'plugin': plugin_file, 'data': None}
        if VmmPyPlugin_fPrintV:
            if df[1] == 'root':
                print("VmmPyPluginLight: Register '" + df[2] + '/' + df[3] + "'")
            else:
                print("VmmPyPluginLight: Register 'by-user/" + df[2][1:] + '/' + df[3] + "'")
    for dir in VmmPyPluginLight_registry:
        if dir[0] == '$':
            dir = '{by-user}/' + dir[1:]
        VmmPyPlugin_FileRegisterDirectory(False, dir, VmmPyPluginLight_InternalCallback_List)



def VmmPyPluginLight_InternalCallback_Refresh():
    """Internal Use Only!
    """
    for e in VmmPyPluginLight_registry.values():
        e['$list'] = None



def VmmPyPluginLight_InternalCallback_List(pid, path):
    """Internal Use Only!
    """
    path, user = VmmPyPlugin_UserDirectoryStrip(path)
    key = path if user == None else '$' + path
    if key not in VmmPyPluginLight_registry:
        return None
    if VmmPyPluginLight_registry[key]['$list'] == None:
        VmmPyPluginLight_Process(path, user, key)
    return VmmPyPluginLight_registry[key]['$list']



def VmmPyPluginLight_InternalCallback_Read(pid, file_path, file_name, file_attr, bytes_length, bytes_offset):
    """Internal Use Only!
    """
    path, user = VmmPyPlugin_UserDirectoryStrip(file_path)
    key = path if user == None else '$' + path
    if key not in VmmPyPluginLight_registry:
        return None
    if VmmPyPluginLight_registry[key]['$list'] == None:
        VmmPyPluginLight_Process(path, user, key)
    if file_name not in VmmPyPluginLight_registry[key]:
        return None
    return VmmPyPluginLight_registry[key][file_name]['data'][bytes_offset:bytes_length+bytes_offset]



def VmmPyPluginLight_Process(path, user, key):
    """Internal Use Only!
    """
    import threading
    import io
    import importlib.util
    from contextlib import redirect_stdout
    VmmPyPluginLight_registry[key]['$lock'].acquire()
    try:
        if VmmPyPluginLight_registry[key]['$list'] != None:
            return
        dlist = {}
        for k, d in VmmPyPluginLight_registry[key].items():
            if k[0] == '$':
                continue
            try:
                if VmmPyPlugin_fPrintVV:
                    print("VmmPyPluginLight: Process: '" + path + "/" + d['file'] + "'")
                spec = importlib.util.spec_from_file_location(d['plugin'], d['plugin'])
                module = importlib.util.module_from_spec(spec)
                setattr(module, 'vmm', vmm)
                setattr(module, 'path', path)
                setattr(module, 'user', user)
                io_stdout = io.StringIO()
                with redirect_stdout(io_stdout):
                    spec.loader.exec_module(module)
                data_str = io_stdout.getvalue()
            except Exception as e:
                data_str = ''
                if VmmPyPlugin_fPrintV:
                    print("------\nVmmPyPluginLight: Exception: Plugin: '" + d['plugin'] + "'\n" + str(e) + "\n------")
            data_bytes = data_str.encode()
            d['data'] = data_bytes
            dlist[d['file']] = { 'size': len(data_bytes), 'read': VmmPyPluginLight_InternalCallback_Read, 'write': None  }
        VmmPyPluginLight_registry[key]['$list'] = dlist
    finally:
        VmmPyPluginLight_registry[key]['$lock'].release()



#------------------------------------------------------------------------------
# Initialize the VmmPyPlugin system and register it with the native code VMM.
#------------------------------------------------------------------------------

try:
    VmmPyPlugin_InternalInitialize()
except Exception as e:
    print(str(e))
