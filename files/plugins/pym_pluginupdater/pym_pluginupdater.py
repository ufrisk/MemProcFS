# pym_pluginupdater.py
#
# Python plugin which allows convenient auto-installation of new or updated
# plugins directly from the plugin directory on Github. This is advantageous
# since it both allows for an updated plugins and to keep non-core potentially
# controversial, but awesome plugins outside the main MemProcFS project.
#
# https://github.com/ufrisk/
#
# (c) Ulf Frisk, 2019-2023
# Author: Ulf Frisk, pcileech@frizk.net
#

import os
import time
import memprocfs
from vmmpyplugin import *
from threading import Thread

text_upgrade = """AN UPGRADE TO THE PLUGIN EXISTS!
================================
To start automatic download and upgrading change something in this file and save it.

Any save of any changes to this file will trigger automatic upgrade of the plugin. Note! save from normal notepad doesn't work at the moment - Notepad++ or similar is recommended.

When the upgrade is complete a message will appear in console window for MemProcFS. MemProcFS will have to be restarted for changes to take affect after a successful upgrade.


MANUAL UPGRADE
==============
If the automatic upgrade fails it's quick and easy to upgrade manually!

The plugin is available for download from https://github.com/ufrisk/MemProcFS-Plugins

Upgrading is quick and easy - just copy the plugin files into the correct plugin directory!

Please see installation instructions at: https://github.com/ufrisk/MemProcFS-Plugins


PLUGIN INFORMATION
==================
"""

text_install = """THIS PLUGIN IS NOT YET INSTALLED BUT MAY BE INSTALLED AUTOMATICALLY!
====================================================================
To start automatic download and installation change something in this file and save it.

Any save of any changes to this file will trigger automatic installation of the plugin. Note! save from normal notepad doesn't work at the moment - Notepad++ or similar is recommended.

When the installation is complete a message will appear in console window for MemProcFS. MemProcFS will have to be restarted for changes to take affect after a successful installation.


MANUAL INSTALLATION
===================
If the automatic installation fails it's quick and easy to install manually!

The plugin is available for download from https://github.com/ufrisk/MemProcFS-Plugins

Installation is quick and easy - just copy the plugin files into the correct plugin directory!

Please see installation instructions at: https://github.com/ufrisk/MemProcFS-Plugins


PLUGIN INFORMATION
==================
"""


text_desc_pypykatz = "The Pypykatz plugin for MemProcFS provides 'mimikatz' like functionality for MemProcFS"
text_desc_regsecrets = "The RegSecrets plugin for MemProcFS provides 'mimikatz' like functionality for MemProcFS."

plugin_dir = os.path.realpath(__file__ + os.sep + '..' + os.sep + '..' + os.sep) + os.sep + 'pym_'

plugins = {
    'regsecrets': {
        'name': 'regsecrets',
        'files': ['__init__.py', 'pym_regsecrets.py', 'version.txt'],
        'pid': None,
        'files_installinfo': ['regsecrets/regsecrets-install.txt'],
        'installed': False,
        'version_installed': '0.0.0',
        'version_remote': '0.0.0',
        'upgrade': False,
        'text_upgrade': text_upgrade + text_desc_regsecrets,
        'text_install': text_install + text_desc_regsecrets,
        'text_completed': 'Additional dependencies: "pip install pypykatz aiowinreg" may be required.',
    }
}

def VersionTuple(v):
    """ Parse version number
    """
    return tuple(map(int, (v.split("."))))



def PluginsUpdateInfoInstalledAndVersion():
    # Retrieve installed plugins and available plugin (from Github).
    # Retrieve installed plugins and their versions.
    fInstalledPlugins = False
    for name in plugins:
        plugin = plugins[name]
        try:
            fd = open(plugin_dir + name + os.sep + 'version.txt')
            plugin['version_installed'] = fd.readline()
            plugin['installed'] = True
            fd.close()
            fInstalledPlugins = True
        except:
            plugin['installed'] = False
            pass
    if not fInstalledPlugins:
        return
    # Retrieve remotely available plugin versions from Github.
    from urllib.request import urlopen
    try:
        data = urlopen('https://raw.githubusercontent.com/ufrisk/MemProcFS-plugins/master/versions.txt').read().decode('utf-8')
    except:
        return
    cloop = 0
    for ln in data.splitlines():
        cloop += 1
        if cloop > 100:
            return
        try:
            t = ln.split()
            p = plugins[t[0]]
            p['version_remote'] = t[1]
            if p['installed'] and VersionTuple(p['version_installed']) < VersionTuple(p['version_remote']):
                p['upgrade'] = True
        except:
            pass



def GetPluginFromName(file_name):
    # Retrieve the plugin name from the file name.
    if file_name[-12:] == '-upgrade.txt':
        plugin_name = file_name[:-12]
        if plugin_name.isalpha():
            return plugin_name, False
    if file_name[-12:] == '-install.txt':
        plugin_name = file_name[:-12]
        if plugin_name.isalpha():
            return plugin_name, True
    raise Exception('unknown plugin')



def WriteFile(pid, file_path, file_name, file_attr, bytes_data, bytes_offset):
    # Write triggers installation/upgrade of the identified plugin.
    plugin_name, plugin_is_install = GetPluginFromName(file_name)
    try:
        import urllib.request
        path_src = 'https://raw.githubusercontent.com/ufrisk/MemProcFS-plugins/master/files/plugins/pym_' + plugin_name + '/'
        path_dst = '.' + os.sep + 'plugins' + os.sep + 'pym_' + plugin_name + os.sep
        try:
            os.mkdir(path_dst)
        except:
            pass
        for file in plugins[plugin_name]['files']:
            urllib.request.urlretrieve(path_src + file, path_dst + file)
        print(plugins[plugin_name]['text_completed'])
        print('Auto-installation of ' + plugin_name + ' module is hopefully completed.')
        print('*** Restart MemProcFS for changes to take affect. ***')
    except Exception as e:
        print('Auto-installation of plugin failed. Please install manually.')
        print('Manual installation from https://github.com/ufrisk/MemProcFS-Plugins')
        print(str(e))



def ReadFile(pid, file_path, file_name, file_attr, bytes_length, bytes_offset):
    # Read plugin-dependant file contents for installation information or upgrade information.
    plugin_name, plugin_is_install = GetPluginFromName(file_name)
    return plugins[plugin_name]['text_install' if plugin_is_install else 'text_upgrade'].encode()[bytes_offset:bytes_offset+bytes_length]



def Initialize_Thread():
    time.sleep(2)
    PluginsUpdateInfoInstalledAndVersion()
    for name in plugins:
        try:
            p = plugins[name]
            if p['upgrade']:
                VmmPyPlugin_FileRegister(None, 'plugins/' + name + '-upgrade.txt', len(p['text_upgrade']), ReadFile, WriteFile)
            if not p['installed']:
                VmmPyPlugin_FileRegister(None, 'plugins/' + name + '-install.txt', len(p['text_install']), ReadFile, WriteFile)
                for f in p['files_installinfo']:
                    VmmPyPlugin_FileRegister(p['pid'], f, len(p['text_install']), ReadFile, WriteFile)
        except:
            pass

def Initialize(target_system, target_memorymodel):
    # Initialize the pluginupdater module.
    # A separate thread is created since part of initialization is retrieving
    # a version information file from Github. If the network call takes time we
    # do not wish to stop further MemProcFS initialization - hence the Thread.
    thread = Thread(target = Initialize_Thread)
    thread.start()
