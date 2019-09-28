The Memory Process File System:
===============================
The Memory Process File System is an easy and convenient way of accessing physical memory as files a virtual file system. 

Easy trivial point and click memory analysis without the need for complicated commandline arguments! Access memory content and artifacts via files in a mounted virtual file system or via a feature rich application library to include in your own projects!

Analyze memory dump files, <b>live memory</b> via [DumpIt](https://www.comae.com/) or WinPMEM, <b>live memory in read-write mode</b> via linked [PCILeech](https://github.com/ufrisk/pcileech/) and [PCILeech-FPGA](https://github.com/ufrisk/pcileech-fpga/) devices!

It's even possible to connect to a remote LeechAgent memory acquisition agent over a secured connection - allowing for remote live memory incident response - even over higher latency low band-width connections!

Use your favorite tools to analyze memory - use your favorite hex editors, your python and powershell scripts, WinDbg or your favorite disassemblers and debuggers - all will work trivally with the Memory Process File System by just reading and writing files!

<p align="center"><img src="https://github.com/ufrisk/MemProcFS/wiki/resources/proc_base2.png" height="190"/><img src="https://github.com/ufrisk/MemProcFS/wiki/resources/pciescreamer.jpeg" height="190"/><img src="https://github.com/ufrisk/MemProcFS/wiki/resources/proc_modules.png" height="190"/></p>


Include the Memory Process File System in your Python or C/C++ programming projects! Almost everything in the Memory Process File System is exposed via an easy-to-use API for use in your own projects! The Plugin friendly architecture allows users to easily extend the Memory Process File System with native C .DLL plugins or Python .py plugins - providing additional analysis capabilities!

<b>Please check out the [project wiki](https://github.com/ufrisk/MemProcFS/wiki)</b> for more in-depth detailed information about the file system itself, its API and its plugin modules!

<b>Please check out the [LeechCore project](https://github.com/ufrisk/LeechCore)</b> for information about supported memory acquisition methods and remote memory access via the LeechService.

<b>To get going clone the sources in the repository or download the [latest binaries, modules and configuration files](https://github.com/ufrisk/MemProcFS/releases/latest) from the releases section.</b>

Fast and easy memory analysis via mounted file system:
======================================================
No matter if you have no prior knowledge of memory analysis or are an advanced user the Memory Process File System (and the API) may be useful! Click around the memory objects in the file system

<p align="center"><img src="https://github.com/ufrisk/MemProcFS/wiki/resources/proc_procstruct.png" height="225"/><img src="https://github.com/ufrisk/MemProcFS/wiki/resources/proc_virt2phys.png" height="225"/></p>

Extensive Python and C/C++ API:
===============================
Everything in the Memory Process File System is exposed as APIs. APIs exist for both C/C++ `vmmdll.h` and Python `vmmpy.py`. The file system itself is made available virtually via the API without the need to mount it. Specialized process analysis and process alteration functionality is made easy by calling API functionality. It is possible to read both virtual process memory as well as physical memory! The example below shows reading 0x20 bytes from physical address 0x1000:
```
>>> from vmmpy import *
>>> VmmPy_Initialize('c:/temp/win10_memdump.raw')
>>> print(VmmPy_UtilFillHexAscii(VmmPy_MemRead(-1, 0x1000, 0x20)))
0000    e9 4d 06 00 01 00 00 00  01 00 00 00 3f 00 18 10   .M..........?...
0010    00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00   ................
```

Modular Plugin Architecture:
============================
Anyone is able to extend the Memory Process File System with custom plugins! It is as easy as dropping a python file in the correct directory or compiling a tiny C DLL. Existing functionality is already implemented as well documented C and Python plugins!

Installing:
===========
## Windows
<b>Get the latest [binaries, modules and configuration files](https://github.com/ufrisk/MemProcFS-dev/releases/latest) from the latest release.</b> Alternatively clone the repository and build from source. If the Memory Process File System is used as an API it is only dependant on the Microsoft Visual C++ Redistributables for Visual Studio 2019 (see below).

The Memory Process File System is dependant on the [LeechCore project](https://github.com/ufrisk/LeechCore) for memory acquisition. The necessary _leechcore.dll_ file is already pre-built and included together with the pre-built binaries.

The Memory Process File System is also dependant in the <b>Microsoft Visual C++ Redistributables for Visual Studio 2019</b>. They can be downloaded from Microsoft [here](https://go.microsoft.com/fwlink/?LinkId=746572). Alternatively, if installing the Dokany file system driver please install the <b>DokanSetup_redist</b> version and it will install the required redistributables.

Mounting the file system requires the <b>Dokany file system library</b> to be installed. Please download and install the latest version of Dokany at: https://github.com/dokan-dev/dokany/releases/latest It is recommended to download and install the <b>DokanSetup_redist</b> version.

Python support requires Python 3.6 or later. The user may specify the path to the Python installation with the command line parameter `-pythonhome`, alternatively download [Python 3.7 - Windows x86-64 embeddable zip file](https://www.python.org/downloads/windows/) and unzip its contents into the `files/python` folder when using Python modules in the file system. To use the Python API a normal 64-bit Python 3.6 or later installation for Windows is required.

To capture live memory (without PCILeech FPGA hardware) download [DumpIt](https://www.comae.com/) and start the Memory Process File System via the DumpIt /LIVEKD mode. Alternatively, get WinPMEM by downloading the most recent signed [WinPMEM driver](https://github.com/Velocidex/c-aff4/tree/master/tools/pmem/resources/winpmem) and place it alongside MemProcFS - detailed instructions in the [LeechCore Wiki](https://github.com/ufrisk/LeechCore/wiki/Device_WinPMEM).

PCILeech FPGA will require hardware as well as _FTD3XX.dll_ to be dropped alongside the MemProcFS binaries. Please check out the [LeechCore](https://github.com/ufrisk/LeechCore) project for instructions.

## Linux
The memory process file system is not yet supported on Linux.

Examples:
=========
Start the Memory Process File System from the command line - possibly by using one of the examples below.

Or register the memory dump file extension with MemProcFS.exe so that the file system is automatically mounted when double-clicking on a memory dump file!

- mount the memory dump file as default M: <br>`memprocfs.exe -device c:\temp\win10x64-dump.raw`
- mount the memory dump file as default M: with extra verbosity: <br>`memprocfs.exe -device c:\temp\win10x64-dump.raw -v`
- mount the memory dump file as default M: with extra extra verbosity: <br>`memprocfs.exe -device c:\temp\win10x64-dump.raw -v -vv`
- mount the memory dump file as S: <br>`memprocfs.exe -mount s -device c:\temp\win10x64-dump.raw`
- mount live target memory, in verbose read-only mode, with DumpIt in /LIVEKD mode: <br>`DumpIt.exe /LIVEKD /A memprocfs.exe /C "-v"`
- mount live target memory, in read-only mode, with WinPMEM driver: <br>`memprocfs.exe -device pmem`
- mount live target memory, in read/write mode, with PCILeech FPGA memory acquisition device: <br>`memprocfs.exe -device fpga`
- mount live target memory, in read/write mode, with TotalMeltdown vulnerability acquisition device: <br>`memprocfs.exe -device totalmeltdown`
- mount an arbitrary x64 memory dump by specifying the process or kernel page table base in the cr3 option: <br>`memprocfs.exe -device c:\temp\unknown-x64-dump.raw -cr3 0x1aa000`

Documentation:
==============
For additional documentation please check out the [project wiki](https://github.com/ufrisk/MemProcFS/wiki) for in-depth detailed information about the file system itself, its API and its plugin modules! For additional information about memory acqusition methods check out the [LeechCore project](https://github.com/ufrisk/LeechCore/)

Also check out my Microsoft BlueHatIL 2019 talk _Practical Uses for Hardware-assisted Memory Visualization_ about MemProcFS at Youtube below:
<p align="center"><a href="https://www.youtube.com/watch?v=Da_9SV9FA34" alt="Microsoft BlueHatIL 2019 talk - Practical Uses for Hardware-assisted Memory Visualization" target="_new"><img src="http://img.youtube.com/vi/Da_9SV9FA34/0.jpg" height="250"/></a></p>

Building:
=========
<b>Pre-built [binaries, modules and configuration files](https://github.com/ufrisk/MemProcFS-dev/releases/latest) are found in the latest release.</b>. The Memory Process File System binaries are built with Visual Studio. MemProcFS is not supported on Linux.

Detailed build instructions may be found in the [Wiki](https://github.com/ufrisk/MemProcFS/wiki) in the [Building](https://github.com/ufrisk/MemProcFS/wiki/Dev_Building) section.

Current Limitations & Future Development:
=========================================
The Memory Process File System is currently limited to analyzing Windows (32-bit and 64-bit XP to 10) memory dumps (other x64 dumps in a very limited way). Also, the Memory Process File System currently does not run on Linux.

Please find some ideas for possible future expansions of the memory process file system listed below. This is a list of ideas - not a list of features that will be implemented. Even though some items are put as prioritized there is no guarantee that they will be implemented in a timely fashion.

### Prioritized items:
- More/new plugins.

### Other items:
- PFN support.
- Support for analyzing x64 Linux, macOS and UEFI memory dumps.
- Hash lookup of executable memory pages in DB.

License:
======
The project source code is released under GPLv3. Some bundled Microsoft redistributable binaries are released under separate licenses.

Links:
======
* Blog: http://blog.frizk.net
* Twitter: https://twitter.com/UlfFrisk
* PCILeech: https://github.com/ufrisk/pcileech/
* LeechCore: https://github.com/ufrisk/LeechCore/
* YouTube: https://www.youtube.com/channel/UC2aAi-gjqvKiC7s7Opzv9rg

Changelog:
===================
v1.0
* Initial Release.

v1.1-v1.2
* Various updates. please see individual relases for more information.

v2.0
* Major new release with multiple changes. Most noteworty are:
* Multi-Threading support.
* Performance optimizations.
* Memory acqusition via the [LeechCore](https://github.com/ufrisk/LeechCore/) library with additional support for:
  * Live memory acquisition with DumpIt in /LIVEKD mode or loaded kernel driver.
  * Support for Microsoft Crash Dumps - such as created by default by [Comae DumpIt](https://www.comae.com).
  * Hyper-V save files.
  * Remote capture via remotely installed LeechService.

v2.1
* New APIs:
  * IAT/EAT hook functionality.
  * Limited Windows 10 MemCompression support.
* Bug fixes.

v2.2
* New API:
  * Force refresh of process list and caches.

v2.3
* Project upgrade to Visual Studio 2019.
* Bug fixes.
* Additional plugins for download available from [MemProcFS-plugins](https://github.com/ufrisk/MemProcFS-plugins).
* Python plugin updater - easy installs and updates from [MemProcFS-plugins](https://github.com/ufrisk/MemProcFS-plugins).
* Pypykatz plugin for 'mimikatz' style functionality available as separate download from [MemProcFS-plugins](https://github.com/ufrisk/MemProcFS-plugins) project. Thanks to [@SkelSec](https://twitter.com/SkelSec) for the contribution.
* Python API support for version >3.6 (i.e Python 3.7 now fully supported).

v2.4
* Bug fixes.
* New module: [PEDump](https://github.com/ufrisk/MemProcFS/wiki/FS_Process_PEDump) - best-effort reconstructed PE modules (.exe, .dll and .sys files) in process pedump sub-folder.

v2.5
* Performance optimizations.
* Windows transition page support.
* New module: [Registry](https://github.com/ufrisk/MemProcFS/wiki/FS_Registry) - best-effort reconstructed registry hives in the registry/hive_files/ sub-folder.

v2.6
* Additional performance optimizations.
* Support for process long names (previously capped to 15 chars), image path and command line.
* New module: [SysInfo](https://github.com/ufrisk/MemProcFS/wiki/FS_SysInfo) - system information including OS version number and process tree with command line.

v2.7
* Bug fixes and optimizations.
* Network support: TCP connections added to [SysInfo](https://github.com/ufrisk/MemProcFS/wiki/FS_SysInfo) module.
* New module: [Phys2Virt](https://github.com/ufrisk/MemProcFS/wiki/FS_Phys2Virt) - search individual or all process address spaces for virtual addresses that map to specific physical address.

v2.8
* Bug fixes.
* Windows 10 Compressed Memory support.

v2.9
* Bug fixes and major internal refactorings.
* Full Registry support - Explore the Windows registry in the file system or via the API.
* NB! The v2.9 C/C++ API vfs (virtual file system) API is incompatible with earlier versions.

[v2.10](https://github.com/ufrisk/MemProcFS/releases/tag/v2.10)
* Dump file support - create a WinDbg compatible `memory.dmp` file in the root folder.
* Early .pdb debugging subsystem with Microsoft symbol server integration.
* Process create/terminate timestamps on process directories.

Latest
* Bug fixes.
* Move binaries into releases section.
