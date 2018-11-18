The Memory Process File System:
===============================
The Memory Process File System is an easy and convenient way of accessing physical memory as files a virtual file system. 

Easy trivial point and click memory analysis without the need for complicated commandline arguments! Access physical memory content and artifacts via files in a mounted virtual file system or via a feature rich .dll application library to include in your own projects!

<b>Analyze memory dump files</b> - or even <b>live memory in read-write mode</b> via linked [pcileech](https://github.com/ufrisk/pcileech/) and [pcileech-fpga](https://github.com/ufrisk/pcileech-fpga/) devices!

Use your favorite tools to analyze memory - use your favorite hex editors, your python and powershell scripts, your disassemblers - all will work trivally with the Memory Process File System by just reading and writing files!

<p align="center"><img src="https://github.com/ufrisk/MemProcFS/wiki/resources/proc_base2.png" height="190"/><img src="https://github.com/ufrisk/MemProcFS/wiki/resources/pciescreamer.jpeg" height="190"/><img src="https://github.com/ufrisk/MemProcFS/wiki/resources/proc_modules.png" height="190"/></p>


Include the Memory Process File System in your Python or C/C++ programming projects! Almost everything in the Memory Process File System is exposed via an easy-to-use API for use in your own projects! The Plugin friendly architecture allows users to easily extend the Memory Process File System with native C .DLL plugins or Python .py plugins - providing additional analysis capabilities!

<b>Please check out the [project wiki](https://github.com/ufrisk/MemProcFS/wiki)</b> for more in-depth detailed information about the file system itself, its API and its plugin modules!

Fast and easy memory analysis via mounted file system:
======================================================
No matter if you have no prior knowledge of memory analysis or are an advanced user the Memory Process File System (and the API) may be useful! Click around the memory objects in the file system

<p align="center"><img src="https://github.com/ufrisk/MemProcFS/wiki/resources/proc_procstruct.png" height="225"/><img src="https://github.com/ufrisk/MemProcFS/wiki/resources/proc_virt2phys.png" height="225"/></p>

Extensive Python and C/C++ API:
===============================
Everything in the Memory Process File System is exposed as APIs. APIs exist for both C/C++ `vmmdll.h` and Python `vmmpy.py`. The file system itself is made available virtually via the API without the need to mount it. Specialized process analysis and process alteration functionality is made easy by calling API functionality. It is possible to read both virtual process memory as well as physical memory! The example below shows reading 0x20 bytes from physical address 0x1000:
```
>>> from vmmpy import *
>>> VmmPy_InitializeFile('c:/temp/win10_memdump.raw')
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
Download or clone the Memory Process File System github repository. <b>Pre-built binaries are found in the files folder.</b> If the Memory Process File System is used as an API it is only dependant on the Microsoft Visual C++ Redistributables for Visual Studio 2017 (see below).

The Memory Process File System is dependant in the <b>Microsoft Visual C++ Redistributables for Visual Studio 2017</b>. They can be downloaded from Microsoft [here](https://go.microsoft.com/fwlink/?LinkId=746572). Alternatively, if installing the Dokany file system driver please install the <b>DokanSetup_redist</b> version and it will install the required redistributables.

Mounting the file system requires the <b>Dokany file system library</b> to be installed. Please download and install the latest version of Dokany at: https://github.com/dokan-dev/dokany/releases/latest It is recommended to download and install the <b>DokanSetup_redist</b> version.

Python support requires Python 3.6. The user may specify the path to the Python 3.6 installation with the command line parameter `-pythonhome`, alternatively download [Python 3.6 - Windows x86-64 embeddable zip file](https://www.python.org/downloads/windows/) and unzip its contents into the `files/python36` folder when using Python modules in the file system. To use the Python API a normal Python 3.6 installation for Windows is required.

PCILeech FPGA will require hardware as well as the _pcileech.dll_ and _FTD3XX.dll_ files to be dropped in the files folder. Please check out the [PCILeech](https://github.com/ufrisk/pcileech) project for instructions.

## Linux
The memory process file system is not yet supported on Linux. Linux support is planned for both the C/C++ and Python API and is a prioritized work item. FUSE file system support will take longer.

Examples:
=========
Start the Memory Process File System from the command line - possibly by using one of the examples below.

Or register the memory dump extension with MemProcFS.exe so that the file system is mounted when double-clicking on a memory dump file!

- mount the memory dump file as default M: <br>`memprocfs.exe -device c:\temp\win10x64-dump.raw`
- mount the memory dump file as default M with extra verbosity: <br>`memprocfs.exe -device c:\temp\win10x64-dump.raw -v`
- mount the memory dump file as S: <br>`memprocfs.exe -mount s -device c:\temp\win10x64-dump.raw`
- mount live target memory, in read/write mode, with PCILeech FPGA memory acquisition device: <br>`memprocfs.exe -device fpga`
- mount live target memory, in read/write mode, with TotalMeltdown vulnerability acquisition device: <br>`memprocfs.exe -device totalmeltdown`
- mount an arbitrary x64 memory dump by specifying the process or kernel page table base in the cr3 option: <br>`memprocfs.exe -device c:\temp\unknown-x64-dump.raw -cr3 0x1aa000`

Documentation:
==============
For additional documentation please check out the [project wiki](https://github.com/ufrisk/MemProcFS/wiki) for in-depth detailed information about the file system itself, its API and its plugin modules!

Building:
=========
Pre-built binaries and other supporting files are found in the files folder. The Memory Process File System binaries are built with Visual Studio 2017. No binaries currently exists for Linux (future support - please see Current Limitations & Future Development below).

Detailed build instructions may be found in the [Wiki](https://github.com/ufrisk/MemProcFS/wiki) in the [Building](https://github.com/ufrisk/MemProcFS/wiki/Dev:-Building) section.

Current Limitations & Future Development:
=========================================
The Memory Process File System is currently limited to analyzing Windows x64 memory dumps (other x64 dumps in a very limited way). Also, the Memory Process File System currently does not run on Linux.

Please find some ideas for possible future expansions of the memory process file system listed below. This is a list of ideas - not a list of features that will be implemented. Even though some items are put as prioritized there is no guarantee that they will be implemented in a timely fashion.

### Prioritized items:
- More/new plugins.
- Linux support - .so files for easy and convenient Linux API access from both C/C++ and Python.
- Additional core functionality (exported functions in .DLL). Please request in Issues section if ideas exist.

### Other items:
- PFN support.
- Multithreading support in main library.
- Linux support in mounted FUSE file system.
- Support for analyzing x64 Linux, macOS and UEFI memory dumps.
- Support for non-x64 memory models (such as x86 32-bit).
- Hash lookup of executable memory pages in DB.

Links:
======
* Blog: http://blog.frizk.net
* Twitter: https://twitter.com/UlfFrisk
* PCILeech: https://github.com/ufrisk/pcileech/
* YouTube: https://www.youtube.com/channel/UC2aAi-gjqvKiC7s7Opzv9rg

Changelog:
===================
v1.0
* Initial Release.
