The Memory Process File System:
===============================
The Memory Process File System (MemProcFS) is an easy and convenient way of viewing physical memory as files in a virtual file system. 

Easy trivial point and click memory analysis without the need for complicated commandline arguments! Access memory content and artifacts via files in a mounted virtual file system or via a feature rich application library to include in your own projects!

Analyze memory dump files, <b>live memory</b> via DumpIt or WinPMEM, <b>live memory in read-write mode</b> via linked [PCILeech](https://github.com/ufrisk/pcileech/) and [PCILeech-FPGA](https://github.com/ufrisk/pcileech-fpga/) devices!

It's even possible to connect to a remote LeechAgent memory acquisition agent over a secured connection - allowing for remote live memory incident response - even over higher latency low band-width connections! Peek into Hyper-V Virtual Machines with [LiveCloudKd](https://github.com/ufrisk/LeechCore/wiki/Device_LiveCloudKd)!

Use your favorite tools to analyze memory - use your favorite hex editors, your python and powershell scripts, WinDbg or your favorite disassemblers and debuggers - all will work trivally with MemProcFS by just reading and writing files!

<p align="center"><img src="https://github.com/ufrisk/MemProcFS/wiki/resources/proc_base3.png" height="190"/><img src="https://github.com/ufrisk/MemProcFS/wiki/resources/pciescreamer.jpeg" height="190"/><img src="https://github.com/ufrisk/MemProcFS/wiki/resources/proc_modules.png" height="190"/></p>


Include MemProcFS in your C/C++, C# or Python programming projects! Everything in MemProcFS is exposed via an easy-to-use API for use in your own projects! The Plugin friendly architecture allows users to easily extend MemProcFS with native C .DLL plugins or Python .py plugins - providing additional analysis capabilities!

MemProcFS is available on Python pip. Just type `pip install memprocfs` and you're ready to go! Please see the [Python API documentation](https://github.com/ufrisk/MemProcFS/wiki/API_Python) and the [YouTube demo](https://youtu.be/pLFU1lxBNM0) for examples and usage!

<b>Please check out the [project wiki](https://github.com/ufrisk/MemProcFS/wiki)</b> for more in-depth detailed information about the file system itself, its API and its plugin modules!

<b>Please check out the [LeechCore project](https://github.com/ufrisk/LeechCore)</b> for information about supported memory acquisition methods and remote memory access via the LeechService.

To get going clone the sources in the repository or download the [latest binaries, modules and configuration files](https://github.com/ufrisk/MemProcFS/releases/latest) from the releases section and **check out the [guide](https://github.com/ufrisk/MemProcFS/wiki).**

Fast and easy memory analysis via mounted file system:
======================================================
No matter if you have no prior knowledge of memory analysis or are an advanced user MemProcFS (and its API) may be useful! Click around the memory objects in the file system

<p align="center"><img src="https://github.com/ufrisk/MemProcFS/wiki/resources/proc_procstruct.png" height="225"/><img src="https://github.com/ufrisk/MemProcFS/wiki/resources/proc_virt2phys.png" height="225"/></p>

Extensive Python, C# and C/C++ API:
===============================
Everything in MemProcFS is exposed as APIs. APIs exist for both C/C++ `vmmdll.h`, C# `vmmsharp.cs` and Python `memprocfs.py`. The file system itself is made available virtually via the API without the need to mount it. SIt is possible to read both virtual process memory as well as physical memory! The example below shows reading 0x20 bytes from physical address 0x1000:
```
>>> import memprocfs
>>> vmm = memprocfs.Vmm(['-device', 'c:/temp/win10_memdump.raw'])
>>> print(vmm.hex( vmm.memory.read(0x1000, 0x20) ))
0000    e9 4d 06 00 01 00 00 00  01 00 00 00 3f 00 18 10   .M..........?...
0010    00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00   ................
```

Modular Plugin Architecture:
============================
Anyone is able to extend MemProcFS with custom plugins! It is as easy as dropping a python file in the correct directory or compiling a tiny C DLL. Existing functionality is already implemented as well documented C and Python plugins!

Installing:
===========
<b>Get the latest [binaries, modules and configuration files](https://github.com/ufrisk/MemProcFS/releases/latest) from the latest release.</b> Alternatively clone the repository and build from source.

MemProcFS is dependent on the [LeechCore project](https://github.com/ufrisk/LeechCore) for memory acquisition. The necessary _leechcore.dll_ / _leechcore.so_ file is already pre-built and included together with the pre-built binaries.

## Windows
Mounting the file system requires the <b>Dokany file system library</b> to be installed. Please download and install the latest version of Dokany at: https://github.com/dokan-dev/dokany/releases/latest It is recommended to download and install the <b>DokanSetup_redist</b> version.

Python support requires Python 3.6 or later. The user may specify the path to the Python installation with the command line parameter `-pythonhome`, alternatively download [Python 3.7 - Windows x86-64 embeddable zip file](https://www.python.org/downloads/windows/) and unzip its contents into the `files/python` folder when using Python modules in the file system. To use the Python API a normal 64-bit Python 3.6 or later installation for Windows is required.

To capture live memory (without PCILeech FPGA hardware) download [DumpIt](https://www.comae.com/) and start MemProcFS via DumpIt /LIVEKD mode. Alternatively, get WinPMEM by downloading the most recent signed [WinPMEM driver](https://github.com/Velocidex/c-aff4/tree/master/tools/pmem/resources/winpmem) and place it alongside MemProcFS - detailed instructions in the [LeechCore Wiki](https://github.com/ufrisk/LeechCore/wiki/Device_WinPMEM).

PCILeech FPGA will require hardware as well as _FTD3XX.dll_ to be dropped alongside the MemProcFS binaries. Please check out the [LeechCore](https://github.com/ufrisk/LeechCore) project for instructions.

## Linux
MemProcFS is dependent on packages, please do a `sudo apt-get install libusb-1.0 fuse openssl lz4` before trying out MemProcFS. If building from source please check out the guide about [MemProcFS on Linux](https://github.com/ufrisk/MemProcFS/wiki/_Linux).

Examples:
=========
Start MemProcFS from the command line - possibly by using one of the examples below.

Or register the memory dump file extension with MemProcFS.exe so that the file system is automatically mounted when double-clicking on a memory dump file!

- mount the memory dump file as /home/pi/mnt/ on Linux: <br>`./memprocfs -mount /home/pi/linux -device /dumps/win10x64-dump.raw`
- mount the memory dump file as default M: <br>`memprocfs.exe -device c:\temp\win10x64-dump.raw`
- mount the memory dump file as default M: with extra verbosity: <br>`memprocfs.exe -device c:\temp\win10x64-dump.raw -v`
- mount the memory dump file as default M: with extra extra verbosity: <br>`memprocfs.exe -device c:\temp\win10x64-dump.raw -v -vv`
- mount the memory dump file as S: <br>`memprocfs.exe -mount s -device c:\temp\win10x64-dump.raw`
- mount live target memory, in verbose read-only mode, with DumpIt in /LIVEKD mode: <br>`DumpIt.exe /LIVEKD /A memprocfs.exe /C "-v"`
- mount live target memory, in read-only mode, with WinPMEM driver: <br>`memprocfs.exe -device pmem`
- mount live target memory, in read/write mode, with PCILeech FPGA memory acquisition device: <br>`memprocfs.exe -device fpga -memmap auto`
- mount a memory dump with a corresponding page files: <br>`memprocfs.exe -device unknown-x64-dump.raw -pagefile0 pagefile.sys -pagefile1 swapfile.sys`

Documentation:
==============
For additional documentation please check out the [project wiki](https://github.com/ufrisk/MemProcFS/wiki) for in-depth detailed information about the file system itself, its API and its plugin modules! For additional information about memory acqusition methods check out the [LeechCore project](https://github.com/ufrisk/LeechCore/)

Also check out my Microsoft BlueHatIL 2019 talk _Practical Uses for Hardware-assisted Memory Visualization_ and my Disobey 2020 talk _Live Memory Attacks and Forensics_ about MemProcFS.

<p align="center"><a href="https://www.youtube.com/watch?v=Da_9SV9FA34" alt="Microsoft BlueHatIL 2019 talk - Practical Uses for Hardware-assisted Memory Visualization" target="_new"><img src="http://img.youtube.com/vi/Da_9SV9FA34/0.jpg" height="250"/></a> <a href="https://youtu.be/mca3rLsHuTA?t=952" alt="Disobey 2020 talk - Live Memory Attacks and Forensics" target="_new"><img src="http://img.youtube.com/vi/mca3rLsHuTA/0.jpg" height="250"/></a></p>


Building:
=========
<b>Pre-built [binaries, modules and configuration files](https://github.com/ufrisk/MemProcFS/releases/latest) are found in the latest release.</b>. MemProcFS binaries are built with Visual Studio. MemProcFS is not supported on Linux.

Detailed build instructions may be found in the [Wiki](https://github.com/ufrisk/MemProcFS/wiki) in the [Building](https://github.com/ufrisk/MemProcFS/wiki/Dev_Building) section.

Current Limitations & Future Development:
=========================================
MemProcFS is currently limited to analyzing Windows (32-bit and 64-bit XP to 10) memory dumps.

Some features are missing in Linux version (compressed windows memory and offline symbols). This both limits and degrades the analysis on Linux systems. These features are planned for future versions.

Please find some ideas for possible future expansions of the memory process file system listed below. This is a list of ideas - not a list of features that will be implemented. Even though some items are put as prioritized there is no guarantee that they will be implemented in a timely fashion.

### Prioritized items:
- More/new plugins.

### Other items:
- Hash lookup of executable memory pages in DB.
- Forensic mode more analysis tasks.

License:
========
The project source code is released under: GNU Affero General Public License v3.0. Some bundled dependencies and plugins are released under GPLv3. Some bundled Microsoft redistributable binaries are released under separate licenses. Alternative licensing may be possible.

Contributing:
=============
PCILeech, MemProcFS and LeechCore are open source but not open contribution. PCILeech, MemProcFS and LeechCore offers a highly flexible plugin architecture that will allow for contributions in the form of plugins. If you wish to make a contribution, other than a plugin, to the core projects please contact me before starting to develop.

Links:
======
* Twitter: [![Twitter](https://img.shields.io/twitter/follow/UlfFrisk?label=UlfFrisk&style=social)](https://twitter.com/intent/follow?screen_name=UlfFrisk)
* Discord: [![Discord | Porchetta Industries](https://img.shields.io/discord/736724457258745996.svg?label=&logo=discord&logoColor=ffffff&color=7389D8&labelColor=6A7EC2)](https://discord.gg/sEkn3aa)
* PCILeech: https://github.com/ufrisk/pcileech
* PCILeech FPGA: https://github.com/ufrisk/pcileech-fpga
* LeechCore: https://github.com/ufrisk/LeechCore
* MemProcFS: https://github.com/ufrisk/MemProcFS
* YouTube: https://www.youtube.com/channel/UC2aAi-gjqvKiC7s7Opzv9rg
* Blog: http://blog.frizk.net

Links - Related Projects:
=========================
* MemProcFSHunter: https://github.com/memprocfshunt/MemProcFSHunter
* MemProcFS-Analyzer: https://github.com/evild3ad/MemProcFS-Analyzer

Support PCILeech/MemProcFS development:
=======================================
PCILeech and MemProcFS is free and open source!

I put a lot of time and energy into PCILeech and MemProcFS and related research to make this happen. Some aspects of the projects relate to hardware and I put quite some money into my projects and related research. If you think PCILeech and/or MemProcFS are awesome tools and/or if you had a use for them it's now possible to contribute by becoming a sponsor! 
 
If you like what I've created with PCIleech and MemProcFS with regards to DMA, Memory Analysis and Memory Forensics and would like to give something back to support future development please consider becoming a sponsor at: [`https://github.com/sponsors/ufrisk`](https://github.com/sponsors/ufrisk)

To all my sponsors, Thank You 💖 

All sponsorships are welcome, no matter how large or small. I especially wish to thank my **bronze sponsors**: [grandprixgp](https://github.com/grandprixgp).

Changelog:
===================
<details><summary>Previous releases (click to expand):</summary>
 
v1.0
* Initial Release.

v1.1-v2.10
* Various updates. Please see individual relases for more information.

[v3.0](https://github.com/ufrisk/MemProcFS/releases/tag/v3.0)
* Major release with new features, optimizations and refactorings.
* New virtual memory core for increased speed and memory recovery:
  * VAD (virtual address descriptor) support.
  * Win10 memory decompression bug-fixes.
  * Pagefile support.
* Handles.
* Threads.
* API: new features and updates (module names from ansi to wide string).

[v3.1](https://github.com/ufrisk/MemProcFS/releases/tag/v3.1)
* Bug fixes and refactorings.
* Code signing of binaries.
* New Features:
  * Users.
  * Volatile registry keys.
  * File recovery via Handles and Vads.  

[v3.2](https://github.com/ufrisk/MemProcFS/releases/tag/v3.2)
* Bug fixes.
* Support for low-memory x64 systems.
* New Features:
  * Certificates.
  * Physical memory map.
  * Per-page physical memory information (PFN database).
  * Registry "big data" value type support.

[v3.3](https://github.com/ufrisk/MemProcFS/releases/tag/v3.3)
* Bug fixes.
* Better write support.
* AMD Ryzen FPGA support.
* Module map: new info - Full .DLL Path.
* Thread map: new info - CPU registers.
* New forensic mode:
  * Timelining.
  * NTFS MFT parsing.
  * SQLITE database generation.
* New Features:
  * Minidump .DMP file generation for individual processes.
  * Syscalls - nt & win32k.
  
[v3.4](https://github.com/ufrisk/MemProcFS/releases/tag/v3.4)
* Bug fixes.
* Support for [LiveCloudKd](https://github.com/ufrisk/LeechCore/wiki/Device_LiveCloudKd).
* Network UDP and TCP listen socket support.
* C# API and examples - located in `vmmsharp` project.

[v3.5](https://github.com/ufrisk/MemProcFS/releases/tag/v3.5)
* Bug fixes.
* New Features:
  * Minidump for live processes.
  * Services information.
  * Memmap: Verbose VAD with individual page info.

[v3.6](https://github.com/ufrisk/MemProcFS/releases/tag/v3.6)
* Bug fixes & refactorings.
* NB! Breaking C/C++ API changes (function renames).
* New Features:
  * Unloaded modules.
  * [FindEvil](https://github.com/ufrisk/MemProcFS/wiki/FS_FindEvil) - find select signs of injections and malware.
 
[v3.7](https://github.com/ufrisk/MemProcFS/releases/tag/v3.7)
* Updates & Improvements:
  * Registry.
  * Services.
  * NTFS MFT.
* New Features:
  * Time: process-time, boot-time, current-time, timezone.
  * Python Light Plugins: print('file system plugins as easy as Python print!')
  * Registry Parsing: usb-storage, bluetooth, wallpapers and more in 'py/reg' & 'py/by-user/reg'.
  
[v3.8](https://github.com/ufrisk/MemProcFS/releases/tag/v3.8)
* Updates & Improvements:
  * Rename 'sysinfo' directory to 'sys'.
  * Better os detection (symbol fallback).
  * Handles: additional object info.
  * Info header in most info-files (enabled by default - possible to disable).
* New Features:
  * Windows Kernel Object Manager Objects.
  * Additional kernel driver information.
  * Detailed Object and Object Header Info.

[v3.9](https://github.com/ufrisk/MemProcFS/releases/tag/v3.9)
* Bug fixes.
* License Change: GNU Affero General Public License v3.0.
* Updates & Improvements:
  * Faster and more robust parsing of physical memory map
  * Rename per-process `user` to `token` and add more info.
* New Features:
  * New [Python API](https://github.com/ufrisk/MemProcFS/wiki/API_Python) now also available on [Python pip](https://pypi.org/project/memprocfs/). Check out the [YouTube demo](https://youtu.be/pLFU1lxBNM0)!
  * `py/reg/net/tcpip_interfaces.txt`

[v3.10](https://github.com/ufrisk/MemProcFS/releases/tag/v3.10)
* Bug fixes.
* New Features:
  * Scheduled Tasks at `/sys/tasks/`
  * Forensic mode: JSON info file generation `/forensic/json/` (compatible with Elasticsearch).
</details>

[v4.0](https://github.com/ufrisk/MemProcFS/releases/tag/v4.0)
* Linux support (x64 and aarch64).
* Separate releases for Windows and Linux.
* API Changes and some incompatibilities.

[v4.1](https://github.com/ufrisk/MemProcFS/releases/tag/v4.1)
* Bug fixes.
* Offline kernel symbols (partial support). This allows for more functionality in Linux mode and in Windows offline mode.
