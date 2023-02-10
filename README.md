MemProcFS:
===============================
MemProcFS is an easy and convenient way of viewing physical memory as files in a virtual file system. 

Easy trivial point and click memory analysis without the need for complicated commandline arguments! Access memory content and artifacts via files in a mounted virtual file system or via a feature rich application library to include in your own projects!

Analyze memory dump files, <b>live memory</b> via DumpIt or WinPMEM, <b>live memory in read-write mode</b> from virtual machines or from [PCILeech](https://github.com/ufrisk/pcileech/) [FPGA](https://github.com/ufrisk/pcileech-fpga/) hardware devices!

It's even possible to connect to a remote LeechAgent memory acquisition agent over a secured connection - allowing for remote live memory incident response - even over higher latency low band-width connections! Peek into [Virtual Machines with MemProcFS](https://github.com/ufrisk/MemProcFS/wiki/VM), [LiveCloudKd](https://github.com/ufrisk/LeechCore/wiki/Device_LiveCloudKd) or [VMware](https://github.com/ufrisk/LeechCore/wiki/Device_VMWare)!

Use your favorite tools to analyze memory - use your favorite hex editors, your python and powershell scripts, WinDbg or your favorite disassemblers and debuggers - all will work trivally with MemProcFS by just reading and writing files!

<p align="center"><img src="https://github.com/ufrisk/MemProcFS/wiki/resources/proc_base3.png" height="190"/><img src="https://github.com/ufrisk/MemProcFS/wiki/resources/pciescreamer.jpeg" height="190"/><img src="https://github.com/ufrisk/MemProcFS/wiki/resources/proc_modules.png" height="190"/></p>



Get Started!
============

Check out the excellent quick walkthrough from [13Cubed](https://www.13cubed.com/) to get going! Also check out my older conference talks from Disobey and BlueHat.

<p align="center"> <a href="https://youtu.be/hjWVUrf7Obk" alt="13Cubed: MemProcFS - This Changes Everything" target="_new"><img src="http://img.youtube.com/vi/hjWVUrf7Obk/0.jpg" height="230"/></a> <a href="https://youtu.be/mca3rLsHuTA?t=952" alt="Disobey 2020 talk - Live Memory Attacks and Forensics" target="_new"><img src="http://img.youtube.com/vi/mca3rLsHuTA/0.jpg" height="230"/></a> <a href="https://www.youtube.com/watch?v=Da_9SV9FA34" alt="Microsoft BlueHatIL 2019 talk - Practical Uses for Hardware-assisted Memory Visualization" target="_new"><img src="http://img.youtube.com/vi/Da_9SV9FA34/0.jpg" height="230"/></a></p>

For additional documentation **please check out the [project wiki](https://github.com/ufrisk/MemProcFS/wiki)** for in-depth detailed information about the file system itself, its API and its plugin modules! For additional information about memory acqusition methods check out the **[LeechCore project](https://github.com/ufrisk/LeechCore/)** or hop into the [#pcileech](https://discord.gg/sEkn3aa) Discord channel!

To get going clone the sources in the repository or download the [latest binaries, modules and configuration files](https://github.com/ufrisk/MemProcFS/releases/latest) from the releases section and **check out the [guide](https://github.com/ufrisk/MemProcFS/wiki).**



Installing:
===========
<b>Get the latest [binaries, modules and configuration files](https://github.com/ufrisk/MemProcFS/releases/latest) from the latest release.</b> Alternatively clone the repository and build from source.

## Windows
Mounting the file system requires the <b>Dokany file system library</b> to be installed. Please download and install the latest version of Dokany version 2 at: https://github.com/dokan-dev/dokany/releases/latest

To capture live memory (without PCILeech FPGA hardware) download [DumpIt](https://www.comae.com/) and start MemProcFS via DumpIt /LIVEKD mode. Alternatively, get WinPMEM by downloading the most recent signed [WinPMEM driver](https://github.com/Velocidex/c-aff4/tree/master/tools/pmem/resources/winpmem) and place it alongside MemProcFS - detailed instructions in the [LeechCore Wiki](https://github.com/ufrisk/LeechCore/wiki/Device_WinPMEM).

PCILeech FPGA will require hardware as well as _FTD3XX.dll_ to be dropped alongside the MemProcFS binaries. Please check out the [LeechCore](https://github.com/ufrisk/LeechCore) project for instructions.

## Linux
MemProcFS is dependent on packages, please do a `sudo apt-get install libusb-1.0 fuse openssl lz4` before trying out MemProcFS. If building from source please check out the guide about [MemProcFS on Linux](https://github.com/ufrisk/MemProcFS/wiki/_Linux).



Extensive Python, Java, C# and C/C++ API:
===============================
Include MemProcFS in your [C/C++](https://github.com/ufrisk/MemProcFS/wiki/API_C), [C#](https://github.com/ufrisk/MemProcFS/wiki/API_CSharp), [Java](https://github.com/ufrisk/MemProcFS/wiki/API_Java) or [Python](https://github.com/ufrisk/MemProcFS/wiki/API_Python) programming projects! Everything in MemProcFS is exposed via an easy-to-use API for use in your own projects! The Plugin friendly architecture allows users to easily extend MemProcFS with native C .DLL plugins or Python plugins!

Everything in MemProcFS is exposed as APIs. APIs exist for both C/C++ `vmmdll.h`, C# `vmmsharp.cs`, Java and Python `memprocfs.py`. The file system itself is made available virtually via the API without the need to mount it. SIt is possible to read both virtual process memory as well as physical memory! The example below shows reading 0x20 bytes from physical address 0x1000:
```
>>> import memprocfs
>>> vmm = memprocfs.Vmm(['-device', 'c:/temp/win10_memdump.raw'])
>>> print(vmm.hex( vmm.memory.read(0x1000, 0x20) ))
0000    e9 4d 06 00 01 00 00 00  01 00 00 00 3f 00 18 10   .M..........?...
0010    00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00   ................
```



Examples:
=========
Start MemProcFS from the command line - possibly by using one of the examples below.

Or register the memory dump file extension with MemProcFS.exe so that the file system is automatically mounted when double-clicking on a memory dump file!

- mount the memory dump file as default M: <br>`memprocfs.exe -device c:\temp\win10x64-dump.raw`
- mount the memory dump file as default M: with extra verbosity: <br>`memprocfs.exe -device c:\temp\win10x64-dump.raw -v`
- mount the memory dump file as default M: and start forensics mode: <br>`memprocfs.exe -device c:\temp\win10x64-dump.raw -forensic 1`
- mount the memory dump file as /home/pi/mnt/ on Linux: <br>`./memprocfs -mount /home/pi/linux -device /dumps/win10x64-dump.raw`
- mount the memory dump file as S: <br>`memprocfs.exe -mount s -device c:\temp\win10x64-dump.raw`
- mount live target memory, in verbose read-only mode, with DumpIt in /LIVEKD mode: <br>`DumpIt.exe /LIVEKD /A memprocfs.exe /C "-v"`
- mount live target memory, in read-only mode, with WinPMEM driver: <br>`memprocfs.exe -device pmem`
- mount live target memory, in read/write mode, with PCILeech FPGA memory acquisition device: <br>`memprocfs.exe -device fpga -memmap auto`
- mount a memory dump with a corresponding page files: <br>`memprocfs.exe -device unknown-x64-dump.raw -pagefile0 pagefile.sys -pagefile1 swapfile.sys`



Building:
=========
<b>Pre-built [binaries, modules and configuration files](https://github.com/ufrisk/MemProcFS/releases/latest) are found in the latest release.</b>. MemProcFS binaries are built with Visual Studio 2022 and Ubuntu x64/AARCH64.

Detailed build instructions may be found in the [Wiki](https://github.com/ufrisk/MemProcFS/wiki) in the [Building](https://github.com/ufrisk/MemProcFS/wiki/Dev_Building) section.



License:
========
The project source code is released under: GNU Affero General Public License v3.0. Some bundled dependencies and plugins are released under GPLv3. Some bundled Microsoft redistributable binaries are released under separate licenses. Alternative closed-source licensing may be possible upon request.



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



Changelog:
===================
<details><summary>Previous releases (click to expand):</summary>
 
v1.0
* Initial Release.

v1.1-v4.9
* Various updates. Please see individual relases for more information.

[v5.0](https://github.com/ufrisk/MemProcFS/releases/tag/v5.0)
* Major release with new features to support parallel analysis tasks.
* Breaking API changes and major updates.
* Extended forensic analysis capabilties and [CSV file](https://github.com/ufrisk/MemProcFS/wiki/FS_Forensic_CSV) support.
* Linux plugin support.
* New [Java API](https://github.com/ufrisk/MemProcFS/wiki/API_Java).

[v5.1](https://github.com/ufrisk/MemProcFS/releases/tag/v5.1)
* Support for Windows 11 22H2.
* Text & Binary-only views at '/misc/view/'.

[v5.2](https://github.com/ufrisk/MemProcFS/releases/tag/v5.2)
* Bug fixes.
* [Virtual Machine support](https://github.com/ufrisk/MemProcFS/wiki/VM).
* [ARM64 Windows support](https://github.com/ufrisk/MemProcFS/wiki/_ARM64).
* FPGA performance improvements.
* Device tree information in /sys/drivers.
* Linux feature additions: memcompress and token.
* Manual download of debug symbols (PDBs) on offline systems (Windows only).
</details>

[v5.3](https://github.com/ufrisk/MemProcFS/releases/tag/v5.3)
* Bug fixes and performance optimizations.
* PE forwarded functions.
* PE version information.
* MemProcFS Python batch mode.
* Linux Python plugin support.
* Hyper-V Container/Sandbox support.
* Windows Hypervisor Platform support (VMware and VirtualBox on Hyper-V).

Latest:
* Microsoft symbol server support on Linux.
