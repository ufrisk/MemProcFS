Vmmsharp:
===============================

Vmmsharp is the C# API for the MemProcFS memory analysis framework.

MemProcFS enables super fast memory analysis and memory forensics. Analyze memory dump files, live memory via DumpIt or WinPMEM, live memory in read-write mode from virtual machines or from PCILeech compatible hardware devices!

Vmmsharp requires native MemProcFS libraries to work. The latest MemProcFS release can be downloaded from [here](https://github.com/ufrisk/MemProcFS/releases/latest).

To get going grab Vmmsharp from [NuGet](https://www.nuget.org/packages/Vmmsharp/). It's also possible to build Vmmsharp from [sources](https://github.com/ufrisk/MemProcFS/tree/master/vmmsharp/vmmsharp).



Links:
===============================
* Vmmsharp NuGet package: https://www.nuget.org/packages/Vmmsharp/
* Vmmsharp at Github: https://github.com/ufrisk/MemProcFS/tree/master/vmmsharp/vmmsharp
* Vmmsharp examples https://github.com/ufrisk/MemProcFS/blob/master/vmmsharp/example/VmmsharpExample.cs
* MemProcFS at Github https://github.com/ufrisk/MemProcFS
* MemProcFS latest release https://github.com/ufrisk/MemProcFS/releases/latest
* Discord: [![Discord | PCILeech/MemProcFS](https://img.shields.io/discord/1155439643395883128.svg?label=&logo=discord&logoColor=ffffff&color=7389D8&labelColor=6A7EC2)](https://discord.gg/pcileech)
* Twitter: [![Twitter](https://img.shields.io/twitter/follow/UlfFrisk?label=UlfFrisk&style=social)](https://twitter.com/intent/follow?screen_name=UlfFrisk)



Example:
===============================

Check out the [Vmmsharp examples](https://github.com/ufrisk/MemProcFS/blob/master/vmmsharp/example/VmmsharpExample.cs) which contains extensive examples of the Vmmsharp functionality.

The below minimal example shows how it's possible to use Vmmsharp to use MemProcFS to analyze a memory dump file and retrieve the virtual memory of the module kernel32.dll in explorer.exe.

```csharp
using Vmmsharp;

namespace vmmsharp_example {
    class VmmsharpExample {
        static void Main(string[] args) {
            // Pre-load the native MemProcFS libraries.
            // (This is recommended if the libraries are not already on the PATH.)
            Vmm.LoadNativeLibrary("C:\\MemProcFS\\");

            // Initialize MemProcFS (Vmm object) with arguments.
            // (A physical memory dump file in this example.)
            Vmm vmm = new Vmm("-device", "c:\\dumps\\memorydump.raw");

            // Get the process object for explorer.exe:
            VmmProcess explorerProcess = vmm.Process("explorer.exe");

            // Get the base address of kernel32.dll in the explorer process:
            ulong kernel32Base = explorerProcess.GetModuleBase("kernel32.dll");
            Console.WriteLine("Base address of kernel32.dll in explorer.exe: {0:X}", kernel32Base);

            // Read the first 256 bytes of kernel32.dll in the explorer process:
            byte[] memReadData = explorerProcess.MemRead(kernel32Base, 0x100);
            string memReadHexDump = Vmm.UtilFillHexAscii(memReadData);
            Console.WriteLine("Read from explorer.exe!kernel32.dll: \n{0}", memReadHexDump);
        }
    }
}
```

The output of the above example is shown below. The result may differ slightly depending on the memory dump file or live memory used.
```
Vmm
VmmProcess:372
explorer.exe!kernel32.dll: 7FFD04330000
Read from explorer.exe!kernel32.dll:
0000    4d 5a 90 00 03 00 00 00  04 00 00 00 ff ff 00 00   MZ..............
0010    b8 00 00 00 00 00 00 00  40 00 00 00 00 00 00 00   ........@.......
0020    00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00   ................
0030    00 00 00 00 00 00 00 00  00 00 00 00 e8 00 00 00   ................
0040    0e 1f ba 0e 00 b4 09 cd  21 b8 01 4c cd 21 54 68   ........!..L.!Th
0050    69 73 20 70 72 6f 67 72  61 6d 20 63 61 6e 6e 6f   is program canno
0060    74 20 62 65 20 72 75 6e  20 69 6e 20 44 4f 53 20   t be run in DOS
0070    6d 6f 64 65 2e 0d 0d 0a  24 00 00 00 00 00 00 00   mode....$.......
0080    a9 6c 42 bd ed 0d 2c ee  ed 0d 2c ee ed 0d 2c ee   .lB...,...,...,.
0090    88 6b 2d ef e9 0d 2c ee  e4 75 bf ee 54 0d 2c ee   .k-...,..u..T.,.
00a0    ed 0d 2d ee eb 08 2c ee  88 6b 28 ef ea 0d 2c ee   ..-...,..k(...,.
00b0    88 6b 2f ef ee 0d 2c ee  88 6b 2c ef ec 0d 2c ee   .k/...,..k,...,.
00c0    88 6b 21 ef 22 0d 2c ee  88 6b d3 ee ec 0d 2c ee   .k!.".,..k....,.
00d0    88 6b 2e ef ec 0d 2c ee  52 69 63 68 ed 0d 2c ee   .k....,.Rich..,.
00e0    00 00 00 00 00 00 00 00  50 45 00 00 64 86 06 00   ........PE..d...
00f0    a1 4d 61 65 00 00 00 00  00 00 00 00 f0 00 22 20   .Mae.........."
```



Support PCILeech/MemProcFS development:
=======================================
PCILeech and MemProcFS is free and open source!

I put a lot of time and energy into PCILeech and MemProcFS and related research to make this happen. Some aspects of the projects relate to hardware and I put quite some money into my projects and related research. If you think PCILeech and/or MemProcFS are awesome tools and/or if you had a use for them it's now possible to contribute by becoming a sponsor! 
 
If you like what I've created with PCIleech and MemProcFS with regards to DMA, Memory Analysis and Memory Forensics and would like to give something back to support future development please consider becoming a sponsor at: [`https://github.com/sponsors/ufrisk`](https://github.com/sponsors/ufrisk)

To all my sponsors, Thank You 💖 
