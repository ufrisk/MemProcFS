/*  
 *  C# API wrapper 'vmmsharp' for MemProcFS 'vmm.dll' and LeechCore 'leechcore.dll' APIs.
 *  
 *  Please see the example project in vmmsharp_example for additional information.
 *  
 *  Please consult the C/C++ header files vmmdll.h and leechcore.h for information about parameters and API usage.
 *  
 *  (c) Ulf Frisk, 2020-2025
 *  Author: Ulf Frisk, pcileech@frizk.net
 *  
 */

using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using Vmmsharp;

namespace vmmsharp_example
{
    internal class VmmsharpExample
    {

        static void Main(string[] args)
        {

            // EXAMPLES STARTING POINT:
            // The examples for the Vmmsharp library which wraps the native libraries vmm.dll and leechcore.dll starts here.

            // TO RUN THE EXAMPLES MARK the vmmsharp_example project as 'STARTUP PROJECT' AND RUN.

            // PRE-LOAD OF NATIVE LIBRARIES:
            // Normally the native libraries should be placed in the same directory as the .NET vmmsharp.dll.
            // This is not the case for the examples so a pre-load of the native libraries are required for
            // the Vmmsharp P/Invoke to correctly locate the native libraries.
            string currentDir = System.AppDomain.CurrentDomain.BaseDirectory;
            string nativeDir = currentDir + "..\\..\\..\\..\\files\\";
            LeechCore.LoadNativeLibrary(nativeDir);
            Vmm.LoadNativeLibrary(nativeDir);

            // RUN VMM (MEMPROCFS) EXAMPLES:
            Console.WriteLine("Running Vmm Examples...");
            Console.WriteLine("====================================");
            VmmExample.Run();

            // RUN LEECHCORE EXAMPLES:
            Console.WriteLine("Running LeechCore Examples...");
            Console.WriteLine("====================================");
            LeechCoreExample.Run();
        }
    }


    public static class VmmExample
    {
        public static readonly string DEVICE_OR_FILE = "c:\\dumps\\WIN7-x64-SP1-1.pmem";
        public static readonly string[] VMM_INITIALIZATION_ARGUMENTS = { "-printf", "-v", "-vm", "-waitinitialize", "-device", DEVICE_OR_FILE };

        public static void Run()
        {
            bool f;

            // Example: Initialize new Vmm instance with arguments:
            Console.WriteLine("====================================");
            Console.WriteLine("Initializing Vmm...");
            Vmm vmm = new Vmm(VMM_INITIALIZATION_ARGUMENTS);
            Console.WriteLine("Result: " + vmm);

            // Examples: General VMM functionality and physical memory access:
            #region General VMM functionality and physical memory access
            {
                // Example: vmm.GetConfig():
                // Retrieve max native address and print it on the screen.
                Console.WriteLine("====================================");
                Console.WriteLine("Vmm.GetConfig():");
                ulong maxNativeAddress = vmm.GetConfig(Vmm.CONFIG_OPT_CORE_MAX_NATIVE_ADDRESS);
                Console.WriteLine("max native address: {0:X} -> {1:X}", Vmm.CONFIG_OPT_CORE_MAX_NATIVE_ADDRESS, maxNativeAddress);


                // Example: vmm.GetConfig():
                // Perform a full refresh of internal data caches.
                Console.WriteLine("====================================");
                Console.WriteLine("Vmm.SetConfig():");
                if (vmm.SetConfig(Vmm.CONFIG_OPT_REFRESH_ALL, 1))
                {
                    Console.WriteLine("full refresh: -> Ok");
                }


                // Example: vmm.MemWrite():
                // Write to physical memory at address 0x1000
                // (Writes are only possible if underlying layers are write-capable.)
                Console.WriteLine("====================================");
                Console.WriteLine("Vmm.MemWrite():");
                byte[] dataToWritePhysical = { 0x56, 0x4d, 0x4d, 0x52, 0x55, 0x53, 0x54 };
                f = vmm.MemWrite(0x1000, dataToWritePhysical);
                Console.WriteLine("Write to physical memory at address 0x1000: {0}", (f ? "success" : "fail"));


                // Example: vmm.MemRead():
                // Read 0x100 bytes from physical address 0x1000.
                Console.WriteLine("====================================");
                Console.WriteLine("Vmm.MemRead():");
                byte[] dataRead = vmm.MemRead(0x1000, 0x100);
                if (dataRead != null)
                {
                    Console.WriteLine("Read from physical memory at address 0x1000: \n{0}", Vmm.UtilFillHexAscii(dataRead));
                }
                else
                {
                    Console.WriteLine("Read from physical memory at address 0x1000: fail");
                }


                // Example: vmm.MemRead() with flags:
                // Read 0x100 bytes from physical address 0x1000 with vmm flags.
                Console.WriteLine("====================================");
                Console.WriteLine("Vmm.MemRead() with flags: Vmm.FLAG_NOCACHE | Vmm.FLAG_ZEROPAD_ON_FAIL");
                dataRead = vmm.MemRead(0x1000, 0x100, Vmm.FLAG_NOCACHE | Vmm.FLAG_ZEROPAD_ON_FAIL);
                if (dataRead != null)
                {
                    Console.WriteLine("Read from physical memory at address 0x1000 (with flags): \n{0}", Vmm.UtilFillHexAscii(dataRead));
                }
                else
                {
                    Console.WriteLine("Read from physical memory at address 0x1000 (with flags): fail");
                }


                // Example: vmm.Log():
                // Log a message to VMM/MemProcFS using default log level (Info) and default module id (API).
                Console.WriteLine("====================================");
                Console.WriteLine("Vmm.Log():");
                vmm.Log("Info from Vmmsharp!");


                // Example: vmm.Log():
                // Log a message to VMM/MemProcFS using log level Warning and module id for API.
                Console.WriteLine("====================================");
                Console.WriteLine("Vmm.Log():");
                vmm.Log("Warning from Vmmsharp!", Vmm.LogLevel.Warning, 0x80000011);


                // Example: vmm.Process():
                // Retrieve the 'System' process by its PID (4).
                // Also print the process name.
                Console.WriteLine("====================================");
                Console.WriteLine("Vmm.Process() [by PID]:");
                VmmProcess systemProcess = vmm.Process(4);
                if (systemProcess != null)
                {
                    Console.WriteLine(systemProcess);
                    Console.WriteLine(systemProcess.Name);
                }


                // Example: vmm.Process():
                // Retrieve the 'System' process by its name.
                // Also print the process name.
                Console.WriteLine("====================================");
                Console.WriteLine("Vmm.Process() [by name]:");
                systemProcess = vmm.Process("System");
                if (systemProcess != null)
                {
                    Console.WriteLine(systemProcess);
                    Console.WriteLine(systemProcess.Name);
                }


                // Example: vmm.Processes:
                // Retrieve all processes of the running system.
                Console.WriteLine("====================================");
                Console.WriteLine("Vmm.Processes:");
                foreach (VmmProcess process in vmm.Processes)
                {
                    Console.WriteLine("{0}:{1}", process, process.Name);
                }


                // Example: vmm.PIDs:
                // Retrieve all process IDs of the running system.
                Console.WriteLine("====================================");
                Console.WriteLine("Vmm.PIDs:");
                foreach (int pid in vmm.PIDs)
                {
                    Console.WriteLine(pid);
                }


                // Example: vmm.MapPfn():
                // Retrieve the first 10 page frame numbers PFNs and display extended info about them.
                // NB! extended PFN info is rather expensive so use with caution.
                Console.WriteLine("====================================");
                Console.WriteLine("Vmm.MapPfn():");
                uint[] pfns = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };
                Vmm.PfnEntry[] pfnEntries = vmm.MapPfn(pfns);
                foreach (Vmm.PfnEntry pfn in pfnEntries)
                {
                    Console.WriteLine("{0} ({1:X}) \t location={2} tp_ex={3} pid={4:X} va={5:X}", pfn, pfn.dwPfn, pfn.tp, pfn.tpExtended, pfn.dwPID, pfn.va);
                }


                // Example: vmm.MapMemory():
                // Retrieve the physical memory map as seen by the operating system:
                Console.WriteLine("====================================");
                Console.WriteLine("Vmm.MapMemory():");
                Vmm.MemoryEntry[] memoryMap = vmm.MapMemory();
                foreach (Vmm.MemoryEntry e in memoryMap)
                {
                    Console.WriteLine("physical address: {0:X} \t size: {1:X}", e.pa, e.cb);
                }


                // Example: vmm.MapMemoryAsString():
                // Retrieve the physical memory map as seen by the operating system as a string:
                Console.WriteLine("====================================");
                Console.WriteLine("Vmm.MapMemoryAsString():");
                string memMap = vmm.MapMemoryAsString();
                Console.WriteLine(memMap);


                // Example: vmm.MapNet():
                // Retrieve the network connection information:
                Console.WriteLine("====================================");
                Console.WriteLine("Vmm.MapNet():");
                Vmm.NetEntry[] netEntries = vmm.MapNet();
                foreach (Vmm.NetEntry netEntry in netEntries)
                {
                    Console.WriteLine("{0} \t pid={1} \t src={2} \t dst={3}", netEntry, netEntry.dwPID, netEntry.src.sText, netEntry.dst.sText);
                }


                // Example: vmm.MapKDevice():
                // Retrieve kernel devices and display them.
                Console.WriteLine("====================================");
                Console.WriteLine("Vmm.MapKDevice():");
                Vmm.KDeviceEntry[] deviceEntries = vmm.MapKDevice();
                foreach (Vmm.KDeviceEntry deviceEntry in deviceEntries)
                {
                    Console.WriteLine("{0}  va={1:X}  type={2}", deviceEntry, deviceEntry.va, deviceEntry.sDeviceType);
                }


                // Example: vmm.MapKDriver():
                // Retrieve kernel drivers and display them.
                Console.WriteLine("====================================");
                Console.WriteLine("Vmm.MapKDriver():");
                Vmm.KDriverEntry[] driverEntries = vmm.MapKDriver();
                foreach (Vmm.KDriverEntry driverEntry in driverEntries)
                {
                    Console.WriteLine("{0}  va={1:X}  va_driver={2:X}  name='{3}'", driverEntry, driverEntry.va, driverEntry.vaDriverStart, driverEntry.sName);
                }


                // Example: vmm.MapKObject():
                // Retrieve kernel drivers and display them.
                Console.WriteLine("====================================");
                Console.WriteLine("Vmm.MapKObject():");
                Vmm.KObjectEntry[] objectEntries = vmm.MapKObject();
                foreach (Vmm.KObjectEntry objectEntry in objectEntries)
                {
                    Console.WriteLine("{0}  va={1:X}  va_parent={2:X}  type={3} \t name='{4}'", objectEntry, objectEntry.va, objectEntry.vaParent, objectEntry.sType, objectEntry.sName);
                }


                /*
                // Example: vmm.MapPool():
                // Retrieve kernel pool allocations and display the 'Proc' allocations.
                // NB! here we retrieve all pool allocations which is substantially
                //     slower than retrieving the big pool only.
                Console.WriteLine("====================================");
                Console.WriteLine("Vmm.MapPool():");
                Vmm.PoolEntry[] poolEntries = vmm.MapPool();
                Vmm.PoolEntry[] poolEntriesProc = poolEntries.Where(e => e.sTag == "Proc").ToArray();
                foreach (Vmm.PoolEntry poolEntryProc in poolEntriesProc)
                {
                    Console.WriteLine("{0} \t tag={1:X} va={2:X} size={3:X}", poolEntryProc, poolEntryProc.sTag, poolEntryProc.va, poolEntryProc.cb);
                }
                */


                // Example: vmm.MapService():
                // Retrieve all services in the system:
                Console.WriteLine("====================================");
                Console.WriteLine("Vmm.MapService():");
                Vmm.ServiceEntry[] serviceEntries = vmm.MapService();
                foreach (Vmm.ServiceEntry serviceEntry in serviceEntries)
                {
                    Console.WriteLine("{0}  va_object={1:X}  device_type={2} \t name={3} \t displayname={4}",
                        serviceEntry, serviceEntry.vaObj, serviceEntry.dwServiceType, serviceEntry.sServiceName, serviceEntry.sDisplayName);
                }


                // Example: vmm.MapUser():
                // Retrieve the detected users in the system:
                Console.WriteLine("====================================");
                Console.WriteLine("Vmm.MapUser():");
                Vmm.UserEntry[] userEntries = vmm.MapUser();
                foreach (Vmm.UserEntry userEntry in userEntries)
                {
                    Console.WriteLine("{0} \t name={1} \t sid={2}", userEntry, userEntry.sText, userEntry.sSID);
                }


                // Example: vmm.map_virtual_machine():
                // Retrieve any virtual machines detected:
                // NB! vm parsing must be enabled (-vm startup option).
                Console.WriteLine("====================================");
                Console.WriteLine("Vmm.MapVirtualMachine():");
                Vmm.VirtualMachineEntry[] vmEntries = vmm.MapVirtualMachine();
                foreach (Vmm.VirtualMachineEntry vmEntry in vmEntries)
                {
                    Console.WriteLine("{0} \t name={1} \t partition_id={2}", vmEntry, vmEntry.sName, vmEntry.dwPartitionID);
                }
            }
            #endregion // General VMM functionality and physical memory access


            #region Vmm Kernel and PDB (debugging) functionality
            {
                // Example: vmm.Kernel().Process():
                // Retrieve the system process (PID 4).
                // NB! vmm.Kernel() is a lightweight operation so ok to call multiple times...
                Console.WriteLine("====================================");
                Console.WriteLine("Vmm.Kernel.Process:");
                VmmProcess systemProcess = vmm.Kernel.Process;
                if (systemProcess != null)
                {
                    Console.WriteLine(systemProcess);
                }


                // Example: vmm.Kernel().Build():
                // Retrieve the kernel build number.
                Console.WriteLine("====================================");
                Console.WriteLine("Vmm.Kernel.Build:");
                Console.WriteLine("Kernel build number: {0}", vmm.Kernel.Build);


                // Example: vmm.Kernel().Pdb():
                // Retrieve the VmmPdb object containg debug symbols for ntoskrnl.
                // NB! This call will always succeed even if the symbols aren't loaded.
                //     Subsequent calls to the pdb methods may however fail.
                Console.WriteLine("====================================");
                Console.WriteLine("Vmm.Kernel.Pdb:");
                VmmPdb pdb = vmm.Kernel.Pdb;
                Console.WriteLine(pdb);


                // Example: pdb.SymbolAddress():
                // Retrieve the address of the symbol nt!MmAllocateContiguousMemory
                // NB! this requires that the MemProcFS symbol-subsystem is working.
                Console.WriteLine("====================================");
                Console.WriteLine("pdb.SymbolAddress():");
                ulong vaSymbolAddress;
                if (pdb.SymbolAddress("MmAllocateContiguousMemory", out vaSymbolAddress))
                {
                    Console.WriteLine("Symbol nt!MmAllocateContiguousMemory: {0:X}", vaSymbolAddress);
                }


                // Example: pdb.SymbolName():
                // Retrieve the symbol name from an address.
                // Use the already retrieved address of nt!MmAllocateContiguousMemory.
                Console.WriteLine("====================================");
                Console.WriteLine("pdb.SymbolName():");
                string symbolName;
                if (pdb.SymbolName(vaSymbolAddress, out symbolName))
                {
                    Console.WriteLine("Symbol name at address {0:X}: {1}", vaSymbolAddress, symbolName);
                }


                // Example: pdb.TypeSize():
                // Retrieve the size of a type. In this example use _EPROCESS.
                Console.WriteLine("====================================");
                Console.WriteLine("pdb.TypeSize():");
                uint typeSize;
                if (pdb.TypeSize("_EPROCESS", out typeSize))
                {
                    Console.WriteLine("Size of _EPROCESS: {0}", typeSize);
                }


                // Example: pdb.TypeChildOffset():
                // Retrieve the offset of a type child.
                // In this example use _EPROCESS.VadRoot
                Console.WriteLine("====================================");
                Console.WriteLine("pdb.TypeChildOffset():");
                uint childOffset;
                if (pdb.TypeChildOffset("_EPROCESS", "VadRoot", out childOffset))
                {
                    Console.WriteLine("Offset of _EPROCESS.VadRoot: {0}", childOffset);
                }
            }
            #endregion // Vmm Kernel and PDB (debugging) functionality


            #region VFS (Virtual File System) functionality
            // Example: vmm.VfsList():
            // Retrieve a directory listing of the /sys/ folder.
            // NB! forward-slash '/' and back-slash '\\' both work fine!
            Console.WriteLine("====================================");
            Console.WriteLine("Vmm.VfsList():");
            List<Vmm.VfsEntry> vfsEntries = vmm.VfsList("/sys/");
            foreach (Vmm.VfsEntry vfsEntry in vfsEntries)
            {
                Console.WriteLine("{0} \t name={1} \t type={2} \t size={3}", vfsEntry, vfsEntry.name, vfsEntry.isDirectory ? "dir " : "file", vfsEntry.size);
            }


            // Example: vmm.VfsRead():
            // Read (a part) of a file in the virtual file system.
            // In this case try reading the file /sys/memory/physmemmap.txt
            // NB! to check the status of the operation use vmm.VfsRead(name, out uint nt).
            Console.WriteLine("====================================");
            Console.WriteLine("Vmm.VfsRead():");
            uint ntStatus;
            byte[] vfsFileData1 = vmm.VfsRead("/sys/memory/physmemmap.txt", out ntStatus);
            string sVfsFileData1 = System.Text.Encoding.UTF8.GetString(vfsFileData1);
            Console.WriteLine("Read from file /sys/memory/physmemmap.txt: ntStatus = {0:X} \n{1}", ntStatus, sVfsFileData1);


            // Example: vmm.VfsWrite():
            // Write (to a part) of a file in the virtual file system.
            // In this case write '1' to /conf/config_process_show_terminated.txt
            // to enable listings of terminated processes in the filesystem.
            // NB! vfs_write() writes are undertaken on a best-effort!
            //     please verify with VfsRead() (if this is possible).
            Console.WriteLine("====================================");
            Console.WriteLine("Vmm.VfsWrite():");
            byte[] vfsDataToWrite = { 0x31 }; // '1'
            uint ntStatusVfsWrite = vmm.VfsWrite("/conf/config_process_show_terminated.txt", vfsDataToWrite, 0);


            // Example: vmm.VfsRead():
            // Read (a part) of a file in the virtual file system.
            // In this case try reading the file /conf/config_process_show_terminated.txt
            Console.WriteLine("====================================");
            Console.WriteLine("Vmm.VfsRead():");
            byte[] vfsFileData2 = vmm.VfsRead("/conf/config_process_show_terminated.txt");
            Console.WriteLine("Read from file /conf/config_process_show_terminated.txt: \n{0}", System.Text.Encoding.UTF8.GetString(vfsFileData2));


            // Example: vmm.VfsRead():
            // Read the /misc/procinfo/dtb.txt file containing process DTB values.
            // The dtb.txt file takes a short while to render so we wait for it.
            Console.WriteLine("====================================");
            Console.WriteLine("Vmm.VfsRead(): /misc/procinfo/dtb.txt");
            while (true)
            {
                byte[] bytesProgress = vmm.VfsRead("/misc/procinfo/progress_percent.txt", 0x100, 0);
                if (bytesProgress.Length == 0)
                {
                    break;
                }
                string sProgress = System.Text.Encoding.UTF8.GetString(bytesProgress).Trim();
                if (sProgress == "100")
                {
                    byte[] bytesDTB = vmm.VfsRead("/misc/procinfo/dtb.txt");
                    string sDTB = System.Text.Encoding.UTF8.GetString(bytesDTB);
                    Console.WriteLine("Read from file /misc/procinfo/dtb.txt: \n{0}", sDTB);
                    break;
                }
                System.Threading.Thread.Sleep(1000);
            }
            #endregion // VFS (Virtual File System) functionality


            #region Registry functionality
            // Example vmm.RegHiveList():
            // List the registry hives of the system:
            Console.WriteLine("====================================");
            Console.WriteLine("Vmm.RegHiveList():");
            Vmm.RegHiveEntry[] regHives = vmm.RegHiveList();
            ulong vaSoftwareCMHIVE = 0;
            foreach (Vmm.RegHiveEntry regHive in regHives)
            {
                Console.WriteLine("{0} \t va_cmhive={1:X} \t name={2} \t path={3}", regHive, regHive.vaCMHIVE, regHive.sName, regHive.sHiveRootPath);
                if (regHive.sHiveRootPath.Contains("SOFTWARE"))
                {
                    vaSoftwareCMHIVE = regHive.vaCMHIVE;
                }
            }


            // Example: vmm.RegHiveRead():
            // Read 0x100 bytes from the address 0x1000 in the software registry hive.
            Console.WriteLine("====================================");
            Console.WriteLine("Vmm.RegHiveRead():");
            byte[] regHiveData = vmm.RegHiveRead(vaSoftwareCMHIVE, 0x1000, 0x100);
            Console.WriteLine("Read from registry hive SOFTWARE at address 0x1000: \n{0}", Vmm.UtilFillHexAscii(regHiveData));


            // Example: vmm.RegHiveWrite():
            // Write to the registry address 0x1000.
            // This have been commented out since this is extremely dangerous on live
            // systems and is likely to bluescreen / cause registry corruption.
            //byte[] regHiveDataToWrite = { 0x56, 0x4d, 0x4d, 0x52, 0x55, 0x53, 0x54 };
            //f = vmm.RegHiveWrite(vaSoftwareCMHIVE, 0x1000, regHiveDataToWrite);


            // Example: vmm.RegEnum() #1
            // Enumerate keys and values under the run key.
            // Registry paths are case sensitive and use backslashes.
            Console.WriteLine("====================================");
            Console.WriteLine("Vmm.RegEnum(): #1");
            Vmm.RegEnumEntry regEnumEntry = vmm.RegEnum("HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run");
            Console.WriteLine("Key: {0}", regEnumEntry.sKeyFullPath);
            foreach (Vmm.RegEnumValueEntry valueEntry in regEnumEntry.ValueList)
            {
                Console.WriteLine("Value: {0} \t type={1} \t size={2}", valueEntry.sName, valueEntry.type, valueEntry.size);
            }
            foreach (Vmm.RegEnumKeyEntry keyEntry in regEnumEntry.KeyList)
            {
                Console.WriteLine("SubKey: {0} \t LastWriteTime: {1}", keyEntry.sName, keyEntry.ftLastWriteTime);
            }


            // Example: vmm.RegEnum() #2
            // Enumerate keys and values under the run key.
            // Use the vaSoftwareCMHIVE address instead of hive name.
            // Registry paths are case sensitive and use backslashes.
            Console.WriteLine("====================================");
            Console.WriteLine("Vmm.RegEnum(): #2");
            Vmm.RegEnumEntry regEnumEntry2 = vmm.RegEnum($"0x{vaSoftwareCMHIVE:X}\\Microsoft\\Windows\\CurrentVersion\\Run");
            Console.WriteLine("Key: {0}", regEnumEntry2.sKeyFullPath);

            // Example: vmm.RegValueRead()
            // Read the raw registry value. This is most likely an UTF16 value if there is a string.
            Console.WriteLine("====================================");
            Console.WriteLine("Vmm.RegValueRead():");
            uint regValueType;
            string regValueName = $"{regEnumEntry.sKeyFullPath}\\{regEnumEntry.ValueList[0].sName}";
            byte[] regValueData = vmm.RegValueRead(regValueName, out regValueType);
            if (regValueData != null)
            {
                Console.WriteLine("Read from registry value {0} \t type {1}: \n{2}", regEnumEntry.ValueList[0].sName, regValueType, Vmm.UtilFillHexAscii(regValueData));
            }
            #endregion // Registry functionality


            #region Process core functionality
            // Example: vmm.Process(): #1
            // Retrieve the process object for 'explorer.exe'.
            // If explorer.exe does not exist just panic since the remainder of the
            // examples forward on are process related.
            Console.WriteLine("====================================");
            Console.WriteLine("Vmm.Process() [by name]:");
            VmmProcess explorerProcess = vmm.Process("explorer.exe");
            if (explorerProcess == null)
            {
                Console.WriteLine("Explorer.exe not found. Exiting...");
                return;
            }
            Console.WriteLine(explorerProcess);


            // Example: vmm.Process(): #2
            // Retrieve the process object for 'SYSTEM'.
            Console.WriteLine("====================================");
            Console.WriteLine("Vmm.Process() [by PID]:");
            VmmProcess systemProcess2 = vmm.Process(4);
            Console.WriteLine(systemProcess2);


            // Example: vmmprocess.GetInfo():
            // Retrieve common process info such as process pid, ppid and name.
            Console.WriteLine("====================================");
            Console.WriteLine("VmmProcess.GetInfo():");
            VmmProcess.ProcessInfo explorerProcessInfo = explorerProcess.GetInfo();
            Console.WriteLine($"struct   -> {explorerProcessInfo}");
            Console.WriteLine($"PID      -> {explorerProcessInfo.dwPID}");
            Console.WriteLine($"PPID     -> {explorerProcessInfo.dwPPID}");
            Console.WriteLine($"PEB      -> {explorerProcessInfo.vaPEB}");
            Console.WriteLine($"EPROCESS -> {explorerProcessInfo.vaEPROCESS}");
            Console.WriteLine($"Name     -> {explorerProcessInfo.sName}");
            Console.WriteLine($"LongName -> {explorerProcessInfo.sNameLong}");
            Console.WriteLine($"SID      -> {explorerProcessInfo.sSID}");


            // Example: vmmprocess.Info
            // Retrieve common process info such as process pid, ppid and name.
            Console.WriteLine("====================================");
            Console.WriteLine("VmmProcess.Info:");
            Console.WriteLine($"struct   -> {explorerProcess.Info}");
            Console.WriteLine($"PID      -> {explorerProcess.Info?.dwPID}");
            Console.WriteLine($"PPID     -> {explorerProcess.Info?.dwPPID}");
            Console.WriteLine($"PEB      -> {explorerProcess.Info?.vaPEB}");
            Console.WriteLine($"EPROCESS -> {explorerProcess.Info?.vaEPROCESS}");
            Console.WriteLine($"Name     -> {explorerProcess.Info?.sName}");
            Console.WriteLine($"LongName -> {explorerProcess.Info?.sNameLong}");
            Console.WriteLine($"SID      -> {explorerProcess.Info?.sSID}");


            // Example: vmmprocess.GetModuleBase():
            // Retrieve the base address of a module.
            Console.WriteLine("====================================");
            Console.WriteLine("VmmProcess.GetModuleBase():");
            ulong vaModuleBaseAddress = explorerProcess.GetModuleBase("kernel32.dll");
            Console.WriteLine("Base address of kernel32.dll: {0:X}", vaModuleBaseAddress);


            // Example: vmmprocess.GetProcAddress():
            // Retrieve the function address inside a module i.e. GetProcAddress().
            Console.WriteLine("====================================");
            Console.WriteLine("VmmProcess.GetProcAddress():");
            ulong vaGetProcAddress = explorerProcess.GetProcAddress("kernel32.dll", "GetProcAddress");
            Console.WriteLine("Address of GetProcAddress in kernel32.dll: {0:X}", vaGetProcAddress);


            // Example: vmmprocess.GetCmdline():
            // Retrieve the process commandline.
            Console.WriteLine("====================================");
            Console.WriteLine("VmmProcess.GetCmdline():");
            string sCmdline = explorerProcess.GetCmdline();
            Console.WriteLine("Commandline: {0}", sCmdline);


            // Example: vmmprocess.GetPathUser():
            // Retrieve the process image path in user-mode (derived from PEB)
            Console.WriteLine("====================================");
            Console.WriteLine("VmmProcess.GetPathUser():");
            string sPathUser = explorerProcess.GetPathUser();
            Console.WriteLine("Path (user-mode): {0}", sPathUser);


            // Example: vmmprocess.GetPathKernel():
            // Retrieve the process image path in user-mode (derived from EPROCESS).
            Console.WriteLine("====================================");
            Console.WriteLine("VmmProcess.GetPathKernel():");
            string sPathKernel = explorerProcess.GetPathKernel();
            Console.WriteLine("Path (kernel-mode): {0}", sPathKernel);
            #endregion // Process core functionality


            #region Process map/info functionality
            // Example: vmmprocess.MapPte():
            // Retrieve the page table entry (PTE) map for explorer.
            Console.WriteLine("====================================");
            Console.WriteLine("VmmProcess.MapPte():");
            VmmProcess.PteEntry[] pteEntries = explorerProcess.MapPTE();
            Console.WriteLine("Number of pte entries: {0}.", pteEntries.Length);
            foreach (VmmProcess.PteEntry pteEntry in pteEntries)
            {
                Console.WriteLine("{0} \t pages={1} \t {2:X}->{3:X} \t flags={4}{5}{6}{7}",
                    pteEntry,
                    pteEntry.cPages,
                    pteEntry.vaBase,
                    pteEntry.vaEnd,
                    pteEntry.fS ? 's' : '-',
                    pteEntry.fR ? 'r' : '-',
                    pteEntry.fW ? 'w' : '-',
                    pteEntry.fX ? 'x' : '-');
            }


            // Example: vmmprocess.MapVad():
            // Retrieve the virtual address descriptor (VAD) map for explorer.
            Console.WriteLine("====================================");
            Console.WriteLine("VmmProcess.MapVad():");
            VmmProcess.VadEntry[] vadEntries = explorerProcess.MapVAD();
            Console.WriteLine("Number of vad entries: {0}.", vadEntries.Length);
            foreach (VmmProcess.VadEntry vadEntry in vadEntries)
            {
                Console.WriteLine("{0} \t {1:X}->{2:X} \t {3}", vadEntry, vadEntry.vaStart, vadEntry.vaEnd, vadEntry.sText);
            }


            // Example: vmmprocess.MapHandle():
            // Retrieve the open handles associated with the process.
            Console.WriteLine("====================================");
            Console.WriteLine("VmmProcess.MapHandle():");
            VmmProcess.HandleEntry[] handleEntries = explorerProcess.MapHandle();
            Console.WriteLine("Number of handle entries: {0}.", handleEntries.Length);
            foreach (VmmProcess.HandleEntry handleEntry in handleEntries)
            {
                Console.WriteLine("{0} \t {1} \t {2} \t {3}", handleEntry, handleEntry.dwHandle, handleEntry.sType, handleEntry.sText);
            }


            // Example: vmmprocess.MapHeap():
            // Retrieve info about the process heaps:
            Console.WriteLine("====================================");
            Console.WriteLine("VmmProcess.MapHeap():");
            VmmProcess.HeapMap heapMap = explorerProcess.MapHeap();
            Console.WriteLine("Number of heap entries: {0}.", heapMap.heaps.Length);
            foreach (VmmProcess.HeapEntry heapEntry in heapMap.heaps)
            {
                Console.WriteLine("{0} \t {1} \t {2:X} \t {3}", heapEntry, heapEntry.iHeapNum, heapEntry.va, heapEntry.tpHeap);
            }
            Console.WriteLine("Number of segment entries: {0}.", heapMap.segments.Length);
            foreach (VmmProcess.HeapSegmentEntry segmentEntry in heapMap.segments)
            {
                Console.WriteLine("{0} \t {1} \t {2:X} \t {3}", segmentEntry, segmentEntry.iHeapNum, segmentEntry.va, segmentEntry.tpHeapSegment);
            }


            // Example: vmmprocess.MapHeapAlloc():
            // Retrieve info about the allocated heap entries for heap 0.
            Console.WriteLine("====================================");
            Console.WriteLine("VmmProcess.MapHeapAlloc():");
            VmmProcess.HeapAllocEntry[] heapAllocEntries = explorerProcess.MapHeapAlloc(0);
            Console.WriteLine("Number of heap alloc entries: {0}.", heapAllocEntries.Length);
            foreach (VmmProcess.HeapAllocEntry heapAllocEntry in heapAllocEntries)
            {
                Console.Write("{0:X}+{1:X}:{2}  ", heapAllocEntry.va, heapAllocEntry.cb, heapAllocEntry.tp);
            }
            Console.WriteLine();


            // Example: vmmprocess.MapThread():
            // Retrieve information about the process threads.
            Console.WriteLine("====================================");
            Console.WriteLine("VmmProcess.MapThread():");
            VmmProcess.ThreadEntry[] threadEntries = explorerProcess.MapThread();
            Console.WriteLine("Number of thread entries: {0}.", threadEntries.Length);
            foreach (VmmProcess.ThreadEntry threadEntry in threadEntries)
            {
                Console.WriteLine("{0} \t {1} \t {2} \t {3}", threadEntry, threadEntry.bState, threadEntry.dwTID, threadEntry.dwPID);
            }


            // Example: vmmprocess.MapThreadCallstack():
            // Retrieve information about a thread callstack.
            Console.WriteLine("====================================");
            Console.WriteLine("VmmProcess.MapThreadCallstack():");
            VmmProcess.ThreadCallstackEntry[] threadCallstackEntries = explorerProcess.MapThreadCallstack(threadEntries[0].dwTID);
            Console.WriteLine("Number of thread callstack entries: {0}.", threadCallstackEntries.Length);
            foreach (VmmProcess.ThreadCallstackEntry threadCallstackEntry in threadCallstackEntries)
            {
                Console.WriteLine("{0}   {1}:{2}   {3}: {4:X} {5:X} \t {6}!{7}+{8}",
                    threadCallstackEntry, threadCallstackEntry.dwPID, threadCallstackEntry.dwTID,
                    threadCallstackEntry.i, threadCallstackEntry.vaRSP, threadCallstackEntry.vaRetAddr,
                    threadCallstackEntry.sModule, threadCallstackEntry.sFunction, threadCallstackEntry.cbDisplacement);
            }


            // Example: vmmprocess.MapUnloadedModule():
            // Retrieve information about unloaded modules (if any).
            Console.WriteLine("====================================");
            Console.WriteLine("VmmProcess.MapUnloadedModule():");
            VmmProcess.UnloadedModuleEntry[] unloadedModuleEntries = explorerProcess.MapUnloadedModule();
            Console.WriteLine("Number of unloaded module entries: {0}.", unloadedModuleEntries.Length);
            foreach (VmmProcess.UnloadedModuleEntry unloadedModuleEntry in unloadedModuleEntries)
            {
                Console.WriteLine("{0} \t {1:X} \t {2}", unloadedModuleEntry, unloadedModuleEntry.vaBase, unloadedModuleEntry.wText);
            }


            // Example: vmmprocess.MapModule():
            // Retrieve information about process modules.
            // NB! Debug Info and Version Info will slow down parsing somewhat.
            Console.WriteLine("====================================");
            Console.WriteLine("VmmProcess.MapModule():");
            VmmProcess.ModuleEntry[] moduleEntries = explorerProcess.MapModule(true);
            Console.WriteLine("Number of module entries: {0}.", moduleEntries.Length);
            foreach (VmmProcess.ModuleEntry moduleEntry in moduleEntries)
            {
                Console.WriteLine("{0} \t {1:X}->{2:X} \t {3} \t {4} \t {5}",
                    moduleEntry,
                    moduleEntry.vaBase,
                    moduleEntry.vaBase + moduleEntry.cbImageSize - 1,
                    moduleEntry.sFullName,
                    moduleEntry.DebugInfo.sPdbFilename,
                    moduleEntry.VersionInfo.sFileOriginalFilename);
            }


            // Example: locate the module of kernel32 within the modules.
            // NB! this will panic if kernel32 is not found, but use this
            //     for simplicity below.
            VmmProcess.ModuleEntry? kernel32Opt = null;
            foreach (VmmProcess.ModuleEntry moduleEntry in moduleEntries)
            {
                if(moduleEntry.sFullName.IndexOf("kernel32.dll", StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    kernel32Opt = moduleEntry;
                    break;
                }
            }
            if (kernel32Opt == null)
            {
                Console.WriteLine("Kernel32.dll not found. Exiting...");
                return;
            }
            VmmProcess.ModuleEntry kernel32 = kernel32Opt.Value;


            // Show debug information related to kernel32.
            // NB! debug info is retrieved on a best-effort way if the flag
            //     fExtendedInfo is set to true in the vmmprocess.MapModule() call.
            Console.WriteLine("====================================");
            Console.WriteLine("VmmProcess.ModuleEntry.DebugInfo:");
            Console.WriteLine("PDB: {0}", kernel32.DebugInfo.sPdbFilename);
            Console.WriteLine("GUID: {0}", kernel32.DebugInfo.sGuid);


            // Show version information related to kernel32.
            // NB! version info is retrieved on a best-effort way if the flag
            //     fExtendedInfo is set to true in the vmmprocess.MapModule() call.
            Console.WriteLine("====================================");
            Console.WriteLine("VmmProcess.ModuleEntry.VersionInfo:");
            Console.WriteLine("OriginalFilename: {0}", kernel32.VersionInfo.sFileOriginalFilename);
            Console.WriteLine("FileVersion:      {0}", kernel32.VersionInfo.sFileVersion);
            Console.WriteLine("ProductVersion:   {0}", kernel32.VersionInfo.sProductVersion);
            Console.WriteLine("Legal Copyright:  {0}", kernel32.VersionInfo.sLegalCopyright);
            Console.WriteLine("Company:          {0}", kernel32.VersionInfo.sCompanyName);
            Console.WriteLine("Description:      {0}", kernel32.VersionInfo.sFileDescription);
            Console.WriteLine("Product:          {0}", kernel32.VersionInfo.sProductName);
            Console.WriteLine("InternalName:     {0}", kernel32.VersionInfo.sInternalName);


            // Example: vmmprocess.MapModuleEAT():
            // Retrieve exported functions in the export address table (EAT) of a
            // module (kernel32 in this case).
            Console.WriteLine("====================================");
            Console.WriteLine("VmmProcess.MapModuleEAT():");
            VmmProcess.EATEntry[] exportEntries = explorerProcess.MapModuleEAT("kernel32.dll");
            Console.WriteLine("Number of export entries: {0}.", exportEntries.Length);
            foreach (VmmProcess.EATEntry exportEntry in exportEntries)
            {
                Console.WriteLine("{0} \t {1:X} \t {2} \t {3}", exportEntry, exportEntry.vaFunction, exportEntry.sFunction, exportEntry.sForwardedFunction);
            }


            // Example: vmmprocess.MapModuleIAT():
            // Retrieve imported functions in the import address table (IAT) of a
            // module (kernel32 in this case).
            Console.WriteLine("====================================");
            Console.WriteLine("VmmProcess.MapModuleIAT():");
            VmmProcess.IATEntry[] importEntries = explorerProcess.MapModuleIAT("kernel32.dll");
            Console.WriteLine("Number of import entries: {0}.", importEntries.Length);
            foreach (VmmProcess.IATEntry importEntry in importEntries)
            {
                Console.WriteLine("{0} \t {1:X} \t {2}!{3}", importEntry, importEntry.vaFunction, importEntry.sModule, importEntry.sFunction);
            }


            // Example: vmmprocess.MapModuleDataDirectory():
            // Retrieve info about the PE data directories, which always equal 16.
            Console.WriteLine("====================================");
            Console.WriteLine("VmmProcess.MapModuleDataDirectory():");
            VmmProcess.IMAGE_DATA_DIRECTORY[] dataDirectoryEntries = explorerProcess.MapModuleDataDirectory("kernel32.dll");
            Console.WriteLine("Number of data directory entries: {0}.", dataDirectoryEntries.Length);
            foreach (VmmProcess.IMAGE_DATA_DIRECTORY dataDirectoryEntry in dataDirectoryEntries)
            {
                Console.WriteLine("{0} \t {1:X} \t {2:X} \t {3}", dataDirectoryEntry, dataDirectoryEntry.VirtualAddress, dataDirectoryEntry.Size, dataDirectoryEntry.name);
            }


            // Example: vmmprocess.MapModuleSection():
            // Retrieve info about the PE sections.
            Console.WriteLine("====================================");
            Console.WriteLine("VmmProcess.MapModuleSection():");
            VmmProcess.IMAGE_SECTION_HEADER[] sectionEntries = explorerProcess.MapModuleSection("kernel32.dll");
            Console.WriteLine("Number of section entries: {0}.", sectionEntries.Length);
            foreach (VmmProcess.IMAGE_SECTION_HEADER sectionEntry in sectionEntries)
            {
                Console.WriteLine("{0} \t {1:X} \t {2:X} \t {3}", sectionEntry, sectionEntry.VirtualAddress, sectionEntry.MiscPhysicalAddressOrVirtualSize, sectionEntry.Name);
            }
            #endregion // Process map/info functionality


            #region Process PDB (debugging) functionality

            // Example: vmmprocess.Pdb() [by address]:
            // Retrieve debugging information (for microsoft modules) given
            // the module base address.
            Console.WriteLine("====================================");
            Console.WriteLine("VmmProcess.Pdb() [by address]:");
            VmmPdb pdbKernel32_1 = explorerProcess.Pdb(kernel32.vaBase);
            Console.WriteLine(pdbKernel32_1);


            // Example: vmmprocess.Pdb() [by name]:
            // Retrieve debugging information (for microsoft modules) given
            // the module name. If there are multiple modules with the same
            // name use vmmprocess.pdb_from_module_address().
            Console.WriteLine("====================================");
            Console.WriteLine("VmmProcess.Pdb() [by name]:");
            VmmPdb pdbKernel32_2 = explorerProcess.Pdb("kernel32.dll");
            Console.WriteLine(pdbKernel32_2);
            #endregion // Process PDB (debugging) functionality


            #region Process Search and YARA functionality

            // Example: vmmprocess.Search() #1: - asynchronous.
            // Search process virtual memory efficiently.
            // Search whole address space in asynchronous non-blocking mode and update.
            // Search max 0x10000 hits (max allowed).
            Console.WriteLine("====================================");
            Console.WriteLine("VmmProcess.Search() #1 [async]:");
            byte[] SEARCH1_TERM1 = { 0x4D, 0x5A }; // MZ
            VmmSearch search1 = explorerProcess.Search();
            VmmSearch.SearchResult search1Result;
            uint search1TermId = search1.AddSearch(SEARCH1_TERM1, null, 0x1000);
            Console.WriteLine("search term with id={0} added.", search1TermId);
            search1.Start();
            while (true)
            {
                search1Result = search1.Poll();
                Console.WriteLine("search poll status: completed={0} va_current={1:x} read_bytes={2:x} results={3}", search1Result.isCompleted, search1Result.addrCurrent, search1Result.totalReadBytes, search1Result.result.Count);
                if (search1Result.isCompleted)
                {
                    break;
                }
                System.Threading.Thread.Sleep(100);
            }
            search1Result = search1.Result();
            Console.WriteLine("search result: completed={0} success={4} va_current={1:x} read_bytes={2:x} results={3}", search1Result.isCompleted, search1Result.addrCurrent, search1Result.totalReadBytes, search1Result.result.Count, search1Result.isCompletedSuccess);
            foreach (VmmSearch.SearchResultEntry search1ResultEntry in search1Result.result)
            {
                Console.Write("{0:X}({1})  ", search1ResultEntry.address, search1ResultEntry.search_term_id);
            }
            Console.WriteLine();


            // Example: vmmprocess.Search() #2: - synchronous.
            // Search process virtual memory efficiently.
            // Search whole address space in synchronous blocking mode.
            // Search max 0x10000 hits (max allowed).
            Console.WriteLine("====================================");
            Console.WriteLine("VmmProcess.Search() #2 [sync]:");
            byte[] SEARCH2_TERM1 = { 0x4D, 0x5A }; // MZ
            VmmSearch search2 = explorerProcess.Search(0, ulong.MaxValue, 0x10000, Vmm.FLAG_NOCACHE);
            uint search2TermID = search2.AddSearch(SEARCH2_TERM1, null, 0x1000);
            Console.WriteLine("search term with id={0} added.", search2TermID);
            VmmSearch.SearchResult search2Result = search2.Result();
            Console.WriteLine("search result: completed={0} success={4} va_current={1:x} read_bytes={2:x} results={3}", search2Result.isCompleted, search2Result.addrCurrent, search2Result.totalReadBytes, search2Result.result.Count, search2Result.isCompletedSuccess);
            foreach (VmmSearch.SearchResultEntry search2ResultEntry in search2Result.result)
            {
                Console.Write("{0:X}({1})  ", search2ResultEntry.address, search2ResultEntry.search_term_id);
            }
            Console.WriteLine();


            // Example: vmmprocess.SearchYara() #1: - asynchronous.
            // Search process virtual memory efficiently using a yara signature.
            // Search whole address space in asynchronous non-blocking mode and update.
            // Search max 0x10000 hits (max allowed).
            // In this example a simple yara signature is used to find the string
            // "MZ" at the start of a page.
            // it's also possible to load yara rules from files - in that case
            // specify the full file path instead of the yara rule string.
            Console.WriteLine("====================================");
            Console.WriteLine("VmmProcess.SearchYara() #1 [async]:");
            string YARA_RULE1 = "rule MZ { strings: $mz = \"MZ\" condition: $mz at 0 }";
            VmmYara yara1 = explorerProcess.SearchYara(YARA_RULE1);
            yara1.Start();
            while (true)
            {
                VmmYara.YaraResult yara1Result = yara1.Poll();
                Console.WriteLine("yara poll status: completed={0} va_current={1:x} read_bytes={2:x} results={3}", yara1Result.isCompleted, yara1Result.addrCurrent, yara1Result.totalReadBytes, yara1Result.result.Count);
                if (yara1Result.isCompleted)
                {
                    break;
                }
                System.Threading.Thread.Sleep(100);
            }
            VmmYara.YaraResult yara1ResultFinal = yara1.Result();
            Console.WriteLine("yara result: completed={0} success={4} va_current={1:x} read_bytes={2:x} results={3}", yara1ResultFinal.isCompleted, yara1ResultFinal.addrCurrent, yara1ResultFinal.totalReadBytes, yara1ResultFinal.result.Count, yara1ResultFinal.isCompletedSuccess);
            foreach (VmmYara.YaraMatch yara1Match in yara1ResultFinal.result)
            {
                Console.Write("rule={0} :: ", yara1Match.sRuleIdentifier);
                foreach (VmmYara.YaraMatchString yaraMatchString in yara1Match.strings)
                {
                    Console.Write("{0}:", yaraMatchString.sString);
                    foreach (ulong yaraMatchAddress in yaraMatchString.addresses)
                    {
                        Console.Write("{0:X},", yaraMatchAddress);
                    }
                }
                Console.WriteLine("");
            }
            #endregion // Process Search and YARA functionality


            #region Process Virtual Memory Read/Write functionality
            // Example: vmmprocess.MemWrite():
            // Write to virtual memory of kernel32 PE header (dangerous)
            // (Writes are only possible if underlying layers are write-capable.)
            Console.WriteLine("====================================");
            Console.WriteLine("VmmProcess.MemWrite():");
            byte[] memWriteData = { 0x56, 0x4D, 0x4D, 0x52, 0x55, 0x53, 0x54 };
            bool fMemWrite = explorerProcess.MemWrite(kernel32.vaBase, memWriteData);


            // Example: vmmprocess.MemRead():
            // Read 0x100 bytes from beginning of explorer.exe!kernel32.dll
            Console.WriteLine("====================================");
            Console.WriteLine("VmmProcess.MemRead():");
            byte[] memReadData = explorerProcess.MemRead(kernel32.vaBase, 0x100);
            Console.WriteLine("Read from explorer.exe!kernel32.dll: \n{0}", Vmm.UtilFillHexAscii(memReadData));


            // Example: vmmprocess.MemRead():
            // Read 0x100 bytes from beginning of explorer.exe!kernel32.dll with vmm flags.
            Console.WriteLine("====================================");
            Console.WriteLine("VmmProcess.MemRead() [flags]:");
            byte[] memReadDataFlags = explorerProcess.MemRead(kernel32.vaBase, 0x100, Vmm.FLAG_NOCACHE | Vmm.FLAG_ZEROPAD_ON_FAIL);
            Console.WriteLine("Read from explorer.exe!kernel32.dll: \n{0}", Vmm.UtilFillHexAscii(memReadDataFlags));


            // Example: vmmprocess.MemReadAs():
            // Read Handle value at kernel32.dll Offset
            Console.WriteLine("====================================");
            Console.WriteLine("VmmProcess.MemReadAs():");
            if (explorerProcess.MemReadAs<IntPtr>(kernel32.vaBase + 0x100) is IntPtr hKernel32)
            {
                // Read Success -> Inspect Result
                hKernel32 = IntPtr.Zero;
                // Attempt to write modified handle back
                if (explorerProcess.MemWriteStruct(kernel32.vaBase + 0x100, hKernel32))
                {
                    // Successful Write
                }
            }


            // Example: vmmprocess.MemVirt2Phys():
            // Retrieve the physical base address of explorer.exe!kernel32.dll.
            Console.WriteLine("====================================");
            Console.WriteLine("VmmProcess.MemVirt2Phys():");
            ulong vaKernel32Phys = explorerProcess.MemVirt2Phys(kernel32.vaBase);


            // Example: vmmprocess.Scatter_Initialize():
            // Retrieve the virtual base address of explorer.exe!kernel32.dll.
            Console.WriteLine("====================================");
            Console.WriteLine("VmmProcess.Scatter_Initialize():");
            VmmScatterMemory scatter = explorerProcess.Scatter_Initialize(Vmm.FLAG_NOCACHE);
            if (scatter != null)
            {
                // prepare multiple ranges to read
                scatter.Prepare(kernel32.vaBase, 0x100);
                scatter.Prepare(kernel32.vaBase + 0x2000, 0x100);
                scatter.Prepare(kernel32.vaBase + 0x3000, (uint)Marshal.SizeOf<IntPtr>());
                // prepare struct value to write
                scatter.PrepareWriteStruct<IntPtr>(kernel32.vaBase, IntPtr.Zero);
                // execute actual read operation to underlying system
                scatter.Execute();
                byte[] pbKernel32_100_1 = scatter.Read(kernel32.vaBase, 0x80);
                byte[] pbKernel32_100_2 = scatter.Read(kernel32.vaBase + 0x2000, 0x100);
                // if scatter object is to be reused for additional reads after a
                // Execute() call it should be cleared before preparing new ranges.
                scatter.Clear(Vmm.FLAG_NOCACHE);
                scatter.Prepare(kernel32.vaBase + 0x3000, 0x100);
                scatter.Prepare(kernel32.vaBase + 0x4000, 0x100);
                scatter.Execute();
                byte[] pbKernel32_100_3 = scatter.Read(kernel32.vaBase + 0x3000, 0x100);
                Console.WriteLine("Read from explorer.exe!kernel32.dll+3000+100: \n{0}", Vmm.UtilFillHexAscii(pbKernel32_100_3));
                byte[] pbKernel32_100_4 = scatter.Read(kernel32.vaBase + 0x4000, 0x100);
                Console.WriteLine("Read from explorer.exe!kernel32.dll+4000+100: \n{0}", Vmm.UtilFillHexAscii(pbKernel32_100_4));
                scatter.ReadAs<IntPtr>(kernel32.vaBase + 0x3000, out IntPtr intPtrResult);
                // clean up scatter handle hS (free native memory)
                // NB! hS handle should not be used after this!
                scatter.Close();
            }
            #endregion // Process Virtual Memory Read/Write functionality
        }
    }


    public static class LeechCoreExample
    {
        public static readonly string DEVICE_OR_FILE = "c:\\dumps\\WIN7-x64-SP1-1.pmem";

        public static void Run()
        {
            // Example: Create LeechCore Object:
            // It's also possible to create LeechCore objects from an active
            // MemProcFS Vmm instance with new LeechCore(vmm).
            Console.WriteLine("====================================");
            Console.WriteLine("Initializing LeechCore...");
            LeechCore leechcore = new LeechCore("file://c:\\dumps\\WIN7-X64-SP1-1.pmem", "", LeechCore.LC_CONFIG_PRINTF_ENABLED | LeechCore.LC_CONFIG_PRINTF_V, 0);


            // Example: leechcore.Read():
            // Read 128 bytes from address 0x1000.
            Console.WriteLine("====================================");
            Console.WriteLine("LeechCore.Read():");
            byte[] memRead = leechcore.Read(0x1000, 128);
            Console.WriteLine("Read from address 0x1000: \n{0}", Vmm.UtilFillHexAscii(memRead));


            // Example: leechcore.ReadScatter():
            // Scatter read two memory pages in one single run.
            Console.WriteLine("====================================");
            Console.WriteLine("LeechCore.ReadScatter():");
            LeechCore.MemScatter[] MEMs = leechcore.ReadScatter(0x1000, 0x2000);
            foreach (LeechCore.MemScatter MEM in MEMs)
            {
                Console.WriteLine("Read from address {0:X} ({1} bytes): \n{2}", MEM.qwA, MEM.pb.Length, Vmm.UtilFillHexAscii(MEM.pb));
            }


            // Example: leechcore.GetOption() / leechcore.SetOption():
            // Get/Set LeechCore option.
            Console.WriteLine("====================================");
            ulong qwOptionVerboseExtra_Pre, qwOptionVerboseExtra_Post;
            qwOptionVerboseExtra_Pre = leechcore.GetOption(LeechCore.LC_OPT_CORE_VERBOSE_EXTRA);
            leechcore.SetOption(LeechCore.LC_OPT_CORE_VERBOSE_EXTRA, 1);
            qwOptionVerboseExtra_Post = leechcore.GetOption(LeechCore.LC_OPT_CORE_VERBOSE_EXTRA);
            Console.WriteLine("LC_OPT_CORE_VERBOSE_EXTRA: {0} -> {1}", qwOptionVerboseExtra_Pre, qwOptionVerboseExtra_Post);


            // Example: leechcore.GetMemMap():
            // Get memory map (as seen by LeechCore):
            Console.WriteLine("====================================");
            Console.WriteLine("LeechCore.GetMemMap():");
            string sMemMap = leechcore.GetMemMap();
            // Set memory map:
            if (sMemMap != null)
            {
                leechcore.SetMemMap(sMemMap);
            }
            Console.WriteLine("Memory map: \n{0}", sMemMap);


            // Example: leechcore.Close():
            // Close the LeechCore handle. Unless done manually the handle will be
            // automatically closed by Dispose() when the object is garbage collected.
            leechcore.Close();
        }
    }
}
