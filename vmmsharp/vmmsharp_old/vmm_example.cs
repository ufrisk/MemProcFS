using System;
using System.Runtime.InteropServices;
using System.Text;
using vmmsharp;

/*  
 *  Examples of using the PCILeech / LeechCore / MemProcFS "Lc" and "Vmm" APIs for C#
 *  
 *  1) Include the file 'vmmsharp.cs' in your project.
 *  2) Make sure your C# project is run as x64 (not x86 or AnyCPU). This is because the
 *     natíve 'leechcore.dll' and 'vmm.dll' only exists as 64-bit native binaries.
 *  3) Make sure the MemProcFS binaries (vmm.dll / leechcore.dll and related binaries)
 *     are located alongside your C# binary or in the "current directory".
 *     
 *  The examples in this file generally don't print anything on the screen, but if
 *  running it from within Visual Studio with breakpoints it should be fairly easy
 *  to follow the calls and have a look at the different return data.
 *  
 *  (c) Ulf Frisk, 2020-2024
 *  Author: Ulf Frisk, pcileech@frizk.net
 *  
 */
class vmm_example
{
    static bool ExampleVfsCallBack_AddFile(ulong h, [MarshalAs(UnmanagedType.LPUTF8Str)] string wszName, ulong cb, IntPtr pExInfo)
    {
        ulong ft = 0;
        if(pExInfo != IntPtr.Zero)
        {
            Vmm.VMMDLL_VFS_FILELIST_EXINFO n = Marshal.PtrToStructure<Vmm.VMMDLL_VFS_FILELIST_EXINFO>(pExInfo);
            ft = n.ftLastWriteTime;
        }
        Console.WriteLine("VFS LIST CALLBACK: HANDLE: " + h + " FILE: '" + wszName + "' SIZE '" + cb + "'\tFileWriteTime " + ft);
        return true;
    }

    static bool ExampleVfsCallBack_AddDirectory(ulong h, [MarshalAs(UnmanagedType.LPUTF8Str)] string wszName, IntPtr pExInfo)
    {
        ulong ft = 0;
        if (pExInfo != IntPtr.Zero)
        {
            Vmm.VMMDLL_VFS_FILELIST_EXINFO n = Marshal.PtrToStructure<Vmm.VMMDLL_VFS_FILELIST_EXINFO>(pExInfo);
            ft = n.ftLastWriteTime;
        }
        Console.WriteLine("VFS LIST CALLBACK: HANDLE: " + h + " FILE: '" + wszName + "'\tFileWriteTime " + ft);
        return true;
    }

    static void ExampleVmm()
    {
        bool result;
        uint nt;
        // initialize vmm with verbose mode with fpga device
        //vmm vmm = new vmm("-printf", "-v", "-device", "fpga");

        // initialize vmm with verbose mode with dump file
        Vmm vmm = new Vmm("-printf", "-v", "-device", "c:\\dumps\\WIN7-X64-SP1-1.pmem");

        // get / set vmm config options
        ulong ulOptionMM, ulOptionVV;
        result = vmm.ConfigGet(Vmm.OPT_CORE_MEMORYMODEL, out ulOptionMM);
        result = vmm.ConfigGet(Vmm.OPT_CORE_VERBOSE_EXTRA, out ulOptionVV);
        result = vmm.ConfigSet(Vmm.OPT_CORE_VERBOSE_EXTRA, 1);
        result = vmm.ConfigGet(Vmm.OPT_CORE_VERBOSE_EXTRA, out ulOptionVV);

        // Get Memory Map Functionality
        string memMap = vmm.GetMemoryMap();
        if (memMap != null)
        {
            // Write output to Text File
            //System.IO.File.WriteAllBytes("mmap.txt", System.Text.Encoding.ASCII.GetBytes(memMap));
        }

        // initialize plugins (required for vfs)
        vmm.InitializePlugins();

        // vfs (virtual file system) list / read / write
        result = vmm.VfsList("\\", 1, ExampleVfsCallBack_AddFile, ExampleVfsCallBack_AddDirectory);
        byte[] pbMemoryRead;
        nt = vmm.VfsRead("\\memory.pmem", 0x200, 0x1000, out pbMemoryRead);
        nt = vmm.VfsWrite("\\memory.pmem", pbMemoryRead, 0x1000);

        // memory read : physical with scatter function (2 pages)
        MEM_SCATTER[] MEMsPhysical = vmm.MemReadScatter(0xffffffff, 0, 0x1000, 0x2000);

        // retrieve all PIDs in the system as a sorted list.
        uint[] dwPidAll = vmm.PidList();

        // retrieve PID of explorer.exe (it's assumed it's started, otherwise example will fail)
        uint dwExplorerPID;
        vmm.PidGetFromName("explorer.exe", out dwExplorerPID);
        
        // get kernel path of explorer.exe
        string strKernel32KernelPath = vmm.ProcessGetInformationString(dwExplorerPID, Vmm.VMMDLL_PROCESS_INFORMATION_OPT_STRING_PATH_KERNEL);

        // retrieve process information of explorer.exe
        Vmm.PROCESS_INFORMATION ProcInfo = vmm.ProcessGetInformation(dwExplorerPID);

        // get procaddress of kernel32.dll!GetTickCount64 and module base
        ulong vaTickCount64 = vmm.ProcessGetProcAddress(dwExplorerPID, "kernel32.dll", "GetTickCount64");
        ulong vaKernel32Base = vmm.ProcessGetModuleBase(dwExplorerPID, "kernel32.dll");

        // retrieve Directories/Sections/IAT/EAT from kernel32.dll of explorer.exe
        Vmm.IMAGE_DATA_DIRECTORY[] DIRs = vmm.ProcessGetDirectories(dwExplorerPID, "kernel32.dll");
        Vmm.IMAGE_SECTION_HEADER[] SECTIONs = vmm.ProcessGetSections(dwExplorerPID, "kernel32.dll");

        // retrieve different "map" structures related to explorer.exe and the system.
        Vmm.MAP_PTEENTRY[] mPte = vmm.Map_GetPte(dwExplorerPID);
        Vmm.MAP_VADENTRY[] mVad = vmm.Map_GetVad(dwExplorerPID);
        Vmm.MAP_VADEXENTRY[] mVadEx = vmm.Map_GetVadEx(dwExplorerPID, 0, 10);
        Vmm.MAP_MODULEENTRY[] mModule = vmm.Map_GetModule(dwExplorerPID, false);
        Vmm.MAP_MODULEENTRY[] mModuleExInfo = vmm.Map_GetModule(dwExplorerPID, true);
        Vmm.MAP_MODULEENTRY mModuleKernel32 = vmm.Map_GetModuleFromName(dwExplorerPID, "kernel32.dll");
        Vmm.MAP_UNLOADEDMODULEENTRY[] mUnloadedModule = vmm.Map_GetUnloadedModule(dwExplorerPID);
        Vmm.MAP_EATINFO EatInfo;
        Vmm.MAP_EATENTRY[] mEAT = vmm.Map_GetEAT(dwExplorerPID, "kernel32.dll", out EatInfo);
        Vmm.MAP_IATENTRY[] mIAT = vmm.Map_GetIAT(dwExplorerPID, "kernel32.dll");
        Vmm.MAP_HEAP mHeap = vmm.Map_GetHeap(dwExplorerPID);
        Vmm.MAP_HEAPALLOCENTRY[] mHeapAlloc = vmm.Map_GetHeapAlloc(dwExplorerPID, 2);
        Vmm.MAP_THREADENTRY[] mThreads = vmm.Map_GetThread(dwExplorerPID);
        Vmm.MAP_HANDLEENTRY[] mHandles = vmm.Map_GetHandle(dwExplorerPID);
        Vmm.MAP_NETENTRY[] mNetworkConnections = vmm.Map_GetNet();
        Vmm.MAP_PHYSMEMENTRY[] mPhysMemRanges = vmm.Map_GetPhysMem();
        Vmm.MAP_POOLENTRY[] mPoolAllocations = vmm.Map_GetPool();
        Vmm.MAP_USERENTRY[] mUsers = vmm.Map_GetUsers();
        Vmm.MAP_SERVICEENTRY[] mServices = vmm.Map_GetServices();
        Vmm.MAP_PFNENTRY[] mPfn = vmm.Map_GetPfn(1, 2, 1024);

        // read first 128 bytes of kernel32.dll
        byte[] dataKernel32MZ = vmm.MemRead(dwExplorerPID, mModuleKernel32.vaBase, 128, 0);

        // Read Handle value at kernel32.dll Offset
        if (vmm.MemReadStruct<IntPtr>(dwExplorerPID, mModuleKernel32.vaBase + 0x100, out var hKernel32))
        {
            // Read Success -> Inspect Result
            hKernel32 = IntPtr.Zero;
            // Attempt to write modified handle back
            if (vmm.MemWriteStruct(dwExplorerPID, mModuleKernel32.vaBase + 0x100, hKernel32))
            {
                // Successful Write
            }
        }

        // Read string: "This program cannot be run in DOS mode" from kernel32.dll with ascii encoding (offset: 0x4e).
        string strDosMode = vmm.MemReadString(Encoding.ASCII, dwExplorerPID, mModuleKernel32.vaBase + 0x4e, 0x26);

        // translate virtual address of 1st page in kernel32.dll to physical address
        ulong paBaseKernel32;
        result = vmm.MemVirt2Phys(dwExplorerPID, mModuleKernel32.vaBase, out paBaseKernel32);

        // read two independent chunks of memory in one single efficient call.
        // also use the nocache flag.
        VmmScatter scatter = vmm.Scatter_Initialize(dwExplorerPID, Vmm.FLAG_NOCACHE);
        if(scatter != null)
        {
            // prepare multiple ranges to read
            scatter.Prepare(mModuleKernel32.vaBase, 0x100);
            scatter.Prepare(mModuleKernel32.vaBase + 0x2000, 0x100);
            scatter.Prepare(mModuleKernel32.vaBase + 0x3000, (uint)Marshal.SizeOf<IntPtr>());
            // prepare struct value to write
            scatter.PrepareWriteStruct<IntPtr>(mModuleKernel32.vaBase, IntPtr.Zero);
            // execute actual read operation to underlying system
            scatter.Execute();
            byte[] pbKernel32_100_1 = scatter.Read(mModuleKernel32.vaBase, 0x80);
            byte[] pbKernel32_100_2 = scatter.Read(mModuleKernel32.vaBase + 0x2000, 0x100);
            // if scatter object is to be reused for additional reads after a
            // Execute() call it should be cleared before preparing new ranges.
            scatter.Clear(dwExplorerPID, Vmm.FLAG_NOCACHE);
            scatter.Prepare(mModuleKernel32.vaBase + 0x3000, 0x100);
            scatter.Prepare(mModuleKernel32.vaBase + 0x4000, 0x100);
            scatter.Execute();
            byte[] pbKernel32_100_3 = scatter.Read(mModuleKernel32.vaBase + 0x3000, 0x100);
            byte[] pbKernel32_100_4 = scatter.Read(mModuleKernel32.vaBase + 0x4000, 0x100);
            scatter.ReadStruct<IntPtr>(mModuleKernel32.vaBase + 0x3000, out IntPtr intPtrResult);
            // clean up scatter handle hS (free native memory)
            // NB! hS handle should not be used after this!
            scatter.Close();
        }

        // load .pdb of kernel32 from microsoft symbol server and query it
        // also do some lookups for kernel symbols.
        string szPdbModuleName = "";
        result = vmm.PdbLoad(dwExplorerPID, mModuleKernel32.vaBase, out szPdbModuleName);
        if (result)
        {
            uint dwSymbolOffset = (uint)(mModuleKernel32.vaEntry - mModuleKernel32.vaBase);
            string szEntryPoint;
            uint dwEntryPointDisplacement;
            result = vmm.PdbSymbolName(szPdbModuleName, dwSymbolOffset, out szEntryPoint, out dwEntryPointDisplacement);
        }
        ulong vaKeQueryOwnerMutant;
        result = vmm.PdbSymbolAddress("nt", "KeQueryOwnerMutant", out vaKeQueryOwnerMutant);
        uint oOptionalHeaders;
        result = vmm.PdbTypeChildOffset("nt", "_IMAGE_NT_HEADERS64", "OptionalHeader", out oOptionalHeaders);

        // WINDOWS REGISTRY QUERY / READ / WRITE
        Vmm.REGISTRY_HIVE_INFORMATION[] RegHives = vmm.RegHiveList();
        if(RegHives.Length > 0)
        {
            byte[] RegHiveData = vmm.RegHiveRead(RegHives[0].vaCMHIVE, 0x1000, 0x100, 0);
        }
        Vmm.REGISTRY_ENUM RegEnum = vmm.RegEnum("HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion");
        if(RegEnum.ValueList.Count > 0)
        {
            uint RegValueType;
            byte[] RegValueData = vmm.RegValueRead(RegEnum.wszFullPathKey + "\\" + RegEnum.ValueList[0].name, out RegValueType);
        }

        // search efficiently in explorer.exe for "This program cannot be run in DOS mode"
        // (in essence perform a search for PE headers).
        // The search function may take up quite a lot of performance / time depending on memory amount.
        // There is also a vmm.MemSearchM function which allows for searching multiple strings at a time.
        ulong[] vaExplorerPE = vmm.MemSearch1(dwExplorerPID, System.Text.Encoding.ASCII.GetBytes("cannot be run in DOS mode"), 0, 0x7fffffffffff);



        // CLOSE
        vmm.Close();
    }

    static void ExampleLeechCore()
    {
        bool result;


        // CREATE LEECHCORE OBJECT:
        // It's also possible to create LeechCore objects from an active
        // MemProcFS Vmm instance with new LeechCore(vmm).
        LeechCore lc = new LeechCore("file://c:\\dumps\\WIN7-X64-SP1-1.pmem", "", LeechCore.LC_CONFIG_PRINTF_ENABLED | LeechCore.LC_CONFIG_PRINTF_V, 0);


        // Read 128 bytes from address 0x1000.
        byte[] MemRead = lc.Read(0x1000, 128);

        // Scatter read two memory pages in one single run.
        MEM_SCATTER[] MEMs = lc.ReadScatter(0x1000, 0x2000);

        // Get/Set LeechCore option.
        ulong qwOptionVerboseExtra_Pre, qwOptionVerboseExtra_Post;
        result = lc.GetOption(LeechCore.LC_OPT_CORE_VERBOSE_EXTRA, out qwOptionVerboseExtra_Pre);
        result = lc.SetOption(LeechCore.LC_OPT_CORE_VERBOSE_EXTRA, 1);
        result = lc.GetOption(LeechCore.LC_OPT_CORE_VERBOSE_EXTRA, out qwOptionVerboseExtra_Post);

        // Get memory map:
        string sMemMap = lc.GetMemMap();

        // Set memory map:
        if(sMemMap != null)
        {
            lc.SetMemMap(sMemMap);
        }

        // CLOSE LEECHCORE OBJECT:
        lc.Close();
    }

    static void Main(string[] args)
    {
        ExampleLeechCore();
        ExampleVmm();
    }
}
