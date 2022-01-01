using System;
using System.Text;
using System.Runtime.InteropServices;
using System.Collections.Generic;

/*  
 *  C# API wrapper 'vmmsharp' for MemProcFS 'vmm.dll' and LeechCore 'leechcore.dll' APIs.
 *  
 *  Please see the example project in vmm_example.cs for additional information.
 *  
 *  Please consult the C/C++ header files vmmdll.h and leechcore.h for information about
 *  parameters and API usage.
 *  
 *  (c) Ulf Frisk, 2020-2022
 *  Author: Ulf Frisk, pcileech@frizk.net
 *  
 *  Version 3.10
 *  
 */

namespace vmmsharp
{
    public struct MEM_SCATTER
    {
        public bool f;
        public ulong qwA;
        public byte[] pb;
    }

    public static class lc
    {
        public static ulong OPT_CORE_PRINTF_ENABLE =            0x4000000100000000;
        public static ulong OPT_CORE_VERBOSE =                  0x4000000200000000;
        public static ulong OPT_CORE_VERBOSE_EXTRA =            0x4000000300000000;
        public static ulong OPT_CORE_VERBOSE_EXTRA_TLP =        0x4000000400000000;
        public static ulong OPT_CORE_VERSION_MAJOR =            0x4000000500000000;
        public static ulong OPT_CORE_VERSION_MINOR =            0x4000000600000000;
        public static ulong OPT_CORE_VERSION_REVISION =         0x4000000700000000;
        public static ulong OPT_CORE_ADDR_MAX =                 0x1000000800000000;

        public static ulong OPT_MEMORYINFO_VALID =              0x0200000100000000;
        public static ulong OPT_MEMORYINFO_FLAG_32BIT =         0x0200000300000000;
        public static ulong OPT_MEMORYINFO_FLAG_PAE =           0x0200000400000000;
        public static ulong OPT_MEMORYINFO_OS_VERSION_MINOR =   0x0200000500000000;
        public static ulong OPT_MEMORYINFO_OS_VERSION_MAJOR =   0x0200000600000000;
        public static ulong OPT_MEMORYINFO_OS_DTB =             0x0200000700000000;
        public static ulong OPT_MEMORYINFO_OS_PFN =             0x0200000800000000;
        public static ulong OPT_MEMORYINFO_OS_PsLoadedModuleList = 0x0200000900000000;
        public static ulong OPT_MEMORYINFO_OS_PsActiveProcessHead = 0x0200000a00000000;
        public static ulong OPT_MEMORYINFO_OS_MACHINE_IMAGE_TP = 0x0200000b00000000;
        public static ulong OPT_MEMORYINFO_OS_NUM_PROCESSORS =  0x0200000c00000000;
        public static ulong OPT_MEMORYINFO_OS_SYSTEMTIME =      0x0200000d00000000;
        public static ulong OPT_MEMORYINFO_OS_UPTIME =          0x0200000e00000000;
        public static ulong OPT_MEMORYINFO_OS_KERNELBASE =      0x0200000f00000000;
        public static ulong OPT_MEMORYINFO_OS_KERNELHINT =      0x0200001000000000;
        public static ulong OPT_MEMORYINFO_OS_KdDebuggerDataBlock = 0x0200001100000000;

        public static ulong OPT_FPGA_PROBE_MAXPAGES =           0x0300000100000000;
        public static ulong OPT_FPGA_MAX_SIZE_RX =              0x0300000300000000;
        public static ulong OPT_FPGA_MAX_SIZE_TX =              0x0300000400000000;
        public static ulong OPT_FPGA_DELAY_PROBE_READ =         0x0300000500000000;
        public static ulong OPT_FPGA_DELAY_PROBE_WRITE =        0x0300000600000000;
        public static ulong OPT_FPGA_DELAY_WRITE =              0x0300000700000000;
        public static ulong OPT_FPGA_DELAY_READ =               0x0300000800000000;
        public static ulong OPT_FPGA_RETRY_ON_ERROR =           0x0300000900000000;
        public static ulong OPT_FPGA_DEVICE_ID =                0x0300008000000000;
        public static ulong OPT_FPGA_FPGA_ID =                  0x0300008100000000;
        public static ulong OPT_FPGA_VERSION_MAJOR =            0x0300008200000000;
        public static ulong OPT_FPGA_VERSION_MINOR =            0x0300008300000000;
        public static ulong OPT_FPGA_ALGO_TINY =                0x0300008400000000;
        public static ulong OPT_FPGA_ALGO_SYNCHRONOUS =         0x0300008500000000;

        public static ulong CMD_FPGA_WRITE_TLP =                0x0000010100000000;
        public static ulong CMD_FPGA_LISTEN_TLP =               0x0000010200000000;
        public static ulong CMD_FPGA_PCIECFGSPACE =             0x0000010300000000;
        public static ulong CMD_FPGA_CFGREGPCIE =               0x0000010400000000;
        public static ulong CMD_FPGA_CFGREGCFG =                0x0000010500000000;
        public static ulong CMD_FPGA_CFGREGDRP =                0x0000010600000000;
        public static ulong CMD_FPGA_CFGREGCFG_MARKWR =         0x0000010700000000;
        public static ulong CMD_FPGA_CFGREGPCIE_MARKWR =        0x0000010800000000;
        public static ulong CMD_FPGA_PCIECFGSPACE_WR =          0x0000010900000000;
        public static ulong CMD_FPGA_CFGREG_DEBUGPRINT =        0x0000010a00000000;
        public static ulong CMD_FPGA_PROBE =                    0x0000010b00000000;

        public static ulong CMD_FILE_DUMPHEADER_GET =           0x0000020100000000;

        public static ulong CMD_STATISTICS_GET =                0x4000010000000000;
        public static ulong CMD_MEMMAP_GET =                    0x4000020000000000;
        public static ulong CMD_MEMMAP_SET =                    0x4000030000000000;

        public static ulong CMD_AGENT_EXEC_PYTHON =             0x8000000100000000;
        public static ulong CMD_AGENT_EXIT_PROCESS =            0x8000000200000000;

        public static uint CONFIG_VERSION =                     0xc0fd0002;
        public static uint CONFIG_ERRORINFO_VERSION =           0xc0fe0001;

        public static uint CONFIG_PRINTF_ENABLED =              0x01;
        public static uint CONFIG_PRINTF_V =                    0x02;
        public static uint CONFIG_PRINTF_VV =                   0x04;
        public static uint CONFIG_PRINTF_VVV =                  0x08;

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential, CharSet = CharSet.Ansi)]
        public struct CONFIG
        {
            public uint dwVersion;
            public uint dwPrintfVerbosity;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)] public string szDevice;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)] public string szRemote;
            public IntPtr pfn_printf_opt;
            public ulong paMax;
            public bool fVolatile;
            public bool fWritable;
            public bool fRemote;
            public bool fRemoteDisableCompress;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)] public string szDeviceName;
        }

        public struct CONFIG_ERRORINFO
        {
            public bool fValid;
            public bool fUserInputRequest;
            public string strUserText;
        }

        public static unsafe ulong Create(ref CONFIG pLcCreateConfig, out CONFIG_ERRORINFO ConfigErrorInfo)
        {
            IntPtr pLcErrorInfo;
            int cbERROR_INFO = System.Runtime.InteropServices.Marshal.SizeOf(typeof(lci.LC_CONFIG_ERRORINFO));
            ulong hLC = lci.LcCreateEx(ref pLcCreateConfig, out pLcErrorInfo);
            long vaLcCreateErrorInfo = pLcErrorInfo.ToInt64();
            ConfigErrorInfo = new CONFIG_ERRORINFO();
            ConfigErrorInfo.strUserText = "";
            if (vaLcCreateErrorInfo == 0) {
                return hLC;
            }
            lci.LC_CONFIG_ERRORINFO e = Marshal.PtrToStructure<lci.LC_CONFIG_ERRORINFO>(pLcErrorInfo);
            if(e.dwVersion == CONFIG_ERRORINFO_VERSION)
            {
                ConfigErrorInfo.fValid = true;
                ConfigErrorInfo.fUserInputRequest = e.fUserInputRequest;
                if(e.cwszUserText > 0)
                {
                    ConfigErrorInfo.strUserText = Marshal.PtrToStringUni((System.IntPtr)(vaLcCreateErrorInfo + cbERROR_INFO));
                }
            }
            lci.LcMemFree(pLcErrorInfo);
            return hLC;
        }

        public static ulong Create(ref CONFIG pLcCreateConfig)
        {
            CONFIG_ERRORINFO ErrorInfo;
            return Create(ref pLcCreateConfig, out ErrorInfo);
        }

        [DllImport("leechcore.dll", EntryPoint = "LcClose")]
        public static extern void Close(ulong hLC);

        public static unsafe byte[] Read(ulong hLC, ulong pa, uint cb)
        {
            byte[] data = new byte[cb];
            fixed (byte* pb = data)
            {
                bool result = lci.LcRead(hLC, pa, cb, pb);
                return result ? data : null;
            }
        }

        public static unsafe MEM_SCATTER[] ReadScatter(ulong hLC, params ulong[] qwA)
        {
            int i;
            long vappMEMs, vapMEM;
            IntPtr pMEM, pMEM_qwA, pppMEMs;
            if (!lci.LcAllocScatter1((uint)qwA.Length, out pppMEMs))
            {
                return null;
            }
            vappMEMs = pppMEMs.ToInt64();
            for (i = 0; i < qwA.Length; i++)
            {
                vapMEM = Marshal.ReadIntPtr(new IntPtr(vappMEMs + i * 8)).ToInt64();
                pMEM_qwA = new IntPtr(vapMEM + 8);
                Marshal.WriteInt64(pMEM_qwA, (long)(qwA[i] & ~(ulong)0xfff));
            }
            MEM_SCATTER[] MEMs = new MEM_SCATTER[qwA.Length];
            lci.LcReadScatter(hLC, (uint)MEMs.Length, pppMEMs);
            for (i = 0; i < MEMs.Length; i++)
            {
                pMEM = Marshal.ReadIntPtr(new IntPtr(vappMEMs + i * 8));
                lci.LC_MEM_SCATTER n = Marshal.PtrToStructure<lci.LC_MEM_SCATTER>(pMEM);
                MEMs[i].f = n.f;
                MEMs[i].qwA = n.qwA;
                MEMs[i].pb = new byte[0x1000];
                Marshal.Copy(n.pb, MEMs[i].pb, 0, 0x1000);
            }
            lci.LcMemFree(pppMEMs);
            return MEMs;
        }

        public static unsafe bool Write(ulong hLC, ulong pa, byte[] data)
        {
            fixed (byte* pb = data)
            {
                return lci.LcWrite(hLC, pa, (uint)data.Length, pb);
            }
        }

        public static unsafe void WriteScatter(ulong hLC, ref MEM_SCATTER[] MEMs)
        {
            int i;
            long vappMEMs, vapMEM;
            IntPtr pMEM, pMEM_f, pMEM_qwA, pMEM_pb, pppMEMs;
            for (i = 0; i < MEMs.Length; i++)
            {
                if((MEMs[i].pb == null) || (MEMs[i].pb.Length != 0x1000))
                {
                    return;
                }
            }
            if (!lci.LcAllocScatter1((uint)MEMs.Length, out pppMEMs))
            {
                return;
            }
            vappMEMs = pppMEMs.ToInt64();
            for (i = 0; i < MEMs.Length; i++)
            {
                vapMEM = Marshal.ReadIntPtr(new IntPtr(vappMEMs + i * 8)).ToInt64();
                pMEM_f = new IntPtr(vapMEM + 4);
                pMEM_qwA = new IntPtr(vapMEM + 8);
                pMEM_pb = Marshal.ReadIntPtr(new IntPtr(vapMEM + 16));
                Marshal.WriteInt32(pMEM_f, MEMs[i].f ? 1 : 0);
                Marshal.WriteInt64(pMEM_qwA, (long)(MEMs[i].qwA & ~(ulong)0xfff));
                Marshal.Copy(MEMs[i].pb, 0, pMEM_pb, MEMs[i].pb.Length);
            }
            lci.LcWriteScatter(hLC, (uint)MEMs.Length, pppMEMs);
            for (i = 0; i < MEMs.Length; i++)
            {
                pMEM = Marshal.ReadIntPtr(new IntPtr(vappMEMs + i * 8));
                lci.LC_MEM_SCATTER n = Marshal.PtrToStructure<lci.LC_MEM_SCATTER>(pMEM);
                MEMs[i].f = n.f;
                MEMs[i].qwA = n.qwA;
            }
            lci.LcMemFree(pppMEMs);
        }

        [DllImport("leechcore.dll", EntryPoint = "LcGetOption")]
        public static extern bool GetOption(ulong hLC, ulong fOption, out ulong pqwValue);

        [DllImport("leechcore.dll", EntryPoint = "LcSetOption")]
        public static extern bool SetOption(ulong hLC, ulong fOption, ulong qwValue);

        public static unsafe bool Command(ulong hLC, ulong fOption, byte[] DataIn, out byte[] DataOut)
        {
            bool result;
            uint cbDataOut;
            IntPtr PtrDataOut;
            DataOut = null;
            if(DataIn == null)
            {
                result = lci.LcCommand(hLC, fOption, 0, null, out PtrDataOut, out cbDataOut);
            } else
            {
                fixed (byte* pbDataIn = DataIn)
                {
                    result = lci.LcCommand(hLC, fOption, (uint)DataIn.Length, pbDataIn, out PtrDataOut, out cbDataOut);
                }
            }
            if(!result) { return false; }
            DataOut = new byte[cbDataOut];
            if(cbDataOut > 0)
            {
                Marshal.Copy(PtrDataOut, DataOut, 0, (int)cbDataOut);
                lci.LcMemFree(PtrDataOut);
            }
            return true;
        }
    }

    public static class vmm
    {
        //---------------------------------------------------------------------
        // CORE FUNCTIONALITY BELOW:
        //---------------------------------------------------------------------

        public static ulong OPT_CORE_PRINTF_ENABLE =             0x4000000100000000;  // RW
        public static ulong OPT_CORE_VERBOSE =                   0x4000000200000000;  // RW
        public static ulong OPT_CORE_VERBOSE_EXTRA =             0x4000000300000000;  // RW
        public static ulong OPT_CORE_VERBOSE_EXTRA_TLP =         0x4000000400000000;  // RW
        public static ulong OPT_CORE_MAX_NATIVE_ADDRESS =        0x4000000800000000;  // R

        public static ulong OPT_CORE_SYSTEM =                    0x2000000100000000;  // R
        public static ulong OPT_CORE_MEMORYMODEL =               0x2000000200000000;  // R

        public static ulong OPT_CONFIG_IS_REFRESH_ENABLED =      0x2000000300000000;  // R - 1/0
        public static ulong OPT_CONFIG_TICK_PERIOD =             0x2000000400000000;  // RW - base tick period in ms
        public static ulong OPT_CONFIG_READCACHE_TICKS =         0x2000000500000000;  // RW - memory cache validity period (in ticks)
        public static ulong OPT_CONFIG_TLBCACHE_TICKS =          0x2000000600000000;  // RW - page table (tlb) cache validity period (in ticks)
        public static ulong OPT_CONFIG_PROCCACHE_TICKS_PARTIAL = 0x2000000700000000; // RW - process refresh (partial) period (in ticks)
        public static ulong OPT_CONFIG_PROCCACHE_TICKS_TOTAL =   0x2000000800000000;  // RW - process refresh (full) period (in ticks)
        public static ulong OPT_CONFIG_VMM_VERSION_MAJOR =       0x2000000900000000;  // R
        public static ulong OPT_CONFIG_VMM_VERSION_MINOR =       0x2000000A00000000;  // R
        public static ulong OPT_CONFIG_VMM_VERSION_REVISION =    0x2000000B00000000;  // R
        public static ulong OPT_CONFIG_STATISTICS_FUNCTIONCALL = 0x2000000C00000000; // RW - enable function call statistics (.status/statistics_fncall file)
        public static ulong OPT_CONFIG_IS_PAGING_ENABLED =       0x2000000D00000000;  // RW - 1/0

        public static ulong OPT_WIN_VERSION_MAJOR =              0x2000010100000000;  // R
        public static ulong OPT_WIN_VERSION_MINOR =              0x2000010200000000;  // R
        public static ulong OPT_WIN_VERSION_BUILD =              0x2000010300000000;  // R

        public static ulong OPT_FORENSIC_MODE =                  0x2000020100000000;  // RW - enable/retrieve forensic mode type [0-4].

        public static ulong OPT_REFRESH_ALL =                    0x2001ffff00000000;  // W - refresh all caches
        public static ulong OPT_REFRESH_FREQ_FAST =              0x2001040000000000;  // W - refresh fast frequency (including partial process listings)
        public static ulong OPT_REFRESH_FREQ_MEDIUM =            0x2001000100000000;  // W - refresh medium frequency (including full process listings)
        public static ulong OPT_REFRESH_FREQ_SLOW =              0x2001001000000000;  // W - refresh slow frequency (including registry)
        public static ulong OPT_REFRESH_READ =                   0x2001000200000000;  // W - refresh physical read cache
        public static ulong OPT_REFRESH_TLB =                    0x2001000400000000;  // W - refresh page table (TLB) cache
        public static ulong OPT_REFRESH_PAGING =                 0x2001000800000000;  // W - refresh virtual memory 'paging' cache
        public static ulong OPT_REFRESH_USER =                   0x2001002000000000;  // W
        public static ulong OPT_REFRESH_PHYSMEMMAP =             0x2001004000000000;  // W
        public static ulong OPT_REFRESH_PFN =                    0x2001008000000000;  // W
        public static ulong OPT_REFRESH_OBJ =                    0x2001010000000000;  // W
        public static ulong OPT_REFRESH_NET =                    0x2001020000000000;  // W


        public enum MEMORYMODEL_TP
        {
            MEMORYMODEL_NA = 0,
            MEMORYMODEL_X86 = 1,
            MEMORYMODEL_X86PAE = 2,
            MEMORYMODEL_X64 = 3
        }

        public enum SYSTEM_TP
        {
            SYSTEM_UNKNOWN_X64 = 1,
            SYSTEM_WINDOWS_X64 = 2,
            SYSTEM_UNKNOWN_X86 = 3,
            SYSTEM_WINDOWS_X86 = 4
        }

        public static unsafe bool Initialize(out lc.CONFIG_ERRORINFO ConfigErrorInfo, params string[] args)
        {
            IntPtr pLcErrorInfo;
            int cbERROR_INFO = System.Runtime.InteropServices.Marshal.SizeOf(typeof(lci.LC_CONFIG_ERRORINFO));
            bool fResult = vmmi.VMMDLL_InitializeEx(args.Length, args, out pLcErrorInfo);
            long vaLcCreateErrorInfo = pLcErrorInfo.ToInt64();
            ConfigErrorInfo = new lc.CONFIG_ERRORINFO();
            ConfigErrorInfo.strUserText = "";
            if (vaLcCreateErrorInfo == 0)
            {
                return fResult;
            }
            lci.LC_CONFIG_ERRORINFO e = Marshal.PtrToStructure<lci.LC_CONFIG_ERRORINFO>(pLcErrorInfo);
            if (e.dwVersion == lc.CONFIG_ERRORINFO_VERSION)
            {
                ConfigErrorInfo.fValid = true;
                ConfigErrorInfo.fUserInputRequest = e.fUserInputRequest;
                if (e.cwszUserText > 0)
                {
                    ConfigErrorInfo.strUserText = Marshal.PtrToStringUni((System.IntPtr)(vaLcCreateErrorInfo + cbERROR_INFO));
                }
            }
            lci.LcMemFree(pLcErrorInfo);
            return fResult;
        }

        public static bool Initialize(params string[] args)
        {
            lc.CONFIG_ERRORINFO ErrorInfo;
            return Initialize(out ErrorInfo, args);
        }

        [DllImport("vmm.dll", EntryPoint = "VMMDLL_Close")]
        public static extern bool Close();

        [DllImport("vmm.dll", EntryPoint = "VMMDLL_ConfigGet")]
        public static extern bool ConfigGet(ulong fOption, out ulong pqwValue);

        [DllImport("vmm.dll", EntryPoint = "VMMDLL_ConfigSet")]
        public static extern bool ConfigSet(ulong fOption, ulong qwValue);

        //---------------------------------------------------------------------
        // VFS (VIRTUAL FILE SYSTEM) FUNCTIONALITY BELOW:
        //---------------------------------------------------------------------

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential)]
        public struct VMMDLL_VFS_FILELIST_EXINFO
        {
            public uint dwVersion;
            public bool fCompressed;
            public ulong ftCreationTime;
            public ulong ftLastAccessTime;
            public ulong ftLastWriteTime;
        }

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate bool VfsCallBack_AddFile(ulong h, [MarshalAs(UnmanagedType.LPUTF8Str)] string wszName, ulong cb, IntPtr pExInfo);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate bool VfsCallBack_AddDirectory(ulong h, [MarshalAs(UnmanagedType.LPUTF8Str)] string wszName, IntPtr pExInfo);

        public static bool VfsList(string wszPath, ulong h, VfsCallBack_AddFile CallbackFile, VfsCallBack_AddDirectory CallbackDirectory)
        {
            vmmi.VMMDLL_VFS_FILELIST FileList;
            FileList.dwVersion = vmmi.VMMDLL_VFS_FILELIST_VERSION;
            FileList.h = h;
            FileList._Reserved = 0;
            FileList.pfnAddFile = Marshal.GetFunctionPointerForDelegate(CallbackFile);
            FileList.pfnAddDirectory = Marshal.GetFunctionPointerForDelegate(CallbackDirectory);
            return vmmi.VMMDLL_VfsList(wszPath, ref FileList);
        }

        public static unsafe uint VfsRead(string wszFileName, uint cb, ulong cbOffset, out byte[] pbData)
        {
            uint nt, cbRead = 0;
            byte[] data = new byte[cb];
            fixed (byte* pb = data)
            {
                nt = vmmi.VMMDLL_VfsRead(wszFileName, pb, cb, out cbRead, cbOffset);
                pbData = new byte[cbRead];
                if (cbRead > 0)
                {
                    Buffer.BlockCopy(data, 0, pbData, 0, (int)cbRead);
                }
                return nt;
            }
        }

        public static unsafe uint VfsWrite(string wszFileName, byte[] pbData, ulong cbOffset)
        {
            uint cbRead = 0;
            fixed (byte* pb = pbData)
            {
                return vmmi.VMMDLL_VfsWrite(wszFileName, pb, (uint)pbData.Length, out cbRead, cbOffset);
            }
        }

        //---------------------------------------------------------------------
        // PLUGIN FUNCTIONALITY BELOW:
        //---------------------------------------------------------------------

        [DllImport("vmm.dll", EntryPoint = "VMMDLL_InitializePlugins")]
        public static extern bool InitializePlugins();

        //---------------------------------------------------------------------
        // MEMORY READ/WRITE FUNCTIONALITY BELOW:
        //---------------------------------------------------------------------

        public static uint PID_PROCESS_WITH_KERNELMEMORY =  0x80000000;      // Combine with dwPID to enable process kernel memory (NB! use with extreme care).

        public static uint FLAG_NOCACHE =                   0x0001;  // do not use the data cache (force reading from memory acquisition device)
        public static uint FLAG_ZEROPAD_ON_FAIL =           0x0002;  // zero pad failed physical memory reads and report success if read within range of physical memory.
        public static uint FLAG_FORCECACHE_READ =           0x0008;  // force use of cache - fail non-cached pages - only valid for reads, invalid with VMM_FLAG_NOCACHE/VMM_FLAG_ZEROPAD_ON_FAIL.
        public static uint FLAG_NOPAGING =                  0x0010;  // do not try to retrieve memory from paged out memory from pagefile/compressed (even if possible)
        public static uint FLAG_NOPAGING_IO =               0x0020;  // do not try to retrieve memory from paged out memory if read would incur additional I/O (even if possible).
        public static uint FLAG_NOCACHEPUT =                0x0100;  // do not write back to the data cache upon successful read from memory acquisition device.
        public static uint FLAG_CACHE_RECENT_ONLY =         0x0200;  // only fetch from the most recent active cache region when reading.

        public static unsafe MEM_SCATTER[] MemReadScatter(uint pid, uint flags, params ulong[] qwA)
        {
            int i;
            long vappMEMs, vapMEM;
            IntPtr pMEM, pMEM_qwA, pppMEMs;
            if (!lci.LcAllocScatter1((uint)qwA.Length, out pppMEMs))
            {
                return null;
            }
            vappMEMs = pppMEMs.ToInt64();
            for (i = 0; i < qwA.Length; i++)
            {
                vapMEM = Marshal.ReadIntPtr(new IntPtr(vappMEMs + i * 8)).ToInt64();
                pMEM_qwA = new IntPtr(vapMEM + 8);
                Marshal.WriteInt64(pMEM_qwA, (long)(qwA[i] & ~(ulong)0xfff));
            }
            MEM_SCATTER[] MEMs = new MEM_SCATTER[qwA.Length];
            vmmi.VMMDLL_MemReadScatter(pid, pppMEMs, (uint)MEMs.Length, flags);
            for (i = 0; i < MEMs.Length; i++)
            {
                pMEM = Marshal.ReadIntPtr(new IntPtr(vappMEMs + i * 8));
                lci.LC_MEM_SCATTER n = Marshal.PtrToStructure<lci.LC_MEM_SCATTER>(pMEM);
                MEMs[i].f = n.f;
                MEMs[i].qwA = n.qwA;
                MEMs[i].pb = new byte[0x1000];
                Marshal.Copy(n.pb, MEMs[i].pb, 0, 0x1000);
            }
            lci.LcMemFree(pppMEMs);
            return MEMs;
        }

        public static unsafe byte[] MemRead(uint pid, ulong qwA, uint cb, uint flags = 0)
        {
            uint cbRead;
            byte[] data = new byte[cb];
            fixed (byte* pb = data)
            {
                if(!vmmi.VMMDLL_MemReadEx(pid, qwA, pb, cb, out cbRead, flags))
                {
                    return null;
                }
            }
            if (cbRead != cb)
            {
                Array.Resize<byte>(ref data, (int)cbRead);
            }
            return data;
        }

        public static unsafe bool MemPrefetchPages(uint pid, ulong[] qwA)
        {
            byte[] data = new byte[qwA.Length * sizeof(ulong)];
            System.Buffer.BlockCopy(qwA, 0, data, 0, data.Length);
            fixed (byte* pb = data)
            {
                return vmmi.VMMDLL_MemPrefetchPages(pid, pb, (uint)qwA.Length);
            }
        }

        public static unsafe bool MemWrite(uint pid, ulong qwA, byte[] data)
        {
            fixed (byte* pb = data)
            {
                return vmmi.VMMDLL_MemWrite(pid, qwA, pb, (uint)data.Length);
            }
        }

        [DllImport("vmm.dll", EntryPoint = "VMMDLL_MemVirt2Phys")]
        public static extern bool MemVirt2Phys(uint dwPID, ulong qwVA, out ulong pqwPA);



        //---------------------------------------------------------------------
        // PROCESS FUNCTIONALITY BELOW:
        //---------------------------------------------------------------------

        public struct PROCESS_INFORMATION
        {
            public bool fValid;
            public uint tpMemoryModel;
            public uint tpSystem;
            public bool fUserOnly;
            public uint dwPID;
            public uint dwPPID;
            public uint dwState;
            public string szName;
            public string szNameLong;
            public ulong paDTB;
            public ulong paDTB_UserOpt;
            public ulong vaEPROCESS;
            public ulong vaPEB;
            public bool fWow64;
            public uint vaPEB32;
            public uint dwSessionId;
            public ulong qwLUID;
            public string szSID;
        }

        [DllImport("vmm.dll", EntryPoint = "VMMDLL_PidGetFromName")]
        public static extern bool PidGetFromName([MarshalAs(UnmanagedType.LPStr)] string szProcName, out uint pdwPID);

        public static unsafe uint[] PidList()
        {
            bool result;
            ulong c = 0;
            result = vmmi.VMMDLL_PidList(null, ref c);
            if (!result || (c == 0)) { return new uint[0]; }
            fixed (byte* pb = new byte[c * 4])
            {
                result = vmmi.VMMDLL_PidList(pb, ref c);
                if (!result || (c == 0)) { return new uint[0]; }
                uint[] m = new uint[c];
                for (ulong i = 0; i < c; i++)
                {
                    m[i] = (uint)Marshal.ReadInt32((System.IntPtr)(pb + i * 4));
                }
                return m;
            }
        }

        public static unsafe PROCESS_INFORMATION ProcessGetInformation(uint pid)
        {
            bool result;
            ulong cbENTRY = (ulong)System.Runtime.InteropServices.Marshal.SizeOf(typeof(vmmi.VMMDLL_PROCESS_INFORMATION));
            fixed (byte* pb = new byte[cbENTRY])
            {
                Marshal.WriteInt64(new IntPtr(pb + 0), (long)vmmi.VMMDLL_PROCESS_INFORMATION_MAGIC);
                Marshal.WriteInt16(new IntPtr(pb + 8), (short)vmmi.VMMDLL_PROCESS_INFORMATION_VERSION);
                result = vmmi.VMMDLL_ProcessGetInformation(pid, pb, ref cbENTRY);
                if (!result) { return new PROCESS_INFORMATION(); }
                vmmi.VMMDLL_PROCESS_INFORMATION n = Marshal.PtrToStructure<vmmi.VMMDLL_PROCESS_INFORMATION>((System.IntPtr)pb);
                if (n.wVersion != vmmi.VMMDLL_PROCESS_INFORMATION_VERSION) { return new PROCESS_INFORMATION(); }
                PROCESS_INFORMATION e;
                e.fValid = true;
                e.tpMemoryModel = n.tpMemoryModel;
                e.tpSystem = n.tpSystem;
                e.fUserOnly = n.fUserOnly;
                e.dwPID = n.dwPID;
                e.dwPPID = n.dwPPID;
                e.dwState = n.dwState;
                e.szName = n.szName;
                e.szNameLong = n.szNameLong;
                e.paDTB = n.paDTB;
                e.paDTB_UserOpt = n.paDTB_UserOpt;
                e.vaEPROCESS = n.vaEPROCESS;
                e.vaPEB = n.vaPEB;
                e.fWow64 = n.fWow64;
                e.vaPEB32 = n.vaPEB32;
                e.dwSessionId = n.dwSessionId;
                e.qwLUID = n.qwLUID;
                e.szSID = n.szSID;
                return e;
            }
        }

        public static uint VMMDLL_PROCESS_INFORMATION_OPT_STRING_PATH_KERNEL = 1;
        public static uint VMMDLL_PROCESS_INFORMATION_OPT_STRING_PATH_USER_IMAGE = 2;
        public static uint VMMDLL_PROCESS_INFORMATION_OPT_STRING_CMDLINE = 3;

        public static unsafe string ProcessGetInformationString(uint pid, uint fOptionString)
        {
            byte* pb = vmmi.VMMDLL_ProcessGetInformationString(pid, fOptionString);
            if (pb == null) { return ""; }
            string s = Marshal.PtrToStringAnsi((System.IntPtr)pb);
            vmmi.VMMDLL_MemFree(pb);
            return s;
        }

        public struct IMAGE_SECTION_HEADER
        {
            public string Name;
            public uint MiscPhysicalAddressOrVirtualSize;
            public uint VirtualAddress;
            public uint SizeOfRawData;
            public uint PointerToRawData;
            public uint PointerToRelocations;
            public uint PointerToLinenumbers;
            public ushort NumberOfRelocations;
            public ushort NumberOfLinenumbers;
            public uint Characteristics;
        }

        public struct IMAGE_DATA_DIRECTORY
        {
            public string name;
            public uint VirtualAddress;
            public uint Size;
        }

        public static unsafe IMAGE_DATA_DIRECTORY[] ProcessGetDirectories(uint pid, string wszModule)
        {
            string[] PE_DATA_DIRECTORIES = new string[16] { "EXPORT", "IMPORT", "RESOURCE", "EXCEPTION", "SECURITY", "BASERELOC", "DEBUG", "ARCHITECTURE", "GLOBALPTR", "TLS", "LOAD_CONFIG", "BOUND_IMPORT", "IAT", "DELAY_IMPORT", "COM_DESCRIPTOR", "RESERVED" };
            bool result;
            uint cData;
            uint cbENTRY = (uint)System.Runtime.InteropServices.Marshal.SizeOf(typeof(vmmi.VMMDLL_IMAGE_DATA_DIRECTORY));
            fixed (byte* pb = new byte[16 * cbENTRY])
            {
                result = vmmi.VMMDLL_ProcessGetDirectories(pid, wszModule, pb, 16, out cData);
                if (!result || (cData != 16)) { return new IMAGE_DATA_DIRECTORY[0]; }
                IMAGE_DATA_DIRECTORY[] m = new IMAGE_DATA_DIRECTORY[16];
                for (int i = 0; i < 16; i++)
                {
                    vmmi.VMMDLL_IMAGE_DATA_DIRECTORY n = Marshal.PtrToStructure<vmmi.VMMDLL_IMAGE_DATA_DIRECTORY>((System.IntPtr)(pb + i * cbENTRY));
                    IMAGE_DATA_DIRECTORY e;
                    e.name = PE_DATA_DIRECTORIES[i];
                    e.VirtualAddress = n.VirtualAddress;
                    e.Size = n.Size;
                    m[i] = e;
                }
                return m;
            }
        }

        public static unsafe IMAGE_SECTION_HEADER[] ProcessGetSections(uint pid, string wszModule)
        {
            bool result;
            uint cData;
            uint cbENTRY = (uint)System.Runtime.InteropServices.Marshal.SizeOf(typeof(vmmi.VMMDLL_IMAGE_SECTION_HEADER));
            result = vmmi.VMMDLL_ProcessGetSections(pid, wszModule, null, 0, out cData);
            if(!result || (cData == 0)) { return new IMAGE_SECTION_HEADER[0]; }
            fixed (byte* pb = new byte[cData * cbENTRY])
            {
                result = vmmi.VMMDLL_ProcessGetSections(pid, wszModule, pb, cData, out cData);
                if (!result || (cData == 0)) { return new IMAGE_SECTION_HEADER[0]; }
                IMAGE_SECTION_HEADER[] m = new IMAGE_SECTION_HEADER[cData];
                for (int i = 0; i < cData; i++)
                {
                    vmmi.VMMDLL_IMAGE_SECTION_HEADER n = Marshal.PtrToStructure<vmmi.VMMDLL_IMAGE_SECTION_HEADER>((System.IntPtr)(pb + i * cbENTRY));
                    IMAGE_SECTION_HEADER e;
                    e.Name = n.Name;
                    e.MiscPhysicalAddressOrVirtualSize = n.MiscPhysicalAddressOrVirtualSize;
                    e.VirtualAddress = n.VirtualAddress;
                    e.SizeOfRawData = n.SizeOfRawData;
                    e.PointerToRawData = n.PointerToRawData;
                    e.PointerToRelocations = n.PointerToRelocations;
                    e.PointerToLinenumbers = n.PointerToLinenumbers;
                    e.NumberOfRelocations = n.NumberOfRelocations;
                    e.NumberOfLinenumbers = n.NumberOfLinenumbers;
                    e.Characteristics = n.Characteristics;
                    m[i] = e;
                }
                return m;
            }
        }

        [DllImport("vmm.dll", EntryPoint = "VMMDLL_ProcessGetProcAddressW")]
        public static extern ulong ProcessGetProcAddress(uint pid, [MarshalAs(UnmanagedType.LPWStr)] string wszModuleName, [MarshalAs(UnmanagedType.LPStr)] string szFunctionName);

        [DllImport("vmm.dll", EntryPoint = "VMMDLL_ProcessGetModuleBaseW")]
        public static extern ulong ProcessGetModuleBase(uint pid, [MarshalAs(UnmanagedType.LPWStr)] string wszModuleName);



        //---------------------------------------------------------------------
        // WINDOWS SPECIFIC DEBUGGING / SYMBOL FUNCTIONALITY BELOW:
        //---------------------------------------------------------------------

        public static unsafe bool PdbLoad(uint pid, ulong vaModuleBase, out string szModuleName)
        {
            szModuleName = "";
            byte[] data = new byte[260];
            fixed (byte* pb = data)
            {
                bool result = vmmi.VMMDLL_PdbLoad(pid, vaModuleBase, pb);
                if(!result) { return false; }
                szModuleName = Encoding.UTF8.GetString(data);
                szModuleName = szModuleName.Substring(0, szModuleName.IndexOf((char)0));
            }
            return true;
        }

        public static unsafe bool PdbSymbolName(string szModule, ulong cbSymbolAddressOrOffset, out string szSymbolName, out uint pdwSymbolDisplacement)
        {
            szSymbolName = "";
            pdwSymbolDisplacement = 0;
            byte[] data = new byte[260];
            fixed (byte* pb = data)
            {
                bool result = vmmi.VMMDLL_PdbSymbolName(szModule, cbSymbolAddressOrOffset, pb, out pdwSymbolDisplacement);
                if (!result) { return false; }
                szSymbolName = Encoding.UTF8.GetString(data);
                szSymbolName = szSymbolName.Substring(0, szSymbolName.IndexOf((char)0));
            }
            return true;
        }

        [DllImport("vmm.dll", EntryPoint = "VMMDLL_PdbSymbolAddress")]
        public static extern bool PdbSymbolAddress([MarshalAs(UnmanagedType.LPStr)] string szModule, [MarshalAs(UnmanagedType.LPStr)] string szSymbolName, out ulong pvaSymbolAddress);

        [DllImport("vmm.dll", EntryPoint = "VMMDLL_PdbTypeSize")]
        public static extern bool PdbTypeSize([MarshalAs(UnmanagedType.LPStr)] string szModule, [MarshalAs(UnmanagedType.LPStr)] string szTypeName, out uint pcbTypeSize);

        [DllImport("vmm.dll", EntryPoint = "VMMDLL_PdbTypeChildOffset")]
        public static extern bool PdbTypeChildOffset([MarshalAs(UnmanagedType.LPStr)] string szModule, [MarshalAs(UnmanagedType.LPStr)] string szTypeName, [MarshalAs(UnmanagedType.LPStr)] string wszTypeChildName, out uint pcbTypeChildOffset);





        //---------------------------------------------------------------------
        // "MAP" FUNCTIONALITY BELOW:
        //---------------------------------------------------------------------

        public static ulong MEMMAP_FLAG_PAGE_W =    0x0000000000000002;
        public static ulong MEMMAP_FLAG_PAGE_NS =   0x0000000000000004;
        public static ulong MEMMAP_FLAG_PAGE_NX =   0x8000000000000000;
        public static ulong MEMMAP_FLAG_PAGE_MASK = 0x8000000000000006;

        public struct MAP_PTEENTRY
        {
            public ulong vaBase;
            public ulong vaEnd;
            public ulong cbSize;
            public ulong cPages;
            public ulong fPage;
            public bool fWoW64;
            public string wszText;
            public uint cSoftware;
        }

        public struct MAP_VADENTRY
        {
            public ulong vaStart;
            public ulong vaEnd;
            public ulong vaVad;
            public ulong cbSize;
            public uint VadType;
            public uint Protection;
            public bool fImage;
            public bool fFile;
            public bool fPageFile;
            public bool fPrivateMemory;
            public bool fTeb;
            public bool fStack;
            public uint fSpare;
            public uint HeapNum;
            public bool fHeap;
            public uint cwszDescription;
            public uint CommitCharge;
            public bool MemCommit;
            public uint u2;
            public uint cbPrototypePte;
            public ulong vaPrototypePte;
            public ulong vaSubsection;
            public string wszText;
            public ulong vaFileObject;
            public uint cVadExPages;
            public uint cVadExPagesBase;
        }

        public struct MAP_VADEXENTRY_PROTOTYPE
        {
            public uint tp;
            public ulong pa;
            public ulong pte;
        }

        public struct MAP_VADEXENTRY
        {
            public uint tp;
            public uint iPML;
            public ulong va;
            public ulong pa;
            public ulong pte;
            public MAP_VADEXENTRY_PROTOTYPE proto;
            public ulong vaVadBase;
        }

        public static uint MAP_MODULEENTRY_TP_NORMAL    = 0;
        public static uint VMMDLL_MODULE_TP_DATA        = 1;
        public static uint VMMDLL_MODULE_TP_NOTLINKED   = 2;
        public static uint VMMDLL_MODULE_TP_INJECTED    = 3;

        public struct MAP_MODULEENTRY
        {
            public bool fValid;
            public ulong vaBase;
            public ulong vaEntry;
            public uint cbImageSize;
            public bool fWow64;
            public string wszText;
            public string wszFullName;
            public uint tp;
            public uint cbFileSizeRaw;
            public uint cSection;
            public uint cEAT;
            public uint cIAT;
        }

        public struct MAP_UNLOADEDMODULEENTRY
        {
            public ulong vaBase;
            public uint cbImageSize;
            public bool fWow64;
            public string wszText;
            public uint dwCheckSum;         // user-mode only
            public uint dwTimeDateStamp;    // user-mode only
            public ulong ftUnload;          // kernel-mode only
        }

        public struct MAP_EATINFO
        {
            public bool fValid; 
            public ulong vaModuleBase;
            public ulong vaAddressOfFunctions;
            public ulong vaAddressOfNames;
            public uint cNumberOfFunctions;
            public uint cNumberOfNames;
            public uint dwOrdinalBase;
        }

        public struct MAP_EATENTRY
        {
            public ulong vaFunction;
            public uint dwOrdinal;
            public uint oFunctionsArray;
            public uint oNamesArray;
            public string wszFunction;
        }

        public struct MAP_IATENTRY
        {
            public ulong vaFunction;
            public ulong vaModule;
            public string wszFunction;
            public string wszModule;
            public bool f32;
            public ushort wHint;
            public uint rvaFirstThunk;
            public uint rvaOriginalFirstThunk;
            public uint rvaNameModule;
            public uint rvaNameFunction;
        }

        public struct MAP_HEAPENTRY
        {
            public ulong vaHeapSegment;
            public uint cPages;
            public uint cPagesUnCommitted;
            public uint HeapId;
            public bool fPrimary;
        }

        public struct MAP_THREADENTRY
        {
            public uint dwTID;
            public uint dwPID;
            public uint dwExitStatus;
            public byte bState;
            public byte bRunning;
            public byte bPriority;
            public byte bBasePriority;
            public ulong vaETHREAD;
            public ulong vaTeb;
            public ulong ftCreateTime;
            public ulong ftExitTime;
            public ulong vaStartAddress;
            public ulong vaStackBaseUser;
            public ulong vaStackLimitUser;
            public ulong vaStackBaseKernel;
            public ulong vaStackLimitKernel;
            public ulong vaTrapFrame;
            public ulong vaRIP;
            public ulong vaRSP;
            public ulong qwAffinity;
            public uint dwUserTime;
            public uint dwKernelTime;
            public byte bSuspendCount;
        }

        public struct MAP_HANDLEENTRY
        {
            public ulong vaObject;
            public uint dwHandle;
            public uint dwGrantedAccess;
            public uint iType;
            public ulong qwHandleCount;
            public ulong qwPointerCount;
            public ulong vaObjectCreateInfo;
            public ulong vaSecurityDescriptor;
            public string wszText;
            public uint dwPID;
            public uint dwPoolTag;
            public string wszType;
        }

        public struct MAP_NETENTRY_ADDR
        {
            public bool fValid;
            public ushort port;
            public byte[] pbAddr;
            public string wszText;
        }

        public struct MAP_NETENTRY
        {
            public uint dwPID;
            public uint dwState;
            public uint dwPoolTag;
            public ushort AF;
            public MAP_NETENTRY_ADDR src;
            public MAP_NETENTRY_ADDR dst;
            public ulong vaObj;
            public ulong ftTime;
            public string wszText;
        }

        public struct MAP_PHYSMEMENTRY
        {
            public ulong pa;
            public ulong cb;
        }
        
        public struct MAP_USERENTRY
        {
            public string szSID;
            public string wszText;
            public ulong vaRegHive;
        }

        public struct MAP_SERVICEENTRY
        {
            public ulong vaObj;
            public uint dwPID;
            public uint dwOrdinal;
            public string wszServiceName;
            public string wszDisplayName;
            public string wszPath;
            public string wszUserTp;
            public string wszUserAcct;
            public string wszImagePath;
            public uint dwStartType;
            public uint dwServiceType;
            public uint dwCurrentState;
            public uint dwControlsAccepted;
            public uint dwWin32ExitCode;
            public uint dwServiceSpecificExitCode;
            public uint dwCheckPoint;
            public uint dwWaitHint;
        }

        public enum MAP_PFN_TYPE
        {
            Zero = 0,
            Free = 1,
            Standby = 2,
            Modified = 3,
            ModifiedNoWrite = 4,
            Bad = 5,
            Active = 6,
            Transition = 7
        }

        public enum MAP_PFN_TYPEEXTENDED
        {
            Unknown = 0,
            Unused = 1,
            ProcessPrivate = 2,
            PageTable = 3,
            LargePage = 4,
            DriverLocked = 5,
            Shareable = 6,
            File = 7,
        }

        public struct MAP_PFNENTRY
        {
            public uint dwPfn;
            public MAP_PFN_TYPE tp;
            public MAP_PFN_TYPEEXTENDED tpExtended;
            public ulong va;
            public ulong vaPte;
            public ulong OriginalPte;
            public uint dwPID;
            public bool fPrototype;
            public bool fModified;
            public bool fReadInProgress;
            public bool fWriteInProgress;
            public byte priority;
        }

        public static unsafe MAP_PTEENTRY[] Map_GetPte(uint pid, bool fIdentifyModules = true)
        {
            bool result;
            uint cb = 0;
            int cbMAP = System.Runtime.InteropServices.Marshal.SizeOf(typeof(vmmi.VMMDLL_MAP_PTE));
            int cbENTRY = System.Runtime.InteropServices.Marshal.SizeOf(typeof(vmmi.VMMDLL_MAP_PTEENTRY));
            result = vmmi.VMMDLL_Map_GetPte(pid, null, ref cb, fIdentifyModules);
            if (!result || (cb == 0)) { return new MAP_PTEENTRY[0]; }
            fixed (byte* pb = new byte[cb])
            {
                result = vmmi.VMMDLL_Map_GetPte(pid, pb, ref cb, fIdentifyModules);
                if (!result) { return new MAP_PTEENTRY[0]; }
                vmmi.VMMDLL_MAP_PTE pm = Marshal.PtrToStructure<vmmi.VMMDLL_MAP_PTE>((System.IntPtr)pb);
                if (pm.dwVersion != vmmi.VMMDLL_MAP_PTE_VERSION) { return new MAP_PTEENTRY[0]; }
                MAP_PTEENTRY[] m = new MAP_PTEENTRY[pm.cMap];
                for (int i = 0; i < pm.cMap; i++)
                {
                    vmmi.VMMDLL_MAP_PTEENTRY n = Marshal.PtrToStructure<vmmi.VMMDLL_MAP_PTEENTRY>((System.IntPtr)(pb + cbMAP + i * cbENTRY));
                    MAP_PTEENTRY e;
                    e.vaBase = n.vaBase;
                    e.vaEnd = n.vaBase + (n.cPages << 12) - 1;
                    e.cbSize = n.cPages << 12;
                    e.cPages = n.cPages;
                    e.fPage = n.fPage;
                    e.fWoW64 = n.fWoW64;
                    e.wszText = n.wszText;
                    e.cSoftware = n.cSoftware;
                    m[i] = e;
                }
                return m;
            }
        }

        public static unsafe MAP_VADENTRY[] Map_GetVad(uint pid, bool fIdentifyModules = true)
        {
            bool result;
            uint cb = 0;
            int cbMAP = System.Runtime.InteropServices.Marshal.SizeOf(typeof(vmmi.VMMDLL_MAP_VAD));
            int cbENTRY = System.Runtime.InteropServices.Marshal.SizeOf(typeof(vmmi.VMMDLL_MAP_VADENTRY));
            result = vmmi.VMMDLL_Map_GetVad(pid, null, ref cb, fIdentifyModules);
            if (!result || (cb == 0)) { return new MAP_VADENTRY[0]; }
            fixed (byte* pb = new byte[cb])
            {
                result = vmmi.VMMDLL_Map_GetVad(pid, pb, ref cb, fIdentifyModules);
                if (!result) { return new MAP_VADENTRY[0]; }
                vmmi.VMMDLL_MAP_VAD pm = Marshal.PtrToStructure<vmmi.VMMDLL_MAP_VAD>((System.IntPtr)pb);
                if (pm.dwVersion != vmmi.VMMDLL_MAP_VAD_VERSION) { return new MAP_VADENTRY[0]; }
                MAP_VADENTRY[] m = new MAP_VADENTRY[pm.cMap];
                for (int i = 0; i < pm.cMap; i++)
                {
                    vmmi.VMMDLL_MAP_VADENTRY n = Marshal.PtrToStructure<vmmi.VMMDLL_MAP_VADENTRY>((System.IntPtr)(pb + cbMAP + i * cbENTRY));
                    MAP_VADENTRY e;
                    e.vaStart = n.vaStart;
                    e.vaEnd = n.vaEnd;
                    e.cbSize = n.vaEnd + 1 - n.vaStart;
                    e.vaVad = n.vaVad;
                    e.VadType = n.dw0 & 0x07;
                    e.Protection = (n.dw0 >> 3) & 0x1f;
                    e.fImage = ((n.dw0 >> 8) & 1) == 1;
                    e.fFile = ((n.dw0 >> 9) & 1) == 1;
                    e.fPageFile = ((n.dw0 >> 10) & 1) == 1;
                    e.fPrivateMemory = ((n.dw0 >> 11) & 1) == 1;
                    e.fTeb = ((n.dw0 >> 12) & 1) == 1;
                    e.fStack = ((n.dw0 >> 13) & 1) == 1;
                    e.fSpare = (n.dw0 >> 14) & 0x03;
                    e.HeapNum = (n.dw0 >> 16) & 0x1f;
                    e.fHeap = ((n.dw0 >> 23) & 1) == 1;
                    e.cwszDescription = (n.dw0 >> 24) & 0xff;
                    e.CommitCharge = n.dw1 & 0x7fffffff;
                    e.MemCommit = ((n.dw1 >> 31) & 1) == 1;
                    e.u2 = n.u2;
                    e.cbPrototypePte = n.cbPrototypePte;
                    e.vaPrototypePte = n.vaPrototypePte;
                    e.vaSubsection = n.vaSubsection;
                    e.wszText = n.wszText;
                    e.vaFileObject = n.vaFileObject;
                    e.cVadExPages = n.cVadExPages;
                    e.cVadExPagesBase = n.cVadExPagesBase;
                    m[i] = e;
                }
                return m;
            }
        }

        public static unsafe MAP_VADEXENTRY[] Map_GetVadEx(uint pid, uint oPages, uint cPages)
        {
            bool result;
            uint cb = 0;
            int cbMAP = System.Runtime.InteropServices.Marshal.SizeOf(typeof(vmmi.VMMDLL_MAP_VADEX));
            int cbENTRY = System.Runtime.InteropServices.Marshal.SizeOf(typeof(vmmi.VMMDLL_MAP_VADEXENTRY));
            result = vmmi.VMMDLL_Map_GetVadEx(pid, null, ref cb, oPages, cPages);
            if (!result || (cb == 0)) { return new MAP_VADEXENTRY[0]; }
            fixed (byte* pb = new byte[cb])
            {
                result = vmmi.VMMDLL_Map_GetVadEx(pid, pb, ref cb, oPages, cPages);
                if (!result) { return new MAP_VADEXENTRY[0]; }
                vmmi.VMMDLL_MAP_VADEX pm = Marshal.PtrToStructure<vmmi.VMMDLL_MAP_VADEX>((System.IntPtr)pb);
                if (pm.dwVersion != vmmi.VMMDLL_MAP_VADEX_VERSION) { return new MAP_VADEXENTRY[0]; }
                MAP_VADEXENTRY[] m = new MAP_VADEXENTRY[pm.cMap];
                for (int i = 0; i < pm.cMap; i++)
                {
                    vmmi.VMMDLL_MAP_VADEXENTRY n = Marshal.PtrToStructure<vmmi.VMMDLL_MAP_VADEXENTRY>((System.IntPtr)(pb + cbMAP + i * cbENTRY));
                    MAP_VADEXENTRY e;
                    e.tp = n.tp;
                    e.iPML = n.iPML;
                    e.va = n.va;
                    e.pa = n.pa;
                    e.pte = n.pte;
                    e.proto.tp = n.proto_tp;
                    e.proto.pa = n.proto_pa;
                    e.proto.pte = n.proto_pte;
                    e.vaVadBase = n.vaVadBase;
                    m[i] = e;
                }
                return m;
            }
        }

        public static unsafe MAP_MODULEENTRY[] Map_GetModule(uint pid)
        {
            bool result;
            uint cb = 0;
            int cbMAP = System.Runtime.InteropServices.Marshal.SizeOf(typeof(vmmi.VMMDLL_MAP_MODULE));
            int cbENTRY = System.Runtime.InteropServices.Marshal.SizeOf(typeof(vmmi.VMMDLL_MAP_MODULEENTRY));
            result = vmmi.VMMDLL_Map_GetModule(pid, null, ref cb);
            if(!result || (cb == 0)) { return new MAP_MODULEENTRY[0]; }
            fixed(byte* pb = new byte[cb])
            {
                result = vmmi.VMMDLL_Map_GetModule(pid, pb, ref cb);
                if(!result) { return new MAP_MODULEENTRY[0]; }
                vmmi.VMMDLL_MAP_MODULE pm = Marshal.PtrToStructure<vmmi.VMMDLL_MAP_MODULE>((System.IntPtr)pb);
                if(pm.dwVersion != vmmi.VMMDLL_MAP_MODULE_VERSION) { return new MAP_MODULEENTRY[0]; }
                MAP_MODULEENTRY[] m = new MAP_MODULEENTRY[pm.cMap];
                for (int i = 0; i < pm.cMap; i++)
                {
                    vmmi.VMMDLL_MAP_MODULEENTRY n = Marshal.PtrToStructure<vmmi.VMMDLL_MAP_MODULEENTRY>((System.IntPtr)(pb + cbMAP + i * cbENTRY));
                    MAP_MODULEENTRY e;
                    e.fValid = true;
                    e.vaBase = n.vaBase;
                    e.vaEntry = n.vaEntry;
                    e.cbImageSize = n.cbImageSize;
                    e.fWow64 = n.fWow64;
                    e.wszText = n.wszText;
                    e.wszFullName = n.wszFullName;
                    e.tp = n.tp;
                    e.cbFileSizeRaw = n.cbFileSizeRaw;
                    e.cSection = n.cSection;
                    e.cEAT = n.cEAT;
                    e.cIAT = n.cIAT;
                    m[i] = e;
                }
                return m;
            }
        }

        public static unsafe MAP_MODULEENTRY Map_GetModuleFromName(uint pid, string wszModuleName)
        {
            bool result;
            uint cbENTRY = 0;
            result = vmmi.VMMDLL_Map_GetModuleFromName(pid, wszModuleName, null, ref cbENTRY);
            if (!result || (cbENTRY == 0)) { return new MAP_MODULEENTRY(); }
            fixed (byte* pb = new byte[cbENTRY])
            {
                result = vmmi.VMMDLL_Map_GetModuleFromName(pid, wszModuleName, pb, ref cbENTRY);
                if (!result) { return new MAP_MODULEENTRY(); }
                vmmi.VMMDLL_MAP_MODULEENTRY n = Marshal.PtrToStructure<vmmi.VMMDLL_MAP_MODULEENTRY>((System.IntPtr)pb);
                MAP_MODULEENTRY e;
                e.fValid = true;
                e.vaBase = n.vaBase;
                e.vaEntry = n.vaEntry;
                e.cbImageSize = n.cbImageSize;
                e.fWow64 = n.fWow64;
                e.wszText = wszModuleName;
                e.wszFullName = n.wszFullName;
                e.tp = n.tp;
                e.cbFileSizeRaw = n.cbFileSizeRaw;
                e.cSection = n.cSection;
                e.cEAT = n.cEAT;
                e.cIAT = n.cIAT;
                return e;
            }
        }

        public static unsafe MAP_UNLOADEDMODULEENTRY[] Map_GetUnloadedModule(uint pid)
        {
            bool result;
            uint cb = 0;
            int cbMAP = System.Runtime.InteropServices.Marshal.SizeOf(typeof(vmmi.VMMDLL_MAP_UNLOADEDMODULE));
            int cbENTRY = System.Runtime.InteropServices.Marshal.SizeOf(typeof(vmmi.VMMDLL_MAP_UNLOADEDMODULEENTRY));
            result = vmmi.VMMDLL_Map_GetUnloadedModule(pid, null, ref cb);
            if (!result || (cb == 0)) { return new MAP_UNLOADEDMODULEENTRY[0]; }
            fixed (byte* pb = new byte[cb])
            {
                result = vmmi.VMMDLL_Map_GetUnloadedModule(pid, pb, ref cb);
                if (!result) { return new MAP_UNLOADEDMODULEENTRY[0]; }
                vmmi.VMMDLL_MAP_UNLOADEDMODULE pm = Marshal.PtrToStructure<vmmi.VMMDLL_MAP_UNLOADEDMODULE>((System.IntPtr)pb);
                if (pm.dwVersion != vmmi.VMMDLL_MAP_UNLOADEDMODULE_VERSION) { return new MAP_UNLOADEDMODULEENTRY[0]; }
                MAP_UNLOADEDMODULEENTRY[] m = new MAP_UNLOADEDMODULEENTRY[pm.cMap];
                for (int i = 0; i < pm.cMap; i++)
                {
                    vmmi.VMMDLL_MAP_UNLOADEDMODULEENTRY n = Marshal.PtrToStructure<vmmi.VMMDLL_MAP_UNLOADEDMODULEENTRY>((System.IntPtr)(pb + cbMAP + i * cbENTRY));
                    MAP_UNLOADEDMODULEENTRY e;
                    e.vaBase = n.vaBase;
                    e.cbImageSize = n.cbImageSize;
                    e.fWow64 = n.fWow64;
                    e.wszText = n.wszText;
                    e.dwCheckSum = n.dwCheckSum;
                    e.dwTimeDateStamp = n.dwTimeDateStamp;
                    e.ftUnload = n.ftUnload;
                    m[i] = e;
                }
                return m;
            }
        }

        public static unsafe MAP_EATENTRY[] Map_GetEAT(uint pid, string wszModule, out MAP_EATINFO EatInfo)
        {
            bool result;
            uint cb = 0;
            int cbMAP = System.Runtime.InteropServices.Marshal.SizeOf(typeof(vmmi.VMMDLL_MAP_EAT));
            int cbENTRY = System.Runtime.InteropServices.Marshal.SizeOf(typeof(vmmi.VMMDLL_MAP_EATENTRY));
            EatInfo = new MAP_EATINFO();
            result = vmmi.VMMDLL_Map_GetEAT(pid, wszModule, null, ref cb);
            if (!result || (cb == 0)) { return new MAP_EATENTRY[0]; }
            fixed (byte* pb = new byte[cb])
            {
                result = vmmi.VMMDLL_Map_GetEAT(pid, wszModule, pb, ref cb);
                if (!result) { return new MAP_EATENTRY[0]; }
                vmmi.VMMDLL_MAP_EAT pm = Marshal.PtrToStructure<vmmi.VMMDLL_MAP_EAT>((System.IntPtr)pb);
                if (pm.dwVersion != vmmi.VMMDLL_MAP_EAT_VERSION) { return new MAP_EATENTRY[0]; }
                MAP_EATENTRY[] m = new MAP_EATENTRY[pm.cMap];
                for (int i = 0; i < pm.cMap; i++)
                {
                    vmmi.VMMDLL_MAP_EATENTRY n = Marshal.PtrToStructure<vmmi.VMMDLL_MAP_EATENTRY>((System.IntPtr)(pb + cbMAP + i * cbENTRY));
                    MAP_EATENTRY e;
                    e.vaFunction = n.vaFunction;
                    e.dwOrdinal = n.dwOrdinal;
                    e.oFunctionsArray = n.oFunctionsArray;
                    e.oNamesArray = n.oNamesArray;
                    e.wszFunction = n.wszFunction;
                    m[i] = e;
                }
                EatInfo.fValid = true;
                EatInfo.vaModuleBase = pm.vaModuleBase;
                EatInfo.vaAddressOfFunctions = pm.vaAddressOfFunctions;
                EatInfo.vaAddressOfNames = pm.vaAddressOfNames;
                EatInfo.cNumberOfFunctions = pm.cNumberOfFunctions;
                EatInfo.cNumberOfNames = pm.cNumberOfNames;
                EatInfo.dwOrdinalBase = pm.dwOrdinalBase;
                return m;
            }
        }

        public static unsafe MAP_IATENTRY[] Map_GetIAT(uint pid, string wszModule)
        {
            bool result;
            uint cb = 0;
            int cbMAP = System.Runtime.InteropServices.Marshal.SizeOf(typeof(vmmi.VMMDLL_MAP_IAT));
            int cbENTRY = System.Runtime.InteropServices.Marshal.SizeOf(typeof(vmmi.VMMDLL_MAP_IATENTRY));
            result = vmmi.VMMDLL_Map_GetIAT(pid, wszModule, null, ref cb);
            if (!result || (cb == 0)) { return new MAP_IATENTRY[0]; }
            fixed (byte* pb = new byte[cb])
            {
                result = vmmi.VMMDLL_Map_GetIAT(pid, wszModule, pb, ref cb);
                if (!result) { return new MAP_IATENTRY[0]; }
                vmmi.VMMDLL_MAP_IAT pm = Marshal.PtrToStructure<vmmi.VMMDLL_MAP_IAT>((System.IntPtr)pb);
                if (pm.dwVersion != vmmi.VMMDLL_MAP_IAT_VERSION) { return new MAP_IATENTRY[0]; }
                MAP_IATENTRY[] m = new MAP_IATENTRY[pm.cMap];
                for (int i = 0; i < pm.cMap; i++)
                {
                    vmmi.VMMDLL_MAP_IATENTRY n = Marshal.PtrToStructure<vmmi.VMMDLL_MAP_IATENTRY>((System.IntPtr)(pb + cbMAP + i * cbENTRY));
                    MAP_IATENTRY e;
                    e.vaFunction = n.vaFunction;
                    e.wszFunction = n.wszFunction;
                    e.wszModule = n.wszModule;
                    e.f32 = n.f32;
                    e.wHint = n.wHint;
                    e.rvaFirstThunk = n.rvaFirstThunk;
                    e.rvaOriginalFirstThunk = n.rvaOriginalFirstThunk;
                    e.rvaNameModule = n.rvaNameModule;
                    e.rvaNameFunction = n.rvaNameFunction;
                    e.vaModule = pm.vaModuleBase;
                    m[i] = e;
                }
                return m;
            }
        }

        public static unsafe MAP_HEAPENTRY[] Map_GetHeap(uint pid)
        {
            bool result;
            uint cb = 0;
            int cbMAP = System.Runtime.InteropServices.Marshal.SizeOf(typeof(vmmi.VMMDLL_MAP_HEAP));
            int cbENTRY = System.Runtime.InteropServices.Marshal.SizeOf(typeof(vmmi.VMMDLL_MAP_HEAPENTRY));
            result = vmmi.VMMDLL_Map_GetHeap(pid, null, ref cb);
            if (!result || (cb == 0)) { return new MAP_HEAPENTRY[0]; }
            fixed (byte* pb = new byte[cb])
            {
                result = vmmi.VMMDLL_Map_GetHeap(pid, pb, ref cb);
                if (!result) { return new MAP_HEAPENTRY[0]; }
                vmmi.VMMDLL_MAP_HEAP pm = Marshal.PtrToStructure<vmmi.VMMDLL_MAP_HEAP>((System.IntPtr)pb);
                if (pm.dwVersion != vmmi.VMMDLL_MAP_HEAP_VERSION) { return new MAP_HEAPENTRY[0]; }
                MAP_HEAPENTRY[] m = new MAP_HEAPENTRY[pm.cMap];
                for (int i = 0; i < pm.cMap; i++)
                {
                    vmmi.VMMDLL_MAP_HEAPENTRY n = Marshal.PtrToStructure<vmmi.VMMDLL_MAP_HEAPENTRY>((System.IntPtr)(pb + cbMAP + i * cbENTRY));
                    MAP_HEAPENTRY e;
                    e.vaHeapSegment = n.vaHeapSegment;
                    e.cPages = n.cPages;
                    e.cPagesUnCommitted = n.cPagesUnCommitted_HeapId_fPrimary & 0x00ffffff;
                    e.HeapId = (n.cPagesUnCommitted_HeapId_fPrimary >> 24) & 0x7f;
                    e.fPrimary = (n.cPagesUnCommitted_HeapId_fPrimary >> 31) == 1;
                    m[i] = e;
                }
                return m;
            }
        }

        public static unsafe MAP_THREADENTRY[] Map_GetThread(uint pid)
        {
            bool result;
            uint cb = 0;
            int cbMAP = System.Runtime.InteropServices.Marshal.SizeOf(typeof(vmmi.VMMDLL_MAP_THREAD));
            int cbENTRY = System.Runtime.InteropServices.Marshal.SizeOf(typeof(vmmi.VMMDLL_MAP_THREADENTRY));
            result = vmmi.VMMDLL_Map_GetThread(pid, null, ref cb);
            if (!result || (cb == 0)) { return new MAP_THREADENTRY[0]; }
            fixed (byte* pb = new byte[cb])
            {
                result = vmmi.VMMDLL_Map_GetThread(pid, pb, ref cb);
                if (!result) { return new MAP_THREADENTRY[0]; }
                vmmi.VMMDLL_MAP_THREAD pm = Marshal.PtrToStructure<vmmi.VMMDLL_MAP_THREAD>((System.IntPtr)pb);
                if (pm.dwVersion != vmmi.VMMDLL_MAP_THREAD_VERSION) { return new MAP_THREADENTRY[0]; }
                MAP_THREADENTRY[] m = new MAP_THREADENTRY[pm.cMap];
                for (int i = 0; i < pm.cMap; i++)
                {
                    vmmi.VMMDLL_MAP_THREADENTRY n = Marshal.PtrToStructure<vmmi.VMMDLL_MAP_THREADENTRY>((System.IntPtr)(pb + cbMAP + i * cbENTRY));
                    MAP_THREADENTRY e;
                    e.dwTID = n.dwTID;
                    e.dwPID = n.dwPID;
                    e.dwExitStatus = n.dwExitStatus;
                    e.bState = n.bState;
                    e.bRunning = n.bRunning;
                    e.bPriority = n.bPriority;
                    e.bBasePriority = n.bBasePriority;
                    e.vaETHREAD = n.vaETHREAD;
                    e.vaTeb = n.vaTeb;
                    e.ftCreateTime = n.ftCreateTime;
                    e.ftExitTime = n.ftExitTime;
                    e.vaStartAddress = n.vaStartAddress;
                    e.vaStackBaseUser = n.vaStackBaseUser;
                    e.vaStackLimitUser = n.vaStackLimitUser;
                    e.vaStackBaseKernel = n.vaStackBaseKernel;
                    e.vaStackLimitKernel = n.vaStackLimitKernel;
                    e.vaTrapFrame = n.vaTrapFrame;
                    e.vaRIP = n.vaRIP;
                    e.vaRSP = n.vaRSP;
                    e.qwAffinity = n.qwAffinity;
                    e.dwUserTime = n.dwUserTime;
                    e.dwKernelTime = n.dwKernelTime;
                    e.bSuspendCount = n.bSuspendCount;
                    m[i] = e;
                }
                return m;
            }
        }

        public static unsafe MAP_HANDLEENTRY[] Map_GetHandle(uint pid)
        {
            bool result;
            uint cb = 0;
            int cbMAP = System.Runtime.InteropServices.Marshal.SizeOf(typeof(vmmi.VMMDLL_MAP_HANDLE));
            int cbENTRY = System.Runtime.InteropServices.Marshal.SizeOf(typeof(vmmi.VMMDLL_MAP_HANDLEENTRY));
            result = vmmi.VMMDLL_Map_GetHandle(pid, null, ref cb);
            if (!result || (cb == 0)) { return new MAP_HANDLEENTRY[0]; }
            fixed (byte* pb = new byte[cb])
            {
                result = vmmi.VMMDLL_Map_GetHandle(pid, pb, ref cb);
                if (!result) { return new MAP_HANDLEENTRY[0]; }
                vmmi.VMMDLL_MAP_HANDLE pm = Marshal.PtrToStructure<vmmi.VMMDLL_MAP_HANDLE>((System.IntPtr)pb);
                if (pm.dwVersion != vmmi.VMMDLL_MAP_HANDLE_VERSION) { return new MAP_HANDLEENTRY[0]; }
                MAP_HANDLEENTRY[] m = new MAP_HANDLEENTRY[pm.cMap];
                for (int i = 0; i < pm.cMap; i++)
                {
                    vmmi.VMMDLL_MAP_HANDLEENTRY n = Marshal.PtrToStructure<vmmi.VMMDLL_MAP_HANDLEENTRY>((System.IntPtr)(pb + cbMAP + i * cbENTRY));
                    MAP_HANDLEENTRY e;
                    e.vaObject = n.vaObject;
                    e.dwHandle = n.dwHandle;
                    e.dwGrantedAccess = n.dwGrantedAccess_iType & 0x00ffffff;
                    e.iType = n.dwGrantedAccess_iType >> 24;
                    e.qwHandleCount = n.qwHandleCount;
                    e.qwPointerCount = n.qwPointerCount;
                    e.vaObjectCreateInfo = n.vaObjectCreateInfo;
                    e.vaSecurityDescriptor = n.vaSecurityDescriptor;
                    e.wszText = n.wszText;
                    e.dwPID = n.dwPID;
                    e.dwPoolTag = n.dwPoolTag;
                    e.wszType = n.wszType;
                    m[i] = e;
                }
                return m;
            }
        }

        public static unsafe MAP_NETENTRY[] Map_GetNet()
        {
            bool result;
            uint cb = 0;
            int cbMAP = System.Runtime.InteropServices.Marshal.SizeOf(typeof(vmmi.VMMDLL_MAP_NET));
            int cbENTRY = System.Runtime.InteropServices.Marshal.SizeOf(typeof(vmmi.VMMDLL_MAP_NETENTRY));
            result = vmmi.VMMDLL_Map_GetNet(null, ref cb);
            if (!result || (cb == 0)) { return new MAP_NETENTRY[0]; }
            fixed (byte* pb = new byte[cb])
            {
                result = vmmi.VMMDLL_Map_GetNet(pb, ref cb);
                if (!result) { return new MAP_NETENTRY[0]; }
                vmmi.VMMDLL_MAP_NET pm = Marshal.PtrToStructure<vmmi.VMMDLL_MAP_NET>((System.IntPtr)pb);
                if (pm.dwVersion != vmmi.VMMDLL_MAP_NET_VERSION) { return new MAP_NETENTRY[0]; }
                MAP_NETENTRY[] m = new MAP_NETENTRY[pm.cMap];
                for (int i = 0; i < pm.cMap; i++)
                {
                    vmmi.VMMDLL_MAP_NETENTRY n = Marshal.PtrToStructure<vmmi.VMMDLL_MAP_NETENTRY>((System.IntPtr)(pb + cbMAP + i * cbENTRY));
                    MAP_NETENTRY e;
                    e.dwPID = n.dwPID;
                    e.dwState = n.dwState;
                    e.dwPoolTag = n.dwPoolTag;
                    e.AF = n.AF;
                    e.src.fValid = n.src_fValid;
                    e.src.port = n.src_port;
                    e.src.pbAddr = n.src_pbAddr;
                    e.src.wszText = n.src_wszText;
                    e.dst.fValid = n.dst_fValid;
                    e.dst.port = n.dst_port;
                    e.dst.pbAddr = n.dst_pbAddr;
                    e.dst.wszText = n.dst_wszText;
                    e.vaObj = n.vaObj;
                    e.ftTime = n.ftTime;
                    e.wszText = n.wszText;
                    m[i] = e;
                }
                return m;
            }
        }

        public static unsafe MAP_PHYSMEMENTRY[] Map_GetPhysMem()
        {
            bool result;
            uint cb = 0;
            int cbMAP = System.Runtime.InteropServices.Marshal.SizeOf(typeof(vmmi.VMMDLL_MAP_PHYSMEM));
            int cbENTRY = System.Runtime.InteropServices.Marshal.SizeOf(typeof(vmmi.VMMDLL_MAP_PHYSMEMENTRY));
            result = vmmi.VMMDLL_Map_GetPhysMem(null, ref cb);
            if (!result || (cb == 0)) { return new MAP_PHYSMEMENTRY[0]; }
            fixed (byte* pb = new byte[cb])
            {
                result = vmmi.VMMDLL_Map_GetPhysMem(pb, ref cb);
                if (!result) { return new MAP_PHYSMEMENTRY[0]; }
                vmmi.VMMDLL_MAP_PHYSMEM pm = Marshal.PtrToStructure<vmmi.VMMDLL_MAP_PHYSMEM>((System.IntPtr)pb);
                if (pm.dwVersion != vmmi.VMMDLL_MAP_PHYSMEM_VERSION) { return new MAP_PHYSMEMENTRY[0]; }
                MAP_PHYSMEMENTRY[] m = new MAP_PHYSMEMENTRY[pm.cMap];
                for (int i = 0; i < pm.cMap; i++)
                {
                    vmmi.VMMDLL_MAP_PHYSMEMENTRY n = Marshal.PtrToStructure<vmmi.VMMDLL_MAP_PHYSMEMENTRY>((System.IntPtr)(pb + cbMAP + i * cbENTRY));
                    MAP_PHYSMEMENTRY e;
                    e.pa = n.pa;
                    e.cb = n.cb;
                    m[i] = e;
                }
                return m;
            }
        }

        public static unsafe MAP_USERENTRY[] Map_GetUsers()
        {
            bool result;
            uint cb = 0;
            int cbMAP = System.Runtime.InteropServices.Marshal.SizeOf(typeof(vmmi.VMMDLL_MAP_USER));
            int cbENTRY = System.Runtime.InteropServices.Marshal.SizeOf(typeof(vmmi.VMMDLL_MAP_USERENTRY));
            result = vmmi.VMMDLL_Map_GetUsers(null, ref cb);
            if (!result || (cb == 0)) { return new MAP_USERENTRY[0]; }
            fixed (byte* pb = new byte[cb])
            {
                result = vmmi.VMMDLL_Map_GetUsers(pb, ref cb);
                if (!result) { return new MAP_USERENTRY[0]; }
                vmmi.VMMDLL_MAP_USER pm = Marshal.PtrToStructure<vmmi.VMMDLL_MAP_USER>((System.IntPtr)pb);
                if (pm.dwVersion != vmmi.VMMDLL_MAP_USER_VERSION) { return new MAP_USERENTRY[0]; }
                MAP_USERENTRY[] m = new MAP_USERENTRY[pm.cMap];
                for (int i = 0; i < pm.cMap; i++)
                {
                    vmmi.VMMDLL_MAP_USERENTRY n = Marshal.PtrToStructure<vmmi.VMMDLL_MAP_USERENTRY>((System.IntPtr)(pb + cbMAP + i * cbENTRY));
                    MAP_USERENTRY e;
                    e.szSID = n.wszSID;
                    e.wszText = n.wszText;
                    e.vaRegHive = n.vaRegHive;
                    m[i] = e;
                }
                return m;
            }
        }

        public static unsafe MAP_SERVICEENTRY[] Map_GetServices()
        {
            bool result;
            uint cb = 0;
            int cbMAP = System.Runtime.InteropServices.Marshal.SizeOf(typeof(vmmi.VMMDLL_MAP_SERVICE));
            int cbENTRY = System.Runtime.InteropServices.Marshal.SizeOf(typeof(vmmi.VMMDLL_MAP_SERVICEENTRY));
            result = vmmi.VMMDLL_Map_GetServices(null, ref cb);
            if (!result || (cb == 0)) { return new MAP_SERVICEENTRY[0]; }
            fixed (byte* pb = new byte[cb])
            {
                result = vmmi.VMMDLL_Map_GetServices(pb, ref cb);
                if (!result) { return new MAP_SERVICEENTRY[0]; }
                vmmi.VMMDLL_MAP_SERVICE pm = Marshal.PtrToStructure<vmmi.VMMDLL_MAP_SERVICE>((System.IntPtr)pb);
                if (pm.dwVersion != vmmi.VMMDLL_MAP_SERVICE_VERSION) { return new MAP_SERVICEENTRY[0]; }
                MAP_SERVICEENTRY[] m = new MAP_SERVICEENTRY[pm.cMap];
                for (int i = 0; i < pm.cMap; i++)
                {
                    vmmi.VMMDLL_MAP_SERVICEENTRY n = Marshal.PtrToStructure<vmmi.VMMDLL_MAP_SERVICEENTRY>((System.IntPtr)(pb + cbMAP + i * cbENTRY));
                    MAP_SERVICEENTRY e;
                    e.vaObj = n.vaObj;
                    e.dwPID = n.dwPID;
                    e.dwOrdinal = n.dwOrdinal;
                    e.wszServiceName = n.wszServiceName;
                    e.wszDisplayName = n.wszDisplayName;
                    e.wszPath = n.wszPath;
                    e.wszUserTp = n.wszUserTp;
                    e.wszUserAcct = n.wszUserAcct;
                    e.wszImagePath = n.wszImagePath;
                    e.dwStartType = n.dwStartType;
                    e.dwServiceType = n.dwServiceType;
                    e.dwCurrentState = n.dwCurrentState;
                    e.dwControlsAccepted = n.dwControlsAccepted;
                    e.dwWin32ExitCode = n.dwWin32ExitCode;
                    e.dwServiceSpecificExitCode = n.dwServiceSpecificExitCode;
                    e.dwCheckPoint = n.dwCheckPoint;
                    e.dwWaitHint = n.dwWaitHint;
                    m[i] = e;
                }
                return m;
            }
        }

        public static unsafe MAP_PFNENTRY[] Map_GetPfn(params uint[] pfns)
        {
            bool result;
            uint cbPfns;
            int cbMAP = System.Runtime.InteropServices.Marshal.SizeOf(typeof(vmmi.VMMDLL_MAP_PFN));
            int cbENTRY = System.Runtime.InteropServices.Marshal.SizeOf(typeof(vmmi.VMMDLL_MAP_PFNENTRY));
            if (pfns.Length == 0) { return new MAP_PFNENTRY[0]; }
            byte[] dataPfns = new byte[pfns.Length * sizeof(uint)];
            System.Buffer.BlockCopy(pfns, 0, dataPfns, 0, dataPfns.Length);
            fixed (byte* pbPfns = dataPfns)
            {
                cbPfns = (uint)(cbMAP + pfns.Length * cbENTRY);
                fixed (byte* pb = new byte[cbPfns])
                {
                    result =
                        vmmi.VMMDLL_Map_GetPfn(pbPfns, (uint)pfns.Length, null, ref cbPfns) &&
                        vmmi.VMMDLL_Map_GetPfn(pbPfns, (uint)pfns.Length, pb, ref cbPfns);
                    if (!result) { return new MAP_PFNENTRY[0]; }
                    vmmi.VMMDLL_MAP_PFN pm = Marshal.PtrToStructure<vmmi.VMMDLL_MAP_PFN>((System.IntPtr)pb);
                    if (pm.dwVersion != vmmi.VMMDLL_MAP_PFN_VERSION) { return new MAP_PFNENTRY[0]; }
                    MAP_PFNENTRY[] m = new MAP_PFNENTRY[pm.cMap];
                    for (int i = 0; i < pm.cMap; i++)
                    {
                        vmmi.VMMDLL_MAP_PFNENTRY n = Marshal.PtrToStructure<vmmi.VMMDLL_MAP_PFNENTRY>((System.IntPtr)(pb + cbMAP + i * cbENTRY));
                        MAP_PFNENTRY e = new MAP_PFNENTRY();
                        e.dwPfn = n.dwPfn;
                        e.tp = (MAP_PFN_TYPE)(n._u3 & 0x07);
                        e.tpExtended = (MAP_PFN_TYPEEXTENDED)n.tpExtended;
                        e.vaPte = n.vaPte;
                        e.OriginalPte = n.OriginalPte;
                        e.fModified = ((n._u3 >> 20) & 1) == 1;
                        e.fReadInProgress = ((n._u3 >> 21) & 1) == 1;
                        e.fWriteInProgress = ((n._u3 >> 19) & 1) == 1;
                        e.priority = (byte)((n._u3 >> 24) & 7);
                        e.fPrototype = ((n._u4 >> 57) & 1) == 1;
                        if ((e.tp == MAP_PFN_TYPE.Active) && !e.fPrototype)
                        {
                            e.va = n.va;
                            e.dwPID = n.dwPfnPte[0];
                        }
                        m[i] = e;
                    }
                    return m;
                }
            }
        }



        //---------------------------------------------------------------------
        // REGISTRY FUNCTIONALITY BELOW:
        //---------------------------------------------------------------------

        public struct REGISTRY_HIVE_INFORMATION
        {
            public ulong vaCMHIVE;
            public ulong vaHBASE_BLOCK;
            public uint cbLength;
            public string szName;
            public string szNameShort;
            public string szHiveRootPath;
        }

        public struct REGISTRY_KEY_ENUM
        {
            public string name;
            public ulong ftLastWriteTime;
        }

        public struct REGISTRY_VALUE_ENUM
        {
            public string name;
            public uint type;
            public uint cbData;
        }

        public struct REGISTRY_ENUM
        {
            public string wszFullPathKey;
            public List<REGISTRY_KEY_ENUM> KeyList;
            public List<REGISTRY_VALUE_ENUM> ValueList;
        }

        public static unsafe REGISTRY_HIVE_INFORMATION[] RegHiveList()
        {
            bool result;
            uint cHives;
            int cbENTRY = System.Runtime.InteropServices.Marshal.SizeOf(typeof(vmmi.VMMDLL_REGISTRY_HIVE_INFORMATION));
            result = vmmi.VMMDLL_WinReg_HiveList(null, 0, out cHives);
            if (!result || (cHives == 0)) { return new REGISTRY_HIVE_INFORMATION[0]; }
            fixed (byte* pb = new byte[cHives * cbENTRY])
            {
                result = vmmi.VMMDLL_WinReg_HiveList(pb, cHives, out cHives);
                if (!result) { return new REGISTRY_HIVE_INFORMATION[0]; }
                REGISTRY_HIVE_INFORMATION[] m = new REGISTRY_HIVE_INFORMATION[cHives];
                for (int i = 0; i < cHives; i++)
                {
                    vmmi.VMMDLL_REGISTRY_HIVE_INFORMATION n = Marshal.PtrToStructure<vmmi.VMMDLL_REGISTRY_HIVE_INFORMATION>((System.IntPtr)(pb + i * cbENTRY));
                    REGISTRY_HIVE_INFORMATION e;
                    e.vaCMHIVE = n.vaCMHIVE;
                    e.vaHBASE_BLOCK = n.vaHBASE_BLOCK;
                    e.cbLength = n.cbLength;
                    e.szName = System.Text.Encoding.UTF8.GetString(n.szName);
                    e.szName = e.szName.Substring(0, e.szName.IndexOf((char)0));
                    e.szNameShort = n.wszNameShort;
                    e.szHiveRootPath = n.wszHiveRootPath;
                    m[i] = e;
                }
                return m;
            }
        }

        public static unsafe byte[] RegHiveRead(ulong vaCMHIVE, uint ra, uint cb, uint flags = 0)
        {
            uint cbRead;
            byte[] data = new byte[cb];
            fixed (byte* pb = data)
            {
                if(!vmmi.VMMDLL_WinReg_HiveReadEx(vaCMHIVE, ra, pb, cb, out cbRead, flags))
                {
                    return null;
                }
            }
            if(cbRead != cb)
            {
                Array.Resize<byte>(ref data, (int)cbRead);
            }
            return data;
        }


        public static unsafe bool RegHiveWrite(ulong vaCMHIVE, uint ra, byte[] data)
        {
            fixed (byte* pb = data)
            {
                return vmmi.VMMDLL_WinReg_HiveWrite(vaCMHIVE, ra, pb, (uint)data.Length);
            }
        }

        public static unsafe REGISTRY_ENUM RegEnum(string wszFullPathKey)
        {
            uint i, cchName, lpType, cbData = 0;
            ulong ftLastWriteTime;
            REGISTRY_ENUM re = new REGISTRY_ENUM();
            re.wszFullPathKey = wszFullPathKey;
            re.KeyList = new List<REGISTRY_KEY_ENUM>();
            re.ValueList = new List<REGISTRY_VALUE_ENUM>();
            fixed (byte* pb = new byte[0x1000])
            {
                i = 0;
                cchName = 0x800;
                while (vmmi.VMMDLL_WinReg_EnumKeyExW(wszFullPathKey, i, pb, ref cchName, out ftLastWriteTime))
                {
                    REGISTRY_KEY_ENUM e = new REGISTRY_KEY_ENUM();
                    e.ftLastWriteTime = ftLastWriteTime;
                    e.name = new string((sbyte*)pb, 0, 2 * (int)Math.Max(1, cchName) - 2, Encoding.Unicode);
                    re.KeyList.Add(e);
                    i++;
                    cchName = 0x800;
                }
                i = 0;
                cchName = 0x800;
                while (vmmi.VMMDLL_WinReg_EnumValueW(wszFullPathKey, i, pb, ref cchName, out lpType, null, ref cbData))
                {
                    REGISTRY_VALUE_ENUM e = new REGISTRY_VALUE_ENUM();
                    e.type = lpType;
                    e.cbData = cbData;
                    e.name = new string((sbyte*)pb, 0, 2 * (int)Math.Max(1, cchName) - 2, Encoding.Unicode);
                    re.ValueList.Add(e);
                    i++;
                    cchName = 0x800;
                }
            }
            return re;
        }

        public static unsafe byte[] RegValueRead(string wszFullPathKeyValue, out uint tp)
        {
            bool result;
            uint cb = 0;
            result = vmmi.VMMDLL_WinReg_QueryValueExW(wszFullPathKeyValue, out tp, null, ref cb);
            if(!result)
            {
                return null;
            }
            byte[] data = new byte[cb];
            fixed (byte* pb = data)
            {
                result = vmmi.VMMDLL_WinReg_QueryValueExW(wszFullPathKeyValue, out tp, pb, ref cb);
                return result ? data : null;
            }
        }
    }



    internal static class lci
    {
        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential)]
        internal struct LC_CONFIG_ERRORINFO
        {
            internal uint dwVersion;
            internal uint cbStruct;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)] internal uint[] _FutureUse;
            internal bool fUserInputRequest;
            internal uint cwszUserText;
            // szUserText
        }

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential)]
        internal struct LC_MEM_SCATTER
        {
            internal uint version;
            internal bool f;
            internal ulong qwA;
            internal IntPtr pb;
            internal uint cb;
            internal uint iStack;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 12)] internal ulong[] vStack;
        }

        [DllImport("leechcore.dll", EntryPoint = "LcCreateEx")]
        public static extern ulong LcCreateEx(ref lc.CONFIG pLcCreateConfig, out IntPtr ppLcCreateErrorInfo);

        [DllImport("leechcore.dll", EntryPoint = "LcMemFree")]
        internal static extern unsafe void LcMemFree(IntPtr pv);

        [DllImport("leechcore.dll", EntryPoint = "LcAllocScatter1")]
        internal static extern unsafe bool LcAllocScatter1(uint cMEMs, out IntPtr pppMEMs);

        [DllImport("leechcore.dll", EntryPoint = "LcRead")]
        internal static extern unsafe bool LcRead(ulong hLC, ulong pa, uint cb, byte* pb);

        [DllImport("leechcore.dll", EntryPoint = "LcReadScatter")]
        internal static extern unsafe void LcReadScatter(ulong hLC, uint cMEMs, IntPtr ppMEMs);

        [DllImport("leechcore.dll", EntryPoint = "LcWrite")]
        internal static extern unsafe bool LcWrite(ulong hLC, ulong pa, uint cb, byte* pb);

        [DllImport("leechcore.dll", EntryPoint = "LcWriteScatter")]
        internal static extern unsafe void LcWriteScatter(ulong hLC, uint cMEMs, IntPtr ppMEMs);

        [DllImport("leechcore.dll", EntryPoint = "LcCommand")]
        internal static extern unsafe bool LcCommand(ulong hLC, ulong fOption, uint cbDataIn, byte* pbDataIn, out IntPtr ppbDataOut, out uint pcbDataOut);
    }



    internal static class vmmi
    {
        internal static ulong MAX_PATH =                     260;
        internal static uint VMMDLL_MAP_PTE_VERSION =        2;
        internal static uint VMMDLL_MAP_VAD_VERSION =        6;
        internal static uint VMMDLL_MAP_VADEX_VERSION =      3;
        internal static uint VMMDLL_MAP_MODULE_VERSION =     5;
        internal static uint VMMDLL_MAP_UNLOADEDMODULE_VERSION = 2;
        internal static uint VMMDLL_MAP_EAT_VERSION =        2;
        internal static uint VMMDLL_MAP_IAT_VERSION =        2;
        internal static uint VMMDLL_MAP_HEAP_VERSION =       2;
        internal static uint VMMDLL_MAP_THREAD_VERSION =     3;
        internal static uint VMMDLL_MAP_HANDLE_VERSION =     2;
        internal static uint VMMDLL_MAP_NET_VERSION =        3;
        internal static uint VMMDLL_MAP_PHYSMEM_VERSION =    2;
        internal static uint VMMDLL_MAP_USER_VERSION =       2;
        internal static uint VMMDLL_MAP_PFN_VERSION =        1;
        internal static uint VMMDLL_MAP_SERVICE_VERSION =    3;



        [DllImport("vmm.dll", EntryPoint = "VMMDLL_Initialize")]
        internal static extern bool VMMDLL_Initialize(
            int argc,
            string[] argv);

        [DllImport("vmm.dll", EntryPoint = "VMMDLL_InitializeEx")]
        internal static extern bool VMMDLL_InitializeEx(
            int argc,
            string[] argv,
            out IntPtr ppLcErrorInfo);

        [DllImport("vmm.dll", EntryPoint = "VMMDLL_MemFree")]
        internal static extern unsafe bool VMMDLL_MemFree(
            byte* pvMem);



        // VFS (VIRTUAL FILE SYSTEM) FUNCTIONALITY BELOW:

        internal static uint VMMDLL_VFS_FILELIST_EXINFO_VERSION =   1;
        internal static uint VMMDLL_VFS_FILELIST_VERSION =          2;

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential)]
        internal struct VMMDLL_VFS_FILELIST
        {
            internal uint dwVersion;
            internal uint _Reserved;
            internal IntPtr pfnAddFile;
            internal IntPtr pfnAddDirectory;
            internal ulong h;
        }

        [DllImport("vmm.dll", EntryPoint = "VMMDLL_VfsListU")]
        internal static extern unsafe bool VMMDLL_VfsList(
            [MarshalAs(UnmanagedType.LPUTF8Str)] string wcsPath,
            ref VMMDLL_VFS_FILELIST pFileList);

        [DllImport("vmm.dll", EntryPoint = "VMMDLL_VfsReadU")]
        internal static extern unsafe uint VMMDLL_VfsRead(
            [MarshalAs(UnmanagedType.LPUTF8Str)] string wcsFileName,
            byte* pb,
            uint cb,
            out uint pcbRead,
            ulong cbOffset);

        [DllImport("vmm.dll", EntryPoint = "VMMDLL_VfsWriteU")]
        internal static extern unsafe uint VMMDLL_VfsWrite(
            [MarshalAs(UnmanagedType.LPUTF8Str)] string wcsFileName,
            byte* pb,
            uint cb,
            out uint pcbRead,
            ulong cbOffset);



        // MEMORY READ/WRITE FUNCTIONALITY BELOW:

        [DllImport("vmm.dll", EntryPoint = "VMMDLL_MemReadScatter")]
        internal static extern unsafe uint VMMDLL_MemReadScatter(
            uint dwPID,
            IntPtr ppMEMs,
            uint cpMEMs,
            uint flags);

        [DllImport("vmm.dll", EntryPoint = "VMMDLL_MemReadEx")]
        internal static extern unsafe bool VMMDLL_MemReadEx(
            uint dwPID,
            ulong qwA,
            byte* pb,
            uint cb,
            out uint pcbReadOpt,
            uint flags);

        [DllImport("vmm.dll", EntryPoint = "VMMDLL_MemPrefetchPages")]
        internal static extern unsafe bool VMMDLL_MemPrefetchPages(
            uint dwPID,
            byte* pPrefetchAddresses,
            uint cPrefetchAddresses);

        [DllImport("vmm.dll", EntryPoint = "VMMDLL_MemWrite")]
        internal static extern unsafe bool VMMDLL_MemWrite(
            uint dwPID,
            ulong qwA,
            byte* pb,
            uint cb);



        // PROCESS FUNCTIONALITY BELOW:

        [DllImport("vmm.dll", EntryPoint = "VMMDLL_PidList")]
        internal static extern unsafe bool VMMDLL_PidList(byte* pPIDs, ref ulong pcPIDs);

        internal static ulong VMMDLL_PROCESS_INFORMATION_MAGIC =        0xc0ffee663df9301e;
        internal static ushort VMMDLL_PROCESS_INFORMATION_VERSION =     6;

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential, CharSet = CharSet.Ansi)]
        internal struct VMMDLL_PROCESS_INFORMATION
        {
            internal ulong magic;
            internal ushort wVersion;
            internal ushort wSize;
            internal uint tpMemoryModel;
            internal uint tpSystem;
            internal bool fUserOnly;
            internal uint dwPID;
            internal uint dwPPID;
            internal uint dwState;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 16)] internal string szName;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 64)] internal string szNameLong;
            internal ulong paDTB;
            internal ulong paDTB_UserOpt;
            internal ulong vaEPROCESS;
            internal ulong vaPEB;
            internal ulong _Reserved1;
            internal bool fWow64;
            internal uint vaPEB32;
            internal uint dwSessionId;
            internal ulong qwLUID;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)] internal string szSID;
        }

        [DllImport("vmm.dll", EntryPoint = "VMMDLL_ProcessGetInformation")]
        internal static extern unsafe bool VMMDLL_ProcessGetInformation(
            uint dwPID,
            byte* pProcessInformation,
            ref ulong pcbProcessInformation);

        [DllImport("vmm.dll", EntryPoint = "VMMDLL_ProcessGetInformationString")]
        internal static extern unsafe byte* VMMDLL_ProcessGetInformationString(
            uint dwPID,
            uint fOptionString);

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential, CharSet = CharSet.Ansi)]
        internal struct VMMDLL_IMAGE_SECTION_HEADER
        {
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 8)] internal string Name;
            internal uint MiscPhysicalAddressOrVirtualSize;
            internal uint VirtualAddress;
            internal uint SizeOfRawData;
            internal uint PointerToRawData;
            internal uint PointerToRelocations;
            internal uint PointerToLinenumbers;
            internal ushort NumberOfRelocations;
            internal ushort NumberOfLinenumbers;
            internal uint Characteristics;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential)]
        internal struct VMMDLL_IMAGE_DATA_DIRECTORY
        {
            internal uint VirtualAddress;
            internal uint Size;
        }

        [DllImport("vmm.dll", EntryPoint = "VMMDLL_ProcessGetDirectoriesW")]
        internal static extern unsafe bool VMMDLL_ProcessGetDirectories(
            uint dwPID,
            [MarshalAs(UnmanagedType.LPWStr)] string wszModule,
            byte* pData,
            uint cData,
            out uint pcData);

        [DllImport("vmm.dll", EntryPoint = "VMMDLL_ProcessGetSectionsW")]
        internal static extern unsafe bool VMMDLL_ProcessGetSections(
            uint dwPID,
            [MarshalAs(UnmanagedType.LPWStr)] string wszModule,
            byte* pData,
            uint cData,
            out uint pcData);



        // WINDOWS SPECIFIC DEBUGGING / SYMBOL FUNCTIONALITY BELOW:

        [DllImport("vmm.dll", EntryPoint = "VMMDLL_PdbLoad")]
        internal static extern unsafe bool VMMDLL_PdbLoad(
            uint dwPID,
            ulong vaModuleBase,
            byte* pModuleMapEntry);

        [DllImport("vmm.dll", EntryPoint = "VMMDLL_PdbSymbolName")]
        internal static extern unsafe bool VMMDLL_PdbSymbolName(
            [MarshalAs(UnmanagedType.LPStr)] string szModule,
            ulong cbSymbolAddressOrOffset,
            byte* szSymbolName,
            out uint pdwSymbolDisplacement);



        // VMMDLL_Map_GetPte

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential)]
        internal struct VMMDLL_MAP_PTEENTRY
        {
            internal ulong vaBase;
            internal ulong cPages;
            internal ulong fPage;
            internal bool fWoW64;
            internal uint _FutureUse1;
            [MarshalAs(UnmanagedType.LPWStr)] internal string wszText;
            internal uint _Reserved1;
            internal uint cSoftware;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential)]
        internal struct VMMDLL_MAP_PTE
        {
            internal uint dwVersion;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 5)] internal uint[] _Reserved1;
            internal ulong pbMultiText;
            internal uint cbMultiText;
            internal uint cMap;
        }

        [DllImport("vmm.dll", EntryPoint = "VMMDLL_Map_GetPteW")]
        internal static extern unsafe bool VMMDLL_Map_GetPte(
            uint dwPid,
            byte* pPteMap,
            ref uint pcbPteMap,
            bool fIdentifyModules);



        // VMMDLL_Map_GetVad

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential)]
        internal struct VMMDLL_MAP_VADENTRY
        {
            internal ulong vaStart;
            internal ulong vaEnd;
            internal ulong vaVad;
            internal uint dw0;
            internal uint dw1;
            internal uint u2;
            internal uint cbPrototypePte;
            internal ulong vaPrototypePte;
            internal ulong vaSubsection;
            [MarshalAs(UnmanagedType.LPWStr)] internal string wszText;
            internal uint _FutureUse1;
            internal uint _Reserved1;
            internal ulong vaFileObject;
            internal uint cVadExPages;
            internal uint cVadExPagesBase;
            internal ulong _Reserved2;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential)]
        internal struct VMMDLL_MAP_VAD
        {
            internal uint dwVersion;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)] internal uint[] _Reserved1;
            internal uint cPage;
            internal ulong pbMultiText;
            internal uint cbMultiText;
            internal uint cMap;
        }

        [DllImport("vmm.dll", EntryPoint = "VMMDLL_Map_GetVadW")]
        internal static extern unsafe bool VMMDLL_Map_GetVad(
            uint dwPid,
            byte* pVadMap,
            ref uint pcbVadMap,
            bool fIdentifyModules);



        // VMMDLL_Map_GetVadEx

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential)]
        internal struct VMMDLL_MAP_VADEXENTRY
        {
            internal uint tp;
            internal uint iPML;
            internal ulong va;
            internal ulong pa;
            internal ulong pte;
            internal uint _Reserved1;
            internal uint proto_tp;
            internal ulong proto_pa;
            internal ulong proto_pte;
            internal ulong vaVadBase;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential)]
        internal struct VMMDLL_MAP_VADEX
        {
            internal uint dwVersion;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)] internal uint[] _Reserved1;
            internal uint cMap;
        }

        [DllImport("vmm.dll", EntryPoint = "VMMDLL_Map_GetVadEx")]
        internal static extern unsafe bool VMMDLL_Map_GetVadEx(
            uint dwPid,
            byte* pVadMap,
            ref uint pcbVadMap,
            uint oPage,
            uint cPage);



        // VMMDLL_Map_GetModule

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential)]
        internal struct VMMDLL_MAP_MODULEENTRY
        {
            internal ulong vaBase;
            internal ulong vaEntry;
            internal uint cbImageSize;
            internal bool fWow64;
            [MarshalAs(UnmanagedType.LPWStr)] internal string wszText;
            internal uint _Reserved3;
            internal uint _Reserved4;
            [MarshalAs(UnmanagedType.LPWStr)] internal string wszFullName;
            internal uint tp;
            internal uint cbFileSizeRaw;
            internal uint cSection;
            internal uint cEAT;
            internal uint cIAT;
            internal uint _Reserved2;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 2)] internal ulong[] _Reserved1;
        }

        internal struct VMMDLL_MAP_MODULE
        {
            internal uint dwVersion;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 5)] internal uint[] _Reserved1;
            internal ulong pbMultiText;
            internal uint cbMultiText;
            internal uint cMap;
        }

        [DllImport("vmm.dll", EntryPoint = "VMMDLL_Map_GetModuleW")]
        internal static extern unsafe bool VMMDLL_Map_GetModule(uint dwPid, byte* pModuleMap, ref uint pcbModuleMap);

        // VMMDLL_Map_GetModuleFromName

        [DllImport("vmm.dll", EntryPoint = "VMMDLL_Map_GetModuleFromNameW")]
        internal static extern unsafe bool VMMDLL_Map_GetModuleFromName(
            uint dwPID,
            [MarshalAs(UnmanagedType.LPWStr)] string wszModuleName,
            byte* pModuleMapEntry,
            ref uint pcbModuleMapEntry);



        // VMMDLL_Map_GetUnloadedModule

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential)]
        internal struct VMMDLL_MAP_UNLOADEDMODULEENTRY
        {
            internal ulong vaBase;
            internal uint cbImageSize;
            internal bool fWow64;
            [MarshalAs(UnmanagedType.LPWStr)] internal string wszText;
            internal uint _FutureUse1;
            internal uint dwCheckSum;
            internal uint dwTimeDateStamp;
            internal uint _Reserved1;
            internal ulong ftUnload;
        }

        internal struct VMMDLL_MAP_UNLOADEDMODULE
        {
            internal uint dwVersion;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 5)] internal uint[] _Reserved1;
            internal ulong pbMultiText;
            internal uint cbMultiText;
            internal uint cMap;
        }

        [DllImport("vmm.dll", EntryPoint = "VMMDLL_Map_GetUnloadedModuleW")]
        internal static extern unsafe bool VMMDLL_Map_GetUnloadedModule(uint dwPid, byte* pModuleMap, ref uint pcbModuleMap);
        
        
        
        // VMMDLL_Map_GetEAT

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential)]
        internal struct VMMDLL_MAP_EATENTRY
        {
            internal ulong vaFunction;
            internal uint dwOrdinal;
            internal uint oFunctionsArray;
            internal uint oNamesArray;
            internal uint _FutureUse1;
            [MarshalAs(UnmanagedType.LPWStr)] internal string wszFunction;
        }

        internal struct VMMDLL_MAP_EAT
        {
            internal uint dwVersion;
            internal uint dwOrdinalBase;
            internal uint cNumberOfNames;
            internal uint cNumberOfFunctions;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)] internal uint[] _Reserved1;
            internal ulong vaModuleBase;
            internal ulong vaAddressOfFunctions;
            internal ulong vaAddressOfNames;
            internal ulong pbMultiText;
            internal uint cbMultiText;
            internal uint cMap;
        }

        [DllImport("vmm.dll", EntryPoint = "VMMDLL_Map_GetEATW")]
        internal static extern unsafe bool VMMDLL_Map_GetEAT(
            uint dwPid,
            [MarshalAs(UnmanagedType.LPWStr)] string wszModuleName,
            byte* pEatMap,
            ref uint pcbEatMap);



        // VMMDLL_Map_GetIAT

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential)]
        internal struct VMMDLL_MAP_IATENTRY
        {
            internal ulong vaFunction;
            [MarshalAs(UnmanagedType.LPWStr)] internal string wszFunction;
            internal uint _FutureUse1;
            internal uint _FutureUse2;
            [MarshalAs(UnmanagedType.LPWStr)] internal string wszModule;
            internal bool f32;
            internal ushort wHint;
            internal ushort _Reserved1;
            internal uint rvaFirstThunk;
            internal uint rvaOriginalFirstThunk;
            internal uint rvaNameModule;
            internal uint rvaNameFunction;
        }

        internal struct VMMDLL_MAP_IAT
        {
            internal uint dwVersion;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 5)] internal uint[] _Reserved1;
            internal ulong vaModuleBase;
            internal ulong pbMultiText;
            internal uint cbMultiText;
            internal uint cMap;
        }

        [DllImport("vmm.dll", EntryPoint = "VMMDLL_Map_GetIATW")]
        internal static extern unsafe bool VMMDLL_Map_GetIAT(
            uint dwPid,
            [MarshalAs(UnmanagedType.LPWStr)] string wszModuleName,
            byte* pIatMap,
            ref uint pcbIatMap);



        // VMMDLL_Map_GetHeap

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential)]
        internal struct VMMDLL_MAP_HEAPENTRY
        {
            internal ulong vaHeapSegment;
            internal uint cPages;
            internal uint cPagesUnCommitted_HeapId_fPrimary;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential)]
        internal struct VMMDLL_MAP_HEAP
        {
            internal uint dwVersion;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)] internal uint[] _Reserved1;
            internal uint cMap;
        }

        [DllImport("vmm.dll", EntryPoint = "VMMDLL_Map_GetHeap")]
        internal static extern unsafe bool VMMDLL_Map_GetHeap(
            uint dwPid,
            byte* pHeapMap,
            ref uint pcbHeapMap);



        // VMMDLL_Map_GetThread

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential)]
        internal struct VMMDLL_MAP_THREADENTRY
        {
            internal uint dwTID;
            internal uint dwPID;
            internal uint dwExitStatus;
            internal byte bState;
            internal byte bRunning;
            internal byte bPriority;
            internal byte bBasePriority;
            internal ulong vaETHREAD;
            internal ulong vaTeb;
            internal ulong ftCreateTime;
            internal ulong ftExitTime;
            internal ulong vaStartAddress;
            internal ulong vaStackBaseUser;          // value from _NT_TIB / _TEB
            internal ulong vaStackLimitUser;         // value from _NT_TIB / _TEB
            internal ulong vaStackBaseKernel;
            internal ulong vaStackLimitKernel;
            internal ulong vaTrapFrame;
            internal ulong vaRIP;                    // RIP register (if user mode)
            internal ulong vaRSP;                    // RSP register (if user mode)
            internal ulong qwAffinity;
            internal uint dwUserTime;
            internal uint dwKernelTime;
            internal byte bSuspendCount;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 3)] internal byte[] _FutureUse1;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 15)] internal uint[] _FutureUse2;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential)]
        internal struct VMMDLL_MAP_THREAD
        {
            internal uint dwVersion;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)] internal uint[] _Reserved1;
            internal uint cMap;
        }

        [DllImport("vmm.dll", EntryPoint = "VMMDLL_Map_GetThread")]
        internal static extern unsafe bool VMMDLL_Map_GetThread(
            uint dwPid,
            byte* pThreadMap,
            ref uint pcbThreadMap);



        // VMMDLL_Map_GetHandle

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential)]
        internal struct VMMDLL_MAP_HANDLEENTRY
        {
            internal ulong vaObject;
            internal uint dwHandle;
            internal uint dwGrantedAccess_iType;
            internal ulong qwHandleCount;
            internal ulong qwPointerCount;
            internal ulong vaObjectCreateInfo;
            internal ulong vaSecurityDescriptor;
            [MarshalAs(UnmanagedType.LPWStr)] internal string wszText;
            internal uint _FutureUse2;
            internal uint dwPID;
            internal uint dwPoolTag;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 5)] internal uint[] _FutureUse;
            [MarshalAs(UnmanagedType.LPWStr)] internal string wszType;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential)]
        internal struct VMMDLL_MAP_HANDLE
        {
            internal uint dwVersion;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 5)] internal uint[] _Reserved1;
            internal ulong pbMultiText;
            internal uint cbMultiText;
            internal uint cMap;
        }

        [DllImport("vmm.dll", EntryPoint = "VMMDLL_Map_GetHandleW")]
        internal static extern unsafe bool VMMDLL_Map_GetHandle(
            uint dwPid,
            byte* pHandleMap,
            ref uint pcbHandleMap);



        // VMMDLL_Map_GetNet

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential)]
        internal struct VMMDLL_MAP_NETENTRY
        {
            internal uint dwPID;
            internal uint dwState;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 3)] internal ushort[] _FutureUse3;
            internal ushort AF;
            // src
            internal bool src_fValid;
            internal ushort src__Reserved1;
            internal ushort src_port;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)] internal byte[] src_pbAddr;
            [MarshalAs(UnmanagedType.LPWStr)] internal string src_wszText;
            // dst
            internal bool dst_fValid;
            internal ushort dst__Reserved1;
            internal ushort dst_port;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)] internal byte[] dst_pbAddr;
            [MarshalAs(UnmanagedType.LPWStr)] internal string dst_wszText;
            //
            internal ulong vaObj;
            internal ulong ftTime;
            internal uint dwPoolTag;
            internal uint _FutureUse4;
            [MarshalAs(UnmanagedType.LPWStr)] internal string wszText;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)] internal uint[] _FutureUse2;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential)]
        internal struct VMMDLL_MAP_NET
        {
            internal uint dwVersion;
            internal uint _Reserved1;
            internal ulong pbMultiText;
            internal uint cbMultiText;
            internal uint cMap;
        }

        [DllImport("vmm.dll", EntryPoint = "VMMDLL_Map_GetNetW")]
        internal static extern unsafe bool VMMDLL_Map_GetNet(
            byte* pNetMap,
            ref uint pcbNetMap);
        
        
        
        // VMMDLL_Map_GetPhysMem

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential)]
        internal struct VMMDLL_MAP_PHYSMEMENTRY
        {
            internal ulong pa;
            internal ulong cb;
        }
        
        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential)]
        internal struct VMMDLL_MAP_PHYSMEM
        {
            internal uint dwVersion;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 5)] internal uint[] _Reserved1;
            internal uint cMap;
            internal uint _Reserved2;
        }

        [DllImport("vmm.dll", EntryPoint = "VMMDLL_Map_GetPhysMem")]
        internal static extern unsafe bool VMMDLL_Map_GetPhysMem(
            byte* pNetMap,
            ref uint pcbNetMap);



        // VMMDLL_Map_GetUsers

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential, CharSet = CharSet.Ansi)]
        internal struct VMMDLL_MAP_USERENTRY
        {
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 2)] internal uint[] _FutureUse1;
            [MarshalAs(UnmanagedType.LPWStr)] internal string wszText;
            internal ulong vaRegHive;
            [MarshalAs(UnmanagedType.LPWStr)] internal string wszSID;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 2)] internal uint[] _FutureUse2;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential)]
        internal struct VMMDLL_MAP_USER
        {
            internal uint dwVersion;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 5)] internal uint[] _Reserved1;
            internal ulong pbMultiText;
            internal uint cbMultiText;
            internal uint cMap;
        }

        [DllImport("vmm.dll", EntryPoint = "VMMDLL_Map_GetUsersW")]
        internal static extern unsafe bool VMMDLL_Map_GetUsers(
            byte* pbUserMap,
            ref uint pcbUserMap);



        // VMMDLL_Map_GetServuces

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential)]
        internal struct VMMDLL_MAP_SERVICEENTRY
        {
            internal ulong vaObj;
            internal uint dwOrdinal;
            internal uint dwStartType;
            // SERVICE_STATUS START
            internal uint dwServiceType;
            internal uint dwCurrentState;
            internal uint dwControlsAccepted;
            internal uint dwWin32ExitCode;
            internal uint dwServiceSpecificExitCode;
            internal uint dwCheckPoint;
            internal uint dwWaitHint;
            // SERVICE_STATUS END
            [MarshalAs(UnmanagedType.LPWStr)] internal string wszServiceName;
            [MarshalAs(UnmanagedType.LPWStr)] internal string wszDisplayName;
            [MarshalAs(UnmanagedType.LPWStr)] internal string wszPath;
            [MarshalAs(UnmanagedType.LPWStr)] internal string wszUserTp;
            [MarshalAs(UnmanagedType.LPWStr)] internal string wszUserAcct;
            [MarshalAs(UnmanagedType.LPWStr)] internal string wszImagePath;
            internal uint dwPID;
            internal uint _FutureUse1;
            internal ulong _FutureUse2;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential)]
        internal struct VMMDLL_MAP_SERVICE
        {
            internal uint dwVersion;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 5)] internal uint[] _Reserved1;
            internal ulong pbMultiText;
            internal uint cbMultiText;
            internal uint cMap;
        }

        [DllImport("vmm.dll", EntryPoint = "VMMDLL_Map_GetServicesW")]
        internal static extern unsafe bool VMMDLL_Map_GetServices(
            byte* pbServiceMap,
            ref uint pcbServiceMap);



        // VMMDLL_Map_GetPfn

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential)]
        internal struct VMMDLL_MAP_PFNENTRY
        {
            internal uint dwPfn;
            internal uint tpExtended;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 5)] internal uint[] dwPfnPte;
            internal ulong va;
            internal ulong vaPte;
            internal ulong OriginalPte;
            internal uint _u3;
            internal ulong _u4;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 6)] internal uint[] _FutureUse;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential)]
        internal struct VMMDLL_MAP_PFN
        {
            internal uint dwVersion;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 5)] internal uint[] _Reserved1;
            internal uint cMap;
            internal uint _Reserved2;
        }

        [DllImport("vmm.dll", EntryPoint = "VMMDLL_Map_GetPfn")]
        internal static extern unsafe bool VMMDLL_Map_GetPfn(
            byte* pPfns,
            uint cPfns,
            byte* pPfnMap,
            ref uint pcbPfnMap);



        // REGISTRY FUNCTIONALITY BELOW:

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        internal struct VMMDLL_REGISTRY_HIVE_INFORMATION
        {
            internal ulong magic;
            internal ushort wVersion;
            internal ushort wSize;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 0x14)] internal byte[] _FutureReserved1;
            internal ulong vaCMHIVE;
            internal ulong vaHBASE_BLOCK;
            internal uint cbLength;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 128)] internal byte[] szName;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 33)] internal string wszNameShort;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)] internal string wszHiveRootPath;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 0x10)] internal ulong[] _FutureReserved;
        }

        [DllImport("vmm.dll", EntryPoint = "VMMDLL_WinReg_HiveList")]
        internal static extern unsafe bool VMMDLL_WinReg_HiveList(
            byte* pHives,
            uint cHives,
            out uint pcHives);

        [DllImport("vmm.dll", EntryPoint = "VMMDLL_WinReg_HiveReadEx")]
        internal static extern unsafe bool VMMDLL_WinReg_HiveReadEx(
            ulong vaCMHive,
            uint ra,
            byte* pb,
            uint cb,
            out uint pcbReadOpt,
            uint flags);

        [DllImport("vmm.dll", EntryPoint = "VMMDLL_WinReg_HiveWrite")]
        internal static extern unsafe bool VMMDLL_WinReg_HiveWrite(
            ulong vaCMHive,
            uint ra,
            byte* pb,
            uint cb);

        [DllImport("vmm.dll", EntryPoint = "VMMDLL_WinReg_EnumKeyExW")]
        internal static extern unsafe bool VMMDLL_WinReg_EnumKeyExW(
            [MarshalAs(UnmanagedType.LPWStr)] string wszFullPathKey,
            uint dwIndex,
            byte* lpName,
            ref uint lpcchName,
            out ulong lpftLastWriteTime);

        [DllImport("vmm.dll", EntryPoint = "VMMDLL_WinReg_EnumValueW")]
        internal static extern unsafe bool VMMDLL_WinReg_EnumValueW(
            [MarshalAs(UnmanagedType.LPWStr)] string wszFullPathKey,
            uint dwIndex,
            byte* lpValueName,
            ref uint lpcchValueName,
            out uint lpType,
            byte* lpData,
            ref uint lpcbData);

        [DllImport("vmm.dll", EntryPoint = "VMMDLL_WinReg_QueryValueExW")]
        internal static extern unsafe bool VMMDLL_WinReg_QueryValueExW(
            [MarshalAs(UnmanagedType.LPWStr)] string wszFullPathKeyValue,
            out uint lpType,
            byte* lpData,
            ref uint lpcbData);
    }
}
