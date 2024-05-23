using System;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using Vmmsharp.Internal;

/*  
 *  C# API wrapper 'vmmsharp' for MemProcFS 'vmm.dll' and LeechCore 'leechcore.dll' APIs.
 *  
 *  Please see the example project in vmm_example.cs for additional information.
 *  
 *  Please consult the C/C++ header files vmmdll.h and leechcore.h for information about
 *  parameters and API usage.
 *  
 *  (c) Ulf Frisk, 2020-2024
 *  Author: Ulf Frisk, pcileech@frizk.net
 *  
 *  Version 5.9
 *  
 */

namespace Vmmsharp
{
    /// <summary>
    /// LeechCore public API
    /// </summary>
    public sealed class LeechCore : IDisposable
    {
        //---------------------------------------------------------------------
        // LEECHCORE: PUBLIC API CONSTANTS BELOW:
        //---------------------------------------------------------------------
        public const uint LC_CONFIG_VERSION = 0xc0fd0002;
        public const uint LC_CONFIG_ERRORINFO_VERSION = 0xc0fe0002;

        public const uint LC_CONFIG_PRINTF_ENABLED = 0x01;
        public const uint LC_CONFIG_PRINTF_V = 0x02;
        public const uint LC_CONFIG_PRINTF_VV = 0x04;
        public const uint LC_CONFIG_PRINTF_VVV = 0x08;

        public const ulong LC_OPT_CORE_PRINTF_ENABLE = 0x4000000100000000;  // RW
        public const ulong LC_OPT_CORE_VERBOSE = 0x4000000200000000;  // RW
        public const ulong LC_OPT_CORE_VERBOSE_EXTRA = 0x4000000300000000;  // RW
        public const ulong LC_OPT_CORE_VERBOSE_EXTRA_TLP = 0x4000000400000000;  // RW
        public const ulong LC_OPT_CORE_VERSION_MAJOR = 0x4000000500000000;  // R
        public const ulong LC_OPT_CORE_VERSION_MINOR = 0x4000000600000000;  // R
        public const ulong LC_OPT_CORE_VERSION_REVISION = 0x4000000700000000;  // R
        public const ulong LC_OPT_CORE_ADDR_MAX = 0x1000000800000000;  // R
        public const ulong LC_OPT_CORE_STATISTICS_CALL_COUNT = 0x4000000900000000;  // R [lo-dword: LC_STATISTICS_ID_*]
        public const ulong LC_OPT_CORE_STATISTICS_CALL_TIME = 0x4000000a00000000;  // R [lo-dword: LC_STATISTICS_ID_*]
        public const ulong LC_OPT_CORE_VOLATILE = 0x1000000b00000000;  // R
        public const ulong LC_OPT_CORE_READONLY = 0x1000000c00000000;  // R

        public const ulong LC_OPT_MEMORYINFO_VALID = 0x0200000100000000;  // R
        public const ulong LC_OPT_MEMORYINFO_FLAG_32BIT = 0x0200000300000000;  // R
        public const ulong LC_OPT_MEMORYINFO_FLAG_PAE = 0x0200000400000000;  // R
        public const ulong LC_OPT_MEMORYINFO_ARCH = 0x0200001200000000;  // R - LC_ARCH_TP
        public const ulong LC_OPT_MEMORYINFO_OS_VERSION_MINOR = 0x0200000500000000;  // R
        public const ulong LC_OPT_MEMORYINFO_OS_VERSION_MAJOR = 0x0200000600000000;  // R
        public const ulong LC_OPT_MEMORYINFO_OS_DTB = 0x0200000700000000;  // R
        public const ulong LC_OPT_MEMORYINFO_OS_PFN = 0x0200000800000000;  // R
        public const ulong LC_OPT_MEMORYINFO_OS_PsLoadedModuleList = 0x0200000900000000;  // R
        public const ulong LC_OPT_MEMORYINFO_OS_PsActiveProcessHead = 0x0200000a00000000;  // R
        public const ulong LC_OPT_MEMORYINFO_OS_MACHINE_IMAGE_TP = 0x0200000b00000000;  // R
        public const ulong LC_OPT_MEMORYINFO_OS_NUM_PROCESSORS = 0x0200000c00000000;  // R
        public const ulong LC_OPT_MEMORYINFO_OS_SYSTEMTIME = 0x0200000d00000000;  // R
        public const ulong LC_OPT_MEMORYINFO_OS_UPTIME = 0x0200000e00000000;  // R
        public const ulong LC_OPT_MEMORYINFO_OS_KERNELBASE = 0x0200000f00000000;  // R
        public const ulong LC_OPT_MEMORYINFO_OS_KERNELHINT = 0x0200001000000000;  // R
        public const ulong LC_OPT_MEMORYINFO_OS_KdDebuggerDataBlock = 0x0200001100000000;  // R

        public const ulong LC_OPT_FPGA_PROBE_MAXPAGES = 0x0300000100000000;  // RW
        public const ulong LC_OPT_FPGA_MAX_SIZE_RX = 0x0300000300000000;  // RW
        public const ulong LC_OPT_FPGA_MAX_SIZE_TX = 0x0300000400000000;  // RW
        public const ulong LC_OPT_FPGA_DELAY_PROBE_READ = 0x0300000500000000;  // RW - uS
        public const ulong LC_OPT_FPGA_DELAY_PROBE_WRITE = 0x0300000600000000;  // RW - uS
        public const ulong LC_OPT_FPGA_DELAY_WRITE = 0x0300000700000000;  // RW - uS
        public const ulong LC_OPT_FPGA_DELAY_READ = 0x0300000800000000;  // RW - uS
        public const ulong LC_OPT_FPGA_RETRY_ON_ERROR = 0x0300000900000000;  // RW
        public const ulong LC_OPT_FPGA_DEVICE_ID = 0x0300008000000000;  // RW - bus:dev:fn (ex: 04:00.0 === 0x0400).
        public const ulong LC_OPT_FPGA_FPGA_ID = 0x0300008100000000;  // R
        public const ulong LC_OPT_FPGA_VERSION_MAJOR = 0x0300008200000000;  // R
        public const ulong LC_OPT_FPGA_VERSION_MINOR = 0x0300008300000000;  // R
        public const ulong LC_OPT_FPGA_ALGO_TINY = 0x0300008400000000;  // RW - 1/0 use tiny 128-byte/tlp read algorithm.
        public const ulong LC_OPT_FPGA_ALGO_SYNCHRONOUS = 0x0300008500000000;  // RW - 1/0 use synchronous (old) read algorithm.
        public const ulong LC_OPT_FPGA_CFGSPACE_XILINX = 0x0300008600000000;  // RW - [lo-dword: register address in bytes] [bytes: 0-3: data, 4-7: byte_enable(if wr/set); top bit = cfg_mgmt_wr_rw1c_as_rw]
        public const ulong LC_OPT_FPGA_TLP_READ_CB_WITHINFO = 0x0300009000000000;  // RW - 1/0 call TLP read callback with additional string info in szInfo
        public const ulong LC_OPT_FPGA_TLP_READ_CB_FILTERCPL = 0x0300009100000000;  // RW - 1/0 call TLP read callback with memory read completions from read calls filtered

        public const ulong LC_CMD_FPGA_PCIECFGSPACE = 0x0000010300000000;  // R
        public const ulong LC_CMD_FPGA_CFGREGPCIE = 0x0000010400000000;  // RW - [lo-dword: register address]
        public const ulong LC_CMD_FPGA_CFGREGCFG = 0x0000010500000000;  // RW - [lo-dword: register address]
        public const ulong LC_CMD_FPGA_CFGREGDRP = 0x0000010600000000;  // RW - [lo-dword: register address]
        public const ulong LC_CMD_FPGA_CFGREGCFG_MARKWR = 0x0000010700000000;  // W  - write with mask [lo-dword: register address] [bytes: 0-1: data, 2-3: mask]
        public const ulong LC_CMD_FPGA_CFGREGPCIE_MARKWR = 0x0000010800000000;  // W  - write with mask [lo-dword: register address] [bytes: 0-1: data, 2-3: mask]
        public const ulong LC_CMD_FPGA_CFGREG_DEBUGPRINT = 0x0000010a00000000;  // N/A
        public const ulong LC_CMD_FPGA_PROBE = 0x0000010b00000000;  // RW
        public const ulong LC_CMD_FPGA_CFGSPACE_SHADOW_RD = 0x0000010c00000000;  // R
        public const ulong LC_CMD_FPGA_CFGSPACE_SHADOW_WR = 0x0000010d00000000;  // W  - [lo-dword: config space write base address]
        public const ulong LC_CMD_FPGA_TLP_WRITE_SINGLE = 0x0000011000000000;  // W  - write single tlp BYTE:s
        public const ulong LC_CMD_FPGA_TLP_WRITE_MULTIPLE = 0x0000011100000000;  // W  - write multiple LC_TLP:s
        public const ulong LC_CMD_FPGA_TLP_TOSTRING = 0x0000011200000000;  // RW - convert single TLP to LPSTR; *pcbDataOut includes NULL terminator.

        public const ulong LC_CMD_FPGA_TLP_CONTEXT = 0x2000011400000000;  // W - set/unset TLP user-defined context to be passed to callback function. (pbDataIn == LPVOID user context). [not remote].
        public const ulong LC_CMD_FPGA_TLP_CONTEXT_RD = 0x2000011b00000000;  // R - get TLP user-defined context to be passed to callback function. [not remote].
        public const ulong LC_CMD_FPGA_TLP_FUNCTION_CALLBACK = 0x2000011500000000;  // W - set/unset TLP callback function (pbDataIn == PLC_TLP_CALLBACK). [not remote].
        public const ulong LC_CMD_FPGA_TLP_FUNCTION_CALLBACK_RD = 0x2000011c00000000;  // R - get TLP callback function. [not remote].
        public const ulong LC_CMD_FPGA_BAR_CONTEXT = 0x2000011800000000;  // W - set/unset BAR user-defined context to be passed to callback function. (pbDataIn == LPVOID user context). [not remote].
        public const ulong LC_CMD_FPGA_BAR_CONTEXT_RD = 0x2000011d00000000;  // R - get BAR user-defined context to be passed to callback function. [not remote].
        public const ulong LC_CMD_FPGA_BAR_FUNCTION_CALLBACK = 0x2000011900000000;  // W - set/unset BAR callback function (pbDataIn == PLC_BAR_CALLBACK). [not remote].
        public const ulong LC_CMD_FPGA_BAR_FUNCTION_CALLBACK_RD = 0x2000011e00000000;  // R - get BAR callback function. [not remote].
        public const ulong LC_CMD_FPGA_BAR_INFO = 0x0000011a00000000;  // R - get BAR info (pbDataOut == LC_BAR_INFO[6]).

        public const ulong LC_CMD_FILE_DUMPHEADER_GET = 0x0000020100000000;  // R

        public const ulong LC_CMD_STATISTICS_GET = 0x4000010000000000;  // R
        public const ulong LC_CMD_MEMMAP_GET = 0x4000020000000000;  // R  - MEMMAP as LPSTR
        public const ulong LC_CMD_MEMMAP_SET = 0x4000030000000000;  // W  - MEMMAP as LPSTR
        public const ulong LC_CMD_MEMMAP_GET_STRUCT = 0x4000040000000000;  // R  - MEMMAP as LC_MEMMAP_ENTRY[]
        public const ulong LC_CMD_MEMMAP_SET_STRUCT = 0x4000050000000000;  // W  - MEMMAP as LC_MEMMAP_ENTRY[]

        public const ulong LC_CMD_AGENT_EXEC_PYTHON = 0x8000000100000000;  // RW - [lo-dword: optional timeout in ms]
        public const ulong LC_CMD_AGENT_EXIT_PROCESS = 0x8000000200000000;  //    - [lo-dword: process exit code]
        public const ulong LC_CMD_AGENT_VFS_LIST = 0x8000000300000000;  // RW
        public const ulong LC_CMD_AGENT_VFS_READ = 0x8000000400000000;  // RW
        public const ulong LC_CMD_AGENT_VFS_WRITE = 0x8000000500000000;  // RW
        public const ulong LC_CMD_AGENT_VFS_OPT_GET = 0x8000000600000000;  // RW
        public const ulong LC_CMD_AGENT_VFS_OPT_SET = 0x8000000700000000;  // RW
        public const ulong LC_CMD_AGENT_VFS_INITIALIZE = 0x8000000800000000;  // RW
        public const ulong LC_CMD_AGENT_VFS_CONSOLE = 0x8000000900000000;  // RW



        //---------------------------------------------------------------------
        // LEECHCORE: CORE FUNCTIONALITY BELOW:
        //---------------------------------------------------------------------

        public struct MEM_SCATTER
        {
            public bool f;
            public ulong qwA;
            public byte[] pb;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential, CharSet = CharSet.Ansi)]
        public struct LC_CONFIG
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

        public struct LC_CONFIG_ERRORINFO
        {
            public bool fValid;
            public bool fUserInputRequest;
            public string strUserText;
        }

        private bool disposed = false;
        private IntPtr hLC = IntPtr.Zero;

        // private zero-argument constructor - do not use!
        private LeechCore()
        {
        }

        private LeechCore(IntPtr hLC)
        {
            this.hLC = hLC;
        }

        // Factory method creating a new LeechCore object taking a LC_CONFIG structure
        // containing the configuration and optionally return a LC_CONFIG_ERRORINFO
        // structure containing any error.
        // Use this when you wish to gain greater control of creating LeechCore objects.
        public static unsafe LeechCore CreateFromConfig(ref LC_CONFIG pLcCreateConfig, out LC_CONFIG_ERRORINFO ConfigErrorInfo)
        {
            IntPtr pLcErrorInfo;
            int cbERROR_INFO = System.Runtime.InteropServices.Marshal.SizeOf<Lci.LC_CONFIG_ERRORINFO>();
            IntPtr hLC = Lci.LcCreateEx(ref pLcCreateConfig, out pLcErrorInfo);
            ConfigErrorInfo = new LC_CONFIG_ERRORINFO();
            ConfigErrorInfo.strUserText = "";
            if ((pLcErrorInfo != IntPtr.Zero) && (hLC != IntPtr.Zero))
            {
                return new LeechCore(hLC);
            }
            if (hLC != IntPtr.Zero)
            {
                Lci.LcClose(hLC);
            }
            if (pLcErrorInfo != IntPtr.Zero)
            {
                Lci.LC_CONFIG_ERRORINFO e = Marshal.PtrToStructure<Lci.LC_CONFIG_ERRORINFO>(pLcErrorInfo);
                if (e.dwVersion == LeechCore.LC_CONFIG_ERRORINFO_VERSION)
                {
                    ConfigErrorInfo.fValid = true;
                    ConfigErrorInfo.fUserInputRequest = e.fUserInputRequest;
                    if (e.cwszUserText > 0)
                    {
                        ConfigErrorInfo.strUserText = Marshal.PtrToStringUni((System.IntPtr)(pLcErrorInfo.ToInt64() + cbERROR_INFO));
                    }
                }
                Lci.LcMemFree(pLcErrorInfo);
            }
            return null;
        }

        public LeechCore(string strDevice)
        {
            LC_CONFIG cfg = new LC_CONFIG();
            cfg.dwVersion = LeechCore.LC_CONFIG_VERSION;
            cfg.szDevice = strDevice;
            IntPtr hLC = Lci.LcCreate(ref cfg);
            if (hLC == IntPtr.Zero)
            {
                throw new Exception("LeechCore: failed to create object.");
            }
            this.hLC = hLC;
        }

        public LeechCore(string strDevice, string strRemote, uint dwVerbosityFlags, ulong paMax)
        {
            LC_CONFIG cfg = new LC_CONFIG();
            cfg.dwVersion = LeechCore.LC_CONFIG_VERSION;
            cfg.szDevice = strDevice;
            cfg.szRemote = strRemote;
            cfg.dwPrintfVerbosity = dwVerbosityFlags;
            cfg.paMax = paMax;
            IntPtr hLC = Lci.LcCreate(ref cfg);
            if (hLC == IntPtr.Zero)
            {
                throw new Exception("LeechCore: failed to create object.");
            }
            this.hLC = hLC;
        }

        public LeechCore(Vmm vmm)
        {
            ulong pqwValue;
            if (!vmm.ConfigGet(Vmm.OPT_CORE_LEECHCORE_HANDLE, out pqwValue))
            {
                throw new Exception("LeechCore: failed retrieving handle from Vmm.");
            }
            string strDevice = string.Format("existing://0x{0:X}", pqwValue);
            LC_CONFIG cfg = new LC_CONFIG();
            cfg.dwVersion = LeechCore.LC_CONFIG_VERSION;
            cfg.szDevice = strDevice;
            IntPtr hLC = Lci.LcCreate(ref cfg);
            if (hLC == IntPtr.Zero)
            {
                throw new Exception("LeechCore: failed to create object.");
            }
            this.hLC = hLC;
        }

        ~LeechCore()
        {
            Dispose(disposing: false);
        }

        public void Dispose()
        {
            Dispose(disposing: true);
            GC.SuppressFinalize(this);
        }

        private void Dispose(bool disposing)
        {
            if (!this.disposed)
            {
                Lci.LcClose(hLC);
                hLC = IntPtr.Zero;
                disposed = true;
            }
        }

        public void Close()
        {
            Dispose(disposing: true);
        }



        //---------------------------------------------------------------------
        // LEECHCORE: GENERAL FUNCTIONALITY BELOW:
        //---------------------------------------------------------------------

        /// <summary>
        /// Read a single physical memory range.
        /// </summary>
        /// <param name="pa">Physical address to read.</param>
        /// <param name="cb">Number of bytes to read.</param>
        /// <returns>Bytes read.</returns>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public unsafe byte[] Read(ulong pa, uint cb) =>
            ReadArray<byte>(pa, cb);

        /// <summary>
        /// Read physcial memory into a single struct value <typeparamref name="T"/>.
        /// </summary>
        /// <typeparam name="T">Value Type.</typeparam>
        /// <param name="pa">Physical address to read.</param>
        /// <param name="result">Result value to populate</param>
        /// <returns>True if read successful, otherwise False.</returns>
        public unsafe bool ReadStruct<T>(ulong pa, out T result)
            where T : unmanaged
        {
            uint cb = (uint)sizeof(T);
            result = default;
            fixed (T* pb = &result)
            {
                if (!Lci.LcRead(hLC, pa, cb, (byte*)pb))
                    return false;
            }
            return true;
        }

        /// <summary>
        /// Read physical memory into an array of type <typeparamref name="T"/>.
        /// </summary>
        /// <typeparam name="T">Value Type.</typeparam>
        /// <param name="pa">Physical address to read.</param>
        /// <param name="count">Number of elements to read.</param>
        /// <returns>Managed Array of type <typeparamref name="T"/>. Null if read failed.</returns>
        public unsafe T[] ReadArray<T>(ulong pa, uint count)
            where T : unmanaged
        {
            uint cb = count * (uint)sizeof(T);
            T[] data = new T[count];
            fixed (T* pb = data)
            {
                bool result = Lci.LcRead(hLC, pa, cb, (byte*)pb);
                return result ? data : null;
            }
        }

        /// <summary>
        /// Read physical memory into unmanaged memory.
        /// </summary>
        /// <param name="pa">Physical address to read.</param>
        /// <param name="cb">Counte of bytes to read.</param>
        /// <param name="pb">Pointer to buffer to read into.</param>
        /// <returns>True if read successful, otherwise False.</returns>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public unsafe bool Read(ulong pa, uint cb, IntPtr pb) =>
            Read(pa, cb, pb.ToPointer());

        /// <summary>
        /// Read physical memory into unmanaged memory.
        /// </summary>
        /// <param name="pa">Physical address to read.</param>
        /// <param name="cb">Counte of bytes to read.</param>
        /// <param name="pb">Pointer to buffer to read into.</param>
        /// <returns>True if read successful, otherwise False.</returns>
        public unsafe bool Read(ulong pa, uint cb, void* pb)
        {
            if (!Lci.LcRead(hLC, pa, cb, (byte*)pb))
                return false;
            return true;
        }

        /// <summary>
        /// Read multiple page-sized physical memory ranges.
        /// </summary>
        /// <param name="pa">Array of multiple physical addresses to read.</param>
        /// <returns>An arary of MEM_SCATTER containing the page-sized results of the reads.</returns>
        public MEM_SCATTER[] ReadScatter(params ulong[] pas)
        {
            int i;
            long vappMEMs, vapMEM;
            IntPtr pMEM, pMEM_qwA, pppMEMs;
            if (!Lci.LcAllocScatter1((uint)pas.Length, out pppMEMs))
            {
                return null;
            }
            vappMEMs = pppMEMs.ToInt64();
            for (i = 0; i < pas.Length; i++)
            {
                vapMEM = Marshal.ReadIntPtr(new IntPtr(vappMEMs + i * 8)).ToInt64();
                pMEM_qwA = new IntPtr(vapMEM + 8);
                Marshal.WriteInt64(pMEM_qwA, (long)(pas[i] & ~(ulong)0xfff));
            }
            MEM_SCATTER[] MEMs = new MEM_SCATTER[pas.Length];
            Lci.LcReadScatter(hLC, (uint)MEMs.Length, pppMEMs);
            for (i = 0; i < MEMs.Length; i++)
            {
                pMEM = Marshal.ReadIntPtr(new IntPtr(vappMEMs + i * 8));
                Lci.LC_MEM_SCATTER n = Marshal.PtrToStructure<Lci.LC_MEM_SCATTER>(pMEM);
                MEMs[i].f = n.f;
                MEMs[i].qwA = n.qwA;
                MEMs[i].pb = new byte[0x1000];
                Marshal.Copy(n.pb, MEMs[i].pb, 0, 0x1000);
            }
            Lci.LcMemFree(pppMEMs);
            return MEMs;
        }

        /// <summary>
        /// Write a single range of physical memory.
        /// </summary>
        /// <param name="pa">Physical address to write</param>
        /// <param name="data">Data to write starting at pa.</param>
        /// <returns>True if write successful, otherwise False. The write is best-effort and may fail. It's recommended to verify the write with a subsequent read.</returns>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public unsafe bool Write(ulong pa, byte[] data) =>
            WriteArray<byte>(pa, data);

        /// <summary>
        /// Write a single struct <typeparamref name="T"/> into physical memory.
        /// </summary>
        /// <typeparam name="T">Value Type.</typeparam>
        /// <param name="pa">Physical address to write</param>
        /// <param name="value"><typeparamref name="T"/> value to write.</param>
        /// <returns>True if write successful, otherwise False. The write is best-effort and may fail. It's recommended to verify the write with a subsequent read.</returns>
        public unsafe bool WriteStruct<T>(ulong pa, T value)
            where T : unmanaged
        {
            uint cb = (uint)sizeof(T);
            byte* pb = (byte*)&value;
            return Lci.LcWrite(hLC, pa, cb, pb);
        }

        /// <summary>
        /// Write a managed <typeparamref name="T"/> array into physical memory.
        /// </summary>
        /// <typeparam name="T">Value Type.</typeparam>
        /// <param name="pa">Physical address to write</param>
        /// <param name="data">Managed <typeparamref name="T"/> array to write.</param>
        /// <returns>True if write successful, otherwise False. The write is best-effort and may fail. It's recommended to verify the write with a subsequent read.</returns>
        public unsafe bool WriteArray<T>(ulong pa, T[] data)
            where T : unmanaged
        {
            uint cb = (uint)sizeof(T) * (uint)data.Length;
            fixed (T* pb = data)
            {
                return Lci.LcWrite(hLC, pa, cb, (byte*)pb);
            }
        }

        /// <summary>
        /// Write from unmanaged memory into physical memory.
        /// </summary>
        /// <param name="pa">Physical address to write</param>
        /// <param name="cb">Count of bytes to write.</param>
        /// <param name="pb">Pointer to buffer to write from.</param>
        /// <returns>True if write successful, otherwise False. The write is best-effort and may fail. It's recommended to verify the write with a subsequent read.</returns>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public unsafe bool Write(ulong pa, uint cb, IntPtr pb) =>
            Write(pa, cb, pb.ToPointer());

        /// <summary>
        /// Write from unmanaged memory into physical memory.
        /// </summary>
        /// <param name="pa">Physical address to write</param>
        /// <param name="cb">Count of bytes to write.</param>
        /// <param name="pb">Pointer to buffer to write from.</param>
        /// <returns>True if write successful, otherwise False. The write is best-effort and may fail. It's recommended to verify the write with a subsequent read.</returns>
        public unsafe bool Write(ulong pa, uint cb, void* pb)
        {
            return Lci.LcWrite(hLC, pa, cb, (byte*)pb);
        }

        /// <summary>
        /// Write multiple page-sized physical memory ranges. The write is best-effort and may fail. It's recommended to verify the writes with subsequent reads.
        /// </summary>
        /// <param name="MEMs">MEMs containing the memory addresses and data to write.</param>
        public void WriteScatter(ref MEM_SCATTER[] MEMs)
        {
            int i;
            long vappMEMs, vapMEM;
            IntPtr pMEM, pMEM_f, pMEM_qwA, pMEM_pb, pppMEMs;
            for (i = 0; i < MEMs.Length; i++)
            {
                if ((MEMs[i].pb == null) || (MEMs[i].pb.Length != 0x1000))
                {
                    return;
                }
            }
            if (!Lci.LcAllocScatter1((uint)MEMs.Length, out pppMEMs))
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
            Lci.LcWriteScatter(hLC, (uint)MEMs.Length, pppMEMs);
            for (i = 0; i < MEMs.Length; i++)
            {
                pMEM = Marshal.ReadIntPtr(new IntPtr(vappMEMs + i * 8));
                Lci.LC_MEM_SCATTER n = Marshal.PtrToStructure<Lci.LC_MEM_SCATTER>(pMEM);
                MEMs[i].f = n.f;
                MEMs[i].qwA = n.qwA;
            }
            Lci.LcMemFree(pppMEMs);
        }

        /// <summary>
        /// Retrieve a LeechCore option value.
        /// </summary>
        /// <param name="fOption">Parameter LeechCore.LC_OPT_*</param>
        /// <param name="pqwValue">The option value retrieved.</param>
        /// <returns></returns>
        public bool GetOption(ulong fOption, out ulong pqwValue)
        {
            return Lci.GetOption(hLC, fOption, out pqwValue);
        }

        /// <summary>
        /// Set a LeechCore option value.
        /// </summary>
        /// <param name="fOption">Parameter LeechCore.LC_OPT_*</param>
        /// <param name="qwValue">The option value to set.</param>
        /// <returns></returns>
        public bool SetOption(ulong fOption, ulong qwValue)
        {
            return Lci.SetOption(hLC, fOption, qwValue);
        }

        /// <summary>
        /// Send a command to LeechCore.
        /// </summary>
        /// <param name="fOption">Parameter LeechCore.LC_CMD_*</param>
        /// <param name="DataIn">The data to set (or null).</param>
        /// <param name="DataOut">The data retrieved.</param>
        /// <returns></returns>
        public bool Command(ulong fOption, byte[] DataIn, out byte[] DataOut)
        {
            unsafe
            {
                bool result;
                uint cbDataOut;
                IntPtr PtrDataOut;
                DataOut = null;
                if (DataIn == null)
                {
                    result = Lci.LcCommand(hLC, fOption, 0, null, out PtrDataOut, out cbDataOut);
                }
                else
                {
                    fixed (byte* pbDataIn = DataIn)
                    {
                        result = Lci.LcCommand(hLC, fOption, (uint)DataIn.Length, pbDataIn, out PtrDataOut, out cbDataOut);
                    }
                }
                if (!result) { return false; }
                DataOut = new byte[cbDataOut];
                if (cbDataOut > 0)
                {
                    Marshal.Copy(PtrDataOut, DataOut, 0, (int)cbDataOut);
                    Lci.LcMemFree(PtrDataOut);
                }
                return true;
            }
        }

        /// <summary>
        /// Retrieve the memory map currently in use by LeechCore.
        /// </summary>
        /// <returns>The memory map (or null on failure).</returns>
        public string GetMemMap()
        {
            byte[] bMemMap;
            if (this.Command(LeechCore.LC_CMD_MEMMAP_GET, null, out bMemMap) && (bMemMap.Length > 0))
            {
                return System.Text.Encoding.UTF8.GetString(bMemMap);
            }
            return null;
        }

        /// <summary>
        /// Set the memory map for LeechCore to use.
        /// </summary>
        /// <param name="sMemMap">The memory map to set.</param>
        /// <returns></returns>
        public bool SetMemMap(string sMemMap)
        {
            return this.Command(LeechCore.LC_CMD_MEMMAP_SET, System.Text.Encoding.UTF8.GetBytes(sMemMap), out byte[] bMemMap);
        }
    }
}
