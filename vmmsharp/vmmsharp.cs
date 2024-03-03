using System;
using System.Text;
using System.Runtime.InteropServices;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.CompilerServices;

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
namespace vmmsharp
{
    public struct MEM_SCATTER
    {
        public bool f;
        public ulong qwA;
        public byte[] pb;
    }

    // LeechCore public API:
    public sealed class LeechCore : IDisposable
    {
        //---------------------------------------------------------------------
        // LEECHCORE: PUBLIC API CONSTANTS BELOW:
        //---------------------------------------------------------------------
        public const uint LC_CONFIG_VERSION =                   0xc0fd0002;
        public const uint LC_CONFIG_ERRORINFO_VERSION =         0xc0fe0002;

        public const uint LC_CONFIG_PRINTF_ENABLED =            0x01;
        public const uint LC_CONFIG_PRINTF_V =                  0x02;
        public const uint LC_CONFIG_PRINTF_VV =                 0x04;
        public const uint LC_CONFIG_PRINTF_VVV =                0x08;

        public const ulong LC_OPT_CORE_PRINTF_ENABLE =          0x4000000100000000;  // RW
        public const ulong LC_OPT_CORE_VERBOSE =                0x4000000200000000;  // RW
        public const ulong LC_OPT_CORE_VERBOSE_EXTRA =          0x4000000300000000;  // RW
        public const ulong LC_OPT_CORE_VERBOSE_EXTRA_TLP =      0x4000000400000000;  // RW
        public const ulong LC_OPT_CORE_VERSION_MAJOR =          0x4000000500000000;  // R
        public const ulong LC_OPT_CORE_VERSION_MINOR =          0x4000000600000000;  // R
        public const ulong LC_OPT_CORE_VERSION_REVISION =       0x4000000700000000;  // R
        public const ulong LC_OPT_CORE_ADDR_MAX =               0x1000000800000000;  // R
        public const ulong LC_OPT_CORE_STATISTICS_CALL_COUNT =  0x4000000900000000;  // R [lo-dword: LC_STATISTICS_ID_*]
        public const ulong LC_OPT_CORE_STATISTICS_CALL_TIME =   0x4000000a00000000;  // R [lo-dword: LC_STATISTICS_ID_*]
        public const ulong LC_OPT_CORE_VOLATILE =               0x1000000b00000000;  // R
        public const ulong LC_OPT_CORE_READONLY =               0x1000000c00000000;  // R

        public const ulong LC_OPT_MEMORYINFO_VALID =            0x0200000100000000;  // R
        public const ulong LC_OPT_MEMORYINFO_FLAG_32BIT =       0x0200000300000000;  // R
        public const ulong LC_OPT_MEMORYINFO_FLAG_PAE =         0x0200000400000000;  // R
        public const ulong LC_OPT_MEMORYINFO_ARCH =             0x0200001200000000;  // R - LC_ARCH_TP
        public const ulong LC_OPT_MEMORYINFO_OS_VERSION_MINOR = 0x0200000500000000;  // R
        public const ulong LC_OPT_MEMORYINFO_OS_VERSION_MAJOR = 0x0200000600000000;  // R
        public const ulong LC_OPT_MEMORYINFO_OS_DTB =           0x0200000700000000;  // R
        public const ulong LC_OPT_MEMORYINFO_OS_PFN =           0x0200000800000000;  // R
        public const ulong LC_OPT_MEMORYINFO_OS_PsLoadedModuleList = 0x0200000900000000;  // R
        public const ulong LC_OPT_MEMORYINFO_OS_PsActiveProcessHead = 0x0200000a00000000;  // R
        public const ulong LC_OPT_MEMORYINFO_OS_MACHINE_IMAGE_TP = 0x0200000b00000000;  // R
        public const ulong LC_OPT_MEMORYINFO_OS_NUM_PROCESSORS = 0x0200000c00000000;  // R
        public const ulong LC_OPT_MEMORYINFO_OS_SYSTEMTIME =    0x0200000d00000000;  // R
        public const ulong LC_OPT_MEMORYINFO_OS_UPTIME =        0x0200000e00000000;  // R
        public const ulong LC_OPT_MEMORYINFO_OS_KERNELBASE =    0x0200000f00000000;  // R
        public const ulong LC_OPT_MEMORYINFO_OS_KERNELHINT =    0x0200001000000000;  // R
        public const ulong LC_OPT_MEMORYINFO_OS_KdDebuggerDataBlock = 0x0200001100000000;  // R

        public const ulong LC_OPT_FPGA_PROBE_MAXPAGES =         0x0300000100000000;  // RW
        public const ulong LC_OPT_FPGA_MAX_SIZE_RX =            0x0300000300000000;  // RW
        public const ulong LC_OPT_FPGA_MAX_SIZE_TX =            0x0300000400000000;  // RW
        public const ulong LC_OPT_FPGA_DELAY_PROBE_READ =       0x0300000500000000;  // RW - uS
        public const ulong LC_OPT_FPGA_DELAY_PROBE_WRITE =      0x0300000600000000;  // RW - uS
        public const ulong LC_OPT_FPGA_DELAY_WRITE =            0x0300000700000000;  // RW - uS
        public const ulong LC_OPT_FPGA_DELAY_READ =             0x0300000800000000;  // RW - uS
        public const ulong LC_OPT_FPGA_RETRY_ON_ERROR =         0x0300000900000000;  // RW
        public const ulong LC_OPT_FPGA_DEVICE_ID =              0x0300008000000000;  // RW - bus:dev:fn (ex: 04:00.0 === 0x0400).
        public const ulong LC_OPT_FPGA_FPGA_ID =                0x0300008100000000;  // R
        public const ulong LC_OPT_FPGA_VERSION_MAJOR =          0x0300008200000000;  // R
        public const ulong LC_OPT_FPGA_VERSION_MINOR =          0x0300008300000000;  // R
        public const ulong LC_OPT_FPGA_ALGO_TINY =              0x0300008400000000;  // RW - 1/0 use tiny 128-byte/tlp read algorithm.
        public const ulong LC_OPT_FPGA_ALGO_SYNCHRONOUS =       0x0300008500000000;  // RW - 1/0 use synchronous (old) read algorithm.
        public const ulong LC_OPT_FPGA_CFGSPACE_XILINX =        0x0300008600000000;  // RW - [lo-dword: register address in bytes] [bytes: 0-3: data, 4-7: byte_enable(if wr/set); top bit = cfg_mgmt_wr_rw1c_as_rw]
        public const ulong LC_OPT_FPGA_TLP_READ_CB_WITHINFO =   0x0300009000000000;  // RW - 1/0 call TLP read callback with additional string info in szInfo
        public const ulong LC_OPT_FPGA_TLP_READ_CB_FILTERCPL =  0x0300009100000000;  // RW - 1/0 call TLP read callback with memory read completions from read calls filtered

        public const ulong LC_CMD_FPGA_PCIECFGSPACE =           0x0000010300000000;  // R
        public const ulong LC_CMD_FPGA_CFGREGPCIE =             0x0000010400000000;  // RW - [lo-dword: register address]
        public const ulong LC_CMD_FPGA_CFGREGCFG =              0x0000010500000000;  // RW - [lo-dword: register address]
        public const ulong LC_CMD_FPGA_CFGREGDRP =              0x0000010600000000;  // RW - [lo-dword: register address]
        public const ulong LC_CMD_FPGA_CFGREGCFG_MARKWR =       0x0000010700000000;  // W  - write with mask [lo-dword: register address] [bytes: 0-1: data, 2-3: mask]
        public const ulong LC_CMD_FPGA_CFGREGPCIE_MARKWR =      0x0000010800000000;  // W  - write with mask [lo-dword: register address] [bytes: 0-1: data, 2-3: mask]
        public const ulong LC_CMD_FPGA_CFGREG_DEBUGPRINT =      0x0000010a00000000;  // N/A
        public const ulong LC_CMD_FPGA_PROBE =                  0x0000010b00000000;  // RW
        public const ulong LC_CMD_FPGA_CFGSPACE_SHADOW_RD =     0x0000010c00000000;  // R
        public const ulong LC_CMD_FPGA_CFGSPACE_SHADOW_WR =     0x0000010d00000000;  // W  - [lo-dword: config space write base address]
        public const ulong LC_CMD_FPGA_TLP_WRITE_SINGLE =       0x0000011000000000;  // W  - write single tlp BYTE:s
        public const ulong LC_CMD_FPGA_TLP_WRITE_MULTIPLE =     0x0000011100000000;  // W  - write multiple LC_TLP:s
        public const ulong LC_CMD_FPGA_TLP_TOSTRING =           0x0000011200000000;  // RW - convert single TLP to LPSTR; *pcbDataOut includes NULL terminator.

        public const ulong LC_CMD_FPGA_TLP_CONTEXT =            0x2000011400000000;  // W - set/unset TLP user-defined context to be passed to callback function. (pbDataIn == LPVOID user context). [not remote].
        public const ulong LC_CMD_FPGA_TLP_CONTEXT_RD =         0x2000011b00000000;  // R - get TLP user-defined context to be passed to callback function. [not remote].
        public const ulong LC_CMD_FPGA_TLP_FUNCTION_CALLBACK =  0x2000011500000000;  // W - set/unset TLP callback function (pbDataIn == PLC_TLP_CALLBACK). [not remote].
        public const ulong LC_CMD_FPGA_TLP_FUNCTION_CALLBACK_RD = 0x2000011c00000000;  // R - get TLP callback function. [not remote].
        public const ulong LC_CMD_FPGA_BAR_CONTEXT =            0x2000011800000000;  // W - set/unset BAR user-defined context to be passed to callback function. (pbDataIn == LPVOID user context). [not remote].
        public const ulong LC_CMD_FPGA_BAR_CONTEXT_RD =         0x2000011d00000000;  // R - get BAR user-defined context to be passed to callback function. [not remote].
        public const ulong LC_CMD_FPGA_BAR_FUNCTION_CALLBACK =  0x2000011900000000;  // W - set/unset BAR callback function (pbDataIn == PLC_BAR_CALLBACK). [not remote].
        public const ulong LC_CMD_FPGA_BAR_FUNCTION_CALLBACK_RD = 0x2000011e00000000;  // R - get BAR callback function. [not remote].
        public const ulong LC_CMD_FPGA_BAR_INFO =               0x0000011a00000000;  // R - get BAR info (pbDataOut == LC_BAR_INFO[6]).

        public const ulong LC_CMD_FILE_DUMPHEADER_GET =         0x0000020100000000;  // R

        public const ulong LC_CMD_STATISTICS_GET =              0x4000010000000000;  // R
        public const ulong LC_CMD_MEMMAP_GET =                  0x4000020000000000;  // R  - MEMMAP as LPSTR
        public const ulong LC_CMD_MEMMAP_SET =                  0x4000030000000000;  // W  - MEMMAP as LPSTR
        public const ulong LC_CMD_MEMMAP_GET_STRUCT =           0x4000040000000000;  // R  - MEMMAP as LC_MEMMAP_ENTRY[]
        public const ulong LC_CMD_MEMMAP_SET_STRUCT =           0x4000050000000000;  // W  - MEMMAP as LC_MEMMAP_ENTRY[]

        public const ulong LC_CMD_AGENT_EXEC_PYTHON =           0x8000000100000000;  // RW - [lo-dword: optional timeout in ms]
        public const ulong LC_CMD_AGENT_EXIT_PROCESS =          0x8000000200000000;  //    - [lo-dword: process exit code]
        public const ulong LC_CMD_AGENT_VFS_LIST =              0x8000000300000000;  // RW
        public const ulong LC_CMD_AGENT_VFS_READ =              0x8000000400000000;  // RW
        public const ulong LC_CMD_AGENT_VFS_WRITE =             0x8000000500000000;  // RW
        public const ulong LC_CMD_AGENT_VFS_OPT_GET =           0x8000000600000000;  // RW
        public const ulong LC_CMD_AGENT_VFS_OPT_SET =           0x8000000700000000;  // RW
        public const ulong LC_CMD_AGENT_VFS_INITIALIZE =        0x8000000800000000;  // RW
        public const ulong LC_CMD_AGENT_VFS_CONSOLE =           0x8000000900000000;  // RW



        //---------------------------------------------------------------------
        // LEECHCORE: CORE FUNCTIONALITY BELOW:
        //---------------------------------------------------------------------

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
            int cbERROR_INFO = System.Runtime.InteropServices.Marshal.SizeOf<lci.LC_CONFIG_ERRORINFO>();
            IntPtr hLC = lci.LcCreateEx(ref pLcCreateConfig, out pLcErrorInfo);
            ConfigErrorInfo = new LC_CONFIG_ERRORINFO();
            ConfigErrorInfo.strUserText = "";
            if ((pLcErrorInfo != IntPtr.Zero) && (hLC != IntPtr.Zero))
            {
                return new LeechCore(hLC);
            }
            if(hLC != IntPtr.Zero)
            {
                lci.LcClose(hLC);
            }
            if (pLcErrorInfo != IntPtr.Zero)
            {
                lci.LC_CONFIG_ERRORINFO e = Marshal.PtrToStructure<lci.LC_CONFIG_ERRORINFO>(pLcErrorInfo);
                if (e.dwVersion == LeechCore.LC_CONFIG_ERRORINFO_VERSION)
                {
                    ConfigErrorInfo.fValid = true;
                    ConfigErrorInfo.fUserInputRequest = e.fUserInputRequest;
                    if (e.cwszUserText > 0)
                    {
                        ConfigErrorInfo.strUserText = Marshal.PtrToStringUni((System.IntPtr)(pLcErrorInfo.ToInt64() + cbERROR_INFO));
                    }
                }
                lci.LcMemFree(pLcErrorInfo);
            }
            return null;
        }

        public LeechCore(string strDevice)
        {
            LC_CONFIG cfg = new LC_CONFIG();
            cfg.dwVersion = LeechCore.LC_CONFIG_VERSION;
            cfg.szDevice = strDevice;
            IntPtr hLC = lci.LcCreate(ref cfg);
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
            IntPtr hLC = lci.LcCreate(ref cfg);
            if(hLC == IntPtr.Zero)
            {
                throw new Exception("LeechCore: failed to create object.");
            }
            this.hLC = hLC;
        }

        public LeechCore(Vmm vmm)
        {
            ulong pqwValue;
            if (!vmm.ConfigGet(Vmm.OPT_CORE_LEECHCORE_HANDLE, out pqwValue)) {
                throw new Exception("LeechCore: failed retrieving handle from Vmm.");
            }
            string strDevice = string.Format("existing://0x{0:X}", pqwValue);
            LC_CONFIG cfg = new LC_CONFIG();
            cfg.dwVersion = LeechCore.LC_CONFIG_VERSION;
            cfg.szDevice = strDevice;
            IntPtr hLC = lci.LcCreate(ref cfg);
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
                lci.LcClose(hLC);
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
                if (!lci.LcRead(hLC, pa, cb, (byte*)pb))
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
                bool result = lci.LcRead(hLC, pa, cb, (byte*)pb);
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
            if (!lci.LcRead(hLC, pa, cb, (byte*)pb))
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
            if (!lci.LcAllocScatter1((uint)pas.Length, out pppMEMs))
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
            return lci.LcWrite(hLC, pa, cb, pb);
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
                return lci.LcWrite(hLC, pa, cb, (byte*)pb);
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
            return lci.LcWrite(hLC, pa, cb, (byte*)pb);
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

        /// <summary>
        /// Retrieve a LeechCore option value.
        /// </summary>
        /// <param name="fOption">Parameter LeechCore.LC_OPT_*</param>
        /// <param name="pqwValue">The option value retrieved.</param>
        /// <returns></returns>
        public bool GetOption(ulong fOption, out ulong pqwValue)
        {
            return lci.GetOption(hLC, fOption, out pqwValue);
        }

        /// <summary>
        /// Set a LeechCore option value.
        /// </summary>
        /// <param name="fOption">Parameter LeechCore.LC_OPT_*</param>
        /// <param name="qwValue">The option value to set.</param>
        /// <returns></returns>
        public bool SetOption(ulong fOption, ulong qwValue)
        {
            return lci.SetOption(hLC, fOption, qwValue);
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
                    result = lci.LcCommand(hLC, fOption, 0, null, out PtrDataOut, out cbDataOut);
                }
                else
                {
                    fixed (byte* pbDataIn = DataIn)
                    {
                        result = lci.LcCommand(hLC, fOption, (uint)DataIn.Length, pbDataIn, out PtrDataOut, out cbDataOut);
                    }
                }
                if (!result) { return false; }
                DataOut = new byte[cbDataOut];
                if (cbDataOut > 0)
                {
                    Marshal.Copy(PtrDataOut, DataOut, 0, (int)cbDataOut);
                    lci.LcMemFree(PtrDataOut);
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
            if(this.Command(LeechCore.LC_CMD_MEMMAP_GET, null, out bMemMap) && (bMemMap.Length > 0))
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



    // MemProcFS public API:
    public sealed class Vmm : IDisposable
    {
        //---------------------------------------------------------------------
        // CORE FUNCTIONALITY BELOW:
        //---------------------------------------------------------------------

        public const ulong OPT_CORE_PRINTF_ENABLE =             0x4000000100000000;  // RW
        public const ulong OPT_CORE_VERBOSE =                   0x4000000200000000;  // RW
        public const ulong OPT_CORE_VERBOSE_EXTRA =             0x4000000300000000;  // RW
        public const ulong OPT_CORE_VERBOSE_EXTRA_TLP =         0x4000000400000000;  // RW
        public const ulong OPT_CORE_MAX_NATIVE_ADDRESS =        0x4000000800000000;  // R
        public const ulong OPT_CORE_LEECHCORE_HANDLE =          0x4000001000000000;  // R - underlying leechcore handle (do not close).

        public const ulong OPT_CORE_SYSTEM =                    0x2000000100000000;  // R
        public const ulong OPT_CORE_MEMORYMODEL =               0x2000000200000000;  // R

        public const ulong OPT_CONFIG_IS_REFRESH_ENABLED =      0x2000000300000000;  // R - 1/0
        public const ulong OPT_CONFIG_TICK_PERIOD =             0x2000000400000000;  // RW - base tick period in ms
        public const ulong OPT_CONFIG_READCACHE_TICKS =         0x2000000500000000;  // RW - memory cache validity period (in ticks)
        public const ulong OPT_CONFIG_TLBCACHE_TICKS =          0x2000000600000000;  // RW - page table (tlb) cache validity period (in ticks)
        public const ulong OPT_CONFIG_PROCCACHE_TICKS_PARTIAL = 0x2000000700000000;  // RW - process refresh (partial) period (in ticks)
        public const ulong OPT_CONFIG_PROCCACHE_TICKS_TOTAL =   0x2000000800000000;  // RW - process refresh (full) period (in ticks)
        public const ulong OPT_CONFIG_VMM_VERSION_MAJOR =       0x2000000900000000;  // R
        public const ulong OPT_CONFIG_VMM_VERSION_MINOR =       0x2000000A00000000;  // R
        public const ulong OPT_CONFIG_VMM_VERSION_REVISION =    0x2000000B00000000;  // R
        public const ulong OPT_CONFIG_STATISTICS_FUNCTIONCALL = 0x2000000C00000000;  // RW - enable function call statistics (.status/statistics_fncall file)
        public const ulong OPT_CONFIG_IS_PAGING_ENABLED =       0x2000000D00000000;  // RW - 1/0
        public const ulong OPT_CONFIG_DEBUG =                   0x2000000E00000000;  // W
        public const ulong OPT_CONFIG_YARA_RULES =              0x2000000F00000000;  // R

        public const ulong OPT_WIN_VERSION_MAJOR =              0x2000010100000000;  // R
        public const ulong OPT_WIN_VERSION_MINOR =              0x2000010200000000;  // R
        public const ulong OPT_WIN_VERSION_BUILD =              0x2000010300000000;  // R
        public const ulong OPT_WIN_SYSTEM_UNIQUE_ID =           0x2000010400000000;  // R

        public const ulong OPT_FORENSIC_MODE =                  0x2000020100000000;  // RW - enable/retrieve forensic mode type [0-4].

        // REFRESH OPTIONS:
        public const ulong OPT_REFRESH_ALL =                    0x2001ffff00000000;  // W - refresh all caches
        public const ulong OPT_REFRESH_FREQ_MEM =               0x2001100000000000;  // W - refresh memory cache (excl. TLB) [fully]
        public const ulong OPT_REFRESH_FREQ_MEM_PARTIAL =       0x2001000200000000;  // W - refresh memory cache (excl. TLB) [partial 33%/call]
        public const ulong OPT_REFRESH_FREQ_TLB =               0x2001080000000000;  // W - refresh page table (TLB) cache [fully]
        public const ulong OPT_REFRESH_FREQ_TLB_PARTIAL =       0x2001000400000000;  // W - refresh page table (TLB) cache [partial 33%/call]
        public const ulong OPT_REFRESH_FREQ_FAST =              0x2001040000000000;  // W - refresh fast frequency - incl. partial process refresh
        public const ulong OPT_REFRESH_FREQ_MEDIUM =            0x2001000100000000;  // W - refresh medium frequency - incl. full process refresh
        public const ulong OPT_REFRESH_FREQ_SLOW =              0x2001001000000000;  // W - refresh slow frequency.

        // PROCESS OPTIONS: [LO-DWORD: Process PID]
        public const ulong OPT_PROCESS_DTB = 0x2002000100000000;  // W - force set process directory table base.

        public enum MEMORYMODEL_TP
        {
            MEMORYMODEL_NA = 0,
            MEMORYMODEL_X86 = 1,
            MEMORYMODEL_X86PAE = 2,
            MEMORYMODEL_X64 = 3,
            MEMORYMODEL_ARM64 = 4
        }

        public enum SYSTEM_TP
        {
            SYSTEM_UNKNOWN_X64 = 1,
            SYSTEM_WINDOWS_X64 = 2,
            SYSTEM_UNKNOWN_X86 = 3,
            SYSTEM_WINDOWS_X86 = 4
        }

        private bool disposed = false;
        private IntPtr hVMM = IntPtr.Zero;

        // private zero-argument constructor - do not use!
        private Vmm()
        {
        }

        private static unsafe IntPtr Initialize(out LeechCore.LC_CONFIG_ERRORINFO ConfigErrorInfo, params string[] args)
        {
            IntPtr pLcErrorInfo;
            int cbERROR_INFO = System.Runtime.InteropServices.Marshal.SizeOf<lci.LC_CONFIG_ERRORINFO>();
            IntPtr hVMM = vmmi.VMMDLL_InitializeEx(args.Length, args, out pLcErrorInfo);
            long vaLcCreateErrorInfo = pLcErrorInfo.ToInt64();
            ConfigErrorInfo = new LeechCore.LC_CONFIG_ERRORINFO();
            ConfigErrorInfo.strUserText = "";
            if (hVMM.ToInt64() == 0)
            {
                throw new Exception("VMM INIT FAILED.");
            }
            if (vaLcCreateErrorInfo == 0)
            {
                return hVMM;
            }
            lci.LC_CONFIG_ERRORINFO e = Marshal.PtrToStructure<lci.LC_CONFIG_ERRORINFO>(pLcErrorInfo);
            if (e.dwVersion == LeechCore.LC_CONFIG_ERRORINFO_VERSION)
            {
                ConfigErrorInfo.fValid = true;
                ConfigErrorInfo.fUserInputRequest = e.fUserInputRequest;
                if (e.cwszUserText > 0)
                {
                    ConfigErrorInfo.strUserText = Marshal.PtrToStringUni((System.IntPtr)(vaLcCreateErrorInfo + cbERROR_INFO));
                }
            }
            lci.LcMemFree(pLcErrorInfo);
            return hVMM;
        }

        public Vmm(out LeechCore.LC_CONFIG_ERRORINFO ConfigErrorInfo, params string[] args)
        {
            this.hVMM = Vmm.Initialize(out ConfigErrorInfo, args);
        }

        public Vmm(params string[] args)
        {
            LeechCore.LC_CONFIG_ERRORINFO ErrorInfo;
            this.hVMM = Vmm.Initialize(out ErrorInfo, args);
        }

        ~Vmm()
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
                vmmi.VMMDLL_Close(hVMM);
                hVMM = IntPtr.Zero;
                disposed = true;
            }
        }

        public void Close()
        {
            Dispose(disposing: true);
        }

        public static void CloseAll()
        {
            vmmi.VMMDLL_CloseAll();
        }

        public bool ConfigGet(ulong fOption, out ulong pqwValue)
        {
            return vmmi.VMMDLL_ConfigGet(hVMM, fOption, out pqwValue);
        }

        public bool ConfigSet(ulong fOption, ulong qwValue)
        {
            return vmmi.VMMDLL_ConfigSet(hVMM, fOption, qwValue);
        }

        /// <summary>
        /// Returns current Memory Map in string format.
        /// </summary>
        /// <returns>Memory Map, NULL if failed.</returns>
        public string GetMemoryMap()
        {
            var map = Map_GetPhysMem();
            if (map.Length == 0)
                return null;
            var sb = new StringBuilder();
            int leftLength = map.Max(x => x.pa).ToString("x").Length;
            for (int i = 0; i < map.Length; i++)
            {
                sb.AppendFormat($"{{0,{-leftLength}}}", map[i].pa.ToString("x"))
                    .Append($" - {(map[i].pa + map[i].cb - 1).ToString("x")}")
                    .AppendLine();
            }
            return sb.ToString();
        }

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

        public bool VfsList(string wszPath, ulong h, VfsCallBack_AddFile CallbackFile, VfsCallBack_AddDirectory CallbackDirectory)
        {
            vmmi.VMMDLL_VFS_FILELIST FileList;
            FileList.dwVersion = vmmi.VMMDLL_VFS_FILELIST_VERSION;
            FileList.h = h;
            FileList._Reserved = 0;
            FileList.pfnAddFile = Marshal.GetFunctionPointerForDelegate(CallbackFile);
            FileList.pfnAddDirectory = Marshal.GetFunctionPointerForDelegate(CallbackDirectory);
            return vmmi.VMMDLL_VfsList(hVMM, wszPath, ref FileList);
        }

        public unsafe uint VfsRead(string wszFileName, uint cb, ulong cbOffset, out byte[] pbData)
        {
            uint nt, cbRead = 0;
            byte[] data = new byte[cb];
            fixed (byte* pb = data)
            {
                nt = vmmi.VMMDLL_VfsRead(hVMM, wszFileName, pb, cb, out cbRead, cbOffset);
                pbData = new byte[cbRead];
                if (cbRead > 0)
                {
                    Buffer.BlockCopy(data, 0, pbData, 0, (int)cbRead);
                }
                return nt;
            }
        }

        public unsafe uint VfsWrite(string wszFileName, byte[] pbData, ulong cbOffset)
        {
            uint cbRead = 0;
            fixed (byte* pb = pbData)
            {
                return vmmi.VMMDLL_VfsWrite(hVMM, wszFileName, pb, (uint)pbData.Length, out cbRead, cbOffset);
            }
        }



        //---------------------------------------------------------------------
        // PLUGIN FUNCTIONALITY BELOW:
        //---------------------------------------------------------------------

        public bool InitializePlugins()
        {
            return vmmi.VMMDLL_InitializePlugins(hVMM);
        }



        //---------------------------------------------------------------------
        // MEMORY READ/WRITE FUNCTIONALITY BELOW:
        //---------------------------------------------------------------------

        public const uint PID_PROCESS_WITH_KERNELMEMORY = 0x80000000;      // Combine with dwPID to enable process kernel memory (NB! use with extreme care).

        public const uint FLAG_NOCACHE = 0x0001;  // do not use the data cache (force reading from memory acquisition device)
        public const uint FLAG_ZEROPAD_ON_FAIL = 0x0002;  // zero pad failed physical memory reads and report success if read within range of physical memory.
        public const uint FLAG_FORCECACHE_READ = 0x0008;  // force use of cache - fail non-cached pages - only valid for reads, invalid with VMM_FLAG_NOCACHE/VMM_FLAG_ZEROPAD_ON_FAIL.
        public const uint FLAG_NOPAGING = 0x0010;  // do not try to retrieve memory from paged out memory from pagefile/compressed (even if possible)
        public const uint FLAG_NOPAGING_IO = 0x0020;  // do not try to retrieve memory from paged out memory if read would incur additional I/O (even if possible).
        public const uint FLAG_NOCACHEPUT = 0x0100;  // do not write back to the data cache upon successful read from memory acquisition device.
        public const uint FLAG_CACHE_RECENT_ONLY = 0x0200;  // only fetch from the most recent active cache region when reading.

        /// <summary>
        /// Performs a Scatter Read on a collection of page-aligned Virtual Addresses.
        /// </summary>
        /// <param name="pid">Process ID.</param>
        /// <param name="flags">VMM Flags</param>
        /// <param name="qwA">Array of Virtual Addresses to read.</param>
        /// <returns>Array of MEM_SCATTER structures.</returns>
        public unsafe MEM_SCATTER[] MemReadScatter(uint pid, uint flags, params ulong[] qwA)
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
            vmmi.VMMDLL_MemReadScatter(hVMM, pid, pppMEMs, (uint)MEMs.Length, flags);
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

        public VmmScatter Scatter_Initialize(uint pid, uint flags)
        {
            IntPtr hS = vmmi.VMMDLL_Scatter_Initialize(hVMM, pid, flags);
            if (hS.ToInt64() == 0) { return null; }
            return new VmmScatter(hS);
        }

        /// <summary>
        /// Read Memory from a Virtual Address into a managed byte-array.
        /// </summary>
        /// <param name="pid">Process ID.</param>
        /// <param name="qwA">Virtual Address to read from.</param>
        /// <param name="cb">Count of bytes to read.</param>
        /// <param name="flags">VMM Flags.</param>
        /// <returns>Managed byte array containing number of bytes read.</returns>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public unsafe byte[] MemRead(uint pid, ulong qwA, uint cb, uint flags = 0) =>
            MemReadArray<byte>(pid, qwA, cb, flags);

        /// <summary>
        /// Read Memory from a Virtual Address into unmanaged memory.
        /// </summary>
        /// <param name="pid">Process ID.</param>
        /// <param name="qwA">Virtual Address to read from.</param>
        /// <param name="cb">Count of bytes to read.</param>
        /// <param name="pb">Pointer to buffer to receive read.</param>
        /// <param name="flags">VMM Flags.</param>
        /// <returns>Count of bytes read.</returns>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public unsafe uint MemRead(uint pid, ulong qwA, uint cb, IntPtr pb, uint flags = 0) =>
            MemRead(pid, qwA, cb, pb.ToPointer(), flags);

        /// <summary>
        /// Read Memory from a Virtual Address into unmanaged memory.
        /// </summary>
        /// <param name="pid">Process ID.</param>
        /// <param name="qwA">Virtual Address to read from.</param>
        /// <param name="cb">Count of bytes to read.</param>
        /// <param name="pb">Pointer to buffer to receive read.</param>
        /// <param name="flags">VMM Flags.</param>
        /// <returns>Count of bytes read.</returns>
        public unsafe uint MemRead(uint pid, ulong qwA, uint cb, void* pb, uint flags = 0)
        {
            if (!vmmi.VMMDLL_MemReadEx(hVMM, pid, qwA, (byte*)pb, cb, out var cbRead, flags))
                return 0;
            return cbRead;
        }

        /// <summary>
        /// Read Memory from a Virtual Address into a struct of Type <typeparamref name="T"/>.
        /// </summary>
        /// <typeparam name="T">Struct Type.</typeparam>
        /// <param name="pid">Process ID.</param>
        /// <param name="qwA">Virtual Address to read from.</param>
        /// <param name="result">Result populated from this read.</param>
        /// <param name="flags">VMM Flags.</param>
        /// <returns>True if read successful, otherwise False.</returns>
        public unsafe bool MemReadStruct<T>(uint pid, ulong qwA, out T result, uint flags = 0)
            where T : unmanaged
        {
            uint cb = (uint)sizeof(T);
            result = default;
            uint cbRead;
            fixed (T* pb = &result)
            {
                if (!vmmi.VMMDLL_MemReadEx(hVMM, pid, qwA, (byte*)pb, cb, out cbRead, flags))
                    return false;
            }
            if (cbRead != cb)
                return false;
            return true;
        }

        /// <summary>
        /// Read Memory from a Virtual Address into an Array of Type <typeparamref name="T"/>.
        /// </summary>
        /// <typeparam name="T">Value Type.</typeparam>
        /// <param name="pid">Process ID.</param>
        /// <param name="qwA">Virtual Address to read from.</param>
        /// <param name="count">Number of elements to read.</param>
        /// <param name="flags">VMM Flags.</param>
        /// <returns>Managed <typeparamref name="T"/> array containing number of elements read.</returns>
        public unsafe T[] MemReadArray<T>(uint pid, ulong qwA, uint count, uint flags = 0)
            where T : unmanaged
        {
            uint cb = (uint)sizeof(T) * count;
            uint cbRead;
            T[] data = new T[count];
            fixed (T* pb = data)
            {
                if (!vmmi.VMMDLL_MemReadEx(hVMM, pid, qwA, (byte*)pb, cb, out cbRead, flags))
                {
                    return null;
                }
            }
            if (cbRead != cb)
            {
                int partialCount = (int)cbRead / sizeof(T);
                Array.Resize<T>(ref data, partialCount);
            }
            return data;
        }

        /// <summary>
        /// Read Memory from a Virtual Address into a Managed String.
        /// </summary>
        /// <param name="encoding">String Encoding for this read.</param>
        /// <param name="pid">Process ID.</param>
        /// <param name="qwA">Virtual Address to read from.</param>
        /// <param name="cb">Number of bytes to read. Keep in mind some string encodings are 2-4 bytes per character.</param>
        /// <param name="flags">VMM Flags.</param>
        /// <param name="terminateOnNullChar">Terminate the string at the first occurrence of the null character.</param>
        /// <returns>C# Managed System.String. Null if failed.</returns>
        public unsafe string MemReadString(Encoding encoding, uint pid, ulong qwA, uint cb,
            uint flags = 0, bool terminateOnNullChar = true)
        {
            byte[] buffer = MemRead(pid, qwA, cb, flags);
            if (buffer is null)
                return null;
            var result = encoding.GetString(buffer);
            if (terminateOnNullChar)
            {
                int nullIndex = result.IndexOf('\0');
                if (nullIndex != -1)
                    result = result.Substring(0, nullIndex);
            }
            return result;
        }

        public unsafe bool MemPrefetchPages(uint pid, ulong[] qwA)
        {
            byte[] data = new byte[qwA.Length * sizeof(ulong)];
            System.Buffer.BlockCopy(qwA, 0, data, 0, data.Length);
            fixed (byte* pb = data)
            {
                return vmmi.VMMDLL_MemPrefetchPages(hVMM, pid, pb, (uint)qwA.Length);
            }
        }

        /// <summary>
        /// Write Memory from a managed byte-array to a given Virtual Address.
        /// </summary>
        /// <param name="pid">Process ID.</param>
        /// <param name="qwA">Virtual Address to write to.</param>
        /// <param name="data">Data to be written.</param>
        /// <returns>True if write successful, otherwise False.</returns>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public unsafe bool MemWrite(uint pid, ulong qwA, byte[] data) =>
            MemWriteArray<byte>(pid, qwA, data);

        /// <summary>
        /// Write Memory from unmanaged memory to a given Virtual Address.
        /// </summary>
        /// <param name="pid">Process ID.</param>
        /// <param name="qwA">Virtual Address to write to.</param>
        /// <param name="cb">Count of bytes to write.</param>
        /// <param name="pb">Pointer to buffer to write from.</param>
        /// <returns>True if write successful, otherwise False.</returns>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public unsafe bool MemWrite(uint pid, ulong qwA, uint cb, IntPtr pb) =>
            MemWrite(pid, qwA, cb, pb.ToPointer());

        /// <summary>
        /// Write Memory from unmanaged memory to a given Virtual Address.
        /// </summary>
        /// <param name="pid">Process ID.</param>
        /// <param name="qwA">Virtual Address to write to.</param>
        /// <param name="cb">Count of bytes to write.</param>
        /// <param name="pb">Pointer to buffer to write from.</param>
        /// <returns>True if write successful, otherwise False.</returns>
        public unsafe bool MemWrite(uint pid, ulong qwA, uint cb, void* pb) =>
            vmmi.VMMDLL_MemWrite(hVMM, pid, qwA, (byte*)pb, cb);

        /// <summary>
        /// Write Memory from a struct value <typeparamref name="T"/> to a given Virtual Address.
        /// </summary>
        /// <typeparam name="T">Value Type.</typeparam>
        /// <param name="pid">Process ID.</param>
        /// <param name="qwA">Virtual Address to write to.</param>
        /// <param name="value"><typeparamref name="T"/> Value to write.</param>
        /// <returns>True if write successful, otherwise False.</returns>
        public unsafe bool MemWriteStruct<T>(uint pid, ulong qwA, T value)
            where T : unmanaged
        {
            uint cb = (uint)sizeof(T);
            byte* pb = (byte*)&value;
            return vmmi.VMMDLL_MemWrite(hVMM, pid, qwA, pb, cb);
        }

        /// <summary>
        /// Write Memory from a managed <typeparamref name="T"/> Array to a given Virtual Address.
        /// </summary>
        /// <typeparam name="T">Value Type.</typeparam>
        /// <param name="pid">Process ID.</param>
        /// <param name="qwA">Virtual Address to write to.</param>
        /// <param name="data">Managed <typeparamref name="T"/> array to write.</param>
        /// <param name="flags">VMM Flags.</param>
        /// <returns>True if write successful, otherwise False.</returns>
        public unsafe bool MemWriteArray<T>(uint pid, ulong qwA, T[] data)
            where T : unmanaged
        {
            uint cb = (uint)sizeof(T) * (uint)data.Length;
            fixed (T* pb = data)
            {
                return vmmi.VMMDLL_MemWrite(hVMM, pid, qwA, (byte*)pb, cb);
            }
        }

        public bool MemVirt2Phys(uint dwPID, ulong qwVA, out ulong pqwPA)
        {
            return vmmi.VMMDLL_MemVirt2Phys(hVMM, dwPID, qwVA, out pqwPA);
        }



        //---------------------------------------------------------------------
        // MEMORY SEARCH FUNCTIONALITY BELOW:
        //---------------------------------------------------------------------

        public struct VMMDLL_MEM_SEARCHENTRY
        {
            public uint cbAlign;
            public byte[] pbSearch;
            public byte[] pbSearchSkipMask;
        }

        public unsafe ulong[] MemSearchM(uint pid, VMMDLL_MEM_SEARCHENTRY[] search, ulong vaMin = 0, ulong vaMax = 0xffffffffffffffff, uint cMaxResult = 0x10000, uint ReadFlags = 0)
        {
            // checks:
            if (search == null || search.Length == 0 || search.Length > 16) { return new ulong[0]; }
            // check search items and convert:
            vmmi.VMMDLL_MEM_SEARCH_CONTEXT_SEARCHENTRY[] es = new vmmi.VMMDLL_MEM_SEARCH_CONTEXT_SEARCHENTRY[16];
            for (int i = 0; i < search.Length; i++)
            {
                if (search[i].pbSearch == null || search[i].pbSearch.Length == 0 || search[i].pbSearch.Length > 32) { return new ulong[0]; }
                if ((search[i].pbSearchSkipMask != null) && (search[i].pbSearchSkipMask.Length > search[i].pbSearch.Length)) { return new ulong[0]; }
                es[i].cbAlign = search[i].cbAlign;
                es[i].cb = (uint)search[i].pbSearch.Length;
                es[i].pb = new byte[32];
                search[i].pbSearch.CopyTo(es[i].pb, 0);
                if (search[i].pbSearchSkipMask != null && search[i].pbSearchSkipMask.Length > 0)
                {
                    es[i].pbSkipMask = new byte[32];
                    search[i].pbSearchSkipMask.CopyTo(es[i].pbSkipMask, 0);
                }
            }
            // initialize search struct:
            vmmi.VMMDLL_MEM_SEARCH_CONTEXT ctx = new vmmi.VMMDLL_MEM_SEARCH_CONTEXT();
            ctx.dwVersion = vmmi.VMMDLL_MEM_SEARCH_VERSION;
            ctx.cMaxResult = cMaxResult;
            ctx.cSearch = 1;
            ctx.vaMin = vaMin;
            ctx.vaMax = vaMax;
            ctx.ReadFlags = ReadFlags;
            ctx.search = es;
            // perform native search:
            uint pcva;
            IntPtr ppva;
            if (!vmmi.VMMDLL_MemSearch(hVMM, pid, ref ctx, out ppva, out pcva)) { return new ulong[0]; }
            ulong[] result = new ulong[pcva];
            for (int i = 0; i < pcva; i++)
            {
                result[i] = Marshal.PtrToStructure<ulong>(IntPtr.Add(ppva, i * 8));
            }
            vmmi.VMMDLL_MemFree((byte*)ppva.ToPointer());
            return result;
        }

        public unsafe ulong[] MemSearch1(uint pid, byte[] pbSearch, ulong vaMin = 0, ulong vaMax = 0xffffffffffffffff, uint cMaxResult = 0x10000, uint ReadFlags = 0, byte[] pbSearchSkipMask = null, uint cbAlign = 1)
        {
            VMMDLL_MEM_SEARCHENTRY[] es = new VMMDLL_MEM_SEARCHENTRY[1];
            es[0].cbAlign = cbAlign;
            es[0].pbSearch = pbSearch;
            es[0].pbSearchSkipMask = pbSearchSkipMask;
            return MemSearchM(pid, es, vaMin, vaMax, cMaxResult, ReadFlags);
        }



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
            public uint IntegrityLevel;
        }

        public bool PidGetFromName(string szProcName, out uint pdwPID)
        {
            return vmmi.VMMDLL_PidGetFromName(hVMM, szProcName, out pdwPID);
        }

        public unsafe uint[] PidList()
        {
            bool result;
            ulong c = 0;
            result = vmmi.VMMDLL_PidList(hVMM, null, ref c);
            if (!result || (c == 0)) { return new uint[0]; }
            fixed (byte* pb = new byte[c * 4])
            {
                result = vmmi.VMMDLL_PidList(hVMM, pb, ref c);
                if (!result || (c == 0)) { return new uint[0]; }
                uint[] m = new uint[c];
                for (ulong i = 0; i < c; i++)
                {
                    m[i] = (uint)Marshal.ReadInt32((System.IntPtr)(pb + i * 4));
                }
                return m;
            }
        }

        public unsafe PROCESS_INFORMATION ProcessGetInformation(uint pid)
        {
            bool result;
            ulong cbENTRY = (ulong)System.Runtime.InteropServices.Marshal.SizeOf<vmmi.VMMDLL_PROCESS_INFORMATION>();
            fixed (byte* pb = new byte[cbENTRY])
            {
                Marshal.WriteInt64(new IntPtr(pb + 0), unchecked((long)vmmi.VMMDLL_PROCESS_INFORMATION_MAGIC));
                Marshal.WriteInt16(new IntPtr(pb + 8), unchecked((short)vmmi.VMMDLL_PROCESS_INFORMATION_VERSION));
                result = vmmi.VMMDLL_ProcessGetInformation(hVMM, pid, pb, ref cbENTRY);
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
                e.IntegrityLevel = n.IntegrityLevel;
                return e;
            }
        }

        public const uint VMMDLL_PROCESS_INFORMATION_OPT_STRING_PATH_KERNEL = 1;
        public const uint VMMDLL_PROCESS_INFORMATION_OPT_STRING_PATH_USER_IMAGE = 2;
        public const uint VMMDLL_PROCESS_INFORMATION_OPT_STRING_CMDLINE = 3;

        public unsafe string ProcessGetInformationString(uint pid, uint fOptionString)
        {
            byte* pb = vmmi.VMMDLL_ProcessGetInformationString(hVMM, pid, fOptionString);
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

        public unsafe IMAGE_DATA_DIRECTORY[] ProcessGetDirectories(uint pid, string wszModule)
        {
            string[] PE_DATA_DIRECTORIES = new string[16] { "EXPORT", "IMPORT", "RESOURCE", "EXCEPTION", "SECURITY", "BASERELOC", "DEBUG", "ARCHITECTURE", "GLOBALPTR", "TLS", "LOAD_CONFIG", "BOUND_IMPORT", "IAT", "DELAY_IMPORT", "COM_DESCRIPTOR", "RESERVED" };
            bool result;
            uint cbENTRY = (uint)System.Runtime.InteropServices.Marshal.SizeOf<vmmi.VMMDLL_IMAGE_DATA_DIRECTORY>();
            fixed (byte* pb = new byte[16 * cbENTRY])
            {
                result = vmmi.VMMDLL_ProcessGetDirectories(hVMM, pid, wszModule, pb);
                if (!result) { return new IMAGE_DATA_DIRECTORY[0]; }
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

        public unsafe IMAGE_SECTION_HEADER[] ProcessGetSections(uint pid, string wszModule)
        {
            bool result;
            uint cData;
            uint cbENTRY = (uint)System.Runtime.InteropServices.Marshal.SizeOf<vmmi.VMMDLL_IMAGE_SECTION_HEADER>();
            result = vmmi.VMMDLL_ProcessGetSections(hVMM, pid, wszModule, null, 0, out cData);
            if (!result || (cData == 0)) { return new IMAGE_SECTION_HEADER[0]; }
            fixed (byte* pb = new byte[cData * cbENTRY])
            {
                result = vmmi.VMMDLL_ProcessGetSections(hVMM, pid, wszModule, pb, cData, out cData);
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

        public ulong ProcessGetProcAddress(uint pid, string wszModuleName, string szFunctionName)
        {
            return vmmi.VMMDLL_ProcessGetProcAddress(hVMM, pid, wszModuleName, szFunctionName);
        }

        public ulong ProcessGetModuleBase(uint pid, string wszModuleName)
        {
            return vmmi.VMMDLL_ProcessGetModuleBase(hVMM, pid, wszModuleName);
        }



        //---------------------------------------------------------------------
        // WINDOWS SPECIFIC DEBUGGING / SYMBOL FUNCTIONALITY BELOW:
        //---------------------------------------------------------------------

        public unsafe bool PdbLoad(uint pid, ulong vaModuleBase, out string szModuleName)
        {
            szModuleName = "";
            byte[] data = new byte[260];
            fixed (byte* pb = data)
            {
                bool result = vmmi.VMMDLL_PdbLoad(hVMM, pid, vaModuleBase, pb);
                if(!result) { return false; }
                szModuleName = Encoding.UTF8.GetString(data);
                szModuleName = szModuleName.Substring(0, szModuleName.IndexOf((char)0));
            }
            return true;
        }

        public unsafe bool PdbSymbolName(string szModule, ulong cbSymbolAddressOrOffset, out string szSymbolName, out uint pdwSymbolDisplacement)
        {
            szSymbolName = "";
            pdwSymbolDisplacement = 0;
            byte[] data = new byte[260];
            fixed (byte* pb = data)
            {
                bool result = vmmi.VMMDLL_PdbSymbolName(hVMM, szModule, cbSymbolAddressOrOffset, pb, out pdwSymbolDisplacement);
                if (!result) { return false; }
                szSymbolName = Encoding.UTF8.GetString(data);
                szSymbolName = szSymbolName.Substring(0, szSymbolName.IndexOf((char)0));
            }
            return true;
        }

        public bool PdbSymbolAddress(string szModule, string szSymbolName, out ulong pvaSymbolAddress)
        {
            return vmmi.VMMDLL_PdbSymbolAddress(hVMM, szModule, szSymbolName, out pvaSymbolAddress);
        }

        public bool PdbTypeSize(string szModule, string szTypeName, out uint pcbTypeSize)
        {
            return vmmi.VMMDLL_PdbTypeSize(hVMM, szModule, szTypeName, out pcbTypeSize);
        }

        public bool PdbTypeChildOffset(string szModule, string szTypeName, string wszTypeChildName, out uint pcbTypeChildOffset)
        {
            return vmmi.VMMDLL_PdbTypeChildOffset(hVMM, szModule, szTypeName, wszTypeChildName, out pcbTypeChildOffset);
        }



        //---------------------------------------------------------------------
        // "MAP" FUNCTIONALITY BELOW:
        //---------------------------------------------------------------------

        public const ulong MEMMAP_FLAG_PAGE_W =    0x0000000000000002;
        public const ulong MEMMAP_FLAG_PAGE_NS =   0x0000000000000004;
        public const ulong MEMMAP_FLAG_PAGE_NX =   0x8000000000000000;
        public const ulong MEMMAP_FLAG_PAGE_MASK = 0x8000000000000006;

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
            public uint pteFlags;
            public MAP_VADEXENTRY_PROTOTYPE proto;
            public ulong vaVadBase;
        }

        public const uint MAP_MODULEENTRY_TP_NORMAL    = 0;
        public const uint VMMDLL_MODULE_TP_DATA        = 1;
        public const uint VMMDLL_MODULE_TP_NOTLINKED   = 2;
        public const uint VMMDLL_MODULE_TP_INJECTED    = 3;

        public struct MODULEENTRY_DEBUGINFO
        {
            public bool fValid;
            public uint dwAge;
            public string wszGuid;
            public string wszPdbFilename;
        }

        public struct MODULEENTRY_VERSIONINFO
        {
            public bool fValid;
            public string wszCompanyName;
            public string wszFileDescription;
            public string wszFileVersion;
            public string wszInternalName;
            public string wszLegalCopyright;
            public string wszFileOriginalFilename;
            public string wszProductName;
            public string wszProductVersion;
        }

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
            public MODULEENTRY_DEBUGINFO DebugInfo;
            public MODULEENTRY_VERSIONINFO VersionInfo;
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
            public uint cNumberOfForwardedFunctions;
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
            public string wszForwardedFunction;
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
            public ulong va;
            public uint tpHeap;
            public bool f32;
            public uint iHeapNum;
        }

        public struct MAP_HEAPSEGMENTENTRY
        {
            public ulong va;
            public uint cb;
            public uint tpHeapSegment;
            public uint iHeapNum;
        }

        public struct MAP_HEAP
        {
            public MAP_HEAPENTRY[] heaps;
            public MAP_HEAPSEGMENTENTRY[] segments;
        }

        public struct MAP_HEAPALLOCENTRY
        {
            public ulong va;
            public uint cb;
            public uint tp;
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
            public ulong vaWin32StartAddress;
            public ulong vaStackBaseUser;
            public ulong vaStackLimitUser;
            public ulong vaStackBaseKernel;
            public ulong vaStackLimitKernel;
            public ulong vaTrapFrame;
            public ulong vaImpersonationToken;
            public ulong vaRIP;
            public ulong vaRSP;
            public ulong qwAffinity;
            public uint dwUserTime;
            public uint dwKernelTime;
            public byte bSuspendCount;
            public byte bWaitReason;
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

        public struct MAP_POOLENTRY
        {
            public ulong va;
            public uint cb;
            public uint fAlloc;
            public uint tpPool;
            public uint tpSS;
            public uint dwTag;
            public string sTag;
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

        public unsafe MAP_PTEENTRY[] Map_GetPte(uint pid, bool fIdentifyModules = true)
        {
            int cbMAP = System.Runtime.InteropServices.Marshal.SizeOf<vmmi.VMMDLL_MAP_PTE>();
            int cbENTRY = System.Runtime.InteropServices.Marshal.SizeOf<vmmi.VMMDLL_MAP_PTEENTRY>();
            IntPtr pMap = IntPtr.Zero;
            MAP_PTEENTRY[] m = new MAP_PTEENTRY[0];
            if (!vmmi.VMMDLL_Map_GetPte(hVMM, pid, fIdentifyModules, out pMap)) { goto fail; }
            vmmi.VMMDLL_MAP_PTE nM = Marshal.PtrToStructure<vmmi.VMMDLL_MAP_PTE>(pMap);
            if (nM.dwVersion != vmmi.VMMDLL_MAP_PTE_VERSION) { goto fail; }
            m = new MAP_PTEENTRY[nM.cMap];
            for (int i = 0; i < nM.cMap; i++)
            {
                vmmi.VMMDLL_MAP_PTEENTRY n = Marshal.PtrToStructure<vmmi.VMMDLL_MAP_PTEENTRY>((System.IntPtr)(pMap.ToInt64() + cbMAP + i * cbENTRY));
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
        fail:
            vmmi.VMMDLL_MemFree((byte*)pMap.ToPointer());
            return m;
        }

        public unsafe MAP_VADENTRY[] Map_GetVad(uint pid, bool fIdentifyModules = true)
        {
            int cbMAP = System.Runtime.InteropServices.Marshal.SizeOf<vmmi.VMMDLL_MAP_VAD>();
            int cbENTRY = System.Runtime.InteropServices.Marshal.SizeOf<vmmi.VMMDLL_MAP_VADENTRY>();
            IntPtr pMap = IntPtr.Zero;
            MAP_VADENTRY[] m = new MAP_VADENTRY[0];
            if (!vmmi.VMMDLL_Map_GetVad(hVMM, pid, fIdentifyModules, out pMap)) { goto fail; }
            vmmi.VMMDLL_MAP_VAD nM = Marshal.PtrToStructure<vmmi.VMMDLL_MAP_VAD>(pMap);
            if (nM.dwVersion != vmmi.VMMDLL_MAP_VAD_VERSION) { goto fail; }
            m = new MAP_VADENTRY[nM.cMap];
            for (int i = 0; i < nM.cMap; i++)
            {
                vmmi.VMMDLL_MAP_VADENTRY n = Marshal.PtrToStructure<vmmi.VMMDLL_MAP_VADENTRY>((System.IntPtr)(pMap.ToInt64() + cbMAP + i * cbENTRY));
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
        fail:
            vmmi.VMMDLL_MemFree((byte*)pMap.ToPointer());
            return m;
        }

        public unsafe MAP_VADEXENTRY[] Map_GetVadEx(uint pid, uint oPages, uint cPages)
        {
            int cbMAP = System.Runtime.InteropServices.Marshal.SizeOf<vmmi.VMMDLL_MAP_VADEX>();
            int cbENTRY = System.Runtime.InteropServices.Marshal.SizeOf<vmmi.VMMDLL_MAP_VADEXENTRY>();
            IntPtr pMap = IntPtr.Zero;
            MAP_VADEXENTRY[] m = new MAP_VADEXENTRY[0];
            if (!vmmi.VMMDLL_Map_GetVadEx(hVMM, pid, oPages, cPages, out pMap)) { goto fail; }
            vmmi.VMMDLL_MAP_VADEX nM = Marshal.PtrToStructure<vmmi.VMMDLL_MAP_VADEX>(pMap);
            if (nM.dwVersion != vmmi.VMMDLL_MAP_VADEX_VERSION) { goto fail; }
            m = new MAP_VADEXENTRY[nM.cMap];
            for (int i = 0; i < nM.cMap; i++)
            {
                vmmi.VMMDLL_MAP_VADEXENTRY n = Marshal.PtrToStructure<vmmi.VMMDLL_MAP_VADEXENTRY>((System.IntPtr)(pMap.ToInt64() + cbMAP + i * cbENTRY));
                MAP_VADEXENTRY e;
                e.tp = n.tp;
                e.iPML = n.iPML;
                e.pteFlags = n.pteFlags;
                e.va = n.va;
                e.pa = n.pa;
                e.pte = n.pte;
                e.proto.tp = n.proto_tp;
                e.proto.pa = n.proto_pa;
                e.proto.pte = n.proto_pte;
                e.vaVadBase = n.vaVadBase;
                m[i] = e;
            }
        fail:
            vmmi.VMMDLL_MemFree((byte*)pMap.ToPointer());
            return m;
        }

        public unsafe MAP_MODULEENTRY[] Map_GetModule(uint pid, bool fExtendedInfo)
        {
            int cbMAP = System.Runtime.InteropServices.Marshal.SizeOf<vmmi.VMMDLL_MAP_MODULE>();
            int cbENTRY = System.Runtime.InteropServices.Marshal.SizeOf<vmmi.VMMDLL_MAP_MODULEENTRY>();
            IntPtr pMap = IntPtr.Zero;
            MAP_MODULEENTRY[] m = new MAP_MODULEENTRY[0];
            uint flags = fExtendedInfo ? (uint)0xff : 0;
            if (!vmmi.VMMDLL_Map_GetModule(hVMM, pid, out pMap, flags)) { goto fail; }
            vmmi.VMMDLL_MAP_MODULE nM = Marshal.PtrToStructure<vmmi.VMMDLL_MAP_MODULE>(pMap);
            if (nM.dwVersion != vmmi.VMMDLL_MAP_MODULE_VERSION) { goto fail; }
            m = new MAP_MODULEENTRY[nM.cMap];
            for (int i = 0; i < nM.cMap; i++)
            {
                vmmi.VMMDLL_MAP_MODULEENTRY n = Marshal.PtrToStructure<vmmi.VMMDLL_MAP_MODULEENTRY>((System.IntPtr)(pMap.ToInt64() + cbMAP + i * cbENTRY));
                MAP_MODULEENTRY e;
                MODULEENTRY_DEBUGINFO eDbg;
                MODULEENTRY_VERSIONINFO eVer;
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
                // Extended Debug Information:
                if (n.pExDebugInfo.ToInt64() == 0)
                {
                    eDbg.fValid = false;
                    eDbg.dwAge = 0;
                    eDbg.wszGuid = "";
                    eDbg.wszPdbFilename = "";
                }
                else
                {
                    vmmi.VMMDLL_MAP_MODULEENTRY_DEBUGINFO nDbg = Marshal.PtrToStructure<vmmi.VMMDLL_MAP_MODULEENTRY_DEBUGINFO>(n.pExDebugInfo);
                    eDbg.fValid = true;
                    eDbg.dwAge = nDbg.dwAge;
                    eDbg.wszGuid = nDbg.wszGuid;
                    eDbg.wszPdbFilename = nDbg.wszPdbFilename;
                }
                e.DebugInfo = eDbg;
                // Extended Version Information
                if (n.pExDebugInfo.ToInt64() == 0)
                {
                    eVer.fValid = false;
                    eVer.wszCompanyName = "";
                    eVer.wszFileDescription = "";
                    eVer.wszFileVersion = "";
                    eVer.wszInternalName = "";
                    eVer.wszLegalCopyright = "";
                    eVer.wszFileOriginalFilename = "";
                    eVer.wszProductName = "";
                    eVer.wszProductVersion = "";
                }
                else
                {
                    vmmi.VMMDLL_MAP_MODULEENTRY_VERSIONINFO nVer = Marshal.PtrToStructure<vmmi.VMMDLL_MAP_MODULEENTRY_VERSIONINFO>(n.pExVersionInfo);
                    eVer.fValid = true;
                    eVer.wszCompanyName = nVer.wszCompanyName;
                    eVer.wszFileDescription = nVer.wszFileDescription;
                    eVer.wszFileVersion = nVer.wszFileVersion;
                    eVer.wszInternalName = nVer.wszInternalName;
                    eVer.wszLegalCopyright = nVer.wszLegalCopyright;
                    eVer.wszFileOriginalFilename = nVer.wszFileOriginalFilename;
                    eVer.wszProductName = nVer.wszProductName;
                    eVer.wszProductVersion = nVer.wszProductVersion;
                }
                e.VersionInfo = eVer;
                m[i] = e;
            }
        fail:
            vmmi.VMMDLL_MemFree((byte*)pMap.ToPointer());
            return m;
        }

        public unsafe MAP_MODULEENTRY Map_GetModuleFromName(uint pid, string wszModuleName)
        {
            IntPtr pMap = IntPtr.Zero;
            MAP_MODULEENTRY e = new MAP_MODULEENTRY();
            if (!vmmi.VMMDLL_Map_GetModuleFromName(hVMM, pid, wszModuleName, out pMap, 0)) { goto fail; }
            vmmi.VMMDLL_MAP_MODULEENTRY nM = Marshal.PtrToStructure<vmmi.VMMDLL_MAP_MODULEENTRY>(pMap);
            e.fValid = true;
            e.vaBase = nM.vaBase;
            e.vaEntry = nM.vaEntry;
            e.cbImageSize = nM.cbImageSize;
            e.fWow64 = nM.fWow64;
            e.wszText = wszModuleName;
            e.wszFullName = nM.wszFullName;
            e.tp = nM.tp;
            e.cbFileSizeRaw = nM.cbFileSizeRaw;
            e.cSection = nM.cSection;
            e.cEAT = nM.cEAT;
            e.cIAT = nM.cIAT;
        fail:
            vmmi.VMMDLL_MemFree((byte*)pMap.ToPointer());
            return e;
        }

        public unsafe MAP_UNLOADEDMODULEENTRY[] Map_GetUnloadedModule(uint pid)
        {
            int cbMAP = System.Runtime.InteropServices.Marshal.SizeOf<vmmi.VMMDLL_MAP_UNLOADEDMODULE>();
            int cbENTRY = System.Runtime.InteropServices.Marshal.SizeOf<vmmi.VMMDLL_MAP_UNLOADEDMODULEENTRY>();
            IntPtr pMap = IntPtr.Zero;
            MAP_UNLOADEDMODULEENTRY[] m = new MAP_UNLOADEDMODULEENTRY[0];
            if (!vmmi.VMMDLL_Map_GetUnloadedModule(hVMM, pid, out pMap)) { goto fail; }
            vmmi.VMMDLL_MAP_UNLOADEDMODULE nM = Marshal.PtrToStructure<vmmi.VMMDLL_MAP_UNLOADEDMODULE>(pMap);
            if (nM.dwVersion != vmmi.VMMDLL_MAP_UNLOADEDMODULE_VERSION) { goto fail; }
            m = new MAP_UNLOADEDMODULEENTRY[nM.cMap];
            for (int i = 0; i < nM.cMap; i++)
            {
                vmmi.VMMDLL_MAP_UNLOADEDMODULEENTRY n = Marshal.PtrToStructure<vmmi.VMMDLL_MAP_UNLOADEDMODULEENTRY>((System.IntPtr)(pMap.ToInt64() + cbMAP + i * cbENTRY));
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
        fail:
            vmmi.VMMDLL_MemFree((byte*)pMap.ToPointer());
            return m;
        }

        public unsafe MAP_EATENTRY[] Map_GetEAT(uint pid, string wszModule, out MAP_EATINFO EatInfo)
        {
            EatInfo = new MAP_EATINFO();
            int cbMAP = System.Runtime.InteropServices.Marshal.SizeOf<vmmi.VMMDLL_MAP_EAT>();
            int cbENTRY = System.Runtime.InteropServices.Marshal.SizeOf<vmmi.VMMDLL_MAP_EATENTRY>();
            IntPtr pMap = IntPtr.Zero;
            MAP_EATENTRY[] m = new MAP_EATENTRY[0];
            if (!vmmi.VMMDLL_Map_GetEAT(hVMM, pid, wszModule, out pMap)) { goto fail; }
            vmmi.VMMDLL_MAP_EAT nM = Marshal.PtrToStructure<vmmi.VMMDLL_MAP_EAT>(pMap);
            if (nM.dwVersion != vmmi.VMMDLL_MAP_EAT_VERSION) { goto fail; }
            m = new MAP_EATENTRY[nM.cMap];
            for (int i = 0; i < nM.cMap; i++)
            {
                vmmi.VMMDLL_MAP_EATENTRY n = Marshal.PtrToStructure<vmmi.VMMDLL_MAP_EATENTRY>((System.IntPtr)(pMap.ToInt64() + cbMAP + i * cbENTRY));
                MAP_EATENTRY e;
                e.vaFunction = n.vaFunction;
                e.dwOrdinal = n.dwOrdinal;
                e.oFunctionsArray = n.oFunctionsArray;
                e.oNamesArray = n.oNamesArray;
                e.wszFunction = n.wszFunction;
                e.wszForwardedFunction = n.wszForwardedFunction;
                m[i] = e;
            }
            EatInfo.fValid = true;
            EatInfo.vaModuleBase = nM.vaModuleBase;
            EatInfo.vaAddressOfFunctions = nM.vaAddressOfFunctions;
            EatInfo.vaAddressOfNames = nM.vaAddressOfNames;
            EatInfo.cNumberOfFunctions = nM.cNumberOfFunctions;
            EatInfo.cNumberOfForwardedFunctions = nM.cNumberOfForwardedFunctions;
            EatInfo.cNumberOfNames = nM.cNumberOfNames;
            EatInfo.dwOrdinalBase = nM.dwOrdinalBase;
        fail:
            vmmi.VMMDLL_MemFree((byte*)pMap.ToPointer());
            return m;
        }

        public unsafe MAP_IATENTRY[] Map_GetIAT(uint pid, string wszModule)
        {
            int cbMAP = System.Runtime.InteropServices.Marshal.SizeOf<vmmi.VMMDLL_MAP_IAT>();
            int cbENTRY = System.Runtime.InteropServices.Marshal.SizeOf<vmmi.VMMDLL_MAP_IATENTRY>();
            IntPtr pMap = IntPtr.Zero;
            MAP_IATENTRY[] m = new MAP_IATENTRY[0];
            if (!vmmi.VMMDLL_Map_GetIAT(hVMM, pid, wszModule, out pMap)) { goto fail; }
            vmmi.VMMDLL_MAP_IAT nM = Marshal.PtrToStructure<vmmi.VMMDLL_MAP_IAT>(pMap);
            if (nM.dwVersion != vmmi.VMMDLL_MAP_IAT_VERSION) { goto fail; }
            m = new MAP_IATENTRY[nM.cMap];
            for (int i = 0; i < nM.cMap; i++)
            {
                vmmi.VMMDLL_MAP_IATENTRY n = Marshal.PtrToStructure<vmmi.VMMDLL_MAP_IATENTRY>((System.IntPtr)(pMap.ToInt64() + cbMAP + i * cbENTRY));
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
                e.vaModule = nM.vaModuleBase;
                m[i] = e;
            }
        fail:
            vmmi.VMMDLL_MemFree((byte*)pMap.ToPointer());
            return m;
        }

        public unsafe MAP_HEAP Map_GetHeap(uint pid)
        {
            IntPtr pMap = IntPtr.Zero;
            int cbMAP = System.Runtime.InteropServices.Marshal.SizeOf<vmmi.VMMDLL_MAP_HEAP>();
            int cbENTRY = System.Runtime.InteropServices.Marshal.SizeOf<vmmi.VMMDLL_MAP_HEAPENTRY>();
            int cbSEGENTRY = System.Runtime.InteropServices.Marshal.SizeOf<vmmi.VMMDLL_MAP_HEAPSEGMENTENTRY>();
            MAP_HEAP Heap;
            Heap.heaps = new MAP_HEAPENTRY[0];
            Heap.segments = new MAP_HEAPSEGMENTENTRY[0];
            if(!vmmi.VMMDLL_Map_GetHeap(hVMM, pid, out pMap)) { goto fail; }
            vmmi.VMMDLL_MAP_HEAP nM = Marshal.PtrToStructure<vmmi.VMMDLL_MAP_HEAP>(pMap);
            if (nM.dwVersion != vmmi.VMMDLL_MAP_HEAP_VERSION) { goto fail; }
            Heap.heaps = new MAP_HEAPENTRY[nM.cMap];
            for (int i = 0; i < nM.cMap; i++)
            {
                vmmi.VMMDLL_MAP_HEAPENTRY nH = Marshal.PtrToStructure<vmmi.VMMDLL_MAP_HEAPENTRY>((System.IntPtr)(pMap.ToInt64() + cbMAP + i * cbENTRY));
                Heap.heaps[i].va = nH.va;
                Heap.heaps[i].f32 = nH.f32;
                Heap.heaps[i].tpHeap = nH.tp;
                Heap.heaps[i].iHeapNum = nH.dwHeapNum;
            }
            Heap.segments = new MAP_HEAPSEGMENTENTRY[nM.cSegments];
            for (int i = 0; i < nM.cMap; i++)
            {
                vmmi.VMMDLL_MAP_HEAPSEGMENTENTRY nH = Marshal.PtrToStructure<vmmi.VMMDLL_MAP_HEAPSEGMENTENTRY>((System.IntPtr)(nM.pSegments.ToInt64() + i * cbSEGENTRY));
                Heap.segments[i].va = nH.va;
                Heap.segments[i].cb = nH.cb;
                Heap.segments[i].tpHeapSegment = nH.tp;
                Heap.segments[i].iHeapNum = nH.iHeap;
            }
        fail:
            vmmi.VMMDLL_MemFree((byte*)pMap.ToPointer());
            return Heap;
        }

        public unsafe MAP_HEAPALLOCENTRY[] Map_GetHeapAlloc(uint pid, ulong vaHeapOrHeapNum)
        {
            IntPtr pHeapAllocMap = IntPtr.Zero;
            int cbMAP = System.Runtime.InteropServices.Marshal.SizeOf<vmmi.VMMDLL_MAP_HEAPALLOC>();
            int cbENTRY = System.Runtime.InteropServices.Marshal.SizeOf<vmmi.VMMDLL_MAP_HEAPALLOCENTRY>();
            if (!vmmi.VMMDLL_Map_GetHeapAlloc(hVMM, pid, vaHeapOrHeapNum, out pHeapAllocMap)) { return new MAP_HEAPALLOCENTRY[0]; }
            vmmi.VMMDLL_MAP_HEAPALLOC nM = Marshal.PtrToStructure<vmmi.VMMDLL_MAP_HEAPALLOC>(pHeapAllocMap);
            if (nM.dwVersion != vmmi.VMMDLL_MAP_HEAPALLOC_VERSION) {
                vmmi.VMMDLL_MemFree((byte*)pHeapAllocMap.ToPointer());
                return new MAP_HEAPALLOCENTRY[0];
            }
            MAP_HEAPALLOCENTRY[] m = new MAP_HEAPALLOCENTRY[nM.cMap];
            for (int i = 0; i < nM.cMap; i++)
            {
                vmmi.VMMDLL_MAP_HEAPALLOCENTRY n = Marshal.PtrToStructure<vmmi.VMMDLL_MAP_HEAPALLOCENTRY>((System.IntPtr)(pHeapAllocMap.ToInt64() + cbMAP + i * cbENTRY));
                m[i].va = n.va;
                m[i].cb = n.cb;
                m[i].tp = n.tp;
            }
            vmmi.VMMDLL_MemFree((byte*)pHeapAllocMap.ToPointer());
            return m;
        }

        public unsafe MAP_THREADENTRY[] Map_GetThread(uint pid)
        {
            int cbMAP = System.Runtime.InteropServices.Marshal.SizeOf<vmmi.VMMDLL_MAP_THREAD>();
            int cbENTRY = System.Runtime.InteropServices.Marshal.SizeOf<vmmi.VMMDLL_MAP_THREADENTRY>();
            IntPtr pMap = IntPtr.Zero;
            MAP_THREADENTRY[] m = new MAP_THREADENTRY[0];
            if (!vmmi.VMMDLL_Map_GetThread(hVMM, pid, out pMap)) { goto fail; }
            vmmi.VMMDLL_MAP_THREAD nM = Marshal.PtrToStructure<vmmi.VMMDLL_MAP_THREAD>(pMap);
            if (nM.dwVersion != vmmi.VMMDLL_MAP_THREAD_VERSION) { goto fail; }
            m = new MAP_THREADENTRY[nM.cMap];
            for (int i = 0; i < nM.cMap; i++)
            {
                vmmi.VMMDLL_MAP_THREADENTRY n = Marshal.PtrToStructure<vmmi.VMMDLL_MAP_THREADENTRY>((System.IntPtr)(pMap.ToInt64() + cbMAP + i * cbENTRY));
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
                e.vaWin32StartAddress = n.vaWin32StartAddress;
                e.vaStackBaseUser = n.vaStackBaseUser;
                e.vaStackLimitUser = n.vaStackLimitUser;
                e.vaStackBaseKernel = n.vaStackBaseKernel;
                e.vaStackLimitKernel = n.vaStackLimitKernel;
                e.vaImpersonationToken = n.vaImpersonationToken;
                e.vaTrapFrame = n.vaTrapFrame;
                e.vaRIP = n.vaRIP;
                e.vaRSP = n.vaRSP;
                e.qwAffinity = n.qwAffinity;
                e.dwUserTime = n.dwUserTime;
                e.dwKernelTime = n.dwKernelTime;
                e.bSuspendCount = n.bSuspendCount;
                e.bWaitReason = n.bWaitReason;
                m[i] = e;
            }
        fail:
            vmmi.VMMDLL_MemFree((byte*)pMap.ToPointer());
            return m;
        }

        public unsafe MAP_HANDLEENTRY[] Map_GetHandle(uint pid)
        {
            int cbMAP = System.Runtime.InteropServices.Marshal.SizeOf<vmmi.VMMDLL_MAP_HANDLE>();
            int cbENTRY = System.Runtime.InteropServices.Marshal.SizeOf<vmmi.VMMDLL_MAP_HANDLEENTRY>();
            IntPtr pMap = IntPtr.Zero;
            MAP_HANDLEENTRY[] m = new MAP_HANDLEENTRY[0];
            if (!vmmi.VMMDLL_Map_GetHandle(hVMM, pid, out pMap)) { goto fail; }
            vmmi.VMMDLL_MAP_HANDLE nM = Marshal.PtrToStructure<vmmi.VMMDLL_MAP_HANDLE>(pMap);
            if (nM.dwVersion != vmmi.VMMDLL_MAP_HANDLE_VERSION) { goto fail; }
            m = new MAP_HANDLEENTRY[nM.cMap];
            for (int i = 0; i < nM.cMap; i++)
            {
                vmmi.VMMDLL_MAP_HANDLEENTRY n = Marshal.PtrToStructure<vmmi.VMMDLL_MAP_HANDLEENTRY>((System.IntPtr)(pMap.ToInt64() + cbMAP + i * cbENTRY));
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
        fail:
            vmmi.VMMDLL_MemFree((byte*)pMap.ToPointer());
            return m;
        }

        public unsafe MAP_NETENTRY[] Map_GetNet()
        {
            int cbMAP = System.Runtime.InteropServices.Marshal.SizeOf<vmmi.VMMDLL_MAP_NET>();
            int cbENTRY = System.Runtime.InteropServices.Marshal.SizeOf<vmmi.VMMDLL_MAP_NETENTRY>();
            IntPtr pMap = IntPtr.Zero;
            MAP_NETENTRY[] m = new MAP_NETENTRY[0];
            if (!vmmi.VMMDLL_Map_GetNet(hVMM, out pMap)) { goto fail; }
            vmmi.VMMDLL_MAP_NET nM = Marshal.PtrToStructure<vmmi.VMMDLL_MAP_NET>(pMap);
            if (nM.dwVersion != vmmi.VMMDLL_MAP_NET_VERSION) { goto fail; }
            m = new MAP_NETENTRY[nM.cMap];
            for (int i = 0; i < nM.cMap; i++)
            {
                vmmi.VMMDLL_MAP_NETENTRY n = Marshal.PtrToStructure<vmmi.VMMDLL_MAP_NETENTRY>((System.IntPtr)(pMap.ToInt64() + cbMAP + i * cbENTRY));
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
        fail:
            vmmi.VMMDLL_MemFree((byte*)pMap.ToPointer());
            return m;
        }

        public unsafe MAP_PHYSMEMENTRY[] Map_GetPhysMem()
        {
            int cbMAP = System.Runtime.InteropServices.Marshal.SizeOf<vmmi.VMMDLL_MAP_PHYSMEM>();
            int cbENTRY = System.Runtime.InteropServices.Marshal.SizeOf<vmmi.VMMDLL_MAP_PHYSMEMENTRY>();
            IntPtr pMap = IntPtr.Zero;
            MAP_PHYSMEMENTRY[] m = new MAP_PHYSMEMENTRY[0];
            if (!vmmi.VMMDLL_Map_GetPhysMem(hVMM, out pMap)) { goto fail; }
            vmmi.VMMDLL_MAP_PHYSMEM nM = Marshal.PtrToStructure<vmmi.VMMDLL_MAP_PHYSMEM>(pMap);
            if (nM.dwVersion != vmmi.VMMDLL_MAP_PHYSMEM_VERSION) { goto fail; }
            m = new MAP_PHYSMEMENTRY[nM.cMap];
            for (int i = 0; i < nM.cMap; i++)
            {
                vmmi.VMMDLL_MAP_PHYSMEMENTRY n = Marshal.PtrToStructure<vmmi.VMMDLL_MAP_PHYSMEMENTRY>((System.IntPtr)(pMap.ToInt64() + cbMAP + i * cbENTRY));
                MAP_PHYSMEMENTRY e;
                e.pa = n.pa;
                e.cb = n.cb;
                m[i] = e;
            }
        fail:
            vmmi.VMMDLL_MemFree((byte*)pMap.ToPointer());
            return m;
        }

        public unsafe MAP_POOLENTRY[] Map_GetPool()
        {
            byte[] tag = { 0, 0, 0, 0};
            IntPtr pN = IntPtr.Zero;
            int cbMAP = System.Runtime.InteropServices.Marshal.SizeOf<vmmi.VMMDLL_MAP_POOL>();
            int cbENTRY = System.Runtime.InteropServices.Marshal.SizeOf<vmmi.VMMDLL_MAP_POOLENTRY>();
            if (!vmmi.VMMDLL_Map_GetPool(hVMM, out pN, 0)) { return new MAP_POOLENTRY[0]; }
            vmmi.VMMDLL_MAP_POOL nM = Marshal.PtrToStructure<vmmi.VMMDLL_MAP_POOL>(pN);
            if (nM.dwVersion != vmmi.VMMDLL_MAP_POOL_VERSION) {
                vmmi.VMMDLL_MemFree((byte*)pN.ToPointer());
                return new MAP_POOLENTRY[0];
            }
            MAP_POOLENTRY[] eM = new MAP_POOLENTRY[nM.cMap];
            for (int i = 0; i < nM.cMap; i++)
            {
                vmmi.VMMDLL_MAP_POOLENTRY nE = Marshal.PtrToStructure<vmmi.VMMDLL_MAP_POOLENTRY>((System.IntPtr)(pN.ToInt64() + cbMAP + i * cbENTRY));
                eM[i].va = nE.va;
                eM[i].cb = nE.cb;
                eM[i].tpPool = nE.tpPool;
                eM[i].tpSS = nE.tpSS;
                eM[i].dwTag = nE.dwTag;
                tag[0] = (byte)((nE.dwTag >> 00) & 0xff);
                tag[1] = (byte)((nE.dwTag >> 08) & 0xff);
                tag[2] = (byte)((nE.dwTag >> 16) & 0xff);
                tag[3] = (byte)((nE.dwTag >> 24) & 0xff);
                eM[i].sTag = System.Text.Encoding.ASCII.GetString(tag);
            }
            vmmi.VMMDLL_MemFree((byte*)pN.ToPointer());
            return eM;
        }

        public unsafe MAP_USERENTRY[] Map_GetUsers()
        {
            int cbMAP = System.Runtime.InteropServices.Marshal.SizeOf<vmmi.VMMDLL_MAP_USER>();
            int cbENTRY = System.Runtime.InteropServices.Marshal.SizeOf<vmmi.VMMDLL_MAP_USERENTRY>();
            IntPtr pMap = IntPtr.Zero;
            MAP_USERENTRY[] m = new MAP_USERENTRY[0];
            if (!vmmi.VMMDLL_Map_GetUsers(hVMM, out pMap)) { goto fail; }
            vmmi.VMMDLL_MAP_USER nM = Marshal.PtrToStructure<vmmi.VMMDLL_MAP_USER>(pMap);
            if (nM.dwVersion != vmmi.VMMDLL_MAP_USER_VERSION) { goto fail; }
            m = new MAP_USERENTRY[nM.cMap];
            for (int i = 0; i < nM.cMap; i++)
            {
                vmmi.VMMDLL_MAP_USERENTRY n = Marshal.PtrToStructure<vmmi.VMMDLL_MAP_USERENTRY>((System.IntPtr)(pMap.ToInt64() + cbMAP + i * cbENTRY));
                MAP_USERENTRY e;
                e.szSID = n.wszSID;
                e.wszText = n.wszText;
                e.vaRegHive = n.vaRegHive;
                m[i] = e;
            }
        fail:
            vmmi.VMMDLL_MemFree((byte*)pMap.ToPointer());
            return m;
        }

        public unsafe MAP_SERVICEENTRY[] Map_GetServices()
        {
            int cbMAP = System.Runtime.InteropServices.Marshal.SizeOf<vmmi.VMMDLL_MAP_SERVICE>();
            int cbENTRY = System.Runtime.InteropServices.Marshal.SizeOf<vmmi.VMMDLL_MAP_SERVICEENTRY>();
            IntPtr pMap = IntPtr.Zero;
            MAP_SERVICEENTRY[] m = new MAP_SERVICEENTRY[0];
            if (!vmmi.VMMDLL_Map_GetServices(hVMM, out pMap)) { goto fail; }
            vmmi.VMMDLL_MAP_SERVICE nM = Marshal.PtrToStructure<vmmi.VMMDLL_MAP_SERVICE>(pMap);
            if (nM.dwVersion != vmmi.VMMDLL_MAP_SERVICE_VERSION) { goto fail; }
            m = new MAP_SERVICEENTRY[nM.cMap];
            for (int i = 0; i < nM.cMap; i++)
            {
                vmmi.VMMDLL_MAP_SERVICEENTRY n = Marshal.PtrToStructure<vmmi.VMMDLL_MAP_SERVICEENTRY>((System.IntPtr)(pMap.ToInt64() + cbMAP + i * cbENTRY));
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
        fail:
            vmmi.VMMDLL_MemFree((byte*)pMap.ToPointer());
            return m;
        }

        public unsafe MAP_PFNENTRY[] Map_GetPfn(params uint[] pfns)
        {
            bool result;
            uint cbPfns;
            int cbMAP = System.Runtime.InteropServices.Marshal.SizeOf<vmmi.VMMDLL_MAP_PFN>();
            int cbENTRY = System.Runtime.InteropServices.Marshal.SizeOf<vmmi.VMMDLL_MAP_PFNENTRY>();
            if (pfns.Length == 0) { return new MAP_PFNENTRY[0]; }
            byte[] dataPfns = new byte[pfns.Length * sizeof(uint)];
            System.Buffer.BlockCopy(pfns, 0, dataPfns, 0, dataPfns.Length);
            fixed (byte* pbPfns = dataPfns)
            {
                cbPfns = (uint)(cbMAP + pfns.Length * cbENTRY);
                fixed (byte* pb = new byte[cbPfns])
                {
                    result =
                        vmmi.VMMDLL_Map_GetPfn(hVMM, pbPfns, (uint)pfns.Length, null, ref cbPfns) &&
                        vmmi.VMMDLL_Map_GetPfn(hVMM, pbPfns, (uint)pfns.Length, pb, ref cbPfns);
                    if (!result) { return new MAP_PFNENTRY[0]; }
                    vmmi.VMMDLL_MAP_PFN pm = Marshal.PtrToStructure<vmmi.VMMDLL_MAP_PFN>((System.IntPtr)pb);
                    if (pm.dwVersion != vmmi.VMMDLL_MAP_PFN_VERSION) { return new MAP_PFNENTRY[0]; }
                    MAP_PFNENTRY[] m = new MAP_PFNENTRY[pm.cMap];
                    for (int i = 0; i < pm.cMap; i++)
                    {
                        vmmi.VMMDLL_MAP_PFNENTRY n = Marshal.PtrToStructure<vmmi.VMMDLL_MAP_PFNENTRY>((System.IntPtr)(pb + cbMAP + i * cbENTRY));
                        MAP_PFNENTRY e = new MAP_PFNENTRY();
                        e.dwPfn = n.dwPfn;
                        e.tp = (MAP_PFN_TYPE)((n._u3 >> 16) & 0x07);
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

        public unsafe REGISTRY_HIVE_INFORMATION[] RegHiveList()
        {
            bool result;
            uint cHives;
            int cbENTRY = System.Runtime.InteropServices.Marshal.SizeOf<vmmi.VMMDLL_REGISTRY_HIVE_INFORMATION>();
            result = vmmi.VMMDLL_WinReg_HiveList(hVMM, null, 0, out cHives);
            if (!result || (cHives == 0)) { return new REGISTRY_HIVE_INFORMATION[0]; }
            fixed (byte* pb = new byte[cHives * cbENTRY])
            {
                result = vmmi.VMMDLL_WinReg_HiveList(hVMM, pb, cHives, out cHives);
                if (!result) { return new REGISTRY_HIVE_INFORMATION[0]; }
                REGISTRY_HIVE_INFORMATION[] m = new REGISTRY_HIVE_INFORMATION[cHives];
                for (int i = 0; i < cHives; i++)
                {
                    vmmi.VMMDLL_REGISTRY_HIVE_INFORMATION n = Marshal.PtrToStructure<vmmi.VMMDLL_REGISTRY_HIVE_INFORMATION>((System.IntPtr)(pb + i * cbENTRY));
                    REGISTRY_HIVE_INFORMATION e;
                    if(n.wVersion != vmmi.VMMDLL_REGISTRY_HIVE_INFORMATION_VERSION) { return new REGISTRY_HIVE_INFORMATION[0]; }
                    e.vaCMHIVE = n.vaCMHIVE;
                    e.vaHBASE_BLOCK = n.vaHBASE_BLOCK;
                    e.cbLength = n.cbLength;
                    e.szName = System.Text.Encoding.UTF8.GetString(n.uszName);
                    e.szName = e.szName.Substring(0, e.szName.IndexOf((char)0));
                    e.szNameShort = System.Text.Encoding.UTF8.GetString(n.uszNameShort);
                    e.szHiveRootPath = System.Text.Encoding.UTF8.GetString(n.uszHiveRootPath);
                    m[i] = e;
                }
                return m;
            }
        }

        public unsafe byte[] RegHiveRead(ulong vaCMHIVE, uint ra, uint cb, uint flags = 0)
        {
            uint cbRead;
            byte[] data = new byte[cb];
            fixed (byte* pb = data)
            {
                if(!vmmi.VMMDLL_WinReg_HiveReadEx(hVMM, vaCMHIVE, ra, pb, cb, out cbRead, flags))
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


        public unsafe bool RegHiveWrite(ulong vaCMHIVE, uint ra, byte[] data)
        {
            fixed (byte* pb = data)
            {
                return vmmi.VMMDLL_WinReg_HiveWrite(hVMM, vaCMHIVE, ra, pb, (uint)data.Length);
            }
        }

        public unsafe REGISTRY_ENUM RegEnum(string wszFullPathKey)
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
                while (vmmi.VMMDLL_WinReg_EnumKeyExW(hVMM, wszFullPathKey, i, pb, ref cchName, out ftLastWriteTime))
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
                while (vmmi.VMMDLL_WinReg_EnumValueW(hVMM, wszFullPathKey, i, pb, ref cchName, out lpType, null, ref cbData))
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

        public unsafe byte[] RegValueRead(string wszFullPathKeyValue, out uint tp)
        {
            bool result;
            uint cb = 0;
            result = vmmi.VMMDLL_WinReg_QueryValueExW(hVMM, wszFullPathKeyValue, out tp, null, ref cb);
            if(!result)
            {
                return null;
            }
            byte[] data = new byte[cb];
            fixed (byte* pb = data)
            {
                result = vmmi.VMMDLL_WinReg_QueryValueExW(hVMM, wszFullPathKeyValue, out tp, pb, ref cb);
                return result ? data : null;
            }
        }
    }

    public sealed class VmmScatter : IDisposable
    {
        //---------------------------------------------------------------------
        // MEMORY NEW SCATTER READ/WRITE FUNCTIONALITY BELOW:
        //---------------------------------------------------------------------
        bool disposed = false;
        IntPtr hS = IntPtr.Zero;

        private VmmScatter()
        {
            ;
        }

        internal VmmScatter(IntPtr hS)
        {
            this.hS = hS;
        }

        ~VmmScatter()
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
                vmmi.VMMDLL_Scatter_CloseHandle(hS);
                hS = IntPtr.Zero;
                disposed = true;
            }
        }

        public void Close()
        {
            Dispose(disposing: true);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public unsafe byte[] Read(ulong qwA, uint cb) =>
            ReadArray<byte>(qwA, cb);

        public unsafe bool ReadStruct<T>(ulong qwA, out T result)
            where T : unmanaged
        {
            uint cb = (uint)sizeof(T);
            uint cbRead;
            result = default;
            fixed (T* pb = &result)
            {
                if (!vmmi.VMMDLL_Scatter_Read(hS, qwA, cb, (byte*)pb, out cbRead))
                    return false;
            }
            if (cbRead != cb)
                return false;
            return true;
        }

        public unsafe T[] ReadArray<T>(ulong qwA, uint count)
            where T : unmanaged
        {
            uint cb = (uint)sizeof(T) * count;
            uint cbRead;
            T[] data = new T[count];
            fixed (T* pb = data)
            {
                if (!vmmi.VMMDLL_Scatter_Read(hS, qwA, cb, (byte*)pb, out cbRead))
                {
                    return null;
                }
            }
            if (cbRead != cb)
            {
                int partialCount = (int)cbRead / sizeof(T);
                Array.Resize<T>(ref data, partialCount);
            }
            return data;
        }

        /// <summary>
        /// Read Memory from a Virtual Address into a Managed String.
        /// </summary>
        /// <param name="encoding">String Encoding for this read.</param>
        /// <param name="qwA">Virtual Address to read from.</param>
        /// <param name="cb">Number of bytes to read. Keep in mind some string encodings are 2-4 bytes per character.</param>
        /// <param name="terminateOnNullChar">Terminate the string at the first occurrence of the null character.</param>
        /// <returns>C# Managed System.String. Null if failed.</returns>
        public unsafe string ReadString(Encoding encoding, ulong qwA, uint cb, bool terminateOnNullChar = true)
        {
            byte[] buffer = Read(qwA, cb);
            if (buffer is null)
                return null;
            var result = encoding.GetString(buffer);
            if (terminateOnNullChar)
            {
                int nullIndex = result.IndexOf('\0');
                if (nullIndex != -1)
                    result = result.Substring(0, nullIndex);
            }
            return result;
        }

        public bool Prepare(ulong qwA, uint cb)
        {
            return vmmi.VMMDLL_Scatter_Prepare(hS, qwA, cb);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public unsafe bool PrepareWrite(ulong qwA, byte[] data) =>
            PrepareWriteArray<byte>(qwA, data);

        public unsafe bool PrepareWriteArray<T>(ulong qwA, T[] data)
            where T : unmanaged
        {
            uint cb = (uint)sizeof(T) * (uint)data.Length;
            fixed (T* pb = data)
            {
                return vmmi.VMMDLL_Scatter_PrepareWrite(hS, qwA, (byte*)pb, cb);
            }
        }

        public unsafe bool PrepareWriteStruct<T>(ulong qwA, T value)
            where T : unmanaged
        {
            uint cb = (uint)sizeof(T);
            byte* pb = (byte*)&value;
            return vmmi.VMMDLL_Scatter_PrepareWrite(hS, qwA, pb, cb);
        }

        public bool Execute()
        {
            return vmmi.VMMDLL_Scatter_Execute(hS);
        }

        public bool Clear(uint dwPID, uint flags)
        {
            return vmmi.VMMDLL_Scatter_Clear(hS, dwPID, flags);
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

        [DllImport("leechcore", EntryPoint = "LcCreate")]
        public static extern IntPtr LcCreate(ref LeechCore.LC_CONFIG pLcCreateConfig);

        [DllImport("leechcore", EntryPoint = "LcCreateEx")]
        public static extern IntPtr LcCreateEx(ref LeechCore.LC_CONFIG pLcCreateConfig, out IntPtr ppLcCreateErrorInfo);

        [DllImport("leechcore", EntryPoint = "LcClose")]
        internal static extern void LcClose(IntPtr hLC);

        [DllImport("leechcore", EntryPoint = "LcMemFree")]
        internal static extern unsafe void LcMemFree(IntPtr pv);

        [DllImport("leechcore", EntryPoint = "LcAllocScatter1")]
        internal static extern unsafe bool LcAllocScatter1(uint cMEMs, out IntPtr pppMEMs);

        [DllImport("leechcore", EntryPoint = "LcRead")]
        internal static extern unsafe bool LcRead(IntPtr hLC, ulong pa, uint cb, byte* pb);

        [DllImport("leechcore", EntryPoint = "LcReadScatter")]
        internal static extern unsafe void LcReadScatter(IntPtr hLC, uint cMEMs, IntPtr ppMEMs);

        [DllImport("leechcore", EntryPoint = "LcWrite")]
        internal static extern unsafe bool LcWrite(IntPtr hLC, ulong pa, uint cb, byte* pb);

        [DllImport("leechcore", EntryPoint = "LcWriteScatter")]
        internal static extern unsafe void LcWriteScatter(IntPtr hLC, uint cMEMs, IntPtr ppMEMs);

        [DllImport("leechcore", EntryPoint = "LcGetOption")]
        public static extern bool GetOption(IntPtr hLC, ulong fOption, out ulong pqwValue);

        [DllImport("leechcore", EntryPoint = "LcSetOption")]
        public static extern bool SetOption(IntPtr hLC, ulong fOption, ulong qwValue);

        [DllImport("leechcore", EntryPoint = "LcCommand")]
        internal static extern unsafe bool LcCommand(IntPtr hLC, ulong fOption, uint cbDataIn, byte* pbDataIn, out IntPtr ppbDataOut, out uint pcbDataOut);
    }



    internal static class vmmi
    {
        internal const ulong MAX_PATH =                     260;
        internal const uint VMMDLL_MAP_PTE_VERSION =        2;
        internal const uint VMMDLL_MAP_VAD_VERSION =        6;
        internal const uint VMMDLL_MAP_VADEX_VERSION =      4;
        internal const uint VMMDLL_MAP_MODULE_VERSION =     6;
        internal const uint VMMDLL_MAP_UNLOADEDMODULE_VERSION = 2;
        internal const uint VMMDLL_MAP_EAT_VERSION =        3;
        internal const uint VMMDLL_MAP_IAT_VERSION =        2;
        internal const uint VMMDLL_MAP_HEAP_VERSION =       4;
        internal const uint VMMDLL_MAP_HEAPALLOC_VERSION =  1;
        internal const uint VMMDLL_MAP_THREAD_VERSION =     4;
        internal const uint VMMDLL_MAP_HANDLE_VERSION =     3;
        internal const uint VMMDLL_MAP_NET_VERSION =        3;
        internal const uint VMMDLL_MAP_PHYSMEM_VERSION =    2;
        internal const uint VMMDLL_MAP_POOL_VERSION =       2;
        internal const uint VMMDLL_MAP_USER_VERSION =       2;
        internal const uint VMMDLL_MAP_PFN_VERSION =        1;
        internal const uint VMMDLL_MAP_SERVICE_VERSION =    3;
        internal const uint VMMDLL_MEM_SEARCH_VERSION =     0xfe3e0002;
        internal const uint VMMDLL_REGISTRY_HIVE_INFORMATION_VERSION = 4;



        [DllImport("vmm", EntryPoint = "VMMDLL_InitializeEx")]
        internal static extern IntPtr VMMDLL_InitializeEx(
            int argc,
            string[] argv,
            out IntPtr ppLcErrorInfo);

        [DllImport("vmm", EntryPoint = "VMMDLL_CloseAll")]
        public static extern void VMMDLL_CloseAll();

        [DllImport("vmm", EntryPoint = "VMMDLL_Close")]
        public static extern void VMMDLL_Close(
            IntPtr hVMM);

        [DllImport("vmm", EntryPoint = "VMMDLL_ConfigGet")]
        public static extern bool VMMDLL_ConfigGet(
            IntPtr hVMM,
            ulong fOption,
            out ulong pqwValue);

        [DllImport("vmm", EntryPoint = "VMMDLL_ConfigSet")]
        public static extern bool VMMDLL_ConfigSet(
            IntPtr hVMM,
            ulong fOption,
            ulong qwValue);

        [DllImport("vmm", EntryPoint = "VMMDLL_MemFree")]
        internal static extern unsafe void VMMDLL_MemFree(
            byte* pvMem);



        // VFS (VIRTUAL FILE SYSTEM) FUNCTIONALITY BELOW:

        internal const uint VMMDLL_VFS_FILELIST_EXINFO_VERSION = 1;
        internal const uint VMMDLL_VFS_FILELIST_VERSION = 2;

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential)]
        internal struct VMMDLL_VFS_FILELIST
        {
            internal uint dwVersion;
            internal uint _Reserved;
            internal IntPtr pfnAddFile;
            internal IntPtr pfnAddDirectory;
            internal ulong h;
        }

        [DllImport("vmm", EntryPoint = "VMMDLL_VfsListU")]
        internal static extern unsafe bool VMMDLL_VfsList(
            IntPtr hVMM,
            [MarshalAs(UnmanagedType.LPUTF8Str)] string wcsPath,
            ref VMMDLL_VFS_FILELIST pFileList);

        [DllImport("vmm", EntryPoint = "VMMDLL_VfsReadU")]
        internal static extern unsafe uint VMMDLL_VfsRead(
            IntPtr hVMM,
            [MarshalAs(UnmanagedType.LPUTF8Str)] string wcsFileName,
            byte* pb,
            uint cb,
            out uint pcbRead,
            ulong cbOffset);

        [DllImport("vmm", EntryPoint = "VMMDLL_VfsWriteU")]
        internal static extern unsafe uint VMMDLL_VfsWrite(
            IntPtr hVMM,
            [MarshalAs(UnmanagedType.LPUTF8Str)] string wcsFileName,
            byte* pb,
            uint cb,
            out uint pcbRead,
            ulong cbOffset);



        // PLUGIN FUNCTIONALITY BELOW:

        [DllImport("vmm", EntryPoint = "VMMDLL_InitializePlugins")]
        public static extern bool VMMDLL_InitializePlugins(IntPtr hVMM);



        // MEMORY READ/WRITE FUNCTIONALITY BELOW:

        [DllImport("vmm", EntryPoint = "VMMDLL_MemReadScatter")]
        internal static extern unsafe uint VMMDLL_MemReadScatter(
            IntPtr hVMM,
            uint dwPID,
            IntPtr ppMEMs,
            uint cpMEMs,
            uint flags);

        [DllImport("vmm", EntryPoint = "VMMDLL_MemReadEx")]
        internal static extern unsafe bool VMMDLL_MemReadEx(
            IntPtr hVMM,
            uint dwPID,
            ulong qwA,
            byte* pb,
            uint cb,
            out uint pcbReadOpt,
            uint flags);

        [DllImport("vmm", EntryPoint = "VMMDLL_MemPrefetchPages")]
        internal static extern unsafe bool VMMDLL_MemPrefetchPages(
            IntPtr hVMM,
            uint dwPID,
            byte* pPrefetchAddresses,
            uint cPrefetchAddresses);

        [DllImport("vmm", EntryPoint = "VMMDLL_MemWrite")]
        internal static extern unsafe bool VMMDLL_MemWrite(
            IntPtr hVMM,
            uint dwPID,
            ulong qwA,
            byte* pb,
            uint cb);

        [DllImport("vmm", EntryPoint = "VMMDLL_MemVirt2Phys")]
        public static extern bool VMMDLL_MemVirt2Phys(
            IntPtr hVMM,
            uint dwPID,
            ulong qwVA,
            out ulong pqwPA
            );



        // MEMORY NEW SCATTER READ/WRITE FUNCTIONALITY BELOW:

        [DllImport("vmm", EntryPoint = "VMMDLL_Scatter_Initialize")]
        internal static extern unsafe IntPtr VMMDLL_Scatter_Initialize(
            IntPtr hVMM,
            uint dwPID,
            uint flags);

        [DllImport("vmm", EntryPoint = "VMMDLL_Scatter_Prepare")]
        internal static extern unsafe bool VMMDLL_Scatter_Prepare(
            IntPtr hS,
            ulong va,
            uint cb);

        [DllImport("vmm", EntryPoint = "VMMDLL_Scatter_PrepareWrite")]
        internal static extern unsafe bool VMMDLL_Scatter_PrepareWrite(
            IntPtr hS,
            ulong va,
            byte* pb,
            uint cb);

        [DllImport("vmm", EntryPoint = "VMMDLL_Scatter_ExecuteRead")]
        internal static extern unsafe bool VMMDLL_Scatter_ExecuteRead(
            IntPtr hS);

        [DllImport("vmm", EntryPoint = "VMMDLL_Scatter_Execute")]
        internal static extern unsafe bool VMMDLL_Scatter_Execute(
            IntPtr hS);

        [DllImport("vmm", EntryPoint = "VMMDLL_Scatter_Read")]
        internal static extern unsafe bool VMMDLL_Scatter_Read(
            IntPtr hS,
            ulong va,
            uint cb,
            byte* pb,
            out uint pcbRead);

        [DllImport("vmm", EntryPoint = "VMMDLL_Scatter_Clear")]
        public static extern bool SVMMDLL_Scatter_Clear(IntPtr hS, uint dwPID, uint flags);

        [DllImport("vmm", EntryPoint = "VMMDLL_Scatter_Clear")]
        internal static extern unsafe bool VMMDLL_Scatter_Clear(
            IntPtr hS,
            uint dwPID,
            uint flags);

        [DllImport("vmm", EntryPoint = "VMMDLL_Scatter_CloseHandle")]
        internal static extern unsafe void VMMDLL_Scatter_CloseHandle(
            IntPtr hS);



        // PROCESS FUNCTIONALITY BELOW:

        [DllImport("vmm", EntryPoint = "VMMDLL_PidList")]
        internal static extern unsafe bool VMMDLL_PidList(IntPtr hVMM, byte* pPIDs, ref ulong pcPIDs);

        [DllImport("vmm", EntryPoint = "VMMDLL_PidGetFromName")]
        public static extern bool VMMDLL_PidGetFromName(IntPtr hVMM, [MarshalAs(UnmanagedType.LPStr)] string szProcName, out uint pdwPID);

        [DllImport("vmm", EntryPoint = "VMMDLL_ProcessGetProcAddressW")]
        public static extern ulong VMMDLL_ProcessGetProcAddress(IntPtr hVMM, uint pid, [MarshalAs(UnmanagedType.LPWStr)] string wszModuleName, [MarshalAs(UnmanagedType.LPStr)] string szFunctionName);

        [DllImport("vmm", EntryPoint = "VMMDLL_ProcessGetModuleBaseW")]
        public static extern ulong VMMDLL_ProcessGetModuleBase(IntPtr hVMM, uint pid, [MarshalAs(UnmanagedType.LPWStr)] string wszModuleName);

        internal const ulong VMMDLL_PROCESS_INFORMATION_MAGIC =         0xc0ffee663df9301e;
        internal const ushort VMMDLL_PROCESS_INFORMATION_VERSION =      7;

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
            internal uint IntegrityLevel;
        }

        [DllImport("vmm", EntryPoint = "VMMDLL_ProcessGetInformation")]
        internal static extern unsafe bool VMMDLL_ProcessGetInformation(
            IntPtr hVMM,
            uint dwPID,
            byte* pProcessInformation,
            ref ulong pcbProcessInformation);

        [DllImport("vmm", EntryPoint = "VMMDLL_ProcessGetInformationString")]
        internal static extern unsafe byte* VMMDLL_ProcessGetInformationString(
            IntPtr hVMM,
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

        [DllImport("vmm", EntryPoint = "VMMDLL_ProcessGetDirectoriesW")]
        internal static extern unsafe bool VMMDLL_ProcessGetDirectories(
            IntPtr hVMM,
            uint dwPID,
            [MarshalAs(UnmanagedType.LPWStr)] string wszModule,
            byte* pData);

        [DllImport("vmm", EntryPoint = "VMMDLL_ProcessGetSectionsW")]
        internal static extern unsafe bool VMMDLL_ProcessGetSections(
            IntPtr hVMM,
            uint dwPID,
            [MarshalAs(UnmanagedType.LPWStr)] string wszModule,
            byte* pData,
            uint cData,
            out uint pcData);



        // WINDOWS SPECIFIC DEBUGGING / SYMBOL FUNCTIONALITY BELOW:

        [DllImport("vmm", EntryPoint = "VMMDLL_PdbLoad")]
        internal static extern unsafe bool VMMDLL_PdbLoad(
            IntPtr hVMM,
            uint dwPID,
            ulong vaModuleBase,
            byte* pModuleMapEntry);

        [DllImport("vmm", EntryPoint = "VMMDLL_PdbSymbolName")]
        internal static extern unsafe bool VMMDLL_PdbSymbolName(
            IntPtr hVMM,
            [MarshalAs(UnmanagedType.LPStr)] string szModule,
            ulong cbSymbolAddressOrOffset,
            byte* szSymbolName,
            out uint pdwSymbolDisplacement);

        [DllImport("vmm", EntryPoint = "VMMDLL_PdbSymbolAddress")]
        public static extern bool VMMDLL_PdbSymbolAddress(
            IntPtr hVMM,
            [MarshalAs(UnmanagedType.LPStr)] string szModule,
            [MarshalAs(UnmanagedType.LPStr)] string szSymbolName,
            out ulong pvaSymbolAddress);

        [DllImport("vmm", EntryPoint = "VMMDLL_PdbTypeSize")]
        public static extern bool VMMDLL_PdbTypeSize(
            IntPtr hVMM,
            [MarshalAs(UnmanagedType.LPStr)] string szModule,
            [MarshalAs(UnmanagedType.LPStr)] string szTypeName,
            out uint pcbTypeSize);

        [DllImport("vmm", EntryPoint = "VMMDLL_PdbTypeChildOffset")]
        public static extern bool VMMDLL_PdbTypeChildOffset(
            IntPtr hVMM,
            [MarshalAs(UnmanagedType.LPStr)] string szModule,
            [MarshalAs(UnmanagedType.LPStr)] string szTypeName,
            [MarshalAs(UnmanagedType.LPStr)] string wszTypeChildName,
            out uint pcbTypeChildOffset);




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

        [DllImport("vmm", EntryPoint = "VMMDLL_Map_GetPteW")]
        internal static extern unsafe bool VMMDLL_Map_GetPte(
            IntPtr hVMM,
            uint dwPid,
            bool fIdentifyModules,
            out IntPtr ppPteMap);



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

        [DllImport("vmm", EntryPoint = "VMMDLL_Map_GetVadW")]
        internal static extern unsafe bool VMMDLL_Map_GetVad(
            IntPtr hVMM,
            uint dwPid,
            bool fIdentifyModules,
            out IntPtr ppVadMap);



        // VMMDLL_Map_GetVadEx

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential)]
        internal struct VMMDLL_MAP_VADEXENTRY
        {
            internal uint tp;
            internal byte iPML;
            internal byte pteFlags;
            internal ushort _Reserved2;
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

        [DllImport("vmm", EntryPoint = "VMMDLL_Map_GetVadEx")]
        internal static extern unsafe bool VMMDLL_Map_GetVadEx(
            IntPtr hVMM,
            uint dwPid,
            uint oPage,
            uint cPage,
            out IntPtr ppVadExMap);



        // VMMDLL_Map_GetModule
        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential)]
        internal struct VMMDLL_MAP_MODULEENTRY_DEBUGINFO
        {
            internal uint dwAge;
            internal uint _Reserved;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)] internal byte[] Guid;
            [MarshalAs(UnmanagedType.LPWStr)] internal string wszGuid;
            [MarshalAs(UnmanagedType.LPWStr)] internal string wszPdbFilename;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential)]
        internal struct VMMDLL_MAP_MODULEENTRY_VERSIONINFO
        {
            [MarshalAs(UnmanagedType.LPWStr)] internal string wszCompanyName;
            [MarshalAs(UnmanagedType.LPWStr)] internal string wszFileDescription;
            [MarshalAs(UnmanagedType.LPWStr)] internal string wszFileVersion;
            [MarshalAs(UnmanagedType.LPWStr)] internal string wszInternalName;
            [MarshalAs(UnmanagedType.LPWStr)] internal string wszLegalCopyright;
            [MarshalAs(UnmanagedType.LPWStr)] internal string wszFileOriginalFilename;
            [MarshalAs(UnmanagedType.LPWStr)] internal string wszProductName;
            [MarshalAs(UnmanagedType.LPWStr)] internal string wszProductVersion;
        }

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
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 3)] internal ulong[] _Reserved1;
            internal IntPtr pExDebugInfo;
            internal IntPtr pExVersionInfo;
        }

        internal struct VMMDLL_MAP_MODULE
        {
            internal uint dwVersion;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 5)] internal uint[] _Reserved1;
            internal ulong pbMultiText;
            internal uint cbMultiText;
            internal uint cMap;
        }

        [DllImport("vmm", EntryPoint = "VMMDLL_Map_GetModuleW")]
        internal static extern unsafe bool VMMDLL_Map_GetModule(
            IntPtr hVMM,
            uint dwPid,
            out IntPtr ppModuleMap,
            uint flags);

        // VMMDLL_Map_GetModuleFromName

        [DllImport("vmm", EntryPoint = "VMMDLL_Map_GetModuleFromNameW")]
        internal static extern unsafe bool VMMDLL_Map_GetModuleFromName(
            IntPtr hVMM,
            uint dwPID,
            [MarshalAs(UnmanagedType.LPWStr)] string wszModuleName,
            out IntPtr ppModuleMapEntry,
            uint flags);



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

        [DllImport("vmm", EntryPoint = "VMMDLL_Map_GetUnloadedModuleW")]
        internal static extern unsafe bool VMMDLL_Map_GetUnloadedModule(
            IntPtr hVMM,
            uint dwPid,
            out IntPtr ppModuleMap);



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
            [MarshalAs(UnmanagedType.LPWStr)] internal string wszForwardedFunction;
        }

        internal struct VMMDLL_MAP_EAT
        {
            internal uint dwVersion;
            internal uint dwOrdinalBase;
            internal uint cNumberOfNames;
            internal uint cNumberOfFunctions;
            internal uint cNumberOfForwardedFunctions;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 3)] internal uint[] _Reserved1;
            internal ulong vaModuleBase;
            internal ulong vaAddressOfFunctions;
            internal ulong vaAddressOfNames;
            internal ulong pbMultiText;
            internal uint cbMultiText;
            internal uint cMap;
        }

        [DllImport("vmm", EntryPoint = "VMMDLL_Map_GetEATW")]
        internal static extern unsafe bool VMMDLL_Map_GetEAT(
            IntPtr hVMM,
            uint dwPid,
            [MarshalAs(UnmanagedType.LPWStr)] string wszModuleName,
            out IntPtr ppEatMap);



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

        [DllImport("vmm", EntryPoint = "VMMDLL_Map_GetIATW")]
        internal static extern unsafe bool VMMDLL_Map_GetIAT(
            IntPtr hVMM,
            uint dwPid,
            [MarshalAs(UnmanagedType.LPWStr)] string wszModuleName,
            out IntPtr ppIatMap);



        // VMMDLL_Map_GetHeap

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential)]
        internal struct VMMDLL_MAP_HEAPENTRY
        {
            internal ulong va;
            internal uint tp;
            internal bool f32;
            internal uint iHeap;
            internal uint dwHeapNum;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential)]
        internal struct VMMDLL_MAP_HEAPSEGMENTENTRY
        {
            internal ulong va;
            internal uint cb;
            internal ushort tp;
            internal ushort iHeap;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential)]
        internal struct VMMDLL_MAP_HEAP
        {
            internal uint dwVersion;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 7)] internal uint[] _Reserved1;
            internal IntPtr pSegments;
            internal uint cSegments;
            internal uint cMap;
        }

        [DllImport("vmm", EntryPoint = "VMMDLL_Map_GetHeap")]
        internal static extern unsafe bool VMMDLL_Map_GetHeap(
            IntPtr hVMM,
            uint dwPid,
            out IntPtr ppHeapMap);



        // VMMDLL_Map_GetHeapAlloc

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential)]
        internal struct VMMDLL_MAP_HEAPALLOCENTRY
        {
            internal ulong va;
            internal uint cb;
            internal uint tp;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential)]
        internal struct VMMDLL_MAP_HEAPALLOC
        {
            internal uint dwVersion;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 7)] internal uint[] _Reserved1;
            internal IntPtr _Reserved20;
            internal IntPtr _Reserved21;
            internal uint cMap;
        }

        [DllImport("vmm", EntryPoint = "VMMDLL_Map_GetHeapAlloc")]
        internal static extern unsafe bool VMMDLL_Map_GetHeapAlloc(
            IntPtr hVMM,
            uint dwPid,
            ulong qwHeapNumOrAddress,
            out IntPtr ppHeapAllocMap);



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
            internal byte bWaitReason;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 2)] internal byte[] _FutureUse1;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 11)] internal uint[] _FutureUse2;
            internal ulong vaImpersonationToken;
            internal ulong vaWin32StartAddress;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential)]
        internal struct VMMDLL_MAP_THREAD
        {
            internal uint dwVersion;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)] internal uint[] _Reserved1;
            internal uint cMap;
        }

        [DllImport("vmm", EntryPoint = "VMMDLL_Map_GetThread")]
        internal static extern unsafe bool VMMDLL_Map_GetThread(
            IntPtr hVMM,
            uint dwPid,
            out IntPtr ppThreadMap);



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
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 7)] internal uint[] _FutureUse;
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

        [DllImport("vmm", EntryPoint = "VMMDLL_Map_GetHandleW")]
        internal static extern unsafe bool VMMDLL_Map_GetHandle(
            IntPtr hVMM,
            uint dwPid,
            out IntPtr ppHandleMap);



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

        [DllImport("vmm", EntryPoint = "VMMDLL_Map_GetNetW")]
        internal static extern unsafe bool VMMDLL_Map_GetNet(
            IntPtr hVMM,
            out IntPtr ppNetMap);



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

        [DllImport("vmm", EntryPoint = "VMMDLL_Map_GetPhysMem")]
        internal static extern unsafe bool VMMDLL_Map_GetPhysMem(
            IntPtr hVMM,
            out IntPtr ppPhysMemMap);



        // VMMDLL_Map_GetPool

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential)]
        internal struct VMMDLL_MAP_POOLENTRY
        {
            internal ulong va;
            internal uint dwTag;
            internal byte _ReservedZero;
            internal byte fAlloc;
            internal byte tpPool;
            internal byte tpSS;
            internal uint cb;
            internal uint _Filler;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential)]
        internal struct VMMDLL_MAP_POOL
        {
            internal uint dwVersion;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 6)] internal uint[] _Reserved1;
            internal uint cbTotal;
            internal IntPtr _piTag2Map;
            internal IntPtr _pTag;
            internal uint cTag;
            internal uint cMap;
        }

        [DllImport("vmm", EntryPoint = "VMMDLL_Map_GetPool")]
        internal static extern unsafe bool VMMDLL_Map_GetPool(
            IntPtr hVMM,
            out IntPtr ppHeapAllocMap,
            uint flags);



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

        [DllImport("vmm", EntryPoint = "VMMDLL_Map_GetUsersW")]
        internal static extern unsafe bool VMMDLL_Map_GetUsers(
            IntPtr hVMM,
            out IntPtr ppUserMap);



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

        [DllImport("vmm", EntryPoint = "VMMDLL_Map_GetServicesW")]
        internal static extern unsafe bool VMMDLL_Map_GetServices(
            IntPtr hVMM,
            out IntPtr ppServiceMap);



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

        [DllImport("vmm", EntryPoint = "VMMDLL_Map_GetPfn")]
        internal static extern unsafe bool VMMDLL_Map_GetPfn(
            IntPtr hVMM,
            byte* pPfns,
            uint cPfns,
            byte* pPfnMap,
            ref uint pcbPfnMap);



        // REGISTRY FUNCTIONALITY BELOW:

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential)]
        internal struct VMMDLL_REGISTRY_HIVE_INFORMATION
        {
            internal ulong magic;
            internal ushort wVersion;
            internal ushort wSize;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 0x34)] internal byte[] _FutureReserved1;
            internal ulong vaCMHIVE;
            internal ulong vaHBASE_BLOCK;
            internal uint cbLength;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 128)] internal byte[] uszName;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 33)] internal byte[] uszNameShort;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 260)] internal byte[] uszHiveRootPath;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 0x10)] internal ulong[] _FutureReserved;
        }

        [DllImport("vmm", EntryPoint = "VMMDLL_WinReg_HiveList")]
        internal static extern unsafe bool VMMDLL_WinReg_HiveList(
            IntPtr hVMM,
            byte* pHives,
            uint cHives,
            out uint pcHives);

        [DllImport("vmm", EntryPoint = "VMMDLL_WinReg_HiveReadEx")]
        internal static extern unsafe bool VMMDLL_WinReg_HiveReadEx(
            IntPtr hVMM,
            ulong vaCMHive,
            uint ra,
            byte* pb,
            uint cb,
            out uint pcbReadOpt,
            uint flags);

        [DllImport("vmm", EntryPoint = "VMMDLL_WinReg_HiveWrite")]
        internal static extern unsafe bool VMMDLL_WinReg_HiveWrite(
            IntPtr hVMM,
            ulong vaCMHive,
            uint ra,
            byte* pb,
            uint cb);

        [DllImport("vmm", EntryPoint = "VMMDLL_WinReg_EnumKeyExW")]
        internal static extern unsafe bool VMMDLL_WinReg_EnumKeyExW(
            IntPtr hVMM,
            [MarshalAs(UnmanagedType.LPWStr)] string wszFullPathKey,
            uint dwIndex,
            byte* lpName,
            ref uint lpcchName,
            out ulong lpftLastWriteTime);

        [DllImport("vmm", EntryPoint = "VMMDLL_WinReg_EnumValueW")]
        internal static extern unsafe bool VMMDLL_WinReg_EnumValueW(
            IntPtr hVMM,
            [MarshalAs(UnmanagedType.LPWStr)] string wszFullPathKey,
            uint dwIndex,
            byte* lpValueName,
            ref uint lpcchValueName,
            out uint lpType,
            byte* lpData,
            ref uint lpcbData);

        [DllImport("vmm", EntryPoint = "VMMDLL_WinReg_QueryValueExW")]
        internal static extern unsafe bool VMMDLL_WinReg_QueryValueExW(
            IntPtr hVMM,
            [MarshalAs(UnmanagedType.LPWStr)] string wszFullPathKeyValue,
            out uint lpType,
            byte* lpData,
            ref uint lpcbData);



        // MEMORY SEARCH FUNCTIONALITY BELOW:

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential)]
        internal struct VMMDLL_MEM_SEARCH_CONTEXT_SEARCHENTRY
        {
            internal uint cbAlign;
            internal uint cb;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)] internal byte[] pb;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)] internal byte[] pbSkipMask;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential)]
        internal struct VMMDLL_MEM_SEARCH_CONTEXT
        {
            internal uint dwVersion;
            internal uint _Filler01;
            internal uint _Filler02;
            internal bool fAbortRequested;
            internal uint cMaxResult;
            internal uint cSearch;
            [MarshalAs(UnmanagedType.ByValArray, ArraySubType = UnmanagedType.Struct, SizeConst = 16)] internal vmmi.VMMDLL_MEM_SEARCH_CONTEXT_SEARCHENTRY[] search;
            internal ulong vaMin;
            internal ulong vaMax;
            internal ulong vaCurrent;
            internal uint _Filler2;
            internal uint cResult;
            internal ulong cbReadTotal;
            internal IntPtr pvUserPtrOpt;
            internal IntPtr pfnResultOptCB;
            internal ulong ReadFlags;
            internal bool fForcePTE;
            internal bool fForceVAD;
            internal IntPtr pfnFilterOptCB;
        }

        [DllImport("vmm", EntryPoint = "VMMDLL_MemSearch")]
        internal static extern unsafe bool VMMDLL_MemSearch(
            IntPtr hVMM,
            uint dwPID,
            ref VMMDLL_MEM_SEARCH_CONTEXT ctx,
            out IntPtr ppva,
            out uint pcva);

    }
}
