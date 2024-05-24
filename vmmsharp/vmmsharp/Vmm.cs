using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;
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
    /// MemProcFS public API
    /// </summary>
    public class Vmm : IDisposable
    {
        public static implicit operator IntPtr(Vmm x) => x.hVMM;
        private bool disposed = false;
        protected IntPtr hVMM = IntPtr.Zero;

        /// <summary>
        /// Underlying LeechCore handle.
        /// </summary>
        public LeechCore LeechCore { get; }

        /// <summary>
        /// Returns All Processes on the Target System.
        /// </summary>
        public VmmProcess[] Processes =>
            PIDs.Select(pid => new VmmProcess(this, pid)).ToArray();

        /// <summary>
        /// Returns All Process IDs on the Target System.
        /// </summary>
        public unsafe uint[] PIDs
        {
            get
            {
                bool result;
                ulong c = 0;
                result = Vmmi.VMMDLL_PidList(hVMM, null, ref c);
                if (!result || (c == 0)) { return new uint[0]; }
                fixed (byte* pb = new byte[c * 4])
                {
                    result = Vmmi.VMMDLL_PidList(hVMM, pb, ref c);
                    if (!result || (c == 0)) { return new uint[0]; }
                    uint[] m = new uint[c];
                    for (ulong i = 0; i < c; i++)
                    {
                        m[i] = (uint)Marshal.ReadInt32((System.IntPtr)(pb + i * 4));
                    }
                    return m;
                }
            }
        }

        // private zero-argument constructor - do not use!
        private Vmm()
        {
        }

        protected static unsafe IntPtr Initialize(out LeechCore.LC_CONFIG_ERRORINFO configErrorInfo, params string[] args)
        {
            IntPtr pLcErrorInfo;
            int cbERROR_INFO = System.Runtime.InteropServices.Marshal.SizeOf<Lci.LC_CONFIG_ERRORINFO>();
            IntPtr hVMM = Vmmi.VMMDLL_InitializeEx(args.Length, args, out pLcErrorInfo);
            long vaLcCreateErrorInfo = pLcErrorInfo.ToInt64();
            configErrorInfo = new LeechCore.LC_CONFIG_ERRORINFO();
            configErrorInfo.strUserText = "";
            if (hVMM.ToInt64() == 0)
            {
                throw new VmmException("VMM INIT FAILED.");
            }
            if (vaLcCreateErrorInfo == 0)
            {
                return hVMM;
            }
            Lci.LC_CONFIG_ERRORINFO e = Marshal.PtrToStructure<Lci.LC_CONFIG_ERRORINFO>(pLcErrorInfo);
            if (e.dwVersion == LeechCore.LC_CONFIG_ERRORINFO_VERSION)
            {
                configErrorInfo.fValid = true;
                configErrorInfo.fUserInputRequest = e.fUserInputRequest;
                if (e.cwszUserText > 0)
                {
                    configErrorInfo.strUserText = Marshal.PtrToStringUni((System.IntPtr)(vaLcCreateErrorInfo + cbERROR_INFO));
                }
            }
            return hVMM;
        }

        public Vmm(out LeechCore.LC_CONFIG_ERRORINFO configErrorInfo, params string[] args)
        {
            this.hVMM = Vmm.Initialize(out configErrorInfo, args);
            this.LeechCore = new LeechCore("existing");
        }

        public Vmm(params string[] args)
        {
            LeechCore.LC_CONFIG_ERRORINFO errorInfo;
            this.hVMM = Vmm.Initialize(out errorInfo, args);
            this.LeechCore = new LeechCore("existing");
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

        protected virtual void Dispose(bool disposing)
        {
            if (!this.disposed)
            {
                Vmmi.VMMDLL_Close(hVMM);
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
            Vmmi.VMMDLL_CloseAll();
        }

        public const ulong OPT_CORE_PRINTF_ENABLE = 0x4000000100000000;  // RW
        public const ulong OPT_CORE_VERBOSE = 0x4000000200000000;  // RW
        public const ulong OPT_CORE_VERBOSE_EXTRA = 0x4000000300000000;  // RW
        public const ulong OPT_CORE_VERBOSE_EXTRA_TLP = 0x4000000400000000;  // RW
        public const ulong OPT_CORE_MAX_NATIVE_ADDRESS = 0x4000000800000000;  // R
        public const ulong OPT_CORE_LEECHCORE_HANDLE = 0x4000001000000000;  // R - underlying leechcore handle (do not close).

        public const ulong OPT_CORE_SYSTEM = 0x2000000100000000;  // R
        public const ulong OPT_CORE_MEMORYMODEL = 0x2000000200000000;  // R

        public const ulong OPT_CONFIG_IS_REFRESH_ENABLED = 0x2000000300000000;  // R - 1/0
        public const ulong OPT_CONFIG_TICK_PERIOD = 0x2000000400000000;  // RW - base tick period in ms
        public const ulong OPT_CONFIG_READCACHE_TICKS = 0x2000000500000000;  // RW - memory cache validity period (in ticks)
        public const ulong OPT_CONFIG_TLBCACHE_TICKS = 0x2000000600000000;  // RW - page table (tlb) cache validity period (in ticks)
        public const ulong OPT_CONFIG_PROCCACHE_TICKS_PARTIAL = 0x2000000700000000;  // RW - process refresh (partial) period (in ticks)
        public const ulong OPT_CONFIG_PROCCACHE_TICKS_TOTAL = 0x2000000800000000;  // RW - process refresh (full) period (in ticks)
        public const ulong OPT_CONFIG_VMM_VERSION_MAJOR = 0x2000000900000000;  // R
        public const ulong OPT_CONFIG_VMM_VERSION_MINOR = 0x2000000A00000000;  // R
        public const ulong OPT_CONFIG_VMM_VERSION_REVISION = 0x2000000B00000000;  // R
        public const ulong OPT_CONFIG_STATISTICS_FUNCTIONCALL = 0x2000000C00000000;  // RW - enable function call statistics (.status/statistics_fncall file)
        public const ulong OPT_CONFIG_IS_PAGING_ENABLED = 0x2000000D00000000;  // RW - 1/0
        public const ulong OPT_CONFIG_DEBUG = 0x2000000E00000000;  // W
        public const ulong OPT_CONFIG_YARA_RULES = 0x2000000F00000000;  // R

        public const ulong OPT_WIN_VERSION_MAJOR = 0x2000010100000000;  // R
        public const ulong OPT_WIN_VERSION_MINOR = 0x2000010200000000;  // R
        public const ulong OPT_WIN_VERSION_BUILD = 0x2000010300000000;  // R
        public const ulong OPT_WIN_SYSTEM_UNIQUE_ID = 0x2000010400000000;  // R

        public const ulong OPT_FORENSIC_MODE = 0x2000020100000000;  // RW - enable/retrieve forensic mode type [0-4].

        // REFRESH OPTIONS:
        public const ulong OPT_REFRESH_ALL = 0x2001ffff00000000;  // W - refresh all caches
        public const ulong OPT_REFRESH_FREQ_MEM = 0x2001100000000000;  // W - refresh memory cache (excl. TLB) [fully]
        public const ulong OPT_REFRESH_FREQ_MEM_PARTIAL = 0x2001000200000000;  // W - refresh memory cache (excl. TLB) [partial 33%/call]
        public const ulong OPT_REFRESH_FREQ_TLB = 0x2001080000000000;  // W - refresh page table (TLB) cache [fully]
        public const ulong OPT_REFRESH_FREQ_TLB_PARTIAL = 0x2001000400000000;  // W - refresh page table (TLB) cache [partial 33%/call]
        public const ulong OPT_REFRESH_FREQ_FAST = 0x2001040000000000;  // W - refresh fast frequency - incl. partial process refresh
        public const ulong OPT_REFRESH_FREQ_MEDIUM = 0x2001000100000000;  // W - refresh medium frequency - incl. full process refresh
        public const ulong OPT_REFRESH_FREQ_SLOW = 0x2001001000000000;  // W - refresh slow frequency.

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

        public bool ConfigGet(ulong fOption, out ulong pqwValue)
        {
            return Vmmi.VMMDLL_ConfigGet(hVMM, fOption, out pqwValue);
        }

        public bool ConfigSet(ulong fOption, ulong qwValue)
        {
            return Vmmi.VMMDLL_ConfigSet(hVMM, fOption, qwValue);
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
        // MEMORY READ/WRITE FUNCTIONALITY BELOW:
        //---------------------------------------------------------------------

        public const uint PID_PHYSICALMEMORY = unchecked((uint)-1);  // Pass as a PID Parameter to read Physical Memory
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
        /// <param name="pid">Process ID for this operation. -1 for Physical Memory (PID_PHYSICALMEMORY Constant).</param>
        /// <param name="flags">VMM Flags</param>
        /// <param name="qwA">Array of Virtual Addresses to read.</param>
        /// <returns>Array of MEM_SCATTER structures.</returns>
        public unsafe LeechCore.MEM_SCATTER[] MemReadScatter(uint pid, uint flags, params ulong[] qwA)
        {
            int i;
            long vappMEMs, vapMEM;
            IntPtr pMEM, pMEM_qwA, pppMEMs;
            if (!Lci.LcAllocScatter1((uint)qwA.Length, out pppMEMs))
                throw new VmmException("LcAllocScatter1 FAIL");
            vappMEMs = pppMEMs.ToInt64();
            for (i = 0; i < qwA.Length; i++)
            {
                vapMEM = Marshal.ReadIntPtr(new IntPtr(vappMEMs + i * 8)).ToInt64();
                pMEM_qwA = new IntPtr(vapMEM + 8);
                Marshal.WriteInt64(pMEM_qwA, (long)(qwA[i] & ~(ulong)0xfff));
            }
            LeechCore.MEM_SCATTER[] MEMs = new LeechCore.MEM_SCATTER[qwA.Length];
            _ = Vmmi.VMMDLL_MemReadScatter(hVMM, pid, pppMEMs, (uint)MEMs.Length, flags);
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

#if NET5_0_OR_GREATER
        /// <summary>
        /// Perform a scatter read of multiple page-sized physical memory ranges.
        /// Does not copy the read memory to a managed byte buffer, but instead allows direct access to the native memory via a Span view.
        /// </summary>
        /// <param name="pid">Process ID for this operation. -1 for Physical Memory (PID_PHYSICALMEMORY Constant).</param>
        /// <param name="flags">Vmm Flags.</param>
        /// <param name="qwA">Array of page-aligned Memory Addresses.</param>
        /// <returns>SCATTER_HANDLE</returns>
        /// <exception cref="VmmException"></exception>
        public unsafe LeechCore.SCATTER_HANDLE MemReadScatter2(uint pid, uint flags, params ulong[] qwA)
        {
            if (!Lci.LcAllocScatter1((uint)qwA.Length, out IntPtr pppMEMs))
                throw new VmmException("LcAllocScatter1 FAIL");
            var ppMEMs = (LeechCore.tdMEM_SCATTER**)pppMEMs.ToPointer();
            for (int i = 0; i < qwA.Length; i++)
            {
                var pMEM = ppMEMs[i];
                pMEM->qwA = qwA[i] & ~(ulong)0xfff;
            }
            var results = new Dictionary<ulong, LeechCore.SCATTER_PAGE>(qwA.Length);
            _ = Vmmi.VMMDLL_MemReadScatter(hVMM, pid, pppMEMs, (uint)qwA.Length, flags);
            for (int i = 0; i < qwA.Length; i++)
            {
                var pMEM = ppMEMs[i];
                if (pMEM->f != 0)
                    results[pMEM->qwA] = new LeechCore.SCATTER_PAGE(pMEM->pb);
            }
            return new LeechCore.SCATTER_HANDLE(results, pppMEMs);
        }

#endif

        public VmmScatter Scatter_Initialize(uint pid, uint flags)
        {
            IntPtr hS = Vmmi.VMMDLL_Scatter_Initialize(hVMM, pid, flags);
            if (hS.ToInt64() == 0) { return null; }
            return new VmmScatter(hS, pid);
        }

        /// <summary>
        /// Read Memory from a Virtual Address into a managed byte-array.
        /// </summary>
        /// <param name="pid">Process ID for this operation. -1 for Physical Memory (PID_PHYSICALMEMORY Constant).</param>
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
        /// <param name="pid">Process ID for this operation. -1 for Physical Memory (PID_PHYSICALMEMORY Constant).</param>
        /// <param name="qwA">Virtual Address to read from.</param>
        /// <param name="pb">Pointer to buffer to receive read.</param>
        /// <param name="cb">Count of bytes to read.</param>
        /// <param name="cbRead">Count of bytes successfully read.</param>
        /// <param name="flags">VMM Flags.</param>
        /// <returns>True if successful, otherwise False. Be sure to check cbRead count.</returns>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public unsafe bool MemRead(uint pid, ulong qwA, IntPtr pb, uint cb, out uint cbRead, uint flags = 0) =>
            MemRead(pid, qwA, pb.ToPointer(), cb, out cbRead, flags);

        /// <summary>
        /// Read Memory from a Virtual Address into unmanaged memory.
        /// </summary>
        /// <param name="pid">Process ID for this operation. -1 for Physical Memory (PID_PHYSICALMEMORY Constant).</param>
        /// <param name="qwA">Virtual Address to read from.</param>
        /// <param name="pb">Pointer to buffer to receive read.</param>
        /// <param name="cb">Count of bytes to read.</param>
        /// <param name="cbRead">Count of bytes successfully read.</param>
        /// <param name="flags">VMM Flags.</param>
        /// <returns>True if successful, otherwise False. Be sure to check cbRead count.</returns>
        public unsafe bool MemRead(uint pid, ulong qwA, void* pb, uint cb, out uint cbRead, uint flags = 0)
        {
            return Vmmi.VMMDLL_MemReadEx(hVMM, pid, qwA, (byte*)pb, cb, out cbRead, flags);
        }

        /// <summary>
        /// Read Memory from a Virtual Address into a nullable struct of Type <typeparamref name="T"/>.
        /// </summary>
        /// <typeparam name="T">Struct Type.</typeparam>
        /// <param name="pid">Process ID for this operation. -1 for Physical Memory (PID_PHYSICALMEMORY Constant).</param>
        /// <param name="qwA">Virtual Address to read from.</param>
        /// <param name="flags">VMM Flags.</param>
        /// <returns>Result if successful, otherwise NULL.</returns>
        public unsafe T? MemReadStruct<T>(uint pid, ulong qwA, uint flags = 0)
            where T : unmanaged
        {
            uint cb = (uint)sizeof(T);
            T result = default;
            if (!Vmmi.VMMDLL_MemReadEx(hVMM, pid, qwA, (byte*)&result, cb, out uint cbRead, flags) ||
                cbRead != cb)
                return null;
            return result;
        }

        /// <summary>
        /// Read Memory from a Virtual Address into an Array of Type <typeparamref name="T"/>.
        /// </summary>
        /// <typeparam name="T">Value Type.</typeparam>
        /// <param name="pid">Process ID for this operation. -1 for Physical Memory (PID_PHYSICALMEMORY Constant).</param>
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
                if (!Vmmi.VMMDLL_MemReadEx(hVMM, pid, qwA, (byte*)pb, cb, out cbRead, flags))
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

#if NET5_0_OR_GREATER
        /// <summary>
        /// Read memory into a Span of <typeparamref name="T"/>.
        /// </summary>
        /// <typeparam name="T">Value Type</typeparam>
        /// <param name="pid">Process ID for this operation. -1 for Physical Memory (PID_PHYSICALMEMORY Constant).</param>
        /// <param name="addr">Memory address to read from.</param>
        /// <param name="span">Span to receive the memory read.</param>
        /// <param name="cbRead">Number of bytes successfully read.</param>
        /// <param name="flags">Read flags.</param>
        /// <returns>True if successful, otherwise False.
        /// Please be sure to also check the cbRead out value.</returns>
        public unsafe bool MemReadSpan<T>(uint pid, ulong addr, Span<T> span, out uint cbRead, uint flags)
            where T : unmanaged
        {
            uint cb = (uint)(sizeof(T) * span.Length);
            fixed (T* pb = span)
            {
                return Vmmi.VMMDLL_MemReadEx(hVMM, pid, addr, (byte*)pb, cb, out cbRead, flags);
            }
        }

        /// <summary>
        /// Write memory from a Span of <typeparamref name="T"/> to a specified memory address.
        /// </summary>
        /// <typeparam name="T">Value Type</typeparam>
        /// <param name="pid">Process ID for this operation. -1 for Physical Memory (PID_PHYSICALMEMORY Constant).</param>
        /// <param name="addr">Memory address to write to.</param>
        /// <param name="span">Span to write from.</param>
        /// <returns>True if successful, otherwise False.</returns>
        public unsafe bool MemWriteSpan<T>(uint pid, ulong addr, Span<T> span)
            where T : unmanaged
        {
            uint cb = (uint)(sizeof(T) * span.Length);
            fixed (T* pb = span)
            {
                return Vmmi.VMMDLL_MemWrite(hVMM, pid, addr, (byte*)pb, cb);
            }
        }
#endif

        /// <summary>
        /// Read Memory from a Virtual Address into a Managed String.
        /// </summary>
        /// <param name="encoding">String Encoding for this read.</param>
        /// <param name="pid">Process ID for this operation. -1 for Physical Memory (PID_PHYSICALMEMORY Constant).</param>
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
                return Vmmi.VMMDLL_MemPrefetchPages(hVMM, pid, pb, (uint)qwA.Length);
            }
        }

        /// <summary>
        /// Write Memory from a managed byte-array to a given Virtual Address.
        /// </summary>
        /// <param name="pid">Process ID for this operation. -1 for Physical Memory (PID_PHYSICALMEMORY Constant).</param>
        /// <param name="qwA">Virtual Address to write to.</param>
        /// <param name="data">Data to be written.</param>
        /// <returns>True if write successful, otherwise False.</returns>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public unsafe bool MemWrite(uint pid, ulong qwA, byte[] data) =>
            MemWriteArray<byte>(pid, qwA, data);

        /// <summary>
        /// Write Memory from unmanaged memory to a given Virtual Address.
        /// </summary>
        /// <param name="pid">Process ID for this operation. -1 for Physical Memory (PID_PHYSICALMEMORY Constant).</param>
        /// <param name="qwA">Virtual Address to write to.</param>
        /// <param name="pb">Pointer to buffer to write from.</param>
        /// <param name="cb">Count of bytes to write.</param>
        /// <returns>True if write successful, otherwise False.</returns>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public unsafe bool MemWrite(uint pid, ulong qwA, IntPtr pb, uint cb) =>
            MemWrite(pid, qwA, pb.ToPointer(), cb);

        /// <summary>
        /// Write Memory from unmanaged memory to a given Virtual Address.
        /// </summary>
        /// <param name="pid">Process ID for this operation. -1 for Physical Memory (PID_PHYSICALMEMORY Constant).</param>
        /// <param name="qwA">Virtual Address to write to.</param>
        /// <param name="pb">Pointer to buffer to write from.</param>
        /// <param name="cb">Count of bytes to write.</param>
        /// <returns>True if write successful, otherwise False.</returns>
        public unsafe bool MemWrite(uint pid, ulong qwA, void* pb, uint cb) =>
            Vmmi.VMMDLL_MemWrite(hVMM, pid, qwA, (byte*)pb, cb);

        /// <summary>
        /// Write Memory from a struct value <typeparamref name="T"/> to a given Virtual Address.
        /// </summary>
        /// <typeparam name="T">Value Type.</typeparam>
        /// <param name="pid">Process ID for this operation. -1 for Physical Memory (PID_PHYSICALMEMORY Constant).</param>
        /// <param name="qwA">Virtual Address to write to.</param>
        /// <param name="value"><typeparamref name="T"/> Value to write.</param>
        /// <returns>True if write successful, otherwise False.</returns>
        public unsafe bool MemWriteStruct<T>(uint pid, ulong qwA, T value)
            where T : unmanaged
        {
            uint cb = (uint)sizeof(T);
            return Vmmi.VMMDLL_MemWrite(hVMM, pid, qwA, (byte*)&value, cb);
        }

        /// <summary>
        /// Write Memory from a managed <typeparamref name="T"/> Array to a given Virtual Address.
        /// </summary>
        /// <typeparam name="T">Value Type.</typeparam>
        /// <param name="pid">Process ID for this operation. -1 for Physical Memory (PID_PHYSICALMEMORY Constant).</param>
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
                return Vmmi.VMMDLL_MemWrite(hVMM, pid, qwA, (byte*)pb, cb);
            }
        }

        public bool MemVirt2Phys(uint pid, ulong qwVA, out ulong pqwPA)
        {
            return Vmmi.VMMDLL_MemVirt2Phys(hVMM, pid, qwVA, out pqwPA);
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
            Vmmi.VMMDLL_VFS_FILELIST FileList;
            FileList.dwVersion = Vmmi.VMMDLL_VFS_FILELIST_VERSION;
            FileList.h = h;
            FileList._Reserved = 0;
            FileList.pfnAddFile = Marshal.GetFunctionPointerForDelegate(CallbackFile);
            FileList.pfnAddDirectory = Marshal.GetFunctionPointerForDelegate(CallbackDirectory);
            return Vmmi.VMMDLL_VfsList(hVMM, wszPath, ref FileList);
        }

        public unsafe uint VfsRead(string wszFileName, uint cb, ulong cbOffset, out byte[] pbData)
        {
            uint nt, cbRead = 0;
            byte[] data = new byte[cb];
            fixed (byte* pb = data)
            {
                nt = Vmmi.VMMDLL_VfsRead(hVMM, wszFileName, pb, cb, out cbRead, cbOffset);
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
                return Vmmi.VMMDLL_VfsWrite(hVMM, wszFileName, pb, (uint)pbData.Length, out cbRead, cbOffset);
            }
        }



        //---------------------------------------------------------------------
        // PLUGIN FUNCTIONALITY BELOW:
        //---------------------------------------------------------------------

        public bool InitializePlugins()
        {
            return Vmmi.VMMDLL_InitializePlugins(hVMM);
        }

        //---------------------------------------------------------------------
        // PROCESS FUNCTIONALITY BELOW:
        //---------------------------------------------------------------------

        /// <summary>
        /// Lookup a process by its name.
        /// Validation is also performed to ensure the process is valid.
        /// </summary>
        /// <param name="szProcName">Process name to get.</param>
        /// <param name="process">Process result. NULL if not found.</param>
        /// <returns>True if successful, otherwise False.</returns>
        public bool ProcessGetFromName(string szProcName, out VmmProcess process)
        {
            if (Vmmi.VMMDLL_PidGetFromName(hVMM, szProcName, out uint pdwPID))
            {
                process = new VmmProcess(this, pdwPID);
                return true;
            }
            process = default;
            return false;
        }

        /// <summary>
        /// Lookup a Process by its Process ID.
        /// Validation is also performed to ensure the process is valid.
        /// </summary>
        /// <param name="pid">Process ID to get.</param>
        /// <param name="process">Process result. NULL if not found.</param>
        /// <returns>True if successful, otherwise False.</returns>
        public bool ProcessGetFromPid(uint pid, out VmmProcess process)
        {
            process = new VmmProcess(this, pid);
            if (process.IsValid)
                return true;
            process = default;
            return false;
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
                bool result = Vmmi.VMMDLL_PdbLoad(hVMM, pid, vaModuleBase, pb);
                if (!result) { return false; }
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
                bool result = Vmmi.VMMDLL_PdbSymbolName(hVMM, szModule, cbSymbolAddressOrOffset, pb, out pdwSymbolDisplacement);
                if (!result) { return false; }
                szSymbolName = Encoding.UTF8.GetString(data);
                szSymbolName = szSymbolName.Substring(0, szSymbolName.IndexOf((char)0));
            }
            return true;
        }

        public bool PdbSymbolAddress(string szModule, string szSymbolName, out ulong pvaSymbolAddress)
        {
            return Vmmi.VMMDLL_PdbSymbolAddress(hVMM, szModule, szSymbolName, out pvaSymbolAddress);
        }

        public bool PdbTypeSize(string szModule, string szTypeName, out uint pcbTypeSize)
        {
            return Vmmi.VMMDLL_PdbTypeSize(hVMM, szModule, szTypeName, out pcbTypeSize);
        }

        public bool PdbTypeChildOffset(string szModule, string szTypeName, string wszTypeChildName, out uint pcbTypeChildOffset)
        {
            return Vmmi.VMMDLL_PdbTypeChildOffset(hVMM, szModule, szTypeName, wszTypeChildName, out pcbTypeChildOffset);
        }



        //---------------------------------------------------------------------
        // "MAP" FUNCTIONALITY BELOW:
        //---------------------------------------------------------------------

        public const ulong MEMMAP_FLAG_PAGE_W = 0x0000000000000002;
        public const ulong MEMMAP_FLAG_PAGE_NS = 0x0000000000000004;
        public const ulong MEMMAP_FLAG_PAGE_NX = 0x8000000000000000;
        public const ulong MEMMAP_FLAG_PAGE_MASK = 0x8000000000000006;

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

        public unsafe MAP_NETENTRY[] Map_GetNet()
        {
            int cbMAP = System.Runtime.InteropServices.Marshal.SizeOf<Vmmi.VMMDLL_MAP_NET>();
            int cbENTRY = System.Runtime.InteropServices.Marshal.SizeOf<Vmmi.VMMDLL_MAP_NETENTRY>();
            IntPtr pMap = IntPtr.Zero;
            MAP_NETENTRY[] m = new MAP_NETENTRY[0];
            if (!Vmmi.VMMDLL_Map_GetNet(hVMM, out pMap)) { goto fail; }
            Vmmi.VMMDLL_MAP_NET nM = Marshal.PtrToStructure<Vmmi.VMMDLL_MAP_NET>(pMap);
            if (nM.dwVersion != Vmmi.VMMDLL_MAP_NET_VERSION) { goto fail; }
            m = new MAP_NETENTRY[nM.cMap];
            for (int i = 0; i < nM.cMap; i++)
            {
                Vmmi.VMMDLL_MAP_NETENTRY n = Marshal.PtrToStructure<Vmmi.VMMDLL_MAP_NETENTRY>((System.IntPtr)(pMap.ToInt64() + cbMAP + i * cbENTRY));
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
            Vmmi.VMMDLL_MemFree((byte*)pMap.ToPointer());
            return m;
        }

        public unsafe MAP_PHYSMEMENTRY[] Map_GetPhysMem()
        {
            int cbMAP = System.Runtime.InteropServices.Marshal.SizeOf<Vmmi.VMMDLL_MAP_PHYSMEM>();
            int cbENTRY = System.Runtime.InteropServices.Marshal.SizeOf<Vmmi.VMMDLL_MAP_PHYSMEMENTRY>();
            IntPtr pMap = IntPtr.Zero;
            MAP_PHYSMEMENTRY[] m = new MAP_PHYSMEMENTRY[0];
            if (!Vmmi.VMMDLL_Map_GetPhysMem(hVMM, out pMap)) { goto fail; }
            Vmmi.VMMDLL_MAP_PHYSMEM nM = Marshal.PtrToStructure<Vmmi.VMMDLL_MAP_PHYSMEM>(pMap);
            if (nM.dwVersion != Vmmi.VMMDLL_MAP_PHYSMEM_VERSION) { goto fail; }
            m = new MAP_PHYSMEMENTRY[nM.cMap];
            for (int i = 0; i < nM.cMap; i++)
            {
                Vmmi.VMMDLL_MAP_PHYSMEMENTRY n = Marshal.PtrToStructure<Vmmi.VMMDLL_MAP_PHYSMEMENTRY>((System.IntPtr)(pMap.ToInt64() + cbMAP + i * cbENTRY));
                MAP_PHYSMEMENTRY e;
                e.pa = n.pa;
                e.cb = n.cb;
                m[i] = e;
            }
        fail:
            Vmmi.VMMDLL_MemFree((byte*)pMap.ToPointer());
            return m;
        }

        public unsafe MAP_POOLENTRY[] Map_GetPool()
        {
            byte[] tag = { 0, 0, 0, 0 };
            IntPtr pN = IntPtr.Zero;
            int cbMAP = System.Runtime.InteropServices.Marshal.SizeOf<Vmmi.VMMDLL_MAP_POOL>();
            int cbENTRY = System.Runtime.InteropServices.Marshal.SizeOf<Vmmi.VMMDLL_MAP_POOLENTRY>();
            if (!Vmmi.VMMDLL_Map_GetPool(hVMM, out pN, 0)) { return new MAP_POOLENTRY[0]; }
            Vmmi.VMMDLL_MAP_POOL nM = Marshal.PtrToStructure<Vmmi.VMMDLL_MAP_POOL>(pN);
            if (nM.dwVersion != Vmmi.VMMDLL_MAP_POOL_VERSION)
            {
                Vmmi.VMMDLL_MemFree((byte*)pN.ToPointer());
                return new MAP_POOLENTRY[0];
            }
            MAP_POOLENTRY[] eM = new MAP_POOLENTRY[nM.cMap];
            for (int i = 0; i < nM.cMap; i++)
            {
                Vmmi.VMMDLL_MAP_POOLENTRY nE = Marshal.PtrToStructure<Vmmi.VMMDLL_MAP_POOLENTRY>((System.IntPtr)(pN.ToInt64() + cbMAP + i * cbENTRY));
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
            Vmmi.VMMDLL_MemFree((byte*)pN.ToPointer());
            return eM;
        }

        public unsafe MAP_USERENTRY[] Map_GetUsers()
        {
            int cbMAP = System.Runtime.InteropServices.Marshal.SizeOf<Vmmi.VMMDLL_MAP_USER>();
            int cbENTRY = System.Runtime.InteropServices.Marshal.SizeOf<Vmmi.VMMDLL_MAP_USERENTRY>();
            IntPtr pMap = IntPtr.Zero;
            MAP_USERENTRY[] m = new MAP_USERENTRY[0];
            if (!Vmmi.VMMDLL_Map_GetUsers(hVMM, out pMap)) { goto fail; }
            Vmmi.VMMDLL_MAP_USER nM = Marshal.PtrToStructure<Vmmi.VMMDLL_MAP_USER>(pMap);
            if (nM.dwVersion != Vmmi.VMMDLL_MAP_USER_VERSION) { goto fail; }
            m = new MAP_USERENTRY[nM.cMap];
            for (int i = 0; i < nM.cMap; i++)
            {
                Vmmi.VMMDLL_MAP_USERENTRY n = Marshal.PtrToStructure<Vmmi.VMMDLL_MAP_USERENTRY>((System.IntPtr)(pMap.ToInt64() + cbMAP + i * cbENTRY));
                MAP_USERENTRY e;
                e.szSID = n.wszSID;
                e.wszText = n.wszText;
                e.vaRegHive = n.vaRegHive;
                m[i] = e;
            }
        fail:
            Vmmi.VMMDLL_MemFree((byte*)pMap.ToPointer());
            return m;
        }

        public unsafe MAP_SERVICEENTRY[] Map_GetServices()
        {
            int cbMAP = System.Runtime.InteropServices.Marshal.SizeOf<Vmmi.VMMDLL_MAP_SERVICE>();
            int cbENTRY = System.Runtime.InteropServices.Marshal.SizeOf<Vmmi.VMMDLL_MAP_SERVICEENTRY>();
            IntPtr pMap = IntPtr.Zero;
            MAP_SERVICEENTRY[] m = new MAP_SERVICEENTRY[0];
            if (!Vmmi.VMMDLL_Map_GetServices(hVMM, out pMap)) { goto fail; }
            Vmmi.VMMDLL_MAP_SERVICE nM = Marshal.PtrToStructure<Vmmi.VMMDLL_MAP_SERVICE>(pMap);
            if (nM.dwVersion != Vmmi.VMMDLL_MAP_SERVICE_VERSION) { goto fail; }
            m = new MAP_SERVICEENTRY[nM.cMap];
            for (int i = 0; i < nM.cMap; i++)
            {
                Vmmi.VMMDLL_MAP_SERVICEENTRY n = Marshal.PtrToStructure<Vmmi.VMMDLL_MAP_SERVICEENTRY>((System.IntPtr)(pMap.ToInt64() + cbMAP + i * cbENTRY));
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
            Vmmi.VMMDLL_MemFree((byte*)pMap.ToPointer());
            return m;
        }

        public unsafe MAP_PFNENTRY[] Map_GetPfn(params uint[] pfns)
        {
            bool result;
            uint cbPfns;
            int cbMAP = System.Runtime.InteropServices.Marshal.SizeOf<Vmmi.VMMDLL_MAP_PFN>();
            int cbENTRY = System.Runtime.InteropServices.Marshal.SizeOf<Vmmi.VMMDLL_MAP_PFNENTRY>();
            if (pfns.Length == 0) { return new MAP_PFNENTRY[0]; }
            byte[] dataPfns = new byte[pfns.Length * sizeof(uint)];
            System.Buffer.BlockCopy(pfns, 0, dataPfns, 0, dataPfns.Length);
            fixed (byte* pbPfns = dataPfns)
            {
                cbPfns = (uint)(cbMAP + pfns.Length * cbENTRY);
                fixed (byte* pb = new byte[cbPfns])
                {
                    result =
                        Vmmi.VMMDLL_Map_GetPfn(hVMM, pbPfns, (uint)pfns.Length, null, ref cbPfns) &&
                        Vmmi.VMMDLL_Map_GetPfn(hVMM, pbPfns, (uint)pfns.Length, pb, ref cbPfns);
                    if (!result) { return new MAP_PFNENTRY[0]; }
                    Vmmi.VMMDLL_MAP_PFN pm = Marshal.PtrToStructure<Vmmi.VMMDLL_MAP_PFN>((System.IntPtr)pb);
                    if (pm.dwVersion != Vmmi.VMMDLL_MAP_PFN_VERSION) { return new MAP_PFNENTRY[0]; }
                    MAP_PFNENTRY[] m = new MAP_PFNENTRY[pm.cMap];
                    for (int i = 0; i < pm.cMap; i++)
                    {
                        Vmmi.VMMDLL_MAP_PFNENTRY n = Marshal.PtrToStructure<Vmmi.VMMDLL_MAP_PFNENTRY>((System.IntPtr)(pb + cbMAP + i * cbENTRY));
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
            int cbENTRY = System.Runtime.InteropServices.Marshal.SizeOf<Vmmi.VMMDLL_REGISTRY_HIVE_INFORMATION>();
            result = Vmmi.VMMDLL_WinReg_HiveList(hVMM, null, 0, out cHives);
            if (!result || (cHives == 0)) { return new REGISTRY_HIVE_INFORMATION[0]; }
            fixed (byte* pb = new byte[cHives * cbENTRY])
            {
                result = Vmmi.VMMDLL_WinReg_HiveList(hVMM, pb, cHives, out cHives);
                if (!result) { return new REGISTRY_HIVE_INFORMATION[0]; }
                REGISTRY_HIVE_INFORMATION[] m = new REGISTRY_HIVE_INFORMATION[cHives];
                for (int i = 0; i < cHives; i++)
                {
                    Vmmi.VMMDLL_REGISTRY_HIVE_INFORMATION n = Marshal.PtrToStructure<Vmmi.VMMDLL_REGISTRY_HIVE_INFORMATION>((System.IntPtr)(pb + i * cbENTRY));
                    REGISTRY_HIVE_INFORMATION e;
                    if (n.wVersion != Vmmi.VMMDLL_REGISTRY_HIVE_INFORMATION_VERSION) { return new REGISTRY_HIVE_INFORMATION[0]; }
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
                if (!Vmmi.VMMDLL_WinReg_HiveReadEx(hVMM, vaCMHIVE, ra, pb, cb, out cbRead, flags))
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


        public unsafe bool RegHiveWrite(ulong vaCMHIVE, uint ra, byte[] data)
        {
            fixed (byte* pb = data)
            {
                return Vmmi.VMMDLL_WinReg_HiveWrite(hVMM, vaCMHIVE, ra, pb, (uint)data.Length);
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
                while (Vmmi.VMMDLL_WinReg_EnumKeyExW(hVMM, wszFullPathKey, i, pb, ref cchName, out ftLastWriteTime))
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
                while (Vmmi.VMMDLL_WinReg_EnumValueW(hVMM, wszFullPathKey, i, pb, ref cchName, out lpType, null, ref cbData))
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
            result = Vmmi.VMMDLL_WinReg_QueryValueExW(hVMM, wszFullPathKeyValue, out tp, null, ref cb);
            if (!result)
            {
                return null;
            }
            byte[] data = new byte[cb];
            fixed (byte* pb = data)
            {
                result = Vmmi.VMMDLL_WinReg_QueryValueExW(hVMM, wszFullPathKeyValue, out tp, pb, ref cb);
                return result ? data : null;
            }
        }
    }
}
