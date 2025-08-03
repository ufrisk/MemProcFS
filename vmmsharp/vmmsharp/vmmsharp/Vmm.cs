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

/* Contributions by imerzan (Frostchi)
 * BSD Zero Clause License
 * 
 * Copyright (c) 2024 imerzan
 * 
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH
 * REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT,
 * INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
 * LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
 * OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 */

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;
using Vmmsharp.Internal;

namespace Vmmsharp
{
    /// <summary>
    /// MemProcFS public API
    /// </summary>
    public class Vmm : IDisposable
    {
        #region Base Functionality

        public static implicit operator IntPtr(Vmm x) => x?.hVMM ?? IntPtr.Zero;
        private bool disposed = false;
        protected IntPtr hVMM = IntPtr.Zero;

        /// <summary>
        /// Underlying LeechCore handle.
        /// </summary>
        public virtual LeechCore LeechCore { get; }

        /// <summary>
        /// ToString() override.
        /// </summary>
        /// <returns></returns>
        public override string ToString()
        {
            return (disposed || (hVMM == IntPtr.Zero)) ? "Vmm:NotValid" : "Vmm";
        }

        /// <summary>
        /// Internal initialization method.
        /// </summary>
        protected static unsafe IntPtr Initialize(out LeechCore.LCConfigErrorInfo configErrorInfo, bool initPlugins, params string[] args)
        {
            IntPtr pLcErrorInfo;
            int cbERROR_INFO = System.Runtime.InteropServices.Marshal.SizeOf<Lci.LC_CONFIG_ERRORINFO>();
            IntPtr hVMM = Vmmi.VMMDLL_InitializeEx(args.Length, args, out pLcErrorInfo);
            long vaLcCreateErrorInfo = pLcErrorInfo.ToInt64();
            configErrorInfo = new LeechCore.LCConfigErrorInfo();
            configErrorInfo.strUserText = "";
            if (hVMM.ToInt64() == 0)
            {
                throw new VmmException("VMM INIT FAILED.");
            }
            if (vaLcCreateErrorInfo == 0)
            {
                if (initPlugins)
                {
                    Vmmi.VMMDLL_InitializePlugins(hVMM);
                }
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
            if (initPlugins)
            {
                Vmmi.VMMDLL_InitializePlugins(hVMM);
            }
            return hVMM;
        }

        /// <summary>
        /// Private zero-argument constructor to prevent instantiation.
        /// </summary>
        private Vmm()
        {
        }

        /// <summary>
        /// Initialize a new Vmm instance with command line arguments.
        /// Also retrieve the extended error information (if there is an error).
        /// </summary>
        /// <param name="configErrorInfo">Error information in case of an error.</param>
        /// <param name="args">MemProcFS/Vmm command line arguments.</param>
        public Vmm(out LeechCore.LCConfigErrorInfo configErrorInfo, params string[] args)
            : this(out configErrorInfo, true, args)
        {
        }

        /// <summary>
        /// Initialize a new Vmm instance with command line arguments.
        /// </summary>
        /// <param name="args">MemProcFS/Vmm command line arguments.</param>
        public Vmm(params string[] args)
            : this(out LeechCore.LCConfigErrorInfo errorInfo, true, args)
        {
        }

        /// <summary>
        /// Initialize a new Vmm instance with command line arguments.
        /// </summary>
        /// <param name="initializePlugins">Initialize plugins on startup.</param>
        /// <param name="args">MemProcFS/Vmm command line arguments.</param>
        public Vmm(bool initializePlugins, params string[] args)
            : this(out _, initializePlugins, args)
        {
        }

        /// <summary>
        /// Initialize a new Vmm instance with command line arguments.
        /// Also retrieve the extended error information (if there is an error).
        /// </summary>
        /// <param name="configErrorInfo">Error information in case of an error.</param>
        /// <param name="initializePlugins">Initialize plugins on startup.</param>
        /// <param name="args">MemProcFS/Vmm command line arguments.</param>
        public Vmm(out LeechCore.LCConfigErrorInfo configErrorInfo, bool initializePlugins, params string[] args)
        {
            this.hVMM = Vmm.Initialize(out configErrorInfo, initializePlugins, args);
            ulong hLC = GetConfig(CONFIG_OPT_CORE_LEECHCORE_HANDLE);
            string sLC = $"existing://0x{hLC:X}";
            this.LeechCore = new LeechCore(sLC);
        }

        /// <summary>
        /// Manually initialize plugins.
        /// By default plugins are initialized during initialization, unless you specifically passed FALSE to the constructor.
        /// </summary>
        public void InitializePlugins()
        {
            Vmmi.VMMDLL_InitializePlugins(hVMM);
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
                // Dispose managed objects.
                if (disposing)
                {
                }
                // Free unmanaged objects.
                this.LeechCore.Dispose(); // Contains unmanaged handles
                Vmmi.VMMDLL_Close(hVMM);
                hVMM = IntPtr.Zero;
                disposed = true;
            }
        }

        /// <summary>
        /// Close the Vmm instance. This also done automatically on Dispose.
        /// </summary>
        public void Close()
        {
            Dispose(disposing: true);
        }

        /// <summary>
        /// Close all Vmm instances in the native layer.
        /// </summary>
        public static void CloseAll()
        {
            Vmmi.VMMDLL_CloseAll();
        }

#if NET5_0_OR_GREATER
        /// <summary>
        /// Load the native vmm.dll and leechcore.dll libraries. This may sometimes be necessary if the libraries are not in the system path.
        /// NB! This method should be called before any other Vmm API methods. This method is only available on Windows.
        /// </summary>
        /// <param name="path"></param>
        public static void LoadNativeLibrary(string path)
        {
            // Load the native vmm.dll and leechcore.dll libraries if possible.
            // Leak the handles to the libraries as it will be used by the API.
            if(NativeLibrary.TryLoad("leechcore", out _) && NativeLibrary.TryLoad("vmm", out _))
            {
                return;
            }
            if (NativeLibrary.TryLoad(Path.Combine(path, "leechcore"), out _) && NativeLibrary.TryLoad(Path.Combine(path, "vmm"), out _))
            {
                return;
            }
            throw new VmmException("Failed to load native libraries vmm.dll and leechcore.dll.");
        }
#else // NET5_0_OR_GREATER
        // P/Invoke to LoadLibrary to pre-load required native libraries (vmm.dll & leechcore.dll)
        [DllImport("Kernel32.dll")]
        private static extern IntPtr LoadLibrary(string path);

        /// <summary>
        /// Load the native vmm.dll and leechcore.dll libraries. This may sometimes be necessary if the libraries are not in the system path.
        /// NB! This method should be called before any other Vmm API methods. This method is only available on Windows.
        /// </summary>
        /// <param name="path"></param>
        public static void LoadNativeLibrary(string path)
        {
            // Load the native vmm.dll and leechcore.dll libraries if possible.
            // Leak the handles to the libraries as it will be used by the API.
            if ((path != null) && !path.EndsWith("\\")) { path += "\\"; }
            if (path == null) { path = ""; }
            IntPtr hLC = LoadLibrary(path + "leechcore.dll");
            IntPtr hVMM = LoadLibrary(path + "vmm.dll");
            if (hLC == IntPtr.Zero || hVMM == IntPtr.Zero)
            {
                throw new VmmException("Failed to load native libraries vmm.dll and leechcore.dll.");
            }
        }
#endif // NET5_0_OR_GREATER

        #endregion


        #region Config Get/Set

        public enum MemoryModelType
        {
            MEMORYMODEL_NA = 0,
            MEMORYMODEL_X86 = 1,
            MEMORYMODEL_X86PAE = 2,
            MEMORYMODEL_X64 = 3,
            MEMORYMODEL_ARM64 = 4
        }

        public enum SystemType
        {
            SYSTEM_UNKNOWN_X64 = 1,
            SYSTEM_WINDOWS_X64 = 2,
            SYSTEM_UNKNOWN_X86 = 3,
            SYSTEM_WINDOWS_X86 = 4
        }

        public const ulong CONFIG_OPT_CORE_PRINTF_ENABLE             = 0x4000000100000000;  // RW
        public const ulong CONFIG_OPT_CORE_VERBOSE                   = 0x4000000200000000;  // RW
        public const ulong CONFIG_OPT_CORE_VERBOSE_EXTRA             = 0x4000000300000000;  // RW
        public const ulong CONFIG_OPT_CORE_VERBOSE_EXTRA_TLP         = 0x4000000400000000;  // RW
        public const ulong CONFIG_OPT_CORE_MAX_NATIVE_ADDRESS        = 0x4000000800000000;  // R
        public const ulong CONFIG_OPT_CORE_LEECHCORE_HANDLE          = 0x4000001000000000;  // R - underlying leechcore handle (do not close).
        public const ulong CONFIG_OPT_CORE_VMM_ID                    = 0x4000002000000000;  // R - use with startup option '-create-from-vmmid' to create a thread-safe duplicate VMM instance.

        public const ulong CONFIG_OPT_CORE_SYSTEM                    = 0x2000000100000000;  // R
        public const ulong CONFIG_OPT_CORE_MEMORYMODEL               = 0x2000000200000000;  // R

        public const ulong CONFIG_OPT_CONFIG_IS_REFRESH_ENABLED      = 0x2000000300000000;  // R - 1/0
        public const ulong CONFIG_OPT_CONFIG_TICK_PERIOD             = 0x2000000400000000;  // RW - base tick period in ms
        public const ulong CONFIG_OPT_CONFIG_READCACHE_TICKS         = 0x2000000500000000;  // RW - memory cache validity period (in ticks)
        public const ulong CONFIG_OPT_CONFIG_TLBCACHE_TICKS          = 0x2000000600000000;  // RW - page table (tlb) cache validity period (in ticks)
        public const ulong CONFIG_OPT_CONFIG_PROCCACHE_TICKS_PARTIAL = 0x2000000700000000;  // RW - process refresh (partial) period (in ticks)
        public const ulong CONFIG_OPT_CONFIG_PROCCACHE_TICKS_TOTAL   = 0x2000000800000000;  // RW - process refresh (full) period (in ticks)
        public const ulong CONFIG_OPT_CONFIG_VMM_VERSION_MAJOR       = 0x2000000900000000;  // R
        public const ulong CONFIG_OPT_CONFIG_VMM_VERSION_MINOR       = 0x2000000A00000000;  // R
        public const ulong CONFIG_OPT_CONFIG_VMM_VERSION_REVISION    = 0x2000000B00000000;  // R
        public const ulong CONFIG_OPT_CONFIG_STATISTICS_FUNCTIONCALL = 0x2000000C00000000;  // RW - enable function call statistics (.status/statistics_fncall file)
        public const ulong CONFIG_OPT_CONFIG_IS_PAGING_ENABLED       = 0x2000000D00000000;  // RW - 1/0
        public const ulong CONFIG_OPT_CONFIG_DEBUG                   = 0x2000000E00000000;  // W
        public const ulong CONFIG_OPT_CONFIG_YARA_RULES              = 0x2000000F00000000;  // R

        public const ulong CONFIG_OPT_WIN_VERSION_MAJOR              = 0x2000010100000000;  // R
        public const ulong CONFIG_OPT_WIN_VERSION_MINOR              = 0x2000010200000000;  // R
        public const ulong CONFIG_OPT_WIN_VERSION_BUILD              = 0x2000010300000000;  // R
        public const ulong CONFIG_OPT_WIN_SYSTEM_UNIQUE_ID           = 0x2000010400000000;  // R

        public const ulong CONFIG_OPT_FORENSIC_MODE                  = 0x2000020100000000;  // RW - enable/retrieve forensic mode type [0-4].

        // REFRESH OPTIONS:
        public const ulong CONFIG_OPT_REFRESH_ALL                    = 0x2001ffff00000000;  // W - refresh all caches
        public const ulong CONFIG_OPT_REFRESH_FREQ_MEM               = 0x2001100000000000;  // W - refresh memory cache (excl. TLB) [fully]
        public const ulong CONFIG_OPT_REFRESH_FREQ_MEM_PARTIAL       = 0x2001000200000000;  // W - refresh memory cache (excl. TLB) [partial 33%/call]
        public const ulong CONFIG_OPT_REFRESH_FREQ_TLB               = 0x2001080000000000;  // W - refresh page table (TLB) cache [fully]
        public const ulong CONFIG_OPT_REFRESH_FREQ_TLB_PARTIAL       = 0x2001000400000000;  // W - refresh page table (TLB) cache [partial 33%/call]
        public const ulong CONFIG_OPT_REFRESH_FREQ_FAST              = 0x2001040000000000;  // W - refresh fast frequency - incl. partial process refresh
        public const ulong CONFIG_OPT_REFRESH_FREQ_MEDIUM            = 0x2001000100000000;  // W - refresh medium frequency - incl. full process refresh
        public const ulong CONFIG_OPT_REFRESH_FREQ_SLOW              = 0x2001001000000000;  // W - refresh slow frequency.

        // PROCESS OPTIONS: [LO-DWORD: Process PID]
        public const ulong CONFIG_OPT_PROCESS_DTB                    = 0x2002000100000000;  // W - force set process directory table base.
        public const ulong CONFIG_OPT_PROCESS_DTB_FAST_LOWINTEGRITY  = 0x2002000200000000;  // W - force set process directory table base (fast, low integrity mode, with less checks) - use at own risk!.

        //---------------------------------------------------------------------
        // CONFIG GET/SET:
        //---------------------------------------------------------------------

        /// <summary>
        /// Get a configuration option given by a Vmm.CONFIG_* constant.
        /// </summary>
        /// <param name="fOption">The a Vmm.CONFIG_* option to get.</param>
        /// <returns>The config value retrieved on success. Zero on fail.</returns>
        public ulong GetConfig(ulong fOption)
        {
            ulong value = 0;
            Vmmi.VMMDLL_ConfigGet(hVMM, fOption, out value);
            return value;
        }


        /// <summary>
        /// Get a configuration option given by a Vmm.CONFIG_* constant.
        /// </summary>
        /// <param name="fOption">The a Vmm.CONFIG_* option to get.</param>
        /// <param name="result">true(success). false(fail).</param>
        /// <returns>The config value retrieved on success. Zero on fail.</returns>
        public ulong GetConfig(ulong fOption, out bool result)
        {
            ulong value = 0;
            result = Vmmi.VMMDLL_ConfigGet(hVMM, fOption, out value);
            return value;
        }


        /// <summary>
        /// Set a configuration option given by a Vmm.CONFIG_* constant.
        /// </summary>
        /// <param name="fOption">The Vmm.CONFIG_* option to set.</param>
        /// <param name="qwValue">The value to set.</param>
        /// <returns></returns>
        public bool SetConfig(ulong fOption, ulong qwValue)
        {
            return Vmmi.VMMDLL_ConfigSet(hVMM, fOption, qwValue);
        }

        #endregion


        #region Memory Read/Write

        //---------------------------------------------------------------------
        // MEMORY READ/WRITE FUNCTIONALITY BELOW:
        //---------------------------------------------------------------------

        public const uint PID_PHYSICALMEMORY            = unchecked((uint)-1);  // Pass as a PID Parameter to read Physical Memory
        public const uint PID_PROCESS_WITH_KERNELMEMORY = 0x80000000;           // Combine with dwPID to enable process kernel memory (NB! use with extreme care).

        public const uint FLAG_NOCACHE                  = 0x0001;  // do not use the data cache (force reading from memory acquisition device)
        public const uint FLAG_ZEROPAD_ON_FAIL          = 0x0002;  // zero pad failed physical memory reads and report success if read within range of physical memory.
        public const uint FLAG_FORCECACHE_READ          = 0x0008;  // force use of cache - fail non-cached pages - only valid for reads, invalid with VMM_FLAG_NOCACHE/VMM_FLAG_ZEROPAD_ON_FAIL.
        public const uint FLAG_NOPAGING                 = 0x0010;  // do not try to retrieve memory from paged out memory from pagefile/compressed (even if possible)
        public const uint FLAG_NOPAGING_IO              = 0x0020;  // do not try to retrieve memory from paged out memory if read would incur additional I/O (even if possible).
        public const uint FLAG_NOCACHEPUT               = 0x0100;  // do not write back to the data cache upon successful read from memory acquisition device.
        public const uint FLAG_CACHE_RECENT_ONLY        = 0x0200;  // only fetch from the most recent active cache region when reading.
        public const uint FLAG_NO_PREDICTIVE_READ       = 0x0400;  // do not use predictive read-ahead when reading memory.
        public const uint FLAG_FORCECACHE_READ_DISABLE  = 0x0800;  // this flag is only recommended for local files. improves forensic artifact order.
        public const uint FLAG_SCATTER_PREPAREEX_NOMEMZERO = 0x1000; // (not used by the C# API).
        public const uint FLAG_NOMEMCALLBACK            = 0x2000;  // (not used by the C# API).
        public const uint FLAG_SCATTER_FORCE_PAGEREAD   = 0x4000; // (not used by the C# API).

        /// <summary>
        /// Performs a Scatter Read on a collection of page-aligned Physical Addresses.
        /// </summary>
        /// <param name="flags">VMM Flags</param>
        /// <param name="pa">Array of Physical Addresses to read.</param>
        /// <returns>Array of MEM_SCATTER structures.</returns>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public LeechCore.MemScatter[] MemReadScatter(uint flags, params ulong[] pa) =>
            Vmmi.MemReadScatter(hVMM, PID_PHYSICALMEMORY, flags, pa);

#if NET5_0_OR_GREATER
        /// <summary>
        /// Perform a scatter read of multiple page-sized physical memory ranges.
        /// Does not copy the read memory to a managed byte buffer, but instead allows direct access to the native memory via a Span view.
        /// </summary>
        /// <param name="flags">Vmm Flags.</param>
        /// <param name="pa">Array of page-aligned Memory Addresses.</param>
        /// <returns>SCATTER_HANDLE</returns>
        /// <exception cref="VmmException"></exception>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public unsafe LeechCore.SCATTER_HANDLE MemReadScatter2(uint flags, params ulong[] pa) =>
        Vmmi.MemReadScatter2(hVMM, PID_PHYSICALMEMORY, flags, pa);
#endif

        /// <summary>
        /// Initialize a Scatter Memory Read handle used to read multiple physical memory regions in a single call.
        /// </summary>
        /// <param name="flags">Vmm Flags.</param>
        /// <returns>A VmmScatterMemory handle.</returns>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public VmmScatterMemory Scatter_Initialize(uint flags = 0) =>
            Vmmi.Scatter_Initialize(hVMM, PID_PHYSICALMEMORY, flags);

        /// <summary>
        /// Read Memory from a Physical Address into a managed byte-array.
        /// </summary>
        /// <param name="pa">Physical Address to read from.</param>
        /// <param name="cb">Count of bytes to read.</param>
        /// <param name="flags">VMM Flags.</param>
        /// <returns>Managed byte array containing number of bytes read.</returns>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public unsafe byte[] MemRead(ulong pa, uint cb, uint flags = 0) =>
            Vmmi.MemReadArray<byte>(hVMM, PID_PHYSICALMEMORY, pa, cb, flags);

        /// <summary>
        /// Read Memory from a Physical Address into unmanaged memory.
        /// </summary>
        /// <param name="pa">Physical Address to read from.</param>
        /// <param name="pb">Pointer to buffer to receive read.</param>
        /// <param name="cb">Count of bytes to read.</param>
        /// <param name="cbRead">Count of bytes successfully read.</param>
        /// <param name="flags">VMM Flags.</param>
        /// <returns>True if successful, otherwise False. Be sure to check cbRead count.</returns>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public unsafe bool MemRead(ulong pa, IntPtr pb, uint cb, out uint cbRead, uint flags = 0) =>
            Vmmi.MemRead(hVMM, PID_PHYSICALMEMORY, pa, pb.ToPointer(), cb, out cbRead, flags);

        /// <summary>
        /// Read Memory from a Physical Address into unmanaged memory.
        /// </summary>
        /// <param name="pa">Physical Address to read from.</param>
        /// <param name="pb">Pointer to buffer to receive read.</param>
        /// <param name="cb">Count of bytes to read.</param>
        /// <param name="cbRead">Count of bytes successfully read.</param>
        /// <param name="flags">VMM Flags.</param>
        /// <returns>True if successful, otherwise False. Be sure to check cbRead count.</returns>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public unsafe bool MemRead(ulong pa, void* pb, uint cb, out uint cbRead, uint flags = 0) =>
            Vmmi.MemRead(hVMM, PID_PHYSICALMEMORY, pa, pb, cb, out cbRead, flags);

        /// <summary>
        /// Read Memory from a Physical Address into a nullable struct of Type <typeparamref name="T"/>.
        /// </summary>
        /// <typeparam name="T">Struct Type.</typeparam>
        /// <param name="pa">Physical Address to read from.</param>
        /// <param name="flags">VMM Flags.</param>
        /// <returns>Result if successful, otherwise NULL.</returns>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public unsafe T? MemReadAs<T>(ulong pa, uint flags = 0)
            where T : unmanaged =>
            Vmmi.MemReadAs<T>(hVMM, PID_PHYSICALMEMORY, pa, flags);

#if NET9_0_OR_GREATER
        /// <summary>
        /// Read Memory from a Physical Address into a ref struct of Type <typeparamref name="T"/>.
        /// </summary>
        /// <typeparam name="T">Struct/Ref Struct Type.</typeparam>
        /// <param name="pa">Physical Address to read from.</param>
        /// <param name="result">Memory read result.</param>
        /// <param name="flags">VMM Flags.</param>
        /// <returns>TRUE if successful, otherwise FALSE.</returns>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public unsafe bool MemReadRefAs<T>(ulong pa, out T result, uint flags = 0)
            where T : unmanaged, allows ref struct =>
            Vmmi.MemReadRefAs<T>(hVMM, PID_PHYSICALMEMORY, pa, out result, flags);
#endif

        /// <summary>
        /// Read Memory from a Physical Address into an Array of Type <typeparamref name="T"/>.
        /// </summary>
        /// <typeparam name="T">Value Type.</typeparam>
        /// <param name="pa">Physical Address to read from.</param>
        /// <param name="count">Number of elements to read.</param>
        /// <param name="flags">VMM Flags.</param>
        /// <returns>Managed <typeparamref name="T"/> array containing number of elements read.</returns>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public unsafe T[] MemReadArray<T>(ulong pa, uint count, uint flags = 0)
            where T : unmanaged =>
            Vmmi.MemReadArray<T>(hVMM, PID_PHYSICALMEMORY, pa, count, flags);

#if NET5_0_OR_GREATER
        /// <summary>
        /// Read memory into a Span of <typeparamref name="T"/>.
        /// </summary>
        /// <typeparam name="T">Value Type</typeparam>
        /// <param name="pa">Physical memory address to read from.</param>
        /// <param name="span">Span to receive the memory read.</param>
        /// <param name="cbRead">Number of bytes successfully read.</param>
        /// <param name="flags">Read flags.</param>
        /// <returns>True if successful, otherwise False.
        /// Please be sure to also check the cbRead out value.</returns>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public unsafe bool MemReadSpan<T>(ulong pa, Span<T> span, out uint cbRead, uint flags)
            where T : unmanaged =>
            Vmmi.MemReadSpan(hVMM, PID_PHYSICALMEMORY, pa, span, out cbRead, flags);

        /// <summary>
        /// Write memory from a Span of <typeparamref name="T"/> to a specified memory address.
        /// </summary>
        /// <typeparam name="T">Value Type</typeparam>
        /// <param name="pa">Physical memory address to write to.</param>
        /// <param name="span">Span to write from.</param>
        /// <returns>True if successful, otherwise False.</returns>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public unsafe bool MemWriteSpan<T>(ulong pa, Span<T> span)
            where T : unmanaged =>
            Vmmi.MemWriteSpan(hVMM, PID_PHYSICALMEMORY, pa, span);
#endif

        /// <summary>
        /// Read Memory from a Physical Address into a Managed String.
        /// </summary>
        /// <param name="encoding">String Encoding for this read.</param>
        /// <param name="pa">Physical Address to read from.</param>
        /// <param name="cb">Number of bytes to read. Keep in mind some string encodings are 2-4 bytes per character.</param>
        /// <param name="flags">VMM Flags.</param>
        /// <param name="terminateOnNullChar">Terminate the string at the first occurrence of the null character.</param>
        /// <returns>C# Managed System.String. Null if failed.</returns>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public unsafe string MemReadString(Encoding encoding, ulong pa, uint cb,
            uint flags = 0, bool terminateOnNullChar = true) =>
            Vmmi.MemReadString(hVMM, encoding, PID_PHYSICALMEMORY, pa, cb, flags, terminateOnNullChar);

        /// <summary>
        /// Prefetch pages into the MemProcFS internal cache.
        /// </summary>
        /// <param name="pa">An array of the physical addresses to prefetch.</param>
        /// <returns></returns>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public unsafe bool MemPrefetchPages(ulong[] pa) =>
            Vmmi.MemPrefetchPages(hVMM, PID_PHYSICALMEMORY, pa);

        /// <summary>
        /// Write Memory from a managed byte-array to a given Physical Address.
        /// </summary>
        /// <param name="pa">Physical Address to write to.</param>
        /// <param name="data">Data to be written.</param>
        /// <returns>True if write successful, otherwise False.</returns>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public unsafe bool MemWrite(ulong pa, byte[] data) =>
            Vmmi.MemWriteArray<byte>(hVMM, PID_PHYSICALMEMORY, pa, data);

        /// <summary>
        /// Write Memory from unmanaged memory to a given Physical Address.
        /// </summary>
        /// <param name="pa">Physical Address to write to.</param>
        /// <param name="pb">Pointer to buffer to write from.</param>
        /// <param name="cb">Count of bytes to write.</param>
        /// <returns>True if write successful, otherwise False.</returns>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public unsafe bool MemWrite(ulong pa, IntPtr pb, uint cb) =>
            Vmmi.MemWrite(hVMM, PID_PHYSICALMEMORY, pa, pb.ToPointer(), cb);

        /// <summary>
        /// Write Memory from unmanaged memory to a given Physical Address.
        /// </summary>
        /// <param name="pa">Physical Address to write to.</param>
        /// <param name="pb">Pointer to buffer to write from.</param>
        /// <param name="cb">Count of bytes to write.</param>
        /// <returns>True if write successful, otherwise False.</returns>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public unsafe bool MemWrite(ulong pa, void* pb, uint cb) =>
            Vmmi.MemWrite(hVMM, PID_PHYSICALMEMORY, pa, pb, cb);

        /// <summary>
        /// Write Memory from a struct value <typeparamref name="T"/> to a given Physical Address.
        /// </summary>
        /// <typeparam name="T">Value Type.</typeparam>
        /// <param name="pa">Physical Address to write to.</param>
        /// <param name="value"><typeparamref name="T"/> Value to write.</param>
        /// <returns>True if write successful, otherwise False.</returns>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public unsafe bool MemWriteStruct<T>(ulong pa, T value)
            where T : unmanaged
#if NET9_0_OR_GREATER
            , allows ref struct
#endif
            =>
            Vmmi.MemWriteStruct(hVMM, PID_PHYSICALMEMORY, pa, value);

        /// <summary>
        /// Write Memory from a managed <typeparamref name="T"/> Array to a given Physical Address.
        /// </summary>
        /// <typeparam name="T">Value Type.</typeparam>
        /// <param name="pa">Physical Address to write to.</param>
        /// <param name="data">Managed <typeparamref name="T"/> array to write.</param>
        /// <param name="flags">VMM Flags.</param>
        /// <returns>True if write successful, otherwise False.</returns>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public unsafe bool MemWriteArray<T>(ulong pa, T[] data)
            where T : unmanaged =>
            Vmmi.MemWriteArray(hVMM, PID_PHYSICALMEMORY, pa, data);

        /// <summary>
        /// Returns current Memory Map in string format.
        /// </summary>
        /// <returns>Memory Map, NULL if failed.</returns>
        public string MapMemoryAsString()
        {
            var map = MapMemory();
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

#endregion


        #region VFS (Virtual File System) functionality

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

        public struct VfsEntry
        {
            public string name;
            public bool isDirectory;
            public ulong size;
            public VMMDLL_VFS_FILELIST_EXINFO info;
        }

#if NET5_0_OR_GREATER
        /// <summary>
        /// VFS list callback function for adding files.
        /// </summary>
        /// <param name="ctx"></param>
        /// <param name="name"></param>
        /// <param name="cb"></param>
        /// <param name="pExInfo"></param>
        /// <returns></returns>
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate bool VfsCallBack_AddFile(ulong ctx, [MarshalAs(UnmanagedType.LPUTF8Str)] string name, ulong cb, IntPtr pExInfo);

        /// <summary>
        /// VFS list callback function for adding directories.
        /// </summary>
        /// <param name="ctx"></param>
        /// <param name="name"></param>
        /// <param name="pExInfo"></param>
        /// <returns></returns>
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate bool VfsCallBack_AddDirectory(ulong ctx, [MarshalAs(UnmanagedType.LPUTF8Str)] string name, IntPtr pExInfo);

        private static bool VfsList_AddFileCB(ulong h, [MarshalAs(UnmanagedType.LPUTF8Str)] string sName, ulong cb, IntPtr pExInfo)
        {
            GCHandle gcHandle = (GCHandle)(new IntPtr((long)h));
            List<VfsEntry> ctx = (List<VfsEntry>)gcHandle.Target;
            VfsEntry e = new VfsEntry();
            e.name = sName;
            e.isDirectory = false;
            e.size = cb;
            if (pExInfo != IntPtr.Zero)
            {
                e.info = Marshal.PtrToStructure<Vmm.VMMDLL_VFS_FILELIST_EXINFO>(pExInfo);
            }
            ctx.Add(e);
            return true;
        }

        private static bool VfsList_AddDirectoryCB(ulong h, [MarshalAs(UnmanagedType.LPUTF8Str)] string sName, IntPtr pExInfo)
        {
            GCHandle gcHandle = (GCHandle)(new IntPtr((long)h));
            List<VfsEntry> ctx = (List<VfsEntry>)gcHandle.Target;
            VfsEntry e = new VfsEntry();
            e.name = sName;
            e.isDirectory = true;
            e.size = 0;
            if (pExInfo != IntPtr.Zero)
            {
                e.info = Marshal.PtrToStructure<Vmm.VMMDLL_VFS_FILELIST_EXINFO>(pExInfo);
            }
            ctx.Add(e);
            return true;
        }
#else
        /// <summary>
        /// VFS list callback function for adding files.
        /// </summary>
        /// <param name="ctx"></param>
        /// <param name="name"></param>
        /// <param name="cb"></param>
        /// <param name="pExInfo"></param>
        /// <returns></returns>
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate bool VfsCallBack_AddFile(ulong ctx, [MarshalAs(UnmanagedType.LPWStr)] string name, ulong cb, IntPtr pExInfo);

        /// <summary>
        /// VFS list callback function for adding directories.
        /// </summary>
        /// <param name="ctx"></param>
        /// <param name="name"></param>
        /// <param name="pExInfo"></param>
        /// <returns></returns>
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate bool VfsCallBack_AddDirectory(ulong ctx, [MarshalAs(UnmanagedType.LPWStr)] string name, IntPtr pExInfo);

        private static bool VfsList_AddFileCB(ulong h, [MarshalAs(UnmanagedType.LPWStr)] string sName, ulong cb, IntPtr pExInfo)
        {
            GCHandle gcHandle = (GCHandle)(new IntPtr((long)h));
            List<VfsEntry> ctx = (List<VfsEntry>)gcHandle.Target;
            VfsEntry e = new VfsEntry();
            e.name = sName;
            e.isDirectory = false;
            e.size = cb;
            if (pExInfo != IntPtr.Zero)
            {
                e.info = Marshal.PtrToStructure<Vmm.VMMDLL_VFS_FILELIST_EXINFO>(pExInfo);
            }
            ctx.Add(e);
            return true;
        }

        private static bool VfsList_AddDirectoryCB(ulong h, [MarshalAs(UnmanagedType.LPWStr)] string sName, IntPtr pExInfo)
        {
            GCHandle gcHandle = (GCHandle)(new IntPtr((long)h));
            List<VfsEntry> ctx = (List<VfsEntry>)gcHandle.Target;
            VfsEntry e = new VfsEntry();
            e.name = sName;
            e.isDirectory = true;
            e.size = 0;
            if (pExInfo != IntPtr.Zero)
            {
                e.info = Marshal.PtrToStructure<Vmm.VMMDLL_VFS_FILELIST_EXINFO>(pExInfo);
            }
            ctx.Add(e);
            return true;
        }
#endif

        /// <summary>
        /// VFS list files and directories in a virtual file system path using callback functions.
        /// </summary>
        /// <param name="path"></param>
        /// <param name="ctx">A user-supplied context which will be passed on to the callback functions.</param>
        /// <param name="CallbackFile"></param>
        /// <param name="CallbackDirectory"></param>
        /// <returns></returns>
        public bool VfsList(string path, ulong ctx, VfsCallBack_AddFile CallbackFile, VfsCallBack_AddDirectory CallbackDirectory)
        {
            Vmmi.VMMDLL_VFS_FILELIST FileList;
            FileList.dwVersion = Vmmi.VMMDLL_VFS_FILELIST_VERSION;
            FileList.h = ctx;
            FileList._Reserved = 0;
            FileList.pfnAddFile = Marshal.GetFunctionPointerForDelegate(CallbackFile);
            FileList.pfnAddDirectory = Marshal.GetFunctionPointerForDelegate(CallbackDirectory);
            return Vmmi.VMMDLL_VfsList(hVMM, path.Replace('/', '\\'), ref FileList);
        }

        /// <summary>
        /// VFS list files and directories in a virtual file system path.
        /// </summary>
        /// <param name="path"></param>
        /// <returns>A list with file and directory entries on success. An empty list on fail.</returns>
        public List<VfsEntry> VfsList(string path)
        {
            List<VfsEntry> ctx = new List<VfsEntry>();
            GCHandle gcHandle = GCHandle.Alloc(ctx);
            ulong nativeHandle = (ulong)((IntPtr)gcHandle).ToInt64();
            VfsList(path, nativeHandle, VfsList_AddFileCB, VfsList_AddDirectoryCB);
            return ctx;
        }

        /// <summary>
        /// VFS read data from a virtual file.
        /// </summary>
        /// <param name="fileName"></param>
        /// <param name="ntStatus">The NTSTATUS value of the operation (success = 0).</param>
        /// <param name="size">The maximum number of bytes to read. (0 = default = 16MB).</param>
        /// <param name="offset"></param>
        /// <returns>The data read on success. Zero-length data on fail. NB! data read may be shorter than size!</returns>
        public unsafe byte[] VfsRead(string fileName, out uint ntStatus, uint size = 0, ulong offset = 0)
        {
            uint cbRead = 0;
            if(size == 0)
            {
                size = 0x01000000; // 16MB
            }
            byte[] data = new byte[size];
            fixed (byte* pb = data)
            {
                ntStatus = Vmmi.VMMDLL_VfsRead(hVMM, fileName.Replace('/', '\\'), pb, size, out cbRead, offset);
                byte[] pbData = new byte[cbRead];
                if (cbRead > 0)
                {
                    Buffer.BlockCopy(data, 0, pbData, 0, (int)cbRead);
                }
                return pbData;
            }
        }

        /// <summary>
        /// VFS read data from a virtual file.
        /// </summary>
        /// <param name="fileName"></param>
        /// <param name="size"></param>
        /// <param name="offset"></param>
        /// <returns>The data read on success. Zero-length data on fail. NB! data read may be shorter than size!</returns>
        public unsafe byte[] VfsRead(string fileName, uint size = 0, ulong offset = 0)
        {
            return VfsRead(fileName, out _, size, offset);
        }

        /// <summary>
        /// VFS write data to a virtual file.
        /// </summary>
        /// <param name="fileName"></param>
        /// <param name="data"></param>
        /// <param name="offset"></param>
        /// <returns>The NTSTATUS value of the operation (success = 0).</returns>
        public unsafe uint VfsWrite(string fileName, byte[] data, ulong offset = 0)
        {
            uint cbRead = 0;
            fixed (byte* pb = data)
            {
                return Vmmi.VMMDLL_VfsWrite(hVMM, fileName.Replace('/', '\\'), pb, (uint)data.Length, out cbRead, offset);
            }
        }

        #endregion


        #region Process functionality

        //---------------------------------------------------------------------
        // PROCESS FUNCTIONALITY BELOW:
        //---------------------------------------------------------------------

        /// <summary>
        /// Lookup a process by its name.
        /// Validation is also performed to ensure the process is valid.
        /// </summary>
        /// <param name="sProcName">Process name to get.</param>
        /// <returns>A VmmProcess if successful, if unsuccessful null.</returns>
        public VmmProcess GetProcessByName(string sProcName)
        {
            if (Vmmi.VMMDLL_PidGetFromName(hVMM, sProcName, out uint pdwPID))
            {
                return GetProcessByPID(pdwPID);
            }
            return null;
        }

        /// <summary>
        /// Lookup a Process by its Process ID.
        /// Validation is also performed to ensure the process is valid.
        /// </summary>
        /// <param name="pid">Process ID to get.</param>
        /// <returns>A VmmProcess if successful, if unsuccessful null.</returns>
        public VmmProcess GetProcessByPID(uint pid)
        {
            var process = new VmmProcess(this, pid);
            if (process.IsValid)
                return process;
            return null;
        }

        /// <summary>
        /// Lookup a process by its name.
        /// Validation is also performed to ensure the process is valid.
        /// </summary>
        /// <param name="sProcName">Process name to get.</param>
        /// <returns>A VmmProcess if successful, if unsuccessful null.</returns>
        public VmmProcess Process(string sProcName) =>
            GetProcessByName(sProcName);

        /// <summary>
        /// Lookup a Process by its Process ID.
        /// Validation is also performed to ensure the process is valid.
        /// </summary>
        /// <param name="pid">Process ID to get.</param>
        /// <returns>A VmmProcess if successful, if unsuccessful null.</returns>
        public VmmProcess Process(uint pid) =>
            GetProcessByPID(pid);

        /// <summary>
        /// Returns All Processes on the Target System.
        /// </summary>
        public VmmProcess[] AllProcesses =>
            AllPIDs.Select(pid => new VmmProcess(this, pid)).ToArray();

        /// <summary>
        /// Returns All Processes on the Target System.
        /// </summary>
        public VmmProcess[] Processes => AllProcesses;

        /// <summary>
        /// Returns All Process IDs on the Target System.
        /// </summary>
        public unsafe uint[] AllPIDs
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

        /// <summary>
        /// Returns All Process IDs on the Target System.
        /// </summary>
        public unsafe uint[] PIDs =>
            AllPIDs;

        #endregion


        #region Registry functionality

        //---------------------------------------------------------------------
        // REGISTRY FUNCTIONALITY BELOW:
        //---------------------------------------------------------------------

        public struct RegHiveEntry
        {
            public ulong vaCMHIVE;
            public ulong vaHBASE_BLOCK;
            public uint cbLength;
            public string sName;
            public string sNameShort;
            public string sHiveRootPath;
        }

        public struct RegEnumKeyEntry
        {
            public string sName;
            public ulong ftLastWriteTime;
        }

        public struct RegEnumValueEntry
        {
            public string sName;
            public uint type;
            public uint size;
        }

        public struct RegEnumEntry
        {
            public string sKeyFullPath;
            public List<RegEnumKeyEntry> KeyList;
            public List<RegEnumValueEntry> ValueList;
        }

        /// <summary>
        /// List the registry hives.
        /// </summary>
        /// <returns></returns>
        public unsafe RegHiveEntry[] RegHiveList()
        {
            bool result;
            uint cHives;
            int cbENTRY = System.Runtime.InteropServices.Marshal.SizeOf<Vmmi.VMMDLL_REGISTRY_HIVE_INFORMATION>();
            result = Vmmi.VMMDLL_WinReg_HiveList(hVMM, null, 0, out cHives);
            if (!result || (cHives == 0)) { return new RegHiveEntry[0]; }
            fixed (byte* pb = new byte[cHives * cbENTRY])
            {
                result = Vmmi.VMMDLL_WinReg_HiveList(hVMM, pb, cHives, out cHives);
                if (!result) { return new RegHiveEntry[0]; }
                RegHiveEntry[] m = new RegHiveEntry[cHives];
                for (int i = 0; i < cHives; i++)
                {
                    Vmmi.VMMDLL_REGISTRY_HIVE_INFORMATION n = Marshal.PtrToStructure<Vmmi.VMMDLL_REGISTRY_HIVE_INFORMATION>((System.IntPtr)(pb + i * cbENTRY));
                    RegHiveEntry e;
                    if (n.wVersion != Vmmi.VMMDLL_REGISTRY_HIVE_INFORMATION_VERSION) { return new RegHiveEntry[0]; }
                    e.vaCMHIVE = n.vaCMHIVE;
                    e.vaHBASE_BLOCK = n.vaHBASE_BLOCK;
                    e.cbLength = n.cbLength;
                    e.sName = System.Text.Encoding.UTF8.GetString(n.uszName);
                    e.sName = e.sName.Substring(0, e.sName.IndexOf((char)0));
                    e.sNameShort = System.Text.Encoding.UTF8.GetString(n.uszNameShort);
                    e.sHiveRootPath = System.Text.Encoding.UTF8.GetString(n.uszHiveRootPath);
                    m[i] = e;
                }
                return m;
            }
        }

        /// <summary>
        /// Read from a registry hive.
        /// </summary>
        /// <param name="vaCMHIVE">The virtual address of the registry hive.</param>
        /// <param name="ra">The hive registry address (ra).</param>
        /// <param name="cb"></param>
        /// <param name="flags"></param>
        /// <returns>Read data on success (length may differ from requested read size). Zero-length array on fail.</returns>
        public unsafe byte[] RegHiveRead(ulong vaCMHIVE, uint ra, uint cb, uint flags = 0)
        {
            uint cbRead;
            byte[] data = new byte[cb];
            fixed (byte* pb = data)
            {
                if (!Vmmi.VMMDLL_WinReg_HiveReadEx(hVMM, vaCMHIVE, ra, pb, cb, out cbRead, flags))
                {
                    return new byte[0];
                }
            }
            if (cbRead != cb)
            {
                Array.Resize<byte>(ref data, (int)cbRead);
            }
            return data;
        }

        /// <summary>
        /// Write to a registry hive. NB! This is a very dangerous operation and is not recommended!
        /// </summary>
        /// <param name="vaCMHIVE">>The virtual address of the registry hive.</param>
        /// <param name="ra">The hive registry address (ra).</param>
        /// <param name="data"></param>
        /// <returns></returns>
        public unsafe bool RegHiveWrite(ulong vaCMHIVE, uint ra, byte[] data)
        {
            fixed (byte* pb = data)
            {
                return Vmmi.VMMDLL_WinReg_HiveWrite(hVMM, vaCMHIVE, ra, pb, (uint)data.Length);
            }
        }

        /// <summary>
        /// Enumerate a registry key for subkeys and values.
        /// </summary>
        /// <param name="sKeyFullPath"></param>
        /// <returns></returns>
        public unsafe RegEnumEntry RegEnum(string sKeyFullPath)
        {
            uint i, cchName, lpType, cbData = 0;
            ulong ftLastWriteTime;
            RegEnumEntry re = new RegEnumEntry();
            re.sKeyFullPath = sKeyFullPath;
            re.KeyList = new List<RegEnumKeyEntry>();
            re.ValueList = new List<RegEnumValueEntry>();
            fixed (byte* pb = new byte[0x1000])
            {
                i = 0;
                cchName = 0x800;
                while (Vmmi.VMMDLL_WinReg_EnumKeyEx(hVMM, sKeyFullPath, i, pb, ref cchName, out ftLastWriteTime))
                {
                    RegEnumKeyEntry e = new RegEnumKeyEntry();
                    e.ftLastWriteTime = ftLastWriteTime;
                    e.sName = new string((sbyte*)pb, 0, 2 * (int)Math.Max(1, cchName) - 2, Encoding.UTF8);
                    re.KeyList.Add(e);
                    i++;
                    cchName = 0x800;
                }
                i = 0;
                cchName = 0x800;
                while (Vmmi.VMMDLL_WinReg_EnumValue(hVMM, sKeyFullPath, i, pb, ref cchName, out lpType, null, ref cbData))
                {
                    RegEnumValueEntry e = new RegEnumValueEntry();
                    e.type = lpType;
                    e.size = cbData;
                    e.sName = new string((sbyte*)pb, 0, 2 * (int)Math.Max(1, cchName) - 2, Encoding.UTF8);
                    re.ValueList.Add(e);
                    i++;
                    cchName = 0x800;
                }
            }
            return re;
        }

        /// <summary>
        /// Read a registry value.
        /// </summary>
        /// <param name="sValueFullPath"></param>
        /// <param name="tp"></param>
        /// <returns></returns>
        public unsafe byte[] RegValueRead(string sValueFullPath, out uint tp)
        {
            bool result;
            uint cb = 0;
            result = Vmmi.VMMDLL_WinReg_QueryValueEx(hVMM, sValueFullPath, out tp, null, ref cb);
            if (!result)
            {
                return null;
            }
            byte[] data = new byte[cb];
            fixed (byte* pb = data)
            {
                result = Vmmi.VMMDLL_WinReg_QueryValueEx(hVMM, sValueFullPath, out tp, pb, ref cb);
                return result ? data : null;
            }
        }
        #endregion // Registry functionality


        #region Map functionality

        //---------------------------------------------------------------------
        // "MAP" FUNCTIONALITY BELOW:
        //---------------------------------------------------------------------

        public const ulong MEMMAP_FLAG_PAGE_W = 0x0000000000000002;
        public const ulong MEMMAP_FLAG_PAGE_NS = 0x0000000000000004;
        public const ulong MEMMAP_FLAG_PAGE_NX = 0x8000000000000000;
        public const ulong MEMMAP_FLAG_PAGE_MASK = 0x8000000000000006;

        public struct NetEntryAddress
        {
            public bool fValid;
            public ushort port;
            public byte[] pbAddr;
            public string sText;
        }

        public struct NetEntry
        {
            public uint dwPID;
            public uint dwState;
            public uint dwPoolTag;
            public ushort AF;
            public NetEntryAddress src;
            public NetEntryAddress dst;
            public ulong vaObj;
            public ulong ftTime;
            public string sText;
        }

        public struct MemoryEntry
        {
            public ulong pa;
            public ulong cb;
        }

        public struct KDeviceEntry
        {
            public ulong va;
            public uint iDepth;
            public uint dwDeviceType;
            public string sDeviceType;
            public ulong vaDriverObject;
            public ulong vaAttachedDevice;
            public ulong vaFileSystemDevice;
            public string sVolumeInfo;
        }

        public struct KDriverEntry
        {
            public ulong va;
            public ulong vaDriverStart;
            public ulong cbDriverSize;
            public ulong vaDeviceObject;
            public string sName;
            public string sPath;
            public string sServiceKeyName;
            public ulong[] MajorFunction;
        }

        public struct KObjectEntry
        {
            public ulong va;
            public ulong vaParent;
            public ulong[] vaChild;
            public string sName;
            public string sType;
        }

        public struct PoolEntry
        {
            public ulong va;
            public uint cb;
            public uint fAlloc;
            public uint tpPool;
            public uint tpSS;
            public uint dwTag;
            public string sTag;
        }

        public struct UserEntry
        {
            public string sSID;
            public string sText;
            public ulong vaRegHive;
        }

        public struct VirtualMachineEntry
        {
            public ulong hVM;
            public string sName;
            public ulong gpaMax;
            public uint tp;
            public bool fActive;
            public bool fReadOnly;
            public bool fPhysicalOnly;
            public uint dwPartitionID;
            public uint dwVersionBuild;
            public uint tpSystem;
            public uint dwParentVmmMountID;
            public uint dwVmMemPID;
        }

        public struct ServiceEntry
        {
            public ulong vaObj;
            public uint dwPID;
            public uint dwOrdinal;
            public string sServiceName;
            public string sDisplayName;
            public string sPath;
            public string sUserTp;
            public string sUserAcct;
            public string sImagePath;
            public uint dwStartType;
            public uint dwServiceType;
            public uint dwCurrentState;
            public uint dwControlsAccepted;
            public uint dwWin32ExitCode;
            public uint dwServiceSpecificExitCode;
            public uint dwCheckPoint;
            public uint dwWaitHint;
        }

        public enum PfnType
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

        public enum PfnTypeExtended
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

        public struct PfnEntry
        {
            public uint dwPfn;
            public PfnType tp;
            public PfnTypeExtended tpExtended;
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

        public unsafe NetEntry[] MapNet()
        {
            int cbMAP = System.Runtime.InteropServices.Marshal.SizeOf<Vmmi.VMMDLL_MAP_NET>();
            int cbENTRY = System.Runtime.InteropServices.Marshal.SizeOf<Vmmi.VMMDLL_MAP_NETENTRY>();
            IntPtr pMap = IntPtr.Zero;
            NetEntry[] m = new NetEntry[0];
            if (!Vmmi.VMMDLL_Map_GetNet(hVMM, out pMap)) { goto fail; }
            Vmmi.VMMDLL_MAP_NET nM = Marshal.PtrToStructure<Vmmi.VMMDLL_MAP_NET>(pMap);
            if (nM.dwVersion != Vmmi.VMMDLL_MAP_NET_VERSION) { goto fail; }
            m = new NetEntry[nM.cMap];
            for (int i = 0; i < nM.cMap; i++)
            {
                Vmmi.VMMDLL_MAP_NETENTRY n = Marshal.PtrToStructure<Vmmi.VMMDLL_MAP_NETENTRY>((System.IntPtr)(pMap.ToInt64() + cbMAP + i * cbENTRY));
                NetEntry e;
                e.dwPID = n.dwPID;
                e.dwState = n.dwState;
                e.dwPoolTag = n.dwPoolTag;
                e.AF = n.AF;
                e.src.fValid = n.src_fValid;
                e.src.port = n.src_port;
                e.src.pbAddr = n.src_pbAddr;
                e.src.sText = n.src_uszText;
                e.dst.fValid = n.dst_fValid;
                e.dst.port = n.dst_port;
                e.dst.pbAddr = n.dst_pbAddr;
                e.dst.sText = n.dst_uszText;
                e.vaObj = n.vaObj;
                e.ftTime = n.ftTime;
                e.sText = n.uszText;
                m[i] = e;
            }
        fail:
            Vmmi.VMMDLL_MemFree((byte*)pMap.ToPointer());
            return m;
        }

        /// <summary>
        /// Retrieve the physical memory map.
        /// </summary>
        /// <returns>An array of MemoryEntry elements.</returns>
        public unsafe MemoryEntry[] MapMemory()
        {
            int cbMAP = System.Runtime.InteropServices.Marshal.SizeOf<Vmmi.VMMDLL_MAP_PHYSMEM>();
            int cbENTRY = System.Runtime.InteropServices.Marshal.SizeOf<Vmmi.VMMDLL_MAP_PHYSMEMENTRY>();
            IntPtr pMap = IntPtr.Zero;
            MemoryEntry[] m = new MemoryEntry[0];
            if (!Vmmi.VMMDLL_Map_GetPhysMem(hVMM, out pMap)) { goto fail; }
            Vmmi.VMMDLL_MAP_PHYSMEM nM = Marshal.PtrToStructure<Vmmi.VMMDLL_MAP_PHYSMEM>(pMap);
            if (nM.dwVersion != Vmmi.VMMDLL_MAP_PHYSMEM_VERSION) { goto fail; }
            m = new MemoryEntry[nM.cMap];
            for (int i = 0; i < nM.cMap; i++)
            {
                Vmmi.VMMDLL_MAP_PHYSMEMENTRY n = Marshal.PtrToStructure<Vmmi.VMMDLL_MAP_PHYSMEMENTRY>((System.IntPtr)(pMap.ToInt64() + cbMAP + i * cbENTRY));
                MemoryEntry e;
                e.pa = n.pa;
                e.cb = n.cb;
                m[i] = e;
            }
        fail:
            Vmmi.VMMDLL_MemFree((byte*)pMap.ToPointer());
            return m;
        }

        /// <summary>
        /// Retrieve the kernel devices on the system.
        /// </summary>
        /// <returns>An array of KDeviceEntry elements.</returns>
        public unsafe KDeviceEntry[] MapKDevice()
        {
            int cbMAP = System.Runtime.InteropServices.Marshal.SizeOf<Vmmi.VMMDLL_MAP_KDEVICE>();
            int cbENTRY = System.Runtime.InteropServices.Marshal.SizeOf<Vmmi.VMMDLL_MAP_KDEVICEENTRY>();
            IntPtr pMap = IntPtr.Zero;
            KDeviceEntry[] m = new KDeviceEntry[0];
            if (!Vmmi.VMMDLL_Map_GetKDevice(hVMM, out pMap)) { goto fail; }
            Vmmi.VMMDLL_MAP_KDEVICE nM = Marshal.PtrToStructure<Vmmi.VMMDLL_MAP_KDEVICE>(pMap);
            if (nM.dwVersion != Vmmi.VMMDLL_MAP_KDEVICE_VERSION) { goto fail; }
            m = new KDeviceEntry[nM.cMap];
            for (int i = 0; i < nM.cMap; i++)
            {
                Vmmi.VMMDLL_MAP_KDEVICEENTRY n = Marshal.PtrToStructure<Vmmi.VMMDLL_MAP_KDEVICEENTRY>((System.IntPtr)(pMap.ToInt64() + cbMAP + i * cbENTRY));
                KDeviceEntry e;
                e.va = n.va;
                e.iDepth = n.iDepth;
                e.dwDeviceType = n.dwDeviceType;
                e.sDeviceType = n.uszDeviceType;
                e.vaDriverObject = n.vaDriverObject;
                e.vaAttachedDevice = n.vaAttachedDevice;
                e.vaFileSystemDevice = n.vaFileSystemDevice;
                e.sVolumeInfo = n.uszVolumeInfo;
                m[i] = e;
            }
        fail:
            Vmmi.VMMDLL_MemFree((byte*)pMap.ToPointer());
            return m;
        }

        /// <summary>
        /// Retrieve the kernel drivers on the system.
        /// </summary>
        /// <returns>An array of KDriverEntry elements.</returns>
        public unsafe KDriverEntry[] MapKDriver()
        {
            int cbMAP = System.Runtime.InteropServices.Marshal.SizeOf<Vmmi.VMMDLL_MAP_KDRIVER>();
            int cbENTRY = System.Runtime.InteropServices.Marshal.SizeOf<Vmmi.VMMDLL_MAP_KDRIVERENTRY>();
            IntPtr pMap = IntPtr.Zero;
            KDriverEntry[] m = new KDriverEntry[0];
            if (!Vmmi.VMMDLL_Map_GetKDriver(hVMM, out pMap)) { goto fail; }
            Vmmi.VMMDLL_MAP_KDRIVER nM = Marshal.PtrToStructure<Vmmi.VMMDLL_MAP_KDRIVER>(pMap);
            if (nM.dwVersion != Vmmi.VMMDLL_MAP_KDRIVER_VERSION) { goto fail; }
            m = new KDriverEntry[nM.cMap];
            for (int i = 0; i < nM.cMap; i++)
            {
                Vmmi.VMMDLL_MAP_KDRIVERENTRY n = Marshal.PtrToStructure<Vmmi.VMMDLL_MAP_KDRIVERENTRY>((System.IntPtr)(pMap.ToInt64() + cbMAP + i * cbENTRY));
                KDriverEntry e;
                e.va = n.va;
                e.vaDriverStart = n.vaDriverStart;
                e.cbDriverSize = n.cbDriverSize;
                e.vaDeviceObject = n.vaDeviceObject;
                e.sName = n.uszName;
                e.sPath = n.uszPath;
                e.sServiceKeyName = n.uszServiceKeyName;
                e.MajorFunction = new ulong[28];
                for (int j = 0; j < 28; j++)
                {
                    e.MajorFunction[j] = n.MajorFunction[j];
                }
                m[i] = e;
            }
        fail:
            Vmmi.VMMDLL_MemFree((byte*)pMap.ToPointer());
            return m;
        }

        /// <summary>
        /// Retrieve the kernel named objects on the system.
        /// </summary>
        /// <returns>An array of KObjectEntry elements.</returns>
        public unsafe KObjectEntry[] MapKObject()
        {
            int cbMAP = System.Runtime.InteropServices.Marshal.SizeOf<Vmmi.VMMDLL_MAP_KOBJECT>();
            int cbENTRY = System.Runtime.InteropServices.Marshal.SizeOf<Vmmi.VMMDLL_MAP_KOBJECTENTRY>();
            IntPtr pMap = IntPtr.Zero;
            KObjectEntry[] m = new KObjectEntry[0];
            if (!Vmmi.VMMDLL_Map_GetKObject(hVMM, out pMap)) { goto fail; }
            Vmmi.VMMDLL_MAP_KOBJECT nM = Marshal.PtrToStructure<Vmmi.VMMDLL_MAP_KOBJECT>(pMap);
            if (nM.dwVersion != Vmmi.VMMDLL_MAP_KOBJECT_VERSION) { goto fail; }
            m = new KObjectEntry[nM.cMap];
            for (int i = 0; i < nM.cMap; i++)
            {
                Vmmi.VMMDLL_MAP_KOBJECTENTRY n = Marshal.PtrToStructure<Vmmi.VMMDLL_MAP_KOBJECTENTRY>((System.IntPtr)(pMap.ToInt64() + cbMAP + i * cbENTRY));
                KObjectEntry e;
                e.va = n.va;
                e.vaParent = n.vaParent;
                e.vaChild = new ulong[n.cvaChild];
                for (int j = 0; j < n.cvaChild; j++)
                {
                    e.vaChild[j] = (ulong)Marshal.ReadInt64(n.pvaChild, j * 8);
                }
                e.sName = n.uszName;
                e.sType = n.uszType;
                m[i] = e;
            }
        fail:
            Vmmi.VMMDLL_MemFree((byte*)pMap.ToPointer());
            return m;
        }

        /// <summary>
        /// Retrieve entries from the kernel pool.
        /// </summary>
        /// <param name="isBigPoolOnly">Set to true to only retrieve big pool allocations (= faster). Default is to retrieve all allocations.</param>
        /// <returns>An array of PoolEntry elements.</returns>
        public unsafe PoolEntry[] MapPool(bool isBigPoolOnly = false)
        {
            byte[] tag = { 0, 0, 0, 0 };
            IntPtr pN = IntPtr.Zero;
            int cbMAP = System.Runtime.InteropServices.Marshal.SizeOf<Vmmi.VMMDLL_MAP_POOL>();
            int cbENTRY = System.Runtime.InteropServices.Marshal.SizeOf<Vmmi.VMMDLL_MAP_POOLENTRY>();
            uint flags = isBigPoolOnly ? Vmmi.VMMDLL_POOLMAP_FLAG_BIG : Vmmi.VMMDLL_POOLMAP_FLAG_ALL;
            if (!Vmmi.VMMDLL_Map_GetPool(hVMM, out pN, flags)) { return new PoolEntry[0]; }
            Vmmi.VMMDLL_MAP_POOL nM = Marshal.PtrToStructure<Vmmi.VMMDLL_MAP_POOL>(pN);
            if (nM.dwVersion != Vmmi.VMMDLL_MAP_POOL_VERSION)
            {
                Vmmi.VMMDLL_MemFree((byte*)pN.ToPointer());
                return new PoolEntry[0];
            }
            PoolEntry[] eM = new PoolEntry[nM.cMap];
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

        /// <summary>
        /// Retrieve the detected users on the system.
        /// </summary>
        /// <returns>An array of UserEntry elements.</returns>
        public unsafe UserEntry[] MapUser()
        {
            int cbMAP = System.Runtime.InteropServices.Marshal.SizeOf<Vmmi.VMMDLL_MAP_USER>();
            int cbENTRY = System.Runtime.InteropServices.Marshal.SizeOf<Vmmi.VMMDLL_MAP_USERENTRY>();
            IntPtr pMap = IntPtr.Zero;
            UserEntry[] m = new UserEntry[0];
            if (!Vmmi.VMMDLL_Map_GetUsers(hVMM, out pMap)) { goto fail; }
            Vmmi.VMMDLL_MAP_USER nM = Marshal.PtrToStructure<Vmmi.VMMDLL_MAP_USER>(pMap);
            if (nM.dwVersion != Vmmi.VMMDLL_MAP_USER_VERSION) { goto fail; }
            m = new UserEntry[nM.cMap];
            for (int i = 0; i < nM.cMap; i++)
            {
                Vmmi.VMMDLL_MAP_USERENTRY n = Marshal.PtrToStructure<Vmmi.VMMDLL_MAP_USERENTRY>((System.IntPtr)(pMap.ToInt64() + cbMAP + i * cbENTRY));
                UserEntry e;
                e.sSID = n.uszSID;
                e.sText = n.uszText;
                e.vaRegHive = n.vaRegHive;
                m[i] = e;
            }
        fail:
            Vmmi.VMMDLL_MemFree((byte*)pMap.ToPointer());
            return m;
        }

        /// <summary>
        /// Retrieve the detected virtual machines on the system. This includes Hyper-V, WSL and other virtual machines running on top of the Windows Hypervisor Platform.
        /// </summary>
        /// <returns>An array of VirtualMachineEntry elements.</returns>
        public unsafe VirtualMachineEntry[] MapVirtualMachine()
        {
            int cbMAP = System.Runtime.InteropServices.Marshal.SizeOf<Vmmi.VMMDLL_MAP_VM>();
            int cbENTRY = System.Runtime.InteropServices.Marshal.SizeOf<Vmmi.VMMDLL_MAP_VMENTRY>();
            IntPtr pMap = IntPtr.Zero;
            VirtualMachineEntry[] m = new VirtualMachineEntry[0];
            if (!Vmmi.VMMDLL_Map_GetVM(hVMM, out pMap)) { goto fail; }
            Vmmi.VMMDLL_MAP_VM nM = Marshal.PtrToStructure<Vmmi.VMMDLL_MAP_VM>(pMap);
            if (nM.dwVersion != Vmmi.VMMDLL_MAP_VM_VERSION) { goto fail; }
            m = new VirtualMachineEntry[nM.cMap];
            for (int i = 0; i < nM.cMap; i++)
            {
                Vmmi.VMMDLL_MAP_VMENTRY n = Marshal.PtrToStructure<Vmmi.VMMDLL_MAP_VMENTRY>((System.IntPtr)(pMap.ToInt64() + cbMAP + i * cbENTRY));
                VirtualMachineEntry e;
                e.hVM = n.hVM;
                e.sName = n.uszName;
                e.gpaMax = n.gpaMax;
                e.tp = n.tp;
                e.fActive = n.fActive;
                e.fReadOnly = n.fReadOnly;
                e.fPhysicalOnly = n.fPhysicalOnly;
                e.dwPartitionID = n.dwPartitionID;
                e.dwVersionBuild = n.dwVersionBuild;
                e.tpSystem = n.tpSystem;
                e.dwParentVmmMountID = n.dwParentVmmMountID;
                e.dwVmMemPID = n.dwVmMemPID;
                m[i] = e;
            }
        fail:
            Vmmi.VMMDLL_MemFree((byte*)pMap.ToPointer());
            return m;
        }

        /// <summary>
        /// Retrieve the services on the system.
        /// </summary>
        /// <returns>An array of ServiceEntry elements.</returns>
        public unsafe ServiceEntry[] MapService()
        {
            int cbMAP = System.Runtime.InteropServices.Marshal.SizeOf<Vmmi.VMMDLL_MAP_SERVICE>();
            int cbENTRY = System.Runtime.InteropServices.Marshal.SizeOf<Vmmi.VMMDLL_MAP_SERVICEENTRY>();
            IntPtr pMap = IntPtr.Zero;
            ServiceEntry[] m = new ServiceEntry[0];
            if (!Vmmi.VMMDLL_Map_GetServices(hVMM, out pMap)) { goto fail; }
            Vmmi.VMMDLL_MAP_SERVICE nM = Marshal.PtrToStructure<Vmmi.VMMDLL_MAP_SERVICE>(pMap);
            if (nM.dwVersion != Vmmi.VMMDLL_MAP_SERVICE_VERSION) { goto fail; }
            m = new ServiceEntry[nM.cMap];
            for (int i = 0; i < nM.cMap; i++)
            {
                Vmmi.VMMDLL_MAP_SERVICEENTRY n = Marshal.PtrToStructure<Vmmi.VMMDLL_MAP_SERVICEENTRY>((System.IntPtr)(pMap.ToInt64() + cbMAP + i * cbENTRY));
                ServiceEntry e;
                e.vaObj = n.vaObj;
                e.dwPID = n.dwPID;
                e.dwOrdinal = n.dwOrdinal;
                e.sServiceName = n.uszServiceName;
                e.sDisplayName = n.uszDisplayName;
                e.sPath = n.uszPath;
                e.sUserTp = n.uszUserTp;
                e.sUserAcct = n.uszUserAcct;
                e.sImagePath = n.uszImagePath;
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

        /// <summary>
        /// Retrieve the PFN entries for the specified PFNs.
        /// </summary>
        /// <param name="pfns">the pfn numbers of the pfns to retrieve.</param>
        /// <returns></returns>
        public unsafe PfnEntry[] MapPfn(params uint[] pfns)
        {
            bool result;
            uint cbPfns;
            int cbMAP = System.Runtime.InteropServices.Marshal.SizeOf<Vmmi.VMMDLL_MAP_PFN>();
            int cbENTRY = System.Runtime.InteropServices.Marshal.SizeOf<Vmmi.VMMDLL_MAP_PFNENTRY>();
            if (pfns.Length == 0) { return new PfnEntry[0]; }
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
                    if (!result) { return new PfnEntry[0]; }
                    Vmmi.VMMDLL_MAP_PFN pm = Marshal.PtrToStructure<Vmmi.VMMDLL_MAP_PFN>((System.IntPtr)pb);
                    if (pm.dwVersion != Vmmi.VMMDLL_MAP_PFN_VERSION) { return new PfnEntry[0]; }
                    PfnEntry[] m = new PfnEntry[pm.cMap];
                    for (int i = 0; i < pm.cMap; i++)
                    {
                        Vmmi.VMMDLL_MAP_PFNENTRY n = Marshal.PtrToStructure<Vmmi.VMMDLL_MAP_PFNENTRY>((System.IntPtr)(pb + cbMAP + i * cbENTRY));
                        PfnEntry e = new PfnEntry();
                        e.dwPfn = n.dwPfn;
                        e.tp = (PfnType)((n._u3 >> 16) & 0x07);
                        e.tpExtended = (PfnTypeExtended)n.tpExtended;
                        e.vaPte = n.vaPte;
                        e.OriginalPte = n.OriginalPte;
                        e.fModified = ((n._u3 >> 20) & 1) == 1;
                        e.fReadInProgress = ((n._u3 >> 21) & 1) == 1;
                        e.fWriteInProgress = ((n._u3 >> 19) & 1) == 1;
                        e.priority = (byte)((n._u3 >> 24) & 7);
                        e.fPrototype = ((n._u4 >> 57) & 1) == 1;
                        if ((e.tp == PfnType.Active) && !e.fPrototype)
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

        #endregion // Map functionality


        #region Search functionality (physical memory)
        /// <summary>
        /// Instantiate a new VmmSearch object to be used to search memory using binary rules.
        /// </summary>
        /// <param name="addr_min"></param>
        /// <param name="addr_max"></param>
        /// <param name="cMaxResult"></param>
        /// <param name="readFlags"></param>
        /// <returns></returns>
        public VmmSearch Search(ulong addr_min = 0, ulong addr_max = UInt64.MaxValue, uint cMaxResult = 0, uint readFlags = 0)
        {
            return new VmmSearch(this, uint.MaxValue, addr_min, addr_max, cMaxResult, readFlags);
        }

        /// <summary>
        /// Instantiate a new VmmYara object to be used to search memory using multiple yara rules.
        /// </summary>
        /// <param name="addr_min"></param>
        /// <param name="addr_max"></param>
        /// <param name="cMaxResult"></param>
        /// <param name="readFlags"></param>
        /// <returns></returns>
        public VmmYara SearchYara(string[] yara_rules, ulong addr_min = 0, ulong addr_max = UInt64.MaxValue, uint cMaxResult = 0, uint readFlags = 0)
        {
            return new VmmYara(this, uint.MaxValue, yara_rules, addr_min, addr_max, cMaxResult, readFlags);
        }

        /// <summary>
        /// Instantiate a new VmmYara object to be used to search memory using a single yara rule.
        /// </summary>
        /// <param name="yara_rule"></param>
        /// <param name="addr_min"></param>
        /// <param name="addr_max"></param>
        /// <param name="cMaxResult"></param>
        /// <param name="readFlags"></param>
        /// <returns></returns>
        public VmmYara SearchYara(string yara_rule, ulong addr_min = 0, ulong addr_max = UInt64.MaxValue, uint cMaxResult = 0, uint readFlags = 0)
        {
            string[] yara_rules = new string[1] { yara_rule };
            return new VmmYara(this, uint.MaxValue, yara_rules, addr_min, addr_max, cMaxResult, readFlags);
        }
        #endregion Search functionality (physical memory)


        #region Utility functionality
        /// <summary>
        /// Convert a byte array to a hexdump formatted string. (static method).
        /// </summary>
        /// <param name="pbData">The data to convert.</param>
        /// <param name="initialOffset">The iniital offset (default = 0).</param>
        /// <returns>A string in hexdump format representing the binary data pbData.</returns>
        public unsafe static string UtilFillHexAscii(byte[] pbData, uint initialOffset = 0)
        {
            bool result;
            uint cbIn = (uint)pbData.Length;
            uint cbOut = 0;
            fixed (byte* pbIn = pbData)
            {
                result = Vmmi.VMMDLL_UtilFillHexAscii(pbIn, cbIn, initialOffset, null, ref cbOut);
                if (!result) { return null; }
                byte[] dataOut = new byte[cbOut];
                fixed (byte* pbOut = dataOut)
                {
                    result = Vmmi.VMMDLL_UtilFillHexAscii(pbIn, cbIn, initialOffset, pbOut, ref cbOut);
                    return result ? Encoding.ASCII.GetString(dataOut) : null;
                }
            }
        }


        /// <summary>
        /// Enum used to specify the log level.
        /// </summary>
        public enum LogLevel
        {
            Critical = 1,   // critical stopping error
            Warning = 2,    // severe warning error
            Info = 3,       // normal/info message
            Verbose = 4,    // verbose message (visible with -v)
            Debug = 5,      // debug message (visible with -vv)
            Trace = 6,      // trace message
        }

        /// <summary>
        /// Log a string to the VMM log.
        /// </summary>
        /// <param name="message">The message to log.</param>
        /// <param name="logLevel">The log level (default INFO).</param>
        /// <param name="MID">Module ID (default = API).</param>
        public unsafe void Log(string message, LogLevel logLevel = LogLevel.Info, uint MID = 0x80000011)
        {
            Vmmi.VMMDLL_Log(hVMM, MID, (uint)logLevel, "%s", message);
        }

        /// <summary>
        /// VmmKernel convenience object.
        /// </summary>
        /// <returns>The VmmKernel object.</returns>
        public VmmKernel Kernel => new VmmKernel(this);
        #endregion // Utility functionality
    }
}
