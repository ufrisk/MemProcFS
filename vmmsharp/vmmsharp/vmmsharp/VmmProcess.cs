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
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;
using Vmmsharp.Internal;

namespace Vmmsharp
{
    /// <summary>
    /// VmmProcess represents a process in the system.
    /// </summary>
    public class VmmProcess
    {
        #region Base Functionality

        protected readonly Vmm _hVmm;

        /// <summary>
        /// Process ID for this Process.
        /// </summary>
        public uint PID { get; }

        private ProcessInfo? _info;

        /// <summary>
        /// Process information for this process. Returns NULL if unable to lookup.
        /// Cached from first access, to get new information call GetInfo().
        /// </summary>
        public ProcessInfo? Info
        {
            get
            {
                if (_info is ProcessInfo result)
                    return result;
                else
                {
                    var info = this.GetInfo(out bool success);
                    if (success)
                        return _info = info;
                    return null;
                }
            }
        }

        /// <summary>
        /// True if this is a valid process, otherwise False.
        /// </summary>
        public bool IsValid
        {
            get
            {
                if (this.Info is ProcessInfo info)
                    return info.fValid;
                return false;
            }
        }

        /// <summary>
        /// Name of this process.
        /// Returns NULL if unable to parse.
        /// </summary>
        public string Name
        {
            get
            {
                if (this.Info is ProcessInfo info)
                    return info.sName;
                return null;
            }
        }


        private VmmProcess() { }

        /// <summary>
        /// Create a new VmmProcess object from a process name.
        /// Performs validation to ensure the process exists.
        /// </summary>
        /// <param name="hVmm">Vmm instance.</param>
        /// <param name="name">Name of process.</param>
        /// <exception cref="VmmException"></exception>
        internal VmmProcess(Vmm hVmm, string name)
        {
            if (hVmm is null)
                throw new ArgumentNullException(nameof(hVmm));
            if (string.IsNullOrWhiteSpace(name))
                throw new ArgumentNullException(nameof(name));
            if (!Vmmi.VMMDLL_PidGetFromName(hVmm, name, out uint pid))
                throw new VmmException("Failed to get PID from process name: " + name);
            PID = pid;
            _hVmm = hVmm;
        }

        /// <summary>
        /// Create a new VmmProcess object from a PID.
        /// WARNING: No validation is performed to ensure the process exists. Please check the IsValid property.
        /// </summary>
        /// <param name="hVmm">Vmm instance.</param>
        /// <param name="pid">Process ID to wrap.</param>
        internal VmmProcess(Vmm hVmm, uint pid)
        {
            if (hVmm is null)
                throw new ArgumentNullException(nameof(hVmm));
            PID = pid;
            _hVmm = hVmm;
        }

        /// <summary>
        /// ToString() override.
        /// </summary>
        /// <returns></returns>
        public override string ToString()
        {
            return "VmmProcess:" + PID;
        }

        #endregion

        #region Memory Read/Write
        /// <summary>
        /// Performs a Scatter Read on a collection of page-aligned Virtual Addresses.
        /// </summary>
        /// <param name="flags">VMM Flags</param>
        /// <param name="va">Array of Virtual Addresses to read.</param>
        /// <returns>Array of MEM_SCATTER structures.</returns>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public LeechCore.MemScatter[] MemReadScatter(uint flags, params ulong[] va) =>
            Vmmi.MemReadScatter(_hVmm, this.PID, flags, va);

#if NET5_0_OR_GREATER
        /// <summary>
        /// Perform a scatter read of multiple page-sized physical memory ranges.
        /// Does not copy the read memory to a managed byte buffer, but instead allows direct access to the native memory via a Span view.
        /// </summary>
        /// <param name="flags">Vmm Flags.</param>
        /// <param name="va">Array of page-aligned Memory Addresses.</param>
        /// <returns>SCATTER_HANDLE</returns>
        /// <exception cref="VmmException"></exception>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public unsafe LeechCore.SCATTER_HANDLE MemReadScatter2(uint flags, params ulong[] va) =>
        Vmmi.MemReadScatter2(_hVmm, this.PID, flags, va);
#endif

        /// <summary>
        /// Initialize a Scatter Memory Read handle used to read multiple virtual memory regions in a single call.
        /// </summary>
        /// <param name="flags">Vmm Flags.</param>
        /// <returns>A VmmScatterMemory handle.</returns>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public VmmScatterMemory Scatter_Initialize(uint flags = 0) =>
            Vmmi.Scatter_Initialize(_hVmm, this.PID, flags);

        /// <summary>
        /// Read Memory from a Virtual Address into a managed byte-array.
        /// </summary>
        /// <param name="va">Virtual Address to read from.</param>
        /// <param name="cb">Count of bytes to read.</param>
        /// <param name="flags">VMM Flags.</param>
        /// <returns>Managed byte array containing number of bytes read.</returns>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public unsafe byte[] MemRead(ulong va, uint cb, uint flags = 0) =>
            Vmmi.MemReadArray<byte>(_hVmm, this.PID, va, cb, flags);

        /// <summary>
        /// Read Memory from a Virtual Address into unmanaged memory.
        /// </summary>
        /// <param name="va">Virtual Address to read from.</param>
        /// <param name="pb">Pointer to buffer to receive read.</param>
        /// <param name="cb">Count of bytes to read.</param>
        /// <param name="cbRead">Count of bytes successfully read.</param>
        /// <param name="flags">VMM Flags.</param>
        /// <returns>True if successful, otherwise False. Be sure to check cbRead count.</returns>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public unsafe bool MemRead(ulong va, IntPtr pb, uint cb, out uint cbRead, uint flags = 0) =>
            Vmmi.MemRead(_hVmm, this.PID, va, pb.ToPointer(), cb, out cbRead, flags);

        /// <summary>
        /// Read Memory from a Virtual Address into unmanaged memory.
        /// </summary>
        /// <param name="va">Virtual Address to read from.</param>
        /// <param name="pb">Pointer to buffer to receive read.</param>
        /// <param name="cb">Count of bytes to read.</param>
        /// <param name="cbRead">Count of bytes successfully read.</param>
        /// <param name="flags">VMM Flags.</param>
        /// <returns>True if successful, otherwise False. Be sure to check cbRead count.</returns>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public unsafe bool MemRead(ulong va, void* pb, uint cb, out uint cbRead, uint flags = 0) =>
            Vmmi.MemRead(_hVmm, this.PID, va, pb, cb, out cbRead, flags);

        /// <summary>
        /// Read Memory from a Virtual Address into a nullable struct of Type <typeparamref name="T"/>.
        /// </summary>
        /// <typeparam name="T">Struct Type.</typeparam>
        /// <param name="va">Virtual Address to read from.</param>
        /// <param name="flags">VMM Flags.</param>
        /// <returns>Result if successful, otherwise NULL.</returns>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public unsafe T? MemReadAs<T>(ulong va, uint flags = 0)
            where T : unmanaged =>
            Vmmi.MemReadAs<T>(_hVmm, this.PID, va, flags);

#if NET9_0_OR_GREATER

        /// <summary>
        /// Read Memory from a Virtual Address into a ref struct of Type <typeparamref name="T"/>.
        /// </summary>
        /// <typeparam name="T">Struct/Ref Struct Type.</typeparam>
        /// <param name="va">Virtual Address to read from.</param>
        /// <param name="result">Memory read result.</param>
        /// <param name="flags">VMM Flags.</param>
        /// <returns>TRUE if successful, otherwise FALSE.</returns>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public unsafe bool MemReadRefAs<T>(ulong va, out T result, uint flags = 0)
            where T : unmanaged, allows ref struct =>
            Vmmi.MemReadRefAs<T>(_hVmm, this.PID, va, out result, flags);
#endif

        /// <summary>
        /// Read Memory from a Virtual Address into an Array of Type <typeparamref name="T"/>.
        /// </summary>
        /// <typeparam name="T">Value Type.</typeparam>
        /// <param name="va">Virtual Address to read from.</param>
        /// <param name="count">Number of elements to read.</param>
        /// <param name="flags">VMM Flags.</param>
        /// <returns>Managed <typeparamref name="T"/> array containing number of elements read.</returns>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public unsafe T[] MemReadArray<T>(ulong va, uint count, uint flags = 0)
            where T : unmanaged =>
            Vmmi.MemReadArray<T>(_hVmm, this.PID, va, count, flags);

#if NET5_0_OR_GREATER
        /// <summary>
        /// Read memory into a Span of <typeparamref name="T"/>.
        /// </summary>
        /// <typeparam name="T">Value Type</typeparam>
        /// <param name="va">Memory address to read from.</param>
        /// <param name="span">Span to receive the memory read.</param>
        /// <param name="cbRead">Number of bytes successfully read.</param>
        /// <param name="flags">Read flags.</param>
        /// <returns>True if successful, otherwise False.
        /// Please be sure to also check the cbRead out value.</returns>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public unsafe bool MemReadSpan<T>(ulong va, Span<T> span, out uint cbRead, uint flags)
            where T : unmanaged =>
            Vmmi.MemReadSpan(_hVmm, this.PID, va, span, out cbRead, flags);

        /// <summary>
        /// Write memory from a Span of <typeparamref name="T"/> to a specified memory address.
        /// </summary>
        /// <typeparam name="T">Value Type</typeparam>
        /// <param name="va">Memory address to write to.</param>
        /// <param name="span">Span to write from.</param>
        /// <returns>True if successful, otherwise False.</returns>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public unsafe bool MemWriteSpan<T>(ulong va, Span<T> span)
            where T : unmanaged =>
            Vmmi.MemWriteSpan(_hVmm, this.PID, va, span);
#endif

        /// <summary>
        /// Read Memory from a Virtual Address into a Managed String.
        /// </summary>
        /// <param name="encoding">String Encoding for this read.</param>
        /// <param name="va">Virtual Address to read from.</param>
        /// <param name="cb">Number of bytes to read. Keep in mind some string encodings are 2-4 bytes per character.</param>
        /// <param name="flags">VMM Flags.</param>
        /// <param name="terminateOnNullChar">Terminate the string at the first occurrence of the null character.</param>
        /// <returns>C# Managed System.String. Null if failed.</returns>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public unsafe string MemReadString(Encoding encoding, ulong va, uint cb,
            uint flags = 0, bool terminateOnNullChar = true) =>
            Vmmi.MemReadString(_hVmm, encoding, this.PID, va, cb, flags, terminateOnNullChar);

        /// <summary>
        /// Prefetch pages into the MemProcFS internal cache.
        /// </summary>
        /// <param name="va">An array of the virtual addresses to prefetch.</param>
        /// <returns></returns>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public unsafe bool MemPrefetchPages(ulong[] va) =>
            Vmmi.MemPrefetchPages(_hVmm, this.PID, va);

        /// <summary>
        /// Write Memory from a managed byte-array to a given Virtual Address.
        /// </summary>
        /// <param name="va">Virtual Address to write to.</param>
        /// <param name="data">Data to be written.</param>
        /// <returns>True if write successful, otherwise False.</returns>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public unsafe bool MemWrite(ulong va, byte[] data) =>
            Vmmi.MemWriteArray<byte>(_hVmm, this.PID, va, data);

        /// <summary>
        /// Write Memory from unmanaged memory to a given Virtual Address.
        /// </summary>
        /// <param name="va">Virtual Address to write to.</param>
        /// <param name="pb">Pointer to buffer to write from.</param>
        /// <param name="cb">Count of bytes to write.</param>
        /// <returns>True if write successful, otherwise False.</returns>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public unsafe bool MemWrite(ulong va, IntPtr pb, uint cb) =>
            Vmmi.MemWrite(_hVmm, this.PID, va, pb.ToPointer(), cb);

        /// <summary>
        /// Write Memory from unmanaged memory to a given Virtual Address.
        /// </summary>
        /// <param name="va">Virtual Address to write to.</param>
        /// <param name="pb">Pointer to buffer to write from.</param>
        /// <param name="cb">Count of bytes to write.</param>
        /// <returns>True if write successful, otherwise False.</returns>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public unsafe bool MemWrite(ulong va, void* pb, uint cb) =>
            Vmmi.MemWrite(_hVmm, this.PID, va, pb, cb);

        /// <summary>
        /// Write Memory from a struct value <typeparamref name="T"/> to a given Virtual Address.
        /// </summary>
        /// <typeparam name="T">Value Type.</typeparam>
        /// <param name="va">Virtual Address to write to.</param>
        /// <param name="value"><typeparamref name="T"/> Value to write.</param>
        /// <returns>True if write successful, otherwise False.</returns>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public unsafe bool MemWriteStruct<T>(ulong va, T value)
            where T : unmanaged
#if NET9_0_OR_GREATER
            , allows ref struct
#endif
            =>
            Vmmi.MemWriteStruct(_hVmm, this.PID, va, value);

        /// <summary>
        /// Write Memory from a managed <typeparamref name="T"/> Array to a given Virtual Address.
        /// </summary>
        /// <typeparam name="T">Value Type.</typeparam>
        /// <param name="va">Virtual Address to write to.</param>
        /// <param name="data">Managed <typeparamref name="T"/> array to write.</param>
        /// <param name="flags">VMM Flags.</param>
        /// <returns>True if write successful, otherwise False.</returns>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public unsafe bool MemWriteArray<T>(ulong va, T[] data)
            where T : unmanaged =>
            Vmmi.MemWriteArray(_hVmm, this.PID, va, data);

        /// <summary>
        /// Translate a virtual address to a physical address.
        /// </summary>
        /// <param name="va">Virtual address to translate from.</param>
        /// <returns>Physical address if successful, zero on fail.</returns>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public ulong MemVirt2Phys(ulong va)
        {
            ulong pa = 0;
            Vmmi.MemVirt2Phys(_hVmm, this.PID, va, out pa);
            return pa;
        }
#endregion

        #region Process Functionality
        /// <summary>
        /// PTE (Page Table Entry) information.
        /// </summary>
        /// <param name="fIdentifyModules"></param>
        /// <returns>Array of PTEs on success. Zero-length array on fail.</returns>
        public unsafe PteEntry[] MapPTE(bool fIdentifyModules = true)
        {
            int cbMAP = System.Runtime.InteropServices.Marshal.SizeOf<Vmmi.VMMDLL_MAP_PTE>();
            int cbENTRY = System.Runtime.InteropServices.Marshal.SizeOf<Vmmi.VMMDLL_MAP_PTEENTRY>();
            IntPtr pMap = IntPtr.Zero;
            PteEntry[] m = new PteEntry[0];
            if (!Vmmi.VMMDLL_Map_GetPte(_hVmm, this.PID, fIdentifyModules, out pMap)) { goto fail; }
            Vmmi.VMMDLL_MAP_PTE nM = Marshal.PtrToStructure<Vmmi.VMMDLL_MAP_PTE>(pMap);
            if (nM.dwVersion != Vmmi.VMMDLL_MAP_PTE_VERSION) { goto fail; }
            m = new PteEntry[nM.cMap];
            for (int i = 0; i < nM.cMap; i++)
            {
                Vmmi.VMMDLL_MAP_PTEENTRY n = Marshal.PtrToStructure<Vmmi.VMMDLL_MAP_PTEENTRY>((System.IntPtr)(pMap.ToInt64() + cbMAP + i * cbENTRY));
                PteEntry e;
                e.vaBase = n.vaBase;
                e.vaEnd = n.vaBase + (n.cPages << 12) - 1;
                e.cbSize = n.cPages << 12;
                e.cPages = n.cPages;
                e.fPage = n.fPage;
                e.fWoW64 = n.fWoW64;
                e.sText = n.uszText;
                e.cSoftware = n.cSoftware;
                e.fR = true;
                e.fW = (0 != (e.fPage & 0x0000000000000002)) ? true : false;
                e.fS = (0 != (e.fPage & 0x0000000000000004)) ? false : true;
                e.fX = (0 != (e.fPage & 0x8000000000000000)) ? false : true;
                m[i] = e;
            }
        fail:
            Vmmi.VMMDLL_MemFree((byte*)pMap.ToPointer());
            return m;
        }

        /// <summary>
        /// VAD (Virtual Address Descriptor) information.
        /// </summary>
        /// <param name="fIdentifyModules"></param>
        /// <returns></returns>
        public unsafe VadEntry[] MapVAD(bool fIdentifyModules = true)
        {
            int cbMAP = System.Runtime.InteropServices.Marshal.SizeOf<Vmmi.VMMDLL_MAP_VAD>();
            int cbENTRY = System.Runtime.InteropServices.Marshal.SizeOf<Vmmi.VMMDLL_MAP_VADENTRY>();
            IntPtr pMap = IntPtr.Zero;
            VadEntry[] m = new VadEntry[0];
            if (!Vmmi.VMMDLL_Map_GetVad(_hVmm, this.PID, fIdentifyModules, out pMap)) { goto fail; }
            Vmmi.VMMDLL_MAP_VAD nM = Marshal.PtrToStructure<Vmmi.VMMDLL_MAP_VAD>(pMap);
            if (nM.dwVersion != Vmmi.VMMDLL_MAP_VAD_VERSION) { goto fail; }
            m = new VadEntry[nM.cMap];
            for (int i = 0; i < nM.cMap; i++)
            {
                Vmmi.VMMDLL_MAP_VADENTRY n = Marshal.PtrToStructure<Vmmi.VMMDLL_MAP_VADENTRY>((System.IntPtr)(pMap.ToInt64() + cbMAP + i * cbENTRY));
                VadEntry e;
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
                e.sText = n.uszText;
                e.vaFileObject = n.vaFileObject;
                e.cVadExPages = n.cVadExPages;
                e.cVadExPagesBase = n.cVadExPagesBase;
                m[i] = e;
            }
        fail:
            Vmmi.VMMDLL_MemFree((byte*)pMap.ToPointer());
            return m;
        }

        /// <summary>
        /// Extended VAD (Virtual Address Descriptor) information.
        /// </summary>
        /// <param name="oPages"></param>
        /// <param name="cPages"></param>
        /// <returns></returns>
        public unsafe VadExEntry[] MapVADEx(uint oPages, uint cPages)
        {
            int cbMAP = System.Runtime.InteropServices.Marshal.SizeOf<Vmmi.VMMDLL_MAP_VADEX>();
            int cbENTRY = System.Runtime.InteropServices.Marshal.SizeOf<Vmmi.VMMDLL_MAP_VADEXENTRY>();
            IntPtr pMap = IntPtr.Zero;
            VadExEntry[] m = new VadExEntry[0];
            if (!Vmmi.VMMDLL_Map_GetVadEx(_hVmm, this.PID, oPages, cPages, out pMap)) { goto fail; }
            Vmmi.VMMDLL_MAP_VADEX nM = Marshal.PtrToStructure<Vmmi.VMMDLL_MAP_VADEX>(pMap);
            if (nM.dwVersion != Vmmi.VMMDLL_MAP_VADEX_VERSION) { goto fail; }
            m = new VadExEntry[nM.cMap];
            for (int i = 0; i < nM.cMap; i++)
            {
                Vmmi.VMMDLL_MAP_VADEXENTRY n = Marshal.PtrToStructure<Vmmi.VMMDLL_MAP_VADEXENTRY>((System.IntPtr)(pMap.ToInt64() + cbMAP + i * cbENTRY));
                VadExEntry e;
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
            Vmmi.VMMDLL_MemFree((byte*)pMap.ToPointer());
            return m;
        }

        /// <summary>
        /// Module (loaded DLLs) information.
        /// </summary>
        /// <param name="fExtendedInfo"></param>
        /// <returns></returns>
        public unsafe ModuleEntry[] MapModule(bool fExtendedInfo = false)
        {
            int cbMAP = System.Runtime.InteropServices.Marshal.SizeOf<Vmmi.VMMDLL_MAP_MODULE>();
            int cbENTRY = System.Runtime.InteropServices.Marshal.SizeOf<Vmmi.VMMDLL_MAP_MODULEENTRY>();
            IntPtr pMap = IntPtr.Zero;
            ModuleEntry[] m = new ModuleEntry[0];
            uint flags = fExtendedInfo ? (uint)0xff : 0;
            if (!Vmmi.VMMDLL_Map_GetModule(_hVmm, this.PID, out pMap, flags)) { goto fail; }
            Vmmi.VMMDLL_MAP_MODULE nM = Marshal.PtrToStructure<Vmmi.VMMDLL_MAP_MODULE>(pMap);
            if (nM.dwVersion != Vmmi.VMMDLL_MAP_MODULE_VERSION) { goto fail; }
            m = new ModuleEntry[nM.cMap];
            for (int i = 0; i < nM.cMap; i++)
            {
                Vmmi.VMMDLL_MAP_MODULEENTRY n = Marshal.PtrToStructure<Vmmi.VMMDLL_MAP_MODULEENTRY>((System.IntPtr)(pMap.ToInt64() + cbMAP + i * cbENTRY));
                ModuleEntry e;
                ModuleEntryDebugInfo eDbg;
                ModuleEntryVersionInfo eVer;
                e.fValid = true;
                e.vaBase = n.vaBase;
                e.vaEntry = n.vaEntry;
                e.cbImageSize = n.cbImageSize;
                e.fWow64 = n.fWow64;
                e.sText = n.uszText;
                e.sFullName = n.uszFullName;
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
                    eDbg.sGuid = "";
                    eDbg.sPdbFilename = "";
                }
                else
                {
                    Vmmi.VMMDLL_MAP_MODULEENTRY_DEBUGINFO nDbg = Marshal.PtrToStructure<Vmmi.VMMDLL_MAP_MODULEENTRY_DEBUGINFO>(n.pExDebugInfo);
                    eDbg.fValid = true;
                    eDbg.dwAge = nDbg.dwAge;
                    eDbg.sGuid = nDbg.uszGuid;
                    eDbg.sPdbFilename = nDbg.uszPdbFilename;
                }
                e.DebugInfo = eDbg;
                // Extended Version Information
                if (n.pExDebugInfo.ToInt64() == 0)
                {
                    eVer.fValid = false;
                    eVer.sCompanyName = "";
                    eVer.sFileDescription = "";
                    eVer.sFileVersion = "";
                    eVer.sInternalName = "";
                    eVer.sLegalCopyright = "";
                    eVer.sFileOriginalFilename = "";
                    eVer.sProductName = "";
                    eVer.sProductVersion = "";
                }
                else
                {
                    Vmmi.VMMDLL_MAP_MODULEENTRY_VERSIONINFO nVer = Marshal.PtrToStructure<Vmmi.VMMDLL_MAP_MODULEENTRY_VERSIONINFO>(n.pExVersionInfo);
                    eVer.fValid = true;
                    eVer.sCompanyName = nVer.uszCompanyName;
                    eVer.sFileDescription = nVer.uszFileDescription;
                    eVer.sFileVersion = nVer.uszFileVersion;
                    eVer.sInternalName = nVer.uszInternalName;
                    eVer.sLegalCopyright = nVer.uszLegalCopyright;
                    eVer.sFileOriginalFilename = nVer.uszFileOriginalFilename;
                    eVer.sProductName = nVer.uszProductName;
                    eVer.sProductVersion = nVer.uszProductVersion;
                }
                e.VersionInfo = eVer;
                m[i] = e;
            }
        fail:
            Vmmi.VMMDLL_MemFree((byte*)pMap.ToPointer());
            return m;
        }

        /// <summary>
        /// Get a module from its name. If more than one module with the same name is loaded, the first one is returned.
        /// </summary>
        /// <param name="module"></param>
        /// <returns></returns>
        public unsafe ModuleEntry MapModuleFromName(string module)
        {
            IntPtr pMap = IntPtr.Zero;
            ModuleEntry e = new ModuleEntry();
            if (!Vmmi.VMMDLL_Map_GetModuleFromName(_hVmm, this.PID, module, out pMap, 0)) { goto fail; }
            Vmmi.VMMDLL_MAP_MODULEENTRY nM = Marshal.PtrToStructure<Vmmi.VMMDLL_MAP_MODULEENTRY>(pMap);
            e.fValid = true;
            e.vaBase = nM.vaBase;
            e.vaEntry = nM.vaEntry;
            e.cbImageSize = nM.cbImageSize;
            e.fWow64 = nM.fWow64;
            e.sText = module;
            e.sFullName = nM.uszFullName;
            e.tp = nM.tp;
            e.cbFileSizeRaw = nM.cbFileSizeRaw;
            e.cSection = nM.cSection;
            e.cEAT = nM.cEAT;
            e.cIAT = nM.cIAT;
        fail:
            Vmmi.VMMDLL_MemFree((byte*)pMap.ToPointer());
            return e;
        }

        /// <summary>
        /// Unloaded module information.
        /// </summary>
        /// <returns></returns>
        public unsafe UnloadedModuleEntry[] MapUnloadedModule()
        {
            int cbMAP = System.Runtime.InteropServices.Marshal.SizeOf<Vmmi.VMMDLL_MAP_UNLOADEDMODULE>();
            int cbENTRY = System.Runtime.InteropServices.Marshal.SizeOf<Vmmi.VMMDLL_MAP_UNLOADEDMODULEENTRY>();
            IntPtr pMap = IntPtr.Zero;
            UnloadedModuleEntry[] m = new UnloadedModuleEntry[0];
            if (!Vmmi.VMMDLL_Map_GetUnloadedModule(_hVmm, this.PID, out pMap)) { goto fail; }
            Vmmi.VMMDLL_MAP_UNLOADEDMODULE nM = Marshal.PtrToStructure<Vmmi.VMMDLL_MAP_UNLOADEDMODULE>(pMap);
            if (nM.dwVersion != Vmmi.VMMDLL_MAP_UNLOADEDMODULE_VERSION) { goto fail; }
            m = new UnloadedModuleEntry[nM.cMap];
            for (int i = 0; i < nM.cMap; i++)
            {
                Vmmi.VMMDLL_MAP_UNLOADEDMODULEENTRY n = Marshal.PtrToStructure<Vmmi.VMMDLL_MAP_UNLOADEDMODULEENTRY>((System.IntPtr)(pMap.ToInt64() + cbMAP + i * cbENTRY));
                UnloadedModuleEntry e;
                e.vaBase = n.vaBase;
                e.cbImageSize = n.cbImageSize;
                e.fWow64 = n.fWow64;
                e.wText = n.uszText;
                e.dwCheckSum = n.dwCheckSum;
                e.dwTimeDateStamp = n.dwTimeDateStamp;
                e.ftUnload = n.ftUnload;
                m[i] = e;
            }
        fail:
            Vmmi.VMMDLL_MemFree((byte*)pMap.ToPointer());
            return m;
        }

        /// <summary>
        /// EAT (Export Address Table) information.
        /// </summary>
        /// <param name="module"></param>
        /// <returns></returns>
        public unsafe EATEntry[] MapModuleEAT(string module)
        {
            return MapModuleEAT(module, out _);
        }

        /// <summary>
        /// EAT (Export Address Table) information.
        /// </summary>
        /// <param name="module"></param>
        /// <param name="info"></param>
        /// <returns></returns>
        public unsafe EATEntry[] MapModuleEAT(string module, out EATInfo info)
        {
            info = new EATInfo();
            int cbMAP = System.Runtime.InteropServices.Marshal.SizeOf<Vmmi.VMMDLL_MAP_EAT>();
            int cbENTRY = System.Runtime.InteropServices.Marshal.SizeOf<Vmmi.VMMDLL_MAP_EATENTRY>();
            IntPtr pMap = IntPtr.Zero;
            EATEntry[] m = new EATEntry[0];
            if (!Vmmi.VMMDLL_Map_GetEAT(_hVmm, this.PID, module, out pMap)) { goto fail; }
            Vmmi.VMMDLL_MAP_EAT nM = Marshal.PtrToStructure<Vmmi.VMMDLL_MAP_EAT>(pMap);
            if (nM.dwVersion != Vmmi.VMMDLL_MAP_EAT_VERSION) { goto fail; }
            m = new EATEntry[nM.cMap];
            for (int i = 0; i < nM.cMap; i++)
            {
                Vmmi.VMMDLL_MAP_EATENTRY n = Marshal.PtrToStructure<Vmmi.VMMDLL_MAP_EATENTRY>((System.IntPtr)(pMap.ToInt64() + cbMAP + i * cbENTRY));
                EATEntry e;
                e.vaFunction = n.vaFunction;
                e.dwOrdinal = n.dwOrdinal;
                e.oFunctionsArray = n.oFunctionsArray;
                e.oNamesArray = n.oNamesArray;
                e.sFunction = n.uszFunction;
                e.sForwardedFunction = n.uszForwardedFunction;
                m[i] = e;
            }
            info.fValid = true;
            info.vaModuleBase = nM.vaModuleBase;
            info.vaAddressOfFunctions = nM.vaAddressOfFunctions;
            info.vaAddressOfNames = nM.vaAddressOfNames;
            info.cNumberOfFunctions = nM.cNumberOfFunctions;
            info.cNumberOfForwardedFunctions = nM.cNumberOfForwardedFunctions;
            info.cNumberOfNames = nM.cNumberOfNames;
            info.dwOrdinalBase = nM.dwOrdinalBase;
        fail:
            Vmmi.VMMDLL_MemFree((byte*)pMap.ToPointer());
            return m;
        }

        /// <summary>
        /// IAT (Import Address Table) information.
        /// </summary>
        /// <param name="module"></param>
        /// <returns></returns>
        public unsafe IATEntry[] MapModuleIAT(string module)
        {
            int cbMAP = System.Runtime.InteropServices.Marshal.SizeOf<Vmmi.VMMDLL_MAP_IAT>();
            int cbENTRY = System.Runtime.InteropServices.Marshal.SizeOf<Vmmi.VMMDLL_MAP_IATENTRY>();
            IntPtr pMap = IntPtr.Zero;
            IATEntry[] m = new IATEntry[0];
            if (!Vmmi.VMMDLL_Map_GetIAT(_hVmm, this.PID, module, out pMap)) { goto fail; }
            Vmmi.VMMDLL_MAP_IAT nM = Marshal.PtrToStructure<Vmmi.VMMDLL_MAP_IAT>(pMap);
            if (nM.dwVersion != Vmmi.VMMDLL_MAP_IAT_VERSION) { goto fail; }
            m = new IATEntry[nM.cMap];
            for (int i = 0; i < nM.cMap; i++)
            {
                Vmmi.VMMDLL_MAP_IATENTRY n = Marshal.PtrToStructure<Vmmi.VMMDLL_MAP_IATENTRY>((System.IntPtr)(pMap.ToInt64() + cbMAP + i * cbENTRY));
                IATEntry e;
                e.vaFunction = n.vaFunction;
                e.sFunction = n.uszFunction;
                e.sModule = n.uszModule;
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
            Vmmi.VMMDLL_MemFree((byte*)pMap.ToPointer());
            return m;
        }

        /// <summary>
        /// Heap information.
        /// </summary>
        /// <returns></returns>
        public unsafe HeapMap MapHeap()
        {
            IntPtr pMap = IntPtr.Zero;
            int cbMAP = System.Runtime.InteropServices.Marshal.SizeOf<Vmmi.VMMDLL_MAP_HEAP>();
            int cbENTRY = System.Runtime.InteropServices.Marshal.SizeOf<Vmmi.VMMDLL_MAP_HEAPENTRY>();
            int cbSEGENTRY = System.Runtime.InteropServices.Marshal.SizeOf<Vmmi.VMMDLL_MAP_HEAPSEGMENTENTRY>();
            HeapMap Heap;
            Heap.heaps = new HeapEntry[0];
            Heap.segments = new HeapSegmentEntry[0];
            if (!Vmmi.VMMDLL_Map_GetHeap(_hVmm, this.PID, out pMap)) { goto fail; }
            Vmmi.VMMDLL_MAP_HEAP nM = Marshal.PtrToStructure<Vmmi.VMMDLL_MAP_HEAP>(pMap);
            if (nM.dwVersion != Vmmi.VMMDLL_MAP_HEAP_VERSION) { goto fail; }
            Heap.heaps = new HeapEntry[nM.cMap];
            for (int i = 0; i < nM.cMap; i++)
            {
                Vmmi.VMMDLL_MAP_HEAPENTRY nH = Marshal.PtrToStructure<Vmmi.VMMDLL_MAP_HEAPENTRY>((System.IntPtr)(pMap.ToInt64() + cbMAP + i * cbENTRY));
                Heap.heaps[i].va = nH.va;
                Heap.heaps[i].f32 = nH.f32;
                Heap.heaps[i].tpHeap = nH.tp;
                Heap.heaps[i].iHeapNum = nH.dwHeapNum;
            }
            Heap.segments = new HeapSegmentEntry[nM.cSegments];
            for (int i = 0; i < nM.cMap; i++)
            {
                Vmmi.VMMDLL_MAP_HEAPSEGMENTENTRY nH = Marshal.PtrToStructure<Vmmi.VMMDLL_MAP_HEAPSEGMENTENTRY>((System.IntPtr)(nM.pSegments.ToInt64() + i * cbSEGENTRY));
                Heap.segments[i].va = nH.va;
                Heap.segments[i].cb = nH.cb;
                Heap.segments[i].tpHeapSegment = nH.tp;
                Heap.segments[i].iHeapNum = nH.iHeap;
            }
        fail:
            Vmmi.VMMDLL_MemFree((byte*)pMap.ToPointer());
            return Heap;
        }

        /// <summary>
        /// Heap allocated entries information.
        /// </summary>
        /// <param name="vaHeapOrHeapNum"></param>
        /// <returns></returns>
        public unsafe HeapAllocEntry[] MapHeapAlloc(ulong vaHeapOrHeapNum)
        {
            IntPtr pHeapAllocMap = IntPtr.Zero;
            int cbMAP = System.Runtime.InteropServices.Marshal.SizeOf<Vmmi.VMMDLL_MAP_HEAPALLOC>();
            int cbENTRY = System.Runtime.InteropServices.Marshal.SizeOf<Vmmi.VMMDLL_MAP_HEAPALLOCENTRY>();
            if (!Vmmi.VMMDLL_Map_GetHeapAlloc(_hVmm, this.PID, vaHeapOrHeapNum, out pHeapAllocMap)) { return new HeapAllocEntry[0]; }
            Vmmi.VMMDLL_MAP_HEAPALLOC nM = Marshal.PtrToStructure<Vmmi.VMMDLL_MAP_HEAPALLOC>(pHeapAllocMap);
            if (nM.dwVersion != Vmmi.VMMDLL_MAP_HEAPALLOC_VERSION)
            {
                Vmmi.VMMDLL_MemFree((byte*)pHeapAllocMap.ToPointer());
                return new HeapAllocEntry[0];
            }
            HeapAllocEntry[] m = new HeapAllocEntry[nM.cMap];
            for (int i = 0; i < nM.cMap; i++)
            {
                Vmmi.VMMDLL_MAP_HEAPALLOCENTRY n = Marshal.PtrToStructure<Vmmi.VMMDLL_MAP_HEAPALLOCENTRY>((System.IntPtr)(pHeapAllocMap.ToInt64() + cbMAP + i * cbENTRY));
                m[i].va = n.va;
                m[i].cb = n.cb;
                m[i].tp = n.tp;
            }
            Vmmi.VMMDLL_MemFree((byte*)pHeapAllocMap.ToPointer());
            return m;
        }

        /// <summary>
        /// Thread information.
        /// </summary>
        /// <returns></returns>
        public unsafe ThreadEntry[] MapThread()
        {
            int cbMAP = System.Runtime.InteropServices.Marshal.SizeOf<Vmmi.VMMDLL_MAP_THREAD>();
            int cbENTRY = System.Runtime.InteropServices.Marshal.SizeOf<Vmmi.VMMDLL_MAP_THREADENTRY>();
            IntPtr pMap = IntPtr.Zero;
            ThreadEntry[] m = new ThreadEntry[0];
            if (!Vmmi.VMMDLL_Map_GetThread(_hVmm, this.PID, out pMap)) { goto fail; }
            Vmmi.VMMDLL_MAP_THREAD nM = Marshal.PtrToStructure<Vmmi.VMMDLL_MAP_THREAD>(pMap);
            if (nM.dwVersion != Vmmi.VMMDLL_MAP_THREAD_VERSION) { goto fail; }
            m = new ThreadEntry[nM.cMap];
            for (int i = 0; i < nM.cMap; i++)
            {
                Vmmi.VMMDLL_MAP_THREADENTRY n = Marshal.PtrToStructure<Vmmi.VMMDLL_MAP_THREADENTRY>((System.IntPtr)(pMap.ToInt64() + cbMAP + i * cbENTRY));
                ThreadEntry e;
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
            Vmmi.VMMDLL_MemFree((byte*)pMap.ToPointer());
            return m;
        }

        /// <summary>
        /// Thread callstack information.
        /// </summary>
        /// <param name="tid">The thread id to retrieve the callstack for.</param>
        /// <param name="flags">Supported flags: 0, FLAG_NOCACHE, FLAG_FORCECACHE_READ</param>
        /// <returns></returns>
        public unsafe ThreadCallstackEntry[] MapThreadCallstack(uint tid, uint flags = 0)
        {
            int cbMAP = System.Runtime.InteropServices.Marshal.SizeOf<Vmmi.VMMDLL_MAP_THREAD_CALLSTACK>();
            int cbENTRY = System.Runtime.InteropServices.Marshal.SizeOf<Vmmi.VMMDLL_MAP_THREAD_CALLSTACKENTRY>();
            IntPtr pMap = IntPtr.Zero;
            ThreadCallstackEntry[] m = new ThreadCallstackEntry[0];
            if (!Vmmi.VMMDLL_Map_GetThread_Callstack(_hVmm, this.PID, tid, flags, out pMap)) { goto fail; }
            Vmmi.VMMDLL_MAP_THREAD_CALLSTACK nM = Marshal.PtrToStructure<Vmmi.VMMDLL_MAP_THREAD_CALLSTACK>(pMap);
            if (nM.dwVersion != Vmmi.VMMDLL_MAP_THREAD_CALLSTACK_VERSION) { goto fail; }
            m = new ThreadCallstackEntry[nM.cMap];
            for (int i = 0; i < nM.cMap; i++)
            {
                Vmmi.VMMDLL_MAP_THREAD_CALLSTACKENTRY n = Marshal.PtrToStructure<Vmmi.VMMDLL_MAP_THREAD_CALLSTACKENTRY>((System.IntPtr)(pMap.ToInt64() + cbMAP + i * cbENTRY));
                ThreadCallstackEntry e;
                e.dwPID = this.PID;
                e.dwTID = tid;
                e.i = n.i;
                e.fRegPresent = n.fRegPresent;
                e.vaRetAddr = n.vaRetAddr;
                e.vaRSP = n.vaRSP;
                e.vaBaseSP = n.vaBaseSP;
                e.cbDisplacement = (int)n.cbDisplacement;
                e.sModule = n.uszModule;
                e.sFunction = n.uszFunction;
                m[i] = e;
            }
        fail:
            Vmmi.VMMDLL_MemFree((byte*)pMap.ToPointer());
            return m;
        }

        /// <summary>
        /// Handle information.
        /// </summary>
        /// <returns></returns>
        public unsafe HandleEntry[] MapHandle()
        {
            int cbMAP = System.Runtime.InteropServices.Marshal.SizeOf<Vmmi.VMMDLL_MAP_HANDLE>();
            int cbENTRY = System.Runtime.InteropServices.Marshal.SizeOf<Vmmi.VMMDLL_MAP_HANDLEENTRY>();
            IntPtr pMap = IntPtr.Zero;
            HandleEntry[] m = new HandleEntry[0];
            if (!Vmmi.VMMDLL_Map_GetHandle(_hVmm, this.PID, out pMap)) { goto fail; }
            Vmmi.VMMDLL_MAP_HANDLE nM = Marshal.PtrToStructure<Vmmi.VMMDLL_MAP_HANDLE>(pMap);
            if (nM.dwVersion != Vmmi.VMMDLL_MAP_HANDLE_VERSION) { goto fail; }
            m = new HandleEntry[nM.cMap];
            for (int i = 0; i < nM.cMap; i++)
            {
                Vmmi.VMMDLL_MAP_HANDLEENTRY n = Marshal.PtrToStructure<Vmmi.VMMDLL_MAP_HANDLEENTRY>((System.IntPtr)(pMap.ToInt64() + cbMAP + i * cbENTRY));
                HandleEntry e;
                e.vaObject = n.vaObject;
                e.dwHandle = n.dwHandle;
                e.dwGrantedAccess = n.dwGrantedAccess_iType & 0x00ffffff;
                e.iType = n.dwGrantedAccess_iType >> 24;
                e.qwHandleCount = n.qwHandleCount;
                e.qwPointerCount = n.qwPointerCount;
                e.vaObjectCreateInfo = n.vaObjectCreateInfo;
                e.vaSecurityDescriptor = n.vaSecurityDescriptor;
                e.sText = n.uszText;
                e.dwPID = n.dwPID;
                e.dwPoolTag = n.dwPoolTag;
                e.sType = n.uszType;
                m[i] = e;
            }
        fail:
            Vmmi.VMMDLL_MemFree((byte*)pMap.ToPointer());
            return m;
        }

        /// <summary>
        /// User mode path of the process image.
        /// </summary>
        /// <returns></returns>
        public string GetPathUser()
        {
            return GetInformationString(VmmProcess.VMMDLL_PROCESS_INFORMATION_OPT_STRING_PATH_USER_IMAGE);
        }

        /// <summary>
        /// Kernel mode path of the process image.
        /// </summary>
        /// <returns></returns>
        public string GetPathKernel()
        {
            return GetInformationString(VmmProcess.VMMDLL_PROCESS_INFORMATION_OPT_STRING_PATH_KERNEL);
        }

        /// <summary>
        /// Process command line.
        /// </summary>
        /// <returns></returns>
        public string GetCmdline()
        {
            return GetInformationString(VmmProcess.VMMDLL_PROCESS_INFORMATION_OPT_STRING_CMDLINE);
        }

        /// <summary>
        /// Get the string representation of an option value.
        /// </summary>
        /// <param name="fOptionString">VmmProcess.VMMDLL_PROCESS_INFORMATION_OPT_*</param>
        /// <returns></returns>
        public unsafe string GetInformationString(uint fOptionString)
        {
            byte* pb = Vmmi.VMMDLL_ProcessGetInformationString(_hVmm, this.PID, fOptionString);
            if (pb == null) { return ""; }
            string s = Marshal.PtrToStringAnsi((System.IntPtr)pb);
            Vmmi.VMMDLL_MemFree(pb);
            return s;
        }

        /// <summary>
        /// IMAGE_DATA_DIRECTORY information for the specified module.
        /// </summary>
        /// <param name="sModule"></param>
        /// <returns></returns>
        public unsafe IMAGE_DATA_DIRECTORY[] MapModuleDataDirectory(string sModule)
        {
            string[] PE_DATA_DIRECTORIES = new string[16] { "EXPORT", "IMPORT", "RESOURCE", "EXCEPTION", "SECURITY", "BASERELOC", "DEBUG", "ARCHITECTURE", "GLOBALPTR", "TLS", "LOAD_CONFIG", "BOUND_IMPORT", "IAT", "DELAY_IMPORT", "COM_DESCRIPTOR", "RESERVED" };
            bool result;
            uint cbENTRY = (uint)System.Runtime.InteropServices.Marshal.SizeOf<Vmmi.VMMDLL_IMAGE_DATA_DIRECTORY>();
            fixed (byte* pb = new byte[16 * cbENTRY])
            {
                result = Vmmi.VMMDLL_ProcessGetDirectories(_hVmm, this.PID, sModule, pb);
                if (!result) { return new IMAGE_DATA_DIRECTORY[0]; }
                IMAGE_DATA_DIRECTORY[] m = new IMAGE_DATA_DIRECTORY[16];
                for (int i = 0; i < 16; i++)
                {
                    Vmmi.VMMDLL_IMAGE_DATA_DIRECTORY n = Marshal.PtrToStructure<Vmmi.VMMDLL_IMAGE_DATA_DIRECTORY>((System.IntPtr)(pb + i * cbENTRY));
                    IMAGE_DATA_DIRECTORY e;
                    e.name = PE_DATA_DIRECTORIES[i];
                    e.VirtualAddress = n.VirtualAddress;
                    e.Size = n.Size;
                    m[i] = e;
                }
                return m;
            }
        }

        /// <summary>
        /// IMAGE_SECTION_HEADER information for the specified module.
        /// </summary>
        /// <param name="sModule"></param>
        /// <returns></returns>
        public unsafe IMAGE_SECTION_HEADER[] MapModuleSection(string sModule)
        {
            bool result;
            uint cData;
            uint cbENTRY = (uint)System.Runtime.InteropServices.Marshal.SizeOf<Vmmi.VMMDLL_IMAGE_SECTION_HEADER>();
            result = Vmmi.VMMDLL_ProcessGetSections(_hVmm, this.PID, sModule, null, 0, out cData);
            if (!result || (cData == 0)) { return new IMAGE_SECTION_HEADER[0]; }
            fixed (byte* pb = new byte[cData * cbENTRY])
            {
                result = Vmmi.VMMDLL_ProcessGetSections(_hVmm, this.PID, sModule, pb, cData, out cData);
                if (!result || (cData == 0)) { return new IMAGE_SECTION_HEADER[0]; }
                IMAGE_SECTION_HEADER[] m = new IMAGE_SECTION_HEADER[cData];
                for (int i = 0; i < cData; i++)
                {
                    Vmmi.VMMDLL_IMAGE_SECTION_HEADER n = Marshal.PtrToStructure<Vmmi.VMMDLL_IMAGE_SECTION_HEADER>((System.IntPtr)(pb + i * cbENTRY));
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

        /// <summary>
        /// Function address of a function in a loaded module.
        /// </summary>
        /// <param name="wszModuleName"></param>
        /// <param name="szFunctionName"></param>
        /// <returns></returns>
        public ulong GetProcAddress(string wszModuleName, string szFunctionName)
        {
            return Vmmi.VMMDLL_ProcessGetProcAddress(_hVmm, this.PID, wszModuleName, szFunctionName);
        }

        /// <summary>
        /// Base address of a loaded module.
        /// </summary>
        /// <param name="wszModuleName"></param>
        /// <returns></returns>
        public ulong GetModuleBase(string wszModuleName)
        {
            return Vmmi.VMMDLL_ProcessGetModuleBase(_hVmm, this.PID, wszModuleName);
        }

        /// <summary>
        /// Get process information.
        /// </summary>
        /// <returns>ProcessInformation on success. Null on fail.</returns>
        public unsafe ProcessInfo GetInfo()
        {
            return GetInfo(out _);
        }

        /// <summary>
        /// Get process information.
        /// </summary>
        /// <param name="result"></param>
        /// <returns>ProcessInformation on success. Null on fail.</returns>
        public unsafe ProcessInfo GetInfo(out bool result)
        {
            ulong cbENTRY = (ulong)System.Runtime.InteropServices.Marshal.SizeOf<Vmmi.VMMDLL_PROCESS_INFORMATION>();
            fixed (byte* pb = new byte[cbENTRY])
            {
                Marshal.WriteInt64(new IntPtr(pb + 0), unchecked((long)Vmmi.VMMDLL_PROCESS_INFORMATION_MAGIC));
                Marshal.WriteInt16(new IntPtr(pb + 8), unchecked((short)Vmmi.VMMDLL_PROCESS_INFORMATION_VERSION));
                result = Vmmi.VMMDLL_ProcessGetInformation(_hVmm, this.PID, pb, ref cbENTRY);
                if (!result) { return new ProcessInfo(); }
                Vmmi.VMMDLL_PROCESS_INFORMATION n = Marshal.PtrToStructure<Vmmi.VMMDLL_PROCESS_INFORMATION>((System.IntPtr)pb);
                if (n.wVersion != Vmmi.VMMDLL_PROCESS_INFORMATION_VERSION) { return new ProcessInfo(); }
                ProcessInfo e;
                e.fValid = true;
                e.tpMemoryModel = n.tpMemoryModel;
                e.tpSystem = n.tpSystem;
                e.fUserOnly = n.fUserOnly;
                e.dwPID = n.dwPID;
                e.dwPPID = n.dwPPID;
                e.dwState = n.dwState;
                e.sName = n.szName;
                e.sNameLong = n.szNameLong;
                e.paDTB = n.paDTB;
                e.paDTB_UserOpt = n.paDTB_UserOpt;
                e.vaEPROCESS = n.vaEPROCESS;
                e.vaPEB = n.vaPEB;
                e.fWow64 = n.fWow64;
                e.vaPEB32 = n.vaPEB32;
                e.dwSessionId = n.dwSessionId;
                e.qwLUID = n.qwLUID;
                e.sSID = n.szSID;
                e.IntegrityLevel = n.IntegrityLevel;
                return e;
            }
        }

        /// <summary>
        /// Retrieve the PDB given a module base address.
        /// </summary>
        /// <param name="vaModuleBase"></param>
        /// <returns></returns>
        public VmmPdb Pdb(ulong vaModuleBase)
        {
            return new VmmPdb(_hVmm, this.PID, vaModuleBase);
        }

        /// <summary>
        /// Retrieve the PDB given a module name.
        /// </summary>
        /// <param name="sModule"></param>
        /// <returns></returns>
        public VmmPdb Pdb(string sModule)
        {
            ModuleEntry eModule = MapModuleFromName(sModule);
            if(eModule.fValid == false)
            {
                throw new VmmException("Module not found.");
            }
            return Pdb(eModule.vaBase);
        }
        #endregion

        #region Search functionality (virtual process memory)
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
            return new VmmSearch(_hVmm, PID, addr_min, addr_max, cMaxResult, readFlags);
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
            return new VmmYara(_hVmm, PID, yara_rules, addr_min, addr_max, cMaxResult, readFlags);
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
            return new VmmYara(_hVmm, PID, yara_rules, addr_min, addr_max, cMaxResult, readFlags);
        }
        #endregion // Search functionality (virtual process memory)

        #region Types

        public struct ProcessInfo
        {
            public bool fValid;
            public uint tpMemoryModel;
            public uint tpSystem;
            public bool fUserOnly;
            public uint dwPID;
            public uint dwPPID;
            public uint dwState;
            public string sName;
            public string sNameLong;
            public ulong paDTB;
            public ulong paDTB_UserOpt;
            public ulong vaEPROCESS;
            public ulong vaPEB;
            public bool fWow64;
            public uint vaPEB32;
            public uint dwSessionId;
            public ulong qwLUID;
            public string sSID;
            public uint IntegrityLevel;
        }

        public struct PteEntry
        {
            public ulong vaBase;
            public ulong vaEnd;
            public ulong cbSize;
            public ulong cPages;
            public ulong fPage;
            public bool fWoW64;
            public string sText;
            public uint cSoftware;
            public bool fS;
            public bool fR;
            public bool fW;
            public bool fX;
        }

        public struct VadEntry
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
            public string sText;
            public ulong vaFileObject;
            public uint cVadExPages;
            public uint cVadExPagesBase;
        }

        public struct VadExEntryPrototype
        {
            public uint tp;
            public ulong pa;
            public ulong pte;
        }

        public struct VadExEntry
        {
            public uint tp;
            public uint iPML;
            public ulong va;
            public ulong pa;
            public ulong pte;
            public uint pteFlags;
            public VadExEntryPrototype proto;
            public ulong vaVadBase;
        }

        public const uint MAP_MODULEENTRY_TP_NORMAL = 0;
        public const uint VMMDLL_MODULE_TP_DATA = 1;
        public const uint VMMDLL_MODULE_TP_NOTLINKED = 2;
        public const uint VMMDLL_MODULE_TP_INJECTED = 3;

        public struct ModuleEntryDebugInfo
        {
            public bool fValid;
            public uint dwAge;
            public string sGuid;
            public string sPdbFilename;
        }

        public struct ModuleEntryVersionInfo
        {
            public bool fValid;
            public string sCompanyName;
            public string sFileDescription;
            public string sFileVersion;
            public string sInternalName;
            public string sLegalCopyright;
            public string sFileOriginalFilename;
            public string sProductName;
            public string sProductVersion;
        }

        public struct ModuleEntry
        {
            public bool fValid;
            public ulong vaBase;
            public ulong vaEntry;
            public uint cbImageSize;
            public bool fWow64;
            public string sText;
            public string sFullName;
            public uint tp;
            public uint cbFileSizeRaw;
            public uint cSection;
            public uint cEAT;
            public uint cIAT;
            public ModuleEntryDebugInfo DebugInfo;
            public ModuleEntryVersionInfo VersionInfo;
        }

        public struct UnloadedModuleEntry
        {
            public ulong vaBase;
            public uint cbImageSize;
            public bool fWow64;
            public string wText;
            public uint dwCheckSum;         // user-mode only
            public uint dwTimeDateStamp;    // user-mode only
            public ulong ftUnload;          // kernel-mode only
        }

        public struct EATInfo
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

        public struct EATEntry
        {
            public ulong vaFunction;
            public uint dwOrdinal;
            public uint oFunctionsArray;
            public uint oNamesArray;
            public string sFunction;
            public string sForwardedFunction;
        }

        public struct IATEntry
        {
            public ulong vaFunction;
            public ulong vaModule;
            public string sFunction;
            public string sModule;
            public bool f32;
            public ushort wHint;
            public uint rvaFirstThunk;
            public uint rvaOriginalFirstThunk;
            public uint rvaNameModule;
            public uint rvaNameFunction;
        }

        public struct HeapEntry
        {
            public ulong va;
            public uint tpHeap;
            public bool f32;
            public uint iHeapNum;
        }

        public struct HeapSegmentEntry
        {
            public ulong va;
            public uint cb;
            public uint tpHeapSegment;
            public uint iHeapNum;
        }

        public struct HeapMap
        {
            public HeapEntry[] heaps;
            public HeapSegmentEntry[] segments;
        }

        public struct HeapAllocEntry
        {
            public ulong va;
            public uint cb;
            public uint tp;
        }

        public struct ThreadEntry
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

        public struct ThreadCallstackEntry
        {
            public uint dwPID;
            public uint dwTID;
            public uint i;
            public bool fRegPresent;
            public ulong vaRetAddr;
            public ulong vaRSP;
            public ulong vaBaseSP;
            public int cbDisplacement;
            public string sModule;
            public string sFunction;
        }

        public struct HandleEntry
        {
            public ulong vaObject;
            public uint dwHandle;
            public uint dwGrantedAccess;
            public uint iType;
            public ulong qwHandleCount;
            public ulong qwPointerCount;
            public ulong vaObjectCreateInfo;
            public ulong vaSecurityDescriptor;
            public string sText;
            public uint dwPID;
            public uint dwPoolTag;
            public string sType;
        }

        public const uint VMMDLL_PROCESS_INFORMATION_OPT_STRING_PATH_KERNEL = 1;
        public const uint VMMDLL_PROCESS_INFORMATION_OPT_STRING_PATH_USER_IMAGE = 2;
        public const uint VMMDLL_PROCESS_INFORMATION_OPT_STRING_CMDLINE = 3;

        /// <summary>
        /// Struct corresponding to the native PE IMAGE_SECTION_HEADER.
        /// </summary>
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

        /// <summary>
        /// Struct corresponding to the native PE IMAGE_DATA_DIRECTORY.
        /// </summary>
        public struct IMAGE_DATA_DIRECTORY
        {
            public string name;
            public uint VirtualAddress;
            public uint Size;
        }
        #endregion
    }
}
