using System;
using System.Collections.Generic;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;
using Vmmsharp.Internal;

namespace Vmmsharp
{
    public class VmmProcess
    {
        protected readonly Vmm _hVmm;

        /// <summary>
        /// Process ID for this Process.
        /// </summary>
        public uint PID { get; }

        private PROCESS_INFORMATION? _info;

        /// <summary>
        /// Process information for this process. Returns NULL if unable to lookup.
        /// Cached from first access, to get new information call GetInformation.
        /// </summary>
        public PROCESS_INFORMATION? Info
        {
            get
            {
                if (_info is PROCESS_INFORMATION result)
                    return result;
                else
                {
                    var info = this.GetInformation(out bool success);
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
                if (this.Info is PROCESS_INFORMATION info)
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
                if (this.Info is PROCESS_INFORMATION info)
                    return info.szName;
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
        public VmmProcess(Vmm hVmm, string name)
        {
            if (hVmm is null)
                throw new ArgumentNullException(nameof(hVmm));
            if (string.IsNullOrWhiteSpace(name))
                throw new ArgumentNullException(nameof(name));
            if (!Vmmi.VMMDLL_PidGetFromName(_hVmm, name, out uint pid))
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
        public VmmProcess(Vmm hVmm, uint pid)
        {
            if (hVmm is null)
                throw new ArgumentNullException(nameof(hVmm));
            PID = pid;
            _hVmm = hVmm;
        }

        #region Memory Read/Write
        /// <summary>
        /// Performs a Scatter Read on a collection of page-aligned Virtual Addresses.
        /// </summary>
        /// <param name="flags">VMM Flags</param>
        /// <param name="qwA">Array of Virtual Addresses to read.</param>
        /// <returns>Array of MEM_SCATTER structures.</returns>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public LeechCore.MEM_SCATTER[] MemReadScatter(uint flags, params ulong[] qwA) =>
            _hVmm.MemReadScatter(this.PID, flags, qwA);

#if NET5_0_OR_GREATER
        /// <summary>
        /// Perform a scatter read of multiple page-sized physical memory ranges.
        /// Does not copy the read memory to a managed byte buffer, but instead allows direct access to the native memory via a Span view.
        /// </summary>
        /// <param name="flags">Vmm Flags.</param>
        /// <param name="qwA">Array of page-aligned Memory Addresses.</param>
        /// <returns>SCATTER_HANDLE</returns>
        /// <exception cref="VmmException"></exception>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public unsafe LeechCore.SCATTER_HANDLE MemReadScatter2(uint flags, params ulong[] qwA) =>
        _hVmm.MemReadScatter2(this.PID, flags, qwA);

#endif

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public VmmScatter Scatter_Initialize(uint flags) =>
            _hVmm.Scatter_Initialize(this.PID, flags);

        /// <summary>
        /// Read Memory from a Virtual Address into a managed byte-array.
        /// </summary>
        /// <param name="qwA">Virtual Address to read from.</param>
        /// <param name="cb">Count of bytes to read.</param>
        /// <param name="flags">VMM Flags.</param>
        /// <returns>Managed byte array containing number of bytes read.</returns>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public unsafe byte[] MemRead(ulong qwA, uint cb, uint flags = 0) =>
            _hVmm.MemReadArray<byte>(this.PID, qwA, cb, flags);

        /// <summary>
        /// Read Memory from a Virtual Address into unmanaged memory.
        /// </summary>
        /// <param name="qwA">Virtual Address to read from.</param>
        /// <param name="pb">Pointer to buffer to receive read.</param>
        /// <param name="cb">Count of bytes to read.</param>
        /// <param name="cbRead">Count of bytes successfully read.</param>
        /// <param name="flags">VMM Flags.</param>
        /// <returns>True if successful, otherwise False. Be sure to check cbRead count.</returns>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public unsafe bool MemRead(ulong qwA, IntPtr pb, uint cb, out uint cbRead, uint flags = 0) =>
            _hVmm.MemRead(this.PID, qwA, pb.ToPointer(), cb, out cbRead, flags);

        /// <summary>
        /// Read Memory from a Virtual Address into unmanaged memory.
        /// </summary>
        /// <param name="qwA">Virtual Address to read from.</param>
        /// <param name="pb">Pointer to buffer to receive read.</param>
        /// <param name="cb">Count of bytes to read.</param>
        /// <param name="cbRead">Count of bytes successfully read.</param>
        /// <param name="flags">VMM Flags.</param>
        /// <returns>True if successful, otherwise False. Be sure to check cbRead count.</returns>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public unsafe bool MemRead(ulong qwA, void* pb, uint cb, out uint cbRead, uint flags = 0) =>
            _hVmm.MemRead(this.PID, qwA, pb, cb, out cbRead, flags);

        /// <summary>
        /// Read Memory from a Virtual Address into a nullable struct of Type <typeparamref name="T"/>.
        /// </summary>
        /// <typeparam name="T">Struct Type.</typeparam>
        /// <param name="qwA">Virtual Address to read from.</param>
        /// <param name="flags">VMM Flags.</param>
        /// <returns>Result if successful, otherwise NULL.</returns>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public unsafe T? MemReadStruct<T>(ulong qwA, uint flags = 0)
            where T : unmanaged =>
            _hVmm.MemReadStruct<T>(this.PID, qwA, flags);

        /// <summary>
        /// Read Memory from a Virtual Address into an Array of Type <typeparamref name="T"/>.
        /// </summary>
        /// <typeparam name="T">Value Type.</typeparam>
        /// <param name="qwA">Virtual Address to read from.</param>
        /// <param name="count">Number of elements to read.</param>
        /// <param name="flags">VMM Flags.</param>
        /// <returns>Managed <typeparamref name="T"/> array containing number of elements read.</returns>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public unsafe T[] MemReadArray<T>(ulong qwA, uint count, uint flags = 0)
            where T : unmanaged =>
            _hVmm.MemReadArray<T>(this.PID, qwA, count, flags);

#if NET5_0_OR_GREATER
        /// <summary>
        /// Read memory into a Span of <typeparamref name="T"/>.
        /// </summary>
        /// <typeparam name="T">Value Type</typeparam>
        /// <param name="addr">Memory address to read from.</param>
        /// <param name="span">Span to receive the memory read.</param>
        /// <param name="cbRead">Number of bytes successfully read.</param>
        /// <param name="flags">Read flags.</param>
        /// <returns>True if successful, otherwise False.
        /// Please be sure to also check the cbRead out value.</returns>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public unsafe bool MemReadSpan<T>(ulong addr, Span<T> span, out uint cbRead, uint flags)
            where T : unmanaged =>
            _hVmm.MemReadSpan(this.PID, addr, span, out cbRead, flags);

        /// <summary>
        /// Write memory from a Span of <typeparamref name="T"/> to a specified memory address.
        /// </summary>
        /// <typeparam name="T">Value Type</typeparam>
        /// <param name="addr">Memory address to write to.</param>
        /// <param name="span">Span to write from.</param>
        /// <returns>True if successful, otherwise False.</returns>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public unsafe bool MemWriteSpan<T>(ulong addr, Span<T> span)
            where T : unmanaged =>
            _hVmm.MemWriteSpan(this.PID, addr, span);
#endif

        /// <summary>
        /// Read Memory from a Virtual Address into a Managed String.
        /// </summary>
        /// <param name="encoding">String Encoding for this read.</param>
        /// <param name="qwA">Virtual Address to read from.</param>
        /// <param name="cb">Number of bytes to read. Keep in mind some string encodings are 2-4 bytes per character.</param>
        /// <param name="flags">VMM Flags.</param>
        /// <param name="terminateOnNullChar">Terminate the string at the first occurrence of the null character.</param>
        /// <returns>C# Managed System.String. Null if failed.</returns>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public unsafe string MemReadString(Encoding encoding, ulong qwA, uint cb,
            uint flags = 0, bool terminateOnNullChar = true) =>
            _hVmm.MemReadString(encoding, this.PID, qwA, cb, flags, terminateOnNullChar);

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public unsafe bool MemPrefetchPages(ulong[] qwA) =>
            _hVmm.MemPrefetchPages(this.PID, qwA);

        /// <summary>
        /// Write Memory from a managed byte-array to a given Virtual Address.
        /// </summary>
        /// <param name="qwA">Virtual Address to write to.</param>
        /// <param name="data">Data to be written.</param>
        /// <returns>True if write successful, otherwise False.</returns>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public unsafe bool MemWrite(ulong qwA, byte[] data) =>
            _hVmm.MemWriteArray<byte>(this.PID, qwA, data);

        /// <summary>
        /// Write Memory from unmanaged memory to a given Virtual Address.
        /// </summary>
        /// <param name="qwA">Virtual Address to write to.</param>
        /// <param name="pb">Pointer to buffer to write from.</param>
        /// <param name="cb">Count of bytes to write.</param>
        /// <returns>True if write successful, otherwise False.</returns>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public unsafe bool MemWrite(ulong qwA, IntPtr pb, uint cb) =>
            _hVmm.MemWrite(this.PID, qwA, pb.ToPointer(), cb);

        /// <summary>
        /// Write Memory from unmanaged memory to a given Virtual Address.
        /// </summary>
        /// <param name="qwA">Virtual Address to write to.</param>
        /// <param name="pb">Pointer to buffer to write from.</param>
        /// <param name="cb">Count of bytes to write.</param>
        /// <returns>True if write successful, otherwise False.</returns>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public unsafe bool MemWrite(ulong qwA, void* pb, uint cb) =>
            _hVmm.MemWrite(this.PID, qwA, pb, cb);

        /// <summary>
        /// Write Memory from a struct value <typeparamref name="T"/> to a given Virtual Address.
        /// </summary>
        /// <typeparam name="T">Value Type.</typeparam>
        /// <param name="qwA">Virtual Address to write to.</param>
        /// <param name="value"><typeparamref name="T"/> Value to write.</param>
        /// <returns>True if write successful, otherwise False.</returns>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public unsafe bool MemWriteStruct<T>(ulong qwA, T value)
            where T : unmanaged =>
            _hVmm.MemWriteStruct(this.PID, qwA, value);

        /// <summary>
        /// Write Memory from a managed <typeparamref name="T"/> Array to a given Virtual Address.
        /// </summary>
        /// <typeparam name="T">Value Type.</typeparam>
        /// <param name="qwA">Virtual Address to write to.</param>
        /// <param name="data">Managed <typeparamref name="T"/> array to write.</param>
        /// <param name="flags">VMM Flags.</param>
        /// <returns>True if write successful, otherwise False.</returns>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public unsafe bool MemWriteArray<T>(ulong qwA, T[] data)
            where T : unmanaged =>
            _hVmm.MemWriteArray(this.PID, qwA, data);

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public bool MemVirt2Phys(ulong qwVA, out ulong pqwPA) =>
            _hVmm.MemVirt2Phys(this.PID, qwVA, out pqwPA);
        #endregion

        #region Process Functionality
        public unsafe MAP_PTEENTRY[] Map_GetPte( bool fIdentifyModules = true)
        {
            int cbMAP = System.Runtime.InteropServices.Marshal.SizeOf<Vmmi.VMMDLL_MAP_PTE>();
            int cbENTRY = System.Runtime.InteropServices.Marshal.SizeOf<Vmmi.VMMDLL_MAP_PTEENTRY>();
            IntPtr pMap = IntPtr.Zero;
            MAP_PTEENTRY[] m = new MAP_PTEENTRY[0];
            if (!Vmmi.VMMDLL_Map_GetPte(_hVmm, this.PID, fIdentifyModules, out pMap)) { goto fail; }
            Vmmi.VMMDLL_MAP_PTE nM = Marshal.PtrToStructure<Vmmi.VMMDLL_MAP_PTE>(pMap);
            if (nM.dwVersion != Vmmi.VMMDLL_MAP_PTE_VERSION) { goto fail; }
            m = new MAP_PTEENTRY[nM.cMap];
            for (int i = 0; i < nM.cMap; i++)
            {
                Vmmi.VMMDLL_MAP_PTEENTRY n = Marshal.PtrToStructure<Vmmi.VMMDLL_MAP_PTEENTRY>((System.IntPtr)(pMap.ToInt64() + cbMAP + i * cbENTRY));
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
            Vmmi.VMMDLL_MemFree((byte*)pMap.ToPointer());
            return m;
        }

        public unsafe MAP_VADENTRY[] Map_GetVad( bool fIdentifyModules = true)
        {
            int cbMAP = System.Runtime.InteropServices.Marshal.SizeOf<Vmmi.VMMDLL_MAP_VAD>();
            int cbENTRY = System.Runtime.InteropServices.Marshal.SizeOf<Vmmi.VMMDLL_MAP_VADENTRY>();
            IntPtr pMap = IntPtr.Zero;
            MAP_VADENTRY[] m = new MAP_VADENTRY[0];
            if (!Vmmi.VMMDLL_Map_GetVad(_hVmm, this.PID, fIdentifyModules, out pMap)) { goto fail; }
            Vmmi.VMMDLL_MAP_VAD nM = Marshal.PtrToStructure<Vmmi.VMMDLL_MAP_VAD>(pMap);
            if (nM.dwVersion != Vmmi.VMMDLL_MAP_VAD_VERSION) { goto fail; }
            m = new MAP_VADENTRY[nM.cMap];
            for (int i = 0; i < nM.cMap; i++)
            {
                Vmmi.VMMDLL_MAP_VADENTRY n = Marshal.PtrToStructure<Vmmi.VMMDLL_MAP_VADENTRY>((System.IntPtr)(pMap.ToInt64() + cbMAP + i * cbENTRY));
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
            Vmmi.VMMDLL_MemFree((byte*)pMap.ToPointer());
            return m;
        }

        public unsafe MAP_VADEXENTRY[] Map_GetVadEx( uint oPages, uint cPages)
        {
            int cbMAP = System.Runtime.InteropServices.Marshal.SizeOf<Vmmi.VMMDLL_MAP_VADEX>();
            int cbENTRY = System.Runtime.InteropServices.Marshal.SizeOf<Vmmi.VMMDLL_MAP_VADEXENTRY>();
            IntPtr pMap = IntPtr.Zero;
            MAP_VADEXENTRY[] m = new MAP_VADEXENTRY[0];
            if (!Vmmi.VMMDLL_Map_GetVadEx(_hVmm, this.PID, oPages, cPages, out pMap)) { goto fail; }
            Vmmi.VMMDLL_MAP_VADEX nM = Marshal.PtrToStructure<Vmmi.VMMDLL_MAP_VADEX>(pMap);
            if (nM.dwVersion != Vmmi.VMMDLL_MAP_VADEX_VERSION) { goto fail; }
            m = new MAP_VADEXENTRY[nM.cMap];
            for (int i = 0; i < nM.cMap; i++)
            {
                Vmmi.VMMDLL_MAP_VADEXENTRY n = Marshal.PtrToStructure<Vmmi.VMMDLL_MAP_VADEXENTRY>((System.IntPtr)(pMap.ToInt64() + cbMAP + i * cbENTRY));
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
            Vmmi.VMMDLL_MemFree((byte*)pMap.ToPointer());
            return m;
        }

        public unsafe MAP_MODULEENTRY[] Map_GetModule( bool fExtendedInfo)
        {
            int cbMAP = System.Runtime.InteropServices.Marshal.SizeOf<Vmmi.VMMDLL_MAP_MODULE>();
            int cbENTRY = System.Runtime.InteropServices.Marshal.SizeOf<Vmmi.VMMDLL_MAP_MODULEENTRY>();
            IntPtr pMap = IntPtr.Zero;
            MAP_MODULEENTRY[] m = new MAP_MODULEENTRY[0];
            uint flags = fExtendedInfo ? (uint)0xff : 0;
            if (!Vmmi.VMMDLL_Map_GetModule(_hVmm, this.PID, out pMap, flags)) { goto fail; }
            Vmmi.VMMDLL_MAP_MODULE nM = Marshal.PtrToStructure<Vmmi.VMMDLL_MAP_MODULE>(pMap);
            if (nM.dwVersion != Vmmi.VMMDLL_MAP_MODULE_VERSION) { goto fail; }
            m = new MAP_MODULEENTRY[nM.cMap];
            for (int i = 0; i < nM.cMap; i++)
            {
                Vmmi.VMMDLL_MAP_MODULEENTRY n = Marshal.PtrToStructure<Vmmi.VMMDLL_MAP_MODULEENTRY>((System.IntPtr)(pMap.ToInt64() + cbMAP + i * cbENTRY));
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
                    Vmmi.VMMDLL_MAP_MODULEENTRY_DEBUGINFO nDbg = Marshal.PtrToStructure<Vmmi.VMMDLL_MAP_MODULEENTRY_DEBUGINFO>(n.pExDebugInfo);
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
                    Vmmi.VMMDLL_MAP_MODULEENTRY_VERSIONINFO nVer = Marshal.PtrToStructure<Vmmi.VMMDLL_MAP_MODULEENTRY_VERSIONINFO>(n.pExVersionInfo);
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
            Vmmi.VMMDLL_MemFree((byte*)pMap.ToPointer());
            return m;
        }

        public unsafe MAP_MODULEENTRY Map_GetModuleFromName( string wszModuleName)
        {
            IntPtr pMap = IntPtr.Zero;
            MAP_MODULEENTRY e = new MAP_MODULEENTRY();
            if (!Vmmi.VMMDLL_Map_GetModuleFromName(_hVmm, this.PID, wszModuleName, out pMap, 0)) { goto fail; }
            Vmmi.VMMDLL_MAP_MODULEENTRY nM = Marshal.PtrToStructure<Vmmi.VMMDLL_MAP_MODULEENTRY>(pMap);
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
            Vmmi.VMMDLL_MemFree((byte*)pMap.ToPointer());
            return e;
        }

        public unsafe MAP_UNLOADEDMODULEENTRY[] Map_GetUnloadedModule()
        {
            int cbMAP = System.Runtime.InteropServices.Marshal.SizeOf<Vmmi.VMMDLL_MAP_UNLOADEDMODULE>();
            int cbENTRY = System.Runtime.InteropServices.Marshal.SizeOf<Vmmi.VMMDLL_MAP_UNLOADEDMODULEENTRY>();
            IntPtr pMap = IntPtr.Zero;
            MAP_UNLOADEDMODULEENTRY[] m = new MAP_UNLOADEDMODULEENTRY[0];
            if (!Vmmi.VMMDLL_Map_GetUnloadedModule(_hVmm, this.PID, out pMap)) { goto fail; }
            Vmmi.VMMDLL_MAP_UNLOADEDMODULE nM = Marshal.PtrToStructure<Vmmi.VMMDLL_MAP_UNLOADEDMODULE>(pMap);
            if (nM.dwVersion != Vmmi.VMMDLL_MAP_UNLOADEDMODULE_VERSION) { goto fail; }
            m = new MAP_UNLOADEDMODULEENTRY[nM.cMap];
            for (int i = 0; i < nM.cMap; i++)
            {
                Vmmi.VMMDLL_MAP_UNLOADEDMODULEENTRY n = Marshal.PtrToStructure<Vmmi.VMMDLL_MAP_UNLOADEDMODULEENTRY>((System.IntPtr)(pMap.ToInt64() + cbMAP + i * cbENTRY));
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
            Vmmi.VMMDLL_MemFree((byte*)pMap.ToPointer());
            return m;
        }

        public unsafe MAP_EATENTRY[] Map_GetEAT( string wszModule, out MAP_EATINFO EatInfo)
        {
            EatInfo = new MAP_EATINFO();
            int cbMAP = System.Runtime.InteropServices.Marshal.SizeOf<Vmmi.VMMDLL_MAP_EAT>();
            int cbENTRY = System.Runtime.InteropServices.Marshal.SizeOf<Vmmi.VMMDLL_MAP_EATENTRY>();
            IntPtr pMap = IntPtr.Zero;
            MAP_EATENTRY[] m = new MAP_EATENTRY[0];
            if (!Vmmi.VMMDLL_Map_GetEAT(_hVmm, this.PID, wszModule, out pMap)) { goto fail; }
            Vmmi.VMMDLL_MAP_EAT nM = Marshal.PtrToStructure<Vmmi.VMMDLL_MAP_EAT>(pMap);
            if (nM.dwVersion != Vmmi.VMMDLL_MAP_EAT_VERSION) { goto fail; }
            m = new MAP_EATENTRY[nM.cMap];
            for (int i = 0; i < nM.cMap; i++)
            {
                Vmmi.VMMDLL_MAP_EATENTRY n = Marshal.PtrToStructure<Vmmi.VMMDLL_MAP_EATENTRY>((System.IntPtr)(pMap.ToInt64() + cbMAP + i * cbENTRY));
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
            Vmmi.VMMDLL_MemFree((byte*)pMap.ToPointer());
            return m;
        }

        public unsafe MAP_IATENTRY[] Map_GetIAT( string wszModule)
        {
            int cbMAP = System.Runtime.InteropServices.Marshal.SizeOf<Vmmi.VMMDLL_MAP_IAT>();
            int cbENTRY = System.Runtime.InteropServices.Marshal.SizeOf<Vmmi.VMMDLL_MAP_IATENTRY>();
            IntPtr pMap = IntPtr.Zero;
            MAP_IATENTRY[] m = new MAP_IATENTRY[0];
            if (!Vmmi.VMMDLL_Map_GetIAT(_hVmm, this.PID, wszModule, out pMap)) { goto fail; }
            Vmmi.VMMDLL_MAP_IAT nM = Marshal.PtrToStructure<Vmmi.VMMDLL_MAP_IAT>(pMap);
            if (nM.dwVersion != Vmmi.VMMDLL_MAP_IAT_VERSION) { goto fail; }
            m = new MAP_IATENTRY[nM.cMap];
            for (int i = 0; i < nM.cMap; i++)
            {
                Vmmi.VMMDLL_MAP_IATENTRY n = Marshal.PtrToStructure<Vmmi.VMMDLL_MAP_IATENTRY>((System.IntPtr)(pMap.ToInt64() + cbMAP + i * cbENTRY));
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
            Vmmi.VMMDLL_MemFree((byte*)pMap.ToPointer());
            return m;
        }

        public unsafe MAP_HEAP Map_GetHeap()
        {
            IntPtr pMap = IntPtr.Zero;
            int cbMAP = System.Runtime.InteropServices.Marshal.SizeOf<Vmmi.VMMDLL_MAP_HEAP>();
            int cbENTRY = System.Runtime.InteropServices.Marshal.SizeOf<Vmmi.VMMDLL_MAP_HEAPENTRY>();
            int cbSEGENTRY = System.Runtime.InteropServices.Marshal.SizeOf<Vmmi.VMMDLL_MAP_HEAPSEGMENTENTRY>();
            MAP_HEAP Heap;
            Heap.heaps = new MAP_HEAPENTRY[0];
            Heap.segments = new MAP_HEAPSEGMENTENTRY[0];
            if (!Vmmi.VMMDLL_Map_GetHeap(_hVmm, this.PID, out pMap)) { goto fail; }
            Vmmi.VMMDLL_MAP_HEAP nM = Marshal.PtrToStructure<Vmmi.VMMDLL_MAP_HEAP>(pMap);
            if (nM.dwVersion != Vmmi.VMMDLL_MAP_HEAP_VERSION) { goto fail; }
            Heap.heaps = new MAP_HEAPENTRY[nM.cMap];
            for (int i = 0; i < nM.cMap; i++)
            {
                Vmmi.VMMDLL_MAP_HEAPENTRY nH = Marshal.PtrToStructure<Vmmi.VMMDLL_MAP_HEAPENTRY>((System.IntPtr)(pMap.ToInt64() + cbMAP + i * cbENTRY));
                Heap.heaps[i].va = nH.va;
                Heap.heaps[i].f32 = nH.f32;
                Heap.heaps[i].tpHeap = nH.tp;
                Heap.heaps[i].iHeapNum = nH.dwHeapNum;
            }
            Heap.segments = new MAP_HEAPSEGMENTENTRY[nM.cSegments];
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

        public unsafe MAP_HEAPALLOCENTRY[] Map_GetHeapAlloc( ulong vaHeapOrHeapNum)
        {
            IntPtr pHeapAllocMap = IntPtr.Zero;
            int cbMAP = System.Runtime.InteropServices.Marshal.SizeOf<Vmmi.VMMDLL_MAP_HEAPALLOC>();
            int cbENTRY = System.Runtime.InteropServices.Marshal.SizeOf<Vmmi.VMMDLL_MAP_HEAPALLOCENTRY>();
            if (!Vmmi.VMMDLL_Map_GetHeapAlloc(_hVmm, this.PID, vaHeapOrHeapNum, out pHeapAllocMap)) { return new MAP_HEAPALLOCENTRY[0]; }
            Vmmi.VMMDLL_MAP_HEAPALLOC nM = Marshal.PtrToStructure<Vmmi.VMMDLL_MAP_HEAPALLOC>(pHeapAllocMap);
            if (nM.dwVersion != Vmmi.VMMDLL_MAP_HEAPALLOC_VERSION)
            {
                Vmmi.VMMDLL_MemFree((byte*)pHeapAllocMap.ToPointer());
                return new MAP_HEAPALLOCENTRY[0];
            }
            MAP_HEAPALLOCENTRY[] m = new MAP_HEAPALLOCENTRY[nM.cMap];
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

        public unsafe MAP_THREADENTRY[] Map_GetThread()
        {
            int cbMAP = System.Runtime.InteropServices.Marshal.SizeOf<Vmmi.VMMDLL_MAP_THREAD>();
            int cbENTRY = System.Runtime.InteropServices.Marshal.SizeOf<Vmmi.VMMDLL_MAP_THREADENTRY>();
            IntPtr pMap = IntPtr.Zero;
            MAP_THREADENTRY[] m = new MAP_THREADENTRY[0];
            if (!Vmmi.VMMDLL_Map_GetThread(_hVmm, this.PID, out pMap)) { goto fail; }
            Vmmi.VMMDLL_MAP_THREAD nM = Marshal.PtrToStructure<Vmmi.VMMDLL_MAP_THREAD>(pMap);
            if (nM.dwVersion != Vmmi.VMMDLL_MAP_THREAD_VERSION) { goto fail; }
            m = new MAP_THREADENTRY[nM.cMap];
            for (int i = 0; i < nM.cMap; i++)
            {
                Vmmi.VMMDLL_MAP_THREADENTRY n = Marshal.PtrToStructure<Vmmi.VMMDLL_MAP_THREADENTRY>((System.IntPtr)(pMap.ToInt64() + cbMAP + i * cbENTRY));
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
            Vmmi.VMMDLL_MemFree((byte*)pMap.ToPointer());
            return m;
        }

        public unsafe MAP_HANDLEENTRY[] Map_GetHandle()
        {
            int cbMAP = System.Runtime.InteropServices.Marshal.SizeOf<Vmmi.VMMDLL_MAP_HANDLE>();
            int cbENTRY = System.Runtime.InteropServices.Marshal.SizeOf<Vmmi.VMMDLL_MAP_HANDLEENTRY>();
            IntPtr pMap = IntPtr.Zero;
            MAP_HANDLEENTRY[] m = new MAP_HANDLEENTRY[0];
            if (!Vmmi.VMMDLL_Map_GetHandle(_hVmm, this.PID, out pMap)) { goto fail; }
            Vmmi.VMMDLL_MAP_HANDLE nM = Marshal.PtrToStructure<Vmmi.VMMDLL_MAP_HANDLE>(pMap);
            if (nM.dwVersion != Vmmi.VMMDLL_MAP_HANDLE_VERSION) { goto fail; }
            m = new MAP_HANDLEENTRY[nM.cMap];
            for (int i = 0; i < nM.cMap; i++)
            {
                Vmmi.VMMDLL_MAP_HANDLEENTRY n = Marshal.PtrToStructure<Vmmi.VMMDLL_MAP_HANDLEENTRY>((System.IntPtr)(pMap.ToInt64() + cbMAP + i * cbENTRY));
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
            Vmmi.VMMDLL_MemFree((byte*)pMap.ToPointer());
            return m;
        }

        public unsafe string GetInformationString(uint fOptionString)
        {
            byte* pb = Vmmi.VMMDLL_ProcessGetInformationString(_hVmm, this.PID, fOptionString);
            if (pb == null) { return ""; }
            string s = Marshal.PtrToStringAnsi((System.IntPtr)pb);
            Vmmi.VMMDLL_MemFree(pb);
            return s;
        }

        public unsafe IMAGE_DATA_DIRECTORY[] GetDirectories(string wszModule)
        {
            string[] PE_DATA_DIRECTORIES = new string[16] { "EXPORT", "IMPORT", "RESOURCE", "EXCEPTION", "SECURITY", "BASERELOC", "DEBUG", "ARCHITECTURE", "GLOBALPTR", "TLS", "LOAD_CONFIG", "BOUND_IMPORT", "IAT", "DELAY_IMPORT", "COM_DESCRIPTOR", "RESERVED" };
            bool result;
            uint cbENTRY = (uint)System.Runtime.InteropServices.Marshal.SizeOf<Vmmi.VMMDLL_IMAGE_DATA_DIRECTORY>();
            fixed (byte* pb = new byte[16 * cbENTRY])
            {
                result = Vmmi.VMMDLL_ProcessGetDirectories(_hVmm, this.PID, wszModule, pb);
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

        public unsafe IMAGE_SECTION_HEADER[] GetSections(string wszModule)
        {
            bool result;
            uint cData;
            uint cbENTRY = (uint)System.Runtime.InteropServices.Marshal.SizeOf<Vmmi.VMMDLL_IMAGE_SECTION_HEADER>();
            result = Vmmi.VMMDLL_ProcessGetSections(_hVmm, this.PID, wszModule, null, 0, out cData);
            if (!result || (cData == 0)) { return new IMAGE_SECTION_HEADER[0]; }
            fixed (byte* pb = new byte[cData * cbENTRY])
            {
                result = Vmmi.VMMDLL_ProcessGetSections(_hVmm, this.PID, wszModule, pb, cData, out cData);
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

        public ulong GetProcAddress(string wszModuleName, string szFunctionName)
        {
            return Vmmi.VMMDLL_ProcessGetProcAddress(_hVmm, this.PID, wszModuleName, szFunctionName);
        }

        public ulong GetModuleBase(string wszModuleName)
        {
            return Vmmi.VMMDLL_ProcessGetModuleBase(_hVmm, this.PID, wszModuleName);
        }

        public unsafe PROCESS_INFORMATION GetInformation(out bool result)
        {
            ulong cbENTRY = (ulong)System.Runtime.InteropServices.Marshal.SizeOf<Vmmi.VMMDLL_PROCESS_INFORMATION>();
            fixed (byte* pb = new byte[cbENTRY])
            {
                Marshal.WriteInt64(new IntPtr(pb + 0), unchecked((long)Vmmi.VMMDLL_PROCESS_INFORMATION_MAGIC));
                Marshal.WriteInt16(new IntPtr(pb + 8), unchecked((short)Vmmi.VMMDLL_PROCESS_INFORMATION_VERSION));
                result = Vmmi.VMMDLL_ProcessGetInformation(_hVmm, this.PID, pb, ref cbENTRY);
                if (!result) { return new PROCESS_INFORMATION(); }
                Vmmi.VMMDLL_PROCESS_INFORMATION n = Marshal.PtrToStructure<Vmmi.VMMDLL_PROCESS_INFORMATION>((System.IntPtr)pb);
                if (n.wVersion != Vmmi.VMMDLL_PROCESS_INFORMATION_VERSION) { return new PROCESS_INFORMATION(); }
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

        #endregion

        #region Memory Search
        public struct VMMDLL_MEM_SEARCHENTRY
        {
            public uint cbAlign;
            public byte[] pbSearch;
            public byte[] pbSearchSkipMask;
        }

        public unsafe ulong[] MemSearchM(VMMDLL_MEM_SEARCHENTRY[] search, ulong vaMin = 0, ulong vaMax = 0xffffffffffffffff, uint cMaxResult = 0x10000, uint ReadFlags = 0)
        {
            // checks:
            if (search == null || search.Length == 0 || search.Length > 16) { return new ulong[0]; }
            // check search items and convert:
            Vmmi.VMMDLL_MEM_SEARCH_CONTEXT_SEARCHENTRY[] es = new Vmmi.VMMDLL_MEM_SEARCH_CONTEXT_SEARCHENTRY[16];
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
            Vmmi.VMMDLL_MEM_SEARCH_CONTEXT ctx = new Vmmi.VMMDLL_MEM_SEARCH_CONTEXT();
            ctx.dwVersion = Vmmi.VMMDLL_MEM_SEARCH_VERSION;
            ctx.cMaxResult = cMaxResult;
            ctx.cSearch = 1;
            ctx.vaMin = vaMin;
            ctx.vaMax = vaMax;
            ctx.ReadFlags = ReadFlags;
            ctx.search = es;
            // perform native search:
            uint pcva;
            IntPtr ppva;
            if (!Vmmi.VMMDLL_MemSearch(_hVmm, this.PID, ref ctx, out ppva, out pcva)) { return new ulong[0]; }
            ulong[] result = new ulong[pcva];
            for (int i = 0; i < pcva; i++)
            {
                result[i] = Marshal.PtrToStructure<ulong>(IntPtr.Add(ppva, i * 8));
            }
            Vmmi.VMMDLL_MemFree((byte*)ppva.ToPointer());
            return result;
        }

        public unsafe ulong[] MemSearch1(byte[] pbSearch, ulong vaMin = 0, ulong vaMax = 0xffffffffffffffff, uint cMaxResult = 0x10000, uint ReadFlags = 0, byte[] pbSearchSkipMask = null, uint cbAlign = 1)
        {
            VMMDLL_MEM_SEARCHENTRY[] es = new VMMDLL_MEM_SEARCHENTRY[1];
            es[0].cbAlign = cbAlign;
            es[0].pbSearch = pbSearch;
            es[0].pbSearchSkipMask = pbSearchSkipMask;
            return MemSearchM(es, vaMin, vaMax, cMaxResult, ReadFlags);
        }
        #endregion

        #region Types

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

        public const uint MAP_MODULEENTRY_TP_NORMAL = 0;
        public const uint VMMDLL_MODULE_TP_DATA = 1;
        public const uint VMMDLL_MODULE_TP_NOTLINKED = 2;
        public const uint VMMDLL_MODULE_TP_INJECTED = 3;

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

        public const uint VMMDLL_PROCESS_INFORMATION_OPT_STRING_PATH_KERNEL = 1;
        public const uint VMMDLL_PROCESS_INFORMATION_OPT_STRING_PATH_USER_IMAGE = 2;
        public const uint VMMDLL_PROCESS_INFORMATION_OPT_STRING_CMDLINE = 3;

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
        #endregion
    }
}
