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
using System.Text;
using System.Threading;
using System.Runtime.InteropServices;
using Vmmsharp.Internal;

namespace Vmmsharp
{
    /// <summary>
    /// The VmmYara class represents a Yara search in memory.
    /// </summary>
    public class VmmYara : IDisposable
    {
        #region Base Functionality

        protected readonly Vmm _hVmm;
        protected readonly uint _PID;

        internal YaraResult _result;
        internal Vmmi.VMMDLL_YARA_CONFIG _native;
        internal Thread _thread;
        internal List<string> _terms;

        IntPtr _ptrNative;
        private bool disposed = false;

        private VmmYara()
        {
            ;
        }

        internal VmmYara(Vmm hVmm, uint pid, string[] yara_rules, ulong addr_min = 0, ulong addr_max = UInt64.MaxValue, uint cMaxResult = 0, uint readFlags = 0)
        {
            if (cMaxResult == 0) { cMaxResult = 0x10000; }
            _hVmm = hVmm;
            _PID = pid;
            _result = new YaraResult();
            _result.addrMin = addr_min;
            _result.addrMax = addr_max;
            _result.result = new List<YaraMatch>();
            _terms = new List<string>(yara_rules);
            _ptrNative = Marshal.AllocHGlobal(Marshal.SizeOf(_native));
            unsafe
            {
                _native = new Vmmi.VMMDLL_YARA_CONFIG();
                _native.dwVersion = Vmmi.VMMDLL_YARA_CONFIG_VERSION;
                _native.vaMin = addr_min;
                _native.vaMax = addr_max;
                _native.cMaxResult = cMaxResult;
                _native.ReadFlags = readFlags;
                _native.pfnScanMemoryCB = YaraResultCallback;
                _native.pvUserPtrOpt = _ptrNative;
            }
            Marshal.StructureToPtr(_native, _ptrNative, false);
        }

        /// <summary>
        /// ToString override.
        /// </summary>
        public override string ToString()
        {
            return "VmmYara";
        }

        ~VmmYara()
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
                Marshal.FreeHGlobal(_ptrNative);
                _ptrNative = IntPtr.Zero;
                disposed = true;
            }
        }

        #endregion // Base Functionality

        #region Specific Functionality

        /// <summary>
        /// Struct with info about the search results. Find the actual results in the result field.
        /// </summary>
        public struct YaraResult
        {
            /// Indicates that the search has been started. i.e. start() or result() have been called.
            public bool isStarted;
            /// Indicates that the search has been completed.
            public bool isCompleted;
            /// If isCompletedSuccess is true this indicates if the search was completed successfully.
            public bool isCompletedSuccess;
            /// Address to start searching from - default 0.
            public ulong addrMin;
            /// Address to stop searching at - default MAXUINT64.
            public ulong addrMax;
            /// Current address being searched in search thread.
            public ulong addrCurrent;
            /// Number of bytes that have been procssed in search.
            public ulong totalReadBytes;
            /// The actual results.
            public List<YaraMatch> result;
        }

        public struct YaraMatch
        {
            public string sRuleIdentifier;
            public string[] tags;
            public string[][] meta;
            public YaraMatchString[] strings;
        }

        public struct YaraMatchString
        {
            public string sString;
            public ulong[] addresses;
        }

        private unsafe void Start_DoWork()
        {
            // 1: set up:
            string[] arrTerms = _terms.ToArray();
            IntPtr[] ptrTerms = new IntPtr[arrTerms.Length];
            GCHandle[] gchTerms = new GCHandle[arrTerms.Length];
            for (int i = 0; i < arrTerms.Length; i++)
            {
                byte[] utf8Bytes = Encoding.UTF8.GetBytes(arrTerms[i] + '\0'); // Add null terminator
                gchTerms[i] = GCHandle.Alloc(utf8Bytes, GCHandleType.Pinned);
                ptrTerms[i] = gchTerms[i].AddrOfPinnedObject();
            }
            GCHandle gchTermsArray = GCHandle.Alloc(ptrTerms, GCHandleType.Pinned);
            IntPtr ptrTermsArray = gchTermsArray.AddrOfPinnedObject();
            _native.cRules = (uint)_terms.Count;
            _native.pszRules = ptrTermsArray;
            // 2: call native:
            Marshal.StructureToPtr(_native, _ptrNative, false);
            bool fResult = Vmmi.VMMDLL_YaraSearch2(_hVmm, _PID, _ptrNative, IntPtr.Zero, IntPtr.Zero);
            // 3: finish / clean up:
            gchTermsArray.Free();
            foreach (GCHandle gch in gchTerms) { gch.Free(); }
            _result.isCompletedSuccess = fResult;
            _result.isCompleted = true;
        }

        /// <summary>
        /// </summary>
        public void Start()
        {
            if (disposed) { throw new VmmException("Object disposed."); }
            if (_result.isStarted) { return; }
            if (_terms.Count == 0) { return; }
            _result.isStarted = true;
            _thread = new Thread(() => Start_DoWork());
            _thread.Start();
        }

        /// <summary>
        /// Abort the search. Blocking / wait until abort is complete.
        /// </summary>
        public void Abort()
        {
            if (disposed) { throw new VmmException("Object disposed."); }
            if (!_result.isStarted) { return; }
            _native.fAbortRequested = true;
            _thread.Join();
        }

        /// <summary>
        /// Poll the search for results. Non-blocking.
        /// </summary>
        /// <returns></returns>
        public YaraResult Poll()
        {
            if (disposed) { throw new VmmException("Object disposed."); }
            if (!_result.isStarted) { Start(); }
            _result.addrCurrent = (ulong)Marshal.ReadInt64(_ptrNative, Marshal.OffsetOf<Vmmi.VMMDLL_YARA_CONFIG>("vaCurrent").ToInt32());
            _result.addrMin = (ulong)Marshal.ReadInt64(_ptrNative, Marshal.OffsetOf<Vmmi.VMMDLL_YARA_CONFIG>("vaMin").ToInt32());
            _result.addrMax = (ulong)Marshal.ReadInt64(_ptrNative, Marshal.OffsetOf<Vmmi.VMMDLL_YARA_CONFIG>("vaMax").ToInt32());
            _result.totalReadBytes = (ulong)Marshal.ReadInt64(_ptrNative, Marshal.OffsetOf<Vmmi.VMMDLL_YARA_CONFIG>("cbReadTotal").ToInt32());
            return _result;
        }

        /// <summary>
        /// Get the result of the search: Blocking / wait until finish.
        /// </summary>
        /// <returns></returns>
        public YaraResult Result()
        {
            if (disposed) { throw new VmmException("Object disposed."); }
            if (!_result.isStarted) { Start(); }
            if (_result.isStarted) { _thread.Join(); }
            return Poll();
        }

        private unsafe bool YaraResultCallback(IntPtr ctx, Vmmi.VMMYARA_RULE_MATCH pRuleMatch, byte* pbBuffer, ulong cbBuffer)
        {
            if(pRuleMatch.dwVersion != Vmmi.VMMYARA_RULE_MATCH_VERSION) { return false; }
            YaraMatch match = new YaraMatch();
            ulong addrBase = (ulong)Marshal.ReadInt64(ctx, Marshal.OffsetOf<Vmmi.VMMDLL_YARA_CONFIG>("vaCurrent").ToInt32());
            match.sRuleIdentifier = pRuleMatch.szRuleIdentifier;
            // tags:
            match.tags = new string[pRuleMatch.cTags];
            for (int i = 0; i < pRuleMatch.cTags; i++)
            {
#if NET5_0_OR_GREATER
                match.tags[i] = Marshal.PtrToStringUTF8(pRuleMatch.szTags[i]);
#else // NET5_0_OR_GREATER
                match.tags[i] = Marshal.PtrToStringAnsi(pRuleMatch.szTags[i]);
#endif // NET5_0_OR_GREATER
            }
            // meta:
            match.meta = new string[pRuleMatch.cMeta][];
            for (int i = 0; i < pRuleMatch.cMeta; i++)
            {
                match.meta[i] = new string[2] { pRuleMatch.Meta[i].szIdentifier, pRuleMatch.Meta[i].szString };
            }
            // strings:
            match.strings = new YaraMatchString[pRuleMatch.cStrings];
            for (int i = 0; i < pRuleMatch.cStrings; i++)
            {
                match.strings[i].sString = pRuleMatch.Strings[i].szString;
                match.strings[i].addresses = new ulong[pRuleMatch.Strings[i].cMatch];
                for (int j = 0; j < pRuleMatch.Strings[i].cMatch; j++)
                {
                    match.strings[i].addresses[j] = addrBase + pRuleMatch.Strings[i].cbMatchOffset[j];
                }
            }
            _result.result.Add(match);
            return true;
        }
#endregion // Specific Functionality
    }
}
