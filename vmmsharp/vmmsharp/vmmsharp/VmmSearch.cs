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
using System.Threading;
using System.Runtime.InteropServices;
using Vmmsharp.Internal;

namespace Vmmsharp
{
    /// <summary>
    /// VmmSearch represents a binary search in memory.
    /// </summary>
    public class VmmSearch : IDisposable
    {
        #region Base Functionality

        protected readonly Vmm _hVmm;
        protected readonly uint _PID;

        internal SearchResult _result;
        internal Vmmi.VMMDLL_MEM_SEARCH_CONTEXT _native;
        internal Thread _thread;
        internal List<Vmmi.VMMDLL_MEM_SEARCH_CONTEXT_SEARCHENTRY> _terms;

        IntPtr _ptrNative;
        private bool disposed = false;

        private VmmSearch()
        {
            ;
        }

        internal VmmSearch(Vmm hVmm, uint pid, ulong addr_min = 0, ulong addr_max = UInt64.MaxValue, uint cMaxResult = 0, uint readFlags = 0)
        {
            if(cMaxResult == 0) { cMaxResult = 0x10000; }
            _hVmm = hVmm;
            _PID = pid;
            _result = new SearchResult();
            _result.addrMin = addr_min;
            _result.addrMax = addr_max;
            _result.result = new List<SearchResultEntry>();
            _terms = new List<Vmmi.VMMDLL_MEM_SEARCH_CONTEXT_SEARCHENTRY>();
            _native = new Vmmi.VMMDLL_MEM_SEARCH_CONTEXT();
            _native.dwVersion = Vmmi.VMMDLL_MEM_SEARCH_VERSION;
            _native.vaMin = addr_min;
            _native.vaMax = addr_max;
            _native.cMaxResult = cMaxResult;
            _native.ReadFlags = readFlags;
            _native.pfnResultOptCB = SearchResultCallback;
            _ptrNative = Marshal.AllocHGlobal(Marshal.SizeOf(_native));
            Marshal.StructureToPtr(_native, _ptrNative, false);
        }

        /// <summary>
        /// ToString override.
        /// </summary>
        public override string ToString()
        {
            return "VmmSearch";
        }

        ~VmmSearch()
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
        public struct SearchResult
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
            public List<SearchResultEntry> result;
        }

        /// <summary>
        /// Struct with info about a single search result. Address & search term id.
        /// </summary>
        public struct SearchResultEntry
        {
            public ulong address;
            public ulong search_term_id;
        }

        /// <summary>
        /// Add a search term to the search. Should be done before search is started.
        /// </summary>
        /// <param name="search"></param>
        /// <param name="skipmask"></param>
        /// <param name="align"></param>
        /// <returns></returns>
        public unsafe uint AddSearch(byte[] search, byte[] skipmask = null, uint align = 1)
        {
            if (disposed) { throw new VmmException("Object disposed."); }
            if (_result.isStarted) { return uint.MaxValue; }
            if (search.Length == 0 || search.Length > 32) { return uint.MaxValue; }
            if (skipmask != null && skipmask.Length != search.Length) { return uint.MaxValue; }
            Vmmi.VMMDLL_MEM_SEARCH_CONTEXT_SEARCHENTRY e = new Vmmi.VMMDLL_MEM_SEARCH_CONTEXT_SEARCHENTRY();
            e.cbAlign = align;
            e.cb = (uint)search.Length;
            fixed (byte* pbSearch = search)
            {
                Buffer.MemoryCopy(pbSearch, e.pb, 32, search.Length);
            }
            if (skipmask != null)
            {
                fixed (byte* pbSkipMask = skipmask)
                {
                    Buffer.MemoryCopy(pbSkipMask, e.pbSkipMask, 32, skipmask.Length);
                }
            }
            _terms.Add(e);
            return (uint)_terms.Count - 1;
        }

        private unsafe void Start_DoWork()
        {
            Vmmi.VMMDLL_MEM_SEARCH_CONTEXT_SEARCHENTRY[] arrTerms = _terms.ToArray();
            GCHandle hndTerms = GCHandle.Alloc(arrTerms, GCHandleType.Pinned);
            _native.cSearch = (uint)_terms.Count;
            _native.search = hndTerms.AddrOfPinnedObject();
            Marshal.StructureToPtr(_native, _ptrNative, false);
            bool fResult = Vmmi.VMMDLL_MemSearch2(_hVmm, _PID, _ptrNative, IntPtr.Zero, IntPtr.Zero);
            hndTerms.Free();
            _result.isCompletedSuccess = fResult && !_native.fAbortRequested;
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
        public SearchResult Poll()
        {
            if (disposed) { throw new VmmException("Object disposed."); }
            if (!_result.isStarted) { Start(); }
            _result.addrCurrent = (ulong)Marshal.ReadInt64(_ptrNative, Marshal.OffsetOf<Vmmi.VMMDLL_MEM_SEARCH_CONTEXT>("vaCurrent").ToInt32());
            _result.addrMin = (ulong)Marshal.ReadInt64(_ptrNative, Marshal.OffsetOf<Vmmi.VMMDLL_MEM_SEARCH_CONTEXT>("vaMin").ToInt32());
            _result.addrMax = (ulong)Marshal.ReadInt64(_ptrNative, Marshal.OffsetOf<Vmmi.VMMDLL_MEM_SEARCH_CONTEXT>("vaMax").ToInt32());
            _result.totalReadBytes = (ulong)Marshal.ReadInt64(_ptrNative, Marshal.OffsetOf<Vmmi.VMMDLL_MEM_SEARCH_CONTEXT>("cbReadTotal").ToInt32());
            return _result;
        }

        /// <summary>
        /// Get the result of the search: Blocking / wait until finish.
        /// </summary>
        /// <returns></returns>
        public SearchResult Result()
        {
            if (disposed) { throw new VmmException("Object disposed."); }
            if (!_result.isStarted) { Start(); }
            if (_result.isStarted) { _thread.Join(); }
            return Poll();
        }

        private bool SearchResultCallback(Vmmi.VMMDLL_MEM_SEARCH_CONTEXT ctx, ulong va, uint iSearch)
        {
            SearchResultEntry e = new SearchResultEntry();
            e.address = va;
            e.search_term_id = iSearch;
            _result.result.Add(e);
            return true;
        }

        #endregion // Specific Functionality
    }
}
