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
using System.Text;
using Vmmsharp.Internal;

namespace Vmmsharp
{
    /// <summary>
    /// The VmmScatterMemory class is used to ease the reading and writing of memory in bulk using the VMM Scatter API.
    /// </summary>
    public class VmmScatterMemory : IDisposable
    {
        #region Base Functionality

        private readonly uint pid;
        private bool disposed = false;
        protected IntPtr hS = IntPtr.Zero;

        private VmmScatterMemory()
        {
            ;
        }

        internal VmmScatterMemory(IntPtr hS, uint pid)
        {
            this.hS = hS;
            this.pid = pid;
        }

        ~VmmScatterMemory()
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
                Vmmi.VMMDLL_Scatter_CloseHandle(hS);
                hS = IntPtr.Zero;
                disposed = true;
            }
        }

        /// <summary>
        /// ToString override.
        /// </summary>
        public override string ToString()
        {
            if(disposed || (hS == IntPtr.Zero))
            {
                return "VmmScatterMemory:NotValid";
            }
            else if(pid == 0xFFFFFFFF)
            {
                return "VmmScatterMemory:physical";
            }
            else
            {
                return $"VmmScatterMemory:virtual:{pid}";
            }
        }

        /// <summary>
        /// Force close the scatter object - free up any resources.
        /// </summary>
        public void Close()
        {
            Dispose(disposing: true);
        }

        #endregion

        #region Memory Read/Write

        /// <summary>
        /// Prepare to read memory of a certain size.
        /// </summary>
        /// <param name="qwA">Address of the memory to be read.</param>
        /// <param name="cb">Length in bytes of the data to be read.</param>
        /// <returns>true/false.</returns>
        public bool Prepare(ulong qwA, uint cb)
        {
            return Vmmi.VMMDLL_Scatter_Prepare(hS, qwA, cb);
        }

        /// <summary>
        /// Prepare to write bytes to memory.
        /// </summary>
        /// <param name="qwA">The address where to write the data.</param>
        /// <param name="data">The data to write to memory.</param>
        /// <returns>true/false</returns>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public unsafe bool PrepareWrite(ulong qwA, byte[] data) =>
            PrepareWriteArray<byte>(qwA, data);

        /// <summary>
        /// Prepare to write an array of a certain struct to memory.
        /// </summary>
        /// <typeparam name="T">The type of struct to write.</typeparam>
        /// <param name="qwA">The address where to write the data.</param>
        /// <param name="data">The data to write to memory.</param>
        /// <returns>true/false.</returns>
        public unsafe bool PrepareWriteArray<T>(ulong qwA, T[] data)
            where T : unmanaged
        {
            uint cb = (uint)sizeof(T) * (uint)data.Length;
            fixed (T* pb = data)
            {
                return Vmmi.VMMDLL_Scatter_PrepareWrite(hS, qwA, (byte*)pb, cb);
            }
        }

        /// <summary>
        /// Prepare to write a struct to memory.
        /// </summary>
        /// <typeparam name="T">The type of struct to write.</typeparam>
        /// <param name="qwA">The address where to write the data.</param>
        /// <param name="value">The data to write to memory.</param>
        /// <returns>true/false.</returns>
        public unsafe bool PrepareWriteStruct<T>(ulong qwA, T value)
            where T : unmanaged
        {
            uint cb = (uint)sizeof(T);
            byte* pb = (byte*)&value;
            return Vmmi.VMMDLL_Scatter_PrepareWrite(hS, qwA, pb, cb);
        }

        /// <summary>
        /// Execute any prepared read and/or write operations.
        /// </summary>
        /// <returns>true/false.</returns>
        public bool Execute()
        {
            return Vmmi.VMMDLL_Scatter_Execute(hS);
        }

        /// <summary>
        /// Read memory bytes from an address.
        /// </summary>
        /// <param name="qwA">Address to read from.</param>
        /// <param name="cb">Bytes to read.</param>
        /// <returns>The byte array on success, Null on fail.</returns>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public unsafe byte[] Read(ulong qwA, uint cb) =>
            ReadArray<byte>(qwA, cb);

        /// <summary>
        /// Read memory from an address into a struct type.
        /// </summary>
        /// <typeparam name="T">The type of struct to read.</typeparam>
        /// <param name="qwA">Address to read from.</param>
        /// <param name="result">true/false</param>
        /// <returns>true/false.</returns>
        public unsafe bool ReadAs<T>(ulong qwA, out T result)
            where T : unmanaged
        {
            uint cb = (uint)sizeof(T);
            uint cbRead;
            result = default;
            fixed (T* pb = &result)
            {
                if (!Vmmi.VMMDLL_Scatter_Read(hS, qwA, cb, (byte*)pb, out cbRead))
                    return false;
            }
            if (cbRead != cb)
                return false;
            return true;
        }

        /// <summary>
        /// Read memory from an address into an array of a certain type.
        /// </summary>
        /// <typeparam name="T">The type of struct to read.</typeparam>
        /// <param name="qwA">Address to read from.</param>
        /// <param name="count">The number of array items to read.</param>
        /// <returns>Array of objects read. Null on fail.</returns>
        public unsafe T[] ReadArray<T>(ulong qwA, uint count)
            where T : unmanaged
        {
            uint cb = (uint)sizeof(T) * count;
            uint cbRead;
            T[] data = new T[count];
            fixed (T* pb = data)
            {
                if (!Vmmi.VMMDLL_Scatter_Read(hS, qwA, cb, (byte*)pb, out cbRead))
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
        /// Read memory from an address into a managed string.
        /// </summary>
        /// <param name="encoding">String Encoding for this read.</param>
        /// <param name="qwA">Address to read from.</param>
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

        /// <summary>
        /// Clear the VmmScatter object to allow for new operations.
        /// </summary>
        /// <param name="flags"></param>
        /// <returns>true/false.</returns>
        public bool Clear(uint flags)
        {
            return Vmmi.VMMDLL_Scatter_Clear(hS, pid, flags);
        }

        #endregion
    }
}
