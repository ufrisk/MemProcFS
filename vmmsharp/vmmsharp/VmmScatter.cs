using System;
using System.Runtime.CompilerServices;
using System.Text;
using Vmmsharp.Internal;

namespace Vmmsharp
{
    public class VmmScatter : IDisposable
    {
        //---------------------------------------------------------------------
        // MEMORY NEW SCATTER READ/WRITE FUNCTIONALITY BELOW:
        //---------------------------------------------------------------------
        private readonly uint pid;
        private bool disposed = false;
        protected IntPtr hS = IntPtr.Zero;

        private VmmScatter()
        {
            ;
        }

        internal VmmScatter(IntPtr hS, uint pid)
        {
            this.hS = hS;
            this.pid = pid;
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

        protected virtual void Dispose(bool disposing)
        {
            if (!this.disposed)
            {
                Vmmi.VMMDLL_Scatter_CloseHandle(hS);
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
                if (!Vmmi.VMMDLL_Scatter_Read(hS, qwA, cb, (byte*)pb, out cbRead))
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
            return Vmmi.VMMDLL_Scatter_Prepare(hS, qwA, cb);
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
                return Vmmi.VMMDLL_Scatter_PrepareWrite(hS, qwA, (byte*)pb, cb);
            }
        }

        public unsafe bool PrepareWriteStruct<T>(ulong qwA, T value)
            where T : unmanaged
        {
            uint cb = (uint)sizeof(T);
            byte* pb = (byte*)&value;
            return Vmmi.VMMDLL_Scatter_PrepareWrite(hS, qwA, pb, cb);
        }

        public bool Execute()
        {
            return Vmmi.VMMDLL_Scatter_Execute(hS);
        }

        public bool Clear(uint flags)
        {
            return Vmmi.VMMDLL_Scatter_Clear(hS, pid, flags);
        }
    }
}
