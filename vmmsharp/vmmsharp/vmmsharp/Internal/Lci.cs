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
using System.Runtime.InteropServices;
#if NET7_0_OR_GREATER
using System.Diagnostics.CodeAnalysis;
#endif

namespace Vmmsharp.Internal
{
    internal static partial class Lci
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

#if NET7_0_OR_GREATER
#pragma warning disable SYSLIB1054
        [RequiresDynamicCode("This P/Invoke was not able to be converted to LibraryImport")]
        [DllImport("leechcore", EntryPoint = "LcCreate")]
        public static extern IntPtr LcCreate(ref LeechCore.LCConfig pLcCreateConfig);

        [RequiresDynamicCode("This P/Invoke was not able to be converted to LibraryImport")]
        [DllImport("leechcore", EntryPoint = "LcCreateEx")]
        public static extern IntPtr LcCreateEx(ref LeechCore.LCConfig pLcCreateConfig, out IntPtr ppLcCreateErrorInfo);
#pragma warning restore SYSLIB1054

        [LibraryImport("leechcore", EntryPoint = "LcClose")]
        internal static partial void LcClose(IntPtr hLC);

        [LibraryImport("leechcore", EntryPoint = "LcMemFree")]
        internal static unsafe partial void LcMemFree(IntPtr pv);

        [LibraryImport("leechcore", EntryPoint = "LcAllocScatter1")]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static unsafe partial bool LcAllocScatter1(uint cMEMs, out IntPtr pppMEMs);

        [LibraryImport("leechcore", EntryPoint = "LcRead")]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static unsafe partial bool LcRead(IntPtr hLC, ulong pa, uint cb, byte* pb);

        [LibraryImport("leechcore", EntryPoint = "LcReadScatter")]
        internal static unsafe partial void LcReadScatter(IntPtr hLC, uint cMEMs, IntPtr ppMEMs);

        [LibraryImport("leechcore", EntryPoint = "LcWrite")]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static unsafe partial bool LcWrite(IntPtr hLC, ulong pa, uint cb, byte* pb);

        [LibraryImport("leechcore", EntryPoint = "LcWriteScatter")]
        internal static unsafe partial void LcWriteScatter(IntPtr hLC, uint cMEMs, IntPtr ppMEMs);

        [LibraryImport("leechcore", EntryPoint = "LcGetOption")]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static partial bool GetOption(IntPtr hLC, ulong fOption, out ulong pqwValue);

        [LibraryImport("leechcore", EntryPoint = "LcSetOption")]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static partial bool SetOption(IntPtr hLC, ulong fOption, ulong qwValue);

        [LibraryImport("leechcore", EntryPoint = "LcCommand")]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static unsafe partial bool LcCommand(IntPtr hLC, ulong fOption, uint cbDataIn, byte* pbDataIn, out IntPtr ppbDataOut, out uint pcbDataOut);
#else

        [DllImport("leechcore", EntryPoint = "LcCreate")]
        public static extern IntPtr LcCreate(ref LeechCore.LCConfig pLcCreateConfig);

        [DllImport("leechcore", EntryPoint = "LcCreateEx")]
        public static extern IntPtr LcCreateEx(ref LeechCore.LCConfig pLcCreateConfig, out IntPtr ppLcCreateErrorInfo);

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
#endif
    }
}
