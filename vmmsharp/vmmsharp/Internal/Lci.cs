using System;
using System.Runtime.InteropServices;

namespace Vmmsharp.Internal
{
    internal static class Lci
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
}
