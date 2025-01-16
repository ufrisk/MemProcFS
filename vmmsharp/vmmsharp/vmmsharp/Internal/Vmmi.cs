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
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;

#if NET7_0_OR_GREATER
using System.Diagnostics.CodeAnalysis;
#endif

namespace Vmmsharp.Internal
{
    internal static partial class Vmmi
    {
        #region .NET 4.8 workarounds: UnmanagedType.LPUTF8Str

#if NET5_0_OR_GREATER
        internal const UnmanagedType VmmString              = UnmanagedType.LPUTF8Str;
        internal const string VMMDLL_VfsListX               = "VMMDLL_VfsListU";
        internal const string VMMDLL_VfsReadX               = "VMMDLL_VfsReadU";
        internal const string VMMDLL_VfsWriteX              = "VMMDLL_VfsWriteU";
        internal const string VMMDLL_ProcessGetProcAddressX = "VMMDLL_ProcessGetProcAddressU";
        internal const string VMMDLL_ProcessGetModuleBaseX  = "VMMDLL_ProcessGetModuleBaseU";
        internal const string VMMDLL_ProcessGetDirectoriesX = "VMMDLL_ProcessGetDirectoriesU";
        internal const string VMMDLL_ProcessGetSectionsX    = "VMMDLL_ProcessGetSectionsU";
        internal const string VMMDLL_Map_GetPteX            = "VMMDLL_Map_GetPteU";
        internal const string VMMDLL_Map_GetVadX            = "VMMDLL_Map_GetVadU";
        internal const string VMMDLL_Map_GetModuleX         = "VMMDLL_Map_GetModuleU";
        internal const string VMMDLL_Map_GetModuleFromNameX = "VMMDLL_Map_GetModuleFromNameU";
        internal const string VMMDLL_Map_GetUnloadedModuleX = "VMMDLL_Map_GetUnloadedModuleU";
        internal const string VMMDLL_Map_GetEATX            = "VMMDLL_Map_GetEATU";
        internal const string VMMDLL_Map_GetIATX            = "VMMDLL_Map_GetIATU";
        internal const string VMMDLL_Map_GetHandleX         = "VMMDLL_Map_GetHandleU";
        internal const string VMMDLL_Map_GetNetX            = "VMMDLL_Map_GetNetU";
        internal const string VMMDLL_Map_GetKDeviceX        = "VMMDLL_Map_GetKDeviceU";
        internal const string VMMDLL_Map_GetKDriverX        = "VMMDLL_Map_GetKDriverU";
        internal const string VMMDLL_Map_GetKObjectX        = "VMMDLL_Map_GetKObjectU";
        internal const string VMMDLL_Map_GetThread_CallstackX = "VMMDLL_Map_GetThread_CallstackU";
        internal const string VMMDLL_Map_GetUsersX          = "VMMDLL_Map_GetUsersU";
        internal const string VMMDLL_Map_GetVMX             = "VMMDLL_Map_GetVMU";
        internal const string VMMDLL_Map_GetServicesX       = "VMMDLL_Map_GetServicesU";
        internal const string VMMDLL_WinReg_EnumKeyExX      = "VMMDLL_WinReg_EnumKeyExU";
        internal const string VMMDLL_WinReg_EnumValueX      = "VMMDLL_WinReg_EnumValueU";
        internal const string VMMDLL_WinReg_QueryValueExX   = "VMMDLL_WinReg_QueryValueExU";
#else
        internal const UnmanagedType VmmString              = UnmanagedType.LPWStr;
        internal const string VMMDLL_VfsListX               = "VMMDLL_VfsListW";
        internal const string VMMDLL_VfsReadX               = "VMMDLL_VfsReadW";
        internal const string VMMDLL_VfsWriteX              = "VMMDLL_VfsWriteW";
        internal const string VMMDLL_ProcessGetProcAddressX = "VMMDLL_ProcessGetProcAddressW";
        internal const string VMMDLL_ProcessGetModuleBaseX  = "VMMDLL_ProcessGetModuleBaseW";
        internal const string VMMDLL_ProcessGetDirectoriesX = "VMMDLL_ProcessGetDirectoriesW";
        internal const string VMMDLL_ProcessGetSectionsX    = "VMMDLL_ProcessGetSectionsW";
        internal const string VMMDLL_Map_GetPteX            = "VMMDLL_Map_GetPteW";
        internal const string VMMDLL_Map_GetVadX            = "VMMDLL_Map_GetVadW";
        internal const string VMMDLL_Map_GetModuleX         = "VMMDLL_Map_GetModuleW";
        internal const string VMMDLL_Map_GetModuleFromNameX = "VMMDLL_Map_GetModuleFromNameW";
        internal const string VMMDLL_Map_GetUnloadedModuleX = "VMMDLL_Map_GetUnloadedModuleW";
        internal const string VMMDLL_Map_GetEATX            = "VMMDLL_Map_GetEATW";
        internal const string VMMDLL_Map_GetIATX            = "VMMDLL_Map_GetIATW";
        internal const string VMMDLL_Map_GetHandleX         = "VMMDLL_Map_GetHandleW";
        internal const string VMMDLL_Map_GetNetX            = "VMMDLL_Map_GetNetW";
        internal const string VMMDLL_Map_GetKDeviceX        = "VMMDLL_Map_GetKDeviceW";
        internal const string VMMDLL_Map_GetKDriverX        = "VMMDLL_Map_GetKDriverW";
        internal const string VMMDLL_Map_GetKObjectX        = "VMMDLL_Map_GetKObjectW";
        internal const string VMMDLL_Map_GetThread_CallstackX = "VMMDLL_Map_GetThread_CallstackW";
        internal const string VMMDLL_Map_GetUsersX          = "VMMDLL_Map_GetUsersW";
        internal const string VMMDLL_Map_GetVMX             = "VMMDLL_Map_GetVMW";
        internal const string VMMDLL_Map_GetServicesX       = "VMMDLL_Map_GetServicesW";
        internal const string VMMDLL_WinReg_EnumKeyExX      = "VMMDLL_WinReg_EnumKeyExW";
        internal const string VMMDLL_WinReg_EnumValueX      = "VMMDLL_WinReg_EnumValueW";
        internal const string VMMDLL_WinReg_QueryValueExX   = "VMMDLL_WinReg_QueryValueExW";
#endif

        #endregion

        #region Types/Constants

        internal const ulong MAX_PATH = 260;
        internal const uint VMMDLL_MAP_PTE_VERSION = 2;
        internal const uint VMMDLL_MAP_VAD_VERSION = 6;
        internal const uint VMMDLL_MAP_VADEX_VERSION = 4;
        internal const uint VMMDLL_MAP_MODULE_VERSION = 6;
        internal const uint VMMDLL_MAP_UNLOADEDMODULE_VERSION = 2;
        internal const uint VMMDLL_MAP_EAT_VERSION = 3;
        internal const uint VMMDLL_MAP_IAT_VERSION = 2;
        internal const uint VMMDLL_MAP_HEAP_VERSION = 4;
        internal const uint VMMDLL_MAP_HEAPALLOC_VERSION = 1;
        internal const uint VMMDLL_MAP_THREAD_VERSION = 4;
        internal const uint VMMDLL_MAP_THREAD_CALLSTACK_VERSION = 1;
        internal const uint VMMDLL_MAP_HANDLE_VERSION = 3;
        internal const uint VMMDLL_MAP_NET_VERSION = 3;
        internal const uint VMMDLL_MAP_PHYSMEM_VERSION = 2;
        internal const uint VMMDLL_MAP_KDEVICE_VERSION = 1;
        internal const uint VMMDLL_MAP_KDRIVER_VERSION = 1;
        internal const uint VMMDLL_MAP_KOBJECT_VERSION = 1;
        internal const uint VMMDLL_MAP_POOL_VERSION = 2;
        internal const uint VMMDLL_MAP_USER_VERSION = 2;
        internal const uint VMMDLL_MAP_VM_VERSION = 2;
        internal const uint VMMDLL_MAP_PFN_VERSION = 1;
        internal const uint VMMDLL_MAP_SERVICE_VERSION = 3;
        internal const uint VMMDLL_MEM_SEARCH_VERSION = 0xfe3e0003;
        internal const uint VMMDLL_YARA_CONFIG_VERSION = 0xdec30001;
        internal const uint VMMDLL_YARA_MEMORY_CALLBACK_CONTEXT_VERSION = 0xdec40002;
        internal const uint VMMDLL_YARA_CONFIG_MAX_RESULT = 0x00010000;      // max 65k results.
        internal const uint VMMDLL_REGISTRY_HIVE_INFORMATION_VERSION = 4;

        internal const uint VMMDLL_VFS_FILELIST_EXINFO_VERSION = 1;
        internal const uint VMMDLL_VFS_FILELIST_VERSION = 2;

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential)]
        internal struct VMMDLL_VFS_FILELIST
        {
            internal uint dwVersion;
            internal uint _Reserved;
            internal IntPtr pfnAddFile;
            internal IntPtr pfnAddDirectory;
            internal ulong h;
        }

        internal const ulong VMMDLL_PROCESS_INFORMATION_MAGIC = 0xc0ffee663df9301e;
        internal const ushort VMMDLL_PROCESS_INFORMATION_VERSION = 7;

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential, CharSet = CharSet.Ansi)]
        internal struct VMMDLL_PROCESS_INFORMATION
        {
            internal ulong magic;
            internal ushort wVersion;
            internal ushort wSize;
            internal uint tpMemoryModel;
            internal uint tpSystem;
            internal bool fUserOnly;
            internal uint dwPID;
            internal uint dwPPID;
            internal uint dwState;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 16)] internal string szName;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 64)] internal string szNameLong;
            internal ulong paDTB;
            internal ulong paDTB_UserOpt;
            internal ulong vaEPROCESS;
            internal ulong vaPEB;
            internal ulong _Reserved1;
            internal bool fWow64;
            internal uint vaPEB32;
            internal uint dwSessionId;
            internal ulong qwLUID;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)] internal string szSID;
            internal uint IntegrityLevel;
        }

        internal struct VMMDLL_MAP_MODULE
        {
            internal uint dwVersion;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 5)] internal uint[] _Reserved1;
            internal ulong pbMultiText;
            internal uint cbMultiText;
            internal uint cMap;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential)]
        internal struct VMMDLL_MAP_PTEENTRY
        {
            internal ulong vaBase;
            internal ulong cPages;
            internal ulong fPage;
            internal bool fWoW64;
            internal uint _FutureUse1;
            [MarshalAs(VmmString)] internal string uszText;
            internal uint _Reserved1;
            internal uint cSoftware;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential)]
        internal struct VMMDLL_MAP_PTE
        {
            internal uint dwVersion;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 5)] internal uint[] _Reserved1;
            internal ulong pbMultiText;
            internal uint cbMultiText;
            internal uint cMap;
        }


        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential, CharSet = CharSet.Ansi)]
        internal struct VMMDLL_IMAGE_SECTION_HEADER
        {
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 8)] internal string Name;
            internal uint MiscPhysicalAddressOrVirtualSize;
            internal uint VirtualAddress;
            internal uint SizeOfRawData;
            internal uint PointerToRawData;
            internal uint PointerToRelocations;
            internal uint PointerToLinenumbers;
            internal ushort NumberOfRelocations;
            internal ushort NumberOfLinenumbers;
            internal uint Characteristics;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential)]
        internal struct VMMDLL_IMAGE_DATA_DIRECTORY
        {
            internal uint VirtualAddress;
            internal uint Size;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential)]
        internal struct VMMDLL_MAP_VADENTRY
        {
            internal ulong vaStart;
            internal ulong vaEnd;
            internal ulong vaVad;
            internal uint dw0;
            internal uint dw1;
            internal uint u2;
            internal uint cbPrototypePte;
            internal ulong vaPrototypePte;
            internal ulong vaSubsection;
            [MarshalAs(VmmString)] internal string uszText;
            internal uint _FutureUse1;
            internal uint _Reserved1;
            internal ulong vaFileObject;
            internal uint cVadExPages;
            internal uint cVadExPagesBase;
            internal ulong _Reserved2;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential)]
        internal struct VMMDLL_MAP_VAD
        {
            internal uint dwVersion;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)] internal uint[] _Reserved1;
            internal uint cPage;
            internal ulong pbMultiText;
            internal uint cbMultiText;
            internal uint cMap;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential)]
        internal struct VMMDLL_MAP_VADEXENTRY
        {
            internal uint tp;
            internal byte iPML;
            internal byte pteFlags;
            internal ushort _Reserved2;
            internal ulong va;
            internal ulong pa;
            internal ulong pte;
            internal uint _Reserved1;
            internal uint proto_tp;
            internal ulong proto_pa;
            internal ulong proto_pte;
            internal ulong vaVadBase;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential)]
        internal struct VMMDLL_MAP_VADEX
        {
            internal uint dwVersion;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)] internal uint[] _Reserved1;
            internal uint cMap;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential)]
        internal struct VMMDLL_MAP_UNLOADEDMODULEENTRY
        {
            internal ulong vaBase;
            internal uint cbImageSize;
            internal bool fWow64;
            [MarshalAs(VmmString)] internal string uszText;
            internal uint _FutureUse1;
            internal uint dwCheckSum;
            internal uint dwTimeDateStamp;
            internal uint _Reserved1;
            internal ulong ftUnload;
        }

        internal struct VMMDLL_MAP_UNLOADEDMODULE
        {
            internal uint dwVersion;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 5)] internal uint[] _Reserved1;
            internal ulong pbMultiText;
            internal uint cbMultiText;
            internal uint cMap;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential)]
        internal struct VMMDLL_MAP_MODULEENTRY_DEBUGINFO
        {
            internal uint dwAge;
            internal uint _Reserved;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)] internal byte[] Guid;
            [MarshalAs(VmmString)] internal string uszGuid;
            [MarshalAs(VmmString)] internal string uszPdbFilename;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential)]
        internal struct VMMDLL_MAP_MODULEENTRY_VERSIONINFO
        {
            [MarshalAs(VmmString)] internal string uszCompanyName;
            [MarshalAs(VmmString)] internal string uszFileDescription;
            [MarshalAs(VmmString)] internal string uszFileVersion;
            [MarshalAs(VmmString)] internal string uszInternalName;
            [MarshalAs(VmmString)] internal string uszLegalCopyright;
            [MarshalAs(VmmString)] internal string uszFileOriginalFilename;
            [MarshalAs(VmmString)] internal string uszProductName;
            [MarshalAs(VmmString)] internal string uszProductVersion;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential)]
        internal struct VMMDLL_MAP_MODULEENTRY
        {
            internal ulong vaBase;
            internal ulong vaEntry;
            internal uint cbImageSize;
            internal bool fWow64;
            [MarshalAs(VmmString)] internal string uszText;
            internal uint _Reserved3;
            internal uint _Reserved4;
            [MarshalAs(VmmString)] internal string uszFullName;
            internal uint tp;
            internal uint cbFileSizeRaw;
            internal uint cSection;
            internal uint cEAT;
            internal uint cIAT;
            internal uint _Reserved2;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 3)] internal ulong[] _Reserved1;
            internal IntPtr pExDebugInfo;
            internal IntPtr pExVersionInfo;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential)]
        internal struct VMMDLL_MAP_EATENTRY
        {
            internal ulong vaFunction;
            internal uint dwOrdinal;
            internal uint oFunctionsArray;
            internal uint oNamesArray;
            internal uint _FutureUse1;
            [MarshalAs(VmmString)] internal string uszFunction;
            [MarshalAs(VmmString)] internal string uszForwardedFunction;
        }

        internal struct VMMDLL_MAP_EAT
        {
            internal uint dwVersion;
            internal uint dwOrdinalBase;
            internal uint cNumberOfNames;
            internal uint cNumberOfFunctions;
            internal uint cNumberOfForwardedFunctions;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 3)] internal uint[] _Reserved1;
            internal ulong vaModuleBase;
            internal ulong vaAddressOfFunctions;
            internal ulong vaAddressOfNames;
            internal ulong pbMultiText;
            internal uint cbMultiText;
            internal uint cMap;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential)]
        internal struct VMMDLL_MAP_IATENTRY
        {
            internal ulong vaFunction;
            [MarshalAs(VmmString)] internal string uszFunction;
            internal uint _FutureUse1;
            internal uint _FutureUse2;
            [MarshalAs(VmmString)] internal string uszModule;
            internal bool f32;
            internal ushort wHint;
            internal ushort _Reserved1;
            internal uint rvaFirstThunk;
            internal uint rvaOriginalFirstThunk;
            internal uint rvaNameModule;
            internal uint rvaNameFunction;
        }

        internal struct VMMDLL_MAP_IAT
        {
            internal uint dwVersion;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 5)] internal uint[] _Reserved1;
            internal ulong vaModuleBase;
            internal ulong pbMultiText;
            internal uint cbMultiText;
            internal uint cMap;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential)]
        internal struct VMMDLL_MAP_HEAPENTRY
        {
            internal ulong va;
            internal uint tp;
            internal bool f32;
            internal uint iHeap;
            internal uint dwHeapNum;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential)]
        internal struct VMMDLL_MAP_HEAPSEGMENTENTRY
        {
            internal ulong va;
            internal uint cb;
            internal ushort tp;
            internal ushort iHeap;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential)]
        internal struct VMMDLL_MAP_HEAP
        {
            internal uint dwVersion;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 7)] internal uint[] _Reserved1;
            internal IntPtr pSegments;
            internal uint cSegments;
            internal uint cMap;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential)]
        internal struct VMMDLL_MAP_HEAPALLOCENTRY
        {
            internal ulong va;
            internal uint cb;
            internal uint tp;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential)]
        internal struct VMMDLL_MAP_HEAPALLOC
        {
            internal uint dwVersion;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 7)] internal uint[] _Reserved1;
            internal IntPtr _Reserved20;
            internal IntPtr _Reserved21;
            internal uint cMap;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential)]
        internal struct VMMDLL_MAP_THREADENTRY
        {
            internal uint dwTID;
            internal uint dwPID;
            internal uint dwExitStatus;
            internal byte bState;
            internal byte bRunning;
            internal byte bPriority;
            internal byte bBasePriority;
            internal ulong vaETHREAD;
            internal ulong vaTeb;
            internal ulong ftCreateTime;
            internal ulong ftExitTime;
            internal ulong vaStartAddress;
            internal ulong vaStackBaseUser;          // value from _NT_TIB / _TEB
            internal ulong vaStackLimitUser;         // value from _NT_TIB / _TEB
            internal ulong vaStackBaseKernel;
            internal ulong vaStackLimitKernel;
            internal ulong vaTrapFrame;
            internal ulong vaRIP;                    // RIP register (if user mode)
            internal ulong vaRSP;                    // RSP register (if user mode)
            internal ulong qwAffinity;
            internal uint dwUserTime;
            internal uint dwKernelTime;
            internal byte bSuspendCount;
            internal byte bWaitReason;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 2)] internal byte[] _FutureUse1;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 11)] internal uint[] _FutureUse2;
            internal ulong vaImpersonationToken;
            internal ulong vaWin32StartAddress;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential)]
        internal struct VMMDLL_MAP_THREAD
        {
            internal uint dwVersion;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)] internal uint[] _Reserved1;
            internal uint cMap;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential)]
        internal struct VMMDLL_MAP_THREAD_CALLSTACKENTRY
        {
            internal uint i;
            internal bool fRegPresent;
            internal ulong vaRetAddr;
            internal ulong vaRSP;
            internal ulong vaBaseSP;
            internal uint _FutureUse1;
            internal uint cbDisplacement;
            [MarshalAs(VmmString)] internal string uszModule;
            [MarshalAs(VmmString)] internal string uszFunction;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential)]
        internal struct VMMDLL_MAP_THREAD_CALLSTACK
        {
            internal uint dwVersion;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 6)] internal uint[] _Reserved1;
            internal uint dwPID;
            internal uint dwTID;
            internal uint cbText;
            [MarshalAs(VmmString)] internal string uszText;
            internal IntPtr pbMultiText;
            internal uint cbMultiText;
            internal uint cMap;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential)]
        internal struct VMMDLL_MAP_HANDLEENTRY
        {
            internal ulong vaObject;
            internal uint dwHandle;
            internal uint dwGrantedAccess_iType;
            internal ulong qwHandleCount;
            internal ulong qwPointerCount;
            internal ulong vaObjectCreateInfo;
            internal ulong vaSecurityDescriptor;
            [MarshalAs(VmmString)] internal string uszText;
            internal uint _FutureUse2;
            internal uint dwPID;
            internal uint dwPoolTag;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 7)] internal uint[] _FutureUse;
            [MarshalAs(VmmString)] internal string uszType;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential)]
        internal struct VMMDLL_MAP_HANDLE
        {
            internal uint dwVersion;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 5)] internal uint[] _Reserved1;
            internal ulong pbMultiText;
            internal uint cbMultiText;
            internal uint cMap;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential)]
        internal struct VMMDLL_MAP_NETENTRY
        {
            internal uint dwPID;
            internal uint dwState;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 3)] internal ushort[] _FutureUse3;
            internal ushort AF;
            // src
            internal bool src_fValid;
            internal ushort src__Reserved1;
            internal ushort src_port;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)] internal byte[] src_pbAddr;
            [MarshalAs(VmmString)] internal string src_uszText;
            // dst
            internal bool dst_fValid;
            internal ushort dst__Reserved1;
            internal ushort dst_port;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)] internal byte[] dst_pbAddr;
            [MarshalAs(VmmString)] internal string dst_uszText;
            //
            internal ulong vaObj;
            internal ulong ftTime;
            internal uint dwPoolTag;
            internal uint _FutureUse4;
            [MarshalAs(VmmString)] internal string uszText;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)] internal uint[] _FutureUse2;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential)]
        internal struct VMMDLL_MAP_NET
        {
            internal uint dwVersion;
            internal uint _Reserved1;
            internal ulong pbMultiText;
            internal uint cbMultiText;
            internal uint cMap;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential)]
        internal struct VMMDLL_MAP_PHYSMEMENTRY
        {
            internal ulong pa;
            internal ulong cb;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential)]
        internal struct VMMDLL_MAP_PHYSMEM
        {
            internal uint dwVersion;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 5)] internal uint[] _Reserved1;
            internal uint cMap;
            internal uint _Reserved2;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential)]
        internal struct VMMDLL_MAP_KDEVICEENTRY
        {
            internal ulong va;
            internal uint iDepth;
            internal uint dwDeviceType;
            [MarshalAs(VmmString)] internal string uszDeviceType;
            internal ulong vaDriverObject;
            internal ulong vaAttachedDevice;
            internal ulong vaFileSystemDevice;
            [MarshalAs(VmmString)] internal string uszVolumeInfo;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential)]
        internal struct VMMDLL_MAP_KDEVICE
        {
            internal uint dwVersion;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 5)] internal uint[] _Reserved1;
            internal ulong pbMultiText;
            internal uint cbMultiText;
            internal uint cMap;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential)]
        internal struct VMMDLL_MAP_KDRIVERENTRY
        {
            internal ulong va;
            internal ulong vaDriverStart;
            internal ulong cbDriverSize;
            internal ulong vaDeviceObject;
            [MarshalAs(VmmString)] internal string uszName;
            [MarshalAs(VmmString)] internal string uszPath;
            [MarshalAs(VmmString)] internal string uszServiceKeyName;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 28)] internal ulong[] MajorFunction;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential)]
        internal struct VMMDLL_MAP_KDRIVER
        {
            internal uint dwVersion;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 5)] internal uint[] _Reserved1;
            internal ulong pbMultiText;
            internal uint cbMultiText;
            internal uint cMap;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential)]
        internal struct VMMDLL_MAP_KOBJECTENTRY
        {
            internal ulong va;
            internal ulong vaParent;
            internal uint _Filler;
            internal uint cvaChild;
            internal IntPtr pvaChild;
            [MarshalAs(VmmString)] internal string uszName;
            [MarshalAs(VmmString)] internal string uszType;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential)]
        internal struct VMMDLL_MAP_KOBJECT
        {
            internal uint dwVersion;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 5)] internal uint[] _Reserved1;
            internal ulong pbMultiText;
            internal uint cbMultiText;
            internal uint cMap;
        }

        internal const uint VMMDLL_POOLMAP_FLAG_ALL = 0;
        internal const uint VMMDLL_POOLMAP_FLAG_BIG = 1;

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential)]
        internal struct VMMDLL_MAP_POOLENTRY
        {
            internal ulong va;
            internal uint dwTag;
            internal byte _ReservedZero;
            internal byte fAlloc;
            internal byte tpPool;
            internal byte tpSS;
            internal uint cb;
            internal uint _Filler;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential)]
        internal struct VMMDLL_MAP_POOL
        {
            internal uint dwVersion;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 6)] internal uint[] _Reserved1;
            internal uint cbTotal;
            internal IntPtr _piTag2Map;
            internal IntPtr _pTag;
            internal uint cTag;
            internal uint cMap;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential, CharSet = CharSet.Ansi)]
        internal struct VMMDLL_MAP_USERENTRY
        {
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 2)] internal uint[] _FutureUse1;
            [MarshalAs(VmmString)] internal string uszText;
            internal ulong vaRegHive;
            [MarshalAs(VmmString)] internal string uszSID;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 2)] internal uint[] _FutureUse2;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential)]
        internal struct VMMDLL_MAP_USER
        {
            internal uint dwVersion;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 5)] internal uint[] _Reserved1;
            internal ulong pbMultiText;
            internal uint cbMultiText;
            internal uint cMap;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential)]
        internal struct VMMDLL_MAP_VMENTRY
        {
            internal ulong hVM;
            [MarshalAs(VmmString)] internal string uszName;
            internal ulong gpaMax;
            internal uint tp;
            internal bool fActive;
            internal bool fReadOnly;
            internal bool fPhysicalOnly;
            internal uint dwPartitionID;
            internal uint dwVersionBuild;
            internal uint tpSystem;
            internal uint dwParentVmmMountID;
            internal uint dwVmMemPID;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential)]
        internal struct VMMDLL_MAP_VM
        {
            internal uint dwVersion;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 5)] internal uint[] _Reserved1;
            internal ulong pbMultiText;
            internal uint cbMultiText;
            internal uint cMap;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential)]
        internal struct VMMDLL_MAP_SERVICEENTRY
        {
            internal ulong vaObj;
            internal uint dwOrdinal;
            internal uint dwStartType;
            // SERVICE_STATUS START
            internal uint dwServiceType;
            internal uint dwCurrentState;
            internal uint dwControlsAccepted;
            internal uint dwWin32ExitCode;
            internal uint dwServiceSpecificExitCode;
            internal uint dwCheckPoint;
            internal uint dwWaitHint;
            // SERVICE_STATUS END
            [MarshalAs(VmmString)] internal string uszServiceName;
            [MarshalAs(VmmString)] internal string uszDisplayName;
            [MarshalAs(VmmString)] internal string uszPath;
            [MarshalAs(VmmString)] internal string uszUserTp;
            [MarshalAs(VmmString)] internal string uszUserAcct;
            [MarshalAs(VmmString)] internal string uszImagePath;
            internal uint dwPID;
            internal uint _FutureUse1;
            internal ulong _FutureUse2;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential)]
        internal struct VMMDLL_MAP_SERVICE
        {
            internal uint dwVersion;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 5)] internal uint[] _Reserved1;
            internal ulong pbMultiText;
            internal uint cbMultiText;
            internal uint cMap;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential)]
        internal struct VMMDLL_MAP_PFNENTRY
        {
            internal uint dwPfn;
            internal uint tpExtended;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 5)] internal uint[] dwPfnPte;
            internal ulong va;
            internal ulong vaPte;
            internal ulong OriginalPte;
            internal uint _u3;
            internal ulong _u4;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 6)] internal uint[] _FutureUse;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential)]
        internal struct VMMDLL_MAP_PFN
        {
            internal uint dwVersion;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 5)] internal uint[] _Reserved1;
            internal uint cMap;
            internal uint _Reserved2;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential)]
        internal struct VMMDLL_REGISTRY_HIVE_INFORMATION
        {
            internal ulong magic;
            internal ushort wVersion;
            internal ushort wSize;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 0x34)] internal byte[] _FutureReserved1;
            internal ulong vaCMHIVE;
            internal ulong vaHBASE_BLOCK;
            internal uint cbLength;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 128)] internal byte[] uszName;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 33)] internal byte[] uszNameShort;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 260)] internal byte[] uszHiveRootPath;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 0x10)] internal ulong[] _FutureReserved;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential)]
        internal struct VMMDLL_MEM_SEARCH_CONTEXT_SEARCHENTRY
        {
            internal uint cbAlign;
            internal uint cb;
            internal unsafe fixed byte pb[32];
            internal unsafe fixed byte pbSkipMask[32];
            //[MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)] internal byte[] pb;
            //[MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)] internal byte[] pbSkipMask;
        }

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        internal delegate bool SearchResultCallback(VMMDLL_MEM_SEARCH_CONTEXT ctx, ulong va, uint iSearch);

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential)]
        internal struct VMMDLL_MEM_SEARCH_CONTEXT
        {
            internal uint dwVersion;
            internal uint _Filler01;
            internal uint _Filler02;
            internal bool fAbortRequested;
            internal uint cMaxResult;
            internal uint cSearch;
            internal IntPtr search;
            internal ulong vaMin;
            internal ulong vaMax;
            internal ulong vaCurrent;
            internal uint _Filler2;
            internal uint cResult;
            internal ulong cbReadTotal;
            internal IntPtr pvUserPtrOpt;
            internal SearchResultCallback pfnResultOptCB;
            internal ulong ReadFlags;
            internal bool fForcePTE;
            internal bool fForceVAD;
            internal IntPtr pfnFilterOptCB;
        }

#pragma warning disable CS0169

        internal const uint VMMYARA_RULE_MATCH_VERSION = 0xfedc0005;
        internal const int VMMYARA_RULE_MATCH_TAG_MAX = 27;
        internal const int VMMYARA_RULE_MATCH_META_MAX = 32;
        internal const int VMMYARA_RULE_MATCH_STRING_MAX = 16;
        internal const int VMMYARA_RULE_MATCH_OFFSET_MAX = 24;

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        internal unsafe delegate bool YaraScanMemoryCallback(IntPtr ctx, VMMYARA_RULE_MATCH pRuleMatch, byte* pbBuffer, ulong cbBuffer);

        internal struct VMMDLL_YARA_CONFIG
        {
            internal uint dwVersion;            // VMMDLL_YARA_CONFIG_VERSION
            internal uint _Filler00;
            internal uint _Filler01;
            internal bool fAbortRequested;      // may be set by caller to abort processing prematurely.
            internal uint cMaxResult;           // # max result entries. max 0x10000 entries. 0 = max entries.
            internal uint cRules;               // number of rules to use - if compiled rules only 1 is allowed.
            internal IntPtr pszRules;           // array of rules to use - either filenames or in-memory rules.
            internal ulong vaMin;
            internal ulong vaMax;
            internal ulong vaCurrent;           // current address (may be read by caller).
            internal uint _Filler2;
            internal uint cResult;              // number of search hits.
            internal ulong cbReadTotal;         // total number of bytes read.
            internal IntPtr pvUserPtrOpt;       // optional pointer set by caller (used for context passing to callbacks)
                                                // match callback function (recommended but optional).
                                                // return = continue search(TRUE), abort search(FALSE).
            internal YaraScanMemoryCallback pfnScanMemoryCB;
            // non-recommended features:
            internal ulong ReadFlags;           // read flags as in VMMDLL_FLAG_*
            internal bool fForcePTE;            // force PTE method for virtual address reads.
            internal bool fForceVAD;            // force VAD method for virtual address reads.
                                                // optional filter callback function for virtual address reads:
                                                // for ranges inbetween vaMin:vaMax callback with pte or vad entry.
                                                // return: read from range(TRUE), do not read from range(FALSE).
            internal IntPtr pfnFilterOptCB;
            internal IntPtr pvUserPtrOpt2;      // optional pointer set by caller (not used by MemProcFS).
            internal ulong _Reserved;
        }

        internal struct VMMYARA_RULE_MATCH
        {
            internal uint dwVersion;            // VMMYARA_RULE_MATCH_VERSION
            internal uint flags;
            [MarshalAs(VmmString)] internal string szRuleIdentifier;
            internal uint cTags;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = VMMYARA_RULE_MATCH_TAG_MAX)] internal IntPtr[] szTags;
            internal uint cMeta;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = VMMYARA_RULE_MATCH_META_MAX)] internal VMMYARA_RULE_MATCH_META[] Meta;
            internal uint cStrings;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = VMMYARA_RULE_MATCH_STRING_MAX)] internal VMMYARA_RULE_MATCH_STRINGS[] Strings;
        }

        internal struct VMMYARA_RULE_MATCH_META
        {
            [MarshalAs(VmmString)] internal string szIdentifier;
            [MarshalAs(VmmString)] internal string szString;
        }

        internal struct VMMYARA_RULE_MATCH_STRINGS
        {
            [MarshalAs(VmmString)] internal string szString;
            internal uint cMatch;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = VMMYARA_RULE_MATCH_OFFSET_MAX)] internal ulong[] cbMatchOffset;
        }

#pragma warning restore CS0169

        #endregion

        #region Base functionality

#if NET7_0_OR_GREATER
        [LibraryImport("vmm", EntryPoint = "VMMDLL_InitializeEx")]
        internal static partial IntPtr VMMDLL_InitializeEx(
            int argc,
            [MarshalAs(UnmanagedType.LPArray, ArraySubType = UnmanagedType.LPStr)]
            string[] argv,
            out IntPtr ppLcErrorInfo);

        [LibraryImport("vmm", EntryPoint = "VMMDLL_CloseAll")]
        public static partial void VMMDLL_CloseAll();

        [LibraryImport("vmm", EntryPoint = "VMMDLL_Close")]
        public static partial void VMMDLL_Close(
            IntPtr hVMM);

        [LibraryImport("vmm", EntryPoint = "VMMDLL_ConfigGet")]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static partial bool VMMDLL_ConfigGet(
            IntPtr hVMM,
            ulong fOption,
            out ulong pqwValue);

        [LibraryImport("vmm", EntryPoint = "VMMDLL_ConfigSet")]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static partial bool VMMDLL_ConfigSet(
            IntPtr hVMM,
            ulong fOption,
            ulong qwValue);

        [LibraryImport("vmm", EntryPoint = "VMMDLL_MemFree")]
        internal static unsafe partial void VMMDLL_MemFree(
            byte* pvMem);

        // VFS (VIRTUAL FILE SYSTEM) FUNCTIONALITY BELOW:

        [LibraryImport("vmm", EntryPoint = "VMMDLL_VfsListU")]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static unsafe partial bool VMMDLL_VfsList(
            IntPtr hVMM,
            [MarshalAs(UnmanagedType.LPUTF8Str)] string wcsPath,
            ref VMMDLL_VFS_FILELIST pFileList);

        [LibraryImport("vmm", EntryPoint = "VMMDLL_VfsReadU")]
        internal static unsafe partial uint VMMDLL_VfsRead(
            IntPtr hVMM,
            [MarshalAs(UnmanagedType.LPUTF8Str)] string wcsFileName,
            byte* pb,
            uint cb,
            out uint pcbRead,
            ulong cbOffset);

        [LibraryImport("vmm", EntryPoint = "VMMDLL_VfsWriteU")]
        internal static unsafe partial uint VMMDLL_VfsWrite(
            IntPtr hVMM,
            [MarshalAs(UnmanagedType.LPUTF8Str)] string wcsFileName,
            byte* pb,
            uint cb,
            out uint pcbRead,
            ulong cbOffset);

        // PLUGIN FUNCTIONALITY BELOW:

        [LibraryImport("vmm", EntryPoint = "VMMDLL_InitializePlugins")]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static partial bool VMMDLL_InitializePlugins(IntPtr hVMM);

        // MEMORY READ/WRITE FUNCTIONALITY BELOW:

        [LibraryImport("vmm", EntryPoint = "VMMDLL_MemReadScatter")]
        internal static unsafe partial uint VMMDLL_MemReadScatter(
            IntPtr hVMM,
            uint dwPID,
            IntPtr ppMEMs,
            uint cpMEMs,
            uint flags);

        [LibraryImport("vmm", EntryPoint = "VMMDLL_MemReadEx")]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static unsafe partial bool VMMDLL_MemReadEx(
            IntPtr hVMM,
            uint dwPID,
            ulong qwA,
            byte* pb,
            uint cb,
            out uint pcbReadOpt,
            uint flags);

        [LibraryImport("vmm", EntryPoint = "VMMDLL_MemPrefetchPages")]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static unsafe partial bool VMMDLL_MemPrefetchPages(
            IntPtr hVMM,
            uint dwPID,
            byte* pPrefetchAddresses,
            uint cPrefetchAddresses);

        [LibraryImport("vmm", EntryPoint = "VMMDLL_MemWrite")]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static unsafe partial bool VMMDLL_MemWrite(
            IntPtr hVMM,
            uint dwPID,
            ulong qwA,
            byte* pb,
            uint cb);

        [LibraryImport("vmm", EntryPoint = "VMMDLL_MemVirt2Phys")]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static partial bool VMMDLL_MemVirt2Phys(
            IntPtr hVMM,
            uint dwPID,
            ulong qwVA,
            out ulong pqwPA
            );

        // MEMORY NEW SCATTER READ/WRITE FUNCTIONALITY BELOW:

        [LibraryImport("vmm", EntryPoint = "VMMDLL_Scatter_Initialize")]
        internal static unsafe partial IntPtr VMMDLL_Scatter_Initialize(
            IntPtr hVMM,
            uint dwPID,
            uint flags);

        [LibraryImport("vmm", EntryPoint = "VMMDLL_Scatter_Prepare")]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static unsafe partial bool VMMDLL_Scatter_Prepare(
            IntPtr hS,
            ulong va,
            uint cb);

        [LibraryImport("vmm", EntryPoint = "VMMDLL_Scatter_PrepareWrite")]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static unsafe partial bool VMMDLL_Scatter_PrepareWrite(
            IntPtr hS,
            ulong va,
            byte* pb,
            uint cb);

        [LibraryImport("vmm", EntryPoint = "VMMDLL_Scatter_ExecuteRead")]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static unsafe partial bool VMMDLL_Scatter_ExecuteRead(
            IntPtr hS);

        [LibraryImport("vmm", EntryPoint = "VMMDLL_Scatter_Execute")]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static unsafe partial bool VMMDLL_Scatter_Execute(
            IntPtr hS);

        [LibraryImport("vmm", EntryPoint = "VMMDLL_Scatter_Read")]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static unsafe partial bool VMMDLL_Scatter_Read(
            IntPtr hS,
            ulong va,
            uint cb,
            byte* pb,
            out uint pcbRead);

        [LibraryImport("vmm", EntryPoint = "VMMDLL_Scatter_Clear")]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static partial bool SVMMDLL_Scatter_Clear(IntPtr hS, uint dwPID, uint flags);

        [LibraryImport("vmm", EntryPoint = "VMMDLL_Scatter_Clear")]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static unsafe partial bool VMMDLL_Scatter_Clear(
            IntPtr hS,
            uint dwPID,
            uint flags);

        [LibraryImport("vmm", EntryPoint = "VMMDLL_Scatter_CloseHandle")]
        internal static unsafe partial void VMMDLL_Scatter_CloseHandle(
            IntPtr hS);

        // PROCESS FUNCTIONALITY BELOW:

        [LibraryImport("vmm", EntryPoint = "VMMDLL_PidList")]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static unsafe partial bool VMMDLL_PidList(IntPtr hVMM, byte* pPIDs, ref ulong pcPIDs);

        [LibraryImport("vmm", EntryPoint = "VMMDLL_PidGetFromName")]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static partial bool VMMDLL_PidGetFromName(IntPtr hVMM, [MarshalAs(UnmanagedType.LPStr)] string szProcName, out uint pdwPID);

        [LibraryImport("vmm", EntryPoint = "VMMDLL_ProcessGetProcAddressU")]
        public static partial ulong VMMDLL_ProcessGetProcAddress(IntPtr hVMM, uint pid, [MarshalAs(UnmanagedType.LPUTF8Str)] string uszModuleName, [MarshalAs(UnmanagedType.LPStr)] string szFunctionName);

        [LibraryImport("vmm", EntryPoint = "VMMDLL_ProcessGetModuleBaseU")]
        public static partial ulong VMMDLL_ProcessGetModuleBase(IntPtr hVMM, uint pid, [MarshalAs(UnmanagedType.LPUTF8Str)] string uszModuleName);

        [LibraryImport("vmm", EntryPoint = "VMMDLL_ProcessGetInformation")]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static unsafe partial bool VMMDLL_ProcessGetInformation(
            IntPtr hVMM,
            uint dwPID,
            byte* pProcessInformation,
            ref ulong pcbProcessInformation);

        [LibraryImport("vmm", EntryPoint = "VMMDLL_ProcessGetInformationString")]
        internal static unsafe partial byte* VMMDLL_ProcessGetInformationString(
            IntPtr hVMM,
            uint dwPID,
            uint fOptionString);

        [LibraryImport("vmm", EntryPoint = "VMMDLL_ProcessGetDirectoriesU")]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static unsafe partial bool VMMDLL_ProcessGetDirectories(
            IntPtr hVMM,
            uint dwPID,
            [MarshalAs(UnmanagedType.LPUTF8Str)] string uszModule,
            byte* pData);

        [LibraryImport("vmm", EntryPoint = "VMMDLL_ProcessGetSectionsU")]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static unsafe partial bool VMMDLL_ProcessGetSections(
            IntPtr hVMM,
            uint dwPID,
            [MarshalAs(UnmanagedType.LPUTF8Str)] string uszModule,
            byte* pData,
            uint cData,
            out uint pcData);

        // WINDOWS SPECIFIC DEBUGGING / SYMBOL FUNCTIONALITY BELOW:

        [LibraryImport("vmm", EntryPoint = "VMMDLL_PdbLoad")]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static unsafe partial bool VMMDLL_PdbLoad(
            IntPtr hVMM,
            uint dwPID,
            ulong vaModuleBase,
            byte* pModuleMapEntry);

        [LibraryImport("vmm", EntryPoint = "VMMDLL_PdbSymbolName")]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static unsafe partial bool VMMDLL_PdbSymbolName(
            IntPtr hVMM,
            [MarshalAs(UnmanagedType.LPStr)] string szModule,
            ulong cbSymbolAddressOrOffset,
            byte* szSymbolName,
            out uint pdwSymbolDisplacement);

        [LibraryImport("vmm", EntryPoint = "VMMDLL_PdbSymbolAddress")]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static partial bool VMMDLL_PdbSymbolAddress(
            IntPtr hVMM,
            [MarshalAs(UnmanagedType.LPStr)] string szModule,
            [MarshalAs(UnmanagedType.LPStr)] string szSymbolName,
            out ulong pvaSymbolAddress);

        [LibraryImport("vmm", EntryPoint = "VMMDLL_PdbTypeSize")]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static partial bool VMMDLL_PdbTypeSize(
            IntPtr hVMM,
            [MarshalAs(UnmanagedType.LPStr)] string szModule,
            [MarshalAs(UnmanagedType.LPStr)] string szTypeName,
            out uint pcbTypeSize);

        [LibraryImport("vmm", EntryPoint = "VMMDLL_PdbTypeChildOffset")]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static partial bool VMMDLL_PdbTypeChildOffset(
            IntPtr hVMM,
            [MarshalAs(UnmanagedType.LPStr)] string szModule,
            [MarshalAs(UnmanagedType.LPStr)] string szTypeName,
            [MarshalAs(UnmanagedType.LPStr)] string wszTypeChildName,
            out uint pcbTypeChildOffset);

        // VMMDLL_Map_GetPte
        [LibraryImport("vmm", EntryPoint = "VMMDLL_Map_GetPteU")]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static unsafe partial bool VMMDLL_Map_GetPte(
            IntPtr hVMM,
            uint dwPid,
            [MarshalAs(UnmanagedType.Bool)] bool fIdentifyModules,
            out IntPtr ppPteMap);

        // VMMDLL_Map_GetVad
        [LibraryImport("vmm", EntryPoint = "VMMDLL_Map_GetVadU")]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static unsafe partial bool VMMDLL_Map_GetVad(
            IntPtr hVMM,
            uint dwPid,
            [MarshalAs(UnmanagedType.Bool)] bool fIdentifyModules,
            out IntPtr ppVadMap);

        // VMMDLL_Map_GetVadEx
        [LibraryImport("vmm", EntryPoint = "VMMDLL_Map_GetVadEx")]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static unsafe partial bool VMMDLL_Map_GetVadEx(
            IntPtr hVMM,
            uint dwPid,
            uint oPage,
            uint cPage,
            out IntPtr ppVadExMap);

        // VMMDLL_Map_GetModule
        [LibraryImport("vmm", EntryPoint = "VMMDLL_Map_GetModuleU")]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static unsafe partial bool VMMDLL_Map_GetModule(
            IntPtr hVMM,
            uint dwPid,
            out IntPtr ppModuleMap,
            uint flags);

        // VMMDLL_Map_GetModuleFromName
        [LibraryImport("vmm", EntryPoint = "VMMDLL_Map_GetModuleFromNameU")]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static unsafe partial bool VMMDLL_Map_GetModuleFromName(
            IntPtr hVMM,
            uint dwPID,
            [MarshalAs(UnmanagedType.LPUTF8Str)] string uszModuleName,
            out IntPtr ppModuleMapEntry,
            uint flags);

        // VMMDLL_Map_GetUnloadedModule
        [LibraryImport("vmm", EntryPoint = "VMMDLL_Map_GetUnloadedModuleU")]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static unsafe partial bool VMMDLL_Map_GetUnloadedModule(
            IntPtr hVMM,
            uint dwPid,
            out IntPtr ppModuleMap);

        // VMMDLL_Map_GetEAT
        [LibraryImport("vmm", EntryPoint = "VMMDLL_Map_GetEATU")]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static unsafe partial bool VMMDLL_Map_GetEAT(
            IntPtr hVMM,
            uint dwPid,
            [MarshalAs(UnmanagedType.LPUTF8Str)] string uszModuleName,
            out IntPtr ppEatMap);

        // VMMDLL_Map_GetIAT
        [LibraryImport("vmm", EntryPoint = "VMMDLL_Map_GetIATU")]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static unsafe partial bool VMMDLL_Map_GetIAT(
            IntPtr hVMM,
            uint dwPid,
            [MarshalAs(UnmanagedType.LPUTF8Str)] string uszModuleName,
            out IntPtr ppIatMap);

        // VMMDLL_Map_GetHeap
        [LibraryImport("vmm", EntryPoint = "VMMDLL_Map_GetHeap")]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static unsafe partial bool VMMDLL_Map_GetHeap(
            IntPtr hVMM,
            uint dwPid,
            out IntPtr ppHeapMap);

        // VMMDLL_Map_GetHeapAlloc
        [LibraryImport("vmm", EntryPoint = "VMMDLL_Map_GetHeapAlloc")]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static unsafe partial bool VMMDLL_Map_GetHeapAlloc(
            IntPtr hVMM,
            uint dwPid,
            ulong qwHeapNumOrAddress,
            out IntPtr ppHeapAllocMap);

        // VMMDLL_Map_GetThread
        [LibraryImport("vmm", EntryPoint = "VMMDLL_Map_GetThread")]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static unsafe partial bool VMMDLL_Map_GetThread(
            IntPtr hVMM,
            uint dwPid,
            out IntPtr ppThreadMap);

        // VMMDLL_Map_GetThread_Callstack
        [LibraryImport("vmm", EntryPoint = "VMMDLL_Map_GetThread_CallstackU")]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static unsafe partial bool VMMDLL_Map_GetThread_Callstack(
            IntPtr hVMM,
            uint dwPID,
            uint dwTID,
            uint flags,
            out IntPtr ppThreadCallstack);

        // VMMDLL_Map_GetHandle
        [LibraryImport("vmm", EntryPoint = "VMMDLL_Map_GetHandleU")]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static unsafe partial bool VMMDLL_Map_GetHandle(
            IntPtr hVMM,
            uint dwPid,
            out IntPtr ppHandleMap);

        // VMMDLL_Map_GetNet
        [LibraryImport("vmm", EntryPoint = "VMMDLL_Map_GetNetU")]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static unsafe partial bool VMMDLL_Map_GetNet(
            IntPtr hVMM,
            out IntPtr ppNetMap);

        // VMMDLL_Map_GetPhysMem
        [LibraryImport("vmm", EntryPoint = "VMMDLL_Map_GetPhysMem")]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static unsafe partial bool VMMDLL_Map_GetPhysMem(
            IntPtr hVMM,
            out IntPtr ppPhysMemMap);

        // VMMDLL_Map_GetKDevice
        [LibraryImport("vmm", EntryPoint = "VMMDLL_Map_GetKDeviceU")]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static unsafe partial bool VMMDLL_Map_GetKDevice(
            IntPtr hVMM,
            out IntPtr ppKDeviceMap);

        // VMMDLL_Map_GetKDriver
        [LibraryImport("vmm", EntryPoint = "VMMDLL_Map_GetKDriverU")]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static unsafe partial bool VMMDLL_Map_GetKDriver(
            IntPtr hVMM,
            out IntPtr ppKDriverMap);

        // VMMDLL_Map_GetKObject
        [LibraryImport("vmm", EntryPoint = "VMMDLL_Map_GetKObjectU")]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static unsafe partial bool VMMDLL_Map_GetKObject(
            IntPtr hVMM,
            out IntPtr ppKObjectMap);

        // VMMDLL_Map_GetPool
        [LibraryImport("vmm", EntryPoint = "VMMDLL_Map_GetPool")]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static unsafe partial bool VMMDLL_Map_GetPool(
            IntPtr hVMM,
            out IntPtr ppPoolMap,
            uint flags);

        // VMMDLL_Map_GetUsers
        [LibraryImport("vmm", EntryPoint = "VMMDLL_Map_GetUsersU")]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static unsafe partial bool VMMDLL_Map_GetUsers(
            IntPtr hVMM,
            out IntPtr ppUserMap);

        // VMMDLL_Map_GetVM
        [LibraryImport("vmm", EntryPoint = "VMMDLL_Map_GetVMU")]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static unsafe partial bool VMMDLL_Map_GetVM(
            IntPtr hVMM,
            out IntPtr ppUserMap);

        // VMMDLL_Map_GetServices
        [LibraryImport("vmm", EntryPoint = "VMMDLL_Map_GetServicesU")]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static unsafe partial bool VMMDLL_Map_GetServices(
            IntPtr hVMM,
            out IntPtr ppServiceMap);

        // VMMDLL_Map_GetPfn
        [LibraryImport("vmm", EntryPoint = "VMMDLL_Map_GetPfn")]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static unsafe partial bool VMMDLL_Map_GetPfn(
            IntPtr hVMM,
            byte* pPfns,
            uint cPfns,
            byte* pPfnMap,
            ref uint pcbPfnMap);

        // REGISTRY FUNCTIONALITY BELOW:
        [LibraryImport("vmm", EntryPoint = "VMMDLL_WinReg_HiveList")]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static unsafe partial bool VMMDLL_WinReg_HiveList(
            IntPtr hVMM,
            byte* pHives,
            uint cHives,
            out uint pcHives);

        [LibraryImport("vmm", EntryPoint = "VMMDLL_WinReg_HiveReadEx")]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static unsafe partial bool VMMDLL_WinReg_HiveReadEx(
            IntPtr hVMM,
            ulong vaCMHive,
            uint ra,
            byte* pb,
            uint cb,
            out uint pcbReadOpt,
            uint flags);

        [LibraryImport("vmm", EntryPoint = "VMMDLL_WinReg_HiveWrite")]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static unsafe partial bool VMMDLL_WinReg_HiveWrite(
            IntPtr hVMM,
            ulong vaCMHive,
            uint ra,
            byte* pb,
            uint cb);

        [LibraryImport("vmm", EntryPoint = "VMMDLL_WinReg_EnumKeyExU")]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static unsafe partial bool VMMDLL_WinReg_EnumKeyEx(
            IntPtr hVMM,
            [MarshalAs(UnmanagedType.LPUTF8Str)] string uszFullPathKey,
            uint dwIndex,
            byte* lpName,
            ref uint lpcchName,
            out ulong lpftLastWriteTime);

        [LibraryImport("vmm", EntryPoint = "VMMDLL_WinReg_EnumValueU")]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static unsafe partial bool VMMDLL_WinReg_EnumValue(
            IntPtr hVMM,
            [MarshalAs(UnmanagedType.LPUTF8Str)] string uszFullPathKey,
            uint dwIndex,
            byte* lpValueName,
            ref uint lpcchValueName,
            out uint lpType,
            byte* lpData,
            ref uint lpcbData);

        [LibraryImport("vmm", EntryPoint = "VMMDLL_WinReg_QueryValueExU")]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static unsafe partial bool VMMDLL_WinReg_QueryValueEx(
            IntPtr hVMM,
            [MarshalAs(UnmanagedType.LPUTF8Str)] string uszFullPathKeyValue,
            out uint lpType,
            byte* lpData,
            ref uint lpcbData);

        // MEMORY SEARCH FUNCTIONALITY BELOW:

#pragma warning disable SYSLIB1054
        [RequiresDynamicCode("This P/Invoke was not able to be converted to LibraryImport")]
        [DllImport("vmm", EntryPoint = "VMMDLL_MemSearch")]
        internal static extern unsafe bool VMMDLL_MemSearch(
            IntPtr hVMM,
            uint dwPID,
            ref VMMDLL_MEM_SEARCH_CONTEXT ctx,
            out IntPtr ppva,
            out uint pcva);

        [RequiresDynamicCode("This P/Invoke was not able to be converted to LibraryImport")]
        [DllImport("vmm", EntryPoint = "VMMDLL_MemSearch")]
        internal static extern unsafe bool VMMDLL_MemSearch2(
            IntPtr hVMM,
            uint dwPID,
            IntPtr ctx,
            IntPtr ppva,
            IntPtr pcva);

        [RequiresDynamicCode("This P/Invoke was not able to be converted to LibraryImport")]
        [DllImport("vmm", EntryPoint = "VMMDLL_YaraSearch")]
        internal static extern unsafe bool VMMDLL_YaraSearch(
            IntPtr hVMM,
            uint dwPID,
            ref VMMDLL_YARA_CONFIG pYaraConfig,
            IntPtr ppva,
            IntPtr pcva);

        [RequiresDynamicCode("This P/Invoke was not able to be converted to LibraryImport")]
        [DllImport("vmm", EntryPoint = "VMMDLL_YaraSearch")]
        internal static extern unsafe bool VMMDLL_YaraSearch2(
            IntPtr hVMM,
            uint dwPID,
            IntPtr pYaraConfig,
            IntPtr ppva,
            IntPtr pcva);
#pragma warning restore SYSLIB1054

        [LibraryImport("vmm", EntryPoint = "VMMDLL_UtilFillHexAscii")]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static unsafe partial bool VMMDLL_UtilFillHexAscii(
            byte* pb,
            uint cb,
            uint cbInitialOffset,
            byte* sz,
            ref uint pcsz);

        [LibraryImport("vmm", EntryPoint = "VMMDLL_Log")]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static unsafe partial bool VMMDLL_Log(
            IntPtr hVMM,
            uint MID,
            uint dwLogLevel,
            [MarshalAs(UnmanagedType.LPStr)] string uszFormat,
            [MarshalAs(UnmanagedType.LPUTF8Str)] string uszTextToLog);

#else

        [DllImport("vmm", EntryPoint = "VMMDLL_InitializeEx")]
        internal static extern IntPtr VMMDLL_InitializeEx(
            int argc,
            string[] argv,
            out IntPtr ppLcErrorInfo);

        [DllImport("vmm", EntryPoint = "VMMDLL_CloseAll")]
        public static extern void VMMDLL_CloseAll();

        [DllImport("vmm", EntryPoint = "VMMDLL_Close")]
        public static extern void VMMDLL_Close(
            IntPtr hVMM);

        [DllImport("vmm", EntryPoint = "VMMDLL_ConfigGet")]
        public static extern bool VMMDLL_ConfigGet(
            IntPtr hVMM,
            ulong fOption,
            out ulong pqwValue);

        [DllImport("vmm", EntryPoint = "VMMDLL_ConfigSet")]
        public static extern bool VMMDLL_ConfigSet(
            IntPtr hVMM,
            ulong fOption,
            ulong qwValue);

        [DllImport("vmm", EntryPoint = "VMMDLL_MemFree")]
        internal static extern unsafe void VMMDLL_MemFree(
            byte* pvMem);

        // VFS (VIRTUAL FILE SYSTEM) FUNCTIONALITY BELOW:

        [DllImport("vmm", EntryPoint = VMMDLL_VfsListX)]
        internal static extern unsafe bool VMMDLL_VfsList(
            IntPtr hVMM,
            [MarshalAs(VmmString)] string wcsPath,
            ref VMMDLL_VFS_FILELIST pFileList);

        [DllImport("vmm", EntryPoint = VMMDLL_VfsReadX)]
        internal static extern unsafe uint VMMDLL_VfsRead(
            IntPtr hVMM,
            [MarshalAs(VmmString)] string wcsFileName,
            byte* pb,
            uint cb,
            out uint pcbRead,
            ulong cbOffset);

        [DllImport("vmm", EntryPoint = VMMDLL_VfsWriteX)]
        internal static extern unsafe uint VMMDLL_VfsWrite(
            IntPtr hVMM,
            [MarshalAs(VmmString)] string wcsFileName,
            byte* pb,
            uint cb,
            out uint pcbRead,
            ulong cbOffset);

        // PLUGIN FUNCTIONALITY BELOW:

        [DllImport("vmm", EntryPoint = "VMMDLL_InitializePlugins")]
        public static extern bool VMMDLL_InitializePlugins(IntPtr hVMM);

        // MEMORY READ/WRITE FUNCTIONALITY BELOW:

        [DllImport("vmm", EntryPoint = "VMMDLL_MemReadScatter")]
        internal static extern unsafe uint VMMDLL_MemReadScatter(
            IntPtr hVMM,
            uint dwPID,
            IntPtr ppMEMs,
            uint cpMEMs,
            uint flags);

        [DllImport("vmm", EntryPoint = "VMMDLL_MemReadEx")]
        internal static extern unsafe bool VMMDLL_MemReadEx(
            IntPtr hVMM,
            uint dwPID,
            ulong qwA,
            byte* pb,
            uint cb,
            out uint pcbReadOpt,
            uint flags);

        [DllImport("vmm", EntryPoint = "VMMDLL_MemPrefetchPages")]
        internal static extern unsafe bool VMMDLL_MemPrefetchPages(
            IntPtr hVMM,
            uint dwPID,
            byte* pPrefetchAddresses,
            uint cPrefetchAddresses);

        [DllImport("vmm", EntryPoint = "VMMDLL_MemWrite")]
        internal static extern unsafe bool VMMDLL_MemWrite(
            IntPtr hVMM,
            uint dwPID,
            ulong qwA,
            byte* pb,
            uint cb);

        [DllImport("vmm", EntryPoint = "VMMDLL_MemVirt2Phys")]
        public static extern bool VMMDLL_MemVirt2Phys(
            IntPtr hVMM,
            uint dwPID,
            ulong qwVA,
            out ulong pqwPA
            );

        // MEMORY NEW SCATTER READ/WRITE FUNCTIONALITY BELOW:

        [DllImport("vmm", EntryPoint = "VMMDLL_Scatter_Initialize")]
        internal static extern unsafe IntPtr VMMDLL_Scatter_Initialize(
            IntPtr hVMM,
            uint dwPID,
            uint flags);

        [DllImport("vmm", EntryPoint = "VMMDLL_Scatter_Prepare")]
        internal static extern unsafe bool VMMDLL_Scatter_Prepare(
            IntPtr hS,
            ulong va,
            uint cb);

        [DllImport("vmm", EntryPoint = "VMMDLL_Scatter_PrepareWrite")]
        internal static extern unsafe bool VMMDLL_Scatter_PrepareWrite(
            IntPtr hS,
            ulong va,
            byte* pb,
            uint cb);

        [DllImport("vmm", EntryPoint = "VMMDLL_Scatter_ExecuteRead")]
        internal static extern unsafe bool VMMDLL_Scatter_ExecuteRead(
            IntPtr hS);

        [DllImport("vmm", EntryPoint = "VMMDLL_Scatter_Execute")]
        internal static extern unsafe bool VMMDLL_Scatter_Execute(
            IntPtr hS);

        [DllImport("vmm", EntryPoint = "VMMDLL_Scatter_Read")]
        internal static extern unsafe bool VMMDLL_Scatter_Read(
            IntPtr hS,
            ulong va,
            uint cb,
            byte* pb,
            out uint pcbRead);

        [DllImport("vmm", EntryPoint = "VMMDLL_Scatter_Clear")]
        public static extern bool SVMMDLL_Scatter_Clear(IntPtr hS, uint dwPID, uint flags);

        [DllImport("vmm", EntryPoint = "VMMDLL_Scatter_Clear")]
        internal static extern unsafe bool VMMDLL_Scatter_Clear(
            IntPtr hS,
            uint dwPID,
            uint flags);

        [DllImport("vmm", EntryPoint = "VMMDLL_Scatter_CloseHandle")]
        internal static extern unsafe void VMMDLL_Scatter_CloseHandle(
            IntPtr hS);

        // PROCESS FUNCTIONALITY BELOW:

        [DllImport("vmm", EntryPoint = "VMMDLL_PidList")]
        internal static extern unsafe bool VMMDLL_PidList(IntPtr hVMM, byte* pPIDs, ref ulong pcPIDs);

        [DllImport("vmm", EntryPoint = "VMMDLL_PidGetFromName")]
        public static extern bool VMMDLL_PidGetFromName(IntPtr hVMM, [MarshalAs(UnmanagedType.LPStr)] string szProcName, out uint pdwPID);

        [DllImport("vmm", EntryPoint = VMMDLL_ProcessGetProcAddressX)]
        public static extern ulong VMMDLL_ProcessGetProcAddress(IntPtr hVMM, uint pid, [MarshalAs(VmmString)] string uszModuleName, [MarshalAs(UnmanagedType.LPStr)] string szFunctionName);

        [DllImport("vmm", EntryPoint = VMMDLL_ProcessGetModuleBaseX)]
        public static extern ulong VMMDLL_ProcessGetModuleBase(IntPtr hVMM, uint pid, [MarshalAs(VmmString)] string uszModuleName);

        [DllImport("vmm", EntryPoint = "VMMDLL_ProcessGetInformation")]
        internal static extern unsafe bool VMMDLL_ProcessGetInformation(
            IntPtr hVMM,
            uint dwPID,
            byte* pProcessInformation,
            ref ulong pcbProcessInformation);

        [DllImport("vmm", EntryPoint = "VMMDLL_ProcessGetInformationString")]
        internal static extern unsafe byte* VMMDLL_ProcessGetInformationString(
            IntPtr hVMM,
            uint dwPID,
            uint fOptionString);

        [DllImport("vmm", EntryPoint = VMMDLL_ProcessGetDirectoriesX)]
        internal static extern unsafe bool VMMDLL_ProcessGetDirectories(
            IntPtr hVMM,
            uint dwPID,
            [MarshalAs(VmmString)] string uszModule,
            byte* pData);

        [DllImport("vmm", EntryPoint = VMMDLL_ProcessGetSectionsX)]
        internal static extern unsafe bool VMMDLL_ProcessGetSections(
            IntPtr hVMM,
            uint dwPID,
            [MarshalAs(VmmString)] string uszModule,
            byte* pData,
            uint cData,
            out uint pcData);

        // WINDOWS SPECIFIC DEBUGGING / SYMBOL FUNCTIONALITY BELOW:

        [DllImport("vmm", EntryPoint = "VMMDLL_PdbLoad")]
        internal static extern unsafe bool VMMDLL_PdbLoad(
            IntPtr hVMM,
            uint dwPID,
            ulong vaModuleBase,
            byte* pModuleMapEntry);

        [DllImport("vmm", EntryPoint = "VMMDLL_PdbSymbolName")]
        internal static extern unsafe bool VMMDLL_PdbSymbolName(
            IntPtr hVMM,
            [MarshalAs(UnmanagedType.LPStr)] string szModule,
            ulong cbSymbolAddressOrOffset,
            byte* szSymbolName,
            out uint pdwSymbolDisplacement);

        [DllImport("vmm", EntryPoint = "VMMDLL_PdbSymbolAddress")]
        public static extern bool VMMDLL_PdbSymbolAddress(
            IntPtr hVMM,
            [MarshalAs(UnmanagedType.LPStr)] string szModule,
            [MarshalAs(UnmanagedType.LPStr)] string szSymbolName,
            out ulong pvaSymbolAddress);

        [DllImport("vmm", EntryPoint = "VMMDLL_PdbTypeSize")]
        public static extern bool VMMDLL_PdbTypeSize(
            IntPtr hVMM,
            [MarshalAs(UnmanagedType.LPStr)] string szModule,
            [MarshalAs(UnmanagedType.LPStr)] string szTypeName,
            out uint pcbTypeSize);

        [DllImport("vmm", EntryPoint = "VMMDLL_PdbTypeChildOffset")]
        public static extern bool VMMDLL_PdbTypeChildOffset(
            IntPtr hVMM,
            [MarshalAs(UnmanagedType.LPStr)] string szModule,
            [MarshalAs(UnmanagedType.LPStr)] string szTypeName,
            [MarshalAs(UnmanagedType.LPStr)] string wszTypeChildName,
            out uint pcbTypeChildOffset);

        // VMMDLL_Map_GetPte
        [DllImport("vmm", EntryPoint = VMMDLL_Map_GetPteX)]
        internal static extern unsafe bool VMMDLL_Map_GetPte(
            IntPtr hVMM,
            uint dwPid,
            bool fIdentifyModules,
            out IntPtr ppPteMap);

        // VMMDLL_Map_GetVad
        [DllImport("vmm", EntryPoint = VMMDLL_Map_GetVadX)]
        internal static extern unsafe bool VMMDLL_Map_GetVad(
            IntPtr hVMM,
            uint dwPid,
            bool fIdentifyModules,
            out IntPtr ppVadMap);

        // VMMDLL_Map_GetVadEx
        [DllImport("vmm", EntryPoint = "VMMDLL_Map_GetVadEx")]
        internal static extern unsafe bool VMMDLL_Map_GetVadEx(
            IntPtr hVMM,
            uint dwPid,
            uint oPage,
            uint cPage,
            out IntPtr ppVadExMap);

        // VMMDLL_Map_GetModule
        [DllImport("vmm", EntryPoint = VMMDLL_Map_GetModuleX)]
        internal static extern unsafe bool VMMDLL_Map_GetModule(
            IntPtr hVMM,
            uint dwPid,
            out IntPtr ppModuleMap,
            uint flags);

        // VMMDLL_Map_GetModuleFromName
        [DllImport("vmm", EntryPoint = VMMDLL_Map_GetModuleFromNameX)]
        internal static extern unsafe bool VMMDLL_Map_GetModuleFromName(
            IntPtr hVMM,
            uint dwPID,
            [MarshalAs(VmmString)] string uszModuleName,
            out IntPtr ppModuleMapEntry,
            uint flags);

        // VMMDLL_Map_GetUnloadedModule
        [DllImport("vmm", EntryPoint = VMMDLL_Map_GetUnloadedModuleX)]
        internal static extern unsafe bool VMMDLL_Map_GetUnloadedModule(
            IntPtr hVMM,
            uint dwPid,
            out IntPtr ppModuleMap);

        // VMMDLL_Map_GetEAT
        [DllImport("vmm", EntryPoint = VMMDLL_Map_GetEATX)]
        internal static extern unsafe bool VMMDLL_Map_GetEAT(
            IntPtr hVMM,
            uint dwPid,
            [MarshalAs(VmmString)] string uszModuleName,
            out IntPtr ppEatMap);

        // VMMDLL_Map_GetIAT
        [DllImport("vmm", EntryPoint = VMMDLL_Map_GetIATX)]
        internal static extern unsafe bool VMMDLL_Map_GetIAT(
            IntPtr hVMM,
            uint dwPid,
            [MarshalAs(VmmString)] string uszModuleName,
            out IntPtr ppIatMap);

        // VMMDLL_Map_GetHeap
        [DllImport("vmm", EntryPoint = "VMMDLL_Map_GetHeap")]
        internal static extern unsafe bool VMMDLL_Map_GetHeap(
            IntPtr hVMM,
            uint dwPid,
            out IntPtr ppHeapMap);

        // VMMDLL_Map_GetHeapAlloc
        [DllImport("vmm", EntryPoint = "VMMDLL_Map_GetHeapAlloc")]
        internal static extern unsafe bool VMMDLL_Map_GetHeapAlloc(
            IntPtr hVMM,
            uint dwPid,
            ulong qwHeapNumOrAddress,
            out IntPtr ppHeapAllocMap);

        // VMMDLL_Map_GetThread
        [DllImport("vmm", EntryPoint = "VMMDLL_Map_GetThread")]
        internal static extern unsafe bool VMMDLL_Map_GetThread(
            IntPtr hVMM,
            uint dwPid,
            out IntPtr ppThreadMap);

        // VMMDLL_Map_GetThread_Callstack
        [DllImport("vmm", EntryPoint = VMMDLL_Map_GetThread_CallstackX)]
        internal static extern unsafe bool VMMDLL_Map_GetThread_Callstack(
            IntPtr hVMM,
            uint dwPID,
            uint dwTID,
            uint flags,
            out IntPtr ppThreadCallstack);

        // VMMDLL_Map_GetHandle
        [DllImport("vmm", EntryPoint = VMMDLL_Map_GetHandleX)]
        internal static extern unsafe bool VMMDLL_Map_GetHandle(
            IntPtr hVMM,
            uint dwPid,
            out IntPtr ppHandleMap);

        // VMMDLL_Map_GetNet
        [DllImport("vmm", EntryPoint = VMMDLL_Map_GetNetX)]
        internal static extern unsafe bool VMMDLL_Map_GetNet(
            IntPtr hVMM,
            out IntPtr ppNetMap);

        // VMMDLL_Map_GetPhysMem
        [DllImport("vmm", EntryPoint = "VMMDLL_Map_GetPhysMem")]
        internal static extern unsafe bool VMMDLL_Map_GetPhysMem(
            IntPtr hVMM,
            out IntPtr ppPhysMemMap);

        // VMMDLL_Map_GetKDevice
        [DllImport("vmm", EntryPoint = VMMDLL_Map_GetKDeviceX)]
        internal static extern unsafe bool VMMDLL_Map_GetKDevice(
            IntPtr hVMM,
            out IntPtr ppKDeviceMap);

        // VMMDLL_Map_GetKDriver
        [DllImport("vmm", EntryPoint = VMMDLL_Map_GetKDriverX)]
        internal static extern unsafe bool VMMDLL_Map_GetKDriver(
            IntPtr hVMM,
            out IntPtr ppKDriverMap);

        // VMMDLL_Map_GetKObject
        [DllImport("vmm", EntryPoint = VMMDLL_Map_GetKObjectX)]
        internal static extern unsafe bool VMMDLL_Map_GetKObject(
            IntPtr hVMM,
            out IntPtr ppKObjectMap);

        // VMMDLL_Map_GetPool
        [DllImport("vmm", EntryPoint = "VMMDLL_Map_GetPool")]
        internal static extern unsafe bool VMMDLL_Map_GetPool(
            IntPtr hVMM,
            out IntPtr ppHeapAllocMap,
            uint flags);

        // VMMDLL_Map_GetUsers
        [DllImport("vmm", EntryPoint = VMMDLL_Map_GetUsersX)]
        internal static extern unsafe bool VMMDLL_Map_GetUsers(
            IntPtr hVMM,
            out IntPtr ppUserMap);

        // VMMDLL_Map_GetVM
        [DllImport("vmm", EntryPoint = VMMDLL_Map_GetVMX)]
        internal static extern unsafe bool VMMDLL_Map_GetVM(
            IntPtr hVMM,
            out IntPtr ppUserMap);

        // VMMDLL_Map_GetServuces
        [DllImport("vmm", EntryPoint = VMMDLL_Map_GetServicesX)]
        internal static extern unsafe bool VMMDLL_Map_GetServices(
            IntPtr hVMM,
            out IntPtr ppServiceMap);

        // VMMDLL_Map_GetPfn
        [DllImport("vmm", EntryPoint = "VMMDLL_Map_GetPfn")]
        internal static extern unsafe bool VMMDLL_Map_GetPfn(
            IntPtr hVMM,
            byte* pPfns,
            uint cPfns,
            byte* pPfnMap,
            ref uint pcbPfnMap);

        // REGISTRY FUNCTIONALITY BELOW:

        [DllImport("vmm", EntryPoint = "VMMDLL_WinReg_HiveList")]
        internal static extern unsafe bool VMMDLL_WinReg_HiveList(
            IntPtr hVMM,
            byte* pHives,
            uint cHives,
            out uint pcHives);

        [DllImport("vmm", EntryPoint = "VMMDLL_WinReg_HiveReadEx")]
        internal static extern unsafe bool VMMDLL_WinReg_HiveReadEx(
            IntPtr hVMM,
            ulong vaCMHive,
            uint ra,
            byte* pb,
            uint cb,
            out uint pcbReadOpt,
            uint flags);

        [DllImport("vmm", EntryPoint = "VMMDLL_WinReg_HiveWrite")]
        internal static extern unsafe bool VMMDLL_WinReg_HiveWrite(
            IntPtr hVMM,
            ulong vaCMHive,
            uint ra,
            byte* pb,
            uint cb);

        [DllImport("vmm", EntryPoint = VMMDLL_WinReg_EnumKeyExX)]
        internal static extern unsafe bool VMMDLL_WinReg_EnumKeyEx(
            IntPtr hVMM,
            [MarshalAs(VmmString)] string uszFullPathKey,
            uint dwIndex,
            byte* lpName,
            ref uint lpcchName,
            out ulong lpftLastWriteTime);

        [DllImport("vmm", EntryPoint = VMMDLL_WinReg_EnumValueX)]
        internal static extern unsafe bool VMMDLL_WinReg_EnumValue(
            IntPtr hVMM,
            [MarshalAs(VmmString)] string uszFullPathKey,
            uint dwIndex,
            byte* lpValueName,
            ref uint lpcchValueName,
            out uint lpType,
            byte* lpData,
            ref uint lpcbData);

        [DllImport("vmm", EntryPoint = VMMDLL_WinReg_QueryValueExX)]
        internal static extern unsafe bool VMMDLL_WinReg_QueryValueEx(
            IntPtr hVMM,
            [MarshalAs(VmmString)] string uszFullPathKeyValue,
            out uint lpType,
            byte* lpData,
            ref uint lpcbData);

        // MEMORY SEARCH FUNCTIONALITY BELOW:

        [DllImport("vmm", EntryPoint = "VMMDLL_MemSearch")]
        internal static extern unsafe bool VMMDLL_MemSearch(
            IntPtr hVMM,
            uint dwPID,
            ref VMMDLL_MEM_SEARCH_CONTEXT ctx,
            out IntPtr ppva,
            out uint pcva);

        [DllImport("vmm", EntryPoint = "VMMDLL_MemSearch")]
        internal static extern unsafe bool VMMDLL_MemSearch2(
            IntPtr hVMM,
            uint dwPID,
            IntPtr ctx,
            IntPtr ppva,
            IntPtr pcva);

        [DllImport("vmm", EntryPoint = "VMMDLL_YaraSearch")]
        internal static extern unsafe bool VMMDLL_YaraSearch(
            IntPtr hVMM,
            uint dwPID,
            ref VMMDLL_YARA_CONFIG pYaraConfig,
            IntPtr ppva,
            IntPtr pcva);

        [DllImport("vmm", EntryPoint = "VMMDLL_YaraSearch")]
        internal static extern unsafe bool VMMDLL_YaraSearch2(
            IntPtr hVMM,
            uint dwPID,
            IntPtr pYaraConfig,
            IntPtr ppva,
            IntPtr pcva);

        [DllImport("vmm", EntryPoint = "VMMDLL_UtilFillHexAscii")]
        internal static extern unsafe bool VMMDLL_UtilFillHexAscii(
            byte* pb,
            uint cb,
            uint cbInitialOffset,
            byte* sz,
            ref uint pcsz);

        [DllImport("vmm", EntryPoint = "VMMDLL_Log")]
        internal static extern unsafe bool VMMDLL_Log(
            IntPtr hVMM,
            uint MID,
            uint dwLogLevel,
            [MarshalAs(UnmanagedType.LPStr)] string uszFormat,
            [MarshalAs(VmmString)] string uszTextToLog);

#endif

        #endregion

        #region Memory read/write helper functionality

        internal static unsafe LeechCore.MemScatter[] MemReadScatter(IntPtr hVMM, uint pid, uint flags, params ulong[] qwA)
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
            LeechCore.MemScatter[] MEMs = new LeechCore.MemScatter[qwA.Length];
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
        internal static unsafe LeechCore.SCATTER_HANDLE MemReadScatter2(IntPtr hVMM, uint pid, uint flags, params ulong[] qwA)
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

        internal static VmmScatterMemory Scatter_Initialize(IntPtr hVMM, uint pid, uint flags)
        {
            IntPtr hS = Vmmi.VMMDLL_Scatter_Initialize(hVMM, pid, flags);
            if (hS.ToInt64() == 0) { return null; }
            return new VmmScatterMemory(hS, pid);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static unsafe byte[] MemRead(IntPtr hVMM, uint pid, ulong qwA, uint cb, uint flags = 0) =>
            MemReadArray<byte>(hVMM, pid, qwA, cb, flags);

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static unsafe bool MemRead(IntPtr hVMM, uint pid, ulong qwA, IntPtr pb, uint cb, out uint cbRead, uint flags = 0) =>
            MemRead(hVMM, pid, qwA, pb.ToPointer(), cb, out cbRead, flags);

        internal static unsafe bool MemRead(IntPtr hVMM, uint pid, ulong qwA, void* pb, uint cb, out uint cbRead, uint flags = 0)
        {
            return Vmmi.VMMDLL_MemReadEx(hVMM, pid, qwA, (byte*)pb, cb, out cbRead, flags);
        }

        internal static unsafe T? MemReadAs<T>(IntPtr hVMM, uint pid, ulong qwA, uint flags = 0)
            where T : unmanaged
        {
            uint cb = (uint)sizeof(T);
            T result = default;
            if (!Vmmi.VMMDLL_MemReadEx(hVMM, pid, qwA, (byte*)&result, cb, out uint cbRead, flags) ||
                cbRead != cb)
                return null;
            return result;
        }

        internal static unsafe T[] MemReadArray<T>(IntPtr hVMM, uint pid, ulong qwA, uint count, uint flags = 0)
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
        internal static unsafe bool MemReadSpan<T>(IntPtr hVMM, uint pid, ulong addr, Span<T> span, out uint cbRead, uint flags)
            where T : unmanaged
        {
            uint cb = (uint)(sizeof(T) * span.Length);
            fixed (T* pb = span)
            {
                return Vmmi.VMMDLL_MemReadEx(hVMM, pid, addr, (byte*)pb, cb, out cbRead, flags);
            }
        }

        internal static unsafe bool MemWriteSpan<T>(IntPtr hVMM, uint pid, ulong addr, Span<T> span)
            where T : unmanaged
        {
            uint cb = (uint)(sizeof(T) * span.Length);
            fixed (T* pb = span)
            {
                return Vmmi.VMMDLL_MemWrite(hVMM, pid, addr, (byte*)pb, cb);
            }
        }
#endif

        internal static unsafe string MemReadString(IntPtr hVMM, Encoding encoding, uint pid, ulong qwA, uint cb,
            uint flags = 0, bool terminateOnNullChar = true)
        {
            byte[] buffer = MemRead(hVMM, pid, qwA, cb, flags);
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

        internal static unsafe bool MemPrefetchPages(IntPtr hVMM, uint pid, ulong[] qwA)
        {
            byte[] data = new byte[qwA.Length * sizeof(ulong)];
            System.Buffer.BlockCopy(qwA, 0, data, 0, data.Length);
            fixed (byte* pb = data)
            {
                return Vmmi.VMMDLL_MemPrefetchPages(hVMM, pid, pb, (uint)qwA.Length);
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static unsafe bool MemWrite(IntPtr hVMM, uint pid, ulong qwA, byte[] data) =>
            MemWriteArray<byte>(hVMM, pid, qwA, data);

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static unsafe bool MemWrite(IntPtr hVMM, uint pid, ulong qwA, IntPtr pb, uint cb) =>
            MemWrite(hVMM, pid, qwA, pb.ToPointer(), cb);

        internal static unsafe bool MemWrite(IntPtr hVMM, uint pid, ulong qwA, void* pb, uint cb) =>
            Vmmi.VMMDLL_MemWrite(hVMM, pid, qwA, (byte*)pb, cb);

        internal static unsafe bool MemWriteStruct<T>(IntPtr hVMM, uint pid, ulong qwA, T value)
            where T : unmanaged
        {
            uint cb = (uint)sizeof(T);
            return Vmmi.VMMDLL_MemWrite(hVMM, pid, qwA, (byte*)&value, cb);
        }

        internal static unsafe bool MemWriteArray<T>(IntPtr hVMM, uint pid, ulong qwA, T[] data)
            where T : unmanaged
        {
            uint cb = (uint)sizeof(T) * (uint)data.Length;
            fixed (T* pb = data)
            {
                return Vmmi.VMMDLL_MemWrite(hVMM, pid, qwA, (byte*)pb, cb);
            }
        }

        internal static bool MemVirt2Phys(IntPtr hVMM, uint pid, ulong qwVA, out ulong pqwPA)
        {
            return Vmmi.VMMDLL_MemVirt2Phys(hVMM, pid, qwVA, out pqwPA);
        }

        #endregion

    }
}
