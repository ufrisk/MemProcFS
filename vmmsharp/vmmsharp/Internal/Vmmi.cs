using System;
using System.Runtime.InteropServices;

namespace Vmmsharp.Internal
{
    internal static class Vmmi
    {
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
        internal const uint VMMDLL_MAP_HANDLE_VERSION = 3;
        internal const uint VMMDLL_MAP_NET_VERSION = 3;
        internal const uint VMMDLL_MAP_PHYSMEM_VERSION = 2;
        internal const uint VMMDLL_MAP_POOL_VERSION = 2;
        internal const uint VMMDLL_MAP_USER_VERSION = 2;
        internal const uint VMMDLL_MAP_PFN_VERSION = 1;
        internal const uint VMMDLL_MAP_SERVICE_VERSION = 3;
        internal const uint VMMDLL_MEM_SEARCH_VERSION = 0xfe3e0002;
        internal const uint VMMDLL_REGISTRY_HIVE_INFORMATION_VERSION = 4;



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

        [DllImport("vmm", EntryPoint = "VMMDLL_VfsListU")]
        internal static extern unsafe bool VMMDLL_VfsList(
            IntPtr hVMM,
            [MarshalAs(UnmanagedType.LPUTF8Str)] string wcsPath,
            ref VMMDLL_VFS_FILELIST pFileList);

        [DllImport("vmm", EntryPoint = "VMMDLL_VfsReadU")]
        internal static extern unsafe uint VMMDLL_VfsRead(
            IntPtr hVMM,
            [MarshalAs(UnmanagedType.LPUTF8Str)] string wcsFileName,
            byte* pb,
            uint cb,
            out uint pcbRead,
            ulong cbOffset);

        [DllImport("vmm", EntryPoint = "VMMDLL_VfsWriteU")]
        internal static extern unsafe uint VMMDLL_VfsWrite(
            IntPtr hVMM,
            [MarshalAs(UnmanagedType.LPUTF8Str)] string wcsFileName,
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

        [DllImport("vmm", EntryPoint = "VMMDLL_ProcessGetProcAddressW")]
        public static extern ulong VMMDLL_ProcessGetProcAddress(IntPtr hVMM, uint pid, [MarshalAs(UnmanagedType.LPWStr)] string wszModuleName, [MarshalAs(UnmanagedType.LPStr)] string szFunctionName);

        [DllImport("vmm", EntryPoint = "VMMDLL_ProcessGetModuleBaseW")]
        public static extern ulong VMMDLL_ProcessGetModuleBase(IntPtr hVMM, uint pid, [MarshalAs(UnmanagedType.LPWStr)] string wszModuleName);

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

        [DllImport("vmm", EntryPoint = "VMMDLL_ProcessGetDirectoriesW")]
        internal static extern unsafe bool VMMDLL_ProcessGetDirectories(
            IntPtr hVMM,
            uint dwPID,
            [MarshalAs(UnmanagedType.LPWStr)] string wszModule,
            byte* pData);

        [DllImport("vmm", EntryPoint = "VMMDLL_ProcessGetSectionsW")]
        internal static extern unsafe bool VMMDLL_ProcessGetSections(
            IntPtr hVMM,
            uint dwPID,
            [MarshalAs(UnmanagedType.LPWStr)] string wszModule,
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

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential)]
        internal struct VMMDLL_MAP_PTEENTRY
        {
            internal ulong vaBase;
            internal ulong cPages;
            internal ulong fPage;
            internal bool fWoW64;
            internal uint _FutureUse1;
            [MarshalAs(UnmanagedType.LPWStr)] internal string wszText;
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

        [DllImport("vmm", EntryPoint = "VMMDLL_Map_GetPteW")]
        internal static extern unsafe bool VMMDLL_Map_GetPte(
            IntPtr hVMM,
            uint dwPid,
            bool fIdentifyModules,
            out IntPtr ppPteMap);



        // VMMDLL_Map_GetVad

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
            [MarshalAs(UnmanagedType.LPWStr)] internal string wszText;
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

        [DllImport("vmm", EntryPoint = "VMMDLL_Map_GetVadW")]
        internal static extern unsafe bool VMMDLL_Map_GetVad(
            IntPtr hVMM,
            uint dwPid,
            bool fIdentifyModules,
            out IntPtr ppVadMap);



        // VMMDLL_Map_GetVadEx

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

        [DllImport("vmm", EntryPoint = "VMMDLL_Map_GetVadEx")]
        internal static extern unsafe bool VMMDLL_Map_GetVadEx(
            IntPtr hVMM,
            uint dwPid,
            uint oPage,
            uint cPage,
            out IntPtr ppVadExMap);



        // VMMDLL_Map_GetModule
        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential)]
        internal struct VMMDLL_MAP_MODULEENTRY_DEBUGINFO
        {
            internal uint dwAge;
            internal uint _Reserved;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)] internal byte[] Guid;
            [MarshalAs(UnmanagedType.LPWStr)] internal string wszGuid;
            [MarshalAs(UnmanagedType.LPWStr)] internal string wszPdbFilename;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential)]
        internal struct VMMDLL_MAP_MODULEENTRY_VERSIONINFO
        {
            [MarshalAs(UnmanagedType.LPWStr)] internal string wszCompanyName;
            [MarshalAs(UnmanagedType.LPWStr)] internal string wszFileDescription;
            [MarshalAs(UnmanagedType.LPWStr)] internal string wszFileVersion;
            [MarshalAs(UnmanagedType.LPWStr)] internal string wszInternalName;
            [MarshalAs(UnmanagedType.LPWStr)] internal string wszLegalCopyright;
            [MarshalAs(UnmanagedType.LPWStr)] internal string wszFileOriginalFilename;
            [MarshalAs(UnmanagedType.LPWStr)] internal string wszProductName;
            [MarshalAs(UnmanagedType.LPWStr)] internal string wszProductVersion;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential)]
        internal struct VMMDLL_MAP_MODULEENTRY
        {
            internal ulong vaBase;
            internal ulong vaEntry;
            internal uint cbImageSize;
            internal bool fWow64;
            [MarshalAs(UnmanagedType.LPWStr)] internal string wszText;
            internal uint _Reserved3;
            internal uint _Reserved4;
            [MarshalAs(UnmanagedType.LPWStr)] internal string wszFullName;
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

        internal struct VMMDLL_MAP_MODULE
        {
            internal uint dwVersion;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 5)] internal uint[] _Reserved1;
            internal ulong pbMultiText;
            internal uint cbMultiText;
            internal uint cMap;
        }

        [DllImport("vmm", EntryPoint = "VMMDLL_Map_GetModuleW")]
        internal static extern unsafe bool VMMDLL_Map_GetModule(
            IntPtr hVMM,
            uint dwPid,
            out IntPtr ppModuleMap,
            uint flags);

        // VMMDLL_Map_GetModuleFromName

        [DllImport("vmm", EntryPoint = "VMMDLL_Map_GetModuleFromNameW")]
        internal static extern unsafe bool VMMDLL_Map_GetModuleFromName(
            IntPtr hVMM,
            uint dwPID,
            [MarshalAs(UnmanagedType.LPWStr)] string wszModuleName,
            out IntPtr ppModuleMapEntry,
            uint flags);



        // VMMDLL_Map_GetUnloadedModule

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential)]
        internal struct VMMDLL_MAP_UNLOADEDMODULEENTRY
        {
            internal ulong vaBase;
            internal uint cbImageSize;
            internal bool fWow64;
            [MarshalAs(UnmanagedType.LPWStr)] internal string wszText;
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

        [DllImport("vmm", EntryPoint = "VMMDLL_Map_GetUnloadedModuleW")]
        internal static extern unsafe bool VMMDLL_Map_GetUnloadedModule(
            IntPtr hVMM,
            uint dwPid,
            out IntPtr ppModuleMap);



        // VMMDLL_Map_GetEAT

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential)]
        internal struct VMMDLL_MAP_EATENTRY
        {
            internal ulong vaFunction;
            internal uint dwOrdinal;
            internal uint oFunctionsArray;
            internal uint oNamesArray;
            internal uint _FutureUse1;
            [MarshalAs(UnmanagedType.LPWStr)] internal string wszFunction;
            [MarshalAs(UnmanagedType.LPWStr)] internal string wszForwardedFunction;
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

        [DllImport("vmm", EntryPoint = "VMMDLL_Map_GetEATW")]
        internal static extern unsafe bool VMMDLL_Map_GetEAT(
            IntPtr hVMM,
            uint dwPid,
            [MarshalAs(UnmanagedType.LPWStr)] string wszModuleName,
            out IntPtr ppEatMap);



        // VMMDLL_Map_GetIAT

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential)]
        internal struct VMMDLL_MAP_IATENTRY
        {
            internal ulong vaFunction;
            [MarshalAs(UnmanagedType.LPWStr)] internal string wszFunction;
            internal uint _FutureUse1;
            internal uint _FutureUse2;
            [MarshalAs(UnmanagedType.LPWStr)] internal string wszModule;
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

        [DllImport("vmm", EntryPoint = "VMMDLL_Map_GetIATW")]
        internal static extern unsafe bool VMMDLL_Map_GetIAT(
            IntPtr hVMM,
            uint dwPid,
            [MarshalAs(UnmanagedType.LPWStr)] string wszModuleName,
            out IntPtr ppIatMap);



        // VMMDLL_Map_GetHeap

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

        [DllImport("vmm", EntryPoint = "VMMDLL_Map_GetHeap")]
        internal static extern unsafe bool VMMDLL_Map_GetHeap(
            IntPtr hVMM,
            uint dwPid,
            out IntPtr ppHeapMap);



        // VMMDLL_Map_GetHeapAlloc

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

        [DllImport("vmm", EntryPoint = "VMMDLL_Map_GetHeapAlloc")]
        internal static extern unsafe bool VMMDLL_Map_GetHeapAlloc(
            IntPtr hVMM,
            uint dwPid,
            ulong qwHeapNumOrAddress,
            out IntPtr ppHeapAllocMap);



        // VMMDLL_Map_GetThread

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

        [DllImport("vmm", EntryPoint = "VMMDLL_Map_GetThread")]
        internal static extern unsafe bool VMMDLL_Map_GetThread(
            IntPtr hVMM,
            uint dwPid,
            out IntPtr ppThreadMap);



        // VMMDLL_Map_GetHandle

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
            [MarshalAs(UnmanagedType.LPWStr)] internal string wszText;
            internal uint _FutureUse2;
            internal uint dwPID;
            internal uint dwPoolTag;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 7)] internal uint[] _FutureUse;
            [MarshalAs(UnmanagedType.LPWStr)] internal string wszType;
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

        [DllImport("vmm", EntryPoint = "VMMDLL_Map_GetHandleW")]
        internal static extern unsafe bool VMMDLL_Map_GetHandle(
            IntPtr hVMM,
            uint dwPid,
            out IntPtr ppHandleMap);



        // VMMDLL_Map_GetNet

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
            [MarshalAs(UnmanagedType.LPWStr)] internal string src_wszText;
            // dst
            internal bool dst_fValid;
            internal ushort dst__Reserved1;
            internal ushort dst_port;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)] internal byte[] dst_pbAddr;
            [MarshalAs(UnmanagedType.LPWStr)] internal string dst_wszText;
            //
            internal ulong vaObj;
            internal ulong ftTime;
            internal uint dwPoolTag;
            internal uint _FutureUse4;
            [MarshalAs(UnmanagedType.LPWStr)] internal string wszText;
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

        [DllImport("vmm", EntryPoint = "VMMDLL_Map_GetNetW")]
        internal static extern unsafe bool VMMDLL_Map_GetNet(
            IntPtr hVMM,
            out IntPtr ppNetMap);



        // VMMDLL_Map_GetPhysMem

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

        [DllImport("vmm", EntryPoint = "VMMDLL_Map_GetPhysMem")]
        internal static extern unsafe bool VMMDLL_Map_GetPhysMem(
            IntPtr hVMM,
            out IntPtr ppPhysMemMap);



        // VMMDLL_Map_GetPool

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

        [DllImport("vmm", EntryPoint = "VMMDLL_Map_GetPool")]
        internal static extern unsafe bool VMMDLL_Map_GetPool(
            IntPtr hVMM,
            out IntPtr ppHeapAllocMap,
            uint flags);



        // VMMDLL_Map_GetUsers

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential, CharSet = CharSet.Ansi)]
        internal struct VMMDLL_MAP_USERENTRY
        {
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 2)] internal uint[] _FutureUse1;
            [MarshalAs(UnmanagedType.LPWStr)] internal string wszText;
            internal ulong vaRegHive;
            [MarshalAs(UnmanagedType.LPWStr)] internal string wszSID;
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

        [DllImport("vmm", EntryPoint = "VMMDLL_Map_GetUsersW")]
        internal static extern unsafe bool VMMDLL_Map_GetUsers(
            IntPtr hVMM,
            out IntPtr ppUserMap);



        // VMMDLL_Map_GetServuces

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
            [MarshalAs(UnmanagedType.LPWStr)] internal string wszServiceName;
            [MarshalAs(UnmanagedType.LPWStr)] internal string wszDisplayName;
            [MarshalAs(UnmanagedType.LPWStr)] internal string wszPath;
            [MarshalAs(UnmanagedType.LPWStr)] internal string wszUserTp;
            [MarshalAs(UnmanagedType.LPWStr)] internal string wszUserAcct;
            [MarshalAs(UnmanagedType.LPWStr)] internal string wszImagePath;
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

        [DllImport("vmm", EntryPoint = "VMMDLL_Map_GetServicesW")]
        internal static extern unsafe bool VMMDLL_Map_GetServices(
            IntPtr hVMM,
            out IntPtr ppServiceMap);



        // VMMDLL_Map_GetPfn

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

        [DllImport("vmm", EntryPoint = "VMMDLL_Map_GetPfn")]
        internal static extern unsafe bool VMMDLL_Map_GetPfn(
            IntPtr hVMM,
            byte* pPfns,
            uint cPfns,
            byte* pPfnMap,
            ref uint pcbPfnMap);



        // REGISTRY FUNCTIONALITY BELOW:

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

        [DllImport("vmm", EntryPoint = "VMMDLL_WinReg_EnumKeyExW")]
        internal static extern unsafe bool VMMDLL_WinReg_EnumKeyExW(
            IntPtr hVMM,
            [MarshalAs(UnmanagedType.LPWStr)] string wszFullPathKey,
            uint dwIndex,
            byte* lpName,
            ref uint lpcchName,
            out ulong lpftLastWriteTime);

        [DllImport("vmm", EntryPoint = "VMMDLL_WinReg_EnumValueW")]
        internal static extern unsafe bool VMMDLL_WinReg_EnumValueW(
            IntPtr hVMM,
            [MarshalAs(UnmanagedType.LPWStr)] string wszFullPathKey,
            uint dwIndex,
            byte* lpValueName,
            ref uint lpcchValueName,
            out uint lpType,
            byte* lpData,
            ref uint lpcbData);

        [DllImport("vmm", EntryPoint = "VMMDLL_WinReg_QueryValueExW")]
        internal static extern unsafe bool VMMDLL_WinReg_QueryValueExW(
            IntPtr hVMM,
            [MarshalAs(UnmanagedType.LPWStr)] string wszFullPathKeyValue,
            out uint lpType,
            byte* lpData,
            ref uint lpcbData);



        // MEMORY SEARCH FUNCTIONALITY BELOW:

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential)]
        internal struct VMMDLL_MEM_SEARCH_CONTEXT_SEARCHENTRY
        {
            internal uint cbAlign;
            internal uint cb;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)] internal byte[] pb;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)] internal byte[] pbSkipMask;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential)]
        internal struct VMMDLL_MEM_SEARCH_CONTEXT
        {
            internal uint dwVersion;
            internal uint _Filler01;
            internal uint _Filler02;
            internal bool fAbortRequested;
            internal uint cMaxResult;
            internal uint cSearch;
            [MarshalAs(UnmanagedType.ByValArray, ArraySubType = UnmanagedType.Struct, SizeConst = 16)] internal Vmmi.VMMDLL_MEM_SEARCH_CONTEXT_SEARCHENTRY[] search;
            internal ulong vaMin;
            internal ulong vaMax;
            internal ulong vaCurrent;
            internal uint _Filler2;
            internal uint cResult;
            internal ulong cbReadTotal;
            internal IntPtr pvUserPtrOpt;
            internal IntPtr pfnResultOptCB;
            internal ulong ReadFlags;
            internal bool fForcePTE;
            internal bool fForceVAD;
            internal IntPtr pfnFilterOptCB;
        }

        [DllImport("vmm", EntryPoint = "VMMDLL_MemSearch")]
        internal static extern unsafe bool VMMDLL_MemSearch(
            IntPtr hVMM,
            uint dwPID,
            ref VMMDLL_MEM_SEARCH_CONTEXT ctx,
            out IntPtr ppva,
            out uint pcva);

    }
}
