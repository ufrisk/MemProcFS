package vmm.internal;

import com.sun.jna.*;
import com.sun.jna.ptr.*;

import vmm.VmmException;

/**
 * JNA native code wrapper for MemProcFS.
 * @see https://github.com/ufrisk/MemProcFS
 * @author Ulf Frisk - pcileech@frizk.net
 */
interface VmmNative extends Library {
	static final int MAX_PATH						= 260;
	
	static final int VMMDLL_VFS_FILELIST_VERSION    			= 2;
	static final long MMDLL_PROCESS_INFORMATION_MAGIC 			= 0xc0ffee663df9301eL;
	static final short VMMDLL_PROCESS_INFORMATION_VERSION 		= 7;
	static final long VMMDLL_REGISTRY_HIVE_INFORMATION_MAGIC	= 0xc0ffee653df8d01eL;
	static final short VMMDLL_REGISTRY_HIVE_INFORMATION_VERSION = 3;
	
	static final int VMMDLL_MAP_PTE_VERSION 		= 2;
	static final int VMMDLL_MAP_VAD_VERSION 		= 6;
	static final int VMMDLL_MAP_VADEX_VERSION 		= 4;
	static final int VMMDLL_MAP_MODULE_VERSION 		= 6;
	static final int VMMDLL_MAP_UNLOADEDMODULE_VERSION = 2;
	static final int VMMDLL_MAP_EAT_VERSION 		= 3;
	static final int VMMDLL_MAP_IAT_VERSION 		= 2;
	static final int VMMDLL_MAP_HEAP_VERSION 		= 4;
	static final int VMMDLL_MAP_HEAPALLOC_VERSION 	= 1;
	static final int VMMDLL_MAP_THREAD_VERSION 		= 4;
	static final int VMMDLL_MAP_HANDLE_VERSION 		= 3;
	static final int VMMDLL_MAP_POOL_VERSION 		= 2;
	static final int VMMDLL_MAP_NET_VERSION 		= 3;
	static final int VMMDLL_MAP_PHYSMEM_VERSION 	= 2;
	static final int VMMDLL_MAP_USER_VERSION 		= 2;
	static final int VMMDLL_MAP_SERVICE_VERSION		= 3;
	
	static final int VMMDLL_POOLMAP_FLAG_ALL 		= 0;
	static final int VMMDLL_POOLMAP_FLAG_BIG 		= 1;
	
	
	
	VmmNative INSTANCE = Native.load("vmm", VmmNative.class);
	
	
	
	Pointer VMMDLL_Initialize(int argc, String argv[]);
	void VMMDLL_Close(Pointer hVMM);
	void VMMDLL_CloseAll();
	long VMMDLL_MemSize(Pointer pvMem);
	void VMMDLL_MemFree(Pointer pvMem);
	
	
	
	boolean VMMDLL_ConfigGet(Pointer hVMM, long fOption, LongByReference pqwValue);
	boolean VMMDLL_ConfigSet(Pointer hVMM, long fOption, long qwValue);
	
	
	
	boolean VMMDLL_InitializePlugins(Pointer hVMM);
	
	
	
	@Structure.FieldOrder({"dwVersion", "pfnAddFile", "pfnAddDirectory", "h"})
	class VMMDLL_VFS_FILELIST2 extends Structure {
		public int dwVersion;
		public CB_FILE pfnAddFile;
		public CB_DIRECTORY pfnAddDirectory;
		public long h;
		interface CB_FILE extends Callback {
			void invoke(long h, String uszName, long cb, Pointer pExInfo);
		}
		interface CB_DIRECTORY extends Callback {
			void invoke(long h, String uszName, Pointer pExInfo);
		}
	}
	
	boolean VMMDLL_VfsListU(Pointer hVMM, byte[] uszPath, VMMDLL_VFS_FILELIST2 pFileList);
	int VMMDLL_VfsReadU(Pointer hVMM, byte[] uszFileName, Pointer pb, int cb, IntByReference pcbRead, long cbOffset);
	int VMMDLL_VfsWriteU(Pointer hVMM, byte[] uszFileName, Pointer pb, int cb, IntByReference pcbWrite, long cbOffset);
	
	
	
	boolean VMMDLL_MemReadEx(Pointer hVMM, int dwPID, long qwA, byte[] pb, int cb, IntByReference pcbReadOpt, int flags);
	boolean VMMDLL_MemPrefetchPages(Pointer hVMM, int dwPID, long[] pPrefetchAddresses, int cPrefetchAddresses);
	boolean VMMDLL_MemWrite(Pointer hVMM, int dwPID, long qwA, byte[] pb, int cb);
	boolean VMMDLL_MemVirt2Phys(Pointer hVMM, int dwPID, long qwVA, LongByReference pqwPA);
	
	
	
	Pointer VMMDLL_Scatter_Initialize(Pointer hVMM, int dwPID, int flags);
	boolean VMMDLL_Scatter_Prepare(Pointer hS, long va, int cb);
	boolean VMMDLL_Scatter_PrepareWrite(Pointer hS, long va, byte[] pb, int cb);
	boolean VMMDLL_Scatter_Execute(Pointer hS);
	boolean VMMDLL_Scatter_Read(Pointer hS, long va, int cb, byte[] pb, IntByReference pcbRead);
	boolean VMMDLL_Scatter_Clear(Pointer hS, int pid, int flags);
	void VMMDLL_Scatter_CloseHandle(Pointer hS);
	
	
	
	boolean VMMDLL_PidGetFromName(Pointer hVMM, byte[] szProcName, IntByReference pdwPID);
	boolean VMMDLL_PidList(Pointer hVMM, int[] pPIDs, LongByReference pcPIDs);
	
	
	
	
	@Structure.FieldOrder({"pa", "cb"})
	class VMMDLL_MAP_PHYSMEM_ENTRY extends Structure {
		public long pa;
		public long cb;
	}
	
	@Structure.FieldOrder({"dwVersion", "_Reserved1", "cMap", "_Reserved2", "pMap"})
	class VMMDLL_MAP_PHYSMEM extends Structure {
		public int dwVersion;
		public int[] _Reserved1 = new int[5];
		public int cMap;
		public int _Reserved2;
		public VMMDLL_MAP_PHYSMEM_ENTRY[] pMap;
		
		VMMDLL_MAP_PHYSMEM(Pointer p)
		{
			super(p);
			pMap = new VMMDLL_MAP_PHYSMEM_ENTRY[1];
			read();
			if(dwVersion != VmmNative.VMMDLL_MAP_PHYSMEM_VERSION) { throw new VmmException("Bad Version"); }
			pMap = new VMMDLL_MAP_PHYSMEM_ENTRY[cMap];
			read();
		}
	}
	
	boolean VMMDLL_Map_GetPhysMem(Pointer hVMM, PointerByReference ppPhysMemMap);
	
	
	
	@Structure.FieldOrder({"fValid", "_Reserved", "port", "pbAddr", "uszText"})
	class VMMDLL_MAP_NETENTRY_SRCDST extends Structure {
		public boolean fValid;
		public short _Reserved;
		public short port;
		public byte[] pbAddr = new byte[16];
		public String uszText;
	}
	
	@Structure.FieldOrder({"dwPID", "dwState", "_FutureUse3", "AF", "Src", "Dst", "vaObj", "ftTime", "dwPoolTag", "_FutureUse4", "uszText", "_FutureUse2"})
	class VMMDLL_MAP_NETENTRY extends Structure {
		public int dwPID;
		public int dwState;
		public short[] _FutureUse3 = new short[3];
		public short AF;
		public VMMDLL_MAP_NETENTRY_SRCDST Src;
		public VMMDLL_MAP_NETENTRY_SRCDST Dst;
		public long vaObj;
		public long ftTime;
		public int dwPoolTag;
		public int _FutureUse4;
		public String uszText;
		public int[] _FutureUse2 = new int[4];
	}
	
	@Structure.FieldOrder({"dwVersion", "_Reserved1", "pbMultiText", "cbMultiText", "cMap", "pMap"})
	class VMMDLL_MAP_NET extends Structure {
		public int dwVersion;
		public int _Reserved1;
		public Pointer pbMultiText;
		public int cbMultiText;
		public int cMap;
		public VMMDLL_MAP_NETENTRY[] pMap;
		
		VMMDLL_MAP_NET(Pointer p)
		{
			super(p);
			pMap = new VMMDLL_MAP_NETENTRY[1];
			read();
			if(dwVersion != VmmNative.VMMDLL_MAP_NET_VERSION) { throw new VmmException("Bad Version"); }
			pMap = new VMMDLL_MAP_NETENTRY[cMap];
			read();
		}
	}
	
	boolean VMMDLL_Map_GetNetU(Pointer hVMM, PointerByReference ppPhysMemMap);
	
	
	
	@Structure.FieldOrder({"_FutureUse1", "uszText", "vaRegHive", "uszSID", "_FutureUse2"})
	class VMMDLL_MAP_USERENTRY extends Structure {
		public int[] _FutureUse1 = new int[2];
		public String uszText;
		public long vaRegHive;
		public String uszSID;
		public int[] _FutureUse2 = new int[2];
	}
	
	@Structure.FieldOrder({"dwVersion", "_Reserved1", "pbMultiText", "cbMultiText", "cMap", "pMap"})
	class VMMDLL_MAP_USER extends Structure {
		public int dwVersion;
		public int[] _Reserved1 = new int[5];
		public Pointer pbMultiText;
		public int cbMultiText;
		public int cMap;
		public VMMDLL_MAP_USERENTRY[] pMap;
		
		VMMDLL_MAP_USER(Pointer p)
		{
			super(p);
			pMap = new VMMDLL_MAP_USERENTRY[1];
			read();
			if(dwVersion != VmmNative.VMMDLL_MAP_USER_VERSION) { throw new VmmException("Bad Version"); }
			pMap = new VMMDLL_MAP_USERENTRY[cMap];
			read();
		}
	}
	
	boolean VMMDLL_Map_GetUsersU(Pointer hVMM, PointerByReference ppUserMap);
	
	
	
	@Structure.FieldOrder({"dwServiceType", "dwCurrentState", "dwControlsAccepted", "dwWin32ExitCode", "dwServiceSpecificExitCode", "dwCheckPoint", "dwWaitHint"})
	class SERVICE_STATUS extends Structure {
		public int dwServiceType;
	    public int dwCurrentState;
	    public int dwControlsAccepted;
	    public int dwWin32ExitCode;
	    public int dwServiceSpecificExitCode;
	    public int dwCheckPoint;
	    public int dwWaitHint;
	}
	
	@Structure.FieldOrder({"vaObj", "dwOrdinal", "dwStartType", "ServiceStatus", "uszServiceName", "uszDisplayName", "uszPath", "uszUserTp", "uszUserAcct", "uszImagePath", "dwPID", "_FutureUse1", "_FutureUse2"})
	class VMMDLL_MAP_SERVICEENTRY extends Structure {
		public long vaObj;
		public int dwOrdinal;
		public int dwStartType;
		public SERVICE_STATUS ServiceStatus;
		public String uszServiceName;
		public String uszDisplayName;
		public String uszPath;
		public String uszUserTp;
		public String uszUserAcct;
		public String uszImagePath;
		public int dwPID;
		public int _FutureUse1;
		public long _FutureUse2;
	}
	
	@Structure.FieldOrder({"dwVersion", "_Reserved1", "pbMultiText", "cbMultiText", "cMap", "pMap"})
	class VMMDLL_MAP_SERVICE extends Structure {
		public int dwVersion;
		public int[] _Reserved1 = new int[5];
		public Pointer pbMultiText;
		public int cbMultiText;
		public int cMap;
		public VMMDLL_MAP_SERVICEENTRY[] pMap;
		
		VMMDLL_MAP_SERVICE(Pointer p)
		{
			super(p);
			pMap = new VMMDLL_MAP_SERVICEENTRY[1];
			read();
			if(dwVersion != VmmNative.VMMDLL_MAP_SERVICE_VERSION) { throw new VmmException("Bad Version"); }
			pMap = new VMMDLL_MAP_SERVICEENTRY[cMap];
			read();
		}
	}
	
	boolean VMMDLL_Map_GetServicesU(Pointer hVMM, PointerByReference ppServiceMap);
	
	
	
	@Structure.FieldOrder({"va", "tag", "fAlloc", "tpPool", "tpSS", "cb", "_Filler"})
	class VMMDLL_MAP_POOLENTRY extends Structure {
		public long va;
		public byte[] tag = new byte[5];
		public byte fAlloc;
		public byte tpPool;
		public byte tpSS;
		public int cb;
		public int _Filler;
	}
	
	@Structure.FieldOrder({"dwVersion", "_Reserved1", "cbTotal", "piTag2Map", "pTag", "cTag", "cMap", "pMap"})
	class VMMDLL_MAP_POOL extends Structure {
		public int dwVersion;
		public int[] _Reserved1 = new int[6];
		public int cbTotal;
		public Pointer piTag2Map;
		public Pointer pTag;
		public int cTag;
		public int cMap;
		public VMMDLL_MAP_POOLENTRY[] pMap;
		
		VMMDLL_MAP_POOL(Pointer p)
		{
			super(p);
			pMap = new VMMDLL_MAP_POOLENTRY[1];
			read();
			if(dwVersion != VmmNative.VMMDLL_MAP_POOL_VERSION) { throw new VmmException("Bad Version"); }
			pMap = new VMMDLL_MAP_POOLENTRY[cMap];
			read();
		}
	}
	
	boolean VMMDLL_Map_GetPool(Pointer hVMM, PointerByReference ppPoolMap, int flags);
	
	
	
	@Structure.FieldOrder({"vaObject", "dwHandle", "_dwGrantedAccess_iType", "qwHandleCount", "qwPointerCount", "vaObjectCreateInfo", "vaSecurityDescriptor", "uszText", "_FutureUse2", "dwPID", "dwPoolTag", "_FutureUse", "uszType"})
	class VMMDLL_MAP_HANDLEENTRY extends Structure {
		public long vaObject;
		public int dwHandle;
		public int _dwGrantedAccess_iType;
		public long qwHandleCount;
		public long qwPointerCount;
		public long vaObjectCreateInfo;
		public long vaSecurityDescriptor;
		public String uszText;
		public int _FutureUse2;
		public int dwPID;
		public byte[] dwPoolTag = new byte[4];
		public int[] _FutureUse = new int[7];
		public String uszType;
	}
	
	@Structure.FieldOrder({"dwVersion", "_Reserved1", "pbMultiText", "cbMultiText", "cMap", "pMap"})
	class VMMDLL_MAP_HANDLE extends Structure {
		public int dwVersion;
		public int[] _Reserved1 = new int[5];
		public Pointer pbMultiText;
		public int cbMultiText;
		public int cMap;
		public VMMDLL_MAP_HANDLEENTRY[] pMap;
		
		VMMDLL_MAP_HANDLE(Pointer p)
		{
			super(p);
			pMap = new VMMDLL_MAP_HANDLEENTRY[1];
			read();
			if(dwVersion != VmmNative.VMMDLL_MAP_HANDLE_VERSION) { throw new VmmException("Bad Version"); }
			pMap = new VMMDLL_MAP_HANDLEENTRY[cMap];
			read();
		}
	}
	
	boolean VMMDLL_Map_GetHandleU(Pointer hVMM, int dwPID, PointerByReference ppHandleMap);
	
	
	
	
	@Structure.FieldOrder({"va", "cb", "tp", "iHeap"})
	class VMMDLL_MAP_HEAP_SEGMENTENTRY extends Structure {
		public long va;
		public int cb;
		public short tp;
		public short iHeap;
	}
	
	@Structure.FieldOrder({"va", "tp", "f32", "iHeap", "dwHeapNum"})
	class VMMDLL_MAP_HEAPENTRY extends Structure {
		public long va;
		public int tp;
		public boolean f32;
		public int iHeap;
		public int dwHeapNum;
	}
	
	@Structure.FieldOrder({"dwVersion", "_Reserved1", "ptrSegments", "cSegments", "cMap", "pMap", "pSegments"})
	class VMMDLL_MAP_HEAP extends Structure {
		public int dwVersion;
		public int[] _Reserved1 = new int[7];
		public Pointer ptrSegments;
		public int cSegments;
		public int cMap;
		public VMMDLL_MAP_HEAPENTRY[] pMap;
		public VMMDLL_MAP_HEAP_SEGMENTENTRY[] pSegments;
		
		VMMDLL_MAP_HEAP(Pointer p)
		{
			super(p);
			pMap = new VMMDLL_MAP_HEAPENTRY[1];
			pSegments = new VMMDLL_MAP_HEAP_SEGMENTENTRY[1];
			read();
			if(dwVersion != VmmNative.VMMDLL_MAP_HEAP_VERSION) { throw new VmmException("Bad Version"); }
			pMap = new VMMDLL_MAP_HEAPENTRY[cMap];
			pSegments = new VMMDLL_MAP_HEAP_SEGMENTENTRY[cSegments];
			read();
		}
	}
	
	boolean VMMDLL_Map_GetHeap(Pointer hVMM, int dwPID, PointerByReference ppHeapMap);
	
	
	
	@Structure.FieldOrder({"va", "cb", "tp"})
	class VMMDLL_MAP_HEAPALLOCENTRY extends Structure {
		public long va;
		public int cb;
		public int tp;
	}
	
	@Structure.FieldOrder({"dwVersion", "_Reserved1", "_Reserved2", "cMap", "pMap"})
	class VMMDLL_MAP_HEAPALLOC extends Structure {
		public int dwVersion;
		public int[] _Reserved1 = new int[7];
		public Pointer[] _Reserved2 = new Pointer[2];
		public int cMap;
		public VMMDLL_MAP_HEAPALLOCENTRY[] pMap;
		
		VMMDLL_MAP_HEAPALLOC(Pointer p)
		{
			super(p);
			pMap = new VMMDLL_MAP_HEAPALLOCENTRY[1];
			read();
			if(dwVersion != VmmNative.VMMDLL_MAP_HEAPALLOC_VERSION) { throw new VmmException("Bad Version"); }
			pMap = new VMMDLL_MAP_HEAPALLOCENTRY[cMap];
			read();
		}
	}
	
	boolean VMMDLL_Map_GetHeapAlloc(Pointer hVMM, int dwPID, long qwHeapNumOrAddress, PointerByReference ppHeapAllocMap);

	
	
	@Structure.FieldOrder({"vaBase", "cPages", "fPage", "fWow64", "_FutureUse1", "uszText", "_Reserved1", "cSoftware"})
	class VMMDLL_MAP_PTEENTRY extends Structure {
		public long vaBase;
		public long cPages;
		public long fPage;
		public boolean fWow64;
		public int _FutureUse1;
		public String uszText;
		public int _Reserved1;
		public int cSoftware;
	}
	
	@Structure.FieldOrder({"dwVersion", "_Reserved1", "pbMultiText", "cbMultiText", "cMap", "pMap"})
	class VMMDLL_MAP_PTE extends Structure {
		public int dwVersion;
		public int[] _Reserved1 = new int[5];
		public Pointer pbMultiText;
		public int cbMultiText;
		public int cMap;
		public VMMDLL_MAP_PTEENTRY[] pMap;
		
		VMMDLL_MAP_PTE(Pointer p)
		{
			super(p);
			pMap = new VMMDLL_MAP_PTEENTRY[1];
			read();
			if(dwVersion != VmmNative.VMMDLL_MAP_PTE_VERSION) { throw new VmmException("Bad Version"); }
			pMap = new VMMDLL_MAP_PTEENTRY[cMap];
			read();
		}
	}
	
	boolean VMMDLL_Map_GetPteU(Pointer hVMM, int dwPID, boolean fIdentifyModules, PointerByReference ppPteMap);
	
	
	
	@Structure.FieldOrder({"dwTID", "dwPID", "dwExitStatus", "bState", "bRunning", "bPriority", "bBasePriority", "vaETHREAD", "vaTeb", "ftCreateTime", "ftExitTime", "vaStartAddress", "vaStackBaseUser", "vaStackLimitUser", "vaStackBaseKernel", "vaStackLimitKernel", "vaTrapFrame", "vaRIP", "vaRSP", "qwAffinity", "dwUserTime", "dwKernelTime", "bSuspendCount", "bWaitReason", "_FutureUse1", "_FutureUse2", "vaImpersonationToken", "vaWin32StartAddress"})
	class VMMDLL_MAP_THREADENTRY extends Structure {
	    public int dwTID;
	    public int dwPID;
	    public int dwExitStatus;
	    public byte bState;
	    public byte bRunning;
	    public byte bPriority;
	    public byte bBasePriority;
	    public long vaETHREAD;
	    public long vaTeb;
	    public long ftCreateTime;
	    public long ftExitTime;
	    public long vaStartAddress;
	    public long vaStackBaseUser;
	    public long vaStackLimitUser;
	    public long vaStackBaseKernel;
	    public long vaStackLimitKernel;
	    public long vaTrapFrame;
	    public long vaRIP;
	    public long vaRSP;
	    public long qwAffinity;
	    public int dwUserTime;
	    public int dwKernelTime;
	    public byte bSuspendCount;
	    public byte bWaitReason;
	    public byte[] _FutureUse1 = new byte[2];
	    public int[] _FutureUse2 = new int[11];
	    public long vaImpersonationToken;
	    public long vaWin32StartAddress;
	}
	
	@Structure.FieldOrder({"dwVersion", "_Reserved", "cMap", "pMap"})
	class VMMDLL_MAP_THREAD extends Structure {
		public int dwVersion;
		public int[] _Reserved = new int[8];
		public int cMap;
		public VMMDLL_MAP_THREADENTRY[] pMap;
		
		VMMDLL_MAP_THREAD(Pointer p)
		{
			super(p);
			pMap = new VMMDLL_MAP_THREADENTRY[1];
			read();
			if(dwVersion != VmmNative.VMMDLL_MAP_THREAD_VERSION) { throw new VmmException("Bad Version"); }
			pMap = new VMMDLL_MAP_THREADENTRY[cMap];
			read();
		}
	}
	
	boolean VMMDLL_Map_GetThread(Pointer hVMM, int dwPID, PointerByReference ppThreadMap);
	

	
	@Structure.FieldOrder({"vaBase", "cbImageSize", "fWow64", "uszText", "_FutureUse1", "dwCheckSum", "dwTimeDateStamp", "ftUnload"})
	class VMMDLL_MAP_UNLOADEDMODULEENTRY extends Structure {
		public long vaBase;
		public int cbImageSize;
		public boolean fWow64;
		public String uszText;
		public int _FutureUse1;
		public int dwCheckSum;
		public int dwTimeDateStamp;
		public long ftUnload;
	}
	
	@Structure.FieldOrder({"dwVersion", "_Reserved1", "pbMultiText", "cbMultiText", "cMap", "pMap"})
	class VMMDLL_MAP_UNLOADEDMODULE extends Structure {
		public int dwVersion;
		public int[] _Reserved1 = new int[5];
		public Pointer pbMultiText;
		public int cbMultiText;
		public int cMap;
		public VMMDLL_MAP_UNLOADEDMODULEENTRY[] pMap;
		
		VMMDLL_MAP_UNLOADEDMODULE(Pointer p)
		{
			super(p);
			pMap = new VMMDLL_MAP_UNLOADEDMODULEENTRY[1];
			read();
			if(dwVersion != VmmNative.VMMDLL_MAP_UNLOADEDMODULE_VERSION) { throw new VmmException("Bad Version"); }
			pMap = new VMMDLL_MAP_UNLOADEDMODULEENTRY[cMap];
			read();
		}
	}
	
	boolean VMMDLL_Map_GetUnloadedModuleU(Pointer hVMM, int dwPID, PointerByReference ppUnloadedModuleMap);
	

	
	@Structure.FieldOrder({"vaStart", "vaEnd", "vaVad", "dw0", "dw1", "dwu2", "cbPrototypePte", "vaPrototypePte", "vaSubsection", "uszText", "_FutureUse1", "_Reserved1", "vaFileObject", "cVadExPages", "cVadExPagesBase", "_Reserved2"})
	class VMMDLL_MAP_VADENTRY extends Structure {
		public long vaStart;
		public long vaEnd;
		public long vaVad;
		public int dw0;
		public int dw1;
		public int dwu2;
		public int cbPrototypePte;
		public long vaPrototypePte;
		public long vaSubsection;
		public String uszText;
		public int _FutureUse1;
		public int _Reserved1;
		public long vaFileObject;
		public int cVadExPages;
		public int cVadExPagesBase;
		public long _Reserved2;
	}
	
	@Structure.FieldOrder({"dwVersion", "_Reserved1", "cPage", "pbMultiText", "cbMultiText", "cMap", "pMap"})
	class VMMDLL_MAP_VAD extends Structure {
		public int dwVersion;
		public int[] _Reserved1 = new int[4];
		public int cPage;
		public Pointer pbMultiText;
		public int cbMultiText;
		public int cMap;
		public VMMDLL_MAP_VADENTRY[] pMap;
		
		VMMDLL_MAP_VAD(Pointer p)
		{
			super(p);
			pMap = new VMMDLL_MAP_VADENTRY[1];
			read();
			if(dwVersion != VmmNative.VMMDLL_MAP_VAD_VERSION) { throw new VmmException("Bad Version"); }
			pMap = new VMMDLL_MAP_VADENTRY[cMap];
			read();
		}
	}
	
	boolean VMMDLL_Map_GetVadU(Pointer hVMM, int dwPID, boolean fIdentifyModules, PointerByReference ppVadMap);

	
	
	@Structure.FieldOrder({"tp", "iPML", "pteFlags", "_Reserved2", "va", "pa", "pte", "_Reserved1", "proto_tp", "proto_pa", "proto_pte", "vaVadBase"})
	class VMMDLL_MAP_VADEXENTRY extends Structure {
		public int tp;
		public byte iPML;
		public byte pteFlags;
		public short _Reserved2;
		public long va;
		public long pa;
		public long pte;
		public int _Reserved1;
		public int proto_tp;
		public long proto_pa;
		public long proto_pte;
		public long vaVadBase;
	}
	
	@Structure.FieldOrder({"dwVersion", "_Reserved1", "cMap", "pMap"})
	class VMMDLL_MAP_VADEX extends Structure {
		public int dwVersion;
		public int[] _Reserved1 = new int[4];
		public int cMap;
		public VMMDLL_MAP_VADEXENTRY[] pMap;
		
		VMMDLL_MAP_VADEX(Pointer p)
		{
			super(p);
			pMap = new VMMDLL_MAP_VADEXENTRY[1];
			read();
			if(dwVersion != VmmNative.VMMDLL_MAP_VADEX_VERSION) { throw new VmmException("Bad Version"); }
			pMap = new VMMDLL_MAP_VADEXENTRY[cMap];
			read();
		}
	}
	
	boolean VMMDLL_Map_GetVadEx(Pointer hVMM, int dwPID, int oPage, int cPage, PointerByReference ppVadExMap);
	
	
	
	static final int VMMDLL_PROCESS_INFORMATION_OPT_STRING_PATH_KERNEL 		= 1;
	static final int VMMDLL_PROCESS_INFORMATION_OPT_STRING_PATH_USER_IMAGE 	= 2;
	static final int VMMDLL_PROCESS_INFORMATION_OPT_STRING_CMDLINE 			= 3;
	
	@Structure.FieldOrder({"magic", "wVersion", "wSize", "tpMemoryModel", "tpSystem", "fUserOnly", "dwPID", "dwPPID", "dwState", "szName", "szNameLong", "paDTB", "paDTB_UserOpt", "vaEPROCESS", "vaPEB", "_Reserved1", "fWow64", "vaPEB32", "dwSessionId", "qwLUID", "szSID", "IntegrityLevel"})
	class VMMDLL_PROCESS_INFORMATION extends Structure {
		public long magic;
		public short wVersion;
		public short wSize;
		public int tpMemoryModel;
		public int tpSystem;
		public boolean fUserOnly;
		public int dwPID;
		public int dwPPID;
		public int dwState;
		public byte[] szName = new byte[16];
		public byte[] szNameLong = new byte[64];
		public long paDTB;
		public long paDTB_UserOpt;
		// win below;
		public long vaEPROCESS;
		public long vaPEB;
		public long _Reserved1;
		public boolean fWow64;
		public int vaPEB32;
		public int dwSessionId;
		public long qwLUID;
		public byte[] szSID = new byte[MAX_PATH];
		public int IntegrityLevel;
	}
	
	boolean VMMDLL_ProcessGetInformation(Pointer hVMM, int dwPID, VMMDLL_PROCESS_INFORMATION pProcessInformation, LongByReference pcbProcessInformation);
	Pointer VMMDLL_ProcessGetInformationString(Pointer hVMM, int dwPID, int fOptionString);
	
	
	
	static final int VMMDLL_MODULE_FLAG_NORMAL           	= 0;
	static final int VMMDLL_MODULE_FLAG_DEBUGINFO        	= 1;
	static final int VMMDLL_MODULE_FLAG_VERSIONINFO      	= 2;
	
	@Structure.FieldOrder({"dwAge", "_Reserved", "Guid", "uszGuid", "uszPdbFilename"})
	class VMMDLL_MAP_MODULEENTRY_DEBUGINFO extends Structure {
		public int dwAge;
		public int _Reserved;
		public byte[] Guid = new byte[16];
		public String uszGuid;
		public String uszPdbFilename;
		
		
		public VMMDLL_MAP_MODULEENTRY_DEBUGINFO()
		{
			super();
		}
		
		VMMDLL_MAP_MODULEENTRY_DEBUGINFO(Pointer p)
		{
			super(p);
			read();
		}
	}
	
	@Structure.FieldOrder({"uszCompanyName", "uszFileDescription", "uszFileVersion", "uszInternalName", "uszLegalCopyright", "uszOriginalFilename", "uszProductName", "uszProductVersion"})
	class VMMDLL_MAP_MODULEENTRY_VERSIONINFO extends Structure {
		public String uszCompanyName;
		public String uszFileDescription;
		public String uszFileVersion;
		public String uszInternalName;
		public String uszLegalCopyright;
		public String uszOriginalFilename;
		public String uszProductName;
		public String uszProductVersion;
		
		
		public VMMDLL_MAP_MODULEENTRY_VERSIONINFO()
		{
			super();
		}
		
		VMMDLL_MAP_MODULEENTRY_VERSIONINFO(Pointer p)
		{
			super(p);
			read();
		}
	}
	
	@Structure.FieldOrder({"vaBase", "vaEntry", "cbImageSize", "fWoW64", "uszText", "_Reserved3", "_Reserved4", "uszFullName", "tp", "cbFileSizeRaw", "cSection", "cEAT", "cIAT", "_Reserved2", "_Reserved1", "pExDebugInfo", "pExVersionInfo"})
	class VMMDLL_MAP_MODULEENTRY extends Structure {
		public long vaBase;
		public long vaEntry;
		public int cbImageSize;
		public boolean fWoW64;
		public String uszText;
		public int _Reserved3;
		public int _Reserved4;
		public String uszFullName;
		public int tp;
		public int cbFileSizeRaw;
		public int cSection;
		public int cEAT;
		public int cIAT;
		public int _Reserved2;
		public long[] _Reserved1 = new long[3];
		public long pExDebugInfo;
		public long pExVersionInfo;
		
		public VMMDLL_MAP_MODULEENTRY()
		{
			super();
		}
		
		VMMDLL_MAP_MODULEENTRY(Pointer p)
		{
			super(p);
			read();
		}
	}
	
	@Structure.FieldOrder({"dwVersion", "_Reserved1", "pbMultiText", "cbMultiText", "cMap", "pMap"})
	class VMMDLL_MAP_MODULE extends Structure {
		public int dwVersion;
		public int[] _Reserved1 = new int[5];
		public Pointer pbMultiText;
		public int cbMultiText;
		public int cMap;
		public VMMDLL_MAP_MODULEENTRY[] pMap;
		
		VMMDLL_MAP_MODULE(Pointer p)
		{
			super(p);
			pMap = new VMMDLL_MAP_MODULEENTRY[1];
			read();
			if(dwVersion != VmmNative.VMMDLL_MAP_MODULE_VERSION) { throw new VmmException("Bad Version"); }
			pMap = new VMMDLL_MAP_MODULEENTRY[cMap];
			read();
		}
	}
	
	boolean VMMDLL_Map_GetModuleU(Pointer hVMM, int dwPID, PointerByReference ppModuleMap, int flags);
	boolean VMMDLL_Map_GetModuleFromNameU(Pointer hVMM, int dwPID, String uszModuleName, PointerByReference ppModuleMapEntry, int flags);
	
	
	
	long VMMDLL_ProcessGetProcAddressU(Pointer hVMM, int dwPID, String uszModuleName, String szFunctionName);
	
	
	
	@Structure.FieldOrder({"vaFunction", "dwOrdinal", "oFunctionsArray", "oNamesArray", "_FutureUse1", "uszFunction", "uszForwardedFunction"})
	class VMMDLL_MAP_EATENTRY extends Structure {
		public long vaFunction;
		public int dwOrdinal;
		public int oFunctionsArray;
		public int oNamesArray;
		public int _FutureUse1;
		public String uszFunction;
		public String uszForwardedFunction;
	}
	
	@Structure.FieldOrder({"dwVersion", "dwOrdinalBase", "cNumberOfNames", "cNumberOfFunctions", "cNumberOfForwardedFunctions", "_Reserved1", "vaModuleBase", "vaAddressOfFunctions", "vaAddressOfNames", "pbMultiText", "cbMultiText", "cMap", "pMap"})
	class VMMDLL_MAP_EAT extends Structure {
		public int dwVersion;
		public int dwOrdinalBase;
		public int cNumberOfNames;
		public int cNumberOfFunctions;
		public int cNumberOfForwardedFunctions;
		public int[] _Reserved1 = new int[3];
		public long vaModuleBase;
		public long vaAddressOfFunctions;
		public long vaAddressOfNames;
		public Pointer pbMultiText;
		public int cbMultiText;
		public int cMap;
		public VMMDLL_MAP_EATENTRY[] pMap;
		
		VMMDLL_MAP_EAT(Pointer p)
		{
			super(p);
			pMap = new VMMDLL_MAP_EATENTRY[1];
			read();
			if(dwVersion != VmmNative.VMMDLL_MAP_EAT_VERSION) { throw new VmmException("Bad Version"); }
			pMap = new VMMDLL_MAP_EATENTRY[cMap];
			read();
		}
	}
	
	boolean VMMDLL_Map_GetEATU(Pointer hVMM, int dwPID, String uszModuleName, PointerByReference ppEatMap);
	
	
	
	@Structure.FieldOrder({"vaFunction", "uszFunction", "_FutureUse1", "_FutureUse2", "uszModule", "f32", "wHint", "_Reserved1", "rvaFirstThunk", "rvaOriginalFirstThunk", "rvaNameModule", "rvaNameFunction"})
	class VMMDLL_MAP_IATENTRY extends Structure {
		public long vaFunction;
		public String uszFunction;
		public int _FutureUse1;
		public int _FutureUse2;
		public String uszModule;
		// Thunk
		public boolean f32;
		public short wHint;
		public short _Reserved1;
		public int rvaFirstThunk;
		public int rvaOriginalFirstThunk;
		public int rvaNameModule;
		public int rvaNameFunction;
	}
	
	@Structure.FieldOrder({"dwVersion", "_Reserved1", "vaModuleBase", "pbMultiText", "cbMultiText", "cMap", "pMap"})
	class VMMDLL_MAP_IAT extends Structure {
		public int dwVersion;
		public int[] _Reserved1 = new int[5];
		public long vaModuleBase;
		public Pointer pbMultiText;
		public int cbMultiText;
		public int cMap;
		public VMMDLL_MAP_IATENTRY[] pMap;
		
		VMMDLL_MAP_IAT(Pointer p)
		{
			super(p);
			pMap = new VMMDLL_MAP_IATENTRY[1];
			read();
			if(dwVersion != VmmNative.VMMDLL_MAP_IAT_VERSION) { throw new VmmException("Bad Version"); }
			pMap = new VMMDLL_MAP_IATENTRY[cMap];
			read();
		}
	}
	
	boolean VMMDLL_Map_GetIATU(Pointer hVMM, int dwPID, String uszModuleName, PointerByReference ppIatMap);
	
	
	
	@Structure.FieldOrder({"VirtualAddress", "Size"})
	class IMAGE_DATA_DIRECTORY extends Structure {
		public int VirtualAddress;
		public int Size;
	}
	
	boolean VMMDLL_ProcessGetDirectoriesU(Pointer hVMM, int dwPID, String uszModule, IMAGE_DATA_DIRECTORY[] pData);
	
	
	
	@Structure.FieldOrder({"name", "MiscVirtualSize", "VirtualAddress", "SizeOfRawData", "PointerToRawData", "PointerToRelocations", "PointerToLinenumbers", "NumberOfRelocations", "NumberOfLinenumbers", "Characteristics"})
	class IMAGE_SECTION_HEADER extends Structure {
		public byte[] name = new byte[8];
		public int MiscVirtualSize;
		public int VirtualAddress;
		public int SizeOfRawData;
		public int PointerToRawData;
		public int PointerToRelocations;
		public int PointerToLinenumbers;
		public short NumberOfRelocations;
		public short NumberOfLinenumbers;
		public int Characteristics;
	}
	
	boolean VMMDLL_ProcessGetSectionsU(Pointer hVMM, int dwPID, String uszModule, IMAGE_SECTION_HEADER[] pData, int cData, IntByReference pcData);
	
	
	
	boolean VMMDLL_PdbLoad(Pointer hVMM, int dwPID, long vaModuleBase, byte[] szModuleName);
	boolean VMMDLL_PdbSymbolName(Pointer hVMM, String szModule, long cbSymbolAddressOrOffset, byte[] szModuleName, IntByReference pdwSymbolDisplacement);
	boolean VMMDLL_PdbSymbolAddress(Pointer hVMM, String szModule, String szTypeName, LongByReference pcbTypeSize);
	boolean VMMDLL_PdbTypeSize(Pointer hVMM, String szModule, String szTypeName, IntByReference pcbTypeSize);
	boolean VMMDLL_PdbTypeChildOffset(Pointer hVMM, String szModule, String uszTypeName, String uszTypeChildName, IntByReference pdwSymbolDisplacement);
	
	
	
	@Structure.FieldOrder({"magic", "wVersion", "wSize", "_FutureReserved1", "vaCMHIVE", "vaHBASE_BLOCK", "cbLength", "uszName", "uszNameShort", "uszHiveRootPath", "_FutureReserved"})
	class VMMDLL_REGISTRY_HIVE_INFORMATION extends Structure {
		public long magic;
		public short wVersion;
		public short wSize;
		public byte[] _FutureReserved1 = new byte[0x34];
		public long vaCMHIVE;
		public long vaHBASE_BLOCK;
		public int cbLength;
		public byte[] uszName = new byte[128];
		public byte[] uszNameShort = new byte[32 + 1];
		public byte[] uszHiveRootPath = new byte[MAX_PATH];
		public long[] _FutureReserved = new long[0x10];
	}
	
	boolean VMMDLL_WinReg_HiveList(Pointer hVMM, VMMDLL_REGISTRY_HIVE_INFORMATION[] pHives, int cHives, IntByReference pcHives);
	boolean VMMDLL_WinReg_HiveReadEx(Pointer hVMM, long vaCMHive, int ra, Pointer ptr, int cb, IntByReference pcbReadOpt, long flags);
	boolean VMMDLL_WinReg_HiveWrite(Pointer hVMM, long vaCMHive, int ra, byte[] pb, int cb);
	boolean VMMDLL_WinReg_EnumKeyExU(Pointer hVMM, String uszFullPathKey, int dwIndex, byte[] lpName, IntByReference lpcchName, LongByReference lpftLastWriteTime);
	boolean VMMDLL_WinReg_EnumValueU(Pointer hVMM, String uszFullPathKey, int dwIndex, byte[] lpValueName, IntByReference lpcchValueName, IntByReference lpType, byte[] lpData, IntByReference lpcbData);
	boolean VMMDLL_WinReg_QueryValueExU(Pointer hVMM, String uszFullPathKeyValue, IntByReference lpType, byte[] lpData, IntByReference lpcbData);
}
