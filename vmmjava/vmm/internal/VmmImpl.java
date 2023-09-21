package vmm.internal;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.sun.jna.*;
import com.sun.jna.ptr.*;

import vmm.*;
import vmm.entry.*;
import vmm.internal.VmmNative.VMMDLL_REGISTRY_HIVE_INFORMATION;

/**
 * JNA native code wrapper for MemProcFS.
 * @see https://github.com/ufrisk/MemProcFS
 * @author Ulf Frisk - pcileech@frizk.net
 */
public class VmmImpl implements IVmm
{ 
	
	//-----------------------------------------------------------------------------
	// INITIALIZATION FUNCTIONALITY BELOW:
	//-----------------------------------------------------------------------------
    private boolean isVerbose = false;
	private Pointer hVMM = null;
	private String vmmNativeLibraryPath = null;
	private IVmmNativeEx jnative = null;
	
	/*
	 * Do not allow direct class instantiation from outside.
	 */
	private VmmImpl()
	{
	}
	
	private VmmImpl(String vmmNativeLibraryPath, String argv[])
	{
		String[] argv_new = null;
		if(argv.length < 2) {
			throw new VmmException("Vmm Init: failed - too few arguments.");
		}
		if(argv[0].equals("") || argv[0].equals("-printf")) {
			argv_new = argv;
		} else {
			argv_new = new String[argv.length + 1];
			argv_new[0] = "";
			System.arraycopy(argv, 0, argv_new, 1, argv.length);
		}
		System.setProperty("jna.library.path", vmmNativeLibraryPath);
		hVMM = VmmNative.INSTANCE.VMMDLL_Initialize(argv_new.length, argv_new);
		if(hVMM == null) { throw new VmmException("Vmm Init: failed in native code."); }
		VmmNative.INSTANCE.VMMDLL_InitializePlugins(hVMM);
		this.vmmNativeLibraryPath = vmmNativeLibraryPath;
		this.isVerbose = getConfig(OPT_CORE_VERBOSE) == 1;
		// Try load java "project panama java.lang.native" implementation.
		// This allows for less function call overhead but it's very recent
		// so it's expected to fail on older JREs. Fallback gracefully to JNA.
		// Implementation is currently built for JDK21. 
		try {
		    if(isVerbose) { System.out.println("vmm: java.lang.foreign implementation = try enable."); }
		    this.jnative = (IVmmNativeEx)Class.forName("vmm.internal.VmmNativeExImpl").getDeclaredConstructor(Long.class, String.class).newInstance(Pointer.nativeValue(hVMM), vmmNativeLibraryPath);
		    if(isVerbose) { System.out.println("vmm: java.lang.foreign implementation = enabled."); }
		} catch(Throwable t) {
		    if(isVerbose) { System.out.println("vmm: java.lang.foreign implementation = failed to enable (JDK21+ required)."); }
		}
	}
	
	public static IVmm Initialize(String vmmNativeLibraryPath, String argv[])
	{
		return new VmmImpl(vmmNativeLibraryPath, argv);
	}
	
	public boolean isValid() {
		return hVMM != null;
	}

	public String getNativeLibraryPath() {
		return vmmNativeLibraryPath;
	}	
	
	public void close()
	{
		VmmNative.INSTANCE.VMMDLL_Close(hVMM);
		hVMM = null;
	}
	
	/*
	 * Always close native implementation upon finalization.
	 */
	@Override
	public void finalize()
	{
	    try {
	        this.close();
	    } catch (Exception e) {}
	}
	
	/*
	 * Custom toString() method.
	 */
	@Override
	public String toString()
	{
		return (hVMM != null) ? "Vmm" : "VmmNotValid";
	}
	
	
	
	//-----------------------------------------------------------------------------
	// CONFIGURATION SETTINGS BELOW:
	//-----------------------------------------------------------------------------
	
	public long getConfig(long fOption)
	{
		LongByReference pqw = new LongByReference();
		boolean f = VmmNative.INSTANCE.VMMDLL_ConfigGet(hVMM, fOption, pqw);
		if(!f) { throw new VmmException(); }
		return pqw.getValue(); 
	}
	
	public void setConfig(long fOption, long qw)
	{
		boolean f = VmmNative.INSTANCE.VMMDLL_ConfigSet(hVMM, fOption, qw);
		if(!f) { throw new VmmException(); }
	}
	
	
	
	//-----------------------------------------------------------------------------
	// INTERNAL UTILITY FUNCTIONALITY BELOW:
	//-----------------------------------------------------------------------------
	
	private static byte[] _utilStringToCString(String s)
	{
		byte[] bjava = s.getBytes(StandardCharsets.UTF_8);
		byte[] bc = new byte[bjava.length+1];
		System.arraycopy(bjava, 0, bc, 0, bjava.length);
		return bc;
	}
	
	
	
	//-----------------------------------------------------------------------------
	// VFS - VIRTUAL FILE SYSTEM FUNCTIONALITY BELOW:
	// NB! VFS FUNCTIONALITY REQUIRES PLUGINS TO BE INITIALIZED
	//     WITH CALL TO InitializePlugins(). 
	//-----------------------------------------------------------------------------
	
	public List<Vmm_VfsListEntry> vfsList(String path)
	{
		ArrayList<Vmm_VfsListEntry> result = new ArrayList<Vmm_VfsListEntry>();
		VmmNative.VMMDLL_VFS_FILELIST2 vfs = new VmmNative.VMMDLL_VFS_FILELIST2();
		vfs.dwVersion = VmmNative.VMMDLL_VFS_FILELIST_VERSION;
		vfs.h = 0;
		vfs.pfnAddFile = new VmmNative.VMMDLL_VFS_FILELIST2.CB_FILE() {
			@Override
			public void invoke(long h, String uszName, long cb, Pointer pExInfo) {
				Vmm_VfsListEntry e = new Vmm_VfsListEntry();
				e.name = uszName;
				e.isFile = true;
				e.size = cb;
				result.add(e);
			}
		};
		vfs.pfnAddDirectory = new VmmNative.VMMDLL_VFS_FILELIST2.CB_DIRECTORY() {
			@Override
			public void invoke(long h, String uszName, Pointer pExInfo) {
				Vmm_VfsListEntry e = new Vmm_VfsListEntry();
				e.name = uszName;
				e.isFile = false;
				e.size = 0;
				result.add(e);
			}
		};
		boolean f = VmmNative.INSTANCE.VMMDLL_VfsListU(hVMM, _utilStringToCString(path), vfs);
		if(!f) { throw new VmmException(); }
		return result;
	}
	
	public byte[] vfsRead(String file, long offset, int size)
	{
		IntByReference pcbRead = new IntByReference();
		Pointer pb = new Memory(size);
		VmmNative.INSTANCE.VMMDLL_VfsReadU(hVMM, _utilStringToCString(file), pb, size, pcbRead, offset);
		if(0 == pcbRead.getValue()) { throw new VmmException(); }
		size = Math.min(size, pcbRead.getValue());
		byte[] result = new byte[size];
		pb.read(0, result, 0, size);
		return result;
	}
	
	public String vfsReadString(String file, long offset, int size)
	{
		byte[] data = vfsRead(file, offset, size);
		return new String(data, StandardCharsets.UTF_8);
	}
	
	public void vfsWrite(String file, byte[] data, long offset)
	{
		IntByReference pcbWrite = new IntByReference();
		Pointer pb = new Memory(data.length);
		pb.write(0, data, 0, data.length);
		VmmNative.INSTANCE.VMMDLL_VfsWriteU(hVMM, _utilStringToCString(file), pb, data.length, pcbWrite, offset);
		if(0 == pcbWrite.getValue()) { throw new VmmException(); }
	}
	
	
	
	//-----------------------------------------------------------------------------
	// INTERNAL VMM MEMORY FUNCTIONALITY BELOW:
	//-----------------------------------------------------------------------------
	
	private class VmmMemScatterMemoryImpl implements IVmmMemScatterMemory {	    
		private final Object objLock = new Object();
		private Object nhS;   // native scatter handle
		private Pointer hS;   // JNA scatter handle
		private int pid;
		private int flags;
		
		private VmmMemScatterMemoryImpl(Pointer hS, Object nhS, int pid, int flags) {
			this.hS = hS;
			this.nhS = nhS;
			this.pid = pid;
			this.flags = flags;
		}
		
		@Override
		public String toString()
		{
			if(pid == -1) {
				return "VmmScatterMemory:Physical";
			} else {
				return "VmmScatterMemory:Virtual:" + String.valueOf(pid);
			}
		}
		
		public boolean isValid() {
			return this.hS != null;
		}

		public int getFlags() {
			return this.flags;
		}

		public void prepare(long va, int size) {
		    if(jnative == null) {		    
    			if(this.hS == null) { throw new VmmException(); }
    			boolean f = VmmNative.INSTANCE.VMMDLL_Scatter_Prepare(hS, va, size);
    			if(!f) { throw new VmmException(); }
		    } else {
		        if(this.nhS == null) { throw new VmmException(); }
		        jnative.scatterPrepare(nhS, va, size);
		    }
		}

		public void prepareWrite(long va, byte[] data) {
		    if(jnative == null) {
    			if(this.hS == null) { throw new VmmException(); }
    			boolean f = VmmNative.INSTANCE.VMMDLL_Scatter_PrepareWrite(hS, va, data, data.length);
    			if(!f) { throw new VmmException(); }
            } else {
                if(this.nhS == null) { throw new VmmException(); }
                jnative.scatterPrepareWrite(nhS, va, data);
            }
		}

		public void execute() {
		    if(jnative == null) {
    			if(this.hS == null) { throw new VmmException(); }
    			boolean f = VmmNative.INSTANCE.VMMDLL_Scatter_Execute(hS);
    			if(!f) { throw new VmmException(); }
            } else {
                if(this.nhS == null) { throw new VmmException(); }
                jnative.scatterExecute(nhS);
            }
		}

		public void clear() {
		    if(jnative == null) {
    			if(this.hS == null) { throw new VmmException(); }
    			boolean f = VmmNative.INSTANCE.VMMDLL_Scatter_Clear(hS, pid, flags);
    			if(!f) { throw new VmmException(); }
            } else {
                if(this.nhS == null) { throw new VmmException(); }
                jnative.scatterClear(nhS, pid, flags);
            }
		}

		public byte[] read(long va, int size) {
		    if(jnative == null) {
    			if(this.hS == null) { throw new VmmException(); }
    			IntByReference pcbRead = new IntByReference();
    			byte[] pbResult = new byte[size];
    			boolean f = VmmNative.INSTANCE.VMMDLL_Scatter_Read(hS, va, size, pbResult, pcbRead);
    			if(!f) { throw new VmmException(); }
    			return pbResult;
		    } else {
                if(this.nhS == null) { throw new VmmException(); }
                return jnative.scatterRead(nhS, va, size);
		    }
		}

		public void close() {
			synchronized(objLock) {
				if(this.hS != null) {
					VmmNative.INSTANCE.VMMDLL_Scatter_CloseHandle(hS);
				}
                if(this.nhS != null) {
                    jnative.scatterClose(nhS);
                }				
                this.hS = null;
                this.nhS = null;
                this.pid = 0;
                this.flags = 0;
			}
		}
		
		@Override
		public void finalize()
		{
		    try {
		        this.close();
		    } catch (Exception e) {}
		}
	}
	
	public byte[] _memRead(int pid, long va, int size)
	{
		return _memRead(pid, va, size, 0);
	}
	
	public byte[] _memRead(int pid, long va, int size, int flags)
	{
	    if(jnative == null) {
	        // JNA implementation:
	        IntByReference pcbRead = new IntByReference();
	        byte[] pbResult = new byte[size];
	        boolean f = VmmNative.INSTANCE.VMMDLL_MemReadEx(hVMM, pid, va, pbResult, size, pcbRead, flags);
	        if(!f) { throw new VmmException(); }
	        return pbResult;
	    } else {
	        // Native java.lang.foreign implementation:
	        return jnative.memRead(pid, va, size, flags);
	    }
	}
	
	public void _memWrite(int pid, long va, byte[] data)
	{
	    if(jnative == null) {
	        // JNA implementation:
	        boolean f = VmmNative.INSTANCE.VMMDLL_MemWrite(hVMM, pid, va, data, data.length);
	        if(!f) { throw new VmmException(); }
	    } else {
	        // Native java.lang.foreign implementation:
	        jnative.memWrite(pid, va, data);
	    }
	}
	
	public void _memPrefetchPages(int pid, long[] vas)
	{
		boolean f = VmmNative.INSTANCE.VMMDLL_MemPrefetchPages(hVMM, pid, vas, vas.length);
		if(!f) { throw new VmmException(); }		
	}
	
	public long _memVirtualToPhysical(int pid, long va)
	{
		LongByReference pa = new LongByReference();
		boolean f = VmmNative.INSTANCE.VMMDLL_MemVirt2Phys(hVMM, pid, va, pa);
		if(!f) { throw new VmmException(); }
		return pa.getValue();
	}

	public IVmmMemScatterMemory _memScatterInitialize(int pid, int flags)
	{
       if(jnative == null) {
            // JNA implementation:
           Pointer hS = VmmNative.INSTANCE.VMMDLL_Scatter_Initialize(hVMM, pid, flags);
           if(hS == null) { throw new VmmException(); }
           return new VmmMemScatterMemoryImpl(hS, null, pid, flags);
       } else {
           // Native java.lang.foreign implementation:
           Object nhS = jnative.scatterInitialize(pid, flags);
           return new VmmMemScatterMemoryImpl(null, nhS, pid, flags);
       }
	}
	
	
	
	//-----------------------------------------------------------------------------
	// VMM PHYSICAL MEMORY FUNCTIONALITY BELOW:
	//-----------------------------------------------------------------------------
	
	public byte[] memRead(long pa, int size)
	{
		return _memRead(-1, pa, size);
	}

	public byte[] memRead(long pa, int size, int flags) {
		return _memRead(-1, pa, size, flags);
	}

	public void memWrite(long pa, byte[] data)
	{
		_memWrite(-1, pa, data);
	}

	public void memPrefetchPages(long[] pas)
	{
		_memPrefetchPages(-1, pas);
	}

	public IVmmMemScatterMemory memScatterInitialize(int flags) {
		return _memScatterInitialize(-1, flags);
	}
	
	
		
	//-----------------------------------------------------------------------------
	// VMM INTERNAL PDB/DEBUG FUNCTIONALITY BELOW:
	//-----------------------------------------------------------------------------
	
	private class VmmPdbImpl implements IVmmPdb
	{
		private String pdbName;
		
		private VmmPdbImpl(int dwPID, long vaModuleBase) {
			byte[] szModuleName = new byte[VmmNative.MAX_PATH];
			boolean f = VmmNative.INSTANCE.VMMDLL_PdbLoad(hVMM, dwPID, vaModuleBase, szModuleName);
			if(!f) { throw new VmmException(); }
			this.pdbName = Native.toString(szModuleName);
		}
		
		private VmmPdbImpl(String pdbName) {
			this.pdbName = pdbName;
		}
		
		@Override
		public String toString() {
			return "VmmPdb:" + pdbName;
		}

		public String getModuleName() {
			return pdbName;
		}

		public long getSymbolAddress(String strSymbol) {
			LongByReference pvaSymbolAddress = new LongByReference();
			boolean f = VmmNative.INSTANCE.VMMDLL_PdbSymbolAddress(hVMM, pdbName, strSymbol, pvaSymbolAddress);
			if(!f) { throw new VmmException(); }
			return pvaSymbolAddress.getValue();
		}

		public String getSymbolName(long vaSymbolOrOffset) {
			IntByReference pdwSymbolDisplacement = new IntByReference();
			byte[] szSymbolName = new byte[VmmNative.MAX_PATH];
			boolean f = VmmNative.INSTANCE.VMMDLL_PdbSymbolName(hVMM, pdbName, vaSymbolOrOffset, szSymbolName, pdwSymbolDisplacement);
			if(!f) { throw new VmmException(); }
			return Native.toString(szSymbolName);
		}

		public int getTypeChildOffset(String strTypeName, String strChild) {
			IntByReference pcbTypeChildOffset = new IntByReference();
			boolean f = VmmNative.INSTANCE.VMMDLL_PdbTypeChildOffset(hVMM, pdbName, strTypeName, strChild, pcbTypeChildOffset);
			if(!f) { throw new VmmException(); }
			return pcbTypeChildOffset.getValue();
		}

		public int getTypeSize(String strTypeName) {
			IntByReference pcbTypeSize = new IntByReference();
			boolean f = VmmNative.INSTANCE.VMMDLL_PdbTypeSize(hVMM, pdbName, strTypeName, pcbTypeSize);
			if(!f) { throw new VmmException(); }
			return pcbTypeSize.getValue();
		}
	}
	
	
	
	//-----------------------------------------------------------------------------
	// VMM KERNEL FUNCTIONALITY BELOW:
	//-----------------------------------------------------------------------------

	public IVmmProcess kernelProcess()
	{
		return new VmmProcessImpl(4);
	}

	public IVmmPdb kernelPdb()
	{
		return new VmmPdbImpl("nt");
	}

	public int kernelBuildNumber()
	{
		return (int)getConfig(OPT_WIN_VERSION_BUILD);
	}
	
	
	
	//-----------------------------------------------------------------------------
	// VMM MAP FUNCTIONALITY BELOW:
	//-----------------------------------------------------------------------------
	
	public List<VmmMap_MemMapEntry> mapPhysicalMemory()
	{
		PointerByReference pptr = new PointerByReference();
		boolean f = VmmNative.INSTANCE.VMMDLL_Map_GetPhysMem(hVMM, pptr);
		if(!f) { throw new VmmException(); }
		VmmNative.VMMDLL_MAP_PHYSMEM pMap = new VmmNative.VMMDLL_MAP_PHYSMEM(pptr.getValue());
		// process result:
		ArrayList<VmmMap_MemMapEntry> result = new ArrayList<VmmMap_MemMapEntry>();
		for(VmmNative.VMMDLL_MAP_PHYSMEM_ENTRY n : pMap.pMap) {
			VmmMap_MemMapEntry e = new VmmMap_MemMapEntry();
			e.pa = n.pa;
			e.cb = n.cb;
			result.add(e);
		}
		VmmNative.INSTANCE.VMMDLL_MemFree(pptr.getValue());
		return result;
	}
	
	public List<VmmMap_NetEntry> mapNet()
	{
		PointerByReference pptr = new PointerByReference();
		boolean f = VmmNative.INSTANCE.VMMDLL_Map_GetNetU(hVMM, pptr);
		if(!f) { throw new VmmException(); }
		VmmNative.VMMDLL_MAP_NET pMap = new VmmNative.VMMDLL_MAP_NET(pptr.getValue());
		// process result:
		ArrayList<VmmMap_NetEntry> result = new ArrayList<VmmMap_NetEntry>();
		for(VmmNative.VMMDLL_MAP_NETENTRY n : pMap.pMap) {
			VmmMap_NetEntry e = new VmmMap_NetEntry();
			e.str = n.uszText;
			e.dwPid = n.dwPID;
			e.dwState = n.dwState;
			e.AF = n.AF;
			e.vaObj = n.vaObj;
			e.ftTime = n.ftTime;
			e.dwPoolTag = n.dwPoolTag;
			e.srcValid = n.Src.fValid;
			e.dstValid = n.Dst.fValid;
			e.srcPort = n.Src.port;
			e.dstPort = n.Dst.port;
			e.srcStr = n.Src.uszText;
			e.dstStr = n.Dst.uszText;
			result.add(e);
		}
		VmmNative.INSTANCE.VMMDLL_MemFree(pptr.getValue());
		return result;
	}
	
	public List<VmmMap_UserEntry> mapUser()
	{
		PointerByReference pptr = new PointerByReference();
		boolean f = VmmNative.INSTANCE.VMMDLL_Map_GetUsersU(hVMM, pptr);
		if(!f) { throw new VmmException(); }
		VmmNative.VMMDLL_MAP_USER pMap = new VmmNative.VMMDLL_MAP_USER(pptr.getValue());
		// process result:
		ArrayList<VmmMap_UserEntry> result = new ArrayList<VmmMap_UserEntry>();
		for(VmmNative.VMMDLL_MAP_USERENTRY n : pMap.pMap) {
			VmmMap_UserEntry e = new VmmMap_UserEntry();
			e.user = n.uszText;
			e.SID = n.uszSID;
			e.vaRegHive = n.vaRegHive;
			result.add(e);
		}
		VmmNative.INSTANCE.VMMDLL_MemFree(pptr.getValue());
		return result;
	}
	
	public List<VmmMap_ServiceEntry> mapService()
	{
		PointerByReference pptr = new PointerByReference();
		boolean f = VmmNative.INSTANCE.VMMDLL_Map_GetServicesU(hVMM, pptr);
		if(!f) { throw new VmmException(); }
		VmmNative.VMMDLL_MAP_SERVICE pMap = new VmmNative.VMMDLL_MAP_SERVICE(pptr.getValue());
		// process result:
		ArrayList<VmmMap_ServiceEntry> result = new ArrayList<VmmMap_ServiceEntry>();
		for(VmmNative.VMMDLL_MAP_SERVICEENTRY n : pMap.pMap) {
			VmmMap_ServiceEntry e = new VmmMap_ServiceEntry();
			e.vaObj = n.vaObj;
			e.dwOrdinal = n.dwOrdinal;
			e.dwStartType = n.dwStartType;
			e.uszServiceName = n.uszServiceName;
			e.uszDisplayName = n.uszDisplayName;
			e.uszPath = n.uszPath;
			e.uszUserTp = n.uszUserTp;
			e.uszUserAcct = n.uszUserAcct;
			e.uszImagePath = n.uszImagePath;
			e.dwPID = n.dwPID;
			e.dwServiceType = n.ServiceStatus.dwServiceType;
			e.dwCurrentState = n.ServiceStatus.dwCurrentState;
			e.dwControlsAccepted = n.ServiceStatus.dwControlsAccepted;
			e.dwWin32ExitCode = n.ServiceStatus.dwWin32ExitCode;
			e.dwServiceSpecificExitCode = n.ServiceStatus.dwServiceSpecificExitCode;
			e.dwCheckPoint = n.ServiceStatus.dwCheckPoint;
			e.dwWaitHint = n.ServiceStatus.dwWaitHint;
			result.add(e);
		}
		VmmNative.INSTANCE.VMMDLL_MemFree(pptr.getValue());
		return result;
	}
	
	public VmmMap_PoolMap mapPool(boolean isBigPoolOnly)
	{
		int flags = isBigPoolOnly ? VmmNative.VMMDLL_POOLMAP_FLAG_BIG : VmmNative.VMMDLL_POOLMAP_FLAG_ALL;
		PointerByReference pptr = new PointerByReference();
		boolean f = VmmNative.INSTANCE.VMMDLL_Map_GetPool(hVMM, pptr, flags);
		if(!f) { throw new VmmException(); }
		VmmNative.VMMDLL_MAP_POOL pMap = new VmmNative.VMMDLL_MAP_POOL(pptr.getValue());
		// process result:
		VmmMap_PoolMap result = new VmmMap_PoolMap();
		result.tag = new HashMap<String, Map<Long, VmmMap_PoolEntry>>();
		result.va = new HashMap<Long, VmmMap_PoolEntry>();
		Map<Long, VmmMap_PoolEntry> tagMap;
		for(VmmNative.VMMDLL_MAP_POOLENTRY n : pMap.pMap) {
			VmmMap_PoolEntry e = new VmmMap_PoolEntry();
			e.va = n.va;
			e.cb = n.cb;
			e.fAlloc = (n.fAlloc != 0);
			e.tpPool = n.tpPool;
			e.tpSS = n.tpSS;
			e.tag = Native.toString(n.tag);
			result.va.put(e.va, e);
			tagMap = result.tag.get(e.tag);
			if(tagMap == null) {
				tagMap = new HashMap<Long, VmmMap_PoolEntry>();
				result.tag.put(e.tag, tagMap);
			}
			tagMap.put(e.va, e);
		}
		VmmNative.INSTANCE.VMMDLL_MemFree(pptr.getValue());
		return result;
	}
	
	
	
	//-----------------------------------------------------------------------------
	// PROCESS INTERNAL FUNCTIONALITY BELOW:
	//-----------------------------------------------------------------------------
	
	private class VmmProcessImpl implements IVmmProcess
	{
		private int pid;
		private VmmNative.VMMDLL_PROCESS_INFORMATION info;
		
		private VmmProcessImpl(int pid) {
			this.pid = pid;
			this.info = null;
		}
		
		/*
		 * Ensure process information is loaded
		 */
		private void ensure() {
			if(this.info == null) {
				LongByReference pcbInfo = new LongByReference();
				VmmNative.VMMDLL_PROCESS_INFORMATION pInfo = new VmmNative.VMMDLL_PROCESS_INFORMATION();
				pcbInfo.setValue(Native.getNativeSize(VmmNative.VMMDLL_PROCESS_INFORMATION.class, pInfo));
				pInfo.magic = VmmNative.MMDLL_PROCESS_INFORMATION_MAGIC;
				pInfo.wVersion = VmmNative.VMMDLL_PROCESS_INFORMATION_VERSION;
				boolean f = VmmNative.INSTANCE.VMMDLL_ProcessGetInformation(hVMM, pid, pInfo, pcbInfo);
				if(!f) { throw new VmmException(); }
				if(pInfo.wVersion != VmmNative.VMMDLL_PROCESS_INFORMATION_VERSION) { throw new VmmException("Bad Version"); }
				this.info = pInfo;
			}
		}
		
		@Override
		public String toString() {
			return "VmmProcess:" + String.valueOf(pid);
		}
		
		public int getPID() {
			return pid;
		}

		public byte[] memRead(long va, int size) {
			return _memRead(pid, va, size);
		}

		public byte[] memRead(long va, int size, int flags) {
			return _memRead(pid, va, size, flags);
		}

		public void memWrite(long va, byte[] data) {
			_memWrite(pid, va, data);
		}

		public void memPrefetchPages(long[] vas) {
			_memPrefetchPages(pid, vas);
		}

		public IVmmMemScatterMemory memScatterInitialize(int flags) {
			return _memScatterInitialize(pid, flags);
		}

		public long memVirtualToPhysical(long va) {
			return _memVirtualToPhysical(pid, va);
		}

		public List<VmmMap_HandleEntry> mapHandle() {
			PointerByReference pptr = new PointerByReference();
			boolean f = VmmNative.INSTANCE.VMMDLL_Map_GetHandleU(hVMM, pid, pptr);
			if(!f) { throw new VmmException(); }
			VmmNative.VMMDLL_MAP_HANDLE pMap = new VmmNative.VMMDLL_MAP_HANDLE(pptr.getValue());
			// process result:
			ArrayList<VmmMap_HandleEntry> result = new ArrayList<VmmMap_HandleEntry>();
			for(VmmNative.VMMDLL_MAP_HANDLEENTRY n : pMap.pMap) {
				VmmMap_HandleEntry e = new VmmMap_HandleEntry();
				e.vaObject = n.vaObject;
				e.dwHandle = n.dwHandle;
				e._dwGrantedAccess_iType = n._dwGrantedAccess_iType;
				e.qwHandleCount = n.qwHandleCount;
				e.qwPointerCount = n.qwPointerCount;
				e.vaObjectCreateInfo = n.vaObjectCreateInfo;
				e.vaSecurityDescriptor = n.vaSecurityDescriptor;
				e.name = n.uszText;
				e.dwPID = n.dwPID;
				e.tag = Native.toString(n.dwPoolTag);
				e.type = n.uszType;
				result.add(e);
			}
			VmmNative.INSTANCE.VMMDLL_MemFree(pptr.getValue());
			return result;
		}

		public List<VmmMap_HeapAllocEntry> mapHeapAlloc(long qwHeapNumOrAddress) {
			PointerByReference pptr = new PointerByReference();
			boolean f = VmmNative.INSTANCE.VMMDLL_Map_GetHeapAlloc(hVMM, pid, qwHeapNumOrAddress, pptr);
			if(!f) { throw new VmmException(); }
			VmmNative.VMMDLL_MAP_HEAPALLOC pMap = new VmmNative.VMMDLL_MAP_HEAPALLOC(pptr.getValue());
			// process result:
			// process result:
			ArrayList<VmmMap_HeapAllocEntry> result = new ArrayList<VmmMap_HeapAllocEntry>();
			for(VmmNative.VMMDLL_MAP_HEAPALLOCENTRY n : pMap.pMap) {
				VmmMap_HeapAllocEntry e = new VmmMap_HeapAllocEntry();
				e.va = n.va;
				e.cb = n.cb;
				e.tp = n.tp;
				result.add(e);
			}
			VmmNative.INSTANCE.VMMDLL_MemFree(pptr.getValue());
			return result;
		}

		public VmmMap_HeapMap mapHeap() {
			PointerByReference pptr = new PointerByReference();
			boolean f = VmmNative.INSTANCE.VMMDLL_Map_GetHeap(hVMM, pid, pptr);
			if(!f) { throw new VmmException(); }
			VmmNative.VMMDLL_MAP_HEAP pMap = new VmmNative.VMMDLL_MAP_HEAP(pptr.getValue());
			// process result:
			VmmMap_HeapMap result = new VmmMap_HeapMap();
			result.heaps = new ArrayList<VmmMap_HeapEntry>();
			result.segments = new ArrayList<VmmMap_HeapSegmentEntry>();
			for(VmmNative.VMMDLL_MAP_HEAPENTRY n : pMap.pMap) {
				VmmMap_HeapEntry e = new VmmMap_HeapEntry();
				e.va = n.va;
				e.tp = n.tp;
				e.f32 = n.f32;
				e.iHeap = n.iHeap;
				e.dwHeapNum = n.dwHeapNum;
				result.heaps.add(e);
			}
			for(VmmNative.VMMDLL_MAP_HEAP_SEGMENTENTRY n : pMap.pSegments) {
				VmmMap_HeapSegmentEntry e = new VmmMap_HeapSegmentEntry();
				e.va = n.va;
				e.cb = n.cb;
				e.tp = n.tp;
				e.iHeap = n.iHeap;
				result.segments.add(e);
			}
			VmmNative.INSTANCE.VMMDLL_MemFree(pptr.getValue());
			return result;
		}

		public List<VmmMap_PteEntry> mapPte() {
			PointerByReference pptr = new PointerByReference();
			boolean f = VmmNative.INSTANCE.VMMDLL_Map_GetPteU(hVMM, pid, true, pptr);
			if(!f) { throw new VmmException(); }
			VmmNative.VMMDLL_MAP_PTE pMap = new VmmNative.VMMDLL_MAP_PTE(pptr.getValue());
			// process result:
			ArrayList<VmmMap_PteEntry> result = new ArrayList<VmmMap_PteEntry>();
			for(VmmNative.VMMDLL_MAP_PTEENTRY n : pMap.pMap) {
				VmmMap_PteEntry e = new VmmMap_PteEntry();
				e.vaBase = n.vaBase;
				e.cPages = n.cPages;
				e.fPage = n.fPage;
				e.fWow64 = n.fWow64;
				e.strDescription = n.uszText;
				e.cSoftware = n.cSoftware;
				result.add(e);
			}
			VmmNative.INSTANCE.VMMDLL_MemFree(pptr.getValue());
			return result;
		}

		public List<VmmMap_ThreadEntry> mapThread() {
			PointerByReference pptr = new PointerByReference();
			boolean f = VmmNative.INSTANCE.VMMDLL_Map_GetThread(hVMM, pid, pptr);
			if(!f) { throw new VmmException(); }
			VmmNative.VMMDLL_MAP_THREAD pMap = new VmmNative.VMMDLL_MAP_THREAD(pptr.getValue());
			// process result:
			ArrayList<VmmMap_ThreadEntry> result = new ArrayList<VmmMap_ThreadEntry>();
			for(VmmNative.VMMDLL_MAP_THREADENTRY n : pMap.pMap) {
				VmmMap_ThreadEntry e = new VmmMap_ThreadEntry();
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
				e.vaTrapFrame = n.vaTrapFrame;
				e.vaImpersonationToken = n.vaImpersonationToken;
				e.vaRIP = n.vaRIP;
				e.vaRSP = n.vaRSP;
				e.qwAffinity = n.qwAffinity;
				e.dwUserTime = n.dwUserTime;
				e.dwKernelTime = n.dwKernelTime;
				e.bSuspendCount = n.bSuspendCount;
				e.bWaitReason = n.bWaitReason;
				result.add(e);
			}
			VmmNative.INSTANCE.VMMDLL_MemFree(pptr.getValue());
			return result;
		}

		public List<VmmMap_UnloadedModuleEntry> mapUnloadedModule() {
			PointerByReference pptr = new PointerByReference();
			boolean f = VmmNative.INSTANCE.VMMDLL_Map_GetUnloadedModuleU(hVMM, pid, pptr);
			if(!f) { throw new VmmException(); }
			VmmNative.VMMDLL_MAP_UNLOADEDMODULE pMap = new VmmNative.VMMDLL_MAP_UNLOADEDMODULE(pptr.getValue());
			// process result:
			ArrayList<VmmMap_UnloadedModuleEntry> result = new ArrayList<VmmMap_UnloadedModuleEntry>();
			for(VmmNative.VMMDLL_MAP_UNLOADEDMODULEENTRY n : pMap.pMap) {
				VmmMap_UnloadedModuleEntry e = new VmmMap_UnloadedModuleEntry();
				e.vaBase = n.vaBase;
				e.cbImageSize = n.cbImageSize;
				e.fWow64 = n.fWow64;
				e.strModuleName = n.uszText;
				e.dwCheckSum = n.dwCheckSum;
				e.dwTimeDateStamp = n.dwTimeDateStamp;
				e.ftUnload = n.ftUnload;
				result.add(e);
			}
			VmmNative.INSTANCE.VMMDLL_MemFree(pptr.getValue());
			return result;
		}

		public List<VmmMap_VadEntry> mapVad() {
			PointerByReference pptr = new PointerByReference();
			boolean f = VmmNative.INSTANCE.VMMDLL_Map_GetVadU(hVMM, pid, true, pptr);
			if(!f) { throw new VmmException(); }
			VmmNative.VMMDLL_MAP_VAD pMap = new VmmNative.VMMDLL_MAP_VAD(pptr.getValue());
			// process result:
			ArrayList<VmmMap_VadEntry> result = new ArrayList<VmmMap_VadEntry>();
			for(VmmNative.VMMDLL_MAP_VADENTRY n : pMap.pMap) {
				VmmMap_VadEntry e = new VmmMap_VadEntry();
				e.vaStart = n.vaStart;
				e.vaEnd = n.vaEnd;
				e.vaVad = n.vaVad;
				e.dw0 = n.dw0;
				e.dw1 = n.dw1;
				e.dwu2 = n.dwu2;
				e.cbPrototypePte = n.cbPrototypePte;
				e.vaPrototypePte = n.vaPrototypePte;
				e.vaSubsection = n.vaSubsection;
				e.uszText = n.uszText;
				e.vaFileObject = n.vaFileObject;
				e.cVadExPages = n.cVadExPages;
				e.cVadExPagesBase = n.cVadExPagesBase;
				result.add(e);
			}
			VmmNative.INSTANCE.VMMDLL_MemFree(pptr.getValue());
			return result;
		}

		public List<VmmMap_VadExEntry> mapVadEx(int oPage, int cPage) {
			PointerByReference pptr = new PointerByReference();
			boolean f = VmmNative.INSTANCE.VMMDLL_Map_GetVadEx(hVMM, pid, oPage, cPage, pptr);
			if(!f) { throw new VmmException(); }
			VmmNative.VMMDLL_MAP_VADEX pMap = new VmmNative.VMMDLL_MAP_VADEX(pptr.getValue());
			// process result:
			ArrayList<VmmMap_VadExEntry> result = new ArrayList<VmmMap_VadExEntry>();
			for(VmmNative.VMMDLL_MAP_VADEXENTRY n : pMap.pMap) {
				VmmMap_VadExEntry e = new VmmMap_VadExEntry();
				e.tp = n.tp;
				e.iPML = Byte.toUnsignedInt(n.iPML);
				e.pteFlags = Byte.toUnsignedInt(n.pteFlags);
				e.va = n.va;
				e.pa = n.pa;
				e.pte = n.pte;
				e.proto_tp = n.proto_tp;
				e.proto_pa = n.proto_pa;
				e.proto_pte = n.proto_pte;
				e.vaVadBase = n.vaVadBase;
				result.add(e);
			}
			VmmNative.INSTANCE.VMMDLL_MemFree(pptr.getValue());
			return result;
		}

		public int getPPID() {
			ensure();
			return info.dwPPID;
		}

		public long getEPROCESS() {
			ensure();
			return info.vaEPROCESS;
		}

		public long getDTB() {
			ensure();
			return info.paDTB;
		}
		
		public long getDTBUser() {
			ensure();
			return info.paDTB_UserOpt;
		}

		public int getState() {
			ensure();
			return info.dwState;
		}

		public long getPEB() {
			ensure();
			return info.vaPEB;
		}

		public int getPEB32() {
			ensure();
			return info.vaPEB32;
		}

		public boolean isWow64() {
			ensure();
			return info.fWow64;
		}

		public boolean isUserMode() {
			ensure();
			return info.fUserOnly;
		}

		public String getName() {
			ensure();
			return Native.toString(info.szName);
		}

		public String getNameFull() {
			ensure();
			return Native.toString(info.szNameLong);
		}

		public String getPathUser() {
			Pointer p = VmmNative.INSTANCE.VMMDLL_ProcessGetInformationString(hVMM, pid, VmmNative.VMMDLL_PROCESS_INFORMATION_OPT_STRING_PATH_USER_IMAGE);
			String s = p.getString(0);
			VmmNative.INSTANCE.VMMDLL_MemFree(p);
			return s;
		}
		
		public String getCmdLine() {
			Pointer p = VmmNative.INSTANCE.VMMDLL_ProcessGetInformationString(hVMM, pid, VmmNative.VMMDLL_PROCESS_INFORMATION_OPT_STRING_CMDLINE);
			String s = p.getString(0);
			VmmNative.INSTANCE.VMMDLL_MemFree(p);
			return s;
		}

		public String getPathKernel() {
			Pointer p  = VmmNative.INSTANCE.VMMDLL_ProcessGetInformationString(hVMM, pid, VmmNative.VMMDLL_PROCESS_INFORMATION_OPT_STRING_PATH_KERNEL);
			String s = p.getString(0);
			VmmNative.INSTANCE.VMMDLL_MemFree(p);
			return s;
		}

		public int getTpMemoryModel() {
			ensure();
			return info.tpMemoryModel;
		}

		public int getTpSystem() {
			ensure();
			return info.tpSystem;
		}

		public long GetLUID() {
			ensure();
			return info.qwLUID;
		}

		public int GetSessionID() {
			ensure();
			return info.dwSessionId;
		}

		public String getSID() {
			return Native.toString(info.szSID);
		}

		public IVmmModule moduleGet(long va, boolean isExtendedInfo) {
			for(IVmmModule m : moduleGetAll(isExtendedInfo)) {
				if((va >= m.getVaBase()) && (va <= m.getVaBase() + m.getSize())) {
					return m;
				}
			}
			return null;
		}

		public IVmmModule moduleGet(String name, boolean isExtendedInfo) {
			int flags = VmmNative.VMMDLL_MODULE_FLAG_NORMAL;
			if(isExtendedInfo) {
				flags = VmmNative.VMMDLL_MODULE_FLAG_DEBUGINFO + VmmNative.VMMDLL_MODULE_FLAG_VERSIONINFO;
			}
			PointerByReference pptr = new PointerByReference();
			boolean f = VmmNative.INSTANCE.VMMDLL_Map_GetModuleFromNameU(hVMM, pid, name, pptr, flags);
			if(!f) { throw new VmmException(); }
			VmmNative.VMMDLL_MAP_MODULEENTRY pEntry = new VmmNative.VMMDLL_MAP_MODULEENTRY(pptr.getValue());
			VmmNative.VMMDLL_MAP_MODULEENTRY_DEBUGINFO pDebugEntry = null;
			if(pEntry.pExDebugInfo != 0) {
				pDebugEntry = new VmmNative.VMMDLL_MAP_MODULEENTRY_DEBUGINFO(new PointerByReference(new Pointer(pEntry.pExDebugInfo)).getValue());
			}
			VmmNative.VMMDLL_MAP_MODULEENTRY_VERSIONINFO pVersionEntry = null;
			if(pEntry.pExVersionInfo != 0) {
				pVersionEntry = new VmmNative.VMMDLL_MAP_MODULEENTRY_VERSIONINFO(new PointerByReference(new Pointer(pEntry.pExVersionInfo)).getValue());
			}
			VmmNative.INSTANCE.VMMDLL_MemFree(pptr.getValue());
			return new VmmImpl.VmmModuleImpl(this, pEntry, pDebugEntry, pVersionEntry);
		}

		public List<IVmmModule> moduleGetAll(boolean isExtendedInfo) {
			int flags = VmmNative.VMMDLL_MODULE_FLAG_NORMAL;
			if(isExtendedInfo) {
				flags = VmmNative.VMMDLL_MODULE_FLAG_DEBUGINFO + VmmNative.VMMDLL_MODULE_FLAG_VERSIONINFO;
			}
			PointerByReference pptr = new PointerByReference();
			boolean f = VmmNative.INSTANCE.VMMDLL_Map_GetModuleU(hVMM, pid, pptr, flags);
			if(!f) { throw new VmmException(); }
			VmmNative.VMMDLL_MAP_MODULE pMap = new VmmNative.VMMDLL_MAP_MODULE(pptr.getValue());
			// process result:
			ArrayList<IVmmModule> result = new ArrayList<IVmmModule>();
			for(VmmNative.VMMDLL_MAP_MODULEENTRY n : pMap.pMap) {
				VmmNative.VMMDLL_MAP_MODULEENTRY_DEBUGINFO pDebugEntry = null;
				if(n.pExDebugInfo != 0) {
					pDebugEntry = new VmmNative.VMMDLL_MAP_MODULEENTRY_DEBUGINFO(new PointerByReference(new Pointer(n.pExDebugInfo)).getValue());
				}
				VmmNative.VMMDLL_MAP_MODULEENTRY_VERSIONINFO pVersionEntry = null;
				if(n.pExVersionInfo != 0) {
					pVersionEntry = new VmmNative.VMMDLL_MAP_MODULEENTRY_VERSIONINFO(new PointerByReference(new Pointer(n.pExVersionInfo)).getValue());
				}
				result.add(new VmmImpl.VmmModuleImpl(this, n, pDebugEntry, pVersionEntry));
			}
			VmmNative.INSTANCE.VMMDLL_MemFree(pptr.getValue());
			return result;
		}
	}
	
	
	
	//-----------------------------------------------------------------------------
	// VMM PROCESS FUNCTIONALITY BELOW:
	//-----------------------------------------------------------------------------

	public IVmmProcess processGet(int pid)
	{
		VmmProcessImpl p = new VmmProcessImpl(pid);
		p.ensure();
		return p;
	}

	public IVmmProcess processGet(String name)
	{
		IntByReference pdwPID = new IntByReference();
		boolean f = VmmNative.INSTANCE.VMMDLL_PidGetFromName(hVMM, _utilStringToCString(name), pdwPID);
		if(!f) { throw new VmmException(); }
		return new VmmProcessImpl(pdwPID.getValue()); 
	}

	public List<IVmmProcess> processGetAll()
	{
		LongByReference pcPIDs = new LongByReference();
		boolean f = VmmNative.INSTANCE.VMMDLL_PidList(hVMM, null, pcPIDs);
		if(!f) { throw new VmmException(); }
		int[] pids = new int[(int)pcPIDs.getValue()];
		f = VmmNative.INSTANCE.VMMDLL_PidList(hVMM, pids, pcPIDs);
		if(!f) { throw new VmmException(); }
		// process result:
		ArrayList<IVmmProcess> result = new ArrayList<IVmmProcess>();
		for(int pid : pids) {
			if(pid != 0) {
				result.add(new VmmProcessImpl(pid));
			}
		}
		return result;
	}
	
	
	
	//-----------------------------------------------------------------------------
	// MODULE INTERNAL FUNCTIONALITY BELOW:
	//-----------------------------------------------------------------------------
	
	private class VmmModuleImpl implements IVmmModule
	{
		private IVmmProcess process;
		private int pid;
		private VmmNative.VMMDLL_MAP_MODULEENTRY module;
		private VmmNative.VMMDLL_MAP_MODULEENTRY_DEBUGINFO debug;
		private VmmNative.VMMDLL_MAP_MODULEENTRY_VERSIONINFO version;
		
		
		private VmmModuleImpl(IVmmProcess process, VmmNative.VMMDLL_MAP_MODULEENTRY module, VmmNative.VMMDLL_MAP_MODULEENTRY_DEBUGINFO debug, VmmNative.VMMDLL_MAP_MODULEENTRY_VERSIONINFO version) {
			this.module = module;
			this.debug = debug;
			this.version = version;
			this.process = process;
			this.pid = process.getPID();
		}
		
		@Override
		public String toString() {
			return "VmmModule:" + String.valueOf(pid) + ":" + module.uszText;
		}

		public IVmmProcess getProcess() {
			return process;
		}

		public String getName() {
			return module.uszText;
		}
		
		public String getNameFull() {
			return module.uszFullName;
		}

		public long getVaBase() {
			return module.vaBase;
		}

		public long getVaEntry() {
			return module.vaEntry;
		}

		public int getSize() {
			return module.cbImageSize;
		}
		
		public int getSizeFile() {
			return module.cbFileSizeRaw;
		}

		public boolean isWow64() {
			return module.fWoW64;
		}

		public int getCountSection() {
			return module.cSection;
		}

		public int getCountEAT() {
			return module.cEAT;
		}

		public int getCountIAT() {
			return module.cIAT;
		}
			
		public Vmm_ModuleExDebugInfo getExDebugInfo() {
			if(debug == null) {
				return null;
			}
			Vmm_ModuleExDebugInfo n = new Vmm_ModuleExDebugInfo();
			n.dwAge = debug.dwAge;
			n.Guid = debug.uszGuid;
			n.GuidBytes = debug.Guid;
			n.PdbFilename = debug.uszPdbFilename;
			return n;
		}
		
		public Vmm_ModuleExVersionInfo getExVersionInfo() {
			if(version == null) {
				return null;
			}
			Vmm_ModuleExVersionInfo n = new Vmm_ModuleExVersionInfo();
			n.CompanyName = version.uszCompanyName;
			n.FileDescription = version.uszFileDescription;
			n.FileVersion = version.uszFileVersion;
			n.InternalName = version.uszInternalName;
			n.LegalCopyright = version.uszLegalCopyright;
			n.OriginalFilename = version.uszOriginalFilename;
			n.ProductName = version.uszProductName;
			n.ProductVersion = version.uszProductVersion;
			return n;
		}

		public long getProcAddress(String szFunctionName) {
			return VmmNative.INSTANCE.VMMDLL_ProcessGetProcAddressU(hVMM, pid, module.uszText, szFunctionName);
		}

		@Override
		public List<VmmMap_ModuleDataDirectory> mapDataDirectory() {
			final String[] DIRECTORIES = { "EXPORT", "IMPORT", "RESOURCE", "EXCEPTION", "SECURITY", "BASERELOC", "DEBUG", "ARCHITECTURE", "GLOBALPTR", "TLS", "LOAD_CONFIG", "BOUND_IMPORT", "IAT", "DELAY_IMPORT", "COM_DESCRIPTOR", "RESERVED" };
			VmmNative.IMAGE_DATA_DIRECTORY[] aData = new VmmNative.IMAGE_DATA_DIRECTORY[16];
			boolean f = VmmNative.INSTANCE.VMMDLL_ProcessGetDirectoriesU(hVMM, pid, module.uszText, aData);
			if(!f) { throw new VmmException(); }
			// process result:
			ArrayList<VmmMap_ModuleDataDirectory> result = new ArrayList<VmmMap_ModuleDataDirectory>();
			for(int i = 0; i < 16; i++) {
				VmmNative.IMAGE_DATA_DIRECTORY n = aData[i];
				VmmMap_ModuleDataDirectory e = new VmmMap_ModuleDataDirectory();
				e.RealVirtualAddress = n.VirtualAddress + module.vaBase;
				e.VirtualAddress = n.VirtualAddress;
				e.Size = n.Size;
				e.name = DIRECTORIES[i];
				result.add(e);
			}
			return result;
		}
		
		public List<VmmMap_ModuleSection> mapSection() {
			IntByReference pcData = new IntByReference();
			boolean f = VmmNative.INSTANCE.VMMDLL_ProcessGetSectionsU(hVMM, pid, module.uszText, null, 0, pcData);
			if(!f) { throw new VmmException(); }
			int cData = pcData.getValue();
			VmmNative.IMAGE_SECTION_HEADER[] aData = new VmmNative.IMAGE_SECTION_HEADER[cData];
			f = VmmNative.INSTANCE.VMMDLL_ProcessGetSectionsU(hVMM, pid, module.uszText, aData, cData, pcData);
			if(!f) { throw new VmmException(); }
			// process result:
			ArrayList<VmmMap_ModuleSection> result = new ArrayList<VmmMap_ModuleSection>();
			for(VmmNative.IMAGE_SECTION_HEADER n : aData) {
				VmmMap_ModuleSection e = new VmmMap_ModuleSection();
				e.name = Native.toString(n.name);
				e.MiscVirtualSize = n.MiscVirtualSize;
				e.VirtualAddress = n.VirtualAddress;
				e.SizeOfRawData = n.SizeOfRawData;
				e.PointerToRawData = n.PointerToRawData;
				e.PointerToRelocations = n.PointerToRelocations;
				e.PointerToLinenumbers = n.PointerToLinenumbers;
				e.NumberOfRelocations = n.NumberOfRelocations;
				e.NumberOfLinenumbers = n.NumberOfLinenumbers;
				e.Characteristics = n.Characteristics;
				result.add(e);
			}
			return result;
		}

		public List<VmmMap_ModuleExport> mapExport() {
			PointerByReference pptr = new PointerByReference();
			boolean f = VmmNative.INSTANCE.VMMDLL_Map_GetEATU(hVMM, pid, module.uszText, pptr);
			if(!f) { throw new VmmException(); }
			VmmNative.VMMDLL_MAP_EAT pMap = new VmmNative.VMMDLL_MAP_EAT(pptr.getValue());
			// process result:
			ArrayList<VmmMap_ModuleExport> result = new ArrayList<VmmMap_ModuleExport>();
			for(VmmNative.VMMDLL_MAP_EATENTRY n : pMap.pMap) {
				VmmMap_ModuleExport e = new VmmMap_ModuleExport();
				e.vaFunction = n.vaFunction;
				e.dwOrdinal = n.dwOrdinal;
				e.oFunctionsArray = n.oFunctionsArray;
				e.oNamesArray = n.oNamesArray;
				e.uszFunction = n.uszFunction;
				e.uszForwardedFunction = n.uszForwardedFunction;
				e.uszModule = module.uszText;
				result.add(e);
			}
			VmmNative.INSTANCE.VMMDLL_MemFree(pptr.getValue());
			return result;
		}

		public List<VmmMap_ModuleImport> mapImport() {
			PointerByReference pptr = new PointerByReference();
			boolean f = VmmNative.INSTANCE.VMMDLL_Map_GetIATU(hVMM, pid, module.uszText, pptr);
			if(!f) { throw new VmmException(); }
			VmmNative.VMMDLL_MAP_IAT pMap = new VmmNative.VMMDLL_MAP_IAT(pptr.getValue());
			// process result:
			ArrayList<VmmMap_ModuleImport> result = new ArrayList<VmmMap_ModuleImport>();
			for(VmmNative.VMMDLL_MAP_IATENTRY n : pMap.pMap) {
				VmmMap_ModuleImport e = new VmmMap_ModuleImport();
				e.vaFunction = n.vaFunction;
				e.uszFunction = n.uszFunction;
				e.uszModule = n.uszModule;
				e.f32 = n.f32;
				e.wHint = n.wHint;
				e.rvaFirstThunk = n.rvaFirstThunk;
				e.rvaOriginalFirstThunk = n.rvaOriginalFirstThunk;
				e.rvaNameModule = n.rvaNameModule;
				e.rvaNameFunction = n.rvaNameFunction;
				result.add(e);
			}
			VmmNative.INSTANCE.VMMDLL_MemFree(pptr.getValue());
			return result;
		}

		public IVmmPdb getPdb() {
			return new VmmImpl.VmmPdbImpl(pid, module.vaBase);
		}
	}
	
	
	
	//-----------------------------------------------------------------------------
	// REGISTRY INTERNAL FUNCTIONALITY BELOW:
	//-----------------------------------------------------------------------------
	
	private class VmmRegHiveImpl implements IVmmRegHive {
		private VmmNative.VMMDLL_REGISTRY_HIVE_INFORMATION hive;
		
		VmmRegHiveImpl(VmmNative.VMMDLL_REGISTRY_HIVE_INFORMATION hive)
		{
			this.hive = hive;
		}
		
		@Override
		public String toString() {
			return String.format("VmmRegHive:0x%016x", hive.vaCMHIVE);
		}

		public String getName() {
			return Native.toString(hive.uszName);
		}

		public String getNameShort() {
			return Native.toString(hive.uszNameShort);
		}

		public String getPath() {
			return Native.toString(hive.uszHiveRootPath);
		}
		
		public int getSize() {
			return hive.cbLength;
		}

		public long getVaHive() {
			return hive.vaCMHIVE;
		}

		public long getVaBaseBlock() {
			return hive.vaHBASE_BLOCK;
		}
		
		public byte[] memRead(int ra, int size) {
			return memRead(ra, size, 0);
		}

		public byte[] memRead(int ra, int size, int flags) {
			IntByReference pcbRead = new IntByReference();
			Pointer pb = new Memory(size);
			boolean f = VmmNative.INSTANCE.VMMDLL_WinReg_HiveReadEx(hVMM, hive.vaCMHIVE, ra, pb, size, pcbRead, flags);
			if(!f) { throw new VmmException(); }
			size = Math.min(size, pcbRead.getValue());
			byte[] result = new byte[size];
			pb.read(0, result, 0, size);
			return result;
		}

		public void memWrite(int ra, byte[] data) {
			boolean f = VmmNative.INSTANCE.VMMDLL_WinReg_HiveWrite(hVMM, hive.vaCMHIVE, ra, data, data.length);
			if(!f) { throw new VmmException(); }
		}

		public IVmmRegKey getKeyRoot() {
			String strKeyPath = String.format("0x%016x\\ROOT", hive.vaCMHIVE);
			return new VmmRegKeyImpl(strKeyPath);
		}

		public IVmmRegKey getKeyOrphan() {
			String strKeyPath = String.format("0x%016llx\\ORPHAN", hive.vaCMHIVE);
			return new VmmRegKeyImpl(strKeyPath);
		}
	}
	
	private class VmmRegKeyImpl implements IVmmRegKey {
		private String strPath;
		private String strName;
		
		private VmmRegKeyImpl(String strPath)
		{
			strName = strPath.substring(strPath.lastIndexOf('\\') + 1);
			this.strPath = strPath;
		}
		
		@Override
		public String toString() {
			return "VmmRegKey:" + strName;
		}

		public String getName() {
			return strName;
		}

		public String getPath() {
			return strPath;
		}

		public IVmmRegKey getKeyParent() {
			int i = strPath.lastIndexOf('\\');
			String strParent = strPath.substring(0, i);
			if(-1 == strParent.indexOf('\\')) {
				return null;
			}
			return new VmmRegKeyImpl(strParent);
		}

		public Map<String, IVmmRegKey> getKeyChild() {
			int i = 0;
			byte[] lpName = new byte[VmmNative.MAX_PATH];
			IntByReference lpcchName = new IntByReference(VmmNative.MAX_PATH);
			HashMap<String, IVmmRegKey> result = new HashMap<String, IVmmRegKey>();
			while(VmmNative.INSTANCE.VMMDLL_WinReg_EnumKeyExU(hVMM, strPath, i, lpName, lpcchName, null)) {
				String strName = Native.toString(lpName);
				result.put(strName, new VmmRegKeyImpl(strPath + "\\" + strName));
				i++;
			}
			return result;
		}

		public Map<String, IVmmRegValue> getValues() {
			int i = 0;
			byte[] lpValueName = new byte[VmmNative.MAX_PATH];
			IntByReference lpcchValueName = new IntByReference(VmmNative.MAX_PATH);
			IntByReference lpType = new IntByReference();
			HashMap<String, IVmmRegValue> result = new HashMap<String, IVmmRegValue>();
			while(VmmNative.INSTANCE.VMMDLL_WinReg_EnumValueU(hVMM, strPath, i, lpValueName, lpcchValueName, lpType, null, null)) {
				String strName = Native.toString(lpValueName);
				result.put(strName, new VmmRegValueImpl(strPath + "\\" + strName, lpType.getValue()));
				i++;
			}
			return result;
		}

		public long getTime() {
			IntByReference cch = new IntByReference();
			LongByReference lpftLastWriteTime = new LongByReference();
			boolean f = VmmNative.INSTANCE.VMMDLL_WinReg_EnumKeyExU(hVMM, strPath, -1, null, cch, lpftLastWriteTime);
			if(!f) { throw new VmmException(); }
			return lpftLastWriteTime.getValue();
		}
	}
	
	private class VmmRegValueImpl implements IVmmRegValue {
		private String strPath;
		private String strName;
		private int dwType;
		
		private VmmRegValueImpl(String strPath, int dwType)
		{
			this.strName = strPath.substring(strPath.lastIndexOf('\\') + 1);
			this.strPath = strPath;
			this.dwType = dwType;
		}
		
		@Override
		public String toString() {
			return "VmmRegValue:" + strName;
		}

		public String getName() {
			return strName;
		}

		public byte[] getValue() {
			IntByReference lpType = new IntByReference();
			IntByReference lpcbData = new IntByReference();
			boolean f = VmmNative.INSTANCE.VMMDLL_WinReg_QueryValueExU(hVMM, strPath, lpType, null, lpcbData);
			if(!f) { throw new VmmException(); }
			byte[] data = new byte[lpcbData.getValue()];
			f = VmmNative.INSTANCE.VMMDLL_WinReg_QueryValueExU(hVMM, strPath, lpType, data, lpcbData);
			if(!f) { throw new VmmException(); }
			return data;
		}

		public String getValueAsString() {
			return Native.toString(getValue(), "UTF-16LE");
		}

		public String getPath() {
			return strPath;
		}

		public IVmmRegKey getKeyParent() {
			int i = strPath.lastIndexOf('\\');
			String strParent = strPath.substring(0, i);
			if(-1 == strParent.indexOf('\\')) {
				return null;
			}
			return new VmmRegKeyImpl(strParent);
		}

		public int getValueAsDword() {
			byte[] v = getValue();
			if(v.length != 4) {
				throw new VmmException("VmmRegValue not DWORD-sized (4)");
			}
			return java.nio.ByteBuffer.wrap(v).order(java.nio.ByteOrder.LITTLE_ENDIAN).getInt();
		}

		public int getType() {
			return dwType;
		}
		
	}

	public List<IVmmRegHive> regHive() {
		IntByReference pcHives = new IntByReference();
		boolean f = VmmNative.INSTANCE.VMMDLL_WinReg_HiveList(hVMM, null, 0, pcHives);
		if(!f) { throw new VmmException(); }
		int cHives = pcHives.getValue();
		VMMDLL_REGISTRY_HIVE_INFORMATION[] pHives = new VMMDLL_REGISTRY_HIVE_INFORMATION[cHives];
		f = VmmNative.INSTANCE.VMMDLL_WinReg_HiveList(hVMM, pHives, cHives, pcHives);
		if(!f) { throw new VmmException(); }
		cHives = pcHives.getValue();
		ArrayList<IVmmRegHive> result = new ArrayList<IVmmRegHive>();
		for(VMMDLL_REGISTRY_HIVE_INFORMATION pHive : pHives) {
			result.add(new VmmRegHiveImpl(pHive));
		}
		return result;
	}

	public IVmmRegKey regKey(String strFullPath) {
		IntByReference lpcchName = new IntByReference();
		boolean f = VmmNative.INSTANCE.VMMDLL_WinReg_EnumKeyExU(hVMM, strFullPath, -1, null, lpcchName, null);
		if(!f) { return null; }
		return new VmmRegKeyImpl(strFullPath);
	}

	public IVmmRegValue regValue(String strFullPath) {
		IntByReference lpType = new IntByReference();
		IntByReference lpcbData = new IntByReference();
		boolean f = VmmNative.INSTANCE.VMMDLL_WinReg_QueryValueExU(hVMM, strFullPath, lpType, null, lpcbData);
		if(!f) { return null; }
		return new VmmRegValueImpl(strFullPath, lpType.getValue());
	}
}
