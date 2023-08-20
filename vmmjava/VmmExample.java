import vmm.*;
import vmm.entry.*;
import leechcore.*;
import leechcore.entry.LeechCoreBar;
import leechcore.entry.LeechCoreBarRequest;

import java.util.*;

/**
 * MemProcFS example code how use the Java wrapper API for the native library.
 * More functionality exists, please check the interfaces for more information.
 * @see https://github.com/ufrisk/MemProcFS
 * @author Ulf Frisk - pcileech@frizk.net
 */
public class VmmExample {
	
	public static String strPathToNativeBinaries = "C:\\Github\\MemProcFS-dev\\files";
	public static String[] argvMemProcFS = {"-device", "c:\\dumps\\WIN7-X64-SP1-1.pmem", "-printf", "-v"};
	
	public static void main(String[] args) {	
		// Initialize VMM.DLL
		// Arguments are as they are given on the command line.
		// Also required is to specify the path to the native MemProcFS files.
		// Important! remember to close the vmm object after use to free up native resources!
		IVmm vmm = IVmm.initializeVmm(strPathToNativeBinaries, argvMemProcFS);

		// Get/Set option
		vmm.setConfig(IVmm.OPT_CORE_PRINTF_ENABLE, 1);
		long build = vmm.getConfig(IVmm.OPT_WIN_VERSION_BUILD);
		
		// VFS init / list / read / write
		List<Vmm_VfsListEntry> vfs_directory_listing = vmm.vfsList("\\sys\\");
		byte[] vfs_build_bytes = vmm.vfsRead("\\sys\\version-build.txt", 0, 10);
		String vfs_build_string = vmm.vfsReadString("\\sys\\version-build.txt", 0, 10);
		//vmm.vfsWrite("\\memory.pmem", vfs_build_bytes, 0); 

		// physical memory prefetch/read/write
		long[] physmem_prefetch = {0x1000, 0x10000, 0x20000};
		vmm.memPrefetchPages(physmem_prefetch);
		byte[] physmem_read = vmm.memRead(0x1000, 0x100);
		byte[] physmem_read_withflags = vmm.memRead(0x1000, 0x100, IVmm.FLAG_NOCACHE | IVmm.FLAG_ZEROPAD_ON_FAIL);
		//vmm.memWrite(0x400, physmem_read);
		
		// physical memory scatter efficient read/write
		IVmmMemScatterMemory physMemScatter = vmm.memScatterInitialize(IVmm.FLAG_ZEROPAD_ON_FAIL);
		physMemScatter.prepare(0x1000, 0x100);
		physMemScatter.prepare(0x2000, 8);
		physMemScatter.execute();
		byte[] physmem_readscatter1 = physMemScatter.read(0x1000, 0x100);
		byte[] physmem_readscatter2 = physMemScatter.read(0x2004, 4);
		byte[] physmem_readscatter3 = physMemScatter.read(0x2000, 8);
		physMemScatter.close();
		
		// get core maps
		List<VmmMap_MemMapEntry> maps_physmemmap = vmm.mapPhysicalMemory();
		List<VmmMap_NetEntry> maps_net = vmm.mapNet();
		List<VmmMap_UserEntry> maps_users = vmm.mapUser();
		List<VmmMap_ServiceEntry> maps_services = vmm.mapService();
		VmmMap_PoolMap maps_pool = vmm.mapPool(true);			// retrieve big pool entries only (faster). 
		
		// get kernel info
		IVmmProcess processKernel1 = vmm.kernelProcess();
		IVmmPdb kernelPdb = vmm.kernelPdb();
		int kernelBuildNumber = vmm.kernelBuildNumber();
		
		// get processes
		IVmmProcess processKernel2 = vmm.processGet(4);
		IVmmProcess processExplorer = vmm.processGet("explorer.exe");
		List<IVmmProcess> processAll = vmm.processGetAll();
		
		// get process maps
		VmmMap_HeapMap procmaps_heap = processExplorer.mapHeap();
		List<VmmMap_HeapAllocEntry> procmaps_heapalloc = processExplorer.mapHeapAlloc(0);
		List<VmmMap_HandleEntry> procmaps_handle = processExplorer.mapHandle();
		List<VmmMap_PteEntry> procmaps_PTEs = processExplorer.mapPte();
		List<VmmMap_ThreadEntry> procmaps_threads = processExplorer.mapThread();
		List<VmmMap_UnloadedModuleEntry> procmaps_unloadedmodules = processExplorer.mapUnloadedModule();
		List<VmmMap_VadEntry> procmaps_VADs = processExplorer.mapVad();
		List<VmmMap_VadExEntry> procmaps_VADex = processExplorer.mapVadEx(0, 0x100);
		
		// get module
		List<IVmmModule> moduleExplorerAll = processExplorer.moduleGetAll(false);				// retrieve without extended debug/version info.
		IVmmModule moduleExplorerKernel32 = processExplorer.moduleGet("kernel32.dll", true);	// retrieve with extended debug/version info.
		
		// get some module info (additional info exists - check interface for more!)
		String strModuleKernel32Full = moduleExplorerKernel32.getNameFull();
		
		// get debug info and version info of kernel32.
		// This requires that the module have been initialized with isExtendedInfo = true,
		// but the call may still fail and return null if required memory is unreadable.
		Vmm_ModuleExDebugInfo moduleExplorerKernel32_DebugInfo = moduleExplorerKernel32.getExDebugInfo();
		Vmm_ModuleExVersionInfo moduleExplorerKernel32_VersionInfo = moduleExplorerKernel32.getExVersionInfo();
		
		// get module maps for kernel32:
		List<VmmMap_ModuleDataDirectory> moduleKernel32_DataDirectory = moduleExplorerKernel32.mapDataDirectory();
		List<VmmMap_ModuleExport> moduleKernel32_Export =  moduleExplorerKernel32.mapExport();
		List<VmmMap_ModuleImport> moduleKernel32_Import = moduleExplorerKernel32.mapImport();
		List<VmmMap_ModuleSection> moduleKernel32_Section =  moduleExplorerKernel32.mapSection();
		
		// pdb debug symbols for kernel and kernel32
		IVmmPdb pdbKernel = vmm.kernelPdb();
		IVmmPdb pdbKernel32 = moduleExplorerKernel32.getPdb();
		long vaGetProcAddress = pdbKernel32.getSymbolAddress("GetProcAddress");
		int cbEprocess = pdbKernel.getTypeSize("_EPROCESS");
		int oEprocessToken = pdbKernel.getTypeChildOffset("_EPROCESS", "Token");	
		
		// registry
		List<IVmmRegHive> reghives = vmm.regHive();
		IVmmRegHive reghive = reghives.get(0);
		IVmmRegKey regkey1 = reghive.getKeyRoot();
		IVmmRegKey regkey2 = vmm.regKey("HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run");
		IVmmRegKey regkey3 = regkey2.getKeyParent();
		Map<String, IVmmRegValue> regvalues = regkey2.getValues();
		IVmmRegValue regvalue = vmm.regValue("HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\VBoxTray");
		
		// LeechCore is the underlying low-level memory acquisition library focusing
		// on physical memory reads. It's possible to initialize LeechCore using
		// arguments and/or retrieve the LeechCore from an existing Vmm instance.
		// The LeechCore object should always be closed after completed usage.
		{
			// Example: LeechCore
			// LeechCore is the underlying low-level memory acquisition library focusing
			// on physical memory reads. It's possible to create it as stand-alone or as
			// here retrieve it from an active Vmm instance.
			ILeechCore lc = ILeechCore.initializeLeechCore(vmm);
			
			// Example: LeechCore memory read:
			byte[] lc_physmem_read = lc.memRead(0x1000, 0x100);
			
			// Example: LeechCore get/set option:
			// Use constants LC_OPT_* for these functions.
			long lc_option_verbose_extra_pre = lc.getOption(ILeechCore.LC_OPT_CORE_VERBOSE_EXTRA);
			lc.setOption(ILeechCore.LC_OPT_CORE_PRINTF_ENABLE, 1);
			lc.setOption(ILeechCore.LC_OPT_CORE_VERBOSE_EXTRA, 1);
			long lc_option_verbose_extra_post = lc.getOption(ILeechCore.LC_OPT_CORE_PRINTF_ENABLE);
			
			// Example: LeechCore get/set memory map in use by LeechCore:
			String lcMemoryMap = lc.getMemMap();
			lc.setMemMap(lcMemoryMap);
			
			// Example: LeechCore close and free up native resources.
			lc.close();
		}
		
		vmm.close();
		
		// Try FPGA devices examples (if possible).
		lcExampleTestPCIeFPGA();
		
	}
	
	// The below examples showcase how LeechCore may be used if the underlying
	// device is a PCIe FPGA board to send/receive PCIe TLPs and respond to
	// PCIe BAR requests.
	public static void lcExampleTestPCIeFPGA() {
		ILeechCore lc = ILeechCore.initializeLeechCore(strPathToNativeBinaries, "fpga://");
		
		// Example: retrieve information about the 6 PCIe BARs.
		LeechCoreBar[] lcBarInfo = lc.getBarInfo();
		
		// Example: register a PCIe BAR callback function. The callback will be
		// called when the host system accesses a Base Address Register (BAR)
		// of the PCIe FPGA device. The function should respond with a reply to
		// each read request, whilst writes require no response.
		BarCallback userBarCB = new BarCallback();
		ILeechCoreBarContext ctxBar = lc.setPCIeBarCallback(userBarCB);
		
		// Example: register a PCIe TLP callback function. The callback will be
		// called for each PCIe TLP packet received.
		// The context created must be kept alive or the callback will close.
		// At most one callback per native LeechCore instance is possible.
		// First instantiate our callback class. This instantiated object may
		// also contain various user-defined states, such as tlpCallCount.
		TlpCallback userTlpCB = new TlpCallback();
		ILeechCoreTlpContext ctxTlp = lc.setPCIeTlpCallback(userTlpCB);
		
		// Example: retrieve FPGA PCIe ID (bus:dev.fn)
		// For getOption/setOption use option ids ILeechCore.LC_OPT_*.
		long lcBusDevId = lc.getOption(ILeechCore.LC_OPT_FPGA_DEVICE_ID);
		
		// Example: send a TLP. In this case the TLP is a memory read TLP that
		// will read a page (0x1000 bytes) from physical address 0x1000. This
		// will also be seen in the TLP callback function previously activated.
		// The below TLP is not yet prepared with the device id in the form of
		// bus:dev.fn (shown as 0x33, 0x33 below).
		byte[] tlp = {0x00, 0x00, 0x00, 0x00, 0x33, 0x33, 0x01, (byte)0xff, 0x00, 0x00, 0x10, 0x00};
		tlp[4] = (byte)((lcBusDevId >> 8) & 0xff);
		tlp[5] = (byte)(lcBusDevId & 0xff);
		lc.writePCIeTLP(tlp);
		
		// Sleep 10 seconds.
		try {
			Thread.sleep(1000000);
		} catch (InterruptedException e) {}
		
		// Example: close the BAR callback
		ctxBar.close();
		
		// Example: close the TLP callback
		ctxTlp.close();
		
		// Example: close the LeechCore instance.
		lc.close();
	}
}

// User-defined callback class to receive TLP callbacks.
class TlpCallback implements ILeechCoreTlpCallback {
	// The callback instance may contain state.
	long tlpCallCount = 0;
	
	// The callback function will be called for each received TLP.
	@Override
	public void LeechCoreTlpCallback(ILeechCore lc, byte[] tlpData, String tlpInfo) {
		tlpCallCount++;
		String str = "";
		str += "------------------------------------------\n";
		str += "PCIe TLP callback received:\n";
		str += "  callcount: " + tlpCallCount + "\n";
		str += tlpInfo;
		System.out.println(str);
	}
}

//User-defined callback class to receive BAR callbacks.
class BarCallback implements ILeechCoreBarCallback {
	// The callback instance may contain state.
	long barCallCount = 0;
	
	private static String toHex(byte[] data) {
		StringBuilder hexString = new StringBuilder();
        for(byte b : data) {
            hexString.append(String.format("%02x ", b));
        }
        return hexString.toString();
	}

	// The callback function will be called for each BAR access.
	// The below implements a small dummy BAR which responds with
	// bytes depending on which address is read.
	@Override
	public void LeechCoreBarCallback(LeechCoreBarRequest req) {
		barCallCount++;
		String str = "";
		str += "------------------------------------------\n";
		str += "PCIe BAR request received:\n";
		str += "  callcount: " + barCallCount + "\n";
		str += "  type: " + (req.isRead ? "read" : "write") + "\n";
		str += "  bar: " + req.bar.iBar + "\n";
		str += "  offset: " + req.oData + "\n";
		str += "  length: " + req.cbData + "\n";
		if(req.isWrite) {
			str += "  data_received: [" + toHex(req.pbDataWrite) + "]\n";
		}
		if(req.isRead) {
			byte[] dataReply = new byte[req.cbData];
			for(int i = 0; i < req.cbData; i++) {
				dataReply[i] = (byte)(req.oData + i);
			}
			str += "  data_reply: [" + toHex(dataReply) + "]\n";
			// reply to a PCIe BAR request this way.
			// length of dataReply must exactly match req.cbData.
			req.reply.reply(dataReply);
		}
		System.out.println(str);
	}
}
