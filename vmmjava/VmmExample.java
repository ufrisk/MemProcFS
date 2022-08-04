import vmm.*;
import vmm.entry.*;

import java.util.*;

/**
 * MemProcFS example code how use the Java wrapper API for the native library.
 * More functionality exists, please check the interfaces for more information.
 * @see https://github.com/ufrisk/MemProcFS
 * @author Ulf Frisk - pcileech@frizk.net
 */
public class VmmExample {

	public static void main(String[] args) {	
		// Initialize VMM.DLL
		// arguments are as they are given on the command line.
		// also required is to specify the path to the native MemProcFS files
		// important! remember to close the vmm object after use to free up native resources!
		String strPathToNativeBinaries = "C:\\Github\\MemProcFS-dev\\files";
		String[] argv = {"-printf", "-device", "c:\\dumps\\WIN7-X64-SP1-1.pmem"};
		IVmm vmm = IVmm.initializeVmm(strPathToNativeBinaries, argv);

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
		VmmMap_PoolMap maps_pool = vmm.mapPool();
		
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
		List<IVmmModule> moduleExplorerAll = processExplorer.moduleGetAll();
		IVmmModule moduleExplorerKernel32 = processExplorer.moduleGet("kernel32.dll");
		
		// get some module info (additional info exists - check interface for more!)
		String strModuleKernel32Full = moduleExplorerKernel32.getNameFull();
		
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
		
		vmm.close();
	}

}
