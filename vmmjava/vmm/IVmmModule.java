package vmm;

import java.util.List;

import vmm.entry.*;

/**
 * Interface representing a module (loaded dll).
 * @see https://github.com/ufrisk/MemProcFS
 * @author Ulf Frisk - pcileech@frizk.net
 */
public interface IVmmModule
{
	
	//-----------------------------------------------------------------------------
	// MODULE CORE FUNCTIONALITY BELOW:
	//-----------------------------------------------------------------------------
	
	/**
	 * Retrieve the process object of this module object.
	 * @return
	 */
	public IVmmProcess getProcess();
	
	/**
	 * Retrieve the module name.
	 * @return
	 */
	public String getName();
	
	/**
	 * Retrieve the full/long module name.
	 * @return
	 */
	public String getNameFull();
	
	/**
	 * Retrieve the module base address.
	 * @return
	 */
	public long getVaBase();
	
	/**
	 * Retieve the module entry point address.
	 * @return
	 */
	public long getVaEntry();
	
	/**
	 * Retrieve the size of the module (in virtual memory).
	 * @return
	 */
	public int getSize();
	
	/**
	 * Retrieve the file size (raw size) of the module.
	 * @return
	 */
	public int getSizeFile();
	
	/**
	 * Check whether the module is a WoW64 module or not (32-bit module in 64-bit os).
	 * @return
	 */
	public boolean isWow64();
	
	/**
	 * Retrieve the module section count.
	 * @return
	 */
	public int getCountSection();
	
	/**
	 * Retrieve the export address table (EAT) count.
	 * @return
	 */
	public int getCountEAT();
	
	/**
	 * Retrieve the import address table (IAT) count.
	 * @return
	 */
	public int getCountIAT();
	
	/**
	 * Retrieve the function address of the specified function.
	 * @param szFunctionName
	 * @return
	 */
	public long getProcAddress(String szFunctionName);
	
	/**
	 * Retrieve pdb debug symbols for the specific module.
	 * @return
	 */
	public IVmmPdb getPdb();

	/**
	 * Retrieve debug directory information. The debug directory info requires
	 * that the module has been initialized with <b>isExtendedInfo</b> but may
	 * still fail if memory is unreadable - in which case null is returned.
	 * @return
	 */	
	public Vmm_ModuleExDebugInfo getExDebugInfo();
	
	/**
	 * Retrieve PE version info. The PE version info requires that the module
	 * has been initialized with <b>isExtendedInfo</b> but may still fail if
	 * memory is unreadable - in which case null is returned.
	 * @return
	 */	
	public Vmm_ModuleExVersionInfo getExVersionInfo();
	
	
	
	//-----------------------------------------------------------------------------
	// MODULE MAP FUNCTIONALITY BELOW:
	//-----------------------------------------------------------------------------
	
	/**
	 * Retrieve the data directories.
	 * @return
	 */
	public List<VmmMap_ModuleDataDirectory> mapDataDirectory();
	
	/**
	 * Retrieve exported symbols from the export address table (EAT).
	 * @return
	 */
	public List<VmmMap_ModuleExport> mapExport();
	
	/**
	 * Retrieve imported symbols from the import address table (IAT).
	 * @return
	 */
	public List<VmmMap_ModuleImport> mapImport();
	
	/**
	 * Retrieve module sections.
	 * @return
	 */
	public List<VmmMap_ModuleSection> mapSection();
	
}
