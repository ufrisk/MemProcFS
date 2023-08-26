package leechcore;

import leechcore.entry.*;

/**
 * The main LeechCore implementation for Java.<br/>
 * LeechCore for Java requires JNA - https://github.com/java-native-access/jna which must be on the classpath.<br>
 * Check out the example code to get started! https://github.com/ufrisk/LeechCore/<br> 
 * @see https://github.com/ufrisk/LeechCore
 * @author Ulf Frisk - pcileech@frizk.net
 */
public interface ILeechCore
{
	
	//-----------------------------------------------------------------------------
	// CORE FUNCTIONALITY BELOW:
	//-----------------------------------------------------------------------------
	
	public static final int LC_CONFIG_PRINTF_ENABLED              = 0x01;
	public static final int LC_CONFIG_PRINTF_V                    = 0x02;
	public static final int LC_CONFIG_PRINTF_VV                   = 0x04;
	public static final int LC_CONFIG_PRINTF_VVV                  = 0x08;
	
	/**
	 * Initialize a LeechCore instance from an already initialized Vmm instance.
	 * @param vmmInstance
	 * @return
	 */
	public static ILeechCore initializeLeechCore(vmm.IVmm vmmInstance)
	{
		return vmm.internal.LeechCoreImpl.Initialize(vmmInstance);
	}
	
	/**
	 * Initialize a new LeechCore instance.
	 * @param lcNativeLibraryPath	path to vmm.dll / vmm.so native binaries, ex: "C:\\Program FIles\\MemProcFS".
	 * @param strDevice				LeechCore device, i.e. dump file name or fpga://
	 * @return
	 */
	public static ILeechCore initializeLeechCore(String lcNativeLibraryPath, String strDevice)
	{
		return vmm.internal.LeechCoreImpl.Initialize(lcNativeLibraryPath, strDevice);
	}
	
	/**
	 * Initialize a new LeechCore instance.
	 * @param lcNativeLibraryPath
	 * @param strDevice
	 * @param strRemote
	 * @param flagsVerbose
	 * @param paMax
	 * @return
	 */
	public static ILeechCore initializeLeechCore(String lcNativeLibraryPath, String strDevice, String strRemote, int flagsVerbose, long paMax)
	{
		return vmm.internal.LeechCoreImpl.Initialize(lcNativeLibraryPath, strDevice, strRemote, flagsVerbose, paMax);
	}
	
	/**
	 * Check whether the current LeechCore instance is active/valid or not.
	 * @return
	 */
	public boolean isValid();

	/**
	 * Retrieve the native library path set at initialization time.
	 * @return
	 */
	public String getNativeLibraryPath();
	
	/**
	 * Close the active instance of LeechCore
	 */
	public void close();
	
	
	
	//-----------------------------------------------------------------------------
	// LEECHCORE PHYSICAL MEMORY FUNCTIONALITY BELOW:
	//-----------------------------------------------------------------------------
	
	/**
	 * Read a single chunk of memory.
	 * @param pa		physical address to read.
	 * @param size		number of bytes to read.
	 * @return
	 */
	public byte[] memRead(long pa, int size);
	
	/**
	 * Write data to the memory. NB! writing may fail silently.
	 * If important it's recommended to verify a write with a subsequent read. 
	 * @param pa		physical address to read.
	 * @param data		data to write.
	 */
	public void memWrite(long pa, byte[] data);
	
	
	
	//-----------------------------------------------------------------------------
	// LEECHCORE MEMORY MAP FUNCTIONALITY BELOW:
	//-----------------------------------------------------------------------------
	
	/**
	 * Retrieve the memory map in use by LeechCore.
	 * @return
	 */
	public String getMemMap();
	
	/**
	 * Set the memory map in use by LeechCore
	 * @param strMemMap
	 */
	public void setMemMap(String strMemMap);
	
	
	
	//-----------------------------------------------------------------------------
	// CONFIGURATION SETTINGS BELOW:
	//-----------------------------------------------------------------------------
	
	public static final long LC_OPT_CORE_PRINTF_ENABLE                   = 0x4000000100000000L;  // RW
	public static final long LC_OPT_CORE_VERBOSE                         = 0x4000000200000000L;  // RW
	public static final long LC_OPT_CORE_VERBOSE_EXTRA                   = 0x4000000300000000L;  // RW
	public static final long LC_OPT_CORE_VERBOSE_EXTRA_TLP               = 0x4000000400000000L;  // RW
	public static final long LC_OPT_CORE_VERSION_MAJOR                   = 0x4000000500000000L;  // R
	public static final long LC_OPT_CORE_VERSION_MINOR                   = 0x4000000600000000L;  // R
	public static final long LC_OPT_CORE_VERSION_REVISION                = 0x4000000700000000L;  // R
	public static final long LC_OPT_CORE_ADDR_MAX                        = 0x1000000800000000L;  // R
	public static final long LC_OPT_CORE_STATISTICS_CALL_COUNT           = 0x4000000900000000L;  // R [lo-dword: LC_STATISTICS_ID_*]
	public static final long LC_OPT_CORE_STATISTICS_CALL_TIME            = 0x4000000a00000000L;  // R [lo-dword: LC_STATISTICS_ID_*]
	public static final long LC_OPT_CORE_VOLATILE                        = 0x1000000b00000000L;  // R
	public static final long LC_OPT_CORE_READONLY                        = 0x1000000c00000000L;  // R

	public static final long LC_OPT_MEMORYINFO_VALID                     = 0x0200000100000000L;  // R
	public static final long LC_OPT_MEMORYINFO_FLAG_32BIT                = 0x0200000300000000L;  // R
	public static final long LC_OPT_MEMORYINFO_FLAG_PAE                  = 0x0200000400000000L;  // R
	public static final long LC_OPT_MEMORYINFO_ARCH                      = 0x0200001200000000L;  // R - LC_ARCH_TP
	public static final long LC_OPT_MEMORYINFO_OS_VERSION_MINOR          = 0x0200000500000000L;  // R
	public static final long LC_OPT_MEMORYINFO_OS_VERSION_MAJOR          = 0x0200000600000000L;  // R
	public static final long LC_OPT_MEMORYINFO_OS_DTB                    = 0x0200000700000000L;  // R
	public static final long LC_OPT_MEMORYINFO_OS_PFN                    = 0x0200000800000000L;  // R
	public static final long LC_OPT_MEMORYINFO_OS_PsLoadedModuleList     = 0x0200000900000000L;  // R
	public static final long LC_OPT_MEMORYINFO_OS_PsActiveProcessHead    = 0x0200000a00000000L;  // R
	public static final long LC_OPT_MEMORYINFO_OS_MACHINE_IMAGE_TP       = 0x0200000b00000000L;  // R
	public static final long LC_OPT_MEMORYINFO_OS_NUM_PROCESSORS         = 0x0200000c00000000L;  // R
	public static final long LC_OPT_MEMORYINFO_OS_SYSTEMTIME             = 0x0200000d00000000L;  // R
	public static final long LC_OPT_MEMORYINFO_OS_UPTIME                 = 0x0200000e00000000L;  // R
	public static final long LC_OPT_MEMORYINFO_OS_KERNELBASE             = 0x0200000f00000000L;  // R
	public static final long LC_OPT_MEMORYINFO_OS_KERNELHINT             = 0x0200001000000000L;  // R
	public static final long LC_OPT_MEMORYINFO_OS_KdDebuggerDataBlock    = 0x0200001100000000L;  // R

	public static final long LC_OPT_FPGA_PROBE_MAXPAGES                  = 0x0300000100000000L;  // RW
	public static final long LC_OPT_FPGA_MAX_SIZE_RX                     = 0x0300000300000000L;  // RW
	public static final long LC_OPT_FPGA_MAX_SIZE_TX                     = 0x0300000400000000L;  // RW
	public static final long LC_OPT_FPGA_DELAY_PROBE_READ                = 0x0300000500000000L;  // RW - uS
	public static final long LC_OPT_FPGA_DELAY_PROBE_WRITE               = 0x0300000600000000L;  // RW - uS
	public static final long LC_OPT_FPGA_DELAY_WRITE                     = 0x0300000700000000L;  // RW - uS
	public static final long LC_OPT_FPGA_DELAY_READ                      = 0x0300000800000000L;  // RW - uS
	public static final long LC_OPT_FPGA_RETRY_ON_ERROR                  = 0x0300000900000000L;  // RW
	public static final long LC_OPT_FPGA_DEVICE_ID                       = 0x0300008000000000L;  // RW - bus:dev:fn (ex: 04:00.0 == = 0x0400).
	public static final long LC_OPT_FPGA_FPGA_ID                         = 0x0300008100000000L;  // R
	public static final long LC_OPT_FPGA_VERSION_MAJOR                   = 0x0300008200000000L;  // R
	public static final long LC_OPT_FPGA_VERSION_MINOR                   = 0x0300008300000000L;  // R
	public static final long LC_OPT_FPGA_ALGO_TINY                       = 0x0300008400000000L;  // RW - 1/0 use tiny 128-byte/tlp read algorithm.
	public static final long LC_OPT_FPGA_ALGO_SYNCHRONOUS                = 0x0300008500000000L;  // RW - 1/0 use synchronous (old) read algorithm.
	public static final long LC_OPT_FPGA_CFGSPACE_XILINX                 = 0x0300008600000000L;  // RW - [lo-dword: register address in bytes] [bytes: 0-3: data, 4-7: byte_enable(if wr/set); top bit = cfg_mgmt_wr_rw1c_as_rw]
	public static final long LC_OPT_FPGA_TLP_READ_CB_WITHINFO            = 0x0300009000000000L;  // RW - 1/0 call TLP read callback with additional string info in szInfo
	public static final long LC_OPT_FPGA_TLP_READ_CB_FILTERCPL           = 0x0300009100000000L;  // RW - 1/0 call TLP read callback with memory read completions from read calls filtered
	
	/**
	 * Get a device specific option value. Please see defines LC_OPT_* for information
	 * about valid option values. Please note that option values may overlap between
	 * different device types with different meanings. 
	 * @param fOption
	 * @return
	 */
	public long getOption(long fOption);
	
	/**
	 * Set a device specific option value. Please see defines LC_OPT_* for information
	 * about valid option values. Please note that option values may overlap between
	 * different device types with different meanings.
	 * @param fOption
	 * @param qw
	 */
	public void setOption(long fOption, long qw);
	
	
	
	//-----------------------------------------------------------------------------
	// LEECHCORE COMMAND FUNCTIONALITY BELOW:
	//-----------------------------------------------------------------------------
	
	public static final long LC_CMD_FPGA_PCIECFGSPACE                    = 0x0000010300000000L;  // R
	public static final long LC_CMD_FPGA_CFGREGPCIE                      = 0x0000010400000000L;  // RW - [lo-dword: register address]
	public static final long LC_CMD_FPGA_CFGREGCFG                       = 0x0000010500000000L;  // RW - [lo-dword: register address]
	public static final long LC_CMD_FPGA_CFGREGDRP                       = 0x0000010600000000L;  // RW - [lo-dword: register address]
	public static final long LC_CMD_FPGA_CFGREGCFG_MARKWR                = 0x0000010700000000L;  // W  - write with mask [lo-dword: register address] [bytes: 0-1: data, 2-3: mask]
	public static final long LC_CMD_FPGA_CFGREGPCIE_MARKWR               = 0x0000010800000000L;  // W  - write with mask [lo-dword: register address] [bytes: 0-1: data, 2-3: mask]
	public static final long LC_CMD_FPGA_CFGREG_DEBUGPRINT               = 0x0000010a00000000L;  // N/A
	public static final long LC_CMD_FPGA_PROBE                           = 0x0000010b00000000L;  // RW
	public static final long LC_CMD_FPGA_CFGSPACE_SHADOW_RD              = 0x0000010c00000000L;  // R
	public static final long LC_CMD_FPGA_CFGSPACE_SHADOW_WR              = 0x0000010d00000000L;  // W  - [lo-dword: config space write base address]
	public static final long LC_CMD_FPGA_TLP_WRITE_SINGLE                = 0x0000011000000000L;  // W  - write single tlp BYTE:s
	public static final long LC_CMD_FPGA_TLP_WRITE_MULTIPLE              = 0x0000011100000000L;  // W  - write multiple LC_TLP:s
	public static final long LC_CMD_FPGA_TLP_TOSTRING                    = 0x0000011200000000L;  // RW - convert single TLP to LPSTR; *pcbDataOut includes NULL terminator.

	public static final long LC_CMD_FPGA_TLP_CONTEXT                     = 0x2000011400000000L;  // W - set/unset TLP user-defined context to be passed to callback function. (pbDataIn == LPVOID user context). [not remote].
	public static final long LC_CMD_FPGA_TLP_CONTEXT_RD                  = 0x2000011b00000000L;  // R - get TLP user-defined context to be passed to callback function. [not remote].
	public static final long LC_CMD_FPGA_TLP_FUNCTION_CALLBACK           = 0x2000011500000000L;  // W - set/unset TLP callback function (pbDataIn == PLC_TLP_CALLBACK). [not remote].
	public static final long LC_CMD_FPGA_TLP_FUNCTION_CALLBACK_RD        = 0x2000011c00000000L;  // R - get TLP callback function. [not remote].
	public static final long LC_CMD_FPGA_BAR_CONTEXT                     = 0x2000012000000000L;  // W - set/unset BAR user-defined context to be passed to callback function. (pbDataIn == LPVOID user context). [not remote].
	public static final long LC_CMD_FPGA_BAR_CONTEXT_RD                  = 0x2000012100000000L;  // R - get BAR user-defined context to be passed to callback function. [not remote].
	public static final long LC_CMD_FPGA_BAR_FUNCTION_CALLBACK           = 0x2000012200000000L;  // W - set/unset BAR callback function (pbDataIn == PLC_BAR_CALLBACK). [not remote].
	public static final long LC_CMD_FPGA_BAR_FUNCTION_CALLBACK_RD        = 0x2000012300000000L;  // R - get BAR callback function. [not remote].
	public static final long LC_CMD_FPGA_BAR_INFO                        = 0x0000012400000000L;  // R - get BAR info (pbDataOut == LC_BAR_INFO[6]).


	public static final long LC_CMD_FILE_DUMPHEADER_GET                  = 0x0000020100000000L;  // R

	public static final long LC_CMD_STATISTICS_GET                       = 0x4000010000000000L;  // R
	public static final long LC_CMD_MEMMAP_GET                           = 0x4000020000000000L;  // R  - MEMMAP as LPSTR
	public static final long LC_CMD_MEMMAP_SET                           = 0x4000030000000000L;  // W  - MEMMAP as LPSTR
	public static final long LC_CMD_MEMMAP_GET_STRUCT                    = 0x4000040000000000L;  // R  - MEMMAP as LC_MEMMAP_ENTRY[]
	public static final long LC_CMD_MEMMAP_SET_STRUCT                    = 0x4000050000000000L;  // W  - MEMMAP as LC_MEMMAP_ENTRY[]

	public static final long LC_CMD_AGENT_EXEC_PYTHON                    = 0x8000000100000000L;  // RW - [lo-dword: optional timeout in ms]
	public static final long LC_CMD_AGENT_EXIT_PROCESS                   = 0x8000000200000000L;  //    - [lo-dword: process exit code]
	public static final long LC_CMD_AGENT_VFS_LIST                       = 0x8000000300000000L;  // RW
	public static final long LC_CMD_AGENT_VFS_READ                       = 0x8000000400000000L;  // RW
	public static final long LC_CMD_AGENT_VFS_WRITE                      = 0x8000000500000000L;  // RW
	public static final long LC_CMD_AGENT_VFS_OPT_GET                    = 0x8000000600000000L;  // RW
	public static final long LC_CMD_AGENT_VFS_OPT_SET                    = 0x8000000700000000L;  // RW
	public static final long LC_CMD_AGENT_VFS_INITIALIZE                 = 0x8000000800000000L;  // RW
	public static final long LC_CMD_AGENT_VFS_CONSOLE                    = 0x8000000900000000L;  // RW
	
	/**
	 * Execute a command. See defines LC_CMD_* for information about valid commands. 
	 * @param fCommand
	 * @param data
	 * @return
	 */
	public byte[] command(long fCommand, byte[] data);
	
	/**
	 * Retrieve info about the 6 PCIe BARs. [PCIe FPGA backend only].
	 * @return an array of 6 PCIe BARs.
	 */
	public LeechCoreBar[] getBarInfo();
	
	/**
	 * Set/Activate a BAR callback. When a BAR access is requested by the host system
	 * this callback will be called. Only one callback may be active at a given time.
	 * Close callback by calling close() on the returned context.
	 * @param callback
	 * @return
	 */
	public ILeechCoreBarContext setPCIeBarCallback(ILeechCoreBarCallback callback);
	
	/**
	 * Set/Activate a TLP callback. When a PCIe TLP packet is received this callback will be called.
	 * Only one callback may be active at a given time.
	 * Close callback by calling close() on the returned context.
	 * @param callback
	 * @return
	 */
	public ILeechCoreTlpContext setPCIeTlpCallback(ILeechCoreTlpCallback callback);
	
	/**
	 * Write a PCIe TLP (best effort).
	 * @param tlp
	 */
	public void writePCIeTLP(byte[] tlp);
}
