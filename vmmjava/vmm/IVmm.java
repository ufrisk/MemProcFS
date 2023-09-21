package vmm;

import java.util.List;

import vmm.entry.*;

/**
 * The main MemProcFS implementation for Java.<br/>
 * MemProcFS for Java requires JNA - https://github.com/java-native-access/jna which must be on the classpath.<br>
 * Check out the example code to get started! https://github.com/ufrisk/MemProcFS/<br> 
 * @see https://github.com/ufrisk/MemProcFS
 * @author Ulf Frisk - pcileech@frizk.net
 */
public interface IVmm
{
    
    //-----------------------------------------------------------------------------
    // CORE FUNCTIONALITY BELOW:
    //-----------------------------------------------------------------------------
    
    /**
     * Initialize a new MemProcFS instance.
     * @param vmmNativeLibraryPath    path to vmm.dll / vmm.so native binaries, ex: "C:\\Program FIles\\MemProcFS".
     * @param argv                    VMM/MemProcFS initialization arguments.
     * @return
     */
    public static IVmm initializeVmm(String vmmNativeLibraryPath, String argv[])
    {
        return vmm.internal.VmmImpl.Initialize(vmmNativeLibraryPath, argv);
    }
    
    /**
     * Check whether the current VMM instance is active/valid or not.
     * @return
     */
    public boolean isValid();

    /**
     * Retrieve the native library path set at initialization time.
     * @return
     */
    public String getNativeLibraryPath();
    
    /**
     * Close the active instance of MemProcFS
     */
    public void close();
    
    
    
    //-----------------------------------------------------------------------------
    // CONFIGURATION SETTINGS BELOW:
    //-----------------------------------------------------------------------------
    
    public static final long OPT_CORE_PRINTF_ENABLE             = 0x4000000100000000L;
    public static final long OPT_CORE_VERBOSE                     = 0x4000000200000000L;
    public static final long OPT_CORE_VERBOSE_EXTRA             = 0x4000000300000000L;
    public static final long OPT_CORE_VERBOSE_EXTRA_TLP         = 0x4000000400000000L;
    public static final long OPT_CORE_MAX_NATIVE_ADDRESS         = 0x4000000800000000L;
    public static final long OPT_CORE_LEECHCORE_HANDLE          = 0x4000001000000000L;
    
    public static final long OPT_CORE_SYSTEM                     = 0x2000000100000000L;
    public static final long OPT_CORE_MEMORYMODEL                 = 0x2000000200000000L;
    
    public static final long OPT_CONFIG_IS_REFRESH_ENABLED         = 0x2000000300000000L;
    public static final long OPT_CONFIG_TICK_PERIOD             = 0x2000000400000000L;
    public static final long OPT_CONFIG_READCACHE_TICKS         = 0x2000000500000000L;
    public static final long OPT_CONFIG_TLBCACHE_TICKS             = 0x2000000600000000L;
    public static final long OPT_CONFIG_PROCCACHE_TICKS_PARTIAL = 0x2000000700000000L;
    public static final long OPT_CONFIG_PROCCACHE_TICKS_TOTAL     = 0x2000000800000000L;
    public static final long OPT_CONFIG_VMM_VERSION_MAJOR         = 0x2000000900000000L;
    public static final long OPT_CONFIG_VMM_VERSION_MINOR         = 0x2000000A00000000L;
    public static final long OPT_CONFIG_VMM_VERSION_REVISION     = 0x2000000B00000000L;
    public static final long OPT_CONFIG_STATISTICS_FUNCTIONCALL = 0x2000000C00000000L;
    public static final long OPT_CONFIG_IS_PAGING_ENABLED         = 0x2000000D00000000L;

    
    
    /**
     * Retrieve the OS kernel major version.
     */
    public static final long OPT_WIN_VERSION_MAJOR                 = 0x2000010100000000L;
    
    /**
     * Retrieve the OS kernel minor version.
     */
    public static final long OPT_WIN_VERSION_MINOR                 = 0x2000010200000000L;
    
    /**
     * Retrieve the OS kernel build.
     */
    public static final long OPT_WIN_VERSION_BUILD                 = 0x2000010300000000L;
    
    /**
     * Retrieve the MemProcFS generated system id.
     */
    public static final long OPT_WIN_SYSTEM_UNIQUE_ID             = 0x2000010400000000L;
    
    
    
    /**
     * Forensic mode.
     */
    public static final long OPT_FORENSIC_MODE                     = 0x2000020100000000L;
    
    
    
    /**
     * Total refresh.
     */
    public static final long VMMDLL_OPT_REFRESH_ALL             = 0x2001ffff00000000L;
    
    /**
     * Refresh total memory caches.
     */
    public static final long VMMDLL_OPT_REFRESH_FREQ_MEM        = 0x2001100000000000L;
    
    /**
     * Refresh partial (1/3) memory caches.
     */
    public static final long VMMDLL_OPT_REFRESH_FREQ_MEM_PARTIAL= 0x2001000200000000L;
    
    /**
     * Refresh completely page table caches.
     */
    public static final long VMMDLL_OPT_REFRESH_FREQ_TLB        = 0x2001080000000000L;
    
    /**
     * Refresh partial (1/3) of page table caches.
     */
    public static final long VMMDLL_OPT_REFRESH_FREQ_TLB_PARTIAL= 0x2001000400000000L;
    
    /**
     * Refresh fast frequency (minor refresh).
     */
    public static final long VMMDLL_OPT_REFRESH_FREQ_FAST       = 0x2001040000000000L;
    
    /**
     * Refresh medium frequency (medium refresh).
     */
    public static final long VMMDLL_OPT_REFRESH_FREQ_MEDIUM     = 0x2001000100000000L;
    
    /**
     * Refresh slow frequency (maximum refresh).
     */
    public static final long VMMDLL_OPT_REFRESH_FREQ_SLOW       = 0x2001001000000000L;
    
    /**
     * Get a device specific option value. Please see defines OPT_* for information
     * about valid option values. Please note that option values may overlap between
     * different device types with different meanings. 
     * @param fOption
     * @return
     */
    public long getConfig(long fOption);
    
    /**
     * Set a device specific option value. Please see defines OPT_* for information
     * about valid option values. Please note that option values may overlap between
     * different device types with different meanings.
     * @param fOption
     * @param qw
     */
    public void setConfig(long fOption, long qw);
    
    
    
    //-----------------------------------------------------------------------------
    // VFS - VIRTUAL FILE SYSTEM FUNCTIONALITY BELOW:
    // NB! VFS FUNCTIONALITY REQUIRES PLUGINS TO BE INITIALIZED
    //     WITH CALL TO InitializePlugins(). 
    //-----------------------------------------------------------------------------
    
    /**
     * List entries in a virtual directory in the virtual file system.
     * @param path
     * @return
     */
    public List<Vmm_VfsListEntry> vfsList(String path);
    
    /**
     * Read a file in the virtual file system.
     * @param file
     * @param offset
     * @param size
     * @return
     */
    public byte[] vfsRead(String file, long offset, int size);
    
    /**
     * Read a file as a String in the virtual file system.
     * @param file
     * @param offset
     * @param size
     * @return
     */
    public String vfsReadString(String file, long offset, int size);
    
    /**
     * Write to a file in the virtual file system.
     * @param file
     * @param data
     * @param offset
     */
    public void vfsWrite(String file, byte[] data, long offset);
    
    
    
    //-----------------------------------------------------------------------------
    // VMM PHYSICAL MEMORY FUNCTIONALITY BELOW:
    //-----------------------------------------------------------------------------
    
    public static int FLAG_NOCACHE                     = 0x0001;
    public static int FLAG_ZEROPAD_ON_FAIL             = 0x0002;
    public static int FLAG_FORCECACHE_READ             = 0x0008;
    public static int FLAG_NOPAGING                 = 0x0010;
    public static int FLAG_NOPAGING_IO                 = 0x0020;
    public static int FLAG_NOCACHEPUT                 = 0x0100;
    public static int FLAG_CACHE_RECENT_ONLY         = 0x0200;
    public static int FLAG_NO_PREDICTIVE_READ         = 0x0400;
    public static int FLAG_FORCECACHE_READ_DISABLE     = 0x0800;
    
    /**
     * Read a single chunk of memory.
     * @param pa        physical address to read.
     * @param size        number of bytes to read.
     * @return
     */
    public byte[] memRead(long pa, int size);
    
    /**
     * Read a single chunk of memory with the given flags
     * @param pa        physical address to read.
     * @param size        number of bytes to read.
     * @param flags        flags as specified by IVmm.FLAG_*
     * @return
     */
    public byte[] memRead(long pa, int size, int flags);
    
    /**
     * Write data to the memory. NB! writing may fail silently.
     * If important it's recommended to verify a write with a subsequent read. 
     * @param pa        physical address to read.
     * @param data        data to write.
     */
    public void memWrite(long pa, byte[] data);
    
    /**
     * Prefetch a number of addresses into the internal memory cache.
     * This is used to achieve faster subsequent reading speeds.
     * @param pas        array of physical addresses to prefetch.
     */
    public void memPrefetchPages(long[] pas);
    
    /**
     * Create a new IVmmMemScatter object used for efficient reading and writing.
     * Upon completion it's recommended to call Close() to free native resources.
     * @param flags     flags as specified by IVmm.FLAG_*
     * @return            IVmmMemScatter object used for scatter reading.
     */
    public IVmmMemScatterMemory memScatterInitialize(int flags);
    
    
    
    //-----------------------------------------------------------------------------
    // VMM PROCESS FUNCTIONALITY BELOW:
    //-----------------------------------------------------------------------------
    
    /**
     * Retrieve a process by its pid.
     * @param pid
     * @return
     */
    public IVmmProcess processGet(int pid);
    
    /**
     * Retrieve a process by its name. If multiple processes exists with same
     * it's undefined which one will be returned.
     * @param name
     * @return
     */
    public IVmmProcess processGet(String name);
    
    /**
     * Retrieve all processes in the system
     * @return
     */
    public List<IVmmProcess> processGetAll();
    
    
    
    //-----------------------------------------------------------------------------
    // VMM KERNEL FUNCTIONALITY BELOW:
    //-----------------------------------------------------------------------------
    
    /**
     * Retrieve the kernel process.
     * @return
     */
    public IVmmProcess kernelProcess();
    
    /**
     * Retrieve the kernel debug symbols.
     * @return
     */
    public IVmmPdb kernelPdb();
    
    /**
     * Retrieve the kernel build number.
     * @return
     */
    public int kernelBuildNumber();
    
    
    
    //-----------------------------------------------------------------------------
    // VMM MAP FUNCTIONALITY BELOW:
    //-----------------------------------------------------------------------------
    
    /**
     * Retrieve the system physical memory map.
     * @return
     */
    public List<VmmMap_MemMapEntry> mapPhysicalMemory();
    
    /**
     * Retrieve network info.
     * @return
     */
    public List<VmmMap_NetEntry> mapNet();
    
    /**
     * Retrieve users.
     * @return
     */
    public List<VmmMap_UserEntry> mapUser();
    
    /**
     * Retrieve services.
     * @return
     */
    public List<VmmMap_ServiceEntry> mapService();
    
    /**
     * Retrieve pool allocations sorted by virtual address and pool tag.
     * @param isBigPoolOnly true=only show entries from bigpool, false=show all entries.
     * @return
     */
    public VmmMap_PoolMap mapPool(boolean isBigPoolOnly);
    
    
    
    //-----------------------------------------------------------------------------
    // VMM REGISTRY FUNCTIONALITY BELOW:
    //-----------------------------------------------------------------------------
    
    /**
     * Enumerate all the hives in the system and return them in a list.
     * @return
     */
    public List<IVmmRegHive> regHive();
    
    /**
     * Retrieve a registry key by its full path.
     * @param strFullPath
     * @return
     */
    public IVmmRegKey regKey(String strFullPath);
    
    /**
     * Retrieve a registry value by its full path.
     * @param strFullPath
     * @return
     */
    public IVmmRegValue regValue(String strFullPath);
    
}
