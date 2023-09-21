package vmm;

import java.util.List;

import vmm.entry.*;

/**
 * Interface representing a process.
 * @see https://github.com/ufrisk/MemProcFS
 * @author Ulf Frisk - pcileech@frizk.net
 */
public interface IVmmProcess
{
    
    //-----------------------------------------------------------------------------
    // PROCESS CORE FUNCTIONALITY BELOW:
    //-----------------------------------------------------------------------------
    
    /**
     * Retrieve the PID of this process object.
     * @return
     */
    public int getPID();
    
    /**
     * Retrieve the parent process id (PPID).
     * @return
     */
    public int getPPID();
    
    /**
     * Retrieve the virtual address of the EPROCESS struct.
     * @return
     */
    public long getEPROCESS();
    
    /**
     * Get the kernel directory table base (default).
     * @return
     */
    public long getDTB();
    
    /**
     * Get the user mode directory table base (if exists).
     * @return
     */
    public long getDTBUser();
    
    /**
     * Get the process state.
     * @return
     */
    public int getState();
    
    /**
     * Get the virtual address of the PEB.
     * @return
     */
    public long getPEB();
    
    /**
     * Get the virtual address of the 32-bit PEB in WoW64 processes.
     * @return
     */
    public int getPEB32();
    
    /**
     * Check whether the process is a Wow64 process.
     * @return
     */
    public boolean isWow64();
    
    /**
     * Check whether the process is a user-mode or kernel-mode process.
     * @return
     */
    public boolean isUserMode();
    
    /**
     * Get the short process name.
     * @return
     */
    public String getName();
    
    /**
     * Get the full process name.
     * @return
     */
    public String getNameFull();
    
    /**
     * Get the process command line.
     * @return
     */
    public String getCmdLine();
    
    /**
     * Get the user mode process path.
     * @return
     */
    public String getPathUser();
    
    /**
     * Get the kernel mode process path.
     * @return
     */
    public String getPathKernel();
    
    /**
     * Get the memory model.
     * @return
     */
    public int getTpMemoryModel();
    
    /**
     * Get the system type.
     * @return
     */
    public int getTpSystem();
    
    /**
     * Get the LUID from the process token.
     * @return
     */
    public long GetLUID();
    
    /**
     * Get the SesssionID from the process token.
     * @return
     */
    public int GetSessionID();
    
    /**
     * Get the SID from the process token.
     * @return
     */
    public String getSID();
    
    
    
    //-----------------------------------------------------------------------------
    // PROCESS VIRTUAL MEMORY FUNCTIONALITY BELOW:
    //-----------------------------------------------------------------------------
    
    /**
     * Read a single chunk of memory.
     * @param va        virtual address to read.
     * @param size        number of bytes to read.
     * @return
     */
    public byte[] memRead(long va, int size);
    
    /**
     * Read a single chunk of memory with the given flags
     * @param va        virtual address to read.
     * @param size        number of bytes to read.
     * @param flags        flags as specified by IVmm.FLAG_*
     * @return
     */
    public byte[] memRead(long va, int size, int flags);
    
    /**
     * Write data to the memory. NB! writing may fail silently.
     * If important it's recommended to verify a write with a subsequent read. 
     * @param va        virtual address to read.
     * @param data        data to write.
     */
    public void memWrite(long va, byte[] data);
    
    /**
     * Prefetch a number of addresses into the internal memory cache.
     * This is used to achieve faster subsequent reading speeds.
     * @param vas        array of virtual addresses to prefetch.
     */
    public void memPrefetchPages(long[] vas);
    
    /**
     * Create a new IVmmMemScatter object used for efficient reading and writing.
     * Upon completion it's recommended to call Close() to free native resources.
     * @param flags     flags as specified by IVmm.FLAG_*
     * @return            IVmmMemScatter object used for scatter reading.
     */
    public IVmmMemScatterMemory memScatterInitialize(int flags);
    
    /**
     * Try translating a virtual memory address to a physical memory address.
     * @param va
     * @return
     */
    public long memVirtualToPhysical(long va);
    
    
    
    //-----------------------------------------------------------------------------
    // PROCESS MODULE FUNCTIONALITY BELOW:
    //-----------------------------------------------------------------------------
    
    /**
     * Retrieve a module by its virtual address.
     * @param va
     * @return
     */
    public IVmmModule moduleGet(long va, boolean isExtendedInfo);
    
    /**
     * Retrieve a module by its name.
     * @param name
     * @return
     */
    public IVmmModule moduleGet(String name, boolean isExtendedInfo);
    
    /**
     * Retrieve all modules loaded into the process.
     * @return
     */
    public List<IVmmModule> moduleGetAll(boolean isExtendedInfo);
    
    
    
    //-----------------------------------------------------------------------------
    // PROCESS MAP FUNCTIONALITY BELOW:
    //-----------------------------------------------------------------------------
    
    /**
     * Retrieve handles.
     * @return
     */
    public List<VmmMap_HandleEntry> mapHandle();
    
    /**
     * Retrieve heap allocations given a heap address or heap number.
     * @param qwHeapNumOrAddress
     * @return
     */
    public List<VmmMap_HeapAllocEntry> mapHeapAlloc(long qwHeapNumOrAddress);
    
    /**
     * Retrieve the process heaps.
     * @return
     */
    public VmmMap_HeapMap mapHeap();
    
    /**
     * Retrieve the process PTEs.
     * @return
     */
    public List<VmmMap_PteEntry> mapPte();
    
    /**
     * Retrieve the process threads.
     * @return
     */
    public List<VmmMap_ThreadEntry> mapThread();
    
    /**
     * Retrieve the process unloaded modules.
     * @return
     */
    public List<VmmMap_UnloadedModuleEntry> mapUnloadedModule();
    
    /**
     * Retrieve the process VADs.
     * @return
     */
    public List<VmmMap_VadEntry> mapVad();
    
    /**
     * Retrieve extended VAD information given a starting page offset (oPage) and number of pages (cPage).
     * @param oPage
     * @param cPage
     * @return
     */
    public List<VmmMap_VadExEntry> mapVadEx(int oPage, int cPage);
    
}
