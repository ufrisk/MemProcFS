package vmm;

/**
 * Interface to simplify efficient scattered read/write from the underlying API.
 * @see https://github.com/ufrisk/MemProcFS
 * @author Ulf Frisk - pcileech@frizk.net
 */
public interface IVmmMemScatterMemory
{
    
    /**
     * Retrieve the object validity. Will turn to false after Close().
     * @return
     */
    public boolean isValid();
    
    /**
     * Retrieve the flags.
     * @return
     */
    public int getFlags();
    
    /**
     * Prepare memory for reading. Read memory after a successful call to Execute()
     * @param va
     * @param size
     */
    void prepare(long va, int size);
    
    /**
     * Prepare memory for writing. Memory will hopefully be written after a call to Execute()
     * @param va
     * @param data
     */
    void prepareWrite(long va, byte[] data);
    
    /**
     * Execute memory read/write operations queued by previous calls to Prepare()/PrepareWrite()
     */
    void execute();
    
    /**
     * Clear the IVmmMemScatter for new calls to Prepare()/PrepareWrite()
     */
    void clear();
    
    /**
     * Read scatter data previously prepared by Prepare() after an Execute() call.
     * @param va
     * @param size
     * @return
     */
    byte[] read(long va, int size);
    
    /**
     * Close the IVmmMemScatter object and clean up native resources.
     */
    void close();
    
}
