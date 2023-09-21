package vmm;

/**
 * Interface representing a registry hive.
 * @see https://github.com/ufrisk/MemProcFS
 * @author Ulf Frisk - pcileech@frizk.net
 */
public interface IVmmRegHive
{
    
    /**
     * Retrieve the registry hive full name.
     * @return
     */
    public String getName();
    
    /**
     * Retrieve the registry hive short name.
     * @return
     */
    public String getNameShort();
    
    /**
     * Retrieve the registry hive path.
     * @return
     */
    public String getPath();
    
    /**
     * Retrieve the registry hive size.
     * @return
     */
    public int getSize();
    
    /**
     * Retrieve the base address of the registry hive.
     * @return
     */
    public long getVaHive();
    
    /**
     * Retrieve the address of the registry base block.
     * @return
     */
    public long getVaBaseBlock();
    
    /**
     * Retrieve the registry hive root key.
     * @return
     */
    public IVmmRegKey getKeyRoot();
    
    /**
     * Retrieve the virtual registry hive orphan key.
     * The orphan key is populated by registry entries of which it's not
     * possible to determine their parents.
     * @return
     */
    public IVmmRegKey getKeyOrphan();
    
    /**
     * Read registry memory.
     * @param ra        the address from the registry base to read.
     * @param size        the number of bytes to read.
     * @return
     */
    public byte[] memRead(int ra, int size);
    
    /**
     * Read registry memory.
     * @param ra        the address from the registry base to read.
     * @param size        the number of bytes to read.
     * @param flags        IVmm.FLAG_*
     * @return
     */
    public byte[] memRead(int ra, int size, int flags);
    
    /**
     * Write data to the registry if possible.
     * NB! this is dangerous and not recommended!
     * @param ra
     * @param data
     */
    public void memWrite(int ra, byte[] data);
    
}
