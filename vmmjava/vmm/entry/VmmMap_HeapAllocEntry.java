package vmm.entry;

import java.io.Serializable;

/**
 * @see https://github.com/ufrisk/MemProcFS
 * @author Ulf Frisk - pcileech@frizk.net
 */
public class VmmMap_HeapAllocEntry implements Serializable
{
    private static final long serialVersionUID = 7660027547435390129L;
    public long va;
    public int cb;
    public int tp;
    
    public String toString() {
        return "VmmMap_HeapAllocEntry:" + Long.toHexString(va) + ":" + Long.toHexString(cb);
    }
}
