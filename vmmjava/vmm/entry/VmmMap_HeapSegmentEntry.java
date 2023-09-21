package vmm.entry;

import java.io.Serializable;

/**
 * @see https://github.com/ufrisk/MemProcFS
 * @author Ulf Frisk - pcileech@frizk.net
 */
public class VmmMap_HeapSegmentEntry implements Serializable
{
    private static final long serialVersionUID = 5620134579124403952L;
    public long va;
    public int cb;
    public short tp;
    public short iHeap;
    
    public String toString() {
        return "VmmMap_HeapSegmentEntry:" + String.valueOf(iHeap) + ":" + Long.toHexString(va) + ":" + Long.toHexString(cb);
    }
}
