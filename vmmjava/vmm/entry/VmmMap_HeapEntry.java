package vmm.entry;

import java.io.Serializable;

/**
 * @see https://github.com/ufrisk/MemProcFS
 * @author Ulf Frisk - pcileech@frizk.net
 */
public class VmmMap_HeapEntry implements Serializable
{
    private static final long serialVersionUID = -2916075662335391903L;
    public long va;
    public int tp;
    public boolean f32;
    public int iHeap;
    public int dwHeapNum;
    
    public String toString() {
        return "VmmMap_HeapEntry:" + String.valueOf(iHeap) + ":" + Long.toHexString(va);
    }
}
