package vmm.entry;

import java.io.Serializable;

/**
 * @see https://github.com/ufrisk/MemProcFS
 * @author Ulf Frisk - pcileech@frizk.net
 */
public class VmmMap_PoolEntry implements Serializable
{
    private static final long serialVersionUID = 6028663064101019000L;
    public long va;
    public int cb;
    public String tag;
    public boolean fAlloc;
    public byte tpPool;
    public byte tpSS;
    
    public String toString() {
        return "VmmMap_PoolEntry:" + tag + ":" + String.valueOf(va);
    }
}
