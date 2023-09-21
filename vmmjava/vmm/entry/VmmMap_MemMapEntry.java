package vmm.entry;

import java.io.Serializable;

/**
 * @see https://github.com/ufrisk/MemProcFS
 * @author Ulf Frisk - pcileech@frizk.net
 */
public class VmmMap_MemMapEntry implements Serializable
{
    private static final long serialVersionUID = 862616981396566108L;
    public long pa;
    public long cb;
    
    public String toString() {
        return "VmmMap_MemMapEntry:" + Long.toHexString(pa) + ":" + Long.toHexString(cb);
    }
}
