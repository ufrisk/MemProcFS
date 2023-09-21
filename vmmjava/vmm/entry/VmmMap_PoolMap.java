package vmm.entry;

import java.util.Map;
import java.io.Serializable;

/**
 * @see https://github.com/ufrisk/MemProcFS
 * @author Ulf Frisk - pcileech@frizk.net
 */
public class VmmMap_PoolMap implements Serializable
{
    private static final long serialVersionUID = -2515154533742691192L;
    public Map<String, Map<Long, VmmMap_PoolEntry>> tag;
    public Map<Long, VmmMap_PoolEntry> va;

    public String toString() {
        return "VmmMap_PoolMap";
    }
}
