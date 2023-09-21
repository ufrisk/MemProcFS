package vmm.entry;

import java.io.Serializable;
import java.util.List;

/**
 * @see https://github.com/ufrisk/MemProcFS
 * @author Ulf Frisk - pcileech@frizk.net
 */
public class VmmMap_HeapMap implements Serializable
{
    private static final long serialVersionUID = 2532269971476991139L;
    public List<VmmMap_HeapEntry> heaps;
    public List<VmmMap_HeapSegmentEntry> segments;
    
    public String toString() {
        return "VmmMap_HeapMap";
    }
}
