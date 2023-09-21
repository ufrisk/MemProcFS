package vmm.entry;

import java.io.Serializable;

/**
 * @see https://github.com/ufrisk/MemProcFS
 * @author Ulf Frisk - pcileech@frizk.net
 */
public class VmmMap_ModuleDataDirectory implements Serializable
{
    private static final long serialVersionUID = -603939752974235784L;
    public long RealVirtualAddress;
    public int VirtualAddress;
    public int Size;
    public String name;
    
    public String toString() {
        return "VmmMap_ModuleDataDirectory:" + name;
    }
}
