package vmm.entry;

import java.io.Serializable;

/**
 * @see https://github.com/ufrisk/MemProcFS
 * @author Ulf Frisk - pcileech@frizk.net
 */
public class Vmm_VfsListEntry implements Serializable
{
    private static final long serialVersionUID = -2708452659192929578L;
    public String name;
    public boolean isFile;
    public long size;
    
    public String toString() {
        return "Vmm_VfsListEntry:" + name;
    }
}
