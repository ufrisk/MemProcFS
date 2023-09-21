package vmm.entry;

import java.io.Serializable;

/**
 * @see https://github.com/ufrisk/MemProcFS
 * @author Ulf Frisk - pcileech@frizk.net
 */
public class VmmMap_PteEntry implements Serializable
{
    private static final long serialVersionUID = -7463671464805453585L;
    public long vaBase;
    public long cPages;
    public long fPage;
    public boolean fWow64;
    public String strDescription;
    public int cSoftware;
    
    public String toString() {
        return "VmmMap_PteEntry:" + Long.toHexString(vaBase) + ":" + Long.toHexString(cPages);
    }
}
