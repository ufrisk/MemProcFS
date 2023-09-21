package vmm.entry;

import java.io.Serializable;

/**
 * @see https://github.com/ufrisk/MemProcFS
 * @author Ulf Frisk - pcileech@frizk.net
 */
public class VmmMap_VadExEntry implements Serializable
{
    private static final long serialVersionUID = -2942891920206162420L;
    public int tp;
    public int iPML;
    public int pteFlags;
    public long va;
    public long pa;
    public long pte;
    public int proto_tp;
    public long proto_pa;
    public long proto_pte;
    public long vaVadBase;
    
    public String toString() {
        return "VmmMap_VadExEntry:" + Long.toHexString(va);
    }
}
