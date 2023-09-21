package vmm.entry;

import java.io.Serializable;

/**
 * @see https://github.com/ufrisk/MemProcFS
 * @author Ulf Frisk - pcileech@frizk.net
 */
public class VmmMap_VadEntry implements Serializable
{
    private static final long serialVersionUID = -4829077937239905960L;
    public long vaStart;
    public long vaEnd;
    public long vaVad;
    public int dw0;
    public int dw1;
    public int dwu2;
    public int cbPrototypePte;
    public long vaPrototypePte;
    public long vaSubsection;
    public String uszText;
    public long vaFileObject;
    public int cVadExPages;
    public int cVadExPagesBase;
    
    public String toString() {
        return "VmmMap_VadEntry:" + Long.toHexString(vaStart) + ":" + Long.toHexString(vaEnd);
    }
}
