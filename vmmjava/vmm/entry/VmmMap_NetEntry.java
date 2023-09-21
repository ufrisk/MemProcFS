package vmm.entry;

import java.io.Serializable;

/**
 * @see https://github.com/ufrisk/MemProcFS
 * @author Ulf Frisk - pcileech@frizk.net
 */
public class VmmMap_NetEntry implements Serializable
{
    private static final long serialVersionUID = 5333048748531523686L;
    public String str;
    public int dwPid;
    public int dwState;
    public short AF;
    public long vaObj;
    public long ftTime;
    public int dwPoolTag;
    public boolean srcValid;
    public boolean dstValid;
    public short srcPort;
    public short dstPort;
    public String srcStr;
    public String dstStr;
    
    public String toString() {
        return "VmmMap_NetEntry:'" + str + "'";
    }
}
