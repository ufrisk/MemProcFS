package vmm.entry;

import java.io.Serializable;

/**
 * @see https://github.com/ufrisk/MemProcFS
 * @author Ulf Frisk - pcileech@frizk.net
 */
public class VmmMap_UserEntry implements Serializable
{
    private static final long serialVersionUID = -7758667727787190877L;
    public String user;
    public String SID;
    public long vaRegHive;
    
    public String toString() {
        return "VmmMap_UserEntry:" + user;
    }
}
