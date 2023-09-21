package vmm.entry;

import java.io.Serializable;

/**
 * @see https://github.com/ufrisk/MemProcFS
 * @author Ulf Frisk - pcileech@frizk.net
 */
public class VmmMap_HandleEntry implements Serializable
{
    private static final long serialVersionUID = 7952416272217348610L;
    public long vaObject;
    public int dwHandle;
    public int _dwGrantedAccess_iType;
    public long qwHandleCount;
    public long qwPointerCount;
    public long vaObjectCreateInfo;
    public long vaSecurityDescriptor;
    public String name;
    public int dwPID;
    public String tag;
    public String type;
    
    public String toString() {
        return "VmmMap_HandleEntry:'" + name + "'";
    }
}
