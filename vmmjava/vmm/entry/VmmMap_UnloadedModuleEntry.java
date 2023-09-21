package vmm.entry;

import java.io.Serializable;

/**
 * @see https://github.com/ufrisk/MemProcFS
 * @author Ulf Frisk - pcileech@frizk.net
 */
public class VmmMap_UnloadedModuleEntry implements Serializable
{
    private static final long serialVersionUID = 2432835898565494177L;
    public long vaBase;
    public long cbImageSize;
    public boolean fWow64;
    public String strModuleName;
    public int dwCheckSum;
    public int dwTimeDateStamp;
    public long ftUnload;
    
    public String toString() {
        return "VmmMap_UnloadedModuleEntry:" + strModuleName;
    }
}
