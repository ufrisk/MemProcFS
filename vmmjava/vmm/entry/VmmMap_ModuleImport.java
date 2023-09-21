package vmm.entry;

import java.io.Serializable;

/**
 * @see https://github.com/ufrisk/MemProcFS
 * @author Ulf Frisk - pcileech@frizk.net
 */
public class VmmMap_ModuleImport implements Serializable
{
    private static final long serialVersionUID = -3945880871638085047L;
    public long vaFunction;
    public String uszFunction;
    public String uszModule;
    // Thunk
    public boolean f32;
    public short wHint;
    public int rvaFirstThunk;
    public int rvaOriginalFirstThunk;
    public int rvaNameModule;
    public int rvaNameFunction;
    
    public String toString() {
        return "VmmMap_ModuleImport:" + uszModule + "!" + uszFunction;
    }
}
