package vmm.entry;

import java.io.Serializable;

/**
 * @see https://github.com/ufrisk/MemProcFS
 * @author Ulf Frisk - pcileech@frizk.net
 */
public class Vmm_ModuleExDebugInfo implements Serializable {

    private static final long serialVersionUID = -7875377132222488703L;
    public int dwAge;
    public byte[] GuidBytes;
    public String Guid;
    public String PdbFilename;

    public String toString() {
        return "Vmm_ModuleExDebugInfo";
    }
}
