package vmm.entry;

import java.io.Serializable;

/**
 * @see https://github.com/ufrisk/MemProcFS
 * @author Ulf Frisk - pcileech@frizk.net
 */
public class Vmm_ModuleExVersionInfo implements Serializable {
    
    private static final long serialVersionUID = -9023423751540659830L;
    public String CompanyName;
    public String FileDescription;
    public String FileVersion;
    public String InternalName;
    public String LegalCopyright;
    public String OriginalFilename;
    public String ProductName;
    public String ProductVersion;
    
    public String toString() {
        return "Vmm_ModuleExVersionInfo";
    }
}
