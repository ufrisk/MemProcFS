package vmm.entry;

import java.io.Serializable;

/**
 * @see https://github.com/ufrisk/MemProcFS
 * @author Ulf Frisk - pcileech@frizk.net
 */
public class VmmMap_ModuleSection implements Serializable
{
    private static final long serialVersionUID = -8748153308397838653L;
    public String name;
    public int MiscVirtualSize;
    public int VirtualAddress;
    public int SizeOfRawData;
    public int PointerToRawData;
    public int PointerToRelocations;
    public int PointerToLinenumbers;
    public short NumberOfRelocations;
    public short NumberOfLinenumbers;
    public int Characteristics;
    
    public String toString() {
        return "VmmMap_ModuleSection:" + name;
    }
}
