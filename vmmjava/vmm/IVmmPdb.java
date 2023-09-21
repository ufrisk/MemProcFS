package vmm;

/**
 * Interface representing debug symbols for a specific module.
 * @see https://github.com/ufrisk/MemProcFS
 * @author Ulf Frisk - pcileech@frizk.net
 */
public interface IVmmPdb
{
    
    /**
     * Retrieve the module name of the PDB debug symbols.
     * @return
     */
    public String getModuleName();
    
    /**
     * Retrieve the address of the given symbol.
     * @param strSymbol
     * @return
     */
    public long getSymbolAddress(String strSymbol);
    
    /**
     * Retrieve the symbol name given symbol virtual address or offset.
     * @param vaSymbolOrOffset
     * @return
     */
    public String getSymbolName(long vaSymbolOrOffset);
    
    /**
     * Retrieve the symbol type child offset.
     * @param strTypeName
     * @param strChild
     * @return
     */
    public int getTypeChildOffset(String strTypeName, String strChild);
    
    /**
     * Retrieve a type size.
     * @param strTypeName
     * @return
     */
    public int getTypeSize(String strTypeName);
    
}
