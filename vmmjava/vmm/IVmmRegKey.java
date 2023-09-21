package vmm;

import java.util.Map;

/**
 * Interface representing a registry key.
 * @see https://github.com/ufrisk/MemProcFS
 * @author Ulf Frisk - pcileech@frizk.net
 */
public interface IVmmRegKey
{
    
    /**
     * Retrieve the registry key name.
     * @return
     */
    public String getName();
    
    /**
     * Retrieve the registry key path.
     * @return
     */
    public String getPath();
    
    /**
     * Retrieve the parent key.
     * @return
     */
    public IVmmRegKey getKeyParent();
    
    /**
     * Retrieve the child keys.
     * @return
     */
    public Map<String, IVmmRegKey> getKeyChild();
    
    /**
     * Retrieve the values.
     * @return
     */
    public Map<String, IVmmRegValue> getValues();
    
    /**
     * Retrieve the last write time.
     * @return
     */
    public long getTime();
    
}
