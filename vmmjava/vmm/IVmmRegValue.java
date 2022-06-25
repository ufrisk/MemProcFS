package vmm;

/**
 * Interface representing a registry value.
 * @see https://github.com/ufrisk/MemProcFS
 * @author Ulf Frisk - pcileech@frizk.net
 */
public interface IVmmRegValue
{
	
	/**
	 * Retrieve the registry key name.
	 * @return
	 */
	public String getName();
	
	/**
	 * Retrieve the registry type.
	 * @return
	 */
	public int getType();
	
	/**
	 * Retrieve the raw registry value.
	 * @return
	 */
	public byte[] getValue();
	
	/**
	 * Retrieve a DWORD value.
	 * @return
	 */
	public int getValueAsDword();
	
	/**
	 * Retrieve the registry value as a String.
	 * @return
	 */
	public String getValueAsString();
	
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
	
}
