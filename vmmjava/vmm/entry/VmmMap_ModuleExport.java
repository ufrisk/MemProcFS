package vmm.entry;

import java.io.Serializable;

/**
 * @see https://github.com/ufrisk/MemProcFS
 * @author Ulf Frisk - pcileech@frizk.net
 */
public class VmmMap_ModuleExport implements Serializable
{
	private static final long serialVersionUID = -7123227183229190306L;
	public long vaFunction;
	public int dwOrdinal;
	public int oFunctionsArray;
	public int oNamesArray;
	public String uszModule;
	public String uszFunction;
	
	public String toString() {
		return "VmmMap_ModuleExport:" + uszModule + "!" + uszFunction;
	}
}
