package leechcore;

/**
 * LeechCore PCIe BAR Context Interface<br>
 * The BAR callback is disabled when this interface is closed / cleaned up.
 * Check out the example code to get started! https://github.com/ufrisk/LeechCore/<br> 
 * @see https://github.com/ufrisk/LeechCore
 * @author Ulf Frisk - pcileech@frizk.net
 */
public interface ILeechCoreBarContext
{
	/**
	 * Close/Inactivate the BAR callback.
	 */
	public void close();
}
