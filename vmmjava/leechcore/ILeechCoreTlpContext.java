package leechcore;

/**
 * LeechCore PCIe TLP Context Interface<br>
 * The TLP callback is disabled when this interface is closed / cleaned up.
 * Check out the example code to get started! https://github.com/ufrisk/LeechCore/<br> 
 * @see https://github.com/ufrisk/LeechCore
 * @author Ulf Frisk - pcileech@frizk.net
 */
public interface ILeechCoreTlpContext
{
	/**
	 * Close/Inactivate the TLP callback.
	 */
	public void close();
}
