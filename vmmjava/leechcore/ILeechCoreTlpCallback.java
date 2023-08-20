package leechcore;

/**
 * LeechCore PCIe TLP Callback Interface<br>
 * Check out the example code to get started! https://github.com/ufrisk/LeechCore/<br> 
 * @see https://github.com/ufrisk/LeechCore
 * @author Ulf Frisk - pcileech@frizk.net
 */
public interface ILeechCoreTlpCallback
{
	/**
	 * LeechCore TLP callback function. This function will be called when a
	 * PCIe TLP arrives. Optionally write back a response TLP via LeechCore.
	 * @param lc
	 * @param tlpData
	 * @param tlpInfo
	 */
	void LeechCoreTlpCallback(ILeechCore lc, byte[] tlpData, String tlpInfo);
}
