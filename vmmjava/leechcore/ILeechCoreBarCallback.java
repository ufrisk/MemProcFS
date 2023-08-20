package leechcore;

import leechcore.entry.LeechCoreBarRequest;

/**
 * LeechCore PCIe BAR Callback Interface<br>
 * Check out the example code to get started! https://github.com/ufrisk/LeechCore/<br> 
 * @see https://github.com/ufrisk/LeechCore
 * @author Ulf Frisk - pcileech@frizk.net
 */
public interface ILeechCoreBarCallback
{
	/**
	 * Callback function will be called when a PCIe BAR request arrives at the FPGA.
	 * If it's a read then it should be replied to by calling req.readReply();
	 * @param req
	 */
	public void LeechCoreBarCallback(LeechCoreBarRequest req);
}
