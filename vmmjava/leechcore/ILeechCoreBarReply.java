package leechcore;

/**
 * LeechCore PCIe BAR Read Reply Interface<br>
 * Check out the example code to get started! https://github.com/ufrisk/LeechCore/<br> 
 * @see https://github.com/ufrisk/LeechCore
 * @author Ulf Frisk - pcileech@frizk.net
 */
public interface ILeechCoreBarReply
{
	/**
	 * Send a read reply back to the system.
	 * Only use this to reply to PCIe BAR read requests. Not write requests!
	 * @param data = data matching req.cbData in length. null == failed request / unsupported request (UR) reply.
	 */
	public void reply(byte[] data);
}
