package leechcore.entry;

import leechcore.ILeechCoreBarReply;

/**
 * @see https://github.com/ufrisk/LeechCore
 * @author Ulf Frisk - pcileech@frizk.net
 */
public class LeechCoreBarRequest
{
	public ILeechCoreBarReply reply;
	public LeechCoreBar bar;
	public byte bTag;
	public byte bFirstBE;
	public byte bLastBE;
	public boolean is64Bit;
	public boolean isRead;
	public boolean isWrite;
	public int cbData;
	public long oData;
	public byte[] pbDataWrite;
	
	public String toString() {
		return "LeechCoreBarRequest";
	}
}
