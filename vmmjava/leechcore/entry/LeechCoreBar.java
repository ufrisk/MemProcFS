package leechcore.entry;

import java.io.Serializable;

/**
 * @see https://github.com/ufrisk/LeechCore
 * @author Ulf Frisk - pcileech@frizk.net
 */
public class LeechCoreBar implements Serializable
{
	private static final long serialVersionUID = -8552459732654567239L;
	public boolean fValid;
	public boolean fIO;
	public boolean f64Bit;
	public boolean fPrefetchable;
	public int iBar;
	public long pa;
	public long cb;
	
	public String toString() {
		if(this.fValid) {
			return "LeechCoreBar:" + iBar + ":[" + Long.toHexString(pa) + "->" + Long.toHexString((pa + cb - 1)) + "]";
		} else {
			return "LeechCoreBar:" + iBar + ":inactive";	
		}
	}
}
