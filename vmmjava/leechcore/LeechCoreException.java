package leechcore;

/**
 * Runtime Exception used to indicate exceptions from the underlying native API.
 * @see https://github.com/ufrisk/MemProcFS
 * @author Ulf Frisk - pcileech@frizk.net
 */
public class LeechCoreException extends RuntimeException
{	
	
	private static final long serialVersionUID = 3361783299857781520L;

	public LeechCoreException() {
        super("Native call to leechcore failed!");
    }

	public LeechCoreException(String errorMessage) {
        super(errorMessage);
    }
	
}
