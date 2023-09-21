package vmm;

/**
 * Runtime Exception used to indicate exceptions from the underlying native API.
 * @see https://github.com/ufrisk/MemProcFS
 * @author Ulf Frisk - pcileech@frizk.net
 */
public class VmmException extends RuntimeException
{    
    
    private static final long serialVersionUID = 3361783299853681520L;

    public VmmException() {
        super("Native call to vmm failed!");
    }

    public VmmException(String errorMessage) {
        super(errorMessage);
    }
    
    public VmmException(String errorMessage, Throwable t) {
        super(errorMessage, t);
    }
    
}
