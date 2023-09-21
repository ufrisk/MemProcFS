package vmm.internal;

/**
 * Project "Panama" Native Code wrapper for MemProcFS
 * @see https://github.com/ufrisk/MemProcFS
 * @author Ulf Frisk - pcileech@frizk.net
 */
interface IVmmNativeEx {   
    public byte[] memRead(int pid, long va, int size, int flags);
    public void memWrite(int pid, long va, byte[] data);
    
    public Object scatterInitialize(int pid, int flags);
    public void scatterPrepare(Object scatterHandle, long va, int size);
    public void scatterPrepareWrite(Object scatterHandle, long va, byte[] data);
    public void scatterExecute(Object scatterHandle);
    public byte[] scatterRead(Object scatterHandle, long va, int size);
    public void scatterClear(Object scatterHandle, int pid, int flags);
    public void scatterClose(Object scatterHandle);
}
