package vmm.entry;

import java.io.Serializable;

/**
 * @see https://github.com/ufrisk/MemProcFS
 * @author Ulf Frisk - pcileech@frizk.net
 */
public class VmmMap_ServiceEntry implements Serializable
{
    private static final long serialVersionUID = 1274183168020644036L;
    public int dwServiceType;
    public int dwCurrentState;
    public int dwControlsAccepted;
    public int dwWin32ExitCode;
    public int dwServiceSpecificExitCode;
    public int dwCheckPoint;
    public int dwWaitHint;
    public long vaObj;
    public int dwOrdinal;
    public int dwStartType;
    public String uszServiceName;
    public String uszDisplayName;
    public String uszPath;
    public String uszUserTp;
    public String uszUserAcct;
    public String uszImagePath;
    public int dwPID;
    
    public String toString() {
        return "VmmMap_ServiceEntry:" + uszServiceName;
    }
}
