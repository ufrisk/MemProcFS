package vmm.entry;

import java.io.Serializable;

/**
 * @see https://github.com/ufrisk/MemProcFS
 * @author Ulf Frisk - pcileech@frizk.net
 */
public class VmmMap_ThreadEntry implements Serializable
{
    private static final long serialVersionUID = -8162285678132928372L;
    public int dwTID;
    public int dwPID;
    public int dwExitStatus;
    public byte bState;
    public byte bRunning;
    public byte bPriority;
    public byte bBasePriority;
    public long vaETHREAD;
    public long vaTeb;
    public long ftCreateTime;
    public long ftExitTime;
    public long vaStartAddress;
    public long vaWin32StartAddress;
    public long vaStackBaseUser;
    public long vaStackLimitUser;
    public long vaStackBaseKernel;
    public long vaStackLimitKernel;
    public long vaTrapFrame;
    public long vaImpersonationToken;
    public long vaRIP;
    public long vaRSP;
    public long qwAffinity;
    public int dwUserTime;
    public int dwKernelTime;
    public byte bSuspendCount;
    public byte bWaitReason;
    
    public String toString() {
        return "VmmMap_ThreadEntry:" + String.valueOf(dwTID);
    }
}
