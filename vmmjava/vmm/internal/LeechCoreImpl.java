package vmm.internal;

import java.nio.charset.StandardCharsets;

import com.sun.jna.*;
import com.sun.jna.ptr.*;

import leechcore.*;
import leechcore.entry.*;
import vmm.internal.LeechCoreNative.LC_BAR_REQUEST;

/**
 * JNA native code wrapper for LeechCore.
 * @see https://github.com/ufrisk/MemProcFS
 * @author Ulf Frisk - pcileech@frizk.net
 */
public class LeechCoreImpl implements ILeechCore
{ 
    
    //-----------------------------------------------------------------------------
    // INITIALIZATION FUNCTIONALITY BELOW:
    //-----------------------------------------------------------------------------
    Pointer hLC = null;
    String lcNativeLibraryPath = null;
    
    /*
     * Do not allow direct class instantiation from outside.
     */
    private LeechCoreImpl()
    {
    }
    
    private LeechCoreImpl(String lcNativeLibraryPath, String strDevice, String strRemote, int flagsVerbose, long paMax)
    {
        byte[] bDevice = strDevice.getBytes(StandardCharsets.UTF_8);
        byte[] bRemote = strRemote.getBytes(StandardCharsets.UTF_8);
        LeechCoreNative.LC_CONFIG lcConfig = new LeechCoreNative.LC_CONFIG();
        lcConfig.dwVersion = LeechCoreNative.LC_CONFIG_VERSION;
        System.arraycopy(bDevice, 0, lcConfig.szDevice, 0, Math.min(lcConfig.szDevice.length - 1, bDevice.length));
        System.arraycopy(bRemote, 0, lcConfig.szRemote, 0, Math.min(lcConfig.szRemote.length - 1, bRemote.length));
        lcConfig.dwPrintfVerbosity = flagsVerbose;
        lcConfig.paMax = paMax;
        System.setProperty("jna.library.path", lcNativeLibraryPath);
        hLC = LeechCoreNative.INSTANCE.LcCreate(lcConfig);
        if(hLC == null) { throw new LeechCoreException("LeechCore Init: failed in native code."); }
        this.lcNativeLibraryPath = lcNativeLibraryPath;
    }
    
    public static ILeechCore Initialize(vmm.IVmm vmmInstance)
    {
        if((vmmInstance == null) || !vmmInstance.isValid()) {
            return null;
        }
        long lcHandle = vmmInstance.getConfig(vmm.IVmm.OPT_CORE_LEECHCORE_HANDLE);
        String strDevice = "existing://0x" + Long.toHexString(lcHandle);
        String lcNativeLibraryPath = vmmInstance.getNativeLibraryPath();
        return new LeechCoreImpl(lcNativeLibraryPath, strDevice, "", 0, 0);
    }
    
    public static ILeechCore Initialize(String lcNativeLibraryPath, String strDevice)
    {
        return new LeechCoreImpl(lcNativeLibraryPath, strDevice, "", 0, 0);
    }
    
    public static ILeechCore Initialize(String lcNativeLibraryPath, String strDevice, String strRemote, int flagsVerbose, long paMax)
    {
        return new LeechCoreImpl(lcNativeLibraryPath, strDevice, strRemote, flagsVerbose, paMax);
    }
    
    public boolean isValid() {
        return hLC != null;
    }

    public String getNativeLibraryPath() {
        return lcNativeLibraryPath;
    }    
    
    public void close()
    {
        LeechCoreNative.INSTANCE.LcClose(hLC);
        hLC = null;
    }
    
    /*
     * Always close native implementation upon finalization.
     */
    @Override
    public void finalize()
    {
        try {
            this.close();
        } catch (Exception e) {}
    }
    
    /*
     * Custom toString() method.
     */
    @Override
    public String toString()
    {
        return (hLC != null) ? "LeechCore" : "LeechCoreNotValid";
    }
    
    
    
    //-----------------------------------------------------------------------------
    // CONFIGURATION SETTINGS BELOW:
    //-----------------------------------------------------------------------------
    
    @Override
    public long getOption(long fOption)
    {
        LongByReference pqw = new LongByReference();
        boolean f = LeechCoreNative.INSTANCE.LcGetOption(hLC, fOption, pqw);
        if(!f) { throw new LeechCoreException("LeechCore.LcGetOption(): failed."); }
        return pqw.getValue(); 
    }
    
    @Override
    public void setOption(long fOption, long qw)
    {
        boolean f = LeechCoreNative.INSTANCE.LcSetOption(hLC, fOption, qw);
        if(!f) { throw new LeechCoreException("LeechCore.LcSetOption(): failed."); }
    }

    @Override
    public byte[] memRead(long pa, int size)
    {
        byte[] pbResult = new byte[size];
        boolean f = LeechCoreNative.INSTANCE.LcRead(hLC, pa, size, pbResult); 
        if(!f) { throw new LeechCoreException("LeechCore.LcRead(): failed."); }
        return pbResult;
    }

    @Override
    public void memWrite(long pa, byte[] data)
    {
        boolean f = LeechCoreNative.INSTANCE.LcWrite(hLC, pa, data.length, data);
        if(!f) { throw new LeechCoreException("LeechCore.LcWrite(): failed."); }
    }

    @Override
    public String getMemMap()
    {
        return new String(command(ILeechCore.LC_CMD_MEMMAP_GET, null), StandardCharsets.UTF_8);
    }

    @Override
    public void setMemMap(String strMemMap)
    {
        byte[] bMemMap = strMemMap.getBytes(StandardCharsets.UTF_8);
        command(ILeechCore.LC_CMD_MEMMAP_SET, bMemMap);
    }
    
    @Override
    public byte[] command(long fCommand, byte[] data)
    {
        PointerByReference ppbDataOut = new PointerByReference();
        IntByReference pcbDataOut = new IntByReference();
        int dataInLen = 0;
        Pointer dataInPtr = null;
        if((data != null) && (data.length > 0)) {
            dataInLen = data.length;
            dataInPtr = new Memory(dataInLen);
            dataInPtr.write(0, data, 0, dataInLen);
        }
        boolean f = LeechCoreNative.INSTANCE.LcCommand(hLC, fCommand, dataInLen, dataInPtr, ppbDataOut, pcbDataOut);
        if(!f) { throw new LeechCoreException("LeechCore.LcCommand(): failed."); }
        int cbDataOut = pcbDataOut.getValue();
        if(0 == cbDataOut) { return null; }
        Pointer pbDataOut = ppbDataOut.getValue();
        if(0 == Pointer.nativeValue(pbDataOut)) { return null; }
        byte[] dataOut = pbDataOut.getByteArray(0, cbDataOut);
        LeechCoreNative.INSTANCE.LcMemFree(pbDataOut);
        return dataOut;
    }
    
    
    
    //-----------------------------------------------------------------------------
    // LEECHCORE TLP FUNCTIONALITY BELOW:
    //-----------------------------------------------------------------------------
    
    @Override
    public void writePCIeTLP(byte[] tlp)
    {
        if((tlp != null) && (tlp.length > 0) || ((tlp.length % 4) == 0)) {
            command(ILeechCore.LC_CMD_FPGA_TLP_WRITE_SINGLE, tlp);
        }
    }
    
    @Override
    public ILeechCoreTlpContext setPCIeTlpCallback(ILeechCoreTlpCallback callback)
    {
        return LeechCoreTlpContextImpl.initializeLeechCoreTlpContextImpl(this, callback);
    }
    
    
    
    //-----------------------------------------------------------------------------
    // LEECHCORE BAR FUNCTIONALITY BELOW:
    //-----------------------------------------------------------------------------
    
    @Override
    public LeechCoreBar[] getBarInfo()
    {
        IntByReference pcbDataOut = new IntByReference();
        PointerByReference ppbDataOut = new PointerByReference();
        boolean f = LeechCoreNative.INSTANCE.LcCommand(hLC, ILeechCore.LC_CMD_FPGA_BAR_INFO, 0, null, ppbDataOut, pcbDataOut);
        if(!f) { throw new LeechCoreException("LeechCore.LcCommand(): failed."); }
        Pointer pbDataOut =  ppbDataOut.getValue();
        if(0 == Pointer.nativeValue(pbDataOut)) { return null; }
        LeechCoreNative.LC_BAR_6 nativeBars = new LeechCoreNative.LC_BAR_6(pbDataOut);
        LeechCoreBar lcBars[] = new LeechCoreBar[6];
        // process result:
        for(LeechCoreNative.LC_BAR n : nativeBars.bars) {
            LeechCoreBar e = new LeechCoreBar();
            e.fValid = n.fValid;
            e.f64Bit = n.f64Bit;
            e.fPrefetchable = n.fPrefetchable;
            e.iBar = n.iBar;
            e.pa = n.pa;
            e.cb = n.cb;
            lcBars[e.iBar] = e;
        }
        LeechCoreNative.INSTANCE.LcMemFree(pbDataOut);
        return lcBars;
    }

    @Override
    public ILeechCoreBarContext setPCIeBarCallback(ILeechCoreBarCallback callback)
    {
        return LeechCoreBarContextImpl.initializeLeechCoreBarContextImpl(this, callback);
    }
}



//-----------------------------------------------------------------------------
// LEECHCORE INTERNAL TLP FUNCTIONALITY BELOW:
//-----------------------------------------------------------------------------

class LeechCoreTlpContextImpl implements ILeechCoreTlpContext
{
    private LeechCoreImpl lc;
    private Integer key;
    private Pointer keyPointer;
    private ILeechCoreTlpCallback cbUser;
    private LeechCoreNative.CALLBACK_TLP cbNative;
            
    static LeechCoreTlpContextImpl initializeLeechCoreTlpContextImpl(LeechCoreImpl lc, ILeechCoreTlpCallback cbUser)
    {
        LeechCoreTlpContextImpl ctx = new LeechCoreTlpContextImpl();
        ctx.cbNative = new LeechCoreNative.CALLBACK_TLP() {
            @Override
            public void invoke(int ctxNative, int cbTlp, Pointer pbTlp, int cbInfo, String szInfo) {
                try {
                    byte[] tlp = pbTlp.getByteArray(0, cbTlp);
                    Integer key = Integer.valueOf(ctxNative);
                    LeechCoreTlpContextImpl ctx = (LeechCoreTlpContextImpl)JnaObjectMap.getInstance().get(key);
                    ctx.cbUser.LeechCoreTlpCallback(ctx.lc, tlp, szInfo);
                } catch (Exception e) {}
            }
        };
        ctx.lc = lc;
        ctx.cbUser = cbUser;
        ctx.key = JnaObjectMap.getInstance().put(ctx);
        ctx.keyPointer = new Pointer(ctx.key.longValue());
        if(!LeechCoreNative.INSTANCE.LcSetOption(lc.hLC, ILeechCore.LC_OPT_FPGA_TLP_READ_CB_WITHINFO, 1)) {
            ctx.close();
            return null;
        }
        if(!LeechCoreNative.INSTANCE.LcCommand(lc.hLC, ILeechCore.LC_CMD_FPGA_TLP_CONTEXT, 0, ctx.keyPointer, null, null)) {
            ctx.close();
            return null;
        }
        if(!LeechCoreNativeEx.INSTANCE.LcCommand(lc.hLC, ILeechCore.LC_CMD_FPGA_TLP_FUNCTION_CALLBACK, 0, ctx.cbNative, null, null)) {
            ctx.close();
            return null;
        }
        return ctx;
    }
    
    @Override
    public void close()
    {
        if((lc == null) || (key == null)) {
            return;
        }
        PointerByReference pptr = new PointerByReference();
        if(!LeechCoreNative.INSTANCE.LcCommand(lc.hLC, ILeechCore.LC_CMD_FPGA_TLP_CONTEXT_RD, 0, null, pptr, null)) {
            return;
        }
        if(Pointer.nativeValue(pptr.getPointer()) != key.longValue()) {
            return;
        }
        LeechCoreNative.INSTANCE.LcCommand(lc.hLC, ILeechCore.LC_CMD_FPGA_TLP_FUNCTION_CALLBACK, 0, null, null, null);
        LeechCoreNative.INSTANCE.LcCommand(lc.hLC, ILeechCore.LC_CMD_FPGA_TLP_CONTEXT, 0, null, null, null);
        JnaObjectMap.getInstance().remove(key);
        keyPointer = null;
        cbNative = null;
        cbUser = null;
        key = null;
        lc = null;
    }
    
    /*
     * Always close native implementation upon finalization.
     */
    @Override
    public void finalize()
    {
        try {
            close();
        } catch (Exception e) {}
    }
    
    @Override
    public String toString()
    {
        return "LeechCoreTlpContext";
    }
}



//-----------------------------------------------------------------------------
// LEECHCORE INTERNAL BAR FUNCTIONALITY BELOW:
//-----------------------------------------------------------------------------

class LeechCoreBarReplyImpl implements ILeechCoreBarReply
{
    LC_BAR_REQUEST n;
    
    @Override
    public void reply(byte[] data) {
        if(!n.fRead) {
            throw new LeechCoreException("LeechCore.replyBarRead(): only possible to reply to read requests.");
        }
        if(data == null) {
            n.cbData = 0;
            n.fReadReply = true;
            return;
        }
        if(n.cbData != data.length) {
            throw new LeechCoreException("LeechCore.replyBarRead(): data length of reply mis-matches requested data length.");
        }
        n.fReadReply = true;
        System.arraycopy(data, 0, n.pbData, 0, n.cbData);
    }
}

class LeechCoreBarContextImpl implements ILeechCoreBarContext
{
    private LeechCoreImpl lc;
    private Integer key;
    private Pointer keyPointer;
    private ILeechCoreBarCallback cbUser;
    private LeechCoreNative.CALLBACK_BAR cbNative;
            
    static LeechCoreBarContextImpl initializeLeechCoreBarContextImpl(LeechCoreImpl lc, ILeechCoreBarCallback cbUser)
    {
        LeechCoreBarContextImpl ctx = new LeechCoreBarContextImpl();
        ctx.cbNative = new LeechCoreNative.CALLBACK_BAR() {
            @Override
            public void invoke(LC_BAR_REQUEST n) {
                try {
                    LeechCoreNative.LC_BAR nbar = new LeechCoreNative.LC_BAR(n.pBar);
                    LeechCoreBar bar = new LeechCoreBar();
                    bar.fValid = nbar.fValid;
                    bar.fIO = nbar.fIO;
                    bar.f64Bit = nbar.f64Bit;
                    bar.fPrefetchable = nbar.fPrefetchable;
                    bar.iBar = nbar.iBar;
                    bar.pa = nbar.pa;
                    bar.cb = nbar.cb;
                    LeechCoreBarReplyImpl reply = new LeechCoreBarReplyImpl();
                    reply.n = n;
                    LeechCoreBarRequest req = new LeechCoreBarRequest();
                    req.reply = reply;
                    req.bar = bar;
                    req.bTag = n.bTag;
                    req.bFirstBE = n.bFirstBE;
                    req.bLastBE = n.bLastBE;
                    req.is64Bit = n.f64;
                    req.isRead = n.fRead;
                    req.isWrite = n.fWrite;
                    req.cbData = n.cbData;
                    req.oData = n.oData;
                    if(req.isWrite) {
                        req.pbDataWrite = new byte[req.cbData];
                        System.arraycopy(n.pbData,  0,  req.pbDataWrite,  0,  req.cbData);
                    }
                    // call into user-defined function:
                    // user may optionally call back to reply.reply() which updated native data.
                    Integer key = Integer.valueOf((int)Pointer.nativeValue(n.ctx));
                    LeechCoreBarContextImpl ctx = (LeechCoreBarContextImpl)JnaObjectMap.getInstance().get(key);
                    ctx.cbUser.LeechCoreBarCallback(req);
                } catch (Exception e) {}
            }
        };
        ctx.lc = lc;
        ctx.cbUser = cbUser;
        ctx.key = JnaObjectMap.getInstance().put(ctx);
        ctx.keyPointer = new Pointer(ctx.key.longValue());
        if(!LeechCoreNative.INSTANCE.LcCommand(lc.hLC, ILeechCore.LC_CMD_FPGA_BAR_CONTEXT, 0, ctx.keyPointer, null, null)) {
            ctx.close();
            return null;
        }
        if(!LeechCoreNativeEx.INSTANCE.LcCommand(lc.hLC, ILeechCore.LC_CMD_FPGA_BAR_FUNCTION_CALLBACK, 0, ctx.cbNative, null, null)) {
            ctx.close();
            return null;
        }
        return ctx;
    }
    
    @Override
    public void close()
    {
        if((lc == null) || (key == null)) {
            return;
        }
        PointerByReference pptr = new PointerByReference();
        if(!LeechCoreNative.INSTANCE.LcCommand(lc.hLC, ILeechCore.LC_CMD_FPGA_BAR_CONTEXT_RD, 0, null, pptr, null)) {
            return;
        }
        if(Pointer.nativeValue(pptr.getPointer()) != key.longValue()) {
            return;
        }
        LeechCoreNative.INSTANCE.LcCommand(lc.hLC, ILeechCore.LC_CMD_FPGA_BAR_FUNCTION_CALLBACK, 0, null, null, null);
        LeechCoreNative.INSTANCE.LcCommand(lc.hLC, ILeechCore.LC_CMD_FPGA_BAR_CONTEXT, 0, null, null, null);
        JnaObjectMap.getInstance().remove(key);
        keyPointer = null;
        cbNative = null;
        cbUser = null;
        key = null;
        lc = null;
    }
    
    /*
     * Always close native implementation upon finalization.
     */
    @Override
    public void finalize()
    {
        try {
            close();
        } catch (Exception e) {}
    }
    
    @Override
    public String toString()
    {
        return "LeechCoreBarContext";
    }
}
