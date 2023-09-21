package vmm.internal;

import com.sun.jna.*;
import com.sun.jna.ptr.*;

/**
 * JNA native code wrapper for LeechCore.
 * @see https://github.com/ufrisk/MemProcFS
 * @author Ulf Frisk - pcileech@frizk.net
 */
interface LeechCoreNative extends Library {
    static final int MAX_PATH                        = 260;
    
    static final int LC_CONFIG_VERSION                 = 0xc0fd0002;
    
    LeechCoreNative INSTANCE = Native.load("leechcore", LeechCoreNative.class);
    
    @Structure.FieldOrder({"dwVersion", "dwPrintfVerbosity", "szDevice", "szRemote", "pfn_printf_opt", "paMax", "fVolatile", "fWritable", "fRemote", "fRemoteDisableCompress", "szDeviceName"})
    class LC_CONFIG extends Structure {
        public int dwVersion;
        public int dwPrintfVerbosity;
        public byte[] szDevice = new byte[MAX_PATH];
        public byte[] szRemote = new byte[MAX_PATH];
        public Pointer pfn_printf_opt;
        public long paMax;
        public boolean fVolatile;
        public boolean fWritable;
        public boolean fRemote;
        public boolean fRemoteDisableCompress;
        public byte[] szDeviceName = new byte[MAX_PATH];
    }
    
    Pointer LcCreate(LC_CONFIG pLcCreateConfig);
    void LcClose(Pointer hLC);
    long LcMemFree(Pointer pvMem);
    boolean LcRead(Pointer hLC, long pa, int cb, byte[] pb);
    boolean LcWrite(Pointer hLC, long pa, int cb, byte[] pb);
    boolean LcGetOption(Pointer hLC, long fOption, LongByReference pqwValue);
    boolean LcSetOption(Pointer hLC, long fOption, long qwValue);
    boolean LcCommand(Pointer hLC, long fCommand, int cbDataIn, Pointer pbDataIn, PointerByReference ppbDataOut, IntByReference pcbDataOut);
    
    interface CALLBACK_BAR extends Callback {
        void invoke(LC_BAR_REQUEST req);
    }
    
    interface CALLBACK_TLP extends Callback {
        void invoke(int ctxNative, int cbTlp, Pointer pbTlp, int cbInfo, String szInfo);
    }
    
    @Structure.FieldOrder({"fValid", "fIO", "f64Bit", "fPrefetchable", "iBar", "_Filler0", "_Filler1", "_Filler2", "pa", "cb"})
    class LC_BAR extends Structure {
        public boolean fValid;
        public boolean fIO;
        public boolean f64Bit;
        public boolean fPrefetchable;
        public int _Filler0;
        public int _Filler1;
        public int _Filler2;
        public int iBar;
        public long pa;
        public long cb;
        
        public LC_BAR(Pointer p) {
            super(p);
            read();
        }
    }
    
    @Structure.FieldOrder({"bars"})
    class LC_BAR_6 extends Structure {
        public LC_BAR[] bars;
        
        LC_BAR_6(Pointer p)
        {
            super(p);
            bars = new LC_BAR[6];
            read();
        }
    }
    
    @Structure.FieldOrder({"ctx", "pBar", "bTag", "bFirstBE", "bLastBE", "_Filler", "f64", "fRead", "fReadReply", "fWrite", "cbData", "oData", "pbData"})
    class LC_BAR_REQUEST extends Structure {
        public Pointer ctx;
        public Pointer pBar;
        public byte bTag;
        public byte bFirstBE;
        public byte bLastBE;
        public byte _Filler;
        public boolean f64;
        public boolean fRead;
        public boolean fReadReply;
        public boolean fWrite;
        public int cbData;
        public long oData;
        public byte[] pbData = new byte[4096];
    }
}

interface LeechCoreNativeEx extends Library
{
    LeechCoreNativeEx INSTANCE = Native.load("leechcore", LeechCoreNativeEx.class);
    boolean LcCommand(Pointer hLC, long fCommand, int cbDataIn, Callback pbDataIn, PointerByReference ppbDataOut, IntByReference pcbDataOut);
}
