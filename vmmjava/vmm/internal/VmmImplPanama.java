package vmm.internal;

import vmm.VmmException;

import java.lang.foreign.*;
import java.lang.invoke.MethodHandle;

import static java.lang.foreign.ValueLayout.*;

public class VmmImplPanama {

    // 256 kb
    private final int PRE_ALLOCATED_SEGMENT_SIZE = 0x40000;

    private final Arena arena = Arena.ofShared();
    private final Linker linker = Linker.nativeLinker();
    private final SymbolLookup lookup = SymbolLookup.libraryLookup("vmm.dll", arena);

    private MemorySegment vmmHandle;

    private MemorySegment dataBufferSegment;
    private MemorySegment refSegment;

    private VmmMethodHandles methodHandles;

    private VmmImplPanama() {

    }

    public VmmImplPanama(MemorySegment vmmHandle) {
        this.vmmHandle = vmmHandle;
        dataBufferSegment = arena.allocateArray(JAVA_BYTE, PRE_ALLOCATED_SEGMENT_SIZE);
        refSegment = arena.allocate(ADDRESS);
        methodHandles = new VmmMethodHandles();
        methodHandles.initialize();
    }

    public byte[] memRead(int pid, long va, int size, int flags) {
        if (size > PRE_ALLOCATED_SEGMENT_SIZE) {
            Arena dynamicArena = Arena.ofShared();
            MemorySegment dataBufferSegment = dynamicArena.allocateArray(JAVA_BYTE, size);
            byte[] bytes = memRead(pid, va, size, flags, dataBufferSegment);
            dynamicArena.close();
            return bytes;
        }
        return memRead(pid, va, size, flags, dataBufferSegment);
    }



    private byte[] memRead(int pid, long va, int size, int flags, MemorySegment dataBufferSegment) {
        boolean successful = (boolean) invokeUnchecked(methodHandles.memRead, vmmHandle, pid, va, dataBufferSegment, size, refSegment, flags);
        if (!successful) {
            throw new VmmException();
        }
        return getBytes(size, dataBufferSegment);
    }

    public void memWrite(int pid, long va, byte[] data) {
        int size = data.length;
        if (size > PRE_ALLOCATED_SEGMENT_SIZE) {
            Arena dynamicArena = Arena.ofShared();
            MemorySegment dataBufferSegment = dynamicArena.allocateArray(JAVA_BYTE, size);
            memWrite(pid, va, data, dataBufferSegment);
            dynamicArena.close();
        } else {
            memWrite(pid, va, data, dataBufferSegment);
        }
    }

    private void memWrite(int pid, long va, byte[] data, MemorySegment dataBufferSegment) {
        putBytes(data, dataBufferSegment);
        boolean successful = (boolean) invokeUnchecked(methodHandles.memWrite, vmmHandle, pid, va, dataBufferSegment, data.length);
        if (!successful) {
            throw new VmmException();
        }
    }

    public void scatterPrepare(MemorySegment scatterHandle, long va, int size) {
        boolean successful = (boolean) invokeUnchecked(methodHandles.scatterPrepare, scatterHandle, va, size);
        if (!successful) {
            throw new VmmException();
        }
    }

    public void scatterPrepareWrite(MemorySegment scatterHandle, long va, byte[] data) {
        int length = data.length;
        if (length > PRE_ALLOCATED_SEGMENT_SIZE) {
            Arena dynamicArena = Arena.ofShared();
            MemorySegment dataBufferSegment = dynamicArena.allocateArray(JAVA_BYTE, length);
            scatterPrepareWrite(scatterHandle, va, data, dataBufferSegment);
            dynamicArena.close();
        } else {
            scatterPrepareWrite(scatterHandle, va, data, dataBufferSegment);
        }
    }

    private void scatterPrepareWrite(MemorySegment scatterHandle, long va, byte[] data, MemorySegment dataBufferSegment) {
        putBytes(data, dataBufferSegment);
        boolean successful = (boolean) invokeUnchecked(methodHandles.scatterPrepareWrite, scatterHandle, va, dataBufferSegment, data.length);
        if (!successful) {
            throw new VmmException();
        }
    }

    public void scatterExecute(MemorySegment scatterHandle) {
        boolean successful = (boolean) invokeUnchecked(methodHandles.scatterExecute, scatterHandle);
        if (!successful) {
            throw new VmmException();
        }
    }

    public void scatterClear(MemorySegment scatterHandle, int pid, int flags) {
        boolean successful = (boolean) invokeUnchecked(methodHandles.scatterClear, scatterHandle, pid, flags);
        if (!successful) {
            throw new VmmException();
        }
    }

    public byte[] scatterRead(MemorySegment scatterHandle, long va, int size) {
        if (size > PRE_ALLOCATED_SEGMENT_SIZE) {
            Arena dynamicArena = Arena.ofShared();
            MemorySegment dataBufferSegment = dynamicArena.allocateArray(JAVA_BYTE, size);
            byte[] bytes = scatterRead(scatterHandle, va, size, dataBufferSegment);
            dynamicArena.close();
            return bytes;
        }
        return scatterRead(scatterHandle, va, size, dataBufferSegment);
    }

    private byte[] scatterRead(MemorySegment scatterHandle, long va, int size, MemorySegment dataBufferSegment) {
        boolean successful = (boolean) invokeUnchecked(methodHandles.scatterRead, scatterHandle, va, size, dataBufferSegment, refSegment);
        if (!successful) {
            throw new VmmException();
        }
        return getBytes(size, dataBufferSegment);
    }

    public void close() {
        arena.close();
    }

    // TODO: try reading/writing one by one and benchmark if it's faster than to wrap the segment as a ByteBuffer
    private void putBytes(byte[] data, MemorySegment dest) {
        dest.asByteBuffer().put(data);
    }

    private byte[] getBytes(int size, MemorySegment src) {
        byte[] bytes = new byte[size];
        src.asByteBuffer().get(bytes);
        return bytes;
    }

    // Just a utility function to not have to write try/catch in each invoke call
    private Object invokeUnchecked(MethodHandle methodHandle, Object... args) {
        try {
            return methodHandle.invokeWithArguments(args);
        } catch (Throwable e) {
            throw new RuntimeException(e);
        }
    }

    private class VmmMethodHandles {
        private MethodHandle memRead;
        private MethodHandle memWrite;
        private MethodHandle scatterPrepare;
        private MethodHandle scatterPrepareWrite;
        private MethodHandle scatterExecute;
        private MethodHandle scatterRead;
        private MethodHandle scatterClear;

        private void initialize() {
            initializeMemReadHandle();
            initializeMemWriteHandle();
            initializeScatterPrepareHandle();
            initializeScatterPrepareWriteHandle();
            initializeScatterExecuteHandle();
            initializeScatterClearHandle();
            initializeScatterReadHandle();
        }

        private void initializeMemReadHandle() {
            FunctionDescriptor memReadDescriptor = FunctionDescriptor.of(JAVA_BOOLEAN, ADDRESS, JAVA_INT, JAVA_LONG, ADDRESS, JAVA_INT, ADDRESS, JAVA_INT);
            memRead = constructMethodHandle("VMMDLL_MemReadEx", memReadDescriptor);
        }

        private void initializeMemWriteHandle() {
            FunctionDescriptor memWriteDescriptor = FunctionDescriptor.of(JAVA_BOOLEAN, ADDRESS, JAVA_INT, JAVA_LONG, ADDRESS, JAVA_INT);
            memWrite = constructMethodHandle("VMMDLL_MemWrite", memWriteDescriptor);
        }

        private void initializeScatterPrepareHandle() {
            FunctionDescriptor scatterPrepareDescriptor = FunctionDescriptor.of(JAVA_BOOLEAN, ADDRESS, JAVA_LONG, JAVA_INT);
            scatterPrepare = constructMethodHandle("VMMDLL_Scatter_Prepare", scatterPrepareDescriptor);
        }

        private void initializeScatterPrepareWriteHandle() {
            FunctionDescriptor scatterPrepareWriteDescriptor = FunctionDescriptor.of(JAVA_BOOLEAN, ADDRESS, JAVA_LONG, ADDRESS, JAVA_INT);
            scatterPrepareWrite = constructMethodHandle("VMMDLL_Scatter_PrepareWrite", scatterPrepareWriteDescriptor);
        }

        private void initializeScatterExecuteHandle() {
            FunctionDescriptor scatterExecuteDescriptor = FunctionDescriptor.of(JAVA_BOOLEAN, ADDRESS);
            scatterExecute = constructMethodHandle("VMMDLL_Scatter_Execute", scatterExecuteDescriptor);
        }

        private void initializeScatterClearHandle() {
            FunctionDescriptor scatterClearDescriptor = FunctionDescriptor.of(JAVA_BOOLEAN, ADDRESS, JAVA_INT, JAVA_INT);
            scatterClear = constructMethodHandle("VMMDLL_Scatter_Clear", scatterClearDescriptor);
        }

        private void initializeScatterReadHandle() {
            FunctionDescriptor scatterReadDescriptor = FunctionDescriptor.of(JAVA_BOOLEAN, ADDRESS, JAVA_LONG, JAVA_INT, ADDRESS, ADDRESS);
            scatterRead = constructMethodHandle("VMMDLL_Scatter_Read", scatterReadDescriptor);
        }

        /**
         * Constructs a {@link MethodHandle} from a method name and a {@link FunctionDescriptor}
         *
         * @param methodName name of the native method
         * @param descriptor descriptor of the native method (return type, arguments)
         * @return the constructed {@link MethodHandle}
         */
        private MethodHandle constructMethodHandle(String methodName, FunctionDescriptor descriptor) {
            MemorySegment memReadEx = lookup.find(methodName).orElseThrow();
            return linker.downcallHandle(memReadEx, descriptor);
        }

    }

}
