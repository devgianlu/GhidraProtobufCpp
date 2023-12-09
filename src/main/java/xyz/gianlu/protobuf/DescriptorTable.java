package xyz.gianlu.protobuf;

import com.google.protobuf.DescriptorProtos.FileDescriptorProto;
import com.google.protobuf.InvalidProtocolBufferException;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.mem.MemoryAccessException;

import java.nio.ByteBuffer;

public final class DescriptorTable {
    private final boolean isEager;
    private final Address descriptorAddr;
    private final FileDescriptorProto descriptor;
    private final Address filenameAddr;
    private final String filename;
    private final Address depsAddr;
    private final DescriptorTable[] deps;
    private final int numMessages;
    private final Address schemasAddr;
    private final MigrationSchema[] schemas;
    private final Address defaultInstancesAddr;
    private final Message[] defaultInstances;
    private final Address offsetsAddr;
    private final int[] offsets;
    private final Address fileLevelMetadataAddr;
    private final Metadata fileLevelMetadata;
    private final Address fileLevelEnumDescriptorsAddr;
    private final EnumDescriptor[] fileLevelEnumDescriptors;
    private final Address fileLevelServiceDescriptorsAddr;
    private final ServiceDescriptor[] fileLevelServiceDescriptors;

    private DescriptorTable(
            boolean isEager,
            Address descriptorAddr,
            FileDescriptorProto descriptor,
            Address filenameAddr,
            String filename,
            Address depsAddr,
            DescriptorTable[] deps,
            int numMessages,
            Address schemasAddr,
            MigrationSchema[] schemas,
            Address defaultInstancesAddr,
            Message[] defaultInstances,
            Address offsetsAddr,
            int[] offsets,
            Address fileLevelMetadataAddr,
            Metadata fileLevelMetadata,
            Address fileLevelEnumDescriptorsAddr,
            EnumDescriptor[] fileLevelEnumDescriptors,
            Address fileLevelServiceDescriptorsAddr,
            ServiceDescriptor[] fileLevelServiceDescriptors
    ) {
        this.isEager = isEager;
        this.descriptorAddr = descriptorAddr;
        this.descriptor = descriptor;
        this.filenameAddr = filenameAddr;
        this.filename = filename;
        this.depsAddr = depsAddr;
        this.deps = deps;
        this.numMessages = numMessages;
        this.schemasAddr = schemasAddr;
        this.schemas = schemas;
        this.defaultInstancesAddr = defaultInstancesAddr;
        this.defaultInstances = defaultInstances;
        this.offsetsAddr = offsetsAddr;
        this.offsets = offsets;
        this.fileLevelMetadataAddr = fileLevelMetadataAddr;
        this.fileLevelMetadata = fileLevelMetadata;
        this.fileLevelEnumDescriptorsAddr = fileLevelEnumDescriptorsAddr;
        this.fileLevelEnumDescriptors = fileLevelEnumDescriptors;
        this.fileLevelServiceDescriptorsAddr = fileLevelServiceDescriptorsAddr;
        this.fileLevelServiceDescriptors = fileLevelServiceDescriptors;


    }

    public static int getStructSize(MemoryUtil util) {
        return 16 + 10 * util.getPointerSize();
    }

    public static DescriptorTable read(MemoryUtil mem, ByteBuffer buf) throws InvalidDescriptorTableException, MemoryAccessException {
        var structSize = getStructSize(mem);
        if (buf.remaining() < structSize) {
            throw new InvalidDescriptorTableException("Not enough data: %d".formatted(buf.remaining()));
        }

        var initialized = buf.get();
        if (initialized != 0)
            throw new InvalidDescriptorTableException("Invalid initialized flag: %d".formatted(initialized));

        var eager = buf.get();
        if (eager != 0 && eager != 1)
            throw new InvalidDescriptorTableException("Invalid eager flag: %d".formatted(eager));

        // skip padding
        buf.get();
        buf.get();

        var size = buf.getInt();
        if (size <= 0 || size > 10 * 1024 * 1024 /* 10 MiB */) {
            throw new InvalidDescriptorTableException("Invalid descriptor size: %d".formatted(size));
        }

        var descriptorAddr = mem.readPtr(buf, MemoryUtil.Space.PROTODESC_COLD);

        ByteBuffer descriptorData;
        try {
            descriptorData = mem.readMemory(descriptorAddr, size);
        } catch (MemoryAccessException ex) {
            throw new InvalidDescriptorTableException(ex);
        }

        FileDescriptorProto descriptor;
        try {
            descriptor = FileDescriptorProto.parseFrom(descriptorData);
        } catch (InvalidProtocolBufferException ex) {
            throw new InvalidDescriptorTableException(ex);
        }

        var filenameAddr = mem.readPtr(buf, MemoryUtil.Space.RODATA);

        String filename;
        try {
            filename = mem.readCString(filenameAddr);
        } catch (AddressOverflowException | MemoryAccessException ex) {
            throw new InvalidDescriptorTableException(ex);
        }

        if (!filename.endsWith(".proto")) {
            throw new InvalidDescriptorTableException("Invalid filename: %s".formatted(filename));
        }

        // skip once_flag
        mem.readPtr(buf, MemoryUtil.Space.DATA);

        var depsAddr = mem.readPtr(buf, MemoryUtil.Space.DATA);
        var numDeps = buf.getInt();

        var depsAddrData = mem.readMemory(depsAddr, mem.getPointerSize() * numDeps);
        var deps = new DescriptorTable[numDeps];
        for (int i = 0; i < numDeps; i++) {
            var depAddr = mem.readPtr(depsAddrData, MemoryUtil.Space.DATA);
            deps[i] = DescriptorTable.read(mem, mem.readMemory(depAddr, structSize));
        }

        var numMessages = buf.getInt();

        var schemasAddr = mem.readPtr(buf, MemoryUtil.Space.RODATA);
        var defaultInstancesAddr = mem.readPtr(buf, MemoryUtil.Space.DATA);
        var offsetsAddr = mem.readPtr(buf, MemoryUtil.Space.PROTODESC_COLD);
        var fileLevelMetadataAddr = mem.readPtr(buf, MemoryUtil.Space.RODATA);
        var fileLevelEnumDescriptorsAddr = mem.readPtr(buf, MemoryUtil.Space.RODATA);
        var fileLevelServiceDescriptorsAddr = mem.readPtr(buf, MemoryUtil.Space.RODATA);

        // TODO

        return new DescriptorTable(
                eager == 1,
                descriptorAddr,
                descriptor,
                filenameAddr,
                filename,
                depsAddr,
                deps,
                numMessages,
                schemasAddr,
                null,
                defaultInstancesAddr,
                null,
                offsetsAddr,
                null,
                fileLevelMetadataAddr,
                null,
                fileLevelEnumDescriptorsAddr,
                null,
                fileLevelServiceDescriptorsAddr,
                null
        );
    }

    public String getFilename() {
        return filename;
    }

    public String getFilenameNoExtension() {
        return filename.substring(0, filename.length() - 6);
    }

    public FileDescriptorProto getDescriptor() {
        return descriptor;
    }

    public Address getFileLevelMetadataAddr() {
        return fileLevelMetadataAddr;
    }

    public int getDepsCount() {
        return deps.length;
    }

    public int getNumMessages() {
        return numMessages;
    }

    public static class MigrationSchema {

    }

    public static class Message {

    }

    public static class Metadata {
        public static int getStructSize(MemoryUtil util) {
            return 2 * util.getPointerSize();
        }
    }

    public static class EnumDescriptor {

    }

    public static class ServiceDescriptor {

    }

    public static class InvalidDescriptorTableException extends Exception {
        InvalidDescriptorTableException(String message) {
            super(message);
        }

        InvalidDescriptorTableException(Throwable cause) {
            super(cause);
        }
    }
}
