package xyz.gianlu.protobuf;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.DataOrganization;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

public final class MemoryUtil {
    private final Program program;
    private final DataOrganization dataOrg;
    private final AddressSpace textAddrSpace;
    private final AddressRange roAddrRange;
    private final AddressSpace descAddrSpace;
    private final AddressSpace roAddrSpace;
    private final AddressSpace dataAddrSpace;

    private MemoryUtil(Program program) {
        this.program = program;
        this.dataOrg = program.getDataTypeManager().getDataOrganization();

        // protobuf descriptor tables are in ".data"
        this.textAddrSpace = program.getMemory().getBlock(".text").getAddressRange().getAddressSpace();

        // protobuf descriptors are in "protodesc_cold".
        this.descAddrSpace = program.getMemory().getBlock("protodesc_cold").getAddressRange().getAddressSpace();

        // protobuf filenames are in ".rodata"
        this.roAddrRange = program.getMemory().getBlock(".rodata").getAddressRange();
        this.roAddrSpace = roAddrRange.getAddressSpace();

        // protobuf descriptor tables are in ".data"
        this.dataAddrSpace = program.getMemory().getBlock(".data").getAddressRange().getAddressSpace();
    }

    public static MemoryUtil forProgram(Program program) {
        return new MemoryUtil(program);
    }

    public int getPointerSize() {
        return dataOrg.getPointerSize();
    }

    public boolean isRoDataAddr(Address addr) {
        return roAddrRange.contains(addr);
    }

    public Address readPtr(ByteBuffer buf, Space space) {
        long offset;
        var dataOrg = program.getDataTypeManager().getDataOrganization();
        if (dataOrg.getPointerSize() == 4) {
            offset = buf.getInt();
        } else if (dataOrg.getPointerSize() == 8) {
            offset = buf.getLong();
        } else {
            throw new RuntimeException("Unsupported pointer size");
        }

        return switch (space) {
            case PROTODESC_COLD -> descAddrSpace.getAddressInThisSpaceOnly(offset);
            case RODATA -> roAddrSpace.getAddressInThisSpaceOnly(offset);
            case DATA -> dataAddrSpace.getAddressInThisSpaceOnly(offset);
            case TEXT -> textAddrSpace.getAddressInThisSpaceOnly(offset);
        };
    }

    public ByteBuffer readMemory(Address addr, int count) throws MemoryAccessException {
        var buf = new byte[count];
        var read = program.getMemory().getBytes(addr, buf);
        if (read != count) {
            throw new MemoryAccessException("Failed reading full buffer: %d < %d".formatted(read, count));
        }

        return ByteBuffer.wrap(buf).order(ByteOrder.LITTLE_ENDIAN);
    }

    public String readCString(Address addr) throws MemoryAccessException, AddressOverflowException {
        var str = new StringBuilder();
        while (true) {
            var c = program.getMemory().getByte(addr);
            if (c == 0) {
                return str.toString();
            }

            str.append((char) c);
            addr = addr.addNoWrap(1);
        }
    }

    public enum Space {
        PROTODESC_COLD,
        RODATA,
        DATA,
        TEXT
    }
}
