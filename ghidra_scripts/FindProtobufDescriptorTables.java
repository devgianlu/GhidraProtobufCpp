//This script finds all C++ protobuf table descriptors.
//
//@author devgianlu
//@category Protobuf
//@keybinding
//@menupath
//@toolbar

import com.google.protobuf.DescriptorProtos;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.CompilerSpec;
import ghidra.program.model.listing.Function;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import xyz.gianlu.protobuf.DescriptorTable;
import xyz.gianlu.protobuf.MemoryUtil;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;


public class FindProtobufDescriptorTables extends GhidraScript {

    private static List<DescriptorProtos.DescriptorProto> getMessages(DescriptorProtos.FileDescriptorProto descriptor) {
        var list = new ArrayList<DescriptorProtos.DescriptorProto>();
        for (var msg : descriptor.getMessageTypeList()) getMessages(list, msg);
        return list;
    }

    private static void getMessages(List<DescriptorProtos.DescriptorProto> list, DescriptorProtos.DescriptorProto descriptor) {
        for (var msg : descriptor.getNestedTypeList()) getMessages(list, msg);
        list.add(descriptor);
    }

    private DataType getDescriptorTableDataType() {
        var dtm = getCurrentProgram().getDataTypeManager();
        var category = dtm.createCategory(new CategoryPath("/google/protobuf/internal"));

        var dataType = category.getDataType("DescriptorTable");
        if (dataType == null) {
            var dataType_ = new StructureDataType("DescriptorTable", 0, dtm);
            dataType_.add(new BooleanDataType(dtm), "is_initialized", ""); // 0x1
            dataType_.add(new BooleanDataType(dtm), "is_eager", "");       // 0x2
            dataType_.add(new Undefined1DataType(dtm));
            dataType_.add(new Undefined1DataType(dtm));
            dataType_.add(new IntegerDataType(dtm), "size", "");                                // 0x4
            dataType_.add(new PointerDataType(new CharDataType(dtm), dtm), "descriptor", "");   // 0x8
            dataType_.add(new PointerDataType(new CharDataType(dtm), dtm), "filename", "");     // 0x10
            dataType_.add(new PointerDataType(new VoidDataType(dtm), dtm), "once", "");         // 0x18
            dataType_.add(new PointerDataType(dataType_, dtm), "deps", "");                     // 0x20
            dataType_.add(new IntegerDataType(dtm), "num_deps", "");                            // 0x28
            dataType_.add(new IntegerDataType(dtm), "num_messages", "");                        // 0x2c
            dataType_.add(new PointerDataType(new VoidDataType(dtm), dtm), "schemas", "");      // 0x30
            dataType_.add(new PointerDataType(new PointerDataType(new VoidDataType(dtm), dtm), dtm), "default_instances", "");   // 0x38
            dataType_.add(new PointerDataType(new UnsignedIntegerDataType(dtm), dtm), "offsets", "");   // 0x40
            dataType_.add(new PointerDataType(new VoidDataType(dtm), dtm), "file_level_metadata", "");  // 0x48
            dataType_.add(new PointerDataType(new PointerDataType(new VoidDataType(dtm), dtm), dtm), "file_level_enum_descriptors", "");     // 0x50
            dataType_.add(new PointerDataType(new PointerDataType(new VoidDataType(dtm), dtm), dtm), "file_level_service_descriptors", "");  // 0x58
            dataType = category.addDataType(dataType_, null);
        }

        return dataType;
    }

    private DataType getInternalMetadataDataType() {
        var dtm = getCurrentProgram().getDataTypeManager();
        var category = dtm.createCategory(new CategoryPath("/google/protobuf/internal"));

        var dataType = category.getDataType("InternalMetadata");
        if (dataType == null) {
            var dataType_ = new StructureDataType("InternalMetadata", 0, dtm);
            dataType_.add(new PointerDataType(dtm), "ptr_", "");
            dataType = category.addDataType(dataType_, null);
        }

        return dataType;
    }

    private DataType getProtobufMessageVtableDataType() {
        var dtm = getCurrentProgram().getDataTypeManager();
        var category =dtm .createCategory(new CategoryPath("/google/protobuf"));

        var dataType = category.getDataType("VTABLE_Message");
        if (dataType == null) {
            var fields = new String[]{
                    "~1",
                    "~2",
                    null,
                    null,
                    null,
                    null,
                    null,
                    null,
                    null,
                    null,
                    null,
                    null,
                    "_InternalSerialize",
                    null,
                    null,
                    null,
                    "GetMetadata",
                    null,
            };

            var dataType_ = new StructureDataType("VTABLE_Message", 0, dtm);
            for (var field : fields) {
                if (field == null) dataType_.add(new PointerDataType(dtm));
                else dataType_.add(new PointerDataType(dtm), field, "");
            }


            dataType = category.addDataType(dataType_, null);
        }

        return dataType;
    }

    private Namespace getOrCreateNamespace(String fullName) throws InvalidInputException, DuplicateNameException {
        Namespace namespace = null;
        for (var part : fullName.split("::")) namespace = createNamespace(namespace, part);
        return namespace;
    }

    @Override
    protected void run() throws Exception {
        var dtm = getCurrentProgram().getDataTypeManager();
        var mem = MemoryUtil.forProgram(getCurrentProgram());

        var descriptorTableDataType = getDescriptorTableDataType();
        var protobufMessageVtableDataType = getProtobufMessageVtableDataType();
        var internalMetadataDataType = getInternalMetadataDataType();

        var structSize = DescriptorTable.getStructSize(mem);
        var dataBlock = getMemoryBlock(".data");

        for (var addr : dataBlock.getAddressRange()) {
            ByteBuffer buf;
            try {
                buf = mem.readMemory(addr, structSize);
            } catch (MemoryAccessException ex) {
                continue;
            }

            DescriptorTable table;
            try {
                table = DescriptorTable.read(mem, buf);
            } catch (DescriptorTable.InvalidDescriptorTableException ex) {
                // was not a DescriptorTable
                continue;
            }

            // clear conflictingly data and place struct and label
            clearListing(addr, addr.addNoWrap(descriptorTableDataType.getLength()));
            createData(addr, descriptorTableDataType);
            createLabel(addr, "ProtoDescriptorTable_%s".formatted(table.getFilenameNoExtension()), true);

            printf("[+] Found table at %s (%s, messages: %d)\n", addr, table.getFilename(), table.getNumMessages());

            // iterate through the file level metadata structs
            var messageTypes = getMessages(table.getDescriptor());
            for (int i = 0; i < table.getNumMessages(); i++) {
                var messageType = messageTypes.get(i);

                var vtableLabel = "VTABLE_%s_%s".formatted(table.getDescriptor().getPackage().replace(".", "_"), messageType.getName());
                var packageNamespace = getOrCreateNamespace(table.getDescriptor().getPackage().replace(".", "::"));
                var messageClass = createClass(packageNamespace, messageType.getName());

                var vtableSymbol = getSymbols(vtableLabel, null).stream().findFirst().orElse(null);
                if (vtableSymbol == null) {
                    // find the "::$proto_ns$::Metadata $classname$::GetMetadata() const" generated function
                    Function metadataFunc = null;
                    var metadataAddr = table.getFileLevelMetadataAddr().addNoWrap((long) i * DescriptorTable.Metadata.getStructSize(mem));
                    for (var ref : getReferencesTo(metadataAddr)) {
                        if (ref.getReferenceType() != RefType.PARAM)
                            continue;

                        metadataFunc = getFunctionContaining(ref.getFromAddress());
                        if (metadataFunc != null)
                            break;
                    }

                    if (metadataFunc == null) {
                        printf("    - (x) Failed finding metadata class method for %s.%s\n", table.getDescriptor().getPackage(), messageType.getName());
                        continue;
                    }

                    // this function is pure virtual, so it is present in the class' vtable.
                    Address vtableStart = null;
                    for (var vtableRef : getReferencesTo(metadataFunc.getEntryPoint())) {
                        if (vtableRef.getReferenceType() != RefType.DATA)
                            continue;

                        if (!mem.isRoDataAddr(vtableRef.getFromAddress()))
                            continue;

                        vtableStart = vtableRef.getFromAddress().subtractNoWrap(mem.getPointerSize() * 16L);
                    }

                    if (vtableStart == null) {
                        printf("    - (x) Failed finding class vtable start for %s.%s\n", table.getDescriptor().getPackage(), messageType.getName());
                        continue;
                    }

                    vtableSymbol = createLabel(vtableStart, vtableLabel, true);
                    clearListing(vtableStart, vtableStart.addNoWrap(protobufMessageVtableDataType.getLength()));
                    createData(vtableStart, protobufMessageVtableDataType);
                }

                printf("    - (+) Found class vtable for %s.%s at %s\n", table.getDescriptor().getPackage(), messageType.getName(), vtableSymbol.getAddress());

                var vtableData = getDataAt(vtableSymbol.getAddress());

                var packageCategory = dtm.createCategory(new CategoryPath("/%s".formatted(table.getDescriptor().getPackage().replace(".", "/"))));
                var messageStructDataType = packageCategory.getDataType(messageType.getName());
                if (messageStructDataType == null) {
                    var dataType_ = new StructureDataType(messageType.getName(), 0, dtm);
                    dataType_.add(new PointerDataType(vtableData.getDataType(), dtm), "vtable", "");
                    dataType_.add(internalMetadataDataType, "_internal_metadata_", "");

                    messageStructDataType = packageCategory.addDataType(dataType_, null);
                } else {
                    var dataType_ = (Structure) messageStructDataType;
                    if (dataType_.getNumComponents() == 0) {
                        dataType_.add(new PointerDataType(vtableData.getDataType(), dtm), "vtable", "");
                        dataType_.add(internalMetadataDataType, "_internal_metadata_", "");
                    } else {
                        if (!Objects.equals(dataType_.getComponent(0).getFieldName(), "vtable")) {
                            printf("   - (x) Class structure for %s.%s does not start with vtable pointer\n", table.getDescriptor().getPackage(), messageType.getName());
                        }
                        if (!Objects.equals(dataType_.getComponent(1).getFieldName(), "_internal_metadata_")) {
                            printf("   - (x) Class structure for %s.%s does not not have internal metadata pointer\n", table.getDescriptor().getPackage(), messageType.getName());
                        }
                    }
                }

                // FIXME: some functions will be shared between classes if they have not been overridden,
                //        they probably belong to Message or MessageLite.
                // make all vtable pointer use the __thiscall convention
                for (int j = 0; j < vtableData.getNumComponents(); j++) {
                    var comp = vtableData.getComponent(j);
                    var compAddr = vtableSymbol.getAddress().addNoWrap(comp.getParentOffset());
                    var compFuncAddr = mem.readPtr(mem.readMemory(compAddr, mem.getPointerSize()), MemoryUtil.Space.TEXT);
                    var compFunc = getFunctionAt(compFuncAddr);
                    if (compFunc == null) {
                        printf("    - (x) No function for component %s for %s.%s at %s\n", comp.getFieldName(), table.getDescriptor().getPackage(), messageType.getName(), compFuncAddr);
                        continue;
                    }

                    compFunc.setParentNamespace(messageClass);
                    compFunc.setCallingConvention(CompilerSpec.CALLING_CONVENTION_thiscall);

                    if (Objects.equals(comp.getFieldName(), "~1") || Objects.equals(comp.getFieldName(), "~2")) {
                        compFunc.setName("~%s".formatted(messageType.getName()), SourceType.USER_DEFINED);
                    } else if (!comp.getFieldName().startsWith("field")) {
                        compFunc.setName(comp.getFieldName(), SourceType.USER_DEFINED);
                    }
                }
            }
        }
    }
}