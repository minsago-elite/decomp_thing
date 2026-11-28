import ghidra.GhidraApplicationLayout;
import ghidra.framework.Application;
import ghidra.framework.HeadlessGhidraApplicationConfiguration;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.symbol.RefType;
import java.nio.file.Files;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.task.TaskMonitor;
import java.nio.file.Path;
import java.lang.reflect.*;
import java.util.*;

/** Controlled real ProgramDB listing, distinct from unmodified stripped ELF analysis. */
public final class OwnedExporterControlledListingProbe {
    static Object resolved(ExportProgramModelOwned exporter, Address target) throws Exception {
        return OwnedExporterReferencedBytesProbe.invoke(exporter, "resolveAddressedData", new Class<?>[]{Address.class}, target);
    }
    static void selection(ExportProgramModelOwned exporter, Data original, int offset, Address expected, String kind) throws Exception {
        Object result = resolved(exporter, original.getAddress().add(offset));
        OwnedExporterReferencedBytesProbe.check(OwnedExporterReferencedBytesProbe.get(result, "base").equals(expected), "selected exact base " + expected);
        OwnedExporterReferencedBytesProbe.check(OwnedExporterReferencedBytesProbe.get(result, "kind").toString().equals(kind), "selection kind " + kind);
    }
    static void addressedControls(ProgramDB program, Function function, Address code, ExportProgramModelOwned exporter, Path work) throws Exception {
        Address base = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x3000);
        program.getMemory().createInitializedBlock("owned-slots", base, 4096, (byte)0, TaskMonitor.DUMMY, false);
        PointerDataType pointer = new PointerDataType(VoidDataType.dataType, 8);
        StructureDataType slots = new StructureDataType("OwnedSlots", 0);
        slots.add(pointer, "first", null); slots.add(pointer, "second", null);
        Data structure = program.getListing().createData(base, slots);
        Address slot = base.add(8);
        program.getMemory().setBytes(slot, new byte[]{0x34,0x12,0,0,0,0,0,0});
        selection(exporter, structure, 8, slot, "PRIMITIVE");
        selection(exporter, structure, 9, base, "ORIGINAL_CONTAINER");
        ArrayDataType arrayType = new ArrayDataType(pointer, 3, 8);
        Data array = program.getListing().createData(base.add(0x40), arrayType);
        selection(exporter, array, 16, array.getAddress().add(16), "PRIMITIVE");
        Data alias = program.getListing().createData(base.add(0x80), new TypedefDataType("OwnedAlias", new TypedefDataType("OwnedInnerAlias", slots)));
        selection(exporter, alias, 8, alias.getAddress().add(8), "PRIMITIVE");
        UnionDataType union = new UnionDataType("OwnedUnion"); union.add(pointer, "pointer", null); union.add(LongLongDataType.dataType, "integer", null);
        for (DataType type : new DataType[]{union, new TypedefDataType("OwnedUnionAlias", union)}) {
            Address address = base.add(type == union ? 0xc0 : 0xe0);
            Data data = program.getListing().createData(address, type);
            selection(exporter, data, 0, address, "ORIGINAL_CONTAINER");
        }
        StructureDataType padded = new StructureDataType("OwnedPadding", 16);
        padded.replaceAtOffset(8, pointer, 8, "pointer", null);
        Data padding = program.getListing().createData(base.add(0x100), padded);
        selection(exporter, padding, 1, padding.getAddress(), "ORIGINAL_CONTAINER");
        selection(exporter, padding, 8, padding.getAddress().add(8), "PRIMITIVE");
        StructureDataType bits = new StructureDataType("OwnedBits", 0);
        bits.addBitField(IntegerDataType.dataType, 2, "flags", null);
        Data bitfield = program.getListing().createData(base.add(0x140), bits);
        selection(exporter, bitfield, 0, bitfield.getAddress(), "ORIGINAL_CONTAINER");
        Data undefined = program.getListing().createData(base.add(0x160), Undefined8DataType.dataType);
        selection(exporter, undefined, 0, undefined.getAddress(), "ORIGINAL_CONTAINER");
        Data scalar = program.getListing().createData(base.add(0x180), IntegerDataType.dataType);
        selection(exporter, scalar, 1, scalar.getAddress(), "ORIGINAL_CONTAINER");
        DataType deep = pointer;
        for (int depth = 0; depth < 33; depth++) {
            StructureDataType wrapper = new StructureDataType("OwnedDepth" + depth, 0); wrapper.add(deep, "child", null); deep = wrapper;
        }
        Data nested = program.getListing().createData(base.add(0x1c0), deep);
        selection(exporter, nested, 0, nested.getAddress(), "ORIGINAL_CONTAINER");
        Object absent = resolved(exporter, base.add(0x200));
        OwnedExporterReferencedBytesProbe.check(OwnedExporterReferencedBytesProbe.get(absent, "base").equals(base.add(0x200)), "absent/undefined data preserves target");
        program.getReferenceManager().addMemoryReference(code, slot, RefType.INDIRECTION, SourceType.USER_DEFINED, 0);
        // Code with no defined function must also be excluded from data evidence.
        Address orphanCode = base.add(0x300);
        program.getMemory().setByte(orphanCode, (byte)0xc3);
        OwnedExporterReferencedBytesProbe.check(new DisassembleCommand(orphanCode, null, true).applyTo(program, TaskMonitor.DUMMY), "orphan code disassembly");
        program.getReferenceManager().addMemoryReference(code, orphanCode, RefType.DATA, SourceType.USER_DEFINED, 1);
        OwnedExporterReferencedBytesProbe.invoke(exporter, "collectReferencedByteEvidence", new Class<?>[]{List.class}, List.of(function));
        @SuppressWarnings("unchecked") Map<String,String> byteEvidence = (Map<String,String>)OwnedExporterReferencedBytesProbe.get(exporter, "referencedByteEvidence");
        String id = "global_0000000000003008";
        OwnedExporterReferencedBytesProbe.check(byteEvidence.containsKey(id) && !byteEvidence.containsKey("global_0000000000003000"), "indirect addressed leaf key");
        OwnedExporterReferencedBytesProbe.check(!byteEvidence.containsKey("global_0000000000003300"), "instruction outside function excluded");
        String evidence = byteEvidence.get(id);
        OwnedExporterReferencedBytesProbe.check(evidence.contains("\"referenceAddress\":\"0x3008\"") && evidence.contains("\"instructionAddress\":\"0x1000\"") &&
            evidence.contains("\"widthBasis\":\"unknown_width\"") && evidence.contains("\"requestedLength\":null"), "indirect observation retains target/origin without invented width");
        Object global = OwnedExporterReferencedBytesProbe.invoke(exporter, "globalAt", new Class<?>[]{Address.class}, slot);
        OwnedExporterReferencedBytesProbe.check(OwnedExporterReferencedBytesProbe.get(global, "id").equals(id) &&
            OwnedExporterReferencedBytesProbe.get(global, "type").equals(structure.getComponent(1).getDataType().getDisplayName()) &&
            OwnedExporterReferencedBytesProbe.get(global, "initializer").equals(structure.getComponent(1).getDefaultValueRepresentation()), "leaf identity type and exact initializer");
        Class<?> planning = Arrays.stream(ExportProgramModelOwned.class.getDeclaredClasses()).filter(c -> c.getSimpleName().equals("PlanningBatchEvidence")).findFirst().orElseThrow();
        Object metadata = OwnedExporterReferencedBytesProbe.invoke(exporter, "collectFunctionMetadata",
            new Class<?>[]{Function.class, Path.class, Path.class, planning}, function,
            Files.createDirectories(work.resolve("owned-globals")), Files.createDirectories(work.resolve("owned-types")), null);
        OwnedExporterReferencedBytesProbe.check(((String)OwnedExporterReferencedBytesProbe.get(metadata, "evidence")).contains(id), "metadata and byte collector share leaf key");
        Set<String> expectedIds = Set.of("global_0000000000002000", "global_0000000000002008", "global_0000000000002010", id);
        try (var paths = Files.list(work.resolve("owned-globals"))) {
            OwnedExporterReferencedBytesProbe.check(paths.map(p -> p.getFileName().toString().replace(".json", "")).collect(java.util.stream.Collectors.toSet()).equals(expectedIds),
                "mixed listing retains exactly all four raw globals");
        }
        for (long offset : new long[]{0x2000, 0x2008, 0x2010, 0x3008}) {
            Address address = base.getAddressSpace().getAddress(offset);
            Object raw = OwnedExporterReferencedBytesProbe.invoke(exporter, "globalAt", new Class<?>[]{Address.class}, address);
            String record = (String)OwnedExporterReferencedBytesProbe.invoke(exporter, "renderGlobal", new Class<?>[]{raw.getClass()}, raw);
            String globalId = (String)OwnedExporterReferencedBytesProbe.get(raw, "id");
            OwnedExporterReferencedBytesProbe.check(OwnedExporterReferencedBytesProbe.get(raw, "address").equals(address), "exact observed global address " + address);
            OwnedExporterReferencedBytesProbe.check(Files.readString(work.resolve("owned-globals").resolve(globalId + ".json")).equals(record),
                "published raw address/type/initializer/origin are unchanged: " + globalId);
            OwnedExporterReferencedBytesProbe.check(((String)OwnedExporterReferencedBytesProbe.get(metadata, "evidence")).contains(globalId), "raw ID retained " + globalId);
            if (offset != 0x3008) {
                Data rawData = program.getListing().getDataAt(address);
                OwnedExporterReferencedBytesProbe.check(rawData.getLength() == 1 &&
                    OwnedExporterReferencedBytesProbe.get(raw, "type").equals(rawData.getDataType().getDisplayName()) &&
                    OwnedExporterReferencedBytesProbe.get(raw, "initializer").equals("00h") && record.contains("\"requestedLength\":8"),
                    "unsupported listing stays one byte with separate eight-byte observation");
            }
        }
        String failure = (String)OwnedExporterReferencedBytesProbe.get(metadata, "failure");
        OwnedExporterReferencedBytesProbe.check(!(boolean)OwnedExporterReferencedBytesProbe.get(metadata, "evidenceComplete") &&
            failure.equals("data-reference recovery refused: metadataRefusal=UNSUPPORTED_SHAPE;detail=TYPE_CONSTRUCTOR; type recovery refused: metadataRefusal=UNSUPPORTED_SHAPE;detail=TYPE_CONSTRUCTOR"),
            "exact independent data-reference and signature refusals: " + failure);
        var coverage = (ExportProgramModelOwned.PlannedTypeCoverage)OwnedExporterReferencedBytesProbe.get(metadata, "coverage");
        OwnedExporterReferencedBytesProbe.check(coverage.byPath.isEmpty(), "neither Undefined nor OwnedSlots contributes declarations to selected void-pointer leaf");
        OwnedExporterPrototypeProbe.program = program;
        OwnedExporterPrototypeProbe.manager = program.getDataTypeManager();
        OwnedExporterPrototypeProbe.target = ExportProgramModelOwned.TargetContext.capture(program);
        OwnedExporterPrototypeProbe.I = new IntegerDataType(program.getDataTypeManager());
        OwnedExporterPrototypeProbe.collectorStatuses(metadata, false);
        System.out.println("owned mixed listing raw globals two phase refusals and failed partial statuses passed");

        Address cleanCode = base.add(0x340);
        program.getMemory().setByte(cleanCode, (byte)0xc3);
        OwnedExporterReferencedBytesProbe.check(new DisassembleCommand(cleanCode, null, true).applyTo(program, TaskMonitor.DUMMY), "clean positive disassembly");
        Function clean = program.getFunctionManager().createFunction("clean_probe", cleanCode, new AddressSet(cleanCode), SourceType.USER_DEFINED);
        clean.setReturnType(new IntegerDataType(program.getDataTypeManager()), SourceType.USER_DEFINED);
        clean.replaceParameters(Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, true, SourceType.USER_DEFINED,
            new ParameterImpl("value", new IntegerDataType(program.getDataTypeManager()), program));
        program.getReferenceManager().addMemoryReference(cleanCode, slot, RefType.INDIRECTION, SourceType.USER_DEFINED, 0);
        ExportProgramModelOwned cleanExporter = new ExportProgramModelOwned();
        OwnedExporterReferencedBytesProbe.field(cleanExporter, "currentProgram", program);
        OwnedExporterReferencedBytesProbe.field(cleanExporter, "monitor", TaskMonitor.DUMMY);
        OwnedExporterReferencedBytesProbe.invoke(cleanExporter, "collectReferencedByteEvidence", new Class<?>[]{List.class}, List.of(clean));
        Object cleanMetadata = OwnedExporterReferencedBytesProbe.invoke(cleanExporter, "collectFunctionMetadata",
            new Class<?>[]{Function.class, Path.class, Path.class, planning}, clean,
            Files.createDirectories(work.resolve("clean-globals")), Files.createDirectories(work.resolve("clean-types")), null);
        OwnedExporterReferencedBytesProbe.check((boolean)OwnedExporterReferencedBytesProbe.get(cleanMetadata, "evidenceComplete") &&
            OwnedExporterReferencedBytesProbe.get(cleanMetadata, "failure") == null &&
            ((String)OwnedExporterReferencedBytesProbe.get(cleanMetadata, "evidence")).contains(id), "clean admitted selected-leaf metadata is complete");
        OwnedExporterPrototypeProbe.collectorStatuses(cleanMetadata, true);
        System.out.println("owned clean admitted listing and authored typed full positive passed");
        System.out.println("owned addressed primitive and indirect origin controls passed");
    }

    static ghidra.program.model.symbol.Reference readReference(ProgramDB program, Address from, Address to, int operand) {
        for (ghidra.program.model.symbol.Reference reference : program.getReferenceManager().getReferencesFrom(from))
            if (reference.getToAddress().equals(to) && reference.getReferenceType().isData()) return reference;
        // Raw listing setup only; the switch provenance below still comes from Ghidra's own switch analysis.
        return program.getReferenceManager().addMemoryReference(from, to, RefType.READ, SourceType.ANALYSIS, operand);
    }
    static Object switchMetadata(ProgramDB program, Function function, Path work, String label) throws Exception {
        ExportProgramModelOwned exporter = new ExportProgramModelOwned();
        OwnedExporterReferencedBytesProbe.field(exporter, "currentProgram", program);
        OwnedExporterReferencedBytesProbe.field(exporter, "monitor", TaskMonitor.DUMMY);
        OwnedExporterReferencedBytesProbe.invoke(exporter, "collectReferencedByteEvidence", new Class<?>[]{List.class}, List.of(function));
        Class<?> planning = Arrays.stream(ExportProgramModelOwned.class.getDeclaredClasses()).filter(c -> c.getSimpleName().equals("PlanningBatchEvidence")).findFirst().orElseThrow();
        return OwnedExporterReferencedBytesProbe.invoke(exporter, "collectFunctionMetadata",
            new Class<?>[]{Function.class, Path.class, Path.class, planning}, function,
            Files.createDirectories(work.resolve(label + "-globals")), Files.createDirectories(work.resolve(label + "-types")), null);
    }
    static boolean switchSlot(ProgramDB program, Function function, Address reader, ghidra.program.model.symbol.Reference read) throws Exception {
        ExportProgramModelOwned exporter = new ExportProgramModelOwned();
        OwnedExporterReferencedBytesProbe.field(exporter, "currentProgram", program);
        OwnedExporterReferencedBytesProbe.field(exporter, "monitor", TaskMonitor.DUMMY);
        return (boolean)OwnedExporterReferencedBytesProbe.invoke(exporter, "recoveredSwitchTableSlot",
            new Class<?>[]{Function.class, Instruction.class, ghidra.program.model.symbol.Reference.class, Data.class}, function,
            program.getListing().getInstructionAt(reader), read, program.getListing().getDataAt(read.getToAddress()));
    }
    /** A real switch recovered by Ghidra's switch analysis, and an ordinary untyped pointer holding the same case address. */
    static void switchProvenanceControls(ProgramDB program, Path work) throws Exception {
        AddressSpace space = program.getAddressFactory().getDefaultAddressSpace();
        Address code = space.getAddress(0x4000), table = space.getAddress(0x5000), ordinary = space.getAddress(0x5100);
        Address tableRead = space.getAddress(0x4007), jump = space.getAddress(0x400f), ordinaryRead = space.getAddress(0x4017);
        long[] cases = {0x4011, 0x4017, 0x4020};
        program.getMemory().createInitializedBlock("switch-code", code, 0x40, (byte)0, TaskMonitor.DUMMY, false);
        program.getMemory().createInitializedBlock("switch-data", table, 0x200, (byte)0, TaskMonitor.DUMMY, false).setWrite(false);
        // cmp edi,2; ja default; mov eax,edi; mov rax,[rax*8+0x5000]; jmp rax;
        // case0: mov eax,10; ret; case1: mov rax,[0x5100]; ret; case2: mov eax,30; ret; default: xor eax,eax; ret
        program.getMemory().setBytes(code, new byte[]{(byte)0x83,(byte)0xff,0x02,0x77,0x21,(byte)0x89,(byte)0xf8,
            0x48,(byte)0x8b,0x04,(byte)0xc5,0x00,0x50,0x00,0x00,(byte)0xff,(byte)0xe0,
            (byte)0xb8,0x0a,0x00,0x00,0x00,(byte)0xc3, 0x48,(byte)0x8b,0x04,0x25,0x00,0x51,0x00,0x00,(byte)0xc3,
            (byte)0xb8,0x1e,0x00,0x00,0x00,(byte)0xc3, 0x31,(byte)0xc0,(byte)0xc3});
        for (int index = 0; index < cases.length; index++) program.getMemory().setLong(table.add(index * 8L), cases[index]);
        program.getMemory().setLong(ordinary, cases[0]);
        OwnedExporterReferencedBytesProbe.check(new DisassembleCommand(code, null, true).applyTo(program, TaskMonitor.DUMMY), "switch entry disassembly");
        Function function = program.getFunctionManager().createFunction("switch_probe", code, new AddressSet(code, code.add(0x28)), SourceType.USER_DEFINED);
        ghidra.app.decompiler.DecompInterface decompiler = new ghidra.app.decompiler.DecompInterface();
        try {
            new ghidra.app.plugin.core.analysis.SwitchAnalysisDecompileConfigurer(program).configure(decompiler);
            OwnedExporterReferencedBytesProbe.check(decompiler.openProgram(program), decompiler.getLastMessage());
            ghidra.app.decompiler.DecompileResults results = decompiler.decompileFunction(function, 30, TaskMonitor.DUMMY);
            OwnedExporterReferencedBytesProbe.check(results.decompileCompleted() && results.getHighFunction() != null &&
                results.getHighFunction().getJumpTables().length == 1, "switch recovery: " + results.getErrorMessage());
            var analysis = new ghidra.app.cmd.function.DecompilerSwitchAnalysisCmd(results);
            OwnedExporterReferencedBytesProbe.check(analysis.applyTo(program, TaskMonitor.DUMMY), analysis.getStatusMsg());
        } finally { decompiler.dispose(); }
        Set<Address> destinations = new TreeSet<>();
        for (ghidra.program.model.symbol.Reference flow : program.getReferenceManager().getReferencesFrom(jump))
            if (flow.getReferenceType().isComputed() && flow.getReferenceType().isJump()) destinations.add(flow.getToAddress());
        Data slot = program.getListing().getDataAt(table);
        OwnedExporterReferencedBytesProbe.check(destinations.size() == 3 && destinations.contains(space.getAddress(cases[0])) &&
            slot != null && slot.getDataType() instanceof Pointer && ((Pointer)slot.getDataType()).getDataType() == null &&
            slot.getValue().equals(space.getAddress(cases[0])) && function.getBody().contains(space.getAddress(cases[2])) &&
            program.getSymbolTable().getSymbol("switchdataD_" + table, table, program.getSymbolTable().getNamespace("switchD_" + jump, null)) != null,
            "Ghidra switch analysis owns the table: " + destinations + " " + slot + " " + Arrays.toString(program.getSymbolTable().getSymbols(table)));
        IntegerDataType integer = new IntegerDataType(program.getDataTypeManager());
        function.setReturnType(integer, SourceType.USER_DEFINED);
        function.replaceParameters(Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, true, SourceType.USER_DEFINED,
            new ParameterImpl("selector", integer, program));
        ghidra.program.model.symbol.Reference slotRead = readReference(program, tableRead, table, 1);
        ghidra.program.model.symbol.Reference pointerRead = readReference(program, ordinaryRead, ordinary, 1);

        program.getListing().createData(ordinary, new PointerDataType(VoidDataType.dataType, 8));
        Object typed = switchMetadata(program, function, work, "switch-typed");
        OwnedExporterReferencedBytesProbe.check((boolean)OwnedExporterReferencedBytesProbe.get(typed, "evidenceComplete") &&
            OwnedExporterReferencedBytesProbe.get(typed, "failure") == null &&
            ((String)OwnedExporterReferencedBytesProbe.get(typed, "evidence")).contains("global_0000000000005000"),
            "recovered switch slot needs no typed declaration: " + OwnedExporterReferencedBytesProbe.get(typed, "failure"));

        program.getListing().clearCodeUnits(ordinary, ordinary.add(7), false);
        Data untyped = program.getListing().createData(ordinary, PointerDataType.dataType);
        OwnedExporterReferencedBytesProbe.check(untyped.getValue().equals(slot.getValue()) && ((Pointer)untyped.getDataType()).getDataType() == null,
            "ordinary untyped pointer holds the same case destination");
        OwnedExporterReferencedBytesProbe.check(switchSlot(program, function, tableRead, slotRead), "switch-analysis table slot is exempt");
        OwnedExporterReferencedBytesProbe.check(!switchSlot(program, function, ordinaryRead, pointerRead), "ordinary pointer with a case value is not a switch slot");
        Object refused = switchMetadata(program, function, work, "switch-ordinary");
        String failure = (String)OwnedExporterReferencedBytesProbe.get(refused, "failure");
        OwnedExporterReferencedBytesProbe.check(!(boolean)OwnedExporterReferencedBytesProbe.get(refused, "evidenceComplete") && failure != null &&
            failure.contains("MISSING_DATA_TYPE_POINTER_TARGET_DEPTH_1"), "ordinary pointer keeps the missing-target refusal: " + failure);
        // The same table slot read by an instruction that does not feed the jump is not the switch's data use.
        ghidra.program.model.symbol.Reference strayRead = program.getReferenceManager().addMemoryReference(
            space.getAddress(cases[2]), table, RefType.READ, SourceType.USER_DEFINED, 1);
        OwnedExporterReferencedBytesProbe.check(!switchSlot(program, function, space.getAddress(cases[2]), strayRead), "stray table read is not the switch's data use");
        program.getReferenceManager().delete(strayRead);
        for (ghidra.program.model.symbol.Symbol label : program.getSymbolTable().getSymbols(table))
            if (label.getName().startsWith("switchdataD_")) label.delete();
        OwnedExporterReferencedBytesProbe.check(!switchSlot(program, function, tableRead, slotRead), "slot without switch-analysis table attribution is not exempt");
        System.out.println("owned switch-table slot provenance and ordinary pointer refusal controls passed");
    }

    public static void main(String[] args) throws Exception {
        Application.initializeApplication(new GhidraApplicationLayout(Path.of(args[0]).toFile()),
            new HeadlessGhidraApplicationConfiguration());
        var language = DefaultLanguageService.getLanguageService().getLanguage(new LanguageID("x86:LE:64:default"));
        Object consumer = new Object();
        // This authored C listing must use the same explicit target policy as the owned type extractor.
        ProgramDB program = new ProgramDB("controlled-one-byte-listing", language,
            language.getCompilerSpecByID(new ghidra.program.model.lang.CompilerSpecID("gcc")), consumer);
        try {
            int transaction = program.startTransaction("authored byte listing fixture");
            try {
                Address code = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x1000);
                Address constant = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x2000);
                program.getMemory().createInitializedBlock("code", code, 32, (byte)0, TaskMonitor.DUMMY, false);
                program.getMemory().createInitializedBlock("constant", constant, 24, (byte)0, TaskMonitor.DUMMY, false);
                // Three authored RIP-relative instructions, each reading its own eight-byte constant.
                // Actual SLEIGH pcode, no proxy instructions and no original-input analysis.
                byte[] instructionOpcodes = {0x10,0x58,0x59};
                String[] mnemonics = {"MOVSD","ADDSD","MULSD"};
                int[] pcodeOpcodes = {PcodeOp.COPY,PcodeOp.FLOAT_ADD,PcodeOp.FLOAT_MULT};
                byte[] payload = {0,0,0,0,0,0,(byte)0xe0,0x3f};
                for (int index=0; index<3; index++) {
                    program.getMemory().setBytes(code.add(index*8), new byte[]{(byte)0xf2,0x0f,instructionOpcodes[index],0x05,(byte)0xf8,0x0f,0,0});
                    program.getMemory().setBytes(constant.add(index*8), payload);
                }
                program.getMemory().setByte(code.add(24), (byte)0xc3);
                var disassembly = new DisassembleCommand(code, new AddressSet(code, code.add(24)), true);
                OwnedExporterReferencedBytesProbe.check(disassembly.applyTo(program, TaskMonitor.DUMMY), disassembly.getStatusMsg());
                Function function = program.getFunctionManager().createFunction("probe", code, new AddressSet(code, code.add(24)), SourceType.USER_DEFINED);
                Data[] data = new Data[3];
                for (int index=0; index<3; index++) {
                    Instruction instruction = program.getListing().getInstructionAt(code.add(index*8));
                    final int expectedOpcode = pcodeOpcodes[index];
                    OwnedExporterReferencedBytesProbe.check(instruction.getMnemonicString().equalsIgnoreCase(mnemonics[index]) &&
                        Arrays.stream(instruction.getPcode()).anyMatch(op -> op.getOpcode() == expectedOpcode), "actual authored instruction and raw pcode " + mnemonics[index]);
                    // Explicit controlled setup: each listing owns one byte; each instruction reads eight.
                    data[index] = program.getListing().createData(constant.add(index*8), Undefined1DataType.dataType);
                    OwnedExporterReferencedBytesProbe.check(data[index].getLength() == 1 && data[index].getDefaultValueRepresentation().equals("00h"), "actual one-byte listing setup");
                }
                ExportProgramModelOwned exporter = new ExportProgramModelOwned();
                OwnedExporterReferencedBytesProbe.field(exporter, "currentProgram", program);
                OwnedExporterReferencedBytesProbe.field(exporter, "monitor", TaskMonitor.DUMMY);
                OwnedExporterReferencedBytesProbe.invoke(exporter, "collectReferencedByteEvidence", new Class<?>[]{List.class}, List.of(function));
                Method render = Arrays.stream(ExportProgramModelOwned.class.getDeclaredMethods()).filter(m -> m.getName().equals("renderGlobal")).findFirst().orElseThrow();
                render.setAccessible(true);
                Field evidence = ExportProgramModelOwned.class.getDeclaredField("referencedByteEvidence"); evidence.setAccessible(true);
                OwnedExporterReferencedBytesProbe.check(((Map<?,?>)evidence.get(exporter)).size() == 3, "three distinct authored global records");
                for (int index=0; index<3; index++) {
                    Address target = constant.add(index*8), origin = code.add(index*8);
                    Object global = OwnedExporterReferencedBytesProbe.invoke(exporter, "globalAt", new Class<?>[]{Address.class}, target);
                    String record = (String)render.invoke(null, global);
                    OwnedExporterReferencedBytesProbe.check(record.contains("\"initializer\": \"00h\""), "preserve one-byte initializer: " + record);
                    OwnedExporterReferencedBytesProbe.check(record.contains("\"requestedLength\":8") && record.contains("\"widthBasis\":\"pcode_direct_read\"") &&
                        record.contains("000000000000e03f") && record.contains("\"availability\":\"available\"") &&
                        record.contains("\"referenceAddress\":\"0x" + Long.toHexString(target.getOffset()) + "\"") &&
                        record.contains("\"instructionAddress\":\"0x" + Long.toHexString(origin.getOffset()) + "\""), "exact authored instruction/target/eight-byte evidence: " + record);
                    OwnedExporterReferencedBytesProbe.check(data[index].getLength() == 1 && data[index].getDefaultValueRepresentation().equals("00h"), "export must not rewrite listing data");
                }
                addressedControls(program, function, code, exporter, Path.of(args[1]));
                switchProvenanceControls(program, Path.of(args[1]));
                System.out.println("controlled real listing passed: MOVSD/COPY, ADDSD/FLOAT_ADD and MULSD/FLOAT_MULT retain one-byte 00h initializers and exact leading-zero eight-byte evidence");
            } finally { program.endTransaction(transaction, false); }
        } finally { program.release(consumer); }
        System.exit(0);
    }
}
