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

    static void check(boolean condition, Object detail) { OwnedExporterReferencedBytesProbe.check(condition, detail); }
    static Object get(Object object, String name) throws Exception { return OwnedExporterReferencedBytesProbe.get(object, name); }
    static Class<?> nested(String name) {
        return Arrays.stream(ExportProgramModelOwned.class.getDeclaredClasses()).filter(c -> c.getSimpleName().equals(name)).findFirst().orElseThrow();
    }
    static ghidra.program.model.symbol.Reference readReference(ProgramDB program, Address from, Address to, int operand) {
        for (ghidra.program.model.symbol.Reference reference : program.getReferenceManager().getReferencesFrom(from))
            if (reference.getToAddress().equals(to) && reference.getReferenceType().isData()) return reference;
        // Raw listing setup only: this is the operand READ that auto-analysis records. Provenance is checked below.
        return program.getReferenceManager().addMemoryReference(from, to, RefType.READ, SourceType.ANALYSIS, operand);
    }
    static ExportProgramModelOwned switchExporter(ProgramDB program) throws Exception {
        ExportProgramModelOwned exporter = new ExportProgramModelOwned();
        OwnedExporterReferencedBytesProbe.field(exporter, "currentProgram", program);
        OwnedExporterReferencedBytesProbe.field(exporter, "monitor", TaskMonitor.DUMMY);
        OwnedExporterReferencedBytesProbe.field(exporter, "phaseObservation", new ExporterPhaseObservationOwnedV1());
        return exporter;
    }
    static Object switchMetadata(ExportProgramModelOwned exporter, Function function, Path work, String label) throws Exception {
        OwnedExporterReferencedBytesProbe.invoke(exporter, "collectReferencedByteEvidence", new Class<?>[]{List.class}, List.of(function));
        return OwnedExporterReferencedBytesProbe.invoke(exporter, "collectFunctionMetadata",
            new Class<?>[]{Function.class, Path.class, Path.class, nested("PlanningBatchEvidence")}, function,
            Files.createDirectories(work.resolve(label + "-globals")), Files.createDirectories(work.resolve(label + "-types")), null);
    }
    static Object candidate(ExportProgramModelOwned exporter, Function function, Address reader,
                            ghidra.program.model.symbol.Reference read, int limit) throws Exception {
        Constructor<?> budget = nested("SwitchProvenanceBudget").getDeclaredConstructor(int.class);
        budget.setAccessible(true);
        Listing listing = function.getProgram().getListing();
        return OwnedExporterReferencedBytesProbe.invoke(exporter, "switchSlotCandidate",
            new Class<?>[]{Function.class, Instruction.class, ghidra.program.model.symbol.Reference.class, Data.class, String.class,
                nested("SwitchProvenanceBudget")},
            function, listing.getInstructionAt(reader), read, listing.getDataAt(read.getToAddress()), "authored refusal", budget.newInstance(limit));
    }
    static final int ENTRY_LIMIT = ghidra.app.decompiler.DecompileOptions.SUGGESTED_MAX_JUMPTABLE_ENTRIES;
    static Object budget(int limit) throws Exception {
        Constructor<?> budget = nested("SwitchProvenanceBudget").getDeclaredConstructor(int.class);
        budget.setAccessible(true);
        return budget.newInstance(limit);
    }
    static long used(Object budget) throws Exception {
        Method method = budget.getClass().getDeclaredMethod("used");
        method.setAccessible(true);
        return (long)method.invoke(budget);
    }
    static boolean proven(ghidra.program.model.pcode.HighFunction high, Object slots, Object budget) throws Exception {
        Method method = ExportProgramModelOwned.class.getDeclaredMethod("decompilerSwitchSlotsProven",
            ghidra.program.model.pcode.HighFunction.class, List.class, int.class, nested("SwitchProvenanceBudget"), TaskMonitor.class);
        method.setAccessible(true);
        return (boolean)method.invoke(null, high, slots, ENTRY_LIMIT, budget, TaskMonitor.DUMMY);
    }
    static boolean proven(ghidra.program.model.pcode.HighFunction high, Object slots, int limit) throws Exception {
        return proven(high, slots, budget(limit));
    }
    static Object slotCandidate(Address reader, Address slot, Address value, Address jump) throws Exception {
        Constructor<?> constructor = nested("SwitchSlotCandidate").getDeclaredConstructor(
            Address.class, Address.class, Address.class, Address.class, int.class, String.class);
        constructor.setAccessible(true);
        return constructor.newInstance(reader, slot, value, jump, 8, MISSING);
    }
    static PcodeOp op(Address at, int sequence, int opcode, ghidra.program.model.pcode.Varnode output, ghidra.program.model.pcode.Varnode... inputs) {
        return new PcodeOp(at, sequence, opcode, inputs, output);
    }
    /** The listing half's address binding, applied to authored raw p-code ending in one LOAD. */
    static boolean binds(ExportProgramModelOwned exporter, Address slot, PcodeOp... ops) throws Exception {
        return (boolean)OwnedExporterReferencedBytesProbe.invoke(exporter, "loadAddressBindsSlot",
            new Class<?>[]{PcodeOp[].class, int.class, Address.class, int.class, nested("SwitchProvenanceBudget")},
            ops, ops.length - 1, slot, 8, budget(4096));
    }
    interface Admits { boolean at(int limit) throws Exception; }
    /** The smallest allowance that admits the evidence. One unit less must keep the refusal. */
    static int exactLimit(Admits admits, String label) throws Exception {
        int limit = 0;
        while (!admits.at(limit)) check(++limit <= 4096, label + " is admitted within the production allowance");
        check(limit > 0 && !admits.at(limit - 1), label + ": one unit below the exact limit keeps the refusal");
        return limit;
    }
    static Object worker(ExportProgramModelOwned exporter) throws Exception {
        Constructor<?> constructor = nested("NativeWorker").getDeclaredConstructor(ExportProgramModelOwned.class, int.class);
        constructor.setAccessible(true);
        return constructor.newInstance(exporter, 0);
    }
    static Object execute(Object worker, Object metadata) throws Exception {
        Method method = worker.getClass().getDeclaredMethod("execute", nested("FunctionMetadata"), boolean.class);
        method.setAccessible(true);
        return method.invoke(worker, metadata, false);
    }
    static void dispose(Object worker) throws Exception {
        Method method = worker.getClass().getDeclaredMethod("dispose");
        method.setAccessible(true);
        method.invoke(worker);
    }
    static ExportProgramModelOwned.NativeOutcome decompile(Function function, ghidra.app.decompiler.DecompInterface decompiler, Object metadata) throws Exception {
        Method method = ExportProgramModelOwned.class.getDeclaredMethod("decompileFunction", Function.class, String.class,
            ghidra.app.decompiler.DecompInterface.class, int.class, TaskMonitor.class, ExportProgramModelOwned.TargetContext.class, List.class);
        method.setAccessible(true);
        return (ExportProgramModelOwned.NativeOutcome)method.invoke(null, function, function.getName(), decompiler, 30, TaskMonitor.DUMMY,
            get(metadata, "target"), get(metadata, "switchSlots"));
    }
    static Object render(Object metadata, ExportProgramModelOwned.NativeOutcome outcome, boolean full) throws Exception {
        return OwnedExporterReferencedBytesProbe.invoke(new ExportProgramModelOwned(), "renderFunction",
            new Class<?>[]{nested("FunctionMetadata"), ExportProgramModelOwned.NativeOutcome.class, boolean.class}, metadata, outcome, full);
    }
    static final String MISSING = "data-reference recovery refused: metadataRefusal=NULL_TYPE;detail=MISSING_DATA_TYPE_POINTER_TARGET_DEPTH_1";
    static void refused(Object metadataOrExport, String label) throws Exception {
        String failure = (String)get(metadataOrExport, "failure");
        check(failure != null && failure.contains(MISSING), label + " keeps the missing-target refusal: " + failure);
        for (Field field : metadataOrExport.getClass().getDeclaredFields()) {
            if (field.getName().equals("evidenceComplete")) check(!(boolean)get(metadataOrExport, "evidenceComplete"), label + " metadata is incomplete");
            if (field.getName().equals("status")) check(!get(metadataOrExport, "status").equals("recovered"), label + " is not recovered");
        }
    }
    static Function switchFunction(ProgramDB program, String name, Address entry, Address last, byte[] bytes) throws Exception {
        program.getMemory().setBytes(entry, bytes);
        check(new DisassembleCommand(entry, null, true).applyTo(program, TaskMonitor.DUMMY), name + " disassembly");
        Function function = program.getFunctionManager().createFunction(name, entry, new AddressSet(entry, last), SourceType.USER_DEFINED);
        IntegerDataType integer = new IntegerDataType(program.getDataTypeManager());
        function.setReturnType(integer, SourceType.USER_DEFINED);
        function.replaceParameters(Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, true, SourceType.USER_DEFINED,
            new ParameterImpl("selector", integer, program));
        function.setCallingConvention("__stdcall");
        return function;
    }
    /** Ghidra's own switch analysis, as auto-analysis runs it: it types the table slots as untyped pointers. */
    static void switchAnalysis(ProgramDB program, Function function, int tables) throws Exception {
        ghidra.app.decompiler.DecompInterface decompiler = new ghidra.app.decompiler.DecompInterface();
        try {
            new ghidra.app.plugin.core.analysis.SwitchAnalysisDecompileConfigurer(program).configure(decompiler);
            check(decompiler.openProgram(program), decompiler.getLastMessage());
            ghidra.app.decompiler.DecompileResults results = decompiler.decompileFunction(function, 30, TaskMonitor.DUMMY);
            check(results.decompileCompleted() && results.getHighFunction() != null &&
                results.getHighFunction().getJumpTables().length == tables, function.getName() + " switch recovery: " + results.getErrorMessage());
            if (tables == 0) return;
            var analysis = new ghidra.app.cmd.function.DecompilerSwitchAnalysisCmd(results);
            check(analysis.applyTo(program, TaskMonitor.DUMMY), analysis.getStatusMsg());
        } finally { decompiler.dispose(); }
    }
    static void untypedSlot(Data slot, Address value, String label) {
        check(slot != null && slot.getDataType() instanceof Pointer && ((Pointer)slot.getDataType()).getDataType() == null &&
            slot.getValue().equals(value), label + " is an untyped pointer holding " + value + ": " + slot);
    }
    static void switchProvenanceControls(ProgramDB program, Path work) throws Exception {
        AddressSpace space = program.getAddressFactory().getDefaultAddressSpace();
        program.getMemory().createInitializedBlock("switch-code", space.getAddress(0x4000), 0x2000, (byte)0, TaskMonitor.DUMMY, false);
        program.getMemory().createInitializedBlock("switch-data", space.getAddress(0x9000), 0x800, (byte)0, TaskMonitor.DUMMY, false).setWrite(false);
        program.getMemory().createInitializedBlock("switch-writable", space.getAddress(0xa000), 0x100, (byte)0, TaskMonitor.DUMMY, false);
        int maximum = (int)ExportProgramModelOwned.class.getDeclaredField("MAXIMUM_SWITCH_PROVENANCE_WORK").get(null);
        check(maximum == 4096, "production provenance allowance");

        // A: cmp edi,2; ja default; mov eax,edi; mov rax,[rax*8+0x9000]; jmp rax;
        // case0: mov eax,10; ret; case1: mov rax,[0x9100]; ret; case2: mov eax,30; ret; default: xor eax,eax; ret
        Address table = space.getAddress(0x9000), ordinary = space.getAddress(0x9100);
        Address tableRead = space.getAddress(0x4007), jump = space.getAddress(0x400f), ordinaryRead = space.getAddress(0x4017);
        long[] cases = {0x4011, 0x4017, 0x4020};
        for (int index = 0; index < cases.length; index++) program.getMemory().setLong(table.add(index * 8L), cases[index]);
        program.getMemory().setLong(ordinary, cases[0]);
        Function function = switchFunction(program, "switch_probe", space.getAddress(0x4000), space.getAddress(0x4028), new byte[]{
            (byte)0x83,(byte)0xff,0x02, 0x77,0x21, (byte)0x89,(byte)0xf8, 0x48,(byte)0x8b,0x04,(byte)0xc5,0x00,(byte)0x90,0x00,0x00, (byte)0xff,(byte)0xe0,
            (byte)0xb8,0x0a,0x00,0x00,0x00,(byte)0xc3, 0x48,(byte)0x8b,0x04,0x25,0x00,(byte)0x91,0x00,0x00,(byte)0xc3,
            (byte)0xb8,0x1e,0x00,0x00,0x00,(byte)0xc3, 0x31,(byte)0xc0,(byte)0xc3});
        switchAnalysis(program, function, 1);
        Set<Address> destinations = new TreeSet<>();
        for (ghidra.program.model.symbol.Reference flow : program.getReferenceManager().getReferencesFrom(jump))
            if (flow.getReferenceType().isComputed() && flow.getReferenceType().isJump()) destinations.add(flow.getToAddress());
        check(destinations.size() == 3 && destinations.contains(space.getAddress(cases[0])), "Ghidra switch analysis owns the table: " + destinations);
        untypedSlot(program.getListing().getDataAt(table), space.getAddress(cases[0]), "Ghidra-typed table slot");
        ghidra.program.model.symbol.Reference slotRead = readReference(program, tableRead, table, 1);
        ghidra.program.model.symbol.Reference pointerRead = readReference(program, ordinaryRead, ordinary, 1);
        program.getListing().createData(ordinary, new PointerDataType(VoidDataType.dataType, 8));

        // Positive: the table load is bound by the listing, then confirmed by this decompile's own JumpTable.
        ExportProgramModelOwned exporter = switchExporter(program);
        Object metadata = switchMetadata(exporter, function, work, "switch-proven");
        List<?> slots = (List<?>)get(metadata, "switchSlots");
        check((boolean)get(metadata, "evidenceComplete") && get(metadata, "failure") == null && slots.size() == 1 &&
            get(slots.get(0), "reader").equals(tableRead) && get(slots.get(0), "jump").equals(jump) && get(slots.get(0), "slot").equals(table) &&
            get(slots.get(0), "value").equals(space.getAddress(cases[0])) && get(slots.get(0), "refusal").equals(MISSING) &&
            ((String)get(metadata, "evidence")).contains("global_0000000000009000"), "the table slot's refusal is deferred, not waived: " + slots);
        Object worker = worker(exporter);
        try {
            Object exported = execute(worker, metadata);
            check(get(exported, "status").equals("recovered") &&
                (get(exported, "failure") == null || !((String)get(exported, "failure")).contains("MISSING_DATA_TYPE")),
                "a decompiler-confirmed switch slot needs no typed declaration: " + get(exported, "status") + " " + get(exported, "failure"));
            var decompiler = (ghidra.app.decompiler.DecompInterface)get(worker, "decompiler");
            var results = decompiler.decompileFunction(function, 30, TaskMonitor.DUMMY);
            var high = results.getHighFunction();
            var tables = high.getJumpTables();
            check(tables.length == 1 && tables[0].getSwitchAddress().equals(jump) && tables[0].getLoadTables().length == 1 &&
                tables[0].getLoadTables()[0].getAddress().equals(table) && tables[0].getLoadTables()[0].getSize() == 8 &&
                tables[0].getLoadTables()[0].getNum() == 3, "production decompiler reports the switch LoadTable");
            boolean finalLoad = false;
            for (var ops = high.getPcodeOps(tableRead); ops.hasNext();) finalLoad |= ops.next().getOpcode() == PcodeOp.LOAD;
            System.out.println("owned switch HighFunction retains the table LOAD at the reader=" + finalLoad);
            check(decompiler.getOptions().getMaxJumpTableEntries() == ENTRY_LIMIT, "the worker configures Ghidra's jump-table entry limit");
            int decompilerLimit = exactLimit(limit -> proven(high, slots, limit), "decompiler provenance");
            check(decompilerLimit > ENTRY_LIMIT + 1 && !proven(high, slots, ENTRY_LIMIT + 1),
                "the entry bound plus the default case is reserved before each array copy: " + decompilerLimit);
            int listingLimit = exactLimit(limit -> candidate(exporter, function, tableRead, slotRead, limit) != null, "listing provenance");
            check(get(candidate(exporter, function, tableRead, slotRead, listingLimit), "jump").equals(jump), "listing candidate binds the jump");

            // (d) No decompile (planning), a decompile that proves nothing, a failed decompile and no HighFunction all keep the refusal.
            Object planning = render(metadata, null, false);
            check(get(planning, "status").equals("failed"), "planning without a decompile does not admit the slot");
            refused(planning, "planning without a decompile");
            var real = decompile(function, decompiler, metadata);
            check(real.provenSwitchSlots.equals(slots) && get(render(metadata, real, true), "status").equals("recovered"), "the production native path proves the slot");
            refused(render(metadata, new ExportProgramModelOwned.NativeOutcome(real.source, real.nativeFailure, real.prototype), true), "a native outcome without switch proof");
            var failing = new ghidra.app.decompiler.DecompInterface() {
                @Override public synchronized ghidra.app.decompiler.DecompileResults decompileFunction(Function target, int timeout, TaskMonitor monitor) { return null; }
            };
            var failed = decompile(function, failing, metadata);
            check(failed.provenSwitchSlots.isEmpty(), "a failed decompile proves no slot");
            refused(render(metadata, failed, true), "a failed decompile");
            check(!proven(null, slots, maximum), "a missing HighFunction proves no slot");
            System.out.println("owned switch provenance exact limits listing=" + listingLimit + " decompiler=" + decompilerLimit + " of " + maximum);

            // R4: repeated candidates at one jump fetch, charge and cache J's arrays once.
            Object once = budget(maximum), thrice = budget(maximum);
            Object repeated = slotCandidate(tableRead, table, space.getAddress(cases[0]), jump);
            check(proven(high, slots, once) && proven(high, List.of(slots.get(0), repeated, repeated), thrice), "repeated candidates at one jump are proven");
            long fetch = used(once) - tables.length - 1;
            check(used(thrice) - used(once) == 2 && fetch >= 1 + 1 + tables[0].getCases().length,
                "each repeated candidate costs one unit and no second fetch: once=" + used(once) + " thrice=" + used(thrice) + " fetch=" + fetch);
            System.out.println("owned switch provenance charged once per jump: one=" + used(once) + " three=" + used(thrice) + " fetch=" + fetch);

            // R2: the decompiler record must be anchored at R's own base, and the slot value must be the first case.
            Object interior = slotCandidate(tableRead, table.add(8), space.getAddress(cases[1]), jump);
            check(!proven(high, List.of(interior), maximum), "a slot covered by a LoadTable that starts at another base is refused");
            Object shifted = slotCandidate(tableRead, table, space.getAddress(cases[1]), jump);
            check(!proven(high, List.of(shifted), maximum), "a slot value that is not the anchored entry's case is refused");
            Object elsewhere = slotCandidate(tableRead, table, space.getAddress(cases[0]), space.getAddress(0x4005));
            check(!proven(high, List.of(elsewhere), maximum), "a candidate whose jump has no recovered table is refused");

            // R2: R's LOAD address resolves only through reaching definitions inside R. These are authored raw p-code ops.
            AddressSpace constants = program.getAddressFactory().getConstantSpace(), unique = program.getAddressFactory().getUniqueSpace();
            var rax = new ghidra.program.model.pcode.Varnode(program.getRegister("RAX").getAddress(), 8);
            var rbx = new ghidra.program.model.pcode.Varnode(program.getRegister("RBX").getAddress(), 8);
            var ram = new ghidra.program.model.pcode.Varnode(constants.getAddress(space.getSpaceID()), 4);
            var base = new ghidra.program.model.pcode.Varnode(constants.getAddress(table.getOffset()), 8);
            var other = new ghidra.program.model.pcode.Varnode(constants.getAddress(0x1234), 8);
            var eight = new ghidra.program.model.pcode.Varnode(constants.getAddress(8), 8);
            var four = new ghidra.program.model.pcode.Varnode(constants.getAddress(4), 8);
            var u1 = new ghidra.program.model.pcode.Varnode(unique.getAddress(0x100), 8);
            var u2 = new ghidra.program.model.pcode.Varnode(unique.getAddress(0x200), 8);
            var u3 = new ghidra.program.model.pcode.Varnode(unique.getAddress(0x300), 8);
            var u4 = new ghidra.program.model.pcode.Varnode(unique.getAddress(0x400), 8);
            check(binds(exporter, table, op(tableRead, 0, PcodeOp.COPY, u1, base), op(tableRead, 1, PcodeOp.INT_MULT, u2, rax, eight),
                op(tableRead, 2, PcodeOp.INT_ADD, u3, u1, u2), op(tableRead, 3, PcodeOp.LOAD, u4, ram, u3)), "authored base + index * 8 binds");
            check(binds(exporter, table, op(tableRead, 0, PcodeOp.COPY, u1, other), op(tableRead, 1, PcodeOp.COPY, u1, base),
                op(tableRead, 2, PcodeOp.INT_MULT, u2, rax, eight), op(tableRead, 3, PcodeOp.INT_ADD, u3, u1, u2),
                op(tableRead, 4, PcodeOp.LOAD, u4, ram, u3)), "the reaching definition of the base is the one that counts");
            check(!binds(exporter, table, op(tableRead, 0, PcodeOp.COPY, u1, base), op(tableRead, 1, PcodeOp.COPY, u1, other),
                op(tableRead, 2, PcodeOp.INT_MULT, u2, rax, eight), op(tableRead, 3, PcodeOp.INT_ADD, u3, u1, u2),
                op(tableRead, 4, PcodeOp.LOAD, u4, ram, u3)), "an overwritten constant slot base is refused");
            check(!binds(exporter, table, op(tableRead, 0, PcodeOp.INT_MULT, u2, rax, eight), op(tableRead, 1, PcodeOp.INT_ADD, u3, rbx, u2),
                op(tableRead, 2, PcodeOp.LOAD, u4, ram, u3)), "a base held in a register from before R is refused");
            check(!binds(exporter, table, op(tableRead, 0, PcodeOp.INT_MULT, u2, rax, four), op(tableRead, 1, PcodeOp.INT_ADD, u3, base, u2),
                op(tableRead, 2, PcodeOp.LOAD, u4, ram, u3)), "an index scale other than the slot width is refused");
            check(!binds(exporter, table, op(tableRead, 0, PcodeOp.INT_XOR, u1, base, rbx), op(tableRead, 1, PcodeOp.INT_MULT, u2, rax, eight),
                op(tableRead, 2, PcodeOp.INT_ADD, u3, u1, u2), op(tableRead, 3, PcodeOp.LOAD, u4, ram, u3)),
                "a slot-base constant used only transitively through another operator is refused");

            // (b) An ordinary untyped pointer holding a case address is read by a non-switch load.
            program.getListing().clearCodeUnits(ordinary, ordinary.add(7), false);
            untypedSlot(program.getListing().createData(ordinary, PointerDataType.dataType), space.getAddress(cases[0]), "ordinary pointer");
            check(candidate(exporter, function, ordinaryRead, pointerRead, maximum) == null, "an ordinary pointer with a case value is not a switch slot");
            Object ordinaryMetadata = switchMetadata(switchExporter(program), function, work, "switch-ordinary");
            refused(ordinaryMetadata, "an ordinary pointer with a case value");
            refused(execute(worker, ordinaryMetadata), "an ordinary pointer with a case value, after a decompile");
            program.getListing().clearCodeUnits(ordinary, ordinary.add(7), false);
            program.getListing().createData(ordinary, new PointerDataType(VoidDataType.dataType, 8));

            // (c) A stray read of the real table slot that does not supply any branch target.
            ghidra.program.model.symbol.Reference strayRead = program.getReferenceManager().addMemoryReference(
                space.getAddress(cases[2]), table, RefType.READ, SourceType.USER_DEFINED, 1);
            check(candidate(exporter, function, space.getAddress(cases[2]), strayRead, maximum) == null, "a stray table read is not the switch's load");
            Object strayMetadata = switchMetadata(switchExporter(program), function, work, "switch-stray");
            refused(strayMetadata, "a stray table read");
            refused(execute(worker, strayMetadata), "a stray table read, after a decompile");
            program.getReferenceManager().delete(strayRead);
        } finally { dispose(worker); }

        // (a) B: a separate read of the real table on the same fall-through path, between the table load and the jump.
        // cmp edi,2; ja default; mov eax,edi; mov rax,[rax*8+0x9200]; mov rcx,[0x9200]; jmp rax; three cases; default
        Address separateTable = space.getAddress(0x9200), genuineRead = space.getAddress(0x4107), separateRead = space.getAddress(0x410f);
        long[] separateCases = {0x4119, 0x411f, 0x4125};
        for (int index = 0; index < separateCases.length; index++) program.getMemory().setLong(separateTable.add(index * 8L), separateCases[index]);
        Function separate = switchFunction(program, "switch_separate", space.getAddress(0x4100), space.getAddress(0x412d), new byte[]{
            (byte)0x83,(byte)0xff,0x02, 0x77,0x26, (byte)0x89,(byte)0xf8, 0x48,(byte)0x8b,0x04,(byte)0xc5,0x00,(byte)0x92,0x00,0x00,
            0x48,(byte)0x8b,0x0c,0x25,0x00,(byte)0x92,0x00,0x00, (byte)0xff,(byte)0xe0,
            (byte)0xb8,0x0a,0x00,0x00,0x00,(byte)0xc3, (byte)0xb8,0x14,0x00,0x00,0x00,(byte)0xc3, (byte)0xb8,0x1e,0x00,0x00,0x00,(byte)0xc3,
            0x31,(byte)0xc0,(byte)0xc3});
        switchAnalysis(program, separate, 1);
        untypedSlot(program.getListing().getDataAt(separateTable), space.getAddress(separateCases[0]), "separate-read table slot");
        ghidra.program.model.symbol.Reference genuine = readReference(program, genuineRead, separateTable, 1);
        ghidra.program.model.symbol.Reference extra = readReference(program, separateRead, separateTable, 1);
        ExportProgramModelOwned separateExporter = switchExporter(program);
        check(candidate(separateExporter, separate, genuineRead, genuine, maximum) != null, "the genuine table load in B is bound");
        check(candidate(separateExporter, separate, separateRead, extra, maximum) == null, "a separate table read that falls through to J is not the switch's load");
        Object separateMetadata = switchMetadata(separateExporter, separate, work, "switch-separate");
        refused(separateMetadata, "a separate read of the real table on the fall-through path");
        Object separateWorker = worker(separateExporter);
        try { refused(execute(separateWorker, separateMetadata), "a separate read of the real table, after a decompile"); }
        finally { dispose(separateWorker); }

        // D: an ordinary pointer whose indexed load does supply an indirect jump, with forged switch labels. The listing
        // half passes, but labels are not evidence, and the decompiler recovers no table for the unguarded index, so the
        // refusal stays. A direct [0xa000] read lifts to COPY from a ram varnode, not a LOAD, so it never gets this far.
        // mov rax,[rdi*8+0xa000]; jmp rax; target: mov eax,1; ret
        Address pointer = space.getAddress(0xa000), indirectRead = space.getAddress(0x4200), indirectJump = space.getAddress(0x4208);
        program.getMemory().setLong(pointer, 0x420a);
        Function indirect = switchFunction(program, "switch_ordinary_jump", space.getAddress(0x4200), space.getAddress(0x420f), new byte[]{
            0x48,(byte)0x8b,0x04,(byte)0xfd,0x00,(byte)0xa0,0x00,0x00, (byte)0xff,(byte)0xe0, (byte)0xb8,0x01,0x00,0x00,0x00,(byte)0xc3});
        check(new DisassembleCommand(space.getAddress(0x420a), null, true).applyTo(program, TaskMonitor.DUMMY), "indirect target disassembly");
        switchAnalysis(program, indirect, 0);
        untypedSlot(program.getListing().createData(pointer, PointerDataType.dataType), space.getAddress(0x420a), "indirect-jump pointer");
        ghidra.program.model.symbol.Reference indirectLoad = readReference(program, indirectRead, pointer, 1);
        var forged = program.getSymbolTable().createNameSpace(null, "switchD_" + indirectJump, SourceType.ANALYSIS);
        program.getSymbolTable().createLabel(indirectJump, "switchD", forged, SourceType.ANALYSIS);
        program.getSymbolTable().createLabel(pointer, "switchdataD_" + pointer, forged, SourceType.ANALYSIS);
        ExportProgramModelOwned indirectExporter = switchExporter(program);
        check(candidate(indirectExporter, indirect, indirectRead, indirectLoad, maximum) != null, "the ordinary pointer's load does supply J");
        Object indirectMetadata = switchMetadata(indirectExporter, indirect, work, "switch-indirect");
        check(((List<?>)get(indirectMetadata, "switchSlots")).size() == 1, "the forged-label slot is only a deferred candidate");
        Object indirectWorker = worker(indirectExporter);
        try { refused(execute(indirectWorker, indirectMetadata), "an ordinary pointer feeding an indirect jump with forged switch labels"); }
        finally { dispose(indirectWorker); }

        // E: the production allowance is reached by a 1024-instruction straight-line run between the table load and J.
        // The run alternates two moves, because Ghidra's disassembler stops after 16 identical repeated instructions.
        // cmp edi,2; ja.rel32 default; mov eax,edi; mov rax,[rax*8+0x9300]; 512 x (mov ecx,ecx; mov edx,edx); jmp rax; three cases; default
        Address longTable = space.getAddress(0x9300), longRead = space.getAddress(0x430b);
        java.io.ByteArrayOutputStream longCode = new java.io.ByteArrayOutputStream();
        longCode.writeBytes(new byte[]{(byte)0x83,(byte)0xff,0x02, 0x0f,(byte)0x87,0x1e,0x08,0x00,0x00, (byte)0x89,(byte)0xf8,
            0x48,(byte)0x8b,0x04,(byte)0xc5,0x00,(byte)0x93,0x00,0x00});
        for (int index = 0; index < 512; index++) longCode.writeBytes(new byte[]{(byte)0x89,(byte)0xc9, (byte)0x89,(byte)0xd2});
        longCode.writeBytes(new byte[]{(byte)0xff,(byte)0xe0, (byte)0xb8,0x0a,0x00,0x00,0x00,(byte)0xc3, (byte)0xb8,0x14,0x00,0x00,0x00,(byte)0xc3,
            (byte)0xb8,0x1e,0x00,0x00,0x00,(byte)0xc3, 0x31,(byte)0xc0,(byte)0xc3});
        long[] longCases = {0x4b15, 0x4b1b, 0x4b21};
        for (int index = 0; index < longCases.length; index++) program.getMemory().setLong(longTable.add(index * 8L), longCases[index]);
        Function longRun = switchFunction(program, "switch_long_run", space.getAddress(0x4300), space.getAddress(0x4b29), longCode.toByteArray());
        switchAnalysis(program, longRun, 1);
        untypedSlot(program.getListing().getDataAt(longTable), space.getAddress(longCases[0]), "long-run table slot");
        ghidra.program.model.symbol.Reference longLoad = readReference(program, longRead, longTable, 1);
        ExportProgramModelOwned longExporter = switchExporter(program);
        check(candidate(longExporter, longRun, longRead, longLoad, 1 << 16) != null, "the long-run table load is bound with a larger allowance");
        check(candidate(longExporter, longRun, longRead, longLoad, maximum) == null, "the production allowance is reached before J");
        refused(switchMetadata(longExporter, longRun, work, "switch-long"), "a slot whose provenance exceeds the production allowance");

        // F: a two-level switch. A second load on the same recovery path, a byte index table, adds a second LoadTable.
        // The listing half binds R, and R's table covers the slot with a matching case. But Ghidra's merged load
        // records cannot say which LoadTable R made, so the refusal stays.
        // cmp edi,2; ja default; mov eax,edi; movzx eax,byte [rax+0x9400]; mov rax,[rax*8+0x9500]; jmp rax; three cases; default
        Address indexTable = space.getAddress(0x9400), levelTable = space.getAddress(0x9500), levelRead = space.getAddress(0x4c0e);
        Address levelJump = space.getAddress(0x4c16);
        program.getMemory().setBytes(indexTable, new byte[]{0, 1, 2});
        long[] levelCases = {0x4c18, 0x4c1e, 0x4c24};
        for (int index = 0; index < levelCases.length; index++) program.getMemory().setLong(levelTable.add(index * 8L), levelCases[index]);
        Function twoLevel = switchFunction(program, "switch_two_level", space.getAddress(0x4c00), space.getAddress(0x4c2c), new byte[]{
            (byte)0x83,(byte)0xff,0x02, 0x77,0x25, (byte)0x89,(byte)0xf8, 0x0f,(byte)0xb6,(byte)0x80,0x00,(byte)0x94,0x00,0x00,
            0x48,(byte)0x8b,0x04,(byte)0xc5,0x00,(byte)0x95,0x00,0x00, (byte)0xff,(byte)0xe0,
            (byte)0xb8,0x0a,0x00,0x00,0x00,(byte)0xc3, (byte)0xb8,0x14,0x00,0x00,0x00,(byte)0xc3, (byte)0xb8,0x1e,0x00,0x00,0x00,(byte)0xc3,
            0x31,(byte)0xc0,(byte)0xc3});
        switchAnalysis(program, twoLevel, 1);
        untypedSlot(program.getListing().getDataAt(levelTable), space.getAddress(levelCases[0]), "two-level address table slot");
        ghidra.program.model.symbol.Reference levelLoad = readReference(program, levelRead, levelTable, 1);
        ExportProgramModelOwned levelExporter = switchExporter(program);
        check(candidate(levelExporter, twoLevel, levelRead, levelLoad, maximum) != null, "the listing half binds R in the two-level switch");
        Object levelMetadata = switchMetadata(levelExporter, twoLevel, work, "switch-two-level");
        check(((List<?>)get(levelMetadata, "switchSlots")).size() == 1, "the two-level table slot is a deferred candidate");
        Object levelWorker = worker(levelExporter);
        try {
            var levelDecompiler = (ghidra.app.decompiler.DecompInterface)get(levelWorker, "decompiler");
            var levelHigh = levelDecompiler.decompileFunction(twoLevel, 30, TaskMonitor.DUMMY).getHighFunction();
            var levelTables = levelHigh.getJumpTables();
            check(levelTables.length == 1 && levelTables[0].getSwitchAddress().equals(levelJump), "one recovered two-level table at J");
            var levelLoads = levelTables[0].getLoadTables();
            boolean extent = false;
            for (var load : levelLoads) extent |= load.getAddress().equals(levelTable) && load.getSize() == 8 && load.getNum() == 3;
            check(levelLoads.length == 2 && extent && Arrays.asList(levelTables[0].getCases()).contains(space.getAddress(levelCases[0])) &&
                levelTables[0].getCases()[0].equals(space.getAddress(levelCases[0])),
                "the slot has a matching extent and first case, beside a second LoadTable: " + levelLoads.length);
            check(!proven(levelHigh, get(levelMetadata, "switchSlots"), maximum), "a second LoadTable on J's path keeps the refusal");
            refused(execute(levelWorker, levelMetadata), "a two-level switch whose LoadTables are ambiguous");
        } finally { dispose(levelWorker); }
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
