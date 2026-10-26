import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import ghidra.GhidraApplicationLayout;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraState;
import ghidra.framework.Application;
import ghidra.framework.HeadlessGhidraApplicationConfiguration;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.lang.CompilerSpecID;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.OutputStream;
import java.io.PrintStream;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.*;

/** Authored actual SLEIGH instructions and bundled decompilation, not constructor-only HighFunctions. */
public final class NativeInferredInterfaceControls {
    private static final TaskMonitor MONITOR = TaskMonitor.DUMMY;
    private static final String ARCHIVE_SHA = "93a5d11a9ad510622acaaf908c556a7b9b764d338e78a7567f3689bf5081fd54";
    private static Path root, collectorSource, listingSource, modelSource, wrapperSource, typeGraphSource, nativeDecompiler, input, model, listing;

    public static void main(String[] arguments) throws Exception {
        require(arguments.length == 7, "expected release, control root, inferred collector, listing collector, model exporter, wrapper and type graph source");
        root = Path.of(arguments[1]).toAbsolutePath();
        collectorSource = Path.of(arguments[2]).toAbsolutePath();
        listingSource = Path.of(arguments[3]).toAbsolutePath();
        modelSource = Path.of(arguments[4]).toAbsolutePath();
        wrapperSource = Path.of(arguments[5]).toAbsolutePath();
        typeGraphSource = Path.of(arguments[6]).toAbsolutePath();
        nativeDecompiler = Path.of(arguments[0]).resolve("Ghidra/Features/Decompiler/os/linux_x86_64/decompile");
        require(Files.isExecutable(nativeDecompiler), "bundled native decompiler unavailable");
        require(Path.of("").toRealPath().equals(root.toRealPath()), "control cwd differs from owned root");
        Application.initializeApplication(new GhidraApplicationLayout(Path.of(arguments[0]).toFile()),
            new HeadlessGhidraApplicationConfiguration());
        require("12.1.3".equals(Application.getApplicationVersion()), "unexpected bundled Ghidra version");
        NativeInferredFailureDiagnosticsControls.run(root.resolve("failure-diagnostics-controls"));
        NativeInterfaceTypeGraphControls.run(root.resolve("graph-controls"));
        var language = DefaultLanguageService.getLanguageService().getLanguage(new LanguageID("x86:LE:64:default"));
        Object consumer = new Object();
        ProgramDB program = new ProgramDB("authored-inferred-interfaces", language, language.getCompilerSpecByID(new CompilerSpecID("gcc")), consumer);
        try {
            Map<String, Function> functions = createControls(program);
            prepareFrozenInputs(program, functions);
            exerciseCollector(program, functions);
        } finally { program.release(consumer); }
        runWindowsControls(root);
        System.out.println("native inferred interface controls passed");
        System.exit(0);
    }

    private static void runWindowsControls(Path parent) throws Exception {
        root = Files.createDirectory(parent.resolve("windows-inferred"));
        var language = DefaultLanguageService.getLanguageService().getLanguage(new LanguageID("x86:LE:64:default"));
        Object consumer = new Object();
        ProgramDB program = new ProgramDB("authored-windows-inferred-interfaces", language,
            language.getCompilerSpecByID(new CompilerSpecID("windows")), consumer);
        try {
            Map<String, Function> functions = createWindowsControls(program);
            prepareFrozenInputs(program, functions);
            Map<Path, String> modelBefore = snapshots(root.resolve("reports"));
            Map<Path, String> listingBefore = snapshots(listing);
            long modification = program.getModificationNumber();
            Path first = root.resolve("first-inferred"), second = root.resolve("second-inferred");
            collectSilently(program, first);
            collectSilently(program, second);
            for (String file : List.of("manifest.json", "native-inferred-interfaces.json")) {
                require(Arrays.equals(Files.readAllBytes(first.resolve(file)), Files.readAllBytes(second.resolve(file))),
                    "nondeterministic Windows inference bytes: " + file);
            }
            JsonObject document = JsonParser.parseString(Files.readString(first.resolve("native-inferred-interfaces.json"))).getAsJsonObject();
            JsonObject receipt = compareWindowsAgainstNative(program, functions, document);
            require(program.getModificationNumber() == modification, "Windows inference or independent API control wrote back to Program");
            require(modelBefore.equals(snapshots(root.resolve("reports"))) && listingBefore.equals(snapshots(listing)),
                "Windows inference changed frozen inputs");
            receipt.addProperty("byteIdenticalRepeatedCapture", true);
            receipt.addProperty("successfulInferenceDiagnosticSilence", true);
            receipt.addProperty("nativeProgramUnchangedByInference", true);
            receipt.addProperty("modelAndListingUnchanged", true);
            receipt.addProperty("observationsSha256", sha256(first.resolve("native-inferred-interfaces.json")));
            receipt.addProperty("observationsBytes", Files.size(first.resolve("native-inferred-interfaces.json")));
            Files.writeString(root.resolve("verified-control-receipt.json"), receipt.toString() + "\n");
            Files.writeString(root.resolve("verified-controls.txt"),
                "actual-windows-HighFunction independent-real-native-prototype-symbol-comparison this-hidden-raw-flags " +
                "listing-forced-indirect-unavailable-inferred-meaning deterministic model-unchanged listing-unchanged program-unchanged\n");
        } finally { program.release(consumer); }
    }

    private static Map<String, Function> createWindowsControls(ProgramDB program) throws Exception {
        byte[] bytes = new byte[0x100]; Arrays.fill(bytes, (byte) 0xcc);
        // this=RCX, hidden result=RDX, forced-indirect aggregate=R8 under this pinned listing model.
        byte[] aggregate = hex("48 89 d0 4d 8b 08 4c 89 0a 4d 8b 48 08 4c 89 4a 08 4d 8b 48 10 4c 89 4a 10 c3");
        byte[] mixed = hex("48 89 c8 48 01 d0 4c 01 c0 4c 01 c8 48 03 44 24 28 48 03 44 24 30 c3");
        System.arraycopy(aggregate, 0, bytes, 0, aggregate.length);
        System.arraycopy(mixed, 0, bytes, 0x40, mixed.length);
        input = root.resolve("synthetic-input.bin"); Files.write(input, bytes);
        Map<String, Function> functions = new LinkedHashMap<>();
        int transaction = program.startTransaction("authored Windows inferred interfaces");
        try {
            program.getMemory().createInitializedBlock("authored-windows-inference", address(program, 0x1000),
                new ByteArrayInputStream(bytes), bytes.length, MONITOR, false).setExecute(true);
            program.setExecutablePath(input.toString()); program.setExecutableSHA256(sha256(input));
            program.setExecutableFormat("authored windows x86-64 inference controls");
            Function method = createFunction(program, functions, "windows_aggregate_method", 0x1000, aggregate.length, true);
            StructureDataType structure = new StructureDataType("Aggregate24", 0, program.getDataTypeManager());
            for (int index = 0; index < 3; index++) structure.add(UnsignedLongLongDataType.dataType, "word" + index, null);
            method.updateFunction("__thiscall", new ReturnParameterImpl(structure, program),
                List.of(new ParameterImpl("aggregate", structure, program, SourceType.USER_DEFINED)),
                Function.FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS, true, SourceType.USER_DEFINED);
            Function parameters = createFunction(program, functions, "windows_mixed_parameters", 0x1040, mixed.length, true);
            List<Variable> six = new ArrayList<>();
            for (int index = 0; index < 6; index++) six.add(new ParameterImpl("value" + index,
                UnsignedLongLongDataType.dataType, program, SourceType.USER_DEFINED));
            parameters.updateFunction("__fastcall", new ReturnParameterImpl(UnsignedLongLongDataType.dataType, program), six,
                Function.FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS, true, SourceType.USER_DEFINED);
        } finally { program.endTransaction(transaction, true); }
        Function method = functions.get("windows_aggregate_method");
        require(method.getParameterCount() == 3 && method.getAutoParameterCount() == 2, "authored Windows hidden/this listing changed");
        require(method.getParameter(0).getAutoParameterType() == AutoParameterType.THIS &&
            method.getParameter(1).getAutoParameterType() == AutoParameterType.RETURN_STORAGE_PTR,
            "authored Windows automatic parameter roles changed");
        require(method.getParameter(2).isForcedIndirect() && method.getReturn().isForcedIndirect(), "authored forced-indirect aggregate missing");
        require(method.getParameter(2).getFormalDataType() instanceof Structure && method.getParameter(2).getDataType() instanceof Pointer,
            "authored listing formal/effective distinction missing");
        return functions;
    }

    private static JsonObject compareWindowsAgainstNative(Program program, Map<String, Function> functions, JsonObject document) throws Exception {
        Map<String, JsonObject> captured = new LinkedHashMap<>();
        for (JsonElement element : document.getAsJsonArray("records")) {
            JsonObject record = element.getAsJsonObject();
            if (text(record, "recordKind").equals("function")) captured.put(addressKey(record.getAsJsonObject("entry")), record);
        }
        equal(captured.size(), functions.size(), "complete Windows native outcomes");
        JsonObject receipt = new JsonObject();
        receipt.addProperty("kind", "authored-windows-inferred-interface-control-v1");
        receipt.addProperty("fixtureOnly", true); receipt.addProperty("compilerSpecId", "windows");
        receipt.addProperty("authoritativeOracleEvidence", false); receipt.addProperty("productionInterfacesAdmitted", false);
        receipt.addProperty("releaseEligible", false);
        receipt.addProperty("formalEffectiveMeaning", "unavailable-native-api");
        receipt.addProperty("forcedIndirectMeaning", "unavailable-for-plain-decoded-storage");
        com.google.gson.JsonArray rows = new com.google.gson.JsonArray();
        DecompInterface decompiler = new DecompInterface();
        try {
            DecompileOptions options = new DecompileOptions();
            options.setMaxInstructions(500000); options.setMaxPayloadMBytes(50); options.setMaxJumpTableEntries(1024);
            require(decompiler.setOptions(options) && decompiler.setSimplificationStyle("decompile") &&
                decompiler.toggleSyntaxTree(true) && decompiler.toggleCCode(false) && decompiler.openProgram(program),
                "independent raw API control could not open actual bundled decompiler");
            for (Function function : functions.values()) {
                JsonObject record = captured.get(addressKey(document, function.getEntryPoint()));
                equal(text(record, "disposition"), "high-function-observed", "actual Windows HighFunction outcome");
                DecompileResults result = decompiler.decompileFunction(function, 30, MONITOR);
                require(result.decompileCompleted() && result.getHighFunction() != null, "independent Windows raw API control has no HighFunction");
                HighFunction high = result.getHighFunction();
                if (function.getName().equals("windows_aggregate_method")) {
                    require(high.getFunctionPrototype().hasThisPointer() && high.getLocalSymbolMap().getNumParams() == 3,
                        "pinned native Windows aggregate/this shape changed");
                    require(high.getLocalSymbolMap().getParamSymbol(0).isThisPointer() &&
                        high.getLocalSymbolMap().getParamSymbol(1).isHiddenReturn(), "pinned native automatic HighSymbol roles missing");
                    require(!high.getLocalSymbolMap().getParamSymbol(2).getStorage().isForcedIndirect(),
                        "pinned decoded aggregate storage no longer exhibits raw indirect limitation; review semantics before updating");
                }
                JsonObject prototype = record.getAsJsonObject("prototype");
                equal(prototype.get("hasThis").getAsBoolean(), high.getFunctionPrototype().hasThisPointer(), "raw native hasThis");
                equal(prototype.get("parameterCount").getAsInt(), high.getFunctionPrototype().getNumParams(), "raw native prototype count");
                equal(record.getAsJsonArray("parameters").size(), high.getLocalSymbolMap().getNumParams(), "raw native symbol census");
                com.google.gson.JsonArray parameterRows = new com.google.gson.JsonArray();
                for (int index = 0; index < high.getLocalSymbolMap().getNumParams(); index++) {
                    HighSymbol symbol = high.getLocalSymbolMap().getParamSymbol(index);
                    JsonObject parameter = record.getAsJsonArray("parameters").get(index).getAsJsonObject();
                    equal(parameter.get("isThisPointer").getAsBoolean(), symbol.isThisPointer(), "raw native this flag");
                    equal(parameter.get("isHiddenReturn").getAsBoolean(), symbol.isHiddenReturn(), "raw native hidden result flag");
                    equal(parameter.get("typeLocked").getAsBoolean(), symbol.isTypeLocked(), "raw native type lock");
                    equal(parameter.get("nameLocked").getAsBoolean(), symbol.isNameLocked(), "raw native name lock");
                    equal(parameter.getAsJsonObject("storage").get("forcedIndirect").getAsBoolean(), symbol.getStorage().isForcedIndirect(), "raw native decoded indirect flag");
                    equal(text(parameter, "formalEffectiveRelation"), "unavailable-native-api", "Windows inferred formal relation remains unavailable");
                    equal(text(parameter, "forcedIndirectMeaning"), "unavailable-for-plain-decoded-storage", "Windows inferred indirect meaning remains unavailable");
                    JsonObject observation = new JsonObject();
                    observation.addProperty("index", index); observation.addProperty("isThisPointer", symbol.isThisPointer());
                    observation.addProperty("isHiddenReturn", symbol.isHiddenReturn());
                    observation.addProperty("rawStorageForcedIndirect", symbol.getStorage().isForcedIndirect());
                    observation.addProperty("storageNativeClass", symbol.getStorage().getClass().getName());
                    parameterRows.add(observation);
                }
                JsonObject row = new JsonObject(); row.addProperty("authoredLabel", function.getName());
                row.addProperty("listingParameterCount", function.getParameterCount());
                row.addProperty("inferredParameterCount", high.getLocalSymbolMap().getNumParams());
                row.addProperty("nativeHasThis", high.getFunctionPrototype().hasThisPointer()); row.add("parameters", parameterRows);
                rows.add(row);
            }
        } finally { decompiler.stopProcess(); decompiler.dispose(); }
        receipt.add("functions", rows); receipt.add("summary", document.get("summary").deepCopy());
        return receipt;
    }

    private static Map<String, Function> createControls(ProgramDB program) throws Exception {
        byte[] bytes = new byte[0x400];
        Arrays.fill(bytes, (byte) 0xcc);
        // DEFAULT listing signatures have no declared parameters. The real decompiler must
        // infer uses of RDI/RSI, XMM0/XMM1, and the incoming stack from these authored bytes.
        Map<String, byte[]> code = new LinkedHashMap<>();
        code.put("integer_add", hex("48 89 f8 48 01 f0 c3"));
        code.put("sse_add", hex("f2 0f 58 c1 c3"));
        code.put("seventh_integer", hex("48 8b 44 24 08 48 01 f8 48 01 f0 48 01 d0 48 01 c8 4c 01 c0 4c 01 c8 c3"));
        code.put("ninth_sse", hex("f2 0f 58 c1 f2 0f 58 c2 f2 0f 58 c3 f2 0f 58 c4 f2 0f 58 c5 f2 0f 58 c6 f2 0f 58 c7 f2 0f 58 44 24 08 c3"));
        code.put("constant_return", hex("b8 2a 00 00 00 c3"));
        code.put("recursive_shape", hex("48 8b 07 c3"));
        code.put("union_shape", hex("48 8b 07 c3"));
        code.put("packed_shape", hex("48 8b 47 01 c3"));
        code.put("array_typedef_shape", hex("8b 07 c3"));
        code.put("bitfield_shape", hex("8b 07 83 e0 07 c3"));
        code.put("declared_variadic", hex("48 89 f8 c3"));
        int offset = 0;
        for (byte[] functionBytes : code.values()) {
            require(functionBytes.length <= 0x30, "authored function exceeds slot");
            System.arraycopy(functionBytes, 0, bytes, offset, functionBytes.length);
            offset += 0x30;
        }
        // One real jump thunk has its own body, and a listed body with no instructions is retained.
        int thunkOffset = 0x300;
        int displacement = -thunkOffset - 5;
        byte[] thunk = {(byte) 0xe9, (byte) displacement, (byte) (displacement >>> 8), (byte) (displacement >>> 16), (byte) (displacement >>> 24)};
        System.arraycopy(thunk, 0, bytes, thunkOffset, thunk.length);
        input = root.resolve("synthetic-input.bin");
        Files.write(input, bytes);
        Map<String, Function> functions = new LinkedHashMap<>();
        int transaction = program.startTransaction("authored inference instructions and shapes");
        try {
            Address start = address(program, 0x1000);
            program.getMemory().createInitializedBlock("authored-inference", start,
                new ByteArrayInputStream(bytes), bytes.length, MONITOR, false).setExecute(true);
            program.setExecutablePath(input.toString());
            program.setExecutableSHA256(sha256(input));
            program.setExecutableFormat("authored x86-64 inference controls");
            offset = 0;
            for (var entry : code.entrySet()) {
                createFunction(program, functions, entry.getKey(), 0x1000 + offset, entry.getValue().length, true);
                offset += 0x30;
            }
            createFunction(program, functions, "jump_thunk", 0x1000 + thunkOffset, thunk.length, true)
                .setThunkedFunction(functions.get("integer_add"));
            createFunction(program, functions, "unsupported_body", 0x1350, 1, false);
            Function external = program.getExternalManager().addExtFunction("authored-inference-library", "external_target", null,
                SourceType.IMPORTED).getFunction();
            require(external != null, "authored external function creation failed");
            functions.put("external_target", external);

            var manager = program.getDataTypeManager();
            StructureDataType recursive = new StructureDataType("RecursiveNode", 0, manager);
            recursive.add(UnsignedLongLongDataType.dataType, "payload", null);
            recursive.add(new PointerDataType(recursive, manager), "next", null);
            UnionDataType union = new UnionDataType(CategoryPath.ROOT, "SameExtentUnion", manager);
            union.add(UnsignedLongLongDataType.dataType, "integer", null);
            union.add(DoubleDataType.dataType, "floating", null);
            StructureDataType packed = new StructureDataType("PackedNode", 0, manager);
            packed.setExplicitPackingValue(1);
            packed.add(ByteDataType.dataType, "tag", null);
            packed.add(UnsignedLongLongDataType.dataType, "payload", null);
            StructureDataType bits = new StructureDataType("RawBitfields", 0, manager);
            bits.setPackingEnabled(true);
            bits.addBitField(UnsignedIntegerDataType.dataType, 3, "low", null);
            bits.addBitField(UnsignedIntegerDataType.dataType, 5, "high", null);
            TypeDef alias = new TypedefDataType(CategoryPath.ROOT, "ArrayAlias", new ArrayDataType(IntegerDataType.dataType, 3, 4, manager), manager);
            declaredPointer(program, functions.get("recursive_shape"), recursive);
            declaredPointer(program, functions.get("union_shape"), union);
            declaredPointer(program, functions.get("packed_shape"), packed);
            declaredPointer(program, functions.get("array_typedef_shape"), alias);
            declaredPointer(program, functions.get("bitfield_shape"), bits);
            functions.get("declared_variadic").updateFunction("__stdcall", new ReturnParameterImpl(UnsignedLongLongDataType.dataType, program),
                List.of(new ParameterImpl("fixed", UnsignedLongLongDataType.dataType, program, SourceType.USER_DEFINED)),
                Function.FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS, true, SourceType.USER_DEFINED);
            functions.get("declared_variadic").setVarArgs(true);
        } finally { program.endTransaction(transaction, true); }
        for (String name : List.of("integer_add", "sse_add", "seventh_integer", "ninth_sse")) {
            Function function = functions.get(name);
            require(function.getSignatureSource() == SourceType.DEFAULT && function.getParameterCount() == 0,
                "inference control listing unexpectedly has declared parameters: " + name);
        }
        require(program.getFunctionManager().getFunctionCount() == functions.size(), "authored census mismatch");
        return functions;
    }

    private static void declaredPointer(Program program, Function function, DataType pointed) throws Exception {
        function.updateFunction("__stdcall", new ReturnParameterImpl(UnsignedLongLongDataType.dataType, program),
            List.of(new ParameterImpl("value", new PointerDataType(pointed, program.getDataTypeManager()), program, SourceType.USER_DEFINED)),
            Function.FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS, true, SourceType.USER_DEFINED);
    }

    private static Function createFunction(Program program, Map<String, Function> functions, String name,
            long offset, int length, boolean disassemble) throws Exception {
        Address entry = address(program, offset);
        AddressSet body = new AddressSet(entry, entry.add(length - 1));
        if (disassemble) {
            DisassembleCommand command = new DisassembleCommand(entry, body, false);
            require(command.applyTo(program, MONITOR), "authored disassembly failed: " + name + ": " + command.getStatusMsg());
            require(program.getListing().getInstructionAt(entry) != null, "authored instruction absent: " + name);
        }
        Function function = program.getFunctionManager().createFunction(name, entry, body, SourceType.USER_DEFINED);
        require(function != null, "authored function creation failed: " + name);
        functions.put(name, function);
        return function;
    }

    private static void prepareFrozenInputs(Program program, Map<String, Function> functions) throws Exception {
        Path reports = Files.createDirectory(root.resolve("reports"));
        model = reports.resolve("program_model.json");
        ExportProgramModel exporter = new ExportProgramModel();
        exporter.setScriptArgs(new String[] {sha256(modelSource), ARCHIVE_SHA, "planning", model.toString()});
        exporter.execute(new GhidraState(null, null, program, null, null, null), MONITOR, new PrintWriter(System.out, true));
        require(Files.size(model) > 0, "genuine planning model export missing");
        listing = root.resolve("frozen-listing");
        ExportNativeInterfacesV1.collect(program, MONITOR, new String[] {
            sha256(input), sha256(modelSource), ARCHIVE_SHA, sha256(listingSource), model.toString(), listing.toString()
        });
        JsonObject properties = new JsonObject();
        properties.addProperty("languageId", program.getLanguageID().getIdAsString());
        properties.addProperty("compilerSpecId", program.getCompilerSpec().getCompilerSpecID().getIdAsString());
        properties.addProperty("imageBaseSpace", program.getImageBase().getAddressSpace().getName());
        properties.addProperty("imageBaseOffsetBits", String.format("%016x", program.getImageBase().getOffset()));
        properties.addProperty("inputSha256", sha256(input));
        properties.addProperty("modelSha256", sha256(model));
        properties.addProperty("modelBytes", Files.size(model));
        properties.addProperty("functions", functions.size());
        properties.addProperty("externalFunctions", functions.values().stream().filter(Function::isExternal).count());
        properties.addProperty("thunks", functions.values().stream().filter(Function::isThunk).count());
        properties.addProperty("fixtureOnly", true);
        Files.writeString(root.resolve("native-properties.json"), properties.toString());
    }

    private static void exerciseCollector(ProgramDB program, Map<String, Function> functions) throws Exception {
        Map<Path, String> originalModel = snapshots(root.resolve("reports"));
        Map<Path, String> originalListing = snapshots(listing);
        long modification = program.getModificationNumber();
        Path first = root.resolve("first-inferred");
        Path second = root.resolve("second-inferred");
        collectSilently(program, first);
        require(program.getModificationNumber() == modification, "inference wrote back to native Program");
        require(originalModel.equals(snapshots(root.resolve("reports"))), "inference changed model artifacts");
        require(originalListing.equals(snapshots(listing)), "inference changed listing snapshot");
        collectSilently(program, second);
        require(program.getModificationNumber() == modification, "repeated inference wrote back to native Program");
        require(originalModel.equals(snapshots(root.resolve("reports"))), "repeated inference changed model artifacts");
        require(originalListing.equals(snapshots(listing)), "repeated inference changed listing snapshot");
        for (String name : List.of("manifest.json", "native-inferred-interfaces.json")) {
            require(Arrays.equals(Files.readAllBytes(first.resolve(name)), Files.readAllBytes(second.resolve(name))),
                "nondeterministic inference bytes: " + name);
        }
        JsonObject document = JsonParser.parseString(Files.readString(first.resolve("native-inferred-interfaces.json"))).getAsJsonObject();
        assertObserved(program, functions, document);
        Map<Path, String> originalOutput = snapshots(first);
        boolean refused = false;
        try { ExportInferredInterfacesV1.collect(program, MONITOR, collectorArguments(first)); }
        catch (Exception expected) { refused = true; }
        require(refused && originalOutput.equals(snapshots(first)), "existing inference output accepted or altered");
        cancelledCollection(program);
        listingCancelledCollection(program);
        changingProgramCollection(program, functions.get("integer_add"));
        changedListingCollection(program);
        stagingBudgetControls(program, functions.get("integer_add"));
        writeControlReceipt(program, functions, document);
        Files.writeString(root.resolve("verified-controls.txt"),
            "actual-bundled-native-decompilation default-listing-zero-versus-inferred-parameters integer SSE stack-use " +
            "ninth-SSE-stack-use-not-promoted-to-parameter " +
            "complete-function-dispositions external thunk unsupported-body typed-first-mapping separate-listing-inferred " +
            "recursive-type-graph union packed array typedef bitfield deterministic model-unchanged listing-unchanged " +
            "program-unchanged cancellation stale-output-rejected same-census-mutation-rejected changed-listing-rejected " +
            "actual-staging-exact-peak actual-staging-one-byte-below-peak actual-stale-listing-larger-rerender-bounded " +
            "successful-inference-diagnostic-silence actual-listing-cancellation-first-owner-freeze bounded-failure-diagnostics\n");
    }

    private static void assertObserved(Program program, Map<String, Function> functions, JsonObject document) {
        Map<String, JsonObject> records = new LinkedHashMap<>();
        Set<Integer> ordinals = new HashSet<>();
        Set<String> channels = new HashSet<>();
        Set<String> graphKinds = new HashSet<>();
        boolean backedge = false;
        boolean explicitPacking = false;
        boolean bitfieldWidths = false;
        for (JsonElement element : document.getAsJsonArray("records")) {
            JsonObject record = element.getAsJsonObject();
            String kind = text(record, "recordKind");
            if (kind.equals("function")) {
                require(records.put(addressKey(record.getAsJsonObject("entry")), record) == null, "duplicate native function output");
                require(ordinals.add(record.get("functionOrdinal").getAsInt()), "duplicate function ordinal");
            } else if (kind.equals("type-root")) channels.add(text(record, "channel"));
            else if (kind.equals("type-node")) {
                String typeKind = text(record, "kind");
                graphKinds.add(typeKind);
                JsonObject details = record.getAsJsonObject("details");
                if (typeKind.equals("structure") && details.get("explicitPackingValue").getAsInt() == 1) explicitPacking = true;
                if (typeKind.equals("bitfield") && details.get("declaredBitSize").getAsInt() == 3 &&
                        details.get("effectiveBitSize").getAsInt() == 3 && !details.get("bigEndian").getAsBoolean()) bitfieldWidths = true;
            } else if (kind.equals("type-edge") && text(record, "referenceState").equals("backedge")) backedge = true;
        }
        require(graphKinds.containsAll(Set.of("structure", "union", "pointer", "array", "typedef", "bitfield")),
            "actual graph lost native type distinctions: " + graphKinds);
        require(backedge, "actual recursive native graph has no explicit backedge");
        require(explicitPacking, "actual packed struct lost explicit packing");
        require(bitfieldWidths, "actual bitfield lost native declared/effective width or endian");
        equal(records.size(), functions.size(), "every native function has one outcome");
        equal(channels, Set.of("listing", "inferred"), "separate type-root channels");
        for (int index = 0; index < functions.size(); index++) require(ordinals.contains(index), "missing dense function ordinal");
        for (Function function : functions.values()) {
            JsonObject record = records.get(addressKey(document, function.getEntryPoint()));
            require(record != null, "native function outcome omitted: " + function.getName());
            equal(record.get("isExternal").getAsBoolean(), function.isExternal(), "raw external flag");
            equal(record.get("isThunk").getAsBoolean(), function.isThunk(), "raw thunk flag");
            String disposition = text(record, "disposition");
            if (function.isExternal()) {
                equal(disposition, "not-attempted-external", "external disposition");
                equal(record.get("attempt").getAsInt(), 0, "external attempt count");
                require(record.get("result").isJsonNull() && record.get("prototype").isJsonNull(), "external invented inference");
            } else if (function.getName().equals("unsupported_body")) {
                equal(disposition, "not-attempted-unsupported-body", "instructionless body disposition");
                equal(record.get("attempt").getAsInt(), 0, "unsupported body attempt count");
            } else {
                equal(disposition, "high-function-observed", "actual decompilation result for " + function.getName());
                equal(record.get("attempt").getAsInt(), 1, "single actual attempt");
                JsonObject result = record.getAsJsonObject("result");
                require(result.get("completed").getAsBoolean() && !result.get("timedOut").getAsBoolean() &&
                    !result.get("cancelled").getAsBoolean() && !result.get("failedToStart").getAsBoolean(), "actual decompilation did not complete");
                JsonObject prototype = record.getAsJsonObject("prototype");
                equal(text(prototype, "formalEffectiveRelation"), "unavailable-native-api", "inferred formal/effective limitation");
                equal(text(prototype, "allMappings"), "first-mapping-only", "prototype storage scope");
                equal(text(prototype, "privateFlags"), "unavailable-native-api", "private flags limitation");
                equal(prototype.get("localSymbolParameterCount").getAsInt(), record.getAsJsonArray("parameters").size(), "complete local-symbol parameter census");
                for (JsonElement parameterElement : record.getAsJsonArray("parameters")) {
                    JsonObject parameter = parameterElement.getAsJsonObject();
                    equal(text(parameter, "formalEffectiveRelation"), "unavailable-native-api", "parameter formal/effective limitation");
                    equal(text(parameter, "forcedIndirectMeaning"), "unavailable-for-plain-decoded-storage", "false forced indirect cannot prove direct passing");
                    equal(text(parameter, "allMappings"), "first-mapping-only", "parameter storage scope");
                }
            }
        }
        for (String name : List.of("integer_add", "sse_add", "seventh_integer", "ninth_sse")) {
            Function function = functions.get(name);
            require(function.getParameterCount() == 0 && function.getSignatureSource() == SourceType.DEFAULT,
                "inference changed default listing signature: " + name);
            JsonObject record = records.get(addressKey(document, function.getEntryPoint()));
            require(record.getAsJsonArray("parameters").size() >= 2, "actual machine argument inference missing: " + name);
        }
        for (String name : List.of("seventh_integer", "ninth_sse")) {
            JsonObject record = records.get(addressKey(document, functions.get(name).getEntryPoint()));
            boolean stack = false;
            for (JsonElement parameter : record.getAsJsonArray("parameters")) {
                for (JsonElement piece : parameter.getAsJsonObject().getAsJsonObject("storage").getAsJsonArray("varnodes")) {
                    JsonObject coordinate = piece.getAsJsonObject().getAsJsonObject("address");
                    if (text(coordinate, "kind").equals("address")) {
                        int index = coordinate.get("spaceIndex").getAsInt();
                        for (JsonElement space : document.getAsJsonArray("addressSpaces")) {
                            JsonObject descriptor = space.getAsJsonObject();
                            if (descriptor.get("index").getAsInt() == index && text(descriptor, "name").equals("stack")) stack = true;
                        }
                    }
                }
            }
            if (name.equals("seventh_integer")) require(stack, "actual stack parameter inference missing: " + name);
            else {
                // Pinned 12.1.3 does not promote this ninth SSE incoming-stack use into a
                // HighParam. Preserve the actual inference limitation rather than filling it
                // from the authored machine semantics or claiming raw parameter completeness.
                equal(record.getAsJsonArray("parameters").size(), 8, "pinned ninth-SSE raw inferred count");
                require(!stack, "pinned ninth-SSE raw storage census changed; review actual inference before updating control");
            }
        }
        JsonObject summary = document.getAsJsonObject("summary");
        equal(summary.get("functions").getAsInt(), functions.size(), "summary census");
        equal(summary.get("externalFunctions").getAsInt(), 1, "external summary");
        equal(summary.get("thunks").getAsInt(), 1, "thunk summary");
        equal(summary.get("attempted").getAsInt(), functions.size() - 2, "attempt census");
        equal(summary.get("observed").getAsInt(), functions.size() - 2, "observation census");
        for (String flag : List.of("authoritativeOracleEvidence", "recoveredModelScored", "productionInterfacesAdmitted", "releaseEligible"))
            require(!summary.get(flag).getAsBoolean(), "raw capture minted authority: " + flag);
    }

    private static void writeControlReceipt(Program program, Map<String, Function> functions, JsonObject document) throws Exception {
        Map<String, JsonObject> captured = new LinkedHashMap<>();
        for (JsonElement element : document.getAsJsonArray("records")) {
            JsonObject row = element.getAsJsonObject();
            if (text(row, "recordKind").equals("function")) captured.put(addressKey(row.getAsJsonObject("entry")), row);
        }
        JsonObject receipt = new JsonObject();
        receipt.addProperty("kind", "authored-native-inferred-interface-control-v1");
        receipt.addProperty("fixtureOnly", true);
        receipt.addProperty("ghidraVersion", Application.getApplicationVersion());
        receipt.addProperty("compilerSpecId", program.getCompilerSpec().getCompilerSpecID().getIdAsString());
        receipt.addProperty("byteIdenticalRepeatedCapture", true);
        receipt.addProperty("modelAndListingUnchanged", true);
        receipt.addProperty("nativeProgramUnchangedByInference", true);
        receipt.addProperty("lateSameCensusMutationRejected", true);
        receipt.addProperty("authoritativeOracleEvidence", false);
        receipt.addProperty("productionInterfacesAdmitted", false);
        receipt.addProperty("releaseEligible", false);
        receipt.addProperty("ninthSseLimitation", "Authored ADDSD [RSP+8] remains outside the eight native HighParam rows; no ninth parameter is manufactured from machine-fixture knowledge.");
        receipt.add("summary", document.get("summary").deepCopy());
        com.google.gson.JsonArray rows = new com.google.gson.JsonArray();
        for (Function function : functions.values()) {
            JsonObject actual = captured.get(addressKey(document, function.getEntryPoint()));
            JsonObject row = new JsonObject();
            row.addProperty("authoredLabel", function.getName());
            row.add("nativeEntry", actual.get("entry").deepCopy());
            row.addProperty("listingParameterCount", function.getParameterCount());
            row.addProperty("listingSignatureSource", function.getSignatureSource().name());
            row.addProperty("disposition", text(actual, "disposition"));
            if (actual.get("prototype").isJsonNull()) row.add("inferredParameterCount", com.google.gson.JsonNull.INSTANCE);
            else row.addProperty("inferredParameterCount", actual.getAsJsonArray("parameters").size());
            rows.add(row);
        }
        receipt.add("functions", rows);
        JsonObject files = new JsonObject();
        for (Path path : List.of(input, model, listing.resolve("native-interfaces.json"), listing.resolve("manifest.json"),
                root.resolve("first-inferred/native-inferred-interfaces.json"), root.resolve("first-inferred/manifest.json"),
                root.resolve("graph-controls/type-graph-controls.txt"))) {
            JsonObject identity = new JsonObject();
            identity.addProperty("bytes", Files.size(path)); identity.addProperty("sha256", sha256(path));
            files.add(root.relativize(path).toString(), identity);
        }
        receipt.add("files", files);
        Files.writeString(root.resolve("verified-control-receipt.json"), receipt.toString() + "\n");
    }

    private static void cancelledCollection(Program program) throws Exception {
        TaskMonitorAdapter monitor = new TaskMonitorAdapter(true);
        monitor.cancel();
        Path destination = root.resolve("cancelled-inferred");
        CapturedRun capture = captureStderr(() -> ExportInferredInterfacesV1.collect(program, monitor, collectorArguments(destination)));
        require(capture.failure() instanceof ghidra.util.exception.CancelledException && !Files.exists(destination),
            "cancelled inference left successful or partial output");
        JsonObject frame = onlyFailureFrame(capture);
        equal(text(frame, "failureKind"), "cancellation-observed", "direct cancellation classification");
        require(frame.getAsJsonObject("census").get("reportedFunctions").isJsonNull(), "pre-census cancellation invented census");
        Files.write(root.resolve("failure-diagnostics-controls/direct-cancellation.stderr"), capture.stderr());
    }

    private static void listingCancelledCollection(Program program) throws Exception {
        Path destination = root.resolve("listing-cancelled-inferred");
        Map<Path, String> modelBefore = snapshots(root.resolve("reports")), listingBefore = snapshots(listing);
        long modification = program.getModificationNumber();
        ghidra.util.exception.CancelledException original = new ghidra.util.exception.CancelledException("authored listing cancellation");
        boolean[] comparisonObserved = {false};
        boolean[] emittedBeforeCleanup = {false};
        TaskMonitorAdapter monitor = new TaskMonitorAdapter(true) {
            @Override public void checkCancelled() throws ghidra.util.exception.CancelledException {
                super.checkCancelled();
                // This authored monitor uses the real collector's existing callback. No
                // production observer or time override is introduced to force this boundary.
                if (Files.isDirectory(destination.resolve("listing-comparison"), LinkOption.NOFOLLOW_LINKS)) {
                    comparisonObserved[0] = true;
                    throw original;
                }
            }
        };
        CapturedRun capture = captureStderr(() -> ExportInferredInterfacesV1.collect(program, monitor, collectorArguments(destination)), () -> {
            Path comparison = destination.resolve("listing-comparison");
            // Observe at the first stderr prefix, before the throwing monitor returns to
            // the listing collector's finally block. This is only a fixture stream sink.
            if (Files.isDirectory(comparison, LinkOption.NOFOLLOW_LINKS)) {
                try (var files = Files.list(comparison)) {
                    Set<String> names = new HashSet<>(files.map(path -> path.getFileName().toString()).toList());
                    emittedBeforeCleanup[0] = names.stream().anyMatch(name -> name.startsWith(".native-interfaces-")) &&
                        names.stream().anyMatch(name -> name.startsWith(".native-interface-types-"));
                } catch (java.io.IOException ignored) { emittedBeforeCleanup[0] = false; }
            }
        });
        require(comparisonObserved[0] && capture.failure() == original, "listing cancellation exception/order changed");
        require(emittedBeforeCleanup[0], "listing cancellation diagnostic was emitted only after listing cleanup");
        JsonObject frame = onlyFailureFrame(capture);
        equal(text(frame, "stage"), "listing-comparison", "first listing owner stage");
        equal(text(frame, "failureKind"), "cancellation-observed", "listing monitor cancellation classification");
        require(frame.getAsJsonObject("census").get("validated").getAsBoolean(), "listing cancellation lost validated census");
        equal(frame.getAsJsonObject("counts").get("nativeCallsStarted").getAsLong(), 0L, "listing cancellation started native work");
        require(!Files.exists(destination, LinkOption.NOFOLLOW_LINKS), "listing cancellation left comparison/inferred/manifest output");
        require(program.getModificationNumber() == modification && modelBefore.equals(snapshots(root.resolve("reports"))) &&
            listingBefore.equals(snapshots(listing)), "listing cancellation changed frozen observations");
        Files.write(root.resolve("failure-diagnostics-controls/listing-cancellation.stderr"), capture.stderr());
        JsonObject receipt = new JsonObject();
        receipt.addProperty("kind", "authored-inferred-listing-cancellation-control-v1");
        receipt.addProperty("fixtureOnly", true);
        receipt.addProperty("actualListingBridgeObserved", comparisonObserved[0]);
        receipt.addProperty("emittedBeforeListingCleanup", emittedBeforeCleanup[0]);
        receipt.addProperty("originalExceptionPreserved", capture.failure() == original);
        receipt.addProperty("completeFrozenCensusRetained", true);
        receipt.addProperty("outputAndComparisonAbsent", true);
        receipt.addProperty("frozenInputsAndProgramUnchanged", true);
        receipt.addProperty("productionInterfacesAdmitted", false);
        Files.writeString(root.resolve("failure-diagnostics-controls/listing-cancellation.json"), receipt + "\n");
    }

    @FunctionalInterface private interface CheckedAction { void run() throws Exception; }
    private record CapturedRun(Throwable failure, byte[] stderr) {}

    private static CapturedRun captureStderr(CheckedAction action) throws Exception {
        return captureStderr(action, () -> {});
    }

    private static CapturedRun captureStderr(CheckedAction action, Runnable firstDiagnostic) throws Exception {
        PrintStream previous = System.err;
        ByteArrayOutputStream retained = new ByteArrayOutputStream();
        boolean[] overflow = {false};
        boolean[] observed = {false};
        OutputStream tee = new OutputStream() {
            private void observe() {
                if (!observed[0] && retained.toString(StandardCharsets.UTF_8).contains("DECOMP_INFERRED_FAILURE_V1 ")) {
                    observed[0] = true;
                    firstDiagnostic.run();
                }
            }
            @Override public void write(int value) {
                previous.write(value);
                if (retained.size() < 1024 * 1024) retained.write(value); else overflow[0] = true;
                observe();
            }
            @Override public void write(byte[] bytes, int offset, int length) {
                previous.write(bytes, offset, length);
                int count = Math.min(length, 1024 * 1024 - retained.size());
                retained.write(bytes, offset, count);
                if (count != length) overflow[0] = true;
                observe();
            }
            @Override public void flush() { previous.flush(); }
        };
        Throwable failure = null;
        PrintStream capture = new PrintStream(tee, true, StandardCharsets.UTF_8);
        try {
            System.setErr(capture);
            try { action.run(); } catch (Throwable problem) { failure = problem; }
        } finally {
            capture.flush();
            System.setErr(previous);
        }
        require(!overflow[0], "authored complete stderr fixture exceeded finite capture bound");
        return new CapturedRun(failure, retained.toByteArray());
    }

    private static void collectSilently(Program program, Path destination) throws Exception {
        CapturedRun capture = captureStderr(() -> ExportInferredInterfacesV1.collect(program, MONITOR, collectorArguments(destination)));
        if (capture.failure() instanceof Exception problem) throw problem;
        if (capture.failure() instanceof Error problem) throw problem;
        require(capture.failure() == null && !new String(capture.stderr(), StandardCharsets.UTF_8).contains("DECOMP_INFERRED_FAILURE_V1 "),
            "successful inference emitted a failure diagnostic");
    }

    private static JsonObject onlyFailureFrame(CapturedRun capture) {
        String prefix = "DECOMP_INFERRED_FAILURE_V1 ";
        String stderr = new String(capture.stderr(), StandardCharsets.UTF_8);
        List<String> frames = stderr.lines().filter(line -> line.startsWith(prefix)).toList();
        require(frames.size() == 1 && stderr.endsWith("\n"), "authored whole-stream capture must contain one complete diagnostic");
        String frame = frames.get(0);
        require((frame + "\n").getBytes(StandardCharsets.UTF_8).length <= 4096, "failure frame exceeded byte ceiling");
        JsonObject result = JsonParser.parseString(frame.substring(prefix.length())).getAsJsonObject();
        equal(text(result, "authority"), "diagnostic-only", "failure diagnostic authority");
        require(!result.get("complete").getAsBoolean() && !result.get("productionInterfacesAdmitted").getAsBoolean() &&
            !result.get("releaseEligible").getAsBoolean(), "failure diagnostic invented success authority");
        return result;
    }

    private static void changingProgramCollection(ProgramDB program, Function function) throws Exception {
        Path destination = root.resolve("changed-program-inferred");
        String originalName = function.getName();
        SourceType originalSource = function.getSymbol().getSource();
        int originalCensus = program.getFunctionManager().getFunctionCount();
        boolean[] changed = {false};
        TaskMonitorAdapter monitor = new TaskMonitorAdapter(true) {
            @Override public void checkCancelled() throws ghidra.util.exception.CancelledException {
                super.checkCancelled();
                boolean outputStagePresent = false;
                if (Files.isDirectory(destination, LinkOption.NOFOLLOW_LINKS)) {
                    try (var entries = Files.list(destination)) {
                        outputStagePresent = entries.anyMatch(path -> path.getFileName().toString().startsWith(".inferred-"));
                    } catch (java.io.IOException failure) { throw new AssertionError(failure); }
                }
                // The stage is created only after the exact listing replay comparison. This
                // exercises the Program guard, not merely the stale-listing refusal above it.
                if (!changed[0] && outputStagePresent) {
                    changed[0] = true;
                    int transaction = program.startTransaction("same-census mutation during inference");
                    try { function.setName(originalName + "_during_inference", SourceType.USER_DEFINED); }
                    catch (Exception failure) { throw new AssertionError(failure); }
                    finally { program.endTransaction(transaction, true); }
                    require(program.getFunctionManager().getFunctionCount() == originalCensus, "mutation changed function census");
                }
            }
        };
        boolean rejected = false;
        try {
            try { ExportInferredInterfacesV1.collect(program, monitor, collectorArguments(destination)); }
            catch (IllegalStateException expected) {
                require(expected.getMessage() != null && expected.getMessage().contains("Program changed"),
                    "late same-census control failed for an unrelated reason: " + expected);
                rejected = true;
            }
            require(changed[0] && rejected && !Files.exists(destination), "same-census Program mutation accepted or left partial capture");
        } finally {
            if (changed[0]) {
                int transaction = program.startTransaction("restore authored function name");
                try { function.setName(originalName, originalSource); }
                finally { program.endTransaction(transaction, true); }
            }
        }
    }

    private static void changedListingCollection(Program program) throws Exception {
        Path changed = root.resolve("changed-listing");
        Files.createDirectory(changed);
        byte[] observations = Files.readAllBytes(listing.resolve("native-interfaces.json"));
        // Same byte count and syntactically valid bytes, but no longer the exact native snapshot.
        String text = new String(observations, java.nio.charset.StandardCharsets.UTF_8);
        require(text.contains("integer_add"), "listing mutation target missing");
        Files.writeString(changed.resolve("native-interfaces.json"), text.replace("integer_add", "integer_bad"));
        Files.copy(listing.resolve("manifest.json"), changed.resolve("manifest.json"));
        Path destination = root.resolve("changed-listing-inferred");
        String[] arguments = collectorArguments(destination);
        arguments[9] = changed.toString();
        boolean rejected = false;
        try { ExportInferredInterfacesV1.collect(program, MONITOR, arguments); }
        catch (IllegalArgumentException | IllegalStateException expected) { rejected = true; }
        require(rejected && !Files.exists(destination), "changed frozen listing accepted or left partial capture");
    }

    private static void stagingBudgetControls(ProgramDB program, Function function) throws Exception {
        final long manifestReservation = 65536;
        final long generousBudget = 4L * 1024 * 1024;
        Path evidence = Files.createDirectory(root.resolve("staging-budget-controls"));
        Map<Path, String> originalModel = snapshots(root.resolve("reports"));
        Map<Path, String> originalListing = snapshots(listing);
        long modification = program.getModificationNumber();
        Path measured = evidence.resolve("measured-listing");
        long peak = ExportNativeInterfacesV1.collectWithStagingBudget(program, MONITOR, listingArguments(measured), generousBudget);
        long finalListingBytes = Files.size(measured.resolve("native-interfaces.json"));
        long finalManifestBytes = Files.size(measured.resolve("manifest.json"));
        require(peak > finalListingBytes + manifestReservation && peak < generousBudget,
            "authored listing does not exercise overlapping output and type-spool storage");
        Path exact = evidence.resolve("exact-peak-listing");
        long repeatedPeak = ExportNativeInterfacesV1.collectWithStagingBudget(program, MONITOR, listingArguments(exact), peak);
        equal(repeatedPeak, peak, "exact permitted staging peak");
        for (String file : List.of("native-interfaces.json", "manifest.json")) {
            require(Arrays.equals(Files.readAllBytes(listing.resolve(file)), Files.readAllBytes(measured.resolve(file))) &&
                Arrays.equals(Files.readAllBytes(measured.resolve(file)), Files.readAllBytes(exact.resolve(file))),
                "bounded staging changed ordinary listing wire bytes: " + file);
        }
        Path below = evidence.resolve("one-below-peak-listing");
        java.io.IOException belowFailure = null;
        try { ExportNativeInterfacesV1.collectWithStagingBudget(program, MONITOR, listingArguments(below), peak - 1); }
        catch (java.io.IOException expected) { belowFailure = expected; }
        require(belowFailure != null && belowFailure.getMessage() != null &&
            belowFailure.getMessage().contains("while output and type spool are live"),
            "one-byte-below peak did not fail during coexisting bounded output/spool writes");
        require(!Files.exists(below, LinkOption.NOFOLLOW_LINKS), "one-byte-below peak left partial listing or manifest");
        require(program.getModificationNumber() == modification, "bounded listing control mutated native Program");
        require(originalModel.equals(snapshots(root.resolve("reports"))) && originalListing.equals(snapshots(listing)),
            "bounded staging changed frozen inputs");

        JsonObject receipt = new JsonObject();
        receipt.addProperty("kind", "authored-native-interface-staging-budget-control-v1");
        receipt.addProperty("fixtureOnly", true);
        receipt.addProperty("manifestReservationBytes", manifestReservation);
        receipt.addProperty("measuredChargedPeakBytes", peak);
        receipt.addProperty("exactLimitBytes", peak);
        receipt.addProperty("exactObservedPeakBytes", repeatedPeak);
        receipt.addProperty("finalListingBytes", finalListingBytes);
        receipt.addProperty("finalManifestBytes", finalManifestBytes);
        receipt.addProperty("belowLimitBytes", peak - 1);
        receipt.addProperty("belowFailure", belowFailure.getMessage());
        receipt.addProperty("belowRejectedWithOutputAndSpoolLive", true);
        receipt.addProperty("belowOutputRemoved", true);
        receipt.addProperty("boundedOutputMatchesOrdinaryBytes", true);
        receipt.addProperty("authoritativeOracleEvidence", false);
        receipt.addProperty("productionInterfacesAdmitted", false);
        receipt.addProperty("releaseEligible", false);

        // The original model/listing remain frozen. Only the actual Program signature becomes
        // larger, so the inferred collector must budget the actual rerender before its later
        // equality check can reject stale listing bytes. Rollback restores the fixture afterward.
        int originalParameterCount = function.getParameterCount();
        SourceType originalSignatureSource = function.getSignatureSource();
        int transaction = program.startTransaction("authored larger actual listing than frozen sibling");
        try {
            List<Variable> parameters = new ArrayList<>();
            for (int index = 0; index < 64; index++) parameters.add(new ParameterImpl("large_parameter_" + index,
                UnsignedLongLongDataType.dataType, program, SourceType.USER_DEFINED));
            function.updateFunction("__stdcall", new ReturnParameterImpl(UnsignedLongLongDataType.dataType, program), parameters,
                Function.FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS, true, SourceType.USER_DEFINED);
            require(function.getParameterCount() == 64, "authored larger listing signature missing");
            Path larger = evidence.resolve("larger-current-listing");
            long largerPeak = ExportNativeInterfacesV1.collectWithStagingBudget(program, MONITOR, listingArguments(larger), generousBudget);
            long largerFinalBytes = Files.size(larger.resolve("native-interfaces.json"));
            require(largerFinalBytes > finalListingBytes, "actual rerender must be larger than frozen listing");
            long available = Math.addExact(largerFinalBytes, manifestReservation);
            require(available < largerPeak, "stale listing control must distinguish final bytes from transient peak");
            long frozenInputBytes = Math.addExact(Files.size(model), Math.addExact(
                Files.size(listing.resolve("native-interfaces.json")), Files.size(listing.resolve("manifest.json"))));
            long combinedLimit = Math.addExact(frozenInputBytes, available);
            require(combinedLimit < generousBudget, "authored inferred control is not a small budget");
            Path destination = evidence.resolve("stale-smaller-inferred");
            CapturedRun staleCapture = captureStderr(() ->
                ExportInferredInterfacesV1.collectWithByteLimit(program, MONITOR, collectorArguments(destination), combinedLimit));
            java.io.IOException staleFailure = staleCapture.failure() instanceof java.io.IOException failure ? failure : null;
            require(staleFailure != null && staleFailure.getMessage() != null &&
                staleFailure.getMessage().contains("while output and type spool are live"),
                "larger actual rerender was not refused during bounded staging writes before equality");
            require(!Files.exists(destination, LinkOption.NOFOLLOW_LINKS),
                "stale smaller listing left inferred output, comparison output or success manifest");
            JsonObject failureFrame = onlyFailureFrame(staleCapture);
            equal(text(failureFrame, "stage"), "listing-comparison", "staging failure stage");
            equal(failureFrame.getAsJsonObject("counts").get("nativeCallsStarted").getAsLong(), 0L,
                "staging refusal invented native call");
            Files.write(root.resolve("failure-diagnostics-controls/staging-refusal.stderr"), staleCapture.stderr());
            require(originalModel.equals(snapshots(root.resolve("reports"))) && originalListing.equals(snapshots(listing)),
                "stale listing control changed frozen inputs");
            receipt.addProperty("staleFrozenInputBytes", frozenInputBytes);
            receipt.addProperty("largerActualFinalListingBytes", largerFinalBytes);
            receipt.addProperty("largerActualChargedPeakBytes", largerPeak);
            receipt.addProperty("staleComparisonAvailableBytes", available);
            receipt.addProperty("staleCombinedLimitBytes", combinedLimit);
            receipt.addProperty("staleFailure", staleFailure.getMessage());
            receipt.addProperty("staleRejectedDuringBoundedWrites", true);
            receipt.addProperty("staleInferredAndComparisonRemoved", true);
            receipt.addProperty("frozenInputsUnchanged", true);
            receipt.addProperty("boundedFailureDiagnosticRetained", true);
            ownedComparisonStagingControls(program, largerPeak, largerFinalBytes, receipt);
        } finally { program.endTransaction(transaction, false); }
        require(function.getParameterCount() == originalParameterCount && function.getSignatureSource() == originalSignatureSource,
            "stale listing control did not restore original native signature");
        Files.writeString(evidence.resolve("verified-staging-controls.json"), receipt.toString() + "\n");
    }

    /** Compose the real enclosing reports accounting with the real comparison/spool writer. */
    private static void ownedComparisonStagingControls(ProgramDB program, long peak, long finalBytes, JsonObject receipt) throws Exception {
        Path reports = model.getParent();
        Path ownedListing = Files.createDirectory(reports.resolve("native-interfaces-v1"));
        Path padding = reports.resolve("program_model.json.export/owned-staging-control.pad");
        Path destination = reports.resolve("native-inferred-interfaces-v1");
        var byteLimit = RunBundledExports.class.getDeclaredMethod("interfaceByteLimit", Path.class, long.class, TaskMonitor.class);
        byteLimit.setAccessible(true);
        try {
            for (String name : List.of("native-interfaces.json", "manifest.json"))
                Files.copy(listing.resolve(name), ownedListing.resolve(name));
            long included = Math.addExact(Files.size(model), Math.addExact(
                Files.size(ownedListing.resolve("native-interfaces.json")), Files.size(ownedListing.resolve("manifest.json"))));
            long beforePadding = (long)byteLimit.invoke(null, reports, 0L, MONITOR);
            long paddingBytes = beforePadding - peak;
            require(paddingBytes > 0 && finalBytes + 65536 + 1 < peak,
                "owned staging control must fit final bytes but distinguish its transient peak");
            // Sparse logical bytes exercise the unchanged global limit without allocating a
            // near-GiB buffer or writing a near-GiB fixture. The pad is removed before snapshots.
            try (var pad = new java.io.RandomAccessFile(padding.toFile(), "rw")) {
                pad.setLength(paddingBytes);
                for (int over = 0; over <= 1; over++) {
                    pad.setLength(paddingBytes + over);
                    long combined = (long)byteLimit.invoke(null, reports, included, MONITOR);
                    equal(combined, included + peak - over, "owned inferred lower-only limit");
                    String[] arguments = collectorArguments(destination);
                    arguments[9] = ownedListing.toString();
                    CapturedRun capture = captureStderr(() ->
                        ExportInferredInterfacesV1.collectWithByteLimit(program, MONITOR, arguments, combined));
                    if (over == 0) {
                        // Exact peak must finish the comparison before the deliberately stale
                        // listing is refused. Neither case can reach a native decompiler call.
                        require(capture.failure() instanceof IllegalStateException &&
                            "listing snapshot does not match current native Program".equals(capture.failure().getMessage()),
                            "exact owned comparison peak did not reach the stale-content check");
                    } else {
                        require(capture.failure() instanceof java.io.IOException && capture.failure().getMessage() != null &&
                            capture.failure().getMessage().contains("while output and type spool are live"),
                            "one-over owned comparison did not refuse simultaneous output and spool");
                    }
                    require(!Files.exists(destination, LinkOption.NOFOLLOW_LINKS), "owned comparison left partial output");
                    equal(onlyFailureFrame(capture).getAsJsonObject("counts").get("nativeCallsStarted").getAsLong(),
                        0L, "owned staging controls must not start native calls");
                }
            }
            receipt.addProperty("ownedComparisonExactPeakReachedContentCheck", true);
            receipt.addProperty("ownedComparisonOneOverRejectedBeforeWrite", true);
            receipt.addProperty("ownedComparisonFinalBytesFitBothLimits", true);
            receipt.addProperty("ownedStreamReservationBytes", 2L * 64 * 1024 * 1024);
        } finally {
            Files.deleteIfExists(padding);
            Files.deleteIfExists(ownedListing.resolve("native-interfaces.json"));
            Files.deleteIfExists(ownedListing.resolve("manifest.json"));
            Files.deleteIfExists(ownedListing);
        }
    }

    private static String[] listingArguments(Path destination) throws Exception {
        return new String[] {sha256(input), sha256(modelSource), ARCHIVE_SHA, sha256(listingSource), model.toString(), destination.toString()};
    }

    private static String[] collectorArguments(Path destination) throws Exception {
        return new String[] {sha256(input), sha256(modelSource), ARCHIVE_SHA, sha256(listingSource), sha256(collectorSource),
            sha256(typeGraphSource), sha256(wrapperSource), sha256(nativeDecompiler), model.toString(), listing.toString(), destination.toString()};
    }

    private static String addressKey(JsonObject address) {
        return address.get("spaceIndex").getAsInt() + ":" + address.get("offsetBits").getAsString();
    }
    private static String addressKey(JsonObject document, Address address) {
        for (JsonElement element : document.getAsJsonArray("addressSpaces")) {
            JsonObject space = element.getAsJsonObject();
            if (text(space, "name").equals(address.getAddressSpace().getName())) {
                return space.get("index").getAsInt() + ":" + String.format("%016x", address.getOffset());
            }
        }
        throw new AssertionError("native address space absent: " + address.getAddressSpace());
    }

    private static byte[] hex(String value) { return HexFormat.of().parseHex(value.replace(" ", "")); }
    private static Address address(Program program, long offset) { return program.getAddressFactory().getDefaultAddressSpace().getAddress(offset); }
    private static String sha256(Path path) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(Files.readAllBytes(path)));
    }
    private static Map<Path, String> snapshots(Path directory) throws Exception {
        Map<Path, String> result = new TreeMap<>();
        try (var paths = Files.walk(directory)) {
            for (Path path : paths.filter(Files::isRegularFile).toList()) result.put(directory.relativize(path), sha256(path));
        }
        return result;
    }
    private static String text(JsonObject value, String name) { return value.get(name).getAsString(); }
    private static void equal(Object actual, Object expected, String message) {
        require(Objects.equals(actual, expected), message + ": actual=" + actual + ", expected=" + expected);
    }
    private static void require(boolean condition, String message) { if (!condition) throw new AssertionError(message); }
}
