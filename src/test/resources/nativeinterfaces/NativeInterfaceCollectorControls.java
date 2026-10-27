import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import ghidra.GhidraApplicationLayout;
import ghidra.app.script.GhidraState;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.framework.Application;
import ghidra.framework.HeadlessGhidraApplicationConfiguration;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.AbstractIntegerDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.Undefined;
import ghidra.program.model.data.Undefined8DataType;
import ghidra.program.model.data.UnsignedLongLongDataType;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.lang.CompilerSpecID;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.AutoParameterType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.ReturnParameterImpl;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.RefType;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;
import java.io.ByteArrayInputStream;
import java.io.PrintWriter;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/** Genuine bundled Ghidra objects with authored interfaces, never production oracle evidence. */
public final class NativeInterfaceCollectorControls {
    private static final TaskMonitor MONITOR = TaskMonitor.DUMMY;
    private static final String ARCHIVE_SHA = "93a5d11a9ad510622acaaf908c556a7b9b764d338e78a7567f3689bf5081fd54";
    private static Path root;
    private static Path collectorSource;
    private static Path modelSource;
    private static Path input;
    private static Path model;

    public static void main(String[] arguments) throws Exception {
        require(arguments.length == 4, "expected release root, control root, collector source, model exporter source");
        root = Path.of(arguments[1]).toAbsolutePath();
        collectorSource = Path.of(arguments[2]).toAbsolutePath();
        modelSource = Path.of(arguments[3]).toAbsolutePath();
        Files.createDirectories(root);
        require(Path.of("").toRealPath().equals(root.toRealPath()), "control cwd differs from owned root");
        Application.initializeApplication(new GhidraApplicationLayout(Path.of(arguments[0]).toFile()),
            new HeadlessGhidraApplicationConfiguration());
        require("12.1.3".equals(Application.getApplicationVersion()), "unexpected bundled Ghidra version");
        Language language = DefaultLanguageService.getLanguageService().getLanguage(new LanguageID("x86:LE:64:default"));
        Object consumer = new Object();
        ProgramDB program = new ProgramDB("authored-native-interfaces", language,
            language.getCompilerSpecByID(new CompilerSpecID("windows")), consumer);
        try {
            Map<String, Function> functions = createControls(program);
            assertNativeControls(program, functions);
            JsonObject document = exportTwice(program, functions);
            assertCapture(program, functions, document);
            globalTypeCapture(program);
            cancelledCollection(program);
            changingProgramCollection(program, functions.get("mixed_parameters"));
            Files.writeString(root.resolve("verified-controls.txt"),
                "genuine-windows64-ProgramDB dynamic-formal-effective forced-indirect automatic-this hidden-return " +
                "mixed-register-stack varargs unknown-convention default-unassessed undefined unassigned void " +
                "ordered-compound-storage external-inventory immediate-thunk-chain type-occurrences " +
                "deterministic model-unchanged program-unchanged stale-output-rejected cancellation " +
                "same-census-native-name-mutation-rejected\n");
        } finally {
            program.release(consumer);
        }
        System.out.println("native interface controls passed");
        System.exit(0);
    }

    private static Map<String, Function> createControls(ProgramDB program) throws Exception {
        byte[] bytes = new byte[0x200];
        Arrays.fill(bytes, (byte) 0xc3);
        input = root.resolve("synthetic-input.bin");
        Files.write(input, bytes);
        Map<String, Function> functions = new LinkedHashMap<>();
        int transaction = program.startTransaction("authored native interfaces");
        try {
            Address start = address(program, 0x1000);
            program.getMemory().createInitializedBlock("authored-interfaces", start,
                new ByteArrayInputStream(bytes), bytes.length, MONITOR, false).setExecute(true);
            program.setExecutablePath(input.toString());
            program.setExecutableSHA256(sha256(input));
            program.setExecutableFormat("authored x86-64 interface controls");
            StructureDataType struct24 = structure(program, "Aggregate24", 3);
            StructureDataType struct16 = structure(program, "Aggregate16", 2);

            Function dynamic = createFunction(program, functions, "dynamic_aggregate", 0x1000);
            dynamic.updateFunction("__thiscall", new ReturnParameterImpl(struct24, program),
                List.of(new ParameterImpl("aggregate", struct24, program, SourceType.USER_DEFINED)),
                Function.FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS, true, SourceType.USER_DEFINED);

            Function mixed = createFunction(program, functions, "mixed_parameters", 0x1010);
            List<Variable> six = new ArrayList<>();
            for (int index = 0; index < 6; index++) six.add(new ParameterImpl("value" + index,
                UnsignedLongLongDataType.dataType, program, SourceType.USER_DEFINED));
            mixed.updateFunction("__fastcall", new ReturnParameterImpl(IntegerDataType.dataType, program), six,
                Function.FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS, true, SourceType.USER_DEFINED);
            mixed.setVarArgs(true);

            Function unknown = createFunction(program, functions, "unknown_undefined", 0x1020);
            unknown.updateFunction(Function.UNKNOWN_CALLING_CONVENTION_STRING,
                new ReturnParameterImpl(Undefined8DataType.dataType, VariableStorage.UNASSIGNED_STORAGE, program),
                List.of(new ParameterImpl(null, Undefined8DataType.dataType, VariableStorage.UNASSIGNED_STORAGE,
                    program, SourceType.DEFAULT)),
                Function.FunctionUpdateType.CUSTOM_STORAGE, true, SourceType.DEFAULT);

            Function defaults = createFunction(program, functions, "default_unassessed", 0x1030);
            defaults.setCallingConvention(Function.DEFAULT_CALLING_CONVENTION_STRING);

            Function split = createFunction(program, functions, "split_storage", 0x1040);
            // Ghidra's ordered compound varnodes put the non-register piece first on little endian.
            VariableStorage storage = new VariableStorage(program,
                new Varnode(program.getAddressFactory().getStackSpace().getAddress(0x28), 8),
                new Varnode(program.getRegister("R10").getAddress(), 8));
            split.updateFunction("__fastcall",
                new ReturnParameterImpl(UnsignedLongLongDataType.dataType, program.getRegister("RAX"), program),
                List.of(new ParameterImpl("split", struct16, storage, program, SourceType.USER_DEFINED)),
                Function.FunctionUpdateType.CUSTOM_STORAGE, true, SourceType.USER_DEFINED);

            Function voidResult = createFunction(program, functions, "void_result", 0x1050);
            voidResult.updateFunction("__fastcall", new ReturnParameterImpl(VoidDataType.dataType, program),
                List.of(), Function.FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS, true, SourceType.USER_DEFINED);

            Function external = program.getExternalManager().addExtFunction("authored-interface-library",
                "external_interface", null, SourceType.IMPORTED).getFunction();
            require(external != null, "external function creation failed");
            external.updateFunction("__fastcall", new ReturnParameterImpl(IntegerDataType.dataType, program),
                List.of(new ParameterImpl("external_value", UnsignedLongLongDataType.dataType, program, SourceType.IMPORTED)),
                Function.FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS, true, SourceType.IMPORTED);
            functions.put("external_interface", external);
            Function inner = createFunction(program, functions, "thunk_inner", 0x1060);
            inner.setThunkedFunction(external);
            Function outer = createFunction(program, functions, "thunk_outer", 0x1070);
            outer.setThunkedFunction(inner);
            program.getListing().createData(address(program, 0x1100), IntegerDataType.dataType);
            require(new DisassembleCommand(start, null, false).applyTo(program, MONITOR), "authored instruction missing");
            program.getReferenceManager().addMemoryReference(start, address(program, 0x1101), RefType.READ,
                SourceType.USER_DEFINED, 0);
            program.getReferenceManager().addMemoryReference(start, address(program, 0x1180), RefType.READ,
                SourceType.USER_DEFINED, 1);
            require(program.getListing().getDataContaining(address(program, 0x1180)) != null &&
                program.getListing().getDefinedDataContaining(address(program, 0x1180)) == null,
                "undefined-memory control does not distinguish the listing accessors");
        } finally {
            program.endTransaction(transaction, true);
        }
        return functions;
    }

    private static StructureDataType structure(Program program, String name, int words) {
        StructureDataType result = new StructureDataType(name, 0, program.getDataTypeManager());
        for (int index = 0; index < words; index++) result.add(UnsignedLongLongDataType.dataType, "word" + index, null);
        require(result.getLength() == words * 8 && !result.isNotYetDefined(), "authored aggregate layout changed");
        return result;
    }

    private static Function createFunction(Program program, Map<String, Function> functions, String name, long offset)
            throws Exception {
        Address entry = address(program, offset);
        Function function = program.getFunctionManager().createFunction(name, entry, new AddressSet(entry), SourceType.USER_DEFINED);
        require(function != null, "authored function creation failed: " + name);
        functions.put(name, function);
        return function;
    }

    private static void assertNativeControls(Program program, Map<String, Function> functions) {
        Function dynamic = functions.get("dynamic_aggregate");
        require(!dynamic.hasCustomVariableStorage() && dynamic.getParameterCount() == 3 && dynamic.getAutoParameterCount() == 2,
            "dynamic aggregate did not create two genuine auto parameters");
        Parameter[] parameters = dynamic.getParameters();
        require(parameters[0].isAutoParameter() && parameters[0].getAutoParameterType() == AutoParameterType.THIS,
            "native this parameter missing");
        require(parameters[1].isAutoParameter() && parameters[1].getAutoParameterType() == AutoParameterType.RETURN_STORAGE_PTR,
            "native hidden return parameter missing");
        requireRegister(parameters[0], "RCX");
        requireRegister(parameters[1], "RDX");
        requireRegister(parameters[2], "R8");
        requireRegister(dynamic.getReturn(), "RAX");
        for (Parameter parameter : List.of(parameters[2], dynamic.getReturn())) {
            require(parameter.isForcedIndirect() && parameter.getFormalDataType() instanceof Structure &&
                parameter.getFormalDataType().getLength() == 24 && parameter.getDataType() instanceof Pointer &&
                parameter.getDataType().getLength() == 8, "native formal/effective aggregate distinction missing");
        }
        Function mixed = functions.get("mixed_parameters");
        require(mixed.hasVarArgs() && mixed.getParameterCount() == 6 && mixed.getAutoParameterCount() == 0,
            "authored variadic interface changed");
        for (int index = 0; index < 4; index++) requireRegister(mixed.getParameter(index), List.of("RCX", "RDX", "R8", "R9").get(index));
        require(mixed.getParameter(4).getStackOffset() == 40 && mixed.getParameter(5).getStackOffset() == 48,
            "native stack parameters missing");
        Function unknown = functions.get("unknown_undefined");
        require(unknown.getCallingConventionName().equals(Function.UNKNOWN_CALLING_CONVENTION_STRING) &&
            unknown.getCallingConvention() == null && unknown.getParameter(0).getVariableStorage().isUnassignedStorage() &&
            Undefined.isUndefined(unknown.getParameter(0).getDataType()), "unknown/undefined control not retained natively");
        Function defaults = functions.get("default_unassessed");
        require(defaults.getSignatureSource() == SourceType.DEFAULT && defaults.getParameterCount() == 0 && !defaults.hasVarArgs() &&
            Undefined.isUndefined(defaults.getReturnType()), "default raw interface control changed");
        Varnode[] pieces = functions.get("split_storage").getParameter(0).getVariableStorage().getVarnodes();
        require(pieces.length == 2 && pieces[0].getAddress().isStackAddress() && pieces[0].getOffset() == 0x28 &&
            pieces[1].getAddress().equals(program.getRegister("R10").getAddress()), "native compound storage order changed");
        require(functions.get("void_result").getReturn().getVariableStorage().isVoidStorage(), "native void storage missing");
        require(functions.get("external_interface").isExternal(), "external inventory control is not external");
        require(functions.get("thunk_outer").getThunkedFunction(false).equals(functions.get("thunk_inner")),
            "native immediate thunk chain changed");
        // Bundled 12.1.3 FunctionDB.getAutoParameterCount delegates thunk calls to the
        // target's total parameter count. Preserve the raw getter and the actual flags.
        for (String name : List.of("thunk_inner", "thunk_outer")) {
            Function thunk = functions.get(name);
            require(thunk.getAutoParameterCount() == 1 &&
                Arrays.stream(thunk.getParameters()).noneMatch(Parameter::isAutoParameter),
                "pinned native thunk raw-count/parameter-flag discrepancy changed");
        }
        require(program.getFunctionManager().getFunctionCount() == functions.size(), "authored function census changed");
    }

    private static JsonObject exportTwice(Program program, Map<String, Function> functions) throws Exception {
        Path reports = Files.createDirectory(root.resolve("reports"));
        model = reports.resolve("program_model.json");
        ExportProgramModel exporter = new ExportProgramModel();
        exporter.setScriptArgs(new String[] {sha256(modelSource), ARCHIVE_SHA, "planning", model.toString()});
        exporter.execute(new GhidraState(null, null, program, null, null, null), MONITOR, new PrintWriter(System.out, true));
        require(Files.size(model) > 0, "genuine planning model export is missing");
        JsonObject properties = new JsonObject();
        properties.addProperty("languageId", program.getLanguageID().getIdAsString());
        properties.addProperty("compilerSpecId", program.getCompilerSpec().getCompilerSpecID().getIdAsString());
        properties.addProperty("imageBaseSpace", program.getImageBase().getAddressSpace().getName());
        properties.addProperty("imageBaseOffsetBits", String.format("%016x", program.getImageBase().getOffset()));
        properties.addProperty("inputSha256", sha256(input));
        properties.addProperty("modelSha256", sha256(model));
        properties.addProperty("modelBytes", Files.size(model));
        properties.addProperty("functions", functions.size());
        properties.addProperty("internalFunctions", functions.values().stream().filter(f -> !f.isExternal()).count());
        properties.addProperty("externalFunctions", functions.values().stream().filter(Function::isExternal).count());
        properties.addProperty("thunks", functions.values().stream().filter(Function::isThunk).count());
        properties.addProperty("fixtureOnly", true);
        Files.writeString(root.resolve("native-properties.json"), properties.toString());
        Map<Path, String> preserved = snapshots(reports);
        long modification = program.getModificationNumber();
        Path first = root.resolve("first-native");
        Path second = root.resolve("second-native");
        ExportNativeInterfacesV1.collect(program, MONITOR, collectorArguments(first));
        require(program.getModificationNumber() == modification, "collector mutated native Program");
        require(preserved.equals(snapshots(reports)), "collector changed paired model/progress/checkpoints");
        ExportNativeInterfacesV1.collect(program, MONITOR, collectorArguments(second));
        require(program.getModificationNumber() == modification, "repeated collector mutated native Program");
        require(preserved.equals(snapshots(reports)), "repeated collector changed paired model/progress/checkpoints");
        for (String name : List.of("manifest.json", "native-interfaces.json")) {
            require(Arrays.equals(Files.readAllBytes(first.resolve(name)), Files.readAllBytes(second.resolve(name))),
                "nondeterministic collector bytes: " + name);
        }
        Map<Path, String> original = snapshots(first);
        boolean rejected = false;
        try { ExportNativeInterfacesV1.collect(program, MONITOR, collectorArguments(first)); }
        catch (Exception expected) { rejected = true; }
        require(rejected && original.equals(snapshots(first)), "existing output accepted or changed");
        return JsonParser.parseString(Files.readString(first.resolve("native-interfaces.json"))).getAsJsonObject();
    }

    private static void assertCapture(Program program, Map<String, Function> functions, JsonObject document) {
        Map<String, Function> expected = new HashMap<>();
        for (Function function : functions.values()) expected.put(addressKey(document, function.getEntryPoint()), function);
        Map<Integer, JsonObject> types = new HashMap<>();
        for (JsonElement element : document.getAsJsonArray("records")) {
            JsonObject record = element.getAsJsonObject();
            if (text(record, "recordKind").equals("type")) require(types.put(record.get("ordinal").getAsInt(), record) == null, "duplicate type occurrence");
        }
        int nextType = 0;
        long parameterCount = 0, autoCount = 0, varnodeCount = 0, functionCount = 0;
        HashSet<String> seen = new HashSet<>();
        for (JsonElement element : document.getAsJsonArray("records")) {
            JsonObject record = element.getAsJsonObject();
            if (!text(record, "recordKind").equals("function")) continue;
            String key = addressKey(record.getAsJsonObject("entry"));
            require(seen.add(key) && expected.containsKey(key), "duplicate or unexpected function entry");
            Function function = expected.get(key);
            functionCount++;
            equal(text(record, "name"), function.getName(), "function name");
            equal(record.get("isExternal").getAsBoolean(), function.isExternal(), "external flag");
            equal(record.get("isThunk").getAsBoolean(), function.isThunk(), "thunk flag");
            Function target = function.isThunk() ? function.getThunkedFunction(false) : null;
            if (target == null) require(record.get("immediateThunkTarget").isJsonNull(), "invented thunk target");
            else equal(addressKey(record.getAsJsonObject("immediateThunkTarget")), addressKey(document, target.getEntryPoint()), "immediate thunk target");
            equal(text(record, "signatureSource"), function.getSignatureSource().name(), "signature source");
            JsonObject convention = record.getAsJsonObject("convention");
            equal(text(convention, "name"), function.getCallingConventionName(), "raw convention");
            String resolved = function.getCallingConvention() == null ? null : function.getCallingConvention().getName();
            nullableText(convention.get("resolvedModel"), resolved, "resolved convention model");
            String state = function.getCallingConventionName().equals(Function.UNKNOWN_CALLING_CONVENTION_STRING) ? "unknown" :
                function.getCallingConventionName().equals(Function.DEFAULT_CALLING_CONVENTION_STRING) ? "default" :
                resolved == null ? "named-unresolved" : "named-resolved";
            equal(text(convention, "state"), state, "convention state");
            equal(record.get("varArgs").getAsBoolean(), function.hasVarArgs(), "raw varargs");
            equal(record.get("customStorage").getAsBoolean(), function.hasCustomVariableStorage(), "custom storage");
            equal(record.get("parameterCount").getAsInt(), function.getParameterCount(), "raw parameter count");
            equal(record.get("autoParameterCount").getAsInt(), function.getAutoParameterCount(), "auto parameter count");
            equal(text(record, "highFunction"), "not-captured", "high function scope");
            nextType = assertParameter(document, record.getAsJsonObject("return"), function.getReturn(), types, nextType);
            varnodeCount += function.getReturn().getVariableStorage().getVarnodes().length;
            Parameter[] parameters = function.getParameters();
            equal(record.getAsJsonArray("parameters").size(), parameters.length, "parameter array count");
            for (int index = 0; index < parameters.length; index++) {
                nextType = assertParameter(document, record.getAsJsonArray("parameters").get(index).getAsJsonObject(), parameters[index], types, nextType);
                varnodeCount += parameters[index].getVariableStorage().getVarnodes().length;
            }
            if (function.isThunk()) {
                require(record.get("autoParameterCount").getAsInt() == 1 &&
                    record.getAsJsonArray("parameters").size() == 1 &&
                    !record.getAsJsonArray("parameters").get(0).getAsJsonObject().get("autoParameter").getAsBoolean(),
                    "capture normalized away the native thunk raw-count/parameter-flag discrepancy");
            }
            parameterCount += parameters.length;
            autoCount += Arrays.stream(parameters).filter(Parameter::isAutoParameter).count();
        }
        equal(seen, expected.keySet(), "complete internal/external/thunk inventory");
        equal(nextType, types.size(), "every type occurrence referenced exactly once");
        JsonObject summary = document.getAsJsonObject("summary");
        equal(text(summary, "coverage"), "all-currently-listed-internal-and-external-functions", "coverage");
        equal(summary.get("functions").getAsLong(), functionCount, "function census");
        equal(summary.get("internalFunctions").getAsLong(), 8L, "internal census");
        equal(summary.get("externalFunctions").getAsLong(), 1L, "external census");
        equal(summary.get("thunks").getAsLong(), 2L, "thunk census");
        equal(summary.get("parameters").getAsLong(), parameterCount, "parameter census");
        equal(summary.get("autoParameters").getAsLong(), autoCount, "auto parameter census");
        equal(summary.get("types").getAsInt(), types.size(), "type occurrence census");
        equal(summary.get("storageVarnodes").getAsLong(), varnodeCount, "varnode census");
        for (String field : List.of("highFunction", "typeClosure", "abiClassification")) equal(text(summary, field), "not-captured", field);
        // A default zero count / false varargs is retained as native data, never promoted to known ABI.
        require(!summary.has("scored") && !summary.has("abiEquivalent") && !summary.has("releaseEligible"), "invented ABI assessment");
        require(types.values().stream().anyMatch(t -> text(t, "kind").equals("structure")), "formal aggregate type lost");
        require(types.values().stream().anyMatch(t -> text(t, "kind").equals("pointer")), "effective pointer type lost");
        require(types.values().stream().anyMatch(t -> text(t, "kind").equals("undefined") && t.get("undefined").getAsBoolean()), "undefined type lost");
        require(types.values().stream().anyMatch(t -> text(t, "kind").equals("void")), "void type lost");
    }

    private static int assertParameter(JsonObject document, JsonObject record, Parameter parameter,
            Map<Integer, JsonObject> types, int nextType) {
        equal(record.get("ordinal").getAsInt(), parameter.getOrdinal(), "parameter ordinal");
        nullableText(record.get("name"), parameter.getName(), "parameter name");
        nullableText(record.get("source"), parameter.getSource() == null ? null : parameter.getSource().name(), "parameter source");
        equal(record.get("autoParameter").getAsBoolean(), parameter.isAutoParameter(), "auto parameter");
        nullableText(record.get("autoParameterType"), parameter.getAutoParameterType() == null ? null : parameter.getAutoParameterType().name(), "auto parameter type");
        equal(record.get("forcedIndirect").getAsBoolean(), parameter.isForcedIndirect(), "forced indirect");
        for (String field : List.of("formalType", "effectiveType")) {
            int ordinal = record.get(field).getAsInt();
            equal(ordinal, nextType++, "sequential unique type occurrence");
            JsonObject type = types.get(ordinal);
            require(type != null, "type reference not present");
            DataType nativeType = field.equals("formalType") ? parameter.getFormalDataType() : parameter.getDataType();
            equal(text(type, "nativeClass"), nativeType.getClass().getName(), "datatype native class");
            equal(text(type, "name"), nativeType.getName(), "datatype name");
            equal(text(type, "path"), nativeType.getPathName(), "datatype path");
            equal(type.get("length").getAsInt(), nativeType.getLength(), "datatype length");
            equal(type.get("alignedLength").getAsInt(), nativeType.getAlignedLength(), "datatype aligned length");
            equal(type.get("alignment").getAsInt(), nativeType.getAlignment(), "datatype alignment");
            equal(type.get("undefined").getAsBoolean(), Undefined.isUndefined(nativeType), "datatype undefined");
            equal(type.get("notYetDefined").getAsBoolean(), nativeType.isNotYetDefined(), "datatype definition state");
            nullableText(type.get("signedness"), nativeType instanceof AbstractIntegerDataType integer ?
                integer.isSigned() ? "signed" : "unsigned" : null, "datatype signedness");
            if (nativeType instanceof AbstractIntegerDataType) equal(text(type, "kind"), "integer", "integer datatype kind");
            equal(text(type, "layout"), "not-captured", "layout scope");
            equal(text(type, "typeClosure"), "not-captured", "type closure scope");
            if (parameter.isForcedIndirect()) equal(text(type, "kind"), field.equals("formalType") ? "structure" : "pointer", "formal/effective kind");
        }
        JsonObject storage = record.getAsJsonObject("storage");
        VariableStorage nativeStorage = parameter.getVariableStorage();
        String state = nativeStorage.isBadStorage() ? "bad" : nativeStorage.isUnassignedStorage() ? "unassigned" :
            nativeStorage.isVoidStorage() ? "void" : "assigned";
        equal(text(storage, "state"), state, "storage state");
        equal(storage.get("size").getAsInt(), nativeStorage.size(), "storage size");
        equal(storage.get("autoStorage").getAsBoolean(), nativeStorage.isAutoStorage(), "auto storage");
        nullableText(storage.get("autoParameterType"), nativeStorage.getAutoParameterType() == null ? null : nativeStorage.getAutoParameterType().name(), "storage auto type");
        equal(storage.get("forcedIndirect").getAsBoolean(), nativeStorage.isForcedIndirect(), "storage forced indirect");
        Varnode[] varnodes = nativeStorage.getVarnodes();
        equal(storage.getAsJsonArray("varnodes").size(), varnodes.length, "storage varnode count");
        for (int index = 0; index < varnodes.length; index++) {
            JsonObject node = storage.getAsJsonArray("varnodes").get(index).getAsJsonObject();
            equal(addressKey(node.getAsJsonObject("address")), addressKey(document, varnodes[index].getAddress()), "ordered varnode address");
            equal(node.get("size").getAsInt(), varnodes[index].getSize(), "ordered varnode size");
        }
        return nextType;
    }

    private static void globalTypeCapture(Program program) throws Exception {
        String modelSha = sha256(model);
        long modification = program.getModificationNumber();
        Path first = root.resolve("global-types.ndjson");
        Path second = root.resolve("global-types-repeat.ndjson");
        ExportGlobalTypeObservationsV1.collect(program, MONITOR,
            new String[] {model.toString(), first.toString(), sha256(input), sha256(modelSource), ARCHIVE_SHA});
        ExportGlobalTypeObservationsV1.collect(program, MONITOR,
            new String[] {model.toString(), second.toString(), sha256(input), sha256(modelSource), ARCHIVE_SHA});
        require(Arrays.equals(Files.readAllBytes(first), Files.readAllBytes(second)), "global/type bytes are not deterministic");
        require(program.getModificationNumber() == modification && sha256(model).equals(modelSha),
            "global/type collector changed program or model");
        List<JsonObject> rows = Files.readAllLines(first).stream()
            .map(line -> JsonParser.parseString(line).getAsJsonObject()).toList();
        require(rows.get(0).get("functionCount").getAsInt() == 9, "global census omitted external function");
        require(rows.stream().filter(r -> text(r, "recordKind").equals("function-global-reference")).count() == 1,
            "defined interior data target was not resolved exactly once");
        require(rows.stream().filter(r -> text(r, "recordKind").equals("function-global-reference-unresolved") &&
            text(r, "reason").equals("no-defined-data-containing-target")).count() == 1,
            "undefined memory target must remain an unresolved observation");
    }

    private static void cancelledCollection(Program program) throws Exception {
        TaskMonitorAdapter cancelled = new TaskMonitorAdapter(true);
        cancelled.cancel();
        Path destination = root.resolve("cancelled-native");
        boolean rejected = false;
        try { ExportNativeInterfacesV1.collect(program, cancelled, collectorArguments(destination)); }
        catch (ghidra.util.exception.CancelledException expected) { rejected = true; }
        require(rejected && !Files.exists(destination.resolve("manifest.json")), "cancelled collector published success");
    }

    private static void changingProgramCollection(ProgramDB program, Function function) throws Exception {
        Path destination = root.resolve("changed-program-native");
        Map<Path, String> preservedModel = snapshots(root.resolve("reports"));
        String originalName = function.getName();
        String changedName = originalName + "_changed_during_capture";
        SourceType originalSource = function.getSymbol().getSource();
        int originalCensus = program.getFunctionManager().getFunctionCount();
        long originalModification = program.getModificationNumber();
        boolean[] triggered = {false};
        boolean[] mutated = {false};
        TaskMonitorAdapter changing = new TaskMonitorAdapter(true) {
            @Override public void checkCancelled() throws ghidra.util.exception.CancelledException {
                super.checkCancelled();
                // The collector has already frozen its initial Program identity and inventory
                // when its private output directory appears. Change an existing row, not census.
                if (!triggered[0] && Files.isDirectory(destination, java.nio.file.LinkOption.NOFOLLOW_LINKS)) {
                    triggered[0] = true;
                    int transaction = program.startTransaction("authored name mutation during interface capture");
                    boolean commit = false;
                    try {
                        function.setName(changedName, SourceType.USER_DEFINED);
                        commit = true;
                    } catch (Exception failure) {
                        throw new AssertionError("native name mutation control failed", failure);
                    } finally {
                        program.endTransaction(transaction, commit);
                    }
                    require(function.getName().equals(changedName), "native mutation did not change the function name");
                    require(program.getModificationNumber() != originalModification, "native mutation did not advance Program identity");
                    require(program.getFunctionManager().getFunctionCount() == originalCensus, "name mutation changed function census");
                    mutated[0] = true;
                }
            }
        };
        boolean rejected = false;
        try {
            try { ExportNativeInterfacesV1.collect(program, changing, collectorArguments(destination)); }
            catch (IllegalStateException expected) {
                require(expected.getMessage() != null && expected.getMessage().contains("native Program changed"),
                    "mutation control failed for an unrelated reason: " + expected);
                rejected = true;
            }
            require(triggered[0] && mutated[0], "mutation callback never changed the native Program during collection");
            require(rejected, "collector accepted a changed native Program with an unchanged function census");
            require(program.getFunctionManager().getFunctionCount() == originalCensus, "collector mutation control changed census");
            require(!Files.exists(destination.resolve("manifest.json")), "mutated Program capture published a success manifest");
            require(!Files.exists(destination), "mutated Program capture left a partial output directory");
            require(preservedModel.equals(snapshots(root.resolve("reports"))), "mutation control changed the paired model artifacts");
        } finally {
            if (mutated[0]) {
                int transaction = program.startTransaction("restore authored interface control name");
                boolean commit = false;
                try {
                    function.setName(originalName, originalSource);
                    commit = true;
                } finally {
                    program.endTransaction(transaction, commit);
                }
            }
        }
        require(function.getName().equals(originalName), "mutation control did not restore the native function name");
    }

    private static String[] collectorArguments(Path output) throws Exception {
        return new String[] {sha256(input), sha256(modelSource), ARCHIVE_SHA, sha256(collectorSource), model.toString(), output.toString()};
    }

    private static void requireRegister(Parameter parameter, String name) {
        require(parameter.isRegisterVariable() && parameter.getRegister() != null && parameter.getRegister().getName().equals(name),
            "unexpected native register for " + parameter.getName() + ": " + parameter.getVariableStorage());
    }

    private static Address address(Program program, long offset) {
        return program.getAddressFactory().getDefaultAddressSpace().getAddress(offset);
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

    private static Map<Path, String> snapshots(Path directory) throws Exception {
        Map<Path, String> result = new TreeMap<>();
        try (var paths = Files.walk(directory)) {
            for (Path path : paths.filter(Files::isRegularFile).toList()) result.put(directory.relativize(path), sha256(path));
        }
        return result;
    }

    private static String sha256(Path path) throws Exception {
        return java.util.HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(Files.readAllBytes(path)));
    }

    private static String text(JsonObject object, String name) { return object.get(name).getAsString(); }
    private static void nullableText(JsonElement actual, String expected, String message) {
        require(expected == null ? actual.isJsonNull() : !actual.isJsonNull() && actual.getAsString().equals(expected), message);
    }
    private static void equal(Object actual, Object expected, String message) {
        require(java.util.Objects.equals(actual, expected), message + ": actual=" + actual + ", expected=" + expected);
    }
    private static void require(boolean condition, String message) { if (!condition) throw new AssertionError(message); }
}
