import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import ghidra.GhidraApplicationLayout;
import ghidra.app.script.GhidraState;
import ghidra.base.project.GhidraProject;
import ghidra.framework.Application;
import ghidra.framework.HeadlessGhidraApplicationConfiguration;
import ghidra.program.database.ProgramDB;
import ghidra.program.disassemble.Disassembler;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.FlowOverride;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;
import java.io.ByteArrayInputStream;
import java.io.PrintWriter;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/** Authored native controls. They create no production oracle authority. */
public final class NativeCallCollectorControls {
    private static final TaskMonitor MONITOR = TaskMonitor.DUMMY;
    private static final String ARCHIVE_SHA = "93a5d11a9ad510622acaaf908c556a7b9b764d338e78a7567f3689bf5081fd54";
    private static Path root;
    private static Path collectorSource;
    private static Path modelSource;

    public static void main(String[] arguments) throws Exception {
        require(arguments.length == 6, "expected bundle, work, collector source, model source, mode, input");
        root = Path.of(arguments[1]);
        collectorSource = Path.of(arguments[2]);
        modelSource = Path.of(arguments[3]);
        Application.initializeApplication(new GhidraApplicationLayout(Path.of(arguments[0]).toFile()),
            new HeadlessGhidraApplicationConfiguration());
        require("12.1.3".equals(Application.getApplicationVersion()), "unexpected bundled Ghidra version");
        if (arguments[4].equals("delayed")) {
            delayedBoundary(Path.of(arguments[5]));
        } else {
            Files.createDirectories(root.resolve("project"));
            // Ghidra rejects dotted ancestor components in project locator strings.
            // The launch cwd is this exact repository-owned control directory.
            require(Path.of("").toRealPath().equals(root.toRealPath()), "control cwd differs from owned root");
            var project = GhidraProject.createProject("/proc/self/cwd/project", "controls", true);
            try {
                Program program = project.importProgram(Path.of(arguments[5]).toFile());
                GhidraProject.analyze(program);
                if (arguments[4].equals("static")) staticControls(program, Path.of(arguments[5]));
                else if (arguments[4].equals("plt") || arguments[4].equals("no-plt")) externalControls(program, Path.of(arguments[5]), arguments[4]);
                else throw new IllegalArgumentException("unknown control mode");
            } finally {
                project.close();
            }
        }
        System.out.println("native controls passed: " + arguments[4]);
        // Ghidra owns background executors; terminate only after project/program cleanup.
        System.exit(0);
    }

    private static void staticControls(Program program, Path input) throws Exception {
        Map<String, Address> address = new LinkedHashMap<>();
        for (String name : List.of("_start", "repeated_first", "repeated_second", "resolved_register", "unresolved_register",
                "resolved_memory", "empty_memory", "external_reference", "conditional_branch", "unresolved_switch", "worker",
                "recursive", "zero_calls", "tail", "thunk_outer", "thunk_inner", "return_override", "call_return_override",
                "analysis_call_candidate", "fallthrough_override", "length_override", "slot", "empty_slot")) {
            address.put(name, symbol(program, name));
        }
        address.put("switch_control", symbol(program, "switch_control"));
        address.put("switch_dispatch", symbol(program, "switch_dispatch"));
        int transaction = program.startTransaction("authored native collector controls");
        try {
            instruction(program, address.get("return_override")).setFlowOverride(FlowOverride.RETURN);
            instruction(program, address.get("call_return_override")).setFlowOverride(FlowOverride.CALL_RETURN);
            instruction(program, address.get("analysis_call_candidate")).setFlowOverride(FlowOverride.CALL);
            instruction(program, address.get("fallthrough_override")).setFallThrough(address.get("worker"));
            instruction(program, address.get("length_override")).setLengthOverride(2);
            // A resolved indirect reference is persisted analysis evidence, never a prototype target.
            program.getReferenceManager().addMemoryReference(address.get("resolved_register"), address.get("worker"),
                RefType.COMPUTED_CALL, SourceType.USER_DEFINED, 0);
            program.getReferenceManager().removeAllReferencesFrom(address.get("unresolved_register"), address.get("unresolved_register"));
            program.getReferenceManager().removeAllReferencesFrom(address.get("unresolved_switch"), address.get("unresolved_switch"));
            program.getReferenceManager().addMemoryReference(address.get("resolved_memory"), address.get("slot"),
                RefType.INDIRECTION, SourceType.USER_DEFINED, 0);
            program.getReferenceManager().addMemoryReference(address.get("slot"), address.get("worker"),
                RefType.DATA, SourceType.USER_DEFINED, 0);
            program.getReferenceManager().addMemoryReference(address.get("empty_memory"), address.get("empty_slot"),
                RefType.INDIRECTION, SourceType.USER_DEFINED, 0);
            program.getReferenceManager().removeAllReferencesFrom(address.get("empty_slot"), address.get("empty_slot"));
            var external = program.getExternalManager().addExtFunction("authored-control-library", "authored_external",
                program.getAddressFactory().getDefaultAddressSpace().getAddress(0x123456L), SourceType.IMPORTED);
            program.getReferenceManager().addExternalReference(address.get("external_reference"), 0, external,
                SourceType.IMPORTED, RefType.COMPUTED_CALL);
            Function worker = function(program, address.get("worker"));
            Function inner = function(program, address.get("thunk_inner"));
            inner.setThunkedFunction(worker);
            function(program, address.get("thunk_outer")).setThunkedFunction(inner);
            address.put("unowned", addCallBlock(program, "authored-unowned", 0x700000L, address.get("worker"), false));
            // The same native parser in a genuine overlay space, outside recovered function bodies.
            address.put("overlay", addCallBlock(program, "authored-overlay", 0x710000L, null, true));
        } finally {
            program.endTransaction(transaction, true);
        }
        JsonObject document = exportTwice(program, input);
        Map<String, JsonObject> sites = recordsByAddress(document, "site", "address");
        Map<String, JsonObject> functions = recordsByAddress(document, "function", "entry");
        Map<String, JsonObject> summaries = recordsByAddress(document, "function-summary", "entry");
        for (String name : List.of("repeated_first", "repeated_second", "recursive")) {
            JsonObject site = at(sites, document, address.get(name));
            require(text(site, "observationKind").equals("prototype-call"), name + " lost prototype call");
            require(!site.getAsJsonArray("prototypeTargets").isEmpty(), name + " lost encoded target");
        }
        require(!address.get("repeated_first").equals(address.get("repeated_second")), "repeated sites conflated");
        require(targetAddress(at(sites, document, address.get("recursive")), "prototypeTargets", addressKey(document, address.get("recursive"))), "recursive target lost");
        JsonObject zero = at(summaries, document, address.get("zero_calls"));
        require(zero.get("prototypeCalls").getAsLong() == 0 && zero.get("instructionsVisited").getAsLong() > 0, "zero-call function not inventoried");
        require(at(functions, document, address.get("zero_calls")) != null, "zero-call function inventory absent");
        require(at(sites, document, address.get("unowned")).get("owner").isJsonNull(), "unowned native call fabricated an owner");
        JsonObject overlay = at(sites, document, address.get("overlay"));
        require(overlay.get("owner").isJsonNull(), "overlay fabricated owner");
        int overlaySpace = overlay.getAsJsonObject("address").get("spaceIndex").getAsInt();
        require(document.getAsJsonArray("addressSpaces").get(overlaySpace).getAsJsonObject().get("overlay").getAsBoolean(), "overlay space lost");
        JsonObject resolved = at(sites, document, address.get("resolved_register"));
        require(resolved.getAsJsonArray("prototypeTargets").isEmpty(), "analysis reference filled prototype target");
        require(referenceTarget(resolved.getAsJsonArray("references"), addressKey(document, address.get("worker"))), "resolved register reference lost");
        require(at(sites, document, address.get("unresolved_register")).getAsJsonArray("prototypeTargets").isEmpty(), "unresolved register target invented");
        require(at(sites, document, address.get("unresolved_register")).getAsJsonArray("references").isEmpty(), "unresolved register reference invented");
        require(!sites.containsKey(addressKey(document, address.get("conditional_branch"))), "conditional branch promoted to call");
        require(!sites.containsKey(addressKey(document, address.get("unresolved_switch"))), "computed switch promoted to call");
        require(!sites.containsKey(addressKey(document, address.get("switch_dispatch"))), "actual switch-table jump promoted to call");
        require(at(summaries, document, address.get("switch_control")).get("ordinaryJumpInstructions").getAsLong() >= 2, "actual switch-table branch coverage absent");
        require(document.getAsJsonObject("summary").get("unresolvedComputedJumps").getAsLong() >= 1, "unresolved switch coverage absent");
        require(text(at(sites, document, address.get("tail")), "observationKind").equals("direct-tail-candidate"), "tail asserted as call or lost");
        JsonObject outer = at(functions, document, address.get("thunk_outer"));
        require(outer.get("isThunk").getAsBoolean(), "outer thunk missing");
        require(addressKey(outer.getAsJsonObject("immediateThunkTarget").getAsJsonObject("address")).equals(addressKey(document, address.get("thunk_inner"))), "thunk recursively collapsed");
        JsonObject returned = at(sites, document, address.get("return_override"));
        require(text(returned, "observationKind").equals("prototype-call") && text(returned, "flowOverride").equals("RETURN"), "RETURN override erased prototype call");
        require(!returned.getAsJsonArray("prototypeTargets").isEmpty(), "RETURN override erased encoded target");
        JsonObject callReturn = at(sites, document, address.get("call_return_override"));
        require(text(callReturn, "flowOverride").equals("CALL_RETURN") && text(callReturn, "observationKind").equals("prototype-call"), "CALL_RETURN override erased prototype call");
        require(text(at(sites, document, address.get("analysis_call_candidate")), "observationKind").equals("analysis-call-candidate"), "effective call not separated from prototype call");
        JsonObject fallthrough = at(sites, document, address.get("fallthrough_override"));
        require(!fallthrough.get("prototypeFallThrough").equals(fallthrough.get("effectiveFallThrough")), "fall-through override not observed separately");
        JsonObject shortened = at(sites, document, address.get("length_override"));
        require(shortened.get("lengthOverridden").getAsBoolean() && text(shortened, "byteStatus").equals("unsupported-boundary") && shortened.get("instructionBytes").isJsonNull(), "length override emitted unsafe physical bytes");
        JsonObject memory = at(sites, document, address.get("resolved_memory"));
        require(memory.getAsJsonArray("prototypeTargets").isEmpty(), "pointer neighborhood filled encoded target");
        require(neighborhoodTarget(memory, addressKey(document, address.get("slot")), addressKey(document, address.get("worker"))), "one-hop slot provenance absent");
        require(emptyNeighborhood(at(sites, document, address.get("empty_memory")), addressKey(document, address.get("empty_slot"))), "empty pointer neighborhood dropped");
        JsonObject ext = at(sites, document, address.get("external_reference"));
        require(hasExternal(ext.getAsJsonArray("references"), "authored_external"), "EXTERNAL reference dropped");
        require(document.getAsJsonObject("summary").get("unownedPrototypeCalls").getAsLong() >= 2, "unowned call coverage absent");
        cancelledCollection(program, input);
        referenceOverflowCollection(program, input, address.get("unowned"));
        Files.writeString(root.resolve("verified-controls.txt"), "repeated recursive zero-call unowned overlay register-indirect pointer-one-hop empty-neighborhood external branch actual-switch-table tail immediate-thunk RETURN CALL_RETURN effective-call fallthrough length-override deterministic model-unchanged cancellation native-reference-overflow\n");
    }

    private static void externalControls(Program program, Path input, String mode) throws Exception {
        Address importedPuts = importShim(program, "puts");
        JsonObject document = exportTwice(program, input);
        Function caller = function(program, symbol(program, "external_call"));
        boolean direct = false;
        boolean pltChain = false;
        boolean externalNeighborhood = false;
        Map<String, JsonObject> functions = recordsByAddress(document, "function", "entry");
        for (JsonElement element : document.getAsJsonArray("records")) {
            JsonObject record = element.getAsJsonObject();
            if (!text(record, "recordKind").equals("site") || record.get("owner").isJsonNull() ||
                !addressKey(record.getAsJsonObject("owner")).equals(addressKey(document, caller.getEntryPoint()))) continue;
            if (!record.getAsJsonArray("prototypeTargets").isEmpty()) direct = true;
            for (JsonElement targetElement : record.getAsJsonArray("prototypeTargets")) {
                JsonObject target = targetElement.getAsJsonObject();
                JsonElement block = target.get("memoryBlock");
                JsonObject nativeThunk = functions.get(addressKey(target.getAsJsonObject("address")));
                if (!block.isJsonNull() && text(block.getAsJsonObject(), "name").startsWith(".plt") && nativeThunk != null &&
                    nativeThunk.get("isThunk").getAsBoolean() && !nativeThunk.get("immediateThunkTarget").isJsonNull() &&
                    addressKey(nativeThunk.getAsJsonObject("immediateThunkTarget").getAsJsonObject("address")).equals(addressKey(document, importedPuts))) pltChain = true;
            }
            for (JsonElement neighborhood : record.getAsJsonArray("referenceNeighborhoods")) {
                if (referenceTarget(neighborhood.getAsJsonObject().getAsJsonArray("references"), addressKey(document, importedPuts))) externalNeighborhood = true;
            }
        }
        boolean putsEvidence = false;
        for (JsonElement element : document.getAsJsonArray("records")) {
            JsonObject record = element.getAsJsonObject();
            if (text(record, "recordKind").equals("site")) {
                putsEvidence |= hasExternal(record.getAsJsonArray("references"), "puts");
                for (JsonElement neighborhood : record.getAsJsonArray("referenceNeighborhoods")) {
                    putsEvidence |= hasExternal(neighborhood.getAsJsonObject().getAsJsonArray("references"), "puts");
                }
            } else if (text(record, "recordKind").equals("function") && !record.get("immediateThunkTarget").isJsonNull()) {
                JsonElement external = record.getAsJsonObject("immediateThunkTarget").get("external");
                putsEvidence |= external != null && !external.isJsonNull() && text(external.getAsJsonObject(), "label").equals("puts");
            }
        }
        require(putsEvidence, "real linked external puts provenance absent");
        if (mode.equals("plt")) require(direct && pltChain, "PLT caller lost actual direct target and immediate native thunk chain");
        else require(!direct && externalNeighborhood, "-fno-plt GOT slot provenance absent or filled prototype target");
        Files.writeString(root.resolve("verified-controls.txt"), mode + " linked ELF actual puts import and call provenance deterministic model-unchanged\n");
    }

    private static void delayedBoundary(Path input) throws Exception {
        Language language = DefaultLanguageService.getLanguageService().getLanguage(new LanguageID("MIPS:BE:32:default"));
        Object consumer = new Object();
        ProgramDB program = new ProgramDB("authored-mips-delay", language, language.getDefaultCompilerSpec(), consumer);
        try {
            int transaction = program.startTransaction("authored delayed instruction");
            Address start;
            try {
                start = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x1000L);
                // jal 0x1010; nop (delay slot); jr ra; nop; jr ra; nop
                byte[] code = {(byte)0x0c, 0, 4, 4, 0, 0, 0, 0, 3, (byte)0xe0, 0, 8, 0, 0, 0, 0, 3, (byte)0xe0, 0, 8, 0, 0, 0, 0};
                program.getMemory().createInitializedBlock("authored-delay", start, new ByteArrayInputStream(code), code.length, MONITOR, false).setExecute(true);
                Disassembler.getDisassembler(program, MONITOR, null).disassemble(start, new AddressSet(start, start.add(code.length - 1)), true);
                program.getFunctionManager().createFunction("delayed_caller", start, new AddressSet(start, start.add(15)), SourceType.USER_DEFINED);
                program.getFunctionManager().createFunction("delayed_callee", start.add(16), new AddressSet(start.add(16), start.add(23)), SourceType.USER_DEFINED);
                program.setExecutablePath(input.toString());
                program.setExecutableSHA256(sha256(input));
                program.setExecutableFormat("authored MIPS bytes");
            } finally {
                program.endTransaction(transaction, true);
            }
            require(instruction(program, start).getDelaySlotDepth() > 0, "control did not disassemble a native delayed call");
            JsonObject document = exportTwice(program, input);
            JsonObject site = at(recordsByAddress(document, "site", "address"), document, start);
            require(text(site, "observationKind").equals("prototype-call"), "delayed prototype call absent");
            require(site.get("delaySlotDepth").getAsInt() > 0 && text(site, "byteStatus").equals("unsupported-boundary") && site.get("instructionBytes").isJsonNull(), "delay slot emitted unsafe physical bytes");
            require(!site.getAsJsonArray("prototypeTargets").isEmpty(), "delayed encoded target absent");
            Files.writeString(root.resolve("verified-controls.txt"), "genuine MIPS delayed prototype call unsupported bytes deterministic model-unchanged\n");
        } finally {
            program.release(consumer);
        }
    }

    private static JsonObject exportTwice(Program program, Path input) throws Exception {
        Path reports = Files.createDirectory(root.resolve("reports"));
        Path model = reports.resolve("program_model.json");
        ExportProgramModel exporter = new ExportProgramModel();
        exporter.setScriptArgs(new String[] {sha256(modelSource), ARCHIVE_SHA, "full", model.toString()});
        exporter.execute(new GhidraState(null, null, program, null, null, null), MONITOR, new PrintWriter(System.out, true));
        require(Files.size(model) > 0, "real model exporter produced no model");
        // Independent native metadata lets the Kotlin reader bind actual collector bytes
        // without accepting the collector's self-reported binding as its expected value.
        JsonObject nativeProperties = new JsonObject();
        nativeProperties.addProperty("languageId", program.getLanguageID().getIdAsString());
        nativeProperties.addProperty("compilerSpecId", program.getCompilerSpec().getCompilerSpecID().getIdAsString());
        nativeProperties.addProperty("imageBaseSpace", program.getImageBase().getAddressSpace().getName());
        nativeProperties.addProperty("imageBaseOffsetBits", String.format("%016x", program.getImageBase().getOffset()));
        long functionCount = 0;
        var nativeFunctions = program.getFunctionManager().getFunctions(true);
        while (nativeFunctions.hasNext()) if (!nativeFunctions.next().isExternal()) functionCount++;
        long instructionCount = 0;
        var nativeInstructions = program.getListing().getInstructions(true);
        while (nativeInstructions.hasNext()) { nativeInstructions.next(); instructionCount++; }
        nativeProperties.addProperty("functions", functionCount);
        nativeProperties.addProperty("instructionsVisited", instructionCount);
        Files.writeString(root.resolve("native-properties.json"), nativeProperties.toString());
        Map<Path, String> preserved = snapshots(reports);
        long modification = program.getModificationNumber();
        Path first = root.resolve("first-native");
        Path second = root.resolve("second-native");
        ExportNativeCallsV1.collect(program, MONITOR, arguments(input, model, first));
        require(program.getModificationNumber() == modification, "collector mutated native Program");
        require(preserved.equals(snapshots(reports)), "collector changed paired model/progress/checkpoints");
        // Exercise the actual compiled dispatch used by the contained worker.
        // Ghidra's nested source-language providers cannot resolve a .class script.
        RunBundledExports dispatch = new RunBundledExports();
        String[] collectorArguments = arguments(input, model, second);
        String[] dispatchArguments = new String[collectorArguments.length + 2];
        dispatchArguments[0] = "ExportNativeCallsV1.class";
        dispatchArguments[1] = "6";
        System.arraycopy(collectorArguments, 0, dispatchArguments, 2, collectorArguments.length);
        dispatch.setScriptArgs(dispatchArguments);
        dispatch.execute(new GhidraState(null, null, program, null, null, null), MONITOR, new PrintWriter(System.out, true));
        require(program.getModificationNumber() == modification, "repeated collector mutated native Program");
        require(preserved.equals(snapshots(reports)), "repeated collector changed paired model/progress/checkpoints");
        for (String name : List.of("manifest.json", "native-calls.json")) {
            require(Arrays.equals(Files.readAllBytes(first.resolve(name)), Files.readAllBytes(second.resolve(name))), "nondeterministic collector bytes: " + name);
        }
        // An existing destination is an error; a successful old artifact is never reused.
        boolean staleRejected = false;
        try { ExportNativeCallsV1.collect(program, MONITOR, arguments(input, model, first)); }
        catch (Exception expected) { staleRejected = true; }
        require(staleRejected, "existing native output accepted");
        require(Arrays.equals(Files.readAllBytes(first.resolve("native-calls.json")), Files.readAllBytes(second.resolve("native-calls.json"))), "failed repeat changed old output");
        return JsonParser.parseString(Files.readString(first.resolve("native-calls.json"))).getAsJsonObject();
    }

    private static void cancelledCollection(Program program, Path input) throws Exception {
        TaskMonitorAdapter cancelled = new TaskMonitorAdapter(true);
        cancelled.cancel();
        Path destination = root.resolve("cancelled-native");
        boolean rejected = false;
        try { ExportNativeCallsV1.collect(program, cancelled, arguments(input, root.resolve("reports/program_model.json"), destination)); }
        catch (ghidra.util.exception.CancelledException expected) { rejected = true; }
        require(rejected, "cancelled collector returned success");
        require(!Files.exists(destination.resolve("manifest.json")), "cancelled collector published manifest");
    }

    private static void referenceOverflowCollection(Program program, Path input, Address from) throws Exception {
        int transaction = program.startTransaction("authored reference overflow negative control");
        try {
            for (int index = 0; index < 65; index++) program.getReferenceManager().addMemoryReference(from, from.add(100 + index), RefType.DATA, SourceType.USER_DEFINED, 0);
            require(program.getReferenceManager().getReferenceCountFrom(from) > 64, "native overflow control failed to retain distinct references");
            long modification = program.getModificationNumber();
            Path destination = root.resolve("overflow-native");
            boolean rejected = false;
            try { ExportNativeCallsV1.collect(program, MONITOR, arguments(input, root.resolve("reports/program_model.json"), destination)); }
            catch (IllegalStateException expected) { rejected = expected.getMessage().contains("reference count bound"); }
            require(rejected, "native reference overflow not rejected at its bound");
            require(!Files.exists(destination.resolve("manifest.json")), "native reference overflow published a manifest");
            require(program.getModificationNumber() == modification, "overflow collector mutated native Program");
        } finally {
            program.endTransaction(transaction, false);
        }
    }

    private static String[] arguments(Path input, Path model, Path output) throws Exception {
        return new String[] {sha256(input), sha256(modelSource), ARCHIVE_SHA, sha256(collectorSource), model.toString(), output.toString()};
    }

    private static Address addCallBlock(Program program, String name, long offset, Address target, boolean overlay) throws Exception {
        Address start = program.getAddressFactory().getDefaultAddressSpace().getAddress(offset);
        long displacement = target == null ? 1 : target.subtract(start.add(5));
        byte[] code = {(byte)0xe8, (byte)displacement, (byte)(displacement >> 8), (byte)(displacement >> 16), (byte)(displacement >> 24), (byte)0xc3, (byte)0xc3};
        MemoryBlock block = program.getMemory().createInitializedBlock(name, start, new ByteArrayInputStream(code), code.length, MONITOR, overlay);
        block.setExecute(true);
        Address actual = block.getStart();
        Disassembler.getDisassembler(program, MONITOR, null).disassemble(actual, new AddressSet(actual, block.getEnd()), true);
        require(instruction(program, actual).getPrototype().getFlowType(instruction(program, actual).getInstructionContext()).isCall(), "authored block not an actual call");
        require(program.getFunctionManager().getFunctionContaining(actual) == null, "authored call unexpectedly owned");
        return actual;
    }

    private static Address symbol(Program program, String name) {
        var matches = program.getSymbolTable().getSymbols(name);
        require(matches.hasNext(), "missing ELF symbol " + name);
        return matches.next().getAddress();
    }

    private static Function function(Program program, Address address) {
        Function function = program.getFunctionManager().getFunctionAt(address);
        require(function != null, "missing recovered function at " + address);
        return function;
    }

    private static Address importShim(Program program, String label) {
        var functions = program.getFunctionManager().getFunctions(true);
        while (functions.hasNext()) {
            Function function = functions.next();
            Function next = function.isThunk() ? function.getThunkedFunction(false) : null;
            if (!function.isExternal() && next != null && next.isExternal() && next.getExternalLocation().getLabel().equals(label)) return function.getEntryPoint();
        }
        throw new AssertionError("real linked ELF import shim missing for " + label);
    }

    private static Instruction instruction(Program program, Address address) {
        Instruction instruction = program.getListing().getInstructionAt(address);
        require(instruction != null, "missing native instruction at " + address);
        return instruction;
    }

    private static Map<Path, String> snapshots(Path directory) throws Exception {
        Map<Path, String> result = new TreeMap<>();
        try (var paths = Files.walk(directory)) {
            for (Path path : paths.filter(Files::isRegularFile).toList()) result.put(directory.relativize(path), sha256(path));
        }
        return result;
    }

    private static Map<String, JsonObject> recordsByAddress(JsonObject document, String kind, String key) {
        Map<String, JsonObject> result = new HashMap<>();
        for (JsonElement element : document.getAsJsonArray("records")) {
            JsonObject record = element.getAsJsonObject();
            if (text(record, "recordKind").equals(kind)) require(result.put(addressKey(record.getAsJsonObject(key)), record) == null, "duplicate record " + kind);
        }
        return result;
    }

    private static JsonObject at(Map<String, JsonObject> records, JsonObject document, Address address) {
        String key = addressKey(document, address);
        require(records.containsKey(key), "missing native record at " + address + " (" + key + ")");
        return records.get(key);
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

    private static boolean targetAddress(JsonObject site, String field, String address) {
        for (JsonElement element : site.getAsJsonArray(field)) if (addressKey(element.getAsJsonObject().getAsJsonObject("address")).equals(address)) return true;
        return false;
    }

    private static boolean referenceTarget(JsonArray references, String address) {
        for (JsonElement reference : references) if (addressKey(reference.getAsJsonObject().getAsJsonObject("target").getAsJsonObject("address")).equals(address)) return true;
        return false;
    }

    private static boolean neighborhoodTarget(JsonObject site, String source, String target) {
        for (JsonElement element : site.getAsJsonArray("referenceNeighborhoods")) {
            JsonObject neighborhood = element.getAsJsonObject();
            if (addressKey(neighborhood.getAsJsonObject("source")).equals(source) && referenceTarget(neighborhood.getAsJsonArray("references"), target)) return true;
        }
        return false;
    }

    private static boolean emptyNeighborhood(JsonObject site, String source) {
        for (JsonElement element : site.getAsJsonArray("referenceNeighborhoods")) {
            JsonObject neighborhood = element.getAsJsonObject();
            if (addressKey(neighborhood.getAsJsonObject("source")).equals(source) && neighborhood.getAsJsonArray("references").isEmpty()) return true;
        }
        return false;
    }

    private static boolean hasExternal(JsonArray references, String label) {
        for (JsonElement element : references) {
            JsonElement value = element.getAsJsonObject().getAsJsonObject("target").get("external");
            if (!value.isJsonNull() && text(value.getAsJsonObject(), "label").equals(label)) return true;
        }
        return false;
    }

    private static String text(JsonObject object, String key) { return object.get(key).getAsString(); }
    private static String sha256(Path path) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        try (var input = Files.newInputStream(path)) {
            byte[] buffer = new byte[65536];
            for (int read; (read = input.read(buffer)) != -1;) digest.update(buffer, 0, read);
        }
        return java.util.HexFormat.of().formatHex(digest.digest());
    }
    private static void require(boolean condition, String message) { if (!condition) throw new AssertionError(message); }
}
