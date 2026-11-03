import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.*;
import ghidra.app.decompiler.*;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;
import ghidra.util.exception.CancelledException;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.MessageDigest;
import java.util.*;

/** Raw recovered HighFunction observations. No ABI equivalence, source truth or admission. */
public final class ExportInferredInterfacesV1 extends GhidraScript {
    private static final long MAXIMUM_BYTES = 1024L * 1024 * 1024;
    private static final long MAXIMUM_MODEL_BYTES = 512L * 1024 * 1024;
    private static final int MAXIMUM_FUNCTIONS = 131072;
    private static final int MAXIMUM_PARAMETERS_PER_FUNCTION = 1024;
    private static final long MAXIMUM_PARAMETERS = 1000000;
    private static final int MAXIMUM_VARNODES_PER_STORAGE = 64;
    private static final long MAXIMUM_VARNODES = 1000000;
    private static final int MAXIMUM_RECORD_BYTES = 1024 * 1024;
    private static final int MAXIMUM_STRING_BYTES = 4096;
    private static final long MAXIMUM_OPERATION_MILLIS = 120000;
    private static final String POLICY = "ghidra-native-inferred-interface-observations-v1";
    private static final String[] DISPOSITIONS = {"high-function-observed", "not-attempted-external",
        "not-attempted-unsupported-body", "decompile-timeout", "decompile-cancelled", "decompiler-start-failed",
        "decompiler-error", "completed-without-high-function", "unsupported-high-representation"};
    private final Program program;
    private final TaskMonitor task;
    private final long maximumCombinedBytes;
    private final long started = System.nanoTime();
    private final FailureDiagnostics diagnostics = new FailureDiagnostics(started);
    private final List<AddressSpace> spaces = new ArrayList<>();
    private final Map<AddressSpace, Integer> spaceIndices = new HashMap<>();
    private final TreeMap<String, Long> dispositions = new TreeMap<>();
    private long parameters, storageVarnodes, roots, attempted, observed, recordCount;
    private int listingOccurrence;
    private BoundedOutput output;
    private NativeInterfaceTypeGraphV1 graph;
    private NativeInterfaceTypeGraphV1.Budget graphBudget;

    public ExportInferredInterfacesV1() { program = null; task = null; maximumCombinedBytes = MAXIMUM_BYTES; }
    private ExportInferredInterfacesV1(Program program, TaskMonitor task) {
        this(program, task, MAXIMUM_BYTES);
    }
    private ExportInferredInterfacesV1(Program program, TaskMonitor task, long maximumCombinedBytes) {
        this.program = Objects.requireNonNull(program); this.task = Objects.requireNonNull(task);
        if (maximumCombinedBytes < 1 || maximumCombinedBytes > MAXIMUM_BYTES)
            throw new IllegalArgumentException("invalid inferred-interface combined byte limit");
        this.maximumCombinedBytes = maximumCombinedBytes;
        for (String state : DISPOSITIONS) dispositions.put(state, 0L);
    }
    @Override protected void run() throws Exception { collect(currentProgram, monitor, getScriptArgs()); }
    public static void collect(Program program, TaskMonitor monitor, String[] arguments) throws Exception {
        new ExportInferredInterfacesV1(program, monitor).export(arguments);
    }
    /** Lower-only enclosing-operation limit; the default compiled invocation remains unchanged. */
    public static void collectWithByteLimit(Program program, TaskMonitor monitor, String[] arguments,
            long maximumCombinedBytes) throws Exception {
        new ExportInferredInterfacesV1(program, monitor, maximumCombinedBytes).export(arguments);
    }
    private void checkpoint() throws Exception {
        try { task.checkCancelled(); }
        catch (Exception | Error failure) {
            diagnostics.freeze(failure instanceof CancelledException ? FailureDiagnostics.FailureKind.CANCELLATION_OBSERVED :
                FailureDiagnostics.FailureKind.VALIDATION_OR_OUTPUT, System.nanoTime());
            throw failure;
        }
        long now = System.nanoTime();
        if (now - started >= MAXIMUM_OPERATION_MILLIS * 1000000L) {
            diagnostics.freeze(FailureDiagnostics.FailureKind.OPERATION_DEADLINE, now);
            throw new IllegalStateException("inferred-interface operation deadline exhausted");
        }
    }
    private TaskMonitor listingMonitor() {
        return diagnosticListingMonitor(task, diagnostics, started);
    }
    /** The existing monitor bridge, with first-observation diagnostics and the real owner clock. */
    static TaskMonitor diagnosticListingMonitor(TaskMonitor task, FailureDiagnostics diagnostics, long started) {
        return new TaskMonitorAdapter() {
            @Override public void checkCancelled() throws CancelledException {
                try { task.checkCancelled(); }
                catch (CancelledException | RuntimeException | Error failure) {
                    diagnostics.freeze(failure instanceof CancelledException ? FailureDiagnostics.FailureKind.CANCELLATION_OBSERVED :
                        FailureDiagnostics.FailureKind.VALIDATION_OR_OUTPUT, System.nanoTime());
                    diagnostics.emitOnce(System.err);
                    throw failure;
                }
                long now = System.nanoTime();
                if (now - started >= MAXIMUM_OPERATION_MILLIS * 1000000L) {
                    diagnostics.freeze(FailureDiagnostics.FailureKind.OPERATION_DEADLINE, now);
                    diagnostics.emitOnce(System.err);
                    throw new CancelledException("inferred-interface operation deadline exhausted");
                }
            }
            @Override public boolean isCancelled() {
                final boolean cancelled;
                try { cancelled = task.isCancelled(); }
                catch (RuntimeException | Error failure) {
                    diagnostics.freeze(FailureDiagnostics.FailureKind.VALIDATION_OR_OUTPUT, System.nanoTime());
                    throw failure;
                }
                if (cancelled) {
                    diagnostics.freeze(FailureDiagnostics.FailureKind.CANCELLATION_OBSERVED, System.nanoTime());
                    return true;
                }
                long now = System.nanoTime();
                boolean expired = now - started >= MAXIMUM_OPERATION_MILLIS * 1000000L;
                if (expired) diagnostics.freeze(FailureDiagnostics.FailureKind.OPERATION_DEADLINE, now);
                return expired;
            }
        };
    }
    private void export(String[] arguments) throws Exception {
        try { exportObserved(arguments); }
        catch (Exception | Error failure) {
            reportFailure(failure, FailureDiagnostics.FailureKind.VALIDATION_OR_OUTPUT);
            throw failure;
        }
    }
    private void reportFailure(Throwable failure, FailureDiagnostics.FailureKind kind) {
        diagnostics.freeze(failure instanceof CancelledException || failure instanceof InterruptedException ?
            FailureDiagnostics.FailureKind.CANCELLATION_OBSERVED : kind, System.nanoTime());
        diagnostics.emitOnce(System.err);
    }
    private static void suppressCleanup(Throwable primary, Throwable cleanup) {
        if (primary != cleanup) try { primary.addSuppressed(cleanup); } catch (Throwable ignored) { }
    }
    private void diagnosticFunction(int ordinal, Address entry) {
        // The census already owns this address; no Function/native-result getter is needed here.
        try {
            Integer space = spaceIndices.get(entry.getAddressSpace());
            if (space == null) diagnostics.omit();
            else diagnostics.function(ordinal, space, entry.getOffset());
        } catch (Throwable diagnosticFailure) { diagnostics.omit(); }
    }
    private void exportObserved(String[] arguments) throws Exception {
        if (arguments.length != 11) throw new IllegalArgumentException("expected eight digest bindings, model, listing directory and output directory");
        String input = digest(arguments[0]), exporter = digest(arguments[1]), archive = digest(arguments[2]);
        String listingCollector = digest(arguments[3]), collector = digest(arguments[4]), typeGraph = digest(arguments[5]);
        String wrapper = digest(arguments[6]), decompiler = digest(arguments[7]);
        if (!input.equals(digest(program.getExecutableSHA256()))) throw new IllegalArgumentException("inferred input differs from imported Program");
        Path model = Path.of(arguments[8]).toAbsolutePath().normalize();
        Path listingDirectory = Path.of(arguments[9]).toAbsolutePath().normalize();
        Path directory = Path.of(arguments[10]).toAbsolutePath().normalize();
        if (directory.getParent() == null || !directory.getParent().toRealPath().equals(directory.getParent()) ||
            Files.exists(directory, LinkOption.NOFOLLOW_LINKS) || model.startsWith(directory) || listingDirectory.startsWith(directory))
            throw new IllegalArgumentException("inferred output must be absent, private and distinct from inputs");
        checkpoint();
        long modification = program.getModificationNumber();
        FileIdentity modelBefore = hashFile(model, MAXIMUM_MODEL_BYTES);
        Path listing = listingDirectory.resolve("native-interfaces.json"), listingManifest = listingDirectory.resolve("manifest.json");
        FileIdentity listingBefore = hashFile(listing, MAXIMUM_BYTES), manifestBefore = hashFile(listingManifest, 65536);
        if (Set.of(modelBefore.attributes.fileKey(), listingBefore.attributes.fileKey(), manifestBefore.attributes.fileKey()).size() != 3)
            throw new IllegalArgumentException("inferred input files alias");
        long inputsBytes = Math.addExact(modelBefore.bytes, Math.addExact(listingBefore.bytes, manifestBefore.bytes));
        if (inputsBytes >= maximumCombinedBytes)
            throw new IllegalArgumentException("combined retained input inventory bound exceeded");
        diagnostics.stage(FailureDiagnostics.Stage.CENSUS, System.nanoTime());
        inventorySpaces();
        FunctionManager manager = program.getFunctionManager();
        int count = manager.getFunctionCount();
        diagnostics.censusReported(count);
        if (count < 0 || count > MAXIMUM_FUNCTIONS) throw new IllegalStateException("function census bound exceeded");
        TreeMap<Address, Function> functions = new TreeMap<>(this::compare);
        diagnostics.censusInventoried(0);
        inventory(manager.getFunctions(true), false, functions); inventory(manager.getExternalFunctions(), true, functions);
        if (functions.size() != count || manager.getFunctionCount() != count) throw new IllegalStateException("inconsistent function census");
        diagnostics.censusValidated();
        Map<String,Object> configuration = object("simplificationStyle", "decompile", "syntaxTree", true, "cCode", false,
            "maximumInstructions", 500000, "maximumPayloadMBytes", 50, "maximumJumpTableEntries", 1024,
            "maximumSecondsPerFunction", 60, "maximumOperationMillis", MAXIMUM_OPERATION_MILLIS, "attemptsPerFunction", 1);
        String configurationSha = sha(canonical(configuration, 65536));
        Map<String,Object> listingBindings = object("collectorSha256", listingCollector,
            "compilerSpecId", text(program.getCompilerSpec().getCompilerSpecID().getIdAsString()), "ghidraArchiveSha256", archive,
            "imageBase", address(program.getImageBase()), "inputSha256", input, "languageId", text(program.getLanguageID().getIdAsString()),
            "programModelBytes", modelBefore.bytes, "programModelExporterSha256", exporter, "programModelSha256", modelBefore.sha256);
        Map<String,Object> bindings = object("listingBindings", listingBindings, "collectorSha256", collector, "typeGraphSha256", typeGraph,
            "wrapperSha256", wrapper, "nativeDecompilerSha256", decompiler, "listingBytes", listingBefore.bytes,
            "listingSha256", listingBefore.sha256, "listingManifestSha256", manifestBefore.sha256, "configurationSha256", configurationSha);
        Path stage = null, manifestStage = null;
        Path comparison = directory.resolve("listing-comparison");
        Path observations = directory.resolve("native-inferred-interfaces.json"), manifestPath = directory.resolve("manifest.json");
        boolean complete = false;
        Throwable exportFailure = null;
        Files.createDirectory(directory, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")));
        try {
            // Prove graph roots refer to this exact pre-inference listing, not same-input stale bytes.
            // The re-render may be larger than the frozen listing. Charge actual comparison
            // output and simultaneous type-spool writes, never a multiple of stale input size.
            diagnostics.stage(FailureDiagnostics.Stage.LISTING_COMPARISON, System.nanoTime());
            ExportNativeInterfacesV1.collectWithStagingBudget(program, listingMonitor(),
                new String[]{input, exporter, archive, listingCollector, model.toString(), comparison.toString()},
                maximumCombinedBytes - inputsBytes);
            requireContent(listingBefore, hashFile(comparison.resolve("native-interfaces.json"), MAXIMUM_BYTES));
            requireContent(manifestBefore, hashFile(comparison.resolve("manifest.json"), 65536));
            removeComparison(comparison); checkpoint(); requireProgramUnchanged(modification);
            stage = privateTemporary(directory, ".inferred-");
            MessageDigest outputDigest = MessageDigest.getInstance("SHA-256"); long bytes;
            try (BoundedOutput target = new BoundedOutput(new BufferedOutputStream(Files.newOutputStream(stage)), outputDigest,
                    maximumCombinedBytes - inputsBytes - 65536, task)) {
              try {
                diagnostics.stage(FailureDiagnostics.Stage.LISTING_ROOTS, System.nanoTime());
                output = target;
                graphBudget = new NativeInterfaceTypeGraphV1.Budget(NativeInterfaceTypeGraphV1.Limits.defaults(), this::checkpoint);
                graph = new NativeInterfaceTypeGraphV1(program.getDataTypeManager().getDataOrganization(), graphBudget, this::record);
                target.writeUtf8("{\n  \"addressSpaces\": "); target.value(spaceRecords(), 2, false);
                target.writeUtf8(",\n  \"bindings\": "); target.value(bindings, 2, false);
                target.writeUtf8(",\n  \"configuration\": "); target.value(configuration, 2, false);
                target.writeUtf8(",\n  \"dataOrganization\": "); target.value(graph.dataOrganization(), 2, false);
                target.writeUtf8(",\n  \"policy\": \"" + POLICY + "\",\n  \"records\": ");
                int ordinal = 0;
                for (var entry : functions.entrySet()) {
                    diagnosticFunction(ordinal, entry.getKey());
                    listingRoots(entry.getValue(), ordinal++);
                }
                requireProgramUnchanged(modification); checkpoint();
                diagnostics.stage(FailureDiagnostics.Stage.DECOMPILER_SETUP, System.nanoTime());
                DecompInterface engine = new DecompInterface();
                Throwable engineFailure = null;
                try {
                    DecompileOptions options = new DecompileOptions();
                    options.setMaxInstructions(500000); options.setMaxPayloadMBytes(50); options.setMaxJumpTableEntries(1024);
                    if (!engine.setOptions(options) || !engine.setSimplificationStyle("decompile") ||
                        !engine.toggleSyntaxTree(true) || !engine.toggleCCode(false)) throw new IllegalStateException("decompiler configuration rejected");
                    boolean opened = engine.openProgram(program);
                    ordinal = 0;
                    for (var entry : functions.entrySet()) {
                        diagnosticFunction(ordinal, entry.getKey());
                        diagnostics.stage(FailureDiagnostics.Stage.NATIVE_PRECHECK, System.nanoTime());
                        checkpoint();
                        Map<String,Object> functionRecord = inferred(entry.getValue(), ordinal++, engine, opened);
                        diagnostics.stage(FailureDiagnostics.Stage.FUNCTION_RECORD, System.nanoTime());
                        record(functionRecord);
                        diagnostics.functionRecordWritten();
                        requireProgramUnchanged(modification);
                    }
                } catch (Exception | Error failure) {
                    engineFailure = failure;
                    reportFailure(failure, FailureDiagnostics.FailureKind.VALIDATION_OR_OUTPUT);
                    throw failure;
                } finally {
                    if (engineFailure == null) { engine.stopProcess(); engine.dispose(); }
                    else {
                        try { engine.stopProcess(); } catch (Exception | Error cleanup) { suppressCleanup(engineFailure, cleanup); }
                        try { engine.dispose(); } catch (Exception | Error cleanup) { suppressCleanup(engineFailure, cleanup); }
                    }
                }
                diagnostics.stage(FailureDiagnostics.Stage.FINAL_VALIDATION, System.nanoTime());
                target.writeUtf8(recordCount == 0 ? "[]" : "\n  ]");
                target.writeUtf8(",\n  \"schemaVersion\": 1,\n  \"summary\": "); target.value(summary(functions.values()), 2, false);
                target.writeUtf8("\n}\n"); bytes = target.bytes;
              } catch (Exception | Error failure) {
                reportFailure(failure, FailureDiagnostics.FailureKind.VALIDATION_OR_OUTPUT);
                throw failure;
              }
            } finally { output = null; graph = null; }
            if (manager.getFunctionCount() != count || dispositions.values().stream().mapToLong(Long::longValue).sum() != count)
                throw new IllegalStateException("inferred census changed or omitted outcomes");
            requireUnchanged(modelBefore, hashFile(model, MAXIMUM_MODEL_BYTES));
            requireUnchanged(listingBefore, hashFile(listing, MAXIMUM_BYTES)); requireUnchanged(manifestBefore, hashFile(listingManifest, 65536));
            requireProgramUnchanged(modification); checkpoint();
            diagnostics.stage(FailureDiagnostics.Stage.PUBLICATION, System.nanoTime());
            byte[] manifest = canonical(object("bytes", bytes, "collectorSha256", collector, "typeGraphSha256", typeGraph, "configurationSha256", configurationSha,
                "file", "native-inferred-interfaces.json", "inputSha256", input,
                "kind", "ghidra-native-inferred-interface-observation-manifest-v1", "listingSha256", listingBefore.sha256,
                "programModelSha256", modelBefore.sha256, "schemaVersion", 1, "sha256", HexFormat.of().formatHex(outputDigest.digest())), 65536);
            if (Math.addExact(inputsBytes, Math.addExact(bytes, manifest.length)) > maximumCombinedBytes) throw new IllegalStateException("combined output bound exceeded");
            Files.setPosixFilePermissions(stage, PosixFilePermissions.fromString("r--------"));
            Files.createLink(observations, stage); Files.delete(stage); stage = null;
            manifestStage = privateTemporary(directory, ".inferred-manifest-"); Files.write(manifestStage, manifest, StandardOpenOption.TRUNCATE_EXISTING);
            Files.setPosixFilePermissions(manifestStage, PosixFilePermissions.fromString("r--------"));
            requireUnchanged(modelBefore, hashFile(model, MAXIMUM_MODEL_BYTES));
            requireUnchanged(listingBefore, hashFile(listing, MAXIMUM_BYTES)); requireUnchanged(manifestBefore, hashFile(listingManifest, 65536));
            requireProgramUnchanged(modification); checkpoint();
            Files.createLink(manifestPath, manifestStage); Files.delete(manifestStage); manifestStage = null;
            complete = true;
        } catch (Exception | Error failure) {
            exportFailure = failure;
            reportFailure(failure, FailureDiagnostics.FailureKind.VALIDATION_OR_OUTPUT);
            throw failure;
        } finally {
            try {
                if (stage != null) Files.deleteIfExists(stage);
                if (manifestStage != null) Files.deleteIfExists(manifestStage);
                removeComparison(comparison);
                if (!complete) { Files.deleteIfExists(manifestPath); Files.deleteIfExists(observations); Files.deleteIfExists(directory); }
            } catch (Exception | Error cleanup) {
                if (exportFailure == null) throw cleanup;
                suppressCleanup(exportFailure, cleanup);
            }
        }
    }

    private void listingRoots(Function function, int ordinal) throws Exception {
        checkpoint(); var scope = graph.scope("listing", ordinal);
        int count = function.getParameterCount();
        if (count < 0 || count > MAXIMUM_PARAMETERS_PER_FUNCTION) throw new IllegalStateException("listing parameter bound exceeded");
        Parameter returned = function.getReturn();
        if (returned != null) {
            root(scope, "listing", ordinal, "return-formal", -1, returned.getFormalDataType(), true);
            root(scope, "listing", ordinal, "return-effective", -1, returned.getDataType(), true);
        }
        for (int i = 0; i < count; i++) {
            Parameter p = Objects.requireNonNull(function.getParameter(i));
            if (p.getOrdinal() != i) throw new IllegalStateException("listing ordinal changed");
            root(scope, "listing", ordinal, "parameter-formal", i, p.getFormalDataType(), true);
            root(scope, "listing", ordinal, "parameter-effective", i, p.getDataType(), true);
        }
    }
    private Integer root(NativeInterfaceTypeGraphV1.Scope scope, String channel, int ordinal, String role, int slot, DataType type, boolean listing) throws Exception {
        checkpoint(); if (++roots > 3393216) throw new IllegalStateException("type root bound exceeded");
        Integer occurrence = listing && type != null ? listingOccurrence++ : null;
        Integer node = scope.reference(type);
        record(object("recordKind", "type-root", "channel", channel, "functionOrdinal", ordinal,
            "role", role, "slot", slot, "listingTypeOrdinal", occurrence, "node", node));
        return node;
    }
    private Map<String,Object> inferred(Function function, int ordinal, DecompInterface engine, boolean opened) throws Exception {
        String disposition; Map<String,Object> result = null, prototype = null;
        List<Object> params = new ArrayList<>(); int attempt = 0;
        if (function.isExternal()) disposition = "not-attempted-external";
        else if (function.getBody().isEmpty() || program.getListing().getInstructionAt(function.getEntryPoint()) == null)
            disposition = "not-attempted-unsupported-body";
        else {
            attempt = 1; attempted++;
            if (!opened) {
                disposition = "decompiler-start-failed";
                result = object("completed", false, "valid", false, "timedOut", false, "cancelled", false,
                    "failedToStart", true, "diagnostic", text(Objects.toString(engine.getLastMessage(), "")));
            } else {
                long allocatedAt = System.nanoTime();
                long remaining = MAXIMUM_OPERATION_MILLIS - (allocatedAt - started) / 1000000L;
                int seconds = (int)Math.min(60, remaining / 1000);
                diagnostics.allocation(seconds);
                if (seconds < 1) {
                    diagnostics.freeze(FailureDiagnostics.FailureKind.INSUFFICIENT_WHOLE_SECOND, allocatedAt);
                    throw new IllegalStateException("insufficient inference operation time");
                }
                DecompileResults returned;
                diagnostics.nativeStarted(System.nanoTime());
                try {
                    returned = engine.decompileFunction(function, seconds, task);
                    diagnostics.nativeReturned(System.nanoTime());
                } catch (Exception | Error failure) {
                    reportFailure(failure, FailureDiagnostics.FailureKind.NATIVE_CALL_EXCEPTION);
                    throw failure;
                }
                DecompileResults nativeResult = Objects.requireNonNull(returned);
                checkpoint();
                if (nativeResult.getFunction() != function) throw new IllegalStateException("decompiler returned a different function");
                result = object("completed", nativeResult.decompileCompleted(), "valid", nativeResult.isValid(),
                    "timedOut", diagnostics.timeoutObserved(nativeResult.isTimedOut()), "cancelled", nativeResult.isCancelled(), "failedToStart", nativeResult.failedToStart(),
                    "diagnostic", text(Objects.toString(nativeResult.getErrorMessage(), "")));
                HighFunction high = nativeResult.getHighFunction();
                if (high != null) diagnostics.highFunctionObserved();
                if (nativeResult.isTimedOut()) disposition = "decompile-timeout";
                else if (nativeResult.isCancelled()) disposition = "decompile-cancelled";
                else if (nativeResult.failedToStart()) disposition = "decompiler-start-failed";
                else if (high == null) disposition = nativeResult.decompileCompleted() ? "completed-without-high-function" : "decompiler-error";
                else {
                    if (high.getFunction() != function || high.getLanguage() != program.getLanguage() ||
                        high.getCompilerSpec() != program.getCompilerSpec()) throw new IllegalStateException("HighFunction owner differs from native census");
                    FunctionPrototype proto = high.getFunctionPrototype();
                    LocalSymbolMap local = high.getLocalSymbolMap();
                    if (proto == null || local == null || !proto.isBackedByLocalSymbolMap()) disposition = "unsupported-high-representation";
                    else {
                        int pCount = proto.getNumParams(), lCount = local.getNumParams();
                        if (pCount < 0 || pCount > MAXIMUM_PARAMETERS_PER_FUNCTION || lCount < 0 || lCount > MAXIMUM_PARAMETERS_PER_FUNCTION ||
                            parameters > MAXIMUM_PARAMETERS - lCount) throw new IllegalStateException("inferred parameter bound exceeded");
                        parameters += lCount;
                        var scope = graph.scope("inferred", ordinal);
                        Integer returnType = root(scope, "inferred", ordinal, "inferred-return", -1, proto.getReturnType(), false);
                        Map<String,Object> returnStorage = storage(proto.getReturnStorage());
                        for (int i = 0; i < lCount; i++) {
                            checkpoint(); HighSymbol sym = Objects.requireNonNull(local.getParamSymbol(i));
                            if (sym.getHighFunction() != high) throw new IllegalStateException("parameter symbol owner differs");
                            HighVariable variable = sym.getHighVariable();
                            Integer highSlot = variable instanceof HighParam param ? param.getSlot() : null;
                            Integer type = root(scope, "inferred", ordinal, "inferred-parameter", i, sym.getDataType(), false);
                            params.add(object("index", i, "categoryIndex", sym.getCategoryIndex(), "highParamSlot", highSlot,
                                "highVariableState", variable == null ? "absent" : variable instanceof HighParam ? "parameter" : "other",
                                "nativeIdBits", String.format(Locale.ROOT, "%016x", sym.getId()), "name", nullableText(sym.getName()),
                                "type", type, "typeLocked", sym.isTypeLocked(), "nameLocked", sym.isNameLocked(),
                                "isThisPointer", sym.isThisPointer(), "isHiddenReturn", sym.isHiddenReturn(),
                                "storage", storage(sym.getStorage()), "firstUse", sym.getPCAddress() == null ? null : address(sym.getPCAddress()),
                                "formalEffectiveRelation", "unavailable-native-api", "forcedIndirectMeaning", "unavailable-for-plain-decoded-storage",
                                "allMappings", "first-mapping-only"));
                        }
                        if (proto.getNumParams() != pCount || local.getNumParams() != lCount) throw new IllegalStateException("inferred parameter census changed");
                        prototype = object("parameterCount", pCount, "localSymbolParameterCount", lCount, "parameterCountsMatch", pCount == lCount,
                            "backedByLocalSymbols", true, "modelName", nullableText(proto.getModelName()), "varArgs", proto.isVarArg(),
                            "extraPop", proto.getExtraPop(), "hasThis", proto.hasThisPointer(), "noReturn", proto.hasNoReturn(), "inline", proto.isInline(),
                            "constructor", proto.isConstructor(), "destructor", proto.isDestructor(), "returnType", returnType, "returnStorage", returnStorage,
                            "formalEffectiveRelation", "unavailable-native-api", "allMappings", "first-mapping-only", "privateFlags", "unavailable-native-api");
                        observed++; disposition = "high-function-observed";
                    }
                }
            }
        }
        dispositions.put(disposition, dispositions.get(disposition) + 1);
        for (int i = 0; i < DISPOSITIONS.length; i++) if (DISPOSITIONS[i].equals(disposition)) { diagnostics.disposition(i); break; }
        return object("recordKind", "function", "functionOrdinal", ordinal, "entry", address(function.getEntryPoint()),
            "isExternal", function.isExternal(), "isThunk", function.isThunk(), "disposition", disposition,
            "attempt", attempt, "result", result, "prototype", prototype, "parameters", params);
    }
    private void record(Map<String,Object> value) throws Exception { checkpoint(); output.record(value, recordCount++); }
    private Map<String,Object> summary(Collection<Function> functions) {
        long external = functions.stream().filter(Function::isExternal).count(), thunks = functions.stream().filter(Function::isThunk).count();
        return object("functions", (long)functions.size(), "internalFunctions", functions.size() - external, "externalFunctions", external,
            "thunks", thunks, "attempted", attempted, "observed", observed, "parameters", parameters, "storageVarnodes", storageVarnodes,
            "roots", roots, "graphNodes", graphBudget.nodes(), "graphEdges", graphBudget.edges(), "graphWork", graphBudget.steps(), "dispositions", dispositions,
            "coverage", "all-currently-listed-internal-and-external-functions", "authoritativeOracleEvidence", false,
            "recoveredModelScored", false, "productionInterfacesAdmitted", false, "releaseEligible", false,
            "abiClassification", "not-captured", "sourceTypeIdentity", "not-captured");
    }
    private void inventorySpaces() throws Exception {
        if (program.getAddressFactory().getNumAddressSpaces() > 256) throw new IllegalStateException("native space bound exceeded");
        AddressSpace[] nativeSpaces = program.getAddressFactory().getAllAddressSpaces();
        if (nativeSpaces.length == 0 || nativeSpaces.length > 256) throw new IllegalStateException("native space inventory bound exceeded");
        spaces.addAll(Arrays.asList(nativeSpaces)); spaces.sort(AddressSpace::compareTo);
        for (int i = 0; i < spaces.size(); i++) if (spaceIndices.put(spaces.get(i), i) != null) throw new IllegalStateException("duplicate native space");
    }
    private List<Object> spaceRecords() {
        List<Object> result = new ArrayList<>(spaces.size());
        for (int i = 0; i < spaces.size(); i++) { AddressSpace s = spaces.get(i);
            result.add(object("index", i, "name", text(s.getName()), "type", s.getType(), "sizeBits", s.getSize(),
                "addressableUnitSize", s.getAddressableUnitSize(), "overlay", s.isOverlaySpace(), "signedOffsets", s.hasSignedOffset())); }
        return result;
    }
    private void inventory(FunctionIterator iterator, boolean external, Map<Address,Function> functions) throws Exception {
        while (iterator.hasNext()) {
            checkpoint(); if (functions.size() >= MAXIMUM_FUNCTIONS) throw new IllegalStateException("function census bound exceeded");
            Function f = Objects.requireNonNull(iterator.next());
            if (f.isExternal() != external || functions.put(f.getEntryPoint(), f) != null) throw new IllegalStateException("inconsistent native function census");
            diagnostics.censusInventoried(functions.size());
        }
    }
    private FileIdentity hashFile(Path path, long maximum) throws Exception {
        checkpoint();
        if (!path.toRealPath().equals(path)) throw new IllegalArgumentException("inferred input contains symbolic links");
        BasicFileAttributes before = Files.readAttributes(path, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
        if (!before.isRegularFile() || before.fileKey() == null || before.size() < 1 || before.size() > maximum ||
            ((Number)Files.getAttribute(path, "unix:nlink", LinkOption.NOFOLLOW_LINKS)).longValue() != 1)
            throw new IllegalArgumentException("inferred input must be bounded nonaliased regular file");
        MessageDigest digest = MessageDigest.getInstance("SHA-256"); long bytes = 0;
        try (InputStream source = Files.newInputStream(path, StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS)) {
            try {
                byte[] buffer = new byte[65536]; int n;
                while ((n = source.read(buffer)) != -1) { checkpoint(); bytes = Math.addExact(bytes,n);
                    if (bytes > maximum) throw new IllegalStateException("inferred input bound exceeded"); digest.update(buffer,0,n); }
            } catch (Exception | Error failure) {
                reportFailure(failure, FailureDiagnostics.FailureKind.VALIDATION_OR_OUTPUT);
                throw failure;
            }
        }
        BasicFileAttributes after = Files.readAttributes(path, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
        if (bytes != before.size() || !sameIdentity(before,after)) throw new IllegalStateException("input changed during hashing");
        return new FileIdentity(bytes, HexFormat.of().formatHex(digest.digest()), after);
    }
    private static boolean sameIdentity(BasicFileAttributes a, BasicFileAttributes b) {
        return b.isRegularFile() && b.fileKey() != null && a.fileKey().equals(b.fileKey()) && a.size() == b.size() && a.lastModifiedTime().equals(b.lastModifiedTime());
    }
    private static void requireContent(FileIdentity a, FileIdentity b) {
        if (a.bytes != b.bytes || !a.sha256.equals(b.sha256)) throw new IllegalStateException("listing snapshot does not match current native Program");
    }
    private static void requireUnchanged(FileIdentity a, FileIdentity b) {
        requireContent(a,b); if (!sameIdentity(a.attributes,b.attributes)) throw new IllegalStateException("inferred input replaced during capture");
    }
    private record FileIdentity(long bytes, String sha256, BasicFileAttributes attributes) {}
    private static String sha(byte[] value) throws Exception { return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value)); }
    private void requireProgramUnchanged(long modification) {
        if (program.getModificationNumber() != modification) throw new IllegalStateException("native Program changed during inference");
    }
    private static void removeComparison(Path path) throws IOException {
        if (!Files.exists(path, LinkOption.NOFOLLOW_LINKS)) return;
        Files.deleteIfExists(path.resolve("manifest.json")); Files.deleteIfExists(path.resolve("native-interfaces.json")); Files.deleteIfExists(path);
    }

    private Map<String, Object> storage(VariableStorage storage) throws Exception {
        if (storage == null) return object("state", "absent", "size", null, "autoStorage", null, "autoParameterType", null,
            "forcedIndirect", null, "varnodes", List.of());
        int count = storage.getVarnodeCount();
        if (count < 0 || count > MAXIMUM_VARNODES_PER_STORAGE || storageVarnodes > MAXIMUM_VARNODES - count) throw new IllegalStateException("native storage population bound exceeded");
        storageVarnodes += count;
        Varnode[] nativeVarnodes = storage.getVarnodes();
        if (nativeVarnodes.length != count) throw new IllegalStateException("native storage count changed");
        List<Object> pieces = new ArrayList<>(count);
        long totalSize = 0;
        for (Varnode varnode : nativeVarnodes) {
            task.checkCancelled();
            if (varnode == null || varnode.getSize() <= 0) throw new IllegalStateException("invalid native storage piece");
            totalSize = Math.addExact(totalSize, varnode.getSize());
            pieces.add(object("address", address(varnode.getAddress()), "size", varnode.getSize()));
        }
        // VariableStorage.size() is documented as the total size of its ordered varnodes.
        if (totalSize != storage.size()) throw new IllegalStateException("native storage size differs from its pieces");
        String state = storage.isBadStorage() ? "bad" : storage.isUnassignedStorage() ? "unassigned" : storage.isVoidStorage() ? "void" : "assigned";
        var auto = storage.getAutoParameterType();
        return object("state", state, "size", storage.size(), "autoStorage", storage.isAutoStorage(),
            "autoParameterType", auto == null ? null : auto.name(), "forcedIndirect", storage.isForcedIndirect(), "varnodes", pieces);
    }

    private int compare(Address left, Address right) {
        if (left.equals(Address.NO_ADDRESS) || right.equals(Address.NO_ADDRESS)) return left.equals(right) ? 0 : left.equals(Address.NO_ADDRESS) ? -1 : 1;
        Integer l = spaceIndices.get(left.getAddressSpace()), r = spaceIndices.get(right.getAddressSpace());
        if (l == null || r == null) throw new IllegalArgumentException("unrepresented native address space");
        int order = Integer.compare(l, r);
        return order != 0 ? order : spaces.get(l).hasSignedOffset() ? Long.compare(left.getOffset(), right.getOffset()) : Long.compareUnsigned(left.getOffset(), right.getOffset());
    }
    private Map<String, Object> address(Address value) {
        Objects.requireNonNull(value, "null native address");
        if (value.equals(Address.NO_ADDRESS)) return object("kind", "no-address");
        Integer index = spaceIndices.get(value.getAddressSpace());
        if (index == null) throw new IllegalArgumentException("unrepresented native address space");
        return object("kind", "address", "spaceIndex", index, "offsetBits", String.format(Locale.ROOT, "%016x", value.getOffset()));
    }
    private static Path privateTemporary(Path directory, String prefix) throws IOException {
        return Files.createTempFile(directory, prefix, ".tmp", PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")));
    }
    private static String digest(String value) {
        if (value == null || !value.matches("[0-9a-f]{64}")) throw new IllegalArgumentException("invalid native-interface digest binding");
        return value;
    }
    private static String nullableText(String value) { return value == null ? null : text(value); }
    private static String text(String value) {
        Objects.requireNonNull(value, "native metadata unavailable");
        // Check code-unit and UTF-8 budgets before an encoding allocation.
        if (value.length() > MAXIMUM_STRING_BYTES) throw new IllegalStateException("native metadata string bound exceeded");
        int bytes = 0;
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (Character.isHighSurrogate(c)) {
                if (i + 1 == value.length() || !Character.isLowSurrogate(value.charAt(++i))) throw new IllegalStateException("invalid native Unicode metadata");
                bytes += 4;
            } else if (Character.isLowSurrogate(c)) throw new IllegalStateException("invalid native Unicode metadata");
            else bytes += c < 0x80 ? 1 : c < 0x800 ? 2 : 3;
            if (bytes > MAXIMUM_STRING_BYTES) throw new IllegalStateException("native metadata string bound exceeded");
        }
        return value;
    }

    /**
     * Passive, fixed-capacity observations only. No Program/result/exception references survive a
     * transition. The owner supplies its real monotonic samples; numeric samples are also usable
     * by package-local controls without providing a collector clock or producer override.
     */
    static final class FailureDiagnostics {
        enum Stage { INPUT_VALIDATION, CENSUS, LISTING_COMPARISON, LISTING_ROOTS, DECOMPILER_SETUP,
            NATIVE_PRECHECK, NATIVE_CALL, HIGH_EXTRACTION, FUNCTION_RECORD, FINAL_VALIDATION, PUBLICATION }
        enum FailureKind { OPERATION_DEADLINE, INSUFFICIENT_WHOLE_SECOND, CANCELLATION_OBSERVED,
            NATIVE_CALL_EXCEPTION, VALIDATION_OR_OUTPUT }
        private static final String[] STAGES = {"input-validation", "census", "listing-comparison", "listing-roots",
            "decompiler-setup", "native-precheck", "native-call", "high-extraction", "function-record",
            "final-validation", "publication"};
        private static final String[] FAILURES = {"operation-deadline", "insufficient-whole-second",
            "cancellation-observed", "native-call-exception", "validation-or-output"};
        private static final String[] CALL_STATES = {"not-started", "in-flight", "returned"};
        private static final String PREFIX = "DECOMP_INFERRED_FAILURE_V1 ";
        private static final int MAXIMUM_FRAME_BYTES = 4096;
        private final long started;
        private final long[] stageNanos = new long[11], dispositionCounts = new long[9];
        private final int[] slowOrdinals = new int[4], slowSpaces = new int[4];
        private final long[] slowOffsets = new long[4], slowNanos = new long[4];
        private final byte[] slowTimedOut = new byte[4]; // -1 unread, 0 false, 1 true
        private int stage, failureKind, reported, inventoried, ordinal = -1, space, callState, timeoutSeconds, slowCount;
        private boolean reportedKnown, inventoriedKnown, censusValid, allocationKnown, frozen, unavailable, emitted;
        private long stageStarted, offsetBits, callStarted, callElapsed, startedCalls, returnedCalls, writtenFunctions,
            observedHighFunctions, dispositionTotal, elapsedAtFailure, remainingAtFailure, wholeSecondsAtFailure;

        FailureDiagnostics(long startedNanos) { started = startedNanos; stageStarted = startedNanos; }
        synchronized void omit() { if (!frozen) unavailable = true; }
        private boolean mutable() { return !frozen && !unavailable; }
        private boolean chargeStage(long now) {
            long duration = now - stageStarted;
            if (duration < 0 || stageNanos[stage] > Long.MAX_VALUE - duration) { unavailable = true; return false; }
            stageNanos[stage] += duration; stageStarted = now;
            return true;
        }
        synchronized void stage(Stage value, long now) {
            if (!mutable()) return;
            if (value == null) { unavailable = true; return; }
            if (chargeStage(now)) stage = value.ordinal();
        }
        synchronized void censusReported(int count) {
            if (!mutable()) return;
            // An out-of-bound native getter is still an actually observed bounded Java int.
            reported = count; reportedKnown = true;
        }
        synchronized void censusInventoried(int count) {
            if (!mutable()) return;
            if (count < 0 || count > MAXIMUM_FUNCTIONS) { unavailable = true; return; }
            inventoried = count; inventoriedKnown = true;
        }
        synchronized void censusValidated() {
            if (!mutable()) return;
            if (!reportedKnown || !inventoriedKnown || reported != inventoried) { unavailable = true; return; }
            censusValid = true;
        }
        synchronized void function(int functionOrdinal, int spaceIndex, long bits) {
            if (!mutable()) return;
            if (functionOrdinal < 0 || functionOrdinal >= MAXIMUM_FUNCTIONS || spaceIndex < 0 || spaceIndex >= 256 || callState == 1) {
                unavailable = true; return;
            }
            ordinal = functionOrdinal; space = spaceIndex; offsetBits = bits;
            callState = 0; allocationKnown = false; callElapsed = 0;
        }
        synchronized void allocation(int seconds) {
            if (!mutable()) return;
            if (ordinal < 0 || callState != 0 || seconds > 60) { unavailable = true; return; }
            timeoutSeconds = seconds; allocationKnown = true;
        }
        synchronized void nativeStarted(long now) {
            if (!mutable()) return;
            if (ordinal < 0 || callState != 0 || !allocationKnown || timeoutSeconds < 1 || startedCalls >= MAXIMUM_FUNCTIONS) {
                unavailable = true; return;
            }
            if (!chargeStage(now)) return;
            stage = Stage.NATIVE_CALL.ordinal(); callStarted = now; callState = 1; startedCalls++;
        }
        synchronized void nativeReturned(long now) {
            if (!mutable()) return;
            long duration = now - callStarted;
            if (callState != 1 || duration < 0 || returnedCalls >= startedCalls) { unavailable = true; return; }
            if (!chargeStage(now)) return;
            stage = Stage.HIGH_EXTRACTION.ordinal(); callElapsed = duration; callState = 2; returnedCalls++;
            int position = 0;
            while (position < slowCount && (slowNanos[position] > duration ||
                    slowNanos[position] == duration && slowOrdinals[position] < ordinal)) position++;
            if (position == 4) return;
            for (int i = Math.min(slowCount, 3); i > position; i--) {
                slowOrdinals[i] = slowOrdinals[i - 1]; slowSpaces[i] = slowSpaces[i - 1];
                slowOffsets[i] = slowOffsets[i - 1]; slowNanos[i] = slowNanos[i - 1]; slowTimedOut[i] = slowTimedOut[i - 1];
            }
            slowOrdinals[position] = ordinal; slowSpaces[position] = space; slowOffsets[position] = offsetBits;
            slowNanos[position] = duration; slowTimedOut[position] = -1; slowCount = Math.min(4, slowCount + 1);
        }
        synchronized boolean timeoutObserved(boolean timedOut) {
            if (mutable()) {
                if (callState != 2) unavailable = true;
                else for (int i = 0; i < slowCount; i++) if (slowOrdinals[i] == ordinal) slowTimedOut[i] = (byte)(timedOut ? 1 : 0);
            }
            return timedOut;
        }
        synchronized void disposition(int index) {
            if (!mutable()) return;
            if (index < 0 || index >= dispositionCounts.length || dispositionTotal >= MAXIMUM_FUNCTIONS) { unavailable = true; return; }
            dispositionCounts[index]++; dispositionTotal++;
        }
        synchronized void functionRecordWritten() {
            if (!mutable()) return;
            if (writtenFunctions >= MAXIMUM_FUNCTIONS) { unavailable = true; return; }
            writtenFunctions++;
        }
        synchronized void highFunctionObserved() {
            if (!mutable()) return;
            if (observedHighFunctions >= MAXIMUM_FUNCTIONS) { unavailable = true; return; }
            observedHighFunctions++;
        }
        synchronized void freeze(FailureKind kind, long now) {
            if (!mutable()) return;
            long elapsed = now - started;
            if (kind == null || elapsed < 0 || !chargeStage(now)) { unavailable = true; return; }
            if (callState == 1) {
                callElapsed = now - callStarted;
                if (callElapsed < 0) { unavailable = true; return; }
            }
            failureKind = kind.ordinal(); elapsedAtFailure = elapsed;
            remainingAtFailure = MAXIMUM_OPERATION_MILLIS * 1000000L - elapsed;
            // Match the owner's existing whole-millisecond/whole-second allocation arithmetic.
            wholeSecondsAtFailure = kind == FailureKind.INSUFFICIENT_WHOLE_SECOND && allocationKnown ? timeoutSeconds :
                (MAXIMUM_OPERATION_MILLIS - elapsed / 1000000L) / 1000L;
            frozen = true;
        }
        synchronized String frame() {
            if (!frozen || unavailable) return null;
            try {
                Frame out = new Frame();
                out.put(PREFIX).put("{\"authority\":\"diagnostic-only\",\"census\":{\"reportedFunctions\":");
                out.nullable(reportedKnown, reported).put(",\"inventoriedFunctions\":").nullable(inventoriedKnown, inventoried)
                    .put(",\"validated\":").bool(censusValid).put("},\"clock\":{\"maximumOperationMillis\":120000,\"elapsedNanosAtFailure\":")
                    .number(elapsedAtFailure).put(",\"remainingNanosAtFailure\":").number(remainingAtFailure)
                    .put(",\"wholeSecondsAvailable\":").number(wholeSecondsAtFailure).put(",\"currentCallElapsedNanos\":")
                    .nullable(callState != 0, callElapsed).put("},\"complete\":false,\"counts\":{\"nativeCallsStarted\":")
                    .number(startedCalls).put(",\"nativeCallsReturned\":").number(returnedCalls)
                    .put(",\"functionRecordsWritten\":").number(writtenFunctions).put(",\"highFunctionsObserved\":")
                    .number(observedHighFunctions).put(",\"dispositions\":{");
                for (int i = 0; i < dispositionCounts.length; i++) {
                    if (i != 0) out.put(",");
                    out.put("\"").put(DISPOSITIONS[i]).put("\":").number(dispositionCounts[i]);
                }
                out.put("}},\"currentFunction\":");
                if (ordinal < 0) out.put("null");
                else out.put("{\"ordinal\":").number(ordinal).put(",\"space\":").number(space).put(",\"offsetBits\":\"")
                    .hex(offsetBits).put("\",\"callState\":\"").put(CALL_STATES[callState]).put("\",\"timeoutSeconds\":")
                    .nullable(allocationKnown, timeoutSeconds).put("}");
                out.put(",\"failureKind\":\"").put(FAILURES[failureKind])
                    .put("\",\"productionInterfacesAdmitted\":false,\"provider\":\"ghidra-inferred-interface-failure-diagnostic-v1\",\"releaseEligible\":false,\"schemaVersion\":1,\"slowestReturnedCalls\":[");
                for (int i = 0; i < slowCount; i++) {
                    if (i != 0) out.put(",");
                    out.put("{\"ordinal\":").number(slowOrdinals[i]).put(",\"space\":").number(slowSpaces[i])
                        .put(",\"offsetBits\":\"").hex(slowOffsets[i]).put("\",\"elapsedNanos\":").number(slowNanos[i])
                        .put(",\"timedOut\":").put(slowTimedOut[i] < 0 ? "null" : slowTimedOut[i] == 1 ? "true" : "false").put("}");
                }
                out.put("],\"stage\":\"").put(STAGES[stage]).put("\",\"stageNanos\":{");
                for (int i = 0; i < stageNanos.length; i++) {
                    if (i != 0) out.put(",");
                    out.put("\"").put(STAGES[i]).put("\":").number(stageNanos[i]);
                }
                return out.put("}}\n").value();
            } catch (Throwable diagnosticFailure) { unavailable = true; return null; }
        }
        synchronized void emitOnce(PrintStream stream) {
            if (!frozen || emitted) return;
            emitted = true;
            try {
                String value = frame();
                if (value != null) stream.print(value);
            } catch (Throwable diagnosticFailure) { /* Never replace the owner's failure. */ }
        }
        /** Every appended string is fixed ASCII or bounded primitive formatting. */
        private static final class Frame {
            private final StringBuilder bytes = new StringBuilder(MAXIMUM_FRAME_BYTES);
            private boolean bounded = true;
            Frame put(String value) {
                if (!bounded || value.length() > MAXIMUM_FRAME_BYTES - bytes.length()) { bounded = false; return this; }
                bytes.append(value); return this;
            }
            Frame number(long value) { return put(Long.toString(value)); }
            Frame bool(boolean value) { return put(value ? "true" : "false"); }
            Frame nullable(boolean present, long value) { return present ? number(value) : put("null"); }
            Frame hex(long value) {
                String text = Long.toHexString(value);
                for (int i = text.length(); i < 16; i++) put("0");
                return put(text);
            }
            String value() { return bounded ? bytes.toString() : null; }
        }
    }

    private static Map<String, Object> object(Object... pairs) {
        TreeMap<String, Object> value = new TreeMap<>();
        for (int i = 0; i < pairs.length; i += 2) {
            String key = (String) pairs[i];
            if (value.containsKey(key)) throw new IllegalStateException("duplicate schema field");
            value.put(key, pairs[i + 1]);
        }
        return value;
    }
    private static byte[] canonical(Object value, int limit) throws Exception {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        try (BoundedOutput output = new BoundedOutput(bytes, null, limit, TaskMonitor.DUMMY)) {
            encode(value, 0, output); output.writeUtf8("\n");
        }
        return bytes.toByteArray();
    }
    private static void encode(Object value, int indentation, BoundedOutput output) throws Exception {
        if (indentation > 32) throw new IllegalStateException("native JSON depth bound exceeded");
        if (value == null) { output.writeUtf8("null"); return; }
        if (value instanceof Map<?, ?> map) {
            if (map.isEmpty()) { output.writeUtf8("{}"); return; }
            output.writeUtf8("{\n"); int i = 0;
            for (var entry : map.entrySet()) {
                if (i++ > 0) output.writeUtf8(",\n"); output.spaces(indentation + 2);
                encode(entry.getKey(), indentation + 2, output); output.writeUtf8(": "); encode(entry.getValue(), indentation + 2, output);
            }
            output.writeUtf8("\n"); output.spaces(indentation); output.writeUtf8("}"); return;
        }
        if (value instanceof List<?> list) {
            if (list.isEmpty()) { output.writeUtf8("[]"); return; }
            output.writeUtf8("[\n"); int i = 0;
            for (Object entry : list) {
                if (i++ > 0) output.writeUtf8(",\n"); output.spaces(indentation + 2); encode(entry, indentation + 2, output);
            }
            output.writeUtf8("\n"); output.spaces(indentation); output.writeUtf8("]"); return;
        }
        if (value instanceof String s) {
            output.writeUtf8("\""); int start = 0;
            for (int i = 0; i < s.length(); i++) {
                char c = s.charAt(i);
                String escape = switch (c) {
                    case '"' -> "\\\""; case '\\' -> "\\\\"; case '\b' -> "\\b"; case '\t' -> "\\t";
                    case '\n' -> "\\n"; case '\f' -> "\\f"; case '\r' -> "\\r";
                    default -> c < 32 ? String.format(Locale.ROOT, "\\u%04x", (int) c) : null;
                };
                if (escape != null) { output.writeUtf8(s.substring(start, i)); output.writeUtf8(escape); start = i + 1; }
            }
            output.writeUtf8(s.substring(start)); output.writeUtf8("\""); return;
        }
        if (value instanceof Boolean || value instanceof Integer || value instanceof Long) { output.writeUtf8(value.toString()); return; }
        throw new IllegalStateException("unsupported canonical value");
    }
    private static final class BoundedOutput extends OutputStream {
        final OutputStream output; final MessageDigest digest; final long maximum; final TaskMonitor monitor; long bytes;
        BoundedOutput(OutputStream output, MessageDigest digest, long maximum, TaskMonitor monitor) {
            this.output = output; this.digest = digest; this.maximum = maximum; this.monitor = monitor;
        }
        @Override public void write(int value) throws IOException { write(new byte[] { (byte) value }); }
        @Override public void write(byte[] value, int offset, int length) throws IOException {
            if (bytes > maximum - length) throw new IOException("native JSON byte bound exceeded");
            bytes += length; output.write(value, offset, length); if (digest != null) digest.update(value, offset, length);
        }
        void writeUtf8(String value) throws Exception { monitor.checkCancelled(); write(value.getBytes(StandardCharsets.UTF_8)); }
        void spaces(int count) throws Exception { writeUtf8(" ".repeat(count)); }
        void value(Object value, int indentation, boolean first) throws Exception {
            byte[] encoded = canonical(value, MAXIMUM_RECORD_BYTES);
            long renderedBytes = encoded.length - 1L + (first ? indentation : 0);
            for (int i = 0; i < encoded.length - 1; i++) if (encoded[i] == '\n') renderedBytes += indentation;
            if (renderedBytes > MAXIMUM_RECORD_BYTES) throw new IOException("indented native record exceeds its byte bound");
            if (first) spaces(indentation);
            int start = 0;
            for (int i = 0; i < encoded.length - 1; i++) if (encoded[i] == '\n') {
                write(encoded, start, i - start); writeUtf8("\n"); spaces(indentation); start = i + 1;
            }
            write(encoded, start, encoded.length - 1 - start);
        }
        void record(Object value, long index) throws Exception { writeUtf8(index == 0 ? "[\n" : ",\n"); value(value, 4, true); }
        @Override public void flush() throws IOException { output.flush(); }
        @Override public void close() throws IOException { output.close(); }
    }
}
