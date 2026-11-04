import ghidra.program.model.data.*;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.*;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;
import java.lang.reflect.*;
import java.nio.file.*;
import java.util.*;

/** Authored typed API controls against the active exporter; no native inference or ABI authority. */
public final class OwnedExporterPrototypeProbe {
    static void check(boolean value, Object message) { if (!value) throw new AssertionError(message); }
    static final class Symbol extends HighSymbol {
        Symbol(String name, DataType type) { super(1, name, type, false, false, null); }
    }
    static class Prototype extends FunctionPrototype {
        DataType result;
        HighSymbol[] symbols;
        boolean variadic;
        int count;
        Prototype(DataType result, HighSymbol... symbols) {
            super((LocalSymbolMap)null, OwnedExporterReferencedBytesProbe.proxy(Function.class, (m,a) -> null));
            this.result = result; this.symbols = symbols; count = symbols.length;
        }
        @Override public DataType getReturnType() { return result; }
        @Override public int getNumParams() { return count; }
        @Override public HighSymbol getParam(int index) { return symbols[index]; }
        @Override public boolean isVarArg() { return variadic; }
    }
    static ExportProgramModelOwned.PrototypeResult extract(Prototype prototype) throws Exception {
        return ExportProgramModelOwned.extractTypedPrototype(prototype, "probe", TaskMonitor.DUMMY);
    }
    static void refused(Prototype prototype, ExportProgramModelOwned.PrototypeRefusalCode code) throws Exception {
        var result = extract(prototype);
        check(result.typed == null && result.refusal != null && result.refusal.code == code,
            "expected " + code + ", got " + (result.refusal == null ? result.typed.declaration : result.refusal.code + ":" + result.refusal.detail));
    }
    static final class GuardedInteger extends IntegerDataType {
        int displays, clones;
        @Override public String getDisplayName() { displays++; return super.getDisplayName(); }
        @Override public IntegerDataType clone(DataTypeManager manager) { clones++; return super.clone(manager); }
    }
    static void boundsAndCancellation() throws Exception {
        GuardedInteger guarded = new GuardedInteger();
        Prototype tooMany = new Prototype(guarded); tooMany.count = 257;
        refused(tooMany, ExportProgramModelOwned.PrototypeRefusalCode.LIMIT);
        check(guarded.displays == 0 && guarded.clones == 0, "count limit before display/clone");
        HighSymbol[] symbols = new HighSymbol[256];
        for (int i = 0; i < symbols.length; i++) symbols[i] = new Symbol("arg_" + i, IntegerDataType.dataType);
        check(extract(new Prototype(IntegerDataType.dataType, symbols)).typed.parameters.size() == 256, "256 typed parameters");
        DataType deep = IntegerDataType.dataType;
        for (int i = 0; i < 32; i++) deep = new PointerDataType(deep, 8);
        check(extract(new Prototype(deep)).typed != null, "depth 32");
        refused(new Prototype(new PointerDataType(deep, 8)), ExportProgramModelOwned.PrototypeRefusalCode.LIMIT);
        Pointer[] cycle = new Pointer[1];
        cycle[0] = OwnedExporterReferencedBytesProbe.proxy(Pointer.class, (m,a) -> {
            if (m.getName().equals("getDataType")) return cycle[0];
            if (m.getName().equals("getLength")) return 8;
            if (m.getName().equals("getDisplayName") || m.getName().equals("clone") || m.getName().equals("getPathName"))
                throw new AssertionError("cycle must be rejected before recursive spelling/clone");
            return null;
        });
        refused(new Prototype(cycle[0]), ExportProgramModelOwned.PrototypeRefusalCode.UNSUPPORTED_SHAPE);
        TaskMonitorAdapter cancelled = new TaskMonitorAdapter(true); cancelled.cancel();
        try {
            ExportProgramModelOwned.extractTypedPrototype(new Prototype(IntegerDataType.dataType), "probe", cancelled);
            throw new AssertionError("pre-cancelled extraction returned");
        } catch (InterruptedException expected) { }
        TaskMonitorAdapter during = new TaskMonitorAdapter(true);
        Prototype trigger = new Prototype(IntegerDataType.dataType, new Symbol("value", IntegerDataType.dataType)) {
            @Override public HighSymbol getParam(int index) { during.cancel(); return super.getParam(index); }
        };
        try {
            ExportProgramModelOwned.extractTypedPrototype(trigger, "probe", during);
            throw new AssertionError("mid-extraction cancellation returned");
        } catch (InterruptedException expected) { }
        check(!Thread.currentThread().isInterrupted(), "probe monitor controls do not alter thread flag");
        System.out.println("owned prototype bounds and cancellation passed");
    }
    static Class<?> nested(String name) {
        return Arrays.stream(ExportProgramModelOwned.class.getDeclaredClasses()).filter(t -> t.getSimpleName().equals(name)).findFirst().orElseThrow();
    }
    static Object metadata(boolean complete, ExportProgramModelOwned.PlannedTypeCoverage coverage) throws Exception {
        Constructor<?> constructor = nested("FunctionMetadata").getDeclaredConstructors()[0]; constructor.setAccessible(true);
        return constructor.newInstance(null, "    {\n      \"id\": \"fn_0000000000001000\",\n      \"name\": \"probe\",\n      \"address\": \"0x1000\",\n",
            "probe", "void probe(void)", "      \"recoveryAssessment\": \"unassessed\",\n      \"calls\": [],\n      \"referencedGlobals\": [],\n      \"strings\": [],\n",
            complete ? null : "metadataRefusal=AUTHORED_INCOMPLETE", complete, coverage);
    }
    static Object render(Object metadata, ExportProgramModelOwned.NativeOutcome outcome, boolean full) throws Exception {
        return OwnedExporterReferencedBytesProbe.invoke(new ExportProgramModelOwned(), "renderFunction",
            new Class<?>[]{nested("FunctionMetadata"), ExportProgramModelOwned.NativeOutcome.class, boolean.class}, metadata, outcome, full);
    }
    static void renderingAndBindings(Path root) throws Exception {
        Files.createDirectories(root);
        var coverage = new ExportProgramModelOwned.PlannedTypeCoverage(Map.of());
        var typed = extract(new Prototype(IntegerDataType.dataType, new Symbol("value", IntegerDataType.dataType)));
        var refused = new ExportProgramModelOwned.PrototypeResult(null,
            new ExportProgramModelOwned.Refusal(ExportProgramModelOwned.PrototypeRefusalCode.NULL_TYPE, "AUTHORED_NULL_TYPE"));
        for (boolean complete : new boolean[]{false, true}) for (String source : new String[]{null, "int probe(int value) { return value; }"}) {
            for (var prototype : List.of(typed, refused)) {
                Object rendered = render(metadata(complete, coverage), new ExportProgramModelOwned.NativeOutcome(source, "native-authored-diagnostic", prototype), true);
                String status = (String)OwnedExporterReferencedBytesProbe.get(rendered, "status");
                check(status.equals(source == null ? "failed" : complete && prototype.typed != null ? "recovered" : "partial"), "full status matrix");
                String record = (String)OwnedExporterReferencedBytesProbe.get(rendered, "record");
                String failure = (String)OwnedExporterReferencedBytesProbe.get(rendered, "failure");
                check(record.contains("\"recoveryAssessment\": \"unassessed\"") && !record.contains("\"prototypeSource\""), "schema 4 stays exact/unassessed");
                check(record.contains(prototype.typed == null ? "void probe(void)" : typed.typed.declaration), "one whole selected prototype");
                check(failure.contains("native-authored-diagnostic") &&
                    (prototype.typed != null || failure.contains("prototypeSource=listing;prototypeRefusal=NULL_TYPE")), "independent failures survive");
            }
            Object planning = render(metadata(complete, coverage), null, false);
            check(OwnedExporterReferencedBytesProbe.get(planning, "status").equals(complete ? "partial" : "failed"), "planning status unchanged");
            check(((String)OwnedExporterReferencedBytesProbe.get(planning, "record")).contains("void probe(void)"), "exact planning prototype retained");
        }
        var sameTextTyped = extract(new Prototype(VoidDataType.dataType));
        Object actualTyped = render(metadata(true, coverage), new ExportProgramModelOwned.NativeOutcome("void probe(void) {}", null, sameTextTyped), true);
        Object sameListing = render(metadata(true, coverage), new ExportProgramModelOwned.NativeOutcome("void probe(void) {}", null, refused), true);
        check(OwnedExporterReferencedBytesProbe.get(actualTyped, "status").equals("recovered") &&
            OwnedExporterReferencedBytesProbe.get(sameListing, "status").equals("partial"), "identical prototype spelling cannot confer typed provenance");
        try { render(metadata(true, coverage), null, true); throw new AssertionError("full null outcome accepted"); }
        catch (InvocationTargetException expected) { check(expected.getCause() instanceof IllegalArgumentException, expected); }
        Object exporter = new ExportProgramModelOwned();
        Path record = root.resolve("fn_0000000000001000.json");
        Path failures = Files.createDirectories(root.resolve("failures"));
        Path sidecar = failures.resolve(record.getFileName());
        Path binding = root.resolve(record.getFileName() + ".binding");
        Object rendered = render(metadata(true, coverage), new ExportProgramModelOwned.NativeOutcome("source", null, refused), true);
        Files.writeString(record, (String)OwnedExporterReferencedBytesProbe.get(rendered, "record"));
        Files.writeString(sidecar, "prototypeSource=listing;prototypeRefusal=NULL_TYPE");
        String identity = (String)OwnedExporterReferencedBytesProbe.invoke(exporter, "currentFullBinding", new Class<?>[]{Path.class, Path.class}, record, sidecar);
        Files.writeString(binding, identity);
        check((boolean)OwnedExporterReferencedBytesProbe.invoke(exporter, "acceptedFullCheckpoint", new Class<?>[]{Path.class, Path.class}, record, failures), "exact function/failure reuse");
        String original = Files.readString(record), failure = Files.readString(sidecar);
        for (int mutation = 0; mutation < 4; mutation++) {
            Files.writeString(record, original); Files.writeString(sidecar, failure); Files.writeString(binding, identity);
            if (mutation == 0) Files.writeString(record, original.replace("void probe(void)", "int probe(int x)"));
            if (mutation == 1) Files.delete(sidecar);
            if (mutation == 2) Files.writeString(sidecar, failure.replace("NULL_TYPE", "NO_HIGH_FUNCTION"));
            if (mutation == 3) Files.delete(binding);
            try {
                OwnedExporterReferencedBytesProbe.invoke(exporter, "acceptedFullCheckpoint", new Class<?>[]{Path.class, Path.class}, record, failures);
                throw new AssertionError("mutated full checkpoint accepted: " + mutation);
            } catch (InvocationTargetException expected) { check(expected.getCause().getClass().getSimpleName().equals("PlanningIntegrityException"), expected); }
        }
        Files.writeString(record, original);
        Object bound = OwnedExporterReferencedBytesProbe.invoke(exporter, "bindCurrentFile", new Class<?>[]{Path.class, List.class}, record, List.of("fn_0000000000001000"));
        OwnedExporterReferencedBytesProbe.invoke(exporter, "verifyBoundFragment", new Class<?>[]{nested("BoundFragment")}, bound);
        Files.writeString(record, original.replace("void probe(void)", "long probe(void)"));
        try {
            OwnedExporterReferencedBytesProbe.invoke(exporter, "verifyBoundFragment", new Class<?>[]{nested("BoundFragment")}, bound);
            throw new AssertionError("full function prototype changed after binding without refusal");
        } catch (InvocationTargetException failureAfterBinding) {
            check(failureAfterBinding.getCause().getClass().getSimpleName().equals("PlanningIntegrityException"), failureAfterBinding);
        }
        System.out.println("owned full status schema refusal and checkpoint binding controls passed");
    }
    static void typeClosureControls(Path root) throws Exception {
        Files.createDirectories(root);
        ExportProgramModelOwned exporter = new ExportProgramModelOwned();
        OwnedExporterReferencedBytesProbe.field(exporter, "monitor", TaskMonitor.DUMMY);
        var space = new ghidra.program.model.address.GenericAddressSpace("ram", 64, ghidra.program.model.address.AddressSpace.TYPE_RAM, 0);
        Path types = Files.createDirectories(root.resolve("types"));
        Class<?> planning = nested("PlanningBatchEvidence");
        Class<?>[] parameters = {List.class, Path.class, planning, ghidra.program.model.address.Address.class};
        var before = (ExportProgramModelOwned.PlannedTypeCoverage)OwnedExporterReferencedBytesProbe.invoke(exporter, "planTypeCoverage", parameters,
            List.of(IntegerDataType.dataType), types, null, space.getAddress(0x1000));
        TypeDef alias = new TypedefDataType("OwnedCount", IntegerDataType.dataType);
        var snapshot = (ExportProgramModelOwned.PlannedTypeCoverage)OwnedExporterReferencedBytesProbe.invoke(exporter, "planTypeCoverage", parameters,
            List.of(new PointerDataType(alias, 8)), types, null, space.getAddress(0x1000));
        var typed = extract(new Prototype(IntegerDataType.dataType, new Symbol("count", new PointerDataType(alias, 8))));
        check(typed.typed != null && ExportProgramModelOwned.checkCoverage(typed.typed, snapshot) == null, "coordinator plans pointer dependency using identical descriptor and id");
        check(ExportProgramModelOwned.checkCoverage(typed.typed, before).code == ExportProgramModelOwned.PrototypeRefusalCode.UNPLANNED_TYPE, "future type cannot modify earlier snapshot");
        var requirement = typed.typed.requirements.get(0);
        Path record = types.resolve(requirement.id + ".json");
        String first = Files.readString(record);
        check(first.contains("OwnedCount") && first.contains("0x1000"), "named declaration and first source owner retained");
        OwnedExporterReferencedBytesProbe.invoke(exporter, "planTypeCoverage", parameters,
            List.of(alias), types, null, space.getAddress(0x2000));
        check(Files.readString(record).equals(first), "later planning cannot change first owner");
        var changed = extract(new Prototype(IntegerDataType.dataType, new Symbol("count", new PointerDataType(new TypedefDataType("OwnedCount", LongDataType.dataType), 8))));
        check(changed.typed != null && ExportProgramModelOwned.checkCoverage(changed.typed, snapshot).code == ExportProgramModelOwned.PrototypeRefusalCode.TYPE_MISMATCH,
            "same-path changed native definition refuses");
        for (DataType invalid : List.of(new TypedefDataType("OwnedCount", LongDataType.dataType),
            new TypedefDataType(new CategoryPath("/other"), "OwnedCount", IntegerDataType.dataType))) {
            try {
                OwnedExporterReferencedBytesProbe.invoke(exporter, "planTypeCoverage", parameters,
                    List.of(invalid), types, null, space.getAddress(0x3000));
                throw new AssertionError("planning collision accepted");
            } catch (InvocationTargetException failure) {
                check(failure.getCause() instanceof ExportProgramModelOwned.PrototypeRejected &&
                    ((ExportProgramModelOwned.PrototypeRejected)failure.getCause()).refusal.code == ExportProgramModelOwned.PrototypeRefusalCode.TYPE_MISMATCH,
                    "planning collision explicit refusal");
            }
        }
        check(Files.readString(record).equals(first), "collision cannot overwrite retained definition");
        System.out.println("owned deterministic type closure and immutable coverage controls passed");
    }

    static final class InitializationDecompiler extends ghidra.app.decompiler.DecompInterface {
        final int failAt;
        int syntax, ccode, opens, stops, disposals;
        InitializationDecompiler(int failAt) { this.failAt = failAt; }
        @Override public boolean toggleSyntaxTree(boolean enabled) { check(enabled, "syntax tree enabled"); syntax++; return failAt != 0; }
        @Override public boolean toggleCCode(boolean enabled) { check(enabled, "C rendering enabled"); ccode++; return failAt != 1; }
        @Override public boolean openProgram(ghidra.program.model.listing.Program program) { opens++; return false; }
        @Override public boolean setOptions(ghidra.app.decompiler.DecompileOptions options) { return true; }
        @Override public void stopProcess() { stops++; }
        @Override public void dispose() { disposals++; }
    }
    static void lifecycleControls() throws Exception {
        var constructor = nested("NativeWorker").getDeclaredConstructor(ExportProgramModelOwned.class, int.class, ghidra.app.decompiler.DecompInterface.class);
        constructor.setAccessible(true);
        for (int failAt = 0; failAt < 3; failAt++) {
            var decompiler = new InitializationDecompiler(failAt);
            try { constructor.newInstance(new ExportProgramModelOwned(), 0, decompiler); throw new AssertionError("initialization failure accepted"); }
            catch (InvocationTargetException failure) { check(failure.getCause() instanceof IllegalStateException, failure); }
            check(decompiler.syntax == 1 && decompiler.ccode == (failAt == 0 ? 0 : 1) &&
                decompiler.opens == (failAt == 2 ? 1 : 0) && decompiler.stops == 1 && decompiler.disposals == 1,
                "each rejected initialization cleans native owner exactly once");
        }
        var metadata = metadata(true, new ExportProgramModelOwned.PlannedTypeCoverage(Map.of()));
        var refusal = new ExportProgramModelOwned.PrototypeResult(null,
            new ExportProgramModelOwned.Refusal(ExportProgramModelOwned.PrototypeRefusalCode.NO_HIGH_FUNCTION, "AUTHORED_REFUSAL"));
        Object timeout = render(metadata, new ExportProgramModelOwned.NativeOutcome(null, "decompilation failed or timed out: process: timeout", refusal), true);
        Object partial = render(metadata, new ExportProgramModelOwned.NativeOutcome("body", null, refusal), true);
        check((boolean)OwnedExporterReferencedBytesProbe.invoke(new ExportProgramModelOwned(), "isRetryableDecompileTimeout", new Class<?>[]{nested("FunctionExport")}, timeout),
            "native timeout remains independently retryable after refusal annotation");
        check(!(boolean)OwnedExporterReferencedBytesProbe.invoke(new ExportProgramModelOwned(), "isRetryableDecompileTimeout", new Class<?>[]{nested("FunctionExport")}, partial),
            "typed refusal cannot fabricate a native timeout");
        check(OwnedExporterReferencedBytesProbe.get(partial, "status").equals("partial"), "successful native retry with refused typed prototype stays partial");
        System.out.println("owned initialization cleanup and native timeout classification controls passed");
    }

    static void builtinAliasControls() throws Exception {
        for (DataType alias : List.of(UnsignedIntegerDataType.dataType, LongLongDataType.dataType, UnsignedLongDataType.dataType)) {
            check(Set.of("uint", "longlong", "ulong").contains(alias.getDisplayName()), "fixture is an undeclared builtin alias");
            for (DataType spelling : List.of(alias, new PointerDataType(alias, 8))) {
                for (boolean resultPosition : new boolean[]{false, true}) {
                    GuardedInteger guarded = new GuardedInteger();
                    Prototype prototype = resultPosition ? new Prototype(spelling, new Symbol("value", guarded)) :
                        new Prototype(guarded, new Symbol("value", spelling));
                    var extracted = extract(prototype);
                    check(extracted.typed == null && extracted.refusal.code == ExportProgramModelOwned.PrototypeRefusalCode.UNSUPPORTED_SHAPE &&
                        extracted.refusal.detail.equals("BUILTIN_C_SPELLING"), "alias refused before declaration admission");
                    check(guarded.clones == 0, "alias refusal precedes typed clone/render");
                    Object rendered = render(metadata(true, new ExportProgramModelOwned.PlannedTypeCoverage(Map.of())),
                        new ExportProgramModelOwned.NativeOutcome("authored source", null, extracted), true);
                    check(OwnedExporterReferencedBytesProbe.get(rendered, "status").equals("partial"), "unbound builtin cannot be recovered with empty coverage");
                    check(((String)OwnedExporterReferencedBytesProbe.get(rendered, "record")).contains("\"recoveryAssessment\": \"unassessed\""), "alias remains unassessed");
                    check(((String)OwnedExporterReferencedBytesProbe.get(rendered, "failure")).contains("BUILTIN_C_SPELLING"), "stable alias fallback evidence");
                }
            }
        }
        System.out.println("owned builtin alias extraction and fallback controls passed");
    }
    static void enumExtractionControls() throws Exception {
        String[] total = new String[17]; Arrays.fill(total, "é".repeat(2048));
        for (String[] names : new String[][]{{"a".repeat(4097)}, {"é".repeat(2048) + "a"}, {"ok", null}, total}) {
            int[] work = {0};
            ghidra.program.model.data.Enum enumeration = OwnedExporterReferencedBytesProbe.proxy(ghidra.program.model.data.Enum.class, (m,a) -> {
                switch (m.getName()) {
                    case "getName": return "BoundedEnum";
                    case "getPathName": return "/BoundedEnum";
                    case "getLength": return 4;
                    case "getCount": return names.length;
                    case "getNames": return names;
                    case "getValue": case "clone": case "getDisplayName": work[0]++; throw new AssertionError("invalid enum reached value/render/clone");
                    default: return null;
                }
            });
            var result = extract(new Prototype(enumeration));
            check(result.typed == null && result.refusal.code == (names.length == 2 ?
                ExportProgramModelOwned.PrototypeRefusalCode.NULL_TYPE : ExportProgramModelOwned.PrototypeRefusalCode.LIMIT), "enum extraction bound");
            check(work[0] == 0, "invalid enum rejected before values/clone/render");
        }
        System.out.println("owned enum extraction bounds before rendering passed");
    }
    static Object call(Object exporter, String method, Class<?>[] types, Object... args) throws Exception {
        return OwnedExporterReferencedBytesProbe.invoke(exporter, method, types, args);
    }
    static ExportProgramModelOwned.PlannedTypeCatalog catalog(ExportProgramModelOwned exporter) throws Exception {
        return (ExportProgramModelOwned.PlannedTypeCatalog)OwnedExporterReferencedBytesProbe.get(exporter, "plannedTypes");
    }
    static Object evidence(Set<String> ownedTypes) throws Exception {
        Constructor<?> constructor = nested("PlanningBatchEvidence").getDeclaredConstructors()[0]; constructor.setAccessible(true);
        return constructor.newInstance(new TreeSet<String>(), ownedTypes);
    }
    @SuppressWarnings("unchecked")
    static Map<String,String> records(Object evidence, String kind) throws Exception {
        return (Map<String,String>)OwnedExporterReferencedBytesProbe.get(evidence, kind);
    }
    static Object collect(ExportProgramModelOwned exporter, Function function, Object evidence) throws Exception {
        return call(exporter, "collectFunctionMetadata", new Class<?>[]{Function.class, Path.class, Path.class, nested("PlanningBatchEvidence")},
            function, null, null, evidence);
    }
    static void replay(ExportProgramModelOwned exporter, List<Function> functions, int start, int end) throws Exception {
        call(exporter, "replayTypeCatalog", new Class<?>[]{List.class, int.class, int.class}, functions, start, end);
    }
    static String outcome(Object exported) throws Exception {
        return OwnedExporterReferencedBytesProbe.get(exported, "record") + "\nFAILURE=" + OwnedExporterReferencedBytesProbe.get(exported, "failure") +
            "\nSTATUS=" + OwnedExporterReferencedBytesProbe.get(exported, "status");
    }
    static final class ResumeFixture {
        final ExportProgramModelOwned exporter = new ExportProgramModelOwned();
        final List<Function> functions = new ArrayList<>();
        final List<ExportProgramModelOwned.PrototypeResult> typed = new ArrayList<>();
        ResumeFixture(String scenario) throws Exception {
            var ram = new ghidra.program.model.address.GenericAddressSpace("ram", 64, ghidra.program.model.address.AddressSpace.TYPE_RAM, 0);
            var listing = OwnedExporterReferencedBytesProbe.proxy(ghidra.program.model.listing.Listing.class, (m,a) ->
                m.getName().equals("getInstructions") ? OwnedExporterReferencedBytesProbe.proxy(ghidra.program.model.listing.InstructionIterator.class, (im,ia) -> null) : null);
            OwnedExporterReferencedBytesProbe.field(exporter, "monitor", TaskMonitor.DUMMY);
            OwnedExporterReferencedBytesProbe.field(exporter, "currentProgram", OwnedExporterReferencedBytesProbe.proxy(ghidra.program.model.listing.Program.class,
                (m,a) -> m.getName().equals("getListing") ? listing : null));
            for (int i = 0; i < 514; i++) {
                int index = i;
                List<DataType> roots = new ArrayList<>();
                if (scenario.equals("limit")) {
                    if (i < 512) for (int n = 0; n < 8; n++) roots.add(new TypedefDataType("T" + (i * 8 + n), IntegerDataType.dataType));
                    else {
                        roots.add(new TypedefDataType("T0", IntegerDataType.dataType));
                        if (i == 512) roots.add(new TypedefDataType("Overflow", IntegerDataType.dataType));
                    }
                } else if (i == 0 || i >= 512) {
                    roots.add(new TypedefDataType(new CategoryPath(scenario.equals("collision") && i == 512 ? "/b" : "/a"), "X",
                        scenario.equals("definition") && i == 512 ? LongDataType.dataType : IntegerDataType.dataType));
                }
                ghidra.program.model.listing.Parameter[] params = new ghidra.program.model.listing.Parameter[roots.size()];
                HighSymbol[] symbols = new HighSymbol[roots.size()];
                for (int n = 0; n < roots.size(); n++) {
                    DataType type = new PointerDataType(roots.get(n), 8);
                    params[n] = OwnedExporterReferencedBytesProbe.proxy(ghidra.program.model.listing.Parameter.class,
                        (m,a) -> m.getName().equals("getDataType") ? type : null);
                    symbols[n] = new Symbol("p" + n, type);
                }
                functions.add(OwnedExporterReferencedBytesProbe.proxy(Function.class, (m,a) -> {
                    switch (m.getName()) {
                        case "getCalledFunctions": return Collections.emptySet();
                        case "getEntryPoint": return ram.getAddress(0x1000 + index * 16L);
                        case "getName": return "probe";
                        case "getPrototypeString": return "int probe(void)";
                        case "getReturnType": return IntegerDataType.dataType;
                        case "getParameters": return params;
                        default: return null;
                    }
                }));
                typed.add(extract(new Prototype(IntegerDataType.dataType, symbols)));
                check(typed.get(i).typed != null, "resume fixture typed extraction");
            }
        }
        Object full(Object metadata, int index) throws Exception {
            return call(exporter, "renderFunction", new Class<?>[]{nested("FunctionMetadata"), ExportProgramModelOwned.NativeOutcome.class, boolean.class},
                metadata, new ExportProgramModelOwned.NativeOutcome("authored body", null, typed.get(index)), true);
        }
        Object planning(Object metadata) throws Exception {
            return call(exporter, "renderFunction", new Class<?>[]{nested("FunctionMetadata"), ExportProgramModelOwned.NativeOutcome.class, boolean.class}, metadata, null, false);
        }
    }
    @SuppressWarnings("unchecked")
    static void catalogResumeControls() throws Exception {
        for (String scenario : List.of("collision", "definition", "limit")) {
            ResumeFixture fixture = new ResumeFixture(scenario);
            var exporter = fixture.exporter;
            var functions = fixture.functions;
            Object semantic = call(exporter, "computePlanningSemanticState", new Class<?>[]{List.class}, functions);
            var expectedBatches = (List<ExporterSemanticFingerprintOwnedV1.BatchCommitment>)OwnedExporterReferencedBytesProbe.get(semantic, "batches");
            List<String> full = new ArrayList<>();
            Set<String> owned = new TreeSet<>();
            List<Set<String>> prefixOwners = new ArrayList<>();
            Map<String,String> firstTypes = new TreeMap<>();
            catalog(exporter).clear();
            for (int start = 0; start < functions.size(); start += 512) {
                Object evidence = evidence(owned);
                List<String> plans = new ArrayList<>();
                int end = Math.min(start + 512, functions.size());
                for (int index = start; index < end; index++) {
                    Object metadata = collect(exporter, functions.get(index), evidence);
                    Object planned = fixture.planning(metadata);
                    plans.add((String)OwnedExporterReferencedBytesProbe.get(planned, "record"));
                    if (OwnedExporterReferencedBytesProbe.get(planned, "failure") != null) {
                        String id = (String)call(exporter, "functionId", new Class<?>[]{Function.class}, functions.get(index));
                        String failure = (String)call(exporter, "renderFunctionFailure", new Class<?>[]{String.class, nested("FunctionExport")}, id, planned);
                        records(evidence, "failures").put(id, failure);
                    }
                    full.add(outcome(fixture.full(metadata, index)));
                }
                var actual = ExporterSemanticFingerprintOwnedV1.commitBatch(start, end, String.join(",\n", plans), "",
                    String.join(",\n", records(evidence, "types").values()), String.join(",\n", records(evidence, "failures").values()));
                ExporterSemanticFingerprintOwnedV1.requireBatchCommitment(expectedBatches.get(start / 512), actual);
                owned.addAll(records(evidence, "types").keySet());
                prefixOwners.add(new TreeSet<>(owned)); firstTypes.putAll(records(evidence, "types"));
            }
            check(full.get(512).endsWith("STATUS=partial") && full.get(513).endsWith("STATUS=recovered"), "conflict/limit is refused and repeat owner remains valid");
            check(full.get(512).contains(scenario.equals("limit") ? "PLANNED_NAMED_TYPES" : scenario.equals("collision") ? "C_SPELLING_COLLISION" : "NAMED_TYPE_CHANGED"), "specific resume refusal");
            // Interrupt within a batch, at its boundary, and after the refused function. Reused
            // sparse full checkpoints are replayed in inventory order, never completion order.
            for (int cut : new int[]{1, 511, 512, 513}) for (boolean sparse : new boolean[]{false, true}) {
                catalog(exporter).clear();
                Object sink = evidence(new TreeSet<>());
                for (int index = 0; index < functions.size(); index++) {
                    boolean accepted = index < cut && (!sparse || index % 3 != 1);
                    if (accepted) replay(exporter, functions, index, index + 1);
                    else {
                        Object metadata = collect(exporter, functions.get(index), sink);
                        check(full.get(index).equals(outcome(fixture.full(metadata, index))), "full bytes/status/failure stable: " + scenario + "/" + cut + "/" + sparse + "/" + index);
                    }
                }
                check(catalog(exporter).definitions.size() == (scenario.equals("limit") ? 4096 : 1), "reused entries share invocation-wide limit");
            }
            // An incomplete planning batch (including an orphan prefix within it) is regenerated
            // after replaying only the accepted 512-function prefix. Compare all four commitments.
            for (int interruptedAt : new int[]{512, 513}) {
                catalog(exporter).clear();
                replay(exporter, functions, 0, 512);
                Object orphanEvidence = evidence(prefixOwners.get(0));
                for (int index = 512; index < interruptedAt; index++) collect(exporter, functions.get(index), orphanEvidence);
                // Simulate process loss: uncommitted catalog and orphan fragment progress carry no authority.
                catalog(exporter).clear();
                replay(exporter, functions, 0, 512);
                Object evidence = evidence(prefixOwners.get(0));
                List<String> plans = new ArrayList<>();
                for (int index = 512; index < functions.size(); index++) {
                    Object metadata = collect(exporter, functions.get(index), evidence);
                    check(full.get(index).equals(outcome(fixture.full(metadata, index))), "resumed tail full result");
                    Object planned = fixture.planning(metadata);
                    plans.add((String)OwnedExporterReferencedBytesProbe.get(planned, "record"));
                    if (OwnedExporterReferencedBytesProbe.get(planned, "failure") != null) {
                        String id = (String)call(exporter, "functionId", new Class<?>[]{Function.class}, functions.get(index));
                        records(evidence, "failures").put(id, (String)call(exporter, "renderFunctionFailure", new Class<?>[]{String.class, nested("FunctionExport")}, id, planned));
                    }
                }
                var actual = ExporterSemanticFingerprintOwnedV1.commitBatch(512, 514, String.join(",\n", plans), "",
                    String.join(",\n", records(evidence, "types").values()), String.join(",\n", records(evidence, "failures").values()));
                ExporterSemanticFingerprintOwnedV1.requireBatchCommitment(expectedBatches.get(1), actual);
                check(records(evidence, "types").isEmpty(), "accepted prefix keeps first type owners at interruption " + interruptedAt);
            }
            check(firstTypes.values().stream().anyMatch(record -> record.contains("0x1000")), "address-order first owner preserved");
            TaskMonitorAdapter cancelled = new TaskMonitorAdapter(true); cancelled.cancel();
            OwnedExporterReferencedBytesProbe.field(exporter, "monitor", cancelled);
            catalog(exporter).clear();
            try { replay(exporter, functions, 0, 512); throw new AssertionError("replay ignored cancellation"); }
            catch (InvocationTargetException expected) { check(expected.getCause() instanceof InterruptedException, expected); }
            check(catalog(exporter).definitions.isEmpty(), "cancelled replay claims no owner");
        }
        System.out.println("owned catalog resume full output and 512 batch commitments passed");
    }

    public static void main(String[] args) throws Exception {
        var zero = extract(new Prototype(VoidDataType.dataType));
        check(zero.typed != null && zero.typed.declaration.equals("void probe(void)") && zero.typed.parameters.isEmpty(), "actual typed zero params");
        DataType pointer = new PointerDataType(CharDataType.dataType, 8);
        var scalarPointers = extract(new Prototype(IntegerDataType.dataType, new Symbol("value", IntegerDataType.dataType),
            new Symbol("text", pointer), new Symbol("output", new PointerDataType(pointer, 8))));
        check(scalarPointers.typed != null && scalarPointers.typed.parameters.size() == 3 && scalarPointers.origin == ExportProgramModelOwned.PrototypeOrigin.HIGH_FUNCTION,
            "three typed scalar/pointer/pointer-to-pointer parameters");
        var variadic = new Prototype(IntegerDataType.dataType, new Symbol("param_1", IntegerDataType.dataType)); variadic.variadic = true;
        var result = extract(variadic);
        check(result.typed != null && result.typed.variadic && result.typed.declaration.contains("param_1, ..."), "default names and varargs preserved");
        var noFixed = new Prototype(IntegerDataType.dataType); noFixed.variadic = true;
        refused(noFixed, ExportProgramModelOwned.PrototypeRefusalCode.UNSUPPORTED_SHAPE);
        refused(new Prototype(null), ExportProgramModelOwned.PrototypeRefusalCode.NULL_TYPE);
        refused(new Prototype(IntegerDataType.dataType, (HighSymbol)null), ExportProgramModelOwned.PrototypeRefusalCode.NULL_SYMBOL);
        refused(new Prototype(IntegerDataType.dataType, new Symbol("value", null)), ExportProgramModelOwned.PrototypeRefusalCode.NULL_TYPE);
        for (String name : new String[]{null, "", "bad-name", "void"})
            refused(new Prototype(IntegerDataType.dataType, new Symbol(name, IntegerDataType.dataType)), ExportProgramModelOwned.PrototypeRefusalCode.INVALID_NAME);
        refused(new Prototype(IntegerDataType.dataType, new Symbol("x", IntegerDataType.dataType), new Symbol("x", IntegerDataType.dataType)), ExportProgramModelOwned.PrototypeRefusalCode.INVALID_NAME);
        refused(new Prototype(IntegerDataType.dataType, new Symbol("array", new ArrayDataType(IntegerDataType.dataType, 4, 4))), ExportProgramModelOwned.PrototypeRefusalCode.UNSUPPORTED_SHAPE);
        refused(new Prototype(new PointerDataType(new FunctionDefinitionDataType("callback"), 8)), ExportProgramModelOwned.PrototypeRefusalCode.UNSUPPORTED_SHAPE);
        check(ExportProgramModelOwned.extractTypedPrototype((ghidra.app.decompiler.DecompileResults)null, "probe", TaskMonitor.DUMMY).refusal.code ==
            ExportProgramModelOwned.PrototypeRefusalCode.NO_HIGH_FUNCTION, "null HighFunction is not void");
        TypeDef alias = new TypedefDataType("Count", IntegerDataType.dataType);
        var named = extract(new Prototype(IntegerDataType.dataType, new Symbol("value", new PointerDataType(alias, 8))));
        check(named.typed != null && named.typed.requirements.size() == 1, "pointer-to-typedef retains alias");
        var namedPointer = extract(new Prototype(IntegerDataType.dataType, new Symbol("value", new TypedefDataType("CountPointer", new PointerDataType(alias, 8)))));
        check(namedPointer.typed != null && namedPointer.typed.requirements.size() == 2, "typedef-to-pointer retains both aliases");
        check(ExportProgramModelOwned.checkCoverage(named.typed, new ExportProgramModelOwned.PlannedTypeCoverage(Map.of())).code ==
            ExportProgramModelOwned.PrototypeRefusalCode.UNPLANNED_TYPE, "native-only named type refuses");
        builtinAliasControls();
        enumExtractionControls();
        catalogResumeControls();
        boundsAndCancellation();
        lifecycleControls();
        renderingAndBindings(Path.of(args[0]));
        typeClosureControls(Path.of(args[0]).resolve("coverage"));
        System.out.println("owned typed prototype API probe passed");
    }
}
