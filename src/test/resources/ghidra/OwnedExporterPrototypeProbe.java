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
    static ghidra.program.database.ProgramDB program;
    static DataTypeManager manager;
    static ExportProgramModelOwned.TargetContext target;
    static DataType I, L, C, UI, UL, LL;
    static PointerDataType pointer(DataType type, int length) { return new PointerDataType(type, length, manager); }
    static TypeDef alias(String name, DataType type) { return new TypedefDataType(CategoryPath.ROOT, name, type, manager); }
    static TypeDef alias(CategoryPath path, String name, DataType type) { return new TypedefDataType(path, name, type, manager); }
    static ArrayDataType array(DataType type, int count, int length) { return new ArrayDataType(type, count, length, manager); }
    static ghidra.program.model.listing.VariableStorage storage(DataType type, boolean result) {
        if (type instanceof VoidDataType) return ghidra.program.model.listing.VariableStorage.VOID_STORAGE;
        try {
            if (result) {
                String register = type.getLength() == 1 ? "AL" : type.getLength() == 2 ? "AX" : type.getLength() == 4 ? "EAX" : "RAX";
                if (type.getLength() > 8) return ghidra.program.model.listing.VariableStorage.UNASSIGNED_STORAGE;
                return new ghidra.program.model.listing.VariableStorage(program, program.getRegister(register));
            }
            return new ghidra.program.model.listing.VariableStorage(program, 8, type.getLength());
        } catch (Exception failure) { throw new IllegalArgumentException(failure); }
    }
    static void configure(ExportProgramModelOwned exporter) throws Exception {
        OwnedExporterReferencedBytesProbe.field(exporter, "monitor", TaskMonitor.DUMMY);
        OwnedExporterReferencedBytesProbe.field(exporter, "targetContext", target);
    }

    static void check(boolean value, Object message) { if (!value) throw new AssertionError(message); }
    static class Symbol extends HighSymbol {
        int ordinal;
        Symbol(String name, DataType type) { super(1, name, type, false, false, null); }
        @Override public boolean isParameter() { return true; }
        @Override public int getCategoryIndex() { return ordinal; }
        @Override public ghidra.program.model.listing.VariableStorage getStorage() {
            try { return new ghidra.program.model.listing.VariableStorage(program, 8 + ordinal * 16, getDataType().getLength()); }
            catch (Exception failure) { throw new IllegalArgumentException(failure); }
        }
    }
    static class Prototype extends FunctionPrototype {
        DataType result;
        HighSymbol[] symbols;
        boolean variadic;
        int count;
        Prototype(DataType result, HighSymbol... symbols) {
            super((LocalSymbolMap)null, OwnedExporterReferencedBytesProbe.proxy(Function.class, (m,a) -> null));
            this.result = result; this.symbols = symbols; count = symbols.length;
            for (int i = 0; i < symbols.length; i++) if (symbols[i] instanceof Symbol) ((Symbol)symbols[i]).ordinal = i;
        }
        @Override public DataType getReturnType() { return result; }
        @Override public int getNumParams() { return count; }
        @Override public HighSymbol getParam(int index) { return symbols[index]; }
        @Override public boolean isVarArg() { return variadic; }
        @Override public String getModelName() { return target.convention; }
        @Override public int getExtraPop() { return target.pointerSize; }
        boolean encodedCustom;
        @Override public void encodePrototype(ghidra.program.model.pcode.Encoder encoder, PcodeDataTypeManager dtm, int first) throws java.io.IOException {
            encoder.openElement(ghidra.program.model.pcode.ElementId.ELEM_PROTOTYPE);
            encoder.writeString(ghidra.program.model.pcode.AttributeId.ATTRIB_MODEL, getModelName());
            encoder.writeBool(ghidra.program.model.pcode.AttributeId.ATTRIB_DOTDOTDOT, variadic);
            encoder.writeBool(ghidra.program.model.pcode.AttributeId.ATTRIB_CUSTOM, encodedCustom);
            encoder.openElement(ghidra.program.model.pcode.ElementId.ELEM_RETURNSYM);
            throw new AssertionError("attribute capture must stop before any typed render");
        }
        @Override public ghidra.program.model.listing.VariableStorage getReturnStorage() { return storage(result, true); }
    }
    static ExportProgramModelOwned.PrototypeResult extract(Prototype prototype) throws Exception {
        return ExportProgramModelOwned.extractTypedPrototype(prototype, "probe", TaskMonitor.DUMMY, target, false);
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
        for (int i = 0; i < symbols.length; i++) symbols[i] = new Symbol("arg_" + i, I);
        check(extract(new Prototype(I, symbols)).typed.parameters.size() == 256, "256 typed parameters");
        DataType deep = I;
        for (int i = 0; i < 32; i++) deep = pointer(deep, 8);
        check(extract(new Prototype(deep)).typed != null, "depth 32");
        refused(new Prototype(pointer(deep, 8)), ExportProgramModelOwned.PrototypeRefusalCode.LIMIT);
        Pointer[] cycle = new Pointer[1];
        cycle[0] = OwnedExporterReferencedBytesProbe.proxy(Pointer.class, (m,a) -> {
            if (m.getName().equals("getDataType")) return cycle[0];
            if (m.getName().equals("getLength") || m.getName().equals("getAlignment")) return 8;
            if (m.getName().equals("getDisplayName") || m.getName().equals("clone") || m.getName().equals("getPathName"))
                throw new AssertionError("cycle must be rejected before recursive spelling/clone");
            return null;
        });
        refused(new Prototype(cycle[0]), ExportProgramModelOwned.PrototypeRefusalCode.UNSUPPORTED_SHAPE);
        TaskMonitorAdapter cancelled = new TaskMonitorAdapter(true); cancelled.cancel();
        try {
            ExportProgramModelOwned.extractTypedPrototype(new Prototype(I), "probe", cancelled, target, false);
            throw new AssertionError("pre-cancelled extraction returned");
        } catch (InterruptedException expected) { }
        TaskMonitorAdapter during = new TaskMonitorAdapter(true);
        Prototype trigger = new Prototype(I, new Symbol("value", I)) {
            @Override public HighSymbol getParam(int index) { during.cancel(); return super.getParam(index); }
        };
        try {
            ExportProgramModelOwned.extractTypedPrototype(trigger, "probe", during, target, false);
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
            complete ? null : "metadataRefusal=AUTHORED_INCOMPLETE", complete, coverage, target);
    }
    static Object render(Object metadata, ExportProgramModelOwned.NativeOutcome outcome, boolean full) throws Exception {
        return OwnedExporterReferencedBytesProbe.invoke(new ExportProgramModelOwned(), "renderFunction",
            new Class<?>[]{nested("FunctionMetadata"), ExportProgramModelOwned.NativeOutcome.class, boolean.class}, metadata, outcome, full);
    }
    static void renderingAndBindings(Path root) throws Exception {
        Files.createDirectories(root);
        var coverage = new ExportProgramModelOwned.PlannedTypeCoverage(Map.of());
        var typed = extract(new Prototype(I, new Symbol("value", I)));
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
        configure(exporter);
        var space = new ghidra.program.model.address.GenericAddressSpace("ram", 64, ghidra.program.model.address.AddressSpace.TYPE_RAM, 0);
        Path types = Files.createDirectories(root.resolve("types"));
        Class<?> planning = nested("PlanningBatchEvidence");
        Class<?>[] parameters = {List.class, Path.class, planning, ghidra.program.model.address.Address.class};
        var before = (ExportProgramModelOwned.PlannedTypeCoverage)OwnedExporterReferencedBytesProbe.invoke(exporter, "planTypeCoverage", parameters,
            List.of(I), types, null, space.getAddress(0x1000));
        TypeDef alias = alias("OwnedCount", I);
        var snapshot = (ExportProgramModelOwned.PlannedTypeCoverage)OwnedExporterReferencedBytesProbe.invoke(exporter, "planTypeCoverage", parameters,
            List.of(pointer(alias, 8)), types, null, space.getAddress(0x1000));
        var typed = extract(new Prototype(I, new Symbol("count", pointer(alias, 8))));
        check(typed.typed != null && ExportProgramModelOwned.checkCoverage(typed.typed, snapshot) == null, "coordinator plans pointer dependency using identical descriptor and id");
        check(ExportProgramModelOwned.checkCoverage(typed.typed, before).code == ExportProgramModelOwned.PrototypeRefusalCode.UNPLANNED_TYPE, "future type cannot modify earlier snapshot");
        var requirement = typed.typed.requirements.get(0);
        Path record = types.resolve(requirement.id + ".json");
        String first = Files.readString(record);
        check(first.contains("OwnedCount") && first.contains("0x1000"), "named declaration and first source owner retained");
        OwnedExporterReferencedBytesProbe.invoke(exporter, "planTypeCoverage", parameters,
            List.of(alias), types, null, space.getAddress(0x2000));
        check(Files.readString(record).equals(first), "later planning cannot change first owner");
        var changed = extract(new Prototype(I, new Symbol("count", pointer(alias("OwnedCount", L), 8))));
        check(changed.typed != null && ExportProgramModelOwned.checkCoverage(changed.typed, snapshot).code == ExportProgramModelOwned.PrototypeRefusalCode.TYPE_MISMATCH,
            "same-path changed native definition refuses");
        for (DataType invalid : List.of(alias("OwnedCount", L),
            alias(new CategoryPath("/other"), "OwnedCount", I))) {
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
        int admitted = catalog(exporter).definitions.size();
        long fileCount;
        try (var paths = Files.list(types)) { fileCount = paths.count(); }
        try {
            OwnedExporterReferencedBytesProbe.invoke(exporter, "planTypeCoverage", parameters,
                List.of(alias("NeverPublished", I), new FloatDataType(manager)), types, null, space.getAddress(0x4000));
            throw new AssertionError("unsupported closure admitted partially");
        } catch (InvocationTargetException failure) { check(failure.getCause() instanceof ExportProgramModelOwned.PrototypeRejected, failure); }
        check(catalog(exporter).definitions.size() == admitted, "whole incoming graph rejection is atomic");
        try (var paths = Files.list(types)) { check(paths.count() == fileCount, "no type fragment published before full graph validation"); }
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

    static ExportProgramModelOwned.PlannedTypeCoverage planned(List<DataType> roots) throws Exception {
        var graph = new ExportProgramModelOwned.TypedGraph(TaskMonitor.DUMMY, target);
        for (DataType root : roots) graph.validate(root);
        graph.finish();
        var catalog = new ExportProgramModelOwned.PlannedTypeCatalog();
        catalog.admit(graph.requirements, () -> {});
        return new ExportProgramModelOwned.PlannedTypeCoverage(graph.requirements);
    }
    static void builtinAliasControls() throws Exception {
        for (DataType builtin : List.of(UI, LL, UL)) {
            String canonical = ((AbstractIntegerDataType)builtin).getCDeclaration();
            for (DataType shape : List.of(builtin, pointer(builtin, 8), alias("Alias", builtin),
                    alias("Outer", alias("Inner", builtin)), pointer(alias("Alias", builtin), 8))) {
                for (boolean resultPosition : new boolean[]{false, true}) {
                    Prototype prototype = resultPosition ? new Prototype(shape, new Symbol("value", I)) :
                        new Prototype(I, new Symbol("value", shape));
                    var extracted = extract(prototype);
                    check(extracted.typed != null, "target-proven builtin and aliases: " + (extracted.refusal == null ? "" : extracted.refusal.detail));
                    var coverage = planned(List.of(shape));
                    check(ExportProgramModelOwned.checkCoverage(extracted.typed, coverage) == null, "actual planned definitions cover typed signature");
                    check(coverage.byPath.get(builtin.getPathName()).declaration.equals("typedef " + canonical + " " + builtin.getName() + ";"),
                        "direct builtin uses its authentic path and target-proven scalar declaration");
                    check(ExportProgramModelOwned.checkCoverage(extracted.typed, new ExportProgramModelOwned.PlannedTypeCoverage(Map.of())).code ==
                        ExportProgramModelOwned.PrototypeRefusalCode.UNPLANNED_TYPE, "empty coverage cannot admit direct or wrapped builtin alias");
                    Object rendered = render(metadata(true, new ExportProgramModelOwned.PlannedTypeCoverage(Map.of())),
                        new ExportProgramModelOwned.NativeOutcome("authored source", null, extracted), true);
                    check(OwnedExporterReferencedBytesProbe.get(rendered, "status").equals("partial"), "unbound alias cannot be recovered");
                    check(((String)OwnedExporterReferencedBytesProbe.get(rendered, "failure")).contains("UNPLANNED_TYPE"), "stable alias fallback evidence");
                }
            }
            var scalarAlias = planned(List.of(alias("Scalar", builtin))).byPath.get("/Scalar");
            check(scalarAlias.declaration.equals("typedef " + canonical + " Scalar;"), "scalar typedef retains rank and identity");
        }
        System.out.println("owned builtin alias extraction and fallback controls passed");
    }
    static void faithfulTypeControls(Path root) throws Exception {
        Files.createDirectories(root);
        TypeDef word = alias("rendering_word", UL);
        EnumDataType kind = new EnumDataType(CategoryPath.ROOT, "RenderingKind", 4, manager);
        kind.add("KIND_ZERO", 0); kind.add("KIND_FIRST", 1); kind.add("KIND_SECOND", 2);
        StructureDataType record = new StructureDataType(CategoryPath.ROOT, "RenderingRecord", 0, manager);
        record.setPackingEnabled(true);
        record.add(word, "value", null); record.add(kind, "kind", null); record.add(array(C, 16, 1), "label", null);
        check(record.getLength() == 32 && record.getAlignment() == 8 && record.getComponent(2).getOffset() == 12, "authored target layout");
        var coverage = planned(List.of(pointer(record, 8), word));
        var signature = extract(new Prototype(word, new Symbol("record", pointer(record, 8)), new Symbol("selector", I)));
        check(signature.typed != null && ExportProgramModelOwned.checkCoverage(signature.typed, coverage) == null,
            "faithful fixture-shaped signature covered");
        String declarations = String.join("\n", coverage.byPath.values().stream().map(r -> r.declaration).toList());
        check(declarations.contains("typedef unsigned long rendering_word;") && declarations.contains("typedef unsigned long ulong;") &&
            declarations.contains("KIND_FIRST = 1") && declarations.contains("RenderingKind kind;") && declarations.contains("char label[16];") &&
            !declarations.contains("_data["), "actual member and enum definitions");
        // Emit dependency order using the plan's actual IDs, independently of discovery/map order.
        Map<String,ExportProgramModelOwned.TypeRequirement> pending = new TreeMap<>();
        coverage.byPath.values().forEach(r -> pending.put(r.id, r));
        Set<String> emitted = new HashSet<>(); StringBuilder header = new StringBuilder("#include <stddef.h>\n");
        while (!pending.isEmpty()) {
            boolean progress = false;
            for (var it = pending.entrySet().iterator(); it.hasNext();) {
                var requirement = it.next().getValue();
                if (emitted.containsAll(requirement.dependencyIds)) {
                    header.append(requirement.declaration).append('\n'); emitted.add(requirement.id); it.remove(); progress = true;
                }
            }
            check(progress, "no invented dependency ordering");
        }
        header.append("_Static_assert(sizeof(rendering_word)==8 && _Alignof(rendering_word)==8, \"scalar layout\");\n")
            .append("_Static_assert(__builtin_types_compatible_p(rendering_word, unsigned long), \"scalar identity\");\n")
            .append("_Static_assert(sizeof(RenderingRecord)==32 && _Alignof(RenderingRecord)==8, \"record layout\");\n")
            .append("_Static_assert(offsetof(RenderingRecord,kind)==8 && offsetof(RenderingRecord,label)==12, \"member offsets\");\n")
            .append("_Static_assert(sizeof(RenderingKind)==4 && _Alignof(RenderingKind)==4 && KIND_SECOND==2, \"enum layout\");\n")
            .append("_Static_assert((RenderingKind)-1 > 0, \"GCC enum representation\");\n");
        Files.writeString(root.resolve("faithful-types.h"), header);
        Files.writeString(root.resolve("typed-observations.txt"), signature.typed.observations + "\n" +
            String.join("\n", coverage.byPath.values().stream().map(r -> r.descriptor + "\ndefinition=" + r.definitionDigest).toList()));
        var old = coverage.byPath.get("/rendering_word");
        var corrupt = new ExportProgramModelOwned.TypeRequirement(old.path, old.id, old.cSpelling, old.semanticDigest,
            "typedef unsigned char rendering_word[8];", old.definitionDigest, old.dependencyIds, old.namespaceKeys, old.descriptor);
        Map<String,ExportProgramModelOwned.TypeRequirement> mutated = new TreeMap<>(coverage.byPath); mutated.put(old.path, corrupt);
        check(ExportProgramModelOwned.checkCoverage(signature.typed, new ExportProgramModelOwned.PlannedTypeCoverage(mutated)).code ==
            ExportProgramModelOwned.PrototypeRefusalCode.TYPE_MISMATCH, "same semantic graph and old digest cannot cover changed definition bytes");
        TypeDef memberArray = alias("MemberArray", array(I, 3, 4));
        var arrayPointer = extract(new Prototype(I, new Symbol("values", pointer(memberArray, 8))));
        check(arrayPointer.typed != null && ExportProgramModelOwned.checkCoverage(arrayPointer.typed, planned(List.of(memberArray))) == null &&
            arrayPointer.typed.declaration.contains("MemberArray * values"), "pointer to a real array typedef retains its constructor without decay");
        refused(new Prototype(I, new Symbol("values", memberArray)), ExportProgramModelOwned.PrototypeRefusalCode.UNSUPPORTED_SHAPE);
        var arrayAlias = planned(List.of(alias("rendering_word", array(C, 8, 1)))).byPath.get("/rendering_word");
        check(!old.same(arrayAlias), "same-sized array cannot masquerade as scalar");
        var signed = planned(List.of(alias("rendering_word", L))).byPath.get("/rendering_word");
        check(!old.semanticDigest.equals(signed.semanticDigest), "equal-sized signed and unsigned have different semantic commitments");
        var reversed = planned(List.of(word, pointer(record, 8)));
        check(coverage.byPath.keySet().equals(reversed.byPath.keySet()), "permuted roots retain definition inventory");
        for (var entry : coverage.byPath.entrySet()) check(entry.getValue().same(reversed.byPath.get(entry.getKey())), "permuted roots retain exact declarations");
        StructureDataType node = new StructureDataType(CategoryPath.ROOT, "Node", 0, manager);
        node.setPackingEnabled(true); node.add(pointer(node, 8), "next", null); node.add(I, "value", null);
        check(planned(List.of(pointer(node, 8))).byPath.get("/Node").declaration.contains("struct Node * next;"), "authentic recursive tag");
        UnionDataType union = new UnionDataType(CategoryPath.ROOT, "ActualUnion", manager);
        union.setPackingEnabled(true); union.add(I, "number", null); union.add(word, "word", null);
        check(planned(List.of(union)).byPath.get("/ActualUnion").declaration.contains("typedef union ActualUnion"), "union kind is preserved");
        StructureDataType wrongLayout = new StructureDataType(CategoryPath.ROOT, "WrongLayout", 12, manager);
        wrongLayout.replaceAtOffset(4, I, 4, "shifted", null);
        try { planned(List.of(wrongLayout)); throw new AssertionError("unknown layout admitted"); }
        catch (ExportProgramModelOwned.PrototypeRejected expected) { check(expected.refusal.detail.equals("MEMBER_OFFSET_MISMATCH"), expected.refusal.detail); }
        StructureDataType bits = new StructureDataType(CategoryPath.ROOT, "Bits", 0, manager);
        bits.setPackingEnabled(true); bits.addBitField(I, 3, "bit", null);
        try { planned(List.of(bits)); throw new AssertionError("bitfield admitted"); }
        catch (ExportProgramModelOwned.PrototypeRejected expected) { check(expected.refusal.detail.equals("AGGREGATE_COMPONENT"), expected.refusal.detail); }
        EnumDataType shortEnum = new EnumDataType(CategoryPath.ROOT, "ShortEnum", 2, manager); shortEnum.add("SHORT_ZERO", 0);
        try { planned(List.of(shortEnum)); throw new AssertionError("unproved enum representation admitted"); }
        catch (ExportProgramModelOwned.PrototypeRejected expected) { check(expected.refusal.detail.equals("ENUM_TARGET_REPRESENTATION"), expected.refusal.detail); }
        record.setExplicitPackingValue(1);
        try { planned(List.of(record)); throw new AssertionError("packed record admitted"); }
        catch (ExportProgramModelOwned.PrototypeRejected expected) { check(expected.refusal.detail.equals("EXPLICIT_PACKING"), expected.refusal.detail); }
        System.out.println("owned faithful scalar record enum array definitions and coverage controls passed");
    }
    static void ordinaryNamespaceControls() throws Exception {
        TypeDef word = alias("Word", UL);
        for (DataType use : List.of(word, pointer(word, 8), alias("Word", I))) {
            var rejected = extract(new Prototype(I, new Symbol("Word", I), new Symbol("value", use)));
            check(rejected.typed == null && rejected.refusal.code == ExportProgramModelOwned.PrototypeRefusalCode.UNSUPPORTED_SHAPE &&
                rejected.refusal.detail.equals("PARAMETER_TYPEDEF_CAPTURE"), "earlier binding captures typed alias: " + use.getName());
        }
        var builtin = extract(new Prototype(I, new Symbol("ulong", I), new Symbol("value", UL)));
        check(builtin.typed == null && builtin.refusal.detail.equals("PARAMETER_TYPEDEF_CAPTURE"), "builtin alias capture");
        for (Prototype supported : List.of(
                new Prototype(I, new Symbol("Word", word)),
                new Prototype(I, new Symbol("value", word), new Symbol("Word", I)),
                new Prototype(I, new Symbol("Word", I), new Symbol("value", L)),
                new Prototype(I, new Symbol("Word", I), new Symbol("value", alias("OuterWord", word))))) {
            var actual = extract(supported);
            check(actual.typed != null, "noncapturing scope remains supported");
            for (int i = 0; i < supported.symbols.length; i++)
                check(actual.typed.parameters.get(i).name.equals(supported.symbols[i].getName()), "authentic HighSymbol name preserved");
        }
        StructureDataType record = new StructureDataType(CategoryPath.ROOT, "Event", 0, manager);
        record.setPackingEnabled(true); record.add(I, "value", null);
        var tagPointer = extract(new Prototype(I, new Symbol("Event", I), new Symbol("value", pointer(record, 8))));
        check(tagPointer.typed != null && tagPointer.typed.declaration.equals("int probe(int Event, struct Event * value)"),
            "parameter binding does not capture a proven constructor tag reference");
        var callable = ExportProgramModelOwned.extractTypedPrototype(new Prototype(I, new Symbol("value", pointer(record, 8))),
            "Event", TaskMonitor.DUMMY, target, false);
        check(callable.typed == null && callable.refusal.detail.equals("ORDINARY_NAMESPACE_COLLISION"),
            "automatic record alias cannot conflict with this callable");
        var graph = new ExportProgramModelOwned.TypedGraph(TaskMonitor.DUMMY, target);
        graph.validate(pointer(record, 8)); graph.finish();
        for (String origin : List.of("callable", "global")) {
            var catalog = new ExportProgramModelOwned.PlannedTypeCatalog();
            catalog.reserveOrdinary("Event", () -> {});
            try { catalog.admit(graph.requirements, () -> {}); throw new AssertionError(origin + " alias capture admitted"); }
            catch (ExportProgramModelOwned.PrototypeRejected expected) {
                check(expected.refusal.detail.equals("ORDINARY_NAMESPACE_COLLISION") && catalog.definitions.isEmpty(),
                    origin + " collision rejects the whole closure");
            }
            catalog.clear(); catalog.admit(graph.requirements, () -> {});
            try { catalog.reserveOrdinary("Event", () -> {}); throw new AssertionError("late " + origin + " capture admitted"); }
            catch (ExportProgramModelOwned.PrototypeRejected expected) {
                check(expected.refusal.detail.equals("ORDINARY_NAMESPACE_COLLISION") && catalog.ordinaryNames.isEmpty(),
                    "late " + origin + " refuses before publication");
            }
        }
        // Exercise the actual metadata publication boundary as well as the catalog DTOs.
        var ram = new ghidra.program.model.address.GenericAddressSpace("ram", 64, ghidra.program.model.address.AddressSpace.TYPE_RAM, 0);
        var unique = new ghidra.program.model.address.GenericAddressSpace("unique", 64, ghidra.program.model.address.AddressSpace.TYPE_UNIQUE, 1);
        var addresses = new ghidra.program.model.address.DefaultAddressFactory(new ghidra.program.model.address.AddressSpace[]{ram, unique});
        Function function = OwnedExporterReferencedBytesProbe.proxy(Function.class, (m,a) -> {
            switch (m.getName()) {
                case "getCalledFunctions": return Collections.emptySet();
                case "getName": return "probe";
                case "getEntryPoint": return ram.getAddress(0x2000);
                case "getPrototypeString": return "int probe(void)";
                case "getReturnType": return I;
                case "getParameters": return new ghidra.program.model.listing.Parameter[0];
                default: return null;
            }
        });
        var references = new OwnedExporterReferencedBytesProbe.CollectionFixture(ram, unique, addresses) {
            @Override ghidra.program.model.listing.Program program() {
                var base = super.program();
                return OwnedExporterReferencedBytesProbe.proxy(ghidra.program.model.listing.Program.class, (m,a) -> {
                    if (m.getName().equals("getSymbolTable")) return OwnedExporterReferencedBytesProbe.proxy(
                        ghidra.program.model.symbol.SymbolTable.class, (sm,sa) -> sm.getName().equals("getPrimarySymbol") ?
                            OwnedExporterReferencedBytesProbe.proxy(ghidra.program.model.symbol.Symbol.class,
                                (nm,na) -> nm.getName().equals("getName") ? "Event" : null) : null);
                    return m.invoke(base, a);
                });
            }
        };
        references.add(1, 8);
        for (boolean aliasFirst : new boolean[]{false, true}) {
            var exporter = new ExportProgramModelOwned(); configure(exporter);
            references.run(exporter);
            if (aliasFirst) catalog(exporter).admit(graph.requirements, () -> {});
            Object sink = evidence(new TreeSet<>());
            Object metadata = collect(exporter, function, sink);
            if (aliasFirst) {
                check(!(boolean)OwnedExporterReferencedBytesProbe.get(metadata, "evidenceComplete") &&
                    ((String)OwnedExporterReferencedBytesProbe.get(metadata, "failure")).contains("ORDINARY_NAMESPACE_COLLISION"),
                    "actual global metadata reports a late alias collision");
                check(records(sink, "globals").isEmpty(), "conflicting global is refused before fragment publication");
            } else {
                check(records(sink, "globals").size() == 1 && catalog(exporter).ordinaryNames.contains("Event"),
                    "actual global metadata reserves its ordinary name");
                try { catalog(exporter).admit(graph.requirements, () -> {}); throw new AssertionError("global capture admitted"); }
                catch (ExportProgramModelOwned.PrototypeRejected expected) {
                    check(expected.refusal.detail.equals("ORDINARY_NAMESPACE_COLLISION"), expected.refusal.detail);
                }
            }
        }
        var exporter = new ExportProgramModelOwned(); configure(exporter);
        Function future = OwnedExporterReferencedBytesProbe.proxy(Function.class, (m,a) -> m.getName().equals("getName") ? "Event" : null);
        call(exporter, "reserveFunctionNames", new Class<?>[]{List.class}, List.of(function, future));
        try { catalog(exporter).admit(graph.requirements, () -> {}); throw new AssertionError("future callable capture admitted"); }
        catch (ExportProgramModelOwned.PrototypeRejected expected) {
            check(expected.refusal.detail.equals("ORDINARY_NAMESPACE_COLLISION") && catalog(exporter).definitions.isEmpty(),
                "complete callable inventory reserves future names before types");
        }
        System.out.println("owned typed alias parameter and catalog ordinary namespace controls passed");
    }
    static void targetAndRoleControls() throws Exception {
        refused(new Prototype(new UnsignedLongDataType()), ExportProgramModelOwned.PrototypeRefusalCode.UNSUPPORTED_SHAPE);
        refused(new Prototype(new FloatDataType(manager)), ExportProgramModelOwned.PrototypeRefusalCode.UNSUPPORTED_SHAPE);
        GuardedInteger unknownRank = new GuardedInteger();
        refused(new Prototype(unknownRank), ExportProgramModelOwned.PrototypeRefusalCode.UNSUPPORTED_SHAPE);
        check(unknownRank.clones == 0 && unknownRank.displays == 0, "unknown rank refused before clone/display");
        for (String model : new String[]{null, "__cdecl", "custom"}) {
            var result = extract(new Prototype(I) { @Override public String getModelName() { return model; } });
            check(result.typed == null && result.refusal.detail.startsWith("PROTOTYPE_"), "unknown/incompatible model refuses");
        }
        check(ExportProgramModelOwned.extractTypedPrototype(new Prototype(I), "probe", TaskMonitor.DUMMY, target, true).refusal.detail.equals(
            "PROTOTYPE_CONVENTION_OR_ROLE"), "custom storage refuses");
        for (Symbol symbol : List.of(new Symbol("x", I) { @Override public boolean isHiddenReturn() { return true; } },
            new Symbol("x", I) { @Override public boolean isThisPointer() { return true; } },
            new Symbol("x", I) { @Override public boolean isParameter() { return false; } },
            new Symbol("x", I) { @Override public int getCategoryIndex() { return 9; } })) {
            check(extract(new Prototype(I, symbol)).refusal.detail.equals("HIGH_PARAMETER_ROLE"), "contradictory typed roles refuse");
        }
        Symbol overlapping = new Symbol("second", I) { @Override public ghidra.program.model.listing.VariableStorage getStorage() { return storage(I, false); } };
        check(extract(new Prototype(I, new Symbol("first", I), overlapping)).refusal.detail.equals("PARAMETER_STORAGE_OVERLAP"), "overlapping formal storage refuses");
        java.io.IOException infrastructure = new java.io.IOException("authored encoder infrastructure failure");
        try {
            extract(new Prototype(I) { @Override public void encodePrototype(ghidra.program.model.pcode.Encoder encoder,
                PcodeDataTypeManager dtm, int first) throws java.io.IOException { throw infrastructure; } });
            throw new AssertionError("infrastructure error converted to fallback");
        } catch (java.io.IOException expected) { check(expected == infrastructure, "exact infrastructure failure propagates"); }
        var encodedCustom = new Prototype(I); encodedCustom.encodedCustom = true;
        check(extract(encodedCustom).refusal.detail.equals("PROTOTYPE_CONVENTION_OR_ROLE"), "native typed custom flag is independently checked");
        check(extract(new Prototype(I) { @Override public int getExtraPop() { return 0; } }).refusal.detail.equals("PROTOTYPE_STACK_EFFECT_UNKNOWN"), "stack effect contradiction");
        var mismatch = extract(new Prototype(I) { @Override public ghidra.program.model.listing.VariableStorage getReturnStorage() {
            return ghidra.program.model.listing.VariableStorage.VOID_STORAGE;
        }});
        check(mismatch.refusal.detail.equals("VOID_STORAGE_CONTRADICTION"), "return storage contradiction");
        var language = ghidra.program.util.DefaultLanguageService.getLanguageService().getLanguage(new ghidra.program.model.lang.LanguageID("x86:LE:32:default"));
        Object consumer = new Object();
        var p32 = new ghidra.program.database.ProgramDB("owned-ilp32", language,
            language.getCompilerSpecByID(new ghidra.program.model.lang.CompilerSpecID("gcc")), consumer);
        try {
            var context = ExportProgramModelOwned.TargetContext.capture(p32);
            var graph = new ExportProgramModelOwned.TypedGraph(TaskMonitor.DUMMY, context);
            var ilpLong = new UnsignedLongDataType(p32.getDataTypeManager());
            graph.validate(ilpLong); graph.finish();
            check(ilpLong.getLength() == 4 && graph.requirements.get(ilpLong.getPathName()).declaration.equals("typedef unsigned long ulong;"),
                "equal int and long widths retain exact long rank");
            try { new ExportProgramModelOwned.TypedGraph(TaskMonitor.DUMMY, target).validate(ilpLong); throw new AssertionError("foreign manager admitted"); }
            catch (ExportProgramModelOwned.PrototypeRejected expected) { check(expected.refusal.detail.equals("SCALAR_TARGET_MISMATCH"), expected.refusal.detail); }
        } finally { p32.release(consumer); }
        var organization = DataOrganizationImpl.getDefaultOrganization(program.getLanguage());
        organization.setLongSize(8); organization.setDefaultPointerAlignment(8); organization.setCharIsSigned(false);
        check(new ExportProgramModelOwned.TargetContext("x86:LE:64:default", "gcc", "__stdcall", organization).refusal != null,
            "unsigned plain char requires an unavailable compiler policy, never guessed host defaults");
        organization.setCharIsSigned(true); organization.setLongSize(4);
        check(new ExportProgramModelOwned.TargetContext("x86:LE:64:default", "gcc", "__stdcall", organization).refusal != null,
            "contradictory long and pointer target widths refuse");
        var unknown = new ExportProgramModelOwned.TargetContext("x86:LE:64:default", "windows", "__cdecl", manager.getDataOrganization());
        check(unknown.refusal != null, "compiler policy is explicit");
        System.out.println("owned target rank manager convention role and storage controls passed");
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
                    case "getValues": return new long[]{0};
                    case "getNames": check(a != null && a.length == 1, "do not sort unvalidated enum names inside Ghidra"); return names;
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

    static final String DATA_CONSTRUCTOR = "data-reference recovery refused: metadataRefusal=UNSUPPORTED_SHAPE;detail=TYPE_CONSTRUCTOR";
    static final String SIGNATURE_CONSTRUCTOR = "type recovery refused: metadataRefusal=UNSUPPORTED_SHAPE;detail=TYPE_CONSTRUCTOR";
    static void collectorStatuses(Object metadata, boolean complete) throws Exception {
        check((boolean)OwnedExporterReferencedBytesProbe.get(metadata, "evidenceComplete") == complete, "actual collector completeness");
        String name = (String)OwnedExporterReferencedBytesProbe.get(metadata, "name");
        var typed = ExportProgramModelOwned.extractTypedPrototype(new Prototype(I, new Symbol("value", I)), name, TaskMonitor.DUMMY, target, false);
        check(typed.typed != null, "authored typed outcome is admitted independently");
        check(OwnedExporterReferencedBytesProbe.get(render(metadata, null, false), "status").equals(complete ? "partial" : "failed"), "actual metadata planning status");
        for (String source : new String[]{null, "int " + name + "(int value) { return value; }"}) {
            Object full = render(metadata, new ExportProgramModelOwned.NativeOutcome(source, null, typed), true);
            check(OwnedExporterReferencedBytesProbe.get(full, "status").equals(source == null ? "failed" : complete ? "recovered" : "partial"),
                "actual metadata full status is never repaired by later success");
            check(Objects.equals(OwnedExporterReferencedBytesProbe.get(full, "failure"), OwnedExporterReferencedBytesProbe.get(metadata, "failure")),
                "rendering preserves independent collector failures");
        }
    }
    /** Public API objects feed the actual collectors; this is authored behavior, not native recovery. */
    static class CollectorFixture extends OwnedExporterReferencedBytesProbe.CollectionFixture {
        final Map<Long,DataType> dataTypes = new TreeMap<>();
        final Map<Long,Integer> selections = new TreeMap<>();
        int graphVisits;
        Runnable graphHook = () -> {};
        boolean callFailure;
        DataType returnType = I;
        CollectorFixture() {
            this(new ghidra.program.model.address.GenericAddressSpace("ram", 64, ghidra.program.model.address.AddressSpace.TYPE_RAM, 0),
                new ghidra.program.model.address.GenericAddressSpace("unique", 64, ghidra.program.model.address.AddressSpace.TYPE_UNIQUE, 1));
        }
        CollectorFixture(ghidra.program.model.address.AddressSpace ram, ghidra.program.model.address.AddressSpace unique) {
            super(ram, unique, new ghidra.program.model.address.DefaultAddressFactory(new ghidra.program.model.address.AddressSpace[]{ram, unique}));
        }
        DataType unsupported() {
            return OwnedExporterReferencedBytesProbe.proxy(DataType.class, (m,a) -> {
                switch (m.getName()) {
                    case "getLength": case "getAlignment": return 1;
                    case "getName": case "getDisplayName": return "authored_unsupported";
                    case "getPathName": return "/authored_unsupported";
                    case "getDefaultSettings": graphVisits++; graphHook.run(); return null;
                    default: return null;
                }
            });
        }
        void reference(long address, DataType type, int repeats) {
            dataTypes.put(address, type); batch(new long[]{address}, 0, repeats);
        }
        Function function(long entry) {
            return OwnedExporterReferencedBytesProbe.proxy(Function.class, (m,a) -> {
                switch (m.getName()) {
                    case "getCalledFunctions":
                        if (callFailure) throw new IllegalStateException("authored call failure");
                        return Collections.emptySet();
                    case "getEntryPoint": return ram.getAddress(entry);
                    case "getName": return "probe";
                    case "getPrototypeString": return "int probe(void)";
                    case "getReturnType": return returnType;
                    case "getParameters": return new ghidra.program.model.listing.Parameter[0];
                    default: return null;
                }
            });
        }
        @Override ghidra.program.model.listing.Program program() {
            var base = super.program();
            var listing = OwnedExporterReferencedBytesProbe.proxy(ghidra.program.model.listing.Listing.class, (m,a) -> {
                if (!m.getName().equals("getDataContaining")) return m.invoke(base.getListing(), a);
                long offset = ((ghidra.program.model.address.Address)a[0]).getOffset();
                DataType type = dataTypes.get(offset);
                if (type == null) return null;
                selections.merge(offset, 1, Integer::sum);
                return OwnedExporterReferencedBytesProbe.proxy(ghidra.program.model.listing.Data.class, (dm,da) -> {
                    switch (dm.getName()) {
                        case "getAddress": return ram.getAddress(offset);
                        case "getLength": return type.getLength();
                        case "isDefined": return true;
                        case "getDataType": case "getBaseDataType": return type;
                        case "getDefaultValueRepresentation": return "00h";
                        default: return null;
                    }
                });
            });
            return OwnedExporterReferencedBytesProbe.proxy(ghidra.program.model.listing.Program.class, (m,a) ->
                m.getName().equals("getListing") ? listing : m.invoke(base, a));
        }
        ExportProgramModelOwned prepare() throws Exception {
            var exporter = new ExportProgramModelOwned(); configure(exporter); run(exporter);
            selections.clear(); referenceVisits = 0; graphVisits = 0;
            return exporter;
        }
    }
    static ExportProgramModelOwned.PlannedTypeCoverage coverage(Object metadata) throws Exception {
        return (ExportProgramModelOwned.PlannedTypeCoverage)OwnedExporterReferencedBytesProbe.get(metadata, "coverage");
    }
    static CollectorFixture mixedCollector() {
        var fixture = new CollectorFixture();
        fixture.reference(0x10000, fixture.unsupported(), 1);
        fixture.reference(0x10200, alias("LaterLeaf", I), 1);
        return fixture;
    }
    static void collectorContinuationControls(Path root) throws Exception {
        Files.createDirectories(root);
        var fixture = mixedCollector(); fixture.returnType = Undefined1DataType.dataType;
        var exporter = fixture.prepare(); Object sink = evidence(new TreeSet<>());
        Object metadata = collect(exporter, fixture.function(0x1000), sink);
        check(OwnedExporterReferencedBytesProbe.get(metadata, "failure").equals(DATA_CONSTRUCTOR + "; " + SIGNATURE_CONSTRUCTOR), "exact two independent phase refusals");
        check(records(sink, "globals").keySet().equals(Set.of("global_0000000000010000", "global_0000000000010200")), "unsupported then valid raw globals retained");
        check(coverage(metadata).byPath.keySet().equals(Set.of("/LaterLeaf")) && catalog(exporter).definitions.keySet().equals(Set.of("/LaterLeaf")), "only later admitted closure is covered");
        collectorStatuses(metadata, false);
        var snapshot = coverage(metadata);
        fixture.dataTypes.put(0x10200L, alias("FutureLeaf", I));
        collect(exporter, fixture.function(0x1010), evidence(new TreeSet<>()));
        check(snapshot.byPath.keySet().equals(Set.of("/LaterLeaf")), "future success cannot widen immutable earlier coverage");

        // Normal files, planning collector, and catalog-only replay share the exact collector path.
        var normalFixture = mixedCollector(); normalFixture.returnType = Undefined1DataType.dataType;
        var normal = normalFixture.prepare();
        Path globals = Files.createDirectories(root.resolve("normal-globals")), types = Files.createDirectories(root.resolve("normal-types"));
        Object normalMetadata = call(normal, "collectFunctionMetadata", new Class<?>[]{Function.class, Path.class, Path.class, nested("PlanningBatchEvidence")},
            normalFixture.function(0x1000), globals, types, null);
        check(outcome(render(metadata, null, false)).equals(outcome(render(normalMetadata, null, false))), "normal and planning complete records/status/failures identical");
        for (var entry : records(sink, "globals").entrySet()) check(Files.readString(globals.resolve(entry.getKey() + ".json")).equals(entry.getValue()), "normal raw globals exact");
        for (var entry : records(sink, "types").entrySet()) check(Files.readString(types.resolve(entry.getKey() + ".json")).equals(entry.getValue()), "normal first type owner exact");
        var replayFixture = mixedCollector(); replayFixture.returnType = Undefined1DataType.dataType;
        var replayed = replayFixture.prepare();
        Object replayMetadata = call(replayed, "collectFunctionMetadata", new Class<?>[]{Function.class, Path.class, Path.class, nested("PlanningBatchEvidence"), boolean.class},
            replayFixture.function(0x1000), null, null, null, true);
        check(outcome(render(metadata, null, false)).equals(outcome(render(replayMetadata, null, false))), "catalog-only retains complete record/status/failure without evidence paths");
        for (String source : new String[]{null, "authored body"}) {
            var nativeOutcome = new ExportProgramModelOwned.NativeOutcome(source, "authored independent native failure", extract(new Prototype(I)));
            String expected = outcome(render(metadata, nativeOutcome, true));
            check(expected.equals(outcome(render(normalMetadata, nativeOutcome, true))) && expected.equals(outcome(render(replayMetadata, nativeOutcome, true))),
                "normal planning and catalog-only full records/status/failures identical");
        }
        check(catalog(replayed).ordinaryNames.equals(catalog(normal).ordinaryNames), "catalog replay retains rejected raw global reservation");
        for (var entry : snapshot.byPath.entrySet()) check(entry.getValue().same(coverage(replayMetadata).byPath.get(entry.getKey())), "same target and definition commitments");
        fullCollectorBindings(root.resolve("bindings"), metadata);
        System.out.println("owned actual collector local refusal normal planning catalog replay and bindings passed");
    }
    static void fullCollectorBindings(Path root, Object metadata) throws Exception {
        Files.createDirectories(root);
        var exporter = new ExportProgramModelOwned();
        Object full = render(metadata, new ExportProgramModelOwned.NativeOutcome("authored body", null, extract(new Prototype(I))), true);
        Path failures = Files.createDirectories(root.resolve("failures"));
        Path record = root.resolve("fn_0000000000001000.json"), sidecar = failures.resolve(record.getFileName());
        Path binding = root.resolve(record.getFileName() + ".binding");
        String renderedFailure = (String)call(exporter, "renderFunctionFailure", new Class<?>[]{String.class, nested("FunctionExport")}, "fn_0000000000001000", full);
        Files.writeString(record, (String)OwnedExporterReferencedBytesProbe.get(full, "record"));
        Files.writeString(sidecar, renderedFailure);
        Files.writeString(binding, (String)call(exporter, "currentFullBinding", new Class<?>[]{Path.class, Path.class}, record, sidecar));
        check((boolean)call(exporter, "acceptedFullCheckpoint", new Class<?>[]{Path.class, Path.class}, record, failures), "actual mixed full checkpoint accepted exactly");
        for (boolean delete : new boolean[]{false, true}) {
            Files.writeString(sidecar, renderedFailure);
            if (delete) Files.delete(sidecar); else Files.writeString(sidecar, renderedFailure.replace("TYPE_CONSTRUCTOR", "OTHER_CONSTRUCTOR"));
            try { call(exporter, "acceptedFullCheckpoint", new Class<?>[]{Path.class, Path.class}, record, failures); throw new AssertionError("mixed failure mutation/deletion accepted"); }
            catch (InvocationTargetException expected) { check(expected.getCause().getClass().getSimpleName().equals("PlanningIntegrityException"), expected); }
        }
    }
    static void collectorRepeatAndAtomicityControls() throws Exception {
        String oneFailure = null;
        for (int repeats : new int[]{1, 64, 256}) {
            var fixture = new CollectorFixture(); fixture.callFailure = true; fixture.returnType = Undefined1DataType.dataType;
            fixture.reference(0x10000, fixture.unsupported(), repeats);
            fixture.reference(0x10200, alias("LaterLeaf", I), 1);
            var exporter = fixture.prepare(); Object sink = evidence(new TreeSet<>());
            Object metadata = collect(exporter, fixture.function(0x1000), sink);
            String failure = (String)OwnedExporterReferencedBytesProbe.get(metadata, "failure");
            if (oneFailure == null) oneFailure = failure;
            check(failure.equals(oneFailure) && failure.equals("call recovery failed: IllegalStateException: authored call failure; " + DATA_CONSTRUCTOR + "; " + SIGNATURE_CONSTRUCTOR),
                "constant diagnostic size even with earlier call failure");
            check(fixture.graphVisits == repeats && fixture.referenceVisits == repeats + 1, "raw duplicates charged and every refused graph attempted");
            check(records(sink, "globals").size() == 2 && coverage(metadata).byPath.size() == 1, "repeat refusal never contributes coverage");
        }
        var bounded = new CollectorFixture();
        bounded.reference(0x10000, bounded.unsupported(), 256);
        var boundedExporter = bounded.prepare();
        // Add an oversized, wholly unadmitted batch after collecting the first real origin.
        // No allowance or byte cutoff is reset; its target must never require an origin.
        bounded.reference(0x10200, alias("BeyondBudget", I), 65536 - 256 + 1);
        Object boundedSink = evidence(new TreeSet<>());
        Object boundedMetadata = collect(boundedExporter, bounded.function(0x1000), boundedSink);
        check(bounded.referenceVisits == 65537 && bounded.graphVisits == 256 && !bounded.selections.containsKey(0x10200L), "whole over-budget batch rejected with charged raw work");
        check(OwnedExporterReferencedBytesProbe.get(boundedMetadata, "failure").equals(DATA_CONSTRUCTOR + "; metadataRefusal=REFERENCE_WORK_LIMIT"), "exact metadata limit follows constant local refusal");
        check(OwnedExporterReferencedBytesProbe.get(boundedExporter, "referenceCollectionCutoff") == null && records(boundedSink, "globals").size() == 1, "metadata bound never fabricates byte cutoff or later raw global");

        var atomic = new CollectorFixture();
        StructureDataType rejected = new StructureDataType(CategoryPath.ROOT, "RejectedClosure", 0, manager);
        rejected.setPackingEnabled(true); rejected.add(alias("RejectedPrefix", I), "valid", null); rejected.add(Undefined4DataType.dataType, "unsupported", null);
        check(rejected.getDefinedComponents().length == 2 && rejected.getComponent(0).getDataType() instanceof TypeDef &&
            rejected.getComponent(1).getDataType() instanceof Undefined, "authored graph has a valid named prefix before its unsupported node");
        atomic.reference(0x10000, alias("EarlierLeaf", I), 1);
        atomic.reference(0x10200, rejected, 1);
        atomic.reference(0x10400, alias("LaterLeaf", I), 1);
        var atomicExporter = atomic.prepare(); Object atomicSink = evidence(new TreeSet<>());
        Object atomicMetadata = collect(atomicExporter, atomic.function(0x1000), atomicSink);
        check(OwnedExporterReferencedBytesProbe.get(atomicMetadata, "failure").equals(DATA_CONSTRUCTOR), "valid prefix then unsupported node is a local constructor refusal");
        check(coverage(atomicMetadata).byPath.keySet().equals(Set.of("/EarlierLeaf", "/LaterLeaf")) && catalog(atomicExporter).definitions.keySet().equals(coverage(atomicMetadata).byPath.keySet()), "rejected closure contributes no partial catalog or coverage");
        check(records(atomicSink, "types").size() == 2 && records(atomicSink, "types").values().stream().noneMatch(s -> s.contains("Rejected")) &&
            catalog(atomicExporter).spellings.keySet().stream().noneMatch(s -> s.contains("Rejected")), "no rejected definition sidecar or spelling");
        check(records(atomicSink, "globals").size() == 3, "raw rejected aggregate still observed");
        Object raw = call(atomicExporter, "globalAt", new Class<?>[]{ghidra.program.model.address.Address.class}, atomic.ram.getAddress(0x10200));
        String rawName = (String)OwnedExporterReferencedBytesProbe.get(raw, "name");
        check(catalog(atomicExporter).ordinaryNames.contains(rawName), "rejected raw global keeps reservation");
        try { catalog(atomicExporter).admit(planned(List.of(alias(rawName, I))).byPath, () -> {}); throw new AssertionError("rejected global reservation lost"); }
        catch (ExportProgramModelOwned.PrototypeRejected expected) { check(expected.refusal.detail.equals("ORDINARY_NAMESPACE_COLLISION"), expected.refusal.detail); }
        System.out.println("owned actual collector repeated refusal charged bound and graph atomicity passed");
    }
    static void stoppedCollector(CollectorFixture fixture, ExportProgramModelOwned exporter, String detail) throws Exception {
        Object sink = evidence(new TreeSet<>());
        Object metadata = collect(exporter, fixture.function(0x1000), sink);
        check(!(boolean)OwnedExporterReferencedBytesProbe.get(metadata, "evidenceComplete") &&
            ((String)OwnedExporterReferencedBytesProbe.get(metadata, "failure")).contains("detail=" + detail), "nonlocal collector refusal " + detail);
        check(!fixture.selections.containsKey(0x10200L) && records(sink, "globals").size() <= 1 && coverage(metadata).byPath.isEmpty(),
            "nonlocal refusal stops before later valid data: " + detail);
        collectorStatuses(metadata, false);
    }
    static void collectorHardBoundaryControls(Path root) throws Exception {
        Files.createDirectories(root);
        // A null child reaches the graph (the raw typedef observation itself remains valid).
        TypeDef nullChild = OwnedExporterReferencedBytesProbe.proxy(TypeDef.class, (m,a) -> {
            switch (m.getName()) {
                case "getLength": case "getAlignment": return 4;
                case "getName": case "getDisplayName": return "NullChild";
                case "getPathName": return "/NullChild";
                default: return null;
            }
        });
        DataType deep = I; for (int depth = 0; depth < 33; depth++) deep = pointer(deep, 8);
        var otherShape = pointer(I, 4);
        List<DataType> refused = List.of(nullChild, alias("bad-name", I), otherShape, deep);
        String[] details = {"MISSING_DATA_TYPE", "TYPE_NAME", "POINTER_TARGET_LAYOUT", "TYPE_GRAPH"};
        for (int index = 0; index < refused.size(); index++) {
            var fixture = mixedCollector(); fixture.dataTypes.put(0x10000L, refused.get(index));
            var exporter = fixture.prepare(); stoppedCollector(fixture, exporter, details[index]);
            check(catalog(exporter).definitions.isEmpty(), "nonlocal rejected graph contributes no definitions");
        }
        var unknown = mixedCollector(); var unknownExporter = unknown.prepare();
        OwnedExporterReferencedBytesProbe.field(unknownExporter, "targetContext",
            new ExportProgramModelOwned.TargetContext("x86:LE:64:default", "windows", "__cdecl", manager.getDataOrganization()));
        stoppedCollector(unknown, unknownExporter, "TARGET_C_POLICY_UNKNOWN");
        var unexpected = mixedCollector(); var unexpectedExporter = unexpected.prepare();
        unexpected.graphHook = () -> { throw new IllegalStateException("authored unexpected graph failure"); };
        Object unexpectedMetadata = collect(unexpectedExporter, unexpected.function(0x1000), evidence(new TreeSet<>()));
        check(OwnedExporterReferencedBytesProbe.get(unexpectedMetadata, "failure").equals("data-reference recovery failed: IllegalStateException: authored unexpected graph failure") &&
            !unexpected.selections.containsKey(0x10200L), "ordinary unexpected exception retains outer stop and diagnostic");

        // Existing catalog conflicts and exhausted catalog/name bounds are outer-phase stops.
        for (String conflict : List.of("namespace", "definition", "spelling", "catalog", "name")) {
            var fixture = mixedCollector(); fixture.dataTypes.put(0x10000L, alias("Conflict", I));
            var exporter = fixture.prepare(); var catalog = catalog(exporter); String detail;
            if (conflict.equals("namespace")) {
                Object raw = call(exporter, "globalAt", new Class<?>[]{ghidra.program.model.address.Address.class}, fixture.ram.getAddress(0x10000));
                catalog.admit(planned(List.of(alias((String)OwnedExporterReferencedBytesProbe.get(raw, "name"), I))).byPath, () -> {});
                detail = "ORDINARY_NAMESPACE_COLLISION";
            } else if (conflict.equals("definition")) {
                catalog.admit(planned(List.of(alias("Conflict", L))).byPath, () -> {}); detail = "NAMED_TYPE_CHANGED";
            } else if (conflict.equals("spelling")) {
                catalog.admit(planned(List.of(alias(new CategoryPath("/other"), "Conflict", I))).byPath, () -> {}); detail = "C_SPELLING_COLLISION";
            } else if (conflict.equals("catalog")) {
                for (int start = 0; start < 4096; start += 8) {
                    List<DataType> roots = new ArrayList<>();
                    for (int n = start; n < start + 8; n++) roots.add(alias("Catalog" + n, I));
                    catalog.admit(planned(roots).byPath, () -> {});
                }
                detail = "PLANNED_NAMED_TYPES";
            } else {
                // Authored pre-existing exhausted state, not a production allowance/reset.
                catalog.ordinaryNameBytes = 4 * 1024 * 1024; detail = "ORDINARY_NAMESPACE";
            }
            Map<String,ExportProgramModelOwned.TypeRequirement> definitions = new TreeMap<>(catalog.definitions);
            Map<String,String> spellings = new TreeMap<>(catalog.spellings);
            stoppedCollector(fixture, exporter, detail);
            check(catalog.definitions.equals(definitions) && catalog.spellings.equals(spellings), "nonlocal catalog refusal is atomic " + conflict);
        }

        // Trigger cancellation while the unsupported constructor is being inspected, so the
        // narrow catch must rethrow the original refusal before considering continuation.
        for (boolean threadOnly : new boolean[]{false, true}) {
            var fixture = mixedCollector(); var exporter = fixture.prepare();
            TaskMonitorAdapter monitor = new TaskMonitorAdapter(true);
            OwnedExporterReferencedBytesProbe.field(exporter, "monitor", monitor);
            fixture.graphHook = () -> { if (threadOnly) Thread.currentThread().interrupt(); else monitor.cancel(); };
            Object sink = evidence(new TreeSet<>());
            try { collect(exporter, fixture.function(0x1000), sink); throw new AssertionError("cancelled failed graph continued"); }
            catch (InvocationTargetException expected) {
                check(expected.getCause() instanceof ExportProgramModelOwned.PrototypeRejected &&
                    ((ExportProgramModelOwned.PrototypeRejected)expected.getCause()).refusal.detail.equals("TYPE_CONSTRUCTOR"), "infrastructure check preserves originating refusal");
                check(threadOnly ? Thread.currentThread().isInterrupted() && !monitor.isCancelled() : monitor.isCancelled(), "cancellation state retained");
                check(!fixture.selections.containsKey(0x10200L) && records(sink, "globals").size() == 1 && catalog(exporter).definitions.isEmpty(), "cancelled graph does not scan later data");
            } finally { if (threadOnly) Thread.interrupted(); }
        }
        // Cancel at the first new iteration after a refused graph, with no monitor flag for
        // the thread-only variant. The signature API must remain unreachable.
        for (boolean threadOnly : new boolean[]{false, true}) {
            var fixture = mixedCollector(); var exporter = fixture.prepare();
            boolean[] refusedGraph = {false}; int[] checksAfterGraph = {0};
            fixture.graphHook = () -> refusedGraph[0] = true;
            TaskMonitor monitor = OwnedExporterReferencedBytesProbe.proxy(TaskMonitor.class, (m,a) -> {
                if (m.getName().equals("isCancelled") && refusedGraph[0] && ++checksAfterGraph[0] >= 2) {
                    if (threadOnly) { Thread.currentThread().interrupt(); return false; }
                    return true;
                }
                return null;
            });
            OwnedExporterReferencedBytesProbe.field(exporter, "monitor", monitor);
            try { collect(exporter, fixture.function(0x1000), evidence(new TreeSet<>())); throw new AssertionError("post-refusal cancellation continued"); }
            catch (InvocationTargetException expected) {
                check(expected.getCause() instanceof InterruptedException && !fixture.selections.containsKey(0x10200L), "next iteration cancellation propagates");
                check(Thread.currentThread().isInterrupted(), "outer catch restores interrupt for InterruptedException");
            } finally { Thread.interrupted(); }
        }
        // Real filesystem publication failure from planTypeCoverage after an earlier local
        // refusal must escape. A following third reference detects accidental continuation.
        var io = mixedCollector(); io.reference(0x10400, alias("NeverAfterIO", I), 1);
        var ioExporter = io.prepare(); Path globals = Files.createDirectories(root.resolve("io-globals"));
        Path typesFile = root.resolve("not-a-directory"); Files.writeString(typesFile, "authored publication obstacle");
        try {
            call(ioExporter, "collectFunctionMetadata", new Class<?>[]{Function.class, Path.class, Path.class, nested("PlanningBatchEvidence")}, io.function(0x1000), globals, typesFile, null);
            throw new AssertionError("type publication IOException became partial evidence");
        } catch (InvocationTargetException expected) {
            check(expected.getCause() instanceof java.io.IOException && !io.selections.containsKey(0x10400L), "actual I/O stops collection");
        }
        var integrity = mixedCollector(); var integrityExporter = integrity.prepare(); Object integritySink = evidence(new TreeSet<>());
        // Force the existing bounded planning sink to refuse its first actual publication.
        OwnedExporterReferencedBytesProbe.field(integritySink, "globalBytes", Long.MAX_VALUE / 2);
        try { collect(integrityExporter, integrity.function(0x1000), integritySink); throw new AssertionError("planning integrity failure downgraded"); }
        catch (InvocationTargetException expected) {
            check(expected.getCause().getClass().getSimpleName().equals("PlanningIntegrityException") && !integrity.selections.containsKey(0x10200L), "actual integrity failure propagates");
            check(records(integritySink, "globals").isEmpty(), "failed publication contributes no raw fragment");
        }
        var typeIntegrity = mixedCollector(); typeIntegrity.reference(0x10400, alias("NeverAfterIntegrity", I), 1);
        var typeIntegrityExporter = typeIntegrity.prepare(); Object typeSink = evidence(new TreeSet<>());
        OwnedExporterReferencedBytesProbe.field(typeSink, "typeBytes", Long.MAX_VALUE / 2);
        try { collect(typeIntegrityExporter, typeIntegrity.function(0x1000), typeSink); throw new AssertionError("type integrity failure downgraded after local refusal"); }
        catch (InvocationTargetException expected) {
            check(expected.getCause().getClass().getSimpleName().equals("PlanningIntegrityException") && !typeIntegrity.selections.containsKey(0x10400L) &&
                records(typeSink, "globals").size() == 2 && records(typeSink, "types").isEmpty(), "planTypeCoverage integrity failure retains propagation and no later scanning");
        }
        var missing = mixedCollector(); var missingExporter = missing.prepare();
        @SuppressWarnings("unchecked") Map<String,String> origins = (Map<String,String>)OwnedExporterReferencedBytesProbe.get(missingExporter, "referencedByteEvidence");
        origins.remove("global_0000000000010000");
        try { collect(missingExporter, missing.function(0x1000), evidence(new TreeSet<>())); throw new AssertionError("missing origin became partial"); }
        catch (InvocationTargetException expected) {
            check(expected.getCause().getClass().getSimpleName().equals("PlanningIntegrityException") && expected.getCause().getMessage().startsWith("missing reference byte-evidence origin:") &&
                !missing.selections.containsKey(0x10200L), "actual missing origin stops before local type admission");
        }
        var conflicting = new CollectorFixture(); conflicting.reference(0x10000, conflicting.unsupported(), 2); conflicting.conflicting = true;
        var conflictExporter = new ExportProgramModelOwned(); configure(conflictExporter);
        try { conflicting.run(conflictExporter); throw new AssertionError("conflicting origin prepass admitted"); }
        catch (InvocationTargetException expected) {
            check(expected.getCause().getClass().getSimpleName().equals("PlanningIntegrityException") && expected.getCause().getMessage().startsWith("conflicting reference byte-evidence origin:") &&
                conflicting.graphVisits == 0, "conflicting origins fail before type continuation is possible");
        }
        System.out.println("owned actual collector cancellation IO integrity origin target conflict and limits passed");
    }
    static final class ResumeFixture {
        final ExportProgramModelOwned exporter = new ExportProgramModelOwned();
        final List<Function> functions = new ArrayList<>();
        final List<ExportProgramModelOwned.PrototypeResult> typed = new ArrayList<>();
        ResumeFixture(String scenario) throws Exception {
            var ram = new ghidra.program.model.address.GenericAddressSpace("ram", 64, ghidra.program.model.address.AddressSpace.TYPE_RAM, 0);
            var listing = OwnedExporterReferencedBytesProbe.proxy(ghidra.program.model.listing.Listing.class, (m,a) ->
                m.getName().equals("getInstructions") ? OwnedExporterReferencedBytesProbe.proxy(ghidra.program.model.listing.InstructionIterator.class, (im,ia) -> null) : null);
            configure(exporter);
            OwnedExporterReferencedBytesProbe.field(exporter, "currentProgram", OwnedExporterReferencedBytesProbe.proxy(ghidra.program.model.listing.Program.class,
                (m,a) -> m.getName().equals("getListing") ? listing : null));
            if (scenario.equals("continuation")) mixedCollector().run(exporter);
            for (int i = 0; i < 514; i++) {
                int index = i;
                List<DataType> roots = new ArrayList<>();
                if (scenario.equals("limit")) {
                    if (i < 512) for (int n = 0; n < 8; n++) roots.add(alias("T" + (i * 8 + n), I));
                    else {
                        roots.add(alias("T0", I));
                        if (i == 512) roots.add(alias("Overflow", I));
                    }
                } else if (i == 0 || i >= 512) {
                    roots.add(alias(new CategoryPath(scenario.equals("collision") && i == 512 ? "/b" : "/a"), "X",
                        scenario.equals("definition") && i == 512 ? L : I));
                }
                ghidra.program.model.listing.Parameter[] params = new ghidra.program.model.listing.Parameter[roots.size()];
                HighSymbol[] symbols = new HighSymbol[roots.size()];
                for (int n = 0; n < roots.size(); n++) {
                    DataType type = pointer(roots.get(n), 8);
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
                        case "getReturnType": return I;
                        case "getParameters": return params;
                        default: return null;
                    }
                }));
                typed.add(extract(new Prototype(I, symbols)));
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
        for (String scenario : List.of("collision", "definition", "limit", "continuation")) {
            ResumeFixture fixture = new ResumeFixture(scenario);
            var exporter = fixture.exporter;
            var functions = fixture.functions;
            Object semantic = call(exporter, "computePlanningSemanticState", new Class<?>[]{List.class}, functions);
            var expectedBatches = (List<ExporterSemanticFingerprintOwnedV1.BatchCommitment>)OwnedExporterReferencedBytesProbe.get(semantic, "batches");
            List<String> full = new ArrayList<>();
            Set<String> owned = new TreeSet<>();
            Set<String> ownedGlobals = new TreeSet<>();
            List<Set<String>> prefixOwners = new ArrayList<>();
            List<Set<String>> prefixGlobalOwners = new ArrayList<>();
            Map<String,String> firstTypes = new TreeMap<>();
            catalog(exporter).clear();
            for (int start = 0; start < functions.size(); start += 512) {
                Object evidence = evidence(owned);
                @SuppressWarnings("unchecked") Set<String> previousGlobals = (Set<String>)OwnedExporterReferencedBytesProbe.get(evidence, "previouslyOwnedGlobalIds");
                previousGlobals.addAll(ownedGlobals);
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
                var actual = ExporterSemanticFingerprintOwnedV1.commitBatch(start, end, String.join(",\n", plans), String.join(",\n", records(evidence, "globals").values()),
                    String.join(",\n", records(evidence, "types").values()), String.join(",\n", records(evidence, "failures").values()));
                ExporterSemanticFingerprintOwnedV1.requireBatchCommitment(expectedBatches.get(start / 512), actual);
                if (scenario.equals("continuation")) {
                    String[] fragments = {String.join(",\n", plans), String.join(",\n", records(evidence, "globals").values()),
                        String.join(",\n", records(evidence, "types").values()), String.join(",\n", records(evidence, "failures").values())};
                    for (int fragment = 0; fragment < fragments.length; fragment++) {
                        String[] mutated = fragments.clone(); mutated[fragment] += " ";
                        var changed = ExporterSemanticFingerprintOwnedV1.commitBatch(start, end, mutated[0], mutated[1], mutated[2], mutated[3]);
                        try { ExporterSemanticFingerprintOwnedV1.requireBatchCommitment(actual, changed); throw new AssertionError("mixed replay fragment mutation accepted " + fragment); }
                        catch (IllegalStateException expected) { }
                    }
                    var deletedFailure = ExporterSemanticFingerprintOwnedV1.commitBatch(start, end, fragments[0], fragments[1], fragments[2], "");
                    try { ExporterSemanticFingerprintOwnedV1.requireBatchCommitment(actual, deletedFailure); throw new AssertionError("mixed planning failure deletion accepted"); }
                    catch (IllegalStateException expected) { }
                }
                owned.addAll(records(evidence, "types").keySet());
                ownedGlobals.addAll(records(evidence, "globals").keySet());
                prefixGlobalOwners.add(new TreeSet<>(ownedGlobals));
                prefixOwners.add(new TreeSet<>(owned)); firstTypes.putAll(records(evidence, "types"));
            }
            if (scenario.equals("continuation")) {
                check(full.stream().allMatch(record -> record.endsWith("STATUS=partial") && record.contains(DATA_CONSTRUCTOR) && record.contains("global_0000000000010200")),
                    "every mixed replay retains later leaf but remains partial");
                check(firstTypes.values().stream().anyMatch(record -> record.contains("LaterLeaf") && record.contains("0x10200")), "selected referenced data is the first type owner");
            } else {
                check(full.get(512).endsWith("STATUS=partial") && full.get(513).endsWith("STATUS=recovered"), "conflict/limit is refused and repeat owner remains valid");
                check(full.get(512).contains(scenario.equals("limit") ? "PLANNED_NAMED_TYPES" : scenario.equals("collision") ? "C_SPELLING_COLLISION" : "NAMED_TYPE_CHANGED"), "specific resume refusal");
            }
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
                check(catalog(exporter).definitions.size() == (scenario.equals("limit") ? 4096 : scenario.equals("continuation") ? 2 : 1), "reused entries share invocation-wide limit");
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
                @SuppressWarnings("unchecked") Set<String> previousGlobals = (Set<String>)OwnedExporterReferencedBytesProbe.get(evidence, "previouslyOwnedGlobalIds");
                previousGlobals.addAll(prefixGlobalOwners.get(0));
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
                var actual = ExporterSemanticFingerprintOwnedV1.commitBatch(512, 514, String.join(",\n", plans), String.join(",\n", records(evidence, "globals").values()),
                    String.join(",\n", records(evidence, "types").values()), String.join(",\n", records(evidence, "failures").values()));
                ExporterSemanticFingerprintOwnedV1.requireBatchCommitment(expectedBatches.get(1), actual);
                check(records(evidence, "types").isEmpty(), "accepted prefix keeps first type owners at interruption " + interruptedAt);
                check(records(evidence, "globals").isEmpty(), "accepted prefix keeps first global owners at interruption " + interruptedAt);
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
        System.out.println("owned local refusal 514 function sparse contiguous replay four commitments passed");
    }

    public static void main(String[] args) throws Exception {
        ghidra.framework.Application.initializeApplication(new ghidra.GhidraApplicationLayout(Path.of(args[1]).toFile()),
            new ghidra.framework.HeadlessGhidraApplicationConfiguration());
        var language = ghidra.program.util.DefaultLanguageService.getLanguageService().getLanguage(new ghidra.program.model.lang.LanguageID("x86:LE:64:default"));
        Object consumer = new Object();
        program = new ghidra.program.database.ProgramDB("owned-faithful-types", language,
            language.getCompilerSpecByID(new ghidra.program.model.lang.CompilerSpecID("gcc")), consumer);
        manager = program.getDataTypeManager(); target = ExportProgramModelOwned.TargetContext.capture(program);
        I = new IntegerDataType(manager); L = new LongDataType(manager); C = new CharDataType(manager);
        UI = new UnsignedIntegerDataType(manager); UL = new UnsignedLongDataType(manager); LL = new LongLongDataType(manager);
        try { runControls(args); } finally { program.release(consumer); }
    }
    static void runControls(String[] args) throws Exception {
        var zero = extract(new Prototype(VoidDataType.dataType));
        check(zero.typed != null && zero.typed.declaration.equals("void probe(void)") && zero.typed.parameters.isEmpty(), "actual typed zero params");
        DataType pointer = pointer(C, 8);
        var scalarPointers = extract(new Prototype(I, new Symbol("value", I),
            new Symbol("text", pointer), new Symbol("output", pointer(pointer, 8))));
        check(scalarPointers.typed != null && scalarPointers.typed.parameters.size() == 3 && scalarPointers.origin == ExportProgramModelOwned.PrototypeOrigin.HIGH_FUNCTION,
            "three typed scalar/pointer/pointer-to-pointer parameters");
        var variadic = new Prototype(I, new Symbol("param_1", I)); variadic.variadic = true;
        var result = extract(variadic);
        check(result.typed != null && result.typed.variadic && result.typed.declaration.contains("param_1, ..."), "default names and varargs preserved");
        var noFixed = new Prototype(I); noFixed.variadic = true;
        refused(noFixed, ExportProgramModelOwned.PrototypeRefusalCode.UNSUPPORTED_SHAPE);
        refused(new Prototype(null), ExportProgramModelOwned.PrototypeRefusalCode.NULL_TYPE);
        refused(new Prototype(I, (HighSymbol)null), ExportProgramModelOwned.PrototypeRefusalCode.NULL_SYMBOL);
        refused(new Prototype(I, new Symbol("value", null)), ExportProgramModelOwned.PrototypeRefusalCode.NULL_TYPE);
        for (String name : new String[]{null, "", "bad-name", "void"})
            refused(new Prototype(I, new Symbol(name, I)), ExportProgramModelOwned.PrototypeRefusalCode.INVALID_NAME);
        refused(new Prototype(I, new Symbol("x", I), new Symbol("x", I)), ExportProgramModelOwned.PrototypeRefusalCode.INVALID_NAME);
        refused(new Prototype(I, new Symbol("array", array(I, 4, 4))), ExportProgramModelOwned.PrototypeRefusalCode.UNSUPPORTED_SHAPE);
        refused(new Prototype(pointer(new FunctionDefinitionDataType("callback"), 8)), ExportProgramModelOwned.PrototypeRefusalCode.UNSUPPORTED_SHAPE);
        check(ExportProgramModelOwned.extractTypedPrototype((ghidra.app.decompiler.DecompileResults)null, "probe", TaskMonitor.DUMMY, target).refusal.code ==
            ExportProgramModelOwned.PrototypeRefusalCode.NO_HIGH_FUNCTION, "null HighFunction is not void");
        TypeDef alias = alias("Count", I);
        var named = extract(new Prototype(I, new Symbol("value", pointer(alias, 8))));
        check(named.typed != null && named.typed.requirements.size() == 1, "pointer-to-typedef retains alias");
        var namedPointer = extract(new Prototype(I, new Symbol("value", alias("CountPointer", pointer(alias, 8)))));
        check(namedPointer.typed != null && namedPointer.typed.requirements.size() == 2, "typedef-to-pointer retains both aliases");
        check(ExportProgramModelOwned.checkCoverage(named.typed, new ExportProgramModelOwned.PlannedTypeCoverage(Map.of())).code ==
            ExportProgramModelOwned.PrototypeRefusalCode.UNPLANNED_TYPE, "native-only named type refuses");
        builtinAliasControls();
        faithfulTypeControls(Path.of(args[0]).resolve("faithful"));
        targetAndRoleControls();
        ordinaryNamespaceControls();
        enumExtractionControls();
        collectorContinuationControls(Path.of(args[0]).resolve("collector"));
        collectorRepeatAndAtomicityControls();
        collectorHardBoundaryControls(Path.of(args[0]).resolve("collector-hard"));
        catalogResumeControls();
        boundsAndCancellation();
        lifecycleControls();
        renderingAndBindings(Path.of(args[0]));
        typeClosureControls(Path.of(args[0]).resolve("coverage"));
        System.out.println("owned typed prototype API probe passed");
    }
}
