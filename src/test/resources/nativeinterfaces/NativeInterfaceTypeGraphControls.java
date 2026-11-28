import ghidra.program.model.data.*;
import java.lang.reflect.*;
import java.nio.file.*;
import java.util.*;

/** Actual native datatypes plus pre-access guard doubles; invoked by the fresh bundled JVM test. */
public final class NativeInterfaceTypeGraphControls {
    private static final DataOrganization ORGANIZATION = DataOrganizationImpl.getDefaultOrganization();
    private static final NativeInterfaceTypeGraphV1.Limits DEFAULTS = NativeInterfaceTypeGraphV1.Limits.defaults();
    private static int cases;

    public static void main(String[] args) throws Exception { ghidra.util.UniversalIdGenerator.initialize(); run(Path.of(args[0])); }
    public static void run(Path evidence) throws Exception {
        cases = 0;
        actualNativeKindsAndIdentity();
        actualRecursivePointer();
        missingAndUnsupportedRemainVisible();
        missingFunctionCountDoesNotAllocateArguments();
        nodeBoundBeforeMetadata();
        componentBoundBeforeAccess();
        referenceBoundBeforeChildAccess();
        depthBoundBeforeChildTraversal();
        deepNativeGettersFollowDependencyPreflight();
        undefinedArrayLookupFollowsReferenceAdmission();
        recursiveByValueMetadataRejectedBeforeGetters();
        reusedRootHeightCannotBypassDepth();
        exactAggregateWorkAndSharedCounters();
        utf8BoundIsBytes();
        cancellationBeforeMetadata();
        organizationCountBeforeArrayAllocation();
        lowerOnlyBounds();
        Files.createDirectories(evidence);
        Files.writeString(evidence.resolve("type-graph-controls.txt"),
            "passed=" + cases + "\nactual-native-kinds\nactual-recursive-backedge\nidentity-not-name\n" +
            "unknown-not-empty\npre-access-bounds\naggregate-work\nutf8-bytes\ncancellation\n");
    }

    private static void actualNativeKindsAndIdentity() throws Exception {
        List<Map<String, Object>> rows = new ArrayList<>();
        NativeInterfaceTypeGraphV1.Budget budget = budget(DEFAULTS);
        NativeInterfaceTypeGraphV1 graph = new NativeInterfaceTypeGraphV1(ORGANIZATION, budget, rows::add);
        Map<String, Object> organization = graph.dataOrganization();
        check(organization.get("bigEndian").equals(ORGANIZATION.isBigEndian()), "native organization context");
        NativeInterfaceTypeGraphV1.Scope scope = graph.scope("listing", 0);
        StructureDataType left = new StructureDataType("SameName", 0);
        left.add(IntegerDataType.dataType, "value", null);
        StructureDataType right = new StructureDataType("SameName", 0);
        right.add(IntegerDataType.dataType, "other", null);
        int leftId = scope.reference(left);
        int rightId = scope.reference(right);
        check(leftId != rightId, "same-name native objects must not merge");
        check(scope.reference(left) == leftId, "same native object must be reused within scope");
        UnionDataType union = new UnionDataType("SameExtent");
        union.add(IntegerDataType.dataType, "integer", null);
        int unionId = scope.reference(union);
        check(node(rows, leftId).get("length").equals(node(rows, unionId).get("length")), "authored equal extent");
        check(node(rows, leftId).get("kind").equals("structure") && node(rows, unionId).get("kind").equals("union"), "structure and union stay distinct");
        int alias = scope.reference(new TypedefDataType("Alias", IntegerDataType.dataType));
        check(details(node(rows, alias)).get("settingsState").equals("unavailable-bounded-count-api"), "typedef settings limitations retained");
        int array = scope.reference(new ArrayDataType(IntegerDataType.dataType, 3, 4));
        check(details(node(rows, array)).get("extentState").equals("consistent"), "native array extent");
        int emptyArray = scope.reference(new ArrayDataType(IntegerDataType.dataType, 0, 4));
        check(details(node(rows, emptyArray)).get("extentState").equals("zero-length"), "empty array is explicit");
        StructureDataType bitfields = new StructureDataType("Bits", 0);
        BitFieldDataType nativeBitfield = (BitFieldDataType) bitfields.addBitField(UnsignedIntegerDataType.dataType, 5, "bits", null).getDataType();
        int bitfield = scope.reference(nativeBitfield);
        check(details(node(rows, bitfield)).get("declaredBitSize").equals(5), "native declared bitfield width");
        check(details(node(rows, bitfield)).get("bitOffset").equals(nativeBitfield.getBitOffset()), "native bit offset");
        EnumDataType enumeration = new EnumDataType("RawEnum", 4);
        enumeration.add("negative", -1); enumeration.add("positive", 2);
        int enumerationId = scope.reference(enumeration);
        check(details(node(rows, enumerationId)).get("enumeratorCount").equals(2), "enum count retained");
        check(details(node(rows, enumerationId)).get("enumeratorsState").equals("not-captured"), "enum contents not claimed");
        List<Map<String, Object>> repeated = new ArrayList<>();
        NativeInterfaceTypeGraphV1 repeatedGraph = new NativeInterfaceTypeGraphV1(ORGANIZATION, budget(DEFAULTS), repeated::add);
        repeatedGraph.scope("listing", 0).reference(left);
        check(rows.subList(0, repeated.size()).equals(repeated), "same authored graph emits identical rows");
        check(budget.nodes() == rows.stream().filter(r -> r.get("recordKind").equals("type-node")).count(), "node count conserved");
        check(budget.edges() == rows.stream().filter(r -> r.get("recordKind").equals("type-edge")).count(), "edge count conserved");
        cases++;
    }

    private static void actualRecursivePointer() throws Exception {
        StructureDataType recursive = new StructureDataType("Recursive", 0);
        recursive.add(new PointerDataType(recursive, 8), "next", null);
        List<Map<String, Object>> rows = collect(recursive, DEFAULTS);
        check(rows.stream().anyMatch(r -> "backedge".equals(r.get("referenceState"))), "real native pointer cycle emits backedge");
        check(rows.size() < 10, "recursive graph terminates without repeated expansion");
        cases++;
    }

    private static void missingAndUnsupportedRemainVisible() throws Exception {
        List<Map<String, Object>> rows = new ArrayList<>();
        NativeInterfaceTypeGraphV1 graph = new NativeInterfaceTypeGraphV1(ORGANIZATION, budget(DEFAULTS), rows::add);
        NativeInterfaceTypeGraphV1.Scope scope = graph.scope("inferred", 0);
        check(scope.reference(null) == null && rows.isEmpty(), "missing root remains missing");
        int pointer = scope.reference(new PointerDataType(null, 8));
        check(rows.stream().anyMatch(r -> "missing".equals(r.get("referenceState"))), "missing pointee stays explicit");
        int unsupported = scope.reference(proxy(DataType.class, Map.of()));
        check(node(rows, unsupported).get("kind").equals("unsupported"), "unsupported native type retained");
        check(node(rows, unsupported).get("expansion").equals("unsupported"), "unsupported closure is not complete");
        check(node(rows, pointer).get("kind").equals("pointer"), "pointer representation distinct");
        cases++;
    }

    private static void missingFunctionCountDoesNotAllocateArguments() throws Exception {
        FunctionDefinition function = proxy(FunctionDefinition.class, Map.of(
            "getCallingConventionName", "unknown", "hasVarArgs", false, "hasNoReturn", false,
            "getReturnType", IntegerDataType.dataType,
            "getArguments", (Forbidden) () -> { throw new AssertionError("unbounded arguments accessor must not run"); }));
        List<Map<String, Object>> rows = collect(function, DEFAULTS);
        check(details(node(rows, 0)).get("argumentsState").equals("unavailable-bounded-count-api"), "unknown function argument population retained");
        check(node(rows, 0).get("expansion").equals("partial"), "partial function type is not complete");
        cases++;
    }

    private static void nodeBoundBeforeMetadata() throws Exception {
        DataType guarded = proxy(DataType.class, Map.of("getLength", (Forbidden) () -> { throw new AssertionError("metadata read after exhausted nodes"); }));
        refuses(() -> collect(guarded, limits(0, 100, 10, 10, 1000, 4096)), "node bound");
        cases++;
    }

    private static void componentBoundBeforeAccess() throws Exception {
        Structure guarded = proxy(Structure.class, Map.of("getNumComponents", 11, "getNumDefinedComponents", 11,
            "getComponent", (Forbidden) () -> { throw new AssertionError("component read after exhausted component bound"); }));
        refuses(() -> collect(guarded, limits(100, 100, 10, 10, 1000, 4096)), "component bound");
        cases++;
    }

    private static void referenceBoundBeforeChildAccess() throws Exception {
        Pointer guarded = proxy(Pointer.class, Map.of("getDataType", (Forbidden) () -> { throw new AssertionError("child read after exhausted references"); }));
        refuses(() -> collect(guarded, limits(100, 0, 10, 10, 1000, 4096)), "reference bound");
        cases++;
    }

    private static void depthBoundBeforeChildTraversal() throws Exception {
        DataType child = proxy(DataType.class, Map.of("getLength", (Forbidden) () -> { throw new AssertionError("child traversed after exhausted depth"); }));
        Pointer guarded = proxy(Pointer.class, Map.of("getDataType", child));
        refuses(() -> collect(guarded, limits(100, 100, 0, 10, 1000, 4096)), "depth bound");
        cases++;
    }

    private static void deepNativeGettersFollowDependencyPreflight() throws Exception {
        DataType nested = IntegerDataType.dataType;
        for (int i = 0; i < 65; i++) nested = new TypedefDataType("Level" + i, nested);
        DataType root = new MetadataGuardTypedef(nested);
        refuses(() -> collect(root, DEFAULTS), "native typedef depth before recursive metadata");
        cases++;
    }

    private static final class MetadataGuardTypedef extends TypedefDataType {
        private MetadataGuardTypedef(DataType target) { super("GuardedMetadataRoot", target); }
        @Override public int getLength() { throw new AssertionError("recursive native metadata called before dependency depth check"); }
    }

    private static void undefinedArrayLookupFollowsReferenceAdmission() throws Exception {
        ghidra.program.model.data.Array guarded = proxy(ghidra.program.model.data.Array.class, Map.of(
            "getNumElements", 1, "getElementLength", 1,
            "getDataType", (Forbidden) () -> { throw new AssertionError("undefined-array predicate read child before reference admission"); }));
        refuses(() -> collect(guarded, limits(100, 0, 10, 10, 1000, 4096)), "undefined-array reference admission");
        cases++;
    }

    private static void recursiveByValueMetadataRejectedBeforeGetters() throws Exception {
        Map<String, Object> values = new HashMap<>();
        TypeDef cyclic = proxy(TypeDef.class, values);
        values.put("getDataType", cyclic);
        values.put("getLength", (Forbidden) () -> { throw new AssertionError("by-value cycle reached recursive native metadata"); });
        refuses(() -> collect(cyclic, DEFAULTS), "by-value metadata cycle");
        cases++;
    }

    private static void reusedRootHeightCannotBypassDepth() throws Exception {
        NativeInterfaceTypeGraphV1 graph = new NativeInterfaceTypeGraphV1(ORGANIZATION, budget(DEFAULTS), row -> {});
        NativeInterfaceTypeGraphV1.Scope scope = graph.scope("listing", 0);
        DataType nested = IntegerDataType.dataType;
        scope.reference(nested);
        for (int i = 0; i < 64; i++) {
            nested = new TypedefDataType("ReuseLevel" + i, nested);
            scope.reference(nested);
        }
        DataType excessive = new MetadataGuardTypedef(nested);
        refuses(() -> scope.reference(excessive), "cached root metadata height");
        cases++;
    }

    private static void exactAggregateWorkAndSharedCounters() throws Exception {
        List<Map<String, Object>> rows = new ArrayList<>();
        NativeInterfaceTypeGraphV1.Budget budget = budget(DEFAULTS);
        NativeInterfaceTypeGraphV1 graph = new NativeInterfaceTypeGraphV1(ORGANIZATION, budget, rows::add);
        graph.scope("listing", 0).reference(IntegerDataType.dataType);
        graph.scope("inferred", 0).reference(IntegerDataType.dataType);
        check(budget.nodes() == 2 && budget.steps() == 8, "scopes share aggregate budget without identity crossjoin");
        check(rows.stream().allMatch(r -> r.get("id").equals(0)), "scope-local IDs reset");
        collect(IntegerDataType.dataType, limits(1, 0, 0, 0, 4, 4096));
        refuses(() -> collect(IntegerDataType.dataType, limits(1, 0, 0, 0, 3, 4096)), "exact work boundary");
        NativeInterfaceTypeGraphV1 limited = new NativeInterfaceTypeGraphV1(ORGANIZATION, budget(limits(1, 0, 0, 0, 100, 4096)), row -> {});
        limited.scope("listing", 0).reference(IntegerDataType.dataType);
        refuses(() -> limited.scope("inferred", 0).reference(IntegerDataType.dataType), "cross-scope node bound");
        cases++;
    }

    private static void utf8BoundIsBytes() throws Exception {
        StructureDataType structure = new StructureDataType("Utf8", 0);
        structure.add(ByteDataType.dataType, "é".repeat(2049), null);
        refuses(() -> collect(structure, DEFAULTS), "UTF-8 byte bound");
        cases++;
    }

    private static void cancellationBeforeMetadata() throws Exception {
        NativeInterfaceTypeGraphV1.Budget budget = new NativeInterfaceTypeGraphV1.Budget(DEFAULTS, () -> { throw new IllegalStateException("authored cancellation"); });
        NativeInterfaceTypeGraphV1 graph = new NativeInterfaceTypeGraphV1(ORGANIZATION, budget, row -> { throw new AssertionError("emission after cancellation"); });
        refuses(() -> graph.scope("listing", 0).reference(IntegerDataType.dataType), "cancellation");
        check(budget.nodes() == 0 && budget.edges() == 0 && budget.steps() == 0, "cancelled work has no observations");
        cases++;
    }

    private static void organizationCountBeforeArrayAllocation() throws Exception {
        DataOrganization guarded = proxy(DataOrganization.class, Map.of("getSizeAlignmentCount", 257,
            "getSizes", (Forbidden) () -> { throw new AssertionError("alignment array allocated before bound"); }));
        NativeInterfaceTypeGraphV1 graph = new NativeInterfaceTypeGraphV1(guarded, budget(DEFAULTS), row -> {});
        refuses(graph::dataOrganization, "alignment bound");
        cases++;
    }

    private static void lowerOnlyBounds() throws Exception {
        try { limits(200001, 100, 1, 1, 100, 4096); throw new AssertionError("node maximum widened"); }
        catch (IllegalArgumentException expected) { }
        try { limits(1, 1, 65, 1, 100, 4096); throw new AssertionError("depth maximum widened"); }
        catch (IllegalArgumentException expected) { }
        cases++;
    }

    private static NativeInterfaceTypeGraphV1.Limits limits(int nodes, int edges, int depth, int children, long steps, int strings) {
        return new NativeInterfaceTypeGraphV1.Limits(nodes, edges, depth, children, steps, strings);
    }
    private static NativeInterfaceTypeGraphV1.Budget budget(NativeInterfaceTypeGraphV1.Limits limits) {
        return new NativeInterfaceTypeGraphV1.Budget(limits, () -> {});
    }
    private static List<Map<String, Object>> collect(DataType type, NativeInterfaceTypeGraphV1.Limits limits) throws Exception {
        List<Map<String, Object>> rows = new ArrayList<>();
        new NativeInterfaceTypeGraphV1(ORGANIZATION, budget(limits), rows::add).scope("listing", 0).reference(type);
        return rows;
    }
    private static Map<String, Object> node(List<Map<String, Object>> rows, int id) {
        return rows.stream().filter(r -> "type-node".equals(r.get("recordKind")) && r.get("id").equals(id)).findFirst().orElseThrow();
    }
    @SuppressWarnings("unchecked") private static Map<String, Object> details(Map<String, Object> row) { return (Map<String, Object>) row.get("details"); }
    @FunctionalInterface private interface Control { void run() throws Exception; }
    @FunctionalInterface private interface Forbidden { Object run(); }
    private static void refuses(Control control, String description) throws Exception {
        try { control.run(); throw new AssertionError("expected refusal: " + description); }
        catch (IllegalStateException expected) { }
    }
    private static void check(boolean value, String description) { if (!value) throw new AssertionError(description); }
    @SuppressWarnings("unchecked") private static <T> T proxy(Class<T> type, Map<String, Object> values) {
        return (T) Proxy.newProxyInstance(type.getClassLoader(), new Class<?>[] { type }, (self, method, args) -> {
            if (values.containsKey(method.getName())) {
                Object value = values.get(method.getName());
                return value instanceof Forbidden forbidden ? forbidden.run() : value;
            }
            return switch (method.getName()) {
                case "getLength", "getAlignedLength", "getAlignment" -> 1;
                case "isZeroLength", "isNotYetDefined" -> false;
                case "equals" -> self == args[0];
                case "hashCode" -> System.identityHashCode(self);
                case "toString" -> "bounded-native-control";
                default -> throw new AssertionError("unexpected native API: " + method.getName());
            };
        });
    }
}
