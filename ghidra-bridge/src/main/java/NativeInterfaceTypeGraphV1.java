import ghidra.program.model.data.*;
import java.util.*;

/**
 * Bounded immediate native datatype relationships. IDs identify Java objects within one
 * function/channel scope, never source types or semantic equivalence. This class neither reads
 * bytes from the target nor resolves, clones, commits or mutates datatypes.
 *
 * Rows are emitted in depth-first order. A new-node edge is immediately followed by its node;
 * backedges refer to active ancestors and reused-node edges to completed nodes in the same scope.
 * A failed traversal invalidates the enclosing capture; the sink must not publish partial output.
 */
public final class NativeInterfaceTypeGraphV1 {
    @FunctionalInterface public interface Checkpoint { void check() throws Exception; }
    @FunctionalInterface public interface RecordSink { void accept(Map<String, Object> record) throws Exception; }

    public static final class Limits {
        public final int maximumNodes, maximumEdges, maximumDepth, maximumChildren, maximumStringBytes;
        public final long maximumSteps;
        public Limits(int nodes, int edges, int depth, int children, long steps, int strings) {
            maximumNodes = bounded(nodes, 200000, "nodes");
            maximumEdges = bounded(edges, 1000000, "edges");
            maximumDepth = bounded(depth, 64, "depth");
            maximumChildren = bounded(children, 4096, "children");
            maximumStringBytes = bounded(strings, 4096, "string bytes");
            if (steps < 0 || steps > 5000000) throw new IllegalArgumentException("invalid graph work bound");
            maximumSteps = steps;
        }
        public static Limits defaults() { return new Limits(200000, 1000000, 64, 4096, 5000000, 4096); }
        private static int bounded(int value, int cap, String label) {
            if (value < 0 || value > cap) throw new IllegalArgumentException("invalid graph " + label + " bound");
            return value;
        }
    }

    /** One instance must be shared by all scopes in an enclosing capture. */
    public static final class Budget {
        private final Limits limits;
        private final Checkpoint checkpoint;
        private long nodes, edges, steps;
        public Budget(Limits limits, Checkpoint checkpoint) {
            this.limits = Objects.requireNonNull(limits);
            this.checkpoint = Objects.requireNonNull(checkpoint);
        }
        public long nodes() { return nodes; }
        public long edges() { return edges; }
        public long steps() { return steps; }
        private void step() throws Exception {
            checkpoint.check();
            if (steps >= limits.maximumSteps) throw new IllegalStateException("native type graph work bound exceeded");
            steps++;
        }
        private void node() throws Exception {
            step();
            if (nodes >= limits.maximumNodes) throw new IllegalStateException("native type graph node bound exceeded");
            nodes++;
        }
        private void edge() throws Exception {
            step();
            if (edges >= limits.maximumEdges) throw new IllegalStateException("native type graph reference bound exceeded");
            edges++;
        }
    }

    private final DataOrganization organization;
    private final Budget budget;
    private final RecordSink sink;
    public NativeInterfaceTypeGraphV1(DataOrganization organization, Budget budget, RecordSink sink) {
        this.organization = Objects.requireNonNull(organization);
        this.budget = Objects.requireNonNull(budget);
        this.sink = Objects.requireNonNull(sink);
    }

    public Scope scope(String channel, long functionOrdinal) {
        if ((!"listing".equals(channel) && !"inferred".equals(channel)) || functionOrdinal < 0 || functionOrdinal >= 131072) {
            throw new IllegalArgumentException("invalid native type graph scope");
        }
        return new Scope(channel, functionOrdinal);
    }

    /** Exact native context; it is not an independent ABI descriptor or an authority grant. */
    public Map<String, Object> dataOrganization() throws Exception {
        budget.step();
        int count = organization.getSizeAlignmentCount();
        if (count < 0 || count > 256 || count > budget.limits.maximumChildren) {
            throw new IllegalStateException("native data-organization alignment bound exceeded");
        }
        // The public count is checked before requesting the array allocation.
        int[] sizes = Objects.requireNonNull(organization.getSizes(), "alignment sizes unavailable");
        if (sizes.length != count || organization.getSizeAlignmentCount() != count) {
            throw new IllegalStateException("native data-organization alignment census changed");
        }
        List<Object> alignments = new ArrayList<>(count);
        int previous = -1;
        for (int size : sizes) {
            budget.step();
            if (size <= previous) throw new IllegalStateException("native data-organization sizes are not strictly ordered");
            previous = size;
            alignments.add(object("size", size, "alignment", organization.getSizeAlignment(size)));
        }
        BitFieldPacking packing = Objects.requireNonNull(organization.getBitFieldPacking(), "bitfield packing unavailable");
        return object("bigEndian", organization.isBigEndian(), "pointerSize", organization.getPointerSize(),
            "pointerShift", organization.getPointerShift(), "signedChar", organization.isSignedChar(),
            "charSize", organization.getCharSize(), "wideCharSize", organization.getWideCharSize(),
            "shortSize", organization.getShortSize(), "integerSize", organization.getIntegerSize(),
            "longSize", organization.getLongSize(), "longLongSize", organization.getLongLongSize(),
            "floatSize", organization.getFloatSize(), "doubleSize", organization.getDoubleSize(),
            "longDoubleSize", organization.getLongDoubleSize(), "absoluteMaxAlignment", organization.getAbsoluteMaxAlignment(),
            "machineAlignment", organization.getMachineAlignment(), "defaultAlignment", organization.getDefaultAlignment(),
            "defaultPointerAlignment", organization.getDefaultPointerAlignment(), "sizeAlignments", List.copyOf(alignments),
            "bitFieldPacking", object("msConvention", packing.useMSConvention(),
                "typeAlignmentEnabled", packing.isTypeAlignmentEnabled(), "zeroLengthBoundary", packing.getZeroLengthBoundary()));
    }

    public final class Scope {
        private final String channel;
        private final long functionOrdinal;
        private final IdentityHashMap<DataType, NodePlan> plans = new IdentityHashMap<>();
        private final List<NodePlan> orderedPlans = new ArrayList<>();
        private final Set<DataType> active = Collections.newSetFromMap(new IdentityHashMap<>());
        private boolean failed;
        private Scope(String channel, long functionOrdinal) { this.channel = channel; this.functionOrdinal = functionOrdinal; }
        public long nodeCount() { return plans.size(); }
        /** The caller emits its separate root locator; null explicitly means missing native type. */
        public Integer reference(DataType type) throws Exception {
            if (failed) throw new IllegalStateException("native type graph scope already failed");
            try {
                budget.step();
                if (type == null) return null;
                NodePlan known = plans.get(type);
                if (known != null) return known.id;
                // Native typedef/array metadata getters can recurse through child types. Validate
                // the whole new dependency closure before calling them, not after emitting a root.
                // Retain bounded object references, never complete row payloads or display strings.
                int firstNew = orderedPlans.size();
                NodePlan plan = prepare(type, 0);
                // Cached prior roots must contribute their full metadata dependency height.
                // Otherwise a sequence of shallow new roots can build an arbitrarily deep
                // typedef/array chain while every individual expansion stays below the bound.
                for (int i = firstNew; i < orderedPlans.size(); i++) metadataHeight(orderedPlans.get(i), 0);
                emitPlan(plan);
                return plan.id;
            } catch (Exception | Error error) {
                failed = true;
                throw error;
            }
        }

        private NodePlan prepare(DataType type, int depth) throws Exception {
            if (depth > budget.limits.maximumDepth) throw new IllegalStateException("native type graph depth bound exceeded");
            budget.node(); // Charge before native metadata access or object table allocation.
            int count = childCount(type);
            if (count < 0 || count > budget.limits.maximumChildren) throw new IllegalStateException("native type child bound exceeded");
            NodePlan plan = new NodePlan(type, plans.size(), count);
            if (plans.put(type, plan) != null || !active.add(type)) throw new IllegalStateException("duplicate graph visit");
            orderedPlans.add(plan);
            for (int ordinal = 0; ordinal < count; ordinal++) {
                budget.edge(); // Charge before retrieving a child/component or traversing it.
                DataType child;
                String relation;
                DataTypeComponent component = null;
                if (type instanceof Pointer pointer) {
                    relation = "pointer-target"; child = pointer.getDataType();
                } else if (type instanceof ghidra.program.model.data.Array array) {
                    relation = "array-element"; child = array.getDataType();
                } else if (type instanceof TypeDef typedef) {
                    relation = "typedef-target"; child = typedef.getDataType();
                } else if (type instanceof Composite composite && (type instanceof Structure || type instanceof Union)) {
                    relation = "component";
                    component = Objects.requireNonNull(composite.getComponent(ordinal), "missing native component");
                    if (component.getOrdinal() != ordinal) throw new IllegalStateException("native component ordinal changed");
                    child = component.getDataType();
                } else if (type instanceof BitFieldDataType bitfield) {
                    relation = "bitfield-base"; child = bitfield.getBaseDataType();
                } else if (type instanceof FunctionDefinition function) {
                    relation = "function-return"; child = function.getReturnType();
                } else throw new IllegalStateException("native graph kind has undeclared children");
                NodePlan known = child == null ? null : plans.get(child);
                String state = child == null ? "missing" : known == null ? "new-node" :
                    active.contains(child) ? "backedge" : "reused-node";
                NodePlan target = child == null ? null : known != null ? known : prepare(child, depth + 1);
                plan.edges.add(new EdgePlan(ordinal, relation, target, state, component));
            }
            if (type instanceof Composite composite && (type instanceof Structure || type instanceof Union) && composite.getNumComponents() != count) {
                throw new IllegalStateException("native composite population changed");
            }
            active.remove(type);
            return plan;
        }

        private int metadataHeight(NodePlan plan, int depth) throws Exception {
            if (plan.metadataHeight >= 0) return plan.metadataHeight;
            if (plan.metadataActive) throw new IllegalStateException("native datatype has recursive by-value metadata dependencies");
            if (depth > budget.limits.maximumDepth) throw new IllegalStateException("native metadata dependency depth bound exceeded");
            budget.step();
            plan.metadataActive = true;
            int height = 0;
            boolean terminal = plan.type instanceof Pointer || plan.type instanceof FunctionDefinition;
            for (EdgePlan edge : plan.edges) {
                budget.step(); // Each prepared edge is charged once even at a metadata terminal.
                if (!terminal && edge.target != null) {
                    int childHeight = metadataHeight(edge.target, depth + 1);
                    if (childHeight >= budget.limits.maximumDepth) throw new IllegalStateException("native metadata dependency depth bound exceeded");
                    height = Math.max(height, childHeight + 1);
                }
            }
            plan.metadataActive = false;
            plan.metadataHeight = height;
            return height;
        }

        private int childCount(DataType type) {
            if (type instanceof Composite composite && (type instanceof Structure || type instanceof Union)) return composite.getNumComponents();
            if (type instanceof Pointer || type instanceof ghidra.program.model.data.Array || type instanceof TypeDef ||
                    type instanceof BitFieldDataType || type instanceof FunctionDefinition) return 1;
            return 0;
        }

        private void emitPlan(NodePlan plan) throws Exception {
            DataType type = plan.type;
            String kind = kind(type);
            int length = type.getLength();
            String expansion = "terminal";
            Map<String, Object> details = object();
            if (type instanceof Pointer) {
                details = object("pointerSize", length); expansion = "expanded";
            } else if (type instanceof ghidra.program.model.data.Array array) {
                int count = array.getNumElements();
                int element = array.getElementLength();
                String extent = count < 0 || element < 0 ? "unknown" : count == 0 ? "zero-length" :
                    (long) count * element == length ? "consistent" : "inconsistent";
                details = object("elementCount", count, "elementLength", element, "extentState", extent);
                expansion = "expanded";
            } else if (type instanceof TypeDef typedef) {
                details = object("autoNamed", typedef.isAutoNamed(), "settingsState", "unavailable-bounded-count-api");
                expansion = "partial";
            } else if (type instanceof Composite composite && (type instanceof Structure || type instanceof Union)) {
                int defined = composite.getNumDefinedComponents();
                if (composite.getNumComponents() != plan.edges.size() || defined < 0 || defined > plan.edges.size()) {
                    throw new IllegalStateException("native composite component bound exceeded or changed");
                }
                details = object("componentCount", plan.edges.size(), "definedComponentCount", defined,
                    "packingType", text(composite.getPackingType().name()), "explicitPackingValue", composite.getExplicitPackingValue(),
                    "alignmentType", text(composite.getAlignmentType().name()),
                    "explicitMinimumAlignment", composite.getExplicitMinimumAlignment());
                expansion = "expanded";
            } else if (type instanceof BitFieldDataType bitfield) {
                details = object("storageSize", bitfield.getStorageSize(), "declaredBitSize", bitfield.getDeclaredBitSize(),
                    "effectiveBitSize", bitfield.getBitSize(), "bitOffset", bitfield.getBitOffset(),
                    "baseTypeSize", bitfield.getBaseTypeSize(), "bigEndian", organization.isBigEndian());
                expansion = "expanded";
            } else if (type instanceof ghidra.program.model.data.Enum enumeration) {
                int count = enumeration.getCount();
                if (count < 0) throw new IllegalStateException("negative native enum population");
                details = object("enumeratorCount", count, "signedState", text(enumeration.getSignedState().name()),
                    "enumeratorsState", "not-captured");
            } else if (type instanceof FunctionDefinition function) {
                // getArguments() has no public count-before-allocation API. Do not invoke it and
                // claim the missing formal population is empty or a complete referenced closure.
                details = object("convention", nullableText(function.getCallingConventionName()),
                    "varArgs", function.hasVarArgs(), "noReturn", function.hasNoReturn(),
                    "argumentsState", "unavailable-bounded-count-api");
                expansion = "partial";
            } else if (type instanceof AbstractIntegerDataType integer) {
                details = object("signed", integer.isSigned());
            } else if (kind.equals("unsupported")) {
                expansion = "unsupported";
            }
            // Exactly Undefined.isUndefined's pinned predicate, using the already charged array
            // edge instead of invoking its uncharged immediate-child getter a second time.
            boolean undefined = type instanceof Undefined || type instanceof DefaultDataType;
            if (type instanceof ghidra.program.model.data.Array && !plan.edges.isEmpty()) {
                NodePlan child = plan.edges.get(0).target;
                undefined = child != null && (child.type instanceof Undefined || child.type instanceof DefaultDataType);
            }
            emit(object("recordKind", "type-node", "channel", channel, "functionOrdinal", functionOrdinal,
                "id", plan.id, "nativeClass", text(type.getClass().getName()), "kind", kind,
                "length", length, "alignedLength", type.getAlignedLength(), "alignment", type.getAlignment(),
                "zeroLength", type.isZeroLength(), "notYetDefined", type.isNotYetDefined(), "undefined", undefined,
                "expansion", expansion, "childCount", plan.edges.size(), "details", details));
            for (EdgePlan edge : plan.edges) {
                Integer offset = null, componentLength = null;
                String field = null;
                Boolean componentUndefined = null, bitField = null, zeroBitField = null;
                if (edge.component != null) {
                    if (edge.component.getOrdinal() != edge.ordinal) throw new IllegalStateException("native component ordinal changed");
                    offset = edge.component.getOffset(); componentLength = edge.component.getLength();
                    field = nullableText(edge.component.getFieldName()); componentUndefined = edge.component.isUndefined();
                    bitField = edge.component.isBitFieldComponent(); zeroBitField = edge.component.isZeroBitFieldComponent();
                }
                emit(object("recordKind", "type-edge", "channel", channel, "functionOrdinal", functionOrdinal,
                    "source", plan.id, "ordinal", edge.ordinal, "relation", edge.relation,
                    "target", edge.target == null ? null : edge.target.id, "referenceState", edge.state,
                    "offset", offset, "length", componentLength, "fieldName", field, "undefined", componentUndefined,
                    "bitField", bitField, "zeroBitField", zeroBitField));
                if (edge.state.equals("new-node")) emitPlan(edge.target);
            }
            if (type instanceof Composite composite && (type instanceof Structure || type instanceof Union) && (composite.getNumComponents() != plan.edges.size() ||
                    composite.getNumDefinedComponents() != (Integer) details.get("definedComponentCount"))) {
                throw new IllegalStateException("native composite population changed");
            }
        }
    }

    private static final class NodePlan {
        private final DataType type;
        private final int id;
        private final List<EdgePlan> edges;
        private int metadataHeight = -1;
        private boolean metadataActive;
        private NodePlan(DataType type, int id, int children) {
            this.type = type; this.id = id;
            // No backing reference array is allocated until an edge has been charged. The
            // per-node child count and shared aggregate reference quota both constrain growth.
            edges = new ArrayList<>();
        }
    }
    private static final class EdgePlan {
        private final int ordinal;
        private final String relation, state;
        private final NodePlan target;
        private final DataTypeComponent component;
        private EdgePlan(int ordinal, String relation, NodePlan target, String state, DataTypeComponent component) {
            this.ordinal = ordinal; this.relation = relation; this.target = target; this.state = state; this.component = component;
        }
    }

    private void emit(Map<String, Object> record) throws Exception { budget.step(); sink.accept(record); }
    private String nullableText(String value) { return value == null ? null : text(value); }
    private String text(String value) {
        Objects.requireNonNull(value, "native metadata unavailable");
        int bytes = 0;
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (c < 0x80) bytes++;
            else if (c < 0x800) bytes += 2;
            else if (Character.isHighSurrogate(c)) {
                if (++i >= value.length() || !Character.isLowSurrogate(value.charAt(i))) throw new IllegalStateException("invalid native metadata UTF-16");
                bytes += 4;
            } else if (Character.isLowSurrogate(c)) throw new IllegalStateException("invalid native metadata UTF-16");
            else bytes += 3;
            if (bytes > budget.limits.maximumStringBytes) throw new IllegalStateException("native graph metadata string bound exceeded");
        }
        return value;
    }
    private static String kind(DataType type) {
        if (type instanceof Pointer) return "pointer";
        if (type instanceof ghidra.program.model.data.Array) return "array";
        if (type instanceof TypeDef) return "typedef";
        if (type instanceof Structure) return "structure";
        if (type instanceof Union) return "union";
        if (type instanceof BitFieldDataType) return "bitfield";
        if (type instanceof ghidra.program.model.data.Enum) return "enum";
        if (type instanceof FunctionDefinition) return "function-definition";
        if (type instanceof VoidDataType) return "void";
        if (type instanceof Undefined || type instanceof DefaultDataType) return "undefined";
        if (type instanceof AbstractIntegerDataType) return "integer";
        if (type instanceof AbstractFloatDataType) return "float";
        return "unsupported";
    }
    private static Map<String, Object> object(Object... pairs) {
        Map<String, Object> result = new TreeMap<>();
        for (int i = 0; i < pairs.length; i += 2) result.put((String) pairs[i], pairs[i + 1]);
        return Collections.unmodifiableMap(result);
    }
}
