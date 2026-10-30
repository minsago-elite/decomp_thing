import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.Varnode;
import ghidra.util.task.TaskMonitor;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.MessageDigest;
import java.util.*;

/**
 * Read-only listing-signature observations, never ABI truth or a decompiler-inferred signature.
 * DEFAULT source, zero parameters and false varargs are raw Program values, not established arity.
 * Type ordinals identify root occurrences only; no type identity, layout or closure is inferred.
 */
public final class ExportNativeInterfacesV1 extends GhidraScript {
    private static final long MAXIMUM_BYTES = 1024L * 1024 * 1024;
    private static final long MAXIMUM_MODEL_BYTES = 512L * 1024 * 1024;
    private static final int MAXIMUM_FUNCTIONS = 131072;
    private static final int MAXIMUM_PARAMETERS_PER_FUNCTION = 1024;
    private static final long MAXIMUM_PARAMETERS = 1000000;
    private static final int MAXIMUM_TYPES = 524288;
    private static final int MAXIMUM_VARNODES_PER_STORAGE = 64;
    private static final long MAXIMUM_VARNODES = 1000000;
    private static final int MAXIMUM_RECORD_BYTES = 1024 * 1024;
    private static final int MAXIMUM_STRING_BYTES = 4096;
    private static final String POLICY = "ghidra-native-interface-observations-v1";
    private final Program program;
    private final TaskMonitor task;
    private final List<AddressSpace> spaces = new ArrayList<>();
    private final Map<AddressSpace, Integer> spaceIndices = new HashMap<>();
    private final Totals totals = new Totals();
    private BoundedOutput typeOutput;
    private long functionCount;

    public ExportNativeInterfacesV1() { program = null; task = null; }
    private ExportNativeInterfacesV1(Program program, TaskMonitor task) {
        this.program = Objects.requireNonNull(program);
        this.task = Objects.requireNonNull(task);
    }
    @Override protected void run() throws Exception { collect(currentProgram, monitor, getScriptArgs()); }
    /** Tests invoke this same compiled collector in a fresh bundled JVM. */
    public static void collect(Program program, TaskMonitor monitor, String[] arguments) throws Exception {
        new ExportNativeInterfacesV1(program, monitor).export(arguments);
    }

    private void export(String[] arguments) throws Exception {
        if (arguments.length != 6) throw new IllegalArgumentException("expected input, model exporter, archive, collector digests, model path and output directory");
        String input = digest(arguments[0]);
        String modelExporter = digest(arguments[1]);
        String archive = digest(arguments[2]);
        String collector = digest(arguments[3]);
        if (!input.equals(digest(program.getExecutableSHA256()))) throw new IllegalArgumentException("native-interface input differs from imported Program");
        Path model = Path.of(arguments[4]).toAbsolutePath().normalize();
        Path directory = Path.of(arguments[5]).toAbsolutePath().normalize();
        if (directory.getParent() == null || !directory.getParent().toRealPath().equals(directory.getParent()) ||
                Files.exists(directory, LinkOption.NOFOLLOW_LINKS) || model.startsWith(directory)) {
            throw new IllegalArgumentException("native-interface output must be an absent private directory distinct from model");
        }
        task.checkCancelled();
        long programModification = program.getModificationNumber();
        ModelIdentity before = hashModel(model);
        // This API counts physical spaces only; all returned analysis spaces are checked before copying.
        if (program.getAddressFactory().getNumAddressSpaces() > 256) throw new IllegalStateException("physical address-space bound exceeded");
        AddressSpace[] nativeSpaces = program.getAddressFactory().getAllAddressSpaces();
        if (nativeSpaces.length == 0 || nativeSpaces.length > 256) throw new IllegalStateException("address-space inventory bound exceeded");
        spaces.addAll(Arrays.asList(nativeSpaces));
        spaces.sort(AddressSpace::compareTo);
        List<Object> spaceRecords = new ArrayList<>(spaces.size());
        for (int i = 0; i < spaces.size(); i++) {
            AddressSpace space = spaces.get(i);
            if (spaceIndices.put(space, i) != null) throw new IllegalStateException("duplicate native address space");
            spaceRecords.add(object("index", i, "name", text(space.getName()), "type", space.getType(),
                "sizeBits", space.getSize(), "addressableUnitSize", space.getAddressableUnitSize(),
                "overlay", space.isOverlaySpace(), "signedOffsets", space.hasSignedOffset()));
        }
        FunctionManager manager = program.getFunctionManager();
        int expectedFunctions = manager.getFunctionCount();
        if (expectedFunctions < 0 || expectedFunctions > MAXIMUM_FUNCTIONS) throw new IllegalStateException("function inventory bound exceeded");
        TreeMap<Address, Function> functions = new TreeMap<>(this::compare);
        inventory(manager.getFunctions(true), false, functions);
        inventory(manager.getExternalFunctions(), true, functions);
        if (functions.size() != expectedFunctions || manager.getFunctionCount() != expectedFunctions) throw new IllegalStateException("native function census changed or omitted functions");
        functionCount = functions.size();
        Map<String, Object> bindings = object("collectorSha256", collector,
            "compilerSpecId", text(program.getCompilerSpec().getCompilerSpecID().getIdAsString()),
            "ghidraArchiveSha256", archive, "imageBase", address(program.getImageBase()), "inputSha256", input,
            "languageId", text(program.getLanguageID().getIdAsString()), "programModelBytes", before.bytes,
            "programModelExporterSha256", modelExporter, "programModelSha256", before.sha256);
        Path stage = null;
        Path typeStage = null;
        Path manifestStage = null;
        Path observations = directory.resolve("native-interfaces.json");
        Path manifestPath = directory.resolve("manifest.json");
        boolean complete = false;
        Files.createDirectory(directory, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")));
        try {
            stage = privateTemporary(directory, ".native-interfaces-");
            typeStage = privateTemporary(directory, ".native-interface-types-");
            MessageDigest outputDigest = MessageDigest.getInstance("SHA-256");
            MessageDigest typeDigest = MessageDigest.getInstance("SHA-256");
            long bytes;
            // Type rows are spooled in occurrence order, never retained as an unbounded in-memory table.
            try (BoundedOutput output = new BoundedOutput(new BufferedOutputStream(Files.newOutputStream(stage)), outputDigest, MAXIMUM_BYTES, task);
                 BoundedOutput types = new BoundedOutput(new BufferedOutputStream(Files.newOutputStream(typeStage)), typeDigest, MAXIMUM_BYTES, task)) {
                typeOutput = types;
                output.writeUtf8("{\n  \"addressSpaces\": "); output.value(spaceRecords, 2, false);
                output.writeUtf8(",\n  \"bindings\": "); output.value(bindings, 2, false);
                output.writeUtf8(",\n  \"policy\": \"" + POLICY + "\",\n  \"records\": ");
                long records = 0;
                for (Function function : functions.values()) {
                    task.checkCancelled();
                    output.record(function(function), records++);
                }
                types.flush();
                byte[] expectedTypeDigest = typeDigest.digest();
                MessageDigest copiedTypeDigest = MessageDigest.getInstance("SHA-256");
                try (InputStream source = Files.newInputStream(typeStage, StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS)) {
                    byte[] buffer = new byte[65536];
                    long copied = 0;
                    int count;
                    while ((count = source.read(buffer)) != -1) {
                        task.checkCancelled();
                        copied = Math.addExact(copied, count);
                        if (copied > types.bytes) throw new IllegalStateException("type spool changed during capture");
                        copiedTypeDigest.update(buffer, 0, count);
                        output.write(buffer, 0, count);
                    }
                    if (copied != types.bytes) throw new IllegalStateException("type spool is incomplete");
                }
                if (!MessageDigest.isEqual(expectedTypeDigest, copiedTypeDigest.digest())) throw new IllegalStateException("type spool bytes changed during capture");
                output.writeUtf8(records == 0 ? "[]" : "\n  ]");
                output.writeUtf8(",\n  \"schemaVersion\": 1,\n  \"summary\": "); output.value(totals.json(), 2, false);
                output.writeUtf8("\n}\n");
                bytes = output.bytes;
            } finally { typeOutput = null; }
            Files.delete(typeStage); typeStage = null;
            if (manager.getFunctionCount() != expectedFunctions || totals.functions != expectedFunctions) throw new IllegalStateException("native function census changed during capture");
            String sha256 = HexFormat.of().formatHex(outputDigest.digest());
            requireModelUnchanged(before, hashModel(model)); task.checkCancelled();
            requireProgramUnchanged(programModification);
            byte[] manifest = canonical(object("bytes", bytes, "collectorSha256", collector, "file", "native-interfaces.json",
                "inputSha256", input, "kind", "ghidra-native-interface-observation-manifest-v1",
                "programModelSha256", before.sha256, "schemaVersion", 1, "sha256", sha256), 65536);
            if (Math.addExact(bytes, manifest.length) > MAXIMUM_BYTES) throw new IllegalStateException("combined native-interface inventory bound exceeded");
            Files.setPosixFilePermissions(stage, PosixFilePermissions.fromString("r--------"));
            Files.createLink(observations, stage); Files.delete(stage); stage = null;
            manifestStage = privateTemporary(directory, ".native-interface-manifest-");
            Files.write(manifestStage, manifest, StandardOpenOption.TRUNCATE_EXISTING);
            Files.setPosixFilePermissions(manifestStage, PosixFilePermissions.fromString("r--------"));
            requireModelUnchanged(before, hashModel(model)); task.checkCancelled();
            requireProgramUnchanged(programModification);
            Files.createLink(manifestPath, manifestStage); Files.delete(manifestStage); manifestStage = null;
            complete = true;
        } finally {
            if (stage != null) Files.deleteIfExists(stage);
            if (typeStage != null) Files.deleteIfExists(typeStage);
            if (manifestStage != null) Files.deleteIfExists(manifestStage);
            if (!complete) { Files.deleteIfExists(manifestPath); Files.deleteIfExists(observations); Files.deleteIfExists(directory); }
        }
    }

    private void inventory(FunctionIterator iterator, boolean external, Map<Address, Function> functions) throws Exception {
        while (iterator.hasNext()) {
            task.checkCancelled();
            if (functions.size() >= MAXIMUM_FUNCTIONS) throw new IllegalStateException("function inventory bound exceeded");
            Function function = Objects.requireNonNull(iterator.next(), "null native function");
            if (function.isExternal() != external) throw new IllegalStateException("native function iterator changed its coverage");
            if (functions.put(function.getEntryPoint(), function) != null) throw new IllegalStateException("duplicate native function entry");
        }
    }

    private Map<String, Object> function(Function function) throws Exception {
        int count = function.getParameterCount();
        int auto = function.getAutoParameterCount();
        if (count < 0 || count > MAXIMUM_PARAMETERS_PER_FUNCTION || auto < 0 || auto > count ||
                totals.parameters > MAXIMUM_PARAMETERS - count) throw new IllegalStateException("native parameter population bound exceeded");
        totals.parameters += count;
        Parameter[] nativeParameters = Objects.requireNonNull(function.getParameters(), "native parameters unavailable");
        if (nativeParameters.length != count) throw new IllegalStateException("native parameter count changed");
        Function thunk = function.isThunk() ? function.getThunkedFunction(false) : null;
        if (function.isThunk() && thunk == null) throw new IllegalStateException("immediate thunk target unavailable");
        String convention = nullableText(function.getCallingConventionName());
        var model = function.getCallingConvention();
        String resolved = model == null ? null : nullableText(model.getName());
        String conventionState = convention == null || convention.equals(Function.UNKNOWN_CALLING_CONVENTION_STRING) ? "unknown" :
            convention.equals(Function.DEFAULT_CALLING_CONVENTION_STRING) ? "default" : resolved == null ? "named-unresolved" : "named-resolved";
        // This order is the wire identity: return formal/effective, then parameter formal/effective.
        Parameter returned = function.getReturn();
        Map<String, Object> returnRecord = returned == null ? null : parameter(returned, Parameter.RETURN_ORIDINAL);
        List<Object> parameters = new ArrayList<>(count);
        int observedAuto = 0;
        for (int index = 0; index < nativeParameters.length; index++) {
            task.checkCancelled();
            Parameter parameter = Objects.requireNonNull(nativeParameters[index], "null native parameter");
            if (parameter.isAutoParameter()) observedAuto++;
            parameters.add(parameter(parameter, index));
        }
        // Ghidra 12.1.3's thunk getAutoParameterCount delegates to the target's TOTAL parameter
        // count. Preserve that raw getter alongside the actual flags; never drop or normalize thunks.
        if (function.getParameterCount() != count || function.getAutoParameterCount() != auto) {
            throw new IllegalStateException("native parameter inventory changed for " + text(function.getName()) +
                ": count=" + count + ", currentCount=" + function.getParameterCount() + ", auto=" + auto +
                ", currentAuto=" + function.getAutoParameterCount() + ", observedAuto=" + observedAuto);
        }
        totals.functions++;
        if (function.isExternal()) totals.externalFunctions++; else totals.internalFunctions++;
        if (function.isThunk()) totals.thunks++;
        totals.autoParameters += observedAuto;
        return object("recordKind", "function", "entry", address(function.getEntryPoint()), "name", text(function.getName()),
            "isExternal", function.isExternal(), "isThunk", function.isThunk(), "immediateThunkTarget", thunk == null ? null : address(thunk.getEntryPoint()),
            "signatureSource", function.getSignatureSource().name(),
            "convention", object("name", convention, "resolvedModel", resolved, "state", conventionState),
            "varArgs", function.hasVarArgs(), "customStorage", function.hasCustomVariableStorage(),
            "parameterCount", count, "autoParameterCount", auto, "return", returnRecord,
            "parameters", parameters, "highFunction", "not-captured");
    }

    private Map<String, Object> parameter(Parameter parameter, int ordinal) throws Exception {
        task.checkCancelled();
        if (parameter.getOrdinal() != ordinal) throw new IllegalStateException("native parameter order differs from its ordinal");
        Integer formal = type(parameter.getFormalDataType());
        Integer effective = type(parameter.getDataType());
        var auto = parameter.getAutoParameterType();
        var source = parameter.getSource();
        return object("ordinal", ordinal, "name", nullableText(parameter.getName()), "source", source == null ? null : source.name(),
            "autoParameter", parameter.isAutoParameter(), "autoParameterType", auto == null ? null : auto.name(),
            "forcedIndirect", parameter.isForcedIndirect(), "formalType", formal, "effectiveType", effective,
            "storage", storage(parameter.getVariableStorage()));
    }

    private Integer type(DataType type) throws Exception {
        if (type == null) return null;
        task.checkCancelled();
        if (totals.types >= MAXIMUM_TYPES) throw new IllegalStateException("native datatype occurrence bound exceeded");
        int ordinal = totals.types++;
        String kind = type instanceof VoidDataType ? "void" : type instanceof Undefined || type instanceof DefaultDataType ? "undefined" :
            type instanceof AbstractIntegerDataType ? "integer" : type instanceof AbstractFloatDataType ? "float" :
            type instanceof Pointer ? "pointer" : type instanceof Array ? "array" : type instanceof Structure ? "structure" :
            type instanceof Union ? "union" : type instanceof ghidra.program.model.data.Enum ? "enum" :
            type instanceof TypeDef ? "typedef" : type instanceof FunctionDefinition ? "function-definition" : "other";
        String signedness = type instanceof AbstractIntegerDataType integer ? integer.isSigned() ? "signed" : "unsigned" : null;
        Map<String, Object> record = object("recordKind", "type", "ordinal", ordinal, "kind", kind,
            "nativeClass", text(type.getClass().getName()), "name", text(type.getName()), "path", text(type.getPathName()),
            "length", type.getLength(), "alignedLength", type.getAlignedLength(), "alignment", type.getAlignment(),
            "undefined", Undefined.isUndefined(type), "notYetDefined", type.isNotYetDefined(), "signedness", signedness,
            "layout", "not-captured", "typeClosure", "not-captured");
        typeOutput.record(record, functionCount + ordinal);
        return ordinal;
    }

    private Map<String, Object> storage(VariableStorage storage) throws Exception {
        if (storage == null) return object("state", "absent", "size", null, "autoStorage", null, "autoParameterType", null,
            "forcedIndirect", null, "varnodes", List.of());
        int count = storage.getVarnodeCount();
        if (count < 0 || count > MAXIMUM_VARNODES_PER_STORAGE || totals.storageVarnodes > MAXIMUM_VARNODES - count) throw new IllegalStateException("native storage population bound exceeded");
        totals.storageVarnodes += count;
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
    private ModelIdentity hashModel(Path model) throws Exception {
        if (!model.toRealPath().equals(model)) throw new IllegalArgumentException("model path contains symbolic links");
        BasicFileAttributes before = Files.readAttributes(model, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
        if (!before.isRegularFile() || before.fileKey() == null || before.size() < 1 || before.size() > MAXIMUM_MODEL_BYTES) throw new IllegalArgumentException("model must be a bounded identified regular file");
        MessageDigest digest = MessageDigest.getInstance("SHA-256"); long bytes = 0;
        try (InputStream stream = Files.newInputStream(model, StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS)) {
            byte[] buffer = new byte[65536]; int count;
            while ((count = stream.read(buffer)) != -1) {
                task.checkCancelled(); bytes = Math.addExact(bytes, count);
                if (bytes > MAXIMUM_MODEL_BYTES) throw new IllegalStateException("model byte bound exceeded");
                digest.update(buffer, 0, count);
            }
        }
        BasicFileAttributes after = Files.readAttributes(model, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
        if (bytes != before.size() || !sameIdentity(before, after)) throw new IllegalStateException("model changed during native export");
        return new ModelIdentity(bytes, HexFormat.of().formatHex(digest.digest()), after);
    }
    private static boolean sameIdentity(BasicFileAttributes a, BasicFileAttributes b) {
        return b.fileKey() != null && a.fileKey().equals(b.fileKey()) && a.size() == b.size() && a.lastModifiedTime().equals(b.lastModifiedTime()) && b.isRegularFile();
    }
    private static void requireModelUnchanged(ModelIdentity a, ModelIdentity b) {
        if (a.bytes != b.bytes || !a.sha256.equals(b.sha256) || !sameIdentity(a.attributes, b.attributes)) throw new IllegalStateException("paired model changed during collection");
    }
    private record ModelIdentity(long bytes, String sha256, BasicFileAttributes attributes) {}
    private void requireProgramUnchanged(long modification) {
        if (program.getModificationNumber() != modification) throw new IllegalStateException("native Program changed during interface collection");
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
    private static Map<String, Object> object(Object... pairs) {
        TreeMap<String, Object> value = new TreeMap<>();
        for (int i = 0; i < pairs.length; i += 2) {
            String key = (String) pairs[i];
            if (value.containsKey(key)) throw new IllegalStateException("duplicate schema field");
            value.put(key, pairs[i + 1]);
        }
        return value;
    }
    private static final class Totals {
        long functions, internalFunctions, externalFunctions, thunks, parameters, autoParameters, storageVarnodes;
        int types;
        Map<String, Object> json() {
            return object("coverage", "all-currently-listed-internal-and-external-functions", "functions", functions,
                "internalFunctions", internalFunctions, "externalFunctions", externalFunctions, "thunks", thunks,
                "parameters", parameters, "autoParameters", autoParameters, "types", types, "storageVarnodes", storageVarnodes,
                "highFunction", "not-captured", "typeClosure", "not-captured", "abiClassification", "not-captured");
        }
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
