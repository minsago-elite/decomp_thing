import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.address.AddressSpace;
import ghidra.util.task.TaskMonitor;
import java.io.BufferedWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.TreeMap;

/**
 * Typed data observations from the imported Program. Keys are source locators only: this
 * collector has no oracle population, identity, or observability authority.
 */
public final class ExportGlobalTypeObservationsV1 {
    private static final int MAXIMUM_DATA = 131_072;
    private static final int MAXIMUM_FUNCTIONS = 131_072;
    private static final long MAXIMUM_REFERENCES = 1_000_000;
    private static final long MAXIMUM_WORK = 5_000_000;
    private static final int MAXIMUM_SPACES = 256;
    private static final long MAXIMUM_BYTES = 64L * 1024 * 1024;
    private static final long MAXIMUM_MODEL_BYTES = 512L * 1024 * 1024;
    private static final String POLICY = "ghidra-global-type-observations-v1";
    private final long maximumBytes;

    private ExportGlobalTypeObservationsV1(long maximumBytes) {
        if (maximumBytes <= 0 || maximumBytes > MAXIMUM_BYTES) throw new IllegalArgumentException("invalid global/type staging allowance");
        this.maximumBytes = maximumBytes;
    }

    public static void collect(Program program, TaskMonitor monitor, String[] arguments) throws Exception {
        new ExportGlobalTypeObservationsV1(MAXIMUM_BYTES).export(program, monitor, arguments);
    }

    /** The enclosing v10 operation reserves report-tree, stream and temporary bytes first. */
    public static void collectWithByteLimit(Program program, TaskMonitor monitor, String[] arguments,
            long maximumStagingBytes) throws Exception {
        new ExportGlobalTypeObservationsV1(Math.min(MAXIMUM_BYTES, maximumStagingBytes)).export(program, monitor, arguments);
    }

    private void export(Program program, TaskMonitor monitor, String[] arguments) throws Exception {
        if (arguments.length != 5) throw new IllegalArgumentException("expected model path, output path and three binding digests");
        Path model = canonical(arguments[0]);
        Path output = canonical(arguments[1]);
        String input = digest(arguments[2]);
        String exporter = digest(arguments[3]);
        String archive = digest(arguments[4]);
        if (!input.equals(digest(program.getExecutableSHA256()))) throw new IllegalArgumentException("global/type input differs from imported Program");
        if (output.getParent() == null || !output.getParent().toRealPath().equals(output.getParent()) ||
                Files.exists(output, LinkOption.NOFOLLOW_LINKS) || model.startsWith(output)) {
            throw new IllegalArgumentException("global/type output must be an absent private file distinct from model");
        }
        ModelIdentity modelBefore = hashModel(model, monitor);
        long modificationBefore = program.getModificationNumber();
        Listing listing = program.getListing();
        AddressSpace[] nativeSpaces = program.getAddressFactory().getAllAddressSpaces();
        if (nativeSpaces.length == 0 || nativeSpaces.length > MAXIMUM_SPACES) throw new IllegalStateException("global/type address-space inventory exceeds its bound");
        List<AddressSpace> spaces = new ArrayList<>(List.of(nativeSpaces));
        spaces.sort(AddressSpace::compareTo);
        java.util.IdentityHashMap<AddressSpace, Integer> spaceIndices = new java.util.IdentityHashMap<>();
        List<Object> spaceRecords = new ArrayList<>(spaces.size());
        for (int i = 0; i < spaces.size(); i++) {
            AddressSpace space = spaces.get(i);
            if (spaceIndices.put(space, i) != null) throw new IllegalStateException("duplicate global/type address space");
            spaceRecords.add(object("index", i, "name", text(space.getName()), "type", space.getType(),
                "sizeBits", space.getSize(), "addressableUnitSize", space.getAddressableUnitSize(),
                "overlay", space.isOverlaySpace(), "signedOffsets", space.hasSignedOffset()));
        }
        long expected = listing.getNumDefinedData();
        if (expected < 0 || expected > MAXIMUM_DATA) throw new IllegalStateException("defined data census exceeds its bound");
        int expectedFunctions = program.getFunctionManager().getFunctionCount();
        if (expectedFunctions < 0 || expectedFunctions > MAXIMUM_FUNCTIONS) throw new IllegalStateException("function inventory exceeds its bound");
        Path staging = Files.createTempFile(output.getParent(), ".global-type-v1-", ".partial");
        boolean complete = false;
        long bytes = 0;
        try {
            try (var raw = Files.newOutputStream(staging, java.nio.file.StandardOpenOption.WRITE);
                 var bounded = new BoundedDigestOutput(raw, maximumBytes);
                 var writer = new BufferedWriter(new java.io.OutputStreamWriter(bounded, StandardCharsets.UTF_8))) {
                Map<String, Object> bindings = object("archiveSha256", archive, "exporterSha256", exporter, "inputSha256", input,
                    "programModelBytes", modelBefore.bytes, "programModelSha256", modelBefore.sha256,
                    "compilerSpecId", text(program.getCompilerSpec().getCompilerSpecID().getIdAsString()),
                    "languageId", text(program.getLanguageID().getIdAsString()),
                    "imageBase", captureKey(program.getImageBase(), spaceIndices));
                writer.write(json(object("addressSpaces", spaceRecords, "bindings", bindings,
                    "definedDataCount", expected, "functionCount", expectedFunctions,
                    "policy", POLICY, "recordKind", "header")));
                writer.write('\n');
                int count = 0;
                long ordinal = 0;
                long[] work = {0};
                boolean[] firstRecord = {true};
                NativeInterfaceTypeGraphV1.Budget[] graphBudget = new NativeInterfaceTypeGraphV1.Budget[1];
                graphBudget[0] = new NativeInterfaceTypeGraphV1.Budget(NativeInterfaceTypeGraphV1.Limits.defaults(),
                    () -> checkGraphWork(work, graphBudget[0].steps(), monitor));
                NativeInterfaceTypeGraphV1 graph = new NativeInterfaceTypeGraphV1(program.getDataTypeManager().getDataOrganization(),
                    graphBudget[0],
                    record -> writeRecord(writer, firstRecord, globalScope(record)));
                DataIterator data = listing.getDefinedData(true);
                Address previousData = null;
                while (data.hasNext()) {
                    monitor.checkCancelled();
                    chargeWork(work, graphBudget[0].steps(), monitor);
                    Data item = Objects.requireNonNull(data.next(), "defined data iterator returned null");
                    if (++count > expected || count > MAXIMUM_DATA) throw new IllegalStateException("defined data census grew during capture");
                    Address address = Objects.requireNonNull(item.getAddress(), "defined data address unavailable");
                    if (previousData != null && previousData.compareTo(address) >= 0) throw new IllegalStateException("defined data iterator is not strictly ordered");
                    previousData = address;
                    DataType type = Objects.requireNonNull(item.getDataType(), "defined data type unavailable");
                    String addressSpace = text(address.getAddressSpace().getName());
                    Symbol symbol = program.getSymbolTable().getPrimarySymbol(address);
                    Map<String, Object> row = object("addressSpace", addressSpace,
                        "addressSpaceIndex", spaceIndex(address, spaceIndices), "captureKey", captureKey(address, spaceIndices),
                        "dataOrdinal", ordinal, "length", item.getLength(),
                        "linkageState", symbol == null ? "no-primary-symbol" : "primary-symbol-present",
                        "symbolExternal", symbol == null ? null : symbol.isExternal(),
                        "symbolGlobal", symbol == null ? null : symbol.isGlobal(),
                        "recordKind", "defined-data", "symbolName", symbol == null ? null : text(symbol.getName()),
                        "symbolSource", symbol == null ? null : text(symbol.getSource().name()),
                        "symbolType", symbol == null ? null : text(symbol.getSymbolType().toString()),
                        "typePathCaptureKey", text(type.getPathName()));
                    writeRecord(writer, firstRecord, row);
                    NativeInterfaceTypeGraphV1.Scope scope = graph.scope("listing", ordinal);
                    Integer root = scope.reference(type);
                    writeRecord(writer, firstRecord, object("dataOrdinal", ordinal, "recordKind", "type-root", "rootNode", root));
                    if (type instanceof ghidra.program.model.data.Enum enumeration) {
                        int enumeratorCount = enumeration.getCount();
                        if (enumeratorCount < 0 || enumeratorCount > 4096) throw new IllegalStateException("global enum member count exceeds its bound");
                        String[] names = Objects.requireNonNull(enumeration.getNames(), "global enum names unavailable");
                        if (names.length != enumeratorCount || enumeration.getCount() != enumeratorCount)
                            throw new IllegalStateException("global enum population changed during capture");
                        java.util.Arrays.sort(names);
                        String previousName = null;
                        for (String name : names) {
                            chargeWork(work, graphBudget[0].steps(), monitor);
                            name = text(name);
                            if (previousName != null && previousName.compareTo(name) >= 0) throw new IllegalStateException("global enum member names are not unique");
                            previousName = name;
                            long value = enumeration.getValue(name);
                            writeRecord(writer, firstRecord, object("dataOrdinal", ordinal, "enumeratorName", name,
                                "recordKind", "enum-member", "value", value,
                                "valueBits", String.format("%016x", value)));
                        }
                        if (enumeration.getCount() != enumeratorCount) throw new IllegalStateException("global enum population changed after capture");
                    }
                    ordinal++;
                }
                if (count != expected || listing.getNumDefinedData() != expected) throw new IllegalStateException("defined data census changed during capture");
                long references = 0;
                int functions = 0;
                HashSet<String> functionIds = new HashSet<>();
                var functionIterator = program.getFunctionManager().getFunctions(true);
                Address previousFunction = null;
                while (functionIterator.hasNext()) {
                    monitor.checkCancelled();
                    chargeWork(work, graphBudget[0].steps(), monitor);
                    Function function = Objects.requireNonNull(functionIterator.next(), "function iterator returned null");
                    if (++functions > expectedFunctions || functions > MAXIMUM_FUNCTIONS) throw new IllegalStateException("function census grew during global reference capture");
                    String functionId = "fn_" + String.format("%016x", function.getEntryPoint().getOffset());
                    if (!functionIds.add(functionId)) throw new IllegalStateException("function owner IDs collide across address spaces");
                    if (previousFunction != null && previousFunction.compareTo(function.getEntryPoint()) >= 0)
                        throw new IllegalStateException("function iterator is not strictly ordered");
                    previousFunction = function.getEntryPoint();
                    InstructionIterator instructions = listing.getInstructions(function.getBody(), true);
                    Address previousInstruction = null;
                    while (instructions.hasNext()) {
                        monitor.checkCancelled();
                        chargeWork(work, graphBudget[0].steps(), monitor);
                        Instruction instruction = instructions.next();
                        if (previousInstruction != null && previousInstruction.compareTo(instruction.getAddress()) >= 0)
                            throw new IllegalStateException("function instruction iterator is not strictly ordered");
                        previousInstruction = instruction.getAddress();
                        ReferenceIterator refs = program.getReferenceManager().getReferenceIterator(instruction.getAddress());
                        ArrayList<Reference> instructionReferences = new ArrayList<>();
                        while (refs.hasNext()) {
                            Reference reference = refs.next();
                            if (!reference.getFromAddress().equals(instruction.getAddress())) break;
                            chargeWork(work, graphBudget[0].steps(), monitor);
                            if (++references > MAXIMUM_REFERENCES) throw new IllegalStateException("global reference observation bound exceeded");
                            if (instructionReferences.size() >= 4096) throw new IllegalStateException("references per instruction exceed their bound");
                            instructionReferences.add(reference);
                        }
                        instructionReferences.sort(Comparator.comparing(Reference::getToAddress)
                            .thenComparingInt(Reference::getOperandIndex)
                            .thenComparing(reference -> reference.getReferenceType().getName()));
                        for (Reference reference : instructionReferences) {
                            if (!reference.getReferenceType().isData()) continue;
                            Address targetAddress = reference.getToAddress();
                            if (!targetAddress.isMemoryAddress()) {
                                writeRecord(writer, firstRecord, unresolvedReference(functionId, instruction.getAddress(), targetAddress,
                                    reference.getOperandIndex(), "non-memory-target", spaceIndices));
                                continue;
                            }
                            Data target = listing.getDataContaining(reference.getToAddress());
                            if (target == null) {
                                writeRecord(writer, firstRecord, unresolvedReference(functionId, instruction.getAddress(), targetAddress,
                                    reference.getOperandIndex(), "no-defined-data-containing-target", spaceIndices));
                                continue;
                            }
                            writeRecord(writer, firstRecord, object("dataCaptureKey", captureKey(target.getAddress(), spaceIndices),
                                "functionId", functionId, "operandIndex", reference.getOperandIndex(),
                                "recordKind", "function-global-reference", "referenceAddress", captureKey(instruction.getAddress(), spaceIndices),
                                "targetAddress", captureKey(targetAddress, spaceIndices)));
                        }
                    }
                }
                if (functions != expectedFunctions || program.getFunctionManager().getFunctionCount() != expectedFunctions) {
                    throw new IllegalStateException("function census changed during global reference capture");
                }
                if (program.getModificationNumber() != modificationBefore || !hashModel(model, monitor).equals(modelBefore)) {
                    throw new IllegalStateException("program or model changed during global/type capture");
                }
                writer.flush();
                bytes = bounded.count;
            }
            monitor.checkCancelled();
            try { Files.move(staging, output, java.nio.file.StandardCopyOption.ATOMIC_MOVE); }
            catch (java.nio.file.AtomicMoveNotSupportedException unsupported) { Files.move(staging, output); }
            complete = true;
        } finally {
            if (!complete) Files.deleteIfExists(staging);
        }
        if (bytes <= 0 || bytes > maximumBytes) throw new IllegalStateException("global/type sidecar byte bound exceeded");
    }

    private static Path canonical(String value) throws IOException {
        Path path = Path.of(value);
        if (!path.isAbsolute() || !path.normalize().equals(path)) throw new IllegalArgumentException("global/type path is not canonical");
        return path;
    }

    private static String digest(String value) {
        if (!value.matches("[a-f0-9]{64}")) throw new IllegalArgumentException("invalid global/type binding digest");
        return value;
    }

    private static ModelIdentity hashModel(Path path, TaskMonitor monitor) throws Exception {
        long size = Files.size(path);
        if (size < 1 || size > MAXIMUM_MODEL_BYTES || !Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS))
            throw new IllegalStateException("program model is missing or excessive");
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        long count = 0;
        try (var input = Files.newInputStream(path)) {
            byte[] buffer = new byte[65536];
            int read;
            while ((read = input.read(buffer)) >= 0) {
                monitor.checkCancelled();
                if (read == 0) continue;
                count = Math.addExact(count, read);
                if (count > size) throw new IllegalStateException("program model grew while hashing");
                digest.update(buffer, 0, read);
            }
        }
        if (count != size || Files.size(path) != size) throw new IllegalStateException("program model changed while hashing");
        return new ModelIdentity(size, java.util.HexFormat.of().formatHex(digest.digest()));
    }

    private record ModelIdentity(long bytes, String sha256) {}

    private static void writeRecord(BufferedWriter writer, boolean[] first, Map<String, Object> value) throws IOException {
        writer.write(json(value));
        writer.write('\n');
        first[0] = false;
    }

    private static Map<String, Object> globalScope(Map<String, Object> record) {
        TreeMap<String, Object> scoped = new TreeMap<>(record);
        Object ordinal = scoped.remove("functionOrdinal");
        Object channel = scoped.remove("channel");
        if (!"listing".equals(channel) || !(ordinal instanceof Number)) {
            throw new IllegalStateException("shared type graph emitted a record outside the expected raw scope");
        }
        scoped.put("dataOrdinal", ((Number) ordinal).longValue());
        scoped.put("scopeKind", "defined-data");
        return Collections.unmodifiableMap(scoped);
    }

    private static String text(String value) {
        if (value == null || value.length() > 4096) throw new IllegalStateException("global/type metadata is unavailable or excessive");
        int utf8Bytes = 0;
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (Character.isHighSurrogate(c)) {
                if (++i >= value.length() || !Character.isLowSurrogate(value.charAt(i))) throw new IllegalStateException("global/type metadata has invalid UTF-16");
                utf8Bytes += 4;
            } else {
                if (Character.isLowSurrogate(c)) throw new IllegalStateException("global/type metadata has invalid UTF-16");
                utf8Bytes += c <= 0x7f ? 1 : c <= 0x7ff ? 2 : 3;
            }
            if (utf8Bytes > 4096) throw new IllegalStateException("global/type metadata exceeds its UTF-8 byte bound");
        }
        return value;
    }

    private static String captureKey(Address address, java.util.IdentityHashMap<AddressSpace, Integer> spaces) {
        AddressSpace space = address.getAddressSpace();
        return "as" + spaceIndex(address, spaces) + "@" + String.format("%016x", address.getUnsignedOffset());
    }

    private static int spaceIndex(Address address, java.util.IdentityHashMap<AddressSpace, Integer> spaces) {
        Integer index = spaces.get(address.getAddressSpace());
        if (index == null) throw new IllegalStateException("address belongs to an unlisted address space");
        return index;
    }

    private static Map<String, Object> unresolvedReference(String functionId, Address from, Address to, int operand,
            String reason, java.util.IdentityHashMap<AddressSpace, Integer> spaces) {
        return object("functionId", functionId, "operandIndex", operand, "reason", reason,
            "recordKind", "function-global-reference-unresolved", "referenceAddress", captureKey(from, spaces),
            "targetAddress", captureKey(to, spaces));
    }

    private static void chargeWork(long[] work, long graphSteps, TaskMonitor monitor) throws Exception {
        monitor.checkCancelled();
        if (work[0] >= MAXIMUM_WORK || graphSteps >= MAXIMUM_WORK - work[0]) throw new IllegalStateException("global/type collector work bound exceeded");
        work[0]++;
        work[0]++;
    }

    private static void checkGraphWork(long[] work, long graphSteps, TaskMonitor monitor) throws Exception {
        monitor.checkCancelled();
        if (work[0] + graphSteps >= MAXIMUM_WORK) throw new IllegalStateException("global/type collector work bound exceeded");
    }

    private static Map<String, Object> object(Object... pairs) {
        Map<String, Object> result = new TreeMap<>();
        for (int i = 0; i < pairs.length; i += 2) result.put((String) pairs[i], pairs[i + 1]);
        return Collections.unmodifiableMap(result);
    }

    private static String json(Object value) {
        if (value == null) return "null";
        if (value instanceof String string) return quote(string);
        if (value instanceof Number || value instanceof Boolean) return value.toString();
        if (value instanceof Map<?, ?> map) {
            List<String> keys = new ArrayList<>();
            for (Object key : map.keySet()) keys.add((String) key);
            Collections.sort(keys);
            List<String> fields = new ArrayList<>(keys.size());
            for (String key : keys) fields.add(quote(key) + ":" + json(map.get(key)));
            return "{" + String.join(",", fields) + "}";
        }
        if (value instanceof Iterable<?> iterable) {
            List<String> values = new ArrayList<>();
            for (Object item : iterable) values.add(json(item));
            return "[" + String.join(",", values) + "]";
        }
        throw new IllegalArgumentException("unsupported global/type JSON value");
    }

    private static String quote(String value) {
        StringBuilder out = new StringBuilder(value.length() + 2).append('"');
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            switch (c) {
                case '"' -> out.append("\\\"");
                case '\\' -> out.append("\\\\");
                case '\b' -> out.append("\\b");
                case '\f' -> out.append("\\f");
                case '\n' -> out.append("\\n");
                case '\r' -> out.append("\\r");
                case '\t' -> out.append("\\t");
                default -> { if (c < 0x20) out.append(String.format("\\u%04x", (int)c)); else out.append(c); }
            }
        }
        return out.append('"').toString();
    }

    private static final class BoundedDigestOutput extends java.io.FilterOutputStream {
        final long maximum;
        long count;
        BoundedDigestOutput(java.io.OutputStream output, long maximum) {
            super(output); this.maximum = maximum;
        }
        @Override public void write(int value) throws IOException {
            reserve(1); out.write(value); count++;
        }
        @Override public void write(byte[] bytes, int offset, int length) throws IOException {
            reserve(length); out.write(bytes, offset, length); count += length;
        }
        private void reserve(int amount) throws IOException {
            if (amount < 0 || count > maximum - amount) throw new IOException("global/type sidecar exceeds its byte bound");
        }
    }
}
