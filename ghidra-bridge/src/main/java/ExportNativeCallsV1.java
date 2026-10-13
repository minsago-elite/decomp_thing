import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.*;
import ghidra.util.task.TaskMonitor;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.MessageDigest;
import java.util.*;

/** Read-only native observations. This collector never assigns oracle identities or modifies Program. */
public final class ExportNativeCallsV1 extends GhidraScript {
    private static final long MAXIMUM_BYTES = 1024L * 1024 * 1024;
    private static final long MAXIMUM_MODEL_BYTES = 512L * 1024 * 1024;
    private static final int MAXIMUM_FUNCTIONS = 131072;
    private static final long MAXIMUM_INSTRUCTIONS = 100000000L;
    private static final long MAXIMUM_SITES = 10000000L;
    private static final int MAXIMUM_REFERENCES = 64;
    private static final int MAXIMUM_SITE_REFERENCES = 256;
    private static final int MAXIMUM_RECORD_BYTES = 1024 * 1024;
    private static final int MAXIMUM_STRING_BYTES = 4096;
    private static final String POLICY = "ghidra-native-call-observations-v1";
    private final Program program;
    private final TaskMonitor task;
    private final List<AddressSpace> spaces = new ArrayList<>();
    private final Map<AddressSpace, Integer> spaceIndices = new HashMap<>();

    public ExportNativeCallsV1() { program = null; task = null; }
    private ExportNativeCallsV1(Program program, TaskMonitor task) { this.program = Objects.requireNonNull(program); this.task = Objects.requireNonNull(task); }
    @Override protected void run() throws Exception { collect(currentProgram, monitor, getScriptArgs()); }
    /** Tests invoke the same compiled collector that the contained worker loads as a post-script. */
    public static void collect(Program program, TaskMonitor monitor, String[] arguments) throws Exception {
        new ExportNativeCallsV1(program, monitor).export(arguments);
    }
    private void export(String[] arguments) throws Exception {
        if (arguments.length != 6) throw new IllegalArgumentException("expected input, model exporter, archive, collector digests, model path and output directory");
        String input = digest(arguments[0]);
        String modelExporter = digest(arguments[1]);
        String archive = digest(arguments[2]);
        String collector = digest(arguments[3]);
        if (!input.equals(digest(program.getExecutableSHA256()))) throw new IllegalArgumentException("native-call input differs from imported Program");
        Path model = Path.of(arguments[4]).toAbsolutePath().normalize();
        Path directory = Path.of(arguments[5]).toAbsolutePath().normalize();
        if (directory.getParent() == null || directory.getParent().toRealPath().compareTo(directory.getParent()) != 0 || Files.exists(directory, LinkOption.NOFOLLOW_LINKS) || model.startsWith(directory)) {
            throw new IllegalArgumentException("native-call output must be an absent private directory distinct from model");
        }
        task.checkCancelled();
        ModelIdentity before = hashModel(model);
        AddressSpace[] nativeSpaces = program.getAddressFactory().getAllAddressSpaces();
        if (nativeSpaces.length == 0 || nativeSpaces.length > 256) throw new IllegalStateException("address-space inventory bound exceeded");
        spaces.addAll(Arrays.asList(nativeSpaces));
        spaces.sort(AddressSpace::compareTo);
        List<Object> spaceRecords = new ArrayList<>();
        for (int i = 0; i < spaces.size(); i++) {
            AddressSpace space = spaces.get(i);
            if (spaceIndices.put(space, i) != null) throw new IllegalStateException("duplicate native address space");
            spaceRecords.add(object("index", i, "name", text(space.getName()), "type", space.getType(), "sizeBits", space.getSize(), "addressableUnitSize", space.getAddressableUnitSize(), "overlay", space.isOverlaySpace(), "signedOffsets", space.hasSignedOffset()));
        }
        TreeMap<Address, FunctionCount> functions = new TreeMap<>(this::compare);
        FunctionIterator iterator = program.getFunctionManager().getFunctions(true);
        while (iterator.hasNext()) {
            task.checkCancelled(); Function function = iterator.next();
            if (function.isExternal()) continue;
            if (functions.size() == MAXIMUM_FUNCTIONS) throw new IllegalStateException("function inventory bound exceeded");
            if (functions.put(function.getEntryPoint(), new FunctionCount(function)) != null) throw new IllegalStateException("duplicate native function entry");
        }
        Map<String,Object> bindings = object("collectorSha256", collector, "compilerSpecId", text(program.getCompilerSpec().getCompilerSpecID().getIdAsString()), "ghidraArchiveSha256", archive, "imageBase", address(program.getImageBase()), "inputSha256", input, "languageId", text(program.getLanguageID().getIdAsString()), "programModelBytes", before.bytes, "programModelExporterSha256", modelExporter, "programModelSha256", before.sha256);
        Path stage = null; Path manifestStage = null;
        Path observations = directory.resolve("native-calls.json"); Path manifestPath = directory.resolve("manifest.json");
        boolean complete = false;
        Files.createDirectory(directory, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")));
        try {
            stage = Files.createTempFile(directory, ".native-calls-", ".tmp", PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")));
            MessageDigest outputDigest = MessageDigest.getInstance("SHA-256");
            Totals totals = new Totals();
            long bytes;
            try (OutputStream file = new BufferedOutputStream(Files.newOutputStream(stage)); BoundedOutput output = new BoundedOutput(file, outputDigest, MAXIMUM_BYTES, task)) {
                output.writeUtf8("{\n  \"addressSpaces\": "); output.value(spaceRecords, 2, false);
                output.writeUtf8(",\n  \"bindings\": "); output.value(bindings, 2, false);
                output.writeUtf8(",\n  \"policy\": \"" + POLICY + "\",\n  \"records\": ");
                long records = 0;
                for (FunctionCount state : functions.values()) {
                    task.checkCancelled(); Function function = state.function;
                    Function target = function.isThunk() ? function.getThunkedFunction(false) : null;
                    if (function.isThunk() && target == null) throw new IllegalStateException("immediate native thunk target unavailable");
                    if (function.isThunk()) totals.thunks++;
                    Map<String,Object> record = object("recordKind", "function", "entry", address(function.getEntryPoint()), "bodyAddressCount", positive(function.getBody().getNumAddresses()), "bodyRangeCount", positive(function.getBody().getNumAddressRanges()), "isThunk", function.isThunk(), "immediateThunkTarget", target == null ? null : target(target.getEntryPoint(), target.isExternal() ? target.getExternalLocation() : null));
                    output.record(record, records++);
                }
                InstructionIterator instructions = program.getListing().getInstructions(true);
                Address previous = null;
                while (instructions.hasNext()) {
                    task.checkCancelled(); Instruction instruction = instructions.next();
                    if (++totals.instructions > MAXIMUM_INSTRUCTIONS) throw new IllegalStateException("instruction scan bound exceeded");
                    if (previous != null && compare(previous, instruction.getAddress()) >= 0) throw new IllegalStateException("native listing order differs from address-space table");
                    previous = instruction.getAddress();
                    Function owner = program.getFunctionManager().getFunctionContaining(instruction.getAddress());
                    FunctionCount count = owner == null ? null : functions.get(owner.getEntryPoint());
                    if (owner != null && (owner.isExternal() || count == null)) throw new IllegalStateException("native instruction owner absent from function inventory");
                    if (count == null) totals.unownedInstructions++; else { totals.ownedInstructions++; count.instructions++; }
                    var context = instruction.getInstructionContext(); var prototype = instruction.getPrototype();
                    FlowType raw = prototype.getFlowType(context); FlowType effective = instruction.getFlowType();
                    Address[] rawTargets = Objects.requireNonNull(prototype.getFlows(context), "null prototype flows");
                    if (rawTargets.length > MAXIMUM_REFERENCES) throw new IllegalStateException("prototype target bound exceeded");
                    rawTargets = rawTargets.clone(); Arrays.sort(rawTargets, this::compare);
                    for (int i = 1; i < rawTargets.length; i++) if (compare(rawTargets[i-1], rawTargets[i]) == 0) throw new IllegalStateException("duplicate prototype target");
                    Reference[] refs = references(instruction.getAddress());
                    boolean analyzedCall = effective.isCall();
                    boolean resolvedJump = false;
                    for (Reference ref : refs) {
                        if (ref.getReferenceType().isCall()) analyzedCall = true;
                        if (!ref.getReferenceType().isIndirect() && (ref.getReferenceType().isCall() || ref.getReferenceType().isJump()) && (ref.getToAddress().isMemoryAddress() || ref.getToAddress().isExternalAddress())) resolvedJump = true;
                    }
                    boolean tail = false;
                    if (!raw.isCall() && !analyzedCall && raw.isJump() && !raw.isConditional() && !raw.isComputed() && rawTargets.length == 1) {
                        Function target = program.getFunctionManager().getFunctionAt(rawTargets[0]);
                        tail = target != null && !target.isExternal() && (owner == null || !target.equals(owner) && !owner.getBody().contains(rawTargets[0]));
                    }
                    String kind = raw.isCall() ? "prototype-call" : analyzedCall ? "analysis-call-candidate" : tail ? "direct-tail-candidate" : null;
                    if (raw.isJump() && kind == null) { totals.ordinaryJumps++; if (count != null) count.ordinaryJumps++; }
                    if (raw.isJump() && raw.isComputed() && !resolvedJump) { totals.unresolvedComputedJumps++; if(count != null) count.unresolvedComputedJumps++; }
                    if (kind == null) continue;
                    if (++totals.sites > MAXIMUM_SITES) throw new IllegalStateException("native site count bound exceeded");
                    totals.site(kind, count == null); if (count != null) count.site(kind);
                    List<Object> targets = new ArrayList<>(); for (Address rawTarget : rawTargets) targets.add(target(rawTarget, null));
                    List<Object> referenceRecords = new ArrayList<>(); for (Reference ref : refs) referenceRecords.add(reference(ref));
                    totals.directReferences = Math.addExact(totals.directReferences, refs.length);
                    List<Object> neighborhoods = new ArrayList<>(); int retainedReferences = refs.length;
                    for (int index = 0; index < refs.length; index++) {
                        task.checkCancelled(); Reference via = refs[index];
                        if (!via.getToAddress().isMemoryAddress() || !(via.getReferenceType().isData() || via.getReferenceType() == RefType.INDIRECTION)) continue;
                        Reference[] second = references(via.getToAddress());
                        retainedReferences = Math.addExact(retainedReferences, second.length);
                        if (retainedReferences > MAXIMUM_SITE_REFERENCES) throw new IllegalStateException("site neighborhood reference bound exceeded");
                        List<Object> recordsAtSource = new ArrayList<>(); for (Reference ref : second) recordsAtSource.add(reference(ref));
                        neighborhoods.add(object("viaReferenceIndex", index, "source", address(via.getToAddress()), "references", recordsAtSource));
                        totals.neighborhoodReferences = Math.addExact(totals.neighborhoodReferences, second.length);
                    }
                    int length = instruction.getLength(); int delay = instruction.getDelaySlotDepth();
                    if (length <= 0 || delay < 0) throw new IllegalStateException("invalid listed instruction boundary");
                    boolean supported = delay == 0 && !instruction.isLengthOverridden() && length <= 4096;
                    byte[] nativeBytes = supported ? instruction.getBytes() : null;
                    if (supported && nativeBytes.length != length) throw new IllegalStateException("native instruction byte count changed");
                    output.record(object("recordKind", "site", "address", address(instruction.getAddress()), "owner", owner == null ? null : address(owner.getEntryPoint()), "observationKind", kind, "listedLength", length, "delaySlotDepth", delay, "lengthOverridden", instruction.isLengthOverridden(), "byteStatus", supported ? "available" : "unsupported-boundary", "instructionBytes", nativeBytes == null ? null : HexFormat.of().formatHex(nativeBytes), "prototypeFlow", refType(raw), "effectiveFlow", refType(effective), "flowOverride", instruction.getFlowOverride().name(), "prototypeFallThrough", nullableAddress(prototype.getFallThrough(context)), "effectiveFallThrough", nullableAddress(instruction.getFallThrough()), "prototypeTargets", targets, "references", referenceRecords, "referenceNeighborhoods", neighborhoods), records++);
                }
                for (FunctionCount count : functions.values()) {
                    task.checkCancelled();
                    output.record(object("recordKind", "function-summary", "entry", address(count.function.getEntryPoint()), "instructionsVisited", count.instructions, "prototypeCalls", count.prototypeCalls, "analysisCallCandidates", count.analysisCallCandidates, "directTailCandidates", count.directTailCandidates, "ordinaryJumpInstructions", count.ordinaryJumps, "unresolvedComputedJumps", count.unresolvedComputedJumps), records++);
                }
                output.writeUtf8(records == 0 ? "[]" : "\n  ]");
                output.writeUtf8(",\n  \"schemaVersion\": 1,\n  \"summary\": "); output.value(totals.json(functions.size()), 2, false);
                output.writeUtf8("\n}\n"); bytes = output.bytes;
            }
            String sha256 = HexFormat.of().formatHex(outputDigest.digest());
            requireModelUnchanged(before, hashModel(model)); task.checkCancelled();
            byte[] manifest = canonical(object("bytes", bytes, "collectorSha256", collector, "file", "native-calls.json", "inputSha256", input, "kind", "ghidra-native-call-observation-manifest-v1", "programModelSha256", before.sha256, "schemaVersion", 1, "sha256", sha256), 65536);
            if (Math.addExact(bytes, manifest.length) > MAXIMUM_BYTES) throw new IllegalStateException("combined native-call inventory bound exceeded");
            Files.setPosixFilePermissions(stage, PosixFilePermissions.fromString("r--------"));
            Files.createLink(observations, stage); Files.delete(stage); stage = null;
            manifestStage = Files.createTempFile(directory, ".native-manifest-", ".tmp", PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")));
            Files.write(manifestStage, manifest, StandardOpenOption.TRUNCATE_EXISTING);
            Files.setPosixFilePermissions(manifestStage, PosixFilePermissions.fromString("r--------"));
            requireModelUnchanged(before, hashModel(model)); task.checkCancelled();
            Files.createLink(manifestPath, manifestStage); Files.delete(manifestStage); manifestStage = null;
            complete = true;
        } finally {
            if (stage != null) Files.deleteIfExists(stage);
            if (manifestStage != null) Files.deleteIfExists(manifestStage);
            if (!complete) { Files.deleteIfExists(manifestPath); Files.deleteIfExists(observations); Files.deleteIfExists(directory); }
        }
    }
    private int compare(Address left, Address right) {
        if (left.equals(Address.NO_ADDRESS) || right.equals(Address.NO_ADDRESS)) return left.equals(right) ? 0 : left.equals(Address.NO_ADDRESS) ? -1 : 1;
        Integer l = spaceIndices.get(left.getAddressSpace()); Integer r = spaceIndices.get(right.getAddressSpace());
        if (l == null || r == null) throw new IllegalArgumentException("unrepresented native address space");
        int order = Integer.compare(l,r); return order != 0 ? order : spaces.get(l).hasSignedOffset() ? Long.compare(left.getOffset(), right.getOffset()) : Long.compareUnsigned(left.getOffset(), right.getOffset());
    }
    private Map<String,Object> address(Address value) {
        if (value == null) throw new IllegalArgumentException("null native address");
        if (value.equals(Address.NO_ADDRESS)) return object("kind", "no-address");
        Integer index = spaceIndices.get(value.getAddressSpace());
        if (index == null) throw new IllegalArgumentException("unrepresented native address space");
        return object("kind", "address", "spaceIndex", index, "offsetBits", String.format(Locale.ROOT, "%016x", value.getOffset()));
    }
    private Object nullableAddress(Address value) { return value == null ? null : address(value); }
    private Map<String,Object> target(Address value, ExternalLocation supplied) {
        Function exact = program.getFunctionManager().getFunctionAt(value);
        ExternalLocation external = supplied;
        if (external == null && value.isExternalAddress()) external = program.getExternalManager().getExternalLocation(program.getSymbolTable().getPrimarySymbol(value));
        if (external == null && exact != null && exact.isExternal()) external = exact.getExternalLocation();
        if (value.isExternalAddress() && external == null) throw new IllegalStateException("external target metadata unavailable");
        Object externalRecord = null;
        if (external != null) {
            if (!external.getExternalSpaceAddress().equals(value)) throw new IllegalStateException("external target address differs from location");
            externalRecord = object("externalSpaceAddress", address(external.getExternalSpaceAddress()), "externalProgramAddress", nullableAddress(external.getAddress()), "libraryName", text(external.getLibraryName()), "label", text(external.getLabel()), "originalImportedName", nullableText(external.getOriginalImportedName()), "source", external.getSource().name());
        }
        MemoryBlock block = value.isMemoryAddress() ? program.getMemory().getBlock(value) : null;
        Object blockRecord = block == null ? null : object("name", text(block.getName()), "start", address(block.getStart()), "end", address(block.getEnd()), "initialized", block.isInitialized(), "executable", block.isExecute());
        return object("address", address(value), "functionEntry", exact == null ? null : address(exact.getEntryPoint()), "external", externalRecord, "memoryBlock", blockRecord);
    }
    private Map<String,Object> reference(Reference ref) {
        ExternalLocation location = ref instanceof ExternalReference external ? Objects.requireNonNull(external.getExternalLocation(), "external reference location unavailable") : null;
        return object("from", address(ref.getFromAddress()), "target", target(ref.getToAddress(), location), "operandIndex", ref.getOperandIndex(), "primary", ref.isPrimary(), "source", ref.getSource().name(), "referenceType", refType(ref.getReferenceType()));
    }
    private Reference[] references(Address source) throws Exception {
        task.checkCancelled(); ReferenceManager manager = program.getReferenceManager();
        int count = manager.getReferenceCountFrom(source);
        if (count < 0 || count > MAXIMUM_REFERENCES) throw new IllegalStateException("native reference count bound exceeded");
        Reference[] values = Objects.requireNonNull(manager.getReferencesFrom(source), "native references unavailable");
        if (values.length != count || values.length > MAXIMUM_REFERENCES) throw new IllegalStateException("native reference count changed or exceeded bound");
        values = values.clone(); Arrays.sort(values, (a,b) -> {
            int c = compare(a.getToAddress(),b.getToAddress()); if(c != 0) return c;
            c = Integer.compare(a.getOperandIndex(),b.getOperandIndex()); if(c != 0) return c;
            c = Byte.compare(a.getReferenceType().getValue(), b.getReferenceType().getValue()); if(c != 0) return c;
            c = a.getSource().name().compareTo(b.getSource().name()); if(c != 0) return c;
            return Boolean.compare(a.isPrimary(),b.isPrimary());
        });
        for (int i = 0; i < values.length; i++) {
            if (!values[i].getFromAddress().equals(source)) throw new IllegalStateException("native reference source differs");
            if (i > 0 && sameReferenceKey(values[i-1], values[i])) throw new IllegalStateException("duplicate native reference key");
        }
        return values;
    }
    private static boolean sameReferenceKey(Reference a, Reference b) { return a.getToAddress().equals(b.getToAddress()) && a.getOperandIndex() == b.getOperandIndex() && a.getReferenceType().equals(b.getReferenceType()) && a.getSource() == b.getSource() && a.isPrimary() == b.isPrimary(); }
    private static Map<String,Object> refType(RefType type) { return object("code", (int) type.getValue(), "name", text(type.getName())); }
    private ModelIdentity hashModel(Path model) throws Exception {
        if (!model.toRealPath().equals(model)) throw new IllegalArgumentException("model path contains symbolic links");
        BasicFileAttributes before = Files.readAttributes(model, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
        if (!before.isRegularFile() || before.fileKey() == null || before.size() < 1 || before.size() > MAXIMUM_MODEL_BYTES) throw new IllegalArgumentException("model must be a bounded identified regular file");
        MessageDigest digest = MessageDigest.getInstance("SHA-256"); long bytes = 0;
        try(InputStream stream = Files.newInputStream(model, StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS)) {
            byte[] buffer = new byte[65536]; int count;
            while((count = stream.read(buffer)) != -1) { task.checkCancelled(); bytes = Math.addExact(bytes,count); if(bytes > MAXIMUM_MODEL_BYTES) throw new IllegalStateException("model byte bound exceeded"); digest.update(buffer,0,count); }
        }
        BasicFileAttributes after = Files.readAttributes(model, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
        if (bytes != before.size() || !sameIdentity(before,after)) throw new IllegalStateException("model changed during native export");
        return new ModelIdentity(bytes, HexFormat.of().formatHex(digest.digest()), after);
    }
    private static boolean sameIdentity(BasicFileAttributes a, BasicFileAttributes b) { return a.fileKey().equals(b.fileKey()) && a.size()==b.size() && a.lastModifiedTime().equals(b.lastModifiedTime()) && b.isRegularFile(); }
    private static void requireModelUnchanged(ModelIdentity a, ModelIdentity b) { if(a.bytes != b.bytes || !a.sha256.equals(b.sha256) || !sameIdentity(a.attributes,b.attributes)) throw new IllegalStateException("paired model changed during collection"); }
    private record ModelIdentity(long bytes, String sha256, BasicFileAttributes attributes) {}
    private static long positive(long value) { if(value < 0) throw new IllegalStateException("native count exceeds signed range"); return value; }
    private static String digest(String value) { if(value == null || !value.matches("[0-9a-f]{64}")) throw new IllegalArgumentException("invalid native-call digest binding"); return value; }
    private static String nullableText(String value) { return value == null ? null : text(value); }
    private static String text(String value) {
        Objects.requireNonNull(value, "native metadata unavailable");
        if(value.getBytes(StandardCharsets.UTF_8).length > MAXIMUM_STRING_BYTES) throw new IllegalStateException("native metadata string bound exceeded");
        for(int i=0;i<value.length();i++) { char c=value.charAt(i); if(Character.isHighSurrogate(c)) { if(i+1==value.length() || !Character.isLowSurrogate(value.charAt(++i))) throw new IllegalStateException("invalid native Unicode metadata"); } else if(Character.isLowSurrogate(c)) throw new IllegalStateException("invalid native Unicode metadata"); }
        return value;
    }
    private static Map<String,Object> object(Object... pairs) { TreeMap<String,Object> value = new TreeMap<>(); for(int i=0;i<pairs.length;i+=2) { String key=(String)pairs[i]; if(value.containsKey(key)) throw new IllegalStateException("duplicate schema field"); value.put(key,pairs[i+1]); } return value; }
    private static class FunctionCount {
        final Function function; long instructions, prototypeCalls, analysisCallCandidates, directTailCandidates, ordinaryJumps, unresolvedComputedJumps;
        FunctionCount(Function function) { this.function=function; }
        void site(String kind) { switch(kind) { case "prototype-call" -> prototypeCalls++; case "analysis-call-candidate" -> analysisCallCandidates++; case "direct-tail-candidate" -> directTailCandidates++; default -> throw new IllegalStateException(); } }
    }
    private static final class Totals extends FunctionCount {
        long thunks, sites, ownedInstructions, unownedInstructions, directReferences, neighborhoodReferences, unownedPrototypeCalls, unownedAnalysisCallCandidates, unownedDirectTailCandidates;
        Totals() { super(null); }
        void site(String kind, boolean unowned) { super.site(kind); if(unowned) switch(kind) { case "prototype-call" -> unownedPrototypeCalls++; case "analysis-call-candidate" -> unownedAnalysisCallCandidates++; case "direct-tail-candidate" -> unownedDirectTailCandidates++; default -> throw new IllegalStateException(); } }
        Map<String,Object> json(long functions) { return object("coverage", "all-currently-listed-instructions-and-recovered-functions", "functions", functions, "thunks", thunks, "instructionsVisited", instructions, "ownedInstructions", ownedInstructions, "unownedInstructions", unownedInstructions, "sites", sites, "prototypeCalls", prototypeCalls, "analysisCallCandidates", analysisCallCandidates, "directTailCandidates", directTailCandidates, "ordinaryJumpInstructions", ordinaryJumps, "unresolvedComputedJumps", unresolvedComputedJumps, "directReferences", directReferences, "neighborhoodReferences", neighborhoodReferences, "unownedPrototypeCalls", unownedPrototypeCalls, "unownedAnalysisCallCandidates", unownedAnalysisCallCandidates, "unownedDirectTailCandidates", unownedDirectTailCandidates); }
    }
    private static byte[] canonical(Object value, int limit) throws Exception {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        try(BoundedOutput output = new BoundedOutput(bytes, null, limit, TaskMonitor.DUMMY)) { encode(value,0,output); output.writeUtf8("\n"); }
        return bytes.toByteArray();
    }
    private static void encode(Object value, int indentation, BoundedOutput output) throws Exception {
        if(indentation > 32) throw new IllegalStateException("native JSON depth bound exceeded");
        if(value == null) { output.writeUtf8("null"); return; }
        if(value instanceof Map<?,?> map) {
            if(map.isEmpty()) { output.writeUtf8("{}"); return; }
            output.writeUtf8("{\n"); int i=0;
            for(var entry : map.entrySet()) { if(i++>0) output.writeUtf8(",\n"); output.spaces(indentation+2); encode(entry.getKey(), indentation+2, output); output.writeUtf8(": "); encode(entry.getValue(), indentation+2, output); }
            output.writeUtf8("\n"); output.spaces(indentation); output.writeUtf8("}"); return;
        }
        if(value instanceof List<?> list) {
            if(list.isEmpty()) { output.writeUtf8("[]"); return; }
            output.writeUtf8("[\n"); int i=0;
            for(Object entry:list) { if(i++>0) output.writeUtf8(",\n"); output.spaces(indentation+2); encode(entry,indentation+2,output); }
            output.writeUtf8("\n"); output.spaces(indentation); output.writeUtf8("]"); return;
        }
        if(value instanceof String s) {
            output.writeUtf8("\""); int start=0;
            for(int i=0;i<s.length();i++) { char c=s.charAt(i); String escape = switch(c) { case '"' -> "\\\""; case '\\' -> "\\\\"; case '\b' -> "\\b"; case '\t' -> "\\t"; case '\n' -> "\\n"; case '\f' -> "\\f"; case '\r' -> "\\r"; default -> c<32 ? String.format(Locale.ROOT,"\\u%04x",(int)c) : null; }; if(escape != null) { output.writeUtf8(s.substring(start,i)); output.writeUtf8(escape); start=i+1; } }
            output.writeUtf8(s.substring(start)); output.writeUtf8("\""); return;
        }
        if(value instanceof Boolean || value instanceof Integer || value instanceof Long) { output.writeUtf8(value.toString()); return; }
        throw new IllegalStateException("unsupported canonical value");
    }
    private static final class BoundedOutput extends OutputStream {
        final OutputStream output; final MessageDigest digest; final long maximum; final TaskMonitor monitor; long bytes;
        BoundedOutput(OutputStream output,MessageDigest digest,long maximum,TaskMonitor monitor) { this.output=output;this.digest=digest;this.maximum=maximum;this.monitor=monitor; }
        @Override public void write(int value) throws IOException { write(new byte[]{(byte)value}); }
        @Override public void write(byte[] value,int offset,int length) throws IOException { if(bytes > maximum-length) throw new IOException("native JSON byte bound exceeded"); bytes+=length; output.write(value,offset,length); if(digest!=null)digest.update(value,offset,length); }
        void writeUtf8(String value) throws Exception { monitor.checkCancelled(); write(value.getBytes(StandardCharsets.UTF_8)); }
        void spaces(int count) throws Exception { writeUtf8(" ".repeat(count)); }
        void value(Object value,int indentation,boolean first) throws Exception { byte[] encoded=canonical(value,MAXIMUM_RECORD_BYTES); if(first)spaces(indentation); int start=0; for(int i=0;i<encoded.length-1;i++) if(encoded[i]=='\n') { write(encoded,start,i-start);writeUtf8("\n");spaces(indentation);start=i+1; } write(encoded,start,encoded.length-1-start); }
        void record(Object value,long index) throws Exception { writeUtf8(index==0 ? "[\n" : ",\n");value(value,4,true); }
        @Override public void close() throws IOException { output.close(); }
    }
}
