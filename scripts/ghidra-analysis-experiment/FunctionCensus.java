// Diagnostic-only: retains the complete recovered function entry set, never an accuracy claim.
//@category Diagnostics

import ghidra.app.script.GhidraScript;
import ghidra.framework.options.OptionType;
import ghidra.framework.options.Options;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Program;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.TreeSet;

public class FunctionCensus extends GhidraScript {
    private static final int MAX_ENTRIES = 1_000_000;
    private static final int MAX_OUTPUT_BYTES = 32 * 1024 * 1024;

    @Override
    protected void run() throws Exception {
        String[] arguments = getScriptArgs();
        if (arguments.length < 1 || arguments.length > 2) {
            throw new IllegalArgumentException("usage: FunctionCensus <output.json> [disabled-analyzers]");
        }
        Path root = Path.of("").toRealPath();
        Path output = Path.of(arguments[0]).toAbsolutePath().normalize();
        if (output.getParent() == null || !output.getParent().toRealPath().startsWith(root)) {
            throw new IllegalArgumentException("census output must be inside the repository working directory");
        }
        if (Files.exists(output, java.nio.file.LinkOption.NOFOLLOW_LINKS)) {
            throw new IllegalArgumentException("census output already exists");
        }
        String inputSha256 = currentProgram.getExecutableSHA256();
        if (inputSha256 == null || !inputSha256.matches("[0-9a-fA-F]{64}")) {
            throw new IllegalArgumentException("program has no complete executable SHA-256");
        }
        Set<String> disabled = new TreeSet<>();
        Options options = currentProgram.getOptions(Program.ANALYSIS_PROPERTIES);
        if (arguments.length == 2) {
            for (String value : arguments[1].split(",", -1)) {
                String name = value.trim();
                if (name.isEmpty() || name.length() > 256 || !disabled.add(name) || disabled.size() > 256
                        || !options.contains(name) || options.getType(name) != OptionType.BOOLEAN_TYPE
                        || options.getBoolean(name, true)) {
                    throw new IllegalArgumentException("disabled analyzer was not verified: " + name);
                }
            }
        }
        Address base = currentProgram.getImageBase();
        if (!base.getAddressSpace().equals(currentProgram.getAddressFactory().getDefaultAddressSpace())) {
            throw new IllegalArgumentException("image base is outside the default address space");
        }
        List<Long> entries = new ArrayList<>();
        FunctionIterator functions = currentProgram.getFunctionManager().getFunctions(true);
        while (functions.hasNext()) {
            monitor.checkCancelled();
            if (entries.size() == MAX_ENTRIES) {
                throw new IllegalArgumentException("function census exceeds its entry bound");
            }
            Function function = functions.next();
            Address entry = function.getEntryPoint();
            if (!entry.getAddressSpace().equals(base.getAddressSpace())) {
                throw new IllegalArgumentException("function entry is outside the default address space");
            }
            entries.add(entry.getOffset());
        }
        entries.sort(Long::compareUnsigned);
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        StringBuilder addresses = new StringBuilder();
        Long previous = null;
        for (long entry : entries) {
            monitor.checkCancelled();
            if (previous != null && entry == previous.longValue()) {
                throw new IllegalArgumentException("duplicate function entry");
            }
            String address = "0x" + Long.toHexString(entry);
            digest.update((address + "\n").getBytes(StandardCharsets.US_ASCII));
            if (previous != null) addresses.append(',');
            addresses.append('"').append(address).append('"');
            previous = entry;
        }
        String entrySha256 = java.util.HexFormat.of().formatHex(digest.digest());
        StringBuilder json = new StringBuilder();
        json.append("{\"schemaVersion\":1,\"kind\":\"ghidra-function-entry-census-v1\",")
            .append("\"authority\":\"diagnostic-only\",\"inputSha256\":")
            .append(quote(inputSha256.toLowerCase(Locale.ROOT)))
            .append(",\"imageBase\":").append(quote("0x" + Long.toHexString(base.getOffset())))
            .append(",\"languageId\":").append(quote(currentProgram.getLanguageID().toString()))
            .append(",\"compilerSpecId\":").append(quote(currentProgram.getCompilerSpec().getCompilerSpecID().toString()))
            .append(",\"entries\":[").append(addresses).append("]")
            .append(",\"entryCount\":").append(entries.size())
            .append(",\"entriesSha256\":").append(quote(entrySha256))
            .append(",\"disabledAnalyzers\":[");
        boolean first = true;
        for (String name : disabled) {
            if (!first) json.append(',');
            json.append(quote(name));
            first = false;
        }
        byte[] payload = json.append("]}\n").toString().getBytes(StandardCharsets.UTF_8);
        if (payload.length > MAX_OUTPUT_BYTES) {
            throw new IllegalArgumentException("function census exceeds its output byte bound");
        }
        monitor.checkCancelled();
        Path staging = Files.createTempFile(output.getParent(), ".function-census-", ".json",
            PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")));
        try {
            Files.write(staging, payload, StandardOpenOption.TRUNCATE_EXISTING);
            monitor.checkCancelled();
            // An atomic hard-link publication fails if the destination exists. ATOMIC_MOVE
            // may replace an existing destination even without REPLACE_EXISTING on Unix.
            Files.createLink(output, staging);
        } finally {
            Files.deleteIfExists(staging);
        }
        println("ANALYZER-EXPERIMENT functions=" + entries.size() + " entriesSha256=" + entrySha256);
    }

    private static String quote(String value) {
        if (value == null || value.length() > 4096) {
            throw new IllegalArgumentException("census metadata exceeds its string bound");
        }
        StringBuilder result = new StringBuilder("\"");
        for (int index = 0; index < value.length(); index++) {
            char character = value.charAt(index);
            if (character == '"' || character == '\\') result.append('\\').append(character);
            else if (character < 0x20 || character > 0x7e) {
                result.append(String.format(Locale.ROOT, "\\u%04x", (int) character));
            } else result.append(character);
        }
        return result.append('"').toString();
    }
}
