package decompengine.project;

import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.util.HexFormat;

/** Test-only, one-time startup observation; it grants no containment or acceptance authority. */
public final class ModuleCompilerFdDiagnosticMain {
    private ModuleCompilerFdDiagnosticMain() {}

    public static void main(String[] arguments) throws Exception {
        if (arguments.length != 3) throw new IllegalArgumentException("expected request, request digest, diagnostic path");
        byte[] limits = readBounded(Path.of("/proc/self/limits"), 8192);
        byte[] stat = readBounded(Path.of("/proc/self/stat"), 4096);
        String limitsText = new String(limits, StandardCharsets.US_ASCII);
        String line = limitsText.lines().filter(value -> value.startsWith("Max open files ")).findFirst().orElseThrow();
        String[] values = line.substring("Max open files".length()).trim().split("\\s+");
        if (values.length != 3 || !values[2].equals("files")) throw new IllegalStateException("malformed open-file limit");
        long soft = Long.parseLong(values[0]);
        long hard = Long.parseLong(values[1]);
        String statText = new String(stat, StandardCharsets.US_ASCII);
        int end = statText.lastIndexOf(')');
        int begin = statText.indexOf('(');
        if (begin < 1 || end <= begin) throw new IllegalStateException("malformed process stat");
        long pid = Long.parseLong(statText.substring(0, begin).trim());
        String[] fields = statText.substring(end + 1).trim().split("\\s+");
        if (fields.length < 20) throw new IllegalStateException("truncated process stat");
        long startTimeTicks = Long.parseLong(fields[19]);
        if (pid != ProcessHandle.current().pid() || startTimeTicks <= 0 || soft <= 0 || hard < soft) {
            throw new IllegalStateException("invalid startup process or limit identity");
        }
        String record = "{\"schemaVersion\":1,\"scope\":\"test-only-worker-startup-observation\",\"pid\":" + pid
            + ",\"startTimeTicks\":" + startTimeTicks + ",\"softNofile\":" + soft + ",\"hardNofile\":" + hard
            + ",\"limitsSha256\":\"" + digest(limits) + "\",\"statSha256\":\"" + digest(stat)
            + "\",\"limits\":" + quote(limitsText) + ",\"stat\":" + quote(statText) + "}";
        Path diagnostic = Path.of(arguments[2]);
        if (!diagnostic.isAbsolute() || !diagnostic.normalize().equals(diagnostic)) {
            throw new IllegalArgumentException("diagnostic path must be absolute and normalized");
        }
        // Every proc/file handle is closed before the actual worker establishes its own protection.
        try (OutputStream output = Files.newOutputStream(diagnostic, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE)) {
            output.write(record.getBytes(StandardCharsets.UTF_8));
        }
        ContainedModuleCompilerWorker.main(new String[] { arguments[0], arguments[1] });
    }

    private static byte[] readBounded(Path path, int maximum) throws Exception {
        try (InputStream input = Files.newInputStream(path)) {
            byte[] bytes = input.readNBytes(maximum + 1);
            if (bytes.length == 0 || bytes.length > maximum) throw new IllegalStateException("unbounded diagnostic proc file");
            return bytes;
        }
    }

    private static String digest(byte[] bytes) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
    }

    private static String quote(String value) {
        StringBuilder result = new StringBuilder("\"");
        for (int index = 0; index < value.length(); index++) {
            char character = value.charAt(index);
            switch (character) {
                case '"' -> result.append("\\\"");
                case '\\' -> result.append("\\\\");
                case '\n' -> result.append("\\n");
                case '\r' -> result.append("\\r");
                case '\t' -> result.append("\\t");
                default -> {
                    if (character < 32 || character > 126) throw new IllegalStateException("unexpected proc text character");
                    result.append(character);
                }
            }
        }
        return result.append('"').toString();
    }
}
