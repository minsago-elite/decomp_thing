package decompengine.ci;

import org.junit.platform.launcher.LauncherSession;
import org.junit.platform.launcher.LauncherSessionListener;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.*;

/** CI fixture identity only; runs inside each selected Test JVM before test execution. */
public final class OwnedJdkFixtureSession implements LauncherSessionListener {
    private Path opened;
    private static void require(boolean ok) {
        if (!ok) throw new IllegalStateException("owned CI Test JVM identity admission failed");
    }
    private static String hash(Path file) throws Exception {
        var digest = MessageDigest.getInstance("SHA-256");
        try (var input = Files.newInputStream(file, LinkOption.NOFOLLOW_LINKS)) {
            byte[] buffer = new byte[65536]; int size; long total = 0;
            while ((size = input.read(buffer)) >= 0) if (size > 0) {
                total += size; require(total <= 16L * 1024 * 1024); digest.update(buffer, 0, size);
            }
        }
        return HexFormat.of().formatHex(digest.digest());
    }
    private static Map<String,String> properties(Path path) throws Exception {
        require(!Files.isSymbolicLink(path) && Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS) && Files.size(path) <= 16384);
        var result = new LinkedHashMap<String,String>();
        byte[] bytes;
        try (var input = Files.newInputStream(path, LinkOption.NOFOLLOW_LINKS)) { bytes = input.readNBytes(16385); }
        require(bytes.length <= 16384);
        for (String line : new String(bytes, StandardCharsets.US_ASCII).split("\n")) {
            int at = line.indexOf('='); require(at > 0);
            require(result.put(line.substring(0, at), line.substring(at + 1)) == null);
        }
        return result;
    }
    private static Map<String,String> caller() throws Exception {
        byte[] bytes;
        try (var input = Files.newInputStream(Path.of("/proc/self/status"))) { bytes = input.readNBytes(65537); }
        require(bytes.length <= 65536);
        var selected = new HashMap<String,String>();
        for (String line : new String(bytes, StandardCharsets.US_ASCII).split("\n")) {
            int at = line.indexOf(':'); if (at < 0) continue;
            String key = line.substring(0, at);
            if (Set.of("Pid", "Uid", "Gid").contains(key)) require(selected.put(key, line.substring(at+1).trim()) == null);
        }
        require(Long.toString(ProcessHandle.current().pid()).equals(selected.get("Pid")));
        var result = new HashMap<String,String>();
        for (String key : List.of("Uid", "Gid")) {
            String value = selected.get(key); require(value != null);
            String[] fields = value.split("\\s+"); require(fields.length == 4);
            for (String field : fields) require(field.matches("[0-9]{1,10}"));
            result.put("caller" + key, String.join(",", fields));
        }
        return result;
    }
    @Override public void launcherSessionOpened(LauncherSession session) {
        String supplied = System.getProperty("decompengine.ci.fixture.receipt");
        if (supplied == null) return;
        try {
            Path receipt = Path.of(supplied);
            require(receipt.isAbsolute() && receipt.toRealPath().equals(receipt));
            var expected = properties(receipt);
            require(expected.keySet().equals(Set.of("home", "java", "dev", "ino", "uid", "mode", "sha256", "callerUid", "callerGid", "receipts")));
            Path home = Path.of(System.getProperty("java.home"));
            String command = ProcessHandle.current().info().command().orElseThrow();
            Path java = Path.of(command);
            require(home.toString().equals(expected.get("home")) && home.toRealPath().equals(home));
            require(command.equals(expected.get("java")) && java.toRealPath().equals(java) && java.equals(home.resolve("bin/java")));
            require(Files.isRegularFile(java, LinkOption.NOFOLLOW_LINKS) && !Files.isSymbolicLink(java));
            var attrs = Files.readAttributes(java, "unix:dev,ino,uid,mode,nlink", LinkOption.NOFOLLOW_LINKS);
            require(((Number)attrs.get("nlink")).longValue() == 1);
            // Bind the running kernel executable, not only a byte-equal named sibling.
            var running = Files.readAttributes(Path.of("/proc/self/exe"), "unix:dev,ino,uid,mode,nlink");
            for (String key : List.of("dev", "ino", "uid", "mode", "nlink")) require(attrs.get(key).equals(running.get(key)));
            var actual = new LinkedHashMap<String,String>();
            actual.put("home", home.toString()); actual.put("command", command);
            for (String key : List.of("dev", "ino", "uid")) actual.put(key, attrs.get(key).toString());
            actual.put("mode", Integer.toOctalString(((Number)attrs.get("mode")).intValue() & 07777));
            actual.put("sha256", hash(java)); actual.putAll(caller());
            for (String key : List.of("dev", "ino", "uid", "mode", "sha256", "callerUid", "callerGid")) require(actual.get(key).equals(expected.get(key)));
            Path state = receipt.getParent();
            require(state.getFileName().toString().matches("ci-jdk-[0-9a-f-]{36}") && state.getParent().getFileName().toString().equals("build"));
            Path scratch = state.getParent().getParent();
            require(scratch.isAbsolute() && scratch.toRealPath().equals(scratch) &&
                scratch.toString().getBytes(StandardCharsets.UTF_8).length + 63 <= 107);
            require(Files.isDirectory(scratch, LinkOption.NOFOLLOW_LINKS));
            var scratchAttrs = Files.readAttributes(scratch, "unix:uid,mode", LinkOption.NOFOLLOW_LINKS);
            require(scratchAttrs.get("uid").equals(attrs.get("uid")) && (((Number)scratchAttrs.get("mode")).intValue() & 0022) == 0);
            for (String key : List.of("java.io.tmpdir", "jna.tmpdir")) require(scratch.toString().equals(System.getProperty(key)));
            for (String key : List.of("TMPDIR", "TMP", "TEMP")) require(scratch.toString().equals(System.getenv(key)));
            actual.put("scratch", scratch.toString());
            String task = System.getProperty("decompengine.ci.fixture.task"); require(task != null && task.matches(":[A-Za-z0-9:_-]{1,160}"));
            actual.put("pid", Long.toString(ProcessHandle.current().pid())); actual.put("task", task);
            Path output = Path.of(expected.get("receipts"));
            require(output.toRealPath().equals(output) && Files.isDirectory(output, LinkOption.NOFOLLOW_LINKS));
            require(output.getParent().equals(receipt.getParent()));
            opened = output.resolve("test-jvm-" + ProcessHandle.current().pid() + "-" + UUID.randomUUID() + ".properties");
            StringBuilder text = new StringBuilder(); actual.forEach((k,v) -> text.append(k).append('=').append(v).append('\n'));
            Files.writeString(opened, text, StandardCharsets.US_ASCII, StandardOpenOption.CREATE_NEW);
        } catch (Exception failure) { throw new IllegalStateException("owned CI Test JVM identity admission failed", failure); }
    }
    @Override public void launcherSessionClosed(LauncherSession session) {
        if (opened == null) return;
        try {
            Path closed = opened.resolveSibling(opened.getFileName().toString().replace(".properties", ".closed"));
            Files.writeString(closed, "closed\n", StandardCharsets.US_ASCII, StandardOpenOption.CREATE_NEW);
        } catch (Exception failure) { throw new IllegalStateException("owned CI Test JVM identity completion failed", failure); }
    }
}
