import decompengine.acp.AcpRuntimeClosureLimits;
import decompengine.acp.LinuxBubblewrapBoundaryKt;
import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.channels.SeekableByteChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.MessageDigest;
import java.util.Comparator;
import java.util.EnumSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;

/** Trusted, host-specific provisioning for the credential-free ACP interoperability lane. */
public final class AcpCompatibilityProvisioner {
    private static final AcpRuntimeClosureLimits CLOSURE_LIMITS =
        new AcpRuntimeClosureLimits(10_000, 536_870_912L, 32);
    private static final List<Path> LIBRARY_DESTINATION_ROOTS = List.of(
        Path.of("/lib64"),
        Path.of("/usr/lib64"),
        Path.of("/lib/x86_64-linux-gnu"),
        Path.of("/usr/lib/x86_64-linux-gnu")
    );
    private static final int MAXIMUM_LDD_BYTES = 64 * 1024;
    private static final int MAXIMUM_AGENT_ARGUMENTS = 1_023;
    private static final long MAXIMUM_AGENT_ARGUMENT_BYTES = 1_048_576L;
    private static final Pattern IMPLEMENTATION_ID =
        Pattern.compile("[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}");
    private static final Pattern NEEDED_LIBRARY = Pattern.compile("[A-Za-z0-9_.+~-]{1,128}");
    private static final Pattern LDD_DEPENDENCY = Pattern.compile(
        "^\\s*([^\\s]+)\\s+=>\\s+(/[^\\s]+)\\s+\\(0x[0-9a-fA-F]+\\)\\s*$"
    );
    private static final Pattern LDD_ABSOLUTE = Pattern.compile(
        "^\\s*(/[^\\s]+)\\s+\\(0x[0-9a-fA-F]+\\)\\s*$"
    );

    private AcpCompatibilityProvisioner() {}

    public static void main(String[] arguments) throws Exception {
        if (arguments.length < 4) {
            throw new IllegalArgumentException(
                "usage: AcpCompatibilityProvisioner <agent> <gate-helper> <implementation-id> " +
                    "<output-config> [agent-argument ...]"
            );
        }
        var agent = requireCanonicalExecutable("ACP compatibility agent", Path.of(arguments[0]));
        var gateHelper = requireCanonicalExecutable("ACP sandbox gate helper", Path.of(arguments[1]));
        var implementationId = arguments[2];
        if (!IMPLEMENTATION_ID.matcher(implementationId).matches()) {
            throw new IllegalArgumentException("ACP compatibility implementation id is invalid");
        }
        var output = requireNewOutput(Path.of(arguments[3]));
        var agentArguments = requireBoundedArguments(arguments, 4);
        var mounts = discoverRuntimeMounts(agent);

        var root = object(
            "schemaVersion", 1,
            "implementationId", implementationId,
            "agent", object(
                "executable", agent.toString(),
                "arguments", agentArguments,
                "environment", List.of(
                    environment("HOME", "/tmp/decomp-acp-compatibility/home"),
                    environment("XDG_CONFIG_HOME", "/tmp/decomp-acp-compatibility/config"),
                    environment("XDG_DATA_HOME", "/tmp/decomp-acp-compatibility/data"),
                    environment("XDG_CACHE_HOME", "/tmp/decomp-acp-compatibility/cache")
                ),
                "inheritParentEnvironment", false,
                "requiredCapabilities", List.of(),
                "timeoutsMillis", object(
                    "startup", 20_000,
                    "request", 120_000,
                    "cancellationGrace", 2_000,
                    "transportDrainGrace", 100,
                    "shutdown", 5_000
                ),
                "protocolLimits", object(
                    "maximumFrameBytes", 1_048_576,
                    "maximumProtocolFrames", 1_024,
                    "maximumStderrBytes", 262_144
                ),
                "filesystemLimits", object(
                    "maximumReadBytes", 8_388_608,
                    "maximumWriteBytes", 8_388_608
                ),
                "permissionMode", "default-deny",
                "expectedExecutableManifestSha256", runtimeManifest(agent)
            ),
            "sandbox", object(
                "bubblewrapExecutable", "/usr/bin/bwrap",
                "resourceLimiterExecutable", "/usr/bin/prlimit",
                "scopeSupervisorExecutable", "/usr/bin/systemd-run",
                "scopeInspectorExecutable", "/usr/bin/systemctl",
                "environmentFdOpenerExecutable", "/usr/bin/bash",
                "sandboxGateHelperExecutable", gateHelper.toString(),
                "systemdUserRuntimeDirectory", "/run/user/" + currentUid(),
                "agentWorkingDirectory", "/tmp",
                "launcherRuntimeMounts", List.of(),
                "agentRuntimeMounts", mounts,
                "agentResourceLimits", object(
                    "maximumProcesses", 32,
                    "maximumOpenFiles", 128,
                    "maximumFileBytes", 67_108_864,
                    "maximumAddressSpaceBytes", 2_147_483_648L,
                    "maximumCpuSeconds", 20
                ),
                "runtimeClosureLimits", object(
                    "maximumEntries", 10_000,
                    "maximumUserOwnedFileBytes", 536_870_912L,
                    "maximumDepth", 32
                ),
                "expectedBubblewrapSha256", fileSha256(Path.of("/usr/bin/bwrap")),
                "expectedResourceLimiterSha256", fileSha256(Path.of("/usr/bin/prlimit")),
                "expectedScopeSupervisorSha256", fileSha256(Path.of("/usr/bin/systemd-run")),
                "expectedScopeInspectorSha256", fileSha256(Path.of("/usr/bin/systemctl")),
                "expectedEnvironmentFdOpenerSha256", fileSha256(Path.of("/usr/bin/bash")),
                "expectedSandboxGateHelperSha256", fileSha256(gateHelper),
                "expectedSandboxGateHelperManifestSha256", runtimeManifest(gateHelper)
            )
        );
        var bytes = AcpCompatibilityJson.encode(root);
        writePrivateFile(output, bytes);
        System.out.println(output);
    }

    private static List<Map<String, Object>> discoverRuntimeMounts(Path executable) throws Exception {
        var interpreter = readElfInterpreter(executable);
        var mounts = new LinkedHashMap<Path, Map<String, Object>>();
        addMount(mounts, interpreter.toRealPath(), interpreter);

        var processBuilder = new ProcessBuilder("/usr/bin/ldd", executable.toString())
            .redirectErrorStream(true);
        processBuilder.environment().clear();
        processBuilder.environment().put("LC_ALL", "C");
        var process = processBuilder.start();
        process.getOutputStream().close();
        if (!process.waitFor(10, TimeUnit.SECONDS)) {
            process.destroyForcibly();
            process.waitFor(2, TimeUnit.SECONDS);
            throw new IllegalStateException("ldd timed out while provisioning the ACP compatibility agent");
        }
        var output = readBounded(process.getInputStream(), MAXIMUM_LDD_BYTES);
        if (process.exitValue() != 0) {
            throw new IllegalStateException("ldd rejected the pinned ACP compatibility agent");
        }
        var sawLibc = false;
        for (var line : new String(output, StandardCharsets.UTF_8).split("\\R")) {
            if (line.isBlank() || line.strip().startsWith("linux-vdso.so.")) {
                continue;
            }
            var dependency = LDD_DEPENDENCY.matcher(line);
            if (dependency.matches()) {
                var needed = dependency.group(1);
                if (!NEEDED_LIBRARY.matcher(needed).matches()) {
                    throw new IllegalStateException("ldd emitted an invalid dependency name");
                }
                var source = Path.of(dependency.group(2)).toRealPath();
                addLibraryMounts(mounts, source, needed);
                sawLibc |= needed.equals("libc.so.6");
                continue;
            }
            var absolute = LDD_ABSOLUTE.matcher(line);
            if (absolute.matches() && Path.of(absolute.group(1)).normalize().equals(interpreter)) {
                continue;
            }
            if (line.contains("=> not found")) {
                throw new IllegalStateException("ACP compatibility agent has an unresolved shared library");
            }
            throw new IllegalStateException("ldd emitted an unsupported record for the ACP compatibility agent");
        }
        if (!sawLibc || mounts.size() < 3) {
            throw new IllegalStateException("ACP compatibility runtime closure is incomplete");
        }
        return mounts.values().stream()
            .sorted(Comparator.comparing(value -> (String) value.get("destination")))
            .toList();
    }

    /**
     * Glibc's x86-64 default library directories vary between FHS and Debian multiarch hosts.
     * Exact authenticated file aliases avoid both a broad library-directory bind and loader-control
     * environment variables or a host ld.so.cache.
     */
    private static void addLibraryMounts(
        Map<Path, Map<String, Object>> mounts,
        Path source,
        String needed
    ) throws Exception {
        for (var root : LIBRARY_DESTINATION_ROOTS) {
            addMount(mounts, source, root.resolve(needed));
        }
    }

    private static void addMount(
        Map<Path, Map<String, Object>> mounts,
        Path source,
        Path destination
    ) throws Exception {
        source = source.toRealPath();
        destination = destination.toAbsolutePath().normalize();
        if (!Files.isRegularFile(source, LinkOption.NOFOLLOW_LINKS)) {
            throw new IllegalStateException("ACP compatibility runtime dependency is not a real file");
        }
        var mount = object(
            "source", source.toString(),
            "destination", destination.toString(),
            "expectedManifestSha256", runtimeManifest(source)
        );
        var previous = mounts.putIfAbsent(destination, mount);
        if (previous != null && !previous.equals(mount)) {
            throw new IllegalStateException("ACP compatibility runtime dependencies conflict");
        }
    }

    private static Path readElfInterpreter(Path executable) throws Exception {
        var size = Files.size(executable);
        if (size < 64) {
            throw new IllegalStateException("ACP compatibility agent is not ELF64");
        }
        try (SeekableByteChannel channel = Files.newByteChannel(executable, StandardOpenOption.READ)) {
            var header = readExactly(channel, 64, 0);
            if (header.get(0) != 0x7f || header.get(1) != 'E' || header.get(2) != 'L' ||
                header.get(3) != 'F' || header.get(4) != 2 || header.get(5) != 1) {
                throw new IllegalStateException("ACP compatibility agent is not little-endian ELF64");
            }
            header.order(ByteOrder.LITTLE_ENDIAN);
            if (Short.toUnsignedInt(header.getShort(18)) != 62) {
                throw new IllegalStateException("ACP compatibility agent is not x86-64 ELF");
            }
            var programOffset = header.getLong(32);
            var entrySize = Short.toUnsignedInt(header.getShort(54));
            var entryCount = Short.toUnsignedInt(header.getShort(56));
            if (programOffset < 0 || entrySize < 56 || entryCount < 1 || entryCount > 1024) {
                throw new IllegalStateException("ACP compatibility agent has an invalid ELF program table");
            }
            Path result = null;
            for (var index = 0; index < entryCount; index++) {
                var offset = Math.addExact(programOffset, Math.multiplyExact((long) index, (long) entrySize));
                if (offset > size - entrySize) {
                    throw new IllegalStateException("ACP compatibility ELF program table exceeds the file");
                }
                var entry = readExactly(channel, entrySize, offset).order(ByteOrder.LITTLE_ENDIAN);
                if (entry.getInt(0) != 3) {
                    continue;
                }
                if (result != null) {
                    throw new IllegalStateException("ACP compatibility agent has multiple ELF interpreters");
                }
                var stringOffset = entry.getLong(8);
                var stringSize = entry.getLong(32);
                if (stringSize < 2 || stringSize > 4096 || stringOffset < 0 || stringOffset > size - stringSize) {
                    throw new IllegalStateException("ACP compatibility ELF interpreter is invalid");
                }
                var encoded = new byte[Math.toIntExact(stringSize)];
                readExactly(channel, encoded, stringOffset);
                if (encoded[encoded.length - 1] != 0) {
                    throw new IllegalStateException("ACP compatibility ELF interpreter is unterminated");
                }
                for (var byteIndex = 0; byteIndex < encoded.length - 1; byteIndex++) {
                    if (encoded[byteIndex] == 0) {
                        throw new IllegalStateException("ACP compatibility ELF interpreter contains NUL");
                    }
                }
                var text = StandardCharsets.UTF_8.newDecoder()
                    .decode(ByteBuffer.wrap(encoded, 0, encoded.length - 1))
                    .toString();
                if (!text.startsWith("/")) {
                    throw new IllegalStateException("ACP compatibility ELF interpreter is not absolute");
                }
                result = Path.of(text).toAbsolutePath().normalize();
            }
            if (result == null || !result.toString().startsWith("/")) {
                throw new IllegalStateException("ACP compatibility agent has no absolute ELF interpreter");
            }
            return result;
        }
    }

    private static ByteBuffer readExactly(SeekableByteChannel channel, int count, long offset) throws Exception {
        var bytes = new byte[count];
        readExactly(channel, bytes, offset);
        return ByteBuffer.wrap(bytes);
    }

    private static void readExactly(SeekableByteChannel channel, byte[] bytes, long offset) throws Exception {
        channel.position(offset);
        var buffer = ByteBuffer.wrap(bytes);
        while (buffer.hasRemaining()) {
            var count = channel.read(buffer);
            if (count <= 0) {
                throw new IllegalStateException(
                    count < 0
                        ? "ACP compatibility ELF record is truncated"
                        : "ACP compatibility ELF read made no progress"
                );
            }
        }
    }

    private static byte[] readBounded(java.io.InputStream input, int maximumBytes) throws Exception {
        var output = new ByteArrayOutputStream();
        var buffer = new byte[8192];
        while (true) {
            var count = input.read(buffer);
            if (count < 0) {
                return output.toByteArray();
            }
            if (output.size() + count > maximumBytes) {
                throw new IllegalStateException("ldd output exceeded its byte limit");
            }
            output.write(buffer, 0, count);
        }
    }

    private static Path requireCanonicalExecutable(String label, Path configured) throws Exception {
        var normalized = configured.toAbsolutePath().normalize();
        var real = normalized.toRealPath();
        if (!normalized.equals(real) || !Files.isRegularFile(real, LinkOption.NOFOLLOW_LINKS) ||
            !Files.isExecutable(real)) {
            throw new IllegalArgumentException(label + " must be a canonical executable file");
        }
        return real;
    }

    private static List<String> requireBoundedArguments(String[] arguments, int offset) {
        var count = arguments.length - offset;
        if (count > MAXIMUM_AGENT_ARGUMENTS) {
            throw new IllegalArgumentException("ACP compatibility argv exceeds its argument-count limit");
        }
        var result = new java.util.ArrayList<String>(count);
        long encodedBytes = 0;
        for (var index = offset; index < arguments.length; index++) {
            var argument = arguments[index];
            encodedBytes = Math.addExact(
                encodedBytes,
                argument.getBytes(StandardCharsets.UTF_8).length + 1L
            );
            if (encodedBytes > MAXIMUM_AGENT_ARGUMENT_BYTES) {
                throw new IllegalArgumentException("ACP compatibility argv exceeds its byte limit");
            }
            result.add(argument);
        }
        return List.copyOf(result);
    }

    private static Path requireNewOutput(Path configured) throws Exception {
        var output = configured.toAbsolutePath().normalize();
        var parent = output.getParent();
        if (parent == null || !Files.isDirectory(parent, LinkOption.NOFOLLOW_LINKS) ||
            Files.isSymbolicLink(parent) || Files.exists(output, LinkOption.NOFOLLOW_LINKS)) {
            throw new IllegalArgumentException("ACP compatibility config output must be a new file in a real directory");
        }
        return output;
    }

    private static int currentUid() throws Exception {
        return ((Number) Files.getAttribute(Path.of("/proc/self"), "unix:uid")).intValue();
    }

    private static Map<String, Object> environment(String name, String value) {
        return object("name", name, "provenance", "public", "value", value);
    }

    private static String runtimeManifest(Path path) {
        return LinuxBubblewrapBoundaryKt.calculateAcpRuntimeManifestSha256(path, CLOSURE_LIMITS);
    }

    private static String fileSha256(Path path) throws Exception {
        var digest = MessageDigest.getInstance("SHA-256");
        try (var input = Files.newInputStream(path)) {
            var buffer = new byte[8192];
            while (true) {
                var count = input.read(buffer);
                if (count < 0) {
                    break;
                }
                digest.update(buffer, 0, count);
            }
        }
        return hex(digest.digest());
    }

    private static String hex(byte[] bytes) {
        var output = new StringBuilder(bytes.length * 2);
        for (var value : bytes) {
            output.append(String.format("%02x", value));
        }
        return output.toString();
    }

    private static void writePrivateFile(Path output, byte[] bytes) throws Exception {
        var permissions = PosixFilePermissions.asFileAttribute(Set.of(
            PosixFilePermission.OWNER_READ,
            PosixFilePermission.OWNER_WRITE
        ));
        try (var channel = Files.newByteChannel(
            output,
            EnumSet.of(StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE),
            permissions
        )) {
            var buffer = ByteBuffer.wrap(bytes);
            while (buffer.hasRemaining()) {
                channel.write(buffer);
            }
        }
    }

    private static Map<String, Object> object(Object... fields) {
        if (fields.length % 2 != 0) {
            throw new IllegalArgumentException("JSON object fields must be key/value pairs");
        }
        var result = new LinkedHashMap<String, Object>();
        for (var index = 0; index < fields.length; index += 2) {
            result.put((String) fields[index], fields[index + 1]);
        }
        return result;
    }
}
