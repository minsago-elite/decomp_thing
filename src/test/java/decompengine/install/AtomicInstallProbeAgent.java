package decompengine.install;

import java.lang.instrument.ClassFileTransformer;
import java.lang.instrument.Instrumentation;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.security.ProtectionDomain;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import java.util.jar.JarFile;

/** Test-only probe: reflection selects production authority discovery, never alternate authority inputs. */
public final class AtomicInstallProbeAgent {
    private static final String MODEL = "decompengine.project.ProgramModelJson";
    private record Definition(ClassLoader loader, ProtectionDomain domain) {}
    private AtomicInstallProbeAgent() {}

    public static void premain(String arguments, Instrumentation instrumentation) {
        int status = 1;
        Path ready = null;
        String phase = "setup";
        try {
            Path app = Path.of(required("atomic.probe.app")).toRealPath();
            ready = Path.of(required("atomic.probe.ready"));
            Path release = Path.of(required("atomic.probe.release"));
            String marker = required("atomic.probe.marker");
            String authorityKind = System.getProperty("atomic.probe.authority", "none");
            long releaseTimeoutSeconds = Long.parseLong(required("atomic.probe.releaseTimeoutSeconds"));
            if (releaseTimeoutSeconds < 1 || releaseTimeoutSeconds > 3600)
                throw new IllegalArgumentException("release timeout outside test bounds");
            AtomicReference<Definition> definition = new AtomicReference<>();
            instrumentation.addTransformer(new ClassFileTransformer() {
                @Override public byte[] transform(Module module, ClassLoader loader, String name,
                        Class<?> redefining, ProtectionDomain domain, byte[] bytes) {
                    if (MODEL.replace('.', '/').equals(name)) {
                        if (!definition.compareAndSet(null, new Definition(loader, domain)))
                            throw new AssertionError("multiple model definitions");
                    }
                    return null;
                }
            }, false);
            ClassLoader loader = ClassLoader.getSystemClassLoader();
            Class<?> main = Class.forName("decompengine.MainKt", false, loader);
            Path origin = origin(main.getProtectionDomain());
            if (!origin.equals(app) || main.getClassLoader() != loader)
                throw new AssertionError("installed MainKt loader/origin mismatch");
            phase = "open retained authority";
            try (AutoCloseable authority = openAuthority(authorityKind);
                 FileChannel pinned = FileChannel.open(app, StandardOpenOption.READ);
                 JarFile oldArchive = new JarFile(app.toFile(), false);
                 var pinnedResource = loader.getResourceAsStream("atomic-install-generation.txt")) {
                if (pinnedResource == null) throw new AssertionError("missing pre-opened loader resource");
                for (Class<?> loaded : instrumentation.getAllLoadedClasses())
                    if (loaded.getName().equals(MODEL)) throw new AssertionError("ProgramModelJson loaded before READY");
                String oldDigest = digest(pinned);
                if (oldArchive.getEntry("decompengine/project/ProgramModelJson.class") == null)
                    throw new AssertionError("old app JAR is incomplete");
                String oldArchiveMarker = archiveMarker(oldArchive);
                if (!marker.equals(oldArchiveMarker)) throw new AssertionError("old archive marker mismatch");
                Map<String, String> evidence = new LinkedHashMap<>();
                evidence.put("descriptorDigest", oldDigest);
                evidence.put("mainOrigin", origin.toString());
                evidence.put("mainLoader", loaderName(main.getClassLoader()));
                evidence.put("classpath", System.getProperty("java.class.path"));
                evidence.put("archiveMarker", oldArchiveMarker);
                evidence.put("modelAbsentBeforeReady", "true");
                evidence.put("resourceOpenedBeforeReady", "true");
                evidence.put("authority", authorityKind);
                evidence.put("releaseTimeoutSeconds", Long.toString(releaseTimeoutSeconds));
                phase = "READY";
                write(ready, evidence);
                long waitStart = System.nanoTime();
                long waitBudget = TimeUnit.SECONDS.toNanos(releaseTimeoutSeconds);
                while (!Files.exists(release)) {
                    if (releaseWaitExpired(waitStart, System.nanoTime(), waitBudget))
                        throw new AssertionError("timed out waiting for RELEASE");
                    Thread.sleep(20);
                }
                phase = "retained authority verification";
                if (authority != null) {
                    String expected = Files.readString(release).strip();
                    try {
                        verifyAuthority(authorityKind, authority);
                        if (!expected.equals("unchanged") && !expected.equals("lease-refused")) throw new AssertionError("retained authority accepted a replaced deployment");
                        evidence.put("authorityOutcome", "unchanged-valid");
                    } catch (InvocationTargetException wrapped) {
                        Throwable failure = wrapped.getCause();
                        if (expected.equals("unchanged") || failure instanceof LinkageError)
                            throw wrapped;
                        String diagnostic = failure.toString();
                        // Require the real guard/reference/lease rejection, not arbitrary probe failures.
                        if (!diagnostic.matches("(?is).*(changed|identity|lease|mutat|reference|replaced|disappear).*") ||
                            !(failure.getClass().getName().startsWith("decompengine.oracle."))) throw wrapped;
                        evidence.put("authorityOutcome", "rejected-before-authorization");
                        evidence.put("authorityDiagnostic", diagnostic);
                    }
                }
                phase = "late resource and model definition";
                if (!new String(pinnedResource.readNBytes(128), java.nio.charset.StandardCharsets.UTF_8).equals(marker))
                    throw new AssertionError("pre-opened classloader resource changed generation");
                try (var stream = loader.getResourceAsStream("atomic-install-generation.txt")) {
                    if (stream == null || !new String(stream.readNBytes(128), java.nio.charset.StandardCharsets.UTF_8).equals(marker))
                        throw new AssertionError("late classloader resource is not the original generation");
                }
                Class<?> modelClass = Class.forName(MODEL, true, loader);
                Definition observed = definition.get();
                Path modelOrigin = origin(modelClass.getProtectionDomain());
                if (observed == null || observed.loader() != modelClass.getClassLoader() ||
                    modelClass.getClassLoader() != main.getClassLoader() ||
                    !origin(observed.domain()).equals(modelOrigin) || !modelOrigin.equals(app))
                    throw new AssertionError("late definition loader/protection-domain mismatch");
                Object singleton = modelClass.getField("INSTANCE").get(null);
                Object decoded = modelClass.getMethod("read", String.class).invoke(singleton, required("atomic.probe.model"));
                long schema = ((Number) decoded.getClass().getMethod("getSchemaVersion").invoke(decoded)).longValue();
                String input = (String) decoded.getClass().getMethod("getInputSha256").invoke(decoded);
                if (schema != 4 || !input.equals("a".repeat(64))) throw new AssertionError("model identity mismatch");
                if (!digest(pinned).equals(oldDigest) || !archiveMarker(oldArchive).equals(marker))
                    throw new AssertionError("old descriptor/archive changed");
                evidence.put("schemaVersion", Long.toString(schema));
                evidence.put("inputSha256", input);
                evidence.put("modelLoader", loaderName(modelClass.getClassLoader()));
                evidence.put("modelOrigin", modelOrigin.toString());
                evidence.put("transformLoader", loaderName(observed.loader()));
                evidence.put("transformOrigin", origin(observed.domain()).toString());
                evidence.put("lateResourceMarker", marker);
                try (FileChannel current = FileChannel.open(app, StandardOpenOption.READ)) {
                    evidence.put("installedPathDigestAfterRelease", digest(current));
                }
                write(ready.resolveSibling("READY.loaded"), evidence);
            }
            status = 0;
        } catch (Throwable failure) {
            System.err.println("Atomic install probe failed during " + phase);
            failure.printStackTrace(System.err);
            if (ready != null) try {
                write(ready.resolveSibling("READY.failure"), Map.of("phase", phase, "failure", failure.toString()));
            } catch (Throwable recording) { failure.addSuppressed(recording); }
        }
        System.exit(status); // Never enter production main after premain, including failure.
    }

    private static AutoCloseable openAuthority(String kind) throws Exception {
        if (kind.equals("none")) return null;
        if (kind.equals("gcc")) {
            Class<?> type = Class.forName("decompengine.oracle.gcc.GccKotlinBootClasspathReference");
            Object companion = type.getField("Companion").get(null);
            return (AutoCloseable) companion.getClass().getMethod("open").invoke(companion);
        }
        if (kind.equals("llvm")) {
            Class<?> source = Class.forName("decompengine.oracle.behavior.LlvmBehaviorHostedWorkerImageV1BuildContextKt");
            Method discover = source.getDeclaredMethod("discoverApplicationSelection");
            discover.setAccessible(true);
            Object selection = discover.invoke(null); // Real installed discovery; no fabricated paths/provenance.
            Class<?> closure = Class.forName("decompengine.oracle.behavior.BoundApplicationClosure");
            var field = closure.getDeclaredField("Companion"); field.setAccessible(true);
            Object companion = field.get(null);
            Method open = companion.getClass().getDeclaredMethod("open", selection.getClass()); open.setAccessible(true);
            return (AutoCloseable) open.invoke(companion, selection);
        }
        throw new IllegalArgumentException("unknown authority " + kind);
    }
    private static void verifyAuthority(String kind, AutoCloseable authority) throws Exception {
        Method verify = authority.getClass().getDeclaredMethod(kind.equals("gcc") ? "verify" : "requireCurrent", String.class);
        verify.setAccessible(true);
        verify.invoke(authority, "atomic-install retained authority before authorization");
    }
    private static String archiveMarker(JarFile jar) throws Exception {
        var entry = jar.getJarEntry("atomic-install-generation.txt");
        if (entry == null || entry.getSize() > 128) throw new AssertionError("missing/bounded marker");
        try (var stream = jar.getInputStream(entry)) { return new String(stream.readNBytes(128), java.nio.charset.StandardCharsets.UTF_8); }
    }
    private static Path origin(ProtectionDomain domain) throws Exception {
        if (domain == null || domain.getCodeSource() == null) throw new AssertionError("missing code origin");
        return Path.of(domain.getCodeSource().getLocation().toURI()).toRealPath();
    }
    private static String loaderName(ClassLoader loader) { return loader.getClass().getName() + "@" + Integer.toHexString(System.identityHashCode(loader)); }
    private static String required(String key) {
        String value = System.getProperty(key);
        if (value == null || value.isBlank()) throw new IllegalArgumentException("missing " + key);
        return value;
    }
    static boolean releaseWaitExpired(long start, long now, long budget) {
        long elapsed = now - start;
        return elapsed < 0 || elapsed >= budget;
    }
    private static void write(Path path, Map<String, String> fields) throws Exception {
        StringBuilder json = new StringBuilder("{");
        for (var entry : fields.entrySet()) {
            if (json.length() > 1) json.append(',');
            json.append(quote(entry.getKey())).append(':').append(quote(entry.getValue()));
        }
        Path stage = path.resolveSibling(path.getFileName() + ".stage");
        try {
            Files.writeString(stage, json.append("}\n").toString(), StandardOpenOption.CREATE_NEW);
            Files.move(stage, path, java.nio.file.StandardCopyOption.ATOMIC_MOVE);
        } finally { Files.deleteIfExists(stage); }
    }
    private static String quote(String text) {
        StringBuilder out = new StringBuilder("\"");
        for (char c : text.toCharArray()) {
            if (c == '"' || c == '\\') out.append('\\').append(c);
            else if (c < 32) out.append(String.format("\\u%04x", (int)c));
            else out.append(c);
        }
        return out.append('"').toString();
    }
    private static String digest(FileChannel channel) throws Exception {
        MessageDigest hash = MessageDigest.getInstance("SHA-256");
        var buffer = java.nio.ByteBuffer.allocateDirect(64 * 1024);
        channel.position(0);
        while (channel.read(buffer) >= 0) { buffer.flip(); hash.update(buffer); buffer.clear(); }
        return HexFormat.of().formatHex(hash.digest());
    }
}
