package decompengine.project

import java.io.ByteArrayOutputStream
import java.net.URLClassLoader
import java.nio.file.Files
import java.nio.file.Path
import javax.tools.ToolProvider
import kotlin.io.path.createDirectories
import kotlin.io.path.readText
import kotlin.io.path.writeText
import kotlin.test.Test
import org.junit.jupiter.api.parallel.Isolated

@Isolated("compares legacy formatting under several process default locales")
class ExporterPureRenderingTest {
    @Test
    fun `production address and digest rendering equals legacy formatting across bits bytes and locales`() =
        withPureRenderingHarness("numeric")

    @Test
    fun `production type-name rendering equals legacy regex over BMP supplementary and malformed UTF16 names`() =
        withPureRenderingHarness("type-name")
    @Test
    fun `owned production rendering retains numeric and type name determinism`() {
        withPureRenderingHarness("numeric", owned = true)
        withPureRenderingHarness("type-name", owned = true)
    }

    @Test
    fun `owned prototype values enforce immutable coverage bounds statuses and refusal semantics`() = withOwnedPrototypeValues()

}

private fun withPureRenderingHarness(scenario: String, owned: Boolean = false) {
    val exporter = Path.of("src/main/resources/ghidra_scripts/${if (owned) "ExportProgramModelOwned" else "ExportProgramModel"}.java").readText()
    val beginMarker = "// PURE_RENDERING_TEST_BEGIN\n"
    val endMarker = "// PURE_RENDERING_TEST_END"
    val begin = exporter.indexOf(beginMarker)
    val end = exporter.indexOf(endMarker)
    require(begin >= 0 && end > begin && exporter.indexOf(beginMarker, begin + 1) == -1 &&
        exporter.indexOf(endMarker, end + 1) == -1) { "unique production pure rendering markers are missing" }
    val implementation = exporter.substring(begin + beginMarker.length, end)
    val root = Path.of("build", "exporter-rendering-v16").createDirectories()
    val temporary = Files.createTempDirectory(root, "differential-")
    try {
        val source = temporary.resolve("PureRenderingHarness.java").also {
            it.writeText(PURE_RENDERING_PREFIX + implementation + if (owned) PURE_RENDERING_HARNESS.replace("ExporterPureRenderingV1", "ExporterPureRenderingOwnedV1") else PURE_RENDERING_HARNESS)
        }
        val compiler = ToolProvider.getSystemJavaCompiler() ?: error("pure rendering tests require a JDK")
        val diagnostics = ByteArrayOutputStream()
        val result = compiler.run(null, diagnostics, diagnostics, "-Xlint:all", "-Werror", "-d", temporary.toString(), source.toString())
        check(result == 0) { diagnostics.toString(Charsets.UTF_8) }
        URLClassLoader(arrayOf(temporary.toUri().toURL())).use { loader ->
            loader.loadClass("PureRenderingHarness").getMethod("run", String::class.java).invoke(null, scenario)
        }
    } finally {
        temporary.toFile().deleteRecursively()
    }
}

private val PURE_RENDERING_PREFIX = """
    import java.util.Locale;
    import java.util.Random;
    import java.util.regex.Pattern;

""".trimIndent() + "\n"

private val PURE_RENDERING_HARNESS = """
    public final class PureRenderingHarness {
        private static final Locale[] LOCALES = {
            Locale.ROOT, Locale.US, Locale.forLanguageTag("tr-TR"),
            Locale.forLanguageTag("ar-EG"), Locale.forLanguageTag("fa-IR"), Locale.JAPAN
        };
        private static final String[] NAMES = {
            "", "a", "valid_Ascii_Name9", "123leadingDigit", "_", "$", "a-b.c/d\\e",
            "space and\ttab\nnewline", "é", "e\u0301", "İıiI", "Σσς", "مرحبا", "漢字",
            "a\u200db", "a\u0000b", "\ud800", "\udfff", "\ud800A\udfff",
            "\ud83d\ude00", "prefix\ud83d\ude00suffix", "\ud800\udc00\udbff\udfff",
            "\ud800\ud800\udc00\udc00", "_9α combining\u0301 pair\ud83d\ude00"
        };

        public static void run(String scenario) {
            Locale original = Locale.getDefault();
            Locale originalFormat = Locale.getDefault(Locale.Category.FORMAT);
            Locale originalDisplay = Locale.getDefault(Locale.Category.DISPLAY);
            try {
                switch (scenario) {
                    case "numeric": numeric(); break;
                    case "type-name": names(); break;
                    default: throw new AssertionError("unknown differential scenario " + scenario);
                }
            } finally {
                Locale.setDefault(original);
                Locale.setDefault(Locale.Category.FORMAT, originalFormat);
                Locale.setDefault(Locale.Category.DISPLAY, originalDisplay);
            }
            require(Locale.getDefault().equals(original), "default locale was not restored");
            require(Locale.getDefault(Locale.Category.FORMAT).equals(originalFormat), "format locale was not restored");
            require(Locale.getDefault(Locale.Category.DISPLAY).equals(originalDisplay), "display locale was not restored");
        }

        private static void numeric() {
            long[] offsets = new long[1040];
            long[] boundaries = {0, 1, 15, 16, 255, 256, 0xffffL, 0x10000L,
                0xffffffffL, 0x100000000L, Long.MIN_VALUE, Long.MIN_VALUE + 1,
                Long.MAX_VALUE - 1, Long.MAX_VALUE, -2, -1};
            System.arraycopy(boundaries, 0, offsets, 0, boundaries.length);
            Random random = new Random(0x63a415ec80b7L);
            for (int i = boundaries.length; i < offsets.length; i++) offsets[i] = random.nextLong();
            byte[] allBytes = new byte[256];
            for (int i = 0; i < allBytes.length; i++) allBytes[i] = (byte)i;
            byte[] digest32 = new byte[32];
            random.nextBytes(digest32);
            for (Locale locale : LOCALES) {
                Locale.setDefault(locale);
                for (long offset : offsets) {
                    equal(String.format("fn_%016x", offset), ExporterPureRenderingV1.addressId("fn_", offset), "function ID " + locale);
                    equal(String.format("global_%016x", offset), ExporterPureRenderingV1.addressId("global_", offset), "global ID " + locale);
                    equal("" + String.format("%016x", offset), ExporterPureRenderingV1.addressId("", offset), "empty ID prefix " + locale);
                    equal("préfix_" + String.format("%016x", offset), ExporterPureRenderingV1.addressId("préfix_", offset), "unchanged ID prefix " + locale);
                }
                equal(legacyDigest(new byte[0]), ExporterPureRenderingV1.hexDigest(new byte[0]), "empty digest " + locale);
                equal(legacyDigest(digest32), ExporterPureRenderingV1.hexDigest(digest32), "32-byte digest " + locale);
                equal(legacyDigest(allBytes), ExporterPureRenderingV1.hexDigest(allBytes), "256-byte digest " + locale);
                for (int value = 0; value < 256; value++) {
                    byte[] one = {(byte)value};
                    equal(legacyDigest(one), ExporterPureRenderingV1.hexDigest(one), "single digest byte " + value + " " + locale);
                }
                for (int iteration = 0; iteration < 32; iteration++) {
                    byte[] digest = new byte[32];
                    random.nextBytes(digest);
                    equal(legacyDigest(digest), ExporterPureRenderingV1.hexDigest(digest), "seeded digest " + iteration + " " + locale);
                }
            }
        }

        private static String legacyDigest(byte[] digest) {
            StringBuilder result = new StringBuilder();
            for (byte value : digest) result.append(String.format("%02x", value & 0xff));
            return result.toString();
        }

        private static void names() {
            for (Locale locale : LOCALES) {
                Locale.setDefault(locale);
                for (String name : NAMES) equal(name.replaceAll("[^A-Za-z0-9_]", "_"), ExporterPureRenderingV1.typeName(name), "name " + locale);
            }
            Locale.setDefault(Locale.ROOT);
            StringBuilder completeBmp = new StringBuilder(65536);
            for (int value = 0; value <= 0xffff; value++) {
                String isolated = String.valueOf((char)value);
                equal(isolated.replaceAll("[^A-Za-z0-9_]", "_"), ExporterPureRenderingV1.typeName(isolated), "isolated BMP unit " + value);
                String surrounded = "A" + isolated + "9_";
                equal(surrounded.replaceAll("[^A-Za-z0-9_]", "_"), ExporterPureRenderingV1.typeName(surrounded), "surrounded BMP unit " + value);
                completeBmp.append((char)value);
            }
            String combined = completeBmp.toString();
            equal(combined.replaceAll("[^A-Za-z0-9_]", "_"), ExporterPureRenderingV1.typeName(combined), "complete BMP sequence");
            Random random = new Random(0x762134aeL);
            for (int iteration = 0; iteration < 512; iteration++) {
                char[] units = new char[random.nextInt(129)];
                for (int i = 0; i < units.length; i++) units[i] = (char)random.nextInt(65536);
                String name = new String(units);
                equal(name.replaceAll("[^A-Za-z0-9_]", "_"), ExporterPureRenderingV1.typeName(name), "seeded UTF16 name " + iteration);
            }
        }

        private static void equal(String expected, String actual, String label) {
            if (expected.equals(actual)) return;
            int difference = 0;
            int common = Math.min(expected.length(), actual.length());
            while (difference < common && expected.charAt(difference) == actual.charAt(difference)) difference++;
            throw new AssertionError(label + ": legacy length=" + expected.length() + ", actual length=" + actual.length() + ", first differing UTF16 index=" + difference);
        }
        private static void require(boolean condition, String message) {
            if (!condition) throw new AssertionError(message);
        }
    }
""".trimIndent()

private fun withOwnedPrototypeValues() {
    val exporter = Path.of("src/main/resources/ghidra_scripts/ExportProgramModelOwned.java").readText()
    val implementation = exporter.substringAfter("// OWNED_PROTOTYPE_VALUES_TEST_BEGIN\n")
        .substringBefore("// OWNED_PROTOTYPE_VALUES_TEST_END")
    require(implementation != exporter && implementation.contains("class NativeOutcome"))
    val fingerprint = exporter.substringAfter("// SEMANTIC_FINGERPRINT_TEST_BEGIN\n")
        .substringBefore("// SEMANTIC_FINGERPRINT_TEST_END")
    require(fingerprint != exporter && fingerprint.contains("class ExporterSemanticFingerprintOwnedV1"))
    val root = Path.of("build/owned-prototype-value-tests").createDirectories()
    val directory = Files.createTempDirectory(root, "values-")
    try {
        val source = directory.resolve("OwnedPrototypeValuesHarness.java")
        source.writeText("import java.util.*;\nimport java.nio.charset.StandardCharsets;\nimport java.security.MessageDigest;\n" + fingerprint +
            "public final class OwnedPrototypeValuesHarness {\n" + implementation + OWNED_PROTOTYPE_VALUES_HARNESS + "\n}\n")
        val compiler = checkNotNull(ToolProvider.getSystemJavaCompiler())
        val diagnostics = ByteArrayOutputStream()
        check(compiler.run(null, diagnostics, diagnostics, "-Xlint:all", "-Werror", "-d", directory.toString(), source.toString()) == 0) {
            diagnostics.toString(Charsets.UTF_8)
        }
        URLClassLoader(arrayOf(directory.toUri().toURL())).use { loader ->
            loader.loadClass("OwnedPrototypeValuesHarness").getMethod("run").invoke(null)
        }
    } finally { directory.toFile().deleteRecursively() }
}

private val OWNED_PROTOTYPE_VALUES_HARNESS = """
    interface Checked { void run() throws Exception; }
    static void check(boolean value, String detail) { if (!value) throw new AssertionError(detail); }
    static void rejected(PrototypeRefusalCode code, Checked action) throws Exception {
        try { action.run(); throw new AssertionError("expected " + code); }
        catch (PrototypeRejected failure) { check(failure.refusal.code == code, "wrong refusal code"); }
    }
    static TypedPrototype typed(List<TypeRequirement> requirements) {
        return new TypedPrototype("int f(int value)", List.of(new ParameterText("value", "int")), "int", false, requirements);
    }
    static Map<String, TypeRequirement> replayRoots(String scenario, int index) {
        Map<String, TypeRequirement> roots = new TreeMap<>();
        if (scenario.equals("limit")) {
            if (index < 512) for (int n = 0; n < 8; n++) {
                String key = "/T" + (index * 8 + n);
                roots.put(key, new TypeRequirement(key, key, key.substring(1), "int"));
            } else {
                roots.put("/T0", new TypeRequirement("/T0", "/T0", "T0", "int"));
                if (index == 512) roots.put("/Overflow", new TypeRequirement("/Overflow", "/Overflow", "Overflow", "int"));
            }
        } else if (index == 0 || index >= 512) {
            String key = scenario.equals("collision") && index == 512 ? "/b/X" : "/a/X";
            roots.put(key, new TypeRequirement(key, key, "X", scenario.equals("definition") && index == 512 ? "long" : "int"));
        }
        return roots;
    }
    static String replayRecord(PlannedTypeCatalog catalog, String scenario, int index) throws Exception {
        Map<String, TypeRequirement> roots = replayRoots(scenario, index);
        Refusal refusal = null;
        try { catalog.admit(roots, () -> {}); }
        catch (PrototypeRejected rejected) { refusal = rejected.refusal; }
        PlannedTypeCoverage snapshot = new PlannedTypeCoverage(refusal == null ? roots : Map.of());
        TypedPrototype typed = typed(new ArrayList<>(roots.values()));
        Refusal coverage = checkCoverage(typed, snapshot);
        return "function=" + index + ";prototype=int f(int value);status=" + prototypeStatus(true, "body", refusal == null, coverage) +
            ";metadata=" + (refusal == null ? "complete" : refusal.detail) + ";coverage=" + (coverage == null ? "admitted" : coverage.detail);
    }
    static void catalogReplay() throws Exception {
        // Pure descriptor/status controls complement the authored public-API replay probe. No exporter runs.
        for (String scenario : List.of("collision", "definition", "limit")) {
            PlannedTypeCatalog original = new PlannedTypeCatalog();
            List<String> expected = new ArrayList<>();
            for (int index = 0; index < 514; index++) expected.add(replayRecord(original, scenario, index));
            check(expected.get(512).contains("status=partial") && expected.get(513).contains("status=recovered"), "bounded conflict and existing owner");
            for (int prefix : new int[]{0, 1, 511, 512, 513, 514}) for (boolean sparse : new boolean[]{false, true}) {
                PlannedTypeCatalog resumed = new PlannedTypeCatalog();
                List<String> actual = new ArrayList<>();
                for (int index = 0; index < 514; index++) {
                    boolean accepted = index < prefix && (!sparse || index % 3 != 1);
                    String replayed = replayRecord(resumed, scenario, index);
                    if (accepted) actual.add(expected.get(index)); else actual.add(replayed);
                    check(expected.get(index).equals(replayed), "replay admission independent of interruption");
                }
                check(expected.equals(actual) && original.definitions.keySet().equals(resumed.definitions.keySet()), "same full descriptor results and catalog");
                for (int start = 0; start < 514; start += 512) {
                    int end = Math.min(start + 512, 514);
                    var before = ExporterSemanticFingerprintOwnedV1.commitBatch(start, end, String.join("\n", expected.subList(start, end)), "", "", "");
                    var after = ExporterSemanticFingerprintOwnedV1.commitBatch(start, end, String.join("\n", actual.subList(start, end)), "", "", "");
                    ExporterSemanticFingerprintOwnedV1.requireBatchCommitment(before, after);
                }
            }
            // Negative control: skipping the replay recreates the original resume bug at batch 512.
            PlannedTypeCatalog missingPrefix = new PlannedTypeCatalog();
            check(!expected.get(512).equals(replayRecord(missingPrefix, scenario, 512)), "missing prefix must change the admitted result");
        }
    }
    static void enumBounds() throws Exception {
        String[] reverse = {"b", "a"};
        PrototypeBudget budget = new PrototypeBudget();
        check(Arrays.equals(boundedEnumNames(reverse, 2, 0, budget, () -> {}), new String[]{"a", "b"}), "sorted enum names");
        check(Arrays.equals(reverse, new String[]{"b", "a"}) && budget.bytes == 2 && budget.nodes == 2, "immutable input and single name charge");
        for (String value : new String[]{"a".repeat(4097), "é".repeat(2048) + "a"}) {
            int[] polls = {0};
            rejected(PrototypeRefusalCode.LIMIT, () -> boundedEnumNames(new String[]{"z", value}, 2, 0, new PrototypeBudget(), () -> polls[0]++));
            check(polls[0] == 3, "overlong input rejected before sort/copy phase");
        }
        rejected(PrototypeRefusalCode.NULL_TYPE, () -> boundedEnumNames(new String[]{"z", null}, 2, 0, new PrototypeBudget(), () -> {}));
        String[] exact = new String[16]; Arrays.fill(exact, "é".repeat(2048));
        PrototypeBudget total = new PrototypeBudget();
        boundedEnumNames(exact, 16, 0, total, () -> {});
        check(total.bytes == 65536, "enum exact multibyte total without duplicate name charge");
        String[] overflow = Arrays.copyOf(exact, 17); overflow[16] = "x";
        rejected(PrototypeRefusalCode.LIMIT, () -> boundedEnumNames(overflow, 17, 0, new PrototypeBudget(), () -> {}));
        String[] common = new String[128];
        for (int i = 0; i < common.length; i++) common[i] = "x".repeat(400) + (1000 - i);
        int[] polls = {0};
        try {
            boundedEnumNames(common, common.length, 0, new PrototypeBudget(), () -> {
                if (++polls[0] == common.length + 4) throw new InterruptedException("sort cancelled");
            });
            throw new AssertionError("sorting ignored cancellation");
        } catch (InterruptedException expected) { check(polls[0] == 132, "cancel during bounded comparisons"); }
        check(common[0].endsWith("1000"), "cancelled sort does not mutate input");
    }
    static void catalogBounds() throws Exception {
        PlannedTypeCatalog catalog = new PlannedTypeCatalog();
        for (int i = 0; i < 4096; i++) {
            TypeRequirement requirement = new TypeRequirement("/" + i, "id" + i, "T" + i, "d" + i);
            catalog.admit(Map.of(requirement.path, requirement), () -> {});
        }
        TypeRequirement first = catalog.definitions.get("/0");
        catalog.admit(Map.of(first.path, first), () -> {});
        check(catalog.definitions.size() == 4096, "exact catalog boundary permits repeat/replay");
        TypeRequirement extra = new TypeRequirement("/extra", "extra", "extra", "extra");
        rejected(PrototypeRefusalCode.LIMIT, () -> catalog.admit(Map.of(first.path, first, extra.path, extra), () -> {}));
        check(catalog.definitions.size() == 4096 && !catalog.spellings.containsKey("extra"), "overflow admission atomic");
        rejected(PrototypeRefusalCode.TYPE_MISMATCH, () -> catalog.admit(Map.of("/other", new TypeRequirement("/other", "other", "T0", "d")), () -> {}));
        rejected(PrototypeRefusalCode.TYPE_MISMATCH, () -> catalog.admit(Map.of("/0", new TypeRequirement("/0", "id0", "T0", "changed")), () -> {}));
        catalog.clear();
        try { catalog.admit(Map.of(first.path, first), () -> { throw new InterruptedException("cancel"); }); throw new AssertionError("catalog cancellation"); }
        catch (InterruptedException expected) { check(catalog.definitions.isEmpty(), "cancelled admission leaves no owner"); }
        for (String spelling : new String[]{"uint", "longlong", "ulong", "undefined8", "int128"})
            check(!supportedBuiltinSpelling(spelling), "unsupported builtin spelling " + spelling);
        for (String spelling : new String[]{"int", "char", "unsigned int", "long long", "double"})
            check(supportedBuiltinSpelling(spelling), "C language spelling " + spelling);
    }
    public static void run() throws Exception {
        enumBounds();
        catalogBounds();
        catalogReplay();
        new PrototypeBudget().parameters(256, false);
        new PrototypeBudget().parameters(0, false);
        new PrototypeBudget().parameters(1, true);
        rejected(PrototypeRefusalCode.LIMIT, () -> new PrototypeBudget().parameters(257, false));
        rejected(PrototypeRefusalCode.LIMIT, () -> new PrototypeBudget().parameters(-1, false));
        rejected(PrototypeRefusalCode.UNSUPPORTED_SHAPE, () -> new PrototypeBudget().parameters(0, true));
        new PrototypeBudget().node(32);
        rejected(PrototypeRefusalCode.LIMIT, () -> new PrototypeBudget().node(33));
        PrototypeBudget nodes = new PrototypeBudget();
        for (int i = 0; i < 4096; i++) nodes.node(0);
        rejected(PrototypeRefusalCode.LIMIT, () -> nodes.node(0));
        new PrototypeBudget().text("a".repeat(4096));
        new PrototypeBudget().text("é".repeat(2048));
        rejected(PrototypeRefusalCode.LIMIT, () -> new PrototypeBudget().text("a".repeat(4097)));
        rejected(PrototypeRefusalCode.LIMIT, () -> new PrototypeBudget().text("é".repeat(2048) + "a"));
        PrototypeBudget total = new PrototypeBudget();
        for (int i = 0; i < 16; i++) total.text("a".repeat(4096));
        check(total.bytes == 65536, "exact total");
        rejected(PrototypeRefusalCode.LIMIT, () -> total.text("a"));
        TypeRequirement first = new TypeRequirement("/A", "type_A", "A", "definition_A");
        TypeRequirement future = new TypeRequirement("/B", "type_B", "B", "definition_B");
        Map<String, TypeRequirement> mutable = new TreeMap<>(); mutable.put(first.path, first);
        PlannedTypeCoverage snapshot = new PlannedTypeCoverage(mutable);
        mutable.put(future.path, future);
        check(checkCoverage(typed(List.of(first)), snapshot) == null, "planned type accepted");
        check(checkCoverage(typed(List.of(future)), snapshot).code == PrototypeRefusalCode.UNPLANNED_TYPE, "future type absent from snapshot");
        check(checkCoverage(typed(List.of(new TypeRequirement("/A", "type_A", "A", "changed"))), snapshot).code == PrototypeRefusalCode.TYPE_MISMATCH, "same path changed definition");
        check(checkCoverage(typed(List.of(new TypeRequirement("/A", "type_bad", "A", "definition_A"))), snapshot).code == PrototypeRefusalCode.TYPE_MISMATCH, "path/id mismatch");
        check(checkCoverage(typed(List.of(new TypeRequirement("/A", "type_A", "other", "definition_A"))), snapshot).code == PrototypeRefusalCode.TYPE_MISMATCH, "spelling mismatch");
        mutable.put("/B", new TypeRequirement("/B", "type_B", "A", "other"));
        check(checkCoverage(typed(List.of(first)), new PlannedTypeCoverage(mutable)).code == PrototypeRefusalCode.TYPE_MISMATCH, "spelling collision");
        List<TypeRequirement> mutableRequirements = new ArrayList<>(List.of(future, first));
        List<ParameterText> mutableParameters = new ArrayList<>(List.of(new ParameterText("value", "int")));
        TypedPrototype immutable = new TypedPrototype("int f(int value)", mutableParameters, "int", false, mutableRequirements);
        mutableParameters.clear(); mutableRequirements.clear();
        check(immutable.parameters.size() == 1 && immutable.requirements.get(0) == first, "defensive sorted copies");
        try { immutable.parameters.clear(); throw new AssertionError("mutable parameters"); } catch (UnsupportedOperationException expected) { }
        try { snapshot.byPath.clear(); throw new AssertionError("mutable coverage"); } catch (UnsupportedOperationException expected) { }
        try { new PrototypeResult(null, null); throw new AssertionError("empty result"); } catch (IllegalArgumentException expected) { }
        Refusal refusal = new Refusal(PrototypeRefusalCode.NULL_TYPE, "MISSING_DATA_TYPE");
        try { new PrototypeResult(immutable, refusal); throw new AssertionError("ambiguous result"); } catch (IllegalArgumentException expected) { }
        check(new PrototypeResult(immutable, null).origin == PrototypeOrigin.HIGH_FUNCTION, "typed provenance");
        check(new PrototypeResult(null, refusal).origin == PrototypeOrigin.LISTING, "listing provenance");
        for (boolean complete : new boolean[]{false, true}) for (String source : new String[]{null, "body"}) {
            check(prototypeStatus(true, source, complete, refusal).equals(source == null ? "failed" : "partial"), "refusal is never recovered");
            check(prototypeStatus(true, source, complete, null).equals(source == null ? "failed" : complete ? "recovered" : "partial"), "typed status matrix");
            check(prototypeStatus(false, source, complete, null).equals(complete ? "partial" : "failed"), "planning status matrix");
        }
        for (String name : new String[]{"value", "param_1", "_named", "f9"}) check(validCName(name), "valid typed name " + name);
        for (String name : new String[]{"", "void", "struct", "x[]", "9x", "bad-name", "é"}) check(!validCName(name), "invalid typed name " + name);
        check(refusal.evidence().contains("prototypeSource=listing;prototypeRefusal=NULL_TYPE"), "stable fallback marker");
    }
""".trimIndent()
