package decompengine.oracle.behavior

import decompengine.oracle.core.OracleArtifactLimits
import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.OracleSchemas
import decompengine.oracle.core.StrictJsonLimits
import java.nio.charset.StandardCharsets
import java.nio.file.Path
import java.util.Base64
import java.util.Locale
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

/**
 * Kotlin/JVM authoring owner for the fixed LLVM behavior reference input plan v2.
 *
 * It accepts no prior corpus, report, matrix, sandbox, expected output, executable identity, ACP
 * receipt, parser, callback, or claimed digest. Literal case bytes live below as reviewed Kotlin
 * UTF-8 byte sources; base64, byte lengths, and SHA-256 values are always derived by Kotlin.
 */
object LlvmBehaviorReferenceInputPlanV2Generator {
    fun publish(outputPath: Path): LlvmBehaviorReferenceInputPlanV2 {
        val target = exactGeneratorOutputPath(outputPath)
        val bytes = renderReviewedReferenceInputPlanV2()
        try {
            val published = OracleArtifacts.publishAtomically(
                target,
                bytes,
                OracleArtifactLimits(GENERATED_INPUT_PLAN_MAXIMUM_BYTES),
            )
            if (published.size != bytes.size || published.sha256 != OracleArtifacts.sha256(bytes)) {
                generatorFail("published reference input plan differs from Kotlin-authored bytes")
            }
        } catch (failure: LlvmBehaviorReferenceInputPlanV2Exception) {
            throw failure
        } catch (failure: Exception) {
            generatorFail("cannot atomically publish the Kotlin-authored reference input plan", failure)
        }
        return LlvmBehaviorReferenceInputPlanV2Verifier.verify(target)
    }
}

object LlvmBehaviorReferenceInputPlanV2GeneratorCli {
    @JvmStatic
    fun main(arguments: Array<String>) {
        if (arguments.size != 1) {
            throw IllegalArgumentException("usage: <absolute-output-path>")
        }
        val verified = LlvmBehaviorReferenceInputPlanV2Generator.publish(Path.of(arguments.single()))
        println("${verified.planSha256}  ${verified.planId}")
    }
}

internal fun renderReviewedReferenceInputPlanV2(): ByteArray {
    val document = reviewedReferenceInputPlanDocument()
    OracleSchemas.validate(GENERATED_INPUT_PLAN_SCHEMA_NAME, document)
    val bytes = OracleJson.canonicalBytes(document, GENERATED_INPUT_PLAN_JSON_LIMITS)
    if (bytes.size != GENERATED_INPUT_PLAN_EXPECTED_BYTES ||
        OracleArtifacts.sha256(bytes) != GENERATED_INPUT_PLAN_EXPECTED_SHA256
    ) {
        generatorFail("Kotlin-authored reference input plan differs from its reviewed exact identity")
    }
    return bytes
}

private fun exactGeneratorOutputPath(path: Path): Path {
    if (!path.isAbsolute || path.normalize() != path || path.parent == null || path.fileName == null) {
        generatorFail("reference input plan output path must be exact, absolute, normalized, and name a file")
    }
    if (path.fileName.toString() != GENERATED_INPUT_PLAN_FILE_NAME) {
        generatorFail("reference input plan output must use the fixed file name $GENERATED_INPUT_PLAN_FILE_NAME")
    }
    val lower = path.toString().lowercase(Locale.ROOT)
    if (listOf(
            "python",
            "oci-container-v1",
            "behavior-preexec-v1",
            "acaa7b33c390b2c9fde15b4e21b0a899ffff62fe98ce22226866272b4efe8d5b",
            "510c510f300d811df22c7769633575a94939073b529a73125bf96cfb96dc7248",
            "e45381109c685311cf84c5e33a1aca7da81d6b55c0f9aed74091fc08c3a94f13",
            "5a1acc5f9935b186eec52fef608cf1e09bdb7477a88745d9daed8529b98f2e92",
        ).any(lower::contains)
    ) {
        generatorFail("reference input plan output path contains forbidden runtime material")
    }
    return path
}

private fun reviewedReferenceInputPlanDocument(): JsonObject {
    val cases = JsonArray(REVIEWED_CASES.map(::reviewedCaseDocument))
    val executionOrder = REVIEWED_CASES.map(ReviewedCaseSpec::id)
        .filterNot { it == "pch-reuse-valid" || it == "pch-reuse-wrong-target" }
        .flatMap { caseId ->
            if (caseId == "precompile-header") {
                listOf(caseId, "pch-reuse-valid", "pch-reuse-wrong-target")
            } else {
                listOf(caseId)
            }
        }
    return jsonObject(
        "schemaVersion" to JsonPrimitive(2),
        "kind" to JsonPrimitive("llvm-behavior-reference-input-plan-v2"),
        "authority" to JsonPrimitive("kotlin-jvm-authored-reference-input-plan-v2"),
        "id" to JsonPrimitive("clang-22-1-6-driver-behavior-reference-input-plan-v2"),
        "scope" to JsonPrimitive("production"),
        "acpBoundary" to jsonObject(
            "role" to JsonPrimitive("first-class-candidate-producer-operator"),
            "candidateContribution" to
                JsonPrimitive("authenticated-session-change-build-artifact-provenance"),
            "candidateProvenanceAccess" to JsonPrimitive("read-only-oracle-input"),
            "candidateAdmissionOwner" to JsonPrimitive("kotlin-jvm-host"),
            "candidateLiveExecutionOwner" to
                JsonPrimitive("separately-reviewed-kotlin-jvm-host"),
            "referenceSubjectAdmission" to JsonPrimitive("kotlin-jvm-host-only"),
            "oracleAuthority" to JsonPrimitive(false),
            "referenceAuthoringAuthority" to JsonPrimitive(false),
            "policyAuthoringAuthority" to JsonPrimitive(false),
            "validationAuthority" to JsonPrimitive(false),
            "observationAuthoringAuthority" to JsonPrimitive(false),
            "startAuthority" to JsonPrimitive(false),
            "containmentAuthority" to JsonPrimitive(false),
            "terminalAbsenceAuthority" to JsonPrimitive(false),
            "scoringAuthority" to JsonPrimitive(false),
            "certificationAuthority" to JsonPrimitive(false),
            "releaseAuthority" to JsonPrimitive(false),
        ),
        "environment" to jsonObject(
            "clearInherited" to JsonPrimitive(true),
            "variables" to jsonObject(
                "HOME" to JsonPrimitive("/nonexistent"),
                "LANG" to JsonPrimitive("C"),
                "LC_ALL" to JsonPrimitive("C"),
                "PATH" to JsonPrimitive("/usr/bin:/bin"),
                "SOURCE_DATE_EPOCH" to JsonPrimitive("1779182222"),
                "TMPDIR" to JsonPrimitive("/workspace/tmp"),
                "TZ" to JsonPrimitive("UTC"),
            ),
        ),
        "directories" to stringArray(listOf("include", "quoted", "system", "tmp")),
        "diagnosticPolicy" to jsonObject(
            "forbiddenNormalizations" to stringArray(
                listOf(
                    "diagnostic-wording",
                    "identifier",
                    "line-column",
                    "option-name",
                    "ordering",
                    "path",
                    "severity",
                ),
            ),
            "locale" to JsonPrimitive("C"),
            "mismatchIdentity" to JsonPrimitive("reference-definition-sha256-case-id-field-v2"),
            "pathRendering" to JsonPrimitive("raw-bytes-no-rewrite"),
            "terminalWidth" to JsonPrimitive("non-tty-no-width"),
        ),
        "captureContract" to jsonObject(
            "artifacts" to JsonPrimitive("complete-final-workspace-tree"),
            "exitStatus" to JsonPrimitive("raw-process-exit-status"),
            "normalizations" to JsonArray(emptyList()),
            "stderr" to JsonPrimitive("raw-bytes"),
            "stdout" to JsonPrimitive("raw-bytes"),
        ),
        "repetitionContract" to jsonObject(
            "agreement" to JsonPrimitive("canonical-observation-payload-byte-identical"),
            "count" to JsonPrimitive(3),
            "dependencyScope" to JsonPrimitive("same-repetition-only"),
            "freshNonce" to JsonPrimitive(true),
            "freshOperation" to JsonPrimitive(true),
            "freshResultsLease" to JsonPrimitive(true),
            "freshWorkspaceLease" to JsonPrimitive(true),
        ),
        "executionOrder" to stringArray(executionOrder),
        "cases" to cases,
        "claims" to jsonObject(
            "definitionBound" to JsonPrimitive(false),
            "expectedOutputsPresent" to JsonPrimitive(false),
            "referenceSubjectPinned" to JsonPrimitive(false),
            "observationsCaptured" to JsonPrimitive(false),
            "referenceTruthEstablished" to JsonPrimitive(false),
            "runtimePreflightVerified" to JsonPrimitive(false),
            "liveContainmentVerified" to JsonPrimitive(false),
            "terminalAbsenceVerified" to JsonPrimitive(false),
            "candidateStarted" to JsonPrimitive(false),
            "startAuthorized" to JsonPrimitive(false),
            "scoringAuthority" to JsonPrimitive(false),
            "certificationAuthority" to JsonPrimitive(false),
            "releaseEligible" to JsonPrimitive(false),
        ),
    )
}

private fun reviewedCaseDocument(case: ReviewedCaseSpec): JsonObject = jsonObject(
    "id" to JsonPrimitive(case.id),
    "ownerSubsystem" to JsonPrimitive(case.ownerSubsystem),
    "categories" to stringArray(case.categories),
    "arguments" to stringArray(case.arguments),
    "environment" to JsonObject(emptyMap()),
    "stdin" to blobDocument(case.stdin),
    "inputs" to JsonArray(case.inputs.map(::reviewedInputDocument)),
)

private fun reviewedInputDocument(input: ReviewedInputSpec): JsonObject = when (input) {
    is ReviewedLiteralInput -> jsonObject(
        "kind" to JsonPrimitive("literal"),
        "path" to JsonPrimitive(input.path),
        "base64" to JsonPrimitive(Base64.getEncoder().encodeToString(input.bytes)),
        "bytes" to JsonPrimitive(input.bytes.size),
        "sha256" to JsonPrimitive(OracleArtifacts.sha256(input.bytes)),
        "executable" to JsonPrimitive(input.executable),
    )
    is ReviewedFreshArtifactInput -> jsonObject(
        "kind" to JsonPrimitive("same-repetition-fresh-reference-artifact"),
        "producerCaseId" to JsonPrimitive(input.producerCaseId),
        "producerPath" to JsonPrimitive(input.producerPath),
        "targetPath" to JsonPrimitive(input.targetPath),
        "compatibilityInputPaths" to stringArray(input.compatibilityInputPaths),
        "producerArtifactType" to JsonPrimitive("regular-file"),
        "producerArtifactFreshness" to JsonPrimitive("same-repetition-produced-not-literal-input"),
    )
}

private fun blobDocument(bytes: ByteArray): JsonObject = jsonObject(
    "base64" to JsonPrimitive(Base64.getEncoder().encodeToString(bytes)),
    "bytes" to JsonPrimitive(bytes.size),
    "sha256" to JsonPrimitive(OracleArtifacts.sha256(bytes)),
)

private fun jsonObject(vararg fields: Pair<String, JsonElement>): JsonObject =
    JsonObject(linkedMapOf(*fields))

private fun stringArray(values: List<String>): JsonArray = JsonArray(values.map(::JsonPrimitive))

private fun utf8(value: String): ByteArray = value.toByteArray(StandardCharsets.UTF_8)

private fun generatorFail(message: String, cause: Throwable? = null): Nothing =
    throw LlvmBehaviorReferenceInputPlanV2Exception(message, cause)

private data class ReviewedCaseSpec(
    val id: String,
    val ownerSubsystem: String,
    val categories: List<String>,
    val arguments: List<String>,
    val stdin: ByteArray,
    val inputs: List<ReviewedInputSpec>,
)

private sealed interface ReviewedInputSpec

private class ReviewedLiteralInput(
    val path: String,
    bytes: ByteArray,
    val executable: Boolean,
) : ReviewedInputSpec {
    private val storedBytes = bytes.copyOf()
    val bytes: ByteArray
        get() = storedBytes.copyOf()
}

private data class ReviewedFreshArtifactInput(
    val producerCaseId: String,
    val producerPath: String,
    val targetPath: String,
    val compatibilityInputPaths: List<String>,
) : ReviewedInputSpec

private const val GENERATED_INPUT_PLAN_SCHEMA_NAME = "llvm-behavior-reference-input-plan-v2"
private const val GENERATED_INPUT_PLAN_FILE_NAME = "behavior-reference-input-plan-v2.json"
private const val GENERATED_INPUT_PLAN_MAXIMUM_BYTES = 1024 * 1024
private const val GENERATED_INPUT_PLAN_EXPECTED_BYTES = 46_787
private const val GENERATED_INPUT_PLAN_EXPECTED_SHA256 =
    "01424f3b14419b2da463c2c5aefbd89a81c03b11ac5847b750f79d72eb7e5d0d"
private val GENERATED_INPUT_PLAN_JSON_LIMITS = StrictJsonLimits(
    maximumInputBytes = GENERATED_INPUT_PLAN_MAXIMUM_BYTES,
    maximumCanonicalBytes = GENERATED_INPUT_PLAN_MAXIMUM_BYTES,
    maximumDepth = 32,
    maximumNodes = 20_000,
    maximumStringBytes = 256 * 1024,
    maximumTotalStringBytes = 768 * 1024,
    maximumNumberCharacters = 32,
)

private val REVIEWED_CASES = listOf(
    ReviewedCaseSpec(
        id = "assemble-invalid",
        ownerSubsystem = "clang-integrated-assembler",
        categories = listOf("assembler", "diagnostics", "exit-status", "stderr"),
        arguments = listOf("-c", "broken.s", "-o", "broken.o"),
        stdin = utf8(""),
        inputs = listOf(
            ReviewedLiteralInput(path = "broken.s", bytes = utf8(".text\nanswer:\n  definitely_not_an_instruction\n"), executable = false),
        ),
    ),
    ReviewedCaseSpec(
        id = "assemble-valid",
        ownerSubsystem = "clang-integrated-assembler",
        categories = listOf("artifacts", "assembler", "object-emission"),
        arguments = listOf("-c", "answer.s", "-o", "answer.o"),
        stdin = utf8(""),
        inputs = listOf(
            ReviewedLiteralInput(path = "answer.s", bytes = utf8(".text\n.globl answer\n.type answer,@function\nanswer:\n  mov \$42, %eax\n  ret\n"), executable = false),
        ),
    ),
    ReviewedCaseSpec(
        id = "compile-c-standard",
        ownerSubsystem = "clang-codegen",
        categories = listOf("artifacts", "c", "file-compile", "language-standard"),
        arguments = listOf("-nostdinc", "-std=c17", "-pedantic-errors", "-c", "source.c", "-o", "c17.o"),
        stdin = utf8(""),
        inputs = listOf(
            ReviewedLiteralInput(path = "source.c", bytes = utf8("int answer(void) { return 42; }\n"), executable = false),
        ),
    ),
    ReviewedCaseSpec(
        id = "compile-cxx-standard",
        ownerSubsystem = "clang-codegen",
        categories = listOf("artifacts", "cxx", "file-compile", "language-standard", "templates"),
        arguments = listOf("-nostdinc", "-std=c++20", "-c", "source.cpp", "-o", "cxx20.o"),
        stdin = utf8(""),
        inputs = listOf(
            ReviewedLiteralInput(path = "source.cpp", bytes = utf8("template <class T> T twice(T value) { return value + value; }\nint answer() { return twice(21); }\n"), executable = false),
        ),
    ),
    ReviewedCaseSpec(
        id = "compile-file",
        ownerSubsystem = "clang-codegen",
        categories = listOf("artifacts", "file-compile"),
        arguments = listOf("-c", "source.c", "-o", "source.o"),
        stdin = utf8(""),
        inputs = listOf(
            ReviewedLiteralInput(path = "source.c", bytes = utf8("int answer(void) { return 42; }\n"), executable = false),
        ),
    ),
    ReviewedCaseSpec(
        id = "compile-stdin",
        ownerSubsystem = "clang-codegen",
        categories = listOf("artifacts", "file-compile", "stdin"),
        arguments = listOf("-x", "c", "-c", "-", "-o", "stdin.o"),
        stdin = utf8("int answer(void) { return 42; }\n"),
        inputs = listOf(

        ),
    ),
    ReviewedCaseSpec(
        id = "diagnostic-color-always",
        ownerSubsystem = "clang-diagnostics-renderer",
        categories = listOf("color", "diagnostics", "exit-status", "stderr"),
        arguments = listOf("-fcolor-diagnostics", "-fsyntax-only", "broken.c"),
        stdin = utf8(""),
        inputs = listOf(
            ReviewedLiteralInput(path = "broken.c", bytes = utf8("int broken( {\n"), executable = false),
        ),
    ),
    ReviewedCaseSpec(
        id = "diagnostic-color-never",
        ownerSubsystem = "clang-diagnostics-renderer",
        categories = listOf("color", "diagnostics", "exit-status", "stderr"),
        arguments = listOf("-fno-color-diagnostics", "-fsyntax-only", "broken.c"),
        stdin = utf8(""),
        inputs = listOf(
            ReviewedLiteralInput(path = "broken.c", bytes = utf8("int broken( {\n"), executable = false),
        ),
    ),
    ReviewedCaseSpec(
        id = "diagnostic-error-limit",
        ownerSubsystem = "clang-diagnostics-engine",
        categories = listOf("diagnostic-limits", "diagnostics", "exit-status", "stderr"),
        arguments = listOf("-ferror-limit=2", "-fsyntax-only", "many.c"),
        stdin = utf8(""),
        inputs = listOf(
            ReviewedLiteralInput(path = "many.c", bytes = utf8("int a( {\nint b( {\nint c( {\n"), executable = false),
        ),
    ),
    ReviewedCaseSpec(
        id = "diagnostic-fixit",
        ownerSubsystem = "clang-parser",
        categories = listOf("caret-ranges", "diagnostics", "exit-status", "fix-its", "stderr"),
        arguments = listOf("-fdiagnostics-parseable-fixits", "-fsyntax-only", "fixit.c"),
        stdin = utf8(""),
        inputs = listOf(
            ReviewedLiteralInput(path = "fixit.c", bytes = utf8("int main(void) { int value = 1 return value; }\n"), executable = false),
        ),
    ),
    ReviewedCaseSpec(
        id = "diagnostic-invalid-option",
        ownerSubsystem = "clang-driver-options",
        categories = listOf("diagnostics", "exit-status", "option-handling", "stderr"),
        arguments = listOf("--definitely-not-a-clang-option"),
        stdin = utf8(""),
        inputs = listOf(

        ),
    ),
    ReviewedCaseSpec(
        id = "diagnostic-missing-include",
        ownerSubsystem = "clang-lex",
        categories = listOf("diagnostics", "fatal-errors", "include-search", "stderr"),
        arguments = listOf("-nostdinc", "-fsyntax-only", "missing.c"),
        stdin = utf8(""),
        inputs = listOf(
            ReviewedLiteralInput(path = "missing.c", bytes = utf8("#include \"absent.h\"\n"), executable = false),
        ),
    ),
    ReviewedCaseSpec(
        id = "diagnostic-syntax",
        ownerSubsystem = "clang-parser",
        categories = listOf("diagnostics", "exit-status", "stderr"),
        arguments = listOf("-fsyntax-only", "broken.c"),
        stdin = utf8(""),
        inputs = listOf(
            ReviewedLiteralInput(path = "broken.c", bytes = utf8("int broken( {\n"), executable = false),
        ),
    ),
    ReviewedCaseSpec(
        id = "diagnostic-template-backtrace",
        ownerSubsystem = "clang-sema",
        categories = listOf("cxx", "diagnostics", "notes", "stderr", "templates"),
        arguments = listOf("-nostdinc", "-std=c++20", "-fsyntax-only", "template.cpp"),
        stdin = utf8(""),
        inputs = listOf(
            ReviewedLiteralInput(path = "template.cpp", bytes = utf8("template<class T> int read(T value) { return value.missing; }\nint answer() { return read(42); }\n"), executable = false),
        ),
    ),
    ReviewedCaseSpec(
        id = "diagnostic-warning-option",
        ownerSubsystem = "clang-sema",
        categories = listOf("diagnostics", "option-provenance", "stderr", "warnings"),
        arguments = listOf("-nostdinc", "-Wall", "-Wextra", "-fsyntax-only", "warning.c"),
        stdin = utf8(""),
        inputs = listOf(
            ReviewedLiteralInput(path = "warning.c", bytes = utf8("int answer(int unused) { return 42; }\n"), executable = false),
        ),
    ),
    ReviewedCaseSpec(
        id = "driver-missing-linker",
        ownerSubsystem = "clang-driver-toolchain",
        categories = listOf("diagnostics", "exit-status", "linking", "missing-tools", "stderr"),
        arguments = listOf("-nostdlib", "-fuse-ld=definitely-missing", "source.c", "-o", "program"),
        stdin = utf8(""),
        inputs = listOf(
            ReviewedLiteralInput(path = "source.c", bytes = utf8("int answer(void) { return 42; }\n"), executable = false),
        ),
    ),
    ReviewedCaseSpec(
        id = "driver-print-commands",
        ownerSubsystem = "clang-driver",
        categories = listOf("assembler", "driver-orchestration", "linking", "stderr"),
        arguments = listOf("-###", "-save-temps=obj", "-nostdlib", "source.c", "-o", "program"),
        stdin = utf8(""),
        inputs = listOf(
            ReviewedLiteralInput(path = "source.c", bytes = utf8("int answer(void) { return 42; }\n"), executable = false),
        ),
    ),
    ReviewedCaseSpec(
        id = "emit-assembly",
        ownerSubsystem = "clang-codegen",
        categories = listOf("artifacts", "assembly-emission", "code-generation"),
        arguments = listOf("-nostdinc", "-S", "source.c", "-o", "source.s"),
        stdin = utf8(""),
        inputs = listOf(
            ReviewedLiteralInput(path = "source.c", bytes = utf8("int answer(void) { return 42; }\n"), executable = false),
        ),
    ),
    ReviewedCaseSpec(
        id = "emit-llvm-ir",
        ownerSubsystem = "clang-codegen",
        categories = listOf("artifacts", "code-generation", "llvm-ir"),
        arguments = listOf("-nostdinc", "-S", "-emit-llvm", "source.c", "-o", "source.ll"),
        stdin = utf8(""),
        inputs = listOf(
            ReviewedLiteralInput(path = "source.c", bytes = utf8("int answer(void) { return 42; }\n"), executable = false),
        ),
    ),
    ReviewedCaseSpec(
        id = "help-driver",
        ownerSubsystem = "clang-driver-options",
        categories = listOf("help", "option-handling", "stdout"),
        arguments = listOf("--help"),
        stdin = utf8(""),
        inputs = listOf(

        ),
    ),
    ReviewedCaseSpec(
        id = "include-cycle-guarded",
        ownerSubsystem = "clang-lex",
        categories = listOf("include-guards", "include-search", "preprocessing", "stdout"),
        arguments = listOf("-E", "-P", "-nostdinc", "-I", "include", "cycle.c"),
        stdin = utf8(""),
        inputs = listOf(
            ReviewedLiteralInput(path = "cycle.c", bytes = utf8("#include \"a.h\"\nint answer = A_VALUE + B_VALUE;\n"), executable = false),
            ReviewedLiteralInput(path = "include/a.h", bytes = utf8("#ifndef A_H\n#define A_H\n#include \"b.h\"\n#define A_VALUE 20\n#endif\n"), executable = false),
            ReviewedLiteralInput(path = "include/b.h", bytes = utf8("#ifndef B_H\n#define B_H\n#include \"a.h\"\n#define B_VALUE 22\n#endif\n"), executable = false),
        ),
    ),
    ReviewedCaseSpec(
        id = "include-framework-order",
        ownerSubsystem = "clang-header-search",
        categories = listOf("framework-includes", "include-search", "preprocessing", "stdout"),
        arguments = listOf("-E", "-P", "-nostdinc", "-F", "frameworks", "framework.c"),
        stdin = utf8(""),
        inputs = listOf(
            ReviewedLiteralInput(path = "framework.c", bytes = utf8("#include <Answer/answer.h>\nint answer = ANSWER;\n"), executable = false),
            ReviewedLiteralInput(path = "frameworks/Answer.framework/Headers/answer.h", bytes = utf8("#define ANSWER 42\n"), executable = false),
        ),
    ),
    ReviewedCaseSpec(
        id = "include-search-order",
        ownerSubsystem = "clang-header-search",
        categories = listOf("include-search", "preprocessing", "stdout"),
        arguments = listOf("-E", "-P", "-nostdinc", "-I", "quoted", "-isystem", "system", "source.c"),
        stdin = utf8(""),
        inputs = listOf(
            ReviewedLiteralInput(path = "quoted/value.h", bytes = utf8("int selected = 1;\n"), executable = false),
            ReviewedLiteralInput(path = "source.c", bytes = utf8("#include <value.h>\n"), executable = false),
            ReviewedLiteralInput(path = "system/value.h", bytes = utf8("int selected = 2;\n"), executable = false),
        ),
    ),
    ReviewedCaseSpec(
        id = "include-trace",
        ownerSubsystem = "clang-header-search",
        categories = listOf("include-search", "include-trace", "preprocessing", "stderr", "stdout"),
        arguments = listOf("-E", "-P", "-H", "-nostdinc", "-I", "include", "source.c"),
        stdin = utf8(""),
        inputs = listOf(
            ReviewedLiteralInput(path = "include/answer.h", bytes = utf8("#define ANSWER 42\n"), executable = false),
            ReviewedLiteralInput(path = "source.c", bytes = utf8("#include \"answer.h\"\nint answer = ANSWER;\n"), executable = false),
        ),
    ),
    ReviewedCaseSpec(
        id = "link-program",
        ownerSubsystem = "clang-driver-linker",
        categories = listOf("artifacts", "linking", "produced-program"),
        arguments = listOf("-nostdlib", "-Wl,--build-id=none", "-Wl,-e,answer", "source.c", "-o", "program"),
        stdin = utf8(""),
        inputs = listOf(
            ReviewedLiteralInput(path = "source.c", bytes = utf8("int answer(void) { return 42; }\n"), executable = false),
        ),
    ),
    ReviewedCaseSpec(
        id = "link-undefined-symbol",
        ownerSubsystem = "clang-driver-linker",
        categories = listOf("diagnostics", "exit-status", "linking", "stderr"),
        arguments = listOf("-save-temps=obj", "-nostdlib", "-Wl,--build-id=none", "undefined.c", "-o", "program"),
        stdin = utf8(""),
        inputs = listOf(
            ReviewedLiteralInput(path = "undefined.c", bytes = utf8("extern int missing(void); int _start(void) { return missing(); }\n"), executable = false),
        ),
    ),
    ReviewedCaseSpec(
        id = "metadata-resource-dir",
        ownerSubsystem = "clang-driver-toolchain",
        categories = listOf("metadata", "resource-directory", "stdout"),
        arguments = listOf("-print-resource-dir"),
        stdin = utf8(""),
        inputs = listOf(

        ),
    ),
    ReviewedCaseSpec(
        id = "metadata-target",
        ownerSubsystem = "clang-driver-targets",
        categories = listOf("metadata", "stdout", "target-query"),
        arguments = listOf("-dumpmachine"),
        stdin = utf8(""),
        inputs = listOf(

        ),
    ),
    ReviewedCaseSpec(
        id = "metadata-version",
        ownerSubsystem = "clang-driver",
        categories = listOf("metadata", "stdout"),
        arguments = listOf("--version"),
        stdin = utf8(""),
        inputs = listOf(

        ),
    ),
    ReviewedCaseSpec(
        id = "modules-flag-supported",
        ownerSubsystem = "clang-driver-options",
        categories = listOf("cxx", "modules", "syntax-only"),
        arguments = listOf("-nostdinc", "-std=c++20", "-fmodules", "-fsyntax-only", "source.cpp"),
        stdin = utf8(""),
        inputs = listOf(
            ReviewedLiteralInput(path = "source.cpp", bytes = utf8("template <class T> T twice(T value) { return value + value; }\nint answer() { return twice(21); }\n"), executable = false),
        ),
    ),
    ReviewedCaseSpec(
        id = "objective-c-syntax",
        ownerSubsystem = "clang-parser",
        categories = listOf("objective-c", "syntax-only"),
        arguments = listOf("-nostdinc", "-x", "objective-c", "-fsyntax-only", "source.m"),
        stdin = utf8(""),
        inputs = listOf(
            ReviewedLiteralInput(path = "source.m", bytes = utf8("@interface Box\n- (int)value;\n@end\n@implementation Box\n- (int)value { return 42; }\n@end\n"), executable = false),
        ),
    ),
    ReviewedCaseSpec(
        id = "pch-reuse-valid",
        ownerSubsystem = "clang-serialization",
        categories = listOf("artifacts", "cache-reuse", "pch", "preprocessing-state"),
        arguments = listOf("-nostdinc", "-include-pch", "answer.pch", "-c", "pch-user.c", "-o", "pch-user.o"),
        stdin = utf8(""),
        inputs = listOf(
            ReviewedLiteralInput(path = "answer.h", bytes = utf8("#ifndef ANSWER_H\n#define ANSWER_H\n#define ANSWER 42\n#endif\n"), executable = false),
            ReviewedFreshArtifactInput(producerCaseId = "precompile-header", producerPath = "answer.pch", targetPath = "answer.pch", compatibilityInputPaths = listOf("answer.h")),
            ReviewedLiteralInput(path = "pch-user.c", bytes = utf8("int answer(void) { return ANSWER; }\n"), executable = false),
        ),
    ),
    ReviewedCaseSpec(
        id = "pch-reuse-wrong-target",
        ownerSubsystem = "clang-serialization",
        categories = listOf("cache-invalidation", "diagnostics", "exit-status", "pch", "preprocessing-state", "target-selection"),
        arguments = listOf("--target=i386-unknown-linux-gnu", "-nostdinc", "-include-pch", "answer.pch", "-c", "pch-user.c", "-o", "pch-user.o"),
        stdin = utf8(""),
        inputs = listOf(
            ReviewedLiteralInput(path = "answer.h", bytes = utf8("#ifndef ANSWER_H\n#define ANSWER_H\n#define ANSWER 42\n#endif\n"), executable = false),
            ReviewedFreshArtifactInput(producerCaseId = "precompile-header", producerPath = "answer.pch", targetPath = "answer.pch", compatibilityInputPaths = listOf("answer.h")),
            ReviewedLiteralInput(path = "pch-user.c", bytes = utf8("int answer(void) { return ANSWER; }\n"), executable = false),
        ),
    ),
    ReviewedCaseSpec(
        id = "precompile-header",
        ownerSubsystem = "clang-serialization",
        categories = listOf("artifacts", "pch", "preprocessing-state"),
        arguments = listOf("-nostdinc", "-x", "c-header", "-Xclang", "-fno-pch-timestamp", "answer.h", "-o", "answer.pch"),
        stdin = utf8(""),
        inputs = listOf(
            ReviewedLiteralInput(path = "answer.h", bytes = utf8("#ifndef ANSWER_H\n#define ANSWER_H\n#define ANSWER 42\n#endif\n"), executable = false),
        ),
    ),
    ReviewedCaseSpec(
        id = "preprocess-dependencies",
        ownerSubsystem = "clang-dependency-scanning",
        categories = listOf("artifacts", "dependency-output", "preprocessing"),
        arguments = listOf("-nostdinc", "-I", "include", "-MMD", "-MF", "source.d", "-c", "source.c", "-o", "source.o"),
        stdin = utf8(""),
        inputs = listOf(
            ReviewedLiteralInput(path = "include/answer.h", bytes = utf8("#define ANSWER 42\n"), executable = false),
            ReviewedLiteralInput(path = "source.c", bytes = utf8("#include \"answer.h\"\nint answer(void) { return ANSWER; }\n"), executable = false),
        ),
    ),
    ReviewedCaseSpec(
        id = "preprocess-file",
        ownerSubsystem = "clang-lex",
        categories = listOf("preprocessing", "stdout"),
        arguments = listOf("-E", "-P", "source.c"),
        stdin = utf8(""),
        inputs = listOf(
            ReviewedLiteralInput(path = "source.c", bytes = utf8("int answer(void) { return 42; }\n"), executable = false),
        ),
    ),
    ReviewedCaseSpec(
        id = "preprocess-macro-state",
        ownerSubsystem = "clang-lex",
        categories = listOf("macros", "preprocessing", "stdout"),
        arguments = listOf("-E", "-P", "-nostdinc", "-D", "COMMAND=6", "macro.c"),
        stdin = utf8(""),
        inputs = listOf(
            ReviewedLiteralInput(path = "macro.c", bytes = utf8("#define JOIN_(a,b) a##b\n#define JOIN(a,b) JOIN_(a,b)\n#define STRING_(x) #x\n#define STRING(x) STRING_(x)\n#define SUM(first, ...) first + __VA_ARGS__\n#if COMMAND == 6\nint JOIN(ans,wer) = SUM(COMMAND, 36);\nconst char *name = STRING(answer);\n#endif\n"), executable = false),
        ),
    ),
    ReviewedCaseSpec(
        id = "preprocess-malformed-macro",
        ownerSubsystem = "clang-lex",
        categories = listOf("diagnostics", "exit-status", "macros", "preprocessing", "stderr"),
        arguments = listOf("-E", "-P", "-nostdinc", "malformed.c"),
        stdin = utf8(""),
        inputs = listOf(
            ReviewedLiteralInput(path = "malformed.c", bytes = utf8("#define BROKEN(value value\nBROKEN(42)\n"), executable = false),
        ),
    ),
    ReviewedCaseSpec(
        id = "preprocess-pragma-once",
        ownerSubsystem = "clang-lex",
        categories = listOf("include-search", "pragma", "preprocessing", "stdout"),
        arguments = listOf("-E", "-P", "-nostdinc", "-I", "include", "pragma.c"),
        stdin = utf8(""),
        inputs = listOf(
            ReviewedLiteralInput(path = "include/once.h", bytes = utf8("#pragma once\nint once_only = 42;\n"), executable = false),
            ReviewedLiteralInput(path = "pragma.c", bytes = utf8("#include \"once.h\"\n#include \"once.h\"\n"), executable = false),
        ),
    ),
    ReviewedCaseSpec(
        id = "preprocess-stdin",
        ownerSubsystem = "clang-lex",
        categories = listOf("preprocessing", "stdin", "stdout"),
        arguments = listOf("-E", "-P", "-x", "c", "-"),
        stdin = utf8("int answer(void) { return 42; }\n"),
        inputs = listOf(

        ),
    ),
    ReviewedCaseSpec(
        id = "response-file",
        ownerSubsystem = "clang-driver-response-files",
        categories = listOf("artifacts", "option-handling", "response-files"),
        arguments = listOf("@compile.rsp"),
        stdin = utf8(""),
        inputs = listOf(
            ReviewedLiteralInput(path = "compile.rsp", bytes = utf8("-c response.c -o response.o\n"), executable = false),
            ReviewedLiteralInput(path = "response.c", bytes = utf8("int answer(void) { return 42; }\n"), executable = false),
        ),
    ),
    ReviewedCaseSpec(
        id = "response-file-nested",
        ownerSubsystem = "clang-driver-response-files",
        categories = listOf("artifacts", "option-handling", "response-files"),
        arguments = listOf("@outer.rsp"),
        stdin = utf8(""),
        inputs = listOf(
            ReviewedLiteralInput(path = "inner.rsp", bytes = utf8("-nostdinc -std=c17 -c response.c -o nested.o\n"), executable = false),
            ReviewedLiteralInput(path = "outer.rsp", bytes = utf8("@inner.rsp\n"), executable = false),
            ReviewedLiteralInput(path = "response.c", bytes = utf8("int answer(void) { return 42; }\n"), executable = false),
        ),
    ),
    ReviewedCaseSpec(
        id = "response-file-quoted-paths",
        ownerSubsystem = "clang-driver-response-files",
        categories = listOf("artifacts", "option-handling", "quoted-arguments", "response-files"),
        arguments = listOf("@quoted.rsp"),
        stdin = utf8(""),
        inputs = listOf(
            ReviewedLiteralInput(path = "quoted.rsp", bytes = utf8("-nostdinc -c \"response source.c\" -o \"quoted response.o\"\n"), executable = false),
            ReviewedLiteralInput(path = "response source.c", bytes = utf8("int answer(void) { return 42; }\n"), executable = false),
        ),
    ),
    ReviewedCaseSpec(
        id = "response-file-recursion",
        ownerSubsystem = "clang-driver-response-files",
        categories = listOf("diagnostics", "exit-status", "response-files", "stderr"),
        arguments = listOf("@recursive.rsp"),
        stdin = utf8(""),
        inputs = listOf(
            ReviewedLiteralInput(path = "recursive.rsp", bytes = utf8("@recursive.rsp\n"), executable = false),
        ),
    ),
    ReviewedCaseSpec(
        id = "response-file-stdin",
        ownerSubsystem = "clang-driver-response-files",
        categories = listOf("artifacts", "option-handling", "response-files", "stdin"),
        arguments = listOf("@stdin.rsp"),
        stdin = utf8("int answer(void) { return 42; }\n"),
        inputs = listOf(
            ReviewedLiteralInput(path = "stdin.rsp", bytes = utf8("-nostdinc -x c -c - -o response-stdin.o\n"), executable = false),
        ),
    ),
    ReviewedCaseSpec(
        id = "target-i386-object",
        ownerSubsystem = "clang-driver-targets",
        categories = listOf("artifacts", "object-emission", "target-i386", "target-selection"),
        arguments = listOf("--target=i386-unknown-linux-gnu", "-nostdinc", "-c", "source.c", "-o", "i386.o"),
        stdin = utf8(""),
        inputs = listOf(
            ReviewedLiteralInput(path = "source.c", bytes = utf8("int answer(void) { return 42; }\n"), executable = false),
        ),
    ),
    ReviewedCaseSpec(
        id = "target-unsupported-aarch64",
        ownerSubsystem = "clang-driver-targets",
        categories = listOf("diagnostics", "exit-status", "target-selection", "unsupported-mode"),
        arguments = listOf("--target=aarch64-unknown-linux-gnu", "-nostdinc", "-c", "source.c", "-o", "aarch64.o"),
        stdin = utf8(""),
        inputs = listOf(
            ReviewedLiteralInput(path = "source.c", bytes = utf8("int answer(void) { return 42; }\n"), executable = false),
        ),
    ),
    ReviewedCaseSpec(
        id = "target-x86-macros",
        ownerSubsystem = "clang-driver-targets",
        categories = listOf("preprocessing", "stdout", "target-selection", "target-x86-64"),
        arguments = listOf("--target=x86_64-unknown-linux-gnu", "-nostdinc", "-dM", "-E", "-x", "c", "/dev/null"),
        stdin = utf8(""),
        inputs = listOf(

        ),
    ),
)
