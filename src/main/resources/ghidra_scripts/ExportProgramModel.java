// Streams a deterministic, address-keyed whole-program model through durable per-function records.
// @category llm_bin_patch

import java.io.BufferedOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.security.DigestInputStream;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;
import java.util.UUID;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.Composite;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Enum;
import ghidra.program.model.data.TypeDef;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.Symbol;

public class ExportProgramModel extends GhidraScript {
    private static final int EXPORTER_VERSION = 2;
    private static final int DECOMPILE_TIMEOUT_SECONDS = 60;

    private static final class GlobalEvidence {
        final String id, name, type, initializer;
        final Address address;

        GlobalEvidence(String id, String name, Address address, String type, String initializer) {
            this.id = id;
            this.name = name;
            this.address = address;
            this.type = type;
            this.initializer = initializer;
        }
    }

    private static final class TypeEvidence {
        final String id, declaration;
        final Address sourceAddress;

        TypeEvidence(String id, String declaration, Address sourceAddress) {
            this.id = id;
            this.declaration = declaration;
            this.sourceAddress = sourceAddress;
        }
    }

    private static final class FunctionExport {
        final String record, status, failure;

        FunctionExport(String record, String status, String failure) {
            this.record = record;
            this.status = status;
            this.failure = failure;
        }
    }

    private static String json(String value) {
        if (value == null) return "null";
        StringBuilder out = new StringBuilder("\"");
        for (char c : value.toCharArray()) {
            switch (c) {
                case '\\': out.append("\\\\"); break;
                case '"': out.append("\\\""); break;
                case '\n': out.append("\\n"); break;
                case '\r': out.append("\\r"); break;
                case '\t': out.append("\\t"); break;
                default: if (c < 0x20) out.append(String.format("\\u%04x", (int)c)); else out.append(c);
            }
        }
        return out.append('"').toString();
    }

    private static String functionId(Function function) {
        return String.format("fn_%016x", function.getEntryPoint().getOffset());
    }

    private static String globalId(Address address) {
        return String.format("global_%016x", address.getOffset());
    }

    private static String sha256(Path path) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        try (InputStream input = new DigestInputStream(Files.newInputStream(path), digest)) {
            byte[] buffer = new byte[64 * 1024];
            while (input.read(buffer) >= 0) {
                // DigestInputStream updates the digest while bytes are consumed.
            }
        }
        StringBuilder result = new StringBuilder();
        for (byte value : digest.digest()) result.append(String.format("%02x", value & 0xff));
        return result.toString();
    }

    private static void appendStrings(StringBuilder output, Iterable<String> values) {
        boolean first = true;
        for (String value : values) {
            if (!first) output.append(", ");
            output.append(json(value));
            first = false;
        }
    }

    private static String appendFailure(String existing, String next) {
        if (next == null || next.trim().isEmpty()) return existing;
        String bounded = next.replace('\n', ' ').replace('\r', ' ').trim();
        if (bounded.length() > 2048) bounded = bounded.substring(0, 2048) + "...";
        return existing == null ? bounded : existing + "; " + bounded;
    }

    private static String exceptionMessage(String phase, Exception failure) {
        String message = failure.getMessage();
        return phase + " failed: " + failure.getClass().getSimpleName() +
            (message == null || message.trim().isEmpty() ? "" : ": " + message);
    }

    private void rethrowInfrastructureFailure(Exception failure) throws Exception {
        if (monitor.isCancelled() || failure instanceof IOException) throw failure;
    }

    private void retainType(Path typesDirectory, DataType type, Address sourceAddress) throws Exception {
        if (!(type instanceof Composite) && !(type instanceof Enum) && !(type instanceof TypeDef)) return;
        String key = type.getPathName();
        String id = String.format("type_%08x", key.hashCode());
        int length = Math.max(type.getLength(), 1);
        String cName = type.getName().replaceAll("[^A-Za-z0-9_]", "_");
        if (cName.isEmpty() || Character.isDigit(cName.charAt(0))) cName = "recovered_" + id;
        String prefix = "/* Ghidra type " + key.replace("*/", "* /") + " */ ";
        String declaration;
        if (type instanceof Composite) {
            declaration = prefix + "typedef struct " + cName + " { unsigned char _data[" + length + "]; } " + cName + ";";
        } else if (type instanceof Enum) {
            declaration = prefix + "typedef int " + cName + ";";
        } else {
            declaration = prefix + "typedef unsigned char " + cName + "[" + length + "];";
        }
        TypeEvidence evidence = new TypeEvidence(id, declaration, sourceAddress);
        writeIfAbsentAtomic(typesDirectory.resolve(id + ".json"), renderType(evidence));
    }

    private GlobalEvidence globalAt(Address address) {
        Data data = currentProgram.getListing().getDataContaining(address);
        Address base = data == null ? address : data.getAddress();
        Symbol symbol = currentProgram.getSymbolTable().getPrimarySymbol(base);
        String name = symbol == null ? "DAT_" + base.toString() : symbol.getName();
        String type = data == null ? "unsigned char" : data.getDataType().getDisplayName();
        String initializer = data == null ? null : data.getDefaultValueRepresentation();
        return new GlobalEvidence(globalId(base), name, base, type, initializer);
    }

    private FunctionExport exportFunction(
        Function function,
        DecompInterface decompiler,
        Path globalsDirectory,
        Path typesDirectory
    ) throws Exception {
        Set<String> callIds = new TreeSet<>();
        Set<String> referencedGlobals = new TreeSet<>();
        Set<String> strings = new TreeSet<>();
        String failure = null;
        boolean evidenceComplete = true;

        try {
            for (Function target : function.getCalledFunctions(monitor)) {
                if (!target.isExternal()) callIds.add(functionId(target));
            }
        } catch (Exception problem) {
            rethrowInfrastructureFailure(problem);
            evidenceComplete = false;
            failure = appendFailure(failure, exceptionMessage("call recovery", problem));
        }

        try {
            InstructionIterator instructions = currentProgram.getListing().getInstructions(function.getBody(), true);
            while (instructions.hasNext()) {
                Instruction instruction = instructions.next();
                for (Reference reference : instruction.getReferencesFrom()) {
                    Address target = reference.getToAddress();
                    if (!target.isMemoryAddress()) continue;
                    Data data = currentProgram.getListing().getDataContaining(target);
                    if (data != null && data.hasStringValue() && data.getValue() != null) {
                        strings.add(data.getValue().toString());
                        continue;
                    }
                    if (reference.getReferenceType().isData() && currentProgram.getFunctionManager().getFunctionContaining(target) == null) {
                        GlobalEvidence global = globalAt(target);
                        writeIfAbsentAtomic(globalsDirectory.resolve(global.id + ".json"), renderGlobal(global));
                        referencedGlobals.add(global.id);
                        if (data != null) retainType(typesDirectory, data.getDataType(), global.address);
                    }
                }
            }
        } catch (Exception problem) {
            rethrowInfrastructureFailure(problem);
            evidenceComplete = false;
            failure = appendFailure(failure, exceptionMessage("data-reference recovery", problem));
        }

        try {
            retainType(typesDirectory, function.getReturnType(), function.getEntryPoint());
            for (Parameter parameter : function.getParameters()) {
                retainType(typesDirectory, parameter.getDataType(), function.getEntryPoint());
            }
        } catch (Exception problem) {
            rethrowInfrastructureFailure(problem);
            evidenceComplete = false;
            failure = appendFailure(failure, exceptionMessage("type recovery", problem));
        }

        String source = null;
        try {
            DecompileResults result = decompiler.decompileFunction(function, DECOMPILE_TIMEOUT_SECONDS, monitor);
            if (result.decompileCompleted() && result.getDecompiledFunction() != null) {
                source = result.getDecompiledFunction().getC();
            } else {
                String detail = result.getErrorMessage();
                failure = appendFailure(
                    failure,
                    "decompilation failed or timed out" +
                        (detail == null || detail.trim().isEmpty() ? "" : ": " + detail)
                );
            }
        } catch (Exception problem) {
            rethrowInfrastructureFailure(problem);
            failure = appendFailure(failure, exceptionMessage("decompilation", problem));
        }

        String status = source == null ? "failed" : (evidenceComplete ? "recovered" : "partial");
        StringBuilder output = new StringBuilder();
        output.append("    {\n");
        output.append("      \"id\": ").append(json(functionId(function))).append(",\n");
        output.append("      \"name\": ").append(json(function.getName())).append(",\n");
        output.append("      \"address\": ").append(json(String.format("0x%x", function.getEntryPoint().getOffset()))).append(",\n");
        output.append("      \"prototype\": ").append(json(function.getPrototypeString(false, false))).append(",\n");
        output.append("      \"status\": ").append(json(status)).append(",\n");
        output.append("      \"calls\": ["); appendStrings(output, callIds); output.append("],\n");
        output.append("      \"referencedGlobals\": ["); appendStrings(output, referencedGlobals); output.append("],\n");
        output.append("      \"strings\": ["); appendStrings(output, strings); output.append("],\n");
        output.append("      \"decompiledC\": ").append(json(source)).append("\n");
        output.append("    }");
        return new FunctionExport(output.toString(), status, failure);
    }

    private static String renderGlobal(GlobalEvidence global) {
        return "    {\n" +
            "      \"id\": " + json(global.id) + ",\n" +
            "      \"name\": " + json(global.name) + ",\n" +
            "      \"address\": " + json(String.format("0x%x", global.address.getOffset())) + ",\n" +
            "      \"type\": " + json(global.type) + ",\n" +
            "      \"initializer\": " + json(global.initializer) + ",\n" +
            "      \"status\": \"recovered\"\n" +
            "    }";
    }

    private static String renderType(TypeEvidence type) {
        return "    {\n" +
            "      \"id\": " + json(type.id) + ",\n" +
            "      \"declaration\": " + json(type.declaration) + ",\n" +
            "      \"sourceAddress\": " + json(String.format("0x%x", type.sourceAddress.getOffset())) + ",\n" +
            "      \"status\": \"partial\"\n" +
            "    }";
    }

    private static boolean isAcceptedRecord(Path record) throws IOException {
        return Files.isRegularFile(record) && Files.size(record) > 0;
    }

    private static void writeIfAbsentAtomic(Path target, String content) throws IOException {
        if (Files.isRegularFile(target)) return;
        Files.createDirectories(target.getParent());
        Path temporary = target.resolveSibling("." + target.getFileName() + "." + UUID.randomUUID() + ".tmp");
        try {
            writeAndForce(temporary, content);
            try {
                Files.move(temporary, target, StandardCopyOption.ATOMIC_MOVE);
            } catch (AtomicMoveNotSupportedException unsupported) {
                Files.move(temporary, target);
            }
            forceDirectory(target.getParent());
        } catch (FileAlreadyExistsException raced) {
            Files.deleteIfExists(temporary);
        } finally {
            Files.deleteIfExists(temporary);
        }
    }

    private static void writeAtomic(Path target, String content) throws IOException {
        Files.createDirectories(target.getParent());
        Path temporary = target.resolveSibling("." + target.getFileName() + "." + UUID.randomUUID() + ".tmp");
        try {
            writeAndForce(temporary, content);
            try {
                Files.move(temporary, target, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
            } catch (AtomicMoveNotSupportedException unsupported) {
                Files.move(temporary, target, StandardCopyOption.REPLACE_EXISTING);
            }
            forceDirectory(target.getParent());
        } finally {
            Files.deleteIfExists(temporary);
        }
    }

    private static void writeAndForce(Path path, String content) throws IOException {
        Files.write(path, content.getBytes(StandardCharsets.UTF_8), StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE);
        try (FileChannel channel = FileChannel.open(path, StandardOpenOption.WRITE)) {
            channel.force(true);
        }
    }

    private static void forceDirectory(Path directory) {
        try (FileChannel channel = FileChannel.open(directory, StandardOpenOption.READ)) {
            channel.force(true);
        } catch (Exception unsupported) {
            // Atomic rename plus file fsync remains the portable baseline when directory fsync is unavailable.
        }
    }

    private static List<Path> sortedRecords(Path directory) throws IOException {
        List<Path> records = new ArrayList<>();
        try (java.util.stream.Stream<Path> paths = Files.list(directory)) {
            paths.filter(path -> Files.isRegularFile(path) && path.getFileName().toString().endsWith(".json"))
                .forEach(records::add);
        }
        records.sort(Comparator.comparing(path -> path.getFileName().toString()));
        return records;
    }

    private static void writeUtf8(OutputStream output, String text) throws IOException {
        output.write(text.getBytes(StandardCharsets.UTF_8));
    }

    private static void appendRecordArray(OutputStream output, List<Path> records) throws IOException {
        for (int index = 0; index < records.size(); index++) {
            Files.copy(records.get(index), output);
            writeUtf8(output, index + 1 == records.size() ? "\n" : ",\n");
        }
    }

    private static void assembleModel(
        Path outputPath,
        String inputSha256,
        List<String> functionIds,
        Path functionsDirectory,
        Path globalsDirectory,
        Path typesDirectory
    ) throws Exception {
        List<Path> functions = new ArrayList<>();
        for (String id : functionIds) {
            Path record = functionsDirectory.resolve(id + ".json");
            if (!isAcceptedRecord(record)) throw new IllegalStateException("missing durable function record: " + id);
            functions.add(record);
        }
        List<Path> globals = sortedRecords(globalsDirectory);
        List<Path> types = sortedRecords(typesDirectory);
        Files.createDirectories(outputPath.getParent());
        Path temporary = outputPath.resolveSibling("." + outputPath.getFileName() + "." + UUID.randomUUID() + ".tmp");
        try {
            try (OutputStream output = new BufferedOutputStream(
                Files.newOutputStream(temporary, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE)
            )) {
                writeUtf8(output, "{\n  \"schemaVersion\": 1,\n  \"inputSha256\": " + json(inputSha256) + ",\n  \"functions\": [\n");
                appendRecordArray(output, functions);
                writeUtf8(output, "  ],\n  \"globals\": [\n");
                appendRecordArray(output, globals);
                writeUtf8(output, "  ],\n  \"types\": [\n");
                appendRecordArray(output, types);
                writeUtf8(output, "  ]\n}\n");
            }
            try (FileChannel channel = FileChannel.open(temporary, StandardOpenOption.WRITE)) {
                channel.force(true);
            }
            try {
                Files.move(temporary, outputPath, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
            } catch (AtomicMoveNotSupportedException unsupported) {
                Files.move(temporary, outputPath, StandardCopyOption.REPLACE_EXISTING);
            }
            forceDirectory(outputPath.getParent());
        } finally {
            Files.deleteIfExists(temporary);
        }
    }

    private static void writeProgress(
        Path progressPath,
        String phase,
        int completed,
        int total,
        int recovered,
        int partial,
        int failed,
        int reused,
        String currentFunction
    ) throws IOException {
        writeAtomic(
            progressPath,
            "{\"schemaVersion\":1,\"phase\":" + json(phase) +
                ",\"completed\":" + completed +
                ",\"total\":" + total +
                ",\"recovered\":" + recovered +
                ",\"partial\":" + partial +
                ",\"failed\":" + failed +
                ",\"reused\":" + reused +
                ",\"currentFunction\":" + json(currentFunction) + "}\n"
        );
    }

    private static int countExportableFunctions(FunctionIterator iterator) {
        int total = 0;
        while (iterator.hasNext()) {
            Function function = iterator.next();
            if (!function.isExternal() && !function.isThunk()) total++;
        }
        return total;
    }

    @Override
    protected void run() throws Exception {
        String[] arguments = getScriptArgs();
        if (arguments.length != 1) throw new IllegalArgumentException("expected output path");
        Path outputPath = Paths.get(arguments[0]).toAbsolutePath().normalize();
        Path stateDirectory = outputPath.resolveSibling(outputPath.getFileName() + ".export");
        Path functionsDirectory = stateDirectory.resolve("functions");
        Path globalsDirectory = stateDirectory.resolve("globals");
        Path typesDirectory = stateDirectory.resolve("types");
        Path failuresDirectory = stateDirectory.resolve("failures");
        Path progressPath = outputPath.resolveSibling(outputPath.getFileName() + ".progress.json");
        Files.createDirectories(functionsDirectory);
        Files.createDirectories(globalsDirectory);
        Files.createDirectories(typesDirectory);
        Files.createDirectories(failuresDirectory);

        Path executablePath = Paths.get(currentProgram.getExecutablePath());
        String inputSha256 = sha256(executablePath);
        String state = "{\"schemaVersion\":1,\"exporterVersion\":" + EXPORTER_VERSION +
            ",\"inputSha256\":" + json(inputSha256) +
            ",\"language\":" + json(currentProgram.getLanguageID().toString()) +
            ",\"compilerSpec\":" + json(currentProgram.getCompilerSpec().getCompilerSpecID().toString()) + "}\n";
        Path statePath = stateDirectory.resolve("state.json");
        if (Files.isRegularFile(statePath)) {
            String existing = new String(Files.readAllBytes(statePath), StandardCharsets.UTF_8);
            if (!existing.equals(state)) {
                throw new IllegalStateException("export checkpoint identity differs from the current binary or exporter");
            }
        } else {
            if (!sortedRecords(functionsDirectory).isEmpty()) {
                throw new IllegalStateException("function checkpoints exist without an export identity");
            }
            writeAtomic(statePath, state);
        }

        int total = countExportableFunctions(currentProgram.getFunctionManager().getFunctions(true));
        List<String> functionIds = new ArrayList<>(total);
        int completed = 0;
        int recovered = 0;
        int partial = 0;
        int failed = 0;
        FunctionIterator inventory = currentProgram.getFunctionManager().getFunctions(true);
        while (inventory.hasNext()) {
            Function function = inventory.next();
            if (function.isExternal() || function.isThunk()) continue;
            String id = functionId(function);
            functionIds.add(id);
            if (isAcceptedRecord(functionsDirectory.resolve(id + ".json"))) {
                completed++;
                Path failurePath = failuresDirectory.resolve(id + ".json");
                if (!Files.isRegularFile(failurePath)) {
                    recovered++;
                } else {
                    String diagnostic = new String(Files.readAllBytes(failurePath), StandardCharsets.UTF_8);
                    if (diagnostic.contains("\"status\":\"partial\"")) partial++; else failed++;
                }
            }
        }
        int reused = completed;
        writeProgress(progressPath, "decompiling", completed, total, recovered, partial, failed, reused, null);

        DecompInterface decompiler = new DecompInterface();
        if (!decompiler.openProgram(currentProgram)) {
            decompiler.dispose();
            throw new IllegalStateException("Ghidra decompiler could not open the current program");
        }
        try {
            FunctionIterator iterator = currentProgram.getFunctionManager().getFunctions(true);
            while (iterator.hasNext()) {
                Function function = iterator.next();
                if (function.isExternal() || function.isThunk()) continue;
                String id = functionId(function);
                Path record = functionsDirectory.resolve(id + ".json");
                if (isAcceptedRecord(record)) continue;
                if (monitor.isCancelled()) throw new InterruptedException("program-model export was cancelled");
                writeProgress(progressPath, "decompiling", completed, total, recovered, partial, failed, reused, id);
                FunctionExport exported = exportFunction(function, decompiler, globalsDirectory, typesDirectory);
                Path failurePath = failuresDirectory.resolve(id + ".json");
                if (exported.failure == null) {
                    Files.deleteIfExists(failurePath);
                } else {
                    writeAtomic(
                        failurePath,
                        "{\"schemaVersion\":1,\"functionId\":" + json(id) +
                            ",\"status\":" + json(exported.status) +
                            ",\"message\":" + json(exported.failure) + "}\n"
                    );
                }
                writeAtomic(record, exported.record);
                completed++;
                if (exported.status.equals("recovered")) recovered++;
                else if (exported.status.equals("partial")) partial++;
                else failed++;
                writeProgress(progressPath, "decompiling", completed, total, recovered, partial, failed, reused, null);
                println("program-model export " + completed + "/" + total + " " + id + " status=" + exported.status);
            }
        } finally {
            decompiler.dispose();
        }

        assembleModel(outputPath, inputSha256, functionIds, functionsDirectory, globalsDirectory, typesDirectory);
        writeProgress(progressPath, "complete", completed, total, recovered, partial, failed, reused, null);
        println(
            "program-model export complete functions=" + completed + " partial=" + partial +
                " failed=" + failed + " reused=" + reused
        );
    }
}
