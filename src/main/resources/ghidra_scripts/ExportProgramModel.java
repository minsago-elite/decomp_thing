// Exports a deterministic, address-keyed whole-program model for source-tree planning.
// @category llm_bin_patch

import java.io.File;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
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
    private static final class GlobalEvidence {
        final String id, name, type, initializer;
        final Address address;
        GlobalEvidence(String id, String name, Address address, String type, String initializer) {
            this.id = id; this.name = name; this.address = address; this.type = type; this.initializer = initializer;
        }
    }

    private static final class TypeEvidence {
        final String id, declaration;
        final Address sourceAddress;
        TypeEvidence(String id, String declaration, Address sourceAddress) {
            this.id = id; this.declaration = declaration; this.sourceAddress = sourceAddress;
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

    private static String functionId(Function function) { return String.format("fn_%016x", function.getEntryPoint().getOffset()); }
    private static String globalId(Address address) { return String.format("global_%016x", address.getOffset()); }
    private static String sha256(byte[] bytes) throws Exception {
        byte[] digest = MessageDigest.getInstance("SHA-256").digest(bytes);
        StringBuilder result = new StringBuilder();
        for (byte value : digest) result.append(String.format("%02x", value & 0xff));
        return result.toString();
    }
    private static void writeStrings(PrintWriter output, Iterable<String> values) {
        boolean first = true;
        for (String value : values) {
            if (!first) output.print(", ");
            output.print(json(value));
            first = false;
        }
    }

    private void retainType(Map<String, TypeEvidence> types, DataType type, Address sourceAddress) {
        if (!(type instanceof Composite) && !(type instanceof Enum) && !(type instanceof TypeDef)) return;
        String key = type.getPathName();
        String id = String.format("type_%08x", key.hashCode());
        int length = Math.max(type.getLength(), 1);
        String cName = type.getName().replaceAll("[^A-Za-z0-9_]", "_");
        if (cName.isEmpty() || Character.isDigit(cName.charAt(0))) cName = "recovered_" + id;
        String prefix = "/* Ghidra type " + key.replace("*/", "* /") + " */ ";
        String declaration;
        if (type instanceof Composite) declaration = prefix + "typedef struct " + cName + " { unsigned char _data[" + length + "]; } " + cName + ";";
        else if (type instanceof Enum) declaration = prefix + "typedef int " + cName + ";";
        else declaration = prefix + "typedef unsigned char " + cName + "[" + length + "];";
        types.putIfAbsent(id, new TypeEvidence(id, declaration, sourceAddress));
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

    @Override
    protected void run() throws Exception {
        String[] arguments = getScriptArgs();
        if (arguments.length != 1) throw new IllegalArgumentException("expected output path");
        List<Function> functions = new ArrayList<>();
        FunctionIterator iterator = currentProgram.getFunctionManager().getFunctions(true);
        while (iterator.hasNext()) {
            Function function = iterator.next();
            if (!function.isExternal() && !function.isThunk()) functions.add(function);
        }
        Collections.sort(functions, Comparator.comparing(Function::getEntryPoint));
        Map<Long, GlobalEvidence> globals = new TreeMap<>();
        Map<String, TypeEvidence> types = new TreeMap<>();
        DecompInterface decompiler = new DecompInterface();
        decompiler.openProgram(currentProgram);
        try (PrintWriter output = new PrintWriter(new File(arguments[0]), StandardCharsets.UTF_8.name())) {
            output.println("{");
            output.println("  \"schemaVersion\": 1,");
            output.println("  \"inputSha256\": " + json(sha256(Files.readAllBytes(Paths.get(currentProgram.getExecutablePath())))) + ",");
            output.println("  \"functions\": [");
            for (int index = 0; index < functions.size(); index++) {
                Function function = functions.get(index);
                DecompileResults result = decompiler.decompileFunction(function, 60, monitor);
                Set<String> callIds = new TreeSet<>();
                for (Function target : function.getCalledFunctions(monitor)) if (!target.isExternal()) callIds.add(functionId(target));
                Set<String> referencedGlobals = new TreeSet<>();
                Set<String> strings = new TreeSet<>();
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
                            globals.putIfAbsent(global.address.getOffset(), global);
                            referencedGlobals.add(global.id);
                            if (data != null) retainType(types, data.getDataType(), global.address);
                        }
                    }
                }
                retainType(types, function.getReturnType(), function.getEntryPoint());
                for (Parameter parameter : function.getParameters()) retainType(types, parameter.getDataType(), function.getEntryPoint());
                String source = result.decompileCompleted() ? result.getDecompiledFunction().getC() : null;
                String status = result.decompileCompleted() ? "recovered" : "failed";
                output.println("    {");
                output.println("      \"id\": " + json(functionId(function)) + ",");
                output.println("      \"name\": " + json(function.getName()) + ",");
                output.println("      \"address\": " + json(String.format("0x%x", function.getEntryPoint().getOffset())) + ",");
                output.println("      \"prototype\": " + json(function.getPrototypeString(false, false)) + ",");
                output.println("      \"status\": " + json(status) + ",");
                output.print("      \"calls\": ["); writeStrings(output, callIds); output.println("],");
                output.print("      \"referencedGlobals\": ["); writeStrings(output, referencedGlobals); output.println("],");
                output.print("      \"strings\": ["); writeStrings(output, strings); output.println("],");
                output.println("      \"decompiledC\": " + json(source));
                output.println("    }" + (index + 1 == functions.size() ? "" : ","));
            }
            output.println("  ],");
            output.println("  \"globals\": [");
            List<GlobalEvidence> globalValues = new ArrayList<>(globals.values());
            for (int index = 0; index < globalValues.size(); index++) {
                GlobalEvidence global = globalValues.get(index);
                output.println("    {");
                output.println("      \"id\": " + json(global.id) + ",");
                output.println("      \"name\": " + json(global.name) + ",");
                output.println("      \"address\": " + json(String.format("0x%x", global.address.getOffset())) + ",");
                output.println("      \"type\": " + json(global.type) + ",");
                output.println("      \"initializer\": " + json(global.initializer) + ",");
                output.println("      \"status\": \"recovered\"");
                output.println("    }" + (index + 1 == globalValues.size() ? "" : ","));
            }
            output.println("  ],");
            output.println("  \"types\": [");
            List<TypeEvidence> typeValues = new ArrayList<>(types.values());
            for (int index = 0; index < typeValues.size(); index++) {
                TypeEvidence type = typeValues.get(index);
                output.println("    {");
                output.println("      \"id\": " + json(type.id) + ",");
                output.println("      \"declaration\": " + json(type.declaration) + ",");
                output.println("      \"sourceAddress\": " + json(String.format("0x%x", type.sourceAddress.getOffset())) + ",");
                output.println("      \"status\": \"partial\"");
                output.println("    }" + (index + 1 == typeValues.size() ? "" : ","));
            }
            output.println("  ]");
            output.println("}");
        } finally {
            decompiler.dispose();
        }
    }
}
