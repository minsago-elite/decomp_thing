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
import java.util.Set;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;

public class ExportProgramModel extends GhidraScript {
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
                default:
                    if (c < 0x20) out.append(String.format("\\u%04x", (int)c));
                    else out.append(c);
            }
        }
        return out.append('"').toString();
    }

    private static String id(Function function) {
        return String.format("fn_%016x", function.getEntryPoint().getOffset());
    }

    private static String sha256(byte[] bytes) throws Exception {
        byte[] digest = MessageDigest.getInstance("SHA-256").digest(bytes);
        StringBuilder result = new StringBuilder();
        for (byte value : digest) result.append(String.format("%02x", value & 0xff));
        return result.toString();
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
                Set<Function> called = function.getCalledFunctions(monitor);
                List<String> callIds = new ArrayList<>();
                for (Function target : called) if (!target.isExternal()) callIds.add(id(target));
                Collections.sort(callIds);
                String source = result.decompileCompleted() ? result.getDecompiledFunction().getC() : null;
                String status = result.decompileCompleted() ? "recovered" : "failed";
                output.println("    {");
                output.println("      \"id\": " + json(id(function)) + ",");
                output.println("      \"name\": " + json(function.getName()) + ",");
                output.println("      \"address\": " + json("0x" + function.getEntryPoint().toString()) + ",");
                output.println("      \"prototype\": " + json(function.getPrototypeString(false, false)) + ",");
                output.println("      \"status\": " + json(status) + ",");
                output.print("      \"calls\": [");
                for (int call = 0; call < callIds.size(); call++) {
                    if (call > 0) output.print(", ");
                    output.print(json(callIds.get(call)));
                }
                output.println("],");
                output.println("      \"referencedGlobals\": [],");
                output.println("      \"strings\": [],");
                output.println("      \"decompiledC\": " + json(source));
                output.println("    }" + (index + 1 == functions.size() ? "" : ","));
            }
            output.println("  ],");
            output.println("  \"globals\": [],");
            output.println("  \"types\": []");
            output.println("}");
        } finally {
            decompiler.dispose();
        }
    }
}
