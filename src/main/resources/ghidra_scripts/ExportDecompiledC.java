// Exports decompiler output for every non-external function.
// @category llm_bin_patch

import java.io.File;
import java.io.PrintWriter;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;

public class ExportDecompiledC extends GhidraScript {
    @Override
    protected void run() throws Exception {
        String[] arguments = getScriptArgs();
        if (arguments.length != 1) {
            throw new IllegalArgumentException("expected output path");
        }
        DecompInterface decompiler = new DecompInterface();
        decompiler.openProgram(currentProgram);
        try (PrintWriter output = new PrintWriter(new File(arguments[0]))) {
            FunctionIterator functions = currentProgram.getFunctionManager().getFunctions(true);
            while (functions.hasNext() && !monitor.isCancelled()) {
                Function function = functions.next();
                if (function.isExternal() || function.isThunk()) continue;
                DecompileResults result = decompiler.decompileFunction(function, 60, monitor);
                output.println("/* FUNCTION " + function.getName() + " @ " + function.getEntryPoint() + " */");
                if (result.decompileCompleted()) {
                    output.println(result.getDecompiledFunction().getC());
                } else {
                    output.println("/* decompilation failed: " + result.getErrorMessage() + " */");
                }
            }
        } finally {
            decompiler.dispose();
        }
    }
}
