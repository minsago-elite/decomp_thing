// Exports decompiler output for every non-external function.
// @category llm_bin_patch

import java.io.File;
import java.io.PrintWriter;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;

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
            output.println("/* GHIDRA_PROGRAM_CONTEXT");
            output.println(" * executable-format: " + safe(currentProgram.getExecutableFormat()));
            output.println(" * language: " + safe(currentProgram.getLanguageID().toString()));
            output.println(" * compiler-spec: " + safe(currentProgram.getCompilerSpec().getCompilerSpecID().toString()));
            output.println(" * image-base: " + currentProgram.getImageBase());
            output.println(" */");
            exportSymbols(output);
            exportStrings(output);
            FunctionIterator functions = currentProgram.getFunctionManager().getFunctions(true);
            while (functions.hasNext() && !monitor.isCancelled()) {
                Function function = functions.next();
                if (function.isExternal() || function.isThunk()) continue;
                DecompileResults result = decompiler.decompileFunction(function, 60, monitor);
                output.println("/* GHIDRA_FUNCTION");
                output.println(" * name: " + safe(function.getName()));
                output.println(" * entry: " + function.getEntryPoint());
                output.println(" * signature: " + safe(function.getSignature(true).toString()));
                output.println(" * calling-convention: " + safe(function.getCallingConventionName()));
                output.println(" * body-addresses: " + function.getBody().getNumAddresses());
                exportControlFlow(output, function);
                output.println(" */");
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

    private void exportSymbols(PrintWriter output) {
        output.println("/* GHIDRA_SYMBOLS");
        SymbolIterator symbols = currentProgram.getSymbolTable().getAllSymbols(true);
        while (symbols.hasNext() && !monitor.isCancelled()) {
            Symbol symbol = symbols.next();
            output.println(" * " + symbol.getAddress() + " " + safe(symbol.getSymbolType().toString()) + " " + safe(symbol.getName(true)));
        }
        output.println(" */");
    }

    private void exportStrings(PrintWriter output) {
        output.println("/* GHIDRA_DEFINED_STRINGS");
        DataIterator data = currentProgram.getListing().getDefinedData(true);
        while (data.hasNext() && !monitor.isCancelled()) {
            Data item = data.next();
            if (item.hasStringValue()) {
                output.println(" * " + item.getAddress() + " " + safe(item.getDefaultValueRepresentation()));
            }
        }
        output.println(" */");
    }

    private void exportControlFlow(PrintWriter output, Function function) {
        Listing listing = currentProgram.getListing();
        InstructionIterator instructions = listing.getInstructions(function.getBody(), true);
        long count = 0;
        StringBuilder edges = new StringBuilder();
        while (instructions.hasNext() && !monitor.isCancelled()) {
            Instruction instruction = instructions.next();
            count++;
            for (Address target : instruction.getFlows()) {
                if (edges.length() > 0) edges.append(", ");
                edges.append(instruction.getAddress()).append("->").append(target);
            }
        }
        output.println(" * instruction-count: " + count);
        output.println(" * control-flow-edges: " + (edges.length() == 0 ? "none" : edges.toString()));
    }

    private String safe(String value) {
        if (value == null) return "unknown";
        return value.replace("*/", "* /").replace("\r", "\\r").replace("\n", "\\n");
    }
}
