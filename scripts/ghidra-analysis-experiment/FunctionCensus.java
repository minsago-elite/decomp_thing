// Diagnostic-only: prints the recovered function count and a digest of the sorted entry points.
//@category Diagnostics

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class FunctionCensus extends GhidraScript {
    @Override
    protected void run() throws Exception {
        List<Long> entries = new ArrayList<>();
        FunctionIterator functions = currentProgram.getFunctionManager().getFunctions(true);
        while (functions.hasNext()) {
            Function function = functions.next();
            entries.add(function.getEntryPoint().getOffset());
        }
        Collections.sort(entries);
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        for (long entry : entries) digest.update(Long.toHexString(entry).getBytes(StandardCharsets.UTF_8));
        StringBuilder hex = new StringBuilder();
        for (byte value : digest.digest()) hex.append(String.format("%02x", value & 0xff));
        println("ANALYZER-EXPERIMENT functions=" + entries.size() + " entrySha256=" + hex);
    }
}
