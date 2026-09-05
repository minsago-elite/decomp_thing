import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.symbol.FlowType;
import java.io.BufferedOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.MessageDigest;
import java.util.HexFormat;
import java.util.TreeSet;

public class ExportRecoveredCallSites extends GhidraScript {
    private static final long MAXIMUM_BYTES = 4L * 1024 * 1024 * 1024;
    private static final long MAXIMUM_SITES = 10_000_000L;
    private static final long MAXIMUM_INSTRUCTIONS = 100_000_000L;
    private long writtenBytes;

    @Override
    public void run() throws Exception {
        String[] arguments = getScriptArgs();
        if (arguments.length != 4) throw new IllegalArgumentException("expected exporter digest, tool digest, model and output paths");
        String exporter = digestArgument(arguments[0]);
        String tool = digestArgument(arguments[1]);
        String input = digestArgument(currentProgram.getExecutableSHA256());
        if (!currentProgram.getLanguageID().toString().equals("x86:LE:64:default")) {
            throw new IllegalArgumentException("recovered call-site export requires x86-64 little-endian instructions");
        }
        Path model = Path.of(arguments[2]).toAbsolutePath().normalize();
        Path output = Path.of(arguments[3]).toAbsolutePath().normalize();
        if (model.equals(output) || Files.exists(output, LinkOption.NOFOLLOW_LINKS)) {
            throw new IllegalArgumentException("recovered call-site destination must be absent and distinct from the model");
        }
        String modelSha256 = hashModel(model);
        Address base = currentProgram.getImageBase();
        Path stage = Files.createTempFile(output.getParent(), ".call-sites-", ".tmp",
            PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")));
        long sites = 0;
        long instructionsSeen = 0;
        try {
            try (OutputStream stream = new BufferedOutputStream(Files.newOutputStream(stage))) {
                write(stream, "{\n  \"analysisToolSha256\": \"" + tool + "\",\n  \"calls\": ");
                FunctionIterator functions = currentProgram.getFunctionManager().getFunctions(true);
                while (functions.hasNext()) {
                    monitor.checkCancelled();
                    Function caller = functions.next();
                    if (caller.isExternal()) continue;
                    long callerRva = rva(caller.getEntryPoint(), base);
                    InstructionIterator instructions = currentProgram.getListing().getInstructions(caller.getBody(), true);
                    while (instructions.hasNext()) {
                        monitor.checkCancelled();
                        if (++instructionsSeen > MAXIMUM_INSTRUCTIONS) throw new IllegalStateException("instruction scan bound exceeded");
                        Instruction instruction = instructions.next();
                        FlowType flow = instruction.getPrototype().getFlowType(instruction.getInstructionContext());
                        if (!flow.isCall() && !flow.isJump()) continue;
                        Address[] encoded = instruction.getDefaultFlows();
                        Address physical = !flow.isComputed() && encoded.length == 1 ? encoded[0] : null;
                        boolean tail = false;
                        if (flow.isJump() && !flow.isComputed() && !flow.isConditional() && physical != null) {
                            Function target = currentProgram.getFunctionManager().getFunctionAt(physical);
                            tail = target != null && !target.equals(caller) && !caller.getBody().contains(physical);
                        }
                        if (!flow.isCall() && !tail && !flow.isComputed()) continue;
                        String kind = flow.isCall() ? (flow.isComputed() ? "indirect-call" : "direct-call")
                            : (tail ? "direct-tail-call" : "indirect-jump");
                        if (instruction.getDelaySlotDepth() != 0 || instruction.isLengthOverridden() ||
                            instruction.getLength() < 1 || instruction.getLength() > 15) {
                            throw new IllegalStateException("unsupported recovered instruction boundary");
                        }
                        long instructionRva = rva(instruction.getAddress(), base);
                        byte[] bytes = instruction.getBytes();
                        if (bytes.length != instruction.getLength()) throw new IllegalStateException("instruction byte count changed");
                        TreeSet<Long> targets = new TreeSet<>(Long::compareUnsigned);
                        for (Address target : instruction.getFlows()) {
                            if (target.isMemoryAddress()) targets.add(rva(target, base));
                            if (targets.size() > 16) throw new IllegalStateException("recovered target-set bound exceeded");
                        }
                        if (++sites > MAXIMUM_SITES) throw new IllegalStateException("call-site count bound exceeded");
                        write(stream, sites == 1 ? "[\n" : ",\n");
                        write(stream, "    {\n      \"callerRva\": " + quotedHex(callerRva) + ",\n      \"flowKind\": \"" + kind +
                            "\",\n      \"instructionBytes\": \"" + HexFormat.of().formatHex(bytes) + "\",\n      \"instructionRva\": " +
                            quotedHex(instructionRva) + ",\n      \"physicalTargetRva\": " +
                            (physical == null ? "null" : quotedHex(rva(physical, base))) + ",\n      \"recoveredTargetRvas\": ");
                        boolean first = true;
                        for (long target : targets) {
                            write(stream, first ? "[\n" : ",\n");
                            first = false;
                            write(stream, "        " + quotedHex(target));
                        }
                        Address returnAddress = flow.isCall() ? instruction.getAddress().addNoWrap(bytes.length) : null;
                        write(stream, (first ? "[]" : "\n      ]") + ",\n      \"returnPcRva\": " +
                            (returnAddress == null ? "null" : quotedHex(rva(returnAddress, base))) + "\n    }");
                    }
                }
                write(stream, (sites == 0 ? "[]" : "\n  ]") + ",\n  \"exporterSha256\": \"" + exporter +
                    "\",\n  \"imageBaseAddress\": " + quotedHex(base.getOffset()) + ",\n  \"inputSha256\": \"" + input +
                    "\",\n  \"programModelSha256\": \"" + modelSha256 + "\",\n  \"schemaVersion\": 1\n}\n");
            }
            if (!modelSha256.equals(hashModel(model))) throw new IllegalStateException("program model changed during call-site export");
            Files.setPosixFilePermissions(stage, PosixFilePermissions.fromString("r--------"));
            Files.createLink(output, stage);
            println("recovered call-site export complete: " + sites);
        } finally {
            Files.deleteIfExists(stage);
        }
    }

    private static String digestArgument(String value) {
        if (value == null || !value.matches("[0-9a-f]{64}")) throw new IllegalArgumentException("invalid call-site digest binding");
        return value;
    }

    private String hashModel(Path model) throws Exception {
        if (!Files.isRegularFile(model, LinkOption.NOFOLLOW_LINKS) || Files.size(model) > 512L * 1024 * 1024) {
            throw new IllegalArgumentException("program model is not a bounded regular file");
        }
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        long total = 0;
        try (InputStream stream = Files.newInputStream(model, StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS)) {
            byte[] buffer = new byte[65536];
            int count;
            while ((count = stream.read(buffer)) != -1) {
                monitor.checkCancelled();
                total += count;
                if (total > 512L * 1024 * 1024) throw new IllegalStateException("program model exceeds byte bound");
                digest.update(buffer, 0, count);
            }
        }
        return HexFormat.of().formatHex(digest.digest());
    }

    private static long rva(Address address, Address base) {
        if (!address.isMemoryAddress() || !address.getAddressSpace().equals(base.getAddressSpace()) ||
            Long.compareUnsigned(address.getOffset(), base.getOffset()) < 0) {
            throw new IllegalArgumentException("call-site address is outside the image address space");
        }
        return address.getOffset() - base.getOffset();
    }

    private static String quotedHex(long value) {
        return "\"0x" + Long.toUnsignedString(value, 16) + "\"";
    }

    private void write(OutputStream stream, String value) throws Exception {
        byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
        writtenBytes = Math.addExact(writtenBytes, bytes.length);
        if (writtenBytes > MAXIMUM_BYTES) throw new IllegalStateException("call-site output byte bound exceeded");
        stream.write(bytes);
    }
}
