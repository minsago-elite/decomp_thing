package decompengine.ghidra;

import ghidra.GhidraApplicationLayout;
import generic.jar.ResourceFile;
import ghidra.app.plugin.processors.sleigh.SleighParserContext;
import ghidra.app.plugin.processors.sleigh.SleighLanguageProvider;
import ghidra.framework.Application;
import ghidra.framework.ApplicationConfiguration;
import ghidra.program.disassemble.Disassembler;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.DisassemblerContext;
import ghidra.program.model.lang.InstructionBlock;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.mem.ByteMemBufferImpl;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.FlowType;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitorAdapter;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.TreeSet;

/**
 * One-instruction byte decoder. No imported program, listing, reference manager,
 * analyzer, recovered model, or model-provided instruction boundary is consumed.
 * The process owner must authenticate the bundled release and bound execution.
 * Public arguments/results deliberately use only JDK types for reflective use.
 */
public final class ByteInstructionDecoderV1 {
    public static final String SUPPORTED_LANGUAGE = "x86:LE:64:default";
    public static final String SUPPORTED_GHIDRA = "12.1.3";
    private static final int MAX_INPUT_BYTES = 32;
    private static final int MAX_PCODE_OPS = 4096;
    private static final int MAX_FLOWS = 16;
    private final Language language;

    /** Initialize only from the caller-authenticated bundled release directory. */
    public static synchronized void initialize(String bundledReleasePath) throws IOException {
        Path requested = Path.of(bundledReleasePath).toRealPath();
        if (!Application.isInitialized()) {
            // Byte-only Sleigh needs the authenticated application layout, not the
            // full headless tool bootstrap (plugin discovery, remote serialization,
            // or ModuleInitializer extension execution). In particular, discovery
            // must not scan the boot JVM classpath outside the isolated loader.
            Application.initializeApplication(new BundledLayout(requested),
                new ApplicationConfiguration());
        }
        if (!SUPPORTED_GHIDRA.equals(Application.getApplicationVersion())
                || !requested.equals(Application.getInstallationDirectory().getFile(false).toPath().toRealPath())) {
            throw new IllegalStateException("byte decoder requires the exact initialized bundled release");
        }
        requireBundledModules(requested);
    }

    public ByteInstructionDecoderV1(String languageId) {
        if (!Application.isInitialized() || !SUPPORTED_GHIDRA.equals(Application.getApplicationVersion())) {
            throw new IllegalStateException("byte decoder requires initialized Ghidra 12.1.3");
        }
        try {
            requireBundledModules(Application.getInstallationDirectory().getFile(false).toPath().toRealPath());
        } catch (IOException failure) {
            throw new IllegalStateException("initialized bundled module identity is unavailable", failure);
        }
        if (!SUPPORTED_LANGUAGE.equals(languageId)) {
            throw new IllegalArgumentException("unsupported byte decoder language");
        }
        try {
            SleighLanguageProvider provider = SleighLanguageProvider.getSleighLanguageProvider();
            if (provider.hadLoadFailure()) throw new IllegalStateException("bundled Sleigh definitions failed validation");
            language = provider.getLanguage(new LanguageID(languageId));
            if (language == null) throw new IllegalStateException("bundled Sleigh language is missing");
        } catch (Exception failure) {
            throw new IllegalArgumentException("bundled decoder language unavailable", failure);
        }
        if (language.getVersion() != 4 || language.getMinorVersion() != 8 || language.isBigEndian()
                || language.getDefaultSpace().getSize() != 64
                || language.getDefaultSpace().getAddressableUnitSize() != 1
                || language.hasProperty("customDisassemblerClass")) {
            throw new IllegalArgumentException("byte decoder language identity differs from x86-64 version 4.8");
        }
    }

    public ByteInstructionDecoderV1(String bundledReleasePath, String languageId) throws IOException {
        this(initializeAndReturnLanguage(bundledReleasePath, languageId));
    }

    private static String initializeAndReturnLanguage(String bundle, String language) throws IOException {
        initialize(bundle);
        return language;
    }

    private static void requireBundledModules(Path release) throws IOException {
        for (ResourceFile module : Application.getModuleRootDirectories()) {
            if (!module.getFile(false).toPath().toRealPath().startsWith(release)) {
                throw new IllegalStateException("byte decoder rejects modules outside the bundled release");
            }
        }
    }

    /** No success result is produced for truncated, ambiguous, or failed decoding. */
    public DecodedInstruction decode(long addressBits, byte[] availableBytes) throws DecodeException {
        if (availableBytes == null || availableBytes.length == 0 || availableBytes.length > MAX_INPUT_BYTES) {
            throw new DecodeException("input-byte-bound");
        }
        if (Thread.currentThread().isInterrupted()) throw new DecodeException("cancelled");
        byte[] ownedBytes = availableBytes.clone();
        try {
            AddressSpace space = language.getDefaultSpace();
            Address address = space.getAddress(addressBits);
            address.addNoWrap(ownedBytes.length - 1L);
            ByteMemBufferImpl buffer = new ByteMemBufferImpl(address, ownedBytes, false);
            boolean[] reported = {false};
            // Construct a fresh disassembler for every instruction. This factory installs
            // the language defaults; no context retained by a previous call can leak in.
            Disassembler disassembler = Disassembler.getDisassembler(language, language.getAddressFactory(),
                new TaskMonitorAdapter(true) {
                    @Override public boolean isCancelled() {
                        return Thread.currentThread().isInterrupted() || super.isCancelled();
                    }
                    @Override public void checkCancelled() throws CancelledException {
                        if (isCancelled()) throw new CancelledException();
                    }
                }, ignored -> reported[0] = true);
            InstructionBlock block = disassembler.pseudoDisassembleBlock(buffer, null, 1);
            if (Thread.currentThread().isInterrupted()) throw new DecodeException("cancelled");
            if (reported[0] || block == null || block.hasInstructionError() || block.getInstructionCount() != 1) {
                throw new DecodeException("instruction-decode-failed");
            }
            Instruction instruction = block.getInstructionAt(address);
            if (instruction == null || !address.equals(instruction.getAddress()) || instruction.getLength() < 1
                    || instruction.getLength() > ownedBytes.length || instruction.getLength() > MAX_INPUT_BYTES
                    || instruction.getDelaySlotDepth() != 0 || instruction.isInDelaySlot()
                    || instruction.getPrototype().hasNext2Dependency()) {
                throw new DecodeException("instruction-boundary-unsupported");
            }
            byte[] decodedBytes = Arrays.copyOf(ownedBytes, instruction.getLength());
            if (!Arrays.equals(decodedBytes, instruction.getParsedBytes())) {
                throw new DecodeException("instruction-byte-mismatch");
            }
            FlowType flow = instruction.getFlowType();
            if (flow == null || flow.isOverride()) throw new DecodeException("instruction-flow-unsupported");
            Address[] rawFlows = instruction.getFlows();
            if (rawFlows == null || rawFlows.length > MAX_FLOWS) throw new DecodeException("instruction-flow-bound");
            TreeSet<String> targets = new TreeSet<>((left, right) ->
                Long.compareUnsigned(Long.parseUnsignedLong(left.substring(2), 16), Long.parseUnsignedLong(right.substring(2), 16)));
            for (Address target : rawFlows) {
                if (target == null || !space.equals(target.getAddressSpace()) || !targets.add(hex(target))) {
                    throw new DecodeException("instruction-target-unsupported");
                }
            }
            Address next = instruction.getFallThrough();
            if (flow.hasFallthrough() != (next != null)
                    || (next != null && (!space.equals(next.getAddressSpace())
                        || !next.equals(address.addNoWrap(instruction.getLength()))))) {
                throw new DecodeException("instruction-fallthrough-unsupported");
            }

            PcodeOp[] pcode = instruction.getPcode(false);
            if (pcode == null || pcode.length > MAX_PCODE_OPS) throw new DecodeException("instruction-pcode-unavailable");
            List<String> calls = new ArrayList<>();
            TreeSet<String> jumps = new TreeSet<>(targets.comparator());
            int indirectCalls = 0;
            int returns = 0;
            boolean userop = false;
            boolean unsupportedPcode = false;
            boolean contextChange = false;
            for (PcodeOp op : pcode) {
                if (op == null) throw new DecodeException("instruction-pcode-unavailable");
                int opcode = op.getOpcode();
                if (opcode == PcodeOp.UNIMPLEMENTED) unsupportedPcode = true;
                if (opcode == PcodeOp.CALLOTHER) userop = true;
                if (opcode == PcodeOp.CALLIND) indirectCalls++;
                if (opcode == PcodeOp.RETURN) returns++;
                if (opcode == PcodeOp.CALL) {
                    if (op.getNumInputs() != 1 || !space.equals(op.getInput(0).getAddress().getAddressSpace())) {
                        throw new DecodeException("direct-call-target-unsupported");
                    }
                    calls.add(hex(op.getInput(0).getAddress()));
                }
                if ((opcode == PcodeOp.BRANCH || opcode == PcodeOp.CBRANCH) && op.getNumInputs() > 0
                        && space.equals(op.getInput(0).getAddress().getAddressSpace())) {
                    jumps.add(hex(op.getInput(0).getAddress()));
                }
                Varnode output = op.getOutput();
                if (output != null && output.isRegister()) {
                    Register register = language.getRegister(output.getAddress(), output.getSize());
                    if (register != null) {
                        String name = register.getBaseRegister().getName().toUpperCase(Locale.ROOT);
                        contextChange |= register.isProcessorContext() || name.equals("CS")
                            || name.equals("EFER") || name.matches("CR[0-9]+");
                    }
                }
            }
            // Inspect reconstructed Sleigh commits without modifying decoder state. An
            // instruction that exports context cannot be followed with a fresh default.
            var parser = instruction.getPrototype().getParserContext(buffer, instruction);
            if (!(parser instanceof SleighParserContext sleigh)) {
                throw new DecodeException("instruction-context-unavailable");
            }
            CommitProbe probe = new CommitProbe(instruction);
            sleigh.applyCommits(probe);
            contextChange |= probe.changed;

            String classification;
            String directCall = null;
            if (unsupportedPcode) classification = "unsupported-pcode";
            else if (contextChange) classification = "unsupported-context";
            else if (userop) classification = "unsupported-trap-or-userop";
            else if (flow.isCall()) {
                if (flow.isComputed()) {
                    if (!calls.isEmpty() || indirectCalls != 1 || !targets.isEmpty()) {
                        throw new DecodeException("indirect-call-pcode-mismatch");
                    }
                    classification = "indirect-call";
                } else {
                    if (calls.size() != 1 || indirectCalls != 0 || targets.size() != 1
                            || !targets.first().equals(calls.get(0))) {
                        throw new DecodeException("direct-call-pcode-mismatch");
                    }
                    directCall = calls.get(0);
                    classification = "direct-call";
                }
            } else {
                if (!calls.isEmpty() || indirectCalls != 0) throw new DecodeException("noncall-pcode-mismatch");
                if (flow.isJump()) {
                    if (flow.isComputed()) classification = "indirect-jump";
                    else {
                        if (targets.isEmpty() || !targets.equals(jumps)) throw new DecodeException("direct-jump-pcode-mismatch");
                        classification = "direct-jump";
                    }
                } else if (flow.isTerminal() && returns == 1 && targets.isEmpty() && next == null) {
                    classification = "return";
                } else if (!flow.isTerminal() && !flow.isComputed() && !flow.isConditional()
                        && targets.isEmpty() && next != null && returns == 0) {
                    classification = "ordinary";
                } else classification = "unsupported-flow";
            }
            if (Thread.currentThread().isInterrupted()) throw new DecodeException("cancelled");
            return new DecodedInstruction(hex(address), instruction.getLength(), decodedBytes, classification,
                flow.isCall(), flow.isComputed(), flow.isJump(), flow.isConditional(), flow.isTerminal(),
                next == null ? null : hex(next), List.copyOf(targets), directCall,
                contextChange ? "context-change" : userop ? "unassessed-userop-context"
                    : unsupportedPcode ? "unassessed-pcode-context" : "language-default-no-commits-v1");
        } catch (DecodeException failure) {
            throw failure;
        } catch (Exception failure) {
            throw new DecodeException("instruction-api-failure", failure);
        }
    }

    private static String hex(Address address) {
        return "0x" + Long.toUnsignedString(address.getOffset(), 16);
    }

    private static final class BundledLayout extends GhidraApplicationLayout {
        private BundledLayout(Path release) throws IOException { super(release.toFile()); }
        @Override protected List<ResourceFile> findExtensionInstallationDirectories() { return List.of(); }
        @Override protected ResourceFile findPatchDirectory() { return null; }
    }

    public record DecodedInstruction(String address, int length, byte[] bytes, String classification,
            boolean call, boolean computed, boolean jump, boolean conditional, boolean terminal,
            String fallthrough, List<String> directTargets, String directCallTarget, String contextStatus) {
        public DecodedInstruction {
            bytes = bytes.clone();
            directTargets = List.copyOf(directTargets);
        }
        @Override public byte[] bytes() { return bytes.clone(); }
    }

    public static final class DecodeException extends Exception {
        private final String code;
        private DecodeException(String code) { super(code); this.code = code; }
        private DecodeException(String code, Exception cause) { super(code, cause); this.code = code; }
        public String code() { return code; }
    }

    private static final class CommitProbe implements DisassemblerContext {
        private final Instruction instruction;
        private boolean changed;
        private CommitProbe(Instruction instruction) { this.instruction = instruction; }
        @Override public void setFutureRegisterValue(Address address, RegisterValue value) { changed = true; }
        @Override public void setFutureRegisterValue(Address from, Address to, RegisterValue value) { changed = true; }
        @Override public void setValue(Register register, BigInteger value) { changed = true; }
        @Override public void setRegisterValue(RegisterValue value) { changed = true; }
        @Override public void clearRegister(Register register) { changed = true; }
        @Override public Register getBaseContextRegister() { return instruction.getBaseContextRegister(); }
        @Override public List<Register> getRegisters() { return instruction.getRegisters(); }
        @Override public Register getRegister(String name) { return instruction.getRegister(name); }
        @Override public BigInteger getValue(Register register, boolean signed) { return instruction.getValue(register, signed); }
        @Override public RegisterValue getRegisterValue(Register register) { return instruction.getRegisterValue(register); }
        @Override public boolean hasValue(Register register) { return instruction.hasValue(register); }
    }
}
