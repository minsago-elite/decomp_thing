package decompengine.ghidra;

import ghidra.app.plugin.processors.sleigh.SleighLanguageProvider;
import ghidra.program.disassemble.Disassembler;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.mem.ByteMemBufferImpl;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitorAdapter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/**
 * A static pointer-slot witness, never a resolved runtime implementation target.
 * Inputs are owned instruction bytes only; no Program, references, recovered model,
 * memory contents, mnemonic matching, or automatic analysis participates.
 *
 * Pinned semantics: Ghidra 12.1.3 docs/languages/html/pcoderef.html#pcoderef_varnode
 * defines a varnode by (address space, offset, size), including a memory location.
 * A RAM varnode input therefore reads that location; it is not an address constant.
 * docs/languages/html/pcodedescription.html#cpui_load separately defines an explicit
 * LOAD's space-ID and pointer inputs. Sleigh uses the first form for x86 FF15/FF25
 * RIP-relative operands, so the two proven relationships remain distinct below.
 * The process owner must authenticate the bundled implementation and bound execution.
 */
public final class ByteStaticMemoryTransferDecoderV1 {
    private static final int POINTER_BYTES = 8;
    private static final int MAX_PCODE_OPS = 4096;
    private final ByteInstructionDecoderV1 basic;
    private final Language language;

    public static void initialize(String bundledReleasePath) throws IOException {
        ByteInstructionDecoderV1.initialize(bundledReleasePath);
    }

    public ByteStaticMemoryTransferDecoderV1(String languageId) {
        basic = new ByteInstructionDecoderV1(languageId);
        language = SleighLanguageProvider.getSleighLanguageProvider().getLanguage(new LanguageID(languageId));
        if (language == null || language.getDefaultSpace().getType() != AddressSpace.TYPE_RAM) {
            throw new IllegalArgumentException("static transfer requires the pinned default RAM space");
        }
    }

    public ByteStaticMemoryTransferDecoderV1(String bundledReleasePath, String languageId) throws IOException {
        this(initializeAndReturnLanguage(bundledReleasePath, languageId));
    }

    private static String initializeAndReturnLanguage(String bundle, String language) throws IOException {
        initialize(bundle);
        return language;
    }

    public StaticMemoryTransfer decode(long addressBits, byte[] availableBytes) throws DecodeException {
        if (availableBytes == null || availableBytes.length < 1 || availableBytes.length > 32) {
            throw new DecodeException("input-byte-bound");
        }
        byte[] owned = availableBytes.clone();
        cancelled();
        try {
            var decoded = basic.decode(addressBits, owned);
            String classification = decoded.classification();
            if (!classification.equals("indirect-call") && !classification.equals("indirect-jump")) {
                return result(decoded, TransferProof.unresolved(classification.startsWith("unsupported-")
                    ? classification : "not-indirect-transfer", null, null));
            }
            if (!decoded.contextStatus().equals("language-default-no-commits-v1")) {
                return result(decoded, TransferProof.unresolved("unsupported-context", null, null));
            }
            var address = language.getDefaultSpace().getAddress(addressBits);
            boolean[] error = {false};
            var disassembler = Disassembler.getDisassembler(language, language.getAddressFactory(),
                new TaskMonitorAdapter(true) {
                    @Override public boolean isCancelled() { return Thread.currentThread().isInterrupted() || super.isCancelled(); }
                    @Override public void checkCancelled() throws CancelledException { if (isCancelled()) throw new CancelledException(); }
                }, ignored -> error[0] = true);
            var block = disassembler.pseudoDisassembleBlock(new ByteMemBufferImpl(address, owned, false), null, 1);
            cancelled();
            if (error[0] || block == null || block.hasInstructionError() || block.getInstructionCount() != 1) {
                throw new DecodeException("instruction-decode-failed");
            }
            var instruction = block.getInstructionAt(address);
            if (instruction == null || !address.equals(instruction.getAddress()) || instruction.getLength() != decoded.length()
                    || !Arrays.equals(instruction.getParsedBytes(), decoded.bytes())) {
                throw new DecodeException("basic-instruction-disagreement");
            }
            var flow = instruction.getFlowType();
            if (flow == null || !flow.isComputed() || flow.isOverride() || flow.isConditional()
                    || flow.isCall() != decoded.call() || flow.isJump() != decoded.jump()
                    || flow.isTerminal() != decoded.terminal() || flow.hasFallthrough() != (decoded.fallthrough() != null)) {
                return result(decoded, TransferProof.unresolved("typed-flow-disagreement", null, null));
            }
            return result(decoded, inspectPcode(instruction.getPcode(false), language.getDefaultSpace(), classification));
        } catch (DecodeException failure) {
            throw failure;
        } catch (ByteInstructionDecoderV1.DecodeException failure) {
            throw new DecodeException(failure.code(), failure);
        } catch (Exception failure) {
            throw new DecodeException("instruction-api-failure", failure);
        }
    }

    private static StaticMemoryTransfer result(ByteInstructionDecoderV1.DecodedInstruction decoded, TransferProof proof) throws DecodeException {
        cancelled();
        return new StaticMemoryTransfer(decoded.address(), decoded.length(), decoded.bytes(), decoded.classification(),
            proof.slot(), proof.width(), proof.relationship(), proof.readOpcode(), proof.readIndex(), proof.transferOpcode(),
            proof.transferIndex(), proof.copies(), decoded.contextStatus(), proof.reason());
    }

    /** Package-private for authored raw-p-code controls; production exposes only decode(bytes). */
    static TransferProof inspectPcode(PcodeOp[] operations, AddressSpace ram, String classification) throws DecodeException {
        if (operations == null || operations.length == 0 || operations.length > MAX_PCODE_OPS) {
            return TransferProof.unresolved("pcode-bound", null, null);
        }
        if (ram == null || ram.getType() != AddressSpace.TYPE_RAM || ram.getSize() != 64 || ram.getAddressableUnitSize() != 1
                || (!classification.equals("indirect-call") && !classification.equals("indirect-jump"))) {
            return TransferProof.unresolved("unsupported-transfer-profile", null, null);
        }
        int expectedTransfer = classification.equals("indirect-call") ? PcodeOp.CALLIND : PcodeOp.BRANCHIND;
        String transferName = classification.equals("indirect-call") ? "CALLIND" : "BRANCHIND";
        int transferIndex = -1;
        int memoryReads = 0;
        for (int index = 0; index < operations.length; index++) {
            cancelled();
            PcodeOp operation = operations[index];
            if (operation == null || operation.getNumInputs() > 64) return TransferProof.unresolved("pcode-bound", null, null);
            int opcode = operation.getOpcode();
            if (opcode == PcodeOp.CALLOTHER || opcode == PcodeOp.UNIMPLEMENTED) {
                return TransferProof.unresolved("unsupported-pcode-or-userop", null, null);
            }
            if (opcode == PcodeOp.CALLIND || opcode == PcodeOp.BRANCHIND) {
                if (opcode != expectedTransfer || transferIndex != -1 || operation.getNumInputs() != 1 || operation.getOutput() != null) {
                    return TransferProof.unresolved("competing-or-invalid-transfers", null, null);
                }
                transferIndex = index;
            } else if (opcode == PcodeOp.BRANCH || opcode == PcodeOp.CBRANCH || opcode == PcodeOp.CALL || opcode == PcodeOp.RETURN) {
                return TransferProof.unresolved("internal-pcode-control", null, null);
            }
            if (opcode == PcodeOp.LOAD) memoryReads++;
            for (int input = 0; input < operation.getNumInputs(); input++) {
                Varnode node = operation.getInput(input);
                if (node == null || node.getSize() < 1 || node.getSize() > 32) return TransferProof.unresolved("pcode-varnode-bound", null, null);
                if (node.isAddress()) memoryReads++;
            }
        }
        if (transferIndex < 0) return TransferProof.unresolved("missing-indirect-transfer", null, null);
        if (transferIndex != operations.length - 1) return TransferProof.unresolved("trailing-pcode-after-transfer", transferName, transferIndex);
        if (memoryReads > 1) return TransferProof.unresolved("multiple-memory-loads", transferName, transferIndex);
        Varnode current = operations[transferIndex].getInput(0);
        int consumer = transferIndex;
        List<Integer> copies = new ArrayList<>();
        while (true) {
            cancelled();
            if (current.getSize() != POINTER_BYTES) return TransferProof.unresolved("unsupported-pointer-width", transferName, transferIndex);
            if (current.isAddress()) {
                if (!ram.equals(current.getAddress().getAddressSpace())) return TransferProof.unresolved("nondefault-memory-space", transferName, transferIndex);
                return proveSlot(operations, ram, current.getOffset(), consumer, consumer == transferIndex ? transferName : "COPY",
                    "static-ram-varnode-exact-transfer-v1", transferName, transferIndex, copies);
            }
            if (!current.isUnique()) {
                return TransferProof.unresolved(current.isRegister() ? "register-transfer" : "nonmemory-indirect-value", transferName, transferIndex);
            }
            int definition = -1;
            for (int index = consumer - 1; index >= 0; index--) {
                cancelled();
                Varnode output = operations[index].getOutput();
                if (output != null && overlaps(output, current)) {
                    if (!output.equals(current)) return TransferProof.unresolved("overlapping-value-write", transferName, transferIndex);
                    definition = index;
                    break;
                }
            }
            if (definition < 0) return TransferProof.unresolved("missing-value-definition", transferName, transferIndex);
            PcodeOp defining = operations[definition];
            if (defining.getOpcode() == PcodeOp.COPY && defining.getNumInputs() == 1 && defining.getInput(0).getSize() == POINTER_BYTES) {
                copies.add(definition);
                current = defining.getInput(0);
                consumer = definition;
                continue;
            }
            if (defining.getOpcode() != PcodeOp.LOAD) return TransferProof.unresolved("unsupported-value-transform", transferName, transferIndex);
            if (defining.getNumInputs() != 2 || !defining.getInput(0).isConstant()
                    || (defining.getInput(0).getSize() != 4 && defining.getInput(0).getSize() != 8)
                    || defining.getInput(0).getOffset() != Integer.toUnsignedLong(ram.getSpaceID())) {
                return TransferProof.unresolved("nondefault-load-space", transferName, transferIndex);
            }
            Varnode pointer = defining.getInput(1);
            if (!pointer.isConstant() || pointer.getSize() != POINTER_BYTES) {
                return TransferProof.unresolved("nonstatic-load-address", transferName, transferIndex);
            }
            return proveSlot(operations, ram, pointer.getOffset(), definition, "LOAD", "single-static-load-exact-transfer-v1",
                transferName, transferIndex, copies);
        }
    }

    private static TransferProof proveSlot(PcodeOp[] operations, AddressSpace ram, long slot, int readIndex, String readOpcode,
            String relationship, String transferOpcode, int transferIndex, List<Integer> reverseCopies) throws DecodeException {
        try { ram.getAddress(slot).addNoWrap(POINTER_BYTES - 1); }
        catch (Exception failure) { return TransferProof.unresolved("pointer-slot-wrap", transferOpcode, transferIndex); }
        Varnode memory = new Varnode(ram.getAddress(slot), POINTER_BYTES);
        for (int index = 0; index < readIndex; index++) {
            cancelled();
            if (operations[index].getOpcode() == PcodeOp.STORE ||
                    (operations[index].getOutput() != null && overlaps(operations[index].getOutput(), memory))) {
                return TransferProof.unresolved("memory-write-before-read", transferOpcode, transferIndex);
            }
        }
        List<Integer> copies = new ArrayList<>(reverseCopies);
        Collections.reverse(copies);
        return new TransferProof("0x" + Long.toUnsignedString(slot, 16), POINTER_BYTES, relationship, readOpcode, readIndex,
            transferOpcode, transferIndex, List.copyOf(copies), null);
    }

    private static boolean overlaps(Varnode left, Varnode right) {
        if (left.getSpace() != right.getSpace()) return false;
        if (left.getSize() < 1 || right.getSize() < 1) return true;
        long leftEnd = left.getOffset() + left.getSize() - 1L;
        long rightEnd = right.getOffset() + right.getSize() - 1L;
        if (Long.compareUnsigned(leftEnd, left.getOffset()) < 0 || Long.compareUnsigned(rightEnd, right.getOffset()) < 0) return true;
        return Long.compareUnsigned(left.getOffset(), rightEnd) <= 0 && Long.compareUnsigned(right.getOffset(), leftEnd) <= 0;
    }

    private static void cancelled() throws DecodeException {
        if (Thread.currentThread().isInterrupted()) throw new DecodeException("cancelled");
    }

    record TransferProof(String slot, Integer width, String relationship, String readOpcode, Integer readIndex,
            String transferOpcode, Integer transferIndex, List<Integer> copies, String reason) {
        static TransferProof unresolved(String reason, String transferOpcode, Integer transferIndex) {
            return new TransferProof(null, null, "unresolved", null, null, transferOpcode, transferIndex, List.of(), reason);
        }
    }

    public record StaticMemoryTransfer(String address, int length, byte[] bytes, String classification,
            String pointerSlotAddress, Integer pointerWidthBytes, String relationship, String rawReadOpcode, Integer rawReadOpIndex,
            String rawTransferOpcode, Integer rawTransferOpIndex, List<Integer> rawCopyOpIndices, String contextStatus, String unresolvedReason) {
        public StaticMemoryTransfer { bytes = bytes.clone(); rawCopyOpIndices = List.copyOf(rawCopyOpIndices); }
        @Override public byte[] bytes() { return bytes.clone(); }
    }

    public static final class DecodeException extends Exception {
        private final String code;
        private DecodeException(String code) { super(code); this.code = code; }
        private DecodeException(String code, Exception cause) { super(code, cause); this.code = code; }
        public String code() { return code; }
    }
}
