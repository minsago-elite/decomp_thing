package decompengine.ghidra;

import ghidra.app.plugin.processors.sleigh.SleighLanguageProvider;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.address.GenericAddressSpace;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import java.util.HexFormat;
import java.util.List;

/** Authored bytes and tiny p-code use/definition controls; never import or execute an ELF. */
public final class ByteStaticMemoryTransferDecoderControls {
    private static int checks;
    private static AddressSpace ram, unique, constants, registers;

    public static void main(String[] arguments) throws Exception {
        refused(() -> new ByteStaticMemoryTransferDecoderV1("x86:LE:64:default"), "uninitialized");
        ByteStaticMemoryTransferDecoderV1.initialize(arguments[0]);
        ByteStaticMemoryTransferDecoderV1.initialize(arguments[0]);
        refused(() -> ByteStaticMemoryTransferDecoderV1.initialize(arguments[1]), "foreign initialized bundle");
        refused(() -> new ByteStaticMemoryTransferDecoderV1("x86:LE:32:default"), "foreign language");
        var decoder = new ByteStaticMemoryTransferDecoderV1("x86:LE:64:default");
        var call = decoder.decode(0x401000, bytes("ff1500000000"));
        positive(call, "indirect-call", "0x401006", "COPY", 0, "CALLIND", 3, List.of(0));
        positive(decoder.decode(0x401000, bytes("ff25faffffff")), "indirect-jump", "0x401000", "BRANCHIND", 0, "BRANCHIND", 0, List.of());
        positive(decoder.decode(0x401000, bytes("ff2510000000")), "indirect-jump", "0x401016", "BRANCHIND", 0, "BRANCHIND", 0, List.of());
        positive(decoder.decode(0x401000, bytes("ff15faffffff")), "indirect-call", "0x401000", "COPY", 0, "CALLIND", 3, List.of(0));
        positive(decoder.decode(0x401000, bytes("ff142578563412")), "indirect-call", "0x12345678", "COPY", 0, "CALLIND", 3, List.of(0));
        positive(decoder.decode(0x8000000000000000L, bytes("ff1500000000")), "indirect-call", "0x8000000000000006", "COPY", 0, "CALLIND", 3, List.of(0));
        unresolved(decoder.decode(-16L, bytes("ff2509000000")), "pointer-slot-wrap");
        for (String encoded : List.of("ffd0", "ffe0")) unresolved(decoder.decode(0x401000, bytes(encoded)), "register-transfer");
        for (String encoded : List.of("ff10", "ff1424", "ff148500000000", "64ff1500000000"))
            unresolved(decoder.decode(0x401000, bytes(encoded)), "nonstatic-load-address");
        for (String encoded : List.of("66ff1500000000", "ff2d00000000"))
            unresolved(decoder.decode(0x401000, bytes(encoded)), "unsupported-value-transform");
        unresolved(decoder.decode(0x401000, bytes("ff1d00000000")), "nonmemory-indirect-value");
        for (String encoded : List.of("e800000000", "c3", "90")) unresolved(decoder.decode(0x401000, bytes(encoded)), "not-indirect-transfer");
        unresolved(decoder.decode(0x401000, bytes("cc")), "unsupported-trap-or-userop");
        unresolved(decoder.decode(0x401000, bytes("0f22c0")), "unsupported-context");
        for (byte[] malformed : List.of(new byte[0], new byte[33], bytes("ff15"))) refused(() -> decoder.decode(0x401000, malformed), "invalid byte window");
        refused(() -> decoder.decode(0x401000, null), "null byte window");
        refused(() -> decoder.decode(-1L, bytes("ff25faffffff")), "instruction window wraps");
        byte[] input = bytes("ff1500000000");
        var immutable = decoder.decode(0x401000, input);
        input[0] = 0;
        byte[] exposed = immutable.bytes(); exposed[0] = 0;
        equal("ff1500000000", HexFormat.of().formatHex(immutable.bytes()), "owned instruction bytes");
        refused(() -> immutable.rawCopyOpIndices().add(999), "immutable copy chain");
        Thread.currentThread().interrupt();
        try { refused(() -> decoder.decode(0x401000, bytes("ff1500000000")), "cancellation"); }
        finally { Thread.interrupted(); }

        var language = SleighLanguageProvider.getSleighLanguageProvider().getLanguage(new LanguageID("x86:LE:64:default"));
        ram = language.getDefaultSpace();
        unique = language.getAddressFactory().getAddressSpace("unique");
        constants = language.getAddressFactory().getAddressSpace("const");
        registers = language.getAddressFactory().getAddressSpace("register");
        rawControls();
        System.out.println("STATIC-MEMORY-TRANSFER-CONTROLS passed=" + checks);
    }

    private static void rawControls() throws Exception {
        Varnode value = node(unique, 0x100, 8), copy = node(unique, 0x200, 8), register = node(registers, 0x20, 8);
        Varnode slot = node(constants, 0x5000, 8), token = node(constants, Integer.toUnsignedLong(ram.getSpaceID()), 4);
        PcodeOp load = op(PcodeOp.LOAD, value, token, slot);
        PcodeOp copied = op(PcodeOp.COPY, copy, value);
        PcodeOp stackStore = op(PcodeOp.STORE, null, token, register, node(constants, 0x401006, 8));
        PcodeOp transfer = op(PcodeOp.CALLIND, null, copy);
        var explicit = inspect(load, copied, stackStore, transfer);
        equal("single-static-load-exact-transfer-v1", explicit.relationship(), "explicit load stays distinct");
        equal("0x5000", explicit.slot(), "constant pointer slot");
        equal(0, explicit.readIndex(), "explicit load index");
        equal(3, explicit.transferIndex(), "explicit transfer index");
        equal(List.of(1), explicit.copies(), "explicit transparent copy");
        PcodeOp implicit = op(PcodeOp.COPY, value, node(ram, 0x5000, 8));
        equal(List.of(0, 1), inspect(implicit, copied, transfer).copies(), "multiple exact copies preserve memory read");
        equal("static-ram-varnode-exact-transfer-v1", inspect(implicit, copied, transfer).relationship(), "implicit memory read stays distinct");
        reject("overlapping-value-write", load, op(PcodeOp.COPY, node(unique, 0x104, 4), node(constants, 1, 4)), copied, transfer);
        reject("overlapping-value-write", load, copied, op(PcodeOp.COPY, node(unique, 0x1ff, 2), node(constants, 1, 2)), transfer);
        reject("register-transfer", load, op(PcodeOp.COPY, value, register), copied, transfer);
        reject("multiple-memory-loads", load, op(PcodeOp.LOAD, node(unique, 0x300, 8), token, slot), copied, transfer);
        reject("multiple-memory-loads", load, op(PcodeOp.COPY, node(unique, 0x300, 8), node(ram, 0x6000, 8)), copied, transfer);
        reject("nondefault-load-space", op(PcodeOp.LOAD, value, node(constants, Integer.toUnsignedLong(ram.getSpaceID()) + 1, 4), slot), copied, transfer);
        reject("nondefault-load-space", op(PcodeOp.LOAD, value, node(constants, Integer.toUnsignedLong(ram.getSpaceID()), 1), slot), copied, transfer);
        reject("nonstatic-load-address", op(PcodeOp.LOAD, value, token, node(constants, 0x5000, 4)), copied, transfer);
        reject("nonstatic-load-address", op(PcodeOp.LOAD, value, token, register), copied, transfer);
        reject("unsupported-pointer-width", load, op(PcodeOp.CALLIND, null, node(unique, 0x100, 4)));
        reject("unsupported-value-transform", load, op(PcodeOp.INT_ADD, copy, value, node(constants, 1, 8)), transfer);
        reject("memory-write-before-read", stackStore, load, copied, transfer);
        reject("memory-write-before-read", op(PcodeOp.COPY, node(ram, 0x5004, 4), node(constants, 0, 4)), implicit, copied, transfer);
        reject("competing-or-invalid-transfers", load, copied, transfer, transfer);
        reject("internal-pcode-control", op(PcodeOp.BRANCH, null, node(constants, 1, 8)), load, copied, transfer);
        reject("unsupported-pcode-or-userop", op(PcodeOp.CALLOTHER, null, node(constants, 0, 4)), load, copied, transfer);
        reject("trailing-pcode-after-transfer", load, copied, transfer, op(PcodeOp.COPY, node(unique, 0x300, 8), node(constants, 0, 8)));
        reject("missing-value-definition", transfer);
        AddressSpace otherRam = new GenericAddressSpace("other-memory", 64, AddressSpace.TYPE_RAM, 99);
        reject("nondefault-memory-space", op(PcodeOp.COPY, value, node(otherRam, 0x5000, 8)), copied, transfer);
        reject("pointer-slot-wrap", op(PcodeOp.LOAD, value, token, node(constants, -1, 8)), copied, transfer);
        // Once copied, a later write to the old temporary cannot change the captured transfer value.
        equal("0x5000", inspect(load, copied, op(PcodeOp.COPY, node(unique, 0x104, 4), node(constants, 1, 4)), transfer).slot(), "use-def liveness is exact");
        equal("pcode-bound", ByteStaticMemoryTransferDecoderV1.inspectPcode(new PcodeOp[4097], ram, "indirect-call").reason(), "pcode hard bound");
        equal("unsupported-transfer-profile", ByteStaticMemoryTransferDecoderV1.inspectPcode(new PcodeOp[] {load, copied, transfer}, ram, "direct-call").reason(), "direct flow cannot borrow memory proof");
    }

    private static ByteStaticMemoryTransferDecoderV1.TransferProof inspect(PcodeOp... operations) throws Exception {
        return ByteStaticMemoryTransferDecoderV1.inspectPcode(operations, ram, "indirect-call");
    }
    private static void reject(String reason, PcodeOp... operations) throws Exception {
        var proof = inspect(operations);
        equal(reason, proof.reason(), "raw p-code refusal");
        equal(null, proof.slot(), "refused proof has no slot");
        equal("unresolved", proof.relationship(), "refused relationship");
    }
    private static PcodeOp op(int opcode, Varnode output, Varnode... inputs) { return new PcodeOp(ram.getAddress(0x401000), 0, opcode, inputs, output); }
    private static Varnode node(AddressSpace space, long offset, int size) { return new Varnode(space.getAddress(offset), size); }
    private static void positive(ByteStaticMemoryTransferDecoderV1.StaticMemoryTransfer witness, String classification, String slot,
            String readOpcode, int readIndex, String transferOpcode, int transferIndex, List<Integer> copies) {
        equal(classification, witness.classification(), "physical computed flow retained");
        equal(slot, witness.pointerSlotAddress(), "static slot address");
        equal(8, witness.pointerWidthBytes(), "pointer width");
        equal("static-ram-varnode-exact-transfer-v1", witness.relationship(), "implicit memory-read semantics");
        equal(readOpcode, witness.rawReadOpcode(), "raw read opcode");
        equal(readIndex, witness.rawReadOpIndex(), "raw read index");
        equal(transferOpcode, witness.rawTransferOpcode(), "raw transfer opcode");
        equal(transferIndex, witness.rawTransferOpIndex(), "raw transfer index");
        equal(copies, witness.rawCopyOpIndices(), "transparent copy chain");
        equal(null, witness.unresolvedReason(), "positive proof has no unresolved reason");
        equal("language-default-no-commits-v1", witness.contextStatus(), "default context only");
    }
    private static void unresolved(ByteStaticMemoryTransferDecoderV1.StaticMemoryTransfer witness, String reason) {
        equal("unresolved", witness.relationship(), "unresolved relationship");
        equal(reason, witness.unresolvedReason(), "unresolved reason");
        equal(null, witness.pointerSlotAddress(), "unresolved slot stays absent");
        equal(null, witness.pointerWidthBytes(), "unresolved pointer width stays absent");
    }
    private static byte[] bytes(String hex) { return HexFormat.of().parseHex(hex); }
    private static void equal(Object expected, Object actual, String label) {
        if (!java.util.Objects.equals(expected, actual)) throw new AssertionError(label + ": expected " + expected + ", actual " + actual);
        checks++;
    }
    private interface Checked { void run() throws Exception; }
    private static void refused(Checked action, String label) throws Exception {
        try { action.run(); } catch (Exception expected) { checks++; return; }
        throw new AssertionError("accepted " + label);
    }
}
