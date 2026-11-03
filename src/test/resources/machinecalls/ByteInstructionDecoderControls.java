import decompengine.ghidra.ByteInstructionDecoderV1;
import decompengine.ghidra.ByteInstructionDecoderV1.DecodedInstruction;
import java.util.HexFormat;
import java.util.List;

/** Authored byte strings only: no ELF import, program database, or analysis. */
public final class ByteInstructionDecoderControls {
    private static final String LANGUAGE = "x86:LE:64:default";
    private static int cases;

    public static void main(String[] args) throws Exception {
        refused(() -> new ByteInstructionDecoderV1(LANGUAGE), "uninitialized application");
        ByteInstructionDecoderV1.initialize(args[0]);
        ByteInstructionDecoderV1.initialize(args[0]);
        refused(() -> ByteInstructionDecoderV1.initialize(args[1]), "foreign initialized bundle");
        refused(() -> new ByteInstructionDecoderV1("x86:LE:32:default"), "foreign language");
        ByteInstructionDecoderV1 decoder = new ByteInstructionDecoderV1(LANGUAGE);

        DecodedInstruction call = decoder.decode(0x1000, bytes("e80b0000009090"));
        equal("direct-call", call.classification(), "typed direct call");
        equal("0x1010", call.directCallTarget(), "raw CALL target");
        equal(List.of("0x1010"), call.directTargets(), "typed flow target");
        equal("0x1005", call.fallthrough(), "call fallthrough");
        equal(5, call.length(), "single instruction length");
        truth(call.call() && !call.computed(), "direct flags");
        equal("language-default-no-commits-v1", call.contextStatus(), "default context");
        equal("0x1000", decoder.decode(0x1000, bytes("e8fbffffff")).directCallTarget(), "negative displacement");
        equal("0x8000000000000010", decoder.decode(0x8000000000000000L, bytes("e80b000000")).directCallTarget(), "unsigned high address");

        for (String encoded : List.of("ffd0", "ff1500000000")) {
            DecodedInstruction indirect = decoder.decode(0x1000, bytes(encoded));
            equal("indirect-call", indirect.classification(), "indirect call classification");
            truth(indirect.call() && indirect.computed() && indirect.directCallTarget() == null
                && indirect.directTargets().isEmpty(), "indirect is not direct evidence");
        }
        DecodedInstruction jump = decoder.decode(0x1000, bytes("eb05"));
        equal("direct-jump", jump.classification(), "direct jump");
        equal(List.of("0x1007"), jump.directTargets(), "jump target");
        truth(jump.fallthrough() == null && !jump.call(), "jump has no call/fallthrough");
        DecodedInstruction conditional = decoder.decode(0x1000, bytes("7505"));
        equal("direct-jump", conditional.classification(), "conditional jump");
        truth(conditional.conditional(), "conditional flag");
        equal("0x1002", conditional.fallthrough(), "conditional fallthrough");
        equal("indirect-jump", decoder.decode(0x1000, bytes("ffe0")).classification(), "computed jump");
        DecodedInstruction returned = decoder.decode(0x1000, bytes("c3"));
        equal("return", returned.classification(), "return");
        truth(returned.terminal() && !returned.computed() && !returned.call() && !returned.jump()
            && returned.fallthrough() == null, "return boundary and bridge flow flags");
        DecodedInstruction nop = decoder.decode(0x1000, bytes("90e80b000000"));
        equal("ordinary", nop.classification(), "ordinary with later call bytes");
        equal(1, nop.length(), "does not follow trailing bytes");
        truth(!nop.call() && nop.directCallTarget() == null, "later bytes not called");

        for (String encoded : List.of("cc", "0f0b", "0f05")) {
            DecodedInstruction trap = decoder.decode(0x1000, bytes(encoded));
            truth(trap.classification().startsWith("unsupported-"), "trap/userop remains unsupported: " + encoded);
            truth(trap.directCallTarget() == null, "trap cannot publish direct call");
        }
        equal("unsupported-context", decoder.decode(0x1000, bytes("0f22c0")).classification(), "control register write");
        equal("unsupported-context", decoder.decode(0x1000, bytes("ca0000")).classification(), "far return context");

        byte[] owned = bytes("e80b000000");
        DecodedInstruction stable = decoder.decode(0x1000, owned);
        owned[0] = 0;
        byte[] exposed = stable.bytes();
        exposed[0] = 0;
        equal("e80b000000", HexFormat.of().formatHex(stable.bytes()), "owned bytes remain immutable");
        refused(() -> stable.directTargets().add("0x0"), "immutable direct target list");

        for (byte[] malformed : List.of(new byte[0], bytes("e8"), bytes("0f"), new byte[33])) {
            refused(() -> decoder.decode(0x1000, malformed), "truncated or oversized bytes");
        }
        refused(() -> decoder.decode(0x1000, null), "null bytes");
        refused(() -> decoder.decode(-1L, bytes("9090")), "input extent wraps address space");
        Thread.currentThread().interrupt();
        try { refused(() -> decoder.decode(0x1000, bytes("90")), "interruption"); }
        finally { Thread.interrupted(); }
        // Independent calls cannot inherit a preceding instruction's mode/flow state.
        DecodedInstruction repeated = decoder.decode(0x1000, bytes("e80b0000009090"));
        equal(call.directCallTarget(), repeated.directCallTarget(), "repeated independent call target");
        equal(HexFormat.of().formatHex(call.bytes()), HexFormat.of().formatHex(repeated.bytes()), "repeated independent instruction bytes");
        System.out.println("BYTE-DECODER-CONTROLS passed=" + cases);
    }

    private static byte[] bytes(String hex) { return HexFormat.of().parseHex(hex); }
    private static void truth(boolean value, String label) {
        if (!value) throw new AssertionError(label);
        cases++;
    }
    private static void equal(Object expected, Object actual, String label) {
        if (!java.util.Objects.equals(expected, actual)) throw new AssertionError(label + ": expected " + expected + ", actual " + actual);
        cases++;
    }
    private interface Checked { void run() throws Exception; }
    private static void refused(Checked action, String label) throws Exception {
        try { action.run(); }
        catch (Exception expected) { cases++; return; }
        throw new AssertionError("accepted " + label);
    }
}
