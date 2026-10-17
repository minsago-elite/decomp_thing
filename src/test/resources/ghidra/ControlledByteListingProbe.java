import ghidra.GhidraApplicationLayout;
import ghidra.framework.Application;
import ghidra.framework.HeadlessGhidraApplicationConfiguration;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.*;
import ghidra.program.model.data.Undefined1DataType;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.task.TaskMonitor;
import java.nio.file.Path;
import java.lang.reflect.*;
import java.util.*;

/** Controlled real ProgramDB listing, distinct from unmodified stripped ELF analysis. */
public final class ControlledByteListingProbe {
    public static void main(String[] args) throws Exception {
        Application.initializeApplication(new GhidraApplicationLayout(Path.of(args[0]).toFile()),
            new HeadlessGhidraApplicationConfiguration());
        var language = DefaultLanguageService.getLanguageService().getLanguage(new LanguageID("x86:LE:64:default"));
        Object consumer = new Object();
        ProgramDB program = new ProgramDB("controlled-one-byte-listing", language, language.getDefaultCompilerSpec(), consumer);
        try {
            int transaction = program.startTransaction("authored byte listing fixture");
            try {
                Address code = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x1000);
                Address constant = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x2000);
                program.getMemory().createInitializedBlock("code", code, 32, (byte)0, TaskMonitor.DUMMY, false);
                program.getMemory().createInitializedBlock("constant", constant, 24, (byte)0, TaskMonitor.DUMMY, false);
                // Three authored RIP-relative instructions, each reading its own eight-byte constant.
                // Actual SLEIGH pcode, no proxy instructions and no original-input analysis.
                byte[] instructionOpcodes = {0x10,0x58,0x59};
                String[] mnemonics = {"MOVSD","ADDSD","MULSD"};
                int[] pcodeOpcodes = {PcodeOp.COPY,PcodeOp.FLOAT_ADD,PcodeOp.FLOAT_MULT};
                byte[] payload = {0,0,0,0,0,0,(byte)0xe0,0x3f};
                for (int index=0; index<3; index++) {
                    program.getMemory().setBytes(code.add(index*8), new byte[]{(byte)0xf2,0x0f,instructionOpcodes[index],0x05,(byte)0xf8,0x0f,0,0});
                    program.getMemory().setBytes(constant.add(index*8), payload);
                }
                program.getMemory().setByte(code.add(24), (byte)0xc3);
                var disassembly = new DisassembleCommand(code, new AddressSet(code, code.add(24)), true);
                ReferencedBytesProbe.check(disassembly.applyTo(program, TaskMonitor.DUMMY), disassembly.getStatusMsg());
                Function function = program.getFunctionManager().createFunction("probe", code, new AddressSet(code, code.add(24)), SourceType.USER_DEFINED);
                Data[] data = new Data[3];
                for (int index=0; index<3; index++) {
                    Instruction instruction = program.getListing().getInstructionAt(code.add(index*8));
                    final int expectedOpcode = pcodeOpcodes[index];
                    ReferencedBytesProbe.check(instruction.getMnemonicString().equalsIgnoreCase(mnemonics[index]) &&
                        Arrays.stream(instruction.getPcode()).anyMatch(op -> op.getOpcode() == expectedOpcode), "actual authored instruction and raw pcode " + mnemonics[index]);
                    // Explicit controlled setup: each listing owns one byte; each instruction reads eight.
                    data[index] = program.getListing().createData(constant.add(index*8), Undefined1DataType.dataType);
                    ReferencedBytesProbe.check(data[index].getLength() == 1 && data[index].getDefaultValueRepresentation().equals("00h"), "actual one-byte listing setup");
                }
                ExportProgramModel exporter = new ExportProgramModel();
                ReferencedBytesProbe.field(exporter, "currentProgram", program);
                ReferencedBytesProbe.field(exporter, "monitor", TaskMonitor.DUMMY);
                ReferencedBytesProbe.invoke(exporter, "collectReferencedByteEvidence", new Class<?>[]{List.class}, List.of(function));
                Method render = Arrays.stream(ExportProgramModel.class.getDeclaredMethods()).filter(m -> m.getName().equals("renderGlobal")).findFirst().orElseThrow();
                render.setAccessible(true);
                Field evidence = ExportProgramModel.class.getDeclaredField("referencedByteEvidence"); evidence.setAccessible(true);
                ReferencedBytesProbe.check(((Map<?,?>)evidence.get(exporter)).size() == 3, "three distinct authored global records");
                for (int index=0; index<3; index++) {
                    Address target = constant.add(index*8), origin = code.add(index*8);
                    Object global = ReferencedBytesProbe.invoke(exporter, "globalAt", new Class<?>[]{Address.class}, target);
                    String record = (String)render.invoke(null, global);
                    ReferencedBytesProbe.check(record.contains("\"initializer\": \"00h\""), "preserve one-byte initializer: " + record);
                    ReferencedBytesProbe.check(record.contains("\"requestedLength\":8") && record.contains("\"widthBasis\":\"pcode_direct_read\"") &&
                        record.contains("000000000000e03f") && record.contains("\"availability\":\"available\"") &&
                        record.contains("\"referenceAddress\":\"0x" + Long.toHexString(target.getOffset()) + "\"") &&
                        record.contains("\"instructionAddress\":\"0x" + Long.toHexString(origin.getOffset()) + "\""), "exact authored instruction/target/eight-byte evidence: " + record);
                    ReferencedBytesProbe.check(data[index].getLength() == 1 && data[index].getDefaultValueRepresentation().equals("00h"), "export must not rewrite listing data");
                }
                System.out.println("controlled real listing passed: MOVSD/COPY, ADDSD/FLOAT_ADD and MULSD/FLOAT_MULT retain one-byte 00h initializers and exact leading-zero eight-byte evidence");
            } finally { program.endTransaction(transaction, false); }
        } finally { program.release(consumer); }
        System.exit(0);
    }
}
