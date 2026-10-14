import ghidra.GhidraApplicationLayout;
import ghidra.framework.Application;
import ghidra.framework.HeadlessGhidraApplicationConfiguration;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.*;
import ghidra.program.model.data.Undefined1DataType;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.*;
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
                program.getMemory().createInitializedBlock("code", code, 16, (byte)0, TaskMonitor.DUMMY, false);
                program.getMemory().createInitializedBlock("constant", constant, 8, (byte)0, TaskMonitor.DUMMY, false);
                // movsd qword ptr [rip+0xff8],xmm0; ret. Actual SLEIGH pcode, no proxy instructions.
                program.getMemory().setBytes(code, new byte[]{(byte)0xf2,0x0f,0x10,0x05,(byte)0xf8,0x0f,0,0,(byte)0xc3});
                program.getMemory().setBytes(constant, new byte[]{0,0,0,0,0,0,(byte)0xe0,0x3f});
                var disassembly = new DisassembleCommand(code, new AddressSet(code, code.add(8)), true);
                ReferencedBytesProbe.check(disassembly.applyTo(program, TaskMonitor.DUMMY), disassembly.getStatusMsg());
                Function function = program.getFunctionManager().createFunction("probe", code, new AddressSet(code, code.add(8)), SourceType.USER_DEFINED);
                // Explicit controlled setup: the listing owns precisely one byte, while the read owns eight.
                Data data = program.getListing().createData(constant, Undefined1DataType.dataType);
                String initializer = data.getDefaultValueRepresentation();
                ReferencedBytesProbe.check(data.getLength() == 1 && initializer.equals("00h"), "actual one-byte listing setup: length=" + data.getLength() + ", initializer=" + initializer);
                ExportProgramModel exporter = new ExportProgramModel();
                ReferencedBytesProbe.field(exporter, "currentProgram", program);
                ReferencedBytesProbe.field(exporter, "monitor", TaskMonitor.DUMMY);
                ReferencedBytesProbe.invoke(exporter, "collectReferencedByteEvidence", new Class<?>[]{List.class}, List.of(function));
                Object global = ReferencedBytesProbe.invoke(exporter, "globalAt", new Class<?>[]{Address.class}, constant);
                Method render = Arrays.stream(ExportProgramModel.class.getDeclaredMethods()).filter(m -> m.getName().equals("renderGlobal")).findFirst().orElseThrow();
                render.setAccessible(true);
                String record = (String)render.invoke(null, global);
                Field evidence = ExportProgramModel.class.getDeclaredField("referencedByteEvidence"); evidence.setAccessible(true);
                String windows = evidence.get(exporter).toString();
                ReferencedBytesProbe.check(record.contains("\"initializer\": \"00h\""), "export must preserve one-byte initializer: " + record);
                ReferencedBytesProbe.check(windows.contains("\"requestedLength\":8") && windows.contains("pcode_direct_read") &&
                    windows.contains("000000000000e03f") && windows.contains("\"availability\":\"available\""), "exact eight-byte evidence: " + windows);
                ReferencedBytesProbe.check(record.contains("000000000000e03f") && record.contains("\"requestedLength\":8"), "rendered global includes exact evidence");
                ReferencedBytesProbe.check(data.getLength() == 1 && data.getDefaultValueRepresentation().equals(initializer), "export must not rewrite listing data");
                System.out.println("controlled real listing passed: one-byte initializer 00h retained; exact eight-byte direct read 000000000000e03f");
            } finally { program.endTransaction(transaction, false); }
        } finally { program.release(consumer); }
        System.exit(0);
    }
}
