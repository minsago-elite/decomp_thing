"""Exercise the actual diagnostic scripts with authored, inert Ghidra API doubles.

No analyzed executable is loaded. Java outputs and temporary source files stay
under the repository's build directory.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]


STUBS = {
    "ghidra/framework/options/OptionType.java": """
package ghidra.framework.options;
public enum OptionType { BOOLEAN_TYPE, INT_TYPE }
""",
    "ghidra/framework/options/Options.java": r"""
package ghidra.framework.options;
import java.util.*;
public class Options {
    public final Map<String,Boolean> values = new HashMap<>();
    public Options() {
        values.put("Stack", true);
        values.put("Decompiler Switch Analysis", true);
        values.put("Ignored", true);
        values.put("escaped \"name\"", false);
    }
    public boolean contains(String name) { return values.containsKey(name) || name.equals("ThreadCount"); }
    public OptionType getType(String name) { return name.equals("ThreadCount") ? OptionType.INT_TYPE : OptionType.BOOLEAN_TYPE; }
    public boolean getBoolean(String name, boolean fallback) { return values.getOrDefault(name, fallback); }
    public void setBoolean(String name, boolean value) { if (!name.equals("Ignored")) values.put(name, value); }
}
""",
    "ghidra/program/model/address/AddressSpace.java": """
package ghidra.program.model.address;
public class AddressSpace {}
""",
    "ghidra/program/model/address/Address.java": """
package ghidra.program.model.address;
public class Address {
    private final long offset; private final AddressSpace space;
    public Address(long offset, AddressSpace space) { this.offset=offset; this.space=space; }
    public long getOffset() { return offset; }
    public AddressSpace getAddressSpace() { return space; }
}
""",
    "ghidra/program/model/address/AddressFactory.java": """
package ghidra.program.model.address;
public class AddressFactory {
    private final AddressSpace space;
    public AddressFactory(AddressSpace space) { this.space=space; }
    public AddressSpace getDefaultAddressSpace() { return space; }
}
""",
    "ghidra/program/model/listing/Function.java": """
package ghidra.program.model.listing;
import ghidra.program.model.address.*;
public class Function {
    private final Address entry;
    public Function(Address entry) { this.entry=entry; }
    public Address getEntryPoint() { return entry; }
}
""",
    "ghidra/program/model/listing/FunctionIterator.java": """
package ghidra.program.model.listing;
public interface FunctionIterator extends java.util.Iterator<Function> {}
""",
    "ghidra/program/model/listing/Program.java": """
package ghidra.program.model.listing;
import ghidra.framework.options.*;
import ghidra.program.model.address.*;
public class Program {
    public static final String ANALYSIS_PROPERTIES="analysis";
    public final Options options=new Options();
    public final AddressSpace space=new AddressSpace();
    public String mode="valid";
    public Options getOptions(String name) { return options; }
    public String getExecutableSHA256() { return mode.equals("missing-sha") ? null : "A".repeat(64); }
    public Address getImageBase() { return new Address(0, mode.equals("foreign-base") ? new AddressSpace() : space); }
    public AddressFactory getAddressFactory() { return new AddressFactory(space); }
    public Object getLanguageID() { return "x86:LE:64:default"; }
    public CompilerSpec getCompilerSpec() { return new CompilerSpec(); }
    public static class CompilerSpec { public Object getCompilerSpecID() { return "gcc"; } }
    public FunctionManager getFunctionManager() { return new FunctionManager(); }
    public class FunctionManager {
        public FunctionIterator getFunctions(boolean forward) {
            final long[] entries = mode.equals("duplicate") ? new long[]{1, 1} : new long[]{-1, 32, Long.MIN_VALUE, 0};
            return new FunctionIterator() {
                int index=0;
                public boolean hasNext() { return index < (mode.equals("over-limit") ? 1_000_001 : entries.length); }
                public Function next() {
                    long entry=mode.equals("over-limit") ? index : entries[index]; index++;
                    return new Function(new Address(entry, mode.equals("foreign-entry") ? new AddressSpace() : space));
                }
            };
        }
    }
}
""",
    "ghidra/app/script/GhidraScript.java": """
package ghidra.app.script;
import ghidra.program.model.listing.Program;
public abstract class GhidraScript {
    public Program currentProgram=new Program();
    public String[] arguments=new String[0];
    public Monitor monitor=new Monitor();
    protected abstract void run() throws Exception;
    protected String[] getScriptArgs() { return arguments; }
    protected void println(String value) { System.out.println(value); }
    public static class Monitor {
        public int remaining=Integer.MAX_VALUE;
        public void checkCancelled() { if (--remaining < 0) throw new IllegalStateException("cancelled"); }
    }
}
""",
    "Harness.java": """
import java.util.Arrays;
import ghidra.app.script.GhidraScript;
public class Harness {
    public static void main(String[] args) throws Exception {
        GhidraScript script = args[0].equals("disable") ? new DisableAnalyzers() : new FunctionCensus();
        script.currentProgram.mode=args[1];
        script.arguments=Arrays.copyOfRange(args,2,args.length);
        if (args[1].equals("disabled")) script.currentProgram.options.setBoolean("Stack",false);
        if (args[1].equals("cancelled")) script.monitor.remaining=0;
        try {
            if (script instanceof DisableAnalyzers) ((DisableAnalyzers)script).run();
            else ((FunctionCensus)script).run();
        } catch (Exception failure) {
            System.err.println(failure.getMessage());
            System.err.println("Stack="+script.currentProgram.options.getBoolean("Stack",true));
            System.exit(2);
        }
    }
}
""",
}


@unittest.skipUnless(shutil.which("javac") and shutil.which("java"), "requires a JDK for authored API doubles")
class GhidraAnalysisExperimentTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        build = ROOT / "build"
        build.mkdir(exist_ok=True)
        cls.temporary = tempfile.TemporaryDirectory(prefix="analysis-script-controls-", dir=build)
        cls.directory = Path(cls.temporary.name)
        cls.classes = cls.directory / "classes"
        cls.classes.mkdir()
        sources = []
        for name, body in STUBS.items():
            path = cls.directory / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(body)
            sources.append(str(path))
        sources.extend(str(ROOT / "scripts/ghidra-analysis-experiment" / name)
                       for name in ("DisableAnalyzers.java", "FunctionCensus.java"))
        compilation = subprocess.run(
            ["javac", "-J-XX:-UsePerfData", f"-J-Djava.io.tmpdir={cls.directory}",
             "-d", str(cls.classes), *sources],
            capture_output=True, text=True, timeout=30,
        )
        if compilation.returncode:
            cls.temporary.cleanup()
            raise AssertionError(compilation.stderr)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.temporary.cleanup()

    def setUp(self) -> None:
        self.case = tempfile.TemporaryDirectory(prefix="case-", dir=self.directory)
        self.case_path = Path(self.case.name)
        self.output = self.case_path / "entries.json"
        self.addCleanup(self.case.cleanup)

    def invoke(self, operation: str, mode: str = "valid", *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["java", "-Xmx256m", "-XX:-UsePerfData", f"-Djava.io.tmpdir={self.case_path}",
             "-cp", str(self.classes), "Harness", operation, mode, *args],
            cwd=self.case_path, capture_output=True, text=True, timeout=20, check=False,
        )

    def test_census_retains_unsigned_sorted_complete_entries_and_delimited_digest(self) -> None:
        result = self.invoke("census", "valid", str(self.output))
        self.assertEqual(0, result.returncode, result.stderr)
        document = json.loads(self.output.read_bytes())
        self.assertEqual({"schemaVersion", "kind", "authority", "inputSha256", "imageBase", "languageId",
                          "compilerSpecId", "entries", "entryCount", "entriesSha256", "disabledAnalyzers"}, set(document))
        entries = ["0x0", "0x20", "0x8000000000000000", "0xffffffffffffffff"]
        self.assertEqual(entries, document["entries"])
        self.assertEqual(4, document["entryCount"])
        self.assertEqual(hashlib.sha256("".join(e + "\n" for e in entries).encode()).hexdigest(), document["entriesSha256"])
        self.assertEqual("a" * 64, document["inputSha256"])
        self.assertEqual([], document["disabledAnalyzers"])
        self.assertEqual("diagnostic-only", document["authority"])
        self.assertEqual(0o600, self.output.stat().st_mode & 0o777)
        self.assertEqual([self.output], list(self.case_path.iterdir()))

    def test_disabled_options_are_verified_and_json_escaped(self) -> None:
        result = self.invoke("census", "disabled", str(self.output), 'Stack,escaped "name"')
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual(["Stack", 'escaped "name"'], json.loads(self.output.read_bytes())["disabledAnalyzers"])

    def test_unknown_option_does_not_partially_disable_valid_predecessor(self) -> None:
        result = self.invoke("disable", "valid", "Stack,Decompiler Switch Analysis - One Time")
        self.assertEqual(2, result.returncode)
        self.assertIn("unknown boolean analyzer option", result.stderr)
        self.assertIn("Stack=true", result.stderr)
        self.assertNotIn("disabled", result.stdout)

    def test_disable_verifies_actual_boolean_state(self) -> None:
        result = self.invoke("disable", "valid", "Decompiler Switch Analysis,Stack")
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertIn("disabled Decompiler Switch Analysis", result.stdout)
        self.assertIn("disabled Stack", result.stdout)
        ignored = self.invoke("disable", "valid", "Ignored")
        self.assertEqual(2, ignored.returncode)
        self.assertIn("remained enabled", ignored.stderr)
        self.assertNotIn("disabled", ignored.stdout)

    def test_malformed_or_nonboolean_disable_requests_are_rejected(self) -> None:
        for request in ("", "Stack,", "Stack,Stack", "ThreadCount", "x" * 257):
            with self.subTest(request=request):
                result = self.invoke("disable", "valid", request)
                self.assertEqual(2, result.returncode)
                self.assertNotIn("disabled", result.stdout)

    def test_census_refuses_unknown_enabled_nonboolean_or_duplicate_option(self) -> None:
        for request in ("Stack", "Missing", "ThreadCount", "Stack,Stack", ""):
            with self.subTest(request=request):
                result = self.invoke("census", "valid", str(self.output), request)
                self.assertEqual(2, result.returncode)
                self.assertFalse(self.output.exists())

    def test_incomplete_or_invalid_population_cannot_publish(self) -> None:
        for mode in ("duplicate", "missing-sha", "foreign-base", "foreign-entry", "cancelled", "over-limit"):
            with self.subTest(mode=mode):
                result = self.invoke("census", mode, str(self.output))
                self.assertEqual(2, result.returncode, result.stderr)
                self.assertFalse(self.output.exists())
                self.assertEqual([], list(self.case_path.iterdir()))

    def test_existing_file_or_symlink_is_never_overwritten(self) -> None:
        self.output.write_bytes(b"previous evidence\n")
        result = self.invoke("census", "valid", str(self.output))
        self.assertEqual(2, result.returncode)
        self.assertEqual(b"previous evidence\n", self.output.read_bytes())
        self.output.unlink()
        self.output.symlink_to("missing")
        result = self.invoke("census", "valid", str(self.output))
        self.assertEqual(2, result.returncode)
        self.assertTrue(self.output.is_symlink())
        self.assertFalse((self.case_path / "missing").exists())

    def test_path_escape_and_missing_output_argument_are_rejected(self) -> None:
        escaped = self.directory / "escaped.json"
        self.assertEqual(2, self.invoke("census", "valid", str(escaped)).returncode)
        self.assertFalse(escaped.exists())
        self.assertEqual(2, self.invoke("census").returncode)


if __name__ == "__main__":
    unittest.main()
