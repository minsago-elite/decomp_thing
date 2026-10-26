"""Offline source-contract guards, NOT executed LibTooling/lifetime qualification.

The pinned native positive and sanitizer smoke still require authorized toolchain
acquisition and an authenticated worker. These guards prevent reintroducing the
known ownership patterns without executing an unapproved compiler.
"""

from pathlib import Path
import unittest


class ProbeLifetimeSourceContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = Path(__file__).with_name("libtooling-probe.cpp").read_text(encoding="utf-8")
        cls.main = cls.source.split("int main(int argc, char **argv) {", 1)[1]

    def test_file_manager_retains_heap_backed_intrusive_owner_across_invocation(self):
        self.assertIn('#include "llvm/ADT/IntrusiveRefCntPtr.h"', self.source)
        owner = "llvm::IntrusiveRefCntPtr<FileManager> files(new FileManager(filesystemOptions));"
        self.assertIn(owner, self.main)
        self.assertLess(self.main.index(owner), self.main.index("tooling::ToolInvocation invocation"))
        self.assertIn("std::move(action), files.get())", self.main)
        self.assertNotIn("FileManager files(", self.main)
        self.assertNotIn("&files", self.main)

    def test_report_reads_main_owned_result_not_destroyed_action_or_consumer(self):
        self.assertLess(self.main.index("ProbeResult result;"),
                        self.main.index("std::make_unique<ProbeAction>(result)"))
        self.assertNotIn("actionView", self.source)
        self.assertNotIn("consumerView", self.source)
        self.assertIn("std::make_unique<ProbeConsumer>(compiler, result)", self.source)
        self.assertIn("std::make_unique<MacroCallbackProbe>(result.macroObservations)", self.source)
        after_run = self.main.split("invocation.run()", 1)[1]
        self.assertNotIn("action->", after_run)
        self.assertIn("result.targetTriple", after_run)
        self.assertIn("result.runtimeLangOptionsChecks", after_run)
        self.assertIn("result.macroObservations", after_run)

    def test_missing_translation_unit_cannot_emit_success_report(self):
        self.assertIn("bool translationUnitHandled = false;", self.source)
        self.assertIn("result.translationUnitHandled = true;", self.source)
        self.assertIn("if (!invocation.run() || result.failed || !result.translationUnitHandled)\n"
                      "    return 4;", self.main)


if __name__ == "__main__":
    unittest.main()
