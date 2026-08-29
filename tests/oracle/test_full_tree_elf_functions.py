from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import unittest


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]

from oracle.full_tree_elf_functions import (  # noqa: E402
    FullTreeElfFunctionError,
    generate_full_tree_elf_function_index,
)
from oracle.full_tree_inventory import generate_inventory  # noqa: E402
from oracle.full_tree_scope import canonical_json_bytes  # noqa: E402


class FullTreeElfFunctionTest(unittest.TestCase):
    def test_elf_twins_produce_one_record_per_rva_with_alias_availability(self) -> None:
        with tempfile.TemporaryDirectory(prefix="full-tree-elf-functions-") as temporary:
            root = Path(temporary)
            source = root / "source/clang/lib/Driver"
            source.mkdir(parents=True)
            (source / "fixture.c").write_text(
                "int answer(void) { return 42; }\n"
                "extern int answer_alias(void) __attribute__((alias(\"answer\")));\n"
                "int main(void) { return answer_alias(); }\n",
                encoding="utf-8",
            )
            rich = root / "fixture.full"
            stripped = root / "fixture.stripped"
            subprocess.run(
                ["gcc", "-g", "-O0", "-no-pie", source / "fixture.c", "-o", rich],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            subprocess.run(
                ["objcopy", "--strip-debug", "--strip-unneeded", rich, stripped],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            scope = json.loads(
                (REPOSITORY_ROOT / "oracle/llvm/22.1.6/full-tree-scope.json").read_text(encoding="utf-8")
            )
            scope["oracle"]["richArtifactSha256"] = hashlib.sha256(rich.read_bytes()).hexdigest()
            scope["oracle"]["strippedArtifactSha256"] = hashlib.sha256(stripped.read_bytes()).hexdigest()
            scope["pathPolicy"]["prefixMaps"] = [{"from": f"{root}/", "to": "source/"}]
            scope["sharding"]["rules"] = [
                {"componentDepth": 1, "pathPrefix": "source/source/clang/lib/", "shardPrefix": "clang-lib"}
            ]
            scope_sha256 = hashlib.sha256(canonical_json_bytes(scope)).hexdigest()
            inventory = generate_inventory(rich, scope, scope_sha256)
            first = generate_full_tree_elf_function_index(
                rich,
                stripped,
                scope=scope,
                scope_sha256=scope_sha256,
                inventory=inventory,
            )
            second = generate_full_tree_elf_function_index(
                rich,
                stripped,
                scope=scope,
                scope_sha256=scope_sha256,
                inventory=inventory,
            )
            self.assertEqual(canonical_json_bytes(first), canonical_json_bytes(second))
            aliases = [
                function
                for function in first["functions"]
                if {alias["name"] for alias in function["aliases"]} >= {"answer", "answer_alias"}
            ]
            self.assertEqual(1, len(aliases))
            self.assertEqual(aliases[0]["id"], f"function-rva-{aliases[0]['rva']}")
            self.assertGreater(first["counts"]["functionRvas"], 1)
            self.assertEqual(
                first["counts"]["externalFunctions"],
                len(first["externalFunctions"]),
            )
            self.assertTrue(
                any(item["name"].startswith("__libc_start_main") for item in first["externalFunctions"])
            )

            substituted = json.loads(json.dumps(scope))
            substituted["oracle"]["strippedArtifactSha256"] = "0" * 64
            with self.assertRaisesRegex(FullTreeElfFunctionError, "SHA-256"):
                generate_full_tree_elf_function_index(
                    rich,
                    stripped,
                    scope=substituted,
                    scope_sha256=scope_sha256,
                    inventory=inventory,
                )


if __name__ == "__main__":
    unittest.main()
