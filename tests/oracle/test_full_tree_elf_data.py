from __future__ import annotations
import hashlib, json, subprocess, tempfile, unittest
from pathlib import Path
REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
from oracle.full_tree_elf_data import FullTreeElfDataError, generate_full_tree_elf_data_index  # noqa: E402
from oracle.full_tree_inventory import generate_inventory  # noqa: E402
from oracle.full_tree_scope import canonical_json_bytes  # noqa: E402

class FullTreeElfDataTest(unittest.TestCase):
    def test_globals_tls_vtable_rtti_and_slots_are_twin_bound(self) -> None:
        with tempfile.TemporaryDirectory(prefix="full-tree-elf-data-") as temporary:
            root = Path(temporary); source = root / "source/clang/lib/CodeGen"; source.mkdir(parents=True)
            (source / "fixture.cpp").write_text("struct Base { virtual int value(); virtual ~Base(); }; int Base::value(){return 42;} Base::~Base()=default; Base global_base; thread_local int global_tls=3; int main(){return global_base.value()+global_tls;}\n", encoding="utf-8")
            rich = root / "fixture.full"; stripped = root / "fixture.stripped"
            subprocess.run(["g++", "-g", "-O0", "-no-pie", source / "fixture.cpp", "-o", rich], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            subprocess.run(["objcopy", "--strip-debug", "--strip-unneeded", rich, stripped], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            scope = json.loads((REPOSITORY_ROOT / "oracle/llvm/22.1.6/full-tree-scope.json").read_text())
            scope["oracle"]["richArtifactSha256"] = hashlib.sha256(rich.read_bytes()).hexdigest(); scope["oracle"]["strippedArtifactSha256"] = hashlib.sha256(stripped.read_bytes()).hexdigest()
            scope["pathPolicy"]["prefixMaps"] = [{"from": f"{root}/", "to": "source/"}]; scope["sharding"]["rules"] = [{"componentDepth": 1, "pathPrefix": "source/source/clang/lib/", "shardPrefix": "clang-lib"}]
            scope_sha256 = hashlib.sha256(canonical_json_bytes(scope)).hexdigest(); inventory = generate_inventory(rich, scope, scope_sha256)
            first = generate_full_tree_elf_data_index(rich, stripped, scope=scope, scope_sha256=scope_sha256, inventory=inventory)
            second = generate_full_tree_elf_data_index(rich, stripped, scope=scope, scope_sha256=scope_sha256, inventory=inventory)
            self.assertEqual(canonical_json_bytes(first), canonical_json_bytes(second)); aliases = [alias for item in first["globals"] for alias in item["aliases"]]
            self.assertTrue(any(alias["name"] == "global_base" for alias in aliases)); self.assertTrue(any(alias["kind"] == "tls" for alias in aliases))
            vtables = [alias for alias in aliases if alias["abi"] and alias["abi"]["kind"] == "vtable"]
            self.assertTrue(vtables); self.assertGreater(len(vtables[0]["abi"]["slots"]), 0)
            forged = json.loads(json.dumps(first)); forged_vtable = next(alias for item in forged["globals"] for alias in item["aliases"] if alias["abi"] and alias["abi"]["kind"] == "vtable"); current_slot = forged_vtable["abi"]["slots"][0]["rawLittleEndian"]; forged_vtable["abi"]["slots"][0]["rawLittleEndian"] = ("ff" if current_slot == "00" * 8 else "00") * 8
            with self.assertRaisesRegex(FullTreeElfDataError, "hash"):
                from oracle.full_tree_elf_data import validate_full_tree_elf_data_index
                validate_full_tree_elf_data_index(forged, scope=scope, scope_sha256=scope_sha256, inventory=inventory)
            substituted = json.loads(json.dumps(scope)); substituted["oracle"]["richArtifactSha256"] = "0" * 64
            with self.assertRaisesRegex(FullTreeElfDataError, "SHA-256"):
                generate_full_tree_elf_data_index(rich, stripped, scope=substituted, scope_sha256=scope_sha256, inventory=inventory)

if __name__ == "__main__": unittest.main()
