from __future__ import annotations

import hashlib
import json
from pathlib import Path
import tempfile
import threading
import time
import unittest


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]

from oracle.bounded_shards import (  # noqa: E402
    BoundedShardError,
    ShardBounds,
    ShardInput,
    load_complete_shard_index,
    run_bounded_shards,
)
from oracle.full_tree_scope import canonical_json_bytes  # noqa: E402
from oracle.full_tree_determinism import compare_full_tree_runs  # noqa: E402
from oracle.full_tree_materialization_determinism import (  # noqa: E402
    compare_full_tree_materializations,
)


BOUNDS = ShardBounds(
    maximum_shards=8,
    per_shard_entities=8,
    whole_run_entities=24,
    per_shard_bytes=4096,
    whole_run_bytes=12288,
    per_shard_seconds=2,
    whole_run_seconds=10,
    per_shard_cpu_seconds=2,
    whole_run_cpu_seconds=10,
    maximum_resident_bytes=2 * 1024 * 1024 * 1024,
    maximum_workers=3,
)
INPUTS = [
    ShardInput("third", hashlib.sha256(b"third").hexdigest()),
    ShardInput("first", hashlib.sha256(b"first").hexdigest()),
    ShardInput("second", hashlib.sha256(b"second").hexdigest()),
]


def producer(shard: ShardInput, output: Path, cancelled: threading.Event) -> int:
    if cancelled.is_set():
        raise RuntimeError("cancelled")
    output.write_bytes(
        canonical_json_bytes(
            {
                "entities": [{"id": f"{shard.identifier}-entity"}],
                "inputSha256": shard.input_sha256,
                "schemaVersion": 1,
                "shardId": shard.identifier,
            }
        )
    )
    return 1


class BoundedShardRunTest(unittest.TestCase):
    def test_truth_materialization_comparison_detects_exact_file_drift(self) -> None:
        with tempfile.TemporaryDirectory(prefix="truth-materialization-") as temporary:
            root = Path(temporary)
            first = root / "first"
            second = root / "second"
            for target in (first, second):
                (target / "shards").mkdir(parents=True)
                (target / "shards/one.json").write_bytes(b"{}")
                (target / "index.json").write_bytes(
                    canonical_json_bytes({"schemaVersion": 1, "shards": [{"path": "shards/one.json"}]})
                )
            report = compare_full_tree_materializations(first, second)
            self.assertTrue(report["identical"])
            self.assertEqual(2, report["files"])
            (second / "shards/one.json").write_bytes(b'{"changed":true}')
            drift = compare_full_tree_materializations(first, second)
            self.assertFalse(drift["identical"])
            self.assertEqual(["shards/one.json"], drift["differingFiles"])

    def test_determinism_ignores_only_authenticated_worker_concurrency(self) -> None:
        with tempfile.TemporaryDirectory(prefix="bounded-shards-determinism-") as temporary:
            root = Path(temporary)
            first_root = root / "first"
            second_root = root / "second"
            run_bounded_shards(
                first_root,
                run_id="fixture-run",
                inputs=INPUTS,
                bounds=ShardBounds(**{**BOUNDS.__dict__, "maximum_workers": 1}),
                producer=producer,
            )
            run_bounded_shards(
                second_root,
                run_id="fixture-run",
                inputs=INPUTS,
                bounds=BOUNDS,
                producer=producer,
            )
            report = compare_full_tree_runs(first_root, second_root)
            self.assertTrue(report["identical"])
            self.assertNotEqual(report["firstRun"], report["secondRun"])
            self.assertEqual(1, report["firstRun"]["maximumWorkers"])
            self.assertEqual(3, report["secondRun"]["maximumWorkers"])

    def test_parallel_order_resume_and_index_are_byte_deterministic(self) -> None:
        with tempfile.TemporaryDirectory(prefix="bounded-shards-") as temporary:
            root = Path(temporary)
            first = run_bounded_shards(
                root,
                run_id="fixture-run",
                inputs=INPUTS,
                bounds=BOUNDS,
                producer=producer,
            )
            index_bytes = (root / "index.json").read_bytes()

            def must_not_run(shard: ShardInput, output: Path, cancelled: threading.Event) -> int:
                raise AssertionError(f"completed shard reran: {shard.identifier}")

            resumed = run_bounded_shards(
                root,
                run_id="fixture-run",
                inputs=reversed(INPUTS),
                bounds=BOUNDS,
                producer=must_not_run,
            )
            self.assertEqual(first, resumed)
            self.assertEqual(index_bytes, (root / "index.json").read_bytes())
            self.assertEqual(first, load_complete_shard_index(root))
            self.assertEqual(["first", "second", "third"], [item["shardId"] for item in first["shards"]])

            checkpoint = root / "checkpoints/second.json"
            prepared = json.loads(checkpoint.read_text(encoding="utf-8"))
            prepared["status"] = "prepared"
            checkpoint.write_bytes(canonical_json_bytes(prepared))
            recovered = run_bounded_shards(
                root,
                run_id="fixture-run",
                inputs=INPUTS,
                bounds=BOUNDS,
                producer=must_not_run,
            )
            self.assertEqual(first, recovered)

    def test_interruption_never_publishes_partial_index_and_resumes(self) -> None:
        with tempfile.TemporaryDirectory(prefix="bounded-shards-interrupt-") as temporary:
            root = Path(temporary)
            interrupted_bounds = ShardBounds(**{**BOUNDS.__dict__, "maximum_workers": 1})

            def interrupted(shard: ShardInput, output: Path, cancelled: threading.Event) -> int:
                if shard.identifier == "second":
                    raise KeyboardInterrupt("fixture interruption")
                return producer(shard, output, cancelled)

            with self.assertRaises(KeyboardInterrupt):
                run_bounded_shards(
                    root,
                    run_id="fixture-run",
                    inputs=INPUTS,
                    bounds=interrupted_bounds,
                    producer=interrupted,
                )
            self.assertFalse((root / "index.json").exists())
            self.assertTrue((root / "checkpoints/first.json").is_file())
            completed = run_bounded_shards(
                root,
                run_id="fixture-run",
                inputs=INPUTS,
                bounds=interrupted_bounds,
                producer=producer,
            )
            self.assertTrue(completed["complete"])
            self.assertEqual(3, completed["counts"]["entities"])

    def test_mutated_checkpoint_output_and_changed_contract_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory(prefix="bounded-shards-mutation-") as temporary:
            root = Path(temporary)
            run_bounded_shards(root, run_id="fixture-run", inputs=INPUTS, bounds=BOUNDS, producer=producer)
            (root / "outputs/first.json").write_bytes(b"substituted\n")
            with self.assertRaisesRegex(BoundedShardError, "does not match"):
                load_complete_shard_index(root)
            changed = ShardBounds(**{**BOUNDS.__dict__, "whole_run_entities": 23})
            with self.assertRaisesRegex(BoundedShardError, "contract differs"):
                run_bounded_shards(root, run_id="fixture-run", inputs=INPUTS, bounds=changed, producer=producer)

    def test_entity_output_and_wall_clock_bounds_fail_before_completion(self) -> None:
        mutations = (
            (lambda shard, output, cancelled: (output.write_bytes(b"{}\n"), 9)[1], "entity bound"),
            (lambda shard, output, cancelled: (output.write_bytes(b"x" * 4097), 1)[1], "size"),
            (lambda shard, output, cancelled: (time.sleep(0.01), output.write_bytes(b"{}\n"), 1)[2], "wall-clock"),
        )
        for implementation, message in mutations:
            with self.subTest(message=message), tempfile.TemporaryDirectory(prefix="bounded-shards-bound-") as temporary:
                bounds = BOUNDS
                if message == "wall-clock":
                    bounds = ShardBounds(**{**BOUNDS.__dict__, "per_shard_seconds": 0.001})
                with self.assertRaisesRegex(BoundedShardError, message):
                    run_bounded_shards(
                        Path(temporary),
                        run_id="fixture-run",
                        inputs=[INPUTS[0]],
                        bounds=ShardBounds(**{**bounds.__dict__, "maximum_workers": 1}),
                        producer=implementation,
                    )

    def test_cpu_time_bound_fails_before_checkpoint(self) -> None:
        def expensive(shard: ShardInput, output: Path, cancelled: threading.Event) -> int:
            started = time.process_time()
            value = b"fixture"
            while time.process_time() - started < 0.02:
                value = hashlib.sha256(value).digest()
            output.write_bytes(canonical_json_bytes({"digest": value.hex()}))
            return 1

        bounds = ShardBounds(
            **{
                **BOUNDS.__dict__,
                "maximum_workers": 1,
                "per_shard_cpu_seconds": 0.001,
            }
        )
        with tempfile.TemporaryDirectory(prefix="bounded-shards-cpu-") as temporary:
            root = Path(temporary)
            with self.assertRaisesRegex(BoundedShardError, "CPU-time bound"):
                run_bounded_shards(
                    root,
                    run_id="fixture-run",
                    inputs=[INPUTS[0]],
                    bounds=bounds,
                    producer=expensive,
                )
            self.assertFalse((root / "checkpoints/third.json").exists())


if __name__ == "__main__":
    unittest.main()
