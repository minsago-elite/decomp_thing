#!/usr/bin/env python3
"""Static ACP cleanup routing controls; not a hosted sandbox qualification."""

from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/acp-contract.yml"


def named_step(text, name):
    match = re.search(r"^      - name: " + re.escape(name) + r"\n(.*?)(?=^      - |\Z)",
                      text, flags=re.MULTILINE | re.DOTALL)
    if match is None:
        raise AssertionError(f"workflow step missing: {name}")
    return match.group(1)


class QuotaCleanupRouting(unittest.TestCase):
    def setUp(self):
        self.workflow = WORKFLOW.read_text()

    def test_preparation_has_the_cleanup_binding(self):
        step = named_step(self.workflow, "Prepare finite ACP quota fixture")
        self.assertIn("        id: prepare-quota\n", step)
        self.assertIn("        run: bash scripts/ci-prepare-acp-quota.sh\n", step)
        self.assertEqual(self.workflow.count("id: prepare-quota"), 1)

    def test_cleanup_runs_after_attempted_preparation_including_failure(self):
        step = named_step(self.workflow, "Release finite ACP quota fixture")
        # Preserve always(): partial acquisition on failure/cancellation still needs cleanup.
        # Exclude both skipped and absent preparation (the prerequisite fails before checkout).
        conditions = [line.strip() for line in step.splitlines() if line.strip().startswith("if:")]
        self.assertEqual(conditions, [
            "if: ${{ always() && steps.prepare-quota.outcome != 'skipped' && steps.prepare-quota.outcome != '' }}"
        ])
        self.assertIn("        run: bash scripts/ci-release-acp-quota.sh\n", step)

    def test_prerequisite_failure_remains_a_required_failure(self):
        self.assertIn("    needs: contained-module-acceptance\n    if: always()\n", self.workflow)
        step = named_step(self.workflow, "Require successful exact module acceptance prerequisite")
        self.assertIn('test "$DECOMP_MODULE_COMPILATION_PREREQUISITE_RESULT" = success', step)
        self.assertIn('[[ "$DECOMP_MODULE_COMPILATION_INVENTORY_SHA256" =~ ^[0-9a-f]{64}$ ]]', step)
        self.assertLess(self.workflow.index("Require successful exact module acceptance prerequisite"),
                        self.workflow.index("uses: actions/checkout@"))


if __name__ == "__main__":
    unittest.main()
