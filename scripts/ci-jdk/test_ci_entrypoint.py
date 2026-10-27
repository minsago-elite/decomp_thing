"""Invocation correlation controls; no Gradle, DNS or native execution."""
from pathlib import Path
import os
import shutil
import subprocess
import tempfile
import unittest
import uuid

ROOT = Path(__file__).resolve().parents[2]


class CiEntrypointTest(unittest.TestCase):
    def test_each_invocation_replaces_inherited_run_id_without_removing_output(self):
        base = ROOT / 'build/ci-entrypoint-controls'
        base.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=base) as temporary:
            repo = Path(temporary)
            (repo / 'scripts').mkdir()
            shutil.copyfile(ROOT / 'scripts/ci.sh', repo / 'scripts/ci.sh')
            launcher = repo / 'gradlew'
            launcher.write_text('#!/bin/bash\nset -eu\nprintf "%s\\n" "$DECOMP_ACP_CONTRACT_RUN_ID" >> runs\n')
            launcher.chmod(0o755)
            stale = repo / 'build/provider-dns-native-qualification/cancel.json'
            stale.parent.mkdir(parents=True)
            stale.write_bytes(b'stale receipt must not be deleted')
            ids = []
            for shard in ('full', 'live', 'live-rest', 'live-fulltree'):
                subprocess.run(['bash', str(repo / 'scripts/ci.sh')], check=True,
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, env={**os.environ,
                        'DECOMP_CI_TEST_SHARD': shard, 'DECOMP_ACP_CONTRACT_RUN_ID': 'inherited-stale-id'})
                current = (repo / 'runs').read_text().splitlines()[-1]
                self.assertEqual(current, str(uuid.UUID(current)))
                self.assertNotIn(current, ids)
                ids.append(current)
                self.assertEqual(b'stale receipt must not be deleted', stale.read_bytes())


if __name__ == '__main__':
    unittest.main()
