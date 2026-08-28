"""Program-neutral import surface for source-bound function scoring profiles.

The implementation retains its historical GCC module location so callers that
patch compatibility seams continue to work. New benchmark adapters import this
module instead.
"""

from oracle.gcc.score_function_recovery import *  # noqa: F401,F403
from oracle.gcc.score_function_recovery import (  # noqa: F401
    _VerifiedArtifactManifestSnapshot,
    _artifact_metadata_from_manifest,
    _verified_artifact_manifest_snapshot,
)
