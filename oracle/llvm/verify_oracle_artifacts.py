"""Legacy non-authoritative LLVM compatibility exports for the Python verifier.

Kotlin/JVM owns production LLVM artifact-manifest validation.  These exports
remain only for differential migration fixtures and cannot certify a release.
"""

from oracle.elf_oracle import *  # noqa: F401,F403
