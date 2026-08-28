"""Compatibility exports for the program-neutral ELF oracle verifier."""

from oracle.elf_oracle import *  # noqa: F401,F403
from oracle.elf_oracle import (  # noqa: F401
    _assemble_manifest,
    _compare_exact,
    _resolve_within,
    _validate_input_record,
)
