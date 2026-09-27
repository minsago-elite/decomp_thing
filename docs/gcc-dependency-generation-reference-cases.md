# GCC dependency-generation reference slice

`oracle/gcc/16.2.0/dependency-generation-reference.json` records one bounded
dependency-generation case without inventing an expected result. It reuses the
`source.c` bytes and digest already retained by the checked GCC behavior corpus,
and binds the case to the source-aligned GCC 16.2.0 driver, source lock, build
record, and toolchain image digest already checked into `oracle/gcc/16.2.0`.

The record remains `unresolved`. The current behavior corpus has 14 cases, but
its preprocessing cases invoke the staged `tools/cc1` mock and expect the fixed
`MOCK-PREPROCESSED` line; that is driver forwarding evidence, not a real GCC
dependency-list observation. The record therefore has no expected stdout,
diagnostic, exit code, or execution receipt.

Production capture is currently unavailable here: Docker and Podman are absent,
and the host `/usr/bin/gcc` is not the recorded `/usr/local/bin/gcc` toolchain
identity. A truthful completion still requires a replay in the authenticated
pinned OCI environment, with declared frontend/resource/include/input
identities, exact dependency output and diagnostics, exit status, and an
independent repeat. Until those gates exist, this slice cannot qualify issue
#710 or the downstream reconstructed-driver comparison.

This record does not add an external Ghidra prerequisite, invoke
`analyzeHeadless`, or move authority across the oracle/candidate boundary.
