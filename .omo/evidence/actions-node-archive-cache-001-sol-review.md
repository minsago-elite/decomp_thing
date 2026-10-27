# Independent Actions Node archive cache review

**CLEAR_SCOPED — exact two-file opt-in source change.** No blocking source finding for the fixed Kotlin-matrix cache route. This is not an observed cache hit, timing result or executed cache/installer qualification.

## Exact inputs

- Freeze `build/actions-node-archive-cache-001/freeze.json`: SHA256 `16268d1b7731b376179752c583a70a3e61978c54d8199ce77cbc245ae44272c9`.
- CI source `fea32cd24638f211aa6b274cb37c58aaf4c0f7f36abe687bee8a9420b94a4630`; installer `9ba3817a78013f9f1d7a38dd0023bc84ae4fdbe07330e56f854ce2b06949f973`; diff `7123e15f13655746e8aefe1fa00fc847b416e9b326f629fd8168254c28279e5f`.
- Independently recomputed both owned source sizes/hashes, both before snapshots, all six artifact rows and three unchanged dependency pins. Current sources remain frozen. Read retained handoff `d29f1d40678d812f9bf2914dfd9fb4695b5aa636f48af2fcfec8b983eec3d772` and source-only checks.

## Source assessment

1. **Authentication precedes use on both routes.** Installer68–77 copies a regular nonsymlink cache entry into the preexisting fresh installation stage and checks that staged copy against the exact reviewed SHA256 before calling it a hit. The original visible staged checksum85–88 is still mandatory for hits and downloads, before tar or Node/npm execution. No Actions cache-hit output bypasses verification. Cached extracted executables are never selected.
2. **Misses preserve the pinned acquisition.** Missing, nonregular/symlink, unreadable/copy-failing or checksum-corrupt entries are not selected as hits. Failed staged copies are removed; the exact original HTTPS URL, protocol/TLS options, retry/connect/total timeout and archive naming remain. Optional cache preparation/publication failures do not remove the checksum gate or create a moving/system-Node fallback. Unset opt-in does not require realpath/cp for cache preparation.
3. **Publication and paths.** Fixed workflow cache path is repository/build/frontend-node-archive-cache. Preparation requires an absolute nonsymlink cache root, resolves it under the physical repository, creates it0700 if absent, and checks directory/nonsymlink/current ownership. Entry selection rejects symlinks. After successful checksum only, publication stages a copy in private `mktemp -d` under that cache and renames the complete file atomically to the fixed archive basename; failure is nonfatal and its owned temporary directory is cleaned. This adds no outside-repository cache/publication temporary path. It preserves the existing caller-selected installation-stage parent; no new hostile-host/race-proof filesystem guarantee is inferred.
4. **Existing toolchain checks remain.** Independently proved the original installer prefix exact, curl command identical modulo indentation, original strict checksum block present, and complete tar/actual Node version/.node-version/package engines/packageManager/npm version/final absent-destination publication tail byte-identical. Approved Node/npm/architecture and checksum inputs are unchanged.
5. **Workflow scope is narrow.** Removing only the new cache step and installer env returns the entire original CI YAML bytes exactly. Only Kotlin core/live matrix receives the opt-in; cache key binds OS/architecture plus installer and reviewed-checksum hashes, using existing actions/cache@v6. Permissions, job conditions, tests, distribution/guardian/DNS/native verifiers and other jobs are untouched. Installation and required gates run independently of hit/miss.

## Evidence limits

Retained author verification is bash-n exit0 and static comparisons only. Reviewer reran no syntax/test/installer/Node/curl/network/native/Actions operation. Cache hit, corrupt/unreadable miss, publication-failure behavior and any speed improvement remain unobserved pending separately authorized execution. This source review supplies no test/native/provider/runtime qualification. Unrelated dirty native contract files were not edited or treated as part of this freeze.

Only bounded source/evidence reads, hashes/comparisons and this additive review were performed; no source/Git/remote mutations.
