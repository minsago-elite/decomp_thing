# Callable evaluator v2 preparation-002 integrity audit

Verdict: **CLEAR** for the actual sealed preparation-002 artifact and its exact bindings below. This is a post-create integrity attestation; implementation acceptance is supplied separately by the bound review and distinct root acceptance. No model trial, authentication release, historical candidate rerun, source checkpoint, issue closure or production qualification is authorized by this audit.

Read-only independent audit on 2026-10-14. Only this new evidence document was written. No source, bound review/acceptance, raw preflight, preparation-001 or Git/GitHub state was modified. No compiler, helper, candidate, model or authentication execution occurred. Private expected declarations and observations are omitted.

## Exact bindings

- Actual preparation-002 freeze SHA256: `87be4f2e2c82a9ef6ca65a270f313b02924413245b693c40a4bc92ddd0977309`.
- Corrected implementation review SHA256: `0119b01cdc63e2f0fbcb65f54add2b45c07b8ea5af44838120c4c96eb0a84915`.
- Distinct root acceptance SHA256: `12eb1d6ebc1b511e10b20e1289d05cc0e43a32c055b042b598fdb3e758d72188`.
- Exact preflight-009 matrix SHA256: `2100c5d13175d2187d4a86ed334165db79bef42490bc115ac1822d39a77d823e`.
- Canonical full preflight inventory SHA256: `d63752d0de1d103677c1b2fa76a6bdf06227320ffdd520bf6c004fdbf662debd`.
- Toolchain/environment pin SHA256: `df06d577d23d2f147671412434577eaa560ec6edeac91158a6e6d62c076ba0a6`.
- Helper007 pin SHA256: `ad2992b948b7e4b9cd5f23fe1f6266714cabbbc4baae20d8f46f24d572114008`.

## Complete post-create checks

Independently rehashed every one of 1,746 copied artifact files and compared the complete relative path/hash map with the freeze manifest, including absence of unlisted artifact files. Compared the entire frozen preflight tree with original preflight-009. Its 1,725-file canonical inventory matches the exact independent review/root acceptance/freeze digest above. Canonical inventory calculation is SHA256 of UTF-8 `json.dumps(relativePathToFileSha256, sort_keys=True, separators=(',', ':'))`.

Checked all 276 execution dependency bindings against current originals and their exact frozen execution snapshots. Independently compared execution sources, private files and contracts against original bytes. Frozen helper source/binary and all matrix/review/acceptance/pin copies match their approved original identities. The original root acceptance and corrected implementation review are separate artifacts with unequal hashes; their frozen copies retain the required CLEAR and OKAY verdicts.

Checked all 2,379 preparation paths: directories and executable files are mode0555, other files including freeze.json are mode0444. The caller and both helper executable copies preserve execution permission. No symlinks or writable paths are present in the sealed preparation.

Independently rehashed all 74,066 external dependency paths against the frozen environment map; all match. The artifact explicitly records that these dependencies were not copied and must be revalidated before later use. Independently rehashed all 3,637 historical v1 files; they match both the unchanged original inventory and the inventory bound into preparation-002.

Reverified preparation-001's original freeze digest, every one of its 1,544 copied artifact hashes and sealed permissions. Its original bound review and integrity audit hashes remain unchanged. Preparation-001 remains semantically unusable because of the former host-probe boundary; preservation and byte integrity do not restore its acceptance. Preparation-002 explicitly records that supersession reason.

The actual freeze records prepared-no-model-call, zero model calls, no authentication release and no trial authorization. ABI remains unassessed, structural score null and all production qualification flags false. #1506 byte-evidence adequacy is not bound. This audit changes no project acceptance or trial authority.

No blocking preparation-002 integrity defect found.
