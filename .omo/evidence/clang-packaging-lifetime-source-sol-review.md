# Clang packaging lifetime correction001 — independent source review

## Terminal: CLEAR_SCOPED for sLH1t and sRgqt source corrections

No blocking defect found in this exact retained-root/output-publication delta. Read-only review; no imports/tests, native/compiler/tool/JVM/proc operations, acquisition/network/auth/model, source/Git/remote edits. Only this report was created. Root retains release/thread/Git custody. This is not production/native/full Clang acceptance.

## Exact bound source and evidence

Worktree wf_ce026d1b-c24-59. Manifest build/clang-packaging-lifetime-correction-001/manifest.json:633a1273f838ed8c70ca7955133c484f5fcb7b6f0cefd8b11ecb4a3e4b815a0f. Current sources match manifest and retained after snapshots:

- scripts/oracle/provision_clang_18_1_3.py:04bc208b47d31fcf4fc0c5b210711d0ba2202ee5cd0698626f7d3b015b332e17.
- oracle/clang/18.1.3/test_provisioning.py:3ddada98441e4e1c4906ccdf496bee569c0965b52af033541a6d061889330e58.

All five evidence hashes match, including result52262974a786b4be3b70bff8a438b74bd29a63ae8e86463716159e34908fd46d and final log54233e74872ab6f60e48c25ffd7360547115a68124ba3b75d289fba26869948e. Retained result/log record22 controls passed in0.133s, zero failures/errors/skips/forbidden attempts. I inspected source, deltas, guard runner, tests and retained records; did not rerun them.

Earlier package002 review remains untouched at .omo/evidence/clang-signed-package-payload-source-sol-review.md, SHAd3cb2c2da13b6613bd2fc01ceac451e93297eaa10473da9f0d94df41022f7d94, including original ad7214 ITERATE prefix.

## sLH1t — retained root lifetime

open_directory_without_links4092–4110 walks bounded absolute components with O_DIRECTORY|O_NOFOLLOW, rejects parent traversal and closes intermediate descriptors. pin_retained_rootfs_directory4114–4141 holds parent and root descriptors, requires root UID0 and no group/world write, verifies named versus held inode binding before yield and in finally, and closes descriptors even on refusal. Existing PinnedRootfsDirectory additionally rechecks root authority4065–4069.

The packaging entry5988 holds that context around the entire _package_provenance_pinned call. Its rootfs argument is the retained /proc/<parent-pid>/fd/<fd> descriptor path; bound6001–6006 checks the original binding before and after each retained-root consumer. Root/image verification receives the binding and sets held_rootfs_descriptor for deterministic tar, instead of reinterpreting the descriptor as an ordinary forbidden root symlink. Installed keys/payloads, driver/runtime identities, probe replay, loader validation, repeated payload comparison and retained probe file checks all use this held-root route. Returned probe paths remain descriptor-relative while final inclusion occurs. Negative comparator and captured external evidence have separate existing byte/descriptor authority and do not consume the retained root.

Context finalization and publication's require_inputs callback recheck original binding rather than silently approving a replaced name. This guarantees the corrected root inode lifetime and refuses original-name replacement; it is not a claim that a directory FD snapshots all descendants or defeats privileged mutation of their bytes. Existing payload/hash/replay checks and the immutable approved-host gate remain necessary.

## sRgqt — output inode and cleanup ownership

PinnedProvenanceArchive5436–5560 opens a held no-follow parent, requires calling-user ownership and no group/world write, creates an anonymous O_TMPFILE0600 inode, and bounds each write before growth. Tar writes use fileobj=output, avoiding pathname reopening. Publication hashes the held inode, fchmods0400 and fsyncs, checks inputs/parent, then links the held FD exclusively into the held parent. Existing files/symlinks cannot be replaced by link creation. After linking it checks input/parent binding, destination inode, full FD digest and final path/held metadata equality after parent fsync. Named publication is not used as byte authority.

No failure cleanup unlinks a caller-controlled name. Before publication close reclaims the anonymous inode; after publication failure an explicitly unaccepted name is retained for separately owned recovery. Closing failures still release the parent FD. The production package path uses this owner object and no longer has the old blind unlink-on-error paths. Unsupported O_TMPFILE/filesystem publication fails closed; source review does not qualify that transport on every deployment filesystem.

## Meaning of retained controls

The nine added lifetime/output methods plus13 payload methods constitute the22 retained controls. They inspect real inert FD identity/close behavior and synthetic tar output, absent destination before publish, successful same-inode digest publication, exact/one-over write budget, preexisting canary preservation, output-parent replacement, post-link destination swap, same-inode mutation after digest, fdopen/close failure cleanup, symlink-ancestor refusal, root replacement and no later consumer after replacement. Root UID0 admission is exercised through metadata mocks on owned inert paths; an ordinary caller-owned directory is refused without mocks. No actual root-owned chroot, privileged tar, probe, compiler or loader runs occur. The packaging seam's prerequisite signature/image/native functions remain mocked as documented; these controls are not real package/native qualification.

## Remaining functional/security qualification

The payload002 closed parent derivation, empty transformation registry, real Noble/merged-/usr behavior, missing bootstrap retention, acquisition pause, approved immutable-host provisioning, sandbox replay, A-loader/workflow correction and all actual signature/package/native/production gates remain separate. No loader or workflow source changed here. CLEAR_SCOPED supports the two exact lifetime source corrections only, not automatic closure of broader review requirements or acceptance of all supported host paths.
