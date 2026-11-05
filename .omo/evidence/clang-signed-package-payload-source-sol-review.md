# Clang signed package payload source review

## Terminal: ITERATE — implicit-parent metadata remains unauthenticated

Independent read-only source/evidence review. No tests/imports, archive extraction, native/tool/compiler/JVM/proc/privileged operations, acquisition, auth/model, Git/remote or source edits. Only this report was written. This review is not production acceptance or thread-closure authority.

### Exact reviewed checkpoint

Worktree wf_ce026d1b-c24-59. Manifest build/clang-signed-package-payload-correction/manifest.json SHA2569af8a8957f98e136dd0f69586e79a2f33bdd41c8aa81f81b2180ad9dac09661b. Both current sources match manifest and retained after snapshots:

- scripts/oracle/provision_clang_18_1_3.py:60f55d4cc969ceb77c0e42f106333af6b9b05cda421a8c542312840b2b5d8d19.
- oracle/clang/18.1.3/test_provisioning.py:3c6bc8ef0a83966eb9d1f0b04638b65409bf68651366088fb8aadc94a1656cec.

All five evidenceHashes match their actual files. Source plan/limits SHA25604d908030b5bdd5e00489a868249b1ea70ae9606502d0948912a5cccb3be4f58. Retained focused result a271547997db4328f8dc93c0a7ff812acfe0b1dac2a467f174d00c4da1231abd reports11 pure controls, zero failures/errors/skips/forbidden attempts and unchanged source. This reviewer inspected the tests, guard runner and retained result; did not execute them.

## Blocking source finding P1 — unauthenticated implicit parent metadata bypasses exact installed comparison

provision_clang_18_1_3.py:2955–2965 derives parent names from signed member paths even when the archive has no directory entry. At2984 any such installed path is accepted solely when it is a directory. The descriptor check2990–2992 compares device/inode only. The exact metadata loop2999 visits manifest entries only; consequently mode/uid/gid checks3015–3017 and extended-metadata rejection3013–3014 never apply to these implicit parents. The second inventory sweep repeats the same type-only admission. The returned authenticated file manifest3069 also omits these parents.

Concrete source counterexample, not executed here: the positive fixture test_provisioning.py:143–155 creates usr/bin, usr/lib/llvm-18/include and etc as ordinary directories but emits signed archive entries only for leaves and links. Keeping every authenticated leaf byte/hash/mode/uid/gid/link unchanged while changing an implicit usr or etc directory to0777, a different owner, or an access ACL does not trigger any comparison in this code path. It stays a directory and all leaf descriptors still resolve. An omitted package's directory metadata can similarly hide behind the parent-name exception. This is an unreviewed generated-metadata allowance despite the advertised empty transformation/generated registry. It weakens the exact installed ownership/security-metadata guarantee; this review does not claim a demonstrated native exploit or a race against a qualified immutable rootfs.

Smallest fail-closed correction: require each non-root installed parent to have an authenticated directory entry in the merged package manifest; refuse absent-directory metadata until an independently specified, reviewed derivation is authorized. Alternatively supply an explicit closed authenticated parent-creation rule binding expected uid/gid/mode and rejecting unadmitted xattrs/ACLs, including those derived entries in the compared/published inventory. Do not derive authority from current disk metadata, a self-consistent record or a general parent-path exemption. Positive synthetic fixtures can include signed directory entries. Add controls for omitted parent refusal and mutated mode/ownership/extended metadata; verify explicitly authenticated directory positives. Keep any real package extraction/default-directory semantics a separate future qualification gate.

## Other source observations

The core byte-authentication correction is substantive: packaging5780–5788 independently loads authenticated candidate/index data, compares exact signed package rows via validate_record_package_metadata2620–2644, then derives archive content from those package hashes. No installed status/md5 record supplies expected file bytes. authenticated_deb_manifest2808–2870 authenticates whole compressed .deb identity, exact supported ar inventory and control tuple. Decoder/tar paths2728–2805 have shared compressed/decoded/entry bounds, explicit gzip/xz/plain support, strict terminators/duplicates/path/link/member-type handling, and do not execute/extract payloads. Unsupported formats refuse rather than being normalized permissively.

Manifest comparison rejects conflicting ownership except exact shared directories, verifies regular bytes and FD/path identity, symlink text, prior hardlink relationships and alias count, and treats conffiles as authenticated file declarations without accepting local modifications. Mandatory archive retention occurs before normalization4595–4599/4636; comparison occurs before and after normalization4651/4713. Packaging archives source payloads and derived manifest5888–5897 and recomputes the installed comparison. These improve payload mutation and omission detection; none closes the implicit-parent gap above.

## Functional qualification remains separate

Even after the finding is fixed, this generation cannot be called production-ready. The empty reviewed transformation/generated registry deliberately rejects real maintainer databases, probe outputs, normalized package-owned files and other non-payload artifacts. Real Noble paths, merged-/usr behavior, supported compression coverage and bootstrap cache retention have not been qualified here; missing authenticated bootstrap bytes must stop. The11 authored tiny archive controls (with signed/index/image prerequisites mocked at packaging seam) are not evidence of actual signature/acquisition/installation/native/provenance success. Keep actual supported-host/package qualification and independent broader source/Actions gates open. No thread should be resolved solely on this source checkpoint.


---

# Correction002 narrow independent rereview

## Terminal: CLEAR_SCOPED — R1 implicit-parent metadata correction

R1 is resolved in the exact two-file generation below. This is source soundness for the closed supported-profile derivation only, not proof that it models every dpkg installation/default or that any real Noble provisioner path qualifies. Prior ITERATE bytes above remain unchanged; all functional/native/production gates stated there remain open. No tests/imports/native/proc/source/Git/remote operations were run by this rereviewer.

Manifest build/clang-signed-package-payload-correction-002/manifest.json: e5348321fc37e36fee329643843086976651d89b51d0deff3441749103bc9e6f. Current source pins:

- scripts/oracle/provision_clang_18_1_3.py:49f0531260b95701d16159cba7f30cfa7182f5bea971cdd9715072bfa5765635.
- oracle/clang/18.1.3/test_provisioning.py:a040eba19da0108c6974f0bcc160769143c7b810b1551c224ebaf5c0d806443d.

Both current hashes and all five002 evidence hashes match. Prior001 manifest and all five001 evidence hashes remain unchanged. Original review prefix SHAad7214f19221aeb0dd5f06e0c9ece533231a1792d88f191e8e560c150d0ceb4f remains byte-exact.

### Why R1 is closed

The parser2782–2784 retains signed root-directory metadata as internal key'.', rather than discarding it. Merge rules still require exact agreement for shared explicit directories, including this root entry. Only missing ancestors of authenticated payload paths can be derived2966–2981, requiring a retained authenticated root record. Expected mode is fixed0755; uid/gid come from that signed record. No installed stat/record/status value supplies these expectations. The named derivation and root source path are published. No signed root metadata means missing-parent derivation refuses; explicit directory metadata is never overwritten.

The broad type-only exemption is removed3000. Every installed nonroot path must now be in the completed manifest; derived parents pass through the same exact type/mode/uid/gid/xattr checks as explicit paths. A signed root entry itself also passes through ordinary metadata comparison via'.'. Final publication3085–3086 includes'/' and every derived parent with its rule. Unrelated generated files still refuse. The finite parent inventory and ordinary bounded no-follow traversal remain.

This is a reviewed conservative profile rule, not an inference that arbitrary root-directory archives authorize all installation transformations. The fixed0755 default may refuse legitimate real layouts; any broader extraction semantics require separate review and qualification. No transformation exceptions for package-owned files or general generated databases/probe outputs were added.

### Retained controls and limits

Author result6ffc72892d2b8c0539b1230e2df400722a7c93eccc723352c852364578235eaf records13 pure controls, zero failures/errors/skips/forbidden attempts, source unchanged. I inspected new source/tests/delta/result; did not rerun them. The positive fixture supplies authenticated root metadata but omits six parent directory entries, checks all six published derived records and exact0755/owner/rule values. Mutation of parent mode to0777 refuses; separate inert stat and xattr stubs exercise owner mismatch and ACL refusal. Missing root authority refuses. Explicit0700 directory remains authoritative and a conflicting0755 second-package entry refuses. The prior omitted-package fixture now includes signed root authority so it still reaches its intended unrelated-path rejection; the rejection assertion was not relaxed. UID/ACL controls are mocks, not privileged/native filesystem qualification.

No remaining blocker found in this narrow R1 delta. The package authentication/parser/gate review is not expanded by the13-test count into acceptance of unsupported compression, complete real rootfs transformations, bootstrap retention availability, signature/acquisition/native execution or production readiness. Root retains thread/release/Git custody.
