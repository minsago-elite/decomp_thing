# Retained machine-call component evidence

This directory retains the exact positive-witness report from a standalone run of
producer commit `98597c5f1c2c5865d75a1338761af1715bc8ce77`. The source tree and
individual producer/input blobs are committed in `evidence.json`. The rich ELF,
canonical function oracle, and artifact manifest are recoverable from that Git
commit, independently of the current checkout.

`driver-report.json.gz` decompresses to 19,116,784 bytes with SHA-256
`d9afc3bbdfff322e5d1112d77a7dce23c033d05642ff1cb03e934660a7a3110e`.
`driver-request.json` preserves the exact original request. Its absolute paths
record the capture location; the offline verifier never dereferences them.

The recorded source commit must exist in the local Git object database. A shallow
checkout must obtain that commit from the repository first; verification never
fetches missing history.

Run the bounded offline verifier from the repository:

```sh
python3 scripts/verify-machine-call-component-evidence.py \
  oracle/gcc/16.2.0/machine-call-component-v1/evidence.json
```

To recover the exact report into an existing repository-local directory, add
`--extract-report build/driver-machine-calls.json`. Extraction creates a new file
only after verification and refuses to replace an existing file. The verifier
checks single-member gzip bounds, byte commitments, canonical JSON, request and
runtime consistency, inventory totals, authority flags, and source/input Git
blobs. It performs no network access or analysis.

The run inventoried 4,069 raw function symbols, 3,430 grouped roots, all 12,844
canonical function records, and 223,963 instruction attempts. It retained 15,376
physical call sites: 11,174 internal positive sites and 4,202 unresolved sites.
Those unresolved sites include 924 indirect targets and 2,934 off-canonical
targets. Twelve roots retain ownership problems and 695 retain addressed
traversal stops.

This is component evidence. `complete`, `releaseEligible`, and
`negativeCompleteness` are false; containment remains `external-owner-required`.
The recorded producer JAR digest is a build observation. The verifier does not
rebuild or attest that binary, execute the decoder, grant production admission,
or establish a complete external/indirect call population. Source, runtime,
request, and report commitments preserve the material for the later contained
operation and independent consumer qualification.
