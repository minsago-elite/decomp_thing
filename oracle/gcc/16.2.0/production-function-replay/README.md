# Retained selected production function replay

This is the original byte evidence from [Actions run 40212192598](https://github.com/minsago-elite/decomp_thing/actions/runs/40212192598), job `121225604948`, artifact `12608161177` (`gcc-driver-live-full-export-40212192598-1`). The selected driver qualification passed on 2026-10-25. The PR head was `202de6b234500419c37c412f385a0da948b98a78`; Actions actually checked out merge commit `f4904e7d21063636ee8a77b298eac08eb1894283`. Both have the identical complete source tree `7fc1055b170b357c0759e3307375765da24b6109`. Both raw commit objects, the complete NUL-delimited Git tree inventory, and original Actions log are retained so the checkout distinction remains explicit.

The manifest binds each original model, observation, score, request, receipt and diagnostic file by its decoded byte count/SHA256 and compressed byte count/SHA256. Gzip packaging is deterministic; decompression reproduces the captured bytes without rewriting any values or prose. It retains the original conservative limitation strings even where those strings predate the selected production admission. These files are historical evidence, not credentials or creators of a live `VerifiedStructuralInputsV1` capability.

From the repository root, verify integrity and independently rederive the selected measurements:

```sh
python3 -B scripts/verify-gcc-production-function-replay-evidence.py \
  oracle/gcc/16.2.0/production-function-replay/evidence.json
```

The verifier requires the explicit evidence manifest and checked function oracle. It performs bounded file/decompression reads, reconstructs the original Git tree from its complete inventory and verifies both retained commit objects, then checks byte links, complete recovered/oracle partitions, exclusions and surviving-alias population. This source check needs no historical Git objects, network access or full-depth checkout. A successful offline check proves consistency of these retained bytes and their measurements; it does not rerun the exporter, authenticate a new operation, or grant production admission to caller-authored JSON.

The captured stripped model is 8,819,191 bytes, SHA256 `0c8f89f9346782f4bcc9ee4d421200aa7ba29122ce762eb4b267b64b0496d1c1`, with all 3,384 recovered function records retained, including one explicit decompilation failure. Of these, 111 match reviewed compiler-generated exclusions, leaving 3,273 scored recoveries against 3,284 scoreable oracle functions. The result has 3,269 exact starts, no near matches, four false positives and 15 false negatives:

| Selected measurement | Result | Required threshold |
| --- | --- | --- |
| Exact-start precision | 3,269 / 3,273 = 99.8778% | At least 95% |
| Exact-start recall | 3,269 / 3,284 = 99.5432% | At least 95% |
| Surviving symbol identities | 6 / 6 = 100% | 100% |

The full oracle function population is 12,844: 3,284 scoreable and 9,560 explicitly excluded (140 compiler-generated and 9,420 inlined). Its selected stripped alias population contains six surviving aliases, 6,211 removed aliases and 17,946 not-observable aliases. Every surviving alias is enumerated and checked at its exact oracle RVA; no excluded function has a surviving alias in this selected population. Removed and unobservable aliases are preserved as those source dispositions, not silently counted as recovered identities.

The original live admission and selected scores cover model provenance, function boundaries and surviving symbol identities. Both contained execution receipts report exit zero and verified unit, cgroup and process absence. Their recorded control-directory UID/GID is 1001/1001 with mode 0700; this is not a separate process-credential measurement or an upgrade of sampled resource counters into terminal counters.

The selected function accuracy report's `benchmarkAccepted: true` applies only to the two measurements above. The full CLI result and qualification retain `complete: false`, `scored: false` and `releaseEligible: false`; qualification also retains `benchmarkAccepted: false`. Interfaces, calls, globals, types and calibration remain unavailable. This snapshot does not establish full structural accuracy, recovery of the failed decompilation, or release eligibility. Source review, current required CI and repository landing remain separate from this historical run.
