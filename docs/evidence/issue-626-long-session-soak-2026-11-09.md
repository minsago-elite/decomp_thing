# #626 packaged long-session soak — local evidence

This is a passing local packaged-fixture run for the long-session slice of #626. It is not hosted CI or production qualification, and it does not complete the broader #220 scope. Keep #626 and #220 open.

## Run identity

- Base: `refs/remotes/origin/master` at `2b1121999c806d5b3f89d3723fca8a39879c49b1`.
- Candidate: the source snapshot represented by this change; runtime harness files are SHA-256-bound below.
- Archive: `llm_bin_patch-0.1.0.zip`, SHA-256 `372faf8a32d76290b568365934af7e3dd4d5f2ff3b81f6568cf3ea879ee9ba17`.
- Application JAR SHA-256: `5dc2a93f58ba444cd2e71cfef0bd2129b8afbb2212fc795bc06eef1ed61b0fb6`.
- Frontend build ID: `c1bb39f336ed634322944c72188e04f694b404f85695e5418caa7891cd9c66b9`.
- Chrome: `149.0.7827.55`, SHA-256 `2d18db9d8608b052b6a552ee00ec1e830f93692e928b65ecc67d693bd33fe801`.
- Driver Node: `24.20.0`; packaged JVM: Temurin `21.0.12.1+1`, default `-Xms64m` with no test-only JVM override.
- Browser mode: headful X11 (`DISPLAY=:0`).
- Raw report: `build/packaged-browser-pEWA7L/report.json`, SHA-256 `cd5f54f22be7b336e47681101abe96423fedc0be13313944b6c49342a21776df`.

The report's `driverCommit` field contains the shared checkout's HEAD (`3823145e756b878d0b70a8b19e0313940f3260e5`), because the candidate was materialized as a plain directory without Git metadata. That field does not identify this candidate's files. These hashes bind the runtime driver and UI inputs used for this run:

| File | SHA-256 |
|---|---|
| `scripts/check-packaged-web-browser.mjs` | `9e2ffabc2b2e505f0ef63372073f8df6f098051352edf2b81ce37eab8f20df1b` |
| `scripts/packaged-browser-soak.mjs` | `758d98dbb7edae2cdc6a5e231881686ca0b48bdbbe3ef5fec58fb83d1de830fa` |
| `scripts/soak626/evaluate.mjs` | `65376c857eecff30a4046ba3ddfb012de3017b2f1675e1a9d376291073fa9276` |
| `scripts/soak626/resources.mjs` | `7394b6d7a3305c6ad63280bb13ff72ee7141241a041e05bf48379b18f4aad2a2` |
| `scripts/soak626/stream-renewal.mjs` | `8411a3575c450bbab9c852cccd8f537bc9114467d2d9a5759f4b0ec90158a4f7` |
| `scripts/soak626/target-cleanup.mjs` | `281126847b8406714808d7d22ee1a38658814c58ad49d6bc3c9c5b83fe4e04b5` |
| `frontend/src/api/eventStream.ts` | `9cf604a2479ba94e2f41d98d214400be46cb4dd78fbb6f65c210c20bd8a5f558` |
| `frontend/src/jobs/Activity.tsx` | `a764945142573bf7659fbd911cd36d83c53eabc2f958d5db54726f81aca530e8` |
| `frontend/src/jobs/activityRetry.ts` | `62757ba30141e04e3f52ffb8d262318e349a3fcad9fce64c828d4af7d4a24921` |

## Results

The full profile passed all evaluator gates:

- Workload: 120/120 ten-second slots over 1,200,000 ms; wall time 1,353,134 ms.
- Coverage: four jobs, 119 job switches, 24,195 Activity rows, 240 source reads, 20 offline/online reconnects with 20 deliveries, 10 visibility transitions, and retained-history-gap recovery.
- Stream lifecycle: four successful natural renewals, each observed over 35,249–35,251 ms; final cleanup completed. Nine transient stream-capacity responses were recovered through polling/backoff.
- Renderer heap: 1.49 MiB after initial browsing and 3.72 MiB at completion. The largest adjacent five-minute checkpoint increase was 0.154 MiB.
- JVM process-tree RSS: baseline 114.17 MiB; maximum including post-logout sample 238.11 MiB; growth 123.94 MiB against the 256 MiB ceiling.
- JVM descriptors: baseline and peak 50; post-logout 46 (−4 from baseline). The stream drain completed in 0 seconds.
- Latency: Activity read p95 87 ms, route-feedback p95 15 ms, first data 297 ms.
- Resource sampling: 1,213 samples; process identity remained stable; shutdown was confirmed; no companion page remained after bounded CDP cleanup polling.

Focused verification also passed: 19/19 Node soak/evaluator tests, 55 frontend tests across six files, TypeScript, and ESLint.

## Limits

This is local fixture evidence against one packaged archive and one browser/host profile. It does not establish a hosted Actions run, cross-engine or constrained-profile results, production workload behavior, or the remaining #220 criteria. The passing result supports only this focused long-session slice; issue acceptance remains for review.
