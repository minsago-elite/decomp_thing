# Clean-checkout contributor replay

This page records one literal run of the contributor instructions that
[#229](https://github.com/minsago-elite/decomp_thing/issues/229) requires: *"Run the
contributor instructions from a clean checkout and check command names against actual
Gradle/package scripts."* The instructions come from four documents:

- [repository-local setup](web-packaging.md#repository-local-frontend-setup-and-rebuilds) and the packaging checks in [packaging](web-packaging.md);
- [fixtures and failure investigation](web-workflow-fixtures.md);
- [route/contract extension](web-architecture.md#route-and-contract-extension-workflow);
- [Git adapter fixtures](web-git-fixtures.md#use-the-fixture-factories-to-test-the-adapter-seam).

This is evidence for one run, not a CI gate. Issue status lives in GitHub.

## Source and host

| Item | Value |
|---|---|
| Source | `origin/master` `33c49f953712ed72905a8693fa98d98c9ad0c66d`, run on 2026-10-26 |
| Checkout | Fresh `git worktree add --detach` inside the repository's ignored `build/`, with no prior build outputs or caches. `GRADLE_USER_HOME`, npm and pip caches were new and repository-local, so Gradle 9.6.1, the dependencies and the bundled Ghidra archive were all downloaded. |
| Environment | `env -i`, keeping only `HOME`, `USER`, `LANG=C.UTF-8`, `JAVA_HOME` and a system `PATH`. The system `PATH` had an unrelated `/usr/bin/node`; the documented `PATH` prefix shadowed it. |
| Host | Linux 7.2.9 x86_64 (Gentoo, hardened kernel), Temurin JDK 21.0.12.1, Python 3.14.9, git 2.56.0, GCC 16 |
| Installed tools | Node v24.20.0 and npm 11.19.0 from `scripts/install-frontend-node.sh` (archive checksum OK); Chrome for Testing 149.0.7827.55 from `scripts/install-web-test-browser.py` |

## Steps and results

Durations are wall-clock times on this host. "Pass" means exit status 0 plus the
expected output.

| Document step | Command (abbreviated) | Result | Time |
|---|---|---|---|
| Setup: scratch/cache directories and `export`s | `mkdir -p build/frontend-dev/...` | Pass | 0 s |
| Setup: Python fixture environment | `python3 -m venv …/tools/python`, then `pip install --requirement requirements/oracle-generation.txt` | Pass | 8 s |
| Setup: pinned Node | `bash scripts/install-frontend-node.sh …/tools/node`; `node --version`; `npm --version` | Pass: v24.20.0 / 11.19.0 | 4 s |
| Setup: locked install | `./gradlew -PfrontendNodeHome=… frontendInstall` | Pass, including the Gradle download | 114 s |
| Setup: frontend checks | `npm --prefix frontend run typecheck` / `run lint` / `test` | Pass; `test`: 64 files, 913 tests | 46 s |
| Setup: distribution | `./gradlew -PfrontendNodeHome=… jar installDist distZip distTar` | Pass, including the Ghidra download | 232 s |
| Resources/references: verify | `./gradlew … verifyGhidraDistributionArchives verifyAcpGateHelperDistribution verifyLlvmBehaviorHelperDistribution verifyKotlinBootClasspathDistribution verifyPackagedWeb` | Pass | 149 s |
| Task order | `jar --info` and the task logs | Matches the documented order `verifyFrontendToolchain → frontendInstall → frontendBuild → generateFrontendAssetManifest → verifyFrontendAssets → stageFrontend → processResources → jar`. Reference generation (`generateGccBundledGhidraReference`, `stageKotlinBootRuntime`, `generateKotlinBootClasspathReference`, `generateLlvmHostedWorkerClasspathReference`) ran after `jar` and before `installDist`/`distZip`. | — |
| Packaging focused checks | `./gradlew … testFrontendAssetManifest verify…Distribution verifyPackagedWeb` | Pass; the asset-manifest node suite ran 22 tests | 185 s |
| Packaging focused tests | `./gradlew … test --tests 'decompengine.web.*' --tests 'decompengine.jobs.*'` | Pass: 94 classes, 857 passed, 1 skipped (`BrowserSessionExpiryTest`, which needs the browser environment that CI provides) | 961 s |
| Fixtures: contracts | `python3 contracts/web/v1/verify.py`; `npm … run api:check`; `npm … run fixtures:check` | Pass: 87 valid and 110 invalid fixtures; generated contracts `ce20034837df` | 3 s |
| Fixtures: development server | `DECOMP_DEV_BASE_PATH=/nested/ npm … run dev:fixtures` | **Deviation.** Port 5173 was already held by an unrelated Vite server on this host. Vite's strict port refused to start, and the first probe reached the other server. With `DECOMP_DEV_PORT=5291`: catalogue 200 ("Simulated development fixtures"), bootstrap 200 with `SIMULATED_DEVELOPMENT_DATA`, `POST /nested/api/v1/jobs` refused with 405 | 2 s |
| Fixtures: frontend layer | `npm … test -- tests/workflow-fixture-mock.test.ts tests/activity-stream.test.tsx tests/event-stream.test.ts` | Pass: 3 files, 33 tests | 9 s |
| Fixtures: development layer | `npm … test -- tests/development.test.ts` | Pass: 6 tests | 4 s |
| Fixtures: JVM layer | `./gradlew test --tests '…ControlledWorkflowFixtureTest' --tests '…WebProgressCutoverTest'` | Pass: 2 + 6 tests with `-PfrontendNodeHome`. The command as written, without the property, also passed: Gradle used the pinned Node from `PATH` (103 s). | 195 s |
| Durable start controls | `./gradlew test --tests '…WorkflowStartReceiptTest' --tests '…DurableWebWorkflowStartTest' --tests '…WebWorkflowStartControllerTest'` | Pass: 9 + 12 + 9 tests | 49 s |
| Scale datasets | `node scripts/generate-web-scale-fixtures.mjs …/scale-v1`, then `verify-web-scale-fixtures.mjs` | Pass: 10 files, 144,274,904 payload bytes, manifest `57f35b13…`. Rerunning the generator on the existing directory was refused (`EEXIST`), as documented | 5 s |
| Architecture focused checks | `npm … test -- tests/paths.test.ts tests/app.test.tsx tests/api-contract.test.ts tests/api-client.test.ts tests/event-stream.test.ts` | Pass: 5 files, 321 tests. Every referenced source/test file and example (`client.get('job', …)`, `<h2>{job.displayFilename}</h2>`, `appPath`, the 2,048-character/24-hour upload ticket) exists as described | 4 s |
| Git fixtures | `node --test scripts/web-git-fixtures.test.mjs scripts/web-github-fixture-http.test.mjs` | Pass: 5 tests. The documented environment, 15 s timeout and 1 MiB output bound match `scripts/web-git-fixtures.mjs` | 4 s |
| Browser: install and helpers | `python3 scripts/install-web-test-browser.py …/build/web-test-browser`; `python3 scripts/test-packaged-browser-install.py`; `node scripts/test-packaged-browser-upgrade.mjs` | Pass: 4 and 13 tests. Chrome started without installing the CI `deb.deps` libraries | 8 s |
| Browser: `--mode session` | `node scripts/check-packaged-web-browser.mjs --archive … --chrome … --mode session` | **Failed in the deep checkout**: Chrome aborted with `Socket path too long` for `<checkout>/build/ct-*/org.chromium.Chromium.*/SingletonSocket` (checkout path: 85 characters). Shutdown and cleanup were still confirmed. | 10 s |
| Browser: rerun | The same driver from a 35-character checkout of the same commit, with the same ZIP, Chrome, Node and Python | Pass for `session` and `metadata`. No sandbox flag was needed; shutdown and cleanup were confirmed. | 69 s |
| Actions artifacts | `gh run download 40194447686 --name frontend-verification` / `packaged-web-verification` / `packaged-browser-expiry-test-reports` | Pass: master run for `244fb547`, 2.1 MB in total, containing five packaged-browser report directories plus JVM/expiry XML and receipts. No model credential was used. | — |

Browser-tested identities. These identify the archive supplied to the browser and
its embedded JAR, not necessarily the installed JAR after later focused tests; see
the [resource/reference identity rule](web-packaging.md#keep-resources-and-runtime-references-together).

| Artifact | SHA-256 / identity |
|---|---|
| `llm_bin_patch-0.1.0.zip` | `896084be3ad2e49741d9d6da211616cbcb007a2133f96ebc524bd588608837ff` |
| Embedded application JAR | `65adac651a6e8675bc5345c0b25ac4c0a09a2ef98bbc00c7b946a0e3e319653c` |
| UI build | `8ae87961b642338c6a4353c600b2afe34d256ac8fdcc4ee9fd656a9d89806e16` (21 files, 380,856 bytes) |
| Chrome binary | `2d18db9d8608b052b6a552ee00ec1e830f93692e928b65ecc67d693bd33fe801` (Chrome/149.0.7827.55) |

## Command-name and link audit

Every Gradle task the four documents name exists in `build.gradle.kts`. The frontend
tasks run `npm ci --ignore-scripts --no-audit --no-fund` as documented. The npm scripts
the documents use (`typecheck`, `lint`, `test`, `build`, `dev`, `dev:fixtures`, `api:generate`,
`api:check`, `fixtures:check`) exist in `frontend/package.json`. So does every
referenced script, lock file, requirements file and test class. The CI job names,
artifact names, 14-day retention and browser modes (`session`, `metadata`, `live`,
`scale`, `proxy`) match `.github/workflows/ci.yml`. All 61 local links and anchors in the
four documents and `frontend/README.md` resolve.

## Drift found and corrected

- [Packaging](web-packaging.md): the introduction listed only bootstrap and single-job reads. It also said the legacy UI had not migrated to the session boundary, but [legacy session migration](web-api.md#legacy-session-migration) shows that it has. Both statements now match master.
- The fixture guide set a new `GRADLE_USER_HOME`. That would download the Gradle distribution, the dependencies and Ghidra again and recompile the build. It now keeps the setup's Gradle user home.
- The fixture guide did not say that `dev:fixtures` uses a strict port. It now documents `DECOMP_DEV_PORT` and warns that a page on 5173 may come from another server.
- The fixture guide used `build/web-test-browser/chrome` without the install step. The step is now shown.
- Packaging now states the checkout path length limit that Chrome's socket imposes on the browser driver.
- Packaging now states that every Gradle invocation that reaches `jar` changes the application JAR digest. ZIP/TAR digests change only when those archive tasks run; a focused `test` refreshes the installed distribution but can leave older archives in place. The native-helper build records contain random scratch names and the absolute checkout path ([#1790](https://github.com/minsago-elite/decomp_thing/issues/1790), filed from this replay and closed as a duplicate of [#1789](https://github.com/minsago-elite/decomp_thing/issues/1789)).

## Not executed

- Browser modes `proxy`, `live` and `scale`. The normal CI lane is configured to run these alongside `session` and `metadata`; that configuration is not evidence of a successful current-head run.
- Browser mode `upgrade`, which needs two separately qualified archives.
- Browser modes `upload`, `history` and `legacy`. Neither this replay nor the normal CI lane executes these modes, so their qualification remains missing here. The shared upload check in `metadata` does not replace the additional mode-gated `upload` journeys.
- The complete Kotlin suite, opt-in live Ghidra cases, Docker, and the CI host's Python 3.12. This host used 3.14.9.
- The fixture guide's original separate `GRADLE_USER_HOME`. It was replaced as described above.
- The replay checkout path contained a dot-prefixed component (`.claude/worktrees/…`). Ghidra refuses such project paths ([#1785](https://github.com/minsago-elite/decomp_thing/issues/1785)), but no documented step here runs a Ghidra project analysis, so none failed for that reason.
