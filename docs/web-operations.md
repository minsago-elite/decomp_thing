# Operating the web workbench

This guide covers [#667](https://github.com/minsago-elite/decomp_thing/issues/667) under tracker
[#232](https://github.com/minsago-elite/decomp_thing/issues/232). It is for whoever installs and
runs the workbench. It explains how to check the version, readiness and storage of a running
server, and how to collect a redacted support bundle. Everything here describes `master` at
`33c49f95`. The [user guide](workbench-user-guide.md) covers sessions, uploads and the UI. See also
[release artifacts](web-release.md) and [backup and restore](web-backup-restore.md).

## Deployment boundary

`master` supports one server per data directory, bound to loopback, used by one person through
the launcher's local session link. `web --ui spa` refuses a non-loopback `--host` with "the SPA
preview currently requires a loopback host". The legacy UI refuses one with "legacy browser access
requires a loopback host until a remote access profile is qualified". The optional authenticated
reverse-proxy profile is pending in #1780. Keep the installation read-only, and keep the data
directory outside it.

Ghidra refuses project paths with a component that starts with a dot, including the default
`--data-dir .decomp_engine/jobs`
([#1785](https://github.com/minsago-elite/decomp_thing/issues/1785)). Pass a `--data-dir` such
as `/srv/decomp/jobs` if the store will be used for analysis.

## Version and build identity

There is no `llm_bin_patch --version`, and `web --help` fails with a stack trace ("--help
requires a value"); use `llm_bin_patch --help` instead. These are the ways to identify a build:

| Identity | Where to read it |
|---|---|
| Application version | The application JAR name, `lib/llm-bin-patch-<version>.jar`, and the **Runtime** page. |
| Server build (`applicationBuildId`) | The SHA-256 of the application JAR: `sha256sum lib/llm-bin-patch-*.jar`. The Runtime page shows it as **Server build**, and the session reply includes it. |
| UI build (`uiBuildId`) | The `buildId` of `decompengine/web/ui/asset-manifest.json` inside the application JAR. The Runtime page shows it as **UI build** and warns when the page and the server differ. |
| Release | `release-record.json` and `SHA256SUMS` from [release assembly](web-release.md#assemble-and-verify-a-release-directory). `applicationBuildId` there must equal the running server's. |

To capture the server's own reply without the browser, exchange a fresh launcher link once.
The token is the part after `#bootstrap=`:

```sh
curl -s -H 'Accept: application/json' -H 'Content-Type: application/json' \
  -H 'Origin: http://127.0.0.1:8000' -d '{"token":"<token>"}' \
  http://127.0.0.1:8000/api/v1/session > session.json
```

`session.json` contains a CSRF token. Treat it as a secret. Pass it to the support-bundle collector,
which keeps only allowlisted fields, rather than sharing it.

## Readiness

- **Runtime page / session reply.** `readiness` is `degraded` on `master`, because the `workflows`
  capability is `unavailable` ("Workflow actions are unavailable in this preview."). This is
  expected. The `harness` capability reports whether an agent harness is configured. `runtime`
  reports the Java version, OS, architecture, `gitVersion` (`null` on `master`), the workflow
  scheduler (workers, queue capacity, lifecycle) and progress retention (`enabled`, `examined`,
  `expired`, `failures`, `lastFailureCode`).
- **`llm_bin_patch doctor --tools-only`** checks the analysis toolchain without an agent. Each
  line is `[ok]` or `[failed]` with a remedy. The exit status is non-zero when any check fails.
  Plain `doctor` also checks the agent harness.
- **Startup refusals** happen before the server binds. They print a Java stack trace whose first
  line carries the message. Examples: "Job store already has a live web server owner" (another
  server owns the data directory); "This workflow storage version is unsupported; use a compatible
  application or restore a backup." (see
  [schema compatibility](web-backup-restore.md#schema-compatibility-and-rollback));
  `Cannot bind web server to 127.0.0.1:8000. Check --host or choose an unused --port.`
  (exit status 2).

## Storage

- `GET /api/v1/recovery` (requires a session) returns a display-only inventory with
  `scannedEntries`, `retainedUploadStages`, `retainedMetadataFiles`, `observedBytes`,
  `uninspectedEntries` and `inventoryComplete`. A retained upload stage is not proof that deletion
  is safe. See [upload staging recovery](web-upload-staging-recovery.md).
- Upload admission measures retained bytes with the bounded scan in
  [retained-storage accounting](web-retained-storage-accounting.md). An incomplete scan fails with
  `STORAGE_ACCOUNTING_UNAVAILABLE` and deletes nothing.
- With `--ui spa`, progress retention compacts terminal progress journals after 24 hours unless
  the attempt is pinned. The legacy UI keeps retention disabled. `master` has no job deletion. Reclaiming space means stopping the server and removing a
  job directory deliberately, after a [backup](web-backup-restore.md).
- `storage.json` in a support bundle gives counts and byte totals without names.

## Logs

The launcher writes to its own stdout and stderr. It keeps no log file, so redirect them if you
want one.

- **stdout** carries the serving line and the **single-use session link**. Do not share stdout as is.
- **stderr** carries one `web-http-failure request_id=<uuid> status=<code> code=<CODE>` line for
  each failed request. The UI shows the same request ID as the **reference** of an error. These
  lines never include request targets, headers, values or exception text, so they are safe to
  share. Startup stack traces also go to stderr.

## Support bundles

`scripts/collect-support-bundle.py` builds a bundle from allowlisted facts only. Run it from a
repository checkout, or copy the single file next to the installation; it needs only Python 3.
The output goes to `build/support/` by default:

```sh
python3 scripts/collect-support-bundle.py \
  --install /opt/llm_bin_patch \
  --data-dir /srv/decomp/jobs \
  --server-log server.err \
  --runtime-json session.json
```

| File | Contents |
|---|---|
| `distribution.json` | Version, `applicationBuildId` and `uiBuildId`, computed from the installed JAR. |
| `java.txt` | The version lines of `java -version` for `JAVA_HOME` or `PATH`. The probe runs without `JAVA_TOOL_OPTIONS`, `JDK_JAVA_OPTIONS` and `_JAVA_OPTIONS`, and any other output line is dropped, so echoed JVM options never appear. |
| `doctor.txt` | `doctor --tools-only` status and summary lines only. Host paths and secret-looking environment values are replaced. Pass `--no-doctor` to skip it. |
| `storage.json` | Job-directory, file, directory and byte counts, pending records, which of the two owner locks (`.web-owner.lock`, `.workflow-owner.lock`) exist, and a count of `workflow-state.json` schema versions. No names, job IDs or contents. |
| `requests.txt` | The last 1,000 `web-http-failure` lines of the given log. Every other line, including the session link and stack traces, is dropped. |
| `runtime.json` | From a saved session or bootstrap reply: build IDs, readiness, capability IDs, states and reason codes, limits and runtime facts. The CSRF token, session expiry and server instance ID are dropped. |
| `README.txt` | What was included and what was excluded. |

The collector never reads binaries, `job.json`, reports, sources or archives, and never copies
the environment. Before it reports success, it rescans every file it wrote. It fails, and deletes
the bundle, if any file contains one of these:

- the installation, data directory, home or working-directory path;
- the value of an environment variable whose name looks secret (`TOKEN`, `SECRET`, `KEY`,
  `PASSWORD`, `CREDENTIAL`, `AUTH`, `COOKIE` or `SESSION`);
- a `#bootstrap=` link, a `decomp_session_` cookie or a `csrfToken`.

`tests/test_support_bundle.py` checks these rules with a synthetic installation, store, log and
session reply.

Review the bundle before you send it. It deliberately leaves out the evidence needed to
investigate a specific job. Share that only if you intend to.

PR #1704 is open and adds shared server-side redaction, audit records for sensitive actions, and a
scoped support-export preview in the UI. Once it lands, this section should point to that export
and describe how it relates to this collector.
