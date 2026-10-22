# Workbench user guide

This guide is for people who want to run the browser workbench and understand what it will and will not do for them.
Every behaviour described here was observed on a build of `master` (`44a13178`, October 2026) by running the installed
launcher; anything not observed is marked **not verified** or **not available**. Developers building or packaging the UI
should read [packaging and preview usage](web-packaging.md) instead.

## Two interfaces

The `web` command serves one of two interfaces:

| Interface | Command | What it is |
|---|---|---|
| Legacy workbench (default) | `llm_bin_patch web` | The full workbench described in the [README](../README.md#browser-gui): uploads, exploration, archival reconstruction, source browsing. **Not re-verified for this guide.** |
| Embedded preview | `llm_bin_patch web --ui spa` | The new Preact interface that ships inside the application JAR. It is a **read-and-upload preview**: see [What the preview can do](#what-the-preview-can-do). |

Both use the same local-session security model (below). Pick the preview to try the new interface; use the legacy
workbench for anything that starts analysis.

## What you need

**To run the installed application**: a JDK 21 (the version the container image and CI use) and the distribution produced by `./gradlew installDist` (or the
`distZip`/`distTar` archives). The interface is **inside the application JAR**. There is no Node, CDN or external web
server at run time.

**To build it** (developers only): the pinned Node/npm from [`.node-version`](../.node-version), installed with
`scripts/install-frontend-node.sh`. Node is a build-time dependency of the embedded interface and nothing else.

**For analysis work** (separate from the interface): Ghidra is a hash-locked **bundled** dependency, not something to
install. A missing bundled artifact is an availability failure of the application, not a `GHIDRA_HOME` you should set.
`doctor` checks the rest of the analysis toolchain; see [Checking readiness](#checking-readiness). Reconstruction
additionally needs a provisioned agent harness (see the README); the preview does not start those workflows.

## Launch

```sh
./gradlew installDist
build/install/llm_bin_patch/bin/llm_bin_patch web --ui spa
```

| Option | Default | Meaning |
|---|---|---|
| `--host` | `127.0.0.1` | Interface to bind. Keep the default; exposing the server to other machines is not covered here. |
| `--port` | `8000` | TCP port. |
| `--data-dir` | `.decomp_engine/jobs` | Where uploaded jobs are stored (see [Your data](#your-data)). |
| `--ui` | `legacy` | `legacy` or `spa`. |
| `--base-path` | `/` | Serve under a prefix such as `/workbench/`. |

On start the launcher prints two lines:

```text
Serving decomp_engine spa UI on http://127.0.0.1:8000/
Open local browser session (expires 2026-10-22T01:01:19Z): http://127.0.0.1:8000/#bootstrap=<token>
```

Open the second URL in your browser. The legacy workbench prints the same pair, with the link at `/login#bootstrap=…`.

## Sessions

- The printed link is a **single-use, five-minute** local session link. Opening it removes the token from the address
  bar and starts a session; the session lasts **eight hours**. Its cookie is `HttpOnly; SameSite=Strict`.
- Using the link a second time fails with `BOOTSTRAP_REQUIRED: Open a newly issued local browser link.` Restart the
  launcher for a new link; it prints a fresh one on every start.
- Without a session, the API answers `401 SESSION_REQUIRED: Open a local browser link to start a session.` The public
  pages (`/`, `/runtime`) still load so the interface can explain itself.
- **Sign out** ends the session explicitly. Nothing is started or changed by creating a session, navigating or
  refreshing.

## What the preview can do

Verified against the running preview:

- **Runtime status** (`/runtime`): what the server reports about workflow availability. The server currently reports a
  single `workflows` capability as `unavailable` with the message *"Workflow actions are unavailable in this preview."*
  and overall readiness as `degraded`. That is expected, not a fault.
- **Upload a binary** (`/upload`): ELF files up to **32 MiB** (the server's reported `maxUploadBytes`, 33,554,432). The
  page shows progress. A successful upload creates a job with status `uploaded`; **no analysis starts**. The server
  reads the ELF header and shows format, endianness, object type, machine, OS ABI and entry point.
- **Retrying an interrupted upload is safe.** If the connection drops and the result is unconfirmed, the page retries
  with the same idempotency key; the server returns the **same job** and does not create a duplicate.
- **Job library** (`/`): your uploaded jobs, newest first by default, 50 per page (up to 200). You can filter by
  filename, workflow state and a created-between range, and sort oldest or newest first. Applied filters become part of
  the address, so a filtered view can be bookmarked or shared.
- **Job overview** and **attempt history** (`/jobs/<id>`, `/jobs/<id>/runs`): the stored facts about a job and any recorded
  attempts.

**Not available in the preview:** starting exploration, reconstruction, builds, validation or repair ("*… is unavailable
in this preview*"), editing or deleting a job, downloading artifacts or browsing source (the server reports a source
chunk limit of 0), and Git workflows. Use the legacy workbench for analysis workflows.

## Complete, validated, accepted

The interface keeps three ideas apart on purpose, and says so in its own words:

- *"Completion is an attempt outcome. Only the recorded accepted revision identifies accepted reconstruction."*
- *"Completion does not establish validated reconstruction."* (shown beside every job list)
- An attempt page keeps its exact identity as newer work is recorded, so you can always tell which attempt you are
  looking at.

Read them as three separate questions: did the attempt **finish** (complete)? Was its output **checked against
evidence** (validated)? Was a specific revision **recorded as accepted**? A finished attempt answers only the first.

## Your data

Uploaded jobs are stored under `--data-dir`, one directory per job named by its 32-character id:

```text
<data-dir>/
  .web-owner.lock  .workflow-owner.lock
  85f2127bb25be8b89ec995987f0c25fe/
    input.elf   job.json   upload-receipt.json
```

- Keep the data directory **outside** the installed distribution; the application files are immutable.
- **Run one server per data directory.** The preview did not refuse to start a second server on the same directory
  during testing, so avoid it.
- The server reports a terminal-event retention limit of **24 hours** (`terminalEventRetentionMs`: 86,400,000). A
  pinned attempt keeps its stored progress history; unpinning allows retention cleanup. **Not verified:** how long job directories themselves are kept;
  the preview offers no delete.
- **Not verified:** a backup or restore procedure. Stop the server before copying anything, and treat a restored
  directory as untested until the D-series backup work lands.

## Checking readiness

```sh
build/install/llm_bin_patch/bin/llm_bin_patch doctor --tools-only
```

Each check prints `[ok]` or `[failed]` with what to do. Example from a host without angr:

```text
[ok] Java: Check passed.
[ok] Ghidra: Check passed.
[ok] bubblewrap: Check passed.
[failed] angr: Install angr for the selected Python interpreter or set ANGR_PYTHON.
Environment check failed (1 check(s)); resolve each [failed] item above.
```

The exit status is non-zero when any check fails. `--tools-only` needs no agent; plain `doctor` also checks the agent
harness (see the README).

## When something goes wrong

| You see | Meaning and what to do |
|---|---|
| `Cannot bind web server to 127.0.0.1:8000. Check --host or choose an unused --port.` | The port is busy. Pick another with `--port`. |
| `BOOTSTRAP_REQUIRED` / "Open a newly issued local browser link." | The link was used or expired. Restart the launcher and open the new link. |
| `SESSION_REQUIRED` / "Open a local browser link to start a session." | You are not signed in, or the session ended. Open the launcher's link. |
| "The local session expired or is unavailable. Reconnect the session to read this job." | Your eight-hour session ended. Restart the launcher for a new link. |
| "This job is unavailable. It may have been removed." | The job id does not exist (or was removed from the data directory). The page keeps a **Return to jobs** link. |
| "This interface cannot read the server's response format. Refresh the page before trying to read this job again." | The page and the server are different builds. Refresh the page; if it persists, restart the launcher. |
| "Stored jobs could not be listed completely. The server has not returned a partial library; inspect job storage before retrying." | A stored job directory is damaged or unreadable. The server will not show a partial list; check the data directory. |
| "This page snapshot expired. Refresh jobs to start a new snapshot." | A paged listing went stale. Use **Refresh jobs**. |
| Startup fails before a socket is bound | Documented in [packaging and preview usage](web-packaging.md) for missing or inconsistent packaged interface files; **not reproduced here**. Rebuild the distribution. |

When you report a problem, include the **reference** shown with an error message (a request id), the output of
`doctor --tools-only`, and the launcher command you used. Do **not** attach uploaded binaries or a job directory unless
you intend to share them.

## What this guide does not cover

Screenshots (none are included; the interface is still changing), the legacy workbench's workflows, remote or
multi-user deployment, Git and pull-request workflows, and release or upgrade procedures. Track those under the D-series
milestones.
