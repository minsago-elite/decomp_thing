package decompengine.web

import decompengine.jobs.Job
import decompengine.jobs.toJson
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.doubleOrNull
import kotlinx.serialization.json.intOrNull
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.net.URLEncoder
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.Path
import kotlin.io.path.exists
import kotlin.io.path.isRegularFile
import kotlin.io.path.name
import kotlin.io.path.readText
import kotlin.math.roundToInt

fun renderDashboard(jobs: List<Job>): String = page(
    title = "Binary workbench",
    body = """
      <header class="hero shell">
        <div class="eyebrow"><span class="signal"></span> Binary reconstruction workbench</div>
        <h1>Understand the binary.<br><em>Keep the evidence.</em></h1>
        <p class="lede">Upload a Linux x86-64 ELF, generate validation inputs, inspect observed behavior, and carry every artifact into repair.</p>
      </header>
      <main class="shell dashboard-grid">
        <section class="panel upload-panel" aria-labelledby="upload-title">
          <div class="section-heading">
            <span class="step">01</span>
            <div><p class="kicker">New analysis</p><h2 id="upload-title">Add an ELF binary</h2></div>
          </div>
          <form action="/jobs" method="post" enctype="multipart/form-data" class="upload-form">
            <label class="drop-zone" for="binary">
              <span class="upload-mark" aria-hidden="true">↑</span>
              <strong>Choose a binary</strong>
              <span id="file-name">or drop it here · maximum 32 MiB</span>
              <input id="binary" name="binary" type="file" accept=".elf,application/x-elf" required>
            </label>
            <button class="button primary" type="submit">Create analysis job <span>↗</span></button>
          </form>
          <div class="guardrails">
            <span>ELF64</span><span>x86-64</span><span>Sandboxed execution</span>
          </div>
        </section>
        <section class="panel queue-panel" aria-labelledby="jobs-title">
          <div class="section-heading compact">
            <span class="step">02</span>
            <div><p class="kicker">Workspace</p><h2 id="jobs-title">Recent jobs</h2></div>
            <span class="count">${jobs.size}</span>
          </div>
          ${renderJobList(jobs)}
        </section>
      </main>
    """.trimIndent(),
    script = """
      const input = document.querySelector('#binary');
      const name = document.querySelector('#file-name');
      input?.addEventListener('change', () => {
        name.textContent = input.files?.[0]?.name || 'or drop it here · maximum 32 MiB';
      });
    """.trimIndent(),
)

fun renderJob(job: Job): String {
    val active = job.status in setOf("queued", "analyzing")
    val metadata = job.metadata.toJson().entries.joinToString("") { (key, value) ->
        "<div class=\"datum\"><dt>${key.replace('_', ' ').title().escapeHtml()}</dt><dd>${value.toString().trim('"').escapeHtml()}</dd></div>"
    }
    val jobDir = job.binaryPath.parent
    val artifacts = listArtifacts(jobDir)
    val action = if (active) {
        "<button class=\"button primary\" disabled>Analysis in progress <span class=\"spinner\"></span></button>"
    } else {
        val label = if (job.status == "complete") "Run exploration again" else "Start automatic exploration"
        """
        <form action="/jobs/${job.id}/reconstruct" method="post"><button class="button primary" type="submit">Generate source tree <span>↗</span></button></form>
        <form action="/jobs/${job.id}/explore" method="post"><button class="button secondary" type="submit">$label</button></form>
        """.trimIndent()
    }
    val script = if (active) """
        const initialStatus = ${jsString(job.status)};
        const poll = async () => {
          try {
            const response = await fetch('/api/jobs/${job.id}', {cache: 'no-store'});
            if (!response.ok) return;
            const job = await response.json();
            if (job.status !== initialStatus || !['queued', 'analyzing'].includes(job.status)) location.reload();
          } finally {
            setTimeout(poll, 1500);
          }
        };
        setTimeout(poll, 900);
    """.trimIndent() else ""
    return page(
        title = job.filename,
        body = """
          <main class="shell job-shell">
            <a class="back-link" href="/">← All jobs</a>
            <section class="job-header">
              <div>
                <div class="eyebrow"><span class="signal"></span> Analysis job</div>
                <h1>${job.filename.escapeHtml()}</h1>
                <p class="job-id">${job.id.escapeHtml()}</p>
              </div>
              <div class="job-actions">
                ${statusPill(job.status)}
                $action
              </div>
            </section>
            ${job.statusMessage?.let { "<div class=\"status-note ${job.status.escapeHtml()}\"><span></span>${it.escapeHtml()}</div>" }.orEmpty()}
            <div class="job-grid">
              <section class="panel overview-panel">
                <div class="section-heading compact"><span class="step">01</span><div><p class="kicker">Binary profile</p><h2>ELF metadata</h2></div></div>
                <dl class="metadata-grid">
                  <div class="datum"><dt>Original filename</dt><dd>${job.filename.escapeHtml()}</dd></div>
                  <div class="datum"><dt>Size</dt><dd>${formatBytes(job.sizeBytes)}</dd></div>
                  <div class="datum"><dt>Created</dt><dd>${formatTimestamp(job.createdAt)}</dd></div>
                  <div class="datum"><dt>Updated</dt><dd>${formatTimestamp(job.updatedAt)}</dd></div>
                  $metadata
                </dl>
              </section>
              <section class="panel workflow-panel">
                <div class="section-heading compact"><span class="step">02</span><div><p class="kicker">Workflow</p><h2>What exploration does</h2></div></div>
                <ol class="workflow-list">
                  <li><span>1</span><div><strong>Symbolic paths</strong><p>angr derives reachable argv and stdin candidates.</p></div></li>
                  <li><span>2</span><div><strong>Static + mutations</strong><p>Binary strings seed bounded input variations.</p></div></li>
                  <li><span>3</span><div><strong>Observed evidence</strong><p>Sandboxed executions become coverage and confidence evidence.</p></div></li>
                </ol>
              </section>
            </div>
            ${renderExploration(job)}
            ${renderReconstructionProgress(job)}
            ${renderSourceTree(job)}
            ${renderRepairHistory(job)}
            ${renderArtifacts(job, artifacts)}
          </main>
        """.trimIndent(),
        script = script,
    )
}

fun renderSourceFile(
    job: Job,
    relativePath: String,
    source: String,
    manifest: JsonObject? = null,
    confidence: JsonObject? = null,
): String {
    val fileEvidence = manifest?.get("files")?.jsonArray?.mapNotNull { it as? JsonObject }
        ?.firstOrNull { it.text("path") == relativePath }
    val generator = fileEvidence?.text("generator").orEmpty()
    val entities = fileEvidence?.get("entityIds")?.jsonArray?.joinToString(", ") { it.jsonPrimitive.content }.orEmpty()
    val moduleId = relativePath.substringAfterLast('/').substringBeforeLast('.')
    val moduleConfidence = runCatching {
        confidence?.get("modules")?.jsonArray
            ?.mapNotNull { it as? JsonObject }?.firstOrNull { it.text("id") == moduleId }
            ?.get("score")?.jsonPrimitive?.doubleOrNull
    }.getOrNull()
    val provenance = if (fileEvidence == null) "" else """
        <div class="source-provenance"><span><b>Generator</b>${generator.escapeHtml()}</span><span><b>Entities</b>${entities.escapeHtml().ifBlank { "none" }}</span>${moduleConfidence?.let { "<span><b>Module confidence</b>${(it * 100).roundToInt()}%</span>" }.orEmpty()}</div>
    """.trimIndent()
    return page(
        title = relativePath,
        body = """
      <main class="shell source-shell">
        <a class="back-link" href="/jobs/${job.id}">← ${job.filename.escapeHtml()}</a>
        <section class="source-heading"><div><p class="kicker">Generated source</p><h1>${relativePath.escapeHtml()}</h1></div><a class="button secondary" href="${artifactHref(job, "reports/source-tree/$relativePath")}">Download</a></section>
        $provenance
        <pre class="source-view"><code>${source.escapeHtml()}</code></pre>
      </main>
        """.trimIndent(),
    )
}

fun renderErrorPage(status: Int, title: String, message: String): String = page(
    title = title,
    body = """
      <main class="shell error-shell">
        <p class="error-code">$status</p>
        <h1>${title.escapeHtml()}</h1>
        <p>${message.escapeHtml()}</p>
        <a class="button primary" href="/">Return to workbench</a>
      </main>
    """.trimIndent(),
)

private fun renderJobList(jobs: List<Job>): String {
    if (jobs.isEmpty()) return """
        <div class="empty-state">
          <span>◇</span><strong>No jobs yet</strong><p>Your uploaded binaries will appear here.</p>
        </div>
    """.trimIndent()
    return "<div class=\"job-list\">" + jobs.joinToString("") { job ->
        """
        <a class="job-row" href="/jobs/${job.id}">
          <span class="file-glyph">ELF</span>
          <span class="job-copy"><strong>${job.filename.escapeHtml()}</strong><small>${formatBytes(job.sizeBytes)} · ${formatTimestamp(job.createdAt)}</small></span>
          ${statusPill(job.status)}
          <span class="arrow">→</span>
        </a>
        """.trimIndent()
    } + "</div>"
}

private fun renderExploration(job: Job): String {
    val reportPath = job.binaryPath.parent.resolve("reports/exploration.json")
    if (!reportPath.exists()) return """
        <section class="panel evidence-panel pending-evidence">
          <div class="section-heading compact"><span class="step">03</span><div><p class="kicker">Evidence</p><h2>Exploration report</h2></div></div>
          <p>Run automatic exploration to generate input, coverage, and confidence evidence.</p>
        </section>
    """.trimIndent()
    val root = runCatching { Json.parseToJsonElement(reportPath.readText()).jsonObject }.getOrNull()
        ?: return "<section class=\"panel evidence-panel\"><h2>Exploration report</h2><p>The report could not be parsed.</p></section>"
    val confidence = root["confidence"]?.jsonObject
    val score = confidence?.get("score")?.jsonPrimitive?.doubleOrNull ?: 0.0
    val candidates = root["candidates"]?.jsonArray ?: JsonArray(emptyList())
    val observations = root["observations"]?.jsonArray?.associateBy {
        it.jsonObject["candidateId"]?.jsonPrimitive?.contentOrNull.orEmpty()
    }.orEmpty()
    val rows = candidates.take(50).joinToString("") { element ->
        val candidate = element.jsonObject
        val id = candidate.text("id")
        val source = candidate.text("source")
        val args = candidate["args"]?.jsonArray?.joinToString(" ") { it.jsonPrimitive.content }.orEmpty()
        val stdinHex = candidate.text("stdinHex")
        val observation = observations[id]?.jsonObject
        val exitCode = observation?.get("exitCode")?.jsonPrimitive?.intOrNull?.toString() ?: "—"
        val output = observation?.text("stdoutHex")?.hexPreview().orEmpty().ifBlank { "∅" }
        "<tr><td><code>${id.escapeHtml()}</code></td><td><span class=\"source-tag ${source.lowercase()}\">${source.escapeHtml()}</span></td><td>${args.escapeHtml().ifBlank { "—" }}</td><td><code>${stdinHex.chunked(2).take(12).joinToString(" ").escapeHtml().ifBlank { "—" }}</code></td><td>$exitCode</td><td><code>${output.escapeHtml()}</code></td></tr>"
    }
    return """
      <section class="panel evidence-panel">
        <div class="section-heading compact"><span class="step">03</span><div><p class="kicker">Evidence</p><h2>Exploration report</h2></div><a class="text-link" href="${artifactHref(job, "reports/exploration.json")}">Download JSON ↓</a></div>
        <div class="metric-grid">
          ${metric("Confidence", "${(score * 100).roundToInt()}%", "Evidence-bounded", score)}
          ${metric("Candidates", root.number("candidateCount"), "Generated inputs")}
          ${metric("Output paths", root.number("expandedOutputSignatures"), "Distinct signatures")}
          ${metric("New paths", root["newOutputSignatures"]?.jsonArray?.size?.toString() ?: "0", "Beyond baseline")}
        </div>
        <div class="table-wrap">
          <table><thead><tr><th>Case</th><th>Source</th><th>Arguments</th><th>stdin · hex</th><th>Exit</th><th>stdout</th></tr></thead><tbody>$rows</tbody></table>
        </div>
        ${if (candidates.size > 50) "<p class=\"table-note\">Showing 50 of ${candidates.size} candidates. Download JSON for the full report.</p>" else ""}
      </section>
    """.trimIndent()
}

fun renderRepairHistory(job: Job): String {
    val historyPath = job.binaryPath.parent.resolve("reports/repair_history.json")
    if (!historyPath.exists()) return ""
    val payload = runCatching { Json.parseToJsonElement(historyPath.readText()).jsonObject }.getOrNull()
        ?: return "<section class=\"panel history-panel\"><h2>Repair history</h2><p>Repair history could not be loaded.</p></section>"
    val iterations = payload["iterations"] as? JsonArray ?: return ""
    if (iterations.isEmpty()) return ""
    val items = iterations.mapNotNull { it as? JsonObject }.joinToString("") { iteration ->
        val index = iteration.text("index").ifBlank { "?" }
        val failureKind = iteration.text("failureKind").ifBlank { "unknown" }
        val summary = iteration.text("summary")
        val succeeded = iteration["succeeded"]?.toString() == "true"
        val regressions = (iteration["retainedRegressionIds"] as? JsonArray)
            ?.joinToString(", ") { it.jsonPrimitive.content.escapeHtml() }.orEmpty()
        val before = renderEvidence("Before", iteration["before"] as? JsonObject)
        val after = renderEvidence("After", iteration["after"] as? JsonObject)
        val outcome = if (succeeded) "passed" else "needs another iteration"
        "<article class=\"history-item\"><div class=\"history-index\" aria-label=\"Iteration $index\">$index</div><div><div class=\"history-title\"><strong>${failureKind.escapeHtml()} — $outcome</strong>${statusPill(if (succeeded) "complete" else "analyzing")}</div><p>${summary.escapeHtml()}</p>$before$after<p class=\"regressions\"><b>Retained:</b> $regressions</p></div></article>"
    }
    return """
      <section class="panel history-panel">
        <div class="section-heading compact"><span class="step">04</span><div><p class="kicker">Iteration log</p><h2>Repair History</h2></div></div>
        <div class="history-list">$items</div>
      </section>
    """.trimIndent()
}

private fun renderEvidence(label: String, evidence: JsonObject?): String {
    if (evidence == null) return ""
    val kind = evidence.text("kind")
    val summary = evidence.text("summary")
    val artifact = evidence.text("artifactPath")
    return "<p class=\"evidence-line\"><b>$label:</b><span>${kind.escapeHtml()} — ${summary.escapeHtml()}</span>${if (artifact.isBlank()) "" else "<code>${artifact.escapeHtml()}</code>"}</p>"
}

private fun renderArtifacts(job: Job, artifacts: List<Path>): String {
    if (artifacts.isEmpty()) return ""
    val root = job.binaryPath.parent
    val links = artifacts.joinToString("") { artifact ->
        val relative = root.relativize(artifact).toString()
        "<a class=\"artifact-row\" href=\"${artifactHref(job, relative)}\"><span class=\"artifact-icon\">${artifact.fileName.toString().substringAfterLast('.', "FILE").uppercase().take(4)}</span><span><strong>${artifact.name.escapeHtml()}</strong><small>${relative.escapeHtml()} · ${runCatching { formatBytes(Files.size(artifact).toInt()) }.getOrDefault("unknown")}</small></span><span>↓</span></a>"
    }
    return """
      <section class="panel artifacts-panel">
        <div class="section-heading compact"><span class="step">05</span><div><p class="kicker">Deliverables</p><h2>Artifacts</h2></div><span class="count">${artifacts.size}</span></div>
        <div class="artifact-list">$links</div>
      </section>
    """.trimIndent()
}

private fun renderSourceTree(job: Job): String {
    val root = job.binaryPath.parent.resolve("reports/source-tree")
    val manifest = root.resolve("source_tree_manifest.json")
    if (!manifest.exists()) return ""
    val files = Files.walk(root).use { paths ->
        paths.filter { it.isRegularFile() }.map { root.relativize(it).toString().replace('\\', '/') }
            .filter { it == "Makefile" || it.endsWith(".c") || it.endsWith(".h") || it.endsWith(".json") || it.endsWith(".md") || it.endsWith(".log") }
            .sorted().toList()
    }
    val rows = files.joinToString("") { relative ->
        val depth = relative.count { it == '/' }
        val kind = relative.substringAfterLast('.', "file").uppercase().take(4)
        "<li style=\"--depth:$depth\"><a href=\"/jobs/${job.id}/source/${encodePath(relative)}\"><span>$kind</span><code>${relative.escapeHtml()}</code><i>→</i></a></li>"
    }
    val confidencePath = root.resolve("reports/confidence.json")
    val confidence = runCatching {
        Json.parseToJsonElement(confidencePath.readText()).jsonObject["projectScore"]?.jsonPrimitive?.doubleOrNull
    }.getOrNull()
    val bundle = job.binaryPath.parent.resolve("reports/source-tree.zip")
    return """
      <section class="panel source-tree-panel">
        <div class="section-heading compact"><span class="step">04</span><div><p class="kicker">Reconstructed project</p><h2>Archival source tree</h2></div>${confidence?.let { "<span class=\"count\">${(it * 100).roundToInt()}%</span>" }.orEmpty()}</div>
        <p class="tree-note">${files.size} readable project files. Confidence is evidence-bounded and does not claim universal equivalence.</p>
        <ul class="source-tree">$rows</ul>
        ${if (bundle.exists()) "<a class=\"button primary archive-download\" href=\"${artifactHref(job, "reports/source-tree.zip")}\">Download verified source archive ↓</a>" else ""}
      </section>
    """.trimIndent()
}

private fun renderReconstructionProgress(job: Job): String {
    val path = job.binaryPath.parent.resolve("reports/reconstruction_progress.json")
    if (!path.exists()) return ""
    val progress = runCatching { Json.parseToJsonElement(path.readText()).jsonObject }.getOrNull() ?: return ""
    val phase = progress.text("phase")
    val completed = progress.number("completed")
    val total = progress.number("total")
    val module = progress.text("module")
    return """
      <section class="panel reconstruction-progress">
        <div><p class="kicker">Source reconstruction · ${phase.escapeHtml()}</p><h2>$completed / $total modules</h2></div>
        ${if (module.isBlank()) "" else "<code>${module.escapeHtml()}</code>"}
      </section>
    """.trimIndent()
}

private fun listArtifacts(jobDir: Path): List<Path> {
    if (!jobDir.exists()) return emptyList()
    return Files.walk(jobDir).use { paths ->
        paths.filter { it.isRegularFile() && it.name != "input.elf" && it.name != "job.json" }
            .sorted()
            .toList()
    }
}

private fun metric(label: String, value: String, detail: String, score: Double? = null): String {
    val gauge = score?.let { "<span class=\"gauge\"><i style=\"width:${(it.coerceIn(0.0, 1.0) * 100).toInt()}%\"></i></span>" }.orEmpty()
    return "<div class=\"metric\"><p>$label</p><strong>$value</strong><small>$detail</small>$gauge</div>"
}

private fun statusPill(status: String): String =
    "<span class=\"status-pill ${status.escapeHtml()}\"><i></i>${status.replace('_', ' ').title().escapeHtml()}</span>"

private fun artifactHref(job: Job, relative: String): String =
    "/jobs/${job.id}/artifacts/" + relative.split('/', '\\').joinToString("/") {
        URLEncoder.encode(it, StandardCharsets.UTF_8).replace("+", "%20")
    }

private fun encodePath(relative: String): String = relative.split('/').joinToString("/") {
    URLEncoder.encode(it, StandardCharsets.UTF_8).replace("+", "%20")
}

private fun page(title: String, body: String, script: String = ""): String = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="color-scheme" content="dark">
  <title>${title.escapeHtml()} · decomp_engine</title>
  <link rel="stylesheet" href="/assets/app.css">
</head>
<body>
  <nav class="topbar"><a href="/" class="brand"><span>de</span> decomp_engine</a><span class="build-label">LOCAL WORKBENCH</span></nav>
$body
  <footer class="shell"><span>decomp_engine</span><span>Evidence over assumptions.</span></footer>
  ${if (script.isBlank()) "" else "<script>$script</script>"}
</body>
</html>
"""

private fun JsonObject.text(name: String): String = get(name)?.jsonPrimitive?.contentOrNull.orEmpty()
private fun JsonObject.number(name: String): String = get(name)?.jsonPrimitive?.contentOrNull ?: "0"

private fun String.hexPreview(): String = runCatching {
    if (length % 2 != 0) return@runCatching this
    chunked(2).map { it.toInt(16).toByte() }.toByteArray().decodeToString()
        .replace("\n", "↵").replace("\r", "").replace(Regex("[\\p{Cntrl}&&[^\\t]]"), "·").take(48)
}.getOrDefault(take(48))

private fun String.escapeHtml(): String =
    replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;").replace("'", "&#39;")

private fun String.title(): String = split(' ').joinToString(" ") { it.replaceFirstChar(Char::uppercase) }
private fun formatTimestamp(value: String): String = value.replace('T', ' ').removeSuffix("Z").substringBefore('.') + " UTC"
private fun formatBytes(bytes: Int): String = when {
    bytes >= 1024 * 1024 -> "%.1f MiB".format(java.util.Locale.ROOT, bytes / (1024.0 * 1024.0))
    bytes >= 1024 -> "%.1f KiB".format(java.util.Locale.ROOT, bytes / 1024.0)
    else -> "$bytes B"
}
private fun jsString(value: String): String = "'" + value.replace("\\", "\\\\").replace("'", "\\'") + "'"

val APP_CSS = """
:root {
  --ink: #edf0e8;
  --muted: #98a199;
  --void: #0b0e0d;
  --surface: #121715;
  --surface-2: #181e1b;
  --line: #2a332e;
  --acid: #c9f55a;
  --cyan: #72d7d0;
  --danger: #ff7b69;
  --warning: #efbd55;
  font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
  color: var(--ink);
  background: var(--void);
  font-synthesis: none;
}
* { box-sizing: border-box; }
body { margin: 0; min-height: 100vh; background: radial-gradient(circle at 85% 8%, rgba(114,215,208,.08), transparent 28rem), var(--void); }
body::before { content: ""; position: fixed; inset: 0; pointer-events: none; opacity: .025; background-image: url("data:image/svg+xml,%3Csvg viewBox='0 0 180 180' xmlns='http://www.w3.org/2000/svg'%3E%3Cfilter id='n'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='.85' numOctaves='3' stitchTiles='stitch'/%3E%3C/filter%3E%3Crect width='100%25' height='100%25' filter='url(%23n)' opacity='.6'/%3E%3C/svg%3E"); }
a { color: inherit; }
.shell { width: min(1180px, calc(100% - 40px)); margin-inline: auto; }
.topbar { height: 68px; padding: 0 max(20px, calc((100vw - 1180px)/2)); display: flex; align-items: center; justify-content: space-between; border-bottom: 1px solid var(--line); background: rgba(11,14,13,.84); backdrop-filter: blur(16px); position: sticky; top: 0; z-index: 10; }
.brand { text-decoration: none; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-weight: 700; letter-spacing: -.04em; }
.brand span { display: inline-grid; place-items: center; width: 28px; height: 28px; margin-right: 8px; color: var(--void); background: var(--acid); border-radius: 4px; }
.build-label, .kicker, .eyebrow, .job-id { font: 700 11px/1.2 ui-monospace, SFMono-Regular, Menlo, monospace; letter-spacing: .12em; text-transform: uppercase; color: var(--muted); }
.hero { padding-block: 88px 54px; }
.eyebrow { color: var(--cyan); display: flex; align-items: center; gap: 9px; }
.signal { width: 7px; height: 7px; background: var(--acid); border-radius: 50%; box-shadow: 0 0 18px var(--acid); }
h1, h2, p { margin-top: 0; }
h1 { margin: 20px 0 24px; font-size: clamp(3rem, 7vw, 6.6rem); line-height: .92; letter-spacing: -.075em; max-width: 900px; }
h1 em { color: var(--acid); font-style: normal; }
.lede { max-width: 650px; color: var(--muted); font-size: 18px; line-height: 1.65; }
.dashboard-grid, .job-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 18px; }
.panel { border: 1px solid var(--line); border-radius: 14px; background: linear-gradient(145deg, rgba(24,30,27,.96), rgba(15,19,17,.96)); box-shadow: 0 24px 80px rgba(0,0,0,.18); }
.upload-panel, .queue-panel, .overview-panel, .workflow-panel, .evidence-panel, .history-panel, .artifacts-panel, .source-tree-panel { padding: 28px; }
.section-heading { display: flex; align-items: flex-start; gap: 14px; margin-bottom: 28px; }
.section-heading.compact { align-items: center; }
.section-heading h2 { margin: 2px 0 0; font-size: 23px; letter-spacing: -.035em; }
.section-heading .kicker { margin: 0; color: var(--cyan); }
.step { display: grid; place-items: center; flex: 0 0 34px; height: 34px; border: 1px solid #3a463f; border-radius: 50%; font: 700 10px ui-monospace, monospace; color: var(--acid); }
.count { margin-left: auto; display: grid; place-items: center; min-width: 30px; height: 30px; padding: 0 9px; border-radius: 15px; background: #222a26; color: var(--muted); font: 700 12px ui-monospace, monospace; }
.upload-form { display: grid; gap: 14px; }
.drop-zone { min-height: 220px; display: grid; place-items: center; align-content: center; gap: 8px; border: 1px dashed #4a5a51; border-radius: 10px; background: rgba(8,11,9,.5); cursor: pointer; transition: .2s ease; text-align: center; }
.drop-zone:hover { border-color: var(--acid); background: rgba(201,245,90,.035); transform: translateY(-1px); }
.drop-zone input { position: absolute; width: 1px; height: 1px; opacity: 0; }
.drop-zone strong { font-size: 17px; }
.drop-zone span:not(.upload-mark) { color: var(--muted); font-size: 13px; }
.upload-mark { display: grid; place-items: center; width: 46px; height: 46px; border-radius: 50%; background: var(--acid); color: #11160d; font-size: 25px; }
.button { min-height: 48px; padding: 0 19px; border: 0; border-radius: 7px; display: inline-flex; align-items: center; justify-content: center; gap: 14px; font: 750 14px inherit; text-decoration: none; cursor: pointer; transition: .18s ease; }
.button.primary { color: #11160d; background: var(--acid); }
.button.primary:hover { background: #ddff82; transform: translateY(-1px); }
.button.secondary { color: var(--ink); background: #252d29; border: 1px solid #3a463f; }
.button.secondary:hover { border-color: var(--cyan); }
.button:disabled { opacity: .6; cursor: wait; transform: none; }
.button span { margin-left: auto; }
.guardrails { display: flex; flex-wrap: wrap; gap: 7px; margin-top: 18px; }
.guardrails span, .source-tag { padding: 5px 8px; background: #222a26; border-radius: 4px; color: var(--muted); font: 700 10px ui-monospace, monospace; letter-spacing: .05em; text-transform: uppercase; }
.job-list { margin: 0 -8px; }
.job-row { display: flex; align-items: center; gap: 13px; padding: 15px 10px; text-decoration: none; border-bottom: 1px solid var(--line); border-radius: 7px; transition: .15s ease; }
.job-row:last-child { border-bottom: 0; }
.job-row:hover { background: #202722; }
.file-glyph { display: grid; place-items: center; flex: 0 0 42px; height: 42px; border: 1px solid #3a463f; border-radius: 6px; font: 800 10px ui-monospace, monospace; color: var(--cyan); }
.job-copy { min-width: 0; flex: 1; }
.job-copy strong, .job-copy small { display: block; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.job-copy small { color: var(--muted); margin-top: 5px; font-size: 11px; }
.arrow { color: var(--muted); }
.status-pill { width: max-content; display: inline-flex; align-items: center; gap: 7px; padding: 6px 9px; border-radius: 20px; background: #222a26; color: var(--muted); font: 700 10px ui-monospace, monospace; letter-spacing: .04em; text-transform: uppercase; white-space: nowrap; }
.status-pill i { width: 6px; height: 6px; border-radius: 50%; background: currentColor; }
.status-pill.complete { color: var(--acid); background: rgba(201,245,90,.09); }
.status-pill.failed { color: var(--danger); background: rgba(255,123,105,.09); }
.status-pill.queued, .status-pill.analyzing { color: var(--warning); background: rgba(239,189,85,.09); }
.empty-state { min-height: 240px; display: grid; place-items: center; align-content: center; color: var(--muted); text-align: center; }
.empty-state span { font-size: 35px; color: var(--acid); }.empty-state strong { margin: 12px 0 5px; color: var(--ink); }.empty-state p { font-size: 13px; }
.job-shell { padding-block: 44px 80px; }.back-link { color: var(--muted); font-size: 13px; text-decoration: none; }.back-link:hover { color: var(--acid); }
.job-header { display: flex; justify-content: space-between; gap: 28px; align-items: flex-end; padding: 45px 0 28px; }
.job-header h1 { font-size: clamp(2.8rem, 6vw, 5rem); margin: 13px 0 12px; word-break: break-word; }.job-id { margin: 0; text-transform: none; letter-spacing: .04em; }
.job-actions { display: flex; align-items: center; gap: 12px; padding-bottom: 8px; }.job-actions form { margin: 0; }
.status-note { display: flex; gap: 10px; align-items: center; margin-bottom: 18px; padding: 13px 16px; border: 1px solid var(--line); border-radius: 8px; color: var(--muted); font-size: 13px; }.status-note span { width: 7px; height: 7px; border-radius: 50%; background: var(--cyan); }.status-note.failed span { background: var(--danger); }
.metadata-grid { display: grid; grid-template-columns: 1fr 1fr; margin: 0; }.datum { padding: 15px 0; border-bottom: 1px solid var(--line); }.datum:nth-child(odd) { padding-right: 20px; }.datum dt { color: var(--muted); font: 700 10px ui-monospace, monospace; text-transform: uppercase; letter-spacing: .06em; }.datum dd { margin: 7px 0 0; font-weight: 650; overflow-wrap: anywhere; }
.workflow-list { list-style: none; padding: 0; margin: 0; }.workflow-list li { display: flex; gap: 14px; padding: 13px 0; border-bottom: 1px solid var(--line); }.workflow-list li:last-child { border: 0; }.workflow-list li > span { color: var(--acid); font: 700 11px ui-monospace, monospace; }.workflow-list strong { font-size: 14px; }.workflow-list p { margin: 4px 0 0; color: var(--muted); font-size: 12px; line-height: 1.45; }
.evidence-panel, .history-panel, .artifacts-panel { margin-top: 18px; }.pending-evidence { color: var(--muted); }
.text-link { margin-left: auto; color: var(--acid); font-size: 12px; text-decoration: none; }
.metric-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 10px; margin-bottom: 24px; }.metric { min-height: 126px; padding: 16px; border: 1px solid var(--line); border-radius: 8px; background: rgba(8,11,9,.35); }.metric p, .metric small { color: var(--muted); font-size: 11px; }.metric strong { display: block; margin: 12px 0 4px; font-size: 30px; letter-spacing: -.05em; }.gauge { display: block; height: 3px; margin-top: 13px; background: #2c342f; }.gauge i { display: block; height: 100%; background: var(--acid); }
.table-wrap { overflow-x: auto; border: 1px solid var(--line); border-radius: 8px; }table { width: 100%; border-collapse: collapse; font-size: 12px; }th { color: var(--muted); background: #101411; font: 700 9px ui-monospace, monospace; letter-spacing: .07em; text-transform: uppercase; text-align: left; }th, td { padding: 12px; border-bottom: 1px solid var(--line); white-space: nowrap; }tbody tr:last-child td { border: 0; }code { font: 11px ui-monospace, SFMono-Regular, Menlo, monospace; color: #c9d0ca; }.source-tag.angr { color: var(--cyan); }.source-tag.mutation { color: var(--warning); }.source-tag.static_hint { color: #ba9cff; }.source-tag.seed { color: var(--acid); }.table-note { color: var(--muted); font-size: 11px; margin: 12px 0 0; }
.history-list { display: grid; gap: 10px; }.history-item { display: grid; grid-template-columns: 40px 1fr; gap: 15px; padding: 17px; border: 1px solid var(--line); border-radius: 8px; }.history-index { display: grid; place-items: center; width: 32px; height: 32px; border-radius: 50%; background: #252d28; color: var(--acid); font: 700 11px ui-monospace, monospace; }.history-title { display: flex; align-items: center; justify-content: space-between; }.history-item p { color: var(--muted); font-size: 12px; }.evidence-line { display: grid; gap: 5px; padding: 9px 11px; border-left: 2px solid var(--cyan); background: rgba(114,215,208,.04); }.evidence-line b { color: var(--ink); }.regressions { margin-bottom: 0; }
.artifact-list { display: grid; grid-template-columns: 1fr 1fr; gap: 9px; }.artifact-row { display: flex; align-items: center; gap: 12px; padding: 13px; border: 1px solid var(--line); border-radius: 8px; text-decoration: none; transition: .15s; }.artifact-row:hover { border-color: #526157; background: #202722; }.artifact-row > span:last-child { margin-left: auto; color: var(--acid); }.artifact-icon { display: grid; place-items: center; width: 38px; height: 38px; border-radius: 5px; background: #252d28; color: var(--cyan); font: 700 9px ui-monospace, monospace; }.artifact-row strong, .artifact-row small { display: block; }.artifact-row small { margin-top: 4px; color: var(--muted); font-size: 10px; }
.source-tree-panel { margin-top: 18px; }.tree-note { color: var(--muted); font-size: 13px; }.source-tree { list-style: none; padding: 0; margin: 18px 0; border: 1px solid var(--line); border-radius: 8px; overflow: hidden; }.source-tree li + li { border-top: 1px solid var(--line); }.source-tree a { display: grid; grid-template-columns: 42px 1fr 20px; gap: 11px; align-items: center; min-height: 43px; padding: 7px 12px 7px calc(12px + var(--depth) * 18px); text-decoration: none; background: rgba(8,11,9,.25); }.source-tree a:hover { background: #202722; }.source-tree span { color: var(--cyan); font: 700 9px ui-monospace, monospace; }.source-tree i { color: var(--acid); font-style: normal; }.archive-download { width: max-content; }.source-shell { padding-block: 44px 80px; }.source-heading { display: flex; align-items: flex-end; justify-content: space-between; gap: 20px; padding: 42px 0 24px; }.source-heading h1 { margin: 8px 0 0; font: 700 clamp(1.8rem,4vw,3.5rem)/1.05 ui-monospace, monospace; letter-spacing: -.05em; }.source-view { overflow: auto; min-height: 420px; padding: 24px; border: 1px solid var(--line); border-radius: 10px; background: #080b09; line-height: 1.55; tab-size: 4; }.source-view code { font-size: 12px; color: #dbe2dc; }
.reconstruction-progress { margin-top: 18px; padding: 20px 28px; display: flex; align-items: center; justify-content: space-between; }.reconstruction-progress h2 { margin: 5px 0 0; }.source-provenance { display: grid; grid-template-columns: repeat(3,1fr); gap: 10px; margin-bottom: 16px; }.source-provenance span { padding: 12px; border: 1px solid var(--line); border-radius: 7px; color: var(--muted); font: 11px ui-monospace,monospace; }.source-provenance b { display: block; margin-bottom: 6px; color: var(--cyan); text-transform: uppercase; font-size: 9px; }
.spinner { width: 12px; height: 12px; border: 2px solid rgba(0,0,0,.25); border-top-color: #111; border-radius: 50%; animation: spin .8s linear infinite; }@keyframes spin { to { transform: rotate(360deg); } }
.error-shell { display: grid; place-items: start; align-content: center; min-height: calc(100vh - 150px); max-width: 760px; }.error-shell h1 { font-size: 58px; margin: 5px 0 20px; }.error-shell > p:not(.error-code) { color: var(--muted); font-size: 17px; }.error-code { color: var(--danger); font: 700 12px ui-monospace, monospace; }.error-shell .button { margin-top: 20px; }
footer { display: flex; justify-content: space-between; padding-block: 32px; margin-top: 60px; border-top: 1px solid var(--line); color: var(--muted); font: 700 10px ui-monospace, monospace; letter-spacing: .08em; text-transform: uppercase; }
@media (max-width: 820px) { .dashboard-grid, .job-grid { grid-template-columns: 1fr; }.hero { padding-top: 58px; }.job-header { align-items: flex-start; flex-direction: column; }.job-actions { align-items: flex-start; flex-direction: column; }.metric-grid { grid-template-columns: 1fr 1fr; }.artifact-list { grid-template-columns: 1fr; }.build-label { display: none; } }
@media (max-width: 520px) { .shell { width: min(100% - 24px, 1180px); }.upload-panel, .queue-panel, .overview-panel, .workflow-panel, .evidence-panel, .history-panel, .artifacts-panel, .source-tree-panel { padding: 19px; }.metric-grid, .metadata-grid { grid-template-columns: 1fr; }.datum:nth-child(odd) { padding-right: 0; }h1 { font-size: 3rem; }.job-row .status-pill { display: none; }.source-heading { align-items: flex-start; flex-direction: column; } }
""".trimIndent()
