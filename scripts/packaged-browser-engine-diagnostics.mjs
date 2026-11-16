// Bounded, structured diagnostics for the cross-engine packaged runner (#536). Diagnostics only:
// nothing here waits, retries, suppresses or reclassifies an event; the runner keeps its existing
// string exception list and failure conditions. Every bound is explicit: dropped records are counted
// per kind and reported, never silently lost. All strings pass through the runner's redaction.

export const diagnosticLimits = Object.freeze({
  contexts: 64, exceptionsPerContext: 64, requestsPerContext: 512, phases: 4096, text: 512, stack: 4096, url: 512,
});

export function diagnosticOverflowFailure(snapshot) {
  return snapshot.overflowed ? `Diagnostics exceeded bounds: ${JSON.stringify(snapshot.overflow)}` : null;
}

/** Strips query and fragment so request URLs never carry tokens; bounded and redacted. */
function boundedUrl(value, safe, limit) {
  if (value === null || value === undefined) return null;
  const text = safe(String(value).split('#')[0].split('?')[0]);
  return text.length > limit ? `${text.slice(0, limit)}…[truncated ${text.length - limit}]` : text;
}

function bounded(value, safe, limit) {
  if (value === null || value === undefined) return null;
  const text = safe(String(value));
  return text.length > limit ? `${text.slice(0, limit)}…[truncated ${text.length - limit}]` : text;
}

/**
 * Creates a run-wide recorder. `safe` is the runner's redaction function; `clock` is injectable for
 * unit controls. Phases are Node-side windows; each exception/request record carries the innermost
 * open phase at the moment Node observed it, so a page exception can be correlated to the
 * navigation, screenshot, keyboard or timing window it arrived in.
 */
export function createEngineDiagnostics({ safe = String, clock = () => Date.now(), limits = diagnosticLimits } = {}) {
  limits = { ...diagnosticLimits, ...limits };
  const origin = clock();
  const now = () => clock() - origin;
  const phases = []; const open = []; const contexts = [];
  const overflow = { phases: 0, contexts: 0 };
  let nextPhase = 0;
  const current = () => open.at(-1) ?? null;
  const phaseLabel = () => current()?.label ?? null;

  async function phase(label, run, meta = {}) {
    const window = { id: nextPhase += 1, label: bounded(label, safe, limits.text), parent: current()?.id ?? null,
      start: now(), end: null, outcome: 'running', ...meta };
    if (phases.length < limits.phases) phases.push(window); else overflow.phases += 1;
    open.push(window);
    try {
      const result = await run();
      window.outcome = 'completed';
      return result;
    } catch (error) {
      window.outcome = 'failed';
      window.error = bounded(error?.message ?? error, safe, limits.text);
      throw error;
    } finally {
      window.end = now();
      const index = open.lastIndexOf(window);
      if (index >= 0) open.splice(index, 1);
    }
  }

  function context(label) {
    if (contexts.length >= limits.contexts) {
      overflow.contexts += 1;
      throw new Error('Diagnostic context bound exceeded');
    }
    const id = `context-${contexts.length + 1}`;
    const entry = { id, label: bounded(label, safe, limits.text), exceptions: [], requests: [],
      overflow: { exceptions: 0, requests: 0 } };
    contexts.push(entry);
    const requestIds = new WeakMap(); const pageIds = new WeakMap();
    let nextRequest = 0; let nextPage = 0;
    const pageId = (page) => {
      if (!page) return null;
      if (!pageIds.has(page)) pageIds.set(page, `${id}/page-${nextPage += 1}`);
      return pageIds.get(page);
    };
    const pageUrl = (page) => { try { return boundedUrl(page?.url?.(), safe, limits.url); } catch { return null; } };
    const frameUrl = (request) => { try { return boundedUrl(request.frame?.()?.url?.(), safe, limits.url); } catch { return null; } };
    return {
      id,
      page: pageId,
      /** Structured companion to the runner's String(error); never replaces it. */
      exception(error, page) {
        if (entry.exceptions.length >= limits.exceptionsPerContext) { entry.overflow.exceptions += 1; return null; }
        const record = {
          text: bounded(String(error), safe, limits.text),
          name: bounded(error?.name ?? null, safe, limits.text),
          message: bounded(error?.message ?? null, safe, limits.text),
          stack: bounded(error?.stack ?? null, safe, limits.stack),
          page: pageId(page), pageUrl: pageUrl(page), phase: phaseLabel(), phaseId: current()?.id ?? null,
          at: now(), sequence: entry.exceptions.length + entry.overflow.exceptions,
        };
        entry.exceptions.push(record);
        return record;
      },
      requestStarted(request) {
        if (entry.requests.length >= limits.requestsPerContext) { entry.overflow.requests += 1; return null; }
        const record = { id: `${id}/request-${nextRequest += 1}`, method: bounded(request.method(), safe, 16),
          url: boundedUrl(request.url(), safe, limits.url), frameUrl: frameUrl(request),
          resourceType: bounded(request.resourceType?.() ?? null, safe, 32),
          phase: phaseLabel(), phaseId: current()?.id ?? null, started: now(), state: 'started' };
        requestIds.set(request, record);
        entry.requests.push(record);
        return record;
      },
      requestFinished(request, status = null) {
        const record = requestIds.get(request);
        if (!record) return null;
        record.state = 'finished'; record.finished = now(); record.finishedPhase = phaseLabel();
        if (status !== null) record.status = status;
        return record;
      },
      requestFailed(request) {
        const record = requestIds.get(request);
        if (!record) return null;
        let failure = null; try { failure = request.failure?.()?.errorText ?? null; } catch { failure = null; }
        record.state = 'failed'; record.finished = now(); record.finishedPhase = phaseLabel();
        record.failure = bounded(failure, safe, limits.text);
        return record;
      },
    };
  }

  function snapshot() {
    const dropped = { phases: overflow.phases, contexts: overflow.contexts,
      exceptions: contexts.reduce((sum, entry) => sum + entry.overflow.exceptions, 0),
      requests: contexts.reduce((sum, entry) => sum + entry.overflow.requests, 0) };
    return { limits: { ...limits }, overflow: dropped,
      overflowed: Object.values(dropped).some((count) => count > 0),
      openPhases: open.map((window) => window.id), phases, contexts };
  }

  return { phase, context, snapshot, currentPhase: phaseLabel };
}
