/** Exact same-origin API URLs for one fixture attempt: no other origin, job, run or query. */
export function attemptUrls({ origin, basePath, jobId, runId, action }) {
  if (!/^[0-9a-f]{32}$/.test(jobId)) throw new Error(`Invalid fixture job id ${jobId}`);
  if (!/^[A-Za-z0-9_-]+$/.test(runId)) throw new Error(`Invalid fixture run id ${runId}`);
  if (!['cancel', 'recover'].includes(action)) throw new Error(`Unknown attempt command ${action}`);
  const root = new URL(basePath.replace(/\/?$/, '/') + `api/v1/jobs/${jobId}/runs/${runId}`, origin).href;
  return { run: root, controls: root + '/controls', command: root + '/' + action };
}

// Playwright emits requestfinished after the response body has downloaded. Record the command
// headers separately so an already-running metadata read cannot qualify as its readback.
export function armAttemptCommandSettle(page, { origin, basePath, jobId, runId, action, readLabel, timeout = 10_000 }) {
  const urls = attemptUrls({ origin, basePath, jobId, runId, action });
  const commands = [];
  const reads = new Map();
  const onRequest = (request) => {
    const url = request.url();
    if (request.method() === 'POST' && url === urls.command) {
      commands.push({ request, status: null, finished: false });
    } else if (request.method() === 'GET' && commands[0]?.status != null && (url === urls.run || url === urls.controls)) {
      reads.set(request, { kind: url === urls.run ? 'Attempt' : 'Controls', status: null, finished: false });
    }
  };
  const observed = (request) => reads.get(request) ?? commands.find((command) => command.request === request);
  const onResponse = (response) => {
    const item = observed(response.request());
    if (item) item.status = response.status();
  };
  const onFinished = (request) => {
    const item = observed(request);
    if (item) item.finished = true;
  };
  const onFailed = (request) => {
    const item = observed(request);
    if (item) item.failure = request.failure()?.errorText ?? 'failed';
  };
  const listeners = { request: onRequest, response: onResponse, requestfinished: onFinished, requestfailed: onFailed };
  for (const [event, listen] of Object.entries(listeners)) page.on(event, listen);

  function pendingRead() {
    if (commands.length > 1) throw new Error(`Attempt command was sent ${commands.length} times`);
    const command = commands[0];
    if (command?.failure) throw new Error(`Attempt command failed in the page: ${command.failure}`);
    if (!command?.finished) return 'command POST answered';
    if (![201, 202].includes(command.status)) throw new Error(`Attempt command returned ${command.status}`);

    let attemptFinished = false;
    let controlsFinished = false;
    let active = false;
    for (const read of reads.values()) {
      if (read.failure) throw new Error(`${read.kind} re-read did not complete: ${read.failure}`);
      if (read.status != null && read.status !== 200) throw new Error(`${read.kind} re-read returned ${read.status}`);
      if (!read.finished || read.status !== 200) active = true;
      else if (read.kind === 'Attempt') attemptFinished = true;
      else controlsFinished = true;
    }
    if (!attemptFinished) return 'attempt re-read after the command';
    if (!controlsFinished || active) return 'controls reads settled';
    return null;
  }
  return async (activate) => {
    try {
      if (activate) await activate();
      const deadline = Date.now() + timeout;
      let pending = 'attempt re-read after the command';
      while (Date.now() < deadline) {
        pending = pendingRead();
        if (!pending) {
          pending = 'enabled read control';
          const control = page.getByRole('button', { name: readLabel, exact: true });
          if (await control.isEnabled({ timeout: Math.max(1, deadline - Date.now()) }) && !pendingRead()) {
            return { status: 200, path: new URL(urls.run).pathname,
              controlsReads: Array.from(reads.values()).filter((entry) => entry.kind === 'Controls').length };
          }
        }
        await new Promise((resolve) => setTimeout(resolve, 10));
      }
      throw new Error(`Attempt command settle exceeded ${timeout} ms: ${pending}`);
    } finally {
      for (const [event, listen] of Object.entries(listeners)) page.off(event, listen);
    }
  };
}
