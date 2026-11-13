/** Track the dashboard's authenticated jobs-list reads by CDP request identity. */
const MAX_DASHBOARD_LISTING_REQUESTS = 16;

export function createDashboardListingTracker({ cdp, sessionId, origin, basePath = '/nested', now = () => Date.now(),
  delay = (milliseconds) => new Promise(resolve => setTimeout(resolve, milliseconds)) } = {}) {
  if (!cdp || typeof cdp.on !== 'function' || typeof sessionId !== 'string' || !sessionId) {
    throw new TypeError('Dashboard listing tracker requires a CDP session');
  }
  const expectedOrigin = new URL(origin).origin;
  const normalizedBasePath = `/${String(basePath).split('/').filter(Boolean).join('/')}`;
  const expectedPath = `${normalizedBasePath}/api/v1/jobs`;
  let active = null;

  const onRequest = (event) => {
    if (!active || event.request?.method !== 'GET' || typeof event.requestId !== 'string') return;
    let url;
    try { url = new URL(event.request.url); } catch { return; }
    if (url.origin !== expectedOrigin || url.pathname !== expectedPath) return;
    if (!active.requests.has(event.requestId) && active.requests.size >= MAX_DASHBOARD_LISTING_REQUESTS) {
      active.overflow = true;
      active.lastActivityAt = now();
      return;
    }
    active.requests.set(event.requestId, { status: null, completed: false, failed: false });
    active.lastActivityAt = now();
  };
  const onResponse = (event) => {
    const request = active?.requests.get(event.requestId);
    if (!request) return;
    request.status = event.response?.status ?? null;
    active.lastActivityAt = now();
  };
  const onFinished = (event) => {
    const request = active?.requests.get(event.requestId);
    if (!request) return;
    request.completed = true;
    active.lastActivityAt = now();
  };
  const onFailed = (event) => {
    const request = active?.requests.get(event.requestId);
    if (!request) return;
    request.completed = true;
    request.failed = true;
    active.lastActivityAt = now();
  };
  cdp.on('Network.requestWillBeSent', onRequest, sessionId);
  cdp.on('Network.responseReceived', onResponse, sessionId);
  cdp.on('Network.loadingFinished', onFinished, sessionId);
  cdp.on('Network.loadingFailed', onFailed, sessionId);

  return {
    begin() {
      if (active) throw new Error('A dashboard listing observation is already active');
      const startedAt = now();
      const token = { startedAt };
      active = { token, startedAt, lastActivityAt: startedAt, requests: new Map(), overflow: false };
      return token;
    },

    async waitForCompletion(token, { timeoutMs = 20_000, quietMs = 250, pollMs = 25 } = {}) {
      if (!active || active.token !== token) throw new Error('Dashboard listing observation is no longer active');
      if (![timeoutMs, quietMs, pollMs].every(Number.isSafeInteger) || timeoutMs < 1 || quietMs < 0 || pollMs < 1) {
        throw new TypeError('Dashboard listing wait bounds are invalid');
      }
      const deadline = token.startedAt + timeoutMs;
      try {
        while (now() < deadline) {
          if (active.overflow) throw new Error(`Dashboard jobs listing exceeded ${MAX_DASHBOARD_LISTING_REQUESTS} requests`);
          const requests = [...active.requests.values()];
          const quiescent = requests.length > 0 && requests.every(request => request.completed) && now() - active.lastActivityAt >= quietMs;
          if (quiescent) {
            const requestCount = requests.length;
            const responseStatuses = requests.map(request => request.status);
            const failedCount = requests.filter(request => request.failed).length;
            if (failedCount || responseStatuses.some(status => status !== 200)) {
              throw new Error(`Dashboard jobs listing did not complete successfully (requests=${requestCount}, failed=${failedCount}, statuses=${responseStatuses.join(',')})`);
            }
            return { requestCount, completedCount: requestCount, responseStatuses, durationMs: now() - token.startedAt };
          }
          await delay(Math.min(pollMs, Math.max(1, deadline - now())));
        }
        const requestCount = active.requests.size;
        const pendingCount = [...active.requests.values()].filter(request => !request.completed).length;
        throw new Error(`Dashboard jobs listing did not settle before the deadline (requests=${requestCount}, pending=${pendingCount})`);
      } finally {
        active = null;
      }
    },
  };
}
