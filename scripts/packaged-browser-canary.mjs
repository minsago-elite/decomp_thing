import assert from 'node:assert/strict';

// Observe each view while it is mounted, not just whichever route survives at journey end.
export const WORKFLOW_CANARY_VIEWS = [
  'disk-full upload', 'selected upload', 'uploaded job', 'live activity',
  'interrupted attempt', 'completed retry', 'recorded source', 'failed attempt',
];

function validStorage(value) {
  if (typeof value !== 'string') return false;
  try {
    const entries = JSON.parse(value);
    return entries !== null && typeof entries === 'object' && !Array.isArray(entries) &&
      Object.values(entries).every(item => typeof item === 'string');
  } catch { return false; }
}

export function createCanaryTracker(canary) {
  assert.ok(typeof canary === 'string' && canary.length > 0, 'A nonempty secret canary is required');
  const observations = [];
  return {
    async observe(target, evaluate, label) {
      // Evaluation failures, unavailable DOM/storage and malformed observations must fail closed.
      const view = await evaluate(target, `({ text: document.documentElement.outerHTML,
        storage: { local: JSON.stringify({ ...localStorage }), session: JSON.stringify({ ...sessionStorage }) },
        injectedFlag: typeof globalThis.__decompInjected,
        injectedImages: [...document.querySelectorAll('main img')].filter(image => image.getAttribute('src') === 'x').length })`);
      assert.ok(view && typeof view.text === 'string' && view.text.length > 0 && view.storage &&
        ['local', 'session'].every(key => validStorage(view.storage[key])),
        `Unavailable or malformed canary observation: ${label}`);
      assert.ok(view.injectedFlag === 'undefined' && view.injectedImages === 0,
        `Untrusted markup became active: ${label}`);
      assert.ok(Array.isArray(target.console) && target.console.every(entry => typeof entry.text === 'string'),
        `Unavailable or malformed console observation: ${label}`);
      // Do not include the raw secret (or page contents) in an assertion's diagnostic.
      assert.ok(!view.text.includes(canary) && !Object.values(view.storage).some(value => value.includes(canary)) &&
        !target.console.some(entry => entry.text.includes(canary)), `The server secret canary escaped redaction: ${label}`);
      observations.push(label);
    },
    summary(requiredViews) {
      assert.ok(requiredViews.length > 0 && requiredViews.every(label => observations.includes(label)),
        'Canary coverage is incomplete for the required views');
      return { liveViews: true, retainedViews: true, browserStorage: true, hostileMarkupInert: true,
        observedViews: [...observations], leaks: 0 };
    },
  };
}
